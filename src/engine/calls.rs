use std::{
    future::{Future, pending},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use tokio::{
    sync::{mpsc, oneshot, watch},
    time::timeout,
};
use uuid::Uuid;
use zeroize::Zeroizing;

#[cfg(feature = "desktop")]
mod aac;
#[cfg(feature = "desktop")]
mod audio;
pub(super) mod outgoing;
#[cfg(feature = "desktop")]
pub mod video;

use super::{Engine, IncomingCalls, Request, active_call};
use crate::{
    CallMode, IncomingCall, Status,
    apple::{
        CallAvcMaterial, CallEndpoint, CallKeyOffer, CallMediaDescription, CallMediaExchange,
        CallMediaHandshake, CallPeerKeys, CallRelayAllocation, CallRelayBinding, CallRelayProfile,
        CallRtpProtection, Identity, Madrid, PeerKeyOffer, PeerPrekey, RelayMediaEvent,
        RelayPeerUpdate, SignedRelayKeys,
    },
    now_ms,
};

const MEDIA_SETUP_TIMEOUT: Duration = Duration::from_secs(12);

/// A media description built from the capture and codec capabilities available to this answer.
pub struct CallAnswerConfig<'a> {
    pub mode: CallMode,
    pub avc_plist: &'a [u8],
    pub relay_profile: CallRelayProfile<'a>,
}

#[cfg(feature = "desktop")]
impl<'a> CallAnswerConfig<'a> {
    fn desktop(device: &'a crate::apple::CallDevice, avc_plist: &'a [u8], mode: CallMode) -> Self {
        Self {
            mode,
            avc_plist,
            relay_profile: CallRelayProfile {
                os_version: &device.relay_os_version,
                hardware_version: &device.model,
                capabilities: 9_271_791, // QuickRelay one-to-one channel binding.
            },
        }
    }
}

/// A joined call with verified peer media parameters and a live relay.
/// Dropping the call ends our participation.
pub struct AnsweredCall {
    pub call: IncomingCall,
    pub local_description: CallMediaDescription,
    pub remote_description: CallMediaDescription,
    pub local_keys: Arc<CallKeyOffer>,
    pub relay: CallRelayBinding,
    peer_keys: watch::Receiver<CallPeerKeys>,
    lifetime: AnswerLifetime,
    rtp: CallRtpProtection,
    requests: mpsc::Sender<Request>,
    installing_key: Option<RelayKeyInstall>,
}

type RelayKeyInstall = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

impl AnsweredCall {
    /// Updates carry keys from the authenticated device on this call.
    pub fn watch_peer_keys(&self) -> watch::Receiver<CallPeerKeys> {
        self.peer_keys.clone()
    }

    /// The channel closes when the caller hangs up or the connection is lost.
    pub fn watch_end(&self) -> watch::Receiver<()> {
        self.lifetime.ended.clone()
    }

    /// Encrypt and authenticate an RTP packet belonging to a negotiated local stream.
    pub fn protect_rtp(&mut self, packet: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        self.lifetime
            .ended
            .has_changed()
            .context("This FaceTime call has ended")?;
        self.rtp.protect(packet)
    }

    /// Verify a protected packet from the negotiated peer before handing it to a decoder.
    pub fn open_rtp(&mut self, packet: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        self.lifetime
            .ended
            .has_changed()
            .context("This FaceTime call has ended")?;
        let key = self
            .peer_keys
            .borrow()
            .media
            .clone()
            .context("Missing FaceTime caller media key")?;
        self.rtp.open(key, packet)
    }

    /// Protect and send an RTP packet through the negotiated one-to-one relay.
    pub async fn send_rtp(&mut self, packet: &[u8]) -> Result<()> {
        let protected = self.protect_rtp(packet)?;
        tokio::select! {
            biased;
            _ = self.lifetime.ended.changed() => anyhow::bail!("This FaceTime call has ended"),
            result = self.relay.send_routed_rtp(&protected) => result,
        }
    }

    /// Receive authenticated RTP and install signed media keys as the other device rotates them.
    pub async fn receive_rtp(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        loop {
            if let Some(install) = &mut self.installing_key {
                let result = tokio::select! {
                    biased;
                    _ = self.lifetime.ended.changed() => Err(anyhow::anyhow!("This FaceTime call has ended")),
                    result = install => result,
                };
                self.installing_key = None;
                result?;
            }
            let event = tokio::select! {
                biased;
                _ = self.lifetime.ended.changed() => anyhow::bail!("This FaceTime call has ended"),
                result = self.relay.receive_media_event() => result?,
            };
            match event {
                RelayMediaEvent::Keys(offer) => {
                    // The desktop can interrupt this read to send audio or video. Keep the
                    // in-flight installation so cancellation cannot lose a key or its receipt.
                    self.installing_key = Some(Box::pin(install_relay_keys(
                        self.requests.clone(),
                        self.call.id,
                        offer,
                    )));
                }
                RelayMediaEvent::Rtp(protected) => {
                    if let Some(clear) = self.open_rtp(&protected)? {
                        return Ok(clear);
                    }
                }
            }
        }
    }

    /// End the local call and release the relay channels.
    pub async fn hang_up(self) -> Result<()> {
        let Self {
            relay, lifetime, ..
        } = self;
        drop(lifetime);
        relay.unbind().await
    }
}

pub(super) struct AnswerAttempt {
    lease: Arc<AnswerLease>,
    call: IncomingCall,
    handshake: Option<Arc<CallMediaHandshake>>,
}

pub(super) struct AnswerLease {
    id: Uuid,
}

pub(super) struct JoinAnswer {
    id: Uuid,
    lease: Arc<AnswerLease>,
    avc_plist: Vec<u8>,
    mode: CallMode,
}

pub(super) struct AnswerLifetime {
    _hangup: oneshot::Sender<()>,
    ended: watch::Receiver<()>,
}

pub(super) struct CallKeyDelivery {
    pub(super) offer: Arc<CallKeyOffer>,
    signed: Option<SignedRelayKeys>,
    ids: oneshot::Receiver<Result<()>>,
}

pub(super) struct CourierKeyDelivery {
    handshake: Arc<CallMediaHandshake>,
    endpoint: CallEndpoint,
    offer: Arc<CallKeyOffer>,
    receipt: oneshot::Sender<Result<()>>,
}

impl CallKeyDelivery {
    pub(super) fn prepare(
        identity: &Identity,
        handshake: Arc<CallMediaHandshake>,
        endpoint: CallEndpoint,
        offer: Arc<CallKeyOffer>,
    ) -> Result<(Self, CourierKeyDelivery)> {
        let signed = identity.sign_relay_keys(&offer, endpoint)?;
        let (receipt, ids) = oneshot::channel();
        let courier = CourierKeyDelivery {
            handshake,
            endpoint,
            offer: offer.clone(),
            receipt,
        };
        Ok((Self { offer, signed, ids }, courier))
    }

    pub(super) async fn wait_for_ids(self) -> Result<()> {
        self.ids
            .await
            .context("The Apple engine stopped while exchanging keys")?
    }

    async fn publish(
        mut self,
        relay: &mut CallRelayBinding,
        description: &CallAvcMaterial,
    ) -> Result<()> {
        if let Some(keys) = self.signed.take() {
            match relay.publish_media(description, Some(&keys)).await {
                Ok(()) => return Ok(()),
                Err(error) => self.wait_for_ids().await.with_context(|| {
                    format!("Could not publish FaceTime keys through the relay: {error:#}")
                })?,
            }
        } else {
            self.wait_for_ids().await?;
        }
        relay.publish_media(description, None).await
    }
}

impl CourierKeyDelivery {
    pub(super) async fn send(&self, identity: &Identity, madrid: &mut Madrid) -> Result<()> {
        madrid
            .publish_call_keys(identity, &self.handshake, self.endpoint, &self.offer)
            .await
    }

    pub(super) fn finish(self, result: Result<()>) {
        let _ = self.receipt.send(result);
    }
}

pub(super) struct ConnectedCall {
    pub(super) call: IncomingCall,
    pub(super) endpoint: CallEndpoint,
    pub(super) relay: Arc<CallRelayAllocation>,
    pub(super) exchange: CallMediaExchange,
    pub(super) initiator: bool,
    local_hangup: oneshot::Receiver<()>,
    _ended: watch::Sender<()>,
}

pub(super) struct JoinReceipt {
    pub(super) call: IncomingCall,
    pub(super) endpoint: CallEndpoint,
    pub(super) relay: Arc<CallRelayAllocation>,
}

impl Engine {
    /// Generate the local media offer from the registered Apple device and answer a ring.
    #[cfg(feature = "desktop")]
    pub async fn answer_desktop_call(&self, id: Uuid, mode: CallMode) -> Result<AnsweredCall> {
        let device = self
            .call_device
            .as_ref()
            .context("The local Apple session has no FaceTime device profile")?;
        let avc_plist = device.description(mode)?;
        self.answer_call(id, CallAnswerConfig::desktop(device, &avc_plist, mode))
            .await
    }

    /// Answer the identified incoming call using the provided, locally supported media description.
    pub async fn answer_call(
        &self,
        id: Uuid,
        config: CallAnswerConfig<'_>,
    ) -> Result<AnsweredCall> {
        let local_description = CallMediaDescription::parse(config.avc_plist, Some(config.mode))?;
        ensure!(
            config.mode != CallMode::Video || local_description.video.is_some(),
            "FaceTime video needs a camera stream"
        );
        let status = self.status();
        let call = active_call(&status, id)?.clone();
        ensure!(
            config.mode != CallMode::Video || call.mode != Some(CallMode::Audio),
            "An incoming FaceTime Audio call must be answered with audio"
        );
        let remaining =
            Duration::from_millis(call.expires_ms.saturating_sub(now_ms()).max(0) as u64);
        let setup = async {
            let AnswerAttempt {
                call,
                lease,
                handshake,
            } = self.wait_for_caller_offer(id).await?;
            ensure!(
                config.mode != CallMode::Video || call.mode != Some(CallMode::Audio),
                "An incoming FaceTime Audio call must be answered with audio"
            );
            let allocation = self.allocate_call_relay(id).await?;
            let (handshake, early_relay) = if let Some(handshake) = handshake {
                (handshake, None)
            } else {
                // The caller's signed participant update established the endpoint.
                // Connect so the relay can deliver its signed prekey.
                let mut relay = allocation
                    .connect()
                    .await?
                    .bind(config.relay_profile)
                    .await?;
                relay.subscribe_to_descriptions().await?;
                let handshake = self.wait_for_answer_media(id, &lease, &mut relay).await?;
                (handshake, Some(relay))
            };
            let delivery = self.prepare_key_delivery(id).await?;
            let local_keys = delivery.offer.clone();
            let description = local_keys.seal_description(config.avc_plist, config.mode)?;
            let relay = if early_relay.is_none() && delivery.signed.is_none() {
                delivery.wait_for_ids().await?;
                let mut relay = allocation
                    .connect()
                    .await?
                    .bind_with_description(config.relay_profile, &description)
                    .await?;
                relay.subscribe_to_descriptions().await?;
                relay
            } else {
                let mut relay = match early_relay {
                    Some(relay) => relay,
                    None => {
                        let mut relay = allocation
                            .connect()
                            .await?
                            .bind(config.relay_profile)
                            .await?;
                        relay.subscribe_to_descriptions().await?;
                        relay
                    }
                };
                delivery.publish(&mut relay, &description).await?;
                relay
            };
            Ok::<_, anyhow::Error>((
                relay,
                local_keys,
                allocation.caller_participant,
                lease,
                handshake,
            ))
        };
        let (relay, local_keys, caller_participant, lease, handshake) = tokio::select! {
            biased;
            error = wait_for_ring_to_end(self.watch_status(), id) => return Err(error),
            result = timeout(remaining, setup) => result.context("The FaceTime call expired during setup")??,
        };
        let (reply, joined) = oneshot::channel();
        self.requests
            .try_send(Request::JoinCall {
                answer: JoinAnswer {
                    id,
                    lease,
                    avc_plist: config.avc_plist.to_vec(),
                    mode: config.mode,
                },
                reply,
            })
            .context("The Apple engine is busy or stopped")?;
        let lifetime = joined
            .await
            .context("The Apple engine stopped before joining FaceTime")??;
        let call = complete_media(
            self,
            handshake,
            relay,
            local_keys,
            local_description,
            caller_participant,
            lifetime,
        )
        .await?;
        let _ = self.requests.try_send(Request::NotifyAnswerElsewhere(id));
        Ok(call)
    }

    async fn wait_for_caller_offer(&self, id: Uuid) -> Result<AnswerAttempt> {
        let mut updates = self.watch_status();
        loop {
            updates.borrow_and_update();
            let (reply, answer) = oneshot::channel();
            self.requests
                .try_send(Request::BeginCallAnswer { id, reply })
                .context("The Apple engine is busy or stopped")?;
            if let Some(attempt) = answer
                .await
                .context("The Apple engine stopped while preparing the answer")??
            {
                return Ok(attempt);
            }
            updates
                .changed()
                .await
                .context("The Apple engine stopped while waiting for the caller to join")?;
        }
    }

    async fn wait_for_answer_media(
        &self,
        id: Uuid,
        lease: &Arc<AnswerLease>,
        relay: &mut CallRelayBinding,
    ) -> Result<Arc<CallMediaHandshake>> {
        let mut updates = self.watch_status();
        let mut relay_prekey = None;
        let mut can_read_relay = true;
        loop {
            updates.borrow_and_update();
            let (reply, result) = oneshot::channel();
            self.requests
                .try_send(Request::ResolveAnswerMedia {
                    id,
                    lease: lease.clone(),
                    relay_prekey: relay_prekey.take(),
                    reply,
                })
                .context("The Apple engine is busy or stopped")?;
            if let Some(handshake) = result
                .await
                .context("The Apple engine stopped while preparing the answer")??
            {
                return Ok(handshake);
            }
            tokio::select! {
                result = updates.changed() => result.context("The Apple engine stopped while waiting for caller keys")?,
                result = relay.wait_for_peer_prekey(), if can_read_relay => {
                    can_read_relay = false;
                    relay_prekey = result.ok().flatten();
                }
            }
        }
    }
}

async fn wait_for_ring_to_end(mut status: watch::Receiver<Status>, id: Uuid) -> anyhow::Error {
    loop {
        {
            let status = status.borrow_and_update();
            if !status.connected {
                return anyhow::anyhow!("The Apple courier disconnected during FaceTime setup");
            }
            if let Err(error) = active_call(&status, id) {
                return error;
            }
        }
        if status.changed().await.is_err() {
            return anyhow::anyhow!("The Apple engine stopped during FaceTime setup");
        }
    }
}

async fn complete_media(
    engine: &Engine,
    handshake: Arc<CallMediaHandshake>,
    mut relay: CallRelayBinding,
    local_keys: Arc<CallKeyOffer>,
    local_description: CallMediaDescription,
    peer_participant: u64,
    mut lifetime: AnswerLifetime,
) -> Result<AnsweredCall> {
    let mut peer_keys = handshake.watch_peer_keys();
    // Announce our route while the IDS engine receives the peer's keys.
    let media_setup = async {
        relay.negotiate_media_path().await?;
        wait_for_media(engine, &handshake, &mut relay, &mut peer_keys).await
    };
    let remote_description = tokio::select! {
        biased;
        _ = lifetime.ended.changed() => anyhow::bail!("This FaceTime call has ended"),
        result = timeout(MEDIA_SETUP_TIMEOUT, media_setup) =>
            result.context("The other device did not finish FaceTime media setup")??,
    };
    let rtp = CallRtpProtection::new(
        handshake.call().id,
        peer_participant,
        &local_keys.media,
        &local_description,
        &remote_description,
    )?;
    Ok(AnsweredCall {
        call: handshake.call().clone(),
        local_description,
        remote_description,
        local_keys,
        relay,
        peer_keys,
        lifetime,
        rtp,
        requests: engine.requests.clone(),
        installing_key: None,
    })
}

async fn wait_for_media(
    engine: &Engine,
    handshake: &CallMediaHandshake,
    relay: &mut CallRelayBinding,
    keys: &mut watch::Receiver<CallPeerKeys>,
) -> Result<CallMediaDescription> {
    let signed_description = handshake.decode_peer_description().ok();
    let mut indications_open = true;
    loop {
        {
            let authenticated = keys.borrow_and_update();
            if authenticated.media.is_some() {
                if let Some(description) = relay.peer_description(&authenticated)? {
                    return Ok(description);
                }
                if let Some(description) = signed_description {
                    return Ok(description);
                }
                ensure!(
                    indications_open,
                    "The peer did not supply a FaceTime media description"
                );
            }
        }
        tokio::select! {
            result = keys.changed() => result.context("This FaceTime call has ended")?,
            result = relay.next_peer_update(), if indications_open => {
                match result {
                    Ok(Some(RelayPeerUpdate::Description)) => (),
                    Ok(Some(RelayPeerUpdate::Keys(offer))) => {
                        install_relay_keys(engine.requests.clone(), handshake.call().id, offer).await?;
                    }
                    Ok(None) => indications_open = false,
                    Err(_) if signed_description.is_some() => indications_open = false,
                    Err(error) => return Err(error),
                }
            }
        }
    }
}

async fn install_relay_keys(
    requests: mpsc::Sender<Request>,
    id: Uuid,
    offer: Box<PeerKeyOffer>,
) -> Result<()> {
    let (reply, receipt) = oneshot::channel();
    requests
        .send(Request::InstallRelayKeys { id, offer, reply })
        .await
        .context("The Apple engine stopped while installing FaceTime keys")?;
    receipt
        .await
        .context("The Apple engine stopped before installing FaceTime keys")
}

impl IncomingCalls {
    pub(super) fn begin_answer(
        &mut self,
        status: &Status,
        id: Uuid,
    ) -> Result<Option<AnswerAttempt>> {
        ensure!(
            status.connected && status.facetime_registered,
            "FaceTime is disconnected"
        );
        ensure!(
            !self.call_in_progress(),
            "A FaceTime call is already in progress"
        );
        let call = active_call(status, id)?.clone();
        let details = self
            .details
            .get(&id)
            .context("Missing FaceTime caller details")?;
        if details.endpoint.participant().is_none() || details.description.is_none() {
            return Ok(None);
        }
        let handshake = details
            .prekey
            .is_some()
            .then(|| self.prepare_media(status, id))
            .transpose()?;
        let lease = Arc::new(AnswerLease { id });
        self.answering = Some(Arc::downgrade(&lease));
        Ok(Some(AnswerAttempt {
            lease,
            call,
            handshake,
        }))
    }

    fn check_answer_lease(&self, id: Uuid, lease: &Arc<AnswerLease>) -> Result<()> {
        ensure!(
            lease.id == id
                && self
                    .answering
                    .as_ref()
                    .and_then(|active| active.upgrade())
                    .is_some_and(|active| Arc::ptr_eq(&active, lease)),
            "The FaceTime answer was canceled"
        );
        Ok(())
    }

    pub(super) fn resolve_answer_media(
        &mut self,
        status: &Status,
        id: Uuid,
        lease: &Arc<AnswerLease>,
        relay_prekey: Option<PeerPrekey>,
    ) -> Result<Option<Arc<CallMediaHandshake>>> {
        self.check_answer_lease(id, lease)?;
        active_call(status, id)?;
        let details = self
            .details
            .get_mut(&id)
            .context("The FaceTime caller is unavailable")?;
        if let Some(prekey) = relay_prekey {
            ensure!(
                details
                    .relay
                    .as_ref()
                    .is_some_and(|relay| relay.call_id == id
                        && details.endpoint.participant() == Some(relay.caller_participant)),
                "FaceTime relay no longer matches the caller"
            );
            details.learn_prekey(prekey);
        }
        details
            .prekey
            .is_some()
            .then(|| self.prepare_media(status, id))
            .transpose()
    }

    pub(super) async fn send_join(
        &self,
        identity: &Identity,
        madrid: &mut Madrid,
        status: &watch::Sender<Status>,
        answer: &JoinAnswer,
    ) -> Result<JoinReceipt> {
        self.check_answer_lease(answer.id, &answer.lease)?;
        let call = active_call(&status.borrow(), answer.id)?.clone();
        ensure!(
            answer.mode != CallMode::Video || call.mode != Some(CallMode::Audio),
            "An incoming FaceTime Audio call must be answered with audio"
        );
        let details = self
            .details
            .get(&answer.id)
            .context("The FaceTime caller is unavailable")?;
        let relay = details
            .relay
            .as_ref()
            .context("Missing FaceTime relay")?
            .clone();
        let exchange = details
            .exchange
            .as_ref()
            .context("Missing FaceTime key exchange")?;
        ensure!(details.offer.is_some(), "Missing FaceTime key offer");
        let endpoint = details.endpoint;
        madrid
            .update_call_participant(
                identity,
                &call,
                endpoint,
                &relay,
                Some((
                    &answer.avc_plist,
                    exchange.handshake.public_prekey(),
                    answer.mode,
                )),
                false,
            )
            .await?;
        Ok(JoinReceipt {
            call,
            relay,
            endpoint,
        })
    }

    pub(super) fn finish_answer(
        &mut self,
        status: &watch::Sender<Status>,
        receipt: &JoinReceipt,
    ) -> Result<AnswerLifetime> {
        let call = active_call(&status.borrow(), receipt.call.id)?.clone();
        let details = self
            .details
            .get(&call.id)
            .context("The FaceTime caller is unavailable")?;
        ensure!(
            details.endpoint.matches(receipt.endpoint),
            "The FaceTime caller device changed"
        );
        let details = self
            .details
            .remove(&call.id)
            .context("The FaceTime caller is unavailable")?;
        let exchange = details.exchange.context("Missing FaceTime key exchange")?;
        let id = call.id;
        let lifetime = self.connect_call(
            call,
            receipt.endpoint,
            receipt.relay.clone(),
            exchange,
            false,
        );
        status.send_modify(|status| status.incoming_calls.retain(|candidate| candidate.id != id));
        Ok(lifetime)
    }

    fn connect_call(
        &mut self,
        call: IncomingCall,
        endpoint: CallEndpoint,
        relay: Arc<CallRelayAllocation>,
        exchange: CallMediaExchange,
        initiator: bool,
    ) -> AnswerLifetime {
        let (hangup, local_hangup) = oneshot::channel();
        let (_ended, ended) = watch::channel(());
        self.connected = Some(ConnectedCall {
            call,
            endpoint,
            relay,
            exchange,
            initiator,
            local_hangup,
            _ended,
        });
        AnswerLifetime {
            _hangup: hangup,
            ended,
        }
    }

    fn call_in_progress(&self) -> bool {
        self.connected.is_some()
            || self.outgoing.is_some()
            || self
                .answering
                .as_ref()
                .and_then(|lease| lease.upgrade())
                .is_some()
    }

    pub(super) async fn wait_for_local_hangup(&mut self) {
        if let Some(connected) = &mut self.connected {
            let _ = (&mut connected.local_hangup).await;
        } else if let Some(outgoing) = &mut self.outgoing {
            outgoing.wait_to_cancel().await;
        } else {
            pending().await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apple::{CallSignal, PeerMediaOffer, PeerPrekey, call_relay_fixture};

    #[tokio::test]
    async fn answering_preserves_the_session_past_ring_expiry_and_only_its_caller_can_end_it()
    -> Result<()> {
        let id = Uuid::new_v4();
        let now = now_ms();
        let relay = Arc::new(call_relay_fixture(id)?);
        let endpoint = CallEndpoint::new([2; 32], Some(relay.caller_participant));
        let caller = "mailto:caller@example.org";
        let own = "mailto:local@example.org";
        let call = IncomingCall {
            id,
            caller: caller.to_owned(),
            mode: Some(CallMode::Audio),
            received_ms: now,
            expires_ms: now + 45_000,
        };
        let (status, mut reader) = watch::channel(Status {
            connected: true,
            detail: String::new(),
            tapback_revision: None,
            facetime_registered: true,
            incoming_calls: Vec::new(),
        });
        let prekey = PeerPrekey::parse(
            1,
            &hex::decode(concat!(
                "043ed113b7883b4c590638379db0c21cda16742ed0255048bf433391d374bc21d190",
                "99209accc4c8a224c843afa4f4c68a090d04da5e9889dae2f8eefce82a3740"
            ))?,
        )?;
        let ring = || CallSignal::Ring {
            call: call.clone(),
            endpoint,
            media: Some(PeerMediaOffer {
                description: b"fixture".to_vec(),
                prekey: Some(prekey.clone()),
            }),
        };
        let end = |device| CallSignal::End {
            id,
            sender: caller.to_owned(),
            received_ms: now + 1,
            endpoint: device,
        };
        let receipt = JoinReceipt {
            call: call.clone(),
            relay,
            endpoint,
        };
        let mut incoming = IncomingCalls::default();
        incoming.update(&status, own, ring());
        incoming.details.get_mut(&id).unwrap().prekey = None;
        reader.borrow_and_update();
        let attempt = incoming
            .begin_answer(&reader.borrow(), id)?
            .context("missing answer reservation")?;
        assert!(attempt.handshake.is_none());
        assert!(incoming.begin_answer(&reader.borrow(), id).is_err());
        assert!(
            incoming
                .resolve_answer_media(&reader.borrow(), id, &attempt.lease, None)?
                .is_none()
        );
        assert!(
            incoming
                .resolve_answer_media(&reader.borrow(), id, &attempt.lease, Some(prekey.clone()))
                .is_err()
        );
        let local = crate::apple::LocalCallPrekey::generate()?;
        let published = *local.public();
        let details = incoming
            .details
            .get_mut(&id)
            .context("Missing caller details")?;
        details.relay = Some(receipt.relay.clone());
        details.local_prekey = Some(local);
        let forged_lease = Arc::new(AnswerLease { id });
        assert!(
            incoming
                .resolve_answer_media(&reader.borrow(), id, &forged_lease, Some(prekey.clone()))
                .is_err()
        );
        let handshake = incoming
            .resolve_answer_media(&reader.borrow(), id, &attempt.lease, Some(prekey.clone()))?
            .context("Missing answer handshake")?;
        assert_eq!(*handshake.public_prekey(), published);
        let mut lifetime = incoming.finish_answer(&status, &receipt)?;
        drop(attempt);
        assert!(reader.borrow().incoming_calls.is_empty());
        status.send_modify(|status| {
            incoming.expire(status, call.expires_ms + 1);
        });
        incoming.update(&status, own, ring());
        incoming.update(&status, own, end(CallEndpoint::new([2; 32], None)));
        incoming.update(
            &status,
            own,
            CallSignal::RespondedElsewhere {
                id,
                sender: own.into(),
                received_ms: now + 1,
            },
        );
        incoming.update(
            &status,
            own,
            end(CallEndpoint::new([3; 32], endpoint.participant())),
        );
        assert!(incoming.connected.is_some());
        assert!(reader.borrow().incoming_calls.is_empty());
        assert!(lifetime.ended.has_changed().is_ok());
        incoming.update(&status, own, end(endpoint));
        assert!(lifetime.ended.changed().await.is_err());
        assert!(incoming.connected.is_none());
        assert!(incoming.finish_answer(&status, &receipt).is_err());
        incoming.update(&status, own, ring());
        assert!(reader.borrow().incoming_calls.is_empty());

        let mut incoming = IncomingCalls::default();
        incoming.update(&status, own, ring());
        let attempt = incoming
            .begin_answer(&reader.borrow(), id)?
            .context("missing answer reservation")?;
        drop(attempt); // A canceled setup should release the reservation.
        let _attempt = incoming
            .begin_answer(&reader.borrow(), id)?
            .context("canceled answer retained its reservation")?;
        let lifetime = incoming.finish_answer(&status, &receipt)?;
        drop(lifetime);
        timeout(Duration::from_secs(1), incoming.wait_for_local_hangup()).await?;
        Ok(())
    }
}
