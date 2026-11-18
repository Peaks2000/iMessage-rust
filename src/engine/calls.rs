use std::{future::pending, sync::Arc, time::Duration};

use anyhow::{Context, Result, ensure};
use tokio::{
    sync::{oneshot, watch},
    time::timeout,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{Engine, IncomingCalls, Request, active_call};
use crate::{
    CallMode, IncomingCall, Status,
    apple::{
        CallEndpoint, CallKeyOffer, CallMediaDescription, CallMediaExchange, CallMediaHandshake,
        CallPeerKeys, CallRelayAllocation, CallRelayBinding, CallRelayProfile, CallRtpProtection,
        Identity, Madrid,
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
}

impl AnsweredCall {
    /// Updates carry only keys received from the device that initiated this call.
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

    /// Receive the caller's authenticated RTP, skipping invalid and replayed packets.
    pub async fn receive_rtp(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        loop {
            let protected = tokio::select! {
                biased;
                _ = self.lifetime.ended.changed() => anyhow::bail!("This FaceTime call has ended"),
                result = self.relay.receive_routed_rtp() => result?,
            };
            if let Some(clear) = self.open_rtp(&protected)? {
                return Ok(clear);
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
    lease: Arc<()>,
    handshake: Arc<CallMediaHandshake>,
}

pub(super) struct JoinAnswer {
    id: Uuid,
    lease: Arc<()>,
    avc_plist: Vec<u8>,
    mode: CallMode,
}

pub(super) struct AnswerLifetime {
    _hangup: oneshot::Sender<()>,
    ended: watch::Receiver<()>,
}

pub(super) struct ConnectedCall {
    pub(super) call: IncomingCall,
    pub(super) endpoint: CallEndpoint,
    pub(super) relay: Arc<CallRelayAllocation>,
    pub(super) exchange: CallMediaExchange,
    local_hangup: oneshot::Receiver<()>,
    _ended: watch::Sender<()>,
}

pub(super) struct JoinReceipt {
    pub(super) call: IncomingCall,
    pub(super) endpoint: CallEndpoint,
    pub(super) relay: Arc<CallRelayAllocation>,
}

impl Engine {
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
            let attempt = self.wait_for_caller_prekey(id).await?;
            ensure!(
                config.mode != CallMode::Video
                    || attempt.handshake.call().mode != Some(CallMode::Audio),
                "An incoming FaceTime Audio call must be answered with audio"
            );
            let allocation = self.allocate_call_relay(id).await?;
            let local_keys = self.publish_call_keys(id).await?;
            let description = local_keys.seal_description(config.avc_plist, config.mode)?;
            let relay = allocation
                .connect()
                .await?
                .bind_with_description(config.relay_profile, &description)
                .await?;
            Ok::<_, anyhow::Error>((relay, local_keys, allocation.caller_participant, attempt))
        };
        let (mut relay, local_keys, caller_participant, AnswerAttempt { lease, handshake }) = tokio::select! {
            biased;
            error = wait_for_ring_to_end(self.watch_status(), id) => return Err(error),
            result = timeout(remaining, setup) => result.context("The FaceTime call expired during setup")??,
        };
        let mut peer_keys = handshake.watch_peer_keys();

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
        let mut lifetime = joined
            .await
            .context("The Apple engine stopped before joining FaceTime")??;
        // Announce our route while the IDS engine receives the peer's keys.
        let media_setup = async {
            relay.negotiate_media_path().await?;
            wait_for_media(&handshake, &mut relay, &mut peer_keys).await
        };
        let remote_description = tokio::select! {
            biased;
            _ = lifetime.ended.changed() => anyhow::bail!("This FaceTime call has ended"),
            result = timeout(MEDIA_SETUP_TIMEOUT, media_setup) =>
                result.context("The caller did not finish FaceTime media setup")??,
        };
        let rtp = CallRtpProtection::new(
            id,
            caller_participant,
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
        })
    }

    async fn wait_for_caller_prekey(&self, id: Uuid) -> Result<AnswerAttempt> {
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
                .context("The Apple engine stopped while waiting for caller keys")?;
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

async fn wait_for_media(
    handshake: &CallMediaHandshake,
    relay: &mut CallRelayBinding,
    keys: &mut watch::Receiver<CallPeerKeys>,
) -> Result<CallMediaDescription> {
    let signed_description = handshake.decode_peer_description();
    loop {
        {
            let authenticated = keys.borrow_and_update();
            if authenticated.media.is_some() {
                if let Some(description) = relay.peer_description(&authenticated)? {
                    return Ok(description);
                }
                if let Ok(description) = signed_description {
                    return Ok(description);
                }
            }
        }
        keys.changed()
            .await
            .context("This FaceTime call has ended")?;
    }
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
            self.connected.is_none()
                && self
                    .answering
                    .as_ref()
                    .and_then(|lease| lease.upgrade())
                    .is_none(),
            "A FaceTime call is already in progress"
        );
        active_call(status, id)?;
        let details = self
            .details
            .get(&id)
            .context("Missing FaceTime caller details")?;
        if details.endpoint.participant().is_none()
            || details.description.is_none()
            || details.prekey.is_none()
        {
            return Ok(None);
        }
        let handshake = self.prepare_media(status, id)?;
        let lease = Arc::new(());
        self.answering = Some(Arc::downgrade(&lease));
        Ok(Some(AnswerAttempt { lease, handshake }))
    }

    pub(super) async fn send_join(
        &self,
        identity: &Identity,
        madrid: &mut Madrid,
        status: &watch::Sender<Status>,
        answer: &JoinAnswer,
    ) -> Result<JoinReceipt> {
        ensure!(
            self.answering
                .as_ref()
                .and_then(|lease| lease.upgrade())
                .is_some_and(|lease| Arc::ptr_eq(&lease, &answer.lease)),
            "The FaceTime answer was canceled"
        );
        let call = active_call(&status.borrow(), answer.id)?.clone();
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
        let (hangup, local_hangup) = oneshot::channel();
        let (ready, ended) = watch::channel(());
        let id = call.id;
        self.connected = Some(ConnectedCall {
            call,
            endpoint: receipt.endpoint,
            relay: receipt.relay.clone(),
            exchange,
            local_hangup,
            _ended: ready,
        });
        status.send_modify(|status| status.incoming_calls.retain(|candidate| candidate.id != id));
        Ok(AnswerLifetime {
            _hangup: hangup,
            ended,
        })
    }

    pub(super) async fn wait_for_local_hangup(&mut self) {
        match &mut self.connected {
            Some(connected) => {
                let _ = (&mut connected.local_hangup).await;
            }
            None => pending().await,
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
        assert!(incoming.begin_answer(&reader.borrow(), id)?.is_none());
        incoming.update(
            &status,
            own,
            CallSignal::Prekey {
                id,
                sender: caller.to_owned(),
                endpoint: CallEndpoint::new([2; 32], None),
                key: prekey.clone(),
            },
        );
        assert!(reader.has_changed()?);
        let attempt = incoming
            .begin_answer(&reader.borrow(), id)?
            .context("missing answer reservation")?;
        assert!(incoming.begin_answer(&reader.borrow(), id).is_err());
        let mut lifetime = incoming.finish_answer(&status, &receipt)?;
        drop(attempt);
        assert!(reader.borrow().incoming_calls.is_empty());
        status.send_modify(|status| {
            incoming.expire(status, call.expires_ms + 1);
        });
        incoming.update(&status, own, ring());
        incoming.update(&status, own, end(None));
        incoming.update(
            &status,
            own,
            end(Some(CallEndpoint::new([3; 32], endpoint.participant()))),
        );
        assert!(incoming.connected.is_some());
        assert!(reader.borrow().incoming_calls.is_empty());
        assert!(lifetime.ended.has_changed().is_ok());
        incoming.update(&status, own, end(Some(endpoint)));
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
