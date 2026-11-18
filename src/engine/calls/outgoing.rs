use anyhow::{Context, Result, ensure};
use tokio::{
    sync::{oneshot, watch},
    time::{sleep, timeout},
};

use super::*;
use crate::{
    address,
    apple::{
        CallSignal, LocalCallPrekey, OutgoingCallTargets, OutgoingRelay, PeerKeyOffer, PeerPrekey,
        RING_TIMEOUT_MS, RingingRelay, SignedRelayPrekey,
    },
};

pub(in crate::engine) struct DialRequest {
    pub(in crate::engine) recipient: String,
    pub(in crate::engine) mode: CallMode,
    pub(in crate::engine) avc: Vec<u8>,
}

pub(in crate::engine) struct OutgoingAttempt {
    id: Uuid,
    _cancel: oneshot::Sender<()>,
    progress: watch::Receiver<OutgoingProgress>,
    relay: Arc<OutgoingRelay>,
    relay_prekey: Option<SignedRelayPrekey>,
}

#[derive(Clone)]
enum OutgoingProgress {
    Ringing,
    Accepted {
        endpoint: CallEndpoint,
        allocation: Arc<CallRelayAllocation>,
        has_prekey: bool,
    },
    Ended(&'static str),
}

pub(in crate::engine) struct OutgoingAnswer {
    handshake: Arc<CallMediaHandshake>,
    endpoint: CallEndpoint,
    local_keys: Arc<CallKeyOffer>,
    lifetime: AnswerLifetime,
}

pub(in crate::engine) struct PendingOutgoing {
    pub(in crate::engine) call: IncomingCall,
    targets: OutgoingCallTargets,
    local: LocalCallPrekey,
    avc: Vec<u8>,
    invited: bool,
    responses: RingResponses,
    cancel: oneshot::Receiver<()>,
    progress: watch::Sender<OutgoingProgress>,
}

struct RingResponses {
    devices: Vec<RingingDevice>,
    selected: Option<usize>,
}

struct RingingDevice {
    endpoint: CallEndpoint,
    prekey: Option<PeerPrekey>,
    description: Option<Vec<u8>>,
    mode: Option<CallMode>,
    keys: Vec<PeerKeyOffer>,
    ended: bool,
}

impl RingingDevice {
    fn learn_relay_prekey(&mut self, source: CallEndpoint, prekey: PeerPrekey) -> Result<()> {
        ensure!(
            source == self.endpoint && !self.ended && self.description.is_some(),
            "The FaceTime prekey belongs to a different device or call"
        );
        self.prekey.get_or_insert(prekey);
        Ok(())
    }
}

impl RingResponses {
    fn new(endpoints: &[CallEndpoint]) -> Self {
        Self {
            devices: endpoints
                .iter()
                .map(|&endpoint| RingingDevice {
                    endpoint,
                    prekey: None,
                    description: None,
                    mode: None,
                    keys: Vec::new(),
                    ended: false,
                })
                .collect(),
            selected: None,
        }
    }

    fn receive(&mut self, call: &IncomingCall, signal: CallSignal) {
        if signal.id() != call.id || now_ms() >= call.expires_ms {
            return;
        }
        let (sender, endpoint) = match &signal {
            CallSignal::Accepted { call, endpoint, .. } => (&call.caller, *endpoint),
            CallSignal::Prekey {
                sender, endpoint, ..
            }
            | CallSignal::MediaKeys {
                sender, endpoint, ..
            }
            | CallSignal::End {
                sender,
                endpoint: Some(endpoint),
                ..
            } => (sender, *endpoint),
            _ => return,
        };
        if sender != &call.caller {
            return;
        }
        let Some(index) = self.devices.iter().position(|candidate| {
            if endpoint.participant().is_some() {
                candidate.endpoint.matches(endpoint)
            } else {
                candidate.endpoint.same_device(endpoint)
            }
        }) else {
            return;
        };
        if self.selected.is_some_and(|selected| selected != index) {
            return;
        }
        let device = &mut self.devices[index];
        if device.ended {
            return;
        }
        match signal {
            CallSignal::Accepted {
                call: response,
                media,
                ..
            } if endpoint.participant().is_some() && response.received_ms >= call.received_ms => {
                if device.description.is_none() {
                    // The recipient may answer a video invitation with audio.
                    let description =
                        CallMediaDescription::parse(&media.description, response.mode).ok();
                    let video = call.mode == Some(CallMode::Video)
                        && match response.mode {
                            Some(CallMode::Video) => true,
                            Some(CallMode::Audio) => false,
                            None => {
                                description.is_some_and(|description| description.video.is_some())
                            }
                        };
                    device.mode = Some(if video {
                        CallMode::Video
                    } else {
                        CallMode::Audio
                    });
                    device.description = Some(media.description);
                    // Prefer the initial participant update over a standalone prekey.
                    device.prekey = media.prekey.or(device.prekey.take());
                } else if device.prekey.is_none() {
                    device.prekey = media.prekey;
                }
            }
            CallSignal::Prekey { key, .. } if device.prekey.is_none() => device.prekey = Some(key),
            CallSignal::MediaKeys { offer, .. } if device.keys.len() < 4 => {
                device.keys.push(*offer)
            }
            CallSignal::End { received_ms, .. }
                if received_ms >= call.received_ms
                    && (self.selected.is_none() || endpoint.participant().is_some()) =>
            {
                device.ended = true;
                device.keys.clear();
                device.prekey = None;
                device.description = None;
            }
            _ => (),
        }
        if device.description.is_some() {
            self.selected = Some(index);
        }
    }

    fn selected(&self) -> Option<&RingingDevice> {
        self.selected.map(|index| &self.devices[index])
    }
}

impl PendingOutgoing {
    fn check_live(&mut self) -> Result<()> {
        ensure!(
            matches!(
                self.cancel.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ) && self.call.expires_ms > now_ms(),
            "The FaceTime call has ended"
        );
        Ok(())
    }

    pub(in crate::engine) fn receive(&mut self, signal: CallSignal) {
        if !self.invited {
            return;
        }
        self.responses.receive(&self.call, signal);
        self.progress.send_if_modified(|progress| {
            let selected = self.responses.selected();
            let replacement = match (&mut *progress, selected) {
                (OutgoingProgress::Ringing, Some(device)) => {
                    let Ok(allocation) = self
                        .targets
                        .allocation_for_peer(&self.call.caller, device.endpoint)
                    else {
                        *progress =
                            OutgoingProgress::Ended("The FaceTime answering device is unavailable");
                        return true;
                    };
                    self.call.expires_ms = now_ms() + MEDIA_SETUP_TIMEOUT.as_millis() as i64;
                    OutgoingProgress::Accepted {
                        endpoint: device.endpoint,
                        allocation: Arc::new(allocation),
                        has_prekey: device.prekey.is_some(),
                    }
                }
                (OutgoingProgress::Ringing, None)
                    if self.responses.devices.iter().all(|device| device.ended) =>
                {
                    OutgoingProgress::Ended("The FaceTime call was declined")
                }
                (OutgoingProgress::Accepted { .. }, Some(device)) if device.ended => {
                    OutgoingProgress::Ended("The other device left the FaceTime call")
                }
                (OutgoingProgress::Accepted { has_prekey, .. }, Some(device))
                    if !*has_prekey && device.prekey.is_some() =>
                {
                    *has_prekey = true;
                    return true;
                }
                _ => return false,
            };
            *progress = replacement;
            true
        });
    }

    fn timed_out(&self) -> &'static str {
        match *self.progress.borrow() {
            OutgoingProgress::Ringing => "The FaceTime call was not answered",
            OutgoingProgress::Accepted { .. } => "The FaceTime call ran out of time during setup",
            OutgoingProgress::Ended(reason) => reason,
        }
    }

    fn authenticated_peer(&self) -> Result<(CallEndpoint, Arc<CallRelayAllocation>)> {
        match &*self.progress.borrow() {
            OutgoingProgress::Accepted {
                endpoint,
                allocation,
                ..
            } => Ok((*endpoint, allocation.clone())),
            OutgoingProgress::Ended(reason) => anyhow::bail!("{reason}"),
            OutgoingProgress::Ringing => anyhow::bail!("The other device has not answered"),
        }
    }

    pub(in crate::engine) async fn wait_to_cancel(&mut self) {
        if self.cancel.is_terminated() {
            return;
        }
        let remaining =
            Duration::from_millis(self.call.expires_ms.saturating_sub(now_ms()).max(0) as u64);
        tokio::select! {
            _ = &mut self.cancel => (),
            () = sleep(remaining) => (),
        }
    }

    pub(in crate::engine) async fn cancel(self, identity: &Identity, madrid: &mut Madrid) {
        self.progress
            .send_replace(OutgoingProgress::Ended(self.timed_out()));
        if self.invited {
            let _ = madrid
                .send_outgoing_call(identity, &self.call, &self.targets, None)
                .await;
        }
    }
}

impl IncomingCalls {
    pub(in crate::engine) async fn begin_outgoing(
        &mut self,
        identity: &Identity,
        madrid: &mut Madrid,
        status: &watch::Sender<Status>,
        dial: DialRequest,
        mut reply: oneshot::Sender<Result<OutgoingAttempt>>,
    ) {
        let result = self
            .prepare_outgoing(identity, madrid, status, dial, &mut reply)
            .await;
        let _ = reply.send(result);
    }

    async fn prepare_outgoing(
        &mut self,
        identity: &Identity,
        madrid: &mut Madrid,
        status: &watch::Sender<Status>,
        dial: DialRequest,
        reply: &mut oneshot::Sender<Result<OutgoingAttempt>>,
    ) -> Result<OutgoingAttempt> {
        ensure!(
            status.borrow().facetime_registered,
            "This Apple session has no FaceTime registration"
        );
        ensure!(
            !self.call_in_progress(),
            "A FaceTime call is already in progress"
        );
        let received_ms = now_ms();
        let call = IncomingCall {
            id: Uuid::new_v4(),
            caller: dial.recipient,
            mode: Some(dial.mode),
            received_ms,
            expires_ms: received_ms + RING_TIMEOUT_MS,
        };
        let local = LocalCallPrekey::generate()?;
        let relay_prekey = identity.sign_relay_prekey(call.id, local.public())?;
        let targets = tokio::select! {
            biased;
            _ = reply.closed() => anyhow::bail!("The FaceTime call was canceled"),
            result = madrid.outgoing_call_targets(identity, &call) => result?,
        };
        ensure!(!reply.is_closed(), "The FaceTime call was canceled");
        let (hangup, cancel) = oneshot::channel();
        let (updates, progress) = watch::channel(OutgoingProgress::Ringing);
        let id = call.id;
        let relay = targets.relay.clone();
        self.outgoing = Some(PendingOutgoing {
            call,
            responses: RingResponses::new(targets.relay.endpoints()),
            targets,
            local,
            avc: dial.avc,
            invited: false,
            cancel,
            progress: updates,
        });
        Ok(OutgoingAttempt {
            id,
            _cancel: hangup,
            progress,
            relay,
            relay_prekey,
        })
    }

    pub(in crate::engine) async fn ring_outgoing(
        &mut self,
        identity: &Identity,
        madrid: &mut Madrid,
        id: Uuid,
    ) -> Result<()> {
        let pending = self
            .outgoing
            .as_mut()
            .filter(|outgoing| !outgoing.invited && outgoing.call.id == id)
            .context("The FaceTime invitation is unavailable")?;
        pending.check_live()?;
        let mode = pending.call.mode.context("Missing FaceTime call mode")?;
        pending.call.received_ms = now_ms();
        pending.call.expires_ms = pending.call.received_ms + RING_TIMEOUT_MS;
        // A rejected send can still have reached a recipient if delivery stopped partway.
        pending.invited = true;
        madrid
            .send_outgoing_call(
                identity,
                &pending.call,
                &pending.targets,
                Some((&pending.avc, pending.local.public(), mode)),
            )
            .await
    }

    pub(in crate::engine) async fn finish_outgoing(
        &mut self,
        identity: &Identity,
        madrid: &mut Madrid,
        id: Uuid,
        relay_prekey: Option<(CallEndpoint, PeerPrekey)>,
    ) -> Result<OutgoingAnswer> {
        let pending = self
            .outgoing
            .as_mut()
            .filter(|outgoing| outgoing.invited && outgoing.call.id == id)
            .context("The FaceTime call has ended")?;
        pending.check_live()?;
        let (endpoint, relay) = pending.authenticated_peer()?;
        let selected = pending
            .responses
            .selected
            .filter(|&index| !pending.responses.devices[index].ended)
            .context("The other device left the FaceTime call")?;
        let device = &mut pending.responses.devices[selected];
        ensure!(
            device.endpoint == endpoint,
            "The FaceTime answering device changed"
        );
        if let Some((source, prekey)) = relay_prekey {
            device.learn_relay_prekey(source, prekey)?;
        }
        ensure!(device.prekey.is_some(), "Missing FaceTime media prekey");
        let pending = self
            .outgoing
            .take()
            .context("The FaceTime call has ended")?;
        let PendingOutgoing {
            mut call,
            local,
            mut responses,
            ..
        } = pending;
        let device = responses.devices.swap_remove(selected);
        call.mode = device.mode;
        let exchange = CallMediaExchange::with_prekey(
            call.clone(),
            &device
                .description
                .context("Missing FaceTime media description")?,
            &device.prekey.context("Missing FaceTime media prekey")?,
            local,
        );
        for offer in device.keys {
            let _ = exchange.receive(offer);
        }
        let handshake = exchange.handshake.clone();
        let lifetime = self.connect_call(call, device.endpoint, relay.clone(), exchange, true);
        let local_keys = Arc::new(handshake.build_key_offer(relay.local_participant)?);
        madrid
            .publish_call_keys(identity, &handshake, device.endpoint, &local_keys)
            .await?;
        Ok(OutgoingAnswer {
            handshake,
            endpoint: device.endpoint,
            local_keys,
            lifetime,
        })
    }
}

impl Engine {
    /// Place a call using the local Apple session and Linux desktop media configuration.
    #[cfg(feature = "desktop")]
    pub async fn dial_desktop_call(&self, recipient: &str, mode: CallMode) -> Result<AnsweredCall> {
        let device = self
            .call_device
            .as_ref()
            .context("The local Apple session has no FaceTime device profile")?;
        let avc = device.description(mode)?;
        self.dial_call(recipient, CallAnswerConfig::desktop(device, &avc, mode))
            .await
    }

    /// Ring a recipient and open an authenticated FaceTime audio or video call.
    pub async fn dial_call(
        &self,
        recipient: &str,
        config: CallAnswerConfig<'_>,
    ) -> Result<AnsweredCall> {
        let recipient = address(recipient)?;
        let mut local_description =
            CallMediaDescription::parse(config.avc_plist, Some(config.mode))?;
        ensure!(
            config.mode != CallMode::Video || local_description.video.is_some(),
            "FaceTime video needs a camera stream"
        );
        let dial = DialRequest {
            recipient,
            mode: config.mode,
            avc: config.avc_plist.to_vec(),
        };
        let (reply, attempt) = oneshot::channel();
        self.requests
            .try_send(Request::DialCall { dial, reply })
            .context("The Apple engine is busy or stopped")?;
        let OutgoingAttempt {
            id,
            _cancel,
            progress,
            relay,
            relay_prekey,
        } = attempt
            .await
            .context("The Apple engine stopped while placing the call")??;
        let mut pending_relay = timeout(
            MEDIA_SETUP_TIMEOUT,
            relay.bind_for_ringing(config.relay_profile, relay_prekey),
        )
        .await
        .context("The FaceTime relay did not bind before ringing")??;
        let answer = self.ring_and_wait(id, progress, &mut pending_relay).await;
        drop(_cancel);
        let OutgoingAnswer {
            handshake,
            endpoint,
            local_keys,
            mut lifetime,
        } = match answer {
            Ok(answer) => answer,
            Err(error) => {
                let _ = pending_relay.unbind().await;
                return Err(error);
            }
        };
        let mode = handshake
            .call()
            .mode
            .context("The other device did not select a call mode")?;
        local_description.mode = Some(mode);
        let description = local_keys.seal_description(config.avc_plist, mode)?;
        let bound = tokio::select! {
            biased;
            _ = lifetime.ended.changed() => anyhow::bail!("The FaceTime call has ended"),
            result = timeout(MEDIA_SETUP_TIMEOUT, pending_relay.join(&description)) =>
                result.context("The FaceTime relay did not confirm the media offer")??,
        };
        complete_media(
            self,
            handshake,
            bound,
            local_keys,
            local_description,
            endpoint
                .participant()
                .context("Missing FaceTime peer participant")?,
            lifetime,
        )
        .await
    }

    async fn ring_and_wait(
        &self,
        id: Uuid,
        mut progress: watch::Receiver<OutgoingProgress>,
        relay: &mut RingingRelay,
    ) -> Result<OutgoingAnswer> {
        let (reply, result) = oneshot::channel();
        self.requests
            .try_send(Request::RingOutgoing { id, reply })
            .context("The Apple engine is busy or stopped")?;
        result
            .await
            .context("The Apple engine stopped while ringing")??;

        let interval = Duration::from_secs(15);
        let mut keepalive =
            tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            match progress.borrow_and_update().clone() {
                OutgoingProgress::Ringing => (),
                OutgoingProgress::Accepted {
                    endpoint,
                    allocation,
                    ..
                } => {
                    relay.select_peer(endpoint, &allocation)?;
                    break;
                }
                OutgoingProgress::Ended(reason) => anyhow::bail!("{reason}"),
            }
            tokio::select! {
                biased;
                result = progress.changed() => result.context("The FaceTime call has ended")?,
                _ = keepalive.tick() => relay.keepalive().await?,
                result = relay.service_during_ring() => result?,
            }
        }
        let mut can_read_relay = true;
        let relay_prekey = loop {
            let endpoint = match *progress.borrow_and_update() {
                OutgoingProgress::Accepted {
                    has_prekey: true, ..
                } => break None,
                OutgoingProgress::Accepted {
                    endpoint,
                    has_prekey: false,
                    ..
                } => endpoint,
                OutgoingProgress::Ended(reason) => anyhow::bail!("{reason}"),
                OutgoingProgress::Ringing => anyhow::bail!("The other device has not answered"),
            };
            tokio::select! {
                biased;
                result = progress.changed() => result.context("The FaceTime call has ended")?,
                result = relay.wait_for_peer_prekey(), if can_read_relay => {
                    if let Some(prekey) = result.ok().flatten() {
                        break Some((endpoint, prekey));
                    }
                    can_read_relay = false;
                }
            }
        };
        let (reply, result) = oneshot::channel();
        self.requests
            .try_send(Request::FinishOutgoing {
                id,
                relay_prekey,
                reply,
            })
            .context("The Apple engine is busy or stopped")?;
        result
            .await
            .context("The Apple engine stopped while joining the call")?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apple::{PeerMediaOffer, signed_avc_fixture};

    #[test]
    fn outbound_audio_fallback_uses_prekey_and_answer_from_one_allocated_device() -> Result<()> {
        let first = CallEndpoint::new([2; 32], Some(22));
        let second = CallEndpoint::new([3; 32], Some(33));
        let mut responses = RingResponses::new(&[first, second]);
        let received_ms = now_ms();
        let call = IncomingCall {
            id: Uuid::new_v4(),
            caller: "mailto:recipient@example.org".to_owned(),
            mode: Some(CallMode::Video),
            received_ms,
            expires_ms: received_ms + 45_000,
        };
        let key = LocalCallPrekey::generate()?;
        let prekey = PeerPrekey::parse(1, key.public())?;
        let answer = |endpoint, caller: &str, key| -> Result<_> {
            Ok(CallSignal::Accepted {
                call: IncomingCall {
                    caller: caller.to_owned(),
                    mode: Some(CallMode::Audio),
                    ..call.clone()
                },
                endpoint,
                media: PeerMediaOffer {
                    description: signed_avc_fixture()?,
                    prekey: key,
                },
            })
        };
        let decline = |endpoint| CallSignal::End {
            id: call.id,
            sender: call.caller.clone(),
            received_ms,
            endpoint: Some(endpoint),
        };
        responses.receive(
            &call,
            answer(
                CallEndpoint::new([2; 32], Some(33)),
                &call.caller,
                Some(prekey.clone()),
            )?,
        );
        responses.receive(
            &call,
            answer(first, "mailto:other@example.org", Some(prekey.clone()))?,
        );
        responses.receive(
            &call,
            answer(
                CallEndpoint::new([2; 32], None),
                &call.caller,
                Some(prekey.clone()),
            )?,
        );
        assert!(responses.selected().is_none());

        responses.receive(&call, answer(second, &call.caller, None)?);
        responses.receive(
            &call,
            CallSignal::Prekey {
                id: call.id,
                sender: call.caller.clone(),
                endpoint: CallEndpoint::new([2; 32], None),
                key: prekey.clone(),
            },
        );
        let selected = responses
            .selected()
            .context("Missing authenticated answer")?;
        assert!(selected.endpoint == second);
        assert!(selected.prekey.is_none());
        let selected = &mut responses.devices[1];
        assert!(selected.learn_relay_prekey(first, prekey.clone()).is_err());
        assert!(selected.prekey.is_none());
        selected.learn_relay_prekey(second, prekey.clone())?;
        let conflicting = LocalCallPrekey::generate()?;
        responses.receive(&call, decline(CallEndpoint::new([2; 32], None)));
        responses.receive(
            &call,
            CallSignal::Prekey {
                id: call.id,
                sender: call.caller.clone(),
                endpoint: CallEndpoint::new([3; 32], None),
                key: PeerPrekey::parse(1, conflicting.public())?,
            },
        );
        assert_eq!(responses.selected, Some(1));
        let selected = responses.selected().context("Missing selected device")?;
        assert_eq!(selected.mode, Some(CallMode::Audio));
        assert!(
            selected
                .prekey
                .as_ref()
                .is_some_and(|key| key.same_as(&prekey))
        );
        responses.receive(&call, answer(first, &call.caller, Some(prekey))?);
        responses.receive(&call, decline(CallEndpoint::new([3; 32], None)));
        assert!(
            !responses
                .selected()
                .context("Missing selected device")?
                .ended
        );
        responses.receive(&call, decline(second));
        assert!(
            responses
                .selected()
                .context("Missing selected device")?
                .ended
        );
        Ok(())
    }
}
