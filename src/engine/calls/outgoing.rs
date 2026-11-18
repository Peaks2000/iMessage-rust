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
        RING_TIMEOUT_MS, RingingRelay,
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
    answered: oneshot::Receiver<Result<()>>,
    relay: Arc<OutgoingRelay>,
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
    answered: Option<oneshot::Sender<Result<()>>>,
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
            } if endpoint.participant().is_some()
                && response.received_ms >= call.received_ms
                && device.description.is_none() =>
            {
                // The recipient may answer a video invitation with audio.
                let description = CallMediaDescription::parse(&media.description, response.mode);
                let Ok(description) = description else { return };
                let video = call.mode == Some(CallMode::Video)
                    && response.mode != Some(CallMode::Audio)
                    && description.video.is_some();
                device.mode = Some(if video {
                    CallMode::Video
                } else {
                    CallMode::Audio
                });
                device.description = Some(media.description);
                // Prefer the prekey in the signed participant update over a standalone prekey.
                if media.prekey.is_some() {
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
        if device.prekey.is_some() && device.description.is_some() {
            self.selected = Some(index);
        }
    }

    fn outcome(&self) -> Option<Result<()>> {
        if self
            .selected
            .is_some_and(|index| !self.devices[index].ended)
        {
            Some(Ok(()))
        } else if self.devices.iter().all(|device| device.ended) {
            Some(Err(anyhow::anyhow!("The FaceTime call was declined")))
        } else {
            None
        }
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
        if let Some(result) = self.responses.outcome()
            && let Some(reply) = self.answered.take()
        {
            if result.is_ok() {
                self.call.expires_ms = now_ms() + MEDIA_SETUP_TIMEOUT.as_millis() as i64;
            }
            let _ = reply.send(result);
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

    pub(in crate::engine) async fn cancel(mut self, identity: &Identity, madrid: &mut Madrid) {
        if let Some(answered) = self.answered.take() {
            let _ = answered.send(Err(anyhow::anyhow!("The FaceTime call was not answered")));
        }
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
        let targets = tokio::select! {
            biased;
            _ = reply.closed() => anyhow::bail!("The FaceTime call was canceled"),
            result = madrid.outgoing_call_targets(identity, &call) => result?,
        };
        ensure!(!reply.is_closed(), "The FaceTime call was canceled");
        let (hangup, cancel) = oneshot::channel();
        let (answer, answered) = oneshot::channel();
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
            answered: Some(answer),
        });
        Ok(OutgoingAttempt {
            id,
            _cancel: hangup,
            answered,
            relay,
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
    ) -> Result<OutgoingAnswer> {
        let pending = self
            .outgoing
            .as_mut()
            .filter(|outgoing| outgoing.invited && outgoing.call.id == id)
            .context("The FaceTime call has ended")?;
        pending.check_live()?;
        let selected = pending
            .responses
            .selected
            .filter(|&index| !pending.responses.devices[index].ended)
            .context("The other device left the FaceTime call")?;
        let device = &pending.responses.devices[selected];
        let relay = Arc::new(pending.targets.relay.for_peer(device.endpoint)?);
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
            answered,
            relay,
        } = attempt
            .await
            .context("The Apple engine stopped while placing the call")??;
        let mut pending_relay = timeout(
            MEDIA_SETUP_TIMEOUT,
            relay.bind_for_ringing(config.relay_profile),
        )
        .await
        .context("The FaceTime relay did not bind before ringing")??;
        let answer = self.ring_and_wait(id, answered, &mut pending_relay).await;
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
            result = timeout(MEDIA_SETUP_TIMEOUT, pending_relay.join(endpoint, &description)) =>
                result.context("The FaceTime relay did not confirm the media offer")??,
        };
        complete_media(
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
        mut answered: oneshot::Receiver<Result<()>>,
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
            tokio::select! {
                biased;
                result = &mut answered => {
                    result.context("The FaceTime call has ended")??;
                    break;
                }
                _ = keepalive.tick() => relay.keepalive().await?,
                result = relay.service_during_ring() => result?,
            }
        }
        let (reply, result) = oneshot::channel();
        self.requests
            .try_send(Request::FinishOutgoing { id, reply })
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
        assert!(responses.outcome().is_none());

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
        assert!(responses.outcome().is_none());
        responses.receive(&call, decline(CallEndpoint::new([2; 32], None)));
        assert!(responses.outcome().is_none());
        responses.receive(
            &call,
            CallSignal::Prekey {
                id: call.id,
                sender: call.caller.clone(),
                endpoint: CallEndpoint::new([3; 32], None),
                key: prekey.clone(),
            },
        );
        assert!(responses.outcome().is_some_and(|result| result.is_ok()));
        assert_eq!(responses.selected, Some(1));
        assert_eq!(responses.devices[1].mode, Some(CallMode::Audio));
        responses.receive(&call, answer(first, &call.caller, Some(prekey))?);
        responses.receive(&call, decline(CallEndpoint::new([3; 32], None)));
        assert!(responses.outcome().is_some_and(|result| result.is_ok()));
        responses.receive(&call, decline(second));
        assert!(responses.outcome().is_some_and(|result| result.is_err()));
        Ok(())
    }
}
