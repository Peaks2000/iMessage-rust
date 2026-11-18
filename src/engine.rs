mod calls;

use calls::outgoing::{DialRequest, OutgoingAnswer, OutgoingAttempt, PendingOutgoing};
#[cfg(feature = "desktop")]
pub use calls::video;
use calls::{
    AnswerAttempt, AnswerLease, AnswerLifetime, CallKeyDelivery, ConnectedCall, CourierKeyDelivery,
    JoinAnswer,
};
pub use calls::{AnsweredCall, CallAnswerConfig};

use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use tokio::{
    sync::{mpsc, oneshot, watch},
    time::sleep,
};

use crate::media::MediaSource;
use crate::{
    Conversation, Delivery, FILE_LIMIT, MAX_ATTACHMENTS, Message, SendText, SetTapback, Status,
    TEXT_LIMIT, Tapback, TapbackEvent, TapbackKind, address, now_ms, now_ns,
};
use crate::{
    apple::{
        CallEndpoint, CallKeyOffer, CallMediaExchange, CallMediaHandshake, CallRelayAllocation,
        CallSignal, Identity, Incoming, LocalCallPrekey, Madrid, Notification, PeerMediaOffer,
        PeerPrekey,
    },
    history::History,
};

#[derive(Clone)]
pub struct Engine {
    state: Arc<State>,
    requests: mpsc::Sender<Request>,
    status: watch::Receiver<Status>,
    #[cfg(feature = "desktop")]
    call_device: Option<Arc<crate::apple::CallDevice>>,
}

struct State {
    history: Mutex<History>,
    _lock: File,
}

enum Request {
    Send(SendText, oneshot::Sender<Result<Message>>),
    Tapback {
        target: uuid::Uuid,
        request: SetTapback,
        reply: oneshot::Sender<Result<Vec<Tapback>>>,
    },
    DeclineCall {
        id: uuid::Uuid,
        reply: oneshot::Sender<Result<()>>,
    },
    PrepareCallMedia {
        id: uuid::Uuid,
        reply: oneshot::Sender<Result<Arc<CallMediaHandshake>>>,
    },
    AllocateCallRelay {
        id: uuid::Uuid,
        reply: oneshot::Sender<Result<Arc<CallRelayAllocation>>>,
    },
    PublishCallKeys {
        id: uuid::Uuid,
        reply: oneshot::Sender<Result<CallKeyDelivery>>,
    },
    BeginCallAnswer {
        id: uuid::Uuid,
        reply: oneshot::Sender<Result<Option<AnswerAttempt>>>,
    },
    ResolveAnswerMedia {
        id: uuid::Uuid,
        lease: Arc<AnswerLease>,
        relay_prekey: Option<PeerPrekey>,
        reply: oneshot::Sender<Result<Option<Arc<CallMediaHandshake>>>>,
    },
    JoinCall {
        answer: JoinAnswer,
        reply: oneshot::Sender<Result<AnswerLifetime>>,
    },
    DialCall {
        dial: DialRequest,
        reply: oneshot::Sender<Result<OutgoingAttempt>>,
    },
    RingOutgoing {
        id: uuid::Uuid,
        reply: oneshot::Sender<Result<()>>,
    },
    FinishOutgoing {
        id: uuid::Uuid,
        relay_prekey: Option<(CallEndpoint, PeerPrekey)>,
        reply: oneshot::Sender<Result<OutgoingAnswer>>,
    },
    InstallRelayKeys {
        id: uuid::Uuid,
        offer: Box<crate::apple::PeerKeyOffer>,
        reply: oneshot::Sender<()>,
    },
    Download {
        id: uuid::Uuid,
        index: usize,
        reply: oneshot::Sender<Result<bytes::Bytes>>,
    },
}

impl Engine {
    pub fn start(root: &Path, identity: Identity) -> Result<Self> {
        let profile = identity.profile_id();
        let lock = OpenOptions::new()
            .mode(0o600)
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(root.join(format!("{profile}.lock")))?;
        fs2::FileExt::try_lock_exclusive(&lock).context("This profile is already open. Connect through the running server or close the other instance")?;
        let state = Arc::new(State {
            history: Mutex::new(History::open(root, &profile)?),
            _lock: lock,
        });
        state.history()?.recover()?;
        let (updates, status) = watch::channel(Status {
            connected: false,
            detail: "Connecting to Apple…".into(),
            tapback_revision: None,
            facetime_registered: identity.facetime_registered(),
            incoming_calls: Vec::new(),
        });
        let (requests, receiver) = mpsc::channel(16);
        #[cfg(feature = "desktop")]
        let call_device = identity.call_device().map(Arc::new);
        tokio::spawn(run_apple(identity, state.clone(), receiver, updates));
        Ok(Self {
            state,
            requests,
            status,
            #[cfg(feature = "desktop")]
            call_device,
        })
    }

    pub fn status(&self) -> Status {
        let mut status = self.status.borrow().clone();
        let now = now_ms();
        status.incoming_calls.retain(|call| call.expires_ms > now);
        status
    }

    pub fn watch_status(&self) -> watch::Receiver<Status> {
        self.status.clone()
    }

    pub fn chats(&self) -> Result<Vec<Conversation>> {
        self.state.history()?.chats()
    }

    pub fn messages(&self, chat: &str, offset: u32) -> Result<Vec<Message>> {
        self.state.history()?.messages(&address(chat)?, offset)
    }

    pub fn delete_conversation(&self, chat: &str) -> Result<()> {
        self.state.history()?.delete_conversation(&address(chat)?)
    }

    pub async fn set_tapback(
        &self,
        target: uuid::Uuid,
        reaction: Option<TapbackKind>,
    ) -> Result<Vec<Tapback>> {
        self.set_message_tapback(
            target,
            SetTapback {
                reaction,
                part: None,
            },
        )
        .await
    }

    pub async fn set_message_tapback(
        &self,
        target: uuid::Uuid,
        request: SetTapback,
    ) -> Result<Vec<Tapback>> {
        if let Some(kind) = &request.reaction {
            kind.validate()?;
        }
        let (reply, answer) = oneshot::channel();
        self.requests
            .try_send(Request::Tapback {
                target,
                request,
                reply,
            })
            .context("The Apple engine is busy or stopped")?;
        answer
            .await
            .context("The Apple engine stopped during the reaction")?
    }

    pub async fn decline_call(&self, id: uuid::Uuid) -> Result<()> {
        let (reply, answer) = oneshot::channel();
        self.requests
            .try_send(Request::DeclineCall { id, reply })
            .context("The Apple engine is busy or stopped")?;
        answer
            .await
            .context("The Apple engine stopped during the call response")?
    }

    /// Prepare ephemeral key material for a verified, still-ringing call.
    /// Callers should invoke this after an explicit local answer action.
    pub async fn prepare_call_media(&self, id: uuid::Uuid) -> Result<Arc<CallMediaHandshake>> {
        let (reply, answer) = oneshot::channel();
        self.requests
            .try_send(Request::PrepareCallMedia { id, reply })
            .context("The Apple engine is busy or stopped")?;
        answer
            .await
            .context("The Apple engine stopped during media preparation")?
    }

    /// Obtain the relay allocated by Apple for the caller after an explicit local answer action.
    pub async fn allocate_call_relay(&self, id: uuid::Uuid) -> Result<Arc<CallRelayAllocation>> {
        let (reply, answer) = oneshot::channel();
        self.requests
            .try_send(Request::AllocateCallRelay { id, reply })
            .context("The Apple engine is busy or stopped")?;
        answer
            .await
            .context("The Apple engine stopped during relay allocation")?
    }

    /// Exchange the local prekey and wrapped keys with the verified device on a ringing call.
    /// Use this after the local answer action has prepared media and obtained a relay.
    pub async fn publish_call_keys(&self, id: uuid::Uuid) -> Result<Arc<CallKeyOffer>> {
        let delivery = self.prepare_key_delivery(id).await?;
        let offer = delivery.offer.clone();
        delivery.wait_for_ids().await?;
        Ok(offer)
    }

    async fn prepare_key_delivery(&self, id: uuid::Uuid) -> Result<CallKeyDelivery> {
        let (reply, answer) = oneshot::channel();
        self.requests
            .try_send(Request::PublishCallKeys { id, reply })
            .context("The Apple engine is busy or stopped")?;
        answer
            .await
            .context("The Apple engine stopped while exchanging keys")?
    }

    pub async fn send(&self, mut request: SendText) -> Result<Message> {
        request.address = address(&request.address)?;
        ensure!(
            (!request.body.trim().is_empty() || !request.files.is_empty())
                && request.body.len() <= TEXT_LIMIT
                && !request.body.contains('\0'),
            "Enter up to {TEXT_LIMIT} UTF-8 bytes or add an attachment"
        );
        ensure!(
            request.files.len() <= MAX_ATTACHMENTS,
            "Too many attachments"
        );
        for file in &mut request.files {
            file.validate()?;
            file.info.part = None;
        }
        ensure!(
            request
                .files
                .iter()
                .map(|file| file.info.size)
                .sum::<usize>()
                <= FILE_LIMIT,
            "A message can contain up to 32 MiB of attachments"
        );
        let (reply, answer) = oneshot::channel();
        self.requests
            .try_send(Request::Send(request, reply))
            .context("The Apple engine is busy or stopped")?;
        answer
            .await
            .context("The Apple engine stopped during the request")?
    }

    pub async fn attachment(&self, id: uuid::Uuid, index: usize) -> Result<bytes::Bytes> {
        let (_, source) = self.state.history()?.attachment(id, index)?;
        if let MediaSource::Local(bytes) = source {
            return Ok(bytes);
        }
        let (reply, answer) = oneshot::channel();
        self.requests
            .try_send(Request::Download { id, index, reply })
            .context("The Apple engine is busy or stopped")?;
        answer
            .await
            .context("The Apple engine stopped during the download")?
    }
}

impl State {
    fn history(&self) -> Result<MutexGuard<'_, History>> {
        self.history
            .lock()
            .map_err(|_| anyhow::anyhow!("Local conversation history is unavailable"))
    }
}

async fn run_apple(
    identity: Identity,
    state: Arc<State>,
    mut requests: mpsc::Receiver<Request>,
    status: watch::Sender<Status>,
) {
    let mut retry_delay = Duration::from_secs(3);
    let mut calls = IncomingCalls::default();
    loop {
        let connection = tokio::select! {
            connection = Madrid::connect(&identity) => connection,
            _ = status.closed() => break,
        };
        let error = match connection {
            Ok(mut madrid) => {
                retry_delay = Duration::from_secs(3);
                set_status(&status, true, "Connected to Apple courier");
                match online(
                    &identity,
                    &state,
                    &mut madrid,
                    &mut requests,
                    &status,
                    &mut calls,
                )
                .await
                {
                    Ok(()) => break,
                    Err(error) => error,
                }
            }
            Err(error) => error,
        };
        if let Some(call) = calls.connected.as_ref() {
            calls.end(call.call.id, now_ms());
        }
        if let Some(outgoing) = calls.outgoing.take() {
            calls.end(outgoing.call.id, now_ms());
        }
        set_status(&status, false, &error.to_string());
        let delay = sleep(retry_delay);
        tokio::pin!(delay);
        loop {
            tokio::select! {
                () = &mut delay => break,
                _ = status.closed() => return,
                request = requests.recv() => {
                    let Some(request) = request else { return };
                    match request {
                        Request::Send(message, reply) => {
                            let result = state.history().and_then(|history| read_previous(&history, &message))
                                .and_then(|previous| previous.context("Apple courier is disconnected"));
                            let _ = reply.send(result);
                        }
                        Request::Download { reply, .. } => {
                            let _ = reply.send(Err(anyhow::anyhow!("Apple courier is disconnected")));
                        }
                        Request::Tapback { reply, .. } => {
                            let _ = reply.send(Err(anyhow::anyhow!("Apple courier is disconnected")));
                        }
                        Request::DeclineCall { reply, .. } => {
                            let _ = reply.send(Err(anyhow::anyhow!("Apple courier is disconnected")));
                        }
                        Request::PrepareCallMedia { reply, .. } => {
                            let _ = reply.send(Err(anyhow::anyhow!("Apple courier is disconnected")));
                        }
                        Request::AllocateCallRelay { reply, .. } => {
                            let _ = reply.send(Err(anyhow::anyhow!("Apple courier is disconnected")));
                        }
                        Request::PublishCallKeys { reply, .. } => {
                            let _ = reply.send(Err(anyhow::anyhow!("Apple courier is disconnected")));
                        }
                        Request::BeginCallAnswer { reply, .. } => {
                            let _ = reply.send(Err(anyhow::anyhow!("Apple courier is disconnected")));
                        }
                        Request::ResolveAnswerMedia { reply, .. } => {
                            let _ = reply.send(Err(anyhow::anyhow!("Apple courier is disconnected")));
                        }
                        Request::JoinCall { reply, .. } => {
                            let _ = reply.send(Err(anyhow::anyhow!("Apple courier is disconnected")));
                        }
                        Request::DialCall { reply, .. } => {
                            let _ = reply.send(Err(anyhow::anyhow!("Apple courier is disconnected")));
                        }
                        Request::RingOutgoing { reply, .. } => {
                            let _ = reply.send(Err(anyhow::anyhow!("Apple courier is disconnected")));
                        }
                        Request::FinishOutgoing { reply, .. } => {
                            let _ = reply.send(Err(anyhow::anyhow!("Apple courier is disconnected")));
                        }
                        Request::InstallRelayKeys { .. } => (),
                    }
                }
            }
        }
        retry_delay = (retry_delay * 2).min(Duration::from_secs(60));
    }
}

async fn online(
    identity: &Identity,
    state: &State,
    madrid: &mut Madrid,
    requests: &mut mpsc::Receiver<Request>,
    status: &watch::Sender<Status>,
    calls: &mut IncomingCalls,
) -> Result<()> {
    loop {
        let next_expiry = status
            .borrow()
            .incoming_calls
            .iter()
            .map(|call| call.expires_ms)
            .min();
        tokio::select! {
            () = sleep(Duration::from_millis(next_expiry.unwrap_or_default().saturating_sub(now_ms()).max(0) as u64)), if next_expiry.is_some() => {
                status.send_if_modified(|status| calls.expire(status, now_ms()));
            }
            notification = madrid.next_notification() => {
                receive_notification(identity, state, madrid, status, calls, notification?).await?;
            }
            () = calls.wait_for_local_hangup() => {
                if let Some(connected) = calls.connected.take() {
                    let call = connected.call.clone();
                    let endpoint = connected.endpoint;
                    let relay = connected.relay.clone();
                    let initiator = connected.initiator;
                    drop(connected); // Close the local call and clear peer keys before network I/O.
                    calls.end(call.id, now_ms());
                    let _ = madrid.update_call_participant(identity, &call, endpoint, &relay, None, initiator).await;
                } else if let Some(outgoing) = calls.outgoing.take() {
                    calls.end(outgoing.call.id, now_ms());
                    outgoing.cancel(identity, madrid).await;
                }
            }
            request = requests.recv() => {
                let Some(request) = request else { return Ok(()) };
                match request {
                    Request::Send(message, reply) => {
                        let _ = reply.send(send_on_courier(identity, state, madrid, &message).await);
                    }
                    Request::Download { id, index, reply } => {
                        let _ = reply.send(download(identity, state, madrid, id, index).await);
                    }
                    Request::Tapback { target, request, reply } => {
                        let _ = reply.send(send_tapback(identity, state, madrid, status, target, request).await);
                    }
                    Request::DeclineCall { id, reply } => {
                        let call = status.borrow().incoming_calls.iter()
                            .find(|call| call.id == id && call.expires_ms > now_ms()).cloned();
                        let result = match call {
                            Some(call) => {
                                let result = madrid.decline_call(identity, &call).await;
                                if result.is_ok() {
                                    calls.end(id, now_ms());
                                }
                                result
                            }
                            None => Ok(()),
                        };
                        if result.is_ok() {
                            status.send_modify(|status| status.incoming_calls.retain(|call| call.id != id));
                        }
                        let _ = reply.send(result);
                    }
                    Request::PrepareCallMedia { id, reply } => {
                        let _ = reply.send(calls.prepare_media(&status.borrow(), id));
                    }
                    Request::AllocateCallRelay { id, mut reply } => {
                        for notification in madrid.take_queued() {
                            receive_notification(identity, state, madrid, status, calls, notification).await?;
                        }
                        let result = tokio::select! {
                            biased;
                            _ = reply.closed() => continue,
                            result = calls.request_relay(identity, madrid, status, id) => result,
                        };
                        // A caller can hang up while the relay request is in flight.
                        for notification in madrid.take_queued() {
                            receive_notification(identity, state, madrid, status, calls, notification).await?;
                        }
                        let result = result.and_then(|allocation| {
                            let state = status.borrow();
                            let _ = active_call(&state, id)?;
                            calls.details.get_mut(&id).context("This FaceTime call has ended")?.relay = Some(allocation.clone());
                            Ok(allocation)
                        });
                        let _ = reply.send(result);
                    }
                    Request::PublishCallKeys { id, reply } => {
                        for notification in madrid.take_queued() {
                            receive_notification(identity, state, madrid, status, calls, notification).await?;
                        }
                        if reply.is_closed() {
                            continue;
                        }
                        let result = calls.prepare_keys(identity, &status.borrow(), id);
                        match result {
                            Ok((delivery, courier)) => {
                                if reply.send(Ok(delivery)).is_ok() {
                                    let sent = courier.send(identity, madrid).await;
                                    for notification in madrid.take_queued() {
                                        receive_notification(identity, state, madrid, status, calls, notification).await?;
                                    }
                                    courier.finish(sent.and_then(|()| active_call(&status.borrow(), id).map(|_| ())));
                                }
                            }
                            Err(error) => { let _ = reply.send(Err(error)); }
                        }
                    }
                    Request::BeginCallAnswer { id, reply } => {
                        if !reply.is_closed() {
                            let _ = reply.send(calls.begin_answer(&status.borrow(), id));
                        }
                    }
                    Request::ResolveAnswerMedia { id, lease, relay_prekey, reply } => {
                        if !reply.is_closed() {
                            let _ = reply.send(calls.resolve_answer_media(&status.borrow(), id, &lease, relay_prekey));
                        }
                    }
                    Request::JoinCall { answer, reply } => {
                        for notification in madrid.take_queued() {
                            receive_notification(identity, state, madrid, status, calls, notification).await?;
                        }
                        if reply.is_closed() {
                            continue;
                        }
                        let result = calls.send_join(identity, madrid, status, &answer).await;
                        for notification in madrid.take_queued() {
                            receive_notification(identity, state, madrid, status, calls, notification).await?;
                        }
                        let result = match result {
                            Ok(receipt) => {
                                let joined = calls.finish_answer(status, &receipt);
                                if joined.is_err() {
                                    let _ = madrid.update_call_participant(
                                        identity, &receipt.call, receipt.endpoint, &receipt.relay, None, false,
                                    ).await;
                                }
                                joined
                            }
                            Err(error) => Err(error),
                        };
                        let _ = reply.send(result);
                    }
                    Request::DialCall { dial, reply } => {
                        calls.begin_outgoing(identity, madrid, status, dial, reply).await;
                    }
                    Request::RingOutgoing { id, reply } => {
                        if !reply.is_closed() {
                            let _ = reply.send(calls.ring_outgoing(identity, madrid, id).await);
                        }
                    }
                    Request::FinishOutgoing { id, relay_prekey, reply } => {
                        for notification in madrid.take_queued() {
                            receive_notification(identity, state, madrid, status, calls, notification).await?;
                        }
                        if reply.is_closed() {
                            continue;
                        }
                        match calls.finish_outgoing(identity, id, relay_prekey) {
                            Ok((answer, courier)) => {
                                if reply.send(Ok(answer)).is_ok() {
                                    let sent = courier.send(identity, madrid).await;
                                    for notification in madrid.take_queued() {
                                        receive_notification(identity, state, madrid, status, calls, notification).await?;
                                    }
                                    courier.finish(sent.and_then(|()| {
                                        ensure!(calls.connected.as_ref().is_some_and(|active| active.call.id == id), "The FaceTime call has ended");
                                        Ok(())
                                    }));
                                }
                            }
                            Err(error) => { let _ = reply.send(Err(error)); }
                        }
                    }
                    Request::InstallRelayKeys { id, offer, reply } => {
                        if let Some(active) = &calls.connected
                            && active.call.id == id
                            && active.endpoint.participant() == Some(offer.participant)
                        {
                            let _ = active.exchange.receive(*offer);
                        }
                        let _ = reply.send(());
                    }
                }
            }
            _ = status.closed() => return Ok(()),
        }
    }
}

async fn receive_notification(
    identity: &Identity,
    state: &State,
    madrid: &mut Madrid,
    status: &watch::Sender<Status>,
    calls: &mut IncomingCalls,
    notification: Notification,
) -> Result<()> {
    match madrid.decode(identity, &notification).await? {
        Some(Incoming::Message(message, media)) => state.history()?.insert(&message, media)?,
        Some(Incoming::Tapback(event)) => {
            let history = state.history()?;
            record_tapback(&history, status, &event)?;
        }
        Some(Incoming::Call(signal)) => calls.update(status, identity.handle(), signal),
        None => (),
    }
    madrid.acknowledge(notification.id).await
}

fn active_call(status: &Status, id: uuid::Uuid) -> Result<&crate::IncomingCall> {
    let now = now_ms();
    status
        .incoming_calls
        .iter()
        .find(|call| call.id == id && call.expires_ms > now)
        .context("This FaceTime call has ended")
}

#[derive(Default)]
struct IncomingCalls {
    details: HashMap<uuid::Uuid, IncomingCallDetails>,
    ended: HashMap<uuid::Uuid, i64>,
    answering: Option<Weak<AnswerLease>>,
    connected: Option<ConnectedCall>,
    outgoing: Option<PendingOutgoing>,
}

struct IncomingCallDetails {
    endpoint: CallEndpoint,
    description: Option<Vec<u8>>,
    prekey: Option<PeerPrekey>,
    local_prekey: Option<LocalCallPrekey>,
    exchange: Option<CallMediaExchange>,
    relay: Option<Arc<CallRelayAllocation>>,
    offer: Option<Arc<CallKeyOffer>>,
}

impl IncomingCallDetails {
    fn learn_prekey(&mut self, key: PeerPrekey) -> bool {
        // One caller prekey per ringing attempt. An established call negotiates rekeys separately.
        if self.prekey.is_none() {
            self.prekey = Some(key);
            return true;
        }
        false
    }

    fn learn_media(&mut self, media: Option<PeerMediaOffer>) -> bool {
        let Some(offer) = media else { return false };
        let learned_key = offer.prekey.is_some_and(|key| self.learn_prekey(key));
        if self
            .description
            .as_ref()
            .is_none_or(|current| current.is_empty() && !offer.description.is_empty())
        {
            self.description = Some(offer.description);
            return true;
        }
        learned_key
    }
}

impl IncomingCalls {
    async fn request_relay(
        &mut self,
        identity: &Identity,
        madrid: &mut Madrid,
        status: &watch::Sender<Status>,
        id: uuid::Uuid,
    ) -> Result<Arc<CallRelayAllocation>> {
        let call = active_call(&status.borrow(), id)?.clone();
        let details = self
            .details
            .get_mut(&id)
            .context("Missing caller details")?;
        if let Some(relay) = &details.relay {
            return Ok(relay.clone());
        }
        let mut relay = madrid
            .allocate_call_relay(identity, &call, details.endpoint)
            .await?;
        if identity.can_sign_relay_prekey() {
            let public = if let Some(exchange) = &details.exchange {
                exchange.handshake.public_prekey()
            } else {
                if details.local_prekey.is_none() {
                    details.local_prekey = Some(LocalCallPrekey::generate()?);
                }
                details
                    .local_prekey
                    .as_ref()
                    .context("Missing local FaceTime prekey")?
                    .public()
            };
            relay.local_prekey = identity.sign_relay_prekey(id, public)?;
        }
        Ok(Arc::new(relay))
    }

    fn prepare_keys(
        &mut self,
        identity: &Identity,
        status: &Status,
        id: uuid::Uuid,
    ) -> Result<(CallKeyDelivery, CourierKeyDelivery)> {
        let _ = active_call(status, id)?;
        let details = self
            .details
            .get_mut(&id)
            .context("Missing caller details")?;
        let relay = details
            .relay
            .as_ref()
            .context("This FaceTime call has no relay yet")?;
        let exchange = details
            .exchange
            .as_ref()
            .context("This FaceTime call has no local prekey yet")?;
        ensure!(
            relay.call_id == id && details.endpoint.participant() == Some(relay.caller_participant),
            "FaceTime relay no longer matches the ringing device"
        );
        // Store the offer before sending so a retry cannot substitute different material
        // for a generation the peer might have already installed.
        if details.offer.is_none() {
            let offer = exchange
                .handshake
                .build_key_offer(relay.local_participant)?;
            details.offer = Some(Arc::new(offer));
        }
        let offer = details
            .offer
            .as_ref()
            .context("Missing FaceTime key offer")?;
        CallKeyDelivery::prepare(
            identity,
            exchange.handshake.clone(),
            details.endpoint,
            offer.clone(),
        )
    }

    fn expire(&mut self, status: &mut Status, now: i64) -> bool {
        let previous = status.incoming_calls.len();
        status.incoming_calls.retain(|call| call.expires_ms > now);
        self.details
            .retain(|id, _| status.incoming_calls.iter().any(|call| call.id == *id));
        self.ended.retain(|_, expires_ms| *expires_ms > now);
        status.incoming_calls.len() != previous
    }

    fn end(&mut self, id: uuid::Uuid, now: i64) {
        self.details.remove(&id);
        if self
            .connected
            .as_ref()
            .is_some_and(|active| active.call.id == id)
        {
            self.connected = None;
        }
        if self.ended.len() >= 256
            && let Some((&oldest, _)) = self.ended.iter().min_by_key(|(_, expiry)| *expiry)
        {
            self.ended.remove(&oldest);
        }
        self.ended.insert(id, now + 120_000);
    }

    fn prepare_media(
        &mut self,
        status: &Status,
        id: uuid::Uuid,
    ) -> Result<Arc<CallMediaHandshake>> {
        let call = active_call(status, id)?;
        let details = self
            .details
            .get_mut(&id)
            .context("Missing caller details")?;
        if let Some(exchange) = &details.exchange {
            return Ok(exchange.handshake.clone());
        }
        let description = details
            .description
            .as_deref()
            .context("The caller has not sent a media description")?;
        let prekey = details
            .prekey
            .as_ref()
            .context("The caller has not sent a supported media prekey")?;
        let exchange = if let Some(local) = details.local_prekey.take() {
            CallMediaExchange::with_prekey(call.clone(), description, prekey, local)
        } else {
            CallMediaExchange::prepare(call.clone(), description, prekey)?
        };
        let handshake = exchange.handshake.clone();
        details.exchange = Some(exchange);
        Ok(handshake)
    }

    fn update(&mut self, status: &watch::Sender<Status>, own: &str, signal: CallSignal) {
        if let Some(outgoing) = &mut self.outgoing
            && outgoing.call.id == signal.id()
        {
            outgoing.receive(signal);
            return;
        }
        let now = now_ms();
        status.send_if_modified(|status| {
            let expired = self.expire(status, now);
            let calls = &mut status.incoming_calls;
            match signal {
                CallSignal::Ring {
                    call: offer,
                    endpoint,
                    media,
                } if offer.expires_ms > now
                    && !self.ended.contains_key(&offer.id)
                    && self
                        .connected
                        .as_ref()
                        .is_none_or(|active| active.call.id != offer.id) =>
                {
                    if let Some(existing) = calls.iter_mut().find(|call| call.id == offer.id) {
                        // Bind a standalone invitation to its join without extending the original ring.
                        if existing.caller == offer.caller
                            && let Some(details) = self.details.get_mut(&offer.id)
                            && details.endpoint.matches(endpoint)
                        {
                            let upgraded_endpoint = details.endpoint.participant().is_none()
                                && endpoint.participant().is_some();
                            details.endpoint = endpoint;
                            let learned_media = details.learn_media(media);
                            if existing.mode.is_none() && offer.mode.is_some() {
                                existing.mode = offer.mode;
                                return true;
                            }
                            return expired || learned_media || upgraded_endpoint;
                        }
                        return expired;
                    }
                    if calls.len() >= 16 {
                        self.details.remove(&calls.remove(0).id);
                    }
                    let mut details = IncomingCallDetails {
                        endpoint,
                        description: None,
                        prekey: None,
                        local_prekey: None,
                        exchange: None,
                        relay: None,
                        offer: None,
                    };
                    details.learn_media(media);
                    self.details.insert(offer.id, details);
                    calls.push(offer);
                    true
                }
                CallSignal::Prekey {
                    id,
                    sender,
                    endpoint,
                    key,
                } => {
                    if calls
                        .iter()
                        .any(|call| call.id == id && call.caller == sender)
                        && let Some(details) = self.details.get_mut(&id)
                        && details.endpoint.same_device(endpoint)
                        && details.learn_prekey(key)
                    {
                        return true;
                    }
                    expired
                }
                CallSignal::MediaKeys {
                    id,
                    sender,
                    endpoint,
                    offer,
                } => {
                    if let Some(active) = &self.connected
                        && active.call.id == id
                        && active.call.caller == sender
                        && active.endpoint.matches(endpoint)
                    {
                        let _ = active.exchange.receive(*offer);
                        return expired;
                    }
                    if calls
                        .iter()
                        .any(|call| call.id == id && call.caller == sender)
                        && let Some(details) = self.details.get(&id)
                        && details.endpoint.matches(endpoint)
                        && let Some(exchange) = &details.exchange
                    {
                        // Malformed key offers cannot interrupt iMessage or replace a valid key.
                        let _ = exchange.receive(*offer);
                    }
                    expired
                }
                CallSignal::End {
                    id,
                    sender,
                    received_ms,
                    endpoint,
                } => {
                    if self.connected.as_ref().is_some_and(|connected| {
                        connected.call.id == id
                            && (endpoint.and_then(CallEndpoint::participant).is_some()
                                || sender == own)
                            && can_end_call(
                                &connected.call,
                                Some(connected.endpoint),
                                own,
                                &sender,
                                received_ms,
                                endpoint,
                            )
                    }) {
                        self.end(id, now);
                        return true;
                    }
                    if let Some(index) = calls.iter().position(|call| {
                        call.id == id
                            && can_end_call(
                                call,
                                self.details.get(&id).map(|details| details.endpoint),
                                own,
                                &sender,
                                received_ms,
                                endpoint,
                            )
                    }) {
                        calls.remove(index);
                        self.end(id, now);
                        return true;
                    }
                    expired
                }
                CallSignal::Ring { .. } | CallSignal::Accepted { .. } => expired,
            }
        });
    }
}

fn can_end_call(
    call: &crate::IncomingCall,
    verified: Option<CallEndpoint>,
    own: &str,
    sender: &str,
    received_ms: i64,
    endpoint: Option<CallEndpoint>,
) -> bool {
    received_ms >= call.received_ms
        && match endpoint {
            Some(leaving) => {
                sender == call.caller
                    && verified.is_some_and(|known| {
                        if leaving.participant().is_some() {
                            known.matches(leaving)
                        } else {
                            known.same_device(leaving)
                        }
                    })
            }
            None => sender == own || sender == call.caller,
        }
}

async fn send_tapback(
    identity: &Identity,
    state: &State,
    madrid: &mut Madrid,
    status: &watch::Sender<Status>,
    target: uuid::Uuid,
    request: SetTapback,
) -> Result<Vec<Tapback>> {
    let message = state
        .history()?
        .get(&target.to_string())?
        .context("This message is unavailable")?;
    let Some(event) = tapback_change(&message, target, request)? else {
        return Ok(message.tapbacks);
    };
    let result = madrid.send_tapback(identity, &message, &event).await?;
    ensure!(
        result == Delivery::Accepted,
        "Apple did not confirm the reaction"
    );
    let history = state.history()?;
    record_tapback(&history, status, &event)?;
    history.tapbacks(&message.id, &message.address)
}

fn tapback_change(
    message: &Message,
    target: uuid::Uuid,
    request: SetTapback,
) -> Result<Option<TapbackEvent>> {
    ensure!(
        matches!(message.status, Delivery::Received | Delivery::Accepted),
        "This message is awaiting delivery"
    );
    let first = message.first_part();
    let part = request.part.unwrap_or_else(|| {
        message
            .tapbacks
            .iter()
            .filter(|tapback| tapback.outgoing)
            .min_by_key(|tapback| tapback.part != first)
            .map_or(first, |tapback| tapback.part)
    });
    let previous = message
        .tapbacks
        .iter()
        .find(|tapback| tapback.outgoing && tapback.part == part);
    ensure!(
        message.has_part(part) || previous.is_some(),
        "This part of the message is unavailable"
    );
    let unchanged = match (previous, &request.reaction) {
        (Some(previous), Some(kind)) => previous.kind.matches_reaction(kind),
        (None, None) => true,
        _ => false,
    };
    if unchanged {
        return Ok(None);
    }
    let removed = request.reaction.is_none();
    let kind = request
        .reaction
        .or_else(|| previous.map(|tapback| tapback.kind.clone()))
        .context("No tapback to remove")?;
    Ok(Some(TapbackEvent {
        id: uuid::Uuid::new_v4(),
        target,
        chat: message.address.clone(),
        timestamp_ns: now_ns(),
        removed,
        tapback: Tapback {
            kind,
            outgoing: true,
            part,
        },
    }))
}

fn record_tapback(
    history: &History,
    status: &watch::Sender<Status>,
    event: &TapbackEvent,
) -> Result<()> {
    if history.insert_tapback(event)? {
        status.send_modify(|status| status.tapback_revision = Some(event.id));
    }
    Ok(())
}

async fn send_on_courier(
    identity: &Identity,
    state: &State,
    madrid: &mut Madrid,
    request: &SendText,
) -> Result<Message> {
    let (mut item, is_new) = {
        let history = state.history()?;
        start_send(&history, request)?
    };
    if !is_new {
        return Ok(item);
    }
    ensure!(item.status == Delivery::Pending, "Invalid outgoing state");
    let delivery = madrid.send(identity, request).await;
    item.status = match &delivery {
        Ok(status) => *status,
        Err(_) => Delivery::Failed,
    };
    state.history()?.update(&item.id, item.status)?;
    delivery.map(|_| item)
}

fn read_previous(history: &History, request: &SendText) -> Result<Option<Message>> {
    let id = request.id.to_string();
    let existing = history.get(&id)?;
    if let Some(existing) = &existing {
        ensure!(
            existing.outgoing
                && existing.address == request.address
                && existing.body == request.body
                && existing.attachments.iter().eq(request.files.iter().map(|file| &file.info))
                && request.files.iter().enumerate().all(|(index, file)| {
                    matches!(history.attachment(request.id, index), Ok((_, MediaSource::Local(bytes))) if bytes == file.bytes)
                }),
            "Message ID is already used by a different message"
        );
    } else {
        ensure!(!history.was_deleted(&id)?, "This message was deleted");
    }
    Ok(existing)
}

fn start_send(history: &History, request: &SendText) -> Result<(Message, bool)> {
    if let Some(mut existing) = read_previous(history, request)? {
        if existing.status == Delivery::Failed {
            history.update(&existing.id, Delivery::Pending)?;
            existing.status = Delivery::Pending;
            return Ok((existing, true));
        }
        return Ok((existing, false));
    }
    let item = Message {
        id: request.id.to_string(),
        address: request.address.clone(),
        body: request.body.clone(),
        text_part: None,
        outgoing: true,
        timestamp_ms: now_ms(),
        status: Delivery::Pending,
        attachments: request.files.iter().map(|file| file.info.clone()).collect(),
        tapbacks: Vec::new(),
    };
    history.insert(
        &item,
        request
            .files
            .iter()
            .map(|file| MediaSource::Local(file.bytes.clone())),
    )?;
    Ok((item, true))
}

fn set_status(status: &watch::Sender<Status>, connected: bool, detail: &str) {
    status.send_modify(|status| {
        status.connected = connected;
        status.detail = detail.to_owned();
    });
}

async fn download(
    identity: &Identity,
    state: &State,
    madrid: &mut Madrid,
    id: uuid::Uuid,
    index: usize,
) -> Result<bytes::Bytes> {
    let (info, source) = state.history()?.attachment(id, index)?;
    match source {
        MediaSource::Local(bytes) => Ok(bytes),
        MediaSource::Apple(media) => {
            let bytes = madrid.download(identity, &media, info.size).await?;
            state.history()?.cache_attachment(id, index, &bytes)?;
            Ok(bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Attachment, Upload};

    #[test]
    fn changes_existing_reactions_on_legacy_parts_without_creating_new_ones_there() -> Result<()> {
        let id = uuid::Uuid::new_v4();
        let mut message = Message {
            id: id.to_string(),
            address: "mailto:peer@example.org".into(),
            body: "Hi".into(),
            text_part: Some(1),
            outgoing: false,
            timestamp_ms: 0,
            status: Delivery::Received,
            attachments: Vec::new(),
            tapbacks: vec![Tapback {
                kind: TapbackKind::Like,
                outgoing: true,
                part: 0,
            }],
        };
        let request = |reaction| SetTapback {
            reaction,
            part: Some(0),
        };
        let replacement = tapback_change(&message, id, request(Some(TapbackKind::Heart)))?
            .context("Missing replacement")?;
        assert_eq!(replacement.tapback.part, 0);
        assert_eq!(replacement.tapback.kind, TapbackKind::Heart);
        assert!(!replacement.removed);
        let removal = tapback_change(&message, id, request(None))?.context("Missing removal")?;
        assert_eq!(removal.tapback, message.tapbacks[0]);
        assert!(removal.removed);
        message.tapbacks[0].outgoing = false;
        assert!(tapback_change(&message, id, request(Some(TapbackKind::Heart))).is_err());
        Ok(())
    }

    #[test]
    fn only_the_caller_or_our_account_can_end_a_ring_and_replays_stay_ended() {
        let caller = "mailto:caller@example.org";
        let own = "mailto:receiver@example.org";
        let now = now_ms();
        let id = uuid::Uuid::new_v4();
        let (status, reader) = watch::channel(Status {
            connected: true,
            detail: String::new(),
            tapback_revision: None,
            facetime_registered: true,
            incoming_calls: Vec::new(),
        });
        let offer = crate::IncomingCall {
            id,
            caller: caller.into(),
            mode: None,
            received_ms: now,
            expires_ms: now + 45_000,
        };
        let end = |sender: &str, time| CallSignal::End {
            id,
            sender: sender.into(),
            received_ms: time,
            endpoint: None,
        };
        let ring = |call, token, participant| CallSignal::Ring {
            call,
            endpoint: CallEndpoint::new([token; 32], participant),
            media: None,
        };
        let leave = |token, participant| CallSignal::End {
            id,
            sender: caller.into(),
            received_ms: now,
            endpoint: Some(CallEndpoint::new([token; 32], Some(participant))),
        };
        let mut incoming = IncomingCalls::default();
        incoming.update(&status, own, ring(offer.clone(), 1, None));
        incoming.update(&status, own, end("mailto:stranger@example.org", now));
        incoming.update(&status, own, end(caller, now - 1));
        let join = crate::IncomingCall {
            mode: Some(crate::CallMode::Video),
            expires_ms: offer.expires_ms + 1_000,
            ..offer.clone()
        };
        incoming.update(&status, own, ring(join.clone(), 2, Some(11)));
        assert_eq!(reader.borrow().incoming_calls, vec![offer.clone()]);
        incoming.update(&status, own, ring(join.clone(), 1, Some(11)));
        incoming.update(&status, own, leave(1, 12));
        incoming.update(&status, own, leave(2, 11));
        assert_eq!(
            reader.borrow().incoming_calls,
            vec![crate::IncomingCall {
                mode: join.mode,
                ..offer.clone()
            }]
        );
        incoming.update(&status, own, leave(1, 11));
        incoming.update(&status, own, ring(offer.clone(), 1, None));
        assert!(reader.borrow().incoming_calls.is_empty());
        let id = uuid::Uuid::new_v4();
        incoming.update(
            &status,
            own,
            ring(crate::IncomingCall { id, ..offer }, 1, None),
        );
        incoming.update(
            &status,
            own,
            CallSignal::End {
                id,
                sender: own.into(),
                received_ms: now,
                endpoint: None,
            },
        );
        assert!(reader.borrow().incoming_calls.is_empty());
    }

    #[test]
    fn media_preparation_uses_only_the_authenticated_ringing_device() -> Result<()> {
        let point = hex::decode(concat!(
            "043ed113b7883b4c590638379db0c21cda16742ed0255048bf433391d374bc21d190",
            "99209accc4c8a224c843afa4f4c68a090d04da5e9889dae2f8eefce82a3740"
        ))?;
        let key = PeerPrekey::parse(1, &point)?;
        let stranger = PeerPrekey::parse(
            1,
            &hex::decode(concat!(
                "0447776904c0f1cc3a9c0984b66f75301a5fa68678f0d64af8ba1abce34738a73e",
                "aa005ee6b5b957286231856577648e8381b2804428d5733f32f787ff71f1fcdc"
            ))?,
        )?;
        let now = now_ms();
        let id = uuid::Uuid::new_v4();
        let own = "mailto:receiver@example.org";
        let caller = "mailto:caller@example.org";
        let (status, reader) = watch::channel(Status {
            connected: true,
            detail: String::new(),
            tapback_revision: None,
            facetime_registered: true,
            incoming_calls: Vec::new(),
        });
        let mut incoming = IncomingCalls::default();
        incoming.update(
            &status,
            own,
            CallSignal::Ring {
                call: crate::IncomingCall {
                    id,
                    caller: caller.into(),
                    mode: Some(crate::CallMode::Audio),
                    received_ms: now,
                    expires_ms: now + 45_000,
                },
                endpoint: CallEndpoint::new([1; 32], Some(7)),
                media: Some(PeerMediaOffer {
                    description: b"signed media description".to_vec(),
                    prekey: None,
                }),
            },
        );
        let prekey = |sender: &str, token, id, key: &PeerPrekey| CallSignal::Prekey {
            id,
            sender: sender.into(),
            endpoint: CallEndpoint::new([token; 32], None),
            key: key.clone(),
        };
        incoming.update(&status, own, prekey(caller, 2, id, &stranger));
        incoming.update(
            &status,
            own,
            prekey("mailto:stranger@example.org", 1, id, &stranger),
        );
        incoming.update(
            &status,
            own,
            prekey(caller, 1, uuid::Uuid::new_v4(), &stranger),
        );
        assert!(incoming.prepare_media(&reader.borrow(), id).is_err());
        incoming.update(&status, own, prekey(caller, 1, id, &key));
        incoming.update(&status, own, prekey(caller, 1, id, &stranger));
        assert!(incoming.details[&id].prekey.as_ref().unwrap().same_as(&key));
        let handshake = incoming.prepare_media(&reader.borrow(), id)?;
        assert_eq!(handshake.call().id, id);
        assert_eq!(handshake.peer_description(), b"signed media description");
        assert!(Arc::ptr_eq(
            &handshake,
            &incoming.prepare_media(&reader.borrow(), id)?
        ));
        let peer_keys = handshake.watch_peer_keys();
        let receiver = PeerPrekey::parse(1, handshake.public_prekey())?;
        let simulated_peer =
            CallMediaExchange::prepare(handshake.call().clone(), b"fixture", &receiver)?;
        let offer = simulated_peer.handshake.build_key_offer(7)?;
        let wrong_participant = simulated_peer.handshake.build_key_offer(8)?;
        let parse = |payload: &[u8], token: u8| {
            crate::apple::decode_call_fixture(211, payload, caller.into(), own, [token; 32], now)
                .context("Expected an IDS media key packet")
        };
        incoming.update(&status, own, parse(&offer.payload, 2)?);
        incoming.update(&status, own, parse(&wrong_participant.payload, 1)?);
        assert!(peer_keys.borrow().media.is_none());
        incoming.update(&status, own, parse(&offer.payload, 1)?);
        {
            let received = peer_keys.borrow();
            let session = received.session.as_ref().context("Expected session keys")?;
            let media = received.media.as_ref().context("Expected media keys")?;
            assert_eq!(session.identifier, offer.session.identifier);
            assert_eq!(media.short_identifier_len, 2);
            assert_eq!(
                *media.key.srtp_key(0x1234)?,
                *offer.media.key.srtp_key(0x1234)?
            );
        }
        incoming.update(
            &status,
            own,
            CallSignal::End {
                id,
                sender: caller.into(),
                received_ms: now,
                endpoint: None,
            },
        );
        incoming.update(&status, own, parse(&offer.payload, 1)?);
        assert!(peer_keys.borrow().media.is_none());
        assert!(peer_keys.borrow().session.is_none());
        assert!(incoming.prepare_media(&reader.borrow(), id).is_err());
        Ok(())
    }

    #[test]
    fn an_attachment_retry_preserves_the_message_and_its_original_bytes() -> Result<()> {
        let folder = tempfile::tempdir()?;
        let history = History::open(folder.path(), "test")?;
        let mut request = SendText {
            id: uuid::Uuid::new_v4(),
            address: "mailto:recipient@example.com".into(),
            body: String::new(),
            files: vec![Upload {
                info: Attachment {
                    name: "photo.png".into(),
                    mime: "image/png".into(),
                    size: 4,
                    width: 4,
                    height: 4,
                    part: None,
                },
                bytes: bytes::Bytes::from_static(b"1234"),
            }],
        };
        let (message, new) = start_send(&history, &request)?;
        assert!(new);
        assert_eq!(history.chats()?[0].preview, "Photo");
        assert_eq!(
            history.messages(&request.address, 0)?[0].attachments,
            vec![request.files[0].info.clone()]
        );
        history.update(&message.id, Delivery::Failed)?;
        let (retry, new) = start_send(&history, &request)?;
        assert!(new);
        assert_eq!(retry.id, message.id);
        assert_eq!(retry.status, Delivery::Pending);
        history.update(&message.id, Delivery::Accepted)?;
        assert!(!start_send(&history, &request)?.1);
        request.files[0].bytes = bytes::Bytes::from_static(b"5678");
        assert!(start_send(&history, &request).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn deleting_a_conversation_removes_attachments_and_rejects_replays() -> Result<()> {
        let folder = tempfile::tempdir()?;
        let history = History::open(folder.path(), "delete")?;
        let request = SendText {
            id: uuid::Uuid::new_v4(),
            address: "tel:+15550100123".into(),
            body: String::new(),
            files: vec![Upload {
                info: Attachment {
                    name: "test.png".into(),
                    mime: "image/png".into(),
                    size: 1,
                    width: 1,
                    height: 1,
                    part: None,
                },
                bytes: bytes::Bytes::from_static(b"x"),
            }],
        };
        let (message, _) = start_send(&history, &request)?;
        assert!(history.delete_conversation(&request.address).is_err());
        history.update(&message.id, Delivery::Accepted)?;
        let other = Message {
            id: uuid::Uuid::new_v4().to_string(),
            address: "mailto:another@example.com".into(),
            body: "Another conversation".into(),
            text_part: None,
            outgoing: false,
            timestamp_ms: now_ms(),
            status: Delivery::Received,
            attachments: Vec::new(),
            tapbacks: Vec::new(),
        };
        history.insert(&other, [])?;
        let engine = Engine {
            state: Arc::new(State {
                history: Mutex::new(history),
                _lock: File::open(folder.path())?,
            }),
            requests: mpsc::channel(1).0,
            #[cfg(feature = "desktop")]
            call_device: None,
            status: watch::channel(Status {
                connected: false,
                detail: String::new(),
                tapback_revision: None,
                facetime_registered: false,
                incoming_calls: Vec::new(),
            })
            .1,
        };
        let router = crate::api::router(engine.clone(), crate::api::AccessPolicy::loopback());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/v1/conversations", listener.local_addr()?);
        let server = tokio::spawn(async move { axum::serve(listener, router).await });
        let client = reqwest::Client::builder().no_proxy().build()?;
        let delete = || {
            client
                .delete(&url)
                .query(&[("address", "+1 (555) 010-0123")])
        };
        assert_eq!(
            delete().send().await?.status(),
            reqwest::StatusCode::FORBIDDEN
        );
        assert_eq!(engine.messages(&request.address, 0)?.len(), 1);
        for _ in 0..2 {
            assert_eq!(
                delete()
                    .header("x-messages-api", "1")
                    .send()
                    .await?
                    .status(),
                reqwest::StatusCode::NO_CONTENT
            );
        }
        server.abort();
        let history = engine.state.history()?;
        assert!(history.attachment(request.id, 0).is_err());
        assert!(start_send(&history, &request).is_err());
        history.insert(
            &message,
            [MediaSource::Local(request.files[0].bytes.clone())],
        )?;
        assert!(history.messages(&request.address, 0)?.is_empty());
        let new = Message {
            id: uuid::Uuid::new_v4().to_string(),
            address: request.address.clone(),
            ..other
        };
        history.insert(&new, [])?;
        assert_eq!(history.chats()?.len(), 2);
        assert_eq!(history.messages(&request.address, 0)?[0].id, new.id);
        Ok(())
    }
}
