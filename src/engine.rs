use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
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
        CallEndpoint, CallMediaExchange, CallMediaHandshake, CallSignal, Identity, Incoming,
        Madrid, PeerMediaOffer, PeerPrekey,
    },
    history::History,
};

#[derive(Clone)]
pub struct Engine {
    state: Arc<State>,
    requests: mpsc::Sender<Request>,
    status: watch::Receiver<Status>,
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
            facetime_registered: identity.facetime_registered(),
            incoming_calls: Vec::new(),
        });
        let (requests, receiver) = mpsc::channel(16);
        tokio::spawn(run_apple(identity, state.clone(), receiver, updates));
        Ok(Self {
            state,
            requests,
            status,
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
                let notification = notification?;
                match madrid.decode(identity, &notification).await? {
                    Some(Incoming::Message(message, media)) => state.history()?.insert(&message, media)?,
                    Some(Incoming::Tapback(event)) => state.history()?.insert_tapback(&event)?,
                    Some(Incoming::Call(signal)) => calls.update(status, identity.handle(), signal),
                    None => (),
                }
                madrid.acknowledge(notification.id).await?;
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
                        let _ = reply.send(send_tapback(identity, state, madrid, target, request).await);
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
                }
            }
            _ = status.closed() => return Ok(()),
        }
    }
}

#[derive(Default)]
struct IncomingCalls {
    details: HashMap<uuid::Uuid, IncomingCallDetails>,
    ended: HashMap<uuid::Uuid, i64>,
}

struct IncomingCallDetails {
    endpoint: CallEndpoint,
    description: Option<Vec<u8>>,
    prekey: Option<PeerPrekey>,
    exchange: Option<CallMediaExchange>,
}

impl IncomingCallDetails {
    fn learn_prekey(&mut self, key: PeerPrekey) {
        // One caller prekey per ringing attempt. An established call negotiates rekeys separately.
        if self.prekey.as_ref().is_none_or(|known| known.same_as(&key)) {
            self.prekey = Some(key);
        }
    }

    fn learn_media(&mut self, media: Option<PeerMediaOffer>) {
        if let Some(offer) = media {
            if let Some(key) = offer.prekey {
                self.learn_prekey(key);
            }
            self.description.get_or_insert(offer.description);
        }
    }
}

impl IncomingCalls {
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
        let call = status
            .incoming_calls
            .iter()
            .find(|call| call.id == id && call.expires_ms > now_ms())
            .context("This FaceTime call has ended")?;
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
        let exchange = CallMediaExchange::prepare(call.clone(), description, prekey)?;
        let handshake = exchange.handshake.clone();
        details.exchange = Some(exchange);
        Ok(handshake)
    }

    fn update(&mut self, status: &watch::Sender<Status>, own: &str, signal: CallSignal) {
        let now = now_ms();
        status.send_if_modified(|status| {
            let expired = self.expire(status, now);
            let calls = &mut status.incoming_calls;
            match signal {
                CallSignal::Ring {
                    call: offer,
                    endpoint,
                    media,
                } if offer.expires_ms > now && !self.ended.contains_key(&offer.id) => {
                    if let Some(existing) = calls.iter_mut().find(|call| call.id == offer.id) {
                        // Bind a standalone invitation to its join without extending the original ring.
                        if existing.caller == offer.caller
                            && let Some(details) = self.details.get_mut(&offer.id)
                            && details.endpoint.matches(endpoint)
                        {
                            details.endpoint = endpoint;
                            details.learn_media(media);
                            if existing.mode.is_none() && offer.mode.is_some() {
                                existing.mode = offer.mode;
                                return true;
                            }
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
                        exchange: None,
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
                    {
                        details.learn_prekey(key);
                    }
                    expired
                }
                CallSignal::MediaKeys {
                    id,
                    sender,
                    endpoint,
                    offer,
                } => {
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
                    if let Some(index) = calls.iter().position(|call| {
                        let can_end = match endpoint {
                            Some(leaving) => {
                                sender == call.caller
                                    && self
                                        .details
                                        .get(&id)
                                        .is_some_and(|details| details.endpoint.matches(leaving))
                            }
                            None => sender == own || sender == call.caller,
                        };
                        call.id == id && can_end && received_ms >= call.received_ms
                    }) {
                        calls.remove(index);
                        self.end(id, now);
                        return true;
                    }
                    expired
                }
                CallSignal::Ring { .. } => expired,
            }
        });
    }
}

async fn send_tapback(
    identity: &Identity,
    state: &State,
    madrid: &mut Madrid,
    target: uuid::Uuid,
    request: SetTapback,
) -> Result<Vec<Tapback>> {
    let message = state
        .history()?
        .get(&target.to_string())?
        .context("This message is unavailable")?;
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
        message.has_part(part) || (request.reaction.is_none() && previous.is_some()),
        "This part of the message is unavailable"
    );
    if previous.map(|tapback| &tapback.kind) == request.reaction.as_ref() {
        return Ok(message.tapbacks);
    }
    let removed = request.reaction.is_none();
    let kind = request
        .reaction
        .or_else(|| previous.map(|tapback| tapback.kind.clone()))
        .context("No tapback to remove")?;
    let event = TapbackEvent {
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
    };
    let result = madrid.send_tapback(identity, &message, &event).await?;
    ensure!(
        result == Delivery::Accepted,
        "Apple did not confirm the reaction"
    );
    let history = state.history()?;
    history.insert_tapback(&event)?;
    history.tapbacks(&message.id, &message.address)
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
    fn only_the_caller_or_our_account_can_end_a_ring_and_replays_stay_ended() {
        let caller = "mailto:caller@example.org";
        let own = "mailto:receiver@example.org";
        let now = now_ms();
        let id = uuid::Uuid::new_v4();
        let (status, reader) = watch::channel(Status {
            connected: true,
            detail: String::new(),
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
            status: watch::channel(Status {
                connected: false,
                detail: String::new(),
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
