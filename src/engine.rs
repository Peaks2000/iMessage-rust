use std::{
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
    Conversation, Delivery, FILE_LIMIT, MAX_ATTACHMENTS, Message, SendText, Status, TEXT_LIMIT,
    address, now_ms,
};
use crate::{
    apple::{Identity, Madrid},
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
        self.status.borrow().clone()
    }

    pub fn chats(&self) -> Result<Vec<Conversation>> {
        self.state.history()?.chats()
    }

    pub fn messages(&self, chat: &str, offset: u32) -> Result<Vec<Message>> {
        self.state.history()?.messages(&address(chat)?, offset)
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
        for file in &request.files {
            file.validate()?;
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
    loop {
        let connection = tokio::select! {
            connection = Madrid::connect(&identity) => connection,
            _ = status.closed() => break,
        };
        let error = match connection {
            Ok(mut madrid) => {
                retry_delay = Duration::from_secs(3);
                set_status(&status, true, "Connected to Apple courier");
                match online(&identity, &state, &mut madrid, &mut requests, &status).await {
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
) -> Result<()> {
    loop {
        tokio::select! {
            notification = madrid.next_notification() => {
                let notification = notification?;
                if let Some((message, media)) = madrid.decode(identity, &notification).await? {
                    state.history()?.insert(&message, media)?;
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
                }
            }
            _ = status.closed() => return Ok(()),
        }
    }
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
    let existing = history.get(&request.id.to_string())?;
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
        outgoing: true,
        timestamp_ms: now_ms(),
        status: Delivery::Pending,
        attachments: request.files.iter().map(|file| file.info.clone()).collect(),
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
    status.send_replace(Status {
        connected,
        detail: detail.to_owned(),
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
}
