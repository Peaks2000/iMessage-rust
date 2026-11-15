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

use crate::{Conversation, Delivery, Message, SendText, Status, TEXT_LIMIT, address, now_ms};
use crate::{
    apple::{Identity, Madrid},
    history::History,
};

#[derive(Clone)]
pub struct Engine {
    state: Arc<State>,
    requests: Option<mpsc::Sender<Request>>,
    status: watch::Receiver<Status>,
}

struct State {
    history: Mutex<History>,
    _lock: File,
}

struct Request {
    message: SendText,
    reply: oneshot::Sender<Result<Message>>,
}

impl Engine {
    pub fn start(root: &Path, identity: Option<Identity>) -> Result<Self> {
        let demo = identity.is_none();
        let profile = identity
            .as_ref()
            .map_or_else(|| "demo".into(), Identity::profile_id);
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
            demo,
            connected: demo,
            detail: if demo {
                "Demo · messages stay on this device".into()
            } else {
                "Connecting to Apple…".into()
            },
        });
        let requests = if let Some(identity) = identity {
            let (requests, receiver) = mpsc::channel(16);
            tokio::spawn(run_apple(identity, state.clone(), receiver, updates));
            Some(requests)
        } else {
            seed(&*state.history()?)?;
            None
        };
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
            !request.body.trim().is_empty()
                && request.body.len() <= TEXT_LIMIT
                && !request.body.contains('\0'),
            "Enter a message between 1 and {TEXT_LIMIT} UTF-8 bytes"
        );
        let Some(queue) = &self.requests else {
            let history = self.state.history()?;
            let (item, _) = start_send(&history, &request, Delivery::Demo)?;
            return Ok(item);
        };
        let (reply, answer) = oneshot::channel();
        queue
            .try_send(Request {
                message: request,
                reply,
            })
            .context("The Apple engine is busy or stopped")?;
        answer
            .await
            .context("The Apple engine stopped during the request")?
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
                    let result = state.history().and_then(|history| read_previous(&history, &request.message))
                        .and_then(|previous| previous.context("Apple courier is disconnected"));
                    let _ = request.reply.send(result);
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
                if let Some(message) = madrid.decode(identity, &notification).await? {
                    state.history()?.insert(&message)?;
                }
                madrid.acknowledge(notification.id).await?;
            }
            request = requests.recv() => {
                let Some(request) = request else { return Ok(()) };
                let value = send_on_courier(identity, state, madrid, &request.message).await;
                let _ = request.reply.send(value);
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
        start_send(&history, request, Delivery::Pending)?
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
                && existing.body == request.body,
            "Message ID is already used by a different message"
        );
    }
    Ok(existing)
}

fn start_send(history: &History, request: &SendText, status: Delivery) -> Result<(Message, bool)> {
    if let Some(existing) = read_previous(history, request)? {
        return Ok((existing, false));
    }
    let item = Message {
        id: request.id.to_string(),
        address: request.address.clone(),
        body: request.body.clone(),
        outgoing: true,
        timestamp_ms: now_ms(),
        status,
    };
    history.insert(&item)?;
    Ok((item, true))
}

fn set_status(status: &watch::Sender<Status>, connected: bool, detail: &str) {
    status.send_replace(Status {
        demo: false,
        connected,
        detail: detail.to_owned(),
    });
}

fn seed(history: &History) -> Result<()> {
    if !history.chats()?.is_empty() {
        return Ok(());
    }
    let sample = [
        (
            1,
            "maya",
            false,
            "Are we still meeting at the bookshop?",
            16,
        ),
        (2, "maya", true, "Yes! I’ll get there a little early.", 14),
        (3, "maya", false, "Perfect. I’ll bring coffee ☕", 12),
        (4, "elliot", false, "I found the photos from Saturday.", 85),
        (5, "noor", false, "That playlist is so good.", 240),
        (
            6,
            "ava",
            false,
            "Can you send me the address when you get a chance?",
            75,
        ),
        (
            7,
            "leo",
            false,
            "I found the one we were talking about.",
            115,
        ),
        (
            8,
            "hana",
            false,
            "Thursday works for me! How about six?",
            184,
        ),
        (
            9,
            "milo",
            false,
            "Sounds good. Let me know if you need anything.",
            205,
        ),
        (10, "ella", false, "Hope you had a lovely weekend.", 480),
        (11, "maya", false, "I finished that book you lent me.", 64),
        (
            12,
            "maya",
            false,
            "The last chapter got me. Have you read anything else by her?",
            63,
        ),
        (13, "maya", true, "I have! The new one is even better.", 62),
        (
            14,
            "maya",
            true,
            "There’s a copy at the bookshop on the corner. They’re doing a reading this weekend, too.",
            61,
        ),
        (
            15,
            "maya",
            false,
            "Let’s go. I haven’t been there in ages.",
            58,
        ),
        (
            16,
            "maya",
            true,
            "They have a little café upstairs now.",
            54,
        ),
        (17, "maya", false, "That sounds lovely.", 47),
        (
            18,
            "maya",
            true,
            "I’ll grab a table by the window if I get there first.",
            40,
        ),
    ];
    for (id, who, outgoing, body, minutes) in sample {
        history.insert(&Message {
            id: format!("demo-{id}"),
            address: format!("mailto:{who}@example.com"),
            body: body.into(),
            outgoing,
            timestamp_ms: now_ms() - minutes * 60_000,
            status: if outgoing {
                Delivery::Demo
            } else {
                Delivery::Received
            },
        })?;
    }
    Ok(())
}
