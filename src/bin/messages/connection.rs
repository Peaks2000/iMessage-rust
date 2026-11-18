use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        mpsc::{self, Receiver, Sender},
    },
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use eframe::egui;
use linux_imessage::{
    Conversation, FILE_LIMIT, Message, SendText, SetTapback, Status, Tapback, api, engine::Engine,
    storage,
};
use reqwest::{Client, Method, RequestBuilder, StatusCode, Url};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use zeroize::Zeroizing;

use super::attachments::{AttachmentId, Contents, Purpose};

#[derive(Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    #[serde(alias = "demo")]
    Local,
    Remote,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct Settings {
    pub mode: Mode,
    pub url: String,
    pub username: String,
    pub remember: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            mode: Mode::Local,
            url: "http://127.0.0.1:7848".into(),
            username: String::new(),
            remember: false,
        }
    }
}

impl Settings {
    pub fn read(root: &Path) -> Result<Self> {
        let path = root.join("client.json");
        if !path.exists() {
            return Ok(Self::default());
        }
        Ok(serde_json::from_slice(&storage::read_private(&path)?)?)
    }

    fn account(&self) -> Result<String> {
        Ok(format!(
            "remote:{}:{}",
            api::server_url(&self.url)?.origin().ascii_serialization(),
            self.username
        ))
    }
}

pub enum Action {
    Refresh(Option<String>),
    Older { chat: String, offset: u32 },
    Send(SendText),
    Tapback { id: uuid::Uuid, request: SetTapback },
    DeleteConversation(String),
    Attachment { id: AttachmentId, purpose: Purpose },
}

pub enum Event {
    Ready(Status),
    LocalUnregistered,
    ConnectionError(String),
    Refresh {
        status: Status,
        chats: Vec<Conversation>,
        thread: Option<(String, Vec<Message>)>,
    },
    Older {
        chat: String,
        result: Result<Vec<Message>>,
    },
    Sent {
        request: SendText,
        result: Result<Message>,
    },
    Tapback {
        id: uuid::Uuid,
        result: Result<Vec<Tapback>>,
    },
    ConversationDeleted {
        chat: String,
        result: Result<()>,
    },
    Attachment {
        id: AttachmentId,
        purpose: Purpose,
        result: Result<Contents>,
    },
    Error(String),
}

pub struct Connection {
    pub actions: UnboundedSender<Action>,
    pub events: Receiver<Event>,
    worker: std::thread::JoinHandle<()>,
}

impl Connection {
    pub fn start(
        context: &egui::Context,
        root: PathBuf,
        settings: Settings,
        previous: Option<Settings>,
        password: Zeroizing<String>,
        stop_first: Option<Self>,
    ) -> Self {
        let (actions, receive) = tokio::sync::mpsc::unbounded_channel();
        let (send, events) = mpsc::channel();
        let context = context.clone();
        let worker = std::thread::spawn(move || {
            if let Some(old) = stop_first {
                let Self {
                    actions, worker, ..
                } = old;
                drop(actions);
                let _ = worker.join();
            }
            let result = run(
                receive, &send, &context, &root, &settings, previous, password,
            );
            if let Err(error) = result {
                let _ = send.send(Event::ConnectionError(error.to_string()));
                context.request_repaint();
            }
        });
        Self {
            actions,
            events,
            worker,
        }
    }
}

fn run(
    actions: UnboundedReceiver<Action>,
    events: &Sender<Event>,
    context: &egui::Context,
    root: &Path,
    settings: &Settings,
    previous: Option<Settings>,
    mut password: Zeroizing<String>,
) -> Result<()> {
    let identity = if settings.mode == Mode::Local {
        let Some(identity) = storage::load_local_session(root)? else {
            emit(events, context, Event::LocalUnregistered);
            return Ok(());
        };
        Some(identity)
    } else {
        None
    };
    if settings.mode == Mode::Remote
        && !settings.username.is_empty()
        && password.is_empty()
        && (settings.remember
            || previous.as_ref().is_some_and(|previous| {
                previous.mode == Mode::Remote
                    && previous.remember
                    && previous.account().ok() == settings.account().ok()
            }))
    {
        password = storage::read_password(&settings.account()?)?;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let backend = runtime.block_on(async {
        match identity {
            Some(identity) => Engine::start(root, identity).map(Backend::Local),
            None => Remote::new(settings, password).map(Backend::Remote),
        }
    })?;
    let status = runtime.block_on(backend.status())?;
    if let Some(previous) = previous {
        persist(root, settings, &previous, &backend)?;
    }
    emit(events, context, Event::Ready(status));
    runtime.block_on(work(actions, events, context, Arc::new(backend)));
    Ok(())
}

fn persist(root: &Path, settings: &Settings, previous: &Settings, backend: &Backend) -> Result<()> {
    if let Backend::Remote(remote) = backend
        && settings.remember
        && !remote.username.is_empty()
    {
        storage::save_password(&settings.account()?, &remote.password)?;
    }
    if settings.mode == Mode::Remote
        && !settings.remember
        && previous.remember
        && previous.mode == Mode::Remote
        && previous.account()? == settings.account()?
    {
        storage::forget_secret(&previous.account()?)?;
    }
    storage::write_private(
        &root.join("client.json"),
        &serde_json::to_vec_pretty(settings)?,
    )
}

async fn work(
    mut actions: UnboundedReceiver<Action>,
    events: &Sender<Event>,
    context: &egui::Context,
    backend: Arc<Backend>,
) {
    while let Some(action) = actions.recv().await {
        let event = match action {
            Action::Refresh(chat) => refresh(&backend, chat)
                .await
                .unwrap_or_else(|error| Event::Error(error.to_string())),
            Action::Older { chat, offset } => {
                let result = backend.messages(&chat, offset).await;
                Event::Older { chat, result }
            }
            Action::Send(request) => {
                let result = backend.send(&request).await;
                Event::Sent { request, result }
            }
            Action::Tapback { id, request } => {
                let result = backend.set_tapback(id, request).await;
                Event::Tapback { id, result }
            }
            Action::DeleteConversation(chat) => {
                let result = backend.delete_conversation(&chat).await;
                Event::ConversationDeleted { chat, result }
            }
            Action::Attachment { id, purpose } => {
                let backend = backend.clone();
                let events = events.clone();
                let context = context.clone();
                tokio::spawn(async move {
                    let result = async {
                        let bytes = backend.attachment(id).await?;
                        tokio::task::spawn_blocking(move || Contents::load(bytes, purpose)).await?
                    }
                    .await;
                    emit(
                        &events,
                        &context,
                        Event::Attachment {
                            id,
                            purpose,
                            result,
                        },
                    );
                });
                continue;
            }
        };
        emit(events, context, event);
    }
}

fn emit(events: &Sender<Event>, context: &egui::Context, event: Event) {
    let _ = events.send(event);
    context.request_repaint();
}

async fn refresh(backend: &Backend, chat: Option<String>) -> Result<Event> {
    let status = backend.status().await?;
    let chats = backend.chats().await?;
    let thread = if let Some(chat) = chat {
        let messages = backend.messages(&chat, 0).await?;
        Some((chat, messages))
    } else {
        None
    };
    Ok(Event::Refresh {
        status,
        chats,
        thread,
    })
}

enum Backend {
    Local(Engine),
    Remote(Remote),
}

impl Backend {
    async fn status(&self) -> Result<Status> {
        match self {
            Self::Local(engine) => Ok(engine.status()),
            Self::Remote(remote) => remote.get("/v1/status").await,
        }
    }

    async fn chats(&self) -> Result<Vec<Conversation>> {
        match self {
            Self::Local(engine) => engine.chats(),
            Self::Remote(remote) => remote.get("/v1/conversations").await,
        }
    }

    async fn messages(&self, address: &str, offset: u32) -> Result<Vec<Message>> {
        match self {
            Self::Local(engine) => engine.messages(address, offset),
            Self::Remote(remote) => {
                remote
                    .fetch(remote.request(Method::GET, "/v1/messages").query(&[
                        ("address", address),
                        ("offset", offset.to_string().as_str()),
                    ]))
                    .await
            }
        }
    }

    async fn send(&self, request: &SendText) -> Result<Message> {
        match self {
            Self::Local(engine) => engine.send(request.clone()).await,
            Self::Remote(remote) => {
                remote
                    .fetch(
                        remote
                            .request(Method::POST, "/v1/messages")
                            .timeout(Duration::from_secs(120))
                            .json(request),
                    )
                    .await
            }
        }
    }

    async fn delete_conversation(&self, chat: &str) -> Result<()> {
        match self {
            Self::Local(engine) => engine.delete_conversation(chat),
            Self::Remote(remote) => {
                remote
                    .body(
                        remote
                            .request(Method::DELETE, "/v1/conversations")
                            .query(&[("address", chat)]),
                        4096,
                    )
                    .await?;
                Ok(())
            }
        }
    }

    async fn set_tapback(&self, id: uuid::Uuid, request: SetTapback) -> Result<Vec<Tapback>> {
        match self {
            Self::Local(engine) => engine.set_message_tapback(id, request).await,
            Self::Remote(remote) => {
                remote
                    .fetch(
                        remote
                            .request(Method::PUT, &format!("/v1/messages/{id}/tapback"))
                            .json(&request),
                    )
                    .await
            }
        }
    }

    async fn attachment(&self, id: AttachmentId) -> Result<bytes::Bytes> {
        match self {
            Self::Local(engine) => engine.attachment(id.message, id.index).await,
            Self::Remote(remote) => Ok(remote
                .body(
                    remote
                        .request(Method::GET, &id.route())
                        .timeout(Duration::from_secs(60)),
                    FILE_LIMIT,
                )
                .await?
                .into()),
        }
    }
}

struct Remote {
    client: Client,
    base: Url,
    username: String,
    password: Zeroizing<String>,
}

impl Remote {
    fn new(settings: &Settings, password: Zeroizing<String>) -> Result<Self> {
        ensure!(
            settings.username.is_empty() == password.is_empty(),
            "Enter both the username and password, or leave both blank"
        );
        if !settings.username.is_empty() {
            api::validate_username(&settings.username)?;
            ensure!(password.len() <= 512, "The server password is too long");
        }
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            client,
            base: api::server_url(&settings.url)?,
            username: settings.username.clone(),
            password,
        })
    }

    fn request(&self, method: Method, route: &str) -> RequestBuilder {
        let request = self
            .client
            .request(
                method,
                self.base.join(route).expect("Fixed API route is valid"),
            )
            .header("x-messages-api", "1");
        if self.username.is_empty() {
            request
        } else {
            request.basic_auth(&self.username, Some(self.password.as_str()))
        }
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.fetch(self.request(Method::GET, path)).await
    }

    async fn fetch<T: DeserializeOwned>(&self, request: RequestBuilder) -> Result<T> {
        serde_json::from_slice(&self.body(request, 4 * 1024 * 1024).await?)
            .context("The server returned an invalid Messages API response")
    }

    async fn body(&self, request: RequestBuilder, max: usize) -> Result<Vec<u8>> {
        let mut response = request
            .send()
            .await
            .map_err(|error| error.without_url())
            .context("Could not connect to the server")?;
        let status = response.status();
        if status == StatusCode::UNAUTHORIZED {
            anyhow::bail!("The server requires a valid username and password");
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            anyhow::bail!("The server is busy. Try again in a moment");
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| error.without_url())?
        {
            ensure!(
                body.len() + chunk.len() <= max,
                "The server response is too large"
            );
            body.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            if let Ok(error) = serde_json::from_slice::<api::ApiError>(&body) {
                anyhow::bail!("{}", error.error);
            }
            anyhow::bail!("The server returned HTTP {}", status.as_u16());
        }
        Ok(body)
    }
}
