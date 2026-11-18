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
    CallMode, Conversation, FILE_LIMIT, IncomingCall, Message, PAGE_SIZE, SendText, SetTapback,
    Status, Tapback, api, display_address, engine::Engine, now_ms, storage,
};
use reqwest::{Client, Method, RequestBuilder, StatusCode, Url};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::sync::{
    mpsc::{UnboundedReceiver, UnboundedSender},
    oneshot, watch,
};
use uuid::Uuid;
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
    Refresh {
        chat: Option<String>,
        older: Option<OlderRefresh>,
    },
    Older {
        chat: String,
        offset: u32,
    },
    Send(SendText),
    Tapback {
        id: uuid::Uuid,
        request: SetTapback,
    },
    DeclineCall(uuid::Uuid),
    AnswerAudio {
        id: Uuid,
        muted: watch::Receiver<bool>,
        hang_up: oneshot::Receiver<()>,
    },
    DeleteConversation(String),
    Attachment {
        id: AttachmentId,
        purpose: Purpose,
    },
}

pub struct OlderRefresh {
    pub oldest: (i64, String),
    pub tapback_revision: Option<uuid::Uuid>,
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
    CallDeclined {
        id: uuid::Uuid,
        result: Result<()>,
    },
    CallConnected(Uuid),
    CallFinished {
        id: Uuid,
        result: Result<()>,
    },
    IncomingCalls(Vec<IncomingCall>),
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

pub struct AudioCallControls {
    mute: watch::Sender<bool>,
    end: Option<oneshot::Sender<()>>,
}

impl AudioCallControls {
    pub fn muted(&self) -> bool {
        *self.mute.borrow()
    }

    pub fn toggle_mute(&self) {
        self.mute.send_modify(|muted| *muted = !*muted);
    }

    pub fn ending(&self) -> bool {
        self.end.is_none()
    }

    pub fn hang_up(&mut self) {
        if let Some(end) = self.end.take() {
            let _ = end.send(());
        }
    }
}

impl Connection {
    #[cfg(test)]
    pub(super) fn test_channels() -> (Self, UnboundedReceiver<Action>, Sender<Event>) {
        let (actions, requests) = tokio::sync::mpsc::unbounded_channel();
        let (report, events) = mpsc::channel();
        (
            Self {
                actions,
                events,
                worker: std::thread::spawn(|| {}),
            },
            requests,
            report,
        )
    }

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

    pub fn answer_audio(&self, id: Uuid) -> Result<AudioCallControls> {
        let (mute, muted) = watch::channel(false);
        let (end, hang_up) = oneshot::channel();
        self.actions
            .send(Action::AnswerAudio { id, muted, hang_up })
            .map_err(|_| anyhow::anyhow!("The connection is closed"))?;
        Ok(AudioCallControls {
            mute,
            end: Some(end),
        })
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
    let calls_registered = status.facetime_registered;
    emit(events, context, Event::Ready(status));
    runtime.block_on(async {
        let backend = Arc::new(backend);
        if calls_registered {
            tokio::spawn(watch_calls(
                backend.clone(),
                events.clone(),
                context.clone(),
            ));
        }
        work(actions, events, context, backend).await;
    });
    Ok(())
}

async fn watch_calls(backend: Arc<Backend>, events: Sender<Event>, context: egui::Context) {
    let mut status_changes = match backend.as_ref() {
        Backend::Local(engine) => Some(engine.watch_status()),
        Backend::Remote(_) => None,
    };
    let mut previous: Vec<IncomingCall> = Vec::new();
    let delay = Duration::from_secs(4);
    let mut timer = tokio::time::interval_at(tokio::time::Instant::now() + delay, delay);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if let Ok(status) = backend.status().await {
            let mut calls = status.incoming_calls;
            calls.retain(|call| call.expires_ms > now_ms());
            if calls != previous {
                for call in &calls {
                    if !previous.iter().any(|earlier| earlier.id == call.id) {
                        let call = call.clone();
                        tokio::spawn(async move {
                            let kind = match call.mode {
                                Some(CallMode::Video) => "FaceTime Video",
                                Some(CallMode::Audio) => "FaceTime Audio",
                                None => "FaceTime",
                            };
                            let caller = display_address(&call.caller);
                            let _ = tokio::time::timeout(
                                Duration::from_secs(5),
                                tokio::process::Command::new("notify-send")
                                    .args([
                                        "--app-name",
                                        "iMessage",
                                        "--icon",
                                        "camera-video",
                                        "--expire-time=5000",
                                        "--hint",
                                        "string:sound-name:phone-incoming-call",
                                        "--",
                                        &format!("{kind} · {caller}"),
                                    ])
                                    .kill_on_drop(true)
                                    .output(),
                            )
                            .await;
                        });
                    }
                }
                previous = calls.clone();
                emit(&events, &context, Event::IncomingCalls(calls));
            }
        }
        if let Some(changes) = &mut status_changes {
            if changes.changed().await.is_err() {
                return;
            }
        } else {
            timer.tick().await;
        }
    }
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
            Action::Refresh { chat, older } => refresh(&backend, chat, older)
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
            Action::DeclineCall(id) => {
                let result = backend.decline_call(id).await;
                Event::CallDeclined { id, result }
            }
            Action::AnswerAudio {
                id,
                muted,
                mut hang_up,
            } => {
                let backend = backend.clone();
                let events = events.clone();
                let context = context.clone();
                tokio::spawn(async move {
                    let call = async {
                        let Backend::Local(engine) = backend.as_ref() else {
                            anyhow::bail!("FaceTime audio uses the Apple session on this computer");
                        };
                        let accepted = engine.answer_audio_call(id).await?;
                        accepted
                            .run_audio(muted, || emit(&events, &context, Event::CallConnected(id)))
                            .await
                    };
                    let result = tokio::select! {
                        biased;
                        _ = &mut hang_up => Ok(()),
                        result = call => result,
                    };
                    emit(&events, &context, Event::CallFinished { id, result });
                });
                continue;
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

async fn refresh(
    backend: &Backend,
    chat: Option<String>,
    older: Option<OlderRefresh>,
) -> Result<Event> {
    let status = backend.status().await?;
    let chats = backend.chats().await?;
    let thread = if let Some(chat) = chat {
        let mut page = backend.messages(&chat, 0).await?;
        if let Some(older) = older.filter(|older| older.tapback_revision != status.tapback_revision)
        {
            let mut pages = Vec::new();
            let mut offset = 0;
            let oldest = (older.oldest.0, older.oldest.1.as_str());
            while page.len() == PAGE_SIZE as usize
                && page
                    .first()
                    .is_some_and(|first| (first.timestamp_ms, first.id.as_str()) > oldest)
            {
                let Some(next) = u32::checked_add(offset, PAGE_SIZE) else {
                    break;
                };
                pages.push(page);
                offset = next;
                page = backend.messages(&chat, offset).await?;
            }
            if !pages.is_empty() {
                page.retain(|message| (message.timestamp_ms, message.id.as_str()) >= oldest);
            }
            pages.push(page);
            page = pages.into_iter().rev().flatten().collect();
        }
        Some((chat, page))
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
                            .timeout(Duration::from_secs(120))
                            .json(&request),
                    )
                    .await
            }
        }
    }

    async fn decline_call(&self, id: uuid::Uuid) -> Result<()> {
        match self {
            Self::Local(engine) => engine.decline_call(id).await,
            Self::Remote(remote) => {
                remote
                    .body(
                        remote.request(Method::POST, &format!("/v1/calls/{id}/decline")),
                        4096,
                    )
                    .await?;
                Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, extract::Query, routing::get};
    use linux_imessage::{Delivery, TapbackKind};

    #[tokio::test]
    async fn desktop_call_controls_are_scoped_to_the_answer_and_close_on_drop() -> Result<()> {
        let (connection, mut requests, _report) = Connection::test_channels();
        let id = Uuid::new_v4();
        let mut controls = connection.answer_audio(id)?;
        let Some(Action::AnswerAudio {
            id: answered,
            mut muted,
            hang_up,
        }) = requests.recv().await
        else {
            panic!("Expected a call answer");
        };
        assert_eq!(answered, id);
        assert!(!*muted.borrow());
        controls.toggle_mute();
        muted.changed().await?;
        assert!(*muted.borrow());
        assert!(!controls.ending());
        controls.hang_up();
        hang_up.await?;
        assert!(controls.ending());

        let controls = connection.answer_audio(Uuid::new_v4())?;
        let Some(Action::AnswerAudio { hang_up, .. }) = requests.recv().await else {
            panic!("Expected a call answer");
        };
        drop(controls);
        assert!(hang_up.await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn reaction_changes_refresh_loaded_older_messages() -> Result<()> {
        let chat = "mailto:peer@example.org";
        let id = |index| Uuid::from_u128(index).to_string();
        let reaction = Tapback {
            kind: TapbackKind::Heart,
            outgoing: false,
            part: 0,
        };
        let rows = Arc::new(
            (0..80)
                .map(|index| Message {
                    id: id(index),
                    address: chat.into(),
                    body: "Hello".into(),
                    text_part: None,
                    outgoing: true,
                    timestamp_ms: index as i64,
                    status: Delivery::Accepted,
                    attachments: Vec::new(),
                    tapbacks: if index == 3 {
                        vec![reaction.clone()]
                    } else {
                        Vec::new()
                    },
                })
                .collect::<Vec<_>>(),
        );
        let revision = Uuid::new_v4();
        let router = Router::new()
            .route(
                "/v1/status",
                get(move || async move {
                    Json(serde_json::json!({
                        "connected": true, "detail": "Connected", "tapback_revision": revision
                    }))
                }),
            )
            .route(
                "/v1/conversations",
                get(|| async { Json(Vec::<Conversation>::new()) }),
            )
            .route(
                "/v1/messages",
                get(
                    move |Query(query): Query<std::collections::HashMap<String, String>>| {
                        let rows = Arc::clone(&rows);
                        async move {
                            let offset = query["offset"].parse::<usize>().unwrap();
                            let end = rows.len().saturating_sub(offset);
                            Json(rows[end.saturating_sub(PAGE_SIZE as usize)..end].to_vec())
                        }
                    },
                ),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let settings = Settings {
            url: format!("http://{}", listener.local_addr()?),
            ..Settings::default()
        };
        let server = tokio::spawn(async move { axum::serve(listener, router).await });
        let backend = Backend::Remote(Remote::new(&settings, Zeroizing::new(String::new()))?);
        for known_revision in [Some(revision), None] {
            let older = OlderRefresh {
                oldest: (3, id(3)),
                tapback_revision: known_revision,
            };
            let Event::Refresh {
                thread: Some((_, messages)),
                ..
            } = refresh(&backend, Some(chat.into()), Some(older)).await?
            else {
                panic!("Expected a message refresh");
            };
            if known_revision.is_some() {
                assert_eq!(messages.len(), PAGE_SIZE as usize);
                assert_eq!(messages[0].id, id(5));
            } else {
                assert_eq!(messages.len(), 77);
                assert_eq!(messages[0].id, id(3));
                assert_eq!(messages[0].tapbacks, vec![reaction.clone()]);
            }
        }
        server.abort();
        Ok(())
    }
}
