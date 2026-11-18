use std::{
    collections::HashMap,
    path::PathBuf,
    rc::Rc,
    sync::mpsc::{Receiver, TryRecvError},
    time::{Duration, Instant},
};

use chrono::{Local, NaiveDate, TimeZone};
use eframe::egui::{
    self, Align, Align2, Color32, FontId, Frame, Layout, Margin, Rect, RichText, ScrollArea, Sense,
    Stroke, StrokeKind, TextEdit, Ui, UiBuilder, pos2, vec2,
};
use linux_imessage::{
    CallMode, Conversation, Delivery, FILE_LIMIT, IncomingCall, MAX_ATTACHMENTS, Message,
    PAGE_SIZE, SendText, SetTapback, Status, TEXT_LIMIT, TapbackKind, address, display_address,
    engine::video::VideoFrame, now_ms, storage,
};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use super::{
    attachments::{self, AttachmentId, DraftFile, LoadedFile, Preview, TranscriptMedia},
    clipboard::Clipboard,
    connection::{Action, CallControls, Connection, Event, Mode, OlderRefresh, Settings},
    contacts::Contacts,
    links::MessageText,
    mac_setup::{MacSetup, Outcome as MacOutcome},
    ringing::RingAction,
    session_import::{Outcome as ImportOutcome, SessionImport},
};

use super::chrome::{
    self, BLUE, BUBBLE_GRAY, CANVAS, DANGER, HAIRLINE, INK, Icon, MUTED, SIDEBAR, TOOLBAR_HEIGHT,
};

const POLL: Duration = Duration::from_secs(4);
const MOTION: f32 = 0.30;
const LOCAL_UNREGISTERED: &str = "Open Settings → This Computer to set up iMessage with your Mac.";
const CALL_GREEN: Color32 = Color32::from_rgb(37, 158, 67);

pub struct MessagesApp {
    root: PathBuf,
    config: Settings,
    settings: Option<SettingsForm>,
    delete_conversation: Option<DeleteConversation>,
    session_import: Option<SessionImport>,
    mac_setup: Option<MacSetup>,
    contacts: Contacts,
    local_unregistered: bool,
    connection: Option<Connection>,
    candidate: Option<Connection>,
    status: Option<Status>,
    error: Option<String>,
    chats: Vec<Conversation>,
    pins: Vec<String>,
    message_motion: HashMap<String, Instant>,
    thread_motion: Option<Instant>,
    thread_loaded: bool,
    info_started: Option<Instant>,
    plus_started: Option<Instant>,
    selected: Option<String>,
    messages: Vec<Message>,
    search: String,
    drafts: HashMap<String, Draft>,
    pending_draft: Option<Draft>,
    picking: Option<(String, Receiver<anyhow::Result<Vec<LoadedFile>>>)>,
    clipboard: Rc<Clipboard>,
    media: TranscriptMedia,
    composing: Option<String>,
    compose_error: Option<String>,
    focus_recipient: bool,
    focus_composer: bool,
    refresh_running: bool,
    refresh_at: Instant,
    history_all: bool,
    loading_older: bool,
    sending: bool,
    retry: Option<SendText>,
    tapback_pending: Option<Uuid>,
    incoming_calls: Vec<IncomingCall>,
    active_call: Option<DesktopCall>,
    declining_call: Option<Uuid>,
    call_error: Option<(Uuid, String)>,
    call_activation: Option<String>,
    quitting: bool,
}

struct DesktopCall {
    id: Uuid,
    peer: String,
    outgoing: bool,
    connected_at: Option<Instant>,
    controls: CallControls,
    video_texture: Option<egui::TextureHandle>,
    camera_preview: Option<egui::TextureHandle>,
    preview_position: egui::Vec2,
}

#[derive(Default)]
struct Draft {
    text: String,
    files: Vec<DraftFile>,
}

struct SettingsForm {
    config: Settings,
    password: String,
    error: Option<String>,
    opened: Instant,
}

struct DeleteConversation {
    chat: String,
    pending: bool,
    error: Option<String>,
}

impl Drop for SettingsForm {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl MessagesApp {
    pub fn new(
        ctx: &egui::Context,
        root: PathBuf,
        mac_setup: bool,
        clipboard: Rc<Clipboard>,
    ) -> Self {
        chrome::theme(ctx);
        let (config, error) = match Settings::read(&root) {
            Ok(config) => (config, None),
            Err(error) => (Settings::default(), Some(error.to_string())),
        };
        let candidate = (!mac_setup).then(|| {
            Connection::start(
                ctx,
                root.clone(),
                config.clone(),
                None,
                Zeroizing::default(),
                None,
            )
        });
        let contacts = Contacts::new(&root);
        Self {
            root,
            config,
            settings: None,
            delete_conversation: None,
            session_import: None,
            mac_setup: mac_setup.then(MacSetup::new),
            contacts,
            local_unregistered: false,
            candidate,
            connection: None,
            status: None,
            error,
            chats: Vec::new(),
            pins: Vec::new(),
            message_motion: HashMap::new(),
            thread_motion: None,
            thread_loaded: false,
            info_started: None,
            plus_started: None,
            selected: None,
            messages: Vec::new(),
            search: String::new(),
            drafts: HashMap::new(),
            pending_draft: None,
            picking: None,
            clipboard,
            media: TranscriptMedia::default(),
            composing: None,
            compose_error: None,
            focus_recipient: false,
            focus_composer: false,
            refresh_running: false,
            refresh_at: Instant::now(),
            history_all: true,
            loading_older: false,
            sending: false,
            retry: None,
            tapback_pending: None,
            incoming_calls: Vec::new(),
            active_call: None,
            declining_call: None,
            call_error: None,
            call_activation: None,
            quitting: false,
        }
    }

    fn process(&mut self, ctx: &egui::Context) {
        self.contacts.poll(ctx);
        self.poll_picker(ctx);
        if let Some(event) = self
            .candidate
            .as_ref()
            .and_then(|connection| connection.events.try_recv().ok())
        {
            match event {
                Event::Ready(mut status) => {
                    self.connection = self.candidate.take();
                    self.delete_conversation = None;
                    if let Some(form) = self.settings.take() {
                        self.config = form.config.clone();
                    }
                    if self.config.mode == Mode::Local {
                        self.local_unregistered = false;
                    }
                    self.incoming_calls = std::mem::take(&mut status.incoming_calls);
                    self.active_call = None;
                    self.status = Some(status);
                    self.pins = self.read_pins();
                    self.chats.clear();
                    self.thread_loaded = false;
                    self.message_motion.clear();
                    self.composing = None;
                    self.selected = None;
                    self.messages.clear();
                    self.drafts.clear();
                    self.pending_draft = None;
                    self.picking = None;
                    self.media = TranscriptMedia::default();
                    self.retry = None;
                    self.tapback_pending = None;
                    self.declining_call = None;
                    self.call_error = None;
                    self.error = None;
                    self.refresh_running = false;
                    self.loading_older = false;
                    self.sending = false;
                    self.refresh_at = Instant::now();
                }
                Event::LocalUnregistered => {
                    self.candidate = None;
                    self.local_unregistered = true;
                }
                Event::ConnectionError(error) => {
                    self.candidate = None;
                    if self.settings.is_none() && self.connection.is_none() {
                        self.open_settings();
                    }
                    if let Some(form) = &mut self.settings {
                        form.error = Some(error);
                    } else {
                        self.error = Some(error);
                    }
                }
                _ => {}
            }
        }

        while let Some(event) = self
            .connection
            .as_ref()
            .and_then(|connection| connection.events.try_recv().ok())
        {
            match event {
                Event::Refresh {
                    status,
                    chats,
                    thread,
                } => {
                    self.refresh_running = false;
                    self.status = Some(status);
                    self.chats = chats;
                    if self.selected.is_none()
                        && let Some(chat) = self.chats.first()
                    {
                        self.select(chat.address.clone(), false);
                    }
                    if let Some((chat, messages)) = thread
                        && self.selected.as_deref() == Some(&chat)
                    {
                        if messages.len() < PAGE_SIZE as usize && !self.sending {
                            // A complete refresh also reflects deletions made by another client.
                            self.messages.retain(|previous| {
                                messages.iter().any(|message| message.id == previous.id)
                            });
                            self.history_all = true;
                        } else if self.messages.len() < PAGE_SIZE as usize {
                            self.history_all = messages.len() < PAGE_SIZE as usize;
                        }
                        if self.thread_loaded {
                            let changed = Instant::now();
                            for message in &messages {
                                if !self.messages.iter().any(|old| old.id == message.id)
                                    && self.messages.last().is_none_or(|last| {
                                        last.timestamp_ms <= message.timestamp_ms
                                    })
                                {
                                    self.message_motion.insert(message.id.clone(), changed);
                                }
                            }
                        } else {
                            self.thread_motion = Some(Instant::now());
                        }
                        self.thread_loaded = true;
                        self.merge(messages);
                    }
                }
                Event::Older { chat, result } => {
                    if self.selected.as_deref() == Some(&chat) {
                        self.loading_older = false;
                        match result {
                            Ok(rows) => {
                                self.history_all = rows.len() < PAGE_SIZE as usize;
                                self.merge(rows);
                            }
                            Err(error) => self.error = Some(error.to_string()),
                        }
                    }
                }
                Event::Sent { request, result } => {
                    self.sending = false;
                    let draft = self.pending_draft.take();
                    match result {
                        Ok(item) if item.status != Delivery::Failed => {
                            self.retry = None;
                            if self.selected.as_deref() == Some(&item.address) {
                                self.merge(vec![item]);
                            }
                        }
                        result => {
                            self.error = Some(match result {
                                Ok(item) => {
                                    if self.selected.as_deref() == Some(&item.address) {
                                        self.merge(vec![item]);
                                    }
                                    "The courier rejected the message. Send again to retry.".into()
                                }
                                Err(error) => error.to_string(),
                            });
                            if let Some(draft) = draft {
                                self.drafts.insert(request.address.clone(), draft);
                            }
                            let id = request.id.to_string();
                            if let Some(message) =
                                self.messages.iter_mut().find(|message| message.id == id)
                                && message.status == Delivery::Pending
                            {
                                message.status = Delivery::Unknown;
                            }
                            self.retry = Some(request);
                        }
                    }
                    self.refresh_at = Instant::now();
                }
                Event::ConversationDeleted { chat, result } => match result {
                    Ok(()) => self.conversation_deleted(&chat),
                    Err(error) => {
                        if let Some(form) = &mut self.delete_conversation {
                            form.pending = false;
                            form.error = Some(format!("{error:#}"));
                        }
                    }
                },
                Event::Tapback { id, result } => {
                    self.tapback_pending = None;
                    match result {
                        Ok(tapbacks) => {
                            if let Some(message) = self
                                .messages
                                .iter_mut()
                                .find(|message| Uuid::parse_str(&message.id).ok() == Some(id))
                            {
                                message.tapbacks = tapbacks;
                            }
                            self.error = None;
                        }
                        Err(error) => self.error = Some(format!("{error:#}")),
                    }
                    self.refresh_at = Instant::now();
                }
                Event::IncomingCalls(calls) => self.incoming_calls = calls,
                Event::IncomingCallAction { id, action, token } => {
                    if self.respond_to_ring(id, action) && action != RingAction::Decline {
                        self.call_activation = token;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                    }
                }
                Event::CallConnected { id, mode } => {
                    if let Some(call) = &mut self.active_call
                        && call.id == id
                    {
                        call.controls.set_negotiated_mode(mode);
                        call.connected_at = Some(Instant::now());
                    }
                }
                Event::CallFinished { id, result } => {
                    if self.active_call.as_ref().is_some_and(|call| call.id == id) {
                        self.active_call = None;
                        if let Err(error) = result {
                            let error = format!("{error:#}");
                            if self
                                .incoming_calls
                                .iter()
                                .any(|call| call.id == id && call.expires_ms > now_ms())
                            {
                                self.call_error = Some((id, error));
                            } else {
                                self.error = Some(error);
                            }
                        }
                    }
                }
                Event::CallDeclined { id, result } => {
                    self.declining_call = None;
                    match result {
                        Ok(()) => {
                            self.incoming_calls.retain(|call| call.id != id);
                            self.call_error = None;
                        }
                        Err(error) => self.call_error = Some((id, format!("{error:#}"))),
                    }
                    self.refresh_at = Instant::now();
                }
                Event::Attachment {
                    id,
                    purpose,
                    result,
                } => self.media.received(ctx, id, purpose, result),
                Event::Error(error) => {
                    self.refresh_running = false;
                    self.error = Some(error);
                }
                Event::ConnectionError(error) => {
                    self.connection = None;
                    self.status = None;
                    self.active_call = None;
                    self.incoming_calls.clear();
                    self.error = Some(error);
                }
                Event::Ready(_) | Event::LocalUnregistered => {}
            }
        }
        if Instant::now() >= self.refresh_at
            && !self.refresh_running
            && !self.loading_older
            && let Some(connection) = &self.connection
        {
            let older = self
                .messages
                .first()
                .filter(|_| self.messages.len() >= PAGE_SIZE as usize)
                .map(|first| OlderRefresh {
                    oldest: (first.timestamp_ms, first.id.clone()),
                    tapback_revision: self
                        .status
                        .as_ref()
                        .and_then(|status| status.tapback_revision),
                });
            self.refresh_running = connection
                .actions
                .send(Action::Refresh {
                    chat: self.selected.clone(),
                    older,
                })
                .is_ok();
            self.refresh_at = Instant::now() + POLL;
        }
        self.message_motion
            .retain(|_, start| start.elapsed().as_secs_f32() < MOTION);
        ctx.request_repaint_after(POLL);
    }

    fn poll_picker(&mut self, ctx: &egui::Context) {
        let Some((_, pending)) = &self.picking else {
            return;
        };
        let result = match pending.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => Err(anyhow::anyhow!(
                "Loading the attachment stopped unexpectedly"
            )),
        };
        let (chat, _) = self.picking.take().expect("A picker returned a result");
        match result {
            Ok(files) if !files.is_empty() => {
                let draft = self.drafts.entry(chat.clone()).or_default();
                let size = draft
                    .files
                    .iter()
                    .map(|file| file.upload.info.size)
                    .chain(files.iter().map(|file| file.upload.info.size))
                    .sum::<usize>();
                if draft.files.len() + files.len() > MAX_ATTACHMENTS || size > FILE_LIMIT {
                    self.error = Some(format!(
                        "A message can contain up to {MAX_ATTACHMENTS} attachments and 32 MiB total"
                    ));
                    return;
                }
                draft.files.extend(files.into_iter().map(|file| DraftFile {
                    upload: file.upload,
                    preview: file.preview.map(|image| Preview::new(ctx, image)),
                }));
                self.error = None;
                self.focus_composer = self.selected.as_deref() == Some(&chat);
            }
            Ok(_) => (),
            Err(error) => self.error = Some(format!("{error:#}")),
        }
    }

    fn select(&mut self, who: String, focus: bool) {
        if self.selected.as_ref() != Some(&who) {
            self.selected = Some(who);
            self.thread_motion = Some(Instant::now());
            self.thread_loaded = false;
            self.messages.clear();
            self.history_all = true;
            self.loading_older = false;
            self.refresh_at = Instant::now();
        }
        self.focus_composer = focus;
    }

    fn merge(&mut self, messages: Vec<Message>) {
        let mut rows = self
            .messages
            .drain(..)
            .map(|message| (message.id.clone(), message))
            .collect::<HashMap<_, _>>();
        rows.extend(
            messages
                .into_iter()
                .map(|message| (message.id.clone(), message)),
        );
        self.messages = rows.into_values().collect();
        self.messages
            .sort_by(|a, b| (a.timestamp_ms, &a.id).cmp(&(b.timestamp_ms, &b.id)));
    }

    fn send(&mut self, chat: &str) {
        let Some(draft) = self.drafts.get(chat) else {
            return;
        };
        if self.sending
            || self.picking.is_some()
            || (draft.text.trim().is_empty() && draft.files.is_empty())
            || draft.text.len() > TEXT_LIMIT
        {
            return;
        }
        if let Some(connection) = &self.connection {
            let files = draft
                .files
                .iter()
                .map(|file| file.upload.clone())
                .collect::<Vec<_>>();
            let request = self
                .retry
                .take()
                .filter(|item| {
                    item.address == chat && item.body == draft.text && item.files == files
                })
                .unwrap_or_else(|| SendText {
                    id: Uuid::new_v4(),
                    address: chat.to_owned(),
                    body: draft.text.clone(),
                    files,
                });
            self.sending = connection
                .actions
                .send(Action::Send(request.clone()))
                .is_ok();
            if self.sending {
                self.media.seed(request.id, &draft.files);
                self.pending_draft = self.drafts.remove(chat);
                let id = request.id.to_string();
                self.message_motion.insert(id.clone(), Instant::now());
                self.merge(vec![Message {
                    id,
                    address: request.address,
                    body: request.body,
                    text_part: None,
                    outgoing: true,
                    timestamp_ms: now_ms(),
                    status: Delivery::Pending,
                    attachments: request.files.iter().map(|file| file.info.clone()).collect(),
                    tapbacks: Vec::new(),
                }]);
                self.error = None;
                self.focus_composer = true;
            }
        }
    }

    fn open_settings(&mut self) {
        self.settings = Some(SettingsForm {
            config: self.config.clone(),
            password: String::new(),
            error: None,
            opened: Instant::now(),
        });
    }

    fn start_compose(&mut self) {
        if self.config.mode == Mode::Local && self.local_unregistered {
            return;
        }
        self.composing = Some(String::new());
        self.compose_error = None;
        self.focus_recipient = true;
    }

    fn pins_path(&self) -> PathBuf {
        let name = if self.config.mode == Mode::Remote {
            let origin = linux_imessage::api::server_url(&self.config.url)
                .map(|url| url.origin().ascii_serialization())
                .unwrap_or_default();
            let digest =
                openssl::sha::sha256(format!("{origin}\n{}", self.config.username).as_bytes());
            let id = digest[..8]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            format!("pins-{id}.json")
        } else {
            "pins-local.json".into()
        };
        self.root.join(name)
    }

    fn read_pins(&self) -> Vec<String> {
        storage::read_private(&self.pins_path())
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    fn toggle_pin(&mut self, address: &str) {
        if let Some(index) = self.pins.iter().position(|pinned| pinned == address) {
            self.pins.remove(index);
        } else {
            self.pins.push(address.to_owned());
        }
        self.save_pins();
    }

    fn save_pins(&mut self) {
        if let Err(error) = serde_json::to_vec(&self.pins)
            .map_err(anyhow::Error::from)
            .and_then(|bytes| storage::write_private(&self.pins_path(), &bytes))
        {
            self.error = Some(error.to_string());
        }
    }

    fn sidebar(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("conversations")
            .default_width(291.)
            .min_width(109.)
            .max_width(372.)
            .show_separator_line(false)
            .frame(
                Frame::new()
                    .fill(SIDEBAR)
                    .corner_radius(egui::CornerRadius {
                        nw: chrome::window_radius(ctx),
                        sw: chrome::window_radius(ctx),
                        ..Default::default()
                    }),
            )
            .show(ctx, |ui| {
                ui.spacing_mut().item_spacing = vec2(0., 0.);
                let compact = ui.available_width() < 170.;
                let width = ui.available_width();
                let (bar, _) = ui.allocate_exact_size(vec2(width, TOOLBAR_HEIGHT), Sense::hover());
                {
                    let mut lights = ui.new_child(UiBuilder::new().max_rect(Rect::from_min_size(
                        bar.min + vec2(16., 14.),
                        vec2(56., 20.),
                    )));
                    if chrome::traffic_lights(&mut lights) {
                        self.quit(ctx);
                    }
                }
                let compose_width = if compact { 30. } else { 38. };
                if compact {
                    chrome::drag_region(ui, Rect::from_min_max(bar.min + vec2(73., 0.), bar.max));
                } else {
                    chrome::drag_region(
                        ui,
                        Rect::from_min_max(
                            bar.min + vec2(76., 0.),
                            bar.max - vec2(compose_width, 0.),
                        ),
                    );
                }
                let button_rect = if compact {
                    Rect::from_center_size(pos2(bar.center().x, bar.bottom() + 17.), vec2(26., 28.))
                } else {
                    Rect::from_center_size(pos2(bar.right() - 25., bar.center().y), vec2(26., 28.))
                };
                let mut button = ui.new_child(UiBuilder::new().max_rect(button_rect));
                if chrome::icon_button(&mut button, Icon::Compose, "New Message", None).clicked() {
                    self.start_compose();
                }
                button.response().context_menu(|ui| {
                    if ui.button("Settings…").clicked() {
                        self.open_settings();
                        ui.close();
                    }
                });

                if compact {
                    ui.add_space(35.);
                } else {
                    self.search_field(ui);
                    ui.add_space(8.);
                }

                let search = if compact {
                    String::new()
                } else {
                    self.search.trim().to_lowercase()
                };
                let mut clicked = None;
                let mut menu = None;
                ScrollArea::vertical()
                    .id_salt("conversation-list")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add_space(4.);
                        if search.is_empty() {
                            let pinned = self
                                .pins
                                .iter()
                                .filter_map(|address| {
                                    self.chats.iter().find(|chat| &chat.address == address)
                                })
                                .collect::<Vec<_>>();
                            if !pinned.is_empty() {
                                let columns = if compact {
                                    1
                                } else if width < 230. {
                                    2
                                } else {
                                    3
                                };
                                let tile_width = (ui.available_width() - 19.) / columns as f32;
                                for row in pinned.chunks(columns) {
                                    ui.horizontal(|ui| {
                                        ui.add_space(9.);
                                        for chat in row {
                                            let name = self.contacts.name(&chat.address);
                                            let active = self.composing.is_none()
                                                && self.selected.as_deref() == Some(&chat.address);
                                            let response = pin_tile(
                                                ui, chat, name, active, compact, tile_width,
                                            );
                                            if response.clicked() {
                                                clicked = Some(chat.address.clone());
                                            }
                                            if let Some(action) = conversation_menu(&response, true)
                                            {
                                                menu = Some((chat.address.clone(), action));
                                            }
                                        }
                                    });
                                }
                                ui.add_space(5.);
                            }
                        }

                        let mut found = false;
                        for chat in &self.chats {
                            let pinned = self.pins.contains(&chat.address);
                            if pinned && search.is_empty() {
                                continue;
                            }
                            let name = self.contacts.name(&chat.address);
                            if !search.is_empty()
                                && !name.to_lowercase().contains(&search)
                                && !display_address(&chat.address)
                                    .to_lowercase()
                                    .contains(&search)
                                && !chat.preview.to_lowercase().contains(&search)
                            {
                                continue;
                            }
                            let active = self.composing.is_none()
                                && self.selected.as_deref() == Some(&chat.address);
                            found = true;
                            let response = chat_row(ui, chat, name, active, compact);
                            if response.clicked() {
                                clicked = Some(chat.address.clone());
                            }
                            if let Some(action) = conversation_menu(&response, pinned) {
                                menu = Some((chat.address.clone(), action));
                            }
                        }

                        if !found && ((!search.is_empty()) || self.chats.is_empty()) {
                            Frame::new()
                                .inner_margin(Margin::symmetric(14, 11))
                                .show(ui, |ui| {
                                    ui.label(
                                        RichText::new(if search.is_empty() {
                                            "No Conversations"
                                        } else {
                                            "No Results"
                                        })
                                        .size(12.)
                                        .color(MUTED),
                                    );
                                });
                        }
                    });
                if let Some(address) = clicked {
                    self.composing = None;
                    self.select(address, false);
                }
                if let Some((chat, action)) = menu {
                    match action {
                        ConversationMenu::TogglePin => self.toggle_pin(&chat),
                        ConversationMenu::Delete => {
                            self.delete_conversation = Some(DeleteConversation {
                                chat,
                                pending: false,
                                error: None,
                            })
                        }
                    }
                }
                let rect = ui.max_rect();
                ui.painter().line_segment(
                    [
                        rect.right_top() - vec2(0.5, 0.),
                        rect.right_bottom() - vec2(0.5, 0.),
                    ],
                    Stroke::new(0.8_f32, HAIRLINE),
                );
            });
    }

    fn search_field(&mut self, ui: &mut Ui) {
        let (row, _) = ui.allocate_exact_size(vec2(ui.available_width(), 27.), Sense::hover());
        let rect = row.shrink2(vec2(10., 0.));
        ui.painter()
            .rect_filled(rect, 6, Color32::from_black_alpha(17));
        chrome::icon(
            ui.painter(),
            rect.left_center() + vec2(12., 0.),
            Icon::Search,
            MUTED,
        );
        let field = Rect::from_min_max(rect.min + vec2(24., 0.), rect.max - vec2(7., 0.));
        ui.put(
            field,
            TextEdit::singleline(&mut self.search)
                .frame(false)
                .margin(Margin::symmetric(1, 5))
                .font(FontId::proportional(12.))
                .hint_text("Search")
                .desired_width(field.width()),
        );
    }

    fn right_panel(&mut self, ctx: &egui::Context, paste: bool) {
        let chat = self.selected.clone().filter(|_| self.composing.is_none());
        self.toolbar(ctx, chat.as_deref());
        if let Some(chat) = &chat {
            self.composer(ctx, chat, paste);
        }
        egui::CentralPanel::default()
            .frame(Frame::new().fill(CANVAS).corner_radius(egui::CornerRadius {
                se: if chat.is_none() {
                    chrome::window_radius(ctx)
                } else {
                    0
                },
                ..Default::default()
            }))
            .show(ctx, |ui| {
                if let Some(chat) = &chat {
                    self.transcript(ui, chat);
                } else if self.composing.is_some() {
                    self.contact_suggestions(ui);
                } else {
                    ui.centered_and_justified(|ui| {
                        let label = if self.candidate.is_some() {
                            "Connecting…"
                        } else if self.config.mode == Mode::Local && self.local_unregistered {
                            LOCAL_UNREGISTERED
                        } else if self.config.mode == Mode::Local {
                            self.error
                                .as_deref()
                                .or_else(|| {
                                    self.status
                                        .as_ref()
                                        .filter(|status| !status.connected)
                                        .map(|status| status.detail.as_str())
                                })
                                .unwrap_or("No Conversation Selected")
                        } else {
                            self.error.as_deref().unwrap_or("No Conversation Selected")
                        };
                        ui.label(RichText::new(label).size(13.).color(MUTED));
                    });
                }
            });
    }

    fn contact_suggestions(&mut self, ui: &mut Ui) {
        let Some(query) = &self.composing else { return };
        let mut chosen = None;
        Frame::new()
            .inner_margin(Margin::symmetric(15, 7))
            .show(ui, |ui| {
                for recipient in self.contacts.matches(query) {
                    let label = format!(
                        "{}  ·  {}",
                        recipient.name,
                        display_address(&recipient.address)
                    );
                    if ui.add(egui::Button::new(label).frame(false)).clicked() {
                        chosen = Some(recipient.address.clone());
                    }
                }
            });
        if let Some(address) = chosen {
            self.composing = None;
            self.compose_error = None;
            self.select(address, true);
        }
    }

    fn toolbar(&mut self, ctx: &egui::Context, chat: Option<&str>) {
        egui::TopBottomPanel::top("conversation-toolbar")
            .exact_height(TOOLBAR_HEIGHT)
            .show_separator_line(false)
            .frame(
                Frame::new()
                    .fill(chrome::TITLEBAR)
                    .corner_radius(egui::CornerRadius {
                        ne: chrome::window_radius(ctx),
                        ..Default::default()
                    }),
            )
            .show(ctx, |ui| {
                let bar = ui.max_rect();
                chrome::line(ui, bar, 0.);
                let compose = self.composing.is_some();
                let body = Rect::from_min_max(bar.min + vec2(18., 0.), bar.max - vec2(88., 1.));
                let painter = ui.painter();
                if compose || chat.is_some() {
                    painter.text(
                        body.left_center(),
                        Align2::LEFT_CENTER,
                        "To:",
                        FontId::proportional(12.),
                        MUTED,
                    );
                }
                if let Some(recipient) = &mut self.composing {
                    let rect =
                        Rect::from_min_max(body.min + vec2(24., 9.), body.max - vec2(0., 9.));
                    let editor = ui.put(
                        rect,
                        TextEdit::singleline(recipient)
                            .frame(false)
                            .font(FontId::proportional(13.))
                            .hint_text("Name, Email, or Phone Number")
                            .margin(Margin::same(5))
                            .desired_width(rect.width()),
                    );
                    if self.focus_recipient {
                        editor.request_focus();
                        self.focus_recipient = false;
                    }
                    let enter = editor.lost_focus()
                        && ui.input(|input| input.key_pressed(egui::Key::Enter));
                    if enter {
                        match address(recipient)
                            .or_else(|error| self.contacts.resolve_name(recipient).ok_or(error))
                        {
                            Ok(selected) => {
                                self.composing = None;
                                self.select(selected, true);
                            }
                            Err(error) => {
                                self.compose_error =
                                    Some(if self.contacts.matches(recipient).next().is_some() {
                                        "Choose a matching contact".into()
                                    } else {
                                        error.to_string()
                                    });
                                editor.request_focus();
                            }
                        }
                    }
                } else {
                    if let Some(chat) = chat {
                        let name = self.contacts.name(chat);
                        ui.painter().with_clip_rect(body).text(
                            body.left_center() + vec2(22., 0.),
                            Align2::LEFT_CENTER,
                            name,
                            FontId::proportional(12.5),
                            INK,
                        );
                    }
                    chrome::drag_region(ui, body);
                }
                if let Some(error) = &self.compose_error
                    && self.composing.is_some()
                {
                    ui.painter().text(
                        bar.left_bottom() + vec2(42., -5.),
                        Align2::LEFT_BOTTOM,
                        error,
                        FontId::proportional(10.),
                        DANGER,
                    );
                }

                let right =
                    Rect::from_center_size(pos2(bar.right() - 43., bar.center().y), vec2(73., 28.));
                let mut controls = ui.new_child(
                    UiBuilder::new()
                        .max_rect(right)
                        .layout(Layout::left_to_right(Align::Center)),
                );
                controls.spacing_mut().item_spacing.x = 9.;
                let can_call = chat.is_some()
                    && !compose
                    && self.config.mode == Mode::Local
                    && self.connection.is_some()
                    && self.active_call.is_none()
                    && self
                        .status
                        .as_ref()
                        .is_some_and(|status| status.connected && status.facetime_registered);
                let unavailable = match self.status.as_ref() {
                    _ if self.config.mode == Mode::Remote => {
                        "Use FaceTime with the Apple session on this computer"
                    }
                    Some(status) if !status.facetime_registered => {
                        "Set up FaceTime in Messages Settings"
                    }
                    Some(status) if !status.connected => "FaceTime is disconnected",
                    _ if self.active_call.is_some() => "A FaceTime call is in progress",
                    _ => "Choose a conversation to call",
                };
                let facetime = controls
                    .add_enabled_ui(can_call, |ui| {
                        chrome::icon_button(ui, Icon::Video, "FaceTime", None)
                            .on_disabled_hover_text(unavailable)
                    })
                    .inner;
                let mut outgoing = None;
                egui::Popup::menu(&facetime)
                    .frame(chrome::popover())
                    .show(|ui| {
                        if !can_call {
                            ui.close();
                            return;
                        }
                        for (mode, label, icon) in [
                            (CallMode::Video, "FaceTime Video", Icon::Video),
                            (CallMode::Audio, "FaceTime Audio", Icon::Phone),
                        ] {
                            if chrome::attachment_item(ui, icon, label, CALL_GREEN).clicked() {
                                outgoing = Some(mode);
                                ui.close();
                            }
                        }
                    });
                if let Some(mode) = outgoing
                    && let Some(peer) = chat
                {
                    self.start_outgoing_call(peer, mode);
                }
                let info =
                    chrome::icon_button(&mut controls, Icon::Info, "Conversation Details", None);
                if info.clicked() {
                    self.info_started = Some(Instant::now());
                }
                egui::Popup::menu(&info).frame(chrome::sheet()).show(|ui| {
                    ui.set_min_width(203.);
                    let open = motion(ctx, self.info_started, 0.16);
                    ui.multiply_opacity(0.25 + open * 0.75);
                    if let Some(chat) = chat {
                        ui.vertical_centered(|ui| {
                            ui.add_space(4.);
                            let (rect, _) = ui.allocate_exact_size(vec2(46., 46.), Sense::hover());
                            let name = self.contacts.name(chat);
                            chrome::avatar(ui, rect.center(), 46., name, chat);
                            ui.label(chrome::bold(name, 13.));
                        });
                        ui.separator();
                        if ui
                            .button(if self.pins.iter().any(|pin| pin == chat) {
                                "Unpin Conversation"
                            } else {
                                "Pin Conversation"
                            })
                            .clicked()
                        {
                            self.toggle_pin(chat);
                            ui.close();
                        }
                    }
                    if let Some(status) = &self.status {
                        ui.label(RichText::new(&status.detail).size(11.).color(MUTED));
                    }
                    if ui.button("Settings…").clicked() {
                        self.open_settings();
                        ui.close();
                    }
                });
            });
    }

    fn composer(&mut self, ctx: &egui::Context, chat: &str, paste: bool) {
        let can_attach = self.connection.is_some() && !self.sending && self.picking.is_none();
        let accepts_attachments = can_attach
            && self.settings.is_none()
            && self.delete_conversation.is_none()
            && self.mac_setup.is_none()
            && self.session_import.is_none()
            && !self.contacts.is_open()
            && !self.media.is_open();
        if accepts_attachments {
            let dropped = ctx.input_mut(|input| std::mem::take(&mut input.raw.dropped_files));
            if !dropped.is_empty() {
                self.picking = Some((
                    chat.to_owned(),
                    attachments::task(ctx, move || attachments::dropped(dropped)),
                ));
            }
        }
        egui::TopBottomPanel::bottom("composer")
            .show_separator_line(false)
            .frame(
                Frame::new()
                    .fill(chrome::COMPOSER)
                    .corner_radius(egui::CornerRadius {
                        se: chrome::window_radius(ctx),
                        ..Default::default()
                    })
                    .inner_margin(Margin::symmetric(10, 10)),
            )
            .show(ctx, |ui| {
                if let Some(error) = &self.error {
                    let mut dismiss = false;
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(error).size(11.).color(DANGER));
                        dismiss = ui.small_button("Dismiss").clicked();
                    });
                    if dismiss {
                        self.error = None;
                    }
                    ui.add_space(3.);
                }

                let enabled = self.status.as_ref().is_some_and(|status| status.connected)
                    && !self.sending
                    && self.delete_conversation.is_none()
                    && self.picking.is_none();
                let draft = self.drafts.entry(chat.to_owned()).or_default();
                let mut send = false;
                let mut picker = None;
                if !draft.files.is_empty() {
                    let mut remove = None;
                    ScrollArea::horizontal()
                        .id_salt("draft-attachments")
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.add_space(30.);
                                for (index, file) in draft.files.iter().enumerate() {
                                    let (rect, response) =
                                        ui.allocate_exact_size(vec2(68., 58.), Sense::hover());
                                    let image_rect = rect.shrink2(vec2(4., 3.));
                                    ui.painter().rect_filled(image_rect, 8, BUBBLE_GRAY);
                                    if let Some(preview) = &file.preview {
                                        let size =
                                            attachments::fit(preview.size(), image_rect.size());
                                        preview.widget(size, 7).paint_at(
                                            ui,
                                            Rect::from_center_size(image_rect.center(), size),
                                        );
                                    } else {
                                        chrome::icon(
                                            ui.painter(),
                                            image_rect.center(),
                                            Icon::File,
                                            MUTED,
                                        );
                                    }
                                    response.on_hover_text(&file.upload.info.name);
                                    let close = Rect::from_center_size(
                                        rect.right_top() + vec2(-6., 8.),
                                        vec2(16., 16.),
                                    );
                                    let button = ui.put(
                                        close,
                                        egui::Button::new("×")
                                            .corner_radius(8)
                                            .min_size(close.size()),
                                    );
                                    if button.on_hover_text("Remove attachment").clicked() {
                                        remove = Some(index);
                                    }
                                }
                            });
                        });
                    if let Some(index) = remove {
                        draft.files.remove(index);
                    }
                    ui.add_space(3.);
                }
                ui.horizontal(|ui| {
                    let extra = ui
                        .add_enabled_ui(can_attach, |ui| {
                            chrome::icon_button(ui, Icon::Plus, "Add Attachment", Some(BUBBLE_GRAY))
                        })
                        .inner;
                    if extra.clicked() {
                        self.plus_started = Some(Instant::now());
                    }
                    egui::Popup::menu(&extra)
                        .align(egui::emath::RectAlign::TOP_START)
                        .gap(8.)
                        .frame(chrome::popover())
                        .show(|ui| {
                            ui.multiply_opacity(0.45 + 0.55 * motion(ctx, self.plus_started, 0.14));
                            if chrome::attachment_item(
                                ui,
                                Icon::Photo,
                                "Photos",
                                Color32::from_rgb(58, 134, 240),
                            )
                            .clicked()
                            {
                                picker = Some(true);
                                ui.close();
                            }
                            if chrome::attachment_item(
                                ui,
                                Icon::File,
                                "Files",
                                Color32::from_rgb(109, 112, 120),
                            )
                            .clicked()
                            {
                                picker = Some(false);
                                ui.close();
                            }
                        });
                    let width = (ui.available_width() - 35.).max(90.);
                    let response = Frame::new()
                        .fill(CANVAS)
                        .corner_radius(14)
                        .stroke(Stroke::new(0.85_f32, HAIRLINE))
                        .inner_margin(Margin::symmetric(3, 0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 0.;
                                let id = ui.make_persistent_id(("draft", chat));
                                let focused = ui.memory(|memory| memory.has_focus(id));
                                if paste
                                    && focused
                                    && accepts_attachments
                                    && self.picking.is_none()
                                    && let Some(load) = self.clipboard.load_image(ctx)
                                {
                                    self.picking = Some((chat.to_owned(), load));
                                }
                                let enter = focused
                                    && ui.input_mut(|input| {
                                        input.consume_key(egui::Modifiers::NONE, egui::Key::Enter)
                                    });
                                let edit = ScrollArea::vertical()
                                    .id_salt(("draft-scroll", chat))
                                    .max_height(105.)
                                    .min_scrolled_height(0.)
                                    .auto_shrink([true, true])
                                    .show(ui, |ui| {
                                        ui.add_enabled(
                                            !self.sending && self.delete_conversation.is_none(),
                                            TextEdit::multiline(&mut draft.text)
                                                .id(id)
                                                .frame(false)
                                                .desired_rows(1)
                                                .desired_width((width - 43.).max(45.))
                                                .char_limit(TEXT_LIMIT)
                                                .font(FontId::proportional(13.))
                                                .hint_text(
                                                    RichText::new("iMessage")
                                                        .color(Color32::from_gray(152)),
                                                )
                                                .margin(Margin::symmetric(5, 5))
                                                .return_key(Some(egui::KeyboardShortcut::new(
                                                    egui::Modifiers::SHIFT,
                                                    egui::Key::Enter,
                                                ))),
                                        )
                                    })
                                    .inner;
                                if self.focus_composer {
                                    edit.request_focus();
                                    self.focus_composer = false;
                                }
                                let visible =
                                    !draft.text.trim().is_empty() || !draft.files.is_empty();
                                let show_button = ctx.animate_bool_with_time(
                                    ui.id().with("send-button"),
                                    visible,
                                    0.14,
                                );
                                if show_button > 0. {
                                    let button = ui
                                        .add_enabled_ui(
                                            enabled && visible && draft.text.len() <= TEXT_LIMIT,
                                            |ui| {
                                                ui.multiply_opacity(show_button);
                                                chrome::icon_button(
                                                    ui,
                                                    Icon::Send,
                                                    "Send Message",
                                                    Some(BLUE),
                                                )
                                            },
                                        )
                                        .inner;
                                    send |= button.clicked();
                                } else {
                                    ui.allocate_space(vec2(28., 25.));
                                }
                                send |= enabled
                                    && visible
                                    && draft.text.len() <= TEXT_LIMIT
                                    && enter
                                    && edit.has_focus();
                            });
                        })
                        .response;
                    if response.clicked() {
                        self.focus_composer = true;
                    }
                    let emoji = ui
                        .add_enabled_ui(!self.sending, |ui| {
                            chrome::icon_button(ui, Icon::Emoji, "Emoji", None)
                        })
                        .inner;
                    egui::Popup::menu(&emoji).frame(chrome::sheet()).show(|ui| {
                        ui.label(chrome::bold("Emoji", 13.));
                        for row in [
                            ["😀", "😂", "❤️", "👍", "👋", "🎉"],
                            ["🥰", "😅", "🙌", "✨", "💙", "☕"],
                        ] {
                            ui.horizontal(|ui| {
                                for icon in row {
                                    if ui.button(RichText::new(icon).size(17.)).clicked() {
                                        draft.text.push_str(icon);
                                        self.focus_composer = true;
                                        ui.close();
                                    }
                                }
                            });
                        }
                    });
                });
                if draft.text.len() > TEXT_LIMIT {
                    ui.label(
                        RichText::new(format!("{} / {TEXT_LIMIT} bytes", draft.text.len()))
                            .color(DANGER)
                            .size(11.),
                    );
                }
                if send && self.picking.is_none() {
                    self.send(chat);
                }
                if let Some(photos) = picker
                    && self.picking.is_none()
                {
                    self.picking = Some((
                        chat.to_owned(),
                        attachments::task(ctx, move || attachments::choose(photos)),
                    ));
                }
            });
    }

    fn transcript(&mut self, ui: &mut Ui, chat: &str) {
        let viewport = ui.available_height();
        let width = ui.available_width();
        let max_text = (width * 0.63).clamp(142., 490.);
        let loaded = self.thread_loaded;
        let can_load_older = !self.history_all;
        let ease = motion(ui.ctx(), self.thread_motion, 0.22);
        let mut reaction = None;
        ScrollArea::vertical()
            .id_salt(("transcript", chat))
            .stick_to_bottom(true)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing = vec2(0., 0.);
                ui.multiply_opacity(0.20 + 0.80 * ease);
                ui.set_min_width(width);
                let layout = self
                    .messages
                    .iter()
                    .map(|message| {
                        let text = (!message.body.trim().is_empty()).then(|| {
                            MessageText::layout(ui, &message.body, message.outgoing, max_text)
                        });
                        let day = Local.timestamp_millis_opt(message.timestamp_ms).single();
                        let media = Uuid::parse_str(&message.id)
                            .ok()
                            .map(|id| {
                                message
                                    .attachments
                                    .iter()
                                    .enumerate()
                                    .map(|(index, info)| {
                                        let id = AttachmentId { message: id, index };
                                        (id, info.clone(), self.media.size(id, info, max_text))
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default();
                        (text, day, media)
                    })
                    .collect::<Vec<_>>();

                let mut last_day: Option<NaiveDate> = None;
                let mut content_height = if can_load_older { 29. } else { 0. };
                for (index, (text, time, media)) in layout.iter().enumerate() {
                    let day = time.map(|value| value.date_naive());
                    if day != last_day {
                        content_height += 24.;
                    }
                    last_day = day;
                    content_height += text.as_ref().map_or(0., |text| text.galley.size().y + 10.)
                        + media.iter().map(|(_, _, size)| size.y + 4.).sum::<f32>()
                        + if group_end(&self.messages, index) {
                            10.
                        } else {
                            3.
                        };
                    if delivery_label(&self.messages, index).is_some() {
                        content_height += 14.;
                    }
                    let message = &self.messages[index];
                    let reacted_parts = media
                        .iter()
                        .filter(|(id, _, _)| {
                            has_tapbacks(message, message.attachment_part(id.index))
                        })
                        .count();
                    content_height += 10. * reacted_parts as f32;
                    if text.is_some() && has_tapbacks(message, message.body_part()) {
                        content_height += 10.;
                    }
                }
                ui.add_space((viewport - content_height - 8.).max(3.) + (1. - ease) * 4.);
                if can_load_older {
                    ui.vertical_centered(|ui| {
                        if ui
                            .add_enabled(
                                !self.loading_older,
                                egui::Button::new(if self.loading_older {
                                    "Loading…"
                                } else {
                                    "Load Earlier Messages"
                                }),
                            )
                            .clicked()
                            && let Some(connection) = &self.connection
                        {
                            self.loading_older = connection
                                .actions
                                .send(Action::Older {
                                    chat: chat.to_owned(),
                                    offset: self.messages.len().try_into().unwrap_or(u32::MAX),
                                })
                                .is_ok();
                        }
                    });
                    ui.add_space(5.);
                }
                if layout.is_empty() && loaded {
                    return;
                }
                last_day = None;
                for (index, (text, time, media)) in layout.into_iter().enumerate() {
                    let message = &self.messages[index];
                    let can_react = self.tapback_pending.is_none()
                        && self.status.as_ref().is_some_and(|status| status.connected)
                        && matches!(message.status, Delivery::Accepted | Delivery::Received);
                    let day = time.map(|value| value.date_naive());
                    if day != last_day
                        && let Some(time) = time
                    {
                        let today = Local::now().date_naive();
                        let stamp = if time.date_naive() == today {
                            time.format("Today %-I:%M %p").to_string()
                        } else if today.pred_opt() == Some(time.date_naive()) {
                            time.format("Yesterday %-I:%M %p").to_string()
                        } else {
                            time.format("%a, %b %-d, %-I:%M %p").to_string()
                        };
                        let (rect, _) = ui.allocate_exact_size(vec2(width, 24.), Sense::hover());
                        ui.painter().text(
                            rect.center(),
                            Align2::CENTER_CENTER,
                            stamp,
                            FontId::proportional(10.),
                            MUTED,
                        );
                    }
                    last_day = day;
                    let progress = motion(
                        ui.ctx(),
                        self.message_motion.get(&message.id).copied(),
                        MOTION,
                    );
                    let tail = group_end(&self.messages, index);
                    // New messages enter from the composer and settle into their transcript slot.
                    let slide = if message.outgoing { 19. } else { 10. };
                    let shift =
                        (1. - progress) * vec2(if message.outgoing { 8. } else { 0. }, slide);
                    let alpha = 0.23 + progress.clamp(0., 1.) * 0.77;
                    for (id, info, size) in media {
                        let part = message.attachment_part(id.index);
                        if has_tapbacks(message, part) {
                            ui.add_space(10.);
                        }
                        let rect = transcript_slot(ui, size, message.outgoing).translate(shift);
                        ui.scope(|ui| {
                            ui.multiply_opacity(alpha);
                            if let Some(response) =
                                self.media
                                    .paint(ui, rect, id, &info, self.connection.as_ref())
                                && can_react
                            {
                                response.context_menu(|ui| {
                                    tapback_options(ui, message, part, &mut reaction)
                                });
                            }
                        });
                        paint_tapbacks(ui, rect, message, part, can_react.then_some(&mut reaction));
                        ui.add_space(4.);
                    }
                    if let Some(text) = text {
                        let part = message.body_part();
                        if has_tapbacks(message, part) {
                            ui.add_space(10.);
                        }
                        let size = text.galley.size() + vec2(19., 10.);
                        let rect = transcript_slot(ui, size, message.outgoing).translate(shift);
                        if ui.is_rect_visible(rect) {
                            let fill = if message.outgoing { BLUE } else { BUBBLE_GRAY };
                            let mut painter = ui.painter().clone();
                            painter.multiply_opacity(alpha);
                            chrome::bubble_shape(&painter, rect, message.outgoing, tail, fill);
                            if can_react {
                                ui.interact(
                                    rect,
                                    ui.id().with((&message.id, "bubble")),
                                    Sense::click(),
                                )
                                .context_menu(|ui| {
                                    tapback_options(ui, message, part, &mut reaction)
                                });
                            }
                            let mut text_ui = ui.new_child(
                                UiBuilder::new()
                                    .id_salt((&message.id, "body"))
                                    .max_rect(rect.shrink2(vec2(9.5, 5.)))
                                    .layout(Layout::top_down(Align::Min)),
                            );
                            text_ui.multiply_opacity(alpha);
                            let response = text.show(
                                &mut text_ui,
                                can_react.then_some(|ui: &mut Ui| {
                                    tapback_options(ui, message, part, &mut reaction);
                                }),
                            );
                            if let Some(time) = time
                                && !text.has_link_at_pointer(&text_ui, &response)
                            {
                                response.on_hover_text(
                                    time.format("%A, %d %B %Y at %-I:%M %p").to_string(),
                                );
                            }
                        }
                        paint_tapbacks(ui, rect, message, part, can_react.then_some(&mut reaction));
                    }
                    if let Some((label, color)) = delivery_label(&self.messages, index) {
                        let (status, _) =
                            ui.allocate_exact_size(vec2(ui.available_width(), 14.), Sense::hover());
                        ui.painter().text(
                            status.right_center() - vec2(17., 0.),
                            Align2::RIGHT_CENTER,
                            label,
                            FontId::proportional(10.),
                            color,
                        );
                    }
                    ui.add_space(if tail { 10. } else { 3. });
                }
            });
        if let Some((id, request)) = reaction
            && self.connection.as_ref().is_some_and(|connection| {
                connection
                    .actions
                    .send(Action::Tapback { id, request })
                    .is_ok()
            })
        {
            self.tapback_pending = Some(id);
        }
    }

    fn import_dialog(&mut self, ctx: &egui::Context) {
        let Some(import) = &mut self.session_import else {
            return;
        };
        match import.show(ctx, &self.root) {
            ImportOutcome::Open => {}
            ImportOutcome::Closed => self.session_import = None,
            ImportOutcome::Saved => {
                self.session_import = None;
                self.contacts.refresh_now(ctx);
                self.open_saved_session(ctx);
            }
        }
    }

    fn call_panel(&mut self, ctx: &egui::Context) {
        if let Some(call) = &mut self.active_call {
            let name = self.contacts.name(&call.peer);
            let mode = call.controls.mode();
            let is_video = mode == CallMode::Video;
            let (title, symbol, width) = if is_video {
                ("FaceTime Video", Icon::Video, 440.)
            } else {
                ("FaceTime Audio", Icon::Phone, 245.)
            };
            let (detail, end_label) = if call.controls.ending() {
                ("Ending…".to_owned(), "End")
            } else if let Some(start) = call.connected_at {
                let elapsed = start.elapsed();
                let elapsed_seconds = elapsed.as_secs();
                ctx.request_repaint_after(Duration::from_millis(
                    1000 - u64::from(elapsed.subsec_millis()),
                ));
                (
                    format!(
                        "{title} · {}:{:02}",
                        elapsed_seconds / 60,
                        elapsed_seconds % 60
                    ),
                    "End",
                )
            } else {
                (
                    if call.outgoing {
                        "Calling…"
                    } else {
                        "Connecting…"
                    }
                    .to_owned(),
                    "Cancel",
                )
            };
            let video_status = call.controls.video_status().unwrap_or_default();
            if let Some(frame) = call.controls.next_video_frame() {
                update_video_texture(
                    ctx,
                    &mut call.video_texture,
                    "FaceTime remote video",
                    frame.as_deref(),
                );
            }
            let preview = call.controls.next_camera_preview();
            if call.controls.ending() || call.controls.camera_enabled() != Some(true) {
                call.camera_preview = None;
            } else if let Some(frame) = preview {
                update_video_texture(
                    ctx,
                    &mut call.camera_preview,
                    "FaceTime camera preview",
                    frame.as_deref(),
                );
            }
            call_card(ctx, name, &detail, symbol, width, |ui| {
                if is_video && call.connected_at.is_some() {
                    let size = vec2(ui.available_width(), ui.available_width() * 9. / 16.);
                    let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
                    if let Some(texture) = &call.video_texture {
                        egui::Image::new((texture.id(), size))
                            .corner_radius(9)
                            .paint_at(ui, rect);
                    } else {
                        ui.painter().rect_filled(rect, 9, Color32::from_gray(26));
                        ui.painter().text(
                            rect.center(),
                            Align2::CENTER_CENTER,
                            if video_status.playback_error.is_some() {
                                "Video unavailable"
                            } else {
                                "Waiting for video…"
                            },
                            FontId::proportional(13.),
                            Color32::WHITE,
                        );
                    }
                    camera_preview(
                        ui,
                        call.id,
                        call.camera_preview.as_ref(),
                        &mut call.preview_position,
                        rect,
                    );
                    if let Some(error) = &video_status.camera_error {
                        ui.colored_label(DANGER, error);
                    }
                    if let Some(error) = &video_status.playback_error {
                        ui.colored_label(DANGER, error);
                    }
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let enabled = !call.controls.ending();
                    if ui
                        .add_enabled(enabled, call_button(end_label, DANGER))
                        .clicked()
                    {
                        call.controls.hang_up();
                    }
                    if call.connected_at.is_some() {
                        if ui
                            .add_enabled(
                                enabled,
                                egui::Button::new(if call.controls.muted() {
                                    "Unmute"
                                } else {
                                    "Mute"
                                })
                                .min_size(vec2(72., 27.)),
                            )
                            .clicked()
                        {
                            call.controls.toggle_mute();
                        }
                        if let Some(camera_enabled) = call.controls.camera_enabled()
                            && ui
                                .add_enabled(
                                    enabled,
                                    egui::Button::new(if video_status.camera_error.is_some() {
                                        "Retry Camera"
                                    } else if camera_enabled {
                                        "Camera Off"
                                    } else {
                                        "Camera On"
                                    })
                                    .min_size(vec2(86., 27.)),
                                )
                                .clicked()
                        {
                            if video_status.camera_error.is_some() {
                                call.controls.retry_camera();
                            } else {
                                call.controls.toggle_camera();
                            }
                        }
                    }
                });
            });
            return;
        }

        let now = now_ms();
        let Some(call) = self
            .incoming_calls
            .iter()
            .find(|call| call.expires_ms > now)
        else {
            self.call_error = None;
            return;
        };
        let call = call.clone();
        let name = self.contacts.name(&call.caller);
        let (heading, icon) = match call.mode {
            Some(CallMode::Audio) => ("FaceTime Audio", Icon::Phone),
            Some(CallMode::Video) => ("FaceTime Video", Icon::Video),
            None => ("FaceTime", Icon::Video),
        };
        ctx.request_repaint_after(Duration::from_millis((call.expires_ms - now) as u64));
        let can_answer = self.config.mode == Mode::Local;
        let show_video = can_answer && call.mode == Some(CallMode::Video);
        let width = if show_video { 340. } else { 245. };
        let available = self.declining_call.is_none() && self.connection.is_some();
        let mut accept = None;
        let mut decline = false;
        call_card(ctx, name, heading, icon, width, |ui| {
            if let Some((id, error)) = &self.call_error
                && *id == call.id
            {
                ui.label(RichText::new(error).size(11.).color(DANGER));
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if show_video
                    && ui
                        .add_enabled(available, call_button("Answer Video", CALL_GREEN))
                        .clicked()
                {
                    accept = Some(CallMode::Video);
                }
                if can_answer {
                    let audio = if call.mode == Some(CallMode::Audio) {
                        "Answer"
                    } else {
                        "Answer as Audio"
                    };
                    let button = if show_video {
                        egui::Button::new(audio).min_size(vec2(72., 27.))
                    } else {
                        call_button(audio, CALL_GREEN)
                    };
                    if ui.add_enabled(available, button).clicked() {
                        accept = Some(CallMode::Audio);
                    }
                }
                decline = ui
                    .add_enabled(available, call_button("Decline", DANGER))
                    .clicked();
            });
        });
        if let Some(mode) = accept {
            self.respond_to_ring(call.id, RingAction::Answer(mode));
        } else if decline {
            self.respond_to_ring(call.id, RingAction::Decline);
        }
    }

    fn respond_to_ring(&mut self, id: Uuid, action: RingAction) -> bool {
        if self.quitting || self.active_call.is_some() || self.declining_call.is_some() {
            return false;
        }
        let Some(connection) = &self.connection else {
            return false;
        };
        let Some(call) = self
            .incoming_calls
            .iter()
            .find(|call| call.id == id && call.expires_ms > now_ms())
        else {
            return false;
        };
        match action {
            RingAction::Open => (),
            RingAction::Answer(mode) => {
                if self.config.mode != Mode::Local
                    || (mode == CallMode::Video && call.mode != Some(CallMode::Video))
                {
                    return false;
                }
                match connection.answer_call(id, mode) {
                    Ok(controls) => {
                        self.active_call = Some(DesktopCall {
                            id,
                            peer: call.caller.clone(),
                            outgoing: false,
                            connected_at: None,
                            controls,
                            video_texture: None,
                            camera_preview: None,
                            preview_position: vec2(1., 1.),
                        });
                        self.call_error = None;
                    }
                    Err(error) => self.call_error = Some((id, error.to_string())),
                }
            }
            RingAction::Decline => match connection.decline_call(id) {
                Ok(()) => {
                    self.declining_call = Some(id);
                    self.call_error = None;
                }
                Err(error) => self.call_error = Some((id, error.to_string())),
            },
        }
        true
    }

    fn start_outgoing_call(&mut self, peer: &str, mode: CallMode) {
        let Some(connection) = &self.connection else {
            return;
        };
        let id = Uuid::new_v4();
        match connection.dial_call(id, peer, mode) {
            Ok(controls) => {
                self.error = None;
                self.active_call = Some(DesktopCall {
                    id,
                    peer: peer.to_owned(),
                    outgoing: true,
                    connected_at: None,
                    controls,
                    video_texture: None,
                    camera_preview: None,
                    preview_position: vec2(1., 1.),
                });
            }
            Err(error) => self.error = Some(error.to_string()),
        }
    }

    fn quit(&mut self, ctx: &egui::Context) {
        self.quitting = true;
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    }

    fn handle_window_actions(&mut self, ctx: &egui::Context) {
        if ctx.input_mut(|input| input.consume_key(egui::Modifiers::COMMAND, egui::Key::Q)) {
            self.quit(ctx);
        } else if ctx.input_mut(|input| input.consume_key(egui::Modifiers::COMMAND, egui::Key::W)) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }

        if !self.quitting
            && ctx.input(|input| input.viewport().close_requested())
            && self.connection.is_some()
            && self
                .status
                .as_ref()
                .is_some_and(|status| status.facetime_registered)
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
        }
    }

    pub(super) fn process_notification_action(&mut self, ctx: &egui::Context) {
        self.process(ctx);
        if let Some(token) = self.call_activation.take() {
            self.clipboard.activate_window(token);
        }
    }

    fn conversation_deleted(&mut self, chat: &str) {
        self.delete_conversation = None;
        self.error = None;
        self.chats.retain(|entry| entry.address != chat);
        self.drafts.remove(chat);
        if self
            .retry
            .as_ref()
            .is_some_and(|request| request.address == chat)
        {
            self.retry = None;
        }
        if self
            .picking
            .as_ref()
            .is_some_and(|(address, _)| address == chat)
        {
            self.picking = None;
        }
        let pinned = self.pins.len();
        self.pins.retain(|address| address != chat);
        if pinned != self.pins.len() {
            self.save_pins();
        }
        if self.selected.as_deref() == Some(chat) {
            self.selected = None;
            self.messages.clear();
            self.message_motion.clear();
            self.info_started = None;
            self.media = TranscriptMedia::default();
            if let Some(next) = self.chats.first() {
                self.select(next.address.clone(), false);
            }
        }
        self.refresh_at = Instant::now();
    }

    fn delete_dialog(&mut self, ctx: &egui::Context) {
        let Some(form) = &mut self.delete_conversation else {
            return;
        };
        let name = self.contacts.name(&form.chat);
        let location = match self.config.mode {
            Mode::Local => "this computer",
            Mode::Remote => "the server",
        };
        let panel = egui::Modal::new(egui::Id::new("delete-conversation"))
            .frame(chrome::sheet())
            .show(ctx, |ui| {
                ui.set_width(345.);
                ui.label(chrome::bold("Delete Conversation?", 19.));
                ui.label(format!("Remove all messages and attachments in the conversation with {name} from {location}."));
                if let Some(error) = &form.error {
                    ui.label(RichText::new(error).color(DANGER));
                }
                ui.add_space(6.);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let label = if form.pending { "Deleting…" } else { "Delete" };
                    let delete = ui.add_enabled(
                        self.connection.is_some() && !form.pending,
                        egui::Button::new(RichText::new(label).color(Color32::WHITE))
                            .fill(DANGER)
                            .corner_radius(5)
                            .min_size(vec2(70., 25.)),
                    ).clicked();
                    let cancel = ui.add_enabled(!form.pending, egui::Button::new("Cancel")
                        .min_size(vec2(65., 25.))).clicked();
                    (cancel, delete)
                }).inner
            });
        let (cancel, delete) = panel.inner;
        if !form.pending && (cancel || panel.should_close()) {
            self.delete_conversation = None;
        } else if delete && let Some(connection) = &self.connection {
            if connection
                .actions
                .send(Action::DeleteConversation(form.chat.clone()))
                .is_ok()
            {
                form.pending = true;
                form.error = None;
            } else {
                form.error = Some("The Messages connection is unavailable".to_owned());
            }
        }
    }

    fn mac_setup_dialog(&mut self, ctx: &egui::Context) {
        let Some(setup) = &mut self.mac_setup else {
            return;
        };
        if let Some(apple) = self.contacts.apple_account() {
            setup.seed_account(&apple.account, apple.password_saved);
        }
        match setup.show(ctx, &self.root) {
            MacOutcome::Open => {}
            MacOutcome::Closed => {
                self.mac_setup = None;
                if self.settings.is_none() && !self.contacts.is_open() {
                    self.candidate = Some(Connection::start(
                        ctx,
                        self.root.clone(),
                        self.config.clone(),
                        None,
                        Zeroizing::default(),
                        None,
                    ));
                }
            }
            MacOutcome::Saved => {
                self.mac_setup = None;
                self.contacts.refresh_now(ctx);
                self.open_saved_session(ctx);
            }
            MacOutcome::ContactsAuthorized => {
                self.mac_setup = None;
                self.contacts.refresh_now(ctx);
            }
        }
    }

    fn open_saved_session(&mut self, ctx: &egui::Context) {
        self.local_unregistered = false;
        if self.settings.is_none() {
            self.open_settings();
        }
        let form = self.settings.as_mut().expect("Settings initialized");
        form.config.mode = Mode::Local;
        form.error = None;
        let old = if self.config.mode == Mode::Local {
            self.status = None;
            self.connection.take()
        } else {
            None
        };
        self.candidate = Some(Connection::start(
            ctx,
            self.root.clone(),
            form.config.clone(),
            Some(self.config.clone()),
            Zeroizing::default(),
            old,
        ));
    }

    fn settings_dialog(&mut self, ctx: &egui::Context) {
        let Some(form) = &mut self.settings else {
            return;
        };
        let mut apply = false;
        let mut import = false;
        let mut setup_mac = false;
        let mut enable_facetime = false;
        let mut contacts = false;
        let mut cancel = false;
        let connecting = self.candidate.is_some();
        let panel = egui::Modal::new(egui::Id::new("settings"))
            .frame(chrome::sheet())
            .show(ctx, |ui| {
                let transition = motion(ctx, Some(form.opened), 0.16);
                ui.multiply_opacity(0.25 + 0.75 * transition);
                ui.set_width(375.);
                ui.label(chrome::bold("Messages Settings", 19.));
                ui.add_space(8.);
                ui.add_enabled_ui(!connecting, |ui| {
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut form.config.mode, Mode::Local, "This Computer");
                        ui.selectable_value(&mut form.config.mode, Mode::Remote, "Server");
                    });
                    ui.add_space(9.);
                    match form.config.mode {
                        Mode::Local => {
                            let label = if self.local_unregistered {
                                "Use your Mac to register iMessage on this computer."
                            } else if self.config.mode == Mode::Local {
                                self.status.as_ref().map_or(
                                    "Connect directly to Apple using a registered session.",
                                    |status| status.detail.as_str(),
                                )
                            } else {
                                "Connect directly to Apple using a registered session."
                            };
                            ui.label(RichText::new(label).color(MUTED));
                            if self.config.mode == Mode::Local
                                && self
                                    .status
                                    .as_ref()
                                    .is_some_and(|status| !status.facetime_registered)
                            {
                                enable_facetime = ui
                                    .add_enabled(
                                        !self.sending && self.active_call.is_none(),
                                        egui::Button::new("Enable FaceTime…"),
                                    )
                                    .clicked();
                            }
                            ui.add_space(3.);
                            ui.horizontal_wrapped(|ui| {
                                setup_mac = ui
                                    .add_enabled(
                                        !self.sending,
                                        egui::Button::new("Set Up with a Mac…"),
                                    )
                                    .clicked();
                                import = ui
                                    .add_enabled(
                                        !self.sending,
                                        egui::Button::new("Import Registered Session…"),
                                    )
                                    .clicked();
                            });
                        }
                        Mode::Remote => {
                            settings_field(
                                ui,
                                "Server URL",
                                &mut form.config.url,
                                "https://messages.example.com",
                                false,
                            );
                            settings_field(
                                ui,
                                "Username",
                                &mut form.config.username,
                                "Optional",
                                false,
                            );
                            settings_field(
                                ui,
                                "Password",
                                &mut form.password,
                                if form.config.remember {
                                    "Use saved password"
                                } else {
                                    "Optional"
                                },
                                true,
                            );
                            ui.checkbox(
                                &mut form.config.remember,
                                "Remember password in Linux Secret Service",
                            );
                        }
                    }
                });
                ui.add_space(6.);
                contacts = ui.button("iCloud Contacts…").clicked();
                if let Some(error) = &form.error {
                    ui.add_space(6.);
                    ui.label(RichText::new(error).size(11.).color(DANGER));
                }
                ui.add_space(9.);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    apply = ui
                        .add_enabled(
                            !connecting && !self.sending,
                            egui::Button::new(
                                RichText::new(if connecting { "Connecting…" } else { "Done" })
                                    .color(Color32::WHITE),
                            )
                            .fill(BLUE)
                            .corner_radius(5)
                            .min_size(vec2(70., 25.)),
                        )
                        .clicked();
                    cancel = ui
                        .add_enabled(
                            !connecting,
                            egui::Button::new("Cancel").min_size(vec2(65., 25.)),
                        )
                        .clicked();
                });
            });
        if contacts {
            self.contacts.open();
        } else if enable_facetime {
            form.error = None;
            self.mac_setup = Some(MacSetup::for_facetime(&self.root));
        } else if setup_mac {
            form.error = None;
            self.mac_setup = Some(MacSetup::new());
        } else if import {
            form.error = None;
            self.session_import = Some(SessionImport::default());
        } else if (cancel || panel.should_close()) && !connecting {
            self.settings = None;
        } else if apply {
            if form.config.mode != Mode::Remote
                && form.config == self.config
                && (self.connection.is_some()
                    || (self.config.mode == Mode::Local && self.local_unregistered))
            {
                self.settings = None;
                return;
            }
            form.error = None;
            let password = Zeroizing::new(std::mem::take(&mut form.password));
            self.candidate = Some(Connection::start(
                ctx,
                self.root.clone(),
                form.config.clone(),
                Some(self.config.clone()),
                password,
                None,
            ));
        }
    }
}

impl eframe::App for MessagesApp {
    fn raw_input_hook(&mut self, _ctx: &egui::Context, input: &mut egui::RawInput) {
        self.clipboard.restore_wayland_text_paste(input);
    }

    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        [0., 0., 0., 0.]
    }

    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        self.clipboard.remember_window(frame);
        self.process_notification_action(ctx);
        self.handle_window_actions(ctx);
        let paste = self.clipboard.take_paste_request(ctx);
        if self.settings.is_none()
            && self.delete_conversation.is_none()
            && self.mac_setup.is_none()
            && !self.media.is_open()
            && !self.contacts.is_open()
        {
            if ctx.input_mut(|input| input.consume_key(egui::Modifiers::COMMAND, egui::Key::N)) {
                self.start_compose();
            }
            if ctx.input_mut(|input| input.consume_key(egui::Modifiers::COMMAND, egui::Key::Comma))
            {
                self.open_settings();
            }
            if self.composing.is_some()
                && ctx
                    .input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
            {
                self.composing = None;
            }
        }
        self.sidebar(ctx);
        self.right_panel(ctx, paste);
        self.call_panel(ctx);
        if self.delete_conversation.is_some() {
            self.delete_dialog(ctx);
        } else if self.mac_setup.is_some() {
            self.mac_setup_dialog(ctx);
        } else if self.session_import.is_some() {
            self.import_dialog(ctx);
        } else if self.contacts.is_open() {
            if self.contacts.show(ctx)
                && let Some(apple) = self.contacts.apple_account()
            {
                self.mac_setup = Some(MacSetup::for_contacts(&apple.account, apple.password_saved));
            }
        } else {
            self.settings_dialog(ctx);
        }
        self.media.show(ctx);
        window_edge(ctx);
    }
}

fn update_video_texture(
    ctx: &egui::Context,
    texture: &mut Option<egui::TextureHandle>,
    label: &str,
    frame: Option<&VideoFrame>,
) {
    let Some(frame) = frame else {
        *texture = None;
        return;
    };
    let image = egui::ColorImage::from_rgba_unmultiplied(
        [usize::from(frame.width), usize::from(frame.height)],
        &frame.rgba,
    );
    if let Some(texture) = texture {
        texture.set(image, egui::TextureOptions::LINEAR);
    } else {
        *texture = Some(ctx.load_texture(label, image, egui::TextureOptions::LINEAR));
    }
}

fn camera_preview(
    ui: &Ui,
    call: Uuid,
    texture: Option<&egui::TextureHandle>,
    position: &mut egui::Vec2,
    stage: Rect,
) {
    let id = ui.id().with(("camera preview", call));
    let alpha = ui.ctx().animate_bool_with_time(id, texture.is_some(), 0.16);
    let Some(texture) = texture else {
        return;
    };
    let bounds = stage.shrink(10.);
    let width = (stage.width() * 0.28).min(136.);
    let size = vec2(width, width * 9. / 16.);
    let travel = (bounds.size() - size).max(egui::Vec2::ZERO);
    let anchor =
        |position: egui::Vec2| bounds.min + vec2(position.x * travel.x, position.y * travel.y);
    let previous = Rect::from_min_size(anchor(*position), size);
    let response = ui.interact(previous, id, Sense::drag());
    let delta = response.drag_delta();
    if response.dragged() {
        *position += vec2(delta.x / travel.x.max(1.), delta.y / travel.y.max(1.));
        *position = position.clamp(egui::Vec2::ZERO, vec2(1., 1.));
    }
    response
        .on_hover_and_drag_cursor(egui::CursorIcon::Grab)
        .on_hover_text("Your camera");
    let rect = Rect::from_min_size(anchor(*position), size);
    let painter = ui.painter().with_clip_rect(stage);
    painter.rect_filled(
        rect.expand(2.).translate(vec2(0., 2.)),
        9,
        Color32::from_black_alpha((110. * alpha) as u8),
    );
    egui::Image::new((texture.id(), size))
        .uv(Rect {
            min: pos2(1., 0.),
            max: pos2(0., 1.),
        })
        .corner_radius(7)
        .tint(Color32::WHITE.gamma_multiply(alpha))
        .paint_at(ui, rect);
    painter.rect_stroke(
        rect,
        7,
        Stroke::new(1.0_f32, Color32::from_white_alpha((122. * alpha) as u8)),
        StrokeKind::Inside,
    );
}

fn call_card(
    ctx: &egui::Context,
    name: &str,
    detail: &str,
    icon: Icon,
    width: f32,
    controls: impl FnOnce(&mut Ui),
) {
    egui::Area::new(egui::Id::new("facetime-call"))
        .anchor(Align2::RIGHT_TOP, vec2(-18., 60.))
        .order(egui::Order::Foreground)
        .show(ctx, |ui| {
            chrome::sheet().show(ui, |ui| {
                ui.set_width(width.min(ui.ctx().content_rect().width() - 70.));
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(vec2(36., 36.), Sense::hover());
                    ui.painter().circle_filled(rect.center(), 17., CALL_GREEN);
                    chrome::icon(ui.painter(), rect.center(), icon, Color32::WHITE);
                    ui.vertical(|ui| {
                        ui.add(egui::Label::new(chrome::bold(name, 15.)).truncate());
                        ui.label(RichText::new(detail).size(12.).color(MUTED));
                    });
                });
                controls(ui);
            });
        });
}

fn call_button(label: &str, fill: Color32) -> egui::Button<'_> {
    egui::Button::new(RichText::new(label).color(Color32::WHITE))
        .fill(fill)
        .corner_radius(6)
        .min_size(vec2(72., 27.))
}

fn transcript_slot(ui: &mut Ui, size: egui::Vec2, outgoing: bool) -> Rect {
    let (row, _) = ui.allocate_exact_size(vec2(ui.available_width(), size.y), Sense::hover());
    let left = if outgoing {
        row.right() - size.x - 17.
    } else {
        row.left() + 18.
    };
    Rect::from_min_size(pos2(left, row.top()), size)
}

fn tapback_label(kind: &TapbackKind) -> (&str, &str) {
    match kind {
        TapbackKind::Heart => ("♥", "Love"),
        TapbackKind::Like => ("👍", "Like"),
        TapbackKind::Dislike => ("👎", "Dislike"),
        TapbackKind::Laugh => ("HA", "Laugh"),
        TapbackKind::Emphasize => ("‼", "Emphasize"),
        TapbackKind::Question => ("?", "Question"),
        TapbackKind::Emoji(emoji) => (emoji, emoji),
    }
}

fn tapback_options(
    ui: &mut Ui,
    message: &Message,
    part: u32,
    selection: &mut Option<(Uuid, SetTapback)>,
) {
    let Ok(id) = Uuid::parse_str(&message.id) else {
        return;
    };
    let current = message
        .tapbacks
        .iter()
        .filter(|reaction| reaction.outgoing && tapback_on_part(message, part, reaction.part))
        .min_by_key(|reaction| reaction.part != part);
    let select = |kind: Option<TapbackKind>| {
        (
            id,
            SetTapback {
                reaction: kind.filter(|kind| {
                    !current.is_some_and(|reaction| reaction.kind.matches_reaction(kind))
                }),
                part: Some(current.map_or(part, |reaction| reaction.part)),
            },
        )
    };
    ui.horizontal(|ui| {
        for kind in [
            TapbackKind::Heart,
            TapbackKind::Like,
            TapbackKind::Dislike,
            TapbackKind::Laugh,
            TapbackKind::Emphasize,
            TapbackKind::Question,
        ] {
            let (symbol, label) = tapback_label(&kind);
            let selected = current.is_some_and(|reaction| reaction.kind.matches_reaction(&kind));
            if ui
                .add(
                    egui::Button::new(RichText::new(symbol).size(17.))
                        .selected(selected)
                        .corner_radius(14)
                        .min_size(vec2(30., 29.)),
                )
                .on_hover_text(label)
                .clicked()
            {
                *selection = Some(select(Some(kind)));
                ui.close();
            }
        }
    });
    let config = egui::containers::menu::MenuConfig::new()
        .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside);
    egui::containers::menu::SubMenuButton::new("Emoji…")
        .config(config)
        .ui(ui, |ui| {
            ui.horizontal(|ui| {
                for emoji in ["😂", "❤️", "🎉", "🔥", "😮", "🙌"] {
                    let kind = TapbackKind::Emoji(emoji.to_owned());
                    let selected =
                        current.is_some_and(|reaction| reaction.kind.matches_reaction(&kind));
                    if ui
                        .selectable_label(selected, RichText::new(emoji).size(17.))
                        .clicked()
                    {
                        *selection = Some(select(Some(kind)));
                        ui.close_kind(egui::UiKind::Menu);
                    }
                }
            });
            if let Some(kind) = tapback_emoji_input(ui) {
                *selection = Some(select(Some(kind)));
                ui.close_kind(egui::UiKind::Menu);
            }
        });
    if current.is_some() && ui.button("Remove Tapback").clicked() {
        *selection = Some(select(None));
        ui.close();
    }
}

fn tapback_emoji_input(ui: &mut Ui) -> Option<TapbackKind> {
    let id = ui.id().with("custom-emoji");
    let mut value = ui.data_mut(|data| data.get_temp::<String>(id).unwrap_or_default());
    let input = ui.add(
        egui::TextEdit::singleline(&mut value)
            .id(id)
            .hint_text("Paste emoji or type :name:")
            .desired_width(154.)
            .char_limit(64),
    );
    let value_trimmed = value.trim();
    let emoji = emojis::get(value_trimmed).or_else(|| {
        let name = value_trimmed.strip_prefix(':')?;
        emojis::get_by_shortcode(name.trim_end_matches(':'))
    });
    let confirm = ui.add_enabled(emoji.is_some(), egui::Button::new("Select Emoji"));
    let enter = input.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
    if let Some(emoji) = emoji.filter(|_| confirm.clicked() || enter) {
        ui.data_mut(|data| data.remove::<String>(id));
        return Some(TapbackKind::Emoji(emoji.as_str().to_owned()));
    }
    if input.changed() {
        ui.data_mut(|data| data.insert_temp(id, value));
    }
    None
}

fn has_tapbacks(message: &Message, part: u32) -> bool {
    message
        .tapbacks
        .iter()
        .any(|reaction| tapback_on_part(message, part, reaction.part))
}

fn tapback_on_part(message: &Message, part: u32, reacted_part: u32) -> bool {
    reacted_part == part || (part == message.first_part() && !message.has_part(reacted_part))
}

fn paint_tapbacks(
    ui: &mut Ui,
    bubble: Rect,
    message: &Message,
    part: u32,
    mut selection: Option<&mut Option<(Uuid, SetTapback)>>,
) {
    if !ui.is_rect_visible(bubble.expand(11.)) {
        return;
    }
    let mut corner = bubble.right_top() + vec2(1., 0.);
    for reaction in message
        .tapbacks
        .iter()
        .filter(|reaction| tapback_on_part(message, part, reaction.part))
        .take(5)
    {
        let (symbol, label) = tapback_label(&reaction.kind);
        let rect = Rect::from_center_size(corner - vec2(11., 0.), vec2(22., 21.));
        let fill = if reaction.outgoing { BLUE } else { BUBBLE_GRAY };
        let ink = if reaction.outgoing {
            Color32::WHITE
        } else {
            INK
        };
        ui.painter().rect(
            rect,
            10,
            fill,
            Stroke::new(1_f32, CANVAS),
            StrokeKind::Outside,
        );
        ui.painter().text(
            rect.center(),
            Align2::CENTER_CENTER,
            symbol,
            chrome::bold_font(11.),
            ink,
        );
        let editable = selection.as_deref_mut().filter(|_| reaction.outgoing);
        let id = ui
            .id()
            .with((&message.id, reaction.part, reaction.outgoing));
        if let Some(selection) = editable {
            let response = ui
                .interact(rect, id, Sense::click())
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .on_hover_text(format!("You · {label}"));
            egui::Popup::menu(&response)
                .frame(chrome::sheet())
                .show(|ui| {
                    tapback_options(ui, message, reaction.part, selection);
                });
        } else {
            ui.interact(rect, id, Sense::hover()).on_hover_text(label);
        }
        corner.x -= 18.;
    }
}

fn motion(ctx: &egui::Context, start: Option<Instant>, duration: f32) -> f32 {
    let Some(start) = start else { return 1. };
    let elapsed = (start.elapsed().as_secs_f32() / duration).clamp(0., 1.);
    if elapsed < 1. {
        ctx.request_repaint();
    }
    1. - (1. - elapsed).powi(3)
}

fn group_end(messages: &[Message], index: usize) -> bool {
    let message = &messages[index];
    messages.get(index + 1).is_none_or(|after| {
        message.outgoing != after.outgoing
            || after.timestamp_ms.saturating_sub(message.timestamp_ms) > 180_000
    })
}

fn delivery_label(messages: &[Message], index: usize) -> Option<(&'static str, Color32)> {
    let message = &messages[index];
    if !message.outgoing {
        return None;
    }
    match message.status {
        Delivery::Pending => Some(("Sending…", MUTED)),
        Delivery::Failed => Some(("Not Delivered", DANGER)),
        Delivery::Unknown => Some(("Delivery Unknown", DANGER)),
        Delivery::Accepted if index + 1 == messages.len() => Some(("Sent", MUTED)),
        _ => None,
    }
}

fn settings_field(ui: &mut Ui, label: &str, value: &mut String, hint: &str, secret: bool) {
    let label = ui.label(chrome::bold(label, 11.));
    ui.add_sized(
        [ui.available_width(), 27.],
        TextEdit::singleline(value)
            .password(secret)
            .hint_text(hint)
            .margin(Margin::symmetric(7, 5)),
    )
    .labelled_by(label.id);
}

enum ConversationMenu {
    TogglePin,
    Delete,
}

fn conversation_menu(response: &egui::Response, pinned: bool) -> Option<ConversationMenu> {
    let mut action = None;
    response.context_menu(|ui| {
        if ui
            .button(if pinned {
                "Unpin Conversation"
            } else {
                "Pin Conversation"
            })
            .clicked()
        {
            action = Some(ConversationMenu::TogglePin);
            ui.close();
        }
        if ui
            .button(RichText::new("Delete Conversation…").color(DANGER))
            .clicked()
        {
            action = Some(ConversationMenu::Delete);
            ui.close();
        }
    });
    action
}

fn pin_tile(
    ui: &mut Ui,
    chat: &Conversation,
    name: &str,
    active: bool,
    compact: bool,
    width: f32,
) -> egui::Response {
    let height = if compact { 62. } else { 98. };
    let (rect, response) = ui.allocate_exact_size(vec2(width, height), Sense::click());
    selected_background(ui, rect.shrink2(vec2(3., 1.)), &response, active, name);
    let selected = ui
        .ctx()
        .animate_bool_with_time(response.id.with("selected"), active, 0.19);
    let hover =
        ui.ctx()
            .animate_bool_with_time(response.id.with("hover-avatar"), response.hovered(), 0.16);
    let size = if compact {
        44.
    } else {
        (width - 24.).clamp(44., 66.)
    };
    let at = pos2(
        rect.center().x,
        rect.top() + if compact { 30. } else { 39. },
    );
    chrome::avatar(ui, at, size + 1.5 * hover, name, &chat.address);
    if !compact {
        let color = MUTED.lerp_to_gamma(Color32::WHITE, selected);
        let label = sidebar_title(
            ui,
            name,
            FontId::proportional(10.),
            color,
            rect.width() - 12.,
        );
        ui.painter().galley(
            pos2(
                rect.center().x - label.size().x * 0.5,
                rect.bottom() - 15. - label.size().y * 0.5,
            ),
            label,
            color,
        );
    }
    response.on_hover_text(name)
}

fn chat_row(
    ui: &mut Ui,
    chat: &Conversation,
    name: &str,
    active: bool,
    compact: bool,
) -> egui::Response {
    let height = if compact { 63. } else { 59. };
    let (rect, response) =
        ui.allocate_exact_size(vec2(ui.available_width(), height), Sense::click());
    selected_background(ui, rect.shrink2(vec2(9., 2.)), &response, active, name);
    let selected = ui
        .ctx()
        .animate_bool_with_time(response.id.with("selected"), active, 0.19);
    let avatar = pos2(
        if compact {
            rect.center().x
        } else {
            rect.left() + 43.
        },
        rect.center().y,
    );
    chrome::avatar(
        ui,
        avatar,
        if compact { 44. } else { 36. },
        name,
        &chat.address,
    );
    if compact {
        return response.on_hover_text(name);
    }
    let right = rect.right() - 20.;
    let left = rect.left() + 67.;
    let time = Local
        .timestamp_millis_opt(chat.updated_ms)
        .single()
        .map(|time| {
            let today = Local::now().date_naive();
            if time.date_naive() == today {
                time.format("%-I:%M %p").to_string()
            } else if today.pred_opt() == Some(time.date_naive()) {
                "Yesterday".into()
            } else {
                time.format("%-m/%-d/%y").to_string()
            }
        })
        .unwrap_or_default();
    let muted = MUTED.lerp_to_gamma(Color32::from_gray(244), selected);
    let text = INK.lerp_to_gamma(Color32::WHITE, selected);
    let painter = ui.painter();
    painter.text(
        pos2(right, rect.top() + 14.),
        Align2::RIGHT_CENTER,
        &time,
        FontId::proportional(10.5),
        muted,
    );
    let time_width = painter
        .layout_no_wrap(time, FontId::proportional(10.5), muted)
        .size()
        .x;
    let title = sidebar_title(
        ui,
        name,
        chrome::bold_font(12.),
        text,
        right - left - time_width - 7.,
    );
    painter.galley(
        pos2(left, rect.top() + 14. - title.size().y * 0.5),
        title,
        text,
    );
    let preview = chat.preview.replace('\n', " ");
    let galley = ui.fonts_mut(|fonts| {
        fonts.layout(
            preview,
            FontId::proportional(11.),
            muted,
            (right - left).max(30.),
        )
    });
    let clip = Rect::from_min_max(
        pos2(left, rect.top() + 23.),
        pos2(right + 1., rect.bottom() - 4.),
    );
    painter
        .with_clip_rect(clip)
        .galley(pos2(left, rect.top() + 23.), galley, muted);
    if selected < 0.8 {
        let segment = Rect::from_min_max(rect.min, rect.max - vec2(9., 0.4));
        chrome::line(ui, segment, 67.);
    }
    response
}

fn sidebar_title(
    ui: &Ui,
    name: &str,
    font: FontId,
    color: Color32,
    width: f32,
) -> std::sync::Arc<egui::Galley> {
    let mut layout = egui::text::LayoutJob::simple(name.into(), font, color, width.max(4.));
    layout.wrap.max_rows = 1;
    layout.wrap.break_anywhere = true;
    ui.fonts_mut(|fonts| fonts.layout_job(layout))
}

fn selected_background(ui: &Ui, rect: Rect, response: &egui::Response, active: bool, name: &str) {
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::SelectableLabel, true, active, name)
    });
    let hover =
        ui.ctx()
            .animate_bool_with_time(response.id.with("hover"), response.hovered(), 0.14);
    let selected = ui
        .ctx()
        .animate_bool_with_time(response.id.with("selected"), active, 0.19);
    let color = Color32::from_black_alpha((18. * hover) as u8).lerp_to_gamma(BLUE, selected);
    ui.painter().rect_filled(rect, 6, color);
    if response.has_focus() {
        ui.painter()
            .rect_stroke(rect, 6, Stroke::new(1.0_f32, BLUE), StrokeKind::Inside);
    }
}

fn window_edge(ctx: &egui::Context) {
    let rect = ctx.content_rect();
    let special = ctx.input(|input| {
        input.viewport().maximized.unwrap_or_default()
            || input.viewport().fullscreen.unwrap_or_default()
    });
    if special {
        return;
    }
    let painter = ctx.layer_painter(egui::LayerId::new(
        egui::Order::Foreground,
        egui::Id::new("window-edge"),
    ));
    painter.rect_stroke(
        rect,
        chrome::window_radius(ctx),
        Stroke::new(1.0_f32, Color32::from_gray(182)),
        StrokeKind::Inside,
    );
    use egui::viewport::ResizeDirection;
    for (id, position, size, direction, cursor) in [
        (
            "west",
            rect.left_top() + vec2(0., 48.),
            vec2(4., rect.height() - 58.),
            ResizeDirection::West,
            egui::CursorIcon::ResizeHorizontal,
        ),
        (
            "east",
            rect.right_top() + vec2(-4., 48.),
            vec2(4., rect.height() - 58.),
            ResizeDirection::East,
            egui::CursorIcon::ResizeHorizontal,
        ),
        (
            "south",
            rect.left_bottom() + vec2(8., -4.),
            vec2(rect.width() - 19., 4.),
            ResizeDirection::South,
            egui::CursorIcon::ResizeVertical,
        ),
        (
            "corner",
            rect.right_bottom() - vec2(9., 9.),
            vec2(9., 9.),
            ResizeDirection::SouthEast,
            egui::CursorIcon::ResizeNwSe,
        ),
    ] {
        egui::Area::new(egui::Id::new(id))
            .order(egui::Order::Foreground)
            .fixed_pos(position)
            .show(ctx, |ui| {
                let (_, grip) = ui.allocate_exact_size(size, Sense::drag());
                if grip.on_hover_cursor(cursor).drag_started() {
                    ctx.send_viewport_cmd(egui::ViewportCommand::BeginResize(direction));
                }
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closing_the_window_keeps_a_face_time_session_available_until_quit() -> anyhow::Result<()> {
        let ctx = egui::Context::default();
        let root = tempfile::tempdir()?;
        let mut app = MessagesApp::new(&ctx, root.path().to_owned(), true, Clipboard::empty());
        let (connection, _actions, _events) = Connection::test_channels();
        app.connection = Some(connection);
        let mut frame = |registered, quit| {
            app.status = Some(Status {
                connected: false,
                detail: String::new(),
                tapback_revision: None,
                facetime_registered: registered,
                incoming_calls: Vec::new(),
            });
            let mut input = egui::RawInput::default();
            input
                .viewports
                .get_mut(&egui::ViewportId::ROOT)
                .unwrap()
                .events
                .push(egui::ViewportEvent::Close);
            if quit {
                let modifiers = egui::Modifiers {
                    ctrl: true,
                    command: true,
                    ..Default::default()
                };
                input.modifiers = modifiers;
                input.events.push(egui::Event::Key {
                    key: egui::Key::Q,
                    physical_key: Some(egui::Key::Q),
                    pressed: true,
                    repeat: false,
                    modifiers,
                });
            }
            ctx.run(input, |ctx| app.handle_window_actions(ctx))
                .viewport_output[&egui::ViewportId::ROOT]
                .commands
                .clone()
        };
        assert!(frame(false, false).is_empty());
        assert_eq!(
            frame(true, false),
            [
                egui::ViewportCommand::CancelClose,
                egui::ViewportCommand::Minimized(true)
            ]
        );
        assert_eq!(frame(true, true), [egui::ViewportCommand::Close]);
        Ok(())
    }

    #[test]
    fn tapback_menu_replaces_a_legacy_reaction_with_a_pasted_emoji() -> anyhow::Result<()> {
        for from_badge in [false, true] {
            replace_legacy_tapback_with_emoji(from_badge)?;
        }
        Ok(())
    }

    fn replace_legacy_tapback_with_emoji(from_badge: bool) -> anyhow::Result<()> {
        let ctx = egui::Context::default();
        let root = tempfile::tempdir()?;
        let mut app = MessagesApp::new(&ctx, root.path().to_owned(), true, Clipboard::empty());
        let (connection, mut actions, _events) = Connection::test_channels();
        app.connection = Some(connection);
        app.status = Some(Status {
            connected: true,
            detail: String::new(),
            tapback_revision: None,
            facetime_registered: false,
            incoming_calls: Vec::new(),
        });
        app.thread_loaded = true;
        app.history_all = true;
        let id = Uuid::new_v4();
        let chat = "mailto:peer@example.org";
        app.messages.push(Message {
            id: id.to_string(),
            address: chat.into(),
            body: "Choose a reaction".into(),
            text_part: Some(1),
            outgoing: false,
            timestamp_ms: now_ms(),
            status: Delivery::Received,
            attachments: Vec::new(),
            tapbacks: vec![linux_imessage::Tapback {
                kind: TapbackKind::Like,
                outgoing: true,
                part: 0,
            }],
        });
        let mut frame = |events| {
            ctx.run(
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(640., 420.))),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| app.transcript(ui, chat));
                },
            )
        };
        if from_badge {
            click(&mut frame, "👍");
        } else {
            let bubble = find_label(&mut frame, "Choose a reaction");
            pointer_click(&mut frame, bubble, egui::PointerButton::Secondary);
        }
        let submenu = find_label(&mut frame, "Emoji…");
        frame(vec![egui::Event::PointerMoved(submenu)]);
        click(&mut frame, "Paste emoji or type :name:");
        frame(vec![egui::Event::Paste("🚀".into())]);
        click(&mut frame, "Select Emoji");
        let Action::Tapback {
            id: target,
            request,
        } = actions.try_recv()?
        else {
            anyhow::bail!("Expected a Tapback request");
        };
        assert_eq!(target, id);
        assert_eq!(request.part, Some(0));
        assert_eq!(request.reaction, Some(TapbackKind::Emoji("🚀".into())));
        Ok(())
    }

    #[test]
    fn existing_apple_session_can_open_face_time_upgrade_from_settings() -> anyhow::Result<()> {
        let ctx = egui::Context::default();
        let root = tempfile::tempdir()?;
        let mut app = MessagesApp::new(&ctx, root.path().to_owned(), true, Clipboard::empty());
        app.mac_setup = None;
        app.status = Some(Status {
            connected: true,
            detail: "Connected to Apple courier".into(),
            tapback_revision: None,
            facetime_registered: false,
            incoming_calls: Vec::new(),
        });
        app.open_settings();
        let mut frame = |events| {
            ctx.run(
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(932., 700.))),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    app.settings_dialog(ctx);
                    app.mac_setup_dialog(ctx);
                },
            )
        };
        click(&mut frame, "Enable FaceTime…");
        frame(Vec::new());
        let output = frame(Vec::new());
        for label in ["Enable FaceTime", "Use Validation File…"] {
            assert!(
                output
                    .shapes
                    .iter()
                    .any(|shape| label_position(&shape.shape, label).is_some())
            );
        }
        Ok(())
    }

    #[test]
    fn conversation_toolbar_places_a_video_call_and_displays_an_audio_answer() -> anyhow::Result<()>
    {
        let ctx = egui::Context::default();
        let root = tempfile::tempdir()?;
        let mut app = MessagesApp::new(&ctx, root.path().to_owned(), true, Clipboard::empty());
        let (connection, mut actions, report) = Connection::test_channels();
        app.connection = Some(connection);
        app.status = Some(Status {
            connected: true,
            detail: String::new(),
            tapback_revision: None,
            facetime_registered: true,
            incoming_calls: Vec::new(),
        });
        app.refresh_at = Instant::now() + Duration::from_secs(120);
        let peer = "mailto:peer@example.org";
        let mut frame = |events| {
            ctx.run(
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(932., 700.))),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    app.process(ctx);
                    app.toolbar(ctx, Some(peer));
                    app.call_panel(ctx);
                },
            )
        };
        click_at(&mut frame, pos2(865., 24.));
        click(&mut frame, "FaceTime Video");
        let Action::StartCall {
            id,
            start: super::super::connection::CallStart::Dial(recipient),
            video: Some(video),
            mut hang_up,
            ..
        } = actions.try_recv()?
        else {
            panic!("Expected an outgoing video call");
        };
        assert_eq!(recipient, peer);
        assert!(
            report
                .send(Event::CallConnected {
                    id,
                    mode: CallMode::Audio
                })
                .is_ok()
        );
        click(&mut frame, "End");
        hang_up.try_recv()?;
        assert!(video.camera_enabled.has_changed().is_err());
        Ok(())
    }

    #[test]
    fn incoming_call_card_answers_audio_video_and_video_as_audio() -> anyhow::Result<()> {
        for (offered, answer, label) in [
            (CallMode::Audio, CallMode::Audio, "Answer"),
            (CallMode::Video, CallMode::Video, "Answer Video"),
            (CallMode::Video, CallMode::Audio, "Answer as Audio"),
        ] {
            exercise_call(offered, answer, Some(label))?;
            exercise_call(offered, answer, None)?;
        }
        Ok(())
    }

    fn exercise_call(
        offered: CallMode,
        answer: CallMode,
        label: Option<&str>,
    ) -> anyhow::Result<()> {
        let ctx = egui::Context::default();
        let root = tempfile::tempdir()?;
        // Bypass starting a real session. All incoming status and action events use test channels.
        let mut app = MessagesApp::new(&ctx, root.path().to_owned(), true, Clipboard::empty());
        let (connection, mut actions, report) = Connection::test_channels();
        app.connection = Some(connection);
        app.status = Some(Status {
            connected: true,
            detail: String::new(),
            tapback_revision: None,
            facetime_registered: true,
            incoming_calls: Vec::new(),
        });
        app.refresh_at = Instant::now() + Duration::from_secs(120);
        let id = Uuid::new_v4();
        let now = now_ms();
        let ring = IncomingCall {
            id,
            caller: "mailto:peer@example.org".into(),
            mode: Some(offered),
            received_ms: now,
            expires_ms: now + 45_000,
        };
        assert!(report.send(Event::IncomingCalls(vec![ring])).is_ok());

        let mut frame = |events| {
            ctx.run(
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, vec2(932., 700.))),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    app.process(ctx);
                    app.call_panel(ctx);
                },
            )
        };
        if let Some(label) = label {
            click(&mut frame, label);
        } else {
            report.send(Event::IncomingCallAction {
                id: Uuid::new_v4(),
                action: RingAction::Answer(CallMode::Audio),
                token: None,
            })?;
            frame(Vec::new());
            assert!(actions.try_recv().is_err());
            report.send(Event::IncomingCallAction {
                id,
                action: RingAction::Open,
                token: Some("open-token".into()),
            })?;
            let output = frame(Vec::new());
            assert!(
                output.viewport_output[&egui::ViewportId::ROOT]
                    .commands
                    .iter()
                    .any(|cmd| matches!(cmd, egui::ViewportCommand::Focus))
            );
            assert!(actions.try_recv().is_err());
            report.send(Event::IncomingCallAction {
                id,
                action: RingAction::Answer(answer),
                token: Some("answer-token".into()),
            })?;
            frame(Vec::new());
        }
        let Action::StartCall {
            id: accepted,
            start: super::super::connection::CallStart::Answer,
            muted,
            mut hang_up,
            video,
        } = actions.try_recv()?
        else {
            panic!("Expected a call answer");
        };
        assert_eq!(accepted, id);
        assert_eq!(video.is_some(), answer == CallMode::Video);
        assert!(!*muted.borrow());
        assert!(
            report
                .send(Event::CallConnected { id, mode: answer })
                .is_ok()
        );
        assert!(report.send(Event::IncomingCalls(Vec::new())).is_ok());
        if let Some(video) = video {
            assert!(*video.camera_enabled.borrow());
            video.frames.send_replace(Some(std::sync::Arc::new(
                linux_imessage::engine::video::VideoFrame {
                    width: 2,
                    height: 2,
                    rgba: Zeroizing::new([20, 120, 220, 255].repeat(4)),
                },
            )));
            video
                .preview
                .send_replace(Some(std::sync::Arc::new(VideoFrame {
                    width: 4,
                    height: 2,
                    rgba: Zeroizing::new([220, 120, 20, 255].repeat(8)),
                })));
            let output = frame(Vec::new());
            assert!(output.textures_delta.set.iter().any(|(_, texture)| {
                let egui::ImageData::Color(image) = &texture.image;
                image.size == [2, 2] && image.pixels[0] == Color32::from_rgb(20, 120, 220)
            }));
            let preview = output
                .textures_delta
                .set
                .iter()
                .find_map(|(id, update)| {
                    let egui::ImageData::Color(image) = &update.image;
                    (image.size == [4, 2] && image.pixels[0] == Color32::from_rgb(220, 120, 20))
                        .then_some(*id)
                })
                .expect("Missing local camera preview");
            let preview_rect = |output: egui::FullOutput| {
                output
                    .shapes
                    .into_iter()
                    .find_map(|shape| {
                        if let egui::Shape::Rect(rect) = shape.shape
                            && let Some(brush) = &rect.brush
                            && brush.fill_texture_id == preview
                        {
                            assert!(brush.uv.min.x > brush.uv.max.x);
                            return Some(rect.rect);
                        }
                        None
                    })
                    .expect("Missing mirrored camera tile")
            };
            for _ in 0..12 {
                frame(Vec::new());
            }
            let original = preview_rect(frame(Vec::new())).center();
            frame(vec![egui::Event::PointerMoved(original)]);
            frame(vec![egui::Event::PointerButton {
                pos: original,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::NONE,
            }]);
            let moved = original - vec2(75., 30.);
            let moved_rect = preview_rect(frame(vec![egui::Event::PointerMoved(moved)]));
            assert!(moved_rect.center().distance(moved) < 2.);
            frame(vec![egui::Event::PointerButton {
                pos: moved,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            }]);
            click(&mut frame, "Camera Off");
            assert!(!*video.camera_enabled.borrow());
            frame(Vec::new());
            assert!(ctx.tex_manager().read().meta(preview).is_none());
            click(&mut frame, "Camera On");
            assert!(*video.camera_enabled.borrow());

            video.status.send_modify(|status| {
                status.camera_error = Some("Could not open the camera".into());
                status.playback_error = Some("The video decoder stopped".into());
            });
            video.frames.send_replace(None);
            find_label(&mut frame, "Video unavailable");
            let mut camera = video.camera_enabled.clone();
            camera.borrow_and_update();
            click(&mut frame, "Retry Camera");
            assert!(camera.has_changed()?);
            assert!(*camera.borrow());
        }
        click(&mut frame, "Mute");
        assert!(*muted.borrow());
        click(&mut frame, "End");
        hang_up.try_recv()?;
        Ok(())
    }

    fn click(frame: &mut impl FnMut(Vec<egui::Event>) -> egui::FullOutput, label: &str) {
        let position = find_label(frame, label);
        click_at(frame, position);
    }

    fn find_label(
        frame: &mut impl FnMut(Vec<egui::Event>) -> egui::FullOutput,
        label: &str,
    ) -> egui::Pos2 {
        frame(Vec::new()); // The area's first frame measures its content.
        let shapes = frame(Vec::new()).shapes;
        shapes
            .iter()
            .find_map(|shape| label_position(&shape.shape, label))
            .unwrap_or_else(|| panic!("Missing label {label}"))
    }

    fn click_at(
        frame: &mut impl FnMut(Vec<egui::Event>) -> egui::FullOutput,
        position: egui::Pos2,
    ) {
        pointer_click(frame, position, egui::PointerButton::Primary);
    }

    fn pointer_click(
        frame: &mut impl FnMut(Vec<egui::Event>) -> egui::FullOutput,
        position: egui::Pos2,
        button: egui::PointerButton,
    ) {
        frame(vec![egui::Event::PointerMoved(position)]);
        for pressed in [true, false] {
            frame(vec![
                egui::Event::PointerMoved(position),
                egui::Event::PointerButton {
                    pos: position,
                    button,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ]);
        }
    }

    fn label_position(shape: &egui::Shape, label: &str) -> Option<egui::Pos2> {
        match shape {
            egui::Shape::Text(shape) if shape.galley.text() == label => {
                Some(shape.pos + shape.galley.size() / 2.)
            }
            egui::Shape::Vec(items) => items.iter().find_map(|shape| label_position(shape, label)),
            _ => None,
        }
    }
}
