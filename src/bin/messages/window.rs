use std::{
    collections::HashMap,
    path::PathBuf,
    time::{Duration, Instant},
};

use chrono::{Local, NaiveDate, TimeZone};
use eframe::egui::{
    self, Align, Align2, Color32, FontId, Frame, Layout, Margin, Rect, RichText, ScrollArea, Sense,
    Stroke, StrokeKind, TextEdit, Ui, UiBuilder, pos2, vec2,
};
use linux_imessage::{
    Conversation, Delivery, Message, PAGE_SIZE, SendText, Status, TEXT_LIMIT, address,
    display_address, now_ms, storage,
};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use super::connection::{Action, Connection, Event, Mode, Settings};

use super::chrome::{
    self, BLUE, BUBBLE_GRAY, CANVAS, DANGER, HAIRLINE, INK, Icon, MUTED, SIDEBAR, TOOLBAR,
    TOOLBAR_HEIGHT,
};

const POLL: Duration = Duration::from_secs(4);
const MOTION: f32 = 0.30;
const DEMO_PINS: &[&str] = &[
    "mailto:maya@example.com",
    "mailto:elliot@example.com",
    "mailto:noor@example.com",
];

pub struct MessagesApp {
    root: PathBuf,
    config: Settings,
    settings: Option<SettingsForm>,
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
    selected: Option<String>,
    messages: Vec<Message>,
    search: String,
    drafts: HashMap<String, String>,
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
}

struct SettingsForm {
    config: Settings,
    password: String,
    error: Option<String>,
    opened: Instant,
}

impl Drop for SettingsForm {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl MessagesApp {
    pub fn new(ctx: &egui::Context, root: PathBuf, demo: bool) -> Self {
        chrome::theme(ctx);
        let (mut config, error) = match Settings::read(&root) {
            Ok(config) => (config, None),
            Err(error) => (Settings::default(), Some(error.to_string())),
        };
        if demo {
            config.mode = Mode::Demo;
        }
        let candidate = Connection::start(
            ctx,
            root.clone(),
            config.clone(),
            None,
            Zeroizing::new(String::new()),
        );
        Self {
            root,
            config,
            settings: None,
            candidate: Some(candidate),
            connection: None,
            status: None,
            error,
            chats: Vec::new(),
            pins: Vec::new(),
            message_motion: HashMap::new(),
            thread_motion: None,
            thread_loaded: false,
            info_started: None,
            selected: None,
            messages: Vec::new(),
            search: String::new(),
            drafts: HashMap::new(),
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
        }
    }

    fn process(&mut self, ctx: &egui::Context) {
        if let Some(event) = self
            .candidate
            .as_ref()
            .and_then(|connection| connection.events.try_recv().ok())
        {
            match event {
                Event::Ready(status) => {
                    self.connection = self.candidate.take();
                    if let Some(form) = self.settings.take() {
                        self.config = form.config.clone();
                    }
                    self.status = Some(status);
                    self.pins = self.read_pins();
                    self.chats.clear();
                    self.thread_loaded = false;
                    self.message_motion.clear();
                    self.composing = None;
                    self.selected = None;
                    self.messages.clear();
                    self.drafts.clear();
                    self.retry = None;
                    self.error = None;
                    self.refresh_running = false;
                    self.loading_older = false;
                    self.sending = false;
                    self.refresh_at = Instant::now();
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
                        if self.messages.len() < PAGE_SIZE as usize {
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
                    match result {
                        Ok(item) => {
                            self.retry = None;
                            if self.selected.as_deref() == Some(&item.address) {
                                self.merge(vec![item]);
                            }
                        }
                        Err(error) => {
                            self.error = Some(error.to_string());
                            self.drafts
                                .entry(request.address.clone())
                                .or_insert_with(|| request.body.clone());
                            let id = request.id.to_string();
                            if let Some(message) =
                                self.messages.iter_mut().find(|message| message.id == id)
                            {
                                message.status = Delivery::Unknown;
                            }
                            self.retry = Some(request);
                        }
                    }
                    self.refresh_at = Instant::now();
                }
                Event::Error(error) => {
                    self.refresh_running = false;
                    self.error = Some(error);
                }
                Event::ConnectionError(error) => {
                    self.connection = None;
                    self.status = None;
                    self.error = Some(error);
                }
                Event::Ready(_) => {}
            }
        }
        if Instant::now() >= self.refresh_at
            && !self.refresh_running
            && let Some(connection) = &self.connection
        {
            self.refresh_running = connection
                .actions
                .send(Action::Refresh(self.selected.clone()))
                .is_ok();
            self.refresh_at = Instant::now() + POLL;
        }
        self.message_motion
            .retain(|_, start| start.elapsed().as_secs_f32() < MOTION);
        ctx.request_repaint_after(POLL);
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

    fn send(&mut self, chat: String, body: String) {
        if self.sending || body.trim().is_empty() || body.len() > TEXT_LIMIT {
            return;
        }
        if let Some(connection) = &self.connection {
            let request = self
                .retry
                .take()
                .filter(|item| item.address == chat && item.body == body)
                .unwrap_or_else(|| SendText {
                    id: Uuid::new_v4(),
                    address: chat,
                    body,
                });
            self.sending = connection
                .actions
                .send(Action::Send(request.clone()))
                .is_ok();
            if self.sending {
                self.drafts.remove(&request.address);
                let id = request.id.to_string();
                self.message_motion.insert(id.clone(), Instant::now());
                self.merge(vec![Message {
                    id,
                    address: request.address,
                    body: request.body,
                    outgoing: true,
                    timestamp_ms: now_ms(),
                    status: Delivery::Pending,
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
        self.composing = Some(String::new());
        self.compose_error = None;
        self.focus_recipient = true;
    }

    fn pins_path(&self) -> PathBuf {
        let name = if self.is_demo() && self.config.mode != Mode::Remote {
            "pins-demo.json".into()
        } else if self.config.mode == Mode::Remote {
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
            .unwrap_or_else(|| {
                if self.is_demo() {
                    DEMO_PINS
                        .iter()
                        .map(|address| (*address).to_owned())
                        .collect()
                } else {
                    Vec::new()
                }
            })
    }

    fn toggle_pin(&mut self, address: &str) {
        if let Some(index) = self.pins.iter().position(|pinned| pinned == address) {
            self.pins.remove(index);
        } else {
            self.pins.push(address.to_owned());
        }
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
            .frame(Frame::new().fill(SIDEBAR))
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
                    chrome::traffic_lights(&mut lights);
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

                let demo = self.is_demo();
                let search = if compact {
                    String::new()
                } else {
                    self.search.trim().to_lowercase()
                };
                let mut clicked = None;
                let mut pin_change = None;
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
                                            let name = chat_name(&chat.address, demo);
                                            let active = self.composing.is_none()
                                                && self.selected.as_deref() == Some(&chat.address);
                                            let response = pin_tile(
                                                ui, chat, &name, active, compact, tile_width,
                                            );
                                            if response.clicked() {
                                                clicked = Some(chat.address.clone());
                                            }
                                            if pin_menu(&response, true) {
                                                pin_change = Some(chat.address.clone());
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
                            let name = chat_name(&chat.address, demo);
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
                            let response = chat_row(ui, chat, &name, active, compact);
                            if response.clicked() {
                                clicked = Some(chat.address.clone());
                            }
                            if pin_menu(&response, pinned) {
                                pin_change = Some(chat.address.clone());
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
                if let Some(address) = pin_change {
                    self.toggle_pin(&address);
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
        ui.painter().rect_filled(rect, 6, Color32::from_gray(215));
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

    fn right_panel(&mut self, ctx: &egui::Context) {
        let chat = self.selected.clone().filter(|_| self.composing.is_none());
        self.toolbar(ctx, chat.as_deref());
        if let Some(chat) = &chat {
            self.composer(ctx, chat);
        }
        egui::CentralPanel::default()
            .frame(Frame::new().fill(CANVAS))
            .show(ctx, |ui| {
                if let Some(chat) = &chat {
                    self.transcript(ui, chat);
                } else if self.composing.is_none() {
                    ui.centered_and_justified(|ui| {
                        let label = if self.candidate.is_some() {
                            "Connecting…"
                        } else {
                            self.error.as_deref().unwrap_or("No Conversation Selected")
                        };
                        ui.label(RichText::new(label).size(13.).color(MUTED));
                    });
                }
            });
    }

    fn toolbar(&mut self, ctx: &egui::Context, chat: Option<&str>) {
        egui::TopBottomPanel::top("conversation-toolbar")
            .exact_height(TOOLBAR_HEIGHT)
            .show_separator_line(false)
            .frame(Frame::new().fill(TOOLBAR))
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
                            .hint_text("Email or Phone Number")
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
                        match address(recipient) {
                            Ok(selected) => {
                                self.composing = None;
                                self.select(selected, true);
                            }
                            Err(error) => {
                                self.compose_error = Some(error.to_string());
                                editor.request_focus();
                            }
                        }
                    }
                } else {
                    if let Some(chat) = chat {
                        let name = chat_name(chat, self.is_demo());
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
                controls.add_enabled_ui(false, |ui| {
                    chrome::icon_button(
                        ui,
                        Icon::Video,
                        "FaceTime requires a supported calling service",
                        None,
                    )
                    .on_disabled_hover_text("FaceTime requires a supported calling service");
                });
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
                            chrome::avatar(
                                ui,
                                rect.center(),
                                46.,
                                &chat_name(chat, self.is_demo()),
                                chat,
                            );
                            ui.label(chrome::bold(chat_name(chat, self.is_demo()), 13.));
                            ui.label(RichText::new(display_address(chat)).size(11.).color(MUTED));
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

    fn composer(&mut self, ctx: &egui::Context, chat: &str) {
        egui::TopBottomPanel::bottom("composer")
            .show_separator_line(false)
            .frame(
                Frame::new()
                    .fill(CANVAS)
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

                let enabled =
                    self.status.as_ref().is_some_and(|status| status.connected) && !self.sending;
                let draft = self.drafts.entry(chat.to_owned()).or_default();
                let mut send = false;
                let mut compose = false;
                let mut settings = false;
                ui.horizontal(|ui| {
                    let extra = chrome::icon_button(ui, Icon::Plus, "Actions", Some(BUBBLE_GRAY));
                    egui::Popup::menu(&extra).frame(chrome::sheet()).show(|ui| {
                        if ui.button("New Message").clicked() {
                            compose = true;
                            ui.close();
                        }
                        if ui.button("Settings…").clicked() {
                            settings = true;
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
                                let enter = ui.memory(|memory| memory.has_focus(id))
                                    && ui.input_mut(|input| {
                                        input.consume_key(egui::Modifiers::NONE, egui::Key::Enter)
                                    });
                                let edit = ScrollArea::vertical()
                                    .id_salt(("draft-scroll", chat))
                                    .max_height(105.)
                                    .min_scrolled_height(0.)
                                    .auto_shrink([true, true])
                                    .show(ui, |ui| {
                                        ui.add(
                                            TextEdit::multiline(draft)
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
                                let visible = !draft.trim().is_empty();
                                let show_button = ctx.animate_bool_with_time(
                                    ui.id().with("send-button"),
                                    visible,
                                    0.14,
                                );
                                if show_button > 0. {
                                    let button = ui
                                        .add_enabled_ui(
                                            enabled && visible && draft.len() <= TEXT_LIMIT,
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
                                    && draft.len() <= TEXT_LIMIT
                                    && enter
                                    && edit.has_focus();
                            });
                        })
                        .response;
                    if response.clicked() {
                        self.focus_composer = true;
                    }
                    let emoji = chrome::icon_button(ui, Icon::Emoji, "Emoji", None);
                    egui::Popup::menu(&emoji).frame(chrome::sheet()).show(|ui| {
                        ui.label(chrome::bold("Emoji", 13.));
                        for row in [
                            ["😀", "😂", "❤️", "👍", "👋", "🎉"],
                            ["🥰", "😅", "🙌", "✨", "💙", "☕"],
                        ] {
                            ui.horizontal(|ui| {
                                for icon in row {
                                    if ui.button(RichText::new(icon).size(17.)).clicked() {
                                        draft.push_str(icon);
                                        self.focus_composer = true;
                                        ui.close();
                                    }
                                }
                            });
                        }
                    });
                });
                if draft.len() > TEXT_LIMIT {
                    ui.label(
                        RichText::new(format!("{} / {TEXT_LIMIT} bytes", draft.len()))
                            .color(DANGER)
                            .size(11.),
                    );
                }
                if send {
                    let message = draft.clone();
                    self.send(chat.to_owned(), message);
                }
                if compose {
                    self.start_compose();
                }
                if settings {
                    self.open_settings();
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
                        let color = if message.outgoing {
                            Color32::WHITE
                        } else {
                            INK
                        };
                        let galley = ui.fonts_mut(|fonts| {
                            fonts.layout(
                                message.body.clone(),
                                FontId::proportional(13.),
                                color,
                                max_text,
                            )
                        });
                        let day = Local.timestamp_millis_opt(message.timestamp_ms).single();
                        (galley, day)
                    })
                    .collect::<Vec<_>>();

                let mut last_day: Option<NaiveDate> = None;
                let mut content_height = if can_load_older { 29. } else { 0. };
                for (index, (galley, time)) in layout.iter().enumerate() {
                    let day = time.map(|value| value.date_naive());
                    if day != last_day {
                        content_height += 24.;
                    }
                    last_day = day;
                    content_height += galley.size().y
                        + 10.
                        + if group_end(&self.messages, index) {
                            10.
                        } else {
                            3.
                        };
                    if delivery_label(&self.messages, index).is_some() {
                        content_height += 14.;
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
                for (index, (galley, time)) in layout.into_iter().enumerate() {
                    let message = &self.messages[index];
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
                    let width = galley.size().x + 19.;
                    let height = galley.size().y + 10.;
                    let (row, _) =
                        ui.allocate_exact_size(vec2(ui.available_width(), height), Sense::hover());
                    let x = if message.outgoing {
                        row.right() - width - 17.
                    } else {
                        row.left() + 18.
                    };
                    // New messages enter from the composer and settle into their transcript slot.
                    let slide = if message.outgoing { 15. } else { 8. };
                    let offset = (1. - progress) * slide;
                    let original = pos2(x, row.top());
                    let rect = Rect::from_min_size(
                        original + vec2(if message.outgoing { offset * 0.45 } else { 0. }, offset),
                        vec2(width, height),
                    );
                    let fill = if message.outgoing { BLUE } else { BUBBLE_GRAY };
                    let mut painter = ui.painter().clone();
                    painter.multiply_opacity(0.25 + progress * 0.75);
                    chrome::bubble_shape(&painter, rect, message.outgoing, tail, fill);
                    let text_rect = rect.shrink2(vec2(9.5, 5.));
                    let mut text_ui = ui.new_child(
                        UiBuilder::new()
                            .max_rect(text_rect)
                            .layout(Layout::top_down(Align::Min)),
                    );
                    text_ui.set_max_width(galley.size().x + 1.);
                    text_ui.multiply_opacity(0.25 + progress * 0.75);
                    let text = text_ui.add(
                        egui::Label::new(RichText::new(&message.body).size(13.).color(
                            if message.outgoing {
                                Color32::WHITE
                            } else {
                                INK
                            },
                        ))
                        .wrap()
                        .selectable(true),
                    );
                    if let Some(time) = time {
                        text.on_hover_text(time.format("%A, %d %B %Y at %-I:%M %p").to_string());
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
    }

    fn is_demo(&self) -> bool {
        self.status.as_ref().is_some_and(|status| status.demo)
    }

    fn settings_dialog(&mut self, ctx: &egui::Context) {
        let Some(form) = &mut self.settings else {
            return;
        };
        let mut apply = false;
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
                        ui.selectable_value(&mut form.config.mode, Mode::Demo, "Demo");
                        ui.selectable_value(&mut form.config.mode, Mode::Local, "This Computer");
                        ui.selectable_value(&mut form.config.mode, Mode::Remote, "Server");
                    });
                    ui.add_space(9.);
                    match form.config.mode {
                        Mode::Demo => {
                            ui.label(RichText::new("Try Messages with sample conversations on this computer.").color(MUTED));
                        }
                        Mode::Local => {
                            ui.label(RichText::new("Run the iMessage engine on this computer. Set up an Apple device session with messages-server login or import-session.").color(MUTED));
                            ui.hyperlink_to("Apple Account setup", "https://github.com/Peaks2000/linux-imessage/blob/main/docs/apple-session.md");
                        }
                        Mode::Remote => {
                            settings_field(ui, "Server URL", &mut form.config.url, "https://messages.example.com", false);
                            settings_field(ui, "Username", &mut form.config.username, "Optional", false);
                            settings_field(ui, "Password", &mut form.password, if form.config.remember { "Use saved password" } else { "Optional" }, true);
                            ui.checkbox(&mut form.config.remember, "Remember password in Linux Secret Service");
                        }
                    }
                });
                if let Some(error) = &form.error {
                    ui.add_space(6.);
                    ui.label(RichText::new(error).size(11.).color(DANGER));
                }
                ui.add_space(9.);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    apply = ui.add_enabled(!connecting && !self.sending, egui::Button::new(
                        RichText::new(if connecting { "Connecting…" } else { "Done" }).color(Color32::WHITE),
                    ).fill(BLUE).corner_radius(5).min_size(vec2(70., 25.))).clicked();
                    cancel = ui.add_enabled(!connecting, egui::Button::new("Cancel").min_size(vec2(65., 25.))).clicked();
                });
            });
        if (cancel || panel.should_close()) && !connecting {
            self.settings = None;
        } else if apply {
            if form.config.mode != Mode::Remote
                && form.config == self.config
                && self.connection.is_some()
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
            ));
        }
    }
}

impl eframe::App for MessagesApp {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        CANVAS.to_normalized_gamma_f32()
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.process(ctx);
        if self.settings.is_none() {
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
        self.right_panel(ctx);
        self.settings_dialog(ctx);
        window_edge(ctx);
    }
}

fn motion(ctx: &egui::Context, start: Option<Instant>, duration: f32) -> f32 {
    let Some(start) = start else { return 1. };
    let elapsed = (start.elapsed().as_secs_f32() / duration).clamp(0., 1.);
    if elapsed < 1. {
        ctx.request_repaint_after(Duration::from_millis(12));
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
        Delivery::Accepted | Delivery::Demo if index + 1 == messages.len() => Some(("Sent", MUTED)),
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

fn pin_menu(response: &egui::Response, pinned: bool) -> bool {
    let mut toggle = false;
    response.context_menu(|ui| {
        if ui
            .button(if pinned {
                "Unpin Conversation"
            } else {
                "Pin Conversation"
            })
            .clicked()
        {
            toggle = true;
            ui.close();
        }
    });
    toggle
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
        let text = ui.painter().with_clip_rect(rect.shrink2(vec2(6., 0.)));
        text.text(
            pos2(rect.center().x, rect.bottom() - 15.),
            Align2::CENTER_CENTER,
            name,
            FontId::proportional(10.),
            MUTED.lerp_to_gamma(Color32::WHITE, selected),
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
    let title_area = Rect::from_min_max(
        pos2(left, rect.top()),
        pos2(right - time_width - 7., rect.top() + 25.),
    );
    painter.with_clip_rect(title_area).text(
        pos2(left, rect.top() + 14.),
        Align2::LEFT_CENTER,
        name,
        chrome::bold_font(12.),
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
    let color = SIDEBAR
        .lerp_to_gamma(Color32::from_gray(217), hover)
        .lerp_to_gamma(BLUE, selected);
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
        0,
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

fn chat_name(address: &str, demo: bool) -> String {
    if demo {
        let name = match address {
            "mailto:maya@example.com" => Some("Maya Chen"),
            "mailto:elliot@example.com" => Some("Elliot Park"),
            "mailto:noor@example.com" => Some("Noor Ali"),
            "mailto:ava@example.com" => Some("Ava Patel"),
            "mailto:leo@example.com" => Some("Leo Rivera"),
            "mailto:hana@example.com" => Some("Hana Kim"),
            "mailto:milo@example.com" => Some("Milo James"),
            "mailto:ella@example.com" => Some("Ella Cooper"),
            _ => None,
        };
        if let Some(name) = name {
            return name.to_owned();
        }
    }
    display_address(address).to_owned()
}
