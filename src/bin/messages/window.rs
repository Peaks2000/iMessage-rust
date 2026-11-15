use std::{
    collections::HashMap,
    path::PathBuf,
    time::{Duration, Instant},
};

use chrono::{Local, TimeZone};
use eframe::egui::{
    self, Align, Color32, FontData, FontDefinitions, FontFamily, FontId, Frame, Layout, Margin,
    RichText, ScrollArea, Sense, Stroke, TextEdit, Vec2, vec2,
};
use linux_imessage::{
    Conversation, Delivery, Message, PAGE_SIZE, SendText, Status, TEXT_LIMIT, address,
    display_address,
};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use super::connection::{Action, Connection, Event, Mode, Settings};

const INK: Color32 = Color32::from_rgb(24, 32, 47);
const MUTED: Color32 = Color32::from_rgb(86, 101, 124);
const HAIRLINE: Color32 = Color32::from_rgb(225, 231, 239);
const BLUE: Color32 = Color32::from_rgb(17, 92, 218);
const BLUE_TINT: Color32 = Color32::from_rgb(228, 239, 255);
const SIDEBAR: Color32 = Color32::from_rgb(245, 247, 251);
const DANGER: Color32 = Color32::from_rgb(157, 44, 39);
const POLL: Duration = Duration::from_secs(4);

pub struct MessagesApp {
    root: PathBuf,
    config: Settings,
    settings: Option<SettingsForm>,
    connection: Option<Connection>,
    candidate: Option<Connection>,
    status: Option<Status>,
    error: Option<String>,
    chats: Vec<Conversation>,
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
}

impl Drop for SettingsForm {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

impl MessagesApp {
    pub fn new(ctx: &egui::Context, root: PathBuf, demo: bool) -> Self {
        theme(ctx);
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
                    self.chats.clear();
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
                            if self.drafts.get(&request.address) == Some(&request.body) {
                                self.drafts.remove(&request.address);
                            }
                            self.retry = None;
                            if self.selected.as_deref() == Some(&item.address) {
                                self.merge(vec![item]);
                            }
                        }
                        Err(error) => {
                            self.error = Some(error.to_string());
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
        ctx.request_repaint_after(POLL);
    }

    fn select(&mut self, who: String, focus: bool) {
        if self.selected.as_ref() != Some(&who) {
            self.selected = Some(who);
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
            self.sending = connection.actions.send(Action::Send(request)).is_ok();
            self.error = None;
            self.focus_composer = true;
        }
    }

    fn open_settings(&mut self) {
        self.settings = Some(SettingsForm {
            config: self.config.clone(),
            password: String::new(),
            error: None,
        });
    }

    fn sidebar(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("conversations")
            .exact_width(300.)
            .resizable(false)
            .show_separator_line(false)
            .frame(
                Frame::new()
                    .fill(SIDEBAR)
                    .stroke(Stroke::new(1.0_f32, HAIRLINE)),
            )
            .show(ctx, |ui| {
                ui.spacing_mut().item_spacing = vec2(0., 0.);
                Frame::new()
                    .inner_margin(Margin::symmetric(20, 19))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(title("Messages", 26.));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui
                                    .add(button("+", BLUE, Color32::WHITE).min_size(vec2(34., 34.)))
                                    .on_hover_text("New message")
                                    .clicked()
                                {
                                    self.composing = Some(String::new());
                                    self.compose_error = None;
                                    self.focus_recipient = true;
                                }
                            });
                        });
                        ui.add_space(15.);
                        ui.add_sized(
                            [ui.available_width(), 34.],
                            TextEdit::singleline(&mut self.search)
                                .hint_text("Search conversations")
                                .margin(Margin::symmetric(11, 8)),
                        );
                    });
                let footer = 57.;
                let available = ui.available_height();
                ui.allocate_ui_with_layout(
                    vec2(ui.available_width(), (available - footer).max(0.)),
                    Layout::top_down(Align::Min),
                    |ui| {
                        ScrollArea::vertical()
                            .id_salt("chat-list")
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                ui.add_space(2.);
                                let search = self.search.trim().to_lowercase();
                                let demo = self.is_demo();
                                let mut clicked = None;
                                let mut found = false;
                                for chat in &self.chats {
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
                                    found = true;
                                    let active = self.selected.as_deref() == Some(&chat.address);
                                    if chat_row(ui, chat, &name, active).clicked() {
                                        clicked = Some(chat.address.clone());
                                    }
                                }
                                if let Some(chat) = clicked {
                                    self.select(chat, false);
                                }
                                if !found {
                                    Frame::new().inner_margin(Margin::symmetric(20, 12)).show(
                                        ui,
                                        |ui| {
                                            ui.label(
                                                RichText::new(if search.is_empty() {
                                                    "No conversations yet"
                                                } else {
                                                    "No matching conversations"
                                                })
                                                .color(MUTED),
                                            );
                                        },
                                    );
                                }
                            });
                    },
                );
                ui.separator();
                Frame::new()
                    .inner_margin(Margin::symmetric(19, 11))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            let (label, color) = match &self.status {
                                Some(status) if status.demo => ("Demo mode", BLUE),
                                Some(status) if status.connected => {
                                    ("Connected", Color32::from_rgb(26, 136, 99))
                                }
                                Some(_) => ("Reconnecting", MUTED),
                                None if self.candidate.is_some() => ("Connecting", MUTED),
                                None => ("Disconnected", MUTED),
                            };
                            let (rect, _) = ui.allocate_exact_size(vec2(8., 12.), Sense::hover());
                            ui.painter().circle_filled(rect.center(), 3.5, color);
                            ui.add_space(7.);
                            let response = ui.label(RichText::new(label).size(12.).color(MUTED));
                            if let Some(status) = &self.status {
                                response.on_hover_text(&status.detail);
                            }
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui
                                    .add(
                                        button("Settings", Color32::WHITE, INK)
                                            .min_size(vec2(69., 29.)),
                                    )
                                    .clicked()
                                {
                                    self.open_settings();
                                }
                            });
                        });
                    });
            });
    }

    fn conversation(&mut self, ctx: &egui::Context) {
        if let Some(chat) = self.selected.clone() {
            let name = chat_name(&chat, self.is_demo());
            egui::TopBottomPanel::top("conversation-title")
                .exact_height(72.)
                .show_separator_line(false)
                .frame(
                    Frame::new()
                        .fill(Color32::WHITE)
                        .stroke(Stroke::new(1.0_f32, HAIRLINE)),
                )
                .show(ctx, |ui| {
                    Frame::new()
                        .inner_margin(Margin::symmetric(26, 15))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                avatar(ui, &name, &chat, 39.);
                                ui.add_space(5.);
                                ui.vertical(|ui| {
                                    ui.label(title(&name, 18.));
                                    let secondary = if self.is_demo() {
                                        display_address(&chat)
                                    } else {
                                        "iMessage"
                                    };
                                    ui.label(RichText::new(secondary).size(12.).color(MUTED));
                                });
                            });
                        });
                });
            self.composer(ctx, &chat);
            egui::CentralPanel::default()
                .frame(Frame::new().fill(Color32::WHITE))
                .show(ctx, |ui| {
                    ScrollArea::vertical()
                        .id_salt(("thread", &chat))
                        .stick_to_bottom(true)
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            Frame::new()
                                .inner_margin(Margin::symmetric(31, 22))
                                .show(ui, |ui| {
                                    ui.set_min_width(ui.available_width());
                                    if !self.history_all {
                                        ui.vertical_centered(|ui| {
                                            if ui
                                                .add_enabled(
                                                    !self.loading_older,
                                                    button(
                                                        if self.loading_older {
                                                            "Loading…"
                                                        } else {
                                                            "Load earlier messages"
                                                        },
                                                        SIDEBAR,
                                                        BLUE,
                                                    ),
                                                )
                                                .clicked()
                                                && let Some(connection) = &self.connection
                                            {
                                                self.loading_older = connection
                                                    .actions
                                                    .send(Action::Older {
                                                        chat: chat.clone(),
                                                        offset: self
                                                            .messages
                                                            .len()
                                                            .try_into()
                                                            .unwrap_or(u32::MAX),
                                                    })
                                                    .is_ok();
                                            }
                                        });
                                        ui.add_space(17.);
                                    }
                                    if self.messages.is_empty() {
                                        ui.vertical_centered(|ui| {
                                            ui.label(
                                                RichText::new("No messages in this conversation")
                                                    .size(13.)
                                                    .color(MUTED),
                                            );
                                        });
                                    }
                                    let mut day = None;
                                    for message in &self.messages {
                                        let date = Local
                                            .timestamp_millis_opt(message.timestamp_ms)
                                            .single();
                                        if date.map(|date| date.date_naive()) != day {
                                            day = date.map(|date| date.date_naive());
                                            if let Some(date) = date {
                                                ui.vertical_centered(|ui| {
                                                    ui.label(
                                                        RichText::new(
                                                            date.format("%A, %e %B").to_string(),
                                                        )
                                                        .size(11.)
                                                        .color(MUTED),
                                                    );
                                                });
                                                ui.add_space(12.);
                                            }
                                        }
                                        bubble(ui, message, self.is_demo());
                                        ui.add_space(7.);
                                    }
                                });
                        });
                });
        } else {
            egui::CentralPanel::default()
                .frame(Frame::new().fill(Color32::WHITE))
                .show(ctx, |ui| {
                    ui.centered_and_justified(|ui| {
                        ui.label(
                            RichText::new(if self.candidate.is_some() {
                                "Connecting…"
                            } else {
                                "Select a conversation or start a new message"
                            })
                            .color(MUTED),
                        );
                    });
                });
        }
    }

    fn composer(&mut self, ctx: &egui::Context, chat: &str) {
        egui::TopBottomPanel::bottom("composer")
            .show_separator_line(false)
            .frame(
                Frame::new()
                    .fill(Color32::WHITE)
                    .stroke(Stroke::new(1.0_f32, HAIRLINE))
                    .inner_margin(Margin::symmetric(26, 13)),
            )
            .show(ctx, |ui| {
                if let Some(error) = &self.error {
                    let mut dismiss = false;
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(error).size(12.).color(DANGER));
                        dismiss = ui.button("Dismiss").clicked();
                    });
                    if dismiss {
                        self.error = None;
                    }
                    ui.add_space(7.);
                }
                let can_send =
                    self.status.as_ref().is_some_and(|status| status.connected) && !self.sending;
                let placeholder = if self.is_demo() {
                    "Demo message"
                } else {
                    "iMessage"
                };
                let draft = self.drafts.entry(chat.to_owned()).or_default();
                let mut send = false;
                ui.horizontal(|ui| {
                    let width = (ui.available_width() - 107.).max(170.);
                    let edit_id = ui.make_persistent_id(("message-draft", chat));
                    let enter = ui.memory(|memory| memory.has_focus(edit_id))
                        && ui.input_mut(|input| {
                            input.consume_key(egui::Modifiers::NONE, egui::Key::Enter)
                        });
                    let response = ScrollArea::vertical()
                        .id_salt(("draft-scroll", chat))
                        .max_height(120.)
                        .min_scrolled_height(0.)
                        .auto_shrink([true, true])
                        .show(ui, |ui| {
                            ui.add(
                                TextEdit::multiline(draft)
                                    .id(edit_id)
                                    .desired_rows(1)
                                    .desired_width(width)
                                    .char_limit(TEXT_LIMIT)
                                    .hint_text(placeholder)
                                    .margin(Margin::symmetric(14, 10))
                                    .return_key(Some(egui::KeyboardShortcut::new(
                                        egui::Modifiers::SHIFT,
                                        egui::Key::Enter,
                                    ))),
                            )
                        })
                        .inner;
                    if self.focus_composer {
                        response.request_focus();
                        self.focus_composer = false;
                    }
                    ui.add_space(6.);
                    let enabled = can_send && !draft.trim().is_empty() && draft.len() <= TEXT_LIMIT;
                    let clicked = ui
                        .add_enabled(
                            enabled,
                            button(
                                if self.sending { "Sending" } else { "Send" },
                                BLUE,
                                Color32::WHITE,
                            )
                            .min_size(vec2(66., 36.)),
                        )
                        .clicked();
                    send = enabled && (clicked || enter && response.has_focus());
                });
                if draft.len() > TEXT_LIMIT {
                    ui.label(
                        RichText::new(format!("{} / {TEXT_LIMIT} bytes", draft.len()))
                            .color(DANGER)
                            .size(12.),
                    );
                }
                if send {
                    let body = draft.clone();
                    self.send(chat.to_owned(), body);
                }
            });
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        if let Some(form) = &mut self.settings {
            let mut apply = false;
            let mut cancel = false;
            let connecting = self.candidate.is_some();
            let panel = egui::Modal::new(egui::Id::new("settings")).frame(dialog_frame()).show(ctx, |ui| {
                ui.set_width(392.);
                ui.label(title("Connection settings", 22.));
                ui.add_space(12.);
                ui.add_enabled_ui(!connecting, |ui| {
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut form.config.mode, Mode::Demo, "Demo");
                        ui.selectable_value(&mut form.config.mode, Mode::Local, "This computer");
                        ui.selectable_value(&mut form.config.mode, Mode::Remote, "Server");
                    });
                    ui.add_space(9.);
                    match form.config.mode {
                        Mode::Demo => {
                            ui.label(RichText::new("Try the app with sample conversations. Messages stay on this device.").color(MUTED));
                        }
                        Mode::Local => {
                            ui.label(RichText::new("Run the iMessage engine on this computer. Import an existing Apple device session with messages-server import-session first.").color(MUTED));
                        }
                        Mode::Remote => {
                            field(ui, "Server URL", &mut form.config.url, "https://messages.example.com", false);
                            field(ui, "Username", &mut form.config.username, "Optional", false);
                            field(ui, "Password", &mut form.password, if form.config.remember { "Use saved password" } else { "Optional" }, true);
                            ui.checkbox(&mut form.config.remember, "Remember password in Linux Secret Service");
                        }
                    }
                });
                if let Some(error) = &form.error {
                    ui.add_space(7.);
                    ui.label(RichText::new(error).color(DANGER).size(12.));
                }
                ui.add_space(17.);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    apply = ui.add_enabled(!connecting && !self.sending,
                        button(if connecting { "Connecting…" } else { "Apply" }, BLUE, Color32::WHITE).min_size(vec2(75., 34.))).clicked();
                    cancel = ui.add_enabled(!connecting, button("Cancel", SIDEBAR, INK).min_size(vec2(70., 34.))).clicked();
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
        } else if let Some(recipient) = &mut self.composing {
            let mut submit = false;
            let mut cancel = false;
            let panel = egui::Modal::new(egui::Id::new("new-message"))
                .frame(dialog_frame())
                .show(ctx, |ui| {
                    ui.set_width(365.);
                    ui.label(title("New message", 22.));
                    ui.add_space(12.);
                    let edit = field(ui, "To", recipient, "Email address or +country code", false);
                    if self.focus_recipient {
                        edit.request_focus();
                        self.focus_recipient = false;
                    }
                    if let Some(error) = &self.compose_error {
                        ui.label(RichText::new(error).size(12.).color(DANGER));
                    }
                    ui.add_space(17.);
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        submit = ui
                            .add(button("Continue", BLUE, Color32::WHITE).min_size(vec2(84., 34.)))
                            .clicked()
                            || (edit.lost_focus()
                                && ui.input(|input| input.key_pressed(egui::Key::Enter)));
                        cancel = ui
                            .add(button("Cancel", SIDEBAR, INK).min_size(vec2(68., 34.)))
                            .clicked();
                    });
                });
            if cancel || panel.should_close() {
                self.composing = None;
            } else if submit {
                match address(recipient) {
                    Ok(chat) => {
                        self.composing = None;
                        self.select(chat, true);
                    }
                    Err(error) => self.compose_error = Some(error.to_string()),
                }
            }
        }
    }

    fn is_demo(&self) -> bool {
        self.status.as_ref().is_some_and(|status| status.demo)
    }
}

impl eframe::App for MessagesApp {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        HAIRLINE.to_normalized_gamma_f32()
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.process(ctx);
        if ctx.input_mut(|input| input.consume_key(egui::Modifiers::CTRL, egui::Key::N))
            && self.settings.is_none()
            && self.composing.is_none()
        {
            self.composing = Some(String::new());
            self.compose_error = None;
            self.focus_recipient = true;
        }
        self.sidebar(ctx);
        self.conversation(ctx);
        self.dialogs(ctx);
    }
}

fn theme(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    fonts.font_data.insert(
        "Inter".into(),
        FontData::from_static(include_bytes!("../../../assets/Inter.ttf")).into(),
    );
    fonts
        .families
        .get_mut(&FontFamily::Proportional)
        .expect("Default proportional family")
        .insert(0, "Inter".into());
    ctx.set_fonts(fonts);
    let mut light = egui::Visuals::light();
    light.override_text_color = Some(INK);
    light.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, HAIRLINE);
    light.widgets.inactive.bg_fill = Color32::WHITE;
    light.widgets.inactive.weak_bg_fill = Color32::WHITE;
    light.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, HAIRLINE);
    light.widgets.hovered.bg_fill = BLUE_TINT;
    light.widgets.hovered.weak_bg_fill = BLUE_TINT;
    light.widgets.active.bg_fill = BLUE_TINT;
    light.selection.bg_fill = BLUE_TINT;
    light.selection.stroke = Stroke::new(1.0_f32, BLUE);
    ctx.set_visuals(light);
    ctx.style_mut(|style| {
        style.spacing.item_spacing = vec2(8., 6.);
        style.spacing.button_padding = vec2(11., 6.);
        style.spacing.interact_size.y = 30.;
    });
}

fn dialog_frame() -> Frame {
    Frame::new()
        .fill(Color32::WHITE)
        .corner_radius(15)
        .inner_margin(23)
        .stroke(Stroke::new(1.0_f32, HAIRLINE))
}

fn title(text: &str, size: f32) -> RichText {
    RichText::new(text).color(INK).size(size).strong()
}

fn button(text: &str, fill: Color32, color: Color32) -> egui::Button<'_> {
    egui::Button::new(RichText::new(text).color(color).strong())
        .fill(fill)
        .corner_radius(9)
        .stroke(if fill == Color32::WHITE {
            Stroke::new(1.0_f32, HAIRLINE)
        } else {
            Stroke::NONE
        })
}

fn field(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut String,
    hint: &str,
    secret: bool,
) -> egui::Response {
    let label = ui.label(RichText::new(label).strong());
    ui.add_sized(
        [ui.available_width(), 34.],
        TextEdit::singleline(value)
            .password(secret)
            .hint_text(hint)
            .margin(Margin::symmetric(10, 8)),
    )
    .labelled_by(label.id)
}

fn chat_row(ui: &mut egui::Ui, chat: &Conversation, name: &str, active: bool) -> egui::Response {
    let time = Local
        .timestamp_millis_opt(chat.updated_ms)
        .single()
        .map(|time| {
            if time.date_naive() == Local::now().date_naive() {
                time.format("%H:%M").to_string()
            } else {
                time.format("%d %b").to_string()
            }
        })
        .unwrap_or_default();
    let date_width = 47.;
    let response = Frame::new()
        .inner_margin(Margin::symmetric(10, 0))
        .show(ui, |ui| {
            let height = 69.;
            let (rect, mut response) =
                ui.allocate_exact_size(vec2(ui.available_width(), height), Sense::click());
            response.widget_info(|| {
                egui::WidgetInfo::selected(egui::WidgetType::SelectableLabel, true, active, name)
            });
            let background = if active {
                BLUE_TINT
            } else if response.hovered() {
                Color32::from_rgb(235, 240, 246)
            } else {
                SIDEBAR
            };
            ui.painter().rect_filled(rect, 11, background);
            let mut row = ui.new_child(
                egui::UiBuilder::new()
                    .max_rect(rect.shrink2(vec2(10., 7.)))
                    .layout(Layout::left_to_right(Align::Center)),
            );
            avatar(&mut row, name, &chat.address, 40.);
            row.add_space(4.);
            row.vertical(|ui| {
                let width = ui.available_width();
                ui.set_width(width);
                ui.horizontal(|ui| {
                    let name_width = (width - date_width).max(30.);
                    ui.allocate_ui_with_layout(
                        vec2(name_width, 18.),
                        Layout::top_down(Align::Min),
                        |ui| {
                            ui.set_max_width(name_width);
                            ui.add(
                                egui::Label::new(title(name, 14.))
                                    .truncate()
                                    .selectable(false),
                            );
                        },
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(
                            RichText::new(&time)
                                .color(if active { BLUE } else { MUTED })
                                .size(11.),
                        );
                    });
                });
                ui.add(
                    egui::Label::new(
                        RichText::new(chat.preview.lines().next().unwrap_or_default())
                            .color(MUTED)
                            .size(12.),
                    )
                    .truncate()
                    .selectable(false),
                );
            });
            response = response.on_hover_cursor(egui::CursorIcon::PointingHand);
            response
        })
        .inner;
    ui.add_space(2.);
    response
}

fn avatar(ui: &mut egui::Ui, name: &str, address: &str, size: f32) {
    let (background, letters) = match address {
        "mailto:maya@example.com" => (
            Color32::from_rgb(231, 218, 250),
            Color32::from_rgb(88, 52, 143),
        ),
        "mailto:elliot@example.com" => (
            Color32::from_rgb(211, 237, 249),
            Color32::from_rgb(38, 96, 128),
        ),
        "mailto:noor@example.com" => (
            Color32::from_rgb(207, 237, 225),
            Color32::from_rgb(42, 105, 88),
        ),
        _ => (BLUE_TINT, BLUE),
    };
    let initials = name
        .split_whitespace()
        .take(2)
        .filter_map(|piece| piece.chars().next())
        .flat_map(char::to_uppercase)
        .collect::<String>();
    let (rect, _) = ui.allocate_exact_size(vec2(size, size), Sense::hover());
    let painter = ui.painter();
    painter.circle_filled(rect.center(), size * 0.5, background);
    painter.text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        initials,
        FontId::proportional(size * 0.31),
        letters,
    );
}

fn bubble(ui: &mut egui::Ui, message: &Message, demo: bool) {
    let width = ui.available_width();
    let desired_width = (width * 0.70).clamp(130., 470.);
    let color = if message.outgoing {
        Color32::WHITE
    } else {
        INK
    };
    let bg = if message.outgoing {
        BLUE
    } else {
        Color32::from_rgb(238, 241, 246)
    };
    let alignment = if message.outgoing {
        Align::Max
    } else {
        Align::Min
    };
    ui.allocate_ui_with_layout(Vec2::new(width, 0.), Layout::top_down(alignment), |ui| {
        Frame::new()
            .fill(bg)
            .corner_radius(16)
            .inner_margin(Margin::symmetric(14, 9))
            .show(ui, |ui| {
                ui.set_max_width(desired_width);
                ui.add(
                    egui::Label::new(RichText::new(&message.body).size(14.).color(color))
                        .wrap()
                        .selectable(true),
                );
            });
        let time = Local
            .timestamp_millis_opt(message.timestamp_ms)
            .single()
            .map(|time| time.format("%H:%M").to_string())
            .unwrap_or_default();
        let status = match message.status {
            Delivery::Accepted if message.outgoing && !demo => " · Accepted by Apple courier",
            Delivery::Pending => " · Sending",
            Delivery::Failed => " · Failed",
            Delivery::Unknown => " · Delivery unknown",
            _ => "",
        };
        ui.label(RichText::new(format!("{time}{status}")).size(10.).color(
            if matches!(message.status, Delivery::Failed | Delivery::Unknown) {
                DANGER
            } else {
                MUTED
            },
        ));
    });
}

fn chat_name(address: &str, demo: bool) -> String {
    if demo {
        match address {
            "mailto:maya@example.com" => return "Maya Chen".into(),
            "mailto:elliot@example.com" => return "Elliot Park".into(),
            "mailto:noor@example.com" => return "Noor Ali".into(),
            _ => {}
        }
    }
    display_address(address).to_owned()
}
