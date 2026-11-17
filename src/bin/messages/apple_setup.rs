use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc::{self, Receiver, Sender, TryRecvError},
};

use anyhow::{Context, Result, ensure};
use eframe::egui::{self, Align, Color32, Layout, Margin, RichText, TextEdit, Ui, vec2};
use linux_imessage::{
    apple::{SmsPrompts, TrustedPhone, login_device_sms},
    storage,
};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

use super::chrome::{self, BLUE, DANGER, MUTED};

const GUIDE: &str = "https://github.com/Peaks2000/linux-imessage/blob/main/docs/apple-session.md";

#[derive(Clone, Copy)]
pub(super) enum Method {
    SignIn,
    Import,
}

pub(super) enum Outcome {
    Open,
    Closed,
    Saved,
}

pub(super) struct AppleSetup {
    method: Method,
    file: String,
    helper: String,
    account: String,
    password: Zeroizing<String>,
    code: Zeroizing<String>,
    step: Step,
    error: Option<String>,
    worker: Option<Worker>,
    picker: Option<Receiver<(FileField, Result<Option<PathBuf>>)>>,
    focus_code: bool,
}

#[derive(Clone, Copy)]
enum FileField {
    Device,
    Session,
    Anisette,
}

impl FileField {
    fn label(self) -> &'static str {
        match self {
            Self::Device => "Apple device plist",
            Self::Session => "Registered session plist",
            Self::Anisette => "Anisette helper",
        }
    }
}

enum Step {
    Form,
    Working(&'static str),
    Phone {
        labels: Vec<String>,
        selected: usize,
        answer: oneshot::Sender<usize>,
    },
    Code(oneshot::Sender<Zeroizing<String>>),
    Saving,
    RetrySave(oneshot::Sender<()>),
}

struct Worker {
    events: Receiver<Event>,
    // Dropping the sender cancels an in-flight Apple request or prompt.
    _cancel: oneshot::Sender<()>,
}

enum Event {
    Phone(Vec<String>, oneshot::Sender<usize>),
    Code(oneshot::Sender<Zeroizing<String>>),
    Save(oneshot::Sender<()>),
    StorageError(anyhow::Error, oneshot::Sender<()>),
    Finished(Result<()>),
}

enum Request {
    SignIn {
        device: PathBuf,
        helper: PathBuf,
        account: String,
        password: Zeroizing<String>,
    },
    Import(PathBuf),
}

impl AppleSetup {
    pub(super) fn new(method: Method) -> Self {
        Self {
            method,
            file: String::new(),
            helper: String::new(),
            account: String::new(),
            password: Zeroizing::new(String::new()),
            code: Zeroizing::new(String::new()),
            step: Step::Form,
            error: None,
            worker: None,
            picker: None,
            focus_code: false,
        }
    }

    pub(super) fn show(&mut self, context: &egui::Context, root: &Path) -> Outcome {
        if self.poll() {
            return Outcome::Saved;
        }

        let can_cancel = !matches!(self.step, Step::Saving) && self.picker.is_none();
        let mut cancel = false;
        let mut browse = None;
        let mut submit = false;
        let dialog = match self.method {
            Method::SignIn => "apple-account-setup",
            Method::Import => "apple-session-import",
        };
        let panel = egui::Modal::new(egui::Id::new(dialog))
            .frame(chrome::sheet())
            .show(context, |ui| {
                ui.set_width(404.);
                ui.label(chrome::bold(
                    match self.method {
                        Method::SignIn => "Set Up Apple Account",
                        Method::Import => "Import Apple Session",
                    },
                    19.,
                ));
                ui.add_space(7.);
                let (label, enabled) = match &mut self.step {
                    Step::Form => {
                        let (action, ready) = self.form(ui, &mut browse);
                        (action, ready && self.picker.is_none())
                    }
                    Step::Phone {
                        labels, selected, ..
                    } => {
                        ui.label("Choose a trusted phone number where Apple can send a text.");
                        egui::ScrollArea::vertical().max_height(145.).show(ui, |ui| {
                            for (index, label) in labels.iter().enumerate() {
                                ui.radio_value(selected, index, label);
                            }
                        });
                        ("Send Code", true)
                    }
                    Step::Code(_) => {
                        ui.label("Enter the six-digit verification code Apple sent by SMS.");
                        let response = edit(ui, "Verification code", &mut self.code, "6 digits", true);
                        if self.focus_code {
                            response.request_focus();
                            self.focus_code = false;
                        }
                        let valid = code_is_valid(&self.code);
                        submit = valid && response.lost_focus()
                            && ui.input(|input| input.key_pressed(egui::Key::Enter));
                        ("Verify", valid)
                    }
                    Step::Working(message) => {
                        progress(ui, message);
                        ("Continue", false)
                    }
                    Step::Saving => {
                        progress(ui, "Saving the Apple session to Linux Secret Service…");
                        ("Continue", false)
                    }
                    Step::RetrySave(_) => {
                        ui.label("The Apple session is ready to save. Unlock your keyring if needed and try again.");
                        ("Retry Save", true)
                    }
                };
                if let Some(error) = &self.error {
                    ui.add_space(4.);
                    ui.label(RichText::new(error).size(12.).color(DANGER));
                }
                ui.add_space(7.);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if !matches!(self.step, Step::Working(_) | Step::Saving) {
                        submit |= ui.add_enabled(enabled, egui::Button::new(RichText::new(label).color(Color32::WHITE))
                            .fill(BLUE).corner_radius(5).min_size(vec2(84., 25.))).clicked();
                    }
                    cancel = ui.add_enabled(can_cancel, egui::Button::new("Cancel")
                        .min_size(vec2(65., 25.))).clicked();
                });
            });

        if can_cancel && (cancel || panel.should_close()) {
            return Outcome::Closed;
        }
        if let Some(field) = browse {
            self.picker = Some(pick_file(context, field));
        }
        if submit {
            self.submit(context, root);
        }
        Outcome::Open
    }

    fn form(&mut self, ui: &mut Ui, browse: &mut Option<FileField>) -> (&'static str, bool) {
        ui.add_enabled_ui(self.picker.is_none(), |ui| match self.method {
            Method::SignIn => {
                ui.label(RichText::new("Use an Apple device provisioning file and a trusted Anisette helper to sign in with SMS.").color(MUTED));
                ui.hyperlink_to("Apple device setup guide", GUIDE);
                file_input(ui, FileField::Device, &mut self.file, browse);
                file_input(ui, FileField::Anisette, &mut self.helper, browse);
                edit(ui, "Apple Account", &mut self.account, "Email or phone number", false);
                edit(ui, "Password", &mut self.password, "", true);
                let ready = [&self.file, &self.helper, &self.account].into_iter().all(|value| !value.trim().is_empty())
                    && !self.password.is_empty();
                ("Sign In", ready)
            }
            Method::Import => {
                ui.label(RichText::new("Choose an existing registered Apple session. The app will store it in Linux Secret Service.").color(MUTED));
                ui.hyperlink_to("Session file format", format!("{GUIDE}#import-a-registered-session"));
                file_input(ui, FileField::Session, &mut self.file, browse);
                ("Import", !self.file.trim().is_empty())
            }
        }).inner
    }

    fn submit(&mut self, context: &egui::Context, root: &Path) {
        self.error = None;
        match std::mem::replace(&mut self.step, Step::Working("Contacting Apple…")) {
            Step::Form => {
                let file = PathBuf::from(self.file.trim());
                let request = match self.method {
                    Method::SignIn => Request::SignIn {
                        device: file,
                        helper: PathBuf::from(self.helper.trim()),
                        account: self.account.trim().to_owned(),
                        password: std::mem::take(&mut self.password),
                    },
                    Method::Import => Request::Import(file),
                };
                self.step = Step::Working(match self.method {
                    Method::SignIn => "Signing in to Apple…",
                    Method::Import => "Validating the Apple session…",
                });
                self.worker = Some(Worker::start(context, root.to_owned(), request));
            }
            Step::Phone {
                answer, selected, ..
            } => {
                self.step = Step::Working("Requesting a verification code…");
                let _ = answer.send(selected);
            }
            Step::Code(answer) => {
                self.step = Step::Working("Verifying the code and registering the device…");
                let _ = answer.send(std::mem::take(&mut self.code));
            }
            Step::RetrySave(answer) => {
                self.step = Step::Saving;
                let _ = answer.send(());
            }
            other => self.step = other,
        }
    }

    fn poll(&mut self) -> bool {
        if let Some(picker) = &self.picker {
            match picker.try_recv() {
                Ok((field, result)) => {
                    self.picker = None;
                    match result {
                        Ok(Some(path)) => {
                            let target = match field {
                                FileField::Device | FileField::Session => &mut self.file,
                                FileField::Anisette => &mut self.helper,
                            };
                            *target = path.to_string_lossy().into_owned();
                            self.error = None;
                        }
                        Ok(None) => {}
                        Err(error) => self.error = Some(error.to_string()),
                    }
                }
                Err(TryRecvError::Disconnected) => self.picker = None,
                Err(TryRecvError::Empty) => {}
            }
        }
        let Some(worker) = &self.worker else {
            return false;
        };
        match worker.events.try_recv() {
            Ok(Event::Phone(labels, answer)) => {
                self.step = Step::Phone {
                    labels,
                    selected: 0,
                    answer,
                }
            }
            Ok(Event::Code(answer)) => {
                self.focus_code = true;
                self.step = Step::Code(answer);
            }
            Ok(Event::Save(ready)) => {
                self.step = Step::Saving;
                let _ = ready.send(());
            }
            Ok(Event::StorageError(error, answer)) => {
                self.step = Step::RetrySave(answer);
                self.error = Some(format!("{error:#}"));
            }
            Ok(Event::Finished(Ok(()))) => return true,
            Ok(Event::Finished(Err(error))) => self.fail(format!("{error:#}")),
            Err(TryRecvError::Disconnected) => {
                self.fail("Apple account setup stopped unexpectedly".into())
            }
            Err(TryRecvError::Empty) => {}
        }
        false
    }

    fn fail(&mut self, error: String) {
        self.worker = None;
        self.step = Step::Form;
        self.error = Some(error);
    }
}

impl Worker {
    fn start(context: &egui::Context, root: PathBuf, request: Request) -> Self {
        let (send, events) = mpsc::channel();
        let (cancel, canceled) = oneshot::channel();
        let context = context.clone();
        std::thread::spawn(move || {
            let prompts = GuiPrompts { send, context };
            let result = run(&root, request, &prompts, canceled);
            let _ = prompts.emit(Event::Finished(result));
        });
        Self {
            events,
            _cancel: cancel,
        }
    }
}

fn run(
    root: &Path,
    request: Request,
    prompts: &GuiPrompts,
    mut canceled: oneshot::Receiver<()>,
) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let session = runtime.block_on(async {
        tokio::select! {
            biased;
            _ = &mut canceled => anyhow::bail!("Apple account setup canceled"),
            result = get_session(request, prompts, root) => result,
        }
    })?;
    let (permit, mut confirmed) = oneshot::channel();
    prompts.emit(Event::Save(permit))?;
    loop {
        runtime.block_on(async {
            tokio::select! {
                biased;
                _ = &mut canceled => anyhow::bail!("Apple account setup canceled"),
                result = &mut confirmed => result.context("Apple account setup canceled"),
            }
        })?;
        match storage::save_session(root, &session, None) {
            Ok(()) => return Ok(()),
            Err(error) => {
                let (retry, confirmation) = oneshot::channel();
                confirmed = confirmation;
                prompts.emit(Event::StorageError(error, retry))?;
            }
        }
    }
}

async fn get_session(
    request: Request,
    prompts: &GuiPrompts,
    root: &Path,
) -> Result<Zeroizing<Vec<u8>>> {
    match request {
        Request::Import(file) => {
            let bytes = storage::read_private(&file)?;
            linux_imessage::apple::Identity::parse(&bytes).context("Invalid Apple session")?;
            storage::check_desktop_session_storage(root)?;
            Ok(bytes)
        }
        Request::SignIn {
            device,
            helper,
            account,
            password,
        } => {
            let plist = storage::read_private(&device)?;
            storage::check_desktop_session_storage(root)?;
            login_device_sms(&plist, &helper, &account, password, &mut prompts.clone()).await
        }
    }
}

#[derive(Clone)]
struct GuiPrompts {
    send: Sender<Event>,
    context: egui::Context,
}

impl GuiPrompts {
    fn emit(&self, event: Event) -> Result<()> {
        self.send
            .send(event)
            .map_err(|_| anyhow::anyhow!("Apple account setup canceled"))?;
        self.context.request_repaint();
        Ok(())
    }
}

impl SmsPrompts for GuiPrompts {
    async fn choose_phone(&mut self, phones: &[TrustedPhone]) -> Result<usize> {
        let (answer, selected) = oneshot::channel();
        let labels = phones
            .iter()
            .enumerate()
            .map(|(index, phone)| {
                if phone.last_two_digits.is_empty() {
                    format!("Trusted number {}", index + 1)
                } else {
                    format!("Number {} ending in {}", index + 1, phone.last_two_digits)
                }
            })
            .collect();
        self.emit(Event::Phone(labels, answer))?;
        selected.await.context("Apple account setup canceled")
    }

    async fn read_code(&mut self) -> Result<Zeroizing<String>> {
        let (answer, code) = oneshot::channel();
        self.emit(Event::Code(answer))?;
        code.await.context("Apple account setup canceled")
    }
}

fn progress(ui: &mut Ui, message: &str) {
    ui.horizontal(|ui| {
        ui.spinner();
        ui.label(message);
    });
}

fn code_is_valid(code: &str) -> bool {
    let code = code.trim();
    code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit())
}

fn edit(ui: &mut Ui, title: &str, field: &mut String, hint: &str, secret: bool) -> egui::Response {
    let label = ui.label(chrome::bold(title, 11.));
    let mut output = TextEdit::singleline(field)
        .id_salt(title)
        .password(secret)
        .hint_text(hint)
        .desired_width(ui.available_width())
        .margin(Margin::symmetric(7, 5))
        .show(ui);
    if secret {
        output.state.clear_undoer();
        output.state.store(ui.ctx(), output.response.id);
    }
    output.response.labelled_by(label.id)
}

fn file_input(ui: &mut Ui, field: FileField, path: &mut String, browse: &mut Option<FileField>) {
    let label = ui.label(chrome::bold(field.label(), 11.));
    ui.horizontal(|ui| {
        ui.add(
            TextEdit::singleline(path)
                .hint_text("/path/to/file")
                .desired_width(ui.available_width() - 78.)
                .margin(Margin::symmetric(7, 5)),
        )
        .labelled_by(label.id);
        if ui.button("Browse…").clicked() {
            *browse = Some(field);
        }
    });
}

fn pick_file(
    context: &egui::Context,
    field: FileField,
) -> Receiver<(FileField, Result<Option<PathBuf>>)> {
    let (send, receive) = mpsc::channel();
    let context = context.clone();
    std::thread::spawn(move || {
        let _ = send.send((field, run_file_picker(field)));
        context.request_repaint();
    });
    receive
}

fn run_file_picker(field: FileField) -> Result<Option<PathBuf>> {
    let mut child = Command::new("zenity")
        .arg("--file-selection")
        .arg("--title")
        .arg(format!("Choose {}", field.label()))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("The file picker is unavailable. Enter the file path in the field")?;
    let mut output = String::new();
    child
        .stdout
        .take()
        .context("The file picker did not return a selection")?
        .take(16385)
        .read_to_string(&mut output)?;
    if output.len() > 16384 {
        let _ = child.kill();
        let _ = child.wait();
        anyhow::bail!("The file picker returned an oversized path");
    }
    let status = child.wait()?;
    if status.code() == Some(1) {
        return Ok(None);
    }
    ensure!(status.success(), "The file picker could not open that file");
    let path = output.strip_suffix('\n').unwrap_or(&output);
    ensure!(!path.is_empty(), "The file picker returned an empty path");
    Ok(Some(PathBuf::from(path)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn desktop_passes_the_sms_code_without_dropping_leading_zeroes() -> Result<()> {
        let (send, events) = mpsc::channel();
        let mut prompts = GuiPrompts {
            send,
            context: egui::Context::default(),
        };
        let (_cancel, _canceled) = oneshot::channel();
        let mut setup = AppleSetup::new(Method::SignIn);
        setup.worker = Some(Worker { events, _cancel });
        let receive_code = prompts.read_code();
        tokio::pin!(receive_code);
        tokio::select! {
            biased;
            _ = &mut receive_code => panic!("The code prompt completed before input"),
            _ = std::future::ready(()) => {}
        }

        assert!(!setup.poll());
        assert!(matches!(setup.step, Step::Code(_)) && setup.focus_code);
        setup.code.push_str("000123");
        assert!(code_is_valid(&setup.code));
        setup.submit(&egui::Context::default(), Path::new("."));
        assert_eq!(receive_code.await?.as_str(), "000123");
        assert!(setup.code.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn closing_desktop_setup_releases_the_pending_code_prompt() {
        let (send, events) = mpsc::channel();
        let mut prompts = GuiPrompts {
            send,
            context: egui::Context::default(),
        };
        let (cancel, _) = oneshot::channel();
        let mut setup = AppleSetup::new(Method::SignIn);
        setup.worker = Some(Worker {
            events,
            _cancel: cancel,
        });
        let receive_code = prompts.read_code();
        tokio::pin!(receive_code);
        tokio::select! {
            biased;
            _ = &mut receive_code => panic!("The code prompt completed before input"),
            _ = std::future::ready(()) => {}
        }
        assert!(!setup.poll());
        assert!(matches!(setup.step, Step::Code(_)));
        drop(setup);
        assert!(receive_code.await.is_err());
    }
}
