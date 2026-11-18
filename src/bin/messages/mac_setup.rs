use std::{
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver, Sender, TryRecvError},
};

use anyhow::{Context, Result};
use eframe::egui::{self, Align, Color32, Layout, Margin, RichText, TextEdit, Ui, vec2};
use linux_imessage::{
    apple::{
        self, AutomaticSetup, DeviceConnection, IcloudContactsGrant, Identity, SmsPrompts,
        SshPrompt, TrustedDeviceResponse, TrustedPhone,
    },
    storage,
};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

use super::chrome::{self, BLUE, DANGER, MUTED};

pub(super) enum Outcome {
    Open,
    Closed,
    Saved,
    ContactsAuthorized,
}

pub(super) struct MacSetup {
    purpose: Purpose,
    device_helper: Option<PathBuf>,
    account_seeded: bool,
    remembered: Option<String>,
    remember_password: bool,
    host: String,
    mac_password: Zeroizing<String>,
    account: String,
    password: Zeroizing<String>,
    code: Zeroizing<String>,
    ssh_answer: Zeroizing<String>,
    step: Step,
    error: Option<String>,
    worker: Option<Worker>,
    focus_code: bool,
    focus_ssh: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Purpose {
    Messages,
    FaceTime,
    Contacts,
}

enum Step {
    Form,
    Working(&'static str),
    Phone {
        labels: Vec<String>,
        selected: usize,
        answer: oneshot::Sender<usize>,
    },
    Code(CodePrompt),
    Ssh(SshPrompt, oneshot::Sender<Zeroizing<String>>),
    Saving,
    RetrySave(oneshot::Sender<()>),
}

enum CodePrompt {
    Sms(oneshot::Sender<Zeroizing<String>>),
    TrustedDevice(oneshot::Sender<TrustedDeviceResponse>),
}

struct Worker {
    events: Receiver<Event>,
    // Dropping the sender cancels an in-flight Apple request or prompt.
    _cancel: oneshot::Sender<()>,
}

enum Event {
    Phone(Vec<String>, oneshot::Sender<usize>),
    Code(CodePrompt),
    Ssh(SshPrompt, oneshot::Sender<Zeroizing<String>>),
    Save(oneshot::Sender<()>),
    StorageError(anyhow::Error, oneshot::Sender<()>),
    Finished(Result<()>),
}

struct Request {
    purpose: Purpose,
    setup: Option<AutomaticSetup>,
    account: String,
    password: Zeroizing<String>,
    mac_password: Zeroizing<String>,
    remember_password: bool,
}

impl MacSetup {
    pub(super) fn new() -> Self {
        Self {
            purpose: Purpose::Messages,
            device_helper: None,
            account_seeded: false,
            remembered: None,
            remember_password: true,
            host: std::env::var("IMESSAGE_MAC_HOST").unwrap_or_default(),
            mac_password: Zeroizing::default(),
            account: String::new(),
            password: Zeroizing::default(),
            code: Zeroizing::default(),
            ssh_answer: Zeroizing::default(),
            step: Step::Form,
            error: None,
            worker: None,
            focus_code: false,
            focus_ssh: false,
        }
    }

    pub(super) fn for_contacts(account: &str, password_saved: bool) -> Self {
        let mut setup = Self::new();
        setup.purpose = Purpose::Contacts;
        setup.seed_account(account, password_saved);
        setup
    }

    pub(super) fn for_facetime(root: &Path) -> Self {
        let mut setup = Self::new();
        setup.purpose = Purpose::FaceTime;
        setup.device_helper = apple::default_device_helper(root);
        setup
    }

    pub(super) fn seed_account(&mut self, account: &str, password_saved: bool) {
        if self.account_seeded {
            return;
        }
        self.account_seeded = true;
        if self.account.is_empty() {
            self.account = account.to_owned();
        }
        self.remembered = password_saved.then(|| account.to_owned());
    }

    pub(super) fn show(&mut self, context: &egui::Context, root: &Path) -> Outcome {
        if self.poll() {
            return if self.purpose == Purpose::Contacts {
                Outcome::ContactsAuthorized
            } else {
                Outcome::Saved
            };
        }

        let can_cancel = !matches!(self.step, Step::Saving);
        let mut cancel = false;
        let mut submit = false;
        let mut use_sms = false;
        let panel = egui::Modal::new(egui::Id::new("mac-apple-setup"))
            .frame(chrome::sheet())
            .show(context, |ui| {
                ui.set_width(404.);
                let title = match self.purpose {
                    Purpose::Messages => "Set Up with a Mac",
                    Purpose::FaceTime => "Enable FaceTime",
                    Purpose::Contacts => "Authorize iCloud Contacts",
                };
                ui.label(chrome::bold(title, 19.));
                ui.add_space(7.);
                let (label, enabled) = match &mut self.step {
                    Step::Form => {
                        let height = (context.content_rect().height() - 120.).max(100.);
                        egui::ScrollArea::vertical().auto_shrink([false, true]).max_height(height)
                            .show(ui, |ui| self.form(ui)).inner
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
                    Step::Code(prompt) => {
                        ui.label(match prompt {
                            CodePrompt::Sms(_) => "Enter the six-digit verification code Apple sent by SMS.",
                            CodePrompt::TrustedDevice(_) => "Tap Allow on your trusted Apple device, then enter the six-digit code it shows.",
                        });
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
                    Step::Ssh(SshPrompt::VerifyHost { host, fingerprint }, _) => {
                        ui.label(format!("Verify this Mac's SSH fingerprint for {host}."));
                        ui.label(RichText::new(fingerprint.as_str()).monospace().size(12.));
                        ui.label(RichText::new("On the Mac, use ssh-keygen -lf with the matching public host key in /etc/ssh.").color(MUTED));
                        ("Trust Mac", true)
                    }
                    Step::Ssh(SshPrompt::Login { host, message }, _) => {
                        ui.label(format!("SSH sign-in for {host}"));
                        if !message.trim().is_empty() {
                            ui.label(RichText::new(message.as_str()).size(11.).color(MUTED));
                        }
                        let response = edit(ui, "Mac login password or SSH passphrase", &mut self.ssh_answer, "", true);
                        if self.focus_ssh {
                            response.request_focus();
                            self.focus_ssh = false;
                        }
                        let valid = (1..=1023).contains(&self.ssh_answer.len());
                        submit = valid && response.lost_focus()
                            && ui.input(|input| input.key_pressed(egui::Key::Enter));
                        ("Sign In to Mac", valid)
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
                    if matches!(self.step, Step::Code(CodePrompt::TrustedDevice(_))) {
                        use_sms = ui.button("Use SMS").clicked();
                    }
                });
            });

        if can_cancel && (cancel || panel.should_close()) {
            return Outcome::Closed;
        }
        if submit || use_sms {
            self.submit(context, root, use_sms);
        }
        Outcome::Open
    }

    fn form(&mut self, ui: &mut Ui) -> (&'static str, bool) {
        if self.purpose == Purpose::Contacts {
            ui.label(
                RichText::new("Sign in with the Apple Account you use for iCloud.").color(MUTED),
            );
        } else if self.device_helper.is_none() {
            ui.label(
                RichText::new(
                    "Enable Remote Login on your Mac. iMessage installs its setup helper over SSH.",
                )
                .color(MUTED),
            );
            edit(
                ui,
                "Mac SSH address",
                &mut self.host,
                "user@mac.local",
                false,
            );
            edit(
                ui,
                "Mac login password",
                &mut self.mac_password,
                "Optional if you use an SSH key",
                true,
            );
            ui.add_space(5.);
        } else {
            ui.label(
                RichText::new("Register FaceTime using the local device helper.").color(MUTED),
            );
        }
        edit(
            ui,
            "Apple Account",
            &mut self.account,
            "Email or phone number",
            false,
        );
        let saved = self
            .remembered
            .as_deref()
            .is_some_and(|account| account.eq_ignore_ascii_case(self.account.trim()));
        let hint = if saved { "Use saved password" } else { "" };
        edit(ui, "Apple Account password", &mut self.password, hint, true);
        ui.checkbox(
            &mut self.remember_password,
            "Remember Apple Account password",
        );
        let mac_ready = !self.host.trim().is_empty() && self.mac_password.len() <= 1023;
        let ready =
            (self.purpose == Purpose::Contacts || self.device_helper.is_some() || mac_ready)
                && !self.account.trim().is_empty()
                && (saved || !self.password.is_empty());
        (
            match self.purpose {
                Purpose::Messages => "Connect",
                Purpose::FaceTime => "Enable FaceTime",
                Purpose::Contacts => "Authorize",
            },
            ready,
        )
    }

    fn submit(&mut self, context: &egui::Context, root: &Path, use_sms: bool) {
        self.error = None;
        match std::mem::replace(&mut self.step, Step::Working("Contacting Apple…")) {
            Step::Form => {
                let request = Request {
                    purpose: self.purpose,
                    setup: (self.purpose != Purpose::Contacts).then(|| AutomaticSetup {
                        connection: match &self.device_helper {
                            Some(path) => DeviceConnection::OnDeviceHelper(path.clone()),
                            None => DeviceConnection::MacOverSsh(self.host.trim().to_owned()),
                        },
                        opencore_config: None,
                        address: String::new(),
                    }),
                    account: self.account.trim().to_owned(),
                    password: std::mem::take(&mut self.password),
                    mac_password: std::mem::take(&mut self.mac_password),
                    remember_password: self.remember_password,
                };
                if self.purpose != Purpose::Contacts && self.device_helper.is_none() {
                    self.step = Step::Working("Connecting to the Mac…");
                }
                self.worker = Some(Worker::start(context, root.to_owned(), request));
            }
            Step::Phone {
                answer, selected, ..
            } => {
                self.step = Step::Working("Requesting a verification code…");
                let _ = answer.send(selected);
            }
            Step::Code(CodePrompt::Sms(answer)) => {
                self.step = Step::Working("Verifying the code…");
                let _ = answer.send(std::mem::take(&mut self.code));
            }
            Step::Code(CodePrompt::TrustedDevice(answer)) => {
                let code = std::mem::take(&mut self.code);
                let response = if use_sms {
                    self.step = Step::Working("Requesting an SMS code…");
                    TrustedDeviceResponse::UseSms
                } else {
                    self.step = Step::Working("Verifying the code…");
                    TrustedDeviceResponse::Code(code)
                };
                let _ = answer.send(response);
            }
            Step::Ssh(prompt, answer) => {
                let value = match prompt {
                    SshPrompt::VerifyHost { .. } => Zeroizing::new("yes".to_owned()),
                    SshPrompt::Login { .. } => std::mem::take(&mut self.ssh_answer),
                };
                self.step = Step::Working("Connecting to the Mac…");
                let _ = answer.send(value);
            }
            Step::RetrySave(answer) => {
                self.step = Step::Saving;
                let _ = answer.send(());
            }
            other => self.step = other,
        }
    }

    fn poll(&mut self) -> bool {
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
            Ok(Event::Ssh(prompt, answer)) => {
                self.ssh_answer = Zeroizing::default();
                self.focus_ssh = true;
                self.step = Step::Ssh(prompt, answer);
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
        self.ssh_answer = Zeroizing::default();
        self.step = Step::Form;
        self.error = Some(error);
    }
}

impl Worker {
    fn start(context: &egui::Context, root: PathBuf, mut request: Request) -> Self {
        let (send, events) = mpsc::channel();
        let (cancel, canceled) = oneshot::channel();
        let context = context.clone();
        std::thread::spawn(move || {
            let mut prompts = GuiPrompts {
                send,
                context,
                mac_password: std::mem::take(&mut request.mac_password),
                contacts_grant: None,
            };
            let result = run(&root, request, &mut prompts, canceled);
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
    prompts: &mut GuiPrompts,
    mut canceled: oneshot::Receiver<()>,
) -> Result<()> {
    let Request {
        purpose,
        setup,
        account,
        mut password,
        remember_password,
        ..
    } = request;
    let account = account.as_str();
    storage::check_desktop_session_storage(root)?;
    let current = if purpose != Purpose::Messages || password.is_empty() {
        storage::load_local_session(root)?
    } else {
        None
    };
    if password.is_empty() {
        let identity = current
            .as_ref()
            .context("Enter your Apple Account password")?;
        password = storage::load_apple_account(root, identity)?
            .filter(|saved| {
                saved.account.eq_ignore_ascii_case(account) && !saved.password.is_empty()
            })
            .context("Enter your Apple Account password")?
            .password;
    }
    let remembered = if remember_password {
        password.clone()
    } else {
        Zeroizing::default()
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (session, identity, contacts) = runtime.block_on(async {
        tokio::select! {
            biased;
            _ = &mut canceled => anyhow::bail!("Apple account setup canceled"),
            result = async {
                if let Some(setup) = setup {
                    let session = if purpose == Purpose::FaceTime {
                        let identity = current.as_ref().context("Sign in to iMessage to enable FaceTime")?;
                        setup.enable_facetime(root, identity, account, password, prompts).await?
                    } else {
                        setup.sign_in(root, account, password, prompts).await?
                    };
                    let identity = Identity::parse(&session)?;
                    Ok((Some(session), Some(identity), prompts.contacts_grant.take()))
                } else {
                    let identity = current.as_ref().context("Sign in to iMessage to authorize Contacts")?;
                    let contacts = apple::authorize_icloud_contacts(root, identity, account, password, prompts).await?;
                    Ok((None, None, Some(contacts)))
                }
            } => result,
        }
    })?;
    let identity = identity
        .as_ref()
        .or(current.as_ref())
        .context("Missing Apple session")?;
    let mut saved = storage::SavedAppleAccount {
        account: account.to_owned(),
        password: remembered,
        contacts,
    };
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
        let result = (|| {
            if saved.contacts.is_none()
                && let Some(previous) = storage::load_apple_account(root, identity)?
                && previous.account.eq_ignore_ascii_case(account)
            {
                saved.contacts = previous.contacts;
            }
            storage::save_apple_account(root, identity, &saved)?;
            if let Some(session) = &session {
                if purpose == Purpose::FaceTime {
                    let previous = current
                        .as_ref()
                        .context("Missing saved iMessage identity")?;
                    storage::save_facetime_upgrade(root, previous, session)?;
                } else {
                    storage::save_session(root, session, None)?;
                }
            }
            Ok(())
        })();
        match result {
            Ok(()) => return Ok(()),
            Err(error) => {
                let (retry, confirmation) = oneshot::channel();
                confirmed = confirmation;
                prompts.emit(Event::StorageError(error, retry))?;
            }
        }
    }
}

struct GuiPrompts {
    send: Sender<Event>,
    context: egui::Context,
    mac_password: Zeroizing<String>,
    contacts_grant: Option<IcloudContactsGrant>,
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
    fn request_icloud_contacts(&self) -> bool {
        true
    }

    fn received_icloud_contacts(&mut self, grant: Result<IcloudContactsGrant>) {
        self.contacts_grant = grant.ok();
    }

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
        self.emit(Event::Code(CodePrompt::Sms(answer)))?;
        code.await.context("Apple account setup canceled")
    }

    async fn read_trusted_device_code(&mut self) -> Result<TrustedDeviceResponse> {
        let (answer, code) = oneshot::channel();
        self.emit(Event::Code(CodePrompt::TrustedDevice(answer)))?;
        code.await.context("Apple account setup canceled")
    }

    fn prefers_ssh_password(&self) -> bool {
        !self.mac_password.is_empty()
    }

    async fn ssh_prompt(&mut self, prompt: SshPrompt) -> Result<Zeroizing<String>> {
        if let SshPrompt::Login { message, .. } = &prompt
            && is_password_prompt(message)
            && !self.mac_password.is_empty()
        {
            return Ok(std::mem::take(&mut self.mac_password));
        }
        let (answer, response) = oneshot::channel();
        self.emit(Event::Ssh(prompt, answer))?;
        response.await.context("Mac sign-in canceled")
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

fn is_password_prompt(message: &str) -> bool {
    let message = message.trim().to_ascii_lowercase();
    message == "password:"
        || message.ends_with("'s password:")
        || (message.starts_with("password for ") && message.ends_with(':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mac_password_skips_one_ssh_password_prompt_and_then_clears() -> Result<()> {
        let (send, events) = mpsc::channel();
        let mut prompts = GuiPrompts {
            send,
            context: egui::Context::default(),
            mac_password: Zeroizing::new("fixture mac password".to_owned()),
            contacts_grant: None,
        };
        let host = "fixture@mac.local".to_owned();
        let message = format!("{host}'s password:");
        let answer = prompts
            .ssh_prompt(SshPrompt::Login {
                host: host.clone(),
                message: message.clone(),
            })
            .await?;
        assert_eq!(answer.as_str(), "fixture mac password");
        assert!(!prompts.prefers_ssh_password());

        let retry = prompts.ssh_prompt(SshPrompt::Login { host, message });
        tokio::pin!(retry);
        tokio::select! {
            biased;
            _ = &mut retry => panic!("Should ask again after the first password was consumed"),
            _ = std::future::ready(()) => (),
        }
        let Event::Ssh(_, reply) = events.try_recv()? else {
            panic!("Expected a fresh SSH prompt");
        };
        reply
            .send(Zeroizing::new("corrected password".into()))
            .unwrap();
        assert_eq!(retry.await?.as_str(), "corrected password");
        assert!(!is_password_prompt(
            "Enter passphrase for key '/home/test/.ssh/id_ed25519':"
        ));
        assert!(!is_password_prompt(
            "Are you sure you want to continue connecting?"
        ));
        Ok(())
    }
}
