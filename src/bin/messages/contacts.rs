use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::mpsc::{Receiver, TryRecvError},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use eframe::egui::{self, Align, Color32, Layout, RichText, TextEdit, vec2};
use linux_imessage::{display_address, storage};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{
    attachments::task,
    carddav::{self, Recipient},
    chrome::{self, BLUE, DANGER, MUTED},
};

const CACHE: &str = "icloud-contacts.json";
const CACHE_LIMIT: u64 = 8 * 1024 * 1024;
const INTERVAL: Duration = Duration::from_secs(30 * 60);
const HELP: &str = "https://support.apple.com/en-us/102654";

#[derive(Clone, Deserialize, Serialize)]
struct Snapshot {
    account: String,
    recipients: Vec<Recipient>,
    #[serde(default)]
    profile: Option<String>,
}

pub(super) struct AppleAccountHint {
    pub account: String,
    pub password_saved: bool,
    authorized: bool,
}

struct Update {
    apple: Option<AppleAccountHint>,
    snapshot: Option<Snapshot>,
    error: Option<String>,
}

#[derive(Default)]
struct Form {
    account: String,
    password: Zeroizing<String>,
}

enum Operation {
    Refresh,
    Connect(Form),
    Disconnect,
}

pub(super) struct Contacts {
    root: PathBuf,
    snapshot: Option<Snapshot>,
    names: HashMap<String, String>,
    next_sync: Instant,
    pending: Option<Receiver<Result<Update>>>,
    refresh_queued: bool,
    apple: Option<AppleAccountHint>,
    form: Option<Form>,
    error: Option<String>,
}

impl Contacts {
    pub fn new(root: &Path) -> Self {
        let (snapshot, error) = match read_cache(root) {
            Ok(snapshot) => (snapshot, None),
            Err(error) => (None, Some(error.to_string())),
        };
        let mut contacts = Self {
            root: root.to_owned(),
            snapshot: None,
            names: HashMap::new(),
            next_sync: Instant::now(),
            pending: None,
            refresh_queued: true,
            apple: None,
            form: None,
            error,
        };
        contacts.set_snapshot(snapshot.filter(|cache| cache.profile.is_none()));
        contacts
    }

    fn set_snapshot(&mut self, snapshot: Option<Snapshot>) {
        self.names.clear();
        if let Some(snapshot) = &snapshot {
            for recipient in &snapshot.recipients {
                self.names
                    .entry(recipient.address.clone())
                    .or_insert_with(|| recipient.name.clone());
            }
        }
        self.snapshot = snapshot;
    }

    pub fn name<'a>(&'a self, address: &'a str) -> &'a str {
        self.names
            .get(address)
            .map_or_else(|| display_address(address), String::as_str)
    }

    pub fn matches(&self, query: &str) -> impl Iterator<Item = &Recipient> {
        let query = query.trim().to_lowercase();
        self.snapshot
            .iter()
            .flat_map(|data| &data.recipients)
            .filter(move |recipient| {
                !query.is_empty()
                    && (recipient.name.to_lowercase().contains(&query)
                        || display_address(&recipient.address).contains(&query))
            })
            .take(8)
    }

    pub fn resolve_name(&self, input: &str) -> Option<String> {
        let input = input.trim().to_lowercase();
        let mut matches = self
            .snapshot
            .as_ref()?
            .recipients
            .iter()
            .filter(|contact| contact.name.to_lowercase() == input);
        let first = matches.next()?;
        matches
            .all(|contact| contact.address == first.address)
            .then(|| first.address.clone())
    }

    pub fn poll(&mut self, ctx: &egui::Context) {
        if let Some(job) = &self.pending {
            let result = match job.try_recv() {
                Ok(result) => result,
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => {
                    Err(anyhow::anyhow!("iCloud Contacts sync stopped"))
                }
            };
            self.pending = None;
            self.next_sync = Instant::now() + INTERVAL;
            match result {
                Ok(update) => {
                    self.error = update.error;
                    self.apple = update.apple;
                    self.set_snapshot(update.snapshot);
                    if let Some(form) = &mut self.form
                        && form.account.is_empty()
                        && let Some(snapshot) = &self.snapshot
                    {
                        form.account = snapshot.account.clone();
                    }
                }
                Err(error) => self.error = Some(format!("{error:#}")),
            }
        }
        if self.refresh_queued {
            self.refresh_queued = false;
            self.start(ctx, Operation::Refresh);
        } else if self.snapshot.is_some()
            || self.apple.as_ref().is_some_and(|apple| apple.authorized)
        {
            let wait = self.next_sync.saturating_duration_since(Instant::now());
            if wait.is_zero() {
                self.start(ctx, Operation::Refresh);
            } else {
                ctx.request_repaint_after(wait);
            }
        }
    }

    pub(super) fn refresh_now(&mut self, ctx: &egui::Context) {
        self.refresh_queued = true;
        ctx.request_repaint();
    }

    pub(super) fn apple_account(&self) -> Option<&AppleAccountHint> {
        self.apple.as_ref()
    }

    fn start(&mut self, ctx: &egui::Context, operation: Operation) {
        self.error = None;
        let root = self.root.clone();
        self.pending = Some(task(ctx, move || run(&root, operation)));
    }

    pub fn open(&mut self) {
        self.form = Some(Form {
            account: self
                .snapshot
                .as_ref()
                .map_or_else(String::new, |data| data.account.clone()),
            ..Default::default()
        });
    }

    pub fn is_open(&self) -> bool {
        self.form.is_some()
    }

    pub fn show(&mut self, ctx: &egui::Context) -> bool {
        let Some(form) = &mut self.form else {
            return false;
        };
        let mut authorize = false;
        let busy = self.pending.is_some();
        let mut operation = None;
        let dialog = egui::Modal::new(egui::Id::new("icloud-contacts"))
            .frame(chrome::sheet())
            .show(ctx, |ui| {
                ui.set_width(375.);
                ui.label(chrome::bold("iCloud Contacts", 19.));
                ui.label(
                    RichText::new(
                        "Sync names, email addresses, and phone numbers directly from iCloud.",
                    )
                    .color(MUTED),
                );
                if let Some(apple) = &self.apple {
                    ui.label(chrome::bold("Apple Account", 11.));
                    ui.label(&apple.account);
                } else if !busy || self.snapshot.is_some() {
                    let account = ui.label(chrome::bold("Apple Account", 11.));
                    ui.add_enabled(
                        !busy,
                        TextEdit::singleline(&mut form.account)
                            .hint_text("Email or phone number")
                            .desired_width(f32::INFINITY),
                    )
                    .labelled_by(account.id);
                    let password = ui.label(chrome::bold("App-specific password", 11.));
                    ui.add_enabled(
                        !busy,
                        TextEdit::singleline(&mut *form.password)
                            .password(true)
                            .hint_text("App-specific password from Apple")
                            .desired_width(f32::INFINITY),
                    )
                    .labelled_by(password.id);
                    ui.hyperlink_to("Create an app-specific password", HELP);
                }
                if let Some(snapshot) = &self.snapshot {
                    ui.label(
                        RichText::new(format!(
                            "{} contact addresses on this computer",
                            snapshot.recipients.len()
                        ))
                        .color(MUTED),
                    );
                }
                if busy {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Updating Contacts…");
                    });
                }
                if let Some(error) = &self.error {
                    ui.label(RichText::new(error).color(DANGER));
                }
                if let Some(apple) = &self.apple
                    && ((!apple.authorized && self.snapshot.is_some())
                        || (apple.authorized && self.error.is_some()))
                {
                    let label = if apple.authorized {
                        "Authorize Again…"
                    } else {
                        "Authorize Contacts…"
                    };
                    authorize = ui.add_enabled(!busy, egui::Button::new(label)).clicked();
                }
                ui.add_space(5.);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let done = ui.button("Done").clicked();
                    if let Some(apple) = &self.apple {
                        let label = if apple.authorized || self.snapshot.is_some() {
                            "Sync Contacts"
                        } else {
                            "Authorize Contacts…"
                        };
                        if ui.add_enabled(!busy, primary(label)).clicked() {
                            if apple.authorized || self.snapshot.is_some() {
                                operation = Some(Operation::Refresh);
                            } else {
                                authorize = true;
                            }
                        }
                    } else {
                        let has_password = !form.password.trim().is_empty();
                        let use_saved = !has_password
                            && self.snapshot.as_ref().is_some_and(|data| {
                                form.account.trim().eq_ignore_ascii_case(&data.account)
                            });
                        if ui
                            .add_enabled(
                                !busy
                                    && (use_saved
                                        || (has_password && !form.account.trim().is_empty())),
                                primary("Sync Contacts"),
                            )
                            .clicked()
                        {
                            operation = Some(if use_saved {
                                Operation::Refresh
                            } else {
                                Operation::Connect(Form {
                                    account: form.account.trim().to_owned(),
                                    password: std::mem::take(&mut form.password),
                                })
                            });
                        }
                    }
                    let connected = self.snapshot.is_some()
                        || self.apple.as_ref().is_some_and(|apple| apple.authorized);
                    if connected
                        && ui
                            .add_enabled(!busy, egui::Button::new("Disconnect"))
                            .clicked()
                    {
                        operation = Some(Operation::Disconnect);
                    }
                    done
                })
                .inner
            });
        if let Some(operation) = operation {
            self.start(ctx, operation);
        } else if dialog.inner || dialog.should_close() {
            self.form = None;
        }
        authorize
    }
}

fn primary(label: &str) -> egui::Button<'_> {
    egui::Button::new(RichText::new(label).color(Color32::WHITE))
        .fill(BLUE)
        .corner_radius(5)
        .min_size(vec2(98., 25.))
}

fn read_cache(root: &Path) -> Result<Option<Snapshot>> {
    let path = root.join(CACHE);
    if !path.try_exists()? {
        return Ok(None);
    }
    serde_json::from_slice(&storage::read_private_limited(&path, CACHE_LIMIT)?)
        .context("Could not read the local iCloud Contacts cache")
}

fn password_key(root: &Path, account: &str) -> String {
    format!("icloud-contacts:{}:{account}", root.display())
}

fn run(root: &Path, operation: Operation) -> Result<Update> {
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(root.join("icloud-contacts.lock"))?;
    fs2::FileExt::try_lock_exclusive(&lock)
        .context("iCloud Contacts is being updated in another window")?;
    let identity = if root.join("apple-session.enc").exists() {
        None
    } else {
        storage::load_local_session(root)?
    };
    let mut saved = identity
        .as_ref()
        .map(|identity| storage::load_apple_account(root, identity))
        .transpose()?
        .flatten();
    let mut apple = identity.as_ref().map(|identity| AppleAccountHint {
        account: saved.as_ref().map_or_else(
            || display_address(identity.handle()).to_owned(),
            |saved| saved.account.clone(),
        ),
        password_saved: saved
            .as_ref()
            .is_some_and(|saved| !saved.password.is_empty()),
        authorized: saved.as_ref().is_some_and(|saved| saved.contacts.is_some()),
    });
    let profile = identity.as_ref().map(|identity| identity.profile_id());
    let mut error = None;
    let previous = match read_cache(root) {
        Ok(previous) => previous,
        Err(cause) => {
            error = Some(format!("{cause:#}"));
            None
        }
    };
    let visible = previous
        .as_ref()
        .filter(|snapshot| match &snapshot.profile {
            Some(value) => {
                profile.as_ref() == Some(value)
                    && apple.as_ref().is_some_and(|apple| {
                        apple.authorized && snapshot.account.eq_ignore_ascii_case(&apple.account)
                    })
            }
            None => apple
                .as_ref()
                .is_none_or(|apple| snapshot.account.eq_ignore_ascii_case(&apple.account)),
        });
    let result = sync(root, operation, identity.as_ref(), &mut saved, visible);
    let snapshot = match result {
        Ok(snapshot) => {
            if let Some(apple) = &mut apple {
                apple.authorized = saved.as_ref().is_some_and(|saved| saved.contacts.is_some());
            }
            if snapshot.is_some() {
                error = None;
            }
            snapshot
        }
        Err(cause) => {
            error = Some(format!("{cause:#}"));
            visible.cloned()
        }
    };
    Ok(Update {
        apple,
        snapshot,
        error,
    })
}

fn sync(
    root: &Path,
    operation: Operation,
    identity: Option<&linux_imessage::apple::Identity>,
    saved: &mut Option<storage::SavedAppleAccount>,
    previous: Option<&Snapshot>,
) -> Result<Option<Snapshot>> {
    let (login, save_password) = match operation {
        Operation::Disconnect => {
            if let (Some(identity), Some(saved)) = (identity, saved)
                && saved.contacts.take().is_some()
            {
                storage::save_apple_account(root, identity, saved)?;
            }
            if let Some(previous) = previous
                && previous.profile.is_none()
            {
                storage::forget_secret(&password_key(root, &previous.account))?;
            }
            let path = root.join(CACHE);
            if path.try_exists()? {
                fs::remove_file(path)
                    .context("Could not remove the local iCloud Contacts cache")?;
            }
            return Ok(None);
        }
        Operation::Refresh => {
            if let (Some(identity), Some(saved)) = (identity, saved)
                && let Some(grant) = &saved.contacts
            {
                let recipients = runtime()?.block_on(carddav::fetch_with_apple_grant(grant))?;
                let snapshot = Snapshot {
                    account: saved.account.clone(),
                    profile: Some(identity.profile_id()),
                    recipients,
                };
                write_snapshot(root, &snapshot)?;
                if let Some(previous) = previous
                    && previous.profile.is_none()
                {
                    let _ = storage::forget_secret(&password_key(root, &previous.account));
                }
                return Ok(Some(snapshot));
            }
            let Some(previous) = previous.filter(|snapshot| snapshot.profile.is_none()) else {
                return Ok(None);
            };
            let password = storage::read_password(&password_key(root, &previous.account))?;
            (
                Form {
                    account: previous.account.clone(),
                    password,
                },
                false,
            )
        }
        Operation::Connect(form) => (form, true),
    };
    let account = login.account.trim().to_ascii_lowercase();
    let password = login.password.trim();
    ensure!(
        !account.is_empty()
            && account.len() <= 254
            && account
                .bytes()
                .all(|ch| ch.is_ascii_graphic() && ch != b':'),
        "Enter a valid Apple Account email or phone number"
    );
    ensure!(
        !password.is_empty()
            && password.len() <= 256
            && password.bytes().all(|ch| ch.is_ascii_graphic()),
        "Enter the app-specific password generated by Apple"
    );
    let recipients = runtime()?.block_on(carddav::fetch(&account, password))?;
    let snapshot = Snapshot {
        account,
        recipients,
        profile: None,
    };
    let prior = previous.filter(|data| data.account != snapshot.account && data.profile.is_none());
    let key = password_key(root, &snapshot.account);
    if save_password {
        storage::save_password(&key, password)?;
    }
    if let Err(error) = write_snapshot(root, &snapshot) {
        if save_password && previous.is_none_or(|data| data.account != snapshot.account) {
            let _ = storage::forget_secret(&key);
        }
        return Err(error);
    }
    if let Some(prior) = prior {
        let _ = storage::forget_secret(&password_key(root, &prior.account));
    }
    Ok(Some(snapshot))
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}

fn write_snapshot(root: &Path, snapshot: &Snapshot) -> Result<()> {
    let encoded = Zeroizing::new(serde_json::to_vec(snapshot)?);
    ensure!(
        encoded.len() as u64 <= CACHE_LIMIT,
        "The iCloud Contacts cache is too large"
    );
    storage::write_private(&root.join(CACHE), &encoded)
        .context("Could not save the local iCloud Contacts cache")
}
