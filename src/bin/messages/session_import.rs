use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc::{self, Receiver, TryRecvError},
};

use anyhow::{Context, Result, ensure};
use eframe::egui::{self, Align, Layout, RichText, TextEdit, vec2};
use linux_imessage::storage;

use super::chrome::{self, DANGER, MUTED};

pub(super) enum Outcome {
    Open,
    Closed,
    Saved,
}

#[derive(Default)]
pub(super) struct SessionImport {
    path: String,
    pending: Option<Receiver<Result<Event>>>,
    importing: bool,
    error: Option<String>,
}

enum Event {
    Chosen(Option<PathBuf>),
    Saved,
}

impl SessionImport {
    pub(super) fn show(&mut self, context: &egui::Context, root: &Path) -> Outcome {
        if self.poll() {
            return Outcome::Saved;
        }

        let mut browse = false;
        let mut save = false;
        let mut cancel = false;
        let idle = self.pending.is_none();
        let panel = egui::Modal::new(egui::Id::new("import-registered-session"))
            .frame(chrome::sheet())
            .show(context, |ui| {
                ui.set_width(404.);
                ui.label(chrome::bold("Import Registered iMessage Session", 19.));
                ui.add_space(7.);
                ui.label(
                    RichText::new(
                        "Choose an existing registered session to save in Linux Secret Service.",
                    )
                    .color(MUTED),
                );
                ui.add_enabled_ui(idle, |ui| {
                    let label = ui.label("Session file");
                    ui.horizontal(|ui| {
                        let width = (ui.available_width() - 80.).max(100.);
                        ui.add(TextEdit::singleline(&mut self.path).desired_width(width))
                            .labelled_by(label.id);
                        browse = ui.button("Browse…").clicked();
                    });
                });
                if !idle {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(if self.importing {
                            "Saving session…"
                        } else {
                            "Choosing file…"
                        });
                    });
                }
                if let Some(error) = &self.error {
                    ui.label(RichText::new(error).size(12.).color(DANGER));
                }
                ui.add_space(7.);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    save = ui
                        .add_enabled(
                            idle && !self.path.trim().is_empty(),
                            egui::Button::new("Import").min_size(vec2(77., 25.)),
                        )
                        .clicked();
                    cancel = ui
                        .add_enabled(idle, egui::Button::new("Cancel").min_size(vec2(65., 25.)))
                        .clicked();
                });
            });

        if idle && (cancel || panel.should_close()) {
            return Outcome::Closed;
        }
        if browse {
            self.start(context, false, || Ok(Event::Chosen(run_file_picker()?)));
        }
        if save {
            let root = root.to_owned();
            let path = PathBuf::from(self.path.trim());
            self.start(context, true, move || {
                storage::import_session(&root, &path, None)?;
                Ok(Event::Saved)
            });
        }
        Outcome::Open
    }

    fn start(
        &mut self,
        context: &egui::Context,
        importing: bool,
        operation: impl FnOnce() -> Result<Event> + Send + 'static,
    ) {
        let (send, receive) = mpsc::channel();
        let context = context.clone();
        self.importing = importing;
        self.error = None;
        self.pending = Some(receive);
        std::thread::spawn(move || {
            let _ = send.send(operation());
            context.request_repaint();
        });
    }

    fn poll(&mut self) -> bool {
        let Some(pending) = &self.pending else {
            return false;
        };
        let result = match pending.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return false,
            Err(TryRecvError::Disconnected) => {
                Err(anyhow::anyhow!("Session import stopped unexpectedly"))
            }
        };
        self.pending = None;
        match result {
            Ok(Event::Saved) => true,
            Ok(Event::Chosen(path)) => {
                if let Some(path) = path {
                    self.path = path.to_string_lossy().into_owned();
                }
                false
            }
            Err(error) => {
                self.error = Some(format!("{error:#}"));
                false
            }
        }
    }
}

fn run_file_picker() -> Result<Option<PathBuf>> {
    let mut child = Command::new("zenity")
        .arg("--file-selection")
        .arg("--title")
        .arg("Choose Registered iMessage Session")
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
