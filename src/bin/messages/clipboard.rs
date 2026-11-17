use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    sync::mpsc::Receiver,
    time::Duration,
};

use anyhow::{Context, Result};
use eframe::{CreationContext, EframeWinitApplication, NativeOptions, UserEvent, egui};
use raw_window_handle::{HasDisplayHandle, RawDisplayHandle};
use winit::{
    application::ApplicationHandler,
    event::{DeviceEvent, DeviceId, ElementState, KeyEvent, StartCause, WindowEvent},
    event_loop::{ActiveEventLoop, EventLoop},
    keyboard::{Key, KeyCode, ModifiersState, NamedKey, PhysicalKey},
    window::WindowId,
};

use super::attachments::{self, LoadedFile};

#[path = "clipboard/wayland.rs"]
mod wayland;

pub(super) struct Clipboard {
    requested: Cell<bool>,
    wayland: RefCell<Option<wayland::Clipboard>>,
}

impl Clipboard {
    pub(super) fn restore_wayland_text_paste(&self, input: &mut egui::RawInput) {
        // Some compositors expose the text offer to our Wayland device before egui's paste succeeds.
        if self.requested.get()
            && input.focused
            && !input
                .events
                .iter()
                .any(|event| matches!(event, egui::Event::Paste(_)))
            && let Some(wayland) = &mut *self.wayland.borrow_mut()
            && let Ok(Some(pipe)) =
                wayland.receive(&["text/plain;charset=utf-8", "UTF8_STRING", "text/plain"])
            && let Ok(bytes) = wayland::read_clipboard(pipe, 1024 * 1024, Duration::from_secs(1))
            && !bytes.is_empty()
        {
            let text = String::from_utf8_lossy(&bytes).replace("\r\n", "\n");
            input.events.push(egui::Event::Paste(text));
        }
    }

    pub(super) fn take_paste_request(&self, ctx: &egui::Context) -> bool {
        self.requested.take()
            && ctx.input(|input| {
                input.focused
                    && !input
                        .events
                        .iter()
                        .any(|event| matches!(event, egui::Event::Paste(_)))
            })
    }

    pub(super) fn load_image(
        &self,
        ctx: &egui::Context,
    ) -> Option<Receiver<Result<Vec<LoadedFile>>>> {
        if let Some(wayland) = &mut *self.wayland.borrow_mut() {
            return match wayland.receive(&[
                "image/png",
                "image/jpeg",
                "image/webp",
                "image/gif",
                "image/bmp",
                "image/tiff",
            ]) {
                Ok(Some(pipe)) => Some(attachments::task(ctx, move || {
                    Ok(vec![wayland::load_image(pipe)?])
                })),
                Ok(None) => None,
                Err(error) => Some(attachments::task(ctx, move || Err(error))),
            };
        }
        Some(attachments::task(ctx, || {
            match arboard::Clipboard::new()?.get_image() {
                Ok(image) => Ok(vec![LoadedFile::from_clipboard_pixels(image)?]),
                Err(arboard::Error::ContentNotAvailable) => Ok(Vec::new()),
                Err(error) => Err(error).context("Could not read the clipboard image"),
            }
        }))
    }
}

pub(super) fn run(
    name: &str,
    options: NativeOptions,
    create: impl FnOnce(&CreationContext<'_>, Rc<Clipboard>) -> Box<dyn eframe::App>,
) -> Result<()> {
    let event_loop = EventLoop::<UserEvent>::with_user_event().build()?;
    let wayland = match event_loop
        .display_handle()
        .ok()
        .map(|handle| handle.as_raw())
    {
        Some(RawDisplayHandle::Wayland(display)) => {
            // This clipboard is dropped in exiting, while the event loop owns the display.
            unsafe { wayland::Clipboard::new(display) }.ok()
        }
        _ => None,
    };
    let clipboard = Rc::new(Clipboard {
        requested: Cell::new(false),
        wayland: RefCell::new(wayland),
    });
    let app_clipboard = clipboard.clone();
    let app = eframe::create_native(
        name,
        options,
        Box::new(move |context| Ok(create(context, app_clipboard))),
        &event_loop,
    );
    event_loop.run_app(&mut NativeApp {
        app,
        clipboard,
        modifiers: ModifiersState::empty(),
    })?;
    Ok(())
}

// egui-winit 0.33 turns paste into a text event and consumes the key press.
// Observe the press before handing it to egui so its normal text paste can take priority.
struct NativeApp<'a> {
    app: EframeWinitApplication<'a>,
    clipboard: Rc<Clipboard>,
    modifiers: ModifiersState,
}

impl ApplicationHandler<UserEvent> for NativeApp<'_> {
    fn window_event(&mut self, event_loop: &ActiveEventLoop, id: WindowId, event: WindowEvent) {
        match &event {
            WindowEvent::ModifiersChanged(modifiers) => self.modifiers = modifiers.state(),
            WindowEvent::Focused(false) => {
                self.modifiers = ModifiersState::empty();
                self.clipboard.requested.set(false);
            }
            WindowEvent::KeyboardInput {
                event,
                is_synthetic: false,
                ..
            } if is_paste(event, self.modifiers) => {
                self.clipboard.requested.set(true);
            }
            _ => {}
        }
        self.app.window_event(event_loop, id, event);
    }

    fn new_events(&mut self, event_loop: &ActiveEventLoop, cause: StartCause) {
        self.app.new_events(event_loop, cause);
    }

    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        self.app.resumed(event_loop);
    }

    fn user_event(&mut self, event_loop: &ActiveEventLoop, event: UserEvent) {
        self.app.user_event(event_loop, event);
    }

    fn device_event(&mut self, event_loop: &ActiveEventLoop, id: DeviceId, event: DeviceEvent) {
        self.app.device_event(event_loop, id, event);
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        self.app.about_to_wait(event_loop);
    }

    fn suspended(&mut self, event_loop: &ActiveEventLoop) {
        self.app.suspended(event_loop);
    }

    fn exiting(&mut self, event_loop: &ActiveEventLoop) {
        self.clipboard.wayland.borrow_mut().take();
        self.app.exiting(event_loop);
    }

    fn memory_warning(&mut self, event_loop: &ActiveEventLoop) {
        self.app.memory_warning(event_loop);
    }
}

fn is_paste(event: &KeyEvent, modifiers: ModifiersState) -> bool {
    if event.state != ElementState::Pressed || event.repeat {
        return false;
    }
    match event.logical_key.as_ref() {
        Key::Named(NamedKey::Paste) => true,
        Key::Character(key) if key.len() == 1 && key.as_bytes()[0].is_ascii_alphabetic() => {
            modifiers.control_key() && key.eq_ignore_ascii_case("v")
        }
        _ => modifiers.control_key() && event.physical_key == PhysicalKey::Code(KeyCode::KeyV),
    }
}
