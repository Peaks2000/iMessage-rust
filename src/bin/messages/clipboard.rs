use std::{
    cell::{Cell, OnceCell, RefCell},
    rc::Rc,
    sync::mpsc::Receiver,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use eframe::{CreationContext, EframeWinitApplication, NativeOptions, UserEvent, egui};
use raw_window_handle::{HasDisplayHandle, HasWindowHandle, RawDisplayHandle};
use winit::{
    application::ApplicationHandler,
    event::{DeviceEvent, DeviceId, ElementState, KeyEvent, StartCause, WindowEvent},
    event_loop::{ActiveEventLoop, EventLoop, EventLoopProxy},
    keyboard::{Key, KeyCode, ModifiersState, NamedKey, PhysicalKey},
    window::WindowId,
};

use super::{
    attachments::{self, LoadedFile},
    window::MessagesApp,
};

#[path = "clipboard/wayland.rs"]
mod wayland;

const RING_ACTION_WAKE: &str = "native-call-wake";

pub(super) struct Clipboard {
    requested: Cell<bool>,
    wayland: RefCell<Option<wayland::Clipboard>>,
}

impl Clipboard {
    #[cfg(test)]
    pub(super) fn empty() -> Rc<Self> {
        Rc::new(Self {
            requested: Cell::new(false),
            wayland: RefCell::new(None),
        })
    }

    pub(super) fn remember_window(&self, frame: &eframe::Frame) {
        if let Some(wayland) = &mut *self.wayland.borrow_mut()
            && let Ok(window) = frame.window_handle()
        {
            wayland.remember_surface(window);
        }
    }

    pub(super) fn activate_window(&self, token: String) {
        if let Some(wayland) = &*self.wayland.borrow() {
            let _ = wayland.activate_window(token);
        }
    }

    fn forget_window(&self) {
        if let Some(wayland) = &mut *self.wayland.borrow_mut() {
            wayland.forget_surface();
        }
    }

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
    mut options: NativeOptions,
    create: impl FnOnce(&CreationContext<'_>, Rc<Clipboard>) -> MessagesApp,
) -> Result<()> {
    let event_loop = EventLoop::<UserEvent>::with_user_event().build()?;
    let proxy = event_loop.create_proxy();
    let wayland = match event_loop
        .display_handle()
        .ok()
        .map(|handle| handle.as_raw())
    {
        Some(RawDisplayHandle::Wayland(display)) => {
            // The compositor paces redraws. Waiting for a swap can block the event loop
            // when a minimized window no longer receives frame callbacks.
            options.vsync = false;
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
    let state = Rc::new(OnceCell::new());
    let app_state = state.clone();
    let app = eframe::create_native(
        name,
        options,
        Box::new(move |context| {
            context.egui_ctx.data_mut(|data| {
                data.insert_temp(
                    egui::Id::new(RING_ACTION_WAKE),
                    Some(RingActionWake {
                        proxy,
                        pending: false,
                    }),
                );
            });
            let app = Rc::new(RefCell::new(create(context, app_clipboard)));
            app_state.get_or_init(|| (context.egui_ctx.clone(), app.clone()));
            Ok(Box::new(SharedApp(app)))
        }),
        &event_loop,
    );
    event_loop.run_app(&mut NativeApp {
        app,
        clipboard,
        state,
        modifiers: ModifiersState::empty(),
    })?;
    Ok(())
}

type AppState = Rc<OnceCell<(egui::Context, Rc<RefCell<MessagesApp>>)>>;

struct SharedApp(Rc<RefCell<MessagesApp>>);

impl eframe::App for SharedApp {
    fn raw_input_hook(&mut self, ctx: &egui::Context, input: &mut egui::RawInput) {
        self.0.borrow_mut().raw_input_hook(ctx, input);
    }

    fn clear_color(&self, visuals: &egui::Visuals) -> [f32; 4] {
        self.0.borrow().clear_color(visuals)
    }

    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        self.0.borrow_mut().update(ctx, frame);
    }
}

#[derive(Clone)]
struct RingActionWake {
    proxy: EventLoopProxy<UserEvent>,
    pending: bool,
}

pub(super) fn wake_for_ring_action(ctx: &egui::Context) {
    let proxy = ctx.data_mut(|data| {
        let wake =
            data.get_temp_mut_or_default::<Option<RingActionWake>>(egui::Id::new(RING_ACTION_WAKE));
        let wake = wake.as_mut()?;
        wake.pending = true;
        Some(wake.proxy.clone())
    });
    if let Some(proxy) = proxy {
        // A compositor can suspend redraws for a minimized window. Wake the event loop directly.
        let _ = proxy.send_event(UserEvent::RequestRepaint {
            viewport_id: egui::ViewportId::ROOT,
            when: Instant::now(),
            cumulative_pass_nr: ctx.cumulative_pass_nr_for(egui::ViewportId::ROOT),
        });
    }
}

// egui-winit 0.33 turns paste into a text event and consumes the key press.
// Observe the press before handing it to egui so its normal text paste can take priority.
struct NativeApp<'a> {
    app: EframeWinitApplication<'a>,
    clipboard: Rc<Clipboard>,
    state: AppState,
    modifiers: ModifiersState,
}

impl ApplicationHandler<UserEvent> for NativeApp<'_> {
    fn window_event(&mut self, event_loop: &ActiveEventLoop, id: WindowId, event: WindowEvent) {
        match &event {
            WindowEvent::Destroyed => self.clipboard.forget_window(),
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
        if let Some((ctx, app)) = self.state.get() {
            let pending = ctx.data_mut(|data| {
                data.get_temp_mut_or_default::<Option<RingActionWake>>(egui::Id::new(
                    RING_ACTION_WAKE,
                ))
                .as_mut()
                .is_some_and(|wake| std::mem::take(&mut wake.pending))
            });
            if pending {
                app.borrow_mut().process_notification_action(ctx);
            }
        }
        self.app.user_event(event_loop, event);
    }

    fn device_event(&mut self, event_loop: &ActiveEventLoop, id: DeviceId, event: DeviceEvent) {
        self.app.device_event(event_loop, id, event);
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        self.app.about_to_wait(event_loop);
    }

    fn suspended(&mut self, event_loop: &ActiveEventLoop) {
        self.clipboard.forget_window();
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
