use std::{os::fd::OwnedFd, time::Duration};

use anyhow::{Context, Result, ensure};
use raw_window_handle::{RawWindowHandle, WaylandDisplayHandle, WindowHandle};
use smithay_client_toolkit::{
    data_device_manager::{
        DataDeviceManagerState,
        data_device::{DataDevice, DataDeviceData, DataDeviceHandler},
        data_offer::{DataOfferData, DataOfferHandler, DragOffer},
    },
    delegate_registry, delegate_seat,
    globals::GlobalData,
    reexports::protocols::xdg::activation::v1::client::xdg_activation_v1::XdgActivationV1,
    registry::{ProvidesRegistryState, RegistryState},
    registry_handlers,
    seat::{Capability, SeatHandler, SeatState},
};
use tokio::io::AsyncReadExt;
use wayland_client::{
    Connection, EventQueue, Proxy, QueueHandle,
    backend::{Backend, ObjectId},
    delegate_dispatch, delegate_noop,
    globals::registry_queue_init,
    protocol::{
        wl_data_device::WlDataDevice,
        wl_data_device_manager::{DndAction, WlDataDeviceManager},
        wl_data_offer::WlDataOffer,
        wl_seat::WlSeat,
        wl_surface::WlSurface,
    },
};

use super::LoadedFile;
use linux_imessage::FILE_LIMIT;

pub(super) struct Clipboard {
    connection: Connection,
    queue: EventQueue<Selection>,
    selection: Selection,
    activation: Option<XdgActivationV1>,
    surface: Option<WlSurface>,
}

struct Selection {
    registry: RegistryState,
    seats: SeatState,
    manager: DataDeviceManagerState,
    devices: Vec<DataDevice>,
    active: Option<WlDataDevice>,
}

impl Clipboard {
    /// The display must outlive this clipboard and its Wayland event queue.
    pub(super) unsafe fn new(display: WaylandDisplayHandle) -> Result<Self> {
        // Use the app's focused Wayland connection to receive the clipboard offer.
        let backend = unsafe { Backend::from_foreign_display(display.display.as_ptr().cast()) };
        let connection = Connection::from_backend(backend);
        let (globals, mut queue) = registry_queue_init(&connection)?;
        let handle = queue.handle();
        let activation = globals.bind(&handle, 1..=1, ()).ok();
        let mut selection = Selection {
            registry: RegistryState::new(&globals),
            seats: SeatState::new(&globals, &handle),
            manager: DataDeviceManagerState::bind(&globals, &handle)?,
            devices: Vec::new(),
            active: None,
        };
        queue.roundtrip(&mut selection)?;
        connection.flush()?;
        Ok(Self {
            connection,
            queue,
            selection,
            activation,
            surface: None,
        })
    }

    pub(super) fn remember_surface(&mut self, window: WindowHandle<'_>) {
        if self.activation.is_some()
            && self
                .surface
                .as_ref()
                .is_none_or(|surface| !surface.is_alive())
            && let RawWindowHandle::Wayland(window) = window.as_raw()
        {
            // Winit owns this proxy on our display. Its Wayland backend tracks when it is
            // destroyed. The event loop uses it only on this thread and clears it on teardown.
            self.surface = unsafe {
                ObjectId::from_ptr(WlSurface::interface(), window.surface.as_ptr().cast())
            }
            .ok()
            .and_then(|id| WlSurface::from_id(&self.connection, id).ok());
        }
    }

    pub(super) fn forget_surface(&mut self) {
        self.surface = None;
    }

    pub(super) fn activate_window(&self, token: String) -> Result<()> {
        if let (Some(activation), Some(surface)) = (&self.activation, &self.surface)
            && surface.is_alive()
        {
            activation.activate(token, surface);
            self.connection.flush()?;
        }
        Ok(())
    }

    pub(super) fn receive(&mut self, accepted: &[&str]) -> Result<Option<OwnedFd>> {
        self.queue.dispatch_pending(&mut self.selection)?;
        let Some(offer) = self
            .selection
            .active
            .as_ref()
            .and_then(|id| {
                self.selection
                    .devices
                    .iter()
                    .find(|device| device.inner() == id)
            })
            .and_then(|device| device.data().selection_offer())
        else {
            return Ok(None);
        };
        let mime = offer.with_mime_types(|offered| {
            accepted
                .iter()
                .find(|mime| offered.iter().any(|format| format == **mime))
                .copied()
        });
        let Some(mime) = mime else {
            return Ok(None);
        };
        let read = offer
            .receive(mime.to_owned())
            .context("Could not read the clipboard")?;
        self.connection.flush()?;
        Ok(Some(read.into()))
    }
}

pub(super) fn load_image(pipe: OwnedFd) -> Result<LoadedFile> {
    let bytes = read_clipboard(pipe, FILE_LIMIT, Duration::from_secs(6))?;
    LoadedFile::from_clipboard_bytes(bytes.into())
}

pub(super) fn read_clipboard(pipe: OwnedFd, limit: usize, timeout: Duration) -> Result<Vec<u8>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let bytes = runtime.block_on(async {
        let mut reader =
            tokio::net::unix::pipe::Receiver::from_owned_fd(pipe)?.take(limit as u64 + 1);
        let mut bytes = Vec::new();
        tokio::time::timeout(timeout, reader.read_to_end(&mut bytes))
            .await
            .context("Reading the clipboard timed out")??;
        Ok::<_, anyhow::Error>(bytes)
    })?;
    ensure!(
        bytes.len() <= limit,
        "The clipboard contents exceed the size limit"
    );
    Ok(bytes)
}

impl ProvidesRegistryState for Selection {
    fn registry(&mut self) -> &mut RegistryState {
        &mut self.registry
    }
    registry_handlers!(SeatState);
}

impl SeatHandler for Selection {
    fn seat_state(&mut self) -> &mut SeatState {
        &mut self.seats
    }

    fn new_seat(&mut self, _: &Connection, _: &QueueHandle<Self>, _: WlSeat) {}

    fn new_capability(
        &mut self,
        _: &Connection,
        queue: &QueueHandle<Self>,
        seat: WlSeat,
        capability: Capability,
    ) {
        if capability == Capability::Keyboard {
            self.devices
                .push(self.manager.get_data_device(queue, &seat));
        }
    }

    fn remove_capability(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        seat: WlSeat,
        capability: Capability,
    ) {
        if capability == Capability::Keyboard {
            self.devices.retain(|device| device.data().seat() != &seat);
        }
    }

    fn remove_seat(&mut self, _: &Connection, _: &QueueHandle<Self>, seat: WlSeat) {
        self.devices.retain(|device| device.data().seat() != &seat);
    }
}

impl DataDeviceHandler for Selection {
    fn selection(&mut self, _: &Connection, _: &QueueHandle<Self>, device: &WlDataDevice) {
        self.active = Some(device.clone());
    }

    fn enter(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &WlDataDevice,
        _: f64,
        _: f64,
        _: &WlSurface,
    ) {
    }
    fn leave(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &WlDataDevice) {}
    fn motion(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &WlDataDevice, _: f64, _: f64) {}
    fn drop_performed(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &WlDataDevice) {}
}

impl DataOfferHandler for Selection {
    fn source_actions(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &mut DragOffer,
        _: DndAction,
    ) {
    }
    fn selected_action(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &mut DragOffer,
        _: DndAction,
    ) {
    }
}

delegate_registry!(Selection);
delegate_seat!(Selection);
delegate_noop!(Selection: XdgActivationV1);
delegate_dispatch!(Selection: [WlDataDeviceManager: GlobalData] => DataDeviceManagerState);
delegate_dispatch!(Selection: [WlDataDevice: DataDeviceData] => DataDeviceManagerState);
delegate_dispatch!(Selection: [WlDataOffer: DataOfferData] => DataDeviceManagerState);
