//! Native-Wayland file drag and drop for the vault browser (Linux).
//!
//! winit 0.30 (what eframe 0.34 runs on) delivers OS file drops on
//! Windows, macOS and X11, but its Wayland backend has no drag-and-drop
//! support at all, so on a GNOME or KDE Wayland session nothing ever
//! reached egui's `hovered_files` / `dropped_files` and dragging files
//! from Nautilus or Dolphin onto the browser did nothing. Upstream
//! landed Wayland drops in winit PR 4571 (August 2026), which ships
//! with winit 0.31; this module can go once eframe is on that.
//!
//! Until then the GUI speaks the core `wl_data_device` protocol itself,
//! on the window's own Wayland connection: it wraps the `wl_display`
//! winit opened (the same trick the clipboard crate uses), binds the
//! data device manager and the seats on a private event queue, and
//! drives that queue from a worker thread. A drag entering one of our
//! surfaces is accepted when it offers `text/uri-list`; on drop the
//! list is read, decoded to local paths and handed to the UI thread
//! through a channel together with a repaint request. Hover state is an
//! atomic the browser reads to draw its drop highlight.
//!
//! `LUKSBOX_GUI_NO_WAYLAND_DND=1` disables the worker.

use std::ffi::OsString;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use raw_window_handle::{HasDisplayHandle, RawDisplayHandle};
use smithay_client_toolkit::data_device_manager::DataDeviceManagerState;
use smithay_client_toolkit::data_device_manager::data_device::{
    DataDevice, DataDeviceData, DataDeviceHandler,
};
use smithay_client_toolkit::data_device_manager::data_offer::{DataOfferHandler, DragOffer};
use smithay_client_toolkit::data_device_manager::data_source::DataSourceHandler;
use smithay_client_toolkit::reexports::client::backend::{Backend, WaylandError};
use smithay_client_toolkit::reexports::client::globals::registry_queue_init;
use smithay_client_toolkit::reexports::client::protocol::wl_data_device::WlDataDevice;
use smithay_client_toolkit::reexports::client::protocol::wl_data_device_manager::DndAction;
use smithay_client_toolkit::reexports::client::protocol::wl_data_source::WlDataSource;
use smithay_client_toolkit::reexports::client::protocol::wl_seat::WlSeat;
use smithay_client_toolkit::reexports::client::protocol::wl_surface::WlSurface;
use smithay_client_toolkit::reexports::client::{Connection, EventQueue, Proxy, QueueHandle};
use smithay_client_toolkit::registry::{ProvidesRegistryState, RegistryState};
use smithay_client_toolkit::seat::{Capability, SeatHandler, SeatState};
use smithay_client_toolkit::{
    delegate_data_device, delegate_registry, delegate_seat, registry_handlers,
};

const URI_LIST: &str = "text/uri-list";
/// How long the drop source gets to write the URI list before we give
/// up on it (a hung source must not freeze the worker for good).
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(10);
/// Poll slice of the worker loop; bounds how long shutdown waits.
const POLL_SLICE_MS: i32 = 250;

/// Handle owned by the app. Dropping it stops the worker thread.
pub struct WaylandDnd {
    rx: Receiver<Vec<PathBuf>>,
    hovering: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl WaylandDnd {
    /// Starts the worker when the window is a native Wayland window.
    /// `None` on X11 (winit delivers drops itself there), when
    /// disabled, or when the worker could not be spawned.
    pub fn start(cc: &eframe::CreationContext<'_>) -> Option<Self> {
        if std::env::var_os("LUKSBOX_GUI_NO_WAYLAND_DND").is_some_and(|v| !v.is_empty() && v != "0")
        {
            return None;
        }
        let RawDisplayHandle::Wayland(h) = cc.display_handle().ok()?.as_raw() else {
            return None;
        };
        // Carried across threads as an integer; it is only ever turned
        // back into a pointer inside `run`.
        let display = h.display.as_ptr() as usize;
        let (tx, rx) = mpsc::channel();
        let hovering = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let ctx = cc.egui_ctx.clone();
        let (hv, st) = (hovering.clone(), stop.clone());
        let worker = std::thread::Builder::new()
            .name("luksbox-wayland-dnd".into())
            .spawn(move || {
                if let Err(e) = run(display, ctx, tx, hv, st) {
                    log::warn!("wayland drag and drop unavailable: {e}");
                }
            })
            .ok()?;
        Some(Self {
            rx,
            hovering,
            stop,
            worker: Some(worker),
        })
    }

    /// True while a drag carrying files is over one of our surfaces.
    pub fn hovering(&self) -> bool {
        self.hovering.load(Ordering::Relaxed)
    }

    /// Paths dropped since the last call.
    pub fn take_dropped(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        while let Ok(mut batch) = self.rx.try_recv() {
            out.append(&mut batch);
        }
        out
    }
}

impl Drop for WaylandDnd {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}

struct State {
    registry: RegistryState,
    seats: SeatState,
    manager: DataDeviceManagerState,
    devices: Vec<DataDevice>,
    ctx: egui::Context,
    tx: Sender<Vec<PathBuf>>,
    hovering: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
}

impl State {
    fn set_hovering(&self, on: bool) {
        if self.hovering.swap(on, Ordering::Relaxed) != on {
            self.ctx.request_repaint();
        }
    }

    fn add_device_for(&mut self, qh: &QueueHandle<Self>, seat: &WlSeat) {
        if self.devices.iter().any(|d| d.data().seat() == seat) {
            return;
        }
        let device = self.manager.get_data_device(qh, seat);
        self.devices.push(device);
    }
}

fn run(
    display: usize,
    ctx: egui::Context,
    tx: Sender<Vec<PathBuf>>,
    hovering: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    // SAFETY: the pointer is the `wl_display` of the window's display
    // handle. winit keeps that display open for as long as the window
    // exists, and `WaylandDnd::drop` (run when the app is dropped,
    // before eframe tears the window down) stops and joins this thread
    // first, so the display outlives every use here.
    let backend = unsafe { Backend::from_foreign_display(display as *mut _) };
    let conn = Connection::from_backend(backend);
    let (globals, mut queue): (_, EventQueue<State>) =
        registry_queue_init(&conn).map_err(|e| format!("registry: {e}"))?;
    let qh = queue.handle();
    let manager = DataDeviceManagerState::bind(&globals, &qh)
        .map_err(|e| format!("wl_data_device_manager: {e}"))?;
    let mut state = State {
        registry: RegistryState::new(&globals),
        seats: SeatState::new(&globals, &qh),
        manager,
        devices: Vec::new(),
        ctx,
        tx,
        hovering,
        stop: stop.clone(),
    };
    for seat in state.seats.seats().collect::<Vec<_>>() {
        state.add_device_for(&qh, &seat);
    }
    log::info!(
        "wayland drag and drop: listening on {} seat(s)",
        state.devices.len()
    );

    // Classic external-loop integration: dispatch what is queued, then
    // wait for the socket with a bounded poll so the stop flag is seen.
    loop {
        queue.flush().map_err(|e| format!("flush: {e}"))?;
        queue
            .dispatch_pending(&mut state)
            .map_err(|e| format!("dispatch: {e}"))?;
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        let Some(guard) = queue.prepare_read() else {
            continue;
        };
        let mut pfd = libc::pollfd {
            fd: guard.connection_fd().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pfd` is a valid, initialised pollfd and we pass its
        // length (1); poll does not retain the pointer.
        let ready = unsafe { libc::poll(&mut pfd, 1, POLL_SLICE_MS) };
        if ready > 0 {
            match guard.read() {
                Ok(_) => {}
                Err(WaylandError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(format!("read: {e}")),
            }
        } else {
            // Timeout or EINTR: give the read intent back to the other
            // threads sharing the connection.
            drop(guard);
        }
    }
}

fn drag_offer(device: &WlDataDevice) -> Option<DragOffer> {
    device.data::<DataDeviceData>()?.drag_offer()
}

fn offers_uris(offer: &DragOffer) -> bool {
    offer.with_mime_types(|mimes| mimes.iter().any(|m| m == URI_LIST))
}

/// Reads the whole URI list from the drop pipe, with a deadline, and
/// bails out early when the app is shutting down.
fn read_all(
    pipe: smithay_client_toolkit::data_device_manager::ReadPipe,
    stop: &AtomicBool,
) -> Result<Vec<u8>, String> {
    let fd = pipe.as_raw_fd();
    // SAFETY: plain fcntl on a pipe fd we own.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
    let deadline = Instant::now() + RECEIVE_TIMEOUT;
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if stop.load(Ordering::Relaxed) {
            return Err("shutting down".into());
        }
        if Instant::now() >= deadline {
            return Err("the drop source did not deliver the file list in time".into());
        }
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: as above.
        let ready = unsafe { libc::poll(&mut pfd, 1, POLL_SLICE_MS) };
        if ready <= 0 {
            continue;
        }
        // SAFETY: reading into a buffer we own, bounded by its length.
        let n = unsafe { libc::read(fd, chunk.as_mut_ptr().cast(), chunk.len()) };
        match n {
            0 => return Ok(out),
            n if n > 0 => out.extend_from_slice(&chunk[..n as usize]),
            _ => {
                let err = std::io::Error::last_os_error();
                match err.kind() {
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => continue,
                    _ => return Err(err.to_string()),
                }
            }
        }
    }
}

/// Decodes a `text/uri-list` payload into local absolute paths.
/// Comment lines, non-`file:` URIs and remote hosts are skipped;
/// percent-escapes are decoded byte-wise so non-UTF-8 names survive.
pub fn parse_uri_list(data: &[u8]) -> Vec<PathBuf> {
    let text = String::from_utf8_lossy(data);
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(file_uri_to_path)
        .collect()
}

fn file_uri_to_path(uri: &str) -> Option<PathBuf> {
    let rest = uri.strip_prefix("file://")?;
    let encoded = if rest.starts_with('/') {
        rest
    } else {
        // `file://host/path`: only the local host is readable.
        let (host, _) = rest.split_once('/')?;
        if !host.eq_ignore_ascii_case("localhost") {
            return None;
        }
        &rest[host.len()..]
    };
    let bytes = percent_decode(encoded.as_bytes());
    if bytes.first() != Some(&b'/') {
        return None;
    }
    Some(PathBuf::from(OsString::from_vec(bytes)))
}

fn percent_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' && i + 2 < input.len() {
            let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
            if let (Some(h), Some(l)) = (hex(input[i + 1]), hex(input[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

impl DataDeviceHandler for State {
    fn enter(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        data_device: &WlDataDevice,
        _x: f64,
        _y: f64,
        _wl_surface: &WlSurface,
    ) {
        let Some(offer) = drag_offer(data_device) else {
            return;
        };
        if offers_uris(&offer) {
            offer.accept_mime_type(offer.serial, Some(URI_LIST.to_owned()));
            offer.set_actions(DndAction::Copy, DndAction::Copy);
            self.set_hovering(true);
        } else {
            offer.accept_mime_type(offer.serial, None);
        }
    }

    fn leave(&mut self, _conn: &Connection, _qh: &QueueHandle<Self>, _device: &WlDataDevice) {
        self.set_hovering(false);
    }

    fn motion(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _device: &WlDataDevice,
        _x: f64,
        _y: f64,
    ) {
    }

    fn selection(&mut self, _conn: &Connection, _qh: &QueueHandle<Self>, _device: &WlDataDevice) {}

    fn drop_performed(
        &mut self,
        conn: &Connection,
        _qh: &QueueHandle<Self>,
        data_device: &WlDataDevice,
    ) {
        self.set_hovering(false);
        let Some(offer) = drag_offer(data_device) else {
            return;
        };
        if !offers_uris(&offer) {
            offer.destroy();
            return;
        }
        let received = offer
            .receive(URI_LIST.to_owned())
            .map_err(|e| e.to_string())
            .and_then(|pipe| {
                // The receive request must reach the compositor before
                // the source can start writing.
                let _ = conn.flush();
                read_all(pipe, &self.stop)
            });
        match received {
            Ok(bytes) => {
                // Tell the source the drop succeeded (v3+), then release
                // the offer: after a drop the client owns it.
                offer.finish();
                offer.destroy();
                let paths = parse_uri_list(&bytes);
                if paths.is_empty() {
                    log::info!("wayland drop carried no local file paths");
                } else {
                    let _ = self.tx.send(paths);
                    self.ctx.request_repaint();
                }
            }
            Err(e) => {
                offer.destroy();
                log::warn!("wayland drop: could not read the dropped file list: {e}");
            }
        }
    }
}

impl DataOfferHandler for State {
    fn source_actions(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _offer: &mut DragOffer,
        _actions: DndAction,
    ) {
    }

    fn selected_action(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _offer: &mut DragOffer,
        _actions: DndAction,
    ) {
    }
}

// We never create a data source (no drags start from LUKSbox), but the
// delegate macro wires the source dispatcher too.
impl DataSourceHandler for State {
    fn accept_mime(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _source: &WlDataSource,
        _mime: Option<String>,
    ) {
    }
    fn send_request(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _source: &WlDataSource,
        _mime: String,
        _fd: smithay_client_toolkit::data_device_manager::WritePipe,
    ) {
    }
    fn cancelled(&mut self, _conn: &Connection, _qh: &QueueHandle<Self>, _source: &WlDataSource) {}
    fn dnd_dropped(&mut self, _conn: &Connection, _qh: &QueueHandle<Self>, _source: &WlDataSource) {
    }
    fn dnd_finished(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _source: &WlDataSource,
    ) {
    }
    fn action(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _source: &WlDataSource,
        _action: DndAction,
    ) {
    }
}

impl SeatHandler for State {
    fn seat_state(&mut self) -> &mut SeatState {
        &mut self.seats
    }

    fn new_seat(&mut self, _conn: &Connection, qh: &QueueHandle<Self>, seat: WlSeat) {
        self.add_device_for(qh, &seat);
    }

    fn new_capability(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _seat: WlSeat,
        _capability: Capability,
    ) {
    }

    fn remove_capability(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _seat: WlSeat,
        _capability: Capability,
    ) {
    }

    fn remove_seat(&mut self, _conn: &Connection, _qh: &QueueHandle<Self>, seat: WlSeat) {
        self.devices.retain(|d| d.data().seat() != &seat);
    }
}

impl ProvidesRegistryState for State {
    fn registry(&mut self) -> &mut RegistryState {
        &mut self.registry
    }
    registry_handlers![SeatState];
}

delegate_registry!(State);
delegate_seat!(State);
delegate_data_device!(State);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_list_decodes_local_files_and_skips_the_rest() {
        let data = b"# dropped from the file manager\r\n\
                     file:///home/u/a%20b.txt\r\n\
                     file:///tmp/plain\r\n\
                     http://example.com/not-a-file\r\n\
                     file://localhost/etc/hosts\r\n\
                     file://nas/share/remote\r\n\
                     \r\n\
                     file:relative\r\n";
        let paths = parse_uri_list(data);
        assert_eq!(
            paths,
            vec![
                PathBuf::from("/home/u/a b.txt"),
                PathBuf::from("/tmp/plain"),
                PathBuf::from("/etc/hosts"),
            ]
        );
    }

    #[test]
    fn percent_escapes_decode_bytewise_and_leave_bad_escapes_alone() {
        assert_eq!(percent_decode(b"a%20b%ZZc%4"), b"a b%ZZc%4".to_vec());
        let p = parse_uri_list(b"file:///tmp/%ff%fe\n");
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].as_os_str().as_encoded_bytes(), b"/tmp/\xff\xfe");
    }

    #[test]
    fn lf_only_lists_and_trailing_whitespace_are_accepted() {
        let p = parse_uri_list(b"file:///a\nfile:///b  \n");
        assert_eq!(p, vec![PathBuf::from("/a"), PathBuf::from("/b")]);
    }
}
