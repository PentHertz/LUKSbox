// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Sync bundles (`.lbxs`) in the GUI.
//!
//! The unlock paths in `ops.rs` read the header and open the vault
//! through `read_header_src` and `open_with_material`: for a bundle
//! folder they read its newest header object and open a sync session,
//! kept here while the vault is open. `tick` (called every frame)
//! publishes saved changes a little after the last one; locking calls
//! `finish_active_session`, which publishes, merges concurrent commits
//! and removes the lease. `status_line` feeds the browser header.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use luksbox_core::HEADER_SIZE;
use luksbox_format::hybrid_sidecar::{self, HybridEntry, SidecarBundle};
use luksbox_format::{Container, UnlockMaterial};
use luksbox_sync::SyncError;
use luksbox_sync::bundle::{self, OpenOptions, OpenReport, Session};
use luksbox_sync::graph::Notice;

struct Active {
    /// Shared with the upload worker, which holds it while publishing.
    session: Arc<Mutex<Session>>,
    /// The background upload in progress, if any. Its result is the new
    /// `last_error`.
    worker: Option<std::thread::JoinHandle<Option<String>>>,
    /// Messages from the open, shown once.
    notices: Vec<String>,
    last_publish: Instant,
    last_heartbeat: Instant,
    last_error: Option<String>,
    /// The session may write (a restore writes into the vault).
    writable: bool,
}

static ACTIVE: Mutex<Option<Active>> = Mutex::new(None);

/// Publish this long after the last check found unpublished changes.
const PUBLISH_EVERY: Duration = Duration::from_secs(15);
const HEARTBEAT_EVERY: Duration = Duration::from_secs(300);

pub fn is_bundle(path: &Path) -> bool {
    bundle::fs::is_bundle(path)
}

fn local_root() -> PathBuf {
    if let Some(p) = std::env::var_os("LUKSBOX_SYNC_STATE_DIR") {
        return PathBuf::from(p);
    }
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("luksbox")
        .join("sync")
}

/// This device's automatic rollback anchors for vaults in cloud folders
/// (shared with the command line).
fn anchors_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("LUKSBOX_SYNC_STATE_DIR") {
        return PathBuf::from(p).join("anchors");
    }
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("luksbox")
        .join("anchors")
}

/// Warnings about a single-file vault in a cloud folder, from the last
/// unlock (taken once, for toasts).
static CLOUD_NOTES: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// A single-file vault in a cloud folder, unlocked without an anchor of
/// its own (phase 0 of `docs/CLOUD_SYNC_DESIGN.md`): attach this
/// device's automatic anchor, say on the first open that the folder is
/// synced, and point at copies the sync client made.
pub fn attach_auto_anchor(cont: &mut Container) -> Result<(), String> {
    if let Ok(mut n) = CLOUD_NOTES.lock() {
        n.clear();
    }
    if cont.is_external() || cont.is_deniable() {
        return Ok(());
    }
    let mut notes = Vec::new();
    if let Some(a) = luksbox_sync::cloud::attach_auto_anchor(cont, &anchors_dir())?
        && a.created
    {
        notes.push(format!(
            "This vault is in a {} folder: use it on one device at a time and let the sync \
             finish before switching. \"Make sync bundle...\" makes a copy that handles several \
             devices. This device now keeps a rollback anchor for this vault.",
            a.service
        ));
    }
    let vault = cont.vault_path();
    if luksbox_sync::cloud::cloud_service(vault).is_some() {
        let copies = luksbox_sync::cloud::conflict_copies(vault);
        if !copies.is_empty() {
            let names: Vec<String> = copies
                .iter()
                .map(|p| {
                    format!(
                        "\"{}\"",
                        p.file_name().unwrap_or_default().to_string_lossy()
                    )
                })
                .collect();
            notes.push(format!(
                "Copies of this vault next to it may hold changes it lacks: {}. Merge one in \
                 with `luksbox merge` (command line).",
                names.join(", ")
            ));
        }
    }
    if let Ok(mut n) = CLOUD_NOTES.lock() {
        *n = notes;
    }
    Ok(())
}

/// The metadata half of the automatic anchor, once the vault is open
/// (no-op for any other anchor).
pub fn settle_auto_anchor(vfs: &mut luksbox_vfs::Vfs) -> Result<(), String> {
    luksbox_sync::cloud::settle_auto_anchor(vfs, &anchors_dir())
}

/// Cloud-folder warnings from the last unlock (taken once).
pub fn take_cloud_notes() -> Vec<String> {
    CLOUD_NOTES
        .lock()
        .map(|mut n| std::mem::take(&mut *n))
        .unwrap_or_default()
}

fn device_label() -> String {
    if let Ok(l) = std::env::var("LUKSBOX_DEVICE_LABEL")
        && !l.trim().is_empty()
    {
        return l;
    }
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        // SAFETY: valid buffer and length.
        if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } == 0 {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            if let Ok(s) = std::str::from_utf8(&buf[..end])
                && !s.is_empty()
            {
                return s.to_string();
            }
        }
    }
    #[cfg(windows)]
    {
        if let Ok(n) = std::env::var("COMPUTERNAME")
            && !n.is_empty()
        {
            return n;
        }
    }
    "device".to_string()
}

fn to_format(e: SyncError) -> luksbox_format::Error {
    match e {
        SyncError::Format(f) => f,
        other => luksbox_format::Error::Io(std::io::Error::other(other.to_string())),
    }
}

/// Header bytes an unlock prompt inspects (newest header object of a
/// bundle). Only used to decide how to prompt.
pub fn read_header_src(header_src: &Path, vault: &Path) -> std::io::Result<[u8; HEADER_SIZE]> {
    if header_src == vault && is_bundle(vault) {
        return bundle::fs::newest_header(vault).map_err(|e| std::io::Error::other(e.to_string()));
    }
    let mut f = luksbox_core::file_util::open_existing_read_no_follow_policy(header_src)?;
    let mut buf = [0u8; HEADER_SIZE];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

fn bundle_sidecar(vault: &Path) -> Result<SidecarBundle, luksbox_format::Error> {
    let bytes = bundle::fs::newest_hybrid(vault)
        .map_err(to_format)?
        .ok_or_else(|| {
            luksbox_format::Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "this sync bundle has no post-quantum sidecar",
            ))
        })?;
    hybrid_sidecar::parse_bundle(&bytes)
}

#[allow(dead_code)]
pub fn read_hybrid_sidecar(
    vault: &Path,
    sidecar: &Path,
) -> Result<SidecarBundle, luksbox_format::Error> {
    if is_bundle(vault) {
        return bundle_sidecar(vault);
    }
    hybrid_sidecar::read_bundle(sidecar)
}

pub fn read_hybrid_for_vault(
    sidecar: &Path,
    vault: &Path,
    header_path: Option<&Path>,
) -> Result<Vec<HybridEntry>, luksbox_format::Error> {
    if header_path.is_none() && is_bundle(vault) {
        let sc = bundle_sidecar(vault)?;
        let header = bundle::fs::newest_header(vault).map_err(to_format)?;
        let h = luksbox_core::Header::from_bytes(&header)?;
        hybrid_sidecar::verify_binding(&sc, &h.header_salt)?;
        return Ok(sc.entries);
    }
    hybrid_sidecar::read_for_vault(sidecar, vault, header_path)
}

fn describe(r: &OpenReport) -> Vec<String> {
    let mut out = Vec::new();
    for n in &r.notices {
        out.push(match n {
            Notice::FirstOpen => "First time this device opens this sync bundle: it is trusted as found.".into(),
            Notice::Pending { count } => format!("{count} commit(s) are still arriving from the sync service."),
            Notice::Missing { seq, .. } => format!(
                "A commit (#{seq}) another device saw has not arrived yet: the vault is read-only \
                 until it does (sync lag, or the provider is withholding it)."
            ),
            Notice::Equivocation { seq, .. } => format!(
                "Two installations used one device identity (commit #{seq}); both versions were kept."
            ),
            Notice::HeaderFork { heads } => format!(
                "{heads} devices changed the keyslots at the same time; not merged automatically."
            ),
            Notice::UnmergedLocalChanges { recoverable: true } => {
                "Changes saved on this computer earlier could not be merged automatically \
                 (the keyslots changed on another computer since). They are shown read-only: \
                 copy out what you need, then run `luksbox sync discard-local --yes` to write \
                 again."
                    .into()
            }
            Notice::UnmergedLocalChanges { recoverable: false } => {
                "Changes saved on this computer earlier were made on a version that is no \
                 longer in the bundle and cannot be rebuilt. The vault stays read-only until \
                 they are discarded (`luksbox sync discard-local --yes`)."
                    .into()
            }
        });
    }
    for n in &r.keyslot_notes {
        out.push(format!("Keyslots: {n}."));
    }
    if r.new_identity {
        out.push("This device's identity was in use elsewhere; it took a new one.".into());
    }
    if r.restored_local_changes {
        out.push("Changes saved on this device earlier were restored.".into());
    }
    for (label, w) in &r.open_elsewhere {
        out.push(format!(
            "Also open on {label}{}.",
            if *w { " (read-write)" } else { "" }
        ));
    }
    if !r.writable {
        out.push("Opened read-only.".into());
    }
    out
}

/// `Container::open`, or a sync session for a bundle folder.
pub fn open_with_material(
    path: &Path,
    header_path: Option<&Path>,
    material: UnlockMaterial<'_>,
) -> Result<Container, luksbox_format::Error> {
    if !is_bundle(path) {
        return Container::open(path, header_path, material);
    }
    if header_path.is_some() {
        return Err(luksbox_format::Error::UnsupportedForExternalStorage(
            "a detached header",
        ));
    }
    let _ = finish_active_session();
    let mut material = material;
    let opts = OpenOptions {
        device_label: device_label(),
        read_only: false,
    };
    let (session, container, report) =
        bundle::fs::open(path, &local_root(), &mut material, &opts).map_err(to_format)?;
    #[cfg(target_os = "linux")]
    folder_icon::set(path);
    install(session, &report);
    Ok(container)
}

/// Open the bundle just made at `path` from a vault this device had
/// unlocked, with that vault's master key: nothing is asked again.
pub fn open_new_bundle(
    path: &Path,
    mvk: &luksbox_core::MasterVolumeKey,
) -> Result<luksbox_vfs::Vfs, String> {
    let _ = finish_active_session();
    let opts = OpenOptions {
        device_label: device_label(),
        read_only: false,
    };
    let (session, container, report) =
        bundle::fs::open_with_key(path, &local_root(), mvk, &opts).map_err(|e| e.to_string())?;
    let vfs = luksbox_vfs::Vfs::open(container).map_err(|e| e.to_string())?;
    install(session, &report);
    Ok(vfs)
}

/// Keep `session` as the open bundle's, for the publishing tick, the
/// status line and locking.
fn install(session: Session, report: &OpenReport) {
    if let Ok(mut g) = ACTIVE.lock() {
        *g = Some(Active {
            session: Arc::new(Mutex::new(session)),
            worker: None,
            notices: describe(report),
            last_publish: Instant::now(),
            last_heartbeat: Instant::now(),
            last_error: None,
            writable: report.writable,
        });
    }
}

/// Messages from the last open (taken once, for toasts).
pub fn take_notices() -> Vec<String> {
    ACTIVE
        .lock()
        .ok()
        .and_then(|mut g| g.as_mut().map(|a| std::mem::take(&mut a.notices)))
        .unwrap_or_default()
}

/// Publish the last saved state on a worker thread, so a large upload
/// freezes neither the window nor the vault: the session publishes
/// without holding the vault's image (see `Session::publish`).
fn spawn_publish(
    session: Arc<Mutex<Session>>,
    heartbeat: bool,
) -> std::thread::JoinHandle<Option<String>> {
    std::thread::spawn(move || {
        let Ok(mut s) = session.lock() else {
            return Some("the sync session was lost".into());
        };
        let r = s.publish().err().map(|e| e.to_string());
        if heartbeat {
            let _ = s.heartbeat();
        }
        r
    })
}

/// Collect a finished upload's result.
fn reap_worker(a: &mut Active) {
    if a.worker.as_ref().is_some_and(|w| w.is_finished()) {
        a.last_error = match a.worker.take().map(|w| w.join()) {
            Some(Ok(e)) => e,
            Some(Err(_)) => Some("the upload thread stopped".into()),
            None => None,
        };
        a.last_publish = Instant::now();
    }
}

/// Called every frame while a vault is open: publish what was saved a
/// little after the last change, on a worker thread, and refresh the
/// lease now and then. The UI thread only ever tries the session's
/// lock: while the worker publishes, it does nothing.
pub fn tick() {
    let Ok(mut g) = ACTIVE.lock() else { return };
    let Some(a) = g.as_mut() else { return };
    reap_worker(a);
    if a.worker.is_some() {
        return;
    }
    let Ok(mut s) = a.session.try_lock() else {
        return;
    };
    if !s.is_writable() {
        return;
    }
    if a.last_heartbeat.elapsed() >= HEARTBEAT_EVERY {
        let _ = s.heartbeat();
        a.last_heartbeat = Instant::now();
    }
    let due = a.last_publish.elapsed() >= PUBLISH_EVERY && s.has_unpublished();
    drop(s);
    if due {
        a.worker = Some(spawn_publish(a.session.clone(), false));
    }
}

/// One line for the browser header, if the open vault is a bundle.
pub fn status_line() -> Option<String> {
    let g = ACTIVE.lock().ok()?;
    let a = g.as_ref()?;
    let uploading = || Some("sync bundle * uploading...".to_string());
    if a.worker.is_some() {
        return uploading();
    }
    let Ok(s) = a.session.try_lock() else {
        return uploading();
    };
    let mut line = format!(
        "sync bundle * commit #{} by {}",
        s.head().m.seq,
        s.head().m.device_label
    );
    if !s.is_writable() {
        line.push_str(" * read-only");
    } else if s.has_unpublished() {
        line.push_str(" * changes not uploaded yet");
    } else {
        line.push_str(" * uploaded");
    }
    if let Some(e) = &a.last_error {
        line.push_str(&format!(" * last upload failed: {e}"));
    }
    Some(line)
}

/// Publish, merge concurrent commits, remove the lease (waiting for an
/// upload in progress first). Returns a summary for a toast.
pub fn finish_active_session() -> Option<String> {
    let mut a = ACTIVE.lock().ok()?.take()?;
    if let Some(w) = a.worker.take() {
        let _ = w.join();
    }
    let mut s = match a.session.lock() {
        Ok(s) => s,
        Err(_) => {
            return Some("Sync bundle: the session was lost; changes stay on this device".into());
        }
    };
    match s.finish_detached() {
        Ok(r) => {
            let mut parts = Vec::new();
            if let Some(c) = r.published {
                parts.push(format!("uploaded commit #{}", c.seq));
            }
            if r.merged > 0 {
                parts.push(format!(
                    "merged {} change set(s) from other devices",
                    r.merged
                ));
            }
            if r.conflicts > 0 {
                parts.push(format!("{} conflict copie(s) made", r.conflicts));
            }
            for n in &r.keyslot_notes {
                parts.push(format!("keyslots: {n}"));
            }
            (!parts.is_empty()).then(|| format!("Sync bundle: {}", parts.join(", ")))
        }
        Err(e) => Some(format!(
            "Sync bundle: upload at lock failed ({e}); it is kept on this device"
        )),
    }
}

/// For an in-process mount of a bundle: publish while mounted and at
/// unmount.
pub fn install_mount_hook() {
    if ACTIVE.lock().map(|g| g.is_none()).unwrap_or(true) {
        return;
    }
    let mut last = Instant::now();
    luksbox_mount::set_commit_hook(Some(Box::new(move |p| match p {
        // Called with the mounted vault locked: only start the upload
        // here, so file operations do not wait for it.
        luksbox_mount::CommitPoint::Periodic => {
            if let Ok(mut g) = ACTIVE.lock()
                && let Some(a) = g.as_mut()
            {
                reap_worker(a);
                if last.elapsed() >= Duration::from_secs(120) && a.worker.is_none() {
                    a.worker = Some(spawn_publish(a.session.clone(), true));
                    last = Instant::now();
                }
            }
        }
        // Waits for an upload in progress, then publishes the rest.
        luksbox_mount::CommitPoint::Unmount => {
            let taken = ACTIVE.lock().ok().and_then(|mut g| g.take());
            if let Some(mut a) = taken {
                if let Some(w) = a.worker.take() {
                    let _ = w.join();
                }
                if let Ok(mut s) = a.session.lock() {
                    let _ = s.finish_detached();
                }
            }
        }
    })));
}

/// A new private folder, outside any synced folder, to build a vault in
/// that then becomes a sync bundle (New vault > Sync bundle). Folders an
/// interrupted creation left behind more than a day ago are removed.
pub fn new_staging_dir() -> std::io::Result<PathBuf> {
    staging_dir_in(&local_root())
}

fn staging_dir_in(local_root: &Path) -> std::io::Result<PathBuf> {
    let root = local_root.join("creating");
    if let Ok(entries) = std::fs::read_dir(&root) {
        for e in entries.flatten() {
            let stale = e
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age > Duration::from_secs(24 * 3600));
            if stale {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = root.join(format!("{}-{nanos}", std::process::id()));
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(&dir)?;
    Ok(dir)
}

/// One earlier version of the open bundle (the Versions view).
pub struct Version {
    pub hash: [u8; 32],
    /// `YYYY-MM-DD HHMM`, UTC.
    pub when: String,
    /// Seconds since then.
    pub age_secs: u64,
    pub device: String,
    pub what: &'static str,
}

fn active_session() -> Result<Arc<Mutex<Session>>, String> {
    ACTIVE
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|a| a.session.clone()))
        .ok_or_else(|| "no sync bundle is open".to_string())
}

/// Whether the open bundle may be written (restoring writes into it).
pub fn is_writable() -> bool {
    ACTIVE
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|a| a.writable))
        .unwrap_or(false)
}

/// The open bundle's versions, newest first, without the commits that
/// only record a clean-up (`sync gc`). Waits for an upload in progress:
/// call it off the UI thread.
pub fn versions() -> Result<Vec<Version>, String> {
    use luksbox_sync::manifest::CommitKind;
    let session = active_session()?;
    let s = session
        .lock()
        .map_err(|_| "the sync session is unavailable".to_string())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Ok(s.snapshots()
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|v| v.kind != CommitKind::Gc)
        .map(|v| Version {
            hash: v.hash,
            when: bundle::stamp(v.wall_clock_ns),
            age_secs: now.saturating_sub(v.wall_clock_ns / 1_000_000_000),
            device: v.device_label,
            what: match v.kind {
                CommitKind::Convert => "created",
                CommitKind::Commit => "changes",
                CommitKind::Merge => "merged with another device",
                CommitKind::Rotation => "new master key",
                CommitKind::Restore => "restored files",
                CommitKind::Gc => "clean-up",
            },
        })
        .collect())
}

/// One version, opened read-only to browse it. Waits like `versions`.
pub fn open_version(hash: &[u8; 32]) -> Result<luksbox_vfs::Vfs, String> {
    let session = active_session()?;
    let s = session
        .lock()
        .map_err(|_| "the sync session is unavailable".to_string())?;
    s.snapshot_view(hash).map_err(|e| e.to_string())
}

/// Copy `inner` (a file or folder) from a version back into the open
/// vault, next to the original as "<name> (restored <date>)", and save.
/// Returns the new path.
pub fn restore(
    view: &mut luksbox_vfs::Vfs,
    live: &mut luksbox_vfs::Vfs,
    inner: &str,
) -> Result<String, String> {
    let to = luksbox_sync::gc::restore_path(view, live, inner).map_err(|e| e.to_string())?;
    live.flush().map_err(|e| e.to_string())?;
    Ok(to)
}

/// Delete the sync bundle at `path` and this device's state for it
/// (`bundle::fs::delete`); returns what to tell the user.
pub fn delete_bundle(path: &Path) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    folder_icon::unset(path);
    let r = bundle::fs::delete(path, &local_root()).map_err(|e| e.to_string())?;
    let mut msg = format!("deleted the sync bundle {}", path.display());
    if !r.folder_removed {
        msg.push_str("; its folder was kept because it holds other files");
        if let Some(f) = r.foreign_sample.first() {
            msg.push_str(&format!(" (for example {f})"));
        }
    }
    Ok(msg)
}

/// Turn the open file vault into a sync bundle at `dest` (the vault file
/// is not changed).
pub fn convert(container: &mut Container, dest: &Path) -> Result<String, String> {
    convert_in(container, dest, &local_root())
}

fn convert_in(container: &mut Container, dest: &Path, local_root: &Path) -> Result<String, String> {
    // Read safely and checked against this vault (never a planted link).
    let hybrid = bundle::fs::hybrid_sidecar_for(container).map_err(|e| e.to_string())?;
    let bid = bundle::fs::convert(
        container,
        dest,
        local_root,
        &bundle::ConvertOptions {
            page_size: bundle::DEFAULT_PAGE_SIZE,
            device_label: device_label(),
            hybrid_sidecar: hybrid,
        },
    )
    .map_err(|e| e.to_string())?;
    #[cfg(target_os = "linux")]
    folder_icon::set(dest);
    Ok(bid.to_hex())
}

/// The bundle icon on bundle folders (Linux). GNOME Files and the other
/// file managers built on GIO show a folder's `metadata::custom-icon`,
/// which GVfs keeps on this computer: nothing is written into the
/// bundle, nothing syncs. Set where a bundle is created or opened, so
/// each computer that uses it shows it. Best-effort, in the background;
/// `LUKSBOX_NO_FOLDER_ICON=1` turns it off (GVfs then keeps no record of
/// the bundle's path).
#[cfg(target_os = "linux")]
mod folder_icon {
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    const PNG: &[u8] = include_bytes!("../assets/bundle-folder.png");

    fn enabled() -> bool {
        std::env::var_os("LUKSBOX_NO_FOLDER_ICON").is_none_or(|v| v.is_empty() || v == "0")
    }

    /// The icon as a file a file manager can read, written once to this
    /// user's data folder.
    fn icon_file() -> Option<PathBuf> {
        let dir = dirs::data_dir()?.join("luksbox").join("icons");
        let p = dir.join("bundle-folder.png");
        if std::fs::read(&p).ok().as_deref() != Some(PNG) {
            std::fs::create_dir_all(&dir).ok()?;
            luksbox_core::file_util::atomic_secure_write(&p, PNG).ok()?;
        }
        Some(p)
    }

    /// `file://` URI of an absolute path, percent-encoding every byte
    /// but unreserved characters and `/`.
    pub(super) fn file_uri(path: &Path) -> String {
        use std::os::unix::ffi::OsStrExt;
        let mut s = String::from("file://");
        for &b in path.as_os_str().as_bytes() {
            if b.is_ascii_alphanumeric() || b"/-._~".contains(&b) {
                s.push(b as char);
            } else {
                s.push_str(&format!("%{b:02X}"));
            }
        }
        s
    }

    fn gio(args: &[&std::ffi::OsStr]) {
        if let Some(gio) = crate::app::resolved_gio_program() {
            let _ = Command::new(gio)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }

    pub(super) fn set(bundle: &Path) {
        if !enabled() {
            return;
        }
        let Ok(bundle) = std::fs::canonicalize(bundle) else {
            return;
        };
        std::thread::spawn(move || {
            let Some(icon) = icon_file() else {
                return;
            };
            let uri = file_uri(&icon);
            gio(&[
                "set".as_ref(),
                "-t".as_ref(),
                "string".as_ref(),
                bundle.as_os_str(),
                "metadata::custom-icon".as_ref(),
                uri.as_ref(),
            ]);
        });
    }

    /// Before deleting a bundle: forget its icon.
    pub(super) fn unset(bundle: &Path) {
        if let Ok(bundle) = std::fs::canonicalize(bundle) {
            gio(&[
                "set".as_ref(),
                "-t".as_ref(),
                "unset".as_ref(),
                bundle.as_os_str(),
                "metadata::custom-icon".as_ref(),
            ]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::{self, CreateOpts, KdfStrength, SlotKindArg};
    use luksbox_core::{CipherSuite, SlotKind};
    use zeroize::Zeroizing;

    /// New vault > Sync bundle, without the window: the vault built in
    /// the staging folder converts into a bundle that opens at once with
    /// the vault's key (no credential asked again), that the unlock form
    /// can inspect, and that opens with the same passphrase once the
    /// staging folder is gone.
    #[test]
    fn a_vault_built_in_staging_becomes_a_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        let staging = staging_dir_in(&state).unwrap();
        assert!(staging.starts_with(state.join("creating")));
        let opts = CreateOpts {
            path: staging.join("v.lbx"),
            header_path: None,
            cipher: CipherSuite::Aes256GcmSiv,
            kind: SlotKindArg::Passphrase,
            passphrase: Some(Zeroizing::new("correct horse".into())),
            backup_passphrase: None,
            pin: None,
            pad_files: false,
            hide_sizes: false,
            anchor_path: None,
            enable_recovery_passphrase: false,
            hybrid_kyber_path: None,
            hybrid_seed_pw: None,
            kdf: KdfStrength::Interactive,
            use_deniable: false,
            use_v3_format: true,
            header_v3: true,
            max_size: 0,
        };
        let mut opened = ops::create_vault(opts)
            .and_then(|o| ops::apply_header_v3(o, true))
            .unwrap();
        opened.vfs.flush().unwrap();
        let dest = tmp.path().join("v.lbxs");
        convert_in(opened.vfs.container_mut(), &dest, &state).unwrap();
        let mvk = opened.vfs.container().mvk_clone();
        drop(opened);
        std::fs::remove_dir_all(&staging).unwrap();

        // Opened at once with the key, as `finish_bundle_create` does.
        let (session, c, report) = bundle::fs::open_with_key(
            &dest,
            &state,
            &mvk,
            &OpenOptions {
                device_label: "test".into(),
                read_only: false,
            },
        )
        .unwrap();
        assert!(report.writable);
        let mut vfs = luksbox_vfs::Vfs::open(c).unwrap();
        let id = vfs.create(vfs.root_id(), "first.txt").unwrap();
        vfs.write(id, 0, b"hello").unwrap();
        vfs.flush().unwrap();
        drop(vfs);
        session.close().unwrap();

        assert!(is_bundle(&dest));
        let slots = ops::inspect_slots(&dest, None).unwrap();
        assert!(
            slots.iter().any(|(_, k)| *k == SlotKind::Passphrase),
            "{slots:?}"
        );
        let (session, _container, report) = bundle::fs::open(
            &dest,
            &state,
            &mut UnlockMaterial::Passphrase(b"correct horse"),
            &OpenOptions {
                device_label: "test".into(),
                read_only: false,
            },
        )
        .unwrap();
        assert!(report.writable);
        session.close().unwrap();
    }

    /// What the Versions view calls, on a real bundle folder: the list
    /// (newest first, labelled), opening one version, and copying a file
    /// back from it into the open vault.
    #[test]
    fn versions_are_listed_opened_and_restored_from() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(2 << 20));
        let kdf = luksbox_core::Argon2idParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        };
        let mut c = Container::create_with_passphrase(
            &tmp.path().join("v.lbx"),
            None,
            CipherSuite::Aes256GcmSiv,
            kdf,
            b"pw",
        )
        .unwrap();
        let dest = tmp.path().join("v.lbxs");
        convert_in(&mut c, &dest, &state).unwrap();
        drop(c);
        let (mut session, c, report) = bundle::fs::open(
            &dest,
            &state,
            &mut UnlockMaterial::Passphrase(b"pw"),
            &OpenOptions {
                device_label: "Laptop".into(),
                read_only: false,
            },
        )
        .unwrap();
        let mut vfs = luksbox_vfs::Vfs::open(c).unwrap();
        let id = vfs.create(vfs.root_id(), "n.txt").unwrap();
        vfs.write(id, 0, b"one").unwrap();
        vfs.flush().unwrap();
        session.publish().unwrap().unwrap();
        vfs.write(id, 0, b"two").unwrap();
        vfs.flush().unwrap();
        session.publish().unwrap().unwrap();
        *ACTIVE.lock().unwrap() = Some(Active {
            session: Arc::new(Mutex::new(session)),
            worker: None,
            notices: Vec::new(),
            last_publish: Instant::now(),
            last_heartbeat: Instant::now(),
            last_error: None,
            writable: report.writable,
        });

        let list = versions().unwrap();
        assert!(list.len() >= 3);
        assert_eq!(list.last().unwrap().what, "created");
        assert_eq!(list[0].what, "changes");
        // This device's name, recorded when it converted the vault.
        assert_eq!(list[0].device, device_label());
        assert!(list[0].age_secs < 600);
        assert!(is_writable());
        let mut view = open_version(&list[1].hash).unwrap();
        let to = restore(&mut view, &mut vfs, "/n.txt").unwrap();
        assert!(
            to.starts_with("/n (restored ") && to.ends_with(").txt"),
            "{to}"
        );
        let rid = vfs.lookup_path(&to).unwrap();
        let mut buf = [0u8; 3];
        vfs.read(rid, 0, &mut buf).unwrap();
        assert_eq!(&buf, b"one");

        drop(ACTIVE.lock().unwrap().take());
        assert!(versions().is_err());
        assert!(!is_writable());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn folder_icon_uris_are_percent_encoded() {
        assert_eq!(
            folder_icon::file_uri(Path::new("/home/a b/r\u{e9}sum\u{e9}#1.png")),
            "file:///home/a%20b/r%C3%A9sum%C3%A9%231.png"
        );
    }

    /// A staging folder an interrupted creation left behind is removed
    /// once it is a day old; a recent one (another creation in progress)
    /// is kept.
    #[cfg(unix)]
    #[test]
    fn stale_staging_folders_are_removed() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("state");
        let old = staging_dir_in(&state).unwrap();
        std::fs::write(old.join("v.lbx"), b"x").unwrap();
        std::fs::File::open(&old)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - Duration::from_secs(2 * 24 * 3600))
            .unwrap();
        let recent = staging_dir_in(&state).unwrap();
        let fresh = staging_dir_in(&state).unwrap();
        assert!(!old.exists());
        assert!(recent.is_dir() && fresh.is_dir() && recent != fresh);
    }
}
