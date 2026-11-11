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

fn local_root() -> Result<PathBuf, String> {
    if let Some(p) = std::env::var_os("LUKSBOX_SYNC_STATE_DIR") {
        note_state_dir_override();
        return Ok(PathBuf::from(p));
    }
    Ok(data_dir()?.join("luksbox").join("sync"))
}

/// This device's automatic rollback anchors for vaults in cloud folders
/// (shared with the command line).
fn anchors_dir() -> Result<PathBuf, String> {
    if let Some(p) = std::env::var_os("LUKSBOX_SYNC_STATE_DIR") {
        note_state_dir_override();
        return Ok(PathBuf::from(p).join("anchors"));
    }
    Ok(data_dir()?.join("luksbox").join("anchors"))
}

/// What the state-folder override warning says (R16-12).
const STATE_DIR_NOTE: &str = "LUKSBOX_SYNC_STATE_DIR is set: sync state and rollback anchors \
     are kept there instead of the application data folder. What rollback detection compares \
     against starts again from what is found there.";

/// Environment warnings (R16-12), shown once per run: pointing the state
/// folder elsewhere, or turning the automatic anchor off, is never
/// silent in the window either.
static ENV_NOTES: Mutex<Vec<String>> = Mutex::new(Vec::new());
static STATE_DIR_NOTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static NO_ANCHOR_NOTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn note_state_dir_override() {
    if !STATE_DIR_NOTED.swap(true, std::sync::atomic::Ordering::Relaxed)
        && let Ok(mut n) = ENV_NOTES.lock()
    {
        n.push(STATE_DIR_NOTE.to_string());
    }
}

fn no_auto_anchor_set() -> bool {
    std::env::var_os(luksbox_sync::cloud::NO_AUTO_ANCHOR_ENV)
        .is_some_and(|v| !v.is_empty() && v != "0")
}

/// The environment warnings not shown yet (taken once, for toasts).
pub fn take_env_notes() -> Vec<String> {
    ENV_NOTES
        .lock()
        .map(|mut n| std::mem::take(&mut *n))
        .unwrap_or_default()
}

/// The application data folder. R16-10: never the working folder as a
/// fallback, which may be the synced folder itself: the device's state
/// (sealed unpublished changes, its identity, its rollback anchors) would
/// then be uploaded to the provider. A relative HOME / XDG_DATA_HOME
/// would do the same (it resolves against the working folder), so only
/// an absolute folder is used.
fn data_dir() -> Result<PathBuf, String> {
    match dirs::data_dir() {
        Some(d) if d.is_absolute() => Ok(d),
        Some(d) => Err(format!(
            "the application data folder ({}) is not an absolute path (HOME / XDG_DATA_HOME \
             is relative), so it would be inside the working folder; set \
             LUKSBOX_SYNC_STATE_DIR to a private folder outside any synced folder",
            d.display()
        )),
        None => Err(
            "no application data folder is known (HOME / XDG_DATA_HOME / APPDATA is not set); \
             set LUKSBOX_SYNC_STATE_DIR to a private folder outside any synced folder"
                .to_string(),
        ),
    }
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
    // R16-12: the opt-out from rollback detection is never silent.
    if no_auto_anchor_set()
        && luksbox_sync::cloud::cloud_service(cont.vault_path()).is_some()
        && !NO_ANCHOR_NOTED.swap(true, std::sync::atomic::Ordering::Relaxed)
    {
        notes.push(format!(
            "{} is set: an older copy of this vault put back by the sync service is not \
             detected.",
            luksbox_sync::cloud::NO_AUTO_ANCHOR_ENV
        ));
    }
    if let Some(a) = luksbox_sync::cloud::attach_auto_anchor(cont, &anchors_dir()?)?
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
        if let Some(first) = copies.first() {
            // Names someone else put in the synced folder: shown without
            // control characters.
            let names: Vec<String> = copies
                .iter()
                .map(|p| {
                    format!(
                        "\"{}\"",
                        luksbox_sync::cloud::printable(
                            &p.file_name().unwrap_or_default().to_string_lossy()
                        )
                    )
                })
                .collect();
            // The copy first, the vault second: the result keeps the
            // vault's keyslots, never the copy's.
            notes.push(format!(
                "Copies of this vault next to it may hold changes it lacks: {}. Merge one in \
                 from the command line with `{}`, check the result, then put it in place of \
                 the vault.",
                names.join(", "),
                luksbox_sync::cloud::merge_command(first, vault)
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
    luksbox_sync::cloud::settle_auto_anchor(vfs, &anchors_dir()?)
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
                "Changes saved on this computer earlier were made on a version that is not \
                 in the bundle here. If the sync is still running, wait for it to finish and \
                 open the vault again: they are merged then. They are gone only if that \
                 version was removed by `luksbox sync gc` after a long time offline; discard \
                 them (`luksbox sync discard-local --yes`) only when you are sure of that. \
                 The vault stays read-only until then."
                    .into()
            }
            Notice::UnpublishedLocalChanges { shown: true } => {
                "Changes saved on this computer earlier have not been uploaded yet. They are \
                 shown (read-only) and included in an export; they upload the next time the \
                 vault opens read-write."
                    .into()
            }
            Notice::UnpublishedLocalChanges { shown: false } => {
                "Changes saved on this computer earlier have not been uploaded yet, and are \
                 not shown here (they were made on an older version). They upload the next \
                 time the vault opens read-write."
                    .into()
            }
            Notice::MergeBaseMissing {
                heads,
                local_changes,
            } => {
                let mut s = String::new();
                if *heads > 0 {
                    s.push_str(&format!(
                        "{heads} concurrent version(s) were not merged: the version they come \
                         from is not complete in the bundle (the sync is still running, or the \
                         provider is withholding or has removed it). They are kept, and merged \
                         once it is there."
                    ));
                }
                if *local_changes {
                    if !s.is_empty() {
                        s.push(' ');
                    }
                    s.push_str(
                        "Changes saved on this computer earlier cannot be merged yet: the \
                         version they come from is not complete in the bundle. They are shown \
                         (read-only) and merged once it is there.",
                    );
                }
                s
            }
            Notice::OlderThanSeen => {
                "The newest version this computer has seen is not complete in the bundle \
                 (files missing or damaged: the sync is still running, or the provider is \
                 withholding or has altered them). An OLDER version is shown, read-only."
                    .into()
            }
        });
    }
    for n in &r.keyslot_notes {
        out.push(format!("Keyslots: {}.", luksbox_sync::cloud::printable(n)));
    }
    if r.new_identity {
        out.push("This device's identity was in use elsewhere; it took a new one.".into());
    }
    if r.restored_local_changes {
        out.push("Changes saved on this device earlier were restored.".into());
    }
    // Device labels in leases come from other devices' sessions: shown
    // without control characters.
    for (label, w) in &r.open_elsewhere {
        out.push(format!(
            "Also open on {}{}.",
            luksbox_sync::cloud::printable(label),
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
    let root = local_root().map_err(|e| luksbox_format::Error::Io(std::io::Error::other(e)))?;
    let (session, container, report) =
        bundle::fs::open(path, &root, &mut material, &opts).map_err(to_format)?;
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
        bundle::fs::open_with_key(path, &local_root()?, mvk, &opts).map_err(|e| e.to_string())?;
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

/// Whether a bundle session is open or finishing (both need frames: the
/// publishing tick, and the toast when the finish ends).
pub fn session_active() -> bool {
    ACTIVE.lock().map(|g| g.is_some()).unwrap_or(false) || finishing()
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
        luksbox_sync::cloud::printable(&s.head().m.device_label)
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
    wait_finishing();
    let a = ACTIVE.lock().ok()?.take()?;
    finish_taken(a)
}

/// A session being finished in the background (`finish_in_background`).
static FINISHING: Mutex<Option<std::thread::JoinHandle<Option<String>>>> = Mutex::new(None);

/// `finish_active_session` on a thread: Lock returns at once while the
/// last upload and merge run (they used to freeze the window for as long
/// as the upload took). Returns whether a session was being finished.
pub fn finish_in_background() -> bool {
    wait_finishing();
    let Some(a) = ACTIVE.lock().ok().and_then(|mut g| g.take()) else {
        return false;
    };
    let h = std::thread::spawn(move || finish_taken(a));
    if let Ok(mut g) = FINISHING.lock() {
        *g = Some(h);
    }
    true
}

/// Whether a background finish is still running.
pub fn finishing() -> bool {
    FINISHING
        .lock()
        .map(|g| g.as_ref().is_some_and(|h| !h.is_finished()))
        .unwrap_or(false)
}

/// The outcome of a background finish that has ended, once.
pub fn poll_finishing() -> Option<Option<String>> {
    let mut g = FINISHING.lock().ok()?;
    if g.as_ref().is_some_and(|h| h.is_finished()) {
        let h = g.take()?;
        return Some(h.join().unwrap_or_else(|_| {
            Some("Sync bundle: the upload at lock stopped; changes stay on this device".into())
        }));
    }
    None
}

/// Wait for a background finish (before opening a bundle again: the
/// finishing session still holds this device's state for it).
fn wait_finishing() {
    let h = FINISHING.lock().ok().and_then(|mut g| g.take());
    if let Some(h) = h {
        let _ = h.join();
    }
}

fn finish_taken(mut a: Active) -> Option<String> {
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
                parts.push(format!("keyslots: {}", luksbox_sync::cloud::printable(n)));
            }
            if r.base_missing > 0 {
                parts.push(format!(
                    "{} concurrent version(s) not merged yet: the version they come from \
                     has not fully arrived",
                    r.base_missing
                ));
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
    bundle::fs::new_staging_dir(&local_root().map_err(std::io::Error::other)?)
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
            device: luksbox_sync::cloud::printable(&v.device_label),
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
    let r = bundle::fs::delete(path, &local_root()?).map_err(|e| e.to_string())?;
    let mut msg = format!("deleted the sync bundle {}", path.display());
    if let Some(id) = &r.local_state_kept {
        // Header object names are not authenticated: a folder whose
        // headers name another bundle's id never wipes that bundle's
        // state on this device.
        msg.push_str(&format!(
            "; this device's state for bundle {id}, which the folder's file names point to, \
             was kept: it is not the bundle this folder was opened as"
        ));
    }
    if !r.folder_removed {
        msg.push_str("; its folder was kept because it holds other files");
        // A name someone else put in the synced folder.
        if let Some(f) = r.foreign_sample.first() {
            msg.push_str(&format!(
                " (for example {})",
                luksbox_sync::cloud::printable(f)
            ));
        }
    }
    Ok(msg)
}

/// What `luksbox revoke` on a sync bundle says (R16-17), in the window.
pub const BUNDLE_REVOKE_WARNING: &str = "On a sync bundle, revoking a keyslot does not change \
     the master key, and the sync service keeps the old keyslot table: in the bundle folder \
     until a clean-up (`luksbox sync gc`), and in its version history for good. Whoever held \
     that credential can still derive the master key with it and read this vault, including \
     every later version. For a real revocation: export the bundle to a .lbx file (`luksbox \
     sync export`), rotate the master key of the exported file (`luksbox rotate-mvk`), convert \
     it into a new sync bundle (`luksbox sync convert`), and delete this one.";

/// A conversion into a sync bundle that failed.
#[derive(Debug)]
pub struct ConvertError {
    pub message: String,
    /// This call created the bundle folder (and may have left part of a
    /// bundle in it). `false` when the folder was already there (it
    /// appeared after the caller's check, for example synced down from
    /// another device) or the failure came before it was made: then the
    /// folder is not this call's to remove.
    pub created_folder: bool,
}

impl std::fmt::Display for ConvertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl ConvertError {
    fn before_folder(message: String) -> Self {
        Self {
            message,
            created_folder: false,
        }
    }
}

/// Turn the open file vault into a sync bundle at `dest` (the vault file
/// is not changed).
pub fn convert(container: &mut Container, dest: &Path) -> Result<String, ConvertError> {
    let root = local_root().map_err(ConvertError::before_folder)?;
    convert_in(container, dest, &root)
}

fn convert_in(
    container: &mut Container,
    dest: &Path,
    local_root: &Path,
) -> Result<String, ConvertError> {
    // Read safely and checked against this vault (never a planted link).
    let hybrid = bundle::fs::hybrid_sidecar_for(container)
        .map_err(|e| ConvertError::before_folder(e.to_string()))?;
    let existed = dest.symlink_metadata().is_ok();
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
    .map_err(|e| ConvertError {
        // `FsStore::create` makes the folder exclusively: "already
        // exists" is its refusal, before anything was written.
        created_folder: !existed
            && !matches!(&e, SyncError::Io(io) if io.kind() == std::io::ErrorKind::AlreadyExists),
        message: e.to_string(),
    })?;
    #[cfg(target_os = "linux")]
    folder_icon::set(dest);
    Ok(bid.to_hex())
}

/// [`convert`], removing what it wrote when it fails halfway (a full
/// disk), so the next attempt does not find a half bundle that "already
/// exists". Only a folder this call created is removed: one that
/// appeared meanwhile (synced down from another device) is never
/// touched.
pub fn convert_or_clean_up(container: &mut Container, dest: &Path) -> Result<String, String> {
    convert(container, dest).map_err(|e| {
        if e.created_folder && is_bundle(dest) {
            let _ = delete_bundle(dest);
        }
        e.message
    })
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
        let staging = bundle::fs::new_staging_dir(&state).unwrap();
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
        // Sets and clears the process-wide open session.
        let _env = crate::test_env_lock();
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

    /// F4: a bundle that appeared at the destination (synced down from
    /// another device after the window's check) makes the conversion
    /// fail as "not this call's folder", so it is never deleted.
    #[test]
    fn a_conversion_never_claims_a_folder_it_did_not_make() {
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
        std::fs::create_dir_all(dest.join("h")).unwrap();
        std::fs::write(dest.join("h").join("someone-else"), b"theirs").unwrap();
        assert!(is_bundle(&dest));
        let e = convert_in(&mut c, &dest, &state).unwrap_err();
        assert!(!e.created_folder, "{e}");
        assert_eq!(
            std::fs::read(dest.join("h").join("someone-else")).unwrap(),
            b"theirs"
        );
        // A free destination converts.
        let fresh = tmp.path().join("fresh.lbxs");
        convert_in(&mut c, &fresh, &state).unwrap();
        assert!(is_bundle(&fresh));
    }

    /// F7: a relative HOME (or XDG_DATA_HOME) is not used as the place
    /// for this device's sync state, and LUKSBOX_SYNC_STATE_DIR is said
    /// once.
    #[test]
    fn environment_overrides_are_never_silent() {
        let _env = crate::test_env_lock();
        let saved: Vec<(&str, Option<std::ffi::OsString>)> =
            ["HOME", "XDG_DATA_HOME", "LUKSBOX_SYNC_STATE_DIR"]
                .into_iter()
                .map(|k| (k, std::env::var_os(k)))
                .collect();
        // SAFETY: test-only; every test that changes these holds
        // `crate::test_env_lock()`.
        unsafe {
            std::env::set_var("HOME", "relative-home");
            std::env::set_var("XDG_DATA_HOME", "relative-data");
            std::env::remove_var("LUKSBOX_SYNC_STATE_DIR");
        }
        let relative = data_dir();
        let tmp = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("LUKSBOX_SYNC_STATE_DIR", tmp.path());
        }
        STATE_DIR_NOTED.store(false, std::sync::atomic::Ordering::Relaxed);
        let _ = take_env_notes();
        let root = local_root().unwrap();
        let anchors = anchors_dir().unwrap();
        let notes = take_env_notes();
        for (k, v) in saved {
            unsafe {
                match v {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
        // Windows takes APPDATA, which this test does not change.
        #[cfg(not(windows))]
        assert!(relative.is_err(), "{relative:?}");
        let _ = relative;
        assert_eq!(root, tmp.path());
        assert_eq!(anchors, tmp.path().join("anchors"));
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].contains("LUKSBOX_SYNC_STATE_DIR"), "{notes:?}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn folder_icon_uris_are_percent_encoded() {
        assert_eq!(
            folder_icon::file_uri(Path::new("/home/a b/r\u{e9}sum\u{e9}#1.png")),
            "file:///home/a%20b/r%C3%A9sum%C3%A9%231.png"
        );
    }
}
