// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Sync bundles (`.lbxs`) from the command line.
//!
//! Every command that opens a vault also accepts a sync bundle folder:
//! the unlock helpers read the bundle's newest header to decide how to
//! prompt, `open_with_material` opens a sync session instead of a file,
//! and when the command is done `finish_active_session` publishes what
//! it saved and merges concurrent commits. `luksbox sync ...` adds the
//! bundle-only operations (convert, export, status, push, verify,
//! snapshots, gc) and `luksbox merge` merges two copies of a `.lbx`
//! (for example a conflict copy a sync client made).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use clap::Subcommand;
use luksbox_core::HEADER_SIZE;
use luksbox_format::hybrid_sidecar::{self, HybridEntry, SidecarBundle};
use luksbox_format::{Container, UnlockMaterial};
use luksbox_sync::SyncError;
use luksbox_sync::bundle::{self, ConvertOptions, OpenOptions, OpenReport, Session};
use luksbox_sync::graph::Notice;
use luksbox_vfs::{InodeKind, Vfs};

use crate::{Result, UnlockArgs};

/// The sync session of the bundle the current command opened, if any.
pub(crate) static SESSION: Mutex<Option<Session>> = Mutex::new(None);

/// Set by commands that only inspect a bundle (`sync verify`, listing
/// snapshots): the session is a read-only view, so it neither merges
/// other devices' commits nor publishes anything.
static OPEN_READ_ONLY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(crate) fn is_bundle(path: &Path) -> bool {
    bundle::fs::is_bundle(path)
}

/// Per-device sync state: `$LUKSBOX_SYNC_STATE_DIR`, else
/// `<data dir>/luksbox/sync` (`$XDG_DATA_HOME` or `~/.local/share` on
/// Linux, `~/Library/Application Support` on macOS, `%APPDATA%` on
/// Windows).
pub(crate) fn local_root() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("LUKSBOX_SYNC_STATE_DIR") {
        note_state_dir_override();
        return Ok(PathBuf::from(p));
    }
    Ok(data_dir()?.join("luksbox").join("sync"))
}

/// This device's automatic rollback anchors for vaults in cloud folders:
/// `$LUKSBOX_SYNC_STATE_DIR/anchors`, else `<data dir>/luksbox/anchors`.
pub(crate) fn anchors_dir() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("LUKSBOX_SYNC_STATE_DIR") {
        note_state_dir_override();
        return Ok(PathBuf::from(p).join("anchors"));
    }
    Ok(data_dir()?.join("luksbox").join("anchors"))
}

static STATE_DIR_NOTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// R16-12: the state folder holds what rollback detection compares
/// against; pointing it elsewhere starts from "trust what is there".
/// Said once, so it is never silent.
fn note_state_dir_override() {
    if !STATE_DIR_NOTED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        eprintln!(
            "note: LUKSBOX_SYNC_STATE_DIR is set: sync state and rollback anchors are kept \
             there instead of the application data folder"
        );
    }
}

/// Set by `luksbox merge`, which opens the copies on purpose.
static QUIET_CLOUD_NOTES: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// A single-file vault in a cloud folder, opened without `--anchor`
/// (phase 0 of `docs/CLOUD_SYNC_DESIGN.md`): attach this device's
/// automatic anchor, say on the first open that the folder is synced,
/// and point at copies the sync client made.
pub(crate) fn attach_auto_anchor(cont: &mut Container) -> Result<()> {
    if cont.is_external() || cont.is_deniable() {
        return Ok(());
    }
    // R16-12: an opt-out from rollback detection is never silent.
    if std::env::var_os(luksbox_sync::cloud::NO_AUTO_ANCHOR_ENV)
        .is_some_and(|v| !v.is_empty() && v != "0")
        && luksbox_sync::cloud::cloud_service(cont.vault_path()).is_some()
    {
        eprintln!(
            "warning: {} is set: an older copy of this vault put back by the sync service \
             is not detected",
            luksbox_sync::cloud::NO_AUTO_ANCHOR_ENV
        );
    }
    if let Some(a) = luksbox_sync::cloud::attach_auto_anchor(cont, &anchors_dir()?)?
        && a.created
    {
        eprintln!(
            "note: this vault is in a {} folder. Use it on one device at a time and let the \
             sync finish before switching: changes made on two devices at once end up in \
             separate copies. A sync bundle handles several devices (`luksbox sync convert`, \
             see docs/SYNC_BUNDLES.md).",
            a.service
        );
        eprintln!(
            "  This device now keeps a rollback anchor for this vault in {} ({}=1 turns it off).",
            a.path.display(),
            luksbox_sync::cloud::NO_AUTO_ANCHOR_ENV
        );
    }
    let vault = cont.vault_path();
    if !QUIET_CLOUD_NOTES.load(std::sync::atomic::Ordering::Relaxed)
        && luksbox_sync::cloud::cloud_service(vault).is_some()
    {
        let copies = luksbox_sync::cloud::conflict_copies(vault);
        if let Some(first) = copies.first() {
            // The names are whatever was put in the synced folder.
            eprintln!("warning: copies of this vault next to it may hold changes this file lacks:");
            for c in &copies {
                eprintln!("  {}", shown(c));
            }
            // The copy first: the result keeps the second file's
            // keyslots (F1).
            eprintln!(
                "  Merge one in with `{}`, check the result, then put it in place of the vault.",
                luksbox_sync::cloud::merge_command(first, vault)
            );
        }
    }
    Ok(())
}

/// The metadata half of the automatic anchor, once the vault is open
/// (no-op for any other anchor).
pub(crate) fn settle_auto_anchor(vfs: &mut Vfs) -> Result<()> {
    let dir = anchors_dir()?;
    Ok(luksbox_sync::cloud::settle_auto_anchor(vfs, &dir)?)
}

pub(crate) fn is_auto_anchor(cont: &Container) -> bool {
    anchors_dir()
        .map(|d| luksbox_sync::cloud::is_auto_anchor(cont, &d))
        .unwrap_or(false)
}

/// The application data folder. R16-10: never the working folder as a
/// fallback. `cd ~/Dropbox && env -i luksbox ...` (or a service unit
/// without HOME) would otherwise put the device's sealed unpublished
/// changes, its identity and its rollback anchors inside the synced
/// folder, where the provider gets them.
fn data_dir() -> Result<PathBuf> {
    data_dir_opt().ok_or_else(|| {
        "no application data folder is known (HOME / XDG_DATA_HOME / APPDATA is not set, or \
         is not an absolute path); set LUKSBOX_SYNC_STATE_DIR to a private folder outside any \
         synced folder"
            .into()
    })
}

/// The environment variable `name` as a folder, if it is set to an
/// absolute path. A relative value (`HOME=.`, `XDG_DATA_HOME=data`) would
/// put the state under the working folder, which may be the synced
/// folder itself (R16-10); the XDG spec says to ignore such a value.
fn absolute_env_dir(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

fn data_dir_opt() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        if let Some(h) = absolute_env_dir("HOME") {
            return Some(h.join("Library").join("Application Support"));
        }
    }
    #[cfg(windows)]
    {
        if let Some(a) = absolute_env_dir("APPDATA") {
            return Some(a);
        }
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        if let Some(x) = absolute_env_dir("XDG_DATA_HOME") {
            return Some(x);
        }
        if let Some(h) = absolute_env_dir("HOME") {
            return Some(h.join(".local").join("share"));
        }
    }
    None
}

/// How this device names itself in commits and conflict copies:
/// `$LUKSBOX_DEVICE_LABEL`, else the host name.
pub(crate) fn device_label() -> String {
    if let Ok(l) = std::env::var("LUKSBOX_DEVICE_LABEL")
        && !l.trim().is_empty()
    {
        return l;
    }
    hostname().unwrap_or_else(|| "device".to_string())
}

#[cfg(unix)]
fn hostname() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: valid buffer and length; gethostname NUL-terminates on
    // success when the name fits.
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } != 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..end])
        .ok()
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(not(unix))]
fn hostname() -> Option<String> {
    std::env::var("COMPUTERNAME").ok().filter(|s| !s.is_empty())
}

fn sync_to_format(e: SyncError) -> luksbox_format::Error {
    match e {
        SyncError::Format(f) => f,
        other => luksbox_format::Error::Io(std::io::Error::other(other.to_string())),
    }
}

/// The 8 KiB header an unlock prompt inspects. `header_src` is the
/// vault (or its `--header` file); for a sync bundle it is the newest
/// header object. Only used to decide how to prompt: the unlock itself
/// verifies everything.
pub(crate) fn read_header_src(
    header_src: &Path,
    vault: &Path,
) -> std::io::Result<[u8; HEADER_SIZE]> {
    if header_src == vault && is_bundle(vault) {
        return bundle::fs::newest_header(vault).map_err(|e| std::io::Error::other(e.to_string()));
    }
    let mut f = luksbox_core::file_util::open_existing_read_no_follow_policy(header_src)?;
    let mut buf = [0u8; HEADER_SIZE];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

fn bundle_sidecar(vault: &Path) -> std::result::Result<SidecarBundle, luksbox_format::Error> {
    let bytes = bundle::fs::newest_hybrid(vault)
        .map_err(sync_to_format)?
        .ok_or_else(|| {
            luksbox_format::Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "this sync bundle has no post-quantum sidecar",
            ))
        })?;
    hybrid_sidecar::parse_bundle(&bytes)
}

/// `hybrid_sidecar::read_bundle`, or the bundle's sidecar object.
#[cfg_attr(not(feature = "fido2-hardware"), allow(dead_code))]
pub(crate) fn read_hybrid_sidecar(
    vault: &Path,
    sidecar_path: &Path,
) -> std::result::Result<SidecarBundle, luksbox_format::Error> {
    if is_bundle(vault) {
        return bundle_sidecar(vault);
    }
    hybrid_sidecar::read_bundle(sidecar_path)
}

/// `hybrid_sidecar::read_for_vault`, or for a bundle its sidecar object
/// checked against the newest header's salt.
pub(crate) fn read_hybrid_for_vault(
    sidecar_path: &Path,
    vault: &Path,
    header_path: Option<&Path>,
) -> std::result::Result<Vec<HybridEntry>, luksbox_format::Error> {
    if header_path.is_none() && is_bundle(vault) {
        let sc = bundle_sidecar(vault)?;
        let header = bundle::fs::newest_header(vault).map_err(sync_to_format)?;
        let h = luksbox_core::Header::from_bytes(&header)?;
        hybrid_sidecar::verify_binding(&sc, &h.header_salt)?;
        return Ok(sc.entries);
    }
    hybrid_sidecar::read_for_vault(sidecar_path, vault, header_path)
}

fn print_report(path: &Path, r: &OpenReport) {
    for n in &r.notices {
        match n {
            Notice::FirstOpen => eprintln!(
                "note: first time this device opens {}; it is trusted as found",
                path.display()
            ),
            Notice::Pending { count } => {
                eprintln!("note: {count} commit(s) still arriving from the sync service")
            }
            Notice::Missing { seq, .. } => eprintln!(
                "warning: a commit (#{seq}) another device saw is not here yet: \
                 the vault is read-only until it arrives (sync lag, or the \
                 provider is withholding it)"
            ),
            Notice::Equivocation { seq, .. } => eprintln!(
                "warning: two installations used one device identity (commit #{seq}); \
                 both versions were kept"
            ),
            Notice::HeaderFork { heads } => eprintln!(
                "warning: {heads} devices changed the keyslots concurrently; \
                 not merged automatically"
            ),
            Notice::UnmergedLocalChanges { recoverable: true } => eprintln!(
                "warning: changes saved on this device earlier could not be merged \
                 automatically (the keyslots changed on another device since). They are \
                 shown read-only: copy out what you need or export them (`luksbox sync \
                 export`), then `luksbox sync discard-local --yes` to write again"
            ),
            Notice::UnmergedLocalChanges { recoverable: false } => eprintln!(
                "warning: changes saved on this device earlier were made on a version that \
                 is not in the bundle here. If the sync is still running, wait for it to \
                 finish and open the vault again: they are merged then. They are gone only \
                 if that version was removed by `luksbox sync gc` after a long time offline; \
                 discard them (`luksbox sync discard-local --yes`) only when you are sure \
                 of that. The vault is read-only until then"
            ),
            Notice::UnpublishedLocalChanges { shown: true } => eprintln!(
                "note: changes saved on this device earlier are not uploaded yet; they are \
                 shown (read-only) and included in an export, and upload the next time the \
                 vault opens read-write"
            ),
            Notice::UnpublishedLocalChanges { shown: false } => eprintln!(
                "note: changes saved on this device earlier are not uploaded yet and are \
                 not shown here (they were made on an older version); they upload the next \
                 time the vault opens read-write"
            ),
            Notice::MergeBaseMissing {
                heads,
                local_changes,
            } => {
                if *heads > 0 {
                    eprintln!(
                        "warning: {heads} concurrent version(s) were not merged: the version \
                         they come from is not complete in the bundle (the sync is still \
                         running, or the provider is withholding or has removed it). They are \
                         kept, and merged once it is there"
                    );
                }
                if *local_changes {
                    eprintln!(
                        "warning: changes saved on this device earlier cannot be merged yet: \
                         the version they come from is not complete in the bundle. They are \
                         shown (read-only) and merged once it is there"
                    );
                }
            }
            Notice::OlderThanSeen => eprintln!(
                "warning: the newest version this device has seen is not complete in the \
                 bundle (files missing or damaged: the sync is still running, or the provider \
                 is withholding or has altered them); an OLDER version is shown, read-only"
            ),
        }
    }
    for n in &r.keyslot_notes {
        eprintln!("note: {}", crate::sanitize_for_terminal(n));
    }
    if r.new_identity {
        eprintln!("note: this device's identity was in use elsewhere; it took a new one");
    }
    if r.restored_local_changes {
        eprintln!("note: changes saved on this device earlier were restored");
    }
    // Labels come from other devices' leases in the synced folder.
    for (label, writable) in &r.open_elsewhere {
        eprintln!(
            "note: also open on {}{}",
            crate::sanitize_for_terminal(label),
            if *writable { " (read-write)" } else { "" }
        );
    }
    if r.foreign_entries > 0 {
        eprintln!(
            "note: {} file(s) in the bundle folder are not part of it (left untouched)",
            r.foreign_entries
        );
    }
    if !r.writable && !OPEN_READ_ONLY.load(std::sync::atomic::Ordering::Relaxed) {
        eprintln!("note: opened read-only");
    }
}

/// `Container::open`, or for a sync bundle a sync session (kept in
/// `SESSION` until `finish_active_session`).
pub(crate) fn open_with_material(
    path: &Path,
    header_path: Option<&Path>,
    material: UnlockMaterial<'_>,
) -> std::result::Result<Container, luksbox_format::Error> {
    if !is_bundle(path) {
        return Container::open(path, header_path, material);
    }
    if header_path.is_some() {
        return Err(luksbox_format::Error::UnsupportedForExternalStorage(
            "--header",
        ));
    }
    // One bundle session at a time: publish the previous one first (the
    // wizard can open several vaults in one run).
    finish_active_session()
        .map_err(|e| luksbox_format::Error::Io(std::io::Error::other(e.to_string())))?;
    let mut material = material;
    let opts = OpenOptions {
        device_label: device_label(),
        read_only: OPEN_READ_ONLY.load(std::sync::atomic::Ordering::Relaxed),
    };
    let root = local_root()
        .map_err(|e| luksbox_format::Error::Io(std::io::Error::other(e.to_string())))?;
    let (session, container, report) =
        bundle::fs::open(path, &root, &mut material, &opts).map_err(sync_to_format)?;
    print_report(path, &report);
    // R16-08: an upload that failed where nobody saw it (a background
    // mount) is reported here, at the next open.
    if let Ok(Some(e)) = session.last_publish_error() {
        eprintln!(
            "warning: the last upload from this device failed ({}); the changes are kept \
             here and the upload is retried",
            crate::sanitize_for_terminal(&e)
        );
    }
    if let Ok(mut g) = SESSION.lock() {
        *g = Some(session);
    }
    Ok(container)
}

/// [`open_with_material`] for a sync bundle whose master key is already
/// in hand: the Windows background mount helper, which gets the key from
/// the `luksbox mount` that unlocked the bundle (handoff protocol v3),
/// and the wizard right after it made a bundle. Each header is checked
/// against the key; the session is kept in `SESSION` as for any other
/// open.
pub(crate) fn open_bundle_with_key(
    path: &Path,
    mvk: &luksbox_core::MasterVolumeKey,
) -> Result<Container> {
    if !is_bundle(path) {
        return Err(format!("{} is not a sync bundle", path.display()).into());
    }
    finish_active_session()?;
    let opts = OpenOptions {
        device_label: device_label(),
        read_only: false,
    };
    let root = local_root()?;
    let (session, container, report) = bundle::fs::open_with_key(path, &root, mvk, &opts)?;
    print_report(path, &report);
    if let Ok(mut g) = SESSION.lock() {
        *g = Some(session);
    }
    Ok(container)
}

/// Let go of the bundle session without publishing or closing its lease:
/// for the parent of a background mount, whose child process now owns
/// the session (R16-13). Without this the parent published (possibly a
/// merge) and closed the lease under the running mount, from the same
/// device identity.
pub(crate) fn forget_active_session() {
    if let Ok(mut g) = SESSION.lock()
        && let Some(s) = g.take()
    {
        std::mem::forget(s);
    }
}

/// Take the bundle session for its final publish. A panic in a periodic
/// publish (it runs on its own thread while a bundle is mounted) poisons
/// the lock: the session's in-memory state is then not used to publish,
/// but everything it saved is staged on this device and goes up the next
/// time the bundle opens. Say so instead of skipping the upload in
/// silence.
fn take_session_for_finish() -> Option<Session> {
    match SESSION.lock() {
        Ok(mut g) => g.take(),
        Err(_) => {
            eprintln!(
                "luksbox: an earlier upload from this device stopped with an internal error, so \
                 the last changes were not uploaded now; they are saved on this device and \
                 uploaded the next time the bundle is opened (or with `luksbox sync push`)"
            );
            None
        }
    }
}

/// End of a command: publish what the bundle session saved, merge
/// concurrent commits, remove the lease.
pub(crate) fn finish_active_session() -> Result<()> {
    let taken = take_session_for_finish();
    let Some(mut s) = taken else { return Ok(()) };
    let r = s.finish_detached()?;
    report_finish(&s, &r);
    Ok(())
}

/// What a session's final publish did, on stderr (the macOS GUI shows
/// these lines from its mount helper).
fn report_finish(s: &Session, r: &luksbox_sync::bundle::FinishReport) {
    if let Some(c) = r.published {
        eprintln!("published commit #{} to {}", c.seq, s.display().display());
    }
    if r.merged > 0 {
        eprintln!(
            "merged {} concurrent commit(s){}",
            r.merged,
            if r.conflicts > 0 {
                format!(", {} conflict copie(s) made", r.conflicts)
            } else {
                String::new()
            }
        );
    }
    for n in &r.keyslot_notes {
        eprintln!("note: {}", crate::sanitize_for_terminal(n));
    }
    if r.header_forks > 0 {
        eprintln!("warning: keyslot changes made concurrently on two devices were not merged");
    }
    if r.base_missing > 0 {
        eprintln!(
            "warning: {} concurrent version(s) were not merged: the version they come from is \
             not complete in the bundle yet; they are merged once it has arrived",
            r.base_missing
        );
    }
}

/// Printed on stderr when a mount of a bundle ends, before its last
/// upload and what it did (`report_finish`): the macOS GUI reads the
/// lines after it from its mount helper (`BUNDLE_UNMOUNT_LINE` there).
pub(crate) const UNMOUNT_UPLOAD_LINE: &str = "luksbox: unmounted, uploading the last changes";

/// For a mount of a bundle: publish now and then while mounted, and
/// everything (with merges) at unmount. Survives the fork of a
/// background mount.
pub(crate) fn install_mount_hook() {
    if SESSION.lock().map(|g| g.is_none()).unwrap_or(true) {
        return;
    }
    let mut last = std::time::Instant::now();
    luksbox_mount::set_commit_hook(Some(Box::new(move |p| match p {
        // Called with the mounted vault locked: start the upload on a
        // thread, and never wait for one in progress (it holds the
        // session), so file operations do not wait for it.
        luksbox_mount::CommitPoint::Periodic => {
            if last.elapsed() >= std::time::Duration::from_secs(120) {
                last = std::time::Instant::now();
                std::thread::spawn(|| {
                    let Ok(mut g) = SESSION.try_lock() else {
                        return;
                    };
                    let Some(s) = g.as_mut() else { return };
                    if let Err(e) = s.publish() {
                        eprintln!("luksbox: publish failed (will retry): {e}");
                    }
                    let _ = s.heartbeat();
                });
            }
        }
        // Waits for an upload in progress, then publishes the rest.
        luksbox_mount::CommitPoint::Unmount => {
            let taken = take_session_for_finish();
            if let Some(mut s) = taken {
                eprintln!("{UNMOUNT_UPLOAD_LINE}");
                match s.finish_detached() {
                    Ok(r) => report_finish(&s, &r),
                    Err(e) => eprintln!("luksbox: publishing at unmount failed: {e}"),
                }
            }
        }
    })));
}

/// Whether `path` names a sync bundle to create: a folder name ending in
/// `.lbxs` (`luksbox create ~/Dropbox/vault.lbxs`).
pub(crate) fn is_bundle_name(path: &Path) -> bool {
    path.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("lbxs"))
}

/// A vault being created as a sync bundle (`luksbox create
/// <folder>.lbxs`, the wizard's "Sync bundle"): built as a vault file in
/// a private staging folder outside any synced folder, then converted
/// into `dest` with [`convert_into_bundle`], as New vault > Sync bundle
/// does in the GUI. The staging folder is removed when this is dropped,
/// however the creation ends.
pub(crate) struct BundleStaging {
    pub(crate) dest: PathBuf,
    /// The vault file to create (inside the staging folder).
    pub(crate) vault: PathBuf,
    dir: PathBuf,
}

/// A new sync bundle's folder, checked before anything is made: it must
/// not exist yet, and the folder it goes in must.
pub(crate) fn check_new_bundle_dest(dest: &Path) -> Result<()> {
    if std::fs::symlink_metadata(dest).is_ok() {
        return Err(format!(
            "{} already exists: pick a new folder name for the sync bundle",
            dest.display()
        )
        .into());
    }
    if let Some(parent) = dest.parent().filter(|p| !p.as_os_str().is_empty())
        && !parent.is_dir()
    {
        return Err(format!("{} is not a folder", parent.display()).into());
    }
    Ok(())
}

/// `path` as a sync bundle folder name: `.lbx` becomes `.lbxs`, and any
/// other name gets `.lbxs` added (`vault` -> `vault.lbxs`).
pub(crate) fn with_bundle_extension(path: PathBuf) -> PathBuf {
    match path.extension() {
        Some(e) if e.eq_ignore_ascii_case("lbxs") => path,
        Some(e) if e.eq_ignore_ascii_case("lbx") => path.with_extension("lbxs"),
        _ => {
            let mut s = path.into_os_string();
            s.push(".lbxs");
            PathBuf::from(s)
        }
    }
}

impl BundleStaging {
    /// Checks `dest` (see [`check_new_bundle_dest`]) before anything is
    /// made.
    pub(crate) fn new(dest: &Path) -> Result<Self> {
        check_new_bundle_dest(dest)?;
        let dir = bundle::fs::new_staging_dir(&local_root()?)
            .map_err(|e| format!("could not create a staging folder: {e}"))?;
        let stem = dest
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "vault".into());
        Ok(Self {
            dest: dest.to_path_buf(),
            vault: dir.join(format!("{stem}.lbx")),
            dir,
        })
    }
}

impl Drop for BundleStaging {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Turn the vault open in `c` into a sync bundle at `dest` (the vault
/// file is not changed; save it first). A bundle folder this call made
/// is removed again when the conversion fails halfway (a full disk), so
/// the next attempt does not find a half bundle that "already exists";
/// a folder that appeared meanwhile (synced down from another device) is
/// never touched. Returns the bundle id.
pub(crate) fn convert_into_bundle(
    c: &mut Container,
    dest: &Path,
    page_size: u32,
) -> Result<String> {
    // Read safely and checked against this vault (never a planted link).
    let hybrid = bundle::fs::hybrid_sidecar_for(c)?;
    let root = local_root()?;
    let existed = dest.symlink_metadata().is_ok();
    let r = bundle::fs::convert(
        c,
        dest,
        &root,
        &ConvertOptions {
            page_size,
            device_label: device_label(),
            hybrid_sidecar: hybrid,
        },
    );
    match r {
        Ok(bid) => Ok(bid.to_hex()),
        Err(e) => {
            // `FsStore::create` makes the folder exclusively: "already
            // exists" is its refusal, before anything was written.
            let created = !existed
                && !matches!(&e, SyncError::Io(io) if io.kind() == std::io::ErrorKind::AlreadyExists);
            if created && is_bundle(dest) {
                let _ = bundle::fs::delete(dest, &root);
            }
            let mut msg = format!("could not create the sync bundle: {e}");
            if created && dest.exists() {
                msg.push_str(&format!(
                    " (delete the incomplete folder {} before trying again)",
                    dest.display()
                ));
            }
            Err(msg.into())
        }
    }
}

/// [`convert_into_bundle`] for the vault open in `vfs`, saved first so
/// the bundle holds everything.
pub(crate) fn convert_open_vault(vfs: &mut Vfs, dest: &Path) -> Result<String> {
    vfs.flush()?;
    convert_into_bundle(vfs.container_mut(), dest, bundle::DEFAULT_PAGE_SIZE)
}

/// What to tell the user once a sync bundle exists.
pub(crate) fn print_bundle_next_steps(dest: &Path) {
    eprintln!(
        "  keep it inside the folder your sync service syncs (Dropbox, Google Drive, \
         OneDrive, iCloud Drive, Nextcloud, Syncthing)\n  \
         every luksbox command takes the folder in place of a .lbx: `luksbox ls {} /`\n  \
         on your other devices, open the folder once it has synced there",
        dest.display()
    );
}

pub(crate) fn refuse_bundle(path: &Path, what: &str) -> Result<()> {
    if is_bundle(path) {
        return Err(format!(
            "{what} is not available for a sync bundle; export it first \
             (`luksbox sync export {} vault.lbx`)",
            path.display()
        )
        .into());
    }
    Ok(())
}

#[derive(Subcommand)]
pub(crate) enum SyncCommand {
    /// Turn a vault into a sync bundle: a folder to keep in Dropbox,
    /// Google Drive, OneDrive, iCloud Drive, Nextcloud or Syncthing.
    /// Only changed parts are uploaded, edits on several devices are
    /// merged, and rollback by the provider is detected. The vault file
    /// itself is not changed.
    Convert {
        /// The vault (.lbx) to convert.
        vault: PathBuf,
        /// The bundle folder to create (for example ~/Dropbox/vault.lbxs).
        bundle: PathBuf,
        /// Page size: 1M, 4M (default) or 16M. Smaller pages upload less
        /// per change but make more files.
        #[arg(long, default_value = "4M")]
        page_size: String,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    /// Write a sync bundle back out as a single .lbx file.
    Export {
        bundle: PathBuf,
        /// The .lbx file to create (must not exist).
        output: PathBuf,
        /// Export an earlier version instead of the newest (a prefix of
        /// its id from `luksbox sync snapshots`): the way out when the
        /// newest version's files arrived damaged.
        #[arg(long)]
        snapshot: Option<String>,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    /// Show the bundle's state: newest commit, devices, open sessions,
    /// changes not published yet.
    Status {
        bundle: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    /// Publish changes this device saved, and merge concurrent commits.
    Push {
        bundle: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    /// Read every file of the newest commit, checking every object.
    Verify {
        bundle: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    /// List snapshots, or copy a file or folder out of one back into the
    /// vault (as "<name> (restored <date>)").
    Snapshots {
        bundle: PathBuf,
        /// Snapshot to restore from (a prefix of its id from the list).
        #[arg(long)]
        restore: Option<String>,
        /// Path inside the vault to restore (with --restore).
        #[arg(long)]
        path: Option<String>,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    /// Drop changes saved on this device that could not be merged
    /// (`luksbox` said so when opening the bundle), so it can write again.
    /// Export them first if you need them.
    DiscardLocal {
        bundle: PathBuf,
        /// Really delete them.
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    /// Delete objects no kept commit needs. Two passes: a run records
    /// what is unused; a run after the grace period deletes it if it is
    /// still unused. Never touches files that are not part of the bundle.
    Gc {
        bundle: PathBuf,
        /// Keep every commit younger than this many days.
        #[arg(long, default_value_t = 30)]
        retention_days: u64,
        /// Delete recorded objects only this many days after recording
        /// (counted on this device too, whatever the recording device's
        /// clock said). Objects no commit refers to yet wait 90 days.
        /// 0 deletes in the next run, without the wait that protects a
        /// device that was offline: it needs --yes.
        #[arg(long, default_value_t = 7)]
        grace_days: u64,
        /// Report only.
        #[arg(long)]
        dry_run: bool,
        /// Confirm `--grace-days 0`.
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
}

fn page_size(s: &str) -> Result<u32> {
    match s
        .to_ascii_uppercase()
        .trim_end_matches("IB")
        .trim_end_matches('B')
    {
        "1M" | "1" => Ok(1 << 20),
        "4M" | "4" => Ok(4 << 20),
        "16M" | "16" => Ok(16 << 20),
        other => Err(format!("page size must be 1M, 4M or 16M, not {other}").into()),
    }
}

fn hex8(h: &[u8; 32]) -> String {
    h[..8].iter().map(|b| format!("{b:02x}")).collect()
}

fn when(ns: u64) -> String {
    // Seconds since the epoch is enough for a list; the GUI formats it.
    let secs = ns / 1_000_000_000;
    let age = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().saturating_sub(secs))
        .unwrap_or(0);
    match age {
        0..=119 => format!("{age} s ago"),
        120..=7199 => format!("{} min ago", age / 60),
        7200..=172_799 => format!("{} h ago", age / 3600),
        _ => format!("{} days ago", age / 86_400),
    }
}

/// The one snapshot whose id starts with `prefix`.
fn snapshot_by_prefix(s: &mut Session, prefix: &str) -> Result<[u8; 32]> {
    let snaps = s.snapshots()?;
    let m: Vec<_> = snaps
        .iter()
        .filter(|x| hex8(&x.hash).starts_with(prefix))
        .collect();
    match m.as_slice() {
        [one] => Ok(one.hash),
        [] => Err("no snapshot with that id".into()),
        _ => Err("that id prefix matches several snapshots".into()),
    }
}

fn with_session<T>(f: impl FnOnce(&mut Session) -> Result<T>) -> Result<T> {
    let mut g = SESSION.lock().map_err(|_| "sync session lock poisoned")?;
    let s = g.as_mut().ok_or("not a sync bundle")?;
    f(s)
}

fn require_bundle(path: &Path) -> Result<()> {
    if !is_bundle(path) {
        return Err(format!("{} is not a sync bundle folder", path.display()).into());
    }
    Ok(())
}

pub(crate) fn cmd_sync(cmd: SyncCommand) -> Result<()> {
    match cmd {
        SyncCommand::Convert {
            vault,
            bundle: dest,
            page_size: ps,
            unlock,
        } => {
            if is_bundle(&vault) {
                return Err("that is already a sync bundle".into());
            }
            let ps = page_size(&ps)?;
            // F2: a rolled-back vault is refused here as at any open,
            // but the vault is only read, so its anchors are only
            // compared (never created or moved).
            let mut c = open_to_read_checked(&vault, &unlock)?;
            let bid = convert_into_bundle(&mut c, &dest, ps)?;
            eprintln!(
                "converted {} into the sync bundle {} (id {bid})\n  the original file is \
                 unchanged; keep using the bundle from now on",
                vault.display(),
                dest.display(),
            );
            print_bundle_next_steps(&dest);
            Ok(())
        }
        SyncCommand::Export {
            bundle: src,
            output,
            snapshot,
            unlock,
        } => {
            require_bundle(&src)?;
            match snapshot {
                None => {
                    let mut c = crate::open_container(&src, &unlock)?;
                    bundle::export(&mut c, &output)?;
                    c.set_read_only();
                    drop(c);
                }
                Some(prefix) => {
                    // Only reads: no merge, no publish, and the newest
                    // version's own objects are never opened.
                    OPEN_READ_ONLY.store(true, std::sync::atomic::Ordering::Relaxed);
                    let c = crate::open_container(&src, &unlock)?;
                    drop(c);
                    let hash = with_session(|s| snapshot_by_prefix(s, &prefix))?;
                    let view = with_session(|s| Ok(s.snapshot_view(&hash)?))?;
                    let mut c = view.close()?;
                    bundle::export(&mut c, &output)?;
                    drop(c);
                }
            }
            eprintln!("exported {} to {}", src.display(), output.display());
            Ok(())
        }
        SyncCommand::Status { bundle: b, unlock } => {
            require_bundle(&b)?;
            let c = crate::open_container(&b, &unlock)?;
            drop(c);
            with_session(|s| {
                let h = s.head();
                println!("bundle      {}", b.display());
                println!("id          {}", s.bundle_id().to_hex());
                println!(
                    "newest      commit #{} by {} ({}, {:?})",
                    h.m.seq,
                    crate::sanitize_for_terminal(&h.m.device_label),
                    when(h.m.wall_clock_ns),
                    h.m.kind
                );
                println!("keyslots    generation {}", h.m.header.generation);
                println!(
                    "this device {}",
                    crate::sanitize_for_terminal(&s.device_state().label)
                );
                println!(
                    "unpublished {}",
                    if s.has_unpublished() { "yes" } else { "no" }
                );
                if let Some(e) = s.last_publish_error()? {
                    println!("last upload error: {}", crate::sanitize_for_terminal(&e));
                }
                for (label, w) in s.fresh_leases()? {
                    println!(
                        "open on     {}{}",
                        crate::sanitize_for_terminal(&label),
                        if w { " (read-write)" } else { "" }
                    );
                }
                let snaps = s.snapshots()?;
                println!("snapshots   {}", snaps.len());
                Ok(())
            })
        }
        SyncCommand::Push { bundle: b, unlock } => {
            require_bundle(&b)?;
            let c = crate::open_container(&b, &unlock)?;
            drop(c);
            // `finish_active_session` publishes and merges at the end.
            Ok(())
        }
        SyncCommand::Verify { bundle: b, unlock } => {
            require_bundle(&b)?;
            OPEN_READ_ONLY.store(true, std::sync::atomic::Ordering::Relaxed);
            let c = crate::open_container(&b, &unlock)?;
            let mut vfs = Vfs::open_read_only(c)?;
            let (files, bytes, errors) = verify_tree(&mut vfs);
            println!("checked {files} file(s), {bytes} bytes");
            if errors.is_empty() {
                println!("every object verified");
                Ok(())
            } else {
                // Vault paths, named by whoever wrote them.
                for e in &errors {
                    println!("FAILED {}", crate::sanitize_for_terminal(e));
                }
                Err(format!("{} file(s) failed verification", errors.len()).into())
            }
        }
        SyncCommand::Snapshots {
            bundle: b,
            restore,
            path,
            unlock,
        } => {
            require_bundle(&b)?;
            // Listing only reads; a restore writes into the vault.
            OPEN_READ_ONLY.store(restore.is_none(), std::sync::atomic::Ordering::Relaxed);
            let c = crate::open_container(&b, &unlock)?;
            match restore {
                None => {
                    drop(c);
                    with_session(|s| {
                        for snap in s.snapshots()? {
                            println!(
                                "{}  #{:<5} {:<20} {:<12} {:?}",
                                hex8(&snap.hash),
                                snap.seq,
                                crate::sanitize_for_terminal(&snap.device_label),
                                when(snap.wall_clock_ns),
                                snap.kind
                            );
                        }
                        Ok(())
                    })
                }
                Some(prefix) => {
                    let inner = path.ok_or("--restore needs --path <path inside the vault>")?;
                    let mut live = Vfs::open(c)?;
                    let snap_hash = with_session(|s| snapshot_by_prefix(s, &prefix))?;
                    let mut view = with_session(|s| Ok(s.snapshot_view(&snap_hash)?))?;
                    let restored = luksbox_sync::gc::restore_path(&mut view, &mut live, &inner)?;
                    live.flush()?;
                    drop(live);
                    println!(
                        "restored {} as {}",
                        crate::sanitize_for_terminal(&inner),
                        crate::sanitize_for_terminal(&restored)
                    );
                    Ok(())
                }
            }
        }
        SyncCommand::DiscardLocal {
            bundle: b,
            yes,
            unlock,
        } => {
            require_bundle(&b)?;
            if !yes {
                return Err("this deletes the changes saved on this device that were \
                            never published; export them first if you need them, then \
                            add --yes"
                    .into());
            }
            // A read-only session never restores them.
            OPEN_READ_ONLY.store(true, std::sync::atomic::Ordering::Relaxed);
            let c = crate::open_container(&b, &unlock)?;
            drop(c);
            let n = with_session(|s| Ok(s.discard_local_changes()?))?;
            println!(
                "discarded the local changes ({n} changed page(s)); open the bundle again to write"
            );
            Ok(())
        }
        SyncCommand::Gc {
            bundle: b,
            retention_days,
            grace_days,
            dry_run,
            yes,
            unlock,
        } => {
            require_bundle(&b)?;
            // F9: with no grace period, two runs back to back delete
            // what the first recorded, so the two-run protection of a
            // device that was offline (or an upload in progress
            // elsewhere) is gone. Never by accident.
            if grace_days == 0 && !dry_run {
                if !yes {
                    return Err("--grace-days 0 deletes recorded objects in the next run, \
                                without the wait that protects a computer that was offline \
                                or is uploading: what it has not published yet may then be \
                                lost. Add --yes to do it anyway (--dry-run shows what would \
                                be deleted)"
                        .into());
                }
                eprintln!(
                    "warning: --grace-days 0: objects recorded as unused are deleted at the \
                     next run, even if another computer that was offline or is uploading still \
                     needs them"
                );
            }
            let c = crate::open_container(&b, &unlock)?;
            drop(c);
            const DAY: u64 = 24 * 3600 * 1_000_000_000;
            let r = with_session(|s| {
                Ok(s.gc(&luksbox_sync::gc::GcOptions {
                    retention_ns: retention_days.saturating_mul(DAY),
                    keep_last: 50,
                    grace_ns: grace_days.saturating_mul(DAY),
                    dry_run,
                    ..Default::default()
                })?)
            })?;
            println!(
                "kept {} commit(s); recorded {} unused object(s); deleted {}{}",
                r.roots,
                r.planned,
                r.deleted,
                if dry_run { " (dry run)" } else { "" }
            );
            if r.orphans > 0 {
                println!(
                    "{} of them belong to no commit yet (probably another device's upload \
                     in progress): they are kept 90 days",
                    r.orphans
                );
            }
            if r.foreign > 0 {
                println!(
                    "{} file(s) in the folder are not part of the bundle (untouched)",
                    r.foreign
                );
            }
            Ok(())
        }
    }
}

/// Read every file; collect the ones that fail.
fn verify_tree(vfs: &mut Vfs) -> (usize, u64, Vec<String>) {
    let mut files = 0;
    let mut bytes = 0u64;
    let mut errors = Vec::new();
    let mut q = vec![(vfs.root_id(), String::new())];
    let mut buf = zeroize::Zeroizing::new(vec![0u8; 1 << 20]);
    while let Some((d, p)) = q.pop() {
        let Ok(entries) = vfs.readdir(d) else {
            errors.push(format!("{p}/ (folder)"));
            continue;
        };
        for e in entries {
            let path = format!("{p}/{}", e.name);
            match e.kind {
                InodeKind::Directory => q.push((e.id, path)),
                InodeKind::File => {
                    files += 1;
                    let size = vfs.stat(e.id).map(|s| s.size).unwrap_or(0);
                    let mut off = 0u64;
                    while off < size {
                        match vfs.read(e.id, off, &mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                off += n as u64;
                                bytes += n as u64;
                            }
                            Err(_) => {
                                errors.push(path.clone());
                                break;
                            }
                        }
                    }
                }
                InodeKind::Symlink => {}
            }
        }
    }
    (files, bytes, errors)
}

/// Shown in messages: a path as typed, without control characters.
fn shown(p: &Path) -> String {
    crate::sanitize_for_terminal(&p.display().to_string())
}

/// What one rollback anchor vouches for, read without writing anything.
struct SeenGen {
    /// Where it comes from, for messages.
    source: String,
    metadata: u64,
    header: Option<u64>,
}

/// The rollback anchors that apply to the copy of a vault at `path`,
/// verified under `c`'s key (an unlocked copy of that vault), and never
/// created or moved: this device's automatic anchor for that path (a
/// vault in a cloud folder), and `--anchor`. For commands that only read
/// a copy (`luksbox merge`, `luksbox sync convert`): opening them the
/// usual way would record the copy as "seen" (creating an anchor for a
/// path met for the first time, moving one forward).
fn anchors_for(c: &Container, path: &Path, unlock: &UnlockArgs) -> Result<Vec<SeenGen>> {
    let mut out = Vec::new();
    if let Some(ap) = unlock.anchor.as_deref() {
        let a = luksbox_format::anchor::read_and_verify(ap, &c.mvk_clone(), c.header_salt())
            .map_err(|e| {
                format!(
                    "the anchor {} does not verify for {} ({e}): it belongs to another vault, \
                     or the master key changed since it was written",
                    ap.display(),
                    shown(path)
                )
            })?;
        out.push(SeenGen {
            source: format!("the anchor {}", ap.display()),
            metadata: a.generation,
            header: a.header_generation,
        });
    }
    static OPT_OUT_NOTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let opted_out = std::env::var_os(luksbox_sync::cloud::NO_AUTO_ANCHOR_ENV)
        .is_some_and(|v| !v.is_empty() && v != "0");
    if opted_out
        && luksbox_sync::cloud::cloud_service(path).is_some()
        && !OPT_OUT_NOTED.swap(true, std::sync::atomic::Ordering::Relaxed)
    {
        eprintln!(
            "warning: {} is set: an older copy of this vault put back by the sync service \
             is not detected",
            luksbox_sync::cloud::NO_AUTO_ANCHOR_ENV
        );
    }
    if let Some(a) = luksbox_sync::cloud::peek_auto_anchor(c, path, &anchors_dir()?)? {
        out.push(SeenGen {
            source: format!(
                "this device's rollback anchor for {} ({})",
                shown(path),
                a.path.display()
            ),
            metadata: a.metadata_generation,
            header: a.header_generation,
        });
    }
    Ok(out)
}

/// `sync convert`: the vault is only read, so its anchors are compared
/// (both halves of rollback detection, as at an ordinary open), never
/// created or moved. Returns the unlocked container, read-only.
fn open_to_read_checked(path: &Path, unlock: &UnlockArgs) -> Result<Container> {
    let c = crate::open_container_unanchored(path, unlock)?;
    let seen = anchors_for(&c, path, unlock)?;
    let header_gen = c.header_generation().unwrap_or(0);
    let vfs = Vfs::open_read_only(c)?;
    let meta_gen = vfs.vault_generation();
    for s in &seen {
        if let Some(h) = s.header
            && h > header_gen
        {
            return Err(format!(
                "ROLLBACK DETECTED: {} has seen keyslot table generation {h} of this vault, but \
                 {} has generation {header_gen} (older): an older keyslot table can bring back a \
                 revoked passphrase or key. Refusing to read it.",
                s.source,
                shown(path)
            )
            .into());
        }
        if s.metadata > meta_gen {
            return Err(format!(
                "ROLLBACK DETECTED: {} has seen generation {} of this vault, but {} is at \
                 generation {meta_gen} (older): what was saved since is missing. Refusing to read \
                 it.",
                s.source,
                s.metadata,
                shown(path)
            )
            .into());
        }
    }
    Ok(vfs.close()?)
}

/// One keyslot, by what it holds: its kind, KDF, wrapped master key,
/// FIDO2 / TPM material and Secure Enclave blob. `None` for an empty
/// slot. (`Keyslot::to_bytes` pads with fresh random bytes, so two
/// serializations of one slot differ.)
type SlotImage = Option<Vec<u8>>;

fn slot_image(k: &luksbox_core::Keyslot, sep: &Option<Vec<u8>>) -> SlotImage {
    if k.is_empty() {
        return None;
    }
    let mut v = vec![k.kind as u8, k.aad_version];
    v.extend_from_slice(&k.uuid);
    for x in [
        k.kdf_params.m_cost_kib,
        k.kdf_params.t_cost,
        k.kdf_params.p_cost,
    ] {
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.extend_from_slice(&k.kdf_salt);
    v.extend_from_slice(&k.aead_nonce);
    v.extend_from_slice(&k.wrapped_ct);
    v.extend_from_slice(&k.wrapped_tag);
    v.extend_from_slice(&k.fido2_hmac_salt);
    v.extend_from_slice(&(k.fido2_cred_id.len() as u64).to_le_bytes());
    v.extend_from_slice(&k.fido2_cred_id);
    if let Some(s) = sep {
        v.extend_from_slice(&(s.len() as u64).to_le_bytes());
        v.extend_from_slice(s);
    }
    Some(v)
}

fn keyslot_table(c: &Container) -> Vec<SlotImage> {
    c.header
        .keyslots
        .iter()
        .zip(c.header.sep_blobs.iter())
        .map(|(k, s)| slot_image(k, s))
        .collect()
}

/// The copies of a merge must be one vault under one master key: the
/// result is THEIRS' header (keyslots, wrapped master key, KDF costs)
/// over data re-encrypted from OURS (and read from BASE) under THEIRS'
/// key. Copies under different master keys mean a rotation happened
/// between them; carrying the older key forward would hand the vault to
/// every credential removed by that rotation (F1).
fn same_vault(
    theirs_c: &Container,
    other: &Container,
    theirs: &Path,
    other_p: &Path,
) -> Result<()> {
    if theirs_c.is_deniable() || other.is_deniable() {
        return Err("luksbox merge does not merge deniable vaults".into());
    }
    if theirs_c.header_salt() != other.header_salt() {
        return Err(format!(
            "{} and {} are not copies of the same vault: luksbox merge only combines two \
             copies of one vault (copy files across with `luksbox get` and `luksbox put`)",
            shown(other_p),
            shown(theirs)
        )
        .into());
    }
    // `MasterVolumeKey`'s `==` is a constant-time compare.
    if theirs_c.mvk_clone() != other.mvk_clone() {
        return Err(format!(
            "{} and {} are copies of the same vault under different master keys: the master \
             key was rotated (`luksbox rotate-mvk`) after they split. A copy from before a \
             rotation opens with every passphrase or key removed since, so luksbox merge never \
             carries one forward. Copy the files you need out of the older copy with `luksbox \
             get` and add them to the newer one with `luksbox put`.",
            shown(other_p),
            shown(theirs)
        )
        .into());
    }
    Ok(())
}

/// The result keeps THEIRS' keyslot table. Refuse when OURS' is known to
/// be newer (a revoke or a passphrase change made there would be undone),
/// or when neither is known to be newer and THEIRS holds a keyslot OURS
/// does not (unless `keep_theirs`).
fn check_keyslots(
    theirs_c: &Container,
    ours_c: &Container,
    theirs: &Path,
    ours: &Path,
    output: &Path,
    keep_theirs: bool,
) -> Result<()> {
    let t = keyslot_table(theirs_c);
    let o = keyslot_table(ours_c);
    if t == o {
        return Ok(());
    }
    // Generations of header v3; a pre-v3 header counts as 0 (an upgrade
    // to v3 is itself a newer header state).
    let tg = theirs_c.header_generation();
    let og = ours_c.header_generation();
    let (tn, on) = (tg.unwrap_or(0), og.unwrap_or(0));
    if tn > on {
        // Normal when the keyslots changed in THEIRS after the split;
        // say so, since a newer table can only come from someone who
        // holds the master key.
        eprintln!(
            "note: the result keeps the keyslots of {} (keyslot table generation {tn}, newer \
             than {} at {on}); if you did not change them yourself, check them with `luksbox \
             info` before using the result",
            shown(theirs),
            shown(ours)
        );
        return Ok(());
    }
    if tn < on {
        return Err(format!(
            "{} has an older keyslot table than {} (generation {tn} < {on}). The result keeps \
             the keyslots of the second file (THEIRS), so a passphrase or key removed in {} \
             since (a revoke, a changed passphrase) would open the result again. If {} is the \
             vault you keep, put it second: `luksbox merge \"{}\" \"{}\" -o {}`. If you did \
             not change the keyslots of {} yourself, do not: a copy with a newer keyslot table \
             you did not make is suspect.",
            shown(theirs),
            shown(ours),
            shown(ours),
            shown(ours),
            shown(theirs),
            shown(ours),
            shown(output),
            shown(ours)
        )
        .into());
    }
    // Same generation (or no generations at all): keyslots changed in
    // both copies since they split, or headers that do not count.
    let extra = t
        .iter()
        .flatten()
        .any(|s| !o.iter().flatten().any(|x| x == s));
    if !extra {
        eprintln!(
            "note: keyslots that {} has and {} has not are not in the result; enroll them \
             again on the result if you need them",
            shown(ours),
            shown(theirs)
        );
        return Ok(());
    }
    if keep_theirs {
        eprintln!(
            "warning: --keep-theirs-keyslots: the result keeps the keyslots of {}, including \
             any that was removed in {}",
            shown(theirs),
            shown(ours)
        );
        return Ok(());
    }
    let why = if tg.is_none() && og.is_none() {
        "their headers are older than v3 and carry no keyslot generation".to_string()
    } else {
        format!("both changed their keyslots since they split (generation {tn} each)")
    };
    Err(format!(
        "{} and {} have different keyslot tables and neither is known to be the newer \
         ({why}). The result keeps the keyslots of {}: a passphrase or key removed in {} \
         would open it again. Compare them (`luksbox info`); if the keyslots of {} are the \
         ones to keep, add --keep-theirs-keyslots, else merge the other way round.",
        shown(ours),
        shown(theirs),
        shown(theirs),
        shown(ours),
        shown(theirs)
    )
    .into())
}

/// F2: neither copy of a merge may be older than what this device saw,
/// or the result (which counts as newer than both) would put an older
/// vault back for good. Every anchor that applies to one of the copies
/// applies to the vault: THEIRS' keyslot table must be at least the
/// newest one seen (the result keeps it), and the newer of the two
/// copies at least the newest metadata generation seen (the result
/// holds all of both).
fn check_merge_anchors(
    seen: &[SeenGen],
    theirs: (&Path, u64, u64),
    ours: (&Path, u64, u64),
    output: &Path,
) -> Result<()> {
    let (tp, t_header, t_gen) = theirs;
    let (op, o_header, o_gen) = ours;
    for s in seen {
        if let Some(h) = s.header
            && h > t_header
        {
            let fix = if o_header >= h {
                format!(
                    "{} has it: if it is the vault you keep, put it second (`luksbox merge \
                     \"{}\" \"{}\" -o {}`).",
                    shown(op),
                    shown(tp),
                    shown(op),
                    shown(output)
                )
            } else {
                "Neither copy has it: look for the newer version (the sync service's version \
                 history)."
                    .to_string()
            };
            return Err(format!(
                "ROLLBACK DETECTED: {} has seen keyslot table generation {h} of this vault, \
                 but {} (whose keyslots the result keeps) has generation {t_header} (older): \
                 a revoked passphrase or key would open the result. {fix}",
                s.source,
                shown(tp)
            )
            .into());
        }
        if s.metadata > t_gen.max(o_gen) {
            return Err(format!(
                "ROLLBACK DETECTED: {} has seen generation {} of this vault, but both copies \
                 are older ({}: {o_gen}, {}: {t_gen}): the merge result would put an older \
                 vault back, without what was saved since. Look for the newer version (the \
                 sync service's version history, another copy).",
                s.source,
                s.metadata,
                shown(op),
                shown(tp)
            )
            .into());
        }
    }
    Ok(())
}

/// The files of a merge result, removed again if the merge fails.
struct MergeOutput {
    files: Vec<PathBuf>,
    keep: bool,
}

impl Drop for MergeOutput {
    fn drop(&mut self) {
        if !self.keep {
            for f in &self.files {
                let _ = std::fs::remove_file(f);
            }
        }
    }
}

fn with_ext(p: &Path, ext: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

/// `luksbox merge`: merge two copies of one vault (`.lbx`), for example
/// the "conflicted copy" a sync client made. The result is a new file:
/// `theirs` with the changes of `ours` applied, conflicts kept as copies.
pub(crate) fn cmd_merge(
    ours: &Path,
    theirs: &Path,
    base: Option<&Path>,
    output: &Path,
    label: Option<String>,
    keep_theirs_keyslots: bool,
    unlock: &UnlockArgs,
) -> Result<()> {
    for p in [Some(ours), Some(theirs), base].into_iter().flatten() {
        refuse_bundle(p, "luksbox merge")?;
    }
    if unlock.header.is_some() {
        // One detached header cannot belong to all the copies, and the
        // result's header would be written into it.
        return Err(
            "luksbox merge needs vaults with their header inside the file; \
                    --header is not supported"
                .into(),
        );
    }
    QUIET_CLOUD_NOTES.store(true, std::sync::atomic::Ordering::Relaxed);
    // Everything the result consists of must be new: on failure it is
    // removed, and only what this run created.
    let sidecars: Vec<PathBuf> = ["meta-bak", "header-bak"]
        .iter()
        .map(|e| with_ext(output, e))
        .chain(std::iter::once(hybrid_sidecar::sidecar_path(output)))
        .collect();
    for p in std::iter::once(output.to_path_buf()).chain(sidecars.iter().cloned()) {
        if std::fs::symlink_metadata(&p).is_ok() {
            return Err(format!("{} already exists", shown(&p)).into());
        }
    }
    let mut result = MergeOutput {
        files: Vec::new(),
        keep: false,
    };
    // The output starts as a copy of `theirs` (streamed, never a link),
    // with its post-quantum sidecar if it has one: same vault, same
    // header salt, so the sidecar's binding holds for the copy.
    {
        let mut src = luksbox_core::file_util::open_existing_read_no_follow_policy(theirs)?;
        let mut f = luksbox_core::file_util::secure_create_new(output)?;
        // From here on the output and its sidecars (checked free above)
        // are this run's: removed again if it fails.
        result.files.push(output.to_path_buf());
        result.files.extend(sidecars);
        std::io::copy(&mut src, &mut f)?;
        f.sync_all()?;
        match hybrid_sidecar::read_sidecar_bytes(&hybrid_sidecar::sidecar_path(theirs)) {
            Ok(sc) => {
                luksbox_core::file_util::atomic_secure_create_new(
                    &hybrid_sidecar::sidecar_path(output),
                    &sc,
                )?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(format!("read the hybrid sidecar of {}: {e}", theirs.display()).into());
            }
        }
        luksbox_core::file_util::sync_parent_dir(output)?;
    }
    // No anchor is attached to any of them: the copies are only read,
    // and the result is not the vault yet (it gets one when it is put
    // in place and opened).
    let target_c = crate::open_container_unanchored(output, unlock)?;
    let ours_c = crate::open_container_unanchored(ours, unlock)?;
    let base_c = match base {
        Some(b) => Some(crate::open_container_unanchored(b, unlock)?),
        None => None,
    };
    same_vault(&target_c, &ours_c, theirs, ours)?;
    if let (Some(b), Some(bc)) = (base, base_c.as_ref()) {
        same_vault(&target_c, bc, theirs, b)?;
    }
    check_keyslots(
        &target_c,
        &ours_c,
        theirs,
        ours,
        output,
        keep_theirs_keyslots,
    )?;
    // The anchors of every copy's own path (the output is a byte copy of
    // THEIRS, so THEIRS' are looked up under its path) and --anchor.
    let mut seen = anchors_for(&target_c, theirs, unlock)?;
    for (p, c) in [(Some(ours), Some(&ours_c)), (base, base_c.as_ref())] {
        if let (Some(p), Some(c)) = (p, c) {
            let mut more = anchors_for(
                c,
                p,
                &UnlockArgs {
                    anchor: None,
                    ..unlock.clone()
                },
            )?;
            seen.append(&mut more);
        }
    }
    let t_header = target_c.header_generation().unwrap_or(0);
    let o_header = ours_c.header_generation().unwrap_or(0);
    let mut target = Vfs::open(target_c)?;
    let mut ours_v = Vfs::open_read_only(ours_c)?;
    let mut base_v = match base_c {
        Some(c) => Some(Vfs::open_read_only(c)?),
        None => None,
    };
    check_merge_anchors(
        &seen,
        (theirs, t_header, target.vault_generation()),
        (ours, o_header, ours_v.vault_generation()),
        output,
    )?;
    let stamp = {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        format!("{secs}")
    };
    let out = luksbox_merge::merge(
        base_v.as_mut(),
        &mut ours_v,
        &mut target,
        &luksbox_merge::Options {
            label: label.unwrap_or_else(|| {
                ours.file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "ours".into())
            }),
            stamp,
        },
    )?;
    // Newer than every copy it was made from, so a rollback anchor that
    // saw one of them (the automatic one of a vault in a cloud folder)
    // accepts the result once it is put in place of the vault.
    let newest = [
        Some(ours_v.vault_generation()),
        base_v.as_ref().map(Vfs::vault_generation),
    ]
    .into_iter()
    .flatten()
    .fold(target.vault_generation(), u64::max);
    target.raise_generation_to(newest + 1)?;
    target.flush()?;
    drop(target);
    result.keep = true;
    // Paths and notes name vault entries, which either copy's author
    // chose.
    for e in &out.events {
        println!(
            "{}: {}",
            crate::sanitize_for_terminal(&e.path),
            crate::sanitize_for_terminal(&e.what)
        );
    }
    println!(
        "merged into {}: {} change(s) applied, {} conflict copie(s)",
        output.display(),
        out.applied,
        out.conflicts
    );
    Ok(())
}
