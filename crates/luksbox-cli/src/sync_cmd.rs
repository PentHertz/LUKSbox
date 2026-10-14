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
pub(crate) fn local_root() -> PathBuf {
    if let Some(p) = std::env::var_os("LUKSBOX_SYNC_STATE_DIR") {
        return PathBuf::from(p);
    }
    data_dir().join("luksbox").join("sync")
}

/// This device's automatic rollback anchors for vaults in cloud folders:
/// `$LUKSBOX_SYNC_STATE_DIR/anchors`, else `<data dir>/luksbox/anchors`.
pub(crate) fn anchors_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("LUKSBOX_SYNC_STATE_DIR") {
        return PathBuf::from(p).join("anchors");
    }
    data_dir().join("luksbox").join("anchors")
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
    if let Some(a) = luksbox_sync::cloud::attach_auto_anchor(cont, &anchors_dir())?
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
        if !copies.is_empty() {
            eprintln!("warning: copies of this vault next to it may hold changes this file lacks:");
            for c in &copies {
                eprintln!("  {}", c.display());
            }
            eprintln!(
                "  Merge one in with `luksbox merge {} \"<copy>\" -o merged.lbx`, check the \
                 result, then put it in place of the vault.",
                vault.display()
            );
        }
    }
    Ok(())
}

/// The metadata half of the automatic anchor, once the vault is open
/// (no-op for any other anchor).
pub(crate) fn settle_auto_anchor(vfs: &mut Vfs) -> Result<()> {
    Ok(luksbox_sync::cloud::settle_auto_anchor(
        vfs,
        &anchors_dir(),
    )?)
}

pub(crate) fn is_auto_anchor(cont: &Container) -> bool {
    luksbox_sync::cloud::is_auto_anchor(cont, &anchors_dir())
}

fn data_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        if let Some(h) = std::env::var_os("HOME") {
            return PathBuf::from(h).join("Library").join("Application Support");
        }
    }
    #[cfg(windows)]
    {
        if let Some(a) = std::env::var_os("APPDATA") {
            return PathBuf::from(a);
        }
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        if let Some(x) = std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
            return PathBuf::from(x);
        }
        if let Some(h) = std::env::var_os("HOME") {
            return PathBuf::from(h).join(".local").join("share");
        }
    }
    PathBuf::from(".")
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
                 is no longer in the bundle and cannot be rebuilt; the vault is read-only \
                 until they are discarded (`luksbox sync discard-local --yes`)"
            ),
        }
    }
    for n in &r.keyslot_notes {
        eprintln!("note: {n}");
    }
    if r.new_identity {
        eprintln!("note: this device's identity was in use elsewhere; it took a new one");
    }
    if r.restored_local_changes {
        eprintln!("note: changes saved on this device earlier were restored");
    }
    for (label, writable) in &r.open_elsewhere {
        eprintln!(
            "note: also open on {label}{}",
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
    let (session, container, report) =
        bundle::fs::open(path, &local_root(), &mut material, &opts).map_err(sync_to_format)?;
    print_report(path, &report);
    if let Ok(mut g) = SESSION.lock() {
        *g = Some(session);
    }
    Ok(container)
}

/// End of a command: publish what the bundle session saved, merge
/// concurrent commits, remove the lease.
pub(crate) fn finish_active_session() -> Result<()> {
    let taken = SESSION.lock().ok().and_then(|mut g| g.take());
    let Some(mut s) = taken else { return Ok(()) };
    let r = s.finish_detached()?;
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
        eprintln!("note: {n}");
    }
    if r.header_forks > 0 {
        eprintln!("warning: keyslot changes made concurrently on two devices were not merged");
    }
    Ok(())
}

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
            let taken = SESSION.lock().ok().and_then(|mut g| g.take());
            if let Some(mut s) = taken
                && let Err(e) = s.finish_detached()
            {
                eprintln!("luksbox: publishing at unmount failed: {e}");
            }
        }
    })));
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
        #[arg(long, default_value_t = 7)]
        grace_days: u64,
        /// Report only.
        #[arg(long)]
        dry_run: bool,
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
            let mut c = crate::open_container(&vault, &unlock)?;
            let hybrid = bundle::fs::hybrid_sidecar_for(&c)?;
            let bid = bundle::fs::convert(
                &mut c,
                &dest,
                &local_root(),
                &ConvertOptions {
                    page_size: ps,
                    device_label: device_label(),
                    hybrid_sidecar: hybrid,
                },
            )?;
            eprintln!(
                "converted {} into the sync bundle {} (id {})\n  the original file is unchanged; \
                 keep using the bundle from now on",
                vault.display(),
                dest.display(),
                bid.to_hex()
            );
            Ok(())
        }
        SyncCommand::Export {
            bundle: src,
            output,
            unlock,
        } => {
            require_bundle(&src)?;
            let mut c = crate::open_container(&src, &unlock)?;
            bundle::export(&mut c, &output)?;
            c.set_read_only();
            drop(c);
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
                    h.m.device_label,
                    when(h.m.wall_clock_ns),
                    h.m.kind
                );
                println!("keyslots    generation {}", h.m.header.generation);
                println!("this device {}", s.device_state().label);
                println!(
                    "unpublished {}",
                    if s.has_unpublished() { "yes" } else { "no" }
                );
                for (label, w) in s.fresh_leases()? {
                    println!(
                        "open on     {label}{}",
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
                for e in &errors {
                    println!("FAILED {e}");
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
                                snap.device_label,
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
                    let snap_hash = with_session(|s| {
                        let snaps = s.snapshots()?;
                        let m: Vec<_> = snaps
                            .iter()
                            .filter(|x| hex8(&x.hash).starts_with(&prefix))
                            .collect();
                        match m.as_slice() {
                            [one] => Ok(one.hash),
                            [] => Err("no snapshot with that id".into()),
                            _ => Err("that id prefix matches several snapshots".into()),
                        }
                    })?;
                    let mut view = with_session(|s| Ok(s.snapshot_view(&snap_hash)?))?;
                    let restored = luksbox_sync::gc::restore_path(&mut view, &mut live, &inner)?;
                    live.flush()?;
                    drop(live);
                    println!("restored {inner} as {restored}");
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
            unlock,
        } => {
            require_bundle(&b)?;
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

/// `luksbox merge`: merge two copies of one vault (`.lbx`), for example
/// the "conflicted copy" a sync client made. The result is a new file:
/// `theirs` with the changes of `ours` applied, conflicts kept as copies.
pub(crate) fn cmd_merge(
    ours: &Path,
    theirs: &Path,
    base: Option<&Path>,
    output: &Path,
    label: Option<String>,
    unlock: &UnlockArgs,
) -> Result<()> {
    for p in [Some(ours), Some(theirs), base].into_iter().flatten() {
        refuse_bundle(p, "luksbox merge")?;
    }
    QUIET_CLOUD_NOTES.store(true, std::sync::atomic::Ordering::Relaxed);
    // The output starts as a copy of `theirs` (streamed, never a link),
    // with its post-quantum sidecar if it has one: same vault, same
    // header salt, so the sidecar's binding holds for the copy.
    {
        let mut src = luksbox_core::file_util::open_existing_read_no_follow_policy(theirs)?;
        let mut f = luksbox_core::file_util::secure_create_new(output)?;
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
    let mut target = Vfs::open(crate::open_container(output, unlock)?)?;
    let mut ours_v = Vfs::open_read_only(crate::open_container(ours, unlock)?)?;
    let mut base_v = match base {
        Some(b) => Some(Vfs::open_read_only(crate::open_container(b, unlock)?)?),
        None => None,
    };
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
    for e in &out.events {
        println!("{}: {}", e.path, e.what);
    }
    println!(
        "merged into {}: {} change(s) applied, {} conflict copie(s)",
        output.display(),
        out.applied,
        out.conflicts
    );
    Ok(())
}
