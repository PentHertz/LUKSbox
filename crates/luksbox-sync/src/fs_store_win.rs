// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! The bundle folder on disk, Windows.
//!
//! Same hostile-input rules as the Unix store (`fs_store.rs`), with the
//! Windows means the rest of LuksBox already uses against junctions:
//!
//! - Every file and folder is opened with `FILE_FLAG_OPEN_REPARSE_POINT`,
//!   so a final-component symlink or junction is opened as itself, and
//!   refused when it is a reparse point. The one reparse point accepted
//!   is a cloud file (`IO_REPARSE_TAG_CLOUD*`: OneDrive Files On-Demand
//!   and every other Cloud Files API provider), which is a placeholder
//!   for the file itself, not a redirection; it is then re-opened
//!   normally (so the provider can download it) and must be the same
//!   file.
//! - The handle's resolved path (`GetFinalPathNameByHandleW`) must equal
//!   the path the bundle expects (`<bundle>\<area>\[<shard>\]<leaf>`,
//!   built from grammar-checked names), and its last component must
//!   match exactly, case included: a junction anywhere inside the bundle
//!   resolves elsewhere, and a folder that differs only in case (`AB`
//!   for `ab`) is not taken for ours.
//! - Folders are pinned for the store's lifetime: the bundle folder and
//!   its area folders from `open`, a shard folder from its first use
//!   (verified once). A pinned
//!   folder is held open without `FILE_SHARE_DELETE`, so it cannot be
//!   renamed, deleted or replaced (by a junction) while the store
//!   creates, lists or removes entries in it by path. This is what the
//!   Unix store gets from `openat` / `unlinkat` on a folder descriptor.
//! - Reads are bounded by the expected size and checked for EOF. An
//!   object with more than one name (a hard link) is read like any other,
//!   as on Unix: sync clients make one while they upload the file, and
//!   authentication, which binds an object to its name, is what decides
//!   whether it is used.
//! - New objects are written to a `.tmp-<hex>` file in their folder,
//!   flushed, and installed with `MoveFileExW` without
//!   `MOVEFILE_REPLACE_EXISTING` (no clobber) and with
//!   `MOVEFILE_WRITE_THROUGH` (the rename is on disk when it returns):
//!   nothing is ever overwritten. Deletions remove the entry itself.
//!   `sweep_tmp` removes temporary files that a crash left.
//! - Sync clients and virus scanners open files without sharing them for
//!   a moment: opens, renames and deletions that fail with a sharing
//!   violation are retried with backoff (about 0.75 s in all) before the
//!   error is returned, and such an error is I/O, never a "refused"
//!   (damaged) object.

#![cfg(windows)]

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::time::Duration;

use std::collections::HashMap;
use std::sync::Mutex;

use luksbox_core::file_util::{final_path_by_handle, windows_paths_eq_ci};

use crate::error::{Result, SyncError};
use crate::names::{Area, Name, is_shard_name, is_tmp_name, tmp_name};
use crate::store::{Created, LenRule, Listing, ObjectStore};

const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_SHARE_READ: u32 = 0x1;
const FILE_SHARE_WRITE: u32 = 0x2;
const FILE_SHARE_DELETE: u32 = 0x4;
/// Share mode of a pinned folder: no `FILE_SHARE_DELETE`, so nobody can
/// rename or delete it while it is held.
const PIN_SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;
const ANY_SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
const ERROR_ACCESS_DENIED: i32 = 5;
const ERROR_SHARING_VIOLATION: i32 = 32;
const ERROR_LOCK_VIOLATION: i32 = 33;
/// `FILE_INFO_BY_HANDLE_CLASS::FileAttributeTagInfo`.
const FILE_ATTRIBUTE_TAG_INFO_CLASS: i32 = 9;
/// `IO_REPARSE_TAG_CLOUD` and its sixteen variants
/// (`IO_REPARSE_TAG_CLOUD_1`..`_F` = `0x9000_101A`..`0x9000_F01A`).
const IO_REPARSE_TAG_CLOUD: u32 = 0x9000_001A;
const IO_REPARSE_TAG_CLOUD_MASK: u32 = 0xFFFF_0FFF;

/// `BY_HANDLE_FILE_INFORMATION` (fileapi.h); `FILETIME` is two DWORDs.
#[repr(C)]
#[derive(Default)]
struct ByHandleFileInformation {
    file_attributes: u32,
    creation_time: [u32; 2],
    last_access_time: [u32; 2],
    last_write_time: [u32; 2],
    volume_serial_number: u32,
    file_size_high: u32,
    file_size_low: u32,
    number_of_links: u32,
    file_index_high: u32,
    file_index_low: u32,
}

/// `FILE_ATTRIBUTE_TAG_INFO` (winbase.h).
#[repr(C)]
#[derive(Default)]
struct FileAttributeTagInfo {
    file_attributes: u32,
    reparse_tag: u32,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileInformationByHandle(
        file: *mut std::ffi::c_void,
        info: *mut ByHandleFileInformation,
    ) -> i32;
    fn GetFileInformationByHandleEx(
        file: *mut std::ffi::c_void,
        class: i32,
        info: *mut std::ffi::c_void,
        size: u32,
    ) -> i32;
    fn MoveFileExW(src: *const u16, dst: *const u16, flags: u32) -> i32;
}

fn handle_info(f: &File) -> std::io::Result<ByHandleFileInformation> {
    let mut info = ByHandleFileInformation::default();
    // SAFETY: a live handle owned by `f`, and a correctly laid out
    // out-parameter.
    if unsafe { GetFileInformationByHandle(f.as_raw_handle(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(info)
}

/// How many names (hard links) the open file has.
/// (`std::os::windows::fs::MetadataExt::number_of_links` is unstable.)
fn number_of_links(f: &File) -> std::io::Result<u32> {
    Ok(handle_info(f)?.number_of_links)
}

/// `(volume serial, file index)`: the same pair means the same file.
fn file_identity(f: &File) -> std::io::Result<(u32, u64)> {
    let i = handle_info(f)?;
    Ok((
        i.volume_serial_number,
        (u64::from(i.file_index_high) << 32) | u64::from(i.file_index_low),
    ))
}

/// Reparse tag of an open reparse point.
fn reparse_tag(f: &File) -> std::io::Result<u32> {
    let mut info = FileAttributeTagInfo::default();
    // SAFETY: a live handle owned by `f`, and an out-parameter of the size
    // passed.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            f.as_raw_handle(),
            FILE_ATTRIBUTE_TAG_INFO_CLASS,
            (&mut info as *mut FileAttributeTagInfo).cast(),
            std::mem::size_of::<FileAttributeTagInfo>() as u32,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(info.reparse_tag)
}

fn is_cloud_tag(tag: u32) -> bool {
    tag & IO_REPARSE_TAG_CLOUD_MASK == IO_REPARSE_TAG_CLOUD
}

/// Errors worth retrying: another program has the file open without
/// sharing it (a sync client uploading it, a virus scanner). For a
/// rename or a deletion, "access denied" too: Windows returns it for a
/// file whose deletion is pending or that a scanner holds.
fn transient(e: &std::io::Error, access_denied_too: bool) -> bool {
    match e.raw_os_error() {
        Some(ERROR_SHARING_VIOLATION) | Some(ERROR_LOCK_VIOLATION) => true,
        Some(ERROR_ACCESS_DENIED) => access_denied_too,
        _ => false,
    }
}

/// Run `f`, retrying a transient failure with backoff (1, 2, 4 ... ms,
/// at most 250 ms apart, about 0.75 s in all).
fn retry<T>(
    access_denied_too: bool,
    mut f: impl FnMut() -> std::io::Result<T>,
) -> std::io::Result<T> {
    const RETRIES: u32 = 10;
    let mut delay = Duration::from_millis(1);
    for _ in 0..RETRIES {
        match f() {
            Err(e) if transient(&e, access_denied_too) => {
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_millis(250));
            }
            r => return r,
        }
    }
    f()
}

fn to_wide(p: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    p.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Rename `tmp` to `dst` in the same folder, failing if `dst` exists
/// (any kind of entry, a reparse point included), durable on return.
fn move_no_replace(tmp: &Path, dst: &Path) -> std::io::Result<()> {
    let (s, d) = (to_wide(tmp), to_wide(dst));
    // SAFETY: two NUL-terminated wide strings that outlive the call.
    if unsafe { MoveFileExW(s.as_ptr(), d.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

pub struct FsStore {
    /// The bundle folder as the system resolves it (no junction).
    root: PathBuf,
    display: PathBuf,
    /// The bundle folder and its area folders, pinned for the store's
    /// lifetime (see the module docs). Only held, never read.
    _pins: Vec<File>,
    /// Shard folders verified and pinned so far, kept for the store's
    /// lifetime (at most 256 per sharded area, like the Unix store's
    /// shard descriptors): a pinned folder cannot have moved, so it is
    /// not verified again.
    shards: Mutex<HashMap<(Area, String), File>>,
}

fn refused(what: &Path, why: &'static str) -> SyncError {
    SyncError::Refused {
        what: what.display().to_string(),
        why,
    }
}

/// Open `p` (file or folder) without following a final reparse point,
/// and require it to be exactly `p` (no junction on the way, same case
/// for its last component) and of the expected kind. A cloud file
/// placeholder is accepted (see the module docs). `share` is the share
/// mode: `PIN_SHARE` pins a folder.
fn open_checked(p: &Path, dir: bool, share: u32) -> std::io::Result<Option<File>> {
    let mut o = OpenOptions::new();
    o.read(true).share_mode(share);
    let mut flags = FILE_FLAG_OPEN_REPARSE_POINT;
    if dir {
        flags |= FILE_FLAG_BACKUP_SEMANTICS;
    }
    o.custom_flags(flags);
    let f = match retry(false, || o.open(p)) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let attrs = f.metadata()?.file_attributes();
    let cloud = if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        if !is_cloud_tag(reparse_tag(&f)?) {
            return Err(refusal(
                std::io::ErrorKind::InvalidInput,
                "is a symbolic link or junction",
            ));
        }
        true
    } else {
        false
    };
    if (attrs & FILE_ATTRIBUTE_DIRECTORY != 0) != dir {
        return Err(refusal(
            std::io::ErrorKind::InvalidInput,
            "is not the expected kind of entry",
        ));
    }
    check_resolves_to(&f, p)?;
    if cloud && !dir {
        // Opened as itself, a placeholder is not downloaded when read:
        // open it again normally (the cloud filter then fetches its
        // data), and require the very same file at the very same path.
        let mut o = OpenOptions::new();
        o.read(true).share_mode(share);
        let g = retry(false, || o.open(p))?;
        if file_identity(&g)? != file_identity(&f)? {
            return Err(refusal(
                std::io::ErrorKind::PermissionDenied,
                "was replaced while being opened",
            ));
        }
        check_resolves_to(&g, p)?;
        return Ok(Some(g));
    }
    Ok(Some(f))
}

/// `p` is always the store's resolved root (`GetFinalPathNameByHandleW`,
/// so already in its long form) joined with names of our own grammar, so
/// it is compared as it is: no `GetLongPathNameW` normalization (a walk
/// of every component), and an 8.3 alias set on some other folder can
/// never stand in for one of ours.
fn check_resolves_to(f: &File, p: &Path) -> std::io::Result<()> {
    let resolved = final_path_by_handle(f)?;
    if !windows_paths_eq_ci(&resolved, p) || resolved.file_name() != p.file_name() {
        return Err(refusal(
            std::io::ErrorKind::PermissionDenied,
            "a junction in the bundle redirected the path",
        ));
    }
    Ok(())
}

/// Marks an error raised by `open_checked`'s own hostile-entry checks, as
/// opposed to an error the OS returned while opening (sharing violation
/// from a sync client or scanner, access denied, network failure...).
/// Only the former is a `Refused` object; the latter stays `Io`, as on
/// Unix (`fs_store.rs` `refuse_open_error`), so a transient lock is never
/// counted as a damaged or missing object.
#[derive(Debug)]
struct Refusal(&'static str);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Refusal {}

fn refusal(kind: std::io::ErrorKind, why: &'static str) -> std::io::Error {
    std::io::Error::new(kind, Refusal(why))
}

fn is_refusal(e: &std::io::Error) -> bool {
    e.get_ref().is_some_and(|x| x.is::<Refusal>())
}

/// The root may be reached through a link the user chose (only its own
/// final component must not be one), so its resolved path is taken as
/// the reference rather than compared with the given path. Pinned.
fn open_checked_root(p: &Path) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.read(true)
        .share_mode(PIN_SHARE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);
    let f = retry(false, || o.open(p))?;
    let attrs = f.metadata()?.file_attributes();
    if attrs & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 && !is_cloud_tag(reparse_tag(&f)?) {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    Ok(f)
}

fn list_names(dir: &Path, cap: usize) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        if out.len() >= cap {
            return Err(SyncError::Limit("too many entries in a bundle folder"));
        }
        out.push(match e.file_name().to_str() {
            Some(s) => s.to_string(),
            None => "<non-UTF-16 name>".to_string(),
        });
    }
    Ok(out)
}

/// A temporary file of `atomic_secure_create_new`
/// (`<object leaf>.tmp.<16 hex>`), which earlier Windows builds used to
/// write objects: swept like our own `.tmp-<hex>` files.
fn is_legacy_tmp_name(area: Area, leaf: &str) -> bool {
    let Some((obj, rnd)) = leaf.split_once(".tmp.") else {
        return false;
    };
    rnd.len() == 16
        && rnd
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && Name::parse_in(area, obj).is_some()
}

impl FsStore {
    pub fn create(path: &Path) -> Result<Self> {
        if std::fs::symlink_metadata(path).is_ok() {
            return Err(SyncError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} already exists", path.display()),
            )));
        }
        std::fs::create_dir(path)?;
        let store = Self::open(path)?;
        Ok(store)
    }

    pub fn open(path: &Path) -> Result<Self> {
        let abs = std::path::absolute(path)?;
        // The bundle folder itself must not be a link; the path leading
        // to it is the user's choice.
        let f = open_checked_root(&abs).map_err(|e| match e.raw_os_error() {
            Some(ERROR_SHARING_VIOLATION) | Some(ERROR_LOCK_VIOLATION) => SyncError::Io(e),
            _ => refused(&abs, "the bundle folder is a link or not a folder"),
        })?;
        let root = final_path_by_handle(&f)?;
        let mut pins = vec![f];
        for area in Area::ALL {
            let p = root.join(area.dir());
            match std::fs::create_dir(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
            match open_checked(&p, true, PIN_SHARE) {
                Ok(Some(pin)) => pins.push(pin),
                Ok(None) => return Err(refused(&p, "an area folder is missing")),
                Err(e) if is_refusal(&e) => {
                    return Err(refused(&p, "an area folder is a link or not a folder"));
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(Self {
            root,
            display: path.to_path_buf(),
            _pins: pins,
            shards: Mutex::new(HashMap::new()),
        })
    }

    /// Pin the shard folder `shard` of `area` (verified once, then kept):
    /// `Ok(false)` if it does not exist. A refusal is an `io::Error`
    /// marked by `refusal`.
    fn pin_shard(&self, area: Area, shard: &str) -> std::io::Result<bool> {
        let key = (area, shard.to_string());
        if self.shards.lock().expect("shard lock").contains_key(&key) {
            return Ok(true);
        }
        let p = self.root.join(area.dir()).join(shard);
        match open_checked(&p, true, PIN_SHARE)? {
            Some(pin) => {
                self.shards
                    .lock()
                    .expect("shard lock")
                    .entry(key)
                    .or_insert(pin);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// The folder `name` lives in, `None` if it does not exist. A shard
    /// folder is pinned from then on, area folders already are: the path
    /// cannot be redirected while the store uses it.
    fn dir_pinned(&self, area: Area, name: &Name, create: bool) -> Result<Option<PathBuf>> {
        let mut p = self.root.join(area.dir());
        if !area.sharded() {
            return Ok(Some(p));
        }
        let shard = name.shard().expect("sharded areas hold object names");
        p = p.join(&shard);
        if create
            && !self
                .shards
                .lock()
                .expect("shard lock")
                .contains_key(&(area, shard.clone()))
        {
            match std::fs::create_dir(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        match self.pin_shard(area, &shard) {
            Ok(true) => Ok(Some(p)),
            Ok(false) => Ok(None),
            Err(e) if is_refusal(&e) => {
                Err(refused(&p, "a shard folder is a link or not a folder"))
            }
            Err(e) => Err(e.into()),
        }
    }

    fn read_one(&self, area: Area, name: &Name, len: LenRule) -> Result<Option<Vec<u8>>> {
        let what = name.display(area);
        let Some(dir) = self.dir_pinned(area, name, false)? else {
            return Ok(None);
        };
        let p = dir.join(name.leaf());
        let mut f = match open_checked(&p, false, ANY_SHARE) {
            Ok(Some(f)) => f,
            Ok(None) => return Ok(None),
            Err(e) if is_refusal(&e) => {
                return Err(SyncError::Refused {
                    what,
                    why: "is a link, a junction or not a regular file",
                });
            }
            Err(e) => return Err(e.into()),
        };
        // A second name for the object (a sync client's upload link) is
        // not refused: see the Unix store.
        let size = f.metadata()?.len();
        if !len.allows(size) {
            return Err(SyncError::Refused {
                what,
                why: "wrong size for its kind",
            });
        }
        let mut buf = vec![0u8; size as usize];
        // Only a short read is the object shrinking; any other error (an
        // online-only file whose provider is not running, a network or
        // device error) is I/O, never a damaged object.
        f.read_exact(&mut buf).map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                SyncError::Refused {
                    what: what.clone(),
                    why: "shrank while being read",
                }
            } else {
                SyncError::Io(e)
            }
        })?;
        let mut probe = [0u8; 1];
        if f.read(&mut probe)? != 0 {
            return Err(SyncError::Refused {
                what,
                why: "grew while being read",
            });
        }
        Ok(Some(buf))
    }

    fn create_one(&self, area: Area, name: &Name, bytes: &[u8]) -> Result<Created> {
        let dir = self
            .dir_pinned(area, name, true)?
            .ok_or_else(|| refused(&self.root, "a shard folder vanished while created"))?;
        let tmp = dir.join(tmp_name()?);
        let dst = dir.join(name.leaf());
        let written = (|| {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()
        })();
        if let Err(e) = written {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.into());
        }
        match retry(true, || move_no_replace(&tmp, &dst)) {
            Ok(()) => Ok(Created::New),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = retry(true, || std::fs::remove_file(&tmp));
                // Another size is another object (as on Unix), not a
                // refused read.
                let same_size = std::fs::symlink_metadata(&dst)
                    .is_ok_and(|m| m.is_file() && m.len() == bytes.len() as u64);
                if !same_size {
                    return Err(SyncError::Collision {
                        name: name.display(area),
                    });
                }
                match self.read_one(area, name, LenRule::Exact(bytes.len()))? {
                    Some(existing) if existing == bytes => Ok(Created::AlreadyIdentical),
                    _ => Err(SyncError::Collision {
                        name: name.display(area),
                    }),
                }
            }
            Err(e) => {
                let _ = retry(true, || std::fs::remove_file(&tmp));
                Err(e.into())
            }
        }
    }

    /// Remove the temporary files of one folder: ours past `min_age`, and
    /// at any age a temporary name that is a second link to a file (an
    /// object a crash left with two names, which reads refuse).
    fn sweep_dir(dir: &Path, area: Area, min_age: Duration) -> Result<usize> {
        let mut removed = 0;
        for leaf in list_names(dir, crate::store::MAX_LIST_ENTRIES)? {
            if !is_tmp_name(&leaf) && !is_legacy_tmp_name(area, &leaf) {
                continue;
            }
            let p = dir.join(&leaf);
            let Ok(m) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if m.is_dir() {
                continue;
            }
            let age = m
                .modified()
                .ok()
                .and_then(|t| t.elapsed().ok())
                .unwrap_or(Duration::ZERO);
            let linked = OpenOptions::new()
                .read(true)
                .share_mode(ANY_SHARE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&p)
                .and_then(|f| number_of_links(&f))
                .is_ok_and(|n| n > 1);
            if age < min_age && !linked {
                continue;
            }
            // remove_file deletes a link itself, never its target.
            match retry(true, || std::fs::remove_file(&p)) {
                Ok(()) => removed += 1,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(removed)
    }
}

impl ObjectStore for FsStore {
    fn list(&mut self, area: Area) -> Result<Listing> {
        let mut l = Listing::default();
        let cap = crate::store::MAX_LIST_ENTRIES;
        // Area folders are pinned (`open`).
        let adir = self.root.join(area.dir());
        let entries = list_names(&adir, cap)?;
        if !area.sharded() {
            for leaf in entries {
                l.classify(area, None, &leaf)?;
            }
            return Ok(l);
        }
        for shard in entries {
            if !is_shard_name(&shard) {
                l.note_foreign(format!("{}/{}", area.dir(), shard));
                continue;
            }
            let sdir = adir.join(&shard);
            match self.pin_shard(area, &shard) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) if is_refusal(&e) => {
                    l.note_foreign(format!("{}/{} (not a folder)", area.dir(), shard));
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            for leaf in list_names(&sdir, cap)? {
                l.classify(area, Some(&shard), &leaf)?;
            }
        }
        Ok(l)
    }

    fn read(&mut self, area: Area, name: &Name, len: LenRule) -> Result<Option<Vec<u8>>> {
        self.read_one(area, name, len)
    }

    fn create_new(&mut self, area: Area, name: &Name, bytes: &[u8]) -> Result<Created> {
        self.create_one(area, name, bytes)
    }

    /// The objects are independent files, each flushed and renamed into
    /// place as by `create_new`: writing several at once overlaps the
    /// flushes, which dominate a commit's upload on Windows.
    fn create_many(&mut self, area: Area, items: &[(Name, &[u8])]) -> Result<()> {
        let this = &*self;
        crate::local::run_parallel(items, |(name, bytes)| {
            this.create_one(area, name, bytes).map(|_| ())
        })
        .into_iter()
        .collect()
    }

    fn remove(&mut self, area: Area, name: &Name) -> Result<bool> {
        let Some(dir) = self.dir_pinned(area, name, false)? else {
            return Ok(false);
        };
        let p = dir.join(name.leaf());
        // remove_file deletes a link itself, never its target.
        match retry(true, || std::fs::remove_file(&p)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Every object was flushed before its rename, and the rename itself
    /// was written through (`MOVEFILE_WRITE_THROUGH`): nothing is left to
    /// flush. (Windows has no folder fsync for an unprivileged process.)
    fn sync(&mut self) -> Result<()> {
        Ok(())
    }

    fn describe(&self) -> String {
        self.display.display().to_string()
    }

    fn sweep_tmp(&mut self, min_age_ns: u64) -> Result<usize> {
        let min_age = Duration::from_nanos(min_age_ns);
        let mut removed = 0;
        for area in Area::ALL {
            let adir = self.root.join(area.dir());
            removed += Self::sweep_dir(&adir, area, min_age)?;
            if !area.sharded() {
                continue;
            }
            for shard in list_names(&adir, crate::store::MAX_LIST_ENTRIES)? {
                if !is_shard_name(&shard) {
                    continue;
                }
                let sdir = adir.join(&shard);
                let Ok(true) = self.pin_shard(area, &shard) else {
                    continue;
                };
                removed += Self::sweep_dir(&sdir, area, min_age)?;
            }
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::ObjectId;

    fn fresh() -> (tempfile::TempDir, PathBuf, FsStore) {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("v.lbxs");
        let s = FsStore::create(&p).unwrap();
        (d, p, s)
    }

    /// `mklink /J` needs no privilege (unlike a symbolic link).
    fn junction(link: &Path, target: &Path) {
        let ok = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .unwrap()
            .status
            .success();
        assert!(ok, "mklink /J failed");
    }

    #[test]
    fn create_read_list_remove() {
        let (_d, p, mut s) = fresh();
        let n = Name::Object(ObjectId([0x3c; 32]));
        assert_eq!(s.create_new(Area::Page, &n, b"abc").unwrap(), Created::New);
        assert_eq!(
            s.create_new(Area::Page, &n, b"abc").unwrap(),
            Created::AlreadyIdentical
        );
        assert!(matches!(
            s.create_new(Area::Page, &n, b"abd"),
            Err(SyncError::Collision { .. })
        ));
        assert!(p.join("p\\3c").join(n.leaf()).is_file());
        assert_eq!(
            s.read(Area::Page, &n, LenRule::Exact(3)).unwrap().unwrap(),
            b"abc"
        );
        assert!(s.read(Area::Page, &n, LenRule::Exact(4)).is_err());
        let l = s.list(Area::Page).unwrap();
        assert_eq!(l.names, vec![n]);
        // No temporary file is left behind, the collision's included.
        assert_eq!(l.tmp_count, 0);
        assert_eq!(l.foreign_count, 0);
        assert!(s.remove(Area::Page, &n).unwrap());
        assert!(!s.remove(Area::Page, &n).unwrap());
        assert!(s.read(Area::Page, &n, LenRule::Exact(3)).unwrap().is_none());
        drop(s);
        FsStore::open(&p).unwrap();
    }

    #[test]
    fn create_many_writes_every_object_and_is_idempotent() {
        let (_d, _p, mut s) = fresh();
        let objs: Vec<(Name, Vec<u8>)> = (0..64u8)
            .map(|i| (Name::Object(ObjectId([i; 32])), vec![i; 1000 + i as usize]))
            .collect();
        let items: Vec<(Name, &[u8])> = objs.iter().map(|(n, b)| (*n, b.as_slice())).collect();
        s.create_many(Area::Page, &items).unwrap();
        s.create_many(Area::Page, &items).unwrap();
        for (n, b) in &objs {
            assert_eq!(
                &s.read(Area::Page, n, LenRule::Exact(b.len()))
                    .unwrap()
                    .unwrap(),
                b
            );
        }
        let l = s.list(Area::Page).unwrap();
        assert_eq!(l.names.len(), 64);
        assert_eq!(l.tmp_count + l.foreign_count, 0);
        // A different object under a taken name fails the batch.
        let bad = [(objs[3].0, &b"other"[..])];
        assert!(matches!(
            s.create_many(Area::Page, &bad),
            Err(SyncError::Collision { .. })
        ));
    }

    #[test]
    fn reads_through_a_second_name_and_refuses_junctioned_shards() {
        let (d, p, mut s) = fresh();
        let outside = d.path().join("secret");
        std::fs::write(&outside, b"xyz").unwrap();
        let n = Name::Object(ObjectId([0x12; 32]));
        let shard = p.join("p\\12");
        std::fs::create_dir_all(&shard).unwrap();
        std::fs::hard_link(&outside, shard.join(n.leaf())).unwrap();
        // A second name: read like any object (authenticated above this
        // layer); removing the object removes its name only.
        assert_eq!(
            s.read(Area::Page, &n, LenRule::Exact(3)).unwrap().unwrap(),
            b"xyz"
        );
        assert!(s.remove(Area::Page, &n).unwrap());
        assert_eq!(std::fs::read(&outside).unwrap(), b"xyz");

        let elsewhere = d.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        let n2 = Name::Object(ObjectId([0x22; 32]));
        std::fs::write(elsewhere.join(n2.leaf()), b"abc").unwrap();
        junction(&p.join("p\\22"), &elsewhere);
        assert!(matches!(
            s.read(Area::Page, &n2, LenRule::Exact(3)),
            Err(SyncError::Refused { .. })
        ));
        assert!(s.create_new(Area::Page, &n2, b"abc").is_err());
        assert!(s.remove(Area::Page, &n2).is_err());
        assert_eq!(std::fs::read(elsewhere.join(n2.leaf())).unwrap(), b"abc");
        let l = s.list(Area::Page).unwrap();
        assert_eq!(l.foreign_count, 1);
    }

    /// A shard folder that differs from ours only in case is not ours:
    /// nothing is written into it.
    #[test]
    fn a_shard_folder_in_another_case_is_refused() {
        let (_d, p, mut s) = fresh();
        std::fs::create_dir(p.join("p\\AB")).unwrap();
        let n = Name::Object(ObjectId([0xab; 32]));
        assert!(matches!(
            s.create_new(Area::Page, &n, b"abc"),
            Err(SyncError::Refused { .. })
        ));
        assert_eq!(std::fs::read_dir(p.join("p\\AB")).unwrap().count(), 0);
    }

    /// The folders a store works in cannot be swapped for a junction
    /// while it works in them: the bundle and area folders are pinned
    /// for the store's lifetime, a shard folder during each operation.
    #[test]
    fn pinned_folders_cannot_be_moved_away() {
        let (d, p, mut s) = fresh();
        let away = d.path().join("away");
        for area in ["l", "h", "m", "p"] {
            let e = std::fs::rename(p.join(area), &away).unwrap_err();
            assert_eq!(e.raw_os_error(), Some(ERROR_SHARING_VIOLATION), "{area}");
        }
        assert!(std::fs::rename(&p, &away).is_err());
        // Once the store is gone, the folders are free again.
        let n = Name::Object(ObjectId([0x5a; 32]));
        s.create_new(Area::Lease, &n, b"lease").unwrap();
        drop(s);
        std::fs::rename(p.join("l"), &away).unwrap();
        // A junction put in its place is refused at the next open.
        junction(&p.join("l"), &away);
        assert!(matches!(FsStore::open(&p), Err(SyncError::Refused { .. })));
    }

    /// A shard folder, once used, is pinned until the store is dropped.
    #[test]
    fn a_used_shard_folder_is_pinned() {
        let (d, p, mut s) = fresh();
        let n = Name::Object(ObjectId([0x61; 32]));
        s.create_new(Area::Page, &n, b"abc").unwrap();
        let dir = p.join("p\\61");
        let e = std::fs::rename(&dir, d.path().join("moved")).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(ERROR_SHARING_VIOLATION));
        drop(s);
        std::fs::rename(&dir, d.path().join("moved")).unwrap();
        assert!(!dir.exists());
    }

    /// A sync client or scanner holding an object open without read
    /// sharing is a transient I/O error, never a `Refused` (damaged)
    /// object: callers count refused manifests as invalid, which could
    /// raise a false rollback alarm or let GC plan a valid commit away.
    #[test]
    fn a_sharing_violation_is_io_not_refused() {
        let (_d, p, mut s) = fresh();
        let n = Name::Object(ObjectId([0x44; 32]));
        s.create_new(Area::Page, &n, b"abc").unwrap();
        let held = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(p.join("p\\44").join(n.leaf()))
            .unwrap();
        match s.read(Area::Page, &n, LenRule::Exact(3)) {
            Err(SyncError::Io(_)) => {}
            other => panic!("expected Io, got {other:?}"),
        }
        drop(held);
        assert_eq!(
            s.read(Area::Page, &n, LenRule::Exact(3)).unwrap().unwrap(),
            b"abc"
        );
    }

    /// ... and one held only for a moment is waited out (retry with
    /// backoff), for reads and for removals alike.
    #[test]
    fn a_brief_sharing_violation_is_retried() {
        let (_d, p, mut s) = fresh();
        let n = Name::Object(ObjectId([0x45; 32]));
        s.create_new(Area::Page, &n, b"abc").unwrap();
        let obj = p.join("p\\45").join(n.leaf());
        let hold = |obj: PathBuf| {
            let f = OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(obj)
                .unwrap();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(60));
                drop(f);
            })
        };
        let t = hold(obj.clone());
        assert_eq!(
            s.read(Area::Page, &n, LenRule::Exact(3)).unwrap().unwrap(),
            b"abc"
        );
        t.join().unwrap();
        let t = hold(obj.clone());
        assert!(s.remove(Area::Page, &n).unwrap());
        t.join().unwrap();
        assert!(!obj.exists());
    }

    /// Cloud Files API (cldapi.dll), enough to turn files and folders into
    /// real cloud placeholders under a local sync root, with no provider
    /// process and no network: what OneDrive Files On-Demand leaves in a
    /// synced folder.
    mod cf {
        #[repr(C)]
        pub struct Guid(pub u32, pub u16, pub u16, pub [u8; 8]);
        #[repr(C)]
        pub struct Registration {
            pub struct_size: u32,
            pub provider_name: *const u16,
            pub provider_version: *const u16,
            pub sync_root_identity: *const u8,
            pub sync_root_identity_len: u32,
            pub file_identity: *const u8,
            pub file_identity_len: u32,
            pub provider_id: Guid,
        }
        #[repr(C)]
        pub struct Policies {
            pub struct_size: u32,
            pub hydration: [u16; 2],
            pub population: [u16; 2],
            pub in_sync: u32,
            pub hard_link: u32,
            pub placeholder_management: u32,
        }
        #[repr(C)]
        pub struct CallbackRegistration {
            pub kind: i32,
            pub callback: *const std::ffi::c_void,
        }
        #[link(name = "cldapi", kind = "raw-dylib")]
        unsafe extern "system" {
            pub fn CfConnectSyncRoot(
                path: *const u16,
                table: *const CallbackRegistration,
                context: *const std::ffi::c_void,
                flags: u32,
                key: *mut i64,
            ) -> i32;
            pub fn CfDisconnectSyncRoot(key: i64) -> i32;
            pub fn CfRegisterSyncRoot(
                path: *const u16,
                reg: *const Registration,
                pol: *const Policies,
                flags: u32,
            ) -> i32;
            pub fn CfUnregisterSyncRoot(path: *const u16) -> i32;
            pub fn CfConvertToPlaceholder(
                file: *mut std::ffi::c_void,
                identity: *const u8,
                identity_len: u32,
                flags: u32,
                usn: *mut i64,
                overlapped: *mut std::ffi::c_void,
            ) -> i32;
            pub fn CfDehydratePlaceholder(
                file: *mut std::ffi::c_void,
                offset: i64,
                length: i64,
                flags: u32,
                overlapped: *mut std::ffi::c_void,
            ) -> i32;
            pub fn CfRevertPlaceholder(
                file: *mut std::ffi::c_void,
                flags: u32,
                overlapped: *mut std::ffi::c_void,
            ) -> i32;
        }
        #[link(name = "ntdll", kind = "raw-dylib")]
        unsafe extern "system" {
            /// PHCM_EXPOSE_PLACEHOLDERS = 2: this process sees
            /// placeholders as the reparse points they are.
            pub fn RtlSetProcessPlaceholderCompatibilityMode(mode: i8) -> i8;
        }
    }

    fn open_for_cf(p: &Path, dir: bool) -> File {
        let mut flags = FILE_FLAG_OPEN_REPARSE_POINT;
        if dir {
            flags |= FILE_FLAG_BACKUP_SEMANTICS;
        }
        OpenOptions::new()
            .read(true)
            .write(!dir)
            .access_mode(if dir {
                0x0001_0000 | 0x80 | 0x100
            } else {
                0xC001_0000
            })
            .share_mode(ANY_SHARE)
            .custom_flags(flags)
            .open(p)
            .unwrap()
    }

    /// OneDrive Files On-Demand (and every Cloud Files provider) makes
    /// every file and folder of a synced folder a reparse point with a
    /// cloud tag. Such a bundle must open, list and read as usual (the
    /// placeholder is the file itself, not a redirection), while a
    /// junction stays refused.
    #[test]
    fn a_bundle_of_cloud_placeholders_is_read_normally() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("cloudroot");
        std::fs::create_dir(&root).unwrap();
        let root_w = to_wide(&root);
        let name = to_wide(Path::new("LuksBoxTest"));
        let ver = to_wide(Path::new("1.0"));
        let ident = b"luksbox-test-root";
        let reg = cf::Registration {
            struct_size: std::mem::size_of::<cf::Registration>() as u32,
            provider_name: name.as_ptr(),
            provider_version: ver.as_ptr(),
            sync_root_identity: ident.as_ptr(),
            sync_root_identity_len: ident.len() as u32,
            file_identity: std::ptr::null(),
            file_identity_len: 0,
            provider_id: cf::Guid(0x6c75_6b73, 0x626f, 0x7874, *b"testsync"),
        };
        let pol = cf::Policies {
            struct_size: std::mem::size_of::<cf::Policies>() as u32,
            hydration: [2, 0],  // CF_HYDRATION_POLICY_FULL
            population: [3, 0], // CF_POPULATION_POLICY_ALWAYS_FULL
            in_sync: 0,
            hard_link: 0,
            placeholder_management: 0,
        };
        // SAFETY: valid structures and strings that outlive the call.
        let hr = unsafe { cf::CfRegisterSyncRoot(root_w.as_ptr(), &reg, &pol, 0) };
        assert_eq!(hr, 0, "CfRegisterSyncRoot failed: {hr:#x}");
        struct Unregister(Vec<u16>);
        impl Drop for Unregister {
            fn drop(&mut self) {
                // SAFETY: a NUL-terminated path.
                unsafe { cf::CfUnregisterSyncRoot(self.0.as_ptr()) };
            }
        }
        let _unreg = Unregister(root_w.clone());
        // SAFETY: plain call.
        unsafe { cf::RtlSetProcessPlaceholderCompatibilityMode(2) };

        let p = root.join("v.lbxs");
        let objs: Vec<(Area, Name, Vec<u8>)> = vec![
            (
                Area::Page,
                Name::Object(ObjectId([0x71; 32])),
                b"page one".to_vec(),
            ),
            (
                Area::Manifest,
                Name::Object(ObjectId([0x72; 32])),
                b"commit".to_vec(),
            ),
            (
                Area::Lease,
                Name::Object(ObjectId([0x73; 32])),
                b"lease".to_vec(),
            ),
        ];
        {
            let mut s = FsStore::create(&p).unwrap();
            for (a, n, b) in &objs {
                s.create_new(*a, n, b).unwrap();
            }
        }
        // Every folder and file of the bundle becomes a placeholder.
        let mut entries = vec![(p.clone(), true)];
        for e in std::fs::read_dir(&p).unwrap() {
            let e = e.unwrap().path();
            entries.push((e.clone(), true));
            for f in std::fs::read_dir(&e).unwrap() {
                let f = f.unwrap().path();
                let is_dir = f.is_dir();
                entries.push((f.clone(), is_dir));
                if is_dir {
                    for g in std::fs::read_dir(&f).unwrap() {
                        entries.push((g.unwrap().path(), false));
                    }
                }
            }
        }
        let fid = b"id";
        for (e, dir) in &entries {
            let h = open_for_cf(e, *dir);
            // CF_CONVERT_FLAG_MARK_IN_SYNC: a full, in-sync placeholder.
            // SAFETY: live handle, valid identity buffer.
            let hr = unsafe {
                cf::CfConvertToPlaceholder(
                    h.as_raw_handle(),
                    fid.as_ptr(),
                    fid.len() as u32,
                    1,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            assert_eq!(
                hr,
                0,
                "CfConvertToPlaceholder({}) failed: {hr:#x}",
                e.display()
            );
        }
        // They really are cloud reparse points to this process.
        let (_, n0, _) = &objs[0];
        let obj0 = p.join("p").join(n0.shard().unwrap()).join(n0.leaf());
        for e in [&p, &obj0] {
            let f = open_for_cf(e, e.is_dir());
            assert_ne!(
                f.metadata().unwrap().file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT,
                0
            );
            let tag = reparse_tag(&f).unwrap();
            assert_eq!(
                tag & IO_REPARSE_TAG_CLOUD_MASK,
                IO_REPARSE_TAG_CLOUD,
                "{}",
                e.display()
            );
        }

        let mut s = FsStore::open(&p).unwrap();
        for (a, n, b) in &objs {
            assert_eq!(
                &s.read(*a, n, LenRule::Exact(b.len())).unwrap().unwrap(),
                b,
                "{a:?}"
            );
            let l = s.list(*a).unwrap();
            assert_eq!(l.names, vec![*n]);
            assert_eq!(l.foreign_count, 0);
        }
        // New objects go into placeholder folders as usual.
        let n = Name::Object(ObjectId([0x71; 32]));
        let mut id = [0x71; 32];
        id[31] = 0;
        let n2 = Name::Object(ObjectId(id));
        s.create_new(Area::Page, &n2, b"page two").unwrap();
        assert_eq!(
            s.read(Area::Page, &n2, LenRule::Exact(8)).unwrap().unwrap(),
            b"page two"
        );
        assert!(s.remove(Area::Page, &n).unwrap());

        // An online-only object (data not on this device) whose provider
        // is not running cannot be read now: an I/O error, never a
        // refused (damaged) object.
        let (a2, n2l, b2) = &objs[2];
        let lease = p.join("l").join(n2l.leaf());
        {
            // Dehydrating needs a connected provider; one with no
            // callbacks is enough. Disconnected again before the read.
            let table = [cf::CallbackRegistration {
                kind: -1, // CF_CALLBACK_TYPE_NONE: end of table
                callback: std::ptr::null(),
            }];
            let mut key = 0i64;
            // SAFETY: valid path, terminated table, out-parameter.
            let hr = unsafe {
                cf::CfConnectSyncRoot(
                    root_w.as_ptr(),
                    table.as_ptr(),
                    std::ptr::null(),
                    0,
                    &mut key,
                )
            };
            assert_eq!(hr, 0, "CfConnectSyncRoot failed: {hr:#x}");
            let h = open_for_cf(&lease, false);
            // SAFETY: live handle; whole file (length -1).
            let hr = unsafe {
                cf::CfDehydratePlaceholder(h.as_raw_handle(), 0, -1, 0, std::ptr::null_mut())
            };
            drop(h);
            // SAFETY: the key CfConnectSyncRoot returned.
            unsafe { cf::CfDisconnectSyncRoot(key) };
            assert_eq!(hr, 0, "CfDehydratePlaceholder failed: {hr:#x}");
        }
        match s.read(*a2, n2l, LenRule::Exact(b2.len())) {
            Err(SyncError::Io(_)) => {}
            other => panic!("expected Io for an online-only object, got {other:?}"),
        }
        drop(s);

        // Placeholders back to plain files so the temporary folder can go.
        for (e, dir) in entries.iter().rev() {
            if let Ok(h) = std::panic::catch_unwind(|| open_for_cf(e, *dir)) {
                // SAFETY: live handle.
                unsafe { cf::CfRevertPlaceholder(h.as_raw_handle(), 0, std::ptr::null_mut()) };
            }
        }
    }

    #[test]
    fn sweep_removes_leftover_links_and_old_temporary_files_only() {
        let (_d, p, mut s) = fresh();
        let n = Name::Object(ObjectId([0x6b; 32]));
        s.create_new(Area::Manifest, &n, b"commit").unwrap();
        let shard = p.join("m\\6b");
        let obj = shard.join(n.leaf());
        // A second name for the object under a temporary name: the
        // object reads as before, and the sweep removes the name at any
        // age.
        let leftover = shard.join(".tmp-00000000000000000000000000000001");
        std::fs::hard_link(&obj, &leftover).unwrap();
        assert_eq!(
            s.read(Area::Manifest, &n, LenRule::AtMost(100))
                .unwrap()
                .unwrap(),
            b"commit"
        );
        // A write in progress (maybe another device's), a temporary file
        // of an earlier Windows build, and a file outside the grammar.
        let young = p.join("h\\.tmp-00000000000000000000000000000002");
        std::fs::write(&young, b"in flight").unwrap();
        let legacy = shard.join(format!("{}.tmp.0123456789abcdef", n.leaf()));
        std::fs::write(&legacy, b"old").unwrap();
        let foreign = p.join("h\\.tmp-not-ours");
        std::fs::write(&foreign, b"x").unwrap();
        assert_eq!(s.sweep_tmp(crate::store::TMP_SWEEP_AGE_NS).unwrap(), 1);
        assert!(!leftover.exists() && young.exists() && legacy.exists() && foreign.exists());
        assert_eq!(
            s.read(Area::Manifest, &n, LenRule::AtMost(100))
                .unwrap()
                .unwrap(),
            b"commit"
        );
        // Old enough: gone too. The foreign file stays.
        assert_eq!(s.sweep_tmp(0).unwrap(), 2);
        assert!(!young.exists() && !legacy.exists() && foreign.exists());
        assert_eq!(s.sweep_tmp(0).unwrap(), 0);
    }
}
