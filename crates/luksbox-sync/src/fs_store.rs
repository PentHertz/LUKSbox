// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! The bundle folder on disk, treated as hostile input.
//!
//! The folder is written by a sync client on behalf of the storage
//! provider, so every name, file type, size and count in it may be
//! attacker-chosen. Rules (section 4 of
//! `docs/CLOUD_SYNC_IMPLEMENTATION.md`):
//!
//! - The bundle folder is opened once (`O_DIRECTORY | O_NOFOLLOW`);
//!   every later operation is relative to that handle or to sub-folder
//!   handles opened the same way, so a link swapped in anywhere in the
//!   bundle is never followed and nothing outside it is reached.
//! - A file is used only if `fstat` on the opened handle shows a regular
//!   file with one link and the size its kind requires. FIFOs, devices,
//!   sockets, hard links and links of any kind are refused before a byte
//!   is read (`O_NONBLOCK` keeps opening a FIFO from blocking).
//! - Reads are bounded by the expected size and checked for EOF; nothing
//!   is read twice by path.
//! - New objects are written to a `.tmp-<hex>` file, fsync'd, and
//!   published under their name with an exclusive rename
//!   (`renameatx_np(RENAME_EXCL)` on Apple platforms, `renameat2
//!   (RENAME_NOREPLACE)` on Linux), or `linkat` + `unlinkat` where the
//!   file system has no exclusive rename. Both fail if the name exists:
//!   an object is never overwritten (a lease refresh is a new object
//!   too). A crash between `linkat` and `unlinkat` leaves the object with
//!   two links (refused when read): `sweep_tmp`, at every writable open,
//!   removes such leftover temporary names, and others older than an
//!   hour (younger ones may be another device's upload in progress).
//! - Durability: on Linux and others every object is `fsync`'d before it
//!   is installed, and `sync` fsyncs the folders. On Apple platforms
//!   `fsync` does not reach the disk's own cache, and `F_FULLFSYNC` per
//!   object cost 4 ms per MiB: each object gets `F_BARRIERFSYNC` (its
//!   data reaches the disk before its name does, so after a power cut an
//!   object is there whole or not at all), and `sync`, which the
//!   publisher calls after the pages and before and after the manifest,
//!   ends with one `F_FULLFSYNC`: the parts are on disk before the commit
//!   that names them is written, and the commit before it is recorded as
//!   published.
//! - Deletions are `unlinkat` of a grammar-valid name, never recursive.

#![cfg(unix)]

use std::collections::{BTreeSet, HashMap};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::error::{Result, SyncError};
use crate::names::{Area, Name, is_shard_name, is_tmp_name, tmp_name};
use crate::store::{Created, LenRule, Listing, ObjectStore};

const DIR_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
const READ_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY;
const CREATE_FLAGS: libc::c_int =
    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;

pub struct FsStore {
    path: PathBuf,
    root: OwnedFd,
    areas: HashMap<Area, OwnedFd>,
    shards: HashMap<(Area, String), OwnedFd>,
    /// Folders with entries created or removed since the last `sync`.
    dirty: BTreeSet<(Area, Option<String>)>,
    root_dirty: bool,
    /// Objects written since the last `sync` whose data may still sit in
    /// the disk's cache (Apple platforms: see the module docs).
    unflushed: bool,
}

fn cstr(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| SyncError::Refused {
        what: s.to_string(),
        why: "name contains NUL",
    })
}

fn last_err() -> std::io::Error {
    std::io::Error::last_os_error()
}

fn open_dir_at(parent: RawFd, name: &str) -> std::io::Result<OwnedFd> {
    let c =
        CString::new(name).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: `c` is a valid NUL-terminated string; `parent` is a live fd.
    let fd = unsafe { libc::openat(parent, c.as_ptr(), DIR_FLAGS) };
    if fd < 0 {
        return Err(last_err());
    }
    // SAFETY: `fd` was just returned by openat and is owned by us.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Whether `fd` is still the folder `name` in `parent`: same device and
/// inode, and `name` neither a link nor gone. The session keeps folder
/// fds open; a sync client or the provider may move a folder away (or
/// replace it) meanwhile, and writes through the old fd would then land
/// outside the bundle while the publish reports success.
fn still_at(fd: RawFd, parent: RawFd, name: &str) -> bool {
    let Ok(c) = CString::new(name) else {
        return false;
    };
    // SAFETY: zeroed `stat` structs are valid out-parameters; `c` is a
    // valid C string; `fd` and `parent` are live fds.
    unsafe {
        let mut held: libc::stat = std::mem::zeroed();
        let mut named: libc::stat = std::mem::zeroed();
        libc::fstat(fd, &mut held) == 0
            && libc::fstatat(parent, c.as_ptr(), &mut named, libc::AT_SYMLINK_NOFOLLOW) == 0
            && (named.st_mode & libc::S_IFMT) == libc::S_IFDIR
            && held.st_dev == named.st_dev
            && held.st_ino == named.st_ino
    }
}

fn mkdir_at(parent: RawFd, name: &str) -> std::io::Result<bool> {
    let c =
        CString::new(name).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: valid C string and live fd.
    if unsafe { libc::mkdirat(parent, c.as_ptr(), 0o700) } == 0 {
        return Ok(true);
    }
    let e = last_err();
    if e.raw_os_error() == Some(libc::EEXIST) {
        Ok(false)
    } else {
        Err(e)
    }
}

/// Point `errno` at zero, so a NULL from `readdir` can be told apart
/// (end of the folder, `errno` still 0) from an error.
fn clear_errno() {
    // SAFETY: each returns this thread's errno location.
    unsafe {
        #[cfg(any(target_os = "linux", target_os = "emscripten"))]
        {
            *libc::__errno_location() = 0;
        }
        #[cfg(target_os = "android")]
        {
            *libc::__errno() = 0;
        }
        #[cfg(any(
            target_vendor = "apple",
            target_os = "freebsd",
            target_os = "dragonfly"
        ))]
        {
            *libc::__error() = 0;
        }
        #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
        {
            *libc::__errno() = 0;
        }
    }
}

/// Make an object's data reach the disk before what follows: on Apple
/// platforms `F_BARRIERFSYNC` (an ordering barrier in the disk's cache;
/// `sync` flushes the cache), elsewhere `fsync`.
fn sync_object(f: &File) -> std::io::Result<()> {
    #[cfg(target_vendor = "apple")]
    {
        // SAFETY: live fd.
        if unsafe { libc::fcntl(f.as_raw_fd(), libc::F_BARRIERFSYNC) } == 0 {
            return Ok(());
        }
        // File systems without the barrier: the full flush.
        f.sync_all()
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        f.sync_all()
    }
}

/// Apple platforms: flush the disk's cache, making everything written
/// and fsync'd on the volume so far durable (`F_FULLFSYNC`). Falls back
/// to `fsync` where the file system does not support it.
#[cfg(target_vendor = "apple")]
fn full_flush(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: live fd.
    if unsafe { libc::fcntl(fd, libc::F_FULLFSYNC) } == 0 {
        return Ok(());
    }
    fsync_fd(fd)
}

fn fsync_fd(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: live fd.
    if unsafe { libc::fsync(fd) } != 0 {
        let e = last_err();
        // Some file systems (and macOS for directories on some volumes)
        // refuse fsync on a directory; the rename / link itself is then
        // as durable as the platform makes it.
        if matches!(e.raw_os_error(), Some(libc::EINVAL) | Some(libc::ENOTSUP)) {
            return Ok(());
        }
        return Err(e);
    }
    Ok(())
}

/// Map an `openat` failure on an object to the store's vocabulary.
fn refuse_open_error(e: std::io::Error, what: &str) -> SyncError {
    match e.raw_os_error() {
        Some(libc::ELOOP) | Some(libc::EMLINK) => SyncError::Refused {
            what: what.to_string(),
            why: "is a symbolic link",
        },
        Some(libc::ENOTDIR) | Some(libc::EISDIR) => SyncError::Refused {
            what: what.to_string(),
            why: "is not a regular file",
        },
        _ => SyncError::Io(e),
    }
}

impl FsStore {
    /// Create a new, empty bundle folder at `path` (which must not exist)
    /// and its six area folders.
    pub fn create(path: &Path) -> Result<Self> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let leaf = path
            .file_name()
            .ok_or_else(|| SyncError::NotABundle(path.display().to_string()))?;
        let pfd = {
            let c = CString::new(parent.as_os_str().as_bytes())
                .map_err(|_| SyncError::NotABundle(path.display().to_string()))?;
            // SAFETY: valid C string.
            let fd = unsafe {
                libc::open(
                    c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(last_err().into());
            }
            // SAFETY: fd just returned by open.
            unsafe { OwnedFd::from_raw_fd(fd) }
        };
        let leaf = leaf
            .to_str()
            .ok_or_else(|| SyncError::NotABundle(path.display().to_string()))?;
        if !mkdir_at(pfd.as_raw_fd(), leaf)? {
            return Err(SyncError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} already exists", path.display()),
            )));
        }
        let root = open_dir_at(pfd.as_raw_fd(), leaf)?;
        for area in Area::ALL {
            mkdir_at(root.as_raw_fd(), area.dir())?;
        }
        fsync_fd(root.as_raw_fd())?;
        fsync_fd(pfd.as_raw_fd())?;
        Self::from_root(path, root)
    }

    /// Open an existing bundle folder. The folder itself must not be a
    /// link; missing area folders are created (a fresh clone of a bundle
    /// may lack an empty `l/`, sync clients drop empty folders).
    pub fn open(path: &Path) -> Result<Self> {
        let c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| SyncError::NotABundle(path.display().to_string()))?;
        // SAFETY: valid C string.
        let fd = unsafe { libc::open(c.as_ptr(), DIR_FLAGS) };
        if fd < 0 {
            let e = last_err();
            return Err(match e.raw_os_error() {
                Some(libc::ELOOP) | Some(libc::ENOTDIR) => SyncError::Refused {
                    what: path.display().to_string(),
                    why: "the bundle folder is a link or not a folder",
                },
                _ => SyncError::Io(e),
            });
        }
        // SAFETY: fd just returned by open.
        let root = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut created = false;
        for area in Area::ALL {
            created |= mkdir_at(root.as_raw_fd(), area.dir())?;
        }
        if created {
            fsync_fd(root.as_raw_fd())?;
        }
        Self::from_root(path, root)
    }

    fn from_root(path: &Path, root: OwnedFd) -> Result<Self> {
        let mut areas = HashMap::new();
        for area in Area::ALL {
            let fd =
                open_dir_at(root.as_raw_fd(), area.dir()).map_err(|e| match e.raw_os_error() {
                    Some(libc::ELOOP) | Some(libc::ENOTDIR) => SyncError::Refused {
                        what: area.dir().to_string(),
                        why: "an area folder is a link or not a folder",
                    },
                    _ => SyncError::Io(e),
                })?;
            areas.insert(area, fd);
        }
        Ok(Self {
            path: path.to_path_buf(),
            root,
            areas,
            shards: HashMap::new(),
            dirty: BTreeSet::new(),
            root_dirty: false,
            unflushed: false,
        })
    }

    /// The fd of `area`'s folder, refused when that folder was moved or
    /// replaced since the store was opened (`still_at`).
    fn area_fd(&self, area: Area) -> Result<RawFd> {
        let fd = self.areas[&area].as_raw_fd();
        if !still_at(fd, self.root.as_raw_fd(), area.dir()) {
            return Err(SyncError::Refused {
                what: area.dir().to_string(),
                why: "an area folder was moved or replaced while the bundle was open",
            });
        }
        Ok(fd)
    }

    /// Folder fd holding `name` in `area`, opening (and with `create`,
    /// making) its shard folder. `Ok(None)` if the shard does not exist.
    fn dir_for(&mut self, area: Area, name: &Name, create: bool) -> Result<Option<RawFd>> {
        if !area.sharded() {
            return Ok(Some(self.area_fd(area)?));
        }
        let shard = name.shard().expect("sharded areas hold object names");
        let afd = self.area_fd(area)?;
        if let Some(fd) = self.shards.get(&(area, shard.clone())) {
            if still_at(fd.as_raw_fd(), afd, &shard) {
                return Ok(Some(fd.as_raw_fd()));
            }
            // Removed (an emptied shard cleaned up) or moved since it was
            // opened: open what the name holds now.
            self.shards.remove(&(area, shard.clone()));
        }
        if create && mkdir_at(afd, &shard)? {
            self.dirty.insert((area, None));
        }
        match open_dir_at(afd, &shard) {
            Ok(fd) => {
                let raw = fd.as_raw_fd();
                self.shards.insert((area, shard), fd);
                Ok(Some(raw))
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(None),
            Err(e) => Err(match e.raw_os_error() {
                Some(libc::ELOOP) | Some(libc::ENOTDIR) => SyncError::Refused {
                    what: format!("{}/{}", area.dir(), shard),
                    why: "a shard folder is a link or not a folder",
                },
                _ => SyncError::Io(e),
            }),
        }
    }

    fn mark_dirty(&mut self, area: Area, name: &Name) {
        let shard = if area.sharded() { name.shard() } else { None };
        self.dirty.insert((area, shard));
    }

    /// Open `leaf` in `dir` for reading under the hostile-file rules and
    /// return it with its size. `Ok(None)` if absent.
    fn open_checked(dir: RawFd, leaf: &str, what: &str) -> Result<Option<(File, u64)>> {
        let c = cstr(leaf)?;
        // SAFETY: valid C string and live fd.
        let fd = unsafe { libc::openat(dir, c.as_ptr(), READ_FLAGS) };
        if fd < 0 {
            let e = last_err();
            if e.raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err(refuse_open_error(e, what));
        }
        // SAFETY: fd just returned by openat.
        let file = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
        // SAFETY: zeroed stat is a valid out-buffer for fstat.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: live fd, valid out pointer.
        if unsafe { libc::fstat(file.as_raw_fd(), &mut st) } != 0 {
            return Err(last_err().into());
        }
        if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(SyncError::Refused {
                what: what.to_string(),
                why: "is not a regular file",
            });
        }
        if st.st_nlink != 1 {
            return Err(SyncError::Refused {
                what: what.to_string(),
                why: "has more than one link (hard link)",
            });
        }
        Ok(Some((file, st.st_size as u64)))
    }

    fn read_bounded(mut file: File, size: u64, what: &str) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; size as usize];
        file.read_exact(&mut buf).map_err(|e| match e.kind() {
            std::io::ErrorKind::UnexpectedEof => SyncError::Refused {
                what: what.to_string(),
                why: "shrank while being read",
            },
            _ => SyncError::Io(e),
        })?;
        let mut probe = [0u8; 1];
        if file.read(&mut probe)? != 0 {
            return Err(SyncError::Refused {
                what: what.to_string(),
                why: "grew while being read",
            });
        }
        Ok(buf)
    }

    /// Write `bytes` to a new temporary file in `dir`, synced
    /// (`sync_object`).
    fn write_tmp(dir: RawFd, bytes: &[u8]) -> Result<String> {
        let tmp = tmp_name()?;
        let c = cstr(&tmp)?;
        // SAFETY: valid C string and live fd.
        let fd = unsafe { libc::openat(dir, c.as_ptr(), CREATE_FLAGS, 0o600 as libc::c_uint) };
        if fd < 0 {
            return Err(last_err().into());
        }
        // SAFETY: fd just returned by openat.
        let mut f = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
        let res = f.write_all(bytes).and_then(|_| sync_object(&f));
        if let Err(e) = res {
            Self::unlink(dir, &tmp);
            return Err(e.into());
        }
        Ok(tmp)
    }

    fn unlink(dir: RawFd, leaf: &str) -> bool {
        match CString::new(leaf) {
            // SAFETY: valid C string and live fd.
            Ok(c) => unsafe { libc::unlinkat(dir, c.as_ptr(), 0) == 0 },
            Err(_) => false,
        }
    }

    /// Publish `tmp` as `leaf` without ever replacing an existing entry
    /// (EEXIST if the name is taken). An exclusive rename first: atomic,
    /// so no crash leaves the temporary name behind as a second link.
    /// File systems without one fall back to `linkat` (which fails if
    /// the name exists) and `unlinkat` of the temporary name, and those
    /// without hard links either (exFAT) to `reserve_and_rename`.
    fn link_no_replace(dir: RawFd, tmp: &str, leaf: &str) -> std::io::Result<()> {
        let ct = CString::new(tmp)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        let cl = CString::new(leaf)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        match rename_no_replace(dir, &ct, &cl) {
            Ok(()) => return Ok(()),
            Err(e) if !rename_unsupported(&e) => return Err(e),
            Err(_) => {}
        }
        // SAFETY: valid C strings and live fds.
        if unsafe { libc::linkat(dir, ct.as_ptr(), dir, cl.as_ptr(), 0) } == 0 {
            Self::unlink(dir, tmp);
            return Ok(());
        }
        let e = last_err();
        if !link_unsupported(&e) {
            return Err(e);
        }
        Self::reserve_and_rename(dir, &ct, &cl)
    }

    /// For a file system with neither an exclusive rename nor hard links
    /// (exFAT, the usual format of a stick shared with Windows): reserve
    /// `leaf` with an exclusive create of an empty placeholder, then
    /// rename the complete `tmp` over it. Only our own placeholder is ever
    /// replaced: the create fails with EEXIST when the name is taken. An
    /// empty placeholder a crash left between the two steps can never be a
    /// valid object (objects are never empty), so a later attempt reuses
    /// it; a reader in between sees an empty object, which it refuses as
    /// incomplete, and garbage collection removes one never completed.
    fn reserve_and_rename(dir: RawFd, tmp: &CStr, leaf: &CStr) -> std::io::Result<()> {
        // SAFETY: valid C string and live fd.
        let fd = unsafe { libc::openat(dir, leaf.as_ptr(), CREATE_FLAGS, 0o600) };
        if fd >= 0 {
            // SAFETY: fd just returned by openat and owned here.
            drop(unsafe { OwnedFd::from_raw_fd(fd) });
        } else {
            let e = last_err();
            if e.raw_os_error() != Some(libc::EEXIST) || !is_empty_placeholder(dir, leaf) {
                return Err(e);
            }
        }
        // SAFETY: valid C strings and live fds.
        if unsafe { libc::renameat(dir, tmp.as_ptr(), dir, leaf.as_ptr()) } != 0 {
            return Err(last_err());
        }
        Ok(())
    }

    /// `sweep_tmp` in one folder.
    fn sweep_dir(dir: RawFd, min_age_ns: u64, now_ns: u64) -> Result<usize> {
        let mut removed = 0;
        for leaf in read_dir_names(dir, crate::store::MAX_LIST_ENTRIES)? {
            if !is_tmp_name(&leaf) {
                continue;
            }
            let c = cstr(&leaf)?;
            // SAFETY: zeroed stat is a valid out-buffer for fstatat.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: valid C string, live fd, valid out pointer; the
            // entry itself is examined, never what a link points to.
            if unsafe { libc::fstatat(dir, c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
                continue;
            }
            if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
                continue;
            }
            // The newer of its data and inode changes: a file still being
            // written is never taken for a leftover.
            let changed =
                (st.st_mtime.max(st.st_ctime).max(0) as u64).saturating_mul(1_000_000_000);
            let old = now_ns.saturating_sub(changed) >= min_age_ns;
            if (st.st_nlink > 1 || old) && Self::unlink(dir, &leaf) {
                removed += 1;
            }
        }
        Ok(removed)
    }
}

/// Hard links the file system does not support (FAT, exFAT), as opposed
/// to a real failure such as EEXIST.
fn link_unsupported(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::Unsupported
        || e.raw_os_error()
            .is_some_and(|c| [libc::ENOTSUP, libc::EOPNOTSUPP, libc::EPERM].contains(&c))
}

/// `leaf` is an empty regular file with one name: a placeholder
/// `reserve_and_rename` made, never an object.
fn is_empty_placeholder(dir: RawFd, leaf: &CStr) -> bool {
    // SAFETY: zeroed stat is a valid out-buffer; valid C string, live fd;
    // the entry itself is examined, not what a link points to.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        libc::fstatat(dir, leaf.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) == 0
            && (st.st_mode & libc::S_IFMT) == libc::S_IFREG
            && st.st_size == 0
            && st.st_nlink == 1
    }
}

/// An exclusive rename the file system (or kernel) does not support, as
/// opposed to a real failure such as EEXIST.
fn rename_unsupported(e: &std::io::Error) -> bool {
    // (ENOTSUP and EOPNOTSUPP are one value on Linux, two on Apple.)
    e.kind() == std::io::ErrorKind::Unsupported
        || e.raw_os_error().is_some_and(|c| {
            [libc::EINVAL, libc::ENOTSUP, libc::EOPNOTSUPP, libc::ENOSYS].contains(&c)
        })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn rename_no_replace(dir: RawFd, from: &CStr, to: &CStr) -> std::io::Result<()> {
    // SAFETY: raw syscall with valid C strings and live fds; renameat2 is
    // called through `syscall` so the static musl build does not depend
    // on a libc wrapper.
    let r = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            dir,
            from.as_ptr(),
            dir,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if r == 0 { Ok(()) } else { Err(last_err()) }
}

#[cfg(target_vendor = "apple")]
fn rename_no_replace(dir: RawFd, from: &CStr, to: &CStr) -> std::io::Result<()> {
    // SAFETY: valid C strings and live fds.
    let r = unsafe { libc::renameatx_np(dir, from.as_ptr(), dir, to.as_ptr(), libc::RENAME_EXCL) };
    if r == 0 { Ok(()) } else { Err(last_err()) }
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn rename_no_replace(_dir: RawFd, _from: &CStr, _to: &CStr) -> std::io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

/// Read every entry name of the folder `fd` (excluding `.` and `..`).
/// Names that are not valid UTF-8 are returned lossily marked so they
/// classify as foreign.
fn read_dir_names(fd: RawFd, cap: usize) -> Result<Vec<String>> {
    // SAFETY: duplicating a live fd; fdopendir takes ownership of the dup.
    let dup = unsafe { libc::dup(fd) };
    if dup < 0 {
        return Err(last_err().into());
    }
    // SAFETY: `dup` is a live directory fd we own.
    let dirp = unsafe { libc::fdopendir(dup) };
    if dirp.is_null() {
        // SAFETY: fdopendir failed, so we still own `dup`.
        unsafe { libc::close(dup) };
        return Err(last_err().into());
    }
    // The dup shares the file offset with `fd`: start from the top.
    // SAFETY: valid DIR*.
    unsafe { libc::rewinddir(dirp) };
    let mut out = Vec::new();
    let result = loop {
        // NULL is both the end and an error: told apart by errno, so an
        // I/O error part way (a network or cloud volume) fails the
        // listing instead of silently cutting it short, which would read
        // as missing commits or objects.
        clear_errno();
        // SAFETY: valid DIR*; readdir returns NULL at the end or on error.
        let ent = unsafe { libc::readdir(dirp) };
        if ent.is_null() {
            let e = last_err();
            break match e.raw_os_error() {
                None | Some(0) => Ok(()),
                Some(_) => Err(SyncError::Io(e)),
            };
        }
        // SAFETY: d_name is NUL-terminated within the dirent.
        let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        if out.len() >= cap {
            break Err(SyncError::Limit("too many entries in a bundle folder"));
        }
        out.push(match std::str::from_utf8(bytes) {
            Ok(s) => s.to_string(),
            Err(_) => format!("<non-UTF-8 name {} bytes>", bytes.len()),
        });
    };
    // SAFETY: valid DIR*, closes the dup'd fd too.
    unsafe { libc::closedir(dirp) };
    result.map(|_| out)
}

impl ObjectStore for FsStore {
    fn list(&mut self, area: Area) -> Result<Listing> {
        let mut l = Listing::default();
        let cap = crate::store::MAX_LIST_ENTRIES;
        let afd = self.area_fd(area)?;
        let entries = read_dir_names(afd, cap)?;
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
            let sfd = match open_dir_at(afd, &shard) {
                Ok(fd) => fd,
                Err(e) if matches!(e.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) => {
                    l.note_foreign(format!("{}/{} (not a folder)", area.dir(), shard));
                    continue;
                }
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
                Err(e) => return Err(e.into()),
            };
            for leaf in read_dir_names(sfd.as_raw_fd(), cap)? {
                l.classify(area, Some(&shard), &leaf)?;
            }
        }
        Ok(l)
    }

    fn read(&mut self, area: Area, name: &Name, len: LenRule) -> Result<Option<Vec<u8>>> {
        let what = name.display(area);
        let Some(dir) = self.dir_for(area, name, false)? else {
            return Ok(None);
        };
        let Some((file, size)) = Self::open_checked(dir, &name.leaf(), &what)? else {
            return Ok(None);
        };
        if !len.allows(size) {
            return Err(SyncError::Refused {
                what,
                why: "wrong size for its kind",
            });
        }
        Self::read_bounded(file, size, &what).map(Some)
    }

    fn create_new(&mut self, area: Area, name: &Name, bytes: &[u8]) -> Result<Created> {
        let dir = self.dir_for(area, name, true)?.expect("created above");
        let tmp = Self::write_tmp(dir, bytes)?;
        let leaf = name.leaf();
        match Self::link_no_replace(dir, &tmp, &leaf) {
            Ok(()) => {
                self.mark_dirty(area, name);
                self.unflushed = true;
                Ok(Created::New)
            }
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                Self::unlink(dir, &tmp);
                let what = name.display(area);
                match Self::open_checked(dir, &leaf, &what)? {
                    Some((f, size)) if size == bytes.len() as u64 => {
                        let existing = Self::read_bounded(f, size, &what)?;
                        if existing == bytes {
                            // Written by an earlier attempt that may not
                            // have reached `sync`: synced again with this
                            // one.
                            self.mark_dirty(area, name);
                            self.unflushed = true;
                            Ok(Created::AlreadyIdentical)
                        } else {
                            Err(SyncError::Collision { name: what })
                        }
                    }
                    _ => Err(SyncError::Collision { name: what }),
                }
            }
            Err(e) => {
                Self::unlink(dir, &tmp);
                Err(e.into())
            }
        }
    }

    fn remove(&mut self, area: Area, name: &Name) -> Result<bool> {
        let Some(dir) = self.dir_for(area, name, false)? else {
            return Ok(false);
        };
        let c = cstr(&name.leaf())?;
        // SAFETY: valid C string and live fd. unlinkat removes the entry
        // itself (a link is removed, not followed).
        if unsafe { libc::unlinkat(dir, c.as_ptr(), 0) } == 0 {
            self.mark_dirty(area, name);
            return Ok(true);
        }
        let e = last_err();
        if e.raw_os_error() == Some(libc::ENOENT) {
            Ok(false)
        } else {
            Err(e.into())
        }
    }

    fn sync(&mut self) -> Result<()> {
        let dirty = std::mem::take(&mut self.dirty);
        for (area, shard) in dirty {
            match shard {
                Some(s) => {
                    if let Some(fd) = self.shards.get(&(area, s)) {
                        fsync_fd(fd.as_raw_fd())?;
                    }
                }
                None => fsync_fd(self.area_fd(area)?)?,
            }
        }
        if std::mem::take(&mut self.root_dirty) {
            fsync_fd(self.root.as_raw_fd())?;
        }
        // Apple platforms: one flush of the disk's cache for everything
        // since the last `sync` (see the module docs).
        // Elsewhere each object was already fsync'd before it was
        // installed.
        if std::mem::take(&mut self.unflushed) {
            #[cfg(target_vendor = "apple")]
            full_flush(self.root.as_raw_fd())?;
        }
        Ok(())
    }

    fn sweep_tmp(&mut self, min_age_ns: u64) -> Result<usize> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let mut removed = 0;
        for area in Area::ALL {
            let afd = self.area_fd(area)?;
            removed += Self::sweep_dir(afd, min_age_ns, now)?;
            if !area.sharded() {
                continue;
            }
            for shard in read_dir_names(afd, crate::store::MAX_LIST_ENTRIES)? {
                if !is_shard_name(&shard) {
                    continue;
                }
                let Ok(sfd) = open_dir_at(afd, &shard) else {
                    continue;
                };
                removed += Self::sweep_dir(sfd.as_raw_fd(), min_age_ns, now)?;
            }
        }
        Ok(removed)
    }

    fn describe(&self) -> String {
        self.path.display().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::ObjectId;
    use std::os::unix::fs::symlink;

    fn fresh() -> (tempfile::TempDir, PathBuf, FsStore) {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("v.lbxs");
        let s = FsStore::create(&p).unwrap();
        (d, p, s)
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
        s.sync().unwrap();
        assert!(p.join("p/3c").join(n.leaf()).is_file());
        assert_eq!(
            s.read(Area::Page, &n, LenRule::Exact(3)).unwrap().unwrap(),
            b"abc"
        );
        assert!(s.read(Area::Page, &n, LenRule::Exact(4)).is_err());
        let l = s.list(Area::Page).unwrap();
        assert_eq!(l.names, vec![n]);
        assert_eq!(l.tmp_count, 0);
        assert!(s.remove(Area::Page, &n).unwrap());
        assert!(!s.remove(Area::Page, &n).unwrap());
        assert!(s.read(Area::Page, &n, LenRule::Exact(3)).unwrap().is_none());
        // Reopen works.
        drop(s);
        FsStore::open(&p).unwrap();
    }

    #[test]
    fn refuses_links_fifos_and_hard_links() {
        let (d, p, mut s) = fresh();
        let outside = d.path().join("secret");
        std::fs::write(&outside, b"xyz").unwrap();
        let n = Name::Object(ObjectId([0x11; 32]));
        let shard = p.join("p/11");
        std::fs::create_dir_all(&shard).unwrap();
        symlink(&outside, shard.join(n.leaf())).unwrap();
        assert!(matches!(
            s.read(Area::Page, &n, LenRule::Exact(3)),
            Err(SyncError::Refused { .. })
        ));

        let n2 = Name::Object(ObjectId([0x12; 32]));
        let shard2 = p.join("p/12");
        std::fs::create_dir_all(&shard2).unwrap();
        std::fs::hard_link(&outside, shard2.join(n2.leaf())).unwrap();
        assert!(matches!(
            s.read(Area::Page, &n2, LenRule::Exact(3)),
            Err(SyncError::Refused { .. })
        ));

        let n3 = Name::Object(ObjectId([0x13; 32]));
        let shard3 = p.join("p/13");
        std::fs::create_dir_all(&shard3).unwrap();
        let fifo = CString::new(shard3.join(n3.leaf()).as_os_str().as_bytes()).unwrap();
        // SAFETY: valid C string.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(matches!(
            s.read(Area::Page, &n3, LenRule::Exact(0)),
            Err(SyncError::Refused { .. })
        ));
    }

    #[test]
    fn refuses_linked_shard_and_bundle_folders() {
        let (d, p, mut s) = fresh();
        let elsewhere = d.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        let n = Name::Object(ObjectId([0x22; 32]));
        std::fs::write(elsewhere.join(n.leaf()), b"abc").unwrap();
        symlink(&elsewhere, p.join("p/22")).unwrap();
        assert!(matches!(
            s.read(Area::Page, &n, LenRule::Exact(3)),
            Err(SyncError::Refused { .. })
        ));
        let l = s.list(Area::Page).unwrap();
        assert!(l.names.is_empty());
        assert_eq!(l.foreign_count, 1);
        // Creating through the linked shard is refused too.
        assert!(s.create_new(Area::Page, &n, b"abc").is_err());
        assert_eq!(std::fs::read(elsewhere.join(n.leaf())).unwrap(), b"abc");

        let link = d.path().join("link.lbxs");
        symlink(&p, &link).unwrap();
        assert!(matches!(
            FsStore::open(&link),
            Err(SyncError::Refused { .. })
        ));
    }

    fn nlink(p: &Path) -> u64 {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(p).unwrap().nlink()
    }

    /// The install for file systems with neither an exclusive rename nor
    /// hard links (exFAT): a new name is taken, an existing object is
    /// never replaced, and an empty placeholder a crash left is reused.
    #[test]
    fn reserve_and_rename_never_replaces_an_object() {
        use std::os::fd::AsRawFd as _;
        let d = tempfile::tempdir().unwrap();
        let dir = std::fs::File::open(d.path()).unwrap();
        let fd = dir.as_raw_fd();
        let put = |name: &str, body: &[u8]| std::fs::write(d.path().join(name), body).unwrap();
        let c = |s: &str| CString::new(s).unwrap();
        // A free name.
        put(".tmp-1", b"object one");
        FsStore::reserve_and_rename(fd, &c(".tmp-1"), &c("obj")).unwrap();
        assert_eq!(std::fs::read(d.path().join("obj")).unwrap(), b"object one");
        assert!(!d.path().join(".tmp-1").exists());
        // Taken by an object: refused, the object untouched.
        put(".tmp-2", b"intruder");
        let e = FsStore::reserve_and_rename(fd, &c(".tmp-2"), &c("obj")).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EEXIST));
        assert_eq!(std::fs::read(d.path().join("obj")).unwrap(), b"object one");
        // An empty placeholder from a crash: reused.
        put("obj2", b"");
        put(".tmp-3", b"object two");
        FsStore::reserve_and_rename(fd, &c(".tmp-3"), &c("obj2")).unwrap();
        assert_eq!(std::fs::read(d.path().join("obj2")).unwrap(), b"object two");
    }

    /// A shard folder the session holds open is moved away (a sync client
    /// or the provider): the next object goes into the folder the name
    /// holds now, never into the moved one outside the bundle. A shard
    /// removed and made again (an emptied one cleaned up) likewise.
    #[test]
    fn a_moved_shard_folder_is_never_written_through() {
        let (d, p, mut s) = fresh();
        let a = Name::Object(ObjectId([0x5a; 32]));
        let mut b_id = [0x5a; 32];
        b_id[31] = 1;
        let b = Name::Object(ObjectId(b_id));
        s.create_new(Area::Page, &a, b"first").unwrap();
        let outside = d.path().join("outside-5a");
        std::fs::rename(p.join("p/5a"), &outside).unwrap();
        s.create_new(Area::Page, &b, b"second").unwrap();
        s.sync().unwrap();
        assert!(
            p.join("p/5a").join(b.leaf()).is_file(),
            "not written into the bundle"
        );
        assert!(
            !outside.join(b.leaf()).exists(),
            "written into the moved folder"
        );
        assert_eq!(
            s.read(Area::Page, &b, LenRule::Exact(6)).unwrap().unwrap(),
            b"second"
        );
        // Removed and made again: still found and written through the new one.
        std::fs::remove_file(p.join("p/5a").join(b.leaf())).unwrap();
        std::fs::remove_dir(p.join("p/5a")).unwrap();
        s.create_new(Area::Page, &b, b"third").unwrap();
        assert!(p.join("p/5a").join(b.leaf()).is_file());
    }

    /// An area folder moved away while the bundle is open is refused
    /// instead of written through.
    #[test]
    fn a_moved_area_folder_is_refused() {
        let (d, p, mut s) = fresh();
        let n = Name::Object(ObjectId([0x6c; 32]));
        s.create_new(Area::Page, &n, b"x").unwrap();
        std::fs::rename(p.join("p"), d.path().join("p-elsewhere")).unwrap();
        std::fs::create_dir(p.join("p")).unwrap();
        let m = Name::Object(ObjectId([0x6d; 32]));
        assert!(matches!(
            s.create_new(Area::Page, &m, b"y"),
            Err(SyncError::Refused { .. })
        ));
        assert!(!d.path().join("p-elsewhere/6d").exists());
    }

    #[test]
    fn objects_are_installed_without_a_second_link() {
        let (_d, p, mut s) = fresh();
        let n = Name::Object(ObjectId([0x5a; 32]));
        s.create_new(Area::Page, &n, b"abc").unwrap();
        s.sync().unwrap();
        let shard = p.join("p/5a");
        assert_eq!(nlink(&shard.join(n.leaf())), 1);
        let names: Vec<_> = std::fs::read_dir(&shard)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from(n.leaf())]);
        // Exclusive, as before: never replaced.
        assert!(matches!(
            s.create_new(Area::Page, &n, b"abd"),
            Err(SyncError::Collision { .. })
        ));
        assert_eq!(nlink(&shard.join(n.leaf())), 1);
    }

    #[test]
    fn sweep_removes_leftover_links_and_old_temporary_files_only() {
        let (_d, p, mut s) = fresh();
        let n = Name::Object(ObjectId([0x6b; 32]));
        s.create_new(Area::Manifest, &n, b"commit").unwrap();
        let shard = p.join("m/6b");
        let obj = shard.join(n.leaf());
        // A crash between linkat and unlinkat: the object has two links
        // and is refused when read.
        let leftover = shard.join(".tmp-00000000000000000000000000000001");
        std::fs::hard_link(&obj, &leftover).unwrap();
        assert!(matches!(
            s.read(Area::Manifest, &n, LenRule::AtMost(100)),
            Err(SyncError::Refused { .. })
        ));
        // A write in progress (maybe another device's), and a file
        // outside the grammar.
        let young = p.join("h/.tmp-00000000000000000000000000000002");
        std::fs::write(&young, b"in flight").unwrap();
        let foreign = p.join("h/.tmp-not-ours");
        std::fs::write(&foreign, b"x").unwrap();
        assert_eq!(s.sweep_tmp(crate::store::TMP_SWEEP_AGE_NS).unwrap(), 1);
        assert!(!leftover.exists() && young.exists() && foreign.exists());
        assert_eq!(
            s.read(Area::Manifest, &n, LenRule::AtMost(100))
                .unwrap()
                .unwrap(),
            b"commit"
        );
        // Old enough: gone too. The foreign file stays.
        assert_eq!(s.sweep_tmp(0).unwrap(), 1);
        assert!(!young.exists() && foreign.exists());
        assert_eq!(s.sweep_tmp(0).unwrap(), 0);
    }

    #[test]
    fn never_overwrites_and_foreign_entries() {
        let (_d, p, mut s) = fresh();
        let n = Name::Object(ObjectId([0x44; 32]));
        s.create_new(Area::Lease, &n, b"one").unwrap();
        assert!(matches!(
            s.create_new(Area::Lease, &n, b"two"),
            Err(SyncError::Collision { .. })
        ));
        assert_eq!(
            s.read(Area::Lease, &n, LenRule::AtMost(10))
                .unwrap()
                .unwrap(),
            b"one"
        );
        std::fs::write(
            p.join("l").join(format!("{} (conflicted copy)", n.leaf())),
            b"x",
        )
        .unwrap();
        std::fs::write(p.join("l/.DS_Store"), b"x").unwrap();
        let l = s.list(Area::Lease).unwrap();
        assert_eq!(l.names, vec![n]);
        assert_eq!(l.foreign_count, 2);
    }
}
