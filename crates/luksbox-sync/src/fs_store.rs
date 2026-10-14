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
//!   published with `linkat`, which fails if the name exists: an object
//!   is never overwritten (a lease refresh is a new object too).
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
use crate::names::{Area, Name, is_shard_name, tmp_name};
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
        })
    }

    fn area_fd(&self, area: Area) -> RawFd {
        self.areas[&area].as_raw_fd()
    }

    /// Folder fd holding `name` in `area`, opening (and with `create`,
    /// making) its shard folder. `Ok(None)` if the shard does not exist.
    fn dir_for(&mut self, area: Area, name: &Name, create: bool) -> Result<Option<RawFd>> {
        if !area.sharded() {
            return Ok(Some(self.area_fd(area)));
        }
        let shard = name.shard().expect("sharded areas hold object names");
        if let Some(fd) = self.shards.get(&(area, shard.clone())) {
            return Ok(Some(fd.as_raw_fd()));
        }
        let afd = self.area_fd(area);
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

    /// Write `bytes` to a new temporary file in `dir`, fsync'd.
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
        let res = f.write_all(bytes).and_then(|_| f.sync_all());
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

    /// Publish `tmp` as `leaf` without ever replacing an existing entry.
    /// `linkat` fails with EEXIST if the name is taken; file systems
    /// without hard links fall back to an exclusive rename where the
    /// platform has one.
    fn link_no_replace(dir: RawFd, tmp: &str, leaf: &str) -> std::io::Result<()> {
        let ct = CString::new(tmp)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        let cl = CString::new(leaf)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        // SAFETY: valid C strings and live fds.
        if unsafe { libc::linkat(dir, ct.as_ptr(), dir, cl.as_ptr(), 0) } == 0 {
            Self::unlink(dir, tmp);
            return Ok(());
        }
        let e = last_err();
        match e.raw_os_error() {
            Some(libc::EPERM) | Some(libc::ENOTSUP) | Some(libc::EXDEV) | Some(libc::EMLINK)
            | Some(libc::ENOSYS) => rename_no_replace(dir, &ct, &cl),
            _ => Err(e),
        }
    }
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
        // SAFETY: valid DIR*; readdir returns NULL at the end or on error.
        let ent = unsafe { libc::readdir(dirp) };
        if ent.is_null() {
            break Ok(());
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
        let afd = self.area_fd(area);
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
                Ok(Created::New)
            }
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                Self::unlink(dir, &tmp);
                let what = name.display(area);
                match Self::open_checked(dir, &leaf, &what)? {
                    Some((f, size)) if size == bytes.len() as u64 => {
                        let existing = Self::read_bounded(f, size, &what)?;
                        if existing == bytes {
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
                None => fsync_fd(self.area_fd(area))?,
            }
        }
        if std::mem::take(&mut self.root_dirty) {
            fsync_fd(self.root.as_raw_fd())?;
        }
        Ok(())
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
