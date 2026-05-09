// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! macOS FUSE-T mount adapter.
//!
//! Mirrors the responsibilities of `fuse.rs` (the macFUSE/Linux
//! adapter) but talks to FUSE-T's libfuse 2.x high-level API via the
//! `luksbox-fuse-t` binding crate. The big shape difference from
//! `fuse.rs` is path-based vs. inode-based: libfuse 2.x high-level
//! callbacks take `&Path`, so every method does an extra
//! `Vfs::lookup_path` to resolve to a `FileId` before the actual op.
//!
//! Performance: the per-call `lookup_path` walks the in-memory tree,
//! which is O(depth) hash lookups, fine for personal-vault depths.
//! If profiling on large vaults shows it dominates, the Phase 2 fix
//! is to cache `(path, FileId)` in a small LRU keyed on the inode
//! tree generation counter.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use luksbox_fuse_t::{
    DirEntry as FtDirEntry, Errno, FileAttr, Filesystem, MountOptions, S_IFDIR, S_IFREG,
};
use luksbox_vfs::{Error as VfsError, FileId, InodeKind, Vfs};

pub fn mount(vfs: Vfs, mountpoint: &Path, _daemonize: bool) -> Result<(), super::MountError> {
    // FUSE-T's high-level API blocks the calling thread until unmount,
    // and installs its own SIGINT handler so Ctrl-C unmounts cleanly.
    // We don't fork/daemonize here, the CLI binary does that one
    // level up if needed (mirroring the structure in fuse.rs but
    // moving the fork to the caller, which is cleaner anyway).
    let fs = LuksboxFuseTFs::new(vfs);
    let mut options = MountOptions::default();
    // Show a friendlier name in Finder than the default "luksbox".
    options.volname = Some("LUKSbox".to_string());
    luksbox_fuse_t::mount(fs, mountpoint, &options)
        .map_err(|e| super::MountError::Io(std::io::Error::other(format!("FUSE-T: {e}"))))
}

pub fn unmount(mountpoint: &Path) -> Result<(), super::MountError> {
    luksbox_fuse_t::unmount(mountpoint)
        .map_err(|e| super::MountError::Io(std::io::Error::other(format!("FUSE-T: {e}"))))
}

struct LuksboxFuseTFs {
    vfs: Mutex<Vfs>,
    uid: u32,
    gid: u32,
}

impl LuksboxFuseTFs {
    fn new(vfs: Vfs) -> Self {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        Self {
            vfs: Mutex::new(vfs),
            uid,
            gid,
        }
    }

    /// Convert a Vfs error to the closest libfuse errno.
    fn vfs_errno(e: &VfsError) -> Errno {
        match e {
            VfsError::NotFound => Errno::ENOENT,
            VfsError::AlreadyExists => Errno::EEXIST,
            VfsError::NotADirectory => Errno::ENOTDIR,
            VfsError::IsADirectory => Errno::EISDIR,
            VfsError::NotAFile => Errno::EISDIR,
            VfsError::NotEmpty => Errno::ENOTEMPTY,
            VfsError::InvalidPath(_) => Errno::EINVAL,
            _ => Errno::EIO,
        }
    }

    /// Convert &Path to a posix-style "/foo/bar" string Vfs expects.
    /// Returns Err(EINVAL) for non-UTF-8 paths.
    fn posix_str(path: &Path) -> Result<String, Errno> {
        path.to_str().map(String::from).ok_or(Errno::EINVAL)
    }

    /// Split "/parent/name" -> ("/parent", "name"). Returns
    /// `("/", name)` for top-level entries. Caller-side EINVAL if the
    /// path has no name component (e.g. "/" or empty).
    fn split_parent_name(path: &Path) -> Result<(PathBuf, String), Errno> {
        let parent = path.parent().ok_or(Errno::EINVAL)?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(Errno::EINVAL)?
            .to_string();
        let parent = if parent.as_os_str().is_empty() {
            PathBuf::from("/")
        } else {
            parent.to_path_buf()
        };
        Ok((parent, name))
    }

    fn lookup_id(&self, vfs: &Vfs, path: &Path) -> Result<FileId, Errno> {
        let s = Self::posix_str(path)?;
        vfs.lookup_path(&s).map_err(|e| Self::vfs_errno(&e))
    }
}

impl Filesystem for LuksboxFuseTFs {
    fn getattr(&self, path: &Path) -> Result<FileAttr, Errno> {
        let mut vfs = self.vfs.lock().map_err(|_| Errno::EIO)?;
        let id = self.lookup_id(&vfs, path)?;
        let stat = vfs.stat(id).map_err(|e| Self::vfs_errno(&e))?;
        let (mode_bits, perm, nlink) = match stat.kind {
            InodeKind::Directory => (S_IFDIR, 0o700u32, 2),
            InodeKind::File => (S_IFREG, 0o600u32, 1),
        };
        Ok(FileAttr {
            mode: mode_bits | perm,
            size: stat.size,
            uid: self.uid,
            gid: self.gid,
            mtime_ns: stat.mtime_ns as u128,
            nlink,
        })
    }

    fn readdir(&self, path: &Path) -> Result<Vec<FtDirEntry>, Errno> {
        let vfs = self.vfs.lock().map_err(|_| Errno::EIO)?;
        let id = self.lookup_id(&vfs, path)?;
        let entries = vfs.readdir(id).map_err(|e| Self::vfs_errno(&e))?;
        Ok(entries
            .into_iter()
            .map(|e| FtDirEntry {
                name: e.name,
                ino: Some(e.id),
                mode: match e.kind {
                    InodeKind::Directory => S_IFDIR,
                    InodeKind::File => S_IFREG,
                },
            })
            .collect())
    }

    fn read(&self, path: &Path, buf: &mut [u8], offset: u64) -> Result<usize, Errno> {
        let mut vfs = self.vfs.lock().map_err(|_| Errno::EIO)?;
        let id = self.lookup_id(&vfs, path)?;
        vfs.read(id, offset, buf).map_err(|e| Self::vfs_errno(&e))
    }

    fn write(&self, path: &Path, data: &[u8], offset: u64) -> Result<usize, Errno> {
        let mut vfs = self.vfs.lock().map_err(|_| Errno::EIO)?;
        let id = self.lookup_id(&vfs, path)?;
        vfs.write(id, offset, data).map_err(|e| Self::vfs_errno(&e))
    }

    fn create(&self, path: &Path, _mode: u32) -> Result<(), Errno> {
        let (parent, name) = Self::split_parent_name(path)?;
        let mut vfs = self.vfs.lock().map_err(|_| Errno::EIO)?;
        let parent_id = self.lookup_id(&vfs, &parent)?;
        vfs.create(parent_id, &name).map_err(|e| Self::vfs_errno(&e))?;
        let _ = vfs.flush();
        Ok(())
    }

    fn mkdir(&self, path: &Path, _mode: u32) -> Result<(), Errno> {
        let (parent, name) = Self::split_parent_name(path)?;
        let mut vfs = self.vfs.lock().map_err(|_| Errno::EIO)?;
        let parent_id = self.lookup_id(&vfs, &parent)?;
        vfs.mkdir(parent_id, &name).map_err(|e| Self::vfs_errno(&e))?;
        // Empty dirs create no chunks; flush now or the metadata
        // change won't survive a subsequent unmount. Same reasoning
        // as fuse.rs:mkdir.
        let _ = vfs.flush();
        Ok(())
    }

    fn unlink(&self, path: &Path) -> Result<(), Errno> {
        let (parent, name) = Self::split_parent_name(path)?;
        let mut vfs = self.vfs.lock().map_err(|_| Errno::EIO)?;
        let parent_id = self.lookup_id(&vfs, &parent)?;
        vfs.unlink(parent_id, &name).map_err(|e| Self::vfs_errno(&e))?;
        let _ = vfs.flush();
        Ok(())
    }

    fn rmdir(&self, path: &Path) -> Result<(), Errno> {
        let (parent, name) = Self::split_parent_name(path)?;
        let mut vfs = self.vfs.lock().map_err(|_| Errno::EIO)?;
        let parent_id = self.lookup_id(&vfs, &parent)?;
        vfs.rmdir(parent_id, &name).map_err(|e| Self::vfs_errno(&e))?;
        let _ = vfs.flush();
        Ok(())
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<(), Errno> {
        let (from_parent, from_name) = Self::split_parent_name(from)?;
        let (to_parent, to_name) = Self::split_parent_name(to)?;
        if from_parent != to_parent {
            // Cross-directory rename intentionally not in v1, matches
            // the same restriction in fuse.rs.
            return Err(Errno::from_raw(libc::ENOSYS));
        }
        let mut vfs = self.vfs.lock().map_err(|_| Errno::EIO)?;
        let parent_id = self.lookup_id(&vfs, &from_parent)?;
        vfs.rename(parent_id, &from_name, &to_name)
            .map_err(|e| Self::vfs_errno(&e))?;
        let _ = vfs.flush();
        Ok(())
    }

    fn truncate(&self, path: &Path, size: u64) -> Result<(), Errno> {
        let mut vfs = self.vfs.lock().map_err(|_| Errno::EIO)?;
        let id = self.lookup_id(&vfs, path)?;
        vfs.truncate(id, size).map_err(|e| Self::vfs_errno(&e))?;
        let _ = vfs.flush();
        Ok(())
    }

    fn flush(&self, _path: &Path) -> Result<(), Errno> {
        let mut vfs = self.vfs.lock().map_err(|_| Errno::EIO)?;
        vfs.flush().map_err(|e| Self::vfs_errno(&e))
    }

    fn fsync(&self, _path: &Path, _datasync: bool) -> Result<(), Errno> {
        let mut vfs = self.vfs.lock().map_err(|_| Errno::EIO)?;
        vfs.flush().map_err(|e| Self::vfs_errno(&e))
    }

    fn release(&self, _path: &Path) -> Result<(), Errno> {
        // Mirror fuse.rs's release(): flush metadata so a write +
        // close pattern (Finder copy, `cp`, etc.) survives unmount.
        // The WinFsp adapter's data-loss bug fix earlier this session
        // applies here too, libfuse calls release() at close(2)
        // time, and that's when our chunk index needs to land on
        // disk.
        let mut vfs = self.vfs.lock().map_err(|_| Errno::EIO)?;
        let _ = vfs.flush();
        Ok(())
    }

    fn destroy(&self) {
        // Final teardown after kernel unmount. Belt-and-suspenders
        // flush so anything held back by release()'s soft-flush gets
        // out.
        if let Ok(mut vfs) = self.vfs.lock() {
            let _ = vfs.flush();
        }
    }
}
