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
    DirEntry as FtDirEntry, Errno, FileAttr, Filesystem, MountOptions, S_IFDIR, S_IFLNK, S_IFREG,
    StatVfs,
};
use luksbox_vfs::{Error as VfsError, FileId, InodeKind, Vfs};

use crate::unix_statvfs::host_fs_statvfs;

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
    /// Directory containing the .lbx vault file, cached at construction
    /// time so `statfs` can probe the host filesystem for real free-space
    /// numbers. macOS's NFS-bridge that FUSE-T runs through takes the
    /// statfs reply literally and refuses WRITE3 RPCs (Finder shows "not
    /// enough space" and blocks file copy) if we surface `f_bavail == 0`,
    /// which is what the default trait impl returns. Mirrors the same
    /// pattern in fuse.rs for libfuse/macFUSE.
    vault_parent: Option<PathBuf>,
}

impl LuksboxFuseTFs {
    fn new(vfs: Vfs) -> Self {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let vault_parent = vfs
            .container()
            .vault_path()
            .parent()
            .map(|p| p.to_path_buf());
        Self {
            vfs: Mutex::new(vfs),
            uid,
            gid,
            vault_parent,
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
            VfsError::RenameCycle => Errno::EINVAL,
            VfsError::MetadataBudgetExhausted => Errno::ENOSPC,
            VfsError::FileSizeExceedsCap => Errno::EFBIG,
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
        // LBM4: use the persisted mode bits when available; mask
        // to 0o7777 so file-type bits don't double-up with the
        // explicit S_IF* added below. nlink for files comes from
        // the persisted link_count (hardlinks); directories report
        // the conventional 2; symlinks 1.
        let (mode_bits, nlink) = match stat.kind {
            InodeKind::Directory => (S_IFDIR, 2u32),
            InodeKind::File => (S_IFREG, stat.link_count.max(1)),
            InodeKind::Symlink => (S_IFLNK, 1u32),
        };
        let perm = stat.mode & 0o7777;
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
                    InodeKind::Symlink => S_IFLNK,
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
        vfs.create(parent_id, &name)
            .map_err(|e| Self::vfs_errno(&e))?;
        let _ = vfs.flush();
        Ok(())
    }

    fn mkdir(&self, path: &Path, _mode: u32) -> Result<(), Errno> {
        let (parent, name) = Self::split_parent_name(path)?;
        let mut vfs = self.vfs.lock().map_err(|_| Errno::EIO)?;
        let parent_id = self.lookup_id(&vfs, &parent)?;
        vfs.mkdir(parent_id, &name)
            .map_err(|e| Self::vfs_errno(&e))?;
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
        vfs.unlink(parent_id, &name)
            .map_err(|e| Self::vfs_errno(&e))?;
        let _ = vfs.flush();
        Ok(())
    }

    fn rmdir(&self, path: &Path) -> Result<(), Errno> {
        let (parent, name) = Self::split_parent_name(path)?;
        let mut vfs = self.vfs.lock().map_err(|_| Errno::EIO)?;
        let parent_id = self.lookup_id(&vfs, &parent)?;
        vfs.rmdir(parent_id, &name)
            .map_err(|e| Self::vfs_errno(&e))?;
        let _ = vfs.flush();
        Ok(())
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<(), Errno> {
        let (from_parent, from_name) = Self::split_parent_name(from)?;
        let (to_parent, to_name) = Self::split_parent_name(to)?;
        let mut vfs = self.vfs.lock().map_err(|_| Errno::EIO)?;
        let from_parent_id = self.lookup_id(&vfs, &from_parent)?;
        // Reuse the same id for same-parent renames so the VFS can
        // detect the case and take its faster single-get_mut path.
        // For cross-parent moves, the two lookups are distinct.
        let to_parent_id = if from_parent == to_parent {
            from_parent_id
        } else {
            self.lookup_id(&vfs, &to_parent)?
        };
        vfs.rename(from_parent_id, &from_name, to_parent_id, &to_name)
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

    /// Persistent chmod (LBM4). The mode is `S_IFREG|S_IFDIR|...`
    /// bits OR'd with permission bits; `Vfs::chmod` masks to
    /// `0o7777` internally so file-type bits don't leak into the
    /// stored mode.
    fn chmod(&self, path: &Path, mode: u32) -> Result<(), Errno> {
        let mut vfs = self.vfs.lock().map_err(|_| Errno::EIO)?;
        let id = self.lookup_id(&vfs, path)?;
        vfs.chmod(id, mode).map_err(|e| Self::vfs_errno(&e))?;
        let _ = vfs.flush();
        Ok(())
    }

    /// Hardlink (LBM4). POSIX semantics: `from` must exist (and be
    /// a regular file), `to` must not exist; both paths are vault-
    /// internal. `Vfs::link` enforces these and refcount-protects
    /// the chunks via `link_count`.
    fn link(&self, from: &Path, to: &Path) -> Result<(), Errno> {
        let (to_parent_path, to_name) = Self::split_parent_name(to)?;
        let mut vfs = self.vfs.lock().map_err(|_| Errno::EIO)?;
        let target_id = self.lookup_id(&vfs, from)?;
        let new_parent_id = self.lookup_id(&vfs, &to_parent_path)?;
        vfs.link(target_id, new_parent_id, &to_name)
            .map_err(|e| Self::vfs_errno(&e))?;
        let _ = vfs.flush();
        Ok(())
    }

    /// Create a symlink. `target` is the stored value (vault-
    /// internal relative path); `linkpath` is where the symlink
    /// lives. `Vfs::symlink` runs `is_safe_symlink_target` so any
    /// attempt to store `/etc/shadow`, `../../outside`, or other
    /// escape vectors is rejected at create time -- the supply-
    /// chain `secret -> /etc/shadow` attack is blocked at the
    /// VFS layer regardless of which mount backend invoked us.
    fn symlink(&self, target: &Path, linkpath: &Path) -> Result<(), Errno> {
        let target_str = target.to_str().ok_or(Errno::EINVAL)?;
        let (link_parent, link_name) = Self::split_parent_name(linkpath)?;
        let mut vfs = self.vfs.lock().map_err(|_| Errno::EIO)?;
        let parent_id = self.lookup_id(&vfs, &link_parent)?;
        vfs.symlink(parent_id, &link_name, target_str)
            .map_err(|e| Self::vfs_errno(&e))?;
        let _ = vfs.flush();
        Ok(())
    }

    /// Read a symlink's stored target into the libfuse-supplied
    /// buffer. We copy at most `buf.len()` bytes; longer targets
    /// are truncated (libfuse's contract -- it sized the buffer
    /// at PATH_MAX = 4096 which matches our `MAX_SYMLINK_TARGET_LEN`,
    /// so practical truncation is impossible).
    fn readlink(&self, path: &Path, buf: &mut [u8]) -> Result<usize, Errno> {
        let vfs = self.vfs.lock().map_err(|_| Errno::EIO)?;
        let id = self.lookup_id(&vfs, path)?;
        let target = vfs.readlink(id).map_err(|e| Self::vfs_errno(&e))?;
        let n = target.len().min(buf.len());
        buf[..n].copy_from_slice(&target.as_bytes()[..n]);
        Ok(n)
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

    fn statfs(&self, _path: &Path) -> Result<StatVfs, Errno> {
        // FUSE-T routes through the macOS NFS client, which gates
        // WRITE3 on the server's reported `f_bavail`. The default
        // trait impl returns zeros and breaks every Finder copy
        // ("not enough space" - even for a small file - while mkdir
        // still works because it does not pass through WRITE3).
        // Query the host filesystem so growth is bounded by real disk
        // space and Finder lets the user write.
        let host = self.vault_parent.as_deref().and_then(host_fs_statvfs);
        match host {
            Some(s) => Ok(StatVfs {
                blocks: s.blocks,
                bfree: s.bfree,
                bavail: s.bavail,
                files: s.files,
                ffree: s.ffree,
                bsize: s.bsize,
                frsize: s.frsize,
                namemax: 255,
            }),
            // Conservative fallback: 1 TiB worth of 4 KiB blocks so
            // writes aren't rejected when statvfs is unavailable.
            // Matches the libfuse fallback in fuse.rs.
            None => Ok(StatVfs {
                blocks: 256 * 1024 * 1024,
                bfree: 256 * 1024 * 1024,
                bavail: 256 * 1024 * 1024,
                files: 1_000_000,
                ffree: 1_000_000,
                bsize: 4096,
                frsize: 4096,
                namemax: 255,
            }),
        }
    }
}
