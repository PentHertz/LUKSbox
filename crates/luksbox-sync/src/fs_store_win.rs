// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! The bundle folder on disk, Windows.
//!
//! Same hostile-input rules as the Unix store (`fs_store.rs`), with the
//! Windows means the rest of LuksBox already uses against junctions:
//!
//! - Every file and folder is opened with `FILE_FLAG_OPEN_REPARSE_POINT`,
//!   so a final-component symlink or junction is opened as itself, and
//!   refused when its attributes show a reparse point.
//! - The handle's resolved path (`GetFinalPathNameByHandleW`) must equal
//!   the path the bundle expects (`<bundle>\<area>\[<shard>\]<leaf>`,
//!   built from grammar-checked names): a junction anywhere inside the
//!   bundle resolves elsewhere and is refused.
//! - Reads are bounded by the expected size and checked for EOF.
//! - New objects are published with `atomic_secure_create_new` (no
//!   clobber: `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING`); nothing
//!   is ever overwritten. Deletions remove the entry itself.
//!
//! Windows has no directory fsync; the file data is flushed by the
//! atomic-write helpers before the rename.

#![cfg(windows)]

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use luksbox_core::file_util::{final_path_by_handle, long_path_name, windows_paths_eq_ci};

use crate::error::{Result, SyncError};
use crate::names::{Area, Name, is_shard_name};
use crate::store::{Created, LenRule, Listing, ObjectStore};

const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;

pub struct FsStore {
    /// The bundle folder as the system resolves it (no junction).
    root: PathBuf,
    display: PathBuf,
}

fn refused(what: &Path, why: &'static str) -> SyncError {
    SyncError::Refused {
        what: what.display().to_string(),
        why,
    }
}

/// Open `p` (file or folder) without following a final reparse point,
/// and require it to be exactly `p` (no junction on the way) and of the
/// expected kind.
fn open_checked(p: &Path, dir: bool) -> std::io::Result<Option<File>> {
    let mut o = OpenOptions::new();
    o.read(true);
    let mut flags = FILE_FLAG_OPEN_REPARSE_POINT;
    if dir {
        flags |= FILE_FLAG_BACKUP_SEMANTICS;
    }
    o.custom_flags(flags);
    let f = match o.open(p) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let attrs = f.metadata()?.file_attributes();
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "is a symbolic link or junction",
        ));
    }
    if (attrs & FILE_ATTRIBUTE_DIRECTORY != 0) != dir {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "is not the expected kind of entry",
        ));
    }
    let resolved = final_path_by_handle(&f)?;
    if !windows_paths_eq_ci(&resolved, &long_path_name(p)) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "a junction in the bundle redirected the path",
        ));
    }
    Ok(Some(f))
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
        let f = open_checked_root(&abs)
            .map_err(|_| refused(&abs, "the bundle folder is a link or not a folder"))?;
        let root = final_path_by_handle(&f)?;
        drop(f);
        let store = Self {
            root,
            display: path.to_path_buf(),
        };
        for area in Area::ALL {
            let p = store.root.join(area.dir());
            match std::fs::create_dir(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
            open_checked(&p, true)
                .map_err(|_| refused(&p, "an area folder is a link or not a folder"))?
                .ok_or_else(|| refused(&p, "an area folder is missing"))?;
        }
        Ok(store)
    }

    fn dir_path(&self, area: Area, name: &Name, create: bool) -> Result<Option<PathBuf>> {
        let mut p = self.root.join(area.dir());
        if area.sharded() {
            p = p.join(name.shard().expect("sharded areas hold object names"));
            if create {
                match std::fs::create_dir(&p) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e.into()),
                }
            }
            match open_checked(&p, true) {
                Ok(Some(_)) => {}
                Ok(None) => return Ok(None),
                Err(_) => return Err(refused(&p, "a shard folder is a link or not a folder")),
            }
        }
        Ok(Some(p))
    }
}

/// The root may be reached through a link the user chose (only its own
/// final component must not be one), so its resolved path is taken as
/// the reference rather than compared with the given path.
fn open_checked_root(p: &Path) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);
    let f = o.open(p)?;
    let attrs = f.metadata()?.file_attributes();
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 || attrs & FILE_ATTRIBUTE_DIRECTORY == 0 {
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

impl ObjectStore for FsStore {
    fn list(&mut self, area: Area) -> Result<Listing> {
        let mut l = Listing::default();
        let cap = crate::store::MAX_LIST_ENTRIES;
        let adir = self.root.join(area.dir());
        if open_checked(&adir, true)
            .map_err(|_| refused(&adir, "an area folder is a link"))?
            .is_none()
        {
            return Ok(l);
        }
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
            match open_checked(&sdir, true) {
                Ok(Some(_)) => {}
                Ok(None) => continue,
                Err(_) => {
                    l.note_foreign(format!("{}/{} (not a folder)", area.dir(), shard));
                    continue;
                }
            }
            for leaf in list_names(&sdir, cap)? {
                l.classify(area, Some(&shard), &leaf)?;
            }
        }
        Ok(l)
    }

    fn read(&mut self, area: Area, name: &Name, len: LenRule) -> Result<Option<Vec<u8>>> {
        let what = name.display(area);
        let Some(dir) = self.dir_path(area, name, false)? else {
            return Ok(None);
        };
        let p = dir.join(name.leaf());
        let mut f = match open_checked(&p, false) {
            Ok(Some(f)) => f,
            Ok(None) => return Ok(None),
            Err(_) => {
                return Err(SyncError::Refused {
                    what,
                    why: "is a link, a junction or not a regular file",
                });
            }
        };
        let size = f.metadata()?.len();
        if !len.allows(size) {
            return Err(SyncError::Refused {
                what,
                why: "wrong size for its kind",
            });
        }
        let mut buf = vec![0u8; size as usize];
        f.read_exact(&mut buf).map_err(|_| SyncError::Refused {
            what: what.clone(),
            why: "shrank while being read",
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

    fn create_new(&mut self, area: Area, name: &Name, bytes: &[u8]) -> Result<Created> {
        let dir = self.dir_path(area, name, true)?.expect("created above");
        let p = dir.join(name.leaf());
        match luksbox_core::file_util::atomic_secure_create_new(&p, bytes) {
            Ok(()) => Ok(Created::New),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                match self.read(area, name, LenRule::Exact(bytes.len()))? {
                    Some(existing) if existing == bytes => Ok(Created::AlreadyIdentical),
                    _ => Err(SyncError::Collision {
                        name: name.display(area),
                    }),
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    fn remove(&mut self, area: Area, name: &Name) -> Result<bool> {
        let Some(dir) = self.dir_path(area, name, false)? else {
            return Ok(false);
        };
        let p = dir.join(name.leaf());
        // remove_file deletes a link itself, never its target.
        match std::fs::remove_file(&p) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    fn sync(&mut self) -> Result<()> {
        Ok(())
    }

    fn describe(&self) -> String {
        self.display.display().to_string()
    }
}
