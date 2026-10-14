// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! luksbox-merge: merge two versions of a vault.
//!
//! `merge(base, ours, target, ..)` replays the changes `ours` made since
//! `base` onto `target`, a writable view of the other version ("theirs",
//! typically the commit already published). Everything goes through the
//! `Vfs` API, so content is decrypted from one view and re-encrypted into
//! the other in memory; nothing is written in plaintext.
//!
//! Files are matched through the common ancestor by inode id: forks
//! allocate ids from the same counter, so an id created after `base` on
//! one side means nothing on the other, and such files are matched by
//! path. This requires `base` to be an ancestor of both `ours` and
//! `target` along history that keeps inode ids (ordinary commits, and a
//! merge's target side; a merge gives files copied in from the other side
//! new ids). The sync layer picks such a base; a base that only shares
//! history through the copied side could match unrelated files by id.
//! Rules (section 7 of `docs/CLOUD_SYNC_IMPLEMENTATION.md`):
//!
//! | Case | Result |
//! |---|---|
//! | changed on one side only | that side's version |
//! | changed on both, same content | one file |
//! | changed on both, different content | theirs at the path, ours as a conflict copy |
//! | deleted on one side, changed on the other | the changed version is kept |
//! | deleted on both | deleted |
//! | renamed on both to different places | theirs' place, ours logged |
//! | moved into each other (a cycle) | theirs' layout, ours logged |
//! | same new path, different content | theirs at the path, ours as a conflict copy |
//! | folder deleted on one side, files added in it on the other | kept |
//!
//! Nothing is ever dropped: a version that cannot be placed where it
//! belongs (its folder vanished, a name collision that cannot be
//! resolved) goes to a recovery folder at the root. Without a base (two
//! vaults with no known ancestor), the merge is a union: every path of
//! `ours` is added, with a conflict copy where `target` already has
//! different content.

use std::collections::BTreeMap;

use luksbox_vfs::{FileId, InodeKind, Vfs};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const ROOT: FileId = 1;
const COPY_CHUNK: usize = 1 << 20;
/// Longest file name the vault accepts, in bytes.
const MAX_NAME: usize = 255;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("vault: {0}")]
    Vfs(#[from] luksbox_vfs::Error),
    #[error("the target of a merge must be writable")]
    TargetReadOnly,
}

pub type Result<T> = std::result::Result<T, Error>;

/// How conflict copies are named: `name (conflict <label> <stamp>).ext`.
#[derive(Clone, Debug)]
pub struct Options {
    /// Who made the version that becomes the copy (a device label).
    pub label: String,
    /// When, for the name (for example `2026-10-13 1032`).
    pub stamp: String,
}

/// One thing the merge did that the user should know about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub path: String,
    pub what: String,
}

#[derive(Debug, Default)]
pub struct Outcome {
    pub events: Vec<Event>,
    /// Conflict copies made.
    pub conflicts: usize,
    /// Changes from `ours` applied to the target.
    pub applied: usize,
}

#[derive(Clone, Debug)]
struct Node {
    id: FileId,
    parent: FileId,
    name: String,
    path: String,
    kind: InodeKind,
    size: u64,
    mtime: u64,
    mode: u32,
    link: Option<String>,
    chunks: Vec<(u64, u64)>,
}

impl Node {
    /// Same content within one lineage: chunk references carry a
    /// generation that every write after the base advances, so equal
    /// references mean equal bytes. Across two forks this is not
    /// enough (both allocate from the same counters); `same_bytes`
    /// compares plaintext then.
    fn same_lineage_content(&self, other: &Node) -> bool {
        self.kind == other.kind
            && self.size == other.size
            && self.chunks == other.chunks
            && self.link == other.link
    }
    fn same_meta(&self, other: &Node) -> bool {
        self.mode == other.mode && self.mtime == other.mtime
    }
    fn moved_from(&self, other: &Node) -> bool {
        self.parent != other.parent || self.name != other.name
    }
}

#[derive(Default)]
struct Index {
    by_id: BTreeMap<FileId, Node>,
    /// Further names of hard-linked files (beyond the first).
    extra_links: BTreeMap<FileId, Vec<String>>,
}

fn index(v: &mut Vfs) -> Result<Index> {
    let mut idx = Index::default();
    let mut queue = vec![(ROOT, String::new())];
    while let Some((dir, dir_path)) = queue.pop() {
        let mut entries = v.readdir(dir)?;
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        for e in entries {
            let path = format!("{dir_path}/{}", e.name);
            if idx.by_id.contains_key(&e.id) {
                idx.extra_links.entry(e.id).or_default().push(path);
                continue;
            }
            let st = v.stat(e.id)?;
            let link = if e.kind == InodeKind::Symlink {
                Some(v.readlink(e.id)?)
            } else {
                None
            };
            let chunks = if e.kind == InodeKind::File {
                v.file_chunks(e.id)?
                    .iter()
                    .map(|c| (c.id, c.generation))
                    .collect()
            } else {
                Vec::new()
            };
            if e.kind == InodeKind::Directory {
                queue.push((e.id, path.clone()));
            }
            idx.by_id.insert(
                e.id,
                Node {
                    id: e.id,
                    parent: dir,
                    name: e.name,
                    path,
                    kind: e.kind,
                    size: st.size,
                    mtime: st.mtime_ns,
                    mode: st.mode,
                    link,
                    chunks,
                },
            );
        }
    }
    Ok(idx)
}

fn hash_file(v: &mut Vfs, id: FileId, size: u64) -> Result<[u8; 32]> {
    let mut h = Sha256::new();
    let mut buf = Zeroizing::new(vec![0u8; COPY_CHUNK]);
    let mut off = 0u64;
    while off < size {
        let n = v.read(id, off, &mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        off += n as u64;
    }
    Ok(h.finalize().into())
}

/// Whether two files or symlinks hold the same bytes (plaintext).
fn same_bytes(a: &mut Vfs, an: &Node, b: &mut Vfs, bn: &Node) -> Result<bool> {
    if an.kind != bn.kind {
        return Ok(false);
    }
    match an.kind {
        InodeKind::Directory => Ok(true),
        InodeKind::Symlink => Ok(an.link == bn.link),
        InodeKind::File => Ok(
            an.size == bn.size && hash_file(a, an.id, an.size)? == hash_file(b, bn.id, bn.size)?
        ),
    }
}

/// Copy a file's bytes, mode and mtime from `src` into the existing,
/// empty or stale file `dst_id` of `dst`.
fn copy_into(src: &mut Vfs, sn: &Node, dst: &mut Vfs, dst_id: FileId) -> Result<()> {
    dst.truncate(dst_id, 0)?;
    let mut buf = Zeroizing::new(vec![0u8; COPY_CHUNK]);
    let mut off = 0u64;
    while off < sn.size {
        let n = src.read(sn.id, off, &mut buf)?;
        if n == 0 {
            break;
        }
        dst.write(dst_id, off, &buf[..n])?;
        off += n as u64;
    }
    dst.chmod(dst_id, sn.mode)?;
    dst.set_mtime(dst_id, sn.mtime)?;
    Ok(())
}

struct Merger<'a> {
    ours: &'a mut Vfs,
    target: &'a mut Vfs,
    opts: &'a Options,
    out: Outcome,
    /// Ours' ids mapped to target ids (base ids map to themselves).
    map: BTreeMap<FileId, FileId>,
    recovery: Option<FileId>,
}

fn split_ext(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    }
}

/// Truncate `s` to at most `max` bytes on a character boundary.
fn clip(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

impl Merger<'_> {
    fn note(&mut self, path: &str, what: impl Into<String>) {
        self.out.events.push(Event {
            path: path.to_string(),
            what: what.into(),
        });
    }

    fn exists(&self, parent: FileId, name: &str) -> Option<FileId> {
        self.target
            .readdir(parent)
            .ok()?
            .into_iter()
            .find(|e| e.name == name)
            .map(|e| e.id)
    }

    /// A free name in `parent` for a conflict copy of `name`.
    fn conflict_name(&self, parent: FileId, name: &str) -> String {
        let (stem, ext) = split_ext(name);
        let label: String = self
            .opts
            .label
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == ' ' || c == '-' || c == '_' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        for n in 1.. {
            let suffix = if n == 1 {
                format!(" (conflict {} {})", label, self.opts.stamp)
            } else {
                format!(" (conflict {} {} {n})", label, self.opts.stamp)
            };
            let room = MAX_NAME.saturating_sub(suffix.len() + ext.len());
            let candidate = format!("{}{}{}", clip(stem, room), suffix, clip(ext, MAX_NAME / 4));
            if self.exists(parent, &candidate).is_none() {
                return candidate;
            }
        }
        unreachable!("an unbounded search always finds a free name")
    }

    /// Recovery folder at the root, created on first use.
    fn recovery_dir(&mut self) -> Result<FileId> {
        if let Some(id) = self.recovery {
            return Ok(id);
        }
        let name = format!("LUKSbox merge recovery {}", self.opts.stamp);
        let id = match self.exists(ROOT, &name) {
            Some(id) => id,
            None => self.target.mkdir(ROOT, &name)?,
        };
        self.recovery = Some(id);
        Ok(id)
    }

    /// Where ours' folder `p` lives in the target. A folder of ours the
    /// target deleted is re-created (same name, under its own resolved
    /// parent), so files added in it are kept where they belong. `None`
    /// if that is impossible (the name is taken by a file).
    fn resolve_parent(&mut self, ours_idx: &Index, p: FileId) -> Result<Option<FileId>> {
        if let Some(&t) = self.map.get(&p)
            && let Ok(InodeKind::Directory) = self.target.inode_kind(t)
        {
            return Ok(Some(t));
        }
        let Some(n) = ours_idx.by_id.get(&p) else {
            return Ok(None);
        };
        if n.kind != InodeKind::Directory || n.id == ROOT {
            return Ok(None);
        }
        let n = n.clone();
        let Some(pp) = self.resolve_parent(ours_idx, n.parent)? else {
            return Ok(None);
        };
        let id = match self.exists(pp, &n.name) {
            Some(id) if self.target.inode_kind(id)? == InodeKind::Directory => id,
            Some(_) => return Ok(None),
            None => {
                self.note(
                    &n.path,
                    "folder deleted there re-created for what was added here",
                );
                self.target.mkdir(pp, &n.name)?
            }
        };
        self.map.insert(p, id);
        Ok(Some(id))
    }

    /// Create ours' file or symlink `n` in the target under `parent`
    /// with `name` (which must be free). Returns its id.
    fn create_copy(&mut self, n: &Node, parent: FileId, name: &str) -> Result<FileId> {
        match n.kind {
            InodeKind::Symlink => {
                let id = self
                    .target
                    .symlink(parent, name, n.link.as_deref().unwrap_or(""))?;
                Ok(id)
            }
            InodeKind::File => {
                let id = self.target.create_with_mode(parent, name, n.mode)?;
                copy_into(self.ours, n, self.target, id)?;
                Ok(id)
            }
            InodeKind::Directory => Ok(self.target.mkdir(parent, name)?),
        }
    }

    /// Place a copy of ours' `n` as `name` in `parent`, or as a conflict
    /// copy if the name is taken, or in the recovery folder if `parent`
    /// is gone.
    fn place(&mut self, n: &Node, parent: Option<FileId>, name: &str, why: &str) -> Result<FileId> {
        let parent = match parent {
            Some(p) => p,
            None => {
                self.note(
                    &n.path,
                    format!("{why}; its folder is gone, saved in the recovery folder"),
                );
                self.recovery_dir()?
            }
        };
        let name = if self.exists(parent, name).is_some() {
            self.out.conflicts += 1;
            let c = self.conflict_name(parent, name);
            self.note(&n.path, format!("{why}; saved as \"{c}\""));
            c
        } else {
            name.to_string()
        };
        self.create_copy(n, parent, &name)
    }
}

/// Merge `ours` into `target`. See the crate documentation.
pub fn merge(
    base: Option<&mut Vfs>,
    ours: &mut Vfs,
    target: &mut Vfs,
    opts: &Options,
) -> Result<Outcome> {
    if target.is_read_only() {
        return Err(Error::TargetReadOnly);
    }
    let (base_idx, base_next) = match base {
        Some(b) => (index(b)?, b.tree_counters().next_file_id),
        None => (Index::default(), ROOT + 1),
    };
    let ours_idx = index(ours)?;
    let theirs_idx = index(target)?;
    let in_base = |id: &FileId| *id < base_next && base_idx.by_id.contains_key(id);

    let mut m = Merger {
        ours,
        target,
        opts,
        out: Outcome::default(),
        map: BTreeMap::new(),
        recovery: None,
    };
    m.map.insert(ROOT, ROOT);
    for id in base_idx.by_id.keys() {
        if theirs_idx.by_id.contains_key(id) {
            m.map.insert(*id, *id);
        }
    }
    for (id, _) in ours_idx.extra_links.iter().filter(|(id, _)| !in_base(id)) {
        if let Some(n) = ours_idx.by_id.get(id) {
            m.note(
                &n.path,
                "hard links of this file were merged as separate copies",
            );
        }
    }

    // Ours' nodes in path order, so parents come before children.
    let mut order: Vec<&Node> = ours_idx.by_id.values().collect();
    order.sort_by(|a, b| a.path.cmp(&b.path));

    // 1. Folders new in ours (union with same-named folders in target).
    for n in order
        .iter()
        .filter(|n| n.kind == InodeKind::Directory && !in_base(&n.id))
    {
        let parent = m.resolve_parent(&ours_idx, n.parent)?;
        let tid = match parent.and_then(|p| m.exists(p, &n.name).map(|id| (p, id))) {
            Some((_, id)) if m.target.inode_kind(id)? == InodeKind::Directory => id,
            _ => {
                let id = m.place(n, parent, &n.name, "folder added here")?;
                m.out.applied += 1;
                id
            }
        };
        m.map.insert(n.id, tid);
    }

    // 2. Renames and moves of base entries.
    for n in order.iter().filter(|n| in_base(&n.id)) {
        let b = &base_idx.by_id[&n.id];
        let Some(t) = theirs_idx.by_id.get(&n.id) else {
            continue;
        };
        if b.kind != n.kind || !n.moved_from(b) {
            continue;
        }
        if t.moved_from(b) {
            if t.parent != m.map.get(&n.parent).copied().unwrap_or(0) || t.name != n.name {
                m.note(
                    &n.path,
                    format!("renamed on both sides; kept \"{}\"", t.path),
                );
            }
            continue;
        }
        let Some(dest_parent) = m.resolve_parent(&ours_idx, n.parent)? else {
            m.note(
                &n.path,
                "moved here into a folder deleted there; left in place",
            );
            continue;
        };
        let name = if m.exists(dest_parent, &n.name).is_some() {
            m.out.conflicts += 1;
            let c = m.conflict_name(dest_parent, &n.name);
            m.note(
                &n.path,
                format!("moved here onto an existing name; moved as \"{c}\""),
            );
            c
        } else {
            n.name.clone()
        };
        // Current location in the target: its parent may itself have
        // been moved above, but the parent id and name are unchanged.
        match m.target.rename(t.parent, &t.name, dest_parent, &name) {
            Ok(()) => m.out.applied += 1,
            // Theirs moved the destination folder into this one: the move
            // would put a folder inside itself. Theirs' layout stays.
            Err(luksbox_vfs::Error::RenameCycle) => m.note(
                &n.path,
                format!(
                    "moved here into a folder that was moved into it there (it would go \
                     into itself); kept \"{}\"",
                    t.path
                ),
            ),
            Err(e) => return Err(e.into()),
        }
    }

    // 3. Content of base entries changed in ours, and new files.
    for n in order.iter().filter(|n| n.kind != InodeKind::Directory) {
        if in_base(&n.id) {
            let b = &base_idx.by_id[&n.id];
            if b.kind != n.kind {
                // Replaced by another kind of entry: treat as new.
                let parent = m.resolve_parent(&ours_idx, n.parent)?;
                m.place(n, parent, &n.name, "replaced here by another kind of entry")?;
                m.out.applied += 1;
                continue;
            }
            let ours_changed = !n.same_lineage_content(b);
            match theirs_idx.by_id.get(&n.id) {
                None if ours_changed => {
                    let parent = m.resolve_parent(&ours_idx, n.parent)?;
                    m.place(n, parent, &n.name, "deleted there, changed here: kept")?;
                    m.out.applied += 1;
                }
                None => {}
                Some(t) if ours_changed => {
                    if !t.same_lineage_content(b) {
                        if same_bytes(m.ours, n, m.target, t)? {
                            continue;
                        }
                        // Both changed: theirs keeps the name.
                        let parent = m.target.parent_of(n.id).ok();
                        m.out.conflicts += 1;
                        let c = m.conflict_name(parent.unwrap_or(ROOT), &n.name);
                        let p = parent.unwrap_or(ROOT);
                        m.create_copy(n, p, &c)?;
                        m.note(
                            &n.path,
                            format!("changed on both sides; this version saved as \"{c}\""),
                        );
                        m.out.applied += 1;
                    } else if n.kind == InodeKind::Symlink {
                        // Symlink target changed here: recreate it.
                        let parent = m.target.parent_of(n.id)?;
                        let name = m
                            .target
                            .readdir(parent)?
                            .into_iter()
                            .find(|e| e.id == n.id)
                            .map(|e| e.name)
                            .unwrap_or_else(|| n.name.clone());
                        m.target.unlink(parent, &name)?;
                        m.target
                            .symlink(parent, &name, n.link.as_deref().unwrap_or(""))?;
                        m.out.applied += 1;
                    } else {
                        copy_into(m.ours, n, m.target, n.id)?;
                        m.out.applied += 1;
                    }
                }
                Some(t) => {
                    if !n.same_meta(b) && t.same_meta(b) && n.kind == InodeKind::File {
                        m.target.chmod(n.id, n.mode)?;
                        m.target.set_mtime(n.id, n.mtime)?;
                        m.out.applied += 1;
                    }
                }
            }
        } else {
            // New in ours.
            let parent = m.resolve_parent(&ours_idx, n.parent)?;
            if let Some(p) = parent
                && let Some(existing) = m.exists(p, &n.name)
                && let Some(t) = index_single(m.target, existing)?
                && same_bytes(m.ours, n, m.target, &t)?
            {
                continue;
            }
            m.place(
                n,
                parent,
                &n.name,
                "added on both sides with different content",
            )?;
            m.out.applied += 1;
        }
    }

    // 4. Deletions made in ours: files first, then folders deepest first,
    // and only entries theirs did not change.
    let mut dirs_to_remove: Vec<&Node> = Vec::new();
    for b in base_idx.by_id.values() {
        let ours_has = ours_idx.by_id.get(&b.id).is_some_and(|n| n.kind == b.kind);
        if ours_has {
            continue;
        }
        let Some(t) = theirs_idx.by_id.get(&b.id) else {
            continue;
        };
        if b.kind == InodeKind::Directory {
            dirs_to_remove.push(b);
            continue;
        }
        if !t.same_lineage_content(b) {
            m.note(&t.path, "deleted here, changed there: kept");
            continue;
        }
        let parent = m.target.parent_of(b.id)?;
        let name = m
            .target
            .readdir(parent)?
            .into_iter()
            .find(|e| e.id == b.id)
            .map(|e| e.name);
        if let Some(name) = name {
            m.target.unlink(parent, &name)?;
            m.out.applied += 1;
        }
    }
    dirs_to_remove.sort_by(|a, b| {
        b.path
            .matches('/')
            .count()
            .cmp(&a.path.matches('/').count())
    });
    for b in dirs_to_remove {
        let Ok(parent) = m.target.parent_of(b.id) else {
            continue;
        };
        let Some(name) = m
            .target
            .readdir(parent)?
            .into_iter()
            .find(|e| e.id == b.id)
            .map(|e| e.name)
        else {
            continue;
        };
        if m.target.readdir(b.id)?.is_empty() {
            m.target.rmdir(parent, &name)?;
            m.out.applied += 1;
        } else {
            m.note(
                &b.path,
                "folder deleted here still holds files kept from there; kept",
            );
        }
    }
    Ok(m.out)
}

/// Index one entry of `v` (for comparing a single existing file).
fn index_single(v: &mut Vfs, id: FileId) -> Result<Option<Node>> {
    let st = v.stat(id)?;
    let link = if st.kind == InodeKind::Symlink {
        Some(v.readlink(id)?)
    } else {
        None
    };
    let chunks = if st.kind == InodeKind::File {
        v.file_chunks(id)?
            .iter()
            .map(|c| (c.id, c.generation))
            .collect()
    } else {
        Vec::new()
    };
    Ok(Some(Node {
        id,
        parent: v.parent_of(id).unwrap_or(ROOT),
        name: String::new(),
        path: String::new(),
        kind: st.kind,
        size: st.size,
        mtime: st.mtime_ns,
        mode: st.mode,
        link,
        chunks,
    }))
}
