// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! The object store a bundle lives in.
//!
//! `ObjectStore` is the only way the sync layer touches the bundle
//! folder. Two implementations: `fs_store::FsStore` (the real folder,
//! hostile-input rules) and `MemStore` (in memory, for tests and the
//! deterministic simulation in `sim`).

use std::collections::BTreeMap;

use crate::error::{Result, SyncError};
use crate::names::{Area, Name, is_shard_name, is_tmp_name};

/// Most entries one listing of one area may return before the store
/// gives up with `SyncError::Limit` (a flooded folder is a denial of
/// service, never a crash or memory exhaustion). 4 million objects is
/// 16 TiB of 4 MiB pages.
pub const MAX_LIST_ENTRIES: usize = 4_000_000;

/// How many foreign names a listing keeps as examples for reports.
const FOREIGN_SAMPLE: usize = 16;

/// Size rule for a read: anything else is refused before reading.
#[derive(Clone, Copy, Debug)]
pub enum LenRule {
    Exact(usize),
    OneOf(&'static [usize]),
    AtMost(usize),
}

impl LenRule {
    pub fn allows(self, len: u64) -> bool {
        match self {
            LenRule::Exact(n) => len == n as u64,
            LenRule::OneOf(set) => set.iter().any(|&n| len == n as u64),
            LenRule::AtMost(n) => len <= n as u64,
        }
    }
}

/// Result of listing one area.
#[derive(Default, Debug)]
pub struct Listing {
    pub names: Vec<Name>,
    /// Entries outside the grammar (never parsed, never deleted).
    pub foreign_count: usize,
    pub foreign_sample: Vec<String>,
    /// Our own temporary files (`.tmp-<hex>`).
    pub tmp_count: usize,
}

impl Listing {
    pub(crate) fn note_foreign(&mut self, what: String) {
        self.foreign_count += 1;
        if self.foreign_sample.len() < FOREIGN_SAMPLE {
            self.foreign_sample.push(what);
        }
    }

    /// Sort a leaf found in `area` (or in one of its shard folders) into
    /// names, temporary files or foreign entries.
    pub(crate) fn classify(&mut self, area: Area, shard: Option<&str>, leaf: &str) -> Result<()> {
        if self.names.len() + self.foreign_count + self.tmp_count >= MAX_LIST_ENTRIES {
            return Err(SyncError::Limit("too many entries in a bundle folder"));
        }
        if is_tmp_name(leaf) {
            self.tmp_count += 1;
            return Ok(());
        }
        match Name::parse_in(area, leaf) {
            // A sharded object must sit in its own shard folder:
            // `p/ab/<oid starting with ab>`. Anywhere else it is foreign.
            Some(n) if area.sharded() && n.shard().as_deref() != shard => {
                self.note_foreign(format!("{}/{}/{}", area.dir(), shard.unwrap_or(""), leaf));
            }
            Some(n) => self.names.push(n),
            None => {
                let path = match shard {
                    Some(s) => format!("{}/{}/{}", area.dir(), s, leaf),
                    None => format!("{}/{}", area.dir(), leaf),
                };
                self.note_foreign(path);
            }
        }
        Ok(())
    }
}

/// Outcome of `create_new`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Created {
    New,
    /// An object with this name and these exact bytes was already
    /// there (an idempotent re-publish after a crash).
    AlreadyIdentical,
}

pub trait ObjectStore: Send {
    /// List the valid names of one area (shard folders flattened).
    fn list(&mut self, area: Area) -> Result<Listing>;

    /// Read one object, refusing anything that is not a plain regular
    /// file whose size satisfies `len`. `Ok(None)` if it does not exist
    /// (or is still a cloud placeholder that cannot be read yet).
    fn read(&mut self, area: Area, name: &Name, len: LenRule) -> Result<Option<Vec<u8>>>;

    /// Create an object that must not exist yet. Never overwrites: an
    /// existing object with different bytes is `SyncError::Collision`.
    fn create_new(&mut self, area: Area, name: &Name, bytes: &[u8]) -> Result<Created>;

    /// Remove one object by name. `Ok(false)` if it was not there.
    fn remove(&mut self, area: Area, name: &Name) -> Result<bool>;

    /// Make every create / remove so far durable.
    fn sync(&mut self) -> Result<()>;

    /// Human-readable location, for messages.
    fn describe(&self) -> String;
}

/// In-memory store. Keys are `(area, shard, leaf)` exactly as a folder
/// would hold them, so tests can plant foreign entries, misplaced
/// shards and temporary files.
#[derive(Default, Clone)]
pub struct MemStore {
    pub(crate) files: BTreeMap<(Area, String, String), Vec<u8>>,
}

impl MemStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(area: Area, name: &Name) -> (Area, String, String) {
        let shard = if area.sharded() {
            name.shard().unwrap_or_default()
        } else {
            String::new()
        };
        (area, shard, name.leaf())
    }

    /// Plant an arbitrary entry (tests: foreign files, misplaced shards).
    pub fn plant(&mut self, area: Area, shard: &str, leaf: &str, bytes: Vec<u8>) {
        self.files
            .insert((area, shard.to_string(), leaf.to_string()), bytes);
    }

    /// Raw access for fault injection.
    pub fn raw_mut(&mut self) -> &mut BTreeMap<(Area, String, String), Vec<u8>> {
        &mut self.files
    }

    pub fn object_count(&self) -> usize {
        self.files.len()
    }
}

impl ObjectStore for MemStore {
    fn list(&mut self, area: Area) -> Result<Listing> {
        let mut l = Listing::default();
        for ((a, shard, leaf), _) in self.files.range((area, String::new(), String::new())..) {
            if *a != area {
                break;
            }
            if area.sharded() {
                if !is_shard_name(shard) {
                    l.note_foreign(format!("{}/{}", area.dir(), shard));
                    continue;
                }
                l.classify(area, Some(shard), leaf)?;
            } else if !shard.is_empty() {
                l.note_foreign(format!("{}/{}", area.dir(), shard));
            } else {
                l.classify(area, None, leaf)?;
            }
        }
        Ok(l)
    }

    fn read(&mut self, area: Area, name: &Name, len: LenRule) -> Result<Option<Vec<u8>>> {
        match self.files.get(&Self::key(area, name)) {
            None => Ok(None),
            Some(b) if !len.allows(b.len() as u64) => Err(SyncError::Refused {
                what: name.display(area),
                why: "wrong size for its kind",
            }),
            Some(b) => Ok(Some(b.clone())),
        }
    }

    fn create_new(&mut self, area: Area, name: &Name, bytes: &[u8]) -> Result<Created> {
        let k = Self::key(area, name);
        match self.files.get(&k) {
            Some(existing) if existing == bytes => Ok(Created::AlreadyIdentical),
            Some(_) => Err(SyncError::Collision {
                name: name.display(area),
            }),
            None => {
                self.files.insert(k, bytes.to_vec());
                Ok(Created::New)
            }
        }
    }

    fn remove(&mut self, area: Area, name: &Name) -> Result<bool> {
        Ok(self.files.remove(&Self::key(area, name)).is_some())
    }

    fn sync(&mut self) -> Result<()> {
        Ok(())
    }

    fn describe(&self) -> String {
        "<memory>".into()
    }
}

/// A `MemStore` shared between sessions (several devices, or one
/// device reopening after a "crash"), with optional fault injection.
#[derive(Clone, Default)]
pub struct SharedMem {
    pub inner: std::sync::Arc<std::sync::Mutex<MemStore>>,
    /// When set, the next `create_new` in this area fails once with an
    /// I/O error (simulated crash or provider error).
    pub fail_next_create: std::sync::Arc<std::sync::Mutex<Option<Area>>>,
}

impl SharedMem {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut MemStore) -> R) -> R {
        f(&mut self.inner.lock().unwrap())
    }
}

impl ObjectStore for SharedMem {
    fn list(&mut self, area: Area) -> Result<Listing> {
        self.inner.lock().unwrap().list(area)
    }
    fn read(&mut self, area: Area, name: &Name, len: LenRule) -> Result<Option<Vec<u8>>> {
        self.inner.lock().unwrap().read(area, name, len)
    }
    fn create_new(&mut self, area: Area, name: &Name, bytes: &[u8]) -> Result<Created> {
        let mut f = self.fail_next_create.lock().unwrap();
        if *f == Some(area) {
            *f = None;
            return Err(SyncError::Io(std::io::Error::other("injected failure")));
        }
        drop(f);
        self.inner.lock().unwrap().create_new(area, name, bytes)
    }
    fn remove(&mut self, area: Area, name: &Name) -> Result<bool> {
        self.inner.lock().unwrap().remove(area, name)
    }
    fn sync(&mut self) -> Result<()> {
        Ok(())
    }
    fn describe(&self) -> String {
        "<shared memory>".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::ObjectId;

    #[test]
    fn mem_store_never_overwrites() {
        let mut s = MemStore::new();
        let n = Name::Object(ObjectId([1; 32]));
        assert_eq!(s.create_new(Area::Page, &n, b"a").unwrap(), Created::New);
        assert_eq!(
            s.create_new(Area::Page, &n, b"a").unwrap(),
            Created::AlreadyIdentical
        );
        assert!(matches!(
            s.create_new(Area::Page, &n, b"b"),
            Err(SyncError::Collision { .. })
        ));
        assert_eq!(
            s.read(Area::Page, &n, LenRule::Exact(1)).unwrap().unwrap(),
            b"a"
        );
        assert!(s.read(Area::Page, &n, LenRule::Exact(2)).is_err());
    }

    #[test]
    fn listing_sorts_out_foreign_and_misplaced() {
        let mut s = MemStore::new();
        let o = ObjectId([0xab; 32]);
        s.plant(Area::Page, "ab", &o.to_hex(), vec![]);
        // Right name, wrong shard folder.
        s.plant(Area::Page, "cd", &o.to_hex(), vec![]);
        // Conflict copy, uppercase, temp file, bad shard folder.
        s.plant(Area::Page, "ab", &format!("{} (1)", o.to_hex()), vec![]);
        s.plant(Area::Page, "ab", &o.to_hex().to_uppercase(), vec![]);
        s.plant(Area::Page, "ab", &crate::names::tmp_name().unwrap(), vec![]);
        s.plant(Area::Page, "AB", &o.to_hex(), vec![]);
        let l = s.list(Area::Page).unwrap();
        assert_eq!(l.names, vec![Name::Object(o)]);
        assert_eq!(l.tmp_count, 1);
        assert_eq!(l.foreign_count, 4);
    }
}
