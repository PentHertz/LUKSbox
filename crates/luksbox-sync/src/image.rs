// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! The container image as pages: `PagedImage` implements `LbxFile`, so
//! `luksbox-format::Container` reads and writes it like the `.lbx` file
//! of a detached-header vault.
//!
//! Reads come from, in order: pages changed in memory (`dirty`), pages
//! staged locally but not yet published (`staged`, sealed in the local
//! outbox), and the pages of the base commit (sealed objects in the
//! bundle). Every page read from storage is checked against the SHA-256
//! its table entry records and opened with its AEAD bound to its index
//! before a byte reaches the container.
//!
//! `sync_all` is the durability point: dirty pages are sealed as new
//! objects into the local outbox and a sealed staged-commit record is
//! written, so a crash loses nothing that was saved. Nothing leaves the
//! device until the session publishes (`bundle::Session::publish`).
//!
//! A publish uploads the last saved state, exactly what the local record
//! holds, never a save still in progress. It holds the image only twice,
//! briefly: to take that state (`prepare`) and to make it the new base
//! (`published`). The vault keeps reading, writing and saving while the
//! objects upload; what it changes meanwhile stays staged on top of the
//! new base.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::{Arc, Mutex, MutexGuard};

use luksbox_core::HEADER_SIZE;
use luksbox_format::LbxFile;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::codec::{self, Binding, OVERHEAD};
use crate::error::{Result, SyncError};
use crate::keys::{BundleKeys, Kind};
use crate::local::{LocalStore, open_local, seal_local};
use crate::manifest::ManifestRef;
use crate::names::{Area, Name, ObjectId};
use crate::store::{LenRule, ObjectStore};
use crate::table::{
    BLOCK_OBJECT_LEN, ENTRIES_PER_BLOCK, ObjRef, TableBlock, block_count, page_count,
};

pub type SharedStore = Arc<Mutex<Box<dyn ObjectStore>>>;
pub type SharedLocal = Arc<Mutex<Box<dyn LocalStore>>>;

/// Decrypted pages kept in memory (they hold inner-container ciphertext,
/// never user plaintext).
const CACHE_BYTES: usize = 64 << 20;
/// Changed pages kept in memory before they are sealed into the outbox
/// ahead of the next `sync_all`, so a large write does not hold the
/// whole file in memory.
const SPILL_BYTES: u64 = if cfg!(test) { 64 << 10 } else { 64 << 20 };
pub(crate) const RECORD_NAME: &str = "staged";
const RECORD_FORMAT: u16 = 1;

pub(crate) fn outbox_name(oid: &ObjectId) -> String {
    format!("p-{}", oid.to_hex())
}

/// What `sync_all` has made durable locally and not published yet.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct StagedRecord {
    pub format: u16,
    /// The commit these changes apply to.
    pub base: Option<ManifestRef>,
    /// Image length of that commit (a length change alone, a pure
    /// truncation, is a change too).
    pub base_len: u64,
    pub page_size: u32,
    pub len: u64,
    /// `(page index, object id, sha256 of the sealed object)`.
    pub pages: Vec<(u64, [u8; 32], [u8; 32])>,
    /// New header state (`persist_header`), if any.
    pub header: Option<Vec<u8>>,
    /// `ImageCore::cut`.
    pub cut: Option<u64>,
}

#[derive(Default)]
struct PageCache {
    order: VecDeque<u64>,
    pages: HashMap<u64, Zeroizing<Vec<u8>>>,
    bytes: usize,
}

impl PageCache {
    fn get(&self, idx: u64) -> Option<&Zeroizing<Vec<u8>>> {
        self.pages.get(&idx)
    }
    fn put(&mut self, idx: u64, page: Zeroizing<Vec<u8>>) {
        if let Some(old) = self.pages.insert(idx, page) {
            self.bytes -= old.len();
            self.order.retain(|&i| i != idx);
        }
        self.bytes += self.pages[&idx].len();
        self.order.push_back(idx);
        while self.bytes > CACHE_BYTES && self.order.len() > 1 {
            let evict = self.order.pop_front().expect("non-empty");
            if let Some(p) = self.pages.remove(&evict) {
                self.bytes -= p.len();
            }
        }
    }
    fn take(&mut self, idx: u64) -> Option<Zeroizing<Vec<u8>>> {
        let p = self.pages.remove(&idx)?;
        self.bytes -= p.len();
        self.order.retain(|&i| i != idx);
        Some(p)
    }
    fn drop_from(&mut self, first: u64) {
        let gone: Vec<u64> = self.pages.keys().copied().filter(|&i| i >= first).collect();
        for i in gone {
            if let Some(p) = self.pages.remove(&i) {
                self.bytes -= p.len();
            }
        }
        self.order.retain(|&i| i < first);
    }
}

pub(crate) struct ImageCore {
    keys: Arc<BundleKeys>,
    store: SharedStore,
    /// `None` for a discard view (snapshot for a merge): writes stay in
    /// memory and are never staged.
    local: Option<SharedLocal>,
    page_size: u64,
    len: u64,
    base: Option<ManifestRef>,
    base_len: u64,
    base_tables: Vec<ObjRef>,
    blocks: HashMap<u64, TableBlock>,
    dirty: BTreeMap<u64, Zeroizing<Vec<u8>>>,
    staged: BTreeMap<u64, ObjRef>,
    /// Outbox objects that left `staged` (replaced or cut off) but that
    /// `saved` may still name: removed at the next save (`stage`).
    superseded: Vec<ObjectId>,
    pending_header: Option<[u8; HEADER_SIZE]>,
    /// The image was truncated to this many pages since the base: pages
    /// from here on no longer come from the base, so growing it again
    /// reads zeros there, as a file does.
    cut: Option<u64>,
    /// Lowest truncation since the last save.
    cut_since_save: Option<u64>,
    /// The last saved state: what the local record holds, and what a
    /// publish uploads. `staged`, `len`, `cut` and `pending_header` are
    /// the live state, which may hold a save in progress.
    saved: Saved,
    /// A publish in progress (`prepare` until `published` or
    /// `abort_publish`).
    upload: Option<Upload>,
    cache: PageCache,
    /// False for views: `stage` never writes, even with a local store
    /// (a view over unpublished local changes reads the outbox).
    stage_enabled: bool,
}

#[derive(Clone, Default)]
struct Saved {
    len: u64,
    pages: BTreeMap<u64, ObjRef>,
    header: Option<[u8; HEADER_SIZE]>,
    cut: Option<u64>,
}

#[derive(Default)]
struct Upload {
    /// Outbox objects being published: kept in the outbox until the
    /// publish ends, even if the vault replaces them meanwhile.
    objects: HashSet<ObjectId>,
    /// Lowest truncation since the save being published: it applies on
    /// top of what is published.
    cut: Option<u64>,
    /// Set when the vault saved again during the upload: the truncations
    /// that newer save holds on top of the one being published.
    saved_cut: Option<Option<u64>>,
}

fn lower(cut: &mut Option<u64>, pages: u64) {
    *cut = Some(cut.map_or(pages, |c| c.min(pages)));
}

impl ImageCore {
    pub(crate) fn new(
        keys: Arc<BundleKeys>,
        store: SharedStore,
        local: Option<SharedLocal>,
        page_size: u64,
        len: u64,
        base: Option<ManifestRef>,
        base_tables: Vec<ObjRef>,
    ) -> Self {
        Self {
            keys,
            store,
            local,
            page_size,
            len,
            base,
            base_len: len,
            base_tables,
            blocks: HashMap::new(),
            dirty: BTreeMap::new(),
            staged: BTreeMap::new(),
            superseded: Vec::new(),
            pending_header: None,
            cut: None,
            cut_since_save: None,
            saved: Saved {
                len,
                ..Saved::default()
            },
            upload: None,
            cache: PageCache::default(),
            stage_enabled: true,
        }
    }

    /// A view: reads like `new`, never stages.
    pub(crate) fn new_view(
        keys: Arc<BundleKeys>,
        store: SharedStore,
        local: Option<SharedLocal>,
        page_size: u64,
        len: u64,
        base: Option<ManifestRef>,
        base_tables: Vec<ObjRef>,
    ) -> Self {
        let mut c = Self::new(keys, store, local, page_size, len, base, base_tables);
        c.stage_enabled = false;
        c
    }

    /// Table blocks of the base already verified by the caller.
    pub(crate) fn seed_blocks(&mut self, blocks: Vec<TableBlock>) {
        for (b, block) in blocks.into_iter().enumerate() {
            self.blocks.insert(b as u64, block);
        }
    }

    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    /// Changes not published yet, saved or not.
    pub(crate) fn has_unpublished(&self) -> bool {
        !self.staged.is_empty()
            || !self.dirty.is_empty()
            || self.pending_header.is_some()
            || self.len != self.base_len
            || self.cuts_base(self.cut)
    }

    /// Saved changes not published yet: what a publish would upload.
    pub(crate) fn has_saved_changes(&self) -> bool {
        !self.saved.pages.is_empty()
            || self.saved.header.is_some()
            || self.saved.len != self.base_len
            || self.cuts_base(self.saved.cut)
    }

    fn cuts_base(&self, cut: Option<u64>) -> bool {
        cut.is_some_and(|c| c < page_count(self.base_len, self.page_size))
    }

    /// Outbox objects something here still names.
    pub(crate) fn outbox_in_use(&self) -> HashSet<ObjectId> {
        let mut keep: HashSet<ObjectId> = self
            .staged
            .values()
            .chain(self.saved.pages.values())
            .map(|r| r.object_id())
            .collect();
        if let Some(u) = &self.upload {
            keep.extend(u.objects.iter().copied());
        }
        keep
    }

    pub(crate) fn pending_header(&self) -> Option<[u8; HEADER_SIZE]> {
        self.pending_header
    }

    /// Restore a staged record left by a session that did not publish.
    pub(crate) fn restore_record(&mut self, rec: &StagedRecord) -> Result<()> {
        if rec.page_size as u64 != self.page_size {
            return Err(SyncError::Malformed {
                name: "local staged record".into(),
                why: "page size differs from the bundle",
            });
        }
        self.len = rec.len;
        for (idx, oid, hash) in &rec.pages {
            self.staged.insert(
                *idx,
                ObjRef {
                    oid: *oid,
                    hash: *hash,
                },
            );
        }
        if let Some(h) = &rec.header {
            let h: [u8; HEADER_SIZE] =
                h.as_slice().try_into().map_err(|_| SyncError::Malformed {
                    name: "local staged record".into(),
                    why: "staged header has the wrong size",
                })?;
            self.pending_header = Some(h);
        }
        self.cut = rec.cut;
        self.saved = Saved {
            len: self.len,
            pages: self.staged.clone(),
            header: self.pending_header,
            cut: self.cut,
        };
        Ok(())
    }

    fn table_block(&mut self, b: u64) -> Result<Option<&TableBlock>> {
        if b >= self.base_tables.len() as u64 {
            return Ok(None);
        }
        if !self.blocks.contains_key(&b) {
            let r = self.base_tables[b as usize];
            let name = Name::Object(r.object_id());
            let obj = self
                .store
                .lock()
                .expect("store lock")
                .read(Area::Table, &name, LenRule::Exact(BLOCK_OBJECT_LEN))?
                .ok_or_else(|| SyncError::MissingHistory {
                    device: "table".into(),
                    seq: b,
                })?;
            let block = TableBlock::open(&self.keys, &r, b, &obj)?;
            self.blocks.insert(b, block);
        }
        Ok(self.blocks.get(&b))
    }

    fn open_page(&self, idx: u64, r: &ObjRef, object: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let display = || format!("p/{}", r.object_id().to_hex());
        if !r.matches(object) {
            return Err(SyncError::ObjectAuth { name: display() });
        }
        let pt = codec::open(
            &self.keys,
            Kind::Page,
            &r.object_id(),
            Binding::Index(idx),
            object,
            display,
        )?;
        if pt.len() as u64 != self.page_size {
            return Err(SyncError::Malformed {
                name: display(),
                why: "page has the wrong size",
            });
        }
        Ok(pt)
    }

    /// Page `idx` for reading, without copying it: the changed page if
    /// there is one, else the cached one (loaded on a miss). The vault
    /// reads and writes in 4 KiB chunks, so a copy of the whole page per
    /// call would cost far more than the call itself.
    fn page_ref(&mut self, idx: u64) -> Result<&[u8]> {
        if !self.dirty.contains_key(&idx) && self.cache.get(idx).is_none() {
            let page = self.load_page(idx)?;
            self.cache.put(idx, page);
        }
        Ok(match self.dirty.get(&idx) {
            Some(p) => p,
            None => self.cache.get(idx).expect("just cached"),
        })
    }

    /// Page `idx` for changing in place: moved into `dirty` the first
    /// time (out of the cache, or loaded; zeros when the caller rewrites
    /// all of it), so the cache never holds a stale copy.
    fn page_mut(&mut self, idx: u64, whole: bool) -> Result<&mut Zeroizing<Vec<u8>>> {
        if !self.dirty.contains_key(&idx) {
            let cached = self.cache.take(idx);
            let page = if whole {
                Zeroizing::new(vec![0u8; self.page_size as usize])
            } else if let Some(p) = cached {
                p
            } else {
                self.load_page(idx)?
            };
            self.dirty.insert(idx, page);
        }
        Ok(self.dirty.get_mut(&idx).expect("just inserted"))
    }

    /// Contents of page `idx` as of the last seal (zeros for a hole or
    /// past the end): from the outbox, the base or nothing; never from
    /// `dirty` or the cache.
    fn load_page(&mut self, idx: u64) -> Result<Zeroizing<Vec<u8>>> {
        let page = if let Some(r) = self.staged.get(&idx).copied() {
            let local = self
                .local
                .as_ref()
                .expect("staged pages imply a local store");
            let obj = local
                .lock()
                .expect("local lock")
                .get(&outbox_name(&r.object_id()))?
                .ok_or_else(|| SyncError::Malformed {
                    name: "local outbox".into(),
                    why: "a staged page is missing from the outbox",
                })?;
            self.open_page(idx, &r, &obj)?
        } else if self.cut.is_some_and(|c| idx >= c) {
            Zeroizing::new(vec![0u8; self.page_size as usize])
        } else {
            let entry = match self.table_block(idx / ENTRIES_PER_BLOCK as u64)? {
                Some(block) => block.entries[(idx % ENTRIES_PER_BLOCK as u64) as usize],
                None => None,
            };
            match entry {
                None => Zeroizing::new(vec![0u8; self.page_size as usize]),
                Some(r) => {
                    let name = Name::Object(r.object_id());
                    let len = self.page_size as usize + OVERHEAD;
                    let obj = self
                        .store
                        .lock()
                        .expect("store lock")
                        .read(Area::Page, &name, LenRule::Exact(len))?
                        .ok_or_else(|| SyncError::MissingHistory {
                            device: "page".into(),
                            seq: idx,
                        })?;
                    self.open_page(idx, &r, &obj)?
                }
            }
        };
        Ok(page)
    }

    pub(crate) fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<usize> {
        if off >= self.len {
            return Ok(0);
        }
        let n = buf.len().min((self.len - off) as usize);
        let mut done = 0;
        while done < n {
            let pos = off + done as u64;
            let idx = pos / self.page_size;
            let in_page = (pos % self.page_size) as usize;
            let take = (n - done).min(self.page_size as usize - in_page);
            let page = self.page_ref(idx)?;
            buf[done..done + take].copy_from_slice(&page[in_page..in_page + take]);
            done += take;
        }
        Ok(n)
    }

    pub(crate) fn write_at(&mut self, off: u64, buf: &[u8]) -> Result<usize> {
        let end = off
            .checked_add(buf.len() as u64)
            .ok_or(SyncError::Limit("image offset overflow"))?;
        let mut done = 0;
        while done < buf.len() {
            let pos = off + done as u64;
            let idx = pos / self.page_size;
            let in_page = (pos % self.page_size) as usize;
            let take = (buf.len() - done).min(self.page_size as usize - in_page);
            // A write covering the whole page needs nothing of the old one.
            let page = self.page_mut(idx, take == self.page_size as usize)?;
            page[in_page..in_page + take].copy_from_slice(&buf[done..done + take]);
            done += take;
        }
        if end > self.len {
            self.len = end;
        }
        if self.dirty.len() as u64 * self.page_size >= SPILL_BYTES {
            self.spill()?;
        }
        Ok(buf.len())
    }

    /// Seal the dirty pages into the outbox now, without touching the
    /// saved state: what is durable after a crash, and what a publish
    /// uploads, is still decided by `stage` alone (spilled pages the
    /// record does not name are cleaned up at the next open). A view
    /// never spills; its writes stay in memory.
    fn spill(&mut self) -> Result<()> {
        if !self.stage_enabled {
            return Ok(());
        }
        let Some(local) = self.local.clone() else {
            return Ok(());
        };
        let mut local = local.lock().expect("local lock");
        self.seal_dirty(&mut **local)
    }

    /// Seal every dirty page as a new outbox object. Objects they replace
    /// go to `superseded`, removed at the next save.
    fn seal_dirty(&mut self, local: &mut dyn LocalStore) -> Result<()> {
        while let Some((idx, page)) = self.dirty.pop_first() {
            let sealed = codec::seal_new(&self.keys, Kind::Page, Binding::Index(idx), &page)
                .and_then(|(oid, obj)| {
                    local.put(&outbox_name(&oid), &obj)?;
                    Ok((oid, obj))
                });
            let (oid, obj) = match sealed {
                Ok(o) => o,
                Err(e) => {
                    // Still changed: sealed by the next attempt.
                    self.dirty.insert(idx, page);
                    return Err(e);
                }
            };
            if let Some(old) = self.staged.insert(idx, ObjRef::of(oid, &obj)) {
                self.superseded.push(old.object_id());
            }
            // Sealed: readable from the cache without opening the object.
            self.cache.put(idx, page);
        }
        Ok(())
    }

    pub(crate) fn set_len(&mut self, len: u64) -> Result<()> {
        if len < self.len {
            let keep_pages = page_count(len, self.page_size);
            self.dirty.retain(|&i, _| i < keep_pages);
            let cut_off = self.staged.split_off(&keep_pages);
            self.superseded
                .extend(cut_off.values().map(|r| r.object_id()));
            self.cache.drop_from(keep_pages);
            lower(&mut self.cut, keep_pages);
            lower(&mut self.cut_since_save, keep_pages);
            if let Some(u) = &mut self.upload {
                lower(&mut u.cut, keep_pages);
            }
            // Zero the tail of a partial last page, so growing the image
            // again reads zeros as a file would.
            let tail = (len % self.page_size) as usize;
            if tail != 0 {
                let idx = len / self.page_size;
                self.page_mut(idx, false)?[tail..].fill(0);
            }
        }
        self.len = len;
        Ok(())
    }

    /// Durability point: seal dirty pages into the outbox, and the live
    /// state becomes the saved state, written to the local record. A
    /// discard view does nothing.
    pub(crate) fn stage(&mut self) -> Result<()> {
        if !self.stage_enabled {
            return Ok(());
        }
        let Some(local) = self.local.clone() else {
            return Ok(());
        };
        let mut local = local.lock().expect("local lock");
        self.seal_dirty(&mut **local)?;
        let saved = Saved {
            len: self.len,
            pages: self.staged.clone(),
            header: self.pending_header,
            cut: self.cut,
        };
        self.write_record(&mut **local, &saved)?;
        self.saved = saved;
        self.cut_since_save = None;
        if let Some(u) = &mut self.upload {
            u.saved_cut = Some(u.cut);
        }
        // Only after the record no longer names them, and never while a
        // publish reads them (`published` removes those).
        for oid in std::mem::take(&mut self.superseded) {
            if !self
                .upload
                .as_ref()
                .is_some_and(|u| u.objects.contains(&oid))
            {
                local.remove(&outbox_name(&oid))?;
            }
        }
        Ok(())
    }

    fn record_of(&self, saved: &Saved) -> StagedRecord {
        StagedRecord {
            format: RECORD_FORMAT,
            base: self.base,
            base_len: self.base_len,
            page_size: self.page_size as u32,
            len: saved.len,
            pages: saved
                .pages
                .iter()
                .map(|(i, r)| (*i, r.oid, r.hash))
                .collect(),
            header: saved.header.map(|h| h.to_vec()),
            cut: saved.cut,
        }
    }

    fn write_record(&self, local: &mut dyn LocalStore, saved: &Saved) -> Result<()> {
        let rec = self.record_of(saved);
        let pt = Zeroizing::new(
            postcard::to_allocvec(&rec).map_err(|_| SyncError::Limit("staged record"))?,
        );
        local.put(RECORD_NAME, &seal_local(&self.keys, RECORD_NAME, &pt)?)
    }

    /// Record a new header state durably (from `HeaderStore`). Only the
    /// header: page changes are saved by `stage`.
    pub(crate) fn stage_header(&mut self, bytes: &[u8; HEADER_SIZE]) -> Result<()> {
        if !self.stage_enabled {
            return Err(SyncError::ReadOnly);
        }
        let mut saved = self.saved.clone();
        saved.header = Some(*bytes);
        if let Some(local) = self.local.clone() {
            let mut local = local.lock().expect("local lock");
            self.write_record(&mut **local, &saved)?;
        }
        self.saved = saved;
        self.pending_header = Some(*bytes);
        Ok(())
    }

    /// Everything a publish of the saved state needs: its pages' objects,
    /// the table after applying them, which table blocks are new, and the
    /// header. Starts the publish: until `published` or `abort_publish`,
    /// the objects it names stay in the outbox.
    pub(crate) fn prepare(&mut self) -> Result<Prepared> {
        // A session publishes one commit at a time; one left behind by a
        // publish that never ended is over.
        self.abort_publish();
        // Only what the vault saved (`sync_all`): pages changed since, in
        // memory or spilled, may belong to a save in progress.
        let saved = self.saved.clone();
        let pages_total = page_count(saved.len, self.page_size);
        let blocks_total = block_count(pages_total);
        let mut touched: BTreeMap<u64, ()> = BTreeMap::new();
        for idx in saved.pages.keys() {
            touched.insert(idx / ENTRIES_PER_BLOCK as u64, ());
        }
        // Shrinking cuts entries out of the (new) last block; growing
        // only adds blocks past the base table, which are built anyway.
        if pages_total < page_count(self.base_len, self.page_size) && blocks_total > 0 {
            touched.insert(blocks_total - 1, ());
        }
        // Base pages past a truncation are gone, even where the image
        // grew back over them.
        if let Some(cut) = saved.cut {
            let old = page_count(self.base_len, self.page_size).min(pages_total);
            if cut < old {
                for b in cut / ENTRIES_PER_BLOCK as u64..=(old - 1) / ENTRIES_PER_BLOCK as u64 {
                    touched.insert(b, ());
                }
            }
        }
        let mut tables = Vec::with_capacity(blocks_total as usize);
        let mut new_tables = Vec::new();
        for b in 0..blocks_total {
            if !touched.contains_key(&b) && (b as usize) < self.base_tables.len() {
                tables.push(self.base_tables[b as usize]);
                continue;
            }
            let mut block = match self.table_block(b)? {
                Some(bl) => bl.clone(),
                None => TableBlock::default(),
            };
            for (i, e) in block.entries.iter_mut().enumerate() {
                let idx = b * ENTRIES_PER_BLOCK as u64 + i as u64;
                if idx >= pages_total {
                    *e = None;
                } else if let Some(r) = saved.pages.get(&idx) {
                    *e = Some(*r);
                } else if saved.cut.is_some_and(|c| idx >= c) {
                    *e = None;
                }
            }
            let (r, obj) = block.seal(&self.keys, b)?;
            tables.push(r);
            new_tables.push((b, r, obj, block));
        }
        let pages: Vec<(u64, ObjRef)> = saved.pages.iter().map(|(i, r)| (*i, *r)).collect();
        self.upload = Some(Upload {
            objects: pages.iter().map(|(_, r)| r.object_id()).collect(),
            cut: self.cut_since_save,
            saved_cut: None,
        });
        Ok(Prepared {
            tables,
            new_tables,
            pages,
            len: saved.len,
            header: saved.header,
        })
    }

    /// A publish failed: what it would have published stays staged.
    /// Its objects nothing names any more are removed at the next save,
    /// like any other replaced object.
    pub(crate) fn abort_publish(&mut self) {
        let Some(u) = self.upload.take() else {
            return;
        };
        let named: HashSet<ObjectId> = self
            .staged
            .values()
            .chain(self.saved.pages.values())
            .map(|r| r.object_id())
            .collect();
        for oid in u.objects {
            if !named.contains(&oid) && !self.superseded.contains(&oid) {
                self.superseded.push(oid);
            }
        }
    }

    /// After a publish: what it published becomes the base. What the
    /// vault changed while it uploaded stays staged on top of it.
    pub(crate) fn published(&mut self, base: ManifestRef, prepared: Prepared) -> Result<()> {
        let upload = self.upload.take().unwrap_or_default();
        for (b, _, _, block) in &prepared.new_tables {
            self.blocks.insert(*b, block.clone());
        }
        let stale: Vec<u64> = self
            .blocks
            .keys()
            .copied()
            .filter(|&b| b >= prepared.tables.len() as u64)
            .collect();
        for b in stale {
            self.blocks.remove(&b);
        }
        self.base_tables = prepared.tables;
        self.base = Some(base);
        self.base_len = prepared.len;
        // Both the live and the saved state keep what changed since the
        // published save, on top of the new base.
        for (idx, r) in &prepared.pages {
            if self.staged.get(idx) == Some(r) {
                self.staged.remove(idx);
            }
            if self.saved.pages.get(idx) == Some(r) {
                self.saved.pages.remove(idx);
            }
        }
        if self.pending_header == prepared.header {
            self.pending_header = None;
        }
        if self.saved.header == prepared.header {
            self.saved.header = None;
        }
        // Truncations made since the published save still apply; the
        // earlier ones are in what was published.
        self.cut = upload.cut;
        self.saved.cut = upload.saved_cut.flatten();
        self.superseded.retain(|o| !upload.objects.contains(o));
        if let Some(local) = self.local.clone() {
            let mut local = local.lock().expect("local lock");
            self.write_record(&mut **local, &self.saved)?;
            for oid in &upload.objects {
                local.remove(&outbox_name(oid))?;
            }
        }
        Ok(())
    }
}

/// A staged page's sealed object, from the local outbox.
pub(crate) fn outbox_object(local: &SharedLocal, oid: &ObjectId) -> Result<Vec<u8>> {
    local
        .lock()
        .expect("local lock")
        .get(&outbox_name(oid))?
        .ok_or_else(|| SyncError::Malformed {
            name: "local outbox".into(),
            why: "a staged page is missing from the outbox",
        })
}

pub(crate) struct Prepared {
    pub tables: Vec<ObjRef>,
    /// `(block index, reference, sealed bytes, decoded block)`.
    pub new_tables: Vec<(u64, ObjRef, Vec<u8>, TableBlock)>,
    pub pages: Vec<(u64, ObjRef)>,
    pub len: u64,
    /// The staged header state, if any.
    pub header: Option<[u8; HEADER_SIZE]>,
}

pub(crate) fn load_record(
    keys: &BundleKeys,
    local: &mut dyn LocalStore,
) -> Result<Option<StagedRecord>> {
    let Some(sealed) = local.get(RECORD_NAME)? else {
        return Ok(None);
    };
    let pt = open_local(keys, RECORD_NAME, &sealed)?;
    let rec: StagedRecord = postcard::from_bytes(&pt).map_err(|_| SyncError::Malformed {
        name: "local staged record".into(),
        why: "does not decode",
    })?;
    if rec.format != RECORD_FORMAT {
        return Err(SyncError::Malformed {
            name: "local staged record".into(),
            why: "unknown format",
        });
    }
    Ok(Some(rec))
}

/// `LbxFile` handle over an `ImageCore`.
pub struct PagedImage {
    core: Arc<Mutex<ImageCore>>,
    pos: u64,
}

impl PagedImage {
    pub(crate) fn new(core: Arc<Mutex<ImageCore>>) -> Self {
        Self { core, pos: 0 }
    }

    fn core(&self) -> MutexGuard<'_, ImageCore> {
        self.core.lock().expect("image lock")
    }
}

fn io_err(e: SyncError) -> std::io::Error {
    match e {
        SyncError::Io(e) => e,
        other => std::io::Error::other(other),
    }
}

impl Read for PagedImage {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let pos = self.pos;
        let n = self.core().read_at(pos, buf).map_err(io_err)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Write for PagedImage {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let pos = self.pos;
        let n = self.core().write_at(pos, buf).map_err(io_err)?;
        self.pos += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Seek for PagedImage {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        let len = self.core().len() as i128;
        let new = match to {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::End(d) => len + d as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if new < 0 || new > u64::MAX as i128 {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

impl LbxFile for PagedImage {
    fn sync_all(&mut self) -> std::io::Result<()> {
        self.core().stage().map_err(io_err)
    }
    fn set_len(&mut self, len: u64) -> std::io::Result<()> {
        self.core().set_len(len).map_err(io_err)
    }
    fn inode_pair(&self) -> std::io::Result<(u64, u64)> {
        // Bundles never take the file-rotation path that uses this.
        Ok((0, 0))
    }
}

/// `HeaderStore` of a bundle session: a new header state is staged in
/// the local record (durable) and published with the next commit.
pub(crate) struct BundleHeaderStore {
    pub(crate) core: Arc<Mutex<ImageCore>>,
}

impl luksbox_format::HeaderStore for BundleHeaderStore {
    fn store_header(&mut self, bytes: &[u8; HEADER_SIZE]) -> std::io::Result<()> {
        self.core
            .lock()
            .expect("image lock")
            .stage_header(bytes)
            .map_err(io_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::tests::fixed_keys;
    use crate::local::MemLocal;
    use crate::store::MemStore;
    use luksbox_core::CipherSuite;

    fn core(page: u64) -> (Arc<Mutex<ImageCore>>, SharedStore, MemLocal) {
        let keys = Arc::new(fixed_keys(CipherSuite::Aes256GcmSiv, [1; 16]));
        let store: SharedStore = Arc::new(Mutex::new(Box::new(MemStore::new())));
        let mem = MemLocal::default();
        let local: SharedLocal = Arc::new(Mutex::new(Box::new(mem.clone())));
        let c = ImageCore::new(keys, store.clone(), Some(local), page, 0, None, vec![]);
        (Arc::new(Mutex::new(c)), store, mem)
    }

    #[test]
    fn read_write_across_pages_and_sparse_growth() {
        let (c, _s, _l) = core(16);
        let mut img = PagedImage::new(c.clone());
        img.seek(SeekFrom::Start(10)).unwrap();
        img.write_all(b"0123456789abcdef0123").unwrap();
        assert_eq!(c.lock().unwrap().len(), 30);
        let mut buf = vec![0u8; 40];
        img.seek(SeekFrom::Start(0)).unwrap();
        let n = img.read(&mut buf).unwrap();
        assert_eq!(n, 30);
        assert_eq!(&buf[..10], &[0u8; 10]);
        assert_eq!(&buf[10..30], b"0123456789abcdef0123");
        // Truncate into a page, then grow: the cut bytes read as zeros.
        img.set_len(12).unwrap();
        img.set_len(20).unwrap();
        let mut b2 = vec![0xffu8; 20];
        img.seek(SeekFrom::Start(0)).unwrap();
        img.read_exact(&mut b2).unwrap();
        assert_eq!(&b2[10..12], b"01");
        assert_eq!(&b2[12..20], &[0u8; 8]);
    }

    #[test]
    fn stage_writes_sealed_pages_and_record_only() {
        let (c, store, local) = core(16);
        let mut img = PagedImage::new(c.clone());
        img.write_all(&[7u8; 40]).unwrap();
        img.sync_all().unwrap();
        // Nothing reached the bundle.
        assert_eq!(
            store.lock().unwrap().list(Area::Page).unwrap().names.len(),
            0
        );
        let names = local.0.lock().unwrap().keys().cloned().collect::<Vec<_>>();
        assert_eq!(names.iter().filter(|n| n.starts_with("p-")).count(), 3);
        assert!(names.contains(&"staged".to_string()));
        // Staged pages contain no plaintext run of the written bytes.
        for (n, v) in local.0.lock().unwrap().iter() {
            if n.starts_with("p-") {
                assert!(!v.windows(16).any(|w| w == [7u8; 16]));
            }
        }
        // Rewriting a staged page supersedes its outbox object.
        img.seek(SeekFrom::Start(0)).unwrap();
        img.write_all(&[8u8; 4]).unwrap();
        img.sync_all().unwrap();
        let pages = local
            .0
            .lock()
            .unwrap()
            .keys()
            .filter(|n| n.starts_with("p-"))
            .count();
        assert_eq!(pages, 3);
        // Reading back goes through the outbox and the AEAD.
        c.lock().unwrap().cache = PageCache::default();
        let mut b = [0u8; 8];
        img.seek(SeekFrom::Start(0)).unwrap();
        img.read_exact(&mut b).unwrap();
        assert_eq!(b, [8, 8, 8, 8, 7, 7, 7, 7]);
    }

    #[test]
    fn large_writes_spill_but_publish_takes_only_the_saved_state() {
        let page = 4096u64;
        let (c, _s, local) = core(page);
        let mut img = PagedImage::new(c.clone());
        let outbox = || {
            local
                .0
                .lock()
                .unwrap()
                .keys()
                .filter(|n| n.starts_with("p-"))
                .count()
        };
        // 20 pages: past the (test) spill threshold of 16.
        img.write_all(&vec![3u8; 20 * page as usize]).unwrap();
        assert!(
            c.lock().unwrap().dirty.len() < 16,
            "dirty pages were spilled"
        );
        assert!(outbox() >= 16);
        // Not a saved state yet: no record, and nothing to publish.
        assert!(!local.0.lock().unwrap().contains_key("staged"));
        assert!(!c.lock().unwrap().has_saved_changes());
        let p = c.lock().unwrap().prepare().unwrap();
        assert!(p.pages.is_empty());
        assert_eq!(p.len, 0);
        c.lock().unwrap().abort_publish();
        // Rewrite spilled pages, then save: the record names only the
        // newest objects and the replaced ones are gone.
        img.seek(SeekFrom::Start(0)).unwrap();
        img.write_all(&vec![4u8; 20 * page as usize]).unwrap();
        img.sync_all().unwrap();
        assert_eq!(outbox(), 20);
        // A spill after the save is not part of what is published.
        img.seek(SeekFrom::Start(0)).unwrap();
        img.write_all(&vec![6u8; 17 * page as usize]).unwrap();
        let p = c.lock().unwrap().prepare().unwrap();
        assert_eq!(p.pages.len(), 20);
        assert_eq!(p.len, 20 * page);
        let saved = c.lock().unwrap().saved.pages.clone();
        assert!(p.pages.iter().all(|(i, r)| saved.get(i) == Some(r)));
        c.lock().unwrap().abort_publish();
        img.sync_all().unwrap();
        c.lock().unwrap().cache = PageCache::default();
        let mut b = vec![0u8; 20 * page as usize];
        img.seek(SeekFrom::Start(0)).unwrap();
        img.read_exact(&mut b).unwrap();
        assert!(b[..17 * page as usize].iter().all(|&x| x == 6));
        assert!(b[17 * page as usize..].iter().all(|&x| x == 4));
    }

    /// What `Session::publish` does around the upload, with the upload
    /// itself in `during`.
    fn publish(c: &Arc<Mutex<ImageCore>>, store: &SharedStore, seq: u64, during: impl FnOnce()) {
        let prepared = c.lock().unwrap().prepare().unwrap();
        during();
        let local = c.lock().unwrap().local.clone().unwrap();
        let mut s = store.lock().unwrap();
        for (_, r) in &prepared.pages {
            let obj = outbox_object(&local, &r.object_id()).unwrap();
            s.create_new(Area::Page, &Name::Object(r.object_id()), &obj)
                .unwrap();
        }
        for (_, r, obj, _) in &prepared.new_tables {
            s.create_new(Area::Table, &Name::Object(r.object_id()), obj)
                .unwrap();
        }
        drop(s);
        let base = ManifestRef {
            device: crate::manifest::DeviceId([9; 16]),
            seq,
            oid: [seq as u8; 32],
            hash: [0; 32],
        };
        c.lock().unwrap().published(base, prepared).unwrap();
    }

    fn contents(c: &Arc<Mutex<ImageCore>>) -> Vec<u8> {
        let mut core = c.lock().unwrap();
        core.cache = PageCache::default();
        let mut b = vec![0u8; core.len() as usize];
        core.read_at(0, &mut b).unwrap();
        b
    }

    #[test]
    fn growing_back_after_a_truncation_reads_zeros_not_the_base() {
        let (c, store, _l) = core(16);
        let mut img = PagedImage::new(c.clone());
        img.write_all(&[5u8; 64]).unwrap();
        img.sync_all().unwrap();
        publish(&c, &store, 1, || {});
        // Cut into page 1, then grow back over the base's pages 2 and 3.
        img.set_len(20).unwrap();
        img.set_len(64).unwrap();
        let mut want = vec![5u8; 20];
        want.resize(64, 0);
        assert_eq!(contents(&c), want);
        // Published too: the new table no longer names the cut pages.
        img.sync_all().unwrap();
        publish(&c, &store, 2, || {});
        assert_eq!(contents(&c), want);
        assert!(!c.lock().unwrap().has_unpublished());
    }

    #[test]
    fn the_vault_keeps_working_while_a_publish_uploads() {
        let (c, store, local) = core(16);
        let mut img = PagedImage::new(c.clone());
        img.write_all(&[1u8; 48]).unwrap();
        img.sync_all().unwrap();
        publish(&c, &store, 1, || {
            // While uploading: rewrite page 0, cut page 2 off and grow
            // back, and save. None of it waits, and none of it removes an
            // object the upload still has to read.
            img.seek(SeekFrom::Start(0)).unwrap();
            img.write_all(&[2u8; 16]).unwrap();
            img.set_len(32).unwrap();
            img.set_len(48).unwrap();
            img.sync_all().unwrap();
        });
        // The upload published the state it started from; the changes
        // made meanwhile stay staged on top of it.
        let mut want = vec![2u8; 16];
        want.extend([1u8; 16]);
        want.extend([0u8; 16]);
        assert_eq!(contents(&c), want);
        assert!(c.lock().unwrap().has_unpublished());
        assert_eq!(c.lock().unwrap().staged.len(), 1);
        let outbox = || {
            local
                .0
                .lock()
                .unwrap()
                .keys()
                .filter(|n| n.starts_with("p-"))
                .count()
        };
        assert_eq!(outbox(), 1, "published and replaced objects are gone");
        publish(&c, &store, 2, || {});
        assert_eq!(contents(&c), want);
        assert!(!c.lock().unwrap().has_unpublished());
        assert_eq!(outbox(), 0);
    }

    #[test]
    fn unsaved_and_concurrent_changes_survive_a_publish() {
        let (c, store, local) = core(16);
        let mut img = PagedImage::new(c.clone());
        img.write_all(&[1u8; 64]).unwrap();
        img.sync_all().unwrap();
        publish(&c, &store, 1, || {});
        // Saved: page 0. Not saved: a cut to one page, grown back.
        img.seek(SeekFrom::Start(0)).unwrap();
        img.write_all(&[2u8; 16]).unwrap();
        img.sync_all().unwrap();
        img.set_len(16).unwrap();
        img.set_len(64).unwrap();
        publish(&c, &store, 2, || {
            // Saved while uploading: page 3, with the cut.
            img.seek(SeekFrom::Start(48)).unwrap();
            img.write_all(&[7u8; 16]).unwrap();
            img.sync_all().unwrap();
        });
        let mut want = vec![2u8; 16];
        want.extend([0u8; 32]);
        want.extend([7u8; 16]);
        assert_eq!(contents(&c), want);
        // The record holds the newer save, on top of the published one.
        let rec = {
            let keys = c.lock().unwrap().keys.clone();
            let mut l = local.clone();
            load_record(&keys, &mut l).unwrap().unwrap()
        };
        assert_eq!(rec.base.unwrap().seq, 2);
        assert_eq!(rec.cut, Some(1));
        assert_eq!(rec.pages.iter().map(|p| p.0).collect::<Vec<_>>(), [3]);
        publish(&c, &store, 3, || {});
        assert_eq!(contents(&c), want);
        assert!(!c.lock().unwrap().has_unpublished());
    }

    #[test]
    fn a_failed_publish_keeps_its_changes_staged() {
        let (c, _store, local) = core(16);
        let mut img = PagedImage::new(c.clone());
        img.write_all(&[1u8; 32]).unwrap();
        img.sync_all().unwrap();
        c.lock().unwrap().prepare().unwrap();
        // Page 0 replaced while uploading, then the upload fails.
        img.seek(SeekFrom::Start(0)).unwrap();
        img.write_all(&[2u8; 16]).unwrap();
        img.sync_all().unwrap();
        c.lock().unwrap().abort_publish();
        let mut want = vec![2u8; 16];
        want.extend([1u8; 16]);
        assert_eq!(contents(&c), want);
        // The replaced object goes with the next save.
        img.sync_all().unwrap();
        let outbox = local
            .0
            .lock()
            .unwrap()
            .keys()
            .filter(|n| n.starts_with("p-"))
            .count();
        assert_eq!(outbox, 2);
        assert!(c.lock().unwrap().prepare().is_ok());
    }

    /// A page moves between the changed set, the cache and the outbox;
    /// a read always sees the newest bytes, also once the cache is gone.
    #[test]
    fn reads_see_the_newest_bytes_wherever_the_page_is() {
        let (c, _s, _l) = core(16);
        let mut img = PagedImage::new(c.clone());
        let mut want = vec![0u8; 48];
        let write = |img: &mut PagedImage, want: &mut Vec<u8>, off: usize, b: &[u8]| {
            img.seek(SeekFrom::Start(off as u64)).unwrap();
            img.write_all(b).unwrap();
            want[off..off + b.len()].copy_from_slice(b);
        };
        // Reads through whatever is cached (`contents` empties the cache
        // first, so it reads from the changed set or the outbox).
        let cached = |c: &Arc<Mutex<ImageCore>>| {
            let mut core = c.lock().unwrap();
            let mut b = vec![0u8; core.len() as usize];
            core.read_at(0, &mut b).unwrap();
            b
        };

        write(&mut img, &mut want, 0, &[1; 48]);
        assert_eq!(cached(&c), want, "changed, not saved");
        img.sync_all().unwrap();
        assert_eq!(cached(&c), want, "saved: sealed pages moved to the cache");
        write(&mut img, &mut want, 5, &[2; 3]);
        assert_eq!(cached(&c), want, "part of a cached page changed");
        write(&mut img, &mut want, 16, &[3; 16]);
        assert_eq!(cached(&c), want, "a whole cached page replaced");
        img.sync_all().unwrap();
        assert_eq!(contents(&c), want, "read from the outbox");
        // `contents` left the pages cached: change one of them.
        write(&mut img, &mut want, 1, &[4; 2]);
        assert_eq!(cached(&c), want, "changed after being cached");
        assert_eq!(contents(&c), want, "changed, cache emptied");
        // Truncate into page 2 and grow back: its tail reads zeros.
        img.set_len(40).unwrap();
        img.set_len(48).unwrap();
        want[40..].fill(0);
        assert_eq!(cached(&c), want, "after a truncation");
        img.sync_all().unwrap();
        assert_eq!(cached(&c), want, "after the last save");
        assert_eq!(contents(&c), want, "after the last save, from the outbox");
    }

    /// A save that cannot write every page to the outbox keeps the pages
    /// it did not write: the next save writes them, nothing is lost.
    #[test]
    fn a_failed_save_keeps_the_pages_it_did_not_write() {
        struct Flaky {
            inner: MemLocal,
            /// Page writes left before one fails.
            fail_after: Arc<Mutex<Option<usize>>>,
        }
        impl LocalStore for Flaky {
            fn get(&mut self, name: &str) -> Result<Option<Vec<u8>>> {
                self.inner.get(name)
            }
            fn put(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
                let mut f = self.fail_after.lock().unwrap();
                if name.starts_with("p-") && *f == Some(0) {
                    *f = None;
                    return Err(SyncError::Io(std::io::Error::other("disk full")));
                }
                if let Some(n) = f.as_mut() {
                    *n -= usize::from(name.starts_with("p-"));
                }
                self.inner.put(name, bytes)
            }
            fn remove(&mut self, name: &str) -> Result<()> {
                self.inner.remove(name)
            }
            fn list(&mut self) -> Result<Vec<String>> {
                self.inner.list()
            }
        }
        let keys = Arc::new(fixed_keys(CipherSuite::Aes256GcmSiv, [1; 16]));
        let store: SharedStore = Arc::new(Mutex::new(Box::new(MemStore::new())));
        let fail_after = Arc::new(Mutex::new(None));
        let local: SharedLocal = Arc::new(Mutex::new(Box::new(Flaky {
            inner: MemLocal::default(),
            fail_after: fail_after.clone(),
        })));
        let c = Arc::new(Mutex::new(ImageCore::new(
            keys,
            store,
            Some(local),
            16,
            0,
            None,
            vec![],
        )));
        let mut img = PagedImage::new(c.clone());
        let data: Vec<u8> = (0..64u8).collect();
        img.write_all(&data).unwrap();
        // The second of the four pages fails to write.
        *fail_after.lock().unwrap() = Some(1);
        assert!(img.sync_all().is_err());
        assert_eq!(contents(&c), data);
        img.sync_all().unwrap();
        c.lock().unwrap().cache = PageCache::default();
        assert_eq!(contents(&c), data);
        assert_eq!(c.lock().unwrap().saved.pages.len(), 4);
    }
}
