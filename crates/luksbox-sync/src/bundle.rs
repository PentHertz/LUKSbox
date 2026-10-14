// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Sessions on a sync bundle: convert a vault into a bundle, open one,
//! publish what was saved.
//!
//! Opening (section 5 of `docs/CLOUD_SYNC_IMPLEMENTATION.md`):
//!
//! 1. Header objects are tried newest first with the caller's unlock
//!    material; the first that opens gives the MVK and the bundle keys.
//! 2. Every manifest is verified, the commit graph is built and checked
//!    against this device's state (rollback, equivocation, withholding).
//! 3. The head's own header must open with the same material: a
//!    credential revoked in a newer header is refused even if an older
//!    header object is still around (`CredentialRevoked`).
//! 4. The head must be complete (every table block and page present);
//!    otherwise its newest complete ancestor opens read-only.
//!
//! Publishing writes every new object first, then records the exact
//! manifest bytes locally (`manifest-pending`), then writes the manifest,
//! then updates the device state. A crash at any point either leaves
//! nothing visible or is finished at the next open with the same bytes,
//! so a device never writes two different commits with one number.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use luksbox_core::{HEADER_SIZE, Header, MasterVolumeKey};
use luksbox_format::{Container, UnlockMaterial};

use crate::error::{Result, SyncError};
use crate::graph::{Graph, Notice, writable};
use crate::image::{
    BundleHeaderStore, ImageCore, PagedImage, SharedLocal, SharedStore, load_record,
};
use crate::keys::{BundleKeys, Kind};
use crate::local::LocalStore;
use crate::manifest::{
    CommitKind, FORMAT, HeaderRef, MANIFEST_SIZES, Manifest, ManifestRef, NamedRef, PAGE_SIZES,
    Seen, Verified, sanitize_label,
};
use crate::names::{Area, BundleId, HeaderName, Name};
use crate::state::{DeviceState, PENDING_MANIFEST};
use crate::store::{LenRule, ObjectStore};
use crate::table::{BLOCK_OBJECT_LEN, ENTRIES_PER_BLOCK, ObjRef, TableBlock, page_count, sha256};

/// Most manifests an open will read (retention keeps far fewer).
pub const MAX_MANIFESTS: usize = 100_000;
/// Largest hybrid sidecar object accepted.
const MAX_HYBRID: usize = 1 << 20;
/// Default page size: 4 MiB.
pub const DEFAULT_PAGE_SIZE: u32 = 4 << 20;

pub struct ConvertOptions {
    pub page_size: u32,
    pub device_label: String,
    /// Bytes of the vault's `.hybrid` sidecar, if it has ML-KEM slots.
    pub hybrid_sidecar: Option<Vec<u8>>,
}

impl Default for ConvertOptions {
    fn default() -> Self {
        Self {
            page_size: DEFAULT_PAGE_SIZE,
            device_label: "device".into(),
            hybrid_sidecar: None,
        }
    }
}

#[derive(Default)]
pub struct OpenOptions {
    pub device_label: String,
    /// Open a view that never writes (nothing staged, nothing published).
    pub read_only: bool,
}

/// What an open found besides the state it opened.
#[derive(Debug, Default)]
pub struct OpenReport {
    pub notices: Vec<Notice>,
    /// Entries in the bundle outside the name grammar (never touched).
    pub foreign_entries: usize,
    /// Manifest objects that did not verify (ignored).
    pub invalid_manifests: usize,
    /// This device found its identity in use elsewhere and took a new one.
    pub new_identity: bool,
    /// Changes saved on this device and not published yet were restored.
    pub restored_local_changes: bool,
    /// Whether this session may write and publish.
    pub writable: bool,
    /// Other heads (concurrent commits) not merged by this open.
    pub other_heads: usize,
    /// Other sessions with a fresh lease: `(device label, writable)`.
    pub open_elsewhere: Vec<(String, bool)>,
    /// What a merge of concurrent keyslot changes decided.
    pub keyslot_notes: Vec<String>,
}

pub struct Session {
    pub(crate) bundle: BundleId,
    pub(crate) display: PathBuf,
    pub(crate) store: SharedStore,
    pub(crate) local: SharedLocal,
    pub(crate) keys: Arc<BundleKeys>,
    pub(crate) core: Arc<Mutex<ImageCore>>,
    pub(crate) state: DeviceState,
    pub(crate) head: Verified,
    pub(crate) writable: bool,
    /// Kept for opening read-only views of other commits (merges).
    pub(crate) mvk: MasterVolumeKey,
    pub(crate) header_bytes: [u8; HEADER_SIZE],
    pub(crate) lease: Option<(crate::names::ObjectId, crate::lease::Lease)>,
    /// Newest commit on the head's first-parent line made by another
    /// device (see `Lease::pin`).
    pub(crate) pin: Option<ManifestRef>,
}

fn header_generation(bytes: &[u8; HEADER_SIZE]) -> u64 {
    Header::from_bytes(bytes)
        .map(|h| h.header_generation)
        .unwrap_or(0)
}

/// Digest of what a header *means*: format, cipher, layout, flags,
/// generation, and every keyslot's fields, but not the random padding a
/// re-serialization refreshes. Two devices that make the same change
/// (for example the same automatic format upgrade) produce different
/// bytes but the same semantics, which is not a conflict.
pub(crate) fn header_semantics(bytes: &[u8; HEADER_SIZE]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let Ok(h) = Header::from_bytes(bytes) else {
        return sha256(bytes);
    };
    let mut d = Sha256::new();
    d.update(b"lbx:sync/header-semantics/v1");
    d.update(h.version_major.to_le_bytes());
    d.update((h.cipher_suite as u16).to_le_bytes());
    d.update((h.kdf as u16).to_le_bytes());
    d.update(h.chunk_size.to_le_bytes());
    d.update(h.flags.to_le_bytes());
    d.update(h.header_salt);
    d.update(h.metadata_offset.to_le_bytes());
    d.update(h.metadata_size.to_le_bytes());
    d.update(h.data_offset.to_le_bytes());
    d.update(h.header_generation.to_le_bytes());
    for (k, sep) in h.keyslots.iter().zip(h.sep_blobs.iter()) {
        d.update([k.kind as u8]);
        if k.kind != luksbox_core::SlotKind::Empty {
            d.update([k.aad_version]);
            d.update(k.uuid);
            d.update(k.kdf_params.m_cost_kib.to_le_bytes());
            d.update(k.kdf_params.t_cost.to_le_bytes());
            d.update(k.kdf_params.p_cost.to_le_bytes());
            d.update(k.kdf_salt);
            d.update(k.aead_nonce);
            d.update(k.wrapped_ct);
            d.update(k.wrapped_tag);
            d.update((k.fido2_cred_id.len() as u32).to_le_bytes());
            d.update(&k.fido2_cred_id);
            d.update(k.fido2_hmac_salt);
        }
        match sep {
            Some(b) => {
                d.update((b.len() as u32 + 1).to_le_bytes());
                d.update(b);
            }
            None => d.update(0u32.to_le_bytes()),
        }
    }
    d.finalize().into()
}

/// Digest of keyslot `i` (its fields and Secure Enclave blob): the unit
/// a keyslot merge compares.
fn slot_digest(h: &Header, i: usize) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let k = &h.keyslots[i];
    let mut d = Sha256::new();
    d.update(b"lbx:sync/slot/v1");
    d.update([k.kind as u8]);
    if k.kind != luksbox_core::SlotKind::Empty {
        d.update([k.aad_version]);
        d.update(k.uuid);
        d.update(k.kdf_params.m_cost_kib.to_le_bytes());
        d.update(k.kdf_params.t_cost.to_le_bytes());
        d.update(k.kdf_params.p_cost.to_le_bytes());
        d.update(k.kdf_salt);
        d.update(k.aead_nonce);
        d.update(k.wrapped_ct);
        d.update(k.wrapped_tag);
        d.update((k.fido2_cred_id.len() as u32).to_le_bytes());
        d.update(&k.fido2_cred_id);
        d.update(k.fido2_hmac_salt);
    }
    match &h.sep_blobs[i] {
        Some(b) => {
            d.update((b.len() as u32 + 1).to_le_bytes());
            d.update(b);
        }
        None => d.update(0u32.to_le_bytes()),
    }
    d.finalize().into()
}

/// Everything in a header but the keyslots, the generation and the flag
/// derived from them (`FLAG_HAS_SEP_REGION`).
fn header_frame(h: &Header) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut d = Sha256::new();
    d.update(b"lbx:sync/header-frame/v1");
    d.update(h.version_major.to_le_bytes());
    d.update((h.cipher_suite as u16).to_le_bytes());
    d.update((h.kdf as u16).to_le_bytes());
    d.update(h.chunk_size.to_le_bytes());
    d.update((h.flags & !luksbox_core::header::FLAG_HAS_SEP_REGION).to_le_bytes());
    d.update(h.header_salt);
    d.update(h.metadata_offset.to_le_bytes());
    d.update(h.metadata_size.to_le_bytes());
    d.update(h.data_offset.to_le_bytes());
    d.finalize().into()
}

/// Three-way merge of two keyslot tables changed concurrently (`target`
/// is the side merged into). Keyslots are independent wrappings of the
/// same master key, so they merge one by one:
///
/// - changed on one side only: that side's version;
/// - removed on one side, changed on the other: removed (a revocation is
///   never undone by a merge);
/// - enrolled on both sides into the same free slot: the target's stays,
///   the other moves to a free slot (a keyslot's AEAD does not bind its
///   index); a post-quantum hybrid slot cannot move (its sidecar entry is
///   keyed by index) and is reported;
/// - changed differently on both sides: the target's version, reported.
///
/// `None` if the rest of the header changed on both sides (format,
/// cipher, flags...): that is still a fork for the user. Returns the
/// merged header (new generation) and what the user should know.
pub(crate) fn merge_keyslot_tables(
    base: &Header,
    target: &Header,
    other: &Header,
) -> Option<(Header, Vec<String>)> {
    use luksbox_core::SlotKind;
    let (fb, ft, fo) = (
        header_frame(base),
        header_frame(target),
        header_frame(other),
    );
    let mut merged = if ft == fo || fo == fb {
        target.clone()
    } else if ft == fb {
        // Only the other side changed the frame: start from it.
        let mut m = other.clone();
        m.keyslots = target.keyslots.clone();
        m.sep_blobs = target.sep_blobs.clone();
        m
    } else {
        return None;
    };
    let mut notes = Vec::new();
    let mut to_move: Vec<usize> = Vec::new();
    for i in 0..merged.keyslots.len() {
        let (db, dt, d_o) = (
            slot_digest(base, i),
            slot_digest(target, i),
            slot_digest(other, i),
        );
        if dt == d_o || d_o == db {
            continue; // keep the target's
        }
        if dt == db {
            merged.keyslots[i] = other.keyslots[i].clone();
            merged.sep_blobs[i] = other.sep_blobs[i].clone();
            continue;
        }
        // Changed on both sides, differently.
        let t_empty = target.keyslots[i].kind == SlotKind::Empty;
        let o_empty = other.keyslots[i].kind == SlotKind::Empty;
        if t_empty || o_empty {
            merged.keyslots[i] = luksbox_core::Keyslot::empty();
            merged.sep_blobs[i] = None;
            notes.push(format!(
                "keyslot {i}: removed on one device and changed on the other; it stays removed"
            ));
        } else if base.keyslots[i].kind == SlotKind::Empty && !other.keyslots[i].kind.is_hybrid_pq()
        {
            to_move.push(i);
        } else {
            notes.push(format!(
                "keyslot {i}: changed differently on two devices; one change was kept, \
                 redo the other"
            ));
        }
    }
    for i in to_move {
        let free = (0..merged.keyslots.len()).find(|&j| {
            merged.keyslots[j].kind == SlotKind::Empty
                && base.keyslots[j].kind == SlotKind::Empty
                && target.keyslots[j].kind == SlotKind::Empty
                && other.keyslots[j].kind == SlotKind::Empty
        });
        match free {
            Some(j) => {
                merged.keyslots[j] = other.keyslots[i].clone();
                merged.sep_blobs[j] = other.sep_blobs[i].clone();
                notes.push(format!(
                    "keyslot {i}: enrolled on two devices at once; the other device's moved to slot {j}"
                ));
            }
            None => notes.push(format!(
                "keyslot {i}: enrolled on two devices at once and no slot is free; one of \
                 them must be enrolled again"
            )),
        }
    }
    if merged.sep_blobs.iter().any(Option::is_some) {
        merged.flags |= luksbox_core::header::FLAG_HAS_SEP_REGION;
    } else {
        merged.flags &= !luksbox_core::header::FLAG_HAS_SEP_REGION;
    }
    if merged.has_header_generation() {
        merged.header_generation = target.header_generation.max(other.header_generation) + 1;
    }
    Some((merged, notes))
}

/// Header objects of the bundle, newest generation first. All must
/// belong to one bundle id.
pub(crate) fn header_candidates(
    store: &mut dyn ObjectStore,
) -> Result<(BundleId, Vec<(HeaderName, [u8; HEADER_SIZE])>)> {
    let listing = store.list(Area::Header)?;
    let mut bid: Option<BundleId> = None;
    let mut out = Vec::new();
    for n in listing.names {
        let Name::Header(h) = n else { continue };
        match bid {
            None => bid = Some(h.bundle),
            Some(b) if b != h.bundle => {
                return Err(SyncError::NotABundle(
                    "header objects of two different bundles in one folder".into(),
                ));
            }
            _ => {}
        }
        let Some(bytes) = store.read(Area::Header, &n, LenRule::Exact(HEADER_SIZE))? else {
            continue;
        };
        let bytes: [u8; HEADER_SIZE] = bytes.try_into().expect("exact length");
        out.push((h, bytes));
    }
    let bid = bid.ok_or_else(|| {
        SyncError::NotABundle(format!("no header object in {}", store.describe()))
    })?;
    // Newest first by the generation inside the header (the name's is
    // only a hint); ties broken by name for determinism.
    out.sort_by_key(|(n, b)| std::cmp::Reverse((header_generation(b), n.to_name())));
    Ok((bid, out))
}

pub(crate) fn shared_store(s: Box<dyn ObjectStore>) -> SharedStore {
    Arc::new(Mutex::new(s))
}

/// Read and verify every manifest. Invalid ones are counted, not fatal.
pub(crate) fn load_manifests(
    store: &SharedStore,
    keys: &BundleKeys,
) -> Result<(Vec<Verified>, usize, usize)> {
    let mut s = store.lock().expect("store lock");
    let listing = s.list(Area::Manifest)?;
    if listing.names.len() > MAX_MANIFESTS {
        return Err(SyncError::Limit("too many manifests in the bundle"));
    }
    let mut out = Vec::with_capacity(listing.names.len());
    let mut invalid = 0;
    for n in &listing.names {
        let Some(oid) = n.object_id() else { continue };
        match s.read(Area::Manifest, n, LenRule::OneOf(&MANIFEST_SIZES)) {
            Ok(Some(bytes)) => match Manifest::open(keys, oid, &bytes) {
                Ok(v) => out.push(v),
                Err(_) => invalid += 1,
            },
            Ok(None) => {}
            Err(SyncError::Refused { .. }) => invalid += 1,
            Err(e) => return Err(e),
        }
    }
    Ok((out, invalid, listing.foreign_count))
}

/// Whether every object of `v` is present and its table blocks verify.
/// Returns the decoded blocks on success.
pub(crate) fn complete(
    store: &SharedStore,
    keys: &BundleKeys,
    v: &Verified,
) -> Result<Option<Vec<TableBlock>>> {
    let mut s = store.lock().expect("store lock");
    let pages = s.list(Area::Page)?;
    let present: std::collections::HashSet<[u8; 32]> = pages
        .names
        .iter()
        .filter_map(|n| n.object_id().map(|o| o.0))
        .collect();
    let total_pages = page_count(v.m.logical_len, v.m.page_size as u64);
    let mut blocks = Vec::with_capacity(v.m.tables.len());
    for (b, r) in v.m.tables.iter().enumerate() {
        let Some(obj) = s.read(
            Area::Table,
            &Name::Object(r.object_id()),
            LenRule::Exact(BLOCK_OBJECT_LEN),
        )?
        else {
            return Ok(None);
        };
        let block = TableBlock::open(keys, r, b as u64, &obj)?;
        for (i, e) in block.entries.iter().enumerate() {
            let idx = b as u64 * ENTRIES_PER_BLOCK as u64 + i as u64;
            match e {
                Some(_) if idx >= total_pages => {
                    return Err(SyncError::Malformed {
                        name: format!("t/{}", r.object_id().to_hex()),
                        why: "table entry past the end of the image",
                    });
                }
                Some(p) if !present.contains(&p.oid) => return Ok(None),
                _ => {}
            }
        }
        blocks.push(block);
    }
    Ok(Some(blocks))
}

pub(crate) fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Write a manifest with the crash-safe protocol described in the module
/// docs, then update the device state.
fn publish_manifest(
    store: &SharedStore,
    local: &mut dyn LocalStore,
    keys: &BundleKeys,
    state: &mut DeviceState,
    m: Manifest,
) -> Result<Verified> {
    let (oid, bytes) = m.seal(keys)?;
    let r = ManifestRef {
        device: m.device,
        seq: m.seq,
        oid: oid.0,
        hash: sha256(&bytes),
    };
    local.put(PENDING_MANIFEST, &bytes)?;
    state.publishing = Some(r);
    state.save(keys, local)?;
    {
        let mut s = store.lock().expect("store lock");
        s.create_new(Area::Manifest, &Name::Object(oid), &bytes)?;
        s.sync()?;
    }
    finish_publish(local, keys, state, &r, m.header.generation)?;
    Ok(Verified {
        oid,
        hash: r.hash,
        size: bytes.len(),
        m,
    })
}

fn finish_publish(
    local: &mut dyn LocalStore,
    keys: &BundleKeys,
    state: &mut DeviceState,
    r: &ManifestRef,
    header_generation: u64,
) -> Result<()> {
    state.own_seq = state.own_seq.max(r.seq);
    state.see(r);
    state.head = Some(*r);
    state.max_header_generation = state.max_header_generation.max(header_generation);
    state.publishing = None;
    state.save(keys, local)?;
    local.remove(PENDING_MANIFEST)
}

/// Turn the vault open in `src` into a new bundle in `store`. The vault
/// itself is not changed. `local_for` gives this device's local store
/// for the new bundle id.
pub fn convert(
    src: &mut Container,
    store: Box<dyn ObjectStore>,
    local_for: impl FnOnce(BundleId) -> Result<Box<dyn LocalStore>>,
    opts: &ConvertOptions,
) -> Result<BundleId> {
    if !PAGE_SIZES.contains(&opts.page_size) {
        return Err(SyncError::Unsupported("page size must be 1, 4 or 16 MiB"));
    }
    if src.is_external() {
        return Err(SyncError::Unsupported("the vault is already in a bundle"));
    }
    let (header_bytes, image_start) = src.export_external_header()?;
    let file_len = src.data_file_len()?;
    let image_len = file_len
        .checked_sub(image_start)
        .ok_or(SyncError::Limit("vault shorter than its header"))?;
    let bid = BundleId::random()?;
    let keys = BundleKeys::from_container(src, bid);
    let store = shared_store(store);
    let mut local = local_for(bid)?;
    let ps = opts.page_size as u64;

    let pages = page_count(image_len, ps);
    let mut entries: Vec<ObjRef> = Vec::with_capacity(pages as usize);
    let mut buf = zeroize::Zeroizing::new(vec![0u8; ps as usize]);
    for i in 0..pages {
        let off = i * ps;
        let n = ps.min(image_len - off) as usize;
        buf.fill(0);
        src.read_at(image_start + off, &mut buf[..n])?;
        let (oid, obj) =
            crate::codec::seal_new(&keys, Kind::Page, crate::codec::Binding::Index(i), &buf)?;
        store
            .lock()
            .expect("store lock")
            .create_new(Area::Page, &Name::Object(oid), &obj)?;
        entries.push(ObjRef::of(oid, &obj));
    }
    let mut tables = Vec::new();
    for (b, chunk) in entries.chunks(ENTRIES_PER_BLOCK).enumerate() {
        let mut block = TableBlock::default();
        for (i, r) in chunk.iter().enumerate() {
            block.entries[i] = Some(*r);
        }
        let (r, obj) = block.seal(&keys, b as u64)?;
        store.lock().expect("store lock").create_new(
            Area::Table,
            &Name::Object(r.object_id()),
            &obj,
        )?;
        tables.push(r);
    }
    let generation = header_generation(&header_bytes);
    let hname = HeaderName::new(bid, generation)?;
    let hybrid = match &opts.hybrid_sidecar {
        Some(bytes) if bytes.len() > MAX_HYBRID => {
            return Err(SyncError::Limit("hybrid sidecar too large"));
        }
        Some(bytes) => {
            let n = HeaderName::new(bid, generation)?;
            store
                .lock()
                .expect("store lock")
                .create_new(Area::Hybrid, &Name::Header(n), bytes)?;
            Some(NamedRef {
                name: n.to_name(),
                hash: sha256(bytes),
            })
        }
        None => None,
    };
    {
        let mut s = store.lock().expect("store lock");
        s.create_new(Area::Header, &Name::Header(hname), &header_bytes)?;
        s.sync()?;
    }
    let label = sanitize_label(&opts.device_label);
    let mut state = DeviceState::new(bid.0, label.clone())?;
    let m = Manifest {
        format: FORMAT,
        bundle: bid.0,
        device: state.device,
        seq: 1,
        lamport: 1,
        wall_clock_ns: now_ns(),
        parents: vec![],
        seen: vec![],
        checkpoint: vec![],
        header: HeaderRef {
            name: Some(hname.to_name()),
            hash: sha256(&header_bytes),
            generation,
        },
        hybrid,
        page_size: opts.page_size,
        logical_len: image_len,
        tables,
        kind: CommitKind::Convert,
        merge_log: vec![],
        gc_plan: None,
        device_label: label,
    };
    let head = publish_manifest(&store, &mut *local, &keys, &mut state, m)?;

    // Bring the bundle's header to the current format (v3, with a header
    // generation) right away, so devices never each upgrade it on their
    // own (different bytes for the same change). The source vault is
    // not touched.
    if Header::from_bytes(&header_bytes)
        .map(|h| !h.has_header_generation())
        .unwrap_or(false)
    {
        let keys = Arc::new(keys);
        let local: SharedLocal = Arc::new(Mutex::new(local));
        let mut core = ImageCore::new(
            keys.clone(),
            store.clone(),
            Some(local.clone()),
            head.m.page_size as u64,
            head.m.logical_len,
            Some(head.as_ref()),
            head.m.tables.clone(),
        );
        if let Some(b) = complete(&store, &keys, &head)? {
            core.seed_blocks(b);
        }
        let core = Arc::new(Mutex::new(core));
        let mvk = src.mvk_clone();
        let container = Container::open_external_with_mvk(
            Box::new(PagedImage::new(core.clone())),
            &header_bytes,
            Box::new(BundleHeaderStore { core: core.clone() }),
            PathBuf::from("<convert>"),
            mvk.clone(),
        )?;
        let mut session = Session {
            bundle: bid,
            display: PathBuf::from("<convert>"),
            store,
            local,
            keys,
            core,
            state,
            head,
            writable: true,
            mvk,
            header_bytes,
            lease: None,
            pin: None,
        };
        let mut vfs = luksbox_vfs::Vfs::open(container).map_err(vfs_err)?;
        if vfs.upgrade_header_to_v3().map_err(vfs_err)? {
            drop(vfs);
            session.publish()?;
        }
    }
    Ok(bid)
}

/// Header bytes a head names, read from the bundle and checked.
fn head_header(
    candidates: &[(HeaderName, [u8; HEADER_SIZE])],
    r: &HeaderRef,
) -> Result<[u8; HEADER_SIZE]> {
    let name = r.name.as_ref().ok_or(SyncError::Unsupported(
        "bundles with a detached header are not supported yet",
    ))?;
    candidates
        .iter()
        .find(|(n, b)| &n.to_name() == name && sha256(b) == r.hash)
        .map(|(_, b)| *b)
        .ok_or_else(|| SyncError::MissingHistory {
            device: "header".into(),
            seq: r.generation,
        })
}

/// First-parent chain of `h` (`h`, its first parent, its first
/// parent...). Inode ids are preserved exactly along this chain: a
/// commit's vault is its first parent's vault plus changes, and a merge
/// writes into its first parent (the target), giving files copied in from
/// the other side new ids.
fn first_parent_chain(graph: &Graph, h: &crate::graph::Hash) -> Vec<crate::graph::Hash> {
    let mut out = Vec::new();
    let mut cur = Some(*h);
    while let Some(x) = cur {
        if out.contains(&x) {
            break;
        }
        out.push(x);
        cur = graph
            .all
            .get(&x)
            .and_then(|v| v.m.parents.first())
            .map(|p| p.hash);
    }
    out
}

/// The newest commit on `h`'s first-parent line made by a device other
/// than `me` (see `Lease::pin`).
fn pin_of(
    graph: &Graph,
    h: &crate::graph::Hash,
    me: crate::manifest::DeviceId,
) -> Option<ManifestRef> {
    first_parent_chain(graph, h)
        .into_iter()
        .filter_map(|x| graph.all.get(&x))
        .find(|v| v.m.device != me)
        .map(|v| v.as_ref())
}

/// The base a merge of `a` and `b` uses: the newest commit on *both*
/// first-parent chains (highest Lamport counter, then hash, so every
/// device picks the same one). Only there do inode ids mean the same
/// file on both sides; a closer common ancestor reached through the
/// other parent of a merge could match unrelated files by id. An older
/// base can only turn already-merged changes into "same content on both
/// sides", never lose one.
fn common_ancestor(
    graph: &Graph,
    a: &crate::graph::Hash,
    b: &crate::graph::Hash,
) -> Option<crate::graph::Hash> {
    let aa: std::collections::HashSet<_> = first_parent_chain(graph, a).into_iter().collect();
    first_parent_chain(graph, b)
        .into_iter()
        .filter(|h| aa.contains(h) && graph.usable.contains(h))
        .max_by_key(|h| (graph.all[h].m.lamport, *h))
}

/// `YYYY-MM-DD HHMM` (UTC), as in conflict-copy names.
pub fn stamp(ns: u64) -> String {
    let secs = ns / 1_000_000_000;
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}{:02}",
        rem / 3600,
        (rem % 3600) / 60
    )
}

/// What `Session::finish` did.
#[derive(Debug, Default)]
pub struct FinishReport {
    pub published: Option<ManifestRef>,
    /// Concurrent commits merged into this vault before closing.
    pub merged: usize,
    pub conflicts: usize,
    /// Concurrent commits left unmerged because both changed keyslots.
    pub header_forks: usize,
    /// What a merge of concurrent keyslot changes decided (moves,
    /// removals, changes to redo).
    pub keyslot_notes: Vec<String>,
}

/// What replaying unpublished local changes onto a newer commit did.
enum Rebase {
    /// Published; what a keyslot merge decided, if one was needed, and
    /// whether the keyslot table changed (the vault is reopened under it).
    Done {
        notes: Vec<String>,
        header_changed: bool,
    },
    /// Kept as is; `recoverable`: they can still be shown.
    Stuck { recoverable: bool },
}

#[derive(Debug, Default)]
struct MergeSummary {
    merged: usize,
    conflicts: usize,
    header_forks: usize,
    header_adopted: bool,
    keyslot_notes: Vec<String>,
}

impl Session {
    /// Open a bundle. Returns the session, the container to wrap in a
    /// `Vfs`, and what was found. A session that may write merges any
    /// concurrent commits, and replays changes this device saved on an
    /// older commit, before handing the vault out.
    pub fn open(
        store: Box<dyn ObjectStore>,
        local_for: impl FnOnce(BundleId) -> Result<Box<dyn LocalStore>>,
        display: PathBuf,
        material: &mut UnlockMaterial<'_>,
        opts: &OpenOptions,
    ) -> Result<(Session, Container, OpenReport)> {
        Self::open_unlocking(
            store,
            local_for,
            display,
            &mut |bytes| Container::unlock_external_header(bytes, material),
            opts,
        )
    }

    /// [`Session::open`] with the vault's master key already in hand (a
    /// vault this device has just created and converted, still open):
    /// each header is checked against the key instead of being unlocked
    /// with a credential, so nothing is asked again.
    pub fn open_with_key(
        store: Box<dyn ObjectStore>,
        local_for: impl FnOnce(BundleId) -> Result<Box<dyn LocalStore>>,
        display: PathBuf,
        mvk: &MasterVolumeKey,
        opts: &OpenOptions,
    ) -> Result<(Session, Container, OpenReport)> {
        Self::open_unlocking(
            store,
            local_for,
            display,
            &mut |bytes| Container::verify_external_header(bytes, mvk).map(|h| (h, mvk.clone())),
            opts,
        )
    }

    /// `open`, with `unlock` turning a header object into the header and
    /// the master key (or failing for a header it cannot open).
    fn open_unlocking(
        store: Box<dyn ObjectStore>,
        local_for: impl FnOnce(BundleId) -> Result<Box<dyn LocalStore>>,
        display: PathBuf,
        unlock: &mut dyn FnMut(
            &[u8; HEADER_SIZE],
        ) -> std::result::Result<
            (Header, MasterVolumeKey),
            luksbox_format::Error,
        >,
        opts: &OpenOptions,
    ) -> Result<(Session, Container, OpenReport)> {
        let mut store = store;
        let (bid, candidates) = header_candidates(&mut *store)?;
        let store = shared_store(store);
        let local: SharedLocal = Arc::new(Mutex::new(local_for(bid)?));
        let mut report = OpenReport::default();

        // 1. Unlock the newest header the material opens.
        let mut unlocked: Option<(usize, Header, MasterVolumeKey)> = None;
        let mut last_err: Option<luksbox_format::Error> = None;
        for (i, (_, bytes)) in candidates.iter().enumerate() {
            match unlock(bytes) {
                Ok((h, mvk)) => {
                    unlocked = Some((i, h, mvk));
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        let (unlocked_idx, header, mvk) = match unlocked {
            Some(u) => u,
            None => {
                return Err(last_err
                    .map(SyncError::Format)
                    .unwrap_or_else(|| SyncError::NotABundle("no header object".into())));
            }
        };
        let keys = Arc::new(BundleKeys::from_subkey_fn(
            header.cipher_suite,
            bid,
            |info| mvk.derive_subkey(&header.header_salt, info),
        ));

        // 2. Device state, and an interrupted publish to finish.
        let mut state = {
            let mut l = local.lock().expect("local lock");
            DeviceState::load(&keys, &mut **l)?
        };
        let (mut manifests, invalid, foreign) = load_manifests(&store, &keys)?;
        report.invalid_manifests = invalid;
        report.foreign_entries = foreign;
        if let Some(st) = state.as_mut()
            && let Some(r) = st.publishing
        {
            let mut l = local.lock().expect("local lock");
            if !manifests.iter().any(|v| v.hash == r.hash)
                && let Some(bytes) = l.get(PENDING_MANIFEST)?
                && sha256(&bytes) == r.hash
            {
                let mut s = store.lock().expect("store lock");
                s.create_new(
                    Area::Manifest,
                    &Name::Object(crate::names::ObjectId(r.oid)),
                    &bytes,
                )?;
                s.sync()?;
                manifests.push(Manifest::open(
                    &keys,
                    crate::names::ObjectId(r.oid),
                    &bytes,
                )?);
            }
            if let Some(v) = manifests.iter().find(|v| v.hash == r.hash) {
                let generation = v.m.header.generation;
                finish_publish(&mut **l, &keys, st, &r, generation)?;
            } else {
                // Never reached the bundle and the bytes are gone: the
                // staged record still holds the changes.
                st.publishing = None;
                st.save(&keys, &mut **l)?;
            }
        }

        // 3. Graph and checks.
        let graph = Graph::build(manifests)?;
        let notices = match graph.check(state.as_ref()) {
            Ok(n) => n,
            Err(SyncError::IdentityConflict) => {
                let st = state.as_mut().expect("identity conflicts need a state");
                st.device = crate::manifest::DeviceId::random()?;
                st.own_seq = 0;
                st.publishing = None;
                report.new_identity = true;
                graph.check(state.as_ref())?
            }
            Err(e) => return Err(e),
        };
        let mut state = match state {
            Some(s) => s,
            None => DeviceState::new(bid.0, sanitize_label(&opts.device_label))?,
        };
        if graph.heads.is_empty() {
            return Err(SyncError::NothingComplete {
                pending: graph.pending(),
            });
        }
        let mut can_write = writable(&notices) && !opts.read_only;
        report.other_heads = graph.heads.len() - 1;

        // 4. The head (highest Lamport counter), falling back to its
        // newest complete ancestor while objects are still arriving.
        let mut head = graph.all[&graph.heads[0]].clone();
        let blocks = loop {
            if let Some(b) = complete(&store, &keys, &head)? {
                break b;
            }
            can_write = false;
            report.notices.push(Notice::Pending { count: 1 });
            let Some(p) = head.m.parents.first() else {
                return Err(SyncError::NothingComplete {
                    pending: graph.pending() + 1,
                });
            };
            head = graph
                .all
                .get(&p.hash)
                .cloned()
                .ok_or(SyncError::NothingComplete {
                    pending: graph.pending() + 1,
                })?;
        };
        if head.m.header.generation < state.max_header_generation {
            return Err(SyncError::RollbackDetected {
                device: "keyslot table".into(),
                seen: state.max_header_generation,
                visible: head.m.header.generation,
            });
        }

        // 5. The head's header must open with the same material.
        let head_header_bytes = head_header(&candidates, &head.m.header)?;
        let (header, mvk) = if head_header_bytes == candidates[unlocked_idx].1 {
            (header, mvk)
        } else {
            match unlock(&head_header_bytes) {
                Ok(hm) => hm,
                Err(_) => {
                    return Err(SyncError::CredentialRevoked {
                        since_generation: head.m.header.generation,
                    });
                }
            }
        };
        let keys = Arc::new(BundleKeys::from_subkey_fn(
            header.cipher_suite,
            bid,
            |info| mvk.derive_subkey(&header.header_salt, info),
        ));

        // 6. Image over the head. Unpublished local changes made on this
        // very head are restored; ones made on an older commit are
        // replayed by a merge below.
        let head_ref = head.as_ref();
        let mut core = ImageCore::new(
            keys.clone(),
            store.clone(),
            if can_write { Some(local.clone()) } else { None },
            head.m.page_size as u64,
            head.m.logical_len,
            Some(head_ref),
            head.m.tables.clone(),
        );
        core.seed_blocks(blocks);
        let mut stale_record = None;
        {
            let mut l = local.lock().expect("local lock");
            if let Some(rec) = load_record(&keys, &mut **l)? {
                let has_changes =
                    !rec.pages.is_empty() || rec.header.is_some() || rec.len != rec.base_len;
                if has_changes && rec.base == Some(head_ref) && can_write {
                    core.restore_record(&rec)?;
                    report.restored_local_changes = true;
                } else if has_changes && rec.base != Some(head_ref) {
                    stale_record = Some(rec);
                }
            }
        }
        let header_in_use = core.pending_header().unwrap_or(head_header_bytes);
        let core = Arc::new(Mutex::new(core));
        let mut container = Container::open_external_with_mvk(
            Box::new(PagedImage::new(core.clone())),
            &header_in_use,
            Box::new(BundleHeaderStore { core: core.clone() }),
            display.clone(),
            mvk.clone(),
        )?;
        if !can_write {
            container.set_read_only();
        }

        // 7. Remember what was seen (strengthens later rollback checks).
        for (_, h) in graph.newest.values() {
            state.see(&graph.head_ref(h));
        }
        state.head = Some(head_ref);
        state.max_header_generation = state.max_header_generation.max(head.m.header.generation);
        {
            let mut l = local.lock().expect("local lock");
            state.save(&keys, &mut **l)?;
            // Garbage-collection plans count their grace period from here
            // too, not only from their author's clock.
            crate::gc::note_plan_sightings(&keys, &mut **l, &graph, now_ns())?;
        }
        report.notices.extend(notices);

        let pin = pin_of(&graph, &head.hash, state.device);
        let mut session = Session {
            bundle: bid,
            display,
            store,
            local,
            keys,
            core,
            state,
            head,
            writable: can_write,
            mvk,
            header_bytes: header_in_use,
            lease: None,
            pin,
        };

        // 8. Replay stale local changes, then merge concurrent heads.
        // (A read-only session leaves them for a writable one.)
        if let Some(rec) = stale_record
            && can_write
        {
            let mut vfs = luksbox_vfs::Vfs::open(container).map_err(vfs_err)?;
            let done = session.rebase_local(&graph, &rec, &mut vfs);
            container = vfs.close().map_err(vfs_err)?;
            match done? {
                Rebase::Done {
                    notes,
                    header_changed,
                } => {
                    report.restored_local_changes = true;
                    report.keyslot_notes.extend(notes);
                    if header_changed {
                        // The vault was open under the previous keyslot
                        // table: reopen it under the published one, which
                        // the credential must still open.
                        container.set_read_only();
                        drop(container);
                        let hb = session.header_bytes;
                        if unlock(&hb).is_err() {
                            return Err(SyncError::CredentialRevoked {
                                since_generation: session.head.m.header.generation,
                            });
                        }
                        container = session.reopen_container()?;
                    }
                }
                Rebase::Stuck { recoverable } => {
                    // Could not be replayed safely: keep them and stay
                    // read-only rather than drop them, showing them
                    // when they can be rebuilt.
                    session.writable = false;
                    container.set_read_only();
                    if recoverable {
                        drop(container);
                        container = session.local_view(&graph, &rec)?;
                    }
                    report
                        .notices
                        .push(Notice::UnmergedLocalChanges { recoverable });
                }
            }
        }
        if session.writable && graph.heads.len() > 1 {
            let mut vfs = luksbox_vfs::Vfs::open(container).map_err(vfs_err)?;
            let merged = session.merge_heads(&mut vfs);
            container = vfs.close().map_err(vfs_err)?;
            let sum = merged?;
            report.other_heads = sum.header_forks;
            report.keyslot_notes = sum.keyslot_notes;
            if sum.header_forks > 0 {
                report.notices.push(Notice::HeaderFork {
                    heads: sum.header_forks + 1,
                });
            }
            if sum.header_adopted {
                // A merge took another device's keyslot table: the
                // credential must still open it, and the vault is
                // reopened under it.
                container.set_read_only();
                drop(container);
                let hb = session.header_bytes;
                if unlock(&hb).is_err() {
                    return Err(SyncError::CredentialRevoked {
                        since_generation: session.head.m.header.generation,
                    });
                }
                container = session.reopen_container()?;
            }
        } else if graph.heads.len() > 1 {
            report.notices.push(Notice::Pending {
                count: graph.heads.len() - 1,
            });
        }
        if session.writable {
            session.write_lease()?;
            session.remove_own_closed_leases()?;
            session.cleanup_outbox()?;
        }
        report.writable = session.writable;
        report.open_elsewhere = session.fresh_leases()?;
        Ok((session, container, report))
    }

    pub fn bundle_id(&self) -> BundleId {
        self.bundle
    }

    pub fn display(&self) -> &Path {
        &self.display
    }

    pub fn is_writable(&self) -> bool {
        self.writable
    }

    pub fn head(&self) -> &Verified {
        &self.head
    }

    pub fn device_state(&self) -> &DeviceState {
        &self.state
    }

    /// Whether this device has changes not published yet (saved, or a
    /// save in progress).
    pub fn has_unpublished(&self) -> bool {
        self.core.lock().expect("image lock").has_unpublished()
    }

    /// Make the deterministic head (`graph.heads[0]`) this session's head
    /// and open a writable vault over it, for merging into. Only called
    /// when nothing is staged.
    fn retarget(&mut self, graph: &Graph) -> Result<luksbox_vfs::Vfs> {
        let target = graph.all[&graph.heads[0]].clone();
        if complete(&self.store, &self.keys, &target)?.is_none() {
            return Err(SyncError::NothingComplete { pending: 1 });
        }
        if target.hash != self.head.hash {
            self.header_bytes = self.read_header_object(&target.m.header)?;
            self.head = target;
            self.pin = pin_of(graph, &self.head.hash, self.state.device);
        }
        let c = self.reopen_container()?;
        luksbox_vfs::Vfs::open(c).map_err(vfs_err)
    }

    /// A fresh writable container over the session's head (after a merge
    /// replaced the keyslot table).
    fn reopen_container(&mut self) -> Result<Container> {
        let head = self.head.clone();
        let mut core = ImageCore::new(
            self.keys.clone(),
            self.store.clone(),
            Some(self.local.clone()),
            head.m.page_size as u64,
            head.m.logical_len,
            Some(head.as_ref()),
            head.m.tables.clone(),
        );
        if let Some(b) = complete(&self.store, &self.keys, &head)? {
            core.seed_blocks(b);
        }
        let core = Arc::new(Mutex::new(core));
        self.core = core.clone();
        Ok(Container::open_external_with_mvk(
            Box::new(PagedImage::new(core.clone())),
            &self.header_bytes,
            Box::new(BundleHeaderStore { core }),
            self.display.clone(),
            self.mvk.clone(),
        )?)
    }

    /// A read-only view of commit `v` (for merges and snapshots).
    pub fn view(&self, v: &Verified) -> Result<luksbox_vfs::Vfs> {
        let core = ImageCore::new_view(
            self.keys.clone(),
            self.store.clone(),
            None,
            v.m.page_size as u64,
            v.m.logical_len,
            Some(v.as_ref()),
            v.m.tables.clone(),
        );
        self.open_view(core)
    }

    fn open_view(&self, core: ImageCore) -> Result<luksbox_vfs::Vfs> {
        let core = Arc::new(Mutex::new(core));
        let mut c = Container::open_external_with_mvk(
            Box::new(PagedImage::new(core.clone())),
            &self.header_bytes,
            Box::new(BundleHeaderStore { core }),
            self.display.clone(),
            self.mvk.clone(),
        )?;
        c.set_read_only();
        luksbox_vfs::Vfs::open_read_only(c).map_err(vfs_err)
    }

    /// Replay changes saved on this device on an older commit (`rec`)
    /// onto the head open in `target`, and publish them. When that cannot
    /// be done safely the record is kept as is and the outcome says
    /// whether it can still be shown (`local_view`).
    fn rebase_local(
        &mut self,
        graph: &Graph,
        rec: &crate::image::StagedRecord,
        target: &mut luksbox_vfs::Vfs,
    ) -> Result<Rebase> {
        let Some(saved_on_ref) = rec.base else {
            return Ok(Rebase::Stuck { recoverable: false });
        };
        let Some(saved_on) = graph.all.get(&saved_on_ref.hash).cloned() else {
            return Ok(Rebase::Stuck { recoverable: false });
        };
        if complete(&self.store, &self.keys, &saved_on)?.is_none() {
            return Ok(Rebase::Stuck { recoverable: false });
        }
        // A keyslot change saved here, while the keyslots also changed
        // elsewhere: merged keyslot by keyslot, or kept back if the rest
        // of the header changed on both sides.
        let mut keyslot_notes = Vec::new();
        let staged_header: Option<[u8; HEADER_SIZE]> = match &rec.header {
            None => None,
            Some(h) => {
                let h: [u8; HEADER_SIZE] =
                    h.as_slice().try_into().map_err(|_| SyncError::Malformed {
                        name: "local staged record".into(),
                        why: "staged header has the wrong size",
                    })?;
                if saved_on.m.header.hash == self.head.m.header.hash {
                    Some(h)
                } else {
                    let base_b = self.read_header_object(&saved_on.m.header)?;
                    let parsed = (
                        Header::from_bytes(&base_b),
                        Header::from_bytes(&self.header_bytes),
                        Header::from_bytes(&h),
                    );
                    match parsed {
                        (Ok(b), Ok(t), Ok(o)) => match merge_keyslot_tables(&b, &t, &o) {
                            Some((m, notes)) => {
                                keyslot_notes = notes;
                                Some(m.to_bytes(&self.mvk))
                            }
                            None => return Ok(Rebase::Stuck { recoverable: true }),
                        },
                        _ => return Ok(Rebase::Stuck { recoverable: true }),
                    }
                }
            }
        };
        // The merge base must keep inode ids on both sides: the newest
        // commit on both first-parent chains (see `common_ancestor`).
        let base = common_ancestor(graph, &saved_on.hash, &self.head.hash)
            .map(|h| graph.all[&h].clone())
            .filter(|b| {
                complete(&self.store, &self.keys, b)
                    .ok()
                    .flatten()
                    .is_some()
            });
        let mut local_core = ImageCore::new_view(
            self.keys.clone(),
            self.store.clone(),
            Some(self.local.clone()),
            saved_on.m.page_size as u64,
            saved_on.m.logical_len,
            Some(saved_on_ref),
            saved_on.m.tables.clone(),
        );
        local_core.restore_record(rec)?;
        let mut ours = self.open_view(local_core)?;
        let mut base_view = match &base {
            Some(b) => Some(self.view(b)?),
            None => None,
        };
        let out = luksbox_merge::merge(
            base_view.as_mut(),
            &mut ours,
            target,
            &luksbox_merge::Options {
                label: self.state.label.clone(),
                stamp: stamp(now_ns()),
            },
        )
        .map_err(merge_err)?;
        drop(ours);
        drop(base_view);
        target.flush().map_err(vfs_err)?;
        if let Some(h) = &staged_header {
            self.core.lock().expect("image lock").stage_header(h)?;
        }
        let mut log = to_log(&out.events);
        log.extend(keyslot_notes.iter().map(|n| crate::manifest::MergeEvent {
            path: "(keyslots)".into(),
            what: n.clone(),
        }));
        self.publish_with(CommitKind::Commit, &[], log)?;
        Ok(Rebase::Done {
            notes: keyslot_notes,
            header_changed: staged_header.is_some(),
        })
    }

    /// A read-only container showing unpublished changes saved on this
    /// device (`rec`) over the commit they were made on.
    fn local_view(&self, graph: &Graph, rec: &crate::image::StagedRecord) -> Result<Container> {
        let saved_on_ref = rec.base.ok_or(SyncError::Unsupported("no base"))?;
        let saved_on = graph
            .all
            .get(&saved_on_ref.hash)
            .ok_or(SyncError::Unsupported("no base"))?;
        let header = match &rec.header {
            Some(h) => h.as_slice().try_into().map_err(|_| SyncError::Malformed {
                name: "local staged record".into(),
                why: "staged header has the wrong size",
            })?,
            None => self.read_header_object(&saved_on.m.header)?,
        };
        let mut core = ImageCore::new_view(
            self.keys.clone(),
            self.store.clone(),
            Some(self.local.clone()),
            saved_on.m.page_size as u64,
            saved_on.m.logical_len,
            Some(saved_on_ref),
            saved_on.m.tables.clone(),
        );
        core.restore_record(rec)?;
        let core = Arc::new(Mutex::new(core));
        let mut c = Container::open_external_with_mvk(
            Box::new(PagedImage::new(core.clone())),
            &header,
            Box::new(BundleHeaderStore { core }),
            self.display.clone(),
            self.mvk.clone(),
        )?;
        c.set_read_only();
        Ok(c)
    }

    /// Delete the unpublished changes saved on this device (the staged
    /// record and its outbox), so it can write again after
    /// `Notice::UnmergedLocalChanges`. Only from a read-only session,
    /// which never restored them. Returns how many changed pages were
    /// dropped.
    pub fn discard_local_changes(&mut self) -> Result<usize> {
        if self.writable {
            return Err(SyncError::Unsupported(
                "discard local changes from a read-only session",
            ));
        }
        let mut l = self.local.lock().expect("local lock");
        let mut n = 0;
        for name in l.list()? {
            if name.starts_with("p-") {
                l.remove(&name)?;
                n += 1;
            }
        }
        l.remove(crate::image::RECORD_NAME)?;
        Ok(n)
    }

    /// Merge every other head into the vault open in `target`, one merge
    /// commit per head.
    fn merge_heads(&mut self, target: &mut luksbox_vfs::Vfs) -> Result<MergeSummary> {
        let (manifests, _, _) = load_manifests(&self.store, &self.keys)?;
        let graph = Graph::build(manifests)?;
        let mut sum = MergeSummary::default();
        let others: Vec<Verified> = graph
            .heads
            .iter()
            .filter(|h| **h != self.head.hash)
            .map(|h| graph.all[h].clone())
            .collect();
        for other in others {
            if complete(&self.store, &self.keys, &other)?.is_none() {
                continue;
            }
            let base = common_ancestor(&graph, &self.head.hash, &other.hash)
                .map(|h| graph.all[&h].clone())
                .filter(|b| {
                    complete(&self.store, &self.keys, b)
                        .ok()
                        .flatten()
                        .is_some()
                });
            // Keyslot tables: a change made on one side only is carried
            // into the merge (a revocation must never be undone by a
            // merge); different changes on both sides are left for the
            // user. Compared by meaning, not bytes.
            let mut adopt = None;
            let mut keyslot_notes: Vec<String> = Vec::new();
            if self.head.m.header.hash != other.m.header.hash {
                let ours_b = self.read_header_object(&self.head.m.header)?;
                let other_b = self.read_header_object(&other.m.header)?;
                let (so, st) = (header_semantics(&ours_b), header_semantics(&other_b));
                if so != st {
                    let base_b = base
                        .as_ref()
                        .and_then(|b| self.read_header_object(&b.m.header).ok());
                    let sb = base_b.as_ref().map(header_semantics);
                    let take_other = match sb {
                        Some(sb) => match (sb != so, sb != st) {
                            // Both changed: merge keyslot by keyslot.
                            (true, true) => {
                                let parsed = (
                                    Header::from_bytes(base_b.as_ref().expect("sb implies it")),
                                    Header::from_bytes(&ours_b),
                                    Header::from_bytes(&other_b),
                                );
                                match parsed {
                                    (Ok(b), Ok(t), Ok(o)) => {
                                        merge_keyslot_tables(&b, &t, &o).map(|(m, notes)| {
                                            adopt = Some(m.to_bytes(&self.mvk));
                                            keyslot_notes = notes;
                                            false
                                        })
                                    }
                                    _ => None,
                                }
                            }
                            (false, true) => Some(true),
                            _ => Some(false),
                        },
                        // The base's header is gone: the higher header
                        // generation wins; a tie is a conflict.
                        None => match other
                            .m
                            .header
                            .generation
                            .cmp(&self.head.m.header.generation)
                        {
                            std::cmp::Ordering::Greater => Some(true),
                            std::cmp::Ordering::Less => Some(false),
                            std::cmp::Ordering::Equal => None,
                        },
                    };
                    match take_other {
                        None => {
                            sum.header_forks += 1;
                            continue;
                        }
                        Some(true) => adopt = Some(other_b),
                        Some(false) => {}
                    }
                }
            }
            let mut base_view = match &base {
                Some(b) => Some(self.view(b)?),
                None => None,
            };
            let mut ours = self.view(&other)?;
            let out = luksbox_merge::merge(
                base_view.as_mut(),
                &mut ours,
                target,
                &luksbox_merge::Options {
                    label: other.m.device_label.clone(),
                    stamp: stamp(other.m.wall_clock_ns),
                },
            )
            .map_err(merge_err)?;
            drop(ours);
            drop(base_view);
            target.flush().map_err(vfs_err)?;
            if let Some(h) = adopt {
                self.core.lock().expect("image lock").stage_header(&h)?;
                sum.header_adopted = true;
            }
            self.state.see(&other.as_ref());
            let mut log = to_log(&out.events);
            log.extend(keyslot_notes.iter().map(|n| crate::manifest::MergeEvent {
                path: "(keyslots)".into(),
                what: n.clone(),
            }));
            self.publish_with(CommitKind::Merge, std::slice::from_ref(&other), log)?;
            sum.merged += 1;
            sum.conflicts += out.conflicts;
            sum.keyslot_notes.extend(keyslot_notes);
        }
        Ok(sum)
    }

    /// Bytes of a header object a commit names, checked against it.
    fn read_header_object(&self, r: &HeaderRef) -> Result<[u8; HEADER_SIZE]> {
        let mut s = self.store.lock().expect("store lock");
        let (_, candidates) = header_candidates(&mut **s)?;
        head_header(&candidates, r)
    }

    /// Publish the vault's last saved state as one commit. The caller
    /// first makes the vault save its changes (`Vfs::flush`, and
    /// `Container::persist_header` after keyslot changes). Returns the
    /// new commit, or `None` if there was nothing to publish.
    ///
    /// The vault stays usable while the objects upload (only `self` is
    /// held): what it changes or saves meanwhile is left for the next
    /// publish.
    ///
    /// If another device published meanwhile, this still publishes, as a
    /// second branch (safe while the vault is mounted); `finish` or the
    /// next open merges the branches.
    pub fn publish(&mut self) -> Result<Option<ManifestRef>> {
        self.publish_with(CommitKind::Commit, &[], vec![])
    }

    /// Publish what is saved, then merge any concurrent commits into the
    /// vault open in `vfs` and publish the merge. Call when the vault is
    /// being locked or unmounted (no file of it is open).
    pub fn finish(&mut self, vfs: &mut luksbox_vfs::Vfs) -> Result<FinishReport> {
        let report = FinishReport::default();
        if !self.writable {
            return Ok(report);
        }
        vfs.flush().map_err(vfs_err)?;
        vfs.container_mut().persist_header()?;
        // The caller's vault is closing: from here on it must not write.
        vfs.container_mut().set_read_only();
        self.finish_detached_into(report)
    }

    /// `finish` for a vault already closed (its container dropped after
    /// its last save, as the CLI and mount helpers do): publish what is
    /// staged, merge concurrent commits, remove the lease.
    pub fn finish_detached(&mut self) -> Result<FinishReport> {
        if !self.writable {
            return Ok(FinishReport::default());
        }
        self.finish_detached_into(FinishReport::default())
    }

    fn finish_detached_into(&mut self, mut report: FinishReport) -> Result<FinishReport> {
        report.published = self.publish()?;
        let (manifests, _, _) = load_manifests(&self.store, &self.keys)?;
        let graph = Graph::build(manifests)?;
        if graph.heads.len() > 1 {
            // Merge into the same head every device would pick (highest
            // Lamport counter, then hash), so two devices merging the
            // same branches produce the same result.
            let mut target = self.retarget(&graph)?;
            let sum = self.merge_heads(&mut target)?;
            report.merged = sum.merged;
            report.conflicts = sum.conflicts;
            report.header_forks = sum.header_forks;
            report.keyslot_notes = sum.keyslot_notes;
            target.container_mut().set_read_only();
        }
        self.close_lease()?;
        Ok(report)
    }

    fn publish_with(
        &mut self,
        kind: CommitKind,
        extra_parents: &[Verified],
        merge_log: Vec<crate::manifest::MergeEvent>,
    ) -> Result<Option<ManifestRef>> {
        self.publish_full(kind, extra_parents, merge_log, None, None)
    }

    pub(crate) fn publish_full(
        &mut self,
        kind: CommitKind,
        extra_parents: &[Verified],
        merge_log: Vec<crate::manifest::MergeEvent>,
        gc_plan: Option<crate::manifest::GcPlan>,
        checkpoint_override: Option<BTreeMap<crate::manifest::DeviceId, u64>>,
    ) -> Result<Option<ManifestRef>> {
        if !self.writable {
            return Err(SyncError::ReadOnly);
        }
        if kind == CommitKind::Commit && !self.core.lock().expect("image lock").has_saved_changes()
        {
            return Ok(None);
        }
        // Refuse to publish while a commit another device saw is missing
        // here (sync lag or withholding): fail closed.
        let (manifests, _, _) = load_manifests(&self.store, &self.keys)?;
        let graph = Graph::build(manifests)?;
        let notices = match graph.check(Some(&self.state)) {
            Err(SyncError::IdentityConflict) => {
                // Another installation published under this device's
                // identity since this session opened: publish as a new
                // device instead (the changes are based on this
                // session's head either way).
                self.state.device = crate::manifest::DeviceId::random()?;
                self.state.own_seq = 0;
                self.state.publishing = None;
                graph.check(Some(&self.state))?
            }
            other => other?,
        };
        if !writable(&notices) {
            return Err(SyncError::Unsupported(
                "a commit referenced by another device has not arrived yet; publish again later",
            ));
        }
        // The image is held only to take what to publish and, at the end,
        // to make it the base: the vault keeps working while it uploads.
        let prepared = self.core.lock().expect("image lock").prepare()?;
        let v = match self.upload_and_commit(
            kind,
            extra_parents,
            merge_log,
            gc_plan,
            checkpoint_override,
            &prepared,
        ) {
            Ok(v) => v,
            Err(e) => {
                self.core.lock().expect("image lock").abort_publish();
                return Err(e);
            }
        };
        let r = v.as_ref();
        if let Some(h) = prepared.header {
            self.header_bytes = h;
        }
        self.head = v;
        self.core
            .lock()
            .expect("image lock")
            .published(r, prepared)?;
        if self.lease.is_some() {
            self.write_lease()?;
        }
        Ok(Some(r))
    }

    /// Upload what `prepared` names, then the commit itself.
    fn upload_and_commit(
        &mut self,
        kind: CommitKind,
        extra_parents: &[Verified],
        merge_log: Vec<crate::manifest::MergeEvent>,
        gc_plan: Option<crate::manifest::GcPlan>,
        checkpoint_override: Option<BTreeMap<crate::manifest::DeviceId, u64>>,
        prepared: &crate::image::Prepared,
    ) -> Result<Verified> {
        for (_, r) in &prepared.pages {
            let obj = crate::image::outbox_object(&self.local, &r.object_id())?;
            self.store.lock().expect("store lock").create_new(
                Area::Page,
                &Name::Object(r.object_id()),
                &obj,
            )?;
        }
        {
            let mut s = self.store.lock().expect("store lock");
            for (_, r, obj, _) in &prepared.new_tables {
                s.create_new(Area::Table, &Name::Object(r.object_id()), obj)?;
            }
            s.sync()?;
        }
        let header = match prepared.header {
            Some(h) => {
                let generation = header_generation(&h);
                let name = HeaderName::new(self.bundle, generation)?;
                let mut s = self.store.lock().expect("store lock");
                s.create_new(Area::Header, &Name::Header(name), &h)?;
                s.sync()?;
                HeaderRef {
                    name: Some(name.to_name()),
                    hash: sha256(&h),
                    generation,
                }
            }
            None => self.head.m.header.clone(),
        };
        let mut seen: Vec<Seen> = self
            .state
            .seen
            .iter()
            .filter(|(d, _)| **d != self.state.device)
            .map(|(d, (seq, hash))| Seen {
                device: *d,
                seq: *seq,
                hash: *hash,
            })
            .collect();
        seen.sort_by_key(|s| s.device);
        let mut parents = vec![self.head.as_ref()];
        parents.extend(extra_parents.iter().map(|v| v.as_ref()));
        let lamport = std::iter::once(&self.head)
            .chain(extra_parents)
            .map(|v| v.m.lamport)
            .max()
            .unwrap_or(0)
            + 1;
        // Lowest kept commit per device: the highest any parent declared
        // (or a garbage-collection pass's new value, never lower).
        let mut checkpoint: BTreeMap<crate::manifest::DeviceId, u64> = BTreeMap::new();
        for v in std::iter::once(&self.head).chain(extra_parents) {
            for c in &v.m.checkpoint {
                let e = checkpoint.entry(c.device).or_insert(0);
                *e = (*e).max(c.min_seq);
            }
        }
        if let Some(over) = checkpoint_override {
            for (d, min) in over {
                let e = checkpoint.entry(d).or_insert(0);
                *e = (*e).max(min);
            }
        }
        let m = Manifest {
            format: FORMAT,
            bundle: self.bundle.0,
            device: self.state.device,
            seq: self.state.own_seq + 1,
            lamport,
            wall_clock_ns: now_ns(),
            parents,
            seen,
            checkpoint: checkpoint
                .into_iter()
                .map(|(device, min_seq)| crate::manifest::Checkpoint { device, min_seq })
                .collect(),
            header,
            hybrid: self.head.m.hybrid.clone(),
            page_size: self.head.m.page_size,
            logical_len: prepared.len,
            tables: prepared.tables.clone(),
            kind,
            merge_log,
            gc_plan,
            device_label: self.state.label.clone(),
        };
        let mut l = self.local.lock().expect("local lock");
        publish_manifest(&self.store, &mut **l, &self.keys, &mut self.state, m)
    }

    /// Write or refresh this session's lease (also re-pins the head).
    pub fn write_lease(&mut self) -> Result<()> {
        let now = now_ns();
        let lease = match &self.lease {
            Some((_, l)) => {
                let mut l = l.clone();
                l.heartbeat_ns = now;
                l.base = self.head.as_ref();
                l.pin = self.pin;
                l
            }
            None => crate::lease::Lease::new(
                self.bundle.0,
                self.state.device,
                self.state.label.clone(),
                self.writable,
                self.head.as_ref(),
                self.pin,
                now,
            ),
        };
        self.put_lease(lease)
    }

    /// Seal `lease` as a new object, then remove the one it replaces.
    // A refresh is a new lease under a new id, then the old one is
    // removed. Never rewritten in place: each object key seals exactly
    // one plaintext (the zero nonce relies on it), and nothing in the
    // bundle is ever overwritten.
    fn put_lease(&mut self, lease: crate::lease::Lease) -> Result<()> {
        let (id, bytes) = lease.seal(&self.keys)?;
        let mut s = self.store.lock().expect("store lock");
        s.create_new(Area::Lease, &Name::Object(id), &bytes)?;
        s.sync()?;
        if let Some((old, _)) = self.lease.replace((id, lease)) {
            s.remove(Area::Lease, &Name::Object(old))?;
            s.sync()?;
        }
        Ok(())
    }

    /// Remove this device's closed leases from earlier sessions (this
    /// session's lease pins what they pinned, or newer). Open leases
    /// under the same identity are left alone: they may be another
    /// installation's (a copied profile).
    fn remove_own_closed_leases(&mut self) -> Result<()> {
        let own = self.lease.as_ref().map(|(id, _)| *id);
        let mut s = self.store.lock().expect("store lock");
        let listing = s.list(Area::Lease)?;
        let mut removed = false;
        for n in listing.names.iter().take(1000) {
            let Some(id) = n.object_id() else { continue };
            if Some(id) == own {
                continue;
            }
            if let Ok(Some(bytes)) = s.read(Area::Lease, n, LenRule::Exact(crate::lease::LEASE_LEN))
                && let Ok(l) = crate::lease::Lease::open(&self.keys, id, &bytes)
                && l.device == self.state.device
                && l.closed
            {
                removed |= s.remove(Area::Lease, n)?;
            }
        }
        if removed {
            s.sync()?;
        }
        Ok(())
    }

    /// Refresh the lease: call every few minutes while the vault is open.
    pub fn heartbeat(&mut self) -> Result<()> {
        if self.lease.is_some() {
            self.write_lease()
        } else {
            Ok(())
        }
    }

    /// End of the session: replace its lease by a closed one that keeps
    /// pinning what it pinned (see the `lease` module).
    fn close_lease(&mut self) -> Result<()> {
        let Some((_, l)) = &self.lease else {
            return Ok(());
        };
        let mut closed = l.clone();
        closed.closed = true;
        closed.writable = false;
        closed.heartbeat_ns = now_ns();
        closed.base = self.head.as_ref();
        closed.pin = self.pin;
        self.put_lease(closed)?;
        // Closed: nothing more to refresh or close.
        self.lease = None;
        Ok(())
    }

    /// Other sessions with a fresh lease: `(device label, writable)`.
    pub fn fresh_leases(&self) -> Result<Vec<(String, bool)>> {
        let now = now_ns();
        let own = self.lease.as_ref().map(|(id, _)| *id);
        let mut s = self.store.lock().expect("store lock");
        let listing = s.list(Area::Lease)?;
        let mut out = Vec::new();
        for n in listing.names.iter().take(1000) {
            let Some(id) = n.object_id() else { continue };
            if Some(id) == own {
                continue;
            }
            if let Ok(Some(bytes)) = s.read(Area::Lease, n, LenRule::Exact(crate::lease::LEASE_LEN))
                && let Ok(l) = crate::lease::Lease::open(&self.keys, id, &bytes)
                && l.is_fresh(now)
                && l.device != self.state.device
            {
                out.push((l.label, l.writable));
            }
        }
        Ok(out)
    }

    /// Delete outbox objects no staged record refers to any more (left
    /// by a crash, or by changes replayed onto a newer commit).
    fn cleanup_outbox(&mut self) -> Result<()> {
        let keep: std::collections::HashSet<String> = self
            .core
            .lock()
            .expect("image lock")
            .outbox_in_use()
            .iter()
            .map(crate::image::outbox_name)
            .collect();
        let mut l = self.local.lock().expect("local lock");
        for name in l.list()? {
            if name.starts_with("p-") && !keep.contains(&name) {
                l.remove(&name)?;
            }
        }
        Ok(())
    }

    /// End the session: remove its lease. Unpublished changes stay
    /// staged on this device and are published by the next session.
    pub fn close(mut self) -> Result<()> {
        self.close_lease()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.close_lease();
    }
}

pub(crate) fn vfs_err(e: luksbox_vfs::Error) -> SyncError {
    match e {
        luksbox_vfs::Error::Format(f) => SyncError::Format(f),
        other => SyncError::Io(std::io::Error::other(other.to_string())),
    }
}

fn merge_err(e: luksbox_merge::Error) -> SyncError {
    match e {
        luksbox_merge::Error::Vfs(v) => vfs_err(v),
        other => SyncError::Io(std::io::Error::other(other.to_string())),
    }
}

fn to_log(events: &[luksbox_merge::Event]) -> Vec<crate::manifest::MergeEvent> {
    events
        .iter()
        .take(4096)
        .map(|e| crate::manifest::MergeEvent {
            path: e.path.clone(),
            what: e.what.clone(),
        })
        .collect()
}

/// Write the vault open in `container` (a bundle session's container)
/// to `dest` as a single inline-header `.lbx`. `dest` must not exist.
/// The copy is a new header state (generation bumped on header format
/// v3) and reopens as an ordinary file vault.
pub fn export(container: &mut Container, dest: &Path) -> Result<()> {
    use std::io::Write;
    if !container.is_external() {
        return Err(SyncError::Unsupported(
            "export works on a vault opened from a bundle",
        ));
    }
    let header = container.export_inline_header()?;
    let len = container.data_file_len()?;
    let mut f = luksbox_core::file_util::secure_create_new(dest)?;
    f.write_all(&header)?;
    let mut buf = zeroize::Zeroizing::new(vec![0u8; 1 << 20]);
    let mut off = 0u64;
    while off < len {
        let n = (len - off).min(buf.len() as u64) as usize;
        container.read_at(off, &mut buf[..n])?;
        f.write_all(&buf[..n])?;
        off += n as u64;
    }
    f.sync_all()?;
    luksbox_core::file_util::sync_parent_dir(dest)?;
    Ok(())
}

#[cfg(any(unix, windows))]
pub mod fs {
    //! Bundles on the real file system, with per-device state under
    //! `local_root` (`<local_root>/<bundle id>/`).

    use super::*;
    use crate::fs_store::FsStore;
    use crate::local::FsLocal;

    fn local_dir(local_root: &Path, bid: BundleId) -> PathBuf {
        local_root.join(bid.to_hex())
    }

    /// Path registry: `<local_root>/paths/<sha256(canonical path)>`
    /// holds the bundle id last seen at that path. A different id there
    /// means the folder now holds another vault.
    fn registry_entry(local_root: &Path, bundle_path: &Path) -> Result<PathBuf> {
        let canon = std::fs::canonicalize(bundle_path)?;
        #[cfg(unix)]
        let h = {
            use std::os::unix::ffi::OsStrExt;
            sha256(canon.as_os_str().as_bytes())
        };
        #[cfg(windows)]
        let h = {
            use std::os::windows::ffi::OsStrExt;
            let wide: Vec<u8> = canon
                .as_os_str()
                .encode_wide()
                .flat_map(|u| u.to_le_bytes())
                .collect();
            sha256(&wide)
        };
        Ok(local_root.join("paths").join(crate::names::to_hex(&h)))
    }

    fn remember(local_root: &Path, bundle_path: &Path, bid: BundleId) -> Result<()> {
        let e = registry_entry(local_root, bundle_path)?;
        std::fs::create_dir_all(e.parent().expect("has parent"))?;
        luksbox_core::file_util::atomic_secure_write(&e, bid.to_hex().as_bytes())?;
        Ok(())
    }

    /// Whether `path` looks like a sync bundle folder (a folder holding an
    /// `h/` folder). Cheap; `open` does the real checks.
    pub fn is_bundle(path: &Path) -> bool {
        std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
            && std::fs::symlink_metadata(path.join("h")).is_ok_and(|m| m.is_dir())
    }

    /// The newest header object of the bundle (by the generation inside
    /// it), for inspecting its keyslots before unlocking. Not
    /// authenticated: only used to decide how to prompt.
    pub fn newest_header(path: &Path) -> Result<[u8; HEADER_SIZE]> {
        let mut store = FsStore::open(path)?;
        let (_, candidates) = header_candidates(&mut store)?;
        candidates
            .first()
            .map(|(_, b)| *b)
            .ok_or_else(|| SyncError::NotABundle(path.display().to_string()))
    }

    /// The newest hybrid post-quantum sidecar object, if the bundle has
    /// one (raw sidecar bytes, checked by the sidecar parser and its
    /// header binding).
    pub fn newest_hybrid(path: &Path) -> Result<Option<Vec<u8>>> {
        let mut store = FsStore::open(path)?;
        let listing = store.list(Area::Hybrid)?;
        let mut best: Option<(u64, Name)> = None;
        for n in listing.names {
            if let Name::Header(h) = n
                && best.as_ref().is_none_or(|(g, _)| h.generation > *g)
            {
                best = Some((h.generation, n));
            }
        }
        match best {
            Some((_, n)) => Ok(store.read(Area::Hybrid, &n, LenRule::AtMost(MAX_HYBRID))?),
            None => Ok(None),
        }
    }

    /// The `.hybrid` sidecar of the vault open in `container`, for
    /// `convert`: read without following a link (a regular file of at
    /// most 32 KiB), parsed, and bound to this vault's header salt, so
    /// nothing but this vault's sidecar is ever copied into the bundle.
    /// `None` if the vault has none.
    pub fn hybrid_sidecar_for(container: &Container) -> Result<Option<Vec<u8>>> {
        use luksbox_format::hybrid_sidecar;
        let p = hybrid_sidecar::sidecar_path(container.vault_path());
        let bytes = match hybrid_sidecar::read_sidecar_bytes(&p) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let sc = hybrid_sidecar::parse_bundle(&bytes)?;
        hybrid_sidecar::verify_binding(&sc, container.header_salt())?;
        Ok(Some(bytes))
    }

    pub fn convert(
        src: &mut Container,
        dest: &Path,
        local_root: &Path,
        opts: &ConvertOptions,
    ) -> Result<BundleId> {
        let store = FsStore::create(dest)?;
        let bid = super::convert(
            src,
            Box::new(store),
            |bid| Ok(Box::new(FsLocal::open(&local_dir(local_root, bid))?) as Box<dyn LocalStore>),
            opts,
        )?;
        remember(local_root, dest, bid)?;
        Ok(bid)
    }

    pub fn open(
        path: &Path,
        local_root: &Path,
        material: &mut UnlockMaterial<'_>,
        opts: &OpenOptions,
    ) -> Result<(Session, Container, OpenReport)> {
        open_at(path, local_root, |store, local_for| {
            Session::open(store, local_for, path.to_path_buf(), material, opts)
        })
    }

    /// [`open`] with the master key in hand: see
    /// [`Session::open_with_key`].
    pub fn open_with_key(
        path: &Path,
        local_root: &Path,
        mvk: &MasterVolumeKey,
        opts: &OpenOptions,
    ) -> Result<(Session, Container, OpenReport)> {
        open_at(path, local_root, |store, local_for| {
            Session::open_with_key(store, local_for, path.to_path_buf(), mvk, opts)
        })
    }

    type LocalFor<'a> = Box<dyn FnOnce(BundleId) -> Result<Box<dyn LocalStore>> + 'a>;

    /// The folder store and this device's state for the bundle at
    /// `path`, refusing a folder that now holds another bundle.
    fn open_at(
        path: &Path,
        local_root: &Path,
        open: impl FnOnce(
            Box<dyn ObjectStore>,
            LocalFor<'_>,
        ) -> Result<(Session, Container, OpenReport)>,
    ) -> Result<(Session, Container, OpenReport)> {
        let store = FsStore::open(path)?;
        let entry = registry_entry(local_root, path)?;
        let known = std::fs::read(&entry).ok();
        let local_for: LocalFor<'_> = Box::new(move |bid: BundleId| {
            if let Some(k) = &known
                && k.as_slice() != bid.to_hex().as_bytes()
            {
                return Err(SyncError::BundleReplaced);
            }
            Ok(Box::new(FsLocal::open(&local_dir(local_root, bid))?) as Box<dyn LocalStore>)
        });
        let out = open(Box::new(store), local_for)?;
        remember(local_root, path, out.0.bundle_id())?;
        Ok(out)
    }

    /// What [`delete`] removed and left.
    #[derive(Debug, Default)]
    pub struct DeleteReport {
        /// Bundle objects removed (every version, every device's).
        pub objects: usize,
        /// Entries that are not part of the bundle, left in place.
        pub foreign: usize,
        pub foreign_sample: Vec<String>,
        /// The bundle folder itself is gone (it held nothing else).
        pub folder_removed: bool,
    }

    /// Delete the bundle at `path`, without unlocking it: every object
    /// it holds (names of the bundle's own grammar only, never
    /// recursively, never through a link: `ObjectStore::remove`), this
    /// device's state for it under `local_root` (unpublished changes
    /// included), then its folders if they are empty. Anything else in
    /// the folder is left where it is. Headers go first, so another
    /// device stops recognizing the vault at once. Safe to run again
    /// after an interruption.
    pub fn delete(path: &Path, local_root: &Path) -> Result<DeleteReport> {
        let mut store = FsStore::open(path)?;
        // Every bundle id this device associates with the folder: from
        // the headers, and from the path registry (headers may already
        // be gone after an interrupted delete).
        let mut ids: Vec<BundleId> = Vec::new();
        if let Ok((bid, _)) = header_candidates(&mut store) {
            ids.push(bid);
        }
        let entry = registry_entry(local_root, path).ok();
        if let Some(bid) = entry
            .as_ref()
            .and_then(|e| std::fs::read(e).ok())
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| BundleId::parse(s.trim()))
            && !ids.contains(&bid)
        {
            ids.push(bid);
        }

        let mut report = DeleteReport::default();
        for area in [
            Area::Header,
            Area::Lease,
            Area::Manifest,
            Area::Table,
            Area::Page,
            Area::Hybrid,
        ] {
            let listing = store.list(area)?;
            for name in &listing.names {
                if store.remove(area, name)? {
                    report.objects += 1;
                }
            }
            report.foreign += listing.foreign_count;
            report
                .foreign_sample
                .extend(listing.foreign_sample.iter().cloned());
        }
        store.sync()?;
        drop(store);

        for bid in ids {
            match std::fs::remove_dir_all(local_dir(local_root, bid)) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
                _ => {}
            }
        }
        if let Some(e) = entry {
            match std::fs::remove_file(e) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
                _ => {}
            }
        }

        // Leftover temporary files of interrupted writes, then the empty
        // folders. `remove_dir` removes empty folders only, and a link in
        // place of a folder is skipped (never followed).
        let is_dir = |p: &Path| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir());
        let remove_tmp = |dir: &Path| {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for e in entries.flatten() {
                    if e.file_name()
                        .to_str()
                        .is_some_and(crate::names::is_tmp_name)
                        && e.file_type().is_ok_and(|t| t.is_file())
                    {
                        let _ = std::fs::remove_file(e.path());
                    }
                }
            }
        };
        for area in Area::ALL {
            let adir = path.join(area.dir());
            if !is_dir(&adir) {
                continue;
            }
            remove_tmp(&adir);
            if area.sharded()
                && let Ok(entries) = std::fs::read_dir(&adir)
            {
                for e in entries.flatten() {
                    let shard = e.path();
                    if e.file_name()
                        .to_str()
                        .is_some_and(crate::names::is_shard_name)
                        && is_dir(&shard)
                    {
                        remove_tmp(&shard);
                        let _ = std::fs::remove_dir(&shard);
                    }
                }
            }
            let _ = std::fs::remove_dir(&adir);
        }
        report.folder_removed = std::fs::remove_dir(path).is_ok();
        Ok(report)
    }
}

#[cfg(test)]
mod keyslot_merge_tests {
    use super::*;
    use luksbox_core::{Argon2idParams, CipherSuite, SlotKind};

    const KDF: Argon2idParams = Argon2idParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };

    /// A real header with slots 0 and 1 in use.
    fn base() -> Header {
        let d = tempfile::tempdir().unwrap();
        let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(2 << 20));
        let mut c = Container::create_with_passphrase(
            &d.path().join("v.lbx"),
            None,
            CipherSuite::Aes256GcmSiv,
            KDF,
            b"one",
        )
        .unwrap();
        c.enroll_passphrase(b"two", KDF).unwrap();
        c.header.clone()
    }

    /// Slot `i` with its wrapped key altered (a different credential).
    fn changed(h: &Header, i: usize) -> Header {
        let mut h = h.clone();
        h.keyslots[i].wrapped_tag[0] ^= 1;
        h
    }

    fn emptied(h: &Header, i: usize) -> Header {
        let mut h = h.clone();
        h.keyslots[i] = luksbox_core::Keyslot::empty();
        h
    }

    #[test]
    fn one_sided_changes_are_taken() {
        let b = base();
        let (m, notes) = merge_keyslot_tables(&b, &b, &emptied(&b, 1)).unwrap();
        assert_eq!(m.keyslots[1].kind, SlotKind::Empty);
        assert!(notes.is_empty());
        assert!(m.header_generation > b.header_generation || !b.has_header_generation());
    }

    #[test]
    fn a_removal_wins_over_a_change_on_either_side() {
        let b = base();
        for (t, o) in [
            (emptied(&b, 1), changed(&b, 1)),
            (changed(&b, 1), emptied(&b, 1)),
        ] {
            let (m, notes) = merge_keyslot_tables(&b, &t, &o).unwrap();
            assert_eq!(m.keyslots[1].kind, SlotKind::Empty);
            assert!(notes.iter().any(|n| n.contains("stays removed")));
            assert_eq!(m.keyslots[0].wrapped_tag, b.keyslots[0].wrapped_tag);
        }
    }

    #[test]
    fn two_enrollments_in_one_free_slot_are_both_kept() {
        let b = base();
        let mut t = b.clone();
        t.keyslots[2] = b.keyslots[1].clone();
        let mut o = b.clone();
        o.keyslots[2] = changed(&b, 1).keyslots[1].clone();
        let (m, notes) = merge_keyslot_tables(&b, &t, &o).unwrap();
        assert_eq!(slot_digest(&m, 2), slot_digest(&t, 2));
        let moved = (3..m.keyslots.len())
            .find(|&j| slot_digest(&m, j) == slot_digest(&o, 2))
            .expect("the other enrollment kept in a free slot");
        assert!(
            notes
                .iter()
                .any(|n| n.contains(&format!("moved to slot {moved}")))
        );
    }

    #[test]
    fn the_rest_of_the_header_changed_on_both_sides_stays_a_fork() {
        let b = base();
        let mut t = b.clone();
        t.flags ^= luksbox_core::header::FLAG_PAD_FILES_POW2;
        let mut o = b.clone();
        o.chunk_size = b.chunk_size * 2;
        assert!(merge_keyslot_tables(&b, &t, &o).is_none());
    }
}
