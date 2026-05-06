// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use std::collections::BTreeSet;

use luksbox_format::Container;

use zeroize::Zeroizing;

use crate::chunk::{self, CHUNK_PLAINTEXT_SIZE};
use crate::error::Error;
use crate::tree::{ChunkRef, DirectoryTree, FileId, Inode, InodeKind, ROOT_ID};

/// Credentials for one keyslot during MVK rotation. Caller (typically the
/// CLI) collects one of these per populated slot before calling
/// `Vfs::rotate_mvk`.
///
/// For FIDO2 wrap-style slots, two distinct hmac-secret outputs are needed:
/// one to verify the OLD slot (computed against `slot.fido2_hmac_salt`),
/// and one to wrap the NEW slot (computed against a fresh `new_hmac_salt`
/// the caller generates). Each requires a YubiKey touch.
pub enum SlotCredential {
    Passphrase {
        slot_idx: usize,
        passphrase: Zeroizing<String>,
    },
    Fido2Wrap {
        slot_idx: usize,
        /// Optional passphrase mixed into the FIDO2 KEK derivation (matches
        /// the original keyslot's `passphrase` argument at enroll time).
        passphrase: Option<Zeroizing<String>>,
        /// Authenticator output for `slot.fido2_hmac_salt` (the old salt).
        /// Used to re-derive the OLD KEK and verify the slot.
        hmac_secret_for_verify: Zeroizing<[u8; 32]>,
        /// Authenticator output for `new_hmac_salt`. Used to derive the
        /// NEW KEK that wraps the new MVK.
        hmac_secret_for_new_wrap: Zeroizing<[u8; 32]>,
        cred_id: Vec<u8>,
        new_hmac_salt: [u8; 32],
    },
}

impl SlotCredential {
    pub fn slot_idx(&self) -> usize {
        match self {
            Self::Passphrase { slot_idx, .. } => *slot_idx,
            Self::Fido2Wrap { slot_idx, .. } => *slot_idx,
        }
    }
}

/// Compute the on-disk chunk count for a logical chunk requirement,
/// honoring the vault's `pad_files_pow2` mode.
///
/// Without padding: `needed` (1:1).
/// With padding:    next power of 2 ≥ `needed` (so 1->1, 2->2, 3->4, 5->8, ...).
///
/// 0 stays 0 (an empty file still uses 0 chunks regardless of mode).
fn padded_chunk_count(needed: usize, padding_on: bool) -> usize {
    if !padding_on || needed <= 1 {
        needed
    } else {
        needed.next_power_of_two()
    }
}

/// 8 bytes at the start of chunk 0's plaintext when `FLAG_HIDE_SIZE_HEADER`
/// is set: u64 LE of the file's real byte length.
const SIZE_HEADER_LEN: usize = 8;

/// Number of chunks needed to hold a file of `real_size` bytes, accounting
/// for the chunk-0 size-header in `hide_size` mode.
///
/// Returns `usize::MAX` if the (already-bounded) addition somehow
/// overflows; callers above (`read`/`write`) reject offset overflow
/// before reaching this helper, so this saturating fallback is purely
/// defense-in-depth.
fn required_chunks(real_size: u64, hide_size: bool) -> usize {
    if real_size == 0 {
        return 0;
    }
    let with_header = if hide_size {
        real_size.saturating_add(SIZE_HEADER_LEN as u64)
    } else {
        real_size
    };
    ((with_header - 1) / CHUNK_PLAINTEXT_SIZE as u64 + 1) as usize
}

/// Translate a file-relative byte offset to `(chunk_idx, in_chunk_offset)`.
/// In `hide_size` mode, file byte 0 lives at chunk 0 byte 8.
fn file_to_chunk(offset: u64, hide_size: bool) -> Result<(usize, usize), Error> {
    let total = if hide_size {
        offset
            .checked_add(SIZE_HEADER_LEN as u64)
            .ok_or(Error::OffsetOverflow)?
    } else {
        offset
    };
    let chunk_idx = (total / CHUNK_PLAINTEXT_SIZE as u64) as usize;
    let in_chunk = (total % CHUNK_PLAINTEXT_SIZE as u64) as usize;
    Ok((chunk_idx, in_chunk))
}

/// File-byte range (start..end) that a given chunk holds, accounting for
/// the chunk-0 header in hide-size mode.
fn chunk_file_range(chunk_idx: usize, hide_size: bool) -> Result<(u64, u64), Error> {
    let chunk_size = CHUNK_PLAINTEXT_SIZE as u64;
    if hide_size && chunk_idx == 0 {
        // Chunk 0: file bytes 0..(4096-8) = 0..4088
        Ok((0, chunk_size - SIZE_HEADER_LEN as u64))
    } else if hide_size {
        // Chunk i>0: file bytes (4088 + (i-1)*4096) .. (4088 + i*4096)
        let start = (chunk_size - SIZE_HEADER_LEN as u64)
            .checked_add(
                (chunk_idx as u64)
                    .checked_sub(1)
                    .and_then(|i| i.checked_mul(chunk_size))
                    .ok_or(Error::OffsetOverflow)?,
            )
            .ok_or(Error::OffsetOverflow)?;
        let end = start.checked_add(chunk_size).ok_or(Error::OffsetOverflow)?;
        Ok((start, end))
    } else {
        // Normal mode: chunk i covers file bytes [i*4096, (i+1)*4096)
        let start = (chunk_idx as u64)
            .checked_mul(chunk_size)
            .ok_or(Error::OffsetOverflow)?;
        let end = start.checked_add(chunk_size).ok_or(Error::OffsetOverflow)?;
        Ok((start, end))
    }
}

/// Write the 8-byte u64 LE size header at the start of a chunk-0 plaintext
/// buffer.
fn install_size_header(buf: &mut [u8], size: u64) {
    buf[..SIZE_HEADER_LEN].copy_from_slice(&size.to_le_bytes());
}

#[derive(Debug, Clone)]
pub struct Stat {
    pub id: FileId,
    pub kind: InodeKind,
    pub size: u64,
    pub mtime_ns: u64,
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub id: FileId,
    pub kind: InodeKind,
}

/// Vault-wide tree counters. Surfaced for forensic tooling
/// (`header dump` JSON output).
#[derive(Debug, Clone, Copy)]
pub struct TreeCounters {
    /// Next chunk_id to be allocated for a fresh write.
    pub next_chunk_id: u64,
    /// Next chunk-generation counter (monotonic, used in chunk AAD
    /// for replay protection).
    pub next_chunk_gen: u64,
    /// Next file_id to be allocated.
    pub next_file_id: u64,
    /// Number of chunk_ids on the LIFO free-list (freed and reusable).
    pub free_chunk_count: u64,
}

/// Decoder cap: 64 MiB. Above any realistic legitimate metadata blob
/// (about 600 K files with average path lengths), well below "OOM the
/// user's machine". Enforced at the Vfs layer BEFORE handing to
/// postcard so the deserializer doesn't even start on a hostile-
/// length payload.
const METADATA_DECODE_LIMIT_BYTES: usize = 64 * 1024 * 1024;

/// 4-byte magic + 1-byte version = "LBM\x02", required prefix on
/// every metadata blob. The version byte allows future format
/// extensions: a future `LBM\x03` reader would dispatch to a v3
/// decoder, with v2 readers refusing the unknown version cleanly
/// rather than silently mis-decoding.
const METADATA_V2_MAGIC: &[u8; 4] = b"LBM\x02";

fn invalid_metadata<T>() -> Result<T, Error> {
    Err(Error::MetadataDeserialize)
}

/// Validate the authenticated metadata tree before any VFS operation trusts
/// it. The AEAD says "this came from someone with the MVK"; these checks say
/// "it is also structurally sane and cannot drive offset/id wraparound."
fn validate_metadata_tree(
    tree: &DirectoryTree,
    data_offset: u64,
    hide_size: bool,
) -> Result<(), Error> {
    if tree.root != ROOT_ID
        || tree.next_file_id <= ROOT_ID
        || tree.next_file_id == u64::MAX
        || tree.next_chunk_gen == 0
        || tree.next_chunk_gen == u64::MAX
        || chunk::slot_offset(data_offset, tree.next_chunk_id).is_err()
    {
        return invalid_metadata();
    }

    let root = tree
        .inodes
        .get(&ROOT_ID)
        .ok_or(Error::MetadataDeserialize)?;
    if root.id != ROOT_ID || root.parent != ROOT_ID || root.kind != InodeKind::Directory {
        return invalid_metadata();
    }

    let mut referenced_inodes = BTreeSet::new();
    let mut live_chunks = BTreeSet::new();

    for (&id, inode) in &tree.inodes {
        if inode.id != id || id >= tree.next_file_id {
            return invalid_metadata();
        }
        if id != ROOT_ID {
            let parent = tree
                .inodes
                .get(&inode.parent)
                .ok_or(Error::MetadataDeserialize)?;
            if parent.kind != InodeKind::Directory {
                return invalid_metadata();
            }
        }

        match inode.kind {
            InodeKind::Directory => {
                if inode.size != 0 || !inode.chunks.is_empty() {
                    return invalid_metadata();
                }
                for (name, &child_id) in &inode.children {
                    if validate_name(name).is_err() || child_id == ROOT_ID {
                        return invalid_metadata();
                    }
                    let child = tree
                        .inodes
                        .get(&child_id)
                        .ok_or(Error::MetadataDeserialize)?;
                    if child.parent != id || !referenced_inodes.insert(child_id) {
                        return invalid_metadata();
                    }
                }
            }
            InodeKind::File => {
                if !inode.children.is_empty() {
                    return invalid_metadata();
                }
                if hide_size {
                    let expected_capacity = (inode.chunks.len() as u64)
                        .checked_mul(CHUNK_PLAINTEXT_SIZE as u64)
                        .ok_or(Error::MetadataDeserialize)?;
                    if inode.size != expected_capacity {
                        return invalid_metadata();
                    }
                } else if inode.chunks.len() < required_chunks(inode.size, false) {
                    return invalid_metadata();
                }
                for chunk_ref in &inode.chunks {
                    if chunk_ref.id >= tree.next_chunk_id
                        || chunk_ref.generation == 0
                        || chunk_ref.generation >= tree.next_chunk_gen
                        || chunk::slot_offset(data_offset, chunk_ref.id).is_err()
                        || !live_chunks.insert(chunk_ref.id)
                    {
                        return invalid_metadata();
                    }
                }
            }
        }
    }

    for &id in tree.inodes.keys() {
        if id != ROOT_ID && !referenced_inodes.contains(&id) {
            return invalid_metadata();
        }
    }

    let mut free_chunks = BTreeSet::new();
    for &id in &tree.free_chunks {
        if id >= tree.next_chunk_id
            || live_chunks.contains(&id)
            || chunk::slot_offset(data_offset, id).is_err()
            || !free_chunks.insert(id)
        {
            return invalid_metadata();
        }
    }

    Ok(())
}

/// Encrypted VFS atop a `Container`. Buffers the directory tree in memory and
/// writes it back to the metadata blob on `flush` / `close` / drop.
pub struct Vfs {
    container: Container,
    tree: DirectoryTree,
    dirty: bool,
}

impl Vfs {
    /// Open a Vfs over an already-unlocked container. If the metadata blob is
    /// empty (freshly created container), initializes a fresh tree.
    pub fn open(mut container: Container) -> Result<Self, Error> {
        let blob = container.read_metadata()?;
        let tree = if blob.is_empty() {
            DirectoryTree::new()
        } else {
            // Every metadata blob MUST start with the v2 magic.
            // LUKSbox is unreleased, no legacy v1 (bincode) format
            // exists in the wild, so the magic is required, not
            // optional. A future v3 reader would dispatch on the
            // version byte (`magic[3]`); for now only v2 is accepted.
            if blob.len() < METADATA_V2_MAGIC.len()
                || &blob[..METADATA_V2_MAGIC.len()] != METADATA_V2_MAGIC
            {
                return Err(Error::MetadataDeserialize);
            }
            let payload = &blob[METADATA_V2_MAGIC.len()..];
            if payload.len() > METADATA_DECODE_LIMIT_BYTES {
                return Err(Error::MetadataDeserialize);
            }
            postcard::from_bytes::<DirectoryTree>(payload)
                .map_err(|_| Error::MetadataDeserialize)?
        };
        validate_metadata_tree(
            &tree,
            container.data_offset(),
            container.header.hide_size_header(),
        )?;
        Ok(Self {
            container,
            tree,
            dirty: false,
        })
    }

    pub fn flush(&mut self) -> Result<(), Error> {
        if !self.dirty {
            return Ok(());
        }
        validate_metadata_tree(
            &self.tree,
            self.container.data_offset(),
            self.container.header.hide_size_header(),
        )?;
        // Always write v2 (postcard) for new persists. Reading remains
        // bicompatible (legacy v1 bincode blobs still open via the
        // fall-through in `Vfs::open`). Buffer layout: 4-byte magic
        // ‖ postcard payload.
        let payload = postcard::to_allocvec(&self.tree).map_err(|_| Error::MetadataSerialize)?;
        if payload.len() > METADATA_DECODE_LIMIT_BYTES {
            return Err(Error::MetadataSerialize);
        }
        let mut bytes = Vec::with_capacity(METADATA_V2_MAGIC.len() + payload.len());
        bytes.extend_from_slice(METADATA_V2_MAGIC);
        bytes.extend_from_slice(&payload);
        self.container.write_metadata(&bytes)?;
        // If the container has an anchor sidecar configured, push the
        // current vault generation to it so a future open can detect
        // rollback via `anchor::compare`.
        self.container.write_anchor(self.tree.next_chunk_gen)?;
        self.dirty = false;
        Ok(())
    }

    /// Current monotonic vault-generation counter. Compare with an
    /// anchor file's generation via `luksbox_format::anchor::compare`
    /// to detect rollback.
    pub fn vault_generation(&self) -> u64 {
        self.tree.next_chunk_gen
    }

    pub fn close(mut self) -> Result<Container, Error> {
        self.flush()?;
        Ok(self.container)
    }

    /// Read-only access to the underlying `Container`. Useful for callers
    /// that want to inspect header / keyslot state without taking the
    /// container apart.
    pub fn container(&self) -> &Container {
        &self.container
    }

    /// Mutable access to the underlying `Container`. Used by callers that
    /// need to enroll/revoke keyslots or call `persist_header`. Don't
    /// move chunks around through this, use the Vfs API for that.
    pub fn container_mut(&mut self) -> &mut Container {
        &mut self.container
    }

    pub fn root_id(&self) -> FileId {
        self.tree.root
    }

    pub fn parent_of(&self, id: FileId) -> Result<FileId, Error> {
        Ok(self.tree.inodes.get(&id).ok_or(Error::NotFound)?.parent)
    }

    pub fn stat(&mut self, id: FileId) -> Result<Stat, Error> {
        let real_size = self.real_size(id)?;
        let inode = self.tree.inodes.get(&id).ok_or(Error::NotFound)?;
        Ok(Stat {
            id: inode.id,
            kind: inode.kind,
            size: real_size,
            mtime_ns: inode.mtime_ns,
        })
    }

    /// Per-file ordered chunk references. Returned as a freshly-allocated
    /// `Vec` so the caller can iterate without holding a `&self` borrow
    /// (the chunk decrypt path needs `&mut Container`). Used by the
    /// forensic-only CLI surfaces (`check`, `extract --tolerate-errors`,
    /// `header dump`) to walk a file's chunks at the format level.
    pub fn file_chunks(&self, id: FileId) -> Result<Vec<crate::tree::ChunkRef>, Error> {
        let inode = self.tree.inodes.get(&id).ok_or(Error::NotFound)?;
        if inode.kind != InodeKind::File {
            return Err(Error::NotAFile);
        }
        Ok(inode.chunks.clone())
    }

    /// All FileIds in the tree (BFS order from root). For forensic
    /// dumps that need to enumerate every inode without recursing
    /// through `readdir` themselves.
    pub fn all_file_ids(&self) -> Vec<FileId> {
        self.tree.inodes.keys().copied().collect()
    }

    /// Inode kind without going through `stat` (avoids the
    /// hide-size chunk decrypt that `stat` performs for files).
    pub fn inode_kind(&self, id: FileId) -> Result<InodeKind, Error> {
        Ok(self.tree.inodes.get(&id).ok_or(Error::NotFound)?.kind)
    }

    /// Stored (non-real) size. In hide-size mode this is the padded
    /// chunk capacity; the real size is in chunk 0. Used by forensic
    /// surfaces that want the raw value without triggering a chunk
    /// decrypt.
    pub fn inode_size_raw(&self, id: FileId) -> Result<u64, Error> {
        Ok(self.tree.inodes.get(&id).ok_or(Error::NotFound)?.size)
    }

    /// Counts of allocated/free chunks across the whole vault, plus
    /// the next-id and next-generation counters. Used by `header dump`
    /// to surface tree-level state for forensics.
    pub fn tree_counters(&self) -> TreeCounters {
        TreeCounters {
            next_chunk_id: self.tree.next_chunk_id,
            next_chunk_gen: self.tree.next_chunk_gen,
            next_file_id: self.tree.next_file_id,
            free_chunk_count: self.tree.free_chunks.len() as u64,
        }
    }

    /// Get the real (logical) byte length of a file, decoding the chunk-0
    /// header in `FLAG_HIDE_SIZE_HEADER` mode (cached after first lookup).
    /// In normal mode this is just `inode.size`.
    fn real_size(&mut self, id: FileId) -> Result<u64, Error> {
        let inode = self.tree.inodes.get(&id).ok_or(Error::NotFound)?;
        if inode.kind != InodeKind::File {
            // Directories etc. have size = 0 in our model; stat returns 0.
            return Ok(0);
        }
        let hide_size = self.container.header.hide_size_header();
        if !hide_size {
            return Ok(inode.size);
        }
        if let Some(s) = inode.cached_real_size {
            return Ok(s);
        }
        if inode.chunks.is_empty() {
            // Empty file in hide-size mode: no chunk to decrypt.
            self.tree.inodes.get_mut(&id).unwrap().cached_real_size = Some(0);
            return Ok(0);
        }
        // Decrypt chunk 0 to extract the size header.
        let chunk0 = inode.chunks[0];
        let key = chunk::file_key(&self.container, id);
        let pt = chunk::read_chunk(&mut self.container, &key, id, 0, chunk0)?;
        let mut size_buf = [0u8; SIZE_HEADER_LEN];
        size_buf.copy_from_slice(&pt[..SIZE_HEADER_LEN]);
        let size = u64::from_le_bytes(size_buf);
        self.tree.inodes.get_mut(&id).unwrap().cached_real_size = Some(size);
        Ok(size)
    }

    pub fn readdir(&self, id: FileId) -> Result<Vec<DirEntry>, Error> {
        let inode = self.require_dir(id)?;
        Ok(inode
            .children
            .iter()
            .map(|(name, &child_id)| {
                let kind = self
                    .tree
                    .inodes
                    .get(&child_id)
                    .map(|i| i.kind)
                    .unwrap_or(InodeKind::File);
                DirEntry {
                    name: name.clone(),
                    id: child_id,
                    kind,
                }
            })
            .collect())
    }

    pub fn lookup(&self, parent: FileId, name: &str) -> Result<FileId, Error> {
        let inode = self.require_dir(parent)?;
        inode.children.get(name).copied().ok_or(Error::NotFound)
    }

    pub fn lookup_path(&self, path: &str) -> Result<FileId, Error> {
        let mut cur = self.tree.root;
        for seg in path.split('/').filter(|s| !s.is_empty()) {
            cur = self.lookup(cur, seg)?;
        }
        Ok(cur)
    }

    pub fn mkdir(&mut self, parent: FileId, name: &str) -> Result<FileId, Error> {
        validate_name(name)?;
        self.require_dir(parent)?;
        if self.tree.inodes[&parent].children.contains_key(name) {
            return Err(Error::AlreadyExists);
        }
        let id = self.tree.alloc_file_id().ok_or(Error::IdSpaceExhausted)?;
        self.tree.inodes.insert(
            id,
            Inode {
                id,
                parent,
                kind: InodeKind::Directory,
                size: 0,
                mtime_ns: 0,
                chunks: Vec::new(),
                children: Default::default(),
                cached_real_size: None,
            },
        );
        self.tree
            .inodes
            .get_mut(&parent)
            .unwrap()
            .children
            .insert(name.to_string(), id);
        self.dirty = true;
        Ok(id)
    }

    pub fn create(&mut self, parent: FileId, name: &str) -> Result<FileId, Error> {
        validate_name(name)?;
        self.require_dir(parent)?;
        if self.tree.inodes[&parent].children.contains_key(name) {
            return Err(Error::AlreadyExists);
        }
        let id = self.tree.alloc_file_id().ok_or(Error::IdSpaceExhausted)?;
        self.tree.inodes.insert(
            id,
            Inode {
                id,
                parent,
                kind: InodeKind::File,
                size: 0,
                mtime_ns: 0,
                chunks: Vec::new(),
                children: Default::default(),
                cached_real_size: None,
            },
        );
        self.tree
            .inodes
            .get_mut(&parent)
            .unwrap()
            .children
            .insert(name.to_string(), id);
        self.dirty = true;
        Ok(id)
    }

    pub fn read(&mut self, id: FileId, offset: u64, buf: &mut [u8]) -> Result<usize, Error> {
        let real = self.real_size(id)?;
        let inode = self.tree.inodes.get(&id).ok_or(Error::NotFound)?.clone();
        if inode.kind != InodeKind::File {
            return Err(Error::NotAFile);
        }
        if offset >= real || buf.is_empty() {
            return Ok(0);
        }
        // checked_add guards against an attacker-supplied offset close
        // to u64::MAX. The .min(real) below would otherwise be reached
        // via wrapping arithmetic in release builds.
        let requested_end = offset
            .checked_add(buf.len() as u64)
            .ok_or(Error::OffsetOverflow)?;
        let read_end = requested_end.min(real);
        let read_len = (read_end - offset) as usize;
        let hide_size = self.container.header.hide_size_header();
        let (first_chunk, _) = file_to_chunk(offset, hide_size)?;
        let (last_chunk, _) = file_to_chunk(read_end - 1, hide_size)?;

        let key = chunk::file_key(&self.container, id);
        let mut buf_pos = 0usize;
        for chunk_idx in first_chunk..=last_chunk {
            // Compute the chunk's file-byte coverage.
            let (chunk_file_start, chunk_file_end) = chunk_file_range(chunk_idx, hide_size)?;
            let in_chunk_offset = offset
                .max(chunk_file_start)
                .saturating_sub(chunk_file_start);
            let in_chunk_end = read_end
                .min(chunk_file_end)
                .saturating_sub(chunk_file_start);
            let len_here = (in_chunk_end - in_chunk_offset) as usize;
            let chunk_data_start = if hide_size && chunk_idx == 0 {
                SIZE_HEADER_LEN
            } else {
                0
            };
            let read_start_in_chunk = chunk_data_start + in_chunk_offset as usize;
            let read_end_in_chunk = chunk_data_start + in_chunk_end as usize;

            let pt = chunk::read_chunk(
                &mut self.container,
                &key,
                id,
                chunk_idx as u32,
                inode.chunks[chunk_idx],
            )?;
            buf[buf_pos..buf_pos + len_here]
                .copy_from_slice(&pt[read_start_in_chunk..read_end_in_chunk]);
            buf_pos += len_here;
        }
        Ok(read_len)
    }

    pub fn write(&mut self, id: FileId, offset: u64, buf: &[u8]) -> Result<usize, Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        let old_real = self.real_size(id)?;
        let inode = self.tree.inodes.get(&id).ok_or(Error::NotFound)?.clone();
        if inode.kind != InodeKind::File {
            return Err(Error::NotAFile);
        }
        // Same overflow guard as `read`. Without checked_add, a
        // malicious or buggy caller could wrap `new_end` and we'd
        // truncate the file rather than refuse the write.
        let new_end = offset
            .checked_add(buf.len() as u64)
            .ok_or(Error::OffsetOverflow)?;
        let new_real = old_real.max(new_end);

        let hide_size = self.container.header.hide_size_header();
        let padding_on = self.container.header.pad_files_pow2();
        let target_count = padded_chunk_count(required_chunks(new_real, hide_size), padding_on);

        let (first_chunk, _) = file_to_chunk(offset, hide_size)?;
        let (last_chunk, _) = file_to_chunk(new_end - 1, hide_size)?;

        let key = chunk::file_key(&self.container, id);
        let mut chunks = inode.chunks.clone();

        // Allocate any missing chunks up to target_count as zero-filled.
        // Covers file extension, sparse holes (write past EOF), and
        // pow2 padding. In hide-size mode, the new chunk 0 (if just
        // allocated) gets its size header set below.
        let zero = vec![0u8; CHUNK_PLAINTEXT_SIZE];
        while chunks.len() < target_count {
            let cref = ChunkRef {
                id: self.tree.alloc_chunk_id().ok_or(Error::IdSpaceExhausted)?,
                generation: self.tree.alloc_chunk_gen().ok_or(Error::IdSpaceExhausted)?,
            };
            let chunk_idx = chunks.len() as u32;
            chunk::write_chunk(&mut self.container, &key, id, chunk_idx, cref, &zero)?;
            chunks.push(cref);
        }

        // Read-modify-write over the covered range. Each rewrite gets a
        // fresh generation counter (replay protection).
        let mut buf_pos = 0usize;
        for chunk_idx in first_chunk..=last_chunk {
            let (chunk_file_start, chunk_file_end) = chunk_file_range(chunk_idx, hide_size)?;
            let in_chunk_offset = offset
                .max(chunk_file_start)
                .saturating_sub(chunk_file_start);
            let in_chunk_end = new_end.min(chunk_file_end).saturating_sub(chunk_file_start);
            let len_here = (in_chunk_end - in_chunk_offset) as usize;
            let data_start = if hide_size && chunk_idx == 0 {
                SIZE_HEADER_LEN
            } else {
                0
            };
            let pt_start = data_start + in_chunk_offset as usize;
            let pt_end = data_start + in_chunk_end as usize;

            let mut pt = chunk::read_chunk(
                &mut self.container,
                &key,
                id,
                chunk_idx as u32,
                chunks[chunk_idx],
            )?;
            pt[pt_start..pt_end].copy_from_slice(&buf[buf_pos..buf_pos + len_here]);
            // If this is chunk 0 in hide-size mode, refresh the size header
            // (the write may have grown the file).
            if hide_size && chunk_idx == 0 {
                install_size_header(&mut pt, new_real);
            }
            // Bump generation before re-writing.
            chunks[chunk_idx].generation =
                self.tree.alloc_chunk_gen().ok_or(Error::IdSpaceExhausted)?;
            chunk::write_chunk(
                &mut self.container,
                &key,
                id,
                chunk_idx as u32,
                chunks[chunk_idx],
                &pt,
            )?;
            buf_pos += len_here;
        }

        // If hide-size and chunk 0 wasn't in the rewritten range but the
        // file grew, refresh chunk 0's size header.
        if hide_size && new_real != old_real && first_chunk > 0 && !chunks.is_empty() {
            let mut pt = chunk::read_chunk(&mut self.container, &key, id, 0, chunks[0])?;
            install_size_header(&mut pt, new_real);
            chunks[0].generation = self.tree.alloc_chunk_gen().ok_or(Error::IdSpaceExhausted)?;
            chunk::write_chunk(&mut self.container, &key, id, 0, chunks[0], &pt)?;
        }

        // Persist updated inode metadata. In hide-size mode, inode.size is
        // padded chunk capacity (not real size); cached_real_size carries
        // the truth for in-memory stat hits.
        let inode_size_field = if hide_size {
            chunks.len() as u64 * CHUNK_PLAINTEXT_SIZE as u64
        } else {
            new_real
        };
        let inode_mut = self.tree.inodes.get_mut(&id).unwrap();
        inode_mut.chunks = chunks;
        inode_mut.size = inode_size_field;
        if hide_size {
            inode_mut.cached_real_size = Some(new_real);
        }
        self.dirty = true;
        Ok(buf.len())
    }

    pub fn truncate(&mut self, id: FileId, new_size: u64) -> Result<(), Error> {
        let inode = self.tree.inodes.get(&id).ok_or(Error::NotFound)?.clone();
        if inode.kind != InodeKind::File {
            return Err(Error::NotAFile);
        }
        let hide_size = self.container.header.hide_size_header();
        let padding_on = self.container.header.pad_files_pow2();
        let needed = required_chunks(new_size, hide_size);
        let new_chunk_count = padded_chunk_count(needed, padding_on);

        let key = chunk::file_key(&self.container, id);
        let mut chunks = inode.chunks.clone();

        while chunks.len() > new_chunk_count {
            let cref = chunks.pop().unwrap();
            self.tree.free_chunk_id(cref.id);
        }

        let zero = vec![0u8; CHUNK_PLAINTEXT_SIZE];
        while chunks.len() < new_chunk_count {
            let cref = ChunkRef {
                id: self.tree.alloc_chunk_id().ok_or(Error::IdSpaceExhausted)?,
                generation: self.tree.alloc_chunk_gen().ok_or(Error::IdSpaceExhausted)?,
            };
            let chunk_idx = chunks.len() as u32;
            chunk::write_chunk(&mut self.container, &key, id, chunk_idx, cref, &zero)?;
            chunks.push(cref);
        }

        // In hide-size mode, refresh the chunk-0 size header.
        if hide_size && !chunks.is_empty() {
            let mut pt = chunk::read_chunk(&mut self.container, &key, id, 0, chunks[0])?;
            install_size_header(&mut pt, new_size);
            chunks[0].generation = self.tree.alloc_chunk_gen().ok_or(Error::IdSpaceExhausted)?;
            chunk::write_chunk(&mut self.container, &key, id, 0, chunks[0], &pt)?;
        }

        let inode_size_field = if hide_size {
            chunks.len() as u64 * CHUNK_PLAINTEXT_SIZE as u64
        } else {
            new_size
        };
        let inode_mut = self.tree.inodes.get_mut(&id).unwrap();
        inode_mut.chunks = chunks;
        inode_mut.size = inode_size_field;
        if hide_size {
            inode_mut.cached_real_size = Some(new_size);
        }
        self.dirty = true;
        Ok(())
    }

    pub fn unlink(&mut self, parent: FileId, name: &str) -> Result<(), Error> {
        let parent_inode = self.require_dir(parent)?;
        let target_id = *parent_inode.children.get(name).ok_or(Error::NotFound)?;
        let target = self.tree.inodes.get(&target_id).unwrap();
        if target.kind != InodeKind::File {
            return Err(Error::IsADirectory);
        }
        let chunks = target.chunks.clone();
        for cref in chunks {
            self.tree.free_chunk_id(cref.id);
        }
        self.tree.inodes.remove(&target_id);
        self.tree
            .inodes
            .get_mut(&parent)
            .unwrap()
            .children
            .remove(name);
        self.dirty = true;
        Ok(())
    }

    pub fn rmdir(&mut self, parent: FileId, name: &str) -> Result<(), Error> {
        let parent_inode = self.require_dir(parent)?;
        let target_id = *parent_inode.children.get(name).ok_or(Error::NotFound)?;
        let target = self.tree.inodes.get(&target_id).unwrap();
        if target.kind != InodeKind::Directory {
            return Err(Error::NotADirectory);
        }
        if !target.children.is_empty() {
            return Err(Error::NotEmpty);
        }
        self.tree.inodes.remove(&target_id);
        self.tree
            .inodes
            .get_mut(&parent)
            .unwrap()
            .children
            .remove(name);
        self.dirty = true;
        Ok(())
    }

    /// Within-directory rename. Cross-directory rename is intentionally not in v1.
    pub fn rename(&mut self, parent: FileId, old_name: &str, new_name: &str) -> Result<(), Error> {
        validate_name(new_name)?;
        let dir = self.tree.inodes.get_mut(&parent).ok_or(Error::NotFound)?;
        if dir.kind != InodeKind::Directory {
            return Err(Error::NotADirectory);
        }
        if dir.children.contains_key(new_name) {
            return Err(Error::AlreadyExists);
        }
        let id = dir.children.remove(old_name).ok_or(Error::NotFound)?;
        dir.children.insert(new_name.to_string(), id);
        self.dirty = true;
        Ok(())
    }

    /// MVK rotation. Re-encrypts every chunk with new MVK-derived file_keys,
    /// re-encrypts the metadata blob with the new MVK-derived metadata_key,
    /// and rebuilds every populated keyslot under fresh random salts, each
    /// slot's user-secret (passphrase, hmac_secret) is preserved but the
    /// wrapped MVK and the AEAD nonce/salt all rotate.
    ///
    /// `credentials` must cover every populated keyslot in the vault. Each
    /// is verified by re-deriving its old KEK and confirming it unlocks the
    /// existing slot to the same MVK currently held by the container; if
    /// any verification fails, no on-disk changes are made.
    ///
    /// **Limitations**:
    /// - Vaults containing a `Fido2DerivedMvk` slot can't be rotated (the
    ///   MVK is YubiKey-derived; rotating it invalidates that derivation).
    /// - **Crash-safety**: inline-header vaults rotate atomically, all
    ///   re-encrypted bytes go to a `<vault>.rotating` temp file that is
    ///   `fsync`'d and atomically renamed over the original at commit.
    ///   A crash before commit leaves the original vault intact; after
    ///   commit, the new vault is durably in place. Detached-header mode
    ///   is NOT yet crash-safe (would need a 2-file commit protocol);
    ///   the rotation runs in-place with a warning. Back up the sidecar
    ///   header before rotating in detached mode.
    pub fn rotate_mvk(
        &mut self,
        credentials: Vec<SlotCredential>,
        kdf_params: luksbox_core::Argon2idParams,
    ) -> Result<(), Error> {
        use luksbox_core::{MasterVolumeKey, SlotKind};

        // Reject any fido2-direct slots upfront.
        for slot in &self.container.header.keyslots {
            if slot.kind == SlotKind::Fido2DerivedMvk {
                return Err(Error::Format(luksbox_format::Error::Crypto(
                    luksbox_core::Error::InvalidField,
                )));
            }
        }

        // Verify the credential set covers every populated slot exactly once.
        let populated: std::collections::BTreeSet<usize> = (0..luksbox_core::MAX_KEYSLOTS)
            .filter(|&i| self.container.header.keyslots[i].kind != SlotKind::Empty)
            .collect();
        let supplied: std::collections::BTreeSet<usize> =
            credentials.iter().map(|c| c.slot_idx()).collect();
        if populated != supplied {
            return Err(Error::Format(luksbox_format::Error::Crypto(
                luksbox_core::Error::InvalidField,
            )));
        }

        // Verify each credential unlocks its slot to the SAME MVK currently
        // held by the container. This is the safety net, if any cred is
        // wrong (typoed passphrase, wrong YubiKey), we abort before
        // touching any chunk.
        let header_salt = *self.container.header_salt();
        let suite = self.container.cipher_suite();
        let current_mvk = self.container.mvk_clone();
        for cred in &credentials {
            let slot = &self.container.header.keyslots[cred.slot_idx()];
            let derived = match cred {
                SlotCredential::Passphrase { passphrase, .. } => {
                    slot.unlock_passphrase(suite, passphrase.as_bytes(), &header_salt)
                }
                SlotCredential::Fido2Wrap {
                    passphrase,
                    hmac_secret_for_verify,
                    ..
                } => slot.unlock_fido2(
                    suite,
                    passphrase.as_ref().map(|p| p.as_bytes()),
                    &*hmac_secret_for_verify,
                    &header_salt,
                ),
            }
            .map_err(|e| Error::Format(luksbox_format::Error::Crypto(e)))?;
            if derived.as_bytes() != current_mvk.as_bytes() {
                return Err(Error::Format(luksbox_format::Error::Crypto(
                    luksbox_core::Error::InvalidField,
                )));
            }
        }

        // All credentials verified. Generate the new MVK.
        let new_mvk = MasterVolumeKey::try_random().map_err(|e| {
            Error::Format(luksbox_format::Error::Crypto(luksbox_core::Error::OsRng(
                e.to_string(),
            )))
        })?;

        // Begin crash-safe rotation if the container supports it (inline
        // mode). All subsequent writes go to a <vault>.rotating temp
        // file; the original is untouched until commit.
        let crash_safe = self.container.supports_atomic_rotation();
        if crash_safe {
            self.container
                .begin_atomic_rotation()
                .map_err(Error::Format)?;
        } else {
            eprintln!(
                "warning: detached-header mode does not support crash-safe \
                 rotation. A crash mid-rotation may leave the vault in a \
                 broken state. Back up the header sidecar before continuing."
            );
        }

        // From here on, any error must trigger abort_atomic_rotation()
        // before returning. Wrap in a closure to centralize cleanup.
        let mut do_rotation = || -> Result<(), Error> {
            // Re-encrypt every chunk: read with old file_key, write with new.
            for (&file_id, inode) in self.tree.inodes.iter() {
                if inode.kind != InodeKind::File {
                    continue;
                }
                for (chunk_idx, chunk_ref) in inode.chunks.iter().enumerate() {
                    let old_fk = chunk::file_key_for_mvk(&current_mvk, &header_salt, file_id);
                    let new_fk = chunk::file_key_for_mvk(&new_mvk, &header_salt, file_id);
                    let mut aad = [0u8; 20];
                    aad[..8].copy_from_slice(&file_id.to_le_bytes());
                    aad[8..12].copy_from_slice(&(chunk_idx as u32).to_le_bytes());
                    aad[12..].copy_from_slice(&chunk_ref.generation.to_le_bytes());
                    self.container
                        .rekey_chunk_at(chunk_ref.id, &*old_fk, &*new_fk, &aad)?;
                }
            }

            // Re-encrypt the metadata blob with new_mvk's metadata_key.
            self.container.rekey_metadata(&new_mvk)?;

            // Build new keyslots wrapping new_mvk. Each rebuilt slot uses a
            // fresh random kdf_salt / aead_nonce / hmac_salt for forward
            // security.
            use luksbox_core::Keyslot;
            let mut new_slots: Vec<(usize, Keyslot)> = Vec::with_capacity(credentials.len());
            for cred in &credentials {
                let slot = match cred {
                    SlotCredential::Passphrase {
                        slot_idx,
                        passphrase,
                    } => {
                        let s = Keyslot::new_passphrase(
                            suite,
                            &new_mvk,
                            passphrase.as_bytes(),
                            kdf_params,
                            &header_salt,
                        )
                        .map_err(luksbox_format::Error::Crypto)?;
                        (*slot_idx, s)
                    }
                    SlotCredential::Fido2Wrap {
                        slot_idx,
                        passphrase,
                        hmac_secret_for_new_wrap,
                        cred_id,
                        new_hmac_salt,
                        ..
                    } => {
                        let s = Keyslot::new_fido2(
                            suite,
                            &new_mvk,
                            passphrase.as_ref().map(|p| p.as_bytes()),
                            &*hmac_secret_for_new_wrap,
                            cred_id,
                            *new_hmac_salt,
                            kdf_params,
                            &header_salt,
                        )
                        .map_err(luksbox_format::Error::Crypto)?;
                        (*slot_idx, s)
                    }
                };
                new_slots.push(slot);
            }

            self.container
                .install_rotated_mvk_multi(new_mvk.clone(), new_slots)
                .map_err(Error::Format)?;
            self.container.persist_header().map_err(Error::Format)?;
            Ok(())
        };

        let result = do_rotation();

        match (crash_safe, result) {
            (true, Ok(())) => {
                // Commit: fsync + atomic rename. After this returns, the
                // rotated vault is durably installed.
                self.container
                    .commit_atomic_rotation()
                    .map_err(Error::Format)?;
                Ok(())
            }
            (true, Err(e)) => {
                // Abort: discard the temp file, reopen the original. The
                // original is untouched, so the Vfs's in-memory state
                // (which still references the old MVK / chunks) remains
                // valid against the original file.
                let _ = self.container.abort_atomic_rotation();
                Err(e)
            }
            (false, r) => r,
        }
    }

    fn require_dir(&self, id: FileId) -> Result<&Inode, Error> {
        let inode = self.tree.inodes.get(&id).ok_or(Error::NotFound)?;
        if inode.kind != InodeKind::Directory {
            return Err(Error::NotADirectory);
        }
        Ok(inode)
    }
}

fn validate_name(name: &str) -> Result<(), Error> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        Err(Error::InvalidPath(name.to_string()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use luksbox_core::{Argon2idParams, CipherSuite};
    use luksbox_format::UnlockMaterial;
    use std::path::Path;
    use tempfile::tempdir;

    fn test_params() -> Argon2idParams {
        Argon2idParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn create_container(path: &Path) -> Container {
        Container::create_with_passphrase(path, None, CipherSuite::Aes256Gcm, test_params(), b"pw")
            .unwrap()
    }

    fn open_container(path: &Path) -> Container {
        Container::open(path, None, UnlockMaterial::Passphrase(b"pw")).unwrap()
    }

    fn write_raw_tree_metadata(container: &mut Container, tree: &DirectoryTree) {
        let payload = postcard::to_allocvec(tree).unwrap();
        let mut bytes = Vec::with_capacity(METADATA_V2_MAGIC.len() + payload.len());
        bytes.extend_from_slice(METADATA_V2_MAGIC);
        bytes.extend_from_slice(&payload);
        container.write_metadata(&bytes).unwrap();
    }

    #[test]
    fn empty_vfs_root_has_no_children() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let c = create_container(&path);
        let vfs = Vfs::open(c).unwrap();
        assert_eq!(vfs.readdir(vfs.root_id()).unwrap().len(), 0);
    }

    #[test]
    fn mkdir_and_readdir() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        vfs.mkdir(root, "docs").unwrap();
        vfs.mkdir(root, "src").unwrap();
        let entries = vfs.readdir(root).unwrap();
        let mut names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["docs", "src"]);
    }

    #[test]
    fn write_then_read_small_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "hello.txt").unwrap();
        let payload = b"hello world";
        let n = vfs.write(f, 0, payload).unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(vfs.stat(f).unwrap().size, payload.len() as u64);
        let mut buf = vec![0u8; payload.len()];
        let r = vfs.read(f, 0, &mut buf).unwrap();
        assert_eq!(r, payload.len());
        assert_eq!(&buf, payload);
    }

    #[test]
    fn write_multi_chunk_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "big").unwrap();
        let payload: Vec<u8> = (0..10_000).map(|i| (i % 251) as u8).collect();
        vfs.write(f, 0, &payload).unwrap();
        let mut buf = vec![0u8; payload.len()];
        vfs.read(f, 0, &mut buf).unwrap();
        assert_eq!(buf, payload);
    }

    #[test]
    fn read_past_eof_returns_short() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "x").unwrap();
        vfs.write(f, 0, b"abc").unwrap();
        let mut buf = [0u8; 100];
        let r = vfs.read(f, 0, &mut buf).unwrap();
        assert_eq!(r, 3);
        assert_eq!(&buf[..3], b"abc");
        let r2 = vfs.read(f, 100, &mut buf).unwrap();
        assert_eq!(r2, 0);
    }

    #[test]
    fn sparse_write_zero_fills_hole() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "sparse").unwrap();
        vfs.write(f, 5000, b"tail").unwrap();
        assert_eq!(vfs.stat(f).unwrap().size, 5004);
        let mut buf = vec![0u8; 5004];
        vfs.read(f, 0, &mut buf).unwrap();
        for &b in &buf[..5000] {
            assert_eq!(b, 0);
        }
        assert_eq!(&buf[5000..], b"tail");
    }

    #[test]
    fn overwrite_within_chunk() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "x").unwrap();
        vfs.write(f, 0, b"hello world").unwrap();
        vfs.write(f, 6, b"WORLD").unwrap();
        let mut buf = vec![0u8; 11];
        vfs.read(f, 0, &mut buf).unwrap();
        assert_eq!(&buf, b"hello WORLD");
    }

    #[test]
    fn truncate_shrink_frees_chunks() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "x").unwrap();
        let payload = vec![0xabu8; 20_000];
        vfs.write(f, 0, &payload).unwrap();
        let chunks_before = vfs.tree.inodes[&f].chunks.len();
        let free_before = vfs.tree.free_chunks.len();
        vfs.truncate(f, 100).unwrap();
        let chunks_after = vfs.tree.inodes[&f].chunks.len();
        let free_after = vfs.tree.free_chunks.len();
        assert!(chunks_after < chunks_before);
        assert!(free_after > free_before);
        assert_eq!(vfs.stat(f).unwrap().size, 100);
    }

    #[test]
    fn truncate_grow_zero_fills() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "x").unwrap();
        vfs.write(f, 0, b"hi").unwrap();
        vfs.truncate(f, 6000).unwrap();
        assert_eq!(vfs.stat(f).unwrap().size, 6000);
        let mut buf = vec![0u8; 6000];
        vfs.read(f, 0, &mut buf).unwrap();
        assert_eq!(&buf[..2], b"hi");
        for &b in &buf[2..] {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn unlink_frees_chunks_for_reuse() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "x").unwrap();
        vfs.write(f, 0, &vec![1u8; 8000]).unwrap();
        let next_chunk_id_before = vfs.tree.next_chunk_id;
        vfs.unlink(root, "x").unwrap();
        // create another file and write 8 KB, should reuse the freed chunks
        let g = vfs.create(root, "y").unwrap();
        vfs.write(g, 0, &vec![2u8; 8000]).unwrap();
        // next_chunk_id should not have grown (we reused freed slots)
        assert_eq!(vfs.tree.next_chunk_id, next_chunk_id_before);
    }

    #[test]
    fn rmdir_empty_ok_nonempty_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let _ = vfs.mkdir(root, "d").unwrap();
        vfs.rmdir(root, "d").unwrap();
        assert!(vfs.lookup(root, "d").is_err());

        let d = vfs.mkdir(root, "d").unwrap();
        vfs.create(d, "f").unwrap();
        let r = vfs.rmdir(root, "d");
        assert!(matches!(r, Err(Error::NotEmpty)));
    }

    #[test]
    fn persist_and_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let payload: Vec<u8> = (0..5000).map(|i| (i & 0xff) as u8).collect();

        {
            let mut vfs = Vfs::open(create_container(&path)).unwrap();
            let root = vfs.root_id();
            vfs.mkdir(root, "d").unwrap();
            let d = vfs.lookup(root, "d").unwrap();
            let f = vfs.create(d, "blob").unwrap();
            vfs.write(f, 0, &payload).unwrap();
            vfs.flush().unwrap();
        }

        let mut vfs = Vfs::open(open_container(&path)).unwrap();
        let root = vfs.root_id();
        let d = vfs.lookup(root, "d").unwrap();
        let f = vfs.lookup(d, "blob").unwrap();
        assert_eq!(vfs.stat(f).unwrap().size, payload.len() as u64);
        let mut buf = vec![0u8; payload.len()];
        vfs.read(f, 0, &mut buf).unwrap();
        assert_eq!(buf, payload);
    }

    #[test]
    fn rename_within_dir() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "old").unwrap();
        vfs.write(f, 0, b"hi").unwrap();
        vfs.rename(root, "old", "new").unwrap();
        assert!(vfs.lookup(root, "old").is_err());
        let g = vfs.lookup(root, "new").unwrap();
        assert_eq!(g, f);
    }

    #[test]
    fn rotate_mvk_multi_slot_passphrase() {
        use luksbox_format::Container;
        use zeroize::Zeroizing;
        let dir = tempdir().unwrap();
        let path = dir.path().join("rot.lbx");
        // Create vault, enroll a 2nd passphrase slot.
        let mut cont = Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            b"alpha",
        )
        .unwrap();
        cont.enroll_passphrase(b"beta", test_params()).unwrap();
        cont.persist_header().unwrap();
        // Write a multi-chunk payload.
        let payload: Vec<u8> = (0..15_000).map(|i| (i & 0xff) as u8).collect();
        let mut vfs = Vfs::open(cont).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "blob").unwrap();
        vfs.write(f, 0, &payload).unwrap();
        vfs.flush().unwrap();
        // Rotate, supplying credentials for both slots.
        let creds = vec![
            SlotCredential::Passphrase {
                slot_idx: 0,
                passphrase: Zeroizing::new("alpha".to_string()),
            },
            SlotCredential::Passphrase {
                slot_idx: 1,
                passphrase: Zeroizing::new("beta".to_string()),
            },
        ];
        vfs.rotate_mvk(creds, test_params()).unwrap();
        vfs.flush().unwrap();
        // Drop everything and re-open with each passphrase to confirm
        // both still work + data is intact.
        let _ = vfs.close().unwrap();
        for pw in [b"alpha".as_ref(), b"beta".as_ref()] {
            let cont = Container::open(&path, None, UnlockMaterial::Passphrase(pw)).unwrap();
            let mut vfs = Vfs::open(cont).unwrap();
            let f = vfs.lookup_path("/blob").unwrap();
            let mut buf = vec![0u8; payload.len()];
            vfs.read(f, 0, &mut buf).unwrap();
            assert_eq!(
                buf,
                payload,
                "after rotation: payload mismatch via {:?}",
                String::from_utf8_lossy(pw)
            );
        }
    }

    #[test]
    fn rotate_mvk_rejects_missing_slot_creds() {
        use luksbox_format::Container;
        use zeroize::Zeroizing;
        let dir = tempdir().unwrap();
        let path = dir.path().join("rot.lbx");
        let mut cont = Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            b"alpha",
        )
        .unwrap();
        cont.enroll_passphrase(b"beta", test_params()).unwrap();
        cont.persist_header().unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        // Only supply one cred when there are two populated slots.
        let creds = vec![SlotCredential::Passphrase {
            slot_idx: 0,
            passphrase: Zeroizing::new("alpha".to_string()),
        }];
        assert!(vfs.rotate_mvk(creds, test_params()).is_err());
    }

    #[test]
    fn rotate_mvk_rejects_wrong_credential() {
        use luksbox_format::Container;
        use zeroize::Zeroizing;
        let dir = tempdir().unwrap();
        let path = dir.path().join("rot.lbx");
        Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            b"alpha",
        )
        .unwrap();
        let cont = Container::open(&path, None, UnlockMaterial::Passphrase(b"alpha")).unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        // Wrong passphrase for the only slot.
        let creds = vec![SlotCredential::Passphrase {
            slot_idx: 0,
            passphrase: Zeroizing::new("WRONG".to_string()),
        }];
        assert!(vfs.rotate_mvk(creds, test_params()).is_err());
        // Vault must still be usable with the original passphrase
        // (rotation aborted before any on-disk changes). Drop the
        // first handle first, Container holds an OS-level flock
        // since the round-6 audit, so a concurrent open would
        // (correctly) be rejected.
        drop(vfs);
        let _ = Container::open(&path, None, UnlockMaterial::Passphrase(b"alpha")).unwrap();
    }

    #[test]
    fn padded_chunk_count_math() {
        assert_eq!(padded_chunk_count(0, true), 0);
        assert_eq!(padded_chunk_count(0, false), 0);
        assert_eq!(padded_chunk_count(1, true), 1);
        assert_eq!(padded_chunk_count(2, true), 2);
        assert_eq!(padded_chunk_count(3, true), 4);
        assert_eq!(padded_chunk_count(5, true), 8);
        assert_eq!(padded_chunk_count(13, true), 16);
        assert_eq!(padded_chunk_count(25, true), 32);
        assert_eq!(padded_chunk_count(33, true), 64);
        // Padding off -> 1:1.
        for n in 0..40 {
            assert_eq!(padded_chunk_count(n, false), n);
        }
    }

    #[test]
    fn hide_size_header_roundtrips_various_sizes() {
        use luksbox_format::Container;
        let dir = tempdir().unwrap();
        let path = dir.path().join("hs.lbx");
        Container::create_with_passphrase_flags(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            luksbox_core::FLAG_PAD_FILES_POW2 | luksbox_core::FLAG_HIDE_SIZE_HEADER,
            b"pw",
        )
        .unwrap();
        let cont = Container::open(&path, None, UnlockMaterial::Passphrase(b"pw")).unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        let root = vfs.root_id();

        // Various sizes including edge cases around the chunk-0 4088-byte capacity.
        for &size in &[0usize, 1, 100, 4087, 4088, 4089, 8000, 12_000, 50_000] {
            let f = vfs.create(root, &format!("f{size}")).unwrap();
            let payload: Vec<u8> = (0..size).map(|i| (i & 0xff) as u8).collect();
            if size > 0 {
                vfs.write(f, 0, &payload).unwrap();
            }
            // Stat returns real size (not padded).
            assert_eq!(vfs.stat(f).unwrap().size, size as u64);
            // Read returns payload byte-for-byte.
            let mut buf = vec![0u8; size];
            let n = vfs.read(f, 0, &mut buf).unwrap();
            assert_eq!(n, size);
            assert_eq!(buf, payload);
            // Inode.size in metadata is the PADDED chunk capacity, not the
            // real size, that's what an MVK-holder would see directly
            // without decrypting chunk 0.
            let chunk_count = vfs.tree.inodes[&f].chunks.len();
            let metadata_size = vfs.tree.inodes[&f].size;
            assert_eq!(
                metadata_size,
                chunk_count as u64 * CHUNK_PLAINTEXT_SIZE as u64,
                "inode.size should be padded chunks * 4096 (got {metadata_size})"
            );
        }
    }

    #[test]
    fn hide_size_truncate_updates_real_size() {
        use luksbox_format::Container;
        let dir = tempdir().unwrap();
        let path = dir.path().join("ht.lbx");
        Container::create_with_passphrase_flags(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            luksbox_core::FLAG_PAD_FILES_POW2 | luksbox_core::FLAG_HIDE_SIZE_HEADER,
            b"pw",
        )
        .unwrap();
        let cont = Container::open(&path, None, UnlockMaterial::Passphrase(b"pw")).unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "x").unwrap();
        vfs.write(f, 0, &vec![0xab; 12_000]).unwrap();
        assert_eq!(vfs.stat(f).unwrap().size, 12_000);
        vfs.truncate(f, 50).unwrap();
        assert_eq!(vfs.stat(f).unwrap().size, 50);
        let mut buf = vec![0u8; 50];
        vfs.read(f, 0, &mut buf).unwrap();
        assert_eq!(&buf, &vec![0xab; 50]);
        vfs.truncate(f, 0).unwrap();
        assert_eq!(vfs.stat(f).unwrap().size, 0);
        assert!(vfs.tree.inodes[&f].chunks.is_empty());
    }

    #[test]
    fn hide_size_persists_across_reopen() {
        use luksbox_format::Container;
        let dir = tempdir().unwrap();
        let path = dir.path().join("hp.lbx");
        Container::create_with_passphrase_flags(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            luksbox_core::FLAG_PAD_FILES_POW2 | luksbox_core::FLAG_HIDE_SIZE_HEADER,
            b"pw",
        )
        .unwrap();
        let payload: Vec<u8> = (0..15_000).map(|i| (i % 251) as u8).collect();
        {
            let cont = Container::open(&path, None, UnlockMaterial::Passphrase(b"pw")).unwrap();
            let mut vfs = Vfs::open(cont).unwrap();
            let root = vfs.root_id();
            let f = vfs.create(root, "blob").unwrap();
            vfs.write(f, 0, &payload).unwrap();
            vfs.flush().unwrap();
        }
        // Re-open and verify stat + read both still produce the real size.
        let cont = Container::open(&path, None, UnlockMaterial::Passphrase(b"pw")).unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        let f = vfs.lookup_path("/blob").unwrap();
        // First stat triggers a chunk-0 decrypt to populate the cache.
        assert_eq!(vfs.stat(f).unwrap().size, 15_000);
        // Second stat hits the cache.
        assert_eq!(vfs.stat(f).unwrap().size, 15_000);
        let mut buf = vec![0u8; 15_000];
        vfs.read(f, 0, &mut buf).unwrap();
        assert_eq!(buf, payload);
    }

    #[test]
    fn pad_files_pow2_inflates_chunk_vec() {
        use luksbox_format::Container;
        let dir = tempdir().unwrap();
        let path = dir.path().join("p.lbx");
        Container::create_with_passphrase_flags(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            luksbox_core::FLAG_PAD_FILES_POW2,
            b"pw",
        )
        .unwrap();
        let cont = Container::open(&path, None, UnlockMaterial::Passphrase(b"pw")).unwrap();
        let mut vfs = Vfs::open(cont).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "x").unwrap();
        // 12_000 bytes -> 3 chunks unpadded, 4 chunks padded
        let payload = vec![0xab; 12_000];
        vfs.write(f, 0, &payload).unwrap();
        // Verify chunks vec is pow2-rounded.
        assert_eq!(
            vfs.tree.inodes[&f].chunks.len(),
            4,
            "expected pow2 chunk count"
        );
        // And the file still reads back verbatim.
        let mut buf = vec![0u8; 12_000];
        vfs.read(f, 0, &mut buf).unwrap();
        assert_eq!(buf, payload);
    }

    #[test]
    fn lookup_path_traverses() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let a = vfs.mkdir(root, "a").unwrap();
        let b = vfs.mkdir(a, "b").unwrap();
        let f = vfs.create(b, "f").unwrap();
        assert_eq!(vfs.lookup_path("/a/b/f").unwrap(), f);
        assert_eq!(vfs.lookup_path("a/b/f").unwrap(), f);
    }

    // Note: there's no companion `read_rejects_offset_overflow` test
    // because `read` short-circuits on `offset >= real` before the
    // overflow guard, and we can't materialize a u64::MAX-byte file
    // to bypass that branch. The guard is still kept as
    // defense-in-depth against future refactors that might remove the
    // early-return.
    #[test]
    fn write_rejects_offset_overflow() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        let f = vfs.create(root, "x").unwrap();
        let payload = vec![0u8; 16];
        // Same overflow shape as the read test.
        let res = vfs.write(f, u64::MAX - 4, &payload);
        assert!(
            matches!(res, Err(Error::OffsetOverflow)),
            "write with overflowing offset must return OffsetOverflow, got {res:?}"
        );
    }

    #[test]
    fn malicious_metadata_with_wrapping_chunk_id_is_rejected_on_open() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut container = create_container(&path);

        let mut tree = DirectoryTree::new();
        let file_id = 2;
        tree.next_file_id = 3;
        tree.next_chunk_id = u64::MAX;
        tree.next_chunk_gen = 2;
        tree.inodes
            .get_mut(&ROOT_ID)
            .unwrap()
            .children
            .insert("x".to_string(), file_id);
        tree.inodes.insert(
            file_id,
            Inode {
                id: file_id,
                parent: ROOT_ID,
                kind: InodeKind::File,
                size: 1,
                mtime_ns: 0,
                chunks: vec![ChunkRef {
                    id: u64::MAX,
                    generation: 1,
                }],
                children: Default::default(),
                cached_real_size: None,
            },
        );
        write_raw_tree_metadata(&mut container, &tree);
        drop(container);

        let container = open_container(&path);
        let err = match Vfs::open(container) {
            Ok(_) => panic!("malicious wrapping chunk id must be rejected"),
            Err(e) => e,
        };
        assert!(matches!(err, Error::MetadataDeserialize), "{err:?}");
    }

    #[test]
    fn malformed_metadata_tree_edges_are_rejected_on_open() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut container = create_container(&path);

        let mut tree = DirectoryTree::new();
        tree.next_file_id = 43;
        tree.inodes
            .get_mut(&ROOT_ID)
            .unwrap()
            .children
            .insert("missing".to_string(), 42);
        write_raw_tree_metadata(&mut container, &tree);
        drop(container);

        let container = open_container(&path);
        let err = match Vfs::open(container) {
            Ok(_) => panic!("metadata with a missing child inode must be rejected"),
            Err(e) => e,
        };
        assert!(matches!(err, Error::MetadataDeserialize), "{err:?}");
    }

    #[test]
    fn exhausted_file_id_space_fails_cleanly() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.lbx");
        let mut vfs = Vfs::open(create_container(&path)).unwrap();
        let root = vfs.root_id();
        vfs.tree.next_file_id = u64::MAX;
        let err = vfs.create(root, "x").unwrap_err();
        assert!(matches!(err, Error::IdSpaceExhausted), "{err:?}");
    }
}
