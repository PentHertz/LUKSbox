// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub type FileId = u64;
pub type ChunkId = u64;

pub const ROOT_ID: FileId = 1;

/// High bit of `FileId` reserved for synthetic IDs that name a file's
/// **chunk-list blocks** (v3 metadata format). For a regular file
/// `file_id = F`, its chunk-list blocks live under the synthetic
/// `F | CHUNK_LIST_FILE_ID_BIT`. Used by `chunk::chunk_aad` so the
/// AEAD AAD distinguishes a chunk-list block from a data chunk
/// without changing the AAD shape.
///
/// Real file IDs are allocated sequentially from `ROOT_ID + 1`; a
/// vault would have to hold > 2⁶³ files for a real ID to land in the
/// reserved range, which is well past the format's other practical
/// limits (chunk_id space, metadata region, etc.).
pub const CHUNK_LIST_FILE_ID_BIT: FileId = 1 << 63;

/// Inode's chunk count threshold for spilling to external chunk-list
/// blocks in v3 metadata format. Files at or below this size keep
/// their `ChunkRef` list inline inside the metadata region (fast,
/// no extra reads on open); files above spill to a chain of encrypted
/// chunk-list blocks in the data area. 1024 chunks at 4 KiB ~ 4 MiB,
/// chosen so the cumulative inline cost across many small files
/// never blows the metadata region but tiny files don't pay an
/// extra-read penalty per access.
pub const V3_INLINE_CHUNK_THRESHOLD: usize = 1024;

/// Reference to a chunk slot on disk, with a monotonic per-vault generation
/// counter for replay protection. The generation is included in the
/// per-chunk AAD; an attacker who has an old encrypted chunk and tries to
/// substitute it for the current contents of the same `chunk_id` slot will
/// fail the AEAD tag because the AAD's generation no longer matches.
///
/// Caveat: this defends only against per-chunk substitution. An attacker
/// who can roll back the *entire* vault (both data area and metadata blob)
/// to a previous snapshot defeats this, the generation counter rolls
/// back too. Full replay protection requires external trusted state
/// (TPM2 NV counter, online auth server, etc.) which is out of scope.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkRef {
    pub id: ChunkId,
    pub generation: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeKind {
    File,
    Directory,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Inode {
    pub id: FileId,
    /// Parent directory's id. The root inode is its own parent (self-loop).
    /// Needed by the mount layer to resolve `..`.
    pub parent: FileId,
    pub kind: InodeKind,
    /// In normal mode: exact byte length of the file.
    /// In `FLAG_HIDE_SIZE_HEADER` mode: padded chunk capacity
    /// (`chunks.len() * 4096`); the real length is stored in chunk 0's
    /// 8-byte plaintext header.
    pub size: u64,
    pub mtime_ns: u64,
    /// Ordered list of chunk references holding this file's data, indexed
    /// by chunk position within the file. Always empty for directories.
    ///
    /// In-memory representation is ALWAYS the fully-materialized list,
    /// regardless of whether the on-disk metadata stored it inline (v2
    /// format) or as an external chain of chunk-list blocks (v3 format).
    /// The Vfs read path expands external chains into this Vec at open
    /// time; the flush path decides per inode whether to write inline
    /// or external based on `V3_INLINE_CHUNK_THRESHOLD` (v3 vaults only).
    pub chunks: Vec<ChunkRef>,
    /// Directory-only: name -> child file_id.
    pub children: BTreeMap<String, FileId>,
    /// In-memory cache of the real file size for `FLAG_HIDE_SIZE_HEADER`
    /// vaults. Skipped by serde so it doesn't leak through the metadata
    /// blob; populated lazily on first stat / read by decrypting chunk 0.
    #[serde(skip, default)]
    pub cached_real_size: Option<u64>,
    /// V3 format only: ChunkRefs of the chunk-list blocks this inode
    /// currently owns in the data area. Populated by the v3 read path
    /// when expanding an External chain into `chunks`; updated by the
    /// v3 flush path when re-writing the chain; consumed by `unlink`
    /// to free the blocks. Always empty for v2-format vaults and for
    /// v3 inodes that fit inline. Serde-skipped: it's bookkeeping for
    /// the in-memory representation, not part of either on-disk shape.
    #[serde(skip, default)]
    pub external_list_blocks: Vec<ChunkRef>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DirectoryTree {
    pub root: FileId,
    pub next_file_id: FileId,
    pub next_chunk_id: ChunkId,
    /// Monotonic per-vault counter, allocated to each chunk write as its
    /// generation tag. Goes into chunk AAD for replay protection.
    pub next_chunk_gen: u64,
    /// LIFO free-list of chunk_ids that have been freed and may be reused.
    /// Each (re-)write picks a fresh random nonce AND a fresh generation
    /// counter so reuse is safe and replay-protected.
    pub free_chunks: Vec<ChunkId>,
    pub inodes: BTreeMap<FileId, Inode>,
}

impl DirectoryTree {
    pub fn new() -> Self {
        let mut inodes = BTreeMap::new();
        inodes.insert(
            ROOT_ID,
            Inode {
                id: ROOT_ID,
                parent: ROOT_ID,
                kind: InodeKind::Directory,
                size: 0,
                mtime_ns: 0,
                chunks: Vec::new(),
                children: BTreeMap::new(),
                cached_real_size: None,
                external_list_blocks: Vec::new(),
            },
        );
        Self {
            root: ROOT_ID,
            next_file_id: ROOT_ID + 1,
            next_chunk_id: 0,
            next_chunk_gen: 1,
            free_chunks: Vec::new(),
            inodes,
        }
    }

    /// Allocate the next per-vault generation counter for a chunk write.
    pub fn alloc_chunk_gen(&mut self) -> Option<u64> {
        let g = self.next_chunk_gen;
        self.next_chunk_gen = self.next_chunk_gen.checked_add(1)?;
        Some(g)
    }

    pub fn alloc_file_id(&mut self) -> Option<FileId> {
        let id = self.next_file_id;
        self.next_file_id = self.next_file_id.checked_add(1)?;
        Some(id)
    }

    pub fn alloc_chunk_id(&mut self) -> Option<ChunkId> {
        if let Some(id) = self.free_chunks.pop() {
            Some(id)
        } else {
            let id = self.next_chunk_id;
            self.next_chunk_id = self.next_chunk_id.checked_add(1)?;
            Some(id)
        }
    }

    pub fn free_chunk_id(&mut self, id: ChunkId) {
        self.free_chunks.push(id);
    }
}

impl Default for DirectoryTree {
    fn default() -> Self {
        Self::new()
    }
}
