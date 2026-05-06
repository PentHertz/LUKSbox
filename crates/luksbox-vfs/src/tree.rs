// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub type FileId = u64;
pub type ChunkId = u64;

pub const ROOT_ID: FileId = 1;

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
    pub chunks: Vec<ChunkRef>,
    /// Directory-only: name -> child file_id.
    pub children: BTreeMap<String, FileId>,
    /// In-memory cache of the real file size for `FLAG_HIDE_SIZE_HEADER`
    /// vaults. Skipped by serde so it doesn't leak through the metadata
    /// blob; populated lazily on first stat / read by decrypting chunk 0.
    #[serde(skip, default)]
    pub cached_real_size: Option<u64>,
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
