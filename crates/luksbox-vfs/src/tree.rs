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

/// Inline chunk-list threshold used when writing LBM5 metadata
/// (v0.3.0+ default). Lower than the V3/V4 value (1024) so the
/// encoded directory tree stays compact for very large vaults with
/// thousands of files: 256 chunks at 4 KiB plaintext ~ 1 MiB per
/// inode before spilling to an external chunk-list chain. The read
/// path tolerates LBM5 blobs that carry larger inline counts
/// (forward-compat with a future threshold change) and only enforces
/// the structural validation common to all formats.
pub const V5_INLINE_CHUNK_THRESHOLD: usize = 256;

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
    /// Symlink. The target string is stored on `Inode.symlink_target`.
    /// Symlinks are an LBM4-only feature; LBM2/LBM3 vaults cannot
    /// represent them, and the auto-upgrade detector in
    /// `Vfs::tree_needs_v4_format` forces an upgrade as soon as any
    /// symlink is created.
    ///
    /// **Security**: targets are validated at create time to refuse
    /// absolute paths, `..` components, and any other form that
    /// could resolve outside the vault namespace (the classic
    /// `secret -> /etc/shadow` supply-chain attack). See
    /// `Vfs::symlink` for the validation rules.
    Symlink,
}

/// In-memory inode. **Never serialised directly** since the LBM4
/// metadata bump: the on-disk shape is one of `InodeV2OnDisk` /
/// `InodeV3OnDisk` / `InodeV4OnDisk` (in `vfs.rs`), and conversion
/// functions populate the in-memory fields when reading or strip
/// them when writing back an older format. Adding fields to this
/// struct does NOT require a format bump as long as the new fields
/// are either serde-skipped or backed by an on-disk shape.
///
/// New as of LBM4:
/// - `mode`: POSIX-style mode bits (0o644 default for files, 0o755
///   for directories). Persisted only when written to LBM4; LBM2/
///   LBM3 readers populate from defaults.
/// - `link_count`: hardlink count. 1 for files with one directory
///   entry, N for files with N hardlinks. Empty directories report
///   nlink=2 to the FUSE layer (self + ".") regardless of this
///   field; the field is meaningful only for `InodeKind::File`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Inode {
    pub id: FileId,
    /// "Canonical" parent directory's id. For ordinary single-linked
    /// files and for all directories this is the unique parent. For
    /// hardlinked files (link_count > 1) it's the parent of the
    /// directory entry that most recently won an arbitrary tie-break;
    /// the mount layer's `..` resolution for files is best-effort and
    /// only meaningful for the entry the kernel happened to traverse
    /// to reach the inode -- POSIX itself doesn't define `..` for
    /// hardlinked files. The root inode is its own parent (self-loop).
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
    /// POSIX mode bits. Serde-skipped because the LBM2/LBM3 on-disk
    /// shapes don't carry a mode field; LBM4 reads populate this from
    /// disk via `InodeV4OnDisk`, LBM2/LBM3 reads populate from the
    /// default for the inode's kind (`default_mode_for_kind`). Writes
    /// go to LBM4 only when `Vfs::flush` decides the vault must
    /// upgrade (non-default mode or link_count > 1 anywhere in the
    /// tree); otherwise the mode field is silently dropped (caller's
    /// choice: keep the vault openable by pre-LBM4 binaries at the
    /// cost of losing user-set mode bits on next flush).
    #[serde(skip, default = "default_mode_file")]
    pub mode: u32,
    /// Hardlink count. Always 1 for freshly created inodes. Incremented
    /// by `Vfs::link`, decremented by `Vfs::unlink`. When it reaches
    /// zero `unlink` frees the chunks. Serde-skipped: same reason as
    /// `mode` (LBM4-only on disk).
    #[serde(skip, default = "default_link_count")]
    pub link_count: u32,
    /// Symlink target. `Some(s)` for `InodeKind::Symlink`, `None`
    /// for files and directories. Validated at create time -- never
    /// stores absolute paths, never stores `..` components, capped
    /// at `MAX_SYMLINK_TARGET_LEN` bytes. Serde-skipped: persisted
    /// in `InodeV4OnDisk::symlink_target` for LBM4 vaults; LBM2/
    /// LBM3 vaults can't have symlinks at all so the field is
    /// always `None` after a v2/v3 read.
    #[serde(skip, default)]
    pub symlink_target: Option<String>,
}

/// Maximum bytes in a symlink target. Linux PATH_MAX = 4096 and
/// most filesystems accept symlink targets up to that size; we cap
/// at the same value to:
/// 1. Avoid metadata-blob bloat from a maliciously huge target
/// 2. Match POSIX expectations (so apps don't see surprising
///    truncation behaviour vs ext4/btrfs/etc.)
/// 3. Bound the in-memory work of any future symlink-following
///    resolver (depth * max-target memory).
pub const MAX_SYMLINK_TARGET_LEN: usize = 4096;

/// Default mode used when reading LBM2/LBM3 vaults that don't carry
/// per-inode mode bits, and as the initial value for new inodes
/// before any chmod. 0o644 for files, 0o755 for directories. Note
/// that `serde(skip, default = ...)` accepts a function with no
/// arguments, so the default-file form is used unconditionally and
/// `Vfs::open` patches directories to 0o755 in the conversion.
pub const DEFAULT_FILE_MODE: u32 = 0o644;
pub const DEFAULT_DIR_MODE: u32 = 0o755;

fn default_mode_file() -> u32 {
    DEFAULT_FILE_MODE
}

fn default_link_count() -> u32 {
    1
}

/// Return the conventional default mode for a freshly-created inode
/// of the given kind. Used by `create`, `mkdir`, and by the LBM2/
/// LBM3-to-in-memory conversion so old vaults present sensible mode
/// bits to the FUSE layer even though the format doesn't carry them.
/// Symlinks default to 0o777 per POSIX -- the mode on a symlink is
/// never enforced (the kernel checks the target's mode instead),
/// so we mirror what mainstream filesystems return.
pub fn default_mode_for_kind(kind: InodeKind) -> u32 {
    match kind {
        InodeKind::File => DEFAULT_FILE_MODE,
        InodeKind::Directory => DEFAULT_DIR_MODE,
        InodeKind::Symlink => 0o777,
    }
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
                mode: DEFAULT_DIR_MODE,
                link_count: 1,
                symlink_target: None,
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
