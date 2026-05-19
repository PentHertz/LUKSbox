// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! luksbox-vfs, virtual filesystem over a luksbox `Container`.
//!
//! - Directory tree lives serde-encoded in the container's metadata blob.
//! - File data is stored in fixed-size 4096-byte plaintext chunks, each
//!   AEAD-sealed independently (see `chunk` module). Chunk slots in the
//!   data area are indexed by `chunk_id`; an inode keeps an ordered
//!   `Vec<chunk_id>` for its file. Free chunk_ids are tracked in a
//!   LIFO free-list and reused on subsequent writes, fresh random
//!   nonce per write means reuse is safe.
//! - Logical file size is tracked in the inode separately from physical
//!   chunk count: a file of 100 bytes still occupies one full 4096-byte
//!   chunk on disk, but reads/writes are bounded by the logical size.
//!
//! No FUSE/WinFsp glue, that lives in `luksbox-mount`.

pub mod chunk;
pub mod error;
pub mod tree;
pub mod vfs;

pub use crate::chunk::{CHUNK_PLAINTEXT_SIZE, CHUNK_SLOT_SIZE};
pub use crate::error::Error;
pub use crate::tree::{ChunkRef, DirectoryTree, FileId, InodeKind};
pub use crate::vfs::{DirEntry, MAX_FILE_SIZE, SlotCredential, Stat, TreeCounters, Vfs};
