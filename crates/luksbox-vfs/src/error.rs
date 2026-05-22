// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("crypto: {0}")]
    Crypto(#[from] luksbox_core::Error),

    #[error("format: {0}")]
    Format(#[from] luksbox_format::Error),

    #[error("path or file not found")]
    NotFound,

    #[error("entry already exists")]
    AlreadyExists,

    #[error("not a directory")]
    NotADirectory,

    #[error("is a directory")]
    IsADirectory,

    #[error("not a file")]
    NotAFile,

    #[error("directory is not empty")]
    NotEmpty,

    #[error("metadata blob serialization failed")]
    MetadataSerialize,

    #[error("metadata blob deserialization failed")]
    MetadataDeserialize,

    #[error("invalid path: {0}")]
    InvalidPath(String),

    /// Cross-directory rename that would move a directory into its
    /// own descendant (or onto itself). POSIX `rename(2)` requires
    /// EINVAL here -- without the guard the tree would gain a cycle
    /// and the next traversal (read_directory, flush, rotate_mvk)
    /// would loop forever. Surfaces to FUSE/WinFsp as EINVAL.
    #[error("rename would create a directory cycle")]
    RenameCycle,

    /// Refused a read/write whose `offset + length` would overflow u64.
    /// Realistic offsets are bounded by file size; this guard exists
    /// for hostile inputs and as a defense-in-depth against misuse of
    /// the public read/write API.
    #[error("offset + length overflows u64")]
    OffsetOverflow,

    #[error("metadata id/generation space exhausted")]
    IdSpaceExhausted,

    /// Refused a write / truncate whose target logical size exceeds the
    /// per-file cap (`luksbox_vfs::MAX_FILE_SIZE`). Round 13 R13-07
    /// guard against pathological inputs that would push
    /// `padded_chunk_count` past `next_power_of_two`'s safe range or
    /// allocate astronomic amounts of disk / RAM.
    #[error("file size exceeds the per-file maximum")]
    FileSizeExceedsCap,

    /// Refused a write / truncate because the directory tree, once
    /// serialised, would no longer fit in the vault's metadata region.
    /// Caught BEFORE any chunk write so the data area isn't polluted
    /// with chunks the metadata blob can't point at. The FUSE layer
    /// maps this to `ENOSPC` so `cp` / `dd` fails mid-copy with the
    /// right errno -- instead of the previous behaviour where chunks
    /// landed on disk, flush failed at unmount, and the file was
    /// invisible on the next mount (silent data loss).
    ///
    /// User-visible fix: re-create the vault with a larger
    /// `--metadata-size`. Default is 16 MiB, which is also the
    /// format-level cap (`MAX_METADATA_SIZE`) in this version --
    /// sufficient for roughly 8-10 GiB of stored content per
    /// vault. Larger vaults need a format-version bump.
    #[error("metadata region exhausted (vault holds too many chunks for its metadata budget)")]
    MetadataBudgetExhausted,
}
