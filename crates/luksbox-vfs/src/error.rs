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
}
