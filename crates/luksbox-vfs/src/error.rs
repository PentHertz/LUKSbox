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
    #[error(
        "the vault's metadata region is full (too many files or chunk references): delete \
         files to make room, enlarge the region if it is under 64 MiB (`luksbox size <vault> \
         --metadata-size 64M`, or Vault size in the wizard or the GUI), or move some files \
         to a new vault"
    )]
    MetadataBudgetExhausted,

    /// Refused a mutation because this Vfs instance recovered one
    /// or more inodes at open time (tolerant recovery mode zeroed
    /// their chunks vec and `size` so the open could complete).
    /// The in-memory tree is lossy: persisting it would overwrite
    /// the original on-disk chunk pointers permanently, and any
    /// write could recycle the broken files' chunk slots. Every
    /// mutating op and any dirty flush on such an instance returns
    /// this error; clean flushes no-op so close()/unmount still
    /// work. Keyed on the per-instance recovery report, not the
    /// transient thread-local/env flag that enabled the open.
    #[error("vault holds recovered (lossy) inodes; mutation refused (mount is read-only)")]
    ReadOnlyMount,
    /// Refused a write that would grow the vault file past the maximum
    /// size the user set (`Vfs::set_max_vault_size`). Free space inside
    /// the vault is still reused; only growth is refused. Mount layers
    /// map it to `ENOSPC` / `STATUS_DISK_FULL`, like a full disk.
    #[error(
        "vault is at its maximum size ({}): raise the limit or delete files",
        luksbox_core::size::format_size(*limit)
    )]
    VaultSizeLimit { limit: u64 },
    /// `Vfs::set_max_vault_size` below what the vault itself takes
    /// (header and metadata region, plus one chunk slot).
    #[error(
        "{} is smaller than the vault itself; the minimum is {}",
        luksbox_core::size::format_size(*requested),
        luksbox_core::size::format_size(*minimum)
    )]
    MaxSizeBelowMinimum { requested: u64, minimum: u64 },
    /// `Vfs::set_max_vault_size` on a vault kept in a metadata format
    /// older than LBM5 (created with `LUKSBOX_FORMAT_V2=1` for older
    /// LUKSbox versions), which has no room for the setting.
    #[error("this vault uses an older format that cannot store a maximum size")]
    MaxSizeNeedsCurrentFormat,
    /// `Vfs::shrink` on a deniable vault: a vault file that shrinks over
    /// time hints that data was deleted from it.
    #[error("deniable vaults are not shrunk: a shrinking file would reveal deletions")]
    ShrinkDeniable,
    /// `Vfs::resize_metadata_region` on a deniable vault, which needs the
    /// user's acknowledgment (`resize_metadata_region_allow_deniable`).
    #[error(
        "resizing a deniable vault moves its data by the size difference: anyone who has an \
         older copy of the file (backups, sync history, disk images) can see that it changed \
         shape. Confirm to resize it anyway"
    )]
    ResizeDeniable,
    /// `Vfs::resize_metadata_region` to a size outside 64 KiB..=64 MiB or
    /// not a multiple of 64 KiB.
    #[error("a metadata region is 64 KiB to 64 MiB, in steps of 64 KiB")]
    ResizeInvalidSize,
    /// `Vfs::resize_metadata_region` to a region the file list does not
    /// fit in.
    #[error(
        "the file list needs {} with some room to spare; choose a larger region",
        luksbox_core::size::format_size(*needed)
    )]
    ResizeTooSmall { needed: u64 },
    /// `Vfs::resize_metadata_region` needs room for a second copy of the
    /// vault while it runs.
    #[error(
        "resizing writes a new copy of the vault next to it: needs {} free, the disk has {}",
        luksbox_core::size::format_size(*needed),
        luksbox_core::size::format_size(*free)
    )]
    ResizeNeedsDiskSpace { needed: u64, free: u64 },
}
