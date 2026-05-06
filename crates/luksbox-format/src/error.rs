// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("crypto: {0}")]
    Crypto(#[from] luksbox_core::Error),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("no keyslot accepted the provided unlock material")]
    UnlockFailed,

    #[error("metadata blob is larger than the metadata region")]
    MetadataTooLarge,

    #[error("metadata region is corrupt")]
    MetadataCorrupt,

    #[error("on-disk offset arithmetic overflows u64")]
    OffsetOverflow,

    #[error("FIDO2 credential id not found in any keyslot")]
    Fido2CredNotFound,

    #[error("anchor file authentication failed (wrong vault, or anchor was tampered)")]
    AnchorAuthFailed,

    #[error("anchor file is corrupt or has wrong magic")]
    AnchorCorrupt,

    #[error(
        "vault locked by another process (path: {path}). \
         Close the other luksbox instance and retry, or check `lsof {path}` \
         for the holder. Set LUKSBOX_NO_LOCK=1 to bypass (DANGEROUS, \
         risks corruption if another writer is active)."
    )]
    VaultLocked { path: String },

    #[error(
        "path '{path}' was substituted between opens, the file we just \
         opened has a different (device, inode) than the one we opened a \
         moment ago. Likely causes: a concurrent symlink swap, atomic \
         rename-over, or bind-mount manipulation. Refusing to proceed to \
         avoid operating on the wrong file."
    )]
    PathSubstituted { path: String },

    #[error(
        "path '{path}' is a symlink and LUKSBOX_NO_FOLLOW_SYMLINKS=1 is \
         set. Either point luksbox at the real file directly, or unset \
         the env var to allow symlink resolution."
    )]
    SymlinkRefused { path: String },
}
