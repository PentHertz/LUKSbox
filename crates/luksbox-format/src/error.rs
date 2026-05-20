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

    /// Single failure mode for the deniable header open path. Wrong
    /// passphrase, wrong cipher, wrong Argon2 params, wrong vault file,
    /// truncated input, and AEAD tag failure all collapse into this
    /// one variant so an attacker observing error output cannot tell
    /// which dimension was wrong. See `docs/DENIABLE_HEADER.md` for
    /// the threat model that motivates the no-oracle property.
    #[error("unlock failed")]
    OpaqueUnlockFailed,

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

    /// `Container::rotate_mvk_v2_deniable` was called on a deniable
    /// vault that already has user content (the metadata blob is
    /// populated). That entry point ONLY rotates the slot envelope +
    /// MVK; it does not re-encrypt chunks, so calling it on a vault
    /// with chunks would leave the chunks encrypted under the OLD
    /// MVK's file_keys and unreadable on next open. Use
    /// `luksbox_vfs::Vfs::rotate_mvk_deniable` instead -- it pairs the
    /// envelope rewrap with a full chunk + chunk-list-block +
    /// metadata re-encryption under the new MVK.
    #[error(
        "deniable envelope-only rotation refused: vault already has content. \
         Use luksbox_vfs::Vfs::rotate_mvk_deniable for the full rotation that \
         re-encrypts chunks under the new MVK."
    )]
    DeniableRotationRequiresEmptyVault,
}
