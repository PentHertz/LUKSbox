// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid magic bytes")]
    InvalidMagic,

    #[error("unsupported version {major}.{minor}")]
    UnsupportedVersion { major: u16, minor: u16 },

    #[error("unsupported cipher suite id {0:#06x}")]
    UnsupportedCipher(u16),

    #[error("unsupported KDF id {0:#06x}")]
    UnsupportedKdf(u16),

    #[error("unsupported slot kind {0}")]
    UnsupportedSlotKind(u8),

    #[error("buffer too short: expected at least {expected} bytes, got {got}")]
    BufferTooShort { expected: usize, got: usize },

    #[error("header authentication failed")]
    HeaderAuthFailed,

    #[error("keyslot authentication failed")]
    KeyslotAuthFailed,

    #[error("KDF failure")]
    Kdf,

    #[error(
        "not enough memory for Argon2id: needs {needed_kib} KiB ({needed_mib} MiB) of \
         contiguous RAM. This host (small VM, container cgroup, or QubesOS AppVM) could \
         not provide it. Give the machine more RAM, or create the keyslot on a larger host."
    )]
    KdfOutOfMemory { needed_kib: u32, needed_mib: u32 },

    #[error("AEAD failure")]
    Aead,

    #[error("invalid keyslot index {0}")]
    InvalidKeyslotIndex(usize),

    #[error("no free keyslot")]
    NoFreeKeyslot,

    #[error("keyslot is empty")]
    EmptyKeyslot,

    #[error("invalid field value")]
    InvalidField,

    #[error("FIDO2 credential id too long ({0} > 128)")]
    Fido2CredIdTooLong(usize),

    #[error("OS RNG failure: {0}")]
    OsRng(String),
}
