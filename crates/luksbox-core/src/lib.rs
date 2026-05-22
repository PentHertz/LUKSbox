// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! luksbox-core, cryptographic primitives and the on-disk container header
//! format for the luksbox encrypted-container tool. Pure crypto, no I/O.

pub mod aead;
pub mod deniable;
pub mod error;
pub mod file_util;
pub mod header;
pub mod kdf;
pub mod key;
pub mod keyslot;
pub mod secret_box;
pub mod secret_mem;

pub use crate::aead::CipherSuite;
pub use crate::error::Error;
pub use crate::header::{
    FLAG_HAS_HEADER_MIRROR, FLAG_HAS_METADATA_MIRROR, FLAG_HIDE_SIZE_HEADER, FLAG_PAD_FILES_POW2,
    HEADER_SIZE, Header, MAGIC_V1, MAGIC_V2, MAX_KEYSLOTS, VERSION_MAJOR_V1, VERSION_MAJOR_V2,
};
pub use crate::kdf::{Argon2idParams, KdfId};
pub use crate::key::{KeyEncryptionKey, MasterVolumeKey, SubKey};
pub use crate::keyslot::{
    AAD_VERSION_V1, AAD_VERSION_V2, AAD_VERSION_V3, FIDO2_CRED_ID_MAX, FIDO2_CRED_ID_MAX_V1V2,
    Keyslot, SLOT_SIZE, SlotKind,
};
