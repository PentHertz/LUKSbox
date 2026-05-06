// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::secret_box::SecretBox;

pub const KEY_LEN: usize = 32;

/// 32-byte symmetric subkey. Always wrapped in `Zeroizing` so it's
/// memset-to-zero when the binding goes out of scope; constant-time-eq
/// for safety on caller side. Used for the per-file file_key, the
/// metadata_key, the header_mac_key, etc.
pub type SubKey = Zeroizing<[u8; KEY_LEN]>;

/// Master Volume Key. Encrypts file content (indirectly, via per-file subkeys).
/// Stored only as wrapped ciphertext in keyslots; never persisted in cleartext.
///
/// Backed by `memfd_secret(2)` on Linux ≥ 5.14 when available, pages are
/// unmappable in any other process and excluded from coredumps and
/// hibernate images. Falls back to a `Box<[u8; 32]>` with `Zeroize` on drop
/// when `memfd_secret` isn't available.
#[derive(Clone)]
pub struct MasterVolumeKey(SecretBox);

impl MasterVolumeKey {
    /// Generate a fresh MVK. Propagates OS RNG errors via Result.
    pub fn try_random() -> Result<Self, rand_core::Error> {
        Ok(Self(SecretBox::try_random()?))
    }

    /// Panic-on-failure variant of `try_random`. Kept for ergonomics in
    /// test code. Production paths should use `try_random` instead so
    /// the rare OS RNG failure surfaces as a recoverable Err.
    pub fn random() -> Self {
        Self(SecretBox::random())
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(SecretBox::from_bytes(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        self.0.as_array()
    }

    /// Whether this MVK lives in `memfd_secret` pages (the strongest mode)
    /// or in regular heap memory (the fallback). Diagnostic only.
    pub fn is_in_secret_memory(&self) -> bool {
        self.0.is_secret_mem()
    }

    /// HKDF-SHA256 expansion to a 32-byte labelled subkey. `salt` is typically
    /// the header_salt, `info` a domain-separation tag (e.g. `b"lbx:header-mac"`).
    /// Returned key is wrapped in `Zeroizing` so it clears when dropped.
    pub fn derive_subkey(&self, salt: &[u8], info: &[u8]) -> SubKey {
        let hk = Hkdf::<Sha256>::new(Some(salt), self.0.as_array());
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        hk.expand(info, out.as_mut_slice())
            .expect("32 ≤ 255 * HashLen");
        out
    }
}

impl ConstantTimeEq for MasterVolumeKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.as_array().ct_eq(other.0.as_array())
    }
}

impl PartialEq for MasterVolumeKey {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}
impl Eq for MasterVolumeKey {}

/// Key-Encryption-Key derived per keyslot from a passphrase or hardware token.
/// Used only to wrap/unwrap the MVK.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyEncryptionKey([u8; KEY_LEN]);

impl KeyEncryptionKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}
