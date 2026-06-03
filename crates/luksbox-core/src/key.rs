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
/// Backed by `memfd_secret(2)` on Linux >= 5.14 when available, pages are
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

    /// Construct an MVK from a `Zeroizing`-wrapped byte array without
    /// materialising a `[u8; KEY_LEN]` temporary on the caller's stack.
    /// The bytes are copied directly from the caller's `Zeroizing` storage
    /// into a freshly-allocated `SecretBox` backing buffer (memfd_secret
    /// pages on Linux >= 5.14, heap with mlockall/VirtualLock otherwise).
    ///
    /// The earlier implementation went through `SecretBox::from_bytes(**bytes)`,
    /// which double-copies: first `**bytes` produces a Copy `[u8; KEY_LEN]`
    /// temporary on the function's stack, then `from_bytes` takes that
    /// temporary by value and copies it into the backing buffer. The
    /// temporary's bytes survive on the stack until frame reuse, defeating
    /// the `Zeroizing` guarantee the audit (R12-17) was meant to provide.
    pub fn from_zeroizing(bytes: &Zeroizing<[u8; KEY_LEN]>) -> Self {
        let mut sb = SecretBox::zeroed();
        sb.as_mut_array().copy_from_slice(&**bytes);
        Self(sb)
    }

    /// Same as `from_zeroizing` but for borrowed array refs that the caller
    /// already holds without `Zeroizing`. Use when the source bytes live in
    /// caller-owned storage that the caller is responsible for wiping
    /// (e.g., a `&[u8; KEY_LEN]` parameter passed through several layers).
    pub fn from_array_ref(bytes: &[u8; KEY_LEN]) -> Self {
        let mut sb = SecretBox::zeroed();
        sb.as_mut_array().copy_from_slice(bytes);
        Self(sb)
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
            .expect("32 <= 255 * HashLen");
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
    /// Same rationale as `MasterVolumeKey::from_zeroizing`: the previous
    /// `Self(**bytes)` form spawned a `[u8; KEY_LEN]` Copy temporary on the
    /// stack before the field assignment, leaving 32 bytes of KEK material
    /// readable in the stack frame after the move. This form constructs
    /// the destination first and writes the bytes into it through a
    /// borrowed pointer, so no anonymous Copy temporary exists.
    ///
    /// NOTE: `KeyEncryptionKey`'s inline `[u8; KEY_LEN]` storage means
    /// the returned value still carries 32 bytes by value through the
    /// return slot; truly heap-only KEK storage would require switching
    /// the field to `Box<[u8; KEY_LEN]>` or `SecretBox`. This fix
    /// closes the *additional* stack copy that `**bytes` introduced.
    pub fn from_zeroizing(bytes: &Zeroizing<[u8; KEY_LEN]>) -> Self {
        let mut k = Self([0u8; KEY_LEN]);
        k.0.copy_from_slice(&**bytes);
        k
    }

    /// Same as `from_zeroizing` but for a borrowed `&[u8; KEY_LEN]` whose
    /// storage is already managed by the caller.
    pub fn from_array_ref(bytes: &[u8; KEY_LEN]) -> Self {
        let mut k = Self([0u8; KEY_LEN]);
        k.0.copy_from_slice(bytes);
        k
    }
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}
