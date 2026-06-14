// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use crate::error::Error;

/// Default Relying-Party ID stamped into every luksbox credential. Stable
/// across versions so re-enrollment isn't needed on upgrade.
pub const RP_ID: &str = "luksbox.local";

/// The W3C WebAuthn Level 3 PRF to CTAP2 hmac-secret salt derivation:
/// `SHA-256("WebAuthn PRF" ‖ 0x00 ‖ salt)`.
///
/// This is the exact byte sequence the authenticator must HMAC for a V4
/// (cross-platform) luksbox keyslot, and it is the single source of
/// truth shared by every backend:
///
/// - **libfido2** (Linux/macOS, `hid.rs`): applies this transform
///   *locally* before handing the result to the device, because
///   libfido2 forwards salts to the device verbatim.
/// - **webauthn.dll** (Windows, `webauthn.rs`): does NOT call this; the
///   Windows WebAuthn API applies exactly this derivation *internally*
///   to any salt on the hmac-secret path (empirically confirmed with
///   the `xplatform_hmac_probe` example: passing the raw salt on Windows
///   reproduces this function's output computed on Linux). So the
///   Windows backend forwards the RAW salt and lets the OS apply `T`.
/// - **MockAuthenticator**: applies this transform when
///   `prehash_salt = true` so unit tests model the real converged wire
///   behaviour.
///
/// Why this precise construction: Microsoft's webauthn.dll is not a salt
/// passthrough and does not do a plain `SHA-256(salt)`. luksbox ≤ v0.3.0
/// assumed one of those two; both were wrong, which is what made FIDO2
/// vaults platform-locked. The only convention that round-trips through
/// webauthn.dll is this PRF-prefixed one, so V4 adopts it on every
/// platform.
///
/// The salt is a public per-vault value (it lives in the slot header),
/// so neither the input nor the output is secret; no zeroization needed.
pub fn webauthn_prf_salt(salt: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"WebAuthn PRF");
    h.update([0x00]);
    h.update(salt);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

#[derive(Debug, Clone)]
pub struct Credential {
    pub id: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EnrollResult {
    pub credential: Credential,
}

/// 32-byte FIDO2 hmac-secret output.
///
/// Round 12 fix R12-19: newtype with `Zeroize + ZeroizeOnDrop` so
/// the bytes are wiped when the wrapper drops, instead of lingering
/// on the stack between authenticator return and consumer use
/// (callers often pass `&hmac.0` into `DeniableCredential::*` /
/// `derive_kek_with_fido2`; the intermediate stack copies are now
/// covered by Drop).
///
/// `Deref` to `[u8; 32]` keeps the existing call sites compiling
/// (`&hmac` continues to work where a `&[u8;32]` was previously
/// passed thanks to deref coercion). `From<[u8;32]>` + `into_inner`
/// cover the construction sites in the libfido2 / webauthn / mock
/// backends.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct HmacSecret(pub [u8; 32]);

impl PartialEq for HmacSecret {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison so a hostile-input equality check
        // (e.g. asserting "this device returned the expected hmac
        // for a known salt") does not leak via timing. The hmac
        // bytes are 32 bytes, fixed length; ConstantTimeEq returns
        // Choice -> into() bool.
        use subtle::ConstantTimeEq as _;
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for HmacSecret {}

impl HmacSecret {
    /// Consume the wrapper and return the raw bytes. The returned
    /// `[u8; 32]` is `Copy` and not auto-zeroized; consumers should
    /// wrap it back into a `Zeroizing` if they hold it for long.
    pub fn into_inner(self) -> [u8; 32] {
        // `self.0` is moved out and `self` Drops zeroing whatever
        // remained, but we have already copied; document this so the
        // caller is aware.
        self.0
    }
}

impl std::fmt::Debug for HmacSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the bytes themselves.
        f.debug_tuple("HmacSecret").field(&"<redacted>").finish()
    }
}

impl From<[u8; 32]> for HmacSecret {
    fn from(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl std::ops::Deref for HmacSecret {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for HmacSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; 32]> for HmacSecret {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

/// All operations require user presence (touch). Operations may also require
/// a PIN if the authenticator was provisioned with one.
pub trait Fido2Authenticator {
    /// Enroll a new credential with the hmac-secret extension. The returned
    /// credential id is what gets stored in a luksbox keyslot.
    fn enroll(
        &mut self,
        rp_id: &str,
        user_handle: &[u8],
        pin: Option<&str>,
    ) -> Result<EnrollResult, Error>;

    /// Compute hmac-secret(salt) for an existing credential.
    ///
    /// `prehash_salt`: selects the on-wire salt convention. When true,
    /// the authenticator must end up computing
    /// `HMAC-SHA256(device_secret, T(salt))` where
    /// `T(salt) = SHA-256("WebAuthn PRF"\0 ‖ salt)` (see
    /// [`webauthn_prf_salt`]). This is the v0.3.0 cross-platform "V4"
    /// slot convention. When false, it must compute
    /// `HMAC-SHA256(device_secret, salt)` (the pre-v0.3.0 V1/V2/V3
    /// raw-salt convention, Linux/macOS only).
    ///
    /// Backend behaviour for `prehash_salt = true`:
    /// - libfido2 (Linux/macOS): applies `T(salt)` locally via
    ///   [`webauthn_prf_salt`] and forwards the result, because
    ///   libfido2 hands the device whatever bytes we give it.
    /// - webauthn.dll (Windows): forwards the RAW salt. The Windows
    ///   WebAuthn API applies `T` to it internally, so the device sees
    ///   the same `T(salt)` as the libfido2 path. (For `false` /
    ///   V1/V2/V3 slots there is no way to suppress `T`, so those
    ///   slots cannot be unlocked on Windows.)
    /// - mock: applies `T(salt)` when true to mirror the converged
    ///   wire behaviour for tests.
    fn hmac_secret(
        &mut self,
        rp_id: &str,
        cred_id: &[u8],
        salt: &[u8; 32],
        prehash_salt: bool,
        pin: Option<&str>,
    ) -> Result<HmacSecret, Error>;
}
