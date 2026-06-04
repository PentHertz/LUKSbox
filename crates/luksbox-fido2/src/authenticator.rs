// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use crate::error::Error;

/// Default Relying-Party ID stamped into every luksbox credential. Stable
/// across versions so re-enrollment isn't needed on upgrade.
pub const RP_ID: &str = "luksbox.local";

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
    /// `prehash_salt`: governs the on-wire convention. When true, the
    /// authenticator must be driven so it computes
    /// `HMAC-SHA256(device_secret, SHA-256(salt))` (v0.3.0 cross-
    /// platform "V4" slot convention). When false, it must compute
    /// `HMAC-SHA256(device_secret, salt)` (pre-v0.3.0 V1/V2/V3
    /// convention, Linux/macOS only).
    ///
    /// Backend behaviour:
    /// - libfido2 (Linux/macOS): SHA-256s the salt locally when
    ///   `prehash_salt=true`; passes it raw when false.
    /// - webauthn.dll (Windows): always prehashes internally per
    ///   W3C WebAuthn Level 3 PRF behaviour, so the param can only
    ///   honour `true`. On `false` (V1/V2/V3 slot) it returns a
    ///   `Fido2SlotPlatformLocked` error pointing at the migration
    ///   command rather than producing wrong bytes.
    /// - mock: mirrors libfido2 semantics for tests.
    fn hmac_secret(
        &mut self,
        rp_id: &str,
        cred_id: &[u8],
        salt: &[u8; 32],
        prehash_salt: bool,
        pin: Option<&str>,
    ) -> Result<HmacSecret, Error>;
}
