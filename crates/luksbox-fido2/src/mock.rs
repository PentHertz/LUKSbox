// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use std::collections::HashMap;

use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;

use crate::authenticator::{Credential, EnrollResult, Fido2Authenticator, HmacSecret};
use crate::error::Error;

/// Deterministic in-memory authenticator. Each enrolled credential gets a
/// random `cred_secret`; `hmac_secret(salt)` returns
/// `HMAC-SHA256(cred_secret, salt)`, matching the abstract behavior of a
/// real FIDO2 authenticator with the hmac-secret extension.
///
/// Useful only for unit tests; do not connect to anything that holds real data.
pub struct MockAuthenticator {
    creds: HashMap<Vec<u8>, [u8; 32]>,
    fail_touch: bool,
    /// Hostile-mode knob (test-only): force `enroll()` to return a
    /// cred_id of exactly this length (filled with random bytes).
    /// `None` = use the default 64-byte length. Used to simulate a
    /// rogue / MITM authenticator returning oversized or empty cred_ids
    /// so we can exercise the downstream length-validation path.
    cred_id_len_override: Option<usize>,
    /// Hostile-mode knob (test-only): force `hmac_secret()` to return
    /// these bytes verbatim for any (cred_id, salt) input. Used to
    /// simulate a rogue authenticator that ignores the HMAC-SHA256
    /// derivation contract and returns attacker-chosen 32-byte values.
    /// `None` = use the legitimate HMAC computation.
    hmac_secret_override: Option<[u8; 32]>,
}

impl MockAuthenticator {
    pub fn new() -> Self {
        Self {
            creds: HashMap::new(),
            fail_touch: false,
            cred_id_len_override: None,
            hmac_secret_override: None,
        }
    }

    /// Make subsequent operations return `TouchTimeout`. Test helper.
    pub fn simulate_no_touch(&mut self) {
        self.fail_touch = true;
    }

    /// Test helper: next `enroll()` call returns a cred_id of `len` bytes
    /// instead of the default 64. Used to simulate rogue / MITM
    /// authenticators returning hostile cred_id sizes.
    pub fn force_cred_id_len(&mut self, len: usize) {
        self.cred_id_len_override = Some(len);
    }

    /// Test helper: every subsequent `hmac_secret()` call returns the
    /// exact 32 bytes provided here, regardless of (cred_id, salt).
    /// Used to simulate a rogue authenticator returning
    /// attacker-controlled hmac_secret values (e.g. all-zeros, all-ones,
    /// or a value the attacker chose to try to predict the KEK).
    pub fn force_hmac_secret(&mut self, value: [u8; 32]) {
        self.hmac_secret_override = Some(value);
    }
}

impl Default for MockAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl Fido2Authenticator for MockAuthenticator {
    fn enroll(
        &mut self,
        _rp_id: &str,
        _user_handle: &[u8],
        _pin: Option<&str>,
    ) -> Result<EnrollResult, Error> {
        if self.fail_touch {
            return Err(Error::TouchTimeout);
        }
        let id_len = self.cred_id_len_override.unwrap_or(64);
        let mut id = vec![0u8; id_len];
        if id_len > 0 {
            OsRng.fill_bytes(&mut id);
        }
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        self.creds.insert(id.clone(), secret);
        Ok(EnrollResult {
            credential: Credential { id },
        })
    }

    fn hmac_secret(
        &mut self,
        _rp_id: &str,
        cred_id: &[u8],
        salt: &[u8; 32],
        prehash_salt: bool,
        _pin: Option<&str>,
    ) -> Result<HmacSecret, Error> {
        if self.fail_touch {
            return Err(Error::TouchTimeout);
        }
        if let Some(forced) = self.hmac_secret_override {
            // Hostile mode: ignore (cred_id, salt) entirely and return
            // attacker-chosen bytes. Models a rogue / MITM device.
            return Ok(HmacSecret(forced));
        }
        let secret = self
            .creds
            .get(cred_id)
            .ok_or_else(|| Error::Other("unknown credential".into()))?;
        // Mirror the real converged wire behaviour: the mock is a
        // CTAP2-level device, so it HMACs whatever bytes reach it. The
        // libfido2 path applies T(salt) = SHA-256("WebAuthn PRF"\0 ||
        // salt) locally when `prehash_salt` is set; the Windows path
        // forwards the raw salt and webauthn.dll applies the same T.
        // Both converge on the device seeing T(salt), so the mock
        // applies T here for `prehash_salt = true`. The cross-platform
        // round-trip test in luksbox-core models the Windows side by
        // computing T(salt) itself and calling with `prehash=false`.
        let mut effective_salt = [0u8; 32];
        if prehash_salt {
            effective_salt.copy_from_slice(&crate::authenticator::webauthn_prf_salt(salt));
        } else {
            effective_salt.copy_from_slice(salt);
        }
        let mut mac = <Hmac<Sha256>>::new_from_slice(secret).expect("HMAC any-len");
        mac.update(&effective_salt);
        let out = mac.finalize().into_bytes();
        let mut hmac = [0u8; 32];
        hmac.copy_from_slice(&out);
        Ok(HmacSecret(hmac))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enroll_then_hmac_is_deterministic() {
        let mut auth = MockAuthenticator::new();
        let r = auth.enroll("luksbox.local", b"user", None).unwrap();
        let salt = [0x42u8; 32];
        let a = auth
            .hmac_secret("luksbox.local", &r.credential.id, &salt, true, None)
            .unwrap();
        let b = auth
            .hmac_secret("luksbox.local", &r.credential.id, &salt, true, None)
            .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_salts_give_different_outputs() {
        let mut auth = MockAuthenticator::new();
        let r = auth.enroll("luksbox.local", b"user", None).unwrap();
        let s1 = [0x01u8; 32];
        let s2 = [0x02u8; 32];
        let o1 = auth
            .hmac_secret("luksbox.local", &r.credential.id, &s1, true, None)
            .unwrap();
        let o2 = auth
            .hmac_secret("luksbox.local", &r.credential.id, &s2, true, None)
            .unwrap();
        assert_ne!(o1, o2);
    }

    #[test]
    fn unknown_credential_rejected() {
        let mut auth = MockAuthenticator::new();
        let r = auth.hmac_secret("luksbox.local", b"nope", &[0u8; 32], true, None);
        assert!(r.is_err());
    }

    #[test]
    fn touch_timeout_simulated() {
        let mut auth = MockAuthenticator::new();
        let r = auth.enroll("luksbox.local", b"u", None).unwrap();
        auth.simulate_no_touch();
        let r2 = auth.hmac_secret("luksbox.local", &r.credential.id, &[0u8; 32], true, None);
        assert!(matches!(r2, Err(Error::TouchTimeout)));
    }

    #[test]
    fn prehash_salt_changes_output() {
        // Locks in the V3 -> V4 wire-format divergence: the same
        // (credential, salt) tuple with prehash=true vs prehash=false
        // produces different HMAC bytes. This is the property that
        // makes a V3 (raw-salt) keyslot incompatible with the V4
        // (prehashed-salt) unlock convention and is exactly what was
        // happening cross-platform between libfido2 (raw) and
        // webauthn.dll (prehashed) before the v0.3.0 fix.
        let mut auth = MockAuthenticator::new();
        let r = auth.enroll("luksbox.local", b"u", None).unwrap();
        let salt = [0x55u8; 32];
        let raw = auth
            .hmac_secret("luksbox.local", &r.credential.id, &salt, false, None)
            .unwrap();
        let prehashed = auth
            .hmac_secret("luksbox.local", &r.credential.id, &salt, true, None)
            .unwrap();
        assert_ne!(raw, prehashed);
    }
}
