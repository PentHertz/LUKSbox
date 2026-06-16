// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! In-memory `MockTpm2Sealer` for adversary-scenario tests.
//!
//! Mirrors the shape of the real `Tpm2Sealer` (seal / seal_with_pin /
//! unseal / unseal_with_pin) but keeps the seal map in a `HashMap` and
//! exposes "hostile-mode" knobs so tests can simulate a malicious or
//! malfunctioning TPM:
//!
//!   - `force_unsealed_bytes(...)`        -every subsequent unseal returns these bytes
//!   - `force_unsealed_truncated(len)`    -return `len` < 32 bytes
//!   - `force_unsealed_oversized(len)`    -return `len` > 32 bytes
//!   - `simulate_unseal_error()`          -return Err(TpmError(...)) on next unseal
//!   - `simulate_seal_error()`            -return Err(TpmError(...)) on next seal
//!   - `forget_blobs()`                   -drop all known blobs (rogue swap to a
//!     different chip; subsequent unseal fails)
//!
//! The format-layer's `UnlockMaterial::Tpm2 { unseal: closure }` already
//! takes a closure, so tests just wrap a `MockTpm2Sealer` in a closure
//! and call `Container::open` with it. No trait abstraction needed.
//!
//! Available unconditionally (no `hardware` feature gate). Real
//! production code never uses this; production goes through the gated
//! `Tpm2Sealer` in `real.rs`.

use std::collections::HashMap;

use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::{Error, SEALED_SECRET_LEN, SealedBlob};

/// Deterministic in-memory "TPM": a HashMap mapping
/// `(public_bytes, private_bytes) -> 32-byte secret`. Each call to
/// `seal()` produces a fresh nondeterministic blob (random public +
/// private bytes) and remembers `blob -> secret`. `unseal()` looks
/// the blob up; PIN-bound seals additionally remember the PIN and
/// verify it at unseal time.
///
/// Adversary knobs let tests force seal/unseal to return wrong data
/// or fail outright.
pub struct MockTpm2Sealer {
    /// Sealed blobs we've issued: `blob_bytes -> (secret, optional_pin)`.
    blobs: HashMap<Vec<u8>, ([u8; 32], Option<Vec<u8>>)>,
    /// If set, every subsequent `unseal()` returns these bytes
    /// regardless of the blob actually presented. Used to simulate a
    /// rogue TPM that pretends to unseal something it never sealed.
    forced_unsealed: Option<Vec<u8>>,
    /// If set, the next `unseal()` returns `Err(TpmError(...))`.
    /// One-shot, then auto-clears.
    next_unseal_errors: bool,
    /// If set, the next `seal()` returns `Err(TpmError(...))`.
    /// One-shot, then auto-clears.
    next_seal_errors: bool,
}

impl Default for MockTpm2Sealer {
    fn default() -> Self {
        Self::new()
    }
}

impl MockTpm2Sealer {
    pub fn new() -> Self {
        Self {
            blobs: HashMap::new(),
            forced_unsealed: None,
            next_unseal_errors: false,
            next_seal_errors: false,
        }
    }

    /// Hostile knob: every subsequent `unseal()` ignores the blob and
    /// returns these bytes. Length need not be 32 (use to test the
    /// downstream's length-check behavior).
    pub fn force_unsealed_bytes(&mut self, bytes: Vec<u8>) {
        self.forced_unsealed = Some(bytes);
    }

    /// Hostile knob: produce a wrong-length unsealed payload. Tests
    /// the downstream defenses against a TPM that misreports the
    /// length of its sealed object.
    pub fn force_unsealed_truncated(&mut self, len: usize) {
        assert!(
            len < SEALED_SECRET_LEN,
            "use force_unsealed_oversized for >= 32"
        );
        self.forced_unsealed = Some(vec![0xa5; len]);
    }

    pub fn force_unsealed_oversized(&mut self, len: usize) {
        assert!(
            len > SEALED_SECRET_LEN,
            "use force_unsealed_truncated for < 32"
        );
        self.forced_unsealed = Some(vec![0x5a; len]);
    }

    /// Hostile knob: next `unseal()` returns `Err(TpmError("rogue"))`.
    pub fn simulate_unseal_error(&mut self) {
        self.next_unseal_errors = true;
    }

    /// Hostile knob: next `seal()` returns `Err(TpmError("rogue"))`.
    pub fn simulate_seal_error(&mut self) {
        self.next_seal_errors = true;
    }

    /// Hostile knob: forget every blob we've issued. Models an
    /// attacker swapping the TPM chip with one that doesn't have the
    /// original endorsement seed, so previously-sealed blobs no
    /// longer unseal.
    pub fn forget_blobs(&mut self) {
        self.blobs.clear();
    }

    /// Mirrors `Tpm2Sealer::seal()`.
    pub fn seal(&mut self, plaintext: &[u8; SEALED_SECRET_LEN]) -> Result<SealedBlob, Error> {
        self.seal_with_pin(plaintext, None)
    }

    /// Mirrors `Tpm2Sealer::seal_with_pin()`.
    pub fn seal_with_pin(
        &mut self,
        plaintext: &[u8; SEALED_SECRET_LEN],
        pin: Option<&[u8]>,
    ) -> Result<SealedBlob, Error> {
        if self.next_seal_errors {
            self.next_seal_errors = false;
            return Err(Error::TpmError("simulated seal failure".into()));
        }
        // Random public + private byte arrays. Real TPM produces
        // about 80 + about 200 byte blobs; we mimic the size envelope so
        // round-trip tests through the full SealedBlob serialization
        // exercise the same length checks.
        let mut public = vec![0u8; 80];
        let mut private = vec![0u8; 200];
        OsRng.fill_bytes(&mut public);
        OsRng.fill_bytes(&mut private);
        let blob = SealedBlob { public, private };
        let key = blob.to_bytes();
        self.blobs
            .insert(key, (*plaintext, pin.map(|p| p.to_vec())));
        Ok(blob)
    }

    /// Mirrors `Tpm2Sealer::unseal()`.
    pub fn unseal(
        &mut self,
        blob: &SealedBlob,
    ) -> Result<Zeroizing<[u8; SEALED_SECRET_LEN]>, Error> {
        self.unseal_with_pin(blob, None)
    }

    /// Mirrors `Tpm2Sealer::unseal_with_pin()`.
    pub fn unseal_with_pin(
        &mut self,
        blob: &SealedBlob,
        pin: Option<&[u8]>,
    ) -> Result<Zeroizing<[u8; SEALED_SECRET_LEN]>, Error> {
        if self.next_unseal_errors {
            self.next_unseal_errors = false;
            return Err(Error::TpmError("simulated unseal failure".into()));
        }
        if let Some(forced) = &self.forced_unsealed {
            // Downstream API requires exactly SEALED_SECRET_LEN bytes;
            // wrong-length forced output simulates a rogue TPM that
            // returns garbage. The real Tpm2Sealer maps wrong-length
            // unseal payloads to TpmError("unsealed length N != 32"),
            // so mirror that semantics here.
            if forced.len() != SEALED_SECRET_LEN {
                return Err(Error::TpmError(format!(
                    "unsealed length {} != expected {}",
                    forced.len(),
                    SEALED_SECRET_LEN
                )));
            }
            let mut out = Zeroizing::new([0u8; SEALED_SECRET_LEN]);
            out.copy_from_slice(forced);
            return Ok(out);
        }
        let key = blob.to_bytes();
        let (secret, expected_pin) = self
            .blobs
            .get(&key)
            .ok_or_else(|| Error::TpmError("unknown sealed blob (rogue chip?)".into()))?;
        // PIN handling mirrors real TPM userAuth semantics: if the
        // blob was sealed with a PIN, the PIN must match at unseal;
        // if it was sealed without one, presenting a PIN is OK
        // (real TPM ignores extra auth on a non-PIN object).
        if let Some(expected) = expected_pin {
            let provided = pin.unwrap_or(b"");
            if provided != expected.as_slice() {
                return Err(Error::TpmError("PIN mismatch (userAuth)".into()));
            }
        }
        let mut out = Zeroizing::new([0u8; SEALED_SECRET_LEN]);
        out.copy_from_slice(secret);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_seal_unseal_roundtrip() {
        let mut tpm = MockTpm2Sealer::new();
        let secret = [0x42u8; SEALED_SECRET_LEN];
        let blob = tpm.seal(&secret).unwrap();
        let out = tpm.unseal(&blob).unwrap();
        assert_eq!(*out, secret);
    }

    #[test]
    fn pin_protected_seal_requires_correct_pin() {
        let mut tpm = MockTpm2Sealer::new();
        let secret = [0x37u8; SEALED_SECRET_LEN];
        let pin = b"1234";
        let blob = tpm.seal_with_pin(&secret, Some(pin)).unwrap();
        // Right PIN works.
        let out = tpm.unseal_with_pin(&blob, Some(pin)).unwrap();
        assert_eq!(*out, secret);
        // Wrong PIN rejected.
        let r = tpm.unseal_with_pin(&blob, Some(b"9999"));
        assert!(matches!(r, Err(Error::TpmError(_))));
        // Missing PIN rejected.
        let r = tpm.unseal_with_pin(&blob, None);
        assert!(matches!(r, Err(Error::TpmError(_))));
    }

    #[test]
    fn forget_blobs_simulates_chip_swap() {
        let mut tpm = MockTpm2Sealer::new();
        let secret = [0x99u8; SEALED_SECRET_LEN];
        let blob = tpm.seal(&secret).unwrap();
        tpm.forget_blobs();
        let r = tpm.unseal(&blob);
        assert!(
            matches!(r, Err(Error::TpmError(_))),
            "forgotten blob must surface as TpmError, got {r:?}"
        );
    }

    #[test]
    fn force_unsealed_bytes_returned_verbatim() {
        let mut tpm = MockTpm2Sealer::new();
        let real_secret = [0x11u8; SEALED_SECRET_LEN];
        let blob = tpm.seal(&real_secret).unwrap();
        let attacker = [0x22u8; SEALED_SECRET_LEN];
        tpm.force_unsealed_bytes(attacker.to_vec());
        let out = tpm.unseal(&blob).unwrap();
        assert_eq!(*out, attacker);
        assert_ne!(*out, real_secret);
    }

    #[test]
    fn force_unsealed_truncated_rejected() {
        let mut tpm = MockTpm2Sealer::new();
        let blob = tpm.seal(&[0u8; SEALED_SECRET_LEN]).unwrap();
        tpm.force_unsealed_truncated(16);
        let r = tpm.unseal(&blob);
        assert!(matches!(r, Err(Error::TpmError(_))));
    }

    #[test]
    fn simulate_unseal_error_is_one_shot() {
        let mut tpm = MockTpm2Sealer::new();
        let secret = [0x55u8; SEALED_SECRET_LEN];
        let blob = tpm.seal(&secret).unwrap();
        tpm.simulate_unseal_error();
        assert!(tpm.unseal(&blob).is_err());
        // Second call clears the flag and succeeds.
        let out = tpm.unseal(&blob).unwrap();
        assert_eq!(*out, secret);
    }
}
