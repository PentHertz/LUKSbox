// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! In-memory `MockSepSealer` for adversary-scenario tests.
//!
//! Mirrors the shape of the real `SepSealer` (seal / seal_biometric /
//! unseal) and the hostile knobs of `luksbox_tpm::mock::MockTpm2Sealer`
//! so format/cli tests can simulate a malicious or replaced Secure
//! Enclave without a real SEP or the Swift toolchain:
//!
//!   - `force_unsealed_bytes(...)`     -every subsequent unseal returns these
//!   - `force_unsealed_truncated(len)` -return len < 32 bytes
//!   - `force_unsealed_oversized(len)` -return len > 32 bytes
//!   - `simulate_unseal_error()`       -next unseal returns Err
//!   - `simulate_seal_error()`         -next seal returns Err
//!   - `forget_blobs()`                -drop all blobs (enclave replaced /
//!     foreign machine; subsequent unseal fails)
//!
//! Keyed by the blob's `sep_data` bytes (the analog of the real SEP's
//! `dataRepresentation`), so a blob produced by one mock instance does
//! not unseal after `forget_blobs()` -- exactly the foreign-enclave
//! rejection the real `init(dataRepresentation:)` enforces.

use std::collections::HashMap;

use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::{EPH_PUB_LEN, Error, SEALED_SECRET_LEN, SepBlob};

pub struct MockSepSealer {
    /// `sep_data -> 32-byte shared secret`.
    blobs: HashMap<Vec<u8>, [u8; SEALED_SECRET_LEN]>,
    forced_unsealed: Option<Vec<u8>>,
    next_unseal_errors: bool,
    next_seal_errors: bool,
}

impl Default for MockSepSealer {
    fn default() -> Self {
        Self::new()
    }
}

impl MockSepSealer {
    pub fn new() -> Self {
        Self {
            blobs: HashMap::new(),
            forced_unsealed: None,
            next_unseal_errors: false,
            next_seal_errors: false,
        }
    }

    pub fn available() -> bool {
        true
    }

    pub fn force_unsealed_bytes(&mut self, bytes: Vec<u8>) {
        self.forced_unsealed = Some(bytes);
    }

    pub fn force_unsealed_truncated(&mut self, len: usize) {
        assert!(len < SEALED_SECRET_LEN, "use force_unsealed_oversized for >= 32");
        self.forced_unsealed = Some(vec![0xa5; len]);
    }

    pub fn force_unsealed_oversized(&mut self, len: usize) {
        assert!(len > SEALED_SECRET_LEN, "use force_unsealed_truncated for < 32");
        self.forced_unsealed = Some(vec![0x5a; len]);
    }

    pub fn simulate_unseal_error(&mut self) {
        self.next_unseal_errors = true;
    }

    pub fn simulate_seal_error(&mut self) {
        self.next_seal_errors = true;
    }

    /// Models the enclave being wiped/replaced, or the vault+sidecar
    /// being moved to a foreign machine: previously-issued blobs no
    /// longer re-derive their shared secret.
    pub fn forget_blobs(&mut self) {
        self.blobs.clear();
    }

    pub fn seal(&mut self) -> Result<(Zeroizing<[u8; SEALED_SECRET_LEN]>, SepBlob), Error> {
        self.seal_inner(false)
    }

    pub fn seal_biometric(&mut self) -> Result<(Zeroizing<[u8; SEALED_SECRET_LEN]>, SepBlob), Error> {
        self.seal_inner(true)
    }

    fn seal_inner(
        &mut self,
        biometric: bool,
    ) -> Result<(Zeroizing<[u8; SEALED_SECRET_LEN]>, SepBlob), Error> {
        if self.next_seal_errors {
            self.next_seal_errors = false;
            return Err(Error::SepError("simulated seal failure".into()));
        }
        // Mimic the real size envelope (284 B plain / 427 B biometric)
        // so round-trips through SepBlob serialization exercise the
        // same length handling.
        let mut sep_data = vec![0u8; if biometric { 427 } else { 284 }];
        OsRng.fill_bytes(&mut sep_data);
        let mut eph_pub = [0u8; EPH_PUB_LEN];
        OsRng.fill_bytes(&mut eph_pub);
        eph_pub[0] = 0x04; // x963 uncompressed tag, cosmetic for the mock
        let mut shared = [0u8; SEALED_SECRET_LEN];
        OsRng.fill_bytes(&mut shared);

        self.blobs.insert(sep_data.clone(), shared);
        let out = Zeroizing::new(shared);
        Ok((
            out,
            SepBlob {
                sep_data,
                eph_pub,
                biometric,
            },
        ))
    }

    pub fn unseal(&mut self, blob: &SepBlob) -> Result<Zeroizing<[u8; SEALED_SECRET_LEN]>, Error> {
        if self.next_unseal_errors {
            self.next_unseal_errors = false;
            return Err(Error::SepError("simulated unseal failure".into()));
        }
        if let Some(forced) = &self.forced_unsealed {
            if forced.len() != SEALED_SECRET_LEN {
                return Err(Error::SepError(format!(
                    "shared secret length {} != expected {}",
                    forced.len(),
                    SEALED_SECRET_LEN
                )));
            }
            let mut out = Zeroizing::new([0u8; SEALED_SECRET_LEN]);
            out.copy_from_slice(forced);
            return Ok(out);
        }
        let shared = self
            .blobs
            .get(&blob.sep_data)
            .ok_or_else(|| Error::SepError("unknown SEP blob (foreign enclave?)".into()))?;
        let mut out = Zeroizing::new([0u8; SEALED_SECRET_LEN]);
        out.copy_from_slice(shared);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_seal_unseal_roundtrip() {
        let mut sep = MockSepSealer::new();
        let (kek, blob) = sep.seal().unwrap();
        let out = sep.unseal(&blob).unwrap();
        assert_eq!(*out, *kek);
    }

    #[test]
    fn biometric_blob_is_larger() {
        let mut sep = MockSepSealer::new();
        let (_, plain) = sep.seal().unwrap();
        let (_, bio) = sep.seal_biometric().unwrap();
        assert!(bio.biometric);
        assert!(bio.sep_data.len() > plain.sep_data.len());
    }

    #[test]
    fn forget_blobs_simulates_foreign_enclave() {
        let mut sep = MockSepSealer::new();
        let (_, blob) = sep.seal().unwrap();
        sep.forget_blobs();
        assert!(matches!(sep.unseal(&blob), Err(Error::SepError(_))));
    }

    #[test]
    fn force_unsealed_bytes_returned_verbatim() {
        let mut sep = MockSepSealer::new();
        let (real, blob) = sep.seal().unwrap();
        let attacker = [0x22u8; SEALED_SECRET_LEN];
        sep.force_unsealed_bytes(attacker.to_vec());
        let out = sep.unseal(&blob).unwrap();
        assert_eq!(*out, attacker);
        assert_ne!(*out, *real);
    }

    #[test]
    fn force_unsealed_truncated_rejected() {
        let mut sep = MockSepSealer::new();
        let (_, blob) = sep.seal().unwrap();
        sep.force_unsealed_truncated(16);
        assert!(matches!(sep.unseal(&blob), Err(Error::SepError(_))));
    }

    #[test]
    fn simulate_unseal_error_is_one_shot() {
        let mut sep = MockSepSealer::new();
        let (kek, blob) = sep.seal().unwrap();
        sep.simulate_unseal_error();
        assert!(sep.unseal(&blob).is_err());
        let out = sep.unseal(&blob).unwrap();
        assert_eq!(*out, *kek);
    }
}
