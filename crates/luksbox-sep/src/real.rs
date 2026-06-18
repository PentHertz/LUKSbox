// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Real Secure Enclave backend: thin `extern "C"` bridge to the
//! CryptoKit Swift shim (`swift/SepShim.swift`, linked by build.rs).
//! Compiled only on `all(feature = "hardware", target_os = "macos")`.
//!
//! No Swift types cross the boundary: the shim writes into caller
//! buffers and returns an `i32` status. We never marshal the SEP
//! private key (it never leaves the enclave) -- only the 32-byte ECDH
//! shared secret, the opaque `dataRepresentation`, and a public key.

use zeroize::Zeroizing;

use crate::{EPH_PUB_LEN, Error, SEALED_SECRET_LEN, SepBlob};

// Generous upper bound for the SEP `dataRepresentation`. Measured 284 B
// (plain) / 427 B (biometric) on Apple M2 / current macOS; Apple does
// not contractually fix this, so we leave headroom and treat overflow
// as ERR_BUFFER rather than a silent truncation.
const SEP_DATA_CAP: usize = 1024;

const OK: i32 = 0;
const ERR_UNAVAILABLE: i32 = -1;
const ERR_SEAL: i32 = -2;
const ERR_BUFFER: i32 = -3;
const ERR_UNSEAL: i32 = -4;

unsafe extern "C" {
    fn luksbox_sep_available() -> i32;
    fn luksbox_sep_seal(
        biometric: i32,
        out_shared: *mut u8,
        out_sep_data: *mut u8,
        out_sep_data_cap: usize,
        out_sep_data_len: *mut usize,
        out_eph_pub: *mut u8,
    ) -> i32;
    fn luksbox_sep_unseal(
        biometric: i32,
        sep_data: *const u8,
        sep_data_len: usize,
        eph_pub: *const u8,
        out_shared: *mut u8,
    ) -> i32;
}

fn seal_status_err(code: i32) -> Error {
    match code {
        ERR_UNAVAILABLE => Error::EnclaveUnavailable("SecureEnclave.isAvailable == false".into()),
        ERR_BUFFER => Error::SepError("dataRepresentation exceeded buffer capacity".into()),
        ERR_SEAL => Error::SepError("Secure Enclave key generation / agreement failed".into()),
        other => Error::SepError(format!("seal failed (status {other})")),
    }
}

/// Real Secure Enclave sealer. Holds no state of its own; each call is
/// an independent SEP operation. Construction merely confirms an
/// enclave is present, matching `Tpm2Sealer::new()`'s contract.
pub struct SepSealer {
    _private: (),
}

impl SepSealer {
    pub fn new() -> Result<Self, Error> {
        if Self::available() {
            Ok(Self { _private: () })
        } else {
            Err(Error::EnclaveUnavailable(
                "no Secure Enclave on this machine".into(),
            ))
        }
    }

    pub fn available() -> bool {
        // SAFETY: the shim function takes no args and returns a plain i32.
        unsafe { luksbox_sep_available() == 1 }
    }

    pub fn seal(&mut self) -> Result<(Zeroizing<[u8; SEALED_SECRET_LEN]>, SepBlob), Error> {
        self.seal_inner(false)
    }

    pub fn seal_biometric(
        &mut self,
    ) -> Result<(Zeroizing<[u8; SEALED_SECRET_LEN]>, SepBlob), Error> {
        self.seal_inner(true)
    }

    fn seal_inner(
        &mut self,
        biometric: bool,
    ) -> Result<(Zeroizing<[u8; SEALED_SECRET_LEN]>, SepBlob), Error> {
        let mut shared = Zeroizing::new([0u8; SEALED_SECRET_LEN]);
        let mut sep_data = vec![0u8; SEP_DATA_CAP];
        let mut sep_data_len: usize = 0;
        let mut eph_pub = [0u8; EPH_PUB_LEN];

        // SAFETY: all pointers reference live, correctly-sized buffers;
        // the shim writes at most `SEP_DATA_CAP` bytes into `sep_data`
        // (enforced shim-side; ERR_BUFFER otherwise) and exactly 32 /
        // 65 bytes into the fixed arrays.
        let status = unsafe {
            luksbox_sep_seal(
                biometric as i32,
                shared.as_mut_ptr(),
                sep_data.as_mut_ptr(),
                SEP_DATA_CAP,
                &mut sep_data_len,
                eph_pub.as_mut_ptr(),
            )
        };
        if status != OK {
            return Err(seal_status_err(status));
        }
        if sep_data_len == 0 || sep_data_len > SEP_DATA_CAP {
            return Err(Error::SepError("shim reported invalid sep_data length".into()));
        }
        reject_null_secret(&shared)?;
        sep_data.truncate(sep_data_len);
        Ok((
            shared,
            SepBlob {
                sep_data,
                eph_pub,
                biometric,
            },
        ))
    }

    pub fn unseal(&mut self, blob: &SepBlob) -> Result<Zeroizing<[u8; SEALED_SECRET_LEN]>, Error> {
        let mut shared = Zeroizing::new([0u8; SEALED_SECRET_LEN]);
        // SAFETY: input slices are valid for their stated lengths and
        // `out_shared` points at a live 32-byte buffer.
        let status = unsafe {
            luksbox_sep_unseal(
                blob.biometric as i32,
                blob.sep_data.as_ptr(),
                blob.sep_data.len(),
                blob.eph_pub.as_ptr(),
                shared.as_mut_ptr(),
            )
        };
        match status {
            OK => {
                reject_null_secret(&shared)?;
                Ok(shared)
            }
            ERR_UNSEAL => Err(Error::SepError(
                "unseal failed (foreign enclave, revoked key, or cancelled auth)".into(),
            )),
            other => Err(Error::SepError(format!("unseal failed (status {other})"))),
        }
    }
}

/// Reject an all-zero ECDH shared secret. A healthy P-256 agreement
/// never yields all zeros; an all-zero value would signal a degenerate
/// / invalid-curve agreement or a broken shim. Refuse it at the source
/// so a null secret never reaches the keyslot KEK derivation.
fn reject_null_secret(shared: &[u8; SEALED_SECRET_LEN]) -> Result<(), Error> {
    if shared.iter().all(|&b| b == 0) {
        return Err(Error::SepError("degenerate all-zero shared secret".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real-hardware round-trip. Runs only when a Secure Enclave is
    // present; otherwise it cleanly no-ops so CI on SEP-less runners
    // (or the stub build) stays green. No biometric here -- that needs
    // a GUI bundle + human touch (see docs/SEP_KEYSLOT_DESIGN.md §7).
    #[test]
    fn hardware_seal_unseal_roundtrip() {
        if !SepSealer::available() {
            eprintln!("skipping: no Secure Enclave on this machine");
            return;
        }
        let mut sep = SepSealer::new().unwrap();
        let (kek, blob) = sep.seal().unwrap();
        assert_eq!(blob.eph_pub.len(), EPH_PUB_LEN);
        assert!(!blob.sep_data.is_empty());
        let out = sep.unseal(&blob).unwrap();
        assert_eq!(*out, *kek, "re-derived shared secret must match");
    }
}
