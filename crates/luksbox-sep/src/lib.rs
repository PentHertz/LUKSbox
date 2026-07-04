// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! macOS Secure Enclave (SEP)-backed derive/unwrap of the LUKSbox
//! Master Volume Key. The macOS analog of `luksbox-tpm`.
//!
//! ## Why
//!
//! macOS has no TPM. The closest hardware analog is the Secure
//! Enclave: a coprocessor holding non-extractable P-256 keys. A vault
//! KEK derived against a SEP-resident key can only be re-derived on
//! the originating enclave, so a stolen vault file is uncrackable
//! regardless of passphrase strength.
//!
//! ## Derive, don't seal
//!
//! Unlike the TPM, the SEP has no generic "seal arbitrary bytes"
//! primitive. Its building block is ECDH against a non-extractable
//! P-256 key. So [`SepSealer::seal`] **derives** a 32-byte ECDH shared
//! secret rather than sealing a caller-supplied KEK. That 32-byte
//! value is fed through the SAME HKDF-with-`header_salt` path the TPM
//! keyslots already use (`Keyslot::unlock_tpm2` & friends), so the
//! format layer needs no SEP-specific key derivation.
//!
//! ## Storage
//!
//! Per-slot SEP material (the opaque `dataRepresentation` of the SEP
//! key + the ephemeral public key) is 353-496 B and does not fit the
//! 352 B inline keyslot region. It lives in a `.lbx.sep` sidecar,
//! mirroring how `.lbx.hybrid` stores ML-KEM material. The blob is
//! NOT secret (it's useless off the originating enclave). See
//! `docs/SEP_KEYSLOT_DESIGN.md`.
//!
//! ## Build
//!
//! Gated on the `hardware` Cargo feature AND `target_os = "macos"`. A
//! default workspace build (or any non-macOS target) compiles a no-op
//! stub that errors at runtime, plus the always-available software
//! `mock` used by adversary tests.

use thiserror::Error;

/// Length of the ECDH shared secret returned by seal/unseal (P-256 ->
/// 32 bytes). Named to mirror `luksbox_tpm::SEALED_SECRET_LEN`.
pub const SEALED_SECRET_LEN: usize = 32;

/// Fixed length of a P-256 public key in X9.63 uncompressed form
/// (`0x04 || X || Y`).
pub const EPH_PUB_LEN: usize = 65;

/// Per-slot Secure Enclave material destined for the `.lbx.sep`
/// sidecar. None of this is secret: `sep_data` is an opaque blob
/// usable only on the enclave that produced it, and `eph_pub` is a
/// public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SepBlob {
    /// CryptoKit `dataRepresentation` of the SEP-resident key. ~284 B
    /// plain, ~427 B biometric. Reconstitutable only on the same SEP.
    pub sep_data: Vec<u8>,
    /// Ephemeral P-256 public key (X9.63, 65 B) used in the ECDH.
    pub eph_pub: [u8; EPH_PUB_LEN],
    /// Whether the SEP key is gated behind user presence/biometry.
    pub biometric: bool,
}

impl SepBlob {
    /// Serialize for the sidecar entry. Layout:
    ///   `[flags: u8][sep_data_len: u16 LE][sep_data][eph_pub: 65]`
    /// `flags` bit 0 = biometric.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 2 + self.sep_data.len() + EPH_PUB_LEN);
        out.push(if self.biometric { 1 } else { 0 });
        out.extend_from_slice(&(self.sep_data.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.sep_data);
        out.extend_from_slice(&self.eph_pub);
        out
    }

    /// Inverse of [`SepBlob::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 1 + 2 {
            return Err(Error::BlobMalformed("too short for flags + length prefix"));
        }
        let biometric = bytes[0] & 1 == 1;
        let sep_len = u16::from_le_bytes([bytes[1], bytes[2]]) as usize;
        let sep_start = 3;
        let eph_start = sep_start + sep_len;
        if bytes.len() != eph_start + EPH_PUB_LEN {
            return Err(Error::BlobMalformed("sep_data_len does not match buffer"));
        }
        let sep_data = bytes[sep_start..eph_start].to_vec();
        let mut eph_pub = [0u8; EPH_PUB_LEN];
        eph_pub.copy_from_slice(&bytes[eph_start..eph_start + EPH_PUB_LEN]);
        Ok(Self {
            sep_data,
            eph_pub,
            biometric,
        })
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(
        "Secure Enclave support not compiled into this binary (rebuild luksbox-sep with --features hardware on macOS)"
    )]
    NotCompiledIn,
    #[error("Secure Enclave not available on this machine: {0}")]
    EnclaveUnavailable(String),
    #[error("Secure Enclave operation failed: {0}")]
    SepError(String),
    #[error("SEP blob malformed: {0}")]
    BlobMalformed(&'static str),
}

// ---------- compiled-out stub (no hardware feature, OR non-macOS) ----
//
// Active when EITHER the `hardware` feature is off, OR the target is
// not macOS. Every constructor / op returns `NotCompiledIn`, so
// downstream code that conditionally uses SEP compiles cleanly on
// every platform.

// `sep_real` is emitted by build.rs only on macOS + `hardware` + a
// present Swift toolchain. The stub covers every other case (non-macOS,
// no `hardware`, or a macOS cross-build without swiftc).
#[cfg(not(sep_real))]
mod stub {
    use super::*;
    use zeroize::Zeroizing;

    pub struct SepSealer;

    impl SepSealer {
        pub fn new() -> Result<Self, Error> {
            Err(Error::NotCompiledIn)
        }
        pub fn available() -> bool {
            false
        }
        pub fn seal(&mut self) -> Result<(Zeroizing<[u8; SEALED_SECRET_LEN]>, SepBlob), Error> {
            Err(Error::NotCompiledIn)
        }
        pub fn seal_biometric(
            &mut self,
        ) -> Result<(Zeroizing<[u8; SEALED_SECRET_LEN]>, SepBlob), Error> {
            Err(Error::NotCompiledIn)
        }
        pub fn unseal(
            &mut self,
            _blob: &SepBlob,
        ) -> Result<Zeroizing<[u8; SEALED_SECRET_LEN]>, Error> {
            Err(Error::NotCompiledIn)
        }
    }
}

#[cfg(not(sep_real))]
pub use stub::SepSealer;

// ---------- real Secure Enclave implementation (hardware, macOS) -----

#[cfg(sep_real)]
mod real;

#[cfg(sep_real)]
pub use real::SepSealer;

// ---------- software mock for adversary tests (no feature gate) ------
//
// Lives outside the cfg gate so format/cli adversary tests run on
// Linux CI without a Secure Enclave or Swift toolchain. Production
// code never imports mock.

pub mod mock;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sep_blob_roundtrip() {
        let original = SepBlob {
            sep_data: vec![0xAB; 284],
            eph_pub: [0x04; EPH_PUB_LEN],
            biometric: true,
        };
        let bytes = original.to_bytes();
        let parsed = SepBlob::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn sep_blob_rejects_length_mismatch() {
        let mut bytes = SepBlob {
            sep_data: vec![0x11; 100],
            eph_pub: [0u8; EPH_PUB_LEN],
            biometric: false,
        }
        .to_bytes();
        bytes.push(0); // trailing junk -> length no longer matches
        assert!(matches!(
            SepBlob::from_bytes(&bytes),
            Err(Error::BlobMalformed(_))
        ));
    }

    #[test]
    fn sep_blob_rejects_short_buffer() {
        assert!(matches!(
            SepBlob::from_bytes(&[0u8]),
            Err(Error::BlobMalformed(_))
        ));
    }

    /// When the real backend wasn't built (no `hardware`, non-macOS,
    /// or no swiftc), every op returns `NotCompiledIn`.
    #[cfg(not(sep_real))]
    #[test]
    fn stub_returns_not_compiled_in() {
        assert!(matches!(SepSealer::new(), Err(Error::NotCompiledIn)));
        assert!(!SepSealer::available());
    }
}
