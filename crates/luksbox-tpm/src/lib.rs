// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Linux TPM 2.0-backed wrap/unwrap of the LUKSbox Master Volume Key.
//!
//! ## Why
//!
//! The MVK is normally wrapped under a passphrase- or FIDO2-derived
//! KEK and stored in a keyslot inside the .lbx file. A stolen vault
//! file is exposed to passphrase brute-force (slowed by Argon2id but
//! eventually feasible for weak passphrases).
//!
//! With TPM wrapping, the wrap key lives inside the TPM 2.0 chip on
//! the user's machine. Unwrapping requires the original chip - a
//! stolen vault file alone is uncrackable, regardless of passphrase
//! strength, because the TPM enforces a dictionary-attack lockout.
//!
//! ## What this crate does (and does not)
//!
//! - **Does**: seal a 32-byte secret (the MVK) under a TPM-resident
//!   Storage Root Key derived from the chip's persistent endorsement
//!   seed; returns a portable `SealedBlob` (the TPM2B_PUBLIC +
//!   TPM2B_PRIVATE bytes) suitable for storage in a keyslot. Unseal
//!   the same blob back to the original 32-byte secret on the same
//!   machine.
//!
//! - **Does NOT (yet)**:
//!   - PCR sealing (boot-chain-tamper detection). Future opt-in flag.
//!   - User PIN / authValue. Future opt-in flag.
//!   - Per-chunk AEAD via TPM. We deliberately keep AEAD in-process
//!     under the unwrapped MVK; TPM is wrap-only because per-chunk
//!     IPC kills throughput (TPMs do 1-10 MB/s symmetric vs. our
//!     in-process about 590 MB/s with AES-NI).
//!
//! ## Build
//!
//! Gated on the `hardware` Cargo feature so a default workspace
//! build doesn't require `libtss2-esys-dev` installed. Linux release
//! builds enable the feature; non-Linux targets compile a no-op stub
//! that errors at runtime if anything tries to use the API.

use thiserror::Error;
#[cfg(any(not(feature = "hardware"), not(target_os = "linux")))]
use zeroize::Zeroizing;

/// 32-byte secret container (the MVK). Wrapping/unwrapping this
/// length-fixed type makes the API safer than passing arbitrary
/// `&[u8]` everywhere.
pub const SEALED_SECRET_LEN: usize = 32;

/// On-disk format of a TPM-sealed secret. The two `Vec<u8>` fields
/// are the marshalled TPM2B_PUBLIC and TPM2B_PRIVATE blobs returned
/// by `Esys_Create`. The wire representation is platform-portable
/// across TPM implementations because TPM2B_* structures are TCG-
/// standardised; what's NOT portable is the ability to *unseal* it
/// (that requires the same chip's endorsement seed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedBlob {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

impl SealedBlob {
    /// Concatenate the two blobs with `u16` length prefixes for
    /// embedding in a fixed-size keyslot. Layout:
    ///   `[public_len: u16 LE | public_bytes | private_len: u16 LE | private_bytes]`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.public.len() + self.private.len());
        out.extend_from_slice(&(self.public.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.public);
        out.extend_from_slice(&(self.private.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.private);
        out
    }

    /// Inverse of `to_bytes`. Returns `Err(BlobMalformed)` if the
    /// length prefixes don't match the actual byte counts (happens
    /// when a slot was truncated or written by a buggy version).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 4 {
            return Err(Error::BlobMalformed("too short for both length prefixes"));
        }
        let pub_len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
        if bytes.len() < 2 + pub_len + 2 {
            return Err(Error::BlobMalformed("public_len overruns buffer"));
        }
        let public = bytes[2..2 + pub_len].to_vec();
        let priv_off = 2 + pub_len;
        let priv_len = u16::from_le_bytes([bytes[priv_off], bytes[priv_off + 1]]) as usize;
        if bytes.len() < priv_off + 2 + priv_len {
            return Err(Error::BlobMalformed("private_len overruns buffer"));
        }
        let private = bytes[priv_off + 2..priv_off + 2 + priv_len].to_vec();
        Ok(Self { public, private })
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(
        "TPM 2.0 support not compiled into this binary (rebuild luksbox-tpm with --features hardware)"
    )]
    NotCompiledIn,
    #[error("TPM device not available: {0}")]
    DeviceNotAvailable(String),
    #[error("TPM operation failed: {0}")]
    TpmError(String),
    #[error("sealed blob malformed: {0}")]
    BlobMalformed(&'static str),
}

// ---------- compiled-out stub (no hardware feature, OR non-Linux) -----
//
// Active when EITHER the `hardware` feature is off, OR the target is
// not Linux. tss-esapi 7.x's -sys crate hard-panics in build.rs on
// Windows/macOS, so even if a parent crate enables `hardware`
// unconditionally we have to fall through to the stub there. The
// runtime behaviour is the same: every constructor / op returns
// `NotCompiledIn`. See Cargo.toml for the matching target-gated dep.

#[cfg(any(not(feature = "hardware"), not(target_os = "linux")))]
mod stub {
    use super::*;

    pub struct Tpm2Sealer;

    impl Tpm2Sealer {
        pub fn new() -> Result<Self, Error> {
            Err(Error::NotCompiledIn)
        }
        pub fn from_tcti_str(_tcti: &str) -> Result<Self, Error> {
            Err(Error::NotCompiledIn)
        }
        pub fn seal(&mut self, _plaintext: &[u8; SEALED_SECRET_LEN]) -> Result<SealedBlob, Error> {
            Err(Error::NotCompiledIn)
        }
        pub fn seal_with_pin(
            &mut self,
            _plaintext: &[u8; SEALED_SECRET_LEN],
            _pin: Option<&[u8]>,
        ) -> Result<SealedBlob, Error> {
            Err(Error::NotCompiledIn)
        }
        pub fn unseal(
            &mut self,
            _blob: &SealedBlob,
        ) -> Result<Zeroizing<[u8; SEALED_SECRET_LEN]>, Error> {
            Err(Error::NotCompiledIn)
        }
        pub fn unseal_with_pin(
            &mut self,
            _blob: &SealedBlob,
            _pin: Option<&[u8]>,
        ) -> Result<Zeroizing<[u8; SEALED_SECRET_LEN]>, Error> {
            Err(Error::NotCompiledIn)
        }
    }
}

#[cfg(any(not(feature = "hardware"), not(target_os = "linux")))]
pub use stub::Tpm2Sealer;

// ---------- real TPM 2.0 implementation (hardware feature, Linux) -----

#[cfg(all(feature = "hardware", target_os = "linux"))]
mod real;

#[cfg(all(feature = "hardware", target_os = "linux"))]
pub use real::{Tpm2Sealer, diagnose_operation_error};

// ---------- mock TPM for adversary tests (no feature gate) -----------
//
// Lives outside the `hardware` cfg gate because adversary tests at the
// format / vfs / cli layer should be able to exercise the rogue-TPM
// scenarios without requiring tss-esapi / libtss2-* on the build
// machine. Production code never imports mock; production goes through
// the gated `Tpm2Sealer` above.

pub mod mock;

/// Stub for non-hardware builds. Mirrors the real `diagnose_operation_error`
/// signature so callers can use the same code path on every platform.
#[cfg(any(not(feature = "hardware"), not(target_os = "linux")))]
pub fn diagnose_operation_error(_raw: &str) -> Option<&'static str> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SealedBlob round-trips through to_bytes / from_bytes. This
    /// works without hardware because it's pure serialization.
    #[test]
    fn sealed_blob_roundtrip() {
        let original = SealedBlob {
            public: vec![0xAA; 80],
            private: vec![0xBB; 200],
        };
        let bytes = original.to_bytes();
        let parsed = SealedBlob::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn sealed_blob_rejects_truncated_buffer() {
        // Just a length prefix claiming 100 bytes follow, but the
        // buffer has only 4 bytes total.
        let bytes = vec![100u8, 0u8, 0u8, 0u8];
        assert!(matches!(
            SealedBlob::from_bytes(&bytes),
            Err(Error::BlobMalformed(_))
        ));
    }

    #[test]
    fn sealed_blob_rejects_short_buffer() {
        assert!(matches!(
            SealedBlob::from_bytes(&[0u8]),
            Err(Error::BlobMalformed(_))
        ));
    }

    /// Without `--features hardware`, the API exists but every
    /// constructor / op returns `NotCompiledIn`. Lets downstream
    /// code that conditionally uses TPM compile cleanly without
    /// the feature. Same path activates on non-Linux even with the
    /// feature on, because tss-esapi 7.x doesn't build there.
    #[cfg(any(not(feature = "hardware"), not(target_os = "linux")))]
    #[test]
    fn stub_returns_not_compiled_in() {
        assert!(matches!(Tpm2Sealer::new(), Err(Error::NotCompiledIn)));
    }
}
