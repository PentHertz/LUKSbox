// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Linux + Windows TPM 2.0-backed wrap/unwrap of the LUKSbox Master
//! Volume Key.
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
//! builds enable the feature against the system tpm2-tss; Windows
//! release builds enable `bundled-tpm` (vendored tpm2-tss, since
//! Windows has no system copy - the TPM is reached through the
//! in-box TBS broker instead of a device node). Targets without a
//! backend (macOS, BSDs) compile a no-op stub that errors at runtime
//! if anything tries to use the API.

use thiserror::Error;
#[cfg(any(
    not(feature = "hardware"),
    not(any(target_os = "linux", target_os = "windows"))
))]
use zeroize::Zeroizing;

/// 32-byte secret container (the MVK). Wrapping/unwrapping this
/// length-fixed type makes the API safer than passing arbitrary
/// `&[u8]` everywhere.
pub const SEALED_SECRET_LEN: usize = 32;

/// Length of a pinned SRK identity (R15-F5): the first 16 bytes of a
/// domain-separated SHA-256 over the SRK's marshalled public area.
/// 128 bits of second-preimage resistance is far beyond what an
/// interposer forging an ECC public area could search, and the short
/// pin keeps a fused TPM+FIDO2 blob inside the 352-byte slot region.
pub const SRK_PIN_LEN: usize = 16;

/// Leading bytes of a pinned `SealedBlob` encoding. A legacy blob
/// starts with its `public_len: u16 LE`; 0xFFFF there would claim a
/// 64 KiB public area, which no slot can hold, so the two encodings
/// never collide and pre-R15-F5 binaries reject a pinned blob as
/// malformed instead of unsealing without the check.
const PINNED_BLOB_MARKER: [u8; 2] = [0xFF, 0xFF];
const PINNED_BLOB_VERSION: u8 = 2;
const SRK_PIN_LABEL: &[u8] = b"luksbox-tpm-srk-pin/v1";

/// SRK identity pinned into a sealed blob, from the marshalled
/// TPMT_PUBLIC that `CreatePrimary` returned for the SRK.
pub fn srk_pin_from_public(marshalled_public: &[u8]) -> [u8; SRK_PIN_LEN] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(SRK_PIN_LABEL);
    h.update(marshalled_public);
    let d = h.finalize();
    let mut pin = [0u8; SRK_PIN_LEN];
    pin.copy_from_slice(&d[..SRK_PIN_LEN]);
    pin
}

/// Whether serialized blob bytes (as stored in a keyslot) carry an SRK
/// pin. For display (`luksbox info`); unseal parses the blob anyway.
pub fn blob_is_srk_pinned(bytes: &[u8]) -> bool {
    bytes.starts_with(&PINNED_BLOB_MARKER)
}

static DEFAULT_SRK_PINNING: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Process-wide default for SRK pinning of NEW seals (R15-F5), read by
/// every `Tpm2Sealer` constructor. The CLI sets it from `--tpm-pin-srk`
/// and the GUI from its preference, so the many enroll / create paths
/// do not each need a parameter. Unsealing always enforces a pin that
/// a blob carries, whatever this says. Off by default: a pinned blob
/// cannot be unsealed by LUKSbox versions before the pinning release.
pub fn set_default_srk_pinning(on: bool) {
    DEFAULT_SRK_PINNING.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// Current process-wide default, see `set_default_srk_pinning`.
pub fn default_srk_pinning() -> bool {
    DEFAULT_SRK_PINNING.load(std::sync::atomic::Ordering::Relaxed)
}

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
    /// R15-F5: identity of the SRK the object was sealed under
    /// (`srk_pin_from_public`). When present, unseal refuses to start
    /// the salted session unless the SRK the TPM returns hashes to it:
    /// an ACTIVE bus interposer that substitutes its own public area in
    /// the `CreatePrimary` response would otherwise receive the session
    /// salt encrypted to its key and read the unsealed KEK.
    pub srk_pin: Option<[u8; SRK_PIN_LEN]>,
}

impl SealedBlob {
    /// Concatenate the two blobs with `u16` length prefixes for
    /// embedding in a fixed-size keyslot. Layout:
    ///   `[public_len: u16 LE | public_bytes | private_len: u16 LE | private_bytes]`
    /// A pinned blob (R15-F5) is prefixed with
    ///   `[0xFF 0xFF | version = 2 | srk_pin (16 B)]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(3 + SRK_PIN_LEN + 4 + self.public.len() + self.private.len());
        if let Some(pin) = &self.srk_pin {
            out.extend_from_slice(&PINNED_BLOB_MARKER);
            out.push(PINNED_BLOB_VERSION);
            out.extend_from_slice(pin);
        }
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
        let (srk_pin, bytes) = if bytes.starts_with(&PINNED_BLOB_MARKER) {
            if bytes.len() < 3 + SRK_PIN_LEN {
                return Err(Error::BlobMalformed(
                    "pinned blob too short for its SRK pin",
                ));
            }
            if bytes[2] != PINNED_BLOB_VERSION {
                return Err(Error::BlobMalformed("unknown pinned-blob version"));
            }
            let mut pin = [0u8; SRK_PIN_LEN];
            pin.copy_from_slice(&bytes[3..3 + SRK_PIN_LEN]);
            (Some(pin), &bytes[3 + SRK_PIN_LEN..])
        } else {
            (None, bytes)
        };
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
        Ok(Self {
            public,
            private,
            srk_pin,
        })
    }
}

/// `Error::NotCompiledIn` text. A Mac has no TPM 2.0 at all, so a
/// rebuild hint would only mislead there.
const NOT_COMPILED_IN_MSG: &str = if cfg!(target_os = "macos") {
    "macOS has no TPM 2.0; TPM keyslots open only on the Linux / Windows machine that \
     sealed them (on a Mac use Secure Enclave keyslots)"
} else {
    "TPM 2.0 support not compiled into this binary (rebuild with --features hardware, or \
     --features bundled-tpm on Windows / older distros)"
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("{}", NOT_COMPILED_IN_MSG)]
    NotCompiledIn,
    #[error("TPM device not available: {0}")]
    DeviceNotAvailable(String),
    #[error("TPM operation failed: {0}")]
    TpmError(String),
    #[error("sealed blob malformed: {0}")]
    BlobMalformed(&'static str),
    /// R15-F5: the SRK returned by `CreatePrimary` is not the one the
    /// blob was sealed under. Nothing secret was sent to the TPM.
    #[error(
        "the TPM's storage root key does not match the one this keyslot was sealed under; \
         refusing to unseal. Either the TPM was cleared or replaced (the slot can no \
         longer be unsealed on this machine), or something between this computer and \
         the TPM substituted the key (a TPM-bus interposer)"
    )]
    SrkMismatch,
}

// ---------- compiled-out stub (no hardware feature, OR no backend) ----
//
// Active when EITHER the `hardware` feature is off, OR the target is
// neither Linux nor Windows. tss-esapi has no backend for macOS and
// the BSDs, so even if a parent crate enables `hardware`
// unconditionally we have to fall through to the stub there. The
// runtime behaviour is the same: every constructor / op returns
// `NotCompiledIn`. See Cargo.toml for the matching target-gated dep.

#[cfg(any(
    not(feature = "hardware"),
    not(any(target_os = "linux", target_os = "windows"))
))]
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
        pub fn set_srk_pinning(&mut self, _on: bool) {}
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

#[cfg(any(
    not(feature = "hardware"),
    not(any(target_os = "linux", target_os = "windows"))
))]
pub use stub::Tpm2Sealer;

// ---------- real TPM 2.0 implementation (hardware, Linux/Windows) -----

/// True when this build talks to a real TPM 2.0 (`hardware` feature on
/// Linux / Windows); otherwise `Tpm2Sealer::new` is a stub that always
/// fails. Front ends use it to hide TPM options the build cannot honour
/// instead of failing after the user typed every other factor.
pub const BACKEND_COMPILED: bool = cfg!(all(
    feature = "hardware",
    any(target_os = "linux", target_os = "windows")
));

#[cfg(all(feature = "hardware", any(target_os = "linux", target_os = "windows")))]
mod real;

#[cfg(all(feature = "hardware", any(target_os = "linux", target_os = "windows")))]
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
#[cfg(any(
    not(feature = "hardware"),
    not(any(target_os = "linux", target_os = "windows"))
))]
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
            srk_pin: None,
        };
        let bytes = original.to_bytes();
        let parsed = SealedBlob::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, original);
    }

    /// R15-F5: the pinned encoding round-trips, is recognisable, and
    /// adds exactly 19 bytes.
    #[test]
    fn pinned_sealed_blob_roundtrip() {
        let legacy = SealedBlob {
            public: vec![0xAA; 80],
            private: vec![0xBB; 200],
            srk_pin: None,
        };
        let pinned = SealedBlob {
            srk_pin: Some(srk_pin_from_public(b"srk public area")),
            ..legacy.clone()
        };
        let bytes = pinned.to_bytes();
        assert_eq!(bytes.len(), legacy.to_bytes().len() + 3 + SRK_PIN_LEN);
        assert!(blob_is_srk_pinned(&bytes));
        assert!(!blob_is_srk_pinned(&legacy.to_bytes()));
        assert_eq!(SealedBlob::from_bytes(&bytes).unwrap(), pinned);
    }

    /// What a pre-R15-F5 parser sees in a pinned blob: a 0xFFFF public
    /// length that overruns any slot, i.e. a clean `BlobMalformed`.
    #[test]
    fn pinned_blob_is_malformed_for_legacy_parsers() {
        let pinned = SealedBlob {
            public: vec![1; 80],
            private: vec![2; 200],
            srk_pin: Some([3; SRK_PIN_LEN]),
        }
        .to_bytes();
        let legacy_pub_len = u16::from_le_bytes([pinned[0], pinned[1]]) as usize;
        assert!(legacy_pub_len + 4 > pinned.len());
        // And an unknown future pinned version is refused, not guessed.
        let mut future = pinned.clone();
        future[2] = 3;
        assert!(matches!(
            SealedBlob::from_bytes(&future),
            Err(Error::BlobMalformed(_))
        ));
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
    /// the feature. Same path activates on macOS and other
    /// backend-less targets even with the feature on, because
    /// tss-esapi doesn't build there.
    #[cfg(any(
        not(feature = "hardware"),
        not(any(target_os = "linux", target_os = "windows"))
    ))]
    #[test]
    fn stub_returns_not_compiled_in() {
        assert!(matches!(Tpm2Sealer::new(), Err(Error::NotCompiledIn)));
    }
}
