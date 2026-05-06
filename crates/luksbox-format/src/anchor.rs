// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! External anchor file for rollback detection.
//!
//! ## What this is
//!
//! Per-chunk replay protection (the vault-wide monotonic generation
//! counter included in chunk AAD) catches an attacker who substitutes
//! ONE chunk into the live vault. It does NOT catch an attacker who
//! rolls back the ENTIRE `.lbx` to a consistent older snapshot.
//!
//! The anchor file is a 48-byte sidecar containing the vault's current
//! generation counter, MAC'd under a key derived from the MVK. On every
//! write that bumps the generation, we update the anchor. On every open,
//! we read the anchor and compare to the generation in the (now-decrypted)
//! metadata blob:
//!
//! - `anchor.generation == metadata.generation` -> all good.
//! - `anchor.generation > metadata.generation` -> **rollback detected**;
//!   refuse to open (someone substituted an older `.lbx`).
//! - `anchor.generation < metadata.generation` -> warn (user wrote
//!   without the anchor present; not necessarily an attack).
//!
//! ## Threat model, honest version
//!
//! For this to actually defeat rollback, the anchor file must live on
//! storage the attacker **cannot** roll back along with the `.lbx`. If
//! both are on the same disk, an attacker who has the disk has both,
//! and can roll them back together. The anchor is meaningful only when
//! kept on physically separate, trusted storage:
//!
//! - A USB stick the user carries (and never leaves with the laptop)
//! - A YubiKey's PIV applet (32-64 bytes, plenty of space)
//! - A network service the user trusts (cloud KMS, etc.)
//! - A TPM2 NV counter (out of scope for v1; spec'd in SECURITY.md)
//!
//! On its own, with anchor + vault on the same medium, this is just
//! integrity-checking the user's own write history.
//!
//! ## File format (48 bytes)
//!
//! ```text
//!   0..8    magic = b"LBXANCH1"
//!   8..16   vault_generation u64 LE  (== tree.next_chunk_gen at write)
//!  16..48   HMAC-SHA256(anchor_key, bytes[0..16])
//! ```
//!
//! `anchor_key = HKDF(MVK, header_salt, "lbx:anchor-mac/v1")`. Without
//! the MVK an attacker can't forge a fresh anchor with arbitrary
//! generation. But they CAN copy any past anchor that was created with
//! the same MVK, which is exactly why we compare counter values.

use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;

use hmac::{Hmac, Mac};
use luksbox_core::MasterVolumeKey;
use luksbox_core::file_util::atomic_secure_write;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::Error;

const MAGIC: [u8; 8] = *b"LBXANCH1";
const ANCHOR_INFO: &[u8] = b"lbx:anchor-mac/v1";
pub const ANCHOR_SIZE: usize = 48;

#[derive(Debug, Clone, Copy)]
pub struct AnchorContents {
    pub generation: u64,
}

fn anchor_key(mvk: &MasterVolumeKey, header_salt: &[u8; 32]) -> [u8; 32] {
    let key = mvk.derive_subkey(header_salt, ANCHOR_INFO);
    *key
}

fn compute_mac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("any-len HMAC key");
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&out);
    tag
}

/// Read and verify an anchor file. Returns the trusted generation counter,
/// or an error if the magic is wrong or the MAC doesn't verify under the
/// MVK-derived key.
pub fn read_and_verify(
    path: &Path,
    mvk: &MasterVolumeKey,
    header_salt: &[u8; 32],
) -> Result<AnchorContents, Error> {
    let mut f = OpenOptions::new().read(true).open(path)?;
    let mut buf = [0u8; ANCHOR_SIZE];
    f.read_exact(&mut buf)?;
    if buf[..8] != MAGIC {
        return Err(Error::AnchorCorrupt);
    }
    let key = anchor_key(mvk, header_salt);
    let expected = compute_mac(&key, &buf[..16]);
    if expected.ct_eq(&buf[16..48]).unwrap_u8() == 0 {
        return Err(Error::AnchorAuthFailed);
    }
    let mut gen_bytes = [0u8; 8];
    gen_bytes.copy_from_slice(&buf[8..16]);
    Ok(AnchorContents {
        generation: u64::from_le_bytes(gen_bytes),
    })
}

/// Write a fresh anchor file containing the given generation counter,
/// MAC'd under the MVK-derived anchor key. Atomic via temp-file +
/// rename, a crash between the temp write and the rename leaves the
/// previous anchor intact (good).
pub fn write(
    path: &Path,
    generation: u64,
    mvk: &MasterVolumeKey,
    header_salt: &[u8; 32],
) -> Result<(), Error> {
    let mut buf = [0u8; ANCHOR_SIZE];
    buf[..8].copy_from_slice(&MAGIC);
    buf[8..16].copy_from_slice(&generation.to_le_bytes());
    let key = anchor_key(mvk, header_salt);
    let tag = compute_mac(&key, &buf[..16]);
    buf[16..48].copy_from_slice(&tag);

    // Round 9E: atomic_secure_write produces a 0600 tmpfile with
    // a random suffix, fsyncs, then renames atomically. Replaces the
    // previous "fixed-name .tmp + plain OpenOptions" path which left
    // the tmpfile world-readable for the brief window before rename
    // (under default umask 022).
    atomic_secure_write(path, &buf)?;
    Ok(())
}

/// Outcome of comparing the anchor's generation against the metadata's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationOutcome {
    /// Generations match. Safe to proceed.
    Ok,
    /// Anchor's generation is HIGHER than the metadata's, the vault
    /// file was rolled back. Refuse to open.
    RollbackDetected { anchor_gen: u64, metadata_gen: u64 },
    /// Anchor's generation is LOWER than the metadata's, vault was
    /// written without the anchor in place. Warn but proceed.
    AnchorStale { anchor_gen: u64, metadata_gen: u64 },
}

pub fn compare(anchor_gen: u64, metadata_gen: u64) -> VerificationOutcome {
    use std::cmp::Ordering;
    match anchor_gen.cmp(&metadata_gen) {
        Ordering::Equal => VerificationOutcome::Ok,
        Ordering::Greater => VerificationOutcome::RollbackDetected {
            anchor_gen,
            metadata_gen,
        },
        Ordering::Less => VerificationOutcome::AnchorStale {
            anchor_gen,
            metadata_gen,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.anchor");
        let mvk = MasterVolumeKey::from_bytes([0x42; 32]);
        let salt = [0x77u8; 32];
        write(&path, 12345, &mvk, &salt).unwrap();
        let r = read_and_verify(&path, &mvk, &salt).unwrap();
        assert_eq!(r.generation, 12345);
    }

    #[test]
    fn wrong_mvk_fails_mac() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.anchor");
        let mvk = MasterVolumeKey::from_bytes([0x42; 32]);
        let salt = [0x77u8; 32];
        write(&path, 5, &mvk, &salt).unwrap();
        let other = MasterVolumeKey::from_bytes([0x99; 32]);
        assert!(matches!(
            read_and_verify(&path, &other, &salt),
            Err(Error::AnchorAuthFailed)
        ));
    }

    #[test]
    fn tampered_generation_fails_mac() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a.anchor");
        let mvk = MasterVolumeKey::from_bytes([0x42; 32]);
        let salt = [0x77u8; 32];
        write(&path, 5, &mvk, &salt).unwrap();
        // Bit-flip the generation field.
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[8] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(
            read_and_verify(&path, &mvk, &salt),
            Err(Error::AnchorAuthFailed)
        ));
    }

    #[test]
    fn compare_classifies_correctly() {
        assert_eq!(compare(5, 5), VerificationOutcome::Ok);
        assert!(matches!(
            compare(10, 5),
            VerificationOutcome::RollbackDetected { .. }
        ));
        assert!(matches!(
            compare(3, 5),
            VerificationOutcome::AnchorStale { .. }
        ));
    }
}
