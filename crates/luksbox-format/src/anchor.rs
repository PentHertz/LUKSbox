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

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::Path;

use hmac::{Hmac, Mac};
use luksbox_core::MasterVolumeKey;
use luksbox_core::file_util::atomic_secure_write;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::Error;

/// Open an anchor file for reading without following symlinks.
///
/// The anchor reader sits at a TOCTOU boundary: GUI / CLI surfaces
/// pre-check that the path is a regular file (see e.g.
/// `preflight_deniable_anchor` in the GUI), but the format layer is
/// the second line of defense in case a caller skips the pre-check
/// or an attacker swaps the path between the check and this open.
/// On Unix we pass `O_NOFOLLOW`; if the path resolves to a symlink
/// at open time, the kernel returns `ELOOP` and we error out instead
/// of silently dereferencing into whatever the symlink targets.
///
/// Windows: Round 12 fix R12-15 - pass `FILE_FLAG_OPEN_REPARSE_POINT`
/// via `custom_flags` so the kernel opens the reparse-point file
/// directly instead of dereferencing the link to its target, then
/// inspect the attribute set and refuse if `FILE_ATTRIBUTE_REPARSE_POINT`
/// is present. Mirrors the Unix `O_NOFOLLOW` semantic.
fn open_anchor_for_read(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        // FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
        // FILE_FLAG_BACKUP_SEMANTICS  = 0x02000000  (needed to open
        //   reparse points reliably on directories; harmless on files)
        opts.custom_flags(0x0020_0000);
    }
    let f = opts.open(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        // FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
        let attrs = f.metadata()?.file_attributes();
        if attrs & 0x0000_0400 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "anchor file is a reparse point (symlink / junction); refused",
            ));
        }
    }
    Ok(f)
}

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
    let mut f = open_anchor_for_read(path)?;
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

// ============================================================
// Deniable anchor format
// ============================================================
//
// The standard anchor has a plaintext magic (`LBXANCH1`) that
// fingerprints the file as a LUKSbox anchor. Deniable mode requires
// every byte to look uniformly random; this format wraps the whole
// thing in AEAD so the on-disk bytes carry no plaintext structure.
//
// Layout (256 B total - padded to a round number so the file size
// is not a fingerprint either):
//
//   [ 0..12 ]    AEAD nonce (random per write)
//   [12..240]    AEAD ciphertext + tag (228 B = 212 plaintext + 16 tag)
//   [240..256]   random padding (16 B from OsRng)
//
// Plaintext (212 B inside the AEAD):
//   [  0..  8]   u64 generation (little-endian)
//   [  8..212]   random padding (204 B from OsRng)
//
// Key derivation:
//   `anchor_key = HKDF(per_vault_salt, MVK, info="luksbox-deniable-v1/anchor")`
//
// AAD (binds the anchor to a specific vault):
//   `b"luksbox-deniable-v1/anchor" || per_vault_salt`
//
// Failure mode: any AEAD failure (wrong vault, wrong MVK, corrupt
// file, truncated file) collapses to `Error::OpaqueUnlockFailed` so
// an attacker observing error output cannot distinguish "this is a
// LUKSbox anchor that fails to verify" from "this is just random
// garbage."

use crate::deniable_header::AAD_PREFIX as DENIABLE_AAD_PREFIX_BYTES;
use luksbox_core::CipherSuite;
use luksbox_core::aead;
use luksbox_core::deniable::fill_random;

pub const DENIABLE_ANCHOR_SIZE: usize = 256;
const DENIABLE_ANCHOR_NONCE_LEN: usize = 12;
const DENIABLE_ANCHOR_TAG_LEN: usize = 16;
const DENIABLE_ANCHOR_PLAINTEXT_LEN: usize = 212;
const DENIABLE_ANCHOR_CT_LEN: usize = DENIABLE_ANCHOR_PLAINTEXT_LEN + DENIABLE_ANCHOR_TAG_LEN; // 228
const DENIABLE_ANCHOR_TRAILING_PAD: usize = 16;
const DENIABLE_ANCHOR_AAD_LABEL: &[u8] = b"luksbox-deniable-v1/anchor";
const DENIABLE_ANCHOR_INFO: &[u8] = b"luksbox-deniable-v1/anchor";

// Compile-time layout check.
const _: () = assert!(
    DENIABLE_ANCHOR_NONCE_LEN + DENIABLE_ANCHOR_CT_LEN + DENIABLE_ANCHOR_TRAILING_PAD
        == DENIABLE_ANCHOR_SIZE
);

fn deniable_anchor_key(mvk: &MasterVolumeKey, per_vault_salt: &[u8; 32]) -> [u8; 32] {
    *mvk.derive_subkey(per_vault_salt, DENIABLE_ANCHOR_INFO)
}

fn deniable_anchor_aad(per_vault_salt: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DENIABLE_ANCHOR_AAD_LABEL.len() + 32);
    aad.extend_from_slice(DENIABLE_ANCHOR_AAD_LABEL);
    aad.extend_from_slice(per_vault_salt);
    aad
}

/// Write a fresh deniable anchor file containing the given generation
/// counter. The whole 256-byte file is computationally indistinguishable
/// from random output (no magic, no fixed structure).
///
/// `cipher_suite` is the vault's cipher; the anchor uses the same AEAD
/// so a vault built with AES-GCM-SIV gets a SIV-encrypted anchor, etc.
/// Atomic via the same `atomic_secure_write` path as the standard
/// anchor.
pub fn deniable_write(
    path: &Path,
    generation: u64,
    mvk: &MasterVolumeKey,
    per_vault_salt: &[u8; 32],
    cipher_suite: CipherSuite,
) -> Result<(), Error> {
    use zeroize::Zeroizing;

    // Plaintext: generation + random padding. Wrapped in Zeroizing
    // so the padding (which carries no secret per se, but might in
    // a future format) is wiped on drop.
    let mut plaintext = Zeroizing::new([0u8; DENIABLE_ANCHOR_PLAINTEXT_LEN]);
    plaintext[..8].copy_from_slice(&generation.to_le_bytes());
    fill_random(&mut plaintext[8..]).map_err(Error::Crypto)?;

    let mut nonce = [0u8; DENIABLE_ANCHOR_NONCE_LEN];
    fill_random(&mut nonce).map_err(Error::Crypto)?;

    let key = deniable_anchor_key(mvk, per_vault_salt);
    let aad = deniable_anchor_aad(per_vault_salt);
    let ct = aead::seal(cipher_suite, &key, &nonce, &aad, &*plaintext).map_err(Error::Crypto)?;
    debug_assert_eq!(ct.len(), DENIABLE_ANCHOR_CT_LEN);

    let mut buf = [0u8; DENIABLE_ANCHOR_SIZE];
    buf[..DENIABLE_ANCHOR_NONCE_LEN].copy_from_slice(&nonce);
    buf[DENIABLE_ANCHOR_NONCE_LEN..DENIABLE_ANCHOR_NONCE_LEN + ct.len()].copy_from_slice(&ct);
    // Trailing random padding. The 240..256 region is just OsRng
    // bytes - kept after the AEAD output so the on-disk file is a
    // fixed 256 B and an analyst can't distinguish "AEAD output is
    // exactly 228 B" from any other random-looking blob.
    fill_random(&mut buf[DENIABLE_ANCHOR_SIZE - DENIABLE_ANCHOR_TRAILING_PAD..])
        .map_err(Error::Crypto)?;

    atomic_secure_write(path, &buf)?;
    Ok(())
}

/// Read and verify a deniable anchor file. Returns the trusted
/// generation counter, or `Error::OpaqueUnlockFailed` for any failure
/// (wrong vault, wrong MVK, truncated file, corrupt ciphertext).
///
/// The single error variant is intentional: an adversary running this
/// against arbitrary files MUST NOT be able to distinguish "this is
/// a LUKSbox anchor for a different vault" from "this is random
/// garbage." Both produce the same `OpaqueUnlockFailed`.
pub fn deniable_read_and_verify(
    path: &Path,
    mvk: &MasterVolumeKey,
    per_vault_salt: &[u8; 32],
    cipher_suite: CipherSuite,
) -> Result<AnchorContents, Error> {
    // Suppress unused-import warning if AAD_PREFIX isn't reached
    // (compile-time const). The constant lives in deniable_header
    // and is the same one used by the slot AAD; the anchor AAD label
    // intentionally differs from it so a copy-paste mistake between
    // contexts fails AEAD.
    let _ = DENIABLE_AAD_PREFIX_BYTES;

    // O_NOFOLLOW: refuse to dereference symlinks at the format layer
    // even if a caller skipped the pre-check. ELOOP collapses to
    // OpaqueUnlockFailed like every other file-level failure so the
    // deniability story (no distinguishable error per failure mode)
    // stays intact.
    let mut f = open_anchor_for_read(path).map_err(|_| Error::OpaqueUnlockFailed)?;
    let mut buf = [0u8; DENIABLE_ANCHOR_SIZE];
    f.read_exact(&mut buf)
        .map_err(|_| Error::OpaqueUnlockFailed)?;

    let nonce: [u8; DENIABLE_ANCHOR_NONCE_LEN] = buf[..DENIABLE_ANCHOR_NONCE_LEN]
        .try_into()
        .map_err(|_| Error::OpaqueUnlockFailed)?;
    let ct = &buf[DENIABLE_ANCHOR_NONCE_LEN..DENIABLE_ANCHOR_NONCE_LEN + DENIABLE_ANCHOR_CT_LEN];

    let key = deniable_anchor_key(mvk, per_vault_salt);
    let aad = deniable_anchor_aad(per_vault_salt);
    let pt =
        aead::open(cipher_suite, &key, &nonce, &aad, ct).map_err(|_| Error::OpaqueUnlockFailed)?;
    if pt.len() != DENIABLE_ANCHOR_PLAINTEXT_LEN {
        return Err(Error::OpaqueUnlockFailed);
    }
    let mut gen_bytes = [0u8; 8];
    gen_bytes.copy_from_slice(&pt[..8]);
    Ok(AnchorContents {
        generation: u64::from_le_bytes(gen_bytes),
    })
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

    // ============================================================
    // Deniable anchor tests
    // ============================================================

    use luksbox_core::CipherSuite;

    #[test]
    fn deniable_anchor_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("opaque.dat");
        let mvk = MasterVolumeKey::from_bytes([0x42; 32]);
        let salt = [0x77u8; 32];
        deniable_write(&path, 12345, &mvk, &salt, CipherSuite::Aes256GcmSiv).unwrap();
        let r = deniable_read_and_verify(&path, &mvk, &salt, CipherSuite::Aes256GcmSiv).unwrap();
        assert_eq!(r.generation, 12345);
    }

    #[test]
    fn deniable_anchor_file_size_is_fixed_256() {
        // INVARIANT: file size is fixed regardless of generation
        // value, so file size cannot be used to fingerprint the
        // anchor file as belonging to a vault that has been written
        // N times.
        let dir = tempdir().unwrap();
        let mvk = MasterVolumeKey::from_bytes([0x42; 32]);
        let salt = [0x77u8; 32];
        for g in [0u64, 1, u32::MAX as u64, u64::MAX] {
            let path = dir.path().join(format!("a-{g}.dat"));
            deniable_write(&path, g, &mvk, &salt, CipherSuite::Aes256GcmSiv).unwrap();
            let sz = std::fs::metadata(&path).unwrap().len();
            assert_eq!(sz, DENIABLE_ANCHOR_SIZE as u64);
        }
    }

    #[test]
    fn deniable_anchor_wrong_mvk_returns_opaque() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("opaque.dat");
        let mvk = MasterVolumeKey::from_bytes([0x42; 32]);
        let salt = [0x77u8; 32];
        deniable_write(&path, 5, &mvk, &salt, CipherSuite::Aes256GcmSiv).unwrap();
        let other = MasterVolumeKey::from_bytes([0x99; 32]);
        assert!(matches!(
            deniable_read_and_verify(&path, &other, &salt, CipherSuite::Aes256GcmSiv),
            Err(Error::OpaqueUnlockFailed),
        ));
    }

    #[test]
    fn deniable_anchor_wrong_vault_salt_returns_opaque() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("opaque.dat");
        let mvk = MasterVolumeKey::from_bytes([0x42; 32]);
        let salt_a = [0x77u8; 32];
        let mut salt_b = salt_a;
        salt_b[0] ^= 0xff;
        deniable_write(&path, 5, &mvk, &salt_a, CipherSuite::Aes256GcmSiv).unwrap();
        assert!(matches!(
            deniable_read_and_verify(&path, &mvk, &salt_b, CipherSuite::Aes256GcmSiv),
            Err(Error::OpaqueUnlockFailed),
        ));
    }

    #[test]
    fn deniable_anchor_wrong_cipher_returns_opaque() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("opaque.dat");
        let mvk = MasterVolumeKey::from_bytes([0x42; 32]);
        let salt = [0x77u8; 32];
        deniable_write(&path, 5, &mvk, &salt, CipherSuite::Aes256GcmSiv).unwrap();
        assert!(matches!(
            deniable_read_and_verify(&path, &mvk, &salt, CipherSuite::ChaCha20Poly1305),
            Err(Error::OpaqueUnlockFailed),
        ));
    }

    #[test]
    fn deniable_anchor_tampered_byte_returns_opaque() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("opaque.dat");
        let mvk = MasterVolumeKey::from_bytes([0x42; 32]);
        let salt = [0x77u8; 32];
        deniable_write(&path, 5, &mvk, &salt, CipherSuite::Aes256GcmSiv).unwrap();
        // Flip a bit anywhere in the AEAD ciphertext range.
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[100] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(matches!(
            deniable_read_and_verify(&path, &mvk, &salt, CipherSuite::Aes256GcmSiv),
            Err(Error::OpaqueUnlockFailed),
        ));
    }

    #[test]
    fn deniable_anchor_truncated_returns_opaque() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("opaque.dat");
        let mvk = MasterVolumeKey::from_bytes([0x42; 32]);
        let salt = [0x77u8; 32];
        deniable_write(&path, 5, &mvk, &salt, CipherSuite::Aes256GcmSiv).unwrap();
        // Truncate to half the expected size.
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();
        assert!(matches!(
            deniable_read_and_verify(&path, &mvk, &salt, CipherSuite::Aes256GcmSiv),
            Err(Error::OpaqueUnlockFailed),
        ));
    }

    #[test]
    fn deniable_anchor_has_high_entropy() {
        // Sanity: a written anchor should be uniformly random
        // looking. Shannon entropy > 7.5 over 256 B is a weak
        // proxy but catches obvious bugs (all-zeros, repeating
        // patterns, plaintext gen field leaking).
        let dir = tempdir().unwrap();
        let path = dir.path().join("opaque.dat");
        let mvk = MasterVolumeKey::from_bytes([0x42; 32]);
        let salt = [0x77u8; 32];
        deniable_write(&path, 42, &mvk, &salt, CipherSuite::Aes256GcmSiv).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let mut counts = [0u64; 256];
        for &b in &bytes {
            counts[b as usize] += 1;
        }
        let n = bytes.len() as f64;
        let mut h = 0.0;
        for &c in counts.iter() {
            if c == 0 {
                continue;
            }
            let p = c as f64 / n;
            h -= p * p.log2();
        }
        // 256 bytes is on the small side for entropy estimation;
        // a fairly loose threshold avoids flakes.
        assert!(
            h > 6.5,
            "anchor entropy {:.3} too low - format leaks structure",
            h
        );
    }

    #[test]
    fn deniable_anchor_two_writes_differ_in_full() {
        // Same generation, same MVK, same salt -> bytes differ
        // because the nonce + padding are fresh per write.
        // Demonstrates no determinism leak that would let an
        // adversary identify "this is the same anchor again."
        let dir = tempdir().unwrap();
        let p1 = dir.path().join("a1.dat");
        let p2 = dir.path().join("a2.dat");
        let mvk = MasterVolumeKey::from_bytes([0x42; 32]);
        let salt = [0x77u8; 32];
        deniable_write(&p1, 7, &mvk, &salt, CipherSuite::Aes256GcmSiv).unwrap();
        deniable_write(&p2, 7, &mvk, &salt, CipherSuite::Aes256GcmSiv).unwrap();
        let b1 = std::fs::read(&p1).unwrap();
        let b2 = std::fs::read(&p2).unwrap();
        assert_ne!(
            b1, b2,
            "identical-input writes should produce distinct bytes via fresh nonces"
        );
    }
}
