// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! On-disk format for the user's ML-KEM seed (the 64-byte secret that
//! re-derives their decapsulation key).
//!
//! The user keeps this file on a separate medium they carry, USB stick,
//! offline machine, sealed inside a TPM, etc. The whole point of a
//! hybrid keyslot is that an attacker who only has the `.lbx` cannot
//! get to this file.
//!
//! As a defence-in-depth, the seed is also encrypted under the user's
//! passphrase with Argon2id-stretched KEK + AES-256-GCM. So even if an
//! attacker steals BOTH the `.lbx` and the `.kyber` file, they still
//! need the passphrase. (For the post-quantum threat model this is
//! gravy, the primary defence is the file being on separate storage
//! the attacker doesn't have.)
//!
//! ## Wire format (133 bytes total)
//!
//! ```text
//! magic              8 B   "lbxkyb01" (ASCII)
//! version            1 B   0x01
//! kdf_m_cost_kib     4 B   little-endian u32
//! kdf_t_cost         1 B   u8
//! kdf_p_cost         1 B   u8
//! kdf_salt          16 B   random per-file
//! aead_nonce        12 B   random per-file
//! wrapped_seed      80 B   AES-256-GCM(KEK, 64 B seed) = 64 B ciphertext + 16 B tag
//!                          AAD = magic || version || kdf_params || kdf_salt || aead_nonce
//!                                (binds wrap to its on-disk parameters)
//! ```

use std::fs;
use std::path::Path;

use luksbox_core::file_util::atomic_secure_write;

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use argon2::Argon2;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::{Error, SEED_LEN};

const MAGIC: [u8; 8] = *b"lbxkyb01";
const VERSION: u8 = 0x01;
const KDF_SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const FILE_LEN: usize = 8 + 1 + 4 + 1 + 1 + KDF_SALT_LEN + NONCE_LEN + SEED_LEN + TAG_LEN;

/// Argon2id cost factors stored alongside the seed, so we can stretch
/// the same passphrase the same way on read.
#[derive(Clone, Copy, Debug)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u8,
    pub p_cost: u8,
}

impl Default for KdfParams {
    /// Same defaults as the rest of luksbox: 256 MiB / 3 iterations /
    /// 4 lanes, tuned for 500 ms on a modern x86_64 core.
    fn default() -> Self {
        Self {
            m_cost_kib: 256 * 1024,
            t_cost: 3,
            p_cost: 4,
        }
    }
}

/// Encrypt `seed` under `passphrase` and write to `path`. Refuses to
/// overwrite an existing file (the caller should ensure cleanup if
/// they really want to replace it).
pub fn write(
    path: &Path,
    seed: &[u8; SEED_LEN],
    passphrase: &[u8],
    kdf: KdfParams,
) -> Result<(), Error> {
    if path.exists() {
        return Err(Error::SeedFile(format!(
            "{} already exists; refusing to overwrite",
            path.display()
        )));
    }

    let mut salt = [0u8; KDF_SALT_LEN];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|e| Error::SeedFile(format!("OS RNG failure generating salt: {e}")))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|e| Error::SeedFile(format!("OS RNG failure generating nonce: {e}")))?;

    let kek = derive_kek(passphrase, &salt, &kdf)?;
    let aad = build_aad(&kdf, &salt, &nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&*kek)
        .map_err(|e| Error::SeedFile(format!("AES-GCM init: {e}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: seed.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|e| Error::SeedFile(format!("AES-GCM encrypt: {e}")))?;

    let mut out = Vec::with_capacity(FILE_LEN);
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&kdf.m_cost_kib.to_le_bytes());
    out.push(kdf.t_cost);
    out.push(kdf.p_cost);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    debug_assert_eq!(out.len(), FILE_LEN);

    // Round 9E: atomic_secure_write produces a random-named 0600
    // tmpfile, fsyncs, renames atomically. Replaces the prior
    // fixed-name `*.kyber.tmp` + `fs::write` (which inherited the
    // umask, leaving the tmp world-readable on default 022 systems).
    // The seed bytes inside this file are passphrase-encrypted, but
    // narrowing the on-disk permission removes a brute-force vector
    // for non-owner users on multi-user systems.
    atomic_secure_write(path, &out)?;
    Ok(())
}

/// Read and decrypt a `.kyber` file. Returns the 64-byte seed.
pub fn read(path: &Path, passphrase: &[u8]) -> Result<Zeroizing<[u8; SEED_LEN]>, Error> {
    let bytes = fs::read(path)?;
    if bytes.len() != FILE_LEN {
        return Err(Error::SeedFile(format!(
            "wrong file size: got {} bytes, expected {}",
            bytes.len(),
            FILE_LEN
        )));
    }
    if bytes[..8] != MAGIC {
        return Err(Error::SeedFile(
            "missing magic bytes, not a .kyber file".into(),
        ));
    }
    if bytes[8] != VERSION {
        return Err(Error::SeedFile(format!(
            "unsupported version {}, expected {}",
            bytes[8], VERSION
        )));
    }
    let m_cost_kib = u32::from_le_bytes(bytes[9..13].try_into().unwrap());
    let t_cost = bytes[13];
    let p_cost = bytes[14];
    let kdf = KdfParams {
        m_cost_kib,
        t_cost,
        p_cost,
    };
    // DoS guard: reject hostile Argon2id params from the on-disk
    // header. An attacker with write-access to the .kyber file (e.g.
    // shared USB stick, tampered backup) could otherwise set
    // m_cost_kib = u32::MAX -> 4 TiB allocation request -> OOM on every
    // unlock attempt, locking the user out of their own vault without
    // ever knowing the passphrase.
    //
    // Bounds:
    //   m_cost_kib <= 512 MiB. Sensitive preset is 1 GiB, but Argon2's
    //   peak memory is m_cost * p_cost * 128 B; with our p_cost cap of
    //   16 a 512 MiB m_cost still allows 1 TiB peak (which Argon2-id
    //   refuses anyway above ~64 GiB on most platforms, but we cap
    //   here as the first line of defence). Lower than a previous
    //   4 GiB cap that combined with p_cost = 16 would have permitted
    //   16 TiB peak requests; ground-truth audit findings.
    //   t_cost <= 16. 3x sensitive's t=5; comfortably above realistic
    //   configs.
    //   p_cost <= 16. Argon2id parallelism cap; we only ever ship
    //   p_cost <= 4 in any preset.
    const SAFE_M_COST_KIB_MAX: u32 = 512 * 1024;
    const SAFE_T_COST_MAX: u8 = 16;
    const SAFE_P_COST_MAX: u8 = 16;
    if !(8..=SAFE_M_COST_KIB_MAX).contains(&m_cost_kib)
        || !(1..=SAFE_T_COST_MAX).contains(&t_cost)
        || !(1..=SAFE_P_COST_MAX).contains(&p_cost)
    {
        return Err(Error::SeedFile(format!(
            "rejecting hostile on-disk Argon2id params \
             (m_cost_kib={m_cost_kib}, t_cost={t_cost}, p_cost={p_cost}), \
             outside safe bounds (m<={SAFE_M_COST_KIB_MAX} KiB, t<={SAFE_T_COST_MAX}, p<={SAFE_P_COST_MAX})"
        )));
    }
    let salt: [u8; KDF_SALT_LEN] = bytes[15..15 + KDF_SALT_LEN].try_into().unwrap();
    let nonce_bytes: [u8; NONCE_LEN] = bytes[15 + KDF_SALT_LEN..15 + KDF_SALT_LEN + NONCE_LEN]
        .try_into()
        .unwrap();
    let ct = &bytes[15 + KDF_SALT_LEN + NONCE_LEN..];

    let kek = derive_kek(passphrase, &salt, &kdf)?;
    let aad = build_aad(&kdf, &salt, &nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&*kek)
        .map_err(|e| Error::SeedFile(format!("AES-GCM init: {e}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let pt = cipher
        .decrypt(nonce, Payload { msg: ct, aad: &aad })
        .map_err(|_| {
            Error::SeedFile(
                "decryption failed, wrong passphrase, or the file has been \
                 tampered with"
                    .into(),
            )
        })?;
    if pt.len() != SEED_LEN {
        return Err(Error::SeedFile(format!(
            "decrypted seed has wrong length: got {}, expected {}",
            pt.len(),
            SEED_LEN
        )));
    }
    let mut seed = [0u8; SEED_LEN];
    seed.copy_from_slice(&pt);
    Ok(Zeroizing::new(seed))
}

fn derive_kek(
    passphrase: &[u8],
    salt: &[u8],
    kdf: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            kdf.m_cost_kib,
            kdf.t_cost as u32,
            kdf.p_cost as u32,
            Some(32),
        )
        .map_err(|e| Error::SeedFile(format!("Argon2id params: {e}")))?,
    );
    let mut kek = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut kek)
        .map_err(|e| Error::SeedFile(format!("Argon2id: {e}")))?;
    Ok(Zeroizing::new(kek))
}

/// AAD bound to the on-disk parameters so that an attacker who can
/// flip the salt or nonce gets a tag failure rather than silent
/// reinterpretation under different KDF parameters.
fn build_aad(kdf: &KdfParams, salt: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + 1 + 4 + 1 + 1 + KDF_SALT_LEN + NONCE_LEN);
    aad.extend_from_slice(&MAGIC);
    aad.push(VERSION);
    aad.extend_from_slice(&kdf.m_cost_kib.to_le_bytes());
    aad.push(kdf.t_cost);
    aad.push(kdf.p_cost);
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    fn fast_kdf() -> KdfParams {
        KdfParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn tmp_path(name: &str) -> std::path::PathBuf {
        let p = temp_dir().join(format!("luksbox-pq-test-{}.kyber", name));
        let _ = fs::remove_file(&p);
        p
    }

    #[test]
    fn round_trip_recovers_seed() {
        let path = tmp_path("roundtrip");
        let mut seed = [0u8; SEED_LEN];
        OsRng.fill_bytes(&mut seed);
        write(&path, &seed, b"hunter2", fast_kdf()).unwrap();
        let recovered = read(&path, b"hunter2").unwrap();
        assert_eq!(*recovered, seed);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let path = tmp_path("wrongpw");
        let mut seed = [0u8; SEED_LEN];
        OsRng.fill_bytes(&mut seed);
        write(&path, &seed, b"hunter2", fast_kdf()).unwrap();
        let r = read(&path, b"WRONGpw");
        assert!(matches!(r, Err(Error::SeedFile(_))));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn tampered_byte_rejected() {
        let path = tmp_path("tampered");
        let mut seed = [0u8; SEED_LEN];
        OsRng.fill_bytes(&mut seed);
        write(&path, &seed, b"hunter2", fast_kdf()).unwrap();
        // Flip a bit in the wrapped-seed region (last 80 bytes).
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        fs::write(&path, &bytes).unwrap();
        let r = read(&path, b"hunter2");
        assert!(matches!(r, Err(Error::SeedFile(_))));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn flipped_aad_rejected() {
        let path = tmp_path("flipped-aad");
        let mut seed = [0u8; SEED_LEN];
        OsRng.fill_bytes(&mut seed);
        write(&path, &seed, b"hunter2", fast_kdf()).unwrap();
        // Flip a byte inside the salt region (offset 15..31).
        let mut bytes = fs::read(&path).unwrap();
        bytes[20] ^= 0xff;
        fs::write(&path, &bytes).unwrap();
        let r = read(&path, b"hunter2");
        assert!(matches!(r, Err(Error::SeedFile(_))));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn refuses_to_overwrite() {
        let path = tmp_path("overwrite");
        let mut seed = [0u8; SEED_LEN];
        OsRng.fill_bytes(&mut seed);
        write(&path, &seed, b"hunter2", fast_kdf()).unwrap();
        let r = write(&path, &seed, b"hunter2", fast_kdf());
        assert!(matches!(r, Err(Error::SeedFile(_))));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn wrong_magic_rejected() {
        let path = tmp_path("wrong-magic");
        let bytes = vec![0u8; FILE_LEN];
        fs::write(&path, &bytes).unwrap();
        let r = read(&path, b"hunter2");
        assert!(matches!(r, Err(Error::SeedFile(_))));
        let _ = fs::remove_file(&path);
    }
}
