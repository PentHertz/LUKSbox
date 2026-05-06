// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Post-quantum key-encapsulation primitives for LUKSbox hybrid keyslots.
//!
//! Wraps `ml-kem` (RustCrypto's pure-Rust FIPS-203 implementation) with
//! a LUKSbox-flavoured byte-oriented API. Two parameter sets are
//! supported, both NIST-standardized in FIPS 203 (August 2024):
//!
//! - **ML-KEM-768**, security category 3 (≈ AES-192 strength). The
//!   default for our hybrid keyslots; matches ANSSI's "Renforcé" /
//!   NIST's recommended baseline.
//! - **ML-KEM-1024**, security category 5 (≈ AES-256 strength). The
//!   high-margin tier for ANSSI "Élevé" / long-life classified data /
//!   anyone who wants the cryptographic-overkill option.
//!
//! ## Wire format constants (FIPS 203 §8 Table 2)
//!
//! | Param   | Encaps key (pk) | Decaps key (sk full) | Ciphertext | Shared key | Seed |
//! |---------|-----------------|----------------------|------------|------------|------|
//! | ML-KEM-768  | 1184 B  | 2400 B | 1088 B | 32 B | 64 B |
//! | ML-KEM-1024 | 1568 B  | 3168 B | 1568 B | 32 B | 64 B |
//!
//! We store the 64-byte SEED on disk (re-derives the full sk
//! deterministically per FIPS 203 §6) rather than the expanded sk,
//! same cryptographic strength, much smaller `.kyber` files.

pub mod seed_file;

use ml_kem::{
    EncapsulationKey, KeyExport, KeySizeUser, MlKem768, MlKem1024, Seed,
    array::Array,
    kem::{Decapsulate, Encapsulate, FromSeed, Kem, TryKeyInit},
};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Debug, Error)]
pub enum Error {
    #[error("ML-KEM key parsing failed (corrupt or wrong-version material)")]
    InvalidKey,

    #[error("ML-KEM ciphertext is the wrong size: got {got} bytes, expected {expected}")]
    WrongCiphertextSize { got: usize, expected: usize },

    #[error("ML-KEM public key is the wrong size: got {got} bytes, expected {expected}")]
    WrongPublicKeySize { got: usize, expected: usize },

    #[error("seed file: {0}")]
    SeedFile(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Parameter-set selector. Mirrors FIPS 203 §7 parameter-set table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqParams {
    /// ML-KEM-768. NIST security category 3 (≈ AES-192). Default.
    Ml768,
    /// ML-KEM-1024. NIST security category 5 (≈ AES-256). High-tier.
    Ml1024,
}

impl PqParams {
    /// Encapsulation key (public) length in bytes.
    pub const fn public_key_len(self) -> usize {
        match self {
            Self::Ml768 => PUBLIC_KEY_LEN_768,
            Self::Ml1024 => PUBLIC_KEY_LEN_1024,
        }
    }

    /// Ciphertext length in bytes.
    pub const fn ciphertext_len(self) -> usize {
        match self {
            Self::Ml768 => CIPHERTEXT_LEN_768,
            Self::Ml1024 => CIPHERTEXT_LEN_1024,
        }
    }

    /// Wire-format byte for use in the hybrid sidecar's v2 entries.
    /// 1 = ML-KEM-768, 2 = ML-KEM-1024.
    pub const fn level_byte(self) -> u8 {
        match self {
            Self::Ml768 => 1,
            Self::Ml1024 => 2,
        }
    }

    pub fn from_level_byte(b: u8) -> Result<Self, Error> {
        match b {
            1 => Ok(Self::Ml768),
            2 => Ok(Self::Ml1024),
            other => Err(Error::SeedFile(format!(
                "unknown PQ level byte: {other} (expected 1 for ML-KEM-768 or 2 for ML-KEM-1024)"
            ))),
        }
    }
}

// FIPS 203 Table 2, never change these without a format-version bump.
pub const PUBLIC_KEY_LEN_768: usize = 1184;
pub const CIPHERTEXT_LEN_768: usize = 1088;
pub const PUBLIC_KEY_LEN_1024: usize = 1568;
pub const CIPHERTEXT_LEN_1024: usize = 1568;

/// 32 bytes, shared secret produced by encapsulate / decapsulate
/// (identical for all FIPS-203 parameter sets).
pub const SHARED_KEY_LEN: usize = 32;

/// 64 bytes, the seed we store in the `.kyber` file. The FIPS-203
/// seed is `d ‖ z`, both 32 B; concatenated = 64 B (same for all
/// parameter sets).
pub const SEED_LEN: usize = 64;

// Back-compat aliases for the original 768-only API.
pub const PUBLIC_KEY_LEN: usize = PUBLIC_KEY_LEN_768;
pub const CIPHERTEXT_LEN: usize = CIPHERTEXT_LEN_768;

/// Generate a fresh keypair from `OsRng`. Shape of the returned blobs
/// depends on the parameter set; see `PqParams::public_key_len`.
pub fn keygen_with(params: PqParams) -> (Vec<u8>, Zeroizing<[u8; SEED_LEN]>) {
    match params {
        PqParams::Ml768 => keygen_768(),
        PqParams::Ml1024 => keygen_1024(),
    }
}

/// Convenience for the ML-KEM-768 default case (preserves the
/// `(pk: [u8; 1184], seed)` tuple shape from the original API).
pub fn keygen() -> ([u8; PUBLIC_KEY_LEN_768], Zeroizing<[u8; SEED_LEN]>) {
    let (pk, seed) = keygen_768();
    let mut arr = [0u8; PUBLIC_KEY_LEN_768];
    arr.copy_from_slice(&pk);
    (arr, seed)
}

fn keygen_768() -> (Vec<u8>, Zeroizing<[u8; SEED_LEN]>) {
    let (dk, ek) = MlKem768::generate_keypair();
    let seed = dk
        .to_seed()
        .expect("from_seed always populates the seed field");
    let mut seed_bytes = [0u8; SEED_LEN];
    seed_bytes.copy_from_slice(seed.as_slice());
    (
        ek.to_bytes().as_slice().to_vec(),
        Zeroizing::new(seed_bytes),
    )
}

fn keygen_1024() -> (Vec<u8>, Zeroizing<[u8; SEED_LEN]>) {
    let (dk, ek) = MlKem1024::generate_keypair();
    let seed = dk
        .to_seed()
        .expect("from_seed always populates the seed field");
    let mut seed_bytes = [0u8; SEED_LEN];
    seed_bytes.copy_from_slice(seed.as_slice());
    (
        ek.to_bytes().as_slice().to_vec(),
        Zeroizing::new(seed_bytes),
    )
}

/// Encapsulate against a peer's encapsulation key. The pubkey length
/// is checked against the requested parameter set; mismatch is an
/// error rather than a silent ML-KEM-768-on-ML-KEM-1024-key call.
pub fn encapsulate_with(
    params: PqParams,
    public_key: &[u8],
) -> Result<(Vec<u8>, Zeroizing<[u8; SHARED_KEY_LEN]>), Error> {
    if public_key.len() != params.public_key_len() {
        return Err(Error::WrongPublicKeySize {
            got: public_key.len(),
            expected: params.public_key_len(),
        });
    }
    match params {
        PqParams::Ml768 => encap_768(public_key),
        PqParams::Ml1024 => encap_1024(public_key),
    }
}

/// Convenience wrapper for the ML-KEM-768 default case.
pub fn encapsulate(
    public_key: &[u8],
) -> Result<([u8; CIPHERTEXT_LEN_768], Zeroizing<[u8; SHARED_KEY_LEN]>), Error> {
    let (ct, k) = encapsulate_with(PqParams::Ml768, public_key)?;
    let mut arr = [0u8; CIPHERTEXT_LEN_768];
    arr.copy_from_slice(&ct);
    Ok((arr, k))
}

fn encap_768(pk: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; SHARED_KEY_LEN]>), Error> {
    let ek_ref: &Array<u8, <EncapsulationKey<MlKem768> as KeySizeUser>::KeySize> =
        pk.try_into().map_err(|_| Error::InvalidKey)?;
    let ek =
        <EncapsulationKey<MlKem768> as TryKeyInit>::new(ek_ref).map_err(|_| Error::InvalidKey)?;
    let (ct, shared) = ek.encapsulate();
    let mut k = [0u8; SHARED_KEY_LEN];
    k.copy_from_slice(shared.as_slice());
    Ok((ct.as_slice().to_vec(), Zeroizing::new(k)))
}

fn encap_1024(pk: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; SHARED_KEY_LEN]>), Error> {
    let ek_ref: &Array<u8, <EncapsulationKey<MlKem1024> as KeySizeUser>::KeySize> =
        pk.try_into().map_err(|_| Error::InvalidKey)?;
    let ek =
        <EncapsulationKey<MlKem1024> as TryKeyInit>::new(ek_ref).map_err(|_| Error::InvalidKey)?;
    let (ct, shared) = ek.encapsulate();
    let mut k = [0u8; SHARED_KEY_LEN];
    k.copy_from_slice(shared.as_slice());
    Ok((ct.as_slice().to_vec(), Zeroizing::new(k)))
}

/// Decapsulate using the user's stored seed. ML-KEM has implicit
/// rejection per FIPS 203 §6.3, a wrong seed yields a deterministic
/// PRF-derived key, never an error. We rely on the downstream HKDF +
/// AEAD-tag verification to catch wrong seeds.
pub fn decapsulate_with(
    params: PqParams,
    seed: &[u8; SEED_LEN],
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; SHARED_KEY_LEN]>, Error> {
    if ciphertext.len() != params.ciphertext_len() {
        return Err(Error::WrongCiphertextSize {
            got: ciphertext.len(),
            expected: params.ciphertext_len(),
        });
    }
    match params {
        PqParams::Ml768 => decap_768(seed, ciphertext),
        PqParams::Ml1024 => decap_1024(seed, ciphertext),
    }
}

/// Convenience wrapper for the ML-KEM-768 default case.
pub fn decapsulate(
    seed: &[u8; SEED_LEN],
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; SHARED_KEY_LEN]>, Error> {
    decapsulate_with(PqParams::Ml768, seed, ciphertext)
}

fn decap_768(seed: &[u8; SEED_LEN], ct: &[u8]) -> Result<Zeroizing<[u8; SHARED_KEY_LEN]>, Error> {
    let seed_arr: Seed = Array(*seed);
    let (dk, _ek) = <MlKem768 as FromSeed>::from_seed(&seed_arr);
    let ct_ref: &Array<u8, <MlKem768 as Kem>::CiphertextSize> =
        ct.try_into().map_err(|_| Error::WrongCiphertextSize {
            got: ct.len(),
            expected: CIPHERTEXT_LEN_768,
        })?;
    let shared = dk.decapsulate(ct_ref);
    // Allocate the destination as Zeroizing from the start so the
    // copy lands directly in a buffer that scrubs on drop. Building
    // a plain `[u8; N]` first and wrapping in `Zeroizing::new(k)`
    // afterwards leaves the original `k` location with the secret
    // bytes (arrays are Copy and the source slot keeps its contents).
    let mut k = Zeroizing::new([0u8; SHARED_KEY_LEN]);
    k.copy_from_slice(shared.as_slice());
    Ok(k)
}

fn decap_1024(seed: &[u8; SEED_LEN], ct: &[u8]) -> Result<Zeroizing<[u8; SHARED_KEY_LEN]>, Error> {
    let seed_arr: Seed = Array(*seed);
    let (dk, _ek) = <MlKem1024 as FromSeed>::from_seed(&seed_arr);
    let ct_ref: &Array<u8, <MlKem1024 as Kem>::CiphertextSize> =
        ct.try_into().map_err(|_| Error::WrongCiphertextSize {
            got: ct.len(),
            expected: CIPHERTEXT_LEN_1024,
        })?;
    let shared = dk.decapsulate(ct_ref);
    let mut k = Zeroizing::new([0u8; SHARED_KEY_LEN]);
    k.copy_from_slice(shared.as_slice());
    Ok(k)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};

    #[test]
    fn round_trip_768() {
        let (pk, seed) = keygen_with(PqParams::Ml768);
        assert_eq!(pk.len(), 1184);
        let (ct, k_send) = encapsulate_with(PqParams::Ml768, &pk).unwrap();
        assert_eq!(ct.len(), 1088);
        let k_recv = decapsulate_with(PqParams::Ml768, &seed, &ct).unwrap();
        assert_eq!(*k_send, *k_recv);
    }

    #[test]
    fn round_trip_1024() {
        let (pk, seed) = keygen_with(PqParams::Ml1024);
        assert_eq!(pk.len(), 1568);
        let (ct, k_send) = encapsulate_with(PqParams::Ml1024, &pk).unwrap();
        assert_eq!(ct.len(), 1568);
        let k_recv = decapsulate_with(PqParams::Ml1024, &seed, &ct).unwrap();
        assert_eq!(*k_send, *k_recv);
    }

    #[test]
    fn cross_param_pubkey_rejected() {
        // Encap with ML-KEM-1024 against an ML-KEM-768 pubkey must be
        // rejected on size grounds, no silent algorithm confusion.
        let (pk_768, _) = keygen_with(PqParams::Ml768);
        let r = encapsulate_with(PqParams::Ml1024, &pk_768);
        assert!(matches!(r, Err(Error::WrongPublicKeySize { .. })));
    }

    #[test]
    fn wrong_seed_yields_different_key_768() {
        let (pk, _) = keygen_with(PqParams::Ml768);
        let (ct, k_send) = encapsulate_with(PqParams::Ml768, &pk).unwrap();
        let mut wrong = [0u8; SEED_LEN];
        OsRng.fill_bytes(&mut wrong);
        let k_other = decapsulate_with(PqParams::Ml768, &wrong, &ct).unwrap();
        assert_ne!(*k_send, *k_other);
    }
}
