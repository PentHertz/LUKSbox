// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! FIPS 203 conformance evidence for LUKSbox's ML-KEM integration.
//!
//! Each test below cites the FIPS 203 section it exercises so an
//! auditor can map our behaviour to the spec without reading the
//! whole crate. The actual cryptographic primitive is provided by
//! `ml-kem 0.3` (RustCrypto, pure Rust, FIPS-203-conformant; tested
//! upstream against NIST ACVP vectors). These tests verify that
//! LUKSbox's wrapper preserves the spec's invariants, sizes,
//! determinism, implicit-rejection behaviour, parameter-set
//! independence, so a regression in the wrapper is caught.
//!
//! What this suite is and is not:
//!
//! - **Is**: a black-box check that LUKSbox's `keygen / encapsulate /
//!   decapsulate` wrappers compose `ml-kem` correctly and never silently
//!   degrade the parameter set, sizes, or rejection semantics.
//! - **Is not**: a CMVP / FIPS 140-3 validation. That requires running
//!   NIST-signed test harnesses inside an accredited lab; we use the
//!   same algorithms but make no validation claim.
//!
//! References: NIST FIPS 203 (August 2024), full text at
//! <https://csrc.nist.gov/pubs/fips/203/final>.

use luksbox_pq::{
    CIPHERTEXT_LEN_768, CIPHERTEXT_LEN_1024, PUBLIC_KEY_LEN_768, PUBLIC_KEY_LEN_1024, PqParams,
    SEED_LEN, SHARED_KEY_LEN, decapsulate_with, encapsulate_with, keygen_with,
};
use rand_core::{OsRng, RngCore};

// ---- §8 Table 2: parameter-set sizes ---------------------------------------
//
// FIPS 203 §8 ("Algorithm Sizes") fixes the exact byte lengths for every
// primitive output. A single wrong constant in luksbox-pq could silently
// produce keys/ciphertexts that an interoperating implementation would
// reject, these tests assert each value matches the spec.

#[test]
fn sizes_match_fips203_table_2_ml_kem_768() {
    assert_eq!(PUBLIC_KEY_LEN_768, 1184, "FIPS 203 Table 2: ML-KEM-768 ek");
    assert_eq!(CIPHERTEXT_LEN_768, 1088, "FIPS 203 Table 2: ML-KEM-768 ct");
    assert_eq!(
        SHARED_KEY_LEN, 32,
        "FIPS 203 §6: shared K is always 32 bytes"
    );
    assert_eq!(SEED_LEN, 64, "FIPS 203 §6: seed = d || z, both 32 bytes");
}

#[test]
fn sizes_match_fips203_table_2_ml_kem_1024() {
    assert_eq!(
        PUBLIC_KEY_LEN_1024, 1568,
        "FIPS 203 Table 2: ML-KEM-1024 ek"
    );
    assert_eq!(
        CIPHERTEXT_LEN_1024, 1568,
        "FIPS 203 Table 2: ML-KEM-1024 ct"
    );
}

#[test]
fn keygen_outputs_have_correct_lengths_for_each_param_set() {
    for params in [PqParams::Ml768, PqParams::Ml1024] {
        let (pk, seed) = keygen_with(params);
        assert_eq!(
            pk.len(),
            params.public_key_len(),
            "{:?}: pubkey length must match FIPS 203 §8",
            params
        );
        assert_eq!(
            seed.len(),
            SEED_LEN,
            "{:?}: seed must always be 64 B (d || z)",
            params
        );
    }
}

#[test]
fn encap_outputs_have_correct_lengths_for_each_param_set() {
    for params in [PqParams::Ml768, PqParams::Ml1024] {
        let (pk, _) = keygen_with(params);
        let (ct, k) = encapsulate_with(params, &pk).unwrap();
        assert_eq!(
            ct.len(),
            params.ciphertext_len(),
            "{:?}: ciphertext length must match FIPS 203 §8",
            params
        );
        assert_eq!(
            k.len(),
            SHARED_KEY_LEN,
            "{:?}: shared K is always 32 bytes per FIPS 203 §6",
            params
        );
    }
}

// ---- §6: encap/decap symmetry (correctness) --------------------------------
//
// FIPS 203 §6 specifies that for any honestly-generated keypair (dk, ek)
// and any encapsulation `(c, K) = ML-KEM.Encaps(ek)`, decapsulation
// `K' = ML-KEM.Decaps(dk, c)` must yield K' = K. This is the "decryption
// failure rate ≤ 2^-138" guarantee from §8.4, practically zero.
//
// We exercise the symmetry over many trials per parameter set; any
// honest-trial failure is a correctness bug.

#[test]
fn fips203_section_6_correctness_ml_kem_768() {
    correctness_run(PqParams::Ml768, 32);
}

#[test]
fn fips203_section_6_correctness_ml_kem_1024() {
    correctness_run(PqParams::Ml1024, 32);
}

fn correctness_run(params: PqParams, trials: usize) {
    for i in 0..trials {
        let (pk, seed) = keygen_with(params);
        let (ct, k_send) = encapsulate_with(params, &pk).unwrap();
        let k_recv = decapsulate_with(params, &seed, &ct).unwrap();
        assert_eq!(
            *k_send, *k_recv,
            "{:?} trial {i}: §6 correctness, Encaps then Decaps must yield the same K",
            params
        );
    }
}

// ---- §6.3 Implicit rejection ----------------------------------------------
//
// FIPS 203 §6.3 specifies that ML-KEM.Decaps(dk, c) NEVER returns an
// error: when c is malformed for the holder's dk, the decap output is a
// PRF-derived value `K' = J(z, c)` derived from the secret z and the
// ciphertext, NOT from the encapsulator's K. The IND-CCA proof depends
// on this, any decap that signalled "wrong ciphertext" via an error
// would leak the validity oracle. We rely on this for our hybrid
// keyslot's tamper detection: a flipped byte in the sidecar's ciphertext
// produces a deterministic-but-wrong `K'`, the wrong K' produces the
// wrong combined KEK, and the existing AEAD tag on the wrapped MVK
// rejects the open.
//
// Concretely we verify:
//   1. decap with a wrong seed never panics or returns Err
//   2. it returns a 32-byte SharedKey
//   3. that SharedKey is NOT equal to what encap produced for the
//      genuine seed (i.e. implicit rejection actually rejected)
//   4. the wrong-seed K' is deterministic (same wrong seed + same ct
//      -> same K'), as required for the J(z, c) construction

#[test]
fn fips203_section_6_3_implicit_rejection_768() {
    implicit_rejection_run(PqParams::Ml768);
}

#[test]
fn fips203_section_6_3_implicit_rejection_1024() {
    implicit_rejection_run(PqParams::Ml1024);
}

fn implicit_rejection_run(params: PqParams) {
    let (pk, _genuine_seed) = keygen_with(params);
    let (ct, k_genuine) = encapsulate_with(params, &pk).unwrap();

    // Use a freshly random seed (not the one matching `pk`).
    let mut wrong_seed = [0u8; SEED_LEN];
    OsRng.fill_bytes(&mut wrong_seed);

    let k_implicit_a = decapsulate_with(params, &wrong_seed, &ct).unwrap();
    assert_eq!(k_implicit_a.len(), 32, "§6.3 SharedKey is always 32 B");
    assert_ne!(
        *k_implicit_a, *k_genuine,
        "§6.3 implicit rejection must produce a value NOT equal to the genuine K"
    );

    // Determinism: same wrong seed + same ct -> same K' (J(z, c)
    // is deterministic on its inputs).
    let k_implicit_b = decapsulate_with(params, &wrong_seed, &ct).unwrap();
    assert_eq!(
        *k_implicit_a, *k_implicit_b,
        "§6.3 J(z, c) must be deterministic on (z, c)"
    );
}

// ---- Domain separation between parameter sets ------------------------------
//
// FIPS 203 keys/ciphertexts are NOT interchangeable across parameter
// sets, an ML-KEM-1024 pubkey must not be usable as an ML-KEM-768
// pubkey, even by coincidence. Our `encapsulate_with` checks the
// pubkey length against the requested param set and rejects mismatches
// with `WrongPublicKeySize`. This guards against algorithm confusion
// at the API boundary.

#[test]
fn pubkey_size_check_blocks_cross_param_use_768_to_1024() {
    let (pk_768, _) = keygen_with(PqParams::Ml768);
    let r = encapsulate_with(PqParams::Ml1024, &pk_768);
    assert!(
        matches!(r, Err(luksbox_pq::Error::WrongPublicKeySize { .. })),
        "768-byte pubkey must not be silently accepted as a 1024 pubkey"
    );
}

#[test]
fn pubkey_size_check_blocks_cross_param_use_1024_to_768() {
    let (pk_1024, _) = keygen_with(PqParams::Ml1024);
    let r = encapsulate_with(PqParams::Ml768, &pk_1024);
    assert!(
        matches!(r, Err(luksbox_pq::Error::WrongPublicKeySize { .. })),
        "1024-byte pubkey must not be silently accepted as a 768 pubkey"
    );
}

#[test]
fn ciphertext_size_check_blocks_cross_param_decap_768_to_1024() {
    let (pk_768, seed_768) = keygen_with(PqParams::Ml768);
    let (ct_768, _) = encapsulate_with(PqParams::Ml768, &pk_768).unwrap();
    let r = decapsulate_with(PqParams::Ml1024, &seed_768, &ct_768);
    assert!(matches!(
        r,
        Err(luksbox_pq::Error::WrongCiphertextSize { .. })
    ));
}

#[test]
fn ciphertext_size_check_blocks_cross_param_decap_1024_to_768() {
    let (pk_1024, seed_1024) = keygen_with(PqParams::Ml1024);
    let (ct_1024, _) = encapsulate_with(PqParams::Ml1024, &pk_1024).unwrap();
    let r = decapsulate_with(PqParams::Ml768, &seed_1024, &ct_1024);
    assert!(matches!(
        r,
        Err(luksbox_pq::Error::WrongCiphertextSize { .. })
    ));
}

// ---- Wire-format constants for the .hybrid sidecar ------------------------
//
// LUKSbox's v2 sidecar entries carry a `level` byte (1 = ML-KEM-768,
// 2 = ML-KEM-1024). The hybrid_sidecar reader uses these bytes to
// dispatch to the correct decapsulate path. A wrong level byte must
// fail loudly, not silently mis-decode.

#[test]
fn level_byte_round_trip_768() {
    assert_eq!(PqParams::Ml768.level_byte(), 1);
    assert_eq!(PqParams::from_level_byte(1).unwrap(), PqParams::Ml768);
}

#[test]
fn level_byte_round_trip_1024() {
    assert_eq!(PqParams::Ml1024.level_byte(), 2);
    assert_eq!(PqParams::from_level_byte(2).unwrap(), PqParams::Ml1024);
}

#[test]
fn unknown_level_byte_rejected() {
    for b in [0u8, 3, 99, 255] {
        let r = PqParams::from_level_byte(b);
        assert!(r.is_err(), "level byte {b} must be rejected");
    }
}

// ---- Independence from RNG state ------------------------------------------
//
// Each keygen / encapsulate call must be independent: two consecutive
// keygens should produce different keypairs (otherwise we'd have a
// stuck-RNG bug). This also catches the worst-case "all-zero seed"
// regression where a faulty integration with OsRng silently produces
// the same key every time.

#[test]
fn keygen_produces_distinct_outputs() {
    for params in [PqParams::Ml768, PqParams::Ml1024] {
        let (pk1, seed1) = keygen_with(params);
        let (pk2, seed2) = keygen_with(params);
        assert_ne!(
            pk1, pk2,
            "{:?}: distinct keygen calls must yield distinct ek",
            params
        );
        assert_ne!(
            *seed1, *seed2,
            "{:?}: distinct keygen calls must yield distinct seeds",
            params
        );
    }
}

#[test]
fn encap_against_same_pk_produces_distinct_ciphertexts() {
    // FIPS 203 §6 Encaps draws fresh randomness `m` per call. Two
    // encaps against the same pk should produce different ct/K with
    // overwhelming probability (collision probability about 2^-256).
    for params in [PqParams::Ml768, PqParams::Ml1024] {
        let (pk, _) = keygen_with(params);
        let (ct1, k1) = encapsulate_with(params, &pk).unwrap();
        let (ct2, k2) = encapsulate_with(params, &pk).unwrap();
        assert_ne!(
            ct1, ct2,
            "{:?}: distinct encaps against same pk must yield distinct ct",
            params
        );
        assert_ne!(
            *k1, *k2,
            "{:?}: distinct encaps must yield distinct K",
            params
        );
    }
}
