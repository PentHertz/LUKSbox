// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)
//
// Round 9C: byte-exact known-answer-test (KAT) regression anchors
// for ML-KEM. Complements `fips203_conformance.rs` (which tests
// structural properties: sizes, determinism, implicit rejection).
//
// Approach: pin the SHA-256 of the encapsulation key bytes that the
// `ml-kem` crate produces from a FIXED 64-byte seed, for both
// ML-KEM-768 and ML-KEM-1024. If a future RustCrypto release
// produces different bytes for the same seed - whether from a real
// FIPS 203 fix, an algorithm tweak, or a regression - this test
// fires and forces a manual review.
//
// What this catches:
//   - Silent regression in `ml-kem` between minor version bumps.
//   - Crate-substitution attack (if a malicious typosquat ever lands
//     on crates.io and our Cargo.lock somehow points at it).
//
// What this DOESN'T catch:
//   - Drift from FIPS 203 specifically (would need real NIST ACVP
//     vectors loaded - hosted at usnistgov/ACVP-Server, 545 KB JSON
//     per parameter set; out of scope for this round).
//   - Side-channel issues (Round 9A's job).
//
// To update the expected hashes after a deliberate algorithm change:
//   1. Run `cargo test -p luksbox-pq --test ml_kem_kat -- --nocapture`
//   2. Read the printed actual hashes from the failure message
//   3. Update KAT_HASH_768_EK / KAT_HASH_1024_EK below
//   4. Document the reason in the audit-report Round 9C update log

use ml_kem::{KeyExport, MlKem768, MlKem1024, kem::FromSeed};
use sha2::{Digest, Sha256};

/// Fixed 64-byte seed for the regression anchor. `[0x01; 64]` chosen
/// for trivial reproducibility ("seed = 64 bytes of 0x01").
const KAT_SEED: [u8; 64] = [0x01; 64];

/// SHA-256 of the ML-KEM-768 encapsulation key produced from KAT_SEED
/// by `ml-kem 0.3.x`. Locked in 2026-05 against the `ml-kem` crate
/// version pinned in workspace Cargo.lock.
const KAT_HASH_768_EK: &str = "e68d60857f9cb41f88c278ca430e472c6df5679fd5bac3ce872334293c5d0c42";

/// SHA-256 of the ML-KEM-1024 encapsulation key produced from KAT_SEED.
const KAT_HASH_1024_EK: &str = "05227acb49aefea81141d2bbc32ed84178283517d724ebc04d570ce84725f656";

#[test]
fn ml_kem_768_byte_exact_regression_anchor() {
    let seed: ml_kem::Seed = ml_kem::array::Array(KAT_SEED);
    let (_dk, ek) = <MlKem768 as FromSeed>::from_seed(&seed);
    let ek_bytes = ek.to_bytes();

    let mut h = Sha256::new();
    h.update(ek_bytes.as_slice());
    let actual = hex::encode(h.finalize());

    assert_eq!(
        actual,
        KAT_HASH_768_EK,
        "\n\nML-KEM-768 KAT regression anchor TRIGGERED.\n\
         The `ml-kem` crate produced different bytes for the same seed.\n\
         Expected SHA-256: {}\n\
         Actual   SHA-256: {}\n\
         Encap-key bytes (hex, first 64): {}...\n\
         Encap-key length: {} bytes (should be 1184 for ML-KEM-768)\n\
         \n\
         Action required: investigate WHY the crate's output changed.\n\
         Possible causes:\n\
         (a) deliberate `ml-kem` crate update with intentional algorithm change\n\
         (b) regression / supply-chain compromise\n\
         If (a): verify the new bytes against NIST ACVP vectors first,\n\
         then update KAT_HASH_768_EK in this test.\n\
         If (b): pin Cargo.lock back, audit the crate diff.\n",
        KAT_HASH_768_EK,
        actual,
        hex::encode(&ek_bytes.as_slice()[..64]),
        ek_bytes.as_slice().len()
    );
}

#[test]
fn ml_kem_1024_byte_exact_regression_anchor() {
    let seed: ml_kem::Seed = ml_kem::array::Array(KAT_SEED);
    let (_dk, ek) = <MlKem1024 as FromSeed>::from_seed(&seed);
    let ek_bytes = ek.to_bytes();

    let mut h = Sha256::new();
    h.update(ek_bytes.as_slice());
    let actual = hex::encode(h.finalize());

    assert_eq!(
        actual,
        KAT_HASH_1024_EK,
        "\n\nML-KEM-1024 KAT regression anchor TRIGGERED.\n\
         Expected SHA-256: {}\n\
         Actual   SHA-256: {}\n\
         Encap-key length: {} bytes (should be 1568 for ML-KEM-1024)\n\
         \n\
         See ml_kem_768_byte_exact_regression_anchor docstring for triage steps.\n",
        KAT_HASH_1024_EK,
        actual,
        ek_bytes.as_slice().len()
    );
}

/// Decapsulation determinism: same (seed, ciphertext) MUST always
/// produce the same shared secret. FIPS 203 Algorithm 18 specifies
/// Decaps as a deterministic function of the decapsulation key + ct.
#[test]
fn ml_kem_768_decap_is_deterministic() {
    use luksbox_pq::{PqParams, decapsulate_with, encapsulate_with, keygen_with};

    let (pk, seed) = keygen_with(PqParams::Ml768);
    let (ct, _ss1) = encapsulate_with(PqParams::Ml768, &pk).expect("encap");

    let recovered_a = decapsulate_with(PqParams::Ml768, &seed, &ct).expect("decap a");
    let recovered_b = decapsulate_with(PqParams::Ml768, &seed, &ct).expect("decap b");
    let recovered_c = decapsulate_with(PqParams::Ml768, &seed, &ct).expect("decap c");

    assert_eq!(
        recovered_a.as_slice(),
        recovered_b.as_slice(),
        "Decapsulation must be deterministic (run a == run b)"
    );
    assert_eq!(
        recovered_b.as_slice(),
        recovered_c.as_slice(),
        "Decapsulation must be deterministic (run b == run c)"
    );
}
