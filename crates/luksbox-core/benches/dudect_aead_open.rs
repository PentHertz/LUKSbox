// AEAD open() dudect bench.
//
// Tests the `aead::open` function for all three cipher suites
// (AES-256-GCM-SIV, AES-256-GCM, ChaCha20-Poly1305). The AEAD tag
// check inside each crate uses subtle::ConstantTimeEq; this bench
// confirms that property under the LUKSbox composition (specific
// nonce/AAD shape we use).
//
// Two classes:
//   Left:  ciphertext + tag where byte 0 of the tag is wrong
//   Right: ciphertext + tag where byte 15 of the tag is wrong
// Both reject; dudect should NOT find a t-stat excursion.
//
// Run with: cargo bench --bench dudect_aead_open -p luksbox-core

use luksbox_core::{CipherSuite, aead};
use luksbox_ct_bench::rand::prelude::*;
use luksbox_ct_bench::{BenchRng, Class, CtRunner, ctbench_main};

fn build_sealed_payload(suite: CipherSuite) -> ([u8; 32], [u8; 12], Vec<u8>, Vec<u8>) {
    // Fixed key + nonce + AAD + plaintext for reproducibility.
    let key = [0xAAu8; 32];
    let nonce = [0x07u8; 12];
    let aad = b"luksbox slot 0".to_vec();
    let pt = b"master volume key going under wrap, do not peek".to_vec();
    let ct = aead::seal(suite, &key, &nonce, &aad, &pt).expect("seal");
    (key, nonce, ct, aad)
}

fn aead_open_bench_for_suite(runner: &mut CtRunner, rng: &mut BenchRng, suite: CipherSuite) {
    const N: usize = 50_000;
    let (key, nonce, ct, aad) = build_sealed_payload(suite);
    let tag_offset = ct.len() - 16; // last 16 bytes are the tag

    let mut inputs: Vec<Vec<u8>> = Vec::with_capacity(N);
    let mut classes = Vec::with_capacity(N);
    for _ in 0..N {
        let mut bad = ct.clone();
        if rng.random::<bool>() {
            bad[tag_offset] ^= 0x01; // first tag byte
            classes.push(Class::Left);
        } else {
            bad[tag_offset + 15] ^= 0x01; // last tag byte
            classes.push(Class::Right);
        }
        inputs.push(bad);
    }

    for (input, class) in inputs.into_iter().zip(classes) {
        runner.run_one(class, || {
            let r = std::hint::black_box(aead::open(
                suite,
                std::hint::black_box(&key),
                std::hint::black_box(&nonce),
                std::hint::black_box(&aad),
                std::hint::black_box(&input),
            ));
            std::hint::black_box(r.is_err())
        });
    }
}

fn aead_open_aes_gcm_siv(runner: &mut CtRunner, rng: &mut BenchRng) {
    aead_open_bench_for_suite(runner, rng, CipherSuite::Aes256GcmSiv);
}

fn aead_open_aes_gcm(runner: &mut CtRunner, rng: &mut BenchRng) {
    aead_open_bench_for_suite(runner, rng, CipherSuite::Aes256Gcm);
}

fn aead_open_chacha(runner: &mut CtRunner, rng: &mut BenchRng) {
    aead_open_bench_for_suite(runner, rng, CipherSuite::ChaCha20Poly1305);
}

ctbench_main!(aead_open_aes_gcm_siv, aead_open_aes_gcm, aead_open_chacha);
