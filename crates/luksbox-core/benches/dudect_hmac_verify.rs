// HMAC verification dudect bench.
//
// Tests `Header::verify_hmac` (and by extension the underlying
// `subtle::ConstantTimeEq` byte-comparison path). For any pair of
// (raw_header, mvk) inputs, the verification time MUST be data-
// independent of where the supplied MAC tag differs from the expected
// one.
//
// We construct a valid header + MVK once, then test the verifier's
// rejection path with two classes of attacker-controlled tags:
//   Left:  tag where byte 0 is wrong
//   Right: tag where byte 31 is wrong
// A leaky implementation that compared bytes one-at-a-time would
// reject Left earlier than Right; dudect would catch it. A correct
// implementation using subtle::ConstantTimeEq must NOT show a t-stat
// excursion on this test.
//
// Run with: cargo bench --bench dudect_hmac_verify -p luksbox-core

use luksbox_core::{
    Argon2idParams, CipherSuite, HEADER_SIZE, Header, KdfId, Keyslot, MasterVolumeKey,
};
use luksbox_ct_bench::rand::prelude::*;
use luksbox_ct_bench::{BenchRng, Class, CtRunner, ctbench_main};

const WEAK_KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

fn build_valid_header() -> ([u8; HEADER_SIZE], MasterVolumeKey) {
    let mvk = MasterVolumeKey::from_bytes([0x55; 32]);
    let mut header = Header::new(
        CipherSuite::Aes256GcmSiv,
        KdfId::Argon2id,
        4096,
        HEADER_SIZE as u64,
    );
    let slot = Keyslot::new_passphrase(
        CipherSuite::Aes256GcmSiv,
        &mvk,
        b"benchpass",
        WEAK_KDF,
        &header.header_salt,
    )
    .expect("slot");
    header.install_slot(0, slot).expect("install");
    let bytes = header.to_bytes(&mvk);
    (bytes, mvk)
}

fn hmac_verify_bench(runner: &mut CtRunner, rng: &mut BenchRng) {
    const N: usize = 50_000;
    const HMAC_OFFSET: usize = HEADER_SIZE - 32;

    let (good_bytes, mvk) = build_valid_header();
    // Sanity: the unmutated header verifies.
    let parsed = Header::from_bytes(&good_bytes).expect("parse");
    assert!(parsed.verify_hmac(&good_bytes, &mvk).is_ok());

    // Pre-generate the two classes of mutated tags.
    let mut inputs: Vec<[u8; HEADER_SIZE]> = Vec::with_capacity(N);
    let mut classes = Vec::with_capacity(N);
    for _ in 0..N {
        let mut buf = good_bytes;
        if rng.random::<bool>() {
            // Class Left: flip byte 0 of the HMAC tag (early in the comparison)
            buf[HMAC_OFFSET] ^= 0x01;
            classes.push(Class::Left);
        } else {
            // Class Right: flip byte 31 of the HMAC tag (last byte)
            buf[HMAC_OFFSET + 31] ^= 0x01;
            classes.push(Class::Right);
        }
        inputs.push(buf);
    }

    for (input, class) in inputs.into_iter().zip(classes) {
        // Re-parse the (mutated) header. Parsing is the same for both
        // classes - it doesn't touch the HMAC tag bytes for layout
        // decisions (HMAC is at offset HEADER_SIZE-32, after the slot
        // table). We measure the verify path.
        let parsed = Header::from_bytes(&input).expect("parse mutated");
        runner.run_one(class, || {
            let r = std::hint::black_box(
                parsed.verify_hmac(std::hint::black_box(&input), std::hint::black_box(&mvk)),
            );
            // Both classes must produce the same Err variant.
            std::hint::black_box(r.is_err())
        });
    }
}

ctbench_main!(hmac_verify_bench);
