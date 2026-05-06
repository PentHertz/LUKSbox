// Slot-unlock dudect bench.
//
// The slot's Argon2id step is intentionally NOT constant-time (it
// must use data-dependent memory access patterns to be ASIC-resistant
// per the Argon2id design). What MUST be constant-time is everything
// AFTER the KEK derivation: the AEAD unwrap of the wrapped MVK and
// the slot-trial loop's rejection path.
//
// To isolate the post-KEK path from Argon2id's intentional variability
// we use the synthetic-slot helper from security_invariants tests:
// build a slot once, then time `Keyslot::unlock_passphrase` on
// MUTATED slot bytes (where the wrap_ct or wrap_tag differs in known
// places). Argon2id always runs on the same passphrase + same salt
// per attempt, so its variability is the SAME between class Left and
// class Right; any timing difference comes from the post-KEK path.
//
// Two classes:
//   Left:  wrapped_tag has byte 0 flipped
//   Right: wrapped_tag has byte 15 flipped
// Both reject; constant-time AEAD says no t-stat excursion.
//
// Run with: cargo bench --bench dudect_slot_unlock -p luksbox-core

use luksbox_core::{Argon2idParams, CipherSuite, Keyslot, MasterVolumeKey, SLOT_SIZE};
use luksbox_ct_bench::rand::prelude::*;
use luksbox_ct_bench::{BenchRng, Class, CtRunner, ctbench_main};

const WEAK_KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};
const HEADER_SALT: [u8; 32] = [0x42; 32];
const PASSPHRASE: &[u8] = b"benchpass";

// Slot byte offsets (see crates/luksbox-core/src/keyslot.rs)
const OFF_WRAPPED_TAG: usize = 108;

fn build_passphrase_slot_bytes() -> [u8; SLOT_SIZE] {
    let mvk = MasterVolumeKey::from_bytes([0xCC; 32]);
    let slot = Keyslot::new_passphrase(
        CipherSuite::Aes256GcmSiv,
        &mvk,
        PASSPHRASE,
        WEAK_KDF,
        &HEADER_SALT,
    )
    .expect("slot");
    slot.to_bytes()
}

fn slot_unlock_bench(runner: &mut CtRunner, rng: &mut BenchRng) {
    // Smaller N here because each iteration runs Argon2id (even with
    // weak params, 1 ms per call). 5_000 samples * 2 classes * 1 ms
    // = 10 seconds wall time for the bench.
    const N: usize = 5_000;
    let good_bytes = build_passphrase_slot_bytes();

    let mut inputs: Vec<[u8; SLOT_SIZE]> = Vec::with_capacity(N);
    let mut classes = Vec::with_capacity(N);
    for _ in 0..N {
        let mut buf = good_bytes;
        if rng.random::<bool>() {
            buf[OFF_WRAPPED_TAG] ^= 0x01;
            classes.push(Class::Left);
        } else {
            buf[OFF_WRAPPED_TAG + 15] ^= 0x01;
            classes.push(Class::Right);
        }
        inputs.push(buf);
    }

    for (input, class) in inputs.into_iter().zip(classes.into_iter()) {
        let parsed = Keyslot::from_bytes(&input).expect("parse mutated slot");
        runner.run_one(class, || {
            let r = std::hint::black_box(parsed.unlock_passphrase(
                CipherSuite::Aes256GcmSiv,
                std::hint::black_box(PASSPHRASE),
                std::hint::black_box(&HEADER_SALT),
            ));
            std::hint::black_box(r.is_err())
        });
    }
}

ctbench_main!(slot_unlock_bench);
