// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

// Deniable envelope-discovery dudect bench.
//
// Pins Round 12 finding R12-01: the v2 envelope discovery loop in
// `crates/luksbox-format/src/deniable_header.rs::try_open_envelope_v2`
// branches on AEAD-open success, allocates a `Zeroizing<Vec>` +
// `Zeroizing<[u8; PAYLOAD_PLAINTEXT_LEN]>` + memcpy + runs
// `SlotPayload::decode` only on the matching slot. Slots that fail
// AEAD-open skip all that. The total wall-clock cost of the loop
// therefore depends on (a) whether ANY slot matched and (b) which
// slot index matched.
//
// This bench drives `try_open_envelope_v2` 5_000 times per class with
// a valid envelope passphrase. Class Left: slot 0 is the occupied
// one. Class Right: slot 7 is the occupied one. All other slots are
// fresh OsRng. A leak-free implementation must visit every slot's
// AEAD-open AND post-open work identically, so the t-stat across the
// two classes should stay below 3.0.
//
// On the CURRENT branch this bench is expected to FAIL with a large
// |t| - that is the proof of R12-01. Once the fix lands (constant-time
// candidate selection via `subtle::Choice`), the bench should pass and
// stay passing.
//
// Run with: cargo bench --bench dudect_deniable_envelope -p luksbox-format

use luksbox_core::deniable::{DENIABLE_HEADER_SIZE, DENIABLE_SLOT_COUNT, DeniableCredential};
use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_ct_bench::rand::prelude::*;
use luksbox_ct_bench::{BenchRng, Class, CtRunner, ctbench_main};
use luksbox_format::deniable_header::{
    DeniableInnerHeader, DeniableMaterial, create_with_credential_v2, try_open_envelope_v2,
};

const WEAK_KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};
const CIPHER: CipherSuite = CipherSuite::Aes256GcmSiv;
const PASSPHRASE: &[u8] = b"benchpass-envelope";

fn cheap_inner() -> DeniableInnerHeader {
    DeniableInnerHeader {
        format_version_minor: 0,
        cipher_suite: CIPHER,
        kdf_id: luksbox_core::KdfId::Argon2id,
        flags: 0,
        metadata_offset: DENIABLE_HEADER_SIZE as u64,
        metadata_size: 4096,
        data_offset: DENIABLE_HEADER_SIZE as u64 + 4096,
        chunk_size: 4096,
    }
}

// Build a deniable header with exactly one occupied slot at `slot_idx`.
// All other slots are pure OsRng, indistinguishable from random.
fn build_header_with_slot_at(slot_idx: usize) -> [u8; DENIABLE_HEADER_SIZE] {
    let cred = DeniableCredential::Passphrase {
        passphrase: PASSPHRASE,
        argon2: WEAK_KDF,
    };
    let material = DeniableMaterial::default();
    let (bytes, _mvk) =
        create_with_credential_v2(&cred, &material, slot_idx, CIPHER, cheap_inner())
            .expect("build deniable header");
    let mut out = [0u8; DENIABLE_HEADER_SIZE];
    out.copy_from_slice(&bytes[..DENIABLE_HEADER_SIZE]);
    out
}

fn envelope_open_bench(runner: &mut CtRunner, rng: &mut BenchRng) {
    // 5_000 samples per class. Each iteration runs ONE Argon2id call
    // (weak params = ~1 ms) + 8 AEAD opens. 10_000 iter * ~1.5 ms =
    // ~15 s total wall time on a modern x86_64.
    const N: usize = 5_000;
    const LEFT_SLOT: usize = 0;
    const RIGHT_SLOT: usize = DENIABLE_SLOT_COUNT - 1;

    // Build the two reference headers once. Each iteration uses a
    // FRESH copy to defeat any allocator-state confound.
    let left_header = build_header_with_slot_at(LEFT_SLOT);
    let right_header = build_header_with_slot_at(RIGHT_SLOT);

    let mut inputs: Vec<([u8; DENIABLE_HEADER_SIZE], Class)> = Vec::with_capacity(N * 2);
    for _ in 0..N {
        if rng.random::<bool>() {
            inputs.push((left_header, Class::Left));
        } else {
            inputs.push((right_header, Class::Right));
        }
    }

    let cred = DeniableCredential::Passphrase {
        passphrase: PASSPHRASE,
        argon2: WEAK_KDF,
    };

    for (header, class) in inputs.into_iter() {
        runner.run_one(class, || {
            let r = std::hint::black_box(try_open_envelope_v2(
                std::hint::black_box(&header),
                std::hint::black_box(&cred),
                std::hint::black_box(CIPHER),
            ));
            std::hint::black_box(r.is_ok())
        });
    }
}

ctbench_main!(envelope_open_bench);
