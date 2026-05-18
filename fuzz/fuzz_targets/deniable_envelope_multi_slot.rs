// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Multi-slot deniable envelope-opacity target.
//!
//! Complements `deniable_header_parse` (which fuzzes a single random
//! buffer) by constructing a real, well-formed deniable header with a
//! fuzzer-controlled subset of slots occupied, then driving
//! `try_open_envelope_v2` with attacker-supplied passphrase / cipher /
//! Argon2 params.
//!
//! Threat model: an attacker who can observe wall-clock or allocator
//! timing across multiple unlock attempts learns which slot (if any)
//! holds the user's credential. Round 12 finding R12-01 documents the
//! current implementation as branching on AEAD-open success - this
//! target catches regressions that re-introduce a NON-OPAQUE error or
//! a panic on the multi-slot path. The timing-leak proper is covered
//! by the dudect bench at
//! `crates/luksbox-format/benches/dudect_deniable_envelope.rs`.
//!
//! Invariants checked:
//! 1. Never panic, regardless of which slots are occupied or which
//!    fuzzer-supplied passphrase is used.
//! 2. Every non-Ok outcome collapses to `Error::OpaqueUnlockFailed`.
//! 3. When the fuzzer-supplied passphrase happens to match an enrolled
//!    slot's envelope passphrase, the open succeeds and the payload
//!    parses cleanly (no panic, no allocator blowup).

use libfuzzer_sys::fuzz_target;
use luksbox_core::deniable::{
    DENIABLE_HEADER_SIZE, DENIABLE_SALT_SIZE, DENIABLE_SLOT_COUNT, DeniableCredential,
};
use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::deniable_header::{
    DeniableInnerHeader, DeniableMaterial, create_with_credential_v2, install_slot_v2,
    try_open_envelope_v2,
};
use luksbox_format::error::Error;

// Cheapest sane Argon2 params. The fuzzer's attacker-controlled
// passphrase will (almost) never match by chance, so we want each
// iteration to spend its budget on the AEAD/discovery path, not on
// Argon2 stretching.
const CHEAP_KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};
const CIPHER: CipherSuite = CipherSuite::Aes256GcmSiv;
// Stable known passphrase the harness uses to enroll slots. The
// fuzzer never knows it, so the only path that opens is "fuzzer
// supplied the same string by chance" (effectively zero) or "fuzzer
// supplied a different string and the open opaque-fails". Both are
// valid outcomes; what's invariant is opacity + no panic.
const ENROLL_PASSPHRASE: &[u8] = b"luksbox-fuzz-enroll-shared-envelope-passphrase";

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

fuzz_target!(|data: &[u8]| {
    // Need at least:
    //   1 byte: occupancy bitmap (which of the 8 slots are enrolled)
    //   1 byte: passphrase length cap (0..=255)
    //   1 byte: cipher choice
    //   <= 256 bytes: attacker passphrase
    if data.len() < 4 {
        return;
    }

    let occupancy: u8 = data[0]; // bit k set -> enroll slot k
    let pass_len = (data[1] as usize).min(data.len() - 3).min(256);
    let cipher = match data[2] % 3 {
        0 => CipherSuite::Aes256GcmSiv,
        1 => CipherSuite::Aes256Gcm,
        _ => CipherSuite::ChaCha20Poly1305,
    };
    let attacker_passphrase = &data[3..3 + pass_len];

    // Find the first occupied slot to seed the header with. If the
    // bitmap is zero, fall back to slot 0 so we still build something
    // resembling a deniable header (uniformly-random slots end up
    // being unparseable as envelopes; the fuzzer still exercises
    // opacity on miss).
    let first = (0..DENIABLE_SLOT_COUNT)
        .find(|i| (occupancy >> i) & 1 == 1)
        .unwrap_or(0);

    let enroll_cred = DeniableCredential::Passphrase {
        passphrase: ENROLL_PASSPHRASE,
        argon2: CHEAP_KDF,
    };
    let material = DeniableMaterial::default();

    let (header_vec, mvk) = match create_with_credential_v2(
        &enroll_cred,
        &material,
        first,
        CIPHER,
        cheap_inner(),
    ) {
        Ok(v) => v,
        Err(_) => return, // create cannot reasonably fail at these params; bail.
    };
    if header_vec.len() < DENIABLE_HEADER_SIZE {
        return;
    }
    let mut header_arr = [0u8; DENIABLE_HEADER_SIZE];
    header_arr.copy_from_slice(&header_vec[..DENIABLE_HEADER_SIZE]);
    // Per-vault salt lives in the first 32 bytes of the header (the
    // sole structural byte every deniable vault necessarily exposes).
    let mut salt = [0u8; DENIABLE_SALT_SIZE];
    salt.copy_from_slice(&header_arr[..DENIABLE_SALT_SIZE]);

    // Enroll the remaining bitmap-selected slots, all with the SAME
    // envelope passphrase (the multi-slot kind-disambiguation path
    // the constant-time invariant must protect).
    for i in (first + 1)..DENIABLE_SLOT_COUNT {
        if (occupancy >> i) & 1 != 1 {
            continue;
        }
        let _ = install_slot_v2(
            &mut header_arr,
            i,
            &enroll_cred,
            &material,
            &mvk,
            CIPHER,
            &salt,
        );
        // Failures fall through silently; the slot stays OsRng-filled,
        // which is exactly the "empty slot" wire shape.
    }

    let attacker_cred = DeniableCredential::Passphrase {
        passphrase: attacker_passphrase,
        argon2: CHEAP_KDF,
    };

    // Drive the envelope-discovery loop with the attacker passphrase
    // against the multi-slot header.
    match try_open_envelope_v2(&header_arr, &attacker_cred, cipher) {
        Ok(_envelope) => {
            // Fuzzer matched the harness's known passphrase by chance.
            // No panic = invariant 3 holds.
        }
        Err(Error::OpaqueUnlockFailed) => {
            // Expected for the overwhelming majority of inputs.
        }
        Err(other) => {
            panic!(
                "multi-slot envelope open leaked a non-opaque error variant: {:?}",
                other
            );
        }
    }
});
