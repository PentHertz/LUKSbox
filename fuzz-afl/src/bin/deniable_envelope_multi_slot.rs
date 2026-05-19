// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! AFL++ harness: multi-slot deniable envelope opacity. Mirrors
//! `fuzz/fuzz_targets/deniable_envelope_multi_slot.rs` (libfuzzer
//! variant).
//!
//! Builds a real deniable header with a fuzzer-controlled subset of
//! the 8 slots enrolled under a shared envelope passphrase, then
//! drives `try_open_envelope_v2` with an attacker-supplied
//! passphrase / cipher. Catches regressions that re-introduce a
//! non-opaque error variant or a panic on the multi-slot path.
//!
//! See `docs/SECURITY_AUDIT_ROUND_12.md` finding R12-01 for the
//! threat model. The timing-leak proper is benched separately via
//! `crates/luksbox-format/benches/dudect_deniable_envelope.rs`.

use luksbox_core::deniable::{
    DENIABLE_HEADER_SIZE, DENIABLE_SALT_SIZE, DENIABLE_SLOT_COUNT, DeniableCredential,
};
use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::deniable_header::{
    DeniableInnerHeader, DeniableMaterial, create_with_credential_v2, install_slot_v2,
    try_open_envelope_v2,
};
use luksbox_format::error::Error;

const CHEAP_KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};
const CIPHER: CipherSuite = CipherSuite::Aes256GcmSiv;
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

fn main() {
    afl::fuzz!(|data: &[u8]| {
        if data.len() < 4 {
            return;
        }

        let occupancy: u8 = data[0];
        let pass_len = (data[1] as usize).min(data.len() - 3).min(256);
        let cipher = match data[2] % 3 {
            0 => CipherSuite::Aes256GcmSiv,
            1 => CipherSuite::Aes256Gcm,
            _ => CipherSuite::ChaCha20Poly1305,
        };
        let attacker_passphrase = &data[3..3 + pass_len];

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
            Err(_) => return,
        };
        if header_vec.len() < DENIABLE_HEADER_SIZE {
            return;
        }
        let mut header_arr = [0u8; DENIABLE_HEADER_SIZE];
        header_arr.copy_from_slice(&header_vec[..DENIABLE_HEADER_SIZE]);
        let mut salt = [0u8; DENIABLE_SALT_SIZE];
        salt.copy_from_slice(&header_arr[..DENIABLE_SALT_SIZE]);

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
        }

        let attacker_cred = DeniableCredential::Passphrase {
            passphrase: attacker_passphrase,
            argon2: CHEAP_KDF,
        };

        match try_open_envelope_v2(&header_arr, &attacker_cred, cipher, None) {
            Ok(_envelope) => {}
            Err(Error::OpaqueUnlockFailed) => {}
            Err(other) => {
                panic!(
                    "multi-slot envelope open leaked a non-opaque error variant: {:?}",
                    other
                );
            }
        }
    });
}
