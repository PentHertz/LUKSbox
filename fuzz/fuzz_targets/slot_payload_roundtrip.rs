// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Encode -> decode round-trip fuzz target for v2 deniable slot
//! payloads. Builds `SlotPayload` instances from attacker-controlled
//! length triples and verifies that any payload `new()` accepts also
//! survives `encode -> decode` with identical fields.
//!
//! Complements `slot_payload_decode`: that target attacks the decoder
//! directly with arbitrary bytes. This one attacks the
//! constructor/encoder/decoder triangle, looking for asymmetries
//! (e.g., a length the constructor accepts but the encoder lays out
//! in a way the decoder rejects) that could cause a legitimate vault
//! to fail to open or, worse, decode into a payload whose fields
//! differ from what was encoded.
//!
//! Invariants checked:
//! 1. `SlotPayload::new` either accepts an input with `Ok(_)` or
//!    rejects it with `Err(Error::InvalidField)`, never panics.
//! 2. Any payload that `new()` + `encode()` accepts MUST also
//!    `decode()` successfully (the constructor's contract is the
//!    decoder's input contract).
//! 3. After `encode -> decode`, every field matches the original
//!    byte-for-byte. A divergence here would mean a legitimate vault
//!    can corrupt itself across save/load.

use libfuzzer_sys::fuzz_target;
use luksbox_core::deniable::DeniableKindTag;
use luksbox_core::deniable::slot_payload::{
    CRED_ID_MAX_LEN, HMAC_SALT_LEN, MATERIAL_BUDGET, SlotPayload, TPM_BLOB_MAX_LEN,
};
use luksbox_core::error::Error;

// The wrapped_mvk nonce + ciphertext+tag region of a slot is opaque
// to this module; use the same constants the production code uses.
const SLOT_NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const SLOT_TAG_LEN: usize = 16;

fuzz_target!(|data: &[u8]| {
    // Need enough bytes for: kind selector (1) + cred_id_len (2) +
    // tpm_blob_len (2) + has_salt (1) + cred_id bytes + tpm_blob bytes
    // + 12 nonce + 48 ct_and_tag. Anything shorter is uninteresting.
    if data.len() < 1 + 2 + 2 + 1 + SLOT_NONCE_LEN + KEY_LEN + SLOT_TAG_LEN {
        return;
    }

    // Pick a kind from the eight valid tags. Modulo 8 ensures every
    // iteration produces a real variant; `DeniableKindTag::from_u8`
    // is exercised separately in `slot_payload_decode`.
    let kind = match data[0] % 8 {
        0 => DeniableKindTag::Passphrase,
        1 => DeniableKindTag::Fido2Passphrase,
        2 => DeniableKindTag::TpmPassphrase,
        3 => DeniableKindTag::TpmFido2Passphrase,
        4 => DeniableKindTag::HybridPqPassphrase,
        5 => DeniableKindTag::HybridPqFido2Passphrase,
        6 => DeniableKindTag::HybridPqTpmPassphrase,
        _ => DeniableKindTag::HybridPqTpmFido2Passphrase,
    };

    // Lengths from the next 4 bytes. Cap each at slightly above its
    // per-field max so we exercise both the under-cap accepting path
    // and the over-cap rejecting path. The joint budget check inside
    // `new()` is then exercised by the modulo-arithmetic landing
    // sometimes above MATERIAL_BUDGET.
    let cred_id_len =
        (u16::from_le_bytes([data[1], data[2]]) as usize) % (CRED_ID_MAX_LEN + 16);
    let tpm_blob_len =
        (u16::from_le_bytes([data[3], data[4]]) as usize) % (TPM_BLOB_MAX_LEN + 16);
    let has_salt = (data[5] & 1) == 1;

    // Build the material vectors deterministically from the
    // remaining fuzzer input. We do NOT need cryptographically
    // meaningful contents; we just need the round-trip to compare
    // byte-for-byte.
    let cred_id = vec![data[5] ^ 0x5a; cred_id_len];
    let tpm_blob = vec![data[5] ^ 0xa5; tpm_blob_len];
    let hmac_salt = if has_salt {
        let mut s = [0u8; HMAC_SALT_LEN];
        // Cycle the remaining input into the salt slot.
        for (i, b) in s.iter_mut().enumerate() {
            *b = data[6 + (i % (data.len() - 6))];
        }
        Some(s)
    } else {
        None
    };

    // Nonce + wrapped MVK ciphertext+tag: fill from any 12 + 48 bytes.
    let nonce_off = 6 % data.len();
    let mut nonce = [0u8; SLOT_NONCE_LEN];
    for (i, b) in nonce.iter_mut().enumerate() {
        *b = data[(nonce_off + i) % data.len()];
    }
    let mut ct_and_tag = [0u8; KEY_LEN + SLOT_TAG_LEN];
    for (i, b) in ct_and_tag.iter_mut().enumerate() {
        *b = data[(nonce_off + SLOT_NONCE_LEN + i) % data.len()];
    }

    let payload = match SlotPayload::new(
        kind,
        cred_id.clone(),
        hmac_salt,
        tpm_blob.clone(),
        nonce,
        ct_and_tag,
    ) {
        Ok(p) => p,
        Err(Error::InvalidField) => {
            // Rejected at construction. Verify the rejection is
            // consistent with the documented caps: at least one
            // length must be over its cap, or the joint material
            // budget must be exceeded.
            let salt_len = if has_salt { HMAC_SALT_LEN } else { 0 };
            let over_cred = cred_id_len > CRED_ID_MAX_LEN;
            let over_tpm = tpm_blob_len > TPM_BLOB_MAX_LEN;
            let over_joint = cred_id_len + salt_len + tpm_blob_len > MATERIAL_BUDGET;
            assert!(
                over_cred || over_tpm || over_joint,
                "SlotPayload::new rejected an in-budget input \
                 (cred_id_len={cred_id_len}, salt_len={salt_len}, \
                  tpm_blob_len={tpm_blob_len})",
            );
            return;
        }
        Err(other) => panic!(
            "SlotPayload::new returned a non-InvalidField error: {other:?}"
        ),
    };

    let buf = payload.encode().expect("encode succeeds for new()-accepted payload");
    let decoded =
        SlotPayload::decode(&buf).expect("decode succeeds for any encoded payload");

    assert_eq!(decoded.kind, kind, "kind diverged across round-trip");
    assert_eq!(decoded.cred_id, cred_id, "cred_id diverged");
    assert_eq!(decoded.hmac_salt, hmac_salt, "hmac_salt diverged");
    assert_eq!(decoded.tpm_blob, tpm_blob, "tpm_blob diverged");
    assert_eq!(decoded.wrapped_mvk_nonce, nonce, "wrapped_mvk_nonce diverged");
    assert_eq!(
        decoded.wrapped_mvk_ct_and_tag, ct_and_tag,
        "wrapped_mvk_ct_and_tag diverged"
    );
});
