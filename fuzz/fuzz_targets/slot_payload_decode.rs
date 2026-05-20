// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Adversarial fuzz target for the v2 deniable slot-payload decoder.
//!
//! `SlotPayload::decode` runs on the AEAD-verified plaintext of a
//! deniable slot envelope. By the time it executes, the attacker has
//! already proven knowledge of the envelope KEK -- but if they can
//! tamper with the underlying storage (e.g. raw block device, NFS
//! middlebox, ZFS snapshot rollback) they can present a tag-forged
//! plaintext that passes the AEAD check on the *next* legitimate
//! open. The decoder is the last validation layer before the
//! resulting `cred_id` / `hmac_salt` / `tpm_blob` are fed into
//! `KEK_factors` derivation and the inner-MVK unwrap.
//!
//! The reachable path through `deniable_header_parse` requires the
//! fuzzer to first guess a valid envelope KEK, which is
//! astronomically unlikely. This target bypasses Argon2id and feeds
//! the decoder directly so the structural checks (kind tag, length
//! fields, reserved bytes, joint material budget, in-buffer offset
//! arithmetic) get real coverage.
//!
//! Invariants checked:
//! 1. NEVER panic / OOB-index / wild-allocate on any 4068-byte input.
//! 2. EVERY rejection returns `Error::InvalidField` (the only failure
//!    mode the decoder is allowed to return). Any other error
//!    variant is a regression that leaks decoder internals.
//! 3. Any input that decodes successfully MUST re-encode to a buffer
//!    whose fixed header (the first PAYLOAD_HEADER_LEN bytes) and
//!    material region (cred_id || hmac_salt || tpm_blob ||
//!    wrapped_mvk) are byte-identical to the input. The trailing
//!    padding will differ (encode fills it with fresh OsRng bytes
//!    deliberately), so that region is excluded from the comparison.

use libfuzzer_sys::fuzz_target;
use luksbox_core::deniable::slot_payload::{
    PAYLOAD_HEADER_LEN, PAYLOAD_PLAINTEXT_LEN, SlotPayload,
};
use luksbox_core::error::Error;

fuzz_target!(|data: &[u8]| {
    if data.len() < PAYLOAD_PLAINTEXT_LEN {
        return;
    }
    let mut buf = [0u8; PAYLOAD_PLAINTEXT_LEN];
    buf.copy_from_slice(&data[..PAYLOAD_PLAINTEXT_LEN]);

    match SlotPayload::decode(&buf) {
        Ok(payload) => {
            // Round-trip: re-encode the decoded payload. The fixed
            // header + declared material must round-trip byte-for-byte.
            // The encoded trailing padding is fresh randomness so we
            // skip past it for the comparison.
            let re = payload.encode().expect("encode succeeds on decoded payload");

            // Fixed 8-byte header (kind + 3 length fields + 2 reserved).
            assert_eq!(
                &buf[..PAYLOAD_HEADER_LEN],
                &re[..PAYLOAD_HEADER_LEN],
                "fixed header diverged across decode->encode",
            );

            // Material region: cred_id + hmac_salt + wrapped_mvk all
            // sit between PAYLOAD_HEADER_LEN and the start of the
            // random padding. Recompute the boundary the same way
            // encode() does.
            use luksbox_core::deniable::slot_payload::{
                HMAC_SALT_LEN, WRAPPED_MVK_LEN,
            };
            let salt_len = if payload.hmac_salt.is_some() {
                HMAC_SALT_LEN
            } else {
                0
            };
            let material_end = PAYLOAD_HEADER_LEN
                + payload.cred_id.len()
                + salt_len
                + payload.tpm_blob.len()
                + WRAPPED_MVK_LEN;
            assert!(material_end <= PAYLOAD_PLAINTEXT_LEN);
            assert_eq!(
                &buf[PAYLOAD_HEADER_LEN..material_end],
                &re[PAYLOAD_HEADER_LEN..material_end],
                "decoded material region did not round-trip",
            );
        }
        Err(Error::InvalidField) => {
            // Expected rejection mode. Done.
        }
        Err(other) => {
            panic!(
                "SlotPayload::decode returned a non-InvalidField error, \
                 leaking decoder internals: {other:?}"
            );
        }
    }
});
