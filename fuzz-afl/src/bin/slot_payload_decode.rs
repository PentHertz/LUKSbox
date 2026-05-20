//! AFL++ harness: arbitrary `PAYLOAD_PLAINTEXT_LEN`-byte buffers fed
//! to `SlotPayload::decode`. Mirrors
//! `fuzz/fuzz_targets/slot_payload_decode.rs` (libfuzzer variant).
//!
//! Threat model + invariants documented at the libfuzzer target;
//! see also `docs/DENIABLE_HEADER.md` § "Test coverage matrix".

use luksbox_core::deniable::slot_payload::{
    PAYLOAD_HEADER_LEN, PAYLOAD_PLAINTEXT_LEN, SlotPayload,
};
use luksbox_core::error::Error;

fn main() {
    afl::fuzz!(|data: &[u8]| {
        if data.len() < PAYLOAD_PLAINTEXT_LEN {
            return;
        }
        let mut buf = [0u8; PAYLOAD_PLAINTEXT_LEN];
        buf.copy_from_slice(&data[..PAYLOAD_PLAINTEXT_LEN]);

        match SlotPayload::decode(&buf) {
            Ok(payload) => {
                let re = payload
                    .encode()
                    .expect("encode succeeds on decoded payload");
                assert_eq!(
                    &buf[..PAYLOAD_HEADER_LEN],
                    &re[..PAYLOAD_HEADER_LEN],
                    "fixed header diverged across decode->encode",
                );
                use luksbox_core::deniable::slot_payload::{HMAC_SALT_LEN, WRAPPED_MVK_LEN};
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
            Err(Error::InvalidField) => {}
            Err(other) => panic!(
                "SlotPayload::decode returned a non-InvalidField error, \
                 leaking decoder internals: {other:?}"
            ),
        }
    });
}
