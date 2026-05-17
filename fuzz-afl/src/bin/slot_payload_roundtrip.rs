//! AFL++ harness: `SlotPayload::new` → `encode` → `decode` round-trip
//! with attacker-controlled length triples. Mirrors
//! `fuzz/fuzz_targets/slot_payload_roundtrip.rs` (libfuzzer variant).

use luksbox_core::deniable::DeniableKindTag;
use luksbox_core::deniable::slot_payload::{
    CRED_ID_MAX_LEN, HMAC_SALT_LEN, MATERIAL_BUDGET, SlotPayload, TPM_BLOB_MAX_LEN,
};
use luksbox_core::error::Error;

const SLOT_NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const SLOT_TAG_LEN: usize = 16;

fn main() {
    afl::fuzz!(|data: &[u8]| {
        if data.len() < 1 + 2 + 2 + 1 + SLOT_NONCE_LEN + KEY_LEN + SLOT_TAG_LEN {
            return;
        }

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

        let cred_id_len =
            (u16::from_le_bytes([data[1], data[2]]) as usize) % (CRED_ID_MAX_LEN + 16);
        let tpm_blob_len =
            (u16::from_le_bytes([data[3], data[4]]) as usize) % (TPM_BLOB_MAX_LEN + 16);
        let has_salt = (data[5] & 1) == 1;

        let cred_id = vec![data[5] ^ 0x5a; cred_id_len];
        let tpm_blob = vec![data[5] ^ 0xa5; tpm_blob_len];
        let hmac_salt = if has_salt {
            let mut s = [0u8; HMAC_SALT_LEN];
            for (i, b) in s.iter_mut().enumerate() {
                *b = data[6 + (i % (data.len() - 6))];
            }
            Some(s)
        } else {
            None
        };

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

        let buf = payload
            .encode()
            .expect("encode succeeds for new()-accepted payload");
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
}
