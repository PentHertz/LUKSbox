//! AFL++ harness: drives the in-header Secure Enclave region serializer +
//! parser with attacker-controlled slot indices, counts, and blob lengths.
//! Mirror of the libFuzzer `sep_region_parse` target. Invariants: never
//! panic; a header we built must re-parse; every accepted blob round-trips
//! byte-identical (the region count/slot_idx/blob_len table is symmetric).

use luksbox_core::{
    Argon2idParams, CipherSuite, Header, KdfId, Keyslot, MasterVolumeKey, MAX_KEYSLOTS,
};

fn main() {
    afl::fuzz!(|data: &[u8]| {
        let mvk = MasterVolumeKey::from_bytes([0x21; 32]);
        let mut header = Header::new(CipherSuite::Aes256GcmSiv, KdfId::Argon2id, 4096, 8192);

        let weak = Argon2idParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        };
        if let Ok(slot) = Keyslot::new_passphrase(
            CipherSuite::Aes256GcmSiv,
            &mvk,
            b"pw",
            weak,
            &header.header_salt,
        ) {
            let _ = header.install_slot(0, slot);
        }

        let mut cur = data;
        let n = cur.first().copied().unwrap_or(0) as usize;
        cur = cur.get(1..).unwrap_or(&[]);
        let mut expected: [Option<Vec<u8>>; MAX_KEYSLOTS] = std::array::from_fn(|_| None);
        for _ in 0..n {
            if cur.len() < 3 {
                break;
            }
            let idx = (cur[0] as usize) % MAX_KEYSLOTS;
            let len = u16::from_le_bytes([cur[1], cur[2]]) as usize;
            cur = &cur[3..];
            let take = len.min(cur.len());
            let blob = cur[..take].to_vec();
            cur = &cur[take..];
            if header.set_sep_blob(idx, blob.clone()).is_ok() {
                expected[idx] = Some(blob);
            }
        }

        let bytes = header.to_bytes(&mvk);
        let parsed = Header::from_bytes(&bytes).expect("a header we built must re-parse");
        for (idx, want) in expected.iter().enumerate() {
            assert_eq!(
                parsed.sep_blob(idx),
                want.as_deref(),
                "SEP blob at slot {idx} must round-trip byte-identical"
            );
        }
    });
}
