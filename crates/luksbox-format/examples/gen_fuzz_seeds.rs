// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Generate seed-corpus files for the cargo-fuzz harness. Run with:
//!     cargo run --example gen_fuzz_seeds -p luksbox-format

use std::fs;

use luksbox_core::{
    Argon2idParams, CipherSuite, HEADER_SIZE, Header, KdfId, Keyslot, MasterVolumeKey, SLOT_SIZE,
};
use luksbox_format::metadata::write_metadata;

fn main() {
    let base = "/home/user/luksbox/fuzz/corpus";
    for d in [
        "header_parse",
        "header_roundtrip",
        "keyslot_parse",
        "metadata_parse",
    ] {
        fs::create_dir_all(format!("{base}/{d}")).unwrap();
    }

    let mvk = MasterVolumeKey::random();
    let weak = Argon2idParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };

    // AES header with one passphrase keyslot.
    let mut h_aes = Header::new(
        CipherSuite::Aes256Gcm,
        KdfId::Argon2id,
        4096,
        HEADER_SIZE as u64,
    );
    let slot_pp = Keyslot::new_passphrase(
        CipherSuite::Aes256Gcm,
        &mvk,
        b"seed",
        weak,
        &h_aes.header_salt,
    )
    .unwrap();
    h_aes.install_slot(0, slot_pp.clone()).unwrap();
    let h_aes_bytes = h_aes.to_bytes(&mvk);
    fs::write(format!("{base}/header_parse/seed_aes"), &h_aes_bytes).unwrap();
    fs::write(format!("{base}/header_roundtrip/seed_aes"), &h_aes_bytes).unwrap();

    // ChaCha header with the same keyslot.
    let mut h_cc = Header::new(
        CipherSuite::ChaCha20Poly1305,
        KdfId::Argon2id,
        4096,
        HEADER_SIZE as u64,
    );
    h_cc.install_slot(0, slot_pp.clone()).unwrap();
    let h_cc_bytes = h_cc.to_bytes(&mvk);
    fs::write(format!("{base}/header_parse/seed_chacha"), &h_cc_bytes).unwrap();
    fs::write(format!("{base}/header_roundtrip/seed_chacha"), &h_cc_bytes).unwrap();

    // FIDO2 keyslot variant for the round-trip target.
    let mut h_fido = Header::new(
        CipherSuite::Aes256Gcm,
        KdfId::Argon2id,
        4096,
        HEADER_SIZE as u64,
    );
    let slot_fido = Keyslot::new_fido2(
        CipherSuite::Aes256Gcm,
        &mvk,
        None,
        &[0xa5; 32],
        b"fake-cred-id-seed",
        [0xb6; 32],
        weak,
        &h_fido.header_salt,
    )
    .unwrap();
    h_fido.install_slot(0, slot_pp.clone()).unwrap();
    h_fido.install_slot(1, slot_fido.clone()).unwrap();
    let h_fido_bytes = h_fido.to_bytes(&mvk);
    fs::write(format!("{base}/header_parse/seed_fido"), &h_fido_bytes).unwrap();
    fs::write(format!("{base}/header_roundtrip/seed_fido"), &h_fido_bytes).unwrap();

    // Keyslot seeds: empty, passphrase, fido2.
    fs::write(format!("{base}/keyslot_parse/seed_empty"), [0u8; SLOT_SIZE]).unwrap();
    fs::write(format!("{base}/keyslot_parse/seed_pp"), slot_pp.to_bytes()).unwrap();
    fs::write(
        format!("{base}/keyslot_parse/seed_fido"),
        slot_fido.to_bytes(),
    )
    .unwrap();

    // V3-specific FIDO2 seeds: realistic cred_id sizes for both ends of
    // the spectrum we observe in production. These give libFuzzer a head
    // start exploring V3 layout offsets (cred_id 128..480, hmac_salt
    // 480..512) and the wider AAD scope (124..512) instead of mutating
    // its way there from a 17-byte cred_id seed.
    //
    // - "yubikey-style": 64 B cred_id, the typical YubiKey 4/5 size.
    //   Fits both V1/V2 and V3, useful for verifying V3 handles the
    //   small-cred-id case identically to V2.
    // - "titan-style":   288 B cred_id, the size we measured against a
    //   live Google Titan v2 (round 8 of the audit report). Exercises
    //   the V3-only path (would have been rejected by V1/V2 with
    //   Fido2CredIdTooLong).
    let yubikey_cred = vec![0xa5; 64];
    let titan_cred = vec![0xb6; 288];

    let slot_v3_yk = Keyslot::new_fido2(
        CipherSuite::Aes256Gcm,
        &mvk,
        None,
        &[0xc7; 32],
        &yubikey_cred,
        [0xd8; 32],
        weak,
        &h_aes.header_salt,
    )
    .expect("V3 64-byte cred_id slot must build");
    let slot_v3_titan = Keyslot::new_fido2(
        CipherSuite::Aes256Gcm,
        &mvk,
        None,
        &[0xe9; 32],
        &titan_cred,
        [0xfa; 32],
        weak,
        &h_aes.header_salt,
    )
    .expect("V3 288-byte cred_id slot must build");

    fs::write(
        format!("{base}/keyslot_parse/seed_fido_v3_yubikey"),
        slot_v3_yk.to_bytes(),
    )
    .unwrap();
    fs::write(
        format!("{base}/keyslot_parse/seed_fido_v3_titan"),
        slot_v3_titan.to_bytes(),
    )
    .unwrap();

    // V3-bearing header for header_parse / header_roundtrip targets.
    // Multi-slot: passphrase + V3 small-cred + V3 large-cred so the
    // parser walks across all three layouts in a single header.
    let mut h_v3 = Header::new(
        CipherSuite::Aes256GcmSiv,
        KdfId::Argon2id,
        4096,
        HEADER_SIZE as u64,
    );
    h_v3.install_slot(0, slot_pp.clone()).unwrap();
    h_v3.install_slot(1, slot_v3_yk.clone()).unwrap();
    h_v3.install_slot(2, slot_v3_titan.clone()).unwrap();
    let h_v3_bytes = h_v3.to_bytes(&mvk);
    fs::write(format!("{base}/header_parse/seed_v3_multi"), &h_v3_bytes).unwrap();
    fs::write(
        format!("{base}/header_roundtrip/seed_v3_multi"),
        &h_v3_bytes,
    )
    .unwrap();

    // Valid encrypted metadata region.
    let mut region = vec![0u8; 1024 * 1024];
    write_metadata(
        CipherSuite::Aes256Gcm,
        &mvk,
        &h_aes.header_salt,
        b"hello-world",
        &mut region,
    )
    .unwrap();
    fs::write(format!("{base}/metadata_parse/seed_valid"), &region).unwrap();

    // Truncated metadata regions to seed pre-AEAD parser exploration.
    fs::write(format!("{base}/metadata_parse/seed_short"), &region[..40]).unwrap();
    fs::write(format!("{base}/metadata_parse/seed_zero"), vec![0u8; 4096]).unwrap();

    // -------------------------------------------------------------
    // Deniable v2 seeds. Written to BOTH the libfuzzer corpus and
    // the AFL++ seeds directory so the two parallel setups share
    // their human-curated regression inputs (see FUZZING.md).
    // -------------------------------------------------------------
    let afl_base = "/home/user/luksbox/fuzz-afl/seeds";
    for d in [
        "deniable_header_parse",
        "slot_payload_decode",
        "slot_payload_roundtrip",
    ] {
        fs::create_dir_all(format!("{base}/{d}")).unwrap();
        fs::create_dir_all(format!("{afl_base}/{d}")).unwrap();
    }

    // deniable_header_parse seed: a real v2 header built from a
    // Passphrase credential, appended with a passphrase length byte +
    // the passphrase + padding. Matches the harness's expected input
    // shape (`DENIABLE_HEADER_SIZE + 64` bytes minimum).
    {
        use luksbox_core::deniable::DeniableCredential;
        use luksbox_format::deniable_header::{
            DeniableInnerHeader, DeniableMaterial, create_with_credential_v2,
        };
        let pass: &[u8] = b"seed-corpus-pass";
        let cred = DeniableCredential::Passphrase {
            passphrase: pass,
            argon2: weak,
        };
        let inner = DeniableInnerHeader {
            format_version_minor: 0,
            cipher_suite: CipherSuite::Aes256GcmSiv,
            kdf_id: KdfId::Argon2id,
            flags: 0,
            metadata_offset: luksbox_core::deniable::DENIABLE_HEADER_SIZE as u64,
            metadata_size: 4096,
            data_offset: luksbox_core::deniable::DENIABLE_HEADER_SIZE as u64 + 4096,
            chunk_size: 4096,
        };
        let (hdr, _mvk) = create_with_credential_v2(
            &cred,
            &DeniableMaterial::passphrase_only(),
            0,
            CipherSuite::Aes256GcmSiv,
            inner,
        )
        .unwrap();

        // Tail layout the harness expects: rest[0] = pass len,
        // rest[1..] = passphrase, rest[257] = cipher byte (=0 here,
        // which maps to Aes256GcmSiv -- matches what we created with).
        let mut tail = vec![0u8; 64];
        tail[0] = pass.len() as u8;
        tail[1..1 + pass.len()].copy_from_slice(pass);

        let mut seed = hdr.clone();
        seed.extend_from_slice(&tail);
        fs::write(
            format!("{base}/deniable_header_parse/seed_passphrase"),
            &seed,
        )
        .unwrap();
        fs::write(
            format!("{afl_base}/deniable_header_parse/seed_passphrase"),
            &seed,
        )
        .unwrap();
    }

    // slot_payload_decode seed: a valid encoded `SlotPayload` whose
    // length is exactly `PAYLOAD_PLAINTEXT_LEN`. Decoder will accept
    // and the harness's round-trip assertion will hold.
    {
        use luksbox_core::deniable::DeniableKindTag;
        use luksbox_core::deniable::slot_payload::{HMAC_SALT_LEN, SlotPayload};
        let payload = SlotPayload::new(
            DeniableKindTag::Fido2Passphrase,
            vec![0x42; 32],
            Some([0x99; HMAC_SALT_LEN]),
            Vec::new(),
            [0xab; 12],
            [0xcd; 48],
        )
        .unwrap();
        let encoded = payload.encode().unwrap();
        fs::write(
            format!("{base}/slot_payload_decode/seed_fido2_payload"),
            &encoded,
        )
        .unwrap();
        fs::write(
            format!("{afl_base}/slot_payload_decode/seed_fido2_payload"),
            &encoded,
        )
        .unwrap();
        // Pure-zero buffer: decoder must reject (kind=0 is not a
        // valid `DeniableKindTag`); good for AFL to learn the
        // fail-fast path.
        let zeros = vec![0u8; encoded.len()];
        fs::write(format!("{base}/slot_payload_decode/seed_zeros"), &zeros).unwrap();
        fs::write(format!("{afl_base}/slot_payload_decode/seed_zeros"), &zeros).unwrap();
    }

    // slot_payload_roundtrip seed: a minimal-length buffer that
    // satisfies the harness's `data.len() >= 1 + 2 + 2 + 1 + 12 +
    // 32 + 16 = 65` precondition. Picks kind=0 (Passphrase) with
    // empty material to hit the simplest in-budget branch.
    {
        let mut seed = vec![0u8; 96];
        seed[0] = 0; // data[0] % 8 -> Passphrase
        // cred_id_len = 0, tpm_blob_len = 0, has_salt = false; nonce
        // + ct_and_tag stay zero. Constructor accepts; round-trip
        // assertion holds.
        fs::write(format!("{base}/slot_payload_roundtrip/seed_minimal"), &seed).unwrap();
        fs::write(
            format!("{afl_base}/slot_payload_roundtrip/seed_minimal"),
            &seed,
        )
        .unwrap();
    }

    println!("seeds written under {base}/ and {afl_base}/");
}
