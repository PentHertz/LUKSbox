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

    println!("seeds written under {base}/");
}
