// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Round-trip property: a header that successfully parses must serialize back
//! to bytes that parse to a structurally equal header. Catches asymmetries
//! between the serializer and parser (different field orderings, lost
//! information, etc.).

use libfuzzer_sys::fuzz_target;
use luksbox_core::{HEADER_SIZE, Header, MasterVolumeKey};

fuzz_target!(|data: &[u8]| {
    if data.len() < HEADER_SIZE {
        return;
    }
    let mut buf = [0u8; HEADER_SIZE];
    buf.copy_from_slice(&data[..HEADER_SIZE]);
    let Ok(parsed) = Header::from_bytes(&buf) else {
        return;
    };

    // Re-serialize under a known MVK (HMAC over the header doesn't survive
    // the round-trip without re-keying, but the structural part 0..HMAC
    // should be reproducible from the parsed header).
    let mvk = MasterVolumeKey::from_bytes([0x55; 32]);
    let bytes2 = parsed.to_bytes(&mvk);
    let parsed2 = Header::from_bytes(&bytes2).expect("re-parse must succeed");

    // Compare structurally relevant fields.
    assert_eq!(parsed.cipher_suite, parsed2.cipher_suite);
    assert_eq!(parsed.kdf, parsed2.kdf);
    assert_eq!(parsed.chunk_size, parsed2.chunk_size);
    assert_eq!(parsed.header_salt, parsed2.header_salt);
    assert_eq!(parsed.metadata_offset, parsed2.metadata_offset);
    assert_eq!(parsed.metadata_size, parsed2.metadata_size);
    assert_eq!(parsed.data_offset, parsed2.data_offset);
    for i in 0..parsed.keyslots.len() {
        let a = &parsed.keyslots[i];
        let b = &parsed2.keyslots[i];
        assert_eq!(a.kind, b.kind);
        assert_eq!(a.uuid, b.uuid);
        // V3 slot layout reorganised cred_id (128..480) and hmac_salt
        // (480..512). A regression that read V3 but wrote V2 (or vice
        // versa) would corrupt these on round-trip without changing
        // kind / uuid. Check them explicitly.
        assert_eq!(a.aad_version, b.aad_version, "aad_version must round-trip");
        assert_eq!(
            a.fido2_cred_id, b.fido2_cred_id,
            "fido2_cred_id must round-trip byte-identical"
        );
        assert_eq!(
            a.fido2_hmac_salt, b.fido2_hmac_salt,
            "fido2_hmac_salt must round-trip byte-identical"
        );
    }
});
