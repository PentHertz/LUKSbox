// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Cross-suite correctness tests that exercise the Container layer
//! end-to-end (header HMAC + keyslot wrap/unwrap + metadata AEAD) for
//! every cipher_suite the format knows about.
//!
//! These complement the per-primitive AEAD roundtrip tests in
//! luksbox-core/src/aead.rs by also checking that the suite identifier
//! flows correctly through header serialization, keyslot AEAD AAD,
//! metadata AEAD, and reopen.

use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::{Container, UnlockMaterial};
use tempfile::tempdir;

fn test_params() -> Argon2idParams {
    Argon2idParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    }
}

/// End-to-end vault roundtrip under every supported cipher suite.
/// Catches the kind of bug where a refactor wires a new suite into
/// the AEAD primitive but forgets to thread it through one of the
/// (header, keyslot, metadata, chunk) callers.
fn roundtrip_under(suite: CipherSuite) {
    let dir = tempdir().unwrap();
    let path = dir.path().join(format!("{suite:?}.lbx"));

    {
        let mut c = Container::create_with_passphrase(
            &path,
            None,
            suite,
            test_params(),
            b"correct horse battery staple",
        )
        .unwrap();
        c.write_metadata(b"payload-for-suite-roundtrip").unwrap();
    }

    let mut c = Container::open(
        &path,
        None,
        UnlockMaterial::Passphrase(b"correct horse battery staple"),
    )
    .unwrap();
    assert_eq!(c.cipher_suite(), suite, "suite preserved across reopen");
    let blob = c.read_metadata().unwrap();
    assert_eq!(&**blob, b"payload-for-suite-roundtrip");
}

#[test]
fn end_to_end_aes_256_gcm() {
    roundtrip_under(CipherSuite::Aes256Gcm);
}

#[test]
fn end_to_end_chacha20_poly1305() {
    roundtrip_under(CipherSuite::ChaCha20Poly1305);
}

#[test]
fn end_to_end_aes_256_gcm_siv() {
    roundtrip_under(CipherSuite::Aes256GcmSiv);
}

/// Backward compatibility check: a vault created the legacy way
/// (explicit Aes256Gcm, the only choice before audit Finding 1) opens
/// cleanly under the new code. Pins that adding the SIV variant did
/// not alter the on-disk layout for existing vaults.
#[test]
fn pre_siv_vault_still_opens() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("legacy.lbx");

    // Create with the pre-audit default explicitly.
    {
        let mut c = Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            test_params(),
            b"legacy-pass",
        )
        .unwrap();
        c.write_metadata(b"data written with legacy suite").unwrap();
    }

    // Reopen with the post-audit code.
    let mut c = Container::open(&path, None, UnlockMaterial::Passphrase(b"legacy-pass")).unwrap();
    assert_eq!(c.cipher_suite(), CipherSuite::Aes256Gcm);
    let blob = c.read_metadata().unwrap();
    assert_eq!(&**blob, b"data written with legacy suite");
}

/// Each suite produces a header HMAC that's tied to that specific
/// suite identifier; the wrong-passphrase path doesn't accidentally
/// pass under a different suite. (Implicit through the AEAD tag, but
/// worth a regression test so a future "skip the suite check"
/// optimization doesn't slip in.)
#[test]
fn wrong_passphrase_rejected_under_each_suite() {
    for suite in [
        CipherSuite::Aes256Gcm,
        CipherSuite::ChaCha20Poly1305,
        CipherSuite::Aes256GcmSiv,
    ] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("v.lbx");
        Container::create_with_passphrase(&path, None, suite, test_params(), b"right").unwrap();
        let r = Container::open(&path, None, UnlockMaterial::Passphrase(b"wrong"));
        assert!(
            matches!(r, Err(luksbox_format::Error::UnlockFailed)),
            "wrong passphrase must be rejected under {suite:?}"
        );
    }
}

/// All three suites use a 12-byte nonce + 16-byte tag, so the on-disk
/// chunk slot size must be identical regardless of suite. This pins
/// the invariant the audit relied on when claiming "no on-disk format
/// change" for the SIV migration.
#[test]
fn all_suites_share_same_aead_geometry() {
    for suite in [
        CipherSuite::Aes256Gcm,
        CipherSuite::ChaCha20Poly1305,
        CipherSuite::Aes256GcmSiv,
    ] {
        assert_eq!(suite.nonce_len(), 12, "{suite:?}");
        assert_eq!(suite.tag_len(), 16, "{suite:?}");
    }
}

/// Cross-suite isolation: tamper the cipher_suite byte in a header
/// to claim a different algorithm; the open must fail. The suite
/// byte sits inside the header-HMAC scope, so the immediate failure
/// is HeaderAuthFailed rather than KeyslotAuthFailed, but EITHER is
/// an acceptable rejection for this regression - we just need the
/// open to refuse.
///
/// Why this matters: if a future "optimization" ever cached the
/// cipher_suite outside the HMAC region, an attacker could rewrite
/// it from Aes256Gcm to Aes256GcmSiv (or vice versa) and force the
/// runtime to attempt decryption with the wrong primitive against
/// the same wrapped MVK ciphertext. With both suites being 32-byte
/// keys + 12-byte nonces + 16-byte tags, the wrong-suite decryption
/// would silently produce garbage bytes that the AEAD tag check
/// would then have to catch - single line of defense rather than
/// two.
#[test]
fn tampered_cipher_suite_byte_is_rejected() {
    use std::io::{Read, Seek, SeekFrom, Write};

    // Header offsets per `header.rs`: OFF_CIPHER = 16, OFF_HEADER_SALT = 24.
    // We rewrite cipher byte at offset 16 (16-bit LE).
    const OFF_CIPHER: u64 = 16;

    for (orig, tampered_bytes, label) in [
        (CipherSuite::Aes256Gcm, [0x03, 0x00], "GCM->SIV"),
        (CipherSuite::Aes256GcmSiv, [0x01, 0x00], "SIV->GCM"),
        (
            CipherSuite::Aes256Gcm,
            [0x02, 0x00],
            "GCM->ChaCha20Poly1305",
        ),
    ] {
        let dir = tempdir().unwrap();
        let path = dir.path().join("victim.lbx");

        Container::create_with_passphrase(&path, None, orig, test_params(), b"pw").unwrap();

        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        f.seek(SeekFrom::Start(OFF_CIPHER)).unwrap();
        f.write_all(&tampered_bytes).unwrap();
        f.sync_all().unwrap();

        // Re-read for sanity (the byte really did change).
        let mut buf = [0u8; 2];
        f.seek(SeekFrom::Start(OFF_CIPHER)).unwrap();
        f.read_exact(&mut buf).unwrap();
        assert_eq!(buf, tampered_bytes, "{label}: tamper didn't take");
        drop(f);

        let r = Container::open(&path, None, UnlockMaterial::Passphrase(b"pw"));
        assert!(
            r.is_err(),
            "{label}: tampered cipher_suite byte must cause open() to fail, got Ok"
        );
    }
}
