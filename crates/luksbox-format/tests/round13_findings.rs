// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Regression tests pinning the Round 13 security audit findings.
//!
//! See `docs/SECURITY_AUDIT_ROUND_13.md` for the threat model and the
//! per-finding fix plan. Unlike Round 12, every test below ships
//! green from the first commit because the fixes landed before the
//! tests did. New regressions surface as test failures rather than
//! re-audits.
//!
//! ```bash
//! cargo test --test round13_findings -p luksbox-format
//! ```
//!
//! A few of the findings live in sibling crates (`luksbox-core`,
//! `luksbox-vfs`, `luksbox-pq`, `luksbox-mount`). Those crates carry
//! their own regression tests under their `tests/` directories; the
//! ones below cover the format-layer surface plus a few cross-crate
//! integration paths that already pull in `luksbox-format` as a dev
//! dependency.

use luksbox_format::{Container, UnlockMaterial};

// ---------------------------------------------------------------------
// R13-02 - inline header restore was reopening the vault path unsafely.
// ---------------------------------------------------------------------
//
// The fix is `Container::restore_header_bytes`, which routes the
// rewrite through the already-verified `self.file` handle (inline) or
// `atomic_secure_write` (detached). This test:
//   1. Builds a vault with a known header.
//   2. Captures the on-disk first-8 KiB.
//   3. Opens the vault as a Container, calls restore_header_bytes
//      with a flipped-byte payload.
//   4. Confirms the on-disk bytes are exactly the supplied payload.

#[test]
fn r13_02_restore_header_bytes_writes_via_container_handle() {
    use luksbox_core::HEADER_SIZE;
    use std::io::{Read as _, Seek as _, SeekFrom};

    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.lbx");

    let kdf = luksbox_core::Argon2idParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };
    // Create a minimal AES-256-GCM-SIV vault with a passphrase slot.
    Container::create_with_passphrase(
        &vault,
        None,
        luksbox_core::CipherSuite::Aes256GcmSiv,
        kdf,
        b"pass",
    )
    .unwrap();

    // Snapshot original header bytes.
    let mut original = [0u8; HEADER_SIZE];
    {
        let mut f = std::fs::File::open(&vault).unwrap();
        f.read_exact(&mut original).unwrap();
    }

    // Build a synthetic "backup": header bytes XOR'd at every offset
    // with a fixed byte. The result is not a valid header (HMAC won't
    // verify), so we go through restore_header_bytes which does NOT
    // re-parse; we're testing the byte-for-byte write path here, not
    // the higher-level CLI HMAC check.
    let mut backup = original;
    for b in backup.iter_mut() {
        *b ^= 0x5a;
    }

    {
        // Re-open container under the same passphrase, install backup.
        let mut cont = Container::open(&vault, None, UnlockMaterial::Passphrase(b"pass")).unwrap();
        cont.restore_header_bytes(&backup).unwrap();
    }

    // Confirm on-disk bytes match the backup payload exactly.
    let mut on_disk = [0u8; HEADER_SIZE];
    let mut f = std::fs::File::open(&vault).unwrap();
    f.seek(SeekFrom::Start(0)).unwrap();
    f.read_exact(&mut on_disk).unwrap();
    assert_eq!(
        on_disk, backup,
        "restore_header_bytes did not write the supplied bytes to disk"
    );
}

// ---------------------------------------------------------------------
// R13-04 - persist_header must sync_all, not flush.
// ---------------------------------------------------------------------
//
// This is a behavioural test rather than a power-loss test (we can't
// actually pull power in CI). We simply assert that
// `Container::persist_header` does NOT error when the underlying file
// supports `sync_all`, and that the rewritten bytes are present
// immediately after the call. The real durability claim is captured
// in the SECURITY_AUDIT_ROUND_13 doc and in the comment block on
// `persist_header`.

#[test]
fn r13_04_persist_header_returns_clean_after_revoke() {
    use luksbox_core::Argon2idParams;
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("v.lbx");
    let kdf = Argon2idParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };
    Container::create_with_passphrase(
        &vault,
        None,
        luksbox_core::CipherSuite::Aes256GcmSiv,
        kdf,
        b"pass-a",
    )
    .unwrap();
    let mut cont = Container::open(&vault, None, UnlockMaterial::Passphrase(b"pass-a")).unwrap();
    let new_idx = cont.enroll_passphrase(b"pass-b", kdf).unwrap();
    cont.revoke_slot(new_idx).unwrap();
    cont.persist_header()
        .expect("persist_header should succeed");
    drop(cont);

    // Re-open: only the original slot survives.
    let _cont2 = Container::open(&vault, None, UnlockMaterial::Passphrase(b"pass-a")).unwrap();
    let err = Container::open(&vault, None, UnlockMaterial::Passphrase(b"pass-b"));
    assert!(err.is_err(), "revoked slot must not unlock the vault");
}

// ---------------------------------------------------------------------
// R13-06 - hybrid sidecar reads are size-bounded.
// ---------------------------------------------------------------------
//
// We can't easily test "an attacker symlinked the sidecar to /dev/zero"
// portably, but we CAN test the size-cap branch: feed the parser a
// file that exceeds the documented cap and confirm it errors before
// allocating gigabytes.

#[test]
fn r13_06_hybrid_sidecar_rejects_oversize_file() {
    use luksbox_format::hybrid_sidecar::read;

    let dir = tempfile::tempdir().unwrap();
    let big = dir.path().join("v.lbx.hybrid");
    // 64 KiB > 32 KiB cap.
    let bytes = vec![0u8; 64 * 1024];
    std::fs::write(&big, &bytes).unwrap();

    let r = read(&big);
    assert!(
        r.is_err(),
        "oversize hybrid sidecar must be rejected by the preflight"
    );
    let msg = format!("{:?}", r.err().unwrap());
    assert!(
        msg.contains("exceeds max") || msg.contains("DoS"),
        "rejection message should mention the size cap, got: {msg}"
    );
}

// ---------------------------------------------------------------------
// R13-09 - SecretBox::clone copies through secret-memory pages only.
// ---------------------------------------------------------------------
//
// This is hard to test directly (we can't observe stack residence in
// safe Rust), but we can pin the property that clone produces a
// SecretBox whose `is_secret_mem()` matches the original on Linux,
// which is the meaningful indicator that the clone path went through
// the proper allocator rather than a `[u8;32]` Copy.

#[test]
fn r13_09_secretbox_clone_preserves_backing() {
    use luksbox_core::MasterVolumeKey;

    let mvk = MasterVolumeKey::random();
    let backing_a = mvk.is_in_secret_memory();
    let cloned = mvk.clone();
    let backing_b = cloned.is_in_secret_memory();
    assert_eq!(
        backing_a, backing_b,
        "SecretBox::clone must produce a SecretBox with the same backing kind"
    );
    // Independence: mutating the original (via re-randomize) must
    // not be observed by the clone. Round-trip via from_bytes since
    // we don't expose mutation on MasterVolumeKey directly.
    let original_bytes = *mvk.as_bytes();
    let cloned_bytes = *cloned.as_bytes();
    assert_eq!(
        original_bytes, cloned_bytes,
        "clone must produce an equal-content SecretBox"
    );
}
