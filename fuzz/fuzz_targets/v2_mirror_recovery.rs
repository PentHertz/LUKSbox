// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Fuzz the v0.3.0 LBM5 / LUKSBOX2 mirror-recovery security boundary.
//!
//! Threat model: the user has a v2-format vault on disk with one or
//! more enrolled credentials and may have revoked some. The on-disk
//! state includes `<vault>.lbx.header-bak` (previous-good header) and
//! `<vault>.lbx.meta-bak` (previous-good encrypted metadata). An
//! attacker who can write to the vault's parent directory can:
//!   - corrupt the live header bytes (any offset, any length)
//!   - replace the mirror with arbitrary content (including oversize
//!     symlink targets pointing at /dev/zero)
//!   - present revoked passphrases against the corrupted vault
//!
//! Security boundary the fuzzer enforces: no matter what corruption
//! or mirror substitution the fuzzer crafts, presenting a credential
//! that was REVOKED in the live header must NEVER unlock the vault.
//! The mirror-recovery path is gated on Header::from_bytes parse
//! failure; if that gating regresses, this fuzzer catches it via the
//! "revoked credential unlocks" invariant.
//!
//! Pipeline per iteration:
//!   1. Build a fresh v2 vault with two passphrases A and B.
//!   2. Persist (rotates mirrors).
//!   3. Revoke A; persist (mirror now still contains A).
//!   4. Apply fuzzer-chosen corruption to live header / mirror file.
//!   5. Try to open with A (must fail) and with B (allowed to
//!      succeed or fail depending on corruption, but must never
//!      panic).
//!   6. Assert: open-with-A never returned Ok.
//!
//! The Argon2id cost of two enrollments per iteration is the
//! bottleneck. We use INTERACTIVE params with a small m_cost so the
//! loop sustains ~100 iter/s on a modern CPU. The auth-bypass found
//! by the reviewer (live unlock fails -> mirror fallback unlocks the
//! revoked slot) would be caught here in the first few iterations.

use libfuzzer_sys::fuzz_target;
use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::{Container, UnlockMaterial};
use tempfile::TempDir;

/// Tiny Argon2 params for fuzz throughput. INTERACTIVE would be
/// ~500 ms per enroll; tiny is ~5 ms.
fn tiny_params() -> Argon2idParams {
    Argon2idParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    }
}

const PW_A: &[u8] = b"pass-A-revoked-target";
const PW_B: &[u8] = b"pass-B-still-valid";

fn run_iteration(fuzz_bytes: &[u8]) {
    let tmp = match TempDir::new() {
        Ok(t) => t,
        Err(_) => return,
    };
    let path = tmp.path().join("v2.lbx");
    // Phase 1: create v2 vault with A in slot 0, B in slot 1.
    {
        let mut c = match Container::create_with_passphrase(
            &path,
            None,
            CipherSuite::Aes256Gcm,
            tiny_params(),
            PW_A,
        ) {
            Ok(c) => c,
            Err(_) => return,
        };
        c.header.version_major = luksbox_core::VERSION_MAJOR_V2;
        c.mark_header_dirty();
        if c.enroll_passphrase(PW_B, tiny_params()).is_err() {
            return;
        }
        if c.persist_header().is_err() {
            return;
        }
    }
    // Phase 2: revoke A and persist. Mirror now still has A.
    {
        let mut c = match Container::open(&path, None, UnlockMaterial::Passphrase(PW_A)) {
            Ok(c) => c,
            Err(_) => return,
        };
        if c.header.revoke_slot(0).is_err() {
            return;
        }
        c.mark_header_dirty();
        if c.persist_header().is_err() {
            return;
        }
    }
    // Phase 3: fuzzer chooses what to corrupt.
    apply_fuzzer_corruption(&path, fuzz_bytes);
    // Phase 4: open with A. Must NEVER succeed regardless of any
    // corruption pattern. The auth-bypass surfaces here.
    if let Ok(_c) =
        Container::open(&path, None, UnlockMaterial::Passphrase(PW_A))
    {
        panic!(
            "AUTH BYPASS: revoked passphrase A unlocked vault after corruption \
             pattern {:?}",
            &fuzz_bytes[..fuzz_bytes.len().min(16)]
        );
    }
    // Phase 5: open with B is allowed to succeed or fail (corruption
    // might have made it un-openable). Just verify no panic.
    let _ = Container::open(&path, None, UnlockMaterial::Passphrase(PW_B));
}

/// Apply fuzzer-derived corruption to the vault file or its mirrors.
/// The first byte selects the target; the rest is the data.
fn apply_fuzzer_corruption(vault: &std::path::Path, data: &[u8]) {
    let Some((&target, body)) = data.split_first() else {
        return;
    };
    let mirror_header = vault.with_file_name(format!(
        "{}.header-bak",
        vault.file_name().unwrap().to_string_lossy()
    ));
    let mirror_meta = vault.with_file_name(format!(
        "{}.meta-bak",
        vault.file_name().unwrap().to_string_lossy()
    ));
    use std::io::{Seek, SeekFrom, Write};
    match target % 6 {
        0 => {
            // Scribble over live header bytes at a fuzzer-chosen offset.
            if body.len() < 3 {
                return;
            }
            let off = u16::from_le_bytes([body[0], body[1]]) as u64 % 8192;
            let len = (body[2] as usize).min(body.len().saturating_sub(3)).min(8192);
            if let Ok(mut f) = std::fs::OpenOptions::new().read(true).write(true).open(vault)
            {
                if f.seek(SeekFrom::Start(off)).is_ok() {
                    let _ = f.write_all(&body[3..3 + len]);
                    let _ = f.sync_all();
                }
            }
        }
        1 => {
            // Replace mirror with arbitrary fuzzer bytes (any length).
            let _ = std::fs::write(&mirror_header, body);
        }
        2 => {
            // Truncate or extend mirror to a fuzzer-chosen length.
            if body.len() >= 2 {
                let len = u16::from_le_bytes([body[0], body[1]]) as usize;
                let payload = if len > body.len() {
                    let mut v = body.to_vec();
                    v.resize(len, 0);
                    v
                } else {
                    body[..len].to_vec()
                };
                let _ = std::fs::write(&mirror_header, payload);
            }
        }
        3 => {
            // Scribble over metadata mirror.
            if !body.is_empty() {
                let _ = std::fs::write(&mirror_meta, body);
            }
        }
        4 => {
            // Delete header mirror entirely (no recovery possible).
            let _ = std::fs::remove_file(&mirror_header);
        }
        5 => {
            // Combination: corrupt live + replace mirror.
            if body.len() < 4 {
                return;
            }
            if let Ok(mut f) = std::fs::OpenOptions::new().read(true).write(true).open(vault)
            {
                let _ = f.seek(SeekFrom::Start(body[0] as u64 * 256));
                let _ = f.write_all(&body[1..1 + body[1] as usize % body.len()]);
                let _ = f.sync_all();
            }
            let _ = std::fs::write(&mirror_header, &body[2..]);
        }
        _ => unreachable!(),
    }
}

fuzz_target!(|data: &[u8]| {
    run_iteration(data);
});
