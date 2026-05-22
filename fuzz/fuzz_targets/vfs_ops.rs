// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Fuzz the VFS mutating operations — `mkdir`, `create`, `rename`,
//! `unlink`, `lookup`, `readdir`, and `write` — with attacker-
//! controlled name strings and offsets, all on a real
//! `Container`-backed `Vfs` instance.
//!
//! Threat model: the user has unlocked the vault legitimately. The
//! attacker can only reach the VFS via path / name strings (FUSE
//! callbacks, WinFsp, CLI args). We want every name they can
//! provide — UTF-8 garbage, `..`, embedded NUL, slashes, oversized,
//! reserved windows names, control chars — to be either accepted
//! cleanly or rejected with a typed `Error`. Never panic, never
//! corrupt the in-memory tree, never leak file IDs across renames.
//!
//! Cross-directory `rename` is fuzzed by picking two independent
//! parent indices from `known_ids`. The cycle-guard path is exercised
//! whenever the fuzzer happens to pick a `new_parent` that lives
//! inside the source's subtree -- `is_descendant_of` must walk that
//! subtree without panicking even when the on-disk tree has been
//! repeatedly mutated, including replace-rename of directories onto
//! other directories.
//!
//! Pipeline per iteration:
//!   1. Split fuzzer input into a small program of operations
//!      (op-byte + variable-length name bytes).
//!   2. Apply each op to the persistent `Vfs` (reused across
//!      iterations, kept in a `OnceLock`).
//!   3. Periodically `flush()` to exercise the persist path
//!      (postcard encode + AEAD-encrypt + sidecar/anchor update).
//!
//! Container bring-up is one-time (lazy), because
//! `Container::create_with_passphrase` runs Argon2id at INTERACTIVE
//! params (~500 ms). Reusing means thousands of iterations for the
//! cost of one keyslot derivation.

use std::sync::{Mutex, OnceLock};

use libfuzzer_sys::fuzz_target;
use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::{Container, UnlockMaterial};
use luksbox_vfs::{FileId, Vfs};
use tempfile::TempDir;

/// Lazily-built singleton VFS. We hold the temp dir alongside it so
/// the on-disk vault stays valid for the lifetime of the process.
struct Harness {
    vfs: Mutex<Vfs>,
    /// Kept alive so the temp dir isn't dropped while Vfs holds the
    /// container.
    _tmp: TempDir,
}

fn harness() -> &'static Harness {
    static H: OnceLock<Harness> = OnceLock::new();
    H.get_or_init(|| {
        let tmp = TempDir::new().expect("tempdir");
        let vault = tmp.path().join("fuzz.lbx");
        // INTERACTIVE Argon2 (~500 ms). One-time cost; the harness is
        // amortized across millions of iterations.
        // Create then immediately drop so the file flock is released
        // before we re-open through the real unlock path.
        drop(
            Container::create_with_passphrase(
                &vault,
                None,
                CipherSuite::Aes256Gcm,
                Argon2idParams::INTERACTIVE,
                b"fuzz-vault-passphrase",
            )
            .expect("create vault"),
        );
        // Reopen via the unlock path so we go through the real
        // production code path, not the create-time shortcut.
        let container = Container::open(
            &vault,
            None,
            UnlockMaterial::Passphrase(b"fuzz-vault-passphrase"),
        )
        .expect("reopen vault");
        let vfs = Vfs::open(container).expect("vfs open on fresh vault");
        Harness {
            vfs: Mutex::new(vfs),
            _tmp: tmp,
        }
    })
}

/// Pop the next `len`-byte slice from `cursor`, returning empty if
/// the cursor is exhausted.
fn take<'a>(cursor: &mut &'a [u8], len: usize) -> &'a [u8] {
    let n = len.min(cursor.len());
    let (head, tail) = cursor.split_at(n);
    *cursor = tail;
    head
}

/// Drive a fuzzer-derived stream of opcodes against the VFS. Each op
/// is one byte + variable payload.
fn run_program(vfs: &mut Vfs, mut cursor: &[u8]) {
    let root = vfs.root_id();
    let mut known_ids: Vec<FileId> = vec![root];
    let mut ops_applied = 0u32;

    while let Some(&op) = cursor.first() {
        cursor = &cursor[1..];
        if ops_applied > 64 {
            // Bound work per iteration so libfuzzer's throughput
            // stays high. 64 ops is enough to hit transitions between
            // mkdir/rename/unlink that surface ordering bugs.
            break;
        }
        ops_applied += 1;

        // Pick a parent FileId from `known_ids` indexed by the next
        // byte. If empty, fall back to root.
        let parent_idx = take(&mut cursor, 1).first().copied().unwrap_or(0);
        let parent = *known_ids
            .get((parent_idx as usize) % known_ids.len())
            .unwrap_or(&root);

        // Read a name length byte (clamped 0..=64) and grab that many
        // bytes; lossy-decode to a UTF-8 string. The lossy step
        // doesn't sanitize control chars, NULs, slashes, ... — those
        // hit `validate_name` in production. That's the point.
        let name_len = take(&mut cursor, 1).first().copied().unwrap_or(0) as usize;
        let name_bytes = take(&mut cursor, name_len.min(64));
        let name = String::from_utf8_lossy(name_bytes).into_owned();

        match op % 10 {
            0 => {
                // mkdir
                if let Ok(id) = vfs.mkdir(parent, &name) {
                    if known_ids.len() < 64 {
                        known_ids.push(id);
                    }
                }
            }
            1 => {
                // create
                if let Ok(id) = vfs.create(parent, &name) {
                    if known_ids.len() < 64 {
                        known_ids.push(id);
                    }
                }
            }
            2 => {
                // lookup (read-only; must never mutate or panic)
                let _ = vfs.lookup(parent, &name);
            }
            3 => {
                // readdir (read-only)
                let _ = vfs.readdir(parent);
            }
            4 => {
                // rename: pick a DIFFERENT parent for the destination
                // so cross-dir + cycle-guard paths get exercised. The
                // second index byte picks new_parent from `known_ids`.
                // The fuzzer hits the cycle guard most often when
                // new_parent happens to live under `name`'s subtree --
                // is_descendant_of must reject those without panic.
                let new_parent_idx = take(&mut cursor, 1).first().copied().unwrap_or(0);
                let new_parent = *known_ids
                    .get((new_parent_idx as usize) % known_ids.len())
                    .unwrap_or(&root);
                let new_len = take(&mut cursor, 1).first().copied().unwrap_or(0) as usize;
                let new_bytes = take(&mut cursor, new_len.min(64));
                let new_name = String::from_utf8_lossy(new_bytes).into_owned();
                let _ = vfs.rename(parent, &name, new_parent, &new_name);
            }
            5 => {
                // unlink
                let _ = vfs.unlink(parent, &name);
            }
            6 => {
                // write to one of our known FileIds at a fuzzer-derived
                // offset and short payload. Writes only succeed on
                // file inodes; mkdir-created dirs return Err which is
                // fine — we just don't want a panic.
                let off_bytes = take(&mut cursor, 4);
                let mut off = 0u32;
                for (i, b) in off_bytes.iter().enumerate() {
                    off |= (*b as u32) << (8 * i);
                }
                let payload_len = take(&mut cursor, 1).first().copied().unwrap_or(0) as usize;
                let payload = take(&mut cursor, payload_len.min(32));
                let _ = vfs.write(parent, (off & 0xFFFF) as u64, payload);
            }
            7 => {
                // flush — exercises the postcard-encode + AEAD-encrypt
                // + anchor write path with the current tree state.
                let _ = vfs.flush();
            }
            8 => {
                // symlink: pick a fuzzer-derived target string with
                // a fresh length byte so we exercise the
                // is_safe_symlink_target validator against a wide
                // range of attacker-controlled inputs (absolute
                // paths, `..` chains, NULs, oversize, etc.). The
                // VFS must never panic regardless of what the fuzzer
                // crafts here.
                let target_len = take(&mut cursor, 1).first().copied().unwrap_or(0) as usize;
                let target_bytes = take(&mut cursor, target_len.min(96));
                let target = String::from_utf8_lossy(target_bytes).into_owned();
                if let Ok(id) = vfs.symlink(parent, &name, &target) {
                    if known_ids.len() < 64 {
                        known_ids.push(id);
                    }
                }
            }
            9 => {
                // chmod: arbitrary fuzzer-derived mode bits. The VFS
                // masks to 0o7777 internally, so any input value is
                // acceptable; the test is that it doesn't panic on
                // the masking or persistence path.
                let mode_bytes = take(&mut cursor, 4);
                let mut mode = 0u32;
                for (i, b) in mode_bytes.iter().enumerate() {
                    mode |= (*b as u32) << (8 * i);
                }
                let _ = vfs.chmod(parent, mode);
            }
            _ => unreachable!(),
        }
    }

    // Always end with one final flush so the next iteration sees a
    // persisted state, in case the fuzzer's program ended without
    // hitting opcode 7.
    let _ = vfs.flush();
}

fuzz_target!(|data: &[u8]| {
    let h = harness();
    let mut vfs = h.vfs.lock().unwrap();
    run_program(&mut vfs, data);
});
