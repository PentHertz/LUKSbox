// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Regression test: a tampered .kyber seed file with a hostile
//! Argon2id m_cost_kib must be rejected at parse time, BEFORE the
//! argon2 crate is asked to allocate about 4 TiB of RAM.
//!
//! Vector: an attacker who can write to the .kyber file (USB stick
//! swap, malicious backup, shared-storage tampering) but does NOT
//! know the passphrase can otherwise lock the user out of their
//! own vault by causing OOM on every unlock attempt.

use std::fs;
use tempfile::TempDir;

use luksbox_pq::seed_file::{self, KdfParams};

const SEED_BYTES: [u8; 64] = [0xAB; 64];
const PASS: &[u8] = b"correct horse battery staple";

fn write_safe_seed(dir: &TempDir) -> std::path::PathBuf {
    let path = dir.path().join("vault.kyber");
    seed_file::write(
        &path,
        &SEED_BYTES,
        PASS,
        // Tiny test params (8 KiB / 1 / 1), fast write/read.
        KdfParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        },
    )
    .expect("write safe seed");
    path
}

#[test]
fn round_trip_safe_params_works() {
    // Sanity: the test fixture itself round-trips when params are sane.
    let dir = TempDir::new().unwrap();
    let path = write_safe_seed(&dir);
    let seed = seed_file::read(&path, PASS).expect("safe round-trip");
    assert_eq!(*seed, SEED_BYTES);
}

#[test]
fn rejects_hostile_m_cost_kib() {
    let dir = TempDir::new().unwrap();
    let path = write_safe_seed(&dir);
    let mut bytes = fs::read(&path).unwrap();
    // Layout: [0..8 magic][8 version][9..13 m_cost_kib LE u32][13 t_cost][14 p_cost][15.. salt+nonce+ct]
    bytes[9..13].copy_from_slice(&u32::MAX.to_le_bytes());
    fs::write(&path, &bytes).unwrap();

    let err = seed_file::read(&path, PASS)
        .expect_err("hostile m_cost_kib must be rejected before argon2 runs");
    let msg = err.to_string();
    assert!(
        msg.contains("hostile") || msg.contains("safe bounds") || msg.contains("Argon2id"),
        "expected DoS-guard message, got: {msg}"
    );
}

#[test]
fn rejects_hostile_t_cost() {
    let dir = TempDir::new().unwrap();
    let path = write_safe_seed(&dir);
    let mut bytes = fs::read(&path).unwrap();
    bytes[13] = u8::MAX;
    fs::write(&path, &bytes).unwrap();
    assert!(seed_file::read(&path, PASS).is_err());
}

#[test]
fn rejects_hostile_p_cost() {
    let dir = TempDir::new().unwrap();
    let path = write_safe_seed(&dir);
    let mut bytes = fs::read(&path).unwrap();
    bytes[14] = u8::MAX;
    fs::write(&path, &bytes).unwrap();
    assert!(seed_file::read(&path, PASS).is_err());
}

#[test]
fn rejects_zero_m_cost() {
    let dir = TempDir::new().unwrap();
    let path = write_safe_seed(&dir);
    let mut bytes = fs::read(&path).unwrap();
    bytes[9..13].copy_from_slice(&0u32.to_le_bytes());
    fs::write(&path, &bytes).unwrap();
    assert!(seed_file::read(&path, PASS).is_err());
}
