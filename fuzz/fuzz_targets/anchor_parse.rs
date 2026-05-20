// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

#![no_main]

//! Fuzz both anchor readers: the standard (48 B, HMAC-keyed) format
//! and the deniable (256 B, AEAD-keyed) format. Same input drives
//! both calls, so a single fuzz run exercises every variant.
//!
//! Why fuzz an anchor reader specifically? Both have file-IO +
//! parsing + crypto-verify layers. The recent `O_NOFOLLOW` change
//! and the GUI-side preflight that rejects symlinks / wrong-size
//! files mean the format reader sees a wider variety of "passed
//! preflight but still hostile" inputs than before. Specifically
//! interesting: truncated reads (file shorter than expected), magic
//! match + everything-else-garbage, AEAD nonce-replay across an
//! intra-vault rotation, length-field arithmetic in the deniable
//! path's `try_into()` calls.
//!
//! Threat model: attacker with write access to the anchor sidecar
//! file (e.g. cloud-sync collision, shared filesystem, malicious
//! backup restore). They cannot forge the MAC/AEAD under the user's
//! MVK, but they can write any byte pattern and trigger the
//! reader. Goal: every byte pattern produces either a clean Err or
//! a structurally valid `AnchorContents` whose generation is then
//! checked by `anchor::compare`; never a panic, never an OOB,
//! never an infinite loop.
//!
//! Deniability bonus: the deniable reader collapses every failure
//! to `Error::OpaqueUnlockFailed`. We don't try to detect leaks
//! through error variants here (would need timing instrumentation),
//! but a panic would be a serious tell to a remote attacker.
//!
//! Fuzz input is the raw file bytes; written to a tempfile and
//! handed to both `read_and_verify` and `deniable_read_and_verify`.
//! Cap at 4096 bytes (libFuzzer default) which is far larger than
//! either ANCHOR_SIZE; testing oversize inputs covers the
//! `read_exact` short-read paths.

use std::io::Write;

use libfuzzer_sys::fuzz_target;
use luksbox_core::{CipherSuite, MasterVolumeKey};
use luksbox_format::anchor;

const MVK_BYTES: [u8; 32] = [0xC3; 32];
const HEADER_SALT: [u8; 32] = [0x3C; 32];
const PER_VAULT_SALT: [u8; 32] = [0xA7; 32];

const SUITES: [CipherSuite; 3] = [
    CipherSuite::Aes256GcmSiv,
    CipherSuite::Aes256Gcm,
    CipherSuite::ChaCha20Poly1305,
];

fuzz_target!(|data: &[u8]| {
    // Skip the very short and very long edges - they don't add
    // coverage and the disk-IO cost dominates iteration time.
    if data.len() > 8192 {
        return;
    }

    // Write the bytes to a unique tempfile; both readers take &Path.
    let tmp = match tempfile::NamedTempFile::new() {
        Ok(t) => t,
        Err(_) => return,
    };
    let path = tmp.path().to_path_buf();
    if std::fs::File::create(&path)
        .and_then(|mut f| f.write_all(data))
        .is_err()
    {
        return;
    }

    let mvk = MasterVolumeKey::from_bytes(MVK_BYTES);

    // Standard reader: 48 B, HMAC-keyed. Will reject most inputs at
    // the magic check or the MAC compare. Either is fine; panic is
    // a bug.
    let _ = anchor::read_and_verify(&path, &mvk, &HEADER_SALT);

    // Deniable reader: 256 B, AEAD-keyed. Cycle through all three
    // cipher suites so the per-suite open paths get exercised. The
    // deniable reader has no magic byte; everything is AEAD. The
    // first byte (if any) picks the suite to avoid wasting two
    // iterations on the same call.
    let suite = if data.is_empty() {
        SUITES[0]
    } else {
        SUITES[(data[0] as usize) % SUITES.len()]
    };
    let _ = anchor::deniable_read_and_verify(&path, &mvk, &PER_VAULT_SALT, suite);
});
