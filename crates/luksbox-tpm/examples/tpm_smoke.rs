// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Live seal/unseal smoke test against the local TPM 2.0.
//!
//! Run with a hardware-enabled build:
//!
//! ```text
//! cargo run -p luksbox-tpm --features hardware    --example tpm_smoke   # Linux
//! cargo run -p luksbox-tpm --features bundled-tpm --example tpm_smoke   # Windows
//! ```
//!
//! Exercises exactly what vault enrollment/unlock does - open a
//! context (device TCTI on Linux, TBS on Windows), derive the
//! transient SRK, seal 32 random bytes, serialize the blob through
//! the keyslot wire format, unseal it back - and reports each step.
//! Uses only transient objects: nothing is persisted to the chip,
//! nothing counts toward the dictionary-attack lockout.
//!
//! In a stub build (no `hardware` feature, or a platform without a
//! TPM backend) this compiles and exits with the NotCompiledIn error,
//! which is itself a useful check of the fallback path.

use luksbox_tpm::{SEALED_SECRET_LEN, SealedBlob, Tpm2Sealer};
use rand_core::{OsRng, RngCore};

fn main() {
    let mut secret = zeroize::Zeroizing::new([0u8; SEALED_SECRET_LEN]);
    OsRng
        .try_fill_bytes(secret.as_mut_slice())
        .expect("OS RNG failure");

    eprintln!("[1/4] opening TPM context...");
    let mut sealer = match Tpm2Sealer::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("FAIL: {e}");
            std::process::exit(1);
        }
    };

    eprintln!("[2/4] sealing {SEALED_SECRET_LEN} random bytes under the SRK...");
    let blob = match sealer.seal(&secret) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("FAIL: {e}");
            std::process::exit(1);
        }
    };
    eprintln!(
        "      sealed: public={} B, private={} B",
        blob.public.len(),
        blob.private.len()
    );

    eprintln!("[3/4] round-tripping the blob through the keyslot wire format...");
    let wire = blob.to_bytes();
    let parsed = SealedBlob::from_bytes(&wire).expect("wire-format roundtrip failed");
    assert_eq!(parsed, blob, "wire-format roundtrip mismatch");

    eprintln!("[4/4] unsealing on the same chip...");
    match sealer.unseal(&parsed) {
        Ok(recovered) if recovered.as_slice() == secret.as_slice() => {
            eprintln!("OK: TPM 2.0 seal/unseal round-trip succeeded");
        }
        Ok(_) => {
            eprintln!("FAIL: unseal returned different bytes than were sealed");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("FAIL: {e}");
            std::process::exit(1);
        }
    }
}
