// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz>

//! Integration tests against a real (emulated) TPM 2.0 via `swtpm`.
//!
//! These tests are gated on:
//! 1. The `hardware` feature being enabled (otherwise `Tpm2Sealer` is
//!    a stub that returns `NotCompiledIn`).
//! 2. The `swtpm` + `swtpm_setup` binaries being on `$PATH`. If not,
//!    every test logs a skip notice and exits `Ok(())` so default
//!    `cargo test` works for contributors who don't have the
//!    emulator installed.
//!
//! CI installs `swtpm` via apt (Ubuntu) so the `tpm-hardware` matrix
//! entry runs these tests for real on every push.
//!
//! ## Why swtpm and not a real TPM?
//!
//! Real TPM 2.0 chips on CI runners would be slow, contended, and
//! impossible to reset between tests (TPM dictionary-attack lockout
//! is sticky across test runs). `swtpm` is a software emulator with
//! the same TCG-compliant command surface; it lives entirely in
//! userspace, can be spawned per-test with a fresh state dir, and
//! tears down cleanly when the parent process exits.
//!
//! ## TCTI choice
//!
//! We use the `swtpm:path=<unix-socket>` TCTI (provided by
//! `libtss2-tcti-swtpm0`, runtime dep of `libtss2-esys-3` so already
//! installed wherever the hardware build runs). Unix sockets avoid
//! port-collision flakiness compared to TCP `mssim:host=,port=`.

#![cfg(all(feature = "hardware", target_os = "linux"))]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use luksbox_tpm::{SealedBlob, Tpm2Sealer};

/// Owned handle to a running `swtpm` subprocess + its state dir.
/// Drop kills the child and the tempdir cleans up the state files.
struct SwtpmHandle {
    child: Child,
    _state_dir: tempfile::TempDir,
    tcti: String,
}

impl Drop for SwtpmHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn `swtpm` with a fresh per-test state dir. Returns `None` if
/// the binary isn't on `$PATH` (so the test logs a skip notice and
/// passes rather than failing).
fn maybe_spawn_swtpm() -> Option<SwtpmHandle> {
    if Command::new("swtpm")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()
        .map(|s| !s.success())
        .unwrap_or(true)
    {
        eprintln!(
            "[skip] swtpm not on PATH; install with `apt install swtpm` (Debian/Ubuntu) or \
             `dnf install swtpm` (Fedora) to enable this integration test."
        );
        return None;
    }
    if Command::new("swtpm_setup")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()
        .map(|s| !s.success())
        .unwrap_or(true)
    {
        eprintln!(
            "[skip] swtpm_setup not on PATH (usually shipped alongside swtpm in the same package)."
        );
        return None;
    }

    let state_dir = tempfile::tempdir().expect("tempdir for swtpm state");
    let state_path: PathBuf = state_dir.path().to_path_buf();
    let sock_server = state_path.join("sock-server");
    let sock_ctrl = state_path.join("sock-ctrl");

    // Initialise NVRAM + EK certificate. Without this the first
    // command we send returns TPM_RC_INITIALIZE.
    let setup = Command::new("swtpm_setup")
        .args([
            "--tpmstate",
            state_path.to_str().unwrap(),
            "--createek",
            "--decryption",
            "--create-ek-cert",
            "--create-platform-cert",
            "--lock-nvram",
            "--tpm2",
        ])
        .output()
        .expect("run swtpm_setup");
    if !setup.status.success() {
        eprintln!(
            "[skip] swtpm_setup failed: {}",
            String::from_utf8_lossy(&setup.stderr)
        );
        return None;
    }

    // Spawn swtpm in the foreground (no --daemon) so we own the Pid
    // and can kill it on Drop.
    let child = Command::new("swtpm")
        .args([
            "socket",
            "--tpmstate",
            &format!("dir={}", state_path.display()),
            "--ctrl",
            &format!("type=unixio,path={}", sock_ctrl.display()),
            "--server",
            &format!("type=unixio,path={}", sock_server.display()),
            "--tpm2",
            "--flags",
            "startup-clear",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn swtpm");

    // Wait for the server socket to appear (swtpm takes about 50-200 ms
    // to bind it). Bounded poll so a broken swtpm doesn't hang the
    // test forever.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !sock_server.exists() {
        if Instant::now() > deadline {
            eprintln!("[skip] swtpm did not create server socket within 5s");
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let tcti = format!("swtpm:path={}", sock_server.display());
    Some(SwtpmHandle {
        child,
        _state_dir: state_dir,
        tcti,
    })
}

/// Round-trip seal -> unseal recovers the original 32-byte secret.
#[test]
fn swtpm_seal_unseal_roundtrip() {
    let Some(swtpm) = maybe_spawn_swtpm() else {
        return;
    };
    let mut sealer =
        Tpm2Sealer::from_tcti_str(&swtpm.tcti).expect("Tpm2Sealer::from_tcti_str against swtpm");

    let secret = [0xA5u8; 32];
    let blob = sealer.seal(&secret).expect("TPM seal");
    let unsealed = sealer.unseal(&blob).expect("TPM unseal");
    assert_eq!(unsealed.as_slice(), &secret);
}

/// Sealing the same plaintext twice produces DIFFERENT blobs (the
/// TPM picks fresh randomness for the symmetric wrap each time);
/// both still unseal to the same plaintext.
#[test]
fn swtpm_seal_is_nondeterministic_but_unseals_consistently() {
    let Some(swtpm) = maybe_spawn_swtpm() else {
        return;
    };
    let mut sealer =
        Tpm2Sealer::from_tcti_str(&swtpm.tcti).expect("Tpm2Sealer::from_tcti_str against swtpm");

    let secret = [0x42u8; 32];
    let blob1 = sealer.seal(&secret).expect("seal #1");
    let blob2 = sealer.seal(&secret).expect("seal #2");
    assert_ne!(
        blob1.private, blob2.private,
        "two seal() calls of the same plaintext must produce different ciphertexts"
    );
    let u1 = sealer.unseal(&blob1).expect("unseal #1");
    let u2 = sealer.unseal(&blob2).expect("unseal #2");
    assert_eq!(u1.as_slice(), &secret);
    assert_eq!(u2.as_slice(), &secret);
}

/// Round-trip through the on-disk SealedBlob serialization (the
/// length-prefixed format that gets stored in keyslots) preserves
/// the unseal result.
#[test]
fn swtpm_blob_survives_to_bytes_from_bytes() {
    let Some(swtpm) = maybe_spawn_swtpm() else {
        return;
    };
    let mut sealer =
        Tpm2Sealer::from_tcti_str(&swtpm.tcti).expect("Tpm2Sealer::from_tcti_str against swtpm");

    let secret = [0xCDu8; 32];
    let blob = sealer.seal(&secret).expect("seal");
    let bytes = blob.to_bytes();
    let reparsed = SealedBlob::from_bytes(&bytes).expect("blob round-trip");
    assert_eq!(reparsed, blob);
    let unsealed = sealer.unseal(&reparsed).expect("unseal reparsed");
    assert_eq!(unsealed.as_slice(), &secret);
}

/// Tampering with the private blob (e.g. flip a byte) makes unseal
/// fail. Crucially: the TPM rejects with an authenticator-failure
/// style error rather than returning garbage.
#[test]
fn swtpm_tampered_blob_unseal_fails() {
    let Some(swtpm) = maybe_spawn_swtpm() else {
        return;
    };
    let mut sealer =
        Tpm2Sealer::from_tcti_str(&swtpm.tcti).expect("Tpm2Sealer::from_tcti_str against swtpm");

    let secret = [0xEFu8; 32];
    let mut blob = sealer.seal(&secret).expect("seal");
    // Flip the last byte of the private (encrypted-sensitive) blob.
    // This corrupts the integrity HMAC the TPM applies to the
    // sensitive area, so unseal MUST fail.
    let last = blob.private.len() - 1;
    blob.private[last] ^= 0xFF;
    let res = sealer.unseal(&blob);
    assert!(
        res.is_err(),
        "unseal of a tampered blob must fail; got Ok({:?})",
        res.ok().map(|s| s.as_slice().to_vec())
    );
}

/// PIN-protected seal/unseal: the same PIN succeeds, a wrong PIN
/// fails, and unseal without a PIN fails. Exercises the userAuth
/// path on the sealed object.
#[test]
fn swtpm_pin_seal_correct_pin_succeeds() {
    let Some(swtpm) = maybe_spawn_swtpm() else {
        return;
    };
    let mut sealer = Tpm2Sealer::from_tcti_str(&swtpm.tcti).expect("sealer");
    let secret = [0x77u8; 32];
    let pin = b"correct-pin-1234";
    let blob = sealer
        .seal_with_pin(&secret, Some(pin))
        .expect("seal_with_pin");
    let unsealed = sealer
        .unseal_with_pin(&blob, Some(pin))
        .expect("unseal_with_pin (correct)");
    assert_eq!(unsealed.as_slice(), &secret);
}

#[test]
fn swtpm_pin_seal_wrong_pin_fails() {
    let Some(swtpm) = maybe_spawn_swtpm() else {
        return;
    };
    let mut sealer = Tpm2Sealer::from_tcti_str(&swtpm.tcti).expect("sealer");
    let secret = [0x88u8; 32];
    let pin = b"correct-pin";
    let blob = sealer
        .seal_with_pin(&secret, Some(pin))
        .expect("seal_with_pin");
    let res = sealer.unseal_with_pin(&blob, Some(b"wrong-pin"));
    assert!(
        res.is_err(),
        "unseal with wrong PIN must fail; got Ok({:?})",
        res.ok().map(|s| s.as_slice().to_vec())
    );
}

#[test]
fn swtpm_pin_seal_omitting_pin_fails() {
    let Some(swtpm) = maybe_spawn_swtpm() else {
        return;
    };
    let mut sealer = Tpm2Sealer::from_tcti_str(&swtpm.tcti).expect("sealer");
    let secret = [0x99u8; 32];
    let pin = b"some-pin";
    let blob = sealer
        .seal_with_pin(&secret, Some(pin))
        .expect("seal_with_pin");
    // Omit the PIN entirely - TPM should reject because the sealed
    // object's userAuth is non-empty.
    let res = sealer.unseal_with_pin(&blob, None);
    assert!(
        res.is_err(),
        "unseal without PIN on a PIN-bound blob must fail"
    );
}

/// A FRESH `Tpm2Sealer` instance (re-deriving the SRK from the TPM's
/// persistent endorsement seed) can unseal a blob created by a
/// previous instance. This is the property that makes our
/// transient-SRK design work: subsequent boots / process restarts
/// get the same SRK, and old slots remain readable.
#[test]
fn swtpm_fresh_sealer_can_unseal_old_blob() {
    let Some(swtpm) = maybe_spawn_swtpm() else {
        return;
    };

    let secret = [0x11u8; 32];
    let blob = {
        let mut sealer1 = Tpm2Sealer::from_tcti_str(&swtpm.tcti).expect("Tpm2Sealer #1");
        sealer1.seal(&secret).expect("seal in sealer1")
        // sealer1 drops here; its session/handle table inside libtss
        // is released. The TPM-side SRK derivation is deterministic
        // from the persistent seed, so a fresh sealer reproduces it.
    };

    let mut sealer2 = Tpm2Sealer::from_tcti_str(&swtpm.tcti).expect("Tpm2Sealer #2");
    let unsealed = sealer2
        .unseal(&blob)
        .expect("unseal in fresh sealer instance");
    assert_eq!(unsealed.as_slice(), &secret);
}
