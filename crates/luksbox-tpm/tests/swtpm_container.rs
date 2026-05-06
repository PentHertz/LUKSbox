// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz>

//! End-to-end Container-level integration tests against the swtpm
//! emulator. These complement the lower-level `swtpm_integration.rs`
//! file by driving the FULL enroll_tpm2 -> persist -> drop -> reopen
//! flow exactly as the CLI / GUI does it.
//!
//! Same skip-if-no-swtpm pattern as `swtpm_integration.rs`: tests log
//! a notice and pass when the emulator binary isn't on PATH.

#![cfg(all(feature = "hardware", target_os = "linux"))]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::{Container, UnlockMaterial};
use luksbox_tpm::{SealedBlob, Tpm2Sealer};

/// Local copy of the swtpm spawn harness (kept private to each test
/// file; cargo doesn't surface a cross-test-binary library easily).
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
        eprintln!("[skip] swtpm not on PATH");
        return None;
    }
    let state_dir = tempfile::tempdir().expect("tempdir");
    let state_path: PathBuf = state_dir.path().to_path_buf();
    let sock_server = state_path.join("sock-server");
    let sock_ctrl = state_path.join("sock-ctrl");
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
        .expect("swtpm_setup");
    if !setup.status.success() {
        eprintln!(
            "[skip] swtpm_setup failed: {}",
            String::from_utf8_lossy(&setup.stderr)
        );
        return None;
    }
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
    let deadline = Instant::now() + Duration::from_secs(5);
    while !sock_server.exists() {
        if Instant::now() > deadline {
            eprintln!("[skip] swtpm did not bind socket within 5s");
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Some(SwtpmHandle {
        child,
        _state_dir: state_dir,
        tcti: format!("swtpm:path={}", sock_server.display()),
    })
}

fn fast_kdf() -> Argon2idParams {
    // Tiny params for tests; never use in real containers.
    Argon2idParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    }
}

/// Full create -> enroll_tpm2 -> persist -> drop -> reopen flow.
/// This is what the CLI / GUI do end-to-end; the test verifies the
/// closure-based UnlockMaterial::Tpm2 path actually unlocks against
/// a real TPM-sealed blob.
#[test]
fn end_to_end_enroll_and_reopen_via_tpm2() {
    let Some(swtpm) = maybe_spawn_swtpm() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.lbx");

    // Create with passphrase as bootstrap (TPM can't be the first slot).
    let mut cont = Container::create_with_passphrase(
        &path,
        None,
        CipherSuite::Aes256GcmSiv,
        fast_kdf(),
        b"bootstrap",
    )
    .unwrap();

    // Enroll a TPM keyslot exactly the way cmd_enroll_tpm2 does.
    let mut sealer = Tpm2Sealer::from_tcti_str(&swtpm.tcti).expect("sealer");
    let kek = [0x37u8; 32];
    let blob = sealer.seal(&kek).expect("TPM seal");
    let blob_bytes = blob.to_bytes();
    let slot_idx = cont.enroll_tpm2(&kek, &blob_bytes).expect("enroll_tpm2");
    cont.persist_header().expect("persist");
    drop(cont);

    // Reopen via UnlockMaterial::Tpm2 with the closure exactly as
    // luksbox-cli's open_container_tpm2 does it: open a fresh
    // Tpm2Sealer and have it unseal each slot's blob.
    let mut reopen_sealer = Tpm2Sealer::from_tcti_str(&swtpm.tcti).expect("reopen sealer");
    let mut unseal = |blob: &[u8]| -> Result<[u8; 32], String> {
        let parsed = SealedBlob::from_bytes(blob).map_err(|e| format!("blob parse: {e}"))?;
        let kek = reopen_sealer
            .unseal(&parsed)
            .map_err(|e| format!("TPM unseal: {e}"))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(kek.as_slice());
        Ok(out)
    };
    let cont = Container::open(
        &path,
        None,
        UnlockMaterial::Tpm2 {
            unseal: &mut unseal,
        },
    )
    .expect("open via Tpm2");
    assert_eq!(
        cont.header.keyslots[slot_idx].kind,
        luksbox_core::SlotKind::Tpm2Sealed
    );
}

/// Full enroll_tpm2_fido2 round-trip is not done here because the
/// FIDO2 half requires a connected authenticator (mocked Fido2 isn't
/// available outside the luksbox-fido2 crate's own tests). The
/// luksbox-format mocked-TPM tests already cover the fused unlock
/// logic; what's swtpm-specific is the seal/unseal half, which the
/// `swtpm_integration.rs` tests cover directly.
#[test]
fn placeholder_for_future_fido2_integrated_test() {
    // No-op intentionally; documents that swtpm + libfido2 hardware
    // integration is a future addition. The current matrix is:
    //   - swtpm seal/unseal: covered (swtpm_integration.rs)
    //   - Container::Tpm2 round-trip via swtpm: covered (above)
    //   - Container::Tpm2Fido2 with mocked TPM + mocked FIDO2:
    //     covered (luksbox-format/src/container.rs tests)
    //   - Container::Tpm2Fido2 with real (emulated) TPM + real
    //     FIDO2: needs a software FIDO2 emulator (e.g.
    //     virtual_fido) that isn't currently a workspace dep.
}
