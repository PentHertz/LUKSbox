// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Regression tests pinning the Round 16 security audit findings at the
//! format layer. See `docs/SECURITY_AUDIT_ROUND_16.md`. R16-01 (header
//! recovered from the mirror re-persisted as a new generation) needs a
//! header-v3 vault, which `luksbox-vfs` upgrades to; its test lives in
//! `crates/luksbox-vfs/tests/round16_findings.rs`.
//!
//! ```bash
//! cargo test --test round16_findings -p luksbox-format
//! ```

use std::path::{Path, PathBuf};

use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::{Container, Error, UnlockMaterial};

const KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};
const PASS: &[u8] = b"first passphrase";

fn create(dir: &Path) -> PathBuf {
    let vault = dir.join("v.lbx");
    let _g = luksbox_format::metadata::set_create_metadata_region_size_override(Some(64 * 1024));
    drop(
        Container::create_with_passphrase(&vault, None, CipherSuite::Aes256GcmSiv, KDF, PASS)
            .unwrap(),
    );
    vault
}

// ---------------------------------------------------------------------
// R16-14: opening a FIFO planted at a sidecar / anchor path with a plain
// `open(2)` blocks until a writer appears, before the regular-file check
// can refuse it. The opens now carry `O_NONBLOCK`.
// ---------------------------------------------------------------------

#[cfg(unix)]
fn mkfifo(p: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
    // SAFETY: valid C string.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
}

#[cfg(unix)]
fn finishes_quickly<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(std::time::Duration::from_secs(10))
        .expect("the open must not block on a FIFO")
}

#[cfg(unix)]
#[test]
fn r16_14_a_fifo_at_the_sidecar_or_anchor_path_is_refused_without_blocking() {
    let dir = tempfile::tempdir().unwrap();
    let sidecar = dir.path().join("v.lbx.hybrid");
    mkfifo(&sidecar);
    let r = finishes_quickly(move || luksbox_format::hybrid_sidecar::read_sidecar_bytes(&sidecar));
    assert!(r.is_err(), "a FIFO is not a sidecar");

    let anchor = dir.path().join("v.anchor");
    mkfifo(&anchor);
    let mvk = luksbox_core::MasterVolumeKey::from_bytes([7u8; 32]);
    let r = finishes_quickly(move || {
        luksbox_format::anchor::read_and_verify(&anchor, &mvk, &[9u8; 32])
    });
    assert!(r.is_err(), "a FIFO is not an anchor");
}

// ---------------------------------------------------------------------
// R16-15: `export_external_header` assumed the data area follows the
// metadata region; a header with a gap converted into a bundle whose
// every chunk slot was mis-addressed.
// ---------------------------------------------------------------------

#[test]
fn r16_15_export_external_header_refuses_a_layout_gap() {
    let dir = tempfile::tempdir().unwrap();
    let vault = create(dir.path());
    let mut c = Container::open(&vault, None, UnlockMaterial::Passphrase(PASS)).unwrap();
    c.set_read_only();
    assert!(c.export_external_header().is_ok());
    c.header.data_offset += 4096;
    assert!(
        matches!(
            c.export_external_header(),
            Err(Error::UnsupportedForExternalStorage(_))
        ),
        "a gap between the metadata region and the data must be refused"
    );
}
