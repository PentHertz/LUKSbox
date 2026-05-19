// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Round 13 R13-05 regressions for the `.kyber` seed-file reader.
//!
//! ```bash
//! cargo test --test round13_seed_file -p luksbox-pq
//! ```

use luksbox_pq::seed_file::{KdfParams, read, write};

fn cheap_kdf() -> KdfParams {
    KdfParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    }
}

#[cfg(unix)]
#[test]
fn r13_05_seed_file_read_refuses_symlink_swap() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real.kyber");
    let seed = [0xa5u8; luksbox_pq::SEED_LEN];
    write(&real, &seed, b"pw", cheap_kdf()).unwrap();

    // Attacker replaces the seed path with a symlink to the real file.
    let attacked = dir.path().join("victim.kyber");
    symlink(&real, &attacked).unwrap();

    // `expect_err` carries the real assertion: with `O_NOFOLLOW` set on
    // the `read()` open, the symlink target is never followed and the
    // open returns ELOOP. The specific kernel strerror text varies
    // across platforms (Linux: "Too many levels of symbolic links",
    // FreeBSD: "Too many levels of symbolic links", macOS: "Too many
    // levels of symbolic links"), so we deliberately do NOT match on
    // message contents -- the test passes iff the read fails.
    let _err = read(&attacked, b"pw").expect_err("symlinked seed path must be refused");
}

#[cfg(unix)]
#[test]
fn r13_05_seed_file_read_rejects_oversized_file() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("huge.kyber");
    // Write something larger than the fixed FILE_LEN.
    let bytes = vec![0u8; 4096];
    std::fs::write(&p, &bytes).unwrap();
    let err = read(&p, b"pw").expect_err("oversize seed file must be refused at preflight");
    let msg = format!("{err}");
    assert!(
        msg.contains("wrong file size") || msg.contains("expected"),
        "rejection message should mention size, got: {msg}"
    );
}

#[cfg(unix)]
#[test]
fn r13_05_seed_file_read_rejects_non_regular_file() {
    // FIFOs and devices are valid open() targets but should be
    // refused by the regular-file check.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("p.kyber");
    use std::ffi::CString;
    let cp = CString::new(p.to_string_lossy().as_bytes()).unwrap();
    let rc = unsafe { libc::mkfifo(cp.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo failed");
    // Open the FIFO for read-side in another thread to keep open()
    // from blocking on the test thread; alternatively use O_NONBLOCK.
    // Since seed_file::read uses O_NOFOLLOW (not O_NONBLOCK) the
    // open() may hang on a non-writer FIFO. To avoid hangs, write a
    // few bytes to the FIFO from a writer that closes immediately.
    std::thread::spawn({
        let p = p.clone();
        move || {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
            let _ = f.write_all(&[0u8; 16]);
        }
    });
    // Allow writer to attach. Best-effort; if the test environment is
    // pathological the assertion below will still surface failure.
    std::thread::sleep(std::time::Duration::from_millis(50));
    let err = read(&p, b"pw").expect_err("non-regular file must be refused");
    let msg = format!("{err}");
    assert!(
        msg.contains("not a regular file") || msg.contains("wrong file size"),
        "rejection should mention regular-file or size, got: {msg}"
    );
}
