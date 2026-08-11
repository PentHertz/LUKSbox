// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Per-operation cost of `Vfs::read` / `Vfs::write` must NOT grow with
//! the size of the file being operated on (issue #31).
//!
//! Each in-memory inode carries one 16-byte `ChunkRef` per 4 KiB of
//! file, so a multi-gigabyte file has millions of them. An earlier
//! implementation cloned that whole vector on every `read` (once) and
//! every `write` (twice), making a single I/O op cost O(file_size) and
//! sequential growth cost O(file_size^2). FUSE hides this on
//! Linux/macOS by batching I/O into large requests, but WinFsp on
//! Windows dispatches far smaller, more numerous requests, so a
//! ~30 MB/s ceiling on a 10 GB copy was reported while native NTFS did
//! ~400 MB/s.
//!
//! ## Why the clone is the bottleneck (measured, isolated)
//!
//! The raw cost of cloning the `ChunkRef` vector (16 bytes/entry) grows
//! strictly linearly with file size:
//!
//! | file size | chunks     | one clone | write paid (2x/op) |
//! |-----------|------------|-----------|--------------------|
//! | 8 MiB     |      2,000 |   0.4 us  |      0.7 us        |
//! | 240 MiB   |     60,000 |    17 us  |       35 us        |
//! | 1 GiB     |    262,144 |   584 us  |      1.2 ms        |
//! | 10 GiB    |  2,621,440 |   9.6 ms  |       19 ms        |
//! | 50 GiB    | 13,107,200 |  49.8 ms  |      100 ms        |
//!
//! At 10 GiB the pre-fix `write` spent ~19 ms per call *just cloning*;
//! with WinFsp issuing ~128 KiB-1 MiB writes that is ~7-52 MB/s, i.e.
//! the reported collapse. The fix copies only the O(request-length)
//! refs an op touches, so per-op cost is independent of file size.
//!
//! ## What these end-to-end benchmarks can and cannot show
//!
//! Below a few hundred thousand chunks the clone (see table) is smaller
//! than the run-to-run noise of the backing-file disk I/O, so an
//! end-to-end A/B at a *test-runnable* size does NOT cleanly separate
//! old from new -- the honest isolation is the clone-cost table above.
//! These benchmarks therefore PRINT the measured latencies (the real
//! signal for a human) and assert only a loose smoke bound; they are
//! not a substitute for the correctness/security coverage in
//! `rmw_chunk_binding_after_refactor.rs`.
//!
//! `#[ignore]`d because it is a wall-clock timing check (inappropriate
//! for the default CI gate). Run it explicitly:
//!
//! ```text
//! cargo test -p luksbox-vfs --test large_file_io_scaling -- --ignored --nocapture
//! ```

use std::time::Instant;

use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::Container;
use luksbox_vfs::Vfs;
use tempfile::tempdir;

const CHUNK: usize = 4096;

fn cheap_params() -> Argon2idParams {
    Argon2idParams {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    }
}

/// Build a fresh vault holding one `chunks`-chunk file and return the
/// open `Vfs` plus the file id. Each vault is independent so the file's
/// total size is the only variable between measurements.
fn vault_with_file(dir: &std::path::Path, tag: &str, chunks: usize) -> (Vfs, u64) {
    let path = dir.join(format!("iso_{tag}.lbx"));
    let c = Container::create_with_passphrase(
        &path,
        None,
        CipherSuite::Aes256GcmSiv,
        cheap_params(),
        b"scaling-test",
    )
    .unwrap();
    let mut vfs = Vfs::open(c).unwrap();
    let root = vfs.root_id();
    let file = vfs.create(root, "big.bin").unwrap();
    let payload = vec![0xA5u8; CHUNK];
    for i in 0..chunks {
        vfs.write(file, (i * CHUNK) as u64, &payload).unwrap();
    }
    (vfs, file)
}

/// Average ns for `samples` scattered single-chunk *in-place*
/// overwrites (no growth). This isolates the per-op chunk-ref handling:
/// disk I/O is a constant 1 read + 1 write per op regardless of file
/// size, and no chunk is appended, so any dependence on `size` is the
/// chunk-vec clone the old code did (O(size)) versus the fix (O(1)).
fn avg_overwrite_ns(vfs: &mut Vfs, file: u64, size: usize, samples: usize) -> f64 {
    let repl = vec![0x5Au8; CHUNK];
    let start = Instant::now();
    for i in 0..samples {
        let idx = (i * 7919) % size; // scatter across the whole file
        vfs.write(file, (idx * CHUNK) as u64, &repl).unwrap();
    }
    start.elapsed().as_nanos() as f64 / samples as f64
}

#[test]
#[ignore = "wall-clock perf check; run with --ignored --nocapture"]
fn overwrite_latency_is_independent_of_file_size() {
    // In-place overwrite cost must not depend on the file's total size.
    // Compare a small file against one 30x larger. With the old
    // O(size) per-write clone the large file's overwrites are many
    // times slower; the fix keeps them within a small constant factor
    // (any residual growth is page-cache locality on the bigger backing
    // file, not the chunk-ref handling).
    const SMALL: usize = 2_000;
    const LARGE: usize = 60_000;
    const SAMPLES: usize = 4_000;

    let dir = tempdir().unwrap();
    let (mut small_vfs, small_file) = vault_with_file(dir.path(), "small", SMALL);
    let (mut large_vfs, large_file) = vault_with_file(dir.path(), "large", LARGE);

    // Warm up, then measure.
    avg_overwrite_ns(&mut small_vfs, small_file, SMALL, 500);
    avg_overwrite_ns(&mut large_vfs, large_file, LARGE, 500);
    let small_ns = avg_overwrite_ns(&mut small_vfs, small_file, SMALL, SAMPLES);
    let large_ns = avg_overwrite_ns(&mut large_vfs, large_file, LARGE, SAMPLES);
    let ratio = large_ns / small_ns;
    eprintln!(
        "[scaling] overwrite small-file({SMALL})≈{:.1}µs  large-file({LARGE})≈{:.1}µs  ratio={:.2}x",
        small_ns / 1000.0,
        large_ns / 1000.0,
        ratio
    );

    // Loose smoke bound only (see the module doc: at this test size the
    // clone is below the disk-I/O noise floor, so this does not isolate
    // the fix -- it just catches catastrophic breakage). The printed
    // latencies above are the signal.
    assert!(
        ratio < 6.0,
        "in-place overwrite cost grew sharply with total file size (small {:.1}µs vs large {:.1}µs, {:.2}x): \
         Vfs::write may be cloning the whole chunk-ref vec again (issue #31)",
        small_ns / 1000.0,
        large_ns / 1000.0,
        ratio
    );
}

/// Fill a fresh vault with a `chunks`-chunk file, then time `SAMPLES`
/// single-chunk reads scattered across the file. Returns average ns per
/// read. Each vault is independent so file size is the only variable.
fn avg_read_ns(dir: &std::path::Path, tag: &str, chunks: usize, samples: usize) -> f64 {
    let path = dir.join(format!("read_{tag}.lbx"));
    let c = Container::create_with_passphrase(
        &path,
        None,
        CipherSuite::Aes256GcmSiv,
        cheap_params(),
        b"randread-test",
    )
    .unwrap();
    let mut vfs = Vfs::open(c).unwrap();
    let root = vfs.root_id();
    let file = vfs.create(root, "big.bin").unwrap();

    let payload = vec![0x5Au8; CHUNK];
    for i in 0..chunks {
        vfs.write(file, (i * CHUNK) as u64, &payload).unwrap();
    }

    let mut buf = vec![0u8; CHUNK];
    let start = Instant::now();
    for i in 0..samples {
        let idx = (i * 7919) % chunks; // scatter across the whole file
        vfs.read(file, (idx * CHUNK) as u64, &mut buf).unwrap();
    }
    start.elapsed().as_nanos() as f64 / samples as f64
}

#[test]
#[ignore = "wall-clock perf check; run with --ignored --nocapture"]
fn read_latency_is_independent_of_file_size() {
    // Read cost must not depend on the file's total size. Compare a
    // small file against one 15x larger. With the O(file_size) clone the
    // large file's reads are many times slower; the fix keeps them flat.
    const SMALL: usize = 2_000;
    const LARGE: usize = 30_000;
    const SAMPLES: usize = 4_000;

    let dir = tempdir().unwrap();
    let small_ns = avg_read_ns(dir.path(), "small", SMALL, SAMPLES);
    let large_ns = avg_read_ns(dir.path(), "large", LARGE, SAMPLES);
    let ratio = large_ns / small_ns;
    eprintln!(
        "[scaling] read small-file({SMALL})≈{:.1}µs  large-file({LARGE})≈{:.1}µs  ratio={:.2}x",
        small_ns / 1000.0,
        large_ns / 1000.0,
        ratio
    );

    // Loose tripwire (see the note in the write benchmark). Some
    // growth is expected purely from worse page-cache locality on the
    // larger backing file, independent of the chunk-ref handling.
    assert!(
        ratio < 6.0,
        "read cost grew sharply with total file size (small {:.1}µs vs large {:.1}µs, {:.2}x): \
         Vfs::read may be cloning the whole chunk-ref vec again (issue #31)",
        small_ns / 1000.0,
        large_ns / 1000.0,
        ratio
    );
}
