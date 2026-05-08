// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! End-to-end integration tests for the WinFsp mount adapter.
//!
//! These tests verify the actual kernel-mounted volume - they create a
//! tiny luksbox vault on disk, mount it on a free drive letter via
//! `luksbox_mount::mount`, do work against the real Win32 path, then
//! tear it down via `luksbox_mount::unmount` and assert the drive is
//! gone.
//!
//! ### What these tests catch
//!
//! The bug that motivated writing them: `FileSystem::start` returned
//! `Ok` and `fsptool lsvol` showed the volume, but Win32 reported the
//! drive as "no recognized file system" because we'd left
//! `OVERWRITE_DEFINED=false`. WinFsp's `FspFileSystemOpCreate` does an
//! up-front null-check that rejects every IRP_MJ_CREATE - including
//! the volume probe - unless ALL of `(Create | CreateEx)`, `Open`,
//! and `(Overwrite | OverwriteEx)` are populated. A unit test on the
//! Rust side wouldn't catch this; only an actual mount + Win32 query
//! does.
//!
//! ### Why these tests are gated
//!
//! - `cfg(target_os = "windows")` - only meaningful on Windows.
//! - `cfg(feature = "winfsp")` - requires the WinFsp Rust binding.
//! - Runtime check for the WinFsp kernel driver - without it,
//!   `winfsp_wrs::init()` fails. We `eprintln!` and `return` (rather
//!   than fail) so dev machines without WinFsp installed don't see
//!   spurious red. CI runners that need to actually run the test must
//!   install WinFsp 2.x first (the dev-pack also installs the driver).
//!
//! ### Why these tests don't run in `cargo test --workspace`
//!
//! They take about 5 seconds each (kernel mount + drive-letter assignment
//! has real latency), and they need WinFsp installed. Run them
//! explicitly with `cargo test -p luksbox-mount` on a Windows host.

#![cfg(all(target_os = "windows", feature = "winfsp"))]

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use luksbox_core::{Argon2idParams, CipherSuite};
use luksbox_format::{Container, UnlockMaterial};
use luksbox_vfs::Vfs;
use tempfile::TempDir;

/// Argon2id at the lowest legal cost so test setup doesn't dominate
/// the test runtime. The mount paths are what we actually care about
/// here; the KDF/keyslot work is exhaustively covered in
/// `luksbox-core` and `luksbox-format` unit tests.
const FAST_KDF: Argon2idParams = Argon2idParams {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};
const PASS: &[u8] = b"luksbox-winfsp-integration-test";

/// Produce a drive letter that is currently free, or `None` if every
/// letter from D: to Z: is in use. We deliberately skip A: through C:
/// (floppy / boot drive territory) and Y: (frequently the WinFsp
/// "first auto" letter).
fn pick_free_drive_letter() -> Option<PathBuf> {
    let in_use: std::collections::HashSet<char> = ('A'..='Z')
        .filter(|c| Path::new(&format!("{c}:\\")).exists())
        .collect();
    // Walk from Z down - keeps low letters free for users / installers
    // and avoids clashing with whatever the developer mounted manually
    // when iterating on this test.
    for c in ('D'..='Z').rev() {
        if !in_use.contains(&c) {
            return Some(PathBuf::from(format!("{c}:")));
        }
    }
    None
}

/// Skip - not fail - if WinFsp's kernel driver isn't installed. CI
/// pipelines that intend to run these tests must install WinFsp 2.x
/// from <https://winfsp.dev/rel/> first.
fn winfsp_available() -> bool {
    // The WinFsp service registers itself under HKLM\SYSTEM\..\Services
    // but in modern (2.x) installs the user-mode launcher dispatches
    // the driver on demand and the service may not be present at rest.
    // The reliable signal is the install-dir registry key + the .sys
    // file shipped alongside winfsp-x64.dll.
    let install_dir = winreg_install_dir();
    if let Some(d) = &install_dir
        && Path::new(d).join("bin").join("winfsp-x64.sys").exists()
    {
        return true;
    }
    false
}

fn winreg_install_dir() -> Option<String> {
    use std::process::Command;
    // Bypass the winreg crate dependency: a single `reg query` is
    // enough and has zero build-time cost on the test path.
    let out = Command::new("reg")
        .args([
            "query",
            r"HKLM\SOFTWARE\WOW6432Node\WinFsp",
            "/v",
            "InstallDir",
        ])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        if let Some(rest) = line.trim().strip_prefix("InstallDir") {
            // line format: `InstallDir    REG_SZ    C:\Program Files (x86)\WinFsp\`
            if let Some(idx) = rest.find("REG_SZ") {
                let path = rest[idx + "REG_SZ".len()..].trim();
                if !path.is_empty() {
                    return Some(path.to_string());
                }
            }
        }
    }
    None
}

/// Helper, create a brand-new vault at `<dir>/<name>.lbx` and return
/// an open `Vfs` plus the on-disk path. Tests that need to mount the
/// SAME vault multiple times should call `reopen_vfs` for the second+
/// iterations to avoid `AlreadyExists` from `create_with_passphrase_flags`.
fn fresh_vfs(dir: &Path, name: &str) -> (Vfs, PathBuf) {
    let vault = dir.join(format!("{name}.lbx"));
    let cont = Container::create_with_passphrase_flags(
        &vault,
        None,
        CipherSuite::Aes256Gcm,
        FAST_KDF,
        0,
        PASS,
    )
    .expect("create vault");
    drop(cont);
    (reopen_vfs(&vault), vault)
}

fn reopen_vfs(vault: &Path) -> Vfs {
    let cont = Container::open(vault, None, UnlockMaterial::Passphrase(PASS)).expect("open vault");
    Vfs::open(cont).expect("open vfs")
}

/// Macro that skips the test (eprintln + early return) when WinFsp
/// isn't installed, instead of failing - keeps `cargo test` green on
/// developer machines without a WinFsp install.
macro_rules! require_winfsp {
    () => {
        if !winfsp_available() {
            eprintln!(
                "[skip] WinFsp 2.x kernel driver not detected. \
                 Install from https://winfsp.dev/rel/ to run this test."
            );
            return;
        }
    };
}

/// The volume becomes visible to Win32 with a real FileSystem name
/// and a non-zero size as soon as `mount()` returns. Validates the
/// `OVERWRITE_DEFINED` fix at the level Windows' user-mode actually
/// cares about.
#[test]
fn mount_makes_drive_visible_to_win32() {
    require_winfsp!();
    let Some(mp) = pick_free_drive_letter() else {
        eprintln!("[skip] no free drive letter D:-Z:");
        return;
    };
    let dir = TempDir::new().unwrap();
    let (vfs, _vault) = fresh_vfs(dir.path(), "visible");

    let mp_thr = mp.clone();
    let mount_join = thread::spawn(move || luksbox_mount::mount(vfs, &mp_thr, false));

    // Give the kernel mount + drive-letter registration time to land.
    // 3 seconds is well over what we observe in practice (sub-second)
    // but tolerant of slow CI runners.
    thread::sleep(Duration::from_secs(3));

    let mp_str = mp.to_str().unwrap();
    // `wmic.exe` was removed from windows-latest images (deprecated by
    // Microsoft, no longer present on Win11 / Server 2022). Replace
    // with PowerShell + `Get-CimInstance Win32_LogicalDisk` and emit
    // the same `FileSystem=...\r\nSize=...\r\n` format wmic used to
    // produce, so the assertions below work unchanged.
    //
    // Implementation note: each PowerShell pipeline statement emits a
    // line, so `"FileSystem=" + $d.FileSystem; "Size=" + $d.Size`
    // produces two CRLF-terminated lines. Plain concatenation avoids
    // the double-quoted-with-subexpression form (`"$($d.X)`r`n..."`)
    // which is fragile through Rust's CreateProcess argument escaping.
    // Empty `$d` (no matching DeviceID) emits nothing, which still
    // trips both asserts the same way wmic's empty output did.
    let ps_script = format!(
        "$d = Get-CimInstance -ClassName Win32_LogicalDisk \
            -Filter \"DeviceID='{mp_str}'\"; \
         if ($d) {{ 'FileSystem=' + $d.FileSystem; 'Size=' + $d.Size }}"
    );
    let logical = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
        .output()
        .expect("powershell");
    let stdout = String::from_utf8_lossy(&logical.stdout);

    luksbox_mount::unmount(&mp).expect("unmount");
    let _ = mount_join.join().expect("mount thread");

    // PS emits `FileSystem=luksbox\r\nSize=1099511627776\r\n` on
    // success and an empty stdout on a ghost mount.
    assert!(
        stdout.contains("FileSystem=luksbox"),
        "drive {mp_str} did not advertise FileSystem=luksbox; powershell said:\n{stdout}\n\
         This is the OVERWRITE_DEFINED bug (or a regression of it)."
    );
    assert!(
        stdout.contains("Size=") && !stdout.contains("Size=\r"),
        "drive {mp_str} did not advertise a non-empty Size; powershell said:\n{stdout}"
    );
}

/// Programmatic unmount from another thread (the GUI flow) wakes the
/// blocked mount thread within a generous timeout. Catches the case
/// where the registry-keyed sender isn't found (path-normalization
/// drift between mount and unmount) or where the mount thread is
/// blocked on something other than the registry channel.
#[test]
fn unmount_from_other_thread_wakes_mount_thread() {
    require_winfsp!();
    let Some(mp) = pick_free_drive_letter() else {
        eprintln!("[skip] no free drive letter D:-Z:");
        return;
    };
    let dir = TempDir::new().unwrap();
    let (vfs, _vault) = fresh_vfs(dir.path(), "wakeup");

    let mp_thr = mp.clone();
    let (done_tx, done_rx) = mpsc::channel::<Result<(), String>>();
    thread::spawn(move || {
        let r = luksbox_mount::mount(vfs, &mp_thr, false).map_err(|e| e.to_string());
        let _ = done_tx.send(r);
    });

    thread::sleep(Duration::from_secs(2));
    luksbox_mount::unmount(&mp).expect("unmount");

    // 10 s is plenty: in practice the mount thread wakes within tens
    // of ms of `unmount()` returning. Margin is for the
    // FileSystem::stop() drain.
    let res = done_rx.recv_timeout(Duration::from_secs(10)).expect(
        "mount thread did not exit within 10s of unmount() - registry / channel path is broken",
    );
    res.expect("mount() returned an error after a clean unmount");
}

/// Mount/unmount three times in the same process. Exercises the
/// `OnceLock`-guarded ctrlc handler (must not double-install) and
/// the mount-registry re-entry path (must not leak the previous
/// sender). A regression here would manifest as a hang on the second
/// or third unmount.
#[test]
fn three_mount_unmount_cycles_in_one_process() {
    require_winfsp!();
    let Some(mp) = pick_free_drive_letter() else {
        eprintln!("[skip] no free drive letter D:-Z:");
        return;
    };
    let dir = TempDir::new().unwrap();
    let (_vfs, vault) = fresh_vfs(dir.path(), "cycles");
    drop(_vfs); // create-only; reopen below for each round

    for round in 1..=3 {
        let vfs = reopen_vfs(&vault);
        let mp_thr = mp.clone();
        let join = thread::spawn(move || luksbox_mount::mount(vfs, &mp_thr, false));
        thread::sleep(Duration::from_secs(2));

        luksbox_mount::unmount(&mp).unwrap_or_else(|e| panic!("round {round}: unmount: {e}"));

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if join.is_finished() {
                join.join()
                    .unwrap()
                    .unwrap_or_else(|e| panic!("round {round}: mount() returned err: {e}"));
                break;
            }
            if Instant::now() > deadline {
                panic!("round {round}: mount thread did not exit within 10s");
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
}

/// Files copied into the mounted volume must survive unmount and be
/// visible on the next open. This is the regression test for the
/// "write a file in Explorer, unmount, remount, file is gone" bug:
/// the WinFsp `cleanup` callback only flushed the VFS on the DELETE
/// path, so normal write+close handles never persisted the metadata
/// blob (chunk index + directory tree). Chunks landed on disk but no
/// inode pointed at them, and they got reaped on next open.
///
/// Verification path is "open the .lbx directly via Vfs::open after
/// unmount" rather than a second kernel remount, because:
///   * Vfs::open reads exactly the bits that were on disk at unmount;
///     if the cleanup-flush is missing, the directory tree reverts to
///     "empty root" and `lookup_path("/persist.txt")` returns
///     `NotFound`. That's the exact failure mode of the bug.
///   * It avoids a second 2-3s kernel mount dance, keeping the test
///     under 5 seconds total.
///
/// A regression of either the cleanup-flush OR the Drop-flush would
/// trip this test.
#[test]
fn file_written_via_win32_survives_unmount() {
    require_winfsp!();
    let Some(mp) = pick_free_drive_letter() else {
        eprintln!("[skip] no free drive letter D:-Z:");
        return;
    };
    let dir = TempDir::new().unwrap();
    let (vfs, vault) = fresh_vfs(dir.path(), "persist");

    let mp_thr = mp.clone();
    let mount_join = thread::spawn(move || luksbox_mount::mount(vfs, &mp_thr, false));

    // Wait for the kernel mount to be visible to Win32.
    thread::sleep(Duration::from_secs(3));

    // Write a file to the root of the mounted volume. Going through
    // `std::fs` exercises the same NT IRP path Explorer uses (CreateFile
    // -> WriteFile -> CloseHandle), which is what triggers Cleanup
    // dispatch on handle close.
    let mp_str = mp.to_str().unwrap();
    let on_volume = PathBuf::from(format!("{mp_str}\\persist.txt"));
    let payload: &[u8] = b"survive-unmount-please";
    let write_result = std::fs::write(&on_volume, payload);

    // Also create a subdirectory + nested file: directory metadata
    // lives in the same tree blob, so a regression that drops file
    // chunks but keeps directory entries (or vice versa) is caught.
    let nested_dir = PathBuf::from(format!("{mp_str}\\sub"));
    let mkdir_result = std::fs::create_dir(&nested_dir);
    let nested_file = PathBuf::from(format!("{mp_str}\\sub\\nested.bin"));
    let nested_payload: Vec<u8> = (0u8..200).cycle().take(8192).collect();
    let nested_write_result = std::fs::write(&nested_file, &nested_payload);

    // Tear down. After this returns, the kernel mount is gone and the
    // .lbx is closed; whatever's on disk is what we'll see on reopen.
    luksbox_mount::unmount(&mp).expect("unmount");
    let _ = mount_join.join().expect("mount thread");

    // Surface the Win32 errors AFTER unmount so the test's main fault
    // line ("did the data persist?") prints whatever the kernel-side
    // copy reported as a hint.
    write_result.expect("write to mounted volume");
    mkdir_result.expect("mkdir on mounted volume");
    nested_write_result.expect("write nested file on mounted volume");

    // Reopen the underlying vault and verify the data is actually
    // persisted. If the cleanup-flush is missing, lookup_path here
    // returns NotFound (no inode), even though the encrypted chunks
    // are physically present on disk - the metadata blob never got
    // updated to reference them.
    let mut vfs = reopen_vfs(&vault);

    let id = vfs
        .lookup_path("/persist.txt")
        .expect("persist.txt should exist after unmount + reopen");
    let stat = vfs.stat(id).expect("stat persist.txt");
    assert_eq!(
        stat.size,
        payload.len() as u64,
        "persist.txt size mismatch after reopen"
    );
    let mut readback = vec![0u8; payload.len()];
    let n = vfs.read(id, 0, &mut readback).expect("read persist.txt");
    assert_eq!(n, payload.len());
    assert_eq!(
        readback, payload,
        "persist.txt content mismatch after reopen"
    );

    let nested_id = vfs
        .lookup_path("/sub/nested.bin")
        .expect("nested file should exist after unmount + reopen");
    let nested_stat = vfs.stat(nested_id).expect("stat nested file");
    assert_eq!(nested_stat.size, nested_payload.len() as u64);
    let mut nested_readback = vec![0u8; nested_payload.len()];
    let mut got = 0usize;
    while got < nested_readback.len() {
        let n = vfs
            .read(nested_id, got as u64, &mut nested_readback[got..])
            .expect("read nested file");
        if n == 0 {
            break;
        }
        got += n;
    }
    assert_eq!(got, nested_payload.len());
    assert_eq!(
        nested_readback, nested_payload,
        "nested file content mismatch after reopen"
    );
}

/// Cross-process unmount (the user opening a second terminal and
/// running `luksbox umount Y:`) must NOT silently succeed - WinFsp
/// has no out-of-band unmount IPC and pretending we honored the
/// request would leave the user thinking the drive is gone when it
/// isn't. This test verifies the error path returns a `MountError`
/// with a clear message, not `Ok(())`.
///
/// Implemented as a unit test (no actual mount) since the registry
/// is per-process: looking up a key that was never inserted
/// reliably exercises the not-in-this-process branch without
/// needing a second process.
#[test]
fn unmount_of_unknown_mountpoint_errors_clearly() {
    let result = luksbox_mount::unmount(Path::new("Q:"));
    let err = result.expect_err("unmount of unknown mountpoint must return Err");
    let msg = format!("{err}");
    assert!(
        msg.contains("Q:"),
        "error message must name the mountpoint, got: {msg}"
    );
    assert!(
        msg.to_lowercase().contains("process"),
        "error message must explain cross-process limitation, got: {msg}"
    );
}
