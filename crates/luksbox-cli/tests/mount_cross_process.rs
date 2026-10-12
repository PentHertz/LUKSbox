// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! `luksbox mount` in one process, `luksbox umount <mountpoint>` from
//! another (GitHub #37). The library-level mount tests
//! (luksbox-mount/tests/{fuse,winfsp}_mount.rs) unmount from the
//! process that mounted; this drives the real binary the way a user
//! does with two terminals:
//!
//!   1. `luksbox mount -f vault.lbx <mountpoint>` as a child process,
//!   2. read a file through the mount and write a new one,
//!   3. `luksbox umount <mountpoint>` as a second process,
//!   4. the mount process exits cleanly, and the file written through
//!      the mount is in the vault (`luksbox get`).
//!
//! Linux unmounts with `fusermount3 -u`, macOS with `umount`, Windows
//! by signalling the named event the mount process waits on (WinFsp
//! has no cross-process unmount of its own).
//!
//! Skipped (not failed) when the host can't mount: no usable
//! /dev/fuse or fusermount3 (Linux), no macFUSE / FUSE-T (macOS), no
//! WinFsp (Windows). CI lanes that install a mount backend set
//! `LUKSBOX_REQUIRE_MOUNT_TESTS=1`, which turns the skip into a
//! failure so a broken runner setup can't pass silently.

#![cfg(any(
    all(any(target_os = "linux", target_os = "macos"), feature = "fuse"),
    all(target_os = "macos", feature = "fuse-t"),
    all(target_os = "windows", feature = "winfsp"),
))]

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::tempdir;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_luksbox")
}

/// One mount test at a time: they take the same free drive letter
/// (Windows) and share the host's mount table.
static MOUNT_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn one_mount_test_at_a_time() -> std::sync::MutexGuard<'static, ()> {
    MOUNT_TESTS.lock().unwrap_or_else(|e| e.into_inner())
}

const ENV: [(&str, &str); 3] = [
    ("LUKSBOX_TEST_FAST_KDF", "1"),
    ("LUKSBOX_PASSPHRASE", "pw"),
    ("LUKSBOX_NEW_PASSPHRASE", "pw"),
];

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .current_dir(dir)
        .envs(ENV)
        .output()
        .expect("spawn binary")
}

fn assert_ok(out: &Output, ctx: &str) {
    assert!(
        out.status.success(),
        "{ctx} failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Whether this host can mount with the backend the binary was built
/// for. Same probes as luksbox-mount's own mount tests.
fn mount_backend_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        let dev_fuse = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/fuse")
            .is_ok();
        // The paths luksbox-mount accepts for fusermount3 (it never
        // searches $PATH).
        let fusermount3 = [
            "/usr/bin/fusermount3",
            "/bin/fusermount3",
            "/usr/local/bin/fusermount3",
        ]
        .iter()
        .any(|p| Path::new(p).is_file());
        dev_fuse && fusermount3
    }
    #[cfg(all(target_os = "macos", feature = "fuse-t"))]
    {
        [
            "/usr/local/lib/libfuse-t.dylib",
            "/opt/homebrew/lib/libfuse-t.dylib",
        ]
        .iter()
        .any(|p| Path::new(p).is_file())
    }
    #[cfg(all(target_os = "macos", not(feature = "fuse-t")))]
    {
        Path::new("/dev/macfuse0").exists() || Path::new("/dev/osxfuse0").exists()
    }
    #[cfg(target_os = "windows")]
    {
        // The binary imports winfsp-x64.dll at load time, so it only
        // starts when WinFsp is installed and its bin dir is on PATH.
        Command::new(bin())
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    }
}

/// False (skip) when the host can't mount; panics instead when
/// `LUKSBOX_REQUIRE_MOUNT_TESTS` is set.
fn mount_backend_or_skip() -> bool {
    if mount_backend_available() {
        return true;
    }
    assert!(
        std::env::var_os("LUKSBOX_REQUIRE_MOUNT_TESTS").is_none(),
        "LUKSBOX_REQUIRE_MOUNT_TESTS is set but this host cannot mount: \
         Linux needs a usable /dev/fuse and fusermount3 (package fuse3), \
         macOS macFUSE or FUSE-T, Windows WinFsp with its bin dir on PATH"
    );
    eprintln!("[skip] no usable mount backend on this host");
    false
}

/// An empty directory inside the test's temp dir.
#[cfg(not(target_os = "windows"))]
fn new_mountpoint(dir: &Path) -> PathBuf {
    let mp = dir.join("mnt");
    std::fs::create_dir(&mp).expect("create mountpoint dir");
    mp
}

/// A free drive letter, from Z: down (same choice as winfsp_mount.rs).
#[cfg(target_os = "windows")]
fn new_mountpoint(_dir: &Path) -> PathBuf {
    ('D'..='Z')
        .rev()
        .map(|c| format!("{c}:"))
        .find(|letter| !Path::new(&format!("{letter}\\")).exists())
        .map(PathBuf::from)
        .expect("no free drive letter D:-Z:")
}

/// `name` at the root of the mounted volume. On Windows `Z:` joined
/// with a name would be relative to the current directory on Z:.
fn in_mount(mountpoint: &Path, name: &str) -> PathBuf {
    if cfg!(target_os = "windows") {
        PathBuf::from(format!("{}\\{name}", mountpoint.display()))
    } else {
        mountpoint.join(name)
    }
}

/// The `luksbox mount` child process. Dropping it while it still runs
/// (the test failed half-way) unmounts it, then kills it, so a failed
/// run leaves no stale mount behind.
struct MountProcess {
    child: Child,
    mountpoint: PathBuf,
    log: PathBuf,
}

impl MountProcess {
    fn spawn(dir: &Path, vault: &str, mountpoint: &Path) -> Self {
        let log = dir.join("mount.log");
        let out = File::create(&log).expect("create mount log");
        let child = Command::new(bin())
            .arg("mount")
            .arg("-f")
            .arg(vault)
            .arg(mountpoint)
            .current_dir(dir)
            .envs(ENV)
            .stdin(Stdio::null())
            .stdout(out.try_clone().expect("clone log handle"))
            .stderr(out)
            .spawn()
            .expect("spawn luksbox mount");
        Self {
            child,
            mountpoint: mountpoint.to_path_buf(),
            log,
        }
    }

    /// Everything the mount process printed so far.
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// The exit status, or `None` if it still runs after `timeout`.
    fn wait_exit(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for MountProcess {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(None)) {
            return;
        }
        let mountpoint = self.mountpoint.clone();
        let umount = move || {
            let _ = Command::new(bin()).arg("umount").arg(&mountpoint).output();
        };
        umount();
        if self.wait_exit(Duration::from_secs(10)).is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
            // A killed FUSE daemon leaves a dead mount ("Transport
            // endpoint is not connected") until it is unmounted.
            umount();
        }
    }
}

#[test]
fn umount_from_another_process_releases_the_mount() {
    if !mount_backend_or_skip() {
        return;
    }
    let _serial = one_mount_test_at_a_time();
    let tmp = tempdir().unwrap();
    let dir = tmp.path();

    assert_ok(&run(dir, &["create", "vault.lbx"]), "create");
    std::fs::write(dir.join("hello.txt"), b"hello from the vault").unwrap();
    assert_ok(
        &run(dir, &["put", "vault.lbx", "hello.txt", "/hello.txt"]),
        "put",
    );

    let mountpoint = new_mountpoint(dir);
    // Declared after `tmp`, so on a panic it is dropped (unmounted)
    // before the temp dir is removed.
    let mut mount = MountProcess::spawn(dir, "vault.lbx", &mountpoint);

    // Mounted once the vault's file shows up at the mountpoint.
    let hello = in_mount(&mountpoint, "hello.txt");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(data) = std::fs::read(&hello) {
            assert_eq!(data, b"hello from the vault", "read through the mount");
            break;
        }
        if let Some(status) = mount.child.try_wait().expect("try_wait") {
            panic!("luksbox mount exited early ({status}):\n{}", mount.log());
        }
        assert!(
            Instant::now() < deadline,
            "{} not readable 30 s after starting luksbox mount:\n{}",
            hello.display(),
            mount.log()
        );
        thread::sleep(Duration::from_millis(200));
    }
    std::fs::write(
        in_mount(&mountpoint, "written.txt"),
        b"written through the mount",
    )
    .expect("write through the mount");

    // The point of the test: a second process releases the mount.
    let out = Command::new(bin())
        .arg("umount")
        .arg(&mountpoint)
        .current_dir(dir)
        .output()
        .expect("spawn luksbox umount");
    assert_ok(&out, "luksbox umount from a second process");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("OK unmounted"),
        "umount stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    let status = mount.wait_exit(Duration::from_secs(30)).unwrap_or_else(|| {
        panic!(
            "luksbox mount still running 30 s after luksbox umount:\n{}",
            mount.log()
        )
    });
    assert!(
        status.success(),
        "luksbox mount exited with {status} after umount:\n{}",
        mount.log()
    );

    // The mount flushed on the way out: the file is in the vault.
    assert_ok(
        &run(dir, &["get", "vault.lbx", "/written.txt", "out.txt"]),
        "get after unmount",
    );
    assert_eq!(
        std::fs::read(dir.join("out.txt")).unwrap(),
        b"written through the mount"
    );
}

/// Unmounts a Windows mountpoint that is still mounted when dropped (the
/// test failed half-way), so a failed run leaves no background mount.
#[cfg(target_os = "windows")]
struct UnmountOnDrop(PathBuf);

#[cfg(target_os = "windows")]
impl Drop for UnmountOnDrop {
    fn drop(&mut self) {
        if Path::new(&format!("{}\\", self.0.display())).exists() {
            let _ = Command::new(bin()).arg("umount").arg(&self.0).output();
        }
    }
}

/// Windows: `luksbox mount` without `-f` runs in the background. The
/// vault is unlocked in the `mount` process, handed to a hidden `luksbox`
/// process that holds the WinFsp mount, and `mount` returns once the
/// volume is live. Its output is captured here the way a script would:
/// that only completes once every copy of the output pipes is closed, so
/// a background process that inherited one would hang it until unmount.
#[cfg(target_os = "windows")]
#[test]
fn background_mount_returns_and_umount_releases_it() {
    if !mount_backend_or_skip() {
        return;
    }
    let _serial = one_mount_test_at_a_time();
    let tmp = tempdir().unwrap();
    let dir = tmp.path();

    assert_ok(&run(dir, &["create", "vault.lbx"]), "create");
    std::fs::write(dir.join("hello.txt"), b"hello from the vault").unwrap();
    assert_ok(
        &run(dir, &["put", "vault.lbx", "hello.txt", "/hello.txt"]),
        "put",
    );

    let mountpoint = new_mountpoint(dir);
    // Declared after `tmp`, so on a panic it is dropped (unmounted)
    // before the temp dir is removed.
    let _unmount = UnmountOnDrop(mountpoint.clone());

    let child = Command::new(bin())
        .arg("mount")
        .arg("vault.lbx")
        .arg(&mountpoint)
        .current_dir(dir)
        .envs(ENV)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn luksbox mount");
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    let out = rx
        .recv_timeout(Duration::from_secs(60))
        .expect(
            "luksbox mount did not return within 60 s: its output pipes are still open \
             (inherited by the background mount process?)",
        )
        .expect("wait for luksbox mount");
    assert_ok(&out, "background luksbox mount");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("(background, pid "),
        "expected the background notice, got: {stderr}"
    );

    // Live as soon as `mount` returned.
    assert_eq!(
        std::fs::read(in_mount(&mountpoint, "hello.txt")).expect("read through the mount"),
        b"hello from the vault"
    );
    std::fs::write(
        in_mount(&mountpoint, "written.txt"),
        b"written through the background mount",
    )
    .expect("write through the mount");

    let out = Command::new(bin())
        .arg("umount")
        .arg(&mountpoint)
        .current_dir(dir)
        .output()
        .expect("spawn luksbox umount");
    assert_ok(&out, "luksbox umount of the background mount");
    // `umount` returns once the drive letter is gone.
    assert!(
        !Path::new(&format!("{}\\", mountpoint.display())).exists(),
        "{} still mounted after luksbox umount",
        mountpoint.display()
    );

    // The background mount flushed on the way out.
    assert_ok(
        &run(dir, &["get", "vault.lbx", "/written.txt", "out.txt"]),
        "get after unmount",
    );
    assert_eq!(
        std::fs::read(dir.join("out.txt")).unwrap(),
        b"written through the background mount"
    );
}
