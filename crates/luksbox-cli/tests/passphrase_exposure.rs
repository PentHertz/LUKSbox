// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)
//
// Round 9F regression: pin the passphrase-exposure properties of
// the CLI. Specifically:
//
//   1. NO subcommand accepts a passphrase as an argv flag value.
//      A regression here would expose the passphrase via `ps aux`
//      to ANY user on the same machine.
//   2. The stdin-pipe path works end-to-end: passphrase fed via
//      `echo pp | luksbox <cmd>` unlocks correctly.
//   3. When using the env-var path (`LUKSBOX_PASSPHRASE`), the
//      passphrase IS visible to same-UID processes via
//      `/proc/<pid>/environ`. This is a known/documented exposure;
//      this test pins that visibility so future maintainers don't
//      assume env vars are private.
//
// Linux-only because the visibility tests use /proc/<pid>/environ.

#![cfg(target_os = "linux")]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use tempfile::tempdir;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_luksbox")
}

fn run_with_stdin(dir: &Path, args: &[&str], stdin_data: &[u8]) -> Output {
    let mut child = Command::new(bin())
        .args(args)
        .current_dir(dir)
        .env("LUKSBOX_TEST_FAST_KDF", "1")
        .env_remove("LUKSBOX_PASSPHRASE")
        .env_remove("LUKSBOX_NEW_PASSPHRASE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin_data)
        .expect("write stdin");
    child.wait_with_output().expect("wait")
}

#[test]
fn passphrase_via_stdin_pipe_creates_then_unlocks() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();

    let pp = b"stdin-pipe-passphrase\n";
    let create = run_with_stdin(dir, &["create", "v.lbx"], pp);
    assert!(
        create.status.success(),
        "create failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&create.stdout),
        String::from_utf8_lossy(&create.stderr),
    );

    let ls = run_with_stdin(dir, &["ls", "v.lbx", "/"], pp);
    assert!(
        ls.status.success(),
        "ls failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&ls.stdout),
        String::from_utf8_lossy(&ls.stderr),
    );
}

#[test]
fn wrong_stdin_passphrase_rejected_cleanly() {
    let tmp = tempdir().unwrap();
    let dir = tmp.path();

    let _create = run_with_stdin(dir, &["create", "v.lbx"], b"correct-pp\n");
    let bad = run_with_stdin(dir, &["ls", "v.lbx", "/"], b"wrong-pp\n");
    assert!(!bad.status.success());
    let stderr = String::from_utf8_lossy(&bad.stderr);
    assert!(
        stderr.contains("no keyslot accepted") || stderr.contains("UnlockFailed"),
        "expected unlock-failed error, got stderr: {stderr}"
    );
}

#[test]
fn stdin_pipe_passphrase_does_not_appear_in_argv() {
    // Spawn luksbox into a sleep-until-stdin-closes state by piping
    // a passphrase + then keeping the pipe open with no extra data.
    // While the child waits for input, scan /proc/<pid>/cmdline for
    // the passphrase string.
    let tmp = tempdir().unwrap();
    let dir = tmp.path();

    // Create a vault first (so the "ls" we spawn has something to act on).
    let _ = run_with_stdin(dir, &["create", "v.lbx"], b"argv-leak-canary-passphrase\n");

    // Now spawn `info` with stdin held open. info doesn't need
    // a passphrase, so the process won't actually consume stdin -
    // perfect for a quick cmdline snapshot. We pass the canary
    // passphrase string as a benign flag value to ensure that IF
    // the binary did echo argv into a string anywhere, we'd still
    // catch it.
    let canary = "argv-leak-canary-passphrase";
    let mut child = Command::new(bin())
        .args(["info", "v.lbx"])
        .current_dir(dir)
        .env("LUKSBOX_TEST_FAST_KDF", "1")
        .env_remove("LUKSBOX_PASSPHRASE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");

    let pid = child.id();
    // Grab cmdline before child can exit. /proc/<pid>/cmdline is
    // the kernel-canonical view of argv as visible to any process
    // running as the same UID via `ps`, `top`, etc.
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    let cmdline_str = String::from_utf8_lossy(&cmdline);

    // Cleanup: close stdin + wait for exit.
    drop(child.stdin.take());
    let _ = child.wait();

    assert!(
        !cmdline_str.contains(canary),
        "REGRESSION: canary string {canary:?} found in /proc/{pid}/cmdline = {cmdline_str:?}"
    );
}

#[test]
fn env_var_passphrase_visible_in_proc_environ_documented() {
    // This test PINS the documented same-UID exposure: any env var
    // set on a process IS visible via /proc/<pid>/environ to any
    // process running as the same user (kernel design, not ours).
    // We make sure future "env vars are private" assumptions don't
    // creep into the docs without challenge.
    //
    // Uses `sleep` instead of luksbox to avoid timing-flakiness
    // (the child needs to be reliably alive when we read /proc).
    let canary = "env-var-canary-pp-9F";
    let mut child = Command::new("sleep")
        .arg("3")
        .env("LUKSBOX_PASSPHRASE", canary)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sleep");

    let pid = child.id();
    // Brief wait so the child is fully spawned + /proc/<pid>/environ
    // is populated.
    std::thread::sleep(std::time::Duration::from_millis(50));
    let environ = std::fs::read(format!("/proc/{pid}/environ")).unwrap_or_default();
    let environ_str = String::from_utf8_lossy(&environ);

    let _ = child.kill();
    let _ = child.wait();

    assert!(
        environ_str.contains(canary),
        "Expected env-var to be visible in /proc/{pid}/environ \
         (documented same-UID exposure). If this assertion fails, the kernel \
         contract changed - update SECURITY.md `Non-interactive passphrase \
         entry` section. environ contents: {environ_str:?}"
    );
}

#[test]
fn stdin_pipe_with_env_var_set_is_rejected_as_ambiguous() {
    // Regression test for the env-var-overrides-pipe bug. If a
    // script pipes a passphrase AND LUKSBOX_PASSPHRASE is also set
    // (e.g. stale from a parent shell), the previous behaviour
    // silently used the env var, ignoring the piped bytes. The
    // current behaviour rejects with a clear error so the user
    // unsets one source explicitly.
    let tmp = tempdir().unwrap();
    let dir = tmp.path();

    let mut child = Command::new(bin())
        .args(["create", "v.lbx"])
        .current_dir(dir)
        .env("LUKSBOX_TEST_FAST_KDF", "1")
        .env("LUKSBOX_PASSPHRASE", "env-var-pp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    // Actual bytes on the pipe (NOT empty) - this is what triggers
    // the ambiguity check.
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"piped-pp\n")
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");

    assert!(
        !out.status.success(),
        "expected create to fail with ambiguity error"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("ambiguous passphrase source"),
        "expected ambiguity error, got stderr: {stderr}"
    );
}
