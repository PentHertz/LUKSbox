// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! The file-dialog helper process (`luksbox-gui --file-dialog-helper`,
//! Linux), run without a desktop: no session bus, so the portal request
//! fails and rfd falls back to `zenity`, here a script.

#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

/// Run the helper for `op`, with `zenity` on `PATH` running `script`
/// (no `zenity` at all when `None`: `PATH` is then an empty folder).
fn helper(dir: &Path, op: &str, script: Option<&str>) -> Output {
    let bin = dir.join(format!("bin-{op}-{}", script.is_some()));
    std::fs::create_dir_all(&bin).unwrap();
    let mut path = bin.display().to_string();
    if let Some(script) = script {
        let z = bin.join("zenity");
        std::fs::write(&z, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&z, std::fs::Permissions::from_mode(0o755)).unwrap();
        // For the tools the script runs.
        path.push_str(":/usr/bin:/bin");
    }
    Command::new(env!("CARGO_BIN_EXE_luksbox-gui"))
        .args(["--file-dialog-helper", op, "A title", ""])
        .env_clear()
        .env("PATH", path)
        .env("HOME", dir)
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/bus")
        .output()
        .unwrap()
}

/// One test, so no other test's spawn holds a script open for writing
/// while it runs (ETXTBSY).
#[test]
fn the_helper_runs_unhardened_and_reports_every_outcome() {
    let dir = tempfile::tempdir().unwrap();

    // The portal identifies its caller through /proc/<pid>/root, which
    // other processes can read only if the caller is dumpable: the very
    // check the GUI process fails. The script makes it on the helper (its
    // parent) and "picks" what it read.
    let out = helper(dir.path(), "pick-file", Some("readlink /proc/$PPID/root"));
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(out.stdout, b"/", "{out:?}");

    // The chosen path comes back byte for byte.
    let out = helper(
        dir.path(),
        "save-file",
        Some("printf '/tmp/a b/r\\303\\251sum\\303\\251.lbx\\n'"),
    );
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(out.stdout, "/tmp/a b/résumé.lbx".as_bytes());

    // Dismissed.
    let out = helper(dir.path(), "pick-folder", Some("exit 1"));
    assert_eq!(out.status.code(), Some(10), "{out:?}");
    assert!(out.stdout.is_empty());

    // Neither the portal nor zenity: no dialog at all, and why.
    let out = helper(dir.path(), "pick-file", None);
    assert_eq!(out.status.code(), Some(11), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("zenity"),
        "{out:?}"
    );

    // A malformed request.
    let out = Command::new(env!("CARGO_BIN_EXE_luksbox-gui"))
        .args(["--file-dialog-helper", "pick-file"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64), "{out:?}");
}
