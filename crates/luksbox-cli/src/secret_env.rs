// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Unlock secrets given through the environment (`LUKSBOX_PASSPHRASE`
//! and the rest of [`NAMES`]).
//!
//! [`take_all`] moves them out of the process environment at start-up,
//! while the process is still single-threaded, and keeps them here, so
//! nothing this process starts inherits them: a background `luksbox
//! mount` stays alive for as long as the vault is mounted, and FUSE-T
//! (`mount_nfs`, its NFS server), `fusermount` or any helper it starts
//! would otherwise get the passphrase in its environment. The command
//! itself reads them from here as often as it needs to (several unlocks
//! in one `merge`, the wizard, a new passphrase and its confirmation).
//!
//! Removing a variable only takes it out of the environment array; the
//! string itself stays in the block the kernel set up at exec, which is
//! what Linux shows in `/proc/<pid>/environ` (to every process of the
//! same user) and macOS in `KERN_PROCARGS2`. On Unix the value's bytes
//! are therefore overwritten in place before the variable is removed, so
//! that block keeps only the variable's name.

use std::sync::OnceLock;

use zeroize::Zeroizing;

/// Every environment variable that carries a secret.
pub(crate) const NAMES: [&str; 6] = [
    "LUKSBOX_PASSPHRASE",
    "LUKSBOX_NEW_PASSPHRASE",
    "LUKSBOX_SEED_PASSPHRASE",
    "LUKSBOX_SLOT_PASSPHRASE",
    "LUKSBOX_TPM_PIN",
    "LUKSBOX_FIDO2_PIN",
];

/// Per name in [`NAMES`]: `None` when it was not set, `Some(None)` when
/// it was set to something that is not UTF-8 (unusable, as with
/// `std::env::var`), `Some(Some(value))` otherwise.
type Taken = Vec<(&'static str, Option<Option<Zeroizing<String>>>)>;

static TAKEN: OnceLock<Taken> = OnceLock::new();

/// Move the secrets out of the process environment.
///
/// # Safety
///
/// Must be called while no other thread exists (the first thing in
/// `main`): it modifies the process environment.
pub(crate) unsafe fn take_all() {
    let taken: Taken = NAMES
        .iter()
        .map(|&name| {
            let v = std::env::var_os(name).map(|os| os.into_string().ok().map(Zeroizing::new));
            if v.is_some() {
                // SAFETY: single-threaded, per this function's contract.
                unsafe {
                    #[cfg(unix)]
                    scrub_in_place(name);
                    std::env::remove_var(name);
                }
            }
            (name, v)
        })
        .collect();
    let _ = TAKEN.set(taken);
}

/// Overwrite the value of `name` where the environment keeps it. For a
/// variable the process was started with, that is the block set up at
/// exec (see the module documentation).
///
/// # Safety
///
/// Single-threaded only, like [`take_all`]: nothing may read or change
/// the environment meanwhile.
#[cfg(unix)]
unsafe fn scrub_in_place(name: &str) {
    let Ok(c) = std::ffi::CString::new(name) else {
        return;
    };
    // SAFETY: `c` is NUL-terminated; per the caller's contract no other
    // thread touches the environment, so the returned pointer stays
    // valid while we write through it.
    unsafe {
        let p = libc::getenv(c.as_ptr());
        if p.is_null() {
            return;
        }
        let len = libc::strlen(p);
        for i in 0..len {
            // Volatile: the bytes are never read again here, so a plain
            // write could be optimized away.
            std::ptr::write_volatile(p.add(i), 0);
        }
    }
}

fn lookup(name: &str) -> Option<&'static Option<Option<Zeroizing<String>>>> {
    TAKEN
        .get()
        .and_then(|t| t.iter().find(|(n, _)| *n == name).map(|(_, v)| v))
}

/// The value of secret `name` (like `std::env::var(name).ok()`). Before
/// [`take_all`] (unit tests), the live environment.
pub(crate) fn var(name: &str) -> Option<Zeroizing<String>> {
    debug_assert!(NAMES.contains(&name), "{name} is not a secret variable");
    match lookup(name) {
        Some(v) => v.as_ref().and_then(|v| v.clone()),
        None if TAKEN.get().is_some() => None,
        None => std::env::var(name).ok().map(Zeroizing::new),
    }
}

/// Whether secret `name` was set at all (like
/// `std::env::var_os(name).is_some()`).
pub(crate) fn is_set(name: &str) -> bool {
    debug_assert!(NAMES.contains(&name), "{name} is not a secret variable");
    match lookup(name) {
        Some(v) => v.is_some(),
        None if TAKEN.get().is_some() => false,
        None => std::env::var_os(name).is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This process's environment block as the kernel shows it to
    /// others: `/proc/self/environ` on Linux, `KERN_PROCARGS2` on macOS.
    #[cfg(target_os = "linux")]
    fn initial_environment_block() -> Option<Vec<u8>> {
        std::fs::read("/proc/self/environ").ok()
    }

    #[cfg(target_os = "macos")]
    fn initial_environment_block() -> Option<Vec<u8>> {
        let mut mib = [
            libc::CTL_KERN,
            libc::KERN_PROCARGS2,
            std::process::id() as i32,
        ];
        let mut size: libc::size_t = 1 << 20;
        let mut buf = vec![0u8; size];
        // SAFETY: `mib` and `buf` outlive the call; `size` is the buffer's
        // length on entry and the bytes written on return.
        let r = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                3,
                buf.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        (r == 0).then(|| {
            buf.truncate(size);
            buf
        })
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn initial_environment_block() -> Option<Vec<u8>> {
        None
    }

    const CHILD: &str = "LUKSBOX_SECRET_ENV_TEST_CHILD";

    fn value(name: &str) -> Option<String> {
        var(name).map(|v| v.to_string())
    }

    /// F10: after `take_all` the secrets are still readable here, as
    /// often as needed, but gone from the environment, so a process
    /// started from here does not get them. Runs in a child process of
    /// the test binary (the environment is process-wide).
    #[cfg(unix)]
    #[test]
    fn secrets_leave_the_environment() {
        if std::env::var_os(CHILD).is_some() {
            // SAFETY: the parent runs this test alone (one test, one test
            // thread); nothing else reads the environment meanwhile.
            unsafe { take_all() };
            assert!(std::env::var_os("LUKSBOX_PASSPHRASE").is_none());
            assert!(std::env::var_os("LUKSBOX_TPM_PIN").is_none());
            for _ in 0..2 {
                assert_eq!(value("LUKSBOX_PASSPHRASE").as_deref(), Some("canary-pp"));
            }
            assert!(is_set("LUKSBOX_TPM_PIN"));
            assert_eq!(value("LUKSBOX_TPM_PIN").as_deref(), Some(""));
            assert!(!is_set("LUKSBOX_NEW_PASSPHRASE"));
            assert!(value("LUKSBOX_NEW_PASSPHRASE").is_none());
            let env = std::process::Command::new("/usr/bin/env")
                .output()
                .expect("run env");
            let env = String::from_utf8_lossy(&env.stdout);
            assert!(!env.contains("canary-pp"), "{env}");
            assert!(!env.contains("LUKSBOX_TPM_PIN="), "{env}");
            assert!(env.contains("LUKSBOX_KEPT=1"), "{env}");
            // Nor in the environment block the kernel shows for this
            // process (what `/proc/<pid>/environ` and `KERN_PROCARGS2`
            // read), where the value is overwritten in place.
            if let Some(block) = initial_environment_block() {
                let canary = b"canary-pp";
                assert!(
                    !block.windows(canary.len()).any(|w| w == canary),
                    "the value is still in the initial environment block"
                );
                let kept = b"LUKSBOX_KEPT=1";
                assert!(block.windows(kept.len()).any(|w| w == kept));
            }
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let o = std::process::Command::new(exe)
            .args([
                "secret_env::tests::secrets_leave_the_environment",
                "--exact",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("LUKSBOX_PASSPHRASE", "canary-pp")
            .env("LUKSBOX_TPM_PIN", "")
            .env_remove("LUKSBOX_NEW_PASSPHRASE")
            .env("LUKSBOX_KEPT", "1")
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        assert!(o.status.success(), "{text}");
        assert!(text.contains("1 passed"), "{text}");
    }
}
