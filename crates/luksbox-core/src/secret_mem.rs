// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Process-level RAM-secret hardening, best-effort.
//!
//! Two mitigations:
//!
//! 1. **`disable_core_dumps`**, via `setrlimit(RLIMIT_CORE, 0)`. Prevents
//!    the kernel from writing a `core.<pid>` file (which would contain
//!    every secret in the process's heap and stack) on a panic / segfault.
//!    Always succeeds for unprivileged users since it only *lowers* a limit.
//!
//! 2. **`enable_memory_lock`**, via `mlockall(MCL_CURRENT | MCL_FUTURE)`.
//!    Prevents kernel from swapping process pages to disk and from including
//!    them in a hibernate image. Requires `RLIMIT_MEMLOCK` >= process RSS;
//!    on most distros the default is 64 KiB which is too small for a
//!    process holding 256 MiB of Argon2id state. We log a warning and
//!    continue when permission is refused, the rest of the secret-handling
//!    chain (zeroize-on-drop, constant-time compares) still applies.
//!
//! Call once near the top of `main()`. No-op on non-Unix targets.

#[cfg(unix)]
pub fn disable_core_dumps() {
    // SAFETY: setrlimit is signal-safe; we pass a valid struct address and
    // a known-valid resource id. Failure (very rare) is non-fatal.
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let _ = libc::setrlimit(libc::RLIMIT_CORE, &limit);
    }

    // Round 9B addition (Linux only): also call `prctl(PR_SET_DUMPABLE, 0)`.
    // Two effects beyond `setrlimit(RLIMIT_CORE, 0)`:
    //
    // 1. Some setuid-like configurations (`fs.suid_dumpable=2` mode) ignore
    //    RLIMIT_CORE and consult PR_DUMPABLE instead. Without the prctl
    //    call those processes can still produce coredumps with the secrets
    //    present in memory.
    // 2. PR_SET_DUMPABLE = 0 also blocks ptrace from non-privileged sibling
    //    processes (per Linux's Yama LSM + the dumpable check in
    //    fs/proc/base.c). A co-resident process running as the same user
    //    can't ptrace-attach to read /proc/<pid>/mem.
    //
    // Both effects matter when an unprivileged attacker has shell access
    // as the same user but doesn't already have CAP_SYS_PTRACE.
    #[cfg(target_os = "linux")]
    unsafe {
        // SAFETY: prctl(PR_SET_DUMPABLE, 0) takes one int arg + ignored
        // remaining args. Always succeeds on Linux >= 2.6.13. No memory
        // accessed.
        let _ = libc::prctl(libc::PR_SET_DUMPABLE, 0i32, 0, 0, 0);
    }
}

/// On Windows, suppress error-mode dialogs (which can trigger Windows
/// Error Reporting and upload a minidump containing process memory) +
/// disable the legacy "GP fault" popup. Best-effort; Windows still
/// allows admins to enable Crash Dump for individual processes via
/// HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps,
/// which we can't override from userspace.
#[cfg(target_os = "windows")]
pub fn disable_core_dumps() {
    // SetErrorMode flag values per Win32 documentation.
    const SEM_FAILCRITICALERRORS: u32 = 0x0001;
    const SEM_NOGPFAULTERRORBOX: u32 = 0x0002;
    const SEM_NOOPENFILEERRORBOX: u32 = 0x8000;

    unsafe extern "system" {
        fn SetErrorMode(uMode: u32) -> u32;
    }

    // SAFETY: SetErrorMode is a thread-process-wide flag setter. No
    // pointers, no locking issues. Return value is the previous mode
    // which we ignore.
    unsafe {
        let _ =
            SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    }
}

#[cfg(not(any(unix, target_os = "windows")))]
pub fn disable_core_dumps() {}

/// Best-effort lock the entire process address space into RAM. Returns
/// `Ok(())` on success and `Err(reason)` on failure (so callers can decide
/// whether to escalate to a hard error in "strongest security" modes or
/// just warn).
#[cfg(unix)]
pub fn enable_memory_lock() -> Result<(), String> {
    // SAFETY: mlockall is signal-safe; flag bits are POSIX-defined.
    let r = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if r != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EPERM) {
            return Err("mlockall: EPERM (your RLIMIT_MEMLOCK is too low; for full \
                 memory locking add `* hard memlock unlimited` to \
                 /etc/security/limits.conf and re-login, or run as root)"
                .to_string());
        }
        return Err(format!("mlockall failed: {err}"));
    }
    Ok(())
}

/// On Windows there is no `mlockall` equivalent (no process-wide
/// "lock everything" syscall). The per-allocation `VirtualLock` is
/// what keeps secret pages out of `pagefile.sys`, and it lives in
/// `SecretBox` (called automatically every time a new `SecretBox`
/// is allocated). This top-level function therefore returns `Ok(())`
/// with no work, so callers don't surface a misleading
/// "not supported on this platform" warning at startup.
#[cfg(target_os = "windows")]
pub fn enable_memory_lock() -> Result<(), String> {
    Ok(())
}

#[cfg(not(any(unix, target_os = "windows")))]
pub fn enable_memory_lock() -> Result<(), String> {
    Err("memory locking not supported on this platform".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// After `disable_core_dumps()` returns, `RLIMIT_CORE` MUST be 0.
    /// Round 9B regression test.
    #[cfg(unix)]
    #[test]
    fn disable_core_dumps_zeroes_rlimit_core() {
        disable_core_dumps();
        let mut rlim = libc::rlimit {
            rlim_cur: u64::MAX as libc::rlim_t,
            rlim_max: u64::MAX as libc::rlim_t,
        };
        let r = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut rlim) };
        assert_eq!(r, 0, "getrlimit must succeed");
        assert_eq!(rlim.rlim_cur, 0, "soft limit must be 0 after hardening");
        assert_eq!(rlim.rlim_max, 0, "hard limit must be 0 after hardening");
    }

    /// After `disable_core_dumps()` on Linux, `prctl(PR_GET_DUMPABLE)` MUST
    /// return 0. Round 9B regression test specifically for the prctl
    /// addition (the suid-dumpable bypass + ptrace-block path).
    #[cfg(target_os = "linux")]
    #[test]
    fn disable_core_dumps_clears_pr_dumpable_on_linux() {
        disable_core_dumps();
        let r = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
        assert_eq!(
            r, 0,
            "PR_GET_DUMPABLE must return 0 after hardening (got {r})"
        );
    }
}
