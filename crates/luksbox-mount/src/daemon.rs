// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Fork-to-background helpers shared by the Unix mount backends
//! (`fuse.rs` for libfuse / macFUSE, `fuse_t.rs` for FUSE-T), so both
//! honour `luksbox mount`'s default daemonize with the same
//! single-threaded-at-fork() guard.

/// Refuse to fork() if more than one thread is alive. Forking a
/// multithreaded process is a known POSIX footgun: only the calling
/// thread survives in the child, and the others' shared state (most
/// notably the libc allocator mutex) is left frozen. The first malloc
/// in the child can deadlock or corrupt heap.
///
/// - Linux: count entries in `/proc/self/task/`.
/// - macOS: enumerate threads via Mach `task_threads()`.
/// - Other unix: no portable thread enumeration without extra deps; the
///   check is skipped. The `daemonize=true` callers in this workspace
///   (`luksbox-cli`) are single-threaded at fork time, so the gap is
///   documented rather than load-bearing.
#[cfg(target_os = "linux")]
pub(crate) fn assert_single_threaded_for_fork() -> std::io::Result<()> {
    // Enumerate threads and read each `/proc/self/task/<tid>/comm` so
    // the error names the offenders. Past regressions in fuse.rs
    // (e.g. constructing LuksboxFs before fork, spawning the flush
    // timer in the parent) were silent counts; naming the threads
    // makes the next regression obvious.
    let mut threads: Vec<(libc::pid_t, String)> = Vec::new();
    for entry in std::fs::read_dir("/proc/self/task")? {
        let entry = entry?;
        let tid = entry
            .file_name()
            .to_string_lossy()
            .parse::<libc::pid_t>()
            .unwrap_or(0);
        let comm = std::fs::read_to_string(entry.path().join("comm"))
            .unwrap_or_else(|_| "<?>".to_string())
            .trim()
            .to_string();
        threads.push((tid, comm));
    }
    if threads.len() > 1 {
        let listing = threads
            .iter()
            .map(|(tid, name)| format!("{tid}={name}"))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(std::io::Error::other(format!(
            "{MULTITHREADED_FORK_MESSAGE} Live threads at fork point: [{listing}]"
        )));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
#[allow(deprecated)] // libc::mach_task_self -> mach2; not worth a new dep.
pub(crate) fn assert_single_threaded_for_fork() -> std::io::Result<()> {
    use libc::{
        kern_return_t, mach_msg_type_number_t, mach_port_t, mach_task_self, thread_act_array_t,
        vm_address_t, vm_deallocate, vm_size_t,
    };

    unsafe extern "C" {
        fn mach_port_deallocate(task: mach_port_t, name: mach_port_t) -> kern_return_t;
    }
    const KERN_SUCCESS: kern_return_t = 0;

    let task = unsafe { mach_task_self() };
    let mut threads: thread_act_array_t = std::ptr::null_mut();
    let mut count: mach_msg_type_number_t = 0;
    let kr = unsafe { libc::task_threads(task, &mut threads, &mut count) };
    if kr != KERN_SUCCESS {
        return Err(std::io::Error::other(format!(
            "luksbox-mount: task_threads() failed with kr={kr}; \
             cannot verify single-threadedness before fork()"
        )));
    }
    for i in 0..count {
        let t = unsafe { *threads.add(i as usize) };
        let _ = unsafe { mach_port_deallocate(task, t) };
    }
    let _ = unsafe {
        vm_deallocate(
            task,
            threads as vm_address_t,
            (count as vm_size_t) * std::mem::size_of::<mach_port_t>(),
        )
    };

    if count > 1 {
        return Err(std::io::Error::other(MULTITHREADED_FORK_MESSAGE));
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn assert_single_threaded_for_fork() -> std::io::Result<()> {
    Ok(())
}

const MULTITHREADED_FORK_MESSAGE: &str = "luksbox-mount: refusing to daemonize from a multithreaded process \
     (POSIX async-signal-safety would be violated). \
     Run with --foreground, or call mount(daemonize=true) before \
     spawning any background thread.";

/// Detach a freshly forked daemon child: new session, stdio on
/// `/dev/null` (so a caller piping `luksbox mount` output is not held
/// open by the daemon).
///
/// # Safety
/// Call only in the child right after `fork()`.
pub(crate) unsafe fn detach_from_terminal() -> std::io::Result<()> {
    if unsafe { libc::setsid() } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
    if null < 0 {
        return Err(std::io::Error::last_os_error());
    }
    for &target in &[0_i32, 1, 2] {
        if unsafe { libc::dup2(null, target) } == -1 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(null) };
            return Err(err);
        }
    }
    if null > 2 {
        unsafe { libc::close(null) };
    }
    Ok(())
}
