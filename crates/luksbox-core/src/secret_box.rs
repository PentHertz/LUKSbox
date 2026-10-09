// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! 32-byte secret container backed by `memfd_secret(2)` on Linux ≥ 5.14
//! when the syscall is available, falling back to a heap allocation otherwise.
//!
//! `memfd_secret` returns a file descriptor whose backing pages have these
//! kernel-enforced properties:
//!   - **Not visible to any other process**, including ones with `PTRACE`
//!     capability and `/proc/<pid>/mem` access. Even root cannot map these
//!     pages from another process.
//!   - **Excluded from kernel coredumps**, survives the
//!     `setrlimit(RLIMIT_CORE)` belt-and-suspenders we already do.
//!   - **Excluded from hibernate images**, closes the gap that plain
//!     `mlock` does NOT cover (mlock only prevents swap, not hibernation
//!     snapshots).
//!
//! When the syscall isn't available (kernel < 5.14, `CONFIG_SECRETMEM`
//! disabled, or non-Linux), we fall back to one private, page-aligned
//! anonymous mapping per secret (`mmap` + `mlock`, or `VirtualAlloc` +
//! `VirtualLock`), and only if even that fails to a `Box<[u8; 32]>`; all
//! variants keep the `Zeroize`-on-drop behavior. Same external API; the upgrade
//! is invisible to callers.
//!
//! ## macOS gap (and roadmap)
//!
//! macOS has no `memfd_secret` equivalent; the macOS path always takes
//! the `Box<[u8; 32]>` fallback. That gives `Zeroize`-on-drop +
//! `mlock` + no coredumps, but a same-machine root attacker (or a
//! process with `com.apple.security.cs.debugger`) can still read the
//! key via `task_for_pid_force` + `mach_vm_read`. On Linux the
//! `memfd_secret` pages refuse to map even for root.
//!
//! The macOS-native upgrade is the **Secure Enclave** (SEP coprocessor
//! on Apple Silicon and T2 Intel Macs): the MVK lives inside the SEP
//! hardware boundary, never exposed to the main CPU, and AEAD ops go
//! through `SecKey` / `CryptoKit` IPC. Significant rework, not a
//! drop-in:
//!
//! - The current "MVK is a 32-byte value our process holds" API
//!   becomes "MVK handle is an opaque enclave reference; ciphertext +
//!   nonce go in, plaintext comes out via IPC."
//! - Secure Enclave doesn't natively support AES-256-GCM-SIV (our
//!   default); it supports AES-GCM and ChaCha20-Poly1305. SEP path
//!   would have to either restrict to those ciphers or keep AES-GCM-SIV
//!   handling in-process for that subset of vaults.
//! - Per-chunk decryption IPC drops throughput from about 590 MB/s
//!   (in-process AES-NI) to the few-hundred MB/s range. Acceptable
//!   for vault use, would matter for streaming-media use cases we
//!   don't target.
//! - SEP-bound keys are not portable between Macs - the design has
//!   to either ship "SEP-locked vaults" as an opt-in mode, or wrap
//!   the MVK *under* the enclave (key-wrap pattern) so the portable
//!   form still exists.
//!
//! Tracked in `SECURITY.md` Tier 3 item 10. Estimated about 2 weeks of
//! design + implementation; not blocking v1 but the right macOS-
//! native posture for high-value-target users.
//!
//! ## Windows path (and roadmap)
//!
//! Windows has no `memfd_secret` equivalent either. The "make pages
//! unmappable from other processes" primitive on Windows is
//! **Protected Process Light** (PPL), but PPL requires the binary
//! to be signed with a Microsoft-issued PPL cert that is only
//! available to AV vendors and a few partners - not a path open
//! to LUKSbox.
//!
//! What we CAN reach on Windows:
//!
//! - **`VirtualLock`** - per-allocation equivalent of `mlock`,
//!   keeps pages out of `pagefile.sys`. Called automatically below
//!   in the Windows fallback path; failure is non-fatal (we still
//!   get `Zeroize`-on-drop). No special privilege required for the
//!   small allocations LUKSbox does.
//! - **`SetErrorMode`** to suppress Windows Error Reporting
//!   minidumps (already done in `secret_mem.rs::disable_core_dumps`).
//!
//! What we CAN'T reach without Microsoft signing:
//!
//! - **PPL** (anti-malware-vendor signing required).
//! - **VBS Trustlets / Isolated User Mode** (kernel signing required).
//!
//! The Windows-native upgrade is the **TPM 2.0** (mandatory for
//! Windows 11) via `NCryptCreatePersistedKey` + the Microsoft
//! Platform Crypto KSP. Same security model as Apple's Secure
//! Enclave: keys live inside the chip, never exposed to userspace,
//! AEAD operations happen through IPC. Same trade-offs as the
//! Secure Enclave roadmap above:
//!
//! - Per-chunk decryption goes through TPM IPC; throughput drops
//!   even more than SEP because TPMs are slower (typically 1-10
//!   MB/s symmetric, vs SEP's hundreds).
//! - TPM doesn't natively support AES-256-GCM-SIV (supports
//!   AES-CCM, AES-GCM, AES-CBC). Same "either restrict ciphers
//!   or keep AES-GCM-SIV in-process" decision.
//! - TPM-bound keys are non-portable between machines - same
//!   key-wrap-mode question as for Secure Enclave.
//!
//! Tracked in `SECURITY.md` Tier 3 item 10 alongside the macOS
//! Secure Enclave entry (the design is the symmetric problem with
//! a different vendor-specific API surface).
//!
//! ## Linux TPM-backed at-rest hardening (also on the roadmap)
//!
//! `memfd_secret` protects the MVK **in process memory** after
//! unlock. It does NOT protect the **wrapped** MVK in the .lbx
//! file - that's still just AES-GCM-SIV(passphrase-derived KEK,
//! plaintext MVK). A stolen vault file is exposed to brute-force
//! against the passphrase; on Linux today there's no machine
//! binding.
//!
//! The Linux-native upgrade is **TPM 2.0** via `tpm2-tss` + the
//! `tss-esapi` Rust crate. The kernel exposes `/dev/tpmrm0` as a
//! resource manager; no special privileges required for
//! unprivileged use. Working precedent:
//! `systemd-cryptenroll --tpm2-device=auto` does this for LUKS2.
//!
//! Same wrap-only design as the macOS / Windows entries (TPM
//! handles the unwrap at unlock; in-process AES-GCM-SIV does the
//! per-chunk work at full AES-NI speed). Of the three platforms,
//! Linux TPM is the easiest to ship: pure-OSS toolchain, no
//! enrollment / signing gates, `swtpm` software-TPM emulator
//! runs in CI for integration tests. Recommended starting point
//! for the hardware-isolated-key roadmap.
//!
//! See `SECURITY.md` Tier 3 item 10 for the full design
//! constraints (cipher restrictions, portability, PCR sealing).

use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

const KEY_LEN: usize = 32;

// `memfd_secret(2)` syscall number. Identical (447) on every Linux
// architecture that has the call (it post-dates the unified syscall
// table), so a single constant is correct; kept local rather than
// `libc::SYS_memfd_secret` because the libc crate only exposes that
// symbol on a subset of targets.
#[cfg(target_os = "linux")]
const SYS_MEMFD_SECRET: libc::c_long = 447;

pub struct SecretBox {
    inner: Inner,
}

enum Inner {
    #[cfg(target_os = "linux")]
    MemfdSecret {
        ptr: *mut u8,
        fd: libc::c_int,
        page_size: usize,
    },
    /// A dedicated, page-aligned anonymous mapping (`mmap` on Unix,
    /// `VirtualAlloc` on Windows) holding exactly one secret, locked out
    /// of swap for its whole lifetime (`mlock` / `VirtualLock`) and, on
    /// Linux, excluded from core dumps (`MADV_DONTDUMP`) and wiped in
    /// forked children (`MADV_WIPEONFORK`).
    ///
    /// One secret per page is the point (R15-04): `munlock` /
    /// `VirtualUnlock` are page-granular and not reference-counted, so
    /// the previous `Box<[u8; 32]>` backing (two MVKs, e.g. an original
    /// and its `clone()`, routinely sharing one 4 KiB heap page) made
    /// dropping either one unlock the page under the survivor. With a
    /// private page per secret the unlock at drop affects nobody else.
    ///
    /// Reached on Linux only when `memfd_secret` was unavailable (kernel
    /// < 5.14, `secretmem.enable=0`); on macOS/BSD/Windows it is the
    /// normal backing.
    #[cfg(any(unix, windows))]
    Page { ptr: *mut u8, len: usize },
    /// Last-resort heap fallback when the page mapping itself fails (or
    /// on targets with neither `mmap` nor `VirtualAlloc`). Locked
    /// best-effort at construction, zeroized on drop, and deliberately
    /// NEVER unlocked at drop so it cannot unlock a neighbour's page.
    Heap(Box<[u8; KEY_LEN]>),
}

// Windows extern declarations for `VirtualLock` / `VirtualUnlock`.
// Same direct `extern "system"` pattern as `secret_mem::SetErrorMode`,
// no extra crate dependency. Both functions take a `LPVOID` + `SIZE_T`
// and return `BOOL` (nonzero on success).
#[cfg(target_os = "windows")]
unsafe extern "system" {
    fn VirtualAlloc(
        addr: *mut core::ffi::c_void,
        size: usize,
        alloc_type: u32,
        protect: u32,
    ) -> *mut core::ffi::c_void;
    fn VirtualFree(addr: *mut core::ffi::c_void, size: usize, free_type: u32) -> i32;
    fn VirtualLock(addr: *mut core::ffi::c_void, size: usize) -> i32;
    fn VirtualUnlock(addr: *mut core::ffi::c_void, size: usize) -> i32;
}
#[cfg(target_os = "windows")]
const MEM_COMMIT: u32 = 0x0000_1000;
#[cfg(target_os = "windows")]
const MEM_RESERVE: u32 = 0x0000_2000;
#[cfg(target_os = "windows")]
const MEM_RELEASE: u32 = 0x0000_8000;
#[cfg(target_os = "windows")]
const PAGE_READWRITE: u32 = 0x0000_0004;

// SecretBox holds a raw pointer (memfd-backed) but the underlying memory
// is owned by this struct alone, no aliasing. Send/Sync are safe.
unsafe impl Send for SecretBox {}
unsafe impl Sync for SecretBox {}

impl SecretBox {
    /// Allocate a 32-byte zeroed `SecretBox`. Tries `memfd_secret` first;
    /// falls back to heap allocation on any failure.
    pub fn zeroed() -> Self {
        #[cfg(target_os = "linux")]
        {
            if let Some(b) = Self::try_memfd_secret() {
                return b;
            }
        }
        #[cfg(any(unix, windows))]
        {
            if let Some(b) = Self::try_private_page() {
                return b;
            }
        }
        // Last resort: plain heap. Lock best-effort and never unlock
        // (see `Inner::Heap`); the zeroize-on-drop wipe still runs.
        let boxed = Box::new([0u8; KEY_LEN]);
        #[cfg(unix)]
        {
            // SAFETY: pointer is to a live Box we just allocated; KEY_LEN is
            // within the allocation. mlock is signal-safe.
            unsafe {
                let _ = libc::mlock(boxed.as_ptr() as *const libc::c_void, KEY_LEN);
            }
        }
        #[cfg(target_os = "windows")]
        {
            // SAFETY: pointer is to a live Box we just allocated;
            // size matches the box; VirtualLock is signal-safe.
            unsafe {
                let _ = VirtualLock(boxed.as_ptr() as *mut core::ffi::c_void, KEY_LEN);
            }
        }
        Self {
            inner: Inner::Heap(boxed),
        }
    }

    /// Map one private anonymous page and pin it for this secret alone.
    /// Returns `None` if the mapping cannot be created (the caller then
    /// falls back to the heap). Locking is best-effort: a finite
    /// `RLIMIT_MEMLOCK` can refuse, in which case zeroize-on-drop stays
    /// the realistic mitigation (same posture the heap path always had).
    #[cfg(unix)]
    fn try_private_page() -> Option<Self> {
        // SAFETY: sysconf is signal-safe; _SC_PAGESIZE always succeeds.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page_size <= 0 {
            return None;
        }
        let len = page_size as usize;
        if len < KEY_LEN {
            return None;
        }
        // SAFETY: anonymous private mapping with sane arguments; the
        // kernel hands back zero-filled pages or MAP_FAILED.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return None;
        }
        // Lock BEFORE any secret is written into the page.
        // SAFETY: ptr/len describe the mapping we just created.
        unsafe {
            let _ = libc::mlock(ptr, len);
        }
        #[cfg(target_os = "linux")]
        {
            // Keep the page out of core dumps and wipe it in forked
            // children (`fork()` precedes every `Command::spawn`). Both
            // best-effort; both pre-date every kernel we support.
            // SAFETY: same mapping as above.
            unsafe {
                let _ = libc::madvise(ptr, len, libc::MADV_DONTDUMP);
                let _ = libc::madvise(ptr, len, libc::MADV_WIPEONFORK);
            }
        }
        Some(Self {
            inner: Inner::Page {
                ptr: ptr as *mut u8,
                len,
            },
        })
    }

    /// Windows twin of the Unix `try_private_page`: commit one page from
    /// a fresh reservation and `VirtualLock` it. `VirtualAlloc` always
    /// hands back whole, zero-filled pages, so one `KEY_LEN` secret per
    /// call keeps the lock accounting exact.
    #[cfg(target_os = "windows")]
    fn try_private_page() -> Option<Self> {
        const LEN: usize = 4096;
        // SAFETY: plain reservation + commit of fresh zero-filled pages.
        let ptr = unsafe {
            VirtualAlloc(
                std::ptr::null_mut(),
                LEN,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if ptr.is_null() {
            return None;
        }
        // SAFETY: ptr/LEN describe the region we just committed.
        unsafe {
            let _ = VirtualLock(ptr, LEN);
        }
        Some(Self {
            inner: Inner::Page {
                ptr: ptr as *mut u8,
                len: LEN,
            },
        })
    }

    /// Construct from a by-value array. The caller's array is moved into
    /// this frame and wiped here after the copy, so the callee side at
    /// least leaves no residue. Prefer `MasterVolumeKey::from_zeroizing`
    /// / `from_array_ref` in production code: those never materialise the
    /// by-value temporary in the first place (R12-17 / R13-09).
    pub fn from_bytes(mut bytes: [u8; KEY_LEN]) -> Self {
        let mut s = Self::zeroed();
        s.as_mut_array().copy_from_slice(&bytes);
        bytes.zeroize();
        s
    }

    /// Allocate a fresh secret box and fill with cryptographic random
    /// bytes. Returns `Err` only if the OS RNG fails, in which case
    /// the system is too broken to do anything else either.
    pub fn try_random() -> Result<Self, rand_core::Error> {
        let mut s = Self::zeroed();
        OsRng.try_fill_bytes(s.as_mut_array())?;
        Ok(s)
    }

    /// Convenience wrapper: panics on RNG failure. Prefer `try_random`
    /// in new code so the failure mode is propagated rather than
    /// killing the process.
    pub fn random() -> Self {
        Self::try_random().expect("OS RNG failure during MVK generation")
    }

    pub fn as_array(&self) -> &[u8; KEY_LEN] {
        match &self.inner {
            #[cfg(target_os = "linux")]
            Inner::MemfdSecret { ptr, .. } => unsafe { &*((*ptr) as *const [u8; KEY_LEN]) },
            // SAFETY: `ptr` is the start of a live mapping of at least
            // KEY_LEN bytes owned exclusively by this struct.
            #[cfg(any(unix, windows))]
            Inner::Page { ptr, .. } => unsafe { &*((*ptr) as *const [u8; KEY_LEN]) },
            Inner::Heap(b) => b,
        }
    }

    pub fn as_mut_array(&mut self) -> &mut [u8; KEY_LEN] {
        match &mut self.inner {
            #[cfg(target_os = "linux")]
            Inner::MemfdSecret { ptr, .. } => unsafe { &mut *((*ptr) as *mut [u8; KEY_LEN]) },
            // SAFETY: as in `as_array`; `&mut self` guarantees uniqueness.
            #[cfg(any(unix, windows))]
            Inner::Page { ptr, .. } => unsafe { &mut *((*ptr) as *mut [u8; KEY_LEN]) },
            Inner::Heap(b) => b,
        }
    }

    /// Whether this allocation is backed by `memfd_secret` (the strongest
    /// mode: unmappable by any other process, excluded from core dumps
    /// and hibernation images). A private locked page or the heap
    /// fallback both report `false`. Diagnostic.
    pub fn is_secret_mem(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            matches!(self.inner, Inner::MemfdSecret { .. })
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    #[cfg(target_os = "linux")]
    fn try_memfd_secret() -> Option<Self> {
        // SAFETY: memfd_secret syscall takes a single u32 flags arg; no
        // memory pointers passed in. Failure returns -1 (we check). On
        // success we get a real FD referring to a kernel-side allocation.
        //
        // R15-01: `O_CLOEXEC` is mandatory. The only flag `memfd_secret`
        // accepts, and the only thing standing between "no other process
        // can map these pages" and "every child we spawn (xdg-open,
        // fusermount, the FUSE-T helper, ...) inherits an fd it can
        // `mmap(MAP_SHARED)` to read the MVK". The earlier `0` flags
        // handed the live MVK to every child process for its lifetime.
        let fd = unsafe { libc::syscall(SYS_MEMFD_SECRET, libc::O_CLOEXEC as libc::c_uint) };
        if fd < 0 {
            // ENOSYS (kernel < 5.14), EFAULT, EPERM, etc., give up.
            return None;
        }
        let fd = fd as libc::c_int;

        // SAFETY: sysconf is signal-safe; _SC_PAGESIZE always succeeds.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        if page_size == 0 || page_size < KEY_LEN {
            unsafe { libc::close(fd) };
            return None;
        }

        // SAFETY: ftruncate on a known-valid FD with a non-negative size.
        if unsafe { libc::ftruncate(fd, page_size as libc::off_t) } != 0 {
            unsafe { libc::close(fd) };
            return None;
        }

        // SAFETY: mmap with sane args. NULL hint, sane length, permissions
        // we own. SHARED is required for memfd_secret-backed mappings.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            unsafe { libc::close(fd) };
            return None;
        }

        // Zero the first KEY_LEN bytes (page is already zeroed by the
        // kernel, but be defensive).
        unsafe { std::ptr::write_bytes(ptr as *mut u8, 0, KEY_LEN) };

        Some(Self {
            inner: Inner::MemfdSecret {
                ptr: ptr as *mut u8,
                fd,
                page_size,
            },
        })
    }
}

impl Drop for SecretBox {
    fn drop(&mut self) {
        match &mut self.inner {
            #[cfg(target_os = "linux")]
            Inner::MemfdSecret { ptr, fd, page_size } => unsafe {
                // Zero the secret bytes (defensive, the kernel will
                // unmap and reclaim the memfd_secret pages on close, but
                // we wipe anyway in case the mmap is observed mid-drop).
                // `zeroize` uses volatile stores the optimiser cannot
                // drop ahead of the unmap.
                std::slice::from_raw_parts_mut(*ptr, KEY_LEN).zeroize();
                libc::munmap(*ptr as *mut libc::c_void, *page_size);
                libc::close(*fd);
            },
            #[cfg(any(unix, windows))]
            Inner::Page { ptr, len } => {
                // SAFETY: ptr/len describe a mapping this struct owns
                // exclusively; nothing else shares the page, so the
                // unlock below cannot expose another secret.
                unsafe {
                    std::slice::from_raw_parts_mut(*ptr, KEY_LEN).zeroize();
                    #[cfg(unix)]
                    {
                        let _ = libc::munlock(*ptr as *const libc::c_void, *len);
                        let _ = libc::munmap(*ptr as *mut libc::c_void, *len);
                    }
                    #[cfg(target_os = "windows")]
                    {
                        let _ = VirtualUnlock(*ptr as *mut core::ffi::c_void, *len);
                        let _ = VirtualFree(*ptr as *mut core::ffi::c_void, 0, MEM_RELEASE);
                    }
                }
            }
            Inner::Heap(b) => {
                // Wipe only. Deliberately no munlock/VirtualUnlock here:
                // those are page-granular and would unlock any other
                // secret sharing this heap page (R15-04, the reason the
                // Page variant exists). A handful of stray locked pages
                // over a process lifetime is the cheaper failure mode.
                b.zeroize();
            }
        }
    }
}

impl Clone for SecretBox {
    /// Round 13 R13-09: copy directly between two `SecretBox` buffers
    /// without going through `Self::from_bytes(*self.as_array())`. The
    /// old path created a `[u8; KEY_LEN]` by-value temporary on the
    /// caller's stack, leaving 32 bytes of key material readable in
    /// the previous stack frame until the next reuse. The new path
    /// allocates a fresh secret-memory backing first and then
    /// `copy_from_slice`s from one allocator-owned buffer to another,
    /// so no stack-resident copy ever exists.
    fn clone(&self) -> Self {
        let mut s = Self::zeroed();
        s.as_mut_array().copy_from_slice(self.as_array());
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_via_array() {
        let mut s = SecretBox::zeroed();
        s.as_mut_array().copy_from_slice(&[0xa5; KEY_LEN]);
        assert_eq!(s.as_array(), &[0xa5; KEY_LEN]);
    }

    #[test]
    fn from_bytes_then_random_differ() {
        let a = SecretBox::from_bytes([0x42; KEY_LEN]);
        let b = SecretBox::random();
        assert_ne!(a.as_array(), b.as_array());
    }

    #[test]
    fn clone_makes_independent_copy() {
        let mut a = SecretBox::from_bytes([0x11; KEY_LEN]);
        let b = a.clone();
        a.as_mut_array()[0] = 0x99;
        assert_ne!(a.as_array(), b.as_array());
        assert_eq!(b.as_array()[0], 0x11);
    }

    /// R15-01 regression: the `memfd_secret` fd must be close-on-exec,
    /// otherwise every spawned child inherits a handle it can
    /// `mmap(MAP_SHARED)` to read the MVK. Only meaningful when the
    /// kernel actually gave us secret memory.
    #[cfg(target_os = "linux")]
    #[test]
    fn memfd_secret_fd_is_close_on_exec() {
        let s = SecretBox::zeroed();
        if let Inner::MemfdSecret { fd, .. } = &s.inner {
            // SAFETY: fd is a valid descriptor owned by `s`.
            let flags = unsafe { libc::fcntl(*fd, libc::F_GETFD) };
            assert!(flags >= 0, "F_GETFD failed");
            assert!(
                flags & libc::FD_CLOEXEC != 0,
                "memfd_secret fd must carry FD_CLOEXEC"
            );
        } else {
            eprintln!("memfd_secret unavailable on this kernel; CLOEXEC check skipped");
        }
    }

    #[test]
    fn drop_doesnt_panic() {
        // Just exercise drop. Not much we can assert about whether the
        // pages are actually wiped, since the wipe happens during Drop.
        for _ in 0..100 {
            let _s = SecretBox::random();
        }
    }
}
