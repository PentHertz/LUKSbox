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
//! disabled, or non-Linux), we fall back to a `Box<[u8; 32]>` with the
//! existing `Zeroize`-on-drop behavior. Same external API; the upgrade
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
    /// Heap allocation. On Windows we additionally call `VirtualLock`
    /// at construction (and `VirtualUnlock` at drop) to keep the page
    /// out of the swap file; the `Box` ownership semantics are
    /// unchanged. On Unix-but-not-Linux (macOS, BSD) the page is
    /// covered by the process-wide `mlockall` from
    /// `secret_mem::enable_memory_lock`. On Linux this variant is
    /// only used when `memfd_secret` itself was unavailable, in
    /// which case `mlockall` is again the live mitigation.
    Heap(Box<[u8; KEY_LEN]>),
}

// Windows extern declarations for `VirtualLock` / `VirtualUnlock`.
// Same direct `extern "system"` pattern as `secret_mem::SetErrorMode`,
// no extra crate dependency. Both functions take a `LPVOID` + `SIZE_T`
// and return `BOOL` (nonzero on success).
#[cfg(target_os = "windows")]
unsafe extern "system" {
    fn VirtualLock(addr: *mut core::ffi::c_void, size: usize) -> i32;
    fn VirtualUnlock(addr: *mut core::ffi::c_void, size: usize) -> i32;
}

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
        let boxed = Box::new([0u8; KEY_LEN]);
        // On Windows, lock the page so the secret bytes don't end up
        // in pagefile.sys. Best-effort: failure is silent (the
        // `Zeroize`-on-drop wipe still runs and is the realistic
        // mitigation against on-disk leakage; `VirtualLock` is the
        // belt to the suspenders). `VirtualLock` operates at page
        // granularity, which means the surrounding heap allocations
        // sharing the same page get locked too - acceptable for the
        // 32-byte allocations we make here.
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

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        let mut s = Self::zeroed();
        s.as_mut_array().copy_from_slice(&bytes);
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
            Inner::Heap(b) => b,
        }
    }

    pub fn as_mut_array(&mut self) -> &mut [u8; KEY_LEN] {
        match &mut self.inner {
            #[cfg(target_os = "linux")]
            Inner::MemfdSecret { ptr, .. } => unsafe { &mut *((*ptr) as *mut [u8; KEY_LEN]) },
            Inner::Heap(b) => b,
        }
    }

    /// Whether this allocation is backed by `memfd_secret`. Diagnostic.
    pub fn is_secret_mem(&self) -> bool {
        !matches!(self.inner, Inner::Heap(_))
    }

    #[cfg(target_os = "linux")]
    fn try_memfd_secret() -> Option<Self> {
        // SAFETY: memfd_secret syscall takes a single u32 flags arg; no
        // memory pointers passed in. Failure returns -1 (we check). On
        // success we get a real FD referring to a kernel-side allocation.
        let fd = unsafe { libc::syscall(SYS_MEMFD_SECRET, 0u32 as libc::c_uint) };
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
                std::ptr::write_bytes(*ptr, 0, KEY_LEN);
                libc::munmap(*ptr as *mut libc::c_void, *page_size);
                libc::close(*fd);
            },
            Inner::Heap(b) => {
                // Wipe first, then unlock on Windows so the bytes
                // are zeroed before the page becomes swappable
                // again.
                b.zeroize();
                #[cfg(target_os = "windows")]
                {
                    // SAFETY: same pointer + size we passed to
                    // VirtualLock at construction. VirtualUnlock on
                    // an already-unlocked page returns 0; we ignore
                    // the return value.
                    unsafe {
                        let _ = VirtualUnlock(b.as_ptr() as *mut core::ffi::c_void, KEY_LEN);
                    }
                }
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

    #[test]
    fn drop_doesnt_panic() {
        // Just exercise drop. Not much we can assert about whether the
        // pages are actually wiped, since the wipe happens during Drop.
        for _ in 0..100 {
            let _s = SecretBox::random();
        }
    }
}
