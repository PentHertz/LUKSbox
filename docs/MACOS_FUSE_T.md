# macOS FUSE-T support

**Status as of 2026-05-09**: LUKSbox supports both **FUSE-T** and
**macFUSE** on macOS for the `mount` subcommand. FUSE-T is the
recommended (kext-free) backend; macFUSE is kept as a fallback for
hosts that have it wired up already.

This document captures the architecture, why it works the way it
does, and the known Phase-1 limitations that need real-world
hardening.

## Quick install

```bash
brew tap macos-fuse-t/homebrew-cask
brew install --cask fuse-t
```

Then build LUKSbox normally - the build script and the release
workflow auto-detect FUSE-T's `fuse-t.pc` and enable the `fuse-t`
Cargo feature on `luksbox-mount`. From source, opt into FUSE-T
explicitly:

```bash
cargo build --release -p luksbox-cli \
    --no-default-features --features hardware,fuse-t,winfsp
```

## Architecture

The macOS mount path on LUKSbox is one of two backends, picked at
build time, mutually exclusive at link time:

```
                         ┌──────────────────────────────┐
                         │   luksbox-mount::mount(vfs)  │
                         └──────────────┬───────────────┘
                                        │
                  ┌─────────────────────┼─────────────────────┐
                  │                     │                     │
            ┌─────▼──────┐        ┌─────▼──────┐         ┌────▼─────┐
            │   fuse-t   │        │    fuse    │         │  winfsp  │
            │  (macOS)   │        │ (Linux+    │         │ (Win)    │
            │            │        │  macOS)    │         │          │
            └─────┬──────┘        └─────┬──────┘         └────┬─────┘
                  │                     │                     │
            ┌─────▼──────┐        ┌─────▼──────┐         ┌────▼─────┐
            │ luksbox-   │        │   fuser    │         │ winfsp_  │
            │  fuse-t    │        │  (libfuse2)│         │   wrs    │
            │ (in-tree)  │        │            │         │          │
            └─────┬──────┘        └─────┬──────┘         └────┬─────┘
                  │                     │                     │
            ┌─────▼──────┐        ┌─────▼──────┐         ┌────▼─────┐
            │ libfuse-t. │        │  libfuse.  │         │  WinFsp  │
            │   dylib    │        │   2.dylib  │         │   driver │
            │            │        │            │         │          │
            │ NFS-loop-  │        │ macFUSE    │         │ Win user │
            │   back     │        │   kext     │         │  mode FS │
            └────────────┘        └────────────┘         └──────────┘
```

The new component is `crates/luksbox-fuse-t/`, a thin in-tree binding
crate. It bindgens against FUSE-T's `<fuse_t/fuse.h>` (the libfuse 2.x
high-level header that FUSE-T ships) and exposes a safe Rust
`Filesystem` trait that `crates/luksbox-mount/src/fuse_t.rs`
implements against `luksbox_vfs::Vfs`.

## Why we don't just use the existing `fuser` crate

`fuser = "0.17"` (`workspace.dependencies` in `Cargo.toml`) hard-codes
a `pkg-config probe("fuse")` for libfuse2 in its `build.rs`'s macOS
branch:

```rust
// fuser-0.17.0/build.rs
} else if target_os == "macos" {
    if cfg!(feature = "macos-no-mount") {
        println!("cargo::rustc-cfg=fuser_mount_impl=\"macos-no-mount\"");
    } else {
        pkg_config::Config::new()
            .atleast_version("2.6.0")
            .probe("fuse")               // <-- libfuse2 .pc, macFUSE only
            .map_err(|e| eprintln!("{e}"))
            .unwrap();
        println!("cargo::rustc-cfg=fuser_mount_impl=\"libfuse2\"");
    }
}
```

FUSE-T installs `fuse-t.pc` (and `fuse3.pc`), not `fuse.pc`. The
naming difference is enough to break fuser's macOS link step before
any other consideration. Even if we forced the link past that, fuser
implements libfuse 2.x low-level on macOS, while FUSE-T's libfuse
2.x interface is high-level (path-based, `struct fuse_operations`).
Different ABIs, different shape.

That's why FUSE-T support couldn't be a config-only swap. The new
`luksbox-fuse-t` crate is what bridges the gap.

## What `luksbox-fuse-t` does

| Layer | File | What it does |
|---|---|---|
| Build | `build.rs` | Probes pkg-config for `fuse-t.pc`. Runs bindgen against `wrapper.h` (which `#include`s `<fuse_t/fuse.h>`). Emits `cargo:rustc-link-lib=fuse-t`. |
| FFI | `src/sys.rs` | `include!()` the bindgen-generated bindings; hand-declares `fuse_main_real` (which lives behind a libfuse macro bindgen can't see through). |
| Trampolines | `src/ops.rs` | `extern "C"` shims for every `struct fuse_operations` callback we implement. Each shim recovers the boxed `dyn Filesystem` from `fuse_get_context()->private_data`, marshalls C args -> safe Rust types, calls the trait method, maps `Result<T, Errno>` -> libfuse's negative-errno return convention. Catches panics so a buggy impl can't take down the FUSE thread mid-syscall. |
| Public API | `src/lib.rs` | `Filesystem` trait, `mount()`, `unmount()`, `Errno`, `FileAttr`, `MountOptions`. Mount blocks until the kernel unmounts; libfuse's high-level loop handles signals (SIGINT/SIGTERM unmount cleanly). |

The adapter at `crates/luksbox-mount/src/fuse_t.rs` is the small piece
that ties the trait to `luksbox_vfs::Vfs`. It mirrors the structure of
`fuse.rs` (the macFUSE/Linux adapter) but calls `Vfs::lookup_path` to
resolve the path-based libfuse 2.x callbacks to the inode-based Vfs
operations. Per-call lookup overhead is O(depth) hash lookups against
the in-memory tree - fine for personal vault depths.

## Threat model differences vs macFUSE (read this before picking)

FUSE-T and macFUSE are NOT security-equivalent. The kext-free
deployment story is a real win on a single-user machine; on a
**shared machine** (corporate laptop, lab Mac, anything with more
than one logged-in human or any unprivileged daemon you don't fully
trust) the picture flips. This section documents the difference so
you can pick deliberately.

### Channel between userspace FS and the kernel

| Concern | macFUSE | FUSE-T (default NFS backend) |
|---|---|---|
| Transport | `/dev/macfuse*` character device | NFSv4 over **TCP loopback (`127.0.0.1:<ephemeral>`)** |
| Access control on the channel | Kernel permissions on the device node (mounter UID only) | **None.** No PID filter, no peer-credential check, no shared secret, no handshake. The NFS port accepts AUTH_SYS UIDs from any local connector. |
| Authoritative source | macFUSE kext source (open) | The NFS server (`go-nfsv4`) ships **closed-source** as a Mach-O binary inside `/Library/Application Support/fuse-t/bin/go-nfsv4-1.2.x`. Only the libfuse glue is open. |

What this means concretely on a multi-user Mac:

- Any other local user (or any unprivileged process running as the
  mounter - **including a sandboxed app**) can connect to the
  ephemeral loopback port FUSE-T binds and speak NFSv4 directly to
  it, presenting whatever AUTH_SYS UIDs they want. The FUSE-T
  project's own wiki acknowledges this: *"currently there's no
  authentication implemented."*
- That bypasses LUKSbox's userspace permission model. The mount's
  `default_permissions` flag is enforced **by the macOS kernel
  against the NFS responses**, not by us - so the attacker simply
  sends NFS requests with the matching UID/GID and the kernel relays
  the unencrypted data back to them.
- macFUSE's `/dev/macfuse*` device-node permission gates this at the
  kernel boundary; only the mounting process's UID can talk to it.
  Same threat model as opening any other restricted device file.

The default port binding IS loopback-only (`127.0.0.1`, never
`0.0.0.0`), so this is **strictly a local-attacker concern** - the
NFS port is not reachable from off-box. But "any local process can
read the mount" is a much weaker model than "only the mounting user
can". For a personal laptop where you're the only user, the
distinction doesn't matter; for a shared machine, it does.

There's a `-l <addr>:<port>` mount option that lets a user
deliberately bind FUSE-T's NFS server to a non-loopback address.
LUKSbox does NOT pass this option. Don't add it without
re-evaluating the threat model from scratch.

### FSKit backend (macOS 26+)

FUSE-T's newer FSKit backend uses a **Unix domain socket** rather
than TCP loopback (symbols `startUnixRPCListener`, `socket_path`,
`group.org.fuset.fskit-srv`). Unix sockets in `/tmp/`-style
directories are filesystem-permission-gated, which closes the
"any local process" hole. If you're on macOS 26+ and FUSE-T elected
the FSKit backend at install time, this section's warnings about
the TCP path don't apply. Verify via FUSE-T's logs at mount time.

### Closed-source NFS server

`go-nfsv4` (Go import path `github.com/fuse-t-org/go-nfsv4`) is the
component that handles every NFS RPC from the kernel - i.e. it is
the actual filesystem server, NOT a thin shim. It ships only as a
binary; there is no public source repository. The strings extracted
from the shipped binary include the maintainer's local build path
(`/Users/alexf/work/new_fuse/go-nfsv4/...`), confirming it's a
private repo. This means:

- We cannot audit the NFS-RPC parsing, authentication-decision
  paths, error handling, or any other security-relevant logic in
  the FUSE-T data path.
- A vulnerability in `go-nfsv4` (parsing bug, AUTH_SYS escalation,
  RPC desync, ...) is in our trust boundary even though we have no
  way to inspect it.
- Our `luksbox-fuse-t` binding crate is fully auditable; the FUSE-T
  glue (`lib/mount_darwin.c` etc.) is open; but the actual RPC
  handler is not.

This is a meaningful step down from macFUSE, where the kext source
is open and reviewable.

### When to choose which

| Situation | Recommended backend |
|---|---|
| Personal laptop, only you log in | **FUSE-T** - the kext-free story wins, the local-attacker hole doesn't apply |
| Shared workstation, lab machine, family Mac | **macFUSE** - the kext approval friction is worth the better local-attacker model |
| Untrusted apps run on the same Mac (random downloaded GUI utilities) | **macFUSE** - those apps shouldn't be able to read your mount via the loopback NFS port |
| Compliance / certification environment that requires audited components in the trust boundary | **macFUSE** - `go-nfsv4` being closed source is a hard blocker; macFUSE kext is auditable |
| Enterprise deployment that forbids kexts | **FUSE-T**, but document the local-attacker model in your threat assessment |
| macOS 26+ with FSKit backend confirmed at mount time | **FUSE-T** - the Unix-socket path closes the hole |

LUKSbox's build script picks FUSE-T over macFUSE when both are
detected. That's a defensible default for the personal-laptop case
(which is most users) but is **not** a "FUSE-T is more secure"
recommendation. If you're in any of the macFUSE-rows above, build
explicitly with `--no-default-features --features
hardware,fuse,winfsp` (see `BUILDING.md`).

### What does NOT change between backends

For completeness - these are the same regardless of which backend
you pick:

- The `.lbx` on-disk format and crypto.
- Per-chunk AEAD, per-file derived keys, anchor-based rollback
  detection.
- The userspace `MountError::Unsupported` fallback when no backend
  is available.
- Authentication of the mount itself (passphrase, FIDO2, TPM,
  PQ-KEM); the backend only affects how the kernel reaches the
  decrypted data once you've already unlocked the vault.

### Source-of-truth note

The findings above come from:
- The FUSE-T project wiki (`github.com/macos-fuse-t/fuse-t/wiki`),
  authored by the maintainer, explicit on the no-authentication
  point and the `-l` option's external-exposure warning.
- The open libfuse glue: `lib/mount_darwin.c:208` (`listen_addr`
  registration), `lib/mount_darwin.c:469-481` (closed-binary
  locator), `lib/mount_darwin.c:316-336` (unmount path).
- `strings` / symbol analysis on the shipped `go-nfsv4-1.2.1`
  Mach-O binary: `127.0.0.1:%d` and `127.0.0.1:0` literals
  (loopback bind, ephemeral port), no `0.0.0.0` / `[::]` literals,
  no `LOCAL_PEERCRED` / `getpeereid` / `SO_PEERCRED` symbols, no
  shared-secret strings.

We cannot cite the actual `bind()` / `listen()` source line
because `go-nfsv4` is not open source. If you need provable
end-to-end auditability of the data path, only macFUSE meets that
bar today.

## Backend selection at build time

Three call sites pick a backend:

1. **`scripts/build_release.sh`** - `fuse_t_for_target()` returns 1 if
   `fuse-t.pc` is on the host. `build_target` then prefers FUSE-T over
   macFUSE when both are available, and exports
   `--features fuse-t` on the cargo invocation.

2. **`.github/workflows/release.yml`** - the macOS deps step taps
   `macos-fuse-t/homebrew-cask` and tries `brew install --cask
   fuse-t`. If that succeeds, sets `LUKSBOX_FEATURES=hardware,fuse-t`
   and `LUKSBOX_FUSE_BACKEND=fuse-t`. If it fails, falls back to
   `brew install --cask macfuse` and `LUKSBOX_FEATURES=hardware,fuse`.
   Build fails hard if neither provider could be installed.

3. **Hand cargo invocations** - `--no-default-features --features
   hardware,fuse-t,winfsp` on macOS. Documented in `BUILDING.md`.

The `fuse-t` and `fuse` features can in principle coexist in the
Cargo manifest, but they cannot coexist at link time (the two libfuse
versions clash on the same symbols). The feature gates in
`crates/luksbox-mount/src/lib.rs` are written so that if both happen
to be on (e.g. downstream picked the union of features), `fuse-t`
wins for `mount()`/`unmount()` dispatch on macOS.

## Phase 1 limitations (what still needs hardening)

This shipped as v0.1.2 with the goal of "kext-free mount works for
the common path". Items that need attention before Phase 2 / v0.2:

- **Single-threaded only.** `mount()` passes `-s` to libfuse so
  callbacks run on one worker thread. Our `Vfs` is `Mutex`-wrapped
  anyway, so removing `-s` would just trade thread-pool overhead for
  lock contention. Worth re-evaluating if we see slow large-file
  reads on FUSE-T's NFS-loopback transport.

- **No xattr support.** FUSE-T forwards `getxattr`/`setxattr` calls;
  our binding doesn't bind them yet, so they'll get the libfuse
  default of ENOSYS. This is fine for vault use today (the Vfs
  doesn't store xattrs), but Finder will probe for `com.apple.quarantine`,
  `com.apple.metadata`, etc. on every file. Visible as a slight
  startup pause on Finder browsing of large directories. Phase 2:
  bind getxattr/setxattr/listxattr/removexattr through to a no-op
  in the trait by default, so they short-circuit without a kernel
  round-trip.

- **`statfs` reports zeros.** libfuse renders that as "unknown space"
  in `df` and Finder. Real FS-size reporting requires walking the
  Vfs's chunk index, doable but not implemented.

- **`destroy()` lifecycle reclamation.** If libfuse exits without
  calling our `op_destroy` trampoline (rare but possible on early
  mount failures), the boxed `FsHolder` leaks. Tracked via the
  comment at the bottom of `src/ops.rs::run_mount`. Fix is an
  Atomic-flag-tracked reclamation in the caller.

- **End-to-end mount has not been exercised on a real FUSE-T host
  by this project's CI yet.** GitHub's macOS runners can install
  the FUSE-T cask but the mount lifecycle (loopback NFS server
  startup, mount syscall, unmount) is what needs validation in
  practice. Phase 1 ships the binding green at compile / link
  time; Phase 2 adds an integration-test job mirroring the WinFsp
  test on Windows.

## Where the code lives

| File | What it is |
|---|---|
| `crates/luksbox-fuse-t/` | New in-tree binding crate. |
| `crates/luksbox-fuse-t/Cargo.toml` | Crate manifest, libc + thiserror runtime deps, bindgen + pkg-config build deps (macOS only). |
| `crates/luksbox-fuse-t/build.rs` | pkg-config probe for `fuse-t.pc`, bindgen invocation, link-lib emit. |
| `crates/luksbox-fuse-t/wrapper.h` | bindgen entry point. `#include`s `<fuse_t/fuse.h>` (or `<fuse.h>` fallback). |
| `crates/luksbox-fuse-t/src/lib.rs` | Public `Filesystem` trait, `mount`, `unmount`, errors. |
| `crates/luksbox-fuse-t/src/sys.rs` | Raw FFI: bindgen include + hand-decl of `fuse_main_real`. |
| `crates/luksbox-fuse-t/src/ops.rs` | C trampolines and the mount loop. |
| `crates/luksbox-mount/Cargo.toml` | Adds the `fuse-t` Cargo feature and a macOS-only optional `luksbox-fuse-t` dep. |
| `crates/luksbox-mount/src/lib.rs` | `mount()`/`unmount()` dispatch with the `fuse-t` > `fuse` precedence on macOS. |
| `crates/luksbox-mount/src/fuse_t.rs` | The adapter, implements `luksbox_fuse_t::Filesystem` against `luksbox_vfs::Vfs`. |
| `scripts/build_release.sh` | `fuse_t_for_target()` probe and the FUSE-T-preferred backend selection. |
| `.github/workflows/release.yml` | macOS deps step: try FUSE-T cask first, fall back to macFUSE. |
| `BUILDING.md` macOS section | User-facing install instructions for both providers. |

## When to reconsider

- **FUSE-T goes unmaintained or stops working on a new macOS.** The
  macFUSE fallback path is intentionally preserved so users can
  still mount; we'd document the workaround prominently in release
  notes.

- **macOS deprecates kexts entirely.** Then the macFUSE fallback
  becomes a no-op and we'd drop the `fuse` feature from the
  default-detected set on macOS. FUSE-T is unaffected by this
  scenario.

- **A community Rust crate ships a complete FUSE-T binding** with
  more features (xattr, async, multi-threaded) than ours. Then this
  crate becomes a maintenance burden we don't need; consider
  swapping in.

## Related history

The pre-implementation analysis lived at `MACOS_FUSE_T_FUTURE.md`.
That document is now obsolete (the support is implemented), see the
git log of this file for the original analysis if useful for
historical context.
