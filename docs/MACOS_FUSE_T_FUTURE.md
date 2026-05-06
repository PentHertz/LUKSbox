# macOS FUSE-T support - analysis and roadmap

**Status as of 2026-05-03**: LUKSbox uses **macFUSE** on macOS for the
`mount` subcommand. FUSE-T is NOT supported. This document captures
why, what would have to change, and at what point it becomes worth
revisiting.

## tl;dr

- macFUSE requires kernel-extension approval (System Settings ->
  Privacy & Security; on Apple Silicon also Recovery Mode -> Reduced
  Security). One-time per machine, but real friction.
- FUSE-T is a kext-free FUSE implementation (uses NFS-over-loopback)
  that would eliminate that friction.
- **No Rust FUSE crate currently supports FUSE-T.** Every published
  crate (`fuser`, `fuse3`, `rfuse3`) hard-codes macFUSE on macOS.
- Adopting FUSE-T requires either writing a new Rust crate (~2-3
  weeks MVP, more for production) or upstreaming patches to one of
  the existing crates (write + review + merge, weeks-to-months).
- Recommendation: stick with macFUSE until FUSE-T-aware Rust
  bindings exist or LUKSbox's user base specifically requires
  kext-free deployment.

## Why we don't already use FUSE-T

When this was first considered (2026-05-03 conversation), the
working assumption was: "switch the macOS install instructions
from macFUSE to FUSE-T, both provide a `mount_macfuse` shim,
fuser-the-crate spawns it at runtime, no code changes required."
**That assumption was wrong on three counts**, all caught only
when CI started failing:

1. **`fuser 0.17` does not spawn `mount_macfuse` from PATH on
   macOS**, even with `default-features = false`. Reading
   `fuser-0.17.0/build.rs`:
   ```rust
   } else if target_os == "macos" {
       pkg_config::Config::new()
           .atleast_version("2.6.0")
           .probe("fuse")  // for macFUSE 4.x
           .unwrap();
       println!("cargo::rustc-cfg=fuser_mount_impl=\"libfuse2\"");
   }
   ```
   The macOS branch unconditionally probes for `fuse.pc` (libfuse2
   ABI) and links libfuse. There is no spawn-only fallback.

2. **FUSE-T does not install `fuse.pc`.** It installs `fuse-t.pc`
   and `fuse3.pc` (libfuse3 ABI, different filename, different
   ABI). fuser's pkg-config probe fails outright.

3. **FUSE-T does not ship a `mount_macfuse` binary.** It ships
   `mount_fusefs` and uses its own NFS-bridge mount protocol; the
   macFUSE mount-helper convention is foreign to it.

So FUSE-T is not a drop-in for macFUSE either at the link layer
(libfuse2 vs libfuse3) or at the spawn layer (`mount_macfuse`
binary missing).

## What about other Rust FUSE crates?

Audit of every FUSE crate on crates.io as of 2026-05-03:

| Crate | Latest | macOS strategy | FUSE-T support |
|---|---|---|---|
| [`fuser`](https://crates.io/crates/fuser) | 0.17.0 | Hard-coded `pkg-config fuse` (libfuse2) + macFUSE link | ❌ |
| [`fuse3`](https://crates.io/crates/fuse3) | 0.9.0 | `find_macfuse_mount()` checks `/Library/Filesystems/macfuse.fs/Contents/Resources/mount_macfuse` | ❌ |
| [`rfuse3`](https://crates.io/crates/rfuse3) | 0.0.7 (fork of fuse3) | Same hard-coded macFUSE path | ❌ |

The macFUSE-only assumption appears to be load-bearing across the
whole Rust FUSE ecosystem. FUSE-T's first stable release was 2022,
and the Rust crates predate it; no maintainer has shipped FUSE-T
support yet.

There may be unmerged PRs / issues upstream we missed. Worth
re-checking before any new spike: <https://github.com/cberner/fuser/issues>,
<https://github.com/Sherlock-Holo/fuse3/issues>.

## Why FUSE-T is hard to add

It's not just a matter of finding a different mount binary. FUSE-T
uses a **fundamentally different transport**:

| Concern | macFUSE | FUSE-T |
|---|---|---|
| Kernel component | Kext (`io.macfuse.filesystems.macfuse`) loaded at install time | None - uses macOS's built-in NFS client |
| Userspace ↔ kernel transport | Custom `/dev/macfuseN` character device | NFS-over-loopback (mountd, lockd, ...) |
| Mount syscall | `mount("macfuse", ...)` against the kext | `mount("nfs", ...)` against `localhost:port` |
| libfuse ABI version | libfuse2 (`fuse.h` from libfuse 2.x) | libfuse3 (`fuse.h` from libfuse 3.x) |

A FUSE-T-aware Rust crate would need to:

1. Bind to FUSE-T's `libfuse-t.dylib` via bindgen, generating
   libfuse3-style declarations.
2. Implement an NFS-server-side handler that responds to NFS RPCs
   from macOS's kernel NFS client. (FUSE-T runs the FS as an
   NFS server bound to a loopback port; the OS mounts it like a
   remote NFS export.)
3. Translate between the libfuse3 callback API and NFS RPC
   semantics.
4. Manage the lifetime of the loopback NFS server alongside the
   FUSE session.

That's significantly more involved than just calling a different
mount helper. It's why no Rust crate has it yet.

## Realistic paths forward

### Option A: Stick with macFUSE (current state)

- ✅ Ships today.
- ✅ Same UX as every other FUSE-on-macOS app the user has likely
  used (sshfs, rclone mount, ntfs-3g).
- ❌ Kext approval friction on first install. Apple Silicon also
  needs Recovery Mode -> Reduced Security.
- ❌ Long-term risk: Apple has been deprecating kernel extensions
  since macOS Big Sur (11.0). They haven't broken kext-based
  filesystems yet, but they've signaled intent.

**Default unless we have a specific reason to invest.**

### Option B: Write a `fuse-t-rs` crate

A new crate that wraps FUSE-T's libfuse-t.dylib and exposes an API
similar to `fuser`'s `Filesystem` trait, then swap our macOS
adapter to use it.

- Estimated effort: **2-3 weeks for an MVP** (single-threaded,
  read/write, basic dir ops). Production-quality (concurrency, edge
  cases, lock semantics) doubles that.
- Open-source contribution to the ecosystem; could be reused by
  rclone, sshfs-ng, etc.
- Maintenance burden ours indefinitely, unless someone else picks
  it up.

**Worth doing if FUSE-T adoption becomes strategic** (e.g.,
enterprise customers who refuse to install kexts; macOS deprecating
kext FS support; widely-used Mac tools migrating).

### Option C: Patch `fuse3` upstream

Add FUSE-T detection + mount-protocol support to the existing
`fuse3` crate, run our own fork in the meantime, push a PR.

- Estimated effort: ~1 week to write the patch (smaller scope than
  Option B since we'd reuse fuse3's request-dispatch loop), plus
  weeks-to-months waiting for upstream review.
- Doesn't help us until upstream merges or we ship a fork.
- Means migrating LUKSbox from `fuser` (sync-trait API) to `fuse3`
  (async-trait API) - that's an additional refactor of
  `crates/luksbox-mount/src/fuse.rs`.

**Worth doing if we'd already migrated to fuse3 for other reasons.**

### Option D: Just ship `mount` only on Linux + Windows, no mount on macOS

- ✅ Zero work; instant.
- ❌ Drops a feature LUKSbox advertises.
- ❌ macOS users get the worst experience.

**Not a serious option** unless mount turns out to be barely used.

## When to revisit

Triggers that should make us re-evaluate:

- **Apple breaks kext FS support** (anything from "deprecation
  warning at install" to "kexts fully removed"). If macFUSE stops
  working, Option B becomes urgent.
- **A `fuse-t-rs` crate ships** from someone else. Then this
  document becomes "swap fuser for fuse-t-rs in
  `crates/luksbox-mount/src/fuse.rs`'s macOS path", a much smaller
  task.
- **Enterprise sales feedback**: "we can't deploy LUKSbox because
  IT policy forbids kexts." Concrete revenue impact justifies
  Option B.
- **macFUSE goes unmaintained**. As of 2026 it's actively
  maintained by Benjamin Fleischer; check periodically.

## Where the macFUSE-bound code lives

If/when we re-attempt this:

- `crates/luksbox-mount/Cargo.toml` - `fuser = { version = "0.17",
  default-features = false }` is the dep to replace.
- `crates/luksbox-mount/src/fuse.rs` - the entire file is wrapped
  around fuser's Filesystem trait. Translating to fuse3 (or
  fuse-t-rs) means rewriting most of it. Keep the
  `luksbox_vfs::Vfs` calls intact; only the trait shape changes.
- `scripts/build_release.sh` - `fuse_for_target()` probes for
  `fuse.pc`. Add a sibling probe for FUSE-T's `fuse-t.pc` when
  the crate change makes that meaningful.
- `.github/workflows/release.yml` - macOS deps step installs
  `--cask macfuse`. Would change to `--cask fuse-t` (with the new
  crate).
- `BUILDING.md` macOS section - install instructions.
- `README.md` and the macOS portable .zip / .dmg release notes -
  user-facing wording.
- GUI mount tooltip (`crates/luksbox-gui/src/app.rs`).

Also: drop the `luksbox_macos_fuse.md` project memory at
`~/.claude/projects/-home-user-luksbox/memory/` since the
constraint it documents would no longer apply.

## Related conversations

The above analysis came out of a 2026-05-03 spike. Two false
starts ate roughly an hour of CI time:

1. **First attempt**: "Switch CI to install FUSE-T instead of
   macFUSE; fuser will spawn its mount_macfuse shim." Failed
   because FUSE-T doesn't ship a `mount_macfuse` shim and the
   pkg-config probe also failed (different .pc filename).
2. **Second attempt**: "Switch to fuse3 crate which surely supports
   FUSE-T since it's libfuse3-based." Failed because fuse3 also
   hard-codes macFUSE's mount path; libfuse3 ABI is necessary but
   not sufficient.

Lesson: confirm the entire stack supports a target before
committing to it, not just the proximate library.
