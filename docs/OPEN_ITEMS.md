# Open items after the v0.7 sync / CLI / TUI / GUI pass (2026-11-08)

What the testing and performance pass of 2026-11-07/08 left to do.
Everything else it found is fixed and listed in `CHANGELOG.md`
(v0.7.0-rc.1, tagged 2026-11-10, and v0.7.1-rc.1 in preparation); how
to run each check is in `TESTING.md`; measured speeds are in
`docs/PERFORMANCE.md`.

## Metadata region resize: done 2026-11-08, every kind of vault

Implemented and verified for vault files (inline header), detached
headers, deniable vaults and sync bundles (protocols in
`docs/VAULT_SIZE.md`): `luksbox size --metadata-size`, `luksbox
deniable-resize --data-moves-visibly`, the wizard (Vault size, and a
main-menu entry for deniable vaults), the GUI's Vault size dialog (an
"I understand" box for deniable vaults). Verified after the last change
(release builds): format + vfs + sync + merge 481 tests, CLI 89, GUI 55
(the end-to-end scenario resizes a vault file, a bundle, the
detached-header vault and the deniable vault), mount 27,
`scripts/cli_scenarios.sh` 233, `scripts/tui_scenarios.sh` 35, clippy
with no new warning. Tests: `crates/luksbox-vfs/tests/metadata_resize.rs`
(10, including a real crash before the rename and every crash state of
a detached-header resize) and `crates/luksbox-sync/tests/bundle_resize.rs`
(10, including merges across a layout change on two devices, a withheld
resize still detected as a rollback, two concurrent resizes kept as a
fork without either device going back to an older header, and merges
into a smaller layout).

An independent review of the finished code (2026-11-08) found six
defects, all fixed with tests: a merge into a head with a smaller file
list failed before the region was resized (every open failed); a bundle
save could fail on cleanup after its record was written, and the resize
then rolled back over a committed state; a detached-header commit that
failed after the rename left the session writable next to a stale
intent that the next open could install over newer keyslot changes (now
read-only, and an intent never overwrites a sidecar that already has the
new layout); recovery I/O errors could fall back to an old-layout
header mirror, and a restored `.rotating` could override the length
evidence; a session's finish could merge onto an older header after a
header fork; the merge fallback gave two different headers one
generation, and a missing base header object failed the open.

Found and fixed on the way (sync bundles): views of other commits used
the session head's header, which breaks once commits differ in layout;
a header adopted in a merge could be staged over an image with the
other layout; and a device that changed the header (keyslots or a
resize) was refused as "rolled back" when another device's head on the
older header came first in a fork (it now opens on the complete head
with the newest header; a header really gone is still refused). A first
version of that fix opened on the older head and relied on the merge,
which a header fork does not do: replaced before review.

Left for later: two different resizes made on two devices at the same
time stay a header fork (both versions kept, like other concurrent
header changes); resolving them automatically (the larger region wins)
would need a merge rule for layouts.

## Decided on 2026-11-08

(Added after the macOS review, same day.) **FUSE-T: an `fsync` is
durable within a second, not on return, without `--sync`.** The macOS
NFS client behind FUSE-T sends a COMMIT at every close, and saving on
each one made small-file copies 9 files/s and wrote 128 MiB per closed
file; coalesced, 575 files/s. Kept by the user; `--sync` (GUI: Eager
flush) stays durable on return (`docs/MACOS_FUSE_T.md`).

0. **Transfer performance accepted as is** (user decision after the final
   benchmark, 256 MiB on an SSD, unlock included): default vaults about
   175 MB/s write / 240 MB/s read, `--hide-sizes` 94 / 241, sync bundles
   109-129 / 153-165. The per-save cost of the 64 MiB default (128 MiB
   written per save, estimated 4-6 s on a USB 2 stick, not measured: no
   stick on the test machine) stays documented; users on slow media
   shrink the file list (also of an existing vault). Concurrent different
   resizes of one bundle staying a header fork: accepted as a known
   limitation.

1. **Default metadata region size: stays 64 MiB** (confirmed after the
   capacities were re-measured). Every save rewrites the region and its
   `.meta-bak` mirror (128 MiB per save, 0.15 s on an SSD, 4 to 6 s on
   a USB 2 stick); writing less per save would reveal the directory
   size between two copies of the vault. Capacity depends on file
   sizes: about 45 000 files of 1 MB in 64 MiB, about 11 000 in 16 MiB
   (table in `docs/PERFORMANCE.md`), so 16 MiB was judged too tight for
   a default. Added instead: a "File list: X% full" line in `luksbox
   size`, the wizard and the GUI's Vault size, and corrected capacity
   labels. Users on slow storage choose a smaller region at create.
   **Resizing the region of an existing vault: done on 2026-11-08**
   (see "Metadata region resize" below).
2. **Deniable rotation: enabled in the GUI, the CLI and the wizard, with a check.** The
   passphrase is typed twice and verified against the unlocked slot
   (`ops::verify_deniable_rotation_passphrase`, which also finds the
   KDF preset the new wrap keeps) before anything changes; a refusal
   leaves the vault open. Rotation keeps only the unlocked slot (the
   format gives every other slot random bytes, and a deniable vault
   cannot show whether others exist), so the modal warns that other
   slots stop working and requires a confirmation. A rotation that
   keeps other slots would need their credentials too. Also added the
   same day: `luksbox deniable-rotate` (refuses without
   `--other-slots-stop-working`; the open proves the passphrase and
   Argon2id settings) and the wizard entry "Rotate a deniable vault's
   master key", covered by `scripts/tui_scenarios.sh`. (The wizard's
   older `rotate_mvk_deniable_prepare`, reachable only from the
   standard open loop that deniable vaults never enter, is now unused
   in practice.)

## Checks not run

1. **Secure Enclave sync bundles through the CLI and the wizard**
   (v0.7.1-rc.1): the steps are in `scripts/cli_scenarios.sh` and
   `scripts/tui_scenarios.sh` but have never run, since they need a Mac
   with a Secure Enclave (CI's macOS runners have none). Run both
   scripts there with a `--features hardware,fuse-t` build before the
   stable release (`LUKSBOX_TEST_TOUCH_ID=1` adds the Touch ID steps); a
   step whose prompt does not appear prints the screen it waited on.
   The bundle layer is covered for every Secure Enclave kind with mocks
   (`luksbox-sync`'s `tests/bundle_hardware_keyslots.rs`).

3. **Optimized GUI timings: done** (2026-11-08, table in
   `docs/PERFORMANCE.md`): 190 to 195 MB/s import, 295 MB/s export.
4. **Visual layout: checked on 2026-11-08** with screenshots rendered
   headlessly (egui_kittest `wgpu` + `snapshot` features, lavapipe;
   enabled temporarily, not kept as a dependency): welcome, create form
   and its advanced section, browser with a toast stack, Keyslots, vault
   size, unlock, deniable rotation modal. Found and fixed: the create
   form's size note assumed 64 MiB, and the deniable rotation modal did
   not say that other slots stop working. To keep such checks, add the
   two features to the `egui_kittest` dev-dependency and save
   `harness.render()` images.
   **The real binary on an X display, same day:** `luksbox-gui` (release)
   on Xvfb (OpenGL through Mesa llvmpipe, system fonts), driven with
   xdotool: create a vault through the form, "+ Add files..." with
   three files picked in the native GTK chooser (zenity
   `--file-selection --multiple`, the fallback without a desktop
   portal), Download through the native save dialog, Lock; the CLI then
   listed and read the files back. Observation: the zenity save dialog
   does not pre-fill the file name (rfd passes a bare name, which zenity
   ignores; the portal used on GNOME / KDE does pre-fill). How to repeat
   it: TESTING.md. HiDPI too: at `WINIT_X11_SCALE_FACTOR=2` on a
   2560x1600 display the window renders at 2x (crisp text and logo,
   same layout) and clicks land where expected. Not covered: Wayland
   and a desktop portal (they need a desktop session).
5. **Windows run.** `cargo check --target x86_64-pc-windows-msvc` of
   `luksbox-cli` and `luksbox-gui` passes (2026-11-08), and the export
   name rules (`luksbox_core::file_util::windows_name_problem`) are
   unit-tested on every platform. Not done: running on Windows (a WinFsp
   mount, a GUI folder export of a vault holding `12:30.log`, the
   multi-file "+ Add files..." dialog).
6. **TPM hardware build.** `--features hardware` with TPM cannot build
   on this machine (tpm2-tss 4.0.1; the bundled build needs autotools).
   The wizard's reordered hybrid-TPM enroll steps were checked by
   reading only: build and run `cargo test -p luksbox-cli --features
   hardware` on a machine with tpm2-tss, and enroll a hybrid TPM slot
   in the wizard once.
7. **macOS: done on 2026-11-08** (macOS 26.6, Apple M5 Max, FUSE-T
   1.2.9). The FUSE-T mount helper with `--anchor` and `--sync` was
   driven as the GUI drives it (master key on stdin): the anchor moves
   forward while mounted, a rolled-back vault is refused by the CLI and
   by the helper. The test suites, `scripts/cli_scenarios.sh` and
   `scripts/tui_scenarios.sh` (mount steps included) pass on the Mac.
   Found and fixed there (CHANGELOG): `umount` did not wait for the save
   on FUSE-T, every file closed on a FUSE-T mount saved the whole vault,
   the AES suites ran in software on Apple Silicon, the opt-in sandbox
   profile did not parse and had no rule for an anchor, locally built
   binaries did not find libfuse-t, and the scripts needed GNU tools.
   A security review found 2 HIGH, 6 MEDIUM and about 20 LOW / INFO
   issues in the sync, merge, vault I/O, CLI and GUI code, all fixed
   with regression tests (`docs/SECURITY_AUDIT_ROUND_16.md`, "Follow-up
   review on macOS"). Verified after the fixes, on the Mac: workspace
   822 tests, CLI + mount 113, the cross-process FUSE-T mount, GUI 54
   (release and debug), `cargo fmt --check`, clippy with no new
   warning, a Linux `cargo check` of the crates with Linux-only paths,
   `scripts/cli_scenarios.sh` 233 and `scripts/tui_scenarios.sh` 35 under
   the stock bash, and real FUSE-T mounts (umount then use, the GUI
   helper with an anchor, a rolled-back vault refused, two-device
   bundles, the opt-in sandbox). Speeds: `docs/PERFORMANCE.md`, "macOS".
   Secure Enclave keyslots on this Mac's enclave (plain, SEP +
   passphrase, hybrid SEP + ML-KEM-768, a sync bundle unlocked by SEP):
   enrolled and unlocked with `--sep`, refused on a copy without the
   slot. GUI (headless): the Secure Enclave choices greyed out exactly
   when the backend is missing, the bundle revoke warning, and the
   sandboxed FUSE-T helper command run for real (mount, I/O, unmount,
   anchor in another folder; `LUKSBOX_TEST_HELPER=<luksbox>`).
   With the user at the Mac: a Secure Enclave + Touch ID keyslot
   (enrolled, unlocked with `--sep` after Touch ID), and a YubiKey
   (FIDO2 keyslot enrolled; a vault and a sync bundle unlocked, written
   and read with `--fido2`). The GUI on the real display: a window
   (1180x792) up and stable, and its welcome, create, browser and
   keyslot screens rendered through wgpu on the Mac's GPU (egui_kittest
   `wgpu` + `snapshot` enabled temporarily, as in item 4). Removable
   media: vaults (put, get, resize, a FUSE-T mount) and two-device
   bundles on exFAT and FAT32 volumes (disk images), which found that
   bundles could not be kept on exFAT (fixed).
   Not run, and left out of scope by the user: a vault in iCloud Drive
   syncing (it would upload to the user's account), macFUSE (kernel
   extension and reboot), running on Windows (it compiles).

## Test-suite follow-up

8. **Resolved: the GUI scenario's failures in parallel runs and the
   lost clicks on Unlock / Lock** were one GUI bug: a stack of toasts
   covered the top right of the window and took the clicks (fixed; see
   CHANGELOG). The scenario is an ordinary test of the default suite
   again (no child process); 3 consecutive in-process runs passed.

## Smaller ideas noted on the way

- **Per-chunk cost of writes.** A profile of a large `put` on Apple
  Silicon (after hardware AES) puts the OS random-number call for each
  4 KiB chunk's nonce (`getentropy`) about level with the chunk's
  `pwrite`, and above the AES work; a per-thread buffer of OS randomness,
  discarded after a `fork` (the mount daemonizes), would save about a
  quarter of the write time. Nonces need no secrecy, only uniqueness;
  not done in the review because nonce handling is security-critical.
  Reusing the per-chunk plaintext buffer would save the next largest
  cost (allocation + zeroize).
- **Small files through a FUSE-T mount** stay about 5x slower than
  through Linux FUSE (575 vs about 2 800 files/s): each create and close
  is an NFS round trip. Folder `put` / `get` from the CLI does not go
  through the mount.
- **A same-hardware Linux comparison** (an arm64 Linux VM on the Mac,
  e.g. OrbStack) would separate the code from the machine in the
  PERFORMANCE.md tables; the Linux figures there come from a Ryzen in a
  VMware VM.

- `luksbox info` does not show how full the metadata region is (the
  only signal is the 75 % / 90 % warning at save time).
- `put` of a folder into a nearly full region now stops at the first
  entry that does not fit and keeps what was copied; a pre-check of the
  whole folder against the free metadata room would refuse it up front.
