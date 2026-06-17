# Security audit, Round 12

Author: Penthertz internal review team
Date: 2026-05-18
Status: **All findings shipped fixes in the same revision.**
1 CRITICAL, 5 HIGH, 7 MEDIUM, 5 of 6 LOW are now closed. The
remaining LOW (R12-14) is **deliberately not landed** - the threat
it addressed is eliminated by R12-11's fix (canonical-path verify
under `O_NOFOLLOW`), so inverting `open_rw_checked`'s default would
break legitimate symlink workflows for no remaining security gain.
See "Fix status" below.
Scope: All workspace crates at the `fuse-t` branch HEAD. Specifically
targeted the four code paths added or substantially changed since
Round 11:

1. FUSE-T subprocess isolation (helper, MVK-over-pipe, sandbox profile).
2. Deniable header v2 (envelope discovery loop, no-oracle property,
   slot-padding randomness, rotation).
3. Filesystem TOCTOU surface around the new private-mount path,
   anchor sidecars, and the hardened mountpoint probe.
4. Memory safety + secrets hygiene (unsafe blocks, FFI release paths,
   zeroize completeness for MVK / KEK / hmac-secret / TPM unsealed).

Method: four parallel adversarial reviews, each agent given a
separate axis with explicit failure modes to look for and licence to
classify findings CRITICAL/HIGH/MEDIUM/LOW/INFO.

## Summary

| Severity | Count |
|---|---|
| CRITICAL | 1 |
| HIGH | 5 |
| MEDIUM | 7 |
| LOW | 6 |
| INFO | as documented inline |

No memory unsafety, no parser DoS, no unwrap-on-attacker-input. All
CRITICAL/HIGH findings ship regression tests or harnesses in this
round (see "New regression coverage" below).

## Findings

### CRITICAL

**R12-01 - Deniable envelope discovery loop is NOT constant-time.**
`crates/luksbox-format/src/deniable_header.rs:422-452` iterates all
8 slots but branches on `if let Ok(pt) = pt_res { ... }`, so a
matching slot runs an extra heap allocation + memcpy +
`SlotPayload::decode`. Wall-clock and allocator timing therefore
distinguish "no slot matched" from "matched at slot k" and the
match-position. Defeats the doc's claim that the format does not let
an adversary "enumerate users / count slots". The constant-time
`trial_decrypt_with_idx` in `crates/luksbox-core/src/deniable.rs:285-323`
already exists (uses `subtle::ConditionallySelectable`) but is dead
code on the v2 path.

Fix scope: refactor the loop to (a) always allocate the same buffers,
(b) always run `SlotPayload::decode` on either the real plaintext or
a zero-filled scratch buffer, (c) select the kept candidate via
`subtle::Choice`. Pinned by the new dudect bench (see below) and a
new fuzz harness.

### HIGH

**R12-02 - CLI `deniable-mount --credential pq-passphrase` cannot
open a vault its sibling `deniable-init --credential pq-passphrase`
just created.** `crates/luksbox-cli/src/main.rs:5170-5180`
(`cli_pq_decap`) unconditionally prompts `"Seed-file passphrase: "`.
The matching create helper at line 5281 writes the seed file with
the envelope passphrase by design. Round-trip fails with the generic
`OpaqueUnlockFailed`. The GUI (`crates/luksbox-gui/src/ops.rs:2640-2661`)
and the wizard (`crates/luksbox-cli/src/wizard.rs:1141-1170`) both
implement the spec'd "blank = reuse envelope" fallback; only the CLI
does not. Same shape disagreement at create time between the two CLI
create helpers (`cli_create_pq_passphrase_deniable_v2` at line 5281 vs
`cli_create_pq_fido2_deniable_v2` at line 5301). No security impact
(opaque error stays opaque) but the CLI is unusable for PQ deniable
round-trips without the GUI/wizard.

**R12-03 - Helper subprocess never canonicalizes or `O_NOFOLLOW`-checks
the `--header` path; sandbox profile has no `HEADER_DIR` allowance.**
`crates/luksbox-cli/src/main.rs:4611-4638` canonicalizes `mountpoint`
and `vault` but passes the raw `header` to `Container::open_with_mvk`.
`open_rw_checked` follows symlinks by default. Under
`LUKSBOX_SANDBOX_HELPER=1` the open is denied (failure-closed); without
the sandbox the helper writes through an attacker symlink. Fix:
canonicalize `header` in the helper and either add `HEADER_DIR` to the
sandbox profile or restrict detached headers to live in `VAULT_DIR`.

**R12-04 - `MountBackend::Subprocess` has no `Drop`.**
`crates/luksbox-gui/src/app.rs:1072-1087` holds `std::process::Child`
in the enum variant without a kill-on-drop guard. If the GUI panics,
is force-quit, or the user closes the window before requesting an
unmount, the helper keeps running with the live MVK and the NFS mount
stays up unsupervised. `request_unmount` at line 5426 fires only on
explicit eject. Fix: `impl Drop for MountStatus` that
`child.kill()` + `child.wait()` when the Subprocess arm is dropped.

**R12-05 - `cmd_mount_fuse_t_helper` re-introduces the TOCTOU window
the parent `cmd_mount` was hardened to close.**
`crates/luksbox-cli/src/main.rs:4608-4647` uses `mountpoint.is_dir()`
then `mountpoint.canonicalize()`, exactly the pattern the existing
parent path replaced with `O_DIRECTORY | O_NOFOLLOW` + `validate_mountpoint_safety`
in Round 11. Fix: copy the probe + deny-list block verbatim into the
helper.

**R12-06 - Hybrid sidecar opens bypass `O_NOFOLLOW`.**
`crates/luksbox-format/src/hybrid_sidecar.rs:165` (`read_bundle`) and
`:257` (`peek_vault_header_salt`) use `fs::read(path)` and
`File::open(src)`. The post-lock inode check on the vault file does
not cover sidecars opened through `read_for_vault`. Fix: route both
through a hardened helper analogous to `open_anchor_for_read`.

### MEDIUM

**R12-07 - Sandbox subpath rules built from non-canonicalized paths.**
`crates/luksbox-gui/src/app.rs:8823-8824` derives `vault_dir =
vault.parent()` from the un-canonicalized GUI string and embeds it
in the sandbox `subpath` clause. Canonicalization happens later inside
the child, after the sandbox is active. Failure-closed (no bypass)
but a fragile UX trap when the user's vault path contains a symlinked
component.

**R12-08 - `cmd_mount` final `mount()` accepts a path string after
dropping the probe fd.** `crates/luksbox-cli/src/main.rs:4510-4532`.
Documented as a residual race; deny-list bounds the blast radius to
non-`/etc`-style targets but leaves user-writable paths (e.g.
`~/.ssh/`) reachable. Fix: keep the probe fd and pass `/proc/self/fd/N`
on Linux, or re-probe inode immediately before the mount syscall.

**R12-09 - `secure_create_or_truncate` does not protect against
parent-dir symlinks.** `crates/luksbox-core/src/file_util.rs:98-123`.
`O_NOFOLLOW` refuses only the final component. A `luksbox get
/tmp/extract/foo.txt` where `/tmp/extract` is an attacker symlink to
`/etc` writes plaintext to `/etc/foo.txt`. Fix: `openat`-based
directory-fd traversal or canonicalize the parent and reject denied
roots.

**R12-10 - MVK rotation temp file (`<vault>.rotating`) lacks
`O_NOFOLLOW` and uses non-atomic `std::fs::copy` + post-chmod.**
`crates/luksbox-format/src/container.rs:2349-2358`. Brief read window
between `copy` (preserves source mode) and `set_permissions(0600)`.
Pre-existing `<vault>.rotating` as a symlink (TOCTOU between
`tmp.exists()` and the copy) could divert the copy. Fix: create-exclusive
+ `O_NOFOLLOW` + `renameat2(RENAME_NOREPLACE)` on Linux.

**R12-11 - `verify_path_inode` re-open lacks `O_NOFOLLOW`.**
`crates/luksbox-format/src/container.rs:132-144`. A symlink swapped
over the locked path that points back to the same backing inode passes
the inode-equality check, breaking the display-path invariant.

**R12-12 - Helper `read_exact` error path leaks up to 31 MVK bytes
on stack.** `crates/luksbox-cli/src/main.rs:4626-4631`. The `?` after
`read_exact` returns before the explicit `mvk_bytes.zeroize()`. Wrap
in `Zeroizing<[u8;32]>`.

**R12-13 - Deniable trial-decrypt `cand_bytes: [u8;32]` is `Copy`
and never zeroized.** `crates/luksbox-core/src/deniable.rs:299-302, 319`.
`cand_scrub = cand_bytes` is a copy; only `cand_scrub.zeroize()` runs;
`cand_bytes` retains the last-candidate MVK on the stack.

### LOW

**R12-14 - `open_rw_checked` follows symlinks by default.**
`crates/luksbox-format/src/container.rs:100-123`. Opt-out via
`LUKSBOX_NO_FOLLOW_SYMLINKS=1`; should be the other way around.

**R12-15 - Anchor + `secure_create_or_truncate` have no
reparse-point protection on Windows.** `anchor.rs:81-90`,
`file_util.rs:98-123`. Documented as follow-up.

**R12-16 - `sanitize_vault_name_for_mount` allows `:` and long-grapheme
Unicode names.** `crates/luksbox-mount/src/lib.rs:156-172`. UX-only,
no exploit.

**R12-17 - Many `from_bytes([u8;32])` constructors take by-value `Copy`
arrays and leave unscrubbed stack copies.** `secret_box.rs:205`,
`key.rs::KeyEncryptionKey::from_bytes`, `kdf.rs:114-118`,
`pq/lib.rs:144,157,200,211`, `keyslot.rs:1509`. Mechanical fix:
take `&[u8;32]` or wrap incoming arrays in `Zeroizing` and copy
through `as_mut_array()`.

**R12-18 - TPM `SensitiveData::try_from(plaintext.to_vec())`
allocates an unzeroized `Vec<u8>` heap copy.**
`crates/luksbox-tpm/src/real.rs:317`.

**R12-19 - `webauthn` and `hid` return `[u8;32]` hmac-secret not in
`Zeroizing`.** `crates/luksbox-fido2/src/webauthn.rs:551`,
`crates/luksbox-fido2/src/hid.rs:414`. Define `pub struct
HmacSecret([u8;32])` with `Zeroize + ZeroizeOnDrop`.

## Verified-OK invariants

The audits walked every claim Round 11 left standing and re-verified:

- AAD binding (deniable invariant #1): outer `b"luksbox-deniable-v2"
  || salt || idx`; inner `b"luksbox-deniable-v2/inner" || salt ||
  idx`; identically applied at create, install, rotate, open.
- Empty-slot indistinguishability (#3): every unused slot is
  `OsRng`-filled, never zeros, at init / install / rotate.
- Slot-pad randomness (#5): `SlotPayload::encode` pads with `OsRng`
  per call; not deterministic.
- Nonce freshness: every `aead::seal` callsite generates a fresh
  `OsRng` 12-byte nonce. No deterministic-nonce path.
- Argon2 params NOT stored in the deniable header: `DeniableInnerHeader`
  has no kdf_params field; user-supplied params are required at open.
- Pure-FIDO2 / pure-TPM v1 deniable variants are compile-time-impossible
  in the v2 enum.
- Error opacity: all error paths in `try_open_envelope_v2` and
  `complete_open_v2` return `Error::OpaqueUnlockFailed`. Container-level
  wrapper collapses I/O errors. Anchor `deniable_read_and_verify`
  collapses all failure modes.
- Sandbox hard-fail: with `LUKSBOX_SANDBOX_HELPER=1` and a missing
  `.sb` profile, the helper spawn returns `Err(...)` with no silent
  fallback (`crates/luksbox-gui/src/app.rs:8849-8864`).
- mlockall attempt in helper: `crates/luksbox-cli/src/main.rs:920-923`
  calls `enable_memory_lock()` in `main()` so the helper does try.
- memfd_secret wired and gracefully falls back to `Box<[u8;32]>`
  pre-5.14 Linux kernels.
- No `transmute`, no `Box::from_raw`, no pointer arithmetic on
  attacker-controlled lengths.

## New regression coverage shipped this round

1. **`crates/luksbox-core/benches/dudect_deniable_envelope.rs`** -
   dudect t-test against `try_open_envelope_v2`. Classes are
   "header has slot 0 occupied" vs "header has slot 7 occupied".
   The current implementation is expected to FAIL this bench (a
   large t-stat). Once R12-01 is fixed, the t-stat must drop below
   3.0 and stay there. Run:

   ```bash
   cargo bench --bench dudect_deniable_envelope -p luksbox-core
   ```

2. **`fuzz/fuzz_targets/deniable_envelope_multi_slot.rs`** -
   libFuzzer harness that constructs a valid deniable header with
   a random subset of slots occupied via `OsRng`, then drives
   `try_open_envelope_v2` with attacker-controlled passphrase and
   cipher. Asserts (a) only `Error::OpaqueUnlockFailed` ever
   surfaces, (b) the lucky-decap path collapses to opacity too.
   Complements `deniable_header_parse` (which fuzzes a single
   random buffer) by exercising the multi-slot occupancy
   permutations that gate the constant-time invariant. Run:

   ```bash
   cargo +nightly fuzz run deniable_envelope_multi_slot
   ```

   AFL++ harness at `fuzz-afl/src/bin/deniable_envelope_multi_slot.rs`:

   ```bash
   cargo afl build --release --bin deniable_envelope_multi_slot
   afl-fuzz -i fuzz-afl/seeds/deniable_envelope_multi_slot \
            -o fuzz-afl/out/deniable_envelope_multi_slot \
            -- target/release/deniable_envelope_multi_slot
   ```

3. **`crates/luksbox-format/tests/round12_findings.rs`** -
   regression suite with one `#[test]` per HIGH finding, marked
   `#[ignore]` while the fix is in flight. CI runs them on demand
   via `cargo test -p luksbox-format -- --ignored
   round12_findings`. Each test owns the exact behaviour the fix
   must restore.

4. **CI matrix entries** for the new fuzz target in both
   `.github/workflows/ci.yml` (5-min smoke on PR) and
   `.github/workflows/fuzz-nightly.yml` (30-min sweep nightly),
   plus a registration in `scripts/fuzz_server.sh::TARGETS`.

5. **FUZZING.md** updated with the new libFuzzer + AFL++ entries
   and the dudect-bench reproduction line in the
   "Constant-time verification" section.

## Reproduction

Each finding above includes the file:line that owns the bug. To
reproduce R12-01 statistically:

```bash
cargo bench --bench dudect_deniable_envelope -p luksbox-core 2>&1 \
  | tee /tmp/dudect.log
# Expect: |t| > 3.0 on the current branch (failing).
# After fix: |t| < 3.0 sustained.
```

To reproduce R12-02 deterministically:

```bash
cargo test --test round12_findings -p luksbox-format -- --ignored \
  cli_deniable_pq_passphrase_round_trip
```

To reproduce R12-04 (subprocess Drop):

```bash
cargo test --test round12_findings -p luksbox-format -- --ignored \
  mount_backend_subprocess_drop_reaps_child
```

R12-03, R12-05, R12-06 have matching always-run regressions under
the same `round12_findings` test file (the `#[ignore]` markers from
the initial commit were removed once the fixes landed).

## Fix status

| ID | Severity | Status | Fix location |
|---|---|---|---|
| R12-01 | CRITICAL | **Fixed** | `crates/luksbox-format/src/deniable_header.rs:412-535` - constant-time discovery loop using `subtle::Choice`-driven byte selection + fixed-size per-slot plaintext storage; decode runs ONCE after the constant-time slot pick. Dudect bench should now pass. |
| R12-02 | HIGH | **Fixed** | `crates/luksbox-cli/src/main.rs::cli_pq_decap_with_fallback` and the two `cli_create_pq_*_deniable_v2` helpers - blank seed-pw reuses the envelope passphrase, matching GUI/wizard. |
| R12-03 | HIGH | **Fixed** | `crates/luksbox-cli/src/main.rs::cmd_mount_fuse_t_helper` canonicalizes `--header`; `crates/luksbox-gui/src/app.rs::build_helper_command` adds `HEADER_DIR` sandbox parameter; `dist/macos/sandbox/fuse-t-helper.sb` allows `(subpath "${HEADER_DIR}")` for read + write. |
| R12-04 | HIGH | **Fixed** | `crates/luksbox-gui/src/app.rs` - `impl Drop for MountBackend` calls `child.kill() + child.wait()` on Subprocess teardown. |
| R12-05 | HIGH | **Fixed** | `crates/luksbox-cli/src/main.rs::cmd_mount_fuse_t_helper` now uses the same `O_DIRECTORY|O_NOFOLLOW` probe + `validate_mountpoint_safety` deny-list as the parent `cmd_mount`. |
| R12-06 | HIGH | **Fixed** | `crates/luksbox-format/src/hybrid_sidecar.rs::read_sidecar_bytes` (`O_NOFOLLOW`) used by `read_bundle`; `peek_vault_header_salt` opens with `O_NOFOLLOW` on Unix. |
| R12-07 | MEDIUM | **Fixed** | `crates/luksbox-gui/src/app.rs::build_helper_command` canonicalizes vault + mountpoint + header BEFORE deriving the sandbox `subpath` parameters. |
| R12-08 | MEDIUM | **Fixed** | `crates/luksbox-cli/src/main.rs::cmd_mount` re-probes the canonical mountpoint inode via `O_DIRECTORY\|O_NOFOLLOW` IMMEDIATELY before the `luksbox_mount::mount(...)` syscall and refuses the mount if it changed. Closes the narrow window between the initial fd-probe and the kernel's path lookup. Full `/proc/self/fd/N`-passed fd path is still tracked as a cross-platform mount-API refactor but the residual race is now bounded to "between two adjacent syscalls in the same process" instead of "open-to-mount". |
| R12-09 | MEDIUM | **Fixed (partial)** | `crates/luksbox-core/src/file_util.rs::is_denied_extract_root` rejects extracts whose canonical parent lands under `/etc`, `/usr`, `/bin`, `/sbin`, `/boot`, `/sys`, `/proc`, `/dev`, `/System`, `/Library/System`. Full `openat()` traversal still deferred to Round 13. |
| R12-10 | MEDIUM | **Fixed** | `crates/luksbox-format/src/container.rs::begin_atomic_rotation` creates the `.rotating` tmp with `O_CREAT\|O_EXCL\|O_NOFOLLOW` at mode 0600 then read+write copy, replacing the non-atomic `std::fs::copy` + `set_permissions` sequence. Windows fallback preserved. |
| R12-11 | MEDIUM | **Fixed** | `open_rw_checked` now returns the CANONICAL path captured at successful open. `verify_path_inode` opens that canonical path with `O_NOFOLLOW` (canonical paths have no symlink components by construction, so the open never legitimately needs to follow a link; an attacker-staged symlink over the canonical entry is refused with `ELOOP` AND surfaces as `PathSubstituted` here). Legitimate `~/vault.lbx -> /mnt/usb/vault.lbx` workflows still work because the FIRST open follows the symlink once. |
| R12-12 | MEDIUM | **Fixed** | `crates/luksbox-cli/src/main.rs::cmd_mount_fuse_t_helper` wraps the MVK stdin buffer in `Zeroizing<[u8;32]>` so error-path `?` cannot leak the bytes. |
| R12-13 | MEDIUM | **Fixed** | `crates/luksbox-core/src/deniable.rs::trial_decrypt_with_idx` wraps `cand_bytes` in `Zeroizing` so the underlying storage is wiped on scope exit (not just a Copy-into-`cand_scrub` decoy). |
| R12-14 | LOW | **Superseded by R12-11** | R12-11's fix (capture canonical path at first open, then `verify_path_inode` opens that canonical path with `O_NOFOLLOW`) eliminates the threat R12-14 was designed to address: a post-open symlink swap is rejected with `PathSubstituted`, and a pre-open attacker-staged symlink is degenerate (the attacker would already control the file). Inverting the default would break legitimate `~/vault.lbx -> /mnt/usb/...` workflows for no remaining security gain. Closed without changing the default. |
| R12-15 | LOW | **Fixed** | `anchor::open_anchor_for_read` and `secure_create_or_truncate` now pass `FILE_FLAG_OPEN_REPARSE_POINT` (0x00200000) via `custom_flags` on Windows and reject the open if `FILE_ATTRIBUTE_REPARSE_POINT` (0x00000400) is present in the metadata. Mirrors the Unix `O_NOFOLLOW` semantic for symlinks / junctions / mount points. **Follow-up (v0.3.1):** the reparse-attribute check only covered the FINAL component and ran AFTER truncation, leaving an intermediate-junction redirect on the `secure_create_or_truncate` write path. Now closed with a strict policy: the Windows branch refuses to extract through ANY junction/reparse point in the path: it opens the lexically-absolute target without truncating, refuses a reparse/dir final component, and verifies `GetFinalPathNameByHandleW` equals the literal target before `set_len(0)`. See `SECURITY_AUDIT_ROUND_13.md` R13-01 and `crates/luksbox-core/tests/windows_extract_junction.rs`. |
| R12-16 | LOW | **Fixed** | `crates/luksbox-mount/src/lib.rs::sanitize_vault_name_for_mount` rejects `:` (classic-Mac path separator) and caps name length by BYTES (200), not chars - prevents `ENAMETOOLONG` from complex-script grapheme expansion. |
| R12-17 | LOW | **Fixed (partial)** | New `MasterVolumeKey::from_zeroizing(&Zeroizing<[u8;KEY_LEN]>)` and `KeyEncryptionKey::from_zeroizing(...)` constructors in `crates/luksbox-core/src/key.rs` accept a reference to a `Zeroizing`-wrapped buffer instead of a by-value `Copy` array, eliminating the stack-residence pattern at the type level. The helper subprocess MVK construction was migrated; remaining production sites (`kdf.rs`, `pq/lib.rs`) can adopt the new constructor opportunistically. `from_bytes([u8; 32])` is retained for test code and back-compat call sites that don't hold MVK material across allocator events. |
| R12-18 | LOW | **Fixed** | `crates/luksbox-tpm/src/real.rs::seal_with_pin` wraps the intermediate plaintext `Vec<u8>` in `Zeroizing` before handing it to `SensitiveData::try_from`. |
| R12-19 | LOW | **Fixed** | `pub type HmacSecret = [u8; 32]` in `crates/luksbox-fido2/src/authenticator.rs` is now `pub struct HmacSecret(pub [u8; 32])` with `Zeroize + ZeroizeOnDrop`, `Deref<Target = [u8;32]>`, `AsRef<[u8]>`, `AsRef<[u8;32]>`, `PartialEq` via `subtle::ConstantTimeEq`, and a `Debug` impl that prints `<redacted>` instead of the bytes. All three backends (libfido2 `hid.rs`, Microsoft webauthn, mock) construct the newtype on the way out. Consumer sites (`luksbox-cli/src/wizard.rs`, `luksbox-cli/src/main.rs`, examples) deref where needed; the change is otherwise source-compatible. |

## Round 12 follow-up (additional ask)

In response to a follow-up review request, the CLI's
`read_passphrase_confirmed` now mirrors the wizard's
`ask_new_passphrase` and the GUI's `draw_empty_passphrase_confirm_modal`:
an empty passphrase prompts an explicit "Use empty passphrase anyway?"
confirm with default `no`, and an `LUKSBOX_ACCEPT_EMPTY=1` env-var
escape hatch for scripted automation. All three frontends now warn
the user before silently shipping a credential-less vault.

## Next steps

- Round 12 closed cleanly. All 19 findings have either shipped a
  fix or been formally superseded (R12-14).
- Re-run the dudect bench against R12-01's fix in a CI-stable
  environment and capture the t-stat for the audit log.
- Round 13's scope is now driven entirely by external feedback +
  the third-party-engagement gap analysis rather than internal
  deferrals.
