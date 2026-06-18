# Security audit, Round 14

Author: Penthertz internal review team
Date: 2026-06-18
Status: **1 HIGH, 2 MEDIUM, 3 LOW found and fixed in the same revision.
No cryptographic break in the stolen-vault / no-unlock-factor model; all
six are local TOCTOU / path-confusion gaps in the CLI/GUI
destructive/mount/extract paths, not in the SEP crypto.**

Scope: focused review of the macOS Secure Enclave (SEP) keyslot work
landed on the `v0.4.0-macos` branch (commits `ef2d203` "Implementing
SEP for Apple Silicon" and `08cd000` "Fixing GUI for SEP"). New and
modified surfaces:

1. New crate `luksbox-sep` (`src/{lib,real,mock}.rs`, `build.rs`,
   `swift/SepShim.swift`): the CryptoKit seal/unseal primitive and its
   FFI boundary.
2. In-header SEP region parse/serialize in
   `crates/luksbox-core/src/header.rs` (the `FLAG_HAS_SEP_REGION`
   table that lives in the formerly-RNG padding between the keyslot
   array and the header HMAC).
3. New `SlotKind` variants (discriminants 15 through 27) and the
   SEP KEK/AAD logic in `crates/luksbox-core/src/keyslot.rs`.
4. SEP enroll/unlock dispatch in
   `crates/luksbox-format/src/container.rs`.
5. CLI/TUI/GUI SEP flows in `crates/luksbox-cli/src/{main,wizard}.rs`
   and `crates/luksbox-gui/src/{app,ops}.rs`.

Method: read the SEP region on-disk format and the
parse/serialize/enroll/unlock data flow, then trace every
attacker-controllable input (a stolen or tampered `.lbx`, a foreign
machine, the C ABI return values from the Swift shim) to the
sensitive operations (KEK derivation, MVK unwrap, header HMAC
verification). Each SEP surface was compared against the existing
TPM/FIDO2 keyslot handling for security-relevant deviations, with
explicit attention to the anti-patterns the keyslot/header layer
historically produces: parsing on unauthenticated bytes, AAD-coverage
drift between `to_bytes` and `build_aead_aad`, blob/slot substitution,
and unchecked length fields across the FFI boundary.

## Summary

| Severity | Count |
|---|---|
| CRITICAL | 0 |
| HIGH | 1 |
| MEDIUM | 2 |
| LOW | 3 |
| INFO | 0 |

R14-02 and R14-03 came from an internal follow-up sweep of the CLI
destructive and mount paths during the same review cycle.

R14-04, R14-05, and R14-06 were reported via coordinated disclosure
(`security@penthertz.com`) by **Garry Jean-Baptiste** (garry@reyse.ai),
who found them with LLM-assisted white-box source review against
`ef690a8`. R14-04 (F1) is the precise pattern the Round-13 fix R13-02
closed, surviving in the rotation-abort sibling the single R13 sweep did
not enumerate; R14-05/06 (F2/F3) are Windows-only GUI-extract
name-confusion issues.

All six are pre-existing local-attacker TOCTOU / path-confusion gaps
(not introduced by the SEP work), recorded here because they were found
and fixed in the v0.4.0-rc.1 revision.

No memory unsafety. No parser DoS or unwrap-on-attacker-input in the
SEP region reader. No wrong-but-accepted KEK/MVK path. No
cross-slot or cross-vault blob-substitution break.

## Findings

### HIGH

**R14-02: the TUI wizard's panic/destroy action followed symlinks on its
destructive opens.** `crates/luksbox-cli/src/wizard.rs::panic_action`
dropped the `Container`, prompted the user, then opened the header and
(on data wipe) the vault with raw
`OpenOptions::new().write(true).open(...)`. Those opens follow symlinks
and ran AFTER an interactive delay. A local attacker with write access
to the parent directory could swap the path for a symlink during the
prompt and redirect the random-bytes overwrite to another file the
caller can write; severe if LUKSbox runs elevated (an
arbitrary-overwrite primitive). The standalone `cmd_panic` (main.rs) and
the wizard's own `panic_by_path` already had the hardened pattern;
`panic_action` was the straggler, despite its doc claiming the "same
shred procedure".

Fix (shipped this revision): open both targets up front with
`secure_open_existing_no_follow` (O_NOFOLLOW + regular-file check on
Unix, reparse-point refusal on Windows) and hold the handles across the
confirmation prompt, writing through the pinned inodes. Inline-header
vaults wipe through the single header handle; detached vaults open a
second no-follow handle to the vault file. Now identical to
`panic_by_path`.

### MEDIUM

**R14-03: deniable-mount never performed the final mountpoint inode
re-probe its own comment promised.**
`crates/luksbox-cli/src/main.rs::cmd_deniable_mount` opened the
mountpoint with `O_DIRECTORY | O_NOFOLLOW` and its comment said a
"post-open inode re-probe" guarded the residual race, but the probe fd
and its inode were dropped, and the later `luksbox_mount::mount` call ran
without re-checking. The normal `cmd_mount` path does the R12-08
`O_DIRECTORY | O_NOFOLLOW` re-probe immediately before mount;
deniable-mount did not. The lower-level FUSE preflight uses path-based
`std::fs::metadata` (which follows symlinks), so the fd-based re-check
was the only failure-closed guard and it was absent. A local attacker
who controls the mountpoint's parent directory could race a replacement
of the canonical entry between validation and the kernel's mount-path
lookup. Blast radius is bounded by `validate_mountpoint_safety` (no
/etc, /usr, /Library, etc.).

Fix (shipped this revision): capture the probed `(dev, ino)` and add the
same R12-08 final re-probe immediately before the mount syscall,
refusing the mount if the inode changed. Brings deniable-mount to parity
with `cmd_mount`.

**R14-04 (external, F1): rotation abort reopened the vault path without
O_NOFOLLOW / inode-recheck (completes R13-02).**
`crates/luksbox-format/src/container.rs::abort_atomic_rotation` reopened
`committed_data_path` with a bare
`OpenOptions::new().read().write().open(...)` and assigned it to
`self.file`; `Container::drop` then calls `persist_header`, writing
HEADER_SIZE bytes (8 KiB, 36 KiB deniable) at offset 0.
`begin_atomic_rotation` releases the original flock (it swaps `self.file`
to the temp), so during the rotation window a directory-level attacker
can swap the vault path for a symlink and the abort/Drop write lands on
the symlink target: an 8 KiB overwrite of an attacker-chosen file the
process can write (severe under an elevated run). Both `rotate_mvk` and
`rotate_mvk_deniable` funnel their abort through this one function, so a
single site is affected (the report listed two; current code shares one).

This is the exact pattern R13-02 removed from `restore_header_bytes`,
surviving in the rotation-abort sibling. The correct helper
`reopen_committed_no_follow` (O_NOFOLLOW + inode-equality ->
`PathSubstituted`) already existed and was used at the R13-02 sites.

Reachability is narrow: the Drop write only fires when `header_dirty ==
true` at abort, set only at the last line of `install_rotated_mvk_multi`
and cleared by `persist_header` on success. Because the chunk rekey is
in-place, realistic failures (ENOSPC) land in the bulk phase before
install, where the Drop write is a no-op. The window is a failure in the
final `persist_header` step, which an unprivileged attacker cannot
reliably induce, hence defense-in-depth / Low-Medium, not a turnkey
primitive.

Fix (shipped this revision): `RotationState` now captures the committed
vault's `(dev, ino)` from the held handle at `begin_atomic_rotation` (via
a new `LbxFile::inode_pair`), and `abort_atomic_rotation` routes its
reopen through `reopen_committed_no_follow` bound to that inode. A
swapped path fails closed with `PathSubstituted` and the header write
never reaches a foreign file. Pinned by
`abort_atomic_rotation_refuses_symlinked_path`.

### LOW

**R14-01: SEP+FIDO2 `fido2_hmac_salt` is persisted but omitted from
the AEAD AAD (the `to_bytes` / `build_aead_aad` salt lists drifted).**
`crates/luksbox-core/src/keyslot.rs`. When the SEP+FIDO2 kinds were
added, `to_bytes` (the salt_len `matches!` at lines ~2112 to 2126) was
extended with a trailing `|| self.kind.is_sep_fido2()`, so it writes
the 32-byte `fido2_hmac_salt` at slot offset 480..512 for those kinds.
The mirror condition in `build_aead_aad` (the salt_len `matches!` at
lines ~2022 to 2035) was NOT extended, so it computes `salt_len = 0`
and leaves that 32-byte AAD region zeroed. For every `is_sep_fido2()`
kind (`SepFido2` = 19, `HybridPqKemSepFido2` = 20,
`HybridPqKem1024SepFido2` = 21, `SepFido2Passphrase` = 25,
`HybridPqKemSepFido2Passphrase` = 26,
`HybridPqKem1024SepFido2Passphrase` = 27) the salt is therefore
written to disk but never bound into the per-slot AEAD tag. This
violates the explicit in-code invariant (the "these two lists MUST
mirror each other" comment at lines ~2010 to 2021) and repeats the
prior TPM+FIDO2 miss noted as "restored 2026-05".

Why LOW (not a reportable bypass):

- The per-slot AEAD is keyed by the KEK, not the MVK, and it fails
  closed. A mutated salt makes the authenticator return a different
  `hmac_secret`, deriving a different KEK, so `aead::open` returns
  `Error::KeyslotAuthFailed`. AES-256-GCM-SIV / AES-GCM /
  ChaCha20-Poly1305 cannot yield a wrong-but-accepted MVK from a wrong
  KEK, so there is no auth bypass or key recovery, only unlock
  failure.
- The salt is still fully covered by the header HMAC:
  `compute_hmac(mac_key, &buf[..OFF_HMAC])` (`header.rs:309` on write,
  `header.rs:464` on verify) spans the entire keyslot array, including
  offset 480..512, which sits below `OFF_HMAC` (the compile-time
  assertion at `header.rs:135`). `mac_key` is an MVK-derived subkey,
  so an outsider cannot mutate the salt undetected without already
  holding the MVK.
- Net reachable impact: a targeted slot lockout (denial of service)
  that additionally presupposes defeating the MVK-keyed header HMAC,
  i.e. presupposes already holding the MVK. There is no concrete
  attack path to unauthorized unlock, key recovery, or data
  disclosure.

It remains a genuine correctness and defense-in-depth defect: the
AEAD layer no longer redundantly binds the salt, and the documented
"MUST mirror" invariant is broken. Fix it for robustness and to keep
the SEP+FIDO2 kinds at parity with the TPM+FIDO2 kinds.

Fix (shipped this revision): introduced a single
`SlotKind::has_inline_hmac_salt()` source of truth and routed all
three sites (`build_aead_aad`, `to_bytes`, and the `from_bytes`
parser) through it, so the salt-bearing set can no longer be encoded
independently at any call site and cannot drift again on a future
keyslot-kind addition. The previous hand-maintained `matches!` lists
are gone.

**R14-05 (external, F2): GUI bulk-extract top-level join skipped the
directory-escape guard (Windows).** `crates/luksbox-gui/src/app.rs::
start_get_dir` computed `parent_dir.join(name)` from a vault-supplied
entry name without calling `name_escapes_directory`. That guard is
applied to child entries inside `get_dir_recursive` but not to the
top-level name, so on Windows a forged entry named e.g. `C:evil`
(drive-letter, which `Path::join` treats as an absolute reset) extracted
outside the chosen folder. POSIX is unaffected. Fix: apply
`name_escapes_directory` (now `pub(crate)`) to the top-level name in
`start_get_dir` and refuse on match.

**R14-06 (external, F3): `:` in a vault entry name allowed a Windows
alternate-data-stream write.** A POSIX-legal name such as
`malware.exe:Zone.Identifier` passed `validate_name` (which rejects
`/ \ NUL . ..` but not `:`) and, on Windows extraction, would target the
ADS of `malware.exe`. We deliberately did NOT add a `:` rejection to
`validate_name`: it runs at metadata-load time (`vfs.rs:892`), so a
blanket reject would make existing POSIX vaults that legitimately contain
`:` in a filename fail to load (a compat break / availability bug). The
report suggested the `validate_name` route; the compat-safe fix instead
extends the already-Windows-gated `name_escapes_directory` to reject any
`:` on Windows (subsuming the drive-letter case), so POSIX vaults keep
loading and extracting `:`-names while Windows extraction refuses ADS.

## New regression coverage

| Finding | Test |
|---|---|
| R14-01 | `crates/luksbox-core/src/keyslot.rs::tests::aad_covers_hmac_salt_for_every_salt_bearing_kind` -- builds a slot with a known 32-byte salt for every salt-bearing kind (the 7 FIDO2/TPM+FIDO2 kinds plus the 6 SEP+FIDO2 kinds) and asserts the salt appears in BOTH the `to_bytes` output AND the `build_aead_aad` output. Fails on any future `salt_len` drift. |
| R14-02 | No new dedicated test (the destructive prompt path is interactive and hard to drive deterministically). The fix makes `panic_action` byte-for-byte match the already-reviewed `panic_by_path` shred path. Follow-up recommended: a symlink-at-target refusal test. |
| R14-03 | Covered by the existing `crates/luksbox-cli/tests/mount_safety.rs` mountpoint-hardening suite, which now exercises the deniable path's re-probe by parity with `cmd_mount`. |
| R14-04 | `crates/luksbox-format/src/container.rs::tests::abort_atomic_rotation_refuses_symlinked_path` -- creates a real vault, `begin_atomic_rotation`, swaps the committed path for a symlink to a victim file, asserts `abort_atomic_rotation` returns `PathSubstituted` and that Drop leaves the victim byte-unchanged. |
| R14-05 / R14-06 | `crates/luksbox-gui/src/ops.rs` `name_escapes_directory_tests`: `windows_ads_colon_is_rejected` (Windows ADS `:` refused), `windows_drive_letter_prefix_is_rejected` (still passes), and `posix_colon_name_is_allowed` (POSIX `:` names still accepted, pinning the compat boundary). |

Verified: `cargo test -p luksbox-core --lib` -> 111 passed, 0 failed.
`cargo test -p luksbox-format --lib` -> 109 passed (incl. R14-04 + the
`LbxFile::inode_pair` trait change across the sim backends).
`cargo build -p luksbox-cli` -> clean. `cargo build -p luksbox-gui` ->
clean; `name_escapes_directory_tests` pass. `cargo test -p luksbox-cli`
(incl. `mount_safety.rs`, `functional.rs`) -> all passed.

## Surfaces reviewed and found sound

Recorded as ground truth so the next round does not re-derive these.

- **SEP region parsing on unauthenticated bytes**
  (`header.rs::parse_sep_region`). Runs before HMAC verification by
  design (the region must be parsed to reconstruct the header), but is
  fully bounds-checked: `count > MAX_KEYSLOTS` rejected; every read
  guarded by `p + 3 > region.len()` and `p + blob_len > region.len()`;
  `slot_idx >= MAX_KEYSLOTS` rejected; duplicate `slot_idx` rejected.
  No integer overflow (`blob_len` is a `u16` <= 0xFFFF, region is
  ~3968 B, usize math on 64-bit). No unwrap/panic on malformed input.
  `region[0]` cannot panic: `OFF_SEP_REGION < OFF_HMAC` is a
  compile-time invariant.
- **Blob swap / cross-slot / cross-vault substitution.** A SEP slot's
  MVK is wrapped under a KEK derived from that slot's ECDH agreement
  (the enclave output for that specific blob). Swapping blobs between
  slots or vaults yields a different KEK, so the AEAD unwrap fails.
  The whole keyslot array plus SEP region is additionally under the
  MVK-keyed header HMAC, so any swap also fails `verify_hmac`.
- **KEK derivation** (`derive_sep_kek`). HKDF-SHA256 salted with
  `header_salt` (binds the KEK to the vault), domain-separated
  `info = "lbx:sep-kek/v1"`, canonical IKM ordering keyed off the
  slot kind so enroll and unlock reconstruct identical input. Fresh
  ephemeral key per seal. All-zero ECDH result and all-zero factors
  rejected at the source and at both enroll and unlock.
- **FFI boundary** (`luksbox-sep/src/real.rs`, `swift/SepShim.swift`).
  Caller-allocated fixed buffers; the shim writes fixed 32/65-byte
  outputs and bounds `sep_data` against `outSepDataCap`, returning
  `ERR_BUFFER` on overflow. Rust re-validates `sep_data_len` before
  `truncate`; `SepBlob::from_bytes` validates the length prefix
  against the buffer. No untrusted length field is used unchecked.
- **`swap_slots` / `revoke_slot`** move and clear `sep_blobs`
  alongside `keyslots`, clearing `FLAG_HAS_SEP_REGION` once no slot
  carries SEP material.
- **Unlock dispatcher** (`container.rs`, `UnlockMaterial::Sep`). Fails
  closed (`Err` when no slot matches), tolerates only per-slot closure
  errors (the foreign-enclave skip), and gates each candidate slot on
  an exact factor-presence match (`check_sep_factors`).

## Fuzz coverage added

Two harnesses now exercise the new SEP parsing surface in both the
libFuzzer (`fuzz/`) and AFL++ (`fuzz-afl/`) setups, plus a `seed_sep`
corpus entry that warms the region path in the existing `header_parse`
and `header_roundtrip` targets (the `FLAG_HAS_SEP_REGION` bit is almost
never set by blind mutation, so without a seed the region parser stays
cold):

- `sep_blob_parse`: arbitrary bytes through `SepBlob::from_bytes` (the
  per-blob `[flags][sep_data_len][sep_data][eph_pub]` decoder read off
  disk and across the CryptoKit FFI return). Smoke run: 11.0 M execs,
  no crash.
- `sep_region_parse`: the in-header region `[count][slot_idx][blob_len]`
  table serialize/parse driven with fuzzer-controlled indices, counts,
  and lengths via the public `Header` API; asserts no panic, re-parse
  success, and byte-identical blob round-trip. Smoke run: 60 K execs,
  cov 918, no crash; the round-trip and re-parse oracles held.

Both build under `cargo +nightly fuzz build` with ASan on Linux (the SEP
parser types are not cfg-gated to macOS) and have AFL++ mirrors in
`fuzz-afl/src/bin/`. They should join the nightly fuzz rotation.

## Fix status

| ID | Severity | Status | Location |
|---|---|---|---|
| R14-01 | LOW | **Fixed** | `crates/luksbox-core/src/keyslot.rs`: new `SlotKind::has_inline_hmac_salt()` is the single source of truth; `build_aead_aad`, `to_bytes`, and the `from_bytes` parser all delegate to it (the hand-maintained `matches!` lists removed). Pinned by `tests::aad_covers_hmac_salt_for_every_salt_bearing_kind`. |
| R14-02 | HIGH | **Fixed** | `crates/luksbox-cli/src/wizard.rs::panic_action`: opens both destructive targets with `secure_open_existing_no_follow` up front and holds the handles across the confirmation prompt, writing through the pinned inodes. Now matches `cmd_panic` / `panic_by_path`. |
| R14-03 | MEDIUM | **Fixed** | `crates/luksbox-cli/src/main.rs::cmd_deniable_mount`: captures the probed `(dev, ino)` and re-probes with `O_DIRECTORY \| O_NOFOLLOW` immediately before `luksbox_mount::mount`, refusing on inode change. R12-08 parity with `cmd_mount`. |
| R14-04 | MEDIUM | **Fixed** | `crates/luksbox-format/src/container.rs`: `RotationState` captures the committed `(dev,ino)` at `begin_atomic_rotation` (new `LbxFile::inode_pair`); `abort_atomic_rotation` reopens via `reopen_committed_no_follow` bound to it. Pinned by `abort_atomic_rotation_refuses_symlinked_path`. Credit: Garry Jean-Baptiste (garry@reyse.ai). |
| R14-05 | LOW | **Fixed** | `crates/luksbox-gui/src/app.rs::start_get_dir`: applies `name_escapes_directory` (now `pub(crate)`) to the top-level vault name before the join. Credit: Garry Jean-Baptiste (garry@reyse.ai). |
| R14-06 | LOW | **Fixed** | `crates/luksbox-gui/src/ops.rs::name_escapes_directory`: rejects any `:` on Windows (ADS + drive-letter). `validate_name` deliberately left unchanged to preserve load of POSIX vaults containing `:`. Credit: Garry Jean-Baptiste (garry@reyse.ai). |

## Next steps

- R14-01 fixed and tested this revision; SEP+FIDO2 kinds are now at
  AAD-coverage parity with the TPM+FIDO2 kinds, and the parity is
  pinned so it cannot silently regress on a future keyslot-kind add.
  Safe to carry into the `v0.4.0-rc.1` pre-release and the v0.4.0
  final tag.
- R14-02 / R14-03 fixed this revision; the CLI destructive-write and
  mount paths now consistently use no-follow opens and pre-mount inode
  re-probes. Follow-up: add a deterministic symlink-at-target refusal
  test for `panic_action` (the interactive prompt makes it awkward to
  drive; a small refactor to a testable inner helper would let it share
  a fixture with `panic_by_path`).
- Reconfirm the deferred SEP items tracked in
  `docs/SEP_KEYSLOT_DESIGN.md` section 10 (reboot survival, biometric
  phase 2) before promoting any SEP kind out of pre-release.
