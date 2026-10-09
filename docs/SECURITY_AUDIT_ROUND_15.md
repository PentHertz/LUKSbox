# Security audit, Round 15

Author: Penthertz internal review team
Baseline: `f64ecc6` (v0.5.2)
Date: 2026-10-09
Status: **5 HIGH, 14 MEDIUM, 29 LOW found. 43 fixed in this revision; 6
accepted / documented (listed at the end with the reason). No break of
the stolen-vault / no-unlock-factor model: an attacker holding only the
`.lbx` still cannot decrypt anything. The HIGHs are data-loss and
supply-chain defects, not cryptographic ones.**

Scope: everything. `luksbox-core` (keyslot, header, KDF, AEAD, deniable
envelope, secret memory, file helpers), `luksbox-format` (container,
metadata, anchor, hybrid sidecar, deniable header), `luksbox-vfs`,
`luksbox-pq`, `luksbox-fido2`, `luksbox-tpm`, `luksbox-sep` (+ Swift
shim), `luksbox-mount` + `luksbox-fuse-t`, the CLI/TUI, the GUI, every
`build.rs`, every script under `scripts/` and `dist/`, the three GitHub
workflows and both composite actions, `Cargo.toml` / `Cargo.lock` /
`.cargo/config.toml`.

Method: white-box source review, one surface at a time, reading each
crate end to end and tracing attacker-controlled input (tampered vault
files, hostile metadata trees authored by a former MVK holder, rogue
authenticators, local co-users, CI inputs) to the sensitive sinks.
Every finding below was verified against the code before a fix was
written; the ones marked *reproduced* were demonstrated with a scratch
program against the real crates. Each fix carries an `R15-...` marker
in the code.

## Summary

| Severity | Found | Fixed | Accepted / documented |
|---|---|---|---|
| CRITICAL | 0 | 0 | 0 |
| HIGH | 5 | 5 | 0 |
| MEDIUM | 14 | 12 | 2 |
| LOW | 29 | 26 | 3 |
| INFO | 1 | 0 | 1 |

## HIGH

**R15-C1: an aborted MVK rotation bricked the vault on `Drop`**
(*reproduced*). `Container::abort_atomic_rotation` restored the file
handle but not the in-memory `header` / `mvk` / deniable envelope
bytes that `rekey_metadata`, `install_rotated_mvk_multi` and the
deniable envelope rotation had already switched to the NEW MVK, and it
left `header_dirty` set. `Container::drop` then ran `persist_header`
and wrote the never-committed header (slots wrapping the new MVK) over
the original vault, whose metadata and chunks were still under the old
MVK. The vault opened with the passphrase and failed every AEAD after
that; the `.meta-bak` mirror could not help (it is under the old MVK
that no slot wraps any more). Deniable vaults hit this on ANY failure
after step 4 of `Vfs::rotate_mvk_deniable` (a single bit-rotted chunk
was enough); standard vaults on a failure of the final `persist_header`,
which a local co-user can force by filling the disk once
`<vault>.lbx.rotating` appears. Fix: `RotationState` snapshots the
header, MVK, `header_dirty` and the deniable state at `begin`, and
`abort` restores all of them. Pinned by
`abort_after_install_restores_original_header_and_mvk`.

**R15-E1: `rename` never updated the moved inode's `parent`; a later
`rmdir` of the old directory broke every subsequent flush**
(*reproduced*). `validate_metadata_tree` (run at the top of every
flush) requires `parent` to name a live directory, so after
`mkdir a; mkdir a/b; mv a/b b; rmdir a` the tree was permanently
unpersistable for the session: the deferred-flush timer logged an
error nobody sees from a GUI-spawned mount, `fsync` returned EIO, and
the vault reopened at the pre-rename snapshot with every later write
lost. Same with files and with hardlinks (`ln a/f g; rm a/f; rmdir a`).
Fix: `rename` re-points `parent`, `unlink` of a hardlinked file adopts
a surviving entry's directory, and `Vfs::open` heals stale pointers
persisted by older binaries (`repair_stale_parents`). Pinned by three
new regression tests.

**R15-I1: the GUI's hardware-kind create wrappers deleted PRE-EXISTING
files on failure.** Every TPM/SEP create wrapper treated any error as
"we created partial files" and `remove_file`d the vault, detached
header, anchor and `.kyber` paths, but the first error a user hits in
practice is the no-clobber refusal from the format layer or the hybrid
enroll helper's "seed already exists". Picking an existing `.kyber`
(the default file name is always `vault.kyber`) therefore deleted
ANOTHER vault's only PQ seed. Fix: `refuse_existing_create_targets`
runs before any hardware wrapper writes anything (dangling symlinks
count as existing), matching what the CLI and the passphrase/FIDO2
path already did.

**R15-D1 (metadata half): the rollback anchor could not detect a
rollback across a metadata-only change.** The anchor stored
`next_chunk_gen`, which only advanced on chunk writes, so a flush after
`unlink` / `rmdir` / `rename` / `chmod` wrote the same generation as the
previous flush and a vault rolled back to that snapshot compared
`Equal` against a perfectly trusted anchor: a deleted file silently
resurrected, contrary to `ROLLBACK_PROTECTION.md`. Fix: every flush of
a dirty tree allocates one generation first, so two persisted states
never share one. The header half of this finding (a restored
pre-revoke header is still invisible to the anchor) is accepted for
now, see the end of this document.

**R15-J1: the Apple Developer ID private key was imported into an
unlocked, ACL-open keychain BEFORE `cargo build` ran ~600 third-party
build scripts and proc-macros, and before `dylibbundler` /
`create-dmg` from Homebrew.** Any compromised dependency could
`security export` the signing identity, a persistent capability far
beyond backdooring one binary. Fix: the import step now runs
immediately before the first `codesign` call (after both builds and the
bundling), and an `if: always()` step deletes the keychain at the end
of the job.

## MEDIUM

- **R15-01** `memfd_secret(2)` was created with `flags = 0`, so every
  child LUKSbox spawns (`xdg-open`, `fusermount`, the FUSE-T helper)
  inherited an fd it could `mmap(MAP_SHARED)` to read the MVK
  (*reproduced*, see `memfd_secret_fd_is_close_on_exec`). Fix:
  `O_CLOEXEC`.
- **R15-C2** `begin_atomic_rotation` dropped the vault's `flock` and
  never re-acquired it, so a second process could open and write the
  vault for the whole (minutes-long) rotation and lose everything to
  the commit rename (*reproduced*). Fix: the original locked handle is
  retained in `RotationState`, the temp is locked from creation, and
  the lock follows the renamed inode. Pinned by
  `rotation_window_keeps_vault_locked`.
- **R15-C3 / E5** MVK rotation re-keyed only live chunks; free-list and
  leaked slots stayed decryptable under the old MVK (the AEAD keystream
  depends only on key + nonce, both on disk), so files deleted before a
  "true revocation" rotation were recoverable by the revoked party
  (*reproduced*). Fix: both rotation paths overwrite every unreferenced
  slot below `next_chunk_id` with random bytes.
- **R15-D2** Deniable vaults stored the metadata ciphertext length in
  the clear at a fixed offset (36876): four zero bytes plus a small
  value, i.e. a 2^-32 false-positive fingerprint for "this random blob
  is a LUKSbox deniable vault", which also leaked the directory-tree
  size. Fix: deniable vaults set `FLAG_MASKED_METADATA_LEN` (inside the
  AEAD-sealed inner header) and XOR the field with
  `HMAC(HKDF(MVK, salt, "lbx:metadata-len-mask/v1"), nonce)[..8]`; the
  real length stays in the AAD, so a wrong mask can only fail the tag.
  Pre-R15 deniable vaults keep their plaintext field and still open.
- **R15-E2** `truncate` shrink left the discarded tail bytes in the last
  chunk, and neither `truncate` up nor a write past EOF zeroed the
  hole, so truncated content resurfaced (*reproduced*). Fix: every
  extension zero-fills the hole in already-present chunks.
- **R15-E3** A re-spilled chunk-list chain freed its old blocks and
  immediately re-allocated the same LIFO slots BEFORE the metadata that
  stopped referencing them was durable; a crash in that window left
  both live and mirror metadata pointing at AEAD-failing blocks, an
  unopenable vault (*reproduced*). Fix: two-phase free (`pending_free`
  becomes reusable only after `write_metadata` returns).
- **R15-E4** The validator skipped `external_list_blocks` on Directory
  inodes while the spill freed them for every kind, so a forged tree
  (needs the MVK) was accepted and the victim's first flush double-freed
  a slot, after which every open was rejected (*reproduced*). Fix:
  validator and both on-disk readers refuse chains on non-File inodes.
- **R15-F1** With no `--fido2-device` / GUI pick, the CLI and GUI sent
  the CTAP2 PIN hash to whichever FIDO HID device enumerated first,
  before that device had proven it held the credential, so a cheap
  implant that sorts first on the bus harvested `LEFT16(SHA-256(PIN))`.
  Fix: refuse to guess when more than one authenticator is present (the
  wizard already prompted).
- **R15-G1** The WinFsp adapter ignored `ConstrainedIo` and extended the
  file on paging writes, so a dirtied memory-mapped 100-byte file became
  a zero-padded 4 KiB file. Fix: clip to the current size as
  memfs/passthrough do.
- **R15-H1** `LUKSBOX_PASSPHRASE` (the UNLOCK secret) was silently used
  as the NEW secret by `enroll`, `update`, `migrate-to-v3` and the
  seed-file prompts, skipping every strength guardrail; a user rotating
  a leaked passphrase with the old one exported re-wrapped the slot
  under the leaked value and was told it was updated. Fix: the unlock
  variable only stands in for a brand-new vault's first secret;
  everything else needs `LUKSBOX_NEW_PASSPHRASE` or the prompt.
- **R15-H2** Secrets read through `std::io::stdin()` (piped
  passphrases, the FUSE-T helper's MVK handoff) stayed in the
  process-global 8 KiB `BufReader` buffer, un-zeroized and swappable,
  for the life of the process. Fix: raw reads on fd 0 into `Zeroizing`
  buffers.
- **R15-I2** The GUI recorded deniable vaults in `recent.json` with a
  `"(deniable)"` label, a same-device tell the deniable design exists to
  avoid. Fix: never persisted.
- **R15-J2** The MSI's `WINFSPINSTALLDIR` was `Secure="yes"` and spliced
  into a `cmd.exe /C copy` deferred custom action running as
  LocalSystem, so a standard user running an elevated repair with
  `WINFSPINSTALLDIR="x" & <cmd> & "` got SYSTEM command execution. Fix:
  the property is no longer client-settable, the copy runs through
  `xcopy.exe` with no shell, and the removal is a WiX `RemoveFile`.
- **R15-J3 / J4 / J5 / J6** (release pipeline): unpinned
  third-party binaries compiled into attested releases (tpm2-tss by
  mutable tag, WinFsp and OpenSSL via unpinned choco packages, the
  embedded WinFsp MSI with an empty hash pin and a substring signer
  check); `contents: write` + `id-token: write` + `attestations: write`
  granted to the build job that runs untrusted build scripts, with the
  checkout token persisted; every third-party action pinned to a mutable
  tag; `github.ref_name` interpolated into `run:` scripts (a crafted tag
  name is shell injection on every runner holding the signing secrets).
  Fixes: SHA-256 pins for the tpm2-tss archives (Windows action and a
  new Linux staging step that sets `TPM2_TSS_SOURCE_PATH`), the WinFsp
  MSI and the choco package version; a CN-anchored signer check; least
  privilege per job with `persist-credentials: false`; every action
  pinned to a commit SHA (with `toolchain:` passed explicitly to
  `dtolnay/rust-toolchain`); the archive name reaches shells only
  through `$ARCHIVE`, and a first step refuses any ref name outside
  `[A-Za-z0-9._/-]`.

## LOW

- **R15-02** `secure_create_or_truncate` opened with `O_TRUNC` and
  never checked the result was a regular file owned by the caller: a
  planted FIFO turned an extraction into a stream its planter reads, and
  under an elevated run an attacker-owned regular file kept its owner
  after the chmod. Fix: open without truncation, `fstat` (regular file,
  `uid == euid`), then `ftruncate`.
- **R15-03 / R15-05** The deniable unlock still built the MVK through
  the by-value `from_bytes` (two un-wiped stack copies) and dropped the
  decrypted envelope `Vec` un-wiped. Fix: `Zeroizing` + `from_zeroizing`;
  `SecretBox::from_bytes` now wipes its parameter.
- **R15-04** The heap fallback of `SecretBox` (always on macOS/BSD,
  Linux without `memfd_secret`) `munlock`ed a 32-byte region at drop,
  which is page-granular: dropping an MVK clone unlocked the page under
  the surviving key. Fix: one private, locked, `MADV_DONTDUMP` +
  `MADV_WIPEONFORK` page per secret.
- **R15-A1** An inline-header vault accepted `metadata_offset == 0` /
  `data_offset < 8 KiB` (a valid-HMAC layout an MVK holder can
  produce), so the victim's first flush wrote ciphertext over the
  keyslot table. Fix: `load_locked_header` bounds both offsets for
  inline headers.
- **R15-A2** The AEAD / block-cipher / universal-hash crates were built
  without their `zeroize` feature, so every `Aes256GcmSiv` temporary
  left the KEK's round keys in dead stack memory. Fix: feature
  unification through direct deps.
- **R15-C4** Rotation wrote `<vault>.lbx.rotating.{meta,header}-bak`
  mirrors that neither commit nor abort removed (a permanent 64 MiB
  current-MVK metadata snapshot at a predictable name). Fix: no mirror
  writes while a rotation is in flight; commit/abort sweep the orphans.
- **R15-D4** `peek_vault_header_salt` lacked the regular-file /
  reparse-point checks of its sibling (FIFO stall before
  `Container::open`). Fixed.
- **R15-D5** The CLI's deniable hybrid unlock decapsulated against
  `entries.first()` instead of the matched slot's sidecar entry, an
  opaque unlock failure for every non-first slot (the wizard already
  had the fix). Fixed.
- **R15-E6** One 1-byte write near `MAX_FILE_SIZE` pre-reserved a
  64 GiB `Vec` and aborted the mount process. Fix: incremental growth;
  ids allocated by a failed extension are returned to the free list.
- **R15-E7 / I4** `validate_name` admitted control characters; `luksbox
  ls` printed them raw (terminal escape injection) and the GUI browser
  rendered a newline as a second row. Fix: names created through the
  API reject controls; existing names are sanitised at display time.
- **R15-F2** The FIDO2 PIN copy handed to libfido2 was a plain
  `CString` (never wiped). Fix: `Zeroizing<CString>` (zeroize `std`).
- **R15-F3** `luksbox-pq` left the 64-byte ML-KEM seed and the shared
  secret in plain stack copies. Fix: `Zeroizing` destinations, library
  copies scrubbed.
- **R15-F4** The SEP Swift shim copied the ECDH shared secret through
  a Foundation `Data` (not scrubbed). Fix: direct copy from CryptoKit's
  `SecureBytes`.
- **R15-G2** WinFsp `overwrite` / allocation-size changes grew EOF to
  the allocation size (zero-padded files from pre-allocating writers).
  Fixed.
- **R15-G4** FUSE-T truncated `nlink` to 16 bits (65 536 links wrapped
  to 0). Fixed.
- **R15-G5** `luksbox umount` could not detach a zombie FUSE mount on
  glibc < 2.33 (`realpath` failed with ENOTCONN before `fusermount -u`
  ran). Fix: `std::path::absolute` fallback.
- **R15-H4** `panic` / `panic_by_path` / `panic_action` sized the data
  wipe from a symlink-following path `stat` (race: a 0-byte swap made
  `--wipe-data` a silent no-op). Fix: size from the pinned handle, fail
  on error.
- **R15-H5** The wizard canonicalised a mountpoint before the mount
  layer's no-follow probe could refuse a symlink, and the wizard /
  `info` header prescans ignored `LUKSBOX_NO_FOLLOW_SYMLINKS`. Fixed.
- **R15-H6** `deniable-info` printed the unlocked slot index (tells a
  coerced co-user's observer that lower slots exist). Removed.
- **R15-I3** The GUI's single-file save restored a vault-supplied
  extension without the R14-06 `:` check (Windows ADS write). Fixed.
- **R15-J7** `audit.toml` sat where cargo-audit never reads it, and
  the pre-push script's vulnerability detector could never match
  (multi-line output). Fix: `.cargo/audit.toml`; exit-status check.
- **R15-J8** The decoded Windows signing PFX stayed on disk for the
  rest of the job. Fix: removed at the end of both signing steps.
- **R15-J10** The macOS post-bundle gate only caught `@rpath/`
  references; absolute Homebrew-prefix load commands (user-writable
  on Apple Silicon) passed. Fixed.

## Accepted for now / documented

| ID | Why not fixed in this revision |
|---|---|
| R15-D1 (header half) | Detecting a rolled-back HEADER (a revoked slot restored from a backup) needs a header generation counter inside the HMAC'd region plus an anchor v2 format and anchor updates from every header-mutating command. Format change; tracked. `ROLLBACK_PROTECTION.md` and `SECURITY.md` now state the limit precisely. |
| R15-D3 | A v3 hybrid sidecar rewritten as v1/v2 drops its vault binding. Impact is an unlock failure for that slot only (the slot AEAD fails closed); refusing unbound sidecars would break pre-v3 vaults. Documented. |
| R15-C5 | Detached-header rotation is not crash-safe; the CLI's "back up the header sidecar" advice was wrong (a header backup cannot decrypt re-keyed chunks). Message and spec corrected to "back up the whole vault + header". |
| R15-F5 | TPM salted sessions defeat a passive bus interposer only; an active interposer that substitutes the SRK public area in `CreatePrimary` learns the KEK. Needs SRK-name pinning in the slot (format change). Documented in `SECURITY.md`. |
| R15-G3 | WinFsp `--sync` does not flush from `create` / `overwrite` / `set_file_size` and the timer is off in that mode. Windows-only adapter change we could not compile-test in this round; tracked. |
| R15-H3 | KDF-strength and passphrase-strength guardrails differ between `deniable-init`, the wizard's custom KDF and `enroll`/`update` (which always use interactive cost). Tracked as UX hardening. |

Also noted (INFO): `examples/passphrase_crack.rs --threads N>1` counts
`VaultLocked` as a miss (the `flock` is taken before the KDF); run with
`LUKSBOX_NO_LOCK=1`. `unlink` of an open file drops it immediately
(POSIX unlink-while-open semantics are not supported).

## New regression coverage

| Finding | Test |
|---|---|
| R15-01 | `secret_box::tests::memfd_secret_fd_is_close_on_exec` |
| R15-C1 | `container::tests::abort_after_install_restores_original_header_and_mvk` |
| R15-C2 | `container::tests::rotation_window_keeps_vault_locked` |
| R14-04 (updated) | `container::tests::abort_atomic_rotation_ignores_symlinked_path` (retained-handle semantics) |
| R15-D1 | `vfs::tests::metadata_only_change_advances_generation_on_flush` |
| R15-D2 | `metadata::tests::masked_length_field_is_not_plaintext_and_roundtrips`; `container::tests::deniable_container_metadata_region_round_trips` (unmasked reader must fail) |
| R15-E1 | `vfs::tests::{rename_out_then_rmdir_old_parent_still_flushes, hardlink_unlink_then_rmdir_canonical_parent_still_flushes, stale_parent_pointer_is_repaired_at_open}` |
| R15-E2 | `vfs::tests::extension_after_shrink_reads_zeros_not_stale_bytes` |
| R15-E3 | existing free-list tests now flush before asserting reuse (`unlink_frees_chunks_for_reuse`, ...) |
| R15-E4 | `vfs::tests::validator_rejects_directory_with_external_chain` |

## Surfaces reviewed and found sound

Recorded so the next round does not re-derive them (details in the
per-surface notes kept internally).

- Keyslot `from_bytes` / `to_bytes` / `build_aead_aad` agree for all 28
  slot kinds; every parse index is bounded; kind and AAD-version bytes
  sit inside the AAD so no kind/version flip survives the tag; nothing
  acted on before HMAC verification can yield a wrong-but-accepted MVK.
- Argon2id bounds, HKDF label uniqueness (seven labels + the new
  `lbx:metadata-len-mask/v1`), per-slot nonces, constant-time MVK and
  tag compares.
- Deniable v2 envelope discovery remains constant-time (R12-01) and
  every layer is domain-separated; `SlotPayload::decode` bounds; inner
  header layout checks.
- Anchor MAC-then-use with `ct_eq`, bound to MVK + salt; mirror
  recovery is intended-state and cannot resurrect a revoked credential.
- Hybrid KEK mixing: the sidecar public key is never used for
  re-encapsulation; a swapped / downgraded sidecar can only fail the
  slot AEAD.
- Every hardware output (hmac-secret, TPM unseal, SEP agreement, KEM
  shared secret) is only ever a KDF input; FFI buffers are bounded;
  `seed_file.rs` has no TOCTOU.
- Chunk AAD and per-file keys, chunk-list chain parsing bounds, offset
  arithmetic, the rest of `validate_metadata_tree`.
- Mount adapters: fuser/FUSE-T/WinFsp bounds, no `allow_other`, uid
  ACL, mountpoint hardening shared by every frontend, the FUSE-T helper
  handoff over an anonymous pipe only.
- CLI: no passphrase on argv, confirmations fail closed on a non-tty,
  destructive paths pinned through no-follow handles, extraction paths
  through `secure_create_or_truncate`, orphan cleanup confined.
- CI: `pull_request` (not `pull_request_target`), no secrets reachable
  from forks, `Cargo.lock` fully check-summed with one git dependency
  pinned to a full SHA and verified byte-for-byte against the crates.io
  release it patches.
