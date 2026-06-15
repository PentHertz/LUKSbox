# Changelog

All notable changes to LUKSbox are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once the v1.0 line is cut. Pre-1.0 releases follow `0.MAJOR.PATCH`
where on-disk format may evolve under audit guidance, but every
breaking format change ships with a migration tool and a clear
upgrade path.

The website at <https://luksbox.penthertz.com/changelog/> mirrors
the highlights for the latest few releases. This file is the
canonical record.

---

## [v0.3.0] - 2026-06-15

Cross-platform FIDO2 keyslots and an in-place migration path.

### Fixed: FIDO2 keyslots no longer platform-locked

A FIDO2 keyslot enrolled on Linux or macOS could not unlock the
vault on Windows, and a slot enrolled on Windows could not unlock on
Linux or macOS. Root cause: the two backends feed the
authenticator's CTAP2 hmac-secret extension DIFFERENT salt bytes.
libfido2 (Linux/macOS) forwards the 32-byte salt to the device
unchanged. `webauthn.dll` (Windows), even on the raw hmac-secret
path (`pHmacSecretSaltValues`, `bEnablePrf = 0`), is NOT a
passthrough: it applies the W3C WebAuthn-PRF derivation
`T(x) = SHA-256("WebAuthn PRF"\0 || x)` to the salt before the
device sees it. Same authenticator, same on-disk salt, the two
paths handed the device different bytes -> two different HMAC
outputs, two different KEKs, AEAD-unwrap failure on the other
platform.

This was confirmed empirically with the `xplatform_hmac_probe`
example (same physical key on both OSes): Windows' output for a raw
salt equals Linux's output for `T(salt)`, and equals neither the raw
salt nor a plain `SHA-256(salt)`.

**Fix:**
- On-disk slot version `AAD_VERSION_V4` defines the canonical device
  salt as `T(salt) = SHA-256("WebAuthn PRF"\0 || salt)` (V1/V2/V3
  used the raw salt).
- Both backends converge on the device computing
  `HMAC-SHA256(device_secret, T(salt))`:
  - `hid.rs` (libfido2) applies `T` LOCALLY via the shared
    `luksbox_fido2::webauthn_prf_salt` helper before handing the
    salt to the device.
  - `webauthn.rs` (Windows) forwards the RAW salt and lets
    `webauthn.dll` apply the identical `T` itself.

**History of this fix:** two earlier v0.3.0 attempts modelled
`webauthn.dll` wrongly -- first as a passthrough, then as a plain
`SHA-256(salt)` prehash. It is neither; it applies the PRF-prefixed
`T`. Both earlier models left V4 slots failing cross-platform with
`crypto: keyslot authentication failed`. `AAD_VERSION_V4` is now
*redefined* to the PRF-prefixed convention.

**Migration required for affected vaults.** Because `T` is one-way,
a FIDO2 slot whose device salt is the raw salt (V1/V2/V3) or a plain
`SHA-256(salt)` (the earlier mislabelled-V4 build) can NEVER be
reproduced through `webauthn.dll`. Such slots cannot be opened on
Windows by any code change; **recreate the FIDO2 slot** under this
build to get a working cross-platform V4 slot. New slots created by
`Keyslot::new_*` are V4 and cross-platform by construction.

**User verification (UV) caveat.** `webauthn.dll` ALWAYS performs
user verification, while libfido2 only does so when a PIN is
supplied -- the two select different per-credential secrets
(`CredRandomWithUV` vs `CredRandomWithoutUV`). Enroll the FIDO2 slot
**with a PIN** so both platforms derive from the same secret;
otherwise the slot still mismatches across platforms even with the
salt fix.

**Verification status:** the salt convention is pinned by the
`fido2_xplatform_wire.rs` regression tests (which now model `T`) and
by the `xplatform_hmac_probe` example on real hardware. The Windows
backend compiles for `x86_64-pc-windows-{gnu,msvc}`.

**Migration:** `luksbox migrate-fido2-slot <vault> --slot N` on
Linux or macOS bundles enroll+revoke: it registers a fresh credential on
the same authenticator under the V4 convention, writes the new
slot at the first free index, and revokes the old slot. The
migration is in-place (no vault rewrite), idempotent against
already-V4 slots, and atomic against the header mirror protocol
(no `header-bak` divergence on crash mid-migration). See the
[CLI page](https://luksbox.penthertz.com/docs/cli/migrate-fido2-slot/)
for the full flow.

**Scope of the migration command in v0.3.0:** only `Fido2HmacSecret`
slots. `Fido2DerivedMvk` (`--kind fido2-direct`) slots cannot be
migrated because their MVK is derived directly from the
authenticator output; recreating the vault is the only path.
Fused TPM+FIDO2 and hybrid-PQ-FIDO2 variants are also outside
the v0.3.0 migration scope -- the command rejects them with a
clear message. Workaround for those slot kinds: enroll a backup
passphrase or non-fused FIDO2 slot from Linux, use it from
Windows, plan a deeper migration for v0.3.1+.

**Surface changes:**
- `Fido2Authenticator::hmac_secret` gains a `prehash_salt: bool`
  parameter. Out-of-tree callers that implemented the trait need
  to add the parameter and route it to their CTAP2 layer.
- `Keyslot::fido2_salt_prehashed(&self) -> bool` returns whether
  this slot's wire convention requires the prehash (V4+) or
  passes the salt raw (V1/V2/V3).
- `Keyslot::touches_fido2(&self) -> bool` returns true for any
  slot kind whose unlock path drives the FIDO2 hmac-secret
  extension. Useful for the slot table + the cross-platform
  compat indicator.
- `luksbox info` prints `compat: V4 cross-platform` or
  `compat: V{1,2,3} Linux/macOS-only -- migrate with ...` per
  FIDO2-touching slot.
- The GUI's Keyslots view shows the same compat status under
  each FIDO2 slot row, with the migration command spelled out.
- The mock authenticator (`MockAuthenticator::hmac_secret`)
  prehashes when `prehash_salt=true` and passes the salt raw
  otherwise, mirroring libfido2 semantics for unit tests.

### Fixed: `luksbox mount` default mode refused to start

`luksbox mount <vault> <mountpoint>` (the default daemonizing
form) failed on Linux with `refusing to daemonize from a
multithreaded process` once the deferred-flush timer landed in
v0.2.x. `mount()` constructed the `LuksboxFs` (which spawns the
`luksbox-flush-timer` thread when `--sync` is off) BEFORE the
fork, then the pre-fork single-threaded check immediately saw
that timer thread and refused. `--foreground` worked because it
skipped the fork. Fix: move `LuksboxFs::new` into the child
branch of `run_daemonized`, after fork and after
`detach_from_terminal`. The parent never spawns the timer, the
check passes, and the child owns its timer like every other
helper thread. The assert now also names the offending threads
in its error message so the next regression of this shape will
be obvious from the user-visible diagnostic instead of a silent
count.

### Fixed: deniable FIDO2 envelopes from v0.2.1/v0.2.2 could not unlock

The keyslot fix above versioned the salt convention via
`aad_version`, but deniable v2 envelopes carry no equivalent
marker, and the v0.3.0 unlock paths initially hard-coded the new
prehashed convention. A FIDO2-bearing deniable vault created by
v0.2.1/v0.2.2 on Linux/macOS (raw-salt convention) would compute
the wrong `KEK_factors`, fail the inner AEAD, and surface the
intentionally generic unlock failure -- indistinguishable from a
wrong passphrase, recoverable only by downgrading the binary.

**Fix: convention probe at unlock.** All three front-ends (CLI,
wizard, GUI) now try the V4 prehashed convention first; if the
inner MVK unwrap fails, they drive the authenticator once more
with the raw-salt convention. New envelopes unlock on the first
touch; pre-v0.3.0 envelopes cost one extra touch (the PIN is
asked once). Supporting API:
`Container::complete_open_v2_deniable_reusable` hands the
envelope handle back on failure so the retry skips the Argon2id
discovery phase and keeps the vault file lock, and
`deniable_header::complete_open_v2` now borrows the opened
envelope instead of consuming it. A future envelope revision can
record the convention explicitly and retire the probe.

### Fixed: tolerant-recovery vaults were not actually read-only

The corrupted-vault recovery mode (wizard checkbox, GUI checkbox,
`LUKSBOX_TOLERATE_BAD_CHUNK_LISTS`) promises a read-only session:
broken inodes are installed as zero-byte placeholders so the rest
of the vault can be copied out, and the lossy in-memory tree must
never overwrite the on-disk metadata (that would permanently
destroy the broken files' chunk pointers and any chance of later
recovery). The enforcement was keyed on the transient thread-local
flag, which the GUI and wizard drop right after `Vfs::open`
returns -- so the recovered vault was in fact fully writable and
the first flush destroyed exactly what the mode exists to protect.
`write()` was worse: it rewrites chunks on disk at call time with
bumped generations, so writing to a healthy file during a recovery
session corrupted it for subsequent normal opens.

**Fix:** the gate is now the per-instance recovery report
(`tolerated_inodes`), checked by every mutating Vfs op (write,
truncate, create, mkdir, unlink, rmdir, rename, link, symlink,
chmod, MVK rotation) which now return `ReadOnlyMount` (EROFS over
FUSE), and by `flush` (clean flushes no-op so unmount still
works). Corollary fixes: a leftover
`LUKSBOX_TOLERATE_BAD_CHUNK_LISTS` no longer freezes flushes on
healthy vaults (the env var also now treats `0`/`false`/`no`/empty
as off), and the whole recovery mode gained its first regression
tests, including one that proves a recovery session leaves the
broken chain bytes on disk untouched.

### Fixed: rename over a hardlinked file orphaned the surviving links

`rename(2)` onto an existing target freed ALL of the displaced
inode's chunks and removed it outright -- correct before
hardlinks existed, data loss after: with `ln a b`, a rename onto
`b` left `a` pointing at a removed inode (panic on next access),
its freed chunk slots were recycled by the next write (silent
ciphertext overwrite of `a`'s content), and
`validate_metadata_tree` then failed every flush for the rest of
the session. The displace path now mirrors `unlink`: decrement
`link_count`, free chunks and chunk-list blocks only when the last
link is gone, and clear the Layer-2 dirty marker alongside.
Covered by new hardlink+rename regression tests, including the
rename-onto-the-same-inode no-op required by POSIX.

### Fixed: `--sync` mount reported success when the flush failed

In `--sync` mode every mutating FUSE op drives an immediate
`Vfs::flush`, but the Layer-1 refactor discarded its result, so a
vault-file write failure (ENOSPC, EIO) was reported to the
syscall as success -- the pre-Layer-1 handlers returned EIO here.
The flush result now propagates to every mutating handler and to
the `flush()` (close(2)) and `release()` callbacks. In deferred
mode, the timer-tick and unmount-time flushes now log failures to
stderr instead of dropping them silently (there is no syscall to
report to from a timer). The FUSE-T adapter propagates the same
way; WinFsp logs at its commit-style call sites.

### Fixed: `LUKSBOX_FORMAT_V2` was ignored where it mattered most

Two defects around the v2-format opt-out. First, released docs
disagreed on the value: the CLI help, GUI tooltip, and
CRYPTO_SPEC.md said `LUKSBOX_FORMAT_V2=1` keeps v2, while the
v0.2.0 changelog said `=0` -- and the implementation honored only
`=0`, so anyone following the binary's own `--help` silently got
a v3 vault. The variable now opts into v2 when set to ANY
non-empty value, which makes every released instruction correct.
Second, the documented suppression of the flush-time auto-upgrade
did not exist at all: the upgrade gate checked only the header
version, so one flush from a v0.2.1+ binary permanently upgraded
a deliberately-v2 vault out from under the pre-v0.2.1 readers it
was created for. The same toggle now vetoes the upgrade. Verified
live: with the variable set, create/put/cat keep the vault v2 and
`migrate-to-v3` accepts it; with the variable unset, the default
auto-upgrade still fires.

### Fixed: TPM handles and PIN copy leaked on failed unseal

`Tpm2Sealer::unseal_with_pin` flushed its transient handles (SRK,
loaded object, and now also the per-operation HMAC session, which
was never flushed anywhere) only on success. On the most common
failure -- wrong PIN at `Esys_Unseal` -- the early return stranded
two transient handles per attempt (TPMs commonly expose about 3
transient slots) and left the PIN bytes in the ESYS context's
C-side `TPM2B_AUTH` slot until the Context dropped. Seal had the
same pattern around `Esys_Create`. All flushes now run on every
path.

### Security hardening (review follow-up)

- **Detached-header lock survives a sidecar rewrite.** In
  detached-header mode, `persist_header` / `restore_header_bytes`
  replace the sidecar via `atomic_secure_write` (temp+fsync+rename)
  and reopen the handle, but the reopened fd pointed at the new inode
  *without* re-taking the advisory lock, so the old lock stayed on the
  now-unlinked pre-rename inode, so the sidecar lock invariant was
  silently lost after any header persist/restore. The new fd is now
  re-locked (honoring `LUKSBOX_NO_LOCK`) before the old handle is
  dropped. `crates/luksbox-format/src/container.rs`.
- **Keyslot serialization can't panic or truncate on an
  externally-built slot.** `Keyslot` fields are `pub`, so external
  crate code can bypass the `new_*` constructors' length validation.
  `to_bytes` / `build_aead_aad` now clamp the variable-length cred_id
  region to the slot's capacity (with a `debug_assert`), turning a
  would-be out-of-bounds slice panic and a silent `len as u16`
  truncation into a bounded copy. No behavior change for any slot
  built through the public constructors (cred_id is already capped at
  `FIDO2_CRED_ID_MAX`). `crates/luksbox-core/src/keyslot.rs`.

### Fixed: GUI create-vault picker hid extensionless vaults

The "New vault file" save dialog applied an `.lbx`-only filter, which
hid extensionless vaults (the old default name was `secret`) and made
it awkward to pick or overwrite them. The filter is gone, matching the
no-filter behavior already used by the open-existing picker (#12).
`crates/luksbox-gui/src/app.rs`. Thanks to Matt Van Horn
(@mvanhorn) for the fix (#15).

### Added

- `crates/luksbox-core/tests/fido2_xplatform_wire.rs`: three
  regression tests that simulate both wire paths through the
  mock authenticator and assert byte-identical HMAC outputs
  under the V4 convention. Round-trips a V4 keyslot through
  enroll-on-Linux-simulated-path + unlock-on-Windows-simulated-
  path to lock in the cross-platform property.
- `MockAuthenticator::prehash_salt_changes_output`: a sanity
  test that the V3 -> V4 wire-format divergence still produces
  different HMAC bytes under the mock, so any future regression
  that silently undoes the prehash on the libfido2 side would
  trip this test before it ships.
- Slot compat labels (CLI `info`, wizard, GUI) now print the
  correct 1-based version (a V1 slot displayed as "V0"), only
  point at `migrate-fido2-slot` for the wrap-style slots the
  command accepts, and spell out the required vault path
  argument.
- `ReadOnlyMount` maps to EROFS over FUSE so cp/rsync/editors
  see "read-only file system" on recovery mounts instead of a
  generic I/O error.
- **Ubuntu 26.04 (resolute) support in CI/CD.** Releases now ship a
  native `luksbox_*_resolute_{amd64,arm64}.deb` and matching tarball,
  built inside an `ubuntu:26.04` container so cargo-deb resolves the
  26.04 dependency sonames (which bump again past noble). CI gains a
  containerised 26.04 test lane (workspace + hardware profiles) that
  runs the suite against the 26.04 library/toolchain stack. Both run
  in a container because GitHub has no native `ubuntu-26.04` hosted
  runner yet; the workflows note where to switch to it once it lands.

### Notes

- No on-disk format change for non-FIDO2 slot kinds. The V3 ->
  V4 bump affects every new keyslot constructor for uniformity
  (so `aad_version >= V4` is a single test for "this vault was
  created post-FIDO2-cross-platform-fix"), but passphrase / TPM
  slots gain nothing functional from V4 vs V3.
- Workspace version stays at 0.2.2 until v0.3.0 is tagged.
  Bumping is a release-engineering step, not part of the patch.

## [v0.2.2] - 2026-06-02

Critical durability fix on top of v0.2.1. **Closes a real-user
data-loss class** where v0.2.1's mirror protocol could commit
"intended new state" pointers to disk before the chunk-list blocks
those pointers reference were durable, so a crash in a narrow
post-mirror-fsync, pre-live-fsync window left a vault whose
recovery target pointed at slots that still held pre-flush bytes.
The reader's AEAD verification then failed on every such block.

Existing v0.2.1 vaults open unchanged; the fix is entirely on the
write path. **No on-disk format change** -- same LBM5 + LUKSBOX2 +
sidecar mirror envelope. Vaults that already lost chunk-list
blocks to this bug are NOT recovered by upgrading; this release
only prevents future occurrences.

### Performance

- **Deferred metadata flush ("Layer 1") on all mount backends.**
  Pre-v0.2.2, every metadata-changing FUSE op (create, mkdir,
  unlink, rmdir, rename, setattr, symlink, link, FUSE flush/release)
  drove an immediate synchronous `Vfs::flush`, which on v0.2.1+
  vaults rewrote the entire 64 MiB metadata mirror and live region
  plus re-spilled every inode's chunk-list chain. On a 10k-file
  vault this could make a single `rm` of one small file take
  **3+ minutes** (real-user report on Linux Mint). v0.2.2 changes
  the default: those ops mark the in-memory tree dirty and return
  immediately, and a background `luksbox-flush-timer` thread (one
  per mount) drives a `Vfs::flush` every 30 seconds when dirty.
  Explicit `fsync(2)` / `fsyncdir(2)` syscalls remain eagerly
  synchronous (POSIX-required). Final flush on unmount via the
  FUSE `destroy()` callback (and WinFsp's `Drop`) also stays eager.
  The net effect on the user's bug-report scenario: `rm` returns
  in milliseconds, `cp -r 10k_files` completes in seconds instead
  of hours.

  **Platform coverage:** Linux libfuse3, macOS macFUSE, macOS
  FUSE-T, and Windows WinFsp all share the same lazy-flush
  pattern. Earlier v0.2.2 drafts shipped Layer 1 for libfuse3 only;
  the FUSE-T and WinFsp adapters now host their own
  `luksbox-flush-timer` thread with identical 30 s cadence,
  identical `--sync` opt-out, and identical final-flush guarantee.
  The shared interval lives in `luksbox_mount::LAZY_FLUSH_INTERVAL_SECS`.

  Durability model matches ext4 / btrfs / xfs commit intervals: a
  crash without an explicit `fsync` can lose up to 30 seconds of
  metadata changes. The on-disk encrypted bytes that ARE flushed
  retain the v0.2.2 mirror-protocol durability fence (chunk-list
  blocks are durable before the mirror commits), so the
  post-flush state is still crash-consistent. Anti-rollback /
  anchor sidecar semantics are unchanged: the anchor lags behind
  the in-memory generation counter by up to the timer interval,
  but catches up on every flush. Keyslot revocation is unaffected
  (`revoke()` calls `persist_header` independently of `vfs.flush`).

  **`luksbox mount --sync`** (also accepted on `deniable-mount`)
  restores the pre-v0.2.2 eager-flush semantics for users whose
  threat model requires every operation to be durable on return.
  Workload cost is proportional to total file count; recommended
  only for small vaults or specific durability-critical workflows.

  **Wizard (TUI):** the open-and-mount and post-create mount flows
  now prompt `"Eager flush? (every metadata op crash-durable on
  return; SLOW on vaults with thousands of files -- default is
  no)"`. Default is no (matches the CLI default).

  **GUI:** the Browser view shows an `Eager flush (--sync)`
  checkbox next to the `Mount as volume...` button, with a hover
  tooltip explaining the trade-off. Default off; per-mount, not
  persisted across vault sessions (the checkbox resets to off
  after each mount).

- **Per-inode dirty tracking in the spill code ("Layer 2").** Pre-
  v0.2.2, `Vfs::flush` (whether eager or timer-driven) re-spilled
  every inode that exceeded the inline-chunk threshold: free old
  external_list_blocks, allocate fresh ChunkIDs + generations,
  re-encrypt every chunk-list block, re-write the chain. For a
  vault with N spilled files this was O(N) chunk-list-block
  AEAD-writes per flush, regardless of how many inodes actually
  changed. With Layer 1 batching the flushes, Layer 2 makes each
  flush itself fast: a `chunks_dirty: BTreeSet<FileId>` is
  populated by `write`, `truncate`, and `create_with_mode`, and
  `spill_to_v3_on_disk` reuses the existing in-memory
  `external_list_blocks` (and therefore the on-disk chunk-list
  blocks) for any inode NOT in that set. Result: per-flush cost
  is now O(K) where K = inodes touched since last flush, not
  O(N) where N = total spilled files.

  Cleared at the end of every successful `Vfs::flush`, alongside
  the existing `dirty = false` flag. Re-populated with every
  inode (`tree.inodes.keys().copied()`) on:
   - format upgrades (V1->V5 and V2/V3->V4 triggered by the
     `tree_needs_v4_format` check)
   - MVK rotation (both standard and deniable variants)
  -- these paths rewrite the chain regardless and want the full
  spill semantics.

  `chmod`, `rename`, `link`, `mkdir`, `symlink` do NOT mark
  chunks_dirty: those touch the in-memory tree but leave the
  chunk-list chain byte-identical on disk and don't change the
  inline-vs-external decision.

  Regression test: `v3_clean_inode_reuses_chunk_list_blocks_across_flush`
  creates two spilled files, modifies only one, flushes, and
  asserts the untouched file's `external_list_blocks` (chunk_ids
  AND generations) are byte-identical to the pre-flush snapshot
  while the touched file's blocks got fresh IDs / gens. Plus a
  reopen sanity check that decrypts the first byte of each file
  through both reused and freshly-spilled chains.

  Scope: this change affects Linux libfuse3 mounts only for v0.2.2.
  macOS FUSE-T (`fuse_t.rs`) and Windows WinFsp (`winfsp.rs`) retain
  their pre-v0.2.2 flush behavior; their `mount()` entry points
  accept the new `sync_mode` parameter for forward compat but
  ignore it. macFUSE on macOS shares `fuse.rs` with Linux libfuse3
  and gets the deferred-flush behavior automatically.

### Fixed

- **Durability hole in the v0.2.1 mirror protocol** (CVE-class
  data-loss bug). `Vfs::flush`'s spill stage writes external
  chunk-list blocks via `Container::write_at` (page cache only,
  no fsync). It then called `Container::write_metadata`, which
  fsyncs `.lbx.meta-bak` BEFORE overwriting the live metadata
  region and fsyncing the `.lbx` file. A crash between the
  mirror's fsync and the `.lbx` sync_all (power loss, OOM kill,
  kernel panic, host hypervisor death) could leave:
  - `.lbx.meta-bak`: durably committed to the NEW state with
    fresh `chunks_external` head/generation tuples pointing at
    chunk-list-block slots in the data area.
  - `.lbx` chunk-list-block slots: still holding bytes from a
    previous flush (the new writes had not yet reached disk).
  On reopen, mirror recovery picks the NEW `chunks_external`
  pointers as authoritative. The reader's AEAD then verifies
  every targeted chunk-list block under the NEW generation in
  AAD, but the bytes on disk were written under the OLD
  generation. Result: `crypto: AEAD failure` for every
  chunk-list block that hadn't been fsync'd before the crash,
  cascading to `metadata blob deserialization failed` from the
  VFS layer at open time. Symptom in the wild: a v0.2.1 user
  lost 26 contiguous-in-generation chunk-list blocks in a single
  flush after a crash, while data chunks and the metadata blob
  itself were intact.

  Fix: new `Container::sync_data_area()` method (one
  `self.file.sync_all()`), called from `Vfs::flush` between the
  spill stage and `write_metadata`. The mirror's "reader can
  trust these pointers" invariant is now backed by durable bytes.
  Deniable vaults are unaffected (they explicitly opt out of the
  sidecar-mirror protocol). v0.2.0 and earlier vaults are
  unaffected (no mirror protocol there at all).

- **`luksbox check --fido2` rejected `fido2-direct` vaults** with
  `no FIDO2 keyslots in this container`. The flag-driven unlock
  path (`open_container_fido2` in `crates/luksbox-cli/src/main.rs`)
  iterated only `SlotKind::Fido2HmacSecret` slots and skipped
  `SlotKind::Fido2DerivedMvk`, even though the format layer's
  `UnlockMaterial::Fido2` arm has handled both kinds since v0.2.0.
  Fixed to accept both kinds.

- **CLI subcommands defaulted to a passphrase prompt on
  FIDO2-only vaults** with no helpful diagnostic. When `--fido2`
  / `--tpm2` / `--tpm2-fido2` / `--pq-hybrid` aren't passed and
  the vault carries zero passphrase keyslots, the subcommand
  now errors with `vault has no passphrase keyslot; rerun with
  --fido2` (or `--tpm2`, `--tpm2-fido2`, `--pq-hybrid` as the
  header dictates) instead of silently prompting for a passphrase
  that no slot will ever accept.

### Added

- **Recovery primitives for vaults already broken by the v0.2.1
  durability hole** (and other corruption classes that leave
  chunk-list-block AEAD failing). Both are opt-in via env var so
  no default behavior changes:
  - `LUKSBOX_DEBUG_OPEN=1` -- instruments `Vfs::open` to print to
    stderr the metadata plaintext head bytes, which LBM2/3/4/5
    magic matched, postcard error details, the per-inode result
    of `v4_on_disk_to_in_memory`, and the `validate_metadata_tree`
    outcome. Lets a user with a refusing vault pinpoint the
    exact parse step that trips without source modification.
  - `LUKSBOX_TOLERATE_BAD_CHUNK_LISTS=1` -- when a chunk-list
    chain fails AEAD during open, install the affected inode
    with empty `chunks` and `size = 0` instead of refusing the
    whole vault. The inode appears as a 0-byte file in the
    mount, so the user can mount read-only and copy out every
    healthy file. A new `Error::ReadOnlyMount` causes any
    subsequent `Vfs::flush` to refuse so the patched (lossy)
    tree is never persisted over the original on-disk metadata.

- **Recovery mode in wizard and GUI** (no more env-var-only UX).
  - **Wizard**: when the user opens a vault and `Vfs::open` fails
    with `MetadataDeserialize`, the wizard now prompts "Try opening
    in recovery mode?" (default yes). On confirm it re-authenticates,
    sets the thread-local toleration flag, retries, and prints the
    list of broken inode IDs / sizes / paths to stderr. Read-only
    mount; flushes refuse.
  - **GUI**: new "Recovery mode (read-only, skips broken files)"
    checkbox in the Open form. On a successful recovery-mode open
    with tolerated inodes, a modal lists every broken file's path
    + original size + AEAD-failure reason so the user knows what
    to re-source. Modal dismisses on click / backdrop / Esc; flush
    is refused while the recovery report is active.
  - The env-var path (`LUKSBOX_TOLERATE_BAD_CHUNK_LISTS=1`) still
    works for CLI/headless use and continues to wrap the same code
    path. The two are unified via the new `luksbox_vfs::set_tolerate_bad_chunk_lists`
    thread-local guard + `tolerate_bad_chunk_lists()` predicate
    (env var OR TLS). A new `Vfs::tolerated_inodes()` accessor
    returns the broken-inode report; UI / scripts can read it
    after a successful recovery-mode open.

- **Regression test infrastructure for the durability fence.** Three
  new tests in `crates/luksbox-vfs/src/vfs.rs`:
  - `flush_runs_sync_data_area_before_write_metadata` -- compliance
    test that snapshots a per-thread flush-op log and asserts
    `Container::sync_data_area` runs strictly before
    `Container::write_metadata` during `Vfs::flush`. Removing the
    fence call breaks this test even when all happy-path tests
    still pass. The log is exposed via three new `pub` helpers in
    `luksbox-format::container`: `FlushOp`, `reset_flush_op_log`,
    `flush_op_log_snapshot`.
  - `skip_fence_thread_local_reproduces_v0_2_1_ordering` --
    bug-reappearance check that uses the new thread-local
    `set_skip_fence_for_test(true)` escape hatch to bypass the
    fence on the calling thread, then verifies the op log shows
    only `WriteMetadata` (matching the v0.2.1 ordering). Thread-
    local instead of an env var so concurrent test threads don't
    race. Production code never touches `set_skip_fence_for_test`.
  - `v0_2_2_fence_prevents_chunk_list_loss_after_simulated_crash`
    -- true crash-impact test using a new `SimFile` backing for
    `Container` (models a kernel page cache vs durable bytes with
    a `crash()` method that reverts un-fsync'd writes), plus a new
    thread-local `set_crash_after_mirror_for_test` injection point
    inside `Container::write_metadata`. The test runs the spill +
    flush cycle twice -- once with the fence enabled (chunk-list
    blocks survive the simulated crash; vault reopens cleanly via
    mirror recovery) and once with the fence disabled via the
    thread-local skip hatch (chunk-list blocks are lost; mirror
    recovery points at slots holding pre-flush bytes; AEAD fails;
    `Vfs::open` surfaces `MetadataDeserialize` matching the
    real-world bug signature). Together with the compliance test
    above this gives both ordering verification and durability-
    semantics verification of the fence.

- **SimFile (`luksbox_format::SimFile` + `SharedSimFile`)** -- public
  test-injection helpers for any future flush-ordering invariant
  that wants a deterministic crash-impact regression. Tracks
  `backing` (page-cache view) vs `durable` (post-fsync view); a
  `crash()` method reverts `backing` to `durable`. Paired with the
  new `Container::swap_lbx_file_for_test` setter (file field now
  `Box<dyn LbxFile>` where `LbxFile: Read + Write + Seek + sync_all`,
  blanket-impl'd for `std::fs::File`) so tests can intercept all
  Container I/O without touching the disk.

### Security

- **`luksbox-vfs::Error::ReadOnlyMount`** -- added so a
  tolerant-recovery-opened vault refuses flushes / writes. Without
  this, mounting a tolerant-recovery vault and letting any FUSE
  write through (atime updates, accidental `touch`, anything that
  marks the tree dirty) would persist the size-zeroed broken
  inodes back to disk via the next flush, foreclosing any future
  brute-force recovery attempt against the original
  `chunks_external` pointers.

### Notes

- Anyone who hit this bug on v0.2.1: the lost chunk-list blocks
  are not recoverable from the live data area (the bytes never
  made it to disk). Deep recovery via an older `.meta-bak.tmp.*`
  snapshot is theoretically possible if such a file exists AND
  its older `chunks_external` pointers reference slots whose
  data chunks haven't since been reused. Not automated in this
  release.

### Known limitations

- **FIDO2 keyslots are platform-locked between Linux and Windows
  in this release.** A vault enrolled with `--kind fido2` (or any
  hybrid-PQ FIDO2 variant) on Linux fails to unlock on Windows
  with `keyslot authentication failed` (wrap variant) or
  `Header authentication failed` (direct-MVK variant); the
  reverse direction fails identically. Cause: the Linux backend
  (libfido2) feeds the raw 32 B hmac-secret salt to the
  authenticator, while the Windows backend (webauthn.dll, via
  `pHmacSecretSaltValues`) SHA-256s the salt internally before
  forwarding to the same authenticator, per W3C WebAuthn Level 3
  PRF behaviour. Same `device_secret`, two different HMAC
  outputs, two different KEKs. Neither side can be overridden
  from outside the platform library. **macOS / Linux interop is
  unaffected** (both use libfido2). Passphrase, TPM 2.0, and
  hybrid-PQ-passphrase keyslots are unaffected.

  *Workaround:* enroll a backup passphrase keyslot on either
  platform; passphrase unlock is byte-identical everywhere.

  *Fix queued for v0.3.0:* a versioned FIDO2 keyslot record
  (AAD_VERSION_V4) whose V4 form prehashes the salt on Linux as
  well, so both backends converge on
  `HMAC-SHA256(device_secret, SHA-256(salt))`. Pre-V4 slots keep
  opening on Linux for backwards compatibility; a
  `luksbox migrate-fido2-slot --slot N` helper bundles
  enroll+revoke for migrating in place. See the v0.3.0 entry
  above for details.

## [v0.2.1] - 2026-05-22

Slot-policy revisit for the multi-factor combos plus the v0.2.1
durability fix (LBM5 + LUKSBOX2 sidecar mirrors, raised metadata
cap, capacity notification, tested-boundary advisory). Existing
v0.1.1 vaults open unchanged; the behavior change is entirely at
create time for the slot-policy work, and auto-upgrades on first
flush for the durability envelope.

### Durability fix: crash-safe header + metadata writes (LBM5 / LUKSBOX2)

Fixes a real-user data-loss bug reported on v0.2.0: a vault that hit
ENOSPC mid-copy at ~13 GB with ~5000 small files became permanently
unopenable after force-quit (`blob deserialization failed` on unlock).
The two underlying causes were:

1. The metadata region cap was 16 MiB; serializing the directory
   tree for a multi-thousand-file vault overflowed it and surfaced
   as `MetadataBudgetExhausted` -> ENOSPC.
2. Both the 8 KiB header (with all keyslots) and the metadata blob
   were written in place with a plain seek+write. A crash mid-write
   destroyed the only copy. A separate failure mode produced
   "no keyslot accepted the provided unlock material" when the
   header was the corrupt region rather than the metadata.

The fix adds A/B durability for both critical regions plus a higher
metadata cap, all cross-platform (Linux, macOS, Windows):

- **`MAX_METADATA_SIZE` raised 16 MiB -> 64 MiB** with
  `DEFAULT_METADATA_REGION_SIZE` to match. New vaults reach ~40+ GiB
  of stored content before any metadata pressure.
- **LBM5 metadata format** lowers the inline chunk-ref spill
  threshold from 1024 to 256 chunks per inode, so encoded trees
  stay compact even for very large vaults. On-disk shape is
  byte-identical to LBM4; only the magic + write-side threshold
  differ.
- **LUKSBOX2 header magic** carries two new HMAC-authenticated
  flag bits (`FLAG_HAS_HEADER_MIRROR`, `FLAG_HAS_METADATA_MIRROR`)
  that signal the presence of sidecar mirrors. Pre-LBM5 binaries
  refuse the new magic via the version-major check, which is the
  correct posture (they would silently miss the recovery sidecars).
- **`<vault>.lbx.header-bak`** holds the previous-good 8 KiB header,
  rotated via temp+rename before every live header overwrite. On
  open, mirror recovery is gated **strictly** on the live header
  failing to PARSE (e.g. magic byte garbled, keyslot kind byte
  invalid, version-major / magic mismatch). Mirror recovery does
  NOT fire when the live header parses fine but unlock rejects
  the credential, because the mirror still carries previously-good
  keyslots that may have been revoked since. Without this gating,
  a user who revoked a passphrase A and persisted would find A
  still working via the mirror. The conservative gating means
  the narrow "live header parses, but keyslot AEAD bytes are
  corrupted" failure mode (a partial-write subclass) is recovered
  manually via `luksbox header-restore <vault> <vault>.lbx.header-bak
  --no-verify` rather than automatically. Manual is correct here:
  it makes the implicit "accept whatever credentials the mirror
  has" choice explicit and auditable. Detached-header vaults put
  the mirror next to the detached sidecar.
- **`<vault>.lbx.meta-bak`** holds the previous-good encrypted
  metadata region with the same rotate-then-overwrite protocol.
  `read_metadata` falls back to it on AEAD verification failure
  and marks `metadata_recovered_from_mirror` so the next `Vfs::flush`
  forces a rewrite.
- **Auto-upgrade on first flush**. A v0.2.0 vault (LUKSBOX1 + LBMx)
  is bumped to LUKSBOX2 + LBM5 the first time `Vfs::flush` runs
  against a dirty tree. The user does not need to run a migration
  command; the rollover is one-way (pre-v0.3 binaries can no
  longer open the vault afterwards).
- **Cross-platform crash safety.** All sidecar rotations go through
  `atomic_secure_write` (temp file + fsync + rename + parent dir
  fsync), which maps to POSIX `rename(2)` on Linux/macOS and
  `MoveFileExW(REPLACE_EXISTING)` on Windows. Directory fsync is
  strict on POSIX, best-effort on Windows (NTFS journals the
  rename via `MoveFileExW`, so the rename is durable on return).
- **Disk cost.** Each v0.2.1+ vault keeps one 8 KiB header-bak plus
  one `metadata_size`-bytes meta-bak alongside the .lbx file
  (16 MiB for upgraded v0.2.0 vaults, 64 MiB for new vaults). For
  the typical encrypted-backup-on-USB use case this is rounding
  error; for tiny demo vaults, `--metadata-size` shrinks the
  region (and therefore the mirror).
- **Security posture preserved.** Mirrors are AEAD/HMAC-bound to
  the same MVK as live, so a forged or attacker-substituted mirror
  fails verification and the open path surfaces the live error.
  The anchor sidecar's rollback check still runs against the
  recovered header. MVK rotation
  (`begin/commit_atomic_rotation`) explicitly **deletes** both
  sidecar mirrors at commit time so the post-rotation vault
  cannot fall back to OLD-MVK-encrypted keyslots; fresh mirrors
  are written on the next live overwrite. Mirror file reads are
  stat-then-bounded so an attacker-planted symlink to `/dev/zero`
  cannot OOM the recovery path.
- **Recovery is not unbounded forgiveness.** Two-level corruption
  (both live and mirror garbled) surfaces the live error as
  before; recovery only saves the user when at most ONE of the
  two regions was destroyed by the crash.

Migration policy: deliberately additive. Old vaults remain
read-supported indefinitely; the upgrade triggers only on first
flush. No `metadata_size` relocation in this release (that would
require moving the data region, which is the dangerous part of any
durability migration).

### Metadata-budget capacity notification

Vaults holding very large inode counts (hundreds of thousands of
files) can approach the 64 MiB metadata region cap before they
exhaust host disk space. Without a notification, the first sign
the user would see is a hard "no space left on device" error
mid-copy (the exact failure that motivated the durability fix).

v0.2.1 emits a soft notification BEFORE the hard ENOSPC, on two
thresholds:

- **>=75% used**: informational. CLI users see a one-line
  message on stderr; GUI users see a non-blocking toast.
- **>=90% used**: stronger warning recommending content
  archival or migration to a new vault with a larger
  `--metadata-size`.

Notifications fire at most once per level per session. The
metadata budget status is exposed as `Vfs::metadata_budget_status()`
returning a `MetadataBudgetStatus { used_bytes, budget_bytes }`
struct with `used_pct`, `near_capacity` (>=75%), and
`critical_capacity` (>=90%) accessors so external tooling can
build dashboards or pre-flight checks.

Deniable vaults DO NOT participate in this notification through
the sidecar-mirror mechanism: deniable vaults deliberately opt
out of every observable LUKSbox-shaped sidecar. They still get
the `MetadataBudgetExhausted` -> ENOSPC backstop and the
`Vfs::metadata_budget_status` API for in-app status display.

See `docs/CRYPTO_SPEC.md` -- "Metadata budget and capacity
notification (v0.2.1+)" for the full design and mitigation
options once a warning fires.

### Tested-boundary advisory (v0.2.1)

v0.2.1 has been ground-truth validated end-to-end (real FUSE
mount, write, force-quit, reopen, verify) up to roughly **30 GiB
of stored content** with several thousand files. The format is
engineered for larger vaults but usage beyond that boundary has
not yet been explicitly tested.

LUKSbox surfaces a one-shot heads-up at two moments:

- At create time: `luksbox create` prints an advisory noting the
  tested boundary so users planning very large vaults know
  upfront.
- At runtime: when `Vfs::flush` notices the on-disk vault size
  has crossed 30 GiB, a one-shot eprintln (CLI) or toast (GUI)
  asks the user to verify the vault still unlocks (the v0.2.0
  failure mode was specifically "can't reopen after force-quit",
  so periodic close+reopen catches that class early) and to
  report any anomalies.

The advisory is informational, not a hard limit. The boundary
will be raised in subsequent releases as validated usage data
accumulates. See `docs/PROJECT_OVERVIEW.md` section 5.4 for the
user-facing guidance.

Deferred:

- CLI `luksbox repair` / `luksbox health` subcommands (manual
  recovery / mirror staleness warning). Automatic recovery covers
  the load-bearing case; tooling is convenience.
- LUKSBOX1 -> LUKSBOX2 in-place header relocation. Not needed
  with the additive sidecar design.

### macFUSE Apple-build fix

Linux-only `renameat2(2)` flag constants (`RENAME_EXCHANGE`,
`RENAME_WHITEOUT`, `RENAME_NOREPLACE`) are exposed by the `fuser`
crate's `RenameFlags` only under `#[cfg(target_os = "linux")]`,
so the macFUSE build broke when the shared `fuse.rs` file
referenced them unconditionally. The Linux rename handler now
cfg-gates the entire flag check: on macOS / Windows the
`renameat2` flags don't exist in the FUSE protocol and the check
is moot. Linux behavior unchanged.

### Install note: Trixie deb + plain `su root`

`dpkg -i luksbox_*.deb` aborts on Debian 13 with
`dpkg: error: 2 expected programs not found in PATH or not
executable` (ldconfig, start-stop-daemon) when run from a shell
where root's `PATH` lacks `/sbin`. This happens when you switch
to root via `su root` rather than `su -` (the latter loads
root's login PATH which includes `/sbin`). Dpkg's pre-flight
check fails BEFORE any maintainer script runs, so we cannot fix
it inside the package. Workarounds:

- `sudo dpkg -i luksbox_*.deb` (sudo honors `secure_path` in
  `/etc/sudoers`, which contains `/sbin`)
- `su -` then `dpkg -i ...` (login shell loads root's PATH)
- `export PATH="$PATH:/sbin:/usr/sbin" && dpkg -i ...` before
  running install

The `dist/install.sh` driver uses `sudo` and is not affected.

### Security audit follow-up (filesystem-boundary hardening)

Round of fixes for findings on the path-handling / TOCTOU surfaces.
All vaults stay readable; the changes harden write paths and the
deniable open path against attacker-controlled parent directories
and symlink-swap scenarios. The reporter who flagged these can be
credited via `security@penthertz.com`.

- **Panic-destroy symlink TOCTOU** (`luksbox panic` CLI, wizard,
  GUI). The previous flow did `path.is_file()` (follows symlinks)
  then `OpenOptions::open(path)` (also follows symlinks) -- an
  attacker who could write to the vault's parent directory could
  swap in a symlink between the check and the open, redirecting the
  random-bytes overwrite to a file of their choice. With `--wipe-data`
  the blast radius was the entire file size; run as root, this was
  arbitrary-file-overwrite via a deliberate destructive command.
  Now all three callsites use a new
  `luksbox_core::file_util::secure_open_existing_no_follow` helper
  that opens with `O_NOFOLLOW` (Unix) / `FILE_FLAG_OPEN_REPARSE_POINT`
  (Windows) and refuses non-regular files. The handles are opened
  BEFORE the confirmation prompt so the prompt itself can no longer
  be raced.
- **Deniable open bypassed `LUKSBOX_NO_FOLLOW_SYMLINKS`.**
  `Container::try_open_envelope_v2_deniable` and
  `Container::open_with_mvk_deniable` used raw `OpenOptions` and
  skipped the hardened `open_rw_checked` + post-lock
  `verify_path_inode` path that the standard `Container::open`
  takes. Now both deniable entry points go through the same hardened
  path. Users who set `LUKSBOX_NO_FOLLOW_SYMLINKS=1` get the same
  policy on deniable vaults that they already got on standard
  vaults.
- **Deniable mount mountpoint check.** Standard `luksbox mount` uses
  `O_DIRECTORY | O_NOFOLLOW` + canonical-path deny-list +
  immediately-before-mount inode re-probe.
  `luksbox deniable-mount` was using only `is_dir() + canonicalize()`,
  which is TOCTOU-racy and skips the deny-list. Now deniable mount
  uses the same hardened mountpoint check, including the deny-list
  refusing system directories.
- **Header-backup no-clobber race.** `luksbox header-backup` did
  `out.exists()` then `secure_create_or_truncate(out)` -- racy. An
  attacker who created a file at the destination in the window
  between check and create had it truncated. Now uses
  `atomic_secure_create_new` (POSIX `link(2)` / Windows
  `MoveFileExW(0)`) which fails the rename if the target appeared
  in the meantime.
- **Mount canonicalize-before-open.** `cmd_mount` was calling
  `path.canonicalize()` BEFORE `open_vfs`, so when
  `LUKSBOX_NO_FOLLOW_SYMLINKS=1` was set the symlink had already
  been resolved by the time the no-follow check fired inside
  `open_rw_checked`. Same problem in the FUSE-T helper for both
  vault and `--header` paths. Added a `LUKSBOX_NO_FOLLOW_SYMLINKS`
  preflight (via `std::fs::symlink_metadata`) that runs BEFORE
  canonicalize.
- **Unlock prescan honors no-follow policy.** The kind-dispatch
  header peek (~14 callsites across CLI + GUI for hybrid / TPM /
  FIDO2 routing) used raw `File::open` which followed symlinks
  even with the policy gate set. Now routed through a new
  `luksbox_core::file_util::open_existing_read_no_follow_policy`
  helper. Default behaviour (env var unset) still follows symlinks
  so legit users aren't broken.

8 new tests across `luksbox-core`, `luksbox-format::tests::security_invariants`,
and `luksbox-cli::tests::functional` pin the regressions, including a
real end-to-end `panic -y --wipe-data` against a symlinked path that
verifies the sentinel file is byte-for-byte unchanged.

### v4 metadata format (NEW DEFAULT) - persistent chmod, hardlinks, symlinks

A new on-disk metadata format ("v4", magic `LBM\x04`) extends v3
with two per-inode fields, `mode: u32` (POSIX mode bits) and
`link_count: u32` (POSIX hardlink count), and a new
`InodeKind::Symlink` variant carrying an in-vault target string.
v4 is the default for newly-created vaults; existing v2/v3 vaults
stay in their original format on flush UNLESS an LBM4-only feature
is used (a chmod to a non-default mode, a link that produces
nlink>1, or any symlink). The auto-upgrade is one-way: once a
vault is written as LBM4, pre-v0.3 LUKSbox binaries can no longer
open it. The env-var opt-out (`LUKSBOX_FORMAT_V2=1`) still works
for users who need to keep new vaults openable by older binaries
-- they just lose the new features.

What the format change enables, end-user-visible:

- **Persistent `chmod`**. `chmod 0o755 script.sh` survives unmount
  and remount; mode bits are stored in the inode rather than
  synthesised on every stat. `git`'s `core.filemode` probe sees
  the change take effect, so executable bits on shell scripts /
  cmd.com binaries / etc. survive a vault checkout.
- **POSIX hardlinks**. `ln file linkname` creates a true hardlink
  (shared inode, both names report `nlink=2`, writing through one
  is visible through the other). The refcount-aware `unlink`
  decrements `link_count` instead of freeing chunks on the first
  removal -- a file with N hardlinks survives N-1 unlinks. Last
  unlink frees chunks the same way pre-LBM4 vaults always did.
- **Symlinks** (with strict target sanitization, see below).

### Symlink supply-chain defense

LUKSbox symlinks are validated by `is_safe_symlink_target` at three
layers (create time, vault-open / load time, and flush time). The
function rejects:

- Absolute targets (start with `/`, `\`, or a Windows drive-letter
  prefix like `C:foo`)
- Targets containing `..` or `.` components (anywhere, not just
  leading)
- NUL bytes (would silently truncate at the C-string boundary
  when crossing the FUSE callback)
- Targets exceeding `MAX_SYMLINK_TARGET_LEN` (PATH_MAX = 4096)
- Empty targets

This closes the `secret -> /etc/shadow` supply-chain attack class:
an attacker who distributes a vault with a passphrase they control
cannot embed a symlink that would, when traversed by a victim's
file manager or `cat`, exfiltrate host files under the victim's
UID. The kernel surfaces `EINVAL` (LUKSbox `Error::InvalidPath`)
to user-space, so `ln -s /etc/shadow evil` inside a mounted vault
fails the same way as creating an invalid filename. The same
defense fires at vault open time, so a vault forged outside
LUKSbox (e.g. via a metadata-blob edit) is refused before any
FUSE `readlink` callback can return the malicious bytes.

Ground-truth verified: `git clone https://github.com/PentHertz/LUKSbox.git`
+ `chmod +x` + `ln target alias` + `ln -s real link` all work
inside a mounted vault, survive unmount/remount, and the four
attack-string symlink-creation attempts (`/etc/shadow`,
`../../../etc/shadow`, `valid/../../etc/shadow`, `C:\Windows\...`)
all return `EINVAL` immediately.

### POSIX rename(2) semantics

`Vfs::rename` was missing two cases POSIX requires; both are now
fixed. Both affected git, sqlite WAL checkpointing, and every
editor that uses the standard "write temp + rename onto target"
atomic-write idiom -- the symptom that surfaced this was
`git clone` failing with "could not write config file ... File
exists".

- **Replace-on-conflict**. Rename onto an existing target now
  replaces (POSIX requirement). The displaced inode's data chunks
  AND v3 chunk-list blocks return to `free_chunks` (same path as
  `unlink`), so the replace never leaks ciphertext storage.
  Pre-fix code returned `AlreadyExists` and broke every atomic-
  write tool. Type compatibility is enforced first: file -> dir is
  rejected with `IsADirectory`, dir -> file with `NotADirectory`,
  dir -> non-empty dir with `NotEmpty`.
- **Cross-directory rename**. `Vfs::rename` now takes
  `(old_parent, old_name, new_parent, new_name)` and moves inodes
  between parents in a single atomic operation. A new
  `Vfs::is_descendant_of` cycle guard refuses moves that would
  put a directory inside its own subtree (POSIX `EINVAL`), using
  a visited-set so the traversal terminates even on a corrupt
  vault with pre-existing cycles. FUSE / FUSE-T / WinFsp callers
  all now honour cross-dir rename instead of returning
  `ENOSYS` / `STATUS_ACCESS_DENIED`.
- **`RENAME_NOREPLACE` flag honoured** on FUSE, **`MoveFileEx`
  `MOVEFILE_REPLACE_EXISTING=false`** honoured on WinFsp:
  applications that explicitly want EEXIST/COLLISION still get it.

### Cross-platform zip-slip defense on vault entry names

`validate_name` now rejects `\` (backslash) on every host, not just
`/`. A vault entry name like `..\..\Windows\System32\drivers\etc\hosts`
would pass the old `/`-only check on Linux but, when the GUI's
"extract directory" feature ran `local.join(&ent.name)` on a
Windows host, `Path::join` would treat `\` as a separator and
escape the destination -- the classic CVE-2018-1002200 ("zip slip")
class. The legitimate use-case cost is "Linux files containing
`\` in their names can't be added to a vault", which we accept as
a security/portability win. The GUI extract path also got a
`name_escapes_directory` defense-in-depth check that re-rejects
anything containing `/`, `\`, `..`, or `.` before joining.

`validate_name` also gained a `MAX_NAME_LEN_BYTES = 255` cap (NAME_MAX)
to prevent programmatic callers from bloating the metadata blob
with megabyte-sized filenames.

### Cycle-guard hardening against corrupted vaults

The rename cycle guard (`is_descendant_of`) now walks `children`
regardless of inode `kind`. The well-formed invariant says "only
Directory inodes have non-empty `children`", but if a corrupted or
attacker-influenced vault carries a File-kind inode with non-empty
children (an LBM4 forgery, or a future bug), skipping by kind
would let those children hide from the cycle check -- a rename
into one of them would then create a real directory cycle, and the
next readdir / flush / rotate_mvk traversal would loop forever.
Walking unconditionally is free on well-formed vaults.

### v3 metadata format (NEW DEFAULT) + bigger v2 default

A new on-disk metadata format ("v3", magic `LBM\x03`) moves per-file
chunk lists out of the fixed metadata region into encrypted
**chunk-list blocks** stored in the data area alongside the file's
data chunks. The previous format (v2, `LBM\x02`) capped per-vault
content at roughly 8-10 GiB because the inline `Vec<ChunkRef>` for
large files would overflow the 16 MiB metadata budget; v3 removes
that ceiling.

- **Default for new vaults.** v3 is now the default on `luksbox create`,
  in the wizard, and in the GUI. Pre-v0.2.0 LUKSbox binaries cannot
  open v3 vaults (LBM3 magic mismatch yields a clean
  `metadata blob deserialization failed`, not silent corruption).
  Pass `--format v2` (or pick v2 in the wizard / GUI) when you need
  to keep a new vault readable by an older LUKSbox install.
- **Opt-out via env var.** `LUKSBOX_FORMAT_V2=0` (or `false`/`no`/`off`)
  in the environment forces v2 for any fresh create on that process.
  The historic env var name is kept so scripts that opted IN to v3
  during the v0.2-dev cycle still work unchanged.
- **Performance.** Measured open at 1 GiB / 262K chunks ~ 19 ms;
  extrapolates to ~2 s at 100 GiB. Lazy loading not needed.
  See `crates/luksbox-vfs/src/vfs.rs::v3_open_perf_baseline` (run with
  `cargo test --release -- --ignored --nocapture v3_open_perf_baseline`).
- **Forward-compat break.** LUKSbox binaries older than this
  release refuse v3 vaults cleanly (`metadata blob deserialization
  failed` -- the magic byte mismatch is the safe failure mode, not
  silent corruption).
- **Migration.** `luksbox migrate-to-v3 <src> --dst <new>` reads a
  v2 vault and writes a fresh v3 vault with the same cipher and
  data; source vault is left untouched. The destination is created
  with a single passphrase keyslot; other keyslots can be
  re-enrolled afterward via `luksbox enroll`. Deniable vaults can
  now be created in v3 format directly (wizard prompts for it after
  the cipher/KDF choice); a `migrate-to-v3` path for deniable is
  not yet wired (deniable open is interactive -- re-create as v3
  using your existing cipher/KDF params and copy your files in).
- **MVK rotation** for v3 vaults now also re-keys the chunk-list
  blocks under the new MVK (regression-tested in
  `v3_rotate_mvk_reencrypts_chunk_list_blocks`).
- **AAD isolation** between data chunks and chunk-list blocks is
  guaranteed by deriving the list-block file_key from a synthetic
  file_id (real `file_id | (1 << 63)`); a data chunk's ciphertext
  cannot be reinterpreted as a chunk-list block or vice versa.
- **Default metadata-region size bumped from 1 MiB -> 16 MiB.** The
  previous 1 MiB default silently lost data around ~800 MiB of
  stored content because the metadata region overflowed at flush
  but the data chunks had already landed on disk. The new 16 MiB
  default + the mid-write `ENOSPC` pre-flight check together
  eliminate both the ceiling shrinkage and the silent-loss bug.
- **New CLI flag**: `luksbox create --metadata-size <BYTES>`
  (64 KiB - 16 MiB) lets advanced users tune the metadata region
  for v2 vaults.

See `docs/CRYPTO_SPEC.md` for the on-disk layout and AEAD
construction of chunk-list blocks.

### Security audit, Round 13 - closed cleanly

Internal Round-13 sweep across filesystem-boundary races, header
durability, sidecar DoS surfaces, and remaining secret-copy
hygiene. Full per-finding report at
[docs/SECURITY_AUDIT_ROUND_13.md](docs/SECURITY_AUDIT_ROUND_13.md).

**Total findings: 2 HIGH, 5 MEDIUM, 2 LOW, 1 INFO. No CRITICAL.
ALL shipped fixes this revision.**

**Fixed**

- **R13-01 (HIGH)** `secure_create_or_truncate` (the helper behind
  `luksbox get` and GUI extract) now opens the destination through
  `openat(parent_dir_fd, basename, ...)` against a canonical
  parent fd on Unix, closing the intermediate-directory symlink-swap
  window. Permission narrowed via `fchmod` on the open fd (no path
  traversal). Windows reparse-point rejection retained.
- **R13-02 (HIGH)** `luksbox header restore` no longer re-opens the
  vault path after the HMAC verify. New
  `Container::restore_header_bytes` reuses the container's
  already-verified, already-inode-bound `self.file` handle (inline)
  or routes through `atomic_secure_write` (detached). The
  `--no-verify` direct write adds `O_NOFOLLOW` (Unix) / reparse-point
  rejection (Windows).
- **R13-03 (MEDIUM)** `Vfs::real_size` now clamps the chunk-0
  authenticated u64 against the inode's chunk capacity. Hostile
  hide-size vaults can no longer panic stat / read / mount via an
  out-of-range `inode.chunks[idx]`.
- **R13-04 (MEDIUM)** `Container::persist_header` uses `sync_all()`
  on inline + deniable, and `atomic_secure_write` (temp + fsync +
  rename + sync_parent_dir) on detached, then re-opens the lock
  handle to the new inode. A power loss mid-persist no longer
  leaves a half-rewritten header / sidecar.
- **R13-05 (MEDIUM)** `.kyber` seed-file reads open with
  `O_NOFOLLOW` (Unix) / reparse-point rejection (Windows), require
  a regular file of exactly the fixed format length, then
  `read_exact`. Refuses FIFO / device / oversize swaps.
- **R13-06 (MEDIUM)** Hybrid sidecar reader preflights `metadata()`,
  requires a regular file under 32 KiB, then `read_exact`. Closes
  the unbounded `read_to_end` path on both Unix and Windows
  (Windows now also rejects reparse points).
- **R13-07 (MEDIUM)** New `luksbox_vfs::MAX_FILE_SIZE = 1 << 44`
  cap + `Error::FileSizeExceedsCap` variant. `write` and `truncate`
  refuse oversize targets BEFORE `padded_chunk_count` can feed
  `next_power_of_two` a panicking value or the chunk-allocation
  loop can exhaust RAM / disk.
- **R13-08 (LOW)** `luksbox-mount`'s FUSE `read` caps the
  requester-supplied `size` at 16 MiB internally before the vec
  allocation. Defence-in-depth against a buggy or hostile kernel
  module along the path.
- **R13-09 (LOW)** `SecretBox::clone` now allocates a fresh
  secret-memory backing and `copy_from_slice`s directly between
  the two allocator-owned regions. No by-value `[u8; KEY_LEN]`
  Copy temporary on the caller's stack.

**New tests + harnesses**

- `crates/luksbox-core/tests/round13_file_util.rs` (4 tests)
- `crates/luksbox-format/tests/round13_findings.rs` (4 tests)
- `crates/luksbox-vfs/tests/round13_findings.rs` (3 tests)
- `crates/luksbox-pq/tests/round13_seed_file.rs` (3 tests)

Run any of them locally with `cargo test --test round13_findings -p
<crate>`; the workspace-wide `cargo test --workspace
--exclude luksbox-gui` exercises them as part of CI's normal flow.

### Security audit, Round 12 - closed cleanly

Four-axis adversarial sweep across the FUSE-T subprocess path, the
deniable header v2 implementation, the filesystem TOCTOU surface,
and the memory-safety + secrets-hygiene posture. Full per-finding
report + Fix-status table at
[docs/SECURITY_AUDIT_ROUND_12.md](docs/SECURITY_AUDIT_ROUND_12.md).

**Total findings: 1 CRITICAL, 5 HIGH, 7 MEDIUM, 6 LOW. ALL shipped
fixes this revision.** R12-14 is formally superseded by R12-11's
canonical-path verify (inverting `open_rw_checked`'s default would
break legitimate `~/vault.lbx -> /mnt/usb/...` workflows for no
remaining security gain).

**Fixed**

- **R12-01 (CRITICAL)** Deniable envelope discovery loop is now
  constant-time. `try_open_envelope_v2` runs identical work per slot
  (always-allocate fixed scratch, always-memcpy via `Choice`-driven
  byte selection); `SlotPayload::decode` runs ONCE after a
  `subtle::Choice`-driven slot-index pick, so the variable-length
  heap allocations happen exactly once on a fixed-position buffer.
  Pinned by the new `dudect_deniable_envelope` bench (proves
  constant-time at the wall-clock level) and the multi-slot
  `deniable_envelope_multi_slot` libFuzzer + AFL++ target.
- **R12-02 (HIGH)** CLI `deniable-mount --credential pq-*` now
  accepts a blank seed-file passphrase as "reuse envelope",
  matching the GUI and wizard. The two CLI create helpers
  (`cli_create_pq_passphrase_deniable_v2` and
  `cli_create_pq_fido2_deniable_v2`) now also share the same
  blank-= reuse default. New helper `cli_pq_decap_with_fallback`.
- **R12-03 (HIGH)** Helper subprocess canonicalizes `--header`
  before opening; sandbox profile gains a `${HEADER_DIR}`
  parameter with matching `(subpath ...)` allow rules for read +
  write.
- **R12-04 (HIGH)** `MountBackend::Subprocess` now has `impl Drop`
  that kills + reaps the helper child on GUI panic / force-quit /
  unclean shutdown.
- **R12-05 (HIGH)** `cmd_mount_fuse_t_helper` uses the same
  `O_DIRECTORY|O_NOFOLLOW` probe + `validate_mountpoint_safety`
  deny-list as the parent `cmd_mount`. Both code paths now share
  the Round 11 TOCTOU hardening.
- **R12-06 (HIGH)** Hybrid sidecar reads (`read_bundle` and
  `peek_vault_header_salt`) route through a new `O_NOFOLLOW`-protected
  helper on Unix. Symlinked `.hybrid` files fail with `ELOOP` at
  the format layer.
- **R12-07 (MEDIUM)** GUI canonicalizes vault + mountpoint +
  header BEFORE deriving the sandbox `subpath` parameters.
- **R12-09 (MEDIUM, partial)** `secure_create_or_truncate`
  rejects extracts whose canonical parent lands under `/etc`,
  `/usr`, `/bin`, `/sbin`, `/boot`, `/sys`, `/proc`, `/dev`,
  `/System`, or `/Library/System`. Full `openat()`-based
  directory-fd traversal still tracked for Round 13.
- **R12-10 (MEDIUM)** MVK rotation `.rotating` tmp file is now
  created with `O_CREAT|O_EXCL|O_NOFOLLOW` at mode 0600 BEFORE
  the source bytes are copied in.
- **R12-12 (MEDIUM)** Helper MVK stdin buffer wrapped in
  `Zeroizing<[u8;32]>` so a `read_exact` error-path `?` can no
  longer leak partial bytes.
- **R12-13 (MEDIUM)** Deniable trial-decrypt `cand_bytes` wrapped
  in `Zeroizing` so the storage (not just a Copy decoy) is wiped
  on scope exit.
- **R12-16 (LOW)** `sanitize_vault_name_for_mount` rejects `:`
  and caps by BYTE length (200), preventing `ENAMETOOLONG` from
  complex-script grapheme expansion.
- **R12-18 (LOW)** TPM `SensitiveData::try_from(plaintext.to_vec())`
  wraps the intermediate `Vec<u8>` in `Zeroizing`.

**Empty-passphrase warnings (Round 12 follow-up)**

In response to a follow-up ask, the CLI's
`read_passphrase_confirmed` now mirrors the wizard's
`ask_new_passphrase` and the GUI's
`draw_empty_passphrase_confirm_modal`: an empty passphrase prompts
an explicit "Use empty passphrase anyway?" confirm (default `no`),
with `LUKSBOX_ACCEPT_EMPTY=1` as the scripted-automation escape
hatch. All three frontends now warn the user before silently
shipping a credential-less vault.

**Fixed (continued)**

- **R12-08 (MEDIUM)** `cmd_mount` re-probes the canonical mountpoint
  inode via `O_DIRECTORY\|O_NOFOLLOW` IMMEDIATELY before the mount
  syscall and refuses if it changed. Bounds the residual race from
  "open-to-mount" to "between two adjacent syscalls".
- **R12-11 (MEDIUM)** `open_rw_checked` captures the CANONICAL path
  at successful open; `verify_path_inode` opens that canonical path
  with `O_NOFOLLOW`. Catches the post-lock symlink-swap attack while
  preserving legitimate symlinked-vault workflows.
- **R12-14 (LOW)** Formally superseded by R12-11 (see audit doc).
- **R12-15 (LOW)** Anchor + extract opens now pass
  `FILE_FLAG_OPEN_REPARSE_POINT` on Windows and refuse the file if
  `FILE_ATTRIBUTE_REPARSE_POINT` is set, mirroring the Unix
  `O_NOFOLLOW` semantic for symlinks / junctions / mount points.
- **R12-17 (LOW, partial)** New `MasterVolumeKey::from_zeroizing` +
  `KeyEncryptionKey::from_zeroizing` constructors take a reference
  to a `Zeroizing<[u8;KEY_LEN]>` instead of a by-value `Copy` array,
  eliminating the stack-residence pattern at the type level. Helper
  subprocess MVK construction migrated; `from_bytes` retained for
  test code and back-compat.
- **R12-19 (LOW)** `HmacSecret` is now a `pub struct HmacSecret([u8;32])`
  newtype with `Zeroize + ZeroizeOnDrop`, `Deref`, redacted `Debug`,
  and constant-time `PartialEq`. All three backends (libfido2,
  webauthn, mock) construct the newtype on the way out.

**New test infrastructure**

- `crates/luksbox-format/tests/round12_findings.rs` - 7 tests
  (was 7 with 5 `#[ignore]`d; now 7 with 0 `#[ignore]`d after fixes
  landed). Each HIGH finding has a deterministic regression test
  that drives the relevant code path and asserts the post-fix
  behaviour. R12-05 and R12-03 use `CARGO_BIN_EXE_luksbox` to
  spawn the CLI; R12-06 calls `read_bundle` directly with a
  symlinked sidecar and asserts `ELOOP`. Run with:
  ```bash
  cargo test --test round12_findings -p luksbox-format
  ```
- `fuzz/fuzz_targets/deniable_envelope_multi_slot.rs` (libFuzzer)
  and `fuzz-afl/src/bin/deniable_envelope_multi_slot.rs` (AFL++).
  Shared seed corpus at
  `fuzz/corpus/deniable_envelope_multi_slot/seed_*` and
  `fuzz-afl/seeds/deniable_envelope_multi_slot/seed_*`. Wired into
  `.github/workflows/ci.yml` (5-min smoke), `.github/workflows/fuzz-nightly.yml`
  (30-min sweep), and `scripts/fuzz_server.sh::TARGETS`.
- `crates/luksbox-format/benches/dudect_deniable_envelope.rs` -
  statistical timing bench gated behind `cargo bench` (not part of
  the default CI run; reproducer for R12-01).

**Reproduction**

Every finding is reproducible from a clean checkout - see the
"Reproduction" section of
[docs/SECURITY_AUDIT_ROUND_12.md](docs/SECURITY_AUDIT_ROUND_12.md).
The dudect bench prints a `|t|` value > 3.0 today and < 3.0 after
the fix. Each `#[ignore]`d test in `round12_findings.rs` has a
one-line `cargo test ... -- --ignored <name>` invocation in the
audit doc.

**Verified-OK invariants (re-audit)**

Round 12 re-walked every property Round 11 left standing. AAD
binding, empty-slot indistinguishability, slot-pad randomness,
nonce freshness, Argon2-params-not-in-header, compile-time-blocked
pure-FIDO2/TPM v1 variants, error opacity at format and container
layers, sandbox hard-fail, mlockall attempt in helper, memfd_secret
wired with graceful fallback, no `transmute` / no pointer arithmetic
on attacker-controlled lengths - all confirmed unchanged.


### Deniable header v2

v2 design landed in [docs/DENIABLE_HEADER.md](docs/DENIABLE_HEADER.md).
Full implementation shipped this revision:

- **Format constants bumped.** `DENIABLE_SLOT_SIZE` 512 -> 4096,
  `DENIABLE_HEADER_SIZE` 8192 -> 36864. AAD prefix
  `luksbox-deniable-v1` -> `luksbox-deniable-v2`. v1 was never
  released publicly so this is a clean break.

- **Two-layer envelope encryption.** Each v2 slot is `AEAD(KEK_envelope,
  payload)` where the payload contains `kind`, embedded `cred_id` /
  `hmac_salt` / `tpm_blob` (per variant), and an inner `wrapped_mvk =
  AEAD(KEK_factors, MVK)`. `KEK_envelope = Argon2id(passphrase, salt)`
  is the discovery key; `KEK_factors = HKDF(per_vault_salt, envelope_kek
  || <secondaries>, info-label)` combines the envelope with the
  per-variant secondary factor outputs. Distinct AADs on the outer
  envelope and inner MVK prevent cross-slot ciphertext reuse.

- **Passphrase mandatory for every deniable credential.** Pure-FIDO2,
  pure-TPM, and non-passphrase multi-factor deniable variants from v1
  are removed from the user-facing flows (chicken-and-egg constraint:
  no slot envelope key exists without a discovery factor). New
  `*Passphrase` variants ship in `DeniableCredential`:
  `TpmFido2Passphrase`, `HybridPqFido2Passphrase`,
  `HybridPqTpmPassphrase`, `HybridPqTpmFido2Passphrase`. v1 variants
  (`Fido2`, `Tpm`, `TpmFido2`, `HybridPqFido2`, `HybridPqTpm`,
  `HybridPqTpmFido2`) are retained as v1-compat enum members so the
  enroll-slot administrative paths (which haven't migrated to v2 yet)
  continue to compile; they are no longer reachable through the
  deniable-create or deniable-open user paths.

- **`.tpm-blob` sidecar eliminated for deniable mode.** TPM sealed
  blobs (typically 1.5-3 KB) now live inside the slot envelope. The
  `.lbx.tpm` file is no longer written at create time. The
  `.kyber` / `.hybrid` sidecars for hybrid-PQ are retained (the
  ML-KEM seed + ciphertext have their own passphrase wrapper and
  don't benefit from in-envelope embedding).

- **External-material CLI flags removed.** `deniable-mount` and
  `deniable-info` no longer accept `--tpm-blob-path`,
  `--fido2-cred-id`, or `--fido2-hmac-salt` - those values are
  recovered from the slot envelope automatically once the
  passphrase opens it. `--kyber-path` is retained (PQ sidecar
  stays).

- **TUI wizard simplified.** `DeniableRecoveryInfo` collapses to an
  empty marker; the post-create "save this recovery info now" page
  no longer prints hex `cred_id` / `hmac_salt` / sidecar path. The
  open-deniable flow drops the "type your cred_id (hex)" /
  "type your hmac_salt (hex)" / ".tpm-blob path" prompts.

- **GUI create + open migrated to v2.** `Container::create_vault`
  routes deniable mode through `create_with_credential_v2_deniable`
  with `DeniableMaterial`; `Container::unlock_vault` uses the
  two-phase `try_open_envelope_v2_deniable` + `complete_open_v2_deniable`
  pattern. Recovery-card modal no longer surfaces FIDO2 hex values.

- **New format-crate API.** `Container::create_with_credential_v2_deniable`,
  `Container::try_open_envelope_v2_deniable`,
  `Container::complete_open_v2_deniable`, and
  `Container::enroll_credential_v2_deniable` are the canonical v2
  surface. `DeniableMaterial { cred_id, hmac_salt, tpm_blob }`
  encapsulates what gets embedded.

- **Slot-payload encoder/decoder.** New
  `luksbox_core::deniable::slot_payload` module: `SlotPayload::new` +
  `encode` + `decode`. Length-capped at `CRED_ID_MAX_LEN = 1024`,
  `HMAC_SALT_LEN = 32`, `TPM_BLOB_MAX_LEN = 3500`, joint budget
  4000 B. 9 round-trip / rejection tests cover encode-then-decode,
  per-kind shape, over-budget rejection, unknown-kind rejection,
  bad-length rejection.

- **v2 round-trip tests.** New tests in
  `crates/luksbox-format/src/deniable_header.rs`:
  `v2_create_then_open_round_trips_passphrase_only`,
  `v2_round_trip_with_fido2_material_embedded`,
  `v2_round_trip_with_tpm_blob_embedded`,
  `v2_wrong_passphrase_returns_opaque_error`,
  `v2_complete_open_rejects_variant_mismatch`.

- **Admin enroll-into-deniable migrated to v2.** All
  `enroll_*_deniable` functions in `crates/luksbox-gui/src/ops.rs`
  now take `passphrase: &str` + `argon2: Argon2idParams` and route
  through `Container::enroll_credential_v2_deniable` with embedded
  material. Affected: `enroll_fido2_deniable`,
  `enroll_tpm2_deniable`, `enroll_tpm2_fido2_deniable`,
  `enroll_hybrid_pq_tpm2_deniable`,
  `enroll_hybrid_pq_tpm2_fido2_deniable`. The dead
  `enroll_tpm2_pin_deniable` (which always errored with "not yet
  wired") is removed; the v2 envelope passphrase subsumes the
  TPM-side PIN. The bootstrap-deniable dispatch in
  `create_vault_with_tpm_bootstrap` reuses the create-time
  passphrase for the new TPM slot's envelope.

- **`AddFido2Form` (GUI) gains `deniable_passphrase` +
  `deniable_kdf`** fields. The "Add FIDO2 keyslot" modal surfaces
  them when the open vault is in deniable mode; ignored otherwise.

- **v1 dead-code cleanup.** Removed the now-unreachable v1
  standalone helpers `fido2_hmac_salt`, `fido2_kek`,
  `tpm_fido2_kek`, `pq_hybrid_kek` from
  `crates/luksbox-core/src/deniable.rs`; removed the HKDF labels
  `FIDO2_SALT`, `FIDO2_KEK`, `TPM_FIDO2_KEK`, `PQ_CLASSICAL`,
  `PQ_HYBRID_KEK` that only they used; removed
  `tpm_seal_for_deniable` + `tpm_blob_sidecar_path` from
  `crates/luksbox-gui/src/ops.rs` (no caller after the enroll
  migration above).

- **v1 surface fully stripped.** Container tests migrated to the
  v2 API (17 deniable container tests now exercise
  `create_with_credential_v2_deniable` +
  `try_open_envelope_v2_deniable` + `complete_open_v2_deniable`).
  After the test migration the following were removed:
  - v1 `DeniableCredential` variants `Fido2`, `Tpm`, `TpmFido2`,
    `HybridPqFido2`, `HybridPqTpm`, `HybridPqTpmFido2`
  - v1 single-step `DeniableCredential::derive_kek` wrapper
  - v1-compat HKDF labels (`KEK_FIDO2`, `KEK_TPM`,
    `KEK_TPM_FIDO2`, `KEK_PQ_FIDO2`, `KEK_PQ_TPM`,
    `KEK_PQ_TPM_FIDO2`)
  - v1 `deniable_header::{create_with_passphrase,
    open_with_passphrase, create_with_credential,
    open_with_credential, install_slot_with_credential,
    install_slot, rotate_mvk}`
  - v1 `Container::{create_with_credential_deniable,
    open_with_credential_deniable, enroll_credential_deniable}`
  - All v1 deniable_header tests (`create_then_open_round_trips`,
    `install_slot_*`, `clear_slot_makes_the_credential_unusable`,
    `invariant_4_rotation_rerandomises_every_slot_byte`,
    `rotate_mvk_*`) - equivalent coverage in v2 round-trip and
    container tests.
  - GUI workers `deniable_create_worker` /
    `deniable_verify_worker` rewritten to go through the v2
    Container API instead of poking the raw header functions.

  `Container::create_with_passphrase_deniable` /
  `open_with_passphrase_deniable` / `enroll_passphrase_deniable`
  are retained as thin convenience wrappers that delegate to the
  v2 two-layer API (same on-disk format).

- **v2 rotation API shipped.** `deniable_header::rotate_mvk_v2`
  generates a fresh `per_vault_salt` + MVK, re-installs each kept
  slot as a v2 envelope under the new salt (re-derived
  `KEK_envelope` + `KEK_factors`), re-randomises non-kept slots,
  and atomically commits the new 36864-byte header (failure leaves
  the input untouched). `Container::rotate_mvk_v2_deniable` wraps
  it at the container layer, swaps the cached MVK + salt + header
  bytes on success, marks `header_dirty`. 4 format-level tests +
  2 container-level tests cover round-trip / drop-slot /
  duplicate-idx / atomic-failure / persist-after-rotate.

- **Variant-aware envelope discovery.** When a deniable vault has
  multiple slots whose envelopes decrypt under the same passphrase
  (e.g. a passphrase slot at 0 + an enrolled FIDO2-passphrase slot
  at 4 with the same envelope passphrase), `try_open_envelope_v2`
  now picks the slot whose `kind` matches the credential variant
  the caller is requesting. Falls back to the first match if no
  kind-matching candidate exists, so the variant-mismatch error
  path in `complete_open_v2` still surfaces for genuine
  credential-type mistakes. Constant-time envelope discovery is
  preserved (always iterates all 8 slots regardless of which
  matches).

- **Optional separate `.kyber` seed-file passphrase.** All HybridPq
  deniable variants (HybridPq, HybridPqFido2, HybridPqTpm2,
  HybridPqTpm2Fido2 + 1024 variants) now accept either a single
  passphrase that doubles as envelope + seed-file (the default,
  matches the existing one-passphrase UX) OR distinct passphrases
  for each role. `CreateOpts.hybrid_seed_pw` /
  `UnlockOpts.hybrid_seed_pw` carry the optional second passphrase;
  empty falls back to the envelope passphrase. The GUI create +
  open forms surface both fields with strength meter + "Generate
  strong passphrase" button + clear hints explaining the
  reuse-vs-distinct choice. The TUI wizard mirrors this with
  `ask_optional_seed_pw` (offers the generator + asks for confirm
  on the distinct path) and `ask_pq_decap_for_deniable` taking the
  envelope passphrase as a fallback parameter.

- **Fuzz target retargeted to v2.** `fuzz/fuzz_targets/deniable_header_parse.rs`
  now exercises `try_open_envelope_v2` (phase 1 envelope discovery)
  and, on the rare phase-1 success, `complete_open_v2` (phase 2
  inner MVK unwrap + inner-header decrypt). Same invariants: no
  panic, no leaked failure-mode variant.

- **GUI add-keyslot modals deniable-aware.** The five TPM-family
  add buttons (TPM-only, TPM+PIN, TPM+FIDO2, hybrid TPM+ML-KEM,
  3-factor hybrid TPM+FIDO2+ML-KEM) and the FIDO2 add modal each
  branch on `Container::is_deniable()`. In deniable mode they
  open a modal with the shared `DeniableEnrollExtras` block
  (envelope passphrase + Argon2id strength + target slot index)
  and dispatch to the matching `enroll_*_deniable` op. The new
  TPM-only deniable modal (`AddTpm2DeniableForm`) covers the
  case where the standard TPM-only enroll has no modal at all.

- **User-facing strings cleaned.** Removed the `v2` version
  prefix from GUI / TUI / CLI labels and toasts (internal API
  names and code comments keep it). Replaced em-dashes and the
  warning emoji with plain ASCII in all user-visible strings.

### Changed (defaults at vault creation)

- **FIDO2-direct: backup passphrase is now opt-in.** The create
  form no longer always shows a "backup passphrase" field. A new
  checkbox "Enable backup passphrase" defaults OFF; ticking it
  reveals the field. Empty field with the checkbox off means no
  passphrase slot is enrolled, the vault is openable only with the
  FIDO2 authenticator, and the create flow no longer asks "are you
  sure" about an empty backup. Existing vaults are unaffected.

- **Tpm2 and Tpm2Pin: opt-in single-slot path.** New checkbox
  "Skip bootstrap passphrase (single TPM slot, no recovery if chip
  dies)" defaults OFF, preserving the current 2-slot
  passphrase + TPM behavior for users who want the recovery
  fallback. Ticking it routes the create through new
  `Container::create_with_tpm2` / `create_with_tpm2_pin`
  constructors that produce a vault with a single TPM keyslot at
  index 0 and no passphrase fallback. If the chip clears the vault
  is permanently unrecoverable.

- **3-factor TPM combos: single-slot by default.** `Tpm2Fido2`,
  `HybridPqTpm2`, `HybridPq1024Tpm2`, `HybridPqTpm2Fido2`, and
  `HybridPq1024Tpm2Fido2` no longer enrol a passphrase slot at
  slot 0 by default. The new default is one keyslot at index 0
  carrying the multi-factor credential, all factors required at
  every unlock. A new checkbox "Enable recovery passphrase (adds
  an OR-attack path; default OFF)" preserves the legacy 2-slot
  behavior for users who want the recovery fallback. Five new
  single-slot `Container::create_with_*` constructors back the new
  defaults
  ([crates/luksbox-format/src/container.rs](crates/luksbox-format/src/container.rs)).

- **Deniable mode: TPM combos always single-slot.** Tpm2,
  Tpm2Pin, Tpm2Fido2, HybridPqTpm2, HybridPq1024Tpm2,
  HybridPqTpm2Fido2, and HybridPq1024Tpm2Fido2 in deniable mode
  are forced to a single deniable slot regardless of UI checkboxes.
  Rationale: the alternative shape (passphrase slot + multi-factor
  slot) would create an invisible second slot the user could never
  enumerate or selectively revoke, see
  [docs/DENIABLE_HEADER.md](docs/DENIABLE_HEADER.md).

### Added

- **Slot-index warning in deniable Add-slot flows.** GUI and TUI
  show "Remember slot N. Deniable vaults cannot enumerate slots,
  so to revoke this credential later you must remember which index
  you used." Appears below the slot picker in Add-FIDO2 /
  Add-passphrase modals and after the TUI's slot-index prompt.

- **CLI parity for deniable create / mount / info.** The
  `deniable-init`, `deniable-mount`, and `deniable-info`
  subcommands gain a `--credential <type>` flag plus per-type
  material flags (`--kyber-path`, `--tpm-blob-path`,
  `--fido2-cred-id`, `--fido2-hmac-salt`). Credential types match
  the wizard's coverage: `passphrase`, `fido2`, `pq-passphrase`,
  `pq-fido2`, `tpm`, `tpm-fido2`, `pq-tpm`, `pq-tpm-fido2`. PINs
  and passphrases stay interactive via `rpassword` so secrets do
  not appear in shell history or `ps argv`. The init flow prints
  a recovery card listing the FIDO2 `cred_id` / `hmac_salt` (hex)
  and the `.tpm-blob` sidecar path as applicable.

- **GUI recovery-card modal for deniable create.** After a deniable
  vault is created the GUI shows a modal listing the
  non-secret-but-not-on-disk values the user must save externally
  (FIDO2 cred_id, hmac_salt, TPM sidecar path, KDF params) with
  Copy buttons for each field.

- **TUI wizard parity for the deniable flow.** Per-combo create
  helpers (`create_den_fido2`, `create_den_pq_passphrase`,
  `create_den_pq_fido2`, `create_den_tpm`, `create_den_tpm_fido2`,
  `create_den_pq_tpm`, `create_den_pq_tpm_fido2`), an
  `open_deniable_by_kind` dispatcher, and a printed recovery card
  at the end of the create flow.

### Fixed

- **FUSE-T: "not enough space" when copying files into a mounted
  vault on macOS.** The FUSE-T `statfs` callback returned zeros,
  which the macOS NFS client interpreted as a full filesystem and
  refused every WRITE3 request. Fixed by querying the host
  filesystem via `libc::statvfs` and surfacing the real values
  ([crates/luksbox-mount/src/fuse_t.rs](crates/luksbox-mount/src/fuse_t.rs)).

### Documentation

- **CRYPTO\_SPEC sec.19.10 Default slot policy for multi-factor combos**
  ([docs/CRYPTO\_SPEC.md](docs/CRYPTO_SPEC.md)). Documents the new
  single-slot create constructors, the per-combo defaults, and the
  threat-model implications of the AND-semantics-by-default
  choice. Cross-references from sec.7 ("Lost device with backup
  enrolled") clarifying that the backup-passphrase recovery
  argument no longer applies by default for FIDO2-direct and
  multi-factor combos.

- **DENIABLE\_HEADER.md** rewritten in places to reflect the new
  shape: the per-credential recovery table for the TPM row now
  records that deniable TPM is single-factor (no backup
  passphrase combined into the KEK); a new section "Deniable +
  TPM combos: always single-factor" spells out the rationale.

- **DISCLAIMER.md** notes that the create flow no longer enrols a
  backup passphrase by default for FIDO2-direct and 3-factor TPM
  combos. Users either tick "Enable backup / recovery
  passphrase" at create time or add a passphrase slot afterwards
  via "Add slot".

### Test coverage

- Round-trip + "passphrase does not work" tests for every new
  single-slot constructor, covering Tpm2, Tpm2Pin, Tpm2Fido2, and
  HybridPqTpm2 paths. Use the mocked-TPM closure so CI runs on
  every commit without real TPM hardware.
- **Cryptographic security audit (round 11)** swept the deniable
  v2 code paths for null-secret / zero-KEK fallbacks, nonce reuse,
  AAD coverage, and material-zeroization gaps. Three real findings
  shipped fixes (per-vault salt mixed into the inner-header AAD,
  envelope plaintext wrapped in `Zeroizing`, `Zeroizing<[u8; 32]>`
  propagated through `deniable_pq_decap` so the ML-KEM shared
  secret is wiped after the slot KEK derives). False-positive
  findings (variant enumeration via timing) documented in
  `docs/DENIABLE_HEADER.md` sec. "Findings that look like leaks but
  are not".
- **New workflow / regression test suite** at
  `crates/luksbox-format/tests/deniable_workflows.rs` (5 tests):
  multi-slot mixed-kind enrollment with shared envelope passphrase,
  cross-vault slot splicing rejection (regresses the per-vault salt
  AAD binding), HybridPq envelope-pass / ML-KEM-shared
  independence, mixed-kind rotation with partial keep set, and
  add-slot-of-different-kind after init. Each pins a specific bug
  that surfaced during the v1 -> v2 migration.
- **New fuzz targets** for the v2 slot-payload codec, in both
  fuzzing setups: `slot_payload_decode` (direct decoder, no
  Argon2id) and `slot_payload_roundtrip` (`new` -> `encode` ->
  `decode` field equality with attacker-controlled length triples).
  These cover the trust boundary the audit hardened that the
  existing `deniable_header_parse` fuzzer only reaches
  probabilistically. Each target now has both a libfuzzer harness
  (`fuzz/fuzz_targets/`) and an AFL++ harness
  (`fuzz-afl/src/bin/`) - different engines, different mutator
  personalities, different bugs found. The previously-missing
  `deniable_header_parse` AFL++ harness was added at the same time,
  closing a pre-existing gap on the deniable surface.
- **Shared fuzz seed corpus**:
  `crates/luksbox-format/examples/gen_fuzz_seeds.rs` now writes
  one curated seed per new target into both `fuzz/corpus/<target>/`
  and `fuzz-afl/seeds/<target>/` so the two engines bootstrap from
  the same regression inputs. Re-run with
  `cargo run --example gen_fuzz_seeds -p luksbox-format`.
- **AFL orchestration**: the three new targets are registered in
  `scripts/fuzz_server.sh`'s `TARGETS` array so the "run all" path
  and the per-target launcher pick them up automatically.
- **Cross-platform deniable enroll gating.** Five call sites in
  `crates/luksbox-gui/src/app.rs` that invoke the
  Linux-only-`#[cfg]`-gated deniable TPM enroll helpers now have
  matching cfg gates with clear "requires the Linux hardware
  build" errors on macOS / Windows, fixing CI failures on those
  platforms.

### Cleanup

- Removed v1 leftover GUI helpers (`parse_hex_32`,
  `deniable_fido2_hmac`, `deniable_tpm_unseal`, `clear_deniable_slot`)
  and their UnlockForm / UnlockOpts companion string fields
  (`deniable_fido2_cred_id_hex`, `deniable_fido2_hmac_salt_hex`,
  `deniable_tpm_blob_path`). v2 embeds all that material in the
  slot envelope, making the hex-input / sidecar-path GUI surface
  obsolete.
- Updated deprecated egui APIs (`Frame::none` -> `Frame::NONE`,
  `Frame::rounding` -> `Frame::corner_radius`) so the workspace
  builds without deprecation warnings.

---

## [v0.1.1] - 2026-05-08

First post-release iteration on top of v0.1.0. No breaking format
changes; every v0.1.0 vault opens unchanged under v0.1.1. The
release bundles security hardening, a Windows mount-flush fix that
was visible to end users, the new forensic / partial-recovery CLI
toolkit, the Apple Developer ID signing pipeline for macOS, a
static-CRT Windows build that drops every `VCRUNTIME*.dll` and
`api-ms-win-crt-*.dll` runtime dependency, and a sweep of CRYPTO\_SPEC
sections that document properties readers were previously expected
to derive from source.

### Fixed

- **WinFsp: Files copied via Explorer disappear after unmount /
  remount** ([crates/luksbox-mount/src/winfsp.rs](crates/luksbox-mount/src/winfsp.rs)).
  The WinFsp `Cleanup` callback only flushed the VFS metadata blob
  on the DELETE path. For the normal `CreateFile -> WriteFile ->
  CloseHandle` flow Explorer uses for copies, encrypted chunks
  landed on disk but the directory tree + chunk index never got
  persisted, so on the next mount the file appeared gone.
  Fixed by flushing in the non-DELETE branch as well, gated by
  WinFsp's existing `set_post_cleanup_when_modified_only(true)`
  setting. Belt-and-suspenders `Drop` impl on `LuksboxFs` flushes
  on `FileSystem::stop()` for the process-killed-mid-copy edge
  case. End-to-end regression test
  (`file_written_via_win32_survives_unmount`) added to the WinFsp
  CI integration suite - runs automatically on `windows-latest`
  with a real WinFsp 2.x kernel mount.

- **GUI: ML-KEM-1024 TPM keyslots could not be unlocked**
  ([crates/luksbox-gui/src/ops.rs](crates/luksbox-gui/src/ops.rs)).
  The hybrid PQ + TPM unlock dispatch only matched the ML-KEM-768
  `SlotKind` variants, silently bypassing every 1024-grade slot the
  user enrolled. Fixed to match both 768 and 1024 variants.

- **Test pollution: parallel symlink tests inherited each other's
  env vars** ([crates/luksbox-format/tests/security\_invariants.rs](crates/luksbox-format/tests/security_invariants.rs)).
  `nofollow_symlinks_env_var_refuses_symlinked_vault` set
  `LUKSBOX_NO_FOLLOW_SYMLINKS=1` without cleanup, and
  `symlink_to_real_vault_opens_cleanly` (running in parallel)
  inherited it and failed intermittently. Fixed with a static
  `OnceLock<Mutex<()>>` that serializes env-var-mutating tests
  in this file.

- **macOS Developer ID signing pipeline failed at PKCS12 import**.
  OpenSSL 3.x defaults to PBES2-encrypted .p12, but macOS
  `security import` only accepts PBES1. Release workflow now
  pre-verifies the .p12 with OpenSSL before handing it to
  `security import` and instructs operators to use
  `openssl pkcs12 -export -legacy ...` when generating their
  Developer ID bundle.

- **macOS entitlements rejected by AMFI's strict XML parser**.
  The XML comments inside the entitlements `<dict>` block were
  silently accepted by `plutil` but rejected by AMFI at codesign
  time with `AMFIUnserializeXML: syntax error near line 9`.
  Comments stripped from inside `<dict>`; rationale moved to
  [`dist/macos/README.md`](dist/macos/README.md).

- **Homebrew formula install regression**. `brew install` on the
  macOS smoke-test runner crashed with
  `undefined method 'to_sym' for nil` in newer Homebrew API
  shapes. Worked around with `HOMEBREW_NO_INSTALL_FROM_API=1` plus
  the explicit `--formula` flag in the CI step.

- **Linux + macOS `cargo audit` advisories surfacing on every CI
  run**. Replaced the audit-tracked dependencies pinned at
  vulnerable versions with non-vulnerable equivalents and added
  an [`audit.toml`](audit.toml) ignore entry only for advisories
  that don't reach the data path.

### Added

- **Forensic / partial-recovery CLI toolkit**
  ([website walkthrough](https://luksbox.penthertz.com/docs/operations/forensics/)):

  - [`luksbox header-backup`](https://luksbox.penthertz.com/docs/cli/header-backup/)  - 
    save the 8 KiB header bytes to a separate file. Equivalent
    to `cryptsetup luksHeaderBackup`. No unlock material
    required. Output mode 0600.

  - [`luksbox header-restore`](https://luksbox.penthertz.com/docs/cli/header-restore/)  - 
    restore the on-disk header from a previously saved backup.
    HMAC-verified against the live MVK by default, blocking the
    attacker-substituted-backup attack. `--no-verify` for the
    case the on-disk header is too damaged to unlock with;
    `--no-verify` is now enumerated as an operator-explicit
    safety bypass in [SECURITY.md sec.3](SECURITY.md).

  - [`luksbox header-dump`](https://luksbox.penthertz.com/docs/cli/header-dump/)  - 
    decrypt the metadata blob and emit a JSON tree of every
    inode, chunk reference, generation counter, and keyslot
    summary. Read-only.

  - [`luksbox check`](https://luksbox.penthertz.com/docs/cli/check/)  - 
    walk every used chunk, AEAD-decrypt it, and report per-chunk
    status with exact `(file_path, chunk_idx, slot_offset,
    generation)`. Exit non-zero on any failure so it composes
    cleanly with `&&` and cron jobs. `--json` for tooling
    consumption.

  - [`luksbox extract --tolerate-errors`](https://luksbox.penthertz.com/docs/cli/extract/)  - 
    forensic best-effort file extraction. Tolerates per-chunk
    AEAD failures by writing 4 KiB of zeros in place of each
    unrecoverable chunk and continuing. Mandatory
    `--tolerate-errors` flag so users don't silently capture
    lossy output.

  - 9 integration tests cover the new subcommands end-to-end,
    including the HMAC pre-check that refuses to install a
    header backup from a different vault.

- **Apple Developer ID signing for macOS releases**. The release
  workflow now codesigns the `.app` with a Developer ID
  Application certificate, runs Apple notarytool, staples the
  notarization ticket to the `.dmg`, and emits a verified bundle
  that opens with the standard "downloaded from internet" prompt
  rather than the Gatekeeper block. Documented in
  [`dist/macos/README.md`](dist/macos/README.md). Apple Silicon
  Macs still need the one-time Recovery Mode -> Reduced Security
  setup before macFUSE's kernel extension loads - the install
  guide walks through it.

- **Windows static-CRT linking** ([`.cargo/config.toml`](.cargo/config.toml)).
  `-C target-feature=+crt-static` on `x86_64-pc-windows-msvc`.
  The shipped `luksbox.exe` no longer imports `VCRUNTIME140.dll`,
  `MSVCP140.dll`, or any `api-ms-win-crt-*.dll`; verified with
  `objdump -p luksbox.exe | grep "DLL Name"`. End users no
  longer need a Visual C++ Redistributable. SmartScreen still
  warns on first launch (LUKSbox is not yet signed with an EV
  Authenticode certificate) - the
  [Windows install guide](https://luksbox.penthertz.com/docs/getting-started/install-windows/)
  has the SmartScreen explainer + the EV signing roadmap.

- **Per-Ubuntu-release `.deb` builds**. The release workflow now
  produces a separate `.deb` per supported Ubuntu line so the
  exact runtime dependency (`libfido2-1`, `libfuse3-3`,
  `libssl3` major) matches what apt resolves on each release.

- **GitHub Artifact Attestations (Sigstore-backed)**. Every
  release artifact carries a verifiable provenance attestation:

  ```bash
  gh attestation verify <downloaded-file> --owner penthertz
  ```

  The attestation proves the artifact came from the exact tagged
  workflow run on a GPG-signed commit; no human had a chance to
  swap it after the fact.

- **Top-level [`DISCLAIMER.md`](DISCLAIMER.md)** and matching
  [Disclaimer page](https://luksbox.penthertz.com/disclaimer/) on
  the website restating Apache 2.0 sec.7-sec.8 (no-warranty /
  no-liability), the data-loss reality of any encrypted
  container, and the export-control responsibility, in plain
  English.

- **"Use LUKSbox for shared or backup copies, not as your only
  copy"** notice on the docs landing page, the README, the
  Quickstart, and the homepage FAQ. The vault is the *travelling*
  copy; the user keeps the *master* copy somewhere they trust.

- **Minimal new `luksbox-vfs` accessors** (`file_chunks`,
  `inode_kind`, `inode_size_raw`, `tree_counters`) so the
  forensic CLI subcommands work on the public VFS surface
  without exposing internal mutability.

### Changed (security hardening)

These are non-breaking tightenings of the safe envelope. No vault
or workflow that was working under v0.1.0 is affected.

- **Tightened Argon2id memory cap on `.kyber` seed-file parsing**
  ([crates/luksbox-pq/src/seed_file.rs](crates/luksbox-pq/src/seed_file.rs)).
  `SAFE_M_COST_KIB_MAX` lowered from 4 GiB to 512 MiB. The
  previous bound let a hostile `.kyber` request a 16 TiB peak
  Argon2id allocation under
  `peak = m_cost x p_cost x 128 B`. The 5 existing seed-file
  DoS-guard regression tests still pass under the tighter cap
  (the hostile values they use - `u32::MAX` - are still
  rejected). All real-world `.kyber` seeds use parameters far
  below the new cap.

- **`libfido2` credential-ID pointer null-check**
  ([crates/luksbox-fido2/src/hid.rs](crates/luksbox-fido2/src/hid.rs)).
  Defends the `unsafe { from_raw_parts(id_ptr, id_len) }` block
  against a hostile or firmware-buggy authenticator returning
  `(id_len > 0, id_ptr = NULL)`. Belt-and-suspenders behind
  libfido2's documented contract - refuses to construct a slice
  from a null pointer and surfaces a clear error.

- **WebAuthn DLL trust-boundary documentation**
  ([crates/luksbox-fido2/src/webauthn.rs](crates/luksbox-fido2/src/webauthn.rs)).
  The Windows path (`webauthn.dll`) does not need the same
  pointer-validity defence as the libfido2 path because the DLL
  is part of Windows itself - trusting `pbFirst` is the same
  trust we already place in every other Win32 API call. Inline
  comment block makes the asymmetry explicit so future readers
  don't add a defensive check that's actually dead code.

- **Operator-explicit safety bypasses enumerated in
  [SECURITY.md sec.3](SECURITY.md)**. The three escape hatches  - 
  `LUKSBOX_NO_LOCK=1` (disables advisory `flock(LOCK_EX)`),
  `LUKSBOX_NO_FOLLOW_SYMLINKS=1` (refuses symlinked vaults), and
  `luksbox header restore --no-verify` (skips HMAC pre-check on
  a backup header) - are now spelled out in the threat model
  with their preconditions and consequences.

### Documentation

- **CRYPTO\_SPEC sec.3.9 Per-chunk encryption layering**
  ([docs/CRYPTO\_SPEC.md](docs/CRYPTO_SPEC.md)). New canonical
  reference for the three-layer chunk-protection property:
  per-chunk random nonce, binding AAD
  (`file_id ‖ chunk_idx ‖ generation`), and per-file derived key
  (`HKDF(MVK, info = "lbx:file/v1:" ‖ file_id)`). Includes a
  mermaid diagram, a per-layer table linking each layer to its
  source line range, an explicit "what removing each layer would
  break" walkthrough, and a "what this combination does NOT
  protect against" subsection (vault-wide rollback, chunk-count
  observability). sec.14 (read scenario) and sec.15 (write scenario)
  now back-reference sec.3.9 as the canonical writeup.

- **CRYPTO\_SPEC sec.sec.3.4 - 3.8: complete on-disk footprint**.
  Detached headers (sec.3.4), the `<file>.tmp.<16hex>` transient
  temp-file convention every atomic update uses (sec.3.5), the
  `<vault>.rotating` MVK-rotation temp file (sec.3.6), the GUI's
  `$XDG_DATA_HOME/luksbox/{recent,preferences}.json` state
  files (sec.3.7), and the crash-orphan classification policy that
  tells the operator what each leftover file means (sec.3.8) are
  now all documented in the spec rather than living only in the
  source comments.

- **PROJECT\_OVERVIEW.md cleanup**: mermaid 11 strict-parser
  fixes (`<br>` not `<br/>`, no square brackets in edge labels,
  no bare `<file>` tokens in sequence-diagram messages, quoted
  node labels for any label containing punctuation),
  consolidated formula notation, removed duplicated narrative.

- **Penthertz logo placement** on the website header, the
  download page, and `dist/macos/README.md`.

- **Website docs expansion** for the new forensic CLI
  subcommands (one page per subcommand with example invocation,
  output format, and exit-code semantics) plus the Forensics
  walkthrough page that ties them together for a real damaged-
  vault recovery scenario.

### Packaging / CI

- WinFsp mount integration tests now run on every push to
  `main` and every PR via the dedicated `windows-latest` job in
  [`.github/workflows/ci.yml`](.github/workflows/ci.yml). 30 s
  WinFsp install via choco (with MSI fallback), 5 s per
  integration test, `--test-threads=1` to serialize on the
  drive-letter pool.

- 26 security regression tests are pinned to their own CI job
  (`security-regressions`, must stay green) so any failure is
  unambiguously a serious regression rather than a noisy
  unrelated test.

- `lintian` and `rpmlint` runs are clean on every release; new
  signature-attestation step verifies the published artifacts
  against their Sigstore attestation before tagging.

### Known limitations

- **Windows SmartScreen still warns on first launch.** LUKSbox
  is not yet signed with an EV Authenticode certificate. EV
  signing is on the v0.2 roadmap; in the meantime, SmartScreen
  shows "Windows protected your PC" once and is silent on
  subsequent launches after *More info -> Run anyway*.

- **Apple Silicon + macFUSE.** macFUSE's kernel extension
  requires Recovery Mode -> Startup Security Utility -> Reduced
  Security on Apple Silicon Macs. This is a one-time setup; the
  install guide walks through it. The CLI / GUI / extract
  paths work without macFUSE; only `mount` needs it.

- **Format compatibility guarantee** is still pre-1.0. v0.1.x
  reads every v0.1.x vault, but the format may evolve under
  audit guidance before v1.0 is cut. Migration tools ship with
  any breaking format change.

---

## [v0.1.0] - 2026-05-06

Initial public release. The core feature set - encrypted vaults
with passphrase / FIDO2 / TPM 2.0 / Windows Hello / hybrid
post-quantum keyslots, chunked AEAD-protected file storage, FUSE +
WinFsp mount adapters, MVK rotation, anchor-based rollback
detection - was audit-tracked through 9 internal review rounds
before the cut. See the
[audit log](https://luksbox.penthertz.com/docs/security/audit/) for
the per-round summaries.

[v0.1.1]: https://github.com/penthertz/LUKSbox/releases/tag/v0.1.1
[v0.1.0]: https://github.com/penthertz/LUKSbox/releases/tag/v0.1.0
