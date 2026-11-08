# Security audit, Round 16: sync bundles and the v0.7 line

Author: Penthertz internal review team
Baseline: `6864909` (v0.7.0-rc.1, "Introducing sync bundles")
Date: 2026-11-07
Status: **0 CRITICAL, 3 HIGH, 8 MEDIUM, 22 LOW, 10 INFO found. 2 HIGH, 5
MEDIUM, 10 LOW and 2 INFO fixed in this revision; 1 HIGH, 1 MEDIUM
mitigated; the rest accepted or documented (listed with the reason).
No break of the stolen-vault / stolen-bundle model: a storage provider
holding the bundle folder, its whole version history and every object
it ever saw still cannot read a byte of the vault or forge a commit
that any device accepts. The two HIGHs are a rollback-detection bypass
on single-file vaults and a data lock-out, not cryptographic breaks.**

Scope: the round the sync design promised ("Audit round 16, dedicated
to the bundle, the merge engine and the storage refactor"), widened to
the whole workspace as in Round 15: `luksbox-sync` (every module, read
end to end), `luksbox-merge`, the `Storage` / read-only refactor of
`Container` and `Vfs`, `luksbox-core`, `luksbox-format`, `luksbox-vfs`,
`luksbox-mount` + `luksbox-fuse-t`, `luksbox-fido2`, `luksbox-tpm`,
`luksbox-sep`, `luksbox-pq`, the CLI and the GUI, with the three
questions the round was asked: does the sync feature leak anything to
the provider or to other local users, is the application layer sound,
and can a faulty (not even hostile) sync service make people lose
their data.

Method: white-box source review, one surface at a time, tracing
attacker-controlled input (the bundle folder as written by the sync
client on the provider's behalf, tampered `.lbx` files and sidecars,
hostile metadata trees from a former key holder, rogue authenticators,
local co-users, the environment of a launched process) to the
sensitive sinks, against the invariants I1 to I14 of
`CLOUD_SYNC_IMPLEMENTATION.md` section 11. Every finding below was
verified against the code before a fix was written; the ones marked
*reproduced* were demonstrated by a regression test that fails on the
baseline and passes on this revision. Each fix carries an `R16-..`
marker in the code.

## Summary

| Severity | Found | Fixed | Mitigated | Accepted / documented |
|---|---|---|---|---|
| CRITICAL | 0 | 0 | 0 | 0 |
| HIGH | 3 | 2 | 1 | 0 |
| MEDIUM | 8 | 5 | 1 | 2 |
| LOW | 22 | 10 | 0 | 12 |
| INFO | 10 | 2 | 0 | 8 |

What the provider learns from a bundle, as reviewed (unchanged, and
now stated in one place in `SYNC_BUNDLES.md`): the bundle id and the
keyslot-table generation (in header-object names), the 8 KiB header
itself (cipher suite, KDF parameters, keyslot kinds and count, FIDO2
credential ids, hardware-slot presence: exactly what any `.lbx`
shows), the page count (vault size rounded to a page), per commit the
number of new pages, table blocks and the manifest size bucket, so the
write volume and, through the metadata bucket, the size bucket of the
directory tree, commit times, and lease churn (when the vault is open
and how many sessions). Not: file names, sizes, count, structure,
which file changed, which device committed, device names. Nothing in
the folder is plaintext besides the header and the hybrid sidecar,
nothing outside the per-device state folder records a bundle on the
device, and deniable vaults never become bundles.

## HIGH

**R16-01: a header recovered from the `.header-bak` mirror was
re-persisted as a NEW header state, defeating the anchor's
rollback detection on the next open** (*reproduced*, `luksbox-format`).
When the live header fails to parse, `Container::open` recovers it
from the mirror and set `header_dirty: recovered` so the live region
would be re-established at the next persist. `persist_header` bumps
the header generation on every write, and `Drop` persists, so a FAILED
open persisted too: the caller's `set_anchor` returned
`HeaderRollbackDetected` (correct), the container was dropped, and the
rolled-back keyslot table was written to live and mirror at generation
k+1, which the anchor (at k+1) then accepted on the second open with no
warning. An attacker holding the vault file and its sidecars (the
cloud-folder model) therefore laundered a pre-revocation keyslot table
past R15-D1 by corrupting the live header and planting the old mirror;
with an anchor further ahead, repeating the plant between retries
ratchets the generation up one by one. Fix: a recovered header is kept
apart (`recovered_header`) and written back byte for byte, same
generation, through `restore_header_bytes`; a real change made after
the recovery is still a new state. Pinned by
`recovered_header_is_not_a_new_state_so_the_anchor_keeps_refusing_it`
and `a_change_after_recovery_is_still_persisted_as_a_new_state`
(`luksbox-vfs/tests/round16_findings.rs`, which can make a header-v3
vault).

**R16-02: `shrink` after a failed write persisted a free-list entry
past `next_chunk_id`; the vault refused to open afterwards**
(*reproduced*, `luksbox-vfs`). A write or truncate that fails on the
vault size limit (or ENOSPC) after allocating a slot at the end of the
file hands the slot back to `pending_free` (R15-E6) without marking the
tree dirty, so `shrink_tail`'s first flush is a no-op. It then lowers
`next_chunk_id` to the first unused slot, filters `free_chunks` but not
`pending_free`, and its second flush serialises the stale id into the
free list. `validate_metadata_tree` rejects a free slot at or beyond
`next_chunk_id`, so the next open failed with `MetadataDeserialize`:
data intact, access lost, no MVK needed (a full disk, a cloud quota or
the vault's own limit plus shrink-on-close). Fix: `pending_free` is
filtered at the cut too. Pinned by
`r16_02_shrink_after_a_failed_write_keeps_the_vault_openable`.

**R16-17 (mitigated, design limitation): revoking a keyslot on a sync
bundle gives no cryptographic protection against the credential's
holder.** The bundle keys are HKDF subkeys of the MVK, which a
revocation does not change; `rotate-mvk` is refused on bundles; the
superseded header object stays in the folder until a manual `sync gc`
(two passes, at least 7 days apart) and in the provider's version
history forever. Anyone who held the revoked credential derives the
MVK from any old header with their own tools and reads every later
commit, and can forge commits under any device identity (the "former
key holder" of the design doc). This is the documented phase-3 gap
(epoch keys), not a regression, but the CLI's `revoke` printed only
"revoked slot N". Mitigation: `revoke` on a bundle now says so and
gives the only real revocation (`sync export`, `rotate-mvk`, `sync
convert` into a new bundle, delete the old one); the limit is stated
in `SYNC_BUNDLES.md`. The fix proper is phase 3 of
`CLOUD_SYNC_DESIGN.md`.

## MEDIUM

- **R16-03** (*reproduced*, `luksbox-sync`) A head whose objects had not
  all arrived made the session read-only, always, even when another
  complete head existed, and `retarget` (merge at lock/unmount) failed
  the same way. The design (4.4 step 3) says pending heads are skipped.
  Since a read-only device cannot publish, nothing could ever outrank
  the stuck head: a laptop that died mid-upload, or a provider that
  withholds one object of the newest commit, locked every device
  read-only for good, with export and a new bundle as the only way
  out. Fix: the first complete head in deterministic order is opened
  (writable), skipped heads are reported as `Pending`, and only when no
  head is complete does the session fall back to the newest complete
  ancestor, read-only. When the objects arrive the pending head is
  merged like any concurrent commit. Pinned by
  `r16_03_an_incomplete_head_is_skipped_so_the_bundle_stays_writable`
  and `..._the_newest_complete_ancestor_opens_read_only`.
- **R16-04** (*reproduced*, `luksbox-sync`) A session that could not
  publish (opened read-only, or a commit another device saw was
  missing here) showed the vault WITHOUT the changes this device had
  saved and never published, reported nothing about them, and
  `has_unpublished()` said no. `sync export` from such a session lost
  them, and a user who then gave up on a "read-only" bundle (deleted
  it, converted again) lost them for good; the staged record stayed on
  disk but nothing said so. Fix: read-only sessions are views that
  include the local record (shown, exportable), `has_unpublished()` is
  true, and a new `Notice::UnpublishedLocalChanges { shown }` names
  them (also when they were saved on an older commit and cannot be
  shown). Pinned by two `r16_04_*` tests.
- **R16-08** (`luksbox-mount`, CLI) `luksbox mount <bundle>`
  daemonizes by default and the child's stdio goes to `/dev/null`; the
  periodic and unmount publishes report failures with `eprintln!`
  only, and `luksbox umount` returns as soon as the kernel detaches,
  before the final publish runs. A failed or interrupted upload was
  invisible: the user closed the lid believing the changes were synced,
  the other device diverged, and the merge later produced conflict
  copies. Fix: every failed publish is recorded (sealed) in the
  device's state (`last-publish-error`) until one succeeds, and the
  next open and `sync status` report it. Pinned by
  `r16_08_a_failed_publish_is_remembered_until_one_succeeds`. Still
  open (documented): `umount` does not wait for the daemon's final
  publish; see `SYNC_BUNDLES.md`.
- **R16-11** (`luksbox-merge`) `merge` never checked that `ours` and
  `theirs` descend from `base`. `luksbox merge --base` with a base that
  is in fact newer (a provider that rolled the cloud copy back and the
  user following the "merge the conflict copy" hint, or a wrong file)
  silently took the base's older content for every file `ours` did not
  touch and dropped what `theirs` "lacked" as deleted, then
  `raise_generation_to` made the result pass the rollback anchor. Fix:
  a side whose vault generation is below the base's is refused
  (`Error::NotDescendants`); the generation only grows along a
  lineage, so a true ancestor always passes. Pinned by
  `a_base_newer_than_a_side_is_refused`.
- **R16-13** (`luksbox-mount` FUSE-T, CLI) The FUSE-T daemonized mount's
  parent returns `Ok` after the mount appears (the fuser parent exits),
  so `dispatch` ran `finish_active_session` in the parent: it published
  from its forked copy of the session (possibly a merge), closed the
  lease under the running mount, and shared the device's sequence
  numbers with the child, which could later publish the same number
  (an equivocation, resolved by a new identity). Fix: the parent
  forgets the session when a background mount returns
  (`forget_active_session`); the child owns it. macOS only; compile-
  checked here, not run.
- **R16-21** (accepted, `luksbox-vfs`) The chunk AAD (`file_id ||
  chunk_idx || generation`) and the per-file key bind nothing specific
  to one fork of a vault. Two copies of a `.lbx` edited on two devices
  (the "conflicted copy" case) continue from the same counters, so the
  first chunk written on each side carries the same AAD under the same
  key with different plaintext: a provider holding both copies can
  transplant that slot from one copy into the other and the AEAD
  passes. Inside a bundle this does not arise (every page is sealed
  under its own key and bound to its position, and merges re-encrypt),
  and a transplant can only move the user's own bytes between the
  user's own forks, never forge content; it is a format change (a
  per-instance fork id in the chunk AAD, refreshed on merge and
  rescue), scheduled with the next format bump.
- **R16-22** (mitigated, `luksbox-sync`; the "faulty sync" question)
  One lost or damaged page object that every later commit inherits
  makes every commit since incomplete, and a page is only ever stored
  once: a sync client that drops or corrupts a single 4 MiB file (and
  mirrors the loss to every device) makes a mostly intact vault
  unopenable through LUKSbox on every device. Partial state never
  opens (G4, correct as the default) and there is no salvage mode. In
  this revision: `luksbox sync export --snapshot <id>` exports any
  earlier complete version to a `.lbx` when the newest one is damaged
  (pinned by `an_earlier_snapshot_can_be_exported_when_the_head_is_damaged`),
  and `SYNC_BUNDLES.md` has a section on it. Still open: a `--salvage`
  mode that opens the newest head read-only with the missing or
  damaged pages mapped to zeros, so the inner container's tolerant
  recovery marks the affected files and everything else can be copied
  out; tracked in `SECURITY.md`.
- **R16-23** (documented, `luksbox-sync`) `open` refuses a bundle with
  more than `MAX_MANIFESTS` (100 000) manifests, garbage collection is
  never automatic, and `gc` needs an open session: a bundle used long
  enough without `sync gc` (the GUI publishes a few seconds after each
  change) locks itself out, data intact. Not reached in realistic use
  before years, and a software fix opens it again; it needs the
  verified-manifest cache the plan has (5.2.1) and a periodic
  collection pass. Tracked in `SECURITY.md`.

## LOW

- **R16-05** (`luksbox-sync`) Every well-named header object was read
  into memory (8 KiB each, up to the 4 000 000 listing cap: 32 GiB) and
  tried with the credential newest first, one Argon2 run or FIDO2
  touch per planted header. Fix: at most 1024 header objects
  (`Limit`), a count a bundle reaches only after a thousand keyslot
  changes without `gc`. Pinned by
  `r16_05_too_many_header_objects_are_refused_before_being_read`.
- **R16-06** (`luksbox-sync`) Lease listings were cut at 1000 entries
  without a word: in `gc` a pin past the cut (the base of an offline
  device's work) was ignored and its commit collectable; `fresh_leases`
  missed open sessions. Fix: `gc` refuses past 10 000 leases, the
  advisory listings read up to 10 000. Pinned by
  `r16_06_gc_refuses_a_flooded_lease_folder_instead_of_ignoring_pins`.
- **R16-07** (`luksbox-sync`) `seen` was built from every device ever
  observed and a manifest allows 256; the 257th identity (identities
  churn on copied profiles and restored VMs) published a manifest that
  every reader rejected as malformed and then read its own commit's
  absence as a rollback. Fix: manifests are validated before sealing
  (fail closed) and `seen` keeps the 256 most recently active devices.
  Pinned by `r16_07_many_device_identities_do_not_brick_the_bundle`.
- **R16-09** (`luksbox-sync`) Only `<bid>/` and `anchors/` were made
  0700; `<data>/luksbox/`, `sync/` and `sync/paths/` took the umask, so
  another account on the machine could list which bundles this one
  uses (the ids are the prefix of header-object names in the cloud
  folder) and the hashed path registry; the `lock` file had the
  default mode. Fix: every folder created on the way is 0700, `lock`
  is 0600. Pinned by `r16_09_every_local_state_folder_created_is_private`.
- **R16-10** (CLI, GUI) The application data folder fell back to the
  working folder when HOME / XDG_DATA_HOME / APPDATA were unset
  (`env -i`, a service unit): `cd ~/Dropbox && luksbox ...` put the
  device's sealed unpublished changes, its identity and its rollback
  anchors inside the synced folder, where the provider gets them and
  where the anchor no longer is "on separate storage". Fix: fail
  closed with the variable to set.
- **R16-12** (CLI) `LUKSBOX_NO_AUTO_ANCHOR` and `LUKSBOX_SYNC_STATE_DIR`
  silently disabled or relocated rollback detection (an empty state
  folder makes every bundle "trusted as found"). Whoever controls the
  environment of a launched process is close to code execution, hence
  low, but an opt-out from a safety check must never be silent. Fix:
  both are announced on stderr.
- **R16-14** (`luksbox-format`) `read_metadata_mirror_nofollow`,
  `hybrid_sidecar::read_sidecar_bytes`, `peek_vault_header_salt` and
  the anchor reader opened with `O_NOFOLLOW` alone; `open(2)` of a FIFO
  blocks until a writer appears, before the regular-file check runs, so
  a FIFO planted at any of those paths by a local co-user with write
  access to the folder stalled the open forever. Comments claimed the
  check was atomic with the open. Fix: `O_NONBLOCK` on those opens, and
  a regular-file check on the anchor reader (which had none). Pinned by
  `r16_14_a_fifo_at_the_sidecar_or_anchor_path_is_refused_without_blocking`.
- **R16-15** (`luksbox-format`) `export_external_header` set
  `data_offset = metadata_size` without checking that the source
  header has no gap between its metadata region and its data; such a
  header (MVK-holder-crafted or a future layout) converted into a
  bundle whose every chunk slot was mis-addressed. Fix: refused. Pinned
  by `r16_15_export_external_header_refuses_a_layout_gap`.
- **R16-16** (`luksbox-format`) `replaced_on_disk` compared the vault
  path's `symlink_metadata` with the open inode, so a vault opened
  through a symlink (supported) was always "replaced" and
  `rescue_if_replaced` copied the whole vault next to the link after
  every save. Fix: `metadata` (follows the link the user chose).
- **R16-18** (CLI, GUI, `luksbox-sync`) `Notice::UnmergedLocalChanges {
  recoverable: false }` said the commit the local changes were made on
  "is no longer in the bundle and cannot be rebuilt", with `discard-local
  --yes` as the remedy. The same notice fires when that commit simply
  has not synced to this device yet; a user following the text during
  sync lag deleted changes a later open would have merged. Fix: the
  message distinguishes "not here yet: wait and open again" from "gone
  after a long time offline", and says to discard only when sure.
- **R16-24** (documented) Leases cannot be turned off; the design
  (section 10) promised `--no-lease`. A writable session writes a 4 KiB
  object at open, at every publish and every heartbeat, so the provider
  learns when the vault is open. Documented in `SYNC_BUNDLES.md`.
- **R16-25** (documented) Unpublished changes whose base commit is gone
  from the bundle are unrecoverable (`Rebase::Stuck { recoverable:
  false }`): the staged pages are diffs against that base. The plan's
  `pins/` folder (a local copy of the base's table blocks and metadata
  pages) was not built. The lease pins the base for 90 days and the
  retention keeps 30 days, so this takes a long absence; a device
  offline that long should export before discarding.
- **R16-26** (documented) A `Missing` notice (a commit another device
  saw is not here) makes the session read-only until it arrives. If it
  never does (the device that made it was destroyed before the upload
  finished, the provider lost it) there is no command to accept the
  gap; the way out is `sync export` and a new bundle.
- **R16-27** (documented, `luksbox-merge`) A merge that runs into the
  vault size limit fails instead of warning as the plan promised
  (7.2); on a bundle the merge re-runs at every open until the limit is
  raised. Add `set_max_vault_size(0)` around merges, or a warning.
- **R16-28** (documented, `luksbox-vfs`) After a legitimate replacement
  of a `.lbx` on disk, every later flush copies the whole vault again
  (`rescue_if_replaced` runs at each flush); a multi-GiB vault stalls
  the mount for minutes per flush. Copy once, or only when the
  metadata generation moved.
- **R16-29** (documented, `luksbox-vfs`) The rescue copy omits the
  `.hybrid` sidecar; a hybrid-PQ-only vault's rescue copy cannot be
  unlocked. The warning text should say so, or the sidecar be copied.
- **R16-30** (documented, `luksbox-vfs`) A deniable vault replaced on
  disk while open loses the session's saves at close with no warning
  (a rescue copy would betray it, a stderr line would not).
- **R16-31** (documented, `luksbox-merge`) Hard links of a new file in
  `ours` are noted as "merged as separate copies" but the extra names
  are not created; `ours`' rename-over-existing idiom ends with the
  intended file at a conflict name and the displaced one deleted.
  Nothing is lost, placement is wrong.
- **R16-32** (documented, `luksbox-mount`) A panic inside the commit
  hook or any Vfs operation while the Vfs mutex is held poisons it: the
  mount returns EIO on everything, the timer thread is gone, `destroy`
  skips the final flush, and `commit_point` silently never calls the
  hook again (a WinFsp callback would panic across the FFI boundary).
  Wrap the hook in `catch_unwind` and treat `PoisonError` as recoverable
  in the adapters.
- **R16-33** (documented, `luksbox-core`) The Argon2 parameter envelope
  accepted from an unauthenticated header (up to 4 GiB x 16 passes) is
  enforced with `try_reserve_exact`, which succeeds virtually under
  Linux overcommit; a hostile header then faults in 4 GiB and the OOM
  killer, not the clean `KdfOutOfMemory` path, ends the process (every
  vault open in a GUI). The slot cannot be unlocked with tampered
  parameters (they are in the AAD), so this is availability only.
- **R16-34** (documented, GUI) The Linux file-dialog helper receives the
  in-vault file name being extracted on its command line, visible in
  `/proc/<pid>/cmdline` to other accounts while the dialog is open.
  Pass it over the helper's stdin.
- **R16-35** (documented, GUI) The bundle `Session` (bundle keys, MVK
  clone, open lease) is installed before the rest of the unlock is
  known to succeed; a failure after it leaves them live until the next
  open or exit. The GUI also has no inactivity lock. Memory-disclosure
  model only.

## INFO

- **R16-19** (fixed, `luksbox-mount` WinFsp) `write` reported
  `buffer.len()` instead of what `Vfs::write` returned; harmless today
  (`Vfs::write` never short-writes), fixed for the day it does.
  Windows-only, compile-unchecked here.
- **R16-20** (fixed, `luksbox-core`) `reject_null_factor` compared a
  secret factor to zero with a short-circuiting `all`; now `subtle`.
- Header objects are sorted by the generation inside them before the
  credential is tried: unauthenticated, but a hint only. The header
  that opens is HMAC-verified under the MVK it yields, and the head's
  header is taken by hash from a verified manifest. Sound.
- The hybrid sidecar object a session uses is the one the newest
  manifest names, but its `hybrid.hash` is not compared at open; the
  sidecar's own salt binding and the slot AEAD fail closed on a swap.
  Compare it (defence in depth).
- FUSE-T on macOS: `default_permissions`, `nosuid`, `nodev` and the
  per-user mount point are enforced by the NFS client, and any local
  process can speak NFS to the loopback port with any uid; the
  mount-layer controls are decorative on that backend (documented in
  `MACOS_FUSE_T.md`).
- TPM slots: no PCR policy, empty auth unless a PIN slot, SRK pinning
  off by default, so any local account in the `tss` group with a copy
  of the vault unseals the KEK (documented "no-PIN baseline").
- FIDO2: nothing authenticates the authenticator before the PIN
  protocol (no attestation, by documented choice);
  `luksbox-fido2/src/protocol.rs` (a hand-rolled pinUvAuth v1) is
  referenced by no production code and should be `#[cfg(test)]` or
  removed.
- Post-quantum hybrid KEKs do not bind the KEM ciphertext or public
  key into the combiner; ML-KEM's implicit rejection and the slot AEAD
  make this a robustness gap, not an attack. Phase 3 (X-Wing) closes it.
- The GUI's GVfs folder icon records the bundle's canonical path in
  `~/.local/share/gvfs-metadata/` (permissions not under LUKSbox's
  control); documented, opt-out `LUKSBOX_NO_FOLDER_ICON`. Never for
  deniable vaults, which cannot be bundles.
- `sync status`, `sync push` and `sync export` publish and may merge on
  their way out (by design, the session is finished at the end of every
  command); a read command can therefore write a merge commit.

## Accepted for now / documented

- **R16-17** (HIGH, mitigated): see above. A revocation on a bundle is
  cosmetic until epoch keys land; the CLI says so at every revoke.
- **R16-21** (MEDIUM): chunk AAD not fork-specific; a format change.
- **R16-23** (MEDIUM): manifest cap without automatic collection.
- The lows and infos marked *documented* above.

## New regression coverage

| File | Tests | Findings |
|---|---|---|
| `crates/luksbox-vfs/tests/round16_findings.rs` | 3 | R16-01 (two tests), R16-02 |
| `crates/luksbox-format/tests/round16_findings.rs` | 2 | R16-14, R16-15 |
| `crates/luksbox-sync/tests/round16_findings.rs` | 11 | R16-03 (two), R16-04 (two), R16-05, R16-06, R16-07, R16-08, R16-09, R16-22 (snapshot export) |
| `crates/luksbox-merge/tests/merge_rules.rs` | +1 | R16-11 |
| `crates/luksbox-cli/tests/sync_bundle.rs` | +1 | R16-17 (revoke warning), R16-22 (`sync export --snapshot`, through the binary) |
| `crates/luksbox-sync/src/bundle.rs` (unit) | +1 | R16-07 (`cap_seen`) |

Every test is green on this revision and `0 #[ignore]`d (the 258-device
run of the R16-07 test is behind `LUKSBOX_SLOW_TESTS=1`, it takes
minutes in a debug build; the default run covers 4 devices and prints
`[skip]`). The tests for R16-01, R16-02, R16-03 and R16-04 were run
against the baseline code and fail there. Not run here: Windows
(R16-19) and macOS (R16-13) paths, compile-checked only where the host
allows.

New fuzz targets (`fuzz/fuzz_targets/`, all also wired for AFL++ where
they take raw bytes; `scripts/fuzz_sync.sh` runs the sync set):
`sync_lease_decode`, `sync_local_state_decode`, `sync_listing_classify`,
`sync_fs_store_hostile` (the real folder with planted links, FIFOs,
hard links and misplaced entries; asserts nothing outside the bundle is
ever read), `sync_keyslot_merge` (a removal is never undone, no slot is
invented, the merged generation is newer) and
`sync_bundle_open_adversarial` (an "evil provider" applying deletions,
damage, truncations, duplications, swaps and plants to a real bundle,
asserting the device never reads bytes it did not write). See
`FUZZING.md`.

## Surfaces reviewed and found sound

- **Sync key schedule and object envelope.** Roots are HKDF subkeys of
  the MVK with the header salt and `lbx:sync/<kind>/v1 || bid` (a label
  prefix no other derivation in the workspace uses); per-object keys
  from a 256-bit random id that only `codec::seal_new` draws, so the
  zero nonce is single-use; key commitment compared in constant time
  before the AEAD; AAD binds format, kind, bundle id, object id and
  position; cut-and-paste between kinds, positions and bundles fails
  (tests). Local records use a random nonce under a separate root.
- **Commit graph.** Contiguous sequence numbers per device above the
  checkpoint, parents matched by hash, device, seq and oid; heads
  sorted deterministically; every `seen` and `parents` claim of every
  verified manifest (usable or not) must be present (`Missing` ->
  read-only, fail closed); a checkpoint can only hide what a verified
  Gc commit declared, and such a commit's own `seen` keeps its author's
  view checkable. Rollback, equivocation and identity conflicts are
  checked against the sealed local state; identity conflicts resolve
  to a new identity without an outage. Head selection and the merge
  base (newest commit on both first-parent chains) are sound given
  R16-03.
- **Publish protocol.** Objects first, `manifest-pending` and
  `publishing` recorded locally, manifest last, state finalised; a
  crash re-publishes the same bytes, so no device writes two commits
  with one number. Uploads never hold the vault; `prepare`/`published`
  rebase saves made meanwhile. Publishing is refused while a referenced
  commit is missing.
- **Garbage collection.** Roots: every device's newest commit, the
  last 50, 30 days by wall clock, every lease pin (base and the newest
  other-device commit on its line) for 90 days; two passes with a 7 day
  grace measured as the younger of the plan's clock and the local
  sighting; orphans (no known commit refers to them: an upload in
  progress) wait 90 days; a device whose clock went back refuses to
  collect; deletion is by validated name only. The lease-delivery
  dependency (a lost lease plus 30 days of inactivity) is inherent and
  documented.
- **Hostile folder I/O (Unix).** The bundle, area and shard folders are
  opened `O_DIRECTORY | O_NOFOLLOW` and every operation is relative to
  those handles; objects are opened `O_NOFOLLOW | O_NONBLOCK | O_NOCTTY`
  and must be regular files with one link and the exact size for their
  kind; reads are bounded with an EOF probe; creates go through an
  exclusive temp file, `linkat` (or `renameat2(RENAME_NOREPLACE)`) and
  folder fsync, never overwriting; deletes are `unlinkat` of a
  grammar-valid name; listings are capped. Windows: handle final-path
  comparison on every open, reparse points refused, no-clobber creates;
  the known by-path write TOCTOU is documented.
- **Names.** Fixed-length lowercase hex matched exactly; uppercase,
  padding, Unicode look-alikes and conflict-copy suffixes are foreign;
  a parsed name prints back to itself (fuzzed).
- **Manifests and leases.** Framed with a strict length and zero
  padding, postcard-decoded with no trailing bytes, validated (format,
  bundle id, bounds, page size, table count against the image length,
  sanitised label, kind/parent consistency, no device twice).
- **Keyslot-table merge.** Compared by meaning, slot by slot against
  the base; a removal always wins; two enrollments into one free slot
  are both kept; different changes to one slot keep the target's and
  say so; a changed frame on both sides stays a fork; the merged header
  is re-MAC'd under the MVK with a generation above both sides'. Now
  fuzzed.
- **Core.** Header HMAC over everything but itself with `ct_eq`; slot
  AAD binds kind, AAD version, uuid, KDF params, salts, nonce, cred id
  and the header salt; no nonce reuse; HKDF labels distinct; all
  secret-bearing types zeroise and have no `Debug`; `memfd_secret` with
  `O_CLOEXEC`; file helpers no-clobber and no-follow. Nothing above LOW.
- **Format.** Pre-HMAC parsing bounds-checked throughout; external
  (bundle) header verification equals the file path's; read-only mode
  refuses every write path including `Drop`; the bucketed metadata
  refresh re-randomises the whole bucket and leaves file vaults
  unchanged (I14); anchors v1/v2 MAC'd and monotonic; mirrors follow
  the intended-state protocol; MVK rotation keeps lock, handle and
  abort state (R15 fixes hold).
- **VFS and merge.** Chunk AAD includes the generation (replay of an
  older chunk at the same place fails); file ids monotonic within a
  lineage; freed slots are reused only after an overwrite; read-only
  mode gates every mutator; `is_safe_symlink_target` enforced at
  create, open and flush; the merge is deterministic, keeps every
  version (property-tested), zeroises plaintext buffers, writes no
  plaintext to disk (I10).
- **Mount, FFI, hardware.** `nosuid`/`nodev`/`default_permissions`, no
  `allow_other`; names validated; offset arithmetic checked; mount
  point re-probed before mounting; MVK handed to helpers over an
  anonymous pipe and zeroised; WinFsp security descriptor limited to
  the user; libfido2 and webauthn.dll buffers bounded; TPM sessions
  salted and encrypted; SEP keys device-bound; ML-KEM used correctly;
  seed files bounded and zeroised.
- **Application layer.** No secrets on command lines or in logs;
  passphrases read with echo off or from an environment variable and
  zeroised; deniable vaults leave no recent entry, anchor, state or
  icon; bundle folders hold nothing but hex-named objects; subprocesses
  are launched from absolute paths with fixed arguments; exported and
  extracted files are created no-clobber; `delete` removes only
  grammar-named objects, never recursively.
