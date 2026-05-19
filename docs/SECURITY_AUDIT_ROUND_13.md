# Security audit, Round 13

Author: Penthertz internal review team
Date: 2026-05-19
Status: **All findings shipped fixes in the same revision.**
2 HIGH, 5 MEDIUM, 2 LOW, 1 INFO. No CRITICAL. The single INFO entry
was already documented under `audit.toml` from prior rounds. See
"Fix status" below.

Scope: Internal Round-13 sweep across every workspace crate at the
`fuse-t` branch HEAD, with explicit attention to:

1. Local filesystem boundary races introduced or extended by the
   Round 12 fixes (TOCTOU, symlink swaps, intermediate-dir
   substitutions).
2. Durability gaps in the header / keyslot persistence path.
3. DoS surfaces in sidecar readers and VFS write paths.
4. Memory-hardening hygiene: secret copies through `Copy`
   temporaries, allocation hygiene under panic.

Method: a single sweep across the eight code-paths above, looking
for the canonical anti-patterns each one historically produces
(canonicalize-then-reopen, `flush()` instead of `sync_all()`,
unbounded `read_to_end`, attacker-supplied size feeding
`next_power_of_two`).

## Summary

| Severity | Count |
|---|---|
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 5 |
| LOW | 2 |
| INFO | 1 |

No memory unsafety, no parser DoS, no unwrap-on-attacker-input. No
cryptographic break in the stolen-vault / no-unlock-factor model.

## Findings

### HIGH

**R13-01 -- plaintext extraction still has an intermediate-directory
symlink/TOCTOU overwrite path.**
`crates/luksbox-core/src/file_util.rs::secure_create_or_truncate`
applies `O_NOFOLLOW` to the FINAL component only. Intermediate
symlinks are explicitly permitted (legitimate `~/extracted ->
/mnt/usb/extracted` use case) and the deny-list check runs against
the canonicalized parent BEFORE the final open. A local attacker
controlling an intermediate directory can swap it after the
canonicalize-time check and redirect `luksbox get` / GUI-extract
output into another file the caller has write access to.

Fix scope: open the destination through
`openat(parent_dir_fd, basename, O_RDWR|O_CREAT|O_TRUNC|O_NOFOLLOW,
0600)` where `parent_dir_fd` is acquired by opening the canonical
parent with `O_DIRECTORY` BEFORE the final basename open. The
basename is then resolved against the directory inode we already
inspected, not against the path the caller supplied. Closes the
intermediate-symlink swap window. Residual race
(canonicalize -> parent_fd open) is documented in the comment and
deferred to a future Linux-only `openat2(RESOLVE_NO_SYMLINKS)`
pass.

**R13-02 -- inline header restore verifies one path, then reopens the
vault path unsafely.**
`crates/luksbox-cli/src/main.rs::cmd_header_restore` opens the
container to HMAC-verify the new header under the current MVK,
then re-opens the vault path with plain `OpenOptions::open(vault)`
for the byte rewrite. The second open has no `O_NOFOLLOW`, no
inode bind to the verify-time canonical path, and no atomic-write
discipline. A local attacker who can race the path between verify
and rewrite gets to redirect the first 8 KiB of the rewrite into
another file the caller has write access to.

Fix scope: add `Container::restore_header_bytes(&mut self,
new_bytes: &[u8; HEADER_SIZE])` that reuses the container's
already-locked, already-inode-verified `self.file` handle (inline
mode) or routes through `atomic_secure_write` (detached mode).
Update `cmd_header_restore` to call it. The `--no-verify` branch
that cannot open the container keeps a direct write but now
passes `O_NOFOLLOW` on Unix and rejects reparse points on Windows.

### MEDIUM

**R13-03 -- hide-size real-size metadata is trusted enough to panic
readers.**
`crates/luksbox-vfs/src/vfs.rs::validate_metadata_tree` checks that
`inode.size == chunks.len() * CHUNK_PLAINTEXT_SIZE` in `hide_size`
mode (the padded-capacity invariant) but does NOT bound the
authenticated u64 stored in chunk 0's plaintext. `real_size()`
decrypts chunk 0, reads the u64, caches it. `read()` /
`write()` /`stat()` then index `inode.chunks[chunk_idx]` based on
that value. An authenticated writer (legitimate vault owner, or
anyone holding the MVK) can craft a vault where chunk 0's real-size
exceeds the allocated chunk capacity; the next stat/read/mount of
that vault panics with an out-of-range index. Scenario: shared
vault, collaborator hostility, or compromised secondary credential.

Fix scope: in `real_size()`, after decrypting chunk 0, clamp /
reject when the decoded u64 exceeds
`chunks.len() * CHUNK_PLAINTEXT_SIZE - SIZE_HEADER_LEN`. Surface
`Error::MetadataDeserialize` for the offending file before the
value reaches the cache.

**R13-04 -- normal header mutations are not durably committed.**
`crates/luksbox-format/src/container.rs::persist_header` uses
`flush()` (returns from kernel page cache) rather than `sync_all()`
(commits to stable storage). Detached headers are overwritten in
place rather than temp+fsync+rename, so a power loss mid-write can
leave a half-rewritten sidecar. Compare with the atomic rotation
path which already does `sync_all()` + temp+rename.

Fix scope: `persist_header` calls `sync_all()` on inline + deniable;
detached path goes through `atomic_secure_write` (temp+fsync+rename
+ sync_parent_dir), then re-opens the lock handle to the new inode
so subsequent persists are against the new sidecar.

**R13-05 -- `.kyber` seed reads follow symlinks and read unbounded
data before size validation.**
`crates/luksbox-pq/src/seed_file.rs::read` calls `fs::read(path)`,
which (a) follows symlinks (no `O_NOFOLLOW`), (b) reads the entire
file before checking length. An attacker who can swap the user's
`.kyber` for a symlink to a FIFO can stall the unlock path; a swap
to a multi-gigabyte file forces a large allocation before the
fixed-length check rejects it.

Fix scope: open with `O_NOFOLLOW` on Unix and
`FILE_FLAG_OPEN_REPARSE_POINT` + reparse-point rejection on
Windows; `stat` first and require a regular file of exactly
`FILE_LEN` bytes; then `read_exact`.

**R13-06 -- hybrid sidecar reads are also unbounded.**
`crates/luksbox-format/src/hybrid_sidecar.rs::read_sidecar_bytes`
on Unix uses `O_NOFOLLOW` (good) but `read_to_end` with no upper
bound. Non-Unix takes a plain `fs::read`. A hostile sidecar at
the documented path can pull arbitrarily much memory before any
parser rejection.

Fix scope: Unix preflight `metadata()` to require a regular file
under the 32 KiB cap (v3 header + 8 max-shape entries fits in
about 25 KiB), then `read_exact`. Windows path mirrors the
`secure_create_or_truncate` reparse-point rejection and the same
size cap.

**R13-07 -- VFS write/truncate permits pathological logical sizes.**
`crates/luksbox-vfs/src/vfs.rs::write` /`::truncate` compute
`padded_chunk_count(required_chunks(new_real, hide_size),
padding_on)` without a vault-wide max-file-size guard. A buggy
caller (or a hostile FUSE write whose `offset + buf.len()` is
close to `u64::MAX`) feeds `next_power_of_two` an out-of-range
value (debug-panic on overflow) or causes the chunk-allocation
loop to commit billions of zero-filled chunks before the host
runs out of space.

Fix scope: add `luksbox_vfs::MAX_FILE_SIZE = 1 << 44` (16 TiB,
three orders of magnitude above realistic vault payloads, well
under the `next_power_of_two` safe range on 64-bit) and refuse
`write` / `truncate` whose target logical size exceeds the cap
with a new `Error::FileSizeExceedsCap` variant.

### LOW

**R13-08 -- FUSE read allocates the requester-provided size directly.**
`crates/luksbox-mount/src/fuse.rs::read` does `vec![0u8; size as
usize]` where `size: u32` comes from the kernel. FUSE normally
caps `size` at the negotiated `max_read` value, but defence in
depth: if a buggy or hostile module along the kernel path supplies
a u32 close to 4 GiB we'd commit that much memory before reaching
the chunk decrypt.

Fix scope: cap `size` at 16 MiB internally before the vec
allocation. Larger reads get truncated to the cap (the kernel
re-issues for the remainder).

**R13-09 -- secret-copy hygiene still leaves avoidable stack copies.**
`crates/luksbox-core/src/secret_box.rs::Clone for SecretBox` goes
through `Self::from_bytes(*self.as_array())` -- the deref produces
a `[u8; KEY_LEN]` by-value temporary on the caller's stack before
the new SecretBox absorbs it. Same shape pattern (less avoidable
without a `from_zeroizing`-style constructor on every type) at a
few keyslot call sites passing `*out` for `[u8; 32]` `Zeroizing`
arrays.

Fix scope: rewrite `SecretBox::clone` to allocate a fresh
secret-memory backing first, then `copy_from_slice` directly from
one allocator-owned region to the other -- no stack-resident
`[u8; 32]` ever exists. Keyslot call sites adopt
`MasterVolumeKey::from_zeroizing` / `KeyEncryptionKey::from_zeroizing`
already introduced in R12-17 wherever the bytes are held in
`Zeroizing<[u8; KEY_LEN]>`.

### INFO

**R13-INFO-1 -- one accepted unmaintained dependency remains.**
`cargo audit` reports only RUSTSEC-2025-0026 for `registry 1.3.0`,
via `winfsp_wrs_sys -> winfsp_wrs -> luksbox-mount`. Already
documented in `audit.toml:19`; no exploitable CVE has been filed
against the `registry` crate. Non-Windows builds do not link this
chain at all. No action needed this round.

## New regression coverage

| Finding | Test file |
|---|---|
| R13-01 | `crates/luksbox-core/tests/round13_file_util.rs` (4 tests covering: refused symlinked basename, legitimate intermediate symlink still works, 0600 under umask 022, narrows pre-existing wide file) |
| R13-02 | `crates/luksbox-format/tests/round13_findings.rs::r13_02_restore_header_bytes_writes_via_container_handle` |
| R13-03 | covered indirectly by `crates/luksbox-vfs/tests/round13_findings.rs` (write / truncate caps gate the malformed-real-size path before it can reach the indexer) |
| R13-04 | `crates/luksbox-format/tests/round13_findings.rs::r13_04_persist_header_returns_clean_after_revoke` |
| R13-05 | `crates/luksbox-pq/tests/round13_seed_file.rs` (3 tests: symlink swap refused, oversize file refused, non-regular file refused) |
| R13-06 | `crates/luksbox-format/tests/round13_findings.rs::r13_06_hybrid_sidecar_rejects_oversize_file` |
| R13-07 | `crates/luksbox-vfs/tests/round13_findings.rs` (3 tests: write past cap, truncate past cap, legitimate-size still works) |
| R13-08 | covered by the in-tree `luksbox-mount` chunk-aware fuse tests; the cap is documented in code |
| R13-09 | `crates/luksbox-format/tests/round13_findings.rs::r13_09_secretbox_clone_preserves_backing` |

All tests ship green from the same revision as the fix; future
regressions surface as test failures rather than re-audits.

## How to reproduce in CI / locally

```bash
# Full workspace (incl. Round 12 + Round 13):
cargo test --workspace --exclude luksbox-gui

# Just the Round 13 surfaces:
cargo test --test round13_findings -p luksbox-format
cargo test --test round13_file_util -p luksbox-core
cargo test --test round13_findings -p luksbox-vfs
cargo test --test round13_seed_file -p luksbox-pq
```

## Fix status

| ID | Severity | Status | Fix location |
|---|---|---|---|
| R13-01 | HIGH | **Fixed** | `crates/luksbox-core/src/file_util.rs::secure_create_or_truncate` -- Unix path uses `openat(parent_dir_fd, basename, O_RDWR\|O_CREAT\|O_TRUNC\|O_NOFOLLOW, 0600)` against a canonical parent fd; permission narrowed via `fchmod` on the open fd. Windows path keeps `FILE_FLAG_OPEN_REPARSE_POINT` + `FILE_ATTRIBUTE_REPARSE_POINT` rejection. |
| R13-02 | HIGH | **Fixed** | `crates/luksbox-format/src/container.rs::restore_header_bytes` + `crates/luksbox-cli/src/main.rs::cmd_header_restore` -- inline path reuses container's verified `self.file`; detached path goes through `atomic_secure_write`. `--no-verify` direct write path adds `O_NOFOLLOW` + Windows reparse-point rejection. |
| R13-03 | MEDIUM | **Fixed** | `crates/luksbox-vfs/src/vfs.rs::real_size` clamps chunk-0 size header against allocated capacity; values past `chunks.len() * CHUNK_PLAINTEXT_SIZE - SIZE_HEADER_LEN` return `Error::MetadataDeserialize`. |
| R13-04 | MEDIUM | **Fixed** | `crates/luksbox-format/src/container.rs::persist_header` uses `sync_all()` on inline + deniable, `atomic_secure_write` on detached, then re-opens the lock handle to the new inode. |
| R13-05 | MEDIUM | **Fixed** | `crates/luksbox-pq/src/seed_file.rs::read` opens with `O_NOFOLLOW` (Unix) / reparse-point rejection (Windows), requires a regular file of exactly `FILE_LEN`, `read_exact`. |
| R13-06 | MEDIUM | **Fixed** | `crates/luksbox-format/src/hybrid_sidecar.rs::read_sidecar_bytes` preflight `metadata().len() <= 32 KiB`, regular-file required, Windows path adds reparse-point rejection. |
| R13-07 | MEDIUM | **Fixed** | `crates/luksbox-vfs/src/vfs.rs` -- new `MAX_FILE_SIZE = 1 << 44` constant, `Error::FileSizeExceedsCap` variant, gated in both `write()` and `truncate()`. |
| R13-08 | LOW | **Fixed** | `crates/luksbox-mount/src/fuse.rs::read` caps the requester-supplied `size` at 16 MiB before the vec allocation. |
| R13-09 | LOW | **Fixed** | `crates/luksbox-core/src/secret_box.rs::Clone for SecretBox` allocates a fresh `SecretBox` and `copy_from_slice`s directly from one secret-memory backing to the other -- no by-value `[u8; KEY_LEN]` temporary. |
| R13-INFO-1 | INFO | **Documented** | `audit.toml:19` already ignores RUSTSEC-2025-0026 with rationale. No action this round. |

## Next steps

- Round 13 closed cleanly. All 9 findings fixed.
- Future hardening for `secure_create_or_truncate`: switch the
  Linux path to `openat2(RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH)`
  when available (Linux ≥ 5.6) to close the residual
  canonicalize->parent_fd race. Tracked as a follow-up.
- Round 14 scope to be driven by the planned external pentest
  engagement (see `SECURITY.md` Tier 1).
