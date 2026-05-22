# Working with Claude on LUKSbox

A living playbook the project maintainers use to brief Claude (Code,
API, web app) on this codebase. Edit freely as you discover patterns
that work or don't. Not auto-loaded — paste the relevant sections
into new sessions, or link to this file.

Two threads run through everything below:

1. **LUKSbox is a cryptographic tool.** Bugs in cryptographic code
   fail silently (wrong KEK still produces a valid-looking AEAD
   nonce; ML-KEM decap "succeeds" with garbage shared secret on
   wrong inputs) and the only defense is rigorous review against a
   short list of mistakes others have made before. Section
   ["Crypto-tool review checklist"](#crypto-tool-review-checklist)
   captures that list as we hit each one.

2. **Each release adds new factors / variants / extensions** (e.g.,
   FIDO2 + ML-KEM in deniable mode, TPM + FIDO2 + PQ 3-factor).
   Extending the credential surface is where most of our security
   bugs land — see ["Extending the credential / slot surface
   safely"](#extending-the-credential--slot-surface-safely).

---

## How to brief a fresh Claude session

Paste this block (trim as needed) at the start of any new
conversation:

> I'm working on LUKSbox, a Rust workspace producing an encrypted-
> container tool with a CLI, TUI wizard, and egui GUI on
> Linux/macOS/Windows. The crypto stack is: Argon2id (passphrase
> KDF), AES-256-GCM / GCM-SIV / ChaCha20-Poly1305 (AEAD), HKDF-SHA256
> (KEK combiner), FIDO2 hmac-secret (CTAP2), TPM 2.0 sealed objects
> (tss-esapi, Linux only), ML-KEM-768/1024 (FIPS 203, post-quantum
> KEM). The format has two modes: standard (visible slot table) and
> deniable (8 envelopes indistinguishable from random). See
> `docs/CRYPTO_SPEC.md`, `docs/DENIABLE_HEADER.md`, and
> `docs/SECURITY_ARCHITECTURE.md` for the formal model.
>
> Behavioural preferences:
> - Terse output. No emojis. No trailing summaries when a diff
>   already speaks for itself.
> - Ask before destructive shell ops (rm, git reset --hard, force
>   push) even after a prior approval.
> - When you fix a security-relevant bug, also add a regression test
>   and run `cargo test --workspace` before declaring done.
> - When making crypto / format changes, follow up with a short
>   security audit referencing the section below.
> - Be honest about what you didn't / couldn't verify (e.g., "I
>   couldn't test the Windows installer on a real machine").

Add project-specific gotchas you remember from the current task.
The above gets you 80% of the way; the rest is whatever this
particular task needs.

---

## Crypto-tool review checklist

Mistakes we've actually shipped (or nearly shipped) and what to
look for so they don't recur. Each entry has: a one-line rule, a
concrete example from THIS repo, and the file to grep when
auditing.

### AAD must cover everything the slot is bound to

**Rule:** every byte that distinguishes one keyslot kind /
version / vault from another must be in the AEAD AAD, so flipping
it on disk breaks the AEAD tag rather than producing a different
valid plaintext.

**Example:** `Keyslot::build_aead_aad` covers slot bytes
`[0..76] || [124..512] || header_salt`, which includes the kind
byte (offset 0), aad_version byte (offset 1), kdf_salt, aead_nonce,
cred_id, hmac_salt, plus the vault's header_salt. A future slot
kind that adds a new field MUST extend the AAD region or the new
field is silently tamperable.

**Grep:** `crates/luksbox-core/src/keyslot.rs::write_aad_region` +
`build_aead_aad`.

### Domain-separate every KEK derivation

**Rule:** every distinct credential variant must derive its KEK
through a HKDF call with a unique `info` label. Variants that share
a KEK formula can interfere via unknown-key-share attacks or simply
get confused at unlock time.

**Example:** the four hybrid-PQ slot constructors use
`b"lbx:hybrid-kek/v1"` (passphrase variant) vs
`b"lbx:hybrid-fido-kek/v1"` (FIDO2 variant). Deniable variants
use `b"luksbox-deniable-v2/kek/..."` prefixed labels. The 768 vs
1024 ML-KEM distinction is NOT in the info string — it's
distinguished by the slot's `kind` byte (in the AEAD AAD), which
is the right tradeoff because the wrap math is identical for both
KEM sizes (both produce a 32-byte shared secret).

**Grep:** `crates/luksbox-core/src/kdf.rs` (look for
`hkdf_combine`, `info:`) and
`crates/luksbox-core/src/deniable.rs::hkdf_info`.

### Atomic enroll: install → write sidecar → write .kyber → persist; reverse on any failure

**Rule:** when an enroll touches multiple on-disk artifacts (slot
table, hybrid sidecar, .kyber seed file), install the in-memory
slot FIRST (no persist yet), then write the disk-side files in
dependency order, then persist the header LAST. On any failure
roll back ALL earlier writes so the on-disk vault is unchanged.

**Example:** `ops::enroll_hybrid_pq_passphrase_deniable` and its
siblings (search for `enroll_hybrid_pq_*_deniable`). Each does:

```
1. install slot in memory (header_dirty = true, NOT persisted)
2. snapshot prior_entries from existing sidecar
3. build new entries = prior.filter(|e| e.slot_idx != new) + new
4. write sidecar  → on failure: clear_deniable_slot + return
5. write .kyber   → on failure: clear_deniable_slot + restore sidecar + return
6. persist_header → on failure: clear_deniable_slot + restore sidecar + remove kyber + return
```

The `rollback_sidecar(path, prior_entries)` helper in
`crates/luksbox-gui/src/ops.rs` exists for this dance.

### Match sidecar entries to the slot index the envelope resolved

**Rule:** when iterating through `.hybrid` sidecar entries, look
up the entry whose `slot_idx` matches the slot you're actually
unlocking. Defaulting to `entries.first()` silently uses the wrong
entry's `(pk, ct)` pair when the user has multiple PQC-bearing
slots, and ML-KEM's implicit rejection (FIPS 203) means the decap
SUCCEEDS with a garbage 32-byte shared secret rather than
returning an error. The garbage then flows through the slot KEK
derivation, the AEAD fails downstream, and the user sees an
opaque unlock failure with no indication of where it broke.

**Example bug we shipped and fixed:**
`ops::deniable_pq_decap` used to take `entries.first()`. Vaults
with 2 PQC slots (e.g., TPM+FIDO2+PQ at slot 1 + passphrase+PQ at
slot 3) failed to unlock the non-first one. Fix:
`hybrid_sidecar::find(&entries, slot_idx)` where `slot_idx` comes
from `envelope.opened.matched_slot_idx`.

**Grep:** `entries.first(`, `entries\[0\]`, `hybrid_sidecar::find`
across both `crates/luksbox-gui/src/ops.rs` and
`crates/luksbox-cli/src/wizard.rs`.

### Reject duplicate slot_idx at write, not just at read

**Rule:** integrity checks that exist on the READ path should ALSO
run on the WRITE path so a buggy writer fails fast at the bug
site, not at the next reader.

**Example:** `hybrid_sidecar::validate_entries` now calls
`reject_duplicate_slot_idx`. Without that, a writer that forgot to
dedupe stale entries produced a sidecar that the next read
rejected with "duplicate entry for slot N" — making the bug
attributable to "the user did something weird" instead of "we
wrote bad bytes". With the write-time check it fails at the
enroll's own write step, surfacing the bug to its author.

### Don't trust ML-KEM decap "success" — it's defined to never fail

**Rule:** FIPS 203 mandates implicit rejection: ML-KEM decap with
invalid inputs returns a deterministic but unrelated 32-byte
output, not an error. Treat the output as garbage if anything else
upstream (sidecar entry mismatch, wrong seed) could be wrong.

**Implication:** wrap downstream AEADs to be the integrity check.
Match the sidecar entry, decap, derive KEK, attempt AEAD-open. If
AEAD fails, the problem could be ANY of: wrong passphrase, wrong
seed file, wrong sidecar entry, wrong kind hint. Surface all of
them in error messages where you can.

### Slot/envelope/seed passphrases are independent — don't conflate

**Rule:** any time the user types a "passphrase", check whether
the code path needs ONE or MULTIPLE passphrases. Conflating them
forces all users into "must reuse the same string" which is
worse UX AND a security weakening.

**Example bug:** `unlock_with_hybrid_pq` used to take a single
`passphrase: &str` and pass it BOTH to `seed_file::read` (decrypts
the .kyber seed) AND to the slot KEK derivation. Users who picked
two distinct passphrases at enroll couldn't unlock. Fix: split
into `slot_pw: &str` and `seed_pw: &str` with a fallback "use
slot_pw if seed_pw is empty" for the ergonomic case.

### Deniable mode: kind-hint the envelope discovery loop

**Rule:** the deniable envelope discovery iterates 8 slots and
prefers a kind-matching slot. If multiple slots share the same
envelope passphrase, the discovery loop picks the FIRST slot
whose AEAD opens — which is usually slot 0 (admin). Hint it with
the user's INTENDED kind via the `want_kind` parameter so the
right slot wins.

**Example:** `try_open_envelope_v2(header, cred, cipher, want_kind)`
takes `Option<DeniableKindTag>`. Production callers pass
`Some(expected_kind)`; tests pass `None` (= use `credential.kind_tag()`
which is legacy v2 behavior).

### Cipher choice persistence (deniable mode footgun)

**Rule:** deniable vaults have no on-disk magic; the user must
remember and re-supply the cipher at every open. If your GUI form
defaults the cipher dropdown to something other than what the
vault was created with, users get "unlock failed" with no clue.

**Example fix:** GUI's recent-vaults handler pre-populates
`deniable_cipher` from `RecentVault.cipher` instead of always
defaulting to AES-GCM-SIV.

### Empty passphrase = silent downgrade

**Rule:** an empty passphrase that gets through validation
silently downgrades a slot to "no auth value". Reject empty input
unless the caller explicitly opts in via `None` / `Option<&[u8]>`.

**Example:** `enroll_tpm2_deniable(tpm_pin: Option<&[u8]>)` rejects
`Some(b"")` with "TPM PIN cannot be empty; pass None for the
no-PIN variant" because an empty-Some used to seal a blob whose
unlock-path `unseal_with_pin(empty)` then failed with
`TPM_RC_AUTH_FAIL` and incremented the chip's dictionary-attack
counter on every retry.

### Constant-time loops over slots / candidates

**Rule:** when iterating slots to find a match (deniable envelope
discovery, FIDO2 cred_id lookup), the iteration MUST do identical
work for every slot or you leak the matched index via timing /
allocator pressure. Use `subtle::Choice`-driven conditional select
rather than `if matched { return ... }`.

**Example:** `try_open_envelope_v2` in
`crates/luksbox-format/src/deniable_header.rs`. Search for the
"Round 12 fix R12-01" comment for the full rationale.

### Zeroize all secrets including stack copies

**Rule:** wrap secrets in `Zeroizing<...>` so panic / early-return
paths also wipe them. `.zeroize()` calls at end-of-scope only fire
on the happy path.

**Example:** `kdf::derive_hybrid_kek` wraps both the HKDF IKM
(`Zeroizing<[u8; 64]>`) and the HKDF output buffer
(`Zeroizing<[u8; 32]>`) so a panic anywhere in `Hkdf::expand`
still wipes the intermediate key material.

---

## Extending the credential / slot surface safely

When adding a new slot variant (e.g., "passphrase + ML-KEM-1024 +
FIDO2 + post-X feature"), follow this checklist:

1. **Define the slot kind byte** in `crates/luksbox-core/src/keyslot.rs::SlotKind`
   with a distinct discriminant. Update the kind-matching predicates
   (`is_passphrase`, `is_hybrid_pq_passphrase`, etc.).
2. **Add a constructor** `Keyslot::new_<variant>(...)` and an unlock
   helper `unlock_<variant>(...)` in the same file. The unlock helper
   MUST refuse if `self.kind != expected_variant` (defense-in-depth
   on top of the AAD's kind byte coverage).
3. **Add a KEK derivation function** in `crates/luksbox-core/src/kdf.rs`
   with a UNIQUE HKDF info label. Reuse the cross-section helpers
   only if you're confident the inputs are domain-separated.
4. **Add Container methods**: `enroll_<variant>` (standard mode) +
   the deniable equivalent in `crates/luksbox-format/src/container.rs`.
5. **Add ops wrappers** in `crates/luksbox-gui/src/ops.rs` that do the
   atomic-enroll dance (install → sidecar → .kyber → persist).
6. **Add unlock dispatch** in both `ops::unlock_vault` (GUI/standard)
   and the deniable phase-2 arms in the same file.
7. **Add the kind-hint mapping** in the GUI unlock form so
   `try_open_envelope_v2_deniable` gets `Some(expected_kind)`.
8. **Add buttons + modals** in `crates/luksbox-gui/src/app.rs`. New
   modals MUST gate deniable-mode rendering on `is_deniable` (the
   envelope passphrase comes from `DeniableEnrollExtras`, not from a
   separate modal field).
9. **Add wizard menu entries** in `crates/luksbox-cli/src/wizard.rs::keyslot_loop`.
10. **Add regression tests** in `crates/luksbox-format/tests/` covering:
    - install + persist + reopen → MVK matches.
    - Original slots still open (no clobber).
    - Wrong factor (wrong hmac_secret / wrong pq_shared / wrong PIN)
      MUST fail unlock — pins that the slot is actually bound to
      that factor.
11. **Run a security audit pass** referencing the checklist above.
    Specifically verify: AAD coverage of any new field, HKDF info
    domain-separation, ML-KEM trap (if PQ is involved), atomic-
    enroll roll-back, sidecar duplicate-slot handling.

---

## Things to ask Claude to do explicitly (or it might not)

| When you want... | Ask explicitly |
|---|---|
| Security audit after a crypto change | "audit this change against `docs/WORKING_WITH_CLAUDE.md` checklist" |
| Regression test for a bug fix | "add a regression test in `tests/security_invariants.rs` that pins this fix" |
| Tests run before declaring done | "verify with `cargo test --workspace`" |
| Compile check across all targets | "verify with `cargo check --workspace --all-targets`" |
| Honesty about what wasn't verified | "what couldn't you verify in this change?" |
| Cross-platform thinking | "does this affect only Linux, or macOS/Windows too?" |
| Conservative roll-back semantics | "what's the on-disk state if step N fails?" |

---

## Patterns that produced good Claude output in this codebase

- **Specific file:line refs.** "Look at `ops.rs:2706 deniable_pq_decap`
  — entries.first() is the bug" gets a clean fix. "There's a bug in
  the unlock path somewhere" gets a multi-hour wild-goose chase.

- **Constrain destructive ops up front.** "Don't run any
  `git push --force` or `--no-verify`" sticks for the session;
  catching a destructive op mid-flight is harder.

- **Say "no" early to scope creep.** When Claude offers a
  "while we're here let me also..." follow-up, accepting all of
  them inflates the diff past what's reviewable. Pick one.

- **Ask for the security audit AFTER the implementation, not during.**
  Mixing "implement X" with "and also audit X" in one prompt gives
  worse audits than asking separately. The audit benefits from
  Claude seeing its own code with fresh eyes.

- **Test on the actual target platform.** Claude can't run Windows
  installers or test the GUI visually. Outputs that depend on
  Windows / macOS rendering need a real machine to verify.

---

## Domain context Claude should know (about LUKSbox specifically)

- **Deniable mode has no on-disk magic.** Detection-by-bytes is
  impossible by design; users must declare the cipher + KDF + kind
  at every open. Anything that defaults a form field silently is
  a UX trap.
- **The `.hybrid` sidecar lives next to the vault as `vault.lbx.hybrid`.**
  It has v2 (no per-vault binding, AEAD failure is the defense) and
  v3 (per-vault binding, parse-time rejection) variants. The new
  enroll paths use v2; switching to v3 is a v0.3 follow-up.
- **The `.kyber` seed file is encrypted with its OWN passphrase**
  (separate from the slot passphrase). At unlock, the GUI shows the
  seed-pw field with a "leave blank to reuse the passphrase above"
  hint.
- **FIDO2 on Windows uses webauthn.dll** (not libfido2). Same Rust
  API surface at our layer.
- **TPM is Linux-only today.** All `Tpm*` slot kinds, the GUI's
  TPM rows, and the wizard's TPM menu entries are
  `#[cfg(target_os = "linux")]`.
- **macOS supports two FUSE backends** (FUSE-T and macFUSE) at the
  same code, picked at build time via cargo features. FUSE-T is
  the default.
- **Windows mount needs WinFsp kernel driver.** The `LUKSboxSetup.exe`
  bundle chains its install; the runtime preflight surfaces a
  clear "install WinFsp from winfsp.dev/rel/" error if missing.
- **The version string is the only on-disk-format gate.** v0.2.0
  added on-disk metadata format v3 (default for new vaults); v2 is
  still readable. Pre-v0.2.0 LUKSbox cannot open v3 vaults.

---

## Key files for orientation

| Concern | File |
|---|---|
| Crypto primitives + KEK derivations | `crates/luksbox-core/src/kdf.rs` |
| Slot table + AEAD AAD | `crates/luksbox-core/src/keyslot.rs` |
| Deniable header layout | `crates/luksbox-format/src/deniable_header.rs` |
| Container API (open / create / enroll / persist) | `crates/luksbox-format/src/container.rs` |
| Hybrid PQ sidecar | `crates/luksbox-format/src/hybrid_sidecar.rs` |
| GUI ops + unlock dispatch | `crates/luksbox-gui/src/ops.rs` |
| GUI views + modals | `crates/luksbox-gui/src/app.rs` |
| TUI wizard | `crates/luksbox-cli/src/wizard.rs` |
| FUSE / WinFsp mount | `crates/luksbox-mount/src/{fuse.rs,winfsp.rs,fuse_t.rs}` |
| ML-KEM bindings | `crates/luksbox-pq/src/lib.rs` |
| FIDO2 bindings | `crates/luksbox-fido2/src/` |
| TPM bindings (Linux only) | `crates/luksbox-tpm/src/` |
| Windows MSI | `dist/luksbox.wxs` |
| Windows Burn bundle | `dist/luksbox-bundle.wxs` |
| CI pipeline | `.github/workflows/release.yml` |

---

## How to upgrade THIS file

Edit it after each session where:

- A new bug pattern came up — add to ["Crypto-tool review
  checklist"](#crypto-tool-review-checklist) with the rule + repo
  example + grep target.
- A pre-fill prompt didn't work — note it under "Patterns that
  produced good Claude output" (positive) or add an explicit
  "Don't ask Claude to..." section.
- The codebase shifted (new crate, renamed file) — update the
  "Key files for orientation" table.
- A behavioural preference changed — update the brief-a-fresh-
  session block at the top.

The file is intentionally NOT auto-loaded by Claude Code. Paste
relevant sections into new sessions, or open it side-by-side and
reference it. Keeping it human-readable beats trying to fit it
into the prompt-budget of every session.
