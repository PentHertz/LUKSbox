# Security audit, Round 14

Author: Penthertz internal review team
Date: 2026-06-18
Status: **1 LOW found and fixed in the same revision. No HIGH/MEDIUM.
No cryptographic break in the stolen-vault / no-unlock-factor model.**

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
| HIGH | 0 |
| MEDIUM | 0 |
| LOW | 1 |
| INFO | 0 |

No memory unsafety. No parser DoS or unwrap-on-attacker-input in the
SEP region reader. No wrong-but-accepted KEK/MVK path. No
cross-slot or cross-vault blob-substitution break.

## Findings

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

## New regression coverage

| Finding | Test |
|---|---|
| R14-01 | `crates/luksbox-core/src/keyslot.rs::tests::aad_covers_hmac_salt_for_every_salt_bearing_kind` -- builds a slot with a known 32-byte salt for every salt-bearing kind (the 7 FIDO2/TPM+FIDO2 kinds plus the 6 SEP+FIDO2 kinds) and asserts the salt appears in BOTH the `to_bytes` output AND the `build_aead_aad` output. Fails on any future `salt_len` drift. |

Verified: `cargo test -p luksbox-core --lib` -> 111 passed, 0 failed.

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

## Fix status

| ID | Severity | Status | Location |
|---|---|---|---|
| R14-01 | LOW | **Fixed** | `crates/luksbox-core/src/keyslot.rs`: new `SlotKind::has_inline_hmac_salt()` is the single source of truth; `build_aead_aad`, `to_bytes`, and the `from_bytes` parser all delegate to it (the hand-maintained `matches!` lists removed). Pinned by `tests::aad_covers_hmac_salt_for_every_salt_bearing_kind`. |

## Next steps

- R14-01 fixed and tested this revision; SEP+FIDO2 kinds are now at
  AAD-coverage parity with the TPM+FIDO2 kinds, and the parity is
  pinned so it cannot silently regress on a future keyslot-kind add.
  Safe to carry into the `v0.4.0-rc.1` pre-release and the v0.4.0
  final tag.
- Reconfirm the deferred SEP items tracked in
  `docs/SEP_KEYSLOT_DESIGN.md` section 10 (reboot survival, biometric
  phase 2) before promoting any SEP kind out of pre-release.
