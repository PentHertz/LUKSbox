# Deniable header format ("LUKSbox v1-deniable")

**Status**: design specification; under implementation.

LUKSbox's standard header (`docs/CRYPTO_SPEC.md`) stores plaintext
markers - magic bytes, cipher suite ID, KDF ID, slot table - that
make the file trivially identifiable as a LUKSbox vault. The
**deniable header** mode replaces all of that on-disk plaintext with
uniformly random bytes so that the entire file is computationally
indistinguishable from random output to anyone without the right
credential.

This is opt-in at vault-creation time (`luksbox init --deniable`).
Existing standard vaults are unaffected.

## Threat model

The format defends against a **forensic analyst who knows LUKSbox
exists** and wants to either prove a file is a LUKSbox vault or
brute-force a known credential. It does not (and cannot, by itself)
defend against an adversary who runs malicious code on the unlock
host, who has the credential, or who can compel the user to reveal
the credential.

| Goal | Defended? |
|---|---|
| File-type tools (file(1), libmagic, yara) cannot identify the vault | yes |
| Forensic analyst with LUKSbox knowledge cannot prove the file is a vault | yes |
| Adversary cannot enumerate users / count slots | yes |
| Adversary cannot identify which credential types are in use | yes (passphrase, FIDO2); partial (TPM, PQ-hybrid via sidecar) |
| Adversary cannot distinguish wrong-passphrase from wrong-cipher from wrong-KDF-params | yes (single AEAD failure mode) |
| File-size pattern (8 KiB + N x 4 KiB) does not reveal LUKSbox | mitigated by optional `--pad-to <N>` quantization |
| Per-chunk 4 KiB stride does not reveal LUKSbox | not addressed (same as standard mode; out of scope) |
| Steganographic carrier (vault hidden inside PNG/JPEG/PDF) | not addressed (separate feature) |
| Two vaults with same passphrase yield same wrapped MVK in slots | mild leak: forensic analyst who guesses the passphrase sees 2 slots match, learns ">=2 users share that passphrase" |

## On-disk layout

```
Offset (bytes)   Size       Content                          Looks like
--------------   ----       -------                          ----------
0                32         Per-vault salt                   uniform random
32               8 x 512    8 slots (any may be occupied)    uniform random
4128             4064       Encrypted inner header           uniform random
8192             ...        Chunked data area                uniform random
```

**Total header size: 8192 bytes** - identical to the standard format,
so the deniable format does not introduce a new size tell.

The per-vault salt is the only "fixed structure" anywhere in the
file. Since 32 bytes of uniform random is the unavoidable minimum
prefix of any AEAD scheme, this leaks nothing on its own.

## Per-slot structure

Each slot is 512 bytes of indistinguishable ciphertext:

```
Slot layout (512 bytes):
  [12B nonce] [32B encrypted MVK] [16B AEAD tag] [452B random padding]
```

A slot is "occupied" iff AEAD-decrypting it with the candidate KEK
produces a valid tag. An "empty" slot is 512 fresh `OsRng` bytes -
under any secure AEAD's properties, occupied-slot ciphertext and
empty-slot random are computationally indistinguishable.

The 452 bytes of padding inside an occupied slot are random bytes
written at enrollment time and not subsequently verified. They exist
so that all slots have identical on-disk layout regardless of how
much per-slot metadata a future format might want; for v1 nothing
uses them.

## AEAD inputs (the binding details)

For slot index `i`:

```
plaintext  = MVK (exactly 32 bytes)
key        = KEK_i (32 bytes, derived per-credential, see below)
nonce      = random 12 bytes (fresh per slot enrollment)
AAD        = b"luksbox-deniable-v1" || per_vault_salt || (i as u8)
```

The AAD binds the slot to both (a) the format version and (b) the
specific vault, preventing slot-shuffling attacks where an adversary
copies bytes from one vault into another.

## Inner header (offset 4128, length 4064)

The "inner header" is AEAD-encrypted using the MVK and replaces
everything the standard header carries in plaintext:

```
inner_plaintext layout:
  [u16 format_version_minor]
  [u16 cipher_suite]
  [u16 kdf_id]
  [u32 flags]
  [u64 metadata_offset]
  [u64 metadata_size]
  [u64 data_offset]
  [u32 chunk_size]
  [rest: padding to 4032 bytes]

AEAD:
  key = HKDF(MVK, info=b"luksbox-deniable-v1/inner-header", salt=per_vault_salt)
  nonce = 12 random bytes (stored as first 12 bytes of the 4064-byte region)
  AAD = b"luksbox-deniable-v1/inner-header" || per_vault_salt
  tag = 16 bytes (stored as last 16 bytes of the 4064-byte region)
```

This means the cipher / KDF / flags that the standard header keeps
in plaintext are visible only after a valid MVK has decrypted the
inner header. A forensic analyst without the MVK sees uniform random
bytes.

## Per-credential KEK derivation

All KEKs are 32 bytes. All derivations use explicit domain-separation
labels in HKDF `info` strings (security invariant #5). All take the
per-vault salt as input so two different vaults with the same
credential produce different KEKs.

### Passphrase

```
KEK = Argon2id(
    password    = user_passphrase,
    salt        = per_vault_salt,
    m_cost_kib  = user_supplied_or_default,
    t_cost      = user_supplied_or_default,
    p_cost      = user_supplied_or_default,
    output_len  = 32,
)
```

No on-disk per-slot data. User supplies the Argon2 parameters at
unlock time; wrong parameters fail identically to a wrong passphrase.

### FIDO2 (hmac-secret extension)

```
fido2_salt = HKDF(
    salt = per_vault_salt,
    ikm  = credential_id,
    info = b"luksbox-deniable-v1/fido2-salt",
    output_len = 32,
)
hmac_output = device.get_assertion(rp_id, credential_id, hmac_secret_salt = fido2_salt)
KEK = HKDF(
    salt = per_vault_salt,
    ikm  = hmac_output,
    info = b"luksbox-deniable-v1/fido2",
    output_len = 32,
)
```

No on-disk per-slot data. User supplies `credential_id` and `rp_id`
at unlock time (they are remembered or stored in a password manager).
Wrong `rp_id` -> wrong device assertion -> wrong KEK -> failed AEAD,
indistinguishable from wrong passphrase.

### TPM + FIDO2 (sidecar required)

```
tpm_secret      = TPM2_Unseal(sealed_blob)         // sealed_blob from sidecar
fido2_kek       = FIDO2 KEK derivation above
KEK = HKDF(
    salt = per_vault_salt,
    ikm  = tpm_secret || fido2_kek,
    info = b"luksbox-deniable-v1/tpm-fido2",
    output_len = 32,
)
```

The TPM sealed blob is a TPM2_PolicyAuthorize structure with a
distinctive on-wire shape, it cannot be made indistinguishable from
random bytes. It lives in a `<vault>.lbx.tpm` **sidecar** file that
the user is expected to store on a separate device (USB key, paper,
password manager export). The vault file itself stays opaque.

If the adversary finds both the vault AND the sidecar on the same
disk, deniability for this credential type is reduced - they learn
the vault probably uses TPM. The vault file alone reveals nothing.

### PQ-hybrid + FIDO2 (sidecar required)

```
classical_secret = HKDF(per_vault_salt, info=b"luksbox-deniable-v1/pq-classical")
pq_shared        = ML_KEM_decap(ciphertext_from_sidecar, mlkem_secret_key)
fido2_kek        = FIDO2 KEK derivation above
KEK = HKDF(
    salt = per_vault_salt,
    ikm  = classical_secret || pq_shared || fido2_kek,
    info = b"luksbox-deniable-v1/pq-hybrid",
    output_len = 32,
)
```

ML-KEM-768 ciphertexts are 1,568 bytes - too large to fit in the
512-byte slot. The ciphertext lives in a `<vault>.lbx.mlkem` sidecar
on the same terms as the TPM sidecar above.

## Open ceremony

```
1. Read first 32 bytes of vault file -> per_vault_salt.
2. Read next 4096 bytes (8 slots x 512 B) -> slot table.
3. For the supplied credential, derive KEK (per the per-credential
   recipe above) using per_vault_salt and the user-supplied params.
4. For slot_idx in 0..8:
     try AEAD-decrypt slot[slot_idx] with KEK, AAD =
       b"luksbox-deniable-v1" || per_vault_salt || (slot_idx as u8)
     record (success, candidate_mvk) constant-time (no early exit).
5. If any slot succeeded, use that MVK; otherwise return
   ERROR_OPAQUE_UNLOCK_FAILED (the same error returned for every
   wrong-credential / wrong-params / wrong-cipher case).
6. Read 4064-byte encrypted inner header.
7. AEAD-decrypt with MVK and the inner-header HKDF / AAD above.
8. Parse inner header -> cipher_suite, kdf_id, flags, offsets.
9. Hand off to the existing VFS open path.
```

Step 4 MUST iterate all 8 slots even after a match is found. See
security invariant #2.

## Init ceremony

```
1. Generate per_vault_salt (32 fresh OsRng bytes).
2. Generate MVK (32 fresh OsRng bytes).
3. Generate inner_header_nonce (12 fresh OsRng bytes).
4. Choose target slot (default: slot 0).
5. Derive initial credential KEK per the recipe.
6. AEAD-encrypt MVK into slot[0], AAD as above.
7. Fill slots 1..8 with 512 fresh OsRng bytes each.
8. Build inner_header_plaintext with user-chosen cipher_suite, kdf_id,
   flags, metadata_offset = 8192, data_offset = 8192, etc.
9. AEAD-encrypt inner_header_plaintext with MVK-derived key.
10. Write 8192 bytes to disk.
```

The wrap nonce + ciphertext + tag for the occupied slot are placed
at slot bytes [0..60], then 452 bytes of OsRng padding fill the
rest of the slot.

## Slot lifecycle

### Adding a user

```
1. MVK-holder opens the vault (gets MVK).
2. For each slot 0..8: attempt to AEAD-decrypt with every known KEK
   the admin has access to (typically only their own). If decrypt
   fails for ALL admin KEKs, the slot is "candidate empty" from the
   admin's POV.
3. Pick the first such slot.
4. Derive new user's KEK (passphrase + Argon2 params; or FIDO2 +
   credential_id; etc.).
5. AEAD-encrypt MVK into that slot, write.
```

An admin with only their own KEK cannot distinguish "empty slot"
from "another user's slot." This is by design: admins cannot
enumerate co-users without all KEKs.

### Removing a user

```
1. MVK-holder identifies the target slot (typically: trial-decrypt
   with the to-be-removed credential's KEK and find which slot
   matches; this requires knowing the credential).
2. Overwrite the slot with 512 fresh OsRng bytes.
3. Write back.
```

After removal, the slot is byte-distinguishable from its old self
to anyone with old + new snapshots. To prevent this, see "MVK
rotation" below.

### MVK rotation (recommended after removing any user)

```
1. Generate new MVK.
2. For each slot 0..8:
     if MVK-holder has a KEK that decrypted the old slot
       AND wishes to keep that user:
         AEAD-encrypt new_MVK with that KEK into the slot,
         using a FRESH nonce (and freshly-randomized 452B padding).
     else:
         overwrite slot with 512 fresh OsRng bytes.
3. Re-encrypt inner header with the new MVK (fresh inner-header nonce).
4. Re-encrypt all chunked data with subkeys derived from the new MVK.
5. Atomic commit (write to .lbx.new + rename).
```

Step 2's "else" branch is critical: empty slots MUST also be
re-randomized so that an adversary with before/after snapshots
cannot see "these N slots changed; those M did not" and infer
occupancy. See security invariant #4.

## Security invariants (acceptance criteria)

These are normative. The implementation MUST satisfy them; tests
MUST assert each.

### Invariant 1: AAD binding

Every slot AEAD computation MUST include
`AAD = b"luksbox-deniable-v1" || per_vault_salt || (slot_idx as u8)`.

**Why**: prevents slot-shuffling attacks across vaults or across
slots within a vault.

**Test**: tampering with any single byte of AAD (e.g., wrong vault
salt, wrong slot index) MUST cause AEAD verification to fail.

### Invariant 2: Constant-time trial decryption (no early exit)

The open-ceremony slot loop MUST execute exactly 8 AEAD attempts on
every call, regardless of which slot matches (or whether any do).
The "match" must be selected via `subtle::ConditionallySelectable`
or equivalent, not via an early `return`.

**Why**: an attacker observing timing must learn only "an open
attempt happened," never "slot 7 matched" or "no slot matched after
slot 2 failed."

**Test**: open with a credential matching slot 0 and again with one
matching slot 7; both should perform the same number of AEAD
operations (verified by tracing-test instrumentation of the AEAD
call site).

### Invariant 3: Empty slots use the same PRG as occupied slots

Empty-slot bytes MUST come from `getrandom::getrandom` (the same
source as nonces and salts). Empty slots MUST NOT be `[0u8; 512]`,
nor encrypted-all-zeros, nor any deterministic pattern.

**Why**: secure AEAD ciphertext is computationally indistinguishable
from uniform random; we need empty slots to share that distribution
exactly. Any other source distinguishes empties from occupied.

**Test**: chi-square uniformity check on a large sample of "empty
slots" passes at the standard p-value (and matches the chi-square
on a sample of fresh AEAD ciphertext-of-MVK outputs).

### Invariant 4: Rotation re-randomizes ALL slots

`rotate_mvk` MUST overwrite all 8 slots with fresh bytes - occupied
ones via fresh AEAD (new MVK, new nonce, new padding), empties via
fresh `OsRng`. No slot may carry over bytes from the pre-rotation
state.

**Why**: an attacker with before/after snapshots could otherwise
identify the occupied subset by diffing.

**Test**: snapshot the slot table before and after rotation; assert
every slot's bytes changed (probability of identical-by-chance is
2^-4096 per slot; effectively zero).

### Invariant 5: Per-credential domain separation

Every credential's KEK derivation MUST use a distinct HKDF `info`
label. The labels are exactly:

| Credential | HKDF `info` |
|---|---|
| Passphrase | (Argon2id; no HKDF, salt-bound directly) |
| FIDO2 (hmac-secret salt derivation) | `b"luksbox-deniable-v1/fido2-salt"` |
| FIDO2 (KEK) | `b"luksbox-deniable-v1/fido2"` |
| TPM + FIDO2 | `b"luksbox-deniable-v1/tpm-fido2"` |
| PQ-hybrid (classical contribution) | `b"luksbox-deniable-v1/pq-classical"` |
| PQ-hybrid (combined KEK) | `b"luksbox-deniable-v1/pq-hybrid"` |
| Inner header AEAD key | `b"luksbox-deniable-v1/inner-header"` |

**Why**: shared per-vault salt across all credential types means a
hypothetical bug in one credential's KDF could otherwise contaminate
another. Domain separation makes each credential operate on a
cryptographically independent key space.

**Test**: given a single shared bytestring used as both a passphrase
and a FIDO2 hmac-output, derived KEKs MUST be unequal.

## What leaks (honest accounting)

| Leak | Mitigation in this design |
|---|---|
| File extension (`.lbx`) | User can rename freely; format is content-agnostic. |
| File size pattern `8192 + N x 4096 + tag overhead` | `init --pad-to {1M, 10M, 100M, 1G}` quantizes. |
| High file entropy (8.0 bits/byte) | Inherent to AEAD storage; stego carrier is a separate feature. |
| Per-chunk 4 KiB stride in data area | Same as standard mode; not addressed here. |
| TPM / PQ-hybrid sidecar files identify credential type if found alongside vault | Documented; user instructed to store sidecar on separate device. |
| Same passphrase across users -> same KEK -> multiple slots decrypt | Minor: one bit (">=2 users use this passphrase") only if the passphrase is already broken. |
| `luksbox` binary itself is identifiable on the host | Out of scope; the deniable mode protects the vault file, not the user's software inventory. |

## Operational gotchas

- **Permanent lockout on forgotten params**: by design. The CLI / GUI
  MUST print params at init time and require explicit acknowledgement.
  Optional `--params-file <path>` writes a sidecar so the user can
  paste into a password manager; the sidecar is a tell if stored on
  the same device, so default is no sidecar.
- **Brute-force runs Argon2 per guess**: standard mode can fail fast
  on bad magic; deniable mode cannot. This is intentional (no oracle
  for "is this a vault") but means typos are expensive (~1 second
  with default Argon2 cost).
- **8 slots is a hard cap** for v1. For teams >8 we would need to
  bump the format (v2 with 16 slots; same layout, new outer
  identifier baked into the binary).
- **Atomic write**: header writes go through the existing
  `supports_atomic_rotation` path (.lbx.new + rename) when the
  inline-header storage is in use.

## Comparison with related systems

| System | Comparable property | Notes |
|---|---|---|
| VeraCrypt standard volume | "looks random" | Roughly equivalent at file-content level. Deniable LUKSbox additionally hides slot count and credential types. |
| VeraCrypt hidden volume | "decoy + hidden" model | Different model. LUKSbox deniable mode makes the entire file noise, no decoy. |
| age / Tarsnap / OpenSSH key | None | All have plaintext markers; deniable LUKSbox is strictly stronger. |
| LUKS2 | Slot table | LUKS2 stores per-slot KDF + cipher in plaintext. Deniable LUKSbox hides all of it. |

## Where the code lives

| Concern | File(s) |
|---|---|
| Format primitives (slot layout, AEAD calls, AAD encoding) | `crates/luksbox-core/src/deniable.rs` (new) |
| KEK derivation per credential | `crates/luksbox-core/src/deniable.rs` |
| Container init / open / slot management | `crates/luksbox-format/src/container.rs` (new methods alongside existing `open`/`init`) |
| CLI flags (`--deniable`, `--cipher`, `--argon2-*`) | `crates/luksbox-cli/src/main.rs` |
| GUI init wizard + unlock dialog | `crates/luksbox-gui/src/app.rs` |
| Acceptance tests for the five invariants | `crates/luksbox-core/tests/deniable_invariants.rs` (new) |
