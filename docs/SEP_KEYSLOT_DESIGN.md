# macOS Secure Enclave keyslot — design

Status: design, 2026-06-18. Supersedes the SEP notes in
`docs/TPM_FUTURE_IMPROVEMENTS.md` §2 (which assumed this was blocked on
Apple Developer enrollment — see "Signing" below; it is not, for the
shipped design).

This document specifies a Secure Enclave (SEP) keyslot for macOS, the
analog of the Linux TPM 2.0 keyslots (`SlotKind::Tpm2Sealed`,
`HybridPqKemTpm2`, …). It folds in empirical findings from two spikes
run on an Apple M2 with **zero codesigning identities**.

---

## 1. Summary of the design

- New crate `luksbox-sep`, gated `#[cfg(all(feature = "hardware", target_os = "macos"))]`,
  mirroring `luksbox-tpm`'s stub / real / mock split. A tiny Swift +
  CryptoKit shim (compiled in `build.rs`) provides the seal/unseal
  primitive; the rest of LUKSbox stays Swift-agnostic.
- Seal/unseal model: **CryptoKit `SecureEnclave.P256.KeyAgreement`**,
  ECDH + HKDF (derive-mode). The per-slot SEP key is persisted as its
  opaque `dataRepresentation`. **No keychain, no entitlement.**
- The SEP blob is stored in an **in-header SEP region** (V5): the
  header's existing ~3968 B reserved/RNG-pad area (offset 4192 up to
  the HMAC at 8160) becomes a structured per-slot table, gated by
  `FLAG_HAS_SEP_REGION` (bit 4). **No external `.lbx.sep` file**, no
  header-size or data-offset change, and the region is already covered
  by the header HMAC. It does *not* fit in the 512-byte keyslot (see
  §4). The `.lbx.hybrid` sidecar is still used for the ML-KEM material
  of the hybrid SEP kinds (large, public, regenerable — unchanged).
- New honest `SlotKind` variants (`SepSealed`, `HybridPqKemSep`,
  `HybridPqKem1024Sep`, plus the fused-FIDO2 and biometric forms),
  not reused `Tpm2*` kinds.
- The format-layer unlock math is **reused unchanged** — a SEP-backed
  `unseal` closure feeds the existing `UnlockMaterial::Tpm2` /
  `HybridPqTpm2` derivation. Only kind-byte guards and the sidecar
  plumbing are new.

Status: **all 13 SEP kinds are implemented** (core + format + CLI +
wizard + GUI) and verified on real hardware. They work from the CLI,
the wizard (TUI), and the GUI. `SepSealedBiometric` prompts for Touch
ID / passcode and works from any **interactive** session (verified live
on the CLI and the wizard); no paid Apple identity needed (see §7). The
`.app` bundle (`scripts/bundle_macos_gui.sh`) is the nicer GUI UX and
the distribution form, not a requirement for biometric.

---

## 2. Why SEP is not "TPM with a different name"

The TPM exposes a generic *seal arbitrary bytes → unseal* primitive
(`TPM2_Create` / `TPM2_Unseal`). **The Secure Enclave has no such
primitive.** Its only building block (via `SecKey` / CryptoKit) is a
**non-extractable P-256 key whose private half never leaves the SEP**.
From that you get ECDH, ECDSA, and ECIES — no RSA, no SEP-resident
symmetric keys, no "store these 32 bytes."

So "seal a KEK" becomes "**derive** a KEK from an ECDH agreement
against a SEP-resident P-256 key." This is closer to LUKSbox's
existing `Fido2DerivedMvk` (derive) than to the TPM (wrap). We keep
the *interface* identical to TPM (opaque blob in, 32 bytes out) so the
format layer doesn't care.

### Seal (enroll)

```
sepKey      = SecureEnclave.P256.KeyAgreement.PrivateKey()      // private half in SEP
eph         = P256.KeyAgreement.PrivateKey()                    // ephemeral, host-side
shared      = ECDH(eph.priv, sepKey.pub)                        // == ECDH(sepKey.priv, eph.pub)
kek         = HKDF-SHA256(shared, salt=slot.kdf_salt, info="lbx:sep-kek/v1", 32)
```

Stored in the `.lbx.sep` sidecar for this slot:
`sepKey.dataRepresentation` (SEP-bound, opaque) and `eph.publicKey`
(x963, public). `eph.priv` is zeroized and never stored. `kek` wraps
the MVK via the slot's existing `wrapped_ct` / `wrapped_tag` /
`aead_nonce` fields, exactly like a TPM slot.

### Unseal (unlock)

```
sepKey  = SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: stored)  // same enclave only
shared  = ECDH(sepKey.priv, stored eph.pub)
kek     = HKDF-SHA256(shared, salt=slot.kdf_salt, info="lbx:sep-kek/v1", 32)
mvk     = unwrap(kek, slot.wrapped_ct, slot.wrapped_tag)
```

`init(dataRepresentation:)` succeeds **only on the originating
enclave**; any other machine gets an error → that slot is skipped, the
same per-slot tolerance the TPM closure arms already have.

---

## 3. Empirical findings (spikes, Apple M2, 0 signing identities)

Spikes live at `/tmp/sep-spike/` (raw `Security.framework` FFI in Rust;
CryptoKit in Swift). All binaries carried only the automatic
ad-hoc/linker signature (`TeamIdentifier=not set`).

| Question | Result |
|---|---|
| SEP key-gen + ECIES wrap/unwrap of 32 B (no entitlement)? | ✅ works |
| Persist + reload across **separate processes** via `dataRepresentation`? | ✅ seal in proc A → blob → unseal in fresh proc B |
| Plain SEP `dataRepresentation` size | **284 B** |
| Biometric-gated SEP `dataRepresentation` size | **427 B** |
| Derive-mode blob (plain): `2+284 + 2+65` | **353 B** |
| Wrap-mode blob (plain): `+ AES-GCM box` | 415 B |
| Biometric derive-mode blob | **496 B** |
| Biometric unseal from a **bare CLI binary** | ❌ `LAError -4` "System authentication is running" / cancelled — a non-bundled CLI process can't own the LocalAuthentication UI |
| Reboot survival | **staged, not yet confirmed**: `~/.luksbox-sep-reboot-test/RUN_AFTER_REBOOT.sh` |

Takeaways that shaped the design:
1. The dataRepresentation path is **entitlement-free** → buildable and
   testable now; the roadmap's "blocked on Apple enrollment" was wrong
   for this design.
2. **Every realistic SEP blob ≥ 353 B**, and biometric is 496 B — they
   do not fit the 352-byte inline keyslot region (§4). → in-header region.
3. **Biometric needs an *interactive* session** (CLI, TUI, or GUI) —
   not a paid identity or a bundle. Only a detached/background/headless
   process can't present the auth UI. See §7.

---

## 4. Storage: the in-header SEP region (V5), no external file

**Decided: store the SEP material inside the `.lbx` header itself**, in
the bytes that are otherwise random padding — *not* in the 512-byte
keyslot, and *not* in a separate `.lbx.sep` file.

Why not the keyslot: it is a fixed `SLOT_SIZE = 512` B record
(`keyslot.rs:102`) with a 352 B variable region (`FIDO2_CRED_ID_MAX`,
`keyslot.rs:115`). The plain SEP blob is 353 B and biometric is 496 B —
both overflow. Enlarging `SLOT_SIZE` would resize the entire keyslot
array and shift header geometry: a major break.

Why the header works: the 8 KiB header (`HEADER_SIZE = 8192`) packs 8
keyslots ending at offset **4192** (`OFF_KEYSLOTS + 8*512`), with the
HMAC at **8160**. The **~3968 B between them** is currently just
RNG-filled padding — and it is **already inside the HMAC-authenticated
range** (`compute_hmac` over `buf[..OFF_HMAC]`). We repurpose that gap
as a structured SEP region:

- No header-size change, no `metadata_offset` / `data_offset` shift
  (those are stored fields, read on every open → old vaults untouched).
- Tamper protection is free: editing the region or flipping the flag
  fails `verify_hmac`.
- Backward compatible like V1→V2: gated by **`FLAG_HAS_SEP_REGION`**
  (bit 4 of `Header::flags`). Old vaults don't set it → byte-identical,
  no region. A vault that sets it also carries SEP-kind keyslots that
  pre-SEP binaries already can't open, so there's no silent-misread risk.

### In-header SEP region format (`header.rs`)

`Header.sep_blobs: [Option<Vec<u8>>; MAX_KEYSLOTS]` holds one **opaque**
`luksbox_sep::SepBlob` per slot (`header.rs` stays SEP-agnostic). On
disk, starting at `OFF_SEP_REGION` (= 4192):

```
count       1 B    number of populated slots
per slot:
  slot_idx  1 B
  blob_len  u16 LE
  blob      <blob_len> B   (SepBlob: [flags|sep_data_len|sep_data|eph_pub])
trailing bytes stay random
```

Capacity is `SEP_REGION_LEN` ≈ **3968 B** = ≥8 plain or ~7 biometric
SEP slots. `Header::set_sep_blob` rejects an overflowing blob with
`Error::SepRegionFull` (no silent truncation); `parse_sep_region`
rejects a malformed table (bad count, length overrun, out-of-range or
duplicate `slot_idx`) with `Error::InvalidField`, before HMAC
verification. `revoke_slot` drops the slot's SEP blob and clears the
flag when none remain.

The FIDO2 cred_id for SEP+FIDO2 kinds still lives in the **keyslot's
own** 352 B region (it's small) — only the SEP `dataRepresentation` +
ephemeral pubkey go in the header region. The **ML-KEM material** for
hybrid SEP kinds still uses the existing `.lbx.hybrid` sidecar (large,
public, regenerable — unchanged); we only avoid introducing a *new*
SEP-specific file.

A wiped/replaced enclave → the SEP blob can't re-derive the KEK → that
slot is unopenable, and the backup passphrase slot recovers the vault
(same recoverability story as TPM, see §8).

---

## 5. Crate `luksbox-sep`

Layout mirrors `luksbox-tpm`:

```
crates/luksbox-sep/
├── Cargo.toml          # hardware feature; macOS-only real dep
├── build.rs            # compiles + links the Swift shim on macOS+hardware
├── swift/SepShim.swift # CryptoKit seal/unseal, C ABI
└── src/
    ├── lib.rs          # SepBlob type, Error, cfg dispatch, mock
    ├── real.rs         # cfg(all(feature="hardware", target_os="macos"))
    └── (stub inline in lib.rs, like luksbox-tpm)
```

### Public API (matches the TPM shape so callers are symmetric)

```rust
pub const SEALED_SECRET_LEN: usize = 32;

/// Per-slot SEP material destined for the .lbx.sep sidecar.
pub struct SepBlob {
    pub sep_data: Vec<u8>,   // CryptoKit dataRepresentation (284 / 427 B)
    pub eph_pub:  [u8; 65],  // ephemeral P-256 x963 public key
    pub biometric: bool,
}

pub struct SepSealer { /* opaque */ }

impl SepSealer {
    pub fn new() -> Result<Self, Error>;                 // checks SecureEnclave.isAvailable
    /// Returns (kek, blob): kek wraps the MVK; blob goes to the sidecar.
    pub fn seal(&mut self) -> Result<(Zeroizing<[u8;32]>, SepBlob), Error>;
    pub fn seal_biometric(&mut self) -> Result<(Zeroizing<[u8;32]>, SepBlob), Error>;
    /// Re-derive the KEK from a stored blob on THIS enclave.
    pub fn unseal(&mut self, blob: &SepBlob) -> Result<Zeroizing<[u8;32]>, Error>;
}

pub enum Error { NotCompiledIn, EnclaveUnavailable(String), SepError(String), BlobMalformed(&'static str) }
```

Note the asymmetry vs TPM: SEP `seal` *returns* the KEK (it derives it),
whereas TPM is handed a random KEK to seal. The container enroll API
(§6) accommodates this.

- **stub** (non-macOS, or `hardware` off): every method →
  `Error::NotCompiledIn`. tss-esapi's macOS build problem has no analog
  here, but we keep the same shape for a uniform call site.
- **mock** (no feature gate): in-process deterministic ECDH/HKDF over a
  software P-256 key, so format/CLI adversary tests run on Linux CI
  without a SEP. Mirrors `luksbox-tpm/src/mock.rs`.
- **build.rs**: on `all(feature="hardware", target_os="macos")`, run
  `swiftc -emit-library -static` over `swift/SepShim.swift`, emit
  `cargo:rustc-link-lib`, and link `-framework CoreFoundation
  -framework Security -framework LocalAuthentication`. The shim exposes
  a small `extern "C"` surface (seal → fills caller buffers + returns
  derived KEK; unseal → returns KEK) so `real.rs` is plain FFI with no
  Swift types crossing the boundary.

### Cargo feature wiring

Reuses the split planned for Windows TPM in
`TPM_FUTURE_IMPROVEMENTS.md` §1: SEP rides the `hardware` feature.
`luksbox-sep` is added as a **target-gated** dependency of
`luksbox-cli` / `luksbox-gui` so non-macOS builds never see the Swift
shim:

```toml
[target.'cfg(target_os = "macos")'.dependencies]
luksbox-sep = { path = "../luksbox-sep" }
```

---

## 6. Core + format-layer integration

### New `SlotKind` variants (`keyslot.rs`)

Continue the enum past 14. The full implemented matrix covers
{none, FIDO2, passphrase, FIDO2+passphrase} × {no-PQ, ML-KEM-768,
ML-KEM-1024}, plus the plain biometric kind (biometric is NOT crossed
with the fusions — it stays on the base path, mirroring how the TPM
family keeps `Tpm2SealedPin` un-crossed with FIDO2/PQ):

```
SepSealed                          = 15
SepSealedBiometric                 = 16   // biometric phase 2
HybridPqKemSep                     = 17
HybridPqKem1024Sep                 = 18
SepFido2                           = 19
HybridPqKemSepFido2                = 20
HybridPqKem1024SepFido2            = 21
SepPassphrase                      = 22
HybridPqKemSepPassphrase           = 23
HybridPqKem1024SepPassphrase       = 24
SepFido2Passphrase                 = 25
HybridPqKemSepFido2Passphrase      = 26
HybridPqKem1024SepFido2Passphrase  = 27
```

The SEP+FIDO2 kinds store the FIDO2 cred_id + hmac_salt in the inline
slot region (free, since the SEP `dataRepresentation` is offloaded to
the `.lbx.sep` sidecar). The SEP+passphrase kinds run Argon2id over the
slot's `kdf_salt`/`kdf_params`. All kinds derive the KEK through one
unified helper, `derive_sep_kek`: `KEK = HKDF(header_salt, sep_shared
|| [argon2_passphrase] || [hmac_secret] || [pq_shared], "lbx:sep-kek/v1")`,
present factors only, in that fixed order.

Update: `SlotKind::from_u8`, the `is_*` predicate groups
(`is_tpm`-style helpers gain `is_sep`), `Display`. New slots are
`AAD_VERSION_V4` like everything else — **no new AAD version needed**,
because the variable region is empty for SEP slots (the SEP blob lives
in the sidecar, not bytes `128..480`). This is the key reason the
sidecar choice keeps the slot-format untouched.

### Keyslot methods

The wrap/unwrap math is byte-identical to TPM, so these are thin shims
over the existing helpers (or relax the kind assertions on
`unlock_tpm2` / `unlock_hybrid_pq_tpm2` to also accept the Sep kinds):

```rust
pub fn new_sep(suite, mvk, kek, header_salt)               // like new_tpm2
pub fn unlock_sep(&self, suite, kek, header_salt)          // like unlock_tpm2
pub fn new_hybrid_pq_sep(suite, mvk, kek, pq_shared, header_salt)
pub fn unlock_hybrid_pq_sep(&self, suite, kek, pq_shared, header_salt)
```

Because nothing is packed into the slot's variable region, there is no
`sealed_blob` argument here (contrast `new_tpm2`, which stores the blob
inline). The blob is handed to the container separately for the
sidecar.

### Container enroll/unlock (`container.rs`)

```rust
pub fn enroll_sep(&mut self, kek: &[u8;32], blob: &SepBlobBytes) -> Result<usize, Error>;
pub fn enroll_hybrid_pq_sep(&mut self, kek: &[u8;32], pq_shared: &[u8;32], blob: &SepBlobBytes) -> Result<usize, Error>;
```

These install the keyslot **and** return the `slot_idx` so the caller
writes the `.lbx.sep` (and, for hybrid, `.lbx.hybrid`) entry — same
caller-owns-the-sidecar contract `enroll_hybrid_pq_tpm2` already uses.
`luksbox-format` stays SEP-agnostic: it receives opaque blob bytes, it
does not link `luksbox-sep`.

`UnlockMaterial` gains **no new variants**. SEP reuses `Tpm2` /
`HybridPqTpm2` by passing a closure that calls `SepSealer::unseal`
instead of `Tpm2Sealer::unseal`. The dispatcher's `matches!` guards
widen to include the Sep kinds:

```rust
// container.rs ~3927
if !matches!(slot.kind,
    SlotKind::Tpm2Sealed | SlotKind::Tpm2SealedPin
    | SlotKind::SepSealed | SlotKind::SepSealedBiometric) { continue; }
```

The blob the closure receives is read from the `.lbx.sep` sidecar by
the caller (CLI/GUI) before opening, then handed in via the closure's
captured state, exactly as the hybrid caller pre-reads `.lbx.hybrid`.

---

## 7. Biometric gating

`SepSealedBiometric` mirrors `Tpm2SealedPin`: a `SecAccessControl` with
`[.privateKeyUsage, .userPresence]` (or `.biometryCurrentSet`) on the
SEP key. Seal is non-interactive; unseal triggers Touch ID at
`sharedSecretFromKeyAgreement`.

**Resolved (2026-06-18, Apple M2, 0 signing identities) — biometric
works from BOTH the CLI and the GUI:**

- Verified live: `luksbox cat <vault> --sep` on a biometric-only vault
  prompts for Touch ID / passcode in an interactive terminal and
  unlocks. So does the bundled GUI.
- The ONLY thing that fails is a **detached / background / headless**
  process (the original spike was run with `run_in_background`), which
  gets `LAError -4` ("System authentication is running") because there
  is no logged-in session to present the auth sheet. That's a
  *non-interactive* limitation, **not** a CLI-vs-GUI one — an earlier
  draft of this doc wrongly concluded the CLI couldn't do biometric.
- No paid Apple identity or entitlement is needed. On Touch-ID Macs the
  `.userPresence` policy works from an unsigned/ad-hoc binary with no
  Info.plist; `NSFaceIDUsageDescription` is required only for **Face ID**
  devices, which is why the GUI bundle (`scripts/bundle_macos_gui.sh`)
  still sets it.

So:
- Every SEP kind, including `SepSealedBiometric`, works from the CLI
  (`--sep`, interactive). The CLI prints a heads-up and the Secure
  Enclave presents Touch ID / passcode.
- The bundled GUI is the nicer UX (no terminal) and is what a
  distributed build ships, but it is **not required** for biometric.

### Signing — what actually gates what

- **SEP crypto + dataRepresentation persistence + biometric unlock**:
  no signing beyond the automatic ad-hoc signature; works from an
  interactive CLI or GUI. Confirmed on hardware. (Only Face ID needs
  `NSFaceIDUsageDescription` in an Info.plist.)
- **Distribution (Gatekeeper/notarization)**: a Developer ID signature
  + notarization is needed only so users can launch a *downloaded*
  build without the right-click-open dance — orthogonal to SEP
  functionality. The bundler accepts `--sign "Developer ID …"`.
- **`keychain-access-groups` entitlement**: only needed if we ever
  switch to keychain-resident `SecKey` (Approach A). We do **not** —
  the dataRepresentation design avoids it.

### Build / linking (`luksbox-sep/build.rs`)

The CryptoKit shim is compiled to a **static** archive and linked into
the final binary, so `luksbox-cli` / `luksbox-gui` are self-contained
(only the OS Swift runtime in `/usr/lib/swift`, present on every macOS
≥ 10.14.4, is referenced dynamically). `build.rs` emits the `sep_real`
cfg only when `target_os = "macos"`, the `hardware` feature is on, AND
`swiftc` is present; otherwise it warns and compiles the stub. That
keeps `--features hardware` (which also drives the FIDO2/TPM links)
buildable everywhere — including macOS cross-builds from Linux via
osxcross, which have clang but no `swiftc` (SEP ops then return
`NotCompiledIn` at runtime, exactly like a non-macOS target).

---

## 8. Recovery & threat model

- **Same recoverability as TPM-only slots.** A wiped/replaced SEP, an
  OS reinstall, or a deleted `.lbx.sep` makes a SEP slot unopenable.
  The existing create-flow default (keep a backup passphrase as slot 0)
  and the revoke guard apply unchanged. The wizard/GUI warnings written
  for TPM should be reused verbatim for SEP.
- **Stolen vault file alone**: useless — the KEK can only be re-derived
  on the originating enclave. Brute force against the AEAD is infeasible.
- **Stolen vault + `.lbx.sep` sidecar, different machine**: still
  useless — `init(dataRepresentation:)` rejects on a foreign enclave.
- **Stolen vault + sidecar + the original Mac, no biometric**: opens
  (the SEP will derive the KEK). This is the SEP analog of the TPM's
  "no PCR, no PIN" baseline. Mitigations: `SepSealedBiometric`
  (Touch ID), or fuse with FIDO2 / passphrase (`HybridPqKemSepFido2`).
- **Sidecar swap**: blocked by the `header_salt` binding (§4).
- The `.lbx.sep` blob is **not confidential**; do not treat its
  exposure as a vulnerability (no different from leaking a public key).

---

## 9. Testing & CI

- **Unit (any platform)**: `SepBlob` / `.lbx.sep` serialization
  round-trip and truncation rejection (like the `SealedBlob` tests in
  `luksbox-tpm/src/lib.rs`).
- **Mock-backed (Linux CI)**: full enroll → unlock → revoke through
  `container.rs` using the software `mock` SEP, plus adversary tests
  (foreign-enclave reject, sidecar swap reject). No SEP hardware needed
  — the analog of the swtpm suite.
- **Real hardware (macOS CI / manual)**: there is **no SEP emulator**
  (unlike swtpm). Needs an Apple-Silicon/T2 runner. Tests: plain seal
  → fresh-process unseal; the staged **reboot-survival** check
  (`~/.luksbox-sep-reboot-test/`) promoted into a documented manual
  gate until a self-hosted macOS runner exists.
- **Biometric**: manual only (requires a human touch); not automatable.

---

## 10. Open items / explicitly deferred

1. **Reboot survival** — documented by Apple, not yet confirmed here.
   Confirm via the staged script before relying on it.
2. **Biometric** (`SepSealedBiometric`) — phase 2, needs the signed
   `.app` bundle.
3. **`dataRepresentation` size drift** — measured 284/427 B today;
   the `.lbx.sep` `u16` length field tolerates growth. No fixed
   assumption baked in.
4. **Fused SEP+FIDO2 hybrid kinds** (19/20) — straightforward once the
   plain + hybrid-PQ paths land; deferred to keep phase 1 small.
5. **CLI biometric UX** — likely "unlock via GUI" message; finalize
   when phase 2 starts.
6. **SEP is not available in deniable mode (current limitation).** The
   deniable v2 format stores all authenticator material inside a
   fixed-size, random-looking slot envelope (`DeniableCredential` has
   passphrase / TPM / FIDO2 / PQ variants but no SEP variant), and
   deniable vaults fix their slot set at creation time, so there is no
   path to put a SEP `dataRepresentation` blob in a deniable vault.
   `Container::enroll_sep` (and every hardware enroll) refuses on a
   deniable vault via `guard_no_deniable_slot_mutation` with
   `Error::DeniableSlotMutationUnsupported`. The GUI hides the Secure
   Enclave factor in deniable mode; the CLI/wizard surface the
   descriptive error. A future `DeniableCredential::Sep*` family could
   embed the `SepBlob` in the slot envelope the way the TPM sealed blob
   already is (§4), but it needs its own deniability review and an
   envelope-budget check (the SEP blob is larger than a TPM blob).

---

## 11. Effort

Down from the roadmap's ~2 weeks now that the gate is disproven and the
storage decision is made:

- `luksbox-sep` crate (Swift shim + FFI + stub + mock): ~3–4 days
- `.lbx.sep` sidecar + core/format integration: ~2 days
- CLI + GUI surface (phase 1, no biometric): ~2 days
- Tests (mock suite + manual hardware): ~2 days
- Phase 2 biometric + bundle: ~3–4 days, gated on `APPLE_SIGNING.md`
```
