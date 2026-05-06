# TPM 2.0 future-improvements roadmap

Status: as of 2026-05-05.

Linux TPM 2.0 wrapping (`SlotKind::Tpm2Sealed`, `Tpm2SealedPin`,
`Tpm2Fido2`, `HybridPqKemTpm2`, `HybridPqKemTpm2Fido2`,
`HybridPqKem1024Tpm2`, `HybridPqKem1024Tpm2Fido2`) is shipped and
covered by the swtpm-emulator integration suite plus a real-hardware
CI matrix entry.

This file tracks what's NEXT for hardware-bound key isolation. It
exists so a future contributor can pick up any one item with the
design constraints already written down.

---

## 1. Windows TPM 2.0 (highest-priority follow-up)

Windows ships a TPM 2.0 on every machine since the Windows 11 launch
floor (firmware TPMs via Intel PTT / AMD fTPM count). It's reachable
from userspace, no admin or signing required for basic use. The
question is which API surface to wire up.

### Three implementation paths evaluated

| Path | Pros | Cons | Verdict |
|---|---|---|---|
| **A. `tss-esapi 8.0.0-alpha.2` + `TctiNameConf::Tbs`** | Same Rust API as Linux. The `Tpm2Sealer` impl already works against `Tcti::Tbs`; on-disk slot bytes are byte-identical between Linux and Windows. A vault sealed with the same chip on either OS would unseal on either OS. | tss-esapi 8.0 is alpha (3-year-old alpha line, alpha.2 published 2026-02-26 after a 2-year gap). Requires `tpm2-tss` ≥ 4.1.3 — drops Debian 12, Ubuntu 22.04/24.04 LTS, RHEL 9 unless we ship the `bundled` feature (vendored static link, +5 MB binary, needs C toolchain at build time). | **Recommended once tss-esapi 8.0 stable lands**, OR sooner if we accept the alpha risk. |
| **B. `windows` crate + NCrypt + Microsoft Platform Crypto KSP** | Most idiomatic Microsoft API; what BitLocker / Windows Hello use internally. No tpm2-tss dependency at all. | Entirely separate code path from Linux. Different on-disk wire format (NCrypt PCP key blobs ≠ TPM2B blobs), so a vault sealed on Windows with the same TPM model wouldn't unseal on Linux. Breaks the cross-platform-vault-portability principle. | Not recommended — the wire-format split is a worse user-facing outcome than no Windows TPM at all. |
| **C. Direct raw FFI bypass via `tss-esapi-sys`** | Stays on tss-esapi 7.7 stable; no alpha-crate risk. | Hundreds of lines of unsafe C-FFI to construct an Esys context manually around `Tss2_TctiLdr_Initialize_Ex(b"tcti-tbs\0", ...)`. Untestable from any non-Windows dev box. Maintenance burden. | Not recommended — the cost vs. just waiting for tss-esapi 8.0 stable is wrong. |

### Path A specifics (when we go)

Code changes in `crates/luksbox-tpm/src/real.rs` are tiny:

1. One import-line rename: `interface_types::resource_handles` →
   `interface_types::reserved_handles`. `Hierarchy` is otherwise
   unchanged.
2. New `cfg(target_os = "windows")` arm in `Tpm2Sealer::new()` that
   uses `Tcti::Tbs`. ~5 lines.
3. Method signatures (`create_primary`, `create`, `load`, `unseal`,
   `set_sessions`, `tr_set_auth`, `tr_sess_set_attributes`,
   `flush_context`, `start_auth_session`) are byte-identical between
   tss-esapi 7.7 and 8.0-alpha.2. Confirmed by reading the source AND
   confirmed by an attempted migration (rolled back; see "Lessons
   from the failed migration attempt" below).

`Cargo.toml` changes — **DO NOT do the simple version-bump alone**:

The naive change `tss-esapi = "8.0.0-alpha.2"` makes default
`cargo build` BREAK on Debian 12, Ubuntu 22.04/24.04 LTS, RHEL 9,
and any other distro shipping `tpm2-tss < 4.1.3`. The right shape is
to split the existing `hardware` feature so the TPM dependency is
opt-in at version-bump time:

```toml
# crates/luksbox-tpm/Cargo.toml
[features]
default = []
# Existing - stays as the no-tss-esapi stub baseline.
# Removed: nothing actually uses bare `hardware = ["dep:tss-esapi"]`
# anymore; `hardware` becomes the union.
fido2-only = []  # placeholder, no-op for the tpm crate
hardware = ["dep:tss-esapi"]            # opt-in: needs tpm2-tss >= 4.1.3
bundled-tpm = ["hardware", "tss-esapi/bundled"]  # vendored static link

# crates/luksbox-cli/Cargo.toml + crates/luksbox-gui/Cargo.toml
[features]
default = ["fido2-hardware", "fuse", "winfsp"]
# NEW: low-floor default that pulls in libfido2 (no tss-esapi link).
fido2-hardware = ["luksbox-fido2/hardware"]
# Renamed semantics: `hardware` now means BOTH (FIDO2 + TPM via
# system tpm2-tss). Existing `--features hardware` users stay on the
# same code path; new default users skip TPM.
hardware = ["fido2-hardware", "luksbox-tpm/hardware"]
bundled-tpm = ["fido2-hardware", "luksbox-tpm/bundled-tpm"]
```

Migration rollout once those features land:

- `cargo build` (default): FIDO2 hardware, no TPM link. Works on
  every distro.
- `cargo build --features hardware`: FIDO2 + TPM, requires system
  `tpm2-tss >= 4.1.3`. Works on Debian 13, Ubuntu 24.10+, Fedora
  40+, Arch.
- `cargo build --features bundled-tpm`: FIDO2 + TPM with vendored
  tpm2-tss. Works everywhere; needs C toolchain.

CI (release.yml + ci.yml):

- Linux job: switch to `--features hardware` only on runners that
  ship modern tpm2-tss (Debian 13 / Ubuntu 24.10+ when GitHub
  starts offering them), otherwise `--features bundled-tpm`. As of
  2026-05, GitHub's Ubuntu 24.04 ships 4.0.1 → use `bundled-tpm`.
- Windows job: `--features bundled-tpm`. Build needs `clang`
  (LLVM) on the runner; install via `choco install llvm`.
- macOS job: stay on `--features hardware` for the FIDO2 part if
  brew tpm2-tss happens to be ≥4.1.3, otherwise `--features
  bundled-tpm`. macOS doesn't actually USE TPM (no chip), so this
  is purely build-side bookkeeping until Secure Enclave ships.

### Lessons from the failed migration attempt

A migration to 8.0-alpha.2 was attempted in this session and rolled
back. The rollback was driven by ONE structural mistake, not by any
problem with tss-esapi 8.0 itself:

- **The mistake**: bumping `tss-esapi = "8.0.0-alpha.2"` while
  keeping `hardware = ["luksbox-fido2/hardware", "luksbox-tpm/hardware"]`
  as the default feature set. This made the existing CLI/GUI default
  `cargo build` start requiring `tpm2-tss >= 4.1.3` for ANYONE,
  including users who don't care about TPM and just want FIDO2
  unlock. On Ubuntu 22.04/24.04 LTS the build then dies with
  `Failed to find tss2-sys library of version 4.1.3 or greater` —
  including this dev box (Ubuntu 24.04, tpm2-tss 4.0.1) and the
  GitHub Ubuntu 24.04 runners.
- **The fix**: the feature reorganization shown above. `default =
  ["fido2-hardware", ...]` keeps the version floor at 0 for the
  default build. Users who explicitly want TPM via `--features
  hardware` accept the higher floor (or use `bundled-tpm` to
  sidestep it). Existing CI scripts that ran `--features hardware`
  keep working unchanged.
- **Why the rollback now**: the feature reorg is straightforward
  but needs to land as a single atomic change with downstream
  documentation updates AND a thorough sweep of every feature
  combination in CI. That's a focused PR on its own, not a tail
  fragment of a "GUI/wizard surface TPM" session. Better to
  preserve the working baseline today and ship the reorg in a
  dedicated PR when there's deliberate time for it.

Distro-floor bump (4.1.3 minimum tpm2-tss):

| Distro | tpm2-tss | OK with 8.0 directly? |
|---|---|---|
| Debian 13 trixie | 4.1.x | ✓ |
| Ubuntu 24.10+ | 4.1.x | ✓ |
| Fedora 40+ | 4.1.x | ✓ |
| Arch rolling | 4.1.x | ✓ |
| **Debian 12 bookworm** | 4.0.1 | ❌ — needs `bundled-tpm` |
| **Ubuntu 22.04 / 24.04 LTS** | 3.2.0 / 4.0.1 | ❌ — needs `bundled-tpm` |
| **RHEL 9** | 3.0.3 | ❌ — needs `bundled-tpm` |

Estimated effort: **~1 day** focused work + a Windows VM smoke test
(the swtpm CI suite proves the Linux path is unchanged; Windows TBS
needs a manual confirmation since we can't emulate the Windows TBS
TCTI from Linux).

### Why not signing-related

A common confusion: "Windows TPM access needs signed binaries." **It
does not.** The signing question on Windows is about two unrelated
things:

- **Authenticode signing** — what we already do for the MSI installer
  to make SmartScreen trust the download. Doesn't gate any runtime
  capability; just a UX hint to the user.
- **Protected Process Light (PPL)** — process memory isolation that
  prevents other processes (including admin ones) from reading our
  RAM. The Windows analog of Linux's `memfd_secret`. PPL DOES require
  a Microsoft-issued cert that's only available to AV vendors. We're
  NOT using PPL — that's a future-improvements item separate from TPM
  access, tracked in the Tier 3 list of `SECURITY.md`.

Neither is involved in calling `tcti-tbs.dll` to seal/unseal data.
Any user-mode app, no admin, no elevation, no special cert. The
same applies to NCrypt + Platform Crypto KSP — also no signing
required, despite the misconception.

---

## 2. macOS Secure Enclave (parity with Linux/Windows TPM)

The macOS analog is the Secure Enclave (SEP) on Apple Silicon and T2
Intel Macs. Distinct from TPM in:

- API: `SecKey` / `CryptoKit` (Swift-bridged from Rust via `core-foundation`)
- Algorithm: SEP supports AES-GCM and ChaCha20-Poly1305, NOT
  AES-256-GCM-SIV. Same workaround as the TPM: SEP wraps the MVK
  using its supported algorithm; per-chunk AEAD stays in-process at
  AES-NI speed.
- Permissions: requires Apple Developer enrollment for code signing
  (in progress per `docs/APPLE_SIGNING.md`) AND a `keychain-access-groups`
  entitlement in the binary's `.entitlements` file.

A `SlotKind::SepSealed` variant would mirror `Tpm2Sealed` at the
format-layer level. The closure-based `UnlockMaterial::Tpm2`
abstraction we use for Linux can be reused for SEP — same shape:
"give me an opaque blob, return 32 bytes."

Estimated effort: ~2 weeks (different API surface, manual signing
plumbing, no easy emulator analogous to swtpm).

Blocked on: Apple Developer enrollment completing first (so we can
even produce a signed binary that has the keychain entitlement).

---

## 3. PCR sealing for Linux + Windows TPM (boot-chain tamper detection)

Today's Linux TPM seal uses an empty policy: any caller on the same
chip can unseal. PCR sealing additionally requires the chip's PCR
register values (PCR0 = firmware, PCR2 = OS loader, PCR4 = kernel,
PCR7 = secure-boot policy) to match the values measured at enroll
time.

Trade-offs:

- **Pro**: vault refuses to open if the boot chain has been tampered
  (someone swapped your kernel for a backdoored one).
- **Con**: legitimate kernel/initramfs/firmware updates change PCR
  values, so the user must re-enroll the slot after every update —
  bad UX.
- **Mitigation**: systemd-cryptenroll's approach uses
  PCR-policy-signing: a long-lived signing key authorises "any of
  these expected boot measurements," so a kernel update only needs
  the new measurement signed once. We could reuse the same scheme.

Recommended: ship as opt-in flag (`--tpm2-pcr-sealed`), default off,
documented as "only enable if you understand the re-enrollment
implications."

Estimated effort: ~1 week. The TPM2_PolicyPCR + TPM2_PolicyAuthorize
construction is well-trodden ground (systemd-cryptenroll is the
reference).

---

## 4. TPM attestation for "this vault is on the chip you trust"

Beyond wrapping, the TPM can produce a remote-attestation quote
proving "I am chip X, at boot state Y." Useful in two scenarios:

1. **Stolen vault, stolen machine, swapped chip**: an attacker who
   steals both the .lbx AND the laptop, then swaps the TPM chip with
   one they control, currently can re-enroll a TPM slot on their new
   chip. Attestation lets the user verify (via a separate device)
   that the chip is the original.
2. **Multi-machine vault portability with chip identity audit**: a
   user with the same vault on two machines could record both
   chips' EK certs and refuse to unlock if the chip ID doesn't
   match either.

Estimated effort: ~3 weeks (EK cert validation, CA chain handling,
out-of-band verification UX, separate from the wrap path).

Probably not worth it for v1.x — pushes too much complexity onto the
user without a clearly distinct threat-model gain over PCR sealing.

---

## 5. Recovery UX: "the TPM died" — better than today

Today, if a user's TPM chip dies and they only have a `Tpm2Sealed`
slot, the vault is unrecoverable. The wizard + GUI both warn about
this and the create-flow now defaults to keeping a backup
passphrase as slot 0.

Improvements still worth shipping:

- **Periodic "verify your backup keyslot" reminder** in the GUI
  status bar when the only non-TPM slot has been untouched for >6
  months. Encourages users to re-test their recovery path before
  they need it.
- **Pre-revoke check**: if the user clicks "Revoke slot N" and that
  slot is the LAST non-TPM slot, hard-fail with "this would leave
  the vault TPM-only and unrecoverable on chip failure" — let them
  override only after explicitly typing the vault path.
- **Chip-replacement migration wizard**: one-shot CLI/GUI flow
  "I'm migrating to a new machine, unwrap with the backup
  passphrase, immediately re-seal under the new chip, optionally
  revoke the old slot."

Estimated effort: ~1 week for all three.

---

## 6. CLI parity gap: `--kind hybrid-pq-tpm2-1024` flags

Background: the `Container::enroll_hybrid_pq_1024_tpm2` and
`enroll_hybrid_pq_1024_tpm2_fido2` methods exist (kinds 13 and 14
in `SlotKind`). The GUI exposes both 768 and 1024 buttons via the
post-create "Add hybrid TPM" modals. The wizard exposes both 768
and 1024 menu options.

But the CLI's `SlotKindArg` only has `HybridPqTpm2` (which maps to
768). There's no `--kind hybrid-pq-tpm2-1024` flag.

A user wanting to enroll the 1024 variant from a script (rather
than the wizard / GUI) currently can't, even though every other
layer supports it. Easy fix: add two new `SlotKindArg` variants +
two new `cmd_enroll_*` functions that delegate to the existing
`enroll_hybrid_pq_1024_*` Container methods.

Estimated effort: ~2 hours.

---

## 7. Per-platform notes

### Linux
- Hardware backend: `/dev/tpmrm0` via libtss2-esys, wrapped by `tss-esapi 7.7`.
- swtpm CI: `crates/luksbox-tpm/tests/swtpm_integration.rs` covers
  the seal/unseal loop end-to-end. Tests skip cleanly without
  `swtpm` on PATH.
- Hardware CI: `tpm-hardware` matrix entry in `.github/workflows/ci.yml`
  installs `libtss2-dev swtpm swtpm-tools libtss2-tcti-swtpm0`.

### Windows
- Status: not implemented. See section 1 above.
- Workaround for users: every other LUKSbox keyslot kind works on
  Windows today (passphrase, FIDO2 wrap/direct, hybrid-PQ ×4).
  Windows Hello via webauthn.dll routes through the platform's
  TPM-backed authenticator, so a `Fido2HmacSecret` slot enrolled
  with `--fido2-device windows://hello` is implicitly TPM-anchored
  even without the explicit `--tpm2` slot kind.

### macOS
- Status: not implemented. See section 2 above.
- Workaround: same as Windows — passphrase / FIDO2 / hybrid-PQ all
  work; FIDO2 with a hardware authenticator is the closest analog
  to Linux's TPM slot until Secure Enclave wrapping ships.

---

## Priority ordering

Based on user impact and implementation cost:

1. **Section 6** (CLI 1024 flags) — 2 hours, useful for scripted
   enrollment. Ship anytime.
2. **Section 1 path A** (Windows TPM via tss-esapi 8.0) — 1 day,
   wait for 8.0 stable OR ship now with alpha-pin if there's user
   demand.
3. **Section 5** (recovery UX) — 1 week, improves the safety story
   for everyone.
4. **Section 3** (PCR sealing, opt-in) — 1 week, advanced users
   only.
5. **Section 2** (macOS Secure Enclave) — 2 weeks, blocked on
   Apple Developer enrollment.
6. **Section 4** (attestation) — 3 weeks, niche threat-model gain.
