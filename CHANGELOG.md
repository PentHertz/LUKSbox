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

## [v0.1.1] — 2026-05-08

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
  on the DELETE path. For the normal `CreateFile → WriteFile →
  CloseHandle` flow Explorer uses for copies, encrypted chunks
  landed on disk but the directory tree + chunk index never got
  persisted, so on the next mount the file appeared gone.
  Fixed by flushing in the non-DELETE branch as well, gated by
  WinFsp's existing `set_post_cleanup_when_modified_only(true)`
  setting. Belt-and-suspenders `Drop` impl on `LuksboxFs` flushes
  on `FileSystem::stop()` for the process-killed-mid-copy edge
  case. End-to-end regression test
  (`file_written_via_win32_survives_unmount`) added to the WinFsp
  CI integration suite — runs automatically on `windows-latest`
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

  - [`luksbox header-backup`](https://luksbox.penthertz.com/docs/cli/header-backup/) —
    save the 8 KiB header bytes to a separate file. Equivalent
    to `cryptsetup luksHeaderBackup`. No unlock material
    required. Output mode 0600.

  - [`luksbox header-restore`](https://luksbox.penthertz.com/docs/cli/header-restore/) —
    restore the on-disk header from a previously saved backup.
    HMAC-verified against the live MVK by default, blocking the
    attacker-substituted-backup attack. `--no-verify` for the
    case the on-disk header is too damaged to unlock with;
    `--no-verify` is now enumerated as an operator-explicit
    safety bypass in [SECURITY.md §3](SECURITY.md).

  - [`luksbox header-dump`](https://luksbox.penthertz.com/docs/cli/header-dump/) —
    decrypt the metadata blob and emit a JSON tree of every
    inode, chunk reference, generation counter, and keyslot
    summary. Read-only.

  - [`luksbox check`](https://luksbox.penthertz.com/docs/cli/check/) —
    walk every used chunk, AEAD-decrypt it, and report per-chunk
    status with exact `(file_path, chunk_idx, slot_offset,
    generation)`. Exit non-zero on any failure so it composes
    cleanly with `&&` and cron jobs. `--json` for tooling
    consumption.

  - [`luksbox extract --tolerate-errors`](https://luksbox.penthertz.com/docs/cli/extract/) —
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
  Macs still need the one-time Recovery Mode → Reduced Security
  setup before macFUSE's kernel extension loads — the install
  guide walks through it.

- **Windows static-CRT linking** ([`.cargo/config.toml`](.cargo/config.toml)).
  `-C target-feature=+crt-static` on `x86_64-pc-windows-msvc`.
  The shipped `luksbox.exe` no longer imports `VCRUNTIME140.dll`,
  `MSVCP140.dll`, or any `api-ms-win-crt-*.dll`; verified with
  `objdump -p luksbox.exe | grep "DLL Name"`. End users no
  longer need a Visual C++ Redistributable. SmartScreen still
  warns on first launch (LUKSbox is not yet signed with an EV
  Authenticode certificate) — the
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
  the website restating Apache 2.0 §7-§8 (no-warranty /
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
  `peak = m_cost × p_cost × 128 B`. The 5 existing seed-file
  DoS-guard regression tests still pass under the tighter cap
  (the hostile values they use — `u32::MAX` — are still
  rejected). All real-world `.kyber` seeds use parameters far
  below the new cap.

- **`libfido2` credential-ID pointer null-check**
  ([crates/luksbox-fido2/src/hid.rs](crates/luksbox-fido2/src/hid.rs)).
  Defends the `unsafe { from_raw_parts(id_ptr, id_len) }` block
  against a hostile or firmware-buggy authenticator returning
  `(id_len > 0, id_ptr = NULL)`. Belt-and-suspenders behind
  libfido2's documented contract — refuses to construct a slice
  from a null pointer and surfaces a clear error.

- **WebAuthn DLL trust-boundary documentation**
  ([crates/luksbox-fido2/src/webauthn.rs](crates/luksbox-fido2/src/webauthn.rs)).
  The Windows path (`webauthn.dll`) does not need the same
  pointer-validity defence as the libfido2 path because the DLL
  is part of Windows itself — trusting `pbFirst` is the same
  trust we already place in every other Win32 API call. Inline
  comment block makes the asymmetry explicit so future readers
  don't add a defensive check that's actually dead code.

- **Operator-explicit safety bypasses enumerated in
  [SECURITY.md §3](SECURITY.md)**. The three escape hatches —
  `LUKSBOX_NO_LOCK=1` (disables advisory `flock(LOCK_EX)`),
  `LUKSBOX_NO_FOLLOW_SYMLINKS=1` (refuses symlinked vaults), and
  `luksbox header restore --no-verify` (skips HMAC pre-check on
  a backup header) — are now spelled out in the threat model
  with their preconditions and consequences.

### Documentation

- **CRYPTO\_SPEC §3.9 Per-chunk encryption layering**
  ([docs/CRYPTO\_SPEC.md](docs/CRYPTO_SPEC.md)). New canonical
  reference for the three-layer chunk-protection property:
  per-chunk random nonce, binding AAD
  (`file_id ‖ chunk_idx ‖ generation`), and per-file derived key
  (`HKDF(MVK, info = "lbx:file/v1:" ‖ file_id)`). Includes a
  mermaid diagram, a per-layer table linking each layer to its
  source line range, an explicit "what removing each layer would
  break" walkthrough, and a "what this combination does NOT
  protect against" subsection (vault-wide rollback, chunk-count
  observability). §14 (read scenario) and §15 (write scenario)
  now back-reference §3.9 as the canonical writeup.

- **CRYPTO\_SPEC §§3.4 – 3.8: complete on-disk footprint**.
  Detached headers (§3.4), the `<file>.tmp.<16hex>` transient
  temp-file convention every atomic update uses (§3.5), the
  `<vault>.rotating` MVK-rotation temp file (§3.6), the GUI's
  `$XDG_DATA_HOME/luksbox/{recent,preferences}.json` state
  files (§3.7), and the crash-orphan classification policy that
  tells the operator what each leftover file means (§3.8) are
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
  subsequent launches after *More info → Run anyway*.

- **Apple Silicon + macFUSE.** macFUSE's kernel extension
  requires Recovery Mode → Startup Security Utility → Reduced
  Security on Apple Silicon Macs. This is a one-time setup; the
  install guide walks through it. The CLI / GUI / extract
  paths work without macFUSE; only `mount` needs it.

- **Format compatibility guarantee** is still pre-1.0. v0.1.x
  reads every v0.1.x vault, but the format may evolve under
  audit guidance before v1.0 is cut. Migration tools ship with
  any breaking format change.

---

## [v0.1.0] — 2026-05-06

Initial public release. The core feature set — encrypted vaults
with passphrase / FIDO2 / TPM 2.0 / Windows Hello / hybrid
post-quantum keyslots, chunked AEAD-protected file storage, FUSE +
WinFsp mount adapters, MVK rotation, anchor-based rollback
detection — was audit-tracked through 9 internal review rounds
before the cut. See the
[audit log](https://luksbox.penthertz.com/docs/security/audit/) for
the per-round summaries.

[v0.1.1]: https://github.com/penthertz/LUKSbox/releases/tag/v0.1.1
[v0.1.0]: https://github.com/penthertz/LUKSbox/releases/tag/v0.1.0
