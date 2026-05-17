# Security policy

This document describes how to **report a vulnerability** in LUKSbox, what the
project's **threat model** is, what is and isn't covered by automated testing,
and which **known limitations** users should weigh before relying on LUKSbox to
protect material information.

The companion documents are:

- [`docs/SECURITY_ARCHITECTURE.md`](docs/SECURITY_ARCHITECTURE.md): security
  mechanisms, diagrams, attack scenarios, and residual risks.
- [the architecture page on the website](https://luksbox.penthertz.com/docs/security/architecture/): adversary
  inputs, fixed issues, open gaps, and regression-test mapping.
- [the audit history on the website](https://luksbox.penthertz.com/docs/security/audit/): per-round audit log
  and historical evidence.

---

## 1. Reporting a vulnerability

**Please do not open a public GitHub issue for security-relevant findings.**

Send a report to **`security@penthertz.com`**, or directly to the maintainer at
**`sebastien.dudek@penthertz.com`**.

If your finding contains exploit details, sample vault files, or anything else
you'd rather not send in cleartext, request our PGP key first by asking on the
same address; we'll reply with a current key fingerprint that you can verify
against the same key published at <https://penthertz.com>.

A useful report includes:

- Affected version (`luksbox --version`, or commit SHA if building from source).
- Whether the bug is reachable pre-authentication (no passphrase / no FIDO2)
  or post-authentication.
- Reproduction steps, ideally a minimal vault file or fuzz seed.
- Your assessment of impact (DoS / info-disclosure / key compromise / etc.).
- Whether you'd like to be credited and under what name.

### Response SLA (target)

| Stage | Target |
|---|---|
| Acknowledgement of receipt | within 3 working days |
| Initial triage (severity + scope) | within 7 working days |
| Fix landed in `main` (for CVE-class) | within 30 calendar days |
| Coordinated public disclosure | typically 90 days from report, earlier on agreement |

These are targets, not guarantees, LUKSbox is maintained by a small team. If
you haven't heard back in 7 days, please re-send; mail can be eaten by spam
filters.

### Coordinated disclosure

We follow a standard 90-day embargo from the date of report. If the bug is
already being exploited in the wild, or if a researcher has a stronger
deadline (e.g. an academic submission), we'll work to shorter timelines on
request.

CVE assignment: we'll request a CVE through MITRE for any vulnerability that
affects released versions and is reachable in a default configuration.
Researchers will be credited in the advisory unless they ask not to be.

---

## 2. Supported versions

| Version line | Status | Receives security fixes |
|---|---|---|
| `main` (development) | active | yes |
| Latest tagged release | active | yes |
| Previous tagged release | maintenance | yes, until 6 months after the next release |
| Older tagged releases | end-of-life | no, please upgrade |

The trust chain for an artifact downloaded from
[GitHub Releases](https://github.com/penthertz/LUKSbox/releases)
combines platform-native signing (where shipped) with Sigstore-
backed provenance (every artifact, every platform). LUKSbox does
not yet ship a GPG-signed `SHA256SUMS.txt.asc`; that is on the
v0.2 roadmap alongside Linux package signing. The current chain is:

1. The release workflow file (`.github/workflows/release.yml`) is in
   the source tree and reviewable.
2. Tagged commits are GPG-signed by the maintainer (verifiable on
   GitHub's commit view).
3. The release workflow runs only on `v*` tags and uploads via
   GitHub's OIDC-authenticated release token; no human can manually
   replace the artifacts after the workflow finishes.
4. Every release artifact is signed via [GitHub Artifact
   Attestations](https://docs.github.com/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds)
   (Sigstore-backed). End users verify with one command:
   `gh attestation verify <file> --owner penthertz`. The signature
   is keyed to a short-lived GitHub-issued certificate that
   identifies this exact workflow run and commit SHA, and is
   registered on the public Sigstore transparency log so the
   signing event itself is auditable.
5. Every artifact is also hashed in `SHA256SUMS.txt` (uploaded by
   the same workflow run) for offline verification.

For maximum assurance, build from source against a tagged commit
whose signature you have verified, or compare the `SHA256SUMS.txt`
on the release page to a hash you compute yourself from the source.
GPG-signed release tarballs and full SLSA L3 provenance are on the
roadmap; the Sigstore attestation already covers the
provenance-pinning property that `SHA256SUMS.txt.asc` would add.

---

## 3. Threat model

### What LUKSbox aims to defend against

- **Lost or stolen storage media.** A `.lbx` file falling into an attacker's
  hands without the passphrase / FIDO2 device must not yield plaintext.
  Authenticated AEAD on every chunk; HMAC over the entire 8 KB header keyed
  from the unlocked MVK.

- **Tampered storage.** Bit-flipping any byte in a `.lbx`, `.hdr`, `.hybrid`,
  `.kyber`, or `.anchor` file must cause a clean `Err` on next open, not
  silent data corruption. Tested by `every_authenticated_byte_of_header_breaks_auth_when_flipped`
  (luksbox-format `security_invariants`) which flips 480 sampled offsets and
  asserts each fails verification.

- **Cross-file / position substitution.** A disk-level attacker who *also*
  has the MVK cannot move chunk slot bytes between files or positions,
  per-file HKDF key + per-chunk AAD with `file_id || chunk_idx || generation`
  defeats both. Tested in `chunk_substitution_between_files_fails_aead`,
  `chunk_position_swap_within_file_fails_aead`,
  `chunk_generation_rollback_fails_aead`.

- **Rollback.** Restoring an older snapshot of a vault (e.g. from backup,
  from cloud sync history) is detected if the user is using `.anchor`
  sidecars on separate trusted storage. Without an anchor, rollback is **not**
  detected, that's the user's choice and is documented in TUTORIAL.md.

- **Argon2id / Kyber-seed parser DoS.** Hostile on-disk KDF parameters
  (`m_cost = u32::MAX`, etc.) are rejected at the parser layer before any
  `argon2` call, capped via `is_sane_for_disk()`. See round 1 in the audit
  report.

- **Rogue / MITM FIDO2 authenticator.** A look-alike YubiKey or compromised
  USB-HID transport (O.MG cable, malicious hub) cannot unlock a wrap-mode or
  direct-mode slot without the legitimate authenticator's sealed `credSeed`.
  17 dedicated tests in `crates/luksbox-fido2/tests/rogue_authenticator.rs`.
  Hybrid-PQ-FIDO2 mode is *strictly more robust* against this attacker
  because the PQ second factor lives entirely off the FIDO2 channel.

- **Concurrent writers.** Advisory `flock(LOCK_EX | LOCK_NB)` on both `.lbx`
  and detached `.hdr` prevents two processes from corrupting metadata. Escape
  hatch via `LUKSBOX_NO_LOCK=1` is documented as dangerous.

- **Symlink swap / atomic rename-over between opens.** `Container::open`
  captures `(device, inode)` on POSIX or `(volume_serial, file_index)` on
  Windows at first-open, and re-checks on every subsequent open. Optional
  strict mode via `LUKSBOX_NO_FOLLOW_SYMLINKS=1`. Both platforms covered
  by tests in `crates/luksbox-format/tests/security_invariants.rs`
  (POSIX: symlink-swap; Windows: rename-over substitution).

- **Hibernate / swap of the master key.** The MVK is allocated via
  `memfd_secret(2)` on Linux when the kernel supports it; otherwise via
  `mlock`'d `Box<Zeroizing<...>>`. `disable_core_dumps()` runs
  process-wide before any keying material is touched.

- **Quantum harvest-now-decrypt-later.** Only when the user opts into a
  hybrid-PQ keyslot. Classical secret + ML-KEM-768 (or ML-KEM-1024) shared
  secret are both required to derive the KEK; recovering only the classical
  half (e.g. via future quantum cryptanalysis of FIDO2's ECDH-P256) is not
  enough. See `crates/luksbox-pq/tests/end_to_end_hybrid.rs`.

### What LUKSbox does NOT defend against

These are out of scope; any of them can defeat the encryption regardless of
how strong the cryptography is.

- **Compromise of the host running luksbox.** Once an attacker has root or
  ptrace access on the machine where you'd open the vault, they can read the
  MVK out of process memory, log your passphrase, or capture the
  decrypted FUSE traffic. LUKSbox is a file-encryption tool, not a TPM.

- **Hardware key extraction from the FIDO2 authenticator.** If the attacker
  can physically recover `credSeed` from the authenticator's secure element
  (decapsulation, fault injection on a vulnerable model), wrap-mode and
  direct-mode FIDO2 slots can be unlocked. Choose authenticators with proven
  certification (FIPS 140-2/3, CC EAL5+).

- **Side-channel attacks.** We use `subtle::ConstantTimeEq` for tag
  comparisons and have no early-exit unlock loop, but we have not measured
  this on real hardware. A patient cache-timing or power-analysis attacker
  with local access is out of scope.

- **Coercion of the user.** "$5 wrench attack" is not a software problem.
  LUKSbox does not currently implement plausible-deniability hidden volumes.

- **Quantum attacks against non-hybrid-PQ vaults.** Vaults created without
  the `--kind hybrid-pq*` modes do not have post-quantum protection. A
  cryptographically relevant quantum computer (CRQC) recovering the MVK from
  a sniffed CTAP2 transport, or from AES-256-GCM / AES-256-GCM-SIV
  ciphertext under Grover, defeats them. The audit report's round 3 (`auth_then_process` fuzz) makes
  the post-AEAD pipeline graceful under MVK recovery, but the secret is
  recovered.

- **Forensic recovery from hibernate / swap on hosts without
  `memfd_secret`.** On older kernels and on macOS, the MVK can be paged
  out. Disable hibernate / use encrypted swap if this matters.

- **Backup security.** A `.lbx` file is its own backup, but the `.kyber`
  seed file and `.anchor` sidecar are *separate* artifacts. Lose them and
  you may be locked out (kyber) or lose rollback detection (anchor). Back
  them up *separately* and on different trusted storage.

- **Operator-explicit safety bypasses.** A small number of escape-hatch
  flags exist for recovery / debugging scenarios. Each is opt-in (never
  default), each is logged at the operator's terminal, and each is
  documented in the CLI help. They are NOT silent vulnerabilities, but
  an operator who runs them blindly can compromise the vault. The set
  today:
    - `LUKSBOX_NO_LOCK=1` - disables advisory `flock(LOCK_EX)`. Allows
      concurrent writers and the metadata corruption that follows.
    - `LUKSBOX_NO_FOLLOW_SYMLINKS=1` - refuses to open vaults whose
      path is a symlink (paranoid mode; failure-closed, not unsafe).
    - `luksbox header restore --no-verify` - skips the HMAC pre-check
      that prevents an attacker-substituted backup header from being
      installed under their MVK. Required ONLY when the on-disk header
      is too damaged to unlock with; using it on a backup file from
      an untrusted source silently installs the attacker's keyslot
      table.

---

## 4. Cryptographic primitives

| Purpose | Primitive | Source |
|---|---|---|
| File / metadata AEAD | AES-256-GCM-SIV (default for new vaults, RFC 8452, nonce-misuse-resistant), AES-256-GCM (legacy default before audit Finding 1), or ChaCha20-Poly1305 | RustCrypto `aes-gcm-siv`, `aes-gcm`, `chacha20poly1305` |
| Header MAC | HMAC-SHA256 | RustCrypto `hmac` + `sha2` |
| Subkey derivation | HKDF-SHA256 with per-purpose `info` strings | RustCrypto `hkdf` |
| Passphrase stretching | Argon2id (interactive / sensitive presets) | RustCrypto `argon2` |
| FIDO2 hmac-secret transport | ECDH-P256 + AES-256-CBC + HMAC-SHA256 (CTAP2 Sec.6.5) | hand-rolled in `luksbox-fido2/src/protocol.rs`; libfido2 via FFI for the device side |
| Post-quantum KEM (hybrid mode) | ML-KEM-768 or ML-KEM-1024 (FIPS 203) | RustCrypto `ml-kem` |
| Random | OS RNG via `rand_core::OsRng` | system getrandom / arc4random / BCryptGenRandom |

ChaCha20-Poly1305 is constant-time on every platform; AES-256-GCM and
AES-256-GCM-SIV are constant-time on CPUs with hardware AES (AES-NI on
x86_64, ARMv8 crypto extension on aarch64). On older / minimal CPUs a
one-time stderr warning recommends `--cipher chacha`. See round 6
section I in the audit report.

**Why AES-256-GCM-SIV is the default for new vaults**: random 96-bit
nonces under vanilla AES-GCM have a NIST-recommended bound of 2^32
messages per key (audit Finding 1). The SIV variant (RFC 8452) is
nonce-misuse-resistant: a nonce collision under the same key reveals
only that two messages had identical (key, nonce, AAD, plaintext)
tuples, never the GHASH key or the XOR of plaintexts. Same 12-byte
nonce + 16-byte tag wire shape, so on-disk chunk format is byte-
identical regardless of which AES variant a vault was created with.
Existing vaults stamped with cipher_suite=0x0001 (AES-256-GCM) at
create time continue to decrypt under that suite; only newly created
vaults default to SIV (cipher_suite=0x0003).

---

## 5. What we test

| Tier | Frequency | Coverage |
|---|---|---|
| Unit tests | every commit | per-module crypto round-trips, parser correctness, `[u8]` round-trips |
| Functional tests | every commit | end-to-end CLI workflows via subprocess |
| Security-regression tests | every commit | 65+ tests pinning each known-fix invariant, Argon2 DoS guard, rogue authenticator, slot AAD coverage, generation rollback, lock contention, symlink swap, AES-NI warning, bincode OOM, and more |
| Fuzz smoke (libFuzzer) | every PR | 5 min per target x 9 targets, cheap parser bugs |
| FIPS-203 conformance | every commit | 17 tests against published test vectors |
| Hardware FIDO2 smoke | manual, before each release | wrap, direct, hybrid-pq-fido2, 4 flows x 6 touches against real authenticator |
| Long-running fuzz | not yet automated | recommended pre-release: 24h x 9 targets |

Total automated test count at last run: **183 passing, 0 failing, 0 ignored**.
30M+ fuzz iterations across all targets to date.

### What we do NOT test

- Cryptanalysis of the underlying primitives. We rely on the upstream
  RustCrypto audits and the FIPS-203 test vectors for ML-KEM.
- Side-channel resistance on real hardware (no `dudect` runs, no
  power-analysis testbed).
- Multiple FIDO2 brands. Yubico YubiKey 5 is the only model exercised on
  real hardware. SoloKey, Nitrokey, Token2, OnlyKey, and Google Titan all
  use libfido2 over USB-HID and *should* work, but are unverified.
- Multi-device FIDO2 flows.
- Wrong-PIN paths (would burn the device's PIN retry counter).
- Windows port end-to-end (winfsp_wrs path is built but not in our CI
  matrix yet).

---

## 6. Known limitations and dependency advisories

We try to be transparent about gaps that haven't been closed. None of these
are exploitable today, but each is a forward-looking risk you should weigh.

### Unmaintained dependencies (`cargo audit` warnings)

`cargo audit` against the workspace currently surfaces **one**
advisory, accepted and documented in `audit.toml` at the workspace
root. CI runs `cargo audit` on every push and PR
(`.github/workflows/ci.yml::audit`) and fails on any non-ignored
advisory.

| Crate | Used by | Advisory | Status |
|---|---|---|---|
| `registry 1.3` | `winfsp_wrs_sys` (transitive) -> `luksbox-mount` on Windows | RUSTSEC-2025-0026 (unmaintained) | **Windows runtime only.** Required for the `mount` subcommand on Windows via WinFsp. Non-Windows builds (Linux + macOS) do not link this chain. The `registry` crate is archived; the recommended replacement is `windows-registry`. `winfsp_wrs 0.4.1` (Jan 2026) is the latest published version and has not migrated yet (https://github.com/Scille/winfsp_wrs). When it does we drop this ignore. |

#### Recently retired

- **`ansi_term 0.12` (RUSTSEC-2021-0139)**, **`atty 0.2`
  (RUSTSEC-2024-0375)**, and **`atty 0.2`
  (RUSTSEC-2021-0145, unsound)** were transitively pulled in by
  `dudect-bencher 0.7 -> clap 2.34`, a dev-dependency of
  `luksbox-core` used for constant-time bench harnesses.
  Replaced in v0.1.0 by the in-repo `luksbox-ct-bench` crate
  (`crates/luksbox-ct-bench`), which has the same `Class` /
  `CtRunner` / `BenchRng` / `ctbench_main!` API surface and only
  depends on `rand 0.9`.
- **`bincode`** was removed entirely in round 7E; the metadata
  format is now postcard-only with the `LBM\x02` magic prefix.

If a CVE is filed against `registry`, we cut a release that pins
`winfsp_wrs` to a fixed upstream version (or vendors a fork) within
the SECURITY.md response SLA above.

### Third-party audit not yet performed

The `unsafe` code in this workspace is concentrated in three files
(1,200 LOC total): `luksbox-fido2/src/{ffi,hid}.rs` and
`luksbox-mount/src/fuse.rs`. These have been internally reviewed and are
covered by SAFETY block comments documenting the libfido2 / POSIX contracts
being relied on, but **no independent third-party audit has been performed**.
This is the largest single gap before LUKSbox should be relied on for
production-sensitive deployments (journalism source protection, healthcare
records, GDPR-bound personal data).

If you represent an organization that could fund such an audit, please
get in touch.

### Operational gaps

- **No reproducible builds.** Bit-for-bit reproducibility is not yet in
  place; build artifacts are not deterministic across machines.
- **Per-platform signing posture (v0.1.1):**
  - **macOS:** `.dmg` and the bundled `.app` are codesigned with the
    Penthertz Apple Developer ID Application certificate (team
    `456J2U7HQL`) under the hardened-runtime profile, and the bundle
    is Apple-notarised with the ticket stapled. Verifiable locally
    with `codesign --verify --deep --strict` and
    `spctl --assess --type execute`.
  - **Windows:** the `.exe` and `.msi` are **not yet** signed with an
    EV Authenticode certificate; SmartScreen warns on first launch.
    EV signing is on the v0.2 roadmap. The static-CRT linking added
    in v0.1.1 means no Visual C++ Redistributable is needed, but
    does not address the SmartScreen prompt.
  - **Linux:** `.deb` / `.rpm` packages are not yet GPG-signed by a
    Penthertz release key. Apt / dnf trust currently relies on
    `SHA256SUMS.txt` + the GitHub Artifact Attestation. A
    distro-style release key is on the v0.2 roadmap.
- **GitHub Artifact Attestations cover every artifact on every
  platform.** Sigstore-backed; verify with
  `gh attestation verify <file> --owner penthertz`. The attestation
  proves the artifact came from the exact tagged workflow run on a
  GPG-signed commit.
- **macOS thread enumeration for the daemonize fork-guard is not
  implemented.** The Linux path uses `/proc/self/task`; macOS would need
  `task_threads()` from Mach. Tracked.
- **Windows path-substitution test coverage is partial.** The
  `inode_of` mechanism using `(volume_serial, file_index)` from
  `GetFileInformationByHandle` IS implemented and tested
  (`rename_over_substitution_is_detected_or_caught_by_unlock` +
  `inode_round_trip_is_stable_across_opens_on_windows`). The
  `LUKSBOX_NO_FOLLOW_SYMLINKS` test is not exercised on Windows
  because non-elevated symlink creation requires Developer Mode
  enabled. The runtime check itself (`std::fs::symlink_metadata().
  file_type().is_symlink()`) is identical on both platforms; the
  gap is purely test setup, not production code.
- **Windows VaultLocked error remapping.** When a second open
  encounters a region-lock held by the first open, Windows returns
  the raw `io::Error` ("The process cannot access the file...
  os error 33") instead of being mapped to the `Error::VaultLocked
  { path }` variant. Lock enforcement IS working - the second open
  fails - but the error message is less actionable than on POSIX.
  No security impact; UX bug.
- **macOS FUSE-T backend has weaker local-attacker resistance than
  macFUSE.** On macOS, LUKSbox's `mount` subcommand can use either
  FUSE-T (default-preferred, kext-free) or macFUSE (legacy
  fallback). The two backends are NOT security-equivalent:
  - FUSE-T's NFS server binds to `127.0.0.1` (loopback only) but
    has **no authentication** on the bound port - any local
    process running on the same Mac can connect via NFSv4 and
    impersonate the kernel-side mount via plain AUTH_SYS UIDs.
    The FUSE-T project's own wiki acknowledges this. macFUSE
    gates the equivalent channel via kernel permissions on the
    `/dev/macfuse*` device node, which restricts access to the
    mounting UID.
  - The actual NFS server inside FUSE-T (`go-nfsv4`) ships
    closed-source as a Mach-O binary; we cannot audit the RPC
    parsing or auth-decision paths in the data flow.
  - For a single-user laptop (the modal LUKSbox user) the
    distinction is moot; for a shared workstation, lab machine,
    or any environment where untrusted local processes might
    coexist with the mount, prefer macFUSE explicitly via
    `cargo build --no-default-features --features
    hardware,fuse,winfsp`.
  - Full threat-model analysis with source citations:
    [`docs/MACOS_FUSE_T.md`](docs/MACOS_FUSE_T.md#threat-model-differences-vs-macfuse-read-this-before-picking).
    On macOS 26+ the FSKit backend (Unix domain socket, no TCP
    loopback) closes this hole.
- **macOS+FUSE-T GUI mounts use subprocess isolation with MVK
  passed over an inherited stdin pipe.** When the GUI mounts a
  vault on a FUSE-T build, it spawns the bundled `luksbox` CLI
  binary as a child process (subcommand `mount-fuse-t-helper`)
  and pipes the 32-byte Master Volume Key over the child's
  stdin. This is necessary because libfuse-t.dylib's teardown
  path issues an uncatchable abort that would kill the GUI
  otherwise; isolating it to a child contains the abort. The
  trade-off is a brief MVK exposure during pipe transit:
  - The pipe is a kernel-anonymous inherited file descriptor;
    no process other than the spawned child can read it.
  - macOS pipe pages are not swappable to disk.
  - Both processes hold the MVK in `[u8; 32]` stack buffers
    only long enough to construct the `MasterVolumeKey`
    (microseconds) and `Zeroize` the buffers immediately
    after.
  - The child's `Container::open_with_mvk` verifies the header
    HMAC against the supplied MVK, so a wrong MVK fails fast
    with `HeaderAuthFailed` instead of producing garbled
    metadata reads.
  - Full architectural detail in
    [`docs/MACOS_FUSE_T.md` § Subprocess isolation](docs/MACOS_FUSE_T.md#subprocess-isolation-gui-mount-on-macosfuse-t).
  This pathway exists ONLY for GUI mounts on macOS+FUSE-T
  builds. CLI mounts (`luksbox mount ...`) and all other
  backends keep the legacy in-process flow with no MVK
  IPC.

### Cryptographic gaps

- **No plausible-deniability hidden volumes.** A user under coercion has no
  way to reveal a "duress" passphrase that opens a different (decoy) vault.
- **No native hardware key (TPM / secure-element) integration on the host
  machine.** FIDO2 authenticators are supported as a *user*-side token; no
  host-side TPM-sealing.
- **No cipher rotation.** A vault's cipher suite is fixed at create
  time. Switching between AES-256-GCM-SIV (current default), AES-256-GCM
  (legacy), and ChaCha20-Poly1305 requires a manual decrypt-then-recreate
  cycle. Vaults created before audit Finding 1 are still on AES-256-GCM
  and cannot be migrated to GCM-SIV in place.

---

## 6.x What's still needed before "production-grade for high-value targets"

This section is the canonical, current list of gaps as of the most
recent audit round. Everything here is **known unfinished work**, not
hypothetical concerns. The order is rough priority, biggest unmitigated
risk first.

### Tier 1 - load-bearing gaps that change the threat model

1. **Independent third-party security audit.** Internal-team audits
   find the things the team remembered to look for. The largest
   remaining unknown is whatever the team hasn't thought of. Scope
   the engagement narrowly to maximize ROI: the 1 200 LOC of
   `unsafe` (`luksbox-fido2/src/{ffi,hid,webauthn}.rs`,
   `luksbox-core/src/{secret_box,secret_mem}.rs`,
   `luksbox-format/src/container.rs` Windows arm,
   `luksbox-mount/src/{fuse,winfsp}.rs`) plus a primitive-correctness
   spot-check on the keyslot wrap/unwrap and the hybrid-PQ KEM mixing.
   See Sec.6 above for the standing offer to fund.

2. **Reproducible builds + signed releases.** A tampered release on
   the GitHub Releases page would currently be undetectable -
   neither the binary nor the `.dmg` / `.msi` carries a checkable
   signature beyond the (optional) Apple / Authenticode codesigns,
   which only verify "Apple/Microsoft trusts the signing identity",
   not "this binary matches a specific commit." Path forward: cargo
   `--locked` builds in a sandbox, Sigstore / SLSA build provenance,
   `cosign attest` on the release artifacts. This is a supply-chain
   gap that no amount of crypto correctness inside the binary
   defends against.

### Tier 2 - defensive gaps with concrete attacker scenarios

3. **Side-channel timing measurement on real hardware.** We use
   `subtle::ConstantTimeEq` for tag comparisons and iterate every
   passphrase keyslot regardless of match (defending against
   first-match timing oracles). What we do *not* do: actually
   measure leakage with `dudect` or `ctgrind` on real CPUs. The
   AES-NI-absence warning at startup is not a substitute. Realistic
   threat: a co-tenant on a shared machine running a cache-timing
   attack against a long-lived `luksbox-gui` process.

4. **Multi-vendor FIDO2 hardware testing.** End-to-end tests
   currently exercise one Yubico YubiKey 5 NFC. Other CTAP2 devices
   in the wild (SoloKey 2, Nitrokey FIDO2, Token2 PIN+, OnlyKey)
   may surface vendor firmware quirks that pure-mock tests can't
   catch. The round-2 cred_id roundtrip bug is the canonical
   example of "looked fine in mock, broke on real device."
   Recommendation: add at least one non-Yubico key to the manual
   pre-release smoke checklist.

5. **Long-running fuzz campaigns before each release.**
   `scripts/release_fuzz.sh` exists for 24h-per-target campaigns
   but compliance is process discipline, not enforced by CI. The
   per-PR `fuzz-smoke` job runs 5 min per target - adequate for
   regression detection, inadequate for finding novel bugs in
   newly-touched parser surface. Run the full campaign before
   tagging any release that touched `crates/luksbox-{format,core,
   pq,vfs}/src/`.

### Tier 3 - quality-of-life and platform-parity gaps

6. **Linux/macOS FUSE mount integration tests.** The Windows
   WinFsp adapter now has 4 integration tests
   (`crates/luksbox-mount/tests/winfsp_mount.rs`) that exercise
   actual kernel mounts. The FUSE adapter has zero - manual smoke
   only. A FUSE integration test needs a writable tmpfs mountpoint
   and (on most distros) a user already in the `fuse` group; the
   GitHub `ubuntu-latest` runner satisfies both, but no one has
   written the tests.

7. **macOS thread enumeration in the daemonize fork-guard.** The
   Linux path uses `/proc/self/task/`. macOS would use
   `task_threads()` from Mach. Without it, a future caller of
   `mount(daemonize=true)` from a multithreaded process could
   silently fork into a deadlocked child. Documented but
   unmitigated on macOS.

8. **Cipher rotation.** A vault's cipher suite is fixed at create
   time; rotating between AES-256-GCM-SIV (default for new vaults),
   AES-256-GCM (legacy), and ChaCha20-Poly1305 requires a manual
   decrypt-then-recreate cycle. Not a security issue per se: all
   three ciphers are sound (and SIV is nonce-misuse-resistant on
   top of being sound). Affected scenarios: a user on a pre-Finding-1
   vault who wants the SIV upgrade, or a user who later discovers
   their CPU has no AES-NI and wants to rotate to ChaCha. Both
   require a fresh vault + content migration.

9. **Plausible-deniability hidden volumes.** No "duress
   passphrase" feature. A user under coercion has no way to open
   a decoy vault while protecting the real one. Out of scope for
   v1 by design; on the roadmap if there's user demand.

10. **Hardware-isolated MVK storage (Linux TPM / macOS Secure
    Enclave / Windows TPM).** Two distinct protection layers to
    keep separate:

    **In-process protection (MVK in RAM after unlock):**

    - **Linux**: `memfd_secret(2)` pages, unmappable from any other
      process even by root. Strongest of the three.
    - **macOS**: `Box<[u8; 32]>` + `mlock` + `RLIMIT_CORE = 0` +
      `Zeroize`-on-drop. No `memfd_secret` equivalent. A
      same-machine root attacker (or a process with
      `com.apple.security.cs.debugger`) can read the MVK via
      `task_for_pid_force` + `mach_vm_read`.
    - **Windows**: same as macOS plus per-allocation `VirtualLock`
      (added in this round) + `SetErrorMode` minidump suppression.
      No `memfd_secret` equivalent. A process with `SeDebugPrivilege`
      can read the MVK. The cross-process-read defense is
      Protected Process Light (PPL), but PPL requires the binary
      to be signed with a Microsoft-issued PPL cert that's only
      available to AV vendors. Not a path open to LUKSbox.

    **At-rest protection (wrapped MVK in the .lbx file):**
    **Linux** now ships with hardware-isolated wrapping via TPM
    2.0 (`SlotKind::Tpm2Sealed` and the fused
    `SlotKind::Tpm2Fido2`); the wrap KEK is sealed inside the
    TPM and only re-emerges on the original machine.
    **macOS and Windows** remain at the wrap-only-protected-by-
    Argon2id level for now (Secure Enclave / Windows TPM
    integrations still on the roadmap below).

    For platforms WITHOUT hardware wrapping the MVK is held only
    under a passphrase-derived KEK (Argon2id) or a FIDO2-bound
    KEK; a stolen vault file is exposed to:

    - Brute-force against the passphrase (Argon2id slows it
      proportionally to your KDF strength setting).
    - Reuse on a different machine if the attacker captures both
      the vault file AND the FIDO2 authenticator.

    Adding hardware-isolated wrapping closes both. Threat-model
    delta from no-hardware to TPM/SEP-bound:

    - Stolen vault file alone is uncrackable - extracting the
      MVK requires the original co-processor (or extracting the
      raw chip via decapsulation, which is a nation-state-tier
      attack).
    - PCR-sealing on Linux/Windows TPM additionally refuses to
      unwrap if the boot chain has been tampered with - defends
      against rootkits and boot-USB attacks.
    - Dictionary-attack lockout on TPM (typical 32 wrong
      attempts -> multi-hour lockout, eventually permanent)
      means even a weak passphrase is effectively uncrackable
      on the original hardware.

    The right native path on each platform is **hardware-isolated
    key wrapping** (a separate co-processor holds the wrap key; the
    MVK gets unwrapped to RAM at unlock via the chip):

    - **Linux**: **TPM 2.0** (discrete chip or firmware TPM via
      Intel PTT / AMD fTPM, present on most modern hardware) via
      `tpm2-tss` + the `tss-esapi` Rust crate. **Shipped** in v1
      as `SlotKind::Tpm2Sealed` (TPM-only), `SlotKind::Tpm2SealedPin`
      (PIN-protected via `userAuth`), `SlotKind::Tpm2Fido2` (fused
      TPM + FIDO2), and the four hybrid-PQ-TPM variants
      (`HybridPqKemTpm2`, `HybridPqKemTpm2Fido2`,
      `HybridPqKem1024Tpm2`, `HybridPqKem1024Tpm2Fido2`) combining
      TPM with ML-KEM-768 or -1024. Enroll via
      `luksbox enroll <vault> --kind tpm2[...]`; unlock via
      `--tpm2` (PIN slots auto-detected). swtpm-based integration
      tests in CI verify the actual seal/unseal round-trip against
      an emulated TCG-compliant TPM. The wizard and GUI both
      surface every TPM variant for enroll/unlock/create.
      Still TODO on the Linux side: PCR sealing for boot-chain
      tamper detection (current slots have empty policy, so any
      caller on this TPM can unseal). Tracked in
      `docs/TPM_FUTURE_IMPROVEMENTS.md`.

      **Threat model reminder for the bare `Tpm2Sealed` kind**:
      with no PIN (`userAuth`) and no PCR policy, the sealed blob
      is unsealable by ANY caller on the same TPM device. This
      protects the vault file in isolation (a stolen `.lbx` cannot
      be opened without the TPM) but does NOT protect against an
      attacker who has the WHOLE DEVICE booted and running. For
      device-theft scenarios, prefer `Tpm2SealedPin`
      (`--kind tpm2-pin` on enroll) so the chip's
      dictionary-attack lockout gates an offline-style attack
      against the PIN, and add PCR policy as an opt-in once it
      ships (boot-chain tamper detection). The wizard surfaces a
      one-line warning at the `tpm2` enroll prompt; the GUI shows
      it under the "Add TPM 2.0 keyslot" modal.

    - **Windows**: not yet shipped, **but reachable today via the
      `TctiNameConf::Tbs` variant added in `tss-esapi 8.0.0-alpha.2`**.
      The Linux `Tpm2Sealer` implementation works against `Tcti::Tbs`
      with a one-line cfg branch + an import rename
      (`resource_handles` -> `reserved_handles`). On-disk slot bytes
      are byte-identical between Linux and Windows TPM, so a vault
      sealed with the same chip would unseal on either OS. Trade-off
      blocking immediate adoption: tss-esapi 8.0 is alpha (alpha line
      since 2024, alpha.2 published 2026-02-26) and bumps the
      `tpm2-tss` floor to 4.1.3, breaking Debian 12, Ubuntu
      22.04/24.04 LTS, and RHEL 9 unless we also ship a `bundled-tpm`
      Cargo feature for static linking. Full design + the three
      implementation paths evaluated (TBS via tss-esapi 8.0, NCrypt
      direct, raw FFI bypass) live in
      `docs/TPM_FUTURE_IMPROVEMENTS.md`.

    - **macOS**: not yet shipped. Different chip (Secure Enclave),
      different API (`SecKey` / `CryptoKit`), needs Apple Developer
      enrollment to sign binaries with the keychain entitlement.
      Tracked in `docs/TPM_FUTURE_IMPROVEMENTS.md` section 2.

    Original cross-platform design notes (preserved as the spec
    for the macOS / Windows ports):

    Same model as `systemd-cryptenroll --tpm2-device=auto` for
    LUKS2. **Easiest of the three platforms
      to implement** (pure-OSS toolchain, no enrollment / signing
      gates, `swtpm` software-TPM emulator runs in CI for
      integration tests).
    - **macOS**: the **Secure Enclave** (SEP coprocessor on Apple
      Silicon and T2 Intel Macs). Accessed via `SecKey` /
      `CryptoKit` APIs. Requires Apple Developer enrollment for
      signing the resulting binaries (in progress per
      `docs/APPLE_SIGNING.md`).
    - **Windows**: the **TPM 2.0** (mandatory on Windows 11) via
      `tcti-tbs.dll` (TPM Base Services) wrapped through
      `tss-esapi 8.0.0-alpha.2`'s `TctiNameConf::Tbs` variant. The
      NCrypt + Platform Crypto KSP API (which BitLocker / Windows
      Hello use) was considered as an alternative but rejected: it
      uses a different on-disk wire format (NCrypt PCP key blobs ≠
      TPM2B blobs), so a vault sealed on Windows would not unseal on
      Linux even with the same chip - that breaks the cross-platform
      vault-portability principle. See
      `docs/TPM_FUTURE_IMPROVEMENTS.md` for the full evaluation.

    Symmetric problem, vendor-specific API surface. Same trade-offs
    on all three platforms:

    - **Wrap-only, not chunk-encrypt-via-chip.** Per-chunk
      decryption through an IPC boundary kills throughput (TPMs
      do 1-10 MB/s symmetric; SEP does a few hundred). Right
      design: the chip wraps the MVK at enrollment, unwraps it
      to RAM at unlock (slow, once), then the in-process MVK
      handles per-chunk AEAD at full AES-NI speed (~590 MB/s).
      The MVK is in process memory after unwrap - same as today
      - but the wrapped form on disk is hardware-bound.
    - **AES-256-GCM-SIV is not a chip primitive.** SEP supports
      AES-GCM and ChaCha20-Poly1305; TPM supports AES-CCM, AES-GCM,
      AES-CBC. Since the chip only handles the unwrap step, this
      is fine: the wrap ceremony uses chip-supported AES-GCM, the
      chunk encryption stays AES-256-GCM-SIV in-process. No
      cipher downgrade for the user.
    - **Hardware-bound keys are non-portable.** A vault enrolled
      with TPM/SEP wrapping cannot be opened on a different
      machine. The design ships TPM/SEP wrapping as a NEW keyslot
      kind alongside the existing passphrase and FIDO2 slot kinds
      - users can have both a TPM slot (for fast / passphrase-
      less unlock on the bound machine) and a passphrase or
      FIDO2 slot (for portability + recovery). Same model as
      systemd-cryptenroll uses.
    - **PCR sealing is opt-in (Linux + Windows).** Sealing the
      wrap to PCR0/2/4/7 means kernel/initramfs/firmware updates
      re-seal. Either we require user re-enrollment after
      updates, or we adopt the systemd-cryptenroll approach of
      PCR-policy-signing (a long-lived signing key authorises
      "any of these expected boot measurements"). Probably
      ship as PCR-unsealed by default with PCR-sealed as an
      opt-in flag.

    Estimated effort: ~2 weeks per platform of design +
    implementation, plus integration tests. Linux TPM is the
    fastest to ship (mature OSS toolchain, swtpm in CI, no
    enrollment gates) and is the recommended starting point.
    macOS Secure Enclave waits on Apple Developer enrollment
    completing first. Windows TPM is the same shape as Linux
    TPM with a different API surface. Tracked here so a
    contributor has the design constraints written down before
    starting.

### What's specifically NOT on this list

- Cryptanalysis of the underlying primitives (AES, AES-GCM-SIV,
  ChaCha20, Argon2id, ML-KEM, HKDF, HMAC, SHA-256). These rely on RustCrypto
  + the FIPS-203 validation suite and would require a separate
  engagement with a primitives-focused cryptographer.
- Formal verification of the parser or protocol. Out of scope for
  any practical-effort timeline.
- Hardware attacks against the FIDO2 authenticator (decapsulation,
  fault injection, EM analysis). The user's choice of authenticator
  governs this; LUKSbox cannot defend a vault whose `credSeed` an
  attacker has physically extracted.

If you're evaluating LUKSbox for a deployment and any of the Tier 1
or Tier 2 items above matter to your threat model, **wait for them
to be addressed** or
budget the audit work yourself.

---

## 7. Operational guidance for users

If you're using LUKSbox to protect material information, please:

1. **Use a strong passphrase**, the in-app strength meter (powered by
   `zxcvbn`) is a guide, not a guarantee. >=80 bits of estimated entropy is
   the floor.

2. **Use the `SENSITIVE` Argon2id preset** if your machine has the RAM,
   `m_cost = 1 GiB / t_cost = 5 / p_cost = 4`, several seconds per unlock.
   Worth it on long-lived vaults.

3. **Use a FIDO2 authenticator** if you have one. Wrap mode for everyday
   use; direct mode if you're willing to trade "lost YubiKey = lost vault"
   for "no passphrase to type." Hybrid-PQ-FIDO2 if you need
   harvest-now-decrypt-later defense.

4. **Use the anchor sidecar** (`--anchor /path/on/usb-stick.anchor`) if you
   care about rollback detection. Keep the anchor on **separate trusted
   storage**, keeping it next to the `.lbx` defeats the purpose.

5. **Use detached headers** (`--header /path/on/separate-storage.hdr`) if
   you need to deny that a particular file is a LUKSbox vault at all. The
   `.lbx` becomes opaque random-looking data without its `.hdr`.

6. **Never share a `.lbx` with a different machine while it's mounted.** Use
   `luksbox umount` first, or let the mount-time lock prevent the second
   open.

7. **Be aware of hibernate / swap.** On Linux with `memfd_secret` available,
   the MVK is excluded from hibernate images. On older kernels and on macOS,
   it isn't. Disable hibernate or use encrypted swap.

8. **Back up the `.kyber` and `.anchor` sidecars separately.** Losing the
   `.kyber` for a hybrid-PQ vault locks you out permanently. Losing the
   `.anchor` only loses rollback detection, but you can't easily re-create
   it later.

9. **Verify on first use that your authenticator is what you think it
   is.** A look-alike device is detected at unlock time, but only after
   you've enrolled it. Keep your purchase chain trustworthy.

10. **Non-interactive passphrase entry** (added in audit Round 9F).
    LUKSbox accepts passphrases via three channels, in this priority
    order. Pick the most-secure that fits your workflow:

    | Method | Visible to | Recommended for |
    |---|---|---|
    | **Interactive prompt** (default) | only the typing user (and the kernel input subsystem) | Direct CLI use. Most secure. |
    | **Stdin pipe** (`echo pp \| luksbox open ...` or `cat pp.txt \| luksbox ...`) | the writing process and the kernel pipe buffer; **NOT** in `/proc/<pid>/cmdline` or `/proc/<pid>/environ` | Scripts and CI. The writing process controls visibility. |
    | **`LUKSBOX_PASSPHRASE` env var** | every process running as the same UID via `/proc/<pid>/environ`, plus the parent shell that exported it | Legacy / convenience. Use ONLY when stdin pipe isn't possible. |

    LUKSbox **never** accepts a passphrase as an argv flag value
    (would expose it via `ps aux` to every user on the machine).
    There is no `--passphrase <VALUE>` flag on any subcommand;
    audit Round 9F's regression test
    (`crates/luksbox-cli/tests/passphrase_exposure.rs`) pins this.

    Recommended script pattern:
    ```bash
    cat ~/.config/my-vault.pp | luksbox put my.lbx report.pdf
    ```
    rather than:
    ```bash
    LUKSBOX_PASSPHRASE="$(cat ~/.config/my-vault.pp)" luksbox put my.lbx report.pdf
    ```
    The second form puts the passphrase in YOUR shell's process
    environment too, where another tool spawned in the same shell
    inherits it. The pipe form is process-local.

---

## 8. Audit history

Internal audits to date, see [the audit history on the website](https://luksbox.penthertz.com/docs/security/audit/)
for the full per-round log.

| Round | Focus | Findings |
|---|---|---|
| 1 | Parser-layer DoS via on-disk Argon2id params | 1 vuln fixed (`Argon2idParams::is_sane_for_disk`); 14 regression tests |
| 2 | FIDO2 trust boundary (rogue / MITM authenticator) | 1 vuln fixed (cred_id OOM at FFI boundary); 11 tests |
| 3 | Auth-then-process pipeline (post-AEAD bincode) | 1 vuln fixed (bincode OOM via hostile metadata); 1 regression test |
| 4 | Live YubiKey detection layer | no findings; thread-safety verified |
| 5 | End-to-end hardware + rogue edge cases | round-2 fix verified on real hardware; 6 additional rogue tests |
| 6 | Invariant lockdown across the stack | no new vulns; HKDF info-string uniqueness, header-tamper coverage, slot AEAD AAD field-by-field, cross-file substitution, generation rollback, concurrent-open enforcement (flock), symlink TOCTOU defense, AES-NI startup warning |

**Ad-hoc improvements** since the audit log was last updated:

- Pre-fork single-thread assertion in `luksbox-mount` (closes the "GUI
  wraps mount in `std::thread::spawn`" footgun).
- `pin_cstr.as_ptr()` lifetime guard-rail in `luksbox-fido2/src/hid.rs`.
- `dup2` return-value checks in the daemonize path.
- libfido2 link-version capture for diagnostic visibility.
- SAFETY/LIFETIME/THREAD-SAFETY block comments on the long unsafe regions
  in `hid.rs`.

---

## 9. Acknowledgments

We will list researchers who report verified vulnerabilities here, with their
permission. Currently empty, be the first.

---

## 10. Scope statement

This policy covers the LUKSbox source tree and its first-party crates
(`luksbox-core`, `luksbox-format`, `luksbox-fido2`, `luksbox-pq`,
`luksbox-vfs`, `luksbox-mount`, `luksbox-cli`, `luksbox-gui`).

Out of scope:
- Vulnerabilities in third-party dependencies, unless we can mitigate at
  our layer (e.g. by capping inputs before they reach the dep). We will
  forward such reports upstream.
- Issues in the user's host operating system, kernel, libfuse, libfido2,
  WinFsp, or FIDO2 authenticator firmware.
- Social-engineering attacks against the user.
- Bugs that require root / Administrator privileges already obtained on
  the user's machine.

---

*Last reviewed: see `git log SECURITY.md` for the most recent edit. The
threat model and dependency advisories are accurate as of that commit; the
audit report is the source of truth for findings.*
