# Development

Reference for maintainers and contributors with write access to the
repo. For project orientation and end-user documentation, see
[`README.md`](README.md).

---

## Workspace layout

```
luksbox/
├── Cargo.toml                 # workspace root: members, MSRV, shared deps
├── Cargo.lock                 # committed (binary project)
├── crates/
│   ├── luksbox-core/          #  <- lowest layer: AEAD, KDF, header, keyslots, secret_box
│   ├── luksbox-format/        #  <- container I/O, metadata, anchor, hybrid sidecar, locking
│   ├── luksbox-vfs/           #  <- in-memory directory tree atop a Container
│   ├── luksbox-pq/            #  <- ML-KEM-768 / ML-KEM-1024 + .kyber seed file
│   ├── luksbox-fido2/         #  <- FIDO2 hmac-secret protocol + libfido2 FFI (bindgen-generated)
│   ├── luksbox-mount/         #  <- FUSE3 (Linux/macOS) + WinFsp (Windows) adapters
│   ├── luksbox-cli/           #  <- `luksbox` binary
│   └── luksbox-gui/           #  <- egui desktop app
├── fuzz/                      # cargo-fuzz harnesses + corpora
├── fuzz-afl/                  # cargo-afl harnesses + seeds
└── scripts/                   # operational scripts
```

### Crate dependency direction (no cycles)

```
luksbox-cli, luksbox-gui
    ↓
luksbox-mount  ──->  luksbox-vfs  ──->  luksbox-format  ──->  luksbox-core
                                  ↘                        ↗
                                   luksbox-pq  ──────────  ↗
                                  luksbox-fido2  ────────  ↗
```

Both `luksbox-cli` and `luksbox-gui` are top-level binaries. They
depend on every lower crate. **Do not reverse this**: nothing under
`crates/luksbox-*` (other than the binaries) may depend on the
binaries.

---

## Required toolchain + system deps

| Component | Version | Notes |
|---|---|---|
| Rust toolchain | **1.88+** (MSRV) | pinned in `[workspace.package].rust-version` |
| Rust nightly | required for `cargo fuzz` | libFuzzer needs sanitizer linkage |
| `pkg-config` | any | finds libfido2 + libfuse3 |
| `libfido2-dev` | ≥ 1.10 | for FIDO2 FFI; `bindgen` regenerates the bindings each build |
| `clang` | any modern | bindgen needs libclang for header parsing |
| `libfuse3-dev` | Linux | for FUSE3 mount layer |
| `macfuse` (macOS) | 4+ | for the mount layer |
| WinFsp 2.x (Windows) | runtime + dev headers | for the Windows mount layer |
| `cargo-audit` | latest | `cargo install cargo-audit` |
| `cargo-fuzz` | latest | `cargo install cargo-fuzz` |
| `cargo-afl` | 0.15 (pinned) | `cargo install --locked --version 0.15 afl` |

On a fresh Debian/Ubuntu dev box:

```bash
sudo apt install -y build-essential clang pkg-config \
    libfido2-dev libfuse3-dev libssl-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup install nightly
cargo install cargo-audit cargo-fuzz
cargo install --locked --version 0.15 afl
```

---

## Day-to-day workflow

### Build everything

```bash
cargo build --workspace --exclude luksbox-fuzz --exclude luksbox-fuzz-afl
```

The fuzz crates are excluded from the workspace `cargo build` because
they require nightly + sanitizer flags that the rest of the workspace
doesn't want.

### Run tests

```bash
# Tier 1: unit + functional + security-regression (fast, ~30s)
cargo test --workspace --exclude luksbox-fuzz --exclude luksbox-fuzz-afl

# Tier 2: with hardware-feature paths (FIDO2 wrap, hybrid-fido)
cargo test --workspace --features luksbox-cli/hardware \
    --exclude luksbox-fuzz --exclude luksbox-fuzz-afl
```

Full test-tier reference: [`TESTING.md`](TESTING.md).

### Format + lint

```bash
cargo fmt --all
cargo clippy --workspace --exclude luksbox-fuzz --exclude luksbox-fuzz-afl \
    --no-deps -- -D warnings
```

CI runs both with `-D warnings`. PRs that fail either won't merge.

### Audit dependencies

```bash
cargo audit            # raw cargo-audit output
scripts/audit.sh       # wraps cargo-audit; tracks known-acceptable warnings
```

Currently the only flagged crate is `registry` (Windows-only,
transitive via WinFsp). Linux/macOS builds are zero-advisory.

### Run the GUI during development

```bash
cargo run -p luksbox-gui
# Or with a manual zoom override for fractional-DPI displays:
LUKSBOX_GUI_ZOOM=1.25 cargo run -p luksbox-gui
```

### Run the CLI

```bash
cargo run -p luksbox-cli -- create /tmp/v.lbx
cargo run -p luksbox-cli -- put /tmp/v.lbx hello.txt -
echo "hi" | cargo run -p luksbox-cli -- put /tmp/v.lbx hello.txt -
```

---

## Adding a feature: where things live

| Want to change | File / module |
|---|---|
| AEAD primitive (cipher suite, tag length) | `crates/luksbox-core/src/aead.rs` |
| KDF (Argon2id parameters, presets) | `crates/luksbox-core/src/kdf.rs` |
| On-disk header layout (8 KiB) | `crates/luksbox-core/src/header.rs` |
| Keyslot kinds (passphrase, FIDO2, hybrid-PQ) | `crates/luksbox-core/src/keyslot.rs` |
| Container open/create/persist | `crates/luksbox-format/src/container.rs` |
| Encrypted-metadata blob serialization | `crates/luksbox-vfs/src/vfs.rs` (postcard, magic `LBM\x02`) |
| Per-chunk AEAD | `crates/luksbox-vfs/src/chunk.rs` |
| FIDO2 protocol (CTAP2 hmac-secret, ECDH-P256, AES-CBC) | `crates/luksbox-fido2/src/protocol.rs` |
| FIDO2 FFI (libfido2 bindings) | `crates/luksbox-fido2/{build.rs, src/ffi.rs, src/hid.rs}` |
| ML-KEM hybrid + .kyber seed file | `crates/luksbox-pq/src/{lib,seed_file}.rs` |
| FUSE callbacks | `crates/luksbox-mount/src/fuse.rs` |
| CLI commands | `crates/luksbox-cli/src/main.rs` (and `wizard.rs` for interactive flows) |
| GUI screens | `crates/luksbox-gui/src/app.rs` |

---

## Format-version policy

The metadata blob has a 4-byte magic prefix `LBM\x02`. To introduce a
v3 (e.g., add a new field to `DirectoryTree` that requires a wire-
format change):

1. Bump the magic to `LBM\x03` in `crates/luksbox-vfs/src/vfs.rs`.
2. Decide whether v2 reads stay supported:
   - If yes: dispatch on the version byte; keep v2 decoder alongside v3.
   - If no (clean break): error out on v2 with a clear migration message.
3. Add a regression test verifying v2 blobs are rejected (or read) per the policy.
4. Bump the internal audit log (kept in `PRIVATE/`, outside the public repo) with a new round documenting the change.

The `LBM\x0?` magic byte was chosen to be structurally inconsistent
with any postcard-encoded `DirectoryTree`, so the dispatch is
unambiguous.

---

## FIDO2 FFI bindings

The libfido2 bindings in `crates/luksbox-fido2/src/ffi.rs` are
**generated at build time** by `bindgen` against the actually-linked
libfido2 headers (resolved via pkg-config / vcpkg / `LIBFIDO2_LIB_DIR`
env override). The crate-level `build.rs` invokes bindgen with an
allowlist restricting the surface to the ~50 symbols we actually use.

You don't need to do anything special for the bindings: they re-
generate on every build that has the `hardware` feature enabled.
The `LUKSBOX_LIBFIDO2_VERSION` env var is captured at build time and
exposed at runtime as `LIBFIDO2_LINK_VERSION` for diagnostic logging
under `LUKSBOX_FIDO2_DEBUG=1`.

---

## Adding a test

| Test type | Where it goes |
|---|---|
| Per-module unit test | `#[cfg(test)] mod tests { ... }` inside the module under test |
| Cross-module integration | `crates/<crate>/tests/<name>.rs` |
| Security regression (lock-in for a fix) | `crates/<crate>/tests/security_invariants.rs` (per-crate) |
| Fuzz harness | new file in `fuzz/fuzz_targets/` and a matching `[[bin]]` entry in `fuzz/Cargo.toml`; mirror in `fuzz-afl/` if appropriate |

After fixing a bug found by fuzzing, **promote the minimised crash
input** to the persistent corpus:

```bash
cp fuzz/artifacts/<target>/crash-XXX fuzz/corpus/<target>/regression_<short-name>
git add fuzz/corpus/<target>/regression_<short-name>
git commit -m "fuzz: regression seed for <short-name>"
```

---

## Pre-push checklist

The script `scripts/clean_for_push.sh` automates the full sequence:

```bash
scripts/clean_for_push.sh
```

What it runs:

1. `cargo clean` + remove fuzz target dirs and campaign output (transient artefacts; not for the repo).
2. Verify `.env`, `.vscode`, `.idea`, `.claude` are git-ignored.
3. `cargo fmt --all -- --check`, refuses on any drift.
4. `cargo clippy --workspace -- -D warnings`.
5. `cargo test --workspace`.
6. `cargo audit`, distinguishes vulnerabilities (block) from unmaintained warnings (note + proceed).

Exits non-zero if any step fails; the final summary explicitly says
"DO NOT push" or "ready to push".

For the fast path (skip the full test run, e.g., between rapid pushes
to a feature branch):

```bash
scripts/clean_for_push.sh --no-test
```

For checks-only without the cleanup pass (e.g., from CI where the
target dir matters):

```bash
scripts/clean_for_push.sh --check
```

---

## Fuzz cadence

| Tier | Cadence | Driver |
|---|---|---|
| Per-PR smoke | every PR (`.github/workflows/ci.yml`) | 5 min x N libFuzzer targets |
| Nightly | scheduled (`.github/workflows/fuzz-nightly.yml`) | 30 min x target |
| Pre-release gate | manual before tagging | `scripts/release_fuzz.sh` (24 h x target x N forks; default 4) |
| Server campaign | weekly on dedicated hardware | `scripts/fuzz_server.sh all 16 86400` (AFL++, 16 cores, 24 h) |

Triage and seed-promotion procedure: [`FUZZING.md`](FUZZING.md).

---

## Hardware FIDO2 smoke (manual, before each release)

```bash
LUKSBOX_FIDO2_PIN=<your-pin> scripts/fido2_smoke.sh
```

Walks four flows x six touches against a connected authenticator:
fido2 wrap, fido2 direct, hybrid-pq-fido2 (ML-KEM-768),
hybrid-pq1024-fido2 (ML-KEM-1024). Non-destructive (creates fresh
test vaults under `/tmp/luksbox-fido2-smoke/`). Burns no PIN
retries, the script will not run wrong-PIN paths.

---

## Release process

1. **Pre-flight on a clean checkout**:
   ```bash
   scripts/clean_for_push.sh
   scripts/release_fuzz.sh 86400 16   # 24 h x 7 targets x 16 forks; or 3600 for a smoke
   scripts/fido2_smoke.sh             # if a YubiKey is at hand
   ```
2. Update SECURITY.md §2 (supported versions) if cutting a maintenance branch.
3. Bump version in workspace `Cargo.toml` `[workspace.package].version`.
4. Update the internal audit log (kept in `PRIVATE/`, outside the public repo) with any new rounds since the previous tag.
5. Tag: `git tag -s vX.Y.Z -m 'release X.Y.Z'`. Sign with the maintainer's GPG key.
6. Push tag: `git push origin vX.Y.Z`.
7. Build release artefacts (CLI + GUI for Linux/macOS/Windows).
8. **Until reproducible builds are in place**, document the build
   environment (rustc version, cargo lockfile hash, libfido2 version)
   in the release notes.

---

## Dependency policy

- **Crypto crates**: only audited RustCrypto (`aes-gcm`,
  `chacha20poly1305`, `argon2`, `hkdf`, `hmac`, `sha2`, `p256`,
  `subtle`) and `ml-kem`. New crypto deps require a written
  justification.
- **No async runtime in crypto-bearing crates** (`luksbox-core`,
  `luksbox-format`, `luksbox-vfs`, `luksbox-pq`, `luksbox-fido2`).
  Mount and GUI are allowed to use threads/runtimes; nothing under
  the crypto layer should pull in tokio/async-std.
- **MSRV**: 1.88. Don't bump without checking with the maintainer.
- **`cargo audit`** must be clean of vulnerabilities and unsound
  advisories. Unmaintained-only warnings are acceptable if documented
  in SECURITY.md §6.
- **No `unsafe` in `luksbox-core` or `luksbox-format`.** The unsafe
  surface is concentrated in `luksbox-fido2/src/{ffi,hid}.rs`,
  `luksbox-mount/src/fuse.rs`, and `luksbox-core/src/secret_{box,mem}.rs`.
  Adding new `unsafe` outside that surface needs a SAFETY/LIFETIME
  block comment explaining the contract.

---

## Useful environment variables

| Variable | Effect |
|---|---|
| `LUKSBOX_FIDO2_DEBUG=1` | Enables libfido2 debug logging + prints linked libfido2 version |
| `LUKSBOX_GUI_ZOOM=1.25` | Manual zoom override for the GUI (useful on fractional-DPI displays) |
| `LUKSBOX_NO_LOCK=1` | Bypasses the `flock` on `.lbx` and `.hdr` (DANGEROUS, read-only inspection only) |
| `LUKSBOX_NO_FOLLOW_SYMLINKS=1` | Refuses to open vaults whose path is a symlink (paranoid mode) |
| `LUKSBOX_SUPPRESS_AES_WARNING=1` | Silences the no-AES-NI warning at startup |
| `LUKSBOX_FAKE_NO_AES=1` | Forces the AES-NI-detection helper to return false; testing only |
| `LIBFIDO2_LIB_DIR` / `LIBFIDO2_LIB_NAME` / `LIBFIDO2_INCLUDE_DIR` | Override libfido2 link + bindgen include paths (useful for cross-compile or non-standard installs) |

---

## Where to find help

- **Project orientation, install, quick start** -> [`README.md`](README.md)
- **End-user how-to + threat model** -> [`SECURITY.md`](SECURITY.md)
- **Audit history** -> [the audit history on the website](https://luksbox.penthertz.com/docs/security/audit/)
- **Test tiers + how to run** -> [`TESTING.md`](TESTING.md)
- **Fuzz workflow** -> [`FUZZING.md`](FUZZING.md)
- **External-auditor handover package** -> the third-party FIDO2 FFI engagement scope package (available on request to `security@penthertz.com`)
