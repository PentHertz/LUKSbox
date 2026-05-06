# Testing

LUKSbox ships **four kinds of tests**, each with a different cost,
purpose, and feedback loop. Pick the right one for the change you're
making:

| Tier | Run on | Wall-clock | Tests what |
|---|---|---|---|
| **Unit tests** | every save (`cargo test -p <crate>`) | 5 s per crate | Per-module invariants, crypto round-trips, parser correctness |
| **Functional tests** | every commit (`cargo test --workspace`) | 30 s | End-to-end CLI workflows via subprocess |
| **Fuzz smoke** | every PR (CI) | 5 min x N targets | Trivially-reachable parser crashes |
| **Hardware tests** | manual, before each release | 5 min | FIDO2 enroll / open / revoke against a real authenticator |

Plus the orchestrated multi-day fuzz campaigns documented in
[`FUZZING.md`](FUZZING.md).

---

## Quick start, run everything sensible locally

```bash
# Workspace tests (unit + functional, 30 s total)
cargo test --workspace --exclude luksbox-gui --exclude luksbox-fuzz --exclude luksbox-fuzz-afl

# Hardware feature paths (FIDO2 wrap, hybrid-fido), needs libfido2-dev installed
cargo test --workspace --features luksbox-cli/hardware \
    --exclude luksbox-gui --exclude luksbox-fuzz --exclude luksbox-fuzz-afl
```

Both runs should finish 100% green. If anything fails, the test
output names the file path + line number, drop into the failing
test and read it; tests are written to be self-documenting about
the property they're verifying.

---

## Unit tests, what's covered

Unit tests live alongside the source they test
(`crates/<crate>/src/<file>.rs` `#[cfg(test)] mod tests`) and in
per-crate `tests/` directories.

### `luksbox-core` (22 tests + 9 in `argon2_dos_guard` + 10 security invariants)

`crates/luksbox-core/`:

- `aead.rs::tests`, AES-256-GCM, AES-256-GCM-SIV, and
  ChaCha20-Poly1305 round-trips, tag-tamper detection, RFC 8452
  KAT for the SIV variant, and a deterministic-output pin for the
  SIV's nonce-misuse-resistance property.
- `header.rs::tests`, header serialize/parse round-trip, HMAC
  verify, version compatibility.
- `keyslot.rs::tests`, passphrase / FIDO2 wrap / FIDO2-direct /
  hybrid-PQ slot round-trips, AAD tamper rejection,
  byte-shape-indistinguishability between kinds.
- `kdf.rs::tests`, Argon2id determinism, HKDF subkey derivation.
- `secret_mem.rs::tests`, `memfd_secret` allocation on Linux,
  fallback to `Box`+`Zeroize` elsewhere. **Plus round-9B
  hardening assertion tests**: `disable_core_dumps_zeroes_rlimit_core`
  (Unix) verifies `RLIMIT_CORE = 0` after hardening;
  `disable_core_dumps_clears_pr_dumpable_on_linux` (Linux only)
  verifies `prctl(PR_GET_DUMPABLE) == 0` after the
  `prctl(PR_SET_DUMPABLE, 0)` call - this also blocks ptrace from
  same-UID sibling processes.
- `tests/argon2_dos_guard.rs`, **9 regression tests** for the
  Argon2id-via-on-disk-params DoS (audit round 1).
- `tests/aead_kat.rs`, **13 byte-exact KAT regression anchors**
  added in audit round 9C: 10 from RFC 8452 Appendix C.2
  (AES-256-GCM-SIV), 1 from RFC 8439 Sec.2.8.2
  (ChaCha20-Poly1305), 2 from McGrew & Viega 2005 GCM Test
  Cases 13/14 (AES-256-GCM). Each asserts `aead::seal` produces
  exact expected bytes + `aead::open` recovers + tag tamper is
  rejected. Catches silent regressions in RustCrypto crates +
  argument-order mistakes + crate-substitution attacks.

### `luksbox-format` (10 tests)

`crates/luksbox-format/src/`:

- `container.rs::tests`, full vault create/open/persist round-trip
  for each keyslot kind.
- `metadata.rs::tests`, encrypted-metadata blob round-trip, AEAD
  tag verification, replay rejection.
- `anchor.rs::tests`, anchor write/read/verify, MAC tamper
  rejection, generation-counter compare.
- `hybrid_sidecar.rs::tests`, sidecar v1 (legacy) and v2 read/write
  round-trips, mixed 768/1024 entries, malformed input rejection.

### `luksbox-pq` (39 tests across 4 files)

- `src/lib.rs::tests`, keygen / encapsulate / decapsulate
  round-trips for ML-KEM-768 and ML-KEM-1024.
- `src/seed_file.rs::tests`, `.kyber` file write/read round-trip.
- `tests/fips203_conformance.rs`, **17 FIPS 203 conformance
  tests** organized by spec section reference (Table 2 sizes, Sec.6
  correctness, Sec.6.3 implicit rejection, cross-parameter guards).
- `tests/end_to_end_hybrid.rs`, full passphrase-based hybrid-PQ
  vault flow with tamper tests.
- `tests/seed_file_dos_guard.rs`, **5 regression tests** for the
  seed-file Argon2id-DoS (audit round 1).

### `luksbox-fido2` (9 tests + 11 in `rogue_authenticator`)

- `src/protocol.rs::tests`, CTAP2 hmac-secret protocol round-trip,
  ECDH agreement, salt-auth tamper detection.
- `src/mock.rs::tests`, `MockAuthenticator` deterministic enroll +
  hmac_secret behaviour.
- `tests/rogue_authenticator.rs`, **11 regression tests** for
  rogue/MITM FIDO2 device behaviour (audit round 2).

### `luksbox-vfs` (22 tests + 1 in `metadata_format_v2`)

`crates/luksbox-vfs/src/vfs.rs::tests`:

- File create / read / write / unlink round-trips.
- Directory mkdir / rmdir / rename / readdir.
- Multi-chunk file writes (>4 KiB).
- Sparse writes (zero-fill holes).
- Overwrite within a chunk.
- MVK rotation with single-slot and multi-slot configurations.
- Anchor / generation-counter rollback detection.
- Hide-size mode round-trips and persistence.
- `tests/metadata_format_v2.rs::postcard_decoder_rejects_oversized_payload`,
  **1 regression test** for the postcard oversize-payload guard
  (replaces the original `bincode_oom_guard` after the codec moved
  from bincode to postcard).

### `luksbox-cli` (5 tests)

`crates/luksbox-cli/tests/cli.rs`, basic create / put / ls / get /
rm / mkdir / mv / enroll / revoke flows. Run as subprocess of the
real binary.

### `luksbox-mount` (4 tests, Windows-only)

`crates/luksbox-mount/tests/winfsp_mount.rs`, **4 integration tests**
that mount a real luksbox vault on a free drive letter through the
WinFsp kernel driver, exercise it, and tear it down. Catches the
class of bug that motivated writing them: `FileSystem::start`
returning `Ok(())` while Win32 still reports the volume as
unrecognized (the `OVERWRITE_DEFINED=false` regression - see
[`crates/luksbox-mount/src/winfsp.rs`](crates/luksbox-mount/src/winfsp.rs)
top-of-file gotcha #1).

Coverage:
- `mount_makes_drive_visible_to_win32`, mount -> query via `wmic
  logicaldisk` -> assert `FileSystem=luksbox` and a non-zero `Size`.
  This is the canary for the WinFsp callback wiring.
- `unmount_from_other_thread_wakes_mount_thread`, simulates the GUI
  flow: mount in thread A, `unmount()` from thread B, assert thread
  A returns `Ok(())` within 10 s. Catches path-normalization drift
  between mount/unmount and any regression in the per-process mount
  registry.
- `three_mount_unmount_cycles_in_one_process`, exercises the
  `OnceLock`-guarded ctrlc handler (must not double-install) and
  the registry re-entry path (must not leak senders). A regression
  here would manifest as a hang on round 2 or 3.
- `unmount_of_unknown_mountpoint_errors_clearly`, asserts that
  cross-process unmount does NOT silently succeed (WinFsp has no
  out-of-band unmount IPC; pretending we honored the request would
  mislead the user).

The Linux/macOS FUSE adapter has no automated tests yet - a FUSE
integration test would need a tmpfs mountpoint and either root or a
working FUSE setup with `/etc/fuse.conf` `user_allow_other`.

#### Running the WinFsp tests

```powershell
# Requires Visual Studio Build Tools 2022 (link.exe) and WinFsp 2.x
# from https://winfsp.dev/rel/ both installed. Run serially because
# they share the drive-letter pool.
cargo test --release -p luksbox-mount --test winfsp_mount -- --test-threads=1
```

If WinFsp isn't installed the tests `eprintln!("[skip] ...")` and
return - you'll see them as `ok` (passed) rather than ignored. CI
runners that need to actually exercise the kernel mount must
install WinFsp first.

### `luksbox-gui`

No automated tests, egui has no headless unit-test story. Manual
click-through before each release. The mount/unmount logic the GUI
calls IS covered, indirectly, by `luksbox-mount/tests/winfsp_mount.rs`
above (the `unmount_from_other_thread_wakes_mount_thread` test
mirrors what the GUI's "Unmount" button does).

### How to run unit tests

```bash
# Single crate
cargo test -p luksbox-core
cargo test -p luksbox-pq

# Single test file
cargo test -p luksbox-core --test argon2_dos_guard

# Single test by name
cargo test -p luksbox-core --test argon2_dos_guard accepts_sensible_argon2_params

# All non-GUI workspace
cargo test --workspace --exclude luksbox-gui --exclude luksbox-fuzz --exclude luksbox-fuzz-afl

# With hardware feature (FIDO2 wrap mode, hybrid-fido)
cargo test --workspace --features luksbox-cli/hardware \
    --exclude luksbox-gui --exclude luksbox-fuzz --exclude luksbox-fuzz-afl
```

### How to debug a failing unit test

```bash
# Print stdout/stderr from the failing test (cargo captures them by default)
cargo test -p luksbox-core <test-name> -- --nocapture

# Get a stack trace
RUST_BACKTRACE=1 cargo test -p luksbox-core <test-name>
RUST_BACKTRACE=full cargo test -p luksbox-core <test-name>

# Run a single test repeatedly to catch flakiness
for i in $(seq 1 50); do cargo test -p luksbox-core <test-name> --quiet; done
```

---

## Functional tests, end-to-end CLI workflows

`crates/luksbox-cli/tests/functional.rs`, **20 tests** that exercise
the actual `luksbox` binary as a subprocess. No library shortcuts,
a regression anywhere in the dispatch / parsing / argument-validation
layer fails here.

### What's covered

| Test | Workflow |
|---|---|
| `vault_persists_across_reopen` | create -> put -> drop process -> get from fresh process |
| `detached_header_round_trip` | `--header` mode; vault file alone is unusable |
| `anchor_round_trip_and_warn_when_missing` | `--anchor` rollback-detection sidecar workflow |
| `hybrid_pq_passphrase_round_trip` | `--kind hybrid-pq --pq-hybrid <kyber>` create + put + get |
| `hybrid_pq_1024_round_trip` | ML-KEM-1024 variant |
| `hybrid_pq_wrong_kyber_seed_fails` | wrong `.kyber` seed must reject open |
| `kdf_strength_recorded_in_slot` | `--kdf interactive/moderate/sensitive` accepted + reflected in `info` |
| `kdf_strength_rejects_garbage` | unknown `--kdf` value validation |
| `info_reports_cipher_kind_and_keyslot_table` | `info` formatting |
| `update_passphrase_changes_unlock_secret` | `update` rotates the slot's wrapping passphrase |
| `many_files_round_trip` | 30 files, varying sizes, nested dirs |
| `one_megabyte_file_round_trip` | multi-chunk file, deterministic content |
| `pad_files_flag_accepted_and_round_trips` | `--pad-files` hardening flag |
| `hide_sizes_flag_accepted_and_round_trips` | `--hide-sizes` hardening flag |
| `cat_streams_to_stdout` | `cat` byte-exact stdout |
| `rmdir_empty_succeeds_nonempty_fails` | dir-removal semantics |
| `panic_destroy_overwrites_header` | `panic -y` overwrites the 8 KB header with random bytes |
| `info_on_missing_file_is_clean_error` | no panic on missing path |
| `ls_on_garbage_file_is_clean_error` | no panic on non-vault input |
| `genpass_outputs_passphrase` | `genpass` produces a non-trivial string |

### How to run

```bash
# All functional tests (30 s)
cargo test -p luksbox-cli --test functional

# Single test
cargo test -p luksbox-cli --test functional vault_persists_across_reopen

# With output visible
cargo test -p luksbox-cli --test functional <name> -- --nocapture
```

### Required environment

The tests inject these env vars into each subprocess:

```
LUKSBOX_TEST_FAST_KDF=1     bypass Argon2id 500 ms sleep (debug builds only)
LUKSBOX_PASSPHRASE=pw       satisfies passphrase prompts
LUKSBOX_NEW_PASSPHRASE=pw   for enroll / update flows
LUKSBOX_ACCEPT_WEAK=1       skip zxcvbn weak-passphrase warning
```

`LUKSBOX_TEST_FAST_KDF` is **compiled out of release binaries**
(`debug_assertions = false`). Setting it in the environment of a
shipped LUKSbox binary has no effect, so a polluted shell or a
malicious launcher cannot downgrade Argon2id to brute-forceable
parameters. The bypass exists only to keep the test suite under a
few minutes.

You don't need to set these manually, the test fixture
`tests/functional.rs::test_env()` does it. But if you want to
reproduce a failure by running the binary by hand (must be a debug
build for the env var to take effect):

```bash
LUKSBOX_TEST_FAST_KDF=1 LUKSBOX_PASSPHRASE=pw \
    cargo run -p luksbox-cli -- create /tmp/v.lbx
```

### What's NOT in the functional tests

- **FIDO2 anything.** Needs real hardware. See "Hardware tests" below.
- **Linux/macOS mount / unmount.** Needs FUSE setup, tmpfs, possibly
  root. See the manual mount smoke in "Hardware tests". Windows
  mount IS covered by `luksbox-mount/tests/winfsp_mount.rs` when
  WinFsp 2.x is installed on the test host.
- **GUI flows.** No headless test for egui. Manual click-through.
- **Multi-process concurrent access.** Vault file isn't designed for
  concurrent writers; out of scope.

---

## Security regression tests, the hard CI gate

These are the **26 tests added during the 3-round fuzz audit** that
encode the safe envelope of the three vulnerabilities we fixed. They
run as their own CI job (`security-regressions`) so the green/red
signal is unambiguous, any failure here is a serious regression.

```bash
cargo test -p luksbox-core    --test argon2_dos_guard       # 9 tests
cargo test -p luksbox-pq      --test seed_file_dos_guard    # 5 tests
cargo test -p luksbox-fido2   --test rogue_authenticator    # 11 tests
cargo test -p luksbox-vfs     --test metadata_format_v2 -- postcard_decoder_rejects_oversized_payload  # 1 test
cargo test -p luksbox-pq      --test fips203_conformance    # 17 tests
cargo test -p luksbox-pq      --test end_to_end_hybrid      # 4 tests
```

Total: 47 tests across 6 suites. Each one must stay green forever.
If you're touching code that any of these guard, run them first
before merging.

---

## Hardware tests, manual, requires a real FIDO2 authenticator

We do NOT auto-test against real hardware in CI:

- Resetting a FIDO2 device wipes ALL credentials (including
  non-LUKSbox ones, SSH, Google, etc.). Hostile to the user.
- The on-device PIN retry counter (typically 8) gets burned by
  failure-mode testing.
- Touch can't be simulated.

Do this **once per release** (or after touching any FIDO2 path).

### Pre-requisites

- A FIDO2 authenticator: YubiKey 5+, SoloKey 2, Nitrokey 3, Token2,
  or anything else CTAP2-compliant.
- libfido2-dev installed: `sudo apt install libfido2-dev pkg-config`
- Build with hardware feature: `cargo build --release -p luksbox-cli --features hardware`

### Smoke test (10 minutes)

There's a one-shot script at [`scripts/fido2_smoke.sh`](scripts/fido2_smoke.sh)
that exercises all four FIDO2-backed modes (wrap, direct, hybrid-768,
hybrid-1024) end-to-end with create + put + get + content-diff
verification. It prompts before each touch with a numbered banner
so you know which operation needs attention.

```bash
# Build with hardware feature
cargo build --release -p luksbox-cli --features hardware

# Run (PIN passed via env so it's not in argv / shell history)
read -s -p "FIDO2 PIN: " LUKSBOX_FIDO2_PIN; export LUKSBOX_FIDO2_PIN
echo
./scripts/fido2_smoke.sh
```

Expected output: `[+] all FIDO2 mode flows passed (10 touches)`.
Each touch prompt looks like:

```
    ━━━ TOUCH #5: hybrid-fido enroll (initial hmac-secret derivation), touch your YubiKey now ━━━
```

Touch the device when you see one of those. The script auto-cleans
its work directory (`/tmp/luksbox-fido2-smoke/`); pass
`LUKSBOX_KEEP_VAULTS=1` to keep the test vaults for inspection.

### Focused in-tree probes (3-7 minutes each)

For bisecting a regression in a specific FIDO2 path, or for sanity-
checking a new device model, three focused probe examples live under
`crates/luksbox-fido2/examples/`. Each is a single self-contained
Rust program that talks to libfido2 directly + (where relevant)
exercises the real `Container` API, no shell-script orchestration.
They're gated on the same `hardware` feature as the rest of the
FIDO2 hardware path.

| Probe | What it tests | Touches | When to run |
|---|---|---|---|
| `probe` | Single device. Enroll, two same-salt asserts (determinism), one different-salt assert (variability). Reports cred_id length vs the V1/V2 (128 B) and V3 (352 B) caps. | 4 (1 enroll + 3 asserts) | Sanity check a new device, verify it implements `hmac-secret` correctly. |
| `multidev_probe` | Two different FIDO2 devices (e.g. YubiKey + Titan) plugged in simultaneously. Builds two slots wrapping the same MVK, then unlocks via each device independently and asserts both recover the same MVK. Verifies V3 layout, multi-slot independence, and cross-vendor compatibility. | 6 (3 per device: enroll + wrap-assert + unlock-assert) | After touching `keyslot.rs` or the V3 layout. After adding support for a new device class. |
| `full_probe` | Single device (Titan-class). End-to-end Container::create -> Container::open against a real `.lbx` file, plus 4 tamper tests (cred_id, hmac_salt, wrapped_ct, aad_version) plus a wrong-device negative test (needs a second device). Also verifies vault integrity is preserved across tampering attempts. | 5 on the primary device, 0 on the secondary | Comprehensive regression check. Run after any change to the FIDO2 path, slot layout, header format, or AEAD AAD scope. |

```bash
# Build any of them (hardware feature required)
cargo build --release -p luksbox-fido2 --features hardware --example probe
cargo build --release -p luksbox-fido2 --features hardware --example multidev_probe
cargo build --release -p luksbox-fido2 --features hardware --example full_probe

# Or build all three at once
cargo build --release -p luksbox-fido2 --features hardware --examples

# Run (PIN passed via env so it's not in argv)
export LUKSBOX_FIDO2_PIN=<your-PIN>
./target/release/examples/probe
./target/release/examples/multidev_probe   # needs 2 FIDO2 devices plugged in
./target/release/examples/full_probe       # needs Titan + YubiKey for the cross-device negative test
```

Each probe prints `TOUCH N (<device-label>)` immediately before each
touch is needed, so the prompts are unambiguous when multiple devices
are connected. The probes pin the device path explicitly via
`HidAuthenticator::with_device(path)` to avoid libfido2 picking the
wrong device when several are visible.

The `multidev_probe` and `full_probe` examples specifically exercise
the V3 keyslot layout (cred_id at offsets 128..480, hmac_salt at
480..512) on real hardware, which is the only way to verify that V3
on-disk roundtrips correctly with a 200-300 byte cred ID from a
Titan-class authenticator. Synthetic unit tests
(`v3_slot_accepts_288_byte_cred_id` in `luksbox-core/tests/security_invariants.rs`)
cover the same code path with a deterministic 288-byte cred_id, but
only the probes prove it works against a live device's actual cred_id
format.

### Expected results

- Each `create` should complete with "✓ created" output and produce
  the named files.
- Each `ls` / `get` / `info` should succeed cleanly.
- The YubiKey LED should blink (or however your device signals
  user-presence requests) before each operation.

### What to watch for

- **Timing**: FIDO2 wrap touches should complete within 30 s; if it
  hangs longer, suspect libfido2 / kernel issues.
- **Error messages**: should be human-readable. The audit added
  brand-aware FFI error messages (e.g. "Yubico YubiKey OTP+FIDO+CCID:
  fido_assert_set_clientdata_hash returned -7"); a raw integer error
  is a regression.
- **Crashes**: any panic / SIGSEGV in libfido2 path is a security bug.

### YubiKey reset (DESTRUCTIVE)

If you need to reset the FIDO2 app on the device (wipes ALL
credentials including non-LUKSbox uses):

```bash
ykman fido reset       # Yubico CLI; touch within 5 s
```

Don't do this casually.

---

## Side-channel measurement (dudect)

Round 9A added DudeCT-style constant-time measurement of the
wrap/unwrap path. Four benches under `crates/luksbox-core/benches/`:

| Bench | Function under test | Expected |
|---|---|---|
| `dudect_reference_leaky` | A naive byte-by-byte comparator with early return - **deliberately leaky**. Sanity check that the tooling actually detects timing leaks on this hardware. | `\|t\|` >> 4.5 (must leak) |
| `dudect_hmac_verify` | `Header::verify_hmac` - tests the `subtle::ConstantTimeEq` byte comparison of HMAC tags. | `\|t\|` < 4.5 (constant-time) |
| `dudect_aead_open` | `aead::open` for all three cipher suites (AES-256-GCM, AES-256-GCM-SIV, ChaCha20-Poly1305) - tests AEAD tag rejection timing. | `\|t\|` < 4.5 each |
| `dudect_slot_unlock` | `Keyslot::unlock_passphrase` - tests post-Argon2id AEAD unwrap timing. (Argon2id itself is intentionally NOT constant-time per its ASIC-resistance design; we test what's after it.) | `\|t\|` < 4.5 |

```bash
# Run the full suite + summary table
./scripts/run_dudect.sh

# Or run a single bench directly (default 50k samples)
cargo build --release -p luksbox-core --bench dudect_hmac_verify
target/release/deps/dudect_hmac_verify-*    # the binary, not the .d file

# Append raw timing CSV for offline analysis
./scripts/run_dudect.sh --csv /tmp/dudect.csv
```

### Interpreting the output

DudeCT reports a Welch's t-statistic over two distributions: timings
under "Class Left" inputs vs "Class Right" inputs. For a constant-
time function the two distributions are statistically indistinguishable
and `|t|` stays low.

| `|t|` magnitude | Verdict |
|---|---|
| < 4.5 | No leak detected at the sample count run |
| 4.5 - 10 | Probable leak; re-run with more samples to confirm |
| > 10 | Almost-certain leak; investigate |
| > 100 | Leak so obvious you'd catch it by eye in a debugger |

The reference-leaky bench produces `|t| > 200` consistently on
commodity hardware, confirming the tooling works. If the reference
bench reports `|t| < 4.5`, **the tooling is broken** (RDTSC not
available, CPU frequency-scaling smearing the measurements, etc.)
and the other benches' "PASS" verdicts cannot be trusted.

### When to run

- Manually after touching any wrap/unwrap or HMAC-verify code path.
- Pre-release smoke (already in `scripts/run_dudect.sh`).
- Not in CI by default - the runner takes 3 minutes and benefits
  from a quiet machine; CI noise can produce false-positive
  `|t|` excursions.

### Run results documented in audit Round 9A

[the audit history on the website](https://luksbox.penthertz.com/docs/security/audit/) Round 9A
documents the per-function `|t|` values measured on the audit-test
machine, the methodology, and the conclusion that no host-side
side-channel leak was detected in the wrap/unwrap path.

---

## Fuzz smoke (CI), already covered

Five-minute libFuzzer pass per target on every PR. See
[`FUZZING.md`](FUZZING.md) for the full fuzz playbook (cargo-fuzz +
AFL++) and crash-triage workflow.

```bash
# Local: same pass CI runs
cargo +nightly fuzz run header_parse fuzz/corpus/header_parse -- -max_total_time=300
```

---

## Pre-commit checklist

Before pushing a PR:

```bash
# 1. Format (CI gates on this)
cargo fmt --all

# 2. Workspace tests (5 of the 6 critical CI gates)
cargo test --workspace --exclude luksbox-gui --exclude luksbox-fuzz --exclude luksbox-fuzz-afl

# 3. Hardware-feature variant
cargo test --workspace --features luksbox-cli/hardware \
    --exclude luksbox-gui --exclude luksbox-fuzz --exclude luksbox-fuzz-afl

# 4. Release builds (CI gates on these)
cargo build --release -p luksbox-cli
cargo build --release -p luksbox-cli --features hardware
cargo build --release -p luksbox-gui

# 5. Clippy (informational; tighten over time)
cargo clippy --workspace --all-targets

# 6. (Optional) 5-min fuzz smoke if you touched a parser
cargo +nightly fuzz run <target-you-touched> fuzz/corpus/<target> -- -max_total_time=300
```

---

## Test counts at a glance

| Crate | Unit tests | Integration tests | Total |
|---|---:|---:|---:|
| luksbox-core | 15 | 9 (argon2 DoS guard) | 24 |
| luksbox-format | 10 | 0 | 10 |
| luksbox-pq | 9 | 22 (FIPS-203, hybrid e2e, seed-file DoS) | 31 |
| luksbox-fido2 | 9 | 11 (rogue authenticator) | 20 |
| luksbox-vfs | 22 | 1 (bincode OOM) | 23 |
| luksbox-cli | 0 | 25 (5 + 20 functional) | 25 |
| luksbox-mount | 0 | 4 (winfsp_mount, Windows-only) | 4 |
| luksbox-gui | 0 | 0 | 0 |
| **Workspace total** | **65** | **72** | **137** |

Plus 6 fuzz harnesses (4 pre-existing + 2 added during the audit) +
1 auth-then-process harness with a fixed MVK.
