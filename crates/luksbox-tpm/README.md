# luksbox-tpm

Linux + Windows TPM 2.0-backed wrap/unwrap of the LUKSbox Master
Volume Key. Backs every TPM keyslot kind (`tpm2`, `tpm2-pin`,
`tpm2-fido2`, and the hybrid ML-KEM-768/1024 combinations) in the
CLI, wizard, and GUI.

## Status

Shipped on both TPM platforms:

- [x] `SealedBlob` on-disk format (length-prefixed
      `TPM2B_PUBLIC` + `TPM2B_PRIVATE`) with serde-free
      `to_bytes` / `from_bytes` helpers. TCG-standard wire bytes:
      a blob sealed by the Linux build unseals under the Windows
      build on the same chip, and vice versa.
- [x] `Tpm2Sealer` API surface: `new()`, `from_tcti_str()`,
      `seal()` / `seal_with_pin()`, `unseal()` / `unseal_with_pin()`.
- [x] `tss-esapi` 8.x integration in `src/real.rs`, gated on
      `--features hardware`. Linux talks to `/dev/tpmrm0`; Windows
      talks to TBS (TPM Base Services), the in-box broker - no
      driver, no admin rights, no code signing.
- [x] No-hardware stub that returns `Error::NotCompiledIn` so
      downstream code compiles cleanly everywhere (including macOS,
      which has no TPM - the Secure Enclave in `luksbox-sep` covers
      that platform).
- [x] `swtpm` emulator integration tests (Linux) + mock-TPM
      adversary tests (every platform).
- [x] Live smoke example: `cargo run -p luksbox-tpm --features
      bundled-tpm --example tpm_smoke` (uses transient objects
      only; nothing persisted, no lockout risk).

## Build prerequisites

The default build (`cargo build -p luksbox-tpm`) compiles only the
stub and works on any platform without extra deps.

### Linux, `--features hardware` (system tpm2-tss)

Links against the system `libtss2-esys` / `libtss2-mu` /
`libtss2-sys` / `libtss2-tctildr`. tss-esapi 8.x needs
**tpm2-tss >= 4.1.3** (Debian 13+, Ubuntu 24.10+, Fedora 40+, Arch):

| Distro | Install command |
|---|---|
| Debian 13+ / Ubuntu 24.10+ | `sudo apt install libtss2-dev` |
| Fedora 40+ / RHEL 10 | `sudo dnf install tpm2-tss-devel` |
| Arch | `sudo pacman -S tpm2-tss` |

### Linux, `--features bundled-tpm` (older distros)

For distros whose tpm2-tss is older than 4.1.3 (Debian 12, Ubuntu
22.04/24.04 LTS, RHEL 9): compiles a vendored tpm2-tss via autotools
at build time. Needs `autoconf automake libtool autoconf-archive
pkg-config libssl-dev` and a C toolchain.

### Windows, `--features bundled-tpm` (MSVC only)

Compiles a vendored tpm2-tss with MSBuild (VS2017+) and generates
the Rust bindings with bindgen (needs `LIBCLANG_PATH`). See
[`BUILDING.md`](../../BUILDING.md) "Native build, Windows" step 6
for the exact recipe (tpm2-tss source staging, the openssl.props
patch, and the DLL closure to ship). The official release artifacts
bundle everything.

## Permissions

**Windows**: none needed. TBS is reachable from any user-mode
process.

**Linux**: unprivileged use of `/dev/tpmrm0` (the kernel resource
manager) requires the user to be in the `tss` group on most distros,
or explicit udev rules:

```bash
sudo usermod -aG tss "$USER"
# log out + back in for the group to take effect
```

Without permission, `Tpm2Sealer::new()` returns
`Error::DeviceNotAvailable` with a hint pointing here.

For the full end-user playbook (containers, Flatpak, troubleshooting,
common error messages, why not to use `sudo`), see
[`docs/TPM_LINUX_PERMISSIONS.md`](../../docs/TPM_LINUX_PERMISSIONS.md).

## Why TPM and not just the existing memfd_secret?

`memfd_secret` (the strongest in-process protection) and TPM-bound
wrapping (machine-binding for the wrapped MVK on disk) solve
**different** problems. They're complementary:

| Threat | memfd_secret | + TPM-bound MVK |
|---|---|---|
| Process memory dump while unlocked | blocks | blocks (unchanged) |
| Stolen vault file + extracted disk | nothing protects this | TPM-bound, uncrackable without the chip |
| Boot-chain tampering (rootkit replaces kernel) | invisible | PCR sealing refuses to release the wrap key (opt-in, future) |
| Brute-force on the wrap | Argon2id slows it | TPM dictionary-attack lockout makes it infeasible |

LUKSbox keeps `memfd_secret` for the unlocked MVK in RAM AND uses
TPM for the at-rest wrap. Both layers active.

## Design notes

- **Wrap-only architecture.** Per-chunk decryption stays in-process
  under the unwrapped MVK at full AES-NI speed (~590 MB/s). The
  TPM only handles the slow unwrap step at unlock time.
- **Storage Root Key is transient.** We re-derive the SRK from the
  TPM's persistent endorsement seed at every operation rather than
  persisting a handle. Same approach as `systemd-cryptenroll`. No
  TPM NV space consumed.
- **No PCR sealing in v1.** Empty policy means any caller on this
  TPM can unseal. PCR sealing is opt-in for v2 (needs PCR-policy-
  signing for kernel-update tolerance); see
  `docs/TPM_FUTURE_IMPROVEMENTS.md` section 3.
- **PIN via TPM userAuth** (`seal_with_pin` / `unseal_with_pin`):
  wrong PINs count toward the chip's dictionary-attack lockout, so
  even short PINs are secure on the original hardware.
- **Version pins**: `tss-esapi = "=8.0.0-alpha.2"` together with a
  deliberate direct pin `tss-esapi-sys = "=0.6.0-alpha.2"` - see
  the Cargo.toml comments and `docs/TPM_FUTURE_IMPROVEMENTS.md`
  section 1 for why the -sys pin must not be dropped until
  tss-esapi 8.0 stable lands.

## Testing

```bash
# Pure-Rust unit + mock adversary tests (no TPM required):
cargo test -p luksbox-tpm

# Linux: full seal/unseal loop against the swtpm emulator
# (skips cleanly when `swtpm` is not on PATH):
cargo test -p luksbox-tpm --features hardware

# Any platform with a real chip: live round-trip smoke
cargo run -p luksbox-tpm --features bundled-tpm --example tpm_smoke
```
