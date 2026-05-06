# luksbox-tpm

Linux TPM 2.0-backed wrap/unwrap of the LUKSbox Master Volume Key.
Foundation for the TPM-bound keyslot kind tracked in
[`SECURITY.md`](../../SECURITY.md) Tier 3 item 10.

## Status

Day-1 of the implementation roadmap. What ships in this commit:

- [x] `SealedBlob` on-disk format (length-prefixed
      `TPM2B_PUBLIC` + `TPM2B_PRIVATE`) with serde-free
      `to_bytes` / `from_bytes` helpers.
- [x] `Tpm2Sealer` API surface: `new()`, `from_tcti_str()`,
      `seal()`, `unseal()`.
- [x] `tss-esapi` 7.x integration in `src/real.rs`, gated on
      `--features hardware`.
- [x] No-hardware stub that returns `Error::NotCompiledIn` so
      downstream code compiles cleanly without `libtss2-dev`.
- [x] Pure-Rust unit tests for the blob format (5 tests, no TPM
      required).
- [ ] Integration tests against `swtpm` (Day 6 of the roadmap).
- [ ] Wired into `luksbox-core::SlotKind` (Day 2).
- [ ] CLI subcommand `luksbox enroll <vault> --tpm2` (Day 4).
- [ ] GUI integration (Day 5).

## Build prerequisites

The default build (`cargo build -p luksbox-tpm`) compiles only the
stub and works on any platform without extra deps.

The hardware build (`cargo build -p luksbox-tpm --features hardware`)
links against `libtss2-esys`, `libtss2-mu`, and `libtss2-sys`. You
need the **development** packages for those (the `.pc` files in
particular).

| Distro | Install command |
|---|---|
| Debian / Ubuntu / Mint | `sudo apt install libtss2-dev` |
| Fedora / RHEL / Rocky | `sudo dnf install tpm2-tss-devel` |
| Arch | `sudo pacman -S tpm2-tss` |
| Alpine | `sudo apk add tpm2-tss-dev` |
| NixOS | `nix-shell -p tpm2-tss pkg-config` |

Runtime: at run time you need only the runtime libraries (`libtss2-esys-3`
on Debian/Ubuntu, `tpm2-tss` on Fedora). These are usually pre-installed
on any system that has a TPM device node, and are listed as runtime
dependencies on the LUKSbox `.deb` / `.rpm` packages once the slot
integration lands.

## Permissions

Unprivileged use of `/dev/tpmrm0` (the kernel resource manager)
requires the user to be in the `tss` group on most distros, or to
have explicit udev rules granting access. Most desktop distros
auto-create the `tss` group and add the desktop user; on minimal /
server installs you may need to:

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
| Boot-chain tampering (rootkit replaces kernel) | invisible | PCR sealing refuses to release the wrap key (opt-in) |
| Brute-force on the wrap | Argon2id slows it | TPM dictionary-attack lockout makes it infeasible |

LUKSbox keeps `memfd_secret` for the unlocked MVK in RAM AND uses
TPM for the at-rest wrap. Both layers active.

## Design notes

- **Wrap-only architecture.** Per-chunk decryption stays in-process
  under the unwrapped MVK at full AES-NI speed (~590 MB/s). The
  TPM only handles the slow unwrap step at unlock time. Chunk
  encryption stays AES-256-GCM-SIV; the chip only sees AES-GCM
  for the wrap.
- **Storage Root Key is transient.** We re-derive the SRK from the
  TPM's persistent endorsement seed at every operation rather than
  persisting a handle. Same approach as `systemd-cryptenroll`. No
  TPM NV space consumed.
- **No PCR sealing in v1.** Empty policy means any caller on this
  TPM can unseal. PCR sealing is opt-in for v2 (needs PCR-policy-
  signing for kernel-update tolerance).
- **No userAuth in v1.** Sealed object has no PIN; possession of
  the chip is sufficient to unseal. PIN auth is opt-in for v2.

## Contributing

If you have access to a real TPM 2.0 chip and a Linux kernel >= 5.0,
the integration tests in `tests/swtpm.rs` (when they land in Day 6)
will exercise the full seal/unseal round-trip. Until then, manual
verification via `tpm2_tools`:

```bash
# Manual round-trip with our blob format
RUST_LOG=debug cargo run --features hardware --example seal_demo \
    --bin seal_demo -- --in /tmp/secret.bin --out /tmp/blob.dat
# (example/seal_demo.rs lands in Day 6)
```
