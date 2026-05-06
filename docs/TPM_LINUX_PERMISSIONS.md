# TPM 2.0 access without root (Linux)

LUKSbox's TPM-bound keyslots talk to the kernel's TPM resource manager
at `/dev/tpmrm0`. Out of the box that device is owned by `root:tss`
mode `0660`, so any unprivileged user who is **a member of the `tss`
group** can use it. You should NOT need to run `luksbox` or
`luksbox-gui` as root.

This doc covers:

1. [Quick check](#quick-check) — am I already set up?
2. [The standard fix](#standard-fix-add-yourself-to-the-tss-group) —
   add yourself to the `tss` group.
3. [Distros without a `tss` group](#distros-without-a-tss-group) —
   write a udev rule.
4. [Verifying the fix](#verifying-the-fix).
5. [Common errors and what they mean](#common-errors).
6. [Containers and Flatpak / Snap notes](#containers-and-sandboxes).
7. [Why not just `sudo`?](#why-not-just-sudo)

---

## Quick check

```bash
ls -l /dev/tpmrm0      # should print:  crw-rw---- 1 root tss ...
id -nG | tr ' ' '\n' | grep -x tss   # should print: tss
```

If both succeed, you're done — close this doc and use LUKSbox normally.

If the first command says **"No such file or directory"**, your
machine doesn't expose a TPM 2.0 device. That's not a permission
issue — see
[`SECURITY.md`](../SECURITY.md) for non-TPM keyslot options
(passphrase, FIDO2, hybrid-PQ).

If the first command shows a different group (e.g. `root root`) or
the second command prints nothing, follow the next section.

---

## Standard fix: add yourself to the `tss` group

Most desktop distros (Debian/Ubuntu/Mint, Fedora/RHEL/Rocky, Arch,
openSUSE) auto-create a `tss` group when you install the
`tpm2-tss` package. The group exists; you're just not in it.

```bash
sudo usermod -aG tss "$USER"
```

The change takes effect at your **next login session**. Either:

- Log out of your desktop and back in, OR
- Open a fresh terminal and run `newgrp tss` (limited to that shell), OR
- Reboot.

Verify:

```bash
id -nG | tr ' ' '\n' | grep -x tss   # must print 'tss'
```

If `tss` is in your groups but `/dev/tpmrm0` STILL refuses access:
your distro's udev rules may not chgrp the node correctly. Skip to
[Distros without a `tss` group](#distros-without-a-tss-group) and
install the udev rule manually.

---

## Distros without a `tss` group

Some minimal / server / immutable installs don't ship the `tss`
group. Two options:

### Option A — create the group + udev rule (recommended)

```bash
# Create the group if it doesn't exist
getent group tss >/dev/null || sudo groupadd --system tss

# Add yourself to it
sudo usermod -aG tss "$USER"

# Tell udev to chgrp the device node on every boot
sudo tee /etc/udev/rules.d/60-tpm.rules >/dev/null <<'EOF'
# LUKSbox / tpm2-tss: allow members of the `tss` group to use the
# TPM 2.0 resource manager at /dev/tpmrm0 (and the raw device at
# /dev/tpm0 for tools like tpm2_getrandom).
KERNEL=="tpm[0-9]*",   GROUP="tss", MODE="0660"
KERNEL=="tpmrm[0-9]*", GROUP="tss", MODE="0660"
EOF

# Apply without reboot
sudo udevadm control --reload-rules
sudo udevadm trigger /dev/tpm* /dev/tpmrm*
```

Then log out + back in.

### Option B — your own group (e.g. `wheel`)

Same as A but substitute the group name:

```bash
sudo tee /etc/udev/rules.d/60-tpm.rules >/dev/null <<'EOF'
KERNEL=="tpm[0-9]*",   GROUP="wheel", MODE="0660"
KERNEL=="tpmrm[0-9]*", GROUP="wheel", MODE="0660"
EOF
sudo udevadm control --reload-rules
sudo udevadm trigger /dev/tpm* /dev/tpmrm*
```

Wider audience access, slightly looser security posture. Stick with
`tss` if you can.

---

## Verifying the fix

The cleanest end-to-end check is to talk to the chip without
LUKSbox:

```bash
# Most distros ship tpm2_getrandom in `tpm2-tools`
sudo apt install tpm2-tools     # Debian/Ubuntu
sudo dnf install tpm2-tools     # Fedora/RHEL
sudo pacman -S tpm2-tools       # Arch

tpm2_getrandom 16 --hex
```

If that prints 32 hex chars and exits 0, **without sudo**, your
unprivileged TPM access is working. LUKSbox will work too.

If it fails with **"could not open device /dev/tpmrm0: Permission
denied"**, double-check `id -nG` includes `tss` AND that you've
opened a fresh shell since `usermod`.

---

## Common errors

| What you see | Meaning | Fix |
|---|---|---|
| `Tpm2 device not available: Permission denied (os error 13)` | `/dev/tpmrm0` exists, your user can't read it | `sudo usermod -aG tss "$USER"`, log out + back in |
| `Tpm2 device not available: No such file or directory` | No TPM 2.0 device node on this machine | Check BIOS/UEFI; enable "TPM 2.0 / fTPM / PTT". On a VM, attach a virtual TPM |
| `failed to load TCTI: tcti-device... Could not initialize TCTI` | The `tpm2-tss` runtime libraries are missing | `sudo apt install libtss2-tcti-device0` (Debian/Ubuntu) or equivalent |
| `TPM_RC_LOCKOUT` | Wrong PINs triggered the chip's dictionary-attack lockout | Wait the lockout interval (typically minutes to hours), or `tpm2_dictionarylockout --clear-lockout` if you have the lockout authorization |
| `TPM_RC_INITIALIZE` | The TPM hasn't been started by the kernel | Reboot. Some BIOSes leave the TPM in a half-initialized state |

---

## Containers and sandboxes

### Docker / Podman

The TPM device must be passed in explicitly:

```bash
docker run --device /dev/tpmrm0:/dev/tpmrm0 \
           --group-add "$(getent group tss | cut -d: -f3)" \
           luksbox-image
```

Use `--device`, not `--privileged`. Bind-mount the device, then add
the host's `tss` GID to the container so the in-container user can
read it. The container user does NOT need to be root.

### Flatpak

Flatpak's sandbox blocks `/dev/tpmrm0` by default. As an end user
you can grant it explicitly:

```bash
flatpak override --user --device=all com.example.LuksboxFlatpak
# or, more narrowly:
flatpak override --user --filesystem=/dev/tpmrm0 com.example.LuksboxFlatpak
```

Note: LUKSbox does not ship a Flatpak today; this is for if you
package it yourself.

### Snap

The default Snap confinement also blocks raw device access. The
`tpm` interface plug doesn't exist upstream yet; you'd need a
classic-confinement snap, which most stores reject. **Do not snap-
package LUKSbox without strict confinement.** A Flatpak or a plain
distro package is the recommended distribution channel on Linux.

### Toolbox / Distrobox / nspawn

These pass through `/dev/tpmrm0` by default if it exists on the
host. You still need the in-container user to be in `tss` (or the
GID-passthrough variant); the udev rule is on the host, not in the
container.

---

## Why not just `sudo`?

Running a vault tool as root is bad opsec:

1. **Wider blast radius on bugs.** A heap corruption in libfido2 or
   tss-esapi running as root can write anywhere on the system. As
   the regular user, the same bug at worst destroys your home dir.
2. **The kernel's resource manager is designed for unprivileged
   use.** That's the whole point of `/dev/tpmrm0` (vs. the raw
   `/dev/tpm0`): it serializes, isolates per-process state, and
   handles cleanup so multiple unprivileged tools can share the
   chip safely.
3. **`sudo` confounds the audit trail.** TPM operations done as
   root attribute to root in the system journal; you lose the
   "who unlocked the vault" signal.
4. **Mounting FUSE as root is wrong.** LUKSbox's mount helper uses
   FUSE's `user_allow_other` only when the FUSE mount is owned by
   the unlocking user; running as root breaks that ownership chain.

If your only blocker to using LUKSbox without sudo is TPM access,
the udev rule above is the right fix; it's how every other
TPM-using consumer tool (systemd-cryptenroll, ssh-tpm-agent,
tpm2-pkcs11) handles the same problem.

---

## Reference

- Kernel TPM resource manager:
  [`Documentation/security/tpm/tpm-security.rst`](https://www.kernel.org/doc/html/latest/security/tpm/tpm_event_log.html)
- `tpm2-tss` packaging notes (where the `tss` group convention
  comes from): [`tpm2-tss` INSTALL.md][tpm2-tss-install]
- LUKSbox TPM crate internals: [`crates/luksbox-tpm/README.md`](../crates/luksbox-tpm/README.md)
- Future improvements (PCR sealing, Windows TBS): [`docs/TPM_FUTURE_IMPROVEMENTS.md`](TPM_FUTURE_IMPROVEMENTS.md)

[tpm2-tss-install]: https://github.com/tpm2-software/tpm2-tss/blob/master/INSTALL.md
