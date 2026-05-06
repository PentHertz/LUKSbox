#!/usr/bin/env bash
#
# Per-user (or system-wide) install for the LUKSbox Linux release.
#
#   ./install.sh                # install to ~/.local
#   ./install.sh --system       # install to /usr/local + /usr/share (sudo)
#   ./install.sh --uninstall    # remove from per-user locations
#   ./install.sh --uninstall --system
#
# Optional flags (interactive by default; explicit overrides for CI):
#   --tpm-setup                 # offer to add user to `tss` group + udev rule
#   --no-tpm-setup              # skip the TPM permission prompt entirely
#
# Idempotent. Re-running overwrites previously-installed files.
#
# What gets installed
#   - luksbox + luksbox-gui              -> bin/
#   - com.penthertz.luksbox.desktop      -> share/applications/
#   - com.penthertz.luksbox.png (each)   -> share/icons/hicolor/{16,24,32,...}/apps/
#   - com.penthertz.luksbox.xml          -> share/mime/packages/   (registers .lbx)
#   - install.manifest                   -> ~/.local/share/luksbox/  (uninstall record)
#
# Optionally (with consent):
#   - adds $USER to the `tss` group (creates the group if missing)
#   - writes /etc/udev/rules.d/60-tpm.rules so `tpmrm0` is `tss`-readable
#
# Exit codes
#   0  success
#   1  unsupported OS / bad usage
#   2  missing required runtime dependency the script can't auto-install
#   3  partial install (binary copy failed)

set -euo pipefail

# ---- preflight ----------------------------------------------------------

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "==> error: this installer is Linux-only (detected $(uname -s))" >&2
    echo "    macOS users: drag LUKSbox.app into /Applications instead." >&2
    echo "    Windows users: run luksbox-gui.exe from the unzipped folder." >&2
    exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

UNINSTALL=0
SYSTEM=0
# TPM setup tristate: 'auto' = prompt interactively if a TPM is present,
# 'force' = run setup non-interactively, 'skip' = never run.
TPM_SETUP="auto"
for arg in "$@"; do
    case "$arg" in
        --system)        SYSTEM=1 ;;
        --uninstall)     UNINSTALL=1 ;;
        --tpm-setup)     TPM_SETUP="force" ;;
        --no-tpm-setup)  TPM_SETUP="skip" ;;
        -h|--help)
            cat <<USAGE
usage: $0 [--system] [--uninstall] [--tpm-setup|--no-tpm-setup]

  --system          install to /usr/local (sudo) instead of \$HOME/.local
  --uninstall       remove the previous install (combine with --system to
                    remove a system-wide install)
  --tpm-setup       run the TPM permission setup non-interactively
                    (skips the prompt; assumes consent for the udev rule
                    and group membership; intended for CI / Ansible)
  --no-tpm-setup    never offer TPM permission setup, even if a TPM is
                    present (intended for headless / non-TPM workflows)
USAGE
            exit 0 ;;
        *)
            echo "usage: $0 [--system] [--uninstall] [--tpm-setup|--no-tpm-setup]" >&2
            exit 1 ;;
    esac
done

if (( SYSTEM )); then
    BIN_DIR="/usr/local/bin"
    APPS_DIR="/usr/local/share/applications"
    ICON_BASE="/usr/local/share/icons/hicolor"
    MIME_DIR="/usr/local/share/mime/packages"
    MANIFEST_DIR="/usr/local/share/luksbox"
    SUDO="sudo"
else
    BIN_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
    APPS_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
    ICON_BASE="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor"
    MIME_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/mime/packages"
    MANIFEST_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/luksbox"
    SUDO=""
fi

ICON_SIZES=(16 24 32 48 64 128 256 512)

# ---- uninstall path ----------------------------------------------------

if (( UNINSTALL )); then
    echo "==> removing LUKSbox from:"
    echo "    bin    : ${BIN_DIR}"
    echo "    apps   : ${APPS_DIR}"
    echo "    icons  : ${ICON_BASE}/<size>/apps/"
    echo "    mime   : ${MIME_DIR}"

    $SUDO rm -f "${BIN_DIR}/luksbox" "${BIN_DIR}/luksbox-gui"
    # Cover both the new reverse-DNS name and the old short name so an
    # upgrade-then-uninstall doesn't leave stale entries behind.
    $SUDO rm -f "${APPS_DIR}/com.penthertz.luksbox.desktop" \
                "${APPS_DIR}/luksbox.desktop"
    for size in "${ICON_SIZES[@]}"; do
        $SUDO rm -f "${ICON_BASE}/${size}x${size}/apps/com.penthertz.luksbox.png" \
                    "${ICON_BASE}/${size}x${size}/apps/luksbox.png"
    done
    $SUDO rm -f "${MIME_DIR}/com.penthertz.luksbox.xml"
    $SUDO rm -rf "${MANIFEST_DIR}"

    # Refresh caches so the entry actually disappears in the active session.
    if command -v update-desktop-database >/dev/null 2>&1; then
        $SUDO update-desktop-database "${APPS_DIR}" 2>/dev/null || true
    fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        $SUDO gtk-update-icon-cache "${ICON_BASE}" 2>/dev/null || true
    fi
    if command -v update-mime-database >/dev/null 2>&1; then
        $SUDO update-mime-database "$(dirname "${MIME_DIR}")" 2>/dev/null || true
    fi
    echo "==> done"
    exit 0
fi

# ---- version banner ----------------------------------------------------

# Pull the version from the binary itself so the banner can never lie
# about what's about to be installed. --version is cheap (no FIDO probe,
# no container open).
if [[ -x "${HERE}/luksbox" ]]; then
    LUKSBOX_VERSION="$("${HERE}/luksbox" --version 2>/dev/null \
        | head -n 1 \
        | awk '{print $NF}' \
        || echo unknown)"
else
    LUKSBOX_VERSION="(binary missing!)"
fi

cat <<BANNER
==> Installing LUKSbox ${LUKSBOX_VERSION}
    target  : $([[ -n "$SUDO" ]] && echo "system-wide (/usr/local)" || echo "per-user (\$HOME/.local)")
    bin     : ${BIN_DIR}
    apps    : ${APPS_DIR}
    icons   : ${ICON_BASE}/<size>/apps/
    mime    : ${MIME_DIR}
BANNER

# ---- runtime-dep check -------------------------------------------------
#
# luksbox links libfido2 (always) and libfuse3 (when built with the fuse
# feature). If they're not on the box, the binary aborts at startup with
# "error while loading shared libraries: ...". We catch that here and
# print the right install command for the detected distro.

detect_pkg_install_cmd() {
    if command -v apt >/dev/null 2>&1; then
        echo "sudo apt install"
    elif command -v dnf >/dev/null 2>&1; then
        echo "sudo dnf install"
    elif command -v pacman >/dev/null 2>&1; then
        echo "sudo pacman -S"
    elif command -v zypper >/dev/null 2>&1; then
        echo "sudo zypper install"
    elif command -v apk >/dev/null 2>&1; then
        echo "sudo apk add"
    fi
}

# Maps a missing soname to (package per pkg-manager).
suggest_pkg_for() {
    local soname="$1"
    case "$soname" in
        libfido2.so.*)
            echo "apt:libfido2-1 dnf:libfido2 pacman:libfido2 zypper:libfido2 apk:libfido2"
            ;;
        libfuse3.so.*)
            echo "apt:libfuse3-3 dnf:fuse3-libs pacman:fuse3 zypper:fuse3 apk:fuse3"
            ;;
        libgtk-3.so.*)
            echo "apt:libgtk-3-0 dnf:gtk3 pacman:gtk3 zypper:gtk3 apk:gtk+3.0"
            ;;
        *)
            echo ""
            ;;
    esac
}

if command -v ldd >/dev/null 2>&1; then
    missing="$(ldd "${HERE}/luksbox" 2>/dev/null | awk '/not found/ {print $1}' || true)"
    missing+=" $(ldd "${HERE}/luksbox-gui" 2>/dev/null | awk '/not found/ {print $1}' || true)"
    missing="$(echo "$missing" | tr ' ' '\n' | sort -u | grep -v '^$' || true)"
    if [[ -n "$missing" ]]; then
        echo
        echo "==> warning: missing runtime libraries detected:"
        for so in $missing; do
            echo "    - $so"
        done
        echo
        echo "    Install them with one of:"
        # Try to guess the right command for the user's distro.
        pm_cmd="$(detect_pkg_install_cmd || true)"
        for so in $missing; do
            mapping="$(suggest_pkg_for "$so")"
            if [[ -n "$mapping" ]] && [[ -n "$pm_cmd" ]]; then
                # Pick the package matching the detected pkg manager.
                pm_short="${pm_cmd%% *}"  # strip "sudo "
                pm_short="${pm_short##*/}"
                pkg="$(echo "$mapping" | tr ' ' '\n' \
                    | grep "^${pm_short##sudo }:" \
                    | cut -d: -f2 || true)"
                [[ -n "$pkg" ]] && echo "      $pm_cmd $pkg     # for $so"
            fi
        done
        echo
        echo "    Then re-run this installer. Continuing anyway (installs"
        echo "    the binaries; they just won't run until the libs are present)."
        echo
    fi
else
    echo "==> warning: ldd not found, skipping runtime-dep check" >&2
fi

# ---- install -----------------------------------------------------------

$SUDO install -d "${BIN_DIR}" "${APPS_DIR}" "${MIME_DIR}" "${MANIFEST_DIR}"

# Binaries.
$SUDO install -m 0755 "${HERE}/luksbox"     "${BIN_DIR}/luksbox"     || exit 3
$SUDO install -m 0755 "${HERE}/luksbox-gui" "${BIN_DIR}/luksbox-gui" || exit 3

# .desktop launcher. Reverse-DNS filename matches the GUI's app_id so
# Wayland compositors can resolve the window's app_id to this entry
# (otherwise the title bar reads "com.penthertz.luksbox" instead of
# "LUKSbox").
$SUDO install -m 0644 "${HERE}/share/applications/com.penthertz.luksbox.desktop" \
                      "${APPS_DIR}/com.penthertz.luksbox.desktop"

# Icons, one per hicolor size dir. Themes prefer the closest exact size
# over downscaling, so shipping all sizes keeps menus crisp at every DPI.
for size in "${ICON_SIZES[@]}"; do
    src="${HERE}/share/icons/hicolor/${size}x${size}/apps/com.penthertz.luksbox.png"
    if [[ -f "$src" ]]; then
        dst="${ICON_BASE}/${size}x${size}/apps"
        $SUDO install -d "$dst"
        $SUDO install -m 0644 "$src" "$dst/com.penthertz.luksbox.png"
    fi
done

# MIME type for *.lbx so file managers offer "Open with LUKSbox" on
# right-click. The XML magic-matches the LUKSBOX1 header so files
# without the .lbx extension still get recognised.
$SUDO install -m 0644 "${HERE}/share/mime/packages/com.penthertz.luksbox.xml" \
                      "${MIME_DIR}/com.penthertz.luksbox.xml"

# Manifest, used by --uninstall in case the layout ever changes (also
# nice for "what version do I have installed" forensics).
{
    echo "version=${LUKSBOX_VERSION}"
    echo "installed_at=$(date -Iseconds)"
    echo "system_wide=$([[ -n "$SUDO" ]] && echo yes || echo no)"
    echo "bin=${BIN_DIR}"
    echo "apps=${APPS_DIR}"
    echo "icon_base=${ICON_BASE}"
    echo "mime=${MIME_DIR}"
} | $SUDO tee "${MANIFEST_DIR}/install.manifest" >/dev/null

# ---- refresh caches ----------------------------------------------------

if command -v update-desktop-database >/dev/null 2>&1; then
    $SUDO update-desktop-database "${APPS_DIR}" 2>/dev/null || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    $SUDO gtk-update-icon-cache "${ICON_BASE}" 2>/dev/null || true
fi
if command -v update-mime-database >/dev/null 2>&1; then
    $SUDO update-mime-database "$(dirname "${MIME_DIR}")" 2>/dev/null || true
fi

# ---- optional TPM permission setup -------------------------------------
#
# LUKSbox's TPM 2.0 keyslots talk to /dev/tpmrm0. The kernel's resource
# manager is designed for unprivileged use, but the device node ships
# owned by `root:tss` mode 0660 — so the user has to be in the `tss`
# group. Most desktop distros add the desktop user automatically; minimal
# / server / immutable installs do not.
#
# We DON'T do this silently: group membership and udev rules are
# system-level changes that survive uninstall, so the user opts in
# explicitly. Running non-interactively (no TTY) defaults to skip;
# `--tpm-setup` forces yes, `--no-tpm-setup` forces no. See the full
# guide at docs/TPM_LINUX_PERMISSIONS.md.

setup_tpm_perms() {
    local tpm_dev="/dev/tpmrm0"

    # No TPM device node on this machine: nothing to set up.
    if [[ ! -e "$tpm_dev" ]]; then
        return 0
    fi

    # User can already read it: nothing to set up.
    if [[ -r "$tpm_dev" ]]; then
        echo
        echo "==> TPM 2.0 device ${tpm_dev}: already accessible to ${USER}"
        return 0
    fi

    # Skip if explicitly disabled, or if we're non-interactive and no
    # explicit force flag was given.
    if [[ "$TPM_SETUP" == "skip" ]]; then
        return 0
    fi
    if [[ "$TPM_SETUP" == "auto" ]] && [[ ! -t 0 ]]; then
        echo
        echo "==> TPM 2.0 device ${tpm_dev} present but not readable by ${USER}."
        echo "    Skipping setup (non-interactive run; pass --tpm-setup to enable,"
        echo "    or see docs/TPM_LINUX_PERMISSIONS.md to set up by hand)."
        return 0
    fi

    # Interactive prompt (auto mode + TTY). Default = yes; Enter accepts.
    if [[ "$TPM_SETUP" == "auto" ]]; then
        echo
        echo "==> TPM 2.0 detected at ${tpm_dev}, but ${USER} can't read it."
        echo "    LUKSbox can offer TPM-bound keyslots only if you can read"
        echo "    the device. The standard fix is:"
        echo "      - add ${USER} to the \`tss\` group (creating it if needed)"
        echo "      - install /etc/udev/rules.d/60-tpm.rules so the device"
        echo "        node is group-readable"
        echo "    Both require sudo. They survive uninstall (other TPM tools"
        echo "    use the same group)."
        echo
        read -r -p "    Proceed? [Y/n] " reply
        case "${reply:-Y}" in
            [Yy]*|"") ;;
            *)
                echo "    Skipping. Run with --tpm-setup later, or follow"
                echo "    docs/TPM_LINUX_PERMISSIONS.md to do it by hand."
                return 0
                ;;
        esac
    fi

    echo
    echo "==> setting up TPM permissions (this needs sudo)"

    # Create the group if missing. `--system` makes it a system group
    # (GID < 1000), matches the convention from tpm2-tss packaging.
    if ! getent group tss >/dev/null 2>&1; then
        echo "    creating system group \`tss\`..."
        if ! sudo groupadd --system tss; then
            echo "==> error: groupadd failed; aborting TPM setup" >&2
            return 0  # Don't fail the whole install.
        fi
    fi

    # Add the invoking user to the group.
    if ! id -nG "$USER" | tr ' ' '\n' | grep -qx tss; then
        echo "    adding ${USER} to \`tss\` group..."
        if ! sudo usermod -aG tss "$USER"; then
            echo "==> error: usermod failed; aborting TPM setup" >&2
            return 0
        fi
    fi

    # Install the udev rule (idempotent — overwrite on re-run is safe).
    local udev_rule="/etc/udev/rules.d/60-tpm.rules"
    echo "    installing ${udev_rule}..."
    sudo tee "$udev_rule" >/dev/null <<'EOF'
# Installed by the LUKSbox installer. Allows members of the `tss` group
# to use the TPM 2.0 device nodes without root. See
# docs/TPM_LINUX_PERMISSIONS.md for context.
KERNEL=="tpm[0-9]*",   GROUP="tss", MODE="0660"
KERNEL=="tpmrm[0-9]*", GROUP="tss", MODE="0660"
EOF
    sudo chmod 0644 "$udev_rule"

    # Reload + retrigger so the change applies without reboot.
    if command -v udevadm >/dev/null 2>&1; then
        sudo udevadm control --reload-rules 2>/dev/null || true
        sudo udevadm trigger /dev/tpm* /dev/tpmrm* 2>/dev/null || true
    fi

    echo
    echo "==> TPM permission setup done."
    echo "    You MUST log out + log back in (or reboot) for the new \`tss\`"
    echo "    group membership to take effect in your session. Verify with:"
    echo "      id -nG | tr ' ' '\\n' | grep -x tss"
    echo "      tpm2_getrandom 16 --hex     # without sudo"
}

setup_tpm_perms

echo
echo "==> done"
echo "    Run 'luksbox --help' or launch LUKSbox from your application menu."
echo "    Double-clicking a .lbx file in Files / Dolphin will also open it."

# Helpful PATH hint, only if we installed per-user and ~/.local/bin
# isn't already on PATH.
if (( ! SYSTEM )) && ! echo ":$PATH:" | grep -q ":${BIN_DIR}:"; then
    cat <<HINT

    Note: ${BIN_DIR} is not on your PATH. Add this to ~/.bashrc:
        export PATH="\$HOME/.local/bin:\$PATH"
    or to ~/.zshrc / ~/.config/fish/config.fish for those shells.
HINT
fi
