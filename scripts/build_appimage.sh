#!/usr/bin/env bash
#
# build_appimage.sh - package a built luksbox-gui into an AppImage.
#
# A single-file GUI for Linux distributions the .deb / .rpm packages do
# not cover. Run on (or in a container of) the OLDEST distribution you
# want to support: an AppImage still uses the host's glibc, so build it
# where glibc is old (the release workflow uses Ubuntu 22.04, glibc 2.35).
#
# Bundled into the image: libfido2, libcbor and libcrypto (with their
# license files), resolved through an $ORIGIN rpath. NOT bundled, on
# purpose, they must come from the host: glibc, libudev (must match the
# host's udev; FIDO2 keys also need the host's udev rules, which every
# mainstream distro ships), zlib, and the graphics stack (OpenGL / EGL /
# Wayland / X11 are dlopen()ed by the GUI). `mount` needs the host's
# `fusermount3`. TPM 2.0 is the statically linked vendored tpm2-tss of a
# `bundled-tpm` build; its TCTI module is dlopen()ed from the host.
#
# The rpath (not LD_LIBRARY_PATH in a wrapper) keeps the bundled
# libraries out of the processes the GUI starts (xdg-open, the file
# manager, fusermount3), which would otherwise load them too.
#
# Usage:
#   scripts/build_appimage.sh --bin target/<triple>/release-hardened/luksbox-gui \
#       [--arch x86_64|aarch64] [--out DIR]
#
# Needs: ldd, patchelf, file, curl, sha256sum. Downloads appimagetool and
# the AppImage runtime at the pinned versions below and refuses them if
# the SHA-256 does not match (R15-J3: no unpinned third-party binaries in
# release artifacts).
#
# Output: <out>/luksbox-v<version>-<arch>.AppImage

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH="$(uname -m)"
BIN=""
OUT="$ROOT/dist-appimage"

# Pinned packaging tools (recorded from the upstream release assets on
# 2026-10-10; bump deliberately, together with the hashes).
APPIMAGETOOL_VERSION="1.9.1"
RUNTIME_VERSION="20251108"
declare -A APPIMAGETOOL_SHA256=(
    [x86_64]="ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0"
    [aarch64]="f0837e7448a0c1e4e650a93bb3e85802546e60654ef287576f46c71c126a9158"
)
declare -A RUNTIME_SHA256=(
    [x86_64]="2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d"
    [aarch64]="00cbdfcf917cc6c0ff6d3347d59e0ca1f7f45a6df1a428a0d6d8a78664d87444"
)

while [ $# -gt 0 ]; do
    case "$1" in
        --bin)  BIN="$2"; shift 2 ;;
        --arch) ARCH="$2"; shift 2 ;;
        --out)  OUT="$2"; shift 2 ;;
        -h|--help) sed -n '2,33p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
case "$ARCH" in
    x86_64|aarch64) ;;
    *) echo "unsupported --arch $ARCH (x86_64 or aarch64)" >&2; exit 2 ;;
esac
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "--bin must point at a built luksbox-gui" >&2; exit 2; }
VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/Cargo.toml" | head -1)"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fetch() { # url dest sha256
    curl -fsSL --retry 3 -o "$2" "$1"
    echo "$3  $2" | sha256sum -c - >/dev/null || {
        echo "error: SHA-256 mismatch for $1" >&2
        exit 1
    }
    chmod 0755 "$2"
}
TOOL="$WORK/appimagetool"
RUNTIME="$WORK/runtime"
fetch "https://github.com/AppImage/appimagetool/releases/download/$APPIMAGETOOL_VERSION/appimagetool-$ARCH.AppImage" \
    "$TOOL" "${APPIMAGETOOL_SHA256[$ARCH]}"
fetch "https://github.com/AppImage/type2-runtime/releases/download/$RUNTIME_VERSION/runtime-$ARCH" \
    "$RUNTIME" "${RUNTIME_SHA256[$ARCH]}"

APPDIR="$WORK/LUKSbox.AppDir"
install -Dm0755 "$BIN" "$APPDIR/usr/bin/luksbox-gui"
mkdir -p "$APPDIR/usr/lib" "$APPDIR/usr/share/licenses"

# Copy the allow-listed shared libraries (and, recursively, theirs).
bundle() {
    local soname path
    while read -r soname path; do
        case "$soname" in
            libfido2.so.*|libcbor.so.*|libcrypto.so.*) ;;
            *) continue ;;
        esac
        [ -e "$APPDIR/usr/lib/$soname" ] && continue
        cp -L "$path" "$APPDIR/usr/lib/$soname"
        chmod 0644 "$APPDIR/usr/lib/$soname"
        bundle "$APPDIR/usr/lib/$soname"
    done < <(ldd "$1" | awk '$2 == "=>" && $3 ~ /^\// { print $1, $3 }')
}
bundle "$APPDIR/usr/bin/luksbox-gui"
# shellcheck disable=SC2016 # a literal $ORIGIN is the point
for lib in "$APPDIR"/usr/lib/*.so.*; do
    [ -e "$lib" ] || continue
    patchelf --set-rpath '$ORIGIN' "$lib"
done
# shellcheck disable=SC2016
patchelf --set-rpath '$ORIGIN/../lib' "$APPDIR/usr/bin/luksbox-gui"

# Every bundled library must now resolve from inside the AppDir, and
# nothing may be missing.
LDD="$(ldd "$APPDIR/usr/bin/luksbox-gui")"
if grep -q 'not found' <<<"$LDD"; then
    echo "$LDD" >&2
    echo "error: unresolved shared libraries" >&2
    exit 1
fi
for lib in "$APPDIR"/usr/lib/*.so.*; do
    [ -e "$lib" ] || continue
    name="$(basename "$lib")"
    # ldd prints the path the loader built from the rpath, e.g.
    # .../usr/bin/../lib/libfido2.so.1, so compare canonical paths.
    resolved="$(awk -v n="$name" '$1 == n && $2 == "=>" { print $3 }' <<<"$LDD")"
    if [ -z "$resolved" ] || [ "$(realpath "$resolved")" != "$(realpath "$lib")" ]; then
        echo "$LDD" >&2
        echo "error: $name does not resolve from the AppDir" >&2
        exit 1
    fi
done

# License files of the bundled libraries (Debian / Ubuntu layout).
for pkg_doc in /usr/share/doc/libfido2-1 /usr/share/doc/libcbor0.8 /usr/share/doc/libssl3; do
    [ -f "$pkg_doc/copyright" ] &&
        cp "$pkg_doc/copyright" "$APPDIR/usr/share/licenses/$(basename "$pkg_doc").copyright"
done
cp "$ROOT/LICENSE" "$APPDIR/usr/share/licenses/LUKSbox.LICENSE"
cp "$ROOT/NOTICE" "$APPDIR/usr/share/licenses/LUKSbox.NOTICE"

# Desktop integration: the entry, icon and .lbx MIME type the packages
# install, in the places AppImage integrators (appimaged,
# AppImageLauncher, Gear Lever) look for them.
cp "$ROOT/dist/com.penthertz.luksbox.desktop" "$APPDIR/"
install -Dm0644 "$ROOT/dist/com.penthertz.luksbox.desktop" \
    "$APPDIR/usr/share/applications/com.penthertz.luksbox.desktop"
install -Dm0644 "$ROOT/crates/luksbox-gui/assets/icon.png" "$APPDIR/com.penthertz.luksbox.png"
install -Dm0644 "$ROOT/crates/luksbox-gui/assets/icon.png" \
    "$APPDIR/usr/share/icons/hicolor/512x512/apps/com.penthertz.luksbox.png"
install -Dm0644 "$ROOT/dist/com.penthertz.luksbox.xml" \
    "$APPDIR/usr/share/mime/packages/com.penthertz.luksbox.xml"
ln -s com.penthertz.luksbox.png "$APPDIR/.DirIcon"
ln -s usr/bin/luksbox-gui "$APPDIR/AppRun"

TARGET_FILE="$OUT/luksbox-v${VERSION}-${ARCH}.AppImage"
# appimagetool is itself an AppImage; extract-and-run avoids needing FUSE
# on the build machine (CI runners, containers).
APPIMAGE_EXTRACT_AND_RUN=1 ARCH="$ARCH" "$TOOL" --no-appstream \
    --runtime-file "$RUNTIME" "$APPDIR" "$TARGET_FILE"
file "$TARGET_FILE"
echo "wrote $TARGET_FILE"
