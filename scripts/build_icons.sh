#!/usr/bin/env bash
#
# Generate platform-specific icon files from the source PNG.
#
# Inputs:
#   crates/luksbox-gui/assets/icon.png         (source, 512x512 RGBA)
#
# Outputs:
#   crates/luksbox-gui/assets/icon.ico         (multi-size Windows icon,
#                                               consumed by build.rs +
#                                               winresource for the .exe)
#   crates/luksbox-gui/assets/icon.icns        (multi-size macOS icon,
#                                               consumed by the .app
#                                               bundle step in CI)
#   crates/luksbox-gui/assets/icons-linux/<N>x<N>.png  (per-size PNGs
#                                               for the Linux hicolor
#                                               theme, consumed by
#                                               dist/install.sh)
#
# All outputs are .gitignored, run this script after editing icon.png
# (or let CI run it before each build).
#
# Required tooling:
#   - ImageMagick 7+ (the `magick` command). On older systems falls
#     back to the legacy `convert` binary.
#   - For macOS .icns generation we prefer Apple's `iconutil` if we're
#     running on macOS (produces the cleanest output Apple's Finder
#     accepts), and fall back to ImageMagick's ICNS writer everywhere
#     else.
#
# Idempotent, safe to re-run.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASSETS_DIR="${REPO_ROOT}/crates/luksbox-gui/assets"
SRC_PNG="${ASSETS_DIR}/icon.png"
OUT_ICO="${ASSETS_DIR}/icon.ico"
OUT_ICNS="${ASSETS_DIR}/icon.icns"

log() { printf '==> %s\n' "$*" >&2; }

if [[ ! -f "${SRC_PNG}" ]]; then
    log "source PNG not found: ${SRC_PNG}"
    exit 1
fi

# Pick whichever ImageMagick binary is available. v7 ships `magick`,
# Debian/Ubuntu's older v6 only has `convert`/`identify`.
if command -v magick >/dev/null 2>&1; then
    IM=(magick)
elif command -v convert >/dev/null 2>&1; then
    IM=(convert)
else
    log "ImageMagick not found, install with one of:"
    log "  apt install imagemagick      # Debian/Ubuntu"
    log "  brew install imagemagick     # macOS"
    log "  choco install imagemagick    # Windows"
    exit 1
fi

# ---- Windows .ico --------------------------------------------------------
#
# Windows Explorer / Alt-Tab / taskbar pick the best size from the
# .ico's embedded sizes at runtime. The classic set is 16/32/48/256;
# Win10+ also asks for 24/64/128 in places. We give it everything
# under 256 so HiDPI title bars look crisp.
log "writing ${OUT_ICO}"
"${IM[@]}" "${SRC_PNG}" \
    -define icon:auto-resize=256,128,64,48,32,24,16 \
    "${OUT_ICO}"

# ---- macOS .icns ---------------------------------------------------------
#
# Apple's iconutil produces .icns from an .iconset directory. It only
# exists on macOS, so on Linux/Windows runners we fall back to
# ImageMagick's ICNS writer (good enough for Finder + Dock + Launchpad,
# fails to embed the high-quality sips-resized variants Apple's tool
# produces, but the visual difference is invisible at typical sizes).
if [[ "$(uname -s)" == "Darwin" ]] && command -v iconutil >/dev/null 2>&1; then
    log "writing ${OUT_ICNS} via iconutil (preferred on macOS)"
    ICONSET_DIR="$(mktemp -d)/icon.iconset"
    mkdir -p "${ICONSET_DIR}"
    # The size+@scale naming is mandated by iconutil; deviation = silent
    # rejection of that size from the resulting .icns.
    "${IM[@]}" "${SRC_PNG}" -resize 16x16     "${ICONSET_DIR}/icon_16x16.png"
    "${IM[@]}" "${SRC_PNG}" -resize 32x32     "${ICONSET_DIR}/icon_16x16@2x.png"
    "${IM[@]}" "${SRC_PNG}" -resize 32x32     "${ICONSET_DIR}/icon_32x32.png"
    "${IM[@]}" "${SRC_PNG}" -resize 64x64     "${ICONSET_DIR}/icon_32x32@2x.png"
    "${IM[@]}" "${SRC_PNG}" -resize 128x128   "${ICONSET_DIR}/icon_128x128.png"
    "${IM[@]}" "${SRC_PNG}" -resize 256x256   "${ICONSET_DIR}/icon_128x128@2x.png"
    "${IM[@]}" "${SRC_PNG}" -resize 256x256   "${ICONSET_DIR}/icon_256x256.png"
    "${IM[@]}" "${SRC_PNG}" -resize 512x512   "${ICONSET_DIR}/icon_256x256@2x.png"
    "${IM[@]}" "${SRC_PNG}" -resize 512x512   "${ICONSET_DIR}/icon_512x512.png"
    # icon_512x512@2x would be 1024x1024, bigger than our source (512),
    # so we let ImageMagick upscale it. Fine in practice, the @2x slot
    # is rarely hit on consumer Macs.
    "${IM[@]}" "${SRC_PNG}" -resize 1024x1024 "${ICONSET_DIR}/icon_512x512@2x.png"
    iconutil -c icns -o "${OUT_ICNS}" "${ICONSET_DIR}"
    rm -rf "$(dirname "${ICONSET_DIR}")"
else
    log "writing ${OUT_ICNS} via ImageMagick (iconutil unavailable)"
    "${IM[@]}" "${SRC_PNG}" \
        -define icns:formats=ic09,ic08,ic07,ic13,ic12,ic11 \
        "${OUT_ICNS}"
fi

# ---- Linux hicolor PNGs --------------------------------------------------
#
# GNOME / KDE / Xfce all read from $XDG_DATA_DIRS/icons/hicolor/<size>/apps/.
# Shipping only 256 means the menu (16/24/32px), the title bar (24-48px),
# and Activities (256/512px) all hit the same source and downscale on the
# fly, blurry on HiDPI. We pre-render the canonical set once and let the
# install.sh drop each into its matching size directory.
LINUX_DIR="${ASSETS_DIR}/icons-linux"
log "writing per-size Linux PNGs to ${LINUX_DIR}"
rm -rf "${LINUX_DIR}"
mkdir -p "${LINUX_DIR}"
for size in 16 24 32 48 64 128 256 512; do
    "${IM[@]}" "${SRC_PNG}" -resize "${size}x${size}" \
        "${LINUX_DIR}/${size}x${size}.png"
done

log "done"
log "  ico         : $(stat -c '%s bytes' "${OUT_ICO}" 2>/dev/null || stat -f '%z bytes' "${OUT_ICO}")"
log "  icns        : $(stat -c '%s bytes' "${OUT_ICNS}" 2>/dev/null || stat -f '%z bytes' "${OUT_ICNS}")"
log "  linux pngs  : ${LINUX_DIR}/{16,24,32,48,64,128,256,512}x*.png"
