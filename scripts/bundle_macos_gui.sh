#!/usr/bin/env bash
# Package luksbox-gui into a macOS .app bundle.
#
# WHY THIS EXISTS: the Secure Enclave *biometric* keyslot
# (`--kind sep-biometric`) prompts for Touch ID via LocalAuthentication.
# A bare CLI/binary cannot present that UI (fails with LAError -4); a
# proper .app bundle whose Info.plist carries `NSFaceIDUsageDescription`
# CAN -- and this works under plain ad-hoc signing, no paid Apple
# Developer identity required (verified on Apple M2, 2026-06-18). All
# the non-biometric SEP kinds already work from the CLI; this bundle is
# what makes the biometric one usable.
#
# Usage:
#   scripts/bundle_macos_gui.sh                 # release build, ad-hoc signed
#   scripts/bundle_macos_gui.sh --debug         # reuse the debug build (fast)
#   scripts/bundle_macos_gui.sh --sign "Developer ID Application: ..."  # real signing
#   scripts/bundle_macos_gui.sh --out dist      # output dir (default: dist)
#
# For DISTRIBUTION (Gatekeeper-friendly download) you still need to sign
# with a Developer ID identity and notarize -- pass --sign and run
# `xcrun notarytool` afterward. Ad-hoc is sufficient for local use and
# for the biometric capability itself.
set -euo pipefail

cd "$(dirname "$0")/.."

PROFILE="release"
PROFILE_FLAG="--release"
SIGN_ID="-"          # ad-hoc by default
OUT_DIR="dist"
FEATURES="hardware,fuse-t"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --debug)   PROFILE="debug";   PROFILE_FLAG="";        shift ;;
        --sign)    SIGN_ID="$2";                              shift 2 ;;
        --out)     OUT_DIR="$2";                              shift 2 ;;
        --features) FEATURES="$2";                            shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 64 ;;
    esac
done

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "error: this script must run on macOS (needs swiftc + codesign)." >&2
    exit 1
fi

VERSION="$(grep -m1 '^version' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
APP="$OUT_DIR/LUKSbox.app"
CONTENTS="$APP/Contents"

echo "==> building luksbox-gui ($PROFILE, --features $FEATURES)"
cargo build -p luksbox-gui $PROFILE_FLAG --no-default-features --features "$FEATURES"

BIN="target/$PROFILE/luksbox-gui"
[[ -x "$BIN" ]] || { echo "error: $BIN not found" >&2; exit 1; }

echo "==> assembling $APP"
rm -rf "$APP"
mkdir -p "$CONTENTS/MacOS" "$CONTENTS/Resources"
cp "$BIN" "$CONTENTS/MacOS/luksbox-gui"

# Best-effort icon: convert the PNG to .icns if the tooling is present.
ICON_KEY=""
SRC_ICON="crates/luksbox-gui/assets/icon.png"
if [[ -f "$SRC_ICON" ]] && command -v sips >/dev/null && command -v iconutil >/dev/null; then
    ICONSET="$(mktemp -d)/AppIcon.iconset"; mkdir -p "$ICONSET"
    for sz in 16 32 64 128 256 512; do
        sips -z $sz $sz       "$SRC_ICON" --out "$ICONSET/icon_${sz}x${sz}.png"        >/dev/null 2>&1 || true
        sips -z $((sz*2)) $((sz*2)) "$SRC_ICON" --out "$ICONSET/icon_${sz}x${sz}@2x.png" >/dev/null 2>&1 || true
    done
    if iconutil -c icns "$ICONSET" -o "$CONTENTS/Resources/AppIcon.icns" 2>/dev/null; then
        ICON_KEY='<key>CFBundleIconFile</key><string>AppIcon</string>'
    fi
fi

cat > "$CONTENTS/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>luksbox-gui</string>
  <key>CFBundleIdentifier</key><string>com.penthertz.luksbox</string>
  <key>CFBundleName</key><string>LUKSbox</string>
  <key>CFBundleDisplayName</key><string>LUKSbox</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
  $ICON_KEY
  <!-- Required for the Secure Enclave biometric keyslot (Touch ID). -->
  <key>NSFaceIDUsageDescription</key>
  <string>LUKSbox uses Touch ID to unlock vault keyslots bound to the Secure Enclave.</string>
</dict></plist>
PLIST

echo "==> signing ($([[ "$SIGN_ID" == "-" ]] && echo ad-hoc || echo "$SIGN_ID"))"
codesign --force --options runtime --sign "$SIGN_ID" "$APP"
codesign --verify --deep --strict "$APP" && echo "    signature verified"

echo "==> done: $APP (version $VERSION)"
echo "    Launch it (Finder double-click or \`open $APP\`); the Secure Enclave"
echo "    biometric keyslot will prompt for Touch ID. For a downloadable build,"
echo "    re-sign with a Developer ID identity (--sign) and notarize."
