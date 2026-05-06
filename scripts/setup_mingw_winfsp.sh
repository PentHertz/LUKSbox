#!/usr/bin/env bash
#
# setup_mingw_winfsp.sh, fetch the official WinFsp .msi installer
# (winfsp/winfsp on GitHub), extract it on Linux via msitools, and
# stage the headers + import libraries under a local sysroot so
# scripts/build_release.sh --targets windows-amd64 can link the
# `mount` subcommand against the WinFsp SDK.
#
# WinFsp ships only a Windows MSI, no source release of the headers /
# .lib alone, so we go through msiextract. The MSI is ~2 MB and only
# contains user-mode SDK bits (no kernel driver gets installed on the
# Linux host, msiextract just unpacks files).
#
# Usage:
#   # one-shot: download/extract if needed, then emit env exports.
#   # designed for `source <(...)` so the env vars land in your shell:
#   source <(scripts/setup_mingw_winfsp.sh)
#
#   # explicit path:
#   source <(scripts/setup_mingw_winfsp.sh /custom/sysroot)
#
#   # pin a specific WinFsp version:
#   source <(scripts/setup_mingw_winfsp.sh --version 2.0.23075)
#
#   # only print the env vars, never download:
#   source <(scripts/setup_mingw_winfsp.sh --print-env)
#
# Then build:
#   scripts/build_release.sh --targets windows-amd64 --gui
#
# Prereqs: msitools (apt install msitools), curl. No root needed.
#
# Runtime caveat: the resulting luksbox.exe links the WinFsp import lib;
# end users still need the WinFsp 2.x kernel driver installed on the
# target Windows machine for `luksbox mount` to actually work
# (https://winfsp.dev/rel/). That's a one-time MSI install on the
# end-user side, it's not a luksbox concern.

set -euo pipefail

GH_REPO="winfsp/winfsp"
DEFAULT_VERSION=""   # empty = auto-detect latest stable from GitHub
SYSROOT=""
PRINT_ENV_ONLY=0

# All status output goes to stderr, so `source <(...)` only consumes
# the env exports we deliberately emit on stdout at the end.
log() { echo "$@" >&2; }

for arg in "$@"; do
    case "$arg" in
        --print-env) PRINT_ENV_ONLY=1 ;;
        --version)
            shift
            DEFAULT_VERSION="$1"
            ;;
        --version=*)
            DEFAULT_VERSION="${arg#--version=}"
            ;;
        -h|--help)
            sed -n '2,/^# Runtime caveat:/p' "$0" | sed 's/^# \{0,1\}//' >&2
            exit 0
            ;;
        *)
            SYSROOT="$arg"
            ;;
    esac
done

[[ -z "$SYSROOT" ]] && SYSROOT="$HOME/.cache/luksbox/winfsp"

# Locate inc/ and lib/ inside the unpacked MSI tree. Newer MSIs use
# "Program Files", older ones "Program Files (x86)".
locate_dirs() {
    local root="$1"
    for cand in "$root/extracted/Program Files (x86)/WinFsp/inc" \
                "$root/extracted/Program Files/WinFsp/inc"; do
        if [[ -f "$cand/winfsp/winfsp.h" ]]; then
            INC_DIR="$cand"
            LIB_DIR="${cand%/inc}/lib"
            return 0
        fi
    done
    return 1
}

emit_env() {
    cat <<EOF
export WINFSP_INC="$INC_DIR"
export WINFSP_LIB="$LIB_DIR"
EOF
}

# --- print-env-only path: bail out cleanly if not yet populated -----------

if [[ "$PRINT_ENV_ONLY" == "1" ]]; then
    if locate_dirs "$SYSROOT"; then
        emit_env
        exit 0
    fi
    log "error: $SYSROOT does not contain a populated WinFsp SDK; run setup first"
    exit 2
fi

# --- one-shot path: setup if needed, then emit env ------------------------

# Already populated? Skip everything, just print env.
if locate_dirs "$SYSROOT"; then
    log "==> WinFsp SDK already present at $SYSROOT"
    emit_env
    exit 0
fi

if ! command -v msiextract >/dev/null 2>&1; then
    log "error: msitools not installed (apt install msitools)"
    exit 2
fi
if ! command -v curl >/dev/null 2>&1; then
    log "error: curl not installed (apt install curl)"
    exit 2
fi

mkdir -p "$SYSROOT"
cd "$SYSROOT"

# Resolve version. If the user didn't pin one, ask GitHub for the latest
# release tag. Avoids depending on `jq` by grepping the Releases API JSON.
if [[ -z "$DEFAULT_VERSION" ]]; then
    log "==> querying github.com/$GH_REPO for latest release"
    DEFAULT_VERSION="$(
        curl -fsSL "https://api.github.com/repos/$GH_REPO/releases/latest" \
        | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"v[0-9.]+"' \
        | head -n1 \
        | sed -E 's/.*"v([0-9.]+)".*/\1/'
    )"
    if [[ -z "$DEFAULT_VERSION" ]]; then
        log "    error: couldn't parse latest release tag, pin one with --version 2.0.xxxxx"
        exit 1
    fi
    log "    latest is v$DEFAULT_VERSION"
fi

# WinFsp's MSI version naming differs from the git tag in some releases:
# tag `v2.0` corresponds to file `winfsp-2.0.23075.msi`. The
# release-page asset list is the source of truth, scrape it.
ASSET_NAME=""
if [[ "$DEFAULT_VERSION" =~ ^[0-9]+\.[0-9]+$ ]]; then
    log "==> resolving build number for v$DEFAULT_VERSION"
    ASSET_NAME="$(
        curl -fsSL "https://api.github.com/repos/$GH_REPO/releases/tags/v$DEFAULT_VERSION" \
        | grep -oE '"name"[[:space:]]*:[[:space:]]*"winfsp-[0-9.]+\.msi"' \
        | head -n1 \
        | sed -E 's/.*"(winfsp-[0-9.]+\.msi)".*/\1/'
    )"
else
    ASSET_NAME="winfsp-${DEFAULT_VERSION}.msi"
fi

if [[ -z "$ASSET_NAME" ]]; then
    log "    error: couldn't resolve MSI asset name for v$DEFAULT_VERSION"
    exit 1
fi

# Some tags are short (`v2.0`) but the asset's path uses the short tag,
# others use the full one. Try both forms.
SHORT_VER="${ASSET_NAME#winfsp-}"
SHORT_VER="${SHORT_VER%.msi}"
SHORT_TAG="v${SHORT_VER%.*}.${SHORT_VER##*.}"
TRY_URLS=(
    "https://github.com/$GH_REPO/releases/download/v$DEFAULT_VERSION/$ASSET_NAME"
    "https://github.com/$GH_REPO/releases/download/$SHORT_TAG/$ASSET_NAME"
)

OK_URL=""
for u in "${TRY_URLS[@]}"; do
    if curl -fsIL "$u" >/dev/null 2>&1; then
        OK_URL="$u"
        break
    fi
done

if [[ -z "$OK_URL" ]]; then
    log "    error: none of the candidate URLs returned 200; tried:"
    printf '    - %s\n' "${TRY_URLS[@]}" >&2
    exit 1
fi

if [[ ! -f "$ASSET_NAME" ]]; then
    log "==> downloading $OK_URL"
    curl -fsSL -o "$ASSET_NAME" "$OK_URL"
fi

# msiextract drops everything under the cwd preserving the in-MSI
# directory structure. We isolate it under extracted/ to keep the cache
# tidy and to give a stable lookup path.
rm -rf extracted
mkdir extracted
log "==> extracting $ASSET_NAME"
( cd extracted && msiextract "../$ASSET_NAME" >/dev/null )

if ! locate_dirs "$SYSROOT"; then
    log "    error: extracted MSI but couldn't find inc/winfsp/winfsp.h"
    log "    contents of extracted/:"
    find extracted -maxdepth 4 -type d >&2
    exit 1
fi

log "==> sysroot ready at: $SYSROOT"
log "    headers: $INC_DIR/winfsp/winfsp.h"
ls -1 "$LIB_DIR"/winfsp*.lib 2>&1 >&2 || \
    log "    (note: no winfsp*.lib found, link may need extra hint)"

emit_env
