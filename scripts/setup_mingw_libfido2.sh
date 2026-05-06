#!/usr/bin/env bash
#
# setup_mingw_libfido2.sh, fetch MSYS2's prebuilt mingw-w64 libfido2
# (and its transitive deps) and stage them under a local sysroot so
# scripts/build_release.sh --targets windows-amd64 can link against
# them from a Linux host.
#
# The MSYS2 project precompiles libfido2 + every transitive dep for
# x86_64-w64-mingw32 and ships them as pkg.tar.zst archives on
# repo.msys2.org. We download those, untar them into a single sysroot
# directory, and emit the env vars luksbox-fido2/build.rs needs.
#
# Usage:
#   # one-shot: download/extract if needed, then emit env exports.
#   # designed for `source <(...)` so the env vars land in your shell:
#   source <(scripts/setup_mingw_libfido2.sh)
#
#   # explicit path:
#   source <(scripts/setup_mingw_libfido2.sh /custom/sysroot)
#
#   # only print the env vars, never download:
#   source <(scripts/setup_mingw_libfido2.sh --print-env)
#
# Then build:
#   scripts/build_release.sh --targets windows-amd64 --gui
#
# Prereqs: zstd (apt install zstd), tar, curl, clang. No root needed.

set -euo pipefail

# MSYS2's mingw64 repo. Mirrors are listed at
# https://www.msys2.org/dev/mirrors/, this one is canonical and CDN-fronted.
MSYS2_REPO="${MSYS2_REPO:-https://repo.msys2.org/mingw/mingw64}"

# Packages we need: libfido2 + its transitive runtime + headers.
# Versions are tracked latest-stable by MSYS2; we pull whichever is
# currently in the repo via a `curl + grep` index probe.
PACKAGES=(
    libfido2
    libcbor
    openssl
    zlib
    hidapi
)

PRINT_ENV_ONLY=0
SYSROOT=""

# All status output goes to stderr, so `source <(...)` only consumes
# the env exports we deliberately emit on stdout at the end.
log() { echo "$@" >&2; }

for arg in "$@"; do
    case "$arg" in
        --print-env) PRINT_ENV_ONLY=1 ;;
        -h|--help)
            sed -n '2,/^# Prereqs:/p' "$0" | sed 's/^# \{0,1\}//' >&2
            exit 0
            ;;
        *)
            SYSROOT="$arg"
            ;;
    esac
done

[[ -z "$SYSROOT" ]] && SYSROOT="$HOME/.cache/luksbox/mingw-libfido2"

is_populated() {
    [[ -f "$1/mingw64/include/fido.h" ]]
}

emit_env() {
    cat <<EOF
export LIBFIDO2_LIB_DIR="$SYSROOT/mingw64/lib"
export LIBFIDO2_INCLUDE_DIR="$SYSROOT/mingw64/include"
# Tags the override with the target it was prepared for, so
# luksbox-fido2/build.rs ignores it on a native (Linux/macOS)
# build when these vars are still in your shell. Without this
# guard a stray native build silently links the Windows .a
# archive and explodes at link time with "neither ET_REL nor
# LLVM bitcode" + dozens of undefined fido_* symbols.
export LIBFIDO2_TARGET="x86_64-pc-windows-gnu"
# bindgen runs clang against fido.h; the mingw sysroot has the
# Windows-flavored stdlib headers it needs.
export BINDGEN_EXTRA_CLANG_ARGS="--target=x86_64-w64-mingw32 -isystem $SYSROOT/mingw64/include"
EOF
}

# --- print-env-only path: bail cleanly if not populated -------------------

if [[ "$PRINT_ENV_ONLY" == "1" ]]; then
    if is_populated "$SYSROOT"; then
        emit_env
        exit 0
    fi
    log "error: $SYSROOT does not contain a populated mingw libfido2; run setup first"
    exit 2
fi

# --- one-shot path: setup if needed, then emit env ------------------------

if is_populated "$SYSROOT"; then
    log "==> mingw libfido2 already present at $SYSROOT"
    emit_env
    exit 0
fi

if ! command -v zstd >/dev/null 2>&1; then
    log "error: zstd not installed (apt install zstd)"
    exit 2
fi

mkdir -p "$SYSROOT"
cd "$SYSROOT"

# Discover current package URLs by listing the mingw64 repo index and
# grepping for `mingw-w64-x86_64-<pkg>-*-any.pkg.tar.zst`. Pick the
# lexicographically-greatest match (= newest version).
log "==> indexing $MSYS2_REPO ..."
INDEX="$(curl -fsSL "$MSYS2_REPO/")"

for pkg in "${PACKAGES[@]}"; do
    pattern="mingw-w64-x86_64-${pkg}-[^\"]*-any\.pkg\.tar\.zst"
    fname="$(echo "$INDEX" | grep -oE "$pattern" | sort -V | tail -n1 | head -n1)"
    if [[ -z "$fname" ]]; then
        log "    error: no match in repo index for $pkg"
        exit 1
    fi
    if [[ -d "extracted/.done.$pkg" ]]; then
        log "==> $pkg already extracted, skipping"
        continue
    fi
    log "==> downloading $fname"
    curl -fsSL -o "$fname" "$MSYS2_REPO/$fname"
    log "    extracting"
    # MSYS2 packages unpack to ./mingw64/{bin,lib,include,share,...}
    zstd -d -c "$fname" | tar -x
    mkdir -p "extracted/.done.$pkg"
    rm -f "$fname"
done

log "==> sysroot ready at: $SYSROOT"
log "    headers: $SYSROOT/mingw64/include/fido.h"
ls -1 "$SYSROOT/mingw64/lib/libfido2"* 2>&1 >&2 || true

emit_env
