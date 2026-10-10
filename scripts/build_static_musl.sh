#!/usr/bin/env bash
#
# build_static_musl.sh - fully static luksbox CLI for Linux (musl libc).
#
# One self-contained `luksbox` binary that runs on any x86_64 / aarch64
# Linux distribution, with no shared-library dependency at all (GitHub
# issue #34). Same tarball the release workflow's `static-linux` job
# publishes.
#
# What is in it:
#   - every passphrase / hybrid-PQ (ML-KEM) / deniable feature of the CLI
#     and the TUI wizard;
#   - `luksbox mount`: the FUSE support is pure Rust (no libfuse link) and
#     only needs the `fusermount3` helper (package `fuse3`) plus
#     /dev/fuse on the target machine.
# What is NOT (they need C libraries that cannot be linked statically
# across distributions): FIDO2 security keys (libfido2 + libudev), TPM 2.0
# (tpm2-tss). Use the distro packages (.deb / .rpm) for those.
#
# Usage:
#   scripts/build_static_musl.sh [--arch x86_64|aarch64] [--docker] [--out DIR]
#
#   --arch    target CPU, default: this machine's.
#   --docker  build inside a `rust:1-bookworm` container (any host with
#             Docker, macOS included; a foreign --arch runs emulated).
#             Without it the build runs on this (Linux) host and needs
#             `rustup target add <arch>-unknown-linux-musl` (the script
#             runs it) and, for an x86_64 build, `musl-tools`.
#   --out     where to write the tarball, default: ./dist-static
#
# Output: <out>/luksbox-<version>-<arch>-linux-musl-static.tar.gz holding
# `luksbox`, LICENSE, NOTICE and README-STATIC.txt.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH="$(uname -m)"
case "$ARCH" in arm64) ARCH=aarch64 ;; esac
USE_DOCKER=0
OUT="$ROOT/dist-static"

while [ $# -gt 0 ]; do
    case "$1" in
        --arch)   ARCH="$2"; shift 2 ;;
        --docker) USE_DOCKER=1; shift ;;
        --out)    OUT="$2"; shift 2 ;;
        -h|--help) sed -n '2,34p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
case "$ARCH" in
    x86_64|aarch64) ;;
    *) echo "unsupported --arch $ARCH (x86_64 or aarch64)" >&2; exit 2 ;;
esac
TARGET="${ARCH}-unknown-linux-musl"
VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/Cargo.toml" | head -1)"
FEATURES=(--no-default-features --features fuse)
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

if [ "$USE_DOCKER" = 1 ]; then
    case "$ARCH" in x86_64) PLATFORM=linux/amd64 ;; aarch64) PLATFORM=linux/arm64 ;; esac
    # Source mounted read-only; the build happens in the container's own
    # target dir, only the finished binary is copied out.
    docker run --rm --platform "$PLATFORM" \
        -v "$ROOT:/src:ro" -v "$OUT:/out" -w /src rust:1-bookworm \
        bash -euc "
            apt-get update -qq >/dev/null
            apt-get install -y -qq musl-tools >/dev/null
            rustup target add $TARGET >/dev/null
            CARGO_TARGET_DIR=/tmp/target cargo build --locked --profile release-hardened \
                -p luksbox-cli ${FEATURES[*]} --target $TARGET
            install -m 0755 /tmp/target/$TARGET/release-hardened/luksbox /out/luksbox
        "
    BIN="$OUT/luksbox"
else
    if [ "$(uname -s)" != Linux ]; then
        echo "native builds need a Linux host; pass --docker on $(uname -s)" >&2
        exit 2
    fi
    rustup target add "$TARGET" >/dev/null
    # Same hardened profile as every other shipped binary.
    (cd "$ROOT" && cargo build --locked --profile release-hardened -p luksbox-cli "${FEATURES[@]}" --target "$TARGET")
    BIN="$ROOT/target/$TARGET/release-hardened/luksbox"
fi

# Refuse anything that is not a static executable: a stray C dependency
# would quietly turn this into a glibc/musl-loader-bound binary again.
if command -v file >/dev/null; then
    file "$BIN"
    if ! file "$BIN" | grep -Eq 'statically linked|static-pie linked'; then
        echo "error: $BIN is not statically linked" >&2
        exit 1
    fi
fi

NAME="luksbox-v${VERSION}-${ARCH}-linux-musl-static"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir "$STAGE/$NAME"
install -m 0755 "$BIN" "$STAGE/$NAME/luksbox"
cp "$ROOT/LICENSE" "$ROOT/NOTICE" "$STAGE/$NAME/"
cat > "$STAGE/$NAME/README-STATIC.txt" <<EOF
luksbox v${VERSION} - static Linux CLI (${ARCH}, musl)

A single binary with no shared-library dependencies; it runs on any
${ARCH} Linux distribution. Copy it anywhere on your PATH:

    install -m 0755 luksbox ~/.local/bin/

Included: every passphrase, hybrid post-quantum (ML-KEM) and deniable
feature of the CLI and of the \`luksbox wizard\` TUI, and \`luksbox mount\`
(needs the \`fusermount3\` helper, package \`fuse3\`, and /dev/fuse).

Not included: FIDO2 security keys and TPM 2.0 keyslots, which need
system C libraries (libfido2, tpm2-tss). Use the .deb / .rpm packages or
the distro tarballs from the same release for those.
EOF
tar -C "$STAGE" -czf "$OUT/$NAME.tar.gz" "$NAME"
rm -f "$OUT/luksbox"
echo "wrote $OUT/$NAME.tar.gz"
