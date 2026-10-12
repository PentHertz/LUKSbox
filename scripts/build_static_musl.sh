#!/usr/bin/env bash
#
# build_static_musl.sh - fully static luksbox CLI for Linux (musl libc).
#
# One self-contained `luksbox` binary that runs on any x86_64 / aarch64
# Linux distribution, with no shared-library dependency at all (GitHub
# issue #34). Same tarballs the release workflow's `static-linux` and
# `static-linux-fido2-tpm` jobs publish. Two variants:
#
# Default, passphrase-only:
#   - every passphrase / hybrid-PQ (ML-KEM) / deniable feature of the CLI
#     and the TUI wizard;
#   - `luksbox mount`: the FUSE support is pure Rust (no libfuse link) and
#     only needs the `fusermount3` helper (package `fuse3`) plus
#     /dev/fuse on the target machine.
#   No FIDO2 security keys, no TPM 2.0.
#
# --fido2-tpm: the same plus FIDO2 security keys and TPM 2.0 keyslots.
#   libfido2, tpm2-tss and what they need (OpenSSL, libcbor, zlib,
#   libudev-zero) are compiled into the binary, so nothing has to be
#   installed on the target machine; it only needs access to the devices
#   (/dev/hidraw*, /dev/tpmrm0). Built inside an Alpine container by
#   scripts/static_fido2_tpm_alpine.sh, so it always needs Docker.
#
# Usage:
#   scripts/build_static_musl.sh [--arch x86_64|aarch64] [--docker]
#                                [--fido2-tpm] [--out DIR]
#
#   --arch       target CPU, default: this machine's.
#   --docker     build inside a `rust:1-bookworm` container (any host with
#                Docker, macOS included; a foreign --arch runs emulated).
#                Without it the build runs on this (Linux) host and needs
#                `rustup target add <arch>-unknown-linux-musl` (the script
#                runs it) and, for an x86_64 build, `musl-tools`.
#   --fido2-tpm  build the FIDO2 + TPM 2.0 variant (always in Docker).
#   --out        where to write the tarball, default: ./dist-static
#
# Output: <out>/luksbox-<version>-<arch>-linux-musl-static.tar.gz (or
# ...-linux-musl-static-fido2-tpm.tar.gz) holding `luksbox`, LICENSE,
# NOTICE and README-STATIC.txt, plus licenses/ for the --fido2-tpm build.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARCH="$(uname -m)"
case "$ARCH" in arm64) ARCH=aarch64 ;; esac
USE_DOCKER=0
FIDO2_TPM=0
OUT="$ROOT/dist-static"

while [ $# -gt 0 ]; do
    case "$1" in
        --arch)   ARCH="$2"; shift 2 ;;
        --docker) USE_DOCKER=1; shift ;;
        --fido2-tpm) FIDO2_TPM=1; shift ;;
        --out)    OUT="$2"; shift 2 ;;
        -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
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

case "$ARCH" in x86_64) PLATFORM=linux/amd64 ;; aarch64) PLATFORM=linux/arm64 ;; esac

if [ "$FIDO2_TPM" = 1 ]; then
    if ! command -v docker >/dev/null; then
        echo "--fido2-tpm builds inside an Alpine container and needs Docker" >&2
        exit 2
    fi
    # Source mounted read-only; the C libraries and the binary are built
    # in the container, which writes `luksbox` and `licenses/` to $OUT.
    docker run --rm --platform "$PLATFORM" -e HOST_IDS="$(id -u):$(id -g)" \
        -v "$ROOT:/src:ro" -v "$OUT:/out" -w /src alpine:3.23 \
        sh /src/scripts/static_fido2_tpm_alpine.sh /out
    BIN="$OUT/luksbox"
elif [ "$USE_DOCKER" = 1 ]; then
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
if [ "$FIDO2_TPM" = 1 ]; then
    NAME="$NAME-fido2-tpm"
fi
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir "$STAGE/$NAME"
install -m 0755 "$BIN" "$STAGE/$NAME/luksbox"
cp "$ROOT/LICENSE" "$ROOT/NOTICE" "$STAGE/$NAME/"
if [ "$FIDO2_TPM" = 1 ]; then
    cp -R "$OUT/licenses" "$STAGE/$NAME/licenses"
    cat > "$STAGE/$NAME/README-STATIC.txt" <<EOF
luksbox v${VERSION} - static Linux CLI with FIDO2 + TPM 2.0 (${ARCH}, musl)

A single binary with no shared-library dependencies; it runs on any
${ARCH} Linux distribution. Copy it anywhere on your PATH:

    install -m 0755 luksbox ~/.local/bin/

Included: everything in the passphrase-only static build (passphrase,
hybrid post-quantum and deniable vaults, the \`luksbox wizard\` TUI and
\`luksbox mount\`), plus FIDO2 security keys and TPM 2.0 keyslots.
libfido2, tpm2-tss and the libraries they use are built into the binary
(see licenses/), so nothing else has to be installed. The machine still
has to give you access to the devices:

  - FIDO2: read/write access to the key's /dev/hidraw* node. Desktop
    distributions usually grant it to the logged-in user; otherwise
    install libfido2's udev rule (70-u2f.rules).
  - TPM 2.0: /dev/tpmrm0, usually open to the \`tss\` group
    (\`sudo usermod -aG tss "\$USER"\`, then log in again).

\`luksbox mount\` needs the \`fusermount3\` helper (package \`fuse3\`) and
/dev/fuse.

The bundled libraries do not get the host's security updates; install a
newer LUKSbox release to pick up fixes in them.
EOF
else
    cat > "$STAGE/$NAME/README-STATIC.txt" <<EOF
luksbox v${VERSION} - static Linux CLI (${ARCH}, musl)

A single binary with no shared-library dependencies; it runs on any
${ARCH} Linux distribution. Copy it anywhere on your PATH:

    install -m 0755 luksbox ~/.local/bin/

Included: every passphrase, hybrid post-quantum (ML-KEM) and deniable
feature of the CLI and of the \`luksbox wizard\` TUI, and \`luksbox mount\`
(needs the \`fusermount3\` helper, package \`fuse3\`, and /dev/fuse).

Not included: FIDO2 security keys and TPM 2.0 keyslots. For those, use
the luksbox-...-linux-musl-static-fido2-tpm tarball from the same release
(also static), or the .deb / .rpm packages.
EOF
fi
tar -C "$STAGE" -czf "$OUT/$NAME.tar.gz" "$NAME"
rm -f "$OUT/luksbox"
rm -rf "$OUT/licenses"
echo "wrote $OUT/$NAME.tar.gz"
