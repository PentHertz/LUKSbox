#!/usr/bin/env bash
#
# stage_tpm2_tss.sh - fetch the pinned tpm2-tss source for `bundled-tpm`
# Linux builds and print the path to export as TPM2_TSS_SOURCE_PATH.
#
# R15-J3: without TPM2_TSS_SOURCE_PATH, tss-esapi-sys runs
# `git clone --depth 1 --branch 4.1.3` at build time (a mutable tag, no
# hash) and statically links the result into the shipped binary. This
# fetches the release archive once, verifies its SHA-256 and unpacks it.
#
# The archive is not a git checkout, and tpm2-tss's `bootstrap` (which
# tss-esapi-sys always runs) starts with `git describe ... > VERSION`,
# which then fails under `set -e`. The tree therefore gets a VERSION file
# with the pinned version, and bootstrap only falls back to
# `git describe` when VERSION is missing. Same value `git describe`
# gives on the tag, so configure's AX_IS_RELEASE still sees a release.
#
# Usage: scripts/stage_tpm2_tss.sh DEST_DIR
#   e.g. echo "TPM2_TSS_SOURCE_PATH=$(scripts/stage_tpm2_tss.sh "$RUNNER_TEMP/tss")" >> "$GITHUB_ENV"

set -euo pipefail

# Bump deliberately, together with the hash.
TPM2_TSS_VERSION="4.1.3"
TPM2_TSS_TARBALL_SHA256="8a389bda64690910e7af7deaf64703a3faed416dc538c9c3e4f893f24893524d"

[ $# -eq 1 ] || { echo "usage: $0 DEST_DIR" >&2; exit 2; }
mkdir -p "$1"
DEST="$(cd "$1" && pwd)"
tarball="$DEST/tpm2-tss-$TPM2_TSS_VERSION.tar.gz"
curl -fsSL --retry 3 -o "$tarball" \
    "https://github.com/tpm2-software/tpm2-tss/archive/refs/tags/$TPM2_TSS_VERSION.tar.gz"
echo "$TPM2_TSS_TARBALL_SHA256  $tarball" | sha256sum -c - >&2
src="$DEST/tpm2-tss-$TPM2_TSS_VERSION"
# Fresh tree on every run, so a re-run patches pristine sources.
rm -rf "$src"
tar -xzf "$tarball" -C "$DEST"

printf '%s\n' "$TPM2_TSS_VERSION" > "$src/VERSION"
describe='git describe --tags --always --dirty > VERSION'
grep -qxF "$describe" "$src/bootstrap" || {
    echo "error: tpm2-tss bootstrap no longer has '$describe'; re-check the patch" >&2
    exit 1
}
sed -i "s/^$describe\$/[ -f VERSION ] || $describe/" "$src/bootstrap"
grep -qxF "[ -f VERSION ] || $describe" "$src/bootstrap"

echo "$src"
