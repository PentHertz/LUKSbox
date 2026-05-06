#!/usr/bin/env bash
# Run cargo audit against the workspace dependency tree. Intended for
# pre-release and CI use. Two-state output: green if no NEW advisories
# beyond the ignore list below; red otherwise (with the offending crate
# highlighted).
#
# Currently-ignored advisories (must be re-reviewed at every release):
#   RUSTSEC-2025-0026  registry crate unmaintained, Windows-only,
#                      transitive via winfsp_wrs_sys (affects
#                      luksbox-mount on `target_os = "windows"` only).
#                      Non-Windows builds are unaffected. Revisit when
#                      the Rust WinFsp bindings update.
#
# Historical (no longer ignored, closed):
#   RUSTSEC-2025-0141  bincode 2.x unmaintained, replaced by postcard
#                      in audit round 7E; bincode dep removed.
#   RUSTSEC-2021-0154  fuser ≤ 0.15 unsound, bumped to 0.16
#                      (advisory `versions.patched = [">= 0.16.0"]`).
#   RUSTSEC-2026-0009  time 0.3.45 DoS, bumped to 0.3.47 (audit
#                      round 7); MSRV moved 1.85 → 1.88 to permit it.
#
# Add new exemptions ONLY with a written justification. Default policy
# should be: fix it, not ignore it.

set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v cargo-audit >/dev/null 2>&1; then
    echo "cargo-audit not installed. Install with: cargo install cargo-audit"
    exit 2
fi

# `--deny warnings` would make ANY advisory fail. We use the explicit
# ignore list instead so we know exactly what we're accepting.
cargo audit \
    --ignore RUSTSEC-2025-0026 \
    --color=auto \
    "$@"
