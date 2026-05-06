#!/usr/bin/env bash
#
# release_fuzz.sh, release-gate libFuzzer campaign across every fuzz
# target in fuzz/fuzz_targets/. Designed to be run on a developer
# workstation or CI server BEFORE cutting a release.
#
# This is the long-form companion to:
#   - the per-PR 5-minute smoke (.github/workflows/ci.yml)
#   - the nightly 30-minute pass (.github/workflows/fuzz-nightly.yml)
#   - the multi-core AFL++ server campaign (scripts/fuzz_server.sh)
#
# Goal: catch the bugs that the shorter campaigns can't reach because
# libFuzzer needs hours-to-days of mutation to find them.
#
# Usage:
#   scripts/release_fuzz.sh [<seconds_per_target>] [<jobs_per_target>]
#
#     seconds_per_target  wall-clock seconds each target gets.
#                         default: 86400 (24 h). Use 3600 for a quick
#                         "is the harness even alive" check.
#     jobs_per_target     parallel libFuzzer workers per target
#                         (libFuzzer's `-fork=N`). default: 4.
#                         Use $(nproc) for full host occupation.
#
# Examples:
#   scripts/release_fuzz.sh                  # 24h × 7 targets, 4 workers each
#   scripts/release_fuzz.sh 3600             # 1h × 7 targets, smoke
#   scripts/release_fuzz.sh 86400 16         # 24h × 7 × 16-fork (heavy)
#   scripts/release_fuzz.sh 0                # ∞ (Ctrl-C to stop)
#
# Findings layout under fuzz/release-runs/<utc-stamp>/:
#   <target>/stdout.log          libFuzzer's per-target output
#   <target>/coverage.txt        cov / ft snapshot at end of run
#   summary.txt                  per-target pass/fail + crash counts
#
# Exit codes:
#   0   every target passed (no crashes, no slow-units beyond cap)
#   1   one or more targets crashed, see summary.txt and stderr
#   2   pre-flight failure (missing toolchain, no nightly Rust, etc.)
#
# Pre-flight:
#   - rustup toolchain install nightly
#   - cargo install cargo-fuzz
#   - clang available on PATH (libFuzzer needs sanitizer linkage)
#
# This script does NOT run AFL++. AFL++ campaigns are different in
# personality (fork-per-input mutator) and live under fuzz_server.sh.
# Best practice for a release: run BOTH (this script for libFuzzer, and
# fuzz_server.sh for AFL++) and union the discovered corpora.

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
FUZZ_DIR="$REPO_ROOT/fuzz"
TARGETS_DIR="$FUZZ_DIR/fuzz_targets"

# ---- arg parse ------------------------------------------------------------

usage() { sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && usage

SECONDS_PER_TARGET="${1:-86400}"
JOBS_PER_TARGET="${2:-4}"

if ! [[ "$SECONDS_PER_TARGET" =~ ^[0-9]+$ ]]; then
    echo "error: seconds_per_target must be 0 or a positive integer, got '$SECONDS_PER_TARGET'" >&2
    exit 2
fi
if ! [[ "$JOBS_PER_TARGET" =~ ^[0-9]+$ ]] || [[ "$JOBS_PER_TARGET" -lt 1 ]]; then
    echo "error: jobs_per_target must be a positive integer, got '$JOBS_PER_TARGET'" >&2
    exit 2
fi

# ---- pre-flight checks ----------------------------------------------------

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "error: required command '$1' not found in PATH." >&2
        echo "       see scripts/release_fuzz.sh header for install steps." >&2
        exit 2
    }
}
need_cmd cargo
need_cmd rustup

# Confirm cargo-fuzz subcommand is installed.
if ! cargo fuzz --version >/dev/null 2>&1; then
    echo "error: 'cargo fuzz' subcommand missing." >&2
    echo "       run: cargo install cargo-fuzz" >&2
    exit 2
fi

# Confirm a nightly toolchain is installed (libFuzzer needs sanitizer).
if ! rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
    echo "error: nightly Rust toolchain not installed." >&2
    echo "       run: rustup toolchain install nightly" >&2
    exit 2
fi

# Discover targets from the actual filesystem (no hardcoded list, picks
# up new harnesses automatically).
TARGETS=()
while IFS= read -r f; do
    TARGETS+=("$(basename "$f" .rs)")
done < <(find "$TARGETS_DIR" -maxdepth 1 -name '*.rs' -type f | sort)

if [[ "${#TARGETS[@]}" -eq 0 ]]; then
    echo "error: no targets found in $TARGETS_DIR" >&2
    exit 2
fi

# ---- run ------------------------------------------------------------------

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="$FUZZ_DIR/release-runs/$STAMP"
mkdir -p "$OUT_DIR"
SUMMARY="$OUT_DIR/summary.txt"

{
    echo "luksbox release-fuzz campaign"
    echo "  start:               $(date -u +%FT%TZ)"
    echo "  seconds_per_target:  $SECONDS_PER_TARGET"
    echo "  jobs_per_target:     $JOBS_PER_TARGET"
    echo "  targets:             ${TARGETS[*]}"
    echo
} | tee "$SUMMARY"

OVERALL_FAIL=0

for target in "${TARGETS[@]}"; do
    target_out="$OUT_DIR/$target"
    mkdir -p "$target_out"
    log="$target_out/stdout.log"

    echo "[+] $target, $(date -u +%FT%TZ)"
    echo "    log: $log"

    # libFuzzer runner flags:
    #   -fork=N             N parallel workers; libFuzzer starts a
    #                       supervisor process plus N children, queue-syncs.
    #   -max_total_time=S   wall-clock cap; 0 = run forever.
    #   -timeout=120        per-input timeout; legitimate Argon2id paths in
    #                       seed_file_parse can take several seconds.
    #   -rss_limit_mb=4096  per-worker memory cap (4 GiB) so a runaway
    #                       allocation doesn't OOM the host.
    fuzz_args=(
        "-fork=$JOBS_PER_TARGET"
        "-timeout=120"
        "-rss_limit_mb=4096"
    )
    if [[ "$SECONDS_PER_TARGET" -gt 0 ]]; then
        fuzz_args+=("-max_total_time=$SECONDS_PER_TARGET")
    fi

    set +e
    (
        cd "$REPO_ROOT"
        cargo +nightly fuzz run "$target" -- "${fuzz_args[@]}"
    ) > "$log" 2>&1
    rc=$?
    set -e

    # Crash artifacts: cargo-fuzz writes them under fuzz/artifacts/<target>/
    # with `crash-` / `oom-` / `slow-unit-` prefixes.
    crashes=0
    if [[ -d "$FUZZ_DIR/artifacts/$target" ]]; then
        crashes=$(find "$FUZZ_DIR/artifacts/$target" -maxdepth 1 \
            \( -name 'crash-*' -o -name 'oom-*' \) 2>/dev/null | wc -l)
    fi

    # libFuzzer reports cov/ft on its final line. Capture it for the
    # summary so we can spot regressions across runs.
    cov_line="$(grep -E 'INFO: seed corpus|cov: [0-9]+ ft:' "$log" 2>/dev/null \
        | tail -1 || true)"
    echo "$cov_line" > "$target_out/coverage.txt"

    if [[ "$rc" -ne 0 || "$crashes" -gt 0 ]]; then
        OVERALL_FAIL=1
        printf '  %-22s FAIL (rc=%d, crashes=%d)\n' "$target" "$rc" "$crashes" \
            | tee -a "$SUMMARY"
        if [[ "$crashes" -gt 0 ]]; then
            echo "    crash artifacts:" | tee -a "$SUMMARY"
            find "$FUZZ_DIR/artifacts/$target" -maxdepth 1 \
                \( -name 'crash-*' -o -name 'oom-*' \) -printf '      %p\n' \
                2>/dev/null | tee -a "$SUMMARY"
        fi
    else
        printf '  %-22s OK   (cov: %s)\n' "$target" \
            "$(grep -oE 'cov: [0-9]+ ft: [0-9]+' "$log" | tail -1 || echo n/a)" \
            | tee -a "$SUMMARY"
    fi
done

{
    echo
    echo "  end:                 $(date -u +%FT%TZ)"
    if [[ "$OVERALL_FAIL" -eq 0 ]]; then
        echo "  result:              ALL OK"
    else
        echo "  result:              FAIL, see per-target lines above"
        echo "  triage:              docs/FUZZING.md → 'Triage a crash'"
    fi
} | tee -a "$SUMMARY"

exit "$OVERALL_FAIL"
