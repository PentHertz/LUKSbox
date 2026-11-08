#!/usr/bin/env bash
#
# fuzz_sync.sh, libFuzzer campaign over the sync-bundle harnesses
# (fuzz/fuzz_targets/sync_*.rs): the object codec, names, page tables,
# manifests, leases, the commit graph, the per-device state record,
# folder listings, the real bundle folder with hostile contents, the
# keyslot-table merge and the end-to-end "evil provider" open.
#
# The bundle folder is written by a sync client on the storage
# provider's behalf, so everything in it is attacker-chosen; these
# harnesses feed exactly that surface. Run them after any change to
# crates/luksbox-sync, and before a release together with
# scripts/release_fuzz.sh (every target) and scripts/fuzz_server.sh
# (AFL++ on a server).
#
# Usage:
#   scripts/fuzz_sync.sh [<seconds_per_target>] [<jobs_per_target>] [<target>...]
#
#     seconds_per_target  wall-clock seconds each target gets.
#                         default: 300. 0 = run forever (Ctrl-C to stop).
#     jobs_per_target     parallel libFuzzer workers (`-fork=N`). default: 2.
#     target...           run only these (names without the sync_ prefix
#                         are accepted); default: every sync_* target.
#
#   scripts/fuzz_sync.sh --build        only build every sync harness
#                                       (what CI does on each change)
#   scripts/fuzz_sync.sh --list         print the targets
#
# Examples:
#   scripts/fuzz_sync.sh                     # 5 min x every sync target
#   scripts/fuzz_sync.sh 3600 8              # 1 h x every target, 8 workers
#   scripts/fuzz_sync.sh 600 4 bundle_open_adversarial fs_store_hostile
#
# Findings layout under fuzz/sync-runs/<utc-stamp>/:
#   <target>/stdout.log          libFuzzer's per-target output
#   summary.txt                  per-target pass/fail + crash counts
#
# Exit codes: 0 every target passed; 1 one or more crashed or timed
# out (see summary.txt and fuzz/artifacts/<target>/); 2 pre-flight
# failure (missing nightly Rust or cargo-fuzz).
#
# Pre-flight: rustup toolchain install nightly; cargo install cargo-fuzz;
# clang on PATH (libFuzzer needs sanitizer linkage).

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
FUZZ_DIR="$REPO_ROOT/fuzz"
TARGETS_DIR="$FUZZ_DIR/fuzz_targets"

usage() { sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

all_targets() {
    find "$TARGETS_DIR" -maxdepth 1 -name 'sync_*.rs' -type f -printf '%f\n' \
        | sed 's/\.rs$//' | sort
}

case "${1:-}" in
    -h|--help) usage ;;
    --list) all_targets; exit 0 ;;
esac

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "error: required command '$1' not found in PATH" >&2
        exit 2
    }
}
need_cmd cargo
need_cmd rustup
if ! cargo fuzz --version >/dev/null 2>&1; then
    echo "error: 'cargo fuzz' missing; run: cargo install cargo-fuzz" >&2
    exit 2
fi
if ! rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
    echo "error: nightly Rust not installed; run: rustup toolchain install nightly" >&2
    exit 2
fi

if [[ "${1:-}" == "--build" ]]; then
    cd "$REPO_ROOT"
    while IFS= read -r t; do
        echo "[+] build $t"
        cargo +nightly fuzz build "$t"
    done < <(all_targets)
    exit 0
fi

SECONDS_PER_TARGET="${1:-300}"
JOBS_PER_TARGET="${2:-2}"
shift $(( $# >= 2 ? 2 : $# )) || true
if ! [[ "$SECONDS_PER_TARGET" =~ ^[0-9]+$ ]]; then
    echo "error: seconds_per_target must be 0 or a positive integer" >&2
    exit 2
fi
if ! [[ "$JOBS_PER_TARGET" =~ ^[0-9]+$ ]] || [[ "$JOBS_PER_TARGET" -lt 1 ]]; then
    echo "error: jobs_per_target must be a positive integer" >&2
    exit 2
fi

TARGETS=()
if [[ $# -gt 0 ]]; then
    for t in "$@"; do
        t="${t#sync_}"
        if [[ ! -f "$TARGETS_DIR/sync_$t.rs" ]]; then
            echo "error: no sync target 'sync_$t' (see --list)" >&2
            exit 2
        fi
        TARGETS+=("sync_$t")
    done
else
    while IFS= read -r t; do TARGETS+=("$t"); done < <(all_targets)
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="$FUZZ_DIR/sync-runs/$STAMP"
mkdir -p "$OUT_DIR"
SUMMARY="$OUT_DIR/summary.txt"
{
    echo "luksbox sync-bundle fuzz campaign"
    echo "  start:               $(date -u +%FT%TZ)"
    echo "  seconds_per_target:  $SECONDS_PER_TARGET"
    echo "  jobs_per_target:     $JOBS_PER_TARGET"
    echo "  targets:             ${TARGETS[*]}"
    echo
} | tee "$SUMMARY"

FAIL=0
for target in "${TARGETS[@]}"; do
    mkdir -p "$OUT_DIR/$target" "$FUZZ_DIR/corpus/$target"
    log="$OUT_DIR/$target/stdout.log"
    echo "[+] $target, $(date -u +%FT%TZ)  (log: $log)"
    # -timeout: the hostile-folder and end-to-end harnesses do real file
    # and vault work per input; 60 s is far above a healthy iteration.
    # -rss_limit_mb: a runaway allocation must show up as a finding, not
    # take the host down.
    fuzz_args=("-fork=$JOBS_PER_TARGET" "-timeout=60" "-rss_limit_mb=4096")
    if [[ "$SECONDS_PER_TARGET" -gt 0 ]]; then
        fuzz_args+=("-max_total_time=$SECONDS_PER_TARGET")
    fi
    set +e
    ( cd "$REPO_ROOT" && cargo +nightly fuzz run "$target" -- "${fuzz_args[@]}" ) > "$log" 2>&1
    rc=$?
    set -e
    crashes=0
    if [[ -d "$FUZZ_DIR/artifacts/$target" ]]; then
        crashes=$(find "$FUZZ_DIR/artifacts/$target" -maxdepth 1 \
            \( -name 'crash-*' -o -name 'oom-*' -o -name 'timeout-*' \) 2>/dev/null | wc -l)
    fi
    if [[ "$rc" -ne 0 || "$crashes" -gt 0 ]]; then
        FAIL=1
        printf '  %-30s FAIL (rc=%d, artifacts=%d)\n' "$target" "$rc" "$crashes" | tee -a "$SUMMARY"
    else
        printf '  %-30s OK   (%s)\n' "$target" \
            "$(grep -oE 'cov: [0-9]+ ft: [0-9]+' "$log" | tail -1 || echo n/a)" | tee -a "$SUMMARY"
    fi
done
{
    echo
    echo "  end:                 $(date -u +%FT%TZ)"
    if [[ "$FAIL" -eq 0 ]]; then echo "  result:              ALL OK"; else echo "  result:              FAIL, see FUZZING.md 'Triage a crash'"; fi
} | tee -a "$SUMMARY"
exit "$FAIL"
