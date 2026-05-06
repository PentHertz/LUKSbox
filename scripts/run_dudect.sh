#!/bin/bash
# Run all dudect constant-time benches and summarise the t-statistic
# per function. See SECURITY_AUDIT_REPORT.md Round 9A for what each
# bench tests and how to interpret the output.
#
# Usage:
#   ./scripts/run_dudect.sh                 # defaults
#   ./scripts/run_dudect.sh --csv out.csv   # also dump raw timings
#
# Exit code: non-zero if any bench's |t-stat| > 4.5 (the standard
# dudect leak threshold) AND the bench is not the reference-leaky one.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CSV=""
for arg in "$@"; do
    case "$arg" in
        --csv) shift; CSV="$1" ;;
    esac
done

LEAK_THRESHOLD="4.5"
BENCHES=(
    "dudect_reference_leaky"   # MUST report a leak (sanity check)
    "dudect_hmac_verify"       # MUST be constant-time
    "dudect_aead_open"         # MUST be constant-time (3 sub-benches)
    "dudect_slot_unlock"       # MUST be constant-time post-KDF
)

echo "[+] Building benches..."
cargo build --release -p luksbox-core --benches >/dev/null

echo "[+] Running dudect benches"
echo "    leak threshold: |t| > $LEAK_THRESHOLD"
echo ""

declare -A RESULTS
FAIL=0

for bench in "${BENCHES[@]}"; do
    bin="$(ls target/release/deps/${bench}-* 2>/dev/null | grep -v '\.d$' | head -1)"
    if [ -z "$bin" ]; then
        echo "  [!] binary for $bench not built; skipping"
        continue
    fi
    args=()
    if [ -n "$CSV" ]; then
        args+=(--out "$CSV")
    fi
    echo "  --- $bench ---"
    output=$("$bin" "${args[@]}" 2>&1)
    echo "$output" | grep -E "^bench " | sed 's/^/    /'

    worst_t=$(echo "$output" \
        | grep -oE 'max t = [+-]?[0-9.]+' \
        | sed 's/max t = //; s/^+//' \
        | tr -d '-' \
        | sort -rn | head -1)
    RESULTS[$bench]="$worst_t"

    is_above_threshold=$(awk -v t="$worst_t" -v th="$LEAK_THRESHOLD" 'BEGIN{print (t>th)?1:0}')
    if [ "$bench" = "dudect_reference_leaky" ]; then
        if [ "$is_above_threshold" = "0" ]; then
            echo "    !! TOOLING BROKEN: reference leaky function did not leak (|t|=$worst_t)"
            FAIL=1
        else
            echo "    OK: tooling correctly detects leaks (|t|=$worst_t)"
        fi
    else
        if [ "$is_above_threshold" = "1" ]; then
            echo "    !! LEAK SUSPECTED: |t|=$worst_t > $LEAK_THRESHOLD"
            FAIL=1
        else
            echo "    OK: |t|=$worst_t < $LEAK_THRESHOLD (constant-time)"
        fi
    fi
    echo ""
done

echo "=== Summary ==="
printf "%-30s %10s %s\n" "Bench" "max |t|" "Status"
printf -- "----------------------------------------\n"
for bench in "${BENCHES[@]}"; do
    t="${RESULTS[$bench]:-N/A}"
    if [ "$bench" = "dudect_reference_leaky" ]; then
        is_above=$(awk -v x="$t" -v th="$LEAK_THRESHOLD" 'BEGIN{print (x>th)?1:0}')
        [ "$is_above" = "1" ] && status="REFERENCE OK (leaks as expected)" || status="!! TOOLING BROKEN"
    else
        is_above=$(awk -v x="$t" -v th="$LEAK_THRESHOLD" 'BEGIN{print (x>th)?1:0}')
        [ "$is_above" = "1" ] && status="!! LEAK" || status="constant-time"
    fi
    printf "%-30s %10s %s\n" "$bench" "$t" "$status"
done

if [ "$FAIL" = "1" ]; then
    echo ""
    echo "[!] One or more benches indicate a problem."
    exit 1
fi
echo ""
echo "[+] All benches within expected bounds."
