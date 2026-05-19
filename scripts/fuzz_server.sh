#!/usr/bin/env bash
#
# fuzz_server.sh, launch a parallel AFL++ campaign against one of the
# luksbox fuzz harnesses. Designed to run on a dedicated server (or
# CI runner) for hours-to-days at a time.
#
# Usage:
#   scripts/fuzz_server.sh <target> <cores> <runtime_seconds>
#
#     target          one of: header_parse, keyslot_parse,
#                     metadata_parse, hybrid_sidecar_parse,
#                     seed_file_parse, auth_then_process,
#                     deniable_header_parse, slot_payload_decode,
#                     slot_payload_roundtrip
#                     OR "all" to run every target sequentially
#                     OR "list" to print the set
#     cores           number of parallel fuzzer instances (master + N-1 slaves).
#                     Recommendation: NUM_CORES - 1 to leave one for OS.
#                     Use 1 for single-process mode.
#     runtime_seconds wall-clock seconds before the campaign stops.
#                     "0" or "infinite" = run forever; Ctrl-C to stop.
#
# Examples:
#   scripts/fuzz_server.sh header_parse 8 3600           # 1 h on 8 cores
#   scripts/fuzz_server.sh auth_then_process 16 86400    # 24 h on 16 cores
#   scripts/fuzz_server.sh all 4 1800                    # 30 min each, 4 cores
#
# Findings layout under fuzz-afl/runs/<target>/<timestamp>/:
#   sync/master/queue/         - corpus discovered by the master fuzzer
#   sync/master/crashes/       - inputs that crashed the harness
#   sync/master/hangs/         - inputs that exceeded the timeout
#   sync/slave_*/...           - same shape, one per parallel slave
#   campaign.log               - aggregated stdout + final summary
#
# Pre-flight:
#   1. Install AFL++ + cargo-afl on the server:
#        apt install build-essential clang llvm
#        cargo install --locked --version 0.15 afl
#   2. Tune the kernel for fuzzing (one-time, requires root):
#        echo core | sudo tee /proc/sys/kernel/core_pattern
#        echo performance | sudo tee \
#          /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
#      (the script will warn if these aren't set)
#   3. Build the harnesses:
#        (cd fuzz-afl && cargo afl build --release)
#      The script does this for you on first run, but pre-building
#      keeps the campaign-start logging cleaner.
#
# Stopping early: Ctrl-C in the foreground OR `pkill -f afl-fuzz`.
# The campaign.log + queue / crashes / hangs are preserved.

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
AFL_DIR="$REPO_ROOT/fuzz-afl"
TARGETS=(header_parse keyslot_parse metadata_parse hybrid_sidecar_parse seed_file_parse auth_then_process deniable_header_parse slot_payload_decode slot_payload_roundtrip chunk_aead_decrypt anchor_parse deniable_envelope_multi_slot)

# ---- arg parse ------------------------------------------------------------

usage() { sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
[[ "${1:-}" == "" || "${1:-}" == "-h" || "${1:-}" == "--help" ]] && usage

TARGET="$1"
CORES="${2:-1}"
RUNTIME="${3:-0}"

if [[ "$TARGET" == "list" ]]; then
    printf '  %s\n' "${TARGETS[@]}"
    exit 0
fi

# Validate target name (or "all").
if [[ "$TARGET" != "all" ]] && ! printf '%s\n' "${TARGETS[@]}" | grep -qx "$TARGET"; then
    echo "error: unknown target '$TARGET'. Run with 'list' to see available targets." >&2
    exit 2
fi

if ! [[ "$CORES" =~ ^[0-9]+$ ]] || [[ "$CORES" -lt 1 ]]; then
    echo "error: cores must be a positive integer, got '$CORES'" >&2
    exit 2
fi

if [[ "$RUNTIME" == "infinite" ]]; then
    RUNTIME=0
fi
if ! [[ "$RUNTIME" =~ ^[0-9]+$ ]]; then
    echo "error: runtime_seconds must be 0 or a non-negative integer, got '$RUNTIME'" >&2
    exit 2
fi

# ---- pre-flight checks ----------------------------------------------------

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "error: required command '$1' not found in PATH." >&2
        echo "       see scripts/fuzz_server.sh header for install steps." >&2
        exit 1
    }
}
need_cmd cargo
need_cmd afl-fuzz
need_cmd afl-whatsup

# Kernel core_pattern check, afl-fuzz refuses to start otherwise on Linux.
if [[ -r /proc/sys/kernel/core_pattern ]]; then
    cp_val="$(cat /proc/sys/kernel/core_pattern)"
    if [[ "$cp_val" != "core" && "$cp_val" != core* ]]; then
        echo "warning: /proc/sys/kernel/core_pattern is '$cp_val'." >&2
        echo "         afl-fuzz needs it to be 'core'. Run as root:" >&2
        echo "         echo core | sudo tee /proc/sys/kernel/core_pattern" >&2
        # Don't hard-fail, afl-fuzz will give the same error anyway and
        # some hosting environments forbid changing this.
    fi
fi

# CPU governor check, performance mode gives ~1.5-2x throughput.
if compgen -G "/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor" >/dev/null; then
    govs="$(cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null \
            | sort -u | tr '\n' ',' | sed 's/,$//')"
    if [[ "$govs" != "performance" ]]; then
        echo "warning: CPU governor is '$govs', not 'performance'." >&2
        echo "         For best fuzz throughput run as root:" >&2
        echo "         echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor" >&2
    fi
fi

# ---- build (idempotent) ---------------------------------------------------

echo "[+] building harnesses (cargo afl build --release)..."
(cd "$AFL_DIR" && cargo afl build --release) 2>&1 | sed 's/^/    /'

# ---- run a single target --------------------------------------------------

run_target() {
    local target="$1"
    local cores="$2"
    local runtime="$3"

    local seeds_dir="$AFL_DIR/seeds/$target"
    if [[ ! -d "$seeds_dir" ]] || [[ -z "$(ls -A "$seeds_dir" 2>/dev/null)" ]]; then
        echo "[!] $target has no seed inputs at $seeds_dir, skipping" >&2
        return 1
    fi

    local stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    local out_dir="$AFL_DIR/runs/$target/$stamp"
    local sync_dir="$out_dir/sync"
    mkdir -p "$out_dir"
    local log="$out_dir/campaign.log"

    echo "[+] target=$target cores=$cores runtime=${runtime}s out=$out_dir"
    echo "    seeds: $(ls "$seeds_dir" | wc -l) files"
    echo "    log:   $log"

    local bin="$AFL_DIR/target/release/$target"
    if [[ ! -x "$bin" ]]; then
        echo "    error: harness binary not found at $bin" >&2
        return 1
    fi

    # Per-instance memory cap (MB). 4 GiB is comfortably above what any
    # of our parsers should need; auth_then_process allocates a 1 MiB
    # region buffer and the bincode 64 MiB limit, so 4 GiB leaves slack
    # for libafl's own overhead.
    local mem_mb=4096
    # Per-input timeout (ms). Most parsers complete in microseconds;
    # seed_file_parse runs Argon2id and can take ~500 ms legitimately.
    local timeout_ms=2000
    if [[ "$target" == "seed_file_parse" ]]; then
        timeout_ms=5000
    fi

    # Common AFL flags. -V seconds, -t timeout_ms, -m memory_mb.
    local common_flags=(-i "$seeds_dir" -o "$sync_dir" -m "$mem_mb" -t "$timeout_ms")
    if [[ "$runtime" -gt 0 ]]; then
        common_flags+=(-V "$runtime")
    fi

    # Spawn master + slaves. Each background-launched, all writing to
    # the shared $sync_dir so AFL's queue-sync picks up new corpus
    # inputs from siblings every few seconds.
    local pids=()
    AFL_NO_UI=1 AFL_AUTORESUME=1 \
        afl-fuzz "${common_flags[@]}" -M master -- "$bin" \
        > "$out_dir/master.log" 2>&1 &
    pids+=($!)
    for ((i = 1; i < cores; i++)); do
        AFL_NO_UI=1 AFL_AUTORESUME=1 \
            afl-fuzz "${common_flags[@]}" -S "slave_$i" -- "$bin" \
            > "$out_dir/slave_$i.log" 2>&1 &
        pids+=($!)
    done

    # Cleanup handler: SIGINT during this script propagates to the
    # afl-fuzz children so they shut down cleanly.
    cleanup() {
        echo
        echo "[+] stopping fuzzers (sending SIGTERM to ${#pids[@]} workers)..."
        for pid in "${pids[@]}"; do
            kill -TERM "$pid" 2>/dev/null || true
        done
        wait "${pids[@]}" 2>/dev/null || true
        # Final summary.
        if command -v afl-whatsup >/dev/null; then
            echo "[+] final state:"
            afl-whatsup -s "$sync_dir" 2>&1 | tee -a "$log"
        fi
        # Surface crashes/hangs counts.
        local crash_n="$(find "$sync_dir" -path '*/crashes/id:*' 2>/dev/null | wc -l)"
        local hang_n="$(find "$sync_dir" -path '*/hangs/id:*' 2>/dev/null | wc -l)"
        echo "[+] $target: $crash_n crash inputs, $hang_n hang inputs" \
            | tee -a "$log"
        if [[ "$crash_n" -gt 0 ]]; then
            echo "    inspect with:" | tee -a "$log"
            find "$sync_dir" -path '*/crashes/id:*' -printf '      %p\n' \
                | tee -a "$log"
        fi
    }
    trap cleanup INT TERM EXIT

    # Periodic stats while running.
    {
        while sleep 30 && kill -0 "${pids[0]}" 2>/dev/null; do
            if command -v afl-whatsup >/dev/null; then
                afl-whatsup -s "$sync_dir" 2>&1 | tail -20 | tee -a "$log"
            fi
        done
    } &
    local stats_pid=$!

    # Wait for the foreground (master) to finish, slaves stop when
    # they see master gone.
    wait "${pids[0]}" 2>/dev/null || true
    kill "$stats_pid" 2>/dev/null || true
    # cleanup() will run via EXIT trap.
}

# ---- dispatch -------------------------------------------------------------

if [[ "$TARGET" == "all" ]]; then
    for t in "${TARGETS[@]}"; do
        run_target "$t" "$CORES" "$RUNTIME" || true
        # Reset the EXIT trap between targets so cleanup() doesn't fire
        # twice.
        trap - INT TERM EXIT
    done
else
    run_target "$TARGET" "$CORES" "$RUNTIME"
fi
