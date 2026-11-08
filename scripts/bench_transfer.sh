#!/usr/bin/env bash
#
# bench_transfer.sh, file-transfer throughput of `luksbox put` / `get` for
# each kind of vault, with a plain copy of the same file as reference.
# Numbers and their reading: docs/PERFORMANCE.md.
#
# Usage:
#   scripts/bench_transfer.sh <luksbox binary> <size MiB> [config...]
#
#   configs: raw siv gcm chacha hide pad detached bundle1 bundle4 bundle16
#            (default: all). Use a release build:
#   cargo build --release -p luksbox-cli
#   scripts/bench_transfer.sh target/release/luksbox 512
#
# Needs about 3x <size> of free disk in $TMPDIR. Times include the
# unlock (Argon2id, ~0.5 s with the default preset); the "open" column
# is that cost alone. Nothing outside the temporary folder is touched.
set -u
B=$(cd "$(dirname "$1")" && pwd)/$(basename "$1"); MB=$2; shift 2
W=$(mktemp -d "${TMPDIR:-/tmp}/luksbox-bench.XXXXXX")
trap 'rm -rf "$W"' EXIT
export LUKSBOX_PASSPHRASE=bench-pass LUKSBOX_NEW_PASSPHRASE=bench-pass LUKSBOX_SYNC_STATE_DIR=$W/state LUKSBOX_DEVICE_LABEL=bench
SRC=$W/src.bin
[ -f $SRC ] && [ $(stat -c %s $SRC) -eq $((MB*1048576)) ] || head -c $((MB*1048576)) /dev/urandom > $SRC
SUM=$(sha256sum < $SRC | cut -c1-16)
t() { local s=$(date +%s.%N); "$@" </dev/null >/dev/null 2>$W/err.txt; local rc=$?; local e=$(date +%s.%N); echo "$(echo "$e - $s" | bc) $rc"; }
mbps() { echo "scale=0; $MB / $1" | bc 2>/dev/null; }
row() { # name put_t get_t open_t ok
  printf '%-22s put %6.2fs (%4s MB/s)  get %6.2fs (%4s MB/s)  open %5.2fs  %s\n' "$1" "$2" "$(mbps $2)" "$3" "$(mbps $3)" "$4" "$5"
}
cfgs=("$@"); [ ${#cfgs[@]} -eq 0 ] && cfgs=(raw siv gcm chacha hide pad detached bundle4 bundle1 bundle16)
for c in "${cfgs[@]}"; do
  rm -rf $W/v.lbx* $W/v.hdr $W/v.lbxs $W/state $W/out.bin
  case $c in
    raw) r=$(t cp $SRC $W/out.bin); p=${r% *}; r=$(t cp $W/out.bin /dev/null); g=${r% *}; row raw-copy $p $g 0 ok; continue;;
    siv) cr=(--cipher aes-256-gcm-siv);; gcm) cr=(--cipher aes-256-gcm);; chacha) cr=(--cipher chacha20-poly1305);;
    hide) cr=(--hide-sizes);; pad) cr=(--pad-files);; detached) cr=(--header $W/v.hdr);;
    bundle*) cr=();;
  esac
  $B create $W/v.lbx "${cr[@]}" </dev/null >/dev/null 2>$W/err.txt || { echo "$c: create failed: $(tail -2 $W/err.txt)"; continue; }
  V=$W/v.lbx; U=()
  [ $c = detached ] && U=(--header $W/v.hdr)
  if [[ $c == bundle* ]]; then
    ps=${c#bundle}M; $B sync convert </dev/null $W/v.lbx $W/v.lbxs --page-size $ps >/dev/null 2>$W/err.txt || { echo "$c: convert failed: $(tail -2 $W/err.txt)"; continue; }
    V=$W/v.lbxs
  fi
  r=$(t $B ls $V "${U[@]}" /); o=${r% *}
  r=$(t $B put $V "${U[@]}" $SRC /big.bin); p=${r% *}; prc=${r#* }
  [ $prc = 0 ] || { echo "$c: put failed: $(tail -3 $W/err.txt)"; continue; }
  r=$(t $B get $V "${U[@]}" /big.bin $W/out.bin); g=${r% *}
  ok=$([ "$(sha256sum < $W/out.bin | cut -c1-16)" = $SUM ] && echo ok || echo MISMATCH)
  extra=""
  if [[ $c == bundle* ]]; then extra=" bundle=$(du -sm $W/v.lbxs | cut -f1)MiB state=$(du -sm $W/state | cut -f1)MiB"; else extra=" vault=$(du -sm $W/v.lbx | cut -f1)MiB"; fi
  row $c $p $g $o "$ok$extra"
done
rm -rf $W/v.lbx* $W/v.hdr $W/v.lbxs $W/state $W/out.bin
