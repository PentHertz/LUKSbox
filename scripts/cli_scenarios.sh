#!/usr/bin/env bash
#
# cli_scenarios.sh, end-to-end scenarios through a built `luksbox` binary
# (no hardware tokens): every vault kind (three cipher suites, padding
# and hidden sizes, detached header, anchor, size limit, post-quantum
# hybrid), every data command on each, keyslots, header backup /
# restore / upgrade, rollback detection, sync bundles on two devices,
# `merge`, `panic`, and the failures that must be refused. Each step
# expects success or failure (and optionally a text in the output);
# failing steps are printed with the command and its output.
#
# Usage:
#   cargo build --release -p luksbox-cli
#   scripts/cli_scenarios.sh target/release/luksbox
#
# A release build runs the real Argon2id preset (~0.5 s per unlock):
# about 3 minutes. Needs ~3 GiB of free disk in $TMPDIR (one vault per
# kind, each with its 64 MiB metadata region and mirror); the folder is
# removed when every step passed. Exit status: the number of failures.
set -u
B=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
W=$(mktemp -d "${TMPDIR:-/tmp}/luksbox-scenarios.XXXXXX")
cd "$W"
export LUKSBOX_PASSPHRASE=pw-one LUKSBOX_NEW_PASSPHRASE=pw-one LUKSBOX_SEED_PASSPHRASE=seed-pw \
       LUKSBOX_SYNC_STATE_DIR=$W/state LUKSBOX_DEVICE_LABEL=Laptop LUKSBOX_ACCEPT_WEAK=1
PASS=0; FAIL=0
run() { "$B" "$@" </dev/null >out.txt 2>err.txt; }
# ok "<desc>" [grep-needle-in-stdout+stderr] -- cmd...
ok() { local d=$1 n=$2; shift 3; run "$@"; local rc=$?
  if [ $rc -eq 0 ] && { [ -z "$n" ] || cat out.txt err.txt | grep -qF -- "$n"; }; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL ok: $d (rc=$rc)"; echo "  cmd: $*"; sed 's/^/  | /' out.txt err.txt | grep -v 'memory not locked' | head -6; fi; }
ko() { local d=$1 n=$2; shift 3; run "$@"; local rc=$?
  if [ $rc -ne 0 ] && { [ -z "$n" ] || cat out.txt err.txt | grep -qF -- "$n"; }; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL ko: $d (rc=$rc, expected failure${n:+ with '$n'})"; echo "  cmd: $*"; sed 's/^/  | /' out.txt err.txt | grep -v 'memory not locked' | head -6; fi; }
eq() { if [ "$2" = "$3" ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL eq: $1: '$2' != '$3'"; fi; }

head -c 300000 /dev/urandom > blob.bin; echo "hello vault" > a.txt; printf 'x%.0s' $(seq 1 5000) > b.txt
SUMB=$(sha256sum < blob.bin)

# --- create variants -------------------------------------------------------
for c in aes-256-gcm-siv aes-256-gcm chacha20-poly1305; do ok "create $c" "" -- create v-$c.lbx --cipher $c; done
ok "create pad+hide" "" -- create v-ph.lbx --pad-files --hide-sizes
ok "create detached header" "" -- create v-det.lbx --header v-det.hdr
ok "create with anchor" "" -- create v-anc.lbx --anchor v-anc.anchor
ok "create with max size" "" -- create v-max.lbx --max-size 80M --metadata-size 2M
ok "create hybrid-pq" "" -- create v-pq.lbx --kind hybrid-pq --pq-hybrid v-pq.kyber
ko "create over existing" "exists" -- create v-aes-256-gcm-siv.lbx
ko "create unknown cipher" "cipher" -- create v-x.lbx --cipher rot13

# --- data commands on each kind -------------------------------------------
for v in v-aes-256-gcm-siv v-aes-256-gcm v-chacha20-poly1305 v-ph v-det v-anc v-pq; do
  U=(); case $v in v-det) U=(--header v-det.hdr);; v-anc) U=(--anchor v-anc.anchor);; v-pq) U=(--pq-hybrid v-pq.kyber);; esac
  ok "$v mkdir" "" -- mkdir $v.lbx "${U[@]}" /docs
  ok "$v put" "wrote 300000 bytes" -- put $v.lbx "${U[@]}" blob.bin /docs/blob.bin
  ok "$v put small" "" -- put $v.lbx "${U[@]}" a.txt /a.txt
  ko "$v put existing" "already exists" -- put $v.lbx "${U[@]}" a.txt /a.txt
  ok "$v ls" "blob.bin" -- ls $v.lbx "${U[@]}" /docs
  ok "$v get" "" -- get $v.lbx "${U[@]}" /docs/blob.bin out-$v.bin
  eq "$v get content" "$(sha256sum < out-$v.bin)" "$SUMB"
  ok "$v cat" "hello vault" -- cat $v.lbx "${U[@]}" /a.txt
  ok "$v mv" "" -- mv $v.lbx "${U[@]}" /a.txt /docs/a2.txt
  ok "$v ls after mv" "a2.txt" -- ls $v.lbx "${U[@]}" /docs
  ko "$v rmdir non-empty" "" -- rmdir $v.lbx "${U[@]}" /docs
  ok "$v rm" "" -- rm $v.lbx "${U[@]}" /docs/a2.txt
  [ $v = v-det ] || ok "$v info" "" -- info $v.lbx
  ok "$v check" "" -- check $v.lbx "${U[@]}"
  ok "$v extract" "" -- extract $v.lbx "${U[@]}" /docs/blob.bin ex-$v.bin --tolerate-errors
  eq "$v extract content" "$(sha256sum < ex-$v.bin)" "$SUMB"
  ok "$v size" "" -- size $v.lbx "${U[@]}"
  ok "$v header-dump" "" -- header-dump $v.lbx "${U[@]}"
done
LUKSBOX_PASSPHRASE=nope ko "wrong passphrase" "" -- ls v-aes-256-gcm.lbx /
ko "detached vault without --header" "" -- ls v-det.lbx /
ko "hybrid without seed" "" -- ls v-pq.lbx /
ko "get missing file" "" -- get v-ph.lbx /nope.txt nope.out
ko "cat a directory" "not a file" -- cat v-ph.lbx /docs
ko "mkdir with slash name" "" -- mkdir v-ph.lbx /a/b/c
ok "deep path mkdir parent" "" -- mkdir v-ph.lbx /x
ok "deep path mkdir child" "" -- mkdir v-ph.lbx /x/y
ok "put into deep dir" "" -- put v-ph.lbx b.txt /x/y/b.txt
ok "cat deep" "xxxxx" -- cat v-ph.lbx /x/y/b.txt

# --- folders: one put / get for a whole tree -------------------------------
mkdir -p tree/a/b tree/c; for i in 1 2 3; do head -c $((i*70000)) /dev/urandom > tree/a/f$i.bin; done
echo deep > tree/a/b/deep.txt; echo c > tree/c/c.txt; ln -s /etc/hostname tree/c/link
ok "put folder (siv)" "file(s)" -- put v-aes-256-gcm-siv.lbx tree /tree
ok "ls folder" "deep.txt" -- ls v-aes-256-gcm-siv.lbx /tree/a/b
ko "put folder over existing" "already exists" -- put v-aes-256-gcm-siv.lbx tree /tree
ok "get folder" "file(s)" -- get v-aes-256-gcm-siv.lbx /tree tree-out
eq "folder round trip" "$(cd tree && find . -type f -exec sha256sum {} + | sort | sha256sum)" "$(cd tree-out && find . -type f -exec sha256sum {} + | sort | sha256sum)"
eq "symlink not recreated" "$(ls tree-out/c)" "c.txt"
ko "get folder over existing" "already exists" -- get v-aes-256-gcm-siv.lbx /tree tree-out
# "/" or a trailing "/" receives the source under its own name (it used
# to fail with "empty inner path"); an existing folder named without the
# "/" is refused with a hint, so a repeated folder put cannot nest a copy.
ok "put file into /" "to /a.txt" -- put v-aes-256-gcm-siv.lbx a.txt /
ko "put file onto existing folder" "write /tree/" -- put v-aes-256-gcm-siv.lbx a.txt /tree
ok "put file into folder/" "to /tree/a.txt" -- put v-aes-256-gcm-siv.lbx a.txt /tree/
ok "put file into deep folder/" "to /tree/a/a.txt" -- put v-aes-256-gcm-siv.lbx a.txt /tree/a/
ko "put into / over existing name" "already exists" -- put v-aes-256-gcm-siv.lbx a.txt /
ok "put folder into /" "into /tree" -- put v-chacha20-poly1305.lbx tree /
ok "cat file put into /" "hello vault" -- cat v-aes-256-gcm-siv.lbx /a.txt

# --- size limit -------------------------------------------------------------
head -c $((100*1048576)) /dev/urandom > big100.bin
ko "put past max size" "" -- put v-max.lbx big100.bin /big.bin
ok "vault still opens after failed put" "" -- ls v-max.lbx /
ok "size raise limit" "" -- size v-max.lbx --max 300M
ok "put after raise" "" -- put v-max.lbx big100.bin /big.bin
ok "rm big" "" -- rm v-max.lbx /big.bin
ok "shrink" "" -- size v-max.lbx --shrink
ok "opens after shrink" "" -- ls v-max.lbx /
rm -f big100.bin

# --- file list (metadata) region resize -------------------------------------
ok "size shows the file list gauge" "File list:" -- size v-max.lbx
ok "put before resize" "" -- put v-max.lbx blob.bin /blob.bin
ok "resize: grow 2M -> 4M" "from 2.0 MB to 4.0 MB" -- size v-max.lbx --metadata-size 4M
eq "resize: mirror follows the region" "$(stat -c %s v-max.lbx.meta-bak)" $((4*1048576))
eq "resize: no .rotating left" "$(ls v-max.lbx.rotating 2>/dev/null)" ""
ok "resize: get after grow" "" -- get v-max.lbx /blob.bin out-rs.bin
eq "resize: content after grow" "$(sha256sum < out-rs.bin)" "$SUMB"
ok "resize: shrink with an anchor" "from 64.0 MB to 1.0 MB" -- size v-anc.lbx --anchor v-anc.anchor --metadata-size 1M
ok "resize: anchor accepts it" "blob.bin" -- ls v-anc.lbx --anchor v-anc.anchor /docs
ok "resize: get after shrink" "" -- get v-anc.lbx --anchor v-anc.anchor /docs/blob.bin out-rs2.bin
eq "resize: content after shrink" "$(sha256sum < out-rs2.bin)" "$SUMB"
ko "resize: invalid size" "in steps of 64 KiB" -- size v-max.lbx --metadata-size 100K
mkdir many; for i in $(seq 1 1500); do echo $i > many/f-$i.txt; done
ok "resize: fill a file list" "wrote 1500 file(s)" -- put v-max.lbx many /many
ko "resize: too small for the file list" "choose a larger region" -- size v-max.lbx --metadata-size 64K
ok "resize: refused one left the vault as it was" "Metadata:       4.0 MB" -- size v-max.lbx
touch v-max.lbx.rotating
ko "resize: leftover .rotating refused" "already exists" -- size v-max.lbx --metadata-size 8M
ok "resize: vault fine after that" "f-1500.txt" -- ls v-max.lbx /many
rm -f v-max.lbx.rotating; rm -rf many
ok "resize: detached header" "from 64.0 MB to 32.0 MB" -- size v-det.lbx --header v-det.hdr --metadata-size 32M
ok "resize: header sidecar follows" "starts at offset 33554432" -- info v-det.lbx --header v-det.hdr
eq "resize: no .resizing left" "$(ls v-det.hdr.resizing 2>/dev/null)" ""
ok "resize: detached get" "" -- get v-det.lbx --header v-det.hdr /docs/blob.bin out-det2.bin
eq "resize: detached content" "$(sha256sum < out-det2.bin)" "$SUMB"
ko "deniable-resize needs its acknowledgment" "--data-moves-visibly" -- deniable-resize den.dat --metadata-size 16M

# --- keyslots ---------------------------------------------------------------
LUKSBOX_NEW_PASSPHRASE=pw-two ok "enroll passphrase" "" -- enroll v-aes-256-gcm.lbx
LUKSBOX_PASSPHRASE=pw-two ok "open with second" "" -- ls v-aes-256-gcm.lbx /
LUKSBOX_NEW_PASSPHRASE=pw-three ok "update slot 1" "" -- update v-aes-256-gcm.lbx --slot 1
LUKSBOX_PASSPHRASE=pw-two ko "old second refused" "" -- ls v-aes-256-gcm.lbx /
LUKSBOX_PASSPHRASE=pw-three ok "updated second" "" -- ls v-aes-256-gcm.lbx /
ok "revoke slot 1" "revoked slot 1" -- revoke v-aes-256-gcm.lbx --slot 1
LUKSBOX_PASSPHRASE=pw-three ko "revoked refused" "" -- ls v-aes-256-gcm.lbx /

# --- header backup / restore / upgrade / migrate ---------------------------
ok "header-backup" "" -- header-backup v-chacha20-poly1305.lbx hb.bin
eq "header-backup size" "$(stat -c %s hb.bin)" 8192
ok "header-restore" "" -- header-restore v-chacha20-poly1305.lbx hb.bin
ok "opens after restore" "blob.bin" -- ls v-chacha20-poly1305.lbx /docs
ok "upgrade-header" "" -- upgrade-header v-aes-256-gcm-siv.lbx
ok "opens after upgrade" "" -- ls v-aes-256-gcm-siv.lbx /docs
ok "cleanup-orphans (report)" "" -- cleanup-orphans v-aes-256-gcm-siv.lbx

# --- anchor rollback detection ---------------------------------------------
cp v-anc.lbx anc-old.lbx
ok "anchor: change" "" -- put v-anc.lbx --anchor v-anc.anchor b.txt /new.txt
cp anc-old.lbx v-anc.lbx
ko "anchor: rollback refused" "" -- ls v-anc.lbx --anchor v-anc.anchor /

# --- deniable ---------------------------------------------------------------
ko "deniable-init without a terminal says so" "no terminal to ask on" -- deniable-init den.dat

# --- misc ------------------------------------------------------------------
ok "genpass" "" -- genpass
ok "list-fido2-devices" "" -- list-fido2-devices

# --- sync bundle round trip and merge --------------------------------------
ok "sync convert" "" -- sync convert v-chacha20-poly1305.lbx b.lbxs --page-size 1M
ok "bundle put" "published commit" -- put b.lbxs b.txt /b.txt
LUKSBOX_DEVICE_LABEL=Desktop LUKSBOX_SYNC_STATE_DIR=$W/state2 ok "bundle second device put" "" -- put b.lbxs a.txt /a.txt
ok "bundle first device sees it" "a.txt" -- ls b.lbxs /
ok "sync status" "newest" -- sync status b.lbxs
ok "sync verify" "every object verified" -- sync verify b.lbxs
ok "sync snapshots" "" -- sync snapshots b.lbxs
ok "sync export" "" -- sync export b.lbxs b-export.lbx
ok "export opens" "b.txt" -- ls b-export.lbx /
ok "sync gc dry" "" -- sync gc b.lbxs --dry-run
ko "rotate refused on bundle" "not available for a sync bundle" -- rotate-mvk b.lbxs
ok "bundle resize" "from 64.0 MB to 16.0 MB" -- size b.lbxs --metadata-size 16M
LUKSBOX_DEVICE_LABEL=Desktop LUKSBOX_SYNC_STATE_DIR=$W/state2 ok "bundle resize seen by the second device" "Metadata:       16.0 MB" -- size b.lbxs
LUKSBOX_DEVICE_LABEL=Desktop LUKSBOX_SYNC_STATE_DIR=$W/state2 ok "bundle second device reads after the resize" "hello vault" -- cat b.lbxs /a.txt
LUKSBOX_DEVICE_LABEL=Desktop LUKSBOX_SYNC_STATE_DIR=$W/state2 ok "bundle second device writes after the resize" "" -- put b.lbxs b.txt /after-resize.txt
ok "bundle first device sees it" "after-resize.txt" -- ls b.lbxs /
ok "sync verify after the resize" "every object verified" -- sync verify b.lbxs
cp v-ph.lbx m-ours.lbx; cp v-ph.lbx m-theirs.lbx
ok "merge: ours change" "" -- put m-ours.lbx a.txt /ours.txt
ok "merge: theirs change" "" -- put m-theirs.lbx b.txt /theirs.txt
ok "merge" "" -- merge m-ours.lbx m-theirs.lbx --base v-ph.lbx -o merged.lbx
ok "merged has both" "ours.txt" -- ls merged.lbx /
grep -q theirs.txt out.txt && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL merged lacks theirs.txt"; }
ko "merge with a newer base refused" "older than the merge base" -- merge v-ph.lbx v-ph.lbx --base merged.lbx -o merged2.lbx

# --- panic ------------------------------------------------------------------
cp v-aes-256-gcm-siv.lbx p.lbx; cp v-aes-256-gcm-siv.lbx.header-bak p.lbx.header-bak 2>/dev/null
ok "panic -y" "" -- panic p.lbx -y
ko "panicked vault does not open" "" -- ls p.lbx /

echo "SCENARIOS: $PASS passed, $FAIL failed"
cd /
if [ $FAIL -eq 0 ]; then rm -rf "$W"; else echo "work folder kept: $W"; fi
exit $FAIL
