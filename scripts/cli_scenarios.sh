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
# Portable to macOS (its stock bash 3.2 and BSD tools) as well as Linux.
if command -v sha256sum >/dev/null 2>&1; then SHA=(sha256sum); else SHA=(shasum -a 256); fi
fsize() { wc -c < "$1" | tr -d ' '; }
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
SUMB=$("${SHA[@]}" < blob.bin)

# --- create variants -------------------------------------------------------
for c in aes-256-gcm-siv aes-256-gcm chacha20-poly1305; do ok "create $c" "" -- create v-$c.lbx --cipher $c; done
ok "create pad+hide" "" -- create v-ph.lbx --pad-files --hide-sizes
ok "create detached header" "" -- create v-det.lbx --header v-det.hdr
ok "create with anchor" "" -- create v-anc.lbx --anchor v-anc.anchor
ok "create with max size" "" -- create v-max.lbx --max-size 80M --metadata-size 2M
ok "create hybrid-pq" "" -- create v-pq.lbx --kind hybrid-pq --pq-hybrid v-pq.kyber
ko "create over existing" "exists" -- create v-aes-256-gcm-siv.lbx
ko "create unknown cipher" "cipher" -- create v-x.lbx --cipher rot13
# A sync bundle in one step (`create <folder>.lbxs`): built in a staging
# folder that is removed, refused with the options it has no use for.
ok "create a sync bundle" "created the sync bundle nb.lbxs" -- create nb.lbxs --metadata-size 2M
ok "create a post-quantum sync bundle" "kept inside the bundle" -- create npq.lbxs --kind hybrid-pq --pq-hybrid npq.kyber --metadata-size 2M
ko "create a bundle over an existing one" "already exists" -- create nb.lbxs
ko "create a bundle with an anchor" "--anchor" -- create nb2.lbxs --anchor nb2.anchor
ko "create a bundle with a detached header" "--header" -- create nb2.lbxs --header nb2.hdr
ko "create a bundle with a maximum size" "--max-size" -- create nb2.lbxs --max-size 1G
ko "create a bundle in the v2 format" "v2 formats" -- create nb2.lbxs --format v2
if [ -d nb.lbxs/h ] && [ -d npq.lbxs/h ] && [ -f npq.kyber ] && [ ! -e npq.lbxs.hybrid ] && [ ! -e nb2.lbxs ] \
  && [ -z "$(ls -A state/creating 2>/dev/null)" ]; then PASS=$((PASS+1)); else
  FAIL=$((FAIL+1)); echo "FAIL bundle create: folders, seed, sidecar or staging not as expected"; fi

# --- data commands on each kind -------------------------------------------
# (nb and npq are the sync bundles made above: every command takes the
# folder; check / extract / header-dump have no bundle equivalent.)
for v in v-aes-256-gcm-siv v-aes-256-gcm v-chacha20-poly1305 v-ph v-det v-anc v-pq nb npq; do
  P=$v.lbx; U=()
  case $v in v-det) U=(--header v-det.hdr);; v-anc) U=(--anchor v-anc.anchor);; v-pq) U=(--pq-hybrid v-pq.kyber);;
    nb) P=nb.lbxs;; npq) P=npq.lbxs; U=(--pq-hybrid npq.kyber);; esac
  ok "$v mkdir" "" -- mkdir $P ${U[@]+"${U[@]}"} /docs
  ok "$v put" "wrote 300000 bytes" -- put $P ${U[@]+"${U[@]}"} blob.bin /docs/blob.bin
  ok "$v put small" "" -- put $P ${U[@]+"${U[@]}"} a.txt /a.txt
  ko "$v put existing" "already exists" -- put $P ${U[@]+"${U[@]}"} a.txt /a.txt
  ok "$v ls" "blob.bin" -- ls $P ${U[@]+"${U[@]}"} /docs
  ok "$v get" "" -- get $P ${U[@]+"${U[@]}"} /docs/blob.bin out-$v.bin
  eq "$v get content" "$("${SHA[@]}" < out-$v.bin)" "$SUMB"
  ok "$v cat" "hello vault" -- cat $P ${U[@]+"${U[@]}"} /a.txt
  ok "$v mv" "" -- mv $P ${U[@]+"${U[@]}"} /a.txt /docs/a2.txt
  ok "$v ls after mv" "a2.txt" -- ls $P ${U[@]+"${U[@]}"} /docs
  ko "$v rmdir non-empty" "" -- rmdir $P ${U[@]+"${U[@]}"} /docs
  ok "$v rm" "" -- rm $P ${U[@]+"${U[@]}"} /docs/a2.txt
  [ $v = v-det ] || ok "$v info" "" -- info $P
  if [ $P = $v.lbxs ]; then
    ok "$v sync verify" "every object verified" -- sync verify $P ${U[@]+"${U[@]}"}
    ko "$v check refused" "not available for a sync bundle" -- check $P ${U[@]+"${U[@]}"}
    ko "$v extract refused" "not available for a sync bundle" -- extract $P ${U[@]+"${U[@]}"} /docs/blob.bin ex-$v.bin --tolerate-errors
    ko "$v header-dump refused" "not available for a sync bundle" -- header-dump $P
  else
    ok "$v check" "" -- check $P ${U[@]+"${U[@]}"}
    ok "$v extract" "" -- extract $P ${U[@]+"${U[@]}"} /docs/blob.bin ex-$v.bin --tolerate-errors
    eq "$v extract content" "$("${SHA[@]}" < ex-$v.bin)" "$SUMB"
    ok "$v header-dump" "" -- header-dump $P ${U[@]+"${U[@]}"}
  fi
  ok "$v size" "" -- size $P ${U[@]+"${U[@]}"}
done
LUKSBOX_PASSPHRASE=nope ko "wrong passphrase" "" -- ls v-aes-256-gcm.lbx /
ko "detached vault without --header" "" -- ls v-det.lbx /
ko "hybrid without seed" "" -- ls v-pq.lbx /
ko "post-quantum bundle without seed" "" -- ls npq.lbxs /
LUKSBOX_DEVICE_LABEL=Desktop LUKSBOX_SYNC_STATE_DIR=$W/state2 ok "new bundle: a second device reads" "blob.bin" -- ls nb.lbxs /docs
LUKSBOX_DEVICE_LABEL=Desktop LUKSBOX_SYNC_STATE_DIR=$W/state2 ok "post-quantum bundle: a second device reads" "blob.bin" -- ls npq.lbxs --pq-hybrid npq.kyber /docs
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
eq "folder round trip" "$(cd tree && find . -type f -exec "${SHA[@]}" {} + | sort | "${SHA[@]}")" "$(cd tree-out && find . -type f -exec "${SHA[@]}" {} + | sort | "${SHA[@]}")"
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
eq "resize: mirror follows the region" "$(fsize v-max.lbx.meta-bak)" $((4*1048576))
eq "resize: no .rotating left" "$(ls v-max.lbx.rotating 2>/dev/null)" ""
ok "resize: get after grow" "" -- get v-max.lbx /blob.bin out-rs.bin
eq "resize: content after grow" "$("${SHA[@]}" < out-rs.bin)" "$SUMB"
ok "resize: shrink with an anchor" "from 64.0 MB to 1.0 MB" -- size v-anc.lbx --anchor v-anc.anchor --metadata-size 1M
ok "resize: anchor accepts it" "blob.bin" -- ls v-anc.lbx --anchor v-anc.anchor /docs
ok "resize: get after shrink" "" -- get v-anc.lbx --anchor v-anc.anchor /docs/blob.bin out-rs2.bin
eq "resize: content after shrink" "$("${SHA[@]}" < out-rs2.bin)" "$SUMB"
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
eq "resize: detached content" "$("${SHA[@]}" < out-det2.bin)" "$SUMB"
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
eq "header-backup size" "$(fsize hb.bin)" 8192
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
# Every vault kind converts, and the bundle opens with the same
# credentials (the post-quantum one with its seed, its sidecar inside the
# bundle); the detached header and the anchor are only needed to convert.
# (v-anc was rolled back on purpose above: its conversion is refused; a
# fresh anchored vault converts.)
ko "convert a rolled-back vault" "ROLLBACK DETECTED" -- sync convert v-anc.lbx c-rb.lbxs --anchor v-anc.anchor
[ ! -e c-rb.lbxs ] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL a refused conversion left a bundle folder"; }
ok "v-anc2 create" "" -- create v-anc2.lbx --anchor v-anc2.anchor --metadata-size 2M
ok "v-max mkdir" "" -- mkdir v-max.lbx /docs
for v in v-max v-anc2; do
  A=(); [ $v = v-anc2 ] && A=(--anchor v-anc2.anchor)
  [ $v = v-anc2 ] && ok "$v mkdir" "" -- mkdir $v.lbx ${A[@]+"${A[@]}"} /docs
  ok "$v put" "" -- put $v.lbx ${A[@]+"${A[@]}"} blob.bin /docs/blob.bin
done
for v in v-aes-256-gcm-siv v-ph v-det v-anc2 v-max v-pq; do
  U=(); O=()
  case $v in v-det) U=(--header v-det.hdr);; v-anc2) U=(--anchor v-anc2.anchor);; v-pq) U=(--pq-hybrid v-pq.kyber); O=(--pq-hybrid v-pq.kyber);; esac
  ok "sync convert $v" "converted $v.lbx into the sync bundle c-$v.lbxs" -- sync convert $v.lbx c-$v.lbxs ${U[@]+"${U[@]}"}
  ok "converted $v lists" "blob.bin" -- ls c-$v.lbxs ${O[@]+"${O[@]}"} /docs
  ok "converted $v get" "" -- get c-$v.lbxs ${O[@]+"${O[@]}"} /docs/blob.bin out-c-$v.bin
  eq "converted $v content" "$("${SHA[@]}" < out-c-$v.bin)" "$SUMB"
  LUKSBOX_DEVICE_LABEL=Desktop LUKSBOX_SYNC_STATE_DIR=$W/state2 ok "converted $v: a second device writes" "" -- put c-$v.lbxs ${O[@]+"${O[@]}"} a.txt /from-desktop.txt
  ok "converted $v: the first device reads it" "hello vault" -- cat c-$v.lbxs ${O[@]+"${O[@]}"} /from-desktop.txt
done
[ ! -e c-v-pq.lbxs.hybrid ] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL a .hybrid file appeared next to the converted bundle"; }
ko "convert into an existing bundle" "already exists" -- sync convert v-ph.lbx c-v-ph.lbxs
ko "convert a bundle" "already a sync bundle" -- sync convert c-v-ph.lbxs c2.lbxs
LUKSBOX_PASSPHRASE=nope ko "bundle: wrong passphrase" "no keyslot accepted" -- ls nb.lbxs /
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

# --- TPM 2.0 sync bundles ---------------------------------------------------
# Only with a TPM given explicitly through TCTI_NAME_CONF (swtpm in CI or a
# container: see TESTING.md) and a TPM-enabled build. A bundle made with
# `create .lbxs` gets TPM and TPM + PIN keyslots and opens with the TPM
# alone on two devices (a wrong PIN refused); a TPM vault and a hybrid
# TPM + ML-KEM one convert and open with the TPM. The FIDO2-fused kinds
# also run when the build takes LUKSBOX_TEST_FIDO2_MOCK (debug builds).
if [ -n "${TCTI_NAME_CONF:-}" ]; then
  export LUKSBOX_TPM_PIN=2468
  ok "tpm: create a bundle" "created the sync bundle tb.lbxs" -- create tb.lbxs --metadata-size 2M
  ok "tpm: put" "" -- put tb.lbxs a.txt /a.txt
  ok "tpm: enroll a TPM keyslot on the bundle" "" -- enroll tb.lbxs --kind tpm2
  ok "tpm: enroll a TPM + PIN keyslot on the bundle" "" -- enroll tb.lbxs --kind tpm2-pin
  ok "tpm: open with the TPM" "hello vault" -- cat tb.lbxs --tpm2 /a.txt
  LUKSBOX_DEVICE_LABEL=Desktop LUKSBOX_SYNC_STATE_DIR=$W/state2 ok "tpm: a second device opens the bundle with the TPM" "hello vault" -- cat tb.lbxs --tpm2 /a.txt
  ok "tpm: revoke the plain TPM keyslot" "" -- revoke tb.lbxs --slot 1
  ok "tpm: open with TPM + PIN" "hello vault" -- cat tb.lbxs --tpm2 /a.txt
  LUKSBOX_TPM_PIN=0000 ko "tpm: a wrong PIN is refused" "" -- cat tb.lbxs --tpm2 /a.txt
  # A TPM vault and a hybrid TPM + ML-KEM-768 vault, converted.
  ok "tpm: create a vault" "" -- create tv.lbx --metadata-size 2M
  ok "tpm: put in the vault" "" -- put tv.lbx a.txt /a.txt
  ok "tpm: enroll on the vault" "" -- enroll tv.lbx --kind tpm2
  ok "tpm: convert it with the TPM" "converted tv.lbx into the sync bundle tv.lbxs" -- sync convert tv.lbx tv.lbxs --tpm2
  LUKSBOX_DEVICE_LABEL=Desktop LUKSBOX_SYNC_STATE_DIR=$W/state2 ok "tpm: a second device opens the converted TPM bundle" "hello vault" -- cat tv.lbxs --tpm2 /a.txt
  ok "tpm: create a vault for hybrid TPM" "" -- create tq.lbx --metadata-size 2M
  ok "tpm: put in it" "" -- put tq.lbx a.txt /a.txt
  ok "tpm: enroll hybrid TPM + ML-KEM" "" -- enroll tq.lbx --kind hybrid-pq-tpm2 --pq-hybrid tq.kyber
  ok "tpm: convert the hybrid TPM vault" "converted" -- sync convert tq.lbx tq.lbxs --tpm2 --pq-hybrid tq.kyber
  [ ! -e tq.lbxs.hybrid ] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL tpm: a .hybrid file next to the bundle"; }
  LUKSBOX_DEVICE_LABEL=Desktop LUKSBOX_SYNC_STATE_DIR=$W/state2 ok "tpm: a second device opens the hybrid TPM bundle" "hello vault" -- cat tq.lbxs --tpm2 --pq-hybrid tq.kyber /a.txt
  ko "tpm: the hybrid TPM bundle needs its seed" "" -- cat tq.lbxs --tpm2 /a.txt
  KEY=$(printf '1%.0s' $(seq 1 64))
  if LUKSBOX_TEST_FIDO2_MOCK=$KEY "$B" list-fido2-devices </dev/null 2>/dev/null | grep -q "software test authenticator"; then
    # Fused TPM + FIDO2, and TPM + FIDO2 + ML-KEM, on a bundle and converted.
    export LUKSBOX_TEST_FIDO2_MOCK=$KEY LUKSBOX_FIDO2_PIN=1234
    ok "tpm+fido2: enroll on the bundle" "" -- enroll tb.lbxs --kind tpm2-fido2
    ok "tpm+fido2: open" "hello vault" -- cat tb.lbxs --tpm2-fido2 /a.txt
    LUKSBOX_DEVICE_LABEL=Desktop LUKSBOX_SYNC_STATE_DIR=$W/state2 ok "tpm+fido2: a second device opens the bundle" "hello vault" -- cat tb.lbxs --tpm2-fido2 /a.txt
    LUKSBOX_TEST_FIDO2_MOCK=$(printf '2%.0s' $(seq 1 64)) ko "tpm+fido2: another key is refused" "" -- cat tb.lbxs --tpm2-fido2 /a.txt
    ok "tpm+fido2+pq: create a vault" "" -- create tf.lbx --metadata-size 2M
    ok "tpm+fido2+pq: put" "" -- put tf.lbx a.txt /a.txt
    ok "tpm+fido2+pq: enroll" "" -- enroll tf.lbx --kind hybrid-pq-tpm2-fido2 --pq-hybrid tf.kyber
    ok "tpm+fido2+pq: convert" "converted" -- sync convert tf.lbx tf.lbxs --tpm2-fido2 --pq-hybrid tf.kyber
    LUKSBOX_DEVICE_LABEL=Desktop LUKSBOX_SYNC_STATE_DIR=$W/state2 ok "tpm+fido2+pq: a second device opens the bundle" "hello vault" -- cat tf.lbxs --tpm2-fido2 --pq-hybrid tf.kyber /a.txt
    unset LUKSBOX_TEST_FIDO2_MOCK LUKSBOX_FIDO2_PIN
  fi
  unset LUKSBOX_TPM_PIN
fi

# --- Secure Enclave sync bundles (macOS) -------------------------------------
# Only on a Mac with a Secure Enclave and a build with `--features
# hardware` (probed by enrolling a keyslot). A bundle made with `create
# .lbxs` gets Secure Enclave and Secure Enclave + passphrase keyslots and
# opens with them on two devices (a wrong slot passphrase refused); a
# Secure Enclave vault and a hybrid Secure Enclave + ML-KEM one convert
# and open the same way. SEP + FIDO2 runs with a debug build's software
# key; Touch ID only with LUKSBOX_TEST_TOUCH_ID=1 (it needs a finger).
SEP_OK=0
if [ "$(uname)" = Darwin ]; then
  run create sprobe.lbx --metadata-size 2M && run enroll sprobe.lbx --kind sep && SEP_OK=1
fi
if [ $SEP_OK = 1 ]; then
  ok "sep: create a bundle" "created the sync bundle sb.lbxs" -- create sb.lbxs --metadata-size 2M
  ok "sep: put" "" -- put sb.lbxs a.txt /a.txt
  ok "sep: enroll a Secure Enclave keyslot on the bundle" "" -- enroll sb.lbxs --kind sep
  ok "sep: enroll a Secure Enclave + passphrase keyslot" "" -- enroll sb.lbxs --kind sep-passphrase
  ok "sep: open with the Secure Enclave" "hello vault" -- cat sb.lbxs --sep /a.txt
  LUKSBOX_DEVICE_LABEL=Desktop LUKSBOX_SYNC_STATE_DIR=$W/state2 ok "sep: a second device opens the bundle with the Secure Enclave" "hello vault" -- cat sb.lbxs --sep /a.txt
  ok "sep: revoke the plain Secure Enclave keyslot" "" -- revoke sb.lbxs --slot 1
  ok "sep: open with Secure Enclave + passphrase" "hello vault" -- cat sb.lbxs --sep /a.txt
  LUKSBOX_PASSPHRASE=nope ko "sep: a wrong slot passphrase is refused" "" -- cat sb.lbxs --sep /a.txt
  ok "sep: create a vault" "" -- create sv.lbx --metadata-size 2M
  ok "sep: put in the vault" "" -- put sv.lbx a.txt /a.txt
  ok "sep: enroll on the vault" "" -- enroll sv.lbx --kind sep
  ok "sep: convert it with the Secure Enclave" "converted sv.lbx into the sync bundle sv.lbxs" -- sync convert sv.lbx sv.lbxs --sep
  LUKSBOX_DEVICE_LABEL=Desktop LUKSBOX_SYNC_STATE_DIR=$W/state2 ok "sep: a second device opens the converted bundle" "hello vault" -- cat sv.lbxs --sep /a.txt
  ok "sep: create a vault for hybrid SEP" "" -- create sq.lbx --metadata-size 2M
  ok "sep: put in it" "" -- put sq.lbx a.txt /a.txt
  ok "sep: enroll hybrid Secure Enclave + ML-KEM" "" -- enroll sq.lbx --kind hybrid-pq-sep --pq-hybrid sq.kyber
  ok "sep: convert the hybrid SEP vault" "converted" -- sync convert sq.lbx sq.lbxs --sep --pq-hybrid sq.kyber
  [ ! -e sq.lbxs.hybrid ] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL sep: a .hybrid file next to the bundle"; }
  LUKSBOX_DEVICE_LABEL=Desktop LUKSBOX_SYNC_STATE_DIR=$W/state2 ok "sep: a second device opens the hybrid SEP bundle" "hello vault" -- cat sq.lbxs --sep --pq-hybrid sq.kyber /a.txt
  ko "sep: the hybrid SEP bundle needs its seed" "" -- cat sq.lbxs --sep /a.txt
  KEY=$(printf '1%.0s' $(seq 1 64))
  if LUKSBOX_TEST_FIDO2_MOCK=$KEY "$B" list-fido2-devices </dev/null 2>/dev/null | grep -q "software test authenticator"; then
    export LUKSBOX_TEST_FIDO2_MOCK=$KEY LUKSBOX_FIDO2_PIN=1234
    ok "sep+fido2: enroll on the bundle" "" -- enroll sb.lbxs --kind sep-fido2
    ok "sep+fido2: open" "hello vault" -- cat sb.lbxs --sep --fido2 /a.txt
    LUKSBOX_DEVICE_LABEL=Desktop LUKSBOX_SYNC_STATE_DIR=$W/state2 ok "sep+fido2: a second device opens it" "hello vault" -- cat sb.lbxs --sep --fido2 /a.txt
    ok "sep+fido2+pq: create a vault" "" -- create sf.lbx --metadata-size 2M
    ok "sep+fido2+pq: put" "" -- put sf.lbx a.txt /a.txt
    ok "sep+fido2+pq: enroll" "" -- enroll sf.lbx --kind hybrid-pq-sep-fido2 --pq-hybrid sf.kyber
    ok "sep+fido2+pq: convert" "converted" -- sync convert sf.lbx sf.lbxs --sep --fido2 --pq-hybrid sf.kyber
    LUKSBOX_DEVICE_LABEL=Desktop LUKSBOX_SYNC_STATE_DIR=$W/state2 ok "sep+fido2+pq: a second device opens it" "hello vault" -- cat sf.lbxs --sep --fido2 --pq-hybrid sf.kyber /a.txt
    unset LUKSBOX_TEST_FIDO2_MOCK LUKSBOX_FIDO2_PIN
  fi
  if [ "${LUKSBOX_TEST_TOUCH_ID:-}" = 1 ]; then
    echo "Touch ID steps: touch the sensor when asked"
    # Its own bundle, so the Touch ID keyslot is the only Secure Enclave one.
    ok "sep+touch id: create a bundle" "" -- create stid.lbxs --metadata-size 2M
    ok "sep+touch id: put" "" -- put stid.lbxs a.txt /a.txt
    ok "sep+touch id: enroll on the bundle" "" -- enroll stid.lbxs --kind sep-biometric
    LUKSBOX_DEVICE_LABEL=Desktop LUKSBOX_SYNC_STATE_DIR=$W/state2 ok "sep+touch id: a second device opens it" "hello vault" -- cat stid.lbxs --sep /a.txt
  fi
else
  [ "$(uname)" = Darwin ] && echo "note: Secure Enclave bundle steps skipped (no Secure Enclave, or a build without --features hardware)"
fi

# --- panic ------------------------------------------------------------------
cp v-aes-256-gcm-siv.lbx p.lbx; cp v-aes-256-gcm-siv.lbx.header-bak p.lbx.header-bak 2>/dev/null
ok "panic -y" "" -- panic p.lbx -y
ko "panicked vault does not open" "" -- ls p.lbx /

echo "SCENARIOS: $PASS passed, $FAIL failed"
cd /
if [ $FAIL -eq 0 ]; then rm -rf "$W"; else echo "work folder kept: $W"; fi
exit $FAIL
