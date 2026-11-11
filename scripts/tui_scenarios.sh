#!/usr/bin/env bash
#
# tui_scenarios.sh, the interactive paths through a pseudo-terminal:
# `luksbox wizard` (create, open, every file action, keyslot menu errors,
# sync bundles: create, make from a vault, open on two devices, mount,
# refusals; an aborted PANIC) and the deniable commands,
# which read secrets from a terminal only (create, mount, write, remount,
# read back). Driven by scripts/tui_drive.py; a step whose prompt does not
# appear prints the screen it was waiting on.
#
# Usage:
#   cargo build --release -p luksbox-cli
#   scripts/tui_scenarios.sh target/release/luksbox
#
# Runs in a temporary folder used as HOME (the wizard expands `~/`).
# Needs FUSE (Linux) or FUSE-T / macFUSE (macOS) for the mount steps,
# which are skipped without one.
# Menu positions are those of the current wizard: when a menu changes,
# update the matching step here.
set -u
# Portable to macOS (its stock bash 3.2, BSD tools and FUSE-T) as well as
# Linux: GNU `timeout`, `mountpoint` and `fusermount3` are not there.
if command -v timeout >/dev/null 2>&1; then TMO=(timeout 300); else TMO=(perl -e 'alarm shift; exec @ARGV or exit 127' 300); fi
is_mounted() {
  mountpoint -q "$1" 2>/dev/null && return 0
  local d; d=$(cd "$1" 2>/dev/null && pwd -P) || return 1
  mount | grep -qF " on $d ("
}
B=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
D=$(cd "$(dirname "$0")" && pwd)/tui_drive.py
W=$(mktemp -d "${TMPDIR:-/tmp}/luksbox-tui.XXXXXX")
cd "$W"
export HOME=$W LUKSBOX_SYNC_STATE_DIR=$W/state LUKSBOX_DEVICE_LABEL=Laptop
unset LUKSBOX_PASSPHRASE LUKSBOX_NEW_PASSPHRASE
PW='Tui-Test-Passphrase-Long-91'
PASS=0; FAIL=0
step() { # name json [expected-text-in-transcript...]
  local name=$1 json=$2; shift 2
  rm -f t.log
  if PTY_LOG=$W/t.log "${TMO[@]}" python3 -I "$D" "$json" -- "$B" "${CMD[@]}" >r.txt 2>&1; then
    local miss=""
    for n in "$@"; do grep -aqF -- "$n" t.log || miss="$miss [$n]"; done
    if [ -z "$miss" ]; then PASS=$((PASS+1)); return; fi
    echo "FAIL $name: missing$miss"
  else
    echo "FAIL $name:"; sed 's/^/  | /' r.txt | tail -12
  fi
  FAIL=$((FAIL+1))
}
DN=$'\x1b[B'; UP=$'\x1b[A'
# Mounting needs FUSE (Linux) or FUSE-T / macFUSE (macOS). On macOS the
# wizard first offers a private mountpoint under ~/Library (answered
# no), and FUSE-T, not luksbox, handles Ctrl-C in a foreground mount.
MP=(); INTR=("received interrupt, unmounting cleanly")
case $(uname) in
  Darwin)
    MP=("private mountpoint" n)
    if "$B" --version 2>/dev/null | grep -q 'FUSE backend: fuse-t' && [ -d '/Library/Application Support/fuse-t' ]; then
      CAN_MOUNT=1; INTR=()
    elif [ -e /dev/macfuse0 ]; then CAN_MOUNT=1; else CAN_MOUNT=0; fi;;
  *) if [ -e /dev/fuse ]; then CAN_MOUNT=1; else CAN_MOUNT=0; fi;;
esac
menu() { local s=""; for ((i=0;i<$1;i++)); do s+="$DN"; done; printf '%s\r' "$s"; }
j() { python3 -c 'import json,sys; print(json.dumps([[sys.argv[i], sys.argv[i+1]] for i in range(1, len(sys.argv), 2)]))' "$@"; }

echo "tui file content" > in.txt
echo "pre-existing local file" > out-exists.txt
CMD=(wizard)
j "What would you like to do" "$(menu 0)" "Vault type" $'\r' "Path for the new vault" "~/wiz.lbx"$'\r' \
  "detached-header sidecar" n "Cipher suite" $'\r' "On-disk metadata format" $'\r' \
  "Passphrase \\(most familiar" $'\r' "Pad each file" n "Hide exact file sizes" n \
  "Use header format v3" y "rollback-detection anchor" n "(?i)max" $'\r' \
  "Generate a strong random passphrase" n "Passphrase" "$PW"$'\r' "Confirm" "$PW"$'\r' \
  "Open and mount this vault now" n "What would you like to do" "$(menu 10)" > create.json
step "wizard: create (~ expanded, default path not pre-filled)" create.json "OK created $W/wiz.lbx"

j "What would you like to do" "$(menu 1)" "Path to vault" "~/wiz.lbx"$'\r' "detached header" n \
  "rollback-detection anchor" n "Passphrase" "$PW"$'\r' \
  "Vault action" "$(menu 2)" "Local file path" "in.txt"$'\r' "Destination inside vault" "/docs-in.txt"$'\r' \
  "Vault action" "$(menu 0)" "Directory to list" $'\r' \
  "Vault action" "$(menu 4)" "Directory path inside vault" "/sub"$'\r' \
  "Vault action" "$(menu 7)" "(?i)old|from|source|rename" "/docs-in.txt"$'\r' "(?i)new|to|dest" "/sub/moved.txt"$'\r' \
  "Vault action" "$(menu 3)" "File inside vault to extract" "/sub/moved.txt"$'\r' "Destination on local disk" "out-exists.txt"$'\r' "Overwrite it" n \
  "Vault action" "$(menu 3)" "File inside vault to extract" "/sub/moved.txt"$'\r' "Destination on local disk" "out-exists.txt"$'\r' "Overwrite it" y \
  "Vault action" "$(menu 1)" "File to print" "/sub/moved.txt"$'\r' \
  "Vault action" "$(menu 8)" "Keyslot action" $'\r' "Generate a strong random passphrase" y "I have stored the passphrase" n \
  "Keyslot action" "$UP"$'\r' \
  "Vault action" "$(menu 5)" "File to remove" "/sub/moved.txt"$'\r' "Remove /sub/moved.txt" y \
  "Vault action" "$(menu 6)" "(?i)directory" "/sub"$'\r' \
  "Vault action" "$(menu 15)" "What would you like to do" "$(menu 10)" > open.json
step "wizard: open and every file action" open.json \
  "OK wrote 17 bytes to /docs-in.txt" "OK created /sub" "OK renamed /docs-in.txt -> /sub/moved.txt" \
  "OK wrote 17 bytes to out-exists.txt" "FAIL aborted (passphrase not saved)" "OK removed /sub/moved.txt" "OK removed /sub"
[ "$(cat out-exists.txt)" = "tui file content" ] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL get overwrite content"; }

# A rotation stopped by a bad anchor and a mistyped mountpoint used to
# drop the vault (back to the main menu, unlock again): the next action
# must run in the same session.
j "What would you like to do" "$(menu 1)" "Path to vault" "~/wiz.lbx"$'\r' "detached header" n \
  "rollback-detection anchor" n "Passphrase" "$PW"$'\r' \
  "Vault action" "$(menu 9)" "Verify a rollback-detection anchor" y "Path to the anchor sidecar" "~/no-such.anchor"$'\r' \
  "Proceed with MVK rotation" y \
  "Vault action" "$(menu 13)" ${MP[@]+"${MP[@]}"} "Mount point" "~/no-such-dir"$'\r' \
  "Vault action" "$(menu 2)" "Local file path" "in.txt"$'\r' "Destination inside vault" "/after-errors.txt"$'\r' \
  "Vault action" "$(menu 15)" "What would you like to do" "$(menu 10)" > keep.json
step "wizard: rotate and mount errors keep the vault open" keep.json \
  "is not a directory" "OK wrote 17 bytes to /after-errors.txt"

# Vault size > change the file list region (64 MiB -> 32 MiB). The entry
# sits just above "Back" (the default), whether or not "Give back" shows.
LUKSBOX_PASSPHRASE=$PW "$B" create rz.lbx </dev/null >/dev/null 2>&1
LUKSBOX_PASSPHRASE=$PW "$B" put rz.lbx in.txt /in.txt </dev/null >/dev/null 2>&1
j "What would you like to do" "$(menu 1)" "Path to vault" "~/rz.lbx"$'\r' "detached header" n \
  "rollback-detection anchor" n "Passphrase" "$PW"$'\r' \
  "Vault action" "$(menu 11)" "Change the file list region \\(now 64" "$UP"$'\r' \
  "New file list region size" "$(menu 1)" "Change the file list region \\(now 32" $'\r' \
  "Vault action" "$(menu 15)" "What would you like to do" "$(menu 10)" > resize.json
step "wizard: resize the file list region" resize.json \
  "OK file list region resized from 64.0 MB to 32.0 MB" "File list:"
LUKSBOX_PASSPHRASE=$PW "$B" size rz.lbx </dev/null 2>/dev/null | grep -qF "Metadata:       32.0 MB" \
  && [ "$(LUKSBOX_PASSPHRASE=$PW "$B" cat rz.lbx /in.txt </dev/null 2>/dev/null)" = "tui file content" ] \
  && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL resized vault: region or content"; }

LUKSBOX_PASSPHRASE=$PW "$B" sync convert wiz.lbx wiz.lbxs --page-size 1M </dev/null >/dev/null 2>&1
j "What would you like to do" "$(menu 1)" "Path to vault" "~/wiz.lbxs"$'\r' "Passphrase" "$PW"$'\r' \
  "Vault action" "$(menu 9)" \
  "Vault action" "$(menu 8)" "Keyslot action" "$(menu 2)" "Keyslot action" "$UP"$'\r' \
  "Vault action" "$(menu 14)" \
  "Vault action" "$(menu 2)" "Local file path" "in.txt"$'\r' "Destination inside vault" "/from-wizard.txt"$'\r' \
  "Vault action" "$(menu 15)" "What would you like to do" "$(menu 10)" > bundle.json
step "wizard: sync bundle refusals and publish" bundle.json \
  "rotate-mvk is not available for a sync bundle" "adding a post-quantum keyslot is not available" \
  "panic is not available for a sync bundle" "published commit"
[ -e wiz.lbxs.hybrid ] && { FAIL=$((FAIL+1)); echo "FAIL a .hybrid file appeared next to the bundle"; } || PASS=$((PASS+1))

# Ctrl-C ends the wizard at once (SIGINT), without publishing: the change
# stays in this device's outbox and is published by the next open.
j "What would you like to do" "$(menu 1)" "Path to vault" "~/wiz.lbxs"$'\r' "Passphrase" "$PW"$'\r' \
  "Vault action" "$(menu 2)" "Local file path" "in.txt"$'\r' "Destination inside vault" "/before-ctrl-c.txt"$'\r' \
  "Vault action" $'\x03' "<EXIT>" -2 > ctrlc.json
step "wizard: Ctrl-C on an open bundle" ctrlc.json "OK wrote 17 bytes to /before-ctrl-c.txt"
LUKSBOX_PASSPHRASE=$PW "$B" sync status wiz.lbxs </dev/null >st1.txt 2>&1
LUKSBOX_PASSPHRASE=$PW "$B" ls wiz.lbxs / </dev/null >ls.txt 2>&1
LUKSBOX_PASSPHRASE=$PW "$B" sync status wiz.lbxs </dev/null >st2.txt 2>&1
if grep -q before-ctrl-c.txt ls.txt; then PASS=$((PASS+1)); else
  FAIL=$((FAIL+1)); echo "FAIL change made before Ctrl-C not kept:"; sed 's/^/  | /' st1.txt ls.txt st2.txt | tail -20; fi

# --- sync bundles: create, make from a vault, open, mount ---------------------
# The kind menu's "Hybrid passphrase + ML-KEM-768": item 3 when the FIDO2
# kinds are shown (the default build), item 1 without them.
HYB=3
"$B" --version 2>/dev/null | grep -qi 'fido2.*not compiled' && HYB=1
# Create > Sync bundle: a name without .lbxs gets it, none of the prompts
# a bundle has no use for is asked (detached header, metadata format,
# header format, anchor, maximum size), nothing is left in staging.
j "What would you like to do" "$(menu 0)" "Vault type" "$(menu 1)" \
  "Folder to create for the sync bundle" "~/wb"$'\r' "Cipher suite" $'\r' \
  "Passphrase \\(most familiar" $'\r' "Pad each file" n "Hide exact file sizes" n \
  "Generate a strong random passphrase" n "Passphrase" "$PW"$'\r' "Confirm" "$PW"$'\r' \
  "Open and mount this sync bundle now" n "What would you like to do" "$(menu 10)" > cb.json
step "wizard: create a sync bundle" cb.json "-> $W/wb.lbxs" \
  "OK created the vault for the sync bundle $W/wb.lbxs" "OK created the sync bundle $W/wb.lbxs"
if grep -aqE 'detached-header sidecar|On-disk metadata format|Use header format v3|rollback-detection anchor|Maximum vault size' t.log; then
  FAIL=$((FAIL+1)); echo "FAIL a prompt a sync bundle has no use for was asked"; else PASS=$((PASS+1)); fi
if [ -d wb.lbxs/h ] && [ -z "$(ls -A state/creating 2>/dev/null)" ] && [ ! -e wb.lbx ] && [ ! -e wb.lbxs.hybrid ]; then PASS=$((PASS+1)); else
  FAIL=$((FAIL+1)); echo "FAIL no bundle folder, or files left next to it or in staging:"; ls -la . state/creating 2>&1 | sed 's/^/  | /' | tail -20; fi
j "What would you like to do" "$(menu 0)" "Vault type" "$(menu 1)" \
  "Folder to create for the sync bundle" "~/wb.lbxs"$'\r' \
  "What would you like to do" "$(menu 0)" "Vault type" "$(menu 1)" \
  "Folder to create for the sync bundle" "~/no-such-dir/x"$'\r' \
  "What would you like to do" "$(menu 1)" "Path to vault" "~/wb.lbxs"$'\r' "Passphrase" "Not-The-Right-One-12"$'\r' \
  "What would you like to do" "$(menu 10)" > cbx.json
step "wizard: bundle refusals (existing folder, missing parent, wrong passphrase)" cbx.json \
  "already exists: pick a new folder name" "$W/no-such-dir is not a folder" \
  "no keyslot accepted the provided unlock material"
[ ! -e no-such-dir ] && [ -z "$(ls -A state/creating 2>/dev/null)" ] && PASS=$((PASS+1)) \
  || { FAIL=$((FAIL+1)); echo "FAIL a refused bundle create left something behind"; }
if [ $HYB = 3 ]; then
  # A kind that fails once the staging folder exists (FIDO2 with no
  # authenticator plugged in): no bundle, nothing left in staging.
  j "What would you like to do" "$(menu 0)" "Vault type" "$(menu 1)" \
    "Folder to create for the sync bundle" "~/wf.lbxs"$'\r' "Cipher suite" $'\r' \
    "Passphrase \\(most familiar" "$(menu 1)" "Pad each file" n "Hide exact file sizes" n \
    "What would you like to do" "$(menu 10)" > cbf.json
  step "wizard: a bundle create that fails leaves nothing" cbf.json "No FIDO2 authenticator detected"
  [ ! -e wf.lbxs ] && [ -z "$(ls -A state/creating 2>/dev/null)" ] && PASS=$((PASS+1)) \
    || { FAIL=$((FAIL+1)); echo "FAIL a failed bundle create left the bundle or its staging folder"; }
fi

# Open it (no detached-header or anchor question), every file action,
# the size view, and "make a sync bundle" refused on a bundle.
j "What would you like to do" "$(menu 1)" "Path to vault" "~/wb.lbxs"$'\r' "Passphrase" "$PW"$'\r' \
  "Vault action" "$(menu 2)" "Local file path" "in.txt"$'\r' "Destination inside vault" "/in.txt"$'\r' \
  "Vault action" "$(menu 4)" "Directory path inside vault" "/sub"$'\r' \
  "Vault action" "$(menu 7)" "(?i)old|from|source|rename" "/in.txt"$'\r' "(?i)new|to|dest" "/sub/in.txt"$'\r' \
  "Vault action" "$(menu 0)" "Directory to list" "/sub"$'\r' \
  "Vault action" "$(menu 1)" "File to print" "/sub/in.txt"$'\r' \
  "Vault action" "$(menu 3)" "File inside vault to extract" "/sub/in.txt"$'\r' "Destination on local disk" "wb-out.txt"$'\r' \
  "Vault action" "$(menu 11)" "Change the file list region" $'\r' \
  "Vault action" "$(menu 12)" \
  "Vault action" "$(menu 15)" "What would you like to do" "$(menu 10)" > ob.json
step "wizard: open the new bundle, every file action" ob.json \
  "OK wrote 17 bytes to /in.txt" "OK created /sub" "OK renamed /in.txt -> /sub/in.txt" \
  "OK wrote 17 bytes to wb-out.txt" "File list:" "this vault is already a sync bundle" "published commit"
[ "$(cat wb-out.txt 2>/dev/null)" = "tui file content" ] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL bundle get content"; }

# A second device (its own sync state) opens it, reads and writes; the
# first device sees the write.
j "What would you like to do" "$(menu 1)" "Path to vault" "~/wb.lbxs"$'\r' "Passphrase" "$PW"$'\r' \
  "Vault action" "$(menu 1)" "File to print" "/sub/in.txt"$'\r' \
  "Vault action" "$(menu 2)" "Local file path" "in.txt"$'\r' "Destination inside vault" "/from-desktop.txt"$'\r' \
  "Vault action" "$(menu 15)" "What would you like to do" "$(menu 10)" > ob2.json
LUKSBOX_SYNC_STATE_DIR=$W/state2 LUKSBOX_DEVICE_LABEL=Desktop step "wizard: a second device opens the bundle" ob2.json \
  "tui file content" "OK wrote 17 bytes to /from-desktop.txt" "published commit"
LUKSBOX_PASSPHRASE=$PW "$B" ls wb.lbxs / </dev/null 2>/dev/null | grep -q from-desktop.txt && PASS=$((PASS+1)) \
  || { FAIL=$((FAIL+1)); echo "FAIL the first device does not see the second device's file"; }
# A passphrase keyslot added on this device opens the bundle on the other.
PW2='Second-Tui-Passphrase-Long-37'
j "What would you like to do" "$(menu 1)" "Path to vault" "~/wb.lbxs"$'\r' "Passphrase" "$PW"$'\r' \
  "Vault action" "$(menu 8)" "Keyslot action" $'\r' "Generate a strong random passphrase" n \
  "New passphrase" "$PW2"$'\r' "Confirm" "$PW2"$'\r' "Argon2id strength" $'\r' \
  "Keyslot action" "$UP"$'\r' \
  "Vault action" "$(menu 15)" "What would you like to do" "$(menu 10)" > ks.json
step "wizard: add a passphrase keyslot to a bundle" ks.json "OK enrolled passphrase in slot 1" "published commit"
j "What would you like to do" "$(menu 1)" "Path to vault" "~/wb.lbxs"$'\r' "Passphrase" "$PW2"$'\r' \
  "Vault action" "$(menu 1)" "File to print" "/from-desktop.txt"$'\r' \
  "Vault action" "$(menu 15)" "What would you like to do" "$(menu 10)" > ks2.json
LUKSBOX_SYNC_STATE_DIR=$W/state2 LUKSBOX_DEVICE_LABEL=Desktop step "wizard: the other device opens it with the new keyslot" ks2.json \
  "tui file content"
j "What would you like to do" "$(menu 2)" "Path to vault or detached-header file" "~/wb.lbxs"$'\r' \
  "What would you like to do" "$(menu 10)" > ib.json
step "wizard: info on a bundle (no unlock)" ib.json "sync bundle (header and pages are objects in the folder)"

# Make a sync bundle from an open vault: an existing folder is refused
# and the vault stays open; then made, with the vault's files in it.
j "What would you like to do" "$(menu 1)" "Path to vault" "~/wiz.lbx"$'\r' "detached header" n \
  "rollback-detection anchor" n "Passphrase" "$PW"$'\r' \
  "Vault action" "$(menu 12)" "Folder to create for the sync bundle" "~/wiz.lbxs"$'\r' \
  "Vault action" "$(menu 12)" "Folder to create for the sync bundle" "~/made"$'\r' \
  "Vault action" "$(menu 15)" "What would you like to do" "$(menu 10)" > mb.json
step "wizard: make a sync bundle from an open vault" mb.json "already exists: pick a new folder name" \
  "-> $W/made.lbxs" "OK created the sync bundle $W/made.lbxs" "is unchanged"
[ "$(LUKSBOX_PASSPHRASE=$PW "$B" cat made.lbxs /after-errors.txt </dev/null 2>/dev/null)" = "tui file content" ] \
  && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL the made bundle lacks the vault's files"; }
# The same from a post-quantum vault (its public sidecar goes inside the
# bundle) and from a vault with a detached header (the bundle no longer
# needs the header file); the other device opens both in the wizard.
LUKSBOX_PASSPHRASE=$PW "$B" create tpq.lbx --kind hybrid-pq --pq-hybrid tpq.kyber --metadata-size 2M </dev/null >/dev/null 2>&1
LUKSBOX_PASSPHRASE=$PW "$B" put tpq.lbx --pq-hybrid tpq.kyber in.txt /in.txt </dev/null >/dev/null 2>&1
LUKSBOX_PASSPHRASE=$PW "$B" create tdet.lbx --header tdet.hdr --metadata-size 2M </dev/null >/dev/null 2>&1
LUKSBOX_PASSPHRASE=$PW "$B" put tdet.lbx --header tdet.hdr in.txt /in.txt </dev/null >/dev/null 2>&1
j "What would you like to do" "$(menu 1)" "Path to vault" "~/tpq.lbx"$'\r' "detached header" n \
  "rollback-detection anchor" n "Path to the Kyber seed" "~/tpq.kyber"$'\r' "Passphrase" "$PW"$'\r' \
  "Vault action" "$(menu 12)" "Folder to create for the sync bundle" $'\r' \
  "Vault action" "$(menu 15)" \
  "What would you like to do" "$(menu 1)" "Path to vault" "~/tdet.lbx"$'\r' "detached header" y \
  "Path to the header sidecar" "~/tdet.hdr"$'\r' "rollback-detection anchor" n "Passphrase" "$PW"$'\r' \
  "Vault action" "$(menu 12)" "Folder to create for the sync bundle" $'\r' \
  "Vault action" "$(menu 15)" "What would you like to do" "$(menu 10)" > mb2.json
step "wizard: make sync bundles from a post-quantum and a detached-header vault" mb2.json \
  "OK created the sync bundle $W/tpq.lbxs" "OK created the sync bundle $W/tdet.lbxs"
[ ! -e tpq.lbxs.hybrid ] && [ ! -e tdet.lbxs.hdr ] && PASS=$((PASS+1)) \
  || { FAIL=$((FAIL+1)); echo "FAIL a sidecar file appeared next to a made bundle"; }
j "What would you like to do" "$(menu 1)" "Path to vault" "~/tpq.lbxs"$'\r' \
  "Path to the Kyber seed" "~/tpq.kyber"$'\r' "Passphrase" "$PW"$'\r' \
  "Vault action" "$(menu 1)" "File to print" "/in.txt"$'\r' \
  "Vault action" "$(menu 15)" \
  "What would you like to do" "$(menu 1)" "Path to vault" "~/tdet.lbxs"$'\r' "Passphrase" "$PW"$'\r' \
  "Vault action" "$(menu 1)" "File to print" "/in.txt"$'\r' \
  "Vault action" "$(menu 15)" "What would you like to do" "$(menu 10)" > ob3.json
LUKSBOX_SYNC_STATE_DIR=$W/state2 LUKSBOX_DEVICE_LABEL=Desktop step "wizard: the other device opens the made bundles" ob3.json \
  "tui file content"
[ "$(grep -ac 'tui file content' t.log)" -ge 2 ] && PASS=$((PASS+1)) \
  || { FAIL=$((FAIL+1)); echo "FAIL the other device did not read both made bundles"; }

# A post-quantum bundle: the public Kyber sidecar goes inside the bundle,
# and a second device opens it with the seed file.
j "What would you like to do" "$(menu 0)" "Vault type" "$(menu 1)" \
  "Folder to create for the sync bundle" "~/wpq.lbxs"$'\r' "Cipher suite" $'\r' \
  "Passphrase \\(most familiar" "$(menu $HYB)" "Path for the Kyber seed file" "~/wpq.kyber"$'\r' \
  "Generate a strong random passphrase" n "Passphrase" "$PW"$'\r' "Confirm" "$PW"$'\r' \
  "Open and mount this sync bundle now" n "What would you like to do" "$(menu 10)" > cpq.json
step "wizard: create a post-quantum sync bundle" cpq.json "(hybrid-pq, ML-KEM-768)" \
  "kept inside the bundle" "OK created the sync bundle $W/wpq.lbxs"
[ -f wpq.kyber ] && [ ! -e wpq.lbxs.hybrid ] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL post-quantum bundle: seed missing or sidecar next to the bundle"; }
j "What would you like to do" "$(menu 1)" "Path to vault" "~/wpq.lbxs"$'\r' \
  "Path to the Kyber seed" "~/wpq.kyber"$'\r' "Passphrase" "$PW"$'\r' \
  "Vault action" "$(menu 2)" "Local file path" "in.txt"$'\r' "Destination inside vault" "/pq.txt"$'\r' \
  "Vault action" "$(menu 15)" "What would you like to do" "$(menu 10)" > opq.json
LUKSBOX_SYNC_STATE_DIR=$W/state2 LUKSBOX_DEVICE_LABEL=Desktop step "wizard: a second device opens the post-quantum bundle" opq.json \
  "OK wrote 17 bytes to /pq.txt" "published commit"

# FIDO2 bundles (wrap, direct, FIDO2 + ML-KEM-768, made from a FIDO2
# vault), with a debug build's software authenticator standing in for the
# security key (LUKSBOX_TEST_FIDO2_MOCK, same seed = same key). Release
# builds ignore the variable: then these steps are skipped (run the script
# with a debug build and LUKSBOX_TEST_FAST_KDF=1 to include them).
KEY=$(printf '1%.0s' $(seq 1 64)); OTHER_KEY=$(printf '2%.0s' $(seq 1 64))
if LUKSBOX_TEST_FIDO2_MOCK=$KEY "$B" list-fido2-devices </dev/null 2>/dev/null | grep -q "software test authenticator"; then
  export LUKSBOX_TEST_FIDO2_MOCK=$KEY
  j "What would you like to do" "$(menu 0)" "Vault type" "$(menu 1)" \
    "Folder to create for the sync bundle" "~/wfido.lbxs"$'\r' "Cipher suite" $'\r' \
    "Passphrase \\(most familiar" "$(menu 1)" "Pad each file" n "Hide exact file sizes" n \
    "FIDO2 PIN" "1234"$'\r' "Open and mount this sync bundle now" n \
    "What would you like to do" "$(menu 0)" "Vault type" "$(menu 1)" \
    "Folder to create for the sync bundle" "~/wfd.lbxs"$'\r' "Cipher suite" $'\r' \
    "Passphrase \\(most familiar" "$(menu 2)" "Proceed with FIDO2-direct" y "FIDO2 PIN" "1234"$'\r' \
    "Enroll a passphrase backup keyslot now" n "Open and mount this sync bundle now" n \
    "What would you like to do" "$(menu 0)" "Vault type" "$(menu 1)" \
    "Folder to create for the sync bundle" "~/wfpq.lbxs"$'\r' "Cipher suite" $'\r' \
    "Passphrase \\(most familiar" "$(menu 4)" "Kyber seed file" "~/wfpq.kyber"$'\r' "FIDO2 PIN" "1234"$'\r' \
    "Generate a strong random passphrase" n "Seed-file passphrase" "$PW"$'\r' "Confirm" "$PW"$'\r' \
    "Open and mount this sync bundle now" n "What would you like to do" "$(menu 10)" > cfido.json
  step "wizard: create FIDO2, FIDO2-direct and FIDO2 + ML-KEM bundles (software key)" cfido.json \
    "OK created the sync bundle $W/wfido.lbxs" "OK created the sync bundle $W/wfd.lbxs" \
    "OK created the sync bundle $W/wfpq.lbxs" "kept inside the bundle"
  [ -d wfido.lbxs/h ] && [ -d wfd.lbxs/h ] && [ -d wfpq.lbxs/h ] && [ -f wfpq.kyber ] && [ ! -e wfpq.lbxs.hybrid ] \
    && [ -z "$(ls -A state/creating 2>/dev/null)" ] && PASS=$((PASS+1)) \
    || { FAIL=$((FAIL+1)); echo "FAIL FIDO2 bundles: folders, seed, sidecar or staging not as expected"; }
  # A FIDO2 vault made into a bundle from the vault menu.
  LUKSBOX_FIDO2_PIN=1234 "$B" create tfido.lbx --kind fido2 --metadata-size 2M </dev/null >/dev/null 2>&1
  j "What would you like to do" "$(menu 1)" "Path to vault" "~/tfido.lbx"$'\r' "detached header" n \
    "rollback-detection anchor" n "FIDO2 PIN" "1234"$'\r' \
    "Vault action" "$(menu 2)" "Local file path" "in.txt"$'\r' "Destination inside vault" "/in.txt"$'\r' \
    "Vault action" "$(menu 12)" "Folder to create for the sync bundle" $'\r' \
    "Vault action" "$(menu 15)" "What would you like to do" "$(menu 10)" > mfido.json
  step "wizard: make a sync bundle from a FIDO2 vault" mfido.json "OK created the sync bundle $W/tfido.lbxs"
  # The other device opens each with the same key: every file action on
  # the FIDO2 one, a write on the others.
  j "What would you like to do" "$(menu 1)" "Path to vault" "~/wfido.lbxs"$'\r' "FIDO2 PIN" "1234"$'\r' \
    "Vault action" "$(menu 2)" "Local file path" "in.txt"$'\r' "Destination inside vault" "/fido.txt"$'\r' \
    "Vault action" "$(menu 0)" "Directory to list" $'\r' \
    "Vault action" "$(menu 1)" "File to print" "/fido.txt"$'\r' \
    "Vault action" "$(menu 15)" \
    "What would you like to do" "$(menu 1)" "Path to vault" "~/wfd.lbxs"$'\r' "FIDO2 PIN" "1234"$'\r' \
    "Vault action" "$(menu 2)" "Local file path" "in.txt"$'\r' "Destination inside vault" "/fd.txt"$'\r' \
    "Vault action" "$(menu 15)" \
    "What would you like to do" "$(menu 1)" "Path to vault" "~/wfpq.lbxs"$'\r' \
    "Path to the Kyber seed" "~/wfpq.kyber"$'\r' "FIDO2 PIN" "1234"$'\r' ".kyber seed-file passphrase" "$PW"$'\r' \
    "Vault action" "$(menu 2)" "Local file path" "in.txt"$'\r' "Destination inside vault" "/fpq.txt"$'\r' \
    "Vault action" "$(menu 15)" \
    "What would you like to do" "$(menu 1)" "Path to vault" "~/tfido.lbxs"$'\r' "FIDO2 PIN" "1234"$'\r' \
    "Vault action" "$(menu 1)" "File to print" "/in.txt"$'\r' \
    "Vault action" "$(menu 15)" "What would you like to do" "$(menu 10)" > ofido.json
  LUKSBOX_SYNC_STATE_DIR=$W/state2 LUKSBOX_DEVICE_LABEL=Desktop step "wizard: the other device opens the FIDO2 bundles" ofido.json \
    "OK wrote 17 bytes to /fido.txt" "OK wrote 17 bytes to /fd.txt" "OK wrote 17 bytes to /fpq.txt" "tui file content"
  # Another key does not open it.
  j "What would you like to do" "$(menu 1)" "Path to vault" "~/wfido.lbxs"$'\r' "FIDO2 PIN" "1234"$'\r' \
    "What would you like to do" "$(menu 10)" > ofx.json
  LUKSBOX_TEST_FIDO2_MOCK=$OTHER_KEY step "wizard: another key does not open the FIDO2 bundle" ofx.json \
    "keyslot authentication failed"
  unset LUKSBOX_TEST_FIDO2_MOCK
  [ "$(LUKSBOX_TEST_FIDO2_MOCK=$KEY LUKSBOX_FIDO2_PIN=1234 "$B" cat wfido.lbxs --fido2 /fido.txt </dev/null 2>/dev/null)" = "tui file content" ] \
    && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL the first device does not read the FIDO2 bundle's new file"; }
else
  echo "note: FIDO2 bundle steps skipped (a release build has no software authenticator)"
fi

# TPM 2.0 bundles, only with a TPM given through TCTI_NAME_CONF (swtpm in
# a container, see TESTING.md) and a TPM-enabled build: a TPM bundle with a
# backup passphrase and a single-slot TPM + PIN one made in the wizard, a
# TPM vault made into a bundle; the other device opens each with the TPM.
TPM_OK=0
if [ -n "${TCTI_NAME_CONF:-}" ]; then
  LUKSBOX_PASSPHRASE=$PW "$B" create tprobe.lbx --metadata-size 2M </dev/null >/dev/null 2>&1
  LUKSBOX_PASSPHRASE=$PW "$B" enroll tprobe.lbx --kind tpm2 </dev/null >/dev/null 2>&1 && TPM_OK=1
fi
if [ $TPM_OK = 1 ]; then
  TPMI=7; [ $HYB = 1 ] && TPMI=3   # "TPM 2.0 (this machine; ...)" in the kind menu
  j "What would you like to do" "$(menu 0)" "Vault type" "$(menu 1)" \
    "Folder to create for the sync bundle" "~/wtpm.lbxs"$'\r' "Cipher suite" $'\r' \
    "Passphrase \\(most familiar" "$(menu $TPMI)" "Continue with TPM-backed creation" y \
    "Skip bootstrap passphrase" n "Generate a strong random passphrase" n \
    "Backup passphrase" "$PW"$'\r' "Confirm" "$PW"$'\r' "storage root key" n \
    "Revoke the backup passphrase now" n "Open and mount this sync bundle now" n \
    "What would you like to do" "$(menu 0)" "Vault type" "$(menu 1)" \
    "Folder to create for the sync bundle" "~/wtpin.lbxs"$'\r' "Cipher suite" $'\r' \
    "Passphrase \\(most familiar" "$(menu $((TPMI+1)))" "Continue with TPM-backed creation" y \
    "Skip bootstrap passphrase" y "TPM PIN" "2468"$'\r' "confirm" "2468"$'\r' \
    "Open and mount this sync bundle now" n "What would you like to do" "$(menu 10)" > ctpm.json
  step "wizard: create TPM and single-slot TPM + PIN sync bundles" ctpm.json \
    "OK created the sync bundle $W/wtpm.lbxs" "OK created the sync bundle $W/wtpin.lbxs"
  LUKSBOX_PASSPHRASE=$PW "$B" create tt.lbx --metadata-size 2M </dev/null >/dev/null 2>&1
  LUKSBOX_PASSPHRASE=$PW "$B" put tt.lbx in.txt /in.txt </dev/null >/dev/null 2>&1
  LUKSBOX_PASSPHRASE=$PW "$B" enroll tt.lbx --kind tpm2 </dev/null >/dev/null 2>&1
  j "What would you like to do" "$(menu 1)" "Path to vault" "~/tt.lbx"$'\r' "detached header" n \
    "rollback-detection anchor" n "How would you like to unlock" "$(menu 1)" \
    "Vault action" "$(menu 12)" "Folder to create for the sync bundle" $'\r' \
    "Vault action" "$(menu 15)" "What would you like to do" "$(menu 10)" > mtpm.json
  step "wizard: make a sync bundle from a TPM vault (opened with the TPM)" mtpm.json \
    "OK created the sync bundle $W/tt.lbxs"
  j "What would you like to do" "$(menu 1)" "Path to vault" "~/wtpm.lbxs"$'\r' "How would you like to unlock" "$(menu 1)" \
    "Vault action" "$(menu 2)" "Local file path" "in.txt"$'\r' "Destination inside vault" "/tpm.txt"$'\r' \
    "Vault action" "$(menu 15)" \
    "What would you like to do" "$(menu 1)" "Path to vault" "~/wtpin.lbxs"$'\r' "TPM PIN" "2468"$'\r' \
    "Vault action" "$(menu 2)" "Local file path" "in.txt"$'\r' "Destination inside vault" "/pin.txt"$'\r' \
    "Vault action" "$(menu 15)" \
    "What would you like to do" "$(menu 1)" "Path to vault" "~/tt.lbxs"$'\r' "How would you like to unlock" "$(menu 1)" \
    "Vault action" "$(menu 1)" "File to print" "/in.txt"$'\r' \
    "Vault action" "$(menu 15)" "What would you like to do" "$(menu 10)" > otpm.json
  LUKSBOX_SYNC_STATE_DIR=$W/state2 LUKSBOX_DEVICE_LABEL=Desktop step "wizard: the other device opens the TPM bundles with the TPM" otpm.json \
    "OK wrote 17 bytes to /tpm.txt" "OK wrote 17 bytes to /pin.txt" "tui file content"
  j "What would you like to do" "$(menu 1)" "Path to vault" "~/wtpin.lbxs"$'\r' "TPM PIN" "0000"$'\r' \
    "What would you like to do" "$(menu 10)" > otpmx.json
  step "wizard: a wrong TPM PIN does not open the bundle" otpmx.json "FAIL"
  if LUKSBOX_TEST_FIDO2_MOCK=$KEY "$B" list-fido2-devices </dev/null 2>/dev/null | grep -q "software test authenticator"; then
    # Fused TPM + FIDO2 (single slot) with the software key: made in the
    # wizard, opened by the other device, not with another key.
    j "What would you like to do" "$(menu 0)" "Vault type" "$(menu 1)" \
      "Folder to create for the sync bundle" "~/wtf.lbxs"$'\r' "Cipher suite" $'\r' \
      "Passphrase \\(most familiar" "$(menu $((TPMI+2)))" "Continue with TPM-backed creation" y \
      "Add a recovery passphrase" n "storage root key" n "FIDO2 PIN" "1234"$'\r' \
      "Open and mount this sync bundle now" n "What would you like to do" "$(menu 10)" > ctf.json
    LUKSBOX_TEST_FIDO2_MOCK=$KEY step "wizard: create a fused TPM + FIDO2 sync bundle" ctf.json \
      "OK created the sync bundle $W/wtf.lbxs"
    j "What would you like to do" "$(menu 1)" "Path to vault" "~/wtf.lbxs"$'\r' "FIDO2 PIN" "1234"$'\r' \
      "Vault action" "$(menu 2)" "Local file path" "in.txt"$'\r' "Destination inside vault" "/tf.txt"$'\r' \
      "Vault action" "$(menu 15)" "What would you like to do" "$(menu 10)" > otf.json
    LUKSBOX_TEST_FIDO2_MOCK=$KEY LUKSBOX_SYNC_STATE_DIR=$W/state2 LUKSBOX_DEVICE_LABEL=Desktop \
      step "wizard: the other device opens the fused TPM + FIDO2 bundle" otf.json "OK wrote 17 bytes to /tf.txt"
    j "What would you like to do" "$(menu 1)" "Path to vault" "~/wtf.lbxs"$'\r' "FIDO2 PIN" "1234"$'\r' \
      "What would you like to do" "$(menu 10)" > otfx.json
    LUKSBOX_TEST_FIDO2_MOCK=$OTHER_KEY step "wizard: another key does not open the fused bundle" otfx.json "FAIL"
  fi
  [ -z "$(ls -A state/creating 2>/dev/null)" ] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL TPM bundle creates left staging folders"; }
else
  echo "note: TPM bundle steps skipped (set TCTI_NAME_CONF to a TPM, e.g. swtpm, with a TPM-enabled build)"
fi

# Secure Enclave bundles, only on a Mac with a Secure Enclave and a build
# with --features hardware (probed by enrolling a keyslot): Secure
# Enclave, Secure Enclave + passphrase and hybrid Secure Enclave + ML-KEM
# bundles made in the wizard and a Secure Enclave vault made into a
# bundle; the other device opens each with the Secure Enclave and a wrong
# slot passphrase is refused. SEP + FIDO2 with a debug build's software
# key; Touch ID only with LUKSBOX_TEST_TOUCH_ID=1 (it needs a finger).
SEP_OK=0
if [ "$(uname)" = Darwin ]; then
  LUKSBOX_PASSPHRASE=$PW "$B" create sprobe.lbx --metadata-size 2M </dev/null >/dev/null 2>&1
  LUKSBOX_PASSPHRASE=$PW "$B" enroll sprobe.lbx --kind sep </dev/null >/dev/null 2>&1 && SEP_OK=1
fi
if [ $SEP_OK = 1 ]; then
  # Kind menu positions on macOS: with the FIDO2 kinds shown, Secure
  # Enclave is item 7, then Touch ID, hybrid 768 / 1024, fused FIDO2,
  # fused passphrase; without them the FIDO2 rows are hidden.
  if [ $HYB = 3 ]; then SEPI=7; SEPPW=12; SEPF=11; else SEPI=3; SEPPW=7; SEPF=; fi
  SEPHY=$((SEPI+2)); SEPTID=$((SEPI+1))
  PW2='Second-Tui-Passphrase-Long-37'
  j "What would you like to do" "$(menu 0)" "Vault type" "$(menu 1)" \
    "Folder to create for the sync bundle" "~/wsep.lbxs"$'\r' "Cipher suite" $'\r' \
    "Passphrase \\(most familiar" "$(menu $SEPI)" "Continue with Secure Enclave-backed creation" y \
    "Generate a strong random passphrase" n "Backup passphrase" "$PW"$'\r' "Confirm" "$PW"$'\r' \
    "Revoke the backup passphrase now" n "Open and mount this sync bundle now" n \
    "What would you like to do" "$(menu 0)" "Vault type" "$(menu 1)" \
    "Folder to create for the sync bundle" "~/wsp.lbxs"$'\r' "Cipher suite" $'\r' \
    "Passphrase \\(most familiar" "$(menu $SEPPW)" "Continue with Secure Enclave-backed creation" y \
    "Generate a strong random passphrase" n "Backup passphrase" "$PW"$'\r' "Confirm" "$PW"$'\r' \
    "Generate a strong random passphrase" n "New slot passphrase" "$PW2"$'\r' "Confirm" "$PW2"$'\r' \
    "Revoke the backup passphrase now" n "Open and mount this sync bundle now" n \
    "What would you like to do" "$(menu 0)" "Vault type" "$(menu 1)" \
    "Folder to create for the sync bundle" "~/wsq.lbxs"$'\r' "Cipher suite" $'\r' \
    "Passphrase \\(most familiar" "$(menu $SEPHY)" "Continue with Secure Enclave-backed creation" y \
    "Generate a strong random passphrase" n "Backup passphrase" "$PW"$'\r' "Confirm" "$PW"$'\r' \
    "Path for the new Kyber seed" "~/wsq.kyber"$'\r' \
    "Generate a strong random passphrase" n "Seed-file passphrase" "$PW"$'\r' "Confirm" "$PW"$'\r' \
    "Revoke the backup passphrase now" n "Open and mount this sync bundle now" n \
    "What would you like to do" "$(menu 10)" > csep.json
  step "wizard: create Secure Enclave, SEP + passphrase and hybrid SEP sync bundles" csep.json \
    "OK created the sync bundle $W/wsep.lbxs" "OK created the sync bundle $W/wsp.lbxs" \
    "OK created the sync bundle $W/wsq.lbxs"
  [ -f wsq.kyber ] && [ ! -e wsq.lbxs.hybrid ] && [ -z "$(ls -A state/creating 2>/dev/null)" ] && PASS=$((PASS+1)) \
    || { FAIL=$((FAIL+1)); echo "FAIL Secure Enclave bundles: seed, sidecar or staging not as expected"; }
  LUKSBOX_PASSPHRASE=$PW "$B" create ts.lbx --metadata-size 2M </dev/null >/dev/null 2>&1
  LUKSBOX_PASSPHRASE=$PW "$B" put ts.lbx in.txt /in.txt </dev/null >/dev/null 2>&1
  LUKSBOX_PASSPHRASE=$PW "$B" enroll ts.lbx --kind sep </dev/null >/dev/null 2>&1
  j "What would you like to do" "$(menu 1)" "Path to vault" "~/ts.lbx"$'\r' "detached header" n \
    "rollback-detection anchor" n "How would you like to unlock" "$(menu 1)" \
    "Vault action" "$(menu 12)" "Folder to create for the sync bundle" $'\r' \
    "Vault action" "$(menu 15)" "What would you like to do" "$(menu 10)" > msep.json
  step "wizard: make a sync bundle from a Secure Enclave vault (opened with it)" msep.json \
    "OK created the sync bundle $W/ts.lbxs"
  j "What would you like to do" "$(menu 1)" "Path to vault" "~/wsep.lbxs"$'\r' "How would you like to unlock" "$(menu 1)" \
    "Vault action" "$(menu 2)" "Local file path" "in.txt"$'\r' "Destination inside vault" "/sep.txt"$'\r' \
    "Vault action" "$(menu 15)" \
    "What would you like to do" "$(menu 1)" "Path to vault" "~/wsp.lbxs"$'\r' "How would you like to unlock" "$(menu 1)" \
    "Slot passphrase" "$PW2"$'\r' \
    "Vault action" "$(menu 2)" "Local file path" "in.txt"$'\r' "Destination inside vault" "/sp.txt"$'\r' \
    "Vault action" "$(menu 15)" \
    "What would you like to do" "$(menu 1)" "Path to vault" "~/wsq.lbxs"$'\r' "How would you like to unlock" "$(menu 1)" \
    "Path to the Kyber seed" "~/wsq.kyber"$'\r' ".kyber seed-file passphrase" "$PW"$'\r' \
    "Vault action" "$(menu 2)" "Local file path" "in.txt"$'\r' "Destination inside vault" "/sq.txt"$'\r' \
    "Vault action" "$(menu 15)" \
    "What would you like to do" "$(menu 1)" "Path to vault" "~/ts.lbxs"$'\r' "How would you like to unlock" "$(menu 1)" \
    "Vault action" "$(menu 1)" "File to print" "/in.txt"$'\r' \
    "Vault action" "$(menu 15)" "What would you like to do" "$(menu 10)" > osep.json
  LUKSBOX_SYNC_STATE_DIR=$W/state2 LUKSBOX_DEVICE_LABEL=Desktop step "wizard: the other device opens the Secure Enclave bundles" osep.json \
    "OK wrote 17 bytes to /sep.txt" "OK wrote 17 bytes to /sp.txt" "OK wrote 17 bytes to /sq.txt" "tui file content"
  j "What would you like to do" "$(menu 1)" "Path to vault" "~/wsp.lbxs"$'\r' "How would you like to unlock" "$(menu 1)" \
    "Slot passphrase" "Not-The-Right-One-12"$'\r' "What would you like to do" "$(menu 10)" > osepx.json
  step "wizard: a wrong slot passphrase does not open the SEP + passphrase bundle" osepx.json "FAIL"
  if [ -n "$SEPF" ] && LUKSBOX_TEST_FIDO2_MOCK=$KEY "$B" list-fido2-devices </dev/null 2>/dev/null | grep -q "software test authenticator"; then
    j "What would you like to do" "$(menu 0)" "Vault type" "$(menu 1)" \
      "Folder to create for the sync bundle" "~/wsf.lbxs"$'\r' "Cipher suite" $'\r' \
      "Passphrase \\(most familiar" "$(menu $SEPF)" "Continue with Secure Enclave-backed creation" y \
      "Generate a strong random passphrase" n "Backup passphrase" "$PW"$'\r' "Confirm" "$PW"$'\r' \
      "FIDO2 PIN" "1234"$'\r' "Revoke the backup passphrase now" n "Open and mount this sync bundle now" n \
      "What would you like to do" "$(menu 10)" > csf.json
    LUKSBOX_TEST_FIDO2_MOCK=$KEY step "wizard: create a Secure Enclave + FIDO2 sync bundle" csf.json \
      "OK created the sync bundle $W/wsf.lbxs"
    j "What would you like to do" "$(menu 1)" "Path to vault" "~/wsf.lbxs"$'\r' "How would you like to unlock" "$(menu 1)" \
      "FIDO2 PIN" "1234"$'\r' \
      "Vault action" "$(menu 2)" "Local file path" "in.txt"$'\r' "Destination inside vault" "/sf.txt"$'\r' \
      "Vault action" "$(menu 15)" "What would you like to do" "$(menu 10)" > osf.json
    LUKSBOX_TEST_FIDO2_MOCK=$KEY LUKSBOX_SYNC_STATE_DIR=$W/state2 LUKSBOX_DEVICE_LABEL=Desktop \
      step "wizard: the other device opens the Secure Enclave + FIDO2 bundle" osf.json "OK wrote 17 bytes to /sf.txt"
  fi
  if [ "${LUKSBOX_TEST_TOUCH_ID:-}" = 1 ]; then
    echo "Touch ID steps: touch the sensor when asked"
    j "What would you like to do" "$(menu 0)" "Vault type" "$(menu 1)" \
      "Folder to create for the sync bundle" "~/wst.lbxs"$'\r' "Cipher suite" $'\r' \
      "Passphrase \\(most familiar" "$(menu $SEPTID)" "Continue with Secure Enclave-backed creation" y \
      "Generate a strong random passphrase" n "Backup passphrase" "$PW"$'\r' "Confirm" "$PW"$'\r' \
      "Revoke the backup passphrase now" n "Open and mount this sync bundle now" n \
      "What would you like to do" "$(menu 1)" "Path to vault" "~/wst.lbxs"$'\r' "How would you like to unlock" "$(menu 1)" \
      "Vault action" "$(menu 0)" "Directory to list" $'\r' \
      "Vault action" "$(menu 15)" "What would you like to do" "$(menu 10)" > cst.json
    step "wizard: create and open a Secure Enclave + Touch ID sync bundle" cst.json \
      "OK created the sync bundle $W/wst.lbxs"
  fi
else
  [ "$(uname)" = Darwin ] && echo "note: Secure Enclave bundle steps skipped (no Secure Enclave, or a build without --features hardware)"
fi

if [ $CAN_MOUNT = 1 ]; then
  # Create a bundle and mount it at once (opened with the key in hand):
  # a file written through the mount is published when it ends.
  mkdir -p m3
  ( for i in $(seq 1 900); do if is_mounted m3; then sleep 1; echo "written while mounted" > m3/mounted.txt; break; fi; sleep 0.1; done ) &
  WR=$!
  j "What would you like to do" "$(menu 0)" "Vault type" "$(menu 1)" \
    "Folder to create for the sync bundle" "~/wm.lbxs"$'\r' "Cipher suite" $'\r' \
    "Passphrase \\(most familiar" $'\r' "Pad each file" n "Hide exact file sizes" n \
    "Generate a strong random passphrase" n "Passphrase" "$PW"$'\r' "Confirm" "$PW"$'\r' \
    "Open and mount this sync bundle now" y ${MP[@]+"${MP[@]}"} "Mount point" "$W/m3"$'\r' \
    "Mount in background" n "Eager flush" n "<SLEEP>" 5 "in the foreground" $'\x03' \
    "What would you like to do" "$(menu 10)" > cbm.json
  step "wizard: create a sync bundle and mount it at once" cbm.json \
    "OK created the sync bundle $W/wm.lbxs" ${INTR[@]+"${INTR[@]}"}
  kill $WR 2>/dev/null; wait $WR 2>/dev/null
  if is_mounted m3; then FAIL=$((FAIL+1)); echo "FAIL the new bundle is still mounted"; "$B" umount m3 </dev/null >/dev/null 2>&1; else PASS=$((PASS+1)); fi
  [ "$(LUKSBOX_PASSPHRASE=$PW "$B" cat wm.lbxs /mounted.txt </dev/null 2>/dev/null)" = "written while mounted" ] \
    && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL a file written through the new bundle's mount was not kept"; }
  # Open a bundle and mount it from the vault menu: the write through the
  # mount reaches the other device.
  mkdir -p m4
  ( for i in $(seq 1 900); do if is_mounted m4; then sleep 1; echo "written while mounted" > m4/mounted2.txt; break; fi; sleep 0.1; done ) &
  WR=$!
  j "What would you like to do" "$(menu 1)" "Path to vault" "~/wb.lbxs"$'\r' "Passphrase" "$PW"$'\r' \
    "Vault action" "$(menu 13)" ${MP[@]+"${MP[@]}"} "Mount point" "$W/m4"$'\r' \
    "Mount in background" n "Eager flush" n "<SLEEP>" 5 "in the foreground" $'\x03' \
    "What would you like to do" "$(menu 10)" > omb.json
  step "wizard: open a bundle and mount it" omb.json ${INTR[@]+"${INTR[@]}"}
  kill $WR 2>/dev/null; wait $WR 2>/dev/null
  if is_mounted m4; then FAIL=$((FAIL+1)); echo "FAIL the bundle is still mounted"; "$B" umount m4 </dev/null >/dev/null 2>&1; else PASS=$((PASS+1)); fi
  [ "$(LUKSBOX_SYNC_STATE_DIR=$W/state2 LUKSBOX_DEVICE_LABEL=Desktop LUKSBOX_PASSPHRASE=$PW "$B" cat wb.lbxs /mounted2.txt </dev/null 2>/dev/null)" = "written while mounted" ] \
    && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL a file written through the bundle's mount did not reach the other device"; }
fi

j "What would you like to do" "$(menu 1)" "Path to vault" "~/wiz.lbx"$'\r' "detached header" n \
  "rollback-detection anchor" n "Passphrase" "$PW"$'\r' "Vault action" "$(menu 14)" \
  "ALSO overwrite the entire vault data area" n "(?i)type literally" "not the phrase"$'\r' \
  "What would you like to do" "$(menu 10)" > panic.json
step "wizard: aborted PANIC changes nothing" panic.json "panic aborted; the vault was not changed"
LUKSBOX_PASSPHRASE=$PW "$B" ls wiz.lbx / </dev/null >/dev/null 2>&1 && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL vault does not open after an aborted panic"; }

if [ $CAN_MOUNT = 1 ]; then
  # Two foreground mounts in one wizard run, each ended with Ctrl-C: the
  # second Ctrl-C must unmount the second mountpoint (it used to target
  # the first one, and the wizard then hung on the second mount), and the
  # second mount is offered in the foreground (a background one cannot
  # fork any more).
  mkdir -p m1 m2
  j "What would you like to do" "$(menu 1)" "Path to vault" "~/wiz.lbx"$'\r' "detached header" n \
    "rollback-detection anchor" n "Passphrase" "$PW"$'\r' "Vault action" "$(menu 13)" \
    ${MP[@]+"${MP[@]}"} "Mount point" "$W/m1"$'\r' "Mount in background" n "Eager flush" n "<SLEEP>" 3 "in the foreground" $'\x03' \
    "What would you like to do" "$(menu 1)" "Path to vault" "~/wiz.lbx"$'\r' "detached header" n \
    "rollback-detection anchor" n "Passphrase" "$PW"$'\r' "Vault action" "$(menu 13)" \
    ${MP[@]+"${MP[@]}"} "Mount point" "$W/m2"$'\r' "Eager flush" n "<SLEEP>" 3 "in the foreground" $'\x03' \
    "What would you like to do" "$(menu 10)" > mounts.json
  CMD=(wizard)
  step "wizard: two foreground mounts, Ctrl-C ends each" mounts.json \
    "a background mount needs a fresh process" ${INTR[@]+"${INTR[@]}"}
  if is_mounted m1 || is_mounted m2; then
    FAIL=$((FAIL+1)); echo "FAIL a wizard mount is still mounted"
    "$B" umount m1 </dev/null >/dev/null 2>&1; "$B" umount m2 </dev/null >/dev/null 2>&1
  else
    PASS=$((PASS+1))
  fi
fi

CMD=(deniable-init den.dat)
j "Passphrase:" "$PW"$'\r' "Confirm:" "$PW"$'\r' > den.json
step "deniable-init through a terminal" den.json "credential: passphrase"
[ "$(ls den.dat* | wc -l | tr -d ' ')" = 1 ] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL deniable vault left extra files"; }
if [ $CAN_MOUNT = 1 ]; then
  mkdir -p dm; j "Passphrase:" "$PW"$'\r' > dm.json
  CMD=(deniable-mount den.dat dm); step "deniable-mount" dm.json
  sleep 1; echo "secret deniable data" > dm/note.txt; "$B" umount dm </dev/null >/dev/null 2>&1
  step "deniable-mount again" dm.json; sleep 1
  [ "$(cat dm/note.txt 2>/dev/null)" = "secret deniable data" ] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL deniable data lost across remount"; }
  "$B" umount dm </dev/null >/dev/null 2>&1
  # Rotate its master key: refused without the acknowledgment, then a
  # wrong passphrase changes nothing, then the right one; the data stays
  # readable with the same passphrase.
  CMD=(deniable-rotate den.dat); j "<EXIT>" 1 > dr0.json
  step "deniable-rotate without --other-slots-stop-working" dr0.json "every other slot"
  CMD=(deniable-rotate den.dat --other-slots-stop-working)
  j "Passphrase:" "Not-The-Right-One-12"$'\r' "<EXIT>" 1 > drbad.json
  step "deniable-rotate with a wrong passphrase" drbad.json
  j "Passphrase:" "$PW"$'\r' > dr.json
  step "deniable-rotate" dr.json "OK master key rotated"
  CMD=(deniable-mount den.dat dm); step "deniable-mount after rotation" dm.json; sleep 1
  [ "$(cat dm/note.txt 2>/dev/null)" = "secret deniable data" ] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL deniable data lost across rotation"; }
  "$B" umount dm </dev/null >/dev/null 2>&1
  # The same through the wizard's menu (a second rotation).
  CMD=(wizard)
  j "What would you like to do" "$(menu 7)" "Path to the deniable vault" "~/den.dat"$'\r' \
    "Cipher suite used at create time" $'\r' "(?i)argon2id params" "$UP"$'\r' \
    "deniable anchor sidecar first" n "Rotate, knowing the other slots stop working" y \
    "Passphrase:" "$PW"$'\r' "What would you like to do" "$(menu 10)" > drw.json
  step "wizard: rotate a deniable vault" drw.json "OK master key rotated"
  CMD=(deniable-mount den.dat dm); step "deniable-mount after the wizard rotation" dm.json; sleep 1
  [ "$(cat dm/note.txt 2>/dev/null)" = "secret deniable data" ] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL deniable data lost across the wizard rotation"; }
  "$B" umount dm </dev/null >/dev/null 2>&1
  # Resize its file list region: refused without the acknowledgment,
  # then 64 -> 16 MiB from the command line and 16 -> 32 MiB from the
  # wizard; the data stays readable and no other file appears.
  CMD=(deniable-resize den.dat --metadata-size 16M); j "<EXIT>" 1 > drs0.json
  step "deniable-resize without --data-moves-visibly" drs0.json "--data-moves-visibly"
  CMD=(deniable-resize den.dat --metadata-size 16M --data-moves-visibly)
  j "Passphrase:" "$PW"$'\r' > drs.json
  step "deniable-resize" drs.json "OK file list region resized from 64.0 MB to 16.0 MB"
  CMD=(deniable-mount den.dat dm); step "deniable-mount after the resize" dm.json; sleep 1
  [ "$(cat dm/note.txt 2>/dev/null)" = "secret deniable data" ] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL deniable data lost across the resize"; }
  "$B" umount dm </dev/null >/dev/null 2>&1
  CMD=(wizard)
  j "What would you like to do" "$(menu 8)" "Path to the deniable vault" "~/den.dat"$'\r' \
    "Cipher suite used at create time" $'\r' "(?i)argon2id params" "$UP"$'\r' \
    "deniable anchor sidecar first" n "New file list region size" "$(menu 1)" \
    "Resize, knowing the change can be seen" y \
    "Passphrase:" "$PW"$'\r' "What would you like to do" "$(menu 10)" > drsw.json
  step "wizard: resize a deniable vault" drsw.json "OK file list region resized from 16.0 MB to 32.0 MB"
  CMD=(deniable-mount den.dat dm); step "deniable-mount after the wizard resize" dm.json; sleep 1
  [ "$(cat dm/note.txt 2>/dev/null)" = "secret deniable data" ] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL deniable data lost across the wizard resize"; }
  "$B" umount dm </dev/null >/dev/null 2>&1
  [ "$(ls den.dat* | wc -l | tr -d ' ')" = 1 ] && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL the deniable resize left extra files"; }
fi

echo "TUI SCENARIOS: $PASS passed, $FAIL failed"
cd /
if [ $FAIL -eq 0 ]; then rm -rf "$W"; else echo "work folder kept: $W"; fi
exit $FAIL
