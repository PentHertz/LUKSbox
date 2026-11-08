#!/usr/bin/env bash
#
# tui_scenarios.sh, the interactive paths through a pseudo-terminal:
# `luksbox wizard` (create, open, every file action, keyslot menu errors,
# a sync bundle's refusals, an aborted PANIC) and the deniable commands,
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
j "What would you like to do" "$(menu 0)" "Path for the new vault" "~/wiz.lbx"$'\r' \
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
  "Vault action" "$(menu 14)" "What would you like to do" "$(menu 10)" > open.json
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
  "Vault action" "$(menu 12)" ${MP[@]+"${MP[@]}"} "Mount point" "~/no-such-dir"$'\r' \
  "Vault action" "$(menu 2)" "Local file path" "in.txt"$'\r' "Destination inside vault" "/after-errors.txt"$'\r' \
  "Vault action" "$(menu 14)" "What would you like to do" "$(menu 10)" > keep.json
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
  "Vault action" "$(menu 14)" "What would you like to do" "$(menu 10)" > resize.json
step "wizard: resize the file list region" resize.json \
  "OK file list region resized from 64.0 MB to 32.0 MB" "File list:"
LUKSBOX_PASSPHRASE=$PW "$B" size rz.lbx </dev/null 2>/dev/null | grep -qF "Metadata:       32.0 MB" \
  && [ "$(LUKSBOX_PASSPHRASE=$PW "$B" cat rz.lbx /in.txt </dev/null 2>/dev/null)" = "tui file content" ] \
  && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); echo "FAIL resized vault: region or content"; }

LUKSBOX_PASSPHRASE=$PW "$B" sync convert wiz.lbx wiz.lbxs --page-size 1M </dev/null >/dev/null 2>&1
j "What would you like to do" "$(menu 1)" "Path to vault" "~/wiz.lbxs"$'\r' "detached header" n "Passphrase" "$PW"$'\r' \
  "Vault action" "$(menu 9)" \
  "Vault action" "$(menu 8)" "Keyslot action" "$(menu 2)" "Keyslot action" "$UP"$'\r' \
  "Vault action" "$(menu 13)" \
  "Vault action" "$(menu 2)" "Local file path" "in.txt"$'\r' "Destination inside vault" "/from-wizard.txt"$'\r' \
  "Vault action" "$(menu 14)" "What would you like to do" "$(menu 10)" > bundle.json
step "wizard: sync bundle refusals and publish" bundle.json \
  "rotate-mvk is not available for a sync bundle" "adding a post-quantum keyslot is not available" \
  "panic is not available for a sync bundle" "published commit"
[ -e wiz.lbxs.hybrid ] && { FAIL=$((FAIL+1)); echo "FAIL a .hybrid file appeared next to the bundle"; } || PASS=$((PASS+1))

# Ctrl-C ends the wizard at once (SIGINT), without publishing: the change
# stays in this device's outbox and is published by the next open.
j "What would you like to do" "$(menu 1)" "Path to vault" "~/wiz.lbxs"$'\r' "detached header" n "Passphrase" "$PW"$'\r' \
  "Vault action" "$(menu 2)" "Local file path" "in.txt"$'\r' "Destination inside vault" "/before-ctrl-c.txt"$'\r' \
  "Vault action" $'\x03' "<EXIT>" -2 > ctrlc.json
step "wizard: Ctrl-C on an open bundle" ctrlc.json "OK wrote 17 bytes to /before-ctrl-c.txt"
LUKSBOX_PASSPHRASE=$PW "$B" sync status wiz.lbxs </dev/null >st1.txt 2>&1
LUKSBOX_PASSPHRASE=$PW "$B" ls wiz.lbxs / </dev/null >ls.txt 2>&1
LUKSBOX_PASSPHRASE=$PW "$B" sync status wiz.lbxs </dev/null >st2.txt 2>&1
if grep -q before-ctrl-c.txt ls.txt; then PASS=$((PASS+1)); else
  FAIL=$((FAIL+1)); echo "FAIL change made before Ctrl-C not kept:"; sed 's/^/  | /' st1.txt ls.txt st2.txt | tail -20; fi

j "What would you like to do" "$(menu 1)" "Path to vault" "~/wiz.lbx"$'\r' "detached header" n \
  "rollback-detection anchor" n "Passphrase" "$PW"$'\r' "Vault action" "$(menu 13)" \
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
    "rollback-detection anchor" n "Passphrase" "$PW"$'\r' "Vault action" "$(menu 12)" \
    ${MP[@]+"${MP[@]}"} "Mount point" "$W/m1"$'\r' "Mount in background" n "Eager flush" n "<SLEEP>" 3 "in the foreground" $'\x03' \
    "What would you like to do" "$(menu 1)" "Path to vault" "~/wiz.lbx"$'\r' "detached header" n \
    "rollback-detection anchor" n "Passphrase" "$PW"$'\r' "Vault action" "$(menu 12)" \
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
