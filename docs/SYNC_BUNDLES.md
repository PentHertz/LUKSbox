# Sync bundles: a vault in Dropbox, Google Drive, OneDrive, iCloud...

**Status: experimental** (new in v0.7.0). The format may still change
before it is declared stable, after a dedicated audit round. Keep a
regular `.lbx` backup of anything that matters (`luksbox sync export`).

A `.lbx` vault is one file. Sync services handle that badly: Google
Drive re-uploads the whole file after every save, Dropbox uploads
about 128 MiB per save, and two computers using the vault at once
overwrite each other. A **sync bundle** (`.lbxs`) stores the same vault
as a folder of small encrypted objects that sync services handle well:

- Only what changed is uploaded (a few MiB for a small edit), on every
  service, Google Drive included.
- Several devices can use the vault. Changes made at the same time, or
  offline, are merged. If the same file changed on two devices, both
  versions are kept (`report (conflict Laptop 2026-10-13 1032).docx`).
  Nothing is dropped.
- A half-uploaded or out-of-order sync never shows a mixed state:
  a device always opens one complete version.
- The provider still sees no file names, no file sizes, no file count
  and no folder structure, only the total size and when changes
  happen.
- Every object is authenticated. If the provider deletes, alters,
  swaps or rolls back objects, the device that notices refuses to
  open (or opens read-only) instead of showing a wrong vault.
- Earlier versions stay available and can be browsed and restored
  (`luksbox sync snapshots`); `luksbox sync gc` trims them to the last
  30 days.

Every keyslot kind works as with a `.lbx` (passphrase, FIDO2, TPM,
Secure Enclave, post-quantum hybrid). Each computer can have its own
TPM or Secure Enclave keyslot.

The bundle folder can be on any local disk or removable drive the sync
client watches, including exFAT and FAT32 (a USB stick or SD card shared
with Windows); on exFAT, which has no hard links, objects are installed
with an exclusive placeholder and a rename instead.

## Create one

A new vault as a bundle (v0.7.1-rc.1 and later): give `luksbox create`
a folder name ending in `.lbxs`, inside the folder your sync service
syncs.

```bash
luksbox create ~/Dropbox/vault.lbxs
luksbox create ~/Dropbox/vault.lbxs --kind hybrid-pq --pq-hybrid /media/usb/vault.kyber
```

Every create option works except those a bundle has no use for:
`--header` (the header is in the folder), `--anchor` (the bundle
detects rollback itself), `--max-size`, and the v2 formats. The vault
is built in a private staging folder on this computer
(`<sync state>/creating/`, removed afterwards) and then becomes the
bundle; nothing is asked twice, and a post-quantum vault's public
sidecar goes inside the bundle.

An existing vault:

```bash
luksbox sync convert vault.lbx ~/Dropbox/vault.lbxs
```

The `.lbx` is not changed; from now on use the bundle.

In the wizard (`luksbox` with no arguments, v0.7.1-rc.1 and later):
**Create a new vault**,
then **Sync bundle (.lbxs folder)** as the vault type and the folder to
create (`.lbxs` is added if you leave it out); it offers to mount the
bundle right away. For an existing vault: **Open an existing vault**,
then **Make a sync bundle from this vault**.

In the GUI: **New vault**, choose **Sync bundle** at the top of the
form, and give a folder name inside the folder your sync service syncs
(for example `~/Dropbox/vault.lbxs`). It opens right away, without
asking for the credentials again. For an existing vault: open it, then
**Make sync bundle...** and pick the folder.

## Use it

Every command takes the bundle folder in place of a `.lbx`:

```bash
luksbox ls    ~/Dropbox/vault.lbxs /
luksbox put   ~/Dropbox/vault.lbxs report.pdf /report.pdf
luksbox mount ~/Dropbox/vault.lbxs ~/vault
luksbox enroll ~/Dropbox/vault.lbxs --kind fido2
```

In the wizard: **Open an existing vault** and the bundle folder (no
detached-header or anchor question: a bundle has neither). In the GUI:
**Open... > Sync bundle** in the sidebar, or **Open sync
bundle (folder)...** on the welcome screen. The header line shows
whether changes are uploaded yet. **Versions** lists the earlier
versions: pick one, browse it, and **Restore** copies a file or folder
back next to the original as `name (restored 2026-10-14 1532)` (UTC);
nothing in the vault is replaced.

On Linux, GNOME Files and other file managers built on GIO show a bundle
folder with a LUKSbox folder icon. The GUI sets it on each computer
where it creates or opens the bundle; it is kept in that computer's
GVfs metadata, nothing is written into the folder.
`LUKSBOX_NO_FOLDER_ICON=1` turns it off (GVfs then keeps no record of
the bundle's path).

Changes are saved on this computer first and uploaded:

- when the command finishes, or when you lock the vault in the GUI;
- every couple of minutes while mounted, and at unmount;
- a few seconds after a change in the GUI browser.

"Saved" and "uploaded" are different: if the computer is switched off
before an upload, the changes are uploaded the next time the vault is
opened on it.

The file list (metadata) region of a bundle can be resized like a
vault file's: `luksbox size ~/Dropbox/vault.lbxs --metadata-size 16M`,
or Vault size in the wizard or the GUI. The vault's pages are rewritten
on this computer and uploaded as a new version; other computers merge
their own changes into it. If two computers resize differently at the
same time, both versions are kept (as for other header changes).

## Other commands

```bash
luksbox sync status    vault.lbxs   # newest commit, devices, pending uploads
luksbox sync push      vault.lbxs   # upload now and merge other devices' changes
luksbox sync verify    vault.lbxs   # read and check every file (changes nothing)
luksbox sync snapshots vault.lbxs   # list versions
luksbox sync snapshots vault.lbxs --restore <id> --path /report.pdf
luksbox sync export    vault.lbxs vault.lbx   # back to a single file
luksbox sync export    vault.lbxs old.lbx --snapshot <id>   # an earlier version
luksbox sync gc        vault.lbxs   # delete what no kept version needs
luksbox sync discard-local --yes vault.lbxs   # drop changes that could not be merged
```

`gc` works in two runs: the first records what is unused, a run at
least 7 days later deletes it if it is still unused, so a device that
was offline never loses what it was working on. The 7 days also count
from when this computer first saw the record, whatever the other
computer's clock said. Pieces of a commit whose upload is still in
progress elsewhere are kept 90 days. `--grace-days 0` deletes in one
run and needs `--yes`: do not use it while another computer may be
uploading. A commit `gc` deleted never comes back into the vault, even
if the sync service restores it from its own history.

To merge two copies of a regular `.lbx` (for example the "conflicted
copy" a sync service made), give the copy first and the vault second:

```bash
luksbox merge "vault (conflicted copy).lbx" vault.lbx -o merged.lbx
```

The result keeps the keyslots and master key of the second file and
takes the changes of the first. `luksbox merge` refuses copies of
different vaults or under different master keys (a rotation in
between), and refuses the files the wrong way round (an older keyslot
table second, which would bring back a revoked key) with the command to
run instead. It also checks this computer's rollback anchors: a merge
whose two copies are both older than what this computer has seen is
refused.

## Crashes, power loss, damaged files

- **While you work.** Each save is all or nothing on this computer: the
  changed parts are written (encrypted) to this computer's sync state,
  then a small record naming them is replaced in one step. After a
  crash or power loss the vault opens as of the last complete save, and
  saved changes not uploaded yet are uploaded then ("Changes saved on
  this device earlier were restored").
- **While uploading.** The parts go up first and the commit that names
  them last (a copy of it is kept on this computer first). Interrupted,
  the previous version stays the current one; the next open sends the
  same commit again. Parts of a commit that never completed are removed
  by `sync gc` after 90 days.
- **On the other computers.** A half-synced folder never opens as a
  mixed state, nor as an older version than one this computer has seen:
  a device opens the newest complete version that contains what it saw
  last. If parts of that version have not arrived (or are damaged), it
  opens read-only on what it saw while newer parts arrive, or refuses to
  open for writing until they are there; `sync snapshots` and `sync
  export --snapshot` still read earlier versions. A version that `sync
  gc` deleted never comes back, even if the sync service restores it.
- **Damage.** Every part is authenticated: a damaged or altered part is
  refused instead of shown. Earlier versions stay in the folder (30
  days with `sync gc`'s default), so a file can be copied back from one:
  **Versions** in the GUI, or `luksbox sync snapshots`. `luksbox sync
  verify` reads and checks everything; `luksbox sync export` makes a
  `.lbx` copy to keep apart.
- **If the sync service loses or damages a file.** Each part of the
  vault is stored once, and the versions share the parts that did not
  change. A part the service lost (or delivered damaged) therefore
  affects every version made since it was written, and the vault does
  not open through those versions on the devices the loss reached (a
  sync client that deletes a file in the cloud deletes it on every
  computer too). What still works: the device that wrote the part has
  it in its own copy of the folder until the sync client removes it;
  any earlier version whose parts are all present opens, and
  `luksbox sync export --snapshot <id> rescued.lbx` writes it out as
  a single file (`luksbox sync snapshots` lists the versions; a
  damaged newest version still lists them). Keep a regular
  `luksbox sync export` of anything that matters: the folder is one
  copy, the export is a second one.
- **Uploads that fail unseen.** A vault mounted in the background
  uploads with nobody watching. An upload that fails is retried, and
  the failure is remembered on this computer: the next open and
  `luksbox sync status` say so ("the last upload from this device
  failed"). `luksbox umount` returns once the mount has saved and
  published into the bundle folder; the sync client then uploads it, so
  give it a moment before switching off.

What is not on the bundle side yet: the `.lbx` tools `check`, `extract`
and header backup / restore (`sync verify` and `sync export` cover
them).

## Delete one

In the GUI: right-click the bundle in the recent list, **Delete
vault...**, tick the confirmation. This deletes every version in the
folder and this computer's changes not uploaded yet; the sync service
then deletes it on every device (it may keep a copy in its own trash
for a while). Files in the folder that are not part of the vault are
kept, and so is the folder if they are there.

## Messages you may see

- **"also open on Laptop"**: another device has the vault open. You
  can go on; changes are merged.
- **"a commit another device saw is not here yet: read-only"**: the
  sync service has not delivered everything yet (wait a minute), or it
  is withholding part of the history. Nothing is written until it
  arrives.
- **"rollback detected"**: the folder shows an older version than this
  computer has already seen, or part of the history it saw is gone.
  Check the sync service (restored version, history rollback). The
  vault is not opened.
- **"the newest version this device has seen ... is not complete in the
  bundle"**: some of its parts are missing or damaged (the sync is still
  running, or the sync service is withholding or has altered them). The
  vault is not opened for writing rather than shown as an older
  version; open it again once the sync has finished. `luksbox sync
  snapshots` and `luksbox sync export --snapshot` can still read earlier
  versions (read-only, with a warning).
- **"N concurrent version(s) were not merged: the version they come from
  is not complete in the bundle"**: two devices changed the vault at the
  same time and the version both started from has not fully arrived.
  They are merged once it has (wait for the sync); until then each
  device keeps its own version. Changes saved here meanwhile are kept
  and shown read-only ("cannot be merged yet").
- **"this credential was revoked"**: the passphrase or key still opens
  an old keyslot table left in the folder, but not the current one.
- **"two installations used one device identity"**: the same LuksBox
  profile runs on two computers (copied profile, restored backup or
  VM). Both versions were kept; the computer took a new identity.
- **"this folder held a different sync bundle"**: the folder now holds
  another vault than the last time. Check before trusting it. If you
  replaced it on purpose (for example converted again into the same
  folder), delete the `paths` folder in this computer's sync state
  (`~/.local/share/luksbox/sync/paths` on Linux,
  `~/Library/Application Support/luksbox/sync/paths` on macOS,
  `%APPDATA%\luksbox\sync\paths` on Windows); it is rebuilt as you
  open bundles.
- **"keyslot N: enrolled on two devices at once; the other device's
  moved to slot M"**: two computers added a key at the same time; both
  work. "Changed differently on two devices" means one of the two
  changes was kept: redo the other. A key removed on one computer stays
  removed.
- **"the file list region stays N: the merged file list does not fit
  M"**: one computer made the file list region smaller while another
  added files; the merged list did not fit the smaller size, so the
  larger one was kept. Nothing was lost.
- **"changes saved on this device earlier could not be merged"**: the
  vault opens read-only. If it says they are shown, copy out what you
  need (or `luksbox sync export`), then `luksbox sync discard-local
  --yes <bundle>` lets this computer write again. If it says the
  version they were made on "is not in the bundle here", wait for the
  sync to finish and open again: they are merged then. They are gone
  only if that version was deleted by `sync gc` after this computer
  was offline for a long time (90 days); discard them only then.
- **"changes saved on this device earlier are not uploaded yet"** (a
  vault opened read-only, or while a commit is missing): they are kept
  on this computer, shown when they were made on the version you see,
  included in an export, and uploaded the next time the vault opens
  read-write. Do not delete the bundle or this computer's sync state
  while this shows.
- **"an area folder was moved or replaced while the bundle was open"**:
  a folder inside the bundle (`p`, `m`, `t`...) was moved away while the
  vault was open (by the sync client, or by hand). Nothing was written
  outside the bundle; close the vault, check the folder, open it again.
- **"the last upload from this device failed"**: a background upload
  did not complete (network, the sync service, the disk). The changes
  are on this computer and the upload is retried; `luksbox sync push`
  retries it now.

## A single `.lbx` in a cloud folder

You can also keep an ordinary `.lbx` in a synced folder, used by one
device at a time. LuksBox then helps:

- **The first open on each computer** says the folder is synced. Use
  the vault on one computer at a time, and let the sync finish before
  switching.
- **Rollback anchor.** Each computer remembers the newest version of
  the vault it has seen, in its own app data (`~/.local/share/luksbox/anchors`
  on Linux, `~/Library/Application Support/luksbox/anchors` on macOS,
  `%APPDATA%\luksbox\anchors` on Windows). A newer version from
  another computer is normal. An **older** one is refused ("ROLLBACK
  DETECTED"): the sync service restored an old version, kept another
  computer's older copy after a conflict, or someone put an old copy
  back. Look for the copies the message names and merge them (below).
  To accept the older vault as it is, delete the anchor file the
  message names. `LUKSBOX_NO_AUTO_ANCHOR=1` turns this off. Not used
  for deniable vaults, or when you pass `--anchor`.
- **Conflict copies** next to the vault (`vault (Laptop's conflicted
  copy 2026-10-13).lbx`, `vault (1).lbx`, `vault.sync-conflict-...lbx`)
  are listed every time you open it.
- **Vault replaced while open.** If the sync client replaces the file
  while you have it open, what you save after that goes to
  `vault (unsaved changes <time>).lbx` instead of being lost.

To bring a copy's changes back:

```bash
luksbox merge "vault (Laptop's conflicted copy 2026-10-13).lbx" vault.lbx -o merged.lbx
luksbox ls merged.lbx /                    # check
mv merged.lbx vault.lbx
mv merged.lbx.meta-bak vault.lbx.meta-bak  # its metadata mirror
```

Then delete the conflict copy.

The merge result counts as newer than both copies, so every computer
accepts it in place of the vault.

## Limits (for now)

- Not available for a bundle: `rotate-mvk`, `panic`, header
  backup/restore/dump, `check`/`extract` (use `sync verify` /
  `sync export`), deniable vaults, detached headers, `--anchor` (a
  bundle keeps its own rollback state on each device), adding a
  post-quantum keyslot (export, enroll, convert again).
- Mounting a bundle: not with the macOS FUSE-T GUI helper (use the
  browser, or `luksbox mount` in a terminal). On Windows `luksbox mount`
  works in the background as for a `.lbx` (and with `--foreground`).
- **Revoking a lost device**: revoking its keyslot stops LuksBox from
  opening the vault with it, but the master key does not change, the
  old keyslot table stays in the folder until `sync gc` and in the
  sync service's version history for good, and whoever has the revoked
  credential can derive the master key from it with their own tools
  and read every later version. Until key epochs land (see
  `docs/CLOUD_SYNC_DESIGN.md`), the only complete protection is to
  export, rotate the master key (`luksbox rotate-mvk` on the exported
  file), convert again into a new bundle and delete the old one.
  `luksbox revoke` on a bundle says so.
- **What the provider sees**: the bundle id and the keyslot-table
  generation (in the names of the header files), the 8 KiB header
  itself (cipher, key-derivation settings, which kinds of keyslots and
  how many, FIDO2 credential ids: the same as for any `.lbx` file), the
  size of the vault rounded to a page, how many parts each change
  touched (roughly how much changed, and over time the size class of
  the folder tree), when changes happen, and when the vault is open on
  how many computers (a small lease file is refreshed every few minutes
  while it is open; it cannot be turned off yet). It does not see file
  names, sizes, how many files, the folder structure, which file
  changed, or which computer made a change. It could also refuse to
  deliver new versions to a device that never hears from the others.
- **Local traces**: this computer's sync state (`luksbox/sync/` in the
  application data folder, private to your account), the folder icon
  record on Linux (see above), and the GUI's recent list name the
  bundle. Deniable vaults cannot become bundles and leave none of
  these.

How it works and what it protects against:
`docs/CLOUD_SYNC_DESIGN.md`, `docs/CLOUD_SYNC_IMPLEMENTATION.md`,
`docs/CRYPTO_SPEC.md` section 22.
