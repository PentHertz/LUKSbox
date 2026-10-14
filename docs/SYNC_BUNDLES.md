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

## Create one

```bash
luksbox sync convert vault.lbx ~/Dropbox/vault.lbxs
```

The `.lbx` is not changed; from now on use the bundle. In the GUI:
open the vault, then **Make sync bundle...** and pick the folder.

To start a new vault as a bundle in the GUI: **New vault**, choose
**Sync bundle** at the top of the form, and give a folder name inside
the folder your sync service syncs (for example
`~/Dropbox/vault.lbxs`). It opens right away, without asking for the
credentials again.

## Use it

Every command takes the bundle folder in place of a `.lbx`:

```bash
luksbox ls    ~/Dropbox/vault.lbxs /
luksbox put   ~/Dropbox/vault.lbxs report.pdf /report.pdf
luksbox mount ~/Dropbox/vault.lbxs ~/vault
luksbox enroll ~/Dropbox/vault.lbxs --kind fido2
```

In the GUI: **Open... > Sync bundle** in the sidebar, or **Open sync
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

## Other commands

```bash
luksbox sync status    vault.lbxs   # newest commit, devices, pending uploads
luksbox sync push      vault.lbxs   # upload now and merge other devices' changes
luksbox sync verify    vault.lbxs   # read and check every file (changes nothing)
luksbox sync snapshots vault.lbxs   # list versions
luksbox sync snapshots vault.lbxs --restore <id> --path /report.pdf
luksbox sync export    vault.lbxs vault.lbx   # back to a single file
luksbox sync gc        vault.lbxs   # delete what no kept version needs
luksbox sync discard-local --yes vault.lbxs   # drop changes that could not be merged
```

`gc` works in two runs: the first records what is unused, a run at
least 7 days later deletes it if it is still unused, so a device that
was offline never loses what it was working on. The 7 days also count
from when this computer first saw the record, whatever the other
computer's clock said. Pieces of a commit whose upload is still in
progress elsewhere are kept 90 days. Do not use `--grace-days 0` while
another computer may be uploading.

To merge two copies of a regular `.lbx` (for example the "conflicted
copy" a sync service made):

```bash
luksbox merge mine.lbx "vault (conflicted copy).lbx" -o merged.lbx
```

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
  mixed state: a device opens the newest complete version, or opens
  read-only while something it already saw is missing.
- **Damage.** Every part is authenticated: a damaged or altered part is
  refused instead of shown. Earlier versions stay in the folder (30
  days with `sync gc`'s default), so a file can be copied back from one:
  **Versions** in the GUI, or `luksbox sync snapshots`. `luksbox sync
  verify` reads and checks everything; `luksbox sync export` makes a
  `.lbx` copy to keep apart.

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
  computer has already seen. Check the sync service (restored
  version, history rollback). The vault is not opened.
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
- **"changes saved on this device earlier could not be merged"**: the
  vault opens read-only. If it says they are shown, copy out what you
  need (or `luksbox sync export`), then `luksbox sync discard-local
  --yes <bundle>` lets this computer write again.

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
  browser, or `luksbox mount` in a terminal); on Windows only with
  `--foreground`.
- **Revoking a lost device**: revoking its keyslot stops LuksBox from
  opening the vault with it, but a copy of an old keyslot table may
  survive in the sync service's version history. Until key epochs land
  (see `docs/CLOUD_SYNC_DESIGN.md`), the only complete protection is to
  export, rotate the master key, and convert again.
- The provider can still see when you work on the vault and roughly
  how much changed, and could refuse to deliver new versions to a
  device that never hears from the others.

How it works and what it protects against:
`docs/CLOUD_SYNC_DESIGN.md`, `docs/CLOUD_SYNC_IMPLEMENTATION.md`,
`docs/CRYPTO_SPEC.md` section 22.
