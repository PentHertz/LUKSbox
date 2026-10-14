# Cloud sync: plan for Google Drive, Dropbox, OneDrive, iCloud and others

Design record, not shipped code. Nothing below is implemented yet. It
plans how a vault can live in a cloud-synced folder, be used from
several devices, and stay as private and tamper-evident as it is on a
USB stick, with a better guarantee than the per-file tools people use
for this today.

## 1. Where we are today

A vault is one `.lbx` file. That is good for privacy (the provider sees
one random-looking blob, no file names, no file count, no file sizes),
but the way it is written today works against sync clients:

- **Every save rewrites about 128 MiB.** `Vfs::flush` rewrites the whole
  metadata region (64 MiB by default) with fresh random padding
  (`metadata::write_metadata_opts`), and then writes the same 64 MiB again
  as the `<vault>.lbx.meta-bak` mirror (`Container::write_metadata_mirror`).
  A mounted vault saves every 30 s while files change
  (`LAZY_FLUSH_INTERVAL_SECS`), on `fsync` and at unmount.
  - Dropbox uploads only the 4 MiB blocks that changed, so a 1 KiB edit
    still costs about 128 MiB of upload.
  - The Google Drive client has no delta upload: it sends the whole
    `.lbx` again, plus the mirror, on every save.
- **The other device can receive a half-written vault.** The sync client
  uploads while the vault is open. `.lbx`, `.meta-bak` and `.header-bak`
  sync independently and arrive in any order, so another device can get
  new metadata with old chunks, or the reverse. At best that ends in a
  read-only "tolerated" open; at worst in a vault that refuses to open.
- **Two devices overwrite each other.** The "vault locked by another
  process" lock is a local byte-range lock. Nothing stops a vault from
  being open on two machines. Depending on the client this produces a
  "conflicted copy" of the whole vault, or loses one device's changes
  without a word.
  - On Linux and macOS a sync client typically replaces the file with a
    rename. A vault that is open keeps writing to the old, unlinked
    inode, and every change made after that point is lost at close.
- **Provider version history is a ready-made rollback tool.** Restoring
  an older version of the `.lbx` from the provider's history is only
  detected when the user set up an `.anchor` on separate storage, which
  most users don't.

The website's compare page already says so: for sync it currently
recommends gocryptfs or Cryptomator, because LUKSbox's single file
"causes whole-vault re-uploads on every change".

## 2. Threat model for synced vaults

The adversary is the storage provider, or anyone with access to the
account (insider, stolen session, legal order). They can:

- read every object and its history, and see when and how much is
  uploaded;
- delete, modify, replace, reorder or delay objects, and restore old
  versions;
- show different devices different states (a "fork");
- leave a partial upload in place.

Out of scope: a device compromised while the vault is unlocked on it.

### Goals

| # | Goal |
|---|---|
| G1 | **Content and metadata stay hidden.** No file names, folder structure, file count, file sizes or timestamps. The only things that leak are the total vault size and write activity, both rounded to a page. |
| G2 | **The whole vault state is authenticated.** Deleting, swapping, modifying or rolling back any object is detected. Rolling back the whole vault is detected relative to what each device has already seen, and a fork is detected as soon as the devices see each other's commits. |
| G3 | **A small change uploads a small amount.** The upload is proportional to the change, never to the vault size or the metadata region size, on every provider, Google Drive included. |
| G4 | **Every visible state is complete.** Whatever arrived and in whatever order, a device opens either a complete earlier snapshot or a complete later one, never a mix. |
| G5 | **Several devices can edit safely.** Offline edits on several devices merge automatically. A real conflict (the same file changed on two devices) keeps both versions inside the vault. There is never a conflicted copy of the vault itself. |
| G6 | **The unlock model stays.** Passphrase, FIDO2, TPM 2.0, Secure Enclave and ML-KEM hybrid keyslots, a hardware slot per device, an optional detached header. |
| G7 | **No server and no account.** It works through any folder sync client (Drive, Dropbox, OneDrive, iCloud Drive, Nextcloud, Syncthing, SMB/NAS); native provider APIs come later. |

### Non-goals

- **Deniability.** A synced vault is a recognisable set of objects;
  `deniable-init` vaults stay single-file only.
- **Real-time collaborative editing.**
- **Hiding that you sync something encrypted.** Object names and sizes
  are random-looking, but the pattern is still fingerprintable.

## 3. What competitors guarantee

| Property | VeraCrypt file | Cryptomator, gocryptfs, rclone crypt | CryFS | LUKSbox `.lbx` today | LUKSbox sync bundle (this plan) |
|---|---|---|---|---|---|
| Hides file names | yes | yes | yes | yes | yes |
| Hides file count, file sizes, folder structure | yes | **no** | yes | yes | yes |
| Small edit = small upload on Google Drive | no | the changed file only | yes | no | yes |
| Detects a deleted, swapped or rolled-back file | no (no integrity) | **no** (integrity per file only) | yes, single client | only with an anchor | yes, by default, per device |
| Several devices editing | corrupts / conflict copy | conflict copies per file, resolved by hand | not supported | conflict copy of the vault | automatic merge, both versions kept on real conflict |
| Consistent state despite partial or out-of-order uploads | no | per file only | not documented | no | yes |
| Encrypted version history checked by the tool | no | no | no | no | yes |
| Hardware-bound (TPM / Secure Enclave) and ML-KEM hybrid keyslots | no | no | no | yes | yes |

Notes:

- **Cryptomator** documents that the number of files and folders, file
  sizes and timestamps are not protected "to allow a working
  synchronization". Sync conflicts come from the cloud client and the
  user resolves them by hand.
- **gocryptfs:** the 2017 Defuse audit found that a storage-level
  attacker can swap or truncate files.
- **CryFS** hides metadata and detects rollback, but does not support
  access from several devices at the same time: the user must make
  sure only one instance runs and that syncing has finished before
  switching devices.
- **Provider-run E2EE services** (Tresorit, Sync, pCloud, Icedrive,
  Seafile, ...) lock you to one provider and its client. The ETH Zurich
  study at CCS 2024 found serious flaws in four of the five it examined.

The gap nobody fills is **CryFS-level metadata hiding and integrity,
with safe use from several devices, cheap on every provider, and with
hardware and post-quantum keyslots**. That is the target.

## 4. Recommended design: the sync bundle (`my.lbxs/`)

The idea: keep the audited container format (header, keyslots,
metadata AEAD, per-chunk AEAD) exactly as it is, and change only where
its bytes are stored. Instead of one file rewritten in place, the
container image is cut into fixed-size **pages**. Each page version is
a new, never-modified object, and a small authenticated **manifest**
says which page versions form the current state. That is the git /
restic model (immutable objects plus a small signed pointer), applied
below the container. It is the `LbxFile` trait
(`crates/luksbox-format/src/container.rs:79`) with a new backend.

This section is the overview. `docs/CLOUD_SYNC_IMPLEMENTATION.md` has
the byte formats, algorithms, security invariants and build order, and
takes precedence where the two differ.

### 4.1 Layout

```
my.lbxs/
  h/<bid>-<gen>-<rand>  header object: today's 8 KiB LUKSBOX3 header
                        (absent when the header is detached)
  p/<xx>/<id>           page: one slice of the container image, fixed size
  t/<xx>/<id>           page-table block: page index -> (page object, hash)
  m/<xx>/<id>           manifest: one per commit, never modified
  l/<id>                lease: "open on some device", heartbeat
```

- **Names:** lowercase hex, two-level sharding, no meaningful text.
  This keeps clear of case-insensitive file systems, forbidden
  characters, OneDrive path-length limits and the files sync clients
  ignore.
- **Device ids:** a random id per device and vault, stored locally.
  The device id, its commit number and the readable label ("Laptop")
  are only inside encrypted manifests, so the provider cannot tell which
  device committed.
- **Single writer per name:** every object except a lease is written
  once and never changed, and every name is written by a single device.
  A sync client therefore never has two versions of the same file to
  reconcile, so it cannot create a conflict copy. Any conflict copy
  found in the bundle is an anomaly to report and ignore.

### 4.2 Cryptography

All keys are HKDF subkeys of the MVK with the vault's `header_salt`,
under new labels, the same pattern as `lbx:anchor-mac/v1`.

- **Pages** are sealed again with the vault's AEAD, under a key derived
  for that one object (so no key or nonce is ever reused, whichever
  device writes), with a key commitment. The associated data binds the
  bundle id, the object id and the page index. The bytes inside are
  already ciphertext; the outer seal does three things:
  - every object looks uniformly random, including unused areas;
  - a page moved to another index, or an older version of the page,
    fails before the container sees it;
  - it is the layer that key epochs (section 6, phase 3) rotate.
- **Page-table blocks** hold 1024 entries and are sealed the same way.
  The manifest lists them, so changing one page rewrites one table
  block, not a full table: a Merkle tree of depth 2.
- **Manifests** are sealed the same way. Each manifest holds:
  - its device and `seq`, which must be contiguous per device;
  - its **parents**, a version vector `{device: seq}` of the commits it
    was built on (two or more for a merge);
  - **seen**, the newest `seq` it has observed from every device;
  - the header object name, hash and `header_generation`;
  - the page size and count, and the table-block list.

  Manifests are padded to a fixed size bucket.
- **The header** stays the 8 KiB HMAC'd LUKSBOX3 header, now an object
  of its own. A device tries header objects in descending
  `header_generation`, unlocks, then checks that the chosen manifest
  references exactly that header.

### 4.3 Writing: local durability vs publication

Two different things that are the same thing today:

- **Durability:** `Vfs::flush` and `fsync` write dirty pages to a local
  write-back cache outside the synced folder
  (`$XDG_DATA_HOME/luksbox/sync/<vault-id>/`, or the platform
  equivalent). The cache is fsync'd, so a crash loses nothing that was
  saved. Its pages are ciphertext, so plaintext never touches disk.
- **Publication:** new page objects, then table blocks, then the
  manifest (always last) go to the synced folder. This happens when the
  vault is locked or unmounted, after a few seconds without writes, at
  most every few minutes while writing (configurable), and on "Sync
  now".

Decoupling them means a 30 s flush timer no longer turns into 30 s
uploads, and several flushes become one commit.

The metadata region needs one change in this mode: refresh the
padding only up to the ciphertext length rounded up to a power-of-two
bucket (at least 1 MiB), instead of the whole 64 MiB. Pages past the
bucket keep their bytes and are not uploaded again. What a provider
comparing two versions can then learn is the metadata size bucket, not
the exact size. The R15-D2 masked length field stays. The same change
can also be offered for single-file vaults (phase 0).

The `.meta-bak` / `.header-bak` mirrors are not used in a bundle:
old pages stay in place until the new manifest exists, so every commit
is crash-safe by construction.

### 4.4 Opening: picking the state and detecting attacks

1. **Collect manifests.** Verify every manifest in `m/` and keep each
   device's contiguous run of `seq`.
2. **Pick the heads.** Heads are the commits no other commit descends
   from (the maximal ones under the version vectors).
3. **Skip pending heads.** A head whose objects have not all arrived
   is pending and skipped, with a notice ("waiting for 3 objects from
   Laptop since 10:32"). This is what makes out-of-order and partial
   uploads harmless (G4).
4. **Check the local anchor.** It is kept per device in app data,
   automatically for every bundle. If a device's latest visible `seq`
   is lower than what this device has already seen, report
   **rollback**. If it is lower than what another device's manifest
   says it saw, report **withholding / fork**: one device's state is
   being hidden from another. This is the fork consistency of SUNDR
   (Li, Krohn, Mazieres, Shasha, OSDI 2004), the best guarantee
   possible without a trusted server.
   - An optional second anchor on separate storage (another provider,
     a USB stick) catches a provider that freezes *every* device's view.
5. **Open.** One head: open it. Several heads (concurrent edits): merge
   them (4.5) when opening read-write, otherwise open the newest
   read-only with a banner.

### 4.5 Several devices: leases and merge

- **Lease.** While a vault is open read-write, the device refreshes an
  encrypted heartbeat in `l/<id>`. Opening read-write on a second
  device warns: "Open on Laptop (seen 2 min ago): open read-only, or
  continue and merge later". The lease is advice, not a lock: sync is
  eventually consistent, so both devices may miss each other's lease.
  Merge is what keeps that safe.
- **Merge.** Merging at page level is impossible, because both branches
  allocated chunk slots from the same free list. Instead, merge works
  at the file-tree level, through the Vfs API:
  - When: at open, lock or unmount. A mounted vault never merges under
    open files; if another device published meanwhile, it publishes its
    own commit as a fork and the merge happens at the next lock.
  - Open the common ancestor, ours and theirs as read-only views. They
    share all the pages they have in common, so this costs little.
  - Compare the trees by inode (renames are followed through the
    ancestor's inode ids) and replay theirs' changes onto ours. Content
    is read from one view and written to the other, so it is decrypted
    and re-encrypted in memory and never written in plaintext.
  - Real conflicts keep both versions: the same file changed on both
    sides, an edit against a delete (the edit wins), or the same new
    path with different content. The second version is saved as
    `name (conflict Laptop 2026-10-13 1032).ext`. Identical content is
    not a conflict, so two devices merging the same fork converge.
  - The merge is committed as a manifest with both parents.
- **Keyslot changes.** Enroll, revoke and update need exclusive mode:
  no fresh foreign lease and no open fork. A fork in the header itself
  is shown to the user to choose.

### 4.6 History, garbage collection, size

- **Encrypted history.** Commits are kept for a retention period (for
  example 30 days or the last N commits). That gives verified,
  encrypted snapshots: `luksbox snapshots list | diff | restore`.
  Restoring writes a new commit; it is not a rollback.
- **Garbage collection.** It deletes only objects that no manifest
  within retention, no device's newest commit and no open session
  needs, and only in a second pass at least 7 days after a first pass
  recorded them as unused, so a device that was offline never finds
  its base deleted. Old manifests are dropped by
  writing a checkpoint (an authenticated "lowest kept seq per device")
  in a new manifest, so a missing old manifest is legitimate only
  below a checkpoint.
- **Page size** is set at creation with an object-count budget in mind.
  Dropbox's desktop client slows down above about 300,000 files.
  - Default: 4 MiB, about 262,000 objects for 1 TiB.
  - 1 MiB when `--max-size` is 256 GiB or less (cheaper small edits).
  - 16 MiB above 1 TiB.
- **Expected cost of a small edit** (1 KiB to one file, 4 MiB pages):
  one data page, one or two metadata pages, one table block and one
  manifest, about 8-12 MiB. With 1 MiB pages, about 2-3 MiB. Today it
  is about 128 MiB on Dropbox and the whole vault on Google Drive.

### 4.7 What the provider still sees

| Visible | Not visible |
|---|---|
| Total vault size (page count) | File names, folder structure |
| When commits happen | Number of files, file sizes, timestamps |
| Pages changed per commit (write volume, rounded to a page) | Which file changed |
| How many sessions are open at once (leases) | Which device committed, device names |
| When a vault is open (lease heartbeats; can be turned off) | Metadata size beyond its bucket |

An optional "constant traffic" mode can pad every commit to a fixed
page count, at a bandwidth cost.

### 4.8 Provider quirks to handle and test

- On-demand placeholders: Dropbox online-only, OneDrive Files
  On-Demand, Google Drive streaming, iCloud "Optimise Mac Storage".
  Reading a page may download it first; this needs time-outs, progress,
  and not counting placeholders as missing objects.
- Listings lag behind uploads (eventual consistency) and objects arrive
  out of order. These are covered by the pending-head rule.
- Each provider's conflict-copy naming: Dropbox "conflicted copy",
  Drive " (1)", OneDrive "-<PC name>", Syncthing `.sync-conflict-`,
  Nextcloud and iCloud " 2". Never expected in a bundle; reported if
  found.
- Rename semantics and temporary files: write `.tmp-*` and rename in
  the same folder. A temp file that gets uploaded is harmless, because
  nothing references it.
- Wall clocks are only informational. Ordering uses `seq`, version
  vectors and a Lamport counter.

## 5. Alternatives considered

- **New log-structured file system format** (CryFS / restic style:
  per-file or per-directory metadata objects, content-defined chunks).
  - For: the smallest uploads.
  - Against: a new file system and metadata model with a whole new audit
    surface, and months before anything ships. The bundle reuses the
    container that went through 15 audit rounds and adds a storage
    layer.
  - If metadata buckets turn out too costly on huge vaults (hundreds
    of thousands of files), the 64 MiB metadata region can later be
    split into per-directory objects, without touching the bundle
    layer.
- **Per-file encryption like Cryptomator.** It gives up G1 (count,
  sizes, structure) and G2 (whole-vault integrity), the two properties
  that make LUKSbox worth choosing.
- **Staged single file** (copy the vault to a local cache on open, put
  it back with an atomic rename and a compare-and-swap on close).
  - For: it fixes partial uploads and silent overwrites for the current
    format.
  - Against: it doubles disk use (unless APFS clonefile or btrfs/XFS
    reflink is available) and still re-uploads the whole vault on
    Google Drive once per session.
  - Not recommended as the main path, but the compare-and-swap check
    is worth keeping for single-file vaults (phase 0).

## 6. Roadmap

### Phase 0: make single-file vaults in cloud folders safe (0.6.x / 0.7)

Small changes, no format change. (Built: items 1 to 4 and 8; items 5
to 7 are open, see the status in `CLOUD_SYNC_IMPLEMENTATION.md`.)

1. **Detect cloud folders.** Recognise a vault inside one:
   - macOS `~/Library/CloudStorage/*` (Dropbox, Google Drive, OneDrive,
     Box) and `~/Library/Mobile Documents/com~apple~CloudDocs`;
   - `~/Dropbox`, `OneDrive*`, Google Drive's `My Drive`, `~/Nextcloud`;
   - a `.dropbox` or `.stfolder` in a parent folder.

   Show a banner in the GUI and the wizard and a note in the CLI, with
   the rules: one device at a time, wait for sync before switching,
   don't keep it mounted for long.
2. **Detect the vault being replaced while open.** At each flush,
   compare the path's `(device, inode)` with the open handle
   (`LbxFile::inode_pair` exists already). If the sync client replaced
   the file:
   - stop writing to the path;
   - flush to the orphaned handle and copy it to
     `name (unsaved Laptop 2026-10-13 1032).lbx`;
   - tell the user.

   Lost updates become a visible second copy.
3. **Detect conflict copies.** List copies of the vault made by sync
   clients (patterns in 4.8) when opening. Warn, and once phase 1
   lands, offer to merge.
4. **Automatic per-device anchor** for vaults in cloud folders (not
   deniable ones), in app data. A provider-side restore below what this
   device has seen is refused. A higher generation written by another
   device is normal and just moves the anchor forward.
5. **Keep the `.meta-bak` / `.header-bak` mirrors in local app data**
   for vaults in cloud folders. This halves the upload, and another
   device can no longer pair a live region with a mirror from a
   different save.
6. **Bucketed metadata padding refresh** (4.3) for vaults in cloud
   folders. Old readers are unaffected, since the padding is not
   authenticated. Dropbox / OneDrive upload per save drops from about
   128 MiB to the bucket plus the changed chunks. The leaked bucket is
   documented.
7. **"Open on another device" marker:** an encrypted heartbeat next to
   the vault, so a second device warns before opening.
8. **Docs:** a "Vaults in a cloud folder" page, an honest compare page,
   and a README note that Google Drive re-uploads the whole vault on
   each save until phase 2.

### Phase 1: merge engine (weeks)

- **`luksbox merge`:** `luksbox merge ours.lbx theirs.lbx [--base
  base.lbx]`, with a three-way merge as in 4.5 and a two-way union
  without a base, using the same conflict naming.
- **GUI:** a "Resolve conflict copy" flow, offered by phase 0 item 3.
- **Same engine as phase 2:** the bundle uses this engine on forks, so
  it gets tested on real conflict copies first.

### Phase 2: sync bundle (months, plus an audit round)

- An object-store trait (put immutable / get / list / delete) and a
  local-folder backend.
- A paged `LbxFile` backend with the write-back cache and publication.
- Bundle mode in `Container`, replacing its path-based side paths:
  - mirrors off;
  - MVK rotation as a native commit instead of `<vault>.rotating`;
  - header persistence as header objects;
  - the anchor in app data.
- Manifests, table blocks, leases, head selection, anchor and fork
  checks, pending heads.
- Merge on fork (phase 1 engine), garbage collection with retention,
  snapshots.
- `luksbox sync convert my.lbx my.lbxs` and
  `luksbox sync export my.lbxs my.lbx` (single file for USB and
  archives). Single file stays the default for local and removable
  storage.
- GUI: a sync status line ("Up to date", "Waiting for 3 objects from
  Laptop", "Merged 2 changes from Laptop; 1 conflict kept").
- Tests:
  - **Fault simulator:** an in-process "evil provider" that drops,
    delays, reorders, duplicates, truncates, rolls back and forks
    objects, creates conflict copies and changes name case. Property
    tests require that every outcome is a valid snapshot or an explicit
    error.
  - **Fuzzing:** manifest and table parsing.
  - **Manual soak matrix:** Dropbox, Google Drive, OneDrive, iCloud
    Drive, Nextcloud, Syncthing.
- Security audit round dedicated to the bundle.

### Phase 3: revoke a device without having it, native backends

- **Revoking needs a new key, not just a revoked slot.** In a synced
  vault, revoking a slot is not enough: the provider's version history
  keeps old header objects, and an old header plus the revoked
  credential still yields the MVK. Today the answer is `rotate-mvk`,
  which re-uploads the whole vault, and which needs every remaining
  slot's credential to re-wrap the key. TPM and Secure Enclave slots
  of other machines can't be re-wrapped from here.
- **Recipient keyslots.** Each slot also stores a public key (X25519 +
  ML-KEM hybrid), whose private key is wrapped by the slot's
  credential as today. Any device can then encrypt a new key to every
  remaining slot without their credentials.
- **Epoch keys** for the page layer: revoking a device seals a new page
  key to the remaining slots. New commits use it immediately, so the
  revoked device can't read new data even though it knows the old MVK.
  Old pages are re-sealed in the background, which also limits what
  the provider's history exposes.

  This needs no change to the container format, only to the bundle's
  outer layer. Result: revoke a lost laptop from your phone or desktop,
  with forward protection at once and no full re-upload.
- **Native backends** without a desktop client: S3, WebDAV, the Dropbox
  API, the Google Drive API, Microsoft Graph. Immutable objects need
  only put / get / list / delete.
- Later: sharing a vault between people (recipient slots give this
  almost for free); a mobile read-only client.

## 7. Success criteria

- **Small edit:** 1 KiB changed in one file uploads no more than one
  page, the metadata bucket pages, one table block and one manifest,
  on Google Drive as well as on Dropbox.
- **Two devices:** zero conflicted copies of the vault in a two-device
  concurrent-edit soak test. Every concurrent change is merged or kept
  as a conflict copy inside the vault.
- **Fault simulator:** every injected fault (rollback, deletion, swap,
  truncation, reordering, fork, partial upload) ends in a valid
  snapshot or an explicit error, never in a silent wrong state.
- **Object count:** below about 300,000 objects for the default page
  size and 1 TiB.

## 8. Open decisions

1. **Concurrent editing:** is merge a requirement for the first bundle
   release, or is "one device at a time, enforced and detected"
   enough? The layout above supports both. Merge can follow in a later
   minor version, but the per-device namespaces must be there from the
   start.
2. **Default page size** (1 or 4 MiB), and whether it follows
   `--max-size` automatically.
3. **Default history retention** (it costs provider space).
4. **Phase 0 defaults:** turn on items 5 and 6 automatically when a
   cloud folder is detected, or ask once.
5. **macOS package:** whether Finder should show a `.lbxs` bundle as a
   single item. (Name decided: `.lbxs`, not `.lbxd`, which would read
   as "deniable" next to `LBXDAHG2` and `deniable-init`.)

## Sources

- Cryptomator security target (unprotected metadata):
  https://docs.cryptomator.org/security/security-target/
- Cryptomator sync conflicts:
  https://docs.cryptomator.org/desktop/sync-conflicts/
- CryFS (concurrent access not supported, integrity checks):
  https://github.com/cryfs/cryfs and https://www.cryfs.org/howitworks
- Defuse, gocryptfs cryptography design audit (2017):
  https://defuse.ca/audits/gocryptfs.htm
- Hofmann, Truong, "End-to-End Encrypted Cloud Storage in the Wild:
  A Broken Ecosystem", ACM CCS 2024: https://eprint.iacr.org/2024/1616
- Dropbox file-count soft limit:
  https://help.dropbox.com/space/file-storage-limit
- Google Drive has no delta upload (third-party client vendor):
  https://forums.insynchq.com/t/delta-updates-to-google-drive-for-large-files/3823
- Li, Krohn, Mazieres, Shasha, "Secure Untrusted Data Repository
  (SUNDR)", OSDI 2004 (fork consistency).
