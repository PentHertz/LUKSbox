# `.lbxs` sync bundle: implementation and security plan

Design record, not shipped code. `docs/CLOUD_SYNC_DESIGN.md` explains
why a sync bundle and what it must guarantee. This document says how
to build it, and how each security property is enforced and tested.
Where the two differ on a detail, this document is the newer one.

## Status (as built, 2026-10-13)

Implemented, experimental: crates `luksbox-sync` and `luksbox-merge`,
the `Storage` / read-only refactor of `Container` and `Vfs`, the CLI
(`luksbox sync ...`, `luksbox merge`, every command on a bundle
folder), the wizard, the GUI, the mount publish hook. The format is
specified in `docs/CRYPTO_SPEC.md` section 22; the user guide is
`docs/SYNC_BUNDLES.md`.

Where the code departs from the plan below, and why:

- **Merge base.** Not "the" common ancestor but the newest commit on
  both *first-parent chains*. The seeded simulation found a
  real loss: a merge gives files copied in from the other side new
  inode ids, so a common ancestor reached through a merge's second
  parent matched unrelated files by id and deleted them. Inode ids are
  preserved exactly along first parents, so that base is safe; an older
  base only turns already-merged changes into "same content on both
  sides".
- **Merge target.** Always the head every device would pick (highest
  Lamport counter, then hash), also when closing a session, so two
  devices merging the same branches produce the same tree.
- **Equivocation** (two commits with one device and sequence number) is
  a notice, not a fatal error: both branches are kept and merged, and
  the device takes a new identity, also when it finds out while
  publishing. A copied profile or restored VM must not make the bundle
  unopenable for everyone.
- **Missing history.** Every verified commit counts as evidence,
  usable or not: hiding one commit also hides everything built on it,
  and a fresh device must still notice it is not seeing everything.
- **Keyslot tables** are compared by meaning (format, layout, flags,
  generation, slot fields, SEP blobs), not bytes: two devices doing the
  same automatic format upgrade wrote different padding. A change on
  one side only is adopted by the merge; different changes on both
  sides are not merged.
- **Convert** also brings the bundle's header to format v3 (a second
  commit), so devices never each upgrade it independently.
- **Windows store.** The standard library has no directory-handle-
  relative opens on Windows: every object is read through a handle
  opened with `FILE_FLAG_OPEN_REPARSE_POINT` whose resolved path must
  equal the expected path inside the bundle (the existing junction
  guard). Writes and deletions go by path after the same check on the
  folder, so a junction swapped in between the check and the write
  would redirect it (open item: create relative to the folder handle
  with `NtCreateFile`). Hard links are not refused on Windows (the
  link count is not in stable `std`); their content still has to pass
  the object's AEAD. Compile-checked for Windows and macOS; run-tested
  on Linux only.
- **Leases** pin their base for 90 days; garbage collection is
  explicit (`luksbox sync gc`), never automatic.
- **Uploads never hold the vault.** A publish takes the last saved
  state, uploads it without the vault image's lock, then makes it the
  new base; the vault keeps reading, writing and saving meanwhile
  (`the_vault_works_while_a_publish_uploads`). The GUI publishes on a
  worker thread (the status line says "uploading..."), and the GUI and
  CLI mount hooks only start the upload, on a thread, so a mounted
  vault's file operations do not wait for it. The GUI and mount parts
  are compile-checked only (no display or FUSE here).

Phase 0 (a single `.lbx` in a cloud folder, `CLOUD_SYNC_DESIGN.md`
section 6) is in for items 1 to 4:

- the folder is recognised (`luksbox_sync::cloud::cloud_service`); the
  first open on each device says so and points at sync bundles (CLI
  note, GUI toast);
- a vault replaced on disk while open: the next save goes to
  `name (unsaved changes <time>).lbx` (`Vfs::rescue_if_replaced`, after
  each flush; not for deniable vaults);
- conflict copies, and that rescue copy, are listed at every open with
  the `luksbox merge` line;
- the automatic per-device anchor: `<data dir>/luksbox/anchors/`, one
  per vault (header salt) and path, so a conflict copy or a merge
  result is not refused against the vault's own history. Created at
  the first open (trust on first use), moved forward by a newer vault,
  refusing an older one with the copies named. Not for deniable vaults
  or with `--anchor`; `LUKSBOX_NO_AUTO_ANCHOR=1` turns it off. A
  verification failure (for example after `rotate-mvk` on another
  device) refuses too, with the file to delete. `luksbox merge` raises
  the result's generation above every input
  (`Vfs::raise_generation_to`), so the result is accepted in place of
  the vault.

Items 5 to 7 (mirrors kept in app data, bucketed metadata padding for
files, an "open elsewhere" marker) are not done: a sync bundle does
each of them better (no mirrors, per-page uploads, leases), so they
wait for a decision on whether single files still need them. Item 8
(docs) is `docs/SYNC_BUNDLES.md`, section "A single `.lbx` in a cloud
folder".

- **Garbage collection and uploads in progress.** A commit whose
  manifest has not reached the collecting device yet is invisible to
  it. Its new objects are orphans there and kept 90 days. The older
  objects it reuses are kept by its device's lease: a lease also pins
  the newest commit on its head's first-parent line made by another
  device (one the others have), and a session's lease is not removed
  on close but replaced by a *closed* lease (not reported as open)
  that pins for 90 days, until the device's next session replaces it.
  `gc` removes leases older than that. A device offline mid-upload for
  more than 90 days can still lose that commit.

Not done yet: the external witness file (5.4), `forget-device`,
recipient keyslots and epoch keys (phase 3), MVK rotation, panic and
post-quantum enrollment on a bundle, bundles with a detached header,
mounting a bundle through the macOS FUSE-T GUI helper and the Windows
background mount, native provider APIs, a GUI "resolve conflict
copy" flow (the GUI names the copies and points at `luksbox merge`),
and handle-relative writes in the Windows store. A header fork (the
rest of the header changed on both sides; keyslot changes alone are
merged) has no resolve command: after `convert` brings the header to
format v3, nothing on a bundle changes those fields (rotation is
refused), so only a misbehaving device can cause one, and the check
stays as a safety net.

Verification so far:

| What | Result |
|---|---|
| Unit and integration tests, `luksbox-sync` | 84 (single device, multi-device, GC, keyslot merge, phase-0 anchor, codec, store, names, graph, simulation, the vault used during an upload, truncate-and-grow, page cache, failed save, delete, restore, opening with the key) |
| Seeded simulation | 3 devices, random sync lag and crashes, GC; adversarial rollback, deletion, corruption, replay, planted files; 20 to 30 seeds per run, no loss, no forged content. Vault keys are random, so a seed does not replay exactly: one run found a harness bug (a device opened read-only after a withheld commit made the harness's `mkdir` fail), not a protocol bug |
| `luksbox-merge` | 11 rule tests and a randomized "no version lost" property |
| Fuzzing | 5 new targets (object open, manifest decode, names, table decode, commit graph); smoke runs without findings |
| Existing suites | core, format, vfs (5 new external-storage, rescue and generation tests), CLI (88, five new end-to-end tests: bundle, merge, cloud-folder anchor, sidecar link on convert, read-only verify): all pass |
| Cross-platform | `luksbox-sync` and `luksbox-merge` compile for Windows (MSVC) and macOS (aarch64); GUI compiles with and without default features; not run there |
| Not done | TLA+ model (no Java on the build machine; the simulation covers the protocol), real-provider soak tests, audit round 16 |

## 0. Security principles

Every decision below follows from these rules.

1. **The bundle folder is hostile input.** Sync clients write into it on
   behalf of the provider: names, file types (symlinks, junctions,
   FIFOs), sizes, counts and contents can all be attacker-chosen. It is
   handled with the care of a network parser, not of a local file.
2. **Authenticate, then parse, then use the bytes you checked.**
   Nothing read from the bundle is parsed before its AEAD tag and
   commitment verify. Everything is read once into memory, verified,
   and used from that buffer; nothing is read twice by path. The only
   exceptions are object names (a strict grammar) and the 8 KiB header,
   which is already parsed before its HMAC today.
3. **One key per object, and every object bound to its identity.**
   Every object is sealed under a key derived for that object alone,
   and its associated data names the bundle, the object kind, the object
   id and its position. Cut-and-paste between objects, positions,
   kinds or bundles fails.
4. **Two independent integrity layers.** The outer bundle layer (this
   plan) authenticates every page and every commit. The inner container
   layer (header HMAC, metadata AEAD, per-chunk AEAD bound to
   `file_id || chunk_idx || generation`) stays exactly as audited. A
   flaw in one layer alone does not give an attacker a forged vault.
5. **Never overwrite, never follow, never delete what a commit may
   need.** Objects are created no-clobber, never through a link, and
   deleted only by name, after a grace period, when nothing reachable
   refers to them.
6. **Fail closed, precisely.** Every integrity problem is a named error
   with what was expected and what was found. Nothing is silently
   repaired.
7. **No new cryptography in the first version.** It uses HKDF-SHA256,
   HMAC-SHA256, SHA-256 and the vault's own AEAD (AES-256-GCM-SIV by
   default), all already in the code. New primitives (X25519, SHA3,
   X-Wing) wait for phase 3.
8. **Specification, model and simulation come before shipping.** The
   format goes into `CRYPTO_SPEC.md` with test vectors. The protocol is
   model-checked, and the real code runs against a simulated hostile
   provider before any user data goes near it.

## 1. What the current code constrains

Mapped from the code before writing this plan (file:line as of
`69448f7`):

- **`Container` reaches storage outside `LbxFile`.** These paths
  bypass the trait:
  - the `.meta-bak` / `.header-bak` mirrors (`container.rs:2689, 3635`);
  - the detached header as a concrete `File` (`HeaderStorage::Detached`,
    `container.rs:539`);
  - MVK rotation through `<vault>.rotating` (`container.rs:3986-4248`);
  - the anchor (`container.rs:3828-3915`);
  - the lock, which takes `&File` (`lock_handles`, `container.rs:427`);
  - `Drop`, which calls `persist_header` (`container.rs:4254`);
  - the hybrid sidecar, keyed by slot index (`hybrid_sidecar.rs:203`);
  - raw header reads in `header-backup` (`main.rs:1884`);
  - free-space checks on `vault_path` in the mount crates.

  No constructor accepts a `Box<dyn LbxFile>`; only the test-only
  `swap_lbx_file_for_test` replaces the handle.
- **`Vfs::flush` is also called internally**: when 256 MiB of slots wait
  to be freed (`vfs.rs:3323`), at the size limit (`vfs.rs:3946`), and
  from `close`, `finish`, shrink and the header upgrade. Uploading can
  therefore not hang off `flush`; it needs its own trigger.
- **There is no real read-only open.** Containers are always opened
  read-write under an exclusive lock. `Drop` can persist a header
  recovered from its mirror, and a `flush` after mirror recovery
  rewrites the vault even when nothing changed. A merge needs
  read-only views.
- **Inode ids are sequential counters** (`tree.rs:264`), so two forks
  allocate the same ids to different files. The per-file key and the
  chunk associated data are bound to the file id (`chunk.rs:38, 104`).
  A merge must therefore match files through the common ancestor and
  copy content by decrypting and re-encrypting. Only `mtime` is stored;
  writing sets it to "now", so a replay must restore it.
- **Slots are not bound to their index** (`keyslot.rs:2027`): moving a
  slot to another index in the same vault is allowed. The hybrid
  sidecar, however, is keyed by slot index.
- **The detached-header layout exists already**: metadata at offset 0,
  data after it (`container.rs:1967`). The bundle image reuses it.

Found while mapping, to fix on their own (step 0 of section 13):

- **Spec drift in `CRYPTO_SPEC.md`:**
  - Section 3.2 lists slot kinds 0-7 and AAD versions V1-V3; the code
    has kinds 0-27 and V4.
  - Section 3.3 lists 4 HKDF labels and describes `file_key` as
    HKDF-Expand only; the code extracts with `header_salt` first and
    has many more labels.
  - Section 3.9 has stale line references.
- **Stale comments in the code:**
  - `chunk.rs:35-37` omits `generation` from the chunk AAD.
  - `keyslot.rs:398` names the wrong label for the Secure Enclave
    hybrid KEK.
- **Create does not reach the disk:** `create_internal` ends with
  `flush()` only, with no `sync_all` and no directory fsync
  (`container.rs:2002`). A crash right after creating a vault can leave
  it incomplete.

## 2. Architecture

```
  GUI / CLI / wizard / mount              unchanged entry points
            |
  luksbox-vfs        + Vfs::open_read_only, + commit_point() hook
            |
  luksbox-format     Container { storage: Storage }
                       Storage::File    today's .lbx (+ .hdr)
                       Storage::Bundle  new, backed by luksbox-sync
            |
  luksbox-sync (new crate, no unsafe outside the OS layer)
    bundle_dir   hostile-folder I/O: openat / no-follow / no-clobber
    codec        seal / open objects, names, size limits
    image        PagedImage: LbxFile over pages + outbox
    outbox       per-device journal of staged commits
    state        per-device sealed state (anchor, ids, pins)
    open         list, verify, build the commit graph, pick the head
    publish      fast-forward / fork publish, leases
    gc           retention, two-phase deletion
  luksbox-merge (new crate) tree diff and replay through the Vfs API
```

- **Build feature:** `sync`, on in the CLI and GUI. The bundle code is
  pure Rust plus `libc` / `windows-sys`, which are already dependencies,
  so the static musl CLI can include it.
- **Refactor first:** `Storage` is introduced with
  `Storage::File` reproducing today's behaviour exactly, and the whole
  existing test suite must pass before any bundle code lands. Every
  side path listed in section 1 becomes a `match` on `Storage`, so
  file vaults keep their audited code paths byte for byte.

## 3. On-disk format

### 3.1 Tree and name grammar

```
my.lbxs/
  h/<bid>-<hgen>-<rnd>      header object, 8192 bytes (absent if detached)
  x/<bid>-<hgen>-<rnd>      hybrid sidecar object (only with ML-KEM slots)
  p/<aa>/<oid>              page objects
  t/<aa>/<oid>              page-table blocks
  m/<aa>/<oid>              manifests (commits)
  l/<lid>                   leases, one per open session
  */.tmp-<rnd>              our temporary files, in the same folder
```

| Field | Format |
|---|---|
| `bid` | bundle id, 32 lowercase hex characters (16 random bytes) |
| `hgen` | `header_generation`, 16 hex characters |
| `rnd` | 32 hex characters |
| `oid` | object id, 64 lowercase hex characters (32 random bytes) |
| `aa` | the first two characters of `oid` |
| `lid` | 64 hex characters, new for every session |

- **Grammar:** names are matched against exact patterns. Anything else
  is "foreign": counted, reported by `luksbox sync status`, never
  parsed, never deleted automatically. That includes sync-client
  conflict copies, `.DS_Store`, uppercase variants and NFD-normalised
  names.
- **Manifest names carry no device or sequence number.** These live
  inside the encrypted manifest, so the provider cannot see which
  device committed, and cannot cheaply single out one device's latest
  commit to withhold.

### 3.2 Image and pages

- **Image layout:** the image is a detached-header container image
  (metadata region at offset 0, chunk slots after it); the header is the
  `h/` object, or the user's detached `.hdr` file.
- **Pages:** page `i` covers image bytes `[i*P, (i+1)*P)`. The page size
  `P` is 1, 4 or 16 MiB and is fixed at creation (design doc 4.6). The
  last page is zero-padded inside the seal; the logical length is in
  the manifest.
- **Page table:** table block `j` lists pages `[j*1024, (j+1)*1024)`.
  Each entry is `oid (32) || sha256(object bytes) (32)`, and an
  all-zero entry is a hole (never written, reads as zeros).

### 3.3 Key schedule

Root keys use the existing `Container::derive_subkey(info)`
(HKDF-SHA256, extract with `header_salt`, expand with `info`). Each
root has its own label:

```
R_page     = derive_subkey("lbx:sync/page/v1"     || bid)
R_table    = derive_subkey("lbx:sync/table/v1"    || bid)
R_manifest = derive_subkey("lbx:sync/manifest/v1" || bid)
R_lease    = derive_subkey("lbx:sync/lease/v1"    || bid)
R_local    = derive_subkey("lbx:sync/local/v1"    || bid)
```

Per object, 64 bytes are expanded from the root of its kind and split:

```
K_enc || K_com = HKDF-Expand(PRK = R_kind, info = "lbx:sync/obj/v1" || kind || oid, L = 64)
```

- **One key, one encryption.** `K_enc` encrypts exactly one object. The
  `oid` is 32 bytes from `OsRng`, and the codec keeps an in-process
  set of the oids it sealed and refuses a second seal. The AEAD nonce
  is therefore the constant zero: with a single-use key that is safe
  for all three suites, and the design no longer depends on random
  nonces never colliding across devices.
- **Key commitment.** `commit = HMAC-SHA256(K_com, "lbx:sync/commit/v1"
  || kind || oid)` is stored in clear and compared in constant time
  (`subtle`) before decrypting. GCM-family AEADs do not commit to their
  key, so without this an object could be made to decrypt validly
  under two keys. That matters little while one MVK derives everything,
  but it closes the class of attack before phase 3 adds several
  recipients.
- **Secrets in memory.** Root keys are `Zeroizing`; the phase 3 epoch
  keys go in `SecretBox`, as the MVK does today.

### 3.4 Object envelope

```
bytes 0..32   commit
bytes 32..    AEAD(K_enc, nonce = 0^12, AAD, plaintext) || tag(16)
AAD = "lbxs" || u16 format || u8 kind || bid || oid || binding
binding: page = page_index u64 | table = block_index u64 | manifest, lease = empty
```

- **No visible format markers.** There is no magic number and no
  version byte in the clear, so every object is uniformly random bytes.
  Kind and version come from the folder and the associated data.
- **Fixed sizes:**
  - page `32 + P + 16`;
  - table block `32 + 65536 + 16`;
  - lease `32 + 4096 + 16`;
  - manifest one of 16 KiB, 64 KiB, 256 KiB or 1 MiB.

  A file of any other size is refused before it is read in full.

### 3.5 Manifest (plaintext after opening)

postcard-encoded, with a decode limit equal to the object size, and
padded inside the AEAD:

```
format u16 = 1          bundle_id [16]         device_id [16]
seq u64                 lamport u64            wall_clock_ns u64 (informative)
parents   [1..=8]    (device_id, seq, manifest_oid, sha256(manifest object))
seen      [..=256]   (device_id, seq, sha256(manifest object))   newest seen per device
checkpoint[..=256]   (device_id, min_seq)      history below is deleted on purpose
header               (name, sha256, header_generation)   or (detached, sha256, hgen)
hybrid               optional (name, sha256)
page_size u32        logical_len u64
tables               [..=16384] (oid, sha256)
kind                 Commit | Merge | Rotation | Convert | Restore
merge_log            optional, bounded list of decisions (section 7)
gc_plan              optional (section 8)
device_label         <= 64 bytes, sanitised
```

- **The manifest commits to the whole image:** its table entries commit
  to the table blocks, the blocks to the pages, and the pages carry the
  inner container. `sha256(manifest object)` is therefore a hash of
  the complete vault state, and it is what `parents`, `seen` and the
  safety code (section 5.4) refer to.
- **Ordering:** `seq` is contiguous per device from 1, and `lamport` is
  `max(parents.lamport) + 1`. Wall-clock time is displayed, never
  trusted.

### 3.6 Per-device state (outside the synced folder)

`<data dir>/luksbox/sync/<bid>/`, folder mode 0700, files 0600, written
with `atomic_secure_write`:

| File | Contents |
|---|---|
| `state` | Sealed under `R_local`. Device id and label, own `seq` and last manifest hash, `seen` (device to seq and hash), highest `header_generation` seen, last opened head, epoch. |
| `journal` | Append-only sealed records of staged commits, fsync'd per record. |
| `outbox/` | Sealed objects not yet published (ciphertext only). |
| `pins/` | The base manifest, its table blocks and the metadata pages of every unpublished commit, kept for a later rebase. |
| `lock` | `flock`, so only one process per device works on a bundle. |

`<data dir>/luksbox/sync/paths` maps each canonical bundle path to its
`bid`. A folder that once held bundle A and now holds bundle B is
reported, as CryFS does.

Deniable vaults never become bundles, so this state never betrays one.
For an ordinary vault it reveals what `recent.json` already does.

## 4. Hostile-folder I/O (`bundle_dir`)

- **Open the bundle once:**
  - The user's path is canonicalised and opened as a directory handle
    with `O_DIRECTORY|O_NOFOLLOW`.
  - Every later operation is relative to that handle or to sub-folder
    handles opened the same way.
  - Linux: `openat2` with `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS`, falling
    back to per-component `O_NOFOLLOW` on kernels older than 5.6.
  - macOS: `O_NOFOLLOW_ANY`.
  - Windows: `FILE_FLAG_OPEN_REPARSE_POINT`, refusing reparse points,
    plus the existing final-path comparison used against junctions.
- **Check what was opened:** `fstat` must show a regular file (folders
  for `h p t m l x` and the shards), with the exact expected size and,
  on Unix, a link count of 1. FIFOs, devices, sockets, hard links and
  links of any kind are refused before a byte is read.
- **Bounded reads:** `read_exact` of the expected size, then an EOF
  check. No `read_to_end`, and no size taken from the file.
- **Bounded listings:** they stream with hard caps (for example 4
  million entries in total and 100,000 manifests). Over a cap, the
  error says so: a flooded folder is a denial of service, never a crash
  or memory exhaustion.
- **No-clobber creates:**
  - write a `.tmp-<rnd>` file (`O_CREAT|O_EXCL|O_NOFOLLOW`, 0600);
  - fsync it;
  - publish it with `atomic_secure_create_new`, which already exists
    (`file_util.rs:1009`, `link(2)` / `MoveFileExW` without replace);
  - fsync the folder.

  An existing name is an error, never an overwrite. Leases are the only
  mutable objects; they use the replace variant.
- **Deletes** are `unlinkat` of a grammar-valid name in a verified
  folder handle, never recursive.
- **Placeholders:** a cloud-only placeholder (OneDrive, iCloud, Dropbox
  online-only, Drive streaming) is downloaded by the read itself.
  Reads have a timeout and report progress. A read error means "not
  available yet", not "corrupt".
- **Sharing violations** while the sync client uploads (Windows) are
  retried with backoff.

## 5. Opening a bundle

### 5.1 Header bootstrap

1. List `h/` (and `x/`) for `bid`. Parse each header without
   authentication (as today) and sort by `header_generation`, newest
   first.
2. Unlock with the newest header the credential opens. Verify its HMAC.
   Headers that fail parsing or the HMAC are reported and skipped.
3. Derive the root keys, then open and select the head (5.2).
4. **Use the head's header.** The selected head names its header. If
   that is not the header used to unlock, unlock again with the named
   one (it is never older than the local state's highest
   `header_generation`).
   - If the credential does not open it, the error is
     `CredentialRevoked { since_generation }`. An honest client never
     opens a bundle through a superseded header, so a revoked
     credential plus an old header the provider kept does not get in
     through LUKSbox.
   - What it does not stop is someone deriving the old MVK from that
     old header with their own tools. That is why revocation needs
     rotation (section 9).

### 5.2 Building and checking the commit graph

1. **Verify the manifests.** Read and verify every manifest: commitment,
   AEAD, decode limit, `bundle_id`. A manifest that fails is foreign
   (reported, ignored). A verified manifest is cached in local state by
   object hash, so the next open does not decrypt it again.
2. **Detect equivocation.** Two different manifests claiming the same
   `(device, seq)` mean two installations share one device id (a
   copied profile, a restored VM) or a former key holder is active. The
   error is `Equivocation`. Both are kept as separate heads for merging,
   and this device takes a new id.
3. **Check continuity.** Per device, `seq` must be contiguous above its
   checkpoint, and every `parents` entry must exist with the stated
   hash. A gap is `MissingHistory`: shown as pending for a grace time
   (sync lag), then as an error.
4. **Compare with local state.** For every device known locally, the
   bundle must contain its recorded `seq` with the recorded hash (or a
   checkpoint above it) and nothing lower as its newest.
   - Lower is `RollbackDetected { device, seen, visible }`.
   - Same `seq` with another hash is `Equivocation`.
   - For this device itself, a newer own `seq` that it never wrote is
     `IdentityConflict` (see step 2).
5. **Check what others saw (transitive).** For every verified manifest
   M and every `(d, s, h)` in `M.seen`, the bundle must contain device
   d's chain up to s with hash h. If not, the error is
   `WithholdingDetected`: one device's commits are hidden from another.
   This is fork consistency (SUNDR).
6. **Pick the heads:** the manifests that are nobody's parent. A head is
   complete when every object it references is present with the right
   size; contents are verified when read.
7. **Open:**
   - One complete head: open it.
   - Several complete heads: merge them (section 7) when opening for
     writing, or open the one with the highest `lamport` read-only with
     a banner.
   - Pending heads only (objects still arriving): open the newest
     complete one and say what is pending.
8. **Record what was seen.** After opening, write the new `seen` to
   local state (atomically) before any write is accepted.

### 5.3 Reading

- **Reading a page:** `PagedImage::read` finds the table block (cached
  after verification) and the page entry, reads the object through
  `bundle_dir`, and checks its size, SHA-256, commitment and AEAD
  (binding `page_index`). Only then is the page cached.
- **What gets cached:** the cached bytes are still inner-container
  ciphertext, so no user plaintext is held by this layer.
- **Inner checks still apply:** header HMAC, metadata AEAD, chunk AEAD.

### 5.4 Safety code and external witness

- **Safety code:** `SHA-256("lbx:sync/safety/v1" || sorted heads
  (device, seq, hash))`, shown as 4 groups of 4 digits in the GUI and in
  `luksbox sync status`. Two devices that show the same code after
  syncing see the same history; a provider showing them different
  forks cannot make the codes match. This is the cheap out-of-band
  check fork consistency needs, the same idea as Signal's safety
  numbers.
- **External witness:** `luksbox sync witness --add <file>` keeps a
  sealed copy of `seen` on separate storage (a USB stick, a second
  provider). It is checked like local state, so a provider that freezes
  *every* device's view is caught. It replaces `--anchor` for bundles.

## 6. Writing and publishing

### 6.1 Local durability

- **Writes:** `PagedImage` implements `LbxFile`. A write copies the
  page (read-modify-write; a write covering the whole page skips the
  read) and marks it dirty in memory. Past 64 MiB of dirty pages they
  are sealed into the outbox early (as built), so a large write does
  not hold the file in memory; the staged record still changes only at
  `sync_all`, and a publish uploads only what the record holds (the
  last save), never a save in progress. Truncating the image and
  growing it back reads zeros past the cut, as a file does (the record
  keeps the cut).
- **`sync_all`, the durability point.** Each dirty page is sealed as a
  new object (new `oid`) into `outbox/`, the changed table blocks are
  sealed too, and a `StagedCommit { base, pages, tables, header? }`
  record is appended to `journal` and fsync'd. A page sealed again
  before publishing replaces its outbox object; the old one was never
  published and is deleted.
- **Internal flushes only stage.** Every `Vfs::flush`, including the
  internal ones (section 1), only stages; nothing leaves the device.
- **Crash safety:** the journal holds every saved change, so a crash
  loses nothing. At the next open, staged commits are replayed and
  published.
- **Changes in bundle mode:**
  - `.meta-bak` / `.header-bak` mirrors are off: staging is atomic.
  - The metadata padding is refreshed only up to the bucket (design 4.3).
  - The exclusive lock is the `lock` file in local state.

### 6.2 When to publish

- **Triggers** (`Vfs::commit_point()`, called by the mount layer and
  the GUI, never by `flush`):
  - lock or unmount;
  - 10 s without writes;
  - at most every 5 minutes while writing;
  - "Sync now" in the GUI or `luksbox sync push`.
- **Header changes are published at once:** enroll, revoke, update and
  rotation.
- **Status:** the GUI shows "Changes not uploaded yet" while the journal
  holds unpublished commits. "Saved" and "uploaded" are different
  things, and the user must be able to see which one they have.

### 6.3 Publish protocol

1. **Look again.** Refresh the view of the bundle (section 5.2, steps
   1-6).
2. **Fast-forward** if the staged commit's base is still the only head:
   1. create every outbox object in the bundle (no-clobber; an object
      already present with the same hash is fine, so re-publishing is
      idempotent);
   2. fsync the folders;
   3. write the manifest last (`seq = own + 1`, `parents = [base]`, full
      `seen`);
   4. update local state;
   5. clear the journal.
3. **Fork publish** if another head appeared and the vault is mounted
   (open handles, so no merge under a live file system): publish the
   same way with `parents = [base]`. This is allowed only if every
   inherited object of `base` still exists, which leases (6.4) make
   sure of. The fork is merged at the next open, lock or unmount.
4. **Merge then publish** if another head appeared and nothing is open
   (lock, unmount, GUI browser idle): rebase with section 7, then
   publish a `Merge` commit with both parents.
5. **Superseded headers:** once a manifest naming a new header is
   published, older header objects of the same lineage are deleted.
   History keeps no headers, so old keyslot tables do not linger in
   the bundle (the provider's own version history may still have them).

### 6.4 Leases

- **What a lease holds:** `l/<lid>` is a fixed-size sealed object with
  the device id and label, the session mode (read-write or read-only),
  the base manifest it pins, the opening time and a heartbeat (every
  5 minutes). It is removed on close. (As built: replaced on close by
  a closed lease that keeps pinning, and every lease also pins the
  newest other-device commit on its first-parent line; see the status
  section.)
- **What it is used for:**
  - A second device opening read-write sees a fresh lease (under 15
    minutes) and is warned.
  - Garbage collection keeps everything a lease's base needs, for up to
    90 days.
- **What it is not:** never a lock, because two devices can always miss
  each other's lease.

## 7. Merge engine (`luksbox-merge`)

### 7.1 Prerequisites

- **`Vfs::open_read_only`:** a real read-only mode. Every mutator
  returns `ReadOnlyMount`, `flush` and `finish` do nothing, and
  `Container::persist_header` and `Drop` never write. It is also useful
  for single-file `luksbox merge` and for `check`.
- **Snapshot views:** bundle views over any manifest are `PagedImage`s
  with a discard overlay. Even a bug that writes cannot stage or
  publish anything.

### 7.2 Algorithm (base B, published head T, ours O)

1. **Index each tree.** Build an index of B, O and T: inode id, path,
   kind, size, `mtime_ns`, mode, link count, symlink target, chunk
   references.
2. **Match files.** Inodes that exist in B are the same file in O and
   T. Ids allocated after B (above B's `next_file_id`) are new on that
   side and are matched by path only, because forks reuse ids.
3. **Decide "changed".** "Changed since B" compares size, mode, target
   and chunk references against B. This is sound because every chunk
   write after B takes a generation above B's counter. "Same content in
   O and T" is decided only when both changed a file, by streaming the
   plaintext SHA-256 of both (1 MiB `Zeroizing` buffers).
4. **Replay O's decisions onto a writable view of T,** through the Vfs
   API: `mkdir`, `create` plus `write` (copied from O's view, so
   decrypted and re-encrypted in memory under T's file ids), `truncate`,
   `rename`, `unlink`, `rmdir`, `symlink` (through
   `is_safe_symlink_target`), `chmod`, `set_mtime` last.

| Case | Result |
|---|---|
| Changed on one side only | That side's version |
| Changed on both, same content | One file; metadata from the higher Lamport |
| Changed on both, different content | T's version at the path; O's as `name (conflict <label> <yyyy-mm-dd hhmm>).ext` |
| Deleted on one side, changed on the other | The changed version is kept (parent folders re-created if needed) |
| Deleted on both | Deleted |
| Renamed on both to different paths | T's path; O's rename recorded in the merge log |
| Same new path, different content | T's at the path, O's as a conflict copy |
| Folder deleted on one side, files added inside it on the other | The folder and the added files are kept |
| Hard links changed on the merging side | Copied as separate files, recorded in the log |

- **Conflict names:** the side already published keeps the name, as with
  sync clients. Conflict names avoid `: / \ * ? " < > |`, stay under
  255 bytes (the stem is shortened, the extension kept) and get a
  numeric suffix if still taken.
- **Deterministic and convergent:** the merge walks paths in sorted
  order, so the same inputs give the same tree. Two devices that merge
  the same fork produce equal trees, and merging those two merges finds
  only "same content" cases.
- **Never loses data.** Every file version present in O or T is in the
  result, at its path or as a conflict copy, unless it was deleted on
  one side and unchanged on the other. This is a tested property
  (section 12).
- **Size limit:** a merge may go past the vault size limit, with a
  warning, rather than fail.
- **Merge log:** what was taken from where and every conflict copy,
  stored in the merge manifest and shown to the user.

### 7.3 Without a base (single-file conflict copies)

`luksbox merge ours.lbx theirs.lbx -o merged.lbx` without `--base` is a
union: each path present on one side is kept, and each path present on
both with different content gets a conflict copy. It is phase 1 of the
design and exercises the engine on real conflict copies before bundles
exist.

## 8. Garbage collection, retention, snapshots

- **Roots** (never deleted, nor anything reachable from them):
  - each device's newest manifest;
  - every manifest from the last 30 days (configurable);
  - every base pinned by a lease less than 90 days old;
  - the current header and hybrid objects.
- **Two-phase deletion:**
  1. A GC pass computes unreachable objects and records them as a
     `gc_plan` (object list digest, Lamport, wall time) in a manifest it
     publishes.
  2. A later pass, at least 7 days after that plan was published,
     deletes only the objects of the plan that are still unreachable
     from all roots *now*.

  As built: "7 days after" is measured both by the plan's clock and
  by when the deleting device first saw the plan (local `gc-seen`),
  whichever is shorter, so another device's wrong clock cannot shorten
  it; a device whose clock went back behind its own records refuses to
  collect. Objects no known commit refers to (*orphans*: most likely a
  commit whose manifest is still uploading, since sync clients upload in
  any order) are flagged in the plan and wait 90 days instead.

  A device that went offline with work based on an old head therefore
  never finds its base deleted under it, unless it was offline longer
  than the lease pin. In that case it rebases from `pins/` in its local
  state.
- **Checkpoints:** old manifests are deleted by publishing a
  `checkpoint` (lowest kept `seq` per device) first. A missing manifest
  below a checkpoint is legitimate; above it, it is `MissingHistory`.
- **What is never deleted automatically:** objects from an
  unauthenticated plan, foreign files, temporary files younger than a
  day, anything in another bundle.
- **Snapshots:** `luksbox sync snapshots list | diff | restore` work on
  manifests within retention. A restore copies files from the snapshot
  into a new commit; it never moves the head backwards, so it is not a
  rollback, and keyslots always stay current.

## 9. Keyslots, rotation, revocation

- **Keyslot changes** (enroll, revoke, update) require no fresh foreign
  read-write lease and no unmerged fork. They write a new header
  object, publish at once, and delete the superseded header. Two
  devices changing keyslots concurrently produce a header fork. It is
  never merged automatically: the user picks one, and the other
  change has to be redone.

  As built: concurrent keyslot changes are merged keyslot by keyslot
  (`bundle::merge_keyslot_tables`, rules in `CRYPTO_SPEC.md` 22.10): a
  removal always wins, two enrollments in the same free slot are both
  kept (one moves), a slot changed differently on both sides keeps the
  target's and the user is told to redo the other. Only a change to the
  rest of the header on both sides is still a fork. A device's
  unpublished changes that cannot be replayed at all (the commit they
  were made on is gone) leave it read-only with
  `Notice::UnmergedLocalChanges`; `luksbox sync discard-local --yes`
  drops them.
- **Revocation needs rotation.** Old headers may survive in the
  provider's version history, so revoking a slot in a synced vault
  shuts out LUKSbox but not someone holding an old header copy. The GUI
  and CLI therefore propose `rotate-mvk` right after a revoke.
- **Rotation in a bundle** is a native atomic commit, replacing the
  `.rotating` temp file:
  1. The existing rotation code re-keys every chunk into the paged
     image; all pages become new objects under the new MVK's roots.
  2. The new header and the `Rotation` manifest are published together
     (parents still reference the previous head by hash, so other
     devices' rollback checks keep working without the old key).
  3. Old pages go through two-phase deletion.

  Costs: local disk for a full outbox, a full re-upload, and history
  older than the rotation can no longer be opened. For a revocation
  that last point is intended.
- **Phase 3, revocation without a full re-upload:**
  - **Recipient keyslots:** each slot also holds an X25519 + ML-KEM-768
    key pair. The private key is wrapped by the slot's existing KEK; the
    public key is in the header.
  - **Hybrid combiner:** X-Wing, which hashes the ML-KEM secret with the
    X25519 secret, ciphertext and public key. That also closes a gap
    seen in today's hybrid KEKs (`kdf.rs:237`), which do not bind the
    KEM ciphertext or public key.
  - **Epoch keys:** an epoch key is sealed to every current recipient
    (`e/` objects). Page, table and manifest roots are derived from the
    epoch key instead of the MVK.
  - **Revoking a device:** seal a new epoch key to the remaining
    recipients, from any device, without the other devices' credentials
    or hardware. New commits use it immediately, so the revoked device
    cannot read or forge anything new even though it knows the old MVK.
    Old pages are re-sealed in the background.

## 10. What the provider learns

| Object | Visible |
|---|---|
| `p/` | Page count (vault size, rounded to a page); how many pages a commit adds (write volume, rounded to a page); never which positions changed, because table blocks are sealed. |
| `t/` | Number of table blocks touched per commit. |
| `m/` | Commit times; the size bucket of each manifest. Not which device committed. |
| `l/` | When a session is open, and how many are open at once. Leases can be turned off (`--no-lease`), losing the warning. |
| `h/`, `x/` | The header, as today (what any `.lbx` shows), and when keyslots change. |

**Optional constant traffic** (`--pad-commits`): every commit is padded
to the next power of two of pages with re-sealed unchanged pages, and
publication times get random jitter. It costs bandwidth, and is off by
default.

## 11. Security invariants

Each invariant has a mechanism and a test that must fail if it breaks.

| # | Invariant | Mechanism | Test |
|---|---|---|---|
| I1 | Nothing from the bundle is parsed or used before its commitment and AEAD verify. | codec API only returns verified buffers | fuzz `sync_object_open`; mutation tests on every byte |
| I2 | Every encryption key is used for exactly one object. | per-object HKDF from a 256-bit `oid` drawn inside `codec::seal_new`, the only sealing entry point; no store can overwrite an object, so a lease refresh is a new object (as built: no seal registry) | `fresh_ids_for_identical_plaintexts`, `never_overwrites_and_foreign_entries`, `a_heartbeat_replaces_the_lease_with_a_new_object` |
| I3 | An object moved to another kind, position, bundle or version fails. | associated data plus table hashes | cut-and-paste tests for every pair of kinds and positions |
| I4 | The opened state is exactly one verified manifest's image. | Merkle chain manifest -> tables -> pages, plus inner integrity | simulation: random partial, mixed and reordered objects never open as a mix |
| I5 | No device opens a state older than one it has seen, for any device. | local state and witness checks (5.2.4) | simulation rollback, freeze and delete faults, 100% detected |
| I6 | Hiding one device's commits from another is detected once any manifest that saw them is visible. | `seen` checks (5.2.5) | simulation fork and withholding faults |
| I7 | Nothing is overwritten, followed through a link, or opened outside the bundle. | `bundle_dir` (section 4) | hostile-folder suite: symlinks, junctions, FIFOs, hard links, renames during reads |
| I8 | No object reachable from a root is deleted. | two-phase GC with grace (section 8) | model check plus simulation with offline devices |
| I9 | A saved change is never lost silently: it reaches every later head, or is shown as a conflict copy. | journal, idempotent publish, merge rules | model check; simulation "every write visible" property; merge property tests |
| I10 | The sync layer writes no plaintext to disk. | it handles inner-container ciphertext only; merge buffers are `Zeroizing` and in memory | test greps outbox, pins and bundle for planted plaintext markers |
| I11 | An honest client never opens through a superseded header. | head-named header (5.1.4) | test: revoked credential with old header present gives `CredentialRevoked` |
| I12 | Two installs with one device id are detected and separated. | `Equivocation` / `IdentityConflict` | simulation clones a device state |
| I13 | Large or many foreign files cannot crash or exhaust memory. | size and count caps, streaming listings | flood tests (1M files, 10 GiB file, deep folders) |
| I14 | File vaults behave exactly as before. | `Storage::File` refactor with no behaviour change | full existing suite plus differential test against the old code |

## 12. Verification plan

1. **Specification:** `CRYPTO_SPEC.md` section 20, covering byte
   layouts, every HKDF label, every associated data format, the
   manifest schema, and the open, publish, merge and GC algorithms.
   Each label and object kind gets a test vector. Fix the spec drift
   listed at the end of section 1 first.
2. **Protocol model:** TLA+ (or Quint) of publish, fork publish, merge,
   leases and GC, with an adversarial store that reorders, delays,
   drops, duplicates, rolls back and forks. Model-check I5, I6, I8 and
   I9 and convergence with 3 devices and short histories.
3. **Deterministic simulation:** the real `luksbox-sync` and
   `luksbox-merge` code run against an in-memory `BundleDir` with a
   virtual clock, several simulated devices doing random file
   operations, and a seeded fault injector:
   - every provider fault class;
   - crashes at every step of staging and publishing, reusing the
     `test-injection` crash points;
   - clock skew.

   Invariants are checked after every step, and seeds reproduce
   failures. It runs short in CI and long nightly.
4. **Fuzzing,** new cargo-fuzz targets next to the existing 20:
   `sync_object_open`, `sync_manifest_decode`, `sync_name_grammar`,
   `sync_graph_build` (random manifest sets), `sync_local_state_decode`
   and `merge_trees` (random operation sequences on two branches).
5. **Differential tests:** the same random operation sequence on a file
   vault and on a bundle gives identical `readdir`, `stat` and `read`
   results.
6. **Hostile-folder suite** on Linux, macOS and Windows CI runners.
7. **Real-provider soak tests** before each release with sync changes:
   two machines or VMs doing random edits for 24 h on Dropbox, Google
   Drive (mirror and streaming), OneDrive (Files On-Demand), iCloud
   Drive (Optimise Storage), Nextcloud and Syncthing. Pass: convergence,
   zero vault-level conflict copies, no integrity error, upload volume
   within the design's estimate.
8. **Audit round 16,** dedicated to the bundle, the merge engine and the
   storage refactor, with the spec and model as inputs. The format stays
   behind `--experimental-sync` until it is done.

## 13. Build order

Each step lands with its tests; none changes file-vault behaviour.

| Step | Content | Exit criterion |
|---|---|---|
| 0 | Spec drift fixes; `CRYPTO_SPEC.md` section 20 draft; TLA+ model | model checks pass; spec reviewed |
| 1 | `Storage` refactor in `Container`; `Vfs::open_read_only` | existing suite green; differential test green |
| 2 | `luksbox-sync`: `bundle_dir`, codec, names, keys, test vectors, fuzz targets | hostile-folder suite and fuzz smoke green |
| 3 | `PagedImage`, outbox and journal, local state, single-device publish and open, `sync convert` / `export` / `status` / `verify` | single-device simulation green; I1-I5, I7, I10 tests |
| 4 | Simulation harness with fault injector in CI | nightly long runs clean |
| 5 | `luksbox-merge` and `luksbox merge` for single-file conflict copies | merge property tests; I9 for merge |
| 6 | Multi-device: leases, graph checks, fork publish, merge on open and lock, header forks, identity conflicts, safety code, witness | multi-device simulation green; I6, I11, I12 |
| 7 | GC, retention, snapshots, checkpoints | I8 in model and simulation |
| 8 | Mount, GUI and wizard integration: publish triggers, status line, conflicts view, snapshots view | manual test plan; GUI status shows unpublished changes |
| 9 | Provider soak matrix, docs, website; ship as `--experimental-sync` | soak criteria met |
| 10 | Audit round 16; fixes; stable | audit findings closed |
| 11 | Phase 3: recipient keyslots, X-Wing, epochs; native provider backends | separate spec and audit |

## 14. CLI surface

```
luksbox sync convert my.lbx ~/Dropbox/my.lbxs [--page-size 4M]
luksbox sync export  ~/Dropbox/my.lbxs my.lbx
luksbox sync status  my.lbxs        # heads, devices, pending, unpublished, safety code
luksbox sync push    my.lbxs        # publish staged commits now
luksbox sync verify  my.lbxs [--full]
luksbox sync snapshots my.lbxs list | diff <a> <b> | restore <snap> [path]
luksbox sync gc      my.lbxs [--dry-run]
luksbox sync forget-device my.lbxs <label|id>
luksbox sync witness my.lbxs --add /media/usb/my.witness
luksbox merge ours.lbx theirs.lbx [--base base.lbx] -o merged.lbx
```

Every existing command (`ls`, `get`, `put`, `mount`, `enroll`,
`revoke`, `size`, ...) accepts a `.lbxs` path. `deniable-*` commands
refuse one.
