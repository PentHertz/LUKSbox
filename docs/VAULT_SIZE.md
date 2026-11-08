# Vault size: maximum size and giving back free space

How a vault's file size is managed (0.6.1+). User docs: the website's
`luksbox size` page; the CLI, wizard and GUI share the behaviour below.

## Where the size goes

A vault file (`.lbx`) is the header (8 KiB, unless detached), the
metadata region (64 MiB by default, preallocated) and the data area: one
4124-byte slot per 4 KiB chunk. New chunks take a free slot when there is
one, else a new slot at the end, which grows the file. A deleted or
truncated file's slots go to the free list (after the next save, see
copy-on-write in `CRYPTO_SPEC.md` section 15) and are reused; nothing
ever moves data to close the gaps.

The free list is saved inside the metadata region, one varint per slot,
and a file over 1 MiB keeps its chunk list in the data area, so a large
file costs almost nothing in the region until it is deleted, truncated
or overwritten. A save never fails on the free list: when the encoded
file tree does not fit, `fit_free_list` first leaves out the free slots
at or past the end of the data in use (and lowers the saved
`next_chunk_id`, as `shrink` does, without truncating; skipped while a
write holds slots no inode references yet), then keeps only the
lowest-numbered slots that fit. The slots left out stay free in memory
for the session, and `Vfs::open` finds them again (`reclaim_unlisted_slots`:
a bounded bitmap scan run only when referenced plus listed slots fall
short of `next_chunk_id`, never read-only or in tolerant recovery). New
entries are refused on the tree alone, never on the free list.
`metadata_budget_status()` reports both: `entries_used_pct()` (what
"File list: N% full" shows and what new entries are refused on) and
`free_list_bytes`, the room the list may take at its largest (free
slots, slots freed since the last save, every slot of the files whose
chunk list is outside the region), which `luksbox size` and the GUI
show on their own line. `Vfs::space_report` returns the file
size, the fixed part, the slots in use, the free slots and what
`shrink` could give back.

## Maximum size

`Vfs::set_max_vault_size(bytes)`, 0 = unlimited (the default).

- Stored in the encrypted metadata as `VaultSettingsOnDisk` after the
  LBM5 payload, magic `LBM\x06`; a vault without a limit stays LBM5.
  Only V5-format vaults accept a limit (`MaxSizeNeedsCurrentFormat`
  otherwise). Not visible without unlocking.
- Minimum: the fixed part plus one slot (`Vfs::minimum_vault_size`,
  `MaxSizeBelowMinimum` below it). A limit below the current file size
  is accepted: the vault stops growing.
- Enforced in `Vfs::alloc_slot`, which every data-chunk allocation goes
  through: a free slot is always fine; growing the file past the limit
  fails with `VaultSizeLimit`, mapped to `ENOSPC` / `STATUS_DISK_FULL` by
  the mount backends. A failed write hands back the slots it had taken.
- Chunk-list blocks written during a save do not count against it: a
  save must never fail on the limit, so a vault can exceed it by a few
  slots.
- Copy-on-write at the limit: a rewrite needs a free slot. Before
  failing, `alloc_slot` saves to recycle the slots retired since the
  last save if at least 1024 are waiting (4 MiB); otherwise the rewrite
  happens in place, without crash protection for that chunk, rather
  than making every file in a full vault read-only.

## Giving back free space (shrink)

`Vfs::shrink`, returning the bytes freed:

1. Save, so every slot freed this session is free on disk.
2. Find the first unused tail slot: one past the highest slot any inode
   uses (data chunks and chunk-list blocks). Slots from there on are
   free, or leaked by a failed write.
3. Drop them from the free list, lower `next_chunk_id`, save.
4. Truncate the file at the end of the last slot the saved metadata
   covers, and fsync.

A crash between 3 and 4 leaves the file longer than its metadata says,
which opens and works normally (later writes overwrite the tail). The
metadata never points past the end of the file. Only free space at the
end comes back; compacting the middle would mean moving data and is
not done.

Refused for deniable vaults (`ShrinkDeniable`): a vault file that
shrinks over time hints that data was deleted from it. Refused in
tolerant recovery mode, like every mutation.

`Vfs::shrink_allow_deniable` does the same for a deniable vault, on an
explicit request only: the GUI's "Vault size" dialog offers "Give back
... anyway" once the user ticks that they understand a smaller file
reveals deletions. A deniable file holds one vault with nothing after
its data area, so cutting the free tail is safe for the format. Nothing
shrinks a deniable vault on its own (`finish` never does).

`Vfs::finish` is what the three mount backends run at unmount: a flush,
then whatever the vault's `ShrinkControl` mode says (`ShrinkOnFinish`):
keep (default), give back (`set_shrink_on_close(true)`, `mount
--shrink-on-close`), or ask. In `Ask { min }` mode `finish` computes the
exact amount after the final flush and, from `min` bytes, publishes it
(`ShrinkControl::question`) and waits for `ShrinkControl::answer`, up to
two minutes, keeping the space without an answer. The GUI holds the
control of an in-process mount and answers from its prompt; the data is
already saved before the question, so a GUI that goes away loses
nothing.

## Resizing the metadata region (file list)

`Vfs::resize_metadata_region(bytes)` (64 KiB to 64 MiB, in steps of
64 KiB; `resize_metadata_region_allow_deniable` for a deniable vault)
changes the size of an open vault's metadata region: larger when the
file list fills up (`luksbox size` and the GUI show "File list: N%
full"), smaller to make every save cheaper (each save rewrites the
whole region and its `.meta-bak` mirror). A smaller size is refused
when the file list, plus the room its list of free space may take
(above), does not fit with the usual headroom; growing is never
refused. The encrypted
chunks are moved, never re-encrypted: they are addressed by slot from
`data_offset` and their AEAD does not depend on where they sit. The
encrypted file list does not depend on the region's size either (its
AAD is the header salt and its length). How each kind commits, so a
crash or an error leaves a vault that opens:

- **Vault file, inline header** (and **deniable**): the vault is copied
  into `<vault>.rotating` with the new layout (header bytes, then the
  region left for the next metadata write, which fills it in full with
  random padding, then the data area at its new offset), the file list
  and the header are written into the copy, and the copy is renamed over
  the original, like the master key rotation. Before the rename the
  original is untouched; the vault's `.meta-bak` and `.header-bak`
  mirrors are removed durably just before it (an old-layout mirror
  beside the new vault would open with the wrong data offset), and the
  next save writes them again. Recovery from a header mirror is refused
  when its layout does not fit the vault file. A leftover `.rotating`
  blocks the next resize until it is removed. A deniable vault's inner
  header is re-sealed with the new layout, and its copy is not
  `<vault>.rotating` (a LUKSbox-shaped name) but a hidden `.<16 hex>.tmp`
  in the same folder, the hex an HMAC of the file name under a key from
  the master key and the per-vault salt; a copy left by a crash, and an
  older version's `.rotating`, are removed at the next successful unlock
  or rewrite of that vault under the same file name (if the vault is
  moved or renamed first, delete the copy by hand).
- **Detached header**: the same copy, but the header is a second file.
  Before the rename, the new header is written to `<header>.resizing`
  (`header || "LBXRSZ01" || new vault length || old vault length`,
  little-endian, created new and synced); after the rename it is
  installed (mirror first, then the sidecar, atomically) and the intent
  removed. If anything fails after the rename, the container turns
  read-only for the rest of the session, so a half-installed header or
  a leftover intent never meets newer states. `Container::open` with
  both files locked reads the intent before the header, and the vault's
  length alone decides: the old length undoes the resize (intent and any
  `.rotating` removed); the new length installs the header from the
  intent, unless the sidecar already has the new layout (then it may
  hold later states and is kept), and removes the old-layout mirrors; an
  incomplete intent undoes the resize only while the copy is still
  there (it is written before the rename); anything else is refused.
  Every recovery failure is `InterruptedResize`, which is never answered
  from a header mirror (it may hold the old layout). The recovery only
  plans before the unlock (`plan_interrupted_resize`, which writes
  nothing) and acts after `try_unlock_and_verify` succeeded
  (`finish_interrupted_resize`; when the intent's header is installed,
  the unlock is done on that header, so its HMAC is checked first): a
  wrong passphrase, or a damaged or foreign intent, changes nothing. The
  intent is read without following links or blocking on a FIFO, at most
  its expected length + 1, must parse, and must have the live header
  salt and cipher suite (else it is ignored with a warning and left in
  place), the same metadata offset and chunk size, a data area that did
  not shrink, and on header v3 a higher generation.
- **Sync bundle**: no file to copy. The data area moves inside the paged
  image (the image spills pages to the outbox as usual, so memory stays
  bounded), the new header is staged to go with the next save
  (`HeaderStore::store_header_with_next_save`), and one `sync_all`
  writes the staged record with both: before it, the record still holds
  the last save and a crash leaves that; a failure discards the moved
  pages (`LbxFile::discard_unsaved`). The next publish uploads it as an
  ordinary commit. A save that wrote its record never reports failure
  for the cleanup after it (a caller undoing it would undo a committed
  state). Every view of another commit (merge sides, base, snapshots,
  changes saved here on an older commit) opens under that commit's own
  header (a base that is incomplete or whose header object is gone is
  not merged over: the versions stay separate until it is there). Before a
  merge, the target grows to the other side's region when that is
  larger, so the merged list has room; after it, a header taken from the
  other side is staged only over an image with its layout (the target
  is resized to it, or, when the merged list does not fit, the header
  keeps the target's layout at a new generation: "the file list region
  stays ..."), and a target that only grew for the merge goes back to
  its size when the list fits. Two different resizes made at the same
  time stay a header fork; the open and the session's finish both work
  on the complete head with the newest header this device saw, never an
  older one. A smaller region gives back the end of the image in a later
  save.

An armed rollback anchor is detached during the resize and moved on
after the commit, so an abort never leaves it ahead of the vault.
Deniable vaults need an explicit acknowledgment in every interface: the
data area moves by the size difference (and a smaller region shrinks the
file), which anyone holding an older copy of the file can see.

## Interfaces

- Sizes: `luksbox_core::size::parse_size` / `format_size`, shared by
  every interface. Units K/M/G/T, 1024-based, with or without `B`/`iB`;
  decimals; plain numbers are bytes; `0`, `unlimited`, `none`, `off`
  mean no limit. Display is 1024-based with KB/MB/GB labels, so a value
  shown can be typed back.
- Metadata region: `create --metadata-size`, `luksbox size
  --metadata-size SIZE` (vault files, detached headers, bundles),
  `luksbox deniable-resize --metadata-size SIZE --data-moves-visibly`;
  the wizard's Vault size > "Change the file list region" and main menu
  "Resize a deniable vault's file list region"; the GUI's Vault size >
  File list region (with an "I understand" box for a deniable vault).
- CLI: `create --max-size`, `luksbox size [--max SIZE] [--shrink]`,
  `mount --shrink-on-close` (forwarded to the background / FUSE-T
  helper process). Never prompts; `rm` prints a hint when at least
  `SHRINK_SUGGEST_MIN` (64 MiB) can be given back.
- Wizard: asks the maximum size at create; "Vault size" menu; offers to
  shrink on "Close vault" from `SHRINK_ASK_MIN` (1 MiB). Its mounts
  never ask (the mount blocks the wizard).
- GUI: logarithmic slider (far left = unlimited, far right = disk free
  space) plus an exact field, on the create form and in the Vault size
  dialog; a preference Ask / Always / Never for locking and unmounting.
  Ask asks from 1 MiB: before locking a browsed vault, and through the
  `ShrinkControl` when an in-process mount ends. The macOS FUSE-T helper
  process cannot ask, so there only Always applies.
