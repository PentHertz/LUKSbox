# Vault size: maximum size and giving back free space

How a vault's file size is managed (0.6.0+). User docs: the website's
`luksbox size` page; the CLI, wizard and GUI share the behaviour below.

## Where the size goes

A vault file (`.lbx`) is the header (8 KiB, unless detached), the
metadata region (64 MiB by default, preallocated) and the data area: one
4124-byte slot per 4 KiB chunk. New chunks take a free slot when there is
one, else a new slot at the end, which grows the file. A deleted or
truncated file's slots go to the free list (after the next save, see
copy-on-write in `CRYPTO_SPEC.md` section 15) and are reused; nothing
ever moves data to close the gaps. `Vfs::space_report` returns the file
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

## Interfaces

- Sizes: `luksbox_core::size::parse_size` / `format_size`, shared by
  every interface. Units K/M/G/T, 1024-based, with or without `B`/`iB`;
  decimals; plain numbers are bytes; `0`, `unlimited`, `none`, `off`
  mean no limit. Display is 1024-based with KB/MB/GB labels, so a value
  shown can be typed back.
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
