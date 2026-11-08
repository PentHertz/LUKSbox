# Performance: moving files in and out of vaults

How fast files go into and out of each kind of vault, what the costs
are made of, and what was changed to make transfers faster. Measured
2026-11-07 on the v0.7.0-rc.1 line; rerun with
`scripts/bench_transfer.sh` (method below) after changes to the vault
I/O path.

## Results

One 512 MiB file of random bytes, `luksbox put` then `luksbox get`
(release build, default Argon2id preset; Linux in a VMware virtual
machine with 8 vCPUs of an AMD Ryzen AI 9 HX 370 with AES instructions,
8 GiB of RAM, virtual disk; files in the page cache). The times include
the unlock (Argon2id, about 0.5 s, the "open" figure), so the data path
alone is faster than the MB/s shown.

| Vault | put | get | Vault file for 512 MiB |
|---|---|---|---|
| Plain copy (`cp`, reference) | 2463 MB/s | (cache) | |
| AES-256-GCM-SIV (default) | 256 MB/s | 347 MB/s | 582 MiB |
| AES-256-GCM | 260 MB/s | 351 MB/s | 582 MiB |
| ChaCha20-Poly1305 | 238 MB/s | 305 MB/s | 582 MiB |
| Detached header | 249 MB/s | 346 MB/s | 582 MiB |
| `--pad-files` | 156 MB/s | 341 MB/s | 582 MiB (see below) |
| `--hide-sizes` | 113 MB/s | 314 MB/s | 1100 MiB (see below) |
| Sync bundle, 4 MiB pages | 155 MB/s | 208 MB/s | 590 MiB of objects |
| Sync bundle, 1 MiB pages | 141 MB/s | 243 MB/s | 587 MiB of objects |
| Sync bundle, 16 MiB pages | 142 MB/s | 218 MB/s | 609 MiB of objects |

Re-run after the metadata region resize change (2026-11-08), 256 MiB
(less free disk than a 512 MiB run needs), times with the unlock; a
second run after the bundle and deniable resize work gave the same
numbers within 5 %:

| Vault kind | put | get |
|---|---|---|
| AES-256-GCM-SIV / AES-256-GCM / detached header | 1.44 s (177 MB/s) | 1.00-1.04 s (246-257 MB/s) |
| ChaCha20-Poly1305 | 1.49 s (171 MB/s) | 1.13 s (226 MB/s) |
| `--pad-files` / `--hide-sizes` | 2.03 s / 2.75 s | 1.08 s / 1.07 s |
| Sync bundle, 1 / 4 / 16 MiB pages | 2.20 / 2.02 / 2.36 s | 1.53 / 1.62 / 1.63 s |

The MB/s are lower than in the 512 MiB table only because the fixed
costs (unlock about 0.55 s, save about 0.15 s) weigh twice as much:
without them the default vault writes about 360 MB/s and reads about
580 MB/s, against about 380 and 540 MB/s from the 512 MiB run, which
is within run-to-run noise here. The transfer path itself was not
changed by the resize.

Through a mount (`luksbox mount`, Linux FUSE; macOS FUSE-T below): writing 512 MiB with
`dd ... conv=fsync` 152 MB/s, reading it back about 370 MB/s.
Small files: 20 000 files of 1 KiB created through the mount in 7.1 s
(about 2 800 files/s), read back in 6.2 s.

Many files through the command line: `luksbox put` and `get` take a
folder and move it with one unlock and one save.

| 500-odd small files (29 MB) | Time |
|---|---|
| One `luksbox put` per file | 345 s (0.7 s per file: unlock + save) |
| `luksbox put vault.lbx folder /dest` (521 files) | 0.78 s |
| `luksbox get vault.lbx /dest folder-out` (521 files) | 0.62 s |

Every vault kind reads and writes at a few hundred MB/s, far above the
speed of a USB stick or a network, so these are rarely the limit. The
exceptions are the costs listed under "What still costs".

## macOS (Apple Silicon, FUSE-T)

Measured 2026-11-08 on macOS 26.6, Apple M5 Max, internal SSD, FUSE-T
1.2.9, release builds with `--features hardware,fuse-t`; 512 MiB of
random bytes, times with the unlock (0.3 s here). "main" is v0.6.1, the
base of this branch; "before" is this branch before the macOS review;
"now" adds its fixes (hardware AES, bundle syncs, FUSE-T fsync
coalescing; CHANGELOG).

| `luksbox put` / `get`, MB/s | main | before | now |
|---|---|---|---|
| AES-256-GCM-SIV (default) | 59 / 164 | 148 / 167 | 393 / 555 |
| AES-256-GCM | 63 / 174 | 156 / 177 | 402 / 589 |
| ChaCha20-Poly1305 | 141 / 356 | 284 / 365 | 286 / 363 |
| `--hide-sizes` | 42 / 155 | 42 / 157 | 184 / 534 |
| `--pad-files` | 58 / 163 | 59 / 166 | 245 / 569 |
| Detached header | 58 / 163 | 147 / 166 | 395 / 569 |
| Sync bundle, 4 MiB pages | | 56 / 75 | 178 / 215 |
| Sync bundle, 1 MiB pages | | 35 / 75 | 160 / 215 |

| Through a FUSE-T mount | main | before | now |
|---|---|---|---|
| 512 MiB file, write + fsync / read (MiB/s) | 60 / 181 | 151 / 181 | 452 / 820 |
| 1 000 files of 1 KiB, created | 4 files/s | 9 files/s | 575 files/s |
| Sync bundle: 512 MiB write / read (MiB/s) | | 66 / 85 | 234 / 267 |
| Sync bundle: 1 000 files of 1 KiB | | 11 files/s | 626 files/s |

What made the difference on this machine:

- **AES in hardware.** The AES and POLYVAL crates use the ARMv8 AES /
  PMULL instructions only with the `aes_armv8` / `polyval_armv8` cfgs
  (`.cargo/config.toml`); without them the default suite ran slower than
  ChaCha20, which is software either way.
- **No save per closed file on FUSE-T.** The macOS NFS client sends an
  `fsync` (COMMIT) at every close; each one rewrote the metadata region
  and its mirror (128 MiB, about 115 ms). Coalesced to one save per
  second at most (`docs/MACOS_FUSE_T.md`).
- **One drive-cache flush per save in bundles.** `F_FULLFSYNC` (what
  `File::sync_all` does on Apple platforms) cost 4.1 ms per object here,
  `F_BARRIERFSYNC` 1.0 ms, a plain `fsync` 0.2 ms.

**Against the Linux figures above.** Those come from other hardware (a
Ryzen AI 9 HX 370 in a VMware VM), so the comparison is rough. Large
files go 1.5 to 2.5x faster here (default suite 393 / 555 against
256 / 347 MB/s; through a mount 452 / 820 against 152 / 370), small
files through a mount about 5x slower (575 against about 2 800 files/s:
every create and close is an NFS round trip under FUSE-T), bundles
about the same (every page is written twice). This is not an AES
difference: x86_64 builds always used AES-NI (the `aes` and `polyval`
crates detect it by themselves; only 64-bit ARM needs the cfgs), and
hardware AES runs at several GB/s per core, far above these rates. What
bounds a transfer is the work around each 4 KiB chunk (a `pwrite`, an OS
random call for its nonce, a buffer zeroized), which costs more inside a
VM. ChaCha20-Poly1305, software on both, shows the machine difference:
286 against 238 MB/s.

Left: each 4 KiB chunk asks the OS for its 12-byte nonce
(`getentropy`, about as costly as the chunk's `pwrite` in a profile of a
large `put`); a per-thread buffer of OS randomness, discarded after a
`fork`, would save about a quarter of the write time. Not done: nonce
generation is security-critical and the gain is moderate.

## What was changed

Measured on the same machine, same file, before and after:

| Change | Before | After |
|---|---|---|
| A new chunk is written once (it was written as encrypted zeros, read back, decrypted, then encrypted and written with its data) | 169 MB/s put | 241-256 MB/s put |
| Positioned reads and writes (`pread` / `pwrite`): one system call per 4 KiB chunk instead of a seek plus a read or write | 2 syscalls/chunk | 1 syscall/chunk |
| The metadata-size check of a growing write runs exactly only when a bound could reach the limit (it serialized the whole directory tree on every write) | 64 MiB into a 20 000-file vault: 5.0 s | 0.96 s |
| Same, for many small files | 20 000 files through a mount: 45 s | 7.1 s |
| `luksbox umount` waits until the mount has saved the vault | next command: "vault locked" | works at once |
| `put` / `get` of a folder (one unlock, one save) | 345 s for 500 files | 0.78 s for 521 files |
| GUI: only the rows in view are drawn for large folders; size report and recent-list checks cached | a repaint walked every entry | constant per repaint |

The metadata check matters most for large vaults: its cost grew with
the number of files, so importing many files into a big vault was
quadratic, through the CLI, the GUI and a mount alike.

## GUI transfers (headless scenario, release build)

The GUI end-to-end scenario run on an optimized build with a 67 MB
tree (120 small files and one 64 MiB file), through the real widgets:

```bash
LUKSBOX_GUI_SCENARIO_MIB=64 cargo test --release -p luksbox-gui \
  --bin luksbox-gui gui_scenarios_end_to_end -- --nocapture
```

| GUI path | Time | Throughput |
|---|---|---|
| Create a vault file (Interactive KDF) | 0.94 s | |
| Vault file: + Add folder | 0.34 s | 195 MB/s |
| Vault file: Download (recursive) | 0.23 s | 295 MB/s |
| Create a sync bundle | 1.39 s | |
| Sync bundle: + Add folder | 0.35 s | 190 MB/s |
| Sync bundle: Lock (publish) | 0.10 s | |
| Detached header + anchor + hidden sizes: + Add folder | 0.59 s | 115 MB/s |
| Deniable vault: rotate master key | 1.40 s | |

With a 135 MB tree (`LUKSBOX_GUI_SCENARIO_MIB=128`) the fixed cost of
the save (unlock, 128 MiB metadata rewrite) weighs less:

| GUI path, 135 MB tree | Time | Throughput |
|---|---|---|
| Vault file: + Add folder | 0.44 s | 307 MB/s |
| Vault file: Download (recursive) | 0.27 s | 493 MB/s |
| Sync bundle: + Add folder | 0.53 s | 254 MB/s |
| Sync bundle: Lock (publish) | 0.13 s | |
| Detached header + anchor + hidden sizes: + Add folder | 0.95 s | 142 MB/s |

The GUI imports and exports at the CLI's speed (same code path); the
hidden-sizes vault writes its padding, hence about half the rate.

## What still costs

- **Every save rewrites 128 MiB.** A save (the end of every CLI command
  that changes something, the GUI after each operation, a mount every
  30 s while files change and at unmount) rewrites the whole metadata
  region, 64 MiB by default, with fresh random padding, and then its
  `.meta-bak` mirror: 128 MiB of writes, 5 fsyncs. On this SSD that is
  0.15 s per command here; on a USB 2 stick (20-30 MB/s) it is 4 to 6 s per
  command, and an hour of active editing in a mounted vault writes about
  15 GB. The full refresh is deliberate: anyone comparing two copies of
  the vault learns nothing about the size of the directory tree. Sync
  bundles already refresh only a power-of-two bucket (at least 1 MiB)
  of the region, which reveals that bucket. Offering the same for files
  (for example a create-time option for vaults on slow or flash
  storage), or a smaller default region for small vaults, is a security
  trade-off to decide, not a bug fix. Until then, `--metadata-size`
  at create time (and, in the GUI, "File list (metadata) region" under
  On-disk format) makes every save cheaper for vaults with few files.

  How many files a region holds depends on their size: files up to
  1 MiB keep their chunk list in the region, larger ones keep it in the
  data area. Measured with a 256 KiB region (`luksbox put` of folders
  until the vault refused more), scaled up; names of about 20
  characters:

  | Files of | Per MiB of region | 16 MiB | 64 MiB (default, maximum) |
  |---|---|---|---|
  | under 4 KiB | about 25 000 | about 400 000 | about 1.6 million |
  | 512 KiB | about 1 400 | about 22 000 | about 88 000 |
  | 1 MiB | about 700 | about 11 000 | about 45 000 |
  | over 1 MiB | over 6 900 (disk full first) | over 110 000 | over 440 000 |

  Writes per save: 2 x the region (32 MiB for 16 MiB, 128 MiB for
  64 MiB). A collection of documents of a few hundred KB fills a
  16 MiB region at 10 000 to 25 000 files, so the default stays 64 MiB
  (decision of 2026-11-08); users on slow storage pick a smaller region
  at create (GUI "File list (metadata) region", `--metadata-size`), and
  `luksbox size` / the GUI's Vault size show how full it is.
- **Padding modes write the padding.** `--pad-files` and `--hide-sizes`
  round every file up to a power of two of 4 KiB chunks, and those
  padding chunks are written (encrypted) too: up to 2x the disk use and
  write time. A file of exactly 2^n bytes doubles under `--hide-sizes`
  (the 8-byte size header pushes it past the power of two).
- **Sync bundles write twice.** A save seals the changed pages into this
  device's outbox; a publish copies them into the bundle folder. Both
  are local disk writes, still far faster than any upload.
- **Each CLI command unlocks the vault and saves it.** Argon2id costs
  about 0.5 s per command with the default preset (by design), and the
  save above comes on top. Move folders with one `put` / `get` (above),
  or mount the vault; the GUI unlocks once per session.
- **4 KiB chunks.** Each chunk has its own nonce, tag and system call;
  larger chunks would cut per-chunk overhead but change the format.

## Method

```bash
cargo build --release -p luksbox-cli
scripts/bench_transfer.sh target/release/luksbox 512           # every kind
scripts/bench_transfer.sh target/release/luksbox 512 siv bundle4
```

The script creates each kind of vault in a temporary folder, times
`ls` (unlock only), `put` and `get` of one random file, checks the
round trip byte for byte, and reports MB/s. Needs about three times
the file size free in `$TMPDIR`. For mounts and many small files, mount
a vault and time `dd` / a loop of small writes against it; the figures
above came from that.
