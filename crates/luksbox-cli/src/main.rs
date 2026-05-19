// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use std::error::Error as StdError;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use luksbox_core::secret_mem;
use luksbox_core::{Argon2idParams, CipherSuite, HEADER_SIZE, Header, MasterVolumeKey, SlotKind};
use luksbox_format::{Container, UnlockMaterial};
use luksbox_vfs::{FileId, InodeKind, Vfs};
use zeroize::Zeroizing;

mod passphrase;
mod wizard;

pub(crate) type Result<T> = std::result::Result<T, Box<dyn StdError>>;

/// Build a `Box<dyn StdError>` from a format string. Used by the
/// deniable subcommands and any other command that wants
/// `anyhow!`-style ergonomics without pulling in the anyhow crate
/// (the CLI deliberately keeps its dep tree small). Available
/// throughout the crate via `macro_rules!`'s default module scope.
macro_rules! cli_err {
    ($($arg:tt)*) => {
        Box::<dyn StdError>::from(format!($($arg)*))
    };
}

/// Extended `--version` output. `-V` still prints the bare version
/// (clap's default short-version behaviour); `--version` prints
/// version + the FUSE backend baked in at build time, so a user who
/// downloaded the wrong .dmg variant for their installed FUSE
/// provider can immediately see the mismatch instead of waiting for
/// the cryptic dyld error at first mount.
///
/// `concat!()` requires string literals, so we cfg-gate the whole
/// const per backend. Exactly one of these blocks is active per
/// build (mutual exclusion enforced by the same cfg pattern as
/// `luksbox_mount::FUSE_BACKEND`).
#[cfg(all(target_os = "macos", feature = "fuse-t"))]
const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\nFUSE backend: fuse-t (kext-free, requires `brew install --cask fuse-t`)"
);
#[cfg(all(target_os = "macos", feature = "fuse", not(feature = "fuse-t"),))]
const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\nFUSE backend: macfuse (kext-based, requires `brew install --cask macfuse`)"
);
#[cfg(all(target_os = "linux", feature = "fuse"))]
const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\nFUSE backend: libfuse3 (requires `apt install libfuse3-3` or distro equivalent)"
);
#[cfg(all(target_os = "windows", feature = "winfsp"))]
const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\nFUSE backend: winfsp (requires WinFsp from https://winfsp.dev/)"
);
#[cfg(any(
    not(any(target_os = "linux", target_os = "macos", target_os = "windows")),
    all(target_os = "linux", not(feature = "fuse")),
    all(target_os = "macos", not(feature = "fuse"), not(feature = "fuse-t")),
    all(target_os = "windows", not(feature = "winfsp")),
))]
const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\nFUSE backend: none (mount support not compiled in)"
);

#[derive(Parser)]
#[command(
    name = "luksbox",
    version,
    long_version = LONG_VERSION,
    about = "Encrypted container tool",
)]
struct Cli {
    /// libfido2 device path to bind every FIDO2 op to. Optional.
    /// Without this flag, luksbox uses the first authenticator
    /// libfido2 enumerates (the legacy single-device behavior). Set
    /// it when more than one authenticator is plugged in (e.g. a
    /// physical YubiKey alongside the Windows Hello platform
    /// authenticator on Windows) and you want to pick a specific
    /// one. Run `luksbox list-fido2-devices` to see the path
    /// strings to use here.
    ///
    /// Examples:
    ///   --fido2-device /dev/hidraw3                 (Linux hidraw)
    ///   --fido2-device 'IOService:/IOResources/...' (macOS HID path)
    ///   --fido2-device '\\?\hid#vid_1050&...'       (Windows HID path)
    ///   --fido2-device 'windows://hello'            (Windows Hello bridge - also accepted: 'winhello://')
    #[arg(long, global = true, value_name = "PATH")]
    fido2_device: Option<String>,

    #[command(subcommand)]
    command: Command,
}

/// Shared unlock-method flag flattened into every command that opens a
/// container. Default: passphrase prompt. With `--fido2`: enumerate the
/// FIDO2 keyslots in the container header and try each against a connected
/// authenticator (touch + PIN).
#[derive(Args, Clone)]
struct UnlockArgs {
    /// Unlock the container via FIDO2 hmac-secret on a connected authenticator
    /// (any CTAP2 authenticator: YubiKey, Nitrokey, SoloKey, Token2, OnlyKey, etc.). Requires `--features hardware` (enabled by default).
    #[arg(long)]
    fido2: bool,
    /// Unlock via the local TPM 2.0 chip. Iterates the vault's
    /// `Tpm2Sealed` keyslots, asks the TPM to unseal each blob, and
    /// the first one whose KEK unwraps the MVK wins. Linux-only at
    /// runtime (TPM access via `/dev/tpmrm0` + `libtss2-esys`); on
    /// other platforms the flag exists but errors cleanly.
    #[arg(long)]
    tpm2: bool,
    /// Unlock via a fused TPM 2.0 + FIDO2 keyslot (both factors
    /// required: local TPM AND a connected FIDO2 authenticator).
    /// Iterates `Tpm2Fido2` slots whose stored cred_id matches the
    /// connected authenticator; for each match, asks the TPM to
    /// unseal the slot's blob, then derives the KEK from BOTH
    /// halves and tries to unwrap. Either factor wrong fails the
    /// unlock. Stronger than `--tpm2` alone (machine-bound) or
    /// `--fido2` alone (key-bound).
    #[arg(long = "tpm2-fido2")]
    tpm2_fido2: bool,
    /// Path to a detached-header sidecar file. If unset, the header is read
    /// from offset 0 of the vault file (inline default). With `--header`
    /// set, the vault file alone is indistinguishable from random, no
    /// magic bytes, no keyslots, nothing to attack.
    #[arg(long)]
    header: Option<PathBuf>,
    /// Path to a rollback-detection anchor file (small sidecar with the
    /// vault's monotonic generation counter, MAC'd under the MVK). On
    /// open, the anchor is verified and the counter compared to the
    /// metadata's; a HIGHER anchor counter means the `.lbx` was rolled
    /// back, and the open is rejected. Only meaningful if you keep the
    /// anchor on storage the attacker cannot also roll back (USB stick
    /// you carry, separate trusted disk, etc.).
    #[arg(long)]
    anchor: Option<PathBuf>,
    /// Path to the user's `.kyber` seed file for a hybrid post-quantum
    /// keyslot (see SECURITY.md section 10). Required to open a vault that
    /// has any `HybridPq` slot. Keep this file on separate trusted
    /// storage (USB stick, offline machine), its whole point is to be
    /// somewhere the attacker who has your `.lbx` doesn't reach.
    #[arg(long)]
    pq_hybrid: Option<PathBuf>,
}

/// Argon2id strength preset for `--kdf` on `create` (and future `enroll`).
#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq, Default)]
pub(crate) enum KdfStrengthArg {
    /// 256 MiB / 3 iter / 4 lanes, 500 ms on a modern laptop.
    #[default]
    Interactive,
    /// 512 MiB / 4 iter / 4 lanes, 1.5 s.
    Moderate,
    /// 1 GiB / 5 iter / 4 lanes, 3-4 s.
    Sensitive,
}

impl KdfStrengthArg {
    pub(crate) fn params(self) -> Argon2idParams {
        match self {
            Self::Interactive => Argon2idParams::INTERACTIVE,
            Self::Moderate => Argon2idParams::MODERATE,
            Self::Sensitive => Argon2idParams::SENSITIVE,
        }
    }
}

/// On-disk metadata format selection for `--format` on `create`.
/// Each vault picks its format once at create time; format is
/// fixed for the lifetime of the vault. Default flipped to v3 in
/// the v0.2.0 release after end-to-end validation across standard
/// + deniable, MVK rotation across all deniable credential kinds,
/// and a perf baseline showing sub-2s open at 100 GiB.
#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq, Default)]
pub(crate) enum VaultFormatArg {
    /// Inline chunk lists in the metadata region. Practical ~10 GiB
    /// per-vault ceiling. Readable by every LUKSbox binary
    /// (including pre-v0.2.0 readers). Pick this if you need to
    /// share the vault with someone on an older LUKSbox.
    V2,
    /// External chunk-list blocks in the data area (default). No
    /// practical per-vault ceiling. Requires LUKSbox v0.2.0 or
    /// newer to open.
    #[default]
    V3,
}

/// Keyslot kind, used by `create`, `enroll`, and `update`.
#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum SlotKindArg {
    /// Stretch a passphrase via Argon2id to wrap the master key.
    Passphrase,
    /// FIDO2 hmac-secret wrapping a random MVK (PIN + touch).
    Fido2,
    /// FIDO2 hmac-secret used directly to DERIVE the MVK, no wrapped key
    /// in the vault, nothing to brute-force. Strongest mode but only valid
    /// at create time and offers no MVK-layer backup.
    Fido2Direct,
    /// Hybrid passphrase + ML-KEM-768 (FIPS 203) keyslot. Requires
    /// `--pq-hybrid <kyber-secret-path>`. KEK derives from BOTH the
    /// passphrase (Argon2id-stretched) and a Kyber decapsulation,
    /// quantum-breaking the classical wrap doesn't yield the MVK
    /// without the seed file.
    HybridPq,
    /// Hybrid FIDO2 + ML-KEM-768. Requires both a FIDO2 authenticator (PIN +
    /// touch) AND `--pq-hybrid <kyber-secret-path>`. Closes the actual
    /// PQ gap in luksbox: an adversary who recorded USB-HID traffic
    /// at enroll/unlock can quantum-recover the FIDO2 hmac_secret,
    /// but they still need the Kyber seed file. SECURITY.md section 10.
    HybridPqFido2,
    /// Hybrid passphrase + ML-KEM-1024 (FIPS 203 security category 5,
    /// about  AES-256). Higher-strength variant of `hybrid-pq` for ANSSI
    /// "Élevé" tier / long-life classified data.
    HybridPq1024,
    /// Hybrid FIDO2 + ML-KEM-1024. Higher-strength variant of
    /// `hybrid-pq-fido2`.
    HybridPq1024Fido2,
    /// TPM 2.0 keyslot bound to the local machine. The wrap key
    /// lives inside the TPM chip; no passphrase is involved. The
    /// vault becomes uncrackable if its file is stolen separately
    /// from this machine, but loses portability (won't unlock on
    /// any other Mac / PC). For portability + recovery, enroll a
    /// Passphrase or FIDO2 slot alongside it. Linux-only at
    /// runtime; requires `--features hardware` (default on) and
    /// `libtss2-esys` at build time.
    Tpm2,
    /// Fused TPM 2.0 + FIDO2 keyslot: unlock requires BOTH the
    /// local TPM (this machine) AND a connected FIDO2
    /// authenticator (this YubiKey). The KEK derives from both
    /// halves, either factor alone fails. Loss of either is
    /// permanent, pair with a Passphrase or FIDO2 recovery slot
    /// unless you accept the unrecoverable trade-off. Constraint:
    /// FIDO2 cred_id + TPM SealedBlob must fit in 352 B (typical
    /// YubiKey <= 80 B + about 280 B blob is fine; Google Titan about 288 B
    /// cred_id overflows, use independent Tpm2 + Fido2 slots).
    Tpm2Fido2,
    /// TPM 2.0 keyslot gated by a user PIN. Same as `Tpm2`
    /// (machine-bound, no passphrase) but adds a 4-6 digit PIN
    /// enforced by the TPM itself - wrong PINs count toward the
    /// chip's dictionary-attack lockout (typically about 32 attempts
    /// then a multi-hour cooldown), so even short PINs are secure
    /// on the original hardware. Loss of EITHER the TPM chip OR
    /// the PIN permanently kills this slot - keep a recovery slot.
    Tpm2Pin,
    /// Hybrid TPM 2.0 + ML-KEM-768 (post-quantum). Closes the
    /// quantum gap in plain `tpm2`: the TPM's wrap is RSA-2048 /
    /// ECC P-256 (both quantum-broken), so a CRQC adversary who
    /// stole the vault file + the TPM's published public key
    /// could break the wrap. Adding ML-KEM means they also need
    /// the Kyber seed file. Requires `--pq-hybrid <kyber-secret>`
    /// at every unlock just like the other hybrid-pq slots.
    HybridPqTpm2,
    /// Maximum-paranoia: TPM 2.0 + FIDO2 + ML-KEM-768. KEK derives
    /// from THREE independent secrets. Loss of any one factor
    /// kills the slot. Same 352 B cred_id-region constraint as
    /// `Tpm2Fido2`.
    HybridPqTpm2Fido2,
    /// ML-KEM-1024 variant of `HybridPqTpm2`. Same 2-factor shape
    /// (TPM + Kyber seed) but uses the NIST Cat-5 / ~AES-256 PQ
    /// parameter set. Larger sidecar entries (about 1568 B Kyber pubkey
    /// + about 1568 B ciphertext) but identical unlock cost.
    HybridPqTpm21024,
    /// ML-KEM-1024 variant of `HybridPqTpm2Fido2`. NIST Cat-5
    /// 3-factor maximum-paranoia.
    HybridPqTpm2Fido21024,
}

impl SlotKindArg {
    pub(crate) fn from_core(k: SlotKind) -> Option<Self> {
        match k {
            SlotKind::Passphrase => Some(Self::Passphrase),
            SlotKind::Fido2HmacSecret => Some(Self::Fido2),
            SlotKind::Fido2DerivedMvk => Some(Self::Fido2Direct),
            SlotKind::HybridPqKemPassphrase => Some(Self::HybridPq),
            SlotKind::HybridPqKemFido2 => Some(Self::HybridPqFido2),
            SlotKind::HybridPqKem1024Passphrase => Some(Self::HybridPq1024),
            SlotKind::HybridPqKem1024Fido2 => Some(Self::HybridPq1024Fido2),
            SlotKind::Tpm2Sealed => Some(Self::Tpm2),
            SlotKind::Tpm2Fido2 => Some(Self::Tpm2Fido2),
            SlotKind::Tpm2SealedPin => Some(Self::Tpm2Pin),
            SlotKind::HybridPqKemTpm2 => Some(Self::HybridPqTpm2),
            SlotKind::HybridPqKemTpm2Fido2 => Some(Self::HybridPqTpm2Fido2),
            SlotKind::HybridPqKem1024Tpm2 => Some(Self::HybridPqTpm21024),
            SlotKind::HybridPqKem1024Tpm2Fido2 => Some(Self::HybridPqTpm2Fido21024),
            SlotKind::Empty => None,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Create a new encrypted container. The first keyslot's kind is set by
    /// `--kind` (passphrase by default; pass `--kind fido2` to make slot 0 a
    /// FIDO2 hardware keyslot, requires a connected authenticator).
    Create {
        path: PathBuf,
        /// Cipher suite: aes (default) or chacha
        #[arg(long, default_value = "aes")]
        cipher: String,
        /// Initial keyslot kind.
        #[arg(long, value_enum, default_value = "passphrase")]
        kind: SlotKindArg,
        /// Write the 8 KB header to a separate sidecar file at this path
        /// (detached-header mode). Without this sidecar, the vault file is
        /// undecipherable, no magic bytes, no keyslots, nothing to brute.
        #[arg(long)]
        header: Option<PathBuf>,
        /// Pad each file's chunk count to the next power of 2. Hides
        /// per-file chunk counts from disk-level forensics within a 2x
        /// bucket; storage cost up to 2x. Note: the exact `size` field is
        /// still stored in the AEAD-encrypted metadata blob, so an
        /// MVK-holder can still see precise file sizes. Use `--hide-sizes`
        /// for stronger hiding. Not compatible with `--kind fido2-direct`.
        #[arg(long)]
        pad_files: bool,
        /// Hide exact file sizes by storing them inside encrypted file
        /// content (chunk-0 size header) rather than in the metadata
        /// blob. Implies `--pad-files`. Hides sizes from `ls -l` on a
        /// mounted vault, from metadata-only memory exposures, and from
        /// metadata-only backups; does NOT hide from a fully-capable
        /// MVK-holder who can decrypt arbitrary file content. Not
        /// compatible with `--kind fido2-direct` in v1.
        #[arg(long)]
        hide_sizes: bool,
        /// Initialize a rollback-detection anchor sidecar at this path
        /// alongside the new vault. The anchor is updated on every
        /// metadata write. Keep it on separate trusted storage (USB
        /// stick you carry, etc.) for it to actually defend against
        /// rollback, see SECURITY.md section 3.3 for the threat-model details.
        #[arg(long)]
        anchor: Option<PathBuf>,
        /// For `--kind hybrid-pq`: where to write the user's secret
        /// `.kyber` seed file. Keep this on separate trusted storage
        /// (USB stick, offline machine). Without it the vault is
        /// unrecoverable. See SECURITY.md section 10.
        #[arg(long)]
        pq_hybrid: Option<PathBuf>,
        /// Argon2id strength preset. `interactive` (default) ~ 500 ms,
        /// 256 MiB; `moderate` ~ 1.5 s, 512 MiB; `sensitive` ~ 3-4 s,
        /// 1 GiB. Applies to all passphrase-stretched keyslots in this
        /// vault.
        #[arg(long, value_enum, default_value = "interactive")]
        kdf: KdfStrengthArg,
        /// Audit Round 9G addition: instead of a fixed preset, ask
        /// LUKSbox to calibrate Argon2id m_cost so that ONE unlock
        /// takes approximately this wall time on the calling CPU.
        /// Format: integer + unit, where unit is `ms`, `s`, or `m`
        /// (e.g. `--kdf-target-time 5s` for 5-second unlock,
        /// `--kdf-target-time 30s` for hardened backup vaults).
        /// Conflicts with `--kdf`. Bounded by RAM available on the
        /// calibrating machine; if no preset within RAM matches the
        /// target, the closest fit is used.
        #[arg(long, conflicts_with = "kdf")]
        kdf_target_time: Option<String>,
        /// Override the encrypted metadata region size. Accepts a
        /// human-readable byte count: `4M`, `8M`, `16777216`, etc.
        /// Default and cap are both 16 MiB (the on-disk format
        /// limit); practical vault-data headroom is roughly 8-10 GiB
        /// before the chunk-reference list overflows. Lower this only
        /// for tiny demo vaults where 16 MiB of minimum file size is
        /// too much; higher values are rejected here at the CLI
        /// boundary because the on-disk parser would also reject them.
        /// The value is stored in the header at create time and used
        /// unchanged on every later open; you cannot resize an
        /// existing vault.
        #[arg(long, value_name = "BYTES")]
        metadata_size: Option<String>,
        /// Opt the new vault into the **v3 metadata format**, which
        /// stores per-file chunk lists out-of-line in encrypted
        /// chunk-list blocks in the data area rather than inline in
        /// the metadata region. Removes the practical ~10 GiB
        /// per-vault ceiling of the v2 format (which capped at the
        /// 16 MiB metadata region size) and lets a vault hold
        /// arbitrarily-large files.
        ///
        /// Trade-offs:
        /// - On open, every spilled file's chunk-list chain is
        ///   walked from disk, so opens of huge vaults are slower
        ///   than v2 (a 100 GiB single-file vault touches ~100k
        ///   chunk-list blocks at open).
        /// - Old LUKSbox binaries (pre-v0.2.0) cannot read v3
        ///   vaults — they refuse the `LBM\x03` metadata magic.
        ///
        /// Default v2 stays the default; v3 is opt-in until
        /// deniable + fuzz coverage land in a later release. Once
        /// chosen at create, the format is permanent for that
        /// vault (re-create to switch).
        #[arg(long, default_value = "v2")]
        format: VaultFormatArg,
    },
    /// Show container header / keyslot summary (no unlock required).
    Info { path: PathBuf },
    /// Add a new keyslot. `--kind` selects what kind to enroll (passphrase
    /// or fido2). `--fido2` selects how to authenticate to the existing
    /// vault, useful if you've revoked the original passphrase and only
    /// have FIDO2 keyslots left.
    Enroll {
        path: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
        /// Slot kind to enroll.
        #[arg(long, value_enum, default_value = "passphrase")]
        kind: SlotKindArg,
    },
    /// Remove a keyslot. WARNING: cannot recover access if you remove the last one.
    Revoke {
        path: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        slot: usize,
    },
    /// Replace an existing keyslot's secret (passphrase or FIDO2 credential)
    /// while keeping its slot index. Defaults to the slot's existing kind;
    /// pass `--kind` to swap a passphrase slot to fido2 or vice versa.
    Update {
        path: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(long)]
        slot: usize,
        /// Slot kind to install. Defaults to the slot's existing kind.
        #[arg(long, value_enum)]
        kind: Option<SlotKindArg>,
    },
    /// List a directory inside the container.
    Ls {
        path: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
        #[arg(default_value = "/")]
        inner: String,
    },
    /// Make a directory inside the container.
    Mkdir {
        path: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
        inner: String,
    },
    /// Copy a local file into the container.
    Put {
        path: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
        local: PathBuf,
        inner: String,
    },
    /// Copy a file out of the container.
    Get {
        path: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
        inner: String,
        local: PathBuf,
    },
    /// Print a file from the container to stdout.
    Cat {
        path: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
        inner: String,
    },
    /// Remove a file from the container.
    Rm {
        path: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
        inner: String,
    },
    /// Remove an empty directory from the container.
    Rmdir {
        path: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
        inner: String,
    },
    /// Rename within a directory (cross-dir rename not in v1).
    Mv {
        path: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
        old: String,
        new: String,
    },
    /// Mount the container as a userspace filesystem.
    ///
    /// Mountpoint conventions:
    ///  - Linux / macOS (FUSE3 / FUSE-T / macFUSE): mountpoint is an
    ///     EXISTING empty directory. `mkdir -p ~/vault && luksbox mount
    ///     v.lbx ~/vault` is the typical pattern.
    ///  - Windows (WinFsp): mountpoint is either a drive letter
    ///     (e.g. `Z:`) OR a non-existent path the driver materializes
    ///     as a reparse point. Passing an existing directory yields
    ///     STATUS_OBJECT_NAME_COLLISION (0xC0000035) at mount start.
    ///
    /// By default the mount daemonizes on Linux/macOS (you get your
    /// shell back; unmount with `luksbox umount`). Windows always runs
    /// in the foreground until the process exits (WinFsp's mount is
    /// tied to the holding handle's lifetime). Pass `-f`/`--foreground`
    /// to override the Linux/macOS default.
    Mount {
        path: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
        /// Run in the foreground instead of daemonizing.
        #[arg(short = 'f', long)]
        foreground: bool,
        /// Mountpoint. Required unless `--private-mount` is given.
        mountpoint: Option<PathBuf>,
        /// macOS-only: derive a per-user mountpoint under
        /// `~/Library/LUKSbox/Mounts/<vault-name>` instead of using
        /// the explicit `<mountpoint>` argument. `~/Library` is mode
        /// 0700 on macOS, so the mountpoint name itself is invisible
        /// to other users on the system (whereas `/Volumes/<name>`
        /// reveals the mount's existence). No effect on Linux/Windows;
        /// rejected if combined with an explicit mountpoint.
        #[arg(long)]
        private_mount: bool,
    },
    /// Subprocess-isolated FUSE-T mount helper. Reads a 32-byte
    /// MasterVolumeKey from stdin and uses it to open the vault
    /// without re-running the unlock derivation, then runs the FUSE
    /// event loop in foreground until unmount. Spawned by the GUI on
    /// macOS+FUSE-T builds so libfuse-t lives in its own process and
    /// can't take down the GUI when it aborts itself during teardown.
    /// Hidden from --help because it's not intended for direct
    /// invocation: there's no UX for typing 32 bytes into stdin and
    /// the same effect is achieved by `luksbox mount` on every other
    /// backend.
    #[command(name = "mount-fuse-t-helper", hide = true)]
    MountFuseTHelper {
        /// Path to the .lbx vault.
        vault: PathBuf,
        /// Optional detached header path.
        #[arg(long)]
        header: Option<PathBuf>,
        /// Where to mount the vault.
        mountpoint: PathBuf,
    },
    /// Unmount a luksbox mountpoint (wraps fusermount3 -u on Linux, umount on macOS).
    Umount { mountpoint: PathBuf },
    /// Create a deniable-header file: an 8 KiB header where every
    /// on-disk byte is indistinguishable from random output. See
    /// `docs/DENIABLE_HEADER.md` for the threat model. The user MUST
    /// remember the cipher + Argon2 params; forgetting them is
    /// permanent lockout (by design - they are part of the secret).
    /// Currently writes only the 8 KiB deniable header to disk;
    /// full mount support requires the Container-level integration
    /// tracked as a separate follow-up.
    #[command(name = "deniable-init")]
    DeniableInit {
        path: PathBuf,
        /// Cipher suite. Choices: aes (AES-256-GCM-SIV, default),
        /// aes-gcm (AES-256-GCM), chacha (ChaCha20-Poly1305).
        #[arg(long, default_value = "aes")]
        cipher: String,
        /// Argon2id memory cost in KiB. Range: 8 (test-only) to
        /// 4 GiB (4194304). Default: 256 MiB.
        #[arg(long, default_value_t = 262_144)]
        argon2_m: u32,
        /// Argon2id iteration count. Range: 1 to 16. Default: 3.
        #[arg(long, default_value_t = 3)]
        argon2_t: u32,
        /// Argon2id parallelism. Range: 1 to 16. Default: 4.
        #[arg(long, default_value_t = 4)]
        argon2_p: u32,
        /// Credential type for the initial slot. Choices:
        /// passphrase (default), fido2, pq-passphrase, pq-fido2,
        /// tpm, tpm-fido2, pq-tpm, pq-tpm-fido2.
        #[arg(long, default_value = "passphrase")]
        credential: String,
        /// Path for the .kyber seed file (required for pq-* combos).
        /// Encrypted at rest with the seed passphrase.
        #[arg(long)]
        kyber_path: Option<PathBuf>,
        /// Use ML-KEM-1024 instead of ML-KEM-768 for pq-* combos.
        /// Off by default (ML-KEM-768 is fine for most threat models).
        #[arg(long)]
        pq_1024: bool,
        /// Optional path for a rollback-detection anchor sidecar. In
        /// deniable mode the anchor uses the AEAD-encrypted format
        /// (256 B, every byte indistinguishable from random); without
        /// the matching vault + MVK + per_vault_salt it fails to
        /// verify with the same opaque error as random garbage.
        /// Keep on separate trusted storage from the vault (USB
        /// stick, second disk) - on the same medium it provides no
        /// protection. See docs/CRYPTO_SPEC.md "Anchor sidecar".
        #[arg(long)]
        anchor: Option<PathBuf>,
    },
    /// Mount a deniable-header vault. Same passphrase / cipher /
    /// Argon2 params requirements as `deniable-init`; all failure
    /// modes produce the same opaque "unlock failed" error.
    #[command(name = "deniable-mount")]
    DeniableMount {
        path: PathBuf,
        /// Cipher suite. Must match init.
        #[arg(long, default_value = "aes")]
        cipher: String,
        /// Argon2id memory cost in KiB. Must match init.
        #[arg(long, default_value_t = 262_144)]
        argon2_m: u32,
        /// Argon2id iteration count. Must match init.
        #[arg(long, default_value_t = 3)]
        argon2_t: u32,
        /// Argon2id parallelism. Must match init.
        #[arg(long, default_value_t = 4)]
        argon2_p: u32,
        /// Credential type. Must match init.
        #[arg(long, default_value = "passphrase")]
        credential: String,
        /// `.kyber` seed file path (pq-* combos). The ML-KEM seed
        /// is the one remaining sidecar in v2; FIDO2 cred-id /
        /// hmac-salt and TPM sealed blobs are now embedded inside
        /// the slot envelope.
        #[arg(long)]
        kyber_path: Option<PathBuf>,
        /// Stay in the foreground (don't daemonize). Default is to
        /// daemonize on Unix; ignored on Windows where WinFsp is
        /// always foreground.
        #[arg(short = 'f', long)]
        foreground: bool,
        /// Optional anchor sidecar to verify before mount. Must be
        /// the same anchor the vault was created/updated against
        /// (deniable AEAD-encrypted format). On rollback detection
        /// (`anchor_gen > metadata_gen`) the mount is refused. A
        /// missing or wrong file fails with the same opaque error as
        /// any other deniable AEAD failure. See `deniable-init
        /// --anchor`.
        #[arg(long)]
        anchor: Option<PathBuf>,
        mountpoint: PathBuf,
    },
    /// Open a deniable-header file and print the inner-header
    /// fields. Use to verify the header is openable with the supplied
    /// passphrase + params + cipher BEFORE bringing it up for mount.
    /// All failure modes (wrong passphrase, wrong params, wrong
    /// cipher, corrupt header) produce the same opaque error.
    #[command(name = "deniable-info")]
    DeniableInfo {
        path: PathBuf,
        /// Cipher suite. Must match what was used at init.
        #[arg(long, default_value = "aes")]
        cipher: String,
        /// Argon2id memory cost in KiB. Must match init.
        #[arg(long, default_value_t = 262_144)]
        argon2_m: u32,
        /// Argon2id iteration count. Must match init.
        #[arg(long, default_value_t = 3)]
        argon2_t: u32,
        /// Argon2id parallelism. Must match init.
        #[arg(long, default_value_t = 4)]
        argon2_p: u32,
        /// Credential type. Must match init.
        #[arg(long, default_value = "passphrase")]
        credential: String,
        /// `.kyber` seed file path (pq-* combos). The only sidecar
        /// remaining in v2; FIDO2 / TPM material lives in the slot.
        #[arg(long)]
        kyber_path: Option<PathBuf>,
    },
    /// Interactive wizard. Walks you through create / open / mount / keyslot
    /// management with prompts. Supports every option the regular subcommands
    /// do, including `--header` (detached) and `--kind fido2-direct`.
    Wizard,
    /// Generate a strong random passphrase (20 chars, 99 bits of entropy)
    /// from `OsRng` and print it to stdout. Useful before `create` or
    /// `enroll` when you don't have a strong passphrase in mind.
    Genpass,
    /// Benchmark Argon2id on this CPU. Runs the KDF at each preset
    /// (interactive, moderate, sensitive) and prints wall time per
    /// derivation, plus a brute-force-cost estimate. Useful before
    /// `create` to decide whether the default (interactive) is strong
    /// enough for your threat model, or whether you should switch to
    /// `--kdf sensitive` or specify `--kdf-target-time` for a custom
    /// target. Audit Round 9G addition.
    KdfBench {
        /// Number of samples to run per preset (default: 3). More
        /// samples reduce noise; 5 is sufficient for stable timings.
        #[arg(long, default_value_t = 3)]
        samples: u32,
    },
    /// Rotate the master volume key. Re-encrypts every chunk and the
    /// metadata blob with a freshly-generated MVK; re-wraps the keyslot
    /// under a fresh random salt with the same passphrase. Useful when
    /// you suspect the wrapped MVK may have been copied (e.g. from an
    /// old backup that was exposed). v1 limitation: the vault must have
    /// exactly one populated keyslot, and it must be a passphrase slot.
    /// **BACK UP THE VAULT FIRST**, a crash mid-rotation leaves it in
    /// an inconsistent state.
    RotateMvk {
        path: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    /// ANTI-FORENSICS PANIC: irreversibly destroy a vault by overwriting
    /// its header with random bytes. Without the header (or its backup),
    /// the vault is mathematically unrecoverable, no keyslots to attack,
    /// no MVK material left. Optionally also overwrites the entire vault
    /// file. Requires explicit confirmation. There is NO undo.
    Panic {
        path: PathBuf,
        /// If the vault uses a detached header sidecar, point at it here
        /// (we'll wipe the sidecar instead of/in addition to the vault).
        #[arg(long)]
        header: Option<PathBuf>,
        /// Also overwrite the entire vault data area with random bytes.
        /// Slow for large vaults (rewrites every byte) but defends against
        /// forensic reconstruction of the keyslot bytes if you don't trust
        /// the underlying storage to actually destroy old data on
        /// overwrite (SSDs, copy-on-write filesystems).
        #[arg(long)]
        wipe_data: bool,
        /// Skip the interactive confirmation prompt. DANGEROUS, only for
        /// scripted use after you've checked twice.
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// List every FIDO2 authenticator libfido2 can currently see.
    /// Each line prints `<index>  <path>  <label>` - copy the path
    /// into `--fido2-device` to bind subsequent commands to that
    /// specific authenticator. Useful on Windows where the platform
    /// authenticator (Windows Hello) shows up alongside any plugged
    /// physical key, and you need to choose between them.
    ListFido2Devices,
    /// Scan for orphan tempfiles next to a vault (`<base>.tmp.<hex>`,
    /// `<base>.rotating`) left behind by a previous crashed run. By
    /// default this is a dry-run report; pass `--delete` to actually
    /// remove the safe-to-delete `.tmp.<hex>` orphans. `.rotating`
    /// orphans are NEVER auto-deleted (they may hold the only copy
    /// of an in-progress MVK rotation); the report flags them and
    /// asks the user to inspect manually.
    CleanupOrphans {
        /// The vault file. Tempfiles in the same directory whose name
        /// starts with this file's basename are considered orphans.
        path: PathBuf,
        /// Actually remove the safe-to-delete `.tmp.<hex>` orphans.
        /// Without this flag, the command only prints what it would do.
        #[arg(long)]
        delete: bool,
    },
    /// Migrate a v2-format vault to v3 (out-of-line chunk lists).
    /// Reads the source vault, creates a new vault at `--dst` with
    /// the same cipher / KDF / keyslots / data, then writes it in
    /// v3 format. The source vault is left untouched (no in-place
    /// migration — too risky on a format change). After verifying
    /// the destination opens cleanly the user can delete the source.
    ///
    /// Requires the unlock material for the source vault. The
    /// destination inherits the SAME initial keyslot kind as the
    /// source's slot 0 (other slots can be re-enrolled afterward).
    /// v3 unlocks bigger-than-10-GiB vaults; for smaller vaults the
    /// migration is mostly a format change with no capacity benefit.
    MigrateToV3 {
        /// Path to the existing v2 vault to read from.
        src: PathBuf,
        /// Path for the new v3 vault. Must not already exist.
        #[arg(long)]
        dst: PathBuf,
        /// Unlock material for the source vault.
        #[command(flatten)]
        unlock: UnlockArgs,
    },
    /// Save a copy of the 8 KiB header bytes (offsets, keyslots, salts,
    /// HMAC) to a separate file. Equivalent to `cryptsetup luksHeaderBackup`.
    /// Does NOT require the unlock material: it just dumps the bytes that
    /// already live on disk. Useful as a routine pre-rotation backup, and
    /// as a recovery copy if the on-disk header later gets corrupted.
    /// Output file is mode 0600. Works in inline AND detached-header modes.
    HeaderBackup {
        /// The vault file. Used only to locate the header (offset 0 in
        /// inline mode, OR the sidecar passed via `--header`).
        path: PathBuf,
        /// Where to write the 8 KiB backup. Refused if the path already
        /// exists, to avoid overwriting an earlier backup by mistake.
        out: PathBuf,
        /// Detached-header sidecar to back up instead of the vault's
        /// own first 8 KiB. If unset, backs up the inline header.
        #[arg(long)]
        header: Option<PathBuf>,
    },
    /// Replace the on-disk header with bytes from a previously-saved
    /// backup file. By default this requires unlock material so we can
    /// HMAC-verify the new header against the current MVK BEFORE writing,
    /// preventing an attacker from substituting a header that authenticates
    /// under their MVK. Pass `--no-verify` to bypass that check (only
    /// when the on-disk header is too damaged to even unlock with).
    /// In inline mode this rewrites the first 8 KiB of the vault file
    /// in place; in detached mode (use `--header <path>` from the
    /// unlock options) it atomically replaces the sidecar at that path.
    HeaderRestore {
        /// The vault file.
        path: PathBuf,
        /// Path to the previously-saved 8 KiB header bytes.
        input: PathBuf,
        /// Unlock material. Used both to verify the NEW header's HMAC
        /// matches the current MVK before writing (skipped under
        /// `--no-verify`), AND to identify the detached header sidecar
        /// path via `--header`. If `--header` is set, the restore
        /// rewrites that sidecar; if unset, the restore rewrites the
        /// first 8 KiB of the vault file in place.
        #[command(flatten)]
        unlock: UnlockArgs,
        /// Skip the HMAC pre-write check. Required when the on-disk
        /// header is damaged enough that you can't open the container
        /// at all.
        #[arg(long)]
        no_verify: bool,
    },
    /// Decrypt the metadata blob and emit a JSON tree of every inode,
    /// chunk reference, generation counter, and keyslot summary.
    /// Read-only (never writes). Strictly forensic: this exposes
    /// metadata that the format normally only handles internally,
    /// and prints it on stdout.
    HeaderDump {
        /// The vault file.
        path: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
        /// Pretty-print the JSON. Off by default (single-line per
        /// document) for piping into `jq`; use `--pretty` for human
        /// reading.
        #[arg(long)]
        pretty: bool,
    },
    /// Walk every used chunk in the vault, AEAD-decrypt it, and report
    /// per-chunk status (`ok` / `aead_fail`). Surfaces the exact
    /// (file, chunk_idx, on-disk offset, generation) of every chunk
    /// the runtime would refuse to decrypt at mount time. Read-only.
    /// Output is human-readable by default; pass `--json` for a
    /// structured report.
    Check {
        /// The vault file.
        path: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
        /// Emit JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
        /// Stop after the first failure instead of scanning every
        /// chunk. Faster on large vaults when you just want a
        /// yes/no answer; off by default since the typical use is
        /// "tell me everything that's broken".
        #[arg(long)]
        stop_on_first_error: bool,
    },
    /// Forensic best-effort extract: pulls a file out of the vault
    /// like `get`, but tolerates per-chunk AEAD failures by writing
    /// 4096 zero bytes in place of each unrecoverable chunk and
    /// continuing. Prints the chunk_idx + on-disk offset of every
    /// failure to stderr (and to `--report <path>` as JSON, if set).
    /// Use this only when `get` fails and you want to recover what's
    /// still readable from a partly-corrupted file.
    Extract {
        /// The vault file.
        path: PathBuf,
        #[command(flatten)]
        unlock: UnlockArgs,
        /// Vault-internal path of the file to extract.
        inner: String,
        /// Local output path (mode 0600 on Unix).
        local: PathBuf,
        /// Required acknowledgement that the output may have
        /// 4096-byte zero gaps where chunks failed AEAD. Refuses to
        /// run without it.
        #[arg(long)]
        tolerate_errors: bool,
        /// Optional path to write a JSON failure report to.
        #[arg(long)]
        report: Option<PathBuf>,
    },
}

/// True if this CPU has hardware AES acceleration (constant-time AES).
/// Without it, the `aes-gcm` crate falls back to software AES which is
/// variable-time and theoretically vulnerable to cache-timing attacks.
/// ChaCha20-Poly1305 is constant-time on all platforms regardless.
///
/// Test-only override: `LUKSBOX_FAKE_NO_AES=1` forces the function
/// to return false. Used by the integration test that verifies the
/// warning path actually fires the right message.
fn aes_hardware_available() -> bool {
    if std::env::var_os("LUKSBOX_FAKE_NO_AES").is_some() {
        return false;
    }
    #[cfg(target_arch = "x86_64")]
    {
        return std::arch::is_x86_feature_detected!("aes");
    }
    #[cfg(target_arch = "aarch64")]
    {
        return std::arch::is_aarch64_feature_detected!("aes");
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

/// Print a one-time warning if AES will be software-implemented on
/// this CPU. Suppressed by `LUKSBOX_SUPPRESS_AES_WARNING=1`. The
/// recommendation (`--cipher chacha`) actually fixes the underlying
/// concern, ChaCha20-Poly1305 has no hardware-acceleration
/// dependency for constant-time execution.
fn maybe_warn_about_software_aes() {
    if std::env::var_os("LUKSBOX_SUPPRESS_AES_WARNING").is_some() {
        return;
    }
    if aes_hardware_available() {
        return;
    }
    eprintln!(
        "warning: this CPU has no hardware AES acceleration (no AES-NI on \
         x86_64 / no ARMv8 crypto extension on aarch64). The aes-gcm \
         crate's software fallback is variable-time and theoretically \
         vulnerable to cache-timing side-channels. For new vaults, \
         consider `--cipher chacha`, ChaCha20-Poly1305 is constant-time \
         on every platform. Suppress this warning with \
         LUKSBOX_SUPPRESS_AES_WARNING=1."
    );
}

// ---- FIDO2 device override -----------------------------------------------
//
// The CLI's global `--fido2-device <path>` flag (parsed on the
// top-level `Cli` struct) lands in this process-wide cell. Every
// FIDO2-touching subcommand below constructs its authenticator via
// `make_fido2_authenticator()` which reads the cell and binds the
// `HidAuthenticator` to that exact device. `None` falls back to the
// legacy "first device libfido2 enumerates wins" behavior.
//
// Mirrors the GUI's `ops::set_selected_fido2_device` plumbing so the
// two front-ends behave identically when the user has multiple
// authenticators plugged in (Windows Hello + a physical key being
// the common case on Windows).

use std::sync::Mutex;

static FIDO2_DEVICE_OVERRIDE: Mutex<Option<String>> = Mutex::new(None);

pub(crate) fn set_fido2_device_override(path: Option<String>) {
    if let Ok(mut g) = FIDO2_DEVICE_OVERRIDE.lock() {
        *g = path;
    }
}

/// Read the current --fido2-device override (None = legacy
/// "first device wins"). Used by the wizard to honor an outer CLI
/// flag when interactively selecting from multiple authenticators.
pub(crate) fn current_fido2_device_override() -> Option<String> {
    FIDO2_DEVICE_OVERRIDE.lock().ok().and_then(|g| g.clone())
}

/// Build a "please authenticate" prompt phrased correctly for the
/// currently-selected device. For Windows Hello the user doesn't
/// touch anything, they look at a camera or type a PIN; saying
/// "Touch your authenticator" misleads them into waiting for an LED
/// that never blinks. For physical keys we keep the touch wording.
///
/// `action` is a short verb-phrase like "register a new credential"
/// or "unlock (slot 2)" that gets appended.
pub(crate) fn auth_prompt(action: &str) -> String {
    let is_winhello = current_fido2_device_override()
        .as_deref()
        .map(luksbox_fido2::is_windows_hello_path)
        .unwrap_or(false);
    if is_winhello {
        format!("Authenticate with Windows Hello (face / fingerprint / PIN) to {action}...")
    } else {
        format!("Touch your FIDO2 authenticator to {action}...")
    }
}

#[cfg(feature = "hardware")]
pub(crate) fn make_fido2_authenticator() -> luksbox_fido2::HidAuthenticator {
    let path = FIDO2_DEVICE_OVERRIDE.lock().ok().and_then(|g| g.clone());
    match path {
        Some(p) => luksbox_fido2::HidAuthenticator::with_device(p),
        None => luksbox_fido2::HidAuthenticator::new(),
    }
}

fn main() -> ExitCode {
    // Process-wide RAM-secret hardening, applied before we touch any
    // keying material. Both calls are best-effort; mlock typically fails
    // for unprivileged users with low RLIMIT_MEMLOCK and we just warn.
    secret_mem::disable_core_dumps();
    if let Err(e) = secret_mem::enable_memory_lock() {
        eprintln!("warning: memory not locked: {e}");
    }
    maybe_warn_about_software_aes();
    let cli = Cli::parse();
    match dispatch(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(cli: Cli) -> Result<()> {
    // Stash the global --fido2-device path so make_fido2_authenticator
    // (used inside every FIDO2-touching subcommand below) binds to
    // the right authenticator. Independent of which subcommand runs.
    set_fido2_device_override(cli.fido2_device);

    match cli.command {
        Command::Create {
            path,
            cipher,
            kind,
            header,
            pad_files,
            hide_sizes,
            anchor,
            pq_hybrid,
            kdf,
            kdf_target_time,
            metadata_size,
            format,
        } => {
            // Round 9G: if --kdf-target-time was supplied, calibrate
            // params on this CPU; otherwise resolve from the static
            // --kdf preset.
            let resolved_params = match kdf_target_time {
                Some(t) => calibrate_kdf_for_target(&t)?,
                None => kdf_params_for(kdf),
            };
            // Resolve --metadata-size to a byte count (or None for default).
            // The override is installed in thread-local state by cmd_create
            // before calling Container::create_with_*.
            let resolved_metadata_size = match metadata_size {
                Some(s) => Some(parse_byte_size(&s)?),
                None => None,
            };
            cmd_create(
                &path,
                &cipher,
                kind,
                header.as_deref(),
                pad_files,
                hide_sizes,
                anchor,
                pq_hybrid,
                resolved_params,
                resolved_metadata_size,
                format,
            )
        }
        Command::Info { path } => cmd_info(&path),
        Command::Enroll { path, unlock, kind } => match kind {
            SlotKindArg::Passphrase => cmd_enroll_passphrase(&path, &unlock),
            SlotKindArg::Fido2 => cmd_enroll_fido2(&path, &unlock),
            SlotKindArg::Tpm2 => cmd_enroll_tpm2(&path, &unlock),
            SlotKindArg::Tpm2Fido2 => cmd_enroll_tpm2_fido2(&path, &unlock),
            SlotKindArg::Tpm2Pin => cmd_enroll_tpm2_pin(&path, &unlock),
            SlotKindArg::HybridPqTpm2 => cmd_enroll_hybrid_pq_tpm2(&path, &unlock, 768),
            SlotKindArg::HybridPqTpm2Fido2 => cmd_enroll_hybrid_pq_tpm2_fido2(&path, &unlock, 768),
            SlotKindArg::HybridPqTpm21024 => cmd_enroll_hybrid_pq_tpm2(&path, &unlock, 1024),
            SlotKindArg::HybridPqTpm2Fido21024 => {
                cmd_enroll_hybrid_pq_tpm2_fido2(&path, &unlock, 1024)
            }
            SlotKindArg::HybridPq => Err(
                "hybrid-pq slots can only be created at vault creation time \
                 (the Kyber pubkey + ciphertext live in the .lbx.hybrid \
                 sidecar, written at create). Recreate the vault with \
                 `luksbox create --kind hybrid-pq` if you need this."
                    .into(),
            ),
            SlotKindArg::HybridPqFido2 => Err(
                "hybrid-pq-fido2 slots can only be created at vault creation time \
                 (Kyber pubkey + ciphertext live in the .lbx.hybrid sidecar). \
                 Recreate the vault with `luksbox create --kind hybrid-pq-fido2`."
                    .into(),
            ),
            SlotKindArg::HybridPq1024 => {
                Err("hybrid-pq-1024 slots can only be created at vault creation time.".into())
            }
            SlotKindArg::HybridPq1024Fido2 => {
                Err("hybrid-pq-1024-fido2 slots can only be created at vault creation time.".into())
            }
            SlotKindArg::Fido2Direct => Err(
                "fido2-direct keyslots can only be created at vault creation time \
                 (the MVK must equal HKDF(authenticator-output) which can't be matched \
                 against an existing MVK). Use `--kind fido2` for a wrap-style \
                 hardware keyslot you can add to an existing vault."
                    .into(),
            ),
        },
        Command::Revoke { path, unlock, slot } => cmd_revoke(&path, &unlock, slot),
        Command::Update {
            path,
            unlock,
            slot,
            kind,
        } => cmd_update(&path, &unlock, slot, kind),
        Command::Ls {
            path,
            unlock,
            inner,
        } => cmd_ls(&path, &unlock, &inner),
        Command::Mkdir {
            path,
            unlock,
            inner,
        } => cmd_mkdir(&path, &unlock, &inner),
        Command::Put {
            path,
            unlock,
            local,
            inner,
        } => cmd_put(&path, &unlock, &local, &inner),
        Command::Get {
            path,
            unlock,
            inner,
            local,
        } => cmd_get(&path, &unlock, &inner, &local),
        Command::Cat {
            path,
            unlock,
            inner,
        } => cmd_cat(&path, &unlock, &inner),
        Command::Rm {
            path,
            unlock,
            inner,
        } => cmd_rm(&path, &unlock, &inner),
        Command::Rmdir {
            path,
            unlock,
            inner,
        } => cmd_rmdir(&path, &unlock, &inner),
        Command::Mv {
            path,
            unlock,
            old,
            new,
        } => cmd_mv(&path, &unlock, &old, &new),
        Command::Mount {
            path,
            unlock,
            foreground,
            mountpoint,
            private_mount,
        } => cmd_mount(
            &path,
            &unlock,
            foreground,
            mountpoint.as_deref(),
            private_mount,
        ),
        Command::MountFuseTHelper {
            vault,
            header,
            mountpoint,
        } => cmd_mount_fuse_t_helper(&vault, header.as_deref(), &mountpoint),
        Command::Umount { mountpoint } => cmd_umount(&mountpoint),
        Command::DeniableInit {
            path,
            cipher,
            argon2_m,
            argon2_t,
            argon2_p,
            credential,
            kyber_path,
            pq_1024,
            anchor,
        } => cmd_deniable_init(
            &path,
            &cipher,
            argon2_m,
            argon2_t,
            argon2_p,
            &credential,
            kyber_path.as_deref(),
            pq_1024,
            anchor.as_deref(),
        ),
        Command::DeniableMount {
            path,
            cipher,
            argon2_m,
            argon2_t,
            argon2_p,
            credential,
            kyber_path,
            foreground,
            anchor,
            mountpoint,
        } => cmd_deniable_mount(
            &path,
            &cipher,
            argon2_m,
            argon2_t,
            argon2_p,
            &credential,
            kyber_path.as_deref(),
            foreground,
            anchor.as_deref(),
            &mountpoint,
        ),
        Command::DeniableInfo {
            path,
            cipher,
            argon2_m,
            argon2_t,
            argon2_p,
            credential,
            kyber_path,
        } => cmd_deniable_info(
            &path,
            &cipher,
            argon2_m,
            argon2_t,
            argon2_p,
            &credential,
            kyber_path.as_deref(),
        ),
        Command::Wizard => wizard::run(),
        Command::Genpass => {
            println!("{}", &*passphrase::generate()?);
            Ok(())
        }
        Command::KdfBench { samples } => cmd_kdf_bench(samples),
        Command::Panic {
            path,
            header,
            wipe_data,
            yes,
        } => cmd_panic(&path, header.as_deref(), wipe_data, yes),
        Command::RotateMvk { path, unlock } => cmd_rotate_mvk(&path, &unlock),
        Command::ListFido2Devices => cmd_list_fido2_devices(),
        Command::CleanupOrphans { path, delete } => cmd_cleanup_orphans(&path, delete),
        Command::MigrateToV3 { src, dst, unlock } => cmd_migrate_to_v3(&src, &dst, &unlock),
        Command::HeaderBackup { path, out, header } => {
            cmd_header_backup(&path, &out, header.as_deref())
        }
        Command::HeaderRestore {
            path,
            input,
            unlock,
            no_verify,
        } => {
            let sidecar = unlock.header.clone();
            cmd_header_restore(&path, &input, sidecar.as_deref(), &unlock, no_verify)
        }
        Command::HeaderDump {
            path,
            unlock,
            pretty,
        } => cmd_header_dump(&path, &unlock, pretty),
        Command::Check {
            path,
            unlock,
            json,
            stop_on_first_error,
        } => cmd_check(&path, &unlock, json, stop_on_first_error),
        Command::Extract {
            path,
            unlock,
            inner,
            local,
            tolerate_errors,
            report,
        } => cmd_extract(
            &path,
            &unlock,
            &inner,
            &local,
            tolerate_errors,
            report.as_deref(),
        ),
    }
}

/// Scan for crash-leftover tempfiles next to a vault and report (or
/// optionally delete the safe ones). See the subcommand docstring for
/// the matching rules.
fn cmd_cleanup_orphans(path: &Path, delete: bool) -> Result<()> {
    use luksbox_core::file_util::{OrphanKind, delete_atomic_write_orphans, find_orphan_tempfiles};

    let orphans = find_orphan_tempfiles(path).map_err(|e| format!("scan failed: {e}"))?;
    if orphans.is_empty() {
        println!("no orphan tempfiles found next to {}", path.display());
        return Ok(());
    }

    let dir_label = path
        .parent()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| ".".to_string());
    println!(
        "found {} orphan tempfile(s) in {}:",
        orphans.len(),
        dir_label
    );
    for o in &orphans {
        let kind_str = match o.kind {
            OrphanKind::AtomicWriteTmp => "atomic-write-tmp",
            OrphanKind::RotationTmp => "rotation-tmp     ",
        };
        println!("  [{kind_str}] {:>12} bytes  {}", o.size, o.path.display());
    }

    let safe = orphans
        .iter()
        .filter(|o| o.kind == OrphanKind::AtomicWriteTmp)
        .count();
    let unsafe_count = orphans
        .iter()
        .filter(|o| o.kind == OrphanKind::RotationTmp)
        .count();

    if unsafe_count > 0 {
        eprintln!();
        eprintln!(
            "WARNING: {unsafe_count} `.rotating` orphan(s) found. These may be the only \
             surviving copy of an in-progress MVK rotation. NOT auto-deleting. To recover:"
        );
        eprintln!("  1. Take a backup of both the original vault and the .rotating file.");
        eprintln!("  2. If the rotation crashed before commit, the original is still valid;");
        eprintln!("     remove the .rotating file manually with `rm`.");
        eprintln!(
            "  3. If you're not sure, copy both files somewhere safe and open a Penthertz support ticket."
        );
    }

    if !delete {
        if safe > 0 {
            println!();
            println!(
                "dry-run: rerun with `--delete` to remove the {safe} safe-to-delete \
                 atomic-write-tmp file(s) above."
            );
        }
        return Ok(());
    }

    let (deleted, errors) = delete_atomic_write_orphans(&orphans);
    println!();
    println!("deleted {} orphan(s):", deleted.len());
    for d in &deleted {
        println!("  {}", d.display());
    }
    if !errors.is_empty() {
        eprintln!();
        eprintln!("{} error(s) during deletion:", errors.len());
        for (p, e) in &errors {
            eprintln!("  {}: {e}", p.display());
        }
        return Err(format!("{} deletion(s) failed", errors.len()).into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Forensic / recovery surfaces. Pre-unlock: `header backup`, `header restore`
// (the latter with optional unlock for HMAC verify). Post-unlock: `header
// dump`, `check`, `extract --tolerate-errors`. Read-only with the single
// exception of `header restore`, which rewrites the 8 KiB header.
// ---------------------------------------------------------------------------

/// Resolve where the 8 KiB header lives on disk for a given vault.
/// In inline mode it's at offset 0 of the vault file; in detached
/// mode it's the entire content of the sidecar passed via `--header`.
/// Returns `(path_to_read, offset)`.
fn resolve_header_location(vault: &Path, header_sidecar: Option<&Path>) -> (PathBuf, u64) {
    match header_sidecar {
        Some(p) => (p.to_path_buf(), 0),
        None => (vault.to_path_buf(), 0),
    }
}

/// Read the 8 KiB header bytes from disk WITHOUT requiring an unlock.
/// Returns the raw bytes plus the parsed `Header` (parse-only, HMAC
/// not verified, since we have no MVK at this point). Used by both
/// `header backup` (to validate before dump) and `header restore` (to
/// validate the input file before write).
fn read_header_bytes(path: &Path, offset: u64) -> Result<([u8; HEADER_SIZE], Header)> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let mut f = File::open(path).map_err(|e| format!("opening {}: {e}", path.display()))?;
    f.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("seek to {} in {}: {e}", offset, path.display()))?;
    let mut buf = [0u8; HEADER_SIZE];
    f.read_exact(&mut buf)
        .map_err(|e| format!("reading {} bytes from {}: {e}", HEADER_SIZE, path.display()))?;
    let parsed = Header::from_bytes(&buf)
        .map_err(|e| format!("not a valid LUKSbox header at {}: {e}", path.display()))?;
    Ok((buf, parsed))
}

fn cmd_header_backup(vault: &Path, out: &Path, header_sidecar: Option<&Path>) -> Result<()> {
    use std::io::Write as _;
    if out.exists() {
        return Err(format!(
            "output file {} already exists; refusing to overwrite an earlier backup",
            out.display()
        )
        .into());
    }
    let (src, offset) = resolve_header_location(vault, header_sidecar);
    let (bytes, parsed) = read_header_bytes(&src, offset)?;
    // Mode 0600 on Unix, no symlink follow at the final component
    // (matches the same hardening cmd_get applies to plaintext exports).
    let mut dst = luksbox_core::file_util::secure_create_or_truncate(out)
        .map_err(|e| format!("creating {}: {e}", out.display()))?;
    dst.write_all(&bytes)
        .map_err(|e| format!("writing {}: {e}", out.display()))?;
    dst.flush()
        .map_err(|e| format!("flushing {}: {e}", out.display()))?;
    drop(dst);
    println!(
        "wrote {} bytes from {} to {}",
        HEADER_SIZE,
        src.display(),
        out.display()
    );
    println!(
        "  cipher: {:?}    metadata at offset {} ({} B)    data at offset {}",
        parsed.cipher_suite, parsed.metadata_offset, parsed.metadata_size, parsed.data_offset
    );
    let populated = parsed.keyslots.iter().filter(|s| !s.is_empty()).count();
    println!(
        "  populated keyslots: {populated} / {}",
        parsed.keyslots.len()
    );
    eprintln!(
        "note: keep this backup on storage SEPARATE from the vault. \
         Anyone who has both the .lbx and a backup of its header has the \
         same offline brute-force surface as anyone who has the original \
         vault."
    );
    Ok(())
}

fn cmd_header_restore(
    vault: &Path,
    input: &Path,
    header_sidecar: Option<&Path>,
    unlock: &UnlockArgs,
    no_verify: bool,
) -> Result<()> {
    // 1. Parse the backup file (catches "this isn't even a header").
    let (new_bytes, new_header) = read_header_bytes(input, 0)?;
    println!(
        "input {}: parses as a valid header (cipher {:?}, header_salt prefix {})",
        input.display(),
        new_header.cipher_suite,
        new_header
            .header_salt
            .iter()
            .take(4)
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    );

    // 2. Round 13 fix R13-02: we open the container UP FRONT (when not
    //    in --no-verify mode) and reuse the same verified handle for
    //    the rewrite. Previously the restore re-opened the vault path
    //    with plain `OpenOptions::open` after verify, creating a
    //    symlink-swap window between the two opens; an attacker who
    //    could race the path between verify and rewrite could redirect
    //    the first 8 KiB into another writable target. The new flow
    //    routes the rewrite through `Container::restore_header_bytes`,
    //    which uses the already-locked, already-inode-verified
    //    `self.file` for inline mode, and `atomic_secure_write` for
    //    detached mode (so the sidecar swap is temp+fsync+rename
    //    rather than in-place truncation).
    //
    //    In --no-verify mode the on-disk header may itself be too
    //    broken to unlock with, so we cannot route through Container
    //    (which would refuse to open the vault). For that path we
    //    keep the legacy direct-open, but add `O_NOFOLLOW` so an
    //    attacker who pre-created a symlink at `vault` cannot
    //    redirect the rewrite.
    if !no_verify {
        let mut container = open_container(vault, unlock).map_err(|e| {
            format!(
                "could not unlock the vault to HMAC-verify the new header against the current MVK: {e}. \
                 If the on-disk header is itself too damaged to unlock with, re-run with `--no-verify` \
                 (this skips the safety check; only use it when you know the backup file came from a \
                 trusted source)."
            )
        })?;
        let mvk = container.mvk_clone();
        new_header.verify_hmac(&new_bytes, &mvk).map_err(|e| {
            format!(
                "HMAC of {} does NOT verify against the vault's current MVK: {e}. \
                     The backup may be from a different vault, from an older MVK, or tampered. \
                     If you really need to install it (for example because the on-disk MVK is \
                     beyond recovery), re-run with `--no-verify`.",
                input.display()
            )
        })?;
        println!("  HMAC verify: OK (the backup was sealed under this vault's current MVK)");

        container
            .restore_header_bytes(&new_bytes)
            .map_err(|e| format!("installing verified backup header: {e}"))?;
        match header_sidecar {
            Some(hp) => println!(
                "restored detached header to {} (atomic rename via container)",
                hp.display()
            ),
            None => println!(
                "restored inline header to {} (in-place fsynced write via container)",
                vault.display()
            ),
        }
        // Drop the container; the in-memory header is stale relative
        // to disk after the rewrite, so we don't keep using it.
        drop(container);
        return Ok(());
    }

    // --no-verify path: write the bytes directly. We can't route
    // through Container here because the on-disk header may be too
    // damaged to unlock.
    eprintln!(
        "warning: --no-verify is set; the backup file is NOT being HMAC-checked \
         against the current MVK. Use this only if you trust the source of the \
         backup file."
    );
    match header_sidecar {
        Some(hp) => {
            luksbox_core::file_util::atomic_secure_write(hp, &new_bytes)
                .map_err(|e| format!("atomic-replace of {}: {e}", hp.display()))?;
            println!(
                "restored detached header to {} (atomic rename)",
                hp.display()
            );
        }
        None => {
            // Direct open, with `O_NOFOLLOW` on Unix and
            // `FILE_FLAG_OPEN_REPARSE_POINT` + reparse-attribute
            // refusal on Windows, so the rewrite cannot be
            // redirected through a symlink an attacker pre-created
            // at the vault path.
            use std::fs::OpenOptions;
            use std::io::{Seek as _, SeekFrom, Write as _};
            let mut o = OpenOptions::new();
            o.read(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                o.custom_flags(libc::O_NOFOLLOW);
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt as _;
                // FILE_FLAG_OPEN_REPARSE_POINT
                o.custom_flags(0x0020_0000);
            }
            let mut f = o
                .open(vault)
                .map_err(|e| format!("opening {} for inline restore: {e}", vault.display()))?;
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt as _;
                let attrs = f
                    .metadata()
                    .map_err(|e| format!("stat {} for restore: {e}", vault.display()))?
                    .file_attributes();
                if attrs & 0x0000_0400 != 0 {
                    return Err(format!(
                        "{} is a reparse point (symlink / junction); refusing to overwrite header",
                        vault.display()
                    )
                    .into());
                }
            }
            f.seek(SeekFrom::Start(0))
                .map_err(|e| format!("seek to 0 in {}: {e}", vault.display()))?;
            f.write_all(&new_bytes)
                .map_err(|e| format!("writing inline header to {}: {e}", vault.display()))?;
            f.sync_all()
                .map_err(|e| format!("fsync {}: {e}", vault.display()))?;
            println!(
                "restored inline header to {} (in-place write of bytes 0..{}, fsynced)",
                vault.display(),
                HEADER_SIZE
            );
        }
    }
    Ok(())
}

fn cmd_header_dump(vault: &Path, unlock: &UnlockArgs, pretty: bool) -> Result<()> {
    let vfs = open_vfs(vault, unlock)?;
    let header_storage = vfs.container().header_storage_path().to_path_buf();
    let h = vfs.container().header.clone();
    let counters = vfs.tree_counters();

    // Recursively walk the directory tree from root, building a
    // serializable inode list. Uses `readdir` (returns name + child
    // id), `inode_kind`, `inode_size_raw`, and `file_chunks` - none
    // require a chunk decrypt, so a vault with corrupted chunks still
    // produces a complete dump (each chunk's status is reported by
    // `check`, not here).
    let mut inodes_json: Vec<serde_json::Value> = Vec::new();
    let root = vfs.root_id();
    let mut stack: Vec<(FileId, String)> = vec![(root, "/".to_string())];
    while let Some((id, path)) = stack.pop() {
        let kind = vfs.inode_kind(id)?;
        let size = vfs.inode_size_raw(id)?;
        let mut entry = serde_json::json!({
            "id": id,
            "path": path,
            "kind": match kind {
                InodeKind::File => "file",
                InodeKind::Directory => "dir",
            },
            "size_raw": size,
        });
        match kind {
            InodeKind::File => {
                let chunks = vfs.file_chunks(id)?;
                let chunk_json: Vec<serde_json::Value> = chunks
                    .iter()
                    .enumerate()
                    .map(|(idx, cref)| {
                        // slot_offset can fail on overflow, but only on
                        // a hostile metadata blob; validate_metadata_tree
                        // already rejected those at open time, so a
                        // None here is purely defensive.
                        let off = luksbox_vfs::CHUNK_SLOT_SIZE
                            .checked_mul(cref.id)
                            .and_then(|rel| rel.checked_add(h.data_offset));
                        serde_json::json!({
                            "chunk_idx": idx,
                            "chunk_id": cref.id,
                            "generation": cref.generation,
                            "slot_offset": off,
                        })
                    })
                    .collect();
                entry["chunks"] = serde_json::Value::Array(chunk_json);
            }
            InodeKind::Directory => {
                let entries = vfs.readdir(id)?;
                let mut children = Vec::with_capacity(entries.len());
                for de in &entries {
                    let child_path = if path == "/" {
                        format!("/{}", de.name)
                    } else {
                        format!("{}/{}", path, de.name)
                    };
                    children.push(serde_json::json!({
                        "name": de.name,
                        "id": de.id,
                    }));
                    stack.push((de.id, child_path));
                }
                entry["children"] = serde_json::Value::Array(children);
            }
        }
        inodes_json.push(entry);
    }

    // Stable sort by id so diffs across two dumps line up.
    inodes_json.sort_by_key(|v| v["id"].as_u64().unwrap_or(0));

    let keyslots_json: Vec<serde_json::Value> = h
        .keyslots
        .iter()
        .enumerate()
        .map(|(i, s)| {
            serde_json::json!({
                "index": i,
                "kind": format!("{:?}", s.kind),
                "is_empty": s.is_empty(),
            })
        })
        .collect();

    let doc = serde_json::json!({
        "vault": vault.display().to_string(),
        "header_storage": header_storage.display().to_string(),
        "header": {
            "cipher": format!("{:?}", h.cipher_suite),
            "kdf": format!("{:?}", h.kdf),
            "chunk_size": h.chunk_size,
            "flags": h.flags,
            "metadata_offset": h.metadata_offset,
            "metadata_size": h.metadata_size,
            "data_offset": h.data_offset,
            "header_salt_prefix": h.header_salt.iter().take(4)
                .map(|b| format!("{b:02x}")).collect::<String>(),
        },
        "keyslots": keyslots_json,
        "tree_counters": {
            "next_chunk_id": counters.next_chunk_id,
            "next_chunk_gen": counters.next_chunk_gen,
            "next_file_id": counters.next_file_id,
            "free_chunk_count": counters.free_chunk_count,
        },
        "inodes": inodes_json,
    });

    let s = if pretty {
        serde_json::to_string_pretty(&doc)
    } else {
        serde_json::to_string(&doc)
    }
    .map_err(|e| format!("serializing dump: {e}"))?;
    println!("{s}");
    Ok(())
}

fn cmd_check(
    vault: &Path,
    unlock: &UnlockArgs,
    json: bool,
    stop_on_first_error: bool,
) -> Result<()> {
    use luksbox_vfs::chunk;
    let mut vfs = open_vfs(vault, unlock)?;
    let data_offset = vfs.container().data_offset();
    let root = vfs.root_id();

    // Per-failure record. Successful chunks are tallied as a count
    // only; broken ones get full details.
    let mut failures: Vec<serde_json::Value> = Vec::new();
    let mut total_files: u64 = 0;
    let mut total_chunks_ok: u64 = 0;
    let mut total_chunks_bad: u64 = 0;

    // BFS tree walk via readdir; same shape as `header dump`.
    let mut stack: Vec<(FileId, String)> = vec![(root, "/".to_string())];
    'walk: while let Some((id, path)) = stack.pop() {
        let kind = vfs.inode_kind(id)?;
        match kind {
            InodeKind::Directory => {
                let entries = vfs.readdir(id)?;
                for de in &entries {
                    let child_path = if path == "/" {
                        format!("/{}", de.name)
                    } else {
                        format!("{}/{}", path, de.name)
                    };
                    stack.push((de.id, child_path));
                }
            }
            InodeKind::File => {
                total_files += 1;
                let chunks = vfs.file_chunks(id)?;
                if chunks.is_empty() {
                    continue;
                }
                let key = chunk::file_key(vfs.container(), id);
                let container = vfs.container_mut();
                for (idx, cref) in chunks.iter().enumerate() {
                    match chunk::read_chunk(container, &key, id, idx as u32, *cref) {
                        Ok(_pt) => total_chunks_ok += 1,
                        Err(e) => {
                            total_chunks_bad += 1;
                            // slot_offset arithmetic is the same as
                            // chunk::slot_offset; recompute here for
                            // the report so we don't take a borrow.
                            let off = luksbox_vfs::CHUNK_SLOT_SIZE
                                .checked_mul(cref.id)
                                .and_then(|rel| rel.checked_add(data_offset));
                            let detail = serde_json::json!({
                                "file_id": id,
                                "path": path,
                                "chunk_idx": idx,
                                "chunk_id": cref.id,
                                "generation": cref.generation,
                                "slot_offset": off,
                                "error": e.to_string(),
                            });
                            if !json {
                                eprintln!(
                                    "BAD  {} chunk_idx={} chunk_id={} gen={} off={} : {}",
                                    path,
                                    idx,
                                    cref.id,
                                    cref.generation,
                                    off.map(|v| v.to_string())
                                        .unwrap_or_else(|| "(overflow)".into()),
                                    e
                                );
                            }
                            failures.push(detail);
                            if stop_on_first_error {
                                break 'walk;
                            }
                        }
                    }
                }
            }
        }
    }

    let total_chunks = total_chunks_ok + total_chunks_bad;
    if json {
        let doc = serde_json::json!({
            "vault": vault.display().to_string(),
            "summary": {
                "files": total_files,
                "chunks_total": total_chunks,
                "chunks_ok": total_chunks_ok,
                "chunks_bad": total_chunks_bad,
            },
            "failures": failures,
            "stopped_on_first_error": stop_on_first_error && total_chunks_bad > 0,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&doc).map_err(|e| format!("serializing: {e}"))?
        );
    } else {
        println!();
        println!(
            "checked {total_files} file(s), {total_chunks} chunk(s): {total_chunks_ok} OK, {total_chunks_bad} BAD"
        );
        if total_chunks_bad > 0 {
            println!("re-run with --json to capture the per-failure details for a bug report.");
        }
    }
    if total_chunks_bad > 0 {
        Err(format!("{total_chunks_bad} chunk(s) failed AEAD verification, see above").into())
    } else {
        Ok(())
    }
}

fn cmd_extract(
    vault: &Path,
    unlock: &UnlockArgs,
    inner: &str,
    local: &Path,
    tolerate_errors: bool,
    report: Option<&Path>,
) -> Result<()> {
    use luksbox_vfs::chunk;
    use std::io::Write as _;

    if !tolerate_errors {
        return Err(
            "`extract` is the lossy recovery path: pass `--tolerate-errors` to acknowledge \
             that the output may have 4096-byte zero gaps where chunks failed AEAD. \
             For normal extraction use `luksbox get`."
                .into(),
        );
    }

    let mut vfs = open_vfs(vault, unlock)?;
    let id = vfs.lookup_path(inner)?;
    let kind = vfs.inode_kind(id)?;
    if kind != InodeKind::File {
        return Err(format!("{inner} is not a file").into());
    }
    let chunks = vfs.file_chunks(id)?;
    let stored_size = vfs.inode_size_raw(id)?;
    // Hide-size mode stores the real size inside chunk 0; if chunk 0 is
    // unreadable we can't know the real size, so we fall back to the
    // padded length (which over-reads zeros at EOF - acceptable in the
    // forensic recovery path).
    let hide_size = vfs.container().header.hide_size_header();
    let data_offset = vfs.container().data_offset();

    let mut dst = luksbox_core::file_util::secure_create_or_truncate(local)
        .map_err(|e| format!("creating {}: {e}", local.display()))?;

    let key = chunk::file_key(vfs.container(), id);
    let container = vfs.container_mut();

    let mut bytes_written: u64 = 0;
    let mut chunks_ok: u64 = 0;
    let mut chunks_bad: u64 = 0;
    let mut failures: Vec<serde_json::Value> = Vec::new();
    let zero_chunk = vec![0u8; luksbox_vfs::CHUNK_PLAINTEXT_SIZE];

    for (idx, cref) in chunks.iter().enumerate() {
        let pt_buf: Vec<u8>;
        let pt: &[u8] = match chunk::read_chunk(container, &key, id, idx as u32, *cref) {
            Ok(z) => {
                chunks_ok += 1;
                pt_buf = z.to_vec();
                &pt_buf
            }
            Err(e) => {
                chunks_bad += 1;
                let off = luksbox_vfs::CHUNK_SLOT_SIZE
                    .checked_mul(cref.id)
                    .and_then(|rel| rel.checked_add(data_offset));
                eprintln!(
                    "chunk_idx={} chunk_id={} gen={} off={} FAILED ({}); writing 4096 zero bytes",
                    idx,
                    cref.id,
                    cref.generation,
                    off.map(|v| v.to_string())
                        .unwrap_or_else(|| "(overflow)".into()),
                    e
                );
                failures.push(serde_json::json!({
                    "chunk_idx": idx,
                    "chunk_id": cref.id,
                    "generation": cref.generation,
                    "slot_offset": off,
                    "error": e.to_string(),
                }));
                &zero_chunk
            }
        };
        // Skip the 8-byte size header on chunk 0 in hide-size mode.
        // (If chunk 0 failed and we're emitting zeros, those 8 zero
        // bytes still get skipped - same shape, no off-by-one.)
        let chunk_data_start = if hide_size && idx == 0 { 8 } else { 0 };
        dst.write_all(&pt[chunk_data_start..])
            .map_err(|e| format!("writing to {}: {e}", local.display()))?;
        bytes_written += (pt.len() - chunk_data_start) as u64;
    }

    // Truncate to the stored logical size so we don't leave 4096-aligned
    // zero padding at EOF (only meaningful in non-hide-size mode; in
    // hide-size mode the stored_size is the padded chunk capacity, so
    // truncating to it is a no-op and we leak the hide-size padding,
    // which is acceptable in this mode for the recovery path).
    if !hide_size && stored_size < bytes_written {
        dst.set_len(stored_size)
            .map_err(|e| format!("truncating {} to {}: {e}", local.display(), stored_size))?;
        bytes_written = stored_size;
    }
    dst.flush()
        .map_err(|e| format!("flushing {}: {e}", local.display()))?;

    println!(
        "wrote {bytes_written} bytes to {} ({chunks_ok} chunks OK, {chunks_bad} chunks zero-filled)",
        local.display()
    );
    if let Some(rp) = report {
        let doc = serde_json::json!({
            "vault": vault.display().to_string(),
            "inner": inner,
            "local": local.display().to_string(),
            "bytes_written": bytes_written,
            "chunks_ok": chunks_ok,
            "chunks_bad": chunks_bad,
            "failures": failures,
        });
        let mut rf = luksbox_core::file_util::secure_create_or_truncate(rp)
            .map_err(|e| format!("creating report {}: {e}", rp.display()))?;
        rf.write_all(
            serde_json::to_string_pretty(&doc)
                .map_err(|e| format!("serializing report: {e}"))?
                .as_bytes(),
        )
        .map_err(|e| format!("writing report {}: {e}", rp.display()))?;
        rf.flush()
            .map_err(|e| format!("flushing report {}: {e}", rp.display()))?;
        println!("failure report written to {}", rp.display());
    }
    if chunks_bad > 0 {
        eprintln!(
            "warning: {chunks_bad} chunk(s) were unrecoverable. The output file has \
             4096-byte zero ranges at the corresponding offsets."
        );
    }
    Ok(())
}

#[cfg(feature = "hardware")]
fn cmd_list_fido2_devices() -> Result<()> {
    let devices = luksbox_fido2::HidAuthenticator::detect_all()
        .map_err(|e| format!("libfido2 enumeration failed: {e}"))?;
    if devices.is_empty() {
        println!(
            "no FIDO2 authenticators detected. Plug one in (any CTAP2 \
             authenticator: YubiKey, Nitrokey, SoloKey, Token2, OnlyKey, \
             etc.) or, on Windows, ensure Windows Hello is set up."
        );
        #[cfg(target_os = "windows")]
        {
            println!();
            println!(
                "Windows note: non-elevated processes can't enumerate USB \
                 FIDO2 devices directly (the FIDO2 HID class is reserved \
                 for the WebAuthn system service since Windows 10 1903). \
                 If your USB security key is plugged in but not listed, \
                 re-run this command from an elevated shell \
                 (`runas /user:Administrator ...`) or via \"Run as \
                 administrator\". Windows Hello does NOT need elevation, \
                 it always shows up if Windows Hello is set up."
            );
        }
        return Ok(());
    }
    println!("INDEX  PATH                                      LABEL");
    for (i, d) in devices.iter().enumerate() {
        // Path can be quite long on Windows / macOS; print as-is so
        // the user can copy-paste verbatim into --fido2-device.
        println!("  {:>3}  {:<40}  {}", i, d.path, d.label);
    }
    println!();
    println!(
        "Pass --fido2-device <PATH> to subsequent commands to bind to a \
         specific authenticator. Without --fido2-device, the first one \
         enumerated is used."
    );
    #[cfg(target_os = "windows")]
    {
        let only_winhello = devices
            .iter()
            .all(|d| luksbox_fido2::is_windows_hello_path(&d.path));
        if only_winhello {
            println!();
            println!(
                "Note: only Windows Hello shows up here. If you have a USB \
                 security key plugged in, re-run this from an elevated \
                 shell - Windows requires admin to enumerate USB FIDO2 \
                 devices directly (HID-class restriction since Windows \
                 10 1903). Windows Hello works without elevation."
            );
        }
    }
    Ok(())
}

#[cfg(not(feature = "hardware"))]
fn cmd_list_fido2_devices() -> Result<()> {
    Err(
        "FIDO2 hardware support not compiled in (rebuild with `cargo build \
         --features hardware`)"
            .into(),
    )
}

// ----- helpers ---------------------------------------------------------------

pub(crate) fn parse_cipher(s: &str) -> Result<CipherSuite> {
    match s {
        // GCM-SIV (recommended) takes both the explicit name and the
        // bare "aes" alias since it's the new default; users who want
        // the legacy GCM must say so explicitly.
        "aes" | "aes-gcm-siv" | "aes-256-gcm-siv" | "siv" => Ok(CipherSuite::Aes256GcmSiv),
        "aes-gcm" | "aes-256-gcm" | "gcm" => Ok(CipherSuite::Aes256Gcm),
        "chacha" | "chacha20-poly1305" => Ok(CipherSuite::ChaCha20Poly1305),
        other => Err(format!("unknown cipher: {other}").into()),
    }
}

/// True iff the `LUKSBOX_TEST_FAST_KDF=1` test bypass should be honored.
///
/// **Compiled out of release binaries** (`debug_assertions = false`),
/// so an attacker who pollutes the environment of a shipped LUKSbox
/// binary cannot downgrade Argon2id to brute-forceable parameters. The
/// env var is read only in debug / `cargo test` builds, where it is
/// used to keep the test suite under a few minutes by sidestepping the
/// production-strength KDF cost.
///
/// Integration tests in `crates/luksbox-cli/tests/*.rs` spawn the
/// binary under the dev profile, so `debug_assertions` is on and the
/// bypass remains available there.
#[inline]
fn test_fast_kdf_enabled() -> bool {
    #[cfg(debug_assertions)]
    {
        std::env::var_os("LUKSBOX_TEST_FAST_KDF").is_some()
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}

/// Default Argon2id parameters used by `enroll`/`update` when no
/// strength is specified. In debug builds, `LUKSBOX_TEST_FAST_KDF=1`
/// switches to laughably weak parameters so KDF doesn't dominate test
/// time; in release builds the env var has no effect (see
/// [`test_fast_kdf_enabled`]).
pub(crate) fn kdf_params() -> Argon2idParams {
    kdf_params_for(KdfStrengthArg::Interactive)
}

pub(crate) fn kdf_params_for(strength: KdfStrengthArg) -> Argon2idParams {
    if test_fast_kdf_enabled() {
        Argon2idParams {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        }
    } else {
        strength.params()
    }
}

/// Read one line from stdin, strip a trailing `\n` (and optional
/// `\r`), wrap in `Zeroizing`. Used for the "stdin is a pipe"
/// non-interactive path - audit Round 9F. Pipe input is preferred
/// over `LUKSBOX_PASSPHRASE` env var when both are usable, because
/// pipe content is not visible in `/proc/<pid>/environ` (env vars
/// are, to processes running as the same UID).
fn read_passphrase_from_stdin_pipe() -> io::Result<Zeroizing<String>> {
    use std::io::BufRead;
    let mut line = String::new();
    let stdin = io::stdin();
    let mut handle = stdin.lock();
    handle.read_line(&mut line)?;
    // Strip trailing newline + optional CR (Windows-style line ends
    // and most "echo / heredoc" pipes append \n; users who genuinely
    // want a trailing newline in the passphrase can put it before
    // the LAST char and use a multi-line entry mechanism).
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    Ok(Zeroizing::new(line))
}

/// Wrap a freshly-read secret string in `Zeroizing` so the underlying
/// allocation is memset-to-zero when the binding is dropped. Note: prior
/// reallocations made by `String::push`/`format!` aren't tracked, we rely
/// on `rpassword`/`std::env::var` returning a single allocation here.
///
/// Source priority:
///   1. Stdin, if stdin is NOT a terminal (i.e., piped from
///      another process or redirected from a file). The passphrase
///      bytes never appear in argv or env; the writing process
///      controls visibility. Use:
///        cat ~/.config/my-pp | luksbox open my.lbx
///   2. `LUKSBOX_PASSPHRASE` env var, if set. (Convenient for shell
///      scripts; visible to same-UID processes via
///      `/proc/<pid>/environ` so prefer the pipe when both are
///      available.)
///   3. Interactive prompt via `rpassword` (echo disabled, terminal
///      cleanup on signals).
///
/// When real bytes arrive on the pipe AND `LUKSBOX_PASSPHRASE` is
/// also set, the function returns an error rather than silently
/// picking one source over the other. Previously the env var won
/// unconditionally, which let a stale or injected env var override
/// the secret a script was piping in - a quiet, hard-to-spot
/// precedence bug. An empty/closed stdin pipe (`Command::output()`
/// auto-pipes but writes nothing, the common test pattern) falls
/// through to the env var so existing harnesses keep working.
fn read_passphrase(prompt: &str) -> io::Result<Zeroizing<String>> {
    use std::io::IsTerminal;
    let env_set = std::env::var_os("LUKSBOX_PASSPHRASE").is_some();
    if !io::stdin().is_terminal() {
        let piped = read_passphrase_from_stdin_pipe()?;
        if !piped.is_empty() {
            if env_set {
                return Err(io::Error::other(
                    "ambiguous passphrase source: both stdin pipe and \
                     LUKSBOX_PASSPHRASE are providing input. Unset \
                     one to disambiguate (the env var is visible via \
                     /proc/<pid>/environ, the pipe is not).",
                ));
            }
            return Ok(piped);
        }
        // Empty pipe (e.g. `Command::output()` with no write to
        // child.stdin) - fall through to env var / prompt.
    }
    if let Ok(p) = std::env::var("LUKSBOX_PASSPHRASE") {
        return Ok(Zeroizing::new(p));
    }
    Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
}

/// Round 12 follow-up: explicit empty-passphrase confirmation in
/// the confirmed-prompt path, matching the wizard's
/// `ask_new_passphrase` warning. Without this an interactive user
/// who Enter-mashes through both passphrase fields silently creates
/// a passphrase-less vault.
fn read_passphrase_confirmed(prompt: &str) -> io::Result<Zeroizing<String>> {
    // Source priority mirrors `read_passphrase`. `LUKSBOX_NEW_PASSPHRASE`
    // takes precedence over `LUKSBOX_PASSPHRASE` when both env vars
    // are set; same ambiguity guard fires when real bytes arrive on
    // the pipe AND any of the recognised env vars is set.
    use std::io::IsTerminal;
    let env_set = std::env::var_os("LUKSBOX_NEW_PASSPHRASE").is_some()
        || std::env::var_os("LUKSBOX_PASSPHRASE").is_some();
    if !io::stdin().is_terminal() {
        let piped = read_passphrase_from_stdin_pipe()?;
        if !piped.is_empty() {
            if env_set {
                return Err(io::Error::other(
                    "ambiguous passphrase source: both stdin pipe and \
                     LUKSBOX_NEW_PASSPHRASE or LUKSBOX_PASSPHRASE \
                     are providing input. Unset the env var(s) or \
                     close stdin to disambiguate.",
                ));
            }
            return Ok(piped);
        }
    }
    if let Ok(p) = std::env::var("LUKSBOX_NEW_PASSPHRASE") {
        return Ok(Zeroizing::new(p));
    }
    if let Ok(p) = std::env::var("LUKSBOX_PASSPHRASE") {
        return Ok(Zeroizing::new(p));
    }
    loop {
        let a = Zeroizing::new(rpassword::prompt_password(prompt)?);
        let b = Zeroizing::new(rpassword::prompt_password("confirm: ")?);
        if *a != *b {
            eprintln!("passphrases do not match, try again");
            continue;
        }
        // Empty-passphrase confirm: explicit, defaults to "no" so an
        // accidental double-Enter does not produce a credential-less
        // vault. Skipped in test/script mode (LUKSBOX_TEST_FAST_KDF
        // or LUKSBOX_ACCEPT_EMPTY) since automation may set it on
        // purpose.
        if !test_fast_kdf_enabled()
            && a.is_empty()
            && std::env::var_os("LUKSBOX_ACCEPT_EMPTY").is_none()
        {
            eprintln!(
                "warning: the passphrase is EMPTY. ANYONE with this vault file \
                 will be able to open it."
            );
            let proceed = dialoguer::Confirm::new()
                .with_prompt("Use the empty passphrase anyway?")
                .default(false)
                .interact()
                .unwrap_or(false);
            if !proceed {
                continue;
            }
        }
        // Strength check. Skip in test mode (`LUKSBOX_TEST_FAST_KDF` is set
        // for tests with weak Argon2 params; same env signal stands for
        // "I'm in tests, skip nag prompts"). Release builds always run
        // the strength check - see `test_fast_kdf_enabled`.
        if !test_fast_kdf_enabled() && !a.is_empty() {
            let strength = passphrase::estimate(&a);
            if strength.score < passphrase::MIN_ACCEPTABLE_SCORE {
                eprintln!(
                    "warning: weak passphrase (zxcvbn score {}/4, ~{:.0} bits estimated){}",
                    strength.score,
                    strength.bits,
                    strength
                        .feedback
                        .map(|f| format!("\n  hint: {f}"))
                        .unwrap_or_default(),
                );
                eprintln!(
                    "  Argon2id stretches the passphrase substantially, but a stronger\n\
                     passphrase still helps if your vault file is ever exposed.\n\
                     Tip: run `luksbox genpass` for a 20-char random passphrase (99 bits)."
                );
                let proceed = std::env::var_os("LUKSBOX_ACCEPT_WEAK").is_some()
                    || dialoguer::Confirm::new()
                        .with_prompt("Use this passphrase anyway?")
                        .default(false)
                        .interact()
                        .unwrap_or(false);
                if !proceed {
                    continue;
                }
            }
        }
        return Ok(a);
    }
}

/// Read a FIDO2 PIN. Honors `LUKSBOX_FIDO2_PIN` for scripting/tests.
#[cfg(feature = "hardware")]
fn read_fido2_pin() -> io::Result<Zeroizing<String>> {
    if let Ok(p) = std::env::var("LUKSBOX_FIDO2_PIN") {
        return Ok(Zeroizing::new(p));
    }
    Ok(Zeroizing::new(rpassword::prompt_password("FIDO2 PIN: ")?))
}

fn open_container_passphrase(path: &Path, header_path: Option<&Path>) -> Result<Container> {
    let pw = read_passphrase("passphrase: ")?;
    Ok(Container::open(
        path,
        header_path,
        UnlockMaterial::Passphrase(pw.as_bytes()),
    )?)
}

fn open_container(path: &Path, unlock: &UnlockArgs) -> Result<Container> {
    if let Some(kp) = unlock.pq_hybrid.as_deref() {
        // Decide between hybrid-passphrase / hybrid-fido2 / hybrid-tpm2 /
        // hybrid-tpm2-fido2 by peeking at the header's slot kinds.
        // The 768/1024 distinction is handled inside each unlock
        // helper via the sidecar's level byte. Routing precedence
        // when multiple hybrid kinds coexist:
        //   --tpm2-fido2 > hybrid-pq-tpm2-fido2
        //   --tpm2       > hybrid-pq-tpm2
        //   --fido2      > hybrid-pq-fido2
        //   default      > hybrid-pq-passphrase
        let header_src = unlock.header.as_deref().unwrap_or(path);
        let mut f = File::open(header_src)?;
        let mut buf = [0u8; HEADER_SIZE];
        f.read_exact(&mut buf)?;
        drop(f);
        let header = Header::from_bytes(&buf)?;
        let has_fido_hybrid = header.keyslots.iter().any(|s| s.kind.is_hybrid_pq_fido2());
        let has_pp_hybrid = header
            .keyslots
            .iter()
            .any(|s| s.kind.is_hybrid_pq_passphrase());
        let has_tpm_hybrid = header
            .keyslots
            .iter()
            .any(|s| s.kind == SlotKind::HybridPqKemTpm2);
        let has_tpm_fido_hybrid = header
            .keyslots
            .iter()
            .any(|s| s.kind == SlotKind::HybridPqKemTpm2Fido2);

        if unlock.tpm2_fido2 && has_tpm_fido_hybrid {
            open_container_hybrid_pq_tpm2_fido2(path, unlock.header.as_deref(), kp)
        } else if unlock.tpm2 && has_tpm_hybrid {
            open_container_hybrid_pq_tpm2(path, unlock.header.as_deref(), kp)
        } else if has_tpm_fido_hybrid && !has_fido_hybrid && !has_pp_hybrid && !has_tpm_hybrid {
            open_container_hybrid_pq_tpm2_fido2(path, unlock.header.as_deref(), kp)
        } else if has_tpm_hybrid && !has_fido_hybrid && !has_pp_hybrid {
            open_container_hybrid_pq_tpm2(path, unlock.header.as_deref(), kp)
        } else if has_fido_hybrid && (unlock.fido2 || !has_pp_hybrid) {
            open_container_hybrid_pq_fido2(path, unlock.header.as_deref(), kp)
        } else if has_pp_hybrid {
            open_container_hybrid_pq(path, unlock.header.as_deref(), kp)
        } else {
            Err("--pq-hybrid given but the vault has no hybrid keyslot".into())
        }
    } else if unlock.tpm2_fido2 {
        open_container_tpm2_fido2(path, unlock.header.as_deref())
    } else if unlock.tpm2 {
        open_container_tpm2(path, unlock.header.as_deref())
    } else if unlock.fido2 {
        open_container_fido2(path, unlock.header.as_deref())
    } else {
        open_container_passphrase(path, unlock.header.as_deref())
    }
}

/// Hybrid FIDO2 + ML-KEM-768 unlock. Reads the .hybrid sidecar, reads
/// the .kyber seed file (decrypts under the user-supplied seed-file
/// passphrase), then for each FIDO2-hybrid slot does an hmac-secret
/// touch with that slot's cred_id + hmac_salt, decapsulates, and tries
/// the unlock.
#[cfg(feature = "hardware")]
fn open_container_hybrid_pq_fido2(
    path: &Path,
    header_path: Option<&Path>,
    kyber_path: &Path,
) -> Result<Container> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID};
    use luksbox_format::hybrid_sidecar;
    use luksbox_pq::seed_file;

    let header_src = header_path.unwrap_or(path);
    let mut f = File::open(header_src)?;
    let mut header_bytes = [0u8; HEADER_SIZE];
    f.read_exact(&mut header_bytes)?;
    drop(f);
    let header = Header::from_bytes(&header_bytes)?;

    let pin = read_fido2_pin()?;
    let seed_pw = read_passphrase(".kyber seed-file passphrase: ")?;
    let seed = seed_file::read(kyber_path, seed_pw.as_bytes())
        .map_err(|e| format!("read kyber seed: {e}"))?;

    let sidecar_path = hybrid_sidecar::sidecar_path(path);
    let bundle = hybrid_sidecar::read_bundle(&sidecar_path)
        .map_err(|e| format!("read hybrid sidecar at {}: {e}", sidecar_path.display()))?;
    // v3 binding check: detect cross-vault sidecar swap BEFORE
    // decap+AEAD. v1/v2 sidecars (no binding) skip the check
    // (verify_binding returns Ok). v3 sidecars with mismatching salt
    // surface a clear "wrong vault" error here.
    hybrid_sidecar::verify_binding(&bundle, &header.header_salt)
        .map_err(|e| format!("hybrid sidecar binding mismatch: {e}"))?;
    let entries = bundle.entries;

    let mut auth = make_fido2_authenticator();
    let mut last_err: Option<String> = None;
    for (slot_idx_usize, slot) in header.keyslots.iter().enumerate() {
        if !slot.kind.is_hybrid_pq_fido2() {
            continue;
        }
        let slot_idx = slot_idx_usize as u8;
        let entry = match hybrid_sidecar::find(&entries, slot_idx) {
            Some(e) => e,
            None => {
                last_err = Some(format!("no hybrid sidecar entry for slot {slot_idx}"));
                continue;
            }
        };
        eprintln!("{}", auth_prompt(&format!("unlock (slot {slot_idx})")));
        let hmac_secret = match auth.hmac_secret(
            RP_ID,
            &slot.fido2_cred_id,
            &slot.fido2_hmac_salt,
            Some(&pin),
        ) {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(format!("FIDO2: {e}"));
                continue;
            }
        };
        let pq_shared = match luksbox_pq::decapsulate_with(entry.level, &seed, &entry.ciphertext) {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(format!("decap slot {slot_idx} ({:?}): {e}", entry.level));
                continue;
            }
        };
        match Container::open(
            path,
            header_path,
            UnlockMaterial::HybridPqFido2 {
                passphrase: None,
                cred_id: &slot.fido2_cred_id,
                hmac_secret: &hmac_secret,
                pq_shared: &pq_shared,
            },
        ) {
            Ok(c) => return Ok(c),
            Err(e) => last_err = Some(format!("open slot {slot_idx}: {e}")),
        }
    }
    Err(last_err
        .unwrap_or_else(|| "no FIDO2-hybrid keyslot in this vault".into())
        .into())
}

#[cfg(not(feature = "hardware"))]
fn open_container_hybrid_pq_fido2(
    _path: &Path,
    _header_path: Option<&Path>,
    _kyber_path: &Path,
) -> Result<Container> {
    Err("FIDO2 hardware support not compiled in (rebuild with --features hardware)".into())
}

/// Hybrid passphrase + ML-KEM-768 unlock. Reads `<vault>.hybrid` (which
/// holds the public Kyber blobs for each hybrid slot), reads the user's
/// `.kyber` seed file (decrypts it under the same passphrase), runs
/// `decapsulate` to reproduce the shared secret, and passes both the
/// passphrase and shared secret to `Container::open`.
fn open_container_hybrid_pq(
    path: &Path,
    header_path: Option<&Path>,
    kyber_path: &Path,
) -> Result<Container> {
    use luksbox_format::hybrid_sidecar;
    use luksbox_pq::seed_file;

    let pw = read_passphrase("passphrase: ")?;
    let seed =
        seed_file::read(kyber_path, pw.as_bytes()).map_err(|e| format!("read kyber seed: {e}"))?;
    let sidecar_path = hybrid_sidecar::sidecar_path(path);
    // `read_for_vault` verifies the v3 vault-binding (if present)
    // against the .lbx's `header_salt`, catching cross-vault sidecar
    // swaps before decap. v1/v2 sidecars pass through; downstream
    // AEAD still catches tampering there.
    let entries = hybrid_sidecar::read_for_vault(&sidecar_path, path, header_path)
        .map_err(|e| format!("read hybrid sidecar at {}: {e}", sidecar_path.display()))?;
    if entries.is_empty() {
        return Err("hybrid sidecar exists but contains no entries".into());
    }
    // Try every hybrid entry until one decapsulates + unlocks. Slots
    // are typically just slot 0; the loop stays cheap and matches the
    // constant-time-ish iteration the format crate does internally.
    let mut last_err: Option<String> = None;
    for entry in &entries {
        // Use the entry's level (1 = ML-KEM-768, 2 = ML-KEM-1024) to
        // pick the right decapsulation; v1 sidecars come back from
        // `read` with level = Ml768 by default.
        let shared = match luksbox_pq::decapsulate_with(entry.level, &seed, &entry.ciphertext) {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(format!(
                    "decap slot {} ({:?}): {e}",
                    entry.slot_idx, entry.level
                ));
                continue;
            }
        };
        match Container::open(
            path,
            header_path,
            UnlockMaterial::HybridPqPassphrase {
                passphrase: pw.as_bytes(),
                pq_shared: &shared,
            },
        ) {
            Ok(c) => return Ok(c),
            Err(e) => last_err = Some(format!("open hybrid slot {}: {e}", entry.slot_idx)),
        }
    }
    Err(last_err
        .unwrap_or_else(|| "hybrid unlock failed (no entries succeeded)".into())
        .into())
}

fn open_vfs(path: &Path, unlock: &UnlockArgs) -> Result<Vfs> {
    let mut cont = open_container(path, unlock)?;
    let trusted_anchor_gen = if let Some(ap) = unlock.anchor.as_deref() {
        cont.set_anchor(Some(ap.to_path_buf()))?
    } else {
        None
    };
    let vfs = Vfs::open(cont)?;
    if let Some(anchor_gen) = trusted_anchor_gen {
        use luksbox_format::anchor;
        match anchor::compare(anchor_gen, vfs.vault_generation()) {
            anchor::VerificationOutcome::Ok => {}
            anchor::VerificationOutcome::RollbackDetected {
                anchor_gen,
                metadata_gen,
            } => {
                return Err(format!(
                    "ROLLBACK DETECTED: anchor reports vault generation {anchor_gen}, \
                     but the metadata in this .lbx is at generation {metadata_gen} (older). \
                     Someone may have substituted an old copy of the vault file. \
                     Refusing to open. If this is intentional (e.g. you restored from backup), \
                     re-create the anchor."
                )
                .into());
            }
            anchor::VerificationOutcome::AnchorStale {
                anchor_gen,
                metadata_gen,
            } => {
                eprintln!(
                    "warning: anchor is at generation {anchor_gen}, vault metadata is at {metadata_gen}. \
                     The vault has been written without the anchor in place. \
                     The next write will refresh the anchor."
                );
            }
        }
    }
    Ok(vfs)
}

#[cfg(feature = "hardware")]
fn open_container_fido2(path: &Path, header_path: Option<&Path>) -> Result<Container> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID};

    // Read header (from sidecar if --header given, else from vault file).
    let header_src = header_path.unwrap_or(path);
    let mut f = File::open(header_src)?;
    let mut header_bytes = [0u8; HEADER_SIZE];
    f.read_exact(&mut header_bytes)?;
    drop(f);
    let header = Header::from_bytes(&header_bytes)?;

    let pin = read_fido2_pin()?;
    let mut auth = make_fido2_authenticator();

    let mut last_err: Option<Box<dyn StdError>> = None;
    let mut tried = 0usize;
    for slot in &header.keyslots {
        if slot.kind != SlotKind::Fido2HmacSecret {
            continue;
        }
        tried += 1;
        eprintln!(
            "{}",
            auth_prompt(&format!(
                "unlock (slot cred_id len {} B)",
                slot.fido2_cred_id.len()
            ))
        );
        let hmac_secret = match auth.hmac_secret(
            RP_ID,
            &slot.fido2_cred_id,
            &slot.fido2_hmac_salt,
            Some(&pin),
        ) {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(format!("FIDO2: {e}").into());
                continue;
            }
        };
        match Container::open(
            path,
            header_path,
            UnlockMaterial::Fido2 {
                passphrase: None,
                cred_id: &slot.fido2_cred_id,
                hmac_secret: &hmac_secret,
            },
        ) {
            Ok(c) => return Ok(c),
            Err(e) => last_err = Some(e.into()),
        }
    }
    if tried == 0 {
        return Err("no FIDO2 keyslots in this container".into());
    }
    Err(last_err.unwrap_or_else(|| "FIDO2 unlock failed".into()))
}

#[cfg(not(feature = "hardware"))]
fn open_container_fido2(_path: &Path, _header_path: Option<&Path>) -> Result<Container> {
    Err("FIDO2 hardware support not compiled in (rebuild with --features hardware)".into())
}

/// Open a vault by asking the local TPM 2.0 to unseal each
/// `Tpm2Sealed` keyslot's blob until one matches. The closure
/// passed into `UnlockMaterial::Tpm2` parses the slot's stored
/// SealedBlob bytes via `luksbox_tpm::SealedBlob::from_bytes`,
/// hands them to a single shared `Tpm2Sealer` (so we only open
/// `/dev/tpmrm0` once per unlock attempt), and returns the
/// recovered KEK. First slot whose KEK successfully unwraps the
/// MVK wins.
///
/// `luksbox-format` itself iterates the slots and tolerates
/// per-slot closure errors (so a vault enrolled on multiple
/// machines works even when only one TPM responds).
#[cfg(feature = "hardware")]
fn open_container_tpm2(path: &Path, header_path: Option<&Path>) -> Result<Container> {
    use luksbox_tpm::{SealedBlob, Tpm2Sealer};

    // Pre-scan the header to detect "no TPM slots" before we do
    // the (potentially slow) TPM open. Same pattern as the FIDO2
    // helper above.
    let header_src = header_path.unwrap_or(path);
    let mut f = File::open(header_src)?;
    let mut header_bytes = [0u8; HEADER_SIZE];
    f.read_exact(&mut header_bytes)?;
    drop(f);
    let header = Header::from_bytes(&header_bytes)?;
    let has_pin_slot = header
        .keyslots
        .iter()
        .any(|s| s.kind == SlotKind::Tpm2SealedPin);
    let has_plain_slot = header
        .keyslots
        .iter()
        .any(|s| s.kind == SlotKind::Tpm2Sealed);
    if !has_plain_slot && !has_pin_slot {
        return Err(
            "vault has no TPM 2.0 keyslot (plain or PIN-protected); enroll one \
             first with `luksbox enroll <vault> --kind tpm2[-pin]`, or unlock \
             via passphrase / FIDO2 instead."
                .into(),
        );
    }
    // Prompt for PIN once if any PIN-protected slot is present.
    // Stored as bytes for the closure's use; wiped on scope exit.
    let pin: Option<zeroize::Zeroizing<String>> = if has_pin_slot {
        Some(read_passphrase("TPM PIN: ")?)
    } else {
        None
    };
    // Wrap the byte-form copy too: `Zeroizing<String>::as_bytes().to_vec()`
    // would otherwise leave a plain `Vec<u8>` of the PIN on the heap until
    // the allocator reuses the slot. The closure below holds this value
    // for the lifetime of the unlock attempt.
    let pin_bytes: Option<zeroize::Zeroizing<Vec<u8>>> = pin
        .as_ref()
        .map(|p| zeroize::Zeroizing::new(p.as_bytes().to_vec()));

    let mut sealer = Tpm2Sealer::new().map_err(|e| {
        // The new Day-7 device-open diagnostic in luksbox-tpm
        // already produces a multi-line actionable message; pass
        // it through unchanged.
        format!("{e}")
    })?;

    // The closure tries no-PIN unseal first (works for plain
    // Tpm2Sealed slots and is fast). On auth failure for PIN-bound
    // slots, retry with the PIN. format's try_unlock tolerates
    // per-slot closure errors so the wrong path failing for one
    // slot doesn't prevent another slot from succeeding.
    let mut unseal = move |blob: &[u8]| -> std::result::Result<[u8; 32], String> {
        let parsed = SealedBlob::from_bytes(blob)
            .map_err(|e| format!("malformed TPM SealedBlob in keyslot: {e}"))?;
        let result = sealer.unseal(&parsed);
        let kek = match result {
            Ok(k) => k,
            Err(_) if pin_bytes.is_some() => sealer
                .unseal_with_pin(&parsed, pin_bytes.as_ref().map(|z| z.as_slice()))
                .map_err(|e| {
                    let s = e.to_string();
                    match luksbox_tpm::diagnose_operation_error(&s) {
                        Some(hint) => format!("TPM unseal (with PIN): {s}\n\n{hint}"),
                        None => format!("TPM unseal (with PIN): {s}"),
                    }
                })?,
            Err(e) => {
                let s = e.to_string();
                return Err(match luksbox_tpm::diagnose_operation_error(&s) {
                    Some(hint) => format!("TPM unseal: {s}\n\n{hint}"),
                    None => format!("TPM unseal: {s}"),
                });
            }
        };
        let mut out = [0u8; 32];
        out.copy_from_slice(kek.as_slice());
        Ok(out)
    };

    Container::open(
        path,
        header_path,
        UnlockMaterial::Tpm2 {
            unseal: &mut unseal,
        },
    )
    .map_err(Into::into)
}

#[cfg(not(feature = "hardware"))]
fn open_container_tpm2(_path: &Path, _header_path: Option<&Path>) -> Result<Container> {
    Err(
        "TPM 2.0 hardware support not compiled in (rebuild with --features hardware). \
         On Linux you also need `libtss2-dev` (Debian/Ubuntu) or `tpm2-tss-devel` \
         (Fedora) at build time."
            .into(),
    )
}

/// Open a vault sealed with a fused TPM + FIDO2 keyslot. Iterates
/// the vault's `Tpm2Fido2` slots, tries each one whose stored
/// cred_id matches a connected FIDO2 authenticator, and asks both
/// the TPM (per slot blob) and the authenticator (touch + PIN) to
/// produce their halves. Both halves combined derive the KEK.
#[cfg(feature = "hardware")]
fn open_container_tpm2_fido2(path: &Path, header_path: Option<&Path>) -> Result<Container> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID};
    use luksbox_tpm::{SealedBlob, Tpm2Sealer};

    // Pre-scan header for any Tpm2Fido2 slot before doing TPM /
    // FIDO2 setup work.
    let header_src = header_path.unwrap_or(path);
    let mut f = File::open(header_src)?;
    let mut header_bytes = [0u8; HEADER_SIZE];
    f.read_exact(&mut header_bytes)?;
    drop(f);
    let header = Header::from_bytes(&header_bytes)?;
    if !header
        .keyslots
        .iter()
        .any(|s| s.kind == SlotKind::Tpm2Fido2)
    {
        return Err("vault has no Tpm2Fido2 keyslot; enroll one with \
             `luksbox enroll <vault> --kind tpm2-fido2`, or unlock via \
             passphrase / --fido2 / --tpm2 instead."
            .into());
    }

    // Open the TPM context once.
    let mut sealer = Tpm2Sealer::new().map_err(|e| {
        // The new Day-7 device-open diagnostic in luksbox-tpm
        // already produces a multi-line actionable message; pass
        // it through unchanged.
        format!("{e}")
    })?;

    // Try each Tpm2Fido2 slot in order: register against the
    // authenticator using the slot's own cred_id + hmac_salt, then
    // hand both halves to UnlockMaterial::Tpm2Fido2 for the unwrap.
    let pin = read_fido2_pin()?;
    let mut auth = make_fido2_authenticator();
    let mut last_err: Option<Box<dyn StdError>> = None;
    for slot in &header.keyslots {
        if slot.kind != SlotKind::Tpm2Fido2 {
            continue;
        }
        let stored_cred = match slot.tpm2_fido2_cred_id() {
            Some(c) => c.to_vec(),
            None => continue,
        };
        eprintln!(
            "{}",
            auth_prompt(&format!(
                "fused TPM+FIDO2 unlock (slot cred_id len {} B)",
                stored_cred.len()
            ))
        );
        let hmac_secret =
            match auth.hmac_secret(RP_ID, &stored_cred, &slot.fido2_hmac_salt, Some(&pin)) {
                Ok(s) => s,
                Err(e) => {
                    last_err = Some(format!("FIDO2: {e}").into());
                    continue;
                }
            };

        // The closure captures `sealer` mutably to call unseal()
        // for whichever slot blob format::try_unlock hands it.
        let mut unseal = |blob: &[u8]| -> std::result::Result<[u8; 32], String> {
            let parsed = SealedBlob::from_bytes(blob)
                .map_err(|e| format!("malformed TPM SealedBlob in keyslot: {e}"))?;
            let kek = sealer.unseal(&parsed).map_err(|e| {
                // Append a hint when we recognise the failure mode
                // (lockout, not-initialized, stale handle).
                let s = e.to_string();
                match luksbox_tpm::diagnose_operation_error(&s) {
                    Some(hint) => format!("TPM unseal: {s}\n\n{hint}"),
                    None => format!("TPM unseal: {s}"),
                }
            })?;
            let mut out = [0u8; 32];
            out.copy_from_slice(kek.as_slice());
            Ok(out)
        };

        match Container::open(
            path,
            header_path,
            UnlockMaterial::Tpm2Fido2 {
                unseal: &mut unseal,
                cred_id: &stored_cred,
                hmac_secret: &hmac_secret,
            },
        ) {
            Ok(c) => return Ok(c),
            Err(e) => last_err = Some(e.into()),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        "no Tpm2Fido2 slot matched the connected authenticator + local TPM".into()
    }))
}

#[cfg(not(feature = "hardware"))]
fn open_container_tpm2_fido2(_path: &Path, _header_path: Option<&Path>) -> Result<Container> {
    Err(
        "TPM 2.0 + FIDO2 fused unlock requires --features hardware (libtss2-dev + libfido2-dev)."
            .into(),
    )
}

/// Hybrid TPM 2.0 + ML-KEM-768 unlock. Reads the .hybrid sidecar
/// + the .kyber seed file (decrypts under user-supplied passphrase),
/// then for each HybridPqKemTpm2 slot decapsulates the Kyber
/// ciphertext to obtain `pq_shared` and asks the TPM to unseal the
/// stored blob; both halves go into UnlockMaterial::HybridPqTpm2.
#[cfg(feature = "hardware")]
fn open_container_hybrid_pq_tpm2(
    path: &Path,
    header_path: Option<&Path>,
    kyber_path: &Path,
) -> Result<Container> {
    use luksbox_format::hybrid_sidecar;
    use luksbox_pq::seed_file;
    use luksbox_tpm::{SealedBlob, Tpm2Sealer};

    let header_src = header_path.unwrap_or(path);
    let mut f = File::open(header_src)?;
    let mut header_bytes = [0u8; HEADER_SIZE];
    f.read_exact(&mut header_bytes)?;
    drop(f);
    let header = Header::from_bytes(&header_bytes)?;

    let seed_pw = read_passphrase(".kyber seed-file passphrase: ")?;
    let seed = seed_file::read(kyber_path, seed_pw.as_bytes())
        .map_err(|e| format!("read kyber seed: {e}"))?;
    let sidecar_path = hybrid_sidecar::sidecar_path(path);
    // v3 vault-binding verification (see `read_for_vault` doc).
    let entries = hybrid_sidecar::read_for_vault(&sidecar_path, path, header_path)
        .map_err(|e| format!("read hybrid sidecar at {}: {e}", sidecar_path.display()))?;

    let mut sealer = Tpm2Sealer::new().map_err(|e| format!("{e}"))?;
    let mut last_err: Option<String> = None;
    for (slot_idx_usize, slot) in header.keyslots.iter().enumerate() {
        if slot.kind != SlotKind::HybridPqKemTpm2 {
            continue;
        }
        let slot_idx = slot_idx_usize as u8;
        let entry = match hybrid_sidecar::find(&entries, slot_idx) {
            Some(e) => e,
            None => {
                last_err = Some(format!("no hybrid sidecar entry for slot {slot_idx}"));
                continue;
            }
        };
        let pq_shared = match luksbox_pq::decapsulate_with(entry.level, &seed, &entry.ciphertext) {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(format!("decap slot {slot_idx}: {e}"));
                continue;
            }
        };
        // Per-slot closure: TPM unseal of THIS slot's blob.
        let mut unseal = |blob: &[u8]| -> std::result::Result<[u8; 32], String> {
            let parsed = SealedBlob::from_bytes(blob)
                .map_err(|e| format!("malformed TPM SealedBlob: {e}"))?;
            let kek = sealer.unseal(&parsed).map_err(|e| {
                let s = e.to_string();
                match luksbox_tpm::diagnose_operation_error(&s) {
                    Some(hint) => format!("TPM unseal: {s}\n\n{hint}"),
                    None => format!("TPM unseal: {s}"),
                }
            })?;
            let mut out = [0u8; 32];
            out.copy_from_slice(kek.as_slice());
            Ok(out)
        };
        match Container::open(
            path,
            header_path,
            UnlockMaterial::HybridPqTpm2 {
                unseal: &mut unseal,
                pq_shared: &pq_shared,
            },
        ) {
            Ok(c) => return Ok(c),
            Err(e) => last_err = Some(format!("open slot {slot_idx}: {e}")),
        }
    }
    Err(last_err
        .unwrap_or_else(|| "no hybrid-pq-tpm2 keyslot in this vault".into())
        .into())
}

#[cfg(not(feature = "hardware"))]
fn open_container_hybrid_pq_tpm2(
    _path: &Path,
    _header_path: Option<&Path>,
    _kyber_path: &Path,
) -> Result<Container> {
    Err("hybrid-pq-tpm2 unlock requires --features hardware.".into())
}

/// Hybrid TPM 2.0 + FIDO2 + ML-KEM-768 unlock. Three-factor flow.
#[cfg(feature = "hardware")]
fn open_container_hybrid_pq_tpm2_fido2(
    path: &Path,
    header_path: Option<&Path>,
    kyber_path: &Path,
) -> Result<Container> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID};
    use luksbox_format::hybrid_sidecar;
    use luksbox_pq::seed_file;
    use luksbox_tpm::{SealedBlob, Tpm2Sealer};

    let header_src = header_path.unwrap_or(path);
    let mut f = File::open(header_src)?;
    let mut header_bytes = [0u8; HEADER_SIZE];
    f.read_exact(&mut header_bytes)?;
    drop(f);
    let header = Header::from_bytes(&header_bytes)?;

    let pin = read_fido2_pin()?;
    let seed_pw = read_passphrase(".kyber seed-file passphrase: ")?;
    let seed = seed_file::read(kyber_path, seed_pw.as_bytes())
        .map_err(|e| format!("read kyber seed: {e}"))?;
    let sidecar_path = hybrid_sidecar::sidecar_path(path);
    // v3 vault-binding verification (see `read_for_vault` doc).
    let entries = hybrid_sidecar::read_for_vault(&sidecar_path, path, header_path)
        .map_err(|e| format!("read hybrid sidecar at {}: {e}", sidecar_path.display()))?;

    let mut sealer = Tpm2Sealer::new().map_err(|e| format!("{e}"))?;
    let mut auth = make_fido2_authenticator();
    let mut last_err: Option<String> = None;
    for (slot_idx_usize, slot) in header.keyslots.iter().enumerate() {
        if slot.kind != SlotKind::HybridPqKemTpm2Fido2 {
            continue;
        }
        let slot_idx = slot_idx_usize as u8;
        let stored_cred = match slot.tpm2_fido2_cred_id() {
            Some(c) => c.to_vec(),
            None => continue,
        };
        let entry = match hybrid_sidecar::find(&entries, slot_idx) {
            Some(e) => e,
            None => {
                last_err = Some(format!("no hybrid sidecar entry for slot {slot_idx}"));
                continue;
            }
        };
        eprintln!(
            "{}",
            auth_prompt(&format!("3-factor unlock (slot {slot_idx})"))
        );
        let hmac_secret =
            match auth.hmac_secret(RP_ID, &stored_cred, &slot.fido2_hmac_salt, Some(&pin)) {
                Ok(s) => s,
                Err(e) => {
                    last_err = Some(format!("FIDO2: {e}"));
                    continue;
                }
            };
        let pq_shared = match luksbox_pq::decapsulate_with(entry.level, &seed, &entry.ciphertext) {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(format!("decap slot {slot_idx}: {e}"));
                continue;
            }
        };
        let mut unseal = |blob: &[u8]| -> std::result::Result<[u8; 32], String> {
            let parsed = SealedBlob::from_bytes(blob)
                .map_err(|e| format!("malformed TPM SealedBlob: {e}"))?;
            let kek = sealer.unseal(&parsed).map_err(|e| {
                let s = e.to_string();
                match luksbox_tpm::diagnose_operation_error(&s) {
                    Some(hint) => format!("TPM unseal: {s}\n\n{hint}"),
                    None => format!("TPM unseal: {s}"),
                }
            })?;
            let mut out = [0u8; 32];
            out.copy_from_slice(kek.as_slice());
            Ok(out)
        };
        match Container::open(
            path,
            header_path,
            UnlockMaterial::HybridPqTpm2Fido2 {
                unseal: &mut unseal,
                cred_id: &stored_cred,
                hmac_secret: &hmac_secret,
                pq_shared: &pq_shared,
            },
        ) {
            Ok(c) => return Ok(c),
            Err(e) => last_err = Some(format!("open slot {slot_idx}: {e}")),
        }
    }
    Err(last_err
        .unwrap_or_else(|| "no hybrid-pq-tpm2-fido2 keyslot in this vault".into())
        .into())
}

#[cfg(not(feature = "hardware"))]
fn open_container_hybrid_pq_tpm2_fido2(
    _path: &Path,
    _header_path: Option<&Path>,
    _kyber_path: &Path,
) -> Result<Container> {
    Err("hybrid-pq-tpm2-fido2 unlock requires --features hardware.".into())
}

/// Resolve "/a/b/c" -> (file_id of "a/b", "c").
pub(crate) fn split_parent_name(vfs: &Vfs, path: &str) -> Result<(FileId, String)> {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return Err("empty inner path".into());
    }
    let (parent_path, name) = match trimmed.rfind('/') {
        Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
        None => ("", trimmed),
    };
    let parent_id = vfs.lookup_path(parent_path)?;
    Ok((parent_id, name.to_string()))
}

pub(crate) fn copy_into(vfs: &mut Vfs, file_id: FileId, src: &mut impl Read) -> Result<u64> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut offset = 0u64;
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            break;
        }
        vfs.write(file_id, offset, &buf[..n])?;
        offset += n as u64;
    }
    Ok(offset)
}

pub(crate) fn copy_out(vfs: &mut Vfs, file_id: FileId, dst: &mut impl Write) -> Result<u64> {
    let size = vfs.stat(file_id)?.size;
    let mut buf = vec![0u8; 64 * 1024];
    let mut offset = 0u64;
    while offset < size {
        let n = vfs.read(file_id, offset, &mut buf)?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n])?;
        offset += n as u64;
    }
    Ok(offset)
}

// ----- commands --------------------------------------------------------------

fn cmd_create(
    path: &Path,
    cipher: &str,
    kind: SlotKindArg,
    header_path: Option<&Path>,
    pad_files: bool,
    hide_sizes: bool,
    anchor_path: Option<PathBuf>,
    pq_hybrid_path: Option<PathBuf>,
    kdf_p: Argon2idParams,
    metadata_size_override: Option<u64>,
    format: VaultFormatArg,
) -> Result<()> {
    let suite = parse_cipher(cipher)?;
    if path.exists() {
        return Err(format!("{} already exists", path.display()).into());
    }
    // Install the metadata-region-size override (if any) for the lifetime
    // of this create. The guard restores the previous value (None) on
    // drop, so a panic between here and the create_with_* call below
    // can't leak the override to a subsequent unrelated create on this
    // thread.
    let _meta_guard = luksbox_format::metadata::set_create_metadata_region_size_override(
        metadata_size_override,
    );
    // Install the v3-metadata-format override for the same lifetime.
    // The Vfs reads this thread-local on first open of the freshly-
    // created vault and locks in the format choice by writing the
    // matching LBM2 / LBM3 magic on first flush.
    let _format_guard = luksbox_vfs::set_format_v3_override(Some(matches!(
        format,
        VaultFormatArg::V3
    )));
    if let Some(hp) = header_path {
        if hp.exists() {
            return Err(format!("header file {} already exists", hp.display()).into());
        }
    }
    let want_pad = pad_files || hide_sizes;
    if (want_pad || hide_sizes) && kind == SlotKindArg::Fido2Direct {
        return Err(
            "--pad-files / --hide-sizes are not yet supported with --kind fido2-direct".into(),
        );
    }
    if let Some(ap) = &anchor_path {
        if ap.exists() {
            return Err(format!("anchor file {} already exists", ap.display()).into());
        }
    }
    let needs_pq_hybrid = matches!(
        kind,
        SlotKindArg::HybridPq
            | SlotKindArg::HybridPqFido2
            | SlotKindArg::HybridPq1024
            | SlotKindArg::HybridPq1024Fido2,
    );
    if needs_pq_hybrid && pq_hybrid_path.is_none() {
        return Err(format!(
            "--kind {} requires --pq-hybrid <path-to-write-the-secret-kyber-file>",
            match kind {
                SlotKindArg::HybridPq => "hybrid-pq",
                SlotKindArg::HybridPqFido2 => "hybrid-pq-fido2",
                SlotKindArg::HybridPq1024 => "hybrid-pq-1024",
                SlotKindArg::HybridPq1024Fido2 => "hybrid-pq-1024-fido2",
                _ => unreachable!(),
            }
        )
        .into());
    }
    if !needs_pq_hybrid && pq_hybrid_path.is_some() {
        return Err(
            "--pq-hybrid is only meaningful with one of the --kind hybrid-pq* variants".into(),
        );
    }
    if let Some(kp) = &pq_hybrid_path {
        if kp.exists() {
            return Err(format!("kyber secret file {} already exists", kp.display()).into());
        }
    }
    let mut flags: u32 = 0;
    if want_pad {
        flags |= luksbox_core::FLAG_PAD_FILES_POW2;
    }
    if hide_sizes {
        flags |= luksbox_core::FLAG_HIDE_SIZE_HEADER;
    }
    // kdf_p is now passed in directly (round 9G: caller may have
    // calibrated via --kdf-target-time, or resolved from --kdf preset).
    let mut cont: Container = match kind {
        SlotKindArg::Passphrase => {
            let pw = read_passphrase_confirmed("passphrase: ")?;
            Container::create_with_passphrase_flags(
                path,
                header_path,
                suite,
                kdf_p,
                flags,
                pw.as_bytes(),
            )?
        }
        SlotKindArg::Fido2 => create_fido2(path, header_path, suite, flags, kdf_p)?,
        SlotKindArg::Fido2Direct => create_fido2_direct(path, header_path, suite)?,
        SlotKindArg::Tpm2 => {
            // TPM-only as the FIRST slot doesn't work: we'd need
            // an MVK to seal under, but the MVK is generated by
            // create_with_*. Force the user through the natural
            // workflow: create with passphrase / FIDO2, then
            // `luksbox enroll <vault> --kind tpm2` to add a TPM
            // slot alongside it. That also gives them the
            // recovery slot they almost certainly want anyway
            // (a TPM-only vault is unrecoverable if the chip dies).
            return Err(
                "tpm2 keyslots cannot be the first slot at create time. Create the \
                 vault with --kind passphrase (or fido2), then run `luksbox enroll \
                 <vault> --kind tpm2` to add a TPM-bound slot. Keeping the original \
                 passphrase / FIDO2 slot also gives you a recovery path if the TPM \
                 chip ever fails or the machine is replaced."
                    .into(),
            );
        }
        SlotKindArg::Tpm2Fido2
        | SlotKindArg::Tpm2Pin
        | SlotKindArg::HybridPqTpm2
        | SlotKindArg::HybridPqTpm2Fido2
        | SlotKindArg::HybridPqTpm21024
        | SlotKindArg::HybridPqTpm2Fido21024 => {
            return Err(
                "TPM-bound keyslots cannot be the first slot at create time. \
                 Create the vault with --kind passphrase (or fido2), then add \
                 the TPM-bound slot via `luksbox enroll <vault> --kind <tpm-kind>`. \
                 Keep the original slot as a recovery path - TPM slots die \
                 permanently if either the chip OR (for hybrid kinds) the \
                 authenticator / PIN / Kyber seed is lost."
                    .into(),
            );
        }
        SlotKindArg::HybridPq => create_hybrid_pq_with_params(
            path,
            header_path,
            suite,
            flags,
            pq_hybrid_path.as_ref().unwrap(),
            luksbox_pq::PqParams::Ml768,
            kdf_p,
        )?,
        SlotKindArg::HybridPqFido2 => create_hybrid_pq_fido2_with_params(
            path,
            header_path,
            suite,
            flags,
            pq_hybrid_path.as_ref().unwrap(),
            luksbox_pq::PqParams::Ml768,
            kdf_p,
        )?,
        SlotKindArg::HybridPq1024 => create_hybrid_pq_with_params(
            path,
            header_path,
            suite,
            flags,
            pq_hybrid_path.as_ref().unwrap(),
            luksbox_pq::PqParams::Ml1024,
            kdf_p,
        )?,
        SlotKindArg::HybridPq1024Fido2 => create_hybrid_pq_fido2_with_params(
            path,
            header_path,
            suite,
            flags,
            pq_hybrid_path.as_ref().unwrap(),
            luksbox_pq::PqParams::Ml1024,
            kdf_p,
        )?,
    };
    if let Some(ap) = anchor_path {
        // Bootstrap anchor at gen=1 (the default `next_chunk_gen` for a
        // fresh DirectoryTree). Subsequent vfs writes will bump it.
        cont.init_anchor(ap.clone(), 1)?;
        eprintln!("  anchor file initialized at {}", ap.display());
    }
    if let Some(hp) = header_path {
        println!(
            "created {} + detached header at {}",
            path.display(),
            hp.display()
        );
        eprintln!("  KEEP THE HEADER FILE SAFE, without it the vault is unrecoverable.");
    } else {
        println!("created {}", path.display());
    }
    if let Some(kp) = &pq_hybrid_path {
        eprintln!(
            "  Kyber seed written to {}\n  KEEP THIS FILE ON SEPARATE TRUSTED STORAGE.\n  \
             Without it (or with a wrong passphrase against it) the vault is unrecoverable.",
            kp.display()
        );
        eprintln!(
            "  hybrid sidecar (public Kyber blobs) written next to the vault: {}",
            luksbox_format::hybrid_sidecar::sidecar_path(path).display()
        );
    }
    Ok(())
}

/// Hybrid passphrase + ML-KEM-768 keyslot creator. Generates a Kyber
/// keypair, encapsulates against its public key to obtain a 32-byte
/// shared secret, builds the keyslot under HKDF(Argon2id(pass) || shared),
/// writes the public Kyber blobs to the `<vault>.hybrid` sidecar and
/// the secret seed to the user-specified `.kyber` file (encrypted under
/// the same passphrase as defence-in-depth).
fn create_hybrid_pq_with_params(
    path: &Path,
    header_path: Option<&Path>,
    suite: CipherSuite,
    flags: u32,
    kyber_path: &Path,
    params: luksbox_pq::PqParams,
    kdf_p: Argon2idParams,
) -> Result<Container> {
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};

    let level_label = match params {
        PqParams::Ml768 => "ML-KEM-768",
        PqParams::Ml1024 => "ML-KEM-1024",
    };
    eprintln!(
        "WARNING: hybrid-pq vault. The MVK is wrapped under \
         HKDF(Argon2id(passphrase) || {} shared secret). Both\n  \
         the passphrase AND the secret Kyber seed are required to open.\n  \
         The seed will be written to {} (also passphrase-encrypted).\n  \
         Move it to separate trusted storage (USB stick, offline machine).\n  \
         Lose the seed file = lose the vault.",
        level_label,
        kyber_path.display()
    );
    let pw = read_passphrase_confirmed("passphrase: ")?;
    let (pk, seed) = keygen_with(params);
    let (ct, shared) =
        encapsulate_with(params, &pk).map_err(|e| format!("ML-KEM encapsulate: {e}"))?;

    let cont = match params {
        PqParams::Ml768 => Container::create_with_hybrid_pq_passphrase(
            path,
            header_path,
            suite,
            kdf_p,
            flags,
            pw.as_bytes(),
            &shared,
        )?,
        PqParams::Ml1024 => Container::create_with_hybrid_pq_1024_passphrase(
            path,
            header_path,
            suite,
            kdf_p,
            flags,
            pw.as_bytes(),
            &shared,
        )?,
    };

    let sidecar = hybrid_sidecar::sidecar_path(path);
    // v3 binding: write the vault's header_salt into the sidecar so a
    // future open can detect cross-vault sidecar swaps at parse time.
    hybrid_sidecar::write_with_binding(
        &sidecar,
        &[HybridEntry {
            slot_idx: 0,
            level: params,
            pubkey: pk,
            ciphertext: ct,
        }],
        cont.header_salt(),
    )
    .map_err(|e| format!("write hybrid sidecar: {e}"))?;

    seed_file::write(
        kyber_path,
        &seed,
        pw.as_bytes(),
        seed_file::KdfParams::default(),
    )
    .map_err(|e| format!("write kyber seed: {e}"))?;

    Ok(cont)
}

/// Hybrid FIDO2 + ML-KEM-768 keyslot creator. Uses the YubiKey's
/// hmac-secret AND a Kyber decapsulation as the two halves of the KEK.
/// Asks the user for a passphrase that protects the .kyber seed file
/// at rest (defence in depth, this passphrase is NOT a luksbox unlock
/// factor by itself; the actual unlock is YubiKey + .kyber + this
/// passphrase together).
#[cfg(feature = "hardware")]
#[cfg(feature = "hardware")]
fn create_hybrid_pq_fido2_with_params(
    path: &Path,
    header_path: Option<&Path>,
    suite: CipherSuite,
    flags: u32,
    kyber_path: &Path,
    params: luksbox_pq::PqParams,
    kdf_p: Argon2idParams,
) -> Result<Container> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};
    use rand_core::{OsRng, RngCore};

    let level_label = match params {
        PqParams::Ml768 => "ML-KEM-768",
        PqParams::Ml1024 => "ML-KEM-1024",
    };
    eprintln!(
        "WARNING: hybrid FIDO2 + {} vault. The MVK wraps under \
         HKDF(Argon2id-of(passphrase || hmac_secret) || Kyber-shared).\n  \
         Unlock requires: FIDO2 authenticator + the .kyber seed at {} + the seed-file\n  \
         passphrase. The .kyber file should live on separate trusted\n  \
         storage from the .lbx, that's the whole post-quantum point.\n  \
         Lose the authenticator OR the seed file = lose the vault.",
        level_label,
        kyber_path.display()
    );
    let pin = read_fido2_pin()?;
    eprintln!("Now choose a passphrase that encrypts the .kyber seed file at rest:");
    let seed_pw = read_passphrase_confirmed("seed-file passphrase: ")?;

    let mut auth = make_fido2_authenticator();
    let user_handle = random_user_handle()?;
    eprintln!("{}", auth_prompt("register a new credential"));
    let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
    let cred_id = er.credential.id;
    let mut hmac_salt = [0u8; 32];
    OsRng.fill_bytes(&mut hmac_salt);
    eprintln!("{}", auth_prompt("again to derive the keyslot secret"));
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(&pin))?;

    let (pk, kyber_seed) = keygen_with(params);
    let (ct, shared) =
        encapsulate_with(params, &pk).map_err(|e| format!("ML-KEM encapsulate: {e}"))?;

    let cont = match params {
        PqParams::Ml768 => Container::create_with_hybrid_pq_fido2(
            path,
            header_path,
            suite,
            kdf_p,
            flags,
            None,
            &hmac_secret,
            &shared,
            &cred_id,
            hmac_salt,
        )?,
        PqParams::Ml1024 => Container::create_with_hybrid_pq_1024_fido2(
            path,
            header_path,
            suite,
            kdf_p,
            flags,
            None,
            &hmac_secret,
            &shared,
            &cred_id,
            hmac_salt,
        )?,
    };

    let sidecar = hybrid_sidecar::sidecar_path(path);
    hybrid_sidecar::write_with_binding(
        &sidecar,
        &[HybridEntry {
            slot_idx: 0,
            level: params,
            pubkey: pk,
            ciphertext: ct,
        }],
        cont.header_salt(),
    )
    .map_err(|e| format!("write hybrid sidecar: {e}"))?;

    seed_file::write(
        kyber_path,
        &kyber_seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    )
    .map_err(|e| format!("write kyber seed: {e}"))?;

    Ok(cont)
}

#[cfg(not(feature = "hardware"))]
fn create_hybrid_pq_fido2_with_params(
    _path: &Path,
    _header_path: Option<&Path>,
    _suite: CipherSuite,
    _flags: u32,
    _kyber_path: &Path,
    _params: luksbox_pq::PqParams,
    _kdf_p: Argon2idParams,
) -> Result<Container> {
    Err("FIDO2 hardware support not compiled in (rebuild with --features hardware)".into())
}

#[cfg(feature = "hardware")]
fn create_fido2(
    path: &Path,
    header_path: Option<&Path>,
    suite: CipherSuite,
    flags: u32,
    kdf_p: Argon2idParams,
) -> Result<Container> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use rand_core::{OsRng, RngCore};

    eprintln!(
        "WARNING: creating a FIDO2-only vault. If you lose access to this\n  authenticator or wipe its FIDO2 app, you will lose access to the vault\n  permanently. Enroll a backup keyslot via `luksbox enroll <path> --kind\n  passphrase --fido2` (or with another authenticator) before storing real data."
    );
    let pin = read_fido2_pin()?;
    let mut auth = make_fido2_authenticator();
    let user_handle = random_user_handle()?;

    eprintln!("{}", auth_prompt("register a new credential"));
    let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
    let cred_id = er.credential.id;

    let mut hmac_salt = [0u8; 32];
    OsRng.fill_bytes(&mut hmac_salt);

    eprintln!("{}", auth_prompt("again to derive the keyslot secret"));
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(&pin))?;

    let cont = Container::create_with_fido2_flags(
        path,
        header_path,
        suite,
        kdf_p,
        flags,
        None,
        &hmac_secret,
        &cred_id,
        hmac_salt,
    )?;
    Ok(cont)
}

#[cfg(not(feature = "hardware"))]
fn create_fido2(
    _path: &Path,
    _header_path: Option<&Path>,
    _suite: CipherSuite,
    _flags: u32,
    _kdf_p: Argon2idParams,
) -> Result<Container> {
    Err("FIDO2 hardware support not compiled in (rebuild with --features hardware)".into())
}

#[cfg(feature = "hardware")]
fn create_fido2_direct(
    path: &Path,
    header_path: Option<&Path>,
    suite: CipherSuite,
) -> Result<Container> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use rand_core::{OsRng, RngCore};

    eprintln!(
        "WARNING: creating a FIDO2-direct vault. The MVK is DERIVED from the\n  \
         YubiKey's hmac-secret output, so there's no wrapped MVK in the vault\n  \
         to brute-force. The cost: this authenticator is the ONLY thing that can\n  \
         derive the MVK, losing it or wiping its FIDO2 app makes the vault\n  \
         unrecoverable, and you cannot enroll a backup at the MVK layer (a\n  \
         backup authenticator would derive a different MVK). You can still add\n  \
         wrap-style backup keyslots later via `luksbox enroll <path> --kind\n  \
         passphrase --fido2` or `--kind fido2 --fido2`."
    );
    let pin = read_fido2_pin()?;
    let mut auth = make_fido2_authenticator();
    let user_handle = random_user_handle()?;

    eprintln!("{}", auth_prompt("register a new credential"));
    let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
    let cred_id = er.credential.id;

    let mut hmac_salt = [0u8; 32];
    OsRng.fill_bytes(&mut hmac_salt);

    eprintln!("{}", auth_prompt("again to derive the keyslot secret"));
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(&pin))?;

    let cont = Container::create_with_fido2_derived_mvk(
        path,
        header_path,
        suite,
        &cred_id,
        &hmac_secret,
        hmac_salt,
    )?;
    Ok(cont)
}

#[cfg(not(feature = "hardware"))]
fn create_fido2_direct(
    _path: &Path,
    _header_path: Option<&Path>,
    _suite: CipherSuite,
) -> Result<Container> {
    Err("FIDO2 hardware support not compiled in (rebuild with --features hardware)".into())
}

fn cmd_info(path: &Path) -> Result<()> {
    let mut f = File::open(path)?;
    let mut buf = [0u8; HEADER_SIZE];
    f.read_exact(&mut buf)?;
    let h = Header::from_bytes(&buf)?;
    println!("container: {}", path.display());
    println!("  cipher:        {:?}", h.cipher_suite);
    println!("  chunk size:    {} bytes", h.chunk_size);
    println!(
        "  metadata:      {} bytes at offset {}",
        h.metadata_size, h.metadata_offset
    );
    println!("  data area:     starts at offset {}", h.data_offset);
    println!("keyslots:");
    for (i, s) in h.keyslots.iter().enumerate() {
        match s.kind {
            SlotKind::Empty => println!("  {i}: empty"),
            SlotKind::Passphrase => println!(
                "  {i}: passphrase  (Argon2id m={} KiB t={} p={})",
                s.kdf_params.m_cost_kib, s.kdf_params.t_cost, s.kdf_params.p_cost
            ),
            SlotKind::Fido2HmacSecret => {
                let hex_prefix: String = s
                    .fido2_cred_id
                    .iter()
                    .take(8)
                    .map(|b| format!("{b:02x}"))
                    .collect();
                println!(
                    "  {i}: fido2        (cred_id={}etc.  {} B)",
                    hex_prefix,
                    s.fido2_cred_id.len()
                );
            }
            SlotKind::Fido2DerivedMvk => {
                let hex_prefix: String = s
                    .fido2_cred_id
                    .iter()
                    .take(8)
                    .map(|b| format!("{b:02x}"))
                    .collect();
                println!(
                    "  {i}: fido2-direct (cred_id={}etc.  {} B; MVK derived directly from authenticator)",
                    hex_prefix,
                    s.fido2_cred_id.len()
                );
            }
            SlotKind::HybridPqKemPassphrase => println!(
                "  {i}: hybrid-pq    (Argon2id m={} KiB t={} p={} + ML-KEM-768; \
                 needs --pq-hybrid <kyber-secret-file> to open)",
                s.kdf_params.m_cost_kib, s.kdf_params.t_cost, s.kdf_params.p_cost
            ),
            SlotKind::HybridPqKemFido2 => {
                let hex_prefix: String = s
                    .fido2_cred_id
                    .iter()
                    .take(8)
                    .map(|b| format!("{b:02x}"))
                    .collect();
                println!(
                    "  {i}: hybrid-pq-fido2 (cred_id={}etc.  {} B, FIDO2 + ML-KEM-768; \
                     needs FIDO2 authenticator + --pq-hybrid <kyber-secret-file>)",
                    hex_prefix,
                    s.fido2_cred_id.len()
                );
            }
            SlotKind::HybridPqKem1024Passphrase => println!(
                "  {i}: hybrid-pq-1024 (Argon2id m={} KiB t={} p={} + ML-KEM-1024; \
                 NIST Cat-5 / ~AES-256 strength; needs --pq-hybrid <kyber-secret-file>)",
                s.kdf_params.m_cost_kib, s.kdf_params.t_cost, s.kdf_params.p_cost
            ),
            SlotKind::HybridPqKem1024Fido2 => {
                let hex_prefix: String = s
                    .fido2_cred_id
                    .iter()
                    .take(8)
                    .map(|b| format!("{b:02x}"))
                    .collect();
                println!(
                    "  {i}: hybrid-pq-1024-fido2 (cred_id={}etc.  {} B, FIDO2 + ML-KEM-1024)",
                    hex_prefix,
                    s.fido2_cred_id.len()
                );
            }
            SlotKind::Tpm2Sealed | SlotKind::Tpm2SealedPin => {
                // For TPM slots, fido2_cred_id holds the TPM
                // SealedBlob bytes (TPM2B_PUBLIC + TPM2B_PRIVATE);
                // print the size and a short hex prefix for
                // identification, but don't try to interpret the
                // contents.
                let hex_prefix: String = s
                    .fido2_cred_id
                    .iter()
                    .take(8)
                    .map(|b| format!("{b:02x}"))
                    .collect();
                let pin_note = if s.kind == SlotKind::Tpm2SealedPin {
                    "; PIN-protected (wrong PIN counts toward TPM lockout)"
                } else {
                    "; no passphrase"
                };
                println!(
                    "  {i}: {label}        (sealed_blob={hex_prefix}etc.  {} B; \
                     unsealed by the local TPM 2.0 chip{pin_note})",
                    s.fido2_cred_id.len(),
                    label = if s.kind == SlotKind::Tpm2SealedPin {
                        "tpm2-pin"
                    } else {
                        "tpm2    "
                    },
                );
            }
            SlotKind::HybridPqKemTpm2 | SlotKind::HybridPqKem1024Tpm2 => {
                let level = if s.kind == SlotKind::HybridPqKem1024Tpm2 {
                    "ML-KEM-1024"
                } else {
                    "ML-KEM-768"
                };
                let hex_prefix: String = s
                    .fido2_cred_id
                    .iter()
                    .take(8)
                    .map(|b| format!("{b:02x}"))
                    .collect();
                println!(
                    "  {i}: hybrid-pq-tpm2 (sealed_blob={}etc.  {} B; \
                     TPM 2.0 + {level}; needs --pq-hybrid <kyber-secret>)",
                    hex_prefix,
                    s.fido2_cred_id.len()
                );
            }
            SlotKind::HybridPqKemTpm2Fido2 | SlotKind::HybridPqKem1024Tpm2Fido2 => {
                let level = if s.kind == SlotKind::HybridPqKem1024Tpm2Fido2 {
                    "ML-KEM-1024"
                } else {
                    "ML-KEM-768"
                };
                let cred_pfx: String = s
                    .tpm2_fido2_cred_id()
                    .map(|c| c.iter().take(8).map(|b| format!("{b:02x}")).collect())
                    .unwrap_or_default();
                let blob_len = s.tpm2_fido2_sealed_blob().map(|b| b.len()).unwrap_or(0);
                let cred_len = s.tpm2_fido2_cred_id().map(|c| c.len()).unwrap_or(0);
                println!(
                    "  {i}: hybrid-pq-tpm2-fido2 (cred_id={cred_pfx}etc. {cred_len} B + \
                     sealed_blob {blob_len} B; TPM + FIDO2 + {level}; needs --pq-hybrid)"
                );
            }
            SlotKind::Tpm2Fido2 => {
                // Fused: combined region holds [tpm_blob_len|blob|cred_id].
                // Show the cred_id prefix (FIDO2 identifier) and
                // the inner blob size separately.
                let cred_pfx: String = s
                    .tpm2_fido2_cred_id()
                    .map(|c| c.iter().take(8).map(|b| format!("{b:02x}")).collect())
                    .unwrap_or_default();
                let blob_len = s.tpm2_fido2_sealed_blob().map(|b| b.len()).unwrap_or(0);
                let cred_len = s.tpm2_fido2_cred_id().map(|c| c.len()).unwrap_or(0);
                println!(
                    "  {i}: tpm2-fido2   (cred_id={cred_pfx}etc. {cred_len} B + \
                     sealed_blob {blob_len} B; both factors required)"
                );
            }
        }
    }
    Ok(())
}

fn cmd_enroll_passphrase(path: &Path, unlock: &UnlockArgs) -> Result<()> {
    let mut c = open_container(path, unlock)?;
    let new_pw = read_passphrase_confirmed("new passphrase: ")?;
    let idx = c.enroll_passphrase(new_pw.as_bytes(), kdf_params())?;
    c.persist_header()?;
    println!("enrolled passphrase in slot {idx}");
    Ok(())
}

#[cfg(feature = "hardware")]
fn cmd_enroll_fido2(path: &Path, unlock: &UnlockArgs) -> Result<()> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use rand_core::{OsRng, RngCore};

    let mut c = open_container(path, unlock)?;
    let pin = read_fido2_pin()?;
    let mut auth = make_fido2_authenticator();
    let user_handle = random_user_handle()?;

    eprintln!("{}", auth_prompt("register a new credential"));
    let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
    let cred_id = er.credential.id;

    let mut hmac_salt = [0u8; 32];
    OsRng.fill_bytes(&mut hmac_salt);

    eprintln!("{}", auth_prompt("again to derive the keyslot secret"));
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(&pin))?;

    let idx = c.enroll_fido2(None, &hmac_secret, &cred_id, hmac_salt, kdf_params())?;
    c.persist_header()?;
    println!(
        "enrolled FIDO2 credential in slot {idx} (cred_id {} bytes)",
        cred_id.len()
    );
    Ok(())
}

#[cfg(not(feature = "hardware"))]
fn cmd_enroll_fido2(_path: &Path, _unlock: &UnlockArgs) -> Result<()> {
    Err("FIDO2 hardware support not compiled in (rebuild with --features hardware)".into())
}

/// Enroll a fresh TPM-sealed keyslot. The user already had to
/// provide some other unlock material (passphrase / FIDO2) to open
/// the container; this command then:
///   1. Generates a random 32-byte KEK.
///   2. Asks the local TPM 2.0 to seal the KEK under a transient
///      Storage Root Key (deterministic per chip; no NV space
///      consumed).
///   3. Stores the resulting (TPM2B_PUBLIC, TPM2B_PRIVATE) blob in
///      a new keyslot, with the MVK wrapped under the same KEK.
///
/// After this, `luksbox open <vault> --tpm2` (or any other
/// subcommand with `--tpm2`) unlocks the vault on this machine
/// without a passphrase. The vault file alone is uncrackable
/// without the original chip.
#[cfg(feature = "hardware")]
fn cmd_enroll_tpm2(path: &Path, unlock: &UnlockArgs) -> Result<()> {
    use luksbox_tpm::Tpm2Sealer;
    use rand_core::{OsRng, RngCore};
    use zeroize::Zeroizing;

    let mut c = open_container(path, unlock)?;

    // Open the TPM context BEFORE generating the KEK, so a chip-
    // not-available error surfaces before we produce secret
    // material that needs wiping.
    let mut sealer = Tpm2Sealer::new().map_err(|e| {
        // The new Day-7 device-open diagnostic in luksbox-tpm
        // already produces a multi-line actionable message; pass
        // it through unchanged.
        format!("{e}")
    })?;

    let mut kek = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(kek.as_mut_slice())
        .map_err(|e| format!("OS RNG failure generating TPM KEK: {e}"))?;

    eprintln!("sealing KEK under the local TPM 2.0...");
    let blob = sealer.seal(&kek).map_err(|e| {
        let s = e.to_string();
        match luksbox_tpm::diagnose_operation_error(&s) {
            Some(hint) => format!("TPM seal: {s}\n\n{hint}"),
            None => format!("TPM seal: {s}"),
        }
    })?;
    let blob_bytes = blob.to_bytes();

    let idx = c.enroll_tpm2(&kek, &blob_bytes)?;
    c.persist_header()?;
    println!(
        "enrolled TPM 2.0 keyslot in slot {idx} (sealed_blob {} bytes). \
         Subsequent unlocks: `luksbox <subcommand> --tpm2 {}`.",
        blob_bytes.len(),
        path.display(),
    );
    // `kek` drops + zeroizes here automatically.
    Ok(())
}

#[cfg(not(feature = "hardware"))]
fn cmd_enroll_tpm2(_path: &Path, _unlock: &UnlockArgs) -> Result<()> {
    Err(
        "TPM 2.0 hardware support not compiled in (rebuild with --features hardware). \
         On Linux you also need `libtss2-dev` (Debian/Ubuntu) or `tpm2-tss-devel` \
         (Fedora) at build time."
            .into(),
    )
}

/// Enroll a fused TPM + FIDO2 keyslot. Both factors required at
/// every subsequent unlock, so this is the strongest single-slot
/// kind LUKSbox supports, but loss of either the TPM (machine) or
/// the FIDO2 authenticator permanently kills the slot. Pair with a
/// recovery slot (passphrase / FIDO2-only / TPM-only) unless you
/// accept the unrecoverable trade-off.
#[cfg(feature = "hardware")]
fn cmd_enroll_tpm2_fido2(path: &Path, unlock: &UnlockArgs) -> Result<()> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_tpm::Tpm2Sealer;
    use rand_core::{OsRng, RngCore};
    use zeroize::Zeroizing;

    let mut c = open_container(path, unlock)?;

    // Open both subsystems BEFORE generating any secret material,
    // so missing-hardware errors surface up-front.
    let mut sealer = Tpm2Sealer::new().map_err(|e| {
        // The new Day-7 device-open diagnostic in luksbox-tpm
        // already produces a multi-line actionable message; pass
        // it through unchanged.
        format!("{e}")
    })?;
    let pin = read_fido2_pin()?;
    let mut auth = make_fido2_authenticator();
    let user_handle = random_user_handle()?;

    // FIDO2 enroll: register a fresh credential so this slot has
    // its own cred_id (not shared with any other FIDO2 slot).
    eprintln!("{}", auth_prompt("register a new FIDO2 credential"));
    let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
    let cred_id = er.credential.id;

    // The TPM-side secret we're going to seal: 32 random bytes.
    // NOT the same as the FIDO2 hmac_secret, this is the TPM's
    // half of the fused KEK.
    let mut tpm_unsealed = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(tpm_unsealed.as_mut_slice())
        .map_err(|e| format!("OS RNG: {e}"))?;
    eprintln!("sealing TPM half under the local TPM 2.0...");
    let blob = sealer.seal(&tpm_unsealed).map_err(|e| {
        let s = e.to_string();
        match luksbox_tpm::diagnose_operation_error(&s) {
            Some(hint) => format!("TPM seal: {s}\n\n{hint}"),
            None => format!("TPM seal: {s}"),
        }
    })?;

    // FIDO2 hmac_secret half: pick a random salt, ask the
    // authenticator for the hmac-secret output for that salt.
    let mut hmac_salt = [0u8; 32];
    OsRng.fill_bytes(&mut hmac_salt);
    eprintln!("{}", auth_prompt("touch again to derive the FIDO2 half"));
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(&pin))?;

    let blob_bytes = blob.to_bytes();
    let idx = c.enroll_tpm2_fido2(
        &tpm_unsealed,
        &hmac_secret,
        &blob_bytes,
        &cred_id,
        hmac_salt,
    )?;
    c.persist_header()?;
    println!(
        "enrolled fused TPM+FIDO2 keyslot in slot {idx} \
         (cred_id {} B + sealed_blob {} B). \
         Subsequent unlocks: `luksbox <subcommand> --tpm2-fido2 {}`.",
        cred_id.len(),
        blob_bytes.len(),
        path.display(),
    );
    Ok(())
}

#[cfg(not(feature = "hardware"))]
fn cmd_enroll_tpm2_fido2(_path: &Path, _unlock: &UnlockArgs) -> Result<()> {
    Err(
        "TPM 2.0 + FIDO2 fused enroll requires --features hardware (libtss2-dev + libfido2-dev)."
            .into(),
    )
}

/// Enroll a PIN-protected TPM 2.0 keyslot. Same shape as
/// `cmd_enroll_tpm2` but seals via `Tpm2Sealer::seal_with_pin` so
/// the chip refuses to unseal without the matching PIN at every
/// future unlock.
#[cfg(feature = "hardware")]
fn cmd_enroll_tpm2_pin(path: &Path, unlock: &UnlockArgs) -> Result<()> {
    use luksbox_tpm::Tpm2Sealer;
    use rand_core::{OsRng, RngCore};
    use zeroize::Zeroizing;

    let mut c = open_container(path, unlock)?;
    let mut sealer = Tpm2Sealer::new().map_err(|e| format!("{e}"))?;

    // Prompt for the PIN with confirmation - typo on enroll would
    // permanently lock the user out of the slot otherwise.
    eprintln!(
        "TPM PIN: any string up to 64 bytes. Wrong PINs count toward the chip's \
         dictionary-attack lockout, so even short PINs (4-6 digits) are secure."
    );
    let pin = read_passphrase_confirmed("TPM PIN: ")?;
    if pin.is_empty() {
        return Err("PIN cannot be empty (use --kind tpm2 for the no-PIN variant)".into());
    }

    let mut kek = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(kek.as_mut_slice())
        .map_err(|e| format!("OS RNG: {e}"))?;
    eprintln!("sealing KEK under the local TPM 2.0 with PIN-binding...");
    let blob = sealer
        .seal_with_pin(&kek, Some(pin.as_bytes()))
        .map_err(|e| format!("TPM seal: {e}"))?;
    let blob_bytes = blob.to_bytes();

    let idx = c.enroll_tpm2_pin(&kek, &blob_bytes)?;
    c.persist_header()?;
    println!(
        "enrolled PIN-protected TPM 2.0 keyslot in slot {idx}. Subsequent unlocks: \
         `luksbox <subcommand> --tpm2 {}` (you'll be prompted for the PIN).",
        path.display(),
    );
    Ok(())
}

#[cfg(not(feature = "hardware"))]
fn cmd_enroll_tpm2_pin(_path: &Path, _unlock: &UnlockArgs) -> Result<()> {
    Err("TPM 2.0 + PIN enroll requires --features hardware (libtss2-dev).".into())
}

/// Enroll a hybrid TPM 2.0 + ML-KEM keyslot. `kem_size` is 768 or
/// 1024 (the latter is NIST Cat-5 / ~AES-256 PQ strength). Combines
/// the existing hybrid-PQ pattern (Kyber keypair + .hybrid sidecar
/// entry + .kyber seed file at rest) with a fresh TPM seal of the
/// wrap-side half of the KEK. Requires `--pq-hybrid <kyber-secret-path>`
/// to know where to write the seed.
#[cfg(feature = "hardware")]
fn cmd_enroll_hybrid_pq_tpm2(path: &Path, unlock: &UnlockArgs, kem_size: u16) -> Result<()> {
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};
    use luksbox_tpm::Tpm2Sealer;
    use rand_core::{OsRng, RngCore};
    use zeroize::Zeroizing;

    let params = match kem_size {
        768 => PqParams::Ml768,
        1024 => PqParams::Ml1024,
        _ => return Err(format!("unsupported ML-KEM size {kem_size} (use 768 or 1024)").into()),
    };
    let level_label = match params {
        PqParams::Ml768 => "ML-KEM-768",
        PqParams::Ml1024 => "ML-KEM-1024",
    };

    let kyber_path = unlock.pq_hybrid.as_deref().ok_or(
        "hybrid-pq-tpm2 enroll requires --pq-hybrid <path-to-write-kyber-seed>; \
         this is the file you'll need on subsequent unlocks (keep it on \
         separate trusted storage like a USB stick)",
    )?;

    // For the bootstrap open we strip --pq-hybrid so open_container
    // doesn't try to route through a hybrid-PQ unlock helper. The
    // user opens via whatever other unlock material they provided
    // (passphrase / FIDO2 / TPM); --pq-hybrid here means "where to
    // WRITE the new seed", not "what seed to read for unlock".
    let mut bootstrap_unlock = unlock.clone();
    bootstrap_unlock.pq_hybrid = None;
    let mut c = open_container(path, &bootstrap_unlock)?;

    let mut sealer = Tpm2Sealer::new().map_err(|e| format!("{e}"))?;
    let seed_pw = read_passphrase_confirmed(".kyber seed-file passphrase: ")?;

    // TPM half: random KEK + seal.
    let mut tpm_kek = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(tpm_kek.as_mut_slice())
        .map_err(|e| format!("OS RNG: {e}"))?;
    eprintln!("sealing TPM half under the local TPM 2.0...");
    let blob = sealer
        .seal(&tpm_kek)
        .map_err(|e| format!("TPM seal: {e}"))?;
    let blob_bytes = blob.to_bytes();

    // ML-KEM half: keygen + encapsulate against the chosen parameter set.
    let (pk, seed) = keygen_with(params);
    let (ct, pq_shared) =
        encapsulate_with(params, &pk).map_err(|e| format!("ML-KEM encapsulate: {e}"))?;

    let idx = match params {
        PqParams::Ml768 => c.enroll_hybrid_pq_tpm2(&tpm_kek, &pq_shared, &blob_bytes)?,
        PqParams::Ml1024 => c.enroll_hybrid_pq_1024_tpm2(&tpm_kek, &pq_shared, &blob_bytes)?,
    };

    // Atomic-enroll ordering: install slot in memory FIRST (already
    // done above), write sidecar + .kyber, then persist the header.
    // On any failure roll back so the on-disk vault is unchanged.
    let sidecar = hybrid_sidecar::sidecar_path(path);
    let mut entries = if sidecar.exists() {
        match hybrid_sidecar::read(&sidecar) {
            Ok(e) => e,
            Err(e) => {
                let _ = c.revoke_slot(idx);
                return Err(format!("read existing hybrid sidecar: {e}").into());
            }
        }
    } else {
        Vec::new()
    };
    entries.push(HybridEntry {
        slot_idx: idx as u8,
        level: params,
        pubkey: pk,
        ciphertext: ct,
    });
    if let Err(e) = hybrid_sidecar::write(&sidecar, &entries) {
        let _ = c.revoke_slot(idx);
        return Err(format!("write hybrid sidecar: {e}").into());
    }

    if let Err(e) = seed_file::write(
        kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    ) {
        let _ = c.revoke_slot(idx);
        entries.pop();
        if entries.is_empty() {
            let _ = std::fs::remove_file(&sidecar);
        } else {
            let _ = hybrid_sidecar::write(&sidecar, &entries);
        }
        return Err(format!("write kyber seed: {e}").into());
    }

    if let Err(e) = c.persist_header() {
        let _ = c.revoke_slot(idx);
        entries.pop();
        if entries.is_empty() {
            let _ = std::fs::remove_file(&sidecar);
        } else {
            let _ = hybrid_sidecar::write(&sidecar, &entries);
        }
        let _ = std::fs::remove_file(kyber_path);
        return Err(format!("persist header: {e}").into());
    }

    println!(
        "enrolled hybrid TPM 2.0 + {level_label} keyslot in slot {idx}.\n  \
         Kyber seed written to {} (passphrase-encrypted).\n  \
         Move the seed file to separate trusted storage (USB stick, \
         offline machine) - lose it = lose this slot.\n  \
         Subsequent unlocks: `luksbox <subcommand> --tpm2 --pq-hybrid {} {}`",
        kyber_path.display(),
        kyber_path.display(),
        path.display(),
    );
    Ok(())
}

#[cfg(not(feature = "hardware"))]
fn cmd_enroll_hybrid_pq_tpm2(_path: &Path, _unlock: &UnlockArgs, _kem_size: u16) -> Result<()> {
    Err("hybrid-pq-tpm2 enroll requires --features hardware (libtss2-dev).".into())
}

/// Enroll the maximum-paranoia hybrid TPM 2.0 + FIDO2 + ML-KEM
/// keyslot. `kem_size` is 768 or 1024. Three independent factors
/// required at every unlock.
#[cfg(feature = "hardware")]
fn cmd_enroll_hybrid_pq_tpm2_fido2(path: &Path, unlock: &UnlockArgs, kem_size: u16) -> Result<()> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};
    use luksbox_tpm::Tpm2Sealer;
    use rand_core::{OsRng, RngCore};
    use zeroize::Zeroizing;

    let params = match kem_size {
        768 => PqParams::Ml768,
        1024 => PqParams::Ml1024,
        _ => return Err(format!("unsupported ML-KEM size {kem_size} (use 768 or 1024)").into()),
    };
    let level_label = match params {
        PqParams::Ml768 => "ML-KEM-768",
        PqParams::Ml1024 => "ML-KEM-1024",
    };

    let kyber_path = unlock
        .pq_hybrid
        .as_deref()
        .ok_or("hybrid-pq-tpm2-fido2 enroll requires --pq-hybrid <path-to-write-kyber-seed>")?;

    // Same bootstrap-open fix as cmd_enroll_hybrid_pq_tpm2: --pq-hybrid
    // here means "output seed path", not "input seed for opening".
    let mut bootstrap_unlock = unlock.clone();
    bootstrap_unlock.pq_hybrid = None;
    let mut c = open_container(path, &bootstrap_unlock)?;

    let mut sealer = Tpm2Sealer::new().map_err(|e| format!("{e}"))?;
    let pin = read_fido2_pin()?;
    let seed_pw = read_passphrase_confirmed(".kyber seed-file passphrase: ")?;
    let mut auth = make_fido2_authenticator();
    let user_handle = random_user_handle()?;

    eprintln!("{}", auth_prompt("register a new FIDO2 credential"));
    let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
    let cred_id = er.credential.id;

    let mut tpm_unsealed = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(tpm_unsealed.as_mut_slice())
        .map_err(|e| format!("OS RNG: {e}"))?;
    eprintln!("sealing TPM half under the local TPM 2.0...");
    let blob = sealer
        .seal(&tpm_unsealed)
        .map_err(|e| format!("TPM seal: {e}"))?;
    let blob_bytes = blob.to_bytes();

    let mut hmac_salt = [0u8; 32];
    OsRng.fill_bytes(&mut hmac_salt);
    eprintln!("{}", auth_prompt("touch again to derive the FIDO2 half"));
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(&pin))?;

    let (pk, seed) = keygen_with(params);
    let (ct, pq_shared) =
        encapsulate_with(params, &pk).map_err(|e| format!("ML-KEM encapsulate: {e}"))?;

    // Atomic-enroll ordering, same shape as cmd_enroll_hybrid_pq_tpm2.
    let idx = match params {
        PqParams::Ml768 => c.enroll_hybrid_pq_tpm2_fido2(
            &tpm_unsealed,
            &hmac_secret,
            &pq_shared,
            &blob_bytes,
            &cred_id,
            hmac_salt,
        )?,
        PqParams::Ml1024 => c.enroll_hybrid_pq_1024_tpm2_fido2(
            &tpm_unsealed,
            &hmac_secret,
            &pq_shared,
            &blob_bytes,
            &cred_id,
            hmac_salt,
        )?,
    };

    let sidecar = hybrid_sidecar::sidecar_path(path);
    let mut entries = if sidecar.exists() {
        match hybrid_sidecar::read(&sidecar) {
            Ok(e) => e,
            Err(e) => {
                let _ = c.revoke_slot(idx);
                return Err(format!("read existing hybrid sidecar: {e}").into());
            }
        }
    } else {
        Vec::new()
    };
    entries.push(HybridEntry {
        slot_idx: idx as u8,
        level: params,
        pubkey: pk,
        ciphertext: ct,
    });
    if let Err(e) = hybrid_sidecar::write(&sidecar, &entries) {
        let _ = c.revoke_slot(idx);
        return Err(format!("write hybrid sidecar: {e}").into());
    }

    if let Err(e) = seed_file::write(
        kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    ) {
        let _ = c.revoke_slot(idx);
        entries.pop();
        if entries.is_empty() {
            let _ = std::fs::remove_file(&sidecar);
        } else {
            let _ = hybrid_sidecar::write(&sidecar, &entries);
        }
        return Err(format!("write kyber seed: {e}").into());
    }

    if let Err(e) = c.persist_header() {
        let _ = c.revoke_slot(idx);
        entries.pop();
        if entries.is_empty() {
            let _ = std::fs::remove_file(&sidecar);
        } else {
            let _ = hybrid_sidecar::write(&sidecar, &entries);
        }
        let _ = std::fs::remove_file(kyber_path);
        return Err(format!("persist header: {e}").into());
    }

    println!(
        "enrolled hybrid TPM 2.0 + FIDO2 + {level_label} keyslot in slot {idx}.\n  \
         All three factors required to unlock: local TPM AND this YubiKey AND the \
         .kyber seed file. Loss of any one factor permanently kills this slot."
    );
    Ok(())
}

#[cfg(not(feature = "hardware"))]
fn cmd_enroll_hybrid_pq_tpm2_fido2(
    _path: &Path,
    _unlock: &UnlockArgs,
    _kem_size: u16,
) -> Result<()> {
    Err("hybrid-pq-tpm2-fido2 enroll requires --features hardware.".into())
}

fn cmd_revoke(path: &Path, unlock: &UnlockArgs, slot: usize) -> Result<()> {
    let mut c = open_container(path, unlock)?;
    c.revoke_slot(slot)?;
    c.persist_header()?;
    println!("revoked slot {slot}");
    Ok(())
}

fn cmd_update(
    path: &Path,
    unlock: &UnlockArgs,
    slot: usize,
    kind_override: Option<SlotKindArg>,
) -> Result<()> {
    let mut c = open_container(path, unlock)?;
    let existing = SlotKindArg::from_core(c.header.keyslots[slot].kind)
        .ok_or_else(|| format!("slot {slot} is empty; nothing to update"))?;
    let target = kind_override.unwrap_or(existing);
    match target {
        SlotKindArg::Passphrase => {
            let new_pw = read_passphrase_confirmed("new passphrase: ")?;
            c.update_passphrase_at(slot, new_pw.as_bytes(), kdf_params())?;
        }
        SlotKindArg::Fido2 => update_fido2_at(&mut c, slot)?,
        SlotKindArg::Fido2Direct => {
            return Err(
                "fido2-direct keyslots can only be installed at vault creation time \
                 (the MVK is derived from the FIDO2 authenticator rather than wrapped, so it \
                 cannot be substituted into an existing slot). Recreate the vault \
                 with `luksbox create --kind fido2-direct` if you need this mode."
                    .into(),
            );
        }
        SlotKindArg::HybridPq => {
            return Err(
                "hybrid-pq keyslots can only be installed at vault creation time \
                 (the Kyber pubkey + ciphertext live in the .lbx.hybrid sidecar, \
                 written at create). Recreate the vault with \
                 `luksbox create --kind hybrid-pq` if you need this mode."
                    .into(),
            );
        }
        SlotKindArg::HybridPqFido2 => {
            return Err(
                "hybrid-pq-fido2 keyslots can only be installed at vault creation time.".into(),
            );
        }
        SlotKindArg::HybridPq1024 | SlotKindArg::HybridPq1024Fido2 => {
            return Err(
                "hybrid-pq-1024 keyslots can only be installed at vault creation time.".into(),
            );
        }
        SlotKindArg::Tpm2 => {
            #[cfg(feature = "hardware")]
            {
                use luksbox_tpm::Tpm2Sealer;
                use rand_core::{OsRng, RngCore};
                use zeroize::Zeroizing;

                // Re-seal a fresh KEK under the local TPM, then
                // overwrite slot `slot`. Same wrap shape as
                // cmd_enroll_tpm2 above; only the install path
                // differs (update_tpm2_at instead of enroll_tpm2).
                let mut sealer = Tpm2Sealer::new()
                    .map_err(|e| format!("could not open local TPM 2.0 device: {e}"))?;
                let mut kek = Zeroizing::new([0u8; 32]);
                OsRng
                    .try_fill_bytes(kek.as_mut_slice())
                    .map_err(|e| format!("OS RNG: {e}"))?;
                eprintln!("re-sealing KEK under the local TPM 2.0...");
                let blob = sealer.seal(&kek).map_err(|e| {
                    let s = e.to_string();
                    match luksbox_tpm::diagnose_operation_error(&s) {
                        Some(hint) => format!("TPM seal: {s}\n\n{hint}"),
                        None => format!("TPM seal: {s}"),
                    }
                })?;
                c.update_tpm2_at(slot, &kek, &blob.to_bytes())?;
            }
            #[cfg(not(feature = "hardware"))]
            {
                return Err(
                    "TPM 2.0 hardware support not compiled in (rebuild with --features hardware)."
                        .into(),
                );
            }
        }
        SlotKindArg::Tpm2Fido2
        | SlotKindArg::Tpm2Pin
        | SlotKindArg::HybridPqTpm2
        | SlotKindArg::HybridPqTpm2Fido2
        | SlotKindArg::HybridPqTpm21024
        | SlotKindArg::HybridPqTpm2Fido21024 => {
            // Fused / PIN / hybrid TPM update needs to re-enroll
            // multiple components AND keep the slot index stable -
            // not yet implemented. Workaround: revoke + re-enroll
            // (gives a different index but unlocks identically).
            return Err(
                "in-place update of fused / PIN / hybrid TPM keyslots isn't \
                 supported yet. Workaround: `luksbox revoke <vault> --slot <slot>` \
                 then `luksbox enroll <vault> --kind <tpm-kind>`. The new slot \
                 will take a different index but unlocks identically."
                    .into(),
            );
        }
    }
    c.persist_header()?;
    println!("updated slot {slot} ({existing:?} -> {target:?})");
    Ok(())
}

#[cfg(feature = "hardware")]
fn update_fido2_at(c: &mut Container, slot: usize) -> Result<()> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use rand_core::{OsRng, RngCore};

    let pin = read_fido2_pin()?;
    let mut auth = make_fido2_authenticator();
    let user_handle = random_user_handle()?;

    eprintln!("{}", auth_prompt("register a new credential"));
    let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
    let cred_id = er.credential.id;

    let mut hmac_salt = [0u8; 32];
    OsRng.fill_bytes(&mut hmac_salt);

    eprintln!("{}", auth_prompt("again to derive the keyslot secret"));
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(&pin))?;

    c.update_fido2_at(slot, None, &hmac_secret, &cred_id, hmac_salt, kdf_params())?;
    Ok(())
}

#[cfg(not(feature = "hardware"))]
fn update_fido2_at(_c: &mut Container, _slot: usize) -> Result<()> {
    Err("FIDO2 hardware support not compiled in (rebuild with --features hardware)".into())
}

fn cmd_ls(path: &Path, unlock: &UnlockArgs, inner: &str) -> Result<()> {
    let mut vfs = open_vfs(path, unlock)?;
    let id = vfs.lookup_path(inner)?;
    let st = vfs.stat(id)?;
    if st.kind != InodeKind::Directory {
        return Err(format!("{inner} is not a directory").into());
    }
    let mut entries = vfs.readdir(id)?;
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    for e in entries {
        let s = vfs.stat(e.id)?;
        let kind = if e.kind == InodeKind::Directory {
            "d"
        } else {
            "-"
        };
        println!("{} {:>10} {}", kind, s.size, e.name);
    }
    Ok(())
}

fn cmd_mkdir(path: &Path, unlock: &UnlockArgs, inner: &str) -> Result<()> {
    let mut vfs = open_vfs(path, unlock)?;
    let (parent, name) = split_parent_name(&vfs, inner)?;
    vfs.mkdir(parent, &name)?;
    vfs.flush()?;
    Ok(())
}

fn cmd_put(path: &Path, unlock: &UnlockArgs, local: &Path, inner: &str) -> Result<()> {
    let mut src = File::open(local)?;
    let mut vfs = open_vfs(path, unlock)?;
    let (parent, name) = split_parent_name(&vfs, inner)?;
    if vfs.lookup(parent, &name).is_ok() {
        return Err(format!("{inner} already exists").into());
    }
    let f = vfs.create(parent, &name)?;
    let n = copy_into(&mut vfs, f, &mut src)?;
    vfs.flush()?;
    println!("wrote {n} bytes to {inner}");
    Ok(())
}

fn cmd_get(path: &Path, unlock: &UnlockArgs, inner: &str, local: &Path) -> Result<()> {
    let mut vfs = open_vfs(path, unlock)?;
    let id = vfs.lookup_path(inner)?;
    let st = vfs.stat(id)?;
    if st.kind != InodeKind::File {
        return Err(format!("{inner} is not a file").into());
    }
    // Plaintext exports are mode 0600 on Unix regardless of umask. The
    // user picked the destination; leaking decrypted contents to other
    // local accounts via the default 022 umask (-> 0644) defeats the
    // purpose of using LUKSbox in the first place.
    let mut dst = luksbox_core::file_util::secure_create_or_truncate(local)?;
    let n = copy_out(&mut vfs, id, &mut dst)?;
    println!("wrote {n} bytes to {}", local.display());
    Ok(())
}

fn cmd_cat(path: &Path, unlock: &UnlockArgs, inner: &str) -> Result<()> {
    let mut vfs = open_vfs(path, unlock)?;
    let id = vfs.lookup_path(inner)?;
    let st = vfs.stat(id)?;
    if st.kind != InodeKind::File {
        return Err(format!("{inner} is not a file").into());
    }
    let stdout = io::stdout();
    let mut h = stdout.lock();
    copy_out(&mut vfs, id, &mut h)?;
    Ok(())
}

fn cmd_rm(path: &Path, unlock: &UnlockArgs, inner: &str) -> Result<()> {
    let mut vfs = open_vfs(path, unlock)?;
    let (parent, name) = split_parent_name(&vfs, inner)?;
    vfs.unlink(parent, &name)?;
    vfs.flush()?;
    Ok(())
}

fn cmd_rmdir(path: &Path, unlock: &UnlockArgs, inner: &str) -> Result<()> {
    let mut vfs = open_vfs(path, unlock)?;
    let (parent, name) = split_parent_name(&vfs, inner)?;
    vfs.rmdir(parent, &name)?;
    vfs.flush()?;
    Ok(())
}

fn cmd_mv(path: &Path, unlock: &UnlockArgs, old: &str, new: &str) -> Result<()> {
    let mut vfs = open_vfs(path, unlock)?;
    let (old_parent, old_name) = split_parent_name(&vfs, old)?;
    let (new_parent, new_name) = split_parent_name(&vfs, new)?;
    if old_parent != new_parent {
        return Err("cross-directory rename is not supported in v1".into());
    }
    vfs.rename(old_parent, &old_name, &new_name)?;
    vfs.flush()?;
    Ok(())
}

/// FHS / system roots that must NOT be mountable. Mounting onto any
/// of these (or a child of any of these) lets attacker-controlled
/// vault contents shadow files the OS or other privileged programs
/// trust - e.g. `luksbox mount mine.lbx /etc` can replace `/etc/passwd`
/// while the vault is mounted. Closes the CVE-2025-23021 class
/// flagged by VeraCrypt 1.26.18.
///
/// `/run`, `/var`, `/tmp` are NOT denied because they hold legitimate
/// user-mountable subpaths (`/run/user/<uid>/...`, `/var/lib/...`,
/// `/tmp/...`). The user's `$HOME` is not denied for the same reason.
#[cfg(not(target_os = "windows"))]
const DENIED_MOUNTPOINT_ROOTS: &[&str] = &[
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/boot",
    "/sys",
    "/proc",
    "/dev",
    #[cfg(target_os = "macos")]
    "/System",
    #[cfg(target_os = "macos")]
    "/Library",
];

/// Reject mountpoints whose canonical path is a system directory or a
/// child of one. Caller MUST pass the path returned by
/// `Path::canonicalize` - the deny check has no defense against
/// `..`/symlink games unless the input is already resolved.
#[cfg(not(target_os = "windows"))]
fn validate_mountpoint_safety(user_supplied: &Path, canonical: &Path) -> Result<()> {
    for denied in DENIED_MOUNTPOINT_ROOTS {
        let denied_path = Path::new(denied);
        if canonical == denied_path || canonical.starts_with(denied_path) {
            return Err(format!(
                "mountpoint {} (resolves to {}) is inside the system \
                 directory {}, which is on LUKSbox's deny-list because \
                 mounting there would let vault contents shadow \
                 system-critical files. Choose a mountpoint outside \
                 {{/etc, /usr, /bin, /sbin, /lib*, /boot, /sys, /proc, \
                 /dev{}}}.",
                user_supplied.display(),
                canonical.display(),
                denied_path.display(),
                if cfg!(target_os = "macos") {
                    ", /System, /Library"
                } else {
                    ""
                },
            )
            .into());
        }
    }
    Ok(())
}

fn cmd_mount(
    path: &Path,
    unlock: &UnlockArgs,
    foreground: bool,
    mountpoint: Option<&Path>,
    private_mount: bool,
) -> Result<()> {
    // Resolve mountpoint:
    //   --private-mount + no explicit path -> derive ~/Library/LUKSbox/Mounts/<vault-name>
    //   explicit path  + no --private-mount -> use as-is
    //   neither / both -> reject (ambiguous or empty input)
    // The helper is macOS-only; on other targets `--private-mount` is
    // rejected so the user sees a clear error instead of a silent
    // behavioural difference.
    let mountpoint_owned: std::path::PathBuf = match (mountpoint, private_mount) {
        (Some(_), true) => {
            return Err(
                "`--private-mount` cannot be combined with an explicit <mountpoint>; \
                 pass exactly one"
                    .into(),
            );
        }
        (None, false) => {
            return Err("missing <mountpoint>. Either give one explicitly or pass \
                 `--private-mount` (macOS+FUSE-T only) to derive \
                 ~/Library/LUKSbox/Mounts/<vault-name>."
                .into());
        }
        (Some(p), false) => p.to_path_buf(),
        (None, true) => {
            #[cfg(target_os = "macos")]
            {
                let vault_name = path
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "vault".to_string());
                luksbox_mount::private_mountpoint_for(&vault_name)
                    .map_err(|e| format!("private mount setup failed: {e}"))?
            }
            #[cfg(not(target_os = "macos"))]
            {
                return Err("`--private-mount` is only supported on macOS".into());
            }
        }
    };
    let mountpoint: &Path = mountpoint_owned.as_path();

    // Mountpoint validation is per-OS:
    //
    // - Linux / macOS (FUSE): the mountpoint MUST exist, be a
    //   directory, and ideally be empty. FUSE mounts on top of an
    //   existing dir; trying to mount on a missing path fails at
    //   mount(2).
    //
    // - Windows (WinFsp): mountpoint is either a drive letter
    //   (`Z:`) or a path that does NOT exist; WinFsp materializes it
    //   as a reparse point at mount time. An existing path yields
    //   STATUS_OBJECT_NAME_COLLISION. So `is_dir()` returns false for
    //   any valid Windows mountpoint, and asserting it would always
    //   reject the correct input.
    //
    // The same logic applies to canonicalize(): on Linux/macOS we
    // want the absolute path so a daemonized child can find it after
    // chdir(); on Windows the path doesn't exist yet so canonicalize
    // would fail. Pass the user-supplied path through unchanged on
    // Windows.
    #[cfg(not(target_os = "windows"))]
    let mp_abs: (std::path::PathBuf, Option<(u64, u64)>) = {
        // FD-based check: open with O_DIRECTORY | O_NOFOLLOW so the
        // kernel atomically rejects both "not a directory" and "this
        // is a symlink" in one syscall. Replaces the previous
        // `is_dir()` + later `canonicalize()` pattern which had a
        // TOCTOU window where an attacker (on a writable shared dir)
        // could swap a real directory for a symlink to a sensitive
        // path between the check and the canonicalize/mount.
        //
        // The deny-list check (validate_mountpoint_safety) still runs
        // on the canonical path because FUSE's mount(2) accepts a
        // PATH not an fd: between our drop(fd) below and the kernel's
        // own path lookup at mount time the attacker could still swap
        // the entry. We document this residual race here. Bounding
        // the blast radius is the role of validate_mountpoint_safety
        // (no /etc, /usr, /Library, etc.).
        use std::os::unix::fs::OpenOptionsExt as _;
        let probe = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(mountpoint)
            .map_err(|e| {
                let kind = if e.raw_os_error() == Some(libc::ELOOP) {
                    "is a symbolic link (refused: open the underlying directory directly)"
                } else if e.raw_os_error() == Some(libc::ENOTDIR) {
                    "is not a directory"
                } else {
                    "could not be opened"
                };
                format!("mountpoint {} {kind}: {e}", mountpoint.display())
            })?;
        // Capture the inode of the probed fd so we can detect any
        // post-probe path-swap immediately before the mount syscall
        // (Round 12 fix R12-08; see "tighten residual race" below).
        use std::os::unix::fs::MetadataExt as _;
        let probe_meta = probe
            .metadata()
            .map_err(|e| format!("cannot stat mountpoint {}: {e}", mountpoint.display()))?;
        let probe_inode_pair = (probe_meta.dev(), probe_meta.ino());
        // The fd has served its check purpose; canonicalize via the
        // path now that we've confirmed at least the user-supplied
        // entry was a non-symlink directory.
        drop(probe);
        let canonical = mountpoint
            .canonicalize()
            .map_err(|e| format!("cannot resolve {}: {e}", mountpoint.display()))?;
        validate_mountpoint_safety(mountpoint, &canonical)?;
        (canonical, Some(probe_inode_pair))
    };
    #[cfg(target_os = "windows")]
    let (mp_abs, _probe_inode): (std::path::PathBuf, Option<(u64, u64)>) =
        (mountpoint.to_path_buf(), None);
    #[cfg(not(target_os = "windows"))]
    let (mp_abs, probe_inode) = mp_abs;

    let path_abs = path
        .canonicalize()
        .map_err(|e| format!("cannot resolve {}: {e}", path.display()))?;
    let vfs = open_vfs(&path_abs, unlock)?;

    // Round 12 fix R12-08: re-probe the canonical mountpoint inode
    // IMMEDIATELY before the mount syscall and refuse if it changed.
    // The deny-list bounds the blast radius to user-writable paths,
    // but this catches the narrow window where an attacker on the
    // mountpoint's parent dir renames a symlink over the canonical
    // entry between our initial probe and the kernel's mount-path
    // lookup. On Linux this is a single openat+stat; on macOS the
    // semantics match.
    #[cfg(unix)]
    if let Some(expected) = probe_inode {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
        let final_probe = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&mp_abs)
            .map_err(|e| {
                format!(
                    "mountpoint {} could not be re-verified before mount: {e}",
                    mp_abs.display()
                )
            })?;
        let m = final_probe.metadata().map_err(|e| {
            format!(
                "cannot stat mountpoint {} for re-verify: {e}",
                mp_abs.display()
            )
        })?;
        if (m.dev(), m.ino()) != expected {
            return Err(format!(
                "mountpoint {} was swapped between probe and mount; refusing",
                mp_abs.display()
            )
            .into());
        }
        drop(final_probe);
    }

    if foreground {
        eprintln!(
            "mounted {} at {} (foreground)\n  unmount: luksbox umount {}  (or Ctrl-C, clean either way)",
            path_abs.display(),
            mp_abs.display(),
            mp_abs.display(),
        );
    }
    luksbox_mount::mount(vfs, &mp_abs, !foreground)?;
    Ok(())
}

/// Subprocess-isolated FUSE-T mount entry point.
///
/// Reads exactly 32 bytes from stdin (the Master Volume Key piped
/// from the parent GUI process), reconstructs the
/// [`MasterVolumeKey`], and opens the vault via the no-derivation
/// [`Container::open_with_mvk`] path. Then builds the Vfs and runs
/// the FUSE event loop in foreground until unmount.
///
/// The parent's `spawn_mount_helper` invokes us with stdin set to
/// a pipe whose writer it controls. After writing 32 bytes, the
/// parent closes its end of the pipe, which causes our
/// `read_exact` to complete. The pipe is anonymous and only
/// accessible to this subprocess (POSIX guarantee), so the MVK
/// bytes never touch a path other process can read.
///
/// Discipline: the on-stack [u8; 32] buffer is zeroed via
/// [`Zeroize`] immediately after the [`MasterVolumeKey`] takes
/// ownership of the bytes. Brief stack exposure (microseconds)
/// is the security trade-off documented in `docs/MACOS_FUSE_T.md`.
fn cmd_mount_fuse_t_helper(vault: &Path, header: Option<&Path>, mountpoint: &Path) -> Result<()> {
    use std::io::Read;

    // Stage trace - the parent captures our stderr and surfaces the
    // last lines in its error toast when we exit non-zero. Emitting a
    // line at each stage lets us pinpoint which step failed from the
    // GUI alone, without asking the user to dig out a logfile. The
    // happy path produces a small constant amount of output (~5
    // lines), all well below the parent's 64 KiB drain cap.
    eprintln!(
        "luksbox-mount-helper: start vault={} mountpoint={} header={:?}",
        vault.display(),
        mountpoint.display(),
        header
    );

    // Ignore SIGPIPE for the entire helper process lifetime.
    //
    // libfuse-t.dylib (and its closed-source `go-nfsv4` companion)
    // writes through internal pipes/sockets during the mount session
    // and, more importantly, during teardown. When the kernel side of
    // the NFS connection drops at unmount, one of those endpoints
    // closes mid-write inside libfuse-t and the kernel delivers
    // SIGPIPE to our process. Default disposition for SIGPIPE is to
    // terminate the process - that's how `head`-piped pipelines end
    // their producer cleanly, and it's the wrong behaviour for any
    // long-running server. With SIG_IGN, the write that would have
    // generated SIGPIPE returns EPIPE instead; libfuse-t handles that
    // gracefully and the helper exits cleanly with status 0.
    //
    // Without this, the GUI sees the helper exit with "signal: 13
    // (SIGPIPE)" on every unmount and surfaces a misleading
    // "mount helper exited abnormally" toast, even though the mount
    // and unmount themselves succeeded.
    //
    // SAFETY: signal() with SIG_IGN is async-signal-safe and has no
    // preconditions. We do this BEFORE reading the MVK so that even
    // a SIGPIPE during the stdin-read path (pipe writer in parent
    // dies between spawn and our read) doesn't kill us silently.
    //
    // `cfg(unix)`: SIGPIPE doesn't exist on Windows. The helper
    // subcommand isn't reachable on Windows in practice (FUSE-T is
    // macOS-only) but we keep the cfg gate so a Windows build of
    // the CLI binary doesn't need libc.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    // Round 12 fix R12-05: mountpoint validation now uses the same
    // O_DIRECTORY|O_NOFOLLOW probe + validate_mountpoint_safety
    // deny-list as the parent `cmd_mount`. The previous version
    // (`is_dir()` -> later `canonicalize()`) re-opened the TOCTOU
    // window the parent path was hardened to close.
    #[cfg(unix)]
    let mp_abs: std::path::PathBuf = {
        use std::os::unix::fs::OpenOptionsExt as _;
        let probe = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(mountpoint)
            .map_err(|e| {
                let kind = if e.raw_os_error() == Some(libc::ELOOP) {
                    "is a symbolic link (refused: open the underlying directory directly)"
                } else if e.raw_os_error() == Some(libc::ENOTDIR) {
                    "is not a directory"
                } else {
                    "could not be opened"
                };
                format!("mountpoint {} {kind}: {e}", mountpoint.display())
            })?;
        drop(probe);
        let canonical = mountpoint
            .canonicalize()
            .map_err(|e| format!("cannot resolve {}: {e}", mountpoint.display()))?;
        validate_mountpoint_safety(mountpoint, &canonical)?;
        canonical
    };
    #[cfg(not(unix))]
    let mp_abs: std::path::PathBuf = mountpoint.to_path_buf();

    let vault_abs = vault
        .canonicalize()
        .map_err(|e| format!("cannot resolve {}: {e}", vault.display()))?;

    // Round 12 fix R12-03: canonicalize the `--header` path so the
    // helper never opens an attacker-supplied symlink. The sandbox
    // profile's `${HEADER_DIR}` subpath rule (also added in Round 12)
    // only matches when the header is inside an explicitly allow-listed
    // directory; canonicalize here ensures the path we hand to
    // `open_with_mvk` is one the sandbox would also accept.
    let header_abs: Option<std::path::PathBuf> = match header {
        Some(p) => Some(
            p.canonicalize()
                .map_err(|e| format!("cannot resolve --header {}: {e}", p.display()))?,
        ),
        None => None,
    };
    eprintln!(
        "luksbox-mount-helper: canonicalized vault={} mountpoint={} header={:?}",
        vault_abs.display(),
        mp_abs.display(),
        header_abs.as_ref().map(|p| p.display().to_string())
    );

    // Stdin handoff protocol from the parent (GUI):
    //
    //   byte 0:        protocol version
    //                    0x01 = standard format, MVK-only payload
    //                    0x02 = deniable format, MVK + state payload
    //   bytes 1..33:   MVK (32 bytes)
    //
    //   v2 deniable additionally appends:
    //     bytes 33..65:   per_vault_salt (32 bytes)
    //     bytes 65..66:   unlocked_slot_idx (u8)
    //     bytes 66..104:  serialised DeniableInnerHeader (38 bytes)
    //
    // Why v2 exists: deniable vaults have no plaintext magic and no
    // standard HMAC header — `Container::open_with_mvk` always fails
    // with "invalid magic bytes". The parent already decrypted the
    // inner header with the user's credential; the helper can't
    // re-derive it from just the MVK, so the parent hands the
    // recovered state over the pipe.
    //
    // Round 12 fix R12-12: wrap in `Zeroizing<[u8;32]>` so a partial
    // read (`?` returns early) does not leak up to 31 MVK bytes on
    // the stack.
    let mut version_byte = [0u8; 1];
    std::io::stdin()
        .read_exact(&mut version_byte)
        .map_err(|e| format!("could not read protocol version from stdin: {e}"))?;

    let mut mvk_bytes: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    std::io::stdin()
        .read_exact(&mut mvk_bytes[..])
        .map_err(|e| format!("could not read MVK from stdin: {e}"))?;
    // Round 12 fix R12-17: use `from_zeroizing` so the caller's
    // bytes are passed by reference, avoiding the by-value Copy
    // pattern that left a stack residue on `from_bytes(*mvk_bytes)`.
    let mvk = MasterVolumeKey::from_zeroizing(&mvk_bytes);
    eprintln!(
        "luksbox-mount-helper: MVK received (protocol v{}), opening container",
        version_byte[0]
    );

    let container = match version_byte[0] {
        0x01 => {
            // Standard format: HMAC verification inside open_with_mvk
            // catches a wrong MVK with HeaderAuthFailed before any
            // garbled metadata is read.
            Container::open_with_mvk(&vault_abs, header_abs.as_deref(), mvk)
                .map_err(|e| format!("open container ({}): {e}", vault_abs.display()))?
        }
        0x02 => {
            // Deniable format: read salt + slot_idx + 38-byte inner
            // header from stdin, hand them to the deniable opener.
            // Any partial read collapses to the same error wording the
            // parent will surface in its toast.
            let mut salt = [0u8; luksbox_core::deniable::DENIABLE_SALT_SIZE];
            std::io::stdin()
                .read_exact(&mut salt)
                .map_err(|e| format!("could not read per-vault salt from stdin: {e}"))?;
            let mut slot_byte = [0u8; 1];
            std::io::stdin()
                .read_exact(&mut slot_byte)
                .map_err(|e| format!("could not read slot index from stdin: {e}"))?;
            let mut inner_buf = [0u8;
                luksbox_format::deniable_header::DENIABLE_INNER_HEADER_SERIALIZED_LEN];
            std::io::stdin()
                .read_exact(&mut inner_buf)
                .map_err(|e| format!("could not read inner header from stdin: {e}"))?;
            let inner = luksbox_format::deniable_header::DeniableInnerHeader::parse_from_handoff(
                &inner_buf,
            )
            .map_err(|e| format!("inner header from parent is malformed: {e}"))?;
            Container::open_with_mvk_deniable(
                &vault_abs,
                header_abs.as_deref(),
                mvk,
                salt,
                inner,
                slot_byte[0] as usize,
            )
            .map_err(|e| format!("open deniable container ({}): {e}", vault_abs.display()))?
        }
        other => {
            return Err(format!(
                "unknown helper protocol version 0x{other:02x} from parent (expected 0x01 or 0x02)"
            )
            .into());
        }
    };
    let vfs = Vfs::open(container).map_err(|e| format!("open Vfs: {e}"))?;
    eprintln!("luksbox-mount-helper: Vfs ready, calling mount");

    // Run the FUSE event loop in foreground (no daemonize). The
    // parent process polls our exit status; daemonizing here would
    // leave the parent unable to detect mount-end.
    luksbox_mount::mount(vfs, &mp_abs, false)
        .map_err(|e| format!("mount {}: {e}", mp_abs.display()))?;
    eprintln!("luksbox-mount-helper: mount returned cleanly, exiting");
    Ok(())
}

fn cmd_umount(mountpoint: &Path) -> Result<()> {
    luksbox_mount::unmount(mountpoint)?;
    println!("OK unmounted {}", mountpoint.display());
    Ok(())
}

/// Parse a CLI --cipher value into a CipherSuite. Shared with
/// cmd_deniable_init and cmd_deniable_info so both subcommands accept
/// the same vocabulary.
fn parse_deniable_cipher(s: &str) -> Result<luksbox_core::CipherSuite> {
    use luksbox_core::CipherSuite;
    match s {
        "aes" | "aes-siv" | "aes-256-gcm-siv" => Ok(CipherSuite::Aes256GcmSiv),
        "aes-gcm" | "aes-256-gcm" => Ok(CipherSuite::Aes256Gcm),
        "chacha" | "chacha20" | "chacha20-poly1305" => Ok(CipherSuite::ChaCha20Poly1305),
        _ => Err(cli_err!(
            "unknown cipher '{}'. expected one of: aes, aes-gcm, chacha",
            s
        )),
    }
}

/// Build sane Argon2id params from CLI flags, with envelope checks
/// matching `Argon2idParams::is_sane_for_disk` so users see a clear
/// error instead of an opaque KDF failure.
fn parse_deniable_argon2(m: u32, t: u32, p: u32) -> Result<luksbox_core::Argon2idParams> {
    use luksbox_core::Argon2idParams;
    let params = Argon2idParams {
        m_cost_kib: m,
        t_cost: t,
        p_cost: p,
    };
    if !params.is_sane_for_disk() {
        return Err(cli_err!(
            "Argon2id params out of sane envelope: m_cost_kib={} (8..={}), t_cost={} (1..={}), p_cost={} (1..={})",
            params.m_cost_kib,
            Argon2idParams::SAFE_M_COST_KIB_MAX,
            params.t_cost,
            Argon2idParams::SAFE_T_COST_MAX,
            params.p_cost,
            Argon2idParams::SAFE_P_COST_MAX,
        ));
    }
    Ok(params)
}

/// Parse the user-supplied --credential string into an enum the
/// dispatch code can match on. Mirrors the wizard's
/// `DenCredKind` shape; kept as a separate enum here to avoid
/// pulling wizard.rs into the CLI dispatch path.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CliDenCred {
    Passphrase,
    Fido2,
    PqPassphrase,
    PqFido2,
    Tpm,
    TpmFido2,
    PqTpm,
    PqTpmFido2,
}

fn parse_cli_den_cred(s: &str) -> Result<CliDenCred> {
    match s {
        "passphrase" => Ok(CliDenCred::Passphrase),
        "fido2" => Ok(CliDenCred::Fido2),
        "pq-passphrase" => Ok(CliDenCred::PqPassphrase),
        "pq-fido2" => Ok(CliDenCred::PqFido2),
        "tpm" => Ok(CliDenCred::Tpm),
        "tpm-fido2" => Ok(CliDenCred::TpmFido2),
        "pq-tpm" => Ok(CliDenCred::PqTpm),
        "pq-tpm-fido2" => Ok(CliDenCred::PqTpmFido2),
        _ => Err(cli_err!(
            "unknown --credential '{}'. Choices: passphrase, fido2, pq-passphrase, pq-fido2, tpm, tpm-fido2, pq-tpm, pq-tpm-fido2",
            s
        )),
    }
}

// v1 helpers `flag_or_env` and `decode_hex_32` were removed in v2:
// FIDO2 `cred_id` and `hmac_salt` are now embedded in the slot
// envelope at create time and recovered from the envelope at unlock
// time; no CLI / env-var ingestion path remains.

fn cmd_deniable_init(
    path: &Path,
    cipher: &str,
    m: u32,
    t: u32,
    p: u32,
    credential: &str,
    kyber_path: Option<&Path>,
    pq_1024: bool,
    anchor: Option<&Path>,
) -> Result<()> {
    let cipher_suite = parse_deniable_cipher(cipher)?;
    let argon2_params = parse_deniable_argon2(m, t, p)?;
    let cred = parse_cli_den_cred(credential)?;

    if path.exists() {
        return Err(cli_err!(
            "refusing to overwrite existing file: {}",
            path.display()
        ));
    }
    if let Some(ap) = anchor {
        if ap.exists() {
            return Err(cli_err!(
                "refusing to overwrite existing anchor file: {}",
                ap.display()
            ));
        }
    }

    let mut cont: luksbox_format::Container = match cred {
        CliDenCred::Passphrase => {
            cli_create_passphrase_deniable_v2(path, cipher_suite, argon2_params)?
        }
        CliDenCred::Fido2 => {
            #[cfg(feature = "hardware")]
            {
                cli_create_fido2_deniable_v2(path, cipher_suite, argon2_params)?
            }
            #[cfg(not(feature = "hardware"))]
            return Err(cli_err!("FIDO2 hardware support not compiled in"));
        }
        CliDenCred::PqPassphrase => {
            let kp =
                kyber_path.ok_or_else(|| cli_err!("--kyber-path required for pq-passphrase"))?;
            cli_create_pq_passphrase_deniable_v2(path, cipher_suite, argon2_params, kp, pq_1024)?
        }
        CliDenCred::PqFido2 => {
            #[cfg(feature = "hardware")]
            {
                let kp =
                    kyber_path.ok_or_else(|| cli_err!("--kyber-path required for pq-fido2"))?;
                cli_create_pq_fido2_deniable_v2(path, cipher_suite, argon2_params, kp, pq_1024)?
            }
            #[cfg(not(feature = "hardware"))]
            return Err(cli_err!("FIDO2 hardware support not compiled in"));
        }
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        CliDenCred::Tpm => cli_create_tpm_deniable_v2(path, cipher_suite, argon2_params)?,
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        CliDenCred::TpmFido2 => {
            cli_create_tpm_fido2_deniable_v2(path, cipher_suite, argon2_params)?
        }
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        CliDenCred::PqTpm => {
            let kp = kyber_path.ok_or_else(|| cli_err!("--kyber-path required for pq-tpm"))?;
            cli_create_pq_tpm_deniable_v2(path, cipher_suite, argon2_params, kp, pq_1024)?
        }
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        CliDenCred::PqTpmFido2 => {
            let kp =
                kyber_path.ok_or_else(|| cli_err!("--kyber-path required for pq-tpm-fido2"))?;
            cli_create_pq_tpm_fido2_deniable_v2(path, cipher_suite, argon2_params, kp, pq_1024)?
        }
        #[cfg(not(all(feature = "hardware", target_os = "linux")))]
        CliDenCred::Tpm | CliDenCred::TpmFido2 | CliDenCred::PqTpm | CliDenCred::PqTpmFido2 => {
            return Err(cli_err!(
                "TPM is Linux-only today; Windows TPM is tracked as a follow-up"
            ));
        }
    };

    // Optional anchor bootstrap. `init_anchor` branches on is_deniable()
    // and writes the AEAD-encrypted deniable anchor (256 B, byte-wise
    // indistinguishable from random) instead of the standard plaintext-
    // magic format. Generation starts at 1 - matches the wizard/GUI
    // create path and Vfs::flush bumps from there.
    if let Some(ap) = anchor {
        cont.init_anchor(ap.to_path_buf(), 1)?;
    }
    drop(cont);

    println!("OK deniable vault created at {}", path.display());
    println!("  cipher:     {:?}", cipher_suite);
    println!("  argon2:     m={m}KiB t={t} p={p}");
    println!("  credential: {credential}");
    if let Some(ap) = anchor {
        println!(
            "  anchor:     {} (keep on separate trusted storage!)",
            ap.display()
        );
    }
    println!();
    println!("Deniable mode: cred_id / hmac_salt / TPM sealed blob are");
    println!("now embedded in the slot envelope. The passphrase + Argon2");
    println!("params above are the only things you must remember; lose");
    println!("them or the FIDO2 device / TPM chip and the vault is");
    println!("unrecoverable. ML-KEM seed (if pq-*) lives in --kyber-path.");
    Ok(())
}

fn cmd_deniable_info(
    path: &Path,
    cipher: &str,
    m: u32,
    t: u32,
    p: u32,
    credential: &str,
    kyber_path: Option<&Path>,
) -> Result<()> {
    let cipher_suite = parse_deniable_cipher(cipher)?;
    let argon2_params = parse_deniable_argon2(m, t, p)?;
    let cred = parse_cli_den_cred(credential)?;

    let container = cli_open_deniable_v2(path, cipher_suite, argon2_params, cred, kyber_path)?;
    println!("OK deniable vault opened");
    println!("  cipher suite:   {:?}", container.header.cipher_suite);
    println!("  kdf id:         {:?}", container.header.kdf);
    println!("  flags:          0x{:08x}", container.header.flags);
    println!("  metadata off:   {}", container.header.metadata_offset);
    println!("  metadata size:  {}", container.header.metadata_size);
    println!("  data offset:    {}", container.header.data_offset);
    println!("  chunk size:     {}", container.header.chunk_size);
    println!("  is deniable:    {}", container.is_deniable());
    println!("  unlocked slot:  {:?}", container.deniable_unlocked_slot());
    Ok(())
}

fn cmd_deniable_mount(
    path: &Path,
    cipher: &str,
    m: u32,
    t: u32,
    p: u32,
    credential: &str,
    kyber_path: Option<&Path>,
    foreground: bool,
    anchor: Option<&Path>,
    mountpoint: &Path,
) -> Result<()> {
    use luksbox_format::anchor as anchor_mod;
    use luksbox_vfs::Vfs;
    let cipher_suite = parse_deniable_cipher(cipher)?;
    let argon2_params = parse_deniable_argon2(m, t, p)?;
    let cred = parse_cli_den_cred(credential)?;

    #[cfg(not(target_os = "windows"))]
    let mp_abs: std::path::PathBuf = {
        if !mountpoint.is_dir() {
            return Err(cli_err!(
                "mountpoint {} is not a directory",
                mountpoint.display()
            ));
        }
        mountpoint
            .canonicalize()
            .map_err(|e| cli_err!("cannot resolve {}: {e}", mountpoint.display()))?
    };
    #[cfg(target_os = "windows")]
    let mp_abs: std::path::PathBuf = mountpoint.to_path_buf();

    let mut container = cli_open_deniable_v2(path, cipher_suite, argon2_params, cred, kyber_path)?;

    // Anchor verification. set_anchor branches on is_deniable() and
    // calls anchor::deniable_read_and_verify under the hood; any
    // failure (wrong vault, wrong MVK, truncated file, missing file)
    // collapses to Error::OpaqueUnlockFailed so deniability is not
    // leaked through differential errors. On success it returns the
    // trusted generation; we then compare against the metadata's
    // generation and refuse the mount on rollback.
    let trusted_gen = if let Some(ap) = anchor {
        container.set_anchor(Some(ap.to_path_buf()))?
    } else {
        None
    };
    let vfs = Vfs::open(container)?;
    if let Some(anchor_gen) = trusted_gen {
        match anchor_mod::compare(anchor_gen, vfs.vault_generation()) {
            anchor_mod::VerificationOutcome::Ok
            | anchor_mod::VerificationOutcome::AnchorStale { .. } => {}
            anchor_mod::VerificationOutcome::RollbackDetected {
                anchor_gen,
                metadata_gen,
            } => {
                return Err(cli_err!(
                    "rollback detected: anchor at gen {anchor_gen} > vault at \
                     gen {metadata_gen}. Mount refused (someone may have \
                     substituted an old copy of the vault)."
                ));
            }
        }
    }
    luksbox_mount::mount(vfs, &mp_abs, !foreground)?;
    Ok(())
}

// ============================================================
// Shared deniable open + per-combo create helpers for the CLI
// ============================================================
//
// All PINs / passphrases prompted interactively via rpassword so
// secrets don't end up in shell history / ps argv. File paths
// (.kyber / .tpm-blob) come via --flag.

fn prompt_pass_twice(p1: &str, p2: &str) -> Result<zeroize::Zeroizing<String>> {
    let a = rpassword::prompt_password(p1)?;
    let b = rpassword::prompt_password(p2)?;
    if a != b {
        return Err(cli_err!("passphrases do not match"));
    }
    if a.is_empty() {
        return Err(cli_err!("empty passphrase not accepted for deniable mode"));
    }
    Ok(zeroize::Zeroizing::new(a))
}

/// v2 deniable open. Always passphrase-driven (envelope discovery
/// requires it); FIDO2 cred_id / hmac_salt / TPM sealed blob come
/// out of the slot envelope after phase 1 trial-decrypt succeeds.
/// `cred` is the user's choice of variant; if it does not match
/// what the matched slot actually carries, phase 2 fails opaquely.
fn cli_open_deniable_v2(
    path: &Path,
    cipher: luksbox_core::CipherSuite,
    argon2: luksbox_core::Argon2idParams,
    cred: CliDenCred,
    kyber_path: Option<&Path>,
) -> Result<luksbox_format::Container> {
    use luksbox_core::deniable::{DeniableCredential, DeniableKindTag};

    // Phase 1: passphrase-only credential for envelope discovery.
    let pass = rpassword::prompt_password("Passphrase: ")?;
    let pass_zeroizing = zeroize::Zeroizing::new(pass);
    let env_cred = DeniableCredential::Passphrase {
        passphrase: pass_zeroizing.as_bytes(),
        argon2,
    };
    let envelope =
        luksbox_format::Container::try_open_envelope_v2_deniable(path, None, &env_cred, cipher)?;

    // Sanity-check the slot's actual kind tag against the variant
    // the user asked for. If they don't match, fail with the same
    // opaque error as a wrong passphrase rather than leaking which
    // mismatch happened.
    let expected_tag = match cred {
        CliDenCred::Passphrase => DeniableKindTag::Passphrase,
        CliDenCred::Fido2 => DeniableKindTag::Fido2Passphrase,
        CliDenCred::PqPassphrase => DeniableKindTag::HybridPqPassphrase,
        CliDenCred::PqFido2 => DeniableKindTag::HybridPqFido2Passphrase,
        CliDenCred::Tpm => DeniableKindTag::TpmPassphrase,
        CliDenCred::TpmFido2 => DeniableKindTag::TpmFido2Passphrase,
        CliDenCred::PqTpm => DeniableKindTag::HybridPqTpmPassphrase,
        CliDenCred::PqTpmFido2 => DeniableKindTag::HybridPqTpmFido2Passphrase,
    };
    if envelope.payload().kind != expected_tag {
        return Err(cli_err!(
            "credential kind mismatch (vault expects a different variant)"
        ));
    }

    // Phase 2: drive secondaries based on payload material, then
    // build the full credential and complete the open.
    // Borrow buffers live for the rest of the function so the
    // DeniableCredential::*Passphrase reference borrows survive.
    let payload_cred_id = envelope.payload().cred_id.clone();
    let payload_hmac_salt = envelope.payload().hmac_salt;
    let payload_tpm_blob = envelope.payload().tpm_blob.clone();

    match cred {
        CliDenCred::Passphrase => {
            let cred = DeniableCredential::Passphrase {
                passphrase: pass_zeroizing.as_bytes(),
                argon2,
            };
            Ok(luksbox_format::Container::complete_open_v2_deniable(
                envelope, &cred,
            )?)
        }
        CliDenCred::Fido2 => {
            #[cfg(feature = "hardware")]
            {
                let salt = payload_hmac_salt
                    .ok_or_else(|| cli_err!("envelope missing hmac_salt for FIDO2 variant"))?;
                let hmac = cli_fido2_hmac_from_payload(&payload_cred_id, &salt)?;
                let cred = DeniableCredential::Fido2Passphrase {
                    passphrase: pass_zeroizing.as_bytes(),
                    argon2,
                    hmac_secret_output: &hmac,
                };
                Ok(luksbox_format::Container::complete_open_v2_deniable(
                    envelope, &cred,
                )?)
            }
            #[cfg(not(feature = "hardware"))]
            Err(cli_err!("FIDO2 hardware support not compiled in"))
        }
        CliDenCred::PqPassphrase => {
            let kp = kyber_path.ok_or_else(|| cli_err!("--kyber-path required"))?;
            let shared = cli_pq_decap_with_fallback(kp, path, Some(pass_zeroizing.as_bytes()))?;
            let cred = DeniableCredential::HybridPqPassphrase {
                passphrase: pass_zeroizing.as_bytes(),
                argon2,
                mlkem_shared: &shared,
            };
            Ok(luksbox_format::Container::complete_open_v2_deniable(
                envelope, &cred,
            )?)
        }
        CliDenCred::PqFido2 => {
            #[cfg(feature = "hardware")]
            {
                let kp = kyber_path.ok_or_else(|| cli_err!("--kyber-path required"))?;
                let shared = cli_pq_decap_with_fallback(kp, path, Some(pass_zeroizing.as_bytes()))?;
                let salt = payload_hmac_salt
                    .ok_or_else(|| cli_err!("envelope missing hmac_salt for FIDO2 variant"))?;
                let hmac = cli_fido2_hmac_from_payload(&payload_cred_id, &salt)?;
                let cred = DeniableCredential::HybridPqFido2Passphrase {
                    passphrase: pass_zeroizing.as_bytes(),
                    argon2,
                    mlkem_shared: &shared,
                    hmac_secret_output: &hmac,
                };
                Ok(luksbox_format::Container::complete_open_v2_deniable(
                    envelope, &cred,
                )?)
            }
            #[cfg(not(feature = "hardware"))]
            Err(cli_err!("FIDO2 hardware support not compiled in"))
        }
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        CliDenCred::Tpm => {
            let unsealed = cli_tpm_unseal_from_bytes(&payload_tpm_blob, None)?;
            let cred = DeniableCredential::TpmPassphrase {
                passphrase: pass_zeroizing.as_bytes(),
                argon2,
                unsealed: &unsealed,
            };
            Ok(luksbox_format::Container::complete_open_v2_deniable(
                envelope, &cred,
            )?)
        }
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        CliDenCred::TpmFido2 => {
            let unsealed = cli_tpm_unseal_from_bytes(&payload_tpm_blob, None)?;
            let salt = payload_hmac_salt
                .ok_or_else(|| cli_err!("envelope missing hmac_salt for FIDO2 variant"))?;
            let hmac = cli_fido2_hmac_from_payload(&payload_cred_id, &salt)?;
            let cred = DeniableCredential::TpmFido2Passphrase {
                passphrase: pass_zeroizing.as_bytes(),
                argon2,
                unsealed: &unsealed,
                hmac_secret_output: &hmac,
            };
            Ok(luksbox_format::Container::complete_open_v2_deniable(
                envelope, &cred,
            )?)
        }
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        CliDenCred::PqTpm => {
            let kp = kyber_path.ok_or_else(|| cli_err!("--kyber-path required"))?;
            let shared = cli_pq_decap_with_fallback(kp, path, Some(pass_zeroizing.as_bytes()))?;
            let unsealed = cli_tpm_unseal_from_bytes(&payload_tpm_blob, None)?;
            let cred = DeniableCredential::HybridPqTpmPassphrase {
                passphrase: pass_zeroizing.as_bytes(),
                argon2,
                mlkem_shared: &shared,
                unsealed: &unsealed,
            };
            Ok(luksbox_format::Container::complete_open_v2_deniable(
                envelope, &cred,
            )?)
        }
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        CliDenCred::PqTpmFido2 => {
            let kp = kyber_path.ok_or_else(|| cli_err!("--kyber-path required"))?;
            let shared = cli_pq_decap_with_fallback(kp, path, Some(pass_zeroizing.as_bytes()))?;
            let unsealed = cli_tpm_unseal_from_bytes(&payload_tpm_blob, None)?;
            let salt = payload_hmac_salt
                .ok_or_else(|| cli_err!("envelope missing hmac_salt for FIDO2 variant"))?;
            let hmac = cli_fido2_hmac_from_payload(&payload_cred_id, &salt)?;
            let cred = DeniableCredential::HybridPqTpmFido2Passphrase {
                passphrase: pass_zeroizing.as_bytes(),
                argon2,
                mlkem_shared: &shared,
                unsealed: &unsealed,
                hmac_secret_output: &hmac,
            };
            Ok(luksbox_format::Container::complete_open_v2_deniable(
                envelope, &cred,
            )?)
        }
        #[cfg(not(all(feature = "hardware", target_os = "linux")))]
        CliDenCred::Tpm | CliDenCred::TpmFido2 | CliDenCred::PqTpm | CliDenCred::PqTpmFido2 => Err(
            cli_err!("TPM is Linux-only today; Windows TPM is tracked as a follow-up"),
        ),
    }
}

/// Drive the FIDO2 authenticator using cred_id + hmac_salt taken
/// from the envelope payload. v2 unlock no longer reads these from
/// the CLI / env: they were embedded at create time.
#[cfg(feature = "hardware")]
fn cli_fido2_hmac_from_payload(
    cred_id: &[u8],
    salt: &[u8; 32],
) -> Result<luksbox_fido2::HmacSecret> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID};
    if cred_id.is_empty() {
        return Err(cli_err!("envelope cred_id is empty for FIDO2 variant"));
    }
    let pin = rpassword::prompt_password("FIDO2 PIN: ")?;
    let mut auth = make_fido2_authenticator();
    Ok(auth.hmac_secret(RP_ID, cred_id, salt, Some(&pin))?)
}

/// Drive the TPM to unseal a blob taken from the envelope payload.
/// v2 unlock no longer needs `--tpm-blob-path`.
#[cfg(all(feature = "hardware", target_os = "linux"))]
fn cli_tpm_unseal_from_bytes(blob_bytes: &[u8], pin: Option<&[u8]>) -> Result<[u8; 32]> {
    use luksbox_tpm::{SealedBlob, Tpm2Sealer};
    if blob_bytes.is_empty() {
        return Err(cli_err!("envelope tpm_blob is empty for TPM variant"));
    }
    let blob = SealedBlob::from_bytes(blob_bytes)?;
    let mut sealer = Tpm2Sealer::new()?;
    let unsealed = match pin {
        Some(p) => sealer.unseal_with_pin(&blob, Some(p))?,
        None => sealer.unseal(&blob)?,
    };
    Ok(*unsealed)
}

#[allow(dead_code)]
fn cli_pq_decap(kyber_path: &Path, vault: &Path) -> Result<[u8; 32]> {
    // Legacy entry; kept for callers that don't yet know the envelope
    // passphrase (e.g. non-deniable flows). Round 12 fix R12-02
    // re-routed every deniable PQ caller to
    // `cli_pq_decap_with_fallback(.., Some(envelope_pw))` so blank
    // reuses the envelope passphrase.
    cli_pq_decap_with_fallback(kyber_path, vault, None)
}

/// Round 12 fix R12-02: CLI seed-pw fallback. When the deniable
/// vault was created via `deniable-init --credential pq-passphrase`
/// the matching create helper writes the .kyber seed file using the
/// ENVELOPE passphrase. The open path must accept the same default.
/// The GUI (`luksbox-gui/src/ops.rs:deniable_pq_decap`) and the
/// wizard (`ask_pq_decap_for_deniable`) both implement this fallback;
/// the CLI previously did not.
///
/// `envelope_pw` is the envelope passphrase already collected by the
/// caller. If the user leaves the seed-file passphrase prompt blank,
/// the envelope passphrase is used instead. If `envelope_pw` is None
/// (legacy callers / non-deniable callers), only the explicit prompt
/// is honoured.
fn cli_pq_decap_with_fallback(
    kyber_path: &Path,
    vault: &Path,
    envelope_pw: Option<&[u8]>,
) -> Result<[u8; 32]> {
    use luksbox_format::hybrid_sidecar;
    use luksbox_pq::seed_file;

    let prompt_text = if envelope_pw.is_some() {
        "Seed-file passphrase (leave blank to reuse the envelope passphrase): "
    } else {
        "Seed-file passphrase: "
    };
    let typed_seed_pw = rpassword::prompt_password(prompt_text)?;
    let seed_pw_bytes: zeroize::Zeroizing<Vec<u8>> = if typed_seed_pw.is_empty() {
        match envelope_pw {
            Some(env) => zeroize::Zeroizing::new(env.to_vec()),
            None => {
                return Err(cli_err!(
                    "seed-file passphrase is required for this open path"
                ));
            }
        }
    } else {
        zeroize::Zeroizing::new(typed_seed_pw.into_bytes())
    };

    let seed = seed_file::read(kyber_path, &seed_pw_bytes[..])?;
    let sidecar = hybrid_sidecar::sidecar_path(vault);
    let entries = hybrid_sidecar::read(&sidecar)?;
    let entry = entries
        .first()
        .ok_or_else(|| cli_err!("hybrid sidecar is empty"))?;
    let shared = luksbox_pq::decapsulate_with(entry.level, &seed, &entry.ciphertext)?;
    Ok(*shared)
}

// v1 `cli_tpm_unseal(path, pin)` removed in v2; replaced by
// `cli_tpm_unseal_from_bytes` which takes the sealed blob recovered
// from the slot envelope rather than reading a `.tpm-blob` sidecar.

// ============================================================
// v2 create helpers: embed material in slot, no .tpm-blob sidecar
// ============================================================

fn cli_create_passphrase_deniable_v2(
    path: &Path,
    cipher: luksbox_core::CipherSuite,
    argon2: luksbox_core::Argon2idParams,
) -> Result<luksbox_format::Container> {
    use luksbox_format::deniable_header::DeniableMaterial;
    let pass = prompt_pass_twice("Passphrase: ", "Confirm:    ")?;
    let cred = luksbox_core::deniable::DeniableCredential::Passphrase {
        passphrase: pass.as_bytes(),
        argon2,
    };
    let cont = luksbox_format::Container::create_with_credential_v2_deniable(
        path,
        None,
        cipher,
        0,
        0,
        &cred,
        &DeniableMaterial::passphrase_only(),
    )?;
    Ok(cont)
}

#[cfg(feature = "hardware")]
fn cli_create_fido2_deniable_v2(
    path: &Path,
    cipher: luksbox_core::CipherSuite,
    argon2: luksbox_core::Argon2idParams,
) -> Result<luksbox_format::Container> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::deniable_header::DeniableMaterial;
    use rand_core::RngCore;
    let pass = prompt_pass_twice("Passphrase: ", "Confirm:    ")?;
    let pin = rpassword::prompt_password("FIDO2 PIN: ")?;
    let mut auth = make_fido2_authenticator();
    let user_handle = random_user_handle()?;
    let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
    let cred_id = er.credential.id;
    let mut hmac_salt = [0u8; 32];
    rand_core::OsRng
        .try_fill_bytes(&mut hmac_salt)
        .map_err(|e| cli_err!("OS RNG: {e}"))?;
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(&pin))?;
    let cred = luksbox_core::deniable::DeniableCredential::Fido2Passphrase {
        passphrase: pass.as_bytes(),
        argon2,
        hmac_secret_output: &hmac_secret,
    };
    let material = DeniableMaterial {
        cred_id,
        hmac_salt: Some(hmac_salt),
        tpm_blob: Vec::new(),
    };
    let cont = luksbox_format::Container::create_with_credential_v2_deniable(
        path, None, cipher, 0, 0, &cred, &material,
    )?;
    Ok(cont)
}

fn cli_create_pq_passphrase_deniable_v2(
    path: &Path,
    cipher: luksbox_core::CipherSuite,
    argon2: luksbox_core::Argon2idParams,
    kyber_path: &Path,
    use_1024: bool,
) -> Result<luksbox_format::Container> {
    use luksbox_format::deniable_header::DeniableMaterial;
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};
    let params = if use_1024 {
        PqParams::Ml1024
    } else {
        PqParams::Ml768
    };
    let pass = prompt_pass_twice("Passphrase: ", "Confirm:    ")?;
    let (pk, seed) = keygen_with(params);
    let (ct, shared) = encapsulate_with(params, &pk)?;
    let cred = luksbox_core::deniable::DeniableCredential::HybridPqPassphrase {
        passphrase: pass.as_bytes(),
        argon2,
        mlkem_shared: &shared,
    };
    let cont = luksbox_format::Container::create_with_credential_v2_deniable(
        path,
        None,
        cipher,
        0,
        0,
        &cred,
        &DeniableMaterial::passphrase_only(),
    )?;
    hybrid_sidecar::write(
        &hybrid_sidecar::sidecar_path(path),
        &[HybridEntry {
            slot_idx: 0,
            level: params,
            pubkey: pk,
            ciphertext: ct,
        }],
    )?;
    seed_file::write(
        kyber_path,
        &seed,
        pass.as_bytes(),
        seed_file::KdfParams::default(),
    )?;
    Ok(cont)
}

#[cfg(feature = "hardware")]
fn cli_create_pq_fido2_deniable_v2(
    path: &Path,
    cipher: luksbox_core::CipherSuite,
    argon2: luksbox_core::Argon2idParams,
    kyber_path: &Path,
    use_1024: bool,
) -> Result<luksbox_format::Container> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::deniable_header::DeniableMaterial;
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};
    use rand_core::RngCore;
    let params = if use_1024 {
        PqParams::Ml1024
    } else {
        PqParams::Ml768
    };
    let pass = prompt_pass_twice("Passphrase: ", "Confirm:    ")?;
    let pin = rpassword::prompt_password("FIDO2 PIN: ")?;
    // Round 12 fix R12-02: align with GUI/wizard. Blank = reuse envelope.
    let typed_seed_pw = rpassword::prompt_password(
        "Seed-file passphrase (leave blank to reuse the envelope passphrase): ",
    )?;
    let seed_pw: zeroize::Zeroizing<Vec<u8>> = if typed_seed_pw.is_empty() {
        zeroize::Zeroizing::new(pass.as_bytes().to_vec())
    } else {
        zeroize::Zeroizing::new(typed_seed_pw.into_bytes())
    };
    let mut auth = make_fido2_authenticator();
    let user_handle = random_user_handle()?;
    let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
    let cred_id = er.credential.id;
    let mut hmac_salt = [0u8; 32];
    rand_core::OsRng
        .try_fill_bytes(&mut hmac_salt)
        .map_err(|e| cli_err!("OS RNG: {e}"))?;
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(&pin))?;
    let (pk, seed) = keygen_with(params);
    let (ct, shared) = encapsulate_with(params, &pk)?;
    let cred = luksbox_core::deniable::DeniableCredential::HybridPqFido2Passphrase {
        passphrase: pass.as_bytes(),
        argon2,
        mlkem_shared: &shared,
        hmac_secret_output: &hmac_secret,
    };
    let material = DeniableMaterial {
        cred_id,
        hmac_salt: Some(hmac_salt),
        tpm_blob: Vec::new(),
    };
    let cont = luksbox_format::Container::create_with_credential_v2_deniable(
        path, None, cipher, 0, 0, &cred, &material,
    )?;
    hybrid_sidecar::write(
        &hybrid_sidecar::sidecar_path(path),
        &[HybridEntry {
            slot_idx: 0,
            level: params,
            pubkey: pk,
            ciphertext: ct,
        }],
    )?;
    seed_file::write(
        kyber_path,
        &seed,
        &seed_pw[..],
        seed_file::KdfParams::default(),
    )?;
    Ok(cont)
}

#[cfg(all(feature = "hardware", target_os = "linux"))]
fn cli_tpm_seal_to_bytes(pin: Option<&[u8]>) -> Result<(zeroize::Zeroizing<[u8; 32]>, Vec<u8>)> {
    use luksbox_tpm::Tpm2Sealer;
    use rand_core::RngCore;
    let mut sealer = Tpm2Sealer::new()?;
    let mut secret = zeroize::Zeroizing::new([0u8; 32]);
    rand_core::OsRng
        .try_fill_bytes(secret.as_mut_slice())
        .map_err(|e| cli_err!("OS RNG: {e}"))?;
    let blob = match pin {
        Some(p) => sealer.seal_with_pin(&secret, Some(p))?,
        None => sealer.seal(&secret)?,
    };
    Ok((secret, blob.to_bytes()))
}

#[cfg(all(feature = "hardware", target_os = "linux"))]
fn cli_create_tpm_deniable_v2(
    path: &Path,
    cipher: luksbox_core::CipherSuite,
    argon2: luksbox_core::Argon2idParams,
) -> Result<luksbox_format::Container> {
    use luksbox_format::deniable_header::DeniableMaterial;
    let pass = prompt_pass_twice("Passphrase: ", "Confirm:    ")?;
    let (secret, blob) = cli_tpm_seal_to_bytes(None)?;
    let cred = luksbox_core::deniable::DeniableCredential::TpmPassphrase {
        passphrase: pass.as_bytes(),
        argon2,
        unsealed: &*secret,
    };
    let material = DeniableMaterial {
        cred_id: Vec::new(),
        hmac_salt: None,
        tpm_blob: blob,
    };
    let cont = luksbox_format::Container::create_with_credential_v2_deniable(
        path, None, cipher, 0, 0, &cred, &material,
    )?;
    Ok(cont)
}

#[cfg(all(feature = "hardware", target_os = "linux"))]
fn cli_create_tpm_fido2_deniable_v2(
    path: &Path,
    cipher: luksbox_core::CipherSuite,
    argon2: luksbox_core::Argon2idParams,
) -> Result<luksbox_format::Container> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::deniable_header::DeniableMaterial;
    use rand_core::RngCore;
    let pass = prompt_pass_twice("Passphrase: ", "Confirm:    ")?;
    let pin = rpassword::prompt_password("FIDO2 PIN: ")?;
    let (secret, blob) = cli_tpm_seal_to_bytes(None)?;
    let mut auth = make_fido2_authenticator();
    let user_handle = random_user_handle()?;
    let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
    let cred_id = er.credential.id;
    let mut hmac_salt = [0u8; 32];
    rand_core::OsRng
        .try_fill_bytes(&mut hmac_salt)
        .map_err(|e| cli_err!("OS RNG: {e}"))?;
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(&pin))?;
    let cred = luksbox_core::deniable::DeniableCredential::TpmFido2Passphrase {
        passphrase: pass.as_bytes(),
        argon2,
        unsealed: &*secret,
        hmac_secret_output: &hmac_secret,
    };
    let material = DeniableMaterial {
        cred_id,
        hmac_salt: Some(hmac_salt),
        tpm_blob: blob,
    };
    let cont = luksbox_format::Container::create_with_credential_v2_deniable(
        path, None, cipher, 0, 0, &cred, &material,
    )?;
    Ok(cont)
}

#[cfg(all(feature = "hardware", target_os = "linux"))]
fn cli_create_pq_tpm_deniable_v2(
    path: &Path,
    cipher: luksbox_core::CipherSuite,
    argon2: luksbox_core::Argon2idParams,
    kyber_path: &Path,
    use_1024: bool,
) -> Result<luksbox_format::Container> {
    use luksbox_format::deniable_header::DeniableMaterial;
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};
    let params = if use_1024 {
        PqParams::Ml1024
    } else {
        PqParams::Ml768
    };
    let pass = prompt_pass_twice("Passphrase: ", "Confirm:    ")?;
    let (secret, blob) = cli_tpm_seal_to_bytes(None)?;
    // Round 12 fix R12-02: align with GUI/wizard. Blank = reuse envelope.
    let typed_seed_pw = rpassword::prompt_password(
        "Seed-file passphrase (leave blank to reuse the envelope passphrase): ",
    )?;
    let seed_pw: zeroize::Zeroizing<Vec<u8>> = if typed_seed_pw.is_empty() {
        zeroize::Zeroizing::new(pass.as_bytes().to_vec())
    } else {
        zeroize::Zeroizing::new(typed_seed_pw.into_bytes())
    };
    let (pk, seed) = keygen_with(params);
    let (ct, shared) = encapsulate_with(params, &pk)?;
    let cred = luksbox_core::deniable::DeniableCredential::HybridPqTpmPassphrase {
        passphrase: pass.as_bytes(),
        argon2,
        mlkem_shared: &shared,
        unsealed: &*secret,
    };
    let material = DeniableMaterial {
        cred_id: Vec::new(),
        hmac_salt: None,
        tpm_blob: blob,
    };
    let cont = luksbox_format::Container::create_with_credential_v2_deniable(
        path, None, cipher, 0, 0, &cred, &material,
    )?;
    hybrid_sidecar::write(
        &hybrid_sidecar::sidecar_path(path),
        &[HybridEntry {
            slot_idx: 0,
            level: params,
            pubkey: pk,
            ciphertext: ct,
        }],
    )?;
    seed_file::write(
        kyber_path,
        &seed,
        &seed_pw[..],
        seed_file::KdfParams::default(),
    )?;
    Ok(cont)
}

#[cfg(all(feature = "hardware", target_os = "linux"))]
fn cli_create_pq_tpm_fido2_deniable_v2(
    path: &Path,
    cipher: luksbox_core::CipherSuite,
    argon2: luksbox_core::Argon2idParams,
    kyber_path: &Path,
    use_1024: bool,
) -> Result<luksbox_format::Container> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::deniable_header::DeniableMaterial;
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};
    use rand_core::RngCore;
    let params = if use_1024 {
        PqParams::Ml1024
    } else {
        PqParams::Ml768
    };
    let pass = prompt_pass_twice("Passphrase: ", "Confirm:    ")?;
    let pin = rpassword::prompt_password("FIDO2 PIN: ")?;
    // Round 12 fix R12-02: align with GUI/wizard. Blank = reuse envelope.
    let typed_seed_pw = rpassword::prompt_password(
        "Seed-file passphrase (leave blank to reuse the envelope passphrase): ",
    )?;
    let seed_pw: zeroize::Zeroizing<Vec<u8>> = if typed_seed_pw.is_empty() {
        zeroize::Zeroizing::new(pass.as_bytes().to_vec())
    } else {
        zeroize::Zeroizing::new(typed_seed_pw.into_bytes())
    };
    let (secret, blob) = cli_tpm_seal_to_bytes(None)?;
    let mut auth = make_fido2_authenticator();
    let user_handle = random_user_handle()?;
    let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
    let cred_id = er.credential.id;
    let mut hmac_salt = [0u8; 32];
    rand_core::OsRng
        .try_fill_bytes(&mut hmac_salt)
        .map_err(|e| cli_err!("OS RNG: {e}"))?;
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(&pin))?;
    let (pk, seed) = keygen_with(params);
    let (ct, shared) = encapsulate_with(params, &pk)?;
    let cred = luksbox_core::deniable::DeniableCredential::HybridPqTpmFido2Passphrase {
        passphrase: pass.as_bytes(),
        argon2,
        mlkem_shared: &shared,
        unsealed: &*secret,
        hmac_secret_output: &hmac_secret,
    };
    let material = DeniableMaterial {
        cred_id,
        hmac_salt: Some(hmac_salt),
        tpm_blob: blob,
    };
    let cont = luksbox_format::Container::create_with_credential_v2_deniable(
        path, None, cipher, 0, 0, &cred, &material,
    )?;
    hybrid_sidecar::write(
        &hybrid_sidecar::sidecar_path(path),
        &[HybridEntry {
            slot_idx: 0,
            level: params,
            pubkey: pk,
            ciphertext: ct,
        }],
    )?;
    seed_file::write(
        kyber_path,
        &seed,
        &seed_pw[..],
        seed_file::KdfParams::default(),
    )?;
    Ok(cont)
}

/// Migrate a v2 vault to v3: opens the source, creates a fresh v3
/// vault at `dst`, and copies the full directory tree + file contents
/// through the VFS read API. The source is left untouched so the
/// migration is fully reversible (just delete `dst` and retry).
///
/// Limitations:
/// - The destination vault is created with a **single passphrase
///   keyslot**, even if the source had multiple slots or non-
///   passphrase kinds. The migrating user is prompted for a fresh
///   passphrase. Other keyslots can be re-enrolled afterwards via
///   `luksbox enroll`.
/// - Deniable vaults are not yet supported (deniable v3 parity is
///   pending in a separate release).
/// - Anchor sidecars on the source are NOT re-bound: the destination
///   starts without an anchor; the user can re-init via the next
///   write or via `luksbox` flags.
fn cmd_migrate_to_v3(src: &Path, dst: &Path, unlock: &UnlockArgs) -> Result<()> {
    use luksbox_format::Container;
    use luksbox_vfs::{Vfs, set_format_v3_override};

    if !src.exists() {
        return Err(format!("source vault {} not found", src.display()).into());
    }
    if dst.exists() {
        return Err(format!(
            "destination {} already exists; refusing to overwrite",
            dst.display()
        )
        .into());
    }

    // 1. Open the source (any format).
    let mut src_vfs = open_vfs(src, unlock)?;
    if src_vfs.uses_v3_metadata() {
        return Err("source vault is already in v3 format; nothing to migrate".into());
    }
    if src_vfs.container().is_deniable() {
        return Err(
            "deniable vaults cannot be migrated to v3 yet (deniable v3 parity is a \
             planned follow-up). Stick with v2 for deniable mode for now."
                .into(),
        );
    }
    // Same cipher + a fresh interactive Argon2id preset for the dst.
    let src_cipher = src_vfs.container().header.cipher_suite;

    eprintln!(
        "Migrating v2 vault {} -> v3 vault {}",
        src.display(),
        dst.display()
    );
    eprintln!("Pick a passphrase for the new vault (can differ from the source).");
    let new_pw = read_passphrase_confirmed("new-vault passphrase: ")?;

    // 2. Create the destination as v3. The format override is
    // installed BEFORE Container::create_with_passphrase so the new
    // Vfs writes the LBM3 magic on its first flush.
    let _format_guard = set_format_v3_override(Some(true));
    let dst_cont = Container::create_with_passphrase(
        dst,
        None,
        src_cipher,
        Argon2idParams::INTERACTIVE,
        new_pw.as_bytes(),
    )?;
    let mut dst_vfs = Vfs::open(dst_cont)?;
    debug_assert!(dst_vfs.uses_v3_metadata());

    // 3. Walk the source tree depth-first and recreate in dst.
    let src_root = src_vfs.root_id();
    let dst_root = dst_vfs.root_id();
    copy_subtree(&mut src_vfs, src_root, &mut dst_vfs, dst_root)?;

    dst_vfs.flush()?;
    drop(dst_vfs);
    eprintln!(
        "OK migration complete. Verify {} opens cleanly (`luksbox info {}`), then \
         delete the source vault if you no longer need it.",
        dst.display(),
        dst.display()
    );
    Ok(())
}

fn copy_subtree(
    src_vfs: &mut luksbox_vfs::Vfs,
    src_dir: luksbox_vfs::FileId,
    dst_vfs: &mut luksbox_vfs::Vfs,
    dst_dir: luksbox_vfs::FileId,
) -> Result<()> {
    use luksbox_vfs::tree::InodeKind;
    // readdir gives us names + ids; we recurse per-entry.
    let entries = src_vfs.readdir(src_dir)?;
    for entry in entries {
        let src_id = entry.id;
        let st = src_vfs.stat(src_id)?;
        match st.kind {
            InodeKind::Directory => {
                let new_dir = dst_vfs.mkdir(dst_dir, &entry.name)?;
                copy_subtree(src_vfs, src_id, dst_vfs, new_dir)?;
            }
            InodeKind::File => {
                let new_file = dst_vfs.create(dst_dir, &entry.name)?;
                // Copy in 64 KiB chunks to keep memory bounded.
                const COPY_BUF: usize = 64 * 1024;
                let mut buf = vec![0u8; COPY_BUF];
                let total = st.size;
                let mut off = 0u64;
                while off < total {
                    let want = std::cmp::min(COPY_BUF as u64, total - off) as usize;
                    let n = src_vfs.read(src_id, off, &mut buf[..want])?;
                    if n == 0 {
                        break;
                    }
                    dst_vfs.write(new_file, off, &buf[..n])?;
                    off += n as u64;
                }
            }
        }
    }
    Ok(())
}

fn cmd_rotate_mvk(path: &Path, unlock: &UnlockArgs) -> Result<()> {
    // Delegate to the wizard's interactive rotation flow.
    // Multi-slot credential collection is inherently interactive
    // (one passphrase prompt or two FIDO2 touches per populated
    // slot), so a non-interactive `rotate-mvk` would mean either a
    // shell-quoted credential bundle on the command line (passphrase
    // leak via /proc and shell history) or a config file. Neither
    // is a good default. The wizard prompts slot-by-slot.
    //
    // We honour the standard `--header` / `--anchor` unlock args so
    // the user can rotate a vault opened with detached header /
    // anchor sidecars; the wizard's flow takes the open Container
    // from us so unlock material is gathered there.
    let cont = open_container(path, unlock)?;
    let cont =
        wizard::run_rotate_mvk_interactive(&dialoguer::theme::ColorfulTheme::default(), cont)?;
    drop(cont);
    Ok(())
}

/// Audit Round 9G: parse a duration string like `5s`, `500ms`, `2m`
/// into milliseconds. Returns an error for malformed inputs and for
/// targets outside `[100ms, 30s]` (smaller wouldn't be hardening,
/// larger is impractical for interactive use).
fn parse_kdf_target(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num_str, mult_ms) = if let Some(n) = s.strip_suffix("ms") {
        (n.trim(), 1u64)
    } else if let Some(n) = s.strip_suffix('s') {
        (n.trim(), 1000u64)
    } else if let Some(n) = s.strip_suffix('m') {
        (n.trim(), 60_000u64)
    } else {
        return Err(
            format!("--kdf-target-time {s:?}: missing unit (use ms / s / m, e.g. `5s`)").into(),
        );
    };
    let n: u64 = num_str
        .parse()
        .map_err(|_| format!("--kdf-target-time {s:?}: not a positive integer"))?;
    let target_ms = n.saturating_mul(mult_ms);
    if !(100..=30_000).contains(&target_ms) {
        return Err(
            format!("--kdf-target-time {s:?} = {target_ms}ms out of range [100ms, 30s]").into(),
        );
    }
    Ok(target_ms)
}

/// Audit Round 9G: calibrate Argon2id m_cost on this CPU so that one
/// `derive_kek` call takes approximately `target_ms` wall time.
///
/// Methodology: hold t_cost = 3 + p_cost = 4 (proven sweet spot for
/// modern multi-core CPUs); scale m_cost linearly from a baseline
/// measurement. Argon2id's runtime is approximately linear in m_cost
/// at fixed t/p, so a single calibration sample is sufficient for
/// 10% accuracy.
///
/// Bounded by available RAM (`Vec::try_reserve` pre-flight) and by
/// `Argon2idParams::SAFE_M_COST_KIB_MAX` (4 GiB cap).
/// Parse a human-readable byte count for `--metadata-size`. Accepts
/// plain decimal (`16777216`) or a single-character binary unit suffix
/// (`k` = KiB, `m` = MiB; case-insensitive).
///
/// Validates against BOTH:
///   - lower floor (64 KiB): below this the AEAD overhead + magic +
///     an empty directory tree wouldn't fit, the first write would
///     fail and the user has created an unusable vault;
///   - upper cap [`luksbox_core::header::MAX_METADATA_SIZE`] (16 MiB
///     in this format version): values above it pass `Header::try_new`
///     and end up serialised into the on-disk header, but the parser
///     in `Header::from_bytes` rejects them, so the user would create
///     a vault they could never re-open. Refuse at the CLI boundary
///     instead.
fn parse_byte_size(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        return Err("--metadata-size: empty value".into());
    }
    let (num_part, mult) = match s.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => {
            let mult = match c.to_ascii_lowercase() {
                'k' => 1024u64,
                'm' => 1024u64 * 1024,
                _ => {
                    return Err(format!(
                        "--metadata-size: unrecognised unit '{c}' (use K or M, e.g. 16M)"
                    )
                    .into());
                }
            };
            (&s[..s.len() - 1], mult)
        }
        _ => (s, 1u64),
    };
    let n: u64 = num_part
        .parse()
        .map_err(|e| format!("--metadata-size: invalid number '{num_part}': {e}"))?;
    let bytes = n
        .checked_mul(mult)
        .ok_or("--metadata-size: value overflows u64")?;
    const FLOOR: u64 = 64 * 1024;
    if bytes < FLOOR {
        return Err(format!(
            "--metadata-size: {bytes} bytes is below the {FLOOR} byte floor \
             (would not fit AEAD overhead + an empty directory tree)"
        )
        .into());
    }
    if bytes > luksbox_core::header::MAX_METADATA_SIZE {
        return Err(format!(
            "--metadata-size: {bytes} bytes exceeds the on-disk format cap of {} bytes \
             ({} MiB). A vault created with a larger value would be unopenable. \
             The cap is set in luksbox-core::header::MAX_METADATA_SIZE; raising it \
             requires a format-version bump and is planned for a future release.",
            luksbox_core::header::MAX_METADATA_SIZE,
            luksbox_core::header::MAX_METADATA_SIZE / (1024 * 1024)
        )
        .into());
    }
    Ok(bytes)
}

fn calibrate_kdf_for_target(target_str: &str) -> Result<Argon2idParams> {
    use luksbox_core::kdf;
    use std::time::Instant;

    let target_ms = parse_kdf_target(target_str)?;
    eprintln!("calibrating Argon2id for {target_ms}ms target (one sample, may take a moment)...");

    // Baseline at the conservative interactive preset.
    let baseline_params = Argon2idParams::INTERACTIVE;
    let canary = b"calibration-canary-not-a-real-passphrase";
    let salt = [0x77u8; 32];

    let start = Instant::now();
    kdf::derive_kek(canary, &salt, baseline_params)
        .map_err(|e| format!("baseline kdf failed: {e:?}"))?;
    let baseline_ms = start.elapsed().as_secs_f64() * 1000.0;
    eprintln!(
        "  baseline {} MiB / t={} / p={} took {baseline_ms:.0}ms",
        baseline_params.m_cost_kib / 1024,
        baseline_params.t_cost,
        baseline_params.p_cost,
    );

    // Scale m_cost linearly. m_cost' = m_cost * target / baseline.
    let scale = (target_ms as f64) / baseline_ms;
    let scaled_m_cost = ((baseline_params.m_cost_kib as f64) * scale).round() as u32;

    // Round to a multiple of 1024 (= 1 MiB) for cleaner config display.
    let scaled_m_cost = scaled_m_cost.next_multiple_of(1024).max(8 * 1024);

    // Clamp to the safe-on-disk cap.
    const SAFE_MAX: u32 = 4 * 1024 * 1024; // 4 GiB
    let m_cost_kib = scaled_m_cost.min(SAFE_MAX);
    if scaled_m_cost > SAFE_MAX {
        eprintln!(
            "  target {target_ms}ms requires more than {SAFE_MAX} KiB Argon2id memory; \
             clamping to {m_cost_kib} KiB ({} MiB)",
            m_cost_kib / 1024
        );
    }

    // Pre-flight RAM check (also belt-and-suspenders against systems
    // where the actual call would OOM-abort uncatchably).
    let bytes_needed = (m_cost_kib as usize).saturating_mul(1024);
    let mut probe: Vec<u8> = Vec::new();
    if probe.try_reserve_exact(bytes_needed).is_err() {
        return Err(format!(
            "calibrated m_cost = {m_cost_kib} KiB ({} MiB) exceeds available RAM. \
             Pick a smaller --kdf-target-time, or fall back to --kdf interactive.",
            m_cost_kib / 1024
        )
        .into());
    }
    drop(probe);

    let calibrated = Argon2idParams {
        m_cost_kib,
        t_cost: baseline_params.t_cost,
        p_cost: baseline_params.p_cost,
    };

    eprintln!(
        "  calibrated: {} MiB / t={} / p={}",
        calibrated.m_cost_kib / 1024,
        calibrated.t_cost,
        calibrated.p_cost,
    );
    eprintln!(
        "  expected unlock time: ~{}ms (approximate; will vary +-20% per run)",
        target_ms
    );

    Ok(calibrated)
}

/// Audit Round 9G: benchmark Argon2id wall time at the standard
/// presets on the user's hardware. Produces concrete numbers so the
/// user can decide whether to upgrade from `interactive` to
/// `sensitive` for high-value vaults.
///
/// Methodology: run `kdf::derive_kek(canary_passphrase, fixed_salt,
/// preset)` `samples` times per preset, report median wall time.
/// Argon2id timing depends on memory bandwidth + L1/L2 cache layout;
/// repeated runs reduce one-off OS-scheduling noise.
fn cmd_kdf_bench(samples: u32) -> Result<()> {
    use luksbox_core::kdf;
    use std::time::Instant;

    let canary = b"this-is-a-bench-passphrase-not-a-real-secret";
    let salt = [0xa5u8; 32];

    println!("=== Argon2id wall-time benchmark ===");
    println!("Hardware: rerun on every CPU you care about; results vary by CPU + RAM speed.");
    println!("Each preset is run {samples} time(s); median wall time reported.");
    println!();

    let presets: &[(&str, Argon2idParams)] = &[
        ("interactive (default)", Argon2idParams::INTERACTIVE),
        ("moderate          ", Argon2idParams::MODERATE),
        ("sensitive         ", Argon2idParams::SENSITIVE),
    ];

    println!(
        "{:<22} | {:>10} | {:>8} | {:>6} | {:>10} | {:>14}",
        "Preset", "memory MiB", "t_cost", "p_cost", "median ms", "g/s 1-thread"
    );
    println!(
        "{:-<22}-+-{:->10}-+-{:->8}-+-{:->6}-+-{:->10}-+-{:->14}",
        "", "", "", "", "", ""
    );

    for (name, params) in presets {
        // Argon2id allocates `m_cost_kib * 1024` bytes upfront; on
        // systems where this fails (low-RAM VMs, cgroup-capped
        // containers, sandboxes, or just CPUs with less RAM than the
        // sensitive preset wants), the `argon2` crate aborts the
        // process via the global allocator's default OOM handler
        // (which `catch_unwind` cannot intercept). Pre-flight via
        // `Vec::try_reserve` to detect whether the allocation would
        // succeed; if not, mark the preset n/a and continue rather
        // than aborting the bench.
        let bytes_needed = (params.m_cost_kib as usize).saturating_mul(1024);
        let mut probe: Vec<u8> = Vec::new();
        let alloc_ok = probe.try_reserve_exact(bytes_needed).is_ok();
        drop(probe); // release immediately so the actual KDF call can grab it
        if !alloc_ok {
            println!(
                "{:<22} | {:>10} | {:>8} | {:>6} | {:>10} | {:>14}",
                name,
                params.m_cost_kib / 1024,
                params.t_cost,
                params.p_cost,
                "n/a",
                "(no RAM)"
            );
            continue;
        }

        let mut times = Vec::with_capacity(samples as usize);
        let mut alloc_failed = false;
        for _ in 0..samples {
            let start = Instant::now();
            // Even with try_reserve passing, the argon2 crate's
            // internal allocation can theoretically still fail under
            // memory pressure between the probe and the actual call.
            // catch_unwind catches panics (rare here); OOM-abort still
            // wouldn't be caught, but in practice try_reserve already
            // gates that.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                kdf::derive_kek(canary, &salt, *params)
            }));
            match result {
                Ok(Ok(_)) => times.push(start.elapsed()),
                Ok(Err(e)) => {
                    eprintln!("    {name}: kdf returned error: {e:?}");
                    alloc_failed = true;
                    break;
                }
                Err(_) => {
                    alloc_failed = true;
                    break;
                }
            }
        }

        if alloc_failed || times.is_empty() {
            println!(
                "{:<22} | {:>10} | {:>8} | {:>6} | {:>10} | {:>14}",
                name,
                params.m_cost_kib / 1024,
                params.t_cost,
                params.p_cost,
                "n/a",
                "(no RAM)"
            );
            continue;
        }

        times.sort();
        let median = times[times.len() / 2];
        let median_ms = median.as_secs_f64() * 1000.0;
        let single_thread_gps = 1000.0 / median_ms;

        println!(
            "{:<22} | {:>10} | {:>8} | {:>6} | {:>10.0} | {:>14.2}",
            name,
            params.m_cost_kib / 1024,
            params.t_cost,
            params.p_cost,
            median_ms,
            single_thread_gps
        );
    }
    println!();
    println!("Brute-force cost interpretation:");
    println!("  Time per attempt = median ms above.");
    println!("  An attacker with N CPU cores doing nothing but Argon2id");
    println!("  performs roughly (N / single-thread time) attempts per second,");
    println!("  bounded by RAM (each attempt needs `memory MiB` MiB resident).");
    println!();
    println!("Recommendations:");
    println!(" - interactive: fine for daily-use vaults that you unlock often.");
    println!(" - moderate:    annual-archive vaults or anything you'd grumble");
    println!("                 about losing for 1-2 sec of unlock latency.");
    println!(" - sensitive:   long-term cold storage. Multiplies attacker cost");
    println!("                 6x vs interactive at 6x your unlock wait.");
    println!();
    println!("For full math, contact security@penthertz.com (internal cracking-cost analysis).");

    Ok(())
}

fn cmd_panic(
    vault: &Path,
    header_path: Option<&Path>,
    wipe_data: bool,
    skip_confirm: bool,
) -> Result<()> {
    use rand_core::{OsRng, RngCore};
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom, Write};

    if !vault.is_file() {
        return Err(format!("{} is not a file", vault.display()).into());
    }
    let header_target = header_path.unwrap_or(vault);

    if !skip_confirm {
        eprintln!(
            "PANIC: about to overwrite the header of {} with random bytes.",
            header_target.display()
        );
        if wipe_data {
            eprintln!(
                "       ALSO overwriting the entire vault file ({} bytes).",
                std::fs::metadata(vault).map(|m| m.len()).unwrap_or(0)
            );
        }
        eprintln!("   This is IRREVERSIBLE. There is NO undo. There is NO recovery.");
        let expected = format!("DESTROY {}", vault.display());
        let typed: String = dialoguer::Input::new()
            .with_prompt(format!("Type literally `{expected}` to confirm"))
            .allow_empty(true)
            .interact_text()?;
        if typed != expected {
            return Err("aborted".into());
        }
    }
    let mut hf = OpenOptions::new().write(true).open(header_target)?;
    let mut buf = [0u8; HEADER_SIZE];
    OsRng.fill_bytes(&mut buf);
    hf.seek(SeekFrom::Start(0))?;
    hf.write_all(&buf)?;
    hf.flush()?;
    if wipe_data {
        let mut vf = OpenOptions::new().write(true).open(vault)?;
        let len = std::fs::metadata(vault)?.len();
        vf.seek(SeekFrom::Start(0))?;
        let mut chunk = vec![0u8; 1 << 20];
        let mut written = 0u64;
        while written < len {
            OsRng.fill_bytes(&mut chunk);
            let n = ((len - written) as usize).min(chunk.len());
            vf.write_all(&chunk[..n])?;
            written += n as u64;
        }
        let _ = vf.sync_all();
    }
    println!("done.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for the `LUKSBOX_TEST_FAST_KDF` bypass gating.
    /// In **release** builds the env var must be ignored entirely so a
    /// polluted shell or a malicious launcher can't downgrade the KDF.
    /// In **debug** builds (including `cargo test`) it must be honored
    /// so the test suite stays under a few minutes.
    ///
    /// Run with both `cargo test -p luksbox-cli --bin luksbox` and
    /// `cargo test -p luksbox-cli --bin luksbox --release` to exercise
    /// both branches of the cfg gate.
    #[test]
    fn fast_kdf_gate_matches_build_profile() {
        // SAFETY: this test mutates a process-global env var. Rust
        // 2024 marks env mutation as unsafe because of cross-thread
        // races; cargo runs tests on multiple threads but no other
        // test in this binary reads `LUKSBOX_TEST_FAST_KDF` from the
        // parent env (the integration tests in `tests/` set it on the
        // *child* process via `Command::env`, not on the parent), so
        // this is race-free in practice.
        let saved = std::env::var_os("LUKSBOX_TEST_FAST_KDF");
        unsafe { std::env::remove_var("LUKSBOX_TEST_FAST_KDF") };
        assert!(
            !test_fast_kdf_enabled(),
            "with env unset, bypass must be disabled in any profile",
        );
        unsafe { std::env::set_var("LUKSBOX_TEST_FAST_KDF", "1") };
        let with_var = test_fast_kdf_enabled();
        match saved {
            Some(v) => unsafe { std::env::set_var("LUKSBOX_TEST_FAST_KDF", v) },
            None => unsafe { std::env::remove_var("LUKSBOX_TEST_FAST_KDF") },
        }
        if cfg!(debug_assertions) {
            assert!(
                with_var,
                "debug build: LUKSBOX_TEST_FAST_KDF=1 must enable the bypass",
            );
        } else {
            assert!(
                !with_var,
                "release build: LUKSBOX_TEST_FAST_KDF must be compiled out \
                 (CVE-class regression - see kdf_params_for)",
            );
        }
    }
}
