// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Background-thread helpers. The egui app runs on the main thread and
//! must never block (touch prompts, Argon2id, file copies all need to
//! happen elsewhere). Each long op spawns a `std::thread`, returns a
//! `Receiver` the UI polls every frame.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, channel};
use std::thread;

use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use luksbox_core::{
    Argon2idParams, CipherSuite, FLAG_HIDE_SIZE_HEADER, FLAG_PAD_FILES_POW2, HEADER_SIZE, Header,
    SlotKind,
};
use luksbox_format::{Container, UnlockMaterial, anchor};
use luksbox_vfs::{InodeKind, Vfs};

// ---- helpers --------------------------------------------------------------

fn estr<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

pub fn cipher_label(s: CipherSuite) -> &'static str {
    match s {
        CipherSuite::Aes256Gcm => "AES-256-GCM",
        CipherSuite::Aes256GcmSiv => "AES-256-GCM-SIV",
        CipherSuite::ChaCha20Poly1305 => "ChaCha20-Poly1305",
    }
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Charset switches for the passphrase generator UI. Each switch adds a
/// disjoint subset to the selection alphabet; the final character pool
/// is the union of every selected switch.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PassgenOpts {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for PassgenOpts {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
        }
    }
}

impl PassgenOpts {
    pub fn charset(self) -> Vec<u8> {
        // Use ambiguous-safe subsets (no 0/O, 1/l/I) when both digits and
        // letters are on, easier to read aloud / type from paper.
        let mut s: Vec<u8> = Vec::with_capacity(96);
        if self.lowercase {
            s.extend_from_slice(b"abcdefghijkmnopqrstuvwxyz");
        }
        if self.uppercase {
            s.extend_from_slice(b"ABCDEFGHJKLMNPQRSTUVWXYZ");
        }
        if self.digits {
            s.extend_from_slice(b"23456789");
        }
        if self.symbols {
            s.extend_from_slice(b"!@#$%^&*-_=+?.,;:");
        }
        s
    }

    pub fn is_valid(self) -> bool {
        self.length >= 4
            && self.length <= 256
            && (self.lowercase || self.uppercase || self.digits || self.symbols)
    }

    /// Approximate entropy of the configured generator: `len * log2(|alphabet|)`.
    pub fn approx_bits(self) -> f64 {
        let n = self.charset().len() as f64;
        if n <= 1.0 {
            0.0
        } else {
            self.length as f64 * n.log2()
        }
    }
}

/// Generate a passphrase using the supplied options. Falls back to the
/// default opts if the supplied set is invalid (no charsets selected).
pub fn generate_passphrase_with(opts: &PassgenOpts) -> String {
    let opts = if opts.is_valid() {
        *opts
    } else {
        PassgenOpts::default()
    };
    let charset = opts.charset();
    let mut out = String::with_capacity(opts.length);
    let mut buf = [0u8; 64];
    let mut idx = buf.len();
    let modulo_bias_cutoff: u8 = (256 - (256 % charset.len())) as u8;
    while out.len() < opts.length {
        if idx >= buf.len() {
            OsRng.fill_bytes(&mut buf);
            idx = 0;
        }
        let b = buf[idx];
        idx += 1;
        // Reject-and-resample to avoid modulo bias for non-power-of-2 alphabets.
        if b >= modulo_bias_cutoff {
            continue;
        }
        out.push(charset[(b as usize) % charset.len()] as char);
    }
    out
}

/// Score a passphrase. Returns (0..=4 zxcvbn score, estimated bits).
/// Score interpretation:
///   0 = too guessable (instant)
///   1 = very guessable (online attack)
///   2 = somewhat guessable (online slow attack)
///   3 = safe (offline slow hash)
///   4 = very safe (offline slow hash + Argon2 buys decades)
pub fn passphrase_strength(s: &str) -> (u8, f64) {
    if s.is_empty() {
        return (0, 0.0);
    }
    let est = zxcvbn::zxcvbn(s, &[]);
    let score = est.score() as u8;
    let bits = (est.guesses() as f64).log2();
    (score, bits)
}

/// Enumerate every FIDO2 authenticator libfido2 can see right now.
/// Brand-agnostic: covers any CTAP2-compliant authenticator
/// (YubiKey, SoloKey, Nitrokey, Token2, OnlyKey, Trezor T, etc.) and
/// the Windows Hello platform authenticator (libfido2 exposes it as
/// a `winhello://` pseudo-device on Windows when the WinHello
/// bridge is built in).
///
/// The returned `(path, label)` pairs feed the GUI's device picker.
/// Empty vec = no authenticator visible right now (use that as the
/// presence-check; we no longer ship a single-device convenience
/// wrapper because the GUI always thinks in terms of the full list).
pub fn detect_fido2_devices() -> Vec<(String, String)> {
    #[cfg(feature = "hardware")]
    {
        luksbox_fido2::HidAuthenticator::detect_all()
            .map(|v| v.into_iter().map(|d| (d.path, d.label)).collect())
            .unwrap_or_default()
    }
    #[cfg(not(feature = "hardware"))]
    {
        Vec::new()
    }
}

// ---- selected FIDO2 device (process-wide) --------------------------------
//
// The GUI lets the user pick which authenticator to use when more
// than one is present (and Windows Hello often appears alongside a
// physical key). Rather than thread an `Option<String>` through the
// 7+ ops functions that touch FIDO2, we keep the selection in a
// small process-wide cell. The GUI calls `set_selected_fido2_device`
// when the dropdown changes; the ops helpers read it when they
// construct a `HidAuthenticator`. `None` means "fall back to the
// first device libfido2 enumerates" (legacy behavior).

use std::sync::Mutex;

static SELECTED_FIDO2_DEVICE: Mutex<Option<String>> = Mutex::new(None);

pub fn set_selected_fido2_device(path: Option<String>) {
    if let Ok(mut g) = SELECTED_FIDO2_DEVICE.lock() {
        *g = path;
    }
}

pub fn selected_fido2_device() -> Option<String> {
    SELECTED_FIDO2_DEVICE.lock().ok().and_then(|g| g.clone())
}

#[cfg(feature = "hardware")]
fn make_fido2_authenticator() -> luksbox_fido2::HidAuthenticator {
    match selected_fido2_device() {
        Some(path) => luksbox_fido2::HidAuthenticator::with_device(path),
        None => luksbox_fido2::HidAuthenticator::new(),
    }
}

// ---- background spawn ----------------------------------------------------

/// Spawn `f` on a background thread; return a Receiver for the result.
/// Caller polls with `try_recv` from the egui update loop.
pub fn spawn<T, F>(f: F) -> Receiver<Result<T, String>>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    let (tx, rx) = channel();
    thread::spawn(move || {
        let r = f();
        let _ = tx.send(r);
    });
    rx
}

// ---- types ----------------------------------------------------------------

#[derive(Clone)]
pub struct CreateOpts {
    pub path: PathBuf,
    pub header_path: Option<PathBuf>,
    pub cipher: CipherSuite,
    pub kind: SlotKindArg,
    pub passphrase: Option<Zeroizing<String>>,
    pub backup_passphrase: Option<Zeroizing<String>>,
    pub pin: Option<Zeroizing<String>>,
    pub pad_files: bool,
    pub hide_sizes: bool,
    pub anchor_path: Option<PathBuf>,
    /// For the 3-factor TPM combos (Tpm2Fido2 / HybridPqTpm2* /
    /// HybridPqTpm2Fido2*): when false (default), the create path
    /// goes through `create_vault_with_tpm_factors_only` which
    /// produces a SINGLE multi-factor keyslot, no passphrase
    /// fallback. When true, the legacy 2-slot path runs
    /// (passphrase at slot 0, multi-factor at slot 1) so the user
    /// has a recovery option if any factor is lost.
    pub enable_recovery_passphrase: bool,
    /// For `HybridPq`: where to write the user's secret `.kyber` seed
    /// file. Encrypted under the same passphrase.
    pub hybrid_kyber_path: Option<PathBuf>,
    /// Optional separate passphrase for encrypting the `.kyber` seed
    /// file at rest. When `None` or empty, falls back to
    /// `opts.passphrase` so the envelope passphrase doubles as the
    /// seed-file passphrase (the common case). Set when the user
    /// wants distinct passphrases for the two roles.
    pub hybrid_seed_pw: Option<Zeroizing<String>>,
    /// Argon2id strength preset for any passphrase-stretched keyslots
    /// in this vault (primary passphrase + backup passphrase + the
    /// passphrase-half of hybrid-pq slots). FIDO2-direct slots ignore.
    pub kdf: KdfStrength,
    /// Use a deniable header instead of the standard one. v1
    /// limitation: requires `kind == Passphrase` and `header_path ==
    /// None`. The cipher + Argon2 params live in `self.cipher` and
    /// `self.kdf` already; remembering them is the user's
    /// responsibility (without them the vault is unopenable).
    pub use_deniable: bool,
    /// On-disk format envelope for the new vault.
    /// `false`: v2 legacy (LBM2 + LUKSBOX1, inline chunk lists, no
    /// sidecar mirrors, ~10 GiB practical ceiling, NOT crash-safe,
    /// readable by pre-v0.3 LUKSbox binaries). Auto-upgrades to v0.2.1
    /// on first flush unless `LUKSBOX_FORMAT_V2=1` is set in the env.
    /// `true` (default): v0.2.1 format (LBM5 + LUKSBOX2 header +
    /// sidecar mirrors at `<vault>.lbx.{header,meta}-bak` for
    /// crash-safety recovery). Requires LUKSbox v0.2.1+ to open.
    /// Permanent for the vault.
    /// The boolean name predates the broader v0.2.1 envelope but is
    /// kept for API stability across the GUI -> ops boundary.
    pub use_v3_format: bool,
}

// Hand-written redacting Debug: `CreateOpts` carries up to four
// `Option<Zeroizing<String>>` secrets. The derived Debug would print
// them through `Zeroizing<String>`'s passthrough Debug, so a stray
// `dbg!(&opts)` would leak the passphrase/PIN. Show the identifying
// non-secret fields, redact every secret, and elide the rest with `..`
// so a future field can't silently become a leak here.
impl std::fmt::Debug for CreateOpts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateOpts")
            .field("path", &self.path)
            .field("kind", &self.kind)
            .field("use_deniable", &self.use_deniable)
            .field(
                "passphrase",
                &self.passphrase.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "backup_passphrase",
                &self.backup_passphrase.as_ref().map(|_| "<redacted>"),
            )
            .field("pin", &self.pin.as_ref().map(|_| "<redacted>"))
            .field(
                "hybrid_seed_pw",
                &self.hybrid_seed_pw.as_ref().map(|_| "<redacted>"),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotKindArg {
    Passphrase,
    Fido2,
    Fido2Direct,
    /// Hybrid passphrase + ML-KEM-768.
    HybridPq,
    /// Hybrid FIDO2 + ML-KEM-768.
    HybridPqFido2,
    /// Hybrid passphrase + ML-KEM-1024 (NIST category 5, ~AES-256 strength).
    HybridPq1024,
    /// Hybrid FIDO2 + ML-KEM-1024 (NIST category 5, ~AES-256 strength).
    HybridPq1024Fido2,
}

#[derive(Clone)]
pub struct UnlockOpts {
    pub path: PathBuf,
    pub header_path: Option<PathBuf>,
    pub anchor_path: Option<PathBuf>,
    pub method: UnlockMethod,
    pub passphrase: Option<Zeroizing<String>>,
    pub pin: Option<Zeroizing<String>>,
    /// For `UnlockMethod::HybridPq`: path to the user's `.kyber` seed.
    pub hybrid_kyber_path: Option<PathBuf>,
    /// Optional separate passphrase for decrypting the `.kyber` seed
    /// file. In v2 deniable mode the same passphrase commonly serves
    /// both roles (envelope discovery + seed decrypt), and this
    /// field is empty so the helper falls back to `opts.passphrase`.
    /// If the user set distinct passphrases at create time (e.g. via
    /// the HybridPq+TPM bootstrap which has a separate `seed_pw`
    /// field), they fill THIS field with the seed-file passphrase
    /// and leave `passphrase` for the envelope.
    pub hybrid_seed_pw: Option<Zeroizing<String>>,
    /// If true, the open flow uses `Container::open_with_passphrase_deniable`
    /// with `deniable_cipher` + `deniable_kdf` instead of the standard
    /// header-parse path. v1 requires `method == Passphrase`.
    pub use_deniable: bool,
    /// Cipher suite the deniable vault was created with. Required
    /// when `use_deniable == true`; ignored otherwise. Wrong values
    /// produce the same `OpaqueUnlockFailed` error as a wrong
    /// passphrase.
    pub deniable_cipher: CipherSuite,
    /// Argon2id strength preset the deniable vault was created with.
    /// Same wrong-value behaviour as `deniable_cipher`.
    pub deniable_kdf: KdfStrength,
    /// Open in tolerant recovery mode (read-only). When set,
    /// `Vfs::open` installs inodes whose chunk-list chain fails AEAD
    /// as zero-byte placeholders and continues, instead of refusing
    /// the whole vault. The resulting Vfs refuses flushes
    /// (`Error::ReadOnlyMount`) so the patched tree never overwrites
    /// the on-disk metadata. UI surfaces the broken-inode list via
    /// `OpenedVault::tolerated_inodes`. Use only when a normal open
    /// failed with `metadata blob deserialization failed`.
    pub recovery_mode: bool,
}

// Hand-written redacting Debug, same rationale as `CreateOpts`:
// `UnlockOpts` holds `passphrase`/`pin`/`hybrid_seed_pw` secrets that
// the derived Debug would print verbatim.
impl std::fmt::Debug for UnlockOpts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockOpts")
            .field("path", &self.path)
            .field("method", &self.method)
            .field("use_deniable", &self.use_deniable)
            .field("recovery_mode", &self.recovery_mode)
            .field(
                "passphrase",
                &self.passphrase.as_ref().map(|_| "<redacted>"),
            )
            .field("pin", &self.pin.as_ref().map(|_| "<redacted>"))
            .field(
                "hybrid_seed_pw",
                &self.hybrid_seed_pw.as_ref().map(|_| "<redacted>"),
            )
            .finish_non_exhaustive()
    }
}

// `Tpm2*` and `HybridPqTpm2*` variants are constructed only from
// Linux+hardware code paths (the corresponding ops functions are
// gated the same way). The enum is unconditionally defined so that
// non-Linux builds can still match on `UnlockMethod` without cfg
// noise at every match arm; allow `dead_code` so the otherwise-
// unused variants do not generate warnings on macOS/Windows.
#[cfg_attr(not(all(feature = "hardware", target_os = "linux")), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlockMethod {
    Passphrase,
    Fido2,
    HybridPq,
    HybridPqFido2,
    /// Unlock via the local Linux TPM 2.0 chip. Iterates the
    /// vault's `Tpm2Sealed` slots; first slot whose unsealed KEK
    /// unwraps the MVK wins.
    Tpm2,
    /// Unlock via a PIN-protected TPM 2.0 slot (`Tpm2SealedPin`).
    /// The PIN is supplied via `UnlockOpts::pin` and presented to
    /// the chip's `userAuth`; wrong PINs count toward the chip's
    /// dictionary-attack lockout.
    Tpm2Pin,
    /// Fused TPM + FIDO2 unlock: requires BOTH the local TPM AND a
    /// connected FIDO2 authenticator. Iterates the vault's
    /// `Tpm2Fido2` slots; per slot, drives the FIDO2 hmac_secret
    /// call with that slot's stored cred_id + hmac_salt, asks the
    /// TPM to unseal the slot's blob, and tries the unwrap.
    Tpm2Fido2,
    /// Hybrid TPM + ML-KEM-768 unlock. Requires the .kyber seed
    /// file + its passphrase + the local TPM.
    HybridPqTpm2,
    /// 3-factor: TPM + FIDO2 + ML-KEM-768.
    HybridPqTpm2Fido2,
    /// Unlock via the local macOS Secure Enclave. Iterates the
    /// vault's `SepSealed` / `SepSealedBiometric` slots; first slot
    /// whose unsealed shared secret unwraps the MVK wins. Biometric
    /// slots trigger a Touch ID prompt inside the enclave unseal.
    Sep,
    /// Hybrid Secure Enclave + ML-KEM unlock. Requires the .kyber
    /// seed file + its passphrase + the local Secure Enclave.
    HybridPqSep,
    /// Fused Secure Enclave + FIDO2 unlock (deniable mode). Requires
    /// both the local enclave AND the authenticator.
    SepFido2,
    /// Hybrid Secure Enclave + FIDO2 + ML-KEM unlock (deniable mode).
    /// Enclave + authenticator + `.kyber` seed.
    HybridPqSepFido2,
}

pub struct OpenedVault {
    pub vfs: Vfs,
    pub vault_path: PathBuf,
    pub header_path: Option<PathBuf>,
    pub anchor_path: Option<PathBuf>,
    pub cipher_label: String,
    pub has_fido2: bool,
    pub has_hybrid_pq: bool,
    pub has_tpm: bool,
    /// Set when a deniable-mode FIDO2 slot was just enrolled
    /// (create or add). Carries the cred_id + hmac_salt that the
    /// device returned - the user MUST save these externally
    /// because they're NOT stored on disk; without them the slot
    /// is unopenable. GUI surfaces this as a "recovery card"
    /// modal post-create / post-enroll.
    pub deniable_fido2_recovery: Option<DeniableFido2RecoveryInfo>,
    /// Set when a deniable-mode TPM slot was just enrolled. The
    /// path is where the .tpm-blob sidecar was written; the user
    /// MUST remember this path (or move the file elsewhere and
    /// remember where) to unlock later.
    pub deniable_tpm_blob_path: Option<PathBuf>,
    /// Tolerant-recovery report: which inodes had their chunk-list
    /// chain skipped during open. Empty for normal opens. Populated
    /// when `UnlockOpts::recovery_mode == true` and the vault had
    /// at least one chunk-list-block AEAD failure. The GUI surfaces
    /// this as a modal listing the broken file paths + original
    /// sizes after the open completes.
    pub tolerated_inodes: Vec<luksbox_vfs::ToleratedInode>,
}

#[derive(Debug, Clone)]
pub struct DeniableFido2RecoveryInfo {
    /// FIDO2 credential ID returned at enroll time. Typically
    /// 64-128 bytes of binary; surfaced to the GUI as hex.
    pub cred_id: Vec<u8>,
    /// 32-byte hmac-secret salt used at enroll time. Same hmac_salt
    /// must be supplied at unlock to derive the same hmac_secret
    /// output from the device.
    pub hmac_salt: [u8; 32],
}

// ---- create ----------------------------------------------------------------

/// Which TPM-bound keyslot to add as the second slot during a TPM-
/// bootstrap create. The `pin` field carries the TPM PIN for `Tpm2Pin`
/// or the FIDO2 PIN for `Tpm2Fido2` / `HybridPqTpm2Fido2`.
pub enum TpmBootstrapKind {
    Tpm2,
    Tpm2Pin {
        pin: zeroize::Zeroizing<String>,
    },
    Tpm2Fido2 {
        pin: zeroize::Zeroizing<String>,
    },
    /// Hybrid post-quantum + TPM (no FIDO2). The .kyber seed file is
    /// created alongside the vault; `kyber_path` is the destination,
    /// `seed_pw` encrypts the seed at rest, `kem_size` is 768 or 1024.
    HybridPqTpm2 {
        kyber_path: PathBuf,
        seed_pw: zeroize::Zeroizing<String>,
        kem_size: u16,
    },
    /// Three-factor: hybrid PQ + TPM + FIDO2. Same as `HybridPqTpm2`
    /// plus a FIDO2 PIN.
    HybridPqTpm2Fido2 {
        kyber_path: PathBuf,
        seed_pw: zeroize::Zeroizing<String>,
        pin: zeroize::Zeroizing<String>,
        kem_size: u16,
    },
}

/// Which Secure Enclave (macOS SEP) keyslot kind to bootstrap a new
/// vault with. Mirrors `TpmBootstrapKind`: the vault is created with
/// a backup passphrase first, then the SEP slot is enrolled and moved
/// to slot 0 (the passphrase stays as a recovery slot unless revoked).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub enum SepBootstrapKind {
    /// Plain Secure Enclave (no Touch ID prompt at unlock).
    Sep,
    /// Secure Enclave + Touch ID (biometric required at unlock).
    SepBiometric,
    /// Hybrid PQ + Secure Enclave. The .kyber seed file is created
    /// alongside the vault; `kyber_path` is the destination, `seed_pw`
    /// encrypts the seed at rest, `kem_size` is 768 or 1024.
    HybridPqSep {
        kyber_path: PathBuf,
        seed_pw: zeroize::Zeroizing<String>,
        kem_size: u16,
    },
    /// Fused Secure Enclave + FIDO2 / passphrase combo, optionally
    /// hybrid (ML-KEM 768/1024). Mirrors the CLI's
    /// `cmd_enroll_sep_fused`: the SEP supplies the machine-bound half
    /// and `factors` + `kem_size` decide which extra secrets are
    /// collected and required at every unlock. `pin` is the FIDO2 PIN
    /// (only used when `factors.has_fido2()`); `passphrase` is the slot
    /// passphrase (only used when `factors.has_passphrase()`);
    /// `kyber_path` + `seed_pw` are only used when `kem_size.is_some()`.
    SepFused {
        factors: SepFactors,
        kem_size: Option<u16>,
        pin: zeroize::Zeroizing<String>,
        passphrase: zeroize::Zeroizing<String>,
        kyber_path: Option<PathBuf>,
        seed_pw: zeroize::Zeroizing<String>,
    },
}

/// Which extra factors a fused Secure Enclave keyslot binds in
/// addition to the SEP itself. Mirrors the CLI's `SepFactors` so the
/// enroll/unlock factor sets stay in lockstep.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub enum SepFactors {
    /// SEP + FIDO2 authenticator.
    Fido2,
    /// SEP + Argon2id passphrase.
    Passphrase,
    /// SEP + FIDO2 + Argon2id passphrase.
    Fido2Passphrase,
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
impl SepFactors {
    pub fn has_fido2(self) -> bool {
        matches!(self, Self::Fido2 | Self::Fido2Passphrase)
    }
    pub fn has_passphrase(self) -> bool {
        matches!(self, Self::Passphrase | Self::Fido2Passphrase)
    }
    /// Resolve to the core `SlotKind` for this factor set + optional
    /// ML-KEM hybrid size (None = plain SEP, Some(768|1024) = hybrid).
    /// Only invoked from the hardware-gated `enroll_sep_fused`.
    #[cfg_attr(not(feature = "hardware"), allow(dead_code))]
    pub fn slot_kind(self, kem_size: Option<u16>) -> Result<SlotKind, String> {
        Ok(match (self, kem_size) {
            (Self::Fido2, None) => SlotKind::SepFido2,
            (Self::Passphrase, None) => SlotKind::SepPassphrase,
            (Self::Fido2Passphrase, None) => SlotKind::SepFido2Passphrase,
            (Self::Fido2, Some(768)) => SlotKind::HybridPqKemSepFido2,
            (Self::Fido2, Some(1024)) => SlotKind::HybridPqKem1024SepFido2,
            (Self::Passphrase, Some(768)) => SlotKind::HybridPqKemSepPassphrase,
            (Self::Passphrase, Some(1024)) => SlotKind::HybridPqKem1024SepPassphrase,
            (Self::Fido2Passphrase, Some(768)) => SlotKind::HybridPqKemSepFido2Passphrase,
            (Self::Fido2Passphrase, Some(1024)) => SlotKind::HybridPqKem1024SepFido2Passphrase,
            (_, Some(n)) => {
                return Err(format!("unsupported ML-KEM size {n} (use 768 or 1024)"));
            }
        })
    }
}

/// Probe the local macOS Secure Enclave without sealing anything.
/// Returns Ok(()) if the enclave is reachable, Err with a friendly
/// message otherwise. Used by the GUI's create / Add-keyslot click
/// handlers to fail fast on a SEP-bound flow BEFORE touching disk.
#[cfg(feature = "hardware")]
pub fn pre_check_sep() -> Result<(), String> {
    let _probe = luksbox_sep::SepSealer::new().map_err(|e| {
        format!(
            "Secure Enclave unavailable, refusing to start a SEP-bound flow that \
             wouldn't have its primary keyslot:\n\n{e}"
        )
    })?;
    Ok(())
}

#[cfg(not(feature = "hardware"))]
pub fn pre_check_sep() -> Result<(), String> {
    Err("Secure Enclave support not compiled in (rebuild with --features hardware)".into())
}

/// Probe the local TPM 2.0 chip without sealing anything. Returns
/// Ok(()) if the chip is reachable, Err with a friendly message if
/// the device is missing, permission-denied (user not in `tss`
/// group), or otherwise unhealthy. Used by the GUI's submit_create
/// and Add-keyslot click handlers to fail fast on a TPM-bound flow
/// BEFORE we touch disk or open a PIN modal.
#[cfg(feature = "hardware")]
pub fn pre_check_tpm() -> Result<(), String> {
    let _probe = luksbox_tpm::Tpm2Sealer::new().map_err(|e| {
        format!(
            "TPM 2.0 unavailable, refusing to start a TPM-bound flow that \
             wouldn't have its primary keyslot:\n\n{e}"
        )
    })?;
    Ok(())
}

#[cfg(not(feature = "hardware"))]
pub fn pre_check_tpm() -> Result<(), String> {
    Err("TPM 2.0 hardware support not compiled in".into())
}

/// Probe for any connected FIDO2 authenticator. Fresh enumeration
/// each call so a user who plugs their key in just before clicking
/// gets a successful pre-flight without waiting for the next
/// background re-probe tick.
#[cfg(feature = "hardware")]
pub fn pre_check_fido2() -> Result<(), String> {
    let devs = detect_fido2_devices();
    if devs.is_empty() {
        return Err(
            "No FIDO2 authenticator detected. Plug in your security key (any \
             CTAP2: YubiKey, Nitrokey, SoloKey, Token2, OnlyKey, etc.) or, on \
             Windows / supported macOS, enable the platform authenticator \
             (Windows Hello / Touch ID), then click Refresh."
                .into(),
        );
    }
    Ok(())
}

#[cfg(not(feature = "hardware"))]
pub fn pre_check_fido2() -> Result<(), String> {
    Err("FIDO2 hardware support not compiled in".into())
}

/// TPM-only create: a single-slot vault whose only keyslot is the
/// TPM 2.0 chip. NO passphrase fallback. If the chip dies (BIOS
/// reset / motherboard replacement / OS reinstall on platforms
/// without TPM persistence) the vault is permanently unrecoverable.
///
/// Caller has already confirmed the tradeoff via the "Skip bootstrap
/// passphrase" checkbox in the GUI / wizard.
#[cfg(all(feature = "hardware", target_os = "linux"))]
pub fn create_vault_tpm2_only(
    opts: CreateOpts,
    pin: Option<Zeroizing<String>>,
) -> Result<OpenedVault, String> {
    use luksbox_format::Container;
    use luksbox_tpm::Tpm2Sealer;
    use luksbox_vfs::Vfs;
    use zeroize::Zeroizing;

    let vault_path = opts.path.clone();
    let header_path = opts.header_path.clone();
    let anchor_path = opts.anchor_path.clone();
    let use_deniable = opts.use_deniable;
    let mut flags = 0u32;
    if opts.pad_files || opts.hide_sizes {
        flags |= FLAG_PAD_FILES_POW2;
    }
    if opts.hide_sizes {
        flags |= FLAG_HIDE_SIZE_HEADER;
    }

    // Open TPM context BEFORE allocating the vault file so a missing
    // chip / permission error doesn't leave a 0-byte .lbx behind.
    let mut sealer =
        Tpm2Sealer::new().map_err(|e| format!("could not open local TPM 2.0 device: {e}"))?;
    let mut kek = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(kek.as_mut_slice())
        .map_err(|e| format!("OS RNG failure generating TPM KEK: {e}"))?;
    let blob = match &pin {
        Some(p) if !p.is_empty() => sealer
            .seal_with_pin(&kek, Some(p.as_bytes()))
            .map_err(|e| format!("TPM seal: {e}"))?,
        Some(_) => return Err("PIN cannot be empty for the PIN-bound TPM kind".into()),
        None => sealer.seal(&kek).map_err(|e| format!("TPM seal: {e}"))?,
    };
    let blob_bytes = blob.to_bytes();

    // v2 deniable mode: embed the sealed blob in the slot envelope
    // (no more .tpm-blob sidecar) and create the vault with a
    // TpmPassphrase slot. v2 requires a passphrase as the envelope
    // discovery factor; pure-Tpm deniable no longer exists.
    let deniable_tpm_blob_path: Option<PathBuf> = None;
    let create_res = if use_deniable {
        use luksbox_format::deniable_header::DeniableMaterial;
        let pw = opts
            .passphrase
            .as_ref()
            .ok_or("passphrase required for v2 deniable TPM envelope discovery")?;
        let kdf_params = opts.kdf.params();
        let cred = luksbox_core::deniable::DeniableCredential::TpmPassphrase {
            passphrase: pw.as_bytes(),
            argon2: kdf_params,
            unsealed: &kek,
        };
        let material = DeniableMaterial {
            cred_id: Vec::new(),
            hmac_salt: None,
            tpm_blob: blob_bytes.clone(),
        };
        Container::create_with_credential_v2_deniable(
            &vault_path,
            header_path.as_deref(),
            opts.cipher,
            flags,
            0,
            &cred,
            &material,
        )
    } else if pin.is_some() {
        Container::create_with_tpm2_pin(
            &vault_path,
            header_path.as_deref(),
            opts.cipher,
            flags,
            &kek,
            &blob_bytes,
        )
    } else {
        Container::create_with_tpm2(
            &vault_path,
            header_path.as_deref(),
            opts.cipher,
            flags,
            &kek,
            &blob_bytes,
        )
    };
    let cont = match create_res {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::remove_file(&vault_path);
            if let Some(hp) = &header_path {
                let _ = std::fs::remove_file(hp);
            }
            if let Some(sc) = &deniable_tpm_blob_path {
                let _ = std::fs::remove_file(sc);
            }
            return Err(format!("TPM-only vault create failed: {e}"));
        }
    };

    let mut cont = cont;
    if let Some(ap) = anchor_path.as_ref()
        && let Err(e) = cont.init_anchor(ap.clone(), 1).map_err(estr)
    {
        drop(cont);
        let _ = std::fs::remove_file(&vault_path);
        let _ = std::fs::remove_file(ap);
        if let Some(sc) = &deniable_tpm_blob_path {
            let _ = std::fs::remove_file(sc);
        }
        return Err(format!("anchor init failed: {e}"));
    }
    let has_fido2 = header_has_fido2(&cont.header);
    let has_hybrid_pq = header_has_hybrid_pq(&cont.header);
    let has_tpm = header_has_tpm(&cont.header) || use_deniable;
    let cipher = cipher_label(cont.header.cipher_suite).to_string();
    let vfs = Vfs::open(cont).map_err(estr)?;
    Ok(OpenedVault {
        vfs,
        vault_path,
        header_path,
        anchor_path,
        cipher_label: cipher,
        has_fido2,
        has_hybrid_pq,
        has_tpm,
        deniable_fido2_recovery: None,
        deniable_tpm_blob_path,
        tolerated_inodes: Vec::new(),
    })
}

#[cfg(not(all(feature = "hardware", target_os = "linux")))]
pub fn create_vault_tpm2_only(
    _opts: CreateOpts,
    _pin: Option<Zeroizing<String>>,
) -> Result<OpenedVault, String> {
    Err("TPM 2.0 is Linux-only today; Windows TPM is tracked as a follow-up".into())
}

/// Deniable-mode single-slot path for the 3-factor TPM combos
/// (Tpm2Fido2, HybridPqTpm2, HybridPqTpm2Fido2). The vault has
/// exactly ONE deniable slot at index 0 carrying the multi-factor
/// `DeniableCredential`; no passphrase slot exists. This matches the
/// design intent of these combos ("all factors required at every
/// unlock"); the previous shape leaked an OR-attack path via the
/// passphrase slot.
///
/// Loss of any single factor permanently destroys the vault by
/// design - users picked these combos because they want AND-semantics.
///
/// `.tpm-blob` and `.hybrid` + `.kyber` sidecars are written as
/// usual; their presence at-rest tells an examiner which factors
/// were used, but each sidecar individually is either bound to the
/// TPM chip or encrypted under the seed-file passphrase.
#[cfg(all(feature = "hardware", target_os = "linux"))]
pub fn create_vault_with_tpm_factors_deniable(
    opts: CreateOpts,
    kind: TpmBootstrapKind,
) -> Result<OpenedVault, String> {
    use luksbox_format::Container;
    use luksbox_vfs::Vfs;

    let vault_path = opts.path.clone();
    let anchor_path = opts.anchor_path.clone();
    let cipher = opts.cipher;
    let mut flags = 0u32;
    if opts.pad_files || opts.hide_sizes {
        flags |= FLAG_PAD_FILES_POW2;
    }
    if opts.hide_sizes {
        flags |= FLAG_HIDE_SIZE_HEADER;
    }

    // v2 deniable: TPM sealed blob now lives inside the slot
    // envelope, so the only sidecars to track are .kyber / .hybrid
    // for hybrid-PQ variants. The .tpm-blob sidecar is gone.
    let mut sidecars_on_disk: Vec<PathBuf> = Vec::new();

    // v2 deniable: per-kind crypto setup; the FIDO2 cred_id / hmac_salt /
    // TPM blob are returned to be embedded in the slot envelope rather
    // than written to sidecars.
    let deniable_tpm_blob_path: Option<PathBuf> = None;
    let deniable_fido2_recovery: Option<DeniableFido2RecoveryInfo> = None;
    let mut hybrid_entries: Option<(luksbox_pq::PqParams, Vec<u8>, Vec<u8>)> = None;
    let mut kyber_to_write: Option<(
        PathBuf,
        zeroize::Zeroizing<[u8; luksbox_pq::SEED_LEN]>,
        Zeroizing<String>,
    )> = None;

    // v2 envelope passphrase: required for every variant.
    let envelope_pw = opts
        .passphrase
        .as_ref()
        .ok_or("passphrase required for v2 deniable TPM envelope discovery")?
        .clone();
    let kdf_params = opts.kdf.params();

    let (cont_res, _post) = match kind {
        TpmBootstrapKind::Tpm2 | TpmBootstrapKind::Tpm2Pin { .. } => {
            // Single-factor TPM is handled by create_vault_tpm2_only.
            // This function only sees the 3-factor combos.
            return Err(
                "internal: single-factor TPM kinds must go through create_vault_tpm2_only".into(),
            );
        }
        TpmBootstrapKind::Tpm2Fido2 { pin } => {
            use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
            use luksbox_format::deniable_header::DeniableMaterial;
            let (tpm_secret, tpm_blob_bytes) = tpm_seal_to_bytes_for_deniable(None)?;

            let mut auth = make_fido2_authenticator();
            let user_handle = random_user_handle().map_err(estr)?;
            let er = auth.enroll(RP_ID, &user_handle, Some(&pin)).map_err(estr)?;
            let cred_id = er.credential.id;
            let mut hmac_salt = [0u8; 32];
            OsRng
                .try_fill_bytes(&mut hmac_salt)
                .map_err(|e| format!("OS RNG failure: {e}"))?;
            let hmac_secret = auth
                .hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(&pin))
                .map_err(estr)?;

            let cred = luksbox_core::deniable::DeniableCredential::TpmFido2Passphrase {
                passphrase: envelope_pw.as_bytes(),
                argon2: kdf_params,
                unsealed: &tpm_secret,
                hmac_secret_output: &hmac_secret,
            };
            let material = DeniableMaterial {
                cred_id,
                hmac_salt: Some(hmac_salt),
                tpm_blob: tpm_blob_bytes,
            };
            let res = Container::create_with_credential_v2_deniable(
                &vault_path,
                None,
                cipher,
                flags,
                0,
                &cred,
                &material,
            );
            (res, ())
        }
        TpmBootstrapKind::HybridPqTpm2 {
            kyber_path,
            seed_pw,
            kem_size,
        } => {
            use luksbox_format::deniable_header::DeniableMaterial;
            use luksbox_pq::{encapsulate_with, keygen_with};
            let params = if kem_size == 1024 {
                luksbox_pq::PqParams::Ml1024
            } else {
                luksbox_pq::PqParams::Ml768
            };
            let (tpm_secret, tpm_blob_bytes) = tpm_seal_to_bytes_for_deniable(None)?;

            let (pk, seed) = keygen_with(params);
            let (ct, shared) = encapsulate_with(params, &pk).map_err(estr)?;
            hybrid_entries = Some((params, pk, ct));
            kyber_to_write = Some((kyber_path, seed, seed_pw));

            let cred = luksbox_core::deniable::DeniableCredential::HybridPqTpmPassphrase {
                passphrase: envelope_pw.as_bytes(),
                argon2: kdf_params,
                mlkem_shared: &shared,
                unsealed: &tpm_secret,
            };
            let material = DeniableMaterial {
                cred_id: Vec::new(),
                hmac_salt: None,
                tpm_blob: tpm_blob_bytes,
            };
            let res = Container::create_with_credential_v2_deniable(
                &vault_path,
                None,
                cipher,
                flags,
                0,
                &cred,
                &material,
            );
            (res, ())
        }
        TpmBootstrapKind::HybridPqTpm2Fido2 {
            kyber_path,
            seed_pw,
            pin,
            kem_size,
        } => {
            use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
            use luksbox_format::deniable_header::DeniableMaterial;
            use luksbox_pq::{encapsulate_with, keygen_with};
            let params = if kem_size == 1024 {
                luksbox_pq::PqParams::Ml1024
            } else {
                luksbox_pq::PqParams::Ml768
            };
            let (tpm_secret, tpm_blob_bytes) = tpm_seal_to_bytes_for_deniable(None)?;

            let mut auth = make_fido2_authenticator();
            let user_handle = random_user_handle().map_err(estr)?;
            let er = auth.enroll(RP_ID, &user_handle, Some(&pin)).map_err(estr)?;
            let cred_id = er.credential.id;
            let mut hmac_salt = [0u8; 32];
            OsRng
                .try_fill_bytes(&mut hmac_salt)
                .map_err(|e| format!("OS RNG failure: {e}"))?;
            let hmac_secret = auth
                .hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(&pin))
                .map_err(estr)?;

            let (pk, seed) = keygen_with(params);
            let (ct, shared) = encapsulate_with(params, &pk).map_err(estr)?;
            hybrid_entries = Some((params, pk, ct));
            kyber_to_write = Some((kyber_path, seed, seed_pw));

            let cred = luksbox_core::deniable::DeniableCredential::HybridPqTpmFido2Passphrase {
                passphrase: envelope_pw.as_bytes(),
                argon2: kdf_params,
                mlkem_shared: &shared,
                unsealed: &tpm_secret,
                hmac_secret_output: &hmac_secret,
            };
            let material = DeniableMaterial {
                cred_id,
                hmac_salt: Some(hmac_salt),
                tpm_blob: tpm_blob_bytes,
            };
            let res = Container::create_with_credential_v2_deniable(
                &vault_path,
                None,
                cipher,
                flags,
                0,
                &cred,
                &material,
            );
            (res, ())
        }
    };
    let cont = match cont_res {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::remove_file(&vault_path);
            for sc in &sidecars_on_disk {
                let _ = std::fs::remove_file(sc);
            }
            return Err(format!("deniable 3-factor vault create failed: {e}"));
        }
    };

    // Write sidecars now that the vault exists.
    if let Some((params, pk, ct)) = hybrid_entries {
        use luksbox_format::hybrid_sidecar::{self, HybridEntry};
        let sidecar = hybrid_sidecar::sidecar_path(&vault_path);
        if let Err(e) = hybrid_sidecar::write(
            &sidecar,
            &[HybridEntry {
                slot_idx: 0,
                level: params,
                pubkey: pk,
                ciphertext: ct,
            }],
        ) {
            drop(cont);
            let _ = std::fs::remove_file(&vault_path);
            for sc in &sidecars_on_disk {
                let _ = std::fs::remove_file(sc);
            }
            let _ = std::fs::remove_file(&sidecar);
            return Err(format!("hybrid sidecar write: {e}"));
        }
        sidecars_on_disk.push(sidecar);
    }
    if let Some((kyber_path, seed, seed_pw)) = kyber_to_write {
        use luksbox_pq::seed_file;
        if let Err(e) = seed_file::write(
            &kyber_path,
            &seed,
            seed_pw.as_bytes(),
            seed_file::KdfParams::default(),
        ) {
            drop(cont);
            let _ = std::fs::remove_file(&vault_path);
            for sc in &sidecars_on_disk {
                let _ = std::fs::remove_file(sc);
            }
            return Err(format!(".kyber write: {e}"));
        }
    }

    let mut cont = cont;
    if let Some(ap) = anchor_path.as_ref()
        && let Err(e) = cont.init_anchor(ap.clone(), 1).map_err(estr)
    {
        drop(cont);
        let _ = std::fs::remove_file(&vault_path);
        for sc in &sidecars_on_disk {
            let _ = std::fs::remove_file(sc);
        }
        let _ = std::fs::remove_file(ap);
        return Err(format!("anchor init failed: {e}"));
    }
    let cipher_lbl = cipher_label(cont.header.cipher_suite).to_string();
    let has_fido2 = deniable_fido2_recovery.is_some();
    let has_hybrid_pq = !sidecars_on_disk.is_empty()
        && sidecars_on_disk
            .iter()
            .any(|p| p.extension().is_some_and(|e| e == "hybrid"));
    let vfs = Vfs::open(cont).map_err(estr)?;
    Ok(OpenedVault {
        vfs,
        vault_path,
        header_path: opts.header_path,
        anchor_path,
        cipher_label: cipher_lbl,
        has_fido2,
        has_hybrid_pq,
        has_tpm: true,
        deniable_fido2_recovery,
        deniable_tpm_blob_path,
        tolerated_inodes: Vec::new(),
    })
}

#[cfg(not(all(feature = "hardware", target_os = "linux")))]
pub fn create_vault_with_tpm_factors_deniable(
    _opts: CreateOpts,
    _kind: TpmBootstrapKind,
) -> Result<OpenedVault, String> {
    Err("TPM 2.0 is Linux-only today; Windows TPM is tracked as a follow-up".into())
}

/// Non-deniable single-slot path for the 3-factor TPM combos. The
/// vault has exactly ONE keyslot at index 0 carrying the multi-factor
/// credential. No passphrase fallback - loss of any factor is
/// unrecoverable by design (this is the user's opt-out from the
/// "passphrase as default recovery" pattern, see
/// docs/CRYPTO_SPEC.md).
///
/// Mirrors `create_vault_with_tpm_factors_deniable` but uses the new
/// non-deniable `Container::create_with_*` constructors and writes
/// sidecars at the standard non-deniable paths.
#[cfg(all(feature = "hardware", target_os = "linux"))]
pub fn create_vault_with_tpm_factors_only(
    opts: CreateOpts,
    kind: TpmBootstrapKind,
) -> Result<OpenedVault, String> {
    use luksbox_format::Container;
    use luksbox_vfs::Vfs;

    let vault_path = opts.path.clone();
    let header_path = opts.header_path.clone();
    let anchor_path = opts.anchor_path.clone();
    let cipher = opts.cipher;
    let mut flags = 0u32;
    if opts.pad_files || opts.hide_sizes {
        flags |= FLAG_PAD_FILES_POW2;
    }
    if opts.hide_sizes {
        flags |= FLAG_HIDE_SIZE_HEADER;
    }

    let mut sidecars_on_disk: Vec<PathBuf> = Vec::new();
    let mut hybrid_entries: Option<(luksbox_pq::PqParams, Vec<u8>, Vec<u8>)> = None;
    let mut kyber_to_write: Option<(
        PathBuf,
        zeroize::Zeroizing<[u8; luksbox_pq::SEED_LEN]>,
        Zeroizing<String>,
    )> = None;

    let cont_res = match kind {
        TpmBootstrapKind::Tpm2 | TpmBootstrapKind::Tpm2Pin { .. } => {
            return Err(
                "internal: single-factor TPM kinds must go through create_vault_tpm2_only".into(),
            );
        }
        TpmBootstrapKind::Tpm2Fido2 { pin } => {
            use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
            use luksbox_tpm::Tpm2Sealer;
            let mut sealer = Tpm2Sealer::new()
                .map_err(|e| format!("could not open local TPM 2.0 device: {e}"))?;
            let mut tpm_unsealed = Zeroizing::new([0u8; 32]);
            OsRng
                .try_fill_bytes(tpm_unsealed.as_mut_slice())
                .map_err(|e| format!("OS RNG: {e}"))?;
            let blob = sealer
                .seal(&tpm_unsealed)
                .map_err(|e| format!("TPM seal: {e}"))?;

            let mut auth = make_fido2_authenticator();
            let user_handle = random_user_handle().map_err(estr)?;
            let er = auth.enroll(RP_ID, &user_handle, Some(&pin)).map_err(estr)?;
            let cred_id = er.credential.id;
            let mut hmac_salt = [0u8; 32];
            OsRng
                .try_fill_bytes(&mut hmac_salt)
                .map_err(|e| format!("OS RNG: {e}"))?;
            let hmac_secret = auth
                .hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(&pin))
                .map_err(estr)?;

            Container::create_with_tpm2_fido2(
                &vault_path,
                header_path.as_deref(),
                cipher,
                flags,
                &tpm_unsealed,
                &hmac_secret,
                &blob.to_bytes(),
                &cred_id,
                hmac_salt,
            )
        }
        TpmBootstrapKind::HybridPqTpm2 {
            kyber_path,
            seed_pw,
            kem_size,
        } => {
            use luksbox_pq::{encapsulate_with, keygen_with};
            use luksbox_tpm::Tpm2Sealer;
            let params = if kem_size == 1024 {
                luksbox_pq::PqParams::Ml1024
            } else {
                luksbox_pq::PqParams::Ml768
            };
            let mut sealer = Tpm2Sealer::new()
                .map_err(|e| format!("could not open local TPM 2.0 device: {e}"))?;
            let mut kek = Zeroizing::new([0u8; 32]);
            OsRng
                .try_fill_bytes(kek.as_mut_slice())
                .map_err(|e| format!("OS RNG: {e}"))?;
            let blob = sealer.seal(&kek).map_err(|e| format!("TPM seal: {e}"))?;

            let (pk, seed) = keygen_with(params);
            let (ct, shared) = encapsulate_with(params, &pk).map_err(estr)?;
            hybrid_entries = Some((params, pk, ct));
            kyber_to_write = Some((kyber_path, seed, seed_pw));

            if params == luksbox_pq::PqParams::Ml1024 {
                Container::create_with_hybrid_pq_1024_tpm2(
                    &vault_path,
                    header_path.as_deref(),
                    cipher,
                    flags,
                    &kek,
                    &shared,
                    &blob.to_bytes(),
                )
            } else {
                Container::create_with_hybrid_pq_tpm2(
                    &vault_path,
                    header_path.as_deref(),
                    cipher,
                    flags,
                    &kek,
                    &shared,
                    &blob.to_bytes(),
                )
            }
        }
        TpmBootstrapKind::HybridPqTpm2Fido2 {
            kyber_path,
            seed_pw,
            pin,
            kem_size,
        } => {
            use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
            use luksbox_pq::{encapsulate_with, keygen_with};
            use luksbox_tpm::Tpm2Sealer;
            let params = if kem_size == 1024 {
                luksbox_pq::PqParams::Ml1024
            } else {
                luksbox_pq::PqParams::Ml768
            };
            let mut sealer = Tpm2Sealer::new()
                .map_err(|e| format!("could not open local TPM 2.0 device: {e}"))?;
            let mut tpm_unsealed = Zeroizing::new([0u8; 32]);
            OsRng
                .try_fill_bytes(tpm_unsealed.as_mut_slice())
                .map_err(|e| format!("OS RNG: {e}"))?;
            let blob = sealer
                .seal(&tpm_unsealed)
                .map_err(|e| format!("TPM seal: {e}"))?;

            let mut auth = make_fido2_authenticator();
            let user_handle = random_user_handle().map_err(estr)?;
            let er = auth.enroll(RP_ID, &user_handle, Some(&pin)).map_err(estr)?;
            let cred_id = er.credential.id;
            let mut hmac_salt = [0u8; 32];
            OsRng
                .try_fill_bytes(&mut hmac_salt)
                .map_err(|e| format!("OS RNG: {e}"))?;
            let hmac_secret = auth
                .hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(&pin))
                .map_err(estr)?;

            let (pk, seed) = keygen_with(params);
            let (ct, shared) = encapsulate_with(params, &pk).map_err(estr)?;
            hybrid_entries = Some((params, pk, ct));
            kyber_to_write = Some((kyber_path, seed, seed_pw));

            if params == luksbox_pq::PqParams::Ml1024 {
                Container::create_with_hybrid_pq_1024_tpm2_fido2(
                    &vault_path,
                    header_path.as_deref(),
                    cipher,
                    flags,
                    &tpm_unsealed,
                    &hmac_secret,
                    &shared,
                    &blob.to_bytes(),
                    &cred_id,
                    hmac_salt,
                )
            } else {
                Container::create_with_hybrid_pq_tpm2_fido2(
                    &vault_path,
                    header_path.as_deref(),
                    cipher,
                    flags,
                    &tpm_unsealed,
                    &hmac_secret,
                    &shared,
                    &blob.to_bytes(),
                    &cred_id,
                    hmac_salt,
                )
            }
        }
    };

    let cont = match cont_res {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::remove_file(&vault_path);
            if let Some(hp) = &header_path {
                let _ = std::fs::remove_file(hp);
            }
            return Err(format!("3-factor vault create failed: {e}"));
        }
    };

    if let Some((params, pk, ct)) = hybrid_entries {
        use luksbox_format::hybrid_sidecar::{self, HybridEntry};
        let sidecar = hybrid_sidecar::sidecar_path(&vault_path);
        if let Err(e) = hybrid_sidecar::write(
            &sidecar,
            &[HybridEntry {
                slot_idx: 0,
                level: params,
                pubkey: pk,
                ciphertext: ct,
            }],
        ) {
            drop(cont);
            let _ = std::fs::remove_file(&vault_path);
            let _ = std::fs::remove_file(&sidecar);
            return Err(format!("hybrid sidecar write: {e}"));
        }
        sidecars_on_disk.push(sidecar);
    }
    if let Some((kyber_path, seed, seed_pw)) = kyber_to_write {
        use luksbox_pq::seed_file;
        if let Err(e) = seed_file::write(
            &kyber_path,
            &seed,
            seed_pw.as_bytes(),
            seed_file::KdfParams::default(),
        ) {
            drop(cont);
            let _ = std::fs::remove_file(&vault_path);
            for sc in &sidecars_on_disk {
                let _ = std::fs::remove_file(sc);
            }
            return Err(format!(".kyber write: {e}"));
        }
    }

    let mut cont = cont;
    if let Some(ap) = anchor_path.as_ref()
        && let Err(e) = cont.init_anchor(ap.clone(), 1).map_err(estr)
    {
        drop(cont);
        let _ = std::fs::remove_file(&vault_path);
        for sc in &sidecars_on_disk {
            let _ = std::fs::remove_file(sc);
        }
        let _ = std::fs::remove_file(ap);
        return Err(format!("anchor init failed: {e}"));
    }

    let cipher_lbl = cipher_label(cont.header.cipher_suite).to_string();
    let has_fido2 = header_has_fido2(&cont.header);
    let has_hybrid_pq = header_has_hybrid_pq(&cont.header);
    let has_tpm = header_has_tpm(&cont.header);
    let vfs = Vfs::open(cont).map_err(estr)?;
    Ok(OpenedVault {
        vfs,
        vault_path,
        header_path,
        anchor_path,
        cipher_label: cipher_lbl,
        has_fido2,
        has_hybrid_pq,
        has_tpm,
        deniable_fido2_recovery: None,
        deniable_tpm_blob_path: None,
        tolerated_inodes: Vec::new(),
    })
}

#[cfg(not(all(feature = "hardware", target_os = "linux")))]
pub fn create_vault_with_tpm_factors_only(
    _opts: CreateOpts,
    _kind: TpmBootstrapKind,
) -> Result<OpenedVault, String> {
    Err("TPM 2.0 is Linux-only today; Windows TPM is tracked as a follow-up".into())
}

/// Atomic "create vault + add TPM keyslot" worker. Either both
/// steps succeed and the returned `OpenedVault` has the backup
/// passphrase in slot 0 + the chosen TPM kind in slot 1, OR an Err
/// is returned and any partial files (`.lbx`, detached header,
/// anchor, `.lbx.hybrid`) are deleted before the error propagates.
///
/// Without this atomic shape, a TPM enroll failure (e.g. /dev/tpm0
/// permission denied) would leave a passphrase-only vault on disk -
/// silently giving the user the weak fallback they did NOT ask for.
pub fn create_vault_with_tpm_bootstrap(
    opts: CreateOpts,
    kind: TpmBootstrapKind,
) -> Result<OpenedVault, String> {
    // Deniable mode redirect for the 3-factor combos: skip the
    // passphrase-bootstrap shape entirely and create a single-slot
    // deniable vault with the multi-factor DeniableCredential at slot
    // 0. The user's design choice for deniable (see
    // docs/DENIABLE_HEADER.md): the invisible-second-slot foot-gun
    // hurts more in deniable mode than the lost-vault-if-factor-lost
    // tradeoff.
    if opts.use_deniable
        && matches!(
            kind,
            TpmBootstrapKind::Tpm2Fido2 { .. }
                | TpmBootstrapKind::HybridPqTpm2 { .. }
                | TpmBootstrapKind::HybridPqTpm2Fido2 { .. }
        )
    {
        return create_vault_with_tpm_factors_deniable(opts, kind);
    }

    // Non-deniable single-slot path for the 3-factor combos: default
    // OFF for recovery passphrase. When the user explicitly opts in
    // by ticking "Enable recovery passphrase", fall through to the
    // legacy 2-slot bootstrap path below.
    if !opts.use_deniable
        && !opts.enable_recovery_passphrase
        && matches!(
            kind,
            TpmBootstrapKind::Tpm2Fido2 { .. }
                | TpmBootstrapKind::HybridPqTpm2 { .. }
                | TpmBootstrapKind::HybridPqTpm2Fido2 { .. }
        )
    {
        return create_vault_with_tpm_factors_only(opts, kind);
    }

    let vault_path = opts.path.clone();
    let header_path = opts.header_path.clone();
    let anchor_path = opts.anchor_path.clone();
    // v2 deniable enroll needs these AFTER opts is consumed by
    // create_vault; capture them up-front.
    let bootstrap_pw_owned = opts.passphrase.clone().unwrap_or_default();
    let bootstrap_argon2_owned = opts.kdf.params();

    let mut opened = create_vault(opts)?;
    // Track the .kyber path for the hybrid-PQ TPM bootstrap variants so
    // we can delete it on rollback (the vault file + sidecar cleanup is
    // unconditional, but .kyber only exists for hybrid kinds).
    let kyber_to_clean: Option<PathBuf> = match &kind {
        TpmBootstrapKind::HybridPqTpm2 { kyber_path, .. }
        | TpmBootstrapKind::HybridPqTpm2Fido2 { kyber_path, .. } => Some(kyber_path.clone()),
        _ => None,
    };
    // Deniable mode routes the TPM enroll through the
    // *_deniable helpers, which seal the TPM secret to a sidecar
    // file and use DeniableCredential variants. Standard mode
    // uses the existing per-kind enroll fns that store the
    // sealed blob inside the slot bytes.
    let is_deniable = opened.vfs.container().is_deniable();
    // v2 deniable: TPM blob is embedded in the slot envelope; no
    // sidecar to track for the post-enroll OpenedVault.
    let deniable_tpm_blob_path: Option<PathBuf> = None;
    let deniable_tpm_fido2_recovery: Option<DeniableFido2RecoveryInfo> = None;
    // v2 deniable bootstrap enroll: reuse the create-time passphrase
    // (captured into bootstrap_pw_owned before opts was moved) as the
    // new TPM-bearing slot's envelope passphrase. Same Argon2id params.
    // Annotated `#[allow]` because the consumers below are all
    // Linux-only via cfg gates; on macOS/Windows the bindings are
    // technically unused but kept for symmetry with the dispatch.
    #[allow(unused_variables)]
    let bootstrap_pw = bootstrap_pw_owned.as_str();
    #[allow(unused_variables)]
    let bootstrap_argon2 = bootstrap_argon2_owned;
    let enroll_result: Result<usize, String> = match (kind, is_deniable) {
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        (TpmBootstrapKind::Tpm2, true) => {
            // Slot 1: the admin's deniable passphrase is at slot 0,
            // TPM lands at slot 1 (matches the standard TPM
            // bootstrap convention).
            enroll_tpm2_deniable(&mut opened.vfs, 1, bootstrap_pw, bootstrap_argon2, None)
        }
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        (TpmBootstrapKind::Tpm2Pin { pin }, true) => enroll_tpm2_deniable(
            &mut opened.vfs,
            1,
            bootstrap_pw,
            bootstrap_argon2,
            Some(pin.as_bytes()),
        ),
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        (TpmBootstrapKind::Tpm2Fido2 { pin }, true) => {
            enroll_tpm2_fido2_deniable(&mut opened.vfs, 1, &pin, bootstrap_pw, bootstrap_argon2)
        }
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        (
            TpmBootstrapKind::HybridPqTpm2 {
                kyber_path,
                seed_pw,
                kem_size,
            },
            true,
        ) => {
            let params = if kem_size == 1024 {
                luksbox_pq::PqParams::Ml1024
            } else {
                luksbox_pq::PqParams::Ml768
            };
            enroll_hybrid_pq_tpm2_deniable(
                &mut opened.vfs,
                1,
                &vault_path,
                &kyber_path,
                &seed_pw,
                bootstrap_pw,
                bootstrap_argon2,
                params,
            )
        }
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        (
            TpmBootstrapKind::HybridPqTpm2Fido2 {
                kyber_path,
                seed_pw,
                pin,
                kem_size,
            },
            true,
        ) => {
            let params = if kem_size == 1024 {
                luksbox_pq::PqParams::Ml1024
            } else {
                luksbox_pq::PqParams::Ml768
            };
            enroll_hybrid_pq_tpm2_fido2_deniable(
                &mut opened.vfs,
                1,
                &vault_path,
                &kyber_path,
                &seed_pw,
                &pin,
                bootstrap_pw,
                bootstrap_argon2,
                params,
            )
        }
        (TpmBootstrapKind::Tpm2, false) => enroll_tpm2(&mut opened.vfs),
        (TpmBootstrapKind::Tpm2Pin { pin }, false) => enroll_tpm2_pin(&mut opened.vfs, &pin),
        (TpmBootstrapKind::Tpm2Fido2 { pin }, false) => enroll_tpm2_fido2(&mut opened.vfs, &pin),
        (
            TpmBootstrapKind::HybridPqTpm2 {
                kyber_path,
                seed_pw,
                kem_size,
            },
            false,
        ) => enroll_hybrid_pq_tpm2(
            &mut opened.vfs,
            &vault_path,
            &kyber_path,
            &seed_pw,
            kem_size,
        ),
        (
            TpmBootstrapKind::HybridPqTpm2Fido2 {
                kyber_path,
                seed_pw,
                pin,
                kem_size,
            },
            false,
        ) => enroll_hybrid_pq_tpm2_fido2(
            &mut opened.vfs,
            &vault_path,
            &kyber_path,
            &seed_pw,
            &pin,
            kem_size,
        ),
        // Catch-all for platforms where hardware features are
        // off (no `feature = "hardware"`) - the per-kind arms
        // above are cfg-gated to Linux+hardware, so on other
        // platforms TPM bootstrap is rejected with a clear
        // message.
        #[cfg(not(all(feature = "hardware", target_os = "linux")))]
        _ => Err("TPM 2.0 is Linux-only today; Windows TPM is tracked as a follow-up".into()),
    };

    let tpm_idx = match enroll_result {
        Ok(idx) => idx,
        Err(e) => {
            drop(opened);
            let _ = std::fs::remove_file(&vault_path);
            if let Some(hp) = &header_path {
                let _ = std::fs::remove_file(hp);
            }
            if let Some(ap) = &anchor_path {
                let _ = std::fs::remove_file(ap);
            }
            let sidecar = luksbox_format::hybrid_sidecar::sidecar_path(&vault_path);
            let _ = std::fs::remove_file(&sidecar);
            if let Some(kp) = &kyber_to_clean {
                let _ = std::fs::remove_file(kp);
            }
            return Err(format!("TPM enroll failed; vault create rolled back: {e}"));
        }
    };

    // Move the TPM slot to index 0 so the slot-list view shows TPM as
    // the primary keyslot and the backup passphrase as a numbered
    // backup. Two cases to handle:
    //   1. Plain TPM kinds: just swap slot 0 (passphrase) with the
    //      TPM slot at `tpm_idx`. The per-slot AAD doesn't include the
    //      slot index (it covers slot bytes + header_salt), so the
    //      swap is safe; both slots' wrapped MVKs stay valid.
    //   2. Hybrid-PQ TPM kinds: same swap, plus rewrite the
    //      `<vault>.lbx.hybrid` sidecar entry so its `slot_idx` field
    //      reflects the new index. The sidecar's `find()` looks up
    //      entries by slot_idx, so a stale index would silently
    //      desync the entry from the slot.
    // Skip the slot-presentation swap in deniable mode. swap_slots
    // only rearranges the SYNTHETIC Header.keyslots (which is all
    // Empty in deniable mode anyway); the actual deniable slot
    // bytes were already written at the requested index by
    // enroll_credential_deniable, and presenting "TPM as slot 0,
    // passphrase as backup slot N" doesn't apply to deniable
    // vaults (whose slot table is opaque to outsiders by design).
    if tpm_idx > 0 && !is_deniable {
        let cont = opened.vfs.container_mut();
        if let Err(e) = cont.swap_slots(0, tpm_idx) {
            return Err(format!("post-enroll swap_slots(0, {tpm_idx}) failed: {e}"));
        }
        // For hybrid-PQ TPM kinds, fix the sidecar's slot_idx too.
        if let Some(kp) = &kyber_to_clean {
            // .kyber path is the marker for hybrid-PQ kinds; sidecar
            // path is derived from the vault path independently.
            let _ = kp; // suppress unused-warning if cfg drops the helper
            let sidecar = luksbox_format::hybrid_sidecar::sidecar_path(&vault_path);
            if sidecar.exists()
                && let Ok(mut entries) = luksbox_format::hybrid_sidecar::read(&sidecar)
            {
                for e in &mut entries {
                    if e.slot_idx as usize == tpm_idx {
                        e.slot_idx = 0;
                    } else if e.slot_idx == 0 {
                        // Defensive: the swap target was 0, but
                        // bootstrap creates slot 0 as a non-hybrid
                        // passphrase, so there shouldn't be a slot_idx=0
                        // entry to relocate. Leave as-is; the parser
                        // would have rejected duplicates anyway.
                    }
                }
                let _ = luksbox_format::hybrid_sidecar::write_with_binding(
                    &sidecar,
                    &entries,
                    cont.header_salt(),
                );
            }
        }
        if let Err(e) = cont.persist_header() {
            return Err(format!("post-swap persist_header failed: {e}"));
        }
    }

    // Surface deniable-TPM bootstrap recovery info on the returned
    // OpenedVault so the GUI can display the .tpm-blob path + any
    // FIDO2 cred_id/hmac_salt that the bootstrap enroll produced.
    opened.has_tpm = true;
    if let Some(p) = deniable_tpm_blob_path {
        opened.deniable_tpm_blob_path = Some(p);
    }
    if let Some(r) = deniable_tpm_fido2_recovery {
        opened.deniable_fido2_recovery = Some(r);
    }
    Ok(opened)
}

/// Create a vault with a bootstrap passphrase, then immediately add
/// the chosen Secure Enclave slot. Mirrors
/// `create_vault_with_tpm_bootstrap` (recovery-friendly default): a SEP
/// slot can't be slot 0, so we bootstrap with the form passphrase,
/// enroll the SEP slot at slot 1, then swap it to slot 0 and keep the
/// passphrase as a backup recovery slot. On enroll failure the whole
/// vault is rolled back so we never leave a passphrase-only orphan.
pub fn create_vault_with_sep_bootstrap(
    opts: CreateOpts,
    kind: SepBootstrapKind,
) -> Result<OpenedVault, String> {
    let vault_path = opts.path.clone();
    let header_path = opts.header_path.clone();
    let anchor_path = opts.anchor_path.clone();

    // Deniable mode: SEP rides as a `SepPassphrase` deniable credential
    // (the macOS analog of TPM+passphrase), created directly with the
    // slot envelope rather than the standard create-then-enroll path
    // (deniable slots are fixed at creation, so post-create enroll_sep
    // is refused). Only plain / biometric SEP is supported; the fused /
    // hybrid SEP kinds have no deniable credential variant yet.
    if opts.use_deniable {
        return create_sep_passphrase_deniable(opts, kind);
    }

    let mut opened = create_vault(opts)?;
    // Track the .kyber path for the hybrid-PQ SEP variant so we can
    // delete it on rollback.
    let kyber_to_clean: Option<PathBuf> = match &kind {
        SepBootstrapKind::HybridPqSep { kyber_path, .. } => Some(kyber_path.clone()),
        SepBootstrapKind::SepFused { kyber_path, .. } => kyber_path.clone(),
        _ => None,
    };
    let is_hybrid = match &kind {
        SepBootstrapKind::HybridPqSep { .. } => true,
        SepBootstrapKind::SepFused { kem_size, .. } => kem_size.is_some(),
        _ => false,
    };

    let enroll_result: Result<usize, String> = match kind {
        SepBootstrapKind::Sep => enroll_sep(&mut opened.vfs, false),
        SepBootstrapKind::SepBiometric => enroll_sep(&mut opened.vfs, true),
        SepBootstrapKind::HybridPqSep {
            kyber_path,
            seed_pw,
            kem_size,
        } => enroll_hybrid_pq_sep(&mut opened.vfs, &vault_path, &kyber_path, &seed_pw, kem_size),
        SepBootstrapKind::SepFused {
            factors,
            kem_size,
            pin,
            passphrase,
            kyber_path,
            seed_pw,
        } => enroll_sep_fused(
            &mut opened.vfs,
            &vault_path,
            factors,
            kem_size,
            &pin,
            &passphrase,
            kyber_path.as_deref(),
            &seed_pw,
        ),
    };

    let sep_idx = match enroll_result {
        Ok(idx) => idx,
        Err(e) => {
            drop(opened);
            let _ = std::fs::remove_file(&vault_path);
            if let Some(hp) = &header_path {
                let _ = std::fs::remove_file(hp);
            }
            if let Some(ap) = &anchor_path {
                let _ = std::fs::remove_file(ap);
            }
            let sidecar = luksbox_format::hybrid_sidecar::sidecar_path(&vault_path);
            let _ = std::fs::remove_file(&sidecar);
            if let Some(kp) = &kyber_to_clean {
                let _ = std::fs::remove_file(kp);
            }
            return Err(format!(
                "Secure Enclave enroll failed; vault create rolled back: {e}"
            ));
        }
    };

    // Move the SEP slot to index 0 (mirrors the TPM bootstrap). The
    // bootstrap path made exactly one slot (passphrase at 0) and the
    // SEP enroll took the next Empty, so swapping is unambiguous.
    if sep_idx > 0 {
        let cont = opened.vfs.container_mut();
        if let Err(e) = cont.swap_slots(0, sep_idx) {
            return Err(format!("post-enroll swap_slots(0, {sep_idx}) failed: {e}"));
        }
        if is_hybrid {
            let sidecar = luksbox_format::hybrid_sidecar::sidecar_path(&vault_path);
            if sidecar.exists()
                && let Ok(mut entries) = luksbox_format::hybrid_sidecar::read(&sidecar)
            {
                for e in &mut entries {
                    if e.slot_idx as usize == sep_idx {
                        e.slot_idx = 0;
                    }
                }
                let _ = luksbox_format::hybrid_sidecar::write_with_binding(
                    &sidecar,
                    &entries,
                    cont.header_salt(),
                );
            }
        }
        if let Err(e) = cont.persist_header() {
            return Err(format!("post-swap persist_header failed: {e}"));
        }
    }

    Ok(opened)
}

/// Create a deniable vault whose only slot is a macOS Secure Enclave +
/// passphrase credential (`DeniableCredential::SepPassphrase`). The SEP
/// `dataRepresentation` blob rides in the slot envelope (the same field
/// the TPM sealed blob uses); the passphrase is the envelope discovery
/// factor. Mirrors the plain-TPM deniable create path.
#[cfg(all(feature = "hardware", target_os = "macos"))]
fn create_sep_passphrase_deniable(
    opts: CreateOpts,
    kind: SepBootstrapKind,
) -> Result<OpenedVault, String> {
    use luksbox_format::deniable_header::DeniableMaterial;
    use luksbox_sep::SepSealer;

    if opts.header_path.is_some() {
        return Err("detached headers are not yet supported in deniable mode".into());
    }
    let envelope_pw = opts
        .passphrase
        .clone()
        .ok_or("a passphrase is required for the deniable Secure Enclave envelope")?;
    let kdf_params = opts.kdf.params();
    let mut flags = 0u32;
    if opts.pad_files || opts.hide_sizes {
        flags |= FLAG_PAD_FILES_POW2;
    }
    if opts.hide_sizes {
        flags |= FLAG_HIDE_SIZE_HEADER;
    }
    let vault_path = opts.path.clone();
    let anchor_path = opts.anchor_path.clone();
    let cipher = opts.cipher;

    let mut sidecars_on_disk: Vec<PathBuf> = Vec::new();
    let mut hybrid_entries: Option<(luksbox_pq::PqParams, Vec<u8>, Vec<u8>)> = None;
    let mut kyber_to_write: Option<(
        PathBuf,
        zeroize::Zeroizing<[u8; luksbox_pq::SEED_LEN]>,
        Zeroizing<String>,
    )> = None;
    let mut has_fido2 = false;

    // Seal under the enclave BEFORE creating any file so a missing /
    // unavailable enclave fails before we touch the disk.
    let mut sealer = SepSealer::new().map_err(|e| format!("{e}"))?;

    let cont_res = match kind {
        SepBootstrapKind::Sep | SepBootstrapKind::SepBiometric => {
            let biometric = matches!(kind, SepBootstrapKind::SepBiometric);
            let (sep_shared, blob) = if biometric {
                sealer
                    .seal_biometric()
                    .map_err(|e| format!("SEP seal (biometric): {e}"))?
            } else {
                sealer.seal().map_err(|e| format!("SEP seal: {e}"))?
            };
            let cred = luksbox_core::deniable::DeniableCredential::SepPassphrase {
                passphrase: envelope_pw.as_bytes(),
                argon2: kdf_params,
                sep_shared: &sep_shared,
            };
            let material = DeniableMaterial {
                cred_id: Vec::new(),
                hmac_salt: None,
                tpm_blob: blob.to_bytes(),
            };
            Container::create_with_credential_v2_deniable(
                &vault_path,
                None,
                cipher,
                flags,
                0,
                &cred,
                &material,
            )
        }
        SepBootstrapKind::HybridPqSep {
            kyber_path,
            seed_pw,
            kem_size,
        } => {
            use luksbox_pq::{encapsulate_with, keygen_with};
            let params = if kem_size == 1024 {
                luksbox_pq::PqParams::Ml1024
            } else {
                luksbox_pq::PqParams::Ml768
            };
            let (pk, seed) = keygen_with(params);
            let (ct, shared) = encapsulate_with(params, &pk).map_err(estr)?;
            let (sep_shared, blob) = sealer.seal().map_err(|e| format!("SEP seal: {e}"))?;
            hybrid_entries = Some((params, pk, ct));
            kyber_to_write = Some((kyber_path, seed, seed_pw));
            let cred = luksbox_core::deniable::DeniableCredential::HybridPqSepPassphrase {
                passphrase: envelope_pw.as_bytes(),
                argon2: kdf_params,
                mlkem_shared: &shared,
                sep_shared: &sep_shared,
            };
            let material = DeniableMaterial {
                cred_id: Vec::new(),
                hmac_salt: None,
                tpm_blob: blob.to_bytes(),
            };
            Container::create_with_credential_v2_deniable(
                &vault_path,
                None,
                cipher,
                flags,
                0,
                &cred,
                &material,
            )
        }
        SepBootstrapKind::SepFused {
            factors,
            kem_size,
            pin,
            passphrase: _slot_pp,
            kyber_path,
            seed_pw,
        } => {
            // In deniable mode the envelope passphrase IS the passphrase
            // factor, so a fused SEP slot must add FIDO2 (otherwise it is
            // just SepPassphrase, handled above).
            if !factors.has_fido2() {
                return Err(
                    "in deniable mode a fused Secure Enclave slot must include FIDO2; for \
                     SEP + passphrase use the plain 'Secure Enclave' variant (its passphrase \
                     is the envelope)."
                        .into(),
                );
            }
            use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
            let mut auth = make_fido2_authenticator();
            let user_handle = random_user_handle().map_err(estr)?;
            let er = auth.enroll(RP_ID, &user_handle, Some(&pin)).map_err(estr)?;
            let cred_id = er.credential.id;
            let mut hmac_salt = [0u8; 32];
            OsRng
                .try_fill_bytes(&mut hmac_salt)
                .map_err(|e| format!("OS RNG failure: {e}"))?;
            let hmac_secret = auth
                .hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(&pin))
                .map_err(estr)?;
            has_fido2 = true;
            let (sep_shared, blob) = sealer.seal().map_err(|e| format!("SEP seal: {e}"))?;

            if let Some(ks) = kem_size {
                use luksbox_pq::{encapsulate_with, keygen_with};
                let params = if ks == 1024 {
                    luksbox_pq::PqParams::Ml1024
                } else {
                    luksbox_pq::PqParams::Ml768
                };
                let (pk, seed) = keygen_with(params);
                let (ct, shared) = encapsulate_with(params, &pk).map_err(estr)?;
                hybrid_entries = Some((params, pk, ct));
                kyber_to_write = Some((
                    kyber_path.ok_or("hybrid SEP+FIDO2 requires a .kyber path")?,
                    seed,
                    seed_pw,
                ));
                let cred =
                    luksbox_core::deniable::DeniableCredential::HybridPqSepFido2Passphrase {
                        passphrase: envelope_pw.as_bytes(),
                        argon2: kdf_params,
                        mlkem_shared: &shared,
                        sep_shared: &sep_shared,
                        hmac_secret_output: &hmac_secret,
                    };
                let material = DeniableMaterial {
                    cred_id,
                    hmac_salt: Some(hmac_salt),
                    tpm_blob: blob.to_bytes(),
                };
                Container::create_with_credential_v2_deniable(
                    &vault_path,
                    None,
                    cipher,
                    flags,
                    0,
                    &cred,
                    &material,
                )
            } else {
                let cred = luksbox_core::deniable::DeniableCredential::SepFido2Passphrase {
                    passphrase: envelope_pw.as_bytes(),
                    argon2: kdf_params,
                    sep_shared: &sep_shared,
                    hmac_secret_output: &hmac_secret,
                };
                let material = DeniableMaterial {
                    cred_id,
                    hmac_salt: Some(hmac_salt),
                    tpm_blob: blob.to_bytes(),
                };
                Container::create_with_credential_v2_deniable(
                    &vault_path,
                    None,
                    cipher,
                    flags,
                    0,
                    &cred,
                    &material,
                )
            }
        }
    };

    let mut cont = cont_res.map_err(|e| {
        let _ = std::fs::remove_file(&vault_path);
        format!("deniable Secure Enclave vault create failed: {e}")
    })?;

    // Write the hybrid sidecar + .kyber seed now that the vault exists.
    if let Some((params, pk, ct)) = hybrid_entries {
        use luksbox_format::hybrid_sidecar::{self, HybridEntry};
        let sidecar = hybrid_sidecar::sidecar_path(&vault_path);
        if let Err(e) = hybrid_sidecar::write(
            &sidecar,
            &[HybridEntry {
                slot_idx: 0,
                level: params,
                pubkey: pk,
                ciphertext: ct,
            }],
        ) {
            drop(cont);
            let _ = std::fs::remove_file(&vault_path);
            let _ = std::fs::remove_file(&sidecar);
            return Err(format!("hybrid sidecar write: {e}"));
        }
        sidecars_on_disk.push(sidecar);
    }
    if let Some((kyber_path, seed, seed_pw)) = kyber_to_write {
        use luksbox_pq::seed_file;
        if let Err(e) = seed_file::write(
            &kyber_path,
            &seed,
            seed_pw.as_bytes(),
            seed_file::KdfParams::default(),
        ) {
            drop(cont);
            let _ = std::fs::remove_file(&vault_path);
            for sc in &sidecars_on_disk {
                let _ = std::fs::remove_file(sc);
            }
            return Err(format!(".kyber write: {e}"));
        }
    }

    if let Some(ap) = anchor_path.as_ref()
        && let Err(e) = cont.init_anchor(ap.clone(), 1).map_err(estr)
    {
        drop(cont);
        let _ = std::fs::remove_file(&vault_path);
        for sc in &sidecars_on_disk {
            let _ = std::fs::remove_file(sc);
        }
        let _ = std::fs::remove_file(ap);
        return Err(format!("anchor init failed: {e}"));
    }

    let has_hybrid_pq = !sidecars_on_disk.is_empty();
    let cipher_lbl = cipher_label(cont.header.cipher_suite).to_string();
    let vfs = Vfs::open(cont).map_err(estr)?;
    Ok(OpenedVault {
        vfs,
        vault_path,
        header_path: None,
        anchor_path,
        cipher_label: cipher_lbl,
        has_fido2,
        has_hybrid_pq,
        has_tpm: false,
        deniable_fido2_recovery: None,
        deniable_tpm_blob_path: None,
        tolerated_inodes: Vec::new(),
    })
}

#[cfg(not(all(feature = "hardware", target_os = "macos")))]
fn create_sep_passphrase_deniable(
    _opts: CreateOpts,
    _kind: SepBootstrapKind,
) -> Result<OpenedVault, String> {
    Err("Secure Enclave is macOS-only".into())
}

/// Create a vault whose ONLY keyslot is a macOS Secure Enclave slot
/// (no backup passphrase). The SEP analog of `create_vault_tpm2_only`,
/// reached from the GUI "Skip backup passphrase" checkbox. If the
/// enclave is wiped/replaced the vault is permanently unrecoverable.
#[cfg(all(feature = "hardware", target_os = "macos"))]
pub fn create_vault_sep_only(opts: CreateOpts, biometric: bool) -> Result<OpenedVault, String> {
    use luksbox_core::SlotKind;
    use luksbox_sep::SepSealer;

    let vault_path = opts.path.clone();
    let header_path = opts.header_path.clone();
    let anchor_path = opts.anchor_path.clone();
    let mut flags = 0u32;
    if opts.pad_files || opts.hide_sizes {
        flags |= FLAG_PAD_FILES_POW2;
    }
    if opts.hide_sizes {
        flags |= FLAG_HIDE_SIZE_HEADER;
    }

    let mut sealer = SepSealer::new().map_err(|e| format!("{e}"))?;
    let kind = if biometric {
        SlotKind::SepSealedBiometric
    } else {
        SlotKind::SepSealed
    };
    let (sep_shared, blob) = if biometric {
        sealer
            .seal_biometric()
            .map_err(|e| format!("SEP seal (biometric): {e}"))?
    } else {
        sealer.seal().map_err(|e| format!("SEP seal: {e}"))?
    };
    let blob_bytes = blob.to_bytes();

    let mut cont = Container::create_with_sep(
        &vault_path,
        header_path.as_deref(),
        opts.cipher,
        flags,
        kind,
        &sep_shared,
        &blob_bytes,
    )
    .map_err(|e| {
        let _ = std::fs::remove_file(&vault_path);
        format!("Secure Enclave-only vault create failed: {e}")
    })?;

    if let Some(ap) = anchor_path.as_ref()
        && let Err(e) = cont.init_anchor(ap.clone(), 1).map_err(estr)
    {
        drop(cont);
        let _ = std::fs::remove_file(&vault_path);
        let _ = std::fs::remove_file(ap);
        return Err(format!("anchor init failed: {e}"));
    }

    let cipher = cipher_label(cont.header.cipher_suite).to_string();
    let vfs = Vfs::open(cont).map_err(estr)?;
    Ok(OpenedVault {
        vfs,
        vault_path,
        header_path,
        anchor_path,
        cipher_label: cipher,
        has_fido2: false,
        has_hybrid_pq: false,
        has_tpm: false,
        deniable_fido2_recovery: None,
        deniable_tpm_blob_path: None,
        tolerated_inodes: Vec::new(),
    })
}

#[cfg(not(all(feature = "hardware", target_os = "macos")))]
pub fn create_vault_sep_only(_opts: CreateOpts, _biometric: bool) -> Result<OpenedVault, String> {
    Err("Secure Enclave is macOS-only".into())
}

pub fn create_vault(opts: CreateOpts) -> Result<OpenedVault, String> {
    if opts.path.exists() {
        return Err(format!("{} already exists", opts.path.display()));
    }
    if let Some(hp) = &opts.header_path
        && hp.exists()
    {
        return Err(format!("header file {} already exists", hp.display()));
    }
    if let Some(ap) = &opts.anchor_path
        && ap.exists()
    {
        return Err(format!("anchor file {} already exists", ap.display()));
    }
    // Install the v3 format override for the lifetime of this create
    // call. The Vfs reads the thread-local on first open of the new
    // vault and locks the format choice by writing the matching
    // LBM2/LBM3 magic on first flush. The RAII guard restores the
    // previous override on drop so a panic mid-create can't leak v3
    // into an unrelated subsequent create on this thread.
    let _format_guard = luksbox_vfs::set_format_v3_override(Some(opts.use_v3_format));
    let mut flags = 0u32;
    if opts.pad_files || opts.hide_sizes {
        flags |= FLAG_PAD_FILES_POW2;
    }
    if opts.hide_sizes {
        flags |= FLAG_HIDE_SIZE_HEADER;
    }
    if (opts.pad_files || opts.hide_sizes) && opts.kind == SlotKindArg::Fido2Direct {
        return Err("size-hiding flags are not yet supported with fido2-direct".into());
    }

    let kdf_params = opts.kdf.params();
    // Validate deniable-mode combinations early so the user sees a
    // clear message before the slow Argon2 stretch.
    if opts.use_deniable {
        // Detached header is still not supported in deniable mode -
        // the format would need a separate sidecar-vs-inline switch
        // in the deniable header itself; not built yet.
        if opts.header_path.is_some() {
            return Err("detached headers are not yet supported in deniable mode".into());
        }
        // Anchor sidecars in deniable mode use the AEAD-encrypted
        // deniable anchor format. Container::init_anchor branches
        // on is_deniable() automatically; no extra validation
        // needed here.
        // pad_files / hide_sizes were gated as v1 caution; the
        // inner header carries flags through cleanly and the
        // chunk / metadata paths don't differ from standard mode,
        // so we let them through.
        // Fido2Direct is fundamentally incompatible: it derives the
        // MVK from the FIDO2 hmac directly, bypassing the slot
        // wrap. The deniable slot model REQUIRES a wrapped MVK.
        if matches!(opts.kind, SlotKindArg::Fido2Direct) {
            return Err(
                "Fido2Direct is incompatible with deniable mode (it derives MVK directly, but deniable slots require a wrapped MVK). Use 'Fido2' (wrap-style) instead.".into(),
            );
        }
        // All non-passphrase credential combos in deniable mode
        // require the user to save type-specific material at
        // create time (and supply it at unlock):
        //  - FIDO2: cred_id + hmac_salt (surfaced via
        //     OpenedVault.deniable_fido2_recovery; user pastes at
        //     unlock).
        //  - Hybrid-PQ: .kyber seed file (path supplied at unlock
        //     via UnlockOpts.hybrid_kyber_path; the .hybrid
        //     sidecar holds the ciphertext, same as standard PQ).
        //  - TPM: `.tpm-blob` sidecar holding the sealed blob
        //     (path supplied at unlock via
        //     UnlockOpts.deniable_tpm_blob_path).
        // Every combo lives in the dispatch table below.
    }

    // v2 deniable create: FIDO2 cred_id + hmac_salt + TPM sealed
    // blob are embedded inside the slot envelope, so the GUI's
    // recovery card no longer needs to capture / display them.
    // Retained as a mutable Option because the legacy hybrid-PQ
    // helper signatures still produce it; v2 helpers populate it
    // with `None`.
    let mut captured_fido2_recovery: Option<DeniableFido2RecoveryInfo> = None;
    let mut cont: Container = match (opts.kind, opts.use_deniable) {
        (SlotKindArg::Passphrase, true) => {
            use luksbox_format::deniable_header::DeniableMaterial;
            let pw = opts.passphrase.as_ref().ok_or("passphrase required")?;
            let cred = luksbox_core::deniable::DeniableCredential::Passphrase {
                passphrase: pw.as_bytes(),
                argon2: kdf_params,
            };
            Container::create_with_credential_v2_deniable(
                &opts.path,
                opts.header_path.as_deref(),
                opts.cipher,
                flags,
                0,
                &cred,
                &DeniableMaterial::passphrase_only(),
            )
            .map_err(estr)?
        }
        #[cfg(feature = "hardware")]
        (SlotKindArg::Fido2, true) => {
            use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
            use luksbox_format::deniable_header::DeniableMaterial;
            let pw = opts
                .passphrase
                .as_ref()
                .ok_or("passphrase required for v2 deniable FIDO2 envelope discovery")?;
            let pin = opts.pin.as_ref().ok_or("FIDO2 PIN required")?;
            let mut auth = make_fido2_authenticator();
            let user_handle = random_user_handle().map_err(estr)?;
            let er = auth.enroll(RP_ID, &user_handle, Some(pin)).map_err(estr)?;
            let cred_id = er.credential.id;
            let mut hmac_salt = [0u8; 32];
            OsRng
                .try_fill_bytes(&mut hmac_salt)
                .map_err(|e| format!("OS RNG failure: {e}"))?;
            let hmac_secret = auth
                .hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(pin))
                .map_err(estr)?;
            let cred = luksbox_core::deniable::DeniableCredential::Fido2Passphrase {
                passphrase: pw.as_bytes(),
                argon2: kdf_params,
                hmac_secret_output: &hmac_secret,
            };
            let material = DeniableMaterial {
                cred_id,
                hmac_salt: Some(hmac_salt),
                tpm_blob: Vec::new(),
            };
            Container::create_with_credential_v2_deniable(
                &opts.path,
                opts.header_path.as_deref(),
                opts.cipher,
                flags,
                0,
                &cred,
                &material,
            )
            .map_err(estr)?
        }
        (SlotKindArg::Passphrase, false) => {
            let pw = opts.passphrase.as_ref().ok_or("passphrase required")?;
            Container::create_with_passphrase_flags(
                &opts.path,
                opts.header_path.as_deref(),
                opts.cipher,
                kdf_params,
                flags,
                pw.as_bytes(),
            )
            .map_err(estr)?
        }
        (SlotKindArg::Fido2, _) => create_fido2_wrap(
            &opts.path,
            opts.header_path.as_deref(),
            opts.cipher,
            flags,
            opts.pin.as_ref().ok_or("FIDO2 PIN required")?,
            kdf_params,
        )?,
        (SlotKindArg::Fido2Direct, _) => create_fido2_direct(
            &opts.path,
            opts.header_path.as_deref(),
            opts.cipher,
            opts.pin.as_ref().ok_or("FIDO2 PIN required")?,
        )?,
        // Deniable hybrid-PQ + passphrase. Generates a Kyber
        // keypair + .kyber seed file (same shape as non-deniable),
        // ML-KEM encapsulates, writes the .hybrid sidecar holding
        // the ciphertext, and builds a HybridPqPassphrase
        // credential for the deniable slot.
        (SlotKindArg::HybridPq, true) | (SlotKindArg::HybridPq1024, true) => {
            let params = if matches!(opts.kind, SlotKindArg::HybridPq1024) {
                luksbox_pq::PqParams::Ml1024
            } else {
                luksbox_pq::PqParams::Ml768
            };
            let envelope_pw = opts.passphrase.as_ref().ok_or("passphrase required")?;
            // v2 deniable: optional separate seed-file passphrase.
            // Empty / unset -> falls back to the envelope passphrase
            // so the common "one passphrase for both" UX still
            // works.
            let seed_pw = opts
                .hybrid_seed_pw
                .as_ref()
                .filter(|s| !s.is_empty())
                .unwrap_or(envelope_pw);
            let kyber_path = opts
                .hybrid_kyber_path
                .as_ref()
                .ok_or("hybrid-PQ deniable requires a path for the .kyber seed file")?;
            create_hybrid_pq_passphrase_deniable(
                &opts.path,
                opts.cipher,
                flags,
                envelope_pw,
                seed_pw,
                kyber_path,
                params,
                kdf_params,
            )?
        }
        #[cfg(feature = "hardware")]
        (SlotKindArg::HybridPqFido2, true) | (SlotKindArg::HybridPq1024Fido2, true) => {
            let params = if matches!(opts.kind, SlotKindArg::HybridPq1024Fido2) {
                luksbox_pq::PqParams::Ml1024
            } else {
                luksbox_pq::PqParams::Ml768
            };
            let pin = opts.pin.as_ref().ok_or("FIDO2 PIN required")?;
            let envelope_pw = opts
                .passphrase
                .as_ref()
                .ok_or("hybrid-PQ + FIDO2 deniable: envelope passphrase required")?;
            let seed_pw = opts
                .hybrid_seed_pw
                .as_ref()
                .filter(|s| !s.is_empty())
                .unwrap_or(envelope_pw);
            let kyber_path = opts
                .hybrid_kyber_path
                .as_ref()
                .ok_or(".kyber seed file path required")?;
            let (cont, recovery) = create_hybrid_pq_fido2_deniable(
                &opts.path,
                opts.cipher,
                flags,
                pin,
                envelope_pw,
                seed_pw,
                kyber_path,
                params,
                kdf_params,
            )?;
            captured_fido2_recovery = recovery;
            cont
        }
        // TPM-bearing CREATE in deniable mode is not yet routable
        // through SlotKindArg (the standard TPM enrollment path
        // uses a separate TpmBootstrapKind that starts from a
        // passphrase vault). Wiring create-time TPM-deniable needs
        // either: (a) extending SlotKindArg with Tpm2/Tpm2Pin/
        // Tpm2Fido2/HybridPq*Tpm* variants and updating the
        // standard path too, OR (b) a "TpmBootstrapForDeniable"
        // helper that creates a passphrase-deniable vault first
        // then enrolls TPM as a second slot. Both are a sizeable
        // PR on their own; tracked separately.
        //
        // OPEN-time TPM-deniable is fully wired in `unlock_vault`
        // below (uses opts.deniable_tpm_blob_path), so vaults
        // created via the Container API directly (luksbox-cli or
        // tests) work through the GUI today.
        (SlotKindArg::HybridPq, _) | (SlotKindArg::HybridPq1024, _) => {
            let params = if matches!(opts.kind, SlotKindArg::HybridPq1024) {
                luksbox_pq::PqParams::Ml1024
            } else {
                luksbox_pq::PqParams::Ml768
            };
            let pw = opts.passphrase.as_ref().ok_or("passphrase required")?;
            let kyber_path = opts
                .hybrid_kyber_path
                .as_ref()
                .ok_or("hybrid-pq requires a path for the .kyber seed file")?;
            if kyber_path.exists() {
                return Err(format!(
                    "{} already exists; refusing to overwrite",
                    kyber_path.display()
                ));
            }
            create_hybrid_pq(
                &opts.path,
                opts.header_path.as_deref(),
                opts.cipher,
                flags,
                pw,
                kyber_path,
                params,
                kdf_params,
            )?
        }
        (SlotKindArg::HybridPqFido2, _) | (SlotKindArg::HybridPq1024Fido2, _) => {
            let params = if matches!(opts.kind, SlotKindArg::HybridPq1024Fido2) {
                luksbox_pq::PqParams::Ml1024
            } else {
                luksbox_pq::PqParams::Ml768
            };
            let seed_pw = opts
                .passphrase
                .as_ref()
                .ok_or("hybrid-pq-fido2 requires a seed-file passphrase")?;
            let pin = opts.pin.as_ref().ok_or("FIDO2 PIN required")?;
            let kyber_path = opts
                .hybrid_kyber_path
                .as_ref()
                .ok_or("hybrid-pq-fido2 requires a path for the .kyber seed file")?;
            if kyber_path.exists() {
                return Err(format!(
                    "{} already exists; refusing to overwrite",
                    kyber_path.display()
                ));
            }
            create_hybrid_pq_fido2(
                &opts.path,
                opts.header_path.as_deref(),
                opts.cipher,
                flags,
                seed_pw,
                pin,
                kyber_path,
                params,
                kdf_params,
            )?
        }
    };
    if let Some(ap) = opts.anchor_path.as_ref() {
        cont.init_anchor(ap.clone(), 1).map_err(estr)?;
    }
    if let Some(bp) = opts.backup_passphrase.as_ref() {
        cont.enroll_passphrase(bp.as_bytes(), kdf_params)
            .map_err(estr)?;
        cont.persist_header().map_err(estr)?;
    }
    let has_fido2 = header_has_fido2(&cont.header);
    let has_hybrid_pq = header_has_hybrid_pq(&cont.header);
    let has_tpm = header_has_tpm(&cont.header);
    let cipher = cipher_label(cont.header.cipher_suite).to_string();
    let vfs = Vfs::open(cont).map_err(estr)?;
    Ok(OpenedVault {
        vfs,
        vault_path: opts.path,
        header_path: opts.header_path,
        anchor_path: opts.anchor_path,
        cipher_label: cipher,
        has_fido2,
        has_hybrid_pq,
        has_tpm,
        deniable_fido2_recovery: captured_fido2_recovery,
        deniable_tpm_blob_path: None,
        tolerated_inodes: Vec::new(),
    })
}

#[cfg(feature = "hardware")]
fn create_fido2_wrap(
    path: &Path,
    header_path: Option<&Path>,
    cipher: CipherSuite,
    flags: u32,
    pin: &str,
    kdf_params: Argon2idParams,
) -> Result<Container, String> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    let mut auth = make_fido2_authenticator();
    let user_handle = random_user_handle().map_err(estr)?;
    let er = auth.enroll(RP_ID, &user_handle, Some(pin)).map_err(estr)?;
    let cred_id = er.credential.id;
    let mut hmac_salt = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut hmac_salt)
        .map_err(|e| format!("OS RNG failure generating FIDO2 hmac salt: {e}"))?;
    let hmac_secret = auth
        .hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(pin))
        .map_err(estr)?;
    Container::create_with_fido2_flags(
        path,
        header_path,
        cipher,
        kdf_params,
        flags,
        None,
        &hmac_secret,
        &cred_id,
        hmac_salt,
    )
    .map_err(estr)
}

#[cfg(not(feature = "hardware"))]
fn create_fido2_wrap(
    _path: &Path,
    _header_path: Option<&Path>,
    _cipher: CipherSuite,
    _flags: u32,
    _pin: &str,
    _kdf_params: Argon2idParams,
) -> Result<Container, String> {
    Err("FIDO2 hardware support not compiled in".into())
}

#[cfg(feature = "hardware")]
fn create_fido2_direct(
    path: &Path,
    header_path: Option<&Path>,
    cipher: CipherSuite,
    pin: &str,
) -> Result<Container, String> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    let mut auth = make_fido2_authenticator();
    let user_handle = random_user_handle().map_err(estr)?;
    let er = auth.enroll(RP_ID, &user_handle, Some(pin)).map_err(estr)?;
    let cred_id = er.credential.id;
    let mut hmac_salt = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut hmac_salt)
        .map_err(|e| format!("OS RNG failure generating FIDO2 hmac salt: {e}"))?;
    let hmac_secret = auth
        .hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(pin))
        .map_err(estr)?;
    Container::create_with_fido2_derived_mvk(
        path,
        header_path,
        cipher,
        &cred_id,
        &hmac_secret,
        hmac_salt,
    )
    .map_err(estr)
}

#[cfg(not(feature = "hardware"))]
fn create_fido2_direct(
    _path: &Path,
    _header_path: Option<&Path>,
    _cipher: CipherSuite,
    _pin: &str,
) -> Result<Container, String> {
    Err("FIDO2 hardware support not compiled in".into())
}

/// Hybrid passphrase + ML-KEM keyslot (768 or 1024 by `params`). Generates
/// a Kyber keypair, encapsulates against the public key, builds the
/// keyslot under the combined KEK, and writes the public Kyber blobs
/// (sidecar) + secret seed (`.kyber` file) to disk.
#[allow(clippy::too_many_arguments)]
fn create_hybrid_pq(
    path: &Path,
    header_path: Option<&Path>,
    cipher: CipherSuite,
    flags: u32,
    passphrase: &str,
    kyber_path: &Path,
    params: luksbox_pq::PqParams,
    kdf_params: Argon2idParams,
) -> Result<Container, String> {
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};

    let (pk, seed) = keygen_with(params);
    let (ct, shared) = encapsulate_with(params, &pk).map_err(estr)?;

    let cont = match params {
        PqParams::Ml768 => Container::create_with_hybrid_pq_passphrase(
            path,
            header_path,
            cipher,
            kdf_params,
            flags,
            passphrase.as_bytes(),
            &shared,
        ),
        PqParams::Ml1024 => Container::create_with_hybrid_pq_1024_passphrase(
            path,
            header_path,
            cipher,
            kdf_params,
            flags,
            passphrase.as_bytes(),
            &shared,
        ),
    }
    .map_err(estr)?;

    let sidecar = hybrid_sidecar::sidecar_path(path);
    hybrid_sidecar::write(
        &sidecar,
        &[HybridEntry {
            slot_idx: 0,
            level: params,
            pubkey: pk,
            ciphertext: ct,
        }],
    )
    .map_err(estr)?;
    seed_file::write(
        kyber_path,
        &seed,
        passphrase.as_bytes(),
        seed_file::KdfParams::default(),
    )
    .map_err(estr)?;

    Ok(cont)
}

/// Hybrid FIDO2 + ML-KEM-768. Uses authenticator's hmac-secret AND a Kyber
/// decapsulation. The `.kyber` seed file is encrypted under
/// `seed_passphrase` (defence in depth, separate from the FIDO2 PIN).
#[cfg(feature = "hardware")]
#[allow(clippy::too_many_arguments)]
fn create_hybrid_pq_fido2(
    path: &Path,
    header_path: Option<&Path>,
    cipher: CipherSuite,
    flags: u32,
    seed_passphrase: &str,
    pin: &str,
    kyber_path: &Path,
    params: luksbox_pq::PqParams,
    kdf_params: Argon2idParams,
) -> Result<Container, String> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};

    let mut auth = make_fido2_authenticator();
    let user_handle = random_user_handle().map_err(estr)?;
    let er = auth.enroll(RP_ID, &user_handle, Some(pin)).map_err(estr)?;
    let cred_id = er.credential.id;
    let mut hmac_salt = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut hmac_salt)
        .map_err(|e| format!("OS RNG failure generating FIDO2 hmac salt: {e}"))?;
    let hmac_secret = auth
        .hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(pin))
        .map_err(estr)?;

    let (pk, kyber_seed) = keygen_with(params);
    let (ct, shared) = encapsulate_with(params, &pk).map_err(estr)?;

    let cont = match params {
        PqParams::Ml768 => Container::create_with_hybrid_pq_fido2(
            path,
            header_path,
            cipher,
            kdf_params,
            flags,
            None,
            &hmac_secret,
            &shared,
            &cred_id,
            hmac_salt,
        ),
        PqParams::Ml1024 => Container::create_with_hybrid_pq_1024_fido2(
            path,
            header_path,
            cipher,
            kdf_params,
            flags,
            None,
            &hmac_secret,
            &shared,
            &cred_id,
            hmac_salt,
        ),
    }
    .map_err(estr)?;

    let sidecar = hybrid_sidecar::sidecar_path(path);
    hybrid_sidecar::write(
        &sidecar,
        &[HybridEntry {
            slot_idx: 0,
            level: params,
            pubkey: pk,
            ciphertext: ct,
        }],
    )
    .map_err(estr)?;
    seed_file::write(
        kyber_path,
        &kyber_seed,
        seed_passphrase.as_bytes(),
        seed_file::KdfParams::default(),
    )
    .map_err(estr)?;

    Ok(cont)
}

#[cfg(not(feature = "hardware"))]
#[allow(clippy::too_many_arguments)]
fn create_hybrid_pq_fido2(
    _path: &Path,
    _header_path: Option<&Path>,
    _cipher: CipherSuite,
    _flags: u32,
    _seed_passphrase: &str,
    _pin: &str,
    _kyber_path: &Path,
    _params: luksbox_pq::PqParams,
    _kdf_params: Argon2idParams,
) -> Result<Container, String> {
    Err("FIDO2 hardware support not compiled in".into())
}

// ---- unlock ---------------------------------------------------------------

/// Pre-flight checks for a deniable anchor file. Returns specific
/// error messages for the file-level failure modes (missing, can't
/// open, wrong size) that the format layer otherwise collapses into
/// `Error::OpaqueUnlockFailed`. Safe to call only on the GUI side
/// where the user has just chosen the anchor path themselves - this
/// is not a deniability concession because the user already knows
/// they supplied an anchor.
fn preflight_deniable_anchor(path: &Path) -> Result<(), String> {
    use luksbox_format::anchor::DENIABLE_ANCHOR_SIZE;
    // symlink_metadata does NOT follow symlinks - we want to reject
    // them explicitly rather than silently dereferencing into whatever
    // target the symlink points at. A symlink at the anchor path is
    // suspicious: a real anchor is a 256-byte regular file emitted by
    // luksbox itself, never a link. Refusing here also rules out the
    // small TOCTOU race where the path could be swapped between
    // pre-flight and the format-layer open (which itself does follow
    // symlinks). If the user has a legitimate reason to use a link,
    // canonicalize it themselves before picking it.
    let md = std::fs::symlink_metadata(path).map_err(|e| {
        format!(
            "Anchor file not readable at {}: {e}. Pick the .anchor file you \
             exported when you created the vault, or open without an anchor \
             to skip rollback detection.",
            path.display()
        )
    })?;
    let ft = md.file_type();
    if ft.is_symlink() {
        return Err(format!(
            "Anchor path at {} is a symbolic link. LUKSbox refuses to follow \
             symlinks for anchor files (a real anchor is a 256-byte regular \
             file). Pick the underlying file directly.",
            path.display()
        ));
    }
    if !ft.is_file() {
        return Err(format!(
            "Anchor path at {} is not a regular file. A deniable anchor is a \
             256-byte file produced by luksbox; directories, devices, and \
             sockets are rejected.",
            path.display()
        ));
    }
    let len = md.len();
    if len != DENIABLE_ANCHOR_SIZE as u64 {
        return Err(format!(
            "Anchor file at {} is {} bytes; a deniable anchor is exactly {} \
             bytes. The file is either not a LUKSbox deniable anchor, was \
             truncated/padded by transfer, or belongs to a standard \
             (non-deniable) vault. Re-export the anchor from this vault.",
            path.display(),
            len,
            DENIABLE_ANCHOR_SIZE,
        ));
    }
    Ok(())
}

pub fn unlock_vault(opts: UnlockOpts) -> Result<OpenedVault, String> {
    // Deniable mode short-circuit: detection-by-magic is impossible
    // (no magic exists by design), so the user MUST declare the
    // header format + credential type. When `use_deniable` is set,
    // route through Container::open_with_credential_deniable with
    // the supplied cipher + KDF + credential material.
    if opts.use_deniable {
        if opts.header_path.is_some() {
            return Err("detached headers are not yet supported in deniable mode".into());
        }
        let kdf_params = opts.deniable_kdf.params();
        let cipher = opts.deniable_cipher;

        // v2: every deniable variant is passphrase-discovered.
        let pw = opts
            .passphrase
            .as_ref()
            .ok_or("passphrase required for deniable v2 envelope discovery")?;

        // Resolve the user's intended unlock kind BEFORE phase 1 so
        // we can pass it as the discovery hint. Without this hint,
        // phase 1 used to hardcode Passphrase as want_kind and
        // discovery preferred any Passphrase slot under the same
        // envelope passphrase -- so enrolling a new FIDO2 / TPM /
        // hybrid slot with the admin's passphrase and trying to
        // unlock with the new slot's kind returned slot 0
        // (Passphrase) and tripped "credential kind mismatch".
        use luksbox_core::deniable::DeniableKindTag;
        #[allow(unreachable_patterns)]
        let expected = match opts.method {
            UnlockMethod::Passphrase => DeniableKindTag::Passphrase,
            UnlockMethod::Fido2 => DeniableKindTag::Fido2Passphrase,
            UnlockMethod::HybridPq => DeniableKindTag::HybridPqPassphrase,
            UnlockMethod::HybridPqFido2 => DeniableKindTag::HybridPqFido2Passphrase,
            #[cfg(all(feature = "hardware", target_os = "macos"))]
            UnlockMethod::Sep => DeniableKindTag::SepPassphrase,
            #[cfg(all(feature = "hardware", target_os = "macos"))]
            UnlockMethod::SepFido2 => DeniableKindTag::SepFido2Passphrase,
            #[cfg(all(feature = "hardware", target_os = "macos"))]
            UnlockMethod::HybridPqSep => DeniableKindTag::HybridPqSepPassphrase,
            #[cfg(all(feature = "hardware", target_os = "macos"))]
            UnlockMethod::HybridPqSepFido2 => DeniableKindTag::HybridPqSepFido2Passphrase,
            #[cfg(all(feature = "hardware", target_os = "linux"))]
            UnlockMethod::Tpm2 | UnlockMethod::Tpm2Pin => DeniableKindTag::TpmPassphrase,
            #[cfg(all(feature = "hardware", target_os = "linux"))]
            UnlockMethod::Tpm2Fido2 => DeniableKindTag::TpmFido2Passphrase,
            #[cfg(all(feature = "hardware", target_os = "linux"))]
            UnlockMethod::HybridPqTpm2 => DeniableKindTag::HybridPqTpmPassphrase,
            #[cfg(all(feature = "hardware", target_os = "linux"))]
            UnlockMethod::HybridPqTpm2Fido2 => DeniableKindTag::HybridPqTpmFido2Passphrase,
            _ => {
                return Err(format!(
                    "unlock method {:?} not yet supported in deniable mode on this platform",
                    opts.method
                ));
            }
        };

        // Phase 1: envelope discovery via passphrase-only credential
        // + explicit kind hint so the discovery prefers the
        // user-intended slot variant when multiple slots share the
        // same envelope passphrase.
        let env_cred = luksbox_core::deniable::DeniableCredential::Passphrase {
            passphrase: pw.as_bytes(),
            argon2: kdf_params,
        };
        let envelope = Container::try_open_envelope_v2_deniable(
            &opts.path,
            None,
            &env_cred,
            cipher,
            Some(expected),
        )
        .map_err(estr)?;

        // Belt-and-suspenders: discovery prefers slots whose kind
        // byte matches `expected`, so this should never fire under
        // honest inputs. Kept to refuse MVK-forged blobs that
        // present a Passphrase-AEAD-OK slot with a mismatched
        // stored kind byte.
        if envelope.payload().kind != expected {
            return Err("credential kind mismatch (vault expects a different variant)".into());
        }

        let payload_cred_id = envelope.payload().cred_id.clone();
        let payload_hmac_salt = envelope.payload().hmac_salt;
        // Consumers below are Linux+hardware-gated; on macOS/Windows
        // builds none of the unseal arms exist so the binding is
        // dead. Allow rather than cfg-gate to keep the extraction
        // logic symmetric across platforms.
        #[allow(unused_variables)]
        let payload_tpm_blob = envelope.payload().tpm_blob.clone();
        // Index of the deniable slot the envelope discovery matched.
        // Captured BEFORE `Container::complete_open_v2_deniable`
        // consumes the envelope, so the dispatch arms below can pass
        // it to `deniable_pq_decap` and look up the right `.hybrid`
        // sidecar entry for THIS slot. Without this, deniable_pq_decap
        // used to default to the first sidecar entry and any vault
        // with two PQC-bearing slots (e.g., TPM+FIDO2+PQ at slot 1 +
        // passphrase+PQ at slot 3) failed to unlock the non-first
        // one because decapsulating the wrong entry's ciphertext
        // with the user's seed produces a garbage shared secret
        // (ML-KEM implicit rejection by design).
        let matched_slot_idx = envelope.opened.matched_slot_idx as u8;

        // Phase 2: drive secondaries, build full credential, complete
        // open. Same portability note as the variant cross-check
        // above: catch-all is structurally unreachable on
        // Linux+hardware, allow the lint to keep the match portable.
        #[allow(unreachable_patterns)]
        let mut cont = match opts.method {
            UnlockMethod::Passphrase => {
                let cred = luksbox_core::deniable::DeniableCredential::Passphrase {
                    passphrase: pw.as_bytes(),
                    argon2: kdf_params,
                };
                Container::complete_open_v2_deniable(envelope, &cred).map_err(estr)?
            }
            #[cfg(feature = "hardware")]
            UnlockMethod::Fido2 => {
                let salt =
                    payload_hmac_salt.ok_or("envelope missing hmac_salt for FIDO2 variant")?;
                let hmac_secret =
                    deniable_fido2_hmac_from_payload(&opts, &payload_cred_id, &salt, true)?;
                let cred = luksbox_core::deniable::DeniableCredential::Fido2Passphrase {
                    passphrase: pw.as_bytes(),
                    argon2: kdf_params,
                    hmac_secret_output: &hmac_secret,
                };
                match Container::complete_open_v2_deniable_reusable(envelope, &cred) {
                    Ok(c) => c,
                    Err((envelope, luksbox_format::Error::OpaqueUnlockFailed)) => {
                        // Pre-v0.3.0 envelope probe: second touch
                        // with the raw-salt convention.
                        let hmac_secret = deniable_fido2_hmac_from_payload(
                            &opts,
                            &payload_cred_id,
                            &salt,
                            false,
                        )?;
                        let cred = luksbox_core::deniable::DeniableCredential::Fido2Passphrase {
                            passphrase: pw.as_bytes(),
                            argon2: kdf_params,
                            hmac_secret_output: &hmac_secret,
                        };
                        Container::complete_open_v2_deniable(envelope, &cred).map_err(estr)?
                    }
                    Err((_, e)) => return Err(estr(e)),
                }
            }
            UnlockMethod::HybridPq => {
                let shared = deniable_pq_decap(&opts, matched_slot_idx)?;
                let cred = luksbox_core::deniable::DeniableCredential::HybridPqPassphrase {
                    passphrase: pw.as_bytes(),
                    argon2: kdf_params,
                    mlkem_shared: &shared,
                };
                Container::complete_open_v2_deniable(envelope, &cred).map_err(estr)?
            }
            #[cfg(feature = "hardware")]
            UnlockMethod::HybridPqFido2 => {
                let shared = deniable_pq_decap(&opts, matched_slot_idx)?;
                let salt =
                    payload_hmac_salt.ok_or("envelope missing hmac_salt for FIDO2 variant")?;
                let hmac_secret =
                    deniable_fido2_hmac_from_payload(&opts, &payload_cred_id, &salt, true)?;
                let cred = luksbox_core::deniable::DeniableCredential::HybridPqFido2Passphrase {
                    passphrase: pw.as_bytes(),
                    argon2: kdf_params,
                    mlkem_shared: &shared,
                    hmac_secret_output: &hmac_secret,
                };
                match Container::complete_open_v2_deniable_reusable(envelope, &cred) {
                    Ok(c) => c,
                    Err((envelope, luksbox_format::Error::OpaqueUnlockFailed)) => {
                        let hmac_secret = deniable_fido2_hmac_from_payload(
                            &opts,
                            &payload_cred_id,
                            &salt,
                            false,
                        )?;
                        let cred =
                            luksbox_core::deniable::DeniableCredential::HybridPqFido2Passphrase {
                                passphrase: pw.as_bytes(),
                                argon2: kdf_params,
                                mlkem_shared: &shared,
                                hmac_secret_output: &hmac_secret,
                            };
                        Container::complete_open_v2_deniable(envelope, &cred).map_err(estr)?
                    }
                    Err((_, e)) => return Err(estr(e)),
                }
            }
            #[cfg(all(feature = "hardware", target_os = "linux"))]
            UnlockMethod::Tpm2 => {
                let unsealed = deniable_tpm_unseal_from_bytes(&payload_tpm_blob, None)?;
                let cred = luksbox_core::deniable::DeniableCredential::TpmPassphrase {
                    passphrase: pw.as_bytes(),
                    argon2: kdf_params,
                    unsealed: &unsealed,
                };
                Container::complete_open_v2_deniable(envelope, &cred).map_err(estr)?
            }
            #[cfg(all(feature = "hardware", target_os = "linux"))]
            UnlockMethod::Tpm2Pin => {
                let pin = opts.pin.as_ref().ok_or("TPM PIN required")?;
                let unsealed =
                    deniable_tpm_unseal_from_bytes(&payload_tpm_blob, Some(pin.as_bytes()))?;
                let cred = luksbox_core::deniable::DeniableCredential::TpmPassphrase {
                    passphrase: pw.as_bytes(),
                    argon2: kdf_params,
                    unsealed: &unsealed,
                };
                Container::complete_open_v2_deniable(envelope, &cred).map_err(estr)?
            }
            #[cfg(all(feature = "hardware", target_os = "linux"))]
            UnlockMethod::Tpm2Fido2 => {
                let unsealed = deniable_tpm_unseal_from_bytes(&payload_tpm_blob, None)?;
                let salt =
                    payload_hmac_salt.ok_or("envelope missing hmac_salt for FIDO2 variant")?;
                let hmac_secret =
                    deniable_fido2_hmac_from_payload(&opts, &payload_cred_id, &salt, true)?;
                let cred = luksbox_core::deniable::DeniableCredential::TpmFido2Passphrase {
                    passphrase: pw.as_bytes(),
                    argon2: kdf_params,
                    unsealed: &unsealed,
                    hmac_secret_output: &hmac_secret,
                };
                match Container::complete_open_v2_deniable_reusable(envelope, &cred) {
                    Ok(c) => c,
                    Err((envelope, luksbox_format::Error::OpaqueUnlockFailed)) => {
                        let hmac_secret = deniable_fido2_hmac_from_payload(
                            &opts,
                            &payload_cred_id,
                            &salt,
                            false,
                        )?;
                        let cred = luksbox_core::deniable::DeniableCredential::TpmFido2Passphrase {
                            passphrase: pw.as_bytes(),
                            argon2: kdf_params,
                            unsealed: &unsealed,
                            hmac_secret_output: &hmac_secret,
                        };
                        Container::complete_open_v2_deniable(envelope, &cred).map_err(estr)?
                    }
                    Err((_, e)) => return Err(estr(e)),
                }
            }
            #[cfg(all(feature = "hardware", target_os = "linux"))]
            UnlockMethod::HybridPqTpm2 => {
                let shared = deniable_pq_decap(&opts, matched_slot_idx)?;
                let unsealed = deniable_tpm_unseal_from_bytes(&payload_tpm_blob, None)?;
                let cred = luksbox_core::deniable::DeniableCredential::HybridPqTpmPassphrase {
                    passphrase: pw.as_bytes(),
                    argon2: kdf_params,
                    mlkem_shared: &shared,
                    unsealed: &unsealed,
                };
                Container::complete_open_v2_deniable(envelope, &cred).map_err(estr)?
            }
            #[cfg(all(feature = "hardware", target_os = "linux"))]
            UnlockMethod::HybridPqTpm2Fido2 => {
                let shared = deniable_pq_decap(&opts, matched_slot_idx)?;
                let unsealed = deniable_tpm_unseal_from_bytes(&payload_tpm_blob, None)?;
                let salt =
                    payload_hmac_salt.ok_or("envelope missing hmac_salt for FIDO2 variant")?;
                let hmac_secret =
                    deniable_fido2_hmac_from_payload(&opts, &payload_cred_id, &salt, true)?;
                let cred = luksbox_core::deniable::DeniableCredential::HybridPqTpmFido2Passphrase {
                    passphrase: pw.as_bytes(),
                    argon2: kdf_params,
                    mlkem_shared: &shared,
                    unsealed: &unsealed,
                    hmac_secret_output: &hmac_secret,
                };
                match Container::complete_open_v2_deniable_reusable(envelope, &cred) {
                    Ok(c) => c,
                    Err((envelope, luksbox_format::Error::OpaqueUnlockFailed)) => {
                        let hmac_secret = deniable_fido2_hmac_from_payload(
                            &opts,
                            &payload_cred_id,
                            &salt,
                            false,
                        )?;
                        let cred =
                            luksbox_core::deniable::DeniableCredential::HybridPqTpmFido2Passphrase {
                                passphrase: pw.as_bytes(),
                                argon2: kdf_params,
                                mlkem_shared: &shared,
                                unsealed: &unsealed,
                                hmac_secret_output: &hmac_secret,
                            };
                        Container::complete_open_v2_deniable(envelope, &cred).map_err(estr)?
                    }
                    Err((_, e)) => return Err(estr(e)),
                }
            }
            #[cfg(all(feature = "hardware", target_os = "macos"))]
            UnlockMethod::Sep => {
                let sep_shared = deniable_sep_unseal_from_bytes(&payload_tpm_blob)?;
                let cred = luksbox_core::deniable::DeniableCredential::SepPassphrase {
                    passphrase: pw.as_bytes(),
                    argon2: kdf_params,
                    sep_shared: &sep_shared,
                };
                Container::complete_open_v2_deniable(envelope, &cred).map_err(estr)?
            }
            #[cfg(all(feature = "hardware", target_os = "macos"))]
            UnlockMethod::SepFido2 => {
                let sep_shared = deniable_sep_unseal_from_bytes(&payload_tpm_blob)?;
                let salt =
                    payload_hmac_salt.ok_or("envelope missing hmac_salt for FIDO2 variant")?;
                let hmac_secret =
                    deniable_fido2_hmac_from_payload(&opts, &payload_cred_id, &salt, true)?;
                let cred = luksbox_core::deniable::DeniableCredential::SepFido2Passphrase {
                    passphrase: pw.as_bytes(),
                    argon2: kdf_params,
                    sep_shared: &sep_shared,
                    hmac_secret_output: &hmac_secret,
                };
                match Container::complete_open_v2_deniable_reusable(envelope, &cred) {
                    Ok(c) => c,
                    Err((envelope, luksbox_format::Error::OpaqueUnlockFailed)) => {
                        let hmac_secret =
                            deniable_fido2_hmac_from_payload(&opts, &payload_cred_id, &salt, false)?;
                        let cred = luksbox_core::deniable::DeniableCredential::SepFido2Passphrase {
                            passphrase: pw.as_bytes(),
                            argon2: kdf_params,
                            sep_shared: &sep_shared,
                            hmac_secret_output: &hmac_secret,
                        };
                        Container::complete_open_v2_deniable(envelope, &cred).map_err(estr)?
                    }
                    Err((_, e)) => return Err(estr(e)),
                }
            }
            #[cfg(all(feature = "hardware", target_os = "macos"))]
            UnlockMethod::HybridPqSep => {
                let shared = deniable_pq_decap(&opts, matched_slot_idx)?;
                let sep_shared = deniable_sep_unseal_from_bytes(&payload_tpm_blob)?;
                let cred = luksbox_core::deniable::DeniableCredential::HybridPqSepPassphrase {
                    passphrase: pw.as_bytes(),
                    argon2: kdf_params,
                    mlkem_shared: &shared,
                    sep_shared: &sep_shared,
                };
                Container::complete_open_v2_deniable(envelope, &cred).map_err(estr)?
            }
            #[cfg(all(feature = "hardware", target_os = "macos"))]
            UnlockMethod::HybridPqSepFido2 => {
                let shared = deniable_pq_decap(&opts, matched_slot_idx)?;
                let sep_shared = deniable_sep_unseal_from_bytes(&payload_tpm_blob)?;
                let salt =
                    payload_hmac_salt.ok_or("envelope missing hmac_salt for FIDO2 variant")?;
                let hmac_secret =
                    deniable_fido2_hmac_from_payload(&opts, &payload_cred_id, &salt, true)?;
                let cred = luksbox_core::deniable::DeniableCredential::HybridPqSepFido2Passphrase {
                    passphrase: pw.as_bytes(),
                    argon2: kdf_params,
                    mlkem_shared: &shared,
                    sep_shared: &sep_shared,
                    hmac_secret_output: &hmac_secret,
                };
                match Container::complete_open_v2_deniable_reusable(envelope, &cred) {
                    Ok(c) => c,
                    Err((envelope, luksbox_format::Error::OpaqueUnlockFailed)) => {
                        let hmac_secret =
                            deniable_fido2_hmac_from_payload(&opts, &payload_cred_id, &salt, false)?;
                        let cred =
                            luksbox_core::deniable::DeniableCredential::HybridPqSepFido2Passphrase {
                                passphrase: pw.as_bytes(),
                                argon2: kdf_params,
                                mlkem_shared: &shared,
                                sep_shared: &sep_shared,
                                hmac_secret_output: &hmac_secret,
                            };
                        Container::complete_open_v2_deniable(envelope, &cred).map_err(estr)?
                    }
                    Err((_, e)) => return Err(estr(e)),
                }
            }
            _ => {
                return Err(format!(
                    "unlock method {:?} not yet supported in deniable mode on this platform",
                    opts.method
                ));
            }
        };
        let cipher_label = format!("{:?} (deniable)", cipher);

        // Anchor verification - mirrors the non-deniable path below.
        // Without this block the user-supplied `opts.anchor_path` was
        // silently ignored in deniable mode: any file (or a missing
        // file) was accepted. `Container::set_anchor` branches on
        // is_deniable() internally and uses the AEAD-encrypted
        // deniable anchor format (see anchor.rs::deniable_read_and_verify),
        // so a non-anchor file or an anchor from a different vault
        // fails the AEAD and returns `Error::OpaqueUnlockFailed`.
        //
        // Error-message policy: the format crate deliberately collapses
        // every anchor failure (missing file, wrong size, AEAD fail)
        // into one opaque `OpaqueUnlockFailed` to keep deniability
        // against an adversary running the reader on random files.
        // Here we are past the credential unlock, on the user's own
        // machine, and the user explicitly chose the anchor path - so
        // surfacing what went wrong leaks nothing they don't already
        // know. Pre-check file presence + size for sharper messages;
        // translate any residual error from `set_anchor` (which can
        // only be the AEAD step at that point) into an anchor-specific
        // message instead of the generic "unlock failed".
        let trusted_gen = if let Some(ap) = opts.anchor_path.as_ref() {
            preflight_deniable_anchor(ap)?;
            cont.set_anchor(Some(ap.clone())).map_err(|e| {
                format!(
                    "Anchor verification failed for {}: the file is the right \
                     size but does not decrypt under this vault's master key. \
                     Likely causes: anchor belongs to a different vault, was \
                     exported with different cipher/KDF parameters, or has been \
                     tampered with. Re-export the anchor from this vault, or \
                     open without an anchor (skips rollback detection). \
                     (underlying error: {e})",
                    ap.display()
                )
            })?
        } else {
            None
        };
        let vfs = open_vfs_with_optional_recovery(cont, opts.recovery_mode)?;
        if let Some(anchor_gen) = trusted_gen {
            match anchor::compare(anchor_gen, vfs.vault_generation()) {
                anchor::VerificationOutcome::Ok
                | anchor::VerificationOutcome::AnchorStale { .. } => {}
                anchor::VerificationOutcome::RollbackDetected {
                    anchor_gen,
                    metadata_gen,
                } => {
                    return Err(format!(
                        "Rollback detected: anchor at gen {anchor_gen} > vault at \
                         gen {metadata_gen}. Open refused (someone may have \
                         substituted an old copy of the vault)."
                    ));
                }
            }
        }
        let tolerated_inodes = vfs.tolerated_inodes().to_vec();
        return Ok(OpenedVault {
            vfs,
            vault_path: opts.path.clone(),
            header_path: None,
            anchor_path: opts.anchor_path.clone(),
            cipher_label,
            has_fido2: false,
            has_hybrid_pq: false,
            has_tpm: false,
            deniable_fido2_recovery: None,
            deniable_tpm_blob_path: None,
            tolerated_inodes,
        });
    }
    let mut cont = match opts.method {
        UnlockMethod::Passphrase => {
            let pw = opts.passphrase.as_ref().ok_or("passphrase required")?;
            Container::open(
                &opts.path,
                opts.header_path.as_deref(),
                UnlockMaterial::Passphrase(pw.as_bytes()),
            )
            .map_err(estr)?
        }
        UnlockMethod::Fido2 => unlock_with_fido2(
            &opts.path,
            opts.header_path.as_deref(),
            opts.pin.as_ref().ok_or("FIDO2 PIN required")?,
        )?,
        UnlockMethod::HybridPq => {
            let pw = opts.passphrase.as_ref().ok_or("passphrase required")?;
            let kp = opts
                .hybrid_kyber_path
                .as_ref()
                .ok_or("hybrid-pq requires the .kyber seed file path")?;
            // The slot passphrase and the .kyber seed-file passphrase
            // can be independent (Add Passphrase + ML-KEM lets the
            // user pick two distinct passphrases at enroll time). If
            // the user filled the seed-pw field, use it; otherwise
            // fall back to the slot passphrase to preserve the
            // "I used the same passphrase for both" ergonomic path.
            let seed_pw = opts
                .hybrid_seed_pw
                .as_ref()
                .filter(|s| !s.is_empty())
                .map(|s| s.as_str())
                .unwrap_or(pw.as_str());
            unlock_with_hybrid_pq(&opts.path, opts.header_path.as_deref(), pw, seed_pw, kp)?
        }
        UnlockMethod::Tpm2 => unlock_with_tpm2(&opts.path, opts.header_path.as_deref())?,
        UnlockMethod::Tpm2Pin => unlock_with_tpm2_pin(
            &opts.path,
            opts.header_path.as_deref(),
            opts.pin
                .as_ref()
                .ok_or_else(|| "TPM PIN required for tpm2-pin unlock".to_string())?,
        )?,
        UnlockMethod::Tpm2Fido2 => unlock_with_tpm2_fido2(
            &opts.path,
            opts.header_path.as_deref(),
            opts.pin
                .as_ref()
                .ok_or_else(|| "FIDO2 PIN required for tpm2-fido2 unlock".to_string())?,
        )?,
        UnlockMethod::HybridPqTpm2 => {
            let kp = opts
                .hybrid_kyber_path
                .as_ref()
                .ok_or("hybrid-pq-tpm2 requires the .kyber seed file path")?;
            let seed_pw = opts
                .passphrase
                .as_ref()
                .ok_or("hybrid-pq-tpm2 requires the .kyber seed-file passphrase")?;
            unlock_with_hybrid_pq_tpm2(&opts.path, opts.header_path.as_deref(), seed_pw, kp)?
        }
        UnlockMethod::HybridPqTpm2Fido2 => {
            let kp = opts
                .hybrid_kyber_path
                .as_ref()
                .ok_or("hybrid-pq-tpm2-fido2 requires the .kyber seed file path")?;
            let seed_pw = opts
                .passphrase
                .as_ref()
                .ok_or("hybrid-pq-tpm2-fido2 requires the .kyber seed-file passphrase")?;
            let pin = opts.pin.as_ref().ok_or("FIDO2 PIN required")?;
            unlock_with_hybrid_pq_tpm2_fido2(
                &opts.path,
                opts.header_path.as_deref(),
                seed_pw,
                pin,
                kp,
            )?
        }
        UnlockMethod::HybridPqFido2 => {
            let seed_pw = opts
                .passphrase
                .as_ref()
                .ok_or("hybrid-pq-fido2 needs the seed-file passphrase")?;
            let pin = opts.pin.as_ref().ok_or("FIDO2 PIN required")?;
            let kp = opts
                .hybrid_kyber_path
                .as_ref()
                .ok_or("hybrid-pq-fido2 needs the .kyber seed file path")?;
            unlock_with_hybrid_pq_fido2(&opts.path, opts.header_path.as_deref(), seed_pw, pin, kp)?
        }
        UnlockMethod::Sep => {
            // Fused SEP slots (FIDO2 / passphrase) also flow through
            // here; the per-slot loop collects whichever factors each
            // slot needs. `pin` carries the FIDO2 PIN, `passphrase` the
            // slot passphrase (both optional for plain/biometric slots).
            let pin = opts.pin.as_ref().map(|p| p.as_str());
            let passphrase = opts.passphrase.as_ref().map(|p| p.as_str());
            unlock_via_sep(&opts.path, opts.header_path.as_deref(), pin, passphrase)?
        }
        UnlockMethod::HybridPqSep => {
            let kp = opts
                .hybrid_kyber_path
                .as_ref()
                .ok_or("hybrid-pq-sep requires the .kyber seed file path")?;
            let seed_pw = opts
                .passphrase
                .as_ref()
                .ok_or("hybrid-pq-sep requires the .kyber seed-file passphrase")?;
            // Fused hybrid SEP slots may additionally bind FIDO2 and/or a
            // slot passphrase. The slot passphrase (when distinct from
            // the seed-file passphrase) is carried in `hybrid_seed_pw`;
            // when only one passphrase field is filled the seed-file
            // passphrase doubles as the slot passphrase.
            let pin = opts.pin.as_ref().map(|p| p.as_str());
            let slot_pp = opts
                .hybrid_seed_pw
                .as_ref()
                .filter(|p| !p.is_empty())
                .map(|p| p.as_str())
                .or(Some(seed_pw.as_str()));
            unlock_via_hybrid_pq_sep(
                &opts.path,
                opts.header_path.as_deref(),
                seed_pw,
                kp,
                pin,
                slot_pp,
            )?
        }
        // SepFido2 / HybridPqSepFido2 are deniable-only discovery hints
        // (standard vaults reach fused/hybrid SEP slots via the `Sep` /
        // `HybridPqSep` methods, which collect all factors per slot).
        UnlockMethod::SepFido2 | UnlockMethod::HybridPqSepFido2 => {
            return Err(
                "the SEP+FIDO2 unlock methods are used only in deniable mode; for a standard \
                 vault use the 'Secure Enclave' method, which collects every factor per slot"
                    .into(),
            );
        }
    };
    let trusted_gen = if let Some(ap) = opts.anchor_path.as_ref() {
        cont.set_anchor(Some(ap.clone())).map_err(estr)?
    } else {
        None
    };
    let has_fido2 = header_has_fido2(&cont.header);
    let has_hybrid_pq = header_has_hybrid_pq(&cont.header);
    let has_tpm = header_has_tpm(&cont.header);
    let cipher = cipher_label(cont.header.cipher_suite).to_string();
    let vfs = open_vfs_with_optional_recovery(cont, opts.recovery_mode)?;
    if let Some(anchor_gen) = trusted_gen {
        match anchor::compare(anchor_gen, vfs.vault_generation()) {
            anchor::VerificationOutcome::Ok | anchor::VerificationOutcome::AnchorStale { .. } => {}
            anchor::VerificationOutcome::RollbackDetected {
                anchor_gen,
                metadata_gen,
            } => {
                return Err(format!(
                    "Rollback detected: anchor at gen {anchor_gen} > vault at gen {metadata_gen}. \
                     Open refused (someone may have substituted an old copy of the vault)."
                ));
            }
        }
    }
    let tolerated_inodes = vfs.tolerated_inodes().to_vec();
    Ok(OpenedVault {
        vfs,
        vault_path: opts.path,
        header_path: opts.header_path,
        anchor_path: opts.anchor_path,
        cipher_label: cipher,
        has_fido2,
        has_hybrid_pq,
        has_tpm,
        deniable_fido2_recovery: None,
        deniable_tpm_blob_path: None,
        tolerated_inodes,
    })
}

/// Helper used by both deniable and standard open paths: runs
/// `Vfs::open(cont)` with the tolerate-bad-chunk-lists thread-local
/// set if and only if `recovery_mode == true`. Returns the resulting
/// Vfs; the `tolerated_inodes()` accessor on the Vfs carries the
/// recovery report (empty for normal opens).
fn open_vfs_with_optional_recovery(cont: Container, recovery_mode: bool) -> Result<Vfs, String> {
    if recovery_mode {
        let _g = luksbox_vfs::set_tolerate_bad_chunk_lists(true);
        Vfs::open(cont).map_err(estr)
    } else {
        Vfs::open(cont).map_err(estr)
    }
}

// ============================================================
// Deniable-mode create helpers (shared across all combos)
// ============================================================

/// Hybrid-PQ + passphrase deniable create. Mirrors `create_hybrid_pq`
/// (the standard variant) but routes through
/// `Container::create_with_credential_deniable` with the
/// `HybridPqPassphrase` variant, so the slot looks random on disk.
/// Generates the .kyber seed file and the .hybrid sidecar
/// alongside the vault (these ARE format-tells per
/// docs/DENIABLE_HEADER.md, documented and accepted for PQ).
#[allow(clippy::too_many_arguments)]
fn create_hybrid_pq_passphrase_deniable(
    path: &Path,
    cipher: CipherSuite,
    flags: u32,
    envelope_pw: &str,
    seed_pw: &str,
    kyber_path: &Path,
    params: luksbox_pq::PqParams,
    kdf_params: Argon2idParams,
) -> Result<Container, String> {
    use luksbox_format::deniable_header::DeniableMaterial;
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{encapsulate_with, keygen_with, seed_file};

    let (pk, seed) = keygen_with(params);
    let (ct, shared) = encapsulate_with(params, &pk).map_err(estr)?;

    let cred = luksbox_core::deniable::DeniableCredential::HybridPqPassphrase {
        passphrase: envelope_pw.as_bytes(),
        argon2: kdf_params,
        mlkem_shared: &shared,
    };
    let cont = Container::create_with_credential_v2_deniable(
        path,
        None,
        cipher,
        flags,
        0,
        &cred,
        &DeniableMaterial::passphrase_only(),
    )
    .map_err(estr)?;

    let sidecar = hybrid_sidecar::sidecar_path(path);
    hybrid_sidecar::write(
        &sidecar,
        &[HybridEntry {
            slot_idx: 0,
            level: params,
            pubkey: pk,
            ciphertext: ct,
        }],
    )
    .map_err(estr)?;
    // v2: seed-file passphrase is independently chosen. If the caller
    // wants both roles to share the same passphrase they pass the
    // envelope passphrase as `seed_pw`.
    seed_file::write(
        kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    )
    .map_err(estr)?;
    Ok(cont)
}

#[cfg(feature = "hardware")]
#[allow(clippy::too_many_arguments)]
fn create_hybrid_pq_fido2_deniable(
    path: &Path,
    cipher: CipherSuite,
    flags: u32,
    pin: &str,
    envelope_pw: &str,
    seed_pw: &str,
    kyber_path: &Path,
    params: luksbox_pq::PqParams,
    kdf_params: Argon2idParams,
) -> Result<(Container, Option<DeniableFido2RecoveryInfo>), String> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::deniable_header::DeniableMaterial;
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{encapsulate_with, keygen_with, seed_file};

    // FIDO2 enroll first - if the device touch fails, we haven't
    // written any sidecars yet.
    let mut auth = make_fido2_authenticator();
    let user_handle = random_user_handle().map_err(estr)?;
    let er = auth.enroll(RP_ID, &user_handle, Some(pin)).map_err(estr)?;
    let cred_id = er.credential.id;
    let mut hmac_salt = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut hmac_salt)
        .map_err(|e| format!("OS RNG failure: {e}"))?;
    let hmac_secret = auth
        .hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(pin))
        .map_err(estr)?;

    let (pk, seed) = keygen_with(params);
    let (ct, shared) = encapsulate_with(params, &pk).map_err(estr)?;

    // v2: envelope_pw opens the slot envelope; seed_pw is used
    // separately for seed-file encryption. Caller passes the same
    // string for both when they want a single shared passphrase
    // (the GUI's default UX), or distinct strings to separate the
    // two roles.
    let cred = luksbox_core::deniable::DeniableCredential::HybridPqFido2Passphrase {
        passphrase: envelope_pw.as_bytes(),
        argon2: kdf_params,
        mlkem_shared: &shared,
        hmac_secret_output: &hmac_secret,
    };
    let material = DeniableMaterial {
        cred_id: cred_id.clone(),
        hmac_salt: Some(hmac_salt),
        tpm_blob: Vec::new(),
    };
    let cont = Container::create_with_credential_v2_deniable(
        path, None, cipher, flags, 0, &cred, &material,
    )
    .map_err(estr)?;

    let sidecar = hybrid_sidecar::sidecar_path(path);
    hybrid_sidecar::write(
        &sidecar,
        &[HybridEntry {
            slot_idx: 0,
            level: params,
            pubkey: pk,
            ciphertext: ct,
        }],
    )
    .map_err(estr)?;
    seed_file::write(
        kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    )
    .map_err(estr)?;

    // v2: cred_id + hmac_salt are now inside the slot envelope, so
    // no recovery info needs to be surfaced to the user. Returning
    // None keeps the existing caller wiring intact.
    Ok((cont, None))
}

// ============================================================
// Deniable-mode unlock helpers (shared across all combos)
// ============================================================
//
// Each helper does one device-or-file operation that yields a
// 32-byte secret (FIDO2 hmac, ML-KEM shared, TPM unsealed). The
// combo-specific dispatch arms in `unlock_vault` call zero or more
// of these and assemble the resulting `DeniableCredential` variant.

/// Deniable PQ-decap: reads the user's `.kyber` seed file at
/// `opts.hybrid_kyber_path` using `opts.passphrase` (the seed
/// passphrase), then runs ML-KEM decapsulation against the
/// ciphertext in the existing `.hybrid` sidecar next to the vault.
/// Returns the 32-byte shared secret to feed into a
/// `DeniableCredential::HybridPq*` variant.
fn deniable_pq_decap(opts: &UnlockOpts, slot_idx: u8) -> Result<Zeroizing<[u8; 32]>, String> {
    use luksbox_format::hybrid_sidecar;
    use luksbox_pq::seed_file;
    let kyber_path = opts
        .hybrid_kyber_path
        .as_ref()
        .ok_or("hybrid-PQ deniable unlock requires the .kyber seed file path")?;
    // v2: the seed-file passphrase can be distinct from the envelope
    // passphrase (the create flows for HybridPq+TPM bootstrap allow
    // separate `seed_pw`). Prefer the explicit `hybrid_seed_pw`
    // field if the caller supplied it; fall back to the envelope
    // passphrase when they're the same.
    let seed_pw = opts
        .hybrid_seed_pw
        .as_ref()
        .filter(|s| !s.is_empty())
        .or(opts.passphrase.as_ref())
        .ok_or(
            "hybrid-PQ deniable unlock requires the seed-file passphrase \
             (in the passphrase or seed-file passphrase field)",
        )?;
    let seed = seed_file::read(kyber_path, seed_pw.as_bytes()).map_err(estr)?;
    let sidecar = hybrid_sidecar::sidecar_path(&opts.path);
    // Deniable mode does not have a standard `Header::header_salt`
    // (the v3 sidecar binding format), so `read_for_vault` does not
    // apply here. Cross-vault swap detection in deniable mode falls
    // back to downstream AEAD failure (slot envelope tag verification)
    // - same posture as v1/v2 sidecars in standard mode.
    let entries = hybrid_sidecar::read(&sidecar).map_err(estr)?;
    // Match the sidecar entry to the deniable slot index the
    // envelope discovery just resolved. Earlier versions defaulted
    // to `entries.first()`, which broke unlock on any vault with
    // two PQC-bearing slots where the user's seed corresponded to
    // a non-first slot: ML-KEM's implicit rejection produced a
    // garbage shared secret instead of a hard decap error, the
    // garbage flowed through factors_kek, and the final AEAD
    // rejected silently.
    let entry = hybrid_sidecar::find(&entries, slot_idx).ok_or_else(|| {
        format!(
            "no .hybrid sidecar entry for slot {slot_idx} (the deniable header \
             resolved this slot but the matching ML-KEM (pk, ct) pair is missing \
             from the sidecar)"
        )
    })?;
    // decapsulate_with returns Zeroizing<[u8; 32]>; pass it
    // through unchanged so the caller borrows from the wrapper and
    // the shared secret is wiped when the caller drops the
    // returned value (after the slot KEK has been derived).
    luksbox_pq::decapsulate_with(entry.level, &seed, &entry.ciphertext).map_err(estr)
}

/// v2 GUI helper: drive the FIDO2 authenticator using cred_id +
/// hmac_salt recovered from the slot envelope (no longer reads them
/// from `opts.deniable_fido2_cred_id_hex` etc).
#[cfg(feature = "hardware")]
fn deniable_fido2_hmac_from_payload(
    opts: &UnlockOpts,
    cred_id: &[u8],
    salt: &[u8; 32],
    prehash_salt: bool,
) -> Result<luksbox_fido2::HmacSecret, String> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID};
    let pin = opts.pin.as_ref().ok_or("FIDO2 PIN required")?;
    if cred_id.is_empty() {
        return Err("envelope cred_id is empty for FIDO2 variant".into());
    }
    let mut auth = make_fido2_authenticator();
    // Deniable v2 envelopes embed the cred_id + salt at create time
    // but, unlike keyslots, record NO salt-convention marker.
    // v0.3.0 creates envelopes under the V4 prehashed convention;
    // v0.2.1/v0.2.2 envelopes recorded raw-salt HMACs on
    // Linux/macOS. Callers probe: `prehash_salt = true` first, then
    // on an inner-AEAD failure retry with `false` via
    // `Container::complete_open_v2_deniable_reusable` (the user
    // touches the authenticator a second time; the PIN comes from
    // `opts` so nothing is re-prompted).
    auth.hmac_secret(RP_ID, cred_id, salt, prehash_salt, Some(pin))
        .map_err(estr)
}

/// v2 GUI helper: unseal a TPM blob recovered from the slot
/// envelope (no longer reads it from `opts.deniable_tpm_blob_path`).
#[cfg(all(feature = "hardware", target_os = "linux"))]
fn deniable_tpm_unseal_from_bytes(
    blob_bytes: &[u8],
    pin: Option<&[u8]>,
) -> Result<[u8; 32], String> {
    use luksbox_tpm::{SealedBlob, Tpm2Sealer};
    if blob_bytes.is_empty() {
        return Err("envelope tpm_blob is empty for TPM variant".into());
    }
    let blob = SealedBlob::from_bytes(blob_bytes).map_err(estr)?;
    let mut sealer = Tpm2Sealer::new().map_err(estr)?;
    let unsealed = match pin {
        Some(p) => sealer.unseal_with_pin(&blob, Some(p)).map_err(estr)?,
        None => sealer.unseal(&blob).map_err(estr)?,
    };
    Ok(*unsealed)
}

/// Re-derive the 32-byte Secure Enclave ECDH secret from the SEP blob
/// revealed by deniable phase-1 envelope decryption. The macOS analog of
/// `deniable_tpm_unseal_from_bytes`; `unseal` prompts Touch ID inside the
/// enclave for biometric blobs.
#[cfg(all(feature = "hardware", target_os = "macos"))]
fn deniable_sep_unseal_from_bytes(blob_bytes: &[u8]) -> Result<[u8; 32], String> {
    use luksbox_sep::{SepBlob, SepSealer};
    if blob_bytes.is_empty() {
        return Err("envelope SEP blob is empty for the Secure Enclave variant".into());
    }
    let blob = SepBlob::from_bytes(blob_bytes).map_err(estr)?;
    let mut sealer = SepSealer::new().map_err(estr)?;
    let shared = sealer.unseal(&blob).map_err(estr)?;
    Ok(*shared)
}

/// Salt-prehash conventions to try, in order, when unlocking a FIDO2
/// keyslot. On Windows, `webauthn.dll` applies an opaque transform to
/// the hmac-secret salt that we cannot observe or override, so a slot
/// enrolled under one convention may need the *other* fed to
/// `webauthn.dll` to reproduce the device salt the slot was created
/// with. Try the slot's declared convention first and, if the open
/// fails, fall back to the opposite, using whichever unlocks (one extra
/// Windows Hello tap only on the fallback). libfido2 (Linux/macOS) is
/// deterministic, so the declared convention is always correct there
/// and we try only it. Mirrors the deniable-envelope probe above and
/// the CLI's `fido2_salt_conventions`.
#[cfg(feature = "hardware")]
fn fido2_salt_conventions(declared_prehash: bool) -> Vec<bool> {
    #[cfg(target_os = "windows")]
    {
        vec![declared_prehash, !declared_prehash]
    }
    #[cfg(not(target_os = "windows"))]
    {
        vec![declared_prehash]
    }
}

#[cfg(feature = "hardware")]
fn unlock_with_fido2(
    path: &Path,
    header_path: Option<&Path>,
    pin: &str,
) -> Result<Container, String> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID};
    let header_src = header_path.unwrap_or(path);
    let mut f =
        luksbox_core::file_util::open_existing_read_no_follow_policy(header_src).map_err(estr)?;
    let mut header_bytes = [0u8; HEADER_SIZE];
    f.read_exact(&mut header_bytes).map_err(estr)?;
    drop(f);
    let header = Header::from_bytes(&header_bytes).map_err(estr)?;
    let mut auth = make_fido2_authenticator();
    let mut last_err: Option<String> = None;
    for slot in &header.keyslots {
        if !matches!(
            slot.kind,
            SlotKind::Fido2HmacSecret | SlotKind::Fido2DerivedMvk
        ) {
            continue;
        }
        // Declared salt convention first, then (Windows) the opposite,
        // since webauthn.dll's salt transform is opaque. Covers both
        // Fido2HmacSecret (wrap) and Fido2DerivedMvk (direct).
        for prehash in fido2_salt_conventions(slot.fido2_salt_prehashed()) {
            let hmac_secret = match auth.hmac_secret(
                RP_ID,
                &slot.fido2_cred_id,
                &slot.fido2_hmac_salt,
                prehash,
                Some(pin),
            ) {
                Ok(s) => s,
                Err(e) => {
                    last_err = Some(format!("FIDO2: {e}"));
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
                Err(e) => last_err = Some(e.to_string()),
            }
        }
    }
    Err(last_err.unwrap_or_else(|| "no FIDO2 keyslot in this vault".into()))
}

#[cfg(not(feature = "hardware"))]
fn unlock_with_fido2(
    _path: &Path,
    _header_path: Option<&Path>,
    _pin: &str,
) -> Result<Container, String> {
    Err("FIDO2 hardware support not compiled in".into())
}

/// Unlock via the local TPM 2.0 chip. Returns a `Container` that
/// the outer `unlock_vault` then runs through anchor + Vfs
/// post-processing (same shape as `unlock_with_fido2`).
#[cfg(feature = "hardware")]
fn unlock_with_tpm2(path: &Path, header_path: Option<&Path>) -> Result<Container, String> {
    use luksbox_tpm::{SealedBlob, Tpm2Sealer};

    // Pre-scan for the slot kind so a missing-slot error is
    // friendly rather than "TPM unsealed something but it didn't
    // match anything".
    let header_src = header_path.unwrap_or(path);
    let mut f =
        luksbox_core::file_util::open_existing_read_no_follow_policy(header_src).map_err(estr)?;
    let mut header_bytes = [0u8; HEADER_SIZE];
    f.read_exact(&mut header_bytes).map_err(estr)?;
    drop(f);
    let header = Header::from_bytes(&header_bytes).map_err(estr)?;
    if !header
        .keyslots
        .iter()
        .any(|s| s.kind == SlotKind::Tpm2Sealed)
    {
        return Err(
            "this vault has no TPM 2.0 keyslot. Open with another method, then \
             enroll one via Manage Keyslots -> Add TPM 2.0 keyslot."
                .into(),
        );
    }

    let mut sealer =
        Tpm2Sealer::new().map_err(|e| format!("could not open local TPM 2.0 device: {e}"))?;
    let mut unseal = |blob: &[u8]| -> std::result::Result<[u8; 32], String> {
        let parsed = SealedBlob::from_bytes(blob)
            .map_err(|e| format!("malformed TPM SealedBlob in keyslot: {e}"))?;
        let kek = sealer
            .unseal(&parsed)
            .map_err(|e| format!("TPM unseal: {e}"))?;
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
    .map_err(estr)
}

#[cfg(not(feature = "hardware"))]
fn unlock_with_tpm2(_path: &Path, _header_path: Option<&Path>) -> Result<Container, String> {
    Err("TPM 2.0 hardware support not compiled in (rebuild with --features hardware)".into())
}

/// Unlock via the local macOS Secure Enclave (CLI's
/// `open_container_sep` equivalent). Iterates the vault's plain +
/// biometric SEP slots; the closure asks the enclave to unseal each
/// slot's blob back to its 32-byte shared secret. Biometric slots
/// trigger a Touch ID prompt inside `unseal`.
#[cfg(feature = "hardware")]
fn unlock_via_sep(
    path: &Path,
    header_path: Option<&Path>,
    pin: Option<&str>,
    passphrase: Option<&str>,
) -> Result<Container, String> {
    let header_src = header_path.unwrap_or(path);
    let mut f =
        luksbox_core::file_util::open_existing_read_no_follow_policy(header_src).map_err(estr)?;
    let mut header_bytes = [0u8; HEADER_SIZE];
    f.read_exact(&mut header_bytes).map_err(estr)?;
    drop(f);
    let header = Header::from_bytes(&header_bytes).map_err(estr)?;
    // Non-hybrid SEP slots (plain / biometric / fused FIDO2 / passphrase).
    if !header
        .keyslots
        .iter()
        .any(|s| s.kind.is_sep() && !s.kind.is_hybrid_pq())
    {
        return Err(
            "this vault has no (non-hybrid) Secure Enclave keyslot. Open with another method, \
             then enroll one via Manage Keyslots -> Add Secure Enclave keyslot."
                .into(),
        );
    }
    open_sep_common(path, header_path, &header, pin, passphrase, None)
}

#[cfg(not(feature = "hardware"))]
fn unlock_via_sep(
    _path: &Path,
    _header_path: Option<&Path>,
    _pin: Option<&str>,
    _passphrase: Option<&str>,
) -> Result<Container, String> {
    Err("Secure Enclave support not compiled in (rebuild with --features hardware)".into())
}

/// Shared SEP open loop for both the non-hybrid (`unlock_via_sep`) and
/// hybrid (`unlock_via_hybrid_pq_sep`) paths. Mirrors the CLI's
/// `open_sep_common`: iterates every SEP keyslot whose hybrid-ness
/// matches this path, collects whichever extra factors the slot's kind
/// requires (FIDO2 hmac-secret derived from the slot's stored cred_id +
/// salt; passphrase reused across slots), and hands `Container::open`
/// an `UnlockMaterial::Sep` whose factor set matches the slot.
/// `pq_shared_for` supplies the ML-KEM shared secret per slot index for
/// hybrid kinds (None = no PQ).
#[cfg(feature = "hardware")]
fn open_sep_common(
    path: &Path,
    header_path: Option<&Path>,
    header: &Header,
    pin: Option<&str>,
    passphrase: Option<&str>,
    pq_shared_for: Option<&dyn Fn(usize) -> Option<[u8; 32]>>,
) -> Result<Container, String> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID};
    use luksbox_sep::{SepBlob, SepSealer};

    let want_pq = pq_shared_for.is_some();

    // Does any in-scope slot need a passphrase / FIDO2?
    let needs_pp = header.keyslots.iter().any(|s| {
        s.kind.is_sep() && s.kind.is_sep_passphrase() && s.kind.is_hybrid_pq() == want_pq
    });
    let any_fido2_slot = header
        .keyslots
        .iter()
        .any(|s| s.kind.is_sep() && s.kind.is_sep_fido2() && s.kind.is_hybrid_pq() == want_pq);

    if needs_pp && passphrase.map(|p| p.is_empty()).unwrap_or(true) {
        return Err(
            "this vault has a Secure Enclave + passphrase keyslot; enter the slot passphrase to \
             unlock."
                .into(),
        );
    }
    let collect_fido2 = any_fido2_slot && pin.map(|p| !p.is_empty()).unwrap_or(false);
    if any_fido2_slot && !collect_fido2 {
        return Err(
            "this vault has a Secure Enclave + FIDO2 keyslot; enter the FIDO2 PIN to unlock."
                .into(),
        );
    }

    let mut sealer = SepSealer::new().map_err(|e| format!("{e}"))?;
    let mut auth = if collect_fido2 {
        Some(make_fido2_authenticator())
    } else {
        None
    };
    let mut last_err: Option<String> = None;

    for (idx, slot) in header.keyslots.iter().enumerate() {
        if !slot.kind.is_sep() {
            continue;
        }
        // Only attempt slots whose hybrid-ness matches this path.
        if slot.kind.is_hybrid_pq() != want_pq {
            continue;
        }
        // Skip FIDO2 slots when we didn't collect a PIN.
        if slot.kind.is_sep_fido2() && !collect_fido2 {
            continue;
        }

        // PQ shared secret for this slot (hybrid kinds only).
        let pq = match (want_pq, pq_shared_for) {
            (true, Some(f)) => match f(idx) {
                Some(s) => Some(s),
                None => {
                    last_err = Some(format!("no ML-KEM shared secret for slot {idx}"));
                    continue;
                }
            },
            _ => None,
        };

        // FIDO2 hmac-secret for this slot, derived from the slot's own
        // stored cred_id + hmac_salt (same as tpm2-fido2). Try both salt
        // conventions, mirroring the CLI's open path.
        let hmac_secret = if slot.kind.is_sep_fido2() {
            let pin = pin.expect("collect_fido2 implies a PIN");
            let auth = auth.as_mut().expect("collect_fido2 implies an authenticator");
            if slot.fido2_cred_id.is_empty() {
                last_err = Some(format!("FIDO2 slot {idx} has no stored cred_id"));
                continue;
            }
            let mut hs: Option<[u8; 32]> = None;
            for prehash in fido2_salt_conventions(slot.fido2_salt_prehashed()) {
                match auth.hmac_secret(
                    RP_ID,
                    &slot.fido2_cred_id,
                    &slot.fido2_hmac_salt,
                    prehash,
                    Some(pin),
                ) {
                    Ok(s) => {
                        hs = Some(*s);
                        break;
                    }
                    Err(e) => last_err = Some(format!("FIDO2 slot {idx}: {e}")),
                }
            }
            match hs {
                Some(s) => Some(s),
                None => continue,
            }
        } else {
            None
        };

        let mut unseal = |blob: &[u8]| -> std::result::Result<[u8; 32], String> {
            let sb = SepBlob::from_bytes(blob).map_err(|e| e.to_string())?;
            let s = sealer.unseal(&sb).map_err(|e| e.to_string())?;
            let mut out = [0u8; 32];
            out.copy_from_slice(s.as_slice());
            Ok(out)
        };

        match Container::open(
            path,
            header_path,
            UnlockMaterial::Sep {
                unseal: &mut unseal,
                hmac_secret: hmac_secret.as_ref(),
                passphrase: if slot.kind.is_sep_passphrase() {
                    passphrase.map(|p| p.as_bytes())
                } else {
                    None
                },
                pq_shared: pq.as_ref(),
            },
        ) {
            Ok(c) => return Ok(c),
            Err(e) => last_err = Some(format!("open slot {idx}: {e}")),
        }
    }
    Err(last_err.unwrap_or_else(|| "no Secure Enclave keyslot matched the supplied factors".into()))
}

/// Unlock via a hybrid Secure Enclave + ML-KEM keyslot (CLI's
/// `open_container_hybrid_pq_sep` equivalent). Reads the .kyber seed +
/// .hybrid sidecar, decapsulates per slot, asks the enclave to unseal,
/// and hands both halves to `UnlockMaterial::Sep { pq_shared }`.
#[cfg(feature = "hardware")]
fn unlock_via_hybrid_pq_sep(
    path: &Path,
    header_path: Option<&Path>,
    seed_pw: &str,
    kyber_path: &Path,
    pin: Option<&str>,
    passphrase: Option<&str>,
) -> Result<Container, String> {
    use luksbox_format::hybrid_sidecar;
    use luksbox_pq::seed_file;

    let header_src = header_path.unwrap_or(path);
    let mut f =
        luksbox_core::file_util::open_existing_read_no_follow_policy(header_src).map_err(estr)?;
    let mut header_bytes = [0u8; HEADER_SIZE];
    f.read_exact(&mut header_bytes).map_err(estr)?;
    drop(f);
    let header = Header::from_bytes(&header_bytes).map_err(estr)?;
    if !header
        .keyslots
        .iter()
        .any(|s| s.kind.is_sep() && s.kind.is_hybrid_pq())
    {
        return Err(
            "this vault has no hybrid Secure Enclave + ML-KEM keyslot. Use a different \
             unlock method or enroll one via Manage Keyslots."
                .into(),
        );
    }
    let seed = seed_file::read(kyber_path, seed_pw.as_bytes())
        .map_err(|e| format!("read kyber seed: {e}"))?;
    // v3 vault-binding verification (see `read_for_vault` doc).
    let entries =
        hybrid_sidecar::read_for_vault(&hybrid_sidecar::sidecar_path(path), path, header_path)
            .map_err(|e| format!("read hybrid sidecar: {e}"))?;

    // Per-slot ML-KEM decapsulation closure, consumed by open_sep_common.
    let decap = |idx: usize| -> Option<[u8; 32]> {
        let entry = hybrid_sidecar::find(&entries, idx as u8)?;
        luksbox_pq::decapsulate_with(entry.level, &seed, &entry.ciphertext)
            .ok()
            .map(|z| *z)
    };

    open_sep_common(path, header_path, &header, pin, passphrase, Some(&decap))
}

#[cfg(not(feature = "hardware"))]
fn unlock_via_hybrid_pq_sep(
    _path: &Path,
    _header_path: Option<&Path>,
    _seed_pw: &str,
    _kyber_path: &Path,
    _pin: Option<&str>,
    _passphrase: Option<&str>,
) -> Result<Container, String> {
    Err("hybrid-pq-sep unlock requires --features hardware (macOS Secure Enclave)".into())
}

/// Unlock via a fused TPM + FIDO2 keyslot. Per slot: drives the
/// FIDO2 hmac_secret call with that slot's stored cred_id +
/// hmac_salt, then asks the TPM to unseal the slot's blob, then
/// hands both halves to `UnlockMaterial::Tpm2Fido2`.
#[cfg(feature = "hardware")]
fn unlock_with_tpm2_fido2(
    path: &Path,
    header_path: Option<&Path>,
    pin: &str,
) -> Result<Container, String> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID};
    use luksbox_tpm::{SealedBlob, Tpm2Sealer};

    let header_src = header_path.unwrap_or(path);
    let mut f =
        luksbox_core::file_util::open_existing_read_no_follow_policy(header_src).map_err(estr)?;
    let mut header_bytes = [0u8; HEADER_SIZE];
    f.read_exact(&mut header_bytes).map_err(estr)?;
    drop(f);
    let header = Header::from_bytes(&header_bytes).map_err(estr)?;
    if !header
        .keyslots
        .iter()
        .any(|s| s.kind == SlotKind::Tpm2Fido2)
    {
        return Err(
            "this vault has no fused TPM+FIDO2 keyslot. Open with another method, \
             then enroll one via Manage Keyslots -> Add TPM 2.0 + FIDO2 keyslot."
                .into(),
        );
    }

    let mut sealer =
        Tpm2Sealer::new().map_err(|e| format!("could not open local TPM 2.0 device: {e}"))?;
    let mut auth = make_fido2_authenticator();
    let mut last_err: Option<String> = None;
    for slot in &header.keyslots {
        if slot.kind != SlotKind::Tpm2Fido2 {
            continue;
        }
        let stored_cred = match slot.tpm2_fido2_cred_id() {
            Some(c) => c.to_vec(),
            None => continue,
        };
        // Declared salt convention first, then (Windows) the opposite,
        // because webauthn.dll's salt transform is opaque.
        for prehash in fido2_salt_conventions(slot.fido2_salt_prehashed()) {
            let hmac_secret = match auth.hmac_secret(
                RP_ID,
                &stored_cred,
                &slot.fido2_hmac_salt,
                prehash,
                Some(pin),
            ) {
                Ok(s) => s,
                Err(e) => {
                    last_err = Some(format!("FIDO2 hmac-secret: {e}"));
                    continue;
                }
            };
            let mut unseal = |blob: &[u8]| -> std::result::Result<[u8; 32], String> {
                let parsed = SealedBlob::from_bytes(blob)
                    .map_err(|e| format!("malformed TPM SealedBlob: {e}"))?;
                let kek = sealer
                    .unseal(&parsed)
                    .map_err(|e| format!("TPM unseal: {e}"))?;
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
                Ok(cont) => return Ok(cont),
                Err(e) => last_err = Some(e.to_string()),
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        "no Tpm2Fido2 slot matched the connected authenticator + local TPM".into()
    }))
}

#[cfg(not(feature = "hardware"))]
fn unlock_with_tpm2_fido2(
    _path: &Path,
    _header_path: Option<&Path>,
    _pin: &str,
) -> Result<Container, String> {
    Err("TPM 2.0 + FIDO2 fused unlock requires --features hardware".into())
}

/// Hybrid TPM + ML-KEM-768 unlock (CLI's open_container_hybrid_pq_tpm2
/// equivalent). Reads .kyber seed + .hybrid sidecar, decapsulates
/// per slot, asks the TPM to unseal, hands both halves to the
/// format layer.
#[cfg(feature = "hardware")]
fn unlock_with_hybrid_pq_tpm2(
    path: &Path,
    header_path: Option<&Path>,
    seed_pw: &str,
    kyber_path: &Path,
) -> Result<Container, String> {
    use luksbox_format::hybrid_sidecar;
    use luksbox_pq::seed_file;
    use luksbox_tpm::{SealedBlob, Tpm2Sealer};

    let header_src = header_path.unwrap_or(path);
    let mut f =
        luksbox_core::file_util::open_existing_read_no_follow_policy(header_src).map_err(estr)?;
    let mut header_bytes = [0u8; HEADER_SIZE];
    f.read_exact(&mut header_bytes).map_err(estr)?;
    drop(f);
    let header = Header::from_bytes(&header_bytes).map_err(estr)?;
    // Match BOTH the ML-KEM-768 and ML-KEM-1024 hybrid TPM slots.
    // The wrap-KEK derivation is identical for both KEM sizes (the
    // 32-byte shared secret enters HKDF the same way); the on-disk
    // SlotKind is the only thing that differs, and the actual KEM
    // level used per slot is encoded in the .hybrid sidecar's
    // `entry.level` so decapsulate_with picks the correct cipher
    // automatically.
    if !header.keyslots.iter().any(|s| {
        matches!(
            s.kind,
            SlotKind::HybridPqKemTpm2 | SlotKind::HybridPqKem1024Tpm2
        )
    }) {
        return Err(
            "this vault has no hybrid TPM + ML-KEM keyslot. Use a different unlock \
             method or enroll one via Manage Keyslots."
                .into(),
        );
    }
    let seed = seed_file::read(kyber_path, seed_pw.as_bytes())
        .map_err(|e| format!("read kyber seed: {e}"))?;
    // v3 vault-binding verification (see `read_for_vault` doc).
    let entries =
        hybrid_sidecar::read_for_vault(&hybrid_sidecar::sidecar_path(path), path, header_path)
            .map_err(|e| format!("read hybrid sidecar: {e}"))?;
    let mut sealer =
        Tpm2Sealer::new().map_err(|e| format!("could not open local TPM 2.0 device: {e}"))?;

    let mut last_err: Option<String> = None;
    for (slot_idx_usize, slot) in header.keyslots.iter().enumerate() {
        if !matches!(
            slot.kind,
            SlotKind::HybridPqKemTpm2 | SlotKind::HybridPqKem1024Tpm2
        ) {
            continue;
        }
        let slot_idx = slot_idx_usize as u8;
        let entry = match hybrid_sidecar::find(&entries, slot_idx) {
            Some(e) => e,
            None => {
                last_err = Some(format!("no sidecar entry for slot {slot_idx}"));
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
        let mut unseal = |blob: &[u8]| -> Result<[u8; 32], String> {
            let parsed = SealedBlob::from_bytes(blob)
                .map_err(|e| format!("malformed TPM SealedBlob: {e}"))?;
            let kek = sealer
                .unseal(&parsed)
                .map_err(|e| format!("TPM unseal: {e}"))?;
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
            Err(e) => last_err = Some(e.to_string()),
        }
    }
    Err(last_err.unwrap_or_else(|| "no hybrid-pq-tpm2 slot matched the local TPM".into()))
}

#[cfg(not(feature = "hardware"))]
fn unlock_with_hybrid_pq_tpm2(
    _path: &Path,
    _header_path: Option<&Path>,
    _seed_pw: &str,
    _kyber_path: &Path,
) -> Result<Container, String> {
    Err("hybrid-pq-tpm2 unlock requires --features hardware".into())
}

/// 3-factor hybrid unlock: TPM + FIDO2 + ML-KEM-768.
#[cfg(feature = "hardware")]
fn unlock_with_hybrid_pq_tpm2_fido2(
    path: &Path,
    header_path: Option<&Path>,
    seed_pw: &str,
    pin: &str,
    kyber_path: &Path,
) -> Result<Container, String> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID};
    use luksbox_format::hybrid_sidecar;
    use luksbox_pq::seed_file;
    use luksbox_tpm::{SealedBlob, Tpm2Sealer};

    let header_src = header_path.unwrap_or(path);
    let mut f =
        luksbox_core::file_util::open_existing_read_no_follow_policy(header_src).map_err(estr)?;
    let mut header_bytes = [0u8; HEADER_SIZE];
    f.read_exact(&mut header_bytes).map_err(estr)?;
    drop(f);
    let header = Header::from_bytes(&header_bytes).map_err(estr)?;
    // Match BOTH 768 and 1024 hybrid-PQ-TPM-FIDO2 slot kinds. See
    // the comment in unlock_with_hybrid_pq_tpm2 above for why the
    // KEM size is auto-detected from the sidecar `entry.level`
    // rather than carried in the SlotKind for unwrap purposes.
    if !header.keyslots.iter().any(|s| {
        matches!(
            s.kind,
            SlotKind::HybridPqKemTpm2Fido2 | SlotKind::HybridPqKem1024Tpm2Fido2
        )
    }) {
        return Err("this vault has no hybrid TPM + FIDO2 + ML-KEM keyslot.".into());
    }
    let seed = seed_file::read(kyber_path, seed_pw.as_bytes())
        .map_err(|e| format!("read kyber seed: {e}"))?;
    // v3 vault-binding verification (see `read_for_vault` doc).
    let entries =
        hybrid_sidecar::read_for_vault(&hybrid_sidecar::sidecar_path(path), path, header_path)
            .map_err(|e| format!("read hybrid sidecar: {e}"))?;
    let mut sealer =
        Tpm2Sealer::new().map_err(|e| format!("could not open local TPM 2.0 device: {e}"))?;
    let mut auth = make_fido2_authenticator();
    let mut last_err: Option<String> = None;
    for (slot_idx_usize, slot) in header.keyslots.iter().enumerate() {
        if !matches!(
            slot.kind,
            SlotKind::HybridPqKemTpm2Fido2 | SlotKind::HybridPqKem1024Tpm2Fido2
        ) {
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
                last_err = Some(format!("no sidecar entry for slot {slot_idx}"));
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
        // Declared salt convention first, then (Windows) the opposite,
        // because webauthn.dll's salt transform is opaque.
        for prehash in fido2_salt_conventions(slot.fido2_salt_prehashed()) {
            let hmac_secret = match auth.hmac_secret(
                RP_ID,
                &stored_cred,
                &slot.fido2_hmac_salt,
                prehash,
                Some(pin),
            ) {
                Ok(s) => s,
                Err(e) => {
                    last_err = Some(format!("FIDO2: {e}"));
                    continue;
                }
            };
            let mut unseal = |blob: &[u8]| -> Result<[u8; 32], String> {
                let parsed = SealedBlob::from_bytes(blob)
                    .map_err(|e| format!("malformed TPM SealedBlob: {e}"))?;
                let kek = sealer
                    .unseal(&parsed)
                    .map_err(|e| format!("TPM unseal: {e}"))?;
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
                Err(e) => last_err = Some(e.to_string()),
            }
        }
    }
    Err(last_err.unwrap_or_else(|| "no hybrid-pq-tpm2-fido2 slot matched all 3 factors".into()))
}

#[cfg(not(feature = "hardware"))]
fn unlock_with_hybrid_pq_tpm2_fido2(
    _path: &Path,
    _header_path: Option<&Path>,
    _seed_pw: &str,
    _pin: &str,
    _kyber_path: &Path,
) -> Result<Container, String> {
    Err("hybrid-pq-tpm2-fido2 unlock requires --features hardware".into())
}

fn header_has_fido2(h: &Header) -> bool {
    h.keyslots.iter().any(|s| {
        matches!(
            s.kind,
            SlotKind::Fido2HmacSecret
                | SlotKind::Fido2DerivedMvk
                | SlotKind::HybridPqKemFido2
                | SlotKind::HybridPqKem1024Fido2
        )
    })
}

pub fn header_has_hybrid_pq(h: &Header) -> bool {
    h.keyslots.iter().any(|s| s.kind.is_hybrid_pq())
}

pub fn header_has_tpm(h: &Header) -> bool {
    h.keyslots.iter().any(|s| s.kind.is_tpm2())
}

/// Read the (unencrypted) on-disk header and return one short label
/// per populated keyslot. Used by the GUI's recent-vaults panel to
/// surface the slot composition BEFORE the user picks an unlock
/// method, so they know which factors are enrolled. Best-effort:
/// returns Err with a friendly message on missing/corrupt headers,
/// the caller falls back to "(unknown)".
pub fn inspect_slot_kinds(vault: &Path, header_path: Option<&Path>) -> Result<Vec<String>, String> {
    use luksbox_core::{HEADER_SIZE, keyslot::SlotKind};
    use std::fs::File;
    use std::io::Read;
    let src = header_path.unwrap_or(vault);
    let mut f = File::open(src).map_err(|e| format!("open {}: {e}", src.display()))?;
    let mut bytes = [0u8; HEADER_SIZE];
    f.read_exact(&mut bytes)
        .map_err(|e| format!("read header: {e}"))?;
    let header = Header::from_bytes(&bytes).map_err(|e| format!("parse header: {e}"))?;
    let labels: Vec<String> = header
        .keyslots
        .iter()
        .enumerate()
        .filter(|(_, s)| s.kind != SlotKind::Empty)
        .map(|(i, s)| format!("slot {i}: {}", slot_kind_label(s.kind)))
        .collect();
    Ok(labels)
}

fn slot_kind_label(k: luksbox_core::keyslot::SlotKind) -> &'static str {
    use luksbox_core::keyslot::SlotKind;
    match k {
        SlotKind::Empty => "empty",
        SlotKind::Passphrase => "passphrase",
        SlotKind::Fido2HmacSecret => "FIDO2 (wrap)",
        SlotKind::Fido2DerivedMvk => "FIDO2-direct",
        SlotKind::HybridPqKemPassphrase => "passphrase + ML-KEM-768",
        SlotKind::HybridPqKemFido2 => "FIDO2 + ML-KEM-768",
        SlotKind::HybridPqKem1024Passphrase => "passphrase + ML-KEM-1024",
        SlotKind::HybridPqKem1024Fido2 => "FIDO2 + ML-KEM-1024",
        SlotKind::Tpm2Sealed => "TPM 2.0",
        SlotKind::Tpm2Fido2 => "TPM 2.0 + FIDO2",
        SlotKind::Tpm2SealedPin => "TPM 2.0 + PIN",
        SlotKind::HybridPqKemTpm2 => "TPM 2.0 + ML-KEM-768",
        SlotKind::HybridPqKemTpm2Fido2 => "TPM 2.0 + FIDO2 + ML-KEM-768",
        SlotKind::HybridPqKem1024Tpm2 => "TPM 2.0 + ML-KEM-1024",
        SlotKind::HybridPqKem1024Tpm2Fido2 => "TPM 2.0 + FIDO2 + ML-KEM-1024",
        SlotKind::SepSealed => "Secure Enclave",
        SlotKind::SepSealedBiometric => "Secure Enclave + biometry",
        SlotKind::HybridPqKemSep => "Secure Enclave + ML-KEM-768",
        SlotKind::HybridPqKem1024Sep => "Secure Enclave + ML-KEM-1024",
        SlotKind::SepFido2 => "Secure Enclave + FIDO2",
        SlotKind::HybridPqKemSepFido2 => "Secure Enclave + FIDO2 + ML-KEM-768",
        SlotKind::HybridPqKem1024SepFido2 => "Secure Enclave + FIDO2 + ML-KEM-1024",
        SlotKind::SepPassphrase => "Secure Enclave + passphrase",
        SlotKind::HybridPqKemSepPassphrase => "Secure Enclave + passphrase + ML-KEM-768",
        SlotKind::HybridPqKem1024SepPassphrase => "Secure Enclave + passphrase + ML-KEM-1024",
        SlotKind::SepFido2Passphrase => "Secure Enclave + FIDO2 + passphrase",
        SlotKind::HybridPqKemSepFido2Passphrase => {
            "Secure Enclave + FIDO2 + passphrase + ML-KEM-768"
        }
        SlotKind::HybridPqKem1024SepFido2Passphrase => {
            "Secure Enclave + FIDO2 + passphrase + ML-KEM-1024"
        }
    }
}

#[cfg(feature = "hardware")]
fn unlock_with_hybrid_pq_fido2(
    path: &Path,
    header_path: Option<&Path>,
    seed_passphrase: &str,
    pin: &str,
    kyber_path: &Path,
) -> Result<Container, String> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID};
    use luksbox_format::hybrid_sidecar;
    use luksbox_pq::seed_file;

    let header_src = header_path.unwrap_or(path);
    let mut f =
        luksbox_core::file_util::open_existing_read_no_follow_policy(header_src).map_err(estr)?;
    let mut header_bytes = [0u8; HEADER_SIZE];
    f.read_exact(&mut header_bytes).map_err(estr)?;
    drop(f);
    let header = Header::from_bytes(&header_bytes).map_err(estr)?;

    let seed = seed_file::read(kyber_path, seed_passphrase.as_bytes()).map_err(estr)?;
    let sidecar = hybrid_sidecar::sidecar_path(path);
    let entries = hybrid_sidecar::read(&sidecar).map_err(estr)?;

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
                last_err = Some(format!("no sidecar entry for slot {slot_idx}"));
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
        // Declared salt convention first, then (Windows) the opposite,
        // because webauthn.dll's salt transform is opaque.
        for prehash in fido2_salt_conventions(slot.fido2_salt_prehashed()) {
            let hmac_secret = match auth.hmac_secret(
                RP_ID,
                &slot.fido2_cred_id,
                &slot.fido2_hmac_salt,
                prehash,
                Some(pin),
            ) {
                Ok(s) => s,
                Err(e) => {
                    last_err = Some(format!("FIDO2: {e}"));
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
    }
    Err(last_err.unwrap_or_else(|| "hybrid-fido2 unlock failed".into()))
}

#[cfg(not(feature = "hardware"))]
fn unlock_with_hybrid_pq_fido2(
    _path: &Path,
    _header_path: Option<&Path>,
    _seed_passphrase: &str,
    _pin: &str,
    _kyber_path: &Path,
) -> Result<Container, String> {
    Err("FIDO2 hardware support not compiled in".into())
}

fn unlock_with_hybrid_pq(
    path: &Path,
    header_path: Option<&Path>,
    slot_pw: &str,
    seed_pw: &str,
    kyber_path: &Path,
) -> Result<Container, String> {
    use luksbox_format::hybrid_sidecar;
    use luksbox_pq::seed_file;

    // The seed file is encrypted with `seed_pw`, the keyslot KEK
    // derives from `slot_pw`. Earlier versions used the same string
    // for both, which broke the "Add Passphrase + ML-KEM" flow where
    // the user picks two distinct passphrases at enroll time and the
    // GUI surfaces a separate seed-pw field at unlock.
    let seed = seed_file::read(kyber_path, seed_pw.as_bytes()).map_err(estr)?;
    let sidecar = hybrid_sidecar::sidecar_path(path);
    let entries = hybrid_sidecar::read(&sidecar).map_err(estr)?;
    if entries.is_empty() {
        return Err("hybrid sidecar is empty".into());
    }
    let mut last_err: Option<String> = None;
    for entry in &entries {
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
                passphrase: slot_pw.as_bytes(),
                pq_shared: &shared,
            },
        ) {
            Ok(c) => return Ok(c),
            Err(e) => last_err = Some(format!("open slot {}: {e}", entry.slot_idx)),
        }
    }
    Err(last_err.unwrap_or_else(|| "hybrid unlock failed".into()))
}

// ---- file ops -------------------------------------------------------------

pub fn put_file(vfs: &mut Vfs, local: &Path, inner: &str) -> Result<u64, String> {
    let (parent, name) = split_parent_name(vfs, inner)?;
    if vfs.lookup(parent, &name).is_ok() {
        return Err(format!("{inner} already exists"));
    }
    let f = vfs.create(parent, &name).map_err(estr)?;
    let mut src = File::open(local).map_err(estr)?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut offset = 0u64;
    loop {
        let n = src.read(&mut buf).map_err(estr)?;
        if n == 0 {
            break;
        }
        vfs.write(f, offset, &buf[..n]).map_err(estr)?;
        offset += n as u64;
    }
    vfs.flush().map_err(estr)?;
    Ok(offset)
}

/// Recursively extract `inner` (must be a directory) into `local`. Creates
/// `local` if needed. Files are decrypted in 64 KiB chunks via `get_file`;
/// subdirectories are walked depth-first. Returns total decrypted-byte
/// count across every file written.
pub fn get_dir_recursive(vfs: &mut Vfs, inner: &str, local: &Path) -> Result<u64, String> {
    let id = vfs.lookup_path(inner).map_err(estr)?;
    let st = vfs.stat(id).map_err(estr)?;
    if st.kind != InodeKind::Directory {
        return Err(format!("{inner} is not a directory"));
    }
    // Extracted directories are mode 0700 on Unix so the plaintext
    // they contain isn't world-readable under a default 022 umask.
    luksbox_core::file_util::secure_create_dir_all(local).map_err(estr)?;
    let entries = vfs.readdir(id).map_err(estr)?;
    let mut total = 0u64;
    for ent in entries {
        // Zip-slip / tar-slip defense-in-depth. luksbox-vfs's
        // `validate_name` already rejects `/`, `\`, NUL, `.`, `..`
        // and over-long names both at create-time AND at metadata-
        // load time, so a well-formed vault can never reach this
        // point with a name that resolves outside `local`. We
        // re-check here because:
        //
        // 1. A future bug in `validate_metadata_tree` (or a new
        //    inode-kind that bypasses the per-entry name walk)
        //    would otherwise let a malicious vault write files
        //    outside the user's chosen extract destination, under
        //    the user's process privileges -- the classic archive-
        //    extraction CVE pattern (CVE-2018-1002200 "zip slip",
        //    a recurring source of supply-chain compromise via
        //    Electron apps and code-signing tools).
        //
        // 2. Belt-and-suspenders against `Path::join` quirks --
        //    on Windows a drive-letter prefix like `C:foo` makes
        //    join discard the base path entirely; the format
        //    layer's NAME_MAX + char allowlist catches the slash
        //    forms but a windows-specific extra check here is
        //    cheap and explicit.
        if name_escapes_directory(&ent.name) {
            return Err(format!(
                "vault contains an entry name that would escape the destination \
                 directory ('{}'); refusing to extract. This indicates a corrupt \
                 or maliciously-constructed vault.",
                ent.name
            ));
        }
        let inner_child = if inner == "/" {
            format!("/{}", ent.name)
        } else {
            format!("{}/{}", inner.trim_end_matches('/'), ent.name)
        };
        let local_child = local.join(&ent.name);
        match ent.kind {
            InodeKind::File => {
                total += get_file(vfs, &inner_child, &local_child)?;
            }
            InodeKind::Directory => {
                total += get_dir_recursive(vfs, &inner_child, &local_child)?;
            }
            InodeKind::Symlink => {
                // Symlinks: re-create on the host filesystem with
                // the validated target. `Vfs::readlink` returned
                // a target that has already gone through
                // `is_safe_symlink_target` (rejects absolute paths,
                // `..` components, NULs, oversize) -- the resulting
                // host-side symlink can only point to a sibling of
                // `local_child` inside the extract destination. If
                // a future bug let an unsafe target through, the
                // host kernel would still resolve it inside the
                // user's filesystem on later access, so the
                // VFS-layer sanitization is the load-bearing
                // defense (this is just the materialization step).
                let target = vfs
                    .readlink(vfs.lookup_path(&inner_child).map_err(estr)?)
                    .map_err(estr)?;
                // Defense-in-depth re-check at extract time, same
                // class as `name_escapes_directory` above. Note:
                // the equivalent check for symlink targets is
                // looser than for entry names (relative `..`s
                // bounded by parent depth would be safe), but the
                // VFS already refuses any `..` so the check
                // collapses to "redundant strict ban", which is
                // fine.
                if target.is_empty()
                    || target.contains('\0')
                    || target.starts_with('/')
                    || target.starts_with('\\')
                    || target.contains("..")
                {
                    return Err(format!(
                        "vault contains a symlink with an escape target ('{target}'); \
                         refusing to materialise"
                    ));
                }
                #[cfg(unix)]
                {
                    if let Err(e) = std::os::unix::fs::symlink(&target, &local_child) {
                        return Err(format!(
                            "failed to materialise symlink {}: {e}",
                            local_child.display()
                        ));
                    }
                }
                #[cfg(not(unix))]
                {
                    return Err(format!(
                        "vault contains a symlink ({inner_child}) but this host \
                         does not support symlink creation in the extract path"
                    ));
                }
            }
        }
    }
    Ok(total)
}

/// Returns true if joining `name` to a directory path could possibly
/// resolve outside that directory. Conservative on purpose: any name
/// that contains a path separator (`/` or `\`), looks like a
/// directory-traversal component (`..` or `.`), is empty, or starts
/// with a Windows drive-letter prefix triggers rejection. Cheap, no
/// I/O.
pub(crate) fn name_escapes_directory(name: &str) -> bool {
    if name.is_empty() || name == "." || name == ".." {
        return true;
    }
    if name.contains('/') || name.contains('\\') {
        return true;
    }
    // On Windows `:` is never valid in a filename: it introduces either
    // a drive-letter prefix (e.g. "C:foo", which `Path::join` treats as
    // an absolute reset, discarding the base directory -- audit F2) or
    // an alternate data stream (e.g. "file.exe:Zone.Identifier", which
    // would target the ADS of `file.exe` -- audit F3). POSIX names can
    // legitimately contain `:`, so the rejection is windows-gated.
    // Rejecting any `:` subsumes the drive-letter prefix case.
    #[cfg(windows)]
    {
        if name.contains(':') {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod name_escapes_directory_tests {
    use super::name_escapes_directory;

    #[test]
    fn rejects_traversal_and_separator_chars() {
        for bad in [
            "",
            ".",
            "..",
            "../etc/passwd",
            "foo/bar",
            "foo\\bar",
            "..\\..\\Windows\\System32\\hosts",
            "\\Windows",
            "/etc/shadow",
        ] {
            assert!(
                name_escapes_directory(bad),
                "expected {bad:?} to be rejected as path-escaping",
            );
        }
    }

    #[test]
    fn accepts_ordinary_names() {
        for good in ["README.md", "deadbeef", "file.tar.gz", "spaces in name"] {
            assert!(
                !name_escapes_directory(good),
                "expected {good:?} to be accepted as a plain leaf name",
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_drive_letter_prefix_is_rejected() {
        assert!(name_escapes_directory("C:malicious"));
        assert!(name_escapes_directory("d:foo"));
    }

    /// R14-06 (audit F3): on Windows, a `:` anywhere in the name targets
    /// an alternate data stream, so it must be rejected even when it is
    /// not a drive-letter prefix. POSIX builds still accept `:` names.
    #[cfg(windows)]
    #[test]
    fn windows_ads_colon_is_rejected() {
        assert!(name_escapes_directory("malware.exe:Zone.Identifier"));
        assert!(name_escapes_directory("readme:hidden"));
    }

    #[cfg(not(windows))]
    #[test]
    fn posix_colon_name_is_allowed() {
        // `:` is a legal POSIX filename byte; the windows-only ADS guard
        // must not reject it on POSIX (existing vaults can contain it).
        assert!(!name_escapes_directory("time-12:30.log"));
    }
}

pub fn get_file(vfs: &mut Vfs, inner: &str, local: &Path) -> Result<u64, String> {
    let id = vfs.lookup_path(inner).map_err(estr)?;
    let st = vfs.stat(id).map_err(estr)?;
    if st.kind != InodeKind::File {
        return Err(format!("{inner} is not a file"));
    }
    // Mode 0600 on Unix - extracted plaintext stays owner-only.
    let mut dst = luksbox_core::file_util::secure_create_or_truncate(local).map_err(estr)?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut offset = 0u64;
    while offset < st.size {
        let n = vfs.read(id, offset, &mut buf).map_err(estr)?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n]).map_err(estr)?;
        offset += n as u64;
    }
    Ok(offset)
}

pub fn split_parent_name(vfs: &Vfs, p: &str) -> Result<(luksbox_vfs::FileId, String), String> {
    let trimmed = p.trim_start_matches('/');
    if trimmed.is_empty() {
        return Err("empty path".into());
    }
    let (parent_path, name) = match trimmed.rfind('/') {
        Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
        None => ("", trimmed),
    };
    let parent_id = vfs.lookup_path(parent_path).map_err(estr)?;
    Ok((parent_id, name.to_string()))
}

// ---- panic-destroy --------------------------------------------------------

pub fn panic_destroy(
    vault: &Path,
    header_path: Option<&Path>,
    wipe_data: bool,
) -> Result<(), String> {
    use luksbox_core::file_util::secure_open_existing_no_follow;
    // No-follow opens for both targets BEFORE any write, closing
    // the TOCTOU window where a symlink swap in the parent dir
    // could redirect the random-bytes overwrite to an arbitrary
    // file (e.g. /etc/shadow if the GUI is somehow running as
    // root, or the user's own SSH keys if not).
    let header_target = header_path.unwrap_or(vault);
    let mut hf = secure_open_existing_no_follow(header_target).map_err(|e| {
        format!(
            "refusing to open {} for destructive overwrite: {e}",
            header_target.display()
        )
    })?;
    let mut vf_opt = if wipe_data && header_target != vault {
        Some(
            secure_open_existing_no_follow(vault)
                .map_err(|e| format!("refusing to open {} for data wipe: {e}", vault.display()))?,
        )
    } else {
        None
    };
    let len_hint = std::fs::metadata(vault).map(|m| m.len()).unwrap_or(0);

    let mut buf = [0u8; HEADER_SIZE];
    OsRng.fill_bytes(&mut buf);
    hf.seek(SeekFrom::Start(0)).map_err(estr)?;
    hf.write_all(&buf).map_err(estr)?;
    hf.flush().map_err(estr)?;
    if wipe_data {
        let writer: &mut std::fs::File = vf_opt.as_mut().unwrap_or(&mut hf);
        let len = len_hint;
        writer.seek(SeekFrom::Start(0)).map_err(estr)?;
        let mut chunk = vec![0u8; 1 << 20];
        let mut written = 0u64;
        while written < len {
            OsRng.fill_bytes(&mut chunk);
            let to_write = ((len - written) as usize).min(chunk.len());
            writer.write_all(&chunk[..to_write]).map_err(estr)?;
            written += to_write as u64;
        }
        writer.flush().map_err(estr)?;
        let _ = writer.sync_all();
    }
    Ok(())
}

// ---- keyslot helpers ------------------------------------------------------

pub fn enroll_passphrase(vfs: &mut Vfs, pw: &str, kdf: KdfStrength) -> Result<usize, String> {
    let cont = vfs.container_mut();
    let idx = cont
        .enroll_passphrase(pw.as_bytes(), kdf.params())
        .map_err(estr)?;
    cont.persist_header().map_err(estr)?;
    Ok(idx)
}

/// Deniable-mode passphrase enrollment at a specific slot index.
/// Standard `enroll_passphrase` would silently mis-save in deniable
/// mode (it mutates the synthetic Header while persist_header writes
/// the cached deniable buffer), so the GUI / CLI route to this
/// function instead. The admin picks `slot_idx` via the UI; the
/// Container rejects the unlock-slot index as a footgun guard.
pub fn enroll_passphrase_deniable(
    vfs: &mut Vfs,
    slot_idx: usize,
    pw: &str,
    kdf: KdfStrength,
) -> Result<usize, String> {
    let cont = vfs.container_mut();
    let idx = cont
        .enroll_passphrase_deniable(slot_idx, pw.as_bytes(), kdf.params())
        .map_err(estr)?;
    cont.persist_header().map_err(estr)?;
    Ok(idx)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KdfStrength {
    Interactive,
    Moderate,
    Sensitive,
}

impl KdfStrength {
    pub fn params(self) -> Argon2idParams {
        match self {
            Self::Interactive => Argon2idParams::INTERACTIVE,
            Self::Moderate => Argon2idParams::MODERATE,
            Self::Sensitive => Argon2idParams::SENSITIVE,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Interactive => "Interactive, 256 MiB / 3 iter (about 500 ms)",
            Self::Moderate => "Moderate, 512 MiB / 4 iter (about 1.5 s)",
            Self::Sensitive => "Sensitive, 1 GiB / 5 iter (about 3-4 s)",
        }
    }
}

#[cfg(feature = "hardware")]
pub fn enroll_fido2(vfs: &mut Vfs, pin: &str) -> Result<usize, String> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    let mut auth = make_fido2_authenticator();
    let user_handle = random_user_handle().map_err(estr)?;
    let er = auth.enroll(RP_ID, &user_handle, Some(pin)).map_err(estr)?;
    let cred_id = er.credential.id;
    let mut hmac_salt = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut hmac_salt)
        .map_err(|e| format!("OS RNG failure generating FIDO2 hmac salt: {e}"))?;
    let hmac_secret = auth
        .hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(pin))
        .map_err(estr)?;
    let cont = vfs.container_mut();
    let idx = cont
        .enroll_fido2(
            None,
            &hmac_secret,
            &cred_id,
            hmac_salt,
            Argon2idParams::INTERACTIVE,
        )
        .map_err(estr)?;
    cont.persist_header().map_err(estr)?;
    Ok(idx)
}

#[cfg(not(feature = "hardware"))]
pub fn enroll_fido2(_vfs: &mut Vfs, _pin: &str) -> Result<usize, String> {
    Err("FIDO2 hardware support not compiled in".into())
}

/// Deniable-mode FIDO2 enrollment at a specific slot index. The
/// container's standard `enroll_fido2` would mis-save (synthetic
/// header mutation + persist writes deniable bytes); this routes
/// through `Container::enroll_credential_deniable` with the
/// `Fido2` variant. Returns the (slot_idx, cred_id_hex,
/// hmac_salt_hex) so the GUI can show a recovery card; cred_id
/// and hmac_salt are NOT stored on disk and must be saved
/// externally for later unlock.
#[cfg(feature = "hardware")]
pub fn enroll_fido2_deniable(
    vfs: &mut Vfs,
    slot_idx: usize,
    pin: &str,
    passphrase: &str,
    argon2: Argon2idParams,
) -> Result<usize, String> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::deniable_header::DeniableMaterial;
    if passphrase.is_empty() {
        return Err("v2 deniable enroll requires an envelope passphrase for the new slot".into());
    }
    let mut auth = make_fido2_authenticator();
    let user_handle = random_user_handle().map_err(estr)?;
    let er = auth.enroll(RP_ID, &user_handle, Some(pin)).map_err(estr)?;
    let cred_id = er.credential.id;
    let mut hmac_salt = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut hmac_salt)
        .map_err(|e| format!("OS RNG failure: {e}"))?;
    let hmac_secret = auth
        .hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(pin))
        .map_err(estr)?;

    let cont = vfs.container_mut();
    let cred = luksbox_core::deniable::DeniableCredential::Fido2Passphrase {
        passphrase: passphrase.as_bytes(),
        argon2,
        hmac_secret_output: &hmac_secret,
    };
    let material = DeniableMaterial {
        cred_id,
        hmac_salt: Some(hmac_salt),
        tpm_blob: Vec::new(),
    };
    let idx = cont
        .enroll_credential_v2_deniable(slot_idx, &cred, &material)
        .map_err(estr)?;
    cont.persist_header().map_err(estr)?;
    Ok(idx)
}

#[cfg(not(feature = "hardware"))]
pub fn enroll_fido2_deniable(
    _vfs: &mut Vfs,
    _slot_idx: usize,
    _pin: &str,
    _passphrase: &str,
    _argon2: Argon2idParams,
) -> Result<usize, String> {
    Err("FIDO2 hardware support not compiled in".into())
}

// ============================================================
// TPM deniable enroll helpers
// ============================================================

// v1 helper `tpm_blob_sidecar_path` removed in v2; the TPM sealed
// blob lives inside the slot envelope instead of next to the vault.

/// v2 helper: seal a fresh 32-byte secret with the local TPM and
/// return both the secret (for KEK derivation) and the sealed blob
/// bytes (for embedding inside the v2 slot envelope). No sidecar is
/// written; the v2 envelope carries the blob.
#[cfg(all(feature = "hardware", target_os = "linux"))]
fn tpm_seal_to_bytes_for_deniable(
    pin: Option<&[u8]>,
) -> Result<(zeroize::Zeroizing<[u8; 32]>, Vec<u8>), String> {
    use luksbox_tpm::Tpm2Sealer;
    let mut sealer =
        Tpm2Sealer::new().map_err(|e| format!("could not open local TPM 2.0 device: {e}"))?;
    let mut secret = zeroize::Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(secret.as_mut_slice())
        .map_err(|e| format!("OS RNG failure generating TPM secret: {e}"))?;
    let blob = match pin {
        Some(p) => sealer
            .seal_with_pin(&secret, Some(p))
            .map_err(|e| format!("TPM seal: {e}"))?,
        None => sealer.seal(&secret).map_err(|e| format!("TPM seal: {e}"))?,
    };
    Ok((secret, blob.to_bytes()))
}

// v1 helper `tpm_seal_for_deniable` (which wrote a `.tpm-blob`
// sidecar) is removed in v2; callers use
// `tpm_seal_to_bytes_for_deniable` above and embed the bytes in the
// slot envelope.

/// Deniable TPM + passphrase enrollment (v2). Seals a fresh secret,
/// embeds the sealed blob in the slot envelope, installs a
/// `DeniableCredential::TpmPassphrase` slot at `slot_idx`. Returns
/// the new slot index.
///
/// `tpm_pin` is the optional userAuth bound to the TPM-sealed blob:
/// `Some(pin)` for the "TPM + PIN" UI flow (unlock will require
/// the same PIN), `None` for "TPM only" (unlock uses the
/// chip-bound primary key without any user secret). Note that the
/// envelope passphrase is independent of `tpm_pin` -- it's always
/// required by v2 deniable's envelope discovery.
///
/// Mismatch warning: the GUI's unlock-side `UnlockMethod::Tpm2Pin`
/// calls `unseal_with_pin(blob, Some(pin))`, which fails with
/// `TPM_RC_AUTH_FAIL` (0x098e) and increments the dictionary-
/// attack counter if the blob was sealed without a PIN. Earlier
/// versions of this function unconditionally sealed with `None`
/// and silently discarded any PIN typed in the "Add TPM+PIN
/// (deniable)" modal, producing the exact symptom above.
#[cfg(all(feature = "hardware", target_os = "linux"))]
pub fn enroll_tpm2_deniable(
    vfs: &mut Vfs,
    slot_idx: usize,
    passphrase: &str,
    argon2: Argon2idParams,
    tpm_pin: Option<&[u8]>,
) -> Result<usize, String> {
    use luksbox_format::deniable_header::DeniableMaterial;
    if passphrase.is_empty() {
        return Err("v2 deniable enroll requires an envelope passphrase for the new slot".into());
    }
    // Refuse empty `Some(pin)` so a stray Default::default() in a
    // form can't silently downgrade the slot to no-PIN. Caller
    // should pass `None` for the TPM-only flow.
    if matches!(tpm_pin, Some(p) if p.is_empty()) {
        return Err("TPM PIN cannot be empty; pass None for the no-PIN variant".into());
    }
    let (secret, blob) = tpm_seal_to_bytes_for_deniable(tpm_pin)?;
    let cred = luksbox_core::deniable::DeniableCredential::TpmPassphrase {
        passphrase: passphrase.as_bytes(),
        argon2,
        unsealed: &secret,
    };
    let material = DeniableMaterial {
        cred_id: Vec::new(),
        hmac_salt: None,
        tpm_blob: blob,
    };
    let cont = vfs.container_mut();
    let idx = cont
        .enroll_credential_v2_deniable(slot_idx, &cred, &material)
        .map_err(estr)?;
    cont.persist_header().map_err(estr)?;
    Ok(idx)
}

/// Deniable TPM + FIDO2 + passphrase enrollment (v2). Seals a fresh
/// TPM secret, enrolls a FIDO2 credential, combines both with the
/// envelope passphrase into a `DeniableCredential::TpmFido2Passphrase`
/// slot with all material embedded inside the slot envelope.
#[cfg(all(feature = "hardware", target_os = "linux"))]
pub fn enroll_tpm2_fido2_deniable(
    vfs: &mut Vfs,
    slot_idx: usize,
    fido2_pin: &str,
    passphrase: &str,
    argon2: Argon2idParams,
) -> Result<usize, String> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::deniable_header::DeniableMaterial;
    if passphrase.is_empty() {
        return Err("v2 deniable enroll requires an envelope passphrase for the new slot".into());
    }
    let (tpm_secret, tpm_blob) = tpm_seal_to_bytes_for_deniable(None)?;

    let mut auth = make_fido2_authenticator();
    let user_handle = random_user_handle().map_err(estr)?;
    let er = auth
        .enroll(RP_ID, &user_handle, Some(fido2_pin))
        .map_err(estr)?;
    let cred_id = er.credential.id;
    let mut hmac_salt = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut hmac_salt)
        .map_err(|e| format!("OS RNG failure: {e}"))?;
    let hmac_secret = auth
        .hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(fido2_pin))
        .map_err(estr)?;

    let cred = luksbox_core::deniable::DeniableCredential::TpmFido2Passphrase {
        passphrase: passphrase.as_bytes(),
        argon2,
        unsealed: &tpm_secret,
        hmac_secret_output: &hmac_secret,
    };
    let material = DeniableMaterial {
        cred_id,
        hmac_salt: Some(hmac_salt),
        tpm_blob,
    };
    let cont = vfs.container_mut();
    let idx = cont
        .enroll_credential_v2_deniable(slot_idx, &cred, &material)
        .map_err(estr)?;
    cont.persist_header().map_err(estr)?;
    Ok(idx)
}

/// Deniable hybrid-PQ + TPM + passphrase enrollment (v2). The TPM
/// sealed blob is embedded in the slot envelope; the `.kyber` seed
/// file remains a sidecar (PQ material is not folded into v2 slots).
#[cfg(all(feature = "hardware", target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
pub fn enroll_hybrid_pq_tpm2_deniable(
    vfs: &mut Vfs,
    slot_idx: usize,
    vault: &Path,
    kyber_path: &Path,
    seed_pw: &str,
    passphrase: &str,
    argon2: Argon2idParams,
    params: luksbox_pq::PqParams,
) -> Result<usize, String> {
    use luksbox_format::deniable_header::DeniableMaterial;
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{encapsulate_with, keygen_with, seed_file};
    if passphrase.is_empty() {
        return Err("v2 deniable enroll requires an envelope passphrase for the new slot".into());
    }

    let (tpm_secret, tpm_blob) = tpm_seal_to_bytes_for_deniable(None)?;
    let (pk, seed) = keygen_with(params);
    let (ct, shared) = encapsulate_with(params, &pk).map_err(estr)?;

    let cred = luksbox_core::deniable::DeniableCredential::HybridPqTpmPassphrase {
        passphrase: passphrase.as_bytes(),
        argon2,
        mlkem_shared: &shared,
        unsealed: &tpm_secret,
    };
    let material = DeniableMaterial {
        cred_id: Vec::new(),
        hmac_salt: None,
        tpm_blob,
    };
    let cont = vfs.container_mut();
    let idx = cont
        .enroll_credential_v2_deniable(slot_idx, &cred, &material)
        .map_err(estr)?;
    cont.persist_header().map_err(estr)?;

    // Merge with existing sidecar entries (replacing any stale
    // entry for the same slot index). Earlier versions of this
    // function unconditionally clobbered the sidecar with a
    // single-entry vec, which silently DELETED entries for other
    // PQ slots and made the symmetric `_passphrase_deniable` /
    // `_fido2_deniable` flows fail with "duplicate entry for
    // slot N" when the user picked an occupied index.
    let hybrid_sidecar_path = hybrid_sidecar::sidecar_path(vault);
    let prior_entries: Vec<HybridEntry> = if hybrid_sidecar_path.exists() {
        hybrid_sidecar::read(&hybrid_sidecar_path).map_err(estr)?
    } else {
        Vec::new()
    };
    let mut entries: Vec<HybridEntry> = prior_entries
        .iter()
        .filter(|e| usize::from(e.slot_idx) != idx)
        .cloned()
        .collect();
    entries.push(HybridEntry {
        slot_idx: idx as u8,
        level: params,
        pubkey: pk,
        ciphertext: ct,
    });
    hybrid_sidecar::write(&hybrid_sidecar_path, &entries).map_err(estr)?;
    seed_file::write(
        kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    )
    .map_err(estr)?;
    Ok(idx)
}

/// Deniable 4-factor enrollment (v2): hybrid-PQ + TPM + FIDO2 +
/// passphrase. TPM blob and FIDO2 material live in the slot
/// envelope; ML-KEM material stays in the `.kyber` sidecar.
#[cfg(all(feature = "hardware", target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
pub fn enroll_hybrid_pq_tpm2_fido2_deniable(
    vfs: &mut Vfs,
    slot_idx: usize,
    vault: &Path,
    kyber_path: &Path,
    seed_pw: &str,
    fido2_pin: &str,
    passphrase: &str,
    argon2: Argon2idParams,
    params: luksbox_pq::PqParams,
) -> Result<usize, String> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::deniable_header::DeniableMaterial;
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{encapsulate_with, keygen_with, seed_file};
    if passphrase.is_empty() {
        return Err("v2 deniable enroll requires an envelope passphrase for the new slot".into());
    }

    let (tpm_secret, tpm_blob) = tpm_seal_to_bytes_for_deniable(None)?;

    let mut auth = make_fido2_authenticator();
    let user_handle = random_user_handle().map_err(estr)?;
    let er = auth
        .enroll(RP_ID, &user_handle, Some(fido2_pin))
        .map_err(estr)?;
    let cred_id = er.credential.id;
    let mut hmac_salt = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut hmac_salt)
        .map_err(|e| format!("OS RNG failure: {e}"))?;
    let hmac_secret = auth
        .hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(fido2_pin))
        .map_err(estr)?;

    let (pk, seed) = keygen_with(params);
    let (ct, shared) = encapsulate_with(params, &pk).map_err(estr)?;

    let cred = luksbox_core::deniable::DeniableCredential::HybridPqTpmFido2Passphrase {
        passphrase: passphrase.as_bytes(),
        argon2,
        mlkem_shared: &shared,
        unsealed: &tpm_secret,
        hmac_secret_output: &hmac_secret,
    };
    let material = DeniableMaterial {
        cred_id,
        hmac_salt: Some(hmac_salt),
        tpm_blob,
    };
    let cont = vfs.container_mut();
    let idx = cont
        .enroll_credential_v2_deniable(slot_idx, &cred, &material)
        .map_err(estr)?;
    cont.persist_header().map_err(estr)?;

    // Merge with existing sidecar (see comment on
    // `enroll_hybrid_pq_tpm2_deniable` above for rationale).
    let hybrid_sidecar_path = hybrid_sidecar::sidecar_path(vault);
    let prior_entries: Vec<HybridEntry> = if hybrid_sidecar_path.exists() {
        hybrid_sidecar::read(&hybrid_sidecar_path).map_err(estr)?
    } else {
        Vec::new()
    };
    let mut entries: Vec<HybridEntry> = prior_entries
        .iter()
        .filter(|e| usize::from(e.slot_idx) != idx)
        .cloned()
        .collect();
    entries.push(HybridEntry {
        slot_idx: idx as u8,
        level: params,
        pubkey: pk,
        ciphertext: ct,
    });
    hybrid_sidecar::write(&hybrid_sidecar_path, &entries).map_err(estr)?;
    seed_file::write(
        kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    )
    .map_err(estr)?;
    Ok(idx)
}

/// Enroll a TPM 2.0-bound keyslot in the open vault. Generates a
/// random 32-byte KEK, asks the local TPM 2.0 to seal it, and
/// installs a `Tpm2Sealed` slot wrapping the MVK under that KEK.
/// No passphrase, no FIDO2 - subsequent unlocks via TPM only.
#[cfg(feature = "hardware")]
pub fn enroll_tpm2(vfs: &mut Vfs) -> Result<usize, String> {
    use luksbox_tpm::Tpm2Sealer;
    use zeroize::Zeroizing;

    // Open TPM context BEFORE generating secret material so a
    // missing-chip error surfaces before we have anything to wipe.
    let mut sealer =
        Tpm2Sealer::new().map_err(|e| format!("could not open local TPM 2.0 device: {e}"))?;
    let mut kek = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(kek.as_mut_slice())
        .map_err(|e| format!("OS RNG failure generating TPM KEK: {e}"))?;
    let blob = sealer.seal(&kek).map_err(|e| format!("TPM seal: {e}"))?;
    let cont = vfs.container_mut();
    let idx = cont.enroll_tpm2(&kek, &blob.to_bytes()).map_err(estr)?;
    cont.persist_header().map_err(estr)?;
    Ok(idx)
}

#[cfg(not(feature = "hardware"))]
pub fn enroll_tpm2(_vfs: &mut Vfs) -> Result<usize, String> {
    Err("TPM 2.0 hardware support not compiled in".into())
}

/// Enroll a fused TPM + FIDO2 keyslot. Both factors required at
/// every subsequent unlock: TPM seals one half, FIDO2 hmac-secret
/// is the other half. KEK = HKDF(both halves). Loss of EITHER
/// factor permanently kills this slot - the GUI's
/// "Add fused TPM+FIDO2 keyslot" affordance prompts for a recovery
/// slot at the same time, but this function itself is layer-pure
/// and just installs the one fused slot.
#[cfg(feature = "hardware")]
pub fn enroll_tpm2_fido2(vfs: &mut Vfs, pin: &str) -> Result<usize, String> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_tpm::Tpm2Sealer;
    use zeroize::Zeroizing;

    let mut sealer =
        Tpm2Sealer::new().map_err(|e| format!("could not open local TPM 2.0 device: {e}"))?;
    let mut auth = make_fido2_authenticator();
    let user_handle = random_user_handle().map_err(estr)?;
    let er = auth.enroll(RP_ID, &user_handle, Some(pin)).map_err(estr)?;
    let cred_id = er.credential.id;

    let mut tpm_unsealed = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(tpm_unsealed.as_mut_slice())
        .map_err(|e| format!("OS RNG failure generating TPM half: {e}"))?;
    let blob = sealer
        .seal(&tpm_unsealed)
        .map_err(|e| format!("TPM seal: {e}"))?;

    let mut hmac_salt = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut hmac_salt)
        .map_err(|e| format!("OS RNG failure generating FIDO2 hmac salt: {e}"))?;
    let hmac_secret = auth
        .hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(pin))
        .map_err(estr)?;

    let cont = vfs.container_mut();
    let idx = cont
        .enroll_tpm2_fido2(
            &tpm_unsealed,
            &hmac_secret,
            &blob.to_bytes(),
            &cred_id,
            hmac_salt,
        )
        .map_err(estr)?;
    cont.persist_header().map_err(estr)?;
    Ok(idx)
}

#[cfg(not(feature = "hardware"))]
pub fn enroll_tpm2_fido2(_vfs: &mut Vfs, _pin: &str) -> Result<usize, String> {
    Err("TPM 2.0 + FIDO2 fused enroll requires --features hardware".into())
}

/// Enroll a PIN-protected TPM 2.0 keyslot. Same shape as `enroll_tpm2`
/// but seals via `Tpm2Sealer::seal_with_pin` so the chip refuses to
/// unseal without the matching PIN at every future unlock.
#[cfg(feature = "hardware")]
pub fn enroll_tpm2_pin(vfs: &mut Vfs, pin: &str) -> Result<usize, String> {
    use luksbox_tpm::Tpm2Sealer;
    use zeroize::Zeroizing;

    if pin.is_empty() {
        return Err("PIN cannot be empty (use the no-PIN TPM kind instead)".into());
    }
    let mut sealer =
        Tpm2Sealer::new().map_err(|e| format!("could not open local TPM 2.0 device: {e}"))?;
    let mut kek = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(kek.as_mut_slice())
        .map_err(|e| format!("OS RNG failure generating TPM PIN-bound KEK: {e}"))?;
    let blob = sealer
        .seal_with_pin(&kek, Some(pin.as_bytes()))
        .map_err(|e| format!("TPM seal: {e}"))?;
    let cont = vfs.container_mut();
    let idx = cont.enroll_tpm2_pin(&kek, &blob.to_bytes()).map_err(estr)?;
    cont.persist_header().map_err(estr)?;
    Ok(idx)
}

#[cfg(not(feature = "hardware"))]
pub fn enroll_tpm2_pin(_vfs: &mut Vfs, _pin: &str) -> Result<usize, String> {
    Err("TPM 2.0 + PIN enroll requires --features hardware".into())
}

/// Enroll a macOS Secure Enclave keyslot. `biometric` selects between
/// the plain SEP slot (no prompt) and the Touch ID-gated variant.
/// Mirrors the CLI's `cmd_enroll_sep`: open the enclave BEFORE sealing
/// so a missing-SEP error surfaces before we touch the vault, seal the
/// KEK, and install the slot.
#[cfg(feature = "hardware")]
pub fn enroll_sep(vfs: &mut Vfs, biometric: bool) -> Result<usize, String> {
    use luksbox_core::SlotKind;
    use luksbox_sep::SepSealer;

    let mut sealer = SepSealer::new().map_err(|e| format!("{e}"))?;
    let kind = if biometric {
        SlotKind::SepSealedBiometric
    } else {
        SlotKind::SepSealed
    };
    let (sep_shared, blob) = if biometric {
        sealer
            .seal_biometric()
            .map_err(|e| format!("SEP seal (biometric): {e}"))?
    } else {
        sealer.seal().map_err(|e| format!("SEP seal: {e}"))?
    };
    let blob_bytes = blob.to_bytes();

    let cont = vfs.container_mut();
    let idx = cont
        .enroll_sep(
            kind,
            &sep_shared,
            &blob_bytes,
            None,
            None,
            Argon2idParams::INTERACTIVE,
            None,
            &[],
            [0u8; 32],
        )
        .map_err(estr)?;
    cont.persist_header().map_err(estr)?;
    Ok(idx)
}

#[cfg(not(feature = "hardware"))]
pub fn enroll_sep(_vfs: &mut Vfs, _biometric: bool) -> Result<usize, String> {
    Err("Secure Enclave enroll requires --features hardware (macOS Secure Enclave)".into())
}

/// Enroll a hybrid Secure Enclave + ML-KEM keyslot. `kem_size` selects
/// 768 or 1024. Mirrors `enroll_hybrid_pq_tpm2` (atomic-enroll
/// ordering: install slot in memory, write sidecar + .kyber, then
/// persist; roll back on any failure) and the CLI's
/// `cmd_enroll_hybrid_pq_sep`.
#[cfg(feature = "hardware")]
pub fn enroll_hybrid_pq_sep(
    vfs: &mut Vfs,
    vault_path: &Path,
    kyber_path: &Path,
    seed_pw: &str,
    kem_size: u16,
) -> Result<usize, String> {
    use luksbox_core::SlotKind;
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};
    use luksbox_sep::SepSealer;

    if kyber_path.exists() {
        return Err(format!("{} already exists", kyber_path.display()));
    }
    let params = match kem_size {
        768 => PqParams::Ml768,
        1024 => PqParams::Ml1024,
        _ => {
            return Err(format!(
                "unsupported ML-KEM size {kem_size} (use 768 or 1024)"
            ));
        }
    };
    let kind = match params {
        PqParams::Ml768 => SlotKind::HybridPqKemSep,
        PqParams::Ml1024 => SlotKind::HybridPqKem1024Sep,
    };

    let mut sealer = SepSealer::new().map_err(|e| format!("{e}"))?;

    // SEP half: the enclave derives the shared secret + opaque blob.
    let (sep_shared, blob) = sealer.seal().map_err(|e| format!("SEP seal: {e}"))?;
    let blob_bytes = blob.to_bytes();

    // ML-KEM half: keygen + encapsulate against the chosen parameter set.
    let (pk, seed) = keygen_with(params);
    let (ct, pq_shared) =
        encapsulate_with(params, &pk).map_err(|e| format!("ML-KEM encapsulate: {e}"))?;

    let cont = vfs.container_mut();
    let idx = cont
        .enroll_sep(
            kind,
            &sep_shared,
            &blob_bytes,
            None,
            None,
            Argon2idParams::INTERACTIVE,
            Some(&pq_shared),
            &[],
            [0u8; 32],
        )
        .map_err(estr)?;

    let sidecar = hybrid_sidecar::sidecar_path(vault_path);
    let mut entries = if sidecar.exists() {
        match hybrid_sidecar::read(&sidecar) {
            Ok(e) => e,
            Err(e) => {
                let _ = cont.revoke_slot(idx);
                return Err(format!("read existing hybrid sidecar: {e}"));
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
        let _ = cont.revoke_slot(idx);
        return Err(format!("write hybrid sidecar: {e}"));
    }

    if let Err(e) = seed_file::write(
        kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    ) {
        let _ = cont.revoke_slot(idx);
        entries.pop();
        if entries.is_empty() {
            let _ = std::fs::remove_file(&sidecar);
        } else {
            let _ = hybrid_sidecar::write(&sidecar, &entries);
        }
        return Err(format!("write kyber seed: {e}"));
    }

    if let Err(e) = cont.persist_header() {
        let _ = cont.revoke_slot(idx);
        entries.pop();
        if entries.is_empty() {
            let _ = std::fs::remove_file(&sidecar);
        } else {
            let _ = hybrid_sidecar::write(&sidecar, &entries);
        }
        let _ = std::fs::remove_file(kyber_path);
        return Err(estr(e));
    }

    Ok(idx)
}

#[cfg(not(feature = "hardware"))]
pub fn enroll_hybrid_pq_sep(
    _vfs: &mut Vfs,
    _vault_path: &Path,
    _kyber_path: &Path,
    _seed_pw: &str,
    _kem_size: u16,
) -> Result<usize, String> {
    Err("hybrid-pq-sep enroll requires --features hardware (macOS Secure Enclave)".into())
}

/// Enroll a fused Secure Enclave keyslot (SEP + FIDO2 / passphrase,
/// optionally hybrid ML-KEM). Mirrors the CLI's `cmd_enroll_sep_fused`:
/// the SEP always supplies the classical machine-bound half
/// (`sealer.seal()`, NOT the biometric variant), and `factors` +
/// `kem_size` decide which extra secrets are collected and stored. For
/// hybrid kinds a fresh Kyber keypair is generated, the ciphertext +
/// pubkey written to the `.lbx.hybrid` sidecar, and the
/// passphrase-encrypted seed written to `kyber_path` - same on-disk
/// shape as `enroll_hybrid_pq_sep`. All enrolled factors are required
/// at every subsequent unlock.
#[cfg(feature = "hardware")]
#[allow(clippy::too_many_arguments)]
pub fn enroll_sep_fused(
    vfs: &mut Vfs,
    vault_path: &Path,
    factors: SepFactors,
    kem_size: Option<u16>,
    pin: &str,
    passphrase: &str,
    kyber_path: Option<&Path>,
    seed_pw: &str,
) -> Result<usize, String> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};
    use luksbox_sep::SepSealer;

    let kind = factors.slot_kind(kem_size)?;

    // Resolve the ML-KEM parameter set (hybrid kinds only).
    let params = match kem_size {
        None => None,
        Some(768) => Some(PqParams::Ml768),
        Some(1024) => Some(PqParams::Ml1024),
        Some(n) => return Err(format!("unsupported ML-KEM size {n} (use 768 or 1024)")),
    };

    let kyber_path = if params.is_some() {
        let kp = kyber_path
            .ok_or("hybrid SEP enroll requires a path to write the .kyber seed file")?;
        if kp.exists() {
            return Err(format!("{} already exists", kp.display()));
        }
        Some(kp)
    } else {
        None
    };

    // Open the Secure Enclave BEFORE generating any secret material, so
    // a missing-enclave error surfaces before we touch the vault.
    let mut sealer = SepSealer::new().map_err(|e| format!("{e}"))?;

    // FIDO2 half: register a fresh credential + derive an hmac_secret,
    // exactly as enroll_fido2 does.
    let fido2 = if factors.has_fido2() {
        let mut auth = make_fido2_authenticator();
        let user_handle = random_user_handle().map_err(estr)?;
        let er = auth.enroll(RP_ID, &user_handle, Some(pin)).map_err(estr)?;
        let cred_id = er.credential.id;
        let mut hmac_salt = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut hmac_salt)
            .map_err(|e| format!("OS RNG failure generating FIDO2 hmac salt: {e}"))?;
        let hmac_secret: [u8; 32] = *auth
            .hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(pin))
            .map_err(estr)?;
        Some((cred_id, hmac_salt, hmac_secret))
    } else {
        None
    };

    // SEP half: the enclave derives the classical shared secret + blob.
    let (sep_shared, blob) = sealer.seal().map_err(|e| format!("SEP seal: {e}"))?;
    let blob_bytes = blob.to_bytes();

    // ML-KEM half (hybrid kinds only): keygen + encapsulate.
    let pq = match params {
        Some(p) => {
            let (pk, seed) = keygen_with(p);
            let (ct, pq_shared) =
                encapsulate_with(p, &pk).map_err(|e| format!("ML-KEM encapsulate: {e}"))?;
            Some((p, pk, seed, ct, pq_shared))
        }
        None => None,
    };

    // Map the optional factors into the enroll_sep argument shapes.
    let hmac_secret_ref = fido2.as_ref().map(|(_, _, hs)| hs);
    let passphrase_ref = if factors.has_passphrase() {
        Some(passphrase.as_bytes())
    } else {
        None
    };
    let pq_shared_ref = pq.as_ref().map(|(_, _, _, _, s)| &**s);
    let cred_id_ref: &[u8] = fido2.as_ref().map(|(c, _, _)| c.as_slice()).unwrap_or(&[]);
    let hmac_salt = fido2.as_ref().map(|(_, s, _)| *s).unwrap_or([0u8; 32]);

    let cont = vfs.container_mut();
    let idx = cont
        .enroll_sep(
            kind,
            &sep_shared,
            &blob_bytes,
            hmac_secret_ref,
            passphrase_ref,
            Argon2idParams::INTERACTIVE,
            pq_shared_ref,
            cred_id_ref,
            hmac_salt,
        )
        .map_err(estr)?;

    // For plain (non-hybrid) kinds we're done after persisting.
    let (params, pk, seed, ct) = match pq {
        Some((p, pk, seed, ct, _)) => (p, pk, seed, ct),
        None => {
            if let Err(e) = cont.persist_header() {
                let _ = cont.revoke_slot(idx);
                return Err(format!("persist header: {e}"));
            }
            return Ok(idx);
        }
    };

    // Hybrid kinds: atomic-enroll ordering (sidecar -> seed -> header),
    // rolling back on any failure. Mirrors enroll_hybrid_pq_sep.
    let kyber_path = kyber_path.expect("hybrid kind implies a kyber path");
    let sidecar = hybrid_sidecar::sidecar_path(vault_path);
    let mut entries = if sidecar.exists() {
        match hybrid_sidecar::read(&sidecar) {
            Ok(e) => e,
            Err(e) => {
                let _ = cont.revoke_slot(idx);
                return Err(format!("read existing hybrid sidecar: {e}"));
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
        let _ = cont.revoke_slot(idx);
        return Err(format!("write hybrid sidecar: {e}"));
    }
    if let Err(e) = seed_file::write(
        kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    ) {
        let _ = cont.revoke_slot(idx);
        entries.pop();
        if entries.is_empty() {
            let _ = std::fs::remove_file(&sidecar);
        } else {
            let _ = hybrid_sidecar::write(&sidecar, &entries);
        }
        return Err(format!("write kyber seed: {e}"));
    }
    if let Err(e) = cont.persist_header() {
        let _ = cont.revoke_slot(idx);
        entries.pop();
        if entries.is_empty() {
            let _ = std::fs::remove_file(&sidecar);
        } else {
            let _ = hybrid_sidecar::write(&sidecar, &entries);
        }
        let _ = std::fs::remove_file(kyber_path);
        return Err(format!("persist header: {e}"));
    }
    Ok(idx)
}

#[cfg(not(feature = "hardware"))]
#[allow(clippy::too_many_arguments)]
pub fn enroll_sep_fused(
    _vfs: &mut Vfs,
    _vault_path: &Path,
    _factors: SepFactors,
    _kem_size: Option<u16>,
    _pin: &str,
    _passphrase: &str,
    _kyber_path: Option<&Path>,
    _seed_pw: &str,
) -> Result<usize, String> {
    Err(
        "fused Secure Enclave enroll requires --features hardware (macOS Secure Enclave; FIDO2 \
         kinds also need libfido2)"
            .into(),
    )
}

/// Enroll a hybrid TPM 2.0 + ML-KEM keyslot. `kem_size` selects 768
/// or 1024. Generates a fresh Kyber keypair, seals a TPM half,
/// installs the slot, appends a `.lbx.hybrid` sidecar entry, and
/// writes the Kyber seed to `kyber_path` encrypted under `seed_pw`.
#[cfg(feature = "hardware")]
pub fn enroll_hybrid_pq_tpm2(
    vfs: &mut Vfs,
    vault_path: &Path,
    kyber_path: &Path,
    seed_pw: &str,
    kem_size: u16,
) -> Result<usize, String> {
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};
    use luksbox_tpm::Tpm2Sealer;
    use zeroize::Zeroizing;

    if kyber_path.exists() {
        return Err(format!("{} already exists", kyber_path.display()));
    }
    let params = match kem_size {
        768 => PqParams::Ml768,
        1024 => PqParams::Ml1024,
        _ => {
            return Err(format!(
                "unsupported ML-KEM size {kem_size} (use 768 or 1024)"
            ));
        }
    };

    let mut sealer =
        Tpm2Sealer::new().map_err(|e| format!("could not open local TPM 2.0 device: {e}"))?;

    let mut tpm_kek = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(tpm_kek.as_mut_slice())
        .map_err(|e| format!("OS RNG failure generating hybrid TPM KEK: {e}"))?;
    let blob = sealer
        .seal(&tpm_kek)
        .map_err(|e| format!("TPM seal: {e}"))?;

    let (pk, seed) = keygen_with(params);
    let (ct, pq_shared) =
        encapsulate_with(params, &pk).map_err(|e| format!("ML-KEM encapsulate: {e}"))?;

    // Atomic-enroll ordering: install slot in memory FIRST, write
    // sidecar + .kyber, THEN persist the header. On any failure,
    // roll back the in-memory slot + delete the partial files. The
    // on-disk vault is unchanged on Err.
    //
    // Without this ordering, persist_header could succeed before the
    // sidecar write, leaving the vault with a dead slot referencing
    // a non-existent sidecar entry. Vault would still be openable via
    // other slots, but the dead slot would occupy an index until the
    // user manually revoked it.
    let cont = vfs.container_mut();
    let idx = match params {
        PqParams::Ml768 => cont.enroll_hybrid_pq_tpm2(&tpm_kek, &pq_shared, &blob.to_bytes()),
        PqParams::Ml1024 => cont.enroll_hybrid_pq_1024_tpm2(&tpm_kek, &pq_shared, &blob.to_bytes()),
    }
    .map_err(estr)?;

    let sidecar = hybrid_sidecar::sidecar_path(vault_path);
    let mut entries = if sidecar.exists() {
        match hybrid_sidecar::read(&sidecar) {
            Ok(e) => e,
            Err(e) => {
                let _ = cont.revoke_slot(idx);
                return Err(format!("read existing hybrid sidecar: {e}"));
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
        let _ = cont.revoke_slot(idx);
        return Err(format!("write hybrid sidecar: {e}"));
    }

    if let Err(e) = seed_file::write(
        kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    ) {
        // Sidecar already written but .kyber failed: roll back both
        // the in-memory slot AND the sidecar entry we just appended.
        let _ = cont.revoke_slot(idx);
        entries.pop();
        if entries.is_empty() {
            let _ = std::fs::remove_file(&sidecar);
        } else {
            let _ = hybrid_sidecar::write(&sidecar, &entries);
        }
        return Err(format!("write kyber seed: {e}"));
    }

    if let Err(e) = cont.persist_header() {
        // persist_header failed AFTER sidecar + .kyber writes. Roll
        // back everything so the vault state is unchanged.
        let _ = cont.revoke_slot(idx);
        entries.pop();
        if entries.is_empty() {
            let _ = std::fs::remove_file(&sidecar);
        } else {
            let _ = hybrid_sidecar::write(&sidecar, &entries);
        }
        let _ = std::fs::remove_file(kyber_path);
        return Err(estr(e));
    }

    Ok(idx)
}

#[cfg(not(feature = "hardware"))]
pub fn enroll_hybrid_pq_tpm2(
    _vfs: &mut Vfs,
    _vault_path: &Path,
    _kyber_path: &Path,
    _seed_pw: &str,
    _kem_size: u16,
) -> Result<usize, String> {
    Err("hybrid-pq-tpm2 enroll requires --features hardware".into())
}

/// Three-factor enroll: TPM + FIDO2 + ML-KEM. `kem_size` is 768 or
/// 1024. Seals a TPM half, registers a FIDO2 credential, generates a
/// Kyber keypair, installs the slot, writes sidecar + seed file.
#[cfg(feature = "hardware")]
pub fn enroll_hybrid_pq_tpm2_fido2(
    vfs: &mut Vfs,
    vault_path: &Path,
    kyber_path: &Path,
    seed_pw: &str,
    fido2_pin: &str,
    kem_size: u16,
) -> Result<usize, String> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};
    use luksbox_tpm::Tpm2Sealer;
    use zeroize::Zeroizing;

    if kyber_path.exists() {
        return Err(format!("{} already exists", kyber_path.display()));
    }
    let params = match kem_size {
        768 => PqParams::Ml768,
        1024 => PqParams::Ml1024,
        _ => {
            return Err(format!(
                "unsupported ML-KEM size {kem_size} (use 768 or 1024)"
            ));
        }
    };

    let mut sealer =
        Tpm2Sealer::new().map_err(|e| format!("could not open local TPM 2.0 device: {e}"))?;
    let mut auth = make_fido2_authenticator();
    let user_handle = random_user_handle().map_err(estr)?;
    let er = auth
        .enroll(RP_ID, &user_handle, Some(fido2_pin))
        .map_err(estr)?;
    let cred_id = er.credential.id;

    let mut tpm_unsealed = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(tpm_unsealed.as_mut_slice())
        .map_err(|e| format!("OS RNG failure generating 3-factor TPM half: {e}"))?;
    let blob = sealer
        .seal(&tpm_unsealed)
        .map_err(|e| format!("TPM seal: {e}"))?;

    let mut hmac_salt = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut hmac_salt)
        .map_err(|e| format!("OS RNG failure generating FIDO2 hmac salt: {e}"))?;
    let hmac_secret = auth
        .hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(fido2_pin))
        .map_err(estr)?;

    let (pk, seed) = keygen_with(params);
    let (ct, pq_shared) =
        encapsulate_with(params, &pk).map_err(|e| format!("ML-KEM encapsulate: {e}"))?;

    // Same atomic-enroll ordering as enroll_hybrid_pq_tpm2: install
    // slot in memory, write sidecar + .kyber FIRST, then persist
    // the header. On any failure, roll back so the on-disk vault is
    // unchanged. See enroll_hybrid_pq_tpm2 above for the rationale.
    let cont = vfs.container_mut();
    let idx = match params {
        PqParams::Ml768 => cont.enroll_hybrid_pq_tpm2_fido2(
            &tpm_unsealed,
            &hmac_secret,
            &pq_shared,
            &blob.to_bytes(),
            &cred_id,
            hmac_salt,
        ),
        PqParams::Ml1024 => cont.enroll_hybrid_pq_1024_tpm2_fido2(
            &tpm_unsealed,
            &hmac_secret,
            &pq_shared,
            &blob.to_bytes(),
            &cred_id,
            hmac_salt,
        ),
    }
    .map_err(estr)?;

    let sidecar = hybrid_sidecar::sidecar_path(vault_path);
    let mut entries = if sidecar.exists() {
        match hybrid_sidecar::read(&sidecar) {
            Ok(e) => e,
            Err(e) => {
                let _ = cont.revoke_slot(idx);
                return Err(format!("read existing hybrid sidecar: {e}"));
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
        let _ = cont.revoke_slot(idx);
        return Err(format!("write hybrid sidecar: {e}"));
    }

    if let Err(e) = seed_file::write(
        kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    ) {
        let _ = cont.revoke_slot(idx);
        entries.pop();
        if entries.is_empty() {
            let _ = std::fs::remove_file(&sidecar);
        } else {
            let _ = hybrid_sidecar::write(&sidecar, &entries);
        }
        return Err(format!("write kyber seed: {e}"));
    }

    if let Err(e) = cont.persist_header() {
        let _ = cont.revoke_slot(idx);
        entries.pop();
        if entries.is_empty() {
            let _ = std::fs::remove_file(&sidecar);
        } else {
            let _ = hybrid_sidecar::write(&sidecar, &entries);
        }
        let _ = std::fs::remove_file(kyber_path);
        return Err(estr(e));
    }

    Ok(idx)
}

#[cfg(not(feature = "hardware"))]
pub fn enroll_hybrid_pq_tpm2_fido2(
    _vfs: &mut Vfs,
    _vault_path: &Path,
    _kyber_path: &Path,
    _seed_pw: &str,
    _fido2_pin: &str,
    _kem_size: u16,
) -> Result<usize, String> {
    Err("hybrid-pq-tpm2-fido2 enroll requires --features hardware".into())
}

/// Unlock via a PIN-protected TPM 2.0 slot (`Tpm2SealedPin`). PIN is
/// presented to the chip via `userAuth`; wrong PINs count toward the
/// dictionary-attack lockout.
#[cfg(feature = "hardware")]
fn unlock_with_tpm2_pin(
    path: &Path,
    header_path: Option<&Path>,
    pin: &str,
) -> Result<Container, String> {
    use luksbox_tpm::{SealedBlob, Tpm2Sealer};

    let header_src = header_path.unwrap_or(path);
    let mut f =
        luksbox_core::file_util::open_existing_read_no_follow_policy(header_src).map_err(estr)?;
    let mut header_bytes = [0u8; HEADER_SIZE];
    f.read_exact(&mut header_bytes).map_err(estr)?;
    drop(f);
    let header = Header::from_bytes(&header_bytes).map_err(estr)?;
    if !header
        .keyslots
        .iter()
        .any(|s| s.kind == SlotKind::Tpm2SealedPin)
    {
        return Err(
            "this vault has no PIN-protected TPM 2.0 keyslot. Open with another \
             method, then enroll one via Manage Keyslots -> Add TPM 2.0 + PIN."
                .into(),
        );
    }

    let mut sealer =
        Tpm2Sealer::new().map_err(|e| format!("could not open local TPM 2.0 device: {e}"))?;
    let pin_bytes = pin.as_bytes().to_vec();
    let mut unseal = move |blob: &[u8]| -> std::result::Result<[u8; 32], String> {
        let parsed =
            SealedBlob::from_bytes(blob).map_err(|e| format!("malformed TPM SealedBlob: {e}"))?;
        let kek = sealer
            .unseal_with_pin(&parsed, Some(&pin_bytes))
            .map_err(|e| format!("TPM unseal (with PIN): {e}"))?;
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
    .map_err(estr)
}

#[cfg(not(feature = "hardware"))]
fn unlock_with_tpm2_pin(
    _path: &Path,
    _header_path: Option<&Path>,
    _pin: &str,
) -> Result<Container, String> {
    Err("TPM 2.0 + PIN unlock requires --features hardware".into())
}

pub fn revoke_keyslot(vfs: &mut Vfs, slot: usize) -> Result<(), String> {
    let cont = vfs.container_mut();
    cont.revoke_slot(slot).map_err(estr)?;
    cont.persist_header().map_err(estr)?;
    Ok(())
}

/// Crash-safe master-volume-key rotation for vaults whose every
/// populated keyslot is a `Passphrase` slot. Re-encrypts every chunk
/// in the vault under a freshly-generated MVK, then re-wraps each
/// keyslot under a fresh random salt with the same passphrase.
///
/// `creds` is `(slot_idx, passphrase)` for every populated slot,
/// caller must collect them up-front from the user.
///
/// Limitations enforced here (mirroring the wizard, which exposes
/// the full multi-credential-kind interactive flow):
///  - FIDO2-direct slots can't be rotated (the MVK *is* the
///    authenticator output).
///  - Hybrid-PQ slots are not yet supported (would need to
///    re-encapsulate against the existing Kyber keypair).
///  - FIDO2-wrap slots aren't covered by this entry point, they
///    need two authenticator touches per slot, and the GUI doesn't yet
///    offer a multi-touch credential modal. Use the CLI's
///    `luksbox rotate-mvk` (which delegates to the interactive
///    wizard) for vaults with FIDO2 slots.
pub fn rotate_mvk_passphrase_only(
    vfs: &mut Vfs,
    creds: Vec<(usize, zeroize::Zeroizing<String>)>,
    kdf: KdfStrength,
) -> Result<(), String> {
    // Deniable vaults route through the deniable-specific rotation
    // path: their slot envelopes don't live in `header.keyslots`
    // (synthetic header is all Empty), and the full rotation has to
    // pair Container::rotate_mvk_v2_deniable's envelope rewrap with
    // a chunk + chunk-list-block + metadata re-encryption. The
    // standard `Vfs::rotate_mvk` would silently no-op for deniable
    // (empty populated set) and leave the user thinking rotation
    // succeeded when in fact nothing changed.
    if vfs.container().is_deniable() {
        return rotate_mvk_deniable_passphrase_only(vfs, creds, kdf);
    }
    // Pre-flight: refuse the kinds we don't handle here.
    let header = vfs.container().header.clone();
    for (i, slot) in header.keyslots.iter().enumerate() {
        match slot.kind {
            luksbox_core::SlotKind::Empty => {}
            luksbox_core::SlotKind::Passphrase => {}
            luksbox_core::SlotKind::Fido2DerivedMvk => {
                return Err(format!(
                    "slot {i} is fido2-direct: the master key is derived from the \
                     authenticator itself and can't be rotated. Revoke the slot first \
                     or recreate the vault."
                ));
            }
            luksbox_core::SlotKind::Fido2HmacSecret => {
                return Err(format!(
                    "slot {i} is FIDO2 (wrap mode). The GUI rotation flow currently \
                     supports passphrase-only vaults; FIDO2 rotation needs two \
                     authenticator touches per slot, which is wired up in the CLI \
                     wizard (`luksbox rotate-mvk` or `luksbox wizard`). Run the \
                     CLI to rotate this vault."
                ));
            }
            luksbox_core::SlotKind::HybridPqKemPassphrase
            | luksbox_core::SlotKind::HybridPqKemFido2
            | luksbox_core::SlotKind::HybridPqKem1024Passphrase
            | luksbox_core::SlotKind::HybridPqKem1024Fido2 => {
                return Err(format!(
                    "slot {i} is hybrid-PQ. Hybrid-PQ rotation (re-encapsulating \
                     against the existing Kyber keypair) is not yet supported in \
                     either the GUI or the CLI. Recreate the vault to rotate."
                ));
            }
            luksbox_core::SlotKind::Tpm2Sealed
            | luksbox_core::SlotKind::Tpm2Fido2
            | luksbox_core::SlotKind::Tpm2SealedPin
            | luksbox_core::SlotKind::HybridPqKemTpm2
            | luksbox_core::SlotKind::HybridPqKemTpm2Fido2
            | luksbox_core::SlotKind::HybridPqKem1024Tpm2
            | luksbox_core::SlotKind::HybridPqKem1024Tpm2Fido2 => {
                return Err(format!(
                    "slot {i} is TPM-bound. Rotation of TPM-sealed slots isn't \
                     supported by the GUI rotation flow yet. Workaround: revoke \
                     the slot via Manage Keyslots, then re-enroll the matching \
                     TPM kind."
                ));
            }
            luksbox_core::SlotKind::SepSealed
            | luksbox_core::SlotKind::SepSealedBiometric
            | luksbox_core::SlotKind::HybridPqKemSep
            | luksbox_core::SlotKind::HybridPqKem1024Sep
            | luksbox_core::SlotKind::SepFido2
            | luksbox_core::SlotKind::HybridPqKemSepFido2
            | luksbox_core::SlotKind::HybridPqKem1024SepFido2
            | luksbox_core::SlotKind::SepPassphrase
            | luksbox_core::SlotKind::HybridPqKemSepPassphrase
            | luksbox_core::SlotKind::HybridPqKem1024SepPassphrase
            | luksbox_core::SlotKind::SepFido2Passphrase
            | luksbox_core::SlotKind::HybridPqKemSepFido2Passphrase
            | luksbox_core::SlotKind::HybridPqKem1024SepFido2Passphrase => {
                return Err(format!(
                    "slot {i} is Secure Enclave-bound. Rotation of SEP slots isn't \
                     supported by the GUI rotation flow yet. Workaround: revoke \
                     the slot via Manage Keyslots, then re-enroll."
                ));
            }
        }
    }

    // Build the credential vec.
    let credentials: Vec<luksbox_vfs::SlotCredential> = creds
        .into_iter()
        .map(
            |(slot_idx, passphrase)| luksbox_vfs::SlotCredential::Passphrase {
                slot_idx,
                passphrase,
            },
        )
        .collect();
    if credentials.is_empty() {
        return Err("no populated keyslots, nothing to rotate".into());
    }

    vfs.rotate_mvk(credentials, kdf.params()).map_err(estr)?;
    vfs.flush().map_err(estr)?;
    Ok(())
}

/// Deniable counterpart of `rotate_mvk_passphrase_only`. Dispatched
/// from there when the open container is deniable. v1 supports a
/// single passphrase-only deniable slot (the most common deniable
/// setup); FIDO2 / TPM / hybrid deniable slot rotation requires a
/// richer credential modal and is deferred.
///
/// The user must supply the SAME Argon2 params they picked at create
/// time (deniable vaults don't persist the KDF params on disk --
/// that would be a beacon). The GUI's rotate-MVK form passes the
/// currently-selected `KdfStrength` here; if it doesn't match what
/// was used at create, the slot envelope rebuild will succeed but
/// SUBSEQUENT unlocks with the saved KDF preset will fail until the
/// user picks the right one. (Note: this is a latent issue for the
/// envelope-only rewrap too -- adding a real-time verification step
/// during rotation is on the roadmap.)
fn rotate_mvk_deniable_passphrase_only(
    vfs: &mut Vfs,
    creds: Vec<(usize, zeroize::Zeroizing<String>)>,
    kdf: KdfStrength,
) -> Result<(), String> {
    use luksbox_format::deniable_header::DeniableMaterial;

    if creds.len() != 1 {
        return Err(format!(
            "deniable rotation v1 supports exactly one passphrase slot; got {}",
            creds.len()
        ));
    }
    let (supplied_idx, passphrase) = creds.into_iter().next().unwrap();

    // The slot we MUST rotate is the one the open ceremony unlocked
    // -- that's the only envelope whose credentials we have. Refuse
    // a mismatch instead of silently re-wrapping a different slot.
    let unlocked_idx = vfs
        .container()
        .deniable_unlocked_slot()
        .ok_or("deniable container has no unlocked-slot index; reopen the vault")?;
    if supplied_idx != unlocked_idx {
        return Err(format!(
            "deniable rotation must target the unlocked slot ({unlocked_idx}); got slot {supplied_idx}"
        ));
    }

    let argon2 = kdf.params();
    let cred = luksbox_vfs::DeniableRotationCredential {
        slot_idx: unlocked_idx,
        kind: luksbox_core::deniable::DeniableKindTag::Passphrase,
        passphrase: zeroize::Zeroizing::new(passphrase.as_bytes().to_vec()),
        argon2,
        material: DeniableMaterial::passphrase_only(),
        hmac_secret_output: None,
        unsealed: None,
        mlkem_shared: None,
    };
    vfs.rotate_mvk_deniable(vec![cred]).map_err(estr)?;
    Ok(())
}

// ============================================================
// Non-TPM hybrid ML-KEM enroll. Same atomic-enroll dance as the
// TPM-bound variants above: install the slot in memory FIRST,
// then write the .hybrid sidecar entry + the .kyber seed, THEN
// persist the header. On any failure roll back everything so
// the on-disk vault is unchanged.
//
// These cover the "I want post-quantum protection but don't have
// (or don't want to bind to) a TPM" cases. Available on every
// platform with the `hardware` feature off, since the only
// hardware dependency is FIDO2 for the *_fido2 variants.
// ============================================================

/// Enroll a passphrase + ML-KEM hybrid keyslot on a standard
/// (non-deniable) vault. `kem_size` is 768 (FIPS 203 Cat 3) or
/// 1024 (Cat 5).
///
/// Writes one new `.hybrid` sidecar entry referencing the new
/// slot index, and creates a brand-new `.kyber` seed file at
/// `kyber_path` (errors if it already exists - the user must pick
/// a free path). The seed is encrypted with `seed_pw`.
pub fn enroll_hybrid_pq_passphrase(
    vfs: &mut Vfs,
    vault_path: &Path,
    kyber_path: &Path,
    slot_pw: &str,
    seed_pw: &str,
    kem_size: u16,
) -> Result<usize, String> {
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};

    if slot_pw.is_empty() {
        return Err("slot passphrase must not be empty".into());
    }
    if kyber_path.exists() {
        return Err(format!("{} already exists", kyber_path.display()));
    }
    let params = match kem_size {
        768 => PqParams::Ml768,
        1024 => PqParams::Ml1024,
        _ => {
            return Err(format!(
                "unsupported ML-KEM size {kem_size} (use 768 or 1024)"
            ));
        }
    };

    let (pk, seed) = keygen_with(params);
    let (ct, pq_shared) =
        encapsulate_with(params, &pk).map_err(|e| format!("ML-KEM encapsulate: {e}"))?;

    let cont = vfs.container_mut();
    let idx = match params {
        PqParams::Ml768 => cont.enroll_hybrid_pq_passphrase(
            slot_pw.as_bytes(),
            &pq_shared,
            Argon2idParams::INTERACTIVE,
        ),
        PqParams::Ml1024 => cont.enroll_hybrid_pq_1024_passphrase(
            slot_pw.as_bytes(),
            &pq_shared,
            Argon2idParams::INTERACTIVE,
        ),
    }
    .map_err(estr)?;

    let sidecar = hybrid_sidecar::sidecar_path(vault_path);
    let mut entries = if sidecar.exists() {
        match hybrid_sidecar::read(&sidecar) {
            Ok(e) => e,
            Err(e) => {
                let _ = cont.revoke_slot(idx);
                return Err(format!("read existing hybrid sidecar: {e}"));
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
        let _ = cont.revoke_slot(idx);
        return Err(format!("write hybrid sidecar: {e}"));
    }

    if let Err(e) = seed_file::write(
        kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    ) {
        let _ = cont.revoke_slot(idx);
        entries.pop();
        if entries.is_empty() {
            let _ = std::fs::remove_file(&sidecar);
        } else {
            let _ = hybrid_sidecar::write(&sidecar, &entries);
        }
        return Err(format!("write kyber seed: {e}"));
    }

    if let Err(e) = cont.persist_header() {
        let _ = cont.revoke_slot(idx);
        entries.pop();
        if entries.is_empty() {
            let _ = std::fs::remove_file(&sidecar);
        } else {
            let _ = hybrid_sidecar::write(&sidecar, &entries);
        }
        let _ = std::fs::remove_file(kyber_path);
        return Err(estr(e));
    }

    Ok(idx)
}

/// FIDO2 + ML-KEM hybrid enroll on a standard vault. The FIDO2
/// `pin` is used for the CTAP2 enroll + the first hmac-secret
/// derivation; `slot_pw` is an optional second factor folded into
/// the KEK (empty string = no second factor). `kem_size` is 768
/// or 1024.
#[cfg(feature = "hardware")]
pub fn enroll_hybrid_pq_fido2(
    vfs: &mut Vfs,
    vault_path: &Path,
    kyber_path: &Path,
    pin: &str,
    slot_pw: &str,
    seed_pw: &str,
    kem_size: u16,
) -> Result<usize, String> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};

    if kyber_path.exists() {
        return Err(format!("{} already exists", kyber_path.display()));
    }
    let params = match kem_size {
        768 => PqParams::Ml768,
        1024 => PqParams::Ml1024,
        _ => {
            return Err(format!(
                "unsupported ML-KEM size {kem_size} (use 768 or 1024)"
            ));
        }
    };

    let mut auth = make_fido2_authenticator();
    let user_handle = random_user_handle().map_err(estr)?;
    let er = auth.enroll(RP_ID, &user_handle, Some(pin)).map_err(estr)?;
    let cred_id = er.credential.id;
    let mut hmac_salt = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut hmac_salt)
        .map_err(|e| format!("OS RNG failure generating FIDO2 hmac salt: {e}"))?;
    let hmac_secret = auth
        .hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(pin))
        .map_err(estr)?;

    let (pk, seed) = keygen_with(params);
    let (ct, pq_shared) =
        encapsulate_with(params, &pk).map_err(|e| format!("ML-KEM encapsulate: {e}"))?;

    let slot_pw_opt: Option<&[u8]> = if slot_pw.is_empty() {
        None
    } else {
        Some(slot_pw.as_bytes())
    };

    let cont = vfs.container_mut();
    let idx = match params {
        PqParams::Ml768 => cont.enroll_hybrid_pq_fido2(
            slot_pw_opt,
            &hmac_secret,
            &pq_shared,
            &cred_id,
            hmac_salt,
            Argon2idParams::INTERACTIVE,
        ),
        PqParams::Ml1024 => cont.enroll_hybrid_pq_1024_fido2(
            slot_pw_opt,
            &hmac_secret,
            &pq_shared,
            &cred_id,
            hmac_salt,
            Argon2idParams::INTERACTIVE,
        ),
    }
    .map_err(estr)?;

    let sidecar = hybrid_sidecar::sidecar_path(vault_path);
    let mut entries = if sidecar.exists() {
        match hybrid_sidecar::read(&sidecar) {
            Ok(e) => e,
            Err(e) => {
                let _ = cont.revoke_slot(idx);
                return Err(format!("read existing hybrid sidecar: {e}"));
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
        let _ = cont.revoke_slot(idx);
        return Err(format!("write hybrid sidecar: {e}"));
    }

    if let Err(e) = seed_file::write(
        kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    ) {
        let _ = cont.revoke_slot(idx);
        entries.pop();
        if entries.is_empty() {
            let _ = std::fs::remove_file(&sidecar);
        } else {
            let _ = hybrid_sidecar::write(&sidecar, &entries);
        }
        return Err(format!("write kyber seed: {e}"));
    }

    if let Err(e) = cont.persist_header() {
        let _ = cont.revoke_slot(idx);
        entries.pop();
        if entries.is_empty() {
            let _ = std::fs::remove_file(&sidecar);
        } else {
            let _ = hybrid_sidecar::write(&sidecar, &entries);
        }
        let _ = std::fs::remove_file(kyber_path);
        return Err(estr(e));
    }

    Ok(idx)
}

#[cfg(not(feature = "hardware"))]
pub fn enroll_hybrid_pq_fido2(
    _vfs: &mut Vfs,
    _vault_path: &Path,
    _kyber_path: &Path,
    _pin: &str,
    _slot_pw: &str,
    _seed_pw: &str,
    _kem_size: u16,
) -> Result<usize, String> {
    Err("FIDO2 + ML-KEM enroll requires --features hardware".into())
}

/// Deniable-mode passphrase + ML-KEM enroll. The `.hybrid`
/// sidecar + `.kyber` seed file are the same as the non-deniable
/// path; the only difference is the slot install API
/// (`enroll_credential_v2_deniable`) which embeds material in the
/// slot envelope. Caller picks `slot_idx`.
pub fn enroll_hybrid_pq_passphrase_deniable(
    vfs: &mut Vfs,
    vault_path: &Path,
    slot_idx: usize,
    kyber_path: &Path,
    envelope_pw: &str,
    seed_pw: &str,
    kem_size: u16,
) -> Result<usize, String> {
    use luksbox_format::deniable_header::DeniableMaterial;
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};

    if envelope_pw.is_empty() {
        return Err("v2 deniable enroll requires an envelope passphrase".into());
    }
    if kyber_path.exists() {
        return Err(format!("{} already exists", kyber_path.display()));
    }
    let params = match kem_size {
        768 => PqParams::Ml768,
        1024 => PqParams::Ml1024,
        _ => {
            return Err(format!(
                "unsupported ML-KEM size {kem_size} (use 768 or 1024)"
            ));
        }
    };

    let (pk, seed) = keygen_with(params);
    let (ct, pq_shared) =
        encapsulate_with(params, &pk).map_err(|e| format!("ML-KEM encapsulate: {e}"))?;

    let cred = luksbox_core::deniable::DeniableCredential::HybridPqPassphrase {
        passphrase: envelope_pw.as_bytes(),
        argon2: Argon2idParams::INTERACTIVE,
        mlkem_shared: &pq_shared,
    };
    let material = DeniableMaterial::passphrase_only();

    let cont = vfs.container_mut();
    let idx = cont
        .enroll_credential_v2_deniable(slot_idx, &cred, &material)
        .map_err(estr)?;

    let sidecar = hybrid_sidecar::sidecar_path(vault_path);
    let prior_entries: Vec<HybridEntry> = if sidecar.exists() {
        match hybrid_sidecar::read(&sidecar) {
            Ok(e) => e,
            Err(e) => {
                let _ = cont.clear_deniable_slot(slot_idx);
                return Err(format!("read existing hybrid sidecar: {e}"));
            }
        }
    } else {
        Vec::new()
    };
    // Replace any stale entry for the target slot index. In
    // deniable mode the user picks `slot_idx` explicitly and can
    // legitimately overwrite an occupied slot (the deniable header
    // doesn't expose populated/empty state; `install_slot_v2` just
    // overwrites the slot bytes). The sidecar entry that was paired
    // with the old credential is now garbage for the new credential
    // (different ML-KEM keypair -> wrong decap -> wrong shared secret
    // -> AEAD reject). Without filtering, `hybrid_sidecar::write`
    // sees two entries with the same `slot_idx` and refuses with
    // "duplicate entry for slot N (rejected to eliminate
    // find()-returns-first ambiguity; rebuild the sidecar from the
    // wizard)".
    let mut entries: Vec<HybridEntry> = prior_entries
        .iter()
        .filter(|e| usize::from(e.slot_idx) != idx)
        .cloned()
        .collect();
    entries.push(HybridEntry {
        slot_idx: idx as u8,
        level: params,
        pubkey: pk,
        ciphertext: ct,
    });
    if let Err(e) = hybrid_sidecar::write(&sidecar, &entries) {
        let _ = cont.clear_deniable_slot(slot_idx);
        return Err(format!("write hybrid sidecar: {e}"));
    }

    if let Err(e) = seed_file::write(
        kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    ) {
        let _ = cont.clear_deniable_slot(slot_idx);
        rollback_sidecar(&sidecar, &prior_entries);
        return Err(format!("write kyber seed: {e}"));
    }

    if let Err(e) = cont.persist_header() {
        let _ = cont.clear_deniable_slot(slot_idx);
        rollback_sidecar(&sidecar, &prior_entries);
        let _ = std::fs::remove_file(kyber_path);
        return Err(estr(e));
    }

    Ok(idx)
}

/// Restore the .hybrid sidecar to a prior snapshot. Used by the
/// deniable enroll roll-back paths after a partial-success state.
/// If `prior` is empty the sidecar file is unlinked; otherwise it
/// is overwritten with `prior` (which is the byte-for-byte set of
/// entries that lived there before this enroll started).
fn rollback_sidecar(sidecar: &Path, prior: &[luksbox_format::hybrid_sidecar::HybridEntry]) {
    use luksbox_format::hybrid_sidecar;
    if prior.is_empty() {
        let _ = std::fs::remove_file(sidecar);
    } else {
        let _ = hybrid_sidecar::write(sidecar, prior);
    }
}

/// Deniable-mode FIDO2 + ML-KEM enroll. Pairs an envelope
/// passphrase with a FIDO2 PIN + ML-KEM keypair, all bound to a
/// specific deniable slot index.
#[cfg(feature = "hardware")]
#[allow(clippy::too_many_arguments)]
pub fn enroll_hybrid_pq_fido2_deniable(
    vfs: &mut Vfs,
    vault_path: &Path,
    slot_idx: usize,
    kyber_path: &Path,
    pin: &str,
    envelope_pw: &str,
    seed_pw: &str,
    kem_size: u16,
) -> Result<usize, String> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::deniable_header::DeniableMaterial;
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};

    if envelope_pw.is_empty() {
        return Err("v2 deniable enroll requires an envelope passphrase".into());
    }
    if kyber_path.exists() {
        return Err(format!("{} already exists", kyber_path.display()));
    }
    let params = match kem_size {
        768 => PqParams::Ml768,
        1024 => PqParams::Ml1024,
        _ => {
            return Err(format!(
                "unsupported ML-KEM size {kem_size} (use 768 or 1024)"
            ));
        }
    };

    let mut auth = make_fido2_authenticator();
    let user_handle = random_user_handle().map_err(estr)?;
    let er = auth.enroll(RP_ID, &user_handle, Some(pin)).map_err(estr)?;
    let cred_id = er.credential.id;
    let mut hmac_salt = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut hmac_salt)
        .map_err(|e| format!("OS RNG failure generating FIDO2 hmac salt: {e}"))?;
    let hmac_secret = auth
        .hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(pin))
        .map_err(estr)?;

    let (pk, seed) = keygen_with(params);
    let (ct, pq_shared) =
        encapsulate_with(params, &pk).map_err(|e| format!("ML-KEM encapsulate: {e}"))?;

    let cred = luksbox_core::deniable::DeniableCredential::HybridPqFido2Passphrase {
        passphrase: envelope_pw.as_bytes(),
        argon2: Argon2idParams::INTERACTIVE,
        mlkem_shared: &pq_shared,
        hmac_secret_output: &hmac_secret,
    };
    let material = DeniableMaterial {
        cred_id: cred_id.clone(),
        hmac_salt: Some(hmac_salt),
        tpm_blob: Vec::new(),
    };

    let cont = vfs.container_mut();
    let idx = cont
        .enroll_credential_v2_deniable(slot_idx, &cred, &material)
        .map_err(estr)?;

    let sidecar = hybrid_sidecar::sidecar_path(vault_path);
    let prior_entries: Vec<HybridEntry> = if sidecar.exists() {
        match hybrid_sidecar::read(&sidecar) {
            Ok(e) => e,
            Err(e) => {
                let _ = cont.clear_deniable_slot(slot_idx);
                return Err(format!("read existing hybrid sidecar: {e}"));
            }
        }
    } else {
        Vec::new()
    };
    // Drop any stale entry for this slot index before appending the
    // new one. Same rationale as `enroll_hybrid_pq_passphrase_deniable`:
    // deniable mode lets the user pick an occupied slot_idx and
    // `install_slot_v2` silently overwrites; the old sidecar entry
    // becomes useless for the new credential.
    let mut entries: Vec<HybridEntry> = prior_entries
        .iter()
        .filter(|e| usize::from(e.slot_idx) != idx)
        .cloned()
        .collect();
    entries.push(HybridEntry {
        slot_idx: idx as u8,
        level: params,
        pubkey: pk,
        ciphertext: ct,
    });
    if let Err(e) = hybrid_sidecar::write(&sidecar, &entries) {
        let _ = cont.clear_deniable_slot(slot_idx);
        return Err(format!("write hybrid sidecar: {e}"));
    }

    if let Err(e) = seed_file::write(
        kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    ) {
        let _ = cont.clear_deniable_slot(slot_idx);
        rollback_sidecar(&sidecar, &prior_entries);
        return Err(format!("write kyber seed: {e}"));
    }

    if let Err(e) = cont.persist_header() {
        let _ = cont.clear_deniable_slot(slot_idx);
        rollback_sidecar(&sidecar, &prior_entries);
        let _ = std::fs::remove_file(kyber_path);
        return Err(estr(e));
    }

    Ok(idx)
}

#[cfg(not(feature = "hardware"))]
#[allow(clippy::too_many_arguments)]
pub fn enroll_hybrid_pq_fido2_deniable(
    _vfs: &mut Vfs,
    _vault_path: &Path,
    _slot_idx: usize,
    _kyber_path: &Path,
    _pin: &str,
    _envelope_pw: &str,
    _seed_pw: &str,
    _kem_size: u16,
) -> Result<usize, String> {
    Err("deniable FIDO2 + ML-KEM enroll requires --features hardware".into())
}
