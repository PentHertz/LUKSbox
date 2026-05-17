// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Background-thread helpers. The egui app runs on the main thread and
//! must never block (touch prompts, Argon2id, file copies all need to
//! happen elsewhere). Each long op spawns a `std::thread`, returns a
//! `Receiver` the UI polls every frame.

use std::fs::{File, OpenOptions};
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

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
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
}

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

/// Probe the local TPM 2.0 chip without sealing anything. Returns
/// Ok(()) if the chip is reachable, Err with a friendly message if
/// the device is missing, permission-denied (user not in `tss`
/// group), or otherwise unhealthy. Used by the GUI's submit_create
/// + Add-keyslot click handlers to fail fast on a TPM-bound flow
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
    if let Some(ap) = anchor_path.as_ref() {
        if let Err(e) = cont.init_anchor(ap.clone(), 1).map_err(estr) {
            drop(cont);
            let _ = std::fs::remove_file(&vault_path);
            let _ = std::fs::remove_file(ap);
            if let Some(sc) = &deniable_tpm_blob_path {
                let _ = std::fs::remove_file(sc);
            }
            return Err(format!("anchor init failed: {e}"));
        }
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

    let (cont_res, post) = match kind {
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
                .hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(&pin))
                .map_err(estr)?;

            let cred = luksbox_core::deniable::DeniableCredential::TpmFido2Passphrase {
                passphrase: envelope_pw.as_bytes(),
                argon2: kdf_params,
                unsealed: &*tpm_secret,
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
                unsealed: &*tpm_secret,
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
                .hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(&pin))
                .map_err(estr)?;

            let (pk, seed) = keygen_with(params);
            let (ct, shared) = encapsulate_with(params, &pk).map_err(estr)?;
            hybrid_entries = Some((params, pk, ct));
            kyber_to_write = Some((kyber_path, seed, seed_pw));

            let cred = luksbox_core::deniable::DeniableCredential::HybridPqTpmFido2Passphrase {
                passphrase: envelope_pw.as_bytes(),
                argon2: kdf_params,
                mlkem_shared: &shared,
                unsealed: &*tpm_secret,
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
    let _ = post;
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
    if let Some(ap) = anchor_path.as_ref() {
        if let Err(e) = cont.init_anchor(ap.clone(), 1).map_err(estr) {
            drop(cont);
            let _ = std::fs::remove_file(&vault_path);
            for sc in &sidecars_on_disk {
                let _ = std::fs::remove_file(sc);
            }
            let _ = std::fs::remove_file(ap);
            return Err(format!("anchor init failed: {e}"));
        }
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
                .hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(&pin))
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
                .hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(&pin))
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
    if let Some(ap) = anchor_path.as_ref() {
        if let Err(e) = cont.init_anchor(ap.clone(), 1).map_err(estr) {
            drop(cont);
            let _ = std::fs::remove_file(&vault_path);
            for sc in &sidecars_on_disk {
                let _ = std::fs::remove_file(sc);
            }
            let _ = std::fs::remove_file(ap);
            return Err(format!("anchor init failed: {e}"));
        }
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
            enroll_tpm2_deniable(&mut opened.vfs, 1, &bootstrap_pw, bootstrap_argon2)
        }
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        (TpmBootstrapKind::Tpm2Pin { pin: _ }, true) => Err(
            "Tpm2Pin deniable bootstrap is not supported in v2; use Tpm2 \
             (envelope passphrase substitutes for the TPM-side PIN)"
                .into(),
        ),
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        (TpmBootstrapKind::Tpm2Fido2 { pin }, true) => {
            enroll_tpm2_fido2_deniable(&mut opened.vfs, 1, &pin, &bootstrap_pw, bootstrap_argon2)
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
                &bootstrap_pw,
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
                &bootstrap_pw,
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
            if sidecar.exists() {
                if let Ok(mut entries) = luksbox_format::hybrid_sidecar::read(&sidecar) {
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
        //   - FIDO2: cred_id + hmac_salt (surfaced via
        //     OpenedVault.deniable_fido2_recovery; user pastes at
        //     unlock).
        //   - Hybrid-PQ: .kyber seed file (path supplied at unlock
        //     via UnlockOpts.hybrid_kyber_path; the .hybrid
        //     sidecar holds the ciphertext, same as standard PQ).
        //   - TPM: `.tpm-blob` sidecar holding the sealed blob
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
                .hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(pin))
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
            // Empty / unset → falls back to the envelope passphrase
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
        .hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(pin))
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
        .hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(pin))
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
        .hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(pin))
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

        // Phase 1: envelope discovery via passphrase-only credential.
        let env_cred = luksbox_core::deniable::DeniableCredential::Passphrase {
            passphrase: pw.as_bytes(),
            argon2: kdf_params,
        };
        let envelope =
            Container::try_open_envelope_v2_deniable(&opts.path, None, &env_cred, cipher)
                .map_err(estr)?;

        // Variant cross-check. The catch-all below covers
        // platform/feature combos where some `UnlockMethod` variants
        // are unreachable (e.g., TPM on macOS without the Linux
        // hardware build). On Linux+hardware every variant is
        // listed explicitly and the catch-all is structurally
        // unreachable - allow the lint so the match stays portable.
        use luksbox_core::deniable::DeniableKindTag;
        #[allow(unreachable_patterns)]
        let expected = match opts.method {
            UnlockMethod::Passphrase => DeniableKindTag::Passphrase,
            UnlockMethod::Fido2 => DeniableKindTag::Fido2Passphrase,
            UnlockMethod::HybridPq => DeniableKindTag::HybridPqPassphrase,
            UnlockMethod::HybridPqFido2 => DeniableKindTag::HybridPqFido2Passphrase,
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

        // Phase 2: drive secondaries, build full credential, complete
        // open. Same portability note as the variant cross-check
        // above: catch-all is structurally unreachable on
        // Linux+hardware, allow the lint to keep the match portable.
        #[allow(unreachable_patterns)]
        let cont = match opts.method {
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
                let hmac_secret = deniable_fido2_hmac_from_payload(&opts, &payload_cred_id, &salt)?;
                let cred = luksbox_core::deniable::DeniableCredential::Fido2Passphrase {
                    passphrase: pw.as_bytes(),
                    argon2: kdf_params,
                    hmac_secret_output: &hmac_secret,
                };
                Container::complete_open_v2_deniable(envelope, &cred).map_err(estr)?
            }
            UnlockMethod::HybridPq => {
                let shared = deniable_pq_decap(&opts)?;
                let cred = luksbox_core::deniable::DeniableCredential::HybridPqPassphrase {
                    passphrase: pw.as_bytes(),
                    argon2: kdf_params,
                    mlkem_shared: &shared,
                };
                Container::complete_open_v2_deniable(envelope, &cred).map_err(estr)?
            }
            #[cfg(feature = "hardware")]
            UnlockMethod::HybridPqFido2 => {
                let shared = deniable_pq_decap(&opts)?;
                let salt =
                    payload_hmac_salt.ok_or("envelope missing hmac_salt for FIDO2 variant")?;
                let hmac_secret = deniable_fido2_hmac_from_payload(&opts, &payload_cred_id, &salt)?;
                let cred = luksbox_core::deniable::DeniableCredential::HybridPqFido2Passphrase {
                    passphrase: pw.as_bytes(),
                    argon2: kdf_params,
                    mlkem_shared: &shared,
                    hmac_secret_output: &hmac_secret,
                };
                Container::complete_open_v2_deniable(envelope, &cred).map_err(estr)?
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
                let hmac_secret = deniable_fido2_hmac_from_payload(&opts, &payload_cred_id, &salt)?;
                let cred = luksbox_core::deniable::DeniableCredential::TpmFido2Passphrase {
                    passphrase: pw.as_bytes(),
                    argon2: kdf_params,
                    unsealed: &unsealed,
                    hmac_secret_output: &hmac_secret,
                };
                Container::complete_open_v2_deniable(envelope, &cred).map_err(estr)?
            }
            #[cfg(all(feature = "hardware", target_os = "linux"))]
            UnlockMethod::HybridPqTpm2 => {
                let shared = deniable_pq_decap(&opts)?;
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
                let shared = deniable_pq_decap(&opts)?;
                let unsealed = deniable_tpm_unseal_from_bytes(&payload_tpm_blob, None)?;
                let salt =
                    payload_hmac_salt.ok_or("envelope missing hmac_salt for FIDO2 variant")?;
                let hmac_secret = deniable_fido2_hmac_from_payload(&opts, &payload_cred_id, &salt)?;
                let cred = luksbox_core::deniable::DeniableCredential::HybridPqTpmFido2Passphrase {
                    passphrase: pw.as_bytes(),
                    argon2: kdf_params,
                    mlkem_shared: &shared,
                    unsealed: &unsealed,
                    hmac_secret_output: &hmac_secret,
                };
                Container::complete_open_v2_deniable(envelope, &cred).map_err(estr)?
            }
            _ => {
                return Err(format!(
                    "unlock method {:?} not yet supported in deniable mode on this platform",
                    opts.method
                ));
            }
        };
        let cipher_label = format!("{:?} (deniable)", cipher);
        let vfs = luksbox_vfs::Vfs::open(cont).map_err(estr)?;
        return Ok(OpenedVault {
            vfs,
            vault_path: opts.path.clone(),
            header_path: None,
            anchor_path: None,
            cipher_label,
            has_fido2: false,
            has_hybrid_pq: false,
            has_tpm: false,
            deniable_fido2_recovery: None,
            deniable_tpm_blob_path: None,
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
            unlock_with_hybrid_pq(&opts.path, opts.header_path.as_deref(), pw, kp)?
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
    let vfs = Vfs::open(cont).map_err(estr)?;
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
    })
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
        .hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(pin))
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
fn deniable_pq_decap(opts: &UnlockOpts) -> Result<Zeroizing<[u8; 32]>, String> {
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
    let entries = hybrid_sidecar::read(&sidecar).map_err(estr)?;
    let entry = entries
        .first()
        .ok_or_else(|| "hybrid sidecar is empty".to_string())?;
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
) -> Result<luksbox_fido2::HmacSecret, String> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID};
    let pin = opts.pin.as_ref().ok_or("FIDO2 PIN required")?;
    if cred_id.is_empty() {
        return Err("envelope cred_id is empty for FIDO2 variant".into());
    }
    let mut auth = make_fido2_authenticator();
    auth.hmac_secret(RP_ID, cred_id, salt, Some(pin))
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

#[cfg(feature = "hardware")]
fn unlock_with_fido2(
    path: &Path,
    header_path: Option<&Path>,
    pin: &str,
) -> Result<Container, String> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID};
    let header_src = header_path.unwrap_or(path);
    let mut f = File::open(header_src).map_err(estr)?;
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
        let hmac_secret =
            match auth.hmac_secret(RP_ID, &slot.fido2_cred_id, &slot.fido2_hmac_salt, Some(pin)) {
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
    let mut f = File::open(header_src).map_err(estr)?;
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
    let mut f = File::open(header_src).map_err(estr)?;
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
        let hmac_secret =
            match auth.hmac_secret(RP_ID, &stored_cred, &slot.fido2_hmac_salt, Some(pin)) {
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
    let mut f = File::open(header_src).map_err(estr)?;
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
    let entries = hybrid_sidecar::read(&hybrid_sidecar::sidecar_path(path))
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
    let mut f = File::open(header_src).map_err(estr)?;
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
    let entries = hybrid_sidecar::read(&hybrid_sidecar::sidecar_path(path))
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
        let hmac_secret =
            match auth.hmac_secret(RP_ID, &stored_cred, &slot.fido2_hmac_salt, Some(pin)) {
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
    let mut f = std::fs::File::open(header_src).map_err(estr)?;
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
        let hmac_secret =
            match auth.hmac_secret(RP_ID, &slot.fido2_cred_id, &slot.fido2_hmac_salt, Some(pin)) {
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
    passphrase: &str,
    kyber_path: &Path,
) -> Result<Container, String> {
    use luksbox_format::hybrid_sidecar;
    use luksbox_pq::seed_file;

    let seed = seed_file::read(kyber_path, passphrase.as_bytes()).map_err(estr)?;
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
                passphrase: passphrase.as_bytes(),
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
        }
    }
    Ok(total)
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
    if !vault.is_file() {
        return Err(format!("{} is not a file", vault.display()));
    }
    let header_target = header_path.unwrap_or(vault);
    let mut hf = OpenOptions::new()
        .write(true)
        .open(header_target)
        .map_err(estr)?;
    let mut buf = [0u8; HEADER_SIZE];
    OsRng.fill_bytes(&mut buf);
    hf.seek(SeekFrom::Start(0)).map_err(estr)?;
    hf.write_all(&buf).map_err(estr)?;
    hf.flush().map_err(estr)?;
    if wipe_data {
        let mut vf = OpenOptions::new().write(true).open(vault).map_err(estr)?;
        let len = std::fs::metadata(vault).map_err(estr)?.len();
        vf.seek(SeekFrom::Start(0)).map_err(estr)?;
        let mut chunk = vec![0u8; 1 << 20];
        let mut written = 0u64;
        while written < len {
            OsRng.fill_bytes(&mut chunk);
            let to_write = ((len - written) as usize).min(chunk.len());
            vf.write_all(&chunk[..to_write]).map_err(estr)?;
            written += to_write as u64;
        }
        vf.flush().map_err(estr)?;
        let _ = vf.sync_all();
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
        .hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(pin))
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
        .hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(pin))
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
#[cfg(all(feature = "hardware", target_os = "linux"))]
pub fn enroll_tpm2_deniable(
    vfs: &mut Vfs,
    slot_idx: usize,
    passphrase: &str,
    argon2: Argon2idParams,
) -> Result<usize, String> {
    use luksbox_format::deniable_header::DeniableMaterial;
    if passphrase.is_empty() {
        return Err("v2 deniable enroll requires an envelope passphrase for the new slot".into());
    }
    let (secret, blob) = tpm_seal_to_bytes_for_deniable(None)?;
    let cred = luksbox_core::deniable::DeniableCredential::TpmPassphrase {
        passphrase: passphrase.as_bytes(),
        argon2,
        unsealed: &*secret,
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
        .hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(fido2_pin))
        .map_err(estr)?;

    let cred = luksbox_core::deniable::DeniableCredential::TpmFido2Passphrase {
        passphrase: passphrase.as_bytes(),
        argon2,
        unsealed: &*tpm_secret,
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
        unsealed: &*tpm_secret,
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

    let hybrid_sidecar_path = hybrid_sidecar::sidecar_path(vault);
    hybrid_sidecar::write(
        &hybrid_sidecar_path,
        &[HybridEntry {
            slot_idx: idx as u8,
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
    Ok(idx)
}

/// Deniable 4-factor enrollment (v2): hybrid-PQ + TPM + FIDO2 +
/// passphrase. TPM blob and FIDO2 material live in the slot
/// envelope; ML-KEM material stays in the `.kyber` sidecar.
#[cfg(all(feature = "hardware", target_os = "linux"))]
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
        .hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(fido2_pin))
        .map_err(estr)?;

    let (pk, seed) = keygen_with(params);
    let (ct, shared) = encapsulate_with(params, &pk).map_err(estr)?;

    let cred = luksbox_core::deniable::DeniableCredential::HybridPqTpmFido2Passphrase {
        passphrase: passphrase.as_bytes(),
        argon2,
        mlkem_shared: &shared,
        unsealed: &*tpm_secret,
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

    let hybrid_sidecar_path = hybrid_sidecar::sidecar_path(vault);
    hybrid_sidecar::write(
        &hybrid_sidecar_path,
        &[HybridEntry {
            slot_idx: idx as u8,
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
        .hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(pin))
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
        .hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(fido2_pin))
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
    let mut f = File::open(header_src).map_err(estr)?;
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
///   - FIDO2-direct slots can't be rotated (the MVK *is* the
///     authenticator output).
///   - Hybrid-PQ slots are not yet supported (would need to
///     re-encapsulate against the existing Kyber keypair).
///   - FIDO2-wrap slots aren't covered by this entry point, they
///     need two authenticator touches per slot, and the GUI doesn't yet
///     offer a multi-touch credential modal. Use the CLI's
///     `luksbox rotate-mvk` (which delegates to the interactive
///     wizard) for vaults with FIDO2 slots.
pub fn rotate_mvk_passphrase_only(
    vfs: &mut Vfs,
    creds: Vec<(usize, zeroize::Zeroizing<String>)>,
    kdf: KdfStrength,
) -> Result<(), String> {
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
