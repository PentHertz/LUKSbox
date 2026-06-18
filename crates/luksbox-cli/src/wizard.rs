// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Interactive wizard for the luksbox CLI. Driven by `dialoguer` prompts;
//! reuses the same `Container` / `Vfs` plumbing as the regular subcommands,
//! so anything done here is byte-equivalent to running the matching CLI flag.
//!
//! The wizard supports every feature the subcommands do:
//!  - inline and detached-header vaults (`--header` equivalent);
//!  - all three keyslot kinds at create time (passphrase, fido2 wrap, fido2-direct);
//!  - unlocking via passphrase or FIDO2 against either keyslot kind;
//!  - put / get / cat / mkdir / rm / rmdir;
//!  - keyslot enroll / revoke;
//!  - background or foreground mount.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Input, Password, Select};

use luksbox_core::{
    CipherSuite, FLAG_HIDE_SIZE_HEADER, FLAG_PAD_FILES_POW2, HEADER_SIZE, Header, MAX_KEYSLOTS,
    SlotKind,
};
use luksbox_format::{Container, UnlockMaterial, anchor};
use luksbox_vfs::{InodeKind, SlotCredential, Vfs};

use crate::{Result, copy_into, copy_out, kdf_params, split_parent_name};

/// Optional create-time hardening flags + anchor sidecar path. Returned by
/// `ask_create_options` and threaded through every create_* helper.
#[derive(Default, Clone)]
struct CreateOptions {
    flags: u32,
    anchor: Option<PathBuf>,
}

/// Probe libfido2 for connected FIDO2 authenticators (any brand) and,
/// when more than one is plugged in, prompt the user to pick which to
/// use for this run. Returns the selected device's label for status
/// display. `None` means no authenticator is visible right now.
///
/// Side effect: pushes the selected device's libfido2 path into the
/// global `--fido2-device` override (`crate::set_fido2_device_override`)
/// so every subsequent FIDO2 op in this wizard session binds to that
/// authenticator. If the user already supplied `--fido2-device` on
/// the outer command line, that override is left in place and no
/// prompt is shown (CLI flag wins, no surprise prompt).
///
/// Brand-agnostic by design: works for YubiKey, Nitrokey, SoloKey,
/// Token2, OnlyKey, Trezor T, Windows Hello (via libfido2's WinHello
/// bridge on Windows), etc.
#[cfg(feature = "hardware")]
pub(crate) fn select_fido2_device(theme: &ColorfulTheme) -> Option<String> {
    let devices = match luksbox_fido2::HidAuthenticator::detect_all() {
        Ok(d) => d,
        Err(_) => return None,
    };
    if devices.is_empty() {
        return None;
    }
    // Honor an explicit --fido2-device passed on the outer CLI: if the
    // override is already set and matches one of the visible devices,
    // skip the prompt and return that device's label. If it's set but
    // doesn't match anything, surface a warning and fall through to
    // the prompt so the user can recover.
    if let Some(want) = crate::current_fido2_device_override() {
        if let Some(d) = devices.iter().find(|d| d.path == want) {
            return Some(d.label.clone());
        } else {
            eprintln!(
                "warning: --fido2-device {want} not found in the current \
                 enumeration; ignoring and prompting"
            );
        }
    }
    if devices.len() == 1 {
        crate::set_fido2_device_override(Some(devices[0].path.clone()));
        return Some(devices[0].label.clone());
    }
    let labels: Vec<String> = devices.iter().map(|d| d.label.clone()).collect();
    let pick = Select::with_theme(theme)
        .with_prompt("Multiple FIDO2 authenticators detected, pick one for this session")
        .items(&labels)
        .default(0)
        .interact()
        .ok()?;
    crate::set_fido2_device_override(Some(devices[pick].path.clone()));
    Some(devices[pick].label.clone())
}

#[cfg(not(feature = "hardware"))]
pub(crate) fn select_fido2_device(_theme: &ColorfulTheme) -> Option<String> {
    None
}

pub(crate) fn run() -> Result<()> {
    let theme = ColorfulTheme::default();
    println!();
    println!("luksbox, encrypted container tool");
    println!("(Ctrl-C to abort at any prompt)");
    // Multi-device aware: if more than one authenticator is plugged
    // in, prompt the user once at startup so every subsequent
    // FIDO2-touching action in this session uses the same device.
    // No prompt when 0 or 1 are present.
    match select_fido2_device(&theme) {
        Some(label) => println!("FIDO2 authenticator selected: {label}"),
        None => println!(
            "No FIDO2 authenticator detected (plug one in for hardware-backed keyslots; \
             any CTAP2 authenticator works: YubiKey, Nitrokey, SoloKey, Token2, OnlyKey, \
             Windows Hello on Windows, etc.)"
        ),
    }
    println!();

    loop {
        let choice = Select::with_theme(&theme)
            .with_prompt("What would you like to do?")
            .items(&[
                "Create a new vault",
                "Open an existing vault",
                "Show info about a vault (no unlock)",
                "Generate a strong random passphrase",
                "Create a deniable vault (advanced)",
                "Mount a deniable vault (advanced)",
                "Verify a deniable header (advanced)",
                "PANIC: irreversibly destroy a vault by header path",
                "Quit",
            ])
            .default(0)
            .interact()?;
        let r = match choice {
            0 => create_wizard(&theme),
            1 => open_wizard(&theme),
            2 => info_wizard(&theme),
            3 => genpass_action(),
            4 => create_deniable_wizard(&theme),
            5 => mount_deniable_wizard(&theme),
            6 => info_deniable_wizard(&theme),
            7 => panic_by_path(&theme),
            8 => return Ok(()),
            _ => unreachable!(),
        };
        if let Err(e) = r {
            eprintln!("FAIL {e}");
        }
        println!();
    }
}

fn genpass_action() -> Result<()> {
    let pw = crate::passphrase::generate()?;
    println!("{}", &*pw);
    Ok(())
}

// ============================================================
// Deniable-mode wizard shared helpers
// ============================================================

/// Credential combinations the wizard's deniable flows can use.
/// Mirrors `DeniableCredential` from luksbox-core, but bundles
/// "credential type" with "what material does the user supply at
/// create / open time" so the wizard can ask one Select then
/// route to the appropriate flow. Excludes the TPM+Pin variant
/// (the existing TpmBootstrapKind shape doesn't carry a
/// passphrase, tracked as a separate small extension).
#[derive(Clone, Copy, PartialEq, Eq)]
enum DenCredKind {
    Passphrase,
    Fido2,
    HybridPqPassphrase,
    HybridPqFido2,
    #[cfg(all(feature = "hardware", target_os = "linux"))]
    Tpm2,
    #[cfg(all(feature = "hardware", target_os = "linux"))]
    Tpm2Fido2,
    #[cfg(all(feature = "hardware", target_os = "linux"))]
    HybridPqTpm2,
    #[cfg(all(feature = "hardware", target_os = "linux"))]
    HybridPqTpmFido2,
}

impl DenCredKind {
    fn label(self) -> &'static str {
        match self {
            Self::Passphrase => "Passphrase only",
            Self::Fido2 => "FIDO2 authenticator only",
            Self::HybridPqPassphrase => "Hybrid post-quantum (ML-KEM) + passphrase",
            Self::HybridPqFido2 => "Hybrid post-quantum (ML-KEM) + FIDO2",
            #[cfg(all(feature = "hardware", target_os = "linux"))]
            Self::Tpm2 => "TPM 2.0 only (this machine)",
            #[cfg(all(feature = "hardware", target_os = "linux"))]
            Self::Tpm2Fido2 => "TPM 2.0 + FIDO2 (both factors)",
            #[cfg(all(feature = "hardware", target_os = "linux"))]
            Self::HybridPqTpm2 => "Hybrid PQ + TPM 2.0",
            #[cfg(all(feature = "hardware", target_os = "linux"))]
            Self::HybridPqTpmFido2 => "3-factor: PQ + TPM + FIDO2",
        }
    }
}

fn ask_den_cipher(theme: &ColorfulTheme, label: &str) -> Result<luksbox_core::CipherSuite> {
    use luksbox_core::CipherSuite;
    let cipher_idx = Select::with_theme(theme)
        .with_prompt(label)
        .items(&[
            "AES-256-GCM-SIV (recommended; nonce-misuse-resistant)",
            "AES-256-GCM (fastest with hardware AES-NI)",
            "ChaCha20-Poly1305 (software-fast on non-AES hardware)",
        ])
        .default(0)
        .interact()?;
    Ok(match cipher_idx {
        0 => CipherSuite::Aes256GcmSiv,
        1 => CipherSuite::Aes256Gcm,
        _ => CipherSuite::ChaCha20Poly1305,
    })
}

fn ask_den_kdf(theme: &ColorfulTheme, label: &str) -> Result<luksbox_core::Argon2idParams> {
    ask_kdf_strength(theme, label, 1)
}

/// Argon2id strength picker. `default_idx` selects the highlighted preset
/// (0 = Interactive, 1 = Moderate, 2 = Sensitive, 3 = Custom). The "Custom"
/// branch lets the user drop the memory cost well below the 256 MiB
/// Interactive preset, which is what makes enrolment possible on
/// memory-constrained hosts (small VMs, containers with a tight cgroup
/// limit, QubesOS AppVMs) where a 256 MiB Argon2id buffer won't allocate.
fn ask_kdf_strength(
    theme: &ColorfulTheme,
    label: &str,
    default_idx: usize,
) -> Result<luksbox_core::Argon2idParams> {
    use luksbox_core::Argon2idParams;
    let preset_idx = Select::with_theme(theme)
        .with_prompt(label)
        .items(&[
            "Interactive (256 MiB, t=3, p=4)  ~500 ms per attempt",
            "Moderate    (512 MiB, t=4, p=4)  ~1.5 s  per attempt",
            "Sensitive   (1 GiB,   t=5, p=4)  ~3-4 s  per attempt",
            "Custom (advanced - lower memory for constrained VMs / AppVMs)",
        ])
        .default(default_idx)
        .interact()?;
    Ok(match preset_idx {
        0 => Argon2idParams::INTERACTIVE,
        1 => Argon2idParams::MODERATE,
        2 => Argon2idParams::SENSITIVE,
        _ => {
            let m: u32 = Input::with_theme(theme)
                .with_prompt("Argon2id memory cost (KiB)")
                .default(262_144u32)
                .interact()?;
            let t: u32 = Input::with_theme(theme)
                .with_prompt("Argon2id iterations")
                .default(3u32)
                .interact()?;
            let p: u32 = Input::with_theme(theme)
                .with_prompt("Argon2id parallelism")
                .default(4u32)
                .interact()?;
            let custom = Argon2idParams {
                m_cost_kib: m,
                t_cost: t,
                p_cost: p,
            };
            if !custom.is_sane_for_disk() {
                return Err("Argon2id params out of sane envelope".into());
            }
            custom
        }
    })
}

fn ask_den_credential_kind(theme: &ColorfulTheme, label: &str) -> Result<DenCredKind> {
    let kinds = available_den_kinds();
    let items: Vec<&'static str> = kinds.iter().map(|k| k.label()).collect();
    let idx = Select::with_theme(theme)
        .with_prompt(label)
        .items(&items)
        .default(0)
        .interact()?;
    Ok(kinds[idx])
}

fn available_den_kinds() -> Vec<DenCredKind> {
    let mut v = vec![
        DenCredKind::Passphrase,
        DenCredKind::Fido2,
        DenCredKind::HybridPqPassphrase,
        DenCredKind::HybridPqFido2,
    ];
    #[cfg(all(feature = "hardware", target_os = "linux"))]
    {
        v.push(DenCredKind::Tpm2);
        v.push(DenCredKind::Tpm2Fido2);
        v.push(DenCredKind::HybridPqTpm2);
        v.push(DenCredKind::HybridPqTpmFido2);
    }
    v
}

/// Recovery info surfaced to the user after a deniable create /
/// enroll that produced material the deniable header doesn't store
/// v2 deniable mode embeds FIDO2 cred_id / hmac_salt / TPM sealed
/// blobs inside the slot envelope, so there is no longer any
/// "recovery info" the user must copy out at create time. The
/// passphrase + Argon2id params they entered + presence of the
/// FIDO2 device / TPM chip is everything they need to remember.
/// `DeniableRecoveryInfo` is retained as an empty marker so the
/// wizard's surrounding flow stays unchanged; `print_deniable_recovery`
/// is a no-op.
#[derive(Default)]
struct DeniableRecoveryInfo;

fn print_deniable_recovery(_info: &DeniableRecoveryInfo) {
    // No external material to print in v2; the slot envelope carries
    // it. The cipher / Argon2id summary is printed by the caller.
}

/// Wizard flow for creating a deniable-header file (8 KiB where every
/// byte is indistinguishable from uniform random). Walks the user
/// through cipher choice + Argon2 params, prompts for a passphrase
/// twice, and writes a fresh deniable header to disk.
///
/// WARNING surfaced loudly at the start: forgetting any of (cipher,
/// argon2 params, passphrase) is permanent lockout - by design, those
/// values are part of the secret in deniable mode. There is no
/// fail-fast magic check, so wrong inputs run a full Argon2 round
/// before failing with the same opaque error as a real wrong
/// passphrase.
fn create_deniable_wizard(theme: &ColorfulTheme) -> Result<()> {
    println!();
    println!("DENIABLE VAULT - ADVANCED MODE");
    println!();
    println!("This creates a vault where every on-disk byte is");
    println!("indistinguishable from random output. There is no");
    println!("LUKSbox magic, no version field, no cipher ID on disk.");
    println!();
    println!("Trade-off: you MUST remember the cipher choice + Argon2");
    println!("params + credential type + any per-credential material");
    println!("(FIDO2 cred_id, TPM blob path, .kyber path). Forgetting");
    println!("any one means PERMANENT lockout. There is no recovery.");
    println!();
    println!("Recommended only if you have read docs/DENIABLE_HEADER.md");
    println!();

    let proceed = Confirm::with_theme(theme)
        .with_prompt("Continue with deniable vault creation?")
        .default(false)
        .interact()?;
    if !proceed {
        return Ok(());
    }

    let path = ask_path(theme, "Path for the new vault file (e.g. ~/notes.dat)")?;
    if path.exists() {
        return Err(format!("refusing to overwrite existing file: {}", path.display()).into());
    }

    let cipher_suite = ask_den_cipher(theme, "Cipher suite (you must remember this choice)")?;
    let argon2_params = ask_den_kdf(theme, "Argon2id strength (you must remember this choice)")?;
    let kind = ask_den_credential_kind(theme, "Credential type for the initial slot")?;

    // Metadata format for the DENIABLE vault. Deniable vaults
    // explicitly opt out of the v0.2.1 sidecar-mirror protocol
    // (mirrors at predictable names + lengths would defeat the
    // deniability property), so "v3" here means LBM4 (out-of-line
    // chunk lists, no per-vault ceiling, no mirrors) and "v2" means
    // LBM2 (inline chunk lists, ~10 GiB ceiling, no mirrors). The
    // LUKSBOX2 header magic is also not used in deniable mode; the
    // deniable header has its own 36 KiB layout. Choice is permanent
    // -- you must remember it alongside the cipher + KDF params.
    let format_choice = Select::with_theme(theme)
        .with_prompt("On-disk metadata format (you must remember this choice)")
        .items(&[
            "v3 (default; LBM4, out-of-line chunk lists, no per-vault ceiling; requires LUKSbox v0.2.0+ to open)",
            "v2 (compat; LBM2, inline chunk lists, ~10 GiB practical per-vault ceiling; readable by pre-v0.2.0 LUKSbox)",
        ])
        .default(0)
        .interact()?;
    let _format_guard = luksbox_vfs::set_format_v3_override(Some(format_choice == 0));

    // Anchor prompt before any device touches so the user isn't asked
    // mid-Argon2 / mid-FIDO2-touch. Matches the GUI's create form
    // where "Anchor" is a checkbox next to "Detached header" and is
    // resolved BEFORE the heavy work starts.
    let anchor_path = if Confirm::with_theme(theme)
        .with_prompt(
            "Initialize a rollback-detection anchor sidecar? (256 B AEAD-encrypted file \
             that's indistinguishable from random; keep on separate trusted storage)",
        )
        .default(false)
        .interact()?
    {
        let p = ask_path(
            theme,
            "Path for the deniable anchor sidecar (e.g. on a USB stick)",
        )?;
        if p.exists() {
            return Err(format!("anchor file {} already exists", p.display()).into());
        }
        Some(p)
    } else {
        None
    };

    let mut recovery = DeniableRecoveryInfo;
    println!();
    println!("Running operations (Argon2 / device touch may take a few seconds)...");

    let mut cont: luksbox_format::Container = match kind {
        DenCredKind::Passphrase => {
            create_den_passphrase_v2(theme, &path, cipher_suite, argon2_params)?
        }
        DenCredKind::Fido2 => {
            create_den_fido2(theme, &path, cipher_suite, argon2_params, &mut recovery)?
        }
        DenCredKind::HybridPqPassphrase => {
            create_den_pq_passphrase(theme, &path, cipher_suite, argon2_params, false)?
        }
        DenCredKind::HybridPqFido2 => create_den_pq_fido2(
            theme,
            &path,
            cipher_suite,
            argon2_params,
            false,
            &mut recovery,
        )?,
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        DenCredKind::Tpm2 => {
            create_den_tpm(theme, &path, cipher_suite, argon2_params, &mut recovery)?
        }
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        DenCredKind::Tpm2Fido2 => {
            create_den_tpm_fido2(theme, &path, cipher_suite, argon2_params, &mut recovery)?
        }
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        DenCredKind::HybridPqTpm2 => create_den_pq_tpm(
            theme,
            &path,
            cipher_suite,
            argon2_params,
            false,
            &mut recovery,
        )?,
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        DenCredKind::HybridPqTpmFido2 => create_den_pq_tpm_fido2(
            theme,
            &path,
            cipher_suite,
            argon2_params,
            false,
            &mut recovery,
        )?,
    };

    if let Some(ap) = &anchor_path {
        cont.init_anchor(ap.clone(), 1)?;
        println!("  anchor file initialized at {}", ap.display());
    }
    drop(cont);

    println!();
    println!("OK deniable vault written to {}", path.display());
    println!();
    println!("SAVE THESE PARAMETERS NOW. Without them the vault cannot be reopened:");
    println!();
    println!("  cipher:         {:?}", cipher_suite);
    println!("  argon2-m (KiB): {}", argon2_params.m_cost_kib);
    println!("  argon2-t:       {}", argon2_params.t_cost);
    println!("  argon2-p:       {}", argon2_params.p_cost);
    println!("  credential:     {}", kind.label());
    print_deniable_recovery(&recovery);
    println!("To reopen later, use the wizard's 'Mount a deniable vault'");
    println!("option or `luksbox deniable-mount`.");
    Ok(())
}

// ============================================================
// Per-credential deniable-create helpers (wizard only)
//
// Each one does: ask for the type-specific material -> run any
// device operations -> call Container::create_with_credential_deniable
// -> populate the recovery info struct so print_deniable_recovery
// can show what the user needs to save.
// ============================================================

fn create_den_passphrase_v2(
    theme: &ColorfulTheme,
    path: &Path,
    cipher: luksbox_core::CipherSuite,
    argon2: luksbox_core::Argon2idParams,
) -> Result<luksbox_format::Container> {
    use luksbox_format::deniable_header::DeniableMaterial;
    let pass = ask_new_passphrase(theme, "Passphrase for the deniable vault")?;
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
fn create_den_fido2(
    theme: &ColorfulTheme,
    path: &Path,
    cipher: luksbox_core::CipherSuite,
    argon2: luksbox_core::Argon2idParams,
    _recovery: &mut DeniableRecoveryInfo,
) -> Result<luksbox_format::Container> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::deniable_header::DeniableMaterial;
    let pass = ask_new_passphrase(theme, "Passphrase (outer envelope of the FIDO2 slot)")?;
    let pin = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt("FIDO2 PIN")
            .interact()?,
    );
    let mut auth = crate::make_fido2_authenticator();
    let user_handle = random_user_handle()?;
    println!("{}", crate::auth_prompt("register a new credential"));
    let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
    let cred_id = er.credential.id;
    let mut hmac_salt = [0u8; 32];
    {
        use rand_core::RngCore;
        rand_core::OsRng
            .try_fill_bytes(&mut hmac_salt)
            .map_err(|e| format!("OS RNG failure: {e}"))?;
    }
    println!("{}", crate::auth_prompt("derive the unlock key"));
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(&pin))?;
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
#[cfg(not(feature = "hardware"))]
fn create_den_fido2(
    _theme: &ColorfulTheme,
    _path: &Path,
    _cipher: luksbox_core::CipherSuite,
    _argon2: luksbox_core::Argon2idParams,
    _recovery: &mut DeniableRecoveryInfo,
) -> Result<luksbox_format::Container> {
    Err("FIDO2 hardware support not compiled in".into())
}

fn create_den_pq_passphrase(
    theme: &ColorfulTheme,
    path: &Path,
    cipher: luksbox_core::CipherSuite,
    argon2: luksbox_core::Argon2idParams,
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
    let envelope_pw = ask_new_passphrase(theme, "Envelope passphrase (deniable - required)")?;
    let seed_pw = ask_optional_seed_pw(theme, &envelope_pw)?;
    let kyber_path = ask_path(
        theme,
        "Path for the .kyber seed file (keep on separate storage)",
    )?;
    let (pk, seed) = keygen_with(params);
    let (ct, shared) = encapsulate_with(params, &pk)?;
    let cred = luksbox_core::deniable::DeniableCredential::HybridPqPassphrase {
        passphrase: envelope_pw.as_bytes(),
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
        &kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    )?;
    Ok(cont)
}

#[cfg(feature = "hardware")]
fn create_den_pq_fido2(
    theme: &ColorfulTheme,
    path: &Path,
    cipher: luksbox_core::CipherSuite,
    argon2: luksbox_core::Argon2idParams,
    use_1024: bool,
    _recovery: &mut DeniableRecoveryInfo,
) -> Result<luksbox_format::Container> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::deniable_header::DeniableMaterial;
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};
    let params = if use_1024 {
        PqParams::Ml1024
    } else {
        PqParams::Ml768
    };
    let envelope_pw = ask_new_passphrase(theme, "Envelope passphrase (deniable - required)")?;
    let pin = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt("FIDO2 PIN")
            .interact()?,
    );
    let seed_pw = ask_optional_seed_pw(theme, &envelope_pw)?;
    let kyber_path = ask_path(theme, "Path for the .kyber seed file")?;

    let mut auth = crate::make_fido2_authenticator();
    let user_handle = random_user_handle()?;
    let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
    let cred_id = er.credential.id;
    let mut hmac_salt = [0u8; 32];
    {
        use rand_core::RngCore;
        rand_core::OsRng
            .try_fill_bytes(&mut hmac_salt)
            .map_err(|e| format!("OS RNG failure: {e}"))?;
    }
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(&pin))?;

    let (pk, seed) = keygen_with(params);
    let (ct, shared) = encapsulate_with(params, &pk)?;
    let cred = luksbox_core::deniable::DeniableCredential::HybridPqFido2Passphrase {
        passphrase: envelope_pw.as_bytes(),
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
        &kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    )?;
    Ok(cont)
}
#[cfg(not(feature = "hardware"))]
fn create_den_pq_fido2(
    _theme: &ColorfulTheme,
    _path: &Path,
    _cipher: luksbox_core::CipherSuite,
    _argon2: luksbox_core::Argon2idParams,
    _use_1024: bool,
    _recovery: &mut DeniableRecoveryInfo,
) -> Result<luksbox_format::Container> {
    Err("FIDO2 hardware support not compiled in".into())
}

#[cfg(all(feature = "hardware", target_os = "linux"))]
fn create_den_tpm(
    theme: &ColorfulTheme,
    path: &Path,
    cipher: luksbox_core::CipherSuite,
    argon2: luksbox_core::Argon2idParams,
    _recovery: &mut DeniableRecoveryInfo,
) -> Result<luksbox_format::Container> {
    use luksbox_format::deniable_header::DeniableMaterial;
    let pass = ask_new_passphrase(theme, "Passphrase (outer envelope of the TPM slot)")?;
    // Optional TPM userAuth. Must match the unlock-side choice
    // exactly: an empty PIN here means the unseal call must use
    // `unseal` (no PIN), otherwise the TPM rejects with
    // TPM_RC_AUTH_FAIL (0x098e) and bumps the dictionary-attack
    // counter. The CLI's `mount-deniable` subcommand selects the
    // unseal variant from `--tpm-pin`; we surface the same toggle
    // here so the seal/unseal sides stay symmetric.
    let pin_input = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt("TPM PIN (leave blank for no PIN)")
            .allow_empty_password(true)
            .interact()?,
    );
    let pin_bytes: Option<&[u8]> = if pin_input.is_empty() {
        None
    } else {
        Some(pin_input.as_bytes())
    };
    let (secret, blob) = tpm_seal_blob_to_bytes(pin_bytes)?;
    let cred = luksbox_core::deniable::DeniableCredential::TpmPassphrase {
        passphrase: pass.as_bytes(),
        argon2,
        unsealed: &secret,
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
fn create_den_tpm_fido2(
    theme: &ColorfulTheme,
    path: &Path,
    cipher: luksbox_core::CipherSuite,
    argon2: luksbox_core::Argon2idParams,
    _recovery: &mut DeniableRecoveryInfo,
) -> Result<luksbox_format::Container> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::deniable_header::DeniableMaterial;
    let pass = ask_new_passphrase(theme, "Passphrase (outer envelope)")?;
    let (secret, blob) = tpm_seal_blob_to_bytes(None)?;
    let pin = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt("FIDO2 PIN")
            .interact()?,
    );
    let mut auth = crate::make_fido2_authenticator();
    let user_handle = random_user_handle()?;
    let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
    let cred_id = er.credential.id;
    let mut hmac_salt = [0u8; 32];
    {
        use rand_core::RngCore;
        rand_core::OsRng
            .try_fill_bytes(&mut hmac_salt)
            .map_err(|e| format!("OS RNG failure: {e}"))?;
    }
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(&pin))?;
    let cred = luksbox_core::deniable::DeniableCredential::TpmFido2Passphrase {
        passphrase: pass.as_bytes(),
        argon2,
        unsealed: &secret,
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
fn create_den_pq_tpm(
    theme: &ColorfulTheme,
    path: &Path,
    cipher: luksbox_core::CipherSuite,
    argon2: luksbox_core::Argon2idParams,
    use_1024: bool,
    _recovery: &mut DeniableRecoveryInfo,
) -> Result<luksbox_format::Container> {
    use luksbox_format::deniable_header::DeniableMaterial;
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};
    let params = if use_1024 {
        PqParams::Ml1024
    } else {
        PqParams::Ml768
    };
    let envelope_pw = ask_new_passphrase(theme, "Envelope passphrase (deniable - required)")?;
    let (tpm_secret, blob) = tpm_seal_blob_to_bytes(None)?;
    let seed_pw = ask_optional_seed_pw(theme, &envelope_pw)?;
    let kyber_path = ask_path(theme, "Path for the .kyber seed file")?;
    let (pk, seed) = keygen_with(params);
    let (ct, shared) = encapsulate_with(params, &pk)?;
    let cred = luksbox_core::deniable::DeniableCredential::HybridPqTpmPassphrase {
        passphrase: envelope_pw.as_bytes(),
        argon2,
        mlkem_shared: &shared,
        unsealed: &tpm_secret,
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
        &kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    )?;
    Ok(cont)
}

#[cfg(all(feature = "hardware", target_os = "linux"))]
fn create_den_pq_tpm_fido2(
    theme: &ColorfulTheme,
    path: &Path,
    cipher: luksbox_core::CipherSuite,
    argon2: luksbox_core::Argon2idParams,
    use_1024: bool,
    _recovery: &mut DeniableRecoveryInfo,
) -> Result<luksbox_format::Container> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::deniable_header::DeniableMaterial;
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};
    let params = if use_1024 {
        PqParams::Ml1024
    } else {
        PqParams::Ml768
    };
    let envelope_pw = ask_new_passphrase(theme, "Envelope passphrase (deniable - required)")?;
    let (tpm_secret, blob) = tpm_seal_blob_to_bytes(None)?;
    let pin = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt("FIDO2 PIN")
            .interact()?,
    );
    let seed_pw = ask_optional_seed_pw(theme, &envelope_pw)?;
    let kyber_path = ask_path(theme, "Path for the .kyber seed file")?;

    let mut auth = crate::make_fido2_authenticator();
    let user_handle = random_user_handle()?;
    let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
    let cred_id = er.credential.id;
    let mut hmac_salt = [0u8; 32];
    {
        use rand_core::RngCore;
        rand_core::OsRng
            .try_fill_bytes(&mut hmac_salt)
            .map_err(|e| format!("OS RNG failure: {e}"))?;
    }
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(&pin))?;

    let (pk, seed) = keygen_with(params);
    let (ct, shared) = encapsulate_with(params, &pk)?;
    let cred = luksbox_core::deniable::DeniableCredential::HybridPqTpmFido2Passphrase {
        passphrase: envelope_pw.as_bytes(),
        argon2,
        mlkem_shared: &shared,
        unsealed: &tpm_secret,
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
        &kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    )?;
    Ok(cont)
}

/// TPM-seal a random 32-byte secret and return the blob bytes for
/// embedding inside the v2 slot envelope. v2 replacement for the
/// v1 `tpm_seal_blob_sidecar` (which wrote a `.tpm-blob` file).
#[cfg(all(feature = "hardware", target_os = "linux"))]
fn tpm_seal_blob_to_bytes(pin: Option<&[u8]>) -> Result<(zeroize::Zeroizing<[u8; 32]>, Vec<u8>)> {
    use luksbox_tpm::Tpm2Sealer;
    let mut sealer = Tpm2Sealer::new()?;
    let mut secret = zeroize::Zeroizing::new([0u8; 32]);
    {
        use rand_core::RngCore;
        rand_core::OsRng
            .try_fill_bytes(secret.as_mut_slice())
            .map_err(|e| format!("OS RNG failure: {e}"))?;
    }
    let blob = match pin {
        Some(p) => sealer.seal_with_pin(&secret, Some(p))?,
        None => sealer.seal(&secret)?,
    };
    Ok((secret, blob.to_bytes()))
}

/// Wizard flow for opening (and printing the inner-header fields of) a
/// deniable-header file. Prompts for the cipher + Argon2 params +
/// passphrase the user recorded at create time. All failure modes
/// (wrong passphrase / wrong cipher / wrong params / corrupt file)
/// collapse to the same opaque error message.
fn info_deniable_wizard(theme: &ColorfulTheme) -> Result<()> {
    let path = ask_path(theme, "Path to the deniable vault file")?;
    let cipher = ask_den_cipher(theme, "Cipher suite used at create time")?;
    let argon2 = ask_den_kdf(theme, "Argon2id params used at create time")?;
    let kind = ask_den_credential_kind(theme, "Credential type used at create time")?;

    let container = open_deniable_by_kind(theme, &path, cipher, argon2, kind)?;
    println!();
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

/// Wizard flow for mounting a deniable-mode vault. Prompts for the
/// same cipher + Argon2 params + passphrase that were used at create
/// time, opens the Container via `Container::open_with_passphrase_deniable`,
/// builds a Vfs over it, and hands off to `luksbox_mount::mount`
/// (foreground). Unmount via Ctrl-C or the standard wizard / CLI
/// umount flow.
fn mount_deniable_wizard(theme: &ColorfulTheme) -> Result<()> {
    use luksbox_vfs::Vfs;

    let path = ask_path(theme, "Path to the deniable vault")?;
    let mountpoint = ask_mountpoint(theme, &path)?;

    #[cfg(not(target_os = "windows"))]
    let mp_abs = {
        if !mountpoint.is_dir() {
            return Err(format!("mountpoint {} is not a directory", mountpoint.display()).into());
        }
        mountpoint
            .canonicalize()
            .map_err(|e| format!("cannot resolve {}: {e}", mountpoint.display()))?
    };
    #[cfg(target_os = "windows")]
    let mp_abs = mountpoint.clone();

    let cipher_suite = ask_den_cipher(theme, "Cipher suite used at create time")?;
    let argon2_params = ask_den_kdf(theme, "Argon2id params used at create time")?;
    let kind = ask_den_credential_kind(theme, "Credential type used at create time")?;

    // Optional anchor sidecar for rollback detection. Asked BEFORE the
    // open so a wrong anchor short-circuits before we burn Argon2 /
    // FIDO2-touch time on the open itself. The deniable anchor format
    // is AEAD-encrypted with the vault's per_vault_salt as AAD; a
    // wrong vault / wrong MVK / random file all collapse to the same
    // OpaqueUnlockFailed error.
    let anchor_path = if Confirm::with_theme(theme)
        .with_prompt(
            "Verify a rollback-detection anchor sidecar before mount? \
             (must be the same anchor the vault was last written against)",
        )
        .default(false)
        .interact()?
    {
        Some(ask_path(theme, "Path to the deniable anchor sidecar")?)
    } else {
        None
    };

    let mut container = open_deniable_by_kind(theme, &path, cipher_suite, argon2_params, kind)?;

    let trusted_gen = if let Some(ap) = &anchor_path {
        container.set_anchor(Some(ap.clone()))?
    } else {
        None
    };
    let vfs = Vfs::open(container)?;
    if let Some(anchor_gen) = trusted_gen {
        match anchor::compare(anchor_gen, vfs.vault_generation()) {
            anchor::VerificationOutcome::Ok | anchor::VerificationOutcome::AnchorStale { .. } => {}
            anchor::VerificationOutcome::RollbackDetected {
                anchor_gen,
                metadata_gen,
            } => {
                return Err(format!(
                    "Rollback detected: anchor at gen {anchor_gen} > vault at \
                     gen {metadata_gen}. Mount refused (someone may have \
                     substituted an old copy of the vault)."
                )
                .into());
            }
        }
    }
    // Eager-flush opt-in. Default OFF (v0.2.2 fast deferred-flush).
    // The default makes vaults with thousands of files usable; ticking
    // this restores the per-op crash-durable semantics of pre-v0.2.2
    // (slow on big vaults, every metadata op fsync's). Matches the
    // `--sync` CLI flag and the GUI's "Eager flush (--sync)" checkbox.
    let sync_mode = Confirm::with_theme(theme)
        .with_prompt(
            "Eager flush? (every metadata op crash-durable on return; SLOW on \
             vaults with thousands of files -- default is no)",
        )
        .default(false)
        .interact()?;
    println!("OK mounting at {}", mp_abs.display());
    luksbox_mount::mount(vfs, &mp_abs, false, sync_mode)?;
    Ok(())
}

/// Shared deniable-open driver (v2): two-phase open. Phase 1
/// derives the envelope KEK from passphrase + Argon2id params and
/// trial-decrypts the 8 slot envelopes; phase 2 reads the
/// recovered (cred_id, hmac_salt, tpm_blob) out of the envelope
/// payload and drives the secondary factors (FIDO2 assertion, TPM
/// unseal, ML-KEM decap) before completing the open.
fn open_deniable_by_kind(
    theme: &ColorfulTheme,
    vault: &Path,
    cipher: luksbox_core::CipherSuite,
    argon2: luksbox_core::Argon2idParams,
    kind: DenCredKind,
) -> Result<luksbox_format::Container> {
    use luksbox_core::deniable::{DeniableCredential, DeniableKindTag};
    println!("Running operations (Argon2 / device touch may take a few seconds)...");

    let pass = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt("Passphrase")
            .interact()?,
    );

    // Resolve the user's intended unlock kind FIRST so we can pass
    // it into phase 1 as the discovery hint. Without this hint
    // (phase 1 used to hardcode Passphrase as want_kind) the
    // envelope discovery preferred any Passphrase slot it found
    // under the same envelope passphrase, returning e.g. the admin
    // slot 0 instead of the freshly-enrolled FIDO2 / TPM / hybrid
    // slot the user is actually trying to open. The post-discovery
    // kind-validation then fired with "credential kind mismatch"
    // even though the user typed the correct unlock kind.
    let expected = match kind {
        DenCredKind::Passphrase => DeniableKindTag::Passphrase,
        DenCredKind::Fido2 => DeniableKindTag::Fido2Passphrase,
        DenCredKind::HybridPqPassphrase => DeniableKindTag::HybridPqPassphrase,
        DenCredKind::HybridPqFido2 => DeniableKindTag::HybridPqFido2Passphrase,
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        DenCredKind::Tpm2 => DeniableKindTag::TpmPassphrase,
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        DenCredKind::Tpm2Fido2 => DeniableKindTag::TpmFido2Passphrase,
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        DenCredKind::HybridPqTpm2 => DeniableKindTag::HybridPqTpmPassphrase,
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        DenCredKind::HybridPqTpmFido2 => DeniableKindTag::HybridPqTpmFido2Passphrase,
    };

    // Phase 1.
    let env_cred = DeniableCredential::Passphrase {
        passphrase: pass.as_bytes(),
        argon2,
    };
    let envelope = luksbox_format::Container::try_open_envelope_v2_deniable(
        vault,
        None,
        &env_cred,
        cipher,
        Some(expected),
    )?;

    // Defense-in-depth: the discovery above prefers slots whose
    // stored kind byte matches `expected`, so this validation
    // should never fire under non-adversarial inputs. Keep it as a
    // belt-and-suspenders check for the case where a vault was
    // forged with a slot whose AEAD opens under the user's
    // envelope passphrase but whose kind byte differs (only
    // possible with MVK-level access; preserves the legacy
    // semantic of refusing to drive secondary factors against
    // a slot of the wrong variant).
    if envelope.payload().kind != expected {
        return Err("credential kind mismatch (vault expects a different variant)".into());
    }

    let cred_id = envelope.payload().cred_id.clone();
    let salt_opt = envelope.payload().hmac_salt;
    let tpm_blob = envelope.payload().tpm_blob.clone();
    // Captured before `complete_open_v2_deniable` consumes the
    // envelope. Threaded into `ask_pq_decap_for_deniable` so the
    // sidecar lookup picks the entry matching THIS slot rather
    // than `entries.first()`, which used to break unlock on any
    // deniable vault with two PQC-bearing slots whose user seed
    // belonged to the non-first one.
    let matched_slot_idx = envelope.opened.matched_slot_idx as u8;

    match kind {
        DenCredKind::Passphrase => {
            let cred = DeniableCredential::Passphrase {
                passphrase: pass.as_bytes(),
                argon2,
            };
            Ok(luksbox_format::Container::complete_open_v2_deniable(
                envelope, &cred,
            )?)
        }
        DenCredKind::Fido2 => {
            #[cfg(feature = "hardware")]
            {
                let salt = salt_opt
                    .ok_or_else(|| "envelope missing hmac_salt for FIDO2 variant".to_string())?;
                let pin = wizard_prompt_fido2_pin(theme)?;
                let hmac_secret = wizard_fido2_hmac_from_payload(&cred_id, &salt, true, &pin)?;
                let cred = DeniableCredential::Fido2Passphrase {
                    passphrase: pass.as_bytes(),
                    argon2,
                    hmac_secret_output: &hmac_secret,
                };
                match luksbox_format::Container::complete_open_v2_deniable_reusable(envelope, &cred)
                {
                    Ok(c) => Ok(c),
                    Err((envelope, luksbox_format::Error::OpaqueUnlockFailed)) => {
                        wizard_deniable_raw_salt_retry_notice();
                        let hmac_secret =
                            wizard_fido2_hmac_from_payload(&cred_id, &salt, false, &pin)?;
                        let cred = DeniableCredential::Fido2Passphrase {
                            passphrase: pass.as_bytes(),
                            argon2,
                            hmac_secret_output: &hmac_secret,
                        };
                        Ok(luksbox_format::Container::complete_open_v2_deniable(
                            envelope, &cred,
                        )?)
                    }
                    Err((_, e)) => Err(e.into()),
                }
            }
            #[cfg(not(feature = "hardware"))]
            Err("FIDO2 hardware support not compiled in".into())
        }
        DenCredKind::HybridPqPassphrase => {
            let shared = ask_pq_decap_for_deniable(theme, vault, &pass, matched_slot_idx)?;
            let cred = DeniableCredential::HybridPqPassphrase {
                passphrase: pass.as_bytes(),
                argon2,
                mlkem_shared: &shared,
            };
            Ok(luksbox_format::Container::complete_open_v2_deniable(
                envelope, &cred,
            )?)
        }
        DenCredKind::HybridPqFido2 => {
            #[cfg(feature = "hardware")]
            {
                let shared = ask_pq_decap_for_deniable(theme, vault, &pass, matched_slot_idx)?;
                let salt = salt_opt
                    .ok_or_else(|| "envelope missing hmac_salt for FIDO2 variant".to_string())?;
                let pin = wizard_prompt_fido2_pin(theme)?;
                let hmac_secret = wizard_fido2_hmac_from_payload(&cred_id, &salt, true, &pin)?;
                let cred = DeniableCredential::HybridPqFido2Passphrase {
                    passphrase: pass.as_bytes(),
                    argon2,
                    mlkem_shared: &shared,
                    hmac_secret_output: &hmac_secret,
                };
                match luksbox_format::Container::complete_open_v2_deniable_reusable(envelope, &cred)
                {
                    Ok(c) => Ok(c),
                    Err((envelope, luksbox_format::Error::OpaqueUnlockFailed)) => {
                        wizard_deniable_raw_salt_retry_notice();
                        let hmac_secret =
                            wizard_fido2_hmac_from_payload(&cred_id, &salt, false, &pin)?;
                        let cred = DeniableCredential::HybridPqFido2Passphrase {
                            passphrase: pass.as_bytes(),
                            argon2,
                            mlkem_shared: &shared,
                            hmac_secret_output: &hmac_secret,
                        };
                        Ok(luksbox_format::Container::complete_open_v2_deniable(
                            envelope, &cred,
                        )?)
                    }
                    Err((_, e)) => Err(e.into()),
                }
            }
            #[cfg(not(feature = "hardware"))]
            Err("FIDO2 hardware support not compiled in".into())
        }
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        DenCredKind::Tpm2 => {
            let unsealed = wizard_tpm_unseal_from_bytes(&tpm_blob, None)?;
            let cred = DeniableCredential::TpmPassphrase {
                passphrase: pass.as_bytes(),
                argon2,
                unsealed: &unsealed,
            };
            Ok(luksbox_format::Container::complete_open_v2_deniable(
                envelope, &cred,
            )?)
        }
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        DenCredKind::Tpm2Fido2 => {
            let unsealed = wizard_tpm_unseal_from_bytes(&tpm_blob, None)?;
            let salt = salt_opt
                .ok_or_else(|| "envelope missing hmac_salt for FIDO2 variant".to_string())?;
            let pin = wizard_prompt_fido2_pin(theme)?;
            let hmac_secret = wizard_fido2_hmac_from_payload(&cred_id, &salt, true, &pin)?;
            let cred = DeniableCredential::TpmFido2Passphrase {
                passphrase: pass.as_bytes(),
                argon2,
                unsealed: &unsealed,
                hmac_secret_output: &hmac_secret,
            };
            match luksbox_format::Container::complete_open_v2_deniable_reusable(envelope, &cred) {
                Ok(c) => Ok(c),
                Err((envelope, luksbox_format::Error::OpaqueUnlockFailed)) => {
                    wizard_deniable_raw_salt_retry_notice();
                    let hmac_secret = wizard_fido2_hmac_from_payload(&cred_id, &salt, false, &pin)?;
                    let cred = DeniableCredential::TpmFido2Passphrase {
                        passphrase: pass.as_bytes(),
                        argon2,
                        unsealed: &unsealed,
                        hmac_secret_output: &hmac_secret,
                    };
                    Ok(luksbox_format::Container::complete_open_v2_deniable(
                        envelope, &cred,
                    )?)
                }
                Err((_, e)) => Err(e.into()),
            }
        }
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        DenCredKind::HybridPqTpm2 => {
            let shared = ask_pq_decap_for_deniable(theme, vault, &pass, matched_slot_idx)?;
            let unsealed = wizard_tpm_unseal_from_bytes(&tpm_blob, None)?;
            let cred = DeniableCredential::HybridPqTpmPassphrase {
                passphrase: pass.as_bytes(),
                argon2,
                mlkem_shared: &shared,
                unsealed: &unsealed,
            };
            Ok(luksbox_format::Container::complete_open_v2_deniable(
                envelope, &cred,
            )?)
        }
        #[cfg(all(feature = "hardware", target_os = "linux"))]
        DenCredKind::HybridPqTpmFido2 => {
            let shared = ask_pq_decap_for_deniable(theme, vault, &pass, matched_slot_idx)?;
            let unsealed = wizard_tpm_unseal_from_bytes(&tpm_blob, None)?;
            let salt = salt_opt
                .ok_or_else(|| "envelope missing hmac_salt for FIDO2 variant".to_string())?;
            let pin = wizard_prompt_fido2_pin(theme)?;
            let hmac_secret = wizard_fido2_hmac_from_payload(&cred_id, &salt, true, &pin)?;
            let cred = DeniableCredential::HybridPqTpmFido2Passphrase {
                passphrase: pass.as_bytes(),
                argon2,
                mlkem_shared: &shared,
                unsealed: &unsealed,
                hmac_secret_output: &hmac_secret,
            };
            match luksbox_format::Container::complete_open_v2_deniable_reusable(envelope, &cred) {
                Ok(c) => Ok(c),
                Err((envelope, luksbox_format::Error::OpaqueUnlockFailed)) => {
                    wizard_deniable_raw_salt_retry_notice();
                    let hmac_secret = wizard_fido2_hmac_from_payload(&cred_id, &salt, false, &pin)?;
                    let cred = DeniableCredential::HybridPqTpmFido2Passphrase {
                        passphrase: pass.as_bytes(),
                        argon2,
                        mlkem_shared: &shared,
                        unsealed: &unsealed,
                        hmac_secret_output: &hmac_secret,
                    };
                    Ok(luksbox_format::Container::complete_open_v2_deniable(
                        envelope, &cred,
                    )?)
                }
                Err((_, e)) => Err(e.into()),
            }
        }
    }
}

/// v2 wizard helper: drive the FIDO2 device with cred_id + hmac_salt
/// recovered from the slot envelope (no longer prompts the user for
/// hex strings).
///
/// Deniable v2 envelopes embed the cred_id + salt at create time
/// but, unlike keyslots, record NO salt-convention marker. v0.3.0
/// creates envelopes under the V4 prehashed convention;
/// v0.2.1/v0.2.2 envelopes recorded raw-salt HMACs on Linux/macOS.
/// Callers probe: `prehash_salt = true` first, then on an
/// inner-AEAD failure retry with `false` via
/// `Container::complete_open_v2_deniable_reusable`. The PIN is
/// prompted once by the caller so the fallback costs only a second
/// touch.
#[cfg(feature = "hardware")]
fn wizard_fido2_hmac_from_payload(
    cred_id: &[u8],
    salt: &[u8; 32],
    prehash_salt: bool,
    pin: &str,
) -> Result<luksbox_fido2::HmacSecret> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID};
    if cred_id.is_empty() {
        return Err("envelope cred_id is empty for FIDO2 variant".into());
    }
    let mut auth = crate::make_fido2_authenticator();
    Ok(auth.hmac_secret(RP_ID, cred_id, salt, prehash_salt, Some(pin))?)
}

/// Prompt the FIDO2 PIN once for a deniable unlock (shared between
/// the first probe attempt and the raw-salt fallback).
#[cfg(feature = "hardware")]
fn wizard_prompt_fido2_pin(theme: &ColorfulTheme) -> Result<zeroize::Zeroizing<String>> {
    Ok(zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt("FIDO2 PIN")
            .interact()?,
    ))
}

/// User-facing notice for the second probe attempt.
#[cfg(feature = "hardware")]
fn wizard_deniable_raw_salt_retry_notice() {
    eprintln!(
        "Unlock failed under the v0.3.0 salt convention; retrying \
         with the pre-v0.3.0 raw-salt convention. Touch the \
         authenticator again."
    );
}

/// v2 wizard helper: unseal the TPM blob recovered from the slot
/// envelope (no longer asks the user for a sidecar path).
#[cfg(all(feature = "hardware", target_os = "linux"))]
fn wizard_tpm_unseal_from_bytes(blob_bytes: &[u8], pin: Option<&[u8]>) -> Result<[u8; 32]> {
    use luksbox_tpm::{SealedBlob, Tpm2Sealer};
    if blob_bytes.is_empty() {
        return Err("envelope tpm_blob is empty for TPM variant".into());
    }
    let blob = SealedBlob::from_bytes(blob_bytes)?;
    let mut sealer = Tpm2Sealer::new()?;
    let unsealed = match pin {
        Some(p) => sealer.unseal_with_pin(&blob, Some(p))?,
        None => sealer.unseal(&blob)?,
    };
    Ok(*unsealed)
}

// v1 helper `ask_fido2_hmac_for_deniable` removed in v2; FIDO2
// `cred_id` and `hmac_salt` are recovered from the slot envelope at
// open time, so callers use `wizard_fido2_hmac_from_payload` above.

/// Prompt for the .kyber seed file path + seed passphrase and run
/// ML-KEM decapsulation against the .hybrid sidecar next to the
/// vault. Returns the 32-byte shared secret for the deniable
/// hybrid-PQ credential.
///
/// `envelope_pw_for_fallback` is the envelope passphrase the caller
/// already collected; if the user leaves the seed-file passphrase
/// blank we reuse it (matches the v2 deniable create-time default
/// where one passphrase opens both roles).
fn ask_pq_decap_for_deniable(
    theme: &ColorfulTheme,
    vault: &Path,
    envelope_pw_for_fallback: &str,
    matched_slot_idx: u8,
) -> Result<[u8; 32]> {
    use luksbox_format::hybrid_sidecar;
    use luksbox_pq::seed_file;
    let kyber_path = ask_path(theme, "Path to the .kyber seed file")?;
    println!("  Hint: leave the next field BLANK if you used the same passphrase for the envelope");
    println!("  AND the .kyber seed at create time (the common default). Fill it only if you set");
    println!("  a DISTINCT seed-file passphrase at create time.");
    let seed_pw = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt("Seed-file passphrase (leave blank to reuse envelope passphrase)")
            .allow_empty_password(true)
            .interact()?,
    );
    let pw_bytes: &[u8] = if seed_pw.is_empty() {
        envelope_pw_for_fallback.as_bytes()
    } else {
        seed_pw.as_bytes()
    };
    let seed = seed_file::read(&kyber_path, pw_bytes)?;
    let sidecar = hybrid_sidecar::sidecar_path(vault);
    let entries = hybrid_sidecar::read(&sidecar)?;
    // Match the sidecar entry to the deniable slot the envelope
    // discovery resolved. Falling back to `entries.first()` (the
    // old behaviour) silently produced a garbage shared secret via
    // ML-KEM's implicit rejection whenever the user's seed was for
    // a non-first slot, and the final AEAD then rejected the
    // unlock with no indication of where things went wrong.
    let entry = hybrid_sidecar::find(&entries, matched_slot_idx).ok_or_else(|| {
        format!(
            "no .hybrid sidecar entry for slot {matched_slot_idx} (envelope \
             discovery resolved this slot but the matching ML-KEM (pk, ct) \
             pair is missing from the sidecar)"
        )
    })?;
    let shared = luksbox_pq::decapsulate_with(entry.level, &seed, &entry.ciphertext)?;
    Ok(*shared)
}

/// Prompt for an optional .kyber seed-file passphrase at CREATE
/// time. Blank => reuse the envelope passphrase (one passphrase
/// opens both roles). Mirrors the GUI's seed-file passphrase
/// field. Offers the strong-passphrase generator if the user wants
/// a distinct one.
fn ask_optional_seed_pw(
    theme: &ColorfulTheme,
    envelope_pw_for_fallback: &zeroize::Zeroizing<String>,
) -> Result<zeroize::Zeroizing<String>> {
    println!();
    println!("  Optional separate .kyber seed-file passphrase.");
    println!(" - Leave BLANK to use the envelope passphrase for both roles");
    println!("    (one passphrase opens the vault AND decrypts the .kyber).");
    println!(" - Fill it to set a DISTINCT seed-file passphrase. You'll then need");
    println!("    to type both at every unlock.");
    if Confirm::with_theme(theme)
        .with_prompt("Use a separate seed-file passphrase?")
        .default(false)
        .interact()?
    {
        if Confirm::with_theme(theme)
            .with_prompt("Generate a strong random seed-file passphrase?")
            .default(false)
            .interact()?
        {
            let pw = crate::passphrase::generate()?;
            println!("  generated seed-file passphrase: {}", &*pw);
            println!("  WRITE THIS DOWN. It is shown only once.");
            if !Confirm::with_theme(theme)
                .with_prompt("I have stored the seed-file passphrase safely. Continue?")
                .default(false)
                .interact()?
            {
                return Err("aborted (seed-file passphrase not saved)".into());
            }
            Ok(pw)
        } else {
            let s = zeroize::Zeroizing::new(
                Password::with_theme(theme)
                    .with_prompt("Seed-file passphrase (distinct from envelope)")
                    .with_confirmation("Confirm", "passphrases don't match")
                    .interact()?,
            );
            Ok(s)
        }
    } else {
        // Reuse the envelope passphrase. Clone so the caller can
        // independently zeroize on drop without affecting the
        // envelope value.
        Ok(envelope_pw_for_fallback.clone())
    }
}

// v1 helper `ask_tpm_unseal_for_deniable` removed in v2; the TPM
// sealed blob is recovered from the slot envelope at open time, so
// callers use `wizard_tpm_unseal_from_bytes` above.

/// Destroy a vault without first unlocking it. Useful for emergency wipes
/// where you don't want to (or can't) authenticate first. Asks for the
/// vault path, optional sidecar header path, and uses the same shred
/// procedure as `panic_action`.
fn panic_by_path(theme: &ColorfulTheme) -> Result<()> {
    use luksbox_core::file_util::secure_open_existing_no_follow;
    use rand_core::{OsRng, RngCore};
    use std::io::{Seek, SeekFrom, Write};

    let vault = ask_path(theme, "Path to vault to destroy")?;
    let detached = Confirm::with_theme(theme)
        .with_prompt("Does this vault use a detached header (sidecar)?")
        .default(false)
        .interact()?;
    let header_target = if detached {
        ask_path(theme, "Path to the sidecar header file")?
    } else {
        vault.clone()
    };
    let wipe_data = Confirm::with_theme(theme)
        .with_prompt("ALSO overwrite the entire vault data area? (slow)")
        .default(false)
        .interact()?;

    // Open the destructive targets BEFORE the confirmation prompt
    // with no-follow semantics. Closes the TOCTOU window where an
    // attacker who controls the parent dir could swap in a symlink
    // between the path-resolution and the open, redirecting the
    // random-bytes overwrite to /etc/shadow or similar. Holding
    // the handles across the prompt also prevents a path-rename
    // race during user interaction.
    let mut hf = secure_open_existing_no_follow(&header_target).map_err(|e| {
        format!(
            "refusing to open {} for destructive overwrite: {e}",
            header_target.display()
        )
    })?;
    let mut vf_opt = if wipe_data && header_target != vault {
        Some(
            secure_open_existing_no_follow(&vault)
                .map_err(|e| format!("refusing to open {} for data wipe: {e}", vault.display()))?,
        )
    } else {
        None
    };
    let len_hint = std::fs::metadata(&vault).map(|m| m.len()).unwrap_or(0);

    eprintln!(
        "PANIC: about to overwrite the {} of {} with random bytes.",
        if header_target == vault {
            "first 8 KB"
        } else {
            "header sidecar"
        },
        header_target.display(),
    );
    eprintln!("This is IRREVERSIBLE. There is NO undo.");
    let expected = format!("DESTROY {}", vault.display());
    let typed: String = Input::with_theme(theme)
        .with_prompt(format!("Type literally `{expected}` to confirm"))
        .allow_empty(true)
        .interact_text()?;
    if typed != expected {
        return Err("aborted (confirmation string did not match)".into());
    }

    let mut buf = [0u8; HEADER_SIZE];
    OsRng.fill_bytes(&mut buf);
    hf.seek(SeekFrom::Start(0))?;
    hf.write_all(&buf)?;
    hf.flush()?;
    eprintln!("OK header at {} overwritten", header_target.display());

    if wipe_data {
        // Inline-header case: vf_opt is None, write through hf
        // (which IS the vault). Detached-header case: separate vf.
        let writer: &mut std::fs::File = vf_opt.as_mut().unwrap_or(&mut hf);
        writer.seek(SeekFrom::Start(0))?;
        let mut chunk = vec![0u8; 1 << 20];
        let mut written = 0u64;
        while written < len_hint {
            OsRng.fill_bytes(&mut chunk);
            let to_write = ((len_hint - written) as usize).min(chunk.len());
            writer.write_all(&chunk[..to_write])?;
            written += to_write as u64;
        }
        writer.flush()?;
        let _ = writer.sync_all();
        eprintln!("OK vault {} ({} bytes) wiped", vault.display(), len_hint);
    }
    println!("done.");
    Ok(())
}

// ---- shared helpers --------------------------------------------------------

/// OS-aware example path snippet to embed in interactive prompts. Pure
/// formatting; the runtime path-resolution code never reads these. Each
/// release binary surfaces the convention native to the host OS:
/// Linux -> `/media/usb/foo`, macOS -> `/Volumes/USB/foo`,
/// Windows -> `D:\foo`.
fn usb_example(name: &str) -> String {
    if cfg!(target_os = "windows") {
        format!("D:\\{name}")
    } else if cfg!(target_os = "macos") {
        format!("/Volumes/USB/{name}")
    } else {
        format!("/media/usb/{name}")
    }
}

fn ask_path(theme: &ColorfulTheme, prompt: &str) -> Result<PathBuf> {
    let s: String = Input::with_theme(theme)
        .with_prompt(prompt)
        .interact_text()?;
    Ok(PathBuf::from(s))
}

fn ask_path_with_default(theme: &ColorfulTheme, prompt: &str, default: &str) -> Result<PathBuf> {
    let s: String = Input::with_theme(theme)
        .with_prompt(prompt)
        .with_initial_text(default)
        .interact_text()?;
    Ok(PathBuf::from(s))
}

/// Prompt the user for a mount target. On macOS+FUSE-T this offers a
/// "private mount" shortcut up front: a `Confirm` (default no) that,
/// if accepted, derives `~/Library/LUKSbox/Mounts/<vault-name>` via
/// [`luksbox_mount::private_mountpoint_for`] so the mountpoint name
/// is invisible to other local users (see the helper's doc comment
/// for the rationale). On every other backend the Confirm is skipped
/// and the user goes straight to the regular path prompt with
/// platform-appropriate phrasing.
///
/// Shared by the standard `mount_action` and the deniable-mode
/// `mount_deniable_wizard` so the prompt copy + private-mount logic
/// stay in lockstep.
#[cfg_attr(not(target_os = "macos"), allow(unused_variables))]
fn ask_mountpoint(theme: &ColorfulTheme, vault: &Path) -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    if luksbox_mount::FUSE_BACKEND == "fuse-t"
        && Confirm::with_theme(theme)
            .with_prompt(
                "Use a private mountpoint under ~/Library/LUKSbox/Mounts/<vault-name>? \
                 (other local users won't see the mount name, but it won't appear in \
                 Finder's Locations sidebar)",
            )
            .default(false)
            .interact()?
    {
        let vault_name = vault
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "vault".to_string());
        return luksbox_mount::private_mountpoint_for(&vault_name)
            .map_err(|e| format!("private mount setup failed: {e}").into());
    }
    let prompt = if cfg!(target_os = "windows") {
        "Mount point (a drive letter like Z: or a non-existent path WinFsp will create)"
    } else {
        "Mount point (must be an existing empty directory)"
    };
    ask_path(theme, prompt)
}

/// Prompt the admin to pick a target slot index for a new deniable
/// credential. Lists slots 0..7; marks the admin's own unlock slot
/// as "(you - cannot overwrite)" so they don't accidentally lock
/// themselves out (Container also guards). Defaults to the first
/// non-unlock slot.
fn ask_deniable_slot_idx(theme: &ColorfulTheme, cont: &Container) -> Result<usize> {
    let unlocked = cont.deniable_unlocked_slot();
    let count = luksbox_core::deniable::DENIABLE_SLOT_COUNT;
    let mut items: Vec<String> = Vec::with_capacity(count);
    for i in 0..count {
        if Some(i) == unlocked {
            items.push(format!("Slot {} (you - cannot overwrite)", i));
        } else {
            items.push(format!("Slot {}", i));
        }
    }
    // Default to the first slot that isn't the admin's own.
    let default_idx = (0..count).find(|i| Some(*i) != unlocked).unwrap_or(0);
    let pick = Select::with_theme(theme)
        .with_prompt(
            "Target slot for the new credential (other slots may be other users' \
             credentials - you cannot tell without their unlock material)",
        )
        .items(&items)
        .default(default_idx)
        .interact()?;
    println!(
        "  WARNING: remember slot {}. Deniable vaults cannot enumerate slots, so to revoke",
        pick
    );
    println!("  this credential later you must remember which index you used.");
    Ok(pick)
}

/// Prompt the user for a new passphrase, with the option to generate a
/// strong random one (about 99 bits via `OsRng`) instead of typing. Used by
/// every place the wizard creates a new passphrase keyslot.
fn ask_new_passphrase(theme: &ColorfulTheme, prompt: &str) -> Result<zeroize::Zeroizing<String>> {
    if Confirm::with_theme(theme)
        .with_prompt("Generate a strong random passphrase instead of typing one?")
        .default(false)
        .interact()?
    {
        let pw = crate::passphrase::generate()?;
        println!("  generated passphrase: {}", &*pw);
        println!("  WRITE THIS DOWN, it is shown only once.");
        if !Confirm::with_theme(theme)
            .with_prompt("I have stored the passphrase safely. Continue?")
            .default(false)
            .interact()?
        {
            return Err("aborted (passphrase not saved)".into());
        }
        return Ok(pw);
    }
    loop {
        // Wrap the dialoguer return in `Zeroizing` immediately so the
        // String heap allocation is scrubbed on every drop path -- the
        // continue-on-empty branch, the confirm-prompt panic path, and
        // the normal return.
        let s = zeroize::Zeroizing::new(
            Password::with_theme(theme)
                .with_prompt(prompt)
                .with_confirmation("Confirm", "passphrases don't match")
                .interact()?,
        );
        // Empty-passphrase guard: confirm rather than silently accept.
        // An empty passphrase is technically valid (Argon2id hashes
        // the empty string fine) but means anyone with the .lbx file
        // can open the vault, so almost always a mistake. Default
        // the confirm to "no" so an Enter-mash doesn't dismiss the
        // warning.
        if s.is_empty() {
            let proceed = Confirm::with_theme(theme)
                .with_prompt(
                    "The passphrase is empty. ANYONE with this vault file will \
                     be able to open it. Are you sure?",
                )
                .default(false)
                .interact()?;
            if !proceed {
                continue;
            }
        }
        return Ok(s);
    }
}

/// Ask the create-time hardening prompts (`--pad-files`, `--hide-sizes`,
/// `--anchor`). The pad/hide flags don't yet apply to FIDO2-direct vaults
/// (the create_with_fido2_derived_mvk API takes no flags param), so they
/// are skipped in that mode. The anchor IS supported for all three kinds.
fn ask_create_options(theme: &ColorfulTheme, fido2_direct: bool) -> Result<CreateOptions> {
    let mut flags = 0u32;
    if !fido2_direct {
        let pad = Confirm::with_theme(theme)
            .with_prompt(
                "Pad each file's chunk count to the next power of 2? (hides per-file \
                 size from disk-level forensics within a 2x bucket; up to 2x storage cost)",
            )
            .default(false)
            .interact()?;
        let hide_sizes = Confirm::with_theme(theme)
            .with_prompt(
                "Hide exact file sizes (encrypts size into chunk-0 plaintext rather \
                 than metadata)? Implies size padding.",
            )
            .default(false)
            .interact()?;
        if pad || hide_sizes {
            flags |= FLAG_PAD_FILES_POW2;
        }
        if hide_sizes {
            flags |= FLAG_HIDE_SIZE_HEADER;
        }
    }
    let anchor_path = if Confirm::with_theme(theme)
        .with_prompt(
            "Initialize a rollback-detection anchor sidecar? (small 48-byte file you \
             keep on separate trusted storage; verified on every open)",
        )
        .default(false)
        .interact()?
    {
        let p = ask_path(theme, "Path for the anchor sidecar (e.g. on a USB stick)")?;
        if p.exists() {
            return Err(format!("anchor file {} already exists", p.display()).into());
        }
        Some(p)
    } else {
        None
    };
    Ok(CreateOptions {
        flags,
        anchor: anchor_path,
    })
}

/// Ask whether the vault uses a detached-header sidecar, and if so, where.
/// Returns `None` for inline (default) or `Some(sidecar)` for detached.
fn ask_detached_header(theme: &ColorfulTheme, for_create: bool) -> Result<Option<PathBuf>> {
    let prompt = if for_create {
        "Use a detached-header sidecar? (vault file alone becomes opaque random)"
    } else {
        "Does this vault use a detached header (sidecar file)?"
    };
    let detached = Confirm::with_theme(theme)
        .with_prompt(prompt)
        .default(false)
        .interact()?;
    if !detached {
        return Ok(None);
    }
    let p = ask_path(theme, "Path to the header sidecar")?;
    if for_create && p.exists() {
        return Err(format!("{} already exists", p.display()).into());
    }
    if !for_create && !p.is_file() {
        return Err(format!("{} is not a file", p.display()).into());
    }
    Ok(Some(p))
}

/// Read the header bytes from either the vault file (inline) or the sidecar
/// file (detached). Returns the parsed `Header`.
fn load_header(vault: &Path, sidecar: Option<&Path>) -> Result<Header> {
    let from = sidecar.unwrap_or(vault);
    let mut f = File::open(from)?;
    let mut buf = [0u8; HEADER_SIZE];
    f.read_exact(&mut buf)?;
    Ok(Header::from_bytes(&buf)?)
}

/// One-line label for a keyslot, used by all three places that print slots
/// (info, post-open summary, revoke picker).
fn format_slot(idx: usize, slot: &luksbox_core::Keyslot, with_kdf: bool) -> String {
    match slot.kind {
        SlotKind::Empty => format!("  {idx}: empty"),
        SlotKind::Passphrase => {
            if with_kdf {
                format!(
                    "  {idx}: passphrase   (Argon2id m={} KiB t={} p={})",
                    slot.kdf_params.m_cost_kib, slot.kdf_params.t_cost, slot.kdf_params.p_cost
                )
            } else {
                format!("  {idx}: passphrase")
            }
        }
        SlotKind::Fido2HmacSecret => {
            let pfx: String = slot
                .fido2_cred_id
                .iter()
                .take(8)
                .map(|b| format!("{b:02x}"))
                .collect();
            format!(
                "  {idx}: fido2        (cred_id={pfx}etc.  {} B)",
                slot.fido2_cred_id.len()
            )
        }
        SlotKind::Fido2DerivedMvk => {
            let pfx: String = slot
                .fido2_cred_id
                .iter()
                .take(8)
                .map(|b| format!("{b:02x}"))
                .collect();
            format!(
                "  {idx}: fido2-direct (cred_id={pfx}etc.  {} B; MVK derived)",
                slot.fido2_cred_id.len()
            )
        }
        SlotKind::HybridPqKemPassphrase => {
            if with_kdf {
                format!(
                    "  {idx}: hybrid-pq    (Argon2id m={} KiB t={} p={} + ML-KEM-768)",
                    slot.kdf_params.m_cost_kib, slot.kdf_params.t_cost, slot.kdf_params.p_cost
                )
            } else {
                format!("  {idx}: hybrid-pq    (passphrase + ML-KEM-768)")
            }
        }
        SlotKind::HybridPqKemFido2 => {
            let pfx: String = slot
                .fido2_cred_id
                .iter()
                .take(8)
                .map(|b| format!("{b:02x}"))
                .collect();
            format!(
                "  {idx}: hybrid-pq-fido2 (cred_id={pfx}etc.  {} B + ML-KEM-768)",
                slot.fido2_cred_id.len()
            )
        }
        SlotKind::HybridPqKem1024Passphrase => {
            if with_kdf {
                format!(
                    "  {idx}: hybrid-pq    (Argon2id m={} KiB t={} p={} + ML-KEM-1024)",
                    slot.kdf_params.m_cost_kib, slot.kdf_params.t_cost, slot.kdf_params.p_cost
                )
            } else {
                format!("  {idx}: hybrid-pq    (passphrase + ML-KEM-1024)")
            }
        }
        SlotKind::HybridPqKem1024Fido2 => {
            let pfx: String = slot
                .fido2_cred_id
                .iter()
                .take(8)
                .map(|b| format!("{b:02x}"))
                .collect();
            format!(
                "  {idx}: hybrid-pq-fido2 (cred_id={pfx}etc.  {} B + ML-KEM-1024)",
                slot.fido2_cred_id.len()
            )
        }
        SlotKind::Tpm2Sealed | SlotKind::Tpm2SealedPin => {
            let pfx: String = slot
                .fido2_cred_id
                .iter()
                .take(8)
                .map(|b| format!("{b:02x}"))
                .collect();
            let label = if slot.kind == SlotKind::Tpm2SealedPin {
                "tpm2-pin"
            } else {
                "tpm2    "
            };
            format!(
                "  {idx}: {label} (sealed_blob={pfx}etc.  {} B; local TPM 2.0)",
                slot.fido2_cred_id.len()
            )
        }
        SlotKind::HybridPqKemTpm2 | SlotKind::HybridPqKem1024Tpm2 => {
            let level = if slot.kind == SlotKind::HybridPqKem1024Tpm2 {
                "1024"
            } else {
                "768"
            };
            let pfx: String = slot
                .fido2_cred_id
                .iter()
                .take(8)
                .map(|b| format!("{b:02x}"))
                .collect();
            format!(
                "  {idx}: hybrid-pq-tpm2 (sealed_blob={pfx}etc.  {} B; TPM + ML-KEM-{level})",
                slot.fido2_cred_id.len()
            )
        }
        SlotKind::HybridPqKemTpm2Fido2 | SlotKind::HybridPqKem1024Tpm2Fido2 => {
            let level = if slot.kind == SlotKind::HybridPqKem1024Tpm2Fido2 {
                "1024"
            } else {
                "768"
            };
            let cred_pfx: String = slot
                .tpm2_fido2_cred_id()
                .map(|c| c.iter().take(8).map(|b| format!("{b:02x}")).collect())
                .unwrap_or_default();
            let cred_len = slot.tpm2_fido2_cred_id().map(|c| c.len()).unwrap_or(0);
            let blob_len = slot.tpm2_fido2_sealed_blob().map(|b| b.len()).unwrap_or(0);
            format!(
                "  {idx}: hybrid-pq-tpm2-fido2 (cred_id={cred_pfx}etc. {cred_len} B + \
                 sealed_blob {blob_len} B; TPM + FIDO2 + ML-KEM-{level})"
            )
        }
        SlotKind::Tpm2Fido2 => {
            let cred_pfx: String = slot
                .tpm2_fido2_cred_id()
                .map(|c| c.iter().take(8).map(|b| format!("{b:02x}")).collect())
                .unwrap_or_default();
            let cred_len = slot.tpm2_fido2_cred_id().map(|c| c.len()).unwrap_or(0);
            let blob_len = slot.tpm2_fido2_sealed_blob().map(|b| b.len()).unwrap_or(0);
            format!(
                "  {idx}: tpm2-fido2   (cred_id={cred_pfx}etc. {cred_len} B + \
                 sealed_blob {blob_len} B; both factors required)"
            )
        }
        SlotKind::SepSealed | SlotKind::SepSealedBiometric => {
            let bio = if slot.kind == SlotKind::SepSealedBiometric {
                " + biometry"
            } else {
                ""
            };
            format!("  {idx}: secure-enclave{bio} (macOS; SEP material in-header)")
        }
        SlotKind::HybridPqKemSep | SlotKind::HybridPqKem1024Sep => {
            let level = if slot.kind == SlotKind::HybridPqKem1024Sep {
                "1024"
            } else {
                "768"
            };
            format!(
                "  {idx}: hybrid-pq-sep (macOS Secure Enclave + ML-KEM-{level}; \
                 SEP material in-header, ML-KEM in .lbx.hybrid)"
            )
        }
        SlotKind::SepFido2 => {
            format!("  {idx}: secure-enclave + FIDO2 (macOS; SEP material in-header)")
        }
        SlotKind::HybridPqKemSepFido2 => format!(
            "  {idx}: hybrid-pq-sep (macOS Secure Enclave + FIDO2 + ML-KEM-768; \
             SEP material in-header, ML-KEM in .lbx.hybrid)"
        ),
        SlotKind::HybridPqKem1024SepFido2 => format!(
            "  {idx}: hybrid-pq-sep (macOS Secure Enclave + FIDO2 + ML-KEM-1024; \
             SEP material in-header, ML-KEM in .lbx.hybrid)"
        ),
        SlotKind::SepPassphrase => {
            format!("  {idx}: secure-enclave + passphrase (macOS; SEP material in-header)")
        }
        SlotKind::HybridPqKemSepPassphrase => format!(
            "  {idx}: hybrid-pq-sep (macOS Secure Enclave + passphrase + ML-KEM-768; \
             SEP material in-header, ML-KEM in .lbx.hybrid)"
        ),
        SlotKind::HybridPqKem1024SepPassphrase => format!(
            "  {idx}: hybrid-pq-sep (macOS Secure Enclave + passphrase + ML-KEM-1024; \
             SEP material in-header, ML-KEM in .lbx.hybrid)"
        ),
        SlotKind::SepFido2Passphrase => {
            format!("  {idx}: secure-enclave + FIDO2 + passphrase (macOS; SEP material in-header)")
        }
        SlotKind::HybridPqKemSepFido2Passphrase => format!(
            "  {idx}: hybrid-pq-sep (macOS Secure Enclave + FIDO2 + passphrase + ML-KEM-768; \
             SEP material in-header, ML-KEM in .lbx.hybrid)"
        ),
        SlotKind::HybridPqKem1024SepFido2Passphrase => format!(
            "  {idx}: hybrid-pq-sep (macOS Secure Enclave + FIDO2 + passphrase + ML-KEM-1024; \
             SEP material in-header, ML-KEM in .lbx.hybrid)"
        ),
    }
}

fn print_slots(header: &Header, with_kdf: bool) {
    println!("keyslots:");
    for (i, s) in header.keyslots.iter().enumerate() {
        println!("{}", format_slot(i, s, with_kdf));
        // Same V4 cross-platform indicator as `luksbox info`. V4
        // FIDO2 slots open on Linux, macOS, and Windows; V1/V2/V3
        // slots open only on Linux/macOS. Wrap-style slots can be
        // migrated with `luksbox migrate-fido2-slot <vault> --slot N`;
        // other FIDO2-touching kinds have no migration path yet.
        if s.touches_fido2() {
            if s.fido2_salt_prehashed() {
                println!("       compat: V4 cross-platform (Linux/macOS/Windows)");
            } else if s.kind == luksbox_core::SlotKind::Fido2HmacSecret {
                // aad_version is 0-based on disk; labels are 1-based.
                println!(
                    "       compat: V{ver} Linux/macOS-only -- migrate with \
                     `luksbox migrate-fido2-slot <vault> --slot {i}` for \
                     cross-platform",
                    ver = s.aad_version + 1,
                );
            } else {
                println!(
                    "       compat: V{ver} Linux/macOS-only -- migration \
                     for this slot kind is not available yet; re-enroll \
                     the credential on v0.3.0 for cross-platform",
                    ver = s.aad_version + 1,
                );
            }
        }
    }
}

// ---- create wizard ---------------------------------------------------------

fn create_wizard(theme: &ColorfulTheme) -> Result<()> {
    let pb = ask_path_with_default(theme, "Path for the new vault", "vault.lbx")?;
    if pb.exists() {
        return Err(format!("{} already exists", pb.display()).into());
    }

    let header_path = ask_detached_header(theme, true)?;

    let cipher = match Select::with_theme(theme)
        .with_prompt("Cipher suite")
        .items(&[
            "AES-256-GCM-SIV (recommended; nonce-misuse-resistant, RFC 8452)",
            "AES-256-GCM (legacy; faster but catastrophic on nonce reuse)",
            "ChaCha20-Poly1305 (no hardware AES; same nonce contract as GCM)",
        ])
        .default(0)
        .interact()?
    {
        0 => CipherSuite::Aes256GcmSiv,
        1 => CipherSuite::Aes256Gcm,
        2 => CipherSuite::ChaCha20Poly1305,
        _ => unreachable!(),
    };

    // Metadata format choice. v2 stays the default (interoperates with
    // every existing LUKSbox binary); v3 unlocks arbitrarily-large
    // single files via out-of-line chunk-list blocks but requires
    // LUKSbox v0.2.0+ to open. The choice is permanent for the vault.
    // We install the thread-local override here so the create_*
    // helpers below pick it up transparently via `luksbox-vfs`'s
    // first-flush format selection.
    let format_choice = Select::with_theme(theme)
        .with_prompt("On-disk metadata format")
        .items(&[
            "v3 (default; out-of-line chunk lists, no per-vault ceiling; requires LUKSbox v0.2.0+ to open)",
            "v2 (compat; inline chunk lists, ~10 GiB practical per-vault ceiling; readable by pre-v0.2.0 LUKSbox)",
        ])
        .default(0)
        .interact()?;
    let _format_guard = luksbox_vfs::set_format_v3_override(Some(format_choice == 0));

    // Show the selected FIDO2 authenticator above the kind picker so
    // the user knows whether the FIDO2 / hybrid-fido kinds will work
    // without re-plugging. select_fido2_device prompts only when more
    // than one device is plugged in AND no override is already set.
    match select_fido2_device(theme) {
        Some(label) => eprintln!("  FIDO2 authenticator available: {label}"),
        None => eprintln!(
            "  No FIDO2 authenticator, passphrase / hybrid-pq still work; \
             plug in a security key (any CTAP2: YubiKey, Nitrokey, SoloKey, \
             Token2, OnlyKey, Windows Hello, etc.) for the FIDO2 kinds."
        ),
    }

    // TPM-bound kinds only on Linux. Windows TPM is on the roadmap;
    // macOS uses Secure Enclave instead. On those platforms the menu
    // hides them rather than offering options that would just error.
    let mut items: Vec<&'static str> = vec![
        "Passphrase (most familiar; can add an authenticator backup later)",
        "FIDO2 wrap-style (authenticator wraps a random MVK; rotation possible)",
        "FIDO2-direct (MVK derived from the authenticator, no wrap; STRONGEST but no MVK-layer backup)",
        "Hybrid passphrase + ML-KEM-768 (post-quantum; needs a separate .kyber seed file)",
        "Hybrid FIDO2 + ML-KEM-768 (post-quantum; authenticator + .kyber seed file, closes the actual PQ gap)",
        "Hybrid passphrase + ML-KEM-1024 (NIST Category 5, AES-256-equivalent PQ strength; .kyber seed file)",
        "Hybrid FIDO2 + ML-KEM-1024 (NIST Category 5, AES-256-equivalent PQ strength; authenticator + .kyber seed)",
    ];
    #[cfg(target_os = "linux")]
    {
        items.extend_from_slice(&[
            "TPM 2.0 (this machine; bootstrap passphrase kept as backup)",
            "TPM 2.0 + PIN (this machine + memorised PIN; bootstrap passphrase kept as backup)",
            "Fused TPM 2.0 + FIDO2 (TPM + authenticator both required; bootstrap passphrase kept as backup)",
            "Hybrid TPM 2.0 + ML-KEM-768 (2-factor; bootstrap passphrase kept as backup)",
            "Hybrid TPM 2.0 + ML-KEM-1024 (2-factor; bootstrap passphrase kept as backup)",
            "3-factor TPM 2.0 + FIDO2 + ML-KEM-768 (paranoid; bootstrap passphrase kept as backup)",
            "3-factor TPM 2.0 + FIDO2 + ML-KEM-1024 (paranoid; bootstrap passphrase kept as backup)",
        ]);
    }
    #[cfg(target_os = "macos")]
    {
        items.extend_from_slice(&[
            "Secure Enclave (this Mac; bootstrap passphrase kept as backup)",
            "Secure Enclave + Touch ID (this Mac + biometry; bootstrap passphrase kept as backup)",
            "Hybrid Secure Enclave + ML-KEM-768 (2-factor; bootstrap passphrase kept as backup)",
            "Hybrid Secure Enclave + ML-KEM-1024 (2-factor; bootstrap passphrase kept as backup)",
            "Fused Secure Enclave + FIDO2 (both required; bootstrap passphrase kept as backup)",
            "Fused Secure Enclave + passphrase (SEP + a slot passphrase; bootstrap passphrase kept as backup)",
            "Fused Secure Enclave + FIDO2 + passphrase (3-factor; bootstrap passphrase kept as backup)",
            "Hybrid Secure Enclave + FIDO2 + ML-KEM-768 (3-factor; bootstrap passphrase kept as backup)",
            "Hybrid Secure Enclave + FIDO2 + ML-KEM-1024 (3-factor; bootstrap passphrase kept as backup)",
            "Hybrid Secure Enclave + passphrase + ML-KEM-768 (3-factor; bootstrap passphrase kept as backup)",
            "Hybrid Secure Enclave + passphrase + ML-KEM-1024 (3-factor; bootstrap passphrase kept as backup)",
            "Hybrid Secure Enclave + FIDO2 + passphrase + ML-KEM-768 (4-factor; bootstrap passphrase kept as backup)",
            "Hybrid Secure Enclave + FIDO2 + passphrase + ML-KEM-1024 (4-factor; bootstrap passphrase kept as backup)",
        ]);
    }
    let kind_choice = Select::with_theme(theme)
        .with_prompt("Initial keyslot kind")
        .items(&items)
        .default(0)
        .interact()?;

    // FIDO2-direct + all four hybrid kinds + all TPM / SEP kinds skip
    // pad/hide-sizes prompts (they have their own follow-on prompts
    // and the size-hardening flags don't apply to keyslot wrapping).
    // On macOS the SEP block runs to index 19; on Linux the TPM block
    // ends at 13.
    let opts = ask_create_options(theme, matches!(kind_choice, 2..=19))?;

    match kind_choice {
        0 => create_passphrase(theme, &pb, header_path.as_deref(), cipher, &opts)?,
        1 => create_fido2_wrap(theme, &pb, header_path.as_deref(), cipher, &opts)?,
        2 => create_fido2_direct(theme, &pb, header_path.as_deref(), cipher, &opts)?,
        3 => create_hybrid_pq(
            theme,
            &pb,
            header_path.as_deref(),
            cipher,
            &opts,
            luksbox_pq::PqParams::Ml768,
        )?,
        4 => create_hybrid_pq_fido2(
            theme,
            &pb,
            header_path.as_deref(),
            cipher,
            &opts,
            luksbox_pq::PqParams::Ml768,
        )?,
        5 => create_hybrid_pq(
            theme,
            &pb,
            header_path.as_deref(),
            cipher,
            &opts,
            luksbox_pq::PqParams::Ml1024,
        )?,
        6 => create_hybrid_pq_fido2(
            theme,
            &pb,
            header_path.as_deref(),
            cipher,
            &opts,
            luksbox_pq::PqParams::Ml1024,
        )?,
        #[cfg(target_os = "linux")]
        7 => create_with_tpm_bootstrap(
            theme,
            &pb,
            header_path.as_deref(),
            cipher,
            &opts,
            TpmBootstrap::Plain,
        )?,
        #[cfg(target_os = "linux")]
        8 => create_with_tpm_bootstrap(
            theme,
            &pb,
            header_path.as_deref(),
            cipher,
            &opts,
            TpmBootstrap::Pin,
        )?,
        #[cfg(target_os = "linux")]
        9 => create_with_tpm_bootstrap(
            theme,
            &pb,
            header_path.as_deref(),
            cipher,
            &opts,
            TpmBootstrap::Fido2,
        )?,
        #[cfg(target_os = "linux")]
        10 => create_with_tpm_bootstrap(
            theme,
            &pb,
            header_path.as_deref(),
            cipher,
            &opts,
            TpmBootstrap::HybridPq(luksbox_pq::PqParams::Ml768),
        )?,
        #[cfg(target_os = "linux")]
        11 => create_with_tpm_bootstrap(
            theme,
            &pb,
            header_path.as_deref(),
            cipher,
            &opts,
            TpmBootstrap::HybridPq(luksbox_pq::PqParams::Ml1024),
        )?,
        #[cfg(target_os = "linux")]
        12 => create_with_tpm_bootstrap(
            theme,
            &pb,
            header_path.as_deref(),
            cipher,
            &opts,
            TpmBootstrap::HybridPqFido2(luksbox_pq::PqParams::Ml768),
        )?,
        #[cfg(target_os = "linux")]
        13 => create_with_tpm_bootstrap(
            theme,
            &pb,
            header_path.as_deref(),
            cipher,
            &opts,
            TpmBootstrap::HybridPqFido2(luksbox_pq::PqParams::Ml1024),
        )?,
        #[cfg(target_os = "macos")]
        7 => create_with_sep_bootstrap(
            theme,
            &pb,
            header_path.as_deref(),
            cipher,
            &opts,
            SepBootstrap::Plain,
        )?,
        #[cfg(target_os = "macos")]
        8 => create_with_sep_bootstrap(
            theme,
            &pb,
            header_path.as_deref(),
            cipher,
            &opts,
            SepBootstrap::Biometric,
        )?,
        #[cfg(target_os = "macos")]
        9 => create_with_sep_bootstrap(
            theme,
            &pb,
            header_path.as_deref(),
            cipher,
            &opts,
            SepBootstrap::HybridPq(luksbox_pq::PqParams::Ml768),
        )?,
        #[cfg(target_os = "macos")]
        10 => create_with_sep_bootstrap(
            theme,
            &pb,
            header_path.as_deref(),
            cipher,
            &opts,
            SepBootstrap::HybridPq(luksbox_pq::PqParams::Ml1024),
        )?,
        #[cfg(target_os = "macos")]
        11 => create_with_sep_bootstrap(
            theme,
            &pb,
            header_path.as_deref(),
            cipher,
            &opts,
            SepBootstrap::Fused(crate::SepFactors::Fido2, None),
        )?,
        #[cfg(target_os = "macos")]
        12 => create_with_sep_bootstrap(
            theme,
            &pb,
            header_path.as_deref(),
            cipher,
            &opts,
            SepBootstrap::Fused(crate::SepFactors::Passphrase, None),
        )?,
        #[cfg(target_os = "macos")]
        13 => create_with_sep_bootstrap(
            theme,
            &pb,
            header_path.as_deref(),
            cipher,
            &opts,
            SepBootstrap::Fused(crate::SepFactors::Fido2Passphrase, None),
        )?,
        #[cfg(target_os = "macos")]
        14 => create_with_sep_bootstrap(
            theme,
            &pb,
            header_path.as_deref(),
            cipher,
            &opts,
            SepBootstrap::Fused(crate::SepFactors::Fido2, Some(luksbox_pq::PqParams::Ml768)),
        )?,
        #[cfg(target_os = "macos")]
        15 => create_with_sep_bootstrap(
            theme,
            &pb,
            header_path.as_deref(),
            cipher,
            &opts,
            SepBootstrap::Fused(crate::SepFactors::Fido2, Some(luksbox_pq::PqParams::Ml1024)),
        )?,
        #[cfg(target_os = "macos")]
        16 => create_with_sep_bootstrap(
            theme,
            &pb,
            header_path.as_deref(),
            cipher,
            &opts,
            SepBootstrap::Fused(
                crate::SepFactors::Passphrase,
                Some(luksbox_pq::PqParams::Ml768),
            ),
        )?,
        #[cfg(target_os = "macos")]
        17 => create_with_sep_bootstrap(
            theme,
            &pb,
            header_path.as_deref(),
            cipher,
            &opts,
            SepBootstrap::Fused(
                crate::SepFactors::Passphrase,
                Some(luksbox_pq::PqParams::Ml1024),
            ),
        )?,
        #[cfg(target_os = "macos")]
        18 => create_with_sep_bootstrap(
            theme,
            &pb,
            header_path.as_deref(),
            cipher,
            &opts,
            SepBootstrap::Fused(
                crate::SepFactors::Fido2Passphrase,
                Some(luksbox_pq::PqParams::Ml768),
            ),
        )?,
        #[cfg(target_os = "macos")]
        19 => create_with_sep_bootstrap(
            theme,
            &pb,
            header_path.as_deref(),
            cipher,
            &opts,
            SepBootstrap::Fused(
                crate::SepFactors::Fido2Passphrase,
                Some(luksbox_pq::PqParams::Ml1024),
            ),
        )?,
        _ => unreachable!(),
    }
    Ok(())
}

/// Probe for any connected FIDO2 authenticator. Returns Ok(()) if at
/// least one device is visible to libfido2 / webauthn, Err with a
/// friendly message if none. Used by the FIDO2-using create + enroll
/// flows to fail fast before the user has typed PINs / passphrases
/// that would then bounce off a NoDevices error from inside the
/// authenticator call several seconds later.
#[cfg(feature = "hardware")]
fn fido2_preflight() -> Result<()> {
    let devs = luksbox_fido2::HidAuthenticator::detect_all().unwrap_or_default();
    if devs.is_empty() {
        return Err(
            "No FIDO2 authenticator detected. Plug in your security key (any \
             CTAP2: YubiKey, Nitrokey, SoloKey, Token2, OnlyKey, etc.) or, on \
             Windows / supported macOS, enable the platform authenticator \
             (Windows Hello / Touch ID), then try again."
                .into(),
        );
    }
    Ok(())
}

#[cfg(not(feature = "hardware"))]
fn fido2_preflight() -> Result<()> {
    Err("FIDO2 hardware support not compiled in".into())
}

/// Which TPM keyslot kind to add after the bootstrap passphrase.
enum TpmBootstrap {
    Plain,
    Pin,
    Fido2,
    HybridPq(luksbox_pq::PqParams),
    HybridPqFido2(luksbox_pq::PqParams),
}

/// Which Secure Enclave keyslot kind to bootstrap a new vault with
/// (macOS create flow). Mirrors `TpmBootstrap`.
#[cfg(target_os = "macos")]
enum SepBootstrap {
    Plain,
    Biometric,
    HybridPq(luksbox_pq::PqParams),
    /// Fused SEP + FIDO2 / passphrase combinations, optionally hybrid
    /// (Some(params) = + ML-KEM). `factors` carries which extra
    /// secrets are bound.
    Fused(crate::SepFactors, Option<luksbox_pq::PqParams>),
}

/// Create a vault with a bootstrap passphrase, then immediately add
/// the chosen Secure Enclave slot. Mirrors `create_with_tpm_bootstrap`
/// (recovery-friendly default): a SEP slot can't be slot 0, so we
/// bootstrap with a passphrase, enroll the SEP slot, move it to slot
/// 0, and keep the passphrase as a backup unless explicitly revoked.
#[cfg(target_os = "macos")]
fn create_with_sep_bootstrap(
    theme: &ColorfulTheme,
    vault: &Path,
    header: Option<&Path>,
    cipher: CipherSuite,
    opts: &CreateOptions,
    kind: SepBootstrap,
) -> Result<()> {
    eprintln!(
        "WARNING: Secure Enclave keyslots only open on the Mac that sealed them.\n  \
         If the machine is lost or wiped, that slot is gone."
    );
    if !Confirm::with_theme(theme)
        .with_prompt("Continue with Secure Enclave-backed creation?")
        .default(true)
        .interact()?
    {
        return Ok(());
    }

    // Pre-flight: try to open the Secure Enclave BEFORE creating the
    // vault file, so a no-SEP failure surfaces without leaving a
    // half-built vault on disk.
    #[cfg(feature = "hardware")]
    {
        let probe = luksbox_sep::SepSealer::new();
        if let Err(e) = probe {
            return Err(format!(
                "Secure Enclave unavailable, refusing to create a SEP-bound vault \
                 that wouldn't have its primary keyslot:\n\n{e}"
            )
            .into());
        }
    }

    let pw = ask_new_passphrase(theme, "Backup passphrase")?;
    eprintln!("Stretching passphrase with Argon2id (around 500 ms)...");
    let mut cont = Container::create_with_passphrase_flags(
        vault,
        header,
        cipher,
        kdf_params(),
        opts.flags,
        pw.as_bytes(),
    )?;
    if let Some(ap) = &opts.anchor {
        cont.init_anchor(ap.clone(), 1)?;
        eprintln!("  anchor file initialized at {}", ap.display());
    }
    println!(
        "OK created {} (bootstrapping with backup passphrase; SEP keyslot will move to slot 0)",
        vault.display()
    );

    let vp = cont.vault_path().to_path_buf();
    let is_hybrid = matches!(
        kind,
        SepBootstrap::HybridPq(_) | SepBootstrap::Fused(_, Some(_))
    );
    let r = match kind {
        SepBootstrap::Plain => enroll_sep_into(theme, &mut cont, false),
        SepBootstrap::Biometric => enroll_sep_into(theme, &mut cont, true),
        SepBootstrap::HybridPq(p) => enroll_hybrid_pq_sep_into(theme, &mut cont, &vp, p),
        SepBootstrap::Fused(factors, params) => {
            enroll_sep_fused_into(theme, &mut cont, &vp, factors, params)
        }
    };
    if let Err(e) = r {
        // Atomic-create contract: roll back the bootstrap vault so we
        // don't leave a passphrase-only orphan when the SEP enroll
        // fails. Same shape as create_with_tpm_bootstrap.
        eprintln!("FAIL Secure Enclave enroll failed: {e}");
        eprintln!("  rolling back the bootstrap vault to leave no orphan files...");
        drop(cont);
        let _ = std::fs::remove_file(vault);
        if let Some(hp) = header {
            let _ = std::fs::remove_file(hp);
        }
        if let Some(ap) = &opts.anchor {
            let _ = std::fs::remove_file(ap);
        }
        let sidecar = luksbox_format::hybrid_sidecar::sidecar_path(vault);
        let _ = std::fs::remove_file(&sidecar);
        return Err(format!("vault create rolled back: {e}").into());
    }

    // Move the SEP slot to index 0 (mirrors the TPM bootstrap). The
    // bootstrap path made exactly one slot (passphrase at 0) and the
    // SEP enroll took the next Empty (1), so swapping (0, 1) is
    // unambiguous.
    cont.swap_slots(0, 1)
        .map_err(|e| format!("post-enroll swap_slots: {e}"))?;
    if is_hybrid {
        let sidecar = luksbox_format::hybrid_sidecar::sidecar_path(vault);
        if sidecar.exists()
            && let Ok(mut entries) = luksbox_format::hybrid_sidecar::read(&sidecar)
        {
            for e in &mut entries {
                if e.slot_idx == 1 {
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
    cont.persist_header()?;
    println!("OK moved Secure Enclave keyslot to slot 0 (backup passphrase now in slot 1)");

    if Confirm::with_theme(theme)
        .with_prompt("Revoke the backup passphrase now? (NOT recommended; loses the recovery path)")
        .default(false)
        .interact()?
    {
        cont.revoke_slot(1)?;
        cont.persist_header()?;
        println!("OK backup passphrase revoked. Vault is now Secure Enclave-only.");
    } else {
        println!("OK backup passphrase retained in slot 1 (recovery path preserved)");
    }

    maybe_mount_now(theme, cont, vault)
}

/// Create a vault with a bootstrap passphrase, then immediately add
/// the chosen TPM slot. The passphrase is kept as a backup unless the
/// user explicitly revokes it; this avoids the footgun where a
/// TPM-only vault becomes unrecoverable when the chip dies.
fn create_with_tpm_bootstrap(
    theme: &ColorfulTheme,
    vault: &Path,
    header: Option<&Path>,
    cipher: CipherSuite,
    opts: &CreateOptions,
    kind: TpmBootstrap,
) -> Result<()> {
    eprintln!(
        "WARNING: TPM-bound keyslots only open on the chip that sealed them.\n  \
         If the chip fails or you reinstall the OS, that slot is gone."
    );
    if !Confirm::with_theme(theme)
        .with_prompt("Continue with TPM-backed creation?")
        .default(true)
        .interact()?
    {
        return Ok(());
    }

    // Pre-flight: try to open a TPM context BEFORE we create the
    // vault file, so the common "no /dev/tpm0 access" failure mode
    // surfaces cleanly without leaving a half-built vault on disk.
    #[cfg(feature = "hardware")]
    {
        let probe = luksbox_tpm::Tpm2Sealer::new();
        if let Err(e) = probe {
            return Err(format!(
                "TPM 2.0 unavailable, refusing to create a TPM-bound vault that \
                 wouldn't have its primary keyslot:\n\n{e}"
            )
            .into());
        }
    }
    if matches!(kind, TpmBootstrap::Fido2 | TpmBootstrap::HybridPqFido2(_)) {
        fido2_preflight()?;
    }

    // Per-kind opt-in question. Defaults match the GUI:
    //  - Plain / Pin: default 2-slot (passphrase + TPM) for recovery.
    //     Skip checkbox = single TPM slot, no recovery if chip dies.
    //  - 3-factor combos: default single-slot (AND-semantics).
    //     Opt-in adds a recovery passphrase that becomes an OR-attack
    //     path against the combo.
    let single_slot = match kind {
        TpmBootstrap::Plain | TpmBootstrap::Pin => Confirm::with_theme(theme)
            .with_prompt(
                "Skip bootstrap passphrase? (single TPM slot, no recovery if chip dies; default: no)",
            )
            .default(false)
            .interact()?,
        TpmBootstrap::Fido2 | TpmBootstrap::HybridPq(_) | TpmBootstrap::HybridPqFido2(_) => {
            let add = Confirm::with_theme(theme)
                .with_prompt(
                    "Add a recovery passphrase? (defeats AND-semantics by introducing an OR-attack path; default: no)",
                )
                .default(false)
                .interact()?;
            !add
        }
    };

    if single_slot {
        return create_single_slot_tpm_vault(theme, vault, header, cipher, opts, kind);
    }

    let pw = ask_new_passphrase(theme, "Backup passphrase")?;
    eprintln!("Stretching passphrase with Argon2id (around 500 ms)...");
    let mut cont = Container::create_with_passphrase_flags(
        vault,
        header,
        cipher,
        kdf_params(),
        opts.flags,
        pw.as_bytes(),
    )?;
    if let Some(ap) = &opts.anchor {
        cont.init_anchor(ap.clone(), 1)?;
        eprintln!("  anchor file initialized at {}", ap.display());
    }
    println!(
        "OK created {} (bootstrapping with backup passphrase; TPM keyslot will move to slot 0)",
        vault.display()
    );

    let vp = cont.vault_path().to_path_buf();
    let r = match kind {
        TpmBootstrap::Plain => enroll_tpm2_into(theme, &mut cont),
        TpmBootstrap::Pin => enroll_tpm2_pin_into(theme, &mut cont),
        TpmBootstrap::Fido2 => enroll_tpm2_fido2_into(theme, &mut cont),
        TpmBootstrap::HybridPq(p) => enroll_hybrid_pq_tpm2_into(theme, &mut cont, &vp, p),
        TpmBootstrap::HybridPqFido2(p) => {
            enroll_hybrid_pq_tpm2_fido2_into(theme, &mut cont, &vp, p)
        }
    };
    if let Err(e) = r {
        // Atomic-create contract: if the TPM enroll fails after the
        // bootstrap-passphrase create, we DO NOT leave a passphrase-
        // only vault on disk. The user asked for a TPM-bound vault;
        // not getting that is a failure, not a soft fallback.
        eprintln!("FAIL TPM enroll failed: {e}");
        eprintln!("  rolling back the bootstrap vault to leave no orphan files...");
        // Drop the Container first to release the file lock + flush
        // any pending writes, THEN delete the file.
        drop(cont);
        let _ = std::fs::remove_file(vault);
        if let Some(hp) = header {
            let _ = std::fs::remove_file(hp);
        }
        if let Some(ap) = &opts.anchor {
            let _ = std::fs::remove_file(ap);
        }
        // The hybrid-PQ-TPM enroll helpers may have written a
        // .lbx.hybrid sidecar before failing; clean it up too.
        let sidecar = luksbox_format::hybrid_sidecar::sidecar_path(vault);
        let _ = std::fs::remove_file(&sidecar);
        return Err(format!("vault create rolled back: {e}").into());
    }

    // Move the TPM slot to index 0 so the slot list shows TPM as the
    // primary keyslot and the backup passphrase as a clearly-numbered
    // backup. The bootstrap path creates exactly one slot (passphrase
    // at index 0) and the TPM enroll picks the next Empty (index 1),
    // so swapping (0, 1) is unambiguous. Per-slot AAD doesn't include
    // slot index, so the swap leaves both wrapped MVKs valid.
    cont.swap_slots(0, 1)
        .map_err(|e| format!("post-enroll swap_slots: {e}"))?;
    // Hybrid-PQ TPM kinds also wrote a sidecar entry pointing at the
    // pre-swap index (1). Rewrite it to point at 0 so the unlock-time
    // `find()` still returns the right entry.
    if matches!(
        kind,
        TpmBootstrap::HybridPq(_) | TpmBootstrap::HybridPqFido2(_)
    ) {
        let sidecar = luksbox_format::hybrid_sidecar::sidecar_path(vault);
        if sidecar.exists()
            && let Ok(mut entries) = luksbox_format::hybrid_sidecar::read(&sidecar)
        {
            for e in &mut entries {
                if e.slot_idx == 1 {
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
    cont.persist_header()?;
    println!("OK moved TPM keyslot to slot 0 (backup passphrase now in slot 1)");

    if Confirm::with_theme(theme)
        .with_prompt("Revoke the backup passphrase now? (NOT recommended; loses the recovery path)")
        .default(false)
        .interact()?
    {
        cont.revoke_slot(1)?;
        cont.persist_header()?;
        println!("OK backup passphrase revoked. Vault is now TPM-only.");
    } else {
        println!("OK backup passphrase retained in slot 1 (recovery path preserved)");
    }

    maybe_mount_now(theme, cont, vault)
}

/// Build a TPM-backed vault with a SINGLE keyslot at index 0
/// carrying the requested multi-factor credential. No passphrase
/// fallback. Used when the user opts into the "Skip bootstrap
/// passphrase" path for Tpm2/Tpm2Pin, or stays on the default
/// (single-slot) path for the 3-factor combos. The lost-vault-
/// if-factor-lost trade-off is accepted by the user via the
/// confirm prompt in `create_with_tpm_bootstrap`.
#[cfg(all(feature = "hardware", target_os = "linux"))]
fn create_single_slot_tpm_vault(
    theme: &ColorfulTheme,
    vault: &Path,
    header: Option<&Path>,
    cipher: CipherSuite,
    opts: &CreateOptions,
    kind: TpmBootstrap,
) -> Result<()> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};
    use luksbox_tpm::Tpm2Sealer;
    use rand_core::{OsRng, RngCore};
    use zeroize::Zeroizing;

    let mut sealer = Tpm2Sealer::new().map_err(|e| format!("{e}"))?;

    // sidecars_on_disk records files we created BEFORE the Container
    // exists; rollback deletes them on any error.
    let mut sidecars_on_disk: Vec<std::path::PathBuf> = Vec::new();

    let cleanup = |sidecars: &[std::path::PathBuf]| {
        let _ = std::fs::remove_file(vault);
        if let Some(hp) = header {
            let _ = std::fs::remove_file(hp);
        }
        for sc in sidecars {
            let _ = std::fs::remove_file(sc);
        }
    };

    let cont_res: std::result::Result<Container, _> = match kind {
        TpmBootstrap::Plain => {
            let mut kek = Zeroizing::new([0u8; 32]);
            OsRng
                .try_fill_bytes(kek.as_mut_slice())
                .map_err(|e| format!("OS RNG: {e}"))?;
            eprintln!("sealing KEK under the local TPM 2.0...");
            let blob = sealer.seal(&kek).map_err(|e| format!("TPM seal: {e}"))?;
            Container::create_with_tpm2(vault, header, cipher, opts.flags, &kek, &blob.to_bytes())
        }
        TpmBootstrap::Pin => {
            let pin = ask_new_tpm_pin(theme)?;
            let mut kek = Zeroizing::new([0u8; 32]);
            OsRng
                .try_fill_bytes(kek.as_mut_slice())
                .map_err(|e| format!("OS RNG: {e}"))?;
            eprintln!("sealing KEK under the local TPM 2.0 with PIN-binding...");
            let blob = sealer
                .seal_with_pin(&kek, Some(pin.as_bytes()))
                .map_err(|e| format!("TPM seal: {e}"))?;
            Container::create_with_tpm2_pin(
                vault,
                header,
                cipher,
                opts.flags,
                &kek,
                &blob.to_bytes(),
            )
        }
        TpmBootstrap::Fido2 => {
            let pin = zeroize::Zeroizing::new(
                Password::with_theme(theme)
                    .with_prompt("FIDO2 PIN")
                    .interact()?,
            );
            let mut auth = crate::make_fido2_authenticator();
            let user_handle = random_user_handle()?;
            eprintln!("{}", crate::auth_prompt("register a new FIDO2 credential"));
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

            let mut hmac_salt = [0u8; 32];
            OsRng.fill_bytes(&mut hmac_salt);
            eprintln!("{}", crate::auth_prompt("again to derive the FIDO2 half"));
            let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(&pin))?;

            Container::create_with_tpm2_fido2(
                vault,
                header,
                cipher,
                opts.flags,
                &tpm_unsealed,
                &hmac_secret,
                &blob.to_bytes(),
                &cred_id,
                hmac_salt,
            )
        }
        TpmBootstrap::HybridPq(params) => {
            let level_label = match params {
                PqParams::Ml768 => "ML-KEM-768",
                PqParams::Ml1024 => "ML-KEM-1024",
            };
            eprintln!("Hybrid TPM 2.0 + {level_label} keyslot.");
            let kyber_path = ask_path(theme, "Path for the new Kyber seed (.kyber) file")?;
            if kyber_path.exists() {
                return Err(format!("{} already exists", kyber_path.display()).into());
            }
            let seed_pw = ask_new_passphrase(theme, "Seed-file passphrase")?;

            let mut tpm_kek = Zeroizing::new([0u8; 32]);
            OsRng
                .try_fill_bytes(tpm_kek.as_mut_slice())
                .map_err(|e| format!("OS RNG: {e}"))?;
            eprintln!("sealing TPM half under the local TPM 2.0...");
            let blob = sealer
                .seal(&tpm_kek)
                .map_err(|e| format!("TPM seal: {e}"))?;
            let (pk, seed) = keygen_with(params);
            let (ct, shared) = encapsulate_with(params, &pk)?;

            let res = if params == PqParams::Ml1024 {
                Container::create_with_hybrid_pq_1024_tpm2(
                    vault,
                    header,
                    cipher,
                    opts.flags,
                    &tpm_kek,
                    &shared,
                    &blob.to_bytes(),
                )
            } else {
                Container::create_with_hybrid_pq_tpm2(
                    vault,
                    header,
                    cipher,
                    opts.flags,
                    &tpm_kek,
                    &shared,
                    &blob.to_bytes(),
                )
            };
            if res.is_ok() {
                let sidecar = hybrid_sidecar::sidecar_path(vault);
                if let Err(e) = hybrid_sidecar::write(
                    &sidecar,
                    &[HybridEntry {
                        slot_idx: 0,
                        level: params,
                        pubkey: pk,
                        ciphertext: ct,
                    }],
                ) {
                    cleanup(&sidecars_on_disk);
                    return Err(format!("hybrid sidecar write: {e}").into());
                }
                sidecars_on_disk.push(sidecar);
                if let Err(e) = seed_file::write(
                    &kyber_path,
                    &seed,
                    seed_pw.as_bytes(),
                    seed_file::KdfParams::default(),
                ) {
                    cleanup(&sidecars_on_disk);
                    return Err(format!(".kyber write: {e}").into());
                }
            }
            res
        }
        TpmBootstrap::HybridPqFido2(params) => {
            let level_label = match params {
                PqParams::Ml768 => "ML-KEM-768",
                PqParams::Ml1024 => "ML-KEM-1024",
            };
            eprintln!("3-factor TPM 2.0 + FIDO2 + {level_label} keyslot.");
            let pin = zeroize::Zeroizing::new(
                Password::with_theme(theme)
                    .with_prompt("FIDO2 PIN")
                    .interact()?,
            );
            let kyber_path = ask_path(theme, "Path for the new Kyber seed (.kyber) file")?;
            if kyber_path.exists() {
                return Err(format!("{} already exists", kyber_path.display()).into());
            }
            let seed_pw = ask_new_passphrase(theme, "Seed-file passphrase")?;

            let mut auth = crate::make_fido2_authenticator();
            let user_handle = random_user_handle()?;
            eprintln!("{}", crate::auth_prompt("register a new FIDO2 credential"));
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

            let mut hmac_salt = [0u8; 32];
            OsRng.fill_bytes(&mut hmac_salt);
            eprintln!("{}", crate::auth_prompt("again to derive the FIDO2 half"));
            let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(&pin))?;

            let (pk, seed) = keygen_with(params);
            let (ct, shared) = encapsulate_with(params, &pk)?;

            let res = if params == PqParams::Ml1024 {
                Container::create_with_hybrid_pq_1024_tpm2_fido2(
                    vault,
                    header,
                    cipher,
                    opts.flags,
                    &tpm_unsealed,
                    &hmac_secret,
                    &shared,
                    &blob.to_bytes(),
                    &cred_id,
                    hmac_salt,
                )
            } else {
                Container::create_with_hybrid_pq_tpm2_fido2(
                    vault,
                    header,
                    cipher,
                    opts.flags,
                    &tpm_unsealed,
                    &hmac_secret,
                    &shared,
                    &blob.to_bytes(),
                    &cred_id,
                    hmac_salt,
                )
            };
            if res.is_ok() {
                let sidecar = hybrid_sidecar::sidecar_path(vault);
                if let Err(e) = hybrid_sidecar::write(
                    &sidecar,
                    &[HybridEntry {
                        slot_idx: 0,
                        level: params,
                        pubkey: pk,
                        ciphertext: ct,
                    }],
                ) {
                    cleanup(&sidecars_on_disk);
                    return Err(format!("hybrid sidecar write: {e}").into());
                }
                sidecars_on_disk.push(sidecar);
                if let Err(e) = seed_file::write(
                    &kyber_path,
                    &seed,
                    seed_pw.as_bytes(),
                    seed_file::KdfParams::default(),
                ) {
                    cleanup(&sidecars_on_disk);
                    return Err(format!(".kyber write: {e}").into());
                }
            }
            res
        }
    };

    let mut cont = match cont_res {
        Ok(c) => c,
        Err(e) => {
            cleanup(&sidecars_on_disk);
            return Err(format!("single-slot TPM vault create failed: {e}").into());
        }
    };

    if let Some(ap) = &opts.anchor {
        if let Err(e) = cont.init_anchor(ap.clone(), 1) {
            drop(cont);
            cleanup(&sidecars_on_disk);
            let _ = std::fs::remove_file(ap);
            return Err(format!("anchor init failed: {e}").into());
        }
        eprintln!("  anchor file initialized at {}", ap.display());
    }
    println!(
        "OK created {} (single-slot TPM vault; no recovery if any factor is lost)",
        vault.display()
    );
    maybe_mount_now(theme, cont, vault)
}

#[cfg(not(all(feature = "hardware", target_os = "linux")))]
fn create_single_slot_tpm_vault(
    _theme: &ColorfulTheme,
    _vault: &Path,
    _header: Option<&Path>,
    _cipher: CipherSuite,
    _opts: &CreateOptions,
    _kind: TpmBootstrap,
) -> Result<()> {
    Err("TPM 2.0 is Linux-only today; Windows TPM is tracked as a follow-up".into())
}

fn create_passphrase(
    theme: &ColorfulTheme,
    vault: &Path,
    header: Option<&Path>,
    cipher: CipherSuite,
    opts: &CreateOptions,
) -> Result<()> {
    let pw = ask_new_passphrase(theme, "Passphrase")?;
    eprintln!("Stretching passphrase with Argon2id (about 500 ms)...");
    let mut cont = Container::create_with_passphrase_flags(
        vault,
        header,
        cipher,
        kdf_params(),
        opts.flags,
        pw.as_bytes(),
    )?;
    if let Some(ap) = &opts.anchor {
        cont.init_anchor(ap.clone(), 1)?;
        eprintln!("  anchor file initialized at {}", ap.display());
    }
    println!("OK created {}", vault.display());
    // No post-creation FIDO2 nag: it fired even with no authenticator plugged
    // in (guaranteeing a confusing FAIL) and is redundant with the keyslot
    // manager. Add FIDO2 or any other keyslot later via
    // "Open an existing vault" -> "Manage keyslots".
    eprintln!("  add more keyslots later via \"Open an existing vault\" -> \"Manage keyslots\"");

    maybe_mount_now(theme, cont, vault)
}

fn create_fido2_wrap(
    theme: &ColorfulTheme,
    vault: &Path,
    header: Option<&Path>,
    cipher: CipherSuite,
    opts: &CreateOptions,
) -> Result<()> {
    #[cfg(not(feature = "hardware"))]
    {
        let _ = (theme, vault, header, cipher, opts);
        return Err("FIDO2 hardware support not compiled in".into());
    }
    #[cfg(feature = "hardware")]
    {
        use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
        use rand_core::{OsRng, RngCore};

        // Pre-flight: confirm an authenticator is reachable BEFORE
        // we ask for the PIN. Without this the user types the PIN
        // and then sees a libfido2 NoDevices error.
        fido2_preflight()?;
        let pin = zeroize::Zeroizing::new(
            Password::with_theme(theme)
                .with_prompt("FIDO2 PIN")
                .interact()?,
        );
        let mut auth = crate::make_fido2_authenticator();
        let user_handle = random_user_handle()?;

        eprintln!("{}", crate::auth_prompt("register a new credential"));
        let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
        let cred_id = er.credential.id;
        let mut hmac_salt = [0u8; 32];
        OsRng.fill_bytes(&mut hmac_salt);
        eprintln!(
            "{}",
            crate::auth_prompt("again to derive the keyslot secret")
        );
        let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(&pin))?;

        let mut cont = Container::create_with_fido2_flags(
            vault,
            header,
            cipher,
            kdf_params(),
            opts.flags,
            None,
            &hmac_secret,
            &cred_id,
            hmac_salt,
        )?;
        if let Some(ap) = &opts.anchor {
            cont.init_anchor(ap.clone(), 1)?;
            eprintln!("  anchor file initialized at {}", ap.display());
        }
        println!(
            "OK created {} with FIDO2 wrap-style keyslot",
            vault.display()
        );
        maybe_mount_now(theme, cont, vault)
    }
}

fn create_fido2_direct(
    theme: &ColorfulTheme,
    vault: &Path,
    header: Option<&Path>,
    cipher: CipherSuite,
    opts: &CreateOptions,
) -> Result<()> {
    #[cfg(not(feature = "hardware"))]
    {
        let _ = (theme, vault, header, cipher, opts);
        return Err("FIDO2 hardware support not compiled in".into());
    }
    #[cfg(feature = "hardware")]
    {
        use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
        use rand_core::{OsRng, RngCore};

        // Pre-flight before showing the long warning + PIN prompt.
        fido2_preflight()?;
        eprintln!(
            "WARNING: FIDO2-direct vault. The MVK is DERIVED from the authenticator's\n  \
             hmac-secret output and is NOT stored in the vault, there is no\n  \
             wrapped MVK to brute-force. Trade-off: this authenticator is the only\n  \
             thing that can derive the MVK, so losing it loses the vault.\n  \
             You can still enroll a passphrase/wrap-FIDO2 backup AFTER creation."
        );
        if !Confirm::with_theme(theme)
            .with_prompt("Proceed with FIDO2-direct?")
            .default(false)
            .interact()?
        {
            return Ok(());
        }

        let pin = zeroize::Zeroizing::new(
            Password::with_theme(theme)
                .with_prompt("FIDO2 PIN")
                .interact()?,
        );
        let mut auth = crate::make_fido2_authenticator();
        let user_handle = random_user_handle()?;

        eprintln!("{}", crate::auth_prompt("register a new credential"));
        let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
        let cred_id = er.credential.id;
        let mut hmac_salt = [0u8; 32];
        OsRng.fill_bytes(&mut hmac_salt);
        eprintln!("{}", crate::auth_prompt("again to derive the MVK"));
        let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(&pin))?;

        let mut cont = Container::create_with_fido2_derived_mvk(
            vault,
            header,
            cipher,
            &cred_id,
            &hmac_secret,
            hmac_salt,
        )?;
        if let Some(ap) = &opts.anchor {
            cont.init_anchor(ap.clone(), 1)?;
            eprintln!("  anchor file initialized at {}", ap.display());
        }
        println!("OK created {} (FIDO2-direct, MVK derived)", vault.display());

        if Confirm::with_theme(theme)
            .with_prompt(
                "Enroll a passphrase backup keyslot now? (adds an OR-attack path; default off)",
            )
            .default(false)
            .interact()?
        {
            let pw = ask_new_passphrase(theme, "Backup passphrase")?;
            eprintln!("Stretching with Argon2id (about 500 ms)...");
            let idx = cont.enroll_passphrase(pw.as_bytes(), kdf_params())?;
            cont.persist_header()?;
            println!("OK passphrase backup enrolled in slot {idx}");
        }

        maybe_mount_now(theme, cont, vault)
    }
}

fn create_hybrid_pq(
    theme: &ColorfulTheme,
    vault: &Path,
    header: Option<&Path>,
    cipher: CipherSuite,
    opts: &CreateOptions,
    params: luksbox_pq::PqParams,
) -> Result<()> {
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};

    let level_label = match params {
        PqParams::Ml768 => "ML-KEM-768",
        PqParams::Ml1024 => "ML-KEM-1024",
    };
    eprintln!(
        "Hybrid passphrase + {level_label} vault. The MVK wraps under\n  \
         HKDF(Argon2id(passphrase) || Kyber-shared-secret). Both the\n  \
         passphrase AND a separate Kyber seed file are required to\n  \
         open. The seed file should live on different trusted storage\n  \
         (USB stick, offline machine) than the .lbx itself,\n  \
         otherwise an attacker who steals the .lbx can also steals the\n  \
         seed and the post-quantum benefit is lost."
    );
    let kyber_path = ask_path(
        theme,
        &format!(
            "Path for the Kyber seed file (e.g. {})",
            usb_example("vault.kyber")
        ),
    )?;
    if kyber_path.exists() {
        return Err(format!("{} already exists", kyber_path.display()).into());
    }

    let pw = ask_new_passphrase(theme, "Passphrase")?;
    eprintln!("Generating {level_label} keypair...");
    let (pk, seed) = keygen_with(params);
    let (ct, shared) =
        encapsulate_with(params, &pk).map_err(|e| format!("ML-KEM encapsulate: {e}"))?;

    eprintln!("Stretching passphrase with Argon2id (about 500 ms)...");
    let mut cont = match params {
        PqParams::Ml768 => Container::create_with_hybrid_pq_passphrase(
            vault,
            header,
            cipher,
            kdf_params(),
            opts.flags,
            pw.as_bytes(),
            &shared,
        )?,
        PqParams::Ml1024 => Container::create_with_hybrid_pq_1024_passphrase(
            vault,
            header,
            cipher,
            kdf_params(),
            opts.flags,
            pw.as_bytes(),
            &shared,
        )?,
    };

    let sidecar = hybrid_sidecar::sidecar_path(vault);
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
        &kyber_path,
        &seed,
        pw.as_bytes(),
        seed_file::KdfParams::default(),
    )
    .map_err(|e| format!("write kyber seed: {e}"))?;

    if let Some(ap) = &opts.anchor {
        cont.init_anchor(ap.clone(), 1)?;
        eprintln!("  anchor file initialized at {}", ap.display());
    }
    println!("OK created {} (hybrid-pq, {level_label})", vault.display());
    eprintln!(
        "  hybrid sidecar (public Kyber blobs): {}",
        sidecar.display()
    );
    eprintln!(
        "  Kyber seed (KEEP THIS SAFE, MOVE TO SEPARATE STORAGE): {}",
        kyber_path.display()
    );

    maybe_mount_now(theme, cont, vault)
}

#[cfg(feature = "hardware")]
fn create_hybrid_pq_fido2(
    theme: &ColorfulTheme,
    vault: &Path,
    header: Option<&Path>,
    cipher: CipherSuite,
    opts: &CreateOptions,
    params: luksbox_pq::PqParams,
) -> Result<()> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};
    use rand_core::{OsRng, RngCore};

    fido2_preflight()?;

    let level_label = match params {
        PqParams::Ml768 => "ML-KEM-768",
        PqParams::Ml1024 => "ML-KEM-1024",
    };
    eprintln!(
        "Hybrid FIDO2 + {level_label} vault. The MVK wraps under\n  \
         HKDF(Argon2id-of(passphrase || hmac_secret) || Kyber-shared).\n  \
         Unlock requires: FIDO2 authenticator + a separate .kyber seed file + the\n  \
         seed-file passphrase. The .kyber file MUST be on different\n  \
         storage from the .lbx, that's the post-quantum part.\n  \
         Lose the authenticator OR the seed file = lose the vault."
    );
    let kyber_path = ask_path(
        theme,
        &format!(
            "Path for the Kyber seed file (e.g. {})",
            usb_example("vault.kyber")
        ),
    )?;
    if kyber_path.exists() {
        return Err(format!("{} already exists", kyber_path.display()).into());
    }

    let pin = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt("FIDO2 PIN")
            .interact()?,
    );
    eprintln!("Now choose a passphrase that encrypts the .kyber seed file at rest.");
    let seed_pw = ask_new_passphrase(theme, "Seed-file passphrase")?;

    let mut auth = crate::make_fido2_authenticator();
    let user_handle = random_user_handle()?;
    eprintln!("{}", crate::auth_prompt("register a new credential"));
    let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
    let cred_id = er.credential.id;
    let mut hmac_salt = [0u8; 32];
    OsRng.fill_bytes(&mut hmac_salt);
    eprintln!(
        "{}",
        crate::auth_prompt("again to derive the keyslot secret")
    );
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(&pin))?;

    eprintln!("Generating {level_label} keypair...");
    let (pk, kyber_seed) = keygen_with(params);
    let (ct, shared) =
        encapsulate_with(params, &pk).map_err(|e| format!("ML-KEM encapsulate: {e}"))?;

    eprintln!("Stretching with Argon2id (about 500 ms)...");
    let mut cont = match params {
        PqParams::Ml768 => Container::create_with_hybrid_pq_fido2(
            vault,
            header,
            cipher,
            kdf_params(),
            opts.flags,
            None,
            &hmac_secret,
            &shared,
            &cred_id,
            hmac_salt,
        )?,
        PqParams::Ml1024 => Container::create_with_hybrid_pq_1024_fido2(
            vault,
            header,
            cipher,
            kdf_params(),
            opts.flags,
            None,
            &hmac_secret,
            &shared,
            &cred_id,
            hmac_salt,
        )?,
    };

    let sidecar = hybrid_sidecar::sidecar_path(vault);
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
        &kyber_path,
        &kyber_seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    )
    .map_err(|e| format!("write kyber seed: {e}"))?;

    if let Some(ap) = &opts.anchor {
        cont.init_anchor(ap.clone(), 1)?;
        eprintln!("  anchor file initialized at {}", ap.display());
    }
    println!(
        "OK created {} (hybrid-pq-fido2, FIDO2 + {level_label})",
        vault.display()
    );
    eprintln!("  hybrid sidecar: {}", sidecar.display());
    eprintln!(
        "  Kyber seed (MOVE TO SEPARATE STORAGE): {}",
        kyber_path.display()
    );

    maybe_mount_now(theme, cont, vault)
}

#[cfg(not(feature = "hardware"))]
fn create_hybrid_pq_fido2(
    _theme: &ColorfulTheme,
    _vault: &Path,
    _header: Option<&Path>,
    _cipher: CipherSuite,
    _opts: &CreateOptions,
    _params: luksbox_pq::PqParams,
) -> Result<()> {
    Err("FIDO2 hardware support not compiled in".into())
}

fn maybe_mount_now(theme: &ColorfulTheme, cont: Container, vault: &Path) -> Result<()> {
    if Confirm::with_theme(theme)
        .with_prompt("Open and mount this vault now?")
        .default(false)
        .interact()?
    {
        let vfs = Vfs::open(cont)?;
        return mount_action(theme, vfs, vault);
    }
    Ok(())
}

// ---- open wizard -----------------------------------------------------------

fn open_wizard(theme: &ColorfulTheme) -> Result<()> {
    let vault = ask_path(theme, "Path to vault")?;
    let header_path = ask_detached_header(theme, false)?;

    let anchor_path = if Confirm::with_theme(theme)
        .with_prompt("Verify against a rollback-detection anchor sidecar?")
        .default(false)
        .interact()?
    {
        let p = ask_path(theme, "Path to the anchor sidecar")?;
        if !p.is_file() {
            return Err(format!("{} is not a file", p.display()).into());
        }
        Some(p)
    } else {
        None
    };

    let header = load_header(&vault, header_path.as_deref())?;
    let has_passphrase = header
        .keyslots
        .iter()
        .any(|s| s.kind == SlotKind::Passphrase);
    let has_fido2 = header.keyslots.iter().any(|s| {
        matches!(
            s.kind,
            SlotKind::Fido2HmacSecret | SlotKind::Fido2DerivedMvk
        )
    });
    // Hybrid PQ unlock is level-agnostic, the per-entry level byte in
    // the .hybrid sidecar is what `decapsulate_with` reads to pick the
    // right ML-KEM parameter set, so the menu has one entry per
    // shape (passphrase or fido2) regardless of 768 vs 1024.
    let has_hybrid_pq = header.keyslots.iter().any(|s| {
        matches!(
            s.kind,
            SlotKind::HybridPqKemPassphrase | SlotKind::HybridPqKem1024Passphrase
        )
    });
    let has_hybrid_pq_fido2 = header.keyslots.iter().any(|s| {
        matches!(
            s.kind,
            SlotKind::HybridPqKemFido2 | SlotKind::HybridPqKem1024Fido2
        )
    });
    // TPM kinds: Tpm2Sealed and Tpm2SealedPin both go through the
    // same `unlock_via_tpm2` helper (PIN slot is auto-detected and
    // prompted), so they share one menu entry.
    let has_tpm2 = header
        .keyslots
        .iter()
        .any(|s| matches!(s.kind, SlotKind::Tpm2Sealed | SlotKind::Tpm2SealedPin));
    let has_tpm2_fido2 = header
        .keyslots
        .iter()
        .any(|s| s.kind == SlotKind::Tpm2Fido2);
    let has_hybrid_pq_tpm2 = header.keyslots.iter().any(|s| {
        matches!(
            s.kind,
            SlotKind::HybridPqKemTpm2 | SlotKind::HybridPqKem1024Tpm2
        )
    });
    let has_hybrid_pq_tpm2_fido2 = header.keyslots.iter().any(|s| {
        matches!(
            s.kind,
            SlotKind::HybridPqKemTpm2Fido2 | SlotKind::HybridPqKem1024Tpm2Fido2
        )
    });
    // Secure Enclave kinds: plain + biometric share one unlock helper
    // (the SEP prompts for Touch ID on biometric slots); the two
    // hybrid SEP kinds share another. The fused FIDO2 / passphrase
    // SEP kinds collect their extra factors inside the unlock helper.
    // Mirrors the TPM grouping. `is_sep_fido2()` / `is_sep_passphrase()`
    // distinguish which factors a slot binds.
    let has_sep = header
        .keyslots
        .iter()
        .any(|s| s.kind.is_sep() && !s.kind.is_hybrid_pq() && !s.kind.is_sep_fido2());
    let has_sep_fido2 = header
        .keyslots
        .iter()
        .any(|s| s.kind.is_sep() && !s.kind.is_hybrid_pq() && s.kind.is_sep_fido2());
    let has_hybrid_pq_sep = header
        .keyslots
        .iter()
        .any(|s| s.kind.is_sep() && s.kind.is_hybrid_pq() && !s.kind.is_sep_fido2());
    let has_hybrid_pq_sep_fido2 = header
        .keyslots
        .iter()
        .any(|s| s.kind.is_sep() && s.kind.is_hybrid_pq() && s.kind.is_sep_fido2());

    // Auto-detect FIDO2 authenticator(s); prompt-on-multiple is
    // suppressed if the user already picked at wizard start (or
    // passed --fido2-device). Used to (a) annotate the menu with
    // which authenticator will be used and (b) default the pick to
    // a FIDO2-using method when a device is plugged in.
    let fido_device = select_fido2_device(theme);

    let mut options: Vec<&str> = Vec::new();
    if has_passphrase {
        options.push("Passphrase");
    }
    if has_fido2 {
        options.push("FIDO2 authenticator");
    }
    if has_hybrid_pq {
        options.push("Hybrid passphrase + ML-KEM (post-quantum)");
    }
    if has_hybrid_pq_fido2 {
        options.push("Hybrid FIDO2 + ML-KEM (post-quantum)");
    }
    // TPM unlock options only on Linux. The slot-detection vars above
    // stay live so the variable-binding compiles on all platforms; on
    // non-Linux the user just doesn't see the unreachable choices.
    #[cfg(target_os = "linux")]
    {
        if has_tpm2 {
            options.push("TPM 2.0 (this machine)");
        }
        if has_tpm2_fido2 {
            options.push("Fused TPM 2.0 + FIDO2");
        }
        if has_hybrid_pq_tpm2 {
            options.push("Hybrid TPM 2.0 + ML-KEM (2-factor)");
        }
        if has_hybrid_pq_tpm2_fido2 {
            options.push("Hybrid TPM 2.0 + FIDO2 + ML-KEM (3-factor)");
        }
    }
    // Secure Enclave unlock options only on macOS. The slot-detection
    // vars stay live on all platforms so the binding compiles; on
    // non-macOS the user just doesn't see the unreachable choices.
    #[cfg(target_os = "macos")]
    {
        if has_sep {
            options.push("Secure Enclave (this Mac)");
        }
        if has_sep_fido2 {
            options.push("Fused Secure Enclave + FIDO2");
        }
        if has_hybrid_pq_sep {
            options.push("Hybrid Secure Enclave + ML-KEM (2-factor)");
        }
        if has_hybrid_pq_sep_fido2 {
            options.push("Hybrid Secure Enclave + FIDO2 + ML-KEM");
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (
        has_sep,
        has_sep_fido2,
        has_hybrid_pq_sep,
        has_hybrid_pq_sep_fido2,
    );
    #[cfg(not(target_os = "linux"))]
    let _ = (
        has_tpm2,
        has_tpm2_fido2,
        has_hybrid_pq_tpm2,
        has_hybrid_pq_tpm2_fido2,
    );
    if options.is_empty() {
        return Err("vault has no usable keyslots".into());
    }
    // Pick the FIDO2-using method as default when a device is plugged
    // in AND the vault has a slot for it. Otherwise fall back to the
    // first available option (typically passphrase).
    let default_idx = if fido_device.is_some() {
        if let Some(i) = options
            .iter()
            .position(|o| *o == "Hybrid FIDO2 + ML-KEM (post-quantum)")
        {
            i
        } else {
            options
                .iter()
                .position(|o| *o == "FIDO2 authenticator")
                .unwrap_or_default()
        }
    } else {
        0
    };
    if let Some(label) = &fido_device {
        eprintln!("  FIDO2 authenticator available: {label}");
    } else if has_fido2 || has_hybrid_pq_fido2 {
        eprintln!(
            "  No FIDO2 authenticator detected, plug in your security key if you \
             want to use the FIDO2 unlock paths."
        );
    }
    let pick = if options.len() == 1 {
        0
    } else {
        Select::with_theme(theme)
            .with_prompt("How would you like to unlock?")
            .items(&options)
            .default(default_idx)
            .interact()?
    };

    let pick_label = options[pick];
    // Inline closure that runs the unlock-by-pick-label dispatch.
    // Used once at first open; re-invoked if Vfs::open trips the
    // metadata-deserialize path and the user opts into recovery mode
    // (re-authentication is required because the first Container was
    // consumed by the failed Vfs::open).
    let do_unlock = || -> Result<Container> {
        Ok(match pick_label {
            "Passphrase" => {
                let pw = zeroize::Zeroizing::new(
                    Password::with_theme(theme)
                        .with_prompt("Passphrase")
                        .interact()?,
                );
                Container::open(
                    &vault,
                    header_path.as_deref(),
                    UnlockMaterial::Passphrase(pw.as_bytes()),
                )?
            }
            "FIDO2 authenticator" => {
                unlock_via_fido2(theme, &vault, header_path.as_deref(), &header)?
            }
            "Hybrid passphrase + ML-KEM (post-quantum)" => {
                unlock_via_hybrid_pq(theme, &vault, header_path.as_deref())?
            }
            "Hybrid FIDO2 + ML-KEM (post-quantum)" => {
                unlock_via_hybrid_pq_fido2(theme, &vault, header_path.as_deref(), &header)?
            }
            "TPM 2.0 (this machine)" => {
                unlock_via_tpm2(theme, &vault, header_path.as_deref(), &header)?
            }
            "Fused TPM 2.0 + FIDO2" => {
                unlock_via_tpm2_fido2(theme, &vault, header_path.as_deref(), &header)?
            }
            "Hybrid TPM 2.0 + ML-KEM (2-factor)" => {
                unlock_via_hybrid_pq_tpm2(theme, &vault, header_path.as_deref(), &header)?
            }
            "Hybrid TPM 2.0 + FIDO2 + ML-KEM (3-factor)" => {
                unlock_via_hybrid_pq_tpm2_fido2(theme, &vault, header_path.as_deref(), &header)?
            }
            "Secure Enclave (this Mac)" => {
                unlock_via_sep(theme, &vault, header_path.as_deref(), &header)?
            }
            "Fused Secure Enclave + FIDO2" => {
                unlock_via_sep_fido2(theme, &vault, header_path.as_deref(), &header)?
            }
            "Hybrid Secure Enclave + ML-KEM (2-factor)" => {
                unlock_via_hybrid_pq_sep(theme, &vault, header_path.as_deref(), &header)?
            }
            "Hybrid Secure Enclave + FIDO2 + ML-KEM" => {
                unlock_via_hybrid_pq_sep_fido2(theme, &vault, header_path.as_deref(), &header)?
            }
            _ => unreachable!(),
        })
    };
    let mut cont = do_unlock()?;
    let trusted_anchor_gen = if let Some(ap) = anchor_path.as_deref() {
        cont.set_anchor(Some(ap.to_path_buf()))?
    } else {
        None
    };
    // Try the normal open. If the metadata-blob parse fails (the
    // v0.2.1 durability-hole symptom; see CHANGELOG v0.2.2), offer
    // the user a tolerant-recovery retry: re-authenticate, set the
    // thread-local toleration flag, install broken inodes as
    // 0-byte placeholders, mount the vault read-only, and print
    // the list of files that were lost.
    let mut tolerated_recovery_used = false;
    let vfs = match Vfs::open(cont) {
        Ok(v) => v,
        Err(luksbox_vfs::Error::MetadataDeserialize) => {
            eprintln!();
            eprintln!(
                "  WARN vault metadata parse failed -- the directory tree appears \
                 corrupt or partially overwritten."
            );
            eprintln!(
                "       This matches the v0.2.1 durability-hole symptom \
                 (fixed in v0.2.2; see CHANGELOG)."
            );
            eprintln!();
            let try_recovery = Confirm::with_theme(theme)
                .with_prompt(
                    "Try opening in recovery mode? (read-only, skips broken \
                     files, you can copy out what's readable; you'll need to \
                     re-authenticate)",
                )
                .default(true)
                .interact()?;
            if !try_recovery {
                return Err("metadata blob deserialization failed".into());
            }
            // Re-unlock since the previous Container was consumed.
            let mut cont2 = do_unlock()?;
            if let Some(ap) = anchor_path.as_deref() {
                cont2.set_anchor(Some(ap.to_path_buf()))?;
            }
            let _tolerate_guard = luksbox_vfs::set_tolerate_bad_chunk_lists(true);
            let v = Vfs::open(cont2)?;
            tolerated_recovery_used = true;
            v
        }
        Err(e) => return Err(e.into()),
    };
    if tolerated_recovery_used {
        let toll = vfs.tolerated_inodes();
        eprintln!();
        eprintln!(
            "  OK opened in recovery mode. {} broken file(s) installed as 0-byte placeholders:",
            toll.len()
        );
        for ti in toll {
            eprintln!(
                "    inode={} kind={:?} original_size={} path={}",
                ti.id, ti.kind, ti.original_size, ti.path
            );
            if !ti.reason.is_empty() {
                eprintln!("        reason: {}", ti.reason);
            }
        }
        eprintln!();
        eprintln!(
            "  Vault is mounted READ-ONLY. Use `luksbox get` or mount to copy out \
             the surviving files. Writes / flush are refused while in recovery mode."
        );
    }
    if let Some(anchor_gen) = trusted_anchor_gen {
        match anchor::compare(anchor_gen, vfs.vault_generation()) {
            anchor::VerificationOutcome::Ok => {
                eprintln!("  OK anchor matches vault (generation {anchor_gen})");
            }
            anchor::VerificationOutcome::RollbackDetected {
                anchor_gen,
                metadata_gen,
            } => {
                return Err(format!(
                    "ROLLBACK DETECTED: anchor reports vault generation {anchor_gen}, \
                     but the metadata in this .lbx is at generation {metadata_gen} (older). \
                     Refusing to open. If this is intentional (e.g. you restored from \
                     backup), delete and re-create the anchor."
                )
                .into());
            }
            anchor::VerificationOutcome::AnchorStale {
                anchor_gen,
                metadata_gen,
            } => {
                eprintln!(
                    "  warning: anchor at generation {anchor_gen}, vault metadata at {metadata_gen}.\n  \
                     The vault has been written without the anchor in place. The next write \
                     will refresh the anchor."
                );
            }
        }
    }
    println!("OK opened {}", vault.display());

    // Surface any pre-v0.3.0 FIDO2 keyslots and point at the
    // in-place migration command. This is the first place a user
    // running the wizard interactively encounters their vault's
    // keyslots after unlock, so it's the right moment to nudge
    // them toward fixing cross-platform compatibility before they
    // try to open the vault on Windows and hit a confusing
    // "keyslot authentication failed".
    let stale_fido2_slots: Vec<usize> = vfs
        .container()
        .header
        .keyslots
        .iter()
        .enumerate()
        .filter(|(_, s)| s.touches_fido2() && !s.fido2_salt_prehashed())
        .map(|(i, _)| i)
        .collect();
    if !stale_fido2_slots.is_empty() {
        eprintln!();
        eprintln!(
            "  Notice: {} FIDO2 keyslot(s) in this vault use the pre-v0.3.0 \
             wire convention (V1/V2/V3) and unlock only on Linux/macOS.",
            stale_fido2_slots.len()
        );
        eprintln!(
            "  To make them cross-platform (Linux + macOS + Windows), run on \
             Linux or macOS:"
        );
        for s in &stale_fido2_slots {
            eprintln!(
                "    luksbox migrate-fido2-slot {} --slot {s}",
                vault.display()
            );
        }
        eprintln!(
            "  This re-enrolls a fresh V4 credential under the same authenticator \
             and revokes the old slot in place."
        );
        eprintln!();
    }

    open_loop(theme, vfs, &vault)
}

// ---- info wizard -----------------------------------------------------------

fn info_wizard(theme: &ColorfulTheme) -> Result<()> {
    let path = ask_path(theme, "Path to vault or detached-header file")?;
    let header = load_header(&path, None)?;
    println!();
    println!("container: {}", path.display());
    println!("  cipher:        {:?}", header.cipher_suite);
    println!("  chunk size:    {} bytes", header.chunk_size);
    let detached = header.metadata_offset == 0;
    println!(
        "  layout:        {} (metadata at offset {}, data at {})",
        if detached {
            "DETACHED header"
        } else {
            "inline header"
        },
        header.metadata_offset,
        header.data_offset
    );
    print_slots(&header, true);
    Ok(())
}

// ---- post-open vault loop --------------------------------------------------

fn open_loop(theme: &ColorfulTheme, mut vfs: Vfs, vault: &Path) -> Result<()> {
    loop {
        let choice = Select::with_theme(theme)
            .with_prompt("Vault action")
            .items(&[
                "List a directory",
                "Cat a file (print to stdout)",
                "Copy a local file in",
                "Copy a file out to disk",
                "Make a directory",
                "Remove a file",
                "Remove a directory",
                "Rename a file or directory (same parent dir)",
                "Manage keyslots",
                "Rotate master volume key",
                "Mount as a filesystem",
                "PANIC: irreversibly destroy this vault",
                "Close vault",
            ])
            .default(0)
            .interact()?;
        let r: Result<()> = match choice {
            0 => list_action(theme, &mut vfs),
            1 => cat_action(theme, &mut vfs),
            2 => put_action(theme, &mut vfs),
            3 => get_action(theme, &mut vfs),
            4 => mkdir_action(theme, &mut vfs),
            5 => rm_action(theme, &mut vfs),
            6 => rmdir_action(theme, &mut vfs),
            7 => mv_action(theme, &mut vfs),
            8 => {
                vfs.flush()?;
                let cont = vfs.close()?;
                let cont = keyslot_loop(theme, cont)?;
                vfs = Vfs::open(cont)?;
                Ok(())
            }
            9 => {
                vfs.flush()?;
                let cont = vfs.close()?;
                let cont = rotate_mvk_action(theme, cont)?;
                vfs = Vfs::open(cont)?;
                Ok(())
            }
            10 => {
                vfs.flush()?;
                return mount_action(theme, vfs, vault);
            }
            11 => {
                vfs.flush()?;
                let cont = vfs.close()?;
                if panic_action(theme, cont, vault)? {
                    return Ok(());
                }
                return Err("vault was destroyed".into());
            }
            12 => {
                vfs.flush()?;
                return Ok(());
            }
            _ => unreachable!(),
        };
        if let Err(e) = r {
            eprintln!("FAIL {e}");
        }
    }
}

// ---- vault actions ---------------------------------------------------------

fn list_action(theme: &ColorfulTheme, vfs: &mut Vfs) -> Result<()> {
    let inner: String = Input::with_theme(theme)
        .with_prompt("Directory to list")
        .with_initial_text("/")
        .interact_text()?;
    let id = vfs.lookup_path(&inner)?;
    if vfs.stat(id)?.kind != InodeKind::Directory {
        return Err(format!("{inner} is not a directory").into());
    }
    let mut entries = vfs.readdir(id)?;
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    if entries.is_empty() {
        println!("  (empty)");
    }
    for e in entries {
        let s = vfs.stat(e.id)?;
        let kind = if e.kind == InodeKind::Directory {
            "d"
        } else {
            "-"
        };
        println!("  {} {:>10} {}", kind, s.size, e.name);
    }
    Ok(())
}

fn cat_action(theme: &ColorfulTheme, vfs: &mut Vfs) -> Result<()> {
    let inner: String = Input::with_theme(theme)
        .with_prompt("File to print")
        .interact_text()?;
    let id = vfs.lookup_path(&inner)?;
    if vfs.stat(id)?.kind != InodeKind::File {
        return Err(format!("{inner} is not a file").into());
    }
    let stdout = std::io::stdout();
    let mut h = stdout.lock();
    copy_out(vfs, id, &mut h)?;
    println!();
    Ok(())
}

fn put_action(theme: &ColorfulTheme, vfs: &mut Vfs) -> Result<()> {
    let local = ask_path(theme, "Local file path")?;
    if !local.is_file() {
        return Err(format!("{} is not a regular file", local.display()).into());
    }
    let inner: String = Input::with_theme(theme)
        .with_prompt("Destination inside vault (e.g. /docs/notes.txt)")
        .interact_text()?;
    let (parent, name) = split_parent_name(vfs, &inner)?;
    if vfs.lookup(parent, &name).is_ok() {
        return Err(format!("{inner} already exists in vault").into());
    }
    let f = vfs.create(parent, &name)?;
    let mut src = File::open(&local)?;
    let n = copy_into(vfs, f, &mut src)?;
    vfs.flush()?;
    println!("OK wrote {n} bytes to {inner}");
    Ok(())
}

fn get_action(theme: &ColorfulTheme, vfs: &mut Vfs) -> Result<()> {
    let inner: String = Input::with_theme(theme)
        .with_prompt("File inside vault to extract")
        .interact_text()?;
    let local = ask_path(theme, "Destination on local disk")?;
    let id = vfs.lookup_path(&inner)?;
    if vfs.stat(id)?.kind != InodeKind::File {
        return Err(format!("{inner} is not a file").into());
    }
    // Mode 0600 - see cmd_get in main.rs for rationale.
    let mut dst = luksbox_core::file_util::secure_create_or_truncate(&local)?;
    let n = copy_out(vfs, id, &mut dst)?;
    println!("OK wrote {n} bytes to {}", local.display());
    Ok(())
}

fn mkdir_action(theme: &ColorfulTheme, vfs: &mut Vfs) -> Result<()> {
    let inner: String = Input::with_theme(theme)
        .with_prompt("Directory path inside vault")
        .interact_text()?;
    let (parent, name) = split_parent_name(vfs, &inner)?;
    vfs.mkdir(parent, &name)?;
    vfs.flush()?;
    println!("OK created {inner}");
    Ok(())
}

fn rm_action(theme: &ColorfulTheme, vfs: &mut Vfs) -> Result<()> {
    let inner: String = Input::with_theme(theme)
        .with_prompt("File to remove")
        .interact_text()?;
    if !Confirm::with_theme(theme)
        .with_prompt(format!("Remove {inner}?"))
        .default(false)
        .interact()?
    {
        return Ok(());
    }
    let (parent, name) = split_parent_name(vfs, &inner)?;
    vfs.unlink(parent, &name)?;
    vfs.flush()?;
    println!("OK removed {inner}");
    Ok(())
}

fn rmdir_action(theme: &ColorfulTheme, vfs: &mut Vfs) -> Result<()> {
    let inner: String = Input::with_theme(theme)
        .with_prompt("Empty directory to remove")
        .interact_text()?;
    let (parent, name) = split_parent_name(vfs, &inner)?;
    vfs.rmdir(parent, &name)?;
    vfs.flush()?;
    println!("OK removed {inner}");
    Ok(())
}

fn mv_action(theme: &ColorfulTheme, vfs: &mut Vfs) -> Result<()> {
    let old: String = Input::with_theme(theme)
        .with_prompt("Existing path inside vault")
        .interact_text()?;
    let new: String = Input::with_theme(theme)
        .with_prompt("New path (same dir or any other dir inside the vault)")
        .interact_text()?;
    let (old_parent, old_name) = split_parent_name(vfs, &old)?;
    let (new_parent, new_name) = split_parent_name(vfs, &new)?;
    vfs.rename(old_parent, &old_name, new_parent, &new_name)?;
    vfs.flush()?;
    println!("OK renamed {old} -> {new}");
    Ok(())
}

fn mount_action(theme: &ColorfulTheme, vfs: Vfs, vault: &Path) -> Result<()> {
    let mp = ask_mountpoint(theme, vault)?;
    #[cfg(not(target_os = "windows"))]
    {
        if !mp.is_dir() {
            return Err(format!("{} is not a directory", mp.display()).into());
        }
    }
    let daemonize = if cfg!(target_os = "windows") {
        // WinFsp's mount lifetime is tied to the holding process; no
        // daemonize path on Windows.
        false
    } else {
        Confirm::with_theme(theme)
            .with_prompt("Mount in background (recommended)?")
            .default(true)
            .interact()?
    };
    #[cfg(not(target_os = "windows"))]
    let mp_abs = mp.canonicalize()?;
    #[cfg(target_os = "windows")]
    let mp_abs = mp.clone();
    if !daemonize {
        eprintln!(
            "mounted {} at {} (foreground)\n  unmount: luksbox umount {}  (or Ctrl-C, clean either way)",
            vault.display(),
            mp_abs.display(),
            mp_abs.display(),
        );
    }
    // Eager-flush opt-in. Same prompt + default as the open-and-mount
    // path above; see the comment there for the trade-off rationale.
    let sync_mode = Confirm::with_theme(theme)
        .with_prompt(
            "Eager flush? (every metadata op crash-durable on return; SLOW on \
             vaults with thousands of files -- default is no)",
        )
        .default(false)
        .interact()?;
    luksbox_mount::mount(vfs, &mp_abs, daemonize, sync_mode)?;
    Ok(())
}

// ---- rotate-mvk + panic ----------------------------------------------------

/// Public entry point so `cmd_rotate_mvk` in main.rs can call the
/// wizard's interactive rotation flow (multi-slot credential
/// collection + crash-safe rotate). The wizard menu also calls this
/// (under its previous name `rotate_mvk_action`).
pub(crate) fn run_rotate_mvk_interactive(
    theme: &ColorfulTheme,
    cont: Container,
) -> Result<Container> {
    rotate_mvk_action(theme, cont)
}

fn rotate_mvk_action(theme: &ColorfulTheme, cont: Container) -> Result<Container> {
    // Deniable vaults have no enumerable slots in `header.keyslots`
    // (synthetic header with all Empty entries); their slot envelopes
    // live in `self.deniable.bytes` and rotation goes through the
    // deniable-specific path. Dispatch here so the standard-slot
    // walker below doesn't silently no-op on deniable vaults.
    if cont.is_deniable() {
        return rotate_mvk_deniable_action(theme, cont);
    }
    for (i, s) in cont.header.keyslots.iter().enumerate() {
        if s.kind == SlotKind::Fido2DerivedMvk {
            return Err(format!(
                "slot {i} is fido2-direct; the MVK is derived from the authenticator itself \
                 and can't be rotated. Revoke the slot first or recreate the vault."
            )
            .into());
        }
    }
    let populated: Vec<(usize, SlotKind)> = (0..MAX_KEYSLOTS)
        .filter_map(|i| {
            let k = cont.header.keyslots[i].kind;
            if k != SlotKind::Empty {
                Some((i, k))
            } else {
                None
            }
        })
        .collect();
    let crash_safe = cont.supports_atomic_rotation();
    let safety_msg = if crash_safe {
        "Crash-safe (inline header): re-encrypted bytes go to a <vault>.rotating temp \
         file that is fsync'd and atomically renamed over the original at commit. \
         A crash before commit leaves the original intact."
    } else {
        "NOT crash-safe (detached-header mode): a crash mid-rotation may leave the \
         vault inconsistent. BACK UP THE HEADER SIDECAR AND VAULT FIRST."
    };
    eprintln!(
        "About to rotate the master volume key.\n  \
         This re-encrypts every chunk in the vault, O(N) time + disk I/O.\n  \
         {} populated keyslot(s) will each be re-authenticated and rebuilt under \
         fresh randomness.\n  \
         {}",
        populated.len(),
        safety_msg,
    );
    if !Confirm::with_theme(theme)
        .with_prompt("Proceed with MVK rotation?")
        .default(false)
        .interact()?
    {
        return Ok(cont);
    }

    let mut credentials: Vec<SlotCredential> = Vec::with_capacity(populated.len());
    for (idx, kind) in &populated {
        eprintln!();
        eprintln!("--- slot {idx} ({kind:?}) ---");
        let cred = match kind {
            SlotKind::Passphrase => {
                let pp = zeroize::Zeroizing::new(
                    Password::with_theme(theme)
                        .with_prompt(format!("passphrase for slot {idx}"))
                        .interact()?,
                );
                SlotCredential::Passphrase {
                    slot_idx: *idx,
                    passphrase: pp,
                }
            }
            SlotKind::Fido2HmacSecret => collect_fido2_credential_for_rotate(theme, &cont, *idx)?,
            SlotKind::Fido2DerivedMvk => unreachable!("rejected above"),
            SlotKind::HybridPqKemPassphrase
            | SlotKind::HybridPqKemFido2
            | SlotKind::HybridPqKem1024Passphrase
            | SlotKind::HybridPqKem1024Fido2 => {
                return Err(format!(
                    "slot {idx} is hybrid-pq; rotation of hybrid slots is not yet \
                     supported (would need to re-encapsulate against the same Kyber \
                     keypair). Revoke the slot first or recreate the vault."
                )
                .into());
            }
            SlotKind::Tpm2Sealed
            | SlotKind::Tpm2Fido2
            | SlotKind::Tpm2SealedPin
            | SlotKind::HybridPqKemTpm2
            | SlotKind::HybridPqKemTpm2Fido2
            | SlotKind::HybridPqKem1024Tpm2
            | SlotKind::HybridPqKem1024Tpm2Fido2 => {
                return Err(format!(
                    "slot {idx} is TPM-bound; rotation of TPM slots isn't supported \
                     by the wizard yet. Workaround: `luksbox revoke <vault> --slot \
                     {idx}` then re-enroll with the matching `--kind`."
                )
                .into());
            }
            SlotKind::SepSealed
            | SlotKind::SepSealedBiometric
            | SlotKind::HybridPqKemSep
            | SlotKind::HybridPqKem1024Sep
            | SlotKind::SepFido2
            | SlotKind::HybridPqKemSepFido2
            | SlotKind::HybridPqKem1024SepFido2
            | SlotKind::SepPassphrase
            | SlotKind::HybridPqKemSepPassphrase
            | SlotKind::HybridPqKem1024SepPassphrase
            | SlotKind::SepFido2Passphrase
            | SlotKind::HybridPqKemSepFido2Passphrase
            | SlotKind::HybridPqKem1024SepFido2Passphrase => {
                return Err(format!(
                    "slot {idx} is Secure Enclave-bound; rotation of SEP slots isn't \
                     supported by the wizard yet. Workaround: `luksbox revoke <vault> \
                     --slot {idx}` then re-enroll."
                )
                .into());
            }
            SlotKind::Empty => unreachable!(),
        };
        credentials.push(cred);
    }

    let mut vfs = Vfs::open(cont)?;
    eprintln!();
    eprintln!("rotating...");
    vfs.rotate_mvk(credentials, kdf_params())?;
    vfs.flush()?;
    println!(
        "OK MVK rotated. {} keyslot(s) rebuilt with fresh salts.",
        populated.len()
    );
    let cont = vfs.close()?;
    Ok(cont)
}

/// Deniable counterpart to `rotate_mvk_action`. Dispatched when the
/// container is deniable. v1 supports passphrase-only deniable slots
/// (the most common deniable setup). The user must remember the
/// Argon2 params they used at create time -- those aren't persisted
/// anywhere on disk for deniable vaults (the format requires every
/// byte to look random; storing the KDF params would be a beacon).
fn rotate_mvk_deniable_action(theme: &ColorfulTheme, cont: Container) -> Result<Container> {
    use luksbox_format::deniable_header::DeniableMaterial;
    use luksbox_vfs::{DeniableRotationCredential, Vfs};

    let slot_idx = cont.deniable_unlocked_slot().ok_or(
        "container is deniable but no unlocked-slot index is set; cannot identify \
         which slot to rotate. Re-open the vault via the deniable open path.",
    )?;

    eprintln!(
        "About to rotate the master volume key on this deniable vault.\n  \
         This re-encrypts every chunk, every chunk-list block (v3), and the\n  \
         metadata blob under a freshly-generated MVK + per-vault salt; the\n  \
         slot envelope at index {slot_idx} (the one your credentials unlocked)\n  \
         is rebuilt under fresh randomness. v1 of this flow supports\n  \
         passphrase-only deniable slots; for FIDO2 / TPM / hybrid deniable\n  \
         slots see the project roadmap.\n  \
         Crash-safety: inline-header vault uses the .rotating temp-file\n  \
         pattern; a crash before commit leaves the original intact."
    );

    if !Confirm::with_theme(theme)
        .with_prompt("Proceed with deniable MVK rotation?")
        .default(false)
        .interact()?
    {
        return Ok(cont);
    }

    // The Argon2 params + cipher are not persisted; user must remember.
    // The cipher we CAN recover from cont.header.cipher_suite (synthesized
    // from the inner header at open time), but the Argon2 params are
    // gone -- ask. Re-using the wizard's existing deniable KDF picker.
    let argon2_params = ask_den_kdf(theme, "Argon2id params used at create time")?;
    let pp = zeroize::Zeroizing::new(
        dialoguer::Password::with_theme(theme)
            .with_prompt(format!(
                "passphrase for the unlocked deniable slot (slot {slot_idx})"
            ))
            .interact()?,
    );

    let creds = vec![DeniableRotationCredential {
        slot_idx,
        kind: luksbox_core::deniable::DeniableKindTag::Passphrase,
        passphrase: zeroize::Zeroizing::new(pp.as_bytes().to_vec()),
        argon2: argon2_params,
        material: DeniableMaterial::passphrase_only(),
        hmac_secret_output: None,
        unsealed: None,
        mlkem_shared: None,
    }];

    let mut vfs = Vfs::open(cont)?;
    eprintln!();
    eprintln!("rotating deniable vault...");
    vfs.rotate_mvk_deniable(creds)?;
    println!("OK deniable MVK rotated. Slot envelope at index {slot_idx} rebuilt.");
    let cont = vfs.close()?;
    Ok(cont)
}

#[cfg(feature = "hardware")]
fn collect_fido2_credential_for_rotate(
    theme: &ColorfulTheme,
    cont: &Container,
    slot_idx: usize,
) -> Result<SlotCredential> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID};
    use rand_core::{OsRng, RngCore};

    let pin = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt("FIDO2 PIN")
            .interact()?,
    );
    let slot = &cont.header.keyslots[slot_idx];
    let cred_id = slot.fido2_cred_id.clone();
    let mut auth = crate::make_fido2_authenticator();

    eprintln!("{}", crate::auth_prompt(&format!("verify slot {slot_idx}")));
    // Verifying the OLD slot uses the slot's own convention; the new
    // wrap derivation that follows is treated as a fresh enrollment
    // and writes the V4 convention.
    let old = auth.hmac_secret(
        RP_ID,
        &cred_id,
        &slot.fido2_hmac_salt,
        slot.fido2_salt_prehashed(),
        Some(&pin),
    )?;

    let mut new_hmac_salt = [0u8; 32];
    OsRng.fill_bytes(&mut new_hmac_salt);
    eprintln!(
        "{}",
        crate::auth_prompt("again to derive the new wrap secret")
    );
    let new = auth.hmac_secret(RP_ID, &cred_id, &new_hmac_salt, true, Some(&pin))?;

    Ok(SlotCredential::Fido2Wrap {
        slot_idx,
        passphrase: None,
        hmac_secret_for_verify: zeroize::Zeroizing::new(*old),
        hmac_secret_for_new_wrap: zeroize::Zeroizing::new(*new),
        cred_id,
        new_hmac_salt,
    })
}

#[cfg(not(feature = "hardware"))]
fn collect_fido2_credential_for_rotate(
    _theme: &ColorfulTheme,
    _cont: &Container,
    _slot_idx: usize,
) -> Result<SlotCredential> {
    Err("FIDO2 hardware support not compiled in".into())
}

/// Returns Ok(true) if the vault was destroyed (caller must not reopen),
/// Ok(false) if the user backed out (caller can reopen the container).
fn panic_action(theme: &ColorfulTheme, cont: Container, vault: &Path) -> Result<bool> {
    let header_target = cont.header_storage_path().to_path_buf();
    let inline = header_target.as_path() == vault;
    drop(cont);

    eprintln!(
        "PANIC: about to overwrite the {} of {} with random bytes.",
        if inline {
            "first 8 KB"
        } else {
            "header sidecar"
        },
        header_target.display(),
    );
    let wipe_data = Confirm::with_theme(theme)
        .with_prompt("ALSO overwrite the entire vault data area? (slow; recommended on SSD only as last resort, see SECURITY.md)")
        .default(false)
        .interact()?;
    eprintln!("This is IRREVERSIBLE. There is NO undo. There is NO recovery.");
    let expected = format!("DESTROY {}", vault.display());
    let typed: String = Input::with_theme(theme)
        .with_prompt(format!("Type literally `{expected}` to confirm"))
        .allow_empty(true)
        .interact_text()?;
    if typed != expected {
        eprintln!("aborted (confirmation string did not match)");
        return Ok(false);
    }

    use rand_core::{OsRng, RngCore};
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom, Write};

    let mut hf = OpenOptions::new().write(true).open(&header_target)?;
    let mut buf = [0u8; HEADER_SIZE];
    OsRng.fill_bytes(&mut buf);
    hf.seek(SeekFrom::Start(0))?;
    hf.write_all(&buf)?;
    hf.flush()?;
    eprintln!(
        "OK header at {} overwritten with random",
        header_target.display()
    );

    if wipe_data {
        let mut vf = OpenOptions::new().write(true).open(vault)?;
        let len = std::fs::metadata(vault)?.len();
        vf.seek(SeekFrom::Start(0))?;
        let mut chunk = vec![0u8; 1 << 20];
        let mut written = 0u64;
        while written < len {
            OsRng.fill_bytes(&mut chunk);
            let to_write = ((len - written) as usize).min(chunk.len());
            vf.write_all(&chunk[..to_write])?;
            written += to_write as u64;
        }
        vf.flush()?;
        let _ = vf.sync_all();
        eprintln!(
            "OK vault file at {} ({} bytes) wiped\n  \
             Note: on SSDs and copy-on-write filesystems, logical overwrite does \
             not guarantee physical destruction.",
            vault.display(),
            len,
        );
    }
    println!("done.");
    Ok(true)
}

// ---- keyslot management ----------------------------------------------------

fn keyslot_loop(theme: &ColorfulTheme, mut cont: Container) -> Result<Container> {
    loop {
        println!();
        println!("Current keyslots:");
        for (i, s) in cont.header.keyslots.iter().enumerate() {
            println!("{}", format_slot(i, s, false));
        }
        println!();

        // TPM-bound add options only on Linux. The four pure-PQ
        // (passphrase|FIDO2) + ML-KEM-768|1024 options are
        // available on every platform: they need no TPM and the
        // FIDO2 ones go through whichever CTAP2 stack the build
        // provides (libfido2 on Linux/macOS, webauthn.dll on
        // Windows). Build the menu list dynamically and remap the
        // choice index back to fixed action numbers so the match
        // arms below stay stable.
        let mut menu: Vec<&'static str> = vec![
            "Add a passphrase keyslot",
            "Add a FIDO2 keyslot (wrap-style)",
            "Add a passphrase + ML-KEM-768 keyslot",
            "Add a passphrase + ML-KEM-1024 keyslot",
            "Add a FIDO2 + ML-KEM-768 keyslot",
            "Add a FIDO2 + ML-KEM-1024 keyslot",
        ];
        #[cfg(target_os = "linux")]
        {
            menu.extend_from_slice(&[
                "Add a TPM 2.0 keyslot (this machine, no PIN)",
                "Add a TPM 2.0 + PIN keyslot",
                "Add a fused TPM 2.0 + FIDO2 keyslot (both required)",
                "Add a hybrid TPM 2.0 + ML-KEM-768 keyslot",
                "Add a hybrid TPM 2.0 + ML-KEM-1024 keyslot",
                "Add a 3-factor TPM 2.0 + FIDO2 + ML-KEM-768 keyslot",
                "Add a 3-factor TPM 2.0 + FIDO2 + ML-KEM-1024 keyslot",
            ]);
        }
        #[cfg(target_os = "macos")]
        {
            menu.extend_from_slice(&[
                "Add a Secure Enclave keyslot (this Mac)",
                "Add a Secure Enclave + Touch ID keyslot",
                "Add a hybrid Secure Enclave + ML-KEM-768 keyslot",
                "Add a hybrid Secure Enclave + ML-KEM-1024 keyslot",
                "Add a fused Secure Enclave + FIDO2 keyslot (both required)",
                "Add a fused Secure Enclave + passphrase keyslot",
                "Add a fused Secure Enclave + FIDO2 + passphrase keyslot (3-factor)",
                "Add a hybrid Secure Enclave + FIDO2 + ML-KEM-768 keyslot",
                "Add a hybrid Secure Enclave + FIDO2 + ML-KEM-1024 keyslot",
                "Add a hybrid Secure Enclave + passphrase + ML-KEM-768 keyslot",
                "Add a hybrid Secure Enclave + passphrase + ML-KEM-1024 keyslot",
                "Add a hybrid Secure Enclave + FIDO2 + passphrase + ML-KEM-768 keyslot (4-factor)",
                "Add a hybrid Secure Enclave + FIDO2 + passphrase + ML-KEM-1024 keyslot (4-factor)",
            ]);
        }
        menu.extend_from_slice(&[
            "Update an existing keyslot's secret in place",
            "Revoke a keyslot",
            "Back to vault menu",
        ]);
        let choice = Select::with_theme(theme)
            .with_prompt("Keyslot action")
            .items(&menu)
            .default(0)
            .interact()?;

        // Action-number mapping. Menu choices 0..=5 are always the
        // six "no TPM needed" rows (passphrase, FIDO2, and the four
        // pure-PQ variants). On Linux choices 6..=12 are the TPM
        // combos and choices 13..=15 are update/revoke/back. On
        // non-Linux the TPM block is absent so update/revoke/back
        // come right after the PQ rows (choices 6..=8). Remap to
        // stable action numbers:
        //   0..=1  -> Passphrase / FIDO2
        //   2..=5  -> pure-PQ (passphrase|FIDO2 x 768|1024)
        //   6..=12 -> TPM combos (linux only)
        //   13     -> update
        //   14     -> revoke
        //   15     -> back
        #[cfg(target_os = "linux")]
        let action = match choice {
            0..=12 => choice,
            13..=15 => choice,
            _ => unreachable!(),
        };
        // macOS: choices 0..=5 are the PQ rows, 6..=9 are the four
        // base Secure Enclave rows (remapped to actions 16..=19),
        // 10..=18 are the nine fused SEP rows (remapped to actions
        // 20..=28), then 19/20/21 are update/revoke/back.
        #[cfg(target_os = "macos")]
        let action = match choice {
            0..=5 => choice,
            6 => 16,
            7 => 17,
            8 => 18,
            9 => 19,
            10..=18 => choice + 10, // 10->20 .. 18->28
            19 => 13,
            20 => 14,
            21 => 15,
            _ => unreachable!(),
        };
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let action = match choice {
            0..=5 => choice,
            6 => 13,
            7 => 14,
            8 => 15,
            _ => unreachable!(),
        };

        let r: Result<()> = match action {
            0 => {
                // Deniable vaults have no visible slot table; the
                // admin must pick a target index explicitly so they
                // don't overwrite another user's slot. Standard
                // vaults auto-pick first-free.
                if cont.is_deniable() {
                    let slot_idx = ask_deniable_slot_idx(theme, &cont)?;
                    let pw = ask_new_passphrase(theme, "New passphrase")?;
                    let kdf = ask_kdf_strength(theme, "Argon2id strength", 0)?;
                    eprintln!("Stretching with Argon2id...");
                    let idx = cont.enroll_passphrase_deniable(slot_idx, pw.as_bytes(), kdf)?;
                    cont.persist_header()?;
                    println!("OK enrolled passphrase in slot {idx}");
                    Ok(())
                } else {
                    let pw = ask_new_passphrase(theme, "New passphrase")?;
                    let kdf = ask_kdf_strength(theme, "Argon2id strength", 0)?;
                    eprintln!("Stretching with Argon2id...");
                    let idx = cont.enroll_passphrase(pw.as_bytes(), kdf)?;
                    cont.persist_header()?;
                    println!("OK enrolled passphrase in slot {idx}");
                    Ok(())
                }
            }
            1 => {
                if cont.is_deniable() {
                    enroll_fido2_deniable_into(theme, &mut cont)
                } else {
                    enroll_fido2_into(theme, &mut cont)
                }
            }
            // ===== pure-PQ rows (no TPM, all platforms) =====
            // Actions 2..=5 cover the 4 pure-PQ variants. They
            // mirror the GUI buttons of the same names. No
            // `#[cfg(target_os = "linux")]` because there's
            // nothing OS-specific about ML-KEM or about FIDO2
            // (Linux/macOS use libfido2, Windows uses
            // webauthn.dll).
            2 => {
                let vp = cont.vault_path().to_path_buf();
                if cont.is_deniable() {
                    enroll_hybrid_pq_passphrase_deniable_into(
                        theme,
                        &mut cont,
                        &vp,
                        luksbox_pq::PqParams::Ml768,
                    )
                } else {
                    enroll_hybrid_pq_passphrase_into(
                        theme,
                        &mut cont,
                        &vp,
                        luksbox_pq::PqParams::Ml768,
                    )
                }
            }
            3 => {
                let vp = cont.vault_path().to_path_buf();
                if cont.is_deniable() {
                    enroll_hybrid_pq_passphrase_deniable_into(
                        theme,
                        &mut cont,
                        &vp,
                        luksbox_pq::PqParams::Ml1024,
                    )
                } else {
                    enroll_hybrid_pq_passphrase_into(
                        theme,
                        &mut cont,
                        &vp,
                        luksbox_pq::PqParams::Ml1024,
                    )
                }
            }
            4 => {
                let vp = cont.vault_path().to_path_buf();
                if cont.is_deniable() {
                    enroll_hybrid_pq_fido2_deniable_into(
                        theme,
                        &mut cont,
                        &vp,
                        luksbox_pq::PqParams::Ml768,
                    )
                } else {
                    enroll_hybrid_pq_fido2_into(theme, &mut cont, &vp, luksbox_pq::PqParams::Ml768)
                }
            }
            5 => {
                let vp = cont.vault_path().to_path_buf();
                if cont.is_deniable() {
                    enroll_hybrid_pq_fido2_deniable_into(
                        theme,
                        &mut cont,
                        &vp,
                        luksbox_pq::PqParams::Ml1024,
                    )
                } else {
                    enroll_hybrid_pq_fido2_into(theme, &mut cont, &vp, luksbox_pq::PqParams::Ml1024)
                }
            }
            #[cfg(target_os = "linux")]
            6 => {
                if cont.is_deniable() {
                    enroll_tpm2_deniable_into(theme, &mut cont)
                } else {
                    enroll_tpm2_into(theme, &mut cont)
                }
            }
            #[cfg(target_os = "linux")]
            7 => {
                if cont.is_deniable() {
                    // The deniable slot envelope has no separate "TPM
                    // policy with PIN" variant - the envelope
                    // passphrase already acts as a knowledge factor on
                    // top of the TPM unseal. Use action 6 (TPM) for
                    // the equivalent posture in deniable vaults.
                    Err(
                        "TPM-PIN deniable enroll is not exposed: the deniable envelope already \
                         requires a passphrase, so 'TPM' gives the same knowledge+TPM \
                         requirement without a second PIN."
                            .into(),
                    )
                } else {
                    enroll_tpm2_pin_into(theme, &mut cont)
                }
            }
            #[cfg(target_os = "linux")]
            8 => {
                if cont.is_deniable() {
                    enroll_tpm2_fido2_deniable_into(theme, &mut cont)
                } else {
                    enroll_tpm2_fido2_into(theme, &mut cont)
                }
            }
            #[cfg(target_os = "linux")]
            9 => {
                let vp = cont.vault_path().to_path_buf();
                if cont.is_deniable() {
                    enroll_hybrid_pq_tpm2_deniable_into(
                        theme,
                        &mut cont,
                        &vp,
                        luksbox_pq::PqParams::Ml768,
                    )
                } else {
                    enroll_hybrid_pq_tpm2_into(theme, &mut cont, &vp, luksbox_pq::PqParams::Ml768)
                }
            }
            #[cfg(target_os = "linux")]
            10 => {
                let vp = cont.vault_path().to_path_buf();
                if cont.is_deniable() {
                    enroll_hybrid_pq_tpm2_deniable_into(
                        theme,
                        &mut cont,
                        &vp,
                        luksbox_pq::PqParams::Ml1024,
                    )
                } else {
                    enroll_hybrid_pq_tpm2_into(theme, &mut cont, &vp, luksbox_pq::PqParams::Ml1024)
                }
            }
            #[cfg(target_os = "linux")]
            11 => {
                let vp = cont.vault_path().to_path_buf();
                if cont.is_deniable() {
                    enroll_hybrid_pq_tpm2_fido2_deniable_into(
                        theme,
                        &mut cont,
                        &vp,
                        luksbox_pq::PqParams::Ml768,
                    )
                } else {
                    enroll_hybrid_pq_tpm2_fido2_into(
                        theme,
                        &mut cont,
                        &vp,
                        luksbox_pq::PqParams::Ml768,
                    )
                }
            }
            #[cfg(target_os = "linux")]
            12 => {
                let vp = cont.vault_path().to_path_buf();
                if cont.is_deniable() {
                    enroll_hybrid_pq_tpm2_fido2_deniable_into(
                        theme,
                        &mut cont,
                        &vp,
                        luksbox_pq::PqParams::Ml1024,
                    )
                } else {
                    enroll_hybrid_pq_tpm2_fido2_into(
                        theme,
                        &mut cont,
                        &vp,
                        luksbox_pq::PqParams::Ml1024,
                    )
                }
            }
            #[cfg(target_os = "macos")]
            16 => {
                if cont.is_deniable() {
                    Err("Secure Enclave deniable enroll is not exposed yet.".into())
                } else {
                    enroll_sep_into(theme, &mut cont, false)
                }
            }
            #[cfg(target_os = "macos")]
            17 => {
                if cont.is_deniable() {
                    Err("Secure Enclave deniable enroll is not exposed yet.".into())
                } else {
                    enroll_sep_into(theme, &mut cont, true)
                }
            }
            #[cfg(target_os = "macos")]
            18 => {
                let vp = cont.vault_path().to_path_buf();
                if cont.is_deniable() {
                    Err("Secure Enclave deniable enroll is not exposed yet.".into())
                } else {
                    enroll_hybrid_pq_sep_into(theme, &mut cont, &vp, luksbox_pq::PqParams::Ml768)
                }
            }
            #[cfg(target_os = "macos")]
            19 => {
                let vp = cont.vault_path().to_path_buf();
                if cont.is_deniable() {
                    Err("Secure Enclave deniable enroll is not exposed yet.".into())
                } else {
                    enroll_hybrid_pq_sep_into(theme, &mut cont, &vp, luksbox_pq::PqParams::Ml1024)
                }
            }
            // ===== fused Secure Enclave rows (macOS) =====
            // Actions 20..=28 cover SEP+FIDO2 / +passphrase / +both,
            // plain and hybrid (ML-KEM-768/1024). Generalized through
            // enroll_sep_fused_into.
            #[cfg(target_os = "macos")]
            20..=28 => {
                if cont.is_deniable() {
                    Err("Secure Enclave deniable enroll is not exposed yet.".into())
                } else {
                    let vp = cont.vault_path().to_path_buf();
                    let (factors, params) = match action {
                        20 => (crate::SepFactors::Fido2, None),
                        21 => (crate::SepFactors::Passphrase, None),
                        22 => (crate::SepFactors::Fido2Passphrase, None),
                        23 => (crate::SepFactors::Fido2, Some(luksbox_pq::PqParams::Ml768)),
                        24 => (crate::SepFactors::Fido2, Some(luksbox_pq::PqParams::Ml1024)),
                        25 => (
                            crate::SepFactors::Passphrase,
                            Some(luksbox_pq::PqParams::Ml768),
                        ),
                        26 => (
                            crate::SepFactors::Passphrase,
                            Some(luksbox_pq::PqParams::Ml1024),
                        ),
                        27 => (
                            crate::SepFactors::Fido2Passphrase,
                            Some(luksbox_pq::PqParams::Ml768),
                        ),
                        28 => (
                            crate::SepFactors::Fido2Passphrase,
                            Some(luksbox_pq::PqParams::Ml1024),
                        ),
                        _ => unreachable!(),
                    };
                    enroll_sep_fused_into(theme, &mut cont, &vp, factors, params)
                }
            }
            13 => update_keyslot_action(theme, &mut cont),
            14 => {
                if cont.is_deniable() {
                    // Deniable vaults don't expose a populated/empty
                    // slot table (it's all opaque ciphertext); admin
                    // picks an index directly. The current unlock slot
                    // is rejected inside `clear_deniable_slot` to
                    // prevent self-lockout.
                    let slot_idx = ask_deniable_slot_idx(theme, &cont)?;
                    if Confirm::with_theme(theme)
                        .with_prompt(format!(
                            "Clear deniable slot {slot_idx}? Whatever credential was there will \
                             no longer unlock this vault."
                        ))
                        .default(false)
                        .interact()?
                    {
                        cont.clear_deniable_slot(slot_idx)?;
                        cont.persist_header()?;
                        println!("OK deniable slot {slot_idx} cleared");
                    }
                    Ok(())
                } else {
                    let labels: Vec<String> = (0..MAX_KEYSLOTS)
                        .map(|i| format_slot(i, &cont.header.keyslots[i], false))
                        .collect();
                    let pick = Select::with_theme(theme)
                        .with_prompt("Slot to revoke")
                        .items(&labels)
                        .interact()?;
                    if Confirm::with_theme(theme)
                        .with_prompt(format!(
                            "Revoke slot {pick}? If this is your last keyslot you will be locked out."
                        ))
                        .default(false)
                        .interact()?
                    {
                        cont.revoke_slot(pick)?;
                        cont.persist_header()?;
                        println!("OK slot {pick} revoked");
                    }
                    Ok(())
                }
            }
            15 => return Ok(cont),
            _ => unreachable!(),
        };
        if let Err(e) = r {
            eprintln!("FAIL {e}");
        }
    }
}

fn update_keyslot_action(theme: &ColorfulTheme, cont: &mut Container) -> Result<()> {
    let populated: Vec<usize> = (0..MAX_KEYSLOTS)
        .filter(|i| cont.header.keyslots[*i].kind != SlotKind::Empty)
        .collect();
    if populated.is_empty() {
        return Err("no populated slots to update".into());
    }
    let labels: Vec<String> = populated
        .iter()
        .map(|i| format_slot(*i, &cont.header.keyslots[*i], false))
        .collect();
    let pick = Select::with_theme(theme)
        .with_prompt("Slot to update")
        .items(&labels)
        .interact()?;
    let slot_idx = populated[pick];
    let existing = cont.header.keyslots[slot_idx].kind;

    if existing == SlotKind::Fido2DerivedMvk {
        return Err(
            "fido2-direct keyslots cannot be updated in place, the MVK is derived \
             from the authenticator, not wrapped. Recreate the vault if you need to change \
             the underlying key."
                .into(),
        );
    }

    let target_options: &[&str] = match existing {
        SlotKind::Passphrase => &[
            "Replace with a fresh passphrase (same kind)",
            "Convert this slot to a FIDO2 wrap-style keyslot",
        ],
        SlotKind::Fido2HmacSecret => &[
            "Re-enroll a FIDO2 credential (same kind)",
            "Convert this slot to a passphrase keyslot",
        ],
        _ => unreachable!(),
    };
    let target_pick = Select::with_theme(theme)
        .with_prompt("New kind")
        .items(target_options)
        .default(0)
        .interact()?;
    let target_passphrase = matches!(
        (existing, target_pick),
        (SlotKind::Passphrase, 0) | (SlotKind::Fido2HmacSecret, 1)
    );

    if target_passphrase {
        let pw = ask_new_passphrase(theme, "New passphrase")?;
        eprintln!("Stretching with Argon2id (about 500 ms)...");
        cont.update_passphrase_at(slot_idx, pw.as_bytes(), kdf_params())?;
    } else {
        update_fido2_in(theme, cont, slot_idx)?;
    }
    cont.persist_header()?;
    println!("OK slot {slot_idx} updated");
    Ok(())
}

#[cfg(feature = "hardware")]
fn update_fido2_in(theme: &ColorfulTheme, c: &mut Container, slot_idx: usize) -> Result<()> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use rand_core::{OsRng, RngCore};

    fido2_preflight()?;
    let pin = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt("FIDO2 PIN")
            .interact()?,
    );
    let mut auth = crate::make_fido2_authenticator();
    let user_handle = random_user_handle()?;

    eprintln!("{}", crate::auth_prompt("register a new credential"));
    let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
    let cred_id = er.credential.id;

    let mut hmac_salt = [0u8; 32];
    OsRng.fill_bytes(&mut hmac_salt);

    eprintln!(
        "{}",
        crate::auth_prompt("again to derive the keyslot secret")
    );
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(&pin))?;

    c.update_fido2_at(
        slot_idx,
        None,
        &hmac_secret,
        &cred_id,
        hmac_salt,
        kdf_params(),
    )?;
    Ok(())
}

#[cfg(not(feature = "hardware"))]
fn update_fido2_in(_theme: &ColorfulTheme, _c: &mut Container, _slot_idx: usize) -> Result<()> {
    Err("FIDO2 hardware support not compiled in".into())
}

// ---- FIDO2 helpers ---------------------------------------------------------

#[cfg(feature = "hardware")]
fn enroll_fido2_into(theme: &ColorfulTheme, c: &mut Container) -> Result<()> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use rand_core::{OsRng, RngCore};

    fido2_preflight()?;
    let pin = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt("FIDO2 PIN")
            .interact()?,
    );
    // Asked before the touch prompts so the user isn't holding a finger on
    // the authenticator while a menu waits. A FIDO2-wrapped slot tolerates a
    // low Argon2id memory cost well: its entropy comes from the hardware
    // hmac-secret, not a human passphrase, so the picker is the supported way
    // to enrol on constrained hosts (small VMs / AppVMs) where 256 MiB
    // won't allocate.
    let kdf = ask_kdf_strength(theme, "Argon2id strength", 0)?;
    let mut auth = crate::make_fido2_authenticator();
    let user_handle = random_user_handle()?;

    eprintln!("{}", crate::auth_prompt("register a new credential"));
    let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
    let cred_id = er.credential.id;
    let mut hmac_salt = [0u8; 32];
    OsRng.fill_bytes(&mut hmac_salt);

    eprintln!(
        "{}",
        crate::auth_prompt("again to derive the keyslot secret")
    );
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(&pin))?;

    let idx = c.enroll_fido2(None, &hmac_secret, &cred_id, hmac_salt, kdf)?;
    c.persist_header()?;
    println!("OK enrolled FIDO2 credential in slot {idx}");
    Ok(())
}

#[cfg(not(feature = "hardware"))]
fn enroll_fido2_into(_theme: &ColorfulTheme, _c: &mut Container) -> Result<()> {
    Err("FIDO2 hardware support not compiled in".into())
}

// ============================================================
// Deniable-mode enroll helpers (wizard)
// ============================================================
//
// Mirror the GUI's `ops::enroll_*_deniable` functions: collect the
// per-credential material the user expects to be asked for, then call
// `Container::enroll_credential_v2_deniable` which routes through the
// shared v2 slot-envelope writer. Each one:
//   1. Asks for the deniable slot index (no first-free auto-pick - the
//      slot table isn't visible, so admin picks explicitly).
//   2. Asks for the per-slot envelope passphrase (required by every
//      v2 deniable variant; the credential type only changes WHICH
//      additional factor is folded into the envelope KEK).
//   3. Drives the credential-specific hardware (FIDO2 register +
//      hmac-secret, TPM seal, ML-KEM keygen+encap) to produce the
//      embedded material.
//   4. Persists the deniable buffer.
//
// All non-passphrase variants require the same `--cipher` /
// `--argon2-*` choice the vault was created with; reused via
// `ask_den_cipher` / `ask_den_kdf` prompts asked at enroll time
// so the wizard works on a vault opened earlier in the same session
// (where the create-time params aren't otherwise around to inherit).

#[cfg(feature = "hardware")]
fn enroll_fido2_deniable_into(theme: &ColorfulTheme, c: &mut Container) -> Result<()> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::deniable_header::DeniableMaterial;
    use rand_core::{OsRng, RngCore};

    fido2_preflight()?;
    let slot_idx = ask_deniable_slot_idx(theme, c)?;
    let argon2 = ask_den_kdf(theme, "Argon2id strength for the new envelope")?;
    let pass = ask_new_passphrase(theme, "Envelope passphrase for the new FIDO2 slot")?;
    let pin = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt("FIDO2 PIN")
            .interact()?,
    );
    let mut auth = crate::make_fido2_authenticator();
    let user_handle = random_user_handle()?;
    eprintln!("{}", crate::auth_prompt("register a new credential"));
    let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
    let cred_id = er.credential.id;
    let mut hmac_salt = [0u8; 32];
    OsRng.fill_bytes(&mut hmac_salt);
    eprintln!("{}", crate::auth_prompt("derive the new slot's secret"));
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(&pin))?;

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
    let idx = c.enroll_credential_v2_deniable(slot_idx, &cred, &material)?;
    c.persist_header()?;
    println!("OK deniable FIDO2 slot enrolled at index {idx}");
    Ok(())
}

#[cfg(not(feature = "hardware"))]
fn enroll_fido2_deniable_into(_theme: &ColorfulTheme, _c: &mut Container) -> Result<()> {
    Err("FIDO2 hardware support not compiled in".into())
}

#[cfg(all(feature = "hardware", target_os = "linux"))]
fn enroll_tpm2_deniable_into(theme: &ColorfulTheme, c: &mut Container) -> Result<()> {
    use luksbox_format::deniable_header::DeniableMaterial;

    let slot_idx = ask_deniable_slot_idx(theme, c)?;
    let argon2 = ask_den_kdf(theme, "Argon2id strength for the new envelope")?;
    let pass = ask_new_passphrase(theme, "Envelope passphrase for the new TPM slot")?;
    // Optional userAuth on the TPM-sealed object. An empty input
    // means "no PIN", matching the seal/unseal asymmetry: the
    // unseal-side path must call `unseal` (no PIN), not
    // `unseal_with_pin`, or the TPM rejects with
    // TPM_RC_AUTH_FAIL. We surface this as a single prompt with
    // an explicit "leave blank for no PIN" hint so callers can't
    // accidentally seal-with-empty-string and trip the same
    // asymmetry on the unseal side.
    let pin_input = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt("TPM PIN (leave blank for no PIN)")
            .allow_empty_password(true)
            .interact()?,
    );
    let pin_bytes: Option<&[u8]> = if pin_input.is_empty() {
        None
    } else {
        Some(pin_input.as_bytes())
    };
    let (secret, blob) = tpm_seal_blob_to_bytes(pin_bytes)?;
    let cred = luksbox_core::deniable::DeniableCredential::TpmPassphrase {
        passphrase: pass.as_bytes(),
        argon2,
        unsealed: &secret,
    };
    let material = DeniableMaterial {
        cred_id: Vec::new(),
        hmac_salt: None,
        tpm_blob: blob,
    };
    let idx = c.enroll_credential_v2_deniable(slot_idx, &cred, &material)?;
    c.persist_header()?;
    println!("OK deniable TPM slot enrolled at index {idx}");
    Ok(())
}

#[cfg(not(all(feature = "hardware", target_os = "linux")))]
fn enroll_tpm2_deniable_into(_theme: &ColorfulTheme, _c: &mut Container) -> Result<()> {
    Err("TPM is Linux-only today; Windows TPM is tracked as a follow-up".into())
}

#[cfg(all(feature = "hardware", target_os = "linux"))]
fn enroll_tpm2_fido2_deniable_into(theme: &ColorfulTheme, c: &mut Container) -> Result<()> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::deniable_header::DeniableMaterial;
    use rand_core::{OsRng, RngCore};

    fido2_preflight()?;
    let slot_idx = ask_deniable_slot_idx(theme, c)?;
    let argon2 = ask_den_kdf(theme, "Argon2id strength for the new envelope")?;
    let pass = ask_new_passphrase(theme, "Envelope passphrase for the new TPM+FIDO2 slot")?;
    let pin = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt("FIDO2 PIN")
            .interact()?,
    );
    let (tpm_secret, tpm_blob) = tpm_seal_blob_to_bytes(None)?;

    let mut auth = crate::make_fido2_authenticator();
    let user_handle = random_user_handle()?;
    let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
    let cred_id = er.credential.id;
    let mut hmac_salt = [0u8; 32];
    OsRng.fill_bytes(&mut hmac_salt);
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(&pin))?;

    let cred = luksbox_core::deniable::DeniableCredential::TpmFido2Passphrase {
        passphrase: pass.as_bytes(),
        argon2,
        unsealed: &tpm_secret,
        hmac_secret_output: &hmac_secret,
    };
    let material = DeniableMaterial {
        cred_id,
        hmac_salt: Some(hmac_salt),
        tpm_blob,
    };
    let idx = c.enroll_credential_v2_deniable(slot_idx, &cred, &material)?;
    c.persist_header()?;
    println!("OK deniable TPM+FIDO2 slot enrolled at index {idx}");
    Ok(())
}

#[cfg(not(all(feature = "hardware", target_os = "linux")))]
fn enroll_tpm2_fido2_deniable_into(_theme: &ColorfulTheme, _c: &mut Container) -> Result<()> {
    Err("TPM is Linux-only today; Windows TPM is tracked as a follow-up".into())
}

#[cfg(all(feature = "hardware", target_os = "linux"))]
fn enroll_hybrid_pq_tpm2_deniable_into(
    theme: &ColorfulTheme,
    c: &mut Container,
    vault_path: &Path,
    params: luksbox_pq::PqParams,
) -> Result<()> {
    use luksbox_format::deniable_header::DeniableMaterial;
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{encapsulate_with, keygen_with, seed_file};

    let slot_idx = ask_deniable_slot_idx(theme, c)?;
    let argon2 = ask_den_kdf(theme, "Argon2id strength for the new envelope")?;
    let envelope_pw =
        ask_new_passphrase(theme, "Envelope passphrase for the new hybrid-PQ+TPM slot")?;
    let seed_pw = ask_optional_seed_pw(theme, &envelope_pw)?;
    let kyber_path = ask_path(
        theme,
        "Path for the .kyber seed file (keep on separate storage)",
    )?;

    let (tpm_secret, tpm_blob) = tpm_seal_blob_to_bytes(None)?;
    let (pk, seed) = keygen_with(params);
    let (ct, shared) = encapsulate_with(params, &pk)?;

    let cred = luksbox_core::deniable::DeniableCredential::HybridPqTpmPassphrase {
        passphrase: envelope_pw.as_bytes(),
        argon2,
        mlkem_shared: &shared,
        unsealed: &tpm_secret,
    };
    let material = DeniableMaterial {
        cred_id: Vec::new(),
        hmac_salt: None,
        tpm_blob,
    };
    let idx = c.enroll_credential_v2_deniable(slot_idx, &cred, &material)?;
    c.persist_header()?;

    // Merge with existing sidecar entries, replacing any stale
    // entry for this slot index. Without the filter the sidecar
    // could end up with two entries for the same slot (rejected
    // by `validate_entries`) when the user re-enrolls at an
    // occupied slot index.
    let sidecar_path = hybrid_sidecar::sidecar_path(vault_path);
    let prior_entries: Vec<HybridEntry> = if sidecar_path.exists() {
        hybrid_sidecar::read(&sidecar_path)
            .map_err(|e| format!("read existing hybrid sidecar: {e}"))?
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
    hybrid_sidecar::write(&sidecar_path, &entries)?;
    seed_file::write(
        &kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    )?;

    println!("OK deniable hybrid-PQ+TPM slot enrolled at index {idx}");
    println!("  .kyber seed:    {}", kyber_path.display());
    println!(
        "  hybrid sidecar: {}",
        hybrid_sidecar::sidecar_path(vault_path).display()
    );
    Ok(())
}

#[cfg(not(all(feature = "hardware", target_os = "linux")))]
fn enroll_hybrid_pq_tpm2_deniable_into(
    _theme: &ColorfulTheme,
    _c: &mut Container,
    _vault_path: &Path,
    _params: luksbox_pq::PqParams,
) -> Result<()> {
    Err("TPM is Linux-only today; Windows TPM is tracked as a follow-up".into())
}

#[cfg(all(feature = "hardware", target_os = "linux"))]
fn enroll_hybrid_pq_tpm2_fido2_deniable_into(
    theme: &ColorfulTheme,
    c: &mut Container,
    vault_path: &Path,
    params: luksbox_pq::PqParams,
) -> Result<()> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::deniable_header::DeniableMaterial;
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{encapsulate_with, keygen_with, seed_file};
    use rand_core::{OsRng, RngCore};

    fido2_preflight()?;
    let slot_idx = ask_deniable_slot_idx(theme, c)?;
    let argon2 = ask_den_kdf(theme, "Argon2id strength for the new envelope")?;
    let envelope_pw = ask_new_passphrase(
        theme,
        "Envelope passphrase for the new hybrid-PQ+TPM+FIDO2 slot",
    )?;
    let pin = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt("FIDO2 PIN")
            .interact()?,
    );
    let seed_pw = ask_optional_seed_pw(theme, &envelope_pw)?;
    let kyber_path = ask_path(theme, "Path for the .kyber seed file")?;

    let (tpm_secret, tpm_blob) = tpm_seal_blob_to_bytes(None)?;

    let mut auth = crate::make_fido2_authenticator();
    let user_handle = random_user_handle()?;
    let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
    let cred_id = er.credential.id;
    let mut hmac_salt = [0u8; 32];
    OsRng.fill_bytes(&mut hmac_salt);
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(&pin))?;

    let (pk, seed) = keygen_with(params);
    let (ct, shared) = encapsulate_with(params, &pk)?;

    let cred = luksbox_core::deniable::DeniableCredential::HybridPqTpmFido2Passphrase {
        passphrase: envelope_pw.as_bytes(),
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
    let idx = c.enroll_credential_v2_deniable(slot_idx, &cred, &material)?;
    c.persist_header()?;

    // Merge with existing sidecar entries; see comment in the
    // sibling `enroll_hybrid_pq_tpm2_deniable_into` above.
    let sidecar_path = hybrid_sidecar::sidecar_path(vault_path);
    let prior_entries: Vec<HybridEntry> = if sidecar_path.exists() {
        hybrid_sidecar::read(&sidecar_path)
            .map_err(|e| format!("read existing hybrid sidecar: {e}"))?
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
    hybrid_sidecar::write(&sidecar_path, &entries)?;
    seed_file::write(
        &kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    )?;

    println!("OK deniable 4-factor slot enrolled at index {idx}");
    println!("  .kyber seed:    {}", kyber_path.display());
    println!(
        "  hybrid sidecar: {}",
        hybrid_sidecar::sidecar_path(vault_path).display()
    );
    Ok(())
}

#[cfg(not(all(feature = "hardware", target_os = "linux")))]
fn enroll_hybrid_pq_tpm2_fido2_deniable_into(
    _theme: &ColorfulTheme,
    _c: &mut Container,
    _vault_path: &Path,
    _params: luksbox_pq::PqParams,
) -> Result<()> {
    Err("TPM is Linux-only today; Windows TPM is tracked as a follow-up".into())
}

#[cfg(feature = "hardware")]
fn unlock_via_fido2(
    theme: &ColorfulTheme,
    vault: &Path,
    header_path: Option<&Path>,
    header: &Header,
) -> Result<Container> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID};

    let pin = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt("FIDO2 PIN")
            .interact()?,
    );
    let mut auth = crate::make_fido2_authenticator();

    let mut last_err: Option<Box<dyn std::error::Error>> = None;
    let mut tried = 0usize;
    for slot in &header.keyslots {
        if !matches!(
            slot.kind,
            SlotKind::Fido2HmacSecret | SlotKind::Fido2DerivedMvk
        ) {
            continue;
        }
        tried += 1;
        eprintln!(
            "{}",
            crate::auth_prompt(&format!(
                "unlock (slot cred_id len {} B)",
                slot.fido2_cred_id.len()
            ))
        );
        let hmac_secret = match auth.hmac_secret(
            RP_ID,
            &slot.fido2_cred_id,
            &slot.fido2_hmac_salt,
            slot.fido2_salt_prehashed(),
            Some(&pin),
        ) {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(format!("FIDO2: {e}").into());
                continue;
            }
        };
        match Container::open(
            vault,
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
        return Err("no FIDO2 keyslots in this vault".into());
    }
    Err(last_err.unwrap_or_else(|| "FIDO2 unlock failed".into()))
}

#[cfg(not(feature = "hardware"))]
fn unlock_via_fido2(
    _theme: &ColorfulTheme,
    _vault: &Path,
    _header_path: Option<&Path>,
    _header: &Header,
) -> Result<Container> {
    Err("FIDO2 hardware support not compiled in".into())
}

/// Hybrid passphrase + ML-KEM-768 unlock flow. Asks for the .kyber
/// seed file path + the passphrase that protects it, reads the public
/// Kyber blobs from the .hybrid sidecar next to the vault,
/// decapsulates, and opens the container.
fn unlock_via_hybrid_pq(
    theme: &ColorfulTheme,
    vault: &Path,
    header_path: Option<&Path>,
) -> Result<Container> {
    use luksbox_format::hybrid_sidecar;
    use luksbox_pq::seed_file;

    let kyber_path = ask_path(theme, "Path to the Kyber seed (.kyber) file")?;
    if !kyber_path.is_file() {
        return Err(format!("{} is not a file", kyber_path.display()).into());
    }
    let pw = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt("Passphrase")
            .interact()?,
    );
    let seed =
        seed_file::read(&kyber_path, pw.as_bytes()).map_err(|e| format!("read kyber seed: {e}"))?;
    let sidecar = hybrid_sidecar::sidecar_path(vault);
    // v3 vault-binding verification (see `read_for_vault` doc).
    let entries = hybrid_sidecar::read_for_vault(&sidecar, vault, header_path)
        .map_err(|e| format!("read hybrid sidecar at {}: {e}", sidecar.display()))?;
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
            vault,
            header_path,
            UnlockMaterial::HybridPqPassphrase {
                passphrase: pw.as_bytes(),
                pq_shared: &shared,
            },
        ) {
            Ok(c) => return Ok(c),
            Err(e) => last_err = Some(format!("open slot {}: {e}", entry.slot_idx)),
        }
    }
    Err(last_err
        .unwrap_or_else(|| "hybrid unlock failed".into())
        .into())
}

#[cfg(feature = "hardware")]
fn unlock_via_hybrid_pq_fido2(
    theme: &ColorfulTheme,
    vault: &Path,
    header_path: Option<&Path>,
    header: &Header,
) -> Result<Container> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID};
    use luksbox_format::hybrid_sidecar;
    use luksbox_pq::seed_file;

    let kyber_path = ask_path(theme, "Path to the Kyber seed (.kyber) file")?;
    if !kyber_path.is_file() {
        return Err(format!("{} is not a file", kyber_path.display()).into());
    }
    let pin = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt("FIDO2 PIN")
            .interact()?,
    );
    let seed_pw = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt(".kyber seed-file passphrase")
            .interact()?,
    );
    let seed = seed_file::read(&kyber_path, seed_pw.as_bytes())
        .map_err(|e| format!("read kyber seed: {e}"))?;

    let sidecar = hybrid_sidecar::sidecar_path(vault);
    // v3 vault-binding verification (see `read_for_vault` doc).
    let entries = hybrid_sidecar::read_for_vault(&sidecar, vault, header_path)
        .map_err(|e| format!("read sidecar: {e}"))?;

    let mut auth = crate::make_fido2_authenticator();
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
        eprintln!(
            "{}",
            crate::auth_prompt(&format!("unlock (slot {slot_idx})"))
        );
        let hmac_secret = match auth.hmac_secret(
            RP_ID,
            &slot.fido2_cred_id,
            &slot.fido2_hmac_salt,
            slot.fido2_salt_prehashed(),
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
            vault,
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
        .unwrap_or_else(|| "hybrid-fido2 unlock failed".into())
        .into())
}

#[cfg(not(feature = "hardware"))]
fn unlock_via_hybrid_pq_fido2(
    _theme: &ColorfulTheme,
    _vault: &Path,
    _header_path: Option<&Path>,
    _header: &Header,
) -> Result<Container> {
    Err("FIDO2 hardware support not compiled in".into())
}

// ---- TPM 2.0 helpers -------------------------------------------------------
//
// Each `enroll_tpm*_into` helper assumes the caller already opened the
// container (i.e. the user already authenticated with whatever existing
// keyslot). They mirror the CLI's `cmd_enroll_tpm2*` functions in
// main.rs but use dialoguer prompts instead of stdin/rpassword.
//
// The corresponding `unlock_via_tpm*` helpers are inverses, used by
// the open-wizard's unlock-method menu when the vault has TPM slots.

/// Prompt for a TPM PIN with confirmation. Same shape as
/// `ask_new_passphrase` but skips the strength check (PIN is bound
/// to the chip's dictionary-attack lockout, not Argon2id, so 4-6
/// digits is fine).
fn ask_new_tpm_pin(theme: &ColorfulTheme) -> Result<zeroize::Zeroizing<String>> {
    eprintln!(
        "TPM PIN: any string up to 64 bytes. Wrong PINs count toward the chip's\n  \
         dictionary-attack lockout, so even 4-6 digit PINs are secure on the\n  \
         original hardware."
    );
    loop {
        let a = zeroize::Zeroizing::new(
            Password::with_theme(theme)
                .with_prompt("TPM PIN")
                .interact()?,
        );
        if a.is_empty() {
            return Err("PIN cannot be empty (use the no-PIN TPM kind instead)".into());
        }
        let b = zeroize::Zeroizing::new(
            Password::with_theme(theme)
                .with_prompt("confirm")
                .interact()?,
        );
        if *a != *b {
            eprintln!("PINs do not match, try again");
            continue;
        }
        return Ok(a);
    }
}

#[cfg(feature = "hardware")]
fn enroll_tpm2_into(_theme: &ColorfulTheme, c: &mut Container) -> Result<()> {
    use luksbox_tpm::Tpm2Sealer;
    use rand_core::{OsRng, RngCore};
    use zeroize::Zeroizing;

    eprintln!(
        "note: bare TPM 2.0 (no PIN, no PCR policy) protects against \
         a stolen vault file but NOT a stolen device booted and \
         running. For device-theft scenarios, prefer the `tpm2-pin` \
         kind so the chip's dictionary-attack lockout gates an \
         offline PIN attack."
    );
    let mut sealer = Tpm2Sealer::new().map_err(|e| format!("{e}"))?;
    let mut kek = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(kek.as_mut_slice())
        .map_err(|e| format!("OS RNG: {e}"))?;
    eprintln!("sealing KEK under the local TPM 2.0...");
    let blob = sealer.seal(&kek).map_err(|e| format!("TPM seal: {e}"))?;
    let blob_bytes = blob.to_bytes();

    let idx = c.enroll_tpm2(&kek, &blob_bytes)?;
    c.persist_header()?;
    println!(
        "OK enrolled TPM 2.0 keyslot in slot {idx} (sealed {} B)",
        blob_bytes.len()
    );
    Ok(())
}

#[cfg(not(feature = "hardware"))]
fn enroll_tpm2_into(_theme: &ColorfulTheme, _c: &mut Container) -> Result<()> {
    Err(
        "TPM 2.0 support not compiled in (rebuild with --features hardware; \
         on Linux also install libtss2-dev / tpm2-tss-devel)"
            .into(),
    )
}

/// Enroll a macOS Secure Enclave keyslot into an already-open
/// container. Mirrors `enroll_tpm2_into`; `biometric` gates the slot
/// behind a Touch ID / user-presence check at every unlock.
#[cfg(feature = "hardware")]
fn enroll_sep_into(_theme: &ColorfulTheme, c: &mut Container, biometric: bool) -> Result<()> {
    use luksbox_sep::SepSealer;

    let mut sealer = SepSealer::new().map_err(|e| format!("{e}"))?;
    let (kind, label) = if biometric {
        (
            luksbox_core::SlotKind::SepSealedBiometric,
            "Secure Enclave + Touch ID",
        )
    } else {
        (luksbox_core::SlotKind::SepSealed, "Secure Enclave")
    };

    eprintln!("sealing KEK under the local Secure Enclave...");
    let (sep_shared, blob) = if biometric {
        sealer
            .seal_biometric()
            .map_err(|e| format!("SEP seal (biometric): {e}"))?
    } else {
        sealer.seal().map_err(|e| format!("SEP seal: {e}"))?
    };
    let blob_bytes = blob.to_bytes();

    let idx = c.enroll_sep(
        kind,
        &sep_shared,
        &blob_bytes,
        None,
        None,
        kdf_params(),
        None,
        &[],
        [0u8; 32],
    )?;
    c.persist_header()?;
    println!(
        "OK enrolled {label} keyslot in slot {idx} (sealed {} B)",
        blob_bytes.len()
    );
    Ok(())
}

#[cfg(not(feature = "hardware"))]
fn enroll_sep_into(_theme: &ColorfulTheme, _c: &mut Container, _biometric: bool) -> Result<()> {
    Err(
        "Secure Enclave support not compiled in (rebuild with --features hardware; \
         Secure Enclave keyslots only work on macOS hardware)"
            .into(),
    )
}

/// Hybrid Secure Enclave + ML-KEM-{768,1024} enroll into an
/// already-open container. Mirrors `enroll_hybrid_pq_tpm2_into`: the
/// SEP supplies the classical half, ML-KEM the post-quantum half;
/// writes the .lbx.hybrid sidecar entry + the Kyber seed file.
#[cfg(feature = "hardware")]
fn enroll_hybrid_pq_sep_into(
    theme: &ColorfulTheme,
    c: &mut Container,
    vault: &Path,
    params: luksbox_pq::PqParams,
) -> Result<()> {
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};
    use luksbox_sep::SepSealer;

    let (level_label, kind) = match params {
        PqParams::Ml768 => ("ML-KEM-768", luksbox_core::SlotKind::HybridPqKemSep),
        PqParams::Ml1024 => ("ML-KEM-1024", luksbox_core::SlotKind::HybridPqKem1024Sep),
    };
    eprintln!(
        "Hybrid Secure Enclave + {level_label} keyslot. KEK = HKDF(salt,\n  \
         sep_shared || pq_shared). Both the local Secure Enclave AND a\n  \
         separate .kyber seed file (kept on different storage from the\n  \
         .lbx) will be required at every unlock."
    );
    let kyber_path = ask_path(theme, "Path for the new Kyber seed (.kyber) file")?;
    if kyber_path.exists() {
        return Err(format!("{} already exists", kyber_path.display()).into());
    }
    let seed_pw = ask_new_passphrase(theme, "Seed-file passphrase")?;

    let mut sealer = SepSealer::new().map_err(|e| format!("{e}"))?;

    eprintln!("sealing SEP half under the local Secure Enclave...");
    let (sep_shared, blob) = sealer.seal().map_err(|e| format!("SEP seal: {e}"))?;
    let blob_bytes = blob.to_bytes();

    eprintln!("generating {level_label} keypair...");
    let (pk, seed) = keygen_with(params);
    let (ct, pq_shared) =
        encapsulate_with(params, &pk).map_err(|e| format!("ML-KEM encapsulate: {e}"))?;

    let idx = c.enroll_sep(
        kind,
        &sep_shared,
        &blob_bytes,
        None,
        None,
        kdf_params(),
        Some(&pq_shared),
        &[],
        [0u8; 32],
    )?;
    c.persist_header()?;

    let sidecar = hybrid_sidecar::sidecar_path(vault);
    let mut entries = if sidecar.exists() {
        hybrid_sidecar::read(&sidecar).map_err(|e| format!("read existing hybrid sidecar: {e}"))?
    } else {
        Vec::new()
    };
    entries.push(HybridEntry {
        slot_idx: idx as u8,
        level: params,
        pubkey: pk,
        ciphertext: ct,
    });
    hybrid_sidecar::write(&sidecar, &entries).map_err(|e| format!("write hybrid sidecar: {e}"))?;

    seed_file::write(
        &kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    )
    .map_err(|e| format!("write kyber seed: {e}"))?;

    println!(
        "OK enrolled hybrid Secure Enclave + {level_label} keyslot in slot {idx}\n  \
         Kyber seed: {} (MOVE TO SEPARATE STORAGE - lose it = lose this slot)",
        kyber_path.display()
    );
    Ok(())
}

#[cfg(not(feature = "hardware"))]
fn enroll_hybrid_pq_sep_into(
    _theme: &ColorfulTheme,
    _c: &mut Container,
    _vault: &Path,
    _params: luksbox_pq::PqParams,
) -> Result<()> {
    Err("hybrid-pq-sep enroll requires --features hardware".into())
}

/// Enroll a fused Secure Enclave keyslot (SEP + FIDO2 / passphrase /
/// hybrid-PQ combinations) into an already-open container. The
/// wizard analog of `crate::cmd_enroll_sep_fused`: the SEP always
/// supplies the classical machine-bound half (plain `seal()`, never
/// biometric), and `factors` + optional `params` decide which extra
/// secrets are collected. For hybrid kinds the `.lbx.hybrid` sidecar
/// entry + the (passphrase-encrypted) `.kyber` seed are written.
#[cfg(feature = "hardware")]
fn enroll_sep_fused_into(
    theme: &ColorfulTheme,
    c: &mut Container,
    vault: &Path,
    factors: crate::SepFactors,
    params: Option<luksbox_pq::PqParams>,
) -> Result<()> {
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{encapsulate_with, keygen_with, seed_file};
    use luksbox_sep::SepSealer;

    let kem_size = params.map(|p| match p {
        luksbox_pq::PqParams::Ml768 => 768u16,
        luksbox_pq::PqParams::Ml1024 => 1024u16,
    });
    let kind = factors.slot_kind(kem_size)?;

    if factors.has_fido2() {
        fido2_preflight()?;
    }
    let mut sealer = SepSealer::new().map_err(|e| format!("{e}"))?;

    // Collect destinations + passphrases before any hardware step.
    let (kyber_path, seed_pw) = if params.is_some() {
        let kp = ask_path(theme, "Path for the new Kyber seed (.kyber) file")?;
        if kp.exists() {
            return Err(format!("{} already exists", kp.display()).into());
        }
        let pw = ask_new_passphrase(theme, "Seed-file passphrase")?;
        (Some(kp), Some(pw))
    } else {
        (None, None)
    };
    let new_pw = if factors.has_passphrase() {
        Some(ask_new_passphrase(theme, "New slot passphrase")?)
    } else {
        None
    };

    // FIDO2 half: fresh credential + hmac_secret, same as
    // enroll_tpm2_fido2_into.
    let fido2 = if factors.has_fido2() {
        use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
        use rand_core::{OsRng, RngCore};
        let pin = wizard_prompt_fido2_pin(theme)?;
        let mut auth = crate::make_fido2_authenticator();
        let user_handle = random_user_handle()?;
        eprintln!("Touch your FIDO2 authenticator to register a new credential...");
        let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
        let cred_id = er.credential.id;
        let mut hmac_salt = [0u8; 32];
        OsRng.fill_bytes(&mut hmac_salt);
        eprintln!("Touch again to derive the FIDO2 half...");
        let hmac_secret: [u8; 32] =
            *auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(&pin))?;
        Some((cred_id, hmac_salt, hmac_secret))
    } else {
        None
    };

    eprintln!("sealing SEP half under the local Secure Enclave...");
    let (sep_shared, blob) = sealer.seal().map_err(|e| format!("SEP seal: {e}"))?;
    let blob_bytes = blob.to_bytes();

    let pq = match params {
        Some(p) => {
            eprintln!("generating ML-KEM keypair...");
            let (pk, seed) = keygen_with(p);
            let (ct, pq_shared) =
                encapsulate_with(p, &pk).map_err(|e| format!("ML-KEM encapsulate: {e}"))?;
            Some((p, pk, seed, ct, pq_shared))
        }
        None => None,
    };

    let hmac_secret_ref = fido2.as_ref().map(|(_, _, hs)| hs);
    let passphrase_ref = new_pw.as_ref().map(|p| p.as_bytes());
    let pq_shared_ref = pq.as_ref().map(|(_, _, _, _, s)| &**s);
    let cred_id_ref: &[u8] = fido2
        .as_ref()
        .map(|(cred, _, _)| cred.as_slice())
        .unwrap_or(&[]);
    let hmac_salt = fido2.as_ref().map(|(_, s, _)| *s).unwrap_or([0u8; 32]);

    let idx = c.enroll_sep(
        kind,
        &sep_shared,
        &blob_bytes,
        hmac_secret_ref,
        passphrase_ref,
        kdf_params(),
        pq_shared_ref,
        cred_id_ref,
        hmac_salt,
    )?;

    match pq {
        None => {
            c.persist_header()?;
            println!("OK enrolled {kind:?} keyslot in slot {idx}");
        }
        Some((p, pk, seed, ct, _)) => {
            c.persist_header()?;
            let sidecar = hybrid_sidecar::sidecar_path(vault);
            let mut entries = if sidecar.exists() {
                hybrid_sidecar::read(&sidecar)
                    .map_err(|e| format!("read existing hybrid sidecar: {e}"))?
            } else {
                Vec::new()
            };
            entries.push(HybridEntry {
                slot_idx: idx as u8,
                level: p,
                pubkey: pk,
                ciphertext: ct,
            });
            hybrid_sidecar::write(&sidecar, &entries)
                .map_err(|e| format!("write hybrid sidecar: {e}"))?;
            let kyber_path = kyber_path.expect("hybrid implies a kyber path");
            let seed_pw = seed_pw.expect("hybrid implies a seed passphrase");
            seed_file::write(
                &kyber_path,
                &seed,
                seed_pw.as_bytes(),
                seed_file::KdfParams::default(),
            )
            .map_err(|e| format!("write kyber seed: {e}"))?;
            println!(
                "OK enrolled {kind:?} keyslot in slot {idx}\n  \
                 Kyber seed: {} (MOVE TO SEPARATE STORAGE - lose it = lose this slot)",
                kyber_path.display()
            );
        }
    }
    Ok(())
}

#[cfg(not(feature = "hardware"))]
fn enroll_sep_fused_into(
    _theme: &ColorfulTheme,
    _c: &mut Container,
    _vault: &Path,
    _factors: crate::SepFactors,
    _params: Option<luksbox_pq::PqParams>,
) -> Result<()> {
    Err("fused Secure Enclave enroll requires --features hardware".into())
}

#[cfg(feature = "hardware")]
fn enroll_tpm2_pin_into(theme: &ColorfulTheme, c: &mut Container) -> Result<()> {
    use luksbox_tpm::Tpm2Sealer;
    use rand_core::{OsRng, RngCore};
    use zeroize::Zeroizing;

    let mut sealer = Tpm2Sealer::new().map_err(|e| format!("{e}"))?;
    let pin = ask_new_tpm_pin(theme)?;

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
    println!("OK enrolled PIN-protected TPM 2.0 keyslot in slot {idx}");
    Ok(())
}

#[cfg(not(feature = "hardware"))]
fn enroll_tpm2_pin_into(_theme: &ColorfulTheme, _c: &mut Container) -> Result<()> {
    Err("TPM 2.0 + PIN support not compiled in".into())
}

#[cfg(feature = "hardware")]
fn enroll_tpm2_fido2_into(theme: &ColorfulTheme, c: &mut Container) -> Result<()> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_tpm::Tpm2Sealer;
    use rand_core::{OsRng, RngCore};
    use zeroize::Zeroizing;

    fido2_preflight()?;
    let mut sealer = Tpm2Sealer::new().map_err(|e| format!("{e}"))?;
    let pin = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt("FIDO2 PIN")
            .interact()?,
    );
    let mut auth = crate::make_fido2_authenticator();
    let user_handle = random_user_handle()?;

    eprintln!("{}", crate::auth_prompt("register a new FIDO2 credential"));
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

    let mut hmac_salt = [0u8; 32];
    OsRng.fill_bytes(&mut hmac_salt);
    eprintln!("{}", crate::auth_prompt("again to derive the FIDO2 half"));
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(&pin))?;

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
        "OK enrolled fused TPM+FIDO2 keyslot in slot {idx} (cred_id {} B, sealed {} B)",
        cred_id.len(),
        blob_bytes.len()
    );
    Ok(())
}

#[cfg(not(feature = "hardware"))]
fn enroll_tpm2_fido2_into(_theme: &ColorfulTheme, _c: &mut Container) -> Result<()> {
    Err("TPM 2.0 + FIDO2 fused enroll requires --features hardware".into())
}

/// Hybrid TPM 2.0 + ML-KEM-{768,1024} enroll into an already-open
/// container. Generates a fresh Kyber keypair, seals a TPM half, and
/// appends a sidecar entry. Writes the Kyber seed to a user-chosen
/// passphrase-protected file.
#[cfg(feature = "hardware")]
fn enroll_hybrid_pq_tpm2_into(
    theme: &ColorfulTheme,
    c: &mut Container,
    vault: &Path,
    params: luksbox_pq::PqParams,
) -> Result<()> {
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};
    use luksbox_tpm::Tpm2Sealer;
    use rand_core::{OsRng, RngCore};
    use zeroize::Zeroizing;

    let level_label = match params {
        PqParams::Ml768 => "ML-KEM-768",
        PqParams::Ml1024 => "ML-KEM-1024",
    };
    eprintln!(
        "Hybrid TPM 2.0 + {level_label} keyslot. KEK = HKDF(salt,\n  \
         tpm_kek || pq_shared). Both the local TPM AND a separate\n  \
         .kyber seed file (kept on different storage from the .lbx)\n  \
         will be required at every unlock."
    );
    let kyber_path = ask_path(theme, "Path for the new Kyber seed (.kyber) file")?;
    if kyber_path.exists() {
        return Err(format!("{} already exists", kyber_path.display()).into());
    }
    let seed_pw = ask_new_passphrase(theme, "Seed-file passphrase")?;

    let mut sealer = Tpm2Sealer::new().map_err(|e| format!("{e}"))?;

    let mut tpm_kek = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(tpm_kek.as_mut_slice())
        .map_err(|e| format!("OS RNG: {e}"))?;
    eprintln!("sealing TPM half under the local TPM 2.0...");
    let blob = sealer
        .seal(&tpm_kek)
        .map_err(|e| format!("TPM seal: {e}"))?;
    let blob_bytes = blob.to_bytes();

    eprintln!("generating {level_label} keypair...");
    let (pk, seed) = keygen_with(params);
    let (ct, pq_shared) =
        encapsulate_with(params, &pk).map_err(|e| format!("ML-KEM encapsulate: {e}"))?;

    let idx = match params {
        PqParams::Ml768 => c.enroll_hybrid_pq_tpm2(&tpm_kek, &pq_shared, &blob_bytes)?,
        PqParams::Ml1024 => c.enroll_hybrid_pq_1024_tpm2(&tpm_kek, &pq_shared, &blob_bytes)?,
    };
    c.persist_header()?;

    let sidecar = hybrid_sidecar::sidecar_path(vault);
    let mut entries = if sidecar.exists() {
        hybrid_sidecar::read(&sidecar).map_err(|e| format!("read existing hybrid sidecar: {e}"))?
    } else {
        Vec::new()
    };
    entries.push(HybridEntry {
        slot_idx: idx as u8,
        level: params,
        pubkey: pk,
        ciphertext: ct,
    });
    hybrid_sidecar::write(&sidecar, &entries).map_err(|e| format!("write hybrid sidecar: {e}"))?;

    seed_file::write(
        &kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    )
    .map_err(|e| format!("write kyber seed: {e}"))?;

    println!(
        "OK enrolled hybrid TPM 2.0 + {level_label} keyslot in slot {idx}\n  \
         Kyber seed: {} (MOVE TO SEPARATE STORAGE - lose it = lose this slot)",
        kyber_path.display()
    );
    Ok(())
}

#[cfg(not(feature = "hardware"))]
fn enroll_hybrid_pq_tpm2_into(
    _theme: &ColorfulTheme,
    _c: &mut Container,
    _vault: &Path,
    _params: luksbox_pq::PqParams,
) -> Result<()> {
    Err("hybrid-pq-tpm2 enroll requires --features hardware".into())
}

#[cfg(feature = "hardware")]
fn enroll_hybrid_pq_tpm2_fido2_into(
    theme: &ColorfulTheme,
    c: &mut Container,
    vault: &Path,
    params: luksbox_pq::PqParams,
) -> Result<()> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};
    use luksbox_tpm::Tpm2Sealer;
    use rand_core::{OsRng, RngCore};
    use zeroize::Zeroizing;

    fido2_preflight()?;

    let level_label = match params {
        PqParams::Ml768 => "ML-KEM-768",
        PqParams::Ml1024 => "ML-KEM-1024",
    };
    eprintln!(
        "Three-factor TPM 2.0 + FIDO2 + {level_label} keyslot. All\n  \
         three required at unlock: the local TPM AND a FIDO2 authenticator\n  \
         AND a separate .kyber seed file. Loss of any one = slot lost."
    );
    let kyber_path = ask_path(theme, "Path for the new Kyber seed (.kyber) file")?;
    if kyber_path.exists() {
        return Err(format!("{} already exists", kyber_path.display()).into());
    }

    let pin = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt("FIDO2 PIN")
            .interact()?,
    );
    let seed_pw = ask_new_passphrase(theme, "Seed-file passphrase")?;

    let mut sealer = Tpm2Sealer::new().map_err(|e| format!("{e}"))?;
    let mut auth = crate::make_fido2_authenticator();
    let user_handle = random_user_handle()?;

    eprintln!("{}", crate::auth_prompt("register a new FIDO2 credential"));
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
    eprintln!("{}", crate::auth_prompt("again to derive the FIDO2 half"));
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(&pin))?;

    eprintln!("generating {level_label} keypair...");
    let (pk, seed) = keygen_with(params);
    let (ct, pq_shared) =
        encapsulate_with(params, &pk).map_err(|e| format!("ML-KEM encapsulate: {e}"))?;

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
    c.persist_header()?;

    let sidecar = hybrid_sidecar::sidecar_path(vault);
    let mut entries = if sidecar.exists() {
        hybrid_sidecar::read(&sidecar).map_err(|e| format!("read existing hybrid sidecar: {e}"))?
    } else {
        Vec::new()
    };
    entries.push(HybridEntry {
        slot_idx: idx as u8,
        level: params,
        pubkey: pk,
        ciphertext: ct,
    });
    hybrid_sidecar::write(&sidecar, &entries).map_err(|e| format!("write hybrid sidecar: {e}"))?;

    seed_file::write(
        &kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    )
    .map_err(|e| format!("write kyber seed: {e}"))?;

    println!(
        "OK enrolled three-factor TPM + FIDO2 + {level_label} keyslot in slot {idx}\n  \
         Kyber seed: {}",
        kyber_path.display()
    );
    Ok(())
}

#[cfg(not(feature = "hardware"))]
fn enroll_hybrid_pq_tpm2_fido2_into(
    _theme: &ColorfulTheme,
    _c: &mut Container,
    _vault: &Path,
    _params: luksbox_pq::PqParams,
) -> Result<()> {
    Err("hybrid-pq-tpm2-fido2 enroll requires --features hardware".into())
}

// ---- non-TPM hybrid PQ wizard helpers --------------------------------------
//
// These mirror the GUI's "Add passphrase + ML-KEM" and "Add FIDO2 +
// ML-KEM" buttons one-for-one. No TPM, available on every platform
// (FIDO2 variants need `--features hardware` for the CTAP2 stack).
// The roll-back ordering (revoke / sidecar pop / .kyber unlink) is
// the same one the TPM-bound siblings use; see
// `enroll_hybrid_pq_tpm2_into` above for the rationale.

fn enroll_hybrid_pq_passphrase_into(
    theme: &ColorfulTheme,
    c: &mut Container,
    vault: &Path,
    params: luksbox_pq::PqParams,
) -> Result<()> {
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};

    let level_label = match params {
        PqParams::Ml768 => "ML-KEM-768",
        PqParams::Ml1024 => "ML-KEM-1024",
    };
    eprintln!(
        "Hybrid passphrase + {level_label} keyslot. KEK = HKDF(salt,\n  \
         Argon2id(passphrase) || pq_shared). Both the slot passphrase\n  \
         AND a separate .kyber seed file will be required at every unlock."
    );
    let slot_pw = ask_new_passphrase(theme, "Slot passphrase")?;
    let kyber_path = ask_path(theme, "Path for the new Kyber seed (.kyber) file")?;
    if kyber_path.exists() {
        return Err(format!("{} already exists", kyber_path.display()).into());
    }
    let seed_pw = ask_new_passphrase(theme, "Seed-file passphrase")?;

    eprintln!("generating {level_label} keypair...");
    let (pk, seed) = keygen_with(params);
    let (ct, pq_shared) =
        encapsulate_with(params, &pk).map_err(|e| format!("ML-KEM encapsulate: {e}"))?;

    let idx = match params {
        PqParams::Ml768 => {
            c.enroll_hybrid_pq_passphrase(slot_pw.as_bytes(), &pq_shared, kdf_params())?
        }
        PqParams::Ml1024 => {
            c.enroll_hybrid_pq_1024_passphrase(slot_pw.as_bytes(), &pq_shared, kdf_params())?
        }
    };
    c.persist_header()?;

    // Drop any stale sidecar entry at the same slot index. Standard
    // mode uses `first_free_slot()` so this is normally a no-op,
    // but defending against stale entries left over from a prior
    // revoke + re-enroll cycle keeps the write idempotent.
    let sidecar = hybrid_sidecar::sidecar_path(vault);
    let prior_entries: Vec<HybridEntry> = if sidecar.exists() {
        hybrid_sidecar::read(&sidecar).map_err(|e| format!("read existing hybrid sidecar: {e}"))?
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
    hybrid_sidecar::write(&sidecar, &entries).map_err(|e| format!("write hybrid sidecar: {e}"))?;

    seed_file::write(
        &kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    )
    .map_err(|e| format!("write kyber seed: {e}"))?;

    println!(
        "OK enrolled hybrid passphrase + {level_label} keyslot in slot {idx}\n  \
         Kyber seed: {} (MOVE TO SEPARATE STORAGE)",
        kyber_path.display()
    );
    Ok(())
}

fn enroll_hybrid_pq_passphrase_deniable_into(
    theme: &ColorfulTheme,
    c: &mut Container,
    vault: &Path,
    params: luksbox_pq::PqParams,
) -> Result<()> {
    use luksbox_format::deniable_header::DeniableMaterial;
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};

    let slot_idx = ask_deniable_slot_idx(theme, c)?;
    let level_label = match params {
        PqParams::Ml768 => "ML-KEM-768",
        PqParams::Ml1024 => "ML-KEM-1024",
    };
    let envelope_pw = ask_new_passphrase(theme, "Envelope passphrase for the new hybrid-PQ slot")?;
    let kyber_path = ask_path(theme, "Path for the new Kyber seed (.kyber) file")?;
    if kyber_path.exists() {
        return Err(format!("{} already exists", kyber_path.display()).into());
    }
    let seed_pw = ask_new_passphrase(theme, "Seed-file passphrase")?;

    eprintln!("generating {level_label} keypair...");
    let (pk, seed) = keygen_with(params);
    let (ct, pq_shared) =
        encapsulate_with(params, &pk).map_err(|e| format!("ML-KEM encapsulate: {e}"))?;

    let cred = luksbox_core::deniable::DeniableCredential::HybridPqPassphrase {
        passphrase: envelope_pw.as_bytes(),
        argon2: kdf_params(),
        mlkem_shared: &pq_shared,
    };
    let material = DeniableMaterial::passphrase_only();
    let idx = c.enroll_credential_v2_deniable(slot_idx, &cred, &material)?;
    c.persist_header()?;

    // Drop any stale sidecar entry for this slot index before
    // appending the new one. Deniable mode lets the user pick an
    // occupied slot_idx; install_slot_v2 overwrote it in-memory,
    // so the old (pubkey, ciphertext) is useless for the new
    // credential. Without the filter `validate_entries` would
    // reject the duplicate slot_idx at write time.
    let sidecar = hybrid_sidecar::sidecar_path(vault);
    let prior_entries: Vec<HybridEntry> = if sidecar.exists() {
        hybrid_sidecar::read(&sidecar).map_err(|e| format!("read existing hybrid sidecar: {e}"))?
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
    hybrid_sidecar::write(&sidecar, &entries).map_err(|e| format!("write hybrid sidecar: {e}"))?;

    seed_file::write(
        &kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    )
    .map_err(|e| format!("write kyber seed: {e}"))?;

    println!(
        "OK enrolled deniable hybrid passphrase + {level_label} keyslot in slot {idx}\n  \
         Kyber seed: {} (MOVE TO SEPARATE STORAGE)",
        kyber_path.display()
    );
    Ok(())
}

#[cfg(feature = "hardware")]
fn enroll_hybrid_pq_fido2_into(
    theme: &ColorfulTheme,
    c: &mut Container,
    vault: &Path,
    params: luksbox_pq::PqParams,
) -> Result<()> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};
    use rand_core::{OsRng, RngCore};

    fido2_preflight()?;
    let level_label = match params {
        PqParams::Ml768 => "ML-KEM-768",
        PqParams::Ml1024 => "ML-KEM-1024",
    };
    eprintln!(
        "Hybrid FIDO2 + {level_label} keyslot. KEK = HKDF(salt,\n  \
         hmac_secret || pq_shared) [+ optional passphrase]. Both the\n  \
         FIDO2 authenticator AND a separate .kyber seed file will be\n  \
         required at every unlock."
    );
    let pin = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt("FIDO2 PIN")
            .interact()?,
    );
    let slot_pw = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt("Optional extra passphrase (leave blank for none)")
            .allow_empty_password(true)
            .interact()?,
    );
    let slot_pw_opt: Option<&[u8]> = if slot_pw.is_empty() {
        None
    } else {
        Some(slot_pw.as_bytes())
    };
    let kyber_path = ask_path(theme, "Path for the new Kyber seed (.kyber) file")?;
    if kyber_path.exists() {
        return Err(format!("{} already exists", kyber_path.display()).into());
    }
    let seed_pw = ask_new_passphrase(theme, "Seed-file passphrase")?;

    let mut auth = crate::make_fido2_authenticator();
    let user_handle = random_user_handle()?;
    let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
    let cred_id = er.credential.id;
    let mut hmac_salt = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut hmac_salt)
        .map_err(|e| format!("OS RNG: {e}"))?;
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(&pin))?;

    eprintln!("generating {level_label} keypair...");
    let (pk, seed) = keygen_with(params);
    let (ct, pq_shared) =
        encapsulate_with(params, &pk).map_err(|e| format!("ML-KEM encapsulate: {e}"))?;

    let idx = match params {
        PqParams::Ml768 => c.enroll_hybrid_pq_fido2(
            slot_pw_opt,
            &hmac_secret,
            &pq_shared,
            &cred_id,
            hmac_salt,
            kdf_params(),
        )?,
        PqParams::Ml1024 => c.enroll_hybrid_pq_1024_fido2(
            slot_pw_opt,
            &hmac_secret,
            &pq_shared,
            &cred_id,
            hmac_salt,
            kdf_params(),
        )?,
    };
    c.persist_header()?;

    // Drop any stale entry at this slot index (defensive; standard
    // mode uses first_free_slot which is normally Empty + has no
    // prior sidecar entry).
    let sidecar = hybrid_sidecar::sidecar_path(vault);
    let prior_entries: Vec<HybridEntry> = if sidecar.exists() {
        hybrid_sidecar::read(&sidecar).map_err(|e| format!("read existing hybrid sidecar: {e}"))?
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
    hybrid_sidecar::write(&sidecar, &entries).map_err(|e| format!("write hybrid sidecar: {e}"))?;

    seed_file::write(
        &kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    )
    .map_err(|e| format!("write kyber seed: {e}"))?;

    println!(
        "OK enrolled hybrid FIDO2 + {level_label} keyslot in slot {idx}\n  \
         Kyber seed: {} (MOVE TO SEPARATE STORAGE)",
        kyber_path.display()
    );
    Ok(())
}

#[cfg(not(feature = "hardware"))]
fn enroll_hybrid_pq_fido2_into(
    _theme: &ColorfulTheme,
    _c: &mut Container,
    _vault: &Path,
    _params: luksbox_pq::PqParams,
) -> Result<()> {
    Err("hybrid-pq-fido2 enroll requires --features hardware".into())
}

#[cfg(feature = "hardware")]
fn enroll_hybrid_pq_fido2_deniable_into(
    theme: &ColorfulTheme,
    c: &mut Container,
    vault: &Path,
    params: luksbox_pq::PqParams,
) -> Result<()> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use luksbox_format::deniable_header::DeniableMaterial;
    use luksbox_format::hybrid_sidecar::{self, HybridEntry};
    use luksbox_pq::{PqParams, encapsulate_with, keygen_with, seed_file};
    use rand_core::{OsRng, RngCore};

    fido2_preflight()?;
    let slot_idx = ask_deniable_slot_idx(theme, c)?;
    let level_label = match params {
        PqParams::Ml768 => "ML-KEM-768",
        PqParams::Ml1024 => "ML-KEM-1024",
    };
    let envelope_pw = ask_new_passphrase(theme, "Envelope passphrase for the new slot")?;
    let pin = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt("FIDO2 PIN")
            .interact()?,
    );
    let kyber_path = ask_path(theme, "Path for the new Kyber seed (.kyber) file")?;
    if kyber_path.exists() {
        return Err(format!("{} already exists", kyber_path.display()).into());
    }
    let seed_pw = ask_new_passphrase(theme, "Seed-file passphrase")?;

    let mut auth = crate::make_fido2_authenticator();
    let user_handle = random_user_handle()?;
    let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
    let cred_id = er.credential.id;
    let mut hmac_salt = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut hmac_salt)
        .map_err(|e| format!("OS RNG: {e}"))?;
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, true, Some(&pin))?;

    eprintln!("generating {level_label} keypair...");
    let (pk, seed) = keygen_with(params);
    let (ct, pq_shared) =
        encapsulate_with(params, &pk).map_err(|e| format!("ML-KEM encapsulate: {e}"))?;

    let cred = luksbox_core::deniable::DeniableCredential::HybridPqFido2Passphrase {
        passphrase: envelope_pw.as_bytes(),
        argon2: kdf_params(),
        mlkem_shared: &pq_shared,
        hmac_secret_output: &hmac_secret,
    };
    let material = DeniableMaterial {
        cred_id: cred_id.clone(),
        hmac_salt: Some(hmac_salt),
        tpm_blob: Vec::new(),
    };
    let idx = c.enroll_credential_v2_deniable(slot_idx, &cred, &material)?;
    c.persist_header()?;

    // Drop any stale entry at this slot index. Deniable mode lets
    // the user pick an occupied index and `install_slot_v2`
    // silently overwrote the old credential; the old sidecar
    // entry's (pk, ct) is useless for the new credential.
    let sidecar = hybrid_sidecar::sidecar_path(vault);
    let prior_entries: Vec<HybridEntry> = if sidecar.exists() {
        hybrid_sidecar::read(&sidecar).map_err(|e| format!("read existing hybrid sidecar: {e}"))?
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
    hybrid_sidecar::write(&sidecar, &entries).map_err(|e| format!("write hybrid sidecar: {e}"))?;

    seed_file::write(
        &kyber_path,
        &seed,
        seed_pw.as_bytes(),
        seed_file::KdfParams::default(),
    )
    .map_err(|e| format!("write kyber seed: {e}"))?;

    println!(
        "OK enrolled deniable hybrid FIDO2 + {level_label} keyslot in slot {idx}\n  \
         Kyber seed: {} (MOVE TO SEPARATE STORAGE)",
        kyber_path.display()
    );
    Ok(())
}

#[cfg(not(feature = "hardware"))]
fn enroll_hybrid_pq_fido2_deniable_into(
    _theme: &ColorfulTheme,
    _c: &mut Container,
    _vault: &Path,
    _params: luksbox_pq::PqParams,
) -> Result<()> {
    Err("hybrid-pq-fido2 deniable enroll requires --features hardware".into())
}

// ---- TPM 2.0 unlock helpers ------------------------------------------------

#[cfg(feature = "hardware")]
fn unlock_via_tpm2(
    theme: &ColorfulTheme,
    vault: &Path,
    header_path: Option<&Path>,
    header: &Header,
) -> Result<Container> {
    use luksbox_tpm::{SealedBlob, Tpm2Sealer};

    let has_pin_slot = header
        .keyslots
        .iter()
        .any(|s| s.kind == SlotKind::Tpm2SealedPin);

    let pin: Option<zeroize::Zeroizing<String>> = if has_pin_slot {
        Some(zeroize::Zeroizing::new(
            Password::with_theme(theme)
                .with_prompt("TPM PIN")
                .interact()?,
        ))
    } else {
        None
    };
    let pin_bytes: Option<Vec<u8>> = pin.as_ref().map(|p| p.as_bytes().to_vec());

    let mut sealer = Tpm2Sealer::new().map_err(|e| format!("{e}"))?;
    let mut unseal = move |blob: &[u8]| -> std::result::Result<[u8; 32], String> {
        let parsed =
            SealedBlob::from_bytes(blob).map_err(|e| format!("malformed TPM SealedBlob: {e}"))?;
        let kek = match sealer.unseal(&parsed) {
            Ok(k) => k,
            Err(_) if pin_bytes.is_some() => sealer
                .unseal_with_pin(&parsed, pin_bytes.as_deref())
                .map_err(|e| format!("TPM unseal (with PIN): {e}"))?,
            Err(e) => return Err(format!("TPM unseal: {e}")),
        };
        let mut out = [0u8; 32];
        out.copy_from_slice(kek.as_slice());
        Ok(out)
    };
    Container::open(
        vault,
        header_path,
        UnlockMaterial::Tpm2 {
            unseal: &mut unseal,
        },
    )
    .map_err(Into::into)
}

#[cfg(not(feature = "hardware"))]
fn unlock_via_tpm2(
    _theme: &ColorfulTheme,
    _vault: &Path,
    _header_path: Option<&Path>,
    _header: &Header,
) -> Result<Container> {
    Err("TPM 2.0 support not compiled in".into())
}

/// Generalized macOS Secure Enclave unlock. Iterates every SEP slot
/// whose factor profile matches (`want_fido2` / `want_pq`; the
/// passphrase factor is auto-detected per-slot), collects the
/// matching extra factors, and hands `Container::open` an
/// `UnlockMaterial::Sep` whose factor set the core dispatcher uses to
/// pick the right slot. The wizard analog of `crate::open_sep_common`.
#[cfg(feature = "hardware")]
fn unlock_via_sep_common(
    theme: &ColorfulTheme,
    vault: &Path,
    header_path: Option<&Path>,
    header: &Header,
    want_fido2: bool,
    want_pq: bool,
) -> Result<Container> {
    use luksbox_sep::{SepBlob, SepSealer};

    // Hybrid kinds: load the .kyber seed + sidecar once.
    let pq_ctx = if want_pq {
        use luksbox_format::hybrid_sidecar;
        use luksbox_pq::seed_file;
        let kyber_path = ask_path(theme, "Path to the Kyber seed (.kyber) file")?;
        if !kyber_path.is_file() {
            return Err(format!("{} is not a file", kyber_path.display()).into());
        }
        let seed_pw = zeroize::Zeroizing::new(
            Password::with_theme(theme)
                .with_prompt(".kyber seed-file passphrase")
                .interact()?,
        );
        let seed = seed_file::read(&kyber_path, seed_pw.as_bytes())
            .map_err(|e| format!("read kyber seed: {e}"))?;
        let sidecar_path = hybrid_sidecar::sidecar_path(vault);
        let entries = hybrid_sidecar::read(&sidecar_path)
            .map_err(|e| format!("read hybrid sidecar at {}: {e}", sidecar_path.display()))?;
        Some((seed, entries))
    } else {
        None
    };

    // Prompt the slot passphrase once if any matching slot needs it.
    let needs_pp = header.keyslots.iter().any(|s| {
        s.kind.is_sep()
            && s.kind.is_sep_passphrase()
            && s.kind.is_hybrid_pq() == want_pq
            && s.kind.is_sep_fido2() == want_fido2
    });
    let passphrase = if needs_pp {
        Some(zeroize::Zeroizing::new(
            Password::with_theme(theme)
                .with_prompt("Slot passphrase")
                .interact()?,
        ))
    } else {
        None
    };

    // FIDO2 PIN once if we're collecting FIDO2 halves.
    let fido2_pin = if want_fido2 {
        fido2_preflight()?;
        Some(wizard_prompt_fido2_pin(theme)?)
    } else {
        None
    };

    let mut sealer = SepSealer::new().map_err(|e| format!("{e}"))?;
    let mut last_err: Option<String> = None;

    for (idx, slot) in header.keyslots.iter().enumerate() {
        if !slot.kind.is_sep()
            || slot.kind.is_hybrid_pq() != want_pq
            || slot.kind.is_sep_fido2() != want_fido2
        {
            continue;
        }

        // PQ shared secret for this slot.
        let pq = match &pq_ctx {
            Some((seed, entries)) => {
                use luksbox_format::hybrid_sidecar;
                let entry = match hybrid_sidecar::find(entries, idx as u8) {
                    Some(e) => e,
                    None => {
                        last_err = Some(format!("no hybrid sidecar entry for slot {idx}"));
                        continue;
                    }
                };
                match luksbox_pq::decapsulate_with(entry.level, seed, &entry.ciphertext) {
                    Ok(s) => Some(s),
                    Err(e) => {
                        last_err = Some(format!("decap slot {idx}: {e}"));
                        continue;
                    }
                }
            }
            None => None,
        };

        // FIDO2 hmac-secret for this slot (derived from stored cred_id).
        let hmac_secret = if want_fido2 {
            let pin = fido2_pin.as_ref().expect("want_fido2 implies a PIN");
            match wizard_sep_fido2_hmac(slot, pin) {
                Ok(hs) => Some(hs),
                Err(e) => {
                    last_err = Some(format!("FIDO2 slot {idx}: {e}"));
                    continue;
                }
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
            vault,
            header_path,
            UnlockMaterial::Sep {
                unseal: &mut unseal,
                hmac_secret: hmac_secret.as_ref(),
                passphrase: passphrase.as_ref().map(|p| p.as_bytes()),
                pq_shared: pq.as_deref(),
            },
        ) {
            Ok(c) => return Ok(c),
            Err(e) => last_err = Some(format!("open slot {idx}: {e}")),
        }
    }
    Err(last_err
        .unwrap_or_else(|| "no matching Secure Enclave slot opened".into())
        .into())
}

/// Derive the FIDO2 hmac-secret half for a SEP+FIDO2 slot in the
/// wizard, from the slot's stored cred_id + hmac_salt.
#[cfg(feature = "hardware")]
fn wizard_sep_fido2_hmac(
    slot: &luksbox_core::Keyslot,
    pin: &str,
) -> std::result::Result<[u8; 32], String> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID};
    let cred = &slot.fido2_cred_id;
    if cred.is_empty() {
        return Err("SEP+FIDO2 slot has no stored cred_id".into());
    }
    let mut auth = crate::make_fido2_authenticator();
    eprintln!("Touch your FIDO2 authenticator to unlock the SEP+FIDO2 slot...");
    let prehash_first = slot.fido2_salt_prehashed();
    for prehash in [prehash_first, !prehash_first] {
        if let Ok(hs) = auth.hmac_secret(RP_ID, cred, &slot.fido2_hmac_salt, prehash, Some(pin)) {
            return Ok(*hs);
        }
    }
    Err("FIDO2 hmac-secret derivation failed".into())
}

#[cfg(feature = "hardware")]
fn unlock_via_sep(
    theme: &ColorfulTheme,
    vault: &Path,
    header_path: Option<&Path>,
    header: &Header,
) -> Result<Container> {
    unlock_via_sep_common(theme, vault, header_path, header, false, false)
}

#[cfg(feature = "hardware")]
fn unlock_via_sep_fido2(
    theme: &ColorfulTheme,
    vault: &Path,
    header_path: Option<&Path>,
    header: &Header,
) -> Result<Container> {
    unlock_via_sep_common(theme, vault, header_path, header, true, false)
}

#[cfg(feature = "hardware")]
fn unlock_via_hybrid_pq_sep(
    theme: &ColorfulTheme,
    vault: &Path,
    header_path: Option<&Path>,
    header: &Header,
) -> Result<Container> {
    unlock_via_sep_common(theme, vault, header_path, header, false, true)
}

#[cfg(feature = "hardware")]
fn unlock_via_hybrid_pq_sep_fido2(
    theme: &ColorfulTheme,
    vault: &Path,
    header_path: Option<&Path>,
    header: &Header,
) -> Result<Container> {
    unlock_via_sep_common(theme, vault, header_path, header, true, true)
}

#[cfg(not(feature = "hardware"))]
fn unlock_via_sep(
    _theme: &ColorfulTheme,
    _vault: &Path,
    _header_path: Option<&Path>,
    _header: &Header,
) -> Result<Container> {
    Err("Secure Enclave support not compiled in".into())
}

#[cfg(not(feature = "hardware"))]
fn unlock_via_sep_fido2(
    _theme: &ColorfulTheme,
    _vault: &Path,
    _header_path: Option<&Path>,
    _header: &Header,
) -> Result<Container> {
    Err("Secure Enclave support not compiled in".into())
}

#[cfg(not(feature = "hardware"))]
fn unlock_via_hybrid_pq_sep(
    _theme: &ColorfulTheme,
    _vault: &Path,
    _header_path: Option<&Path>,
    _header: &Header,
) -> Result<Container> {
    Err("hybrid-pq-sep unlock requires --features hardware".into())
}

#[cfg(not(feature = "hardware"))]
fn unlock_via_hybrid_pq_sep_fido2(
    _theme: &ColorfulTheme,
    _vault: &Path,
    _header_path: Option<&Path>,
    _header: &Header,
) -> Result<Container> {
    Err("hybrid-pq-sep unlock requires --features hardware".into())
}

#[cfg(feature = "hardware")]
fn unlock_via_tpm2_fido2(
    theme: &ColorfulTheme,
    vault: &Path,
    header_path: Option<&Path>,
    header: &Header,
) -> Result<Container> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID};
    use luksbox_tpm::{SealedBlob, Tpm2Sealer};

    let pin = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt("FIDO2 PIN")
            .interact()?,
    );
    let mut sealer = Tpm2Sealer::new().map_err(|e| format!("{e}"))?;
    let mut auth = crate::make_fido2_authenticator();
    let mut last_err: Option<String> = None;
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
            crate::auth_prompt(&format!(
                "fused TPM+FIDO2 unlock (cred_id {} B)",
                stored_cred.len()
            ))
        );
        let hmac_secret = match auth.hmac_secret(
            RP_ID,
            &stored_cred,
            &slot.fido2_hmac_salt,
            slot.fido2_salt_prehashed(),
            Some(&pin),
        ) {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(format!("FIDO2: {e}"));
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
            vault,
            header_path,
            UnlockMaterial::Tpm2Fido2 {
                unseal: &mut unseal,
                cred_id: &stored_cred,
                hmac_secret: &hmac_secret,
            },
        ) {
            Ok(c) => return Ok(c),
            Err(e) => last_err = Some(format!("{e}")),
        }
    }
    Err(last_err
        .unwrap_or_else(|| "no Tpm2Fido2 slot matched".into())
        .into())
}

#[cfg(not(feature = "hardware"))]
fn unlock_via_tpm2_fido2(
    _theme: &ColorfulTheme,
    _vault: &Path,
    _header_path: Option<&Path>,
    _header: &Header,
) -> Result<Container> {
    Err("TPM 2.0 + FIDO2 unlock requires --features hardware".into())
}

#[cfg(feature = "hardware")]
fn unlock_via_hybrid_pq_tpm2(
    theme: &ColorfulTheme,
    vault: &Path,
    header_path: Option<&Path>,
    header: &Header,
) -> Result<Container> {
    use luksbox_format::hybrid_sidecar;
    use luksbox_pq::seed_file;
    use luksbox_tpm::{SealedBlob, Tpm2Sealer};

    let kyber_path = ask_path(theme, "Path to the Kyber seed (.kyber) file")?;
    if !kyber_path.is_file() {
        return Err(format!("{} is not a file", kyber_path.display()).into());
    }
    let seed_pw = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt(".kyber seed-file passphrase")
            .interact()?,
    );
    let seed = seed_file::read(&kyber_path, seed_pw.as_bytes())
        .map_err(|e| format!("read kyber seed: {e}"))?;

    let sidecar_path = hybrid_sidecar::sidecar_path(vault);
    let entries = hybrid_sidecar::read(&sidecar_path)
        .map_err(|e| format!("read hybrid sidecar at {}: {e}", sidecar_path.display()))?;

    let mut sealer = Tpm2Sealer::new().map_err(|e| format!("{e}"))?;
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
            vault,
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
        .unwrap_or_else(|| "no hybrid-pq-tpm2 slot opened".into())
        .into())
}

#[cfg(not(feature = "hardware"))]
fn unlock_via_hybrid_pq_tpm2(
    _theme: &ColorfulTheme,
    _vault: &Path,
    _header_path: Option<&Path>,
    _header: &Header,
) -> Result<Container> {
    Err("hybrid-pq-tpm2 unlock requires --features hardware".into())
}

#[cfg(feature = "hardware")]
fn unlock_via_hybrid_pq_tpm2_fido2(
    theme: &ColorfulTheme,
    vault: &Path,
    header_path: Option<&Path>,
    header: &Header,
) -> Result<Container> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID};
    use luksbox_format::hybrid_sidecar;
    use luksbox_pq::seed_file;
    use luksbox_tpm::{SealedBlob, Tpm2Sealer};

    let kyber_path = ask_path(theme, "Path to the Kyber seed (.kyber) file")?;
    if !kyber_path.is_file() {
        return Err(format!("{} is not a file", kyber_path.display()).into());
    }
    let pin = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt("FIDO2 PIN")
            .interact()?,
    );
    let seed_pw = zeroize::Zeroizing::new(
        Password::with_theme(theme)
            .with_prompt(".kyber seed-file passphrase")
            .interact()?,
    );
    let seed = seed_file::read(&kyber_path, seed_pw.as_bytes())
        .map_err(|e| format!("read kyber seed: {e}"))?;

    let sidecar_path = hybrid_sidecar::sidecar_path(vault);
    let entries = hybrid_sidecar::read(&sidecar_path).map_err(|e| format!("read sidecar: {e}"))?;

    let mut sealer = Tpm2Sealer::new().map_err(|e| format!("{e}"))?;
    let mut auth = crate::make_fido2_authenticator();
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
                last_err = Some(format!("no hybrid sidecar entry for slot {slot_idx}"));
                continue;
            }
        };
        eprintln!(
            "{}",
            crate::auth_prompt(&format!("3-factor unlock (slot {slot_idx})"))
        );
        let hmac_secret = match auth.hmac_secret(
            RP_ID,
            &stored_cred,
            &slot.fido2_hmac_salt,
            slot.fido2_salt_prehashed(),
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
                last_err = Some(format!("decap slot {slot_idx}: {e}"));
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
            vault,
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
        .unwrap_or_else(|| "no hybrid-pq-tpm2-fido2 slot opened".into())
        .into())
}

#[cfg(not(feature = "hardware"))]
fn unlock_via_hybrid_pq_tpm2_fido2(
    _theme: &ColorfulTheme,
    _vault: &Path,
    _header_path: Option<&Path>,
    _header: &Header,
) -> Result<Container> {
    Err("hybrid-pq-tpm2-fido2 unlock requires --features hardware".into())
}
