// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Interactive wizard for the luksbox CLI. Driven by `dialoguer` prompts;
//! reuses the same `Container` / `Vfs` plumbing as the regular subcommands,
//! so anything done here is byte-equivalent to running the matching CLI flag.
//!
//! The wizard supports every feature the subcommands do:
//!   - inline and detached-header vaults (`--header` equivalent);
//!   - all three keyslot kinds at create time (passphrase, fido2 wrap, fido2-direct);
//!   - unlocking via passphrase or FIDO2 against either keyslot kind;
//!   - put / get / cat / mkdir / rm / rmdir;
//!   - keyslot enroll / revoke;
//!   - background or foreground mount.

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
            4 => panic_by_path(&theme),
            5 => return Ok(()),
            _ => unreachable!(),
        };
        if let Err(e) = r {
            eprintln!("✗ {e}");
        }
        println!();
    }
}

fn genpass_action() -> Result<()> {
    let pw = crate::passphrase::generate()?;
    println!("{}", &*pw);
    Ok(())
}

/// Destroy a vault without first unlocking it. Useful for emergency wipes
/// where you don't want to (or can't) authenticate first. Asks for the
/// vault path, optional sidecar header path, and uses the same shred
/// procedure as `panic_action`.
fn panic_by_path(theme: &ColorfulTheme) -> Result<()> {
    let vault = ask_path(theme, "Path to vault to destroy")?;
    if !vault.is_file() {
        return Err(format!("{} is not a file", vault.display()).into());
    }
    let header_target = if Confirm::with_theme(theme)
        .with_prompt("Does this vault use a detached header (sidecar)?")
        .default(false)
        .interact()?
    {
        let p = ask_path(theme, "Path to the sidecar header file")?;
        if !p.is_file() {
            return Err(format!("{} is not a file", p.display()).into());
        }
        p
    } else {
        vault.clone()
    };
    let wipe_data = Confirm::with_theme(theme)
        .with_prompt("ALSO overwrite the entire vault data area? (slow)")
        .default(false)
        .interact()?;
    eprintln!(
        "⚠ PANIC: about to overwrite the {} of {} with random bytes.",
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

    use rand_core::{OsRng, RngCore};
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom, Write};

    let mut hf = OpenOptions::new().write(true).open(&header_target)?;
    let mut buf = [0u8; HEADER_SIZE];
    OsRng.fill_bytes(&mut buf);
    hf.seek(SeekFrom::Start(0))?;
    hf.write_all(&buf)?;
    hf.flush()?;
    eprintln!("✓ header at {} overwritten", header_target.display());

    if wipe_data {
        let mut vf = OpenOptions::new().write(true).open(&vault)?;
        let len = std::fs::metadata(&vault)?.len();
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
        eprintln!("✓ vault {} ({} bytes) wiped", vault.display(), len);
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
        let s = Password::with_theme(theme)
            .with_prompt(prompt)
            .with_confirmation("Confirm", "passphrases don't match")
            .interact()?;
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
        return Ok(zeroize::Zeroizing::new(s));
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
                 size from disk-level forensics within a 2× bucket; up to 2× storage cost)",
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
    }
}

fn print_slots(header: &Header, with_kdf: bool) {
    println!("keyslots:");
    for (i, s) in header.keyslots.iter().enumerate() {
        println!("{}", format_slot(i, s, with_kdf));
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
    let kind_choice = Select::with_theme(theme)
        .with_prompt("Initial keyslot kind")
        .items(&items)
        .default(0)
        .interact()?;

    // FIDO2-direct + all four hybrid kinds + all TPM kinds skip
    // pad/hide-sizes prompts (they have their own follow-on prompts
    // and the size-hardening flags don't apply to keyslot wrapping).
    let opts = ask_create_options(theme, matches!(kind_choice, 2 | 3 | 4 | 5 | 6 | 7..=13))?;

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
         If the chip fails or you reinstall the OS, that slot is gone.\n  \
         As a safety net we'll create a passphrase keyslot FIRST and keep\n  \
         it as a backup. You can revoke it later from the keyslot manager\n  \
         if you really want a single-factor TPM-only vault."
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
    // Without this the user types the passphrase, waits 500 ms on
    // Argon2id, THEN sees the permission-denied error - and now has
    // a passphrase-only vault on disk that doesn't reflect what they
    // asked for.
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
    // Pre-flight FIDO2 too if the chosen TPM kind needs an
    // authenticator (fused TPM+FIDO2 or 3-factor). Catches missing
    // device upfront rather than after the bootstrap-passphrase
    // create.
    if matches!(kind, TpmBootstrap::Fido2 | TpmBootstrap::HybridPqFido2(_)) {
        fido2_preflight()?;
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
        "✓ created {} (bootstrapping with backup passphrase; TPM keyslot will move to slot 0)",
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
        eprintln!("✗ TPM enroll failed: {e}");
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
        if sidecar.exists() {
            if let Ok(mut entries) = luksbox_format::hybrid_sidecar::read(&sidecar) {
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
    }
    cont.persist_header()?;
    println!("✓ moved TPM keyslot to slot 0 (backup passphrase now in slot 1)");

    if Confirm::with_theme(theme)
        .with_prompt("Revoke the backup passphrase now? (NOT recommended; loses the recovery path)")
        .default(false)
        .interact()?
    {
        cont.revoke_slot(1)?;
        cont.persist_header()?;
        println!("✓ backup passphrase revoked. Vault is now TPM-only.");
    } else {
        println!("✓ backup passphrase retained in slot 1 (recovery path preserved)");
    }

    maybe_mount_now(theme, cont, vault)
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
    println!("✓ created {}", vault.display());

    if Confirm::with_theme(theme)
        .with_prompt("Enroll a FIDO2 keyslot now? (recommended)")
        .default(true)
        .interact()?
    {
        if let Err(e) = enroll_fido2_into(theme, &mut cont) {
            eprintln!("✗ FIDO2 enroll failed: {e}");
            eprintln!("  (vault still usable via passphrase; you can try again later)");
        }
    }

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
        let pin = Password::with_theme(theme)
            .with_prompt("FIDO2 PIN")
            .interact()?;
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
        let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(&pin))?;

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
            "✓ created {} with FIDO2 wrap-style keyslot",
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

        let pin = Password::with_theme(theme)
            .with_prompt("FIDO2 PIN")
            .interact()?;
        let mut auth = crate::make_fido2_authenticator();
        let user_handle = random_user_handle()?;

        eprintln!("{}", crate::auth_prompt("register a new credential"));
        let er = auth.enroll(RP_ID, &user_handle, Some(&pin))?;
        let cred_id = er.credential.id;
        let mut hmac_salt = [0u8; 32];
        OsRng.fill_bytes(&mut hmac_salt);
        eprintln!("{}", crate::auth_prompt("again to derive the MVK"));
        let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(&pin))?;

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
        println!("✓ created {} (FIDO2-direct, MVK derived)", vault.display());

        if Confirm::with_theme(theme)
            .with_prompt("Enroll a passphrase backup keyslot now? (strongly recommended unless you have a strict no-recovery policy)")
            .default(true)
            .interact()?
        {
            let pw = ask_new_passphrase(theme, "Backup passphrase")?;
            eprintln!("Stretching with Argon2id (about 500 ms)...");
            let idx = cont.enroll_passphrase(pw.as_bytes(), kdf_params())?;
            cont.persist_header()?;
            println!("✓ passphrase backup enrolled in slot {idx}");
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
    println!("✓ created {} (hybrid-pq, {level_label})", vault.display());
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

    let pin = Password::with_theme(theme)
        .with_prompt("FIDO2 PIN")
        .interact()?;
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
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(&pin))?;

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
        "✓ created {} (hybrid-pq-fido2, FIDO2 + {level_label})",
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
        } else if let Some(i) = options.iter().position(|o| *o == "FIDO2 authenticator") {
            i
        } else {
            0
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

    let mut cont = match options[pick] {
        "Passphrase" => {
            let pw = Password::with_theme(theme)
                .with_prompt("Passphrase")
                .interact()?;
            Container::open(
                &vault,
                header_path.as_deref(),
                UnlockMaterial::Passphrase(pw.as_bytes()),
            )?
        }
        "FIDO2 authenticator" => unlock_via_fido2(theme, &vault, header_path.as_deref(), &header)?,
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
        _ => unreachable!(),
    };
    let trusted_anchor_gen = if let Some(ap) = anchor_path.as_deref() {
        cont.set_anchor(Some(ap.to_path_buf()))?
    } else {
        None
    };
    let vfs = Vfs::open(cont)?;
    if let Some(anchor_gen) = trusted_anchor_gen {
        match anchor::compare(anchor_gen, vfs.vault_generation()) {
            anchor::VerificationOutcome::Ok => {
                eprintln!("  ✓ anchor matches vault (generation {anchor_gen})");
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
    println!("✓ opened {}", vault.display());
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
            eprintln!("✗ {e}");
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
    println!("✓ wrote {n} bytes to {inner}");
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
    println!("✓ wrote {n} bytes to {}", local.display());
    Ok(())
}

fn mkdir_action(theme: &ColorfulTheme, vfs: &mut Vfs) -> Result<()> {
    let inner: String = Input::with_theme(theme)
        .with_prompt("Directory path inside vault")
        .interact_text()?;
    let (parent, name) = split_parent_name(vfs, &inner)?;
    vfs.mkdir(parent, &name)?;
    vfs.flush()?;
    println!("✓ created {inner}");
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
    println!("✓ removed {inner}");
    Ok(())
}

fn rmdir_action(theme: &ColorfulTheme, vfs: &mut Vfs) -> Result<()> {
    let inner: String = Input::with_theme(theme)
        .with_prompt("Empty directory to remove")
        .interact_text()?;
    let (parent, name) = split_parent_name(vfs, &inner)?;
    vfs.rmdir(parent, &name)?;
    vfs.flush()?;
    println!("✓ removed {inner}");
    Ok(())
}

fn mv_action(theme: &ColorfulTheme, vfs: &mut Vfs) -> Result<()> {
    let old: String = Input::with_theme(theme)
        .with_prompt("Existing path inside vault")
        .interact_text()?;
    let new: String = Input::with_theme(theme)
        .with_prompt("New path (must be in the same parent directory)")
        .interact_text()?;
    let (old_parent, old_name) = split_parent_name(vfs, &old)?;
    let (new_parent, new_name) = split_parent_name(vfs, &new)?;
    if old_parent != new_parent {
        return Err("cross-directory rename is not supported in v1".into());
    }
    vfs.rename(old_parent, &old_name, &new_name)?;
    vfs.flush()?;
    println!("✓ renamed {old} -> {new}");
    Ok(())
}

fn mount_action(theme: &ColorfulTheme, vfs: Vfs, vault: &Path) -> Result<()> {
    // Per-OS mountpoint convention: existing empty dir on
    // Linux/macOS (FUSE), drive letter / non-existent path on
    // Windows (WinFsp). See cmd_mount in main.rs for the full
    // explanation. The wizard prompt phrasing is platform-conditional
    // so users aren't told to "pick an existing directory" on
    // Windows where that would yield STATUS_OBJECT_NAME_COLLISION.
    let prompt = if cfg!(target_os = "windows") {
        "Mount point (a drive letter like Z: or a non-existent path WinFsp will create)"
    } else {
        "Mount point (must be an existing empty directory)"
    };
    let mp = ask_path(theme, prompt)?;
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
    luksbox_mount::mount(vfs, &mp_abs, daemonize)?;
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
                let pp = Password::with_theme(theme)
                    .with_prompt(format!("passphrase for slot {idx}"))
                    .interact()?;
                SlotCredential::Passphrase {
                    slot_idx: *idx,
                    passphrase: zeroize::Zeroizing::new(pp),
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
        "✓ MVK rotated. {} keyslot(s) rebuilt with fresh salts.",
        populated.len()
    );
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

    let pin = Password::with_theme(theme)
        .with_prompt("FIDO2 PIN")
        .interact()?;
    let slot = &cont.header.keyslots[slot_idx];
    let cred_id = slot.fido2_cred_id.clone();
    let mut auth = crate::make_fido2_authenticator();

    eprintln!("{}", crate::auth_prompt(&format!("verify slot {slot_idx}")));
    let old = auth.hmac_secret(RP_ID, &cred_id, &slot.fido2_hmac_salt, Some(&pin))?;

    let mut new_hmac_salt = [0u8; 32];
    OsRng.fill_bytes(&mut new_hmac_salt);
    eprintln!(
        "{}",
        crate::auth_prompt("again to derive the new wrap secret")
    );
    let new = auth.hmac_secret(RP_ID, &cred_id, &new_hmac_salt, Some(&pin))?;

    Ok(SlotCredential::Fido2Wrap {
        slot_idx,
        passphrase: None,
        hmac_secret_for_verify: zeroize::Zeroizing::new(old),
        hmac_secret_for_new_wrap: zeroize::Zeroizing::new(new),
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
        "⚠ PANIC: about to overwrite the {} of {} with random bytes.",
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
        "✓ header at {} overwritten with random",
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
            "✓ vault file at {} ({} bytes) wiped\n  \
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

        // TPM-bound add options only on Linux. Build the menu list
        // dynamically and remap the choice index back to the static
        // 0..=11 dispatch positions so the existing match arms stay
        // unchanged.
        let mut menu: Vec<&'static str> = vec![
            "Add a passphrase keyslot",
            "Add a FIDO2 keyslot (wrap-style)",
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

        // Index remap: on Linux, choice == action. On non-Linux, the
        // 7 TPM entries are absent so action 9..=11 (update/revoke/
        // back) come at choice 2..=4.
        #[cfg(target_os = "linux")]
        let action = choice;
        #[cfg(not(target_os = "linux"))]
        let action = match choice {
            0 | 1 => choice,
            2 => 9,
            3 => 10,
            4 => 11,
            _ => unreachable!(),
        };

        let r: Result<()> = match action {
            0 => {
                let pw = ask_new_passphrase(theme, "New passphrase")?;
                eprintln!("Stretching with Argon2id (around 500 ms)...");
                let idx = cont.enroll_passphrase(pw.as_bytes(), kdf_params())?;
                cont.persist_header()?;
                println!("✓ enrolled passphrase in slot {idx}");
                Ok(())
            }
            1 => enroll_fido2_into(theme, &mut cont),
            #[cfg(target_os = "linux")]
            2 => enroll_tpm2_into(theme, &mut cont),
            #[cfg(target_os = "linux")]
            3 => enroll_tpm2_pin_into(theme, &mut cont),
            #[cfg(target_os = "linux")]
            4 => enroll_tpm2_fido2_into(theme, &mut cont),
            #[cfg(target_os = "linux")]
            5 => {
                let vp = cont.vault_path().to_path_buf();
                enroll_hybrid_pq_tpm2_into(theme, &mut cont, &vp, luksbox_pq::PqParams::Ml768)
            }
            #[cfg(target_os = "linux")]
            6 => {
                let vp = cont.vault_path().to_path_buf();
                enroll_hybrid_pq_tpm2_into(theme, &mut cont, &vp, luksbox_pq::PqParams::Ml1024)
            }
            #[cfg(target_os = "linux")]
            7 => {
                let vp = cont.vault_path().to_path_buf();
                enroll_hybrid_pq_tpm2_fido2_into(theme, &mut cont, &vp, luksbox_pq::PqParams::Ml768)
            }
            #[cfg(target_os = "linux")]
            8 => {
                let vp = cont.vault_path().to_path_buf();
                enroll_hybrid_pq_tpm2_fido2_into(
                    theme,
                    &mut cont,
                    &vp,
                    luksbox_pq::PqParams::Ml1024,
                )
            }
            9 => update_keyslot_action(theme, &mut cont),
            10 => {
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
                    println!("✓ slot {pick} revoked");
                }
                Ok(())
            }
            11 => return Ok(cont),
            _ => unreachable!(),
        };
        if let Err(e) = r {
            eprintln!("✗ {e}");
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
    println!("✓ slot {slot_idx} updated");
    Ok(())
}

#[cfg(feature = "hardware")]
fn update_fido2_in(theme: &ColorfulTheme, c: &mut Container, slot_idx: usize) -> Result<()> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID, random_user_handle};
    use rand_core::{OsRng, RngCore};

    fido2_preflight()?;
    let pin = Password::with_theme(theme)
        .with_prompt("FIDO2 PIN")
        .interact()?;
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
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(&pin))?;

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
    let pin = Password::with_theme(theme)
        .with_prompt("FIDO2 PIN")
        .interact()?;
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
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(&pin))?;

    let idx = c.enroll_fido2(None, &hmac_secret, &cred_id, hmac_salt, kdf_params())?;
    c.persist_header()?;
    println!("✓ enrolled FIDO2 credential in slot {idx}");
    Ok(())
}

#[cfg(not(feature = "hardware"))]
fn enroll_fido2_into(_theme: &ColorfulTheme, _c: &mut Container) -> Result<()> {
    Err("FIDO2 hardware support not compiled in".into())
}

#[cfg(feature = "hardware")]
fn unlock_via_fido2(
    theme: &ColorfulTheme,
    vault: &Path,
    header_path: Option<&Path>,
    header: &Header,
) -> Result<Container> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID};

    let pin = Password::with_theme(theme)
        .with_prompt("FIDO2 PIN")
        .interact()?;
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
    let pw = Password::with_theme(theme)
        .with_prompt("Passphrase")
        .interact()?;
    let seed =
        seed_file::read(&kyber_path, pw.as_bytes()).map_err(|e| format!("read kyber seed: {e}"))?;
    let sidecar = hybrid_sidecar::sidecar_path(vault);
    let entries = hybrid_sidecar::read(&sidecar)
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
    let pin = Password::with_theme(theme)
        .with_prompt("FIDO2 PIN")
        .interact()?;
    let seed_pw = Password::with_theme(theme)
        .with_prompt(".kyber seed-file passphrase")
        .interact()?;
    let seed = seed_file::read(&kyber_path, seed_pw.as_bytes())
        .map_err(|e| format!("read kyber seed: {e}"))?;

    let sidecar = hybrid_sidecar::sidecar_path(vault);
    let entries = hybrid_sidecar::read(&sidecar).map_err(|e| format!("read sidecar: {e}"))?;

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
        "✓ enrolled TPM 2.0 keyslot in slot {idx} (sealed {} B)",
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
    println!("✓ enrolled PIN-protected TPM 2.0 keyslot in slot {idx}");
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
    let pin = Password::with_theme(theme)
        .with_prompt("FIDO2 PIN")
        .interact()?;
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
    eprintln!(
        "{}",
        crate::auth_prompt("touch again to derive the FIDO2 half")
    );
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
        "✓ enrolled fused TPM+FIDO2 keyslot in slot {idx} (cred_id {} B, sealed {} B)",
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
        "✓ enrolled hybrid TPM 2.0 + {level_label} keyslot in slot {idx}\n  \
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

    let pin = Password::with_theme(theme)
        .with_prompt("FIDO2 PIN")
        .interact()?;
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
    eprintln!(
        "{}",
        crate::auth_prompt("touch again to derive the FIDO2 half")
    );
    let hmac_secret = auth.hmac_secret(RP_ID, &cred_id, &hmac_salt, Some(&pin))?;

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
        "✓ enrolled three-factor TPM + FIDO2 + {level_label} keyslot in slot {idx}\n  \
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

#[cfg(feature = "hardware")]
fn unlock_via_tpm2_fido2(
    theme: &ColorfulTheme,
    vault: &Path,
    header_path: Option<&Path>,
    header: &Header,
) -> Result<Container> {
    use luksbox_fido2::{Fido2Authenticator, RP_ID};
    use luksbox_tpm::{SealedBlob, Tpm2Sealer};

    let pin = Password::with_theme(theme)
        .with_prompt("FIDO2 PIN")
        .interact()?;
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
        let hmac_secret =
            match auth.hmac_secret(RP_ID, &stored_cred, &slot.fido2_hmac_salt, Some(&pin)) {
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
    let seed_pw = Password::with_theme(theme)
        .with_prompt(".kyber seed-file passphrase")
        .interact()?;
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
    let pin = Password::with_theme(theme)
        .with_prompt("FIDO2 PIN")
        .interact()?;
    let seed_pw = Password::with_theme(theme)
        .with_prompt(".kyber seed-file passphrase")
        .interact()?;
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
