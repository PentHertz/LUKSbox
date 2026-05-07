// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! All UI views in one place. Single update loop, immediate-mode.
//!
//! State machine sketch:
//!   View::Welcome -> user picks Create / Open / Recent
//!   View::Create  -> fills CreateForm, hits Create -> spawns op -> on Ok jumps to Browser
//!   View::Unlock  -> fills UnlockForm, hits Unlock -> spawns op -> on Ok jumps to Browser
//!   View::Browser -> manages cwd, file list, keyslots, lock
//!   PendingOp     -> in-flight background work; UI shows a "waiting..." overlay

use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::time::Duration;

use egui::{
    Align, Color32, CornerRadius, Frame, Layout, Margin, RichText, ScrollArea, Stroke, Vec2,
};
use zeroize::Zeroizing;

use luksbox_core::SlotKind;
use luksbox_vfs::InodeKind;

use crate::clipboard_guard;
use crate::ops::{self, KdfStrength, OpenedVault, PassgenOpts, SlotKindArg, UnlockMethod};
use crate::preferences;
use crate::recent::{self, RecentVault};
use crate::theme;

/// Sidebar logo. Replace `crates/luksbox-gui/assets/logo.png` with your
/// branding (transparent PNG) and rebuild. Sizing is controlled by
/// `LOGO_MAX_HEIGHT_PX` below, bump it for a bigger logo.
const LOGO_PNG: &[u8] = include_bytes!("../assets/logo.png");

/// Max height in pixels for the sidebar logo. Width is implicit (the
/// PNG aspect is preserved up to the sidebar's available width).
/// Default = 120 px. Try 160 or 200 for a chunkier brand.
const LOGO_MAX_HEIGHT_PX: f32 = 120.0;

/// Modal that lets the user dial in length + charset before generating.
/// `target` says which form field will receive the picked passphrase.
/// `preview` is `Zeroizing<String>` so the heap buffer is wiped when
/// the dialog is dropped (cancel, accept, regenerate, app exit) -
/// passphrases are short-lived secrets and shouldn't linger in the
/// allocator's freelists.
struct PassgenDialog {
    opts: PassgenOpts,
    preview: zeroize::Zeroizing<String>,
    target: PassgenTarget,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PassgenTarget {
    /// Just show the result; user copies and pastes elsewhere.
    Standalone,
    /// Fill `create.passphrase` on accept.
    CreatePrimary,
    /// Fill `create.backup_passphrase` on accept.
    CreateBackup,
    /// Fill the in-flight `add_passphrase_modal` keyslot field on accept.
    AddKeyslotPassphrase,
}

// ---- view enum ------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Welcome,
    Create,
    Unlock,
    Browser,
    Keyslots,
    Panic,
    About,
}

/// Deferred navigation that an open vault is blocking. Set when the
/// user clicks something that would abandon the currently-open vault
/// (open another, create a new one, go to PANIC); cleared when the
/// confirm-lock modal returns Yes (action runs) or No (action drops).
///
/// Carrying the action around the modal turn means the modal is the
/// only place that talks to `lock_and_drop_vault`; every "would
/// switch vaults" call site just hands a NavigateAction in via
/// `request_navigate` and forgets about the open-vault question.
#[derive(Clone)]
enum NavigateAction {
    OpenRecent(RecentVault),
    OpenPicker,
    GoCreate,
    GoPanic,
    GoWelcome,
}

/// Top-level factor for the create-vault picker. Lets the user pick
/// the broad kind (Passphrase / FIDO2 / TPM) first, then a specific
/// variant within that factor. Avoids a flat 14-radio list.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Factor {
    Passphrase,
    Fido2,
    Tpm2,
}
impl Factor {
    fn label(self) -> &'static str {
        match self {
            Self::Passphrase => "Passphrase only",
            Self::Fido2 => "FIDO2 authenticator",
            Self::Tpm2 => "TPM 2.0 (this machine)",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CreateKind {
    Passphrase,
    Fido2,
    Fido2Direct,
    HybridPq,
    HybridPqFido2,
    HybridPq1024,
    HybridPq1024Fido2,
    /// TPM 2.0 bootstrap. The vault is actually created with a
    /// passphrase first (kept as a backup so the chip dying doesn't
    /// orphan the vault); the TPM slot is then added immediately
    /// after creation. The `passphrase` field is the backup.
    Tpm2,
    /// TPM 2.0 + PIN bootstrap. Same pattern as `Tpm2` plus a PIN
    /// bound to the chip's `userAuth`. The `pin` field carries the
    /// TPM PIN (NOT a FIDO2 PIN); `passphrase` is the backup.
    Tpm2Pin,
    /// Fused TPM 2.0 + FIDO2 bootstrap. Both factors required at
    /// every unlock. The `pin` field is the FIDO2 PIN; `passphrase`
    /// is the backup.
    Tpm2Fido2,
    /// Hybrid PQ + TPM bootstrap (ML-KEM-768). Requires the .kyber
    /// seed file path + a seed-file passphrase + the local TPM. Backup
    /// passphrase still kept in slot 0.
    HybridPqTpm2,
    /// Hybrid PQ + TPM bootstrap (ML-KEM-1024). Same shape as
    /// `HybridPqTpm2` with the strongest PQ parameter set.
    HybridPq1024Tpm2,
    /// 3-factor: hybrid PQ + TPM + FIDO2 (ML-KEM-768). Backup
    /// passphrase + .kyber seed + FIDO2 PIN; the chip and key are
    /// both required at every unlock.
    HybridPqTpm2Fido2,
    /// 3-factor: hybrid PQ + TPM + FIDO2 (ML-KEM-1024).
    HybridPq1024Tpm2Fido2,
}
impl CreateKind {
    fn to_arg(self) -> SlotKindArg {
        match self {
            Self::Passphrase => SlotKindArg::Passphrase,
            Self::Fido2 => SlotKindArg::Fido2,
            Self::Fido2Direct => SlotKindArg::Fido2Direct,
            Self::HybridPq => SlotKindArg::HybridPq,
            Self::HybridPqFido2 => SlotKindArg::HybridPqFido2,
            Self::HybridPq1024 => SlotKindArg::HybridPq1024,
            Self::HybridPq1024Fido2 => SlotKindArg::HybridPq1024Fido2,
            // TPM kinds bootstrap as Passphrase: the vault is
            // actually created with the backup passphrase, then the
            // TPM slot is added in a follow-on step (see
            // `submit_create_tpm` / `create_vault_with_tpm_bootstrap`).
            Self::Tpm2
            | Self::Tpm2Pin
            | Self::Tpm2Fido2
            | Self::HybridPqTpm2
            | Self::HybridPq1024Tpm2
            | Self::HybridPqTpm2Fido2
            | Self::HybridPq1024Tpm2Fido2 => SlotKindArg::Passphrase,
        }
    }
    /// True for any of the TPM-bootstrap kinds, used to gate the
    /// recovery-warning panel and the post-create TPM-add follow-up.
    fn is_tpm_bootstrap(self) -> bool {
        matches!(
            self,
            Self::Tpm2
                | Self::Tpm2Pin
                | Self::Tpm2Fido2
                | Self::HybridPqTpm2
                | Self::HybridPq1024Tpm2
                | Self::HybridPqTpm2Fido2
                | Self::HybridPq1024Tpm2Fido2
        )
    }
    /// Which factor this kind belongs to. Drives the 2-step picker:
    /// the Factor radio group is the top control, then the matching
    /// CreateKind sub-radios appear below.
    fn factor(self) -> Factor {
        match self {
            Self::Passphrase | Self::HybridPq | Self::HybridPq1024 => Factor::Passphrase,
            Self::Fido2 | Self::Fido2Direct | Self::HybridPqFido2 | Self::HybridPq1024Fido2 => {
                Factor::Fido2
            }
            Self::Tpm2
            | Self::Tpm2Pin
            | Self::Tpm2Fido2
            | Self::HybridPqTpm2
            | Self::HybridPq1024Tpm2
            | Self::HybridPqTpm2Fido2
            | Self::HybridPq1024Tpm2Fido2 => Factor::Tpm2,
        }
    }
    /// True iff the kind needs a FIDO2 touch (and prompts for a FIDO2 PIN).
    fn needs_fido2(self) -> bool {
        matches!(
            self,
            Self::Fido2
                | Self::Fido2Direct
                | Self::HybridPqFido2
                | Self::HybridPq1024Fido2
                | Self::Tpm2Fido2
                | Self::HybridPqTpm2Fido2
                | Self::HybridPq1024Tpm2Fido2
        )
    }
}

#[derive(Clone, PartialEq, Eq)]
enum CipherChoice {
    /// AES-256-GCM-SIV (RFC 8452). Default for new vaults.
    /// Nonce-misuse-resistant, same 12/16 nonce-tag wire shape as
    /// vanilla GCM.
    AesSiv,
    /// AES-256-GCM (legacy). Kept for compatibility with existing
    /// vaults; faster but catastrophic on nonce reuse.
    Aes,
    Chacha,
}

// ---- form state -----------------------------------------------------------

struct CreateForm {
    path: String,
    use_detached: bool,
    header_path: String,
    cipher: CipherChoice,
    kind: CreateKind,
    /// Wrapped in `Zeroizing` so the String's heap bytes are wiped
    /// when the form is dropped (view transition, vault create).
    /// Eg-text-edit binding uses `&mut *self.create.passphrase` to
    /// borrow the inner `String` for `egui::TextEdit::singleline`.
    passphrase: Zeroizing<String>,
    backup_passphrase: Zeroizing<String>,
    pin: Zeroizing<String>,
    use_anchor: bool,
    anchor_path: String,
    pad_files: bool,
    hide_sizes: bool,
    /// Path to write the .kyber seed file when kind == HybridPq.
    hybrid_kyber_path: String,
    /// Optional at-rest password that encrypts the .kyber seed file
    /// for hybrid-PQ kinds. The unlock form prompts for this
    /// separately as "Seed-file passphrase". Leave empty to reuse
    /// the slot-0 backup passphrase (the legacy default that the
    /// previous wizard / GUI used unconditionally).
    hybrid_seed_pw: Zeroizing<String>,
    kdf: KdfStrength,
}

impl Default for CreateForm {
    fn default() -> Self {
        Self {
            path: String::new(),
            use_detached: false,
            header_path: String::new(),
            cipher: CipherChoice::AesSiv,
            kind: CreateKind::Passphrase,
            passphrase: Zeroizing::default(),
            backup_passphrase: Zeroizing::default(),
            pin: Zeroizing::default(),
            use_anchor: false,
            anchor_path: String::new(),
            pad_files: false,
            hide_sizes: false,
            hybrid_kyber_path: String::new(),
            hybrid_seed_pw: Zeroizing::default(),
            kdf: KdfStrength::Interactive,
        }
    }
}

struct UnlockForm {
    path: String,
    header_path: String,
    anchor_path: String,
    use_detached: bool,
    use_anchor: bool,
    method: UnlockMethod,
    /// Wrapped in `Zeroizing` so the heap bytes are wiped when the
    /// form is dropped (Back button, vault open success).
    passphrase: Zeroizing<String>,
    pin: Zeroizing<String>,
    /// Path to the .kyber seed file when method == HybridPq.
    hybrid_kyber_path: String,
    /// One-shot snapshot of the vault's keyslot composition, read
    /// from the unencrypted on-disk header when the user picks a
    /// vault from the recent list. Some(Ok) = labels to show, Some(Err)
    /// = error message to surface, None = not loaded yet (e.g. the
    /// user typed a path manually instead of clicking a recent).
    slot_inspection: Option<Result<Vec<String>, String>>,
}

impl Default for UnlockForm {
    fn default() -> Self {
        Self {
            path: String::new(),
            header_path: String::new(),
            anchor_path: String::new(),
            use_detached: false,
            use_anchor: false,
            method: UnlockMethod::Passphrase,
            passphrase: Zeroizing::default(),
            pin: Zeroizing::default(),
            hybrid_kyber_path: String::new(),
            slot_inspection: None,
        }
    }
}

#[derive(Clone)]
/// One row in the rotate-master-key modal, slot index + passphrase
/// being collected from the user.
struct RotateSlotInput {
    slot_idx: usize,
    passphrase: Zeroizing<String>,
}

/// State for the in-progress rotate-master-key modal.
struct RotateForm {
    entries: Vec<RotateSlotInput>,
    kdf: KdfStrength,
}

struct AddPassphraseForm {
    passphrase: Zeroizing<String>,
    kdf: KdfStrength,
}

impl Default for AddPassphraseForm {
    fn default() -> Self {
        Self {
            passphrase: Zeroizing::default(),
            kdf: KdfStrength::Interactive,
        }
    }
}

#[derive(Default)]
struct PanicForm {
    vault: String,
    header_path: String,
    use_detached: bool,
    wipe_data: bool,
    confirmation: String,
}

/// State for the "Add TPM 2.0 + PIN keyslot" modal. Two PIN fields
/// for typo-protection (entering the wrong PIN at enroll would
/// permanently lock the slot since the chip refuses unseal without
/// the matching PIN).
#[derive(Default)]
struct AddTpm2PinForm {
    pin: Zeroizing<String>,
    pin_confirm: Zeroizing<String>,
}

/// State for the "Add hybrid TPM + ML-KEM" modal. Captures both the
/// destination .kyber path (kept on separate trusted storage) and the
/// passphrase that encrypts that file at rest. `kem_size` is 768 or
/// 1024.
struct AddHybridTpm2Form {
    kyber_path: String,
    seed_pw: Zeroizing<String>,
    seed_pw_confirm: Zeroizing<String>,
    kem_size: u16,
}

impl AddHybridTpm2Form {
    fn new(kem_size: u16) -> Self {
        Self {
            kyber_path: String::new(),
            seed_pw: Zeroizing::default(),
            seed_pw_confirm: Zeroizing::default(),
            kem_size,
        }
    }
}

/// Which submit path triggered the empty-passphrase warning modal.
/// On confirm we re-fire the matching submit with the bypass flag
/// set; on cancel we just clear the state and let the user keep
/// editing the form.
#[derive(Clone, Copy)]
enum EmptyPassphraseTarget {
    /// User clicked "Create vault" with an empty passphrase field
    /// for a kind that needs a passphrase. Empty = no protection.
    CreateVault,
    /// User clicked "Create vault" for FIDO2-direct with the
    /// backup-passphrase field empty. Empty backup = lose the FIDO2
    /// authenticator and the vault is unrecoverable.
    Fido2DirectBackup,
    /// User clicked "Enroll" inside the "Add passphrase keyslot"
    /// modal with the passphrase field empty.
    AddPassphraseKeyslot,
}

/// State for the 3-factor "Add hybrid TPM + FIDO2 + ML-KEM" modal.
/// Adds a FIDO2 PIN field on top of `AddHybridTpm2Form`.
struct AddHybridTpm2Fido2Form {
    kyber_path: String,
    seed_pw: Zeroizing<String>,
    seed_pw_confirm: Zeroizing<String>,
    fido2_pin: Zeroizing<String>,
    kem_size: u16,
}

impl AddHybridTpm2Fido2Form {
    fn new(kem_size: u16) -> Self {
        Self {
            kyber_path: String::new(),
            seed_pw: Zeroizing::default(),
            seed_pw_confirm: Zeroizing::default(),
            fido2_pin: Zeroizing::default(),
            kem_size,
        }
    }
}

// ---- pending op tracker ---------------------------------------------------

/// Result envelope used by ops that take ownership of the Vfs on a
/// worker thread. Worker sends BOTH the vault (so the GUI can keep
/// using it) AND the operation result on a single channel. This lets
/// the main thread set `pending` *before* the slow op starts, which is
/// essential for the FIDO2 touch overlay (and any spinner) to render.
type VaultRet<T> = (OpenedVault, Result<T, String>);

enum Pending {
    /// Background re-enumeration of FIDO2 devices. Result is the
    /// fresh `(path, label)` list. Triggered at startup and when the
    /// user clicks "Refresh FIDO2" or the device dropdown's
    /// "Re-detect" entry.
    Fido2Probe(Receiver<Result<Vec<(String, String)>, String>>),
    Create {
        rx: Receiver<Result<OpenedVault, String>>,
        needs_touch: bool,
    },
    Unlock {
        rx: Receiver<Result<OpenedVault, String>>,
        needs_touch: bool,
    },
    /// Atomic "create with TPM bootstrap": create+enroll on the same
    /// worker thread. On failure the worker has already deleted the
    /// partial files, so the GUI just surfaces the error and stays
    /// on the create form. Replaces the older chain via Pending::Create
    /// -> Pending::EnrollTpm2 which silently left a passphrase-only
    /// vault on disk if the TPM enroll failed.
    CreateWithTpmBootstrap {
        rx: Receiver<Result<OpenedVault, String>>,
        needs_touch: bool,
    },
    PutFile {
        rx: Receiver<VaultRet<u64>>,
        name: String,
    },
    GetFile {
        rx: Receiver<VaultRet<u64>>,
    },
    EnrollPassphrase {
        rx: Receiver<VaultRet<usize>>,
    },
    EnrollFido2 {
        rx: Receiver<VaultRet<usize>>,
    },
    EnrollTpm2 {
        rx: Receiver<VaultRet<usize>>,
    },
    EnrollTpm2Pin {
        rx: Receiver<VaultRet<usize>>,
    },
    EnrollTpm2Fido2 {
        rx: Receiver<VaultRet<usize>>,
    },
    EnrollHybridPqTpm2 {
        rx: Receiver<VaultRet<usize>>,
    },
    EnrollHybridPqTpm2Fido2 {
        rx: Receiver<VaultRet<usize>>,
    },
    Panic(Receiver<Result<(), String>>),
    /// Master-key rotation in flight. The worker owns the moved-out
    /// `OpenedVault` and returns it on Ok; we re-install the vault
    /// into `self.vault` in the poll handler.
    RotateMvk(Receiver<Result<OpenedVault, String>>),
}

impl Pending {
    fn label(&self) -> String {
        // The "touch your authenticator" copy is wrong for Windows
        // Hello (no touch - face / fingerprint / PIN). Detect the
        // selected device path and word the prompt accordingly so
        // users aren't waiting to tap something that isn't there.
        let is_winhello = ops::selected_fido2_device()
            .as_deref()
            .map(luksbox_fido2::is_windows_hello_path)
            .unwrap_or(false);
        let auth_verb = if is_winhello {
            "authenticate with Windows Hello (face / fingerprint / PIN)"
        } else {
            "touch your FIDO2 authenticator"
        };
        match self {
            Pending::Fido2Probe(_) => "probing for FIDO2 authenticators...".to_string(),
            Pending::Create {
                needs_touch: true, ..
            } => format!("creating vault, {auth_verb} when prompted"),
            Pending::Create {
                needs_touch: false, ..
            } => "stretching passphrase with Argon2id...".to_string(),
            Pending::Unlock {
                needs_touch: true, ..
            } => format!("unlocking, {auth_verb} when prompted"),
            Pending::Unlock {
                needs_touch: false, ..
            } => "stretching passphrase with Argon2id...".to_string(),
            Pending::CreateWithTpmBootstrap {
                needs_touch: true, ..
            } => format!(
                "creating vault + sealing under the local TPM 2.0 ({auth_verb} for the FIDO2 half)"
            ),
            Pending::CreateWithTpmBootstrap {
                needs_touch: false, ..
            } => "creating vault + sealing under the local TPM 2.0...".to_string(),
            Pending::PutFile { .. } => "encrypting file...".to_string(),
            Pending::GetFile { .. } => "decrypting...".to_string(),
            Pending::EnrollPassphrase { .. } => {
                "stretching passphrase with Argon2id...".to_string()
            }
            Pending::EnrollFido2 { .. } => format!("registering credential - {auth_verb}"),
            Pending::EnrollTpm2 { .. } => "sealing key under the local TPM 2.0...".to_string(),
            Pending::EnrollTpm2Pin { .. } => {
                "sealing key under the local TPM 2.0 with PIN-binding...".to_string()
            }
            Pending::EnrollTpm2Fido2 { .. } => {
                format!("fused TPM+FIDO2 enroll - {auth_verb} + sealing under the local TPM 2.0")
            }
            Pending::EnrollHybridPqTpm2 { .. } => {
                "hybrid TPM + ML-KEM enroll: sealing TPM half + generating Kyber keypair..."
                    .to_string()
            }
            Pending::EnrollHybridPqTpm2Fido2 { .. } => {
                format!("3-factor TPM+FIDO2+ML-KEM enroll - {auth_verb} + TPM seal + Kyber keygen")
            }
            Pending::Panic(_) => "wiping...".to_string(),
            Pending::RotateMvk(_) => {
                "rotating master key (re-encrypting every chunk)...".to_string()
            }
        }
    }

    fn needs_touch(&self) -> bool {
        matches!(
            self,
            Pending::Create {
                needs_touch: true,
                ..
            } | Pending::Unlock {
                needs_touch: true,
                ..
            } | Pending::CreateWithTpmBootstrap {
                needs_touch: true,
                ..
            } | Pending::EnrollFido2 { .. }
                | Pending::EnrollTpm2Fido2 { .. }
                | Pending::EnrollHybridPqTpm2Fido2 { .. }
        )
    }
}

// ---- toast ----------------------------------------------------------------

struct Toast {
    text: String,
    kind: ToastKind,
    deadline: std::time::Instant,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ToastKind {
    Ok,
    Err,
    Warn,
}

// ---- the App --------------------------------------------------------------

pub struct LuksboxApp {
    view: View,
    /// All FIDO2 authenticators currently visible to libfido2,
    /// `(path, label)`. Refreshed at startup and on demand from the
    /// sidebar. Multiple entries are common on Windows where Windows
    /// Hello shows up alongside any plugged-in physical key.
    fido_devices: Vec<(String, String)>,
    /// Index into `fido_devices` of the currently-selected
    /// authenticator. `None` when no devices are present OR when the
    /// previously-selected device disappeared between probes.
    /// The selected device is also pushed into `ops::set_selected_fido2_device`
    /// so background ops use the right authenticator without
    /// threading the choice through every options struct.
    selected_fido_idx: Option<usize>,
    recent_list: Vec<RecentVault>,
    create: CreateForm,
    unlock: UnlockForm,
    panic: PanicForm,
    vault: Option<OpenedVault>,
    cwd: String,
    listing: Vec<DirEntry>,
    listing_err: Option<String>,
    pending: Option<Pending>,
    toasts: Vec<Toast>,
    passgen_dialog: Option<PassgenDialog>,
    add_passphrase_modal: Option<AddPassphraseForm>,
    /// PIN typed into the "add FIDO2 keyslot" modal. Wrapped in
    /// `Zeroizing` so the buffer is wiped on cancel / submit / drop.
    add_fido2_pin_modal: Option<Zeroizing<String>>,
    /// PIN typed into the "add fused TPM+FIDO2 keyslot" modal. Same
    /// shape as `add_fido2_pin_modal`; separate field so the two
    /// flows can't collide if the user opens both in quick
    /// succession.
    add_tpm2_fido2_pin_modal: Option<Zeroizing<String>>,
    /// PIN entered in the "Add TPM 2.0 + PIN" modal. The PIN binds
    /// the sealed object to the chip's `userAuth` so unseal needs
    /// it. Two-field confirmation prevents typo lockout.
    add_tpm2_pin_modal: Option<AddTpm2PinForm>,
    /// Form state for the "Add hybrid TPM 2.0 + ML-KEM(-1024)" modal.
    /// Captures the destination .kyber path + the seed-file passphrase
    /// + the chosen ML-KEM size (768 / 1024).
    add_hybrid_tpm2_modal: Option<AddHybridTpm2Form>,
    /// Form state for the 3-factor "Add hybrid TPM + FIDO2 + ML-KEM"
    /// modal. Adds a FIDO2 PIN field on top of `AddHybridTpm2Form`.
    add_hybrid_tpm2_fido2_modal: Option<AddHybridTpm2Fido2Form>,
    /// When a TPM-bootstrap CreateKind was selected, the create flow
    /// first creates the vault with a passphrase; once that succeeds
    /// and the vault is installed in `self.vault`, this field triggers
    /// the follow-up TPM enroll. Cleared once the enroll dispatches.
    /// "Empty passphrase, are you sure?" confirm modal target. Set
    /// when the user submits a create / add-passphrase form with an
    /// empty passphrase; the matching submit re-fires after the user
    /// confirms.
    empty_passphrase_confirm: Option<EmptyPassphraseTarget>,
    /// Active master-key-rotation modal. `None` outside the
    /// rotation flow. See `draw_rotate_modal`.
    rotate_modal: Option<RotateForm>,
    mkdir_input: Option<String>,
    rename_target: Option<RenameTarget>,
    mount_status: Option<MountStatus>,
    /// A file/folder picker running on a background thread. Some rfd
    /// dialogs (notably `save_file()` on Wayland with broken
    /// xdg-desktop-portal) hang when called from egui's main thread,
    /// this offloads them so the GUI stays responsive.
    pending_picker: Option<PendingPicker>,
    /// Navigation the user requested while a vault is still open.
    /// `Some(action)` triggers the "Lock current vault?" modal; on
    /// confirmation we drop the vault and run the action, on cancel
    /// we drop the action and stay on the current view.
    confirm_lock: Option<NavigateAction>,
    /// Active clipboard auto-clear job. `Some` between the moment the
    /// user clicks "Copy to clipboard" and the deadline (default 30 s
    /// later). The per-frame `tick_clipboard_guard` checks expiry and
    /// hash-clears the OS clipboard if the user hasn't overwritten it.
    clipboard_guard: Option<clipboard_guard::Guard>,
    /// Persisted preferences (currently just the
    /// "I've seen the clipboard-history warning" flag).
    prefs: preferences::Preferences,
    /// `Some` while the one-time clipboard-warning modal is on screen.
    /// Holds the passphrase + target that triggered it; on "I
    /// understand", we proceed with the actual copy + guard
    /// installation. On cancel, we abort the copy entirely.
    pending_clipboard_warning: Option<zeroize::Zeroizing<String>>,
    /// `Some` while the user is being asked to confirm a keyslot
    /// revocation. Revoking a slot is destructive (the wrapped MVK
    /// for that credential is lost forever); a one-click bare
    /// "Revoke" button is too easy to mis-click. The modal forces a
    /// second click and surfaces a stronger warning when the slot is
    /// the LAST active credential on the vault (revoking it would
    /// permanently lock the user out).
    revoke_confirm: Option<RevokeConfirm>,
}

/// In-flight keyslot-revocation confirmation. Carries the slot index,
/// its kind (so the modal copy can name what's being revoked), and a
/// flag for the "this would lock you out forever" upgrade path.
struct RevokeConfirm {
    slot_idx: usize,
    slot_kind: SlotKind,
    would_be_last_active_slot: bool,
}

struct PendingPicker {
    rx: std::sync::mpsc::Receiver<Option<std::path::PathBuf>>,
    target: PickerTarget,
}

#[derive(Clone, Copy)]
enum PickerTarget {
    /// Write the picked path into `create.hybrid_kyber_path`.
    CreateHybridKyber,
    /// Write the picked path into `unlock.hybrid_kyber_path`.
    UnlockHybridKyber,
    /// Write the picked path into `create.anchor_path`.
    CreateAnchor,
    /// Write the picked path into the active "Add hybrid TPM 2.0 +
    /// ML-KEM" or "Add 3-factor TPM + FIDO2 + ML-KEM" modal's
    /// `kyber_path` field.
    AddHybridKyber,
}

/// In-flight rename. The user picked a row; we keep the original name
/// (so we can call `vfs.rename(parent, old, new)`) and a buffer the
/// modal binds to.
struct RenameTarget {
    old_name: String,
    buf: String,
    is_dir: bool,
}

/// Live FUSE/WinFsp mount. While present, the Vfs has been moved into
/// the mount thread and the browser shows a "mounted" placeholder.
/// The receiver fires when the mount thread exits (clean unmount or
/// crash); on either we drop back to Welcome.
struct MountStatus {
    mountpoint: PathBuf,
    rx: std::sync::mpsc::Receiver<Result<(), String>>,
    unmount_requested: bool,
}

#[derive(Clone)]
struct DirEntry {
    name: String,
    kind: InodeKind,
    size: u64,
}

impl LuksboxApp {
    /// Construct the app with an optional pre-selected vault. The path
    /// comes from the CLI (or Nautilus's "Open with LUKSbox" -> Exec=%f
    /// on a .lbx file). When set we land directly on the Unlock view
    /// with that path filled in, so the user just types their
    /// passphrase / taps their authenticator.
    pub fn new_with_vault(initial_vault: Option<std::path::PathBuf>) -> Self {
        let mut unlock = UnlockForm::default();
        let mut view = View::Welcome;
        if let Some(p) = initial_vault {
            unlock.path = p.to_string_lossy().into_owned();
            view = View::Unlock;
        }
        let mut s = Self {
            view,
            fido_devices: Vec::new(),
            selected_fido_idx: None,
            recent_list: recent::load(),
            create: CreateForm::default(),
            unlock,
            panic: PanicForm::default(),
            vault: None,
            cwd: "/".into(),
            listing: Vec::new(),
            listing_err: None,
            pending: None,
            toasts: Vec::new(),
            passgen_dialog: None,
            add_passphrase_modal: None,
            add_fido2_pin_modal: None,
            add_tpm2_fido2_pin_modal: None,
            add_tpm2_pin_modal: None,
            add_hybrid_tpm2_modal: None,
            add_hybrid_tpm2_fido2_modal: None,
            empty_passphrase_confirm: None,
            rotate_modal: None,
            mkdir_input: None,
            rename_target: None,
            mount_status: None,
            pending_picker: None,
            confirm_lock: None,
            clipboard_guard: None,
            prefs: preferences::load(),
            pending_clipboard_warning: None,
            revoke_confirm: None,
        };
        // Cheap initial probe so the welcome banner + sidebar reflect
        // which FIDO2 authenticators are available before the user
        // touches anything.
        s.pending = Some(Pending::Fido2Probe(ops::spawn(|| {
            Ok(ops::detect_fido2_devices())
        })));
        s
    }

    fn toast_ok(&mut self, t: impl Into<String>) {
        self.push_toast(t.into(), ToastKind::Ok);
    }
    fn toast_err(&mut self, t: impl Into<String>) {
        self.push_toast(t.into(), ToastKind::Err);
    }
    fn toast_warn(&mut self, t: impl Into<String>) {
        self.push_toast(t.into(), ToastKind::Warn);
    }
    fn push_toast(&mut self, text: String, kind: ToastKind) {
        self.toasts.push(Toast {
            text,
            kind,
            deadline: std::time::Instant::now() + Duration::from_secs(5),
        });
    }

    /// Spawn a save-file dialog on a worker thread so egui's main
    /// loop stays responsive even if the system file-picker portal
    /// hangs. Result is delivered via `pending_picker.rx` and applied
    /// in `poll_picker`.
    fn start_save_picker(&mut self, title: &str, default_name: &str, target: PickerTarget) {
        if self.pending_picker.is_some() {
            return; // one at a time
        }
        let title = title.to_string();
        let default_name = default_name.to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let r = rfd::FileDialog::new()
                .set_title(&title)
                .set_file_name(&default_name)
                .save_file();
            let _ = tx.send(r);
        });
        self.pending_picker = Some(PendingPicker { rx, target });
    }

    fn start_open_picker(&mut self, title: &str, target: PickerTarget) {
        if self.pending_picker.is_some() {
            return;
        }
        let title = title.to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let r = rfd::FileDialog::new().set_title(&title).pick_file();
            let _ = tx.send(r);
        });
        self.pending_picker = Some(PendingPicker { rx, target });
    }

    /// Polled each frame from `update`. If the worker thread has
    /// returned a path, write it into the target field.
    fn poll_picker(&mut self) {
        let Some(p) = self.pending_picker.take() else {
            return;
        };
        match p.rx.try_recv() {
            Ok(Some(path)) => {
                let s = path.display().to_string();
                match p.target {
                    PickerTarget::CreateHybridKyber => self.create.hybrid_kyber_path = s,
                    PickerTarget::UnlockHybridKyber => self.unlock.hybrid_kyber_path = s,
                    PickerTarget::CreateAnchor => self.create.anchor_path = s,
                    PickerTarget::AddHybridKyber => {
                        // Whichever add-keyslot modal is currently
                        // open gets the path. Only one of these
                        // modals is open at a time (mutually
                        // exclusive in the UI flow).
                        if let Some(form) = self.add_hybrid_tpm2_modal.as_mut() {
                            form.kyber_path = s.clone();
                        }
                        if let Some(form) = self.add_hybrid_tpm2_fido2_modal.as_mut() {
                            form.kyber_path = s;
                        }
                    }
                }
            }
            Ok(None) => {}
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                self.pending_picker = Some(p);
            }
            Err(_) => {}
        }
    }

    fn open_passgen(&mut self, target: PassgenTarget) {
        let opts = PassgenOpts::default();
        let preview = zeroize::Zeroizing::new(ops::generate_passphrase_with(&opts));
        self.passgen_dialog = Some(PassgenDialog {
            opts,
            preview,
            target,
        });
    }

    fn refresh_listing(&mut self) {
        self.listing.clear();
        self.listing_err = None;
        let Some(v) = self.vault.as_mut() else {
            return;
        };
        match v.vfs.lookup_path(&self.cwd) {
            Ok(id) => match v.vfs.readdir(id) {
                Ok(mut entries) => {
                    entries.sort_by(|a, b| a.name.cmp(&b.name));
                    for ent in entries {
                        let st = match v.vfs.stat(ent.id) {
                            Ok(s) => s,
                            Err(e) => {
                                self.listing_err = Some(e.to_string());
                                return;
                            }
                        };
                        self.listing.push(DirEntry {
                            name: ent.name,
                            kind: ent.kind,
                            size: st.size,
                        });
                    }
                }
                Err(e) => self.listing_err = Some(e.to_string()),
            },
            Err(e) => self.listing_err = Some(e.to_string()),
        }
    }
}

// ---- update loop ----------------------------------------------------------

impl eframe::App for LuksboxApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        // Live zoom controls, Ctrl+= / Ctrl+- step the egui zoom
        // factor in 0.1 increments; Ctrl+0 resets to 1.0. Useful on
        // fractional-DPI handhelds (GPD, Steam Deck, Surface Go, etc.)
        // where the OS-reported scale + egui's hit-rect rounding drift
        // produces dead-zones in the bottom-right of long pages.
        // Persistent override via env var: LUKSBOX_GUI_ZOOM=1.5
        ctx.input_mut(|i| {
            let ctrl = i.modifiers.command;
            if ctrl
                && (i.consume_key(egui::Modifiers::COMMAND, egui::Key::Equals)
                    || i.consume_key(egui::Modifiers::COMMAND, egui::Key::Plus))
            {
                let z = (ctx.zoom_factor() + 0.1).min(4.0);
                ctx.set_zoom_factor(z);
            }
            if ctrl && i.consume_key(egui::Modifiers::COMMAND, egui::Key::Minus) {
                let z = (ctx.zoom_factor() - 0.1).max(0.5);
                ctx.set_zoom_factor(z);
            }
            if ctrl && i.consume_key(egui::Modifiers::COMMAND, egui::Key::Num0) {
                ctx.set_zoom_factor(1.0);
            }
        });

        // Drive pending ops; repaint quickly while one is in flight.
        self.poll_pending(&ctx);
        self.poll_mount();
        self.poll_picker();
        // Clipboard auto-clear runs on every frame because the deadline
        // can elapse between paints. `tick_clipboard_guard` is a no-op
        // when no guard is active.
        self.tick_clipboard_guard(&ctx);
        if self.pending.is_some() || self.mount_status.is_some() || self.pending_picker.is_some() {
            ctx.request_repaint_after(Duration::from_millis(120));
        }

        // Keep the sidebar compact. The controls inside the sidebar
        // size to available width, so long status text cannot force a
        // wider visual gap before the divider.
        egui::Panel::left("sidebar")
            .exact_size(262.0)
            .resizable(false)
            .frame(
                Frame::default()
                    .fill(theme::PANEL)
                    .stroke(Stroke::new(1.0, theme::BORDER))
                    .inner_margin(Margin {
                        left: 14,
                        right: 14,
                        top: 16,
                        bottom: 16,
                    }),
            )
            .show_inside(ui, |ui| self.draw_sidebar(ui));

        // Central content. Each view that needs a primary action bar
        // (Create, Unlock) draws it INSIDE the central panel as a normal
        // ui.horizontal at the top, easier to reason about than nested
        // Panel::bottom calls and not subject to egui panel-layout
        // surprises.
        egui::CentralPanel::default()
            .frame(Frame::default().fill(theme::BG).inner_margin(Margin {
                left: 8,
                right: 32,
                top: 24,
                bottom: 24,
            }))
            .show_inside(ui, |ui| match self.view {
                View::Welcome => self.draw_welcome(ui),
                View::Create => self.draw_create(ui),
                View::Unlock => self.draw_unlock(ui),
                View::Browser => self.draw_browser(ui),
                View::Keyslots => self.draw_keyslots(ui),
                View::Panic => self.draw_panic(ui),
                View::About => self.draw_about(ui),
            });

        // Overlays last (drawn on top of everything).
        self.draw_pending_overlay(&ctx);
        self.draw_modals(&ctx);
        self.draw_toasts(&ctx);
    }
}

// ---- pending op polling ---------------------------------------------------

impl LuksboxApp {
    fn poll_pending(&mut self, _ctx: &egui::Context) {
        let Some(p) = self.pending.take() else {
            return;
        };
        match p {
            Pending::Fido2Probe(rx) => match rx.try_recv() {
                Ok(Ok(devices)) => {
                    // Try to preserve the user's selection across
                    // re-enumerations: if the previously-chosen device
                    // path is still present, keep it selected; if it's
                    // gone, fall back to index 0 (or None when the list
                    // is empty). Push the result through to ops so
                    // background workers pick the same device.
                    let prior_path = self
                        .selected_fido_idx
                        .and_then(|i| self.fido_devices.get(i).map(|(p, _)| p.clone()));
                    self.fido_devices = devices;
                    self.selected_fido_idx = match prior_path {
                        Some(p) => self
                            .fido_devices
                            .iter()
                            .position(|(path, _)| path == &p)
                            .or_else(|| (!self.fido_devices.is_empty()).then_some(0)),
                        None => (!self.fido_devices.is_empty()).then_some(0),
                    };
                    ops::set_selected_fido2_device(
                        self.selected_fido_idx
                            .and_then(|i| self.fido_devices.get(i).map(|(p, _)| p.clone())),
                    );
                    // Previously we auto-flipped self.create.kind from
                    // Passphrase to Fido2 when a device was detected
                    // here. Removed because the auto-probe runs every
                    // about 3 s and would re-flip the Create form's kind
                    // mid-interaction, repositioning every widget the
                    // user was about to click on. The Welcome screen's
                    // recommendation banner already adapts based on
                    // detected presence, that's enough.
                }
                Ok(Err(_)) => {}
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    self.pending = Some(Pending::Fido2Probe(rx));
                }
                Err(_) => {}
            },
            Pending::Create { rx, needs_touch } => match rx.try_recv() {
                Ok(Ok(opened)) => {
                    let cipher = opened.cipher_label.clone();
                    let path = opened.vault_path.clone();
                    let header_path = opened.header_path.clone();
                    let anchor_path = opened.anchor_path.clone();
                    let has_fido2 = opened.has_fido2;
                    let has_hybrid_pq = opened.has_hybrid_pq;
                    let has_tpm = opened.has_tpm;
                    self.vault = Some(opened);
                    self.cwd = "/".into();
                    self.refresh_listing();
                    self.view = View::Browser;
                    self.create = CreateForm::default();
                    recent::upsert(RecentVault {
                        path,
                        header_path,
                        anchor_path,
                        last_opened: Some(ops::now_unix()),
                        cipher,
                        has_fido2,
                        has_hybrid_pq,
                        has_tpm,
                    });
                    self.recent_list = recent::load();
                    self.toast_ok("vault created");
                }
                Ok(Err(e)) => self.toast_err(e),
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    self.pending = Some(Pending::Create { rx, needs_touch });
                }
                Err(_) => self.toast_err("create task crashed"),
            },
            // Atomic create+enroll: same install path as Pending::Create
            // when it succeeds; on failure, the worker has already
            // deleted any partial files so we just surface the error.
            Pending::CreateWithTpmBootstrap { rx, needs_touch } => match rx.try_recv() {
                Ok(Ok(opened)) => {
                    let cipher = opened.cipher_label.clone();
                    let path = opened.vault_path.clone();
                    let header_path = opened.header_path.clone();
                    let anchor_path = opened.anchor_path.clone();
                    let has_fido2 = opened.has_fido2;
                    let has_hybrid_pq = opened.has_hybrid_pq;
                    let has_tpm = opened.has_tpm;
                    self.vault = Some(opened);
                    self.cwd = "/".into();
                    self.refresh_listing();
                    self.view = View::Browser;
                    self.create = CreateForm::default();
                    recent::upsert(RecentVault {
                        path,
                        header_path,
                        anchor_path,
                        last_opened: Some(ops::now_unix()),
                        cipher,
                        has_fido2,
                        has_hybrid_pq,
                        has_tpm,
                    });
                    self.recent_list = recent::load();
                    self.toast_ok("vault created with TPM keyslot");
                }
                Ok(Err(e)) => self.toast_err(e),
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    self.pending = Some(Pending::CreateWithTpmBootstrap { rx, needs_touch });
                }
                Err(_) => self.toast_err("TPM bootstrap task crashed"),
            },
            Pending::Unlock { rx, needs_touch } => match rx.try_recv() {
                Ok(Ok(opened)) => {
                    let cipher = opened.cipher_label.clone();
                    let path = opened.vault_path.clone();
                    let header_path = opened.header_path.clone();
                    let anchor_path = opened.anchor_path.clone();
                    let has_fido2 = opened.has_fido2;
                    let has_hybrid_pq = opened.has_hybrid_pq;
                    let has_tpm = opened.has_tpm;
                    self.vault = Some(opened);
                    self.cwd = "/".into();
                    self.refresh_listing();
                    self.view = View::Browser;
                    self.unlock = UnlockForm::default();
                    recent::upsert(RecentVault {
                        path,
                        header_path,
                        anchor_path,
                        last_opened: Some(ops::now_unix()),
                        cipher,
                        has_fido2,
                        has_hybrid_pq,
                        has_tpm,
                    });
                    self.recent_list = recent::load();
                    self.toast_ok("vault unlocked");
                }
                Ok(Err(e)) => self.toast_err(e),
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    self.pending = Some(Pending::Unlock { rx, needs_touch });
                }
                Err(_) => self.toast_err("unlock task crashed"),
            },
            Pending::PutFile { rx, name } => match rx.try_recv() {
                Ok((vault, result)) => {
                    self.vault = Some(vault);
                    match result {
                        Ok(bytes) => {
                            self.toast_ok(format!("added {name} ({bytes} bytes)"));
                            self.refresh_listing();
                        }
                        Err(e) => self.toast_err(e),
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    self.pending = Some(Pending::PutFile { rx, name });
                }
                Err(_) => self.toast_err("put task crashed"),
            },
            Pending::GetFile { rx } => match rx.try_recv() {
                Ok((vault, result)) => {
                    self.vault = Some(vault);
                    match result {
                        Ok(bytes) => self.toast_ok(format!("extracted {bytes} bytes")),
                        Err(e) => self.toast_err(e),
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    self.pending = Some(Pending::GetFile { rx });
                }
                Err(_) => self.toast_err("get task crashed"),
            },
            Pending::EnrollPassphrase { rx } => match rx.try_recv() {
                Ok((vault, result)) => {
                    self.vault = Some(vault);
                    match result {
                        Ok(idx) => self.toast_ok(format!("enrolled passphrase in slot {idx}")),
                        Err(e) => self.toast_err(e),
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    self.pending = Some(Pending::EnrollPassphrase { rx });
                }
                Err(_) => self.toast_err("enroll task crashed"),
            },
            Pending::EnrollFido2 { rx } => match rx.try_recv() {
                Ok((mut vault, result)) => {
                    match result {
                        Ok(idx) => {
                            vault.has_fido2 = true;
                            self.toast_ok(format!("enrolled FIDO2 in slot {idx}"));
                        }
                        Err(e) => self.toast_err(e),
                    }
                    self.vault = Some(vault);
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    self.pending = Some(Pending::EnrollFido2 { rx });
                }
                Err(_) => self.toast_err("enroll task crashed"),
            },
            Pending::EnrollTpm2 { rx } => match rx.try_recv() {
                Ok((mut vault, result)) => {
                    match result {
                        Ok(idx) => {
                            vault.has_tpm = true;
                            self.toast_ok(format!("enrolled TPM 2.0 in slot {idx}"));
                        }
                        Err(e) => self.toast_err(e),
                    }
                    self.vault = Some(vault);
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    self.pending = Some(Pending::EnrollTpm2 { rx });
                }
                Err(_) => self.toast_err("TPM enroll task crashed"),
            },
            Pending::EnrollTpm2Pin { rx } => match rx.try_recv() {
                Ok((mut vault, result)) => {
                    match result {
                        Ok(idx) => {
                            vault.has_tpm = true;
                            self.toast_ok(format!("enrolled TPM 2.0 + PIN in slot {idx}"));
                        }
                        Err(e) => self.toast_err(e),
                    }
                    self.vault = Some(vault);
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    self.pending = Some(Pending::EnrollTpm2Pin { rx });
                }
                Err(_) => self.toast_err("TPM+PIN enroll task crashed"),
            },
            Pending::EnrollTpm2Fido2 { rx } => match rx.try_recv() {
                Ok((mut vault, result)) => {
                    match result {
                        Ok(idx) => {
                            vault.has_fido2 = true;
                            vault.has_tpm = true;
                            self.toast_ok(format!("enrolled fused TPM+FIDO2 in slot {idx}"));
                        }
                        Err(e) => self.toast_err(e),
                    }
                    self.vault = Some(vault);
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    self.pending = Some(Pending::EnrollTpm2Fido2 { rx });
                }
                Err(_) => self.toast_err("TPM+FIDO2 enroll task crashed"),
            },
            Pending::EnrollHybridPqTpm2 { rx } => match rx.try_recv() {
                Ok((mut vault, result)) => {
                    match result {
                        Ok(idx) => {
                            vault.has_hybrid_pq = true;
                            vault.has_tpm = true;
                            self.toast_ok(format!("enrolled hybrid TPM + ML-KEM in slot {idx}"));
                        }
                        Err(e) => self.toast_err(e),
                    }
                    self.vault = Some(vault);
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    self.pending = Some(Pending::EnrollHybridPqTpm2 { rx });
                }
                Err(_) => self.toast_err("hybrid-PQ-TPM enroll task crashed"),
            },
            Pending::EnrollHybridPqTpm2Fido2 { rx } => match rx.try_recv() {
                Ok((mut vault, result)) => {
                    match result {
                        Ok(idx) => {
                            vault.has_fido2 = true;
                            vault.has_hybrid_pq = true;
                            vault.has_tpm = true;
                            self.toast_ok(format!(
                                "enrolled 3-factor TPM+FIDO2+ML-KEM in slot {idx}"
                            ));
                        }
                        Err(e) => self.toast_err(e),
                    }
                    self.vault = Some(vault);
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    self.pending = Some(Pending::EnrollHybridPqTpm2Fido2 { rx });
                }
                Err(_) => self.toast_err("3-factor enroll task crashed"),
            },
            Pending::Panic(rx) => match rx.try_recv() {
                Ok(Ok(())) => {
                    self.toast_warn("vault destroyed");
                    self.recent_list = recent::load();
                    self.view = View::Welcome;
                    self.panic = PanicForm::default();
                }
                Ok(Err(e)) => self.toast_err(e),
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    self.pending = Some(Pending::Panic(rx));
                }
                Err(_) => self.toast_err("panic task crashed"),
            },
            Pending::RotateMvk(rx) => match rx.try_recv() {
                Ok(Ok(reopened)) => {
                    // Worker returns the same OpenedVault with an
                    // updated VFS; re-install it so the Keyslots
                    // view reflects the new wraps.
                    self.vault = Some(reopened);
                    self.toast_ok("✓ master key rotated");
                }
                Ok(Err(e)) => {
                    // Rotation failed (or was aborted). The worker
                    // moved the vault out; without the OpenedVault
                    // back we have to drop to Welcome, same shape
                    // as a mount-side disconnect.
                    self.view = View::Welcome;
                    self.toast_err(format!("rotate failed: {e}"));
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    self.pending = Some(Pending::RotateMvk(rx));
                }
                Err(_) => {
                    self.view = View::Welcome;
                    self.toast_err("rotate task crashed");
                }
            },
        }
    }
}

// ---- sidebar --------------------------------------------------------------

impl LuksboxApp {
    fn draw_sidebar(&mut self, ui: &mut egui::Ui) {
        // Wrap the entire sidebar in a vertical ScrollArea so a short
        // window can still reach the bottom items (Generate, PANIC,
        // About, YK indicator).
        ScrollArea::vertical()
            .auto_shrink([false; 2])
            .scroll_bar_visibility(egui::containers::scroll_area::ScrollBarVisibility::AlwaysHidden)
            .show(ui, |ui| {
                let logo_max_w = ui.available_width() - 8.0;
                let img = egui::Image::from_bytes("bytes://luksbox-logo.png", LOGO_PNG)
                    .max_height(LOGO_MAX_HEIGHT_PX)
                    .max_width(logo_max_w)
                    .fit_to_original_size(1.0);
                let resp = ui.add(img);
                if resp.rect.height() < 6.0 {
                    ui.horizontal(|ui| {
                        let (rect, _) =
                            ui.allocate_exact_size(Vec2::new(10.0, 10.0), egui::Sense::hover());
                        ui.painter()
                            .circle_filled(rect.center(), 5.0, theme::ACCENT);
                        ui.label(RichText::new("LUKSbox").strong().size(16.0));
                    });
                }
                ui.add_space(14.0);

                let sidebar_w = sidebar_content_width(ui);
                if ui
                    .add_sized([sidebar_w, 32.0], primary_button("+ New vault"))
                    .clicked()
                {
                    self.request_navigate(NavigateAction::GoCreate);
                }
                if ui
                    .add_sized([sidebar_w, 32.0], ghost_button("Open existing..."))
                    .clicked()
                {
                    self.request_navigate(NavigateAction::OpenPicker);
                }

                ui.add_space(20.0);
                ui.label(RichText::new("RECENT").small().color(theme::FAINT).strong());
                ui.add_space(6.0);
                if self.recent_list.is_empty() {
                    ui.label(
                        RichText::new("No recent vaults yet")
                            .color(theme::FAINT)
                            .small(),
                    );
                }
                let entries = self.recent_list.clone();
                for r in &entries {
                    self.draw_recent_item(ui, r);
                }

                ui.add_space(16.0);
                ui.separator();
                ui.add_space(8.0);

                if ui
                    .button(
                        RichText::new("Generate strong passphrase")
                            .color(theme::DIM)
                            .small(),
                    )
                    .clicked()
                {
                    self.open_passgen(PassgenTarget::Standalone);
                }
                if ui
                    .button(
                        RichText::new("PANIC: destroy a vault...")
                            .color(theme::DANGER)
                            .small(),
                    )
                    .clicked()
                {
                    self.request_navigate(NavigateAction::GoPanic);
                }

                ui.add_space(8.0);
                let sidebar_w = sidebar_content_width(ui);
                self.draw_fido_picker(ui, sidebar_w);

                ui.add_space(10.0);
                ui.separator();
                ui.add_space(6.0);
                if ui
                    .button(RichText::new("About LUKSbox").color(theme::DIM).small())
                    .clicked()
                {
                    self.view = View::About;
                }
                ui.label(
                    RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                        .color(theme::FAINT)
                        .size(10.0),
                );
                let z = ui.ctx().zoom_factor();
                ui.label(
                    RichText::new(format!("zoom {:.0}%  (Ctrl +/- to adjust)", z * 100.0))
                        .color(theme::FAINT)
                        .size(10.0),
                )
                .on_hover_text(
                    "Adjust if widgets become hard to click on the right/bottom \
                     edge, fractional-DPI displays (GPD, Steam Deck, Surface Go) \
                     can mis-round egui hit-rects. Persistent override: env var \
                     LUKSBOX_GUI_ZOOM=1.0 (or any value 0.5-4.0).",
                );
            });
    }

    fn draw_fido_picker(&mut self, ui: &mut egui::Ui, width: f32) {
        ui.label(
            RichText::new("FIDO2 AUTHENTICATOR")
                .small()
                .color(theme::FAINT)
                .strong(),
        );
        ui.add_space(4.0);

        if self.fido_devices.is_empty() {
            // Empty-state badge: dim "no devices" framing with the
            // same hover hint as the old single-device path.
            let resp = Frame::new()
                .fill(theme::DIM.linear_multiply(0.08))
                .stroke(Stroke::new(1.0, theme::DIM))
                .corner_radius(CornerRadius::same(8))
                .inner_margin(Margin::symmetric(8, 5))
                .show(ui, |ui| {
                    ui.set_min_width((width - 16.0).max(80.0));
                    ui.label(
                        RichText::new("No authenticator detected")
                            .small()
                            .strong()
                            .color(theme::DIM),
                    );
                    ui.label(
                        RichText::new("Plug in a security key")
                            .size(11.0)
                            .color(theme::DIM),
                    );
                })
                .response;
            let hint = if cfg!(target_os = "windows") {
                "Plug in any FIDO2 authenticator (YubiKey, SoloKey, Nitrokey, \
                 Token2, OnlyKey, etc.) or use Windows Hello.\n\n\
                 If your USB security key IS plugged in but only Windows Hello \
                 appears here, that's a known Windows limitation: non-elevated \
                 applications can't enumerate FIDO2 HID devices directly (the \
                 FIDO2 HID class is reserved for the WebAuthn system service \
                 since Windows 10 1903). Either run LUKSbox as Administrator \
                 to access USB keys, OR use Windows Hello (which works \
                 unprivileged because it goes through the WebAuthn system API)."
            } else {
                "Plug in any FIDO2 authenticator (YubiKey, SoloKey, Nitrokey, \
                 Token2, OnlyKey, etc.). On Linux you may also need to install \
                 the libfido2 udev rules so non-root users can access the \
                 device (`apt install libfido2-1` on Debian / Ubuntu does \
                 this automatically)."
            };
            resp.on_hover_text(hint);
        } else {
            // Dropdown: each entry is a `(path, label)` from libfido2.
            // The selected entry both feeds the visual badge and is
            // pushed into `ops::set_selected_fido2_device` so background
            // workers use that device's libfido2 path. Truncate
            // labels via shorten_middle so a "Yubico YubiKey 5 NFC"
            // doesn't blow out the sidebar width.
            let max_chars = chars_for_width(width - 36.0);
            let selected_label = self
                .selected_fido_idx
                .and_then(|i| self.fido_devices.get(i))
                .map(|(_, l)| shorten_middle(l, max_chars))
                .unwrap_or_else(|| "(pick one)".to_string());

            let mut new_selection: Option<usize> = None;
            egui::ComboBox::from_id_salt("fido2-device-picker")
                .width(width - 16.0)
                .selected_text(selected_label)
                .show_ui(ui, |ui| {
                    for (i, (path, label)) in self.fido_devices.iter().enumerate() {
                        let is_selected = self.selected_fido_idx == Some(i);
                        let resp =
                            ui.selectable_label(is_selected, shorten_middle(label, max_chars + 16));
                        // Windows Hello has fundamentally different UX
                        // from a plug-in security key (TPM-bound, not
                        // portable; auth method picked inside Windows's
                        // own prompt). Hover hint sets expectations
                        // before the user commits.
                        if luksbox_fido2::is_windows_hello_path(path) {
                            resp.clone().on_hover_text(
                                "Windows Hello: Windows will show its own prompt and let you \
                                 pick face, fingerprint, or PIN (whatever you've enrolled). \
                                 Caveats: credentials are bound to this PC's TPM and your \
                                 user account, so reinstalling Windows or moving PCs loses \
                                 the keyslot. Always enroll a passphrase backup keyslot \
                                 alongside Windows Hello. Requires Windows 11 22H2+ for the \
                                 hmac-secret extension LUKSbox needs.",
                            );
                        }
                        if resp.clicked() {
                            new_selection = Some(i);
                        }
                    }
                });
            if let Some(i) = new_selection {
                self.selected_fido_idx = Some(i);
                ops::set_selected_fido2_device(self.fido_devices.get(i).map(|(p, _)| p.clone()));
            }
        }

        ui.add_space(4.0);
        if ui
            .add_sized([width, 22.0], ghost_button("↻ Re-detect"))
            .on_hover_text(
                "Re-enumerate plugged-in FIDO2 authenticators. Useful after \
                 plugging or unplugging a device.",
            )
            .clicked()
        {
            self.pending = Some(Pending::Fido2Probe(ops::spawn(|| {
                Ok(ops::detect_fido2_devices())
            })));
        }
    }

    fn draw_recent_item(&mut self, ui: &mut egui::Ui, r: &RecentVault) {
        // Cheap stat: the path-not-found state is one syscall per
        // recent entry per repaint, only about 20 entries max, so OK.
        let missing = !r.path.is_file();
        let mut want_forget = false;

        let resp = Frame::new()
            .fill(theme::PANEL)
            .stroke(Stroke::new(1.0, Color32::TRANSPARENT))
            .corner_radius(CornerRadius::same(6))
            .inner_margin(Margin::symmetric(10, 8))
            .show(ui, |ui| {
                let name = r
                    .path
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| r.path.display().to_string());
                ui.horizontal(|ui| {
                    let title_color = if missing { theme::DIM } else { theme::TEXT };
                    // Truncate long vault names with ellipsis so they
                    // can't push the × button off-screen on narrow
                    // sidebars; full name still available on hover.
                    ui.add(
                        egui::Label::new(
                            RichText::new(&name).strong().color(title_color).size(13.0),
                        )
                        .truncate()
                        .selectable(false),
                    )
                    .on_hover_text(&name);
                    // Push the × button to the right edge with explicit
                    // spacing rather than a nested right_to_left layout,
                    // which was clipping the button's hit-rect on narrow
                    // sidebars and silently swallowing clicks.
                    let avail = ui.available_width();
                    if avail > 28.0 {
                        ui.add_space(avail - 26.0);
                    }
                    let btn = ui.add_sized(
                        [22.0, 22.0],
                        egui::Button::new(RichText::new("×").color(theme::FAINT).size(14.0))
                            .frame(false),
                    );
                    if btn
                        .on_hover_text("forget this vault (doesn't delete the file)")
                        .clicked()
                    {
                        want_forget = true;
                    }
                });
                // Path also truncates with ellipsis; full path on hover.
                ui.add(
                    egui::Label::new(
                        RichText::new(r.path.display().to_string())
                            .small()
                            .color(theme::FAINT),
                    )
                    .truncate()
                    .selectable(false),
                )
                .on_hover_text(r.path.display().to_string());
                // Pills wrap to multiple rows, 5 pills don't fit on a
                // about 248 px sidebar in one line.
                ui.horizontal_wrapped(|ui| {
                    if missing {
                        theme::pill(
                            ui,
                            RichText::new("missing").small().color(theme::DANGER),
                            theme::DANGER,
                        );
                    }
                    // Factor badges (FIDO2 / hybrid-PQ / TPM) are
                    // intentionally NOT shown here. The recent list
                    // is meant to be a low-information path picker;
                    // the slot composition is sensitive structural
                    // intelligence and only needs to surface AFTER
                    // the user has selected a vault to unlock (where
                    // it appears in the unlock view's slot panel).
                    if r.header_path.is_some() {
                        theme::pill(
                            ui,
                            RichText::new("detached").small().color(theme::OK),
                            theme::OK,
                        );
                    }
                    if r.anchor_path.is_some() {
                        theme::pill(
                            ui,
                            RichText::new("anchor").small().color(theme::WARN),
                            theme::WARN,
                        );
                    }
                });
                if missing {
                    ui.label(
                        RichText::new(
                            "file not found at this path, moved or deleted? \
                             click × to forget it from this list, or move \
                             the .lbx back to this path.",
                        )
                        .small()
                        .color(theme::DANGER),
                    );
                }
            })
            .response
            .interact(egui::Sense::click());

        // Right-click also exposes Forget, same action via two paths.
        resp.context_menu(|ui| {
            if ui.button("Forget this vault").clicked() {
                want_forget = true;
                ui.close();
            }
            if ui
                .button(RichText::new("Forget AND delete the .lbx file").color(theme::DANGER))
                .on_hover_text("Removes from recent list and unlinks the .lbx, IRREVERSIBLE.")
                .clicked()
            {
                // Defer the actual delete to `forget_recent_path` so we
                // don't borrow self twice.
                want_forget = true;
                let _ = std::fs::remove_file(&r.path);
                ui.close();
            }
        });

        if resp.hovered() {
            ui.painter().rect_stroke(
                resp.rect,
                CornerRadius::same(6),
                Stroke::new(1.0, theme::BORDER),
                egui::StrokeKind::Inside,
            );
        }
        // Plain click opens the unlock flow, but only if the file
        // still exists. Clicking a missing entry surfaces a toast
        // explaining the situation rather than a cryptic Container::open
        // failure later.
        if resp.clicked() && !want_forget {
            if missing {
                self.toast_warn(format!(
                    "{} no longer exists, click × to forget it.",
                    r.path.display()
                ));
            } else {
                self.request_navigate(NavigateAction::OpenRecent(r.clone()));
            }
        }
        if want_forget {
            self.forget_recent_path(&r.path);
        }
        ui.add_space(4.0);
    }

    /// Remove a recent entry from disk + in-memory list. Surfaces a
    /// confirmation toast so the user knows the action happened. The
    /// caller's frame is mid-render so we rely on egui's normal
    /// auto-repaint after input, no explicit ctx.request_repaint
    /// needed (the click itself triggered a repaint already).
    fn forget_recent_path(&mut self, path: &std::path::Path) {
        recent::forget(path);
        self.recent_list = recent::load();
        self.toast_ok(format!("forgot {}", path.display()));
    }

    fn open_existing_picker(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Open LUKSbox vault (.lbx)")
            .add_filter("LUKSbox vault", &["lbx"])
            .add_filter("any file", &["*"])
            .pick_file()
        {
            let mut entry = RecentVault {
                path: path.clone(),
                header_path: None,
                anchor_path: None,
                last_opened: None,
                cipher: String::new(),
                has_fido2: false,
                has_hybrid_pq: false,
                has_tpm: false,
            };
            // Preserve metadata if we already have this vault recorded.
            if let Some(existing) = self.recent_list.iter().find(|r| r.path == path).cloned() {
                entry.header_path = existing.header_path;
                entry.anchor_path = existing.anchor_path;
                entry.cipher = existing.cipher;
                entry.has_fido2 = existing.has_fido2;
                entry.has_hybrid_pq = existing.has_hybrid_pq;
                entry.has_tpm = existing.has_tpm;
            }
            self.start_unlock(entry);
        }
    }

    fn start_unlock(&mut self, r: RecentVault) {
        let method = match (
            r.has_hybrid_pq,
            r.has_fido2 && !self.fido_devices.is_empty(),
        ) {
            (true, true) => UnlockMethod::HybridPqFido2,
            (true, false) => UnlockMethod::HybridPq,
            (false, true) => UnlockMethod::Fido2,
            (false, false) => UnlockMethod::Passphrase,
        };
        // One-shot header read so the unlock view can show the vault's
        // keyslot composition before the user picks an unlock method.
        // Header is unencrypted (no auth needed); a few-KB read +
        // parse, fast enough to do synchronously.
        let slot_inspection = Some(ops::inspect_slot_kinds(&r.path, r.header_path.as_deref()));
        self.unlock = UnlockForm {
            path: r.path.display().to_string(),
            header_path: r
                .header_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            anchor_path: r
                .anchor_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            use_detached: r.header_path.is_some(),
            use_anchor: r.anchor_path.is_some(),
            method,
            passphrase: Zeroizing::default(),
            pin: Zeroizing::default(),
            hybrid_kyber_path: String::new(),
            slot_inspection,
        };
        self.view = View::Unlock;
    }

    /// Drop the currently-open vault if any, flushing first so any
    /// pending VFS writes hit disk before the file handle goes away.
    /// Resets browser-local state (cwd, listing) so a subsequent
    /// unlock starts clean.
    fn lock_and_drop_vault(&mut self) {
        if let Some(mut v) = self.vault.take() {
            let _ = v.vfs.flush();
        }
        self.cwd = "/".into();
        self.listing.clear();
        self.listing_err = None;
    }

    /// Entry point for any UI action that would abandon the
    /// currently-open vault. If there's no vault, runs the action
    /// directly; if there is, defers it behind the confirm-lock modal.
    fn request_navigate(&mut self, action: NavigateAction) {
        if self.vault.is_none() {
            self.execute_navigate(action);
        } else {
            self.confirm_lock = Some(action);
        }
    }

    /// Drop the open vault (if any) and execute the navigation. Only
    /// reachable through `request_navigate` or the confirm-lock
    /// modal's "Lock and continue" button.
    fn execute_navigate(&mut self, action: NavigateAction) {
        self.lock_and_drop_vault();
        match action {
            NavigateAction::OpenRecent(r) => self.start_unlock(r),
            NavigateAction::OpenPicker => self.open_existing_picker(),
            NavigateAction::GoCreate => self.view = View::Create,
            NavigateAction::GoPanic => self.view = View::Panic,
            NavigateAction::GoWelcome => self.view = View::Welcome,
        }
    }
}

// ---- welcome --------------------------------------------------------------

impl LuksboxApp {
    fn draw_welcome(&mut self, ui: &mut egui::Ui) {
        ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                ui.add_space(40.0);
                ui.label(
                    RichText::new("Encrypted containers, made boring.")
                        .size(28.0)
                        .strong(),
                );
                ui.add_space(14.0);
                ui.label(
                    RichText::new(
                        "LUKSbox is an offline encrypted-vault tool with passphrase + \
                         FIDO2 authenticator keyslots, post-quantum hybrid (ML-KEM-768 / \
                         ML-KEM-1024) keyslots, detached headers, rollback-detection \
                         anchors, and crash-safe key rotation. Pick a recent vault, \
                         open one, or create a new one.",
                    )
                    .color(theme::DIM)
                    .size(14.0),
                );
                ui.add_space(22.0);

                ui.horizontal(|ui| {
                    if ui.add(primary_button("+ Create a new vault")).clicked() {
                        self.request_navigate(NavigateAction::GoCreate);
                    }
                    if ui.add(ghost_button("Open existing vault...")).clicked() {
                        self.request_navigate(NavigateAction::OpenPicker);
                    }
                });

                ui.add_space(34.0);

                // ---- Primary recommendation banner -------------------------
                let (headline, body) = if !self.fido_devices.is_empty() {
                    (
                        "Recommended: FIDO2 + passphrase backup + detached header + anchor",
                        "FIDO2 protects the master key with a hardware secret your \
                         authenticator never reveals. A passphrase backup keyslot lets \
                         you recover if the key is lost. A detached header makes the \
                         .lbx alone indistinguishable from random. The anchor sidecar \
                         (on separate trusted storage) catches whole-vault rollback \
                         attempts.",
                    )
                } else {
                    (
                        "Recommended: passphrase + detached header + anchor",
                        "No FIDO2 device detected. Use a strong (>=4-word) passphrase, \
                         Argon2id stretches it. A detached header makes the .lbx alone \
                         opaque random; the anchor sidecar (on separate trusted \
                         storage) catches rollback attempts. Plug in a FIDO2 \
                         authenticator for stronger hardware-backed protection.",
                    )
                };
                Frame::new()
                    .fill(theme::PANEL)
                    .stroke(Stroke::new(1.0, theme::ACCENT.linear_multiply(0.4)))
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(18)
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new(headline)
                                .strong()
                                .color(theme::TEXT)
                                .size(14.0),
                        );
                        ui.add_space(6.0);
                        ui.label(RichText::new(body).color(theme::DIM).size(13.0));
                    });

                // ---- Post-quantum guidance --------------------------------
                ui.add_space(18.0);
                Frame::new()
                    .fill(theme::PANEL)
                    .stroke(Stroke::new(1.0, theme::WARN.linear_multiply(0.5)))
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(18)
                    .show(ui, |ui| {
                        // Match the `section()` helper's width behaviour:
                        // an egui Frame sizes to its content, so without
                        // claiming the parent's available width the box
                        // shrinks to the longest line of text inside.
                        ui.set_min_width(ui.available_width());
                        ui.label(
                            RichText::new("Post-quantum guidance")
                                .strong()
                                .color(theme::WARN)
                                .size(14.0),
                        );
                        ui.add_space(6.0);
                        ui.label(
                            RichText::new(
                                "Adversaries running long-term storage of today's \
                                 ciphertexts (\"harvest now, decrypt later\") could \
                                 break classical key-exchange once a cryptographically \
                                 relevant quantum computer is available. If your vault \
                                 is meant to remain confidential past about 2035, choose a \
                                 hybrid keyslot:",
                            )
                            .color(theme::DIM)
                            .size(13.0),
                        );
                        ui.add_space(8.0);
                        bullet(
                            ui,
                            "Hybrid passphrase + ML-KEM-768",
                            "Classical Argon2id + post-quantum KEM. NIST category 3 \
                             (~AES-192). Default PQ choice, small sidecar, broad \
                             interop. Keep the .kyber seed file on separate trusted \
                             storage.",
                        );
                        bullet(
                            ui,
                            "Hybrid FIDO2 + ML-KEM-768",
                            "The KEM closes the actual PQ gap: ECDH-P256 inside CTAP2 \
                             is the only asymmetric primitive on the FIDO2 wire, so \
                             a CRQC adversary who recorded USB-HID traffic could \
                             quantum-recover the hmac_secret. Adding Kyber means \
                             they still need the .kyber seed file.",
                        );
                        bullet(
                            ui,
                            "Hybrid + ML-KEM-1024 (passphrase or FIDO2)",
                            "Strongest PQ parameter set, NIST category 5, ~AES-256 \
                             equivalent. Larger sidecar (about 3.1 KB instead of about 2.3 KB). \
                             Pick this when you don't mind the size and want the \
                             cryptographic-overkill option.",
                        );
                        ui.add_space(6.0);
                        ui.label(
                            RichText::new(
                                "All hybrid modes write a separate .kyber seed file, \
                                 BACK IT UP on different storage. Losing it locks you \
                                 out of the vault even if you have the passphrase or \
                                 FIDO2 authenticator.",
                            )
                            .color(theme::WARN)
                            .size(12.0),
                        );
                    });

                // ---- Operational tips -------------------------------------
                ui.add_space(18.0);
                Frame::new()
                    .fill(theme::PANEL)
                    .stroke(Stroke::new(1.0, theme::BORDER))
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(18)
                    .show(ui, |ui| {
                        // Same width fix as the post-quantum guidance box
                        // and the `section()` helper.
                        ui.set_min_width(ui.available_width());
                        ui.label(
                            RichText::new("Operational tips")
                                .strong()
                                .color(theme::TEXT)
                                .size(14.0),
                        );
                        ui.add_space(6.0);
                        bullet(
                            ui,
                            "Use the SENSITIVE Argon2id preset for archival vaults",
                            "1 GiB memory, 5 iterations, about 3-4 s per unlock on a modern \
                             CPU. Worth it for vaults you unlock rarely.",
                        );
                        bullet(
                            ui,
                            "Keep .kyber and .anchor sidecars on separate trusted storage",
                            "Putting them next to the .lbx defeats the purpose. A USB \
                             stick, a separate machine, or cloud storage you control \
                             work fine, they're small.",
                        );
                        bullet(
                            ui,
                            "Detached header for plausible deniability of vault presence",
                            "With a detached header the .lbx looks like random data \
                             alone. Useful when storing on shared cloud or untrusted \
                             media.",
                        );
                        bullet(
                            ui,
                            "Hibernate caution",
                            "On Linux with memfd_secret available, the master key is \
                             excluded from hibernate images. On older kernels and on \
                             macOS, it isn't, disable hibernate or use encrypted swap.",
                        );
                    });

                ui.add_space(24.0);
            });
    }

    fn draw_about(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("< Back").clicked() {
                self.view = View::Welcome;
            }
            ui.add_space(8.0);
            ui.label(RichText::new("About LUKSbox").size(20.0).strong());
        });
        ui.add_space(20.0);

        Frame::new()
            .fill(theme::PANEL)
            .stroke(Stroke::new(1.0, theme::BORDER))
            .corner_radius(CornerRadius::same(10))
            .inner_margin(22)
            .show(ui, |ui| {
                ui.label(
                    RichText::new("LUKSbox")
                        .strong()
                        .color(theme::ACCENT)
                        .size(24.0),
                );
                ui.label(
                    RichText::new(format!("version {}", env!("CARGO_PKG_VERSION")))
                        .color(theme::DIM)
                        .size(13.0),
                );
                ui.add_space(14.0);
                ui.label(
                    RichText::new(
                        "Offline encrypted-vault tool with passphrase + FIDO2 keyslots, \
                         post-quantum hybrid (ML-KEM-768 / ML-KEM-1024) keyslots, detached \
                         headers, rollback-detection anchors, and crash-safe key rotation.",
                    )
                    .color(theme::TEXT)
                    .size(13.0),
                );
                ui.add_space(18.0);

                ui.label(RichText::new("Created by").color(theme::DIM).size(12.0));
                ui.label(
                    RichText::new("Sebastien Dudek, Penthertz")
                        .color(theme::TEXT)
                        .size(14.0)
                        .strong(),
                );
                ui.add_space(10.0);

                ui.label(RichText::new("Website").color(theme::DIM).size(12.0));
                ui.hyperlink_to(
                    RichText::new("https://penthertz.com")
                        .color(theme::ACCENT)
                        .size(13.0),
                    "https://penthertz.com",
                );
                ui.add_space(8.0);

                ui.label(RichText::new("Contact").color(theme::DIM).size(12.0));
                ui.hyperlink_to(
                    RichText::new("contact@penthertz.com")
                        .color(theme::ACCENT)
                        .size(13.0),
                    "mailto:contact@penthertz.com",
                );
                ui.add_space(8.0);

                ui.label(RichText::new("Social").color(theme::DIM).size(12.0));
                ui.hyperlink_to(
                    RichText::new("Twitter / X, @PentHertz")
                        .color(theme::ACCENT)
                        .size(13.0),
                    "https://x.com/PentHertz",
                );
                ui.hyperlink_to(
                    RichText::new("LinkedIn, Penthertz")
                        .color(theme::ACCENT)
                        .size(13.0),
                    "https://fr.linkedin.com/company/penthertz",
                );
                ui.add_space(14.0);

                ui.label(RichText::new("License").color(theme::DIM).size(12.0));
                ui.label(
                    RichText::new(
                        "Open source under the Apache License 2.0. Read the \
                         source, audit the cryptography, build it yourself, \
                         modify it, redistribute it, even use it in a \
                         competing product - the code is free. \"LUKSbox\" \
                         and the Penthertz name and logo are trademarks of \
                         Penthertz (Apache 2.0 does not grant trademark \
                         rights); see TRADEMARK.md.",
                    )
                    .color(theme::TEXT)
                    .size(12.0),
                );
                ui.hyperlink_to(
                    RichText::new("Apache License 2.0")
                        .color(theme::ACCENT)
                        .size(12.0),
                    "https://www.apache.org/licenses/LICENSE-2.0",
                );
            });
    }
}

// ---- create ---------------------------------------------------------------

impl LuksboxApp {
    fn draw_create(&mut self, ui: &mut egui::Ui) {
        // Top action bar: Back on the left, Create on the right.
        let can_submit = self.pending.is_none();
        let mut submit = false;
        let mut submit_via_enter = false;
        let mut go_back = false;
        ui.horizontal(|ui| {
            if ui.button("< Back").clicked() {
                go_back = true;
            }
            ui.add_space(8.0);
            ui.label(RichText::new("Create a new vault").size(20.0).strong());
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .add_enabled(can_submit, primary_button("Create vault"))
                    .clicked()
                {
                    submit = true;
                }
            });
        });
        ui.separator();
        ui.add_space(10.0);
        if go_back {
            // Wipe any typed passphrase / PIN by replacing the form
            // with a fresh default (the old form's `Zeroizing<String>`
            // fields zero their heap bytes on Drop).
            self.create = CreateForm::default();
            self.view = View::Welcome;
            return;
        }
        if submit {
            self.submit_create();
        }

        ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            section(ui, "Vault file", |ui| {
                ui.label(RichText::new("Vault path").color(theme::DIM).size(12.0));
                ui.horizontal(|ui| {
                    let (field_w, browse_w) = trailing_button_row_widths(ui, FORM_FIELD_MAX_W, 90.0);
                    let resp = ui.add_sized(
                        [field_w, CONTROL_H],
                        egui::TextEdit::singleline(&mut self.create.path)
                            .hint_text(path_hints::home("secret.lbx")),
                    );
                    if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        submit_via_enter = true;
                    }
                    if ui.add_sized([browse_w, CONTROL_H], ghost_button("Browse")).clicked()
                        && let Some(p) = rfd::FileDialog::new()
                            .set_title("New vault file")
                            .add_filter("LUKSbox vault", &["lbx"])
                            .save_file()
                        {
                            self.create.path = p.display().to_string();
                        }
                });
                ui.add_space(8.0);
                ui.checkbox(
                    &mut self.create.use_detached,
                    "Use a detached header sidecar (the .lbx alone becomes opaque random, strongest at-rest posture)",
                );
                if self.create.use_detached {
                    ui.label(RichText::new("Header sidecar path").color(theme::DIM).size(12.0));
                    ui.horizontal(|ui| {
                        let (field_w, browse_w) = trailing_button_row_widths(ui, FORM_FIELD_MAX_W, 90.0);
                        ui.add_sized([field_w, CONTROL_H], egui::TextEdit::singleline(&mut self.create.header_path).hint_text(path_hints::usb("secret.hdr")));
                        if ui.add_sized([browse_w, CONTROL_H], ghost_button("Browse...")).clicked()
                            && let Some(p) = rfd::FileDialog::new().set_title("Header sidecar").save_file() {
                                self.create.header_path = p.display().to_string();
                            }
                    });
                }
            });

            section(ui, "Cipher", |ui| {
                ui.radio_value(&mut self.create.cipher, CipherChoice::AesSiv, "AES-256-GCM-SIV (recommended; nonce-misuse-resistant, RFC 8452)");
                ui.radio_value(&mut self.create.cipher, CipherChoice::Aes, "AES-256-GCM (legacy; kept for compatibility)");
                ui.radio_value(&mut self.create.cipher, CipherChoice::Chacha, "ChaCha20-Poly1305 (better without hardware AES)");
            });

            // Two-step keyslot picker: pick a factor first
            // (Passphrase / FIDO2 / TPM), then a specific variant
            // within that factor. Avoids a flat 14-radio list and
            // makes the PQ option (ML-KEM-768 vs ML-KEM-1024) visible
            // for every factor.
            section(ui, "Keyslot factor", |ui| {
                let mut factor = self.create.kind.factor();
                let prev = factor;
                ui.radio_value(&mut factor, Factor::Passphrase, Factor::Passphrase.label());
                ui.radio_value(&mut factor, Factor::Fido2, Factor::Fido2.label());
                #[cfg(target_os = "linux")]
                ui.radio_value(&mut factor, Factor::Tpm2, Factor::Tpm2.label());
                if factor != prev {
                    // Switching factors snaps the kind to the simplest
                    // variant of that factor so the user always lands
                    // on a coherent state.
                    self.create.kind = match factor {
                        Factor::Passphrase => CreateKind::Passphrase,
                        Factor::Fido2 => CreateKind::Fido2,
                        Factor::Tpm2 => CreateKind::Tpm2,
                    };
                }
            });

            section(ui, "Keyslot variant", |ui| {
                match self.create.kind.factor() {
                    Factor::Passphrase => {
                        ui.radio_value(&mut self.create.kind, CreateKind::Passphrase,
                            "Plain passphrase, stretched with Argon2id.");
                        ui.radio_value(&mut self.create.kind, CreateKind::HybridPq,
                            "Hybrid passphrase + ML-KEM-768 (post-quantum). KEK = HKDF(Argon2id(pass) || Kyber). Adds a .kyber seed file (keep on separate storage).");
                        ui.radio_value(&mut self.create.kind, CreateKind::HybridPq1024,
                            "Hybrid passphrase + ML-KEM-1024 (NIST Cat 5, ~AES-256 PQ strength). Same shape as 768, larger sidecar.");
                    }
                    Factor::Fido2 => {
                        ui.radio_value(&mut self.create.kind, CreateKind::Fido2,
                            "FIDO2 (wrap). Random MVK wrapped under the authenticator's hmac-secret. Single-slot at create time; add a passphrase or second FIDO2 backup AFTER creation via the keyslot manager if you want recovery.");
                        ui.radio_value(&mut self.create.kind, CreateKind::Fido2Direct,
                            "FIDO2-direct. MVK = HKDF(hmac-secret); no FIDO2-side wrapped MVK on disk. \
                             WITHOUT a backup passphrase below: nothing to brute-force, but losing the device = losing the vault. \
                             WITH a backup passphrase below: a passphrase keyslot is auto-enrolled wrapping the same MVK, equivalent to wrap mode + backup.");
                        ui.radio_value(&mut self.create.kind, CreateKind::HybridPqFido2,
                            "Hybrid FIDO2 + ML-KEM-768. FIDO2 authenticator + .kyber seed file. Closes the actual PQ gap.");
                        ui.radio_value(&mut self.create.kind, CreateKind::HybridPq1024Fido2,
                            "Hybrid FIDO2 + ML-KEM-1024. Strongest 2-factor hybrid mode.");
                    }
                    Factor::Tpm2 => {
                        ui.radio_value(&mut self.create.kind, CreateKind::Tpm2,
                            "Plain TPM 2.0, wrap key sealed under the local chip. Backup passphrase only.");
                        ui.radio_value(&mut self.create.kind, CreateKind::Tpm2Pin,
                            "TPM 2.0 + PIN, sealed object bound to a memorised PIN via userAuth. Backup passphrase + TPM PIN.");
                        ui.radio_value(&mut self.create.kind, CreateKind::Tpm2Fido2,
                            "Fused TPM 2.0 + FIDO2, both factors required at every unlock. Backup passphrase + FIDO2 PIN.");
                        ui.radio_value(&mut self.create.kind, CreateKind::HybridPqTpm2,
                            "Hybrid TPM 2.0 + ML-KEM-768. PQ + machine-bound. .kyber seed file required.");
                        ui.radio_value(&mut self.create.kind, CreateKind::HybridPq1024Tpm2,
                            "Hybrid TPM 2.0 + ML-KEM-1024. Strongest 2-factor PQ + TPM.");
                        ui.radio_value(&mut self.create.kind, CreateKind::HybridPqTpm2Fido2,
                            "3-factor: TPM 2.0 + FIDO2 + ML-KEM-768. Backup passphrase + FIDO2 PIN + .kyber seed.");
                        ui.radio_value(&mut self.create.kind, CreateKind::HybridPq1024Tpm2Fido2,
                            "3-factor: TPM 2.0 + FIDO2 + ML-KEM-1024. Strongest configuration.");
                    }
                }
            });

            // TPM-bootstrap recovery warning panel. Shown only when
            // a TPM kind is selected; tries to make the unrecoverable
            // failure mode hard to dismiss.
            if self.create.kind.is_tpm_bootstrap() {
                section(ui, "⚠ TPM bootstrap recovery", |ui| {
                    ui.label(
                        RichText::new(
                            "TPM-bound keyslots ONLY open on the chip that sealed them. \
                             If the chip fails or you reinstall the OS, that slot is lost. \
                             To stay recoverable, this flow keeps the backup passphrase as \
                             slot 0 by default. You can revoke it later (Manage Keyslots -> \
                             Revoke) once you've added a second backup, but DO NOT skip the \
                             backup passphrase below.",
                        )
                        .color(theme::WARN)
                        .size(12.0),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(
                            "Hybrid TPM + ML-KEM (post-quantum) variants require a separate \
                             .kyber seed file; create the vault with one of the kinds above, \
                             then use Manage Keyslots -> Add hybrid TPM to bring those in.",
                        )
                        .color(theme::FAINT)
                        .size(11.0),
                    );
                });
            }

            match self.create.kind {
                CreateKind::Passphrase => {
                    section(ui, "Passphrase", |ui| {
                        ui.label(RichText::new("Passphrase").color(theme::DIM).size(12.0));
                        let te = egui::TextEdit::singleline(&mut *self.create.passphrase)
                            .password(true);
                        ui.add_sized([form_width(ui), CONTROL_H], te);
                        strength_meter(ui, &self.create.passphrase);
                        ui.add_space(6.0);
                        if ui
                            .add_sized([form_width(ui), CONTROL_H], ghost_button("Generate strong passphrase..."))
                            .clicked()
                        {
                            self.open_passgen(PassgenTarget::CreatePrimary);
                        }
                    });
                }
                CreateKind::Fido2 => {
                    section(ui, "FIDO2", |ui| {
                        ui.label(RichText::new("FIDO2 PIN").color(theme::DIM).size(12.0));
                        ui.add_sized([form_width(ui), CONTROL_H], egui::TextEdit::singleline(&mut *self.create.pin).password(true));
                        ui.label(
                            RichText::new("You'll be asked to touch the FIDO2 authenticator twice, once to register a new credential, once to derive the keyslot secret.")
                                .color(theme::FAINT).size(12.0),
                        );
                    });
                }
                CreateKind::Fido2Direct => {
                    section(ui, "FIDO2-direct (optional backup passphrase)", |ui| {
                        ui.label(RichText::new("FIDO2 PIN").color(theme::DIM).size(12.0));
                        ui.add_sized([form_width(ui), CONTROL_H], egui::TextEdit::singleline(&mut *self.create.pin).password(true));
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new("Backup passphrase (optional). Filling it adds a passphrase keyslot wrapping the same MVK after create. \
                                           Trade-off: losing the device no longer loses the vault, but the wrapped MVK now exists on disk under the passphrase KEK \
                                           and can be brute-forced offline if the passphrase is weak. Leave empty for the no-wrapped-MVK property of FIDO2-direct.")
                                .color(theme::WARN).size(12.0),
                        );
                        let te = egui::TextEdit::singleline(&mut *self.create.backup_passphrase)
                            .password(true);
                        ui.add_sized([form_width(ui), CONTROL_H], te);
                        strength_meter(ui, &self.create.backup_passphrase);
                        ui.add_space(6.0);
                        if ui
                            .add_sized([form_width(ui), CONTROL_H], ghost_button("Generate strong passphrase..."))
                            .clicked()
                        {
                            self.open_passgen(PassgenTarget::CreateBackup);
                        }
                    });
                }
                CreateKind::HybridPq | CreateKind::HybridPq1024 => {
                    let title = if self.create.kind == CreateKind::HybridPq1024 {
                        "Hybrid passphrase + ML-KEM-1024"
                    } else {
                        "Hybrid passphrase + ML-KEM-768"
                    };
                    section(ui, title, |ui| {
                        ui.label(RichText::new("Passphrase").color(theme::DIM).size(12.0));
                        let te = egui::TextEdit::singleline(&mut *self.create.passphrase)
                            .password(true);
                        ui.add_sized([form_width(ui), CONTROL_H], te);
                        strength_meter(ui, &self.create.passphrase);
                        ui.add_space(6.0);
                        if ui
                            .add_sized([form_width(ui), CONTROL_H], ghost_button("Generate strong passphrase..."))
                            .clicked()
                        {
                            self.open_passgen(PassgenTarget::CreatePrimary);
                        }
                        ui.add_space(10.0);
                        ui.label(
                            RichText::new(
                                "Path to write the secret .kyber seed file (KEEP ON SEPARATE \
                                 STORAGE, USB stick, offline machine. Lose it = lose the vault.)",
                            )
                            .color(theme::WARN)
                            .size(12.0),
                        );
                        ui.add_sized(
                            [form_width(ui), CONTROL_H],
                            egui::TextEdit::singleline(&mut self.create.hybrid_kyber_path)
                                .hint_text(path_hints::usb("vault.kyber")),
                        );
                        ui.add_space(4.0);
                        if ui
                            .add_sized(
                                [form_width(ui), CONTROL_H],
                                ghost_button("Browse for .kyber save location..."),
                            )
                            .clicked()
                        {
                            self.start_save_picker(
                                "Where to save the Kyber seed",
                                "vault.kyber",
                                PickerTarget::CreateHybridKyber,
                            );
                        }
                    });
                }
                CreateKind::HybridPqFido2 | CreateKind::HybridPq1024Fido2 => {
                    let title = if self.create.kind == CreateKind::HybridPq1024Fido2 {
                        "Hybrid FIDO2 + ML-KEM-1024"
                    } else {
                        "Hybrid FIDO2 + ML-KEM-768"
                    };
                    section(ui, title, |ui| {
                        ui.label(RichText::new("FIDO2 PIN").color(theme::DIM).size(12.0));
                        let te = egui::TextEdit::singleline(&mut *self.create.pin).password(true);
                        ui.add_sized([form_width(ui), CONTROL_H], te);
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new(
                                "Seed-file passphrase (encrypts the .kyber seed at rest, NOT a LUKSbox unlock factor by itself)",
                            )
                            .color(theme::DIM)
                            .size(12.0),
                        );
                        let te = egui::TextEdit::singleline(&mut *self.create.passphrase).password(true);
                        ui.add_sized([form_width(ui), CONTROL_H], te);
                        strength_meter(ui, &self.create.passphrase);
                        ui.add_space(6.0);
                        if ui
                            .add_sized([form_width(ui), CONTROL_H], ghost_button("Generate strong passphrase..."))
                            .clicked()
                        {
                            self.open_passgen(PassgenTarget::CreatePrimary);
                        }
                        ui.add_space(10.0);
                        ui.label(
                            RichText::new(
                                "Path to write the secret .kyber seed file (KEEP ON SEPARATE STORAGE, USB stick. Lose authenticator OR seed = lose vault.)",
                            )
                            .color(theme::WARN)
                            .size(12.0),
                        );
                        ui.add_sized(
                            [form_width(ui), CONTROL_H],
                            egui::TextEdit::singleline(&mut self.create.hybrid_kyber_path)
                                .hint_text(path_hints::usb("vault.kyber")),
                        );
                        ui.add_space(4.0);
                        if ui
                            .add_sized(
                                [form_width(ui), CONTROL_H],
                                ghost_button("Browse for .kyber save location..."),
                            )
                            .clicked()
                        {
                            self.start_save_picker(
                                "Where to save the Kyber seed",
                                "vault.kyber",
                                PickerTarget::CreateHybridKyber,
                            );
                        }
                        ui.label(
                            RichText::new("You'll be asked to touch the FIDO2 authenticator twice during create.")
                                .color(theme::FAINT)
                                .size(12.0),
                        );
                    });
                }
                CreateKind::Tpm2 => {
                    section(ui, "TPM 2.0 + backup passphrase", |ui| {
                        ui.label(
                            RichText::new("Backup passphrase (slot 0; recovery path if the TPM dies)")
                                .color(theme::WARN).size(12.0),
                        );
                        let te = egui::TextEdit::singleline(&mut *self.create.passphrase)
                            .password(true);
                        ui.add_sized([form_width(ui), CONTROL_H], te);
                        strength_meter(ui, &self.create.passphrase);
                        ui.add_space(6.0);
                        if ui
                            .add_sized([form_width(ui), CONTROL_H], ghost_button("Generate strong passphrase..."))
                            .clicked()
                        {
                            self.open_passgen(PassgenTarget::CreatePrimary);
                        }
                        ui.label(
                            RichText::new(
                                "After the vault is created, the TPM 2.0 keyslot will be added \
                                 automatically. Linux only; requires /dev/tpmrm0 access.",
                            )
                            .color(theme::FAINT).size(12.0),
                        );
                    });
                }
                CreateKind::Tpm2Pin => {
                    section(ui, "TPM 2.0 + PIN + backup passphrase", |ui| {
                        ui.label(
                            RichText::new("Backup passphrase (slot 0; recovery path)")
                                .color(theme::WARN).size(12.0),
                        );
                        let te = egui::TextEdit::singleline(&mut *self.create.passphrase)
                            .password(true);
                        ui.add_sized([form_width(ui), CONTROL_H], te);
                        strength_meter(ui, &self.create.passphrase);
                        ui.add_space(8.0);
                        ui.label(RichText::new("TPM PIN").color(theme::DIM).size(12.0));
                        let te = egui::TextEdit::singleline(&mut *self.create.pin).password(true);
                        ui.add_sized([form_width(ui), CONTROL_H], te);
                        ui.label(
                            RichText::new(
                                "Wrong PINs count toward the chip's dictionary-attack lockout, \
                                 so even short PINs (4-6 digits) are secure on the original \
                                 hardware.",
                            )
                            .color(theme::FAINT).size(11.0),
                        );
                    });
                }
                CreateKind::Tpm2Fido2 => {
                    section(ui, "Fused TPM 2.0 + FIDO2 + backup passphrase", |ui| {
                        ui.label(
                            RichText::new("Backup passphrase (slot 0; recovery path)")
                                .color(theme::WARN).size(12.0),
                        );
                        let te = egui::TextEdit::singleline(&mut *self.create.passphrase)
                            .password(true);
                        ui.add_sized([form_width(ui), CONTROL_H], te);
                        strength_meter(ui, &self.create.passphrase);
                        ui.add_space(8.0);
                        ui.label(RichText::new("FIDO2 PIN").color(theme::DIM).size(12.0));
                        let te = egui::TextEdit::singleline(&mut *self.create.pin).password(true);
                        ui.add_sized([form_width(ui), CONTROL_H], te);
                        ui.label(
                            RichText::new(
                                "Both factors required at every unlock: local TPM AND the \
                                 FIDO2 authenticator. Loss of either kills the slot, keep \
                                 the backup passphrase.",
                            )
                            .color(theme::FAINT).size(11.0),
                        );
                    });
                }
                CreateKind::HybridPqTpm2 | CreateKind::HybridPq1024Tpm2 => {
                    let title = if self.create.kind == CreateKind::HybridPq1024Tpm2 {
                        "Hybrid TPM 2.0 + ML-KEM-1024 + backup passphrase"
                    } else {
                        "Hybrid TPM 2.0 + ML-KEM-768 + backup passphrase"
                    };
                    section(ui, title, |ui| {
                        ui.label(
                            RichText::new("Backup passphrase (slot 0; recovery path if the TPM dies)")
                                .color(theme::WARN).size(12.0),
                        );
                        let te = egui::TextEdit::singleline(&mut *self.create.passphrase)
                            .password(true);
                        ui.add_sized([form_width(ui), CONTROL_H], te);
                        strength_meter(ui, &self.create.passphrase);
                        ui.add_space(6.0);
                        if ui
                            .add_sized([form_width(ui), CONTROL_H], ghost_button("Generate strong passphrase..."))
                            .clicked()
                        {
                            self.open_passgen(PassgenTarget::CreatePrimary);
                        }
                        ui.add_space(10.0);
                        ui.label(
                            RichText::new(
                                "Seed-file passphrase (encrypts the .kyber seed file at rest. \
                                 Leave empty to reuse the backup passphrase above.)",
                            )
                            .color(theme::DIM).size(12.0),
                        );
                        let te = egui::TextEdit::singleline(&mut *self.create.hybrid_seed_pw)
                            .password(true);
                        ui.add_sized([form_width(ui), CONTROL_H], te);
                        ui.add_space(10.0);
                        ui.label(
                            RichText::new(
                                "Path to write the secret .kyber seed file (KEEP ON SEPARATE STORAGE. Lose seed OR chip = lose slot; backup passphrase still recovers.)",
                            )
                            .color(theme::WARN).size(12.0),
                        );
                        ui.add_sized(
                            [form_width(ui), CONTROL_H],
                            egui::TextEdit::singleline(&mut self.create.hybrid_kyber_path)
                                .hint_text(path_hints::usb("vault.kyber")),
                        );
                        ui.add_space(4.0);
                        if ui
                            .add_sized(
                                [form_width(ui), CONTROL_H],
                                ghost_button("Browse for .kyber save location..."),
                            )
                            .clicked()
                        {
                            self.start_save_picker(
                                "Where to save the Kyber seed",
                                "vault.kyber",
                                PickerTarget::CreateHybridKyber,
                            );
                        }
                    });
                }
                CreateKind::HybridPqTpm2Fido2 | CreateKind::HybridPq1024Tpm2Fido2 => {
                    let title = if self.create.kind == CreateKind::HybridPq1024Tpm2Fido2 {
                        "3-factor: TPM 2.0 + FIDO2 + ML-KEM-1024 + backup passphrase"
                    } else {
                        "3-factor: TPM 2.0 + FIDO2 + ML-KEM-768 + backup passphrase"
                    };
                    section(ui, title, |ui| {
                        ui.label(
                            RichText::new("Backup passphrase (slot 0; recovery path)")
                                .color(theme::WARN).size(12.0),
                        );
                        let te = egui::TextEdit::singleline(&mut *self.create.passphrase)
                            .password(true);
                        ui.add_sized([form_width(ui), CONTROL_H], te);
                        strength_meter(ui, &self.create.passphrase);
                        ui.add_space(8.0);
                        ui.label(RichText::new("FIDO2 PIN").color(theme::DIM).size(12.0));
                        let te = egui::TextEdit::singleline(&mut *self.create.pin).password(true);
                        ui.add_sized([form_width(ui), CONTROL_H], te);
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new(
                                "Seed-file passphrase (encrypts the .kyber seed file at rest. \
                                 Leave empty to reuse the backup passphrase above.)",
                            )
                            .color(theme::DIM).size(12.0),
                        );
                        let te = egui::TextEdit::singleline(&mut *self.create.hybrid_seed_pw)
                            .password(true);
                        ui.add_sized([form_width(ui), CONTROL_H], te);
                        ui.add_space(10.0);
                        ui.label(
                            RichText::new(
                                "Path to write the secret .kyber seed file (KEEP ON SEPARATE STORAGE. All three factors required at every unlock.)",
                            )
                            .color(theme::WARN).size(12.0),
                        );
                        ui.add_sized(
                            [form_width(ui), CONTROL_H],
                            egui::TextEdit::singleline(&mut self.create.hybrid_kyber_path)
                                .hint_text(path_hints::usb("vault.kyber")),
                        );
                        ui.add_space(4.0);
                        if ui
                            .add_sized(
                                [form_width(ui), CONTROL_H],
                                ghost_button("Browse for .kyber save location..."),
                            )
                            .clicked()
                        {
                            self.start_save_picker(
                                "Where to save the Kyber seed",
                                "vault.kyber",
                                PickerTarget::CreateHybridKyber,
                            );
                        }
                    });
                }
            }

            // KDF strength only matters for kinds that stretch a
            // passphrase. Fido2-direct (kind 3) doesn't run Argon2id at
            // all, so hide the selector there.
            if self.create.kind != CreateKind::Fido2Direct {
                section(ui, "KDF strength (Argon2id)", |ui| {
                    egui::ComboBox::from_id_salt("create-kdf")
                        .width(capped_width(ui, 440.0))
                        .selected_text(self.create.kdf.label())
                        .show_ui(ui, |ui| {
                            for kdf in [
                                KdfStrength::Interactive,
                                KdfStrength::Moderate,
                                KdfStrength::Sensitive,
                            ] {
                                ui.selectable_value(&mut self.create.kdf, kdf, kdf.label());
                            }
                        });
                    ui.label(
                        RichText::new(
                            "Higher = slower unlock + more memory cost, harder to \
                             brute-force. Applies to every Argon2id-stretched \
                             keyslot: passphrase, FIDO2 (wrap mode, Argon2id over \
                             passphrase || hmac_secret), and hybrid-pq variants. \
                             FIDO2-direct skips Argon2id (HKDF only, the authenticator \
                             output is already 256 bits of high-entropy secret).",
                        )
                        .color(theme::FAINT)
                        .size(12.0),
                    );
                });
            }

            section(ui, "Hardening", |ui| {
                ui.checkbox(
                    &mut self.create.use_anchor,
                    "Rollback-detection anchor, small 48-byte sidecar. Keep it on separate trusted storage (USB stick) for it to actually defend against rollback.",
                );
                if self.create.use_anchor {
                    ui.add_sized(
                        [form_width(ui), CONTROL_H],
                        egui::TextEdit::singleline(&mut self.create.anchor_path)
                            .hint_text(path_hints::usb("secret.anchor")),
                    );
                    ui.add_space(4.0);
                    // Async picker (start_save_picker spawns a worker
                    // thread), synchronous rfd::FileDialog blocks the
                    // egui main thread and the previous in-row hit-rect
                    // was being collapsed, so the button looked
                    // dead-clicked.
                    if ui
                        .add_sized(
                            [form_width(ui), CONTROL_H],
                            ghost_button("Browse for anchor save location..."),
                        )
                        .clicked()
                    {
                        self.start_save_picker(
                            "Anchor sidecar",
                            "secret.anchor",
                            PickerTarget::CreateAnchor,
                        );
                    }
                }

                if self.create.kind != CreateKind::Fido2Direct {
                    ui.add_space(6.0);
                    ui.collapsing(
                        RichText::new("Advanced size-hiding (paranoid)").color(theme::DIM).size(12.0),
                        |ui| {
                            ui.checkbox(&mut self.create.pad_files, "Pad files to power-of-2 chunks (hides per-file size in a 2× bucket; up to 2× storage cost)");
                            ui.checkbox(&mut self.create.hide_sizes, "Hide exact sizes (encrypts size in chunk-0 plaintext; implies padding)");
                        },
                    );
                }
            });

            add_scroll_edge_padding(ui);
        });
        if submit_via_enter && can_submit {
            self.submit_create();
        }
    }

    fn submit_create(&mut self) {
        if self.create.path.trim().is_empty() {
            self.toast_err("vault path is required");
            return;
        }
        // Empty-passphrase guard: every CreateKind that needs a
        // passphrase (passphrase, hybrid-pq variants, TPM-bootstrap
        // kinds) must have one. Empty is technically valid but means
        // ANYONE with the .lbx file can open the vault, so almost
        // always a mistake. Surface a confirm modal; the user re-clicks
        // Create after confirming, which sets `empty_passphrase_confirm`
        // to None and bypasses this check.
        // Every kind except FIDO2 / FIDO2-direct needs a passphrase
        // (either as the primary slot or as the TPM-bootstrap backup).
        let needs_passphrase = !matches!(
            self.create.kind,
            CreateKind::Fido2 | CreateKind::Fido2Direct
        );
        if needs_passphrase
            && self.create.passphrase.is_empty()
            && self.empty_passphrase_confirm.is_none()
        {
            self.empty_passphrase_confirm = Some(EmptyPassphraseTarget::CreateVault);
            return;
        }
        // FIDO2-direct backup-passphrase guard: the FIDO2-direct kind
        // derives the MVK from the authenticator output (no wrapped
        // MVK on disk). Without a backup passphrase, losing the
        // authenticator = losing the vault, no recovery. Confirm
        // before allowing an empty backup.
        if self.create.kind == CreateKind::Fido2Direct
            && self.create.backup_passphrase.is_empty()
            && self.empty_passphrase_confirm.is_none()
        {
            self.empty_passphrase_confirm = Some(EmptyPassphraseTarget::Fido2DirectBackup);
            return;
        }
        self.empty_passphrase_confirm = None;
        let opts = ops::CreateOpts {
            path: PathBuf::from(self.create.path.trim()),
            header_path: if self.create.use_detached && !self.create.header_path.trim().is_empty() {
                Some(PathBuf::from(self.create.header_path.trim()))
            } else if self.create.use_detached {
                self.toast_err("header sidecar path required");
                return;
            } else {
                None
            },
            cipher: match self.create.cipher {
                CipherChoice::AesSiv => luksbox_core::CipherSuite::Aes256GcmSiv,
                CipherChoice::Aes => luksbox_core::CipherSuite::Aes256Gcm,
                CipherChoice::Chacha => luksbox_core::CipherSuite::ChaCha20Poly1305,
            },
            kind: self.create.kind.to_arg(),
            // `mem::take` MOVES the secret out of the form (replacing
            // it with `Zeroizing(String::new())`) so we don't leave a
            // clone of the passphrase in the form to be zeroed at
            // some unspecified later view-transition. The field stays
            // visible to the user until view-change anyway, since the
            // `submit_create` worker is async.
            // All kinds except FIDO2 / FIDO2-direct route the form
            // passphrase into slot 0. For the TPM-bootstrap kinds it
            // becomes the recovery backup; for the hybrid-PQ kinds it
            // also stretches into the per-slot KEK alongside the PQ
            // shared secret. FIDO2-direct uses `backup_passphrase`
            // separately because it has no primary passphrase factor.
            passphrase: if needs_passphrase {
                Some(std::mem::take(&mut self.create.passphrase))
            } else {
                None
            },
            backup_passphrase: if self.create.kind == CreateKind::Fido2Direct
                && !self.create.backup_passphrase.is_empty()
            {
                Some(std::mem::take(&mut self.create.backup_passphrase))
            } else {
                None
            },
            // PIN: collected by every kind that touches a FIDO2
            // authenticator at create time. The TPM+PIN bootstrap
            // (Tpm2Pin) ALSO uses self.create.pin, but that's
            // forwarded via TpmBootstrapKind below, NOT through
            // CreateOpts.pin (the underlying create path doesn't
            // know about TPM PINs).
            pin: if matches!(
                self.create.kind,
                CreateKind::Fido2
                    | CreateKind::Fido2Direct
                    | CreateKind::HybridPqFido2
                    | CreateKind::HybridPq1024Fido2
            ) {
                Some(std::mem::take(&mut self.create.pin))
            } else {
                None
            },
            pad_files: self.create.pad_files,
            hide_sizes: self.create.hide_sizes,
            anchor_path: if self.create.use_anchor && !self.create.anchor_path.trim().is_empty() {
                Some(PathBuf::from(self.create.anchor_path.trim()))
            } else if self.create.use_anchor {
                self.toast_err("anchor path required");
                return;
            } else {
                None
            },
            // CreateOpts.hybrid_kyber_path is for kinds that produce
            // the .kyber seed inside `create_vault`. The TPM+hybrid
            // bootstrap kinds skip this (they create the .kyber as
            // part of the post-create TPM enroll step) and route the
            // path through TpmBootstrapKind instead.
            hybrid_kyber_path: if matches!(
                self.create.kind,
                CreateKind::HybridPq
                    | CreateKind::HybridPqFido2
                    | CreateKind::HybridPq1024
                    | CreateKind::HybridPq1024Fido2
            ) {
                if self.create.hybrid_kyber_path.trim().is_empty() {
                    self.toast_err("hybrid mode requires a path for the .kyber seed file");
                    return;
                }
                Some(PathBuf::from(self.create.hybrid_kyber_path.trim()))
            } else {
                None
            },
            kdf: self.create.kdf,
        };
        let needs_touch = self.create.kind.needs_fido2();

        // FIDO2 pre-flight for any kind that touches an authenticator.
        // Catches missing-device upfront so the user doesn't waste
        // time on PIN entry / Argon2id only to bounce off a libfido2
        // NoDevices error from inside the worker.
        if needs_touch {
            if let Err(e) = ops::pre_check_fido2() {
                self.toast_err(e);
                return;
            }
        }

        // TPM-bootstrap path: pre-flight the chip so the common
        // "user not in tss group" failure surfaces BEFORE we touch
        // disk, then dispatch the atomic create+enroll worker that
        // rolls back the vault on failure. Without this atomic shape,
        // a TPM-enroll failure would leave a passphrase-only vault on
        // disk - silently giving the user the weak fallback they did
        // NOT ask for.
        // For hybrid-PQ TPM kinds we need the .kyber path + a seed-file
        // passphrase. The seed-file passphrase reuses the form's
        // passphrase field (it has already been moved into `opts.passphrase`
        // above; clone before the move to keep a copy here). Simpler:
        // re-borrow from opts.passphrase for the bootstrap struct.
        let tpm_bootstrap_kind: Option<ops::TpmBootstrapKind> = match self.create.kind {
            CreateKind::Tpm2 => Some(ops::TpmBootstrapKind::Tpm2),
            CreateKind::Tpm2Pin => {
                let pin = std::mem::take(&mut self.create.pin);
                if pin.is_empty() {
                    self.toast_err("TPM PIN required");
                    return;
                }
                Some(ops::TpmBootstrapKind::Tpm2Pin { pin })
            }
            CreateKind::Tpm2Fido2 => {
                let pin = std::mem::take(&mut self.create.pin);
                if pin.is_empty() {
                    self.toast_err("FIDO2 PIN required");
                    return;
                }
                Some(ops::TpmBootstrapKind::Tpm2Fido2 { pin })
            }
            CreateKind::HybridPqTpm2 | CreateKind::HybridPq1024Tpm2 => {
                if self.create.hybrid_kyber_path.trim().is_empty() {
                    self.toast_err("hybrid TPM kind requires a path for the .kyber seed file");
                    return;
                }
                let kem_size = if self.create.kind == CreateKind::HybridPq1024Tpm2 {
                    1024
                } else {
                    768
                };
                // Seed-file passphrase: prefer the explicit
                // `hybrid_seed_pw` field if the user filled it; fall
                // back to the backup passphrase from `opts.passphrase`
                // otherwise (the legacy default before we exposed the
                // separate field).
                let seed_pw = {
                    let explicit = std::mem::take(&mut self.create.hybrid_seed_pw);
                    if !explicit.is_empty() {
                        explicit
                    } else {
                        opts.passphrase
                            .as_ref()
                            .cloned()
                            .unwrap_or_else(|| zeroize::Zeroizing::new(String::new()))
                    }
                };
                Some(ops::TpmBootstrapKind::HybridPqTpm2 {
                    kyber_path: PathBuf::from(self.create.hybrid_kyber_path.trim()),
                    seed_pw,
                    kem_size,
                })
            }
            CreateKind::HybridPqTpm2Fido2 | CreateKind::HybridPq1024Tpm2Fido2 => {
                if self.create.hybrid_kyber_path.trim().is_empty() {
                    self.toast_err("hybrid TPM kind requires a path for the .kyber seed file");
                    return;
                }
                let pin = std::mem::take(&mut self.create.pin);
                if pin.is_empty() {
                    self.toast_err("FIDO2 PIN required");
                    return;
                }
                let kem_size = if self.create.kind == CreateKind::HybridPq1024Tpm2Fido2 {
                    1024
                } else {
                    768
                };
                let seed_pw = {
                    let explicit = std::mem::take(&mut self.create.hybrid_seed_pw);
                    if !explicit.is_empty() {
                        explicit
                    } else {
                        opts.passphrase
                            .as_ref()
                            .cloned()
                            .unwrap_or_else(|| zeroize::Zeroizing::new(String::new()))
                    }
                };
                Some(ops::TpmBootstrapKind::HybridPqTpm2Fido2 {
                    kyber_path: PathBuf::from(self.create.hybrid_kyber_path.trim()),
                    seed_pw,
                    pin,
                    kem_size,
                })
            }
            _ => None,
        };

        if let Some(kind) = tpm_bootstrap_kind {
            if let Err(e) = ops::pre_check_tpm() {
                self.toast_err(e);
                return;
            }
            let rx = ops::spawn(move || ops::create_vault_with_tpm_bootstrap(opts, kind));
            self.pending = Some(Pending::CreateWithTpmBootstrap { rx, needs_touch });
            return;
        }

        let rx = ops::spawn(move || ops::create_vault(opts));
        self.pending = Some(Pending::Create { rx, needs_touch });
    }
}

// ---- unlock ---------------------------------------------------------------

impl LuksboxApp {
    fn draw_unlock(&mut self, ui: &mut egui::Ui) {
        let can_submit = self.pending.is_none();
        let mut submit = false;
        let mut go_back = false;
        // Top bar: Back on the left, title centered, Unlock button
        // pinned to the right (matches the create view's layout).
        ui.horizontal(|ui| {
            if ui.button("< Back").clicked() {
                go_back = true;
            }
            ui.add_space(8.0);
            ui.label(RichText::new("Unlock vault").size(20.0).strong());
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .add_enabled(can_submit, primary_button("Unlock"))
                    .clicked()
                {
                    submit = true;
                }
            });
        });
        ui.label(
            RichText::new(&self.unlock.path)
                .color(theme::DIM)
                .size(12.0)
                .monospace(),
        );
        ui.separator();
        ui.add_space(10.0);
        if go_back {
            // Wipe typed passphrase / PIN, see Create-view comment.
            self.unlock = UnlockForm::default();
            self.view = View::Welcome;
            return;
        }
        if submit {
            self.submit_unlock();
        }

        ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                let total_w = ui.available_width();
                // Threshold below which the right-side slot panel
                // would crowd the form fields. Below this we fall
                // back to the single-column flow with the slot panel
                // on top.
                let split = total_w >= 760.0;
                if split {
                    ui.horizontal_top(|ui| {
                        let gap = 16.0_f32;
                        // Left column gets about 62 % so the form fields
                        // have comfortable room; right column gets
                        // the rest, but not less than 240 px so the
                        // slot kind labels don't wrap awkwardly.
                        let left_w = ((total_w - gap) * 0.62).clamp(360.0, total_w - gap - 240.0);
                        let right_w = total_w - gap - left_w;
                        ui.allocate_ui_with_layout(
                            Vec2::new(left_w, 0.0),
                            Layout::top_down(Align::Min),
                            |ui| {
                                self.draw_unlock_form(ui);
                            },
                        );
                        ui.add_space(gap);
                        ui.allocate_ui_with_layout(
                            Vec2::new(right_w, 0.0),
                            Layout::top_down(Align::Min),
                            |ui| {
                                self.draw_unlock_slot_panel(ui);
                            },
                        );
                    });
                } else {
                    self.draw_unlock_slot_panel(ui);
                    self.draw_unlock_form(ui);
                }
                add_scroll_edge_padding(ui);
            });
    }

    /// Right-side panel showing the vault's keyslot composition.
    /// Read from the unencrypted on-disk header at `start_unlock`
    /// and cached on `UnlockForm::slot_inspection`. Renders nothing
    /// if the user typed a path manually instead of clicking a
    /// recent (no header read attempted yet).
    ///
    /// Visually distinct from the left form: a tinted (`PANEL2`)
    /// background + accent-colored border + accent-colored title so
    /// the user reads it as informational context rather than as a
    /// required input.
    fn draw_unlock_slot_panel(&mut self, ui: &mut egui::Ui) {
        let Some(inspection) = self.unlock.slot_inspection.as_ref() else {
            return;
        };
        let frame = Frame::new()
            .fill(theme::PANEL2)
            .stroke(Stroke::new(1.0, theme::ACCENT.linear_multiply(0.4)))
            .corner_radius(CornerRadius::same(10))
            .inner_margin(18);
        frame.show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.label(
                RichText::new("KEYSLOTS IN THIS VAULT")
                    .color(theme::ACCENT)
                    .small()
                    .strong(),
            );
            ui.add_space(8.0);
            match inspection {
                Ok(slots) if slots.is_empty() => {
                    ui.label(
                        RichText::new("(no populated keyslots; vault may be corrupt)")
                            .color(theme::DANGER)
                            .size(12.0),
                    );
                }
                Ok(slots) => {
                    for line in slots {
                        ui.label(
                            RichText::new(line)
                                .monospace()
                                .size(12.0)
                                .color(theme::TEXT),
                        );
                    }
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(
                            "Read from the (unencrypted) on-disk header. \
                             Match the unlock method on the left to one \
                             of these slots.",
                        )
                        .color(theme::DIM)
                        .size(11.0),
                    );
                }
                Err(msg) => {
                    ui.label(
                        RichText::new(format!("could not inspect slots: {msg}"))
                            .color(theme::DANGER)
                            .size(12.0),
                    );
                }
            }
        });
        ui.add_space(12.0);
    }

    /// Left-side form: Sidecars + Method + per-method inputs. Form
    /// fields use the column's full inner width (instead of the
    /// global `FORM_FIELD_MAX_W` cap) so the 2-column layout doesn't
    /// leave a wide right margin inside each section.
    fn draw_unlock_form(&mut self, ui: &mut egui::Ui) {
        section(ui, "Sidecars", |ui| {
            ui.checkbox(
                &mut self.unlock.use_detached,
                "This vault uses a detached header sidecar",
            );
            if self.unlock.use_detached {
                ui.horizontal(|ui| {
                    let (field_w, browse_w) =
                        trailing_button_row_widths(ui, FORM_FIELD_MAX_W, 90.0);
                    ui.add_sized(
                        [field_w, CONTROL_H],
                        egui::TextEdit::singleline(&mut self.unlock.header_path)
                            .hint_text("path to .hdr"),
                    );
                    if ui
                        .add_sized([browse_w, CONTROL_H], ghost_button("Browse..."))
                        .clicked()
                        && let Some(p) = rfd::FileDialog::new()
                            .set_title("Header sidecar")
                            .pick_file()
                    {
                        self.unlock.header_path = p.display().to_string();
                    }
                });
            }
            ui.add_space(6.0);
            ui.checkbox(
                &mut self.unlock.use_anchor,
                "Verify against a rollback-detection anchor sidecar",
            );
            if self.unlock.use_anchor {
                ui.horizontal(|ui| {
                    let (field_w, browse_w) =
                        trailing_button_row_widths(ui, FORM_FIELD_MAX_W, 90.0);
                    ui.add_sized(
                        [field_w, CONTROL_H],
                        egui::TextEdit::singleline(&mut self.unlock.anchor_path)
                            .hint_text("path to .anchor"),
                    );
                    if ui
                        .add_sized([browse_w, CONTROL_H], ghost_button("Browse..."))
                        .clicked()
                        && let Some(p) = rfd::FileDialog::new()
                            .set_title("Anchor sidecar")
                            .pick_file()
                    {
                        self.unlock.anchor_path = p.display().to_string();
                    }
                });
            }
        });

        section(ui, "Method", |ui| {
            ui.radio_value(
                &mut self.unlock.method,
                UnlockMethod::Passphrase,
                "Passphrase",
            );
            ui.radio_value(
                &mut self.unlock.method,
                UnlockMethod::Fido2,
                "FIDO2 authenticator (passphrase backup)",
            );
            ui.radio_value(
                &mut self.unlock.method,
                UnlockMethod::HybridPq,
                "Hybrid passphrase + ML-KEM (post-quantum)",
            );
            ui.radio_value(
                &mut self.unlock.method,
                UnlockMethod::HybridPqFido2,
                "Hybrid FIDO2 + ML-KEM (post-quantum, authenticator + .kyber)",
            );
            // TPM unlock methods only on Linux. Windows TPM
            // is on the roadmap (see docs/SECURITY.md Tier 3
            // item 10); macOS uses Secure Enclave instead. On
            // those platforms hide the radios so users don't
            // see options that would just error.
            #[cfg(target_os = "linux")]
            {
                ui.radio_value(
                    &mut self.unlock.method,
                    UnlockMethod::Tpm2,
                    "TPM 2.0 (this machine, no passphrase)",
                );
                ui.radio_value(
                    &mut self.unlock.method,
                    UnlockMethod::Tpm2Pin,
                    "TPM 2.0 + PIN (this machine + memorised PIN)",
                );
                ui.radio_value(
                    &mut self.unlock.method,
                    UnlockMethod::Tpm2Fido2,
                    "TPM 2.0 + FIDO2 (this machine AND this authenticator)",
                );
                ui.radio_value(
                    &mut self.unlock.method,
                    UnlockMethod::HybridPqTpm2,
                    "Hybrid TPM 2.0 + ML-KEM (PQ + machine-bound)",
                );
                ui.radio_value(
                    &mut self.unlock.method,
                    UnlockMethod::HybridPqTpm2Fido2,
                    "Hybrid TPM 2.0 + FIDO2 + ML-KEM (3 factors)",
                );
            }
            if matches!(
                self.unlock.method,
                UnlockMethod::HybridPq
                    | UnlockMethod::HybridPqFido2
                    | UnlockMethod::HybridPqTpm2
                    | UnlockMethod::HybridPqTpm2Fido2
            ) {
                ui.label(
                    RichText::new(
                        "ML-KEM parameter set (768 or 1024) is auto-detected from the \
                         .hybrid sidecar, no need to choose.",
                    )
                    .color(theme::FAINT)
                    .size(12.0),
                );
            }
        });

        match self.unlock.method {
            UnlockMethod::Passphrase => {
                section(ui, "Passphrase", |ui| {
                    let te =
                        egui::TextEdit::singleline(&mut *self.unlock.passphrase).password(true);
                    let resp = ui.add_sized([form_width(ui), CONTROL_H], te);
                    strength_meter(ui, &self.unlock.passphrase);
                    if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        self.submit_unlock();
                    }
                });
            }
            UnlockMethod::Fido2 => {
                section(ui, "FIDO2 PIN", |ui| {
                    let te = egui::TextEdit::singleline(&mut *self.unlock.pin).password(true);
                    let resp = ui.add_sized([form_width(ui), CONTROL_H], te);
                    if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        self.submit_unlock();
                    }
                    ui.label(
                        RichText::new(
                            "You'll be asked to touch your authenticator once it has the PIN.",
                        )
                        .color(theme::FAINT)
                        .size(12.0),
                    );
                });
            }
            UnlockMethod::HybridPq => {
                section(ui, "Hybrid (passphrase + Kyber)", |ui| {
                    ui.label(RichText::new("Passphrase").color(theme::DIM).size(12.0));
                    let te =
                        egui::TextEdit::singleline(&mut *self.unlock.passphrase).password(true);
                    ui.add_sized([form_width(ui), CONTROL_H], te);
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("Path to the .kyber seed file")
                            .color(theme::DIM)
                            .size(12.0),
                    );
                    ui.horizontal(|ui| {
                        let (field_w, browse_w) = trailing_button_row_widths(ui, 400.0, 90.0);
                        ui.add_sized(
                            [field_w, CONTROL_H],
                            egui::TextEdit::singleline(&mut self.unlock.hybrid_kyber_path)
                                .hint_text(path_hints::usb("vault.kyber")),
                        );
                        if ui
                            .add_sized([browse_w, CONTROL_H], ghost_button("Browse..."))
                            .clicked()
                        {
                            self.start_open_picker(
                                "Kyber seed file",
                                PickerTarget::UnlockHybridKyber,
                            );
                        }
                    });
                });
            }
            UnlockMethod::Tpm2 => {
                section(ui, "TPM 2.0 (this machine)", |ui| {
                    ui.label(
                        RichText::new(
                            "No passphrase needed - the local TPM chip will \
                                     unseal the wrap key.",
                        )
                        .color(theme::FAINT)
                        .size(12.0),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(
                            "Linux only. Requires /dev/tpmrm0 access (typically \
                                     via membership in the `tss` group).",
                        )
                        .color(theme::FAINT)
                        .size(11.0),
                    );
                });
            }
            UnlockMethod::Tpm2Pin => {
                section(ui, "TPM 2.0 + PIN", |ui| {
                    ui.label(RichText::new("TPM PIN").color(theme::DIM).size(12.0));
                    let te = egui::TextEdit::singleline(&mut *self.unlock.pin).password(true);
                    let resp = ui.add_sized([form_width(ui), CONTROL_H], te);
                    if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        self.submit_unlock();
                    }
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(
                            "The PIN is presented to the chip's userAuth slot. Wrong \
                                     PINs count toward the chip's dictionary-attack lockout, \
                                     so even short PINs (4-6 digits) are secure on the original \
                                     hardware.",
                        )
                        .color(theme::FAINT)
                        .size(12.0),
                    );
                });
            }
            UnlockMethod::Tpm2Fido2 => {
                section(ui, "TPM 2.0 + FIDO2 (both required)", |ui| {
                    ui.label(RichText::new("FIDO2 PIN").color(theme::DIM).size(12.0));
                    let te = egui::TextEdit::singleline(&mut *self.unlock.pin).password(true);
                    let resp = ui.add_sized([form_width(ui), CONTROL_H], te);
                    if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        self.submit_unlock();
                    }
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(
                            "Both factors required: the local TPM chip AND a \
                                     touch on your authenticator. Either factor wrong \
                                     fails the unlock.",
                        )
                        .color(theme::FAINT)
                        .size(12.0),
                    );
                });
            }
            UnlockMethod::HybridPqTpm2 => {
                section(ui, "Hybrid TPM 2.0 + ML-KEM", |ui| {
                    ui.label(
                        RichText::new("Seed-file passphrase (encrypts the .kyber seed)")
                            .color(theme::DIM)
                            .size(12.0),
                    );
                    let te =
                        egui::TextEdit::singleline(&mut *self.unlock.passphrase).password(true);
                    ui.add_sized([form_width(ui), CONTROL_H], te);
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("Path to the .kyber seed file")
                            .color(theme::DIM)
                            .size(12.0),
                    );
                    ui.horizontal(|ui| {
                        let (field_w, browse_w) = trailing_button_row_widths(ui, 400.0, 90.0);
                        ui.add_sized(
                            [field_w, CONTROL_H],
                            egui::TextEdit::singleline(&mut self.unlock.hybrid_kyber_path)
                                .hint_text(path_hints::usb("vault.kyber")),
                        );
                        if ui
                            .add_sized([browse_w, CONTROL_H], ghost_button("Browse..."))
                            .clicked()
                        {
                            self.start_open_picker(
                                "Kyber seed file",
                                PickerTarget::UnlockHybridKyber,
                            );
                        }
                    });
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(
                            "Two factors: the local TPM chip AND the .kyber seed file. \
                                     Closes the quantum-attack gap of plain TPM.",
                        )
                        .color(theme::FAINT)
                        .size(12.0),
                    );
                });
            }
            UnlockMethod::HybridPqTpm2Fido2 => {
                section(ui, "Hybrid TPM 2.0 + FIDO2 + ML-KEM", |ui| {
                    ui.label(RichText::new("FIDO2 PIN").color(theme::DIM).size(12.0));
                    let te = egui::TextEdit::singleline(&mut *self.unlock.pin).password(true);
                    ui.add_sized([form_width(ui), CONTROL_H], te);
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("Seed-file passphrase (encrypts the .kyber seed)")
                            .color(theme::DIM)
                            .size(12.0),
                    );
                    let te =
                        egui::TextEdit::singleline(&mut *self.unlock.passphrase).password(true);
                    ui.add_sized([form_width(ui), CONTROL_H], te);
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("Path to the .kyber seed file")
                            .color(theme::DIM)
                            .size(12.0),
                    );
                    ui.horizontal(|ui| {
                        let (field_w, browse_w) = trailing_button_row_widths(ui, 400.0, 90.0);
                        ui.add_sized(
                            [field_w, CONTROL_H],
                            egui::TextEdit::singleline(&mut self.unlock.hybrid_kyber_path)
                                .hint_text(path_hints::usb("vault.kyber")),
                        );
                        if ui
                            .add_sized([browse_w, CONTROL_H], ghost_button("Browse..."))
                            .clicked()
                        {
                            self.start_open_picker(
                                "Kyber seed file",
                                PickerTarget::UnlockHybridKyber,
                            );
                        }
                    });
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(
                            "Three factors required: local TPM AND the FIDO2 \
                                     authenticator AND the .kyber seed file.",
                        )
                        .color(theme::FAINT)
                        .size(12.0),
                    );
                });
            }
            UnlockMethod::HybridPqFido2 => {
                section(ui, "Hybrid (FIDO2 + Kyber)", |ui| {
                    ui.label(RichText::new("FIDO2 PIN").color(theme::DIM).size(12.0));
                    let te = egui::TextEdit::singleline(&mut *self.unlock.pin).password(true);
                    ui.add_sized([form_width(ui), CONTROL_H], te);
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("Seed-file passphrase (encrypts the .kyber seed)")
                            .color(theme::DIM)
                            .size(12.0),
                    );
                    let te =
                        egui::TextEdit::singleline(&mut *self.unlock.passphrase).password(true);
                    ui.add_sized([form_width(ui), CONTROL_H], te);
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("Path to the .kyber seed file")
                            .color(theme::DIM)
                            .size(12.0),
                    );
                    ui.horizontal(|ui| {
                        let (field_w, browse_w) = trailing_button_row_widths(ui, 400.0, 90.0);
                        ui.add_sized(
                            [field_w, CONTROL_H],
                            egui::TextEdit::singleline(&mut self.unlock.hybrid_kyber_path)
                                .hint_text(path_hints::usb("vault.kyber")),
                        );
                        if ui
                            .add_sized([browse_w, CONTROL_H], ghost_button("Browse..."))
                            .clicked()
                        {
                            self.start_open_picker(
                                "Kyber seed file",
                                PickerTarget::UnlockHybridKyber,
                            );
                        }
                    });
                    ui.label(
                        RichText::new(
                            "You'll be asked to touch your authenticator once it has the PIN.",
                        )
                        .color(theme::FAINT)
                        .size(12.0),
                    );
                });
            }
        }
    }

    fn submit_unlock(&mut self) {
        if self.unlock.path.trim().is_empty() {
            self.toast_err("vault path required");
            return;
        }
        let opts = ops::UnlockOpts {
            path: PathBuf::from(self.unlock.path.trim()),
            header_path: if self.unlock.use_detached && !self.unlock.header_path.trim().is_empty() {
                Some(PathBuf::from(self.unlock.header_path.trim()))
            } else {
                None
            },
            anchor_path: if self.unlock.use_anchor && !self.unlock.anchor_path.trim().is_empty() {
                Some(PathBuf::from(self.unlock.anchor_path.trim()))
            } else {
                None
            },
            method: self.unlock.method,
            // mem::take, see comment on submit_create: avoids leaving
            // an extra copy of the secret in the form.
            passphrase: if matches!(
                self.unlock.method,
                UnlockMethod::Passphrase
                    | UnlockMethod::HybridPq
                    | UnlockMethod::HybridPqFido2
                    | UnlockMethod::HybridPqTpm2
                    | UnlockMethod::HybridPqTpm2Fido2
            ) {
                Some(std::mem::take(&mut self.unlock.passphrase))
            } else {
                None
            },
            pin: if matches!(
                self.unlock.method,
                UnlockMethod::Fido2
                    | UnlockMethod::HybridPqFido2
                    | UnlockMethod::Tpm2Pin
                    | UnlockMethod::Tpm2Fido2
                    | UnlockMethod::HybridPqTpm2Fido2
            ) {
                Some(std::mem::take(&mut self.unlock.pin))
            } else {
                None
            },
            hybrid_kyber_path: if matches!(
                self.unlock.method,
                UnlockMethod::HybridPq
                    | UnlockMethod::HybridPqFido2
                    | UnlockMethod::HybridPqTpm2
                    | UnlockMethod::HybridPqTpm2Fido2
            ) {
                if self.unlock.hybrid_kyber_path.trim().is_empty() {
                    self.toast_err("hybrid mode requires the .kyber seed file path");
                    return;
                }
                Some(PathBuf::from(self.unlock.hybrid_kyber_path.trim()))
            } else {
                None
            },
        };
        let needs_touch = matches!(
            opts.method,
            UnlockMethod::Fido2
                | UnlockMethod::HybridPqFido2
                | UnlockMethod::Tpm2Fido2
                | UnlockMethod::HybridPqTpm2Fido2
        );
        let rx = ops::spawn(move || ops::unlock_vault(opts));
        self.pending = Some(Pending::Unlock { rx, needs_touch });
    }
}

// ---- browser --------------------------------------------------------------

impl LuksboxApp {
    fn draw_browser(&mut self, ui: &mut egui::Ui) {
        // Mounted state: the Vfs has been moved into the mount thread,
        // so neither the file list nor any keyslot/info action makes
        // sense. Show a short status panel + Unmount button instead.
        if self.mount_status.is_some() {
            self.draw_mounted(ui);
            return;
        }

        let title = self
            .vault
            .as_ref()
            .map(|v| {
                v.vault_path
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| v.vault_path.display().to_string())
            })
            .unwrap_or_else(|| "(no vault)".into());
        let cipher = self
            .vault
            .as_ref()
            .map(|v| v.cipher_label.clone())
            .unwrap_or_default();

        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(RichText::new(title).size(22.0).strong());
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&self.cwd).monospace().color(theme::DIM));
                    ui.label(
                        RichText::new(format!("· {}", cipher))
                            .small()
                            .color(theme::FAINT),
                    );
                });
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.add(ghost_button("Lock")).clicked() {
                    // Explicit user action; no confirm modal needed
                    // (the click IS the confirmation).
                    self.execute_navigate(NavigateAction::GoWelcome);
                }
                let mount_tooltip = if cfg!(target_os = "windows") {
                    "Mount the vault as a Windows drive (auto-picks the next free \
                     letter from Z down). Requires WinFsp installed; use the \
                     drive in Explorer like any other volume. Click Unmount or \
                     close LUKSbox to release."
                } else {
                    "Mount the vault as a virtual filesystem at a directory you \
                     pick (must exist and be empty). Files you copy in are \
                     encrypted on the fly. Requires macFUSE (macOS, \
                     approve kext on first install) or libfuse3 (Linux)."
                };
                if ui
                    .add(ghost_button("Mount as volume..."))
                    .on_hover_text(mount_tooltip)
                    .clicked()
                {
                    self.start_mount_picker();
                }
                if ui.add(ghost_button("Keyslots")).clicked() {
                    self.view = View::Keyslots;
                }
                if ui.add(ghost_button("+ Add file...")).clicked() {
                    self.add_file_picker();
                }
                if ui.add(ghost_button("+ Folder")).clicked() {
                    self.mkdir_input = Some(String::new());
                }
            });
        });
        ui.add_space(14.0);

        if let Some(e) = &self.listing_err {
            ui.colored_label(theme::DANGER, e);
        }

        // Breadcrumb / parent-up
        if self.cwd != "/" {
            if ui
                .button(RichText::new("< parent dir").color(theme::DIM))
                .clicked()
            {
                let parent = parent_path(&self.cwd);
                self.cwd = parent;
                self.refresh_listing();
            }
            ui.add_space(8.0);
        }

        Frame::new()
            .fill(theme::PANEL)
            .stroke(Stroke::new(1.0, theme::BORDER))
            .corner_radius(CornerRadius::same(10))
            .inner_margin(0)
            .show(ui, |ui| {
                if self.listing.is_empty() && self.listing_err.is_none() {
                    ui.add_space(40.0);
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new("Empty directory").color(theme::FAINT));
                    });
                    ui.add_space(40.0);
                    return;
                }
                let entries = self.listing.clone();
                let mut nav_into: Option<String> = None;
                let mut do_download: Option<String> = None;
                let mut do_download_dir: Option<String> = None;
                let mut do_rename: Option<(String, bool)> = None;
                let mut do_delete: Option<(String, bool)> = None;
                ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .show(ui, |ui| {
                        for ent in &entries {
                            let resp = Frame::new()
                                .inner_margin(Margin::symmetric(16, 8))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        let icon = if ent.kind == InodeKind::Directory {
                                            "[D]"
                                        } else {
                                            "[ ]"
                                        };
                                        ui.label(RichText::new(icon).size(15.0));
                                        ui.label(
                                            RichText::new(&ent.name).strong().color(theme::TEXT),
                                        );
                                        ui.with_layout(
                                            Layout::right_to_left(Align::Center),
                                            |ui| {
                                                if ent.kind == InodeKind::File {
                                                    ui.label(
                                                        RichText::new(format_size(ent.size))
                                                            .color(theme::FAINT)
                                                            .small(),
                                                    );
                                                }
                                            },
                                        );
                                    });
                                })
                                .response
                                .interact(egui::Sense::click());

                            // Right-click context menu, replaces the per-row buttons.
                            resp.context_menu(|ui| {
                                match ent.kind {
                                    InodeKind::Directory => {
                                        if ui.button("Open").clicked() {
                                            nav_into = Some(ent.name.clone());
                                            ui.close();
                                        }
                                        if ui
                                            .button("Download (recursive)...")
                                            .on_hover_text(
                                                "Recursively extract this folder \
                                             and everything inside it to disk.",
                                            )
                                            .clicked()
                                        {
                                            do_download_dir = Some(ent.name.clone());
                                            ui.close();
                                        }
                                    }
                                    InodeKind::File => {
                                        if ui.button("Download...").clicked() {
                                            do_download = Some(ent.name.clone());
                                            ui.close();
                                        }
                                    }
                                }
                                if ui.button("Rename...").clicked() {
                                    do_rename =
                                        Some((ent.name.clone(), ent.kind == InodeKind::Directory));
                                    ui.close();
                                }
                                ui.separator();
                                if ui
                                    .button(RichText::new("Delete").color(theme::DANGER))
                                    .clicked()
                                {
                                    do_delete =
                                        Some((ent.name.clone(), ent.kind == InodeKind::Directory));
                                    ui.close();
                                }
                            });

                            // Double-click to open dirs (left-click). Standard
                            // file-manager pattern; right-click also offers Open.
                            if ent.kind == InodeKind::Directory && resp.double_clicked() {
                                nav_into = Some(ent.name.clone());
                            }
                            ui.separator();
                        }
                        add_scroll_edge_padding(ui);
                    });

                // Dispatch the row action picked above (after the loop so
                // we don't mutate self.listing while iterating it).
                if let Some(name) = nav_into {
                    self.cwd = join_path(&self.cwd, &name);
                    self.refresh_listing();
                } else if let Some(name) = do_download {
                    self.start_get_file(&name);
                } else if let Some(name) = do_download_dir {
                    self.start_get_dir(&name);
                } else if let Some((name, is_dir)) = do_rename {
                    self.rename_target = Some(RenameTarget {
                        old_name: name.clone(),
                        buf: name,
                        is_dir,
                    });
                } else if let Some((name, is_dir)) = do_delete {
                    self.delete_entry(&name, is_dir);
                }
            });
    }

    fn add_file_picker(&mut self) {
        let Some(local) = rfd::FileDialog::new()
            .set_title("Add file to vault")
            .pick_file()
        else {
            return;
        };
        let name = match local.file_name() {
            Some(n) => n.to_string_lossy().into_owned(),
            None => {
                self.toast_err("could not determine filename");
                return;
            }
        };
        let inner = join_path(&self.cwd, &name);
        let v = match self.vault.take() {
            Some(v) => v,
            None => return,
        };
        // Single channel: worker sends BOTH the vault and the result so
        // the main thread is never blocked waiting for the vault back.
        // Pending is set immediately, so the spinner overlay shows up
        // before the slow op even starts.
        let (tx, rx) = std::sync::mpsc::channel::<VaultRet<u64>>();
        std::thread::spawn(move || {
            let mut v = v;
            let r = ops::put_file(&mut v.vfs, &local, &inner);
            let _ = tx.send((v, r));
        });
        self.pending = Some(Pending::PutFile { rx, name });
    }

    fn start_get_dir(&mut self, name: &str) {
        let inner = join_path(&self.cwd, name);
        let Some(parent_dir) = rfd::FileDialog::new()
            .set_title("Choose destination folder for the recursive extract")
            .pick_folder()
        else {
            return;
        };
        let local = parent_dir.join(name);
        if local.exists() {
            self.toast_err(format!(
                "{} already exists in destination - pick another folder or move it aside first",
                local.display()
            ));
            return;
        }
        let v = match self.vault.take() {
            Some(v) => v,
            None => return,
        };
        let (tx, rx) = std::sync::mpsc::channel::<VaultRet<u64>>();
        std::thread::spawn(move || {
            let mut v = v;
            let r = ops::get_dir_recursive(&mut v.vfs, &inner, &local);
            let _ = tx.send((v, r));
        });
        self.pending = Some(Pending::GetFile { rx });
    }

    fn start_get_file(&mut self, name: &str) {
        let inner = join_path(&self.cwd, name);
        // Build the save dialog with a filter matching the file's
        // own extension. Windows' `IFileSaveDialog` (which `rfd`
        // wraps) strips a pre-filled filename's extension when no
        // file-type filter matches it - so "foo.pptx" gets saved
        // as "foo" with no extension. Registering the extension as
        // a filter makes the dialog treat it as a known type and
        // preserves it. macOS / Linux handle pre-filled names
        // verbatim regardless of filters but the filter is harmless
        // there. The "All files" fallback lets the user override
        // the suggested type.
        let mut dialog = rfd::FileDialog::new()
            .set_title("Save extracted file as")
            .set_file_name(name);
        if let Some(ext) = std::path::Path::new(name)
            .extension()
            .and_then(|s| s.to_str())
        {
            let filter_label = format!(".{ext} file");
            dialog = dialog.add_filter(&filter_label, &[ext]);
        }
        dialog = dialog.add_filter("All files", &["*"]);
        let Some(mut local) = dialog.save_file() else {
            return;
        };
        // Last-resort guard: if the chosen path has NO extension
        // but the source file did (e.g. user typed a bare name in
        // the dialog, or Windows stripped it despite the filter),
        // restore the source's extension. Without this, double-
        // clicking the saved file in Explorer fails to launch the
        // associated app even though the bytes are intact. Skip
        // when the chosen path already has an extension (the user
        // explicitly chose to rename to a different type).
        if local.extension().is_none() {
            if let Some(ext) = std::path::Path::new(name)
                .extension()
                .and_then(|s| s.to_str())
            {
                local.set_extension(ext);
            }
        }
        let v = match self.vault.take() {
            Some(v) => v,
            None => return,
        };
        let (tx, rx) = std::sync::mpsc::channel::<VaultRet<u64>>();
        std::thread::spawn(move || {
            let mut v = v;
            let r = ops::get_file(&mut v.vfs, &inner, &local);
            let _ = tx.send((v, r));
        });
        self.pending = Some(Pending::GetFile { rx });
    }

    fn delete_entry(&mut self, name: &str, is_dir: bool) {
        let v = match self.vault.as_mut() {
            Some(v) => v,
            None => return,
        };
        let parent_id = match v.vfs.lookup_path(&self.cwd) {
            Ok(id) => id,
            Err(e) => {
                self.toast_err(e.to_string());
                return;
            }
        };
        let r = if is_dir {
            v.vfs.rmdir(parent_id, name).map_err(|e| e.to_string())
        } else {
            v.vfs.unlink(parent_id, name).map_err(|e| e.to_string())
        };
        match r {
            Ok(()) => {
                let _ = v.vfs.flush();
                self.toast_ok(format!("removed {name}"));
                self.refresh_listing();
            }
            Err(e) => self.toast_err(e),
        }
    }

    /// Open a folder picker, then spawn the mount on a worker thread.
    /// The Vfs is moved into the thread; the GUI no longer owns it
    /// while mounted, hence the dedicated "mounted" UI in `draw_mounted`.
    fn start_mount_picker(&mut self) {
        // Mountpoint semantics differ by OS:
        //
        // - Linux / macOS: FUSE mounts onto an existing directory.
        //   The user picks an empty folder; we pass it through.
        //
        // - Windows: WinFsp wants either a drive letter (`Z:`) OR a
        //   non-existent path it will materialize as a reparse point.
        //   Passing an existing directory yields
        //   STATUS_OBJECT_NAME_COLLISION (0xC0000035) at start_failed.
        //   We auto-pick the next free drive letter so the user never
        //   has to know this rule. Power users who want a specific
        //   letter can use the CLI, which forwards whatever path
        //   they supplied.
        let mountpoint: PathBuf = if cfg!(target_os = "windows") {
            match find_free_windows_drive_letter() {
                Some(p) => p,
                None => {
                    self.toast_err(
                        "no free drive letter available; unmount something or use the CLI \
                         with an explicit path",
                    );
                    return;
                }
            }
        } else {
            let Some(mp) = rfd::FileDialog::new()
                .set_title("Choose mountpoint (existing empty directory)")
                .pick_folder()
            else {
                return;
            };
            mp
        };
        let Some(opened) = self.vault.take() else {
            return;
        };
        let mp_clone = mountpoint.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let r = luksbox_mount::mount(opened.vfs, &mp_clone, false).map_err(|e| e.to_string());
            let _ = tx.send(r);
        });
        self.mount_status = Some(MountStatus {
            mountpoint,
            rx,
            unmount_requested: false,
        });
    }

    /// View shown while a mount is in flight. No file list (Vfs is gone),
    /// just status + Unmount.
    fn draw_mounted(&mut self, ui: &mut egui::Ui) {
        let Some(ms) = self.mount_status.as_ref() else {
            return;
        };
        let mp = ms.mountpoint.display().to_string();
        let pending_unmount = ms.unmount_requested;

        ui.label(
            RichText::new("Vault mounted")
                .size(22.0)
                .strong()
                .color(theme::OK),
        );
        ui.add_space(8.0);
        ui.label(
            RichText::new(format!("at  {}", mp))
                .monospace()
                .color(theme::DIM),
        );
        ui.add_space(18.0);
        ui.label(
            RichText::new(
                "Open the mountpoint in your file manager to read and write \
                 vault contents like a regular folder. Files you copy in are \
                 encrypted on the fly and stored as chunks inside the .lbx.",
            )
            .color(theme::DIM)
            .size(13.0),
        );
        ui.add_space(20.0);

        ui.horizontal(|ui| {
            let label = if pending_unmount {
                "Unmounting..."
            } else {
                "Unmount"
            };
            if ui
                .add_enabled(!pending_unmount, primary_button(label))
                .clicked()
            {
                self.request_unmount();
            }
            ui.add_space(8.0);
            if ui.button("Open mountpoint").clicked() {
                open_in_file_manager(&mp);
            }
        });

        if pending_unmount {
            ui.add_space(14.0);
            #[cfg(target_os = "windows")]
            let msg = "Signaled WinFsp to stop the dispatcher; the mount \
                       thread will exit once all open file handles in \
                       your file manager are closed.";
            #[cfg(not(target_os = "windows"))]
            let msg = "Sent fusermount3 -u; the mount thread will exit \
                       once all open file handles in your file manager \
                       are closed.";
            ui.label(RichText::new(msg).color(theme::FAINT).size(12.0));
        }
    }

    fn request_unmount(&mut self) {
        let Some(ms) = self.mount_status.as_mut() else {
            return;
        };
        if ms.unmount_requested {
            return;
        }
        ms.unmount_requested = true;
        let mp = ms.mountpoint.clone();
        std::thread::spawn(move || {
            let _ = luksbox_mount::unmount(&mp);
        });
    }

    /// Polled from the main update loop. If the mount thread has
    /// finished (clean unmount or crash), drop back to Welcome since
    /// the Vfs has been consumed and there's nothing to browse.
    fn poll_mount(&mut self) {
        let Some(ms) = self.mount_status.as_ref() else {
            return;
        };
        match ms.rx.try_recv() {
            Ok(Ok(())) => {
                self.mount_status = None;
                self.view = View::Welcome;
                self.cwd = "/".into();
                self.listing.clear();
                self.toast_ok("vault unmounted");
            }
            Ok(Err(e)) => {
                self.mount_status = None;
                self.view = View::Welcome;
                self.toast_err(format!("mount error: {e}"));
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
            Err(_) => {
                self.mount_status = None;
                self.view = View::Welcome;
                self.toast_err("mount thread terminated unexpectedly");
            }
        }
    }
}

// ---- keyslots -------------------------------------------------------------

impl LuksboxApp {
    fn draw_keyslots(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui
                .button(RichText::new("< Back").color(theme::DIM))
                .clicked()
            {
                self.view = View::Browser;
            }
        });
        ui.add_space(6.0);
        ui.label(RichText::new("Keyslots").size(22.0).strong());
        ui.add_space(20.0);

        let header = self
            .vault
            .as_ref()
            .map(|v| v.vfs.container().header.clone());
        let Some(header) = header else {
            ui.label("no vault open");
            return;
        };
        // Used by the revoke-confirm flow below: if the slot the user
        // is revoking is the ONLY active credential left, the modal
        // upgrades from "are you sure?" to "you will be locked out".
        let active_slot_count = header
            .keyslots
            .iter()
            .filter(|s| !matches!(s.kind, SlotKind::Empty))
            .count();

        // Vault-wide info banner, clarifies why per-slot cipher choice
        // doesn't exist (it's set at create time and applies to every
        // slot, since the same MVK is wrapped under each keyslot).
        let cipher_label = match header.cipher_suite {
            luksbox_core::CipherSuite::Aes256Gcm => "AES-256-GCM",
            luksbox_core::CipherSuite::Aes256GcmSiv => "AES-256-GCM-SIV",
            luksbox_core::CipherSuite::ChaCha20Poly1305 => "ChaCha20-Poly1305",
        };
        ui.label(
            RichText::new(format!(
                "Vault cipher: {cipher_label} (set at create, same for every slot). \
                 Per-slot you can pick the KDF strength (passphrase) or hybrid PQ \
                 parameter set (at create time). Hybrid-PQ slots can't be added \
                 post-create, recreate the vault."
            ))
            .color(theme::FAINT)
            .size(12.0),
        );
        ui.add_space(14.0);

        // Wrap the slot list + add buttons in a ScrollArea so a short
        // window can still reach the bottom Add buttons.
        ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                for (i, slot) in header.keyslots.iter().enumerate() {
                    Frame::new()
                        .fill(theme::PANEL)
                        .stroke(Stroke::new(1.0, theme::BORDER))
                        .corner_radius(CornerRadius::same(8))
                        .inner_margin(14)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(format!("Slot {i}"))
                                        .strong()
                                        .color(theme::TEXT),
                                );
                                let kind_label = match slot.kind {
                                    SlotKind::Empty => "empty",
                                    SlotKind::Passphrase => "passphrase",
                                    SlotKind::Fido2HmacSecret => "fido2 (wrap)",
                                    SlotKind::Fido2DerivedMvk => "fido2-direct",
                                    SlotKind::HybridPqKemPassphrase => "hybrid-pq (768)",
                                    SlotKind::HybridPqKemFido2 => "hybrid-pq-fido2 (768)",
                                    SlotKind::HybridPqKem1024Passphrase => "hybrid-pq (1024)",
                                    SlotKind::HybridPqKem1024Fido2 => "hybrid-pq-fido2 (1024)",
                                    SlotKind::Tpm2Sealed => "tpm2 (this machine)",
                                    SlotKind::Tpm2Fido2 => "tpm2 + fido2 (both)",
                                    SlotKind::Tpm2SealedPin => "tpm2 + PIN",
                                    SlotKind::HybridPqKemTpm2 => "tpm2 + ML-KEM-768",
                                    SlotKind::HybridPqKemTpm2Fido2 => {
                                        "tpm2 + fido2 + ML-KEM-768"
                                    }
                                    SlotKind::HybridPqKem1024Tpm2 => "tpm2 + ML-KEM-1024",
                                    SlotKind::HybridPqKem1024Tpm2Fido2 => {
                                        "tpm2 + fido2 + ML-KEM-1024"
                                    }
                                };
                                let kc = match slot.kind {
                                    SlotKind::Empty => theme::FAINT,
                                    SlotKind::Passphrase => theme::DIM,
                                    SlotKind::Fido2HmacSecret | SlotKind::Fido2DerivedMvk => {
                                        theme::ACCENT
                                    }
                                    SlotKind::HybridPqKemPassphrase
                                    | SlotKind::HybridPqKemFido2
                                    | SlotKind::HybridPqKem1024Passphrase
                                    | SlotKind::HybridPqKem1024Fido2 => theme::WARN,
                                    // TPM-bound slots use the
                                    // accent colour - similar trust
                                    // tier to FIDO2 (hardware-bound
                                    // credential). Hybrid-PQ-TPM
                                    // variants use WARN since they
                                    // share the "needs sidecar +
                                    // exotic" property of the
                                    // existing hybrid-PQ kinds.
                                    SlotKind::Tpm2Sealed
                                    | SlotKind::Tpm2Fido2
                                    | SlotKind::Tpm2SealedPin => theme::ACCENT,
                                    SlotKind::HybridPqKemTpm2
                                    | SlotKind::HybridPqKemTpm2Fido2
                                    | SlotKind::HybridPqKem1024Tpm2
                                    | SlotKind::HybridPqKem1024Tpm2Fido2 => theme::WARN,
                                };
                                theme::pill(ui, RichText::new(kind_label).small().color(kc), kc);
                                if !matches!(slot.kind, SlotKind::Empty) {
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        // Revoke is destructive (the
                                        // wrapped MVK for this credential
                                        // is gone forever after this).
                                        // Stash a confirmation request;
                                        // the actual revoke fires from
                                        // the modal handler.
                                        if ui.add(ghost_button("Revoke")).clicked() {
                                            self.revoke_confirm = Some(RevokeConfirm {
                                                slot_idx: i,
                                                slot_kind: slot.kind,
                                                would_be_last_active_slot: active_slot_count
                                                    <= 1,
                                            });
                                        }
                                    });
                                }
                            });
                            if matches!(slot.kind, SlotKind::Passphrase) {
                                ui.label(
                                    RichText::new(format!(
                                        "Argon2id m={} KiB t={} p={}",
                                        slot.kdf_params.m_cost_kib,
                                        slot.kdf_params.t_cost,
                                        slot.kdf_params.p_cost
                                    ))
                                    .small()
                                    .color(theme::FAINT),
                                );
                            }
                            if matches!(
                                slot.kind,
                                SlotKind::Fido2HmacSecret | SlotKind::Fido2DerivedMvk
                            ) {
                                let prefix: String = slot
                                    .fido2_cred_id
                                    .iter()
                                    .take(8)
                                    .map(|b| format!("{b:02x}"))
                                    .collect();
                                ui.label(
                                    RichText::new(format!(
                                        "cred_id {prefix}...  ({} B)",
                                        slot.fido2_cred_id.len()
                                    ))
                                    .small()
                                    .color(theme::FAINT),
                                );
                            }
                        });
                    ui.add_space(8.0);
                }

                ui.add_space(12.0);
                ui.label(
                    RichText::new("ADD KEYSLOT")
                        .small()
                        .color(theme::FAINT)
                        .strong(),
                );
                ui.add_space(6.0);

                // Full-width row buttons. Previously these were in a
                // ui.horizontal(...) and a layout quirk made the hit-rect for
                // long button labels collapse to just the leading "+", so
                // clicks landed only on the first character. Allocating a
                // fixed-size rect per button via add_sized gives a proper
                // click region matching the visible label.
                let row_w = form_width(ui);
                if ui
                    .add_sized([row_w, 32.0], ghost_button("+ Add passphrase keyslot"))
                    .clicked()
                {
                    self.add_passphrase_modal = Some(AddPassphraseForm::default());
                }
                if ui
                    .add_sized(
                        [row_w, 32.0],
                        ghost_button("+ Add FIDO2 keyslot (wrap mode)"),
                    )
                    .on_hover_text(
                        "Adds a FIDO2 wrap-mode keyslot (any CTAP2 authenticator) that wraps the existing \
                 vault MVK. PIN + touch on every unlock.",
                    )
                    .clicked()
                {
                    if let Err(e) = ops::pre_check_fido2() {
                        self.toast_err(e);
                    } else {
                        self.add_fido2_pin_modal = Some(Zeroizing::default());
                    }
                }
                // TPM-bound "Add keyslot" buttons only on Linux. Each
                // button pre-flights its hardware before opening the
                // modal so the user gets the friendly missing-device
                // toast BEFORE typing PIN / passphrase.
                #[cfg(target_os = "linux")]
                if ui
                    .add_sized(
                        [row_w, 32.0],
                        ghost_button("+ Add TPM 2.0 keyslot (this machine)"),
                    )
                    .on_hover_text(
                        "Adds a TPM 2.0-bound keyslot. The wrap key lives inside the local \
                 TPM chip; no passphrase needed. Linux only. The vault becomes uncrackable \
                 if its file is stolen separately from this machine, but only unlocks on \
                 this machine.",
                    )
                    .clicked()
                {
                    if let Err(e) = ops::pre_check_tpm() {
                        self.toast_err(e);
                    } else if let Some(v) = self.vault.take() {
                        let (tx, rx) = std::sync::mpsc::channel::<VaultRet<usize>>();
                        std::thread::spawn(move || {
                            let mut v = v;
                            let r = ops::enroll_tpm2(&mut v.vfs);
                            let _ = tx.send((v, r));
                        });
                        self.pending = Some(Pending::EnrollTpm2 { rx });
                    }
                }
                #[cfg(target_os = "linux")]
                if ui
                    .add_sized(
                        [row_w, 32.0],
                        ghost_button("+ Add TPM 2.0 + PIN keyslot"),
                    )
                    .on_hover_text(
                        "Adds a TPM 2.0 keyslot bound to a memorised PIN. The chip refuses \
                 to unseal without the matching PIN; wrong PINs count toward its dictionary-\
                 attack lockout. Even short PINs (4-6 digits) are secure on the original \
                 hardware. Loses if the chip dies or the PIN is forgotten; keep a backup \
                 keyslot.",
                    )
                    .clicked()
                {
                    if let Err(e) = ops::pre_check_tpm() {
                        self.toast_err(e);
                    } else {
                        self.add_tpm2_pin_modal = Some(AddTpm2PinForm::default());
                    }
                }
                #[cfg(target_os = "linux")]
                if ui
                    .add_sized(
                        [row_w, 32.0],
                        ghost_button("+ Add fused TPM 2.0 + FIDO2 keyslot (both required)"),
                    )
                    .on_hover_text(
                        "Adds a fused keyslot requiring BOTH the local TPM chip AND a touch \
                 on a FIDO2 authenticator at every unlock. Strongest single-slot mode but \
                 loses both factors permanently kills this slot; keep a Passphrase or \
                 FIDO2-only slot as recovery.",
                    )
                    .clicked()
                {
                    if let Err(e) = ops::pre_check_tpm() {
                        self.toast_err(e);
                    } else if let Err(e) = ops::pre_check_fido2() {
                        self.toast_err(e);
                    } else {
                        self.add_tpm2_fido2_pin_modal = Some(Zeroizing::default());
                    }
                }
                #[cfg(target_os = "linux")]
                if ui
                    .add_sized(
                        [row_w, 32.0],
                        ghost_button("+ Add hybrid TPM 2.0 + ML-KEM-768 keyslot"),
                    )
                    .on_hover_text(
                        "2-factor: local TPM chip AND a separate .kyber seed file (kept on \
                 different storage from the .lbx). Closes the quantum-attack gap of plain \
                 TPM. Generates a fresh Kyber-768 keypair and writes the seed to a new \
                 passphrase-encrypted file you choose.",
                    )
                    .clicked()
                {
                    if let Err(e) = ops::pre_check_tpm() {
                        self.toast_err(e);
                    } else {
                        self.add_hybrid_tpm2_modal = Some(AddHybridTpm2Form::new(768));
                    }
                }
                #[cfg(target_os = "linux")]
                if ui
                    .add_sized(
                        [row_w, 32.0],
                        ghost_button("+ Add hybrid TPM 2.0 + ML-KEM-1024 keyslot"),
                    )
                    .on_hover_text(
                        "Same 2-factor shape as the ML-KEM-768 variant but uses ML-KEM-1024 \
                 (NIST Cat-5, AES-256-equivalent PQ strength). Larger keys and ciphertexts; \
                 same unlock cost.",
                    )
                    .clicked()
                {
                    if let Err(e) = ops::pre_check_tpm() {
                        self.toast_err(e);
                    } else {
                        self.add_hybrid_tpm2_modal = Some(AddHybridTpm2Form::new(1024));
                    }
                }
                #[cfg(target_os = "linux")]
                if ui
                    .add_sized(
                        [row_w, 32.0],
                        ghost_button("+ Add 3-factor TPM 2.0 + FIDO2 + ML-KEM-768 keyslot"),
                    )
                    .on_hover_text(
                        "All three required at every unlock: local TPM AND a FIDO2 \
                 authenticator AND the .kyber seed file. Loss of any one factor permanently \
                 kills this slot; keep a recovery keyslot.",
                    )
                    .clicked()
                {
                    if let Err(e) = ops::pre_check_tpm() {
                        self.toast_err(e);
                    } else if let Err(e) = ops::pre_check_fido2() {
                        self.toast_err(e);
                    } else {
                        self.add_hybrid_tpm2_fido2_modal = Some(AddHybridTpm2Fido2Form::new(768));
                    }
                }
                #[cfg(target_os = "linux")]
                if ui
                    .add_sized(
                        [row_w, 32.0],
                        ghost_button("+ Add 3-factor TPM 2.0 + FIDO2 + ML-KEM-1024 keyslot"),
                    )
                    .on_hover_text(
                        "Same 3-factor shape as the ML-KEM-768 variant but uses ML-KEM-1024 \
                 (NIST Cat-5, AES-256-equivalent PQ strength).",
                    )
                    .clicked()
                {
                    if let Err(e) = ops::pre_check_tpm() {
                        self.toast_err(e);
                    } else if let Err(e) = ops::pre_check_fido2() {
                        self.toast_err(e);
                    } else {
                        self.add_hybrid_tpm2_fido2_modal = Some(AddHybridTpm2Fido2Form::new(1024));
                    }
                }

                // FIDO2-direct can't be added post-create: in that mode the
                // MVK *is* HKDF(yubikey-output), so wrapping the existing MVK
                // under a different YubiKey would require that YubiKey to
                // reproduce the exact MVK, which it can't.
                let _ = ui.add_enabled_ui(false, |ui| {
                    ui.add_sized(
                        [row_w, 32.0],
                        ghost_button("+ Add FIDO2-direct keyslot  (unavailable)"),
                    )
                    .on_hover_text(
                        "FIDO2-direct keyslots can only be created at vault creation time. \
                 The MVK in this mode is derived from the authenticator, so it can't be \
                 retrofitted to an existing vault.",
                    );
                });

                // ---- Rotate master key ---------------------------------------
                ui.add_space(20.0);
                ui.label(RichText::new("ROTATE").small().color(theme::FAINT).strong());
                ui.add_space(6.0);

                // Pre-flight: figure out which kinds are present so we can
                // give the user a meaningful action.
                let has_passphrase = header
                    .keyslots
                    .iter()
                    .any(|s| s.kind == SlotKind::Passphrase);
                let has_fido2_wrap = header
                    .keyslots
                    .iter()
                    .any(|s| s.kind == SlotKind::Fido2HmacSecret);
                let has_fido2_direct = header
                    .keyslots
                    .iter()
                    .any(|s| s.kind == SlotKind::Fido2DerivedMvk);
                let has_hybrid = header.keyslots.iter().any(|s| {
                    matches!(
                        s.kind,
                        SlotKind::HybridPqKemPassphrase
                            | SlotKind::HybridPqKemFido2
                            | SlotKind::HybridPqKem1024Passphrase
                            | SlotKind::HybridPqKem1024Fido2,
                    )
                });

                let can_rotate_in_gui =
                    has_passphrase && !has_fido2_wrap && !has_fido2_direct && !has_hybrid;

                if can_rotate_in_gui {
                    if ui
                        .add_sized([row_w, 32.0], ghost_button("Rotate master key..."))
                        .on_hover_text(
                            "Re-encrypts every chunk in the vault under a freshly-generated \
                     master key, then re-wraps each keyslot with a fresh random salt \
                     under the same passphrase. Crash-safe in inline-header mode \
                     (writes go to a .rotating temp file that's atomically renamed \
                     at commit). O(N) time + disk I/O.",
                        )
                        .clicked()
                    {
                        // Pre-populate the form with one passphrase entry
                        // per populated Passphrase slot.
                        let mut entries: Vec<RotateSlotInput> = Vec::new();
                        for (i, slot) in header.keyslots.iter().enumerate() {
                            if slot.kind == SlotKind::Passphrase {
                                entries.push(RotateSlotInput {
                                    slot_idx: i,
                                    passphrase: Zeroizing::default(),
                                });
                            }
                        }
                        self.rotate_modal = Some(RotateForm {
                            entries,
                            kdf: KdfStrength::Interactive,
                        });
                    }
                } else {
                    // Rotation isn't available in the GUI for this vault's
                    // slot mix. Show why and point at the CLI.
                    let _ = ui.add_enabled_ui(false, |ui| {
                        ui.add_sized([row_w, 32.0], ghost_button("Rotate master key  (use CLI)"));
                    });
                    let reason = if has_fido2_direct {
                        "FIDO2-direct slots can't be rotated, the master key IS the authenticator \
                 output, not wrapped. Revoke the slot and recreate the vault to \
                 change keys."
                    } else if has_hybrid {
                        "Hybrid-PQ rotation isn't supported yet (would need to re-encapsulate \
                 against the existing Kyber keypair). Recreate the vault if you need \
                 to rotate."
                    } else if has_fido2_wrap {
                        "FIDO2 (wrap-mode) rotation needs two authenticator touches per slot, wired \
                 up in the CLI: `luksbox rotate-mvk <path>` (or `luksbox wizard` -> \
                 Rotate). The GUI's rotation flow currently handles passphrase-only \
                 vaults."
                    } else {
                        "No populated keyslots, nothing to rotate."
                    };
                    ui.label(RichText::new(reason).color(theme::DIM).size(12.0));
                }

                add_scroll_edge_padding(ui);
            }); // close ScrollArea
    }

    /// Modal for rotate-master-key. Shown when `self.rotate_modal` is
    /// `Some`. Lists every populated Passphrase slot, asks for the
    /// passphrase, picks a KDF strength, then spawns the rotation
    /// worker on submit. Closes itself on success or via Cancel.
    fn draw_rotate_modal(&mut self, ctx: &egui::Context) {
        let Some(form) = self.rotate_modal.as_mut() else {
            return;
        };
        let mut closed = false;
        let mut submit = false;

        let modal = egui::Modal::new(egui::Id::new("rotate-mvk-modal"))
            .frame(
                Frame::default()
                    .fill(theme::PANEL)
                    .stroke(Stroke::new(1.0, theme::BORDER))
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(20),
            )
            .show(ctx, |ui| {
                ui.set_min_width(capped_width(ui, 460.0));
                ui.label(RichText::new("Rotate master key").size(16.0).strong());
                ui.add_space(8.0);
                ui.label(
                    RichText::new(
                        "Re-encrypts every chunk and re-wraps every keyslot under a \
                         freshly-generated master key. The vault's content is \
                         unchanged; the keys protecting it are replaced. Useful if \
                         you suspect the wrapped MVK was copied (e.g. from an old \
                         backup that was exposed).",
                    )
                    .color(theme::DIM)
                    .size(12.0),
                );
                ui.add_space(8.0);
                ui.label(
                    RichText::new(
                        "Crash-safe in inline-header mode: in-progress bytes go to a \
                         <vault>.rotating temp file that is fsync'd and atomically \
                         renamed at commit. A crash before commit leaves the original \
                         intact.",
                    )
                    .color(theme::FAINT)
                    .size(12.0),
                );
                ui.add_space(14.0);

                ui.label(
                    RichText::new(
                        "Enter the passphrase for every populated keyslot. Each \
                         slot is re-authenticated and rebuilt under fresh \
                         randomness.",
                    )
                    .color(theme::DIM)
                    .size(12.0),
                );
                ui.add_space(8.0);

                for entry in form.entries.iter_mut() {
                    ui.label(
                        RichText::new(format!("Slot {}, passphrase", entry.slot_idx))
                            .color(theme::DIM)
                            .size(12.0),
                    );
                    let te = egui::TextEdit::singleline(&mut *entry.passphrase).password(true);
                    ui.add_sized([capped_width(ui, 420.0), CONTROL_H], te);
                    ui.add_space(6.0);
                }

                ui.add_space(8.0);
                ui.label(
                    RichText::new("KDF strength for the new wraps (Argon2id)")
                        .color(theme::DIM)
                        .size(12.0),
                );
                egui::ComboBox::from_id_salt("rotate-kdf")
                    .width(capped_width(ui, 420.0))
                    .selected_text(form.kdf.label())
                    .show_ui(ui, |ui| {
                        for kdf in [
                            KdfStrength::Interactive,
                            KdfStrength::Moderate,
                            KdfStrength::Sensitive,
                        ] {
                            ui.selectable_value(&mut form.kdf, kdf, kdf.label());
                        }
                    });

                ui.add_space(14.0);
                ui.separator();
                ui.add_space(10.0);

                let can_submit =
                    form.entries.iter().all(|e| !e.passphrase.is_empty()) && self.pending.is_none();

                if ui
                    .add_sized(
                        [capped_width(ui, 420.0), 30.0],
                        primary_button("Rotate master key"),
                    )
                    .on_hover_text(if can_submit {
                        "Spawns a background worker; the rotation runs O(N) over the \
                         vault's chunks."
                    } else if self.pending.is_some() {
                        "Another operation is in flight, wait for it to finish."
                    } else {
                        "Fill in every slot's passphrase first."
                    })
                    .clicked()
                    && can_submit
                {
                    submit = true;
                }
                ui.add_space(4.0);
                if ui
                    .add_sized(
                        [capped_width(ui, 420.0), CONTROL_H],
                        egui::Button::new("Cancel"),
                    )
                    .clicked()
                {
                    closed = true;
                }
            });

        if modal.backdrop_response.clicked() {
            closed = true;
        }
        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            closed = true;
        }

        if submit {
            // Move the credentials out of the form before spawning so
            // the worker owns its own zeroizing copies.
            let kdf;
            let creds: Vec<(usize, zeroize::Zeroizing<String>)>;
            {
                let f = self.rotate_modal.as_mut().expect("checked above");
                kdf = f.kdf;
                creds = f
                    .entries
                    .iter_mut()
                    .map(|e| (e.slot_idx, std::mem::take(&mut e.passphrase)))
                    .collect();
            }
            self.rotate_modal = None;

            // Take the open vault out so we can move it into the
            // worker; it'll be re-installed on success or restored
            // (un-rotated) on failure.
            let Some(opened) = self.vault.take() else {
                return;
            };
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let mut opened = opened;
                let r =
                    ops::rotate_mvk_passphrase_only(&mut opened.vfs, creds, kdf).map(|_| opened);
                let _ = tx.send(r);
            });
            self.pending = Some(Pending::RotateMvk(rx));
        }

        if closed {
            self.rotate_modal = None;
        }
    }

    /// "You have <vault> open, lock it and continue?" prompt.
    /// Renders only when `confirm_lock` is Some, which only happens
    /// "Are you sure?" modal that fires when a create / add-passphrase
    /// form is submitted with an empty passphrase. Empty is technically
    /// valid (Argon2id hashes the empty string fine) but means ANYONE
    /// with the .lbx file can open the vault, so almost always a
    /// mistake.
    ///
    /// Yes button leaves `empty_passphrase_confirm` set to its current
    /// value (acting as a one-shot bypass flag) and re-fires the
    /// matching submit; the submit clears the flag immediately so the
    /// next submit re-checks. Cancel just clears the flag, leaves the
    /// form open for the user to type a real passphrase.
    fn draw_empty_passphrase_confirm_modal(&mut self, ctx: &egui::Context) {
        let target = match self.empty_passphrase_confirm {
            Some(t) => t,
            None => return,
        };
        let (title, body, button_label) = match target {
            EmptyPassphraseTarget::CreateVault | EmptyPassphraseTarget::AddPassphraseKeyslot => (
                "Empty passphrase, are you sure?",
                "The passphrase field is empty. ANYONE who gets a copy of this vault \
                 file will be able to open it without any secret. Are you sure you want \
                 to continue?",
                "Yes, use empty passphrase",
            ),
            EmptyPassphraseTarget::Fido2DirectBackup => (
                "No backup passphrase, are you sure?",
                "FIDO2-direct vaults derive the master key from the authenticator's \
                 output; there's no wrapped MVK on disk to brute-force. Without a backup \
                 passphrase, LOSING THE AUTHENTICATOR loses the vault permanently with \
                 no recovery. Are you sure you want to skip the backup?",
                "Yes, skip backup passphrase",
            ),
        };
        let mut proceed = false;
        let mut cancel = false;
        egui::Window::new(title)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label(RichText::new(body).color(theme::WARN).size(13.0));
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.add(ghost_button("Cancel")).clicked() {
                        cancel = true;
                    }
                    if ui.add(primary_button(button_label)).clicked() {
                        proceed = true;
                    }
                });
            });
        if cancel {
            self.empty_passphrase_confirm = None;
        } else if proceed {
            // Re-fire the matching submit. The submit's empty-check
            // sees `empty_passphrase_confirm.is_some()`, skips the
            // guard, then clears the flag.
            match target {
                EmptyPassphraseTarget::CreateVault | EmptyPassphraseTarget::Fido2DirectBackup => {
                    self.submit_create()
                }
                EmptyPassphraseTarget::AddPassphraseKeyslot => {
                    // Bypass the modal-poll path: we already know the
                    // user hit Yes, so dispatch the enroll directly.
                    self.empty_passphrase_confirm = None;
                    if let Some(form) = self.add_passphrase_modal.take()
                        && let Some(v) = self.vault.take()
                    {
                        let (tx, rx) = std::sync::mpsc::channel::<VaultRet<usize>>();
                        std::thread::spawn(move || {
                            let mut v = v;
                            let r = ops::enroll_passphrase(&mut v.vfs, &form.passphrase, form.kdf);
                            let _ = tx.send((v, r));
                        });
                        self.pending = Some(Pending::EnrollPassphrase { rx });
                    }
                }
            }
        }
    }

    /// "Lock and continue" runs the deferred action via
    /// `execute_navigate` (which calls `lock_and_drop_vault` first);
    /// "Cancel" drops the action so the user stays on the current
    /// view with their vault still open. Triggered from
    /// `request_navigate` while a vault is open.
    fn draw_confirm_lock_modal(&mut self, ctx: &egui::Context) {
        if self.confirm_lock.is_none() {
            return;
        }

        let open_path = self
            .vault
            .as_ref()
            .map(|v| v.vault_path.display().to_string())
            .unwrap_or_default();
        let next_label = match self.confirm_lock.as_ref().expect("checked above") {
            NavigateAction::OpenRecent(r) => format!("open {}", r.path.display()),
            NavigateAction::OpenPicker => "open another vault".into(),
            NavigateAction::GoCreate => "create a new vault".into(),
            NavigateAction::GoPanic => "go to the PANIC screen".into(),
            NavigateAction::GoWelcome => "return to the welcome screen".into(),
        };

        let mut decision: Option<bool> = None; // Some(true)=lock+go, Some(false)=cancel

        let modal = egui::Modal::new(egui::Id::new("confirm-lock-modal"))
            .frame(
                Frame::default()
                    .fill(theme::PANEL)
                    .stroke(Stroke::new(1.0, theme::BORDER))
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(20),
            )
            .show(ctx, |ui| {
                ui.set_min_width(capped_width(ui, 460.0));
                ui.label(
                    RichText::new("Lock current vault first?")
                        .size(16.0)
                        .strong(),
                );
                ui.add_space(8.0);
                ui.label(
                    RichText::new(format!(
                        "{open_path} is still open. To {next_label} we need to lock it \
                         first, which flushes any pending writes and drops the file \
                         handle so the vault can be reopened cleanly."
                    ))
                    .color(theme::DIM)
                    .size(12.0),
                );
                ui.add_space(14.0);
                ui.separator();
                ui.add_space(10.0);

                if ui
                    .add_sized(
                        [capped_width(ui, 420.0), 30.0],
                        primary_button("Lock and continue"),
                    )
                    .clicked()
                {
                    decision = Some(true);
                }
                ui.add_space(4.0);
                if ui
                    .add_sized(
                        [capped_width(ui, 420.0), CONTROL_H],
                        egui::Button::new("Cancel"),
                    )
                    .clicked()
                {
                    decision = Some(false);
                }
            });

        if modal.backdrop_response.clicked() || ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            decision = Some(false);
        }

        match decision {
            Some(true) => {
                let action = self.confirm_lock.take().expect("checked above");
                self.execute_navigate(action);
            }
            Some(false) => {
                self.confirm_lock = None;
            }
            None => {}
        }
    }
}

// ---- panic ---------------------------------------------------------------

impl LuksboxApp {
    fn draw_panic(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui
                .button(RichText::new("< Back").color(theme::DIM))
                .clicked()
            {
                self.view = View::Welcome;
            }
        });
        ui.add_space(6.0);
        ui.label(
            RichText::new("PANIC: irreversibly destroy a vault")
                .size(22.0)
                .strong()
                .color(theme::DANGER),
        );
        ui.add_space(8.0);
        ui.label(
            RichText::new(
                "Overwrites the 8 KB header (or the detached sidecar) with random bytes. \
                 Without the header, and without a backup of it, the vault is \
                 mathematically unrecoverable. Optionally also overwrites the entire \
                 vault data area. There is NO undo.",
            )
            .color(theme::DIM)
            .size(13.0),
        );
        ui.add_space(16.0);

        section(ui, "Target", |ui| {
            ui.label(RichText::new("Vault path").color(theme::DIM).size(12.0));
            ui.horizontal(|ui| {
                let (field_w, browse_w) = trailing_button_row_widths(ui, FORM_FIELD_MAX_W, 90.0);
                ui.add_sized(
                    [field_w, CONTROL_H],
                    egui::TextEdit::singleline(&mut self.panic.vault)
                        .hint_text(path_hints::home("vault.lbx")),
                );
                if ui
                    .add_sized([browse_w, CONTROL_H], ghost_button("Browse..."))
                    .clicked()
                    && let Some(p) = rfd::FileDialog::new()
                        .set_title("Vault to destroy")
                        .pick_file()
                {
                    self.panic.vault = p.display().to_string();
                }
            });
            ui.add_space(6.0);
            ui.checkbox(
                &mut self.panic.use_detached,
                "This vault uses a detached header sidecar",
            );
            if self.panic.use_detached {
                ui.horizontal(|ui| {
                    let (field_w, browse_w) =
                        trailing_button_row_widths(ui, FORM_FIELD_MAX_W, 90.0);
                    ui.add_sized(
                        [field_w, CONTROL_H],
                        egui::TextEdit::singleline(&mut self.panic.header_path)
                            .hint_text(path_hints::usb("vault.hdr")),
                    );
                    if ui
                        .add_sized([browse_w, CONTROL_H], ghost_button("Browse..."))
                        .clicked()
                        && let Some(p) = rfd::FileDialog::new()
                            .set_title("Header sidecar to destroy")
                            .pick_file()
                    {
                        self.panic.header_path = p.display().to_string();
                    }
                });
            }
            ui.add_space(6.0);
            ui.checkbox(
                &mut self.panic.wipe_data,
                "ALSO overwrite the entire vault data area with random (slow on large vaults)",
            );
        });

        let expected = format!("DESTROY {}", self.panic.vault.trim());
        section(ui, "Confirm", |ui| {
            ui.label(
                RichText::new(format!("Type literally `{expected}` to confirm:"))
                    .color(theme::DIM)
                    .size(12.0),
            );
            ui.add_sized(
                [form_width(ui), CONTROL_H],
                egui::TextEdit::singleline(&mut self.panic.confirmation),
            );
        });

        ui.add_space(14.0);
        let armed = self.panic.confirmation == expected && !self.panic.vault.trim().is_empty();
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let btn = egui::Button::new(RichText::new("Destroy").color(Color32::WHITE))
                .fill(if armed { theme::DANGER } else { theme::FAINT });
            if ui
                .add_enabled(armed && self.pending.is_none(), btn)
                .clicked()
            {
                let vault = PathBuf::from(self.panic.vault.trim());
                let header = if self.panic.use_detached && !self.panic.header_path.trim().is_empty()
                {
                    Some(PathBuf::from(self.panic.header_path.trim()))
                } else {
                    None
                };
                let wipe = self.panic.wipe_data;
                let path_for_recent = vault.clone();
                self.pending = Some(Pending::Panic(ops::spawn(move || {
                    let r = ops::panic_destroy(&vault, header.as_deref(), wipe);
                    if r.is_ok() {
                        recent::forget(&path_for_recent);
                    }
                    r
                })));
            }
        });
    }
}

// ---- pending overlay + modals + toasts -----------------------------------

impl LuksboxApp {
    fn draw_pending_overlay(&self, ctx: &egui::Context) {
        let Some(p) = &self.pending else { return };
        // Fido2Probe is a silent background poke at libfido2 to
        // refresh the sidebar device picker, never block the UI for
        // it. (Was previously eating clicks because egui::Area is
        // interactable by default.)
        if matches!(p, Pending::Fido2Probe(_)) {
            return;
        }
        let needs_touch = p.needs_touch();
        let label = p.label();
        // Drive a continuous repaint while the overlay is up so the
        // pulse animation and pending channels both stay live.
        ctx.request_repaint_after(Duration::from_millis(40));

        egui::Area::new(egui::Id::new("pending-overlay"))
            .fixed_pos(egui::pos2(0.0, 0.0))
            .order(egui::Order::Foreground)
            .interactable(true) // we DO want this overlay to block input
            .show(ctx, |ui| {
                let rect = ctx.content_rect();
                ui.painter()
                    .rect_filled(rect, 0.0, Color32::from_black_alpha(190));
                let center = rect.center();
                let panel_size = Vec2::new(420.0, if needs_touch { 180.0 } else { 130.0 });
                let panel_rect = egui::Rect::from_center_size(center, panel_size);
                ui.painter()
                    .rect_filled(panel_rect, CornerRadius::same(12), theme::PANEL);
                ui.painter().rect_stroke(
                    panel_rect,
                    CornerRadius::same(12),
                    Stroke::new(
                        1.0,
                        if needs_touch {
                            theme::ACCENT
                        } else {
                            theme::BORDER
                        },
                    ),
                    egui::StrokeKind::Inside,
                );
                ui.scope_builder(
                    egui::UiBuilder::new().max_rect(panel_rect.shrink(20.0)),
                    |ui| {
                        ui.vertical_centered(|ui| {
                            if needs_touch {
                                let t = ui.input(|i| i.time);
                                let pulse = 0.5 + 0.5 * (t * 3.5).sin() as f32; // 0..1
                                let dot_color = theme::ACCENT.linear_multiply(0.4 + 0.6 * pulse);
                                let radius = 18.0 + 6.0 * pulse;
                                let (dot_rect, _) = ui.allocate_exact_size(
                                    Vec2::new(60.0, 60.0),
                                    egui::Sense::hover(),
                                );
                                ui.painter()
                                    .circle_filled(dot_rect.center(), radius, dot_color);
                                // Inner solid disc for contrast.
                                ui.painter()
                                    .circle_filled(dot_rect.center(), 10.0, theme::ACCENT);
                                ui.add_space(8.0);
                                ui.label(
                                    RichText::new("TOUCH YOUR YUBIKEY")
                                        .strong()
                                        .color(theme::ACCENT)
                                        .size(15.0),
                                );
                                ui.add_space(4.0);
                                ui.label(RichText::new(label).color(theme::DIM).size(12.0));
                            } else {
                                ui.add(egui::Spinner::new().color(theme::ACCENT).size(28.0));
                                ui.add_space(8.0);
                                ui.label(RichText::new(label).color(theme::TEXT).size(13.0));
                            }
                        });
                    },
                );
            });
    }

    fn draw_modals(&mut self, ctx: &egui::Context) {
        self.draw_passgen_dialog(ctx);
        self.draw_clipboard_warning_modal(ctx);
        self.draw_revoke_confirm_modal(ctx);
        self.draw_rotate_modal(ctx);
        self.draw_confirm_lock_modal(ctx);
        self.draw_empty_passphrase_confirm_modal(ctx);

        // Add-passphrase modal
        let mut close_pp = false;
        let mut submit_pp = false;
        let mut open_passgen_for_keyslot = false;
        if let Some(form) = self.add_passphrase_modal.as_mut() {
            egui::Window::new("Add passphrase keyslot")
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(RichText::new("New passphrase").color(theme::DIM).size(12.0));
                    ui.horizontal(|ui| {
                        let (field_w, button_w) = trailing_button_row_widths(ui, 320.0, 110.0);
                        let te = egui::TextEdit::singleline(&mut *form.passphrase).password(true);
                        ui.add_sized([field_w, CONTROL_H], te);
                        // Explicit hit-rect via add_sized, same egui
                        // quirk that bit the +Add and Cancel buttons.
                        if ui
                            .add_sized([button_w, CONTROL_H], ghost_button("Generate..."))
                            .clicked()
                        {
                            open_passgen_for_keyslot = true;
                        }
                    });
                    strength_meter(ui, &form.passphrase);
                    ui.add_space(10.0);

                    ui.label(
                        RichText::new("KDF strength (Argon2id)")
                            .color(theme::DIM)
                            .size(12.0),
                    );
                    egui::ComboBox::from_id_salt("add-pp-kdf")
                        .width(capped_width(ui, 380.0))
                        .selected_text(form.kdf.label())
                        .show_ui(ui, |ui| {
                            for kdf in [
                                KdfStrength::Interactive,
                                KdfStrength::Moderate,
                                KdfStrength::Sensitive,
                            ] {
                                ui.selectable_value(&mut form.kdf, kdf, kdf.label());
                            }
                        });
                    ui.label(
                        RichText::new(
                            "Higher strength = slower unlock + more memory cost. \
                             Re-tunable per-slot; the vault MVK is identical.",
                        )
                        .color(theme::FAINT)
                        .size(11.0),
                    );

                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.add(ghost_button("Cancel")).clicked() {
                            close_pp = true;
                        }
                        if ui.add(primary_button("Enroll")).clicked() {
                            submit_pp = true;
                        }
                    });
                });
        }
        if open_passgen_for_keyslot {
            self.open_passgen(PassgenTarget::AddKeyslotPassphrase);
        }
        if submit_pp {
            // Empty-passphrase guard: confirm before enrolling an
            // empty-passphrase keyslot. Same modal as the create
            // flow; the user re-clicks Enroll after confirming,
            // which clears `empty_passphrase_confirm`.
            let pp_empty = self
                .add_passphrase_modal
                .as_ref()
                .map(|f| f.passphrase.is_empty())
                .unwrap_or(false);
            if pp_empty && self.empty_passphrase_confirm.is_none() {
                self.empty_passphrase_confirm = Some(EmptyPassphraseTarget::AddPassphraseKeyslot);
            } else {
                self.empty_passphrase_confirm = None;
                if let Some(form) = self.add_passphrase_modal.take()
                    && let Some(v) = self.vault.take()
                {
                    let (tx, rx) = std::sync::mpsc::channel::<VaultRet<usize>>();
                    std::thread::spawn(move || {
                        let mut v = v;
                        let r = ops::enroll_passphrase(&mut v.vfs, &form.passphrase, form.kdf);
                        let _ = tx.send((v, r));
                    });
                    self.pending = Some(Pending::EnrollPassphrase { rx });
                }
            }
        } else if close_pp {
            self.add_passphrase_modal = None;
        }

        // Add-fido2 modal
        let mut close_fido = false;
        let mut submit_fido = false;
        if let Some(buf) = self.add_fido2_pin_modal.as_mut() {
            egui::Window::new("Add FIDO2 authenticator keyslot")
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(RichText::new("FIDO2 PIN").color(theme::DIM).size(12.0));
                    let te = egui::TextEdit::singleline(&mut **buf).password(true);
                    ui.add_sized([capped_width(ui, 320.0), CONTROL_H], te);
                    ui.label(
                        RichText::new("You'll be asked to touch the FIDO2 authenticator twice.")
                            .color(theme::FAINT)
                            .size(12.0),
                    );
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.add(ghost_button("Cancel")).clicked() {
                            close_fido = true;
                        }
                        if ui.add(primary_button("Enroll")).clicked() {
                            submit_fido = true;
                        }
                    });
                });
        }
        if submit_fido {
            if let Some(pin) = self.add_fido2_pin_modal.take()
                && let Some(v) = self.vault.take()
            {
                let (tx, rx) = std::sync::mpsc::channel::<VaultRet<usize>>();
                std::thread::spawn(move || {
                    let mut v = v;
                    let r = ops::enroll_fido2(&mut v.vfs, &pin);
                    let _ = tx.send((v, r));
                });
                self.pending = Some(Pending::EnrollFido2 { rx });
            }
        } else if close_fido {
            self.add_fido2_pin_modal = None;
        }

        // Add fused TPM+FIDO2 modal. Same shape as the FIDO2 PIN
        // modal above; on submit, ops::enroll_tpm2_fido2 takes
        // care of seal + register + install in one call.
        let mut close_tf = false;
        let mut submit_tf = false;
        if let Some(buf) = self.add_tpm2_fido2_pin_modal.as_mut() {
            egui::Window::new("Add TPM 2.0 + FIDO2 fused keyslot")
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(RichText::new("FIDO2 PIN").color(theme::DIM).size(12.0));
                    let te = egui::TextEdit::singleline(&mut **buf).password(true);
                    ui.add_sized([capped_width(ui, 320.0), CONTROL_H], te);
                    ui.label(
                        RichText::new(
                            "Both factors required at every future unlock: the local TPM \
                             AND the FIDO2 authenticator. You'll touch the authenticator \
                             twice (register, then derive).",
                        )
                        .color(theme::FAINT)
                        .size(12.0),
                    );
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(
                            "Loss of either factor permanently kills this slot. Keep a \
                             Passphrase or FIDO2-only slot as a recovery path.",
                        )
                        .color(theme::WARN)
                        .size(11.0),
                    );
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.add(ghost_button("Cancel")).clicked() {
                            close_tf = true;
                        }
                        if ui.add(primary_button("Enroll")).clicked() {
                            submit_tf = true;
                        }
                    });
                });
        }
        if submit_tf {
            if let Some(pin) = self.add_tpm2_fido2_pin_modal.take()
                && let Some(v) = self.vault.take()
            {
                let (tx, rx) = std::sync::mpsc::channel::<VaultRet<usize>>();
                std::thread::spawn(move || {
                    let mut v = v;
                    let r = ops::enroll_tpm2_fido2(&mut v.vfs, &pin);
                    let _ = tx.send((v, r));
                });
                self.pending = Some(Pending::EnrollTpm2Fido2 { rx });
            }
        } else if close_tf {
            self.add_tpm2_fido2_pin_modal = None;
        }

        // Add TPM 2.0 + PIN modal. Two PIN fields prevent typo
        // lockout (the chip refuses unseal without the matching PIN).
        let mut close_tp = false;
        let mut submit_tp = false;
        let mut tp_err: Option<String> = None;
        if let Some(form) = self.add_tpm2_pin_modal.as_mut() {
            egui::Window::new("Add TPM 2.0 + PIN keyslot")
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(RichText::new("TPM PIN").color(theme::DIM).size(12.0));
                    let te = egui::TextEdit::singleline(&mut *form.pin).password(true);
                    ui.add_sized([capped_width(ui, 320.0), CONTROL_H], te);
                    ui.add_space(6.0);
                    ui.label(RichText::new("Confirm PIN").color(theme::DIM).size(12.0));
                    let te = egui::TextEdit::singleline(&mut *form.pin_confirm).password(true);
                    ui.add_sized([capped_width(ui, 320.0), CONTROL_H], te);
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(
                            "Wrong PINs count toward the chip's dictionary-attack lockout, \
                             so even short PINs (4-6 digits) are secure on the original \
                             hardware. Loses if the chip dies or the PIN is forgotten - \
                             keep a backup keyslot.",
                        )
                        .color(theme::FAINT)
                        .size(12.0),
                    );
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.add(ghost_button("Cancel")).clicked() {
                            close_tp = true;
                        }
                        if ui.add(primary_button("Enroll")).clicked() {
                            if form.pin.is_empty() {
                                tp_err = Some("PIN cannot be empty".into());
                            } else if *form.pin != *form.pin_confirm {
                                tp_err = Some("PINs do not match".into());
                            } else {
                                submit_tp = true;
                            }
                        }
                    });
                });
        }
        if let Some(e) = tp_err {
            self.toast_err(e);
        }
        if submit_tp {
            if let Some(form) = self.add_tpm2_pin_modal.take()
                && let Some(v) = self.vault.take()
            {
                let pin = form.pin;
                let (tx, rx) = std::sync::mpsc::channel::<VaultRet<usize>>();
                std::thread::spawn(move || {
                    let mut v = v;
                    let r = ops::enroll_tpm2_pin(&mut v.vfs, &pin);
                    let _ = tx.send((v, r));
                });
                self.pending = Some(Pending::EnrollTpm2Pin { rx });
            }
        } else if close_tp {
            self.add_tpm2_pin_modal = None;
        }

        // Add hybrid TPM + ML-KEM(-1024) modal. Captures the
        // destination .kyber path + seed-file passphrase + chosen
        // ML-KEM size (768 or 1024).
        let mut close_ht = false;
        let mut submit_ht = false;
        let mut ht_err: Option<String> = None;
        let mut open_ht_picker = false;
        if let Some(form) = self.add_hybrid_tpm2_modal.as_mut() {
            let title = format!("Add hybrid TPM 2.0 + ML-KEM-{} keyslot", form.kem_size);
            egui::Window::new(title)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(
                        RichText::new("Path for the new .kyber seed file")
                            .color(theme::DIM)
                            .size(12.0),
                    );
                    ui.horizontal(|ui| {
                        let (field_w, browse_w) = trailing_button_row_widths(ui, 320.0, 90.0);
                        ui.add_sized(
                            [field_w, CONTROL_H],
                            egui::TextEdit::singleline(&mut form.kyber_path)
                                .hint_text(path_hints::usb("vault.kyber")),
                        );
                        if ui
                            .add_sized([browse_w, CONTROL_H], ghost_button("Browse..."))
                            .clicked()
                        {
                            open_ht_picker = true;
                        }
                    });
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("Seed-file passphrase (encrypts the .kyber at rest)")
                            .color(theme::DIM)
                            .size(12.0),
                    );
                    let te = egui::TextEdit::singleline(&mut *form.seed_pw).password(true);
                    ui.add_sized([capped_width(ui, 320.0), CONTROL_H], te);
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new("Confirm passphrase")
                            .color(theme::DIM)
                            .size(12.0),
                    );
                    let te = egui::TextEdit::singleline(&mut *form.seed_pw_confirm).password(true);
                    ui.add_sized([capped_width(ui, 320.0), CONTROL_H], te);
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(
                            "MOVE THIS FILE TO SEPARATE TRUSTED STORAGE (USB stick, offline \
                             machine) so an attacker who steals the .lbx can't also grab the \
                             seed. Lose the seed = lose this keyslot.",
                        )
                        .color(theme::WARN)
                        .size(11.0),
                    );
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.add(ghost_button("Cancel")).clicked() {
                            close_ht = true;
                        }
                        if ui.add(primary_button("Enroll")).clicked() {
                            if form.kyber_path.trim().is_empty() {
                                ht_err = Some(".kyber path cannot be empty".into());
                            } else if form.seed_pw.is_empty() {
                                ht_err = Some("seed-file passphrase cannot be empty".into());
                            } else if *form.seed_pw != *form.seed_pw_confirm {
                                ht_err = Some("passphrases do not match".into());
                            } else {
                                submit_ht = true;
                            }
                        }
                    });
                });
        }
        if open_ht_picker {
            // Reuses the existing save-picker plumbing; user picks a
            // path that DOESN'T exist yet (the enroll fails if it does).
            self.start_save_picker(
                "New .kyber seed file",
                "vault.kyber",
                PickerTarget::AddHybridKyber,
            );
        }
        if let Some(e) = ht_err {
            self.toast_err(e);
        }
        if submit_ht {
            if let Some(form) = self.add_hybrid_tpm2_modal.take()
                && let Some(v) = self.vault.take()
            {
                let kyber_path = std::path::PathBuf::from(form.kyber_path);
                let seed_pw = form.seed_pw;
                let kem_size = form.kem_size;
                let vault_path = v.vault_path.clone();
                let (tx, rx) = std::sync::mpsc::channel::<VaultRet<usize>>();
                std::thread::spawn(move || {
                    let mut v = v;
                    let r = ops::enroll_hybrid_pq_tpm2(
                        &mut v.vfs,
                        &vault_path,
                        &kyber_path,
                        &seed_pw,
                        kem_size,
                    );
                    let _ = tx.send((v, r));
                });
                self.pending = Some(Pending::EnrollHybridPqTpm2 { rx });
            }
        } else if close_ht {
            self.add_hybrid_tpm2_modal = None;
        }

        // Add 3-factor TPM + FIDO2 + ML-KEM modal.
        let mut close_h3 = false;
        let mut submit_h3 = false;
        let mut h3_err: Option<String> = None;
        let mut open_h3_picker = false;
        if let Some(form) = self.add_hybrid_tpm2_fido2_modal.as_mut() {
            let title = format!(
                "Add 3-factor TPM 2.0 + FIDO2 + ML-KEM-{} keyslot",
                form.kem_size
            );
            egui::Window::new(title)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(RichText::new("FIDO2 PIN").color(theme::DIM).size(12.0));
                    let te = egui::TextEdit::singleline(&mut *form.fido2_pin).password(true);
                    ui.add_sized([capped_width(ui, 320.0), CONTROL_H], te);
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("Path for the new .kyber seed file")
                            .color(theme::DIM)
                            .size(12.0),
                    );
                    ui.horizontal(|ui| {
                        let (field_w, browse_w) = trailing_button_row_widths(ui, 320.0, 90.0);
                        ui.add_sized(
                            [field_w, CONTROL_H],
                            egui::TextEdit::singleline(&mut form.kyber_path)
                                .hint_text(path_hints::usb("vault.kyber")),
                        );
                        if ui
                            .add_sized([browse_w, CONTROL_H], ghost_button("Browse..."))
                            .clicked()
                        {
                            open_h3_picker = true;
                        }
                    });
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("Seed-file passphrase (encrypts the .kyber at rest)")
                            .color(theme::DIM)
                            .size(12.0),
                    );
                    let te = egui::TextEdit::singleline(&mut *form.seed_pw).password(true);
                    ui.add_sized([capped_width(ui, 320.0), CONTROL_H], te);
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new("Confirm passphrase")
                            .color(theme::DIM)
                            .size(12.0),
                    );
                    let te = egui::TextEdit::singleline(&mut *form.seed_pw_confirm).password(true);
                    ui.add_sized([capped_width(ui, 320.0), CONTROL_H], te);
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(
                            "All three factors required at every unlock. Loss of the chip, \
                             the authenticator, OR the seed file permanently kills this slot. \
                             Keep a Passphrase or FIDO2-only backup keyslot.",
                        )
                        .color(theme::WARN)
                        .size(11.0),
                    );
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.add(ghost_button("Cancel")).clicked() {
                            close_h3 = true;
                        }
                        if ui.add(primary_button("Enroll")).clicked() {
                            if form.fido2_pin.is_empty() {
                                h3_err = Some("FIDO2 PIN cannot be empty".into());
                            } else if form.kyber_path.trim().is_empty() {
                                h3_err = Some(".kyber path cannot be empty".into());
                            } else if form.seed_pw.is_empty() {
                                h3_err = Some("seed-file passphrase cannot be empty".into());
                            } else if *form.seed_pw != *form.seed_pw_confirm {
                                h3_err = Some("passphrases do not match".into());
                            } else {
                                submit_h3 = true;
                            }
                        }
                    });
                });
        }
        if open_h3_picker {
            self.start_save_picker(
                "New .kyber seed file",
                "vault.kyber",
                PickerTarget::AddHybridKyber,
            );
        }
        if let Some(e) = h3_err {
            self.toast_err(e);
        }
        if submit_h3 {
            if let Some(form) = self.add_hybrid_tpm2_fido2_modal.take()
                && let Some(v) = self.vault.take()
            {
                let kyber_path = std::path::PathBuf::from(form.kyber_path);
                let seed_pw = form.seed_pw;
                let fido2_pin = form.fido2_pin;
                let kem_size = form.kem_size;
                let vault_path = v.vault_path.clone();
                let (tx, rx) = std::sync::mpsc::channel::<VaultRet<usize>>();
                std::thread::spawn(move || {
                    let mut v = v;
                    let r = ops::enroll_hybrid_pq_tpm2_fido2(
                        &mut v.vfs,
                        &vault_path,
                        &kyber_path,
                        &seed_pw,
                        &fido2_pin,
                        kem_size,
                    );
                    let _ = tx.send((v, r));
                });
                self.pending = Some(Pending::EnrollHybridPqTpm2Fido2 { rx });
            }
        } else if close_h3 {
            self.add_hybrid_tpm2_fido2_modal = None;
        }

        // mkdir modal
        let mut close_mk = false;
        let mut submit_mk = false;
        if let Some(buf) = self.mkdir_input.as_mut() {
            egui::Window::new("New folder")
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(RichText::new("Folder name").color(theme::DIM).size(12.0));
                    let te = egui::TextEdit::singleline(buf).hint_text("name");
                    ui.add_sized([capped_width(ui, 280.0), CONTROL_H], te);
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.add(ghost_button("Cancel")).clicked() {
                            close_mk = true;
                        }
                        if ui.add(primary_button("Create")).clicked() {
                            submit_mk = true;
                        }
                    });
                });
        }
        if submit_mk {
            let name = self.mkdir_input.take().unwrap_or_default();
            let trimmed = name.trim().to_string();
            if !trimmed.is_empty() {
                let cwd = self.cwd.clone();
                if let Some(v) = self.vault.as_mut() {
                    match v.vfs.lookup_path(&cwd) {
                        Ok(parent) => match v.vfs.mkdir(parent, &trimmed) {
                            Ok(_) => {
                                let _ = v.vfs.flush();
                                self.toast_ok(format!("created /{trimmed}"));
                                self.refresh_listing();
                            }
                            Err(e) => self.toast_err(e.to_string()),
                        },
                        Err(e) => self.toast_err(e.to_string()),
                    }
                }
            }
        } else if close_mk {
            self.mkdir_input = None;
        }

        // Rename modal
        let mut close_rn = false;
        let mut submit_rn = false;
        if let Some(rt) = self.rename_target.as_mut() {
            egui::Modal::new(egui::Id::new("rename-modal"))
                .frame(
                    Frame::default()
                        .fill(theme::PANEL)
                        .stroke(Stroke::new(1.0, theme::BORDER))
                        .corner_radius(CornerRadius::same(10))
                        .inner_margin(20),
                )
                .show(ctx, |ui| {
                    ui.set_min_width(capped_width(ui, 360.0));
                    ui.label(
                        RichText::new(if rt.is_dir {
                            "Rename folder"
                        } else {
                            "Rename file"
                        })
                        .size(15.0)
                        .strong(),
                    );
                    ui.add_space(10.0);
                    ui.label(
                        RichText::new(format!("currently: {}", rt.old_name))
                            .color(theme::FAINT)
                            .small(),
                    );
                    ui.add_space(6.0);
                    let resp = ui.add_sized(
                        [capped_width(ui, 320.0), CONTROL_H],
                        egui::TextEdit::singleline(&mut rt.buf).hint_text("new name"),
                    );
                    if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        submit_rn = true;
                    }
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        if ui.button("Rename").clicked() {
                            submit_rn = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close_rn = true;
                        }
                    });
                });
            if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
                close_rn = true;
            }
        }
        if submit_rn {
            if let Some(rt) = self.rename_target.take() {
                let new_name = rt.buf.trim().to_string();
                if new_name.is_empty() || new_name == rt.old_name {
                    // No-op cases, just close.
                } else if new_name.contains('/') {
                    self.toast_err("name can't contain '/'");
                } else if let Some(v) = self.vault.as_mut() {
                    let cwd = self.cwd.clone();
                    match v.vfs.lookup_path(&cwd) {
                        Ok(parent) => match v.vfs.rename(parent, &rt.old_name, &new_name) {
                            Ok(()) => {
                                let _ = v.vfs.flush();
                                self.toast_ok(format!("renamed to {new_name}"));
                                self.refresh_listing();
                            }
                            Err(e) => self.toast_err(e.to_string()),
                        },
                        Err(e) => self.toast_err(e.to_string()),
                    }
                }
            }
        } else if close_rn {
            self.rename_target = None;
        }
    }

    fn draw_passgen_dialog(&mut self, ctx: &egui::Context) {
        let Some(dialog) = self.passgen_dialog.as_mut() else {
            return;
        };
        let mut closed = false;
        let mut accepted: Option<(PassgenTarget, String)> = None;
        let mut regenerate_now = false;
        // `Some(payload)` if the user clicked "Copy to clipboard". The
        // actual OS-clipboard write happens AFTER the modal closure
        // returns so we can route through the first-time clipboard
        // warning (which itself is another modal we'd be nesting).
        let mut copy_requested: Option<String> = None;
        // True iff the user clicked the "Clear now" button under the
        // active guard's countdown row.
        let mut clear_now_clicked = false;

        // NOTE: every widget below is a vanilla, single-row ui.* call,
        // no horizontal_wrapped, no with_layout(right_to_left), no
        // ghost_button/primary_button wrappers. Two prior rounds of bug
        // reports localised the issue to widgets placed via those layout
        // helpers; whatever the underlying egui interaction was, this
        // explicit per-row layout dodges it entirely.
        let modal = egui::Modal::new(egui::Id::new("passgen-modal"))
            .frame(
                Frame::default()
                    .fill(theme::PANEL)
                    .stroke(Stroke::new(1.0, theme::BORDER))
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(20),
            )
            .show(ctx, |ui| {
                ui.set_min_width(capped_width(ui, 420.0));
                ui.label(RichText::new("Generate passphrase").size(16.0).strong());
                ui.add_space(12.0);

                let prev_opts = dialog.opts;

                ui.label(
                    RichText::new(format!("Length: {} chars", dialog.opts.length))
                        .color(theme::DIM)
                        .small(),
                );
                // Force the slider track to a known width so the
                // draggable region is the full visible bar, not just
                // the area between the value-display and the right
                // edge of the modal. egui's `.text("chars")` form puts
                // the value+suffix label inside the slider widget but
                // those labels are NOT draggable, clicks on them are
                // dead. Splitting the label out (above) gives the
                // slider track the modal's full inner width.
                ui.spacing_mut().slider_width = capped_width(ui, 360.0);
                ui.add(egui::Slider::new(&mut dialog.opts.length, 8..=128).show_value(false));
                ui.add_space(10.0);

                ui.label(RichText::new("Character set").color(theme::DIM).small());
                ui.checkbox(&mut dialog.opts.lowercase, "lowercase letters  (a-z)");
                ui.checkbox(&mut dialog.opts.uppercase, "UPPERCASE letters  (A-Z)");
                ui.checkbox(
                    &mut dialog.opts.digits,
                    "digits  (2-9, ambiguous 0/1 omitted)",
                );
                ui.checkbox(&mut dialog.opts.symbols, "symbols  (!@#$%^&*-_=+?.,;:)");

                let charset_size = dialog.opts.charset().len();
                let bits = dialog.opts.approx_bits();
                ui.add_space(4.0);
                ui.label(
                    RichText::new(format!(
                        "alphabet: {} chars  |  ~{:.0} bits of entropy",
                        charset_size, bits
                    ))
                    .small()
                    .color(theme::FAINT),
                );

                ui.add_space(12.0);
                ui.label(RichText::new("Preview").color(theme::DIM).small());
                // The TextEdit needs a `&mut String`; deref the
                // Zeroizing wrapper. The buffer the user sees is a
                // throwaway clone; egui doesn't let us bind a non-
                // String backing store, so we accept that the rendered
                // copy lives one frame in egui's text galleys until
                // the dialog closes and the preview is wiped on drop.
                let mut preview_visible: String = (*dialog.preview).clone();
                ui.add(
                    egui::TextEdit::singleline(&mut preview_visible)
                        .desired_width(capped_width(ui, 380.0))
                        .font(egui::TextStyle::Monospace),
                );

                if dialog.opts != prev_opts {
                    regenerate_now = true;
                }

                if !dialog.opts.is_valid() {
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("pick at least one character set")
                            .color(theme::DANGER)
                            .small(),
                    );
                }

                ui.add_space(14.0);
                ui.separator();
                ui.add_space(10.0);

                // Action row, explicit per-widget sizes so each click
                // region matches its visible button. (Bare ui.button
                // inside ui.horizontal has been losing hit-rect width
                // on long labels in this codebase repeatedly.)
                let use_label = match dialog.target {
                    PassgenTarget::Standalone => "Done",
                    PassgenTarget::CreatePrimary
                    | PassgenTarget::CreateBackup
                    | PassgenTarget::AddKeyslotPassphrase => "Use this passphrase",
                };
                if ui
                    .add_sized(
                        [capped_width(ui, 380.0), 30.0],
                        egui::Button::new(use_label),
                    )
                    .clicked()
                {
                    accepted = Some((dialog.target, (*dialog.preview).clone()));
                }
                ui.add_space(4.0);
                if ui
                    .add_sized(
                        [capped_width(ui, 380.0), CONTROL_H],
                        egui::Button::new("Re-roll"),
                    )
                    .clicked()
                {
                    regenerate_now = true;
                }
                ui.add_space(4.0);
                // Copy to clipboard. Useful when the user opened the
                // generator from the sidebar (Standalone target) and
                // wants to paste the passphrase into another tool
                // (KeePass, Bitwarden, 1Password). The actual copy is
                // deferred to the post-modal block so we can route
                // through the one-time clipboard-history warning.
                if ui
                    .add_sized(
                        [capped_width(ui, 380.0), CONTROL_H],
                        egui::Button::new("Copy to clipboard"),
                    )
                    .clicked()
                {
                    copy_requested = Some((*dialog.preview).clone());
                }
                ui.add_space(4.0);
                // Cancel on its own full-width row so the hit-rect is
                // always intact and the click reliably closes the
                // modal even when the cursor is near the button edge.
                if ui
                    .add_sized(
                        [capped_width(ui, 380.0), CONTROL_H],
                        egui::Button::new("Cancel"),
                    )
                    .clicked()
                {
                    closed = true;
                }

                // Live countdown for the active clipboard guard, if any.
                // Shown beneath the action buttons so it doesn't shift
                // the rest of the modal layout when it appears /
                // disappears.
                if let Some(g) = self.clipboard_guard.as_ref() {
                    let secs = g.seconds_remaining();
                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(format!("Clipboard auto-clears in {}s", secs))
                            .color(theme::DIM)
                            .small(),
                    );
                    if ui
                        .add_sized(
                            [capped_width(ui, 380.0), CONTROL_H],
                            egui::Button::new("Clear clipboard now"),
                        )
                        .clicked()
                    {
                        clear_now_clicked = true;
                    }
                }
            });

        // Click on the dimmed backdrop = cancel.
        if modal.backdrop_response.clicked() {
            closed = true;
        }
        // Escape key = cancel.
        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            closed = true;
        }

        if regenerate_now
            && let Some(d) = self.passgen_dialog.as_mut()
            && d.opts.is_valid()
        {
            d.preview = zeroize::Zeroizing::new(ops::generate_passphrase_with(&d.opts));
        }
        // Route the copy intent. First time ever: stash the payload
        // and pop the warning modal next frame; user has to "I
        // understand" before the bytes touch the OS clipboard.
        // Subsequent times: copy + install the auto-clear guard
        // immediately.
        if let Some(payload) = copy_requested {
            if self.prefs.clipboard_warning_acknowledged {
                self.commit_clipboard_copy(&ctx, payload);
            } else {
                self.pending_clipboard_warning = Some(zeroize::Zeroizing::new(payload));
            }
        }
        if clear_now_clicked {
            // User pressed the explicit "Clear clipboard now" button.
            // Drop the guard and best-effort wipe; we don't hash-
            // compare here because the user is asking for an
            // unconditional clear.
            self.clipboard_guard = None;
            if let Ok(mut cb) = arboard::Clipboard::new() {
                let _ = cb.set_text(String::new());
            }
            self.toast_ok("clipboard cleared");
        }
        // Keep the countdown ticking smoothly while a guard is live.
        // (The auto-clear toast itself is fired from
        // `tick_clipboard_guard`, not here.)
        if self.clipboard_guard.is_some() {
            ctx.request_repaint_after(Duration::from_millis(500));
        }
        if let Some((target, value)) = accepted {
            match target {
                PassgenTarget::Standalone => {
                    self.toast_ok("passphrase ready, paste it where you need it");
                }
                PassgenTarget::CreatePrimary => {
                    *self.create.passphrase = value;
                    self.toast_ok("passphrase filled in");
                }
                PassgenTarget::CreateBackup => {
                    *self.create.backup_passphrase = value;
                    self.toast_ok("backup passphrase filled in");
                }
                PassgenTarget::AddKeyslotPassphrase => {
                    if let Some(form) = self.add_passphrase_modal.as_mut() {
                        *form.passphrase = value;
                        self.toast_ok("passphrase filled in");
                    }
                }
            }
            self.passgen_dialog = None;
        } else if closed {
            self.passgen_dialog = None;
        }
    }

    /// Push `payload` to the OS clipboard and arm an auto-clear guard
    /// for the configured timeout (currently fixed at 30 s; expose as
    /// a settings dropdown in a future round).
    fn commit_clipboard_copy(&mut self, ctx: &egui::Context, payload: String) {
        const CLEAR_AFTER: Duration = Duration::from_secs(30);
        ctx.copy_text(payload.clone());
        self.clipboard_guard = Some(clipboard_guard::Guard::for_payload(&payload, CLEAR_AFTER));
        self.toast_ok("passphrase copied (auto-clears in 30s)");
        // payload drops here. It's a plain String (not Zeroizing)
        // because it came in by value from the dialog; the dialog's
        // own buffer was Zeroizing, and the clipboard now owns its
        // own copy in egui's output buffer + the OS clipboard. The
        // hash-compare clear is the protection from here on.
    }

    /// Per-frame check on the clipboard auto-clear guard. Called from
    /// the top of `update`. If the guard has expired, hash-compare the
    /// current clipboard contents against what we copied; clear the
    /// clipboard only if it still matches (so a user who copied
    /// something else after pasting our passphrase doesn't lose
    /// their unrelated copy).
    fn tick_clipboard_guard(&mut self, ctx: &egui::Context) {
        let Some(g) = self.clipboard_guard.as_ref() else {
            return;
        };
        if !g.expired() {
            // Repaint a bit before the deadline so the UI countdown
            // ticks down without lag.
            ctx.request_repaint_after(Duration::from_millis(500));
            return;
        }
        let cleared = clipboard_guard::try_clear_if_unchanged(g);
        self.clipboard_guard = None;
        if cleared {
            self.toast_ok("clipboard auto-cleared");
        }
        // No toast on the "user already copied something else" path
        // because the user's intent makes that obvious.
    }

    /// Confirmation modal for keyslot revocation. Always shown before a
    /// destructive `revoke_keyslot` call. When the slot is the only
    /// active credential left, the modal escalates to a stronger
    /// "you will be permanently locked out" warning so the user can't
    /// muscle-memory their way through losing access.
    fn draw_revoke_confirm_modal(&mut self, ctx: &egui::Context) {
        let Some(req) = self.revoke_confirm.as_ref() else {
            return;
        };
        let slot_idx = req.slot_idx;
        let slot_kind = req.slot_kind;
        let would_be_last = req.would_be_last_active_slot;
        let kind_label = match slot_kind {
            SlotKind::Empty => "(empty)",
            SlotKind::Passphrase => "passphrase",
            SlotKind::Fido2HmacSecret => "FIDO2 (hmac-secret)",
            SlotKind::Fido2DerivedMvk => "FIDO2 (derived MVK)",
            SlotKind::HybridPqKemPassphrase => "hybrid-PQ + passphrase",
            SlotKind::HybridPqKemFido2 => "hybrid-PQ + FIDO2",
            SlotKind::HybridPqKem1024Passphrase => "hybrid-PQ-1024 + passphrase",
            SlotKind::HybridPqKem1024Fido2 => "hybrid-PQ-1024 + FIDO2",
            SlotKind::Tpm2Sealed => "TPM 2.0 (machine-bound)",
            SlotKind::Tpm2Fido2 => "TPM 2.0 + FIDO2 (both required)",
            SlotKind::Tpm2SealedPin => "TPM 2.0 + PIN",
            SlotKind::HybridPqKemTpm2 => "hybrid TPM 2.0 + ML-KEM-768",
            SlotKind::HybridPqKemTpm2Fido2 => "hybrid TPM 2.0 + FIDO2 + ML-KEM-768",
            SlotKind::HybridPqKem1024Tpm2 => "hybrid TPM 2.0 + ML-KEM-1024",
            SlotKind::HybridPqKem1024Tpm2Fido2 => "hybrid TPM 2.0 + FIDO2 + ML-KEM-1024",
        };
        let mut confirmed = false;
        let mut cancelled = false;
        let modal = egui::Modal::new(egui::Id::new("revoke-confirm-modal"))
            .frame(
                Frame::default()
                    .fill(theme::PANEL)
                    .stroke(Stroke::new(1.0, theme::BORDER))
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(20),
            )
            .show(ctx, |ui| {
                ui.set_min_width(capped_width(ui, 460.0));
                ui.label(
                    RichText::new(format!("Revoke keyslot #{slot_idx}?"))
                        .size(15.0)
                        .strong(),
                );
                ui.add_space(10.0);
                ui.label(format!(
                    "This will permanently delete the {kind_label} credential in slot \
                     {slot_idx}. The wrapped master key for that credential is \
                     overwritten and cannot be recovered, so the passphrase / \
                     authenticator that unlocked this slot will no longer open the \
                     vault."
                ));
                if would_be_last {
                    ui.add_space(10.0);
                    ui.label(
                        RichText::new(
                            "This is the last active keyslot on this vault. \
                             Revoking it will permanently lock you out of the \
                             vault, no recovery is possible. If you intend to \
                             rotate credentials, enroll the new one FIRST and \
                             then revoke the old one.",
                        )
                        .color(theme::DANGER)
                        .strong(),
                    );
                }
                ui.add_space(8.0);
                ui.label(
                    RichText::new(
                        "Other keyslots on the same vault are unaffected; they \
                         can still unlock the vault as before.",
                    )
                    .color(theme::DIM)
                    .small(),
                );
                ui.add_space(14.0);
                ui.separator();
                ui.add_space(10.0);
                let revoke_label = if would_be_last {
                    "Yes, lock me out permanently"
                } else {
                    "Revoke this keyslot"
                };
                if ui
                    .add_sized(
                        [capped_width(ui, 420.0), CONTROL_H],
                        egui::Button::new(revoke_label),
                    )
                    .clicked()
                {
                    confirmed = true;
                }
                ui.add_space(4.0);
                if ui
                    .add_sized(
                        [capped_width(ui, 420.0), CONTROL_H],
                        egui::Button::new("Cancel"),
                    )
                    .clicked()
                {
                    cancelled = true;
                }
            });
        if modal.backdrop_response.clicked() || ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            cancelled = true;
        }
        if confirmed {
            self.revoke_confirm = None;
            if let Some(v) = self.vault.as_mut() {
                match ops::revoke_keyslot(&mut v.vfs, slot_idx) {
                    Ok(()) => self.toast_ok(format!("slot {slot_idx} revoked")),
                    Err(e) => self.toast_err(e),
                }
            }
        } else if cancelled {
            self.revoke_confirm = None;
        }
    }

    /// One-time clipboard-history warning modal. Surfaces the first
    /// time the user clicks "Copy to clipboard" in any session, ever.
    /// On "I understand", the deferred copy fires and the
    /// acknowledgment is persisted to disk so the modal never returns.
    /// On cancel, the deferred copy is discarded.
    fn draw_clipboard_warning_modal(&mut self, ctx: &egui::Context) {
        if self.pending_clipboard_warning.is_none() {
            return;
        }
        let mut acknowledged = false;
        let mut cancelled = false;
        let modal = egui::Modal::new(egui::Id::new("clipboard-warning-modal"))
            .frame(
                Frame::default()
                    .fill(theme::PANEL)
                    .stroke(Stroke::new(1.0, theme::BORDER))
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(20),
            )
            .show(ctx, |ui| {
                ui.set_min_width(capped_width(ui, 460.0));
                ui.label(
                    RichText::new("About copying passphrases to the clipboard")
                        .size(15.0)
                        .strong(),
                );
                ui.add_space(10.0);
                ui.label(
                    "LUKSbox auto-clears the clipboard 30 seconds after a copy, \
                     and only if the contents haven't changed in the meantime - \
                     so pasting into KeePass / Bitwarden / 1Password works as \
                     you'd expect.",
                );
                ui.add_space(8.0);
                ui.label(
                    RichText::new(
                        "However, third-party clipboard managers (CopyQ, \
                         Klipper, Win+V, KDE Clipboard, GNOME Clipboard \
                         Indicator, macOS Universal Clipboard) keep their \
                         own history independent of the live clipboard. \
                         LUKSbox cannot reach into those histories. If \
                         you have one running, the passphrase will sit \
                         in its log until you clear it manually.",
                    )
                    .color(theme::DIM)
                    .small(),
                );
                ui.add_space(8.0);
                ui.label(
                    RichText::new(
                        "For the strongest path, type the passphrase into the \
                         LUKSbox unlock dialog directly rather than copying.",
                    )
                    .color(theme::DIM)
                    .small(),
                );
                ui.add_space(14.0);
                ui.separator();
                ui.add_space(10.0);
                if ui
                    .add_sized(
                        [capped_width(ui, 420.0), CONTROL_H],
                        egui::Button::new("I understand - copy and don't ask again"),
                    )
                    .clicked()
                {
                    acknowledged = true;
                }
                ui.add_space(4.0);
                if ui
                    .add_sized(
                        [capped_width(ui, 420.0), CONTROL_H],
                        egui::Button::new("Cancel"),
                    )
                    .clicked()
                {
                    cancelled = true;
                }
            });
        if modal.backdrop_response.clicked() || ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            cancelled = true;
        }
        if acknowledged {
            self.prefs.clipboard_warning_acknowledged = true;
            preferences::save(&self.prefs);
            if let Some(payload) = self.pending_clipboard_warning.take() {
                self.commit_clipboard_copy(ctx, (*payload).clone());
            }
        } else if cancelled {
            self.pending_clipboard_warning = None;
        }
    }

    fn draw_toasts(&mut self, ctx: &egui::Context) {
        let now = std::time::Instant::now();
        self.toasts.retain(|t| t.deadline > now);
        if !self.toasts.is_empty() {
            ctx.request_repaint_after(Duration::from_millis(300));
        } else {
            return;
        }
        let toasts = self.toasts.clone();
        egui::Area::new(egui::Id::new("toasts"))
            .anchor(egui::Align2::RIGHT_BOTTOM, [-20.0, -20.0])
            .order(egui::Order::Tooltip)
            .interactable(false)
            .show(ctx, |ui| {
                ui.with_layout(Layout::bottom_up(Align::Max), |ui| {
                    for t in toasts.iter().rev() {
                        let color = match t.kind {
                            ToastKind::Ok => theme::OK,
                            ToastKind::Err => theme::DANGER,
                            ToastKind::Warn => theme::WARN,
                        };
                        Frame::new()
                            .fill(theme::PANEL)
                            .stroke(Stroke::new(1.0, color))
                            .corner_radius(CornerRadius::same(6))
                            .inner_margin(Margin::symmetric(14, 10))
                            .show(ui, |ui| {
                                ui.label(RichText::new(&t.text).color(color).size(12.0));
                            });
                        ui.add_space(8.0);
                    }
                });
            });
    }
}

impl Clone for Toast {
    fn clone(&self) -> Self {
        Self {
            text: self.text.clone(),
            kind: self.kind,
            deadline: self.deadline,
        }
    }
}

// ---- helpers --------------------------------------------------------------

/// OS-aware example file paths used as `hint_text` placeholders. Pure
/// formatting; the runtime path-resolution code never consults these.
/// `cfg!()` resolves at compile time, so each release binary shows the
/// convention native to the host OS:
///
/// | OS      | `home("foo.lbx")`           | `usb("foo.kyber")`     |
/// |---------|-----------------------------|------------------------|
/// | Linux   | `/home/you/foo.lbx`         | `/media/usb/foo.kyber` |
/// | macOS   | `/Users/you/foo.lbx`        | `/Volumes/USB/foo.kyber` |
/// | Windows | `C:\Users\you\foo.lbx`      | `D:\foo.kyber`         |
mod path_hints {
    pub fn home(name: &str) -> String {
        if cfg!(target_os = "windows") {
            format!("C:\\Users\\you\\{name}")
        } else if cfg!(target_os = "macos") {
            format!("/Users/you/{name}")
        } else {
            format!("/home/you/{name}")
        }
    }

    /// Removable / external storage example. Used in placeholders that
    /// remind the user to keep .kyber / .anchor / detached .hdr files
    /// on a separate device, not next to the .lbx.
    pub fn usb(name: &str) -> String {
        if cfg!(target_os = "windows") {
            format!("D:\\{name}")
        } else if cfg!(target_os = "macos") {
            format!("/Volumes/USB/{name}")
        } else {
            format!("/media/usb/{name}")
        }
    }
}

const FORM_FIELD_MAX_W: f32 = 600.0;
const FORM_FIELD_MIN_W: f32 = 120.0;
const CONTROL_H: f32 = 28.0;
const SCROLL_EDGE_PAD: f32 = 64.0;

fn sidebar_content_width(ui: &egui::Ui) -> f32 {
    capped_width(ui, 248.0)
}

fn capped_width(ui: &egui::Ui, max: f32) -> f32 {
    let available = ui.available_width();
    if available.is_finite() && available >= 1.0 {
        available.max(FORM_FIELD_MIN_W).min(max)
    } else {
        max
    }
}

fn form_width(ui: &egui::Ui) -> f32 {
    capped_width(ui, FORM_FIELD_MAX_W)
}

fn trailing_button_row_widths(ui: &egui::Ui, field_max: f32, button_max: f32) -> (f32, f32) {
    let available = ui.available_width().max(FORM_FIELD_MIN_W);
    let gap = ui.spacing().item_spacing.x;
    let button_w = button_max.min((available * 0.35).max(72.0));
    let field_w = (available - button_w - gap)
        .max(FORM_FIELD_MIN_W)
        .min(field_max);
    (field_w, button_w)
}

fn add_scroll_edge_padding(ui: &mut egui::Ui) {
    ui.add_space(SCROLL_EDGE_PAD);
}

fn chars_for_width(width: f32) -> usize {
    if !width.is_finite() || width <= 0.0 {
        return 24;
    }
    (width / 6.2).floor().clamp(8.0, 48.0) as usize
}

fn shorten_middle(s: &str, max_chars: usize) -> String {
    let len = s.chars().count();
    if len <= max_chars {
        return s.to_string();
    }
    if max_chars <= 3 {
        return ".".repeat(max_chars);
    }

    let keep = max_chars - 3;
    let head_len = keep.div_ceil(2);
    let tail_len = keep / 2;
    let head: String = s.chars().take(head_len).collect();
    let tail: String = s
        .chars()
        .rev()
        .take(tail_len)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{head}...{tail}")
}

/// Coloured bar (red->green) + numeric estimate. Drawn under a passphrase
/// field. Empty input renders nothing, keeps the form quiet until the
/// user starts typing.
fn strength_meter(ui: &mut egui::Ui, passphrase: &str) {
    if passphrase.is_empty() {
        return;
    }
    let (score, _bits) = ops::passphrase_strength(passphrase);
    let (color, label) = match score {
        0 => (theme::DANGER, "very weak"),
        1 => (Color32::from_rgb(0xff, 0x8a, 0x4a), "weak"),
        2 => (theme::WARN, "okay"),
        3 => (Color32::from_rgb(0xa0, 0xd9, 0x73), "strong"),
        _ => (theme::OK, "very strong"),
    };
    let chars = passphrase.chars().count();
    ui.add_space(4.0);
    let total_w = form_width(ui);
    let bar_h = 6.0_f32;
    let (rect, _) = ui.allocate_exact_size(Vec2::new(total_w, bar_h), egui::Sense::hover());
    ui.painter()
        .rect_filled(rect, CornerRadius::same(3), theme::PANEL2);
    let fill_w = (total_w * (0.1 + 0.225 * score as f32)).min(total_w);
    let fill_rect = egui::Rect::from_min_size(rect.min, Vec2::new(fill_w, bar_h));
    ui.painter()
        .rect_filled(fill_rect, CornerRadius::same(3), color);
    ui.painter().rect_stroke(
        rect,
        CornerRadius::same(3),
        Stroke::new(1.0, theme::BORDER),
        egui::StrokeKind::Inside,
    );
    ui.add_space(2.0);
    let suffix = if chars == 1 { "char" } else { "chars" };
    ui.label(
        RichText::new(format!("{label}  ·  {chars} {suffix}"))
            .color(color)
            .size(11.0),
    );
}

fn primary_button(text: impl Into<egui::WidgetText>) -> egui::Button<'static> {
    egui::Button::new(text.into().color(Color32::from_rgb(0x0a, 0x0e, 0x16)))
        .fill(theme::ACCENT)
        .min_size(Vec2::new(0.0, 32.0))
}

fn ghost_button(text: impl Into<egui::WidgetText>) -> egui::Button<'static> {
    egui::Button::new(text.into().color(theme::DIM))
        .fill(Color32::TRANSPARENT)
        .stroke(Stroke::new(1.0, theme::BORDER))
        .min_size(Vec2::new(0.0, 28.0))
}

/// Welcome-page bulleted item: bold one-line title, dim explanation
/// underneath. Used inside the post-quantum / operational-tips
/// frames on `draw_welcome`.
fn bullet(ui: &mut egui::Ui, title: &str, body: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("•").color(theme::ACCENT).size(13.0));
        ui.vertical(|ui| {
            ui.label(RichText::new(title).strong().color(theme::TEXT).size(13.0));
            ui.label(RichText::new(body).color(theme::DIM).size(12.0));
        });
    });
    ui.add_space(6.0);
}

fn section(ui: &mut egui::Ui, title: &str, body: impl FnOnce(&mut egui::Ui)) {
    Frame::new()
        .fill(theme::PANEL)
        .stroke(Stroke::new(1.0, theme::BORDER))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(18)
        .show(ui, |ui| {
            // egui Frame sizes to its content by default; force the
            // inner ui to claim the parent's available width so the
            // box visually fills its column instead of shrinking to
            // the longest label inside.
            ui.set_min_width(ui.available_width());
            ui.label(
                RichText::new(title.to_uppercase())
                    .color(theme::FAINT)
                    .small()
                    .strong(),
            );
            ui.add_space(8.0);
            body(ui);
        });
    ui.add_space(12.0);
}

fn parent_path(p: &str) -> String {
    if p == "/" {
        return p.into();
    }
    let trimmed = p.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(0) => "/".into(),
        Some(i) => trimmed[..i].into(),
        None => "/".into(),
    }
}

fn join_path(cwd: &str, name: &str) -> String {
    if cwd == "/" {
        format!("/{name}")
    } else {
        format!("{cwd}/{name}")
    }
}

fn format_size(b: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{} B", b)
    } else {
        format!("{:.1} {}", v, UNITS[u])
    }
}

/// Canonical absolute paths for the host's "open in file manager"
/// helper. Hard-coded allow-list, NOT a `$PATH` lookup, to close the
/// PATH-hijack class flagged by CVE-2024-54187 (VeraCrypt 1.26.18).
/// See also `crates/luksbox-mount/src/fuse.rs`'s
/// `resolved_unmount_program` for the same pattern on the unmount
/// helper side.
///
/// NixOS ships xdg-open under `/run/current-system/sw/bin/xdg-open`;
/// users on those distros will see `Refusing to fall back to PATH`.
/// That is the intended outcome (security over convenience); add a
/// distro feature flag rather than reopen the PATH lookup if NixOS
/// support becomes a real ask.
#[cfg(target_os = "linux")]
const OPEN_HELPER_CANDIDATES: &[&str] = &[
    "/usr/bin/xdg-open",
    "/bin/xdg-open",
    "/usr/local/bin/xdg-open",
];
#[cfg(target_os = "macos")]
const OPEN_HELPER_CANDIDATES: &[&str] = &["/usr/bin/open"];

/// Resolve the platform "open in file manager" helper to an absolute
/// path. Returns `None` if no candidate exists; caller surfaces a
/// user-visible error instead of falling through to a `$PATH` lookup.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn resolved_default_app_opener() -> Option<std::path::PathBuf> {
    OPEN_HELPER_CANDIDATES
        .iter()
        .map(std::path::Path::new)
        .find(|p| p.is_file())
        .map(|p| p.to_path_buf())
}

/// On Windows, resolve `explorer.exe` against `%SystemRoot%`. We
/// refuse to fall back to a bare-name spawn (which would be a `$PATH`
/// lookup) even when `SystemRoot` is unset, since a missing
/// `SystemRoot` indicates a tampered environment.
#[cfg(target_os = "windows")]
fn resolved_default_app_opener() -> Option<std::path::PathBuf> {
    let sysroot = std::env::var_os("SystemRoot").map(std::path::PathBuf::from);
    let candidate = sysroot
        .map(|r| r.join("explorer.exe"))
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows\explorer.exe"));
    if candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
}

/// Open `path` in the host's file manager (Finder / Explorer / the
/// XDG-default). Resolves the helper to a hard-coded absolute path
/// rather than relying on `$PATH` (CVE-2024-54187 class). On platforms
/// where no helper resolves, surfaces the failure via the existing
/// `eprintln!` channel - caller is fire-and-forget.
fn open_in_file_manager(path: impl AsRef<std::path::Path>) {
    let path = path.as_ref();

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    let cmd = match resolved_default_app_opener() {
        Some(prog) => std::process::Command::new(&prog).arg(path).spawn(),
        None => Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no trusted file-manager opener found at any known absolute \
             path; refusing to fall back to a $PATH lookup (CVE-2024-54187 \
             class). Install the helper at a standard system location.",
        )),
    };

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    let cmd: std::io::Result<std::process::Child> = Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no file-manager opener known for this platform",
    ));

    if let Err(e) = cmd {
        eprintln!("open mountpoint {}: {e}", path.display());
    }
}

/// Find the first unused Windows drive letter, walking from Z down
/// (the conventional "user mounts go high" range). Skips A-D
/// because those are typically claimed by the system / removable
/// media. Probes each letter with `Path::exists()` on the root path
/// (e.g. `Z:\`) and treats a non-existent root as available.
///
/// Returns the path WinFsp expects as the mountpoint argument: the
/// drive letter followed by a colon, no trailing slash. Linux/macOS
/// paths are not relevant here; this function is only called on
/// Windows.
#[allow(dead_code)] // referenced via cfg!(target_os = "windows") branch
fn find_free_windows_drive_letter() -> Option<std::path::PathBuf> {
    for c in (b'E'..=b'Z').rev() {
        let root = format!("{}:\\", c as char);
        if !std::path::Path::new(&root).exists() {
            return Some(std::path::PathBuf::from(format!("{}:", c as char)));
        }
    }
    None
}
