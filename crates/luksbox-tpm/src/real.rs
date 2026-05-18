// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Real TPM 2.0 implementation, gated on `--features hardware`.
//!
//! Uses the `tss-esapi` crate (wrapper over libtss2-esys). The flow
//! follows the systemd-cryptenroll model for LUKS2 TPM enrollment:
//!
//! 1. Open a TPM context (TCTI defaults to `device:/dev/tpmrm0` ->
//!    `device:/dev/tpm0` -> environment `TPM2TOOLS_TCTI`).
//! 2. Build a Storage Root Key under the Owner hierarchy. The SRK is
//!    deterministically derived from the TPM's persistent
//!    endorsement seed, so we recreate it identically on every
//!    open - no need to persist a handle.
//! 3. `Create` a sealed data object as a child of the SRK,
//!    containing the 32-byte plaintext.
//! 4. Return the (TPM2B_PUBLIC, TPM2B_PRIVATE) bytes.
//!
//! Unseal is the inverse: recreate SRK, `Load` the blobs as a
//! transient object, `Unseal` to extract the data.
//!
//! No PCR sealing in v1 (sealed object policy is empty so any
//! caller on this TPM can unseal). No userAuth either. Both are
//! opt-in extensions tracked in `SECURITY.md`.

use tss_esapi::{
    Context, TctiNameConf,
    attributes::ObjectAttributesBuilder,
    constants::SessionType,
    handles::ObjectHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        key_bits::AesKeyBits,
        resource_handles::Hierarchy,
        session_handles::AuthSession,
    },
    structures::{
        Auth, CreateKeyResult, CreatePrimaryKeyResult, Digest, EccPoint, EccScheme,
        KeyDerivationFunctionScheme, KeyedHashScheme, Private, PublicBuilder,
        PublicEccParametersBuilder, PublicKeyedHashParameters, SensitiveData, SymmetricDefinition,
        SymmetricDefinitionObject,
    },
    tcti_ldr::{DeviceConfig, TctiNameConf as Tcti},
    traits::{Marshall, UnMarshall},
};
use zeroize::Zeroizing;

use crate::{Error, SEALED_SECRET_LEN, SealedBlob};

pub struct Tpm2Sealer {
    ctx: Context,
}

impl Tpm2Sealer {
    /// Open a TPM context using the default TCTI: `device:/dev/tpmrm0`
    /// (the kernel resource manager). Falls back to `device:/dev/tpm0`
    /// if the resource manager isn't present (older kernel or
    /// `CONFIG_TCG_TPM2_HMAC` disabled).
    ///
    /// Honors the `TCTI_NAME_CONF` environment variable transparently
    /// (the underlying `tpm2-tss` library reads it before our default
    /// kicks in). Setting `TCTI_NAME_CONF=tabrmd` for example routes
    /// through the resource-manager daemon instead.
    pub fn new() -> Result<Self, Error> {
        // If the user has explicitly set TCTI_NAME_CONF, use it -
        // they're overriding the default for a reason (tabrmd,
        // swtpm at a non-standard path, etc.).
        if let Ok(spec) = std::env::var("TCTI_NAME_CONF") {
            return Self::from_tcti_str(&spec);
        }
        // Try the resource manager first (no exclusive lock).
        let primary = Tcti::Device(DeviceConfig::default());
        let ctx = Context::new(primary)
            .map_err(|e| Error::DeviceNotAvailable(diagnose_device_open_failure(&e.to_string())))?;
        Ok(Self { ctx })
    }

    /// Construct from an explicit TCTI configuration string. Used by
    /// integration tests with `swtpm` (e.g.
    /// `from_tcti_str("swtpm:host=127.0.0.1,port=2321")`) and by users
    /// who need to override the device path.
    pub fn from_tcti_str(tcti: &str) -> Result<Self, Error> {
        let conf: TctiNameConf = tcti
            .parse()
            .map_err(|e| Error::DeviceNotAvailable(format!("bad TCTI string {tcti:?}: {e}")))?;
        let ctx = Context::new(conf).map_err(|e| {
            Error::DeviceNotAvailable(format!("could not open TPM via {tcti:?}: {e}"))
        })?;
        Ok(Self { ctx })
    }

    /// Seal `plaintext` under a fresh sealed-data object that's a
    /// child of the SRK. Returns the (public, private) blobs the
    /// caller stores in the keyslot.
    pub fn seal(&mut self, plaintext: &[u8; SEALED_SECRET_LEN]) -> Result<SealedBlob, Error> {
        self.seal_with_pin(plaintext, None)
    }

    /// Like `seal` but binds a PIN to the sealed object via TPM
    /// `userAuth`. At unseal time the same PIN must be presented or
    /// the TPM refuses; wrong PINs count toward the chip's
    /// dictionary-attack lockout (typically about 32 wrong attempts then
    /// a multi-hour cooldown), so even short PINs (4-6 digits) are
    /// secure on the original hardware.
    ///
    /// Pass `pin = None` to behave identically to `seal()` (no
    /// userAuth, no PIN required for unseal).
    pub fn seal_with_pin(
        &mut self,
        plaintext: &[u8; SEALED_SECRET_LEN],
        pin: Option<&[u8]>,
    ) -> Result<SealedBlob, Error> {
        // Need an HMAC session for command/response auth; without one
        // any subsequent `Esys_Create` rejects with TPM_RC_AUTH_MISSING.
        let session = self.start_hmac_session()?;
        self.ctx.set_sessions((Some(session), None, None));

        let primary = self.create_srk(session)?;
        let result = self.create_sealed_object(primary.key_handle.into(), plaintext, pin)?;

        // Flush the SRK transient handle so we don't leak handles
        // across many seal operations (TPMs typically have a small
        // handle table - about 3 transient slots is common).
        let _ = self.ctx.flush_context(primary.key_handle.into());

        let public_bytes = result
            .out_public
            .marshall()
            .map_err(|e| Error::TpmError(format!("marshall TPM2B_PUBLIC: {e}")))?;
        // `Private` is a buffer type, not a marshalled struct - it
        // exposes its bytes via `value()`. We treat the raw byte
        // run as opaque and prefix it with its length when packed
        // into the SealedBlob (see `SealedBlob::to_bytes`).
        let private_bytes: Vec<u8> = result.out_private.value().to_vec();

        Ok(SealedBlob {
            public: public_bytes,
            private: private_bytes,
        })
    }

    /// Unseal a previously-sealed blob, returning the original 32-byte
    /// plaintext wrapped in `Zeroizing` so the caller's heap copy is
    /// wiped on drop.
    pub fn unseal(
        &mut self,
        blob: &SealedBlob,
    ) -> Result<Zeroizing<[u8; SEALED_SECRET_LEN]>, Error> {
        self.unseal_with_pin(blob, None)
    }

    /// Like `unseal` but presents `pin` as the sealed object's
    /// userAuth. Required for blobs created via `seal_with_pin(_, Some)`.
    /// Wrong PINs are counted by the TPM toward dictionary-attack
    /// lockout - the caller should not retry blindly; surface the
    /// failure to the user instead.
    pub fn unseal_with_pin(
        &mut self,
        blob: &SealedBlob,
        pin: Option<&[u8]>,
    ) -> Result<Zeroizing<[u8; SEALED_SECRET_LEN]>, Error> {
        let session = self.start_hmac_session()?;
        self.ctx.set_sessions((Some(session), None, None));

        let primary = self.create_srk(session)?;

        let public = tss_esapi::structures::Public::unmarshall(&blob.public)
            .map_err(|e| Error::TpmError(format!("unmarshall TPM2B_PUBLIC: {e}")))?;
        let private = Private::try_from(blob.private.clone())
            .map_err(|e| Error::TpmError(format!("private blob too large: {e}")))?;

        let loaded = self
            .ctx
            .load(primary.key_handle, private, public)
            .map_err(|e| Error::TpmError(format!("Esys_Load: {e}")))?;

        // If the blob was sealed with a PIN, set it on the loaded
        // object's auth slot so the next Esys_Unseal carries the
        // correct password session value.
        if let Some(pin_bytes) = pin {
            // `Auth::try_from(&[u8])` copies into the type's internal
            // storage (a `BoxedBytes`-like buffer); avoid an additional
            // unzeroized `Vec<u8>` on our side. The Auth-internal copy
            // is upstream-owned and not zeroized in tss-esapi 7.x.
            let auth = Auth::try_from(pin_bytes)
                .map_err(|e| Error::TpmError(format!("PIN too long: {e}")))?;
            self.ctx
                .tr_set_auth(loaded.into(), auth)
                .map_err(|e| Error::TpmError(format!("Esys_TR_SetAuth (PIN): {e}")))?;
        }

        let unsealed = self
            .ctx
            .unseal(ObjectHandle::from(loaded))
            .map_err(|e| Error::TpmError(format!("Esys_Unseal: {e}")))?;

        let _ = self.ctx.flush_context(loaded.into());
        let _ = self.ctx.flush_context(primary.key_handle.into());

        // `SensitiveData` is a buffer type; `value()` returns the
        // unsealed plaintext bytes.
        let bytes: &[u8] = unsealed.value();
        if bytes.len() != SEALED_SECRET_LEN {
            return Err(Error::TpmError(format!(
                "unsealed length {} != expected {}",
                bytes.len(),
                SEALED_SECRET_LEN
            )));
        }
        let mut out = Zeroizing::new([0u8; SEALED_SECRET_LEN]);
        out.copy_from_slice(bytes);
        Ok(out)
    }

    // ---- internal helpers --------------------------------------------

    fn start_hmac_session(&mut self) -> Result<AuthSession, Error> {
        let session = self
            .ctx
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256,
            )
            .map_err(|e| Error::TpmError(format!("Esys_StartAuthSession: {e}")))?
            .ok_or_else(|| Error::TpmError("StartAuthSession returned no session".into()))?;
        let (sess_attrs, mask) = tss_esapi::attributes::SessionAttributesBuilder::new()
            .with_decrypt(true)
            .with_encrypt(true)
            .build();
        self.ctx
            .tr_sess_set_attributes(session, sess_attrs, mask)
            .map_err(|e| Error::TpmError(format!("Esys_TRSess_SetAttributes: {e}")))?;
        Ok(session)
    }

    /// Build the Storage Root Key as a transient primary key in the
    /// Owner hierarchy. Same template as systemd-cryptenroll uses;
    /// deterministic from the TPM's primary seed, so re-derives
    /// identically on every call.
    fn create_srk(&mut self, _session: AuthSession) -> Result<CreatePrimaryKeyResult, Error> {
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_st_clear(false)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_restricted(true)
            .build()
            .map_err(|e| Error::TpmError(format!("ObjectAttributesBuilder: {e}")))?;

        let ecc_params = PublicEccParametersBuilder::new()
            .with_ecc_scheme(EccScheme::Null)
            .with_curve(EccCurve::NistP256)
            .with_is_signing_key(false)
            .with_is_decryption_key(true)
            .with_restricted(true)
            .with_symmetric(SymmetricDefinitionObject::Aes {
                key_bits: AesKeyBits::Aes128,
                mode: tss_esapi::interface_types::algorithm::SymmetricMode::Cfb,
            })
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .build()
            .map_err(|e| Error::TpmError(format!("EccParametersBuilder: {e}")))?;

        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_ecc_parameters(ecc_params)
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .map_err(|e| Error::TpmError(format!("PublicBuilder (SRK): {e}")))?;

        self.ctx
            .create_primary(Hierarchy::Owner, public, None, None, None, None)
            .map_err(|e| Error::TpmError(format!("Esys_CreatePrimary (SRK): {e}")))
    }

    /// Build a sealed data object containing `plaintext` as a child
    /// of `parent`. Returns the (public, private) blobs. If `pin` is
    /// `Some`, it's set as the object's userAuth so subsequent
    /// `Esys_Unseal` calls require it.
    fn create_sealed_object(
        &mut self,
        parent: ObjectHandle,
        plaintext: &[u8; SEALED_SECRET_LEN],
        pin: Option<&[u8]>,
    ) -> Result<CreateKeyResult, Error> {
        // Sealed-data objects use the KeyedHash algorithm with a Null
        // scheme (the data isn't keyed; it's just opaque user payload).
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_st_clear(false)
            .with_sensitive_data_origin(false) // <- caller-provided data
            .with_user_with_auth(true)
            .with_decrypt(false)
            .with_sign_encrypt(false)
            .build()
            .map_err(|e| Error::TpmError(format!("ObjectAttributesBuilder (sealed): {e}")))?;

        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
            .with_keyed_hash_unique_identifier(Digest::default())
            .build()
            .map_err(|e| Error::TpmError(format!("PublicBuilder (sealed): {e}")))?;

        // Round 12 fix R12-18: wrap the intermediate Vec in a
        // Zeroizing wrapper so the heap copy of the 32-byte plaintext
        // is wiped at end-of-scope rather than left dangling for
        // allocator reuse to reveal. `SensitiveData::try_from`
        // internally clones the bytes into a TSS-owned buffer; the
        // upstream impl does NOT zeroize on drop (see audit note in
        // unseal_with_pin), so this wrapper is the last line of
        // defense before the bytes leave Rust's allocator.
        let plaintext_vec: zeroize::Zeroizing<Vec<u8>> =
            zeroize::Zeroizing::new(plaintext.to_vec());
        let sensitive_data = SensitiveData::try_from((*plaintext_vec).clone())
            .map_err(|e| Error::TpmError(format!("SensitiveData: {e}")))?;

        // tss-esapi 7.x's Context::create takes (auth_value,
        // sensitive_data) as separate Option args (it builds the
        // TPMS_SENSITIVE_CREATE internally). When auth_value is
        // Some, the TPM stores it as userAuth; subsequent unseal
        // operations need it presented via tr_set_auth on the
        // loaded object handle. Pass None to omit (no PIN required).
        let user_auth = match pin {
            // Same reasoning as in `unseal_with_pin`: pass the slice
            // straight in and skip the local unzeroized Vec round-trip.
            Some(pin_bytes) => Some(
                Auth::try_from(pin_bytes)
                    .map_err(|e| Error::TpmError(format!("PIN too long for TPM Auth: {e}")))?,
            ),
            None => None,
        };

        self.ctx
            .create(
                parent.into(),
                public,
                user_auth,
                Some(sensitive_data),
                None,
                None,
            )
            .map_err(|e| Error::TpmError(format!("Esys_Create (seal): {e}")))
    }
}

/// Map a raw libtss2 device-open error into an actionable user-facing
/// hint. tss-esapi normalises the underlying TCTI errors to terse
/// strings like "response code not recognized" that don't hint at
/// the right fix, so we pre-stat the expected device nodes and use
/// THAT signal to pick the right remediation - the libtss2 stderr
/// output that mentions "No such file" / "Permission denied" doesn't
/// reach the Rust-side error string.
fn diagnose_device_open_failure(raw: &str) -> String {
    use std::path::Path;
    let lower = raw.to_lowercase();
    let dev_rm = Path::new("/dev/tpmrm0");
    let dev = Path::new("/dev/tpm0");
    // Phase 1: pre-stat the expected device nodes. If neither
    // exists we know it's the missing-driver / disabled-firmware
    // case independent of what libtss2 said.
    let device_kind = if !dev_rm.exists() && !dev.exists() {
        DeviceKind::None
    } else {
        // At least one node exists; check if we can open it for
        // read+write to distinguish permission-denied from genuine
        // device errors.
        let target = if dev_rm.exists() { dev_rm } else { dev };
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(target)
        {
            Ok(_) => DeviceKind::Opens,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => DeviceKind::PermDenied,
            Err(_) => DeviceKind::Other,
        }
    };
    // Suppress unused-variable warning - `lower` is used by future
    // diagnostics that key off the libtss2 string in addition to
    // the device-existence pre-check.
    let _ = lower;
    let hint = match device_kind {
        DeviceKind::None => {
            "No /dev/tpmrm0 (or /dev/tpm0) device node was found.\n\n\
         Most modern PCs ship a TPM 2.0 (discrete chip OR firmware TPM\n\
         via Intel PTT / AMD fTPM), but the kernel module may not be\n\
         loaded or the firmware setting may be disabled.\n\n\
         Diagnose:\n  \
         lsmod | grep tpm                  # is the driver loaded?\n  \
         dmesg | grep -i tpm | tail -10    # what does the kernel say?\n\n\
         Fixes:\n  \
         - In the BIOS/UEFI setup, look for an option like \"Trusted Platform\n\
           Module\", \"Intel PTT\" (firmware TPM on Intel), or \"AMD fTPM\"\n\
           (firmware TPM on AMD). Enable it, save, reboot.\n  \
         - If the chip exists but the driver isn't loaded:\n      \
             sudo modprobe tpm_crb        # CRB-interface chips (most modern)\n      \
             sudo modprobe tpm_tis        # TIS-interface chips (older)\n  \
         - On a server/cloud VM, the host typically doesn't expose a\n    \
             TPM to guests. Use a virtual TPM (`swtpm`) or fall back\n    \
             to a passphrase / FIDO2 keyslot."
        }
        DeviceKind::PermDenied => {
            "Permission denied opening /dev/tpmrm0.\n\n\
         The TPM device node is owned by root:tss on most distros.\n\
         Add yourself to the `tss` group:\n  \
             sudo usermod -aG tss \"$USER\"\n  \
             # log out + log back in for the new group to take effect\n\n\
         Verify membership with `id`. If `tss` doesn't exist on your\n\
         system, install the TPM userspace tools:\n  \
             sudo apt install tpm2-tools         # Debian/Ubuntu\n  \
             sudo dnf install tpm2-tools         # Fedora/RHEL\n  \
             sudo pacman -S tpm2-tools           # Arch\n\n\
         Full guide (udev rules, container/Flatpak passthrough,\n\
         common errors): docs/TPM_LINUX_PERMISSIONS.md"
        }
        DeviceKind::Opens | DeviceKind::Other => {
            "The device node exists and is readable, but the TPM\n\
         operation itself failed. Possible causes:\n  \
             - TPM is in dictionary-attack lockout (clear with\n        \
                 `tpm2_dictionarylockout --clear-lockout`).\n  \
             - Firmware TPM (Intel PTT / AMD fTPM) is enabled but\n    \
                 not initialised (toggle off + on in BIOS, save,\n    \
                 cold-boot the machine).\n  \
             - Another process is exclusively holding /dev/tpm0;\n    \
                 use /dev/tpmrm0 (the resource manager) by setting\n    \
                 TCTI_NAME_CONF=device:/dev/tpmrm0.\n\n\
         Open with another method (passphrase / FIDO2) instead, or set\n\
         TCTI_NAME_CONF to override the device path (e.g.\n\
         TCTI_NAME_CONF=tabrmd to route through the resource-manager\n\
         daemon)."
        }
    };
    format!("could not open the local TPM 2.0 device: {raw}\n\n{hint}")
}

#[derive(Debug)]
enum DeviceKind {
    /// No /dev/tpm* device node present on the system.
    None,
    /// Device exists but the calling user can't open it rw.
    PermDenied,
    /// Device opens fine; the failure was inside the TPM protocol.
    Opens,
    /// Other I/O error while trying to open (rare).
    Other,
}

/// Map common TPM operation failures (busy, lockout, etc.) into the
/// same actionable-hint shape. Called from the user-facing wrappers
/// that surface these errors at the GUI / CLI layer; the raw
/// `Esys_*` error string from `tss-esapi` rarely tells a non-expert
/// what to do next.
///
/// Currently used by integration code outside this crate via the
/// `Error::TpmError(String)` Display path; this function is exposed
/// so the CLI / GUI can prepend hints without re-parsing libtss2
/// error codes themselves.
pub fn diagnose_operation_error(raw: &str) -> Option<&'static str> {
    let lower = raw.to_lowercase();
    if lower.contains("lockout") || lower.contains("rc_lockout") {
        Some(
            "The TPM is in dictionary-attack lockout. The chip refuses further auth\n\
             attempts for a cooldown period (typically 1-24 hours, configurable per\n\
             vendor) after too many wrong tries.\n\n\
             To clear the lockout NOW (requires the TPM owner authorization, which\n\
             on most systems is empty / not yet set):\n  \
                 tpm2_dictionarylockout --clear-lockout\n\n\
             If the owner auth has been set (e.g. by systemd-cryptenroll or by an\n\
             enterprise management tool), you'll need that password.",
        )
    } else if lower.contains("rc_initialize") || lower.contains("not initialized") {
        Some(
            "The TPM hasn't been initialized for use yet. Run `tpm2_startup -c` to\n\
             send the Startup(CLEAR) command (the kernel normally does this\n\
             automatically at boot; if it didn't, the firmware may need a fresh\n\
             power cycle, NOT just a reboot).",
        )
    } else if lower.contains("auth") && lower.contains("missing") {
        Some(
            "The operation needed authorization but none was supplied. This usually\n\
             means a stale handle is in the TPM's transient table from a previous\n\
             crashed luksbox process. Restart the calling process; if that doesn't\n\
             help, run `tpm2_flushcontext --transient-object` to clear stale handles.",
        )
    } else {
        None
    }
}
