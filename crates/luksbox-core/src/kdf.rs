// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::{Zeroize, Zeroizing};

use crate::error::Error;
use crate::key::{KEY_LEN, KeyEncryptionKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum KdfId {
    Argon2id = 0x0001,
}

impl KdfId {
    pub fn from_u16(v: u16) -> Result<Self, Error> {
        match v {
            0x0001 => Ok(Self::Argon2id),
            _ => Err(Error::UnsupportedKdf(v)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2idParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Argon2idParams {
    /// DoS guard: maximum memory cost we'll accept from on-disk params.
    /// 4 GiB is comfortably above our `Sensitive` preset (1 GiB). An
    /// attacker who has write access to a vault file or .kyber seed file
    /// could otherwise set `m_cost_kib = u32::MAX` (about 4 TiB allocation
    /// request -> instant OOM) on every unlock attempt.
    pub const SAFE_M_COST_KIB_MAX: u32 = 4 * 1024 * 1024;
    /// DoS guard: maximum iteration count. 16 is about 3x our `SENSITIVE`
    /// preset (t=5), still gives plenty of headroom for any future
    /// preset that wants extra stretching, while bounding compute cost
    /// from a hostile on-disk value. Tightened from 64 in audit
    /// follow-up: lower bound speeds up `seed_file_parse` fuzzing
    /// (Argon2id is the per-iteration cost driver) without rejecting
    /// any legitimate user-chosen config.
    pub const SAFE_T_COST_MAX: u32 = 16;
    /// DoS guard: maximum lane count. Argon2id parallelism > about 16 has
    /// diminishing returns; bounding limits CPU explosion from a
    /// hostile on-disk value.
    pub const SAFE_P_COST_MAX: u32 = 16;

    /// Returns true if these params fit in the safe envelope used by
    /// the on-disk parsers. Empty/zero params (used by slot kinds that
    /// don't run Argon2id, e.g. Fido2DerivedMvk) return false; callers
    /// should guard the check by kind.
    pub fn is_sane_for_disk(&self) -> bool {
        self.m_cost_kib >= 8
            && self.m_cost_kib <= Self::SAFE_M_COST_KIB_MAX
            && self.t_cost >= 1
            && self.t_cost <= Self::SAFE_T_COST_MAX
            && self.p_cost >= 1
            && self.p_cost <= Self::SAFE_P_COST_MAX
    }

    /// Conservative interactive default: 256 MiB memory, 3 iterations, 4 lanes.
    /// Targets about 500 ms on a modern x86_64 laptop. Re-tune at `create` time.
    pub const INTERACTIVE: Self = Self {
        m_cost_kib: 256 * 1024,
        t_cost: 3,
        p_cost: 4,
    };

    /// Moderate strength: 512 MiB memory, 4 iterations, 4 lanes.
    /// Targets about 1.5 s on a modern x86_64 laptop. Use when the keyslot
    /// won't be unlocked frequently.
    pub const MODERATE: Self = Self {
        m_cost_kib: 512 * 1024,
        t_cost: 4,
        p_cost: 4,
    };

    /// Sensitive strength: 1 GiB memory, 5 iterations, 4 lanes.
    /// Targets about 3-4 s on a modern x86_64 laptop. For long-term archival
    /// or backup keyslots that expect rare unlock.
    pub const SENSITIVE: Self = Self {
        m_cost_kib: 1024 * 1024,
        t_cost: 5,
        p_cost: 4,
    };

    /// Tiny params for unit tests only, never use in production.
    #[cfg(test)]
    pub const TEST_ONLY: Self = Self {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };
}

/// Stretch a passphrase + salt to a 32-byte KEK.
pub fn derive_kek(
    passphrase: &[u8],
    salt: &[u8],
    params: Argon2idParams,
) -> Result<KeyEncryptionKey, Error> {
    let p = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|_| Error::Kdf)?;
    // Number of 1 KiB scratch blocks Argon2id needs for these params. Capture
    // it before `p` is moved into `Argon2::new`.
    let block_count = p.block_count();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    // `Zeroizing<[u8; KEY_LEN]>` so the finished KEK is wiped on drop. The
    // array is `Copy`, so `KeyEncryptionKey::from_zeroizing` reads it without
    // moving it out; the local copy is then scrubbed when `out` drops -
    // including panic / early-return paths. Matches the hybrid KEK paths
    // below, which already wrap their output for the same reason.
    let mut out = Zeroizing::new([0u8; KEY_LEN]);

    // Allocate Argon2id's working memory ourselves with a *fallible*
    // reservation instead of letting `hash_password_into` allocate it via an
    // infallible `Vec`. On a memory-starved host (small VM, a container with a
    // tight cgroup memory limit, or a QubesOS AppVM that hasn't been granted
    // enough RAM) the infallible path hits the global allocator's
    // `handle_alloc_error`, which *aborts the whole process* - the user sees a
    // bare "memory allocation of N bytes failed / Aborted" and loses the
    // session. `try_reserve_exact` lets us turn that into a clean, actionable
    // error the CLI/GUI can render and recover from.
    let mut memory: Vec<Block> = Vec::new();
    memory.try_reserve_exact(block_count).map_err(|_| {
        let needed_kib = block_count as u32; // 1 block == 1 KiB
        Error::KdfOutOfMemory {
            needed_kib,
            needed_mib: needed_kib / 1024,
        }
    })?;
    memory.resize(block_count, Block::new());

    let result =
        argon2.hash_password_into_with_memory(passphrase, salt, out.as_mut_slice(), &mut memory);

    // Scrub Argon2id's working memory before it is freed: those blocks hold
    // password-derived intermediate state. The argon2 crate never wipes this
    // buffer (`Block` is `#[derive(Copy)]`, so it has no `Drop`), and the old
    // internal-`Vec` path dropped it in the clear. Now that we own the buffer
    // we zeroize it on both the success and error paths - a strict improvement
    // over the previous behaviour, not a regression.
    for blk in memory.iter_mut() {
        blk.zeroize();
    }

    result.map_err(|_| Error::Kdf)?;
    Ok(KeyEncryptionKey::from_zeroizing(&out))
}

/// Combine a passphrase with a 32-byte FIDO2 hmac-secret output before stretching.
/// Domain-separated so a leaked hmac-secret output can't be replayed as a passphrase.
///
/// **Defence-in-depth on the unprefixed delimiter:** the input layout is
/// `b"lbx:fido" || passphrase || 0xff || hmac_secret`. The `0xff` byte is
/// not a valid UTF-8 byte sequence, so for valid UTF-8 passphrases (every
/// production caller - CLI prompt, GUI text input, env var) two distinct
/// `(passphrase, hmac_secret)` pairs cannot produce identical KDF input.
/// The `&[u8]` API surface still accepts arbitrary bytes, however, so a
/// future caller passing binary keying material directly could in
/// principle craft a colliding pair. We refuse such inputs explicitly
/// rather than rely on every call site staying disciplined: this closes
/// the audit Finding 2 hole at the API boundary without needing a
/// length-prefixed re-derivation (which would be on-disk-format-breaking).
pub fn derive_kek_with_fido2(
    passphrase: &[u8],
    hmac_secret: &[u8; 32],
    salt: &[u8],
    params: Argon2idParams,
) -> Result<KeyEncryptionKey, Error> {
    if passphrase.contains(&0xffu8) {
        return Err(Error::InvalidField);
    }
    // `Zeroizing<Vec<u8>>` so the heap bytes are wiped on drop even
    // if Argon2id panics partway. `fill(0)` after use was the prior
    // mitigation; wrapping is defense-in-depth (covers panic / early
    // return paths the manual fill would miss).
    let mut input = Zeroizing::new(Vec::<u8>::with_capacity(8 + passphrase.len() + 1 + 32));
    input.extend_from_slice(b"lbx:fido");
    input.extend_from_slice(passphrase);
    input.push(0xff);
    input.extend_from_slice(hmac_secret);
    derive_kek(&input, salt, params)
}

/// Hybrid FIDO2 KEK: combines the FIDO2-flavoured Argon2id output
/// (Argon2id over `b"lbx:fido" || passphrase || 0xff || hmac_secret`) with
/// a PQ-KEM shared secret via HKDF-SHA256. Domain-separated under
/// `b"lbx:hybrid-fido-kek/v1"` so it can't be confused with either the
/// passphrase-only hybrid or a non-hybrid FIDO2 wrap.
pub fn derive_hybrid_fido2_kek(
    passphrase: &[u8],
    hmac_secret: &[u8; 32],
    pq_shared: &[u8; 32],
    salt: &[u8],
    params: Argon2idParams,
) -> Result<KeyEncryptionKey, Error> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let classical = derive_kek_with_fido2(passphrase, hmac_secret, salt, params)?;
    // `Zeroizing<[u8; 64]>` so the IKM (classical KEK || pq_shared)
    // is wiped on drop including panic / early-return paths. Manual
    // .zeroize() at end of scope was prior mitigation; wrapping is
    // defense-in-depth.
    let mut ikm = Zeroizing::new([0u8; KEY_LEN * 2]);
    ikm[..KEY_LEN].copy_from_slice(classical.as_bytes());
    ikm[KEY_LEN..].copy_from_slice(pq_shared);
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm.as_ref());
    // Wrap the HKDF output buffer too: KeyEncryptionKey::from_bytes
    // takes the array by value, but `[u8; N]` is Copy so the local
    // `out` retains the KEK bytes after the move. Without `Zeroizing`,
    // those bytes sit on the stack frame until reused.
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(b"lbx:hybrid-fido-kek/v1", out.as_mut_slice())
        .map_err(|_| Error::Kdf)?;
    Ok(KeyEncryptionKey::from_zeroizing(&out))
}

/// Hybrid KEK = HKDF-SHA256 over (Argon2id-stretched passphrase ||
/// PQ-KEM shared secret). Domain-separated under
/// `info = b"lbx:hybrid-kek/v1"` so a future reuse of the same Argon2id
/// output in some other context can't be conflated with this one.
///
/// The Argon2id output is computed as in `derive_kek`. The HKDF salt is
/// the existing per-slot `kdf_salt` (already random per slot). The
/// resulting KEK has the same `KeyEncryptionKey` shape so the existing
/// `wrap_mvk` / `unwrap_mvk` paths work unchanged.
pub fn derive_hybrid_kek(
    passphrase: &[u8],
    pq_shared: &[u8; 32],
    salt: &[u8],
    params: Argon2idParams,
) -> Result<KeyEncryptionKey, Error> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    // Step 1: stretch the passphrase the normal way.
    let classical = derive_kek(passphrase, salt, params)?;
    // Step 2: HKDF over (classical || pq_shared) with the same salt.
    // `Zeroizing<[u8; 64]>` wipes IKM on drop including panic paths;
    // prior code used a manual .zeroize() at end of scope, which
    // misses early returns (e.g. hkdf.expand panic).
    let mut ikm = Zeroizing::new([0u8; KEY_LEN * 2]);
    ikm[..KEY_LEN].copy_from_slice(classical.as_bytes());
    ikm[KEY_LEN..].copy_from_slice(pq_shared);
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm.as_ref());
    // See `derive_hybrid_fido2_kek` for the rationale on wrapping the
    // HKDF output buffer.
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(b"lbx:hybrid-kek/v1", out.as_mut_slice())
        .map_err(|_| Error::Kdf)?;
    Ok(KeyEncryptionKey::from_zeroizing(&out))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guard against the unprefixed-delimiter ambiguity in
    /// `derive_kek_with_fido2`: a passphrase containing 0xff would
    /// collide with `passphrase' = passphrase[..i] || hmac_secret_prefix`
    /// for some choice of i. UTF-8 input cannot contain 0xff, so this
    /// only triggers when the API is misused with raw binary input.
    #[test]
    fn fido2_kdf_rejects_passphrase_with_ff_delimiter() {
        let salt = [0u8; 32];
        let hmac = [0u8; 32];
        // Valid UTF-8 passphrases work.
        assert!(derive_kek_with_fido2(b"hunter2", &hmac, &salt, Argon2idParams::TEST_ONLY).is_ok());
        assert!(
            derive_kek_with_fido2(
                "café résumé".as_bytes(),
                &hmac,
                &salt,
                Argon2idParams::TEST_ONLY,
            )
            .is_ok(),
            "valid UTF-8 with multi-byte chars must be accepted"
        );
        // 0xff in the passphrase is rejected (not a valid UTF-8 byte).
        assert!(matches!(
            derive_kek_with_fido2(
                b"contains\xffdelimiter",
                &hmac,
                &salt,
                Argon2idParams::TEST_ONLY,
            ),
            Err(Error::InvalidField)
        ));
        // Empty passphrase is allowed (FIDO2-only mode).
        assert!(derive_kek_with_fido2(b"", &hmac, &salt, Argon2idParams::TEST_ONLY).is_ok());
    }

    /// The hybrid-fido KDF inherits the guard via its inner call to
    /// `derive_kek_with_fido2`. Pin this so a future refactor can't
    /// accidentally bypass it on the hybrid path.
    #[test]
    fn hybrid_fido_kdf_inherits_ff_guard() {
        let salt = [0u8; 32];
        let hmac = [0u8; 32];
        let pq = [0u8; 32];
        assert!(matches!(
            derive_hybrid_fido2_kek(b"\xff", &hmac, &pq, &salt, Argon2idParams::TEST_ONLY,),
            Err(Error::InvalidField)
        ));
    }

    /// `derive_kek` switched from the argon2 crate's internal `Vec<Block>`
    /// allocation to a caller-owned, fallibly-reserved buffer that we zeroize
    /// after use. The output must stay deterministic and identical across
    /// calls; if the buffer were mis-sized, fed in the wrong order, or scrubbed
    /// before `finalize` read it, the bytes would change and every existing
    /// vault would fail to unlock. Pin the round-trip stability here.
    #[test]
    fn derive_kek_is_deterministic_over_owned_buffer() {
        let salt = [7u8; 32];
        let a = derive_kek(b"correct horse", &salt, Argon2idParams::TEST_ONLY).unwrap();
        let b = derive_kek(b"correct horse", &salt, Argon2idParams::TEST_ONLY).unwrap();
        assert_eq!(
            a.as_bytes(),
            b.as_bytes(),
            "same passphrase+salt+params must yield identical KEK bytes"
        );
        // A different passphrase must diverge (sanity: we're not returning a
        // zeroed/constant buffer).
        let c = derive_kek(b"correct hose", &salt, Argon2idParams::TEST_ONLY).unwrap();
        assert_ne!(a.as_bytes(), c.as_bytes());
        assert_ne!(a.as_bytes(), &[0u8; KEY_LEN]);
    }

    /// Larger-than-test params still derive successfully through the owned
    /// buffer path (exercises a realistic multi-MiB `block_count`, not just
    /// the 8 KiB `TEST_ONLY` floor). Kept modest so the suite stays fast.
    #[test]
    fn derive_kek_owned_buffer_handles_realistic_block_count() {
        let salt = [3u8; 32];
        let params = Argon2idParams {
            m_cost_kib: 4 * 1024, // 4 MiB: many blocks, still quick
            t_cost: 2,
            p_cost: 2,
        };
        let k = derive_kek(b"vault passphrase", &salt, params).unwrap();
        assert_ne!(k.as_bytes(), &[0u8; KEY_LEN]);
    }
}
