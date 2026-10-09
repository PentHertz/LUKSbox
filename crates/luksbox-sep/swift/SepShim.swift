// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)
//
// CryptoKit Secure Enclave shim with a flat C ABI, linked into
// `luksbox-sep` by build.rs on `all(feature = "hardware",
// target_os = "macos")`. No Swift types cross the boundary; the Rust
// side (src/real.rs) is plain `extern "C"`.
//
// Design model (docs/SEP_KEYSLOT_DESIGN.md §2): derive, don't wrap.
// A per-slot SEP-resident P-256 key + a host-side ephemeral key
// produce an ECDH shared secret. We hand the raw 32-byte shared
// secret back to Rust, which feeds it through the SAME HKDF-with-
// header_salt path the TPM keyslots use. The SEP private half never
// leaves the enclave; we persist only its opaque `dataRepresentation`
// (-> the .lbx.sep sidecar) and the ephemeral PUBLIC key.

import Foundation
import CryptoKit
import LocalAuthentication

// Status codes shared with src/real.rs.
private let OK: Int32 = 0
private let ERR_UNAVAILABLE: Int32 = -1
private let ERR_SEAL: Int32 = -2
private let ERR_BUFFER: Int32 = -3
private let ERR_UNSEAL: Int32 = -4


/// R15-F4: copy exactly 32 bytes of a CryptoKit `SharedSecret` into a
/// caller-owned buffer without materialising a `Data` copy (which is not
/// scrubbed on deallocation, unlike CryptoKit's own SecureBytes).
/// Returns false if the secret is not 32 bytes long.
private func copySharedSecret(_ shared: SharedSecret, to out: UnsafeMutablePointer<UInt8>) -> Bool {
    return shared.withUnsafeBytes { (buf: UnsafeRawBufferPointer) -> Bool in
        guard buf.count == 32, let base = buf.baseAddress else { return false }
        UnsafeMutableRawPointer(out).copyMemory(from: base, byteCount: 32)
        return true
    }
}

@_cdecl("luksbox_sep_available")
public func luksbox_sep_available() -> Int32 {
    return SecureEnclave.isAvailable ? 1 : 0
}

/// Generate a fresh SEP key, ECDH against a throwaway ephemeral key,
/// and return: the 32-byte shared secret, the SEP key's persistable
/// `dataRepresentation`, and the ephemeral PUBLIC key (x963, 65 B).
///
/// `biometric != 0` gates the SEP key behind user presence; note the
/// resulting blob is larger (~427 B) and unseal will require a Touch
/// ID / passcode prompt from a GUI-bundled process (phase 2).
@_cdecl("luksbox_sep_seal")
public func luksbox_sep_seal(
    _ biometric: Int32,
    _ outShared: UnsafeMutablePointer<UInt8>,       // 32 B
    _ outSepData: UnsafeMutablePointer<UInt8>,
    _ outSepDataCap: Int,
    _ outSepDataLen: UnsafeMutablePointer<Int>,
    _ outEphPub: UnsafeMutablePointer<UInt8>         // 65 B
) -> Int32 {
    guard SecureEnclave.isAvailable else { return ERR_UNAVAILABLE }
    do {
        let sepKey: SecureEnclave.P256.KeyAgreement.PrivateKey
        if biometric != 0 {
            var cfErr: Unmanaged<CFError>?
            guard let ac = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage, .userPresence],
                &cfErr) else { return ERR_SEAL }
            sepKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: ac)
        } else {
            sepKey = try SecureEnclave.P256.KeyAgreement.PrivateKey()
        }
        let eph = P256.KeyAgreement.PrivateKey()
        let shared = try eph.sharedSecretFromKeyAgreement(with: sepKey.publicKey)
        let sepData = sepKey.dataRepresentation
        let ephPub = eph.publicKey.x963Representation

        guard ephPub.count == 65 else { return ERR_SEAL }
        guard sepData.count <= outSepDataCap else { return ERR_BUFFER }

        // R15-F4: copy the shared secret straight out of CryptoKit's
        // scrubbed SecureBytes into the caller's buffer. Going through a
        // Foundation `Data` left an unscrubbed heap copy of the ECDH
        // secret behind until the allocator happened to reuse it.
        guard copySharedSecret(shared, to: outShared) else { return ERR_SEAL }
        sepData.copyBytes(to: outSepData, count: sepData.count)
        outSepDataLen.pointee = sepData.count
        ephPub.copyBytes(to: outEphPub, count: 65)
        return OK
    } catch {
        return ERR_SEAL
    }
}

/// Reconstitute the SEP key from `dataRepresentation` (succeeds only on
/// the originating enclave) and re-derive the same 32-byte shared
/// secret via ECDH against the stored ephemeral public key.
@_cdecl("luksbox_sep_unseal")
public func luksbox_sep_unseal(
    _ biometric: Int32,
    _ sepData: UnsafePointer<UInt8>,
    _ sepDataLen: Int,
    _ ephPub: UnsafePointer<UInt8>,                  // 65 B
    _ outShared: UnsafeMutablePointer<UInt8>         // 32 B
) -> Int32 {
    do {
        let sepDataD = Data(bytes: sepData, count: sepDataLen)
        let key: SecureEnclave.P256.KeyAgreement.PrivateKey
        if biometric != 0 {
            let ctx = LAContext()
            ctx.localizedReason = "Unlock LUKSbox vault keyslot"
            key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: sepDataD, authenticationContext: ctx)
        } else {
            key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: sepDataD)
        }
        let ephPubD = Data(bytes: ephPub, count: 65)
        let ephPubKey = try P256.KeyAgreement.PublicKey(x963Representation: ephPubD)
        let shared = try key.sharedSecretFromKeyAgreement(with: ephPubKey)
        // R15-F4: see the seal path, no `Data` intermediate.
        guard copySharedSecret(shared, to: outShared) else { return ERR_UNSEAL }
        return OK
    } catch {
        return ERR_UNSEAL
    }
}
