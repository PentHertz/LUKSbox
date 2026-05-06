# Hardware side-channel notes for FIDO2 authenticators

> **Companion to [`SECURITY.md`](../SECURITY.md) and [`docs/CRYPTO_SPEC.md`](CRYPTO_SPEC.md).**
> This document catalogues publicly-known side-channel attacks against
> the secure-element silicon used in FIDO2 hardware keys, what
> mitigates each, and how it interacts with LUKSbox's threat model.
>
> **TL;DR**: LUKSbox explicitly delegates secure-element security to
> the device vendor (see CRYPTO_SPEC.md Section 19.5). Every attack
> documented here requires physical possession of the device for
> minutes to hours, plus EM measurement equipment and significant
> expertise. None can be performed remotely or without losing custody
> of the device. Both Yubico and Google have shipped firmware /
> hardware updates that mitigate the published attacks. The
> recommendation remains: a hardware key is meaningfully better than
> no hardware key, and a CURRENT-GENERATION hardware key is
> meaningfully better than a 2018-vintage one.

---

## 1. NinjaLab "A Side Journey to Titan" (2021)

**Paper**: https://ninjalab.io/wp-content/uploads/2022/05/a_side_journey_to_titan.pdf
**Project page**: https://ninjalab.io/a-side-journey-to-titan/

### What was attacked

| Aspect | Detail |
|---|---|
| Devices | Google Titan Security Key (all generations available in 2021), several Feitian models, NXP J3D081 reference platform |
| Silicon | NXP P5 / SmartMX family, including the NXP A700X used in first-generation Titan |
| Cryptographic primitive | ECDSA over P-256 (the FIDO U2F / CTAP2 signature) |

### How

- Capture **electromagnetic radiation** during ECDSA signature generation using EM probes near the chip surface.
- Apply machine-learning + lattice-based cryptanalysis to recover bits of the per-signature ephemeral key (`k`).
- Combine 4,000-6,000 leak measurements (4k on the NXP J3D081 reference, 6k on Titan) to recover the long-term ECDSA private key.

### Practical cost

| Resource | Estimate |
|---|---|
| Physical access to the device | continuous, 10 hours per device |
| Equipment | EM probe + oscilloscope (~$10k of lab equipment, plus expertise) |
| Software | Custom analysis stack (NinjaLab's own; not public) |
| Skill ceiling | "PhD-level side-channel cryptanalysis" |

### Outcome

Long-term ECDSA private key for ONE specific FIDO U2F account on the
device. The attacker can then **clone the device** for that account
indefinitely. Other accounts on the same device require their own
extraction.

### What mitigates it

- **NXP P60 / SmartMX2** and **NXP P70 / SmartMX3** silicon are
  unaffected. Devices using these chips are not vulnerable to this
  specific attack.
- Modern Yubico devices (Infineon-based, NOT NXP) were unaffected by
  this attack at publication time. Note: this comment from 2021
  was overtaken by EUCLEAK (2024); see Section 2.
- Google Titan v2 (USB-C Feitian-manufactured) uses different silicon
  from the original USB-A Titan. Vulnerability status against this
  specific attack is not publicly confirmed; assume the worst until
  the vendor states otherwise.

### Vendor response

Google did not recall affected Titans. Newer Titan generations ship
with newer silicon. Field-deployed first-generation Titans (sold
2018-2021) remain vulnerable per the paper's published methodology.

---

## 2. NinjaLab EUCLEAK (2024)

**Project page**: https://ninjalab.io/eucleak/
**Plain-English writeup**: https://www.zach.be/p/the-most-secure-chip-in-the-world

### What was attacked

| Aspect | Detail |
|---|---|
| Devices | All YubiKey 5 Series with firmware < 5.7.0 (sold 2017-May 2024) |
| Silicon | Infineon SLE78 secure element, with Infineon's cryptographic library |
| Cryptographic primitive | ECDSA, specifically the Extended Euclidean Algorithm (EEA) used for modular inversion |

### How

- The Infineon library's modular-inversion routine is **not constant-time**.
- Infineon attempted to mask it with **32-bit blinding** of the input, but a 32-bit space is brute-forceable.
- Capture EM emanations during a few ECDSA signatures; brute-force the 32-bit blinding mask; recover the nonce; derive the private key.

### Practical cost

| Resource | Estimate |
|---|---|
| Physical access | "few minutes" of EM acquisition (orders of magnitude less than the Titan attack) |
| Equipment | EM probe + oscilloscope, "expensive equipment" per the paper - not specified in dollars but lab-grade |
| Software | Custom analysis stack |
| Skill ceiling | High, but the technique is now publicly described |

### Outcome

ECDSA private key extraction. Enables **device cloning** for any
FIDO credential that uses ECDSA on the affected device.

### Affected beyond YubiKey

The same Infineon library ships in **every Infineon TPM in active
deployment**, plus Infineon-based smart cards in:
- Some electronic passports
- Some cryptocurrency hardware wallets
- Some smart-vehicle key fobs / immobilisers
- Some home automation systems

### What mitigates it

- **YubiKey firmware 5.7.0** (released 2024-05-06). Yubico replaced
  Infineon's crypto library with their own implementation. **Not a
  field-flashable update**: YubiKey firmware is one-time-programmable,
  so mitigation requires buying a new device manufactured 2024-05 or
  later.
- **Yubico released a security advisory** (YSA-2024-03) listing
  affected serial number ranges. Devices with serials issued after
  May 2024 ship with firmware >= 5.7.
- **Infineon developed a library patch**, but as of the EUCLEAK
  publication that patch had not completed Common Criteria
  re-certification.

### What the 14-year persistence tells us

The EUCLEAK paper notes the vulnerable EEA implementation existed in
Infineon's library for 14 years across 80 Common Criteria
evaluations without being detected. The zach.be writeup argues this
challenges blind reliance on certifications: a CC certificate proves
that an evaluator looked at the implementation and didn't find a
problem; it doesn't prove there isn't one.

---

## 3. How this interacts with LUKSbox's threat model

LUKSbox's published threat model
([CRYPTO_SPEC.md Section 19.5](CRYPTO_SPEC.md), Sec.19.5 "What we delegate to the device vendor")
explicitly places "side-channel resistance during HMAC" and "supply
chain integrity" in the vendor's column. We do not claim and have
never claimed to defend against an attacker who can extract the
per-credential master from a device's secure element.

### What LUKSbox CAN'T do about these attacks

- Detect that a hardware key has been cloned. From the host's
  perspective, a cloned device behaves identically to the original.
- Detect that an attacker had physical custody of the device long
  enough to extract a secret. There's no host-observable signal.
- Mitigate the underlying silicon vulnerability. That requires
  firmware (Yubico) or new hardware (NXP/Titan).

### What LUKSbox DOES do that limits the damage

| Defense | Effect |
|---|---|
| **PIN counter on the device** | Even with the secret extracted, the attacker still needs the PIN. The device wipes after 8 wrong PIN attempts. |
| **Multi-keyslot vaults** | If you've enrolled multiple FIDO2 devices + a passphrase, a single compromised device doesn't open the vault unless the attacker also has the others / the passphrase. |
| **`luksbox revoke` + `luksbox rotate-mvk`** | If you suspect a device was compromised: revoke its slot, rotate the MVK. Previously-extracted material then unwraps to nothing useful. |
| **Hybrid-PQ FIDO2 keyslots** | The hmac-secret is one factor; the `.kyber` seed file (kept on separate trusted storage) is the other. A cloned FIDO2 device alone doesn't unlock a hybrid-PQ vault. |

### What you SHOULD do

| Situation | Action |
|---|---|
| Using a YubiKey 5 with firmware < 5.7.0 | Replace the device. Field flash isn't possible; check serial vs Yubico's YSA-2024-03 list. |
| Using an original USB-A Google Titan (sold 2018-2021) | Replace with a current-generation Titan or a YubiKey 5 firmware >= 5.7. |
| Using a Nitrokey, SoloKey, Token2, or other vendor | Check vendor's security advisories. Most use different silicon with different vulnerability profiles. |
| Storing very high-value secrets | Use TWO different vendor's devices in two different keyslots. Different silicon = different vulnerability profiles. |
| Lost a hardware key (might have been stolen, not just lost) | Treat as compromise: revoke + rotate-mvk, on the assumption the recipient has the resources to extract the secret over the following weeks. |

---

## 4. Per-vendor / per-generation status (as of 2026-05)

| Device | Silicon | Status |
|---|---|---|
| YubiKey 5 (firmware < 5.7.0) | Infineon SLE78 + Infineon crypto lib | **Vulnerable to EUCLEAK** |
| YubiKey 5 (firmware >= 5.7.0) | Infineon SLE78 + Yubico's own crypto | **Mitigated** (Yubico's library is constant-time) |
| YubiKey FIPS 5 | Same Infineon silicon, FIPS-validated firmware | Same EUCLEAK exposure as non-FIPS pre-5.7; FIPS firmware update timeline differs - check Yubico FIPS advisory |
| YubiKey Bio | Same Infineon silicon | Same vulnerability profile as YubiKey 5 with corresponding firmware |
| Google Titan v1 (USB-A, sold 2018-2021) | NXP A700X (P5/SmartMX) | **Vulnerable to "A Side Journey to Titan"** |
| Google Titan v2 (USB-C, Feitian-made) | Different silicon - publicly unconfirmed which exactly | Status unclear; assume partially-mitigated until Google states otherwise |
| Nitrokey 3 | NXP IFX with newer SmartMX2/3 | Not vulnerable to either documented attack |
| SoloKey 2 | NXP K22 (general-purpose MCU, not certified secure element) | Different vulnerability class - has had its own SCA findings; check vendor security advisories |
| Token2 PIN+ | Various | Check vendor advisory |
| OnlyKey | Microchip ATECC608 | Different vulnerability class - check vendor advisory |
| Trezor Safe 3 / 5 | EAL6+ secure element | Not specifically targeted by the cited research |
| Windows Hello platform authenticator | Platform-specific (TPM, IME, secure enclave) | TPMs that use Infineon are exposed via EUCLEAK; AMD fTPM and Intel PTT have separate research history |

---

## 5. Summary recommendations

1. **Replace pre-2024 YubiKeys** if your threat model includes
   adversaries who could plausibly steal-and-return your device.
   Yubico's serial-number lookup tells you whether you're on
   firmware >= 5.7.0.
2. **Replace original USB-A Titans** for the same reason, regardless
   of how long ago you bought them.
3. **Multi-vendor keyslot redundancy** is a defense against
   single-vendor cryptanalytic surprises. Enroll one YubiKey 5
   firmware >= 5.7 and one Nitrokey 3 (or vice versa) into the same
   vault.
4. **Hybrid-PQ FIDO2 keyslots** convert "compromised hardware key"
   into a non-event for vault confidentiality (attacker also needs
   the `.kyber` seed file).
5. **Revoke + rotate-mvk after device loss**. Even if you find the
   device a week later, treat it as compromised - revoke its slot,
   rotate the MVK. The Argon2id-protected passphrase keyslot you've
   also enrolled lets you do this.

These attacks are **public, documented, and important context** for
a defender choosing a hardware key. They are NOT an indictment of
hardware-backed authentication: as the EUCLEAK author writes, using
a YubiKey is "safer than not using one." LUKSbox's recommendation
remains: use a current-generation hardware key, enroll a backup
keyslot, rotate after suspected loss.

---

## 6. Sources

| Paper | Year | Authors | URL |
|---|---|---|---|
| A Side Journey to Titan | 2021 | NinjaLab (Thomas Roche) | https://ninjalab.io/a-side-journey-to-titan/ |
| EUCLEAK | 2024 | NinjaLab (Thomas Roche) | https://ninjalab.io/eucleak/ |
| The Most Secure Chip in the World Just Got Hacked | 2024 | Zach (zach.be) | https://www.zach.be/p/the-most-secure-chip-in-the-world |
| Yubico YSA-2024-03 | 2024 | Yubico | https://www.yubico.com/support/security-advisories/ysa-2024-03/ |

## 7. Update log

| Date | Change |
|---|---|
| 2026-05-04 | Initial document. Covers Titan 2021 + EUCLEAK 2024. Future additions: any new published silicon-level attacks on FIDO2 authenticators. |
