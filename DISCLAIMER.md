# Disclaimer

LUKSbox is open-source software provided **AS IS**, with no warranty
of any kind, under the [Apache License 2.0](LICENSE) (sections 7
and 8 in particular). This page restates the parts that matter most
for users of cryptographic data-protection software, in plain
English.

## You assume all risk

By using LUKSbox you accept that:

- **Cryptography can lose data.** A LUKSbox vault is encrypted; if
  you lose every keyslot, every header backup, and the unencrypted
  copy you kept, the data is mathematically unrecoverable. No
  backdoor exists. The Penthertz team **cannot recover your
  vault**, even if you ask.

- The software is provided **with no warranty** of merchantability,
  fitness for a particular purpose, non-infringement, or accuracy
  (LICENSE section 7).

- The authors and contributors are **not liable** for any damages
  arising from your use of LUKSbox, including direct, indirect,
  incidental, consequential, or punitive damages, even if advised
  of the possibility (LICENSE section 8).

- LUKSbox is currently **pre-1.0**. The on-disk format is locked,
  the cryptographic primitives are NIST / RFC standards built on
  RustCrypto, and internal audit rounds are documented publicly,
  but a paid third-party audit has not yet been performed. See the
  [Status](README.md#status) section of the README and the
  [audit history](https://luksbox.penthertz.com/docs/security/audit/)
  for the current state.

## What protects your data

LUKSbox does not protect data on its own; **you** do. Reliable
protection requires:

1. A **strong passphrase** (or a hardware key) you can recover.
   Use a password manager. Use the `sensitive` Argon2id preset for
   long-lived vaults.

2. **At least one backup keyslot** in advance: a second FIDO2
   device, a backup passphrase printed on paper kept in a safe,
   anything that means losing one factor does not lose the vault.
   See [Recovery](https://luksbox.penthertz.com/docs/operations/recovery/).

3. A **header backup** on separate media. Run
   `luksbox header-backup` after every `enroll` / `revoke` /
   `rotate-mvk`. See
   [Forensics](https://luksbox.penthertz.com/docs/operations/forensics/).

4. **An unencrypted copy of irreplaceable files** somewhere you
   trust. A LUKSbox vault is the *travelling* copy (cloud, USB,
   shared drive); not the *master* copy.

5. **Realistic threat-model awareness.** LUKSbox protects data
   *at rest*. It cannot protect data on a compromised host once
   the vault is unlocked. See the
   [threat model](https://luksbox.penthertz.com/docs/security/threat-model/).

## Export controls

LUKSbox uses strong cryptography (AES-256, ChaCha20-Poly1305,
Argon2id, ML-KEM-768 / 1024). The source code is published from
France under the Apache License 2.0 and is freely available
online; on that basis it qualifies for the "publicly available"
exception of EU Dual-Use Regulation (EU) 2021/821 (Annex I,
General Note 4) and equivalent provisions in other jurisdictions.

**You are responsible** for verifying that downloading, using, or
redistributing LUKSbox is lawful where you are, in particular
under any sanctions regime you may be subject to. The Penthertz
team makes no representation that LUKSbox can lawfully be imported
into, exported from, or used in any specific country.

## Trademarks

"LUKSbox" and the Penthertz name and logo are trademarks. The
Apache License does **not** grant trademark rights. You can fork,
modify, and redistribute the source code freely; you cannot call
your fork "LUKSbox" or use the Penthertz logo without permission.
See [TRADEMARK.md](TRADEMARK.md) for the full policy.

## Reporting vulnerabilities

See [SECURITY.md](SECURITY.md) for the coordinated-disclosure
policy, response SLA, and PGP key. Please do not open public
GitHub issues for security-relevant findings.
