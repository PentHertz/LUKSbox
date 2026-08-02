# Rollback protection: current guarantee and candidate mitigation

This note records a design tradeoff confirmed by the v0.5.0-rc.3
ground-truth audit. It is a design record, not a shipped code change.
See `docs/SECURITY_ARCHITECTURE.md` sections 2 and the threat table for
the higher-level model this expands on.

## What is protected today

Every authenticated region of a vault is bound to the Master Volume Key
(MVK):

- The 8 KiB header is covered by an HMAC under an MVK-derived subkey and
  is verified right after a keyslot unlocks.
- The encrypted metadata region is authenticated with AEAD whose
  associated data is `header_salt || ct_len`.
- Each data chunk and each chunk-list block is authenticated with AEAD
  whose associated data binds `file_id || chunk_idx || generation`,
  under a per-file derived key.

The chunk-level generation binding defeats a single-chunk substitution
or replay: presenting an old ciphertext for one chunk fails the tag,
because the metadata that references it carries a newer generation.

The optional `.anchor` sidecar adds true rollback detection. It stores
the vault's current generation, authenticated under an MVK-derived key,
and `anchor::compare` refuses to mount when the on-disk generation is
older than the anchor. The anchor is only meaningful when it lives on
storage the attacker cannot roll back in lockstep with the vault (a
different disk, a hardware token, a remote record).

## The gap

The metadata region's AEAD associated data is `header_salt || ct_len`.
The MVK, `header_salt`, and the derived `metadata_key` are all constant
for the life of the vault, and the associated data carries no monotonic
generation or version counter. So an offline attacker who holds the
vault files can present an older, internally self-consistent snapshot of
the whole vault, or of just the metadata region, taken from an earlier
point in the same vault's life. It decrypts and authenticates cleanly,
because it was produced under the same key with valid tags.

Concretely, without an external anchor, an attacker with access to a
backup or a cloud copy can roll the vault back to a state before a file
was deleted, before a keyslot was revoked, or before a sensitive edit,
and nothing in the vault itself detects it. This is the residual
exposure the audit ranked highest, and it is the one behavior that is
"documented but not mitigated" in the default (no-anchor) configuration.

## Candidate mitigation

Bind a monotonic metadata generation counter into the metadata AEAD
associated data, so it becomes `header_salt || ct_len || meta_gen`,
where `meta_gen` increments on every metadata commit and is also stored
(authenticated) in the header.

Effect: an attacker who substitutes an older metadata region now
presents a `meta_gen` that disagrees with the header's current value,
and the check fails without any external state. This closes intra-vault
metadata rollback (the older-metadata-under-current-header case) even
when no anchor is configured.

Limits: it does not, on its own, close whole-vault rollback where the
attacker rolls the header and metadata back together to a consistent
earlier pair. Detecting that still requires trusted external state,
which is exactly what the anchor provides. So the counter is a strict
improvement for the no-anchor case, not a replacement for the anchor.

## Why it does not ship in rc.3

Changing the metadata associated data is an on-disk format change: old
vaults authenticate without `meta_gen`, new ones with it, so it needs a
format-version bump, a read path that accepts both, and a migration
story, consistent with the project's rule that every breaking format
change ships with a migration tool. That is a larger change than a
release-candidate hardening pass should carry silently. The decision on
whether it lands in the v0.5.0 line or a later minor is deferred; this
note exists so the tradeoff is on record and the mitigation is
pre-designed when that decision is made.

## Operational guidance until then

For threat models that include rollback (untrusted backup or cloud
storage, an adversary who can present old snapshots), enable the
`.anchor` sidecar and keep it on storage separate from the vault. That
is the supported, shipping mitigation today.
