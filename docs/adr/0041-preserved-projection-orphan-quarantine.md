# ADR-0041: Preserve unowned final projection stages for audit

- Status: Accepted
- Date: 2026-07-22

## Context

Projection preparation owns a final manifest/config stage only while the
process retains the inode capability returned by its writer, or while a valid
durable projection intent names the stage's exact size and SHA-256. After a
restart with no owning intent, a scanner sees only a predictable final
pathname. It cannot distinguish an interrupted writer's inode from a file that
replaced that inode before recovery began. Rebinding the current pathname and
deleting it would turn a byte digest or naming convention into deletion
authority; even a same-byte replacement may belong to another actor.

Random write, install-isolation, and removal-quarantine names are different:
their 128-bit nonce is a private temporary namespace capability, and their
strict grammar identifies state that can never be a canonical final stage.

## Decision

- Asset final stages are exactly
  `asset-projection-stage-<32 lowercase hex>.tsv` or
  `asset-projection-stage-<32 lowercase hex>-config.yaml`.
- Package final stages are exactly
  `package-projection-stage-<32 lowercase hex>-config.yaml` or a canonical
  `%03d`-formatted manifest index (three or more decimal digits without a
  non-canonical leading zero).
- A final stage named by the current validated intent remains live recovery
  input and is never treated as residue.
- A final stage with no owning intent is bound as a private regular inode and
  moved with a native no-replace rename to
  `<final>.preserved-<32 lowercase hex>`. It is not deleted. The first
  `--recover` reports the exact preserved name and fails closed; a subsequent
  `--recover` ignores only that strict audit-quarantine form and can continue.
- Strict random write, install-isolation, and removal-quarantine names retain
  their existing exact-inode cleanup behavior. Any other name beginning with a
  projection stage or intent prefix is unsafe and blocks recovery unchanged.

This decision supersedes only the "delete an exact orphan final stage" row in
the V-75 implementation spec. Descriptor-bound deletion of writer-owned
temporaries, and exact post-commit cleanup backed by a still-valid intent,
remain unchanged.

## Consequences

- Recovery cannot delete a replacement that was already present before the
  scanner acquired an inode descriptor.
- An interrupted final stage costs disk space until an operator inspects and
  explicitly retires its preserved audit copy. Ordinary recovery remains
  deterministic: one call quarantines and reports; the next call proceeds.
- Malformed, legacy deterministic, or test-only suffixes are visible failures
  instead of silently ignored files or overly broad package-prefix deletions.
- `fsck`/GC enumeration and explicit retirement of preserved projection audit
  quarantines remains a separate operational feature; recovery itself never
  converts that future policy into implicit deletion.

## Evidence

See [the implementation report](../evidence/2026-07-22-projection-stage-install-rollback-identity.md),
`internal/cli/projection_intent_remove.go`,
`internal/cli/projection_intent_removal_test.go`, and V-77 in the
[requirements ledger](../requirements-traceability.md).
