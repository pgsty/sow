# ADR-0044: Capability-bound retirement of preserved projection audits

- Status: Accepted
- Date: 2026-07-28

## Context

ADR-0041 deliberately refuses to delete an unowned final asset/package
projection stage after restart. Recovery moves the descriptor-bound inode to a
strict `.preserved-<32 lowercase hex>` coordinate and ignores that audit form
on later recovery. This prevents a pathname or matching digest from becoming
deletion authority, but leaves the operator with no supported inventory or
retirement path.

Manual `rm` is not an acceptable product workflow: it bypasses admission,
identity, durability and reproducible audit output. Folding these copies into
ordinary `--recover` or CAS GC would also destroy the safety distinction that
ADR-0041 established.

## Decision

- `verify` L1 and local `fsck` stream the `.sow` directory and recognize only
  the exact asset/package final-stage grammar followed by
  `.preserved-<32 lowercase hex>`.
- Inventory admits the state root and each file under ADR-0043, binds a
  no-follow/nonblocking descriptor, hashes with a 256 KiB buffer, and rechecks
  descriptor/path/root identity. It retains at most 1,024 records and fails
  closed on malformed related names, unsafe objects or excess cardinality.
- Every valid copy is critical integrity drift and includes kind, name, size,
  SHA-256 and a retirement token. The token is SHA-256 over a domain-separated
  canonical tuple containing kind, name, size, content SHA-256, full mode,
  device/inode, mtime, UID/GID and link count.
- Retirement is exactly:

  ```text
  sow fsck --retire-preserved-projection NAME --confirm TOKEN
  ```

  It is local-only, one-at-a-time, and mutually exclusive with `--recover`,
  remote targets, inventory adoption, purge-ledger repair and repo/OS/arch
  selectors.
- The retirement path rebinds and rehashes the current object, recomputes the
  token, and keeps that descriptor open through a no-replace quarantine,
  repeated identity/byte checks, unlink and parent fsync. A stale token,
  replacement, extra hardlink, mode/owner drift or reoccupied coordinate
  preserves evidence and returns conflict.
- Replaying an exact syntactically valid name/token after the coordinate is
  absent performs no mutation and reports `already_absent=true`. This is safe
  response-loss recovery, not proof that an arbitrary absent object once
  existed.
- Ordinary `fsck`, `verify`, `--recover` and `gc` never retire these copies.

## Consequences

- Operators get a supported inspection/deletion workflow without weakening
  recovery safety or turning a content checksum into ambient deletion power.
- A replacement with identical bytes still needs a fresh token because device
  and inode are bound. A same inode with changed metadata or bytes also needs a
  fresh token and must pass live admission.
- Bulk deletion is intentionally absent. Requiring one explicit name/token
  keeps each irreversible action independently reviewable and safely
  replayable.
- Inventory cost is streaming in bytes and bounded in record memory. A
  repository with more than 1,024 preserved audit copies requires manual
  forensic reduction outside SOW before mutation can resume.

## Evidence

See `internal/cli/projection_audit_quarantine.go`,
`internal/cli/projection_audit_quarantine_test.go`,
[the implementation report](../evidence/2026-07-28-preserved-projection-audit-retirement.md),
and V-83 in the [requirements ledger](../requirements-traceability.md).
