# ADR-0043: POSIX-DAC admission for derived control state

- Status: Accepted
- Date: 2026-07-28

## Context

V-80 and V-81 bind derived-state pathnames to descriptors, inodes and exact
bytes. Those protocols detect coordinate replacement, but they previously
admitted directories writable by another local principal and regular control
files with more than one hardlink. A different UID could therefore retain a
writable alias to an admitted inode, or replace a child through an unsafe
ancestor, after the last byte/inode proof.

The PRD assumes one operator and one workstation. This decision is
defense-in-depth for a different local principal constrained by ordinary POSIX
DAC; it does not turn SOW into a shared multi-writer authorization system.

## Decision

- The process effective UID is the local control-state trust anchor on Linux
  and macOS. The repository directory that immediately contains `.sow`, the
  `.sow` root, and every derived control directory must:

  - be a real directory rather than a symlink;
  - be owned by the effective UID;
  - have no group/other write bit; and
  - retain exact UID, GID and full mode across descriptor/path checks.

- Directory link count remains part of the existing mutation token but is not
  required to equal one. Child-directory creation legitimately changes it,
  and Linux and APFS expose different directory-link behavior.
- A mutable control file must additionally be a real regular file with link
  count exactly one. UID, GID, mode and link count are rechecked on the held
  descriptor and current pathname at bind, bounded read/hash, rename/exchange,
  replay, quarantine and final removal boundaries.
- Unsafe pre-existing or raced-in evidence is never chmodded, chowned or
  unlinked automatically. The operation fails closed. Once an external alias
  or unsafe mode is removed by the operator, ordinary `--recover` replay may
  re-admit the unchanged safe inode.
- Intent schema v1 remains unchanged. Existing V-81 carriers are compatible:
  recovery parses the same durable body, then applies current live owner,
  mode and single-link admission before acting.
- State-lock publication can no longer use a create-only hardlink because that
  protocol temporarily violates the single-link invariant itself. Linux
  `RENAME_NOREPLACE` and Darwin `RENAME_EXCL` publish the fully fsynced private
  inode without an alias, followed by an exact lock-directory fsync before the
  published hook or success. Stale-record preservation uses the same
  no-replace rename and durability barrier.
- `state.lease`, `state.lock`, replacement intents/carriers, writer
  temporaries, projection intents/control stages/residues and bounded
  materialization journals use the strict control-file policy.
- The policy deliberately does not apply to `.pool`, serving trees,
  materialized package payloads, compatibility trust routes, or offline
  archive payload stages. Those objects intentionally use hardlinks.
- SOW remains CGO-free and uses no `lsof`, `/proc` enumeration, ACL command or
  other external runtime helper.

## Security boundary and non-claims

`nlink == 1` proves that no other directory entry currently names the inode. It
cannot detect a writer of the same UID that opened the file before unlinking
its alias. Root, `CAP_DAC_OVERRIDE` or equivalent privilege, kernel mutation,
bind mounts, macOS/NFSv4 extended ACL grants, unreliable network/FUSE UID or
link-count mappings, and a same-UID pre-held writable descriptor remain in the
trusted computing base or outside this guarantee.

Accordingly, the closed claim is: a different local UID, constrained by
reliable POSIX ownership/mode/link semantics and without a pre-held descriptor,
cannot retain a pathname alias or writable admitted directory through SOW's
derived-state transaction. Deployments using extended ACLs or non-local
filesystems must independently ensure they do not grant additional write
authority.

## Consequences

- A repository whose immediate directory or existing `.sow` control directory
  is group/other writable is refused before SOW creates a lock, temporary,
  intent or canonical control file. Operators must inspect ownership and
  permissions and correct them explicitly; SOW does not hide the condition by
  repairing it.
- A control-file alias introduced before commit yields `not-committed`; after
  durable transaction authority exists it yields `recovery-required`.
  Transaction evidence is retained rather than silently cleaned.
- Existing read-only group access such as mode `0640` remains compatible.
  Group/other writes, foreign ownership and multiple links are not.
- The extra `stat` comparisons and parent fsync are constant work per touched
  control object and do not scan CAS or serving payloads.

## Evidence

See [the implementation report](../evidence/2026-07-28-derived-state-hostile-writer-admission.md),
`internal/cli/derived_state_security.go`,
`internal/state/lock_security.go`, and V-82 in the
[requirements ledger](../requirements-traceability.md).
