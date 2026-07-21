---
title: 'Local YUM serving atomic parent rollback'
type: 'hardening'
created: '2026-07-20'
status: 'done'
baseline_commit: 'a74d758'
---

## Intent

When post-flip package-trust verification fails, local YUM serving must return
the mutable mirrorlist to its exact pre-flip state. The previous helper removed
the child first and then restored whichever valid parent channel it was given.
It neither bound that parent to the digest/target identity sealed in the child
nor kept removal and restoration inside one atomic replacement.

## Contract

- A parent rollback accepts only the same leaf/path, parent generation,
  parent mirrorlist digest and target identity sealed into the child channel.
- Target migration binds the old `ParentTargetID`; ordinary advancement binds
  the current target ID. In both cases target root must remain exact.
- Validation happens before filesystem mutation. Another syntactically valid
  channel, including one that renders byte-identical mirrorlist content under a
  different target root, must be rejected without changing the child.
- A correct parent is restored with one parent-bound atomic replacement; there
  is no remove-then-create availability or foreign-writer window.
- First-install rollback atomically restores exact absence and cannot be used
  for a parent-bound child.

## Implementation and verification

- `rollbackLocalServingMirrorlist` validates the parent, checks its sealed
  leaf/generation/digest/target link, renders the exact prior body, then calls
  `serving.RollbackMirrorlist`.
- A real filesystem test derives valid target-partitioned generations and
  channels, installs the parent then child, and covers wrong URL, same bytes but
  wrong target root, exact parent, and exact first-install absence.
- Before the correction, the wrong-parent negative returned `nil`; the old
  helper had already deleted the child and admitted the unsealed parent.
- Focused ordinary/race, the complete local-serving recovery group, affected
  G-M/R-V ordinary/race shards, compile/vet/Staticcheck, family migration,
  local adoption rollback and deterministic clean delivery must pass.
- No cloud, upstream, Docker or production repository access is involved.

## Result

All focused, affected ordinary/race, static and migration gates passed. Two
post-evidence clean deliveries are rebuilt and compared bytewise; their
non-self-referential identity is recorded in the external V-54 ledger. The
long-term Goal remains active.
