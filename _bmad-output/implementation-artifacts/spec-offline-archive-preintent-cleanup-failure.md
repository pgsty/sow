---
title: 'Offline archive pre-intent cleanup failure closure'
type: 'hardening'
created: '2026-07-20'
status: 'done'
baseline_commit: '266d3a4'
---

## Intent

An offline tgz is complete before its durable projection intent and canonical
taint receipt exist. Every failure in that pre-intent interval must either
remove the private hard-link stage durably or tell the operator that an orphan
remains and `--recover` is mandatory.

## Contract

- A stage-install failure removes the exact transaction-named hard link through
  a bound private stage directory and fsyncs that directory.
- An intent-write failure applies the same cleanup contract.
- Cleanup failure is joined to the initiating error; it is never discarded by
  a defer. The message is stable and explicitly requires `--recover`.
- Failed pre-intent work creates no projection intent, taint receipt or visible
  destination. A safely removed stage can be retried normally.
- If directory permission drift prevents cleanup, the exact orphan remains
  private. After the directory is repaired, `--recover` removes the orphan and
  safely replays materialization.

## Implementation and verification

- `installOfflineArchiveProjectionStage` and
  `prepareOfflineArchiveProjectionIntent` now use named result errors and join
  failures from `discardOfflineArchiveProjectionStage`.
- Stage-install rollback no longer removes a nested entry through the state
  root and fsyncs the wrong parent. The shared cleanup helper binds the exact
  stage directory, removes there and fsyncs that directory.
- Fault injection changes the private directory to mode 000 or 0777 exactly
  after stage creation, then fails stage fsync or intent write. Tests prove the
  error, private residue, absence of intent/receipt/destination and convergent
  `--recover` replay. A no-drift control proves immediate cleanup and normal
  retry.
- Focused, complete offline-archive and affected N-O ordinary/race suites pass,
  as do static gates. Deterministic delivery is recorded externally after the
  delivery-managed source set is frozen.
- No cloud, upstream, Docker or production repository access is involved.
