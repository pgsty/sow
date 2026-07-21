---
title: 'YUM compatibility bound cutover recovery closure'
type: 'hardening'
created: '2026-07-20'
status: 'done'
baseline_commit: 'efad175'
---

## Intent

The production `sow compatibility yum-cutover/yum-rollback` path retains the
repository root, state root and lock as directory capabilities. Earlier crash
tests exercised the superseded pathname-oriented recovery helpers, leaving the
actual bound recovery branches without executable evidence. Those branches are
the last local authority before the frozen EL8 compatibility serving link is
reconciled after interruption.

## Contract

- A partial `.next` with no canonical event is removable only under explicit
  recovery and must leave canonical S2 and the serving namespace unchanged.
- A prepared base plus partial `.next`, or an orphan committed `.next`, may
  converge only when the exact content-bound event is already canonical.
- A committed main or dual-phase journal without the exact canonical event
  fails closed, keeps forensic journal bytes and never changes the serving link.
- Recovery mutates only through the retained repository/state capabilities and
  continues to validate the state lock and namespace identity at each boundary.
- If a post-flip failure is observed while the process is still alive, the link
  is restored exactly: prior link target when one existed, absence otherwise.
- Production workflows have no injected hook; the additional post-flip seam is
  unexported, deterministic and test-only when non-nil.

## Implementation

- `internal/cli/yum_compat_bound_recovery_test.go` builds full canonical S0/S1/S2
  fixtures, appends real Git-backed S3 events where authorized, acquires the
  real state lock, binds `os.Root` repository/state capabilities, installs exact
  journal crash residues and calls the same bound recovery used by the CLI.
- `reconcileYUMCompatibilityServingLinkWithBinding` exposes a named post-rename
  fault boundary through the existing nil-by-default mutation hook so rollback
  and rollback verification run as an integrated bound operation.
- Negative cases prove that journal phase alone is not commit authority and
  that rejected evidence is retained for a later explicit recovery attempt.

## Verification

- Focused ordinary and `-race` tests for all bound recovery and post-flip
  rollback cases.
- Focused atomic coverage over `internal/cli`, with every formerly zero bound
  recovery/rollback function executed.
- Compile, vet, Staticcheck, full CLI/non-CLI ordinary and race gates, migration
  suites and deterministic clean-delivery reconstruction before status becomes
  `done`.
- All real-cloud, real-upstream and Docker compatibility opt-ins remain off;
  no Cloudflare, CO/COS or production repository access is required.

## Result

The final code-bearing source passed 709 CLI tests in six ordinary and six
`-race` shards, all non-CLI packages ordinary/race, the nested RPM module,
compile/vet/Staticcheck, four static cross-builds, 47/47 edge contracts, seven
migration suites, fixed vulnerability/provenance gates and all 50k performance
tests. Two post-evidence clean deliveries were rebuilt and compared bytewise;
their non-self-referential identity is recorded in the external V-48 ledger.
