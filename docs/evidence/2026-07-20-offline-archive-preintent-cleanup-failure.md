# 2026-07-20 offline archive pre-intent cleanup failure closure

Status: final local ordinary/race, static and delivery gates passed. No cloud
or production resource was accessed.

## Red findings

Two independent pre-intent failure windows discarded cleanup errors:

1. After the private stage was linked, an injected stage-directory fsync
   failure returned only `injected durable archive stage sync failure`.
2. After the stage was durable, an injected intent-write failure returned only
   `injected offline archive intent write failure`.

In both cases the fault also changed the private stage directory permissions so
rollback could not remove the hard link. The old CLI exited with verification
code 4 but did not mention the retained orphan or `--recover`.

The stage-install defer also removed a nested entry through the state root and
fsynced the state root, not the stage directory whose entry had changed.

## Correction

Both pre-intent functions now preserve a named result error and join cleanup
failure as:

```text
offline archive projection stage cleanup failed; retry with --recover
```

Both use `discardOfflineArchiveProjectionStage`, which validates the exact
transaction filename, binds the private stage directory, removes through that
directory handle and fsyncs the changed directory. Successful cleanup leaves
no orphan and needs no recovery. Permission drift leaves the private orphan in
place with an actionable error; once permissions are repaired, real CLI
`materialize --recover` removes it and completes a fresh deterministic archive.

No failed pre-intent path creates an intent, taint receipt or operator-visible
destination.

## Commands and results

```bash
go test -count=1 ./internal/cli \
  -run '^TestOfflineArchive(IntentWriteFailure(ReportsStageCleanupDrift|RemovesUnownedStage)|StageSyncFailureReportsCleanupDrift)$'
go test -race -count=1 ./internal/cli \
  -run '^TestOfflineArchive(IntentWriteFailure(ReportsStageCleanupDrift|RemovesUnownedStage)|StageSyncFailureReportsCleanupDrift)$'

go test -count=1 ./internal/cli -run '^TestOfflineArchive'
go test -race -count=1 ./internal/cli -run '^TestOfflineArchive'
```

The three focused fault/control tests pass in 6.525s ordinary and 10.063s race.
The complete 37-test offline-archive family passes in 69.048s ordinary and
92.407s race, including crash, directory replacement, taint, adoption and
recovery paths.

The final affected N-O CLI shard passes in 105.136s ordinary and 137.667s race.
Focused coverage reaches 75.0% for stage install, 77.1% for intent preparation
and 76.9% for exact stage discard. Compile, vet, repository Staticcheck, module
integrity and diff whitespace gates pass.

After this report, its spec, trace row and delivery allowlist were frozen, two
isolated clean deliveries were compared bytewise, and their
non-self-referential identity was recorded in the external V-58 section of
`_bmad-output/implementation-artifacts/validation-selected-set-materialization-2026-07-13.md`.

## Boundary

Tests use real CLI dispatch, Git state, hard links, bound filesystem roots,
directory permission drift and deterministic tgz bytes under temporary roots.
All real-cloud and upstream opt-ins are absent. This closes local pre-intent
cleanup semantics only and does not upgrade cloud, CDN, production migration
or operational metrics.
