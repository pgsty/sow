# YUM consumer preflight lock-release evidence

Date: 2026-07-19

Baseline: `f60eb7a6a8525761f6d8eea33fc6e2e1b071b272`

Scope: local YUM consumer preparation teardown only

External mutation: none

## Result

The broad audit claim that ordinary `init`, `publish`, and `sync` still ignored
successful-command state-lock release failures was stale: current source has
used `propagateStateLockRelease` at those sites since `f17ca5b5`. The remaining
production exception was narrower and real. If `prepareYUMConsumerPreflight`
acquired the canonical lock and then hit a primary preparation error, its local
failure closure discarded `Lock.Release()` unconditionally.

The preparation boundary now receives the command's stderr and invokes the
same shared release contract. A primary error remains the exact returned error
with its original exit class; a simultaneous release failure is emitted as a
warning. The successful preparation path still transfers the owned lock to the
top-level preflight or receipt-check command, whose existing deferred release
makes teardown part of command success.

## Fault evidence

`TestYUMConsumerPreparationFailureDiagnosesDurableLockReleaseFailure` acquires a
real process-instance state lock in a temporary repository, renames the visible
`state.lock` after acquisition, and then executes the preparation-failure
cleanup. The real `Release()` refuses to delete a missing/replaced authoritative
record. The test proves all three required outcomes:

- the original `ExitVerification` error object and exit code are unchanged;
- stderr contains `warning: release state lock` and the durable-record failure;
- the displaced foreign lock evidence remains present.

The existing generic release test continues to prove that a release failure is
`ExitInternal` when it is the only failure, while a primary error wins without
hiding the teardown diagnostic.

## Reproduced commands

```bash
go test -count=1 ./internal/cli \
  -run '^(TestYUMConsumerPreparationFailureDiagnosesDurableLockReleaseFailure|TestStateLockReleaseFailureChangesOnlySuccessfulCommandResult)$' -v
go test -race -count=1 ./internal/cli \
  -run '^(TestYUMConsumerPreparationFailureDiagnosesDurableLockReleaseFailure|TestStateLockReleaseFailureChangesOnlySuccessfulCommandResult)$' -v
go test -count=1 ./internal/cli -run '^TestYUMConsumer'
go test -race -count=1 ./internal/cli -run '^TestYUMConsumer'
go test ./... -run '^$'
go vet ./internal/cli
staticcheck -checks='SA*,S1*' ./internal/cli
SOW_RUN_REAL_CLOUD=0 SOW_RUN_REAL_EDGE_EVIDENCE=0 \
  SOW_RUN_REAL_UPSTREAM=0 go test -count=1 ./test/compat/cleandelivery
```

Observed current-source results:

```text
focused ordinary: 0.923s PASS
focused race: 1.800s PASS
all YUM consumer ordinary: 7.782s PASS
all YUM consumer race: 13.279s PASS
all-package compile gate, go vet and Staticcheck SA*/S1*: PASS
clean-delivery policy closure: 2.105s PASS
independent Blind Hunter review: []
```

## Evidence boundary

All tests used temporary local directories and a local process-instance lock.
No network request, credential, cloud bucket, CDN, production repository, or
Pigsty checkout was read or modified. This strengthens the local FR-28/NFR-09
teardown/recovery contract; it does not upgrade their still-open dual-cloud
publication evidence.
