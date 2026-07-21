# 2026-07-20 YUM compatibility bound cutover recovery

Status: final local ordinary/race, static, migration, performance and delivery
gates passed. No cloud or production resource was accessed.

## Evidence boundary

This run used only `t.TempDir` repositories, the real Go Git-backed canonical
state store, real state locks, retained `os.Root` capabilities, on-disk journals
and symlinks. It did not use in-memory storage adapters. All cloud, upstream and
Docker compatibility opt-ins remained disabled.

## Crash states exercised

- prepared main journal refuses implicit recovery and is discarded only under
  explicit recovery before any canonical event exists;
- orphan partial `.next` converges both at S2 and after an exact canonical S3
  event, with the latter rebuilding the serving link from canonical authority;
- prepared main plus partially written committed phase converges only against
  the exact canonical event;
- orphan committed phase and committed main converge after the exact canonical
  event;
- committed main, dual-phase journal and orphan committed phase without the
  canonical event fail closed, retain forensic bytes and leave the link absent;
- a deterministic failure immediately after link rename restores either the
  exact previous target or exact prior absence.

## Commands and focused results

```bash
go test -count=1 \
  -run 'TestYUMCompatibilityBound(CutoverRecoveryConvergesCrashStates|ServingLinkPostFlipFailureRestoresPriorState)$' \
  ./internal/cli

go test -race -count=1 \
  -run 'TestYUMCompatibilityBound(CutoverRecoveryConvergesCrashStates|ServingLinkPostFlipFailureRestoresPriorState)$' \
  ./internal/cli

go test -count=1 -covermode=atomic -coverpkg=./internal/cli \
  -coverprofile=/tmp/sow-yum-bound-recovery.out \
  -run 'TestYUMCompatibilityBound(CutoverRecoveryConvergesCrashStates|ServingLinkPostFlipFailureRestoresPriorState)$' \
  ./internal/cli
```

Observed results: ordinary `PASS` in 4.190s, race `PASS` in 6.993s with no race
report. Focused atomic coverage changed the production-bound recovery cluster
from entirely unexecuted to:

| function | focused statement coverage |
| --- | ---: |
| `recoverYUMCompatibilityCutoverJournalBound` | 81.5% |
| `recoverPartialYUMCompatibilityCutoverNextBound` | 68.4% |
| `recoverOrphanYUMCompatibilityCutoverNextBound` | 75.0% |
| `removeYUMCompatibilityCutoverNextBound` | 66.7% |
| `restoreYUMCompatibilityServingLink` | 52.0% |
| `verifyRestoredYUMCompatibilityServingLink` | 58.8% |

These percentages are branch-driving evidence, not a replacement for semantic
assertions or whole-product coverage.

## Final local gates

The code-bearing source passed all 709 `internal/cli` tests in six ordinary
shards (575.391s, 804.710s, 267.712s, 916.265s, 591.069s, 247.751s) and six
`-race` shards (621.128s, 906.577s, 272.782s, 1107.675s, 644.720s, 307.649s),
with no race report. All non-CLI packages and the nested RPM module passed
ordinary/race. Compile-only, `go vet ./...`, repository Staticcheck, module
verification, pinned RPM upstream provenance and fixed root/nested
`govulncheck@v1.6.0` passed; the vulnerability tool and provenance extraction
were reproduced with the local read-only module proxy after the public proxy
timed out.

All four `CGO_ENABLED=0 -trimpath` darwin/linux × amd64/arm64 builds passed.
Edge bundles rebuilt without diff and all 47 shared Cloudflare/EdgeOne contracts
passed. All seven hermetic migration suites passed, including both compatibility
architectures and the copy-only Pigsty consumer workflow.

The final 50k gates observed: upstream spool retained-heap growth 0 with
29,265,920 bytes on disk; APT 2.989s with four workers and 256-entry peak chunk;
YUM 6.429s with retained-heap growth 0; hardlink materialization 15.532s with
eight workers and 154,064 bytes retained growth; one-object publish planning
12.395ms; 100 incremental no-view-read preflights 8.595ms.

Two isolated post-document clean-delivery builds used only the read-only local
module proxy and were compared byte-for-byte. Their final identity is recorded
in the delivery-external V-48 section of
`_bmad-output/implementation-artifacts/validation-selected-set-materialization-2026-07-13.md`
so the digest is not embedded in content that it hashes.
