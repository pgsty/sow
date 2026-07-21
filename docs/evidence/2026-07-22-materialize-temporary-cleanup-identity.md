# Materialize temporary-cleanup identity — 2026-07-22

## Finding

Atomic replacement creates an unpredictable temporary hardlink to a verified
CAS inode before exchanging it with an existing destination. On every failure
before the exchange, `cleanupMaterializeTemporary` re-read whichever inode was
currently at the temporary name and then treated that inode as SOW-owned.

A concurrent same-user writer could rename the verified link away and install
another regular file at that name between proof and failure cleanup. The red
fault-injection test performed exactly that replacement and then returned an
injected error. Before the fix SOW returned only the injected error and unlinked
the concurrent canary.

## Resolution

The retained CAS descriptor is identified before temporary-link creation. That
verified device/inode identity is now carried through every pre-exchange failure
branch and supplied to the existing quarantine remover. Cleanup therefore:

- removes a still-owned temporary hardlink;
- treats a missing temporary as already clean; and
- quarantines, compares and restores a replaced name without unlinking it,
  returning `ErrUnsafePath` together with the primary failure.

No cleanup branch derives deletion authority from the current path occupant.
The destination remains unchanged until the descriptor-bound atomic exchange.

## Current-source verification

All tests used local temporary repositories:

```text
# Red result before the fix
go test ./internal/repository -run '^TestMaterializeFailureCleanupPreservesConcurrentTemporaryReplacement$' -count=1
FAIL: expected primary failure plus ErrUnsafePath; only the injected failure was returned

# Both sides of the cleanup contract after the fix
go test ./internal/repository -run '^TestMaterializeFailureCleanup(RemovesOwnedTemporary|PreservesConcurrentTemporaryReplacement)$' -count=1
PASS 0.740s

go test -race ./internal/repository -run '^TestMaterializeFailureCleanup(RemovesOwnedTemporary|PreservesConcurrentTemporaryReplacement)$' -count=1
PASS 1.530s

go test ./internal/repository -count=1
PASS 2.498s

go test -race ./internal/repository -count=1
PASS 3.405s

go test ./internal/cli -run 'Materialize' -count=1 -timeout=15m
PASS 204.130s (59 tests)

go test -race ./internal/cli -run 'Materialize' -count=1 -timeout=20m
PASS 272.082s (59 tests)

go vet ./internal/repository ./internal/cli
staticcheck ./internal/repository ./internal/cli
PASS
```

The focused coverage run reached 100% of
`cleanupMaterializeTemporary`; the two tests separately prove owned removal and
foreign-inode preservation.

## Boundary

No credential, external network, cloud resource, local production tree or
cloud production repository was used. This closes one local materialization
race/failure-recovery defect only; it does not upgrade the outstanding real
Cloudflare control/CDN, COS/EdgeOne or production-migration evidence.
