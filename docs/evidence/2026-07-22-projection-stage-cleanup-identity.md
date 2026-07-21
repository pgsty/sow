# Projection stage cleanup identity — 2026-07-22

## Finding

V-71 made durable projection-intent removal an inode- and byte-bound completion
commit. The post-commit garbage collection that followed it still called
`os.Remove` directly on asset/package manifest-stage and frozen-config
pathnames. A same-user replacement between completion and cleanup could
therefore be deleted even though it was not the staged file bound by the
intent.

Two deterministic fault tests replaced the validated asset and package stage
with a private regular-file canary immediately before cleanup. Before the fix,
both completed transactions returned success and deleted the canary.

## Resolution

Stage/config cleanup now consumes the size and SHA-256 frozen in the durable
intent and uses the same exact state-file removal transaction as intent
completion:

1. bind the private regular file through the state-root descriptor and retain
   its inode identity;
2. stream at most `expected_size + 1` bytes through SHA-256 with a 256 KiB
   buffer, rejecting length, digest, mode, timestamp or inode drift;
3. atomically move the live name to an unpredictable no-replace quarantine;
4. compare the quarantined inode and stream the retained descriptor again;
5. restore a replacement without overwrite, or fsync exact removal and collect
   the recognizable private residue.

The implementation never loads a manifest stage into memory. Empty manifests
remain valid. A same-length digest mismatch is retained rather than deleted.
Because the durable intent has already disappeared, cleanup failure is
recoverable garbage and cannot turn a completed projection back into a
reported transaction failure.

## Current-source verification

```text
# Red result before the fix
go test ./internal/cli -run \
  'Test(Asset|Package)ProjectionCompletionPreservesConcurrentStageReplacement' \
  -count=1
FAIL: both post-commit cleanup paths deleted the replacement canary (8.121s)

# Exact intent/stage completion, replacement, empty and digest-mismatch cases
go test ./internal/cli -run \
  'TestAssetProjectionCompletion|TestPackageProjectionCompletion' -count=1
PASS 2.539s

go test -race ./internal/cli -run \
  'TestAssetProjectionCompletion|TestPackageProjectionCompletion' -count=1
PASS 3.765s

go test ./internal/cli -run 'Projection' -count=1 -timeout=10m
PASS 80.449s

go test -race ./internal/cli -run 'Projection' -count=1 -timeout=10m
PASS 117.594s

go test ./internal/cli -count=1 -timeout=25m
PASS 1190.270s

go vet ./...
staticcheck ./...
PASS 8.306s / 14.795s
```

Focused coverage reports the stage remover at 77.1%, the shared quarantine
commit at 76.0%, the stage binder at 75.0%, the streaming verifier at 90.0%,
and both private-file predicates at 100%. Static test binaries compiled with
`CGO_ENABLED=0` for Darwin arm64, Linux amd64 and Linux arm64; their SHA-256
values are respectively `09eee794...adc14`, `f1c8941d...b8675` and
`de240454...16ba1`.

## Boundary

All mutation occurred below local temporary roots. No credential, network,
cloud resource, production repository or production local tree was accessed.
This strengthens local interruption/recovery cleanup only; it does not upgrade
Cloudflare Worker/purge/cache-log, COS/EdgeOne, production migration or
operational-metric acceptance status.
