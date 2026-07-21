# Reconcile stale-path prune identity — 2026-07-22

## Finding

`ReconcileExact` scans the materialized target, diffs it against the desired
manifest and removes paths classified as stale. Its deletion primitive checked
the current path with `Lstat` and then called `os.Remove` by pathname. A file or
ancestor replacement between those operations could therefore redirect the
deletion to a different inode.

The red fault-injection test moved the scanned stale inode aside and installed
a hardlink to a canary immediately before removal. The old implementation
returned success and deleted the canary link.

## Resolution

Stale-path removal now uses the same Linux/macOS descriptor-bound filesystem
contract as materialization:

1. bind the exact target root and parent directory without following symlinks;
2. open the stale regular file and record its device/inode identity;
3. move the name to an unpredictable sibling with no-replace rename;
4. compare the quarantined inode with the recorded identity;
5. unlink only an exact match, otherwise restore the replacement without
   overwrite and return `ErrUnsafePath`;
6. fsync the bound parent and revalidate parent/root coordinates.

This preserves exact-reconcile semantics while removing pathname-derived
deletion authority. A concurrent replacement remains visible for diagnosis and
the final tree verification cannot report success.

## Current-source verification

```text
# Red result before the fix
go test ./internal/repository -run '^TestReconcilePrunePreservesConcurrentPathReplacement$' -count=1
FAIL: expected ErrUnsafePath, got nil

go test ./internal/repository -run '^TestReconcile(PrunePreservesConcurrentPathReplacement|ExactPrunesStaleFilesAndKeepsHardlinks)$' -count=1
PASS 0.720s

go test -race ./internal/repository -run '^TestReconcile(PrunePreservesConcurrentPathReplacement|ExactPrunesStaleFilesAndKeepsHardlinks)$' -count=1
PASS 1.526s

go test ./internal/repository -count=1
PASS 2.391s

go test -race ./internal/repository -count=1
PASS 3.309s

go test ./internal/cli -run 'Reconcile|DirectMaterialize' -count=1 -timeout=10m
PASS 12.909s

go test -race ./internal/cli -run 'Reconcile|DirectMaterialize' -count=1 -timeout=10m
PASS 17.327s

go test ./internal/cli -run 'Materialize' -count=1 -timeout=15m
PASS 196.080s (59 tests)

go test -race ./internal/cli -run 'Materialize' -count=1 -timeout=20m
PASS 270.222s (59 tests)

go vet ./internal/repository ./internal/cli
staticcheck ./internal/repository ./internal/cli
PASS
```

Focused coverage reports `removeMaterializedPath` at 100% and the bound helper
at 79.5%. Static test binaries compiled with `CGO_ENABLED=0` for Darwin arm64,
Linux amd64 and Linux arm64; their SHA-256 values are respectively
`f31ffbd4...6636d`, `74fc245b...d4cc` and `1d689f2f...05b3`.

## Boundary

All mutation occurred below local temporary roots. No credential, network,
cloud resource, production repository or production local tree was accessed.
This is local materialization/recovery evidence and does not upgrade the open
Cloudflare control/CDN, COS/EdgeOne or production-migration items.
