# Projection intent completion identity — 2026-07-22

## Finding

Asset and package projection recovery both use a durable intent as the bridge
between canonical Git/ref mutation and local materialization. Intent removal is
the completion commit. Both completion paths validated the intent and then
called `os.Remove` on its pathname, so a replacement between validation and
removal redirected the commit to a different inode.

Two deterministic fault-injection tests moved the validated intent aside and
installed a private regular-file canary at the same pathname. Before the fix,
both asset and package completion returned success and deleted the canary.

## Resolution

Projection intent completion now uses a shared Linux/macOS exact-removal
primitive:

1. open the private intent through a bound state root and retain its file
   descriptor, inode identity and exact validated bytes;
2. move the live name to an unpredictable sibling with an atomic no-replace
   rename;
3. compare the quarantined file with the retained inode and reread the same
   descriptor to prove its bytes did not change;
4. restore any replacement without overwrite and return an error;
5. fsync the directory to commit disappearance of the exact validated intent,
   then remove the recognizable private quarantine residue.

The package completion receipt is still durably written before this commit.
The quarantine name remains covered by the existing `--recover` residue
scanner if a process terminates after the directory commit and before garbage
collection.

## Current-source verification

```text
# Red result before the fix
go test ./internal/cli -run \
  'Test(Asset|Package)ProjectionCompletionPreservesConcurrentIntentReplacement' \
  -count=1
FAIL: both completion paths accepted the replacement pathname

# Exact success, replacement rejection and post-commit cleanup
go test ./internal/cli -run \
  'TestAssetProjectionCompletion|TestPackageProjectionCompletionPreservesConcurrentIntentReplacement|TestPackageProjectionCompletionIgnoresOrphanStageCleanupFailure' \
  -count=1
PASS 1.985s

go test -race ./internal/cli -run \
  'TestAssetProjectionCompletion|TestPackageProjectionCompletionPreservesConcurrentIntentReplacement' \
  -count=1
PASS 2.431s

go test ./internal/cli -run 'Projection' -count=1
PASS 80.330s

go test -race ./internal/cli -run 'Projection' -count=1 -timeout=10m
PASS 118.005s

go test ./internal/cli -count=1 -timeout=20m
PASS 1179.359s

go test ./... -count=1 -timeout=25m
PASS (CLI 1203.745s; clean-delivery 8.720s; every other package PASS)

go test ./internal/cli -run \
  '^TestYUMCompatibilityAArch64StateMachineThroughRollback$' -count=1
PASS 21.734s

go vet ./...
staticcheck ./...
PASS
```

The isolated YUM state-machine run confirms that the earlier unextended
`go test ./...` timeout occurred because the complete CLI package needs about
20 minutes on this host; the test named in the timeout stack was not stalled.
The extended full-tree run subsequently passed. The clean-delivery policy was
updated for the new current-source test/helper and the previously committed
V-65/V-67/V-69 evidence files, then passed inside that same full-tree run.

Focused coverage reports `removeExactProjectionIntent` at 74.4%, the asset and
package completion wrappers at 75.0% and 80.0%, and the private-file predicate
at 100%. Static test binaries compiled with `CGO_ENABLED=0` for Darwin arm64,
Linux amd64 and Linux arm64. Their SHA-256 values are respectively
`e7011987...c6d9b`, `666013d5...422f` and `b089ece6...2b45`.

## Boundary

All mutation occurred below local temporary roots. No credential, network,
cloud resource, production repository or production local tree was accessed.
This strengthens local interruption/recovery semantics only; it does not
upgrade Cloudflare Worker/purge/cache-log, COS/EdgeOne, production migration or
operational-metric acceptance status.
