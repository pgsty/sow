# Projection stage install and prepare rollback identity evidence

Date: 2026-07-22

Scope: V-77, local filesystem only

Baseline: `bb00b57f3287`

## Defect reproduction

Before the product fix, deterministic fault tests captured six failures in
`1.483s`: the legacy deterministic `.tmp` canary was deleted, a destination
created after the absence check was overwritten, a replacement install
candidate was published, a same-byte source-coordinate replacement was
accepted, and both asset and package preparation deleted recovery stages after
the exact intent had already been installed but its writer returned a simulated
durability error. Two additional rollback-replacement tests failed in `1.417s`:
path-only cleanup deleted an unrelated inode.

The two independent adversarial reviews then found further reachable gaps:
archive inspection could reopen a FIFO and drain a concurrently growing file;
a restrictive umask could remove owner-read permission; prepared stages were
not revalidated around intent installation; ambiguous read-back was not closed
over the prepared state-root identity; missing rollback coordinates were
treated as success; recovery rebound unowned final names as deletion authority;
package recovery matched every stage-prefix name; and exact removal had a final
deterministic replacement seam immediately before unlink.

## Implemented fences

- Source admission opens one exact regular non-symlink descriptor with
  no-follow/nonblocking flags. Inspection and stage copy reuse that descriptor;
  every drain/copy is limited to admitted size plus one byte and uses a 256 KiB
  streaming buffer. Descriptor, public coordinate, size, mode, modification
  time and SHA-256 are rechecked through publication.
- Every stage uses a random `O_EXCL` temporary, explicit `chmod 0600`, and a
  second random isolation coordinate. Isolation and final installation use
  native Linux/macOS no-replace renames. The retained writer descriptor, inode,
  byte identity and state-root inode remain bound through directory sync and
  failure cleanup.
- Asset/package prepare retain process-local inode capabilities for config and
  every manifest. The entire vector is re-hashed immediately before and after
  the create-only intent commit. A root replacement, same-byte stage
  replacement, competing intent, or ambiguous durability result retains every
  recovery input and fails closed with an actionable `--recover` error.
- A pre-intent failure rolls the complete installed-stage ledger back in
  reverse order, continues after individual conflicts, and joins every cleanup
  error. Cleanup consumes only the captured inode capability; a missing stage
  is an error and a replacement survives.
- Exact removal revalidates quarantine descriptor/inode/bytes after the final
  test seam and immediately before unlink. All stage/residue/intent binders and
  the shared bounded state reader use nonblocking no-follow opens.
- Restart recovery now applies ADR-0041. Strict random temporary names retain
  exact cleanup, but a final stage with no valid owning intent is moved to
  `.preserved-<32hex>`, reported, and never deleted. The next `--recover`
  ignores that exact audit form. Unknown asset/package suffixes fail unchanged;
  broad package-prefix deletion and silent `.test-original` handling are gone.

## Current-source verification

Credential variables and every real-cloud/real-edge/real-upstream opt-in were
blank or disabled for the commands below. `GOPROXY=off` was used after the
local module cache was populated. No command targeted an object store or CDN.

```bash
# Review-final install, intent, rollback, recovery, FIFO and root boundaries
go test ./internal/cli -run \
  'Test(OfflineArchiveExactOpen|OfflineArchiveDigestAndMarker|ProjectionStage|ProjectionIntent|ProjectionRecovery|ExactPrivateStateRemoval|AssetProjectionPrepare|PackageProjectionPrepare|PackageProjectionCompletionCleanup)' \
  -coverprofile=/tmp/sow-v77-review.cover -count=1
PASS 5.802s, coverage 11.6% of the complete CLI package

go test -race ./internal/cli -run \
  'Test(OfflineArchiveExactOpen|OfflineArchiveDigestAndMarker|ProjectionStage|ProjectionIntent|ProjectionRecovery|ExactPrivateStateRemoval|AssetProjectionPrepare|PackageProjectionPrepare|PackageProjectionCompletionCleanup)' \
  -count=1
PASS 7.949s, no race report

go test ./internal/cli -run Projection -count=1
PASS 87.271s

go test -race ./internal/cli -run Projection -count=1
PASS 193.995s, no race report

go test ./internal/cli -timeout=25m -count=1
PASS 1326.431s

go list ./... | rg -v '/internal/cli$' | xargs go test -count=1
PASS: every non-CLI package, including test/compat and clean-delivery policy

go vet ./...
staticcheck ./...
git diff --check
PASS

# Adjacent publication/projection/recovery race surface
go test -race ./internal/cli -run \
  'Publish|Projection|MaterializationSelection|DerivedState|LocalServingJournal|ServingTopology' \
  -count=1 -timeout=20m
PASS 693.228s, wall 708.60s, no race report
```

The focused set includes exact-open FIFO replacement without blocking,
restrictive-umask repair, legacy-temp preservation, destination/candidate/source
replacement, post-verification replacement, `size+1` read accounting, strict
stage-name grammar, final orphan audit preservation and two-pass recovery,
unknown-suffix rejection, exact and conflicting multi-stage rollback, prepared
root replacement, concurrent intent preservation, ambiguous commit retention,
pre/post intent stage-vector verification, and final-unlink replacement.

Focused coverage is 74.1%/67.0% for asset/package prepare, 80.0% for exact
source open, 70.6% for retained-descriptor inspection, 71.9%/73.9% for admitted
stage install/streaming writer, 70.0%/100% for single/vector stage verification,
67.4%/100% for exact rollback/ledger, 67.9% for orphan preservation, 78.6% for
the shared quarantine commit, 78.0%/70.8% for asset/package recovery scanners,
and 93.3–100% for the strict final/temp/preserved name classifiers.

`CGO_ENABLED=0 go test -c -trimpath` produced four static test binaries:

| Target | SHA-256 |
|---|---|
| Darwin amd64 | `08df62e28e0709acce95d223213c5d44feabaa28aeaec2f0d86906a794d73efb` |
| Darwin arm64 | `5c2c69c945cd761e42e915dc944ca613f8d6593c997d34ad8a18dab6751af489` |
| Linux amd64 | `3ef81fe1ab1a08dec3055826d2b132d6fa8c4517af4d418ef5a4c97c7055249b` |
| Linux arm64 | `56a54004d1c1cb42797a6943111c4f8052cc2aefd2df8163c3c4e46051317e7a` |

The Linux arm64 binary then ran the focused V-77 set successfully in
`debian:13-slim` with `--platform linux/arm64`, `--network none`, a read-only
container, read-only workspace/binary mounts, and only `/tmp` supplied as
tmpfs. This is an isolated runtime check, not a claim that every cross-built
target was executed.

## Review disposition and boundary

Blind Hunter and Edge Case Hunter findings were classified as current-patch
fixes or pre-existing scope. All current-patch issues above are closed. The
pre-existing `Store.Apply` staged-path reopen gap is recorded in
`deferred-work.md`; the final-stage restart decision is explicit in ADR-0041.
No frozen intent gap was found, so the review-loop counter remains zero.

All mutation occurred below isolated local temporary roots or the ignored local
development binary. No network request, object-store operation, CDN purge,
production repository access, or `pro` test-bucket access occurred. This
evidence strengthens FR-28/NFR-09 local interruption/replay behavior only; it
does not upgrade any R2, COS, Cloudflare Worker, EdgeOne, CDN, or production
migration status.
