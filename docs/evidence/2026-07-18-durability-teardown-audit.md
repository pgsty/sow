# Durability and teardown audit — 2026-07-18

## Boundary

This audit used the current dirty worktree based on commit `84800a6`, Go
`1.26.5`, and macOS/arm64. It touched only repository source files and local
temporary directories. No Cloudflare, R2, CO/COS, EdgeOne, production
repository, or provider API was read or written during these tests.

The report is current-source evidence for the audited paths below. It is not a
release identity, a real-cloud result, or a Goal-completion claim.

## Closed failure paths

- APT output-directory locks, upstream download locks, publish journal locks,
  sync operation leases, and top-level YUM compatibility state locks now make
  unlock/descriptor failures part of command success. An existing primary
  failure keeps its exit class and receives an explicit teardown diagnostic.
- `manifest.AtomicCopy`, provenance receipt installation, and preserved
  upstream evidence require a successful parent-directory durability barrier.
  Fault-injected post-link/post-rename sync failures return an error, and exact
  replay converges without rewriting immutable content.
- failed canonical worktree installation retains its backup when restoration
  fails; restore/remove/sync errors are joined instead of deleting the only
  recovery evidence.
- `fsck` no longer discards the retained admission's final Git integrity or
  topology recheck on an early return. A previously successful result becomes
  verification failure; a pre-existing network/config/conflict exit class is
  preserved while both causes remain visible.
- YUM compatibility adopt/candidate/freeze/cutover/rollback commands now apply
  the same result semantics to root capabilities, candidate bindings, private
  canonical workspaces, and private CAS workspaces.
- the real-cloud purge watcher acceptance process now returns flock unlock and
  file-close failures, including its liveness probe. Its tests used only local
  files and loopback fixtures.
- `publish.Publisher` rejects a nil context instead of panicking. Historical
  NUL regular-file tar headers remain accepted without the deprecated Go alias;
  offline-archive extended attributes remain rejected through their canonical
  PAX representation.
- every CLI stdout/stderr sink is now wrapped at the single `Run` boundary.
  A write error or short write can no longer leave a successful exit status;
  an existing usage/config/network/conflict class remains authoritative while
  the independently observable output error stays in the error chain. The
  wrapper serializes concurrent progress writes and also rejects a nil sink.
- recovery repo narrowing now allocates its architecture slice rather than
  aliasing the canonical `sow.yaml` slice. A regression mutates the returned
  recovery value and proves the loaded configuration remains byte-for-byte
  unchanged.
- CAS materialization now joins parent-cache, retained CAS/shard, coordinate
  recheck, directory-sync and repository/target binding descriptor close
  failures into the API result. Fault injection proves a completed hardlink
  retains its exact work accounting but cannot be reported as successful when
  final descriptor teardown fails; a simultaneous content conflict remains the
  primary recognizable error while the teardown failure is also retained.
- descriptor-bound canonical Git reads now propagate nested parent/directory
  close failures. Cleanup is joined only when it actually fails, preserving
  the original `os.IsNotExist` classification required by go-git's optional
  `packed-refs` probes; an explicit nested-path regression locks that identity.
- APT/YUM L1 package-body verification now propagates input-manifest close,
  external-sort spool and temporary-tree cleanup failures. A simultaneous body
  inspection/cancellation error is retained alongside teardown evidence instead
  of being replaced by result arrival order. Canonical YUM compatibility history
  applies the same rule to its streaming Git storage.

## Executed evidence

Core ordinary and race packages passed after the durability changes:

```text
go test ./internal/aptrepo ./internal/manifest ./internal/provenance ./internal/upstream ./internal/publish ./internal/state -count=1
PASS: 8.599s / 1.360s / 0.760s / 13.934s / 13.272s / 15.039s

go test -race ./internal/aptrepo ./internal/manifest ./internal/provenance ./internal/upstream ./internal/publish ./internal/state -count=1
PASS: 6.620s / 1.649s / 2.628s / 20.722s / 13.286s / 15.927s
```

Focused ordinary/race regressions passed for FSCK finalization, state/sync
lease teardown, compatibility cleanup, APT legacy tar and offline-archive
envelopes, and the purge watcher lock. Representative current invocations:

```text
go test ./internal/cli -run 'Test(CanonicalFSCK|FSCKRejectsHashMismatched|FSCKRecoverAudits)' -count=1
ok  github.com/pgsty/sow/internal/cli  1.807s

go test -race ./internal/cli -run 'Test(CanonicalFSCK|FSCKRejectsHashMismatched|FSCKRecoverAudits)' -count=1
ok  github.com/pgsty/sow/internal/cli  3.456s

go test ./internal/cli -run 'Test(YUMCompatibility|CanonicalFSCKFinalizer|YUMCompatibilityCleanup)' -count=1
ok  github.com/pgsty/sow/internal/cli  13.493s

go test -race ./internal/cli -run 'Test(YUMCompatibility|CanonicalFSCKFinalizer|YUMCompatibilityCleanup)' -count=1
ok  github.com/pgsty/sow/internal/cli  31.839s

go test ./internal/repository -count=1
ok  github.com/pgsty/sow/internal/repository  4.448s

go test -race ./internal/repository -count=1
ok  github.com/pgsty/sow/internal/repository  6.302s

go test ./internal/state -count=1
ok  github.com/pgsty/sow/internal/state  7.669s

go test -race ./internal/state -count=1
ok  github.com/pgsty/sow/internal/state  12.565s

go test ./internal/verify -count=1
ok  github.com/pgsty/sow/internal/verify  4.528s

go test -race ./internal/verify -count=1
ok  github.com/pgsty/sow/internal/verify  6.284s

go test ./internal/cli -run '^(TestAssetAddIsCASBackedMaterializedAndReplayable|TestInitAdoptContentRealAPTAndYUMThenMaterializeVerifyFSCK|TestAssetOnlyDirectMaterializeFailureRetainsSelectedSetAndRecoversExactly|TestMaterializeCLIProducesExactHardlinkTree|TestMaterializeMutableYUMBuildsCanonicalStrongRoutesAndRetainsOldGeneration|TestMaterializeAPTSnapshotBuildsConsumableRepositoryAndRebuildsAfterRetention)$' -count=1
ok  github.com/pgsty/sow/internal/cli  30.756s

go test -race ./internal/cli -run '^(TestAssetAddIsCASBackedMaterializedAndReplayable|TestInitAdoptContentRealAPTAndYUMThenMaterializeVerifyFSCK|TestAssetOnlyDirectMaterializeFailureRetainsSelectedSetAndRecoversExactly|TestMaterializeCLIProducesExactHardlinkTree|TestMaterializeMutableYUMBuildsCanonicalStrongRoutesAndRetainsOldGeneration|TestMaterializeAPTSnapshotBuildsConsumableRepositoryAndRebuildsAfterRetention)$' -count=1
ok  github.com/pgsty/sow/internal/cli  34.930s

go test ./internal/cli -run '^(TestInitAdoptContentRealAPTAndYUMThenMaterializeVerifyFSCK|TestInitAndFSCKEndToEnd|TestCanonicalFSCKFinalizerFailureIsNeverDiscarded|TestPublicViewWithCanonicalGatedDigestFailsEveryLocalReadGate|TestVerifyCLIL3AndL4ClosePublishedAPTAndYUMProtocols|TestVerifySnapshotL1ChecksAssetMaterialization|TestVerifyAndFSCKAuditLocalStrongServingClosure|TestFSCKAuditsS0CompatibilityCarrierAgainstImmutableRef)$' -count=1
ok  github.com/pgsty/sow/internal/cli  56.208s

go test -race ./internal/cli -run '^(TestInitAdoptContentRealAPTAndYUMThenMaterializeVerifyFSCK|TestInitAndFSCKEndToEnd|TestCanonicalFSCKFinalizerFailureIsNeverDiscarded|TestPublicViewWithCanonicalGatedDigestFailsEveryLocalReadGate|TestVerifyCLIL3AndL4ClosePublishedAPTAndYUMProtocols|TestVerifySnapshotL1ChecksAssetMaterialization|TestVerifyAndFSCKAuditLocalStrongServingClosure|TestFSCKAuditsS0CompatibilityCarrierAgainstImmutableRef)$' -count=1
ok  github.com/pgsty/sow/internal/cli  78.230s

go test ./test/compat -run 'TestRealCloudPurgeWatcher(DuplicateProcess|LockTeardown|DurabilityBarriers)' -count=1
ok  github.com/pgsty/sow/test/compat  1.136s

go test -race ./test/compat -run 'TestRealCloudPurgeWatcher(DuplicateProcess|LockTeardown|DurabilityBarriers)' -count=1
ok  github.com/pgsty/sow/test/compat  2.064s
```

After the materialization, bound-Git, L1 spool and YUM-history teardown fixes,
all 678 default CLI tests were exhausted again in ordinary and race modes
through the same six shards used by CI. The two six-process batches include
local disk/CPU contention, but every ordinary shard completed below its 20
minute package timeout, every race shard below its 25 minute timeout, and all
twelve invocations exited zero with no race report:

| Shard | Ordinary | Race |
|---|---:|---:|
| `^Test[A-F]` | 522.845s | 638.368s |
| `^Test[G-M]` | 747.754s | 869.742s |
| `^Test[N-O]` | 250.913s | 295.533s |
| `^Test[P-Q]` | 855.778s | 1073.248s |
| `^Test[R-V]` | 492.494s | 622.440s |
| `^Test([W-Z]\|[^A-Z]\|$)` | 110.902s | 151.309s |

An unsharded `go test ./... -count=1` and an unsharded CLI retry reached their
10m/20m package timeouts while the currently running tests had been active for
only seconds and were consuming CPU in local Git/RSA/SQLite/fsync paths. Every
non-CLI package in the first run passed. The supported exhaustive entrypoint is
therefore the six explicit shards; CI's ordinary CLI shard timeout was raised
from 15m to 20m and its job budget from 20m to 30m to avoid slow-runner flakes.
This records the timeout honestly rather than treating it as a pass.

The delivery policy includes the new descriptor and manifest fault-injection
tests and then passed:

```text
go test ./test/compat/cleandelivery -count=1
ok  github.com/pgsty/sow/test/compat/cleandelivery  2.238s
```

Current ordinary tests for every non-CLI package passed with real-cloud and
real-upstream switches disabled; the longest package was `internal/state` at
28.085s. Focused output/recovery regressions passed ordinary and race, and the
broader changed local-serving/L3 set passed ordinary at 22.531s and race at
29.629s. Cloudflare bootstrap/provider-attestation loopback tests passed
ordinary and race. The patched RPM parser module also passed.

`go vet ./...`, `go vet -tags perf ./internal/cli ./test/perf`, both module
integrity checks, four static `darwin/linux × amd64/arm64` builds, and
`git diff --check` exited zero. Staticcheck `v0.6.1` now has no default
correctness/simplification/deprecation finding under the explicit reproducible
profile below; intentional nil-context and pinned SDK/platform exceptions are
suppressed at their exact statements:

```text
staticcheck -checks='inherit,-ST1005,-U1000' ./...
PASS
```

The two exclusions are not presented as passed checks: raw Staticcheck retains
112 `ST1005` operator/protocol wording findings and 40 `U1000` compatibility or
test wrappers. `errcheck -ignoretests ./internal/...` was also inspected rather
than claimed green: after the CLI sink boundary, its remaining output consists
of read/iterator closes, failure cleanup/removal, transaction rollback, hash
writes, and the now centrally observed terminal writes; no unchecked durable
`Sync`, `Rename`, `Link`, commit, or upload operation was found.

The generated edge bundles remained byte-identical and all 41 shared
Cloudflare/EdgeOne contract tests passed. `govulncheck v1.6.0` found no reachable
vulnerability in the main or patched RPM module; it reported one required main
module advisory as unreachable. No `TODO`, `FIXME`, product panic, or external
runtime command was found by the production-source scan.

The post-document clean-delivery closure uses 535 product-source files and 679
delivery files. Two independent fresh HOME/GOMODCACHE/GOCACHE runs must agree
byte-for-byte; their non-self-referential product, delivery and archive
identities are recorded outside the delivery root in
`_bmad-output/implementation-artifacts/validation-selected-set-materialization-2026-07-13.md`.

After the descriptor and L1 teardown changes, the full Docker/Nginx compatibility
package was rerun with every real-cloud/real-edge/real-upstream switch and cloud
credential explicitly cleared. Real apt 1.2/2.4, YUM 3, EL8 gzip DNF and EL9/10
zstd DNF generation, signing, consumption and negative gates passed in
`139.249s`; all origins were disposable loopback fixtures and no production or
cloud repository was accessed.

## Remaining boundary

These local results do not upgrade any real Cloudflare/EdgeOne/COS readiness,
dual-cloud drift, production migration, purge observation, or operational
metric. Those matrix entries remain blocked or unverified exactly as before.
