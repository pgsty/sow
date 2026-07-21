# Derived-state and recovery-residue identity — 2026-07-22

## Findings

The projection recovery scanners enumerated orphan stage/config residues,
checked the current pathname with `Lstat`, then removed the pathname. A
replacement between those operations was deleted by explicit `--recover`.

The shared derived-state writer had several related problems. Its temporary
name was a predictable 64-bit prefix of the body digest and was
unconditionally removed before create. Its failure defer also removed that
pathname without retaining the inode it created. A replacement after write
verification but before `Rename(temp, destination)` could be installed as
canonical derived state. Metadata-only validation also accepted same-inode,
same-size bytes after their mtime was restored. The writer did not bind the
public state-root or leaf-directory coordinates, so a directory replacement
could make it mutate a detached tree and report success. Finally, it computed
the expected digest after a test boundary, allowing the caller-owned body and
temporary to be mutated together, and it silently discarded cleanup failures.

Fault tests reproduced every issue before the fix: both asset/package residue
scanners deleted replacement canaries; the writer deleted a pre-existing
deterministic canary and a failure-time replacement; and the final install
published replacement bytes over an existing canonical file. A further red
test modified the writer-owned inode in place, preserved its size and restored
its mtime; metadata-only validation still published those incorrect bytes.
Additional red tests replaced the leaf directory and state root, mutated both
the caller buffer and temporary, and forced a cleanup race. The old writer
respectively reported success against a detached tree, accepted the wrong
bytes, and hid the cleanup failure.

The adversarial review then exposed a second layer: three journal recovery
contracts recognized only the legacy 16-hex temporary suffix, not the new
32-hex write temporary or install-isolation names; their cleaners still used
`Lstat(path) -> Remove(path)`; the shared quarantine was not revalidated after
its callback and hid unlink/fsync errors; the writer closed its retained inode
before failure cleanup and did not revalidate isolation after the final hash.
Fault tests reproduced all of these behaviors before the review fixes.

## Resolution

Asset/package residue recovery now binds both the public state-root coordinate
and private orphan inode, then uses no-replace quarantine plus descriptor
revalidation. A replacement is restored without overwrite and recovery fails
closed. Exact empty residues and a concurrently disappeared residue remain
idempotent. Quarantine is revalidated after the caller callback and immediately
before unlink; unlink and final directory-sync failures are returned.

Materialization-selection, local-serving and topology-removal recovery share
one strict name contract covering legacy 16-hex write temps, current 32-hex
write temps, 32-hex install isolation, and removal-quarantine residue. All
three cleaners now use the same descriptor-bound exact removal primitive and
retain their file-size bounds.

`writeDerivedStateFile` now:

1. freezes the expected size and SHA-256 at function entry;
2. binds the real state-root and leaf-directory inodes to their public
   coordinates and rechecks both before and after installation;
3. creates a 128-bit random, create-only temporary below the descriptor-bound
   leaf directory and never pre-deletes another pathname;
4. retains the created inode through write, fsync, size and coordinate checks;
5. cleans failure residue only when the current temporary is that exact inode,
   and joins cleanup/close failures into the returned error;
6. moves the candidate with no-replace into a second random isolation name,
   verifies inode/size/mode/mtime and the frozen SHA-256 through the retained
   read/write descriptor, revalidates after the final fault boundary, and only
   then atomically replaces the canonical destination;
7. restores a replacement without overwrite and leaves prior canonical bytes
   unchanged on mismatch;
8. keeps the retained descriptor open through installation and verifies the
   installed destination inode and bytes before reporting success.

The shared quarantine primitive is used by projection intent, stage, residue
and derived-state cleanup. Linux/macOS remain the supported runtime targets.

## Current-source verification

```text
# Red results before the fixes
go test ./internal/cli -run \
  'Test(Asset|Package)ProjectionRecoveryPreservesConcurrentResidueReplacement' \
  -count=1
FAIL: both scanners accepted and deleted replacement residues (0.884s)

go test ./internal/cli -run \
  'TestDerivedStateWrite(PreservesLegacyDeterministicTemporary|FailureCleanupPreservesConcurrentReplacement)' \
  -count=1
FAIL: both temporary canaries were deleted (0.857s)

go test ./internal/cli -run \
  'TestDerivedStateWriteRefusesConcurrentTemporaryReplacementBeforeInstall' \
  -count=1
FAIL: replacement bytes were installed as canonical state (1.039s)

go test ./internal/cli -run \
  '^TestDerivedStateWriteRefusesInPlaceMutationWithRestoredMetadata$' -count=1
FAIL: in-place mutated bytes were installed as canonical state (0.860s)

go test ./internal/cli -run \
  '^TestDerivedStateWriteRejectsReplacedParentDirectoryBeforeInstall$' -count=1
FAIL: detached parent mutation was reported as success (0.885s)

go test ./internal/cli -run \
  '^TestDerivedStateWriteRejectsReplacedStateRootBeforeInstall$' -count=1
FAIL: detached state-root mutation was reported as success (0.910s)

go test ./internal/cli -run \
  'TestDerivedStateWrite(FailureCleanupPreservesConcurrentReplacement|FreezesExpectedBodyBeforeHooks)' \
  -count=1
FAIL: cleanup failure was hidden and hook-mutated expected bytes were accepted (0.916s)

# Red results produced by adversarial review
go test ./internal/cli -run \
  'Test(DerivedStateRecoveryRecognizesCurrentTemporaryNames|DerivedStateRecoveryPreservesConcurrentTemporaryReplacement|ExactPrivateStateRemovalRevalidatesQuarantineAfterCallback|DerivedStateWriteRevalidatesIsolationAfterFinalHash)' \
  -count=1
FAIL: six current temp/install residues survived, three legacy cleaners bypassed
exact replacement fencing, quarantine replacement was deleted, and post-hash
replacement was published (0.954s)

go test ./internal/cli -run \
  '^TestProjectionRecoveryRejectsReplacedStateRootAfterResidueBind$' -count=1
FAIL: detached state-root cleanup was reported as success (0.878s)

go test ./internal/cli -run \
  '^TestProjectionRecoveryTreatsConcurrentResidueDisappearanceAsIdempotent$' -count=1
FAIL: concurrent exact disappearance returned unsafe-residue failure (0.957s)

# Final exact/missing/empty/replacement recovery and writer commit/failure paths
go test ./internal/cli -run \
  'Test(DerivedState|DerivedPublicationState|AssetProjectionRecovery|PackageProjectionRecovery|ProjectionRecovery|LocalServingJournalRecovery|ServingTopologyRecovery|SyncJournalTempCleanup)' \
  -coverprofile=/tmp/sow-v75-review.cover -count=1
PASS 4.411s

go test -race ./internal/cli -run \
  'Test(DerivedState|DerivedPublicationState|AssetProjectionRecovery|PackageProjectionRecovery|ProjectionRecovery|LocalServingJournalRecovery|ServingTopologyRecovery|SyncJournalTempCleanup)' \
  -count=1
PASS 6.436s

go test ./internal/cli -count=1 -timeout=25m
PASS 1246.716s

go test -race ./internal/cli -run \
  'Publish|Projection|MaterializationSelection|DerivedState|LocalServingJournal|ServingTopology' \
  -count=1 -timeout=20m
PASS 704.559s

go vet ./...
staticcheck ./...
git diff --check
PASS

go list ./... | rg -v '^github.com/pgsty/sow/internal/cli$' | \
  xargs go test -count=1 -timeout=5m
PASS: every non-CLI functional package. The first clean-delivery run correctly
rejected the new test file until it was added to the sorted product allowlist;
the final clean-delivery rerun passed.

# Final Linux arm64 binary, read-only workspace, no network, tmpfs scratch
docker run --rm --platform linux/arm64 --network none --read-only \
  --mount type=bind,src=/tmp/sow-v75-reviewed-linux-arm64.test,dst=/sow.test,readonly \
  --mount type=bind,src="$PWD",dst=/workspace,readonly \
  --tmpfs /tmp:rw,exec,nosuid,nodev --workdir /workspace/internal/cli \
  debian:13-slim /sow.test \
  -test.run='Test(DerivedState|DerivedPublicationState|AssetProjectionRecovery|PackageProjectionRecovery|ProjectionRecovery|LocalServingJournalRecovery|ServingTopologyRecovery|SyncJournalTempCleanup)' \
  -test.count=1
PASS (0.9s wall)
```

Focused coverage reports bounded projection-residue removal at 73.1%, shared
exact quarantine commit at 75.8%, derived-state write at 77.5%, exact install
at 81.6%, byte verification at 83.3%, shared temporary-name parsing at 75.0%,
and the three bounded journal cleaners at 88.2%, 88.2% and 76.5%. Static test
binaries compiled with `CGO_ENABLED=0` for Darwin amd64/arm64 and Linux
amd64/arm64. Their SHA-256 values are respectively
`86c383a0263045f761cbf8e6164f70ecce9236cc67ec5178f2557bfd974804db`,
`dedb491c7063d3168b6ea7f4cd826841676985f38c06c9a4c3bdfb5fe6485922`,
`e64e9854fee9d3a132ddaef22454ff94e33d043635f4ac979315eb660a04827b`,
and `d68233112ff47781f1da668bac4801db3800767d84cf728bbce31f8c7dfadcc3`.

## Boundary

All mutation occurred below local temporary roots. No credential, network,
cloud resource, production repository or production local tree was accessed.
This is local state/recovery hardening only and does not upgrade Cloudflare
Worker/purge/cache-log, COS/EdgeOne, production migration or operational-metric
acceptance status.
