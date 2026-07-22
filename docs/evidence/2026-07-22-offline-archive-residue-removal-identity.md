# Offline archive residue removal identity evidence

Date: 2026-07-22

Scope: V-79, local filesystem and isolated Linux container only

Baseline: `cbeb439`

## Defect and red evidence

`cleanupOfflineArchiveProjectionResidue` enumerated an intent temporary or
archive stage, checked it with `Lstat`, and later removed the pathname. A file
replacement between those operations inherited deletion authority. Before the
fix, both deterministic replacement tests failed because cleanup returned
success and deleted the replacement:

```text
TestOfflineArchiveIntentTempCleanupPreservesConcurrentReplacement
TestOfflineArchiveStageResidueCleanupPreservesConcurrentReplacement
FAIL 3.402s
```

The scanner also lacked a strict failure contract for malformed siblings,
could not converge after a second crash created a nested removal quarantine,
and did not revalidate intent ownership or retained root coordinates on every
successful branch.

## Implemented closure

- Intent residues are admitted only by the exact derived-state grammar plus
  strict one-or-more `.tmp-remove-<32-lower-hex>` recovery suffixes. Stage
  residues require an exact transaction final/temp grammar. Unknown siblings
  in either owned namespace fail closed.
- State-root intent temporaries require complete mode `0600` and at most 1 MiB;
  archive stages require complete mode `0444`. Symlinks, FIFOs, devices,
  permission variants and special mode bits are rejected before a blocking
  open or deletion.
- Cleanup retains a no-follow/nonblocking descriptor and exact inode identity,
  then performs a no-replace quarantine rename. Coordinate, inode, type, mode,
  size and mtime are rechecked through the final unlink boundary; the exact
  parent is fsynced. A reoccupied original coordinate preserves both the
  replacement and the admitted inode at quarantine.
- Replaying an already quarantined residue strips only strict offline-archive
  removal suffixes to a stable base. A second interruption therefore replaces
  one quarantine suffix instead of growing an unrecoverable nested name;
  legacy nested strict names are accepted and converge.
- Stage deletion is authorized against an intent snapshot read through the
  retained state-root descriptor. Appearance, disappearance or ID change of
  the intent, including a new intent that owns the stage, aborts deletion.
  Bound state/stage roots are revalidated on removal and no-removal branches;
  an initially absent stage coordinate must remain absent.
- The shared derived-state writer now establishes and rechecks exact `0600`
  before publication. On Linux/macOS, package initialization clears inherited
  owner-mask bits (`0700`) while preserving group/other restrictions, so
  `0600` files and `0700` directories have their exact mode from creation and
  no pre-`chmod` SIGKILL residue window exists.

## Failure-injection matrix

Current-source tests cover different-inode replacement after enumeration and
binding, FIFO replacement without blocking, replacement at the final unlink
seam, reoccupation of the original coordinate, root and stage-directory
replacement, malformed names, nested crash quarantines, exact-mode rejection,
same-inode mode mutation, restrictive inherited umask, a newly owning intent,
an appearing stage tree, non-`--recover` preservation, successful recovery and
idempotent replay. Each destructive negative asserts surviving bytes at both
the original and displaced/quarantine coordinates as applicable.

## Current-source verification

All real-cloud, real-edge and real-upstream opt-ins were disabled. No command
contacted an object store, CDN, provider control plane, upstream package
repository or production repository.

```bash
go test ./internal/cli \
  -run 'Test(SOWProcessInitNormalizesRestrictiveOwnerUmask|OfflineArchive.*(Residue|Temp|Stage|Owned)|DerivedStateWriter)' \
  -count=1
# PASS 13.589s

go test -race ./internal/cli \
  -run 'Test(SOWProcessInitNormalizesRestrictiveOwnerUmask|OfflineArchive.*(Residue|Temp|Stage|Owned)|DerivedStateWriter)' \
  -count=1
# PASS 20.383s; no race report

go test ./internal/cli \
  -run 'TestOfflineArchive(ResidueCleanupRequarantinesWithoutNesting|IntentTempCleanupRejectsReoccupiedCoordinate|StageCleanupRejectsNewOwningIntent|ResidueNoDeleteBranchRevalidatesStateRoot|ResidueNoStageBranchRejectsAppearingStageCoordinate|OwnedStageBranchRevalidatesStageRoot|ResidueCleanupRequiresExactModes)$|TestDerivedStateWriter(RepairsRestrictiveUmaskToExactPrivateMode|RejectsSameInodeModeMutation)$' \
  -count=50
# PASS 4.748s

go test ./internal/cli \
  -run 'OfflineArchive|DerivedStateRecovery|ProjectionStageNameClassification' \
  -count=1
# PASS 63.351s

go test -race ./internal/cli \
  -run 'OfflineArchive|DerivedStateRecovery|ProjectionStageNameClassification' \
  -count=1
# PASS 83.872s; no race report

go test ./... -count=1 -timeout=30m
# CLI 1370.025s; every package PASS
# publish 21.745s; repository 22.215s; serving 33.935s; state 51.219s
# upstream 31.714s; verify 22.156s; yumrepo 28.864s
# compat 33.033s; clean-delivery 8.712s

go test ./internal/cli \
  -run '^TestSOWProcessInitNormalizesRestrictiveOwnerUmask$' -count=10
go test -race ./internal/cli \
  -run '^TestSOWProcessInitNormalizesRestrictiveOwnerUmask$' -count=1
# PASS 1.223s / 2.844s

go vet ./internal/cli
staticcheck ./internal/cli
git diff --check
# PASS
```

The same final tree also passed `go vet ./...`, `staticcheck ./...`, `go mod
verify`, the nested patched RPM module test suite, and the fixed
`govulncheck@v1.6.0` root plus nested-module gates. The reachable scan reported
zero vulnerabilities; two required-module advisories were unreachable from
product code. The first official-proxy tool fetch timed out, then the identical
fixed version completed through `goproxy.cn`; neither scan accessed a product
repository, object store or provider API.

The focused coverage run reports 86.9% for the scanner, 100% for both exact
mode policies, the offline temporary parser, suffix stripper and stage
classifier, 86.7% for descriptor binding, 76.7% for the exact remover, 76.3%
for the shared commit primitive and 72.4% for the generic writer.

`CGO_ENABLED=0 go test -c -trimpath ./internal/cli` produced current-source
test binaries for all supported target pairs:

| Target | SHA-256 |
|---|---|
| Darwin amd64 | `b59f0ab054fdc06521b24c3aea229dc68c375d7420363ac1bddafd59f644595a` |
| Darwin arm64 | `046bdf8b8e594e48c5c940cd6f7d0d1a53f5440d5b4c46ffd1e8214636a3afd8` |
| Linux amd64 | `52ce7324167e72102e46a0b23f59a3a58813dd1d5fa001d718e37953b97298f7` |
| Linux arm64 | `eabb8f7bbf493618199ee437c303c263a9e21d52b051f264d5a9898f2475f020` |

The Linux arm64 binary ran the focused set as root in `debian:13-slim` with
`--network none`, a read-only container and read-only binary/source mounts;
only `/tmp` was a writable `nosuid,nodev` tmpfs. It exited `PASS`, including
the inherited-umask subprocess and FIFO/replacement tests.

The umask subprocess inherits `0500` before package initialization and must
create an exact `0700` directory containing an exact `0600` file. This is a
creation-time proof, not a post-test chmod assertion.

## Review disposition and external boundary

Blind Hunter and Edge Case Hunter independently returned `[]` on the final
source. Their earlier findings drove the stable quarantine base, original
coordinate absence fence, bound intent snapshot, no-delete root fence,
post-write exact-mode check and full owner-umask normalization.

All mutations occurred below isolated local temporary roots. This run did not
read or write `pro`, Cloudflare resources, CO/COS, any object store, CDN,
Worker, EdgeOne function, upstream package repository or production
repository. It strengthens FR-28/NFR-09 interruption, recovery and idempotency
evidence only; it does not upgrade any real-cloud, provider, CDN or production
migration status.
