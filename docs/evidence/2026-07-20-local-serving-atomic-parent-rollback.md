# 2026-07-20 local serving atomic parent rollback

Status: final local ordinary/race, static, migration and delivery gates passed.
No cloud or production resource was accessed.

## Red finding

`rollbackLocalServingMirrorlist` previously performed two independent actions:
remove the just-installed child, then call `RestoreMirrorlist` on the supplied
parent. A valid channel with another URL was accepted with `err=<nil>` even
though its mirrorlist digest was not the child's sealed parent digest. The same
code also accepted a different target partition when its URL and rendered
pointer bytes happened to match.

That created two failures of authority: the helper could restore the wrong
parent, and the coordinate was absent between deletion and restoration.

## Correction

The helper now validates before mutation and requires:

- exact view/repo/OS/arch and mirrorlist path;
- exact `ParentGeneration` and `ParentMirrorlistSHA256`;
- ordinary current target ID, or migrated `ParentTargetID` when present;
- exact target root.

It then passes the rendered, digest-bound parent body to
`serving.RollbackMirrorlist`, which verifies the current child body and performs
one expected-child-to-parent atomic replacement. A nil parent uses the same
primitive to restore first-install absence.

## Commands and results

```bash
go test -count=1 ./internal/cli \
  -run '^TestRollbackLocalServingMirrorlistBindsExactParentAndPriorState$'
go test -race -count=1 ./internal/cli \
  -run '^TestRollbackLocalServingMirrorlistBindsExactParentAndPriorState$'

go test -count=1 -covermode=atomic -coverpkg=./internal/cli \
  -coverprofile=/tmp/sow-local-serving-rollback.out ./internal/cli \
  -run '^TestRollbackLocalServingMirrorlistBindsExactParentAndPriorState$'

go test -count=1 ./internal/cli \
  -run '^Test(DedicatedPartialPublicMaterializeDropsOutOfScopeGatedServingTree|RollbackLocalServing|LocalServing|MaterializeRecoverMigratesLegacyUnpartitionedServingChannel|GCLocalServing)'
go test -race -count=1 ./internal/cli \
  -run '^Test(DedicatedPartialPublicMaterializeDropsOutOfScopeGatedServingTree|RollbackLocalServing|LocalServing|MaterializeRecoverMigratesLegacyUnpartitionedServingChannel|GCLocalServing)'
```

Focused ordinary/race passed in 0.960s/1.888s; the helper reached 76.9%
focused statement coverage. The complete adjacent local-serving/trust/recovery
group passed in 43.774s/56.955s with no race report.

Final affected shards passed:

| shard | ordinary | race |
| --- | ---: | ---: |
| G-M | 690.728s | 822.653s |
| R-V | 473.754s | 601.655s |

Compile-only, `go vet ./...`, repository Staticcheck, root tidy-diff and module
verification passed. The hermetic family E2E gate passed 44 families, five
mutation negatives and 16 real CLI flows in 168.235s with external network
disabled and production mutation none. The independent local adoption/rollback
suite also passed.

After this report, its spec, trace row and delivery allowlist were frozen, two
isolated clean deliveries were rebuilt with the local read-only module proxy
and compared bytewise. Their final non-self-referential identity is recorded in
the delivery-external V-54 section of
`_bmad-output/implementation-artifacts/validation-selected-set-materialization-2026-07-13.md`.

## Boundary

Tests use real files, atomic mirrorlist operations, valid generated channels
and target identities under temporary roots. Credentials and cloud opt-ins are
absent. V-53 closes the local rollback-authority defect only; it does not
upgrade real-cloud, CDN, production migration or operational metrics.
