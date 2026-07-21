# 2026-07-20 retained YUM authority and verifier credential closure

Status: final local ordinary/race, static, migration and delivery gates passed.
No cloud or production resource was accessed.

## Red findings

`mergeRetainedYUMPackageClosure(nil, nil, ...)` previously returned `nil` and
copied the current manifest. That discarded the obligation to prove packages
still referenced by retained YUM generations. The red test observed:

```text
missing retained-generation authority was accepted: <nil>
```

`networkCredentialCheck` previously returned an internal error. The verifier
converted it into generic `VERIFY_CHECK_OPERATIONAL`, so the operator could not
distinguish missing credentials from another operational check failure.

## Corrections

The retained closure now fails before creating its destination when canonical
authority is absent, and also rejects a channel whose canonical history yields
no generation pins. The old copy-only fallback is deleted.

The credential check now records the safe stable code
`CDN_VERIFICATION_CREDENTIAL_UNAVAILABLE`, keeps the report incomplete, and
maps the CLI to `ExitNetworkAuth`. The finding contains neither provider error
details nor secret values.

Adjacent boundary tests also prove that selected YUM export excludes physical
owner siblings, manifest-only adoption freezes `default_pool`, and duplicate
APT by-hash stages require byte equality.

## Current commands and results

```bash
go test -count=1 ./internal/cli \
  -run '^Test(MergeRetainedYUMPackageClosureRejectsMissingCanonicalAuthority|NetworkCredentialCheckReportsActionableOperationalFinding)$'
go test -race -count=1 ./internal/cli \
  -run '^Test(MergeRetainedYUMPackageClosureRejectsMissingCanonicalAuthority|NetworkCredentialCheckReportsActionableOperationalFinding)$'

go test -count=1 ./internal/cli \
  -run '^Test(MergeRetainedYUMPackageClosureRejectsMissingCanonicalAuthority|NetworkCredentialCheckReportsActionableOperationalFinding|VerifyCLIStableUsesRuntimeTokenWithoutPersistingOrLoggingIt|SelectedMaterializationArchiveExactExcludesPhysicalOwnerSiblings|DefaultPoolCannotReclassifyAdoptedManifestWithoutView|MergeAPTByHashStagesRequiresByteIdenticalDuplicate)$'
go test -race -count=1 ./internal/cli \
  -run '^Test(MergeRetainedYUMPackageClosureRejectsMissingCanonicalAuthority|NetworkCredentialCheckReportsActionableOperationalFinding|VerifyCLIStableUsesRuntimeTokenWithoutPersistingOrLoggingIt|SelectedMaterializationArchiveExactExcludesPhysicalOwnerSiblings|DefaultPoolCannotReclassifyAdoptedManifestWithoutView|MergeAPTByHashStagesRequiresByteIdenticalDuplicate)$'

go vet ./...
staticcheck ./...
```

The two red tests pass after correction in 0.921s ordinary and 1.763s race.
The larger focused gate passes in 9.604s ordinary and 15.683s race. Focused
coverage reaches 100% for `networkCredentialCheck`, 83.3% for exact selected
archive projection, 72.7% for canonical pool lookup and 71.4% for bytewise
duplicate comparison. Vet and repository Staticcheck pass.

Final affected CLI shards pass with real CLI/filesystem tests and all real
cloud, upstream and Docker opt-ins disabled:

| shard | ordinary | race |
| --- | ---: | ---: |
| A-F | 654.923s | 786.911s |
| G-M | 911.396s | 1075.528s |
| R-V | 677.747s | 794.544s |

The hermetic family migration gate passes 44 families, five mutation
negatives and 16 real CLI flows in 191.809s, with external network disabled
and production mutation none. The independent zero-byte adoption,
materialization and byte-exact rollback suite also passes. After this report,
its spec, trace row and delivery allowlist were frozen, two isolated clean
deliveries were compared bytewise, and their non-self-referential identity was
recorded in the external V-56 section of
`_bmad-output/implementation-artifacts/validation-selected-set-materialization-2026-07-13.md`.

## Boundary

All evidence above uses temporary local files, real CLI dispatch and the real
verification report/exit path. Cloud credentials and real-cloud opt-ins are
absent. This slice does not upgrade Cloudflare, COS/EdgeOne, CDN purge,
production migration or operational-metric status.
