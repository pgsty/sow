# 2026-07-22 materialization target hostability preflight

Status: local ordinary/race, static and real CLI smoke gates passed. No cloud
or production resource was accessed.

## Red finding

The real CLI was first exercised from `/tmp/sow-mvp-demo`. On macOS `/tmp` is
a symlink to `/private/tmp`. `materialize latest` printed that it had linked the
asset and committed the working tree, then failed while persisting exact route
receipts:

```text
materialize materialized view=latest repo=asset entries=1 linked=1 ...
working tree committed=... changed=true ...
persist exact local Nginx route receipts: materialized route target is not
Nginx-worker traversable: Nginx worker directory tmp/... is not a real directory
```

The regression test captured the same old behavior: one payload was installed
and canonical HEAD advanced before the error. A recovery attempt using the
canonical `/private/tmp` spelling could not reuse the journal because target
identity intentionally binds the lexical absolute path.

## Correction

`runMaterialize` now performs a read-only target hostability preflight before
the state lock and every materialization mutation. The preflight:

- resolves a clean absolute coordinate without following it;
- walks upward to the deepest existing ancestor;
- rejects a symlink or non-directory ancestor;
- verifies the complete existing absolute directory chain is traversable by an
  unprivileged Nginx worker;
- permits missing descendants without creating them.

The existing retained-root final validation remains in place. The hardlink
installer already opens and creates target components one at a time through
retained directory descriptors, so a concurrent symlink substitution cannot
turn the allowed missing suffix into an unsafe write path.

## Commands and results

```bash
go test ./internal/cli \
  -run '^TestMaterialize(PreflightsSymlinkedRepositoryRootBeforeMutation|HostabilityPreflightAllowsMissingTargetBelowSafeAncestor|HostabilityPreflightRejectsSymlinkAncestor)$' \
  -count=1
go test -race ./internal/cli \
  -run '^TestMaterialize(PreflightsSymlinkedRepositoryRootBeforeMutation|HostabilityPreflightAllowsMissingTargetBelowSafeAncestor|HostabilityPreflightRejectsSymlinkAncestor)$' \
  -count=1
```

Focused ordinary/race passed in 1.644s/2.662s. Focused atomic coverage reports
78.9% for `preflightMaterializedRouteTargetHostability`.

```bash
go test -timeout 20m -count=1 ./internal/cli -run '^TestMaterialize'
go test -race -timeout 30m -count=1 ./internal/cli -run '^TestMaterialize'
```

All materialize tests passed in 139.808s/187.224s with no race report.

With cloud credentials removed and every real-cloud/edge/upstream/Docker
opt-in set to zero, the affected G-M shard passed in 453.454s ordinary and
612.668s race. `go vet ./...`, `staticcheck ./...` and `git diff --check` also
passed.

The freshly built Darwin/arm64 binary
`/private/tmp/sow-mvp-v2` has SHA-256
`aa652099125d6f053df06a4644dcd6ab98b4e378f20a67f0f622cf9d9cbce2cb`.
Against a new `/private/tmp/sow-mvp-demo-v2` repository it completed:

```text
init -> add asset -> promote beta latest -> materialize latest
verify L1: passed, errors=0, critical=0
fsck: drift=0, materialized route ledgers=1
gc: reachable=1, orphans=0, missing=0
```

The materialized `asset/tool.bin` and its `.pool/sha256/...` object both had
inode `115397624`, proving the smoke used a real CAS hardlink rather than a
copy or mock adapter.

## Boundary

The real CLI smoke wrote only to fresh directories under `/private/tmp`; Go
tests used their own temporary roots and loopback protocol fixtures. Cloud
credentials were absent, external-network/provider opt-ins were zero, and
neither the authorized empty `pro` R2 bucket nor any Cloudflare, CO/COS,
EdgeOne or production repository was read or written. V-59 closes this local
failure-order defect only; it does not upgrade real-cloud, CDN or production
migration status.
