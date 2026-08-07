# 0.3 single-payload implementation evidence — 2026-08-05

## Claim boundary

本记录证明当前开发 checkout 已把 `design/next` 的 Repository-scoped single-payload
架构落入源码，并通过本地 unit/fault/mock verification。它不是 release-candidate retained
lab：尚未提交 `fixture-lock.json`，没有使用真实云凭据，也没有把历史 v0.2/V1 客户端或
Cloudflare 结果冒充成当前 0.3 PASS。

| Evidence layer | Current status |
| --- | --- |
| Source / wire | IMPLEMENTED — `sow/v3` config、schema v7/v8、Repository UUID、20-digit GenerationID、single-payload renderer/checker、explicit-only migration、retained/export/publication/abandoned-object records |
| Local repository | LOCALLY VERIFIED — root `pool/ + dists/`、RPM computed parent-relative href、APT raw `Filename`/encode-once/by-hash、exact Generation/Changeset、local GC |
| Compatibility export | LOCALLY VERIFIED — `sow-rpm-leaf-v1`, copy default, same-filesystem hardlink opt-in, exact manifest and marker-last verification |
| Filesystem publication | LOCALLY VERIFIED — path/key one-to-one, effective-path overlap fence, pre-commit abandon/reuse, mutable-alias/pointer commit boundary, crash replay, published-pointer withdrawal fence, grace, conditional delete and absence receipt |
| R2 publication | MOCK VERIFIED — strict credential references, list/head/get/conditional put, public GET verification, multi-target state and retain/report-only target GC; no DeleteObject path |
| Real APT/DNF HTTP clients | UNVERIFIED for this checkout |
| Default EL reposync on canonical Repository | UNSUPPORTED by product contract; pinned v0.2-era AlmaLinux 9 negative remains historical evidence |
| Default EL reposync on completed export | UNVERIFIED; required before calling export a verified fallback |
| Real nonproduction Cloudflare R2 | UNVERIFIED; requires explicit user authority and fixture lock |
| R2 physical remote deletion | DISABLED by design; candidate report only |
| Third-party repository managers / proxies | UNVERIFIED |

## Implemented surfaces

- Public Repository and every publish prefix expose only `pool/ + dists/`; no `release/`,
  `reposync/`, public control object, per-view package alias, per-generation package tree or
  per-snapshot package tree is created.
- `sow repo migrate` owns the v0.2 C2 transition through a private forward-only journal and exact
  alias deletion receipts. Frozen v0.2 config/state remains readable without mutation; ordinary
  writers cannot migrate it implicitly. `repo migrate --abort` is pre-commit only. Ordinary changes,
  publication and GC fail closed while a transition is nonterminal.
- `sow retain add|ls|rm` stores exact metadata and payload refsets without package copies.
- `sow publish TARGET` owns a target-scoped attempt/checkpoint/grace state. Filesystem and R2
  adapters share the state machine, but their remote-delete capabilities are intentionally different.
  `publish TARGET --abort` reconciles only a pre-commit attempt, removes local filesystem stage,
  preserves exact add-only remote-object evidence and performs no remote copy/delete. Mutable APT
  stable aliases and protocol pointers are written only after commit intent. Configured targets with
  Applied Checkpoints fence local removal of their Dist/architecture/signing pointers.
- `sow gc` performs Repository-local reference-closure GC. `sow gc TARGET` performs target
  maintenance; filesystem can conditionally delete after grace/absence proof, while R2 persists an
  exact retained-candidate report and reports zero reclaimed bytes.
- `sow export rpm-leaf DIST ARCH DIR [--hardlink]` creates an external, disposable standalone
  RPM leaf, including managed basenames with literal `:`/`%`. It rejects overlap with the Repository,
  `.sow`, or configured filesystem publication roots and never becomes Membership, Generation,
  publish input or GC root.

## Local verification commands

The final command transcript and outcome are filled by the current-turn verification pass. These
commands are the required local evidence set, not substitutes for the live matrix:

```text
go test ./internal/aptrepo ./internal/yumrepo ./internal/v2/...
go test ./internal/v2/managed -race
go test ./...
go vet ./...
go mod verify
go mod tidy -diff
CGO_ENABLED=0 GOOS={linux,darwin} GOARCH={amd64,arm64} go build ./cmd/sow
git diff --check
```

## Outstanding release evidence

Before a release compatibility claim, create the immutable fixture lock required by
[`../specs/acceptance-matrix.md`](../specs/acceptance-matrix.md), then retain current-checkout
transcripts for APT/DNF file+HTTP, default reposync negative, completed-export reposync positive,
whole-root relocation, and an explicitly authorized nonproduction R2 prefix. Until then, those
cells stay `UNVERIFIED` even when the implementation and mocks are green.
