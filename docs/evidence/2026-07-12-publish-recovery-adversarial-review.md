# Publish/recovery adversarial review evidence (2026-07-12)

Source identity: 320 product-source files, aggregate SHA-256
`667ad529751a9a975944fa51dbcd52e30e36b40d19a5203c9a4d084ddeeae5b6`.

## Scope and method

The final publication block was reviewed independently in three layers: blind
defect hunting, branch/boundary enumeration, and PRD acceptance auditing. A
second no-edit regression pass then inspected every CLI callsite after the
first fixes. The review treated a persisted `Plan` and `Request` as untrusted
recovery input: a plan is not allowed to prove its own forged route, digest,
generation, deletion authority, or cache closure.

The review produced no unresolved decision item. Ten initial patch groups and
eight follow-up recovery findings were implemented. One item remains explicitly
deferred: the two-key raw YUM `repomd.xml`/`.asc` compatibility window, recorded
in `_bmad-output/implementation-artifacts/deferred-work.md`; the supported strong
route is the generation-pinned mirrorlist.

## Closed findings

- Object classes are a closed union; nil manifest readers fail with errors;
  `WithCDN` detaches caller slices; full-change verification is O(N), not O(N²).
- Pointer and deletion CDN paths are bound to exact latest/beta/stable/snapshot
  namespaces. Presence/absence collisions and non-canonical CDN bases fail.
- Stable transformed mirrorlist verification is derived from canonical
  `ChannelState`; arbitrary digest overrides cannot bless stale cache bytes.
- APT and YUM generation keys must name the request generation. Snapshot route
  JSON is produced by one shared `SnapshotRouteBody` encoder and is re-derived
  from the request intent during recovery.
- Snapshot payload namespaces accept create-only classes. A snapshot route,
  package and self-declared digest cannot substitute for missing YUM metadata:
  every snapshot YUM payload leaf requires exactly one primary, filelists,
  other, `repomd.xml`, and `.asc` object.
- Normal YUM publications validate a bidirectional O(objects+channels) closure:
  every current generation leaf has all five metadata objects, byte-identical
  raw aliases, a current `ChannelState`, and the exact static/dynamic
  generation-pinned pointer; aliases and pointers cannot exist without the
  corresponding immutable generation.
- Every serving deletion is bound to the request view. Snapshot retention may
  accompany another intent only after the new target ref vector no longer
  retains that snapshot.
- Already-committed recovery reissues the complete normalized purge set before
  L3 verification, including both client URLs and internal `.sow/*` clean-cache
  keys. Provider tests assert the exact Cloudflare purge POST and signed object
  DELETE calls.

## Reproducible gates

```text
go test -count=1 ./internal/publish
  PASS, 4.786s in the final review pass

go test -race -count=1 ./internal/publish
  PASS, 9.200s in the final all-race pass

go test -count=1 ./internal/cli -run 'Snapshot|PublishCLIRecoversRemoteCheckpointCommittedBeforeLocalRemoteRef'
  PASS, 35.069s

go test -count=1 -run '^TestPlanLargeClosureValidationIsLinearInChangedObjects$' -v ./internal/publish
  objects=50000 elapsed=92.766291ms, PASS

go test -count=1 ./...
  PASS; CLI 269.371s, publish 11.970s

go test -race -count=1 ./internal/cli ./internal/config ./internal/publish ./internal/state
  PASS; CLI 334.161s, publish 9.200s
```

The fake providers remain layer tests only. The same final runtime source also
passed pinned MinIO, real Nginx apt/dnf, and official PGDG gates; real
R2/COS/Cloudflare/EdgeOne execution is still an external blocker and is not
claimed by this review.

## 2026-07-14 canonical-history and cache-crash re-review

The current working tree received another independent blind/edge review after
the purge receipt became a permanent canonical ledger. The pass closed these
additional fail-open boundaries:

- every generation now binds the global generation/checkpoint/plan, target
  `content.tsv`, and intent-local generation/checkpoint/plan at one immutable
  publication anchor; deleting or rewriting any member without advancing the
  generation is permanent drift;
- consecutive publication anchors must follow the real Git ancestor graph, so
  history position cannot bless a sibling-branch generation or a sibling
  `desired_commit`;
- the local-only v1 repair validates that complete closure before restoring the
  original anchor receipt and derived attestation. A CLI E2E then repairs v1,
  publishes generation 2, proves the strict v2 checkpoint-to-plan digest, and
  passes L2 plus full fsck without any repair-time protocol request;
- L2, full fsck, adoption, and publish validate the complete local closure
  before provider I/O. COS additionally binds the create-only generation lock;
  adoption rejects reserved control namespaces, incomplete inventory, and any
  object whose planned deletion has reappeared;
- every production `Store.Apply` goes through one catalog wrapper. A durable
  pending marker spans Git commit through SQLite file and directory fsync;
  ordinary restart and `--recover` force a full rebuild before clearing it.
  Projection-neutral commits use an exact HEAD CAS only after Git blob/ref
  identity proves the query projection unchanged.

Focused ordinary and race tests, `go vet`, `git diff --check`, merge-DAG,
symlink, precommit, after-commit and protocol-count negative tests passed in the
independent re-review. A subsequent current-tree broad run is recorded only in
the traceability matrix once it completes. Every command explicitly disabled
real-cloud, real-edge and real-upstream opt-ins and cleared ambient AWS,
Cloudflare and Tencent credentials. No CO/COS or Cloudflare production resource
was contacted; this local evidence does not upgrade the real-cloud PoC.
