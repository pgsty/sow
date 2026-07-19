# Snapshot L1-L4 verification evidence — 2026-07-12

## Scope

`sow verify --snapshot <suite>-YYYYMMDD` is an exact publication intent, not
an alias for `stable`. It is mutually exclusive with `--view` and validates one
immutable snapshot through these independent surfaces:

- L1 opens each selected `SnapshotRef` at its exact commit and reads the
  corresponding `SnapshotPath`; it then verifies CAS history and compares the
  canonical payload manifests with the real default snapshot materialization.
  APT signatures, by-hash indexes and pool closure, YUM repomd signatures and
  three-metadata closure, and asset bytes are checked from the hostable tree.
- L2 reads the intent projection below
  `remotes/<target>/intents/snapshots/<id>/`, closes generation/checkpoint/plan,
  compares local immutable refs and target refs, reads the immutable remote
  generation, checks checkpoint monotonicity, and HEAD-verifies every planned
  remote object.
- L3 fetches every planned byte through the exact
  `pro/v1/<credential>/_sow/v1/snapshots/<id>/` CDN route.
- L4 follows the signed APT or YUM repository protocol through that same
  snapshot route and downloads and parses one authenticated DEB or RPM.

Missing refs, materializations, target state, plan coverage, or package-client
coverage produce findings; no layer silently falls back to a mutable view.
Runtime Pro tokens remain file-only secrets and are rewritten into request URLs
without entering canonical plans, reports, or logs.

## Reproducible tests

The focused suite exercises real filesystem/CAS bytes and the production S3,
CDN-routing, OpenPGP, APT and RPM-MD clients against the protocol transport:

```text
go test -race ./internal/cli -run 'TestPublishCLIYUMSnapshotUsesExactIntentStableRouteAndServerSideCopy|TestVerifySnapshotArgumentsAndMissingCoverageFailClosed|TestVerifySnapshotL1ChecksAssetMaterialization|TestMaterializeAPTSnapshotBuildsConsumableRepositoryAndRebuildsAfterRetention' -count=1
```

The combined YUM case proves:

1. stable is captured into an immutable `el10-YYYYMMDD` ref;
2. the snapshot is published with an exact intent generation and route pointer;
3. `verify --layer all --snapshot ...` passes L1-L4;
4. direct Git ref tampering is reported as `SNAPSHOT_IMMUTABLE_REF_DRIFT`;
5. a later `latest` publication advances the bucket-global checkpoint;
6. the older snapshot still passes L2-L4 through a runtime token route without
   emitting the token.

The APT case proves the default snapshot tree's signed `InRelease`, detached
signature, by-hash indexes, canonical pool payloads and CAS closure. The asset
case proves exact canonical-to-materialized bytes and detects a replaced file as
`FS_CHANGED`. Argument tests cover invalid dates, multiple snapshot values,
`--view`/`--snapshot` mixing, and missing-ref coverage.

Package-level regression commands:

```text
go vet ./internal/cli ./internal/verify ./internal/publish
go test ./internal/verify ./internal/publish -count=1
```

## Adjacent defect closed

The combined checkpoint-advance test exposed that the publisher inferred a
stable publication from any historical stable ref in the cumulative target
vector. That made a public `latest` generation impossible after a stable or
snapshot publication. Namespace enforcement now binds to the frozen
`generation.intent_view`; a regression proves `latest` may retain historical
stable refs while stable/snapshot intents still reject public generation
metadata.

## Explicit boundary

The protocol transport exercises the real signing, request, route, signature,
metadata and package parsing code, but it is not evidence of a live Cloudflare
R2/Worker or Tencent COS/EdgeOne deployment. Those supplier PoCs remain separate
external-environment gates.
