# Physical-owner publication, route receipts, restore, and archive evidence — 2026-07-15

## Scope and safety boundary

This report records the current-source, local product-path evidence for five
related invariants:

1. a logical selector is closed over every local physical route owner before
   mutable APT/YUM publication work starts;
2. a canonical materialized-route receipt is required before an ordinary
   publish can take its ref-vector no-op fast path or Nginx can expose a route;
3. historical YUM aliases that share one repo+architecture owner are restored
   as one physical generation with independently tracked logical channels;
4. a selected offline archive remains a logical export even though the live
   mutable tree is rebuilt over its complete physical owner; and
5. an installed retired YUM generation remains in the route's exact read
   capability without becoming a live CAS payload root.

No real cloud or production resource was used. Every run cleared AWS,
Cloudflare and Tencent credentials, set `AWS_CONFIG_FILE` and
`AWS_SHARED_CREDENTIALS_FILE` to `/dev/null`, disabled EC2 metadata and all
`SOW_RUN_REAL_*` gates, set `GOPROXY=off`, and pointed every general proxy at a
refusing loopback endpoint. Tests whose configured target is named `cf` use an
in-memory HTTP transport and synthetic credentials installed only with
`t.Setenv`; they do not resolve or dial a provider endpoint. In particular,
this report is not evidence for R2, COS/CO, Cloudflare CDN, EdgeOne, a
production repository, or a production migration.

## Requirement placement

The evidence belongs to the following ledger entries. A requirement listed as
secondary receives supporting implementation evidence only; its existing
external or operational status is not upgraded by this report.

| Evidence concern | Primary requirement placement | Secondary placement and boundary |
|---|---|---|
| Physical-owner closure with narrow logical remote intent | FR-03, FR-06–FR-08, FR-12, FR-21, FR-25–FR-26, FR-28, FR-42; NFR-03, NFR-09; FZ-01, FZ-06, FZ-09 | G1 is only a local accident-prevention mechanism and remains operationally unverified; G3 remains a local/protocol O(change-set) result; COMP-01 still needs the final current-source real-client matrix. |
| Canonical route receipt as a read capability and fast-path prerequisite | FR-01, FR-06, FR-12, FR-25, FR-28–FR-29, FR-34; NFR-08–NFR-09; FZ-01, FZ-09 | It proves canonical Git auditability and local fail-closed admission, not remote L2/L3 or production Nginx cutover. |
| Historical shared-owner YUM alias restore | FR-21, FR-25–FR-28; NFR-09; FZ-06, FZ-09; MIG-06 | Restore uses the full product CLI and publication saga over an in-memory provider protocol. The isolated-alias removal assertion exercises the production planner from sealed parent evidence; package-topology immutability prevents constructing a valid CLI fixture that rewrites a historical two-alias owner into a one-alias config. It is therefore not claimed as a full provider or production removal E2E. |
| Logical selected offline archive | FR-12, FR-23–FR-24, FR-42; FZ-09 | The APT and frozen-YUM archives are byte-deterministic and pass L1 locally. This does not close old-APT policy, a real client consuming the newly selected archive, EOL business policy, or a production archive migration. |
| Retired generation exact-versus-payload lifecycle | FR-13, FR-27, FR-29, FR-34; NFR-08–NFR-09; FZ-09 | It proves local delayed-client read capability, audit and GC-root separation. Remote retention/deletion and provider behavior remain outside this evidence. |

## Product-path evidence

### Physical owner closure and canonical receipts

`TestPublishPartialYUMAliasClosesFastPathAndRepairsRouteReceipt` gives the
Rocky and EL10 logical refs different package manifests while both aliases own
the same `rpm-test/x86_64` physical route. A publish selected only with
`--os rocky` proves all of the following:

- the durable recovery vector contains both aliases in both raw and serving
  units, and a forged one-alias journal is rejected as an incomplete physical
  owner;
- one physical signed repodata root and both immutable alias generations each
  contain the two-package owner union;
- the target generation records two refs and two channels, while one canonical
  route receipt binds both refs and validates the physical tree;
- a second invocation takes `status=unchanged preflight=ref-vector` without
  local materialization or remote protocol effects;
- deleting only the receipt/exact/payload canonical triple makes Nginx
  admission fail and prevents that fast path; the next publish rebuilds and
  recommits the receipt without a remote PUT, purge or GET, after which Nginx
  admission succeeds again.

`TestPartialAPTMaterializeClosesPhysicalOwnerAndPreservesSiblingRoute` proves
that a jammy/amd64 selection rebuilds the four-ref repo-wide APT owner and does
not delete another APT repo's receipt. The ordinary publish coverage in
`TestPublishCLIPartialAPTIsSuiteWideAndSnapshotSafe` additionally proves the
live local owner contains the unselected pending suite while the remote
manifest, plan and refs remain limited to the requested logical suite. Local
hostability is therefore not used as authority to widen remote publication.

### Historical aliases and forward-only restore

`TestPublishRestoreHistoricalYUMAliasesSharePhysicalOwnerAndPlanIsolatedAliasRemoval`
creates disjoint Rocky and EL10 ref commits over one physical YUM owner, then
publishes two generations and restores generation 1 forward as generation 3.
The restored generation reports `refs=2`, `yum_repos=1`, has two complete
channels pointing to one immutable physical generation, and its raw
`repomd.xml`/`.asc` pair is byte-identical to the strong generation. OpenPGP
validation proves the restored two-package repodata, and all three historical
RPM payload objects remain present.

An injected failure after purge does not advance the local target generation;
the normal CLI replay performs the mandatory purge again and completes. A
subsequent restore is effect-free: no PUT, Copy, DELETE, purge or CDN GET. The
sealed-parent removal planner deletes only the Rocky mirrorlist pointer while
retaining the EL10 channel, physical repodata root and packages.

### Logical offline archives

`TestLatestWorkingTreeAPTArchiveRetainsLogicalSuiteSelector` starts with jammy
and noble in one live physical APT owner. `materialize latest --os jammy --tgz`
leaves both suites in the live owner but the deterministic archive contains
only jammy indexes and payload. The extracted archive passes APT L1, a replay
is byte-identical, and canonical HEAD does not advance.

`TestLatestWorkingTreeArchiveCarriesFrozenYUMCompatibility` exports a selected
frozen cross-EL compatibility projection. The archive contains the frozen raw
gzip route, one strong generation, mirrorlist and exact package/repository
trust bytes; it excludes an unselected asset, canonical state, transaction
temporaries and flat RPM aliases from the immutable generation. Both raw and
strong repodata pass OpenPGP/YUM L1 with the frozen package keyring. Replay is
byte-identical and does not advance canonical HEAD.

### Retired generation exact versus payload

The canonical route builder in `materialize_route_receipts.go` derives active
generation exact manifests from their canonical generation ledgers and adds
only active `Packages/*.rpm` entries to the payload manifest. It independently
discovers installed generation IDs and admits a non-active ID only when the
same target/view/repo/architecture/root has an exact canonical retirement
witness. That witness is prefixed into the exact manifest and deliberately is
not appended to the payload manifest.

`TestYUMPayloadClosureExpiresOnlyAfterConfiguredRealFlips` exercises the
delayed-client retention window across real local generation flips, then
requires both Nginx admission and `fsck clean`. The subtests in
`TestAuditCanonicalMaterializedRouteLedgersReplaysHistoricalYUMLifecycle`
reject a forged generation payload, mirrorlist or serving-target identity.
Together with route-root validation, this proves a retained directory can
remain readable and auditable without resurrecting all retired packages as CAS
GC roots.

## Reproducible validation

The current-source focused set was run with the strict offline environment
described above:

```text
go test ./internal/cli -run '^(TestPublishPartialYUMAliasClosesFastPathAndRepairsRouteReceipt|TestPublishRestoreHistoricalYUMAliasesSharePhysicalOwnerAndPlanIsolatedAliasRemoval|TestLatestWorkingTreeArchiveCarriesFrozenYUMCompatibility|TestLatestWorkingTreeAPTArchiveRetainsLogicalSuiteSelector|TestYUMPayloadClosureExpiresOnlyAfterConfiguredRealFlips|TestPartialAPTMaterializeClosesPhysicalOwnerAndPreservesSiblingRoute|TestAuditCanonicalMaterializedRouteLedgersReplaysHistoricalYUMLifecycle)$' -count=1
ok github.com/pgsty/sow/internal/cli 126.863s
```

Additional focused runs from the same implementation pass were:

```text
TestPublishPartialYUMAliasClosesFastPathAndRepairsRouteReceipt
  race: PASS, internal/cli 18.347s

TestPublishRestoreHistoricalYUMAliasesSharePhysicalOwnerAndPlanIsolatedAliasRemoval
  ordinary: PASS, internal/cli 19.627s
  race:     PASS, internal/cli 30.168s

five-test publish/restore P0 set
  ordinary: PASS, internal/cli 119.263s

go test ./internal/publish -count=1
  PASS, internal/publish 7.709s

go vet ./internal/cli ./internal/publish
  PASS
```

These focused runs do not replace the final full ordinary/race suite, static
checks, four-platform builds, current-source apt/dnf compatibility matrix,
clean-delivery identity, old-APT decision, approved non-production cloud PoC,
or production migration/rollback. They do not authorize access to production
CO/COS/Cloudflare resources. The Goal remains active.
