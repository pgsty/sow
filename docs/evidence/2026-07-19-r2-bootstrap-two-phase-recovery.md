# R2 bootstrap two-phase recovery evidence

Date: 2026-07-19

Status: current-source local/protocol evidence passed; no cloud request or
write was made.

## Defect closed

The V-25 resource-stable lease protocol made ordinary apply/rollback reject an
expired live lease, but `recover-lease` still CAS-retired that live object to
idle before its private recovery receipt was durable. A process death in that
window could let another executor acquire idle and destroy the exact
remote-to-local provenance replay path.

Bootstrap recovery now uses one resource-stable key and four ordered durable
states:

1. exact expired live is CAS-replaced by canonical owning
   `sow-real-cloud-cloudflare-bootstrap-lease-recovery-pending/v1`;
2. pending binds recovery run/current plan/resource/account/zone, the complete
   recovered lease and digest, and a canonical start time;
3. deterministic receipt v3 binds that pending digest plus current/recovered
   plan and complete recovered-lease identity, and is no-replace installed from
   a fully written and synced inode;
4. completion reopens the exact receipt bytes, then CASes the pending ETag to
   recovery idle v3. Idle binds both pending and receipt SHA-256 values and
   embeds the complete recovered lease.

Live lease v3 appends each completed pending/receipt pair to an ordered
canonical lineage. Every later acquisition, release and recovery preserves
the prior entries. Completion can therefore recognize an exact recovery idle
or a later live/release-idle/pending descendant after provider response loss,
including after another recovery generation, while a marker without the exact
pair remains unrelated. The 1024-entry safety bound is checked before the
expired live ETag is changed, so saturation cannot leave a pending marker.

Pending is not another expiring lease. It remains owning until the exact same
run and plan resume; clock-based takeover by another executor would recreate
the provenance gap. Ordinary apply/rollback and readiness reject it. Idle
replay reconstructs the entire pending canonical body from the current plan,
receipt and embedded lease before accepting either digest. Normal release-idle
and recovery-idle are distinct canonical states. No path has DeleteObject
authority.

V-25's idle v2/direct-recovery receipt v2 were never deployed: bootstrap and
provider-deployment registries remained closed and its evidence made no cloud
write. Unexpected v2 or legacy plan-key objects therefore remain foreign and
fail closed rather than receiving an unsafe automatic migration.

## Fault and identity coverage

The focused tests prove:

- a live lease cannot be recovered before exact expiry;
- a committed pending Put whose response is lost is recovered by exact GET;
- interruption after pending and before receipt is read-only replayable by the
  same run even far past the old lease TTL;
- exact concurrent receipt persistence is idempotent; divergent receipt bytes
  cannot overwrite the completed local file;
- interruption after receipt and committed final-Put response loss converges
  to the same recovery idle, and a later replay performs no Put;
- an immediate contender, its release, a later completed recovery and its next
  live holder retain the earlier receipt lineage; both old and new receipts
  replay read-only, while a valid same-resource live marker without lineage is
  rejected;
- duplicate lineage and saturated lineage fail closed, with saturation
  rejected before the live-to-pending Put;
- another run, rotated plan, ordinary acquisition, stale ETag and readiness
  cannot take or admit pending;
- forged recovered-lease fields, mutually forged pending/receipt digests and a
  normal release-idle cannot satisfy the recovery closure;
- a stale crashed holder cannot release the pending/recovery-idle replacement;
- the single resource key remains unchanged and Delete calls remain zero.

The storage implementation used by the live opt-in remains the official R2
SigV4 control client with conditional Put. Fake-store tests isolate every
state transition and provider-success/client-response-loss edge; generic
private-file fault tests cover complete-inode/no-replace publication. This is
not an in-memory-only product path: the real `recover-lease` acceptance entry
calls the same begin, durable receipt and completion functions while exposing
only R2 authority.

## Reproducible validation

All real-cloud opt-ins were explicitly `0`:

```text
go test ./test/compat -run 'CloudflareBootstrap|CloudflareReadiness|RealCloudPrivateBootstrapAtomicWindows' -count=1
ok github.com/pgsty/sow/test/compat 1.126s

go test -race ./test/compat -run 'CloudflareBootstrap|CloudflareReadiness|RealCloudPrivateBootstrapAtomicWindows' -count=1
ok github.com/pgsty/sow/test/compat 2.460s

go test ./test/compat -count=1
ok github.com/pgsty/sow/test/compat 10.266s

go test -race ./test/compat -count=1
ok github.com/pgsty/sow/test/compat 14.318s

go vet ./test/compat
PASS (no output)

staticcheck -checks='inherit,-ST1005,-U1000' ./test/compat
PASS (no output)

git diff --check
PASS (no output)
```

This report deliberately does not embed its own post-document product,
delivery or archive digests. Two independent fresh-cache clean-delivery runs,
their byte-for-byte `cmp`, final identities and archive paths are recorded in
the external implementation validation ledger.

## Boundary

No request was sent to `pro`; no R2 object, Worker, route, domain, cache or
control-plane setting changed. CO/COS and every Cloudflare production
repository remain forbidden mutation targets. This closes one local recovery
protocol defect; it does not prove signed Cloudflare readiness, Worker deploy,
purge/negative verification, provider logs, COS/EdgeOne, multi-PoP behavior,
production migration/revocation or operational metrics. POC-06 and the
long-term Goal remain open.
