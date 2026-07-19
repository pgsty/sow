# ADR-0032: Exact owner-designated Cloudflare test resource exception

Status: Accepted (2026-07-17)

## Context

The real-cloud harness rejects production-looking resource names and every
Pigsty DNS suffix before it reads credentials or creates a client. That default
remains correct. The owner has now explicitly designated one newly created R2
bucket, `pro`, and the `pro.pigsty.io` test namespace while reiterating that no
CO/COS or Cloudflare production repository may ever be a test target. The
existing SOW contract requires beta to remain a distinct host, so the
reversible, pre-deployment default is `beta.pro.pigsty.io`.

The identifiers do not satisfy the generic `sow-test` naming policy and the
hosts share a production DNS zone. Treating any value as a generic exception
would weaken the permanent safety boundary; continuing to reject the exact
tuple would discard an explicitly provisioned test surface.

## Decision

1. The safety validator recognizes only the inseparable exact tuple
   `cf_r2_bucket=pro`, `cf_cdn_base=https://pro.pigsty.io`, and
   `cf_beta_cdn_base=https://beta.pro.pigsty.io`. Any subset, trailing slash,
   another Pigsty hostname, or another bucket remains rejected.
2. The exception changes only structural admission. Provider-scoped read-only
   readiness pins the exact R2 account endpoint, account ID, bucket, zone
   ID/name and main/beta roots in the independent registry from ADR-0033. The
   later destructive/evidence path additionally requires the complete
   COS/EdgeOne topology and all provider-deployment identities in its two
   existing registries. Every applicable registry byte must match its compiled
   SHA-256 constant.
3. The provider-readiness registry may contain only the independently reviewed
   exact tuple. As of 2026-07-18 it contains that single Cloudflare entry. The
   full-resource, provider-deployment and bootstrap registries remain separate
   and closed; every write-capable opt-in still fails in `TestMain` before
   credential decoding, client construction, or requests.
4. The first permitted request is provider-scoped read-only readiness. It may
   prove only that the exact R2 bucket is empty, the exact shared zone matches
   the pinned entry, and the bucket's complete custom-domain inventory is
   exactly enabled/active main+beta with active SSL. It does not attest Worker
   routes, private-origin deployment, logging, purge or cache behavior.
   Shared-zone admission is restricted to canonical `pigsty.io` plus the exact
   tuple; another zone or host fails closed before any request.
5. Provider attestation audits the whole shared-zone route inventory but binds
   only the two reviewed routes. Unrelated routes are allowed only when their
   Cloudflare pattern cannot match either reviewed host. Any exact-host,
   wildcard-host, path-specific, malformed, negating, or extra auth-Worker
   route that can overlap either host fails closed. Unrelated production route
   bytes are not included in the SOW deployment identity.
6. Provider attestation also audits the whole shared-zone Logpush inventory.
   The configured SOW `http_requests` job remains an exact, enabled,
   full-sample contract for the two reviewed hosts. Other disabled jobs are
   harmless. Another enabled job is allowed only when it cannot write the SOW
   raw-log bucket and, for `http_requests`, its filter proves that neither
   reviewed host can be included. Unknown, malformed, or unsupported filter
   forms are treated as overlapping and fail closed. Unrelated job bytes are
   not included in the SOW deployment identity.
7. Write credentials must be scoped to the exact bucket; Cloudflare API tokens
   must be scoped to the exact zone and URL-list purge operations. Purge-all,
   wildcard host admission, other buckets, other Pigsty hosts, CO/COS production
   resources, and production repository trees remain forbidden.
8. This bucket is only an acceptance-test transport. It does not revive the
   superseded standalone Pro-bucket product architecture from ADR-0007; the
   tested SOW layout remains the unified public/gated repository model.

## Consequences

- The owner-designated tuple can be prepared as an offline registry candidate
  without adding a generic Pigsty-domain or arbitrary-bucket bypass.
- Exact account ID/R2 endpoint, zone ID/name, active main+beta R2 custom-domain
  bindings, the independent reviewed readiness entry and scoped read
  credentials are required before read-only readiness can run. Worker/private
  origin deployment identities remain mandatory before the full POC can run.
- The initial read-only dashboard observation recorded account ID
  `72cdbd1b54f7add44ecbd3d986399481`, an empty `pro` bucket with public access,
  and a working `pro.pigsty.io` empty-root 404. The 2026-07-18 authorized
  follow-up closed the exact zone ID, active beta DNS/domain, TLS 1.2 floor,
  authenticated empty-bucket list and readiness-registry entry. It did not
  produce the signed control-plane readiness receipt.
- No write-capable cloud request or mutation is authorized by this ADR alone.
  The independent readiness entry authorizes only its fixed read-only operation
  set; the still-closed write registries keep later entrypoints fail-closed.
- The 2026-07-18 R2 storage-protocol test was separately authorized by the
  owner and admitted by ADR-0036's exact run-owned-key gate. It reused this
  tuple only as an identity pin; it does not turn this ADR or a readiness
  receipt into general mutation authorization.
- Historical evidence that the earlier pair was rejected remains true for the source
  version that produced it; this ADR supersedes that structural policy only for
  the exact tuple and does not retroactively claim real-cloud evidence.

## Evidence

`TestRealCloudProductionIsolationGate`,
`TestRealCloudPinnedRegistryCannotApproveProductionResource`,
`TestRealCloudOwnerDesignatedCloudflarePairStillRequiresExactRegistry`,
`TestRealCloudOwnerDesignatedCloudflareSharedZoneIsExact`, and
`TestRealCloudRegistryCandidateBuilderIsDeterministicAndProductionSafe` cover
tuple-only admission, generic production rejection, empty-registry rejection,
host/zone drift, and offline candidate generation without network access.
`TestRealCloudCloudflareRouteHostOverlapIsConservative` and the loopback SDK
collector additionally prove unrelated-route admission and overlapping
exact/wildcard/path/invalid route rejection.
`TestRealCloudCloudflareLogpushHostOverlapIsConservative` and the same collector
prove that an unrelated shared-zone job can coexist, while reviewed-host
overlap or SOW raw-bucket reuse is rejected.
The independent preliminary gate is specified and tested by
[ADR-0033](0033-provider-scoped-readiness-registry.md).
The external read-only observation and its explicit non-claims are recorded in
[`2026-07-17-cloudflare-pro-readonly-inventory.md`](../evidence/2026-07-17-cloudflare-pro-readonly-inventory.md).
The owner-authorized domain/TLS change, authenticated empty-bucket evidence and
remaining token boundary are recorded in
[`2026-07-18-cloudflare-pro-domain-readiness.md`](../evidence/2026-07-18-cloudflare-pro-domain-readiness.md).
The separately authorized storage-only mutation and its empty-after proof are
recorded in
[`2026-07-18-real-r2-storage-protocol.md`](../evidence/2026-07-18-real-r2-storage-protocol.md)
under [ADR-0036](0036-provider-delete-capability-and-checkpoint-fenced-fallback.md).

Cloudflare's route contract permits only a leading host wildcard and an
optional trailing path wildcard, and resolves overlapping patterns by
specificity. The SOW shared-zone check intentionally uses the stricter rule
that any non-SOW route capable of matching either reviewed hostname is a
conflict: <https://developers.cloudflare.com/workers/configuration/routing/routes/>.
