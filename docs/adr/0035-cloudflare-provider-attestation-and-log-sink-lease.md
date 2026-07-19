# ADR-0035: Cloudflare provider attestation and log-sink lease

- Status: accepted
- Date: 2026-07-17
- Scope: dedicated non-production provider evidence only

## Context

ADR-0034 closes first-deployment races, but a later provider attestation must
also prove that the active Workers still have the reviewed runtime semantics.
Content and binding digests alone do not cover compatibility settings, CPU and
subrequest limits, placement, observability, schedules, tail consumers or
workers.dev exposure. Likewise, two acceptance runs that update the same
Cloudflare Logpush job and EdgeOne realtime-log task can interleave even when
both use dedicated non-production resources.

Cloudflare's R2 custom-domain API defaults an omitted minimum TLS version to
1.0. Its cipher list uses BoringSSL names. Treating an absent policy or an
arbitrary known string as readiness would therefore admit a materially weaker
edge contract than SOW intends.

## Decision

Provider attestation config v3 pins a separate compatibility date and sorted,
unique flag inventory for the auth, origin and token-verifier Workers. The
provider deployment identity includes those contracts. Every active Worker is
then bracketed by deployment reads and two identical security observations:

- immutable version runtime uses the exact date/flags, `standard` usage model,
  zero/default limits and no migration tag;
- script settings have no cache, placement, Logpush, observability, tags or
  tail consumers and contain no unknown top-level/nested fields;
- schedule inventory is explicitly present and empty;
- workers.dev and preview exposure are explicitly disabled.

Raw provider attestation v3 records independent security digests for all three
Workers. Its Cloudflare control digest also includes compatibility values and a
twice-read canonical inventory of every Worker identity, embedded route, zone
route and Worker custom domain. Missing custom-domain service/certificate/zone
identity fails closed. The complete inventory and managed exposure digests
must be identical across consecutive reads and across the outer raw-log
collection bracket.

The same config pins the EdgeOne realtime-log task's immutable `Area` to exactly
`mainland` or `overseas`. The collector requires the live task to report that
exact area and binds it into the task digest, provider-deployment identity, raw
attestation and durable acceptance ledger. An omitted, unknown or mismatched
area fails closed because EdgeOne does not allow changing `Area` after task
creation.

R2 custom-domain readiness requires both exact main/beta domains to use TLS
1.2 or 1.3 and the exact six-suite Cloudflare "Modern" TLS 1.2 set (ECDHE,
AEAD, RSA+ECDSA certificate compatibility). Empty ciphers, TLS 1.0/1.1,
duplicates and unknown or legacy suites fail closed. TLS 1.3 suites are not
listed because Cloudflare enables them separately and does not allow selecting
individual TLS 1.3 ciphers. This follows the official
[R2 custom-domain API](https://developers.cloudflare.com/api/terraform/resources/r2/)
and [Cloudflare Modern cipher recommendation](https://developers.cloudflare.com/ssl/edge-certificates/additional-options/cipher-suites/recommendations/).

Per-run provider log-sink setup acquires one provider-visible R2 lease at
`<raw_root>.sow/provider-log-sink-lease.json` after both provider zone safety
checks and before either control-plane mutation. Creation is `If-None-Match`,
expired takeover and renewal are ETag compare-and-set, and successful closure
CAS-retires the exact live entity to a canonical non-owning marker. The lease
is renewed before both the Cloudflare and EdgeOne mutations. A partial cross-provider failure deliberately retains
the lease until its five-minute expiry, preventing another run from adopting
uncertain state; the next run may then replace it by CAS and replay the
idempotent configuration.

R2 does not implement conditional DeleteObject, so this reusable serialization
key is never deleted by SOW. The next run replaces the idle marker by ETag CAS;
a stale holder cannot erase the replacement. The lease uses a separate
`SOW_REAL_CF_LOG_CONTROL_JSON` identity, pinned by digest in config and scoped
only to Get/conditional Put on the lease prefix. It is pairwise distinct from
publisher, raw reader, Cloudflare Logpush
writer and EdgeOne writer identities. Exporter writer credentials remain
write-only and never receive List/Get/Delete.

Cloudflare Logpush verification selects the configured job by exact ID and
audits every other enabled job for reviewed-host or raw-bucket overlap. A safe
unrelated shared-zone job no longer causes a post-mutation false failure.

## Consequences

- A live readiness run will fail until both designated custom domains have the
  frozen TLS policy; no automatic production or shared-zone mutation is made.
- New Worker/runtime fields introduced by Cloudflare fail closed until reviewed
  and represented in the contract.
- Log-sink setup needs one additional narrowly scoped R2 control credential.
- The shipped resource, bootstrap and provider-deployment registries remain
  empty. These changes have only loopback/fake-store evidence and do not claim
  that POC-06 or any real Cloudflare/COS operation passed.
- CO/COS and Cloudflare production repositories remain forbidden test targets.
