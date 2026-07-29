# ADR-0035: Cloudflare provider attestation and log-sink lease

- Status: accepted
- Date: 2026-07-17
- Amended: 2026-07-29
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

Provider attestation config and deployment identity v5 use the product
`edge.token_verifier` reference as a strict union discriminator. In
`provider://id` mode they pin a separate compatibility date and sorted, unique
flag inventory for the auth, origin and token-verifier Workers. In
`env://NAME` mode every provider-only verifier service, runtime, content,
binding, URL and deployment field must be empty; the exact `NAME` must instead
appear in both Cloudflare and EdgeOne secret inventories. The default bounded
real-cloud acceptance product config uses the latter mode. Every managed
active Worker is bracketed by deployment reads and two identical security
observations:

- immutable version runtime uses the exact date/flags, `standard` usage model,
  zero/default limits and no migration tag;
- script settings have no cache, placement, observability, tags or tail
  consumers and contain no unknown top-level/nested fields; the auth Worker
  alone has `logpush=true`, while origin and provider verifier require
  `logpush=false`;
- schedule inventory is explicitly present and empty;
- workers.dev and preview exposure are explicitly disabled.

The discriminator is not allowed to define its own expected product. Decode
receives the actual generated `sow.yaml` bytes from outside the attestation,
requires their digest and verifier reference to match before any credential is
read or provider client is built, and derives both edge contracts from those
external bytes. The provider entry point loads only those non-secret resource
fields, not the two entitlement bearer tokens. The exact two-stage active
evidence set and both vendor config digests are then closed against that product
digest before any of the six provider/publisher credentials are read. The
first-step raw-log mutation additionally compares the
attestation digest with the durable acceptance-ledger binding before reading a
log/API credential. A self-consistent provider config therefore cannot replace
the run's default static product config.

Raw provider attestation v5 records the verifier kind and non-secret binding
name. Provider mode retains independent security digests for all three Workers;
static mode records no third-Worker identity, ETag or digest and proves the
secret only through the auth Worker binding name/type and redacted runtime
digest. Its Cloudflare control digest also includes compatibility values and a
twice-read canonical inventory of every Worker identity, embedded route, zone
route and Worker custom domain. Missing custom-domain service/certificate/zone
identity fails closed. The complete inventory and managed exposure digests
must be identical across consecutive reads and across the outer raw-log
collection bracket.

The static Cloudflare closure therefore contains exactly auth and origin as
managed Workers, with `ORIGIN` as its only service binding. The EdgeOne closure
omits the provider URL and bearer and requires the same named static secret.
For EdgeOne, a secret is accepted only when the live runtime response identifies
it as type `secret` and omits or redacts its value. A same-name `string`/`json`
variable or a non-empty returned secret value fails closed; the collector never
uses plaintext presence as secret evidence. This follows Tencent's documented
[Environment Variable and Secret](https://intl.cloud.tencent.com/document/product/1145/62764)
contract that a saved Secret value is no longer visible. The current public
[API data type](https://cloud.tencent.com/document/product/1552/80721#FunctionEnvironmentVariable)
still documents only `string`/`json`, so a real deployment must prove the
redacted `secret` wire shape; absence of that shape is a provider capability
failure, not permission to weaken attestation.
Because the Tencent SDK does not retain its raw response, the dedicated client
transport boundedly captures only the runtime-environment response, token-walks
the exact `Response/EnvironmentVariables/RequestId` shape and each exact
`Key/Type[/Value]` object, then clears the temporary body after SDK consumption.
Duplicate `Type`/`Value`, null, missing, unknown or non-string wire fields fail
before `encoding/json` may collapse them into a trusted struct. The size/read/
close gate runs before checking HTTP status; non-success responses are cleared
and replaced by a fixed error so the SDK cannot unboundedly read or embed them.
Cloudflare binding evidence is also a strict SDK-union closure: the collector
requires the exact raw JSON keys for each reviewed type and rejects every
non-zero field belonging to another union variant. Thus `secret_text` plus a
residual service/bucket/KV/database capability cannot be normalized into an
apparently exact secret inventory. The outer `bindings` member must be an
explicit non-null valid array, and all admitted binding values must retain their
JSON string type; missing arrays, null and wrong-type zero-value coercions fail.
The SDK-preserved raw resources object is parsed independently and must contain
`bindings`, `script` and `script_runtime` exactly once with their array/object
types and no unknown keys. The nested script/runtime/limits objects are also
token-walked with exact keys and JSON types, including numeric `cpu_ms` and
string-only compatibility flags; duplicate-key or zero-value SDK projection is
not trusted. The mutable `/settings` observation is independently token-walked
from the SDK-preserved raw body as well: every top-level settings member and
every cache/limit/observability/log/trace member must occur exactly once with
its reviewed JSON type and closed value. Duplicate booleans, numeric strings,
null inventories and omitted nested telemetry fields therefore cannot be
normalized into an apparently closed settings struct. Its flat-string binding
objects are canonicalized with duplicate-field rejection and must equal the
active immutable version's exact binding multiset. The schedule and subdomain
responses likewise require exact raw `{schedules: []}` and explicit false
exposure booleans, not SDK-projected nil/zero values; the independent complete
routing/inventory recheck applies the same raw exposure predicate.

The durable acceptance binding parses the canonical verifier reference from the
exact installed product YAML bytes and stores it beside their SHA-256. A v4 fact
must match both that config digest and the exact `kind://name`; grammar-valid
alternate names and provider/static substitutions fail before recovery may use
the fact. A v3 fact or any provider/static field mixture cannot resume harness
v8.

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
the dedicated raw bucket's stable `.sow/provider-log-sink-lease.json` key after
both provider zone safety checks and before either control-plane mutation.
Raw-prefix or deployment-contract rotation therefore cannot fork the lock
namespace. The deployment SHA remains in every live/idle body for audit;
lease/idle schema v2 also binds the dedicated raw bucket identity, preventing
canonical marker bodies from being relocated between buckets;
same account/zone idle or expired historical deployments may be taken over by
exact ETag CAS, while every live holder still blocks. Creation is `If-None-Match`,
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

Cloudflare evidence uses the account-scoped `workers_trace_events` dataset,
not the Enterprise-only zone `http_requests` dataset. This is the provider
path available on
[Workers Paid](https://developers.cloudflare.com/workers/observability/logs/logpush/)
and therefore preserves NFR-07. The job is
full-sample NDJSON, filters exact auth `ScriptName` plus `Outcome=ok`, and
exports only `EventTimestampMs`, `Logs`, `Outcome`, `ScriptName` and
`ScriptVersion`. `Event` and `Exceptions` are deliberately omitted so the raw
sink cannot receive a visitor URL, headers, token or unrelated exception text.
The auth Worker emits one bounded ten-field JSON console record only for an
explicit, route-safe `X-SOW-Provider-Probe` run ID. The shared request builder
does not forward that header to origin. Ordinary invocations therefore have an
empty `Logs` array and are ignored; records for another valid run ID are also
ignored after shape validation. A current-run record must bind the active
provider-owned script/version/timestamps to the visitor `CF-Ray` base and colo,
the clean URL digest, cache status/freshness and successful status. Unknown,
duplicate, truncated, URL-bearing, wrong-version or unjoinable records fail
closed.

The configured Workers Trace job is selected by exact ID from the account
inventory. Every other enabled account job is rejected if it can include the
reviewed auth Worker or write the SOW raw bucket. The zone inventory is still
read independently: any enabled HTTP job that can include main/beta or any
zone job that can write the raw bucket fails closed. Safe unrelated account
and zone jobs may coexist. Because Cloudflare documents roughly 10–15 minutes
for [destination changes to propagate](https://developers.cloudflare.com/logs/logpush/logpush-job/api-configuration/),
the durable acceptance program configures
the sink in its first step and enforces a 16-minute gate before the first
provider probe, including after recovery replay.

## Consequences

- A live readiness run will fail until both designated custom domains have the
  frozen TLS policy; no automatic production or shared-zone mutation is made.
- New Worker/runtime fields introduced by Cloudflare fail closed until reviewed
  and represented in the contract.
- Log-sink setup needs one additional narrowly scoped R2 control credential.
- Creating or changing the account Workers Trace job additionally requires an
  account-scoped `Logs Edit` token (the generic filter API documentation calls
  the write capability `Logs Write`); this is a permission requirement, not an
  Enterprise-plan requirement.
- That credential is scoped only to Get and conditional Put on the dedicated
  raw bucket's exact `.sow/provider-log-sink-lease.json` key; it needs no
  payload prefix or Delete authority.
- The Cloudflare bootstrap registry pins only the owner-authorized disposable
  `pro` plan produced by the corrected bundle. The full dual-cloud resource and
  provider-deployment registries remain closed. These changes have only
  loopback/fake-store evidence and do not claim that POC-06 or any real
  Cloudflare/COS operation passed.
- CO/COS and Cloudflare production repositories remain forbidden test targets.
