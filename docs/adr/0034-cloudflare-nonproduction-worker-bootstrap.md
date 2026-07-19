# ADR-0034: Cloudflare non-production Worker bootstrap

- Status: accepted
- Date: 2026-07-17
- Scope: real-cloud POC infrastructure only; never production resources

## Context

The real-cloud acceptance already verifies active Worker bytes, bindings,
routes, exposure, provider logs and cache behavior. It deliberately requires a
SHA-pinned provider-deployment identity before any request. That post-deploy
gate cannot also authorize the first deployment: doing so would require the
deployment identity to exist before it can be created, while a manual Wrangler
step would leave an unreviewed and non-replayable mutation outside the evidence
chain.

The owner designated only the exact Cloudflare test tuple `pro` /
`pro.pigsty.io` / `beta.pro.pigsty.io` for this POC. The shared `pigsty.io`
zone and every unrelated Worker, route, DNS record and bucket remain outside
the mutation scope. CO/COS and Cloudflare production repositories are never
test targets.

## Decision

The compatibility harness has a separate first-deployment bootstrap with five
independent gates, all evaluated before credentials or clients:

1. the provider-scoped readiness resource is present in its compiled-SHA
   registry;
2. a canonical bootstrap plan binds that resource, the state-admitted
   `sow materialize latest --edge-contract cf` document, exact in-repository
   bundle hashes, script names, verifier evidence, compatibility date and the
   two exact host routes;
3. the plan hash is present in a second compiled-SHA bootstrap registry;
4. apply and rollback consume a canonical readiness receipt for the same run
   that is no more than 15 minutes old and proves the exact bucket was empty,
   or contained only one canonical non-owning bootstrap lease marker, and both
   custom domains were active. Its v3 seal is an Ed25519 signature
   over the exact canonical receipt bytes; the signer public key is part of the
   SHA-pinned bootstrap plan. Recomputing an unkeyed digest or substituting an
   attacker key cannot authorize mutation. Expired-lease recovery is
   deliberately R2-only and does not authorize Worker/CDN access;
5. the operator supplies an authorization phrase that binds mode, run ID,
   plan SHA, account ID and zone ID.

The bootstrap owns only:

- one auth Worker containing `edge/dist/cloudflare-worker.mjs`;
- one service-only origin Worker containing
  `edge/dist/cloudflare-origin-worker.mjs` and the single `REPOSITORY` R2
  binding;
- `pro.pigsty.io/*` and `beta.pro.pigsty.io/*`, both bound to the auth Worker.

It does not create or mutate the token verifier. That service is a separate
commercial identity dependency and must already match independently reviewed
content, binding, compatibility-date/flags, closed telemetry, placement,
limits, usage-model and exposure policy. It does not write repository payload
objects, custom domains, DNS, Logpush, cache rules or unrelated routes. The
only R2 mutation is a provider-visible conditional lease at
`.sow/bootstrap/leases/<plan-sha>.json`. After the local outcome receipt is
durable, its exact live bytes are compare-and-set to a canonical idle marker;
SOW never calls R2 DeleteObject for this reusable key. The initial transport is
the deployable `r2-service` correctness path; the later cache-normalization POC
is a separate, explicitly attested deployment state.

The runtime constructs an R2-only signed control client for that lease. Apply
and rollback additionally read the separately injected Cloudflare API token
and construct a Worker control client only after all selection/readiness gates
pass. `recover-lease` neither reads the CDN credential nor constructs a Worker
client, so its executable authority is limited to the exact R2 lease object.

The readiness signer seed is injected only through
`SOW_REAL_CLOUD_PROVIDER_READINESS_SIGNER_JSON`; it is never stored in the
receipt, seal, plan, registry, log or repository. Plan onboarding carries only
the lower-hex Ed25519 public key. Key rotation therefore requires a new plan
digest and administrator-reviewed bootstrap-registry entry; a receipt signed
by any other key fails before provider credentials are read.

Lease acquisition is not treated as proof that the earlier empty-bucket
readiness observation is still current. Immediately after create/CAS, and
again after every pre-mutation renewal, the executor consumes every bounded
`ListObjectsV2` page and requires the bucket's exact closure to contain only
that lease with its current size and ETag. It then GETs the lease and compares
the canonical bytes and ETag to the held entity. At the same boundary it
re-reads the exact zone plus the enabled main/beta R2 custom-domain closure and
requires its digest to equal the fresh readiness receipt. Any intervening
object, domain, TLS-policy or zone drift fails before the inner Worker/route
mutation runs.

Before the first mutation, the executor reads the account Worker inventory,
zone routes, Worker custom domains, managed-script schedules, tail consumers,
the verifier deployment, and any pre-existing planned scripts. Foreign routes
that exactly match or may overlap either designated host fail closed. Existing
planned scripts are reusable only when their active bytes, bindings and
runtime match the plan exactly. Custom domains, schedules, tail consumers or
excessive capability bindings on a managed script also fail closed.

Auth/origin ownership annotations bind both the plan and the exact run. New
scripts use `If-None-Match: *`, so an absent-to-upload race cannot overwrite a
foreign script. The apply order is origin upload, origin exposure disable, auth upload, auth
exposure disable, then the two exact routes. Every step is followed by active
deployment inspection, the auth Worker is rechecked immediately before every
route creation, and the final account/route/Worker closure must match across
two consecutive complete observations. Settings and workers.dev/preview
exposure are also read twice around the active-deployment check. A retry
reconciles only an exact same-run partial state and does not recreate completed
resources. A different run cannot adopt it. The receipt atomically stores a
canonical envelope containing active deployment/version IDs, ETags, content
and binding hashes, route IDs and a closure hash outside the repository; there
is no crash window between a receipt file and a second seal file.

Rollback requires that sealed apply receipt and independently acquires the
same provider-visible lease. It accepts an exact partial rollback, reads each
receipt route and both receipt Workers by their exact identities even when a
provider list omits them. An exact 404 is an idempotent, already-converged
step. A present route must match its sealed ID, pattern and script immediately
before deletion. Before deleting an auth or origin Worker with `force=false`,
the adapter rechecks the account/zone attachment closure, the exact script's
schedules, the complete active deployment state and the entire bounded version
list; the list must contain exactly the sealed version and no inactive or draft
version. It never deletes the verifier. The expected route/Worker identity is
passed into one checked-delete adapter call. Its leased wrapper renews the
lease, revalidates bucket/provider closure and requires at least one bounded
mutation interval of lease lifetime before entering the provider adapter. The
whole checked mutation has a context deadline equal to one third of the
five-minute lease TTL. API errors after a provider-side success are safe: the
next run exact-probes the receipt identity, observes absence and continues.

The current Cloudflare route/script delete APIs accept only resource identity
(plus `force` for scripts) and do not expose a documented `If-Match`, version,
or other conditional delete precondition. The lease serializes SOW bootstrap
executors, while adapter-local identity and closure rechecks reject drift
already visible before deletion. For a route, the exact route GET is adjacent
to DELETE. For a Worker, identity is necessarily a multi-request observation;
the final version-closure page is adjacent to DELETE, while deployment,
settings, exposure and attachment checks precede it. None of those request
sequences is an atomic CAS. A new external-admin mutation can still race after
the last relevant read, so no stronger claim is made about writes outside SOW.
R2 has no conditional DeleteObject. Lease release and expired recovery therefore
use only the provider-validated conditional PutObject primitive: the exact live
ETag is CAS-replaced by a non-owning marker containing the digest and canonical
body of the previous lease. Acquisition may CAS that marker to a new live lease.
A stale holder can neither renew nor retire the replacement because its ETag no
longer matches, and there is no unconditional delete that could erase a new holder.

The lease expiration decision also uses the executing host's wall clock and
therefore assumes bootstrap hosts have bounded clock skew; it is not a provider
fencing token for a severely skewed host. A crashed executor leaves a
five-minute lease rather than unlocking an uncertain mutation. The separately
authorized `recover-lease` mode can retire only an expired, canonical,
plan/account/zone-matching lease by matching ETag and emits a private durable
recovery receipt.

## Consequences

- The shipped readiness and bootstrap registries remain empty, so ordinary
  tests and accidental environment variables cannot perform a cloud mutation.
- A reviewed plan can be produced offline from the CLI edge contract without
  credentials. Registry candidates are private files outside the repository.
- The official Cloudflare Go SDK is used for multipart Worker upload, per-script
  exposure, route creation/deletion, inventories and non-forced script deletion.
  Loopback protocol tests assert both auth and origin multipart bodies, create-only
  headers and exact route bodies. Failure-injection, cross-run takeover,
  compare-and-set acquisition/renewal/idle retirement/recovery, lease-only bucket pagination/identity,
  post-readiness provider drift, stale inventory omission, checked-delete
  identity/version/attachment drift, bounded mutation lifetime, final-read to
  DELETE request adjacency, exact-404 replay and provider-success/client-error
  replay tests are required.
- This closes the hidden manual deployment step for SOW-owned Cloudflare
  bundles. It does not claim the live Cloudflare POC passed; readiness,
  credentials, explicit authorization and real provider observations are still
  required.
