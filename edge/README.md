# SOW edge authorization contract

`shared/contract.mjs` is the single observable contract used by both vendors.
It authenticates before origin access, removes customer credentials from origin
URLs/headers and clean origin subrequests, renders a one-URL dynamic Pro
mirrorlist, and rejects control paths. Public beta/latest mirrorlists are
ordinary static objects emitted by `sow publish`; neither adapter synthesizes
them.

- Cloudflare sources: `cloudflare/worker.mjs` (public auth Worker) and
  `cloudflare/origin.mjs` (service-only R2 origin Worker).
- EdgeOne source: `edgeone/function.mjs` plus `edgeone/index.js` (documented
  `addEventListener('fetch', …)` runtime, direct COS SigV4 origin).
- Deployable single-file outputs: `dist/cloudflare-worker.mjs`,
  `dist/cloudflare-origin-worker.mjs` and `dist/edgeone.js`. The build check
  rejects stale bundles and `npm test` syntax-checks every output.

`SOW_BETA_BASE_URL` names the distinct public beta origin. Requests on that
origin resolve beta metadata below the private `.sow/beta/` namespace and fall
back to the shared public package pool; the latest origin never aliases beta.

## Versioned deployment contract

`edge.token_verifier` in `sow.yaml` is copied byte-for-byte to the non-secret
runtime variable `SOW_TOKEN_VERIFIER`. The command
`sow materialize latest --edge-contract TARGET` validates and maps this value,
then renders the secret-free, canonical-state-admitted deployment document.
Internally it uses
`Config.EdgeDeployment(target, admission)`; both executable adapters consume it
at startup. Calling `Config.EdgeDeployment(target)` without admission is
fail-closed for compatibility routes.
The other required non-secret variables are:

```text
SOW_EDGE_SCHEMA=sow-edge-runtime/v2
SOW_PRO_PREFIX=/pro/v1/{token}/
SOW_PUBLIC_BASE_URL=https://repo.example
SOW_BETA_BASE_URL=https://beta.example
SOW_PUBLIC_PREFIXES=["apt","pkg/pig","yum"]
SOW_PUBLIC_KEYS=["keys/pigsty.asc","pkg"]
```

Missing, stale or unknown values stop adapter construction. The production
entrypoints convert that failure to a private `503`; no origin request occurs.
The displayed allowlists illustrate shape only. For every real target,
`SOW_PUBLIC_PREFIXES`, `SOW_PUBLIC_KEYS`, and
`SOW_COMPATIBILITY_ADMISSION` must be installed together from the exact
document rendered by `sow materialize latest --edge-contract TARGET`;
never hand-author, merge or widen them. Expanded repository paths such as
`pkg/pig` are boundary-aware prefixes, while the configured public signing key
and root-mapped asset `pkg` are exact keys. In particular, moving `pkg` into
`SOW_PUBLIC_PREFIXES` would expose every undeclared child below that root.
Undeclared root objects such as `sow.yaml` and unknown `_sow` control routes are
always 404, including after Pro auth.
Runtime v2 also binds each ordinary YUM `(view, repo, os, arch)` coordinate to
its exact literal repository root. Compatibility coordinates use the exact
projection root. A dynamic channel document may choose a generation only; it
cannot redirect that coordinate to a sibling root. Any root mismatch returns a
private 503 without emitting a mirrorlist. Snapshot payloads and `_route.json`
are admitted by exact snapshot ID from immutable-ref inventories, so an EOL
snapshot survives current-view removal without exposing another snapshot's
objects.
The closed verifier references are:

- `provider://<id>`: Cloudflare requires a `TOKEN_VERIFIER` service binding.
  EdgeOne requires non-secret `SOW_TOKEN_VERIFIER_URL` and the platform secret
  `SOW_TOKEN_VERIFIER_BEARER`. Both transports receive the same
  `sow-token-verifier-request/v1` JSON containing the provider ID, token
  SHA-256, audience and canonical path. The raw token is never sent.
- `env://<NAME>`: both runtimes read a strict entitlement JSON array from the
  named platform secret binding. This is suitable for small/static deployments
  and deterministic tests; malformed documents fail deployment rather than
  becoming an empty allowlist.

Cloudflare provider bindings are illustrated by
[`cloudflare/wrangler.toml.example`](cloudflare/wrangler.toml.example). EdgeOne's
variable/secret inventory is in
[`edgeone/bindings.example.json`](edgeone/bindings.example.json). Placeholder
values must be supplied through the vendor deployment system; never check
secret values into either file.

Static authorization documents (for `env://`) and Basic authorization use JSON
arrays. Every entry is fail-closed and must contain a
lowercase SHA-256 credential digest, UTC expiry, exact audiences and
boundary-aware path prefixes, for example:

```json
[{"sha256":"0000000000000000000000000000000000000000000000000000000000000000","expires_at":"2027-01-01T00:00:00Z","audiences":["repo.example"],"path_prefixes":["/yum/infra"]}]
```

Expired credentials return 401; a valid digest with the wrong audience or path
returns 403. Provider denial uses the same status mapping; provider transport
failure returns 503. Private-origin variables and secrets are described below.

The contract deliberately does not use the Workers/Edge Cache API. Origin
transport is an explicit closed mode, never an implicit fallback. The
deployable `r2-service` and `cos-sigv4` modes converge token forms onto one
credential-free URL but bypass the provider CDN cache; they solve private reads,
not FR-38 cache normalization. Only the separately configured
`https-bearer` global-fetch mode is a cache-topology candidate, and it remains
unverified until POC-06 observes two-token HIT/tiered behavior and purge.

Every edge response carries `X-SOW-Edge-Contract: sow-edge-runtime/v2`. The
opt-in real-cloud harness requires this marker so a direct public bucket/CDN
mapping cannot be mistaken for a deployed edge path.
Before any gated publication mutation, the Go publisher anonymously requests
`/.sow/gated/.sow-confidentiality-preflight` and requires the exact v2
`404 not_found` private/no-store response. This path is intentionally handled
by the existing closed `.sow` namespace gate and never reaches origin. A raw
bucket 404, old runtime, redirect, Cookie challenge or cacheable response stops
the publication before its journal/checkpoint/PUT boundary; there is no bypass
flag. See [ADR-0037](../docs/adr/0037-pre-upload-confidential-edge-denial-attestation.md).
Object responses additionally expose `X-SOW-Origin-Transport`, normalized
`X-SOW-Origin-Cache-Status` and a SHA-256 of the clean origin URL. These contain
no credential or object bytes; they let the true-cloud harness distinguish a
private transport (`BYPASS`) from an observed clean global-cache `HIT`.

## Deployable private origins

### Cloudflare: service-only R2 Worker

Deploy `dist/cloudflare-origin-worker.mjs` with
[`cloudflare/wrangler.origin.toml.example`](cloudflare/wrangler.origin.toml.example),
then bind that service as `ORIGIN` in the public auth Worker. The origin config
sets both `workers_dev = false` and `preview_urls = false` and declares no public
route. Its only capability is the `REPOSITORY` R2 binding; it accepts only
`GET`/`HEAD` on the exact internal host `sow-private-origin.invalid`, rejects
credentials and non-canonical keys before touching R2, and implements R2
conditional/ranged reads. Object HTTP metadata, quoted ETag, length,
Last-Modified, `206` and Content-Range are preserved. All errors are private
and no-store.

Cloudflare documents that R2 Worker API bindings and the S3 API access the
bucket directly and do not transit Cloudflare Cache. Consequently this mode
reports `r2-service/BYPASS`; it is a deployable correctness/security path but
cannot close FR-38 or NFR-07.

The deployment identity needs permission to update these two Worker services
and attach the one existing R2 bucket. The origin service itself receives no
token verifier, CDN API, S3 API credential or public route. Keep R2 public
development/custom-domain access disabled; repository publication continues to
use its separate scoped storage credential.

### EdgeOne: direct COS SigV4

EdgeOne requires these non-secret variables:

```text
SOW_COS_REGION=ap-guangzhou
SOW_COS_BUCKET=repository-1250000000
```

Inject `SOW_COS_SECRET_ID` and `SOW_COS_SECRET_KEY` as EdgeOne platform secrets;
temporary credentials additionally use `SOW_COS_SESSION_TOKEN`. The adapter
does not accept an origin URL. It derives exactly
`https://<bucket>.cos.<region>.myqcloud.com`, validates every object key, signs
GET/HEAD with Web Crypto using S3 SigV4, forwards Range/conditional headers and
uses `redirect: manual`. A redirect is converted to a private `502`, so signed
headers are never replayed to another host.

Use a dedicated CAM sub-account or temporary role limited to
`name/cos:GetObject` and `name/cos:HeadObject` on exactly:

```text
qcs::cos:<region>:uid/<appid>:<bucket-name-with-appid>/*
```

Do not grant ListBucket, PutObject, DeleteObject, ACL, policy or CDN permissions
to this origin identity. The token-verifier secret remains independent from COS
credentials. See [`edgeone/bindings.example.json`](edgeone/bindings.example.json)
for the names-only deployment inventory.

This is a cross-host fetch to COS. EdgeOne documents that Fetch reaches its node
cache/origin only when the inbound host, fetch URL host and Host header match;
therefore `cos-sigv4` reports `BYPASS` and is not cache-normalization evidence.

## Candidate clean global-cache topology

Set `SOW_ORIGIN_MODE=https-bearer`; when the optional origin aliases are kept,
`SOW_ORIGIN_BASE_URL` must exactly equal `SOW_PUBLIC_BASE_URL` and
`SOW_BETA_ORIGIN_BASE_URL` must exactly equal `SOW_BETA_BASE_URL`. Inject
`SOW_ORIGIN_BEARER`. Every request resolved from the beta public host stays on
the beta origin for aliases, strong generation URLs, static mirrorlists and the
entire `.sow/beta/...` shared-payload fallback group; a beta namespace/view
mismatch fails closed. Latest and Pro groups use the main host. The adapters validate the customer token or Basic credentials first,
remove them, then issue a same-host global Fetch for the clean key. Redirects are refused. The external topology
must prevent anonymous access to `.sow/gated` before this mode is usable; a
Cloudflare custom domain needs appropriate WAF/access rules, and EdgeOne trigger
and origin rules must preserve same-host Fetch semantics.

Cloudflare's cache-PoC config explicitly pins `global_fetch_private_origin`.
With that compatibility behavior, a same-zone global Fetch skips mapped Workers
and security rules and reaches the zone origin; enabling
`global_fetch_strictly_public` would return to the public front door and can loop
through the auth Worker. Consequently the same-host origin itself must validate
`SOW_ORIGIN_BEARER` before serving `.sow/*`; WAF alone is not that validation.
Because the subrequest carries `Authorization`, the origin response must be
explicitly shared-cache eligible (`public`, `s-maxage`, or
`must-revalidate`), must not emit `private`, `no-store`, `Set-Cookie` or
`Vary: Authorization`, and the CDN cache key must remain the clean URL. The
live harness rejects `BYPASS`, `DYNAMIC` and `UNKNOWN`, so a merely reachable
authenticated origin cannot masquerade as cache normalization.
This is an external POC-06 deployment condition, distinct from the service-only
R2 binding transport.

Local fixtures only prove that both tokens select the same clean URL and that
provider cache-status headers are normalized. POC-06 must use two distinct
entitled tokens and a truly gated object: anonymous public and direct
`/.sow/gated/...` clean access are both edge-contract 404, token
A primes, token B reports `HIT` for the same clean URL digest, and after the
publication transaction's paired exact client/clean-key purge token A observes
new bytes before token B returns HIT. (The transaction's own L3 read-back may
already refill the clean key, so an immediate token-A `HIT` is valid.) Provider
logs must confirm the tiered/shared-cache
behavior. If any condition fails, use the no-store Basic fallback.

## Basic fallback without edge compute

FR-40 is a separate deployment, not another branch that dies with the edge
function. Materialize stable to a dedicated tree and serve it with Nginx's
native `auth_basic` using [`basic/nginx.conf.example`](basic/nginx.conf.example).
The CDN behavior forwards `Authorization` to origin and must not cache the
`private,no-store` response. Excluding Authorization from the cache key is safe
only when an edge component authenticates before cache lookup; origin-only
Basic Auth followed by a shared cache would let anonymous callers reuse a prior
authenticated fill. The real-client compatibility suite starts this standalone
Nginx configuration, proves naked paths are 404 and unauthenticated paths are
401, then installs through apt `auth.conf` and a credential-bearing dnf
`baseurl`. This path has no Worker, EdgeOne function, token verifier, shared
cache, or channel-pointer dependency.

Run `npm run build && npm test` in this directory. Besides shared auth/routing
tests, it exercises the R2 origin GET/HEAD/range/conditional contract, both
vendors' gated-to-public 404 fallback, COS SigV4 fixtures, scheme-shaped key
SSRF negatives, manual redirect refusal and response credential stripping. The
suite is a local vendor-contract test, not a real Cloudflare or EdgeOne
cache-hierarchy PoC; that external gate remains open until credentials and test
zones are provided.
