# 2026-07-20 static verifier provider attestation

## Result

The real-cloud acceptance control plane now consumes the same strict
`provider://ID` / `env://NAME` union as the product edge contract. The bounded
default acceptance config uses `env://SOW_REAL_EDGE_STATIC_ENTITLEMENTS`, so a
Cloudflare run no longer requires an independently deployed third verifier
Worker. Provider mode remains covered and unchanged in capability.

This is local and loopback-provider evidence. All destructive/readiness/edge
opt-ins remained off; no credential was read and no request was sent to R2,
Cloudflare, COS, EdgeOne or a production repository. POC-06 and FR-38 therefore
remain unverified in real cloud.

## Closed contract

- Attestation config, deployment identity and raw fact advance from v3 to v4.
  The acceptance harness advances to v8 so an old workspace cannot silently
  resume under the new verifier semantics.
- `provider://ID` requires the existing three Cloudflare Workers, exact verifier
  bundle/binding/runtime digests, EdgeOne HTTPS verifier URL, bearer and pinned
  external deployment identity.
- `env://NAME` requires all provider-only fields to be empty. Cloudflare manages
  auth/origin only; auth contains `ORIGIN` plus exact `NAME` as `secret_text`.
  EdgeOne omits verifier URL/bearer/deployment evidence and accepts the same
  name only as a `secret`-typed, value-redacted runtime entry. A same-name
  plaintext variable or returned secret value fails closed.
- Attestation decode receives the actual expected product YAML bytes from its
  caller. It checks their digest and verifier mode before credential decode or
  client construction; first-step log-sink mutation also checks the durable
  ledger's config digest. Attestation can no longer choose a different product
  mode and manufacture a matching digest for itself.
- The provider entry point loads only non-secret resource identity; it does not
  read the two entitlement bearer tokens. Before reading any of the six
  provider/publisher credentials, the collector
  also requires the exact two active stages and both vendors' `ConfigSHA256` to
  match that product digest. Missing stages, vendors or a single digest mismatch
  stop at top-level and post-deployment credential-read sentinels covering all
  eight secret variables and cannot reach client construction.
- The raw fact records only verifier kind and non-secret name. Static facts must
  have empty verifier Worker identity/ETag/digests; provider facts must have all
  of them. The durable ledger binds the canonical `kind://name` parsed from the
  exact product YAML alongside its byte digest, and rejects facts from another
  config, verifier name or mode. It also rejects mixed, missing, unknown-kind
  and v3 facts.
- Every Cloudflare binding is checked as a closed SDK union. Besides exact
  name/type/value identity, all fields belonging to other binding variants and
  all unknown raw JSON fields must be absent. In particular, a `secret_text`
  carrying a residual `service`, bucket, KV or database capability fails. The
  enclosing `bindings` field must be an explicit non-null valid array, and every
  admitted raw binding value must retain its JSON string type; omitted arrays,
  nulls and zero-value coercions cannot hash as valid empty capability evidence.
  The raw resources object must contain `bindings`, `script` and
  `script_runtime` exactly once with their array/object types and no unknown
  keys. `script`, `script_runtime` and nested `limits` are themselves token-walked
  exact objects: duplicate ETag/limits, string-typed `cpu_ms`, non-string flags
  and missing/unknown fields fail, so nested SDK projection cannot create an
  ambiguous runtime inventory. The separate mutable `/settings` response is
  closed from its SDK-preserved raw body too: exact outer keys and exact nested
  cache, limit, observability, logs and traces objects reject duplicate keys,
  missing fields, numeric strings, null inventories and unknown fields before
  the typed SDK values are trusted. Raw settings bindings are canonicalized as
  duplicate-free flat-string objects and must equal the immutable active
  version's exact binding multiset. Raw schedules must be an explicit empty
  array, while workers.dev and preview exposure must be explicit JSON `false`;
  null/missing/duplicate projections fail in both the per-Worker security
  observation and the independent complete routing/inventory recheck.
- Runtime names use the same uppercase/underscore grammar as the product and
  bootstrap contracts, including a leading underscore.

## Provider-protocol evidence

`TestRealCloudStaticProviderControlUsesTwoCloudflareWorkers` uses the official
Cloudflare and Tencent SDK clients against one loopback provider. It reads the
reviewed auth/origin/EdgeOne bundles, observes closed runtime/settings,
schedule, workers.dev, complete route/domain/Worker inventory and exact
EdgeOne runtime, and asserts that no third verifier Worker endpoint is ever
requested.

`TestRealCloudProviderControlKeepsThreeWorkerVerifierContract` runs the same
SDK surface in provider mode and requires the external verifier Worker,
security digest and binding digest. The full raw-log/control-plane bracket test
now uses the default static product config and emits a v4 static raw fact while
preserving dual-provider log reconstruction, double reads and lease behavior.

## Negative evidence

Focused tests reject provider fields in static config, missing or substituted
static secrets, provider bearer/URL/deployment residue, provider service
binding substitution, extra EdgeOne provider bearer, product-config digest
substitution, self-consistent cross-mode product replacement, plaintext or
non-redacted EdgeOne secret substitution, invalid ledger kind/name,
cross-product or valid-name cross-verifier ledger fact splicing, mixed
Cloudflare binding variants, missing/null/mistyped binding inventories and raw
values, duplicate/unknown outer resources keys, ambiguous raw `/settings`,
settings/version binding drift, null/duplicate schedules or exposure booleans,
duplicate/null/unknown EdgeOne runtime wire fields, static facts retaining
verifier Worker evidence and provider facts missing it.
Nested duplicate keys, omitted telemetry members and wrong runtime/settings
JSON types are covered independently.

Tencent's product documentation defines a Secret whose value is no longer
visible after save, while the current public API data-type page still lists only
`string` and `json`. The collector therefore requires an observed redacted
`secret` wire type and will fail a real PoC if that provider surface is absent;
it does not infer secrecy from an ordinary environment-variable name or value.
The Tencent SDK discards raw JSON, so its dedicated transport first captures a
bounded runtime response, exact-token-walks the response and every
`Key/Type[/Value]` object, and clears the temporary bytes after SDK consumption.
Duplicate `Type`/`Value`, null, missing, unknown and wrong-type fields fail
before SDK projection. The same bound/read/close/clear gate precedes status
handling, and non-success bodies become a fixed error rather than reaching the
SDK's unbounded error-body path. Other actions and clients do not expose this
capture.
See [Environment Variable and Secret](https://intl.cloud.tencent.com/document/product/1145/62764)
and [FunctionEnvironmentVariable](https://cloud.tencent.com/document/product/1552/80721#FunctionEnvironmentVariable).

## Verification

- Focused static/provider/runtime/ledger/purge-watcher/environment suite — PASS
  (`2.853s`); final raw-resource/settings and official-SDK control regression —
  PASS (`0.907s`).
- `go test ./test/compat -count=1` — PASS (`8.654s`).
- `go test -race ./test/compat -count=1` — PASS (`13.028s`).
- `go test ./... -run '^$' -count=1` — PASS; every Go package compiles.
- `go vet ./...` — PASS.
- `staticcheck -checks='inherit,-ST1005,-U1000' ./test/compat` — PASS.
- `npm test --prefix edge` — PASS (`47/47`, `136.781ms`).
- `git diff --check` — PASS.
- Final clean-context Blind and Edge reviews — PASS (`[]`, `[]`).

All commands above were rerun on the review-loop-11 corrected tree after the
static secret namespace uniqueness guard, external product binding, redacted
EdgeOne secret type, exact ledger config/verifier binding, closed Cloudflare SDK
binding unions, exact raw immutable resources and mutable settings closure, and
their negative tests were added. Real-cloud opt-ins remained off throughout.

## Remaining external proof

The code path is ready for a reviewed static bootstrap/deployment registry and
a scoped non-production Cloudflare API token. Actual Worker upload, two exact
routes, token/anonymous HTTP probes, cache/purge/provider-log observation and
rollback still require the designated empty `pro` resources. COS/EdgeOne and
production repositories were not used.
