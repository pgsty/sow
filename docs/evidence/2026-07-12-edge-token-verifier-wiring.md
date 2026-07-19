# Edge token-verifier wiring evidence — 2026-07-12

> Supersession note (2026-07-15): this report preserves the original local v1
> verifier-wiring run. Executable adapters now reject v1 and require the v2
> exact route-admission contract defined by ADR-0004; current evidence must be
> reproduced from the current source and must not reuse the historical counts
> below.

## Contract under test

This evidence covers the local implementation and vendor-adapter contract for
FR-38/FR-39 and the token-verifier portion of FR-40. It does not claim a live
Cloudflare or EdgeOne deployment.

- `internal/config/edge.go` parses the closed `env://NAME | provider://id`
  verifier union and maps every configured target to a secret-free
  then-current `sow-edge-runtime/v1` deployment contract during config
  preflight (now superseded and rejected by the adapters).
- `edge/shared/contract.mjs` consumes the mapped runtime variables and owns the
  shared digest-only provider protocol and fail-closed status mapping.
- `edge/cloudflare/worker.mjs` binds provider mode to `TOKEN_VERIFIER`. Its
  deployable `r2-service` path reaches `edge/cloudflare/origin.mjs` through the
  private `ORIGIN` binding and deliberately reports cache `BYPASS`; the separate
  `https-bearer` path is the same-host cache-PoC interface.
- `edge/edgeone/function.mjs` binds provider mode to an HTTPS endpoint plus the
  `SOW_TOKEN_VERIFIER_BEARER` platform secret. Its direct COS GET/HEAD path is
  fixed-host SigV4 and reports `BYPASS`; its separate `https-bearer` mode is the
  same-host cache-PoC interface.
- `edge/shared/private-origin.mjs` owns strict object-key and fixed-origin
  checks shared by the Cloudflare auth/origin path and EdgeOne.
- `edge/testdata/runtime-contract.json` is read by both the Go config test and
  the two JavaScript adapters' contract fixtures, preventing the original
  `provider://...` value from becoming an unconsumed placeholder again.

No generated contract, example or test fixture contains a raw customer token,
verifier bearer, origin credential or entitlement document. Only binding names,
non-secret origins and the logical provider ID are persisted.

## Reproducible checks

From the repository root:

```bash
go test -count=1 ./internal/config
go vet ./internal/config
```

Observed result: config tests pass, including strict reference rejection,
target-specific binding mapping, env-secret mapping, no-secret serialization
and cross-language runtime-fixture parity.

From `edge/`:

```bash
npm run build
npm test
```

Observed result on the unbound 2026-07-12 worktree: all three generated
single-file bundles are current, pass `node --check` and load without source-tree
imports; 26 shared/private-origin
contract tests pass. The tests prove:

1. both vendors send `sow-token-verifier-request/v1` with the same provider ID,
   token SHA-256, audience and canonical path;
2. the raw token is absent from provider URL, headers and body;
3. provider 403 maps to client 403 and provider failure maps to private 503;
4. neither denial nor outage reaches the repository origin;
5. missing binding, unknown provider syntax and malformed `env://` entitlement
   JSON fail adapter construction before origin access;
6. beta asset and APT/YUM metadata removals never fall through to latest,
   while only exact APT pool DEBs and YUM Packages RPMs share immutable bodies;
7. Go config preflight keeps this classification mechanical by reserving
   `apt`/`apt/...` for APT, `yum`/`yum/...` for YUM, and rejecting assets in
   either namespace.
8. the Cloudflare origin accepts only its internal host and GET/HEAD, preserves
   R2 metadata/ETag, performs conditional and ranged reads with `206` /
   Content-Range, and returns private no-store 404/503 failures;
9. EdgeOne derives the only credential-bearing host from the COS bucket/region,
   emits a deterministic S3 SigV4 signature, forwards Range/HEAD, strips origin
   authorization from responses, and refuses redirects without following a
   non-COS Location;
10. scheme-shaped keys remain object paths and both vendors exercise the same
    gated-key 404 to public-key fallback without customer credentials reaching
    the origin URL;
11. direct Cloudflare R2 binding and EdgeOne COS SigV4 responses are explicitly
    marked `r2-service/BYPASS` and `cos-sigv4/BYPASS`, so local correctness cannot
    be mistaken for CDN cache evidence;
12. both `https-bearer` adapters reject arbitrary origin aliases, keep a whole
    `.sow/beta/...` fallback group on the beta host, converge two token paths on
    one clean URL digest, and normalize synthetic MISS/HIT headers. These are
    interface fixtures only, not provider cache observations.

The report is not bound to a commit or dirty-worktree digest; final audit must
rerun the same commands with source identity captured.

The broader Go suite is also run by the root validation pass; this file records
only the independently reproducible surface owned by the edge wiring change.

## External gate still open

The following are deliberately not reported as passed:

- deployment of both Cloudflare bundles, the R2 binding and verifier binding;
- deployment of the generated EdgeOne bundle, HTTPS verifier and scoped COS
  secrets;
- proof that real R2 accepts conditional/Range requests through the service
  binding and real COS accepts the generated S3 SigV4 GET/HEAD requests;
- proof that EdgeOne clean subrequests populate the desired shared/tiered cache;
- proof that two distinct entitlements can read a gated-only object while the
  anonymous/public URL remains 404, and token B reports a provider `HIT` on the
  same clean URL digest;
- real-provider proof that the plan's paired client-visible and exact `.sow/*`
  clean-cache purge invalidates the cache entry used by global Fetch;
- provider/CDN log inspection proving production redaction and cache-key
  normalization across multiple PoPs.

Those checks require real accounts, credentials, zones, private origin and a
test entitlement provider. Until supplied, the local contract/build evidence is
necessary but not a substitute for the PRD's real-cloud PoC.
