# 2026-07-19 edge entitlement expiry canonicalization

## Conclusion

The Cloudflare and EdgeOne adapters now accept exactly one static entitlement
expiry wire form: whole-second UTC RFC3339
`YYYY-MM-DDTHH:MM:SSZ`. Timezone-less, numeric-offset, fractional, invalid
calendar rollover and `24:00:00` values fail adapter construction. A malformed
Basic entitlement document now fails construction as well; it can no longer
survive deployment and become only a request-time 503.

This closes a cross-vendor authorization ambiguity. JavaScript `Date.parse`
accepts timezone-less input in the runtime's local timezone, so two vendor
runtimes could otherwise disagree about the validity interval of the same
credential. The strict grammar plus ISO round trip makes the decision
independent of runtime timezone and rejects calendar normalization.

## Implementation

- `edge/shared/contract.mjs` validates both optional static entitlement
  bindings at adapter construction and uses one `canonicalUTCExpiryMillis`
  function for admission and request-time expiry checks.
- The checked-in Cloudflare and EdgeOne bundles were regenerated from the
  source; the service-only R2 origin bundle was byte-unchanged.
- ADR-0004 and `edge/README.md` now freeze and document the exact secret schema.
- The shared contract suite exercises a valid leap-day boundary, five invalid
  expiry classes, malformed Basic JSON/schema and a dormant malformed static
  secret in provider mode against both vendor adapters. Every construction
  failure asserts zero origin and entitlement-provider calls.

Generated bundle SHA-256 values after the rebuild:

```text
cloudflare-worker.mjs        19e0254e71bd5bbf2c846fb5722b28a236ffe146e518481d5b80e1d7069782c5
cloudflare-origin-worker.mjs 54f9dfe5d124b59cd4c81feb5980f9f8a30f95adb85c8c0f786b27915a646923
edgeone.js                   1702282c1209e70409dd6cfd30f98886a437d414f64a01eb3e6ab29ca2658523
```

## Reproducible validation

```text
node --test test/contract.test.mjs --test-reporter=spec
  46 tests, 46 pass, 122.543041ms

npm run build
npm test -- --test-reporter=spec
  build freshness + three syntax checks + 46 tests, 46 pass, 119.742875ms

TZ=UTC node --test test/contract.test.mjs --test-reporter=dot
  46 tests, 46 pass, 112.83375ms

TZ=Asia/Shanghai node --test test/contract.test.mjs --test-reporter=dot
  46 tests, 46 pass, 114.606042ms

go test ./internal/config ./internal/cli \
  -run 'Edge|Deployment|TokenVerifier|Contract' -count=1
  internal/config 0.473s, internal/cli 54.164s, PASS

go test ./test/compat \
  -run 'CloudflareEdge|EdgeContract|RealCloudCloudflareBootstrap.*Contract' -count=1
  0.653s, PASS

go vet ./...
go vet -tags perf ./internal/cli ./test/perf
staticcheck -checks='inherit,-ST1005,-U1000' ./...
go mod tidy -diff && go mod verify
git diff --check
  PASS; Staticcheck 2025.1.1 (0.6.1), both module verification gates clean
```

All validation above used local source, generated bundles, local HTTP fixtures
and in-memory vendor adapters. It used no cloud credential and performed no
Cloudflare, R2, COS or EdgeOne mutation. It strengthens FR-38/FZ-08/NFR-06 but
does not upgrade the still-open real Worker, CDN cache, purge, provider-log or
multi-PoP evidence.
