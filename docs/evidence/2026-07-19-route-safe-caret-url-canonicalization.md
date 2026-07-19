# V-29: Route-safe caret URL canonicalization

- Date: 2026-07-19
- Baseline: `0a1d520fa4ee9a5030cff8a1f9125f01cd45466a`
- Scope: Go route/publish/serving/verification chain plus the shared Cloudflare Worker/EdgeOne parser
- External mutation: none

## Result

The local and edge route contract now carries an RPM-valid caret byte through
one standards-compatible wire spelling. A literal `^` in a URL constructed by
the standard `Request` API serializes as uppercase `%5E`; the shared edge parser
accepts only that exact sequence, reconstructs the literal caret object key and
routes the same key through both vendor adapters.

The same narrow mapping now covers every mirrorlist producer and consumer.
`ChannelState` retains a literal config-valid root such as
`yum/infra^next/x86_64`, while beta/latest static bodies, local serving,
stable transformed verification, runtime token/Basic expectations and
compatibility Verify/purge URLs all use `infra%5Enext`. Cloudflare and EdgeOne
dynamic Pro mirrorlists emit the identical wire bytes. No client URL contains
a raw caret that a subsequent standard request would serialize differently.

The local directly-hostable path is closed too. The Nginx renderer now validates
each route segment with the frozen literal alphabet instead of its former
`._-/` subset. Its generated location and alias retain literal `^`; a real
Nginx public/Basic loopback accepts the client `%5E` form and serves that exact
tree without weakening authentication, ownership, traversal or symlink gates.

The previous blanket percent rejection made a locally valid name such as
`tool-1.0^git.rpm` unreachable through a normal URL client. General
percent-decoding was not enabled. Lowercase `%5e`, encoded unreserved bytes,
encoded `/`, double encoding, raw serialized caret, trailing-empty segments and
query/fragment forms that remain visible in `Request.url` fail before origin.

WHATWG parsing removes dot segments and normalizes special-URL backslashes
before either adapter receives `Request.url`; shared JavaScript cannot inspect
the original request-target. New tests therefore do not claim raw rejection.
They prove the final canonical path re-enters the route allowlist and
entitlement scope: an owned canonical target may route, an unowned target is
404, and a token normalized outside its `/pkg` scope is 403, both with zero
origin calls for the denied cases. Provider pre-Worker cache-key convergence or
raw-rule rejection remains a real POC-06 requirement.

[ADR-0039](../adr/0039-caret-url-wire-canonicalization.md) records why this
narrow canonical wire representation preserves the frozen route alphabet and
does not create an object-key alias.

## Implemented evidence

- `internal/config/config_test.go` exhaustively checks all 256 possible byte
  values and proves the Go exact encode/decode helper rejects raw/lowercase,
  double, encoded-unreserved/separator and trailing aliases.
- `internal/publish/model.go`, `saga.go` and `model_plan_test.go` prove channel
  JSON keeps literal caret while beta/latest bodies and stable transformed
  verification use uppercase `%5E`; a raw-caret digest is rejected.
- `internal/serving/model.go` generates identical local latest/stable bodies.
- `internal/serving/nginx.go` renders caret roots as literal origin locations
  and escaped regex literals; its unit tests retain directive-injection
  rejection. `test/compat/nginx_product_include_test.go` drives a real Nginx
  public and Basic-auth include from `%5E` URLs into a literal caret tree.
- `internal/cli/publish_plan.go`, `verify_remote.go` and
  `publish_compat_closure.go` use the shared helper for plan bodies, runtime
  token/Basic expectations, positive Verify and purge recognition.
- `internal/cli/verify_remote_test.go` runs real CLI add/publish/verify flows for
  beta→latest and stable token/Basic with `yum/test^next/x86_64`; L3 and L4 pass.
- `edge/shared/contract.mjs` performs exact `%5E` decode-and-reencode equality
  before the existing safe-segment predicate and uses the inverse exact encoder
  when constructing a dynamic mirrorlist client URL.
- `edge/test/contract.test.mjs` proves standard `Request` serialization,
  anonymous and token-gated caret routing, literal origin-key recovery, and
  origin-free rejection of percent and trailing-slash alias classes on both
  Cloudflare and EdgeOne. It also covers allowed-final, unowned-final and
  scoped-Pro outcomes after WHATWG dot/backslash normalization, plus token and
  Basic dynamic mirrorlists whose channel roots contain caret.
- `edge/dist/cloudflare-worker.mjs` and `edge/dist/edgeone.js` were regenerated
  from the shared source; the build freshness check passes.

## Reproduced commands

```bash
go test -count=1 ./internal/config ./internal/cli \
  -run 'RouteSegmentContract|NonRoutable|Routable|AssetLogicalPath|AssetAddRejectsNonRoutable'
go test -race -count=1 ./internal/config ./internal/cli \
  -run 'RouteSegmentContract|NonRoutable|Routable|AssetLogicalPath|AssetAddRejectsNonRoutable'
go test -count=1 ./internal/publish \
  -run '^TestJoinCDNURLUsesCanonicalCaretWireForm$'
go test -count=1 ./internal/config ./internal/publish ./internal/serving ./internal/cli \
  -run 'CanonicalRouteWirePathAndURL|YUMChannelPointerCanonicalCaretWireForm|ValidateIntentCDNBindingsCanonicalCaretStableMirrorlist|MirrorlistBodyCanonicalCaretWireForm|BuildCompatibilityL4ChecksBindsIndependentGenerationAndRawRoutes|CompatibilityPlanRouteRequiresExactObjectsVerifyAndPurge|VerifyCLIL3AndL4ClosePublishedAPTAndYUMProtocols|VerifyCLIStableUsesRuntimeTokenWithoutPersistingOrLoggingIt'
go test -race -count=1 ./internal/config ./internal/publish ./internal/serving ./internal/cli \
  -run 'CanonicalRouteWirePathAndURL|YUMChannelPointerCanonicalCaretWireForm|ValidateIntentCDNBindingsCanonicalCaretStableMirrorlist|MirrorlistBodyCanonicalCaretWireForm|BuildCompatibilityL4ChecksBindsIndependentGenerationAndRawRoutes|CompatibilityPlanRouteRequiresExactObjectsVerifyAndPurge|VerifyCLIL3AndL4ClosePublishedAPTAndYUMProtocols|VerifyCLIStableUsesRuntimeTokenWithoutPersistingOrLoggingIt'
npm run build --prefix edge
npm test --prefix edge
SOW_COMPAT_NGINX=1 go test -count=1 ./test/compat \
  -run '^TestProductGeneratedNginxIncludeLoopbackContract$' -v
```

Observed current-source results:

```text
focused Go ordinary: config 0.608s, cli 2.160s PASS
focused Go race: config 1.272s, cli 2.626s PASS
Go publisher canonical caret URL: 0.634s PASS
cross-layer Go ordinary: config 0.821s, publish 0.794s, serving 0.469s, cli 15.390s PASS
cross-layer Go race: config 1.772s, publish 1.787s, serving 2.980s, cli 25.430s PASS
real Nginx public/Basic caret loopback: package 10.743s PASS
edge build freshness, syntax and 45/45 shared contract tests PASS
edge node test duration: 128.386292ms
all-package compile gate, go vet, Staticcheck SA*/S1* and git diff --check PASS
clean-delivery policy closure: 2.083s PASS
```

## Evidence boundary

All executable tests used local temporary repository state, a real local Nginx
process, local HTTP provider protocol transports, in-memory vendor fixtures and
generated deployment bundles.
No external credential was read, no cloud request was made, and no local or
cloud production repository was modified.
This closes the cross-language caret/path defect and strengthens FR-38's local
shared-contract evidence. It does not claim a deployed Cloudflare Worker,
EdgeOne function, provider cache normalization, purge, multi-PoP observation or
POC-06 success. The clean-delivery policy closure was also rerun with all
real-cloud switches disabled and passed in 2.083s after admitting the
superseding spec as an exact delivery file.
