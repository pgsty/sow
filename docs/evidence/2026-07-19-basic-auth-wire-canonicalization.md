# 2026-07-19 Basic authorization wire canonicalization

## Conclusion

The shared Cloudflare and EdgeOne fallback now accepts one bounded Basic
authorization wire contract: a case-insensitive `Basic` scheme, one or more
literal SP bytes, canonical padded RFC 4648 Base64, and at most 1024 decoded
printable US-ASCII bytes in `user:password` form. The user is non-empty; the
password may contain additional colons. Control bytes, DEL, non-ASCII bytes,
missing separators, Base64 aliases and oversized credentials return private
401 before either origin adapter is called.

The entitlement digest remains SHA-256 over the exact decoded ASCII
`user:password`, so existing supported credentials do not migrate. The 401
challenge is now `Basic realm="Pigsty Pro"`; it no longer advertises UTF-8 that
the implementation does not support. This follows the control-character and
credential construction boundary in [RFC 7617](https://www.rfc-editor.org/rfc/rfc7617.html)
and the case-insensitive authentication-scheme rule in
[RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html).

## Implementation and negative closure

- `edge/shared/contract.mjs` bounds the complete header before parsing, bounds
  the token before `atob`, checks decoded length, and requires a byte-for-byte
  canonical Base64 round trip before hashing.
- The shared parser rejects tab separation, embedded whitespace, URL-safe and
  unpadded aliases, non-zero padding bits, empty user, missing colon, CTL, DEL,
  UTF-8 bytes, a 1025-byte credential and an oversized header.
- Both adapters accept canonical, lower-case-scheme and multi-SP forms, strip
  the customer credential before origin, preserve an empty password and
  additional password colons, and accept the exact 1024-byte decoded boundary.
- Every invalid case asserts the realm-only 401 challenge and zero origin
  calls. EdgeOne's own clean COS SigV4 `Authorization` is allowed; the customer
  Basic bytes are proven absent from that subrequest.
- The Cloudflare and EdgeOne deployment bundles were regenerated from the same
  source. The service-only R2 origin bundle was byte-unchanged.

Generated bundle SHA-256 values:

```text
cloudflare-worker.mjs        85389273136e7b67b58ef0a57afbadac34dcca4fad7181506ad2239e0c9fea0c
cloudflare-origin-worker.mjs 54f9dfe5d124b59cd4c81feb5980f9f8a30f95adb85c8c0f786b27915a646923
edgeone.js                   04224c76274d6ab45061ed6d7ce5e687766026dc58d83b9efd226ca01b7d4685
```

## Reproducible validation

```text
cd edge
node --test test/contract.test.mjs --test-reporter=spec
  47 tests, 47 pass, 163.310917ms

cd ..
npm test --prefix edge -- --test-reporter=spec
  build freshness + three syntax checks + 47 tests, 47 pass, 140.634583ms

cd edge
TZ=UTC node --test test/contract.test.mjs --test-reporter=dot
  47 tests, 47 pass, 171.552208ms

TZ=Asia/Shanghai node --test test/contract.test.mjs --test-reporter=dot
  47 tests, 47 pass, 169.410083ms

cd ..
go test ./test/compat \
  -run 'TestRealCloudEdgeTokenValidation|TestRealCloudAnonymousGatedResponseContract|TestRealCloudGatedCacheEvidenceContract|TestRealCloudCloudflareBootstrapPlanBuilderConsumesExactEdgeContract' \
  -count=1
  0.701s, PASS

SOW_RUN_DOCKER_COMPAT=1 SOW_COMPAT_NGINX=1 \
  go test -timeout 25m -count=1 ./test/compat \
  -run '^TestDockerClientCompatibility$'
  77.657s, PASS
```

All validation in this report used local source, generated deployment bundles,
local Request/HTTP fixtures, in-memory vendor adapters, temporary Nginx roots
and fixed Docker client images. The Docker matrix rechecked real apt/YUM/DNF
consumption and the existing Nginx Basic path; the JavaScript Basic wire itself
is proven by the shared adapter suite above. No cloud opt-in or credential was
enabled, and no Cloudflare, R2, COS or EdgeOne request or mutation occurred. It
strengthens FR-40/FZ-08/NFR-06 but does not upgrade the still-open real Worker,
CDN cache, purge, provider-log or multi-PoP evidence.
