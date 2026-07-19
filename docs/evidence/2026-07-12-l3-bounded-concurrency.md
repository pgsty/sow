# L3 bounded-concurrency and 50,000-object evidence (2026-07-12)

## Result

Publication L3 no longer performs one CDN round trip at a time. The publisher
uses the configured `WithWorkers` bound for CDN byte verification, streams and
closes every response body, preserves plan-order error reporting, stops
dispatching new work after an observed failure, cancels outstanding requests,
and joins every started worker before returning.

The CLI and publisher both reject worker counts outside `1..64`; the CLI
default is `min(runtime.NumCPU(), 64)`. This is a per-remote-target bound, so
the fixed two-target cf/cos execution has a hard aggregate ceiling of 128
publisher workers rather than scaling with object count.

The coordinator retains at most the plan plus completed out-of-order results;
it never creates one goroutine per object. Uploads, mutable commit points,
purge, and checkpoint CAS retain their existing ordering semantics.

## Reproducible evidence

Executed from the repository root with Go 1.26.5:

```text
GOTOOLCHAIN=go1.26.5 go test -count=1 \
  -run '^TestCDNVerificationFiftyThousandObjectClosure$' -v ./internal/publish

cdn_verify_50k objects=50000 workers=8 peak=8 elapsed=80.712292ms
PASS
ok github.com/pgsty/sow/internal/publish 0.513s

GOTOOLCHAIN=go1.26.5 go test -count=1 \
  -run 'TestCDNVerification' ./internal/publish
PASS

GOTOOLCHAIN=go1.26.5 go test -race -count=1 \
  -run 'TestCDNVerification' ./internal/publish
PASS
```

最终 product-source 摘要
`667ad529751a9a975944fa51dbcd52e30e36b40d19a5203c9a4d084ddeeae5b6`
重跑为 `objects=50000 workers=8 peak=8 elapsed=79.63325ms`，package 0.359s，PASS。

The focused suite additionally proves:

- configured peak concurrency is reached but never exceeded;
- all 50,000 expected objects are opened and every body is closed exactly once;
- a later, faster failure cannot replace an earlier plan-order failure;
- query credentials are redacted from verification errors;
- early failure prevents the remaining queued expectations from being dispatched;
- context cancellation remains discoverable with `errors.Is`, and response
  close failures fail the publication rather than being discarded.
- `--workers 65` and a direct publisher configured with 65 workers fail before
  state mutation, origin/CDN requests, or goroutine-pool construction.

## Evidence boundary

The 50,000-object fixture uses the real publisher coordinator and streaming
hash verifier with an instrumented protocol driver. It proves algorithmic
work count, worker bounds, cleanup, cancellation, and failure ordering; its
elapsed time is not a WAN/CDN throughput claim. Real Cloudflare and EdgeOne
latency, quota, cache tier, purge, and credential behavior remain blocked on
the paid-provider validation window and are not reported as passed here.
