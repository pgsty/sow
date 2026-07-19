# R2 reusable lease CAS retirement evidence

Date: 2026-07-19

Status: current-source local/protocol evidence passed; no cloud write was made.

## Defect closed

The owner-authorized V-21 R2 probe proved that Cloudflare R2 accepts a stale
`DeleteObject If-Match`. The Cloudflare bootstrap and provider log-sink leases
still called that API after a GET/ETag check. A contender could replace the
lease between the read and delete and have its live lease removed.

Both reusable coordination keys now have a two-state CAS protocol:

1. acquisition creates a live lease with `If-None-Match`, or replaces an
   expired live lease / canonical idle marker with `PutObject If-Match`;
2. renewal replaces only the exact live ETag;
3. successful release replaces the exact live ETag with a canonical,
   non-owning idle marker and reads it back by body and ETag;
4. bootstrap recovery performs the same live-to-idle CAS and is replayable
   from the idle marker;
5. the lease-store interface exposes Get/List/conditional Put only. Neither
   lease path can call `R2Delete`, even if the concrete R2 client provides it.

Cloudflare readiness v3 remains read-only. It admits a pristine empty bucket or
exactly one canonical idle bootstrap marker, records its key and complete
key/size/ETag/body-digest closure in the Ed25519-sealed receipt, and requires
the marker key to match the selected bootstrap plan before acquisition. Live
leases, payloads, foreign markers, multiple objects, list/GET identity drift,
continuation cycles and a marker for another plan fail before Worker authority
can mutate anything. EdgeOne readiness still requires an empty bucket.

## Executed validation

```text
go vet ./test/compat
PASS (no output)

staticcheck -checks='inherit,-ST1005,-U1000' ./test/compat
PASS (no output)

go test ./test/compat -count=1
ok github.com/pgsty/sow/test/compat 7.766s

go test -race ./test/compat -count=1
ok github.com/pgsty/sow/test/compat 11.209s

git diff --check
PASS (no output)
```

The focused tests additionally assert live conflict rejection, renewal, stale
holder rejection, expired takeover, idle takeover, recovery replay, durable
idle read-back, zero lease-store delete calls, exact idle readiness admission,
foreign payload rejection and same-plan marker binding.

The installed Staticcheck binary initially reported that it had been built with
Go 1.26.4 while the module requires Go 1.26.5. It was rebuilt from the already
cached v0.6.1 source with the current Go 1.26.5 toolchain; no repository or
dependency version changed.

## Boundary

This change uses fake-store and official-client protocol paths to close a
locally provable concurrency defect. It does not claim a live Worker bootstrap,
Cloudflare purge/negative verification, COS/EdgeOne, provider logs or POC-06
passed. No `pro` object, Worker, route, cache or control-plane setting was
written, and no CO/COS or other production resource was accessed for mutation.
