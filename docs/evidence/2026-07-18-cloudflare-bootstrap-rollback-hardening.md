# 2026-07-18 Cloudflare bootstrap rollback hardening

Status: local implementation, official-SDK loopback contracts, failure
injection, race tests, clean-delivery policy and the complete ordinary Go suite
passed. No real-cloud opt-in was enabled and no Cloudflare or CO/COS resource
was read or mutated by these commands. This is not a POC-06 pass.

## Safety defect and resolution

Cloudflare's documented Route Delete and Worker Script Delete APIs do not
accept an `If-Match`, version or other conditional-delete precondition. The
old rollback performed an identity check before the leased wrapper renewed the
lease and revalidated provider closure, leaving an avoidable check/delete gap.

The rollback boundary now has these properties:

- the sealed receipt identity is passed into one checked-delete adapter call;
- each mutation renews the lease, revalidates bucket/provider closure, requires
  at least one full mutation interval of remaining lease lifetime, and runs
  under a deadline equal to one third of the five-minute TTL;
- a route is exact-probed by receipt ID and must still match ID, pattern and
  script immediately before non-conditional DELETE;
- an auth/origin Worker is exact-probed even if account inventory omitted it,
  then the zone/account route, custom-domain, schedule and attachment closure,
  active deployment/settings/exposure identity, and entire bounded version set
  are rechecked; exactly the sealed version may exist and deletion uses
  `force=false`;
- exact 404 is an idempotent already-converged step, so a provider-side success
  followed by client response loss safely replays without an extra deletion;
- rollback requires its fresh, sealed readiness receipt before any credential
  is read or client is constructed;
- `recover-lease` constructs a SigV4 R2-only control client. It neither reads
  the CDN token nor constructs a Worker client.

The implementation does not claim an atomic provider CAS. A route GET and
DELETE are separate requests; Worker identity is necessarily a multi-request
observation whose final version page precedes DELETE. An external administrator
can still race after the last read, and the five-minute lease uses local wall
time rather than a provider fencing token. ADR-0034 records those limits.

## Adversarial regressions

The ordinary and race suites cover:

- route and Worker replacement at the inner checked-delete boundary;
- provider closure consuming the mutation budget before the inner call;
- a newly attached route/schedule/domain or extra inactive/draft Worker
  version;
- provider inventory omitting receipt routes or Workers while exact probes
  still find them;
- provider deletion succeeding before the client receives an error, followed
  by effect-free replay;
- SDK-level exact 404, deployment drift, extra-version rejection, final-read
  ordering and proof that no DELETE was issued on drift;
- pre-credential apply/rollback selection and R2-only recovery authority.

## Commands and measured results

All commands ran from the current source tree with every real-cloud opt-in at
its default disabled value:

```text
go test ./test/compat -run 'TestRealCloudCloudflareBootstrap' -count=1
PASS  1.370s

go test -race ./test/compat -run 'TestRealCloudCloudflareBootstrap' -count=1
PASS  1.920s

go test ./test/compat -count=1
PASS  7.759s

go test -race ./test/compat -count=1
PASS  11.646s

go vet ./test/compat
PASS

go test ./internal/publish -count=1
PASS  6.807s

go test ./internal/cli -count=1 -timeout=30m
PASS  1155.500s

go test ./... -count=1 -timeout=30m
PASS  internal/cli=1211.904s; compat=31.877s; clean-delivery=7.698s

git diff --check
PASS
```

The first unsharded full-suite attempt used Go's default ten-minute package
timeout and was killed while `internal/cli` was still running. The isolated
measurement proved that package needs about nineteen minutes on this host; the
30-minute rerun passed every package. CI already runs the CLI test inventory in
ordinary and race shards with explicit package/job timeouts, so this is a local
unsharded evidence command rather than a relaxation of test coverage.

## Remaining real-provider boundary

The reviewed bootstrap registry remains closed and no Worker, route, object or
purge mutation was attempted. Live signed readiness still needs the scoped
Cloudflare read token described in the domain-readiness report. A real
bootstrap/rollback run additionally requires reviewed verifier/deployment
identity and explicit registry/confirmation inputs. POC-06 therefore remains
blocked and no production resource is an acceptable substitute.
