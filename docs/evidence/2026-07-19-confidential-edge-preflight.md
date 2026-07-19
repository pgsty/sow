# Gated publication pre-upload edge denial gate — 2026-07-19

Date: 2026-07-19 (Asia/Shanghai)
Host: Apple Silicon macOS, Go 1.26.5

## Safety boundary

All mutation-path tests used `t.TempDir` and in-process HTTP/S3/provider protocol transports. Cloud
credentials were unset, real-cloud/real-edge/upstream opt-ins were forced off, AWS profile files were
`/dev/null`, EC2 metadata was disabled, and `GOPROXY=off` was used for exhaustive CLI shards.

The only public network action was an anonymous GET of the fixed canary on the owner-authorized exact
non-production hosts `pro.pigsty.io` and `beta.pro.pigsty.io`. It carried no credential and cannot write,
purge, deploy, or change configuration. No CO/COS resource, Cloudflare production repository, Worker,
route, API, or bucket mutation was used.

## Defect and implemented boundary

The previous concrete provider preflight validated only URL shape. A stable/snapshot plan pointed at a
raw public custom domain could therefore upload `.sow/gated/...` before L3 noticed the missing edge
runtime. The fix threads `context.Context` through both vendor interfaces and `targetDriver`, then runs
one shared anonymous denial attestation before local journal acquisition or any remote mutation.

Relevant product paths:

- `internal/publish/saga.go`: preflight ordering before journal and remote saga state;
- `internal/publish/provider.go` and `driver.go`: context-aware vendor contract;
- `internal/publish/http_object.go`: confidential-plan union, bounded request/response validation and
  exact `sow-edge-runtime/v2` private 404 contract;
- `internal/publish/http_cloudflare.go` and `http_tencent.go`: both real HTTP providers call the same
  gate;
- `internal/publish/confidential_preflight_test.go`: real HTTP, failure injection, cancellation,
  read/close and exact authorized-host negative evidence;
- `internal/cli/publish_cli_test.go`: full CLI/provider protocol positive and raw-custom-domain negative
  paths.

Public-only plans make no canary request. Confidential detection covers gated object/delete keys and
every persisted Basic route surface: object/delete CDN paths, purge URLs, positive verification,
unchanged probes and absence verification. The canary is anonymous, redirect-manual and bounded to 64
bytes. A caller-supplied `http.CookieJar` is removed on both canary and normal CDN read-back clients;
the test installs a matching ambient cookie and proves it never reaches the server. A successful denial
has exact 404/body/runtime/content/cache semantics and no credential, encoding, trailer or origin marker.

## Reproducible local and protocol results

Focused implementation gates:

```text
go test ./internal/publish -count=1
ok  github.com/pgsty/sow/internal/publish  8.099s

go test -race ./internal/publish -count=1
ok  github.com/pgsty/sow/internal/publish  10.753s

go test ./internal/cli -run 'TestPublishCLI(StableUsesGatedNamespaceAndScopedBasicVerification|RejectsRawPublicCustomDomainBeforeGatedMutation)' -count=1
ok  github.com/pgsty/sow/internal/cli  2.354s

go test -race ./internal/cli -run 'TestPublishCLI(StableUsesGatedNamespaceAndScopedBasicVerification|RejectsRawPublicCustomDomainBeforeGatedMutation)' -count=1
ok  github.com/pgsty/sow/internal/cli  4.000s
```

The failure table rejects raw 404 without marker, anonymous 200/object bytes, 3xx, v1 runtime,
public cache policy, origin transport/cache markers, oversized body, response close failure, content
encoding, authentication challenge, duplicate runtime marker and canceled context. The close and
context errors remain discoverable with `errors.Is`.

The full CLI ordinary surface enumerated 679 default tests and passed through the six exhaustive CI
shards:

| Shard | Result |
|---|---:|
| `^Test[A-F]` | 540.426s PASS |
| `^Test[G-M]` | 776.669s PASS |
| `^Test[N-O]` | 246.807s PASS |
| `^Test[P-Q]` | 887.017s PASS |
| `^Test[R-V]` | 563.162s PASS |
| `^Test([W-Z]\|[^A-Z]\|$)` | 123.294s PASS |

The same exhaustive partition passed under the race detector with a 25-minute per-shard gate and no
race report:

| Race shard | Result |
|---|---:|
| `^Test[A-F]` | 567.808s PASS |
| `^Test[G-M]` | 830.500s PASS |
| `^Test[N-O]` | 246.498s PASS |
| `^Test[P-Q]` | 1023.397s PASS |
| `^Test[R-V]` | 585.309s PASS |
| `^Test([W-Z]\|[^A-Z]\|$)` | 140.420s PASS |

An intentionally unsharded retry hit Go's default 10-minute package alarm while the currently active
test had run only 12 seconds and was in a local manifest `fsync`. It is recorded as `FAIL timeout`, not
as a pass or product defect. The six disjoint CI shards are the supported exhaustive entrypoint.

## Final local closure

Every non-CLI package passed in one exhaustive ordinary and race invocation with all real-cloud,
real-edge, real-upstream, Docker, MinIO, performance and owner-resource opt-ins forced to zero.
Ordinary's longest package was `test/compat` at 28.595s; race's was `internal/upstream` at 36.100s.
`internal/publish` itself passed at 22.577s/28.665s. No race report was emitted.

The final static and delivery-input gates passed:

```text
go vet ./...                                      PASS
go vet -tags perf ./internal/cli ./test/perf      PASS
staticcheck v0.6.1 -checks=inherit,-ST1005,-U1000 PASS
go mod tidy -diff / go mod verify                 PASS / all modules verified
nested RPM test/vet/tidy/verify + v1.3.0 bytes    PASS
govulncheck v1.6.0 main/nested                    0 reachable / none
git diff --check                                  PASS
first-party and modified Go-file gofmt scan        PASS
```

The installed Staticcheck binary had been built by Go 1.26.4 and correctly refused this module's
Go 1.26.5 floor. The same pinned v0.6.1 source was therefore rebuilt with Go 1.26.5 from the local
read-only module download cache; that binary produced the recorded clean result. This is an environment
repair, not a suppressed analyzer failure.

Four `CGO_ENABLED=0 -trimpath` builds passed. Linux amd64/arm64 are static ELF with SHA-256
`b54d9a49…0cfd` / `9b2f24e8…21cd`; Darwin amd64/arm64 are target-architecture Mach-O with
`5ae8bfa4…e119` / `77999900…ca35`.

After this report and the traceability ledger were frozen, two independent clean-delivery roots rebuilt
536 allowlisted product files and 682 delivery files from fresh HOME/GOMODCACHE/GOCACHE using only the
local read-only module cache. Exact product/delivery/archive digests and paths are deliberately recorded
only in `_bmad-output/implementation-artifacts/validation-selected-set-materialization-2026-07-13.md`
outside the delivery root, avoiding a self-referential digest.

## Exact authorized raw-domain negative observation

The product helper itself was run against both frozen test hosts:

```text
SOW_RUN_AUTHORIZED_CF_RAW_PREFLIGHT_NEGATIVE=1 GOPROXY=off \
  go test ./internal/publish \
  -run '^TestAuthorizedCloudflareRawDomainsFailConfidentialPreflight$' \
  -count=1 -v -timeout=1m

--- PASS: TestAuthorizedCloudflareRawDomainsFailConfidentialPreflight (2.52s)
    --- PASS: .../https://pro.pigsty.io/ (1.28s)
    --- PASS: .../https://beta.pro.pigsty.io/ (1.24s)
ok  github.com/pgsty/sow/internal/publish  3.262s
```

Independent anonymous curl summaries at the same instant were:

```text
main: status=404 type=text/html bytes=27150 edge=<absent> cache=<absent> location=<absent> ray=FRA
beta: status=404 type=text/html bytes=27150 edge=<absent> cache=<absent> location=<absent> ray=FRA
```

Both are Cloudflare/R2 generic HTML `Object not found` responses, not
`sow-edge-runtime/v2` private denials. The new product gate therefore rejects the exact current raw
data plane before a gated mutation, as intended. This is a negative readiness result: it does not
claim Worker deployment, private origin, purge, negative verify, multi-PoP/cache log, COS/EdgeOne or
POC-06 completion.

After the final read-only probe, `rclone lsf cf:pro --recursive --max-depth -1` exited 0 with empty
stdout. No object was created by this gate, and the authorized bucket remained empty.

The rebuilt edge bundles retained their three prior SHA-256 identities and the current shared contract
passed 42/42 (`npm test`, 142.981375ms). The new case proves both vendor adapters return the exact
anonymous denial without touching either origin.

## Mutation ordering evidence

The direct publisher fault test injects provider preflight failure for both targets and observes one
preflight call, zero checkpoint/control read, zero PUT/COPY/DELETE/purge and no journal directory. The
full CLI negative uses the real R2/Cloudflare SDK protocol client with a raw-domain 404 and observes
one canary plus zero PUT/COPY/DELETE/purge. The CLI may perform read-only parent checkpoint inspection
before constructing the request; no remote mutation crosses the gate.
