# 2026-07-20 full-provider checkpoint-fenced delete

Status: final local TLS protocol, ordinary/race, static and delivery gates
passed. No cloud or production resource was accessed.

## Gap

The existing local test called
`R2CloudflareControlHTTP.R2DeleteCheckpointFenced`. A focused coverage replay
of that old surface showed:

| function | old focused coverage |
| --- | ---: |
| storage-only R2 wrapper | 100.0% |
| full Cloudflare R2 wrapper | 0.0% |
| full EdgeOne COS wrapper | 0.0% |
| shared delete implementation | 40.0% |

Real-cloud optional tests referenced the complete wrappers, but those cannot be
the only proof for a publication safety boundary.

## Executable contract

`TestFullProvidersCheckpointFencedDeleteIsExactSignedAndFailClosed` constructs
the production `R2CloudflareHTTP` and `COSEdgeOneHTTP` types against independent
real TLS loopback servers. For each vendor it proves:

- exact `DELETE /bucket/.sow/publication/retired.json?x-id=DeleteObject`;
- no `If-Match`/`If-None-Match`, including the SigV4 signed-header list;
- exact R2 `auto` + `x-amz-security-token` and COS `ap-shanghai` + native
  `x-cos-security-token` credential projection;
- one request for each 204/404/412/501 response and stable nil/not-found/
  conflict/capability classification;
- `../escape` rejection before a fifth request;
- no CDN or provider-control request.

The first run intentionally rejected the SDK request because the test assumed
an empty query. Inspection showed the official SDK's stable
`x-id=DeleteObject` operation marker for both vendors. The contract was
corrected to require exactly that marker; no production behavior changed.

## Commands and results

```bash
go test -count=1 ./internal/publish \
  -run '^TestFullProvidersCheckpointFencedDeleteIsExactSignedAndFailClosed$'
go test -race -count=1 ./internal/publish \
  -run '^TestFullProvidersCheckpointFencedDeleteIsExactSignedAndFailClosed$'

go test -count=1 -covermode=atomic \
  -coverprofile=/tmp/sow-provider-fenced-delete-final.out \
  ./internal/publish \
  -run '^Test(R2CheckpointFencedDeleteIsExplicitlyUnconditionalAndSigned|FullProvidersCheckpointFencedDeleteIsExactSignedAndFailClosed)$'

go test -timeout 15m -count=1 ./internal/publish
go test -race -timeout 20m -count=1 ./internal/publish
go test -run '^$' ./...
go vet ./...
staticcheck ./...
```

Focused ordinary/race passed in 0.528s/1.598s. The complete publish package
passed in 8.546s/15.035s with no race report. Compile, vet and Staticcheck
passed. Combined atomic coverage was 100% for the storage-only R2, full R2 and
full COS wrappers, and 90% for `deleteObjectCheckpointFenced`.

The only product-source change is this executable test; production Go bytes are
identical to V-50. After this report, its spec, trace row and delivery allowlist
were frozen, two isolated clean deliveries were rebuilt with the local
read-only module proxy and compared bytewise. Their final identity is recorded
in the delivery-external V-52 section of
`_bmad-output/implementation-artifacts/validation-selected-set-materialization-2026-07-13.md`.

## Boundary

TLS terminates in `httptest`; all credentials are inert contract literals. The
test does not resolve or contact Cloudflare, Tencent, R2, COS, EdgeOne, any CDN
or any Pigsty domain. V-51 adds local protocol evidence only and does not
upgrade POC-01/POC-06, real-cloud, production-migration or operational metrics.
