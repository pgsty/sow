# Vendor SDK contract evidence — 2026-07-12

## Claim and boundary

This evidence proves the frozen local implementation boundary: one official
AWS S3 SDK path serves R2 and COS, while Cloudflare and EdgeOne use their
official concrete Go SDKs. It does **not** claim that real paid vendor resources
were exercised; the Goal's R2/COS/CDN production gate remains open.

Pinned modules in `go.mod`:

- AWS SDK core v1.42.1 and S3 v1.105.0;
- cloudflare-go/v7 v7.7.0;
- Tencent Cloud TEO/common v1.3.131, API `v20220901`.

## Executed protocol evidence

The focused provider suite passed with these behaviors:

- both constructors contain the same concrete `*s3.Client` implementation;
- R2 immutable PUT uses signed `If-None-Match`, explicit `sow-sha256`, and R2
  create-only CopyObject destination binding;
- COS create/copy uses signed `x-cos-forbid-overwrite` and `x-cos-*` metadata /
  copy headers without pretending to support replacement CAS;
- COS temporary credentials project `session_token` to the signed
  `x-cos-security-token` header on both control and audit operations and never
  emit `x-amz-security-token`;
- ordinary DeleteObject requests preserve and sign the caller's `If-Match`, but
  the product never infers that a vendor enforces it: a deterministic runtime
  probe is mandatory, and the explicit checkpoint-fenced extension emits a
  truthfully unconditional DELETE only after Publisher admission;
- the COS never-versioned probe runs on every call and rejects Enabled or
  Suspended state;
- Cloudflare uses v7 exact-file purge in bounded 100-URL batches and decodes
  the SDK's public response envelope explicitly: HTTP 2xx is accepted only
  when `success=true`, `errors` is empty, and `result.id` is non-empty;
- EdgeOne uses TEO CreatePurgeTask plus DescribePurgeTasks on the exact JobId;
- optional SDK CRC/trailer headers and `aws-chunked` framing are absent;
- an S3 CopyObject HTTP 200 response containing `<Error>` is rejected after one
  attempt, proving the official SDK's embedded-error middleware remains in the
  path; CopyObject 2xx XML is independently capped at 1 MiB and an oversized
  success document is rejected before deserialization.

Commands:

```bash
go test -count=1 ./internal/publish
go test -race -count=1 ./internal/publish
SOW_MINIO_TEST=1 go test -count=1 -v ./internal/publish \
  -run '^TestMinIOS3Compatibility$'
go test -count=1 ./internal/cli
go vet ./internal/publish ./internal/cli
go mod verify
```

The independent post-fix rerun reports full `internal/publish` PASS in 4.309s,
race PASS in 7.432s, and the pinned real MinIO compatibility test PASS in 0.74s
(package 1.308s). Four HTTP-200 Cloudflare negative fixtures (`success=false`
even with a forged ID, `success=true` with errors, null result, and empty ID)
all fail closed. The provider/adoption/L2/L3/L4 CLI subset previously passed in
27.685s; the embedded-error and oversized-CopyObject focused pair passed
(package 1.012s). `go vet` for both packages and `go mod verify` also exited
zero. These timings will be rebound to the final product-source digest by the
final local audit.

The YUM remote-inventory adoption regression was also rerun directly. The
custom transport originally exposed parsed `ContentLength` without the wire
header that the generated SDK deserializer consumes; the shared SDK wrapper now
normalizes those equivalent representations. The focused test passed without
changing key decoding, ETag equality, or inventory size rules:

```bash
go test -count=1 ./internal/cli \
  -run '^TestAdoptedLatestYUMAfterBetaBuildsGenerationRouteWithoutRPMRetransfer$' -v
```

## SDK gap handling

AWS S3 models do not directly express R2's
`Cf-Copy-Destination-If-None-Match` or COS's forbid-overwrite/header dialect.
The only compatibility middleware is a closed R2/COS projection inserted
before the official SDK signer. The projected headers are signature-bound;
there is no hand-written SigV4/TC3 or direct purge fallback.

The session-token projection follows Tencent COS's temporary-key wire
contract ([Tencent temporary-key guide](https://intl.cloud.tencent.com/document/product/436/14048)).
Protocol fixtures cover both a mutation and paginated ListObjectsV2,
so the assertion is bound to the client-wide middleware rather than one
operation-specific code path. This is still protocol evidence; the opt-in real
COS harness must exercise a temporary credential before production acceptance.

2026-07-18 adds real R2 data-plane evidence on the owner-designated empty
non-production `pro` bucket: conditional PUT/CAS, HEAD/streamed GET and CopyObject
passed, while a deliberately stale DeleteObject `If-Match` was ignored and the
run-owned object was deleted. This matches Cloudflare's documented compatibility
surface and is now handled by ADR-0036's default-fail-closed / explicit
checkpoint-fenced split. See
[real R2 storage evidence](2026-07-18-real-r2-storage-protocol.md).

Real COS, Cloudflare Worker/CDN, EdgeOne, provider logs and the complete dual-cloud
transaction still need the dedicated resources, credentials and logs listed by
POC-06. The R2 storage result is not a production-cloud or full POC-06 pass.
