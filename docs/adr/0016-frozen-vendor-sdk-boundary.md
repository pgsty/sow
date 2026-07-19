# ADR-0016: Freeze the concrete vendor SDK boundary

Status: Accepted — 2026-07-12

## Context

The PRD excludes a generic cloud-provider layer and freezes a narrower runtime
contract: R2 and COS share one S3-compatible SDK, while Cloudflare and Tencent
cache invalidation use their own concrete SDKs. The first implementation used
hand-written SigV4, Cloudflare REST, and TC3 code. Although its protocol tests
were strict, that implementation did not satisfy the frozen dependency
boundary.

Replacing it must not weaken the existing publication invariants. In
particular, immutable writes and copies are create-only, deletion is bound to
the observed ETag, COS versioning is probed before every publication, purge is
an exact bounded URL set, and EdgeOne success means the accepted job reached a
terminal `success` state.

## Decision

The Go CLI pins these official SDK modules:

- `github.com/aws/aws-sdk-go-v2/service/s3` v1.105.0, with the matching AWS SDK
  core v1.42.1, for both R2 and COS;
- `github.com/cloudflare/cloudflare-go/v7` v7.7.0 for Cloudflare exact-file
  purge;
- `github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/teo` v1.3.131
  (`v20220901`) for EdgeOne purge creation and status polling.

`internal/publish` keeps vendor-specific provider interfaces because their
transaction semantics differ; it does not expose a generic storage/CDN plugin.
Both object providers contain the same `*s3.Client` wrapper. The shared wrapper
disables automatic retries and optional request/response checksums, validates a
clean bucket-root URL, bounds SDK responses, and maps HTTP 404/409/412/501 onto
the existing domain errors.

The generated S3 model does not directly emit every compatibility header that
the real providers require. A Smithy finalize middleware therefore performs
only these closed vendor projections before the official SDK signer runs:

- R2 CopyObject adds `Cf-Copy-Destination-If-None-Match: *`;
- COS rewrites S3 metadata/copy headers to their `x-cos-*` dialect and adds
  `x-cos-forbid-overwrite: true` for create-only PUT/CopyObject;
- COS temporary credentials place the STS token in the provider-defined
  `x-cos-security-token` header before signing. The shared AWS credential
  object deliberately omits that token on the COS dialect so it cannot also
  emit the incompatible `x-amz-security-token` spelling.

Those headers remain part of the SDK-generated SigV4 canonical request. There
is no hand-written signer or fallback HTTP implementation. The middleware also
provides the already computed content SHA-256 to the SDK signing stack, so
streaming uploads do not require a second body read. SDK CRC/trailer generation
is explicitly `when-required`, avoiding unsupported `aws-chunked` behavior on
S3-compatible targets.

Cloudflare purge remains capped at 100 exact URLs per SDK request. EdgeOne uses
the TEO SDK to submit `purge_url`, then polls the same JobId until `success`;
mismatched, unknown, failed, canceled, or timed-out results fail closed. Both
SDK clients reject redirects, cap response bodies, disable implicit retries,
and receive credentials only from the selected target secret.

An accepted EdgeOne JobId that is absent from one status response remains
accepted and recoverable. If the exact JobId is absent from repeated, distinct
status calls after the bounded grace rule, SOW persists an `indeterminate`
receipt containing the confirmation count and request identity. That attempt
can never satisfy the purge closure. A later recovery starts a new exact purge
attempt for the same normalized URL set instead of polling the vanished JobId
forever or treating absence as success; the old attempt remains auditable in
the sidecar.

The generated Cloudflare v7 method treats an HTTP 2xx transport as a nil Go
error without interpreting the API envelope's business status. SOW therefore
uses the SDK's public `WithResponseBodyInto` option and accepts a batch only
when `CachePurgeResponseEnvelope` says `success=true`, has no errors, and
contains a non-empty result ID. This is response validation around the concrete
SDK, not a second REST client.

### Remote audit capability separation

`sow fsck --target` is an object-storage audit, not a publication. It therefore
constructs provider-specific R2 or COS storage-only clients and resolves only
the selected target's storage secret. The fsck client exposes the required
Get/List/Head/Open dispatch and cannot be converted into a Publisher. It never
resolves a Cloudflare API token or Tencent EdgeOne credential and never
constructs either CDN SDK client. Publication, purge, CDN verification and
recovery continue to use the distinct full provider constructors.

R2 and COS remain separate concrete types; this capability split does not add
a generic cloud abstraction. Protocol fixtures must prove both providers work
when the CDN secret is absent or malformed. Real-cloud fsck evidence must use
an exact reviewed non-production resource and storage-only credential path; it
cannot upgrade Worker, CDN, purge, COS/EdgeOne or POC-06 status.

## Consequences

- The source-level vendor SDK contract is now reproducible through `go.mod`,
  constructor type tests, protocol fixtures, and a negative HTTP-200 embedded
  CopyObject error test plus a 1 MiB success-document ceiling.
- SDK middleware is an intentional compatibility seam, not a general extension
  API. Adding another provider requires a new frozen decision.
- MinIO and signed protocol fixtures validate the shared S3 path but do not
  prove R2/COS support for every conditional header. Real R2/COS/Cloudflare/
  EdgeOne acceptance remains required before production status can advance.
- Tencent and Cloudflare SDK upgrades are reviewed changes because generated
  request/response behavior can change even within a stable major module.
- A read-only remote audit cannot acquire unrelated CDN control authority by
  construction; callers needing purge or publication must explicitly request
  the stronger full provider type.

## Verification

- `go test -count=1 ./internal/publish`
- `go test -count=1 ./internal/cli`
- `go vet ./internal/publish ./internal/cli`
- `go mod verify`
- `go test ./test/compat -run '^TestRealCloudR2FSCKStorageOnly$' -count=1 -v`

Focused fixtures assert the official SDK client types, exact R2/COS signed
headers, absence of optional checksum/trailer framing, exact CDN requests,
EdgeOne task identity/status, repeated missing-JobId transition and exact
attempt replay, no redirect following, and fail-closed handling
of a CopyObject HTTP 200 response whose body is an `<Error>` document.
Oversized HTTP-200 CopyObject documents are rejected before XML
deserialization.
