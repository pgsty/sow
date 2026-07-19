# Real S3-compatible publication evidence (MinIO)

Date: 2026-07-12
Host: Darwin/arm64, Docker Linux/arm64, Go 1.26.5

## Reproduction

The test starts and removes its own container, creates a fresh bucket on a
private bind mount, and never writes credentials to logs:

```sh
SOW_MINIO_TEST=1 go test ./internal/publish \
  -run '^TestMinIOS3Compatibility$' -count=1 -v
```

Pinned fixture:

```text
minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e
```

Observed result:

```text
=== RUN   TestMinIOS3Compatibility
--- PASS: TestMinIOS3Compatibility (0.74s)
PASS
ok  github.com/pgsty/sow/internal/publish  1.409s
```

This run is bound to the 320-file product-source digest recorded in
`2026-07-12-final-local-audit.md`; it remains a dirty-worktree observation rather
than a Git commit and does not replace real R2/COS evidence.

## What crossed a real protocol boundary

- AWS SigV4 requests reached a real S3-compatible HTTP service; this was not an
  in-memory provider.
- A complete R2/Cloudflare publication saga performed create-only immutable
  uploads, pointer overwrite, exact one-URL purge through an HTTPS API fixture,
  CDN read-back through a signed-object bridge, checkpoint compare-and-set,
  and local remote-ref readiness.
- Replaying the committed transaction returned the same checkpoint and
  reissued the same exact purge closure before L3. This deliberately repairs
  a lost or externally repopulated CDN cache without repeating object uploads.
- Independent probes exercised `If-None-Match: *`, failing and successful
  PUT `If-Match`, custom SHA-256 metadata through HEAD, streamed GET,
  ListObjectsV2 and same-bucket CopyObject with source ETag.
- The pinned MinIO build accepted DELETE `If-Match` but ignored a deliberately
  wrong ETag and deleted the object. SOW's product-level deterministic
  conditional-delete probe detected this and returned `ErrCapability` before
  any live serving key. This is real negative provider evidence, not a claim
  that MinIO supplies safe conditional deletion.
- The CI workflow runs the same pinned fixture on Linux.

## Evidence boundary

MinIO proves the common S3 wire path, SOW's real HTTP client, and fail-closed
detection of ignored conditional DELETE. It does **not**
prove Cloudflare's R2-only destination-copy conditional extension, Cloudflare
CDN purge behavior, COS `x-cos-forbid-overwrite`/never-versioned semantics, or
EdgeOne purge behavior. Those vendor-specific claims remain gated on the
provider contract tests plus real R2/Cloudflare and COS/EdgeOne credentials.
