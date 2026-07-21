---
title: 'Full-provider checkpoint-fenced delete protocol evidence'
type: 'hardening'
created: '2026-07-20'
status: 'done'
baseline_commit: 'e9b8afb'
---

## Intent

Publication can use an unconditional object DELETE only after the saga has
proved the exact object twice and revalidated its remote checkpoint or
generation lock immediately before and after the request. The storage-only R2
control client had local wire evidence, but the complete Cloudflare and
EdgeOne provider wrappers used by real publication had no direct offline
protocol execution.

## Contract

- `R2CloudflareHTTP.R2DeleteCheckpointFenced` and
  `COSEdgeOneHTTP.COSDeleteCheckpointFenced` must issue one exact-key S3
  `DeleteObject` request through their frozen full-provider constructors.
- The request is deliberately unconditional: neither `If-Match` nor
  `If-None-Match` may be sent or listed among SigV4 signed headers.
- R2 uses its exact access-key/`auto` scope and `x-amz-security-token`; COS uses
  its exact access-key/`ap-shanghai` scope and native
  `x-cos-security-token`, with no AWS-token alias.
- 404, 412 and 501 map to `ErrNotFound`, `ErrConflict` and `ErrCapability`;
  success maps only from an accepted 2xx response.
- An unsafe key fails before transport. The operation must not acquire or call
  CDN purge, Worker, Zone or EdgeOne control authority.

## Implementation and verification

- A real TLS loopback server observes the requests emitted by the official S3
  SDK under both complete provider constructors. It accepts only the exact
  bucket/key and SDK `x-id=DeleteObject` operation marker.
- Four responses per vendor cover 204/404/412/501, followed by an invalid-key
  zero-request negative.
- The earlier control-only test is retained. Combined atomic coverage executes
  both R2 wrappers and the COS wrapper at 100%, and the shared checkpoint-fenced
  delete implementation at 90%.
- The complete `internal/publish` package passes ordinary and race, followed by
  compile/vet/Staticcheck and deterministic clean delivery.
- No production Go file changes. No cloud credential is loaded and no network
  request leaves the local TLS server.

## Result

Focused ordinary/race, complete publish ordinary/race, compile/vet/Staticcheck
and clean-delivery policy gates passed. Two post-evidence clean deliveries are
rebuilt and compared bytewise; their non-self-referential identity is recorded
in the external V-52 ledger. This closes local full-provider protocol evidence,
not real Cloudflare/COS/EdgeOne acceptance.
