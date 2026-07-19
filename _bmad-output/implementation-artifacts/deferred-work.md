# Deferred Work

## Deferred from: code review of prd.md (2026-07-12)

- YUM raw-baseurl `repomd.xml` and `repomd.xml.asc` cannot be replaced atomically as two object keys. SOW orders the compatibility alias pair and requires an identical immutable generation plus a generation-pinned mirrorlist/channel in the same transaction, but the observable raw-alias window remains until production clients migrate to the strong mirrorlist route. This is an explicit compatibility/production-migration blocker, not evidence that the raw pair is atomic.

- source_spec: `_bmad-output/implementation-artifacts/spec-sow-product-implementation.md`
  summary: Cloudflare bootstrap lease teardown must stop treating R2 DeleteObject `If-Match` as a compare-and-delete primitive.
  evidence: The owner-authorized V-21 real R2 probe demonstrated that R2 accepts a stale `If-Match` delete, while `recoverExpiredRealCloudCloudflareBootstrapLease` and held-lease release still delete the lock by ETag; a contender can replace the lease after GET and have its live lock removed.
