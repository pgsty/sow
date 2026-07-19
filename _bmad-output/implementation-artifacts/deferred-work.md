# Deferred Work

## Deferred from: code review of prd.md (2026-07-12)

- YUM raw-baseurl `repomd.xml` and `repomd.xml.asc` cannot be replaced atomically as two object keys. SOW orders the compatibility alias pair and requires an identical immutable generation plus a generation-pinned mirrorlist/channel in the same transaction, but the observable raw-alias window remains until production clients migrate to the strong mirrorlist route. This is an explicit compatibility/production-migration blocker, not evidence that the raw pair is atomic.
