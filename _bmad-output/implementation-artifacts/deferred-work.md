# Deferred Work

## Deferred from: code review of prd.md (2026-07-12)

- YUM raw-baseurl `repomd.xml` and `repomd.xml.asc` cannot be replaced atomically as two object keys. SOW orders the compatibility alias pair and requires an identical immutable generation plus a generation-pinned mirrorlist/channel in the same transaction, but the observable raw-alias window remains until production clients migrate to the strong mirrorlist route. This is an explicit compatibility/production-migration blocker, not evidence that the raw pair is atomic.

- source_spec: `_bmad-output/implementation-artifacts/spec-r2-readiness-resource-stable-lease.md`
  summary: Bootstrap expired-lease recovery still has a pre-existing remote-idle-to-local-receipt interruption window that needs a dedicated two-phase recovery-marker protocol.
  evidence: `recoverExpiredRealCloudCloudflareBootstrapLease` CAS-retires the remote live lease before the caller durably writes its local recovery receipt; a crash plus another holder acquiring the idle marker can prevent exact provenance replay even though ordinary apply/rollback now cannot bypass `recover-lease`.
