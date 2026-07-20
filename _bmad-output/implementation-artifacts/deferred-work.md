# Deferred Work

## Deferred from: code review of prd.md (2026-07-12)

- YUM raw-baseurl `repomd.xml` and `repomd.xml.asc` cannot be replaced atomically as two object keys. SOW orders the compatibility alias pair and requires an identical immutable generation plus a generation-pinned mirrorlist/channel in the same transaction, but the observable raw-alias window remains until production clients migrate to the strong mirrorlist route. V-27/ADR-0038 fixes the infra cross-EL route map and requires an expiring canonical endpoint/RPM/trust receipt before local source apply, but no production origin or consumer was changed. This remains an explicit compatibility/production-migration blocker, not evidence that the raw pair is atomic.

- source_spec: `_bmad-output/implementation-artifacts/spec-r2-readiness-resource-stable-lease.md`
  summary: Bootstrap expired-lease recovery still has a pre-existing remote-idle-to-local-receipt interruption window that needs a dedicated two-phase recovery-marker protocol.
  evidence: `recoverExpiredRealCloudCloudflareBootstrapLease` CAS-retires the remote live lease before the caller durably writes its local recovery receipt; a crash plus another holder acquiring the idle marker can prevent exact provenance replay even though ordinary apply/rollback now cannot bypass `recover-lease`.
  status: resolved
  resolution: V-26 replaces direct retirement with exact `live -> owning pending -> durable receipt -> recovery idle` CAS fencing; same-run phase/response-loss replay and cross-run/plan/readiness/forgery negatives are covered by `docs/evidence/2026-07-19-r2-bootstrap-two-phase-recovery.md`.

- source_spec: `_bmad-output/implementation-artifacts/spec-config-input-and-rpm-provenance-hardening.md`
  summary: Reachable-history contract scanners retain every distinct decoded canonical config and need an aggregate-memory bound independent of the per-blob 8 MiB ceiling.
  evidence: `historicalAssetProjectionOwners` and `loadReachablePackageRepositoryHistory` cache decoded configs by blob identity across all reachable commits, so many unique near-limit blobs can still grow memory with history length.
  status: resolved
  resolution: V-39 replaces both commit-to-config maps with commit-to-blob-identity indexes and a shared two-entry/16 MiB canonical-input LRU; misses revalidate immutable blob type/size/hash, failures are never cached, owner evidence retains at most the sufficient conflicting pair, and eviction/off-HEAD/merge history remains fail closed. See `_bmad-output/implementation-artifacts/spec-reachable-history-config-memory-bound.md` and `docs/evidence/2026-07-20-reachable-history-config-memory-bound.md`.

- source_spec: `_bmad-output/implementation-artifacts/spec-config-input-and-rpm-provenance-hardening.md`
  summary: Config default propagation and validation need explicit cardinality or complexity bounds for large repo/upstream arch and component sets.
  evidence: `applyDefaults` copies repo arches/components into matching upstreams and uses repeated linear membership checks, allowing a syntactically sub-limit config to drive superlinear CPU and multiplicative canonical memory.
  status: resolved
  resolution: Review loop 1 replaced the invalid flat-count candidate with independent pre-default ceilings of 65,536 structural work units and 64 MiB derived string bytes, plus indexed/one-pass validation and projection paths. The corrected source passed two clean adversarial reviews, all 707 CLI ordinary/race tests, all non-CLI ordinary/race packages, static/module/provenance/vulnerability/build gates, seven migration suites and the V-43 dual clean-delivery reconstruction. See `_bmad-output/implementation-artifacts/spec-config-cardinality-complexity-bounds.md`, `docs/adr/0040-bounded-configuration-topology.md`, and `docs/evidence/2026-07-20-config-topology-complexity-bound.md`.
