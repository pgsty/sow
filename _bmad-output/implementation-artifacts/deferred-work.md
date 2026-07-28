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

- source_spec: `_bmad-output/implementation-artifacts/spec-derived-state-residue-removal-identity.md`
  summary: Non-journal derived-state consumers need a generic scanner and recovery contract for random write, install-isolation, and removal-quarantine residues.
  evidence: `writeDerivedStateFile` also writes generated publish sources, completion receipts, projection configuration stages, and serving journals outside the three strict journal directories fixed by V-75; a crash can leave a safe but currently unaudited random residue in those locations.

- source_spec: `_bmad-output/implementation-artifacts/spec-derived-state-residue-removal-identity.md`
  summary: Offline-archive projection temporary cleanup still needs exact-inode deletion instead of a pathname check followed by pathname removal.
  evidence: `cleanupOfflineArchiveProjectionIntentTemps` in `internal/cli/offline_archive_projection_intent.go` retains the pre-existing `Lstat(path) -> os.Remove(path)` race and can delete a replacement after validation.
  status: resolved
  resolution: V-79 replaces pathname deletion for intent temporaries and 0444 stage residues with strict offline-only grammar, retained no-follow/nonblocking descriptors, stable no-replace quarantine, original-coordinate absence checks, exact mode/size/root/intent ownership fences and parent fsync. Repeated-crash, replacement, ownership, umask and no-delete branches are covered by ordinary/race/fault-injection tests. See `_bmad-output/implementation-artifacts/spec-offline-archive-residue-removal-identity.md` and `docs/evidence/2026-07-22-offline-archive-residue-removal-identity.md`.

- source_spec: `_bmad-output/implementation-artifacts/spec-derived-state-residue-removal-identity.md`
  summary: Shared derived-state directory creation needs a recursively durable mkdir protocol.
  evidence: `writeDerivedStateFile` uses `Root.MkdirAll` and fsyncs only the leaf after file installation; transaction-specific callers sometimes pre-create and fsync one parent, but arbitrary newly created ancestor entries are not generically proven durable.
  status: resolved
  resolution: V-80 replaces `MkdirAll` with component-wise private stage creation, descriptor/inode binding, no-replace installation, exact-parent fsync and root/parent/child revalidation. Strict crash-stage recovery, concurrent first-writer convergence, inherited-umask repair, replacement preservation, bounded streaming scans, short-lived directory mutation epochs and a no-cache/full-scan fallback for unsupported seals are covered by ordinary/race/fault-injection tests. See `_bmad-output/implementation-artifacts/spec-derived-state-recursive-directory-durability.md` and `docs/evidence/2026-07-26-derived-state-recursive-directory-durability.md`.

- source_spec: `_bmad-output/implementation-artifacts/spec-derived-state-residue-removal-identity.md`
  summary: Canonical derived-state replacement needs an explicit committed-versus-rolled-back result for destination and fsync failures.
  evidence: The pre-existing final rename model can return a directory-sync error after the exact new destination is already installed; the error-only API cannot distinguish rollback-safe failure from a committed state that must be replayed, and it does not preserve a prior destination for rollback.

- source_spec: `_bmad-output/implementation-artifacts/spec-derived-state-residue-removal-identity.md`
  summary: Derived-state admission should freeze directory ownership/writeability and reject foreign hardlink aliases when the threat model includes same-host hostile writers.
  evidence: Root and leaf identity checks reject coordinate replacement but do not reject group/other-writable directories or require link count one, so another principal with write access could retain an alias and mutate the installed inode after verification.

- source_spec: `_bmad-output/implementation-artifacts/spec-projection-stage-install-rollback-identity.md`
  summary: Canonical `Store.Apply` reopens staged pathnames after journaling, so a post-prepare replacement can commit bytes that are not bound to the durable projection intent.
  evidence: The asset/package `after-fence-before-apply` boundary occurs after prepare returns its process-local stage identity ledger; `buildJournal` hashes the then-current replacement and `installPathChanges` reopens/copies it without comparing that inode and digest to the higher-level projection intent identity.
  status: resolved
  resolution: V-78 makes projection inject the complete canonical path-to-size/SHA-256 vector, binds every stage once with a no-follow/nonblocking retained descriptor before journaling, and consumes that descriptor through Apply/Recover/RecoverAborted. Exact raw HEAD/ref/index/tree/worktree CAS and native lock retention close the adjacent Git commit window. See `_bmad-output/implementation-artifacts/spec-canonical-apply-stage-identity.md` and `docs/evidence/2026-07-22-canonical-apply-stage-identity.md`.

- source_spec: `_bmad-output/implementation-artifacts/spec-projection-stage-install-rollback-identity.md`
  summary: Preserved projection-orphan audit quarantines need explicit `fsck` inventory and capability-bound retirement.
  evidence: ADR-0041 deliberately makes the first `--recover` rename an unowned final stage to `.preserved-<nonce>` and makes later recovery ignore that strict form; current `fsck`/GC does not enumerate or retire those audit copies.
