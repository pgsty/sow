# Changelog

All notable changes to SOW are recorded here.

## Unreleased

## 0.4.0 - 2026-08-24

- Added schema v12 and operator-confirmed publication target rebinding. Target
  storage identity, provider, endpoint, region, bucket, and prefix remain
  immutable, while target name, public endpoint, and maximum cache TTL may be
  revised under the same stable TargetIdentity. Initial bindings, migration
  backfills, and every rebind now append immutable binding revisions; pending
  maintenance and filesystem conditional-delete workflows preserve their TTL
  and endpoint safety fences.
- Made each `sow check` authenticate every unique physical package payload
  exactly once, independent of cached fingerprints, retained Generation count,
  Dist count, and trust-ring count. Descriptor-bound evidence is keyed by
  device/inode/size/mtime/ctime and shared by retained validation, final
  manifest traversal, and `sow changes`. Signed RPMs use one additional
  main-header-to-EOF stream for all signature packets and candidate trust rings.
- Added independent multi-ring embedded RPM signature verification. Every
  recognized packet must verify within one candidate ring and at least one path
  must authenticate the payload, so a combined trusted ring can accept a
  deliberately dual-signed package without cross-assembling packet-by-key
  successes for single retained rings. Historical CentOS v3/v4 signatures
  remain covered.
- Scoped production package-facts reads to the selected digest set in bounded,
  deterministic SQLite batches. Warm 64 MiB builds perform no package-body
  reads; fingerprint drift and missing facts share one authoritative payload
  pass, and selected rows/bytes, signature streams, metadata hashing, tree
  walks, and package reads are recorded in operation metrics and CI contracts.
- Shared one hardened public HTTP verifier between R2 and filesystem HTTP(S)
  targets. Response-header and body-idle deadlines are independent, ordinary
  canonical GETs remain authoritative, stale content follows cache TTL,
  transient HTTP failures use a short bounded window, oversize bodies fail
  closed, and filesystem public absence waits for canonical 404/410 visibility.
  Filesystem target aliases are also rejected before durable bind on their
  prospective physical paths, including case aliases on case-insensitive
  volumes.
- Raised the required build toolchain to Go 1.27.0 and refreshed the AWS SDK,
  SQLite, compression, and cryptography dependencies. Quality gates now pin
  staticcheck v0.8.1, deadcode v0.49.0, and govulncheck v1.7.0. Repository
  behavior and the public layout are unchanged.

- Added schema v11 and an explicit `sow repo migrate` repair for the v0.3 Dist
  lifecycle bug that could mark a Repository clean while another Dist remained
  dirty. Repository status is now always derived in the committing transaction.
  The migration also removes stale abandoned-object evidence from resurrected
  attempts. Missing signed historical identities are represented explicitly as
  unverified rather than guessed; they cannot reach the current head, propagate
  to a successor, or become a retained trust assertion.
- Fixed incremental publication recovery after commit intent. Every pointer may
  contain its exact old checkpoint or target Generation bytes during replay;
  unknown, missing, or third identities still fail closed. Re-abandoning a
  resurrected pre-commit attempt is idempotent, and Target GC recognizes but
  never deletes abandoned add-only evidence.
- Made R2 publication resilient to slow and transient networks: phase-specific
  HTTP timeouts replace the two-minute whole-request deadline, replayable
  conditional writes and read operations use standard retries, stalled uploads
  and response bodies are canceled by idle-progress deadlines, and large
  objects use bounded conditional multipart upload. Transient public 5xx
  retries use a short fixed window; only stale content waits up to cache TTL.
  Mutable pointers/aliases now request revalidation while immutable objects get
  long-lived cache metadata. Public verification waits within `max_cache_ttl`
  on the canonical URL and rechecks ordinary client visibility.
- Reduced routine publication verification from full public-Generation download
  to the exact change set. No-op and applied-checkpoint recovery reuse complete
  private inventory evidence, while Target GC streams only protocol pointers;
  full storage inventory reconciliation remains fail-closed.
- Made Generation RPM signer rows an exact manifest side table across initial
  Dist creation, partial builds, Dist add/remove, layout migration, and local
  GC. Heterogeneous key rotations remain faithfully represented and retained/v1
  rejects them instead of asserting a false common signer.
- Made default repeated `add` converge a previously skipped or config-dirty
  selected Dist. Crash recovery retains the requested build concurrency while
  remaining compatible with older journals. `rm --check` now shares the
  mutating configuration guard, uses Built architectures for prior RPM and APT
  metadata retention while rendering configured architectures, and is
  independent of the scratch filesystem device.
- Added human renderers for every managed command, distinct discovery/config
  JSON error classes, null results before meaningful work while preserving
  committed/partial/diagnostic results, and complete leaf command option help.
  Root and nested-module `govulncheck`, RPM fork provenance, and both test-aware
  and Linux-amd64-pinned binary-reachability dead-code gates now run in CI.
- Increased the race-test package and CI job ceilings without reducing default
  coverage, preserving headroom for the expanded publication and migration
  fault matrices.
- Removed the retired 3,058-line APT v1 build, external-sort, empty-Dist, and
  Git-tracked by-hash ledger implementation together with its self-only tests.
  Package parsing and the Plain/Managed APT render paths remain covered.

## 0.3.0 - 2026-08-10

- Removed the retired V1 CLI/runtime, cloud/CDN publication saga, Edge worker,
  completed migration program, stale V1 examples, and their obsolete test
  harnesses. The active binary now depends only on V2 packages; R2 publication
  uses a focused storage-only transport, default `go test ./...` covers the
  whole current tree, and historical implementation remains available from Git
  history and the v0.2.0 tag.
- Added repository schema v10 with a rebuildable package-facts cache keyed by
  immutable package SHA-256. Ingest now authenticates each new RPM/DEB in one
  complete pass and retains its view-independent render facts; builds bulk-load
  those facts once, match them in memory, and lazily rebuild missing or corrupt
  entries from authenticated package bytes. Ordinary warm builds exhaustively
  traverse the public namespace but validate unchanged Pool payloads from their
  device/inode/size/mtime/ctime fingerprint, reducing package-body reads to
  zero; fingerprint drift falls back to one authoritative SHA-256 pass and
  self-heals instead of blocking future writes. Fingerprint-only checks do not
  load or hash the cached facts BLOB, and final normalization reuses its own
  descriptor snapshot rather than starting a third Pool scan. `sow check`
  remains the explicit full cryptographic audit. RPM metadata artifacts and DEB
  architecture indexes now use bounded `--jobs` concurrency, and Generation
  manifest/changeset rows are inserted in batches. The v10
  migration goes directly to the current schema; there is no old/new runtime
  dual-read or dual-write path before 1.0.0.
- Simplified Plain `sow create` into a rebuildable one-pass projection. The
  default unsigned path now hashes and parses each package once with `--jobs`,
  renders from retained parsed metadata, and performs only a final package-set
  and `stat` snapshot check before publication. Plain no longer writes an
  operation journal, recovery trash, rollback pre-images, or repeated package
  hashes; an interrupted run is handled by rerunning `create` to overwrite
  derived metadata. Managed repository transactions and recovery are unchanged.
- Added repository schema v9, which indexes every membership table by
  `package_sha256`. Managed builds and checks now expand Desired and Built
  Membership with one bulk projection instead of one query per object: listing
  a 5,000-object Dist drops from about 4.1 s to about 33 ms, and 50,000 objects
  complete in well under a second where they previously did not finish.
  Migration is automatic on the first write operation; until it runs, a v8
  repository is not readable by the read-only status path, and a migrated v9
  repository cannot be opened by SOW 0.2.0 or earlier.
- Replaced per-object payload promotion with a bounded single-writer group
  commit. Each batch creates every public Pool link, persists the distinct
  target directories, then removes the pending names and persists their shared
  directory, so a crash leaves pending-only, exact dual-link, or Pool-only
  state and can never durably lose both names. Recovery accepts the dual-link
  window that this makes reachable.
- Fixed payload publication to persist the target directory entry before
  unlinking the source name, instead of relying on the filesystem to order the
  two metadata operations implicitly.
- Added structured `build_progress` operation events for the rendering,
  payload-promotion, Dist-publication, normalization, and finalization phases,
  observable through the operation log. Progress records no longer checkpoint,
  so telemetry can neither slow nor fail an otherwise complete build.
- Changed pending payload files to their final `0644` mode at ingest, keeping
  them private through the enclosing `0700` pending directory rather than
  through the file mode. Promotion is therefore a pure namespace operation.
  Existing `0600` pending files remain valid and are normalized on promotion.
- Reduced the pending source guard from holding one descriptor per pending
  object for the whole build to an identity snapshot that is rebound when the
  build ends. This keeps descriptor use bounded at repository scale; it still
  detects persistent path replacement and external hardlinks, but no longer
  claims to defeat a same-user replace-and-restore during a build.

## 0.2.0 - 2026-08-08

- Added plain RPM and DEB repository generation compatible with supported
  `createrepo_c`, DNF/YUM, `dpkg-dev`, and APT client behavior.
- Added RPM package signing through `--sign-with`/`-S`; unsigned packages are
  signed by default, while `--overwrite` deliberately re-signs every RPM.
- Added managed Workspace, Repository, Distribution, Desired Membership,
  Build, Generation, query, change, check, and operation-log workflows.
- Added bounded locking, crash recovery, explicit migration, integrity
  validation, deterministic repository metadata, and clean-delivery coverage.

- Replaced per-view RPM payload aliases with one canonical payload object per
  Repository/publish prefix and metadata-only `dists/` views.
- Added deterministic Repository migration, retained-generation manifests,
  export, local garbage collection, and target-scoped publication state.
- Added filesystem publication with exact conditional deletion and R2
  publication with report-only retention; R2 never issues object deletion.
- Added explicit pre-commit `repo migrate --abort` and `publish --abort` paths.
  Publication abandon reconciles and records exact add-only target objects
  without copying or deleting them; mutable APT aliases and protocol pointers
  remain behind durable commit intent.
- Kept earlier managed workspaces readable without allowing ordinary writers to
  migrate them implicitly, and fenced local withdrawal of pointers already
  applied to a configured target.
- Rejected filesystem targets that overlap at their effective paths and kept
  RPM compatibility exports outside every configured filesystem publish root.
- Made ordinary RPM `reposync` compatibility explicitly unsupported while
  retaining the canonical SOW layout and the opt-in `sow-rpm-leaf-v1` export
  profile.
- Added online APT/DNF and S3-compatible integration workflows plus a tag-driven
  GoReleaser pipeline for Linux/macOS archives and Linux RPM/DEB packages.

## 0.1.0 - 2026-07-31

- Archived the original Git/CAS repository-manager MVP as the v0.1 baseline.
