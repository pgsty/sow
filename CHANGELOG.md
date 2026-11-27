# Changelog

All notable changes to SOW are recorded here.

## 0.9.0 - 2026-11-27

- Make flat `sow create` and `sow prune` fault-tolerant by default and add
  `--strict` to restore fail-fast rejection:
  - Corrupt, unreadable, source (`src`/`nosrc`), and coordinate-conflicting
    packages (including Debian version-equivalent conflicts such as `1.0-1` vs
    `1.00-1`), as well as unmatched `--protect` names, are skipped with warnings
    so remaining valid packages still index.
  - Per-format failure isolation preserves a format's previous index, history,
    and completion state when all its candidates fail, while still publishing
    valid packages of the other format (including in fresh `--pigsty`
    directories).
  - In mixed RPM + DEB directories, `sow prune` updates the RPM index, preserves
    the DEB index, and carries forward existing `repo_complete` digests for
    still-present DEBs without prematurely hashing unindexed DEBs.
  - Human output writes warnings to `stderr`; successful `--json` output carries
    `warnings` and `skipped` in the `stdout` JSON envelope and leaves `stderr`
    empty.
  - Retain TOCTOU file-identity/size/mtime checks across scan, publication,
    signing installation, and package deletion without repeating full
    decompression read-backs.
- Add full RPM format v6 support (lead major versions 3..6, `PAYLOADSHA256`
  without `PAYLOADSHA256ALGO`, native `RPMSIGTAG_OPENPGP` tag `278` OpenPGP
  v4/v6 signature arrays) across flat `create`/`prune`/`--sign-with` and managed
  `add`/`build`/`check`, including dual- and multi-signed RPMs. When tag `278`
  is present it is authoritative over legacy signature tags.
- Fix RPM indexing for packages that repeat an identical main-header tag value
  (such as duplicate `SOURCERPM` in EL10 packages), while continuing to reject
  conflicting main tags and duplicate signature-header tags. Normalize legacy
  Latin-1 bytes (`>=0x80`) in binary `.deb` `control` files to UTF-8, and accept
  human-readable comments outside armor fences in `.asc` OpenPGP keyrings.
- Accept both `sow.yml` and `sow.yaml` uniformly across workspace discovery,
  `init`, recovery, and `config check` (while keeping support for a legacy
  repository directory named `sow.yaml/` beside `sow.yml` and refusing explicit
  `-C`/`--workdir` fallback to `CWD`/`SOW_DIR`). Resolve the physical SQLite
  path before probing `-wal`/`-shm`/`-journal` sidecars and enforcing single
  hardlink (`nlink == 1`) invariants, eliminating Darwin-specific C ABI code.
- Harden managed workspace operations and ergonomics:
  - Require offline recovery when a populated `.sow/` directory loses
    `workspace.lock` instead of silently minting a competing lock inode, while
    allowing `sow init` to repair missing per-repository lock files under
    `workspace.lock`.
  - Allow ECDSA and DSA metadata signing keys alongside RSA and EdDSA
    (Ed25519/Ed448); `rm --check` is a read-only semantic preview that does not
    touch `.sow/<repo>/stage`, while real writes still probe directory-exchange
    capability before committing Desired.
  - Support symlinks (including Kubernetes `Secret` mounts), optional UTF-8 BOM
    stripping, and named pipes (FIFOs with a 2-second deadline) for `--passfile`,
    `SOW_GPG_PASSFILE`, and `passfile`, surfacing bounded helper `stderr`
    diagnostics on failure.
  - Report `sow.yml` `limit`/`exclude` policy drift in `sow check` as `dirty`
    instead of integrity failure, allow APT `by-hash` verification by content
    digest when hardlinks are broken, tolerate `.DS_Store` under `.sow/`, ignore
    unreadable non-package files during `sow add -R`, resume interrupted v0.7.1
    local GC plans containing an empty `manifest` array, and consistently return
    exit code `6` (`rejected`) when a legacy schema v12 workspace requires
    `sow repo migrate`.
- Simplify target configuration and harden publication and target GC:
  - New target GC grace records use the configured `max_cache_ttl` directly
    (removing the hardcoded 30-day floor and 24-hour padding). **Upgrade note:**
    review any target configured with `max_cache_ttl: 0s` before upgrading —
    superseded objects may become eligible at the next target GC, while existing
    recorded `NotBefore` deadlines remain effective. Backward NTP clock steps
    retain the time-witness high-water mark.
  - Default `authoritative_workspace`, `single_writer`, and
    `exclusive_write_authority` to `true` when omitted (explicit `false` remains
    rejected), default R2 `region` to `auto`, normalize endpoint/duration
    formatting, allow dotted R2 bucket names, and reject overlapping R2 targets
    across region spellings (such as `auto` vs `us-east-1`) for the same
    `(endpoint, bucket, prefix)`.
  - Follow CDN redirects during public HTTP verification while rejecting
    HTTPS-to-HTTP downgrades, verifying connected dial IPs against private
    loopback/link-local ranges, and refusing cross-origin redirects through an
    HTTP proxy. Ignore harmless foreign files at target root outside `pool/` and
    `dists/`.
- Improve CLI ergonomics and release packaging: duplicate flags use last-wins
  semantics, boolean flags accept `=true`/`=false`, `--timeout 0s` is accepted,
  `sow log export FILE` resolves symlinked parent directories (such as macOS
  `/tmp`) and checks parent directory sync, and release archives and Linux
  packages ship the `sow` binary and `LICENSE` directly.

This release keeps schema v13 and the existing public repository layout.
Workspaces already on v0.5.0 through v0.8.0 do not require a schema migration.
Interrupted v0.7.1 local GC plans with an empty `manifest` array now resume
directly under v0.9.0 without needing the v0.7.1 binary first. Review targets
configured with `max_cache_ttl: 0s` before upgrading, as new target GC grace
records now follow `max_cache_ttl` without a hardcoded 30-day floor.

## 0.8.0 - 2026-11-23

- Add opt-in `sow gc TARGET --delete` for R2 publication targets. Default
  `sow gc TARGET` on R2 remains report-only; `--delete` (either directly or
  after a prior report-only review) re-verifies live protection roots, verifies
  each candidate's remote size, SHA-256 metadata, and ETag before issuing
  `DeleteObject`, verifies storage and public HTTP 404/410 absence, and records
  durable deletion receipts scoped to the object's causal publication epoch so
  re-publishing identical package bytes keeps subsequent publications
  idempotent. An unfinished conditional-delete report requires `--delete` to
  resume.
- Allow external secret and keyring symlinks outside the workspace root (such as
  Kubernetes `Secret` mounts and `/var/run/secrets` paths) for `--passfile`,
  `SOW_GPG_PASSFILE`, `passfile`, `key: file://`, and `trusted_keys`, while
  keeping strict component-by-component `O_NOFOLLOW` traversal inside the
  workspace and rejecting symlinks that resolve back into the workspace.
- Drop `.deb` `control.tar.lzma` decompression support and remove the unmaintained
  `github.com/kjk/lzma` and `pault.ag/go/debian/deb` package dependencies. Binary
  `.deb` control archives using `.tar`, `.gz`, `.bz2`, `.xz`, and `.zst` remain
  supported, and `ar` member headers are validated directly with 64-bit bounds.
- Release the parent directory lock in `sow create` and `sow prune` before waiting
  on a busy target directory and immediately after target binding, so neither
  active nor queued runs on one flat repository block sibling repositories. Guard
  `sow create` against running inside a managed `.sow` workspace ancestor or over
  an interrupted `.sow-prune-repo-complete` marker, apply `--pigsty` filtering
  before duplicate-filename checks, re-verify replacement SHA-256 digests on
  `ctime`/`nlink` changes during `sow prune`, and cryptographically verify
  exported OpenPGP signatures after `sow create --sign-with`.
- Harden DEB and RPM metadata parsing and signature verification: enforce valid
  UTF-8 in binary DEB `control` documents, accept explicit `0:` zero epochs in
  flat APT self-validation, encode deb822 paragraphs without corrupting folded
  leading-whitespace lines, enforce strict `InRelease` clearsign framing and
  single-packet `Release.gpg` / `repomd.xml.asc` signatures, sanitize XML-illegal
  control bytes from RPM display strings at parse time, extract `SourceRPM` names
  by stripping the trailing `-version-release.arch.rpm` suffix for newly admitted
  packages while preserving existing `Source` / `PoolPath` compatibility for
  previously admitted subpackages, normalize empty RPM epochs, deduplicate
  non-adjacent RPM `Requires`, parse RPM keyrings entity by entity, enforce
  SHA-256+ hashes on published `repomd.xml.asc`, reject unsupported RPM signature
  tag `278`, prefer payload-authenticating RPM signatures over header-only
  signatures when attributing signers, and reject duplicate tags in main RPM
  headers.
- Unify managed `workspace.lock` -> `repo.lock` acquisition and recovery ordering
  across `dist new`, `dist rm`, and `repo migrate` so an interrupted `repo.rm`
  journal recovers without self-deadlock. Use descriptor-anchored directory
  exchanges with preflight capability probes (recovering interrupted empty probe
  directories automatically) and a `linkat`+`unlinkat` fallback when
  `RENAME_NOREPLACE` is unsupported, replay and surface `retain-remove-*`
  tombstones in `sow gc` and `sow check`, clamp `GraceRecord.NotBefore`
  monotonically across `--rebind` TTL reductions while processing equal-deadline
  checkpoints in causal publication order, and prune empty `pool/` and `dists/`
  parent directories after filesystem target conditional deletes.
- Ensure every SQLite writer (including `OpenExisting` after staged WAL schema
  validation) reconnects through a connector that applies
  `SQLITE_FCNTL_PERSIST_WAL` and `BEGIN IMMEDIATE` transactions, stage
  `OpenExistingForMigration` safely before inspecting legacy schemas and
  checkpoint WAL after migration commit, make `UpdateOperationPayload` a single
  atomic statement, pass `--define "_gpg_path $GNUPGHOME"` to `rpmsign` when
  `GNUPGHOME` is set, bound signing subprocess teardown with `WaitDelay`, and
  zero-overwrite temporary passfile scratch files before removal.
- Accelerate large-repository publication, GC, and SQLite state updates without
  changing schema v13: validate local publication sources via fast stat/evidence
  checks, reuse R2 checkpoint `(Path, Size, ETag)` identities to skip redundant
  `HEAD` calls on unchanged `pool/` payloads while raising per-host idle HTTP
  connections, cache descriptor hashes within filesystem target sessions while
  re-reading freshly installed public files, hoist target maintenance inventory
  verification outside per-attempt loops, omit surviving manifests from
  `localGCPlan` and execute large unreachable backlogs in bounded batches below
  the 64 MiB plan limit, and batch SQLite `memberships`, checkpoint, audit, and
  legacy-alias updates.
- Allow read-only inspection commands (`config check`, `repo ls`, `repo show`,
  `dist ls`, `dist show`) on frozen `sow/v2` workspaces, populate `operation` in
  `sow log prune --json` and `repository` in `sow where -r --json`, handle local
  valued options cleanly before global flags, surface a clear hint when `sow.yaml`
  is present without `sow.yml`, pin reproducible GoReleaser build and package
  timestamps, add macOS CI coverage and signed Managed APT/DNF container tests,
  and refresh `THIRD_PARTY_NOTICES`.
- Refresh dependencies with Go 1.27.4, including S3 v1.116.0, SQLite v1.63.0,
  libc v1.82.12, compress v1.20.5, x/crypto v0.59.0, and go/debian v0.21.4.
  Update the Silo integration fixture to the 20261112 release, GoReleaser to
  v2.20.3, deadcode to v0.53.0, and govulncheck to v1.10.0.

This release keeps schema v13 and the existing public repository layout.
Workspaces already on v0.5.0 through v0.7.1 do not require a schema migration.
If local GC was interrupted under v0.7.1, complete it with the v0.7.1 binary
(`sow gc -r REPOSITORY -C WORKSPACE`) before switching to v0.8.0. An old plan
with an empty `manifest` array requires the old binary to finish recovery.

## 0.7.1 - 2026-11-11

- Require Go 1.27.4 and refresh runtime and test dependencies to their latest
  available versions. Update the AWS SDK core to v1.48.0, S3 to v1.114.10,
  Smithy to v1.28.9, compression to v1.20.4, libc to v1.81.0, and `x/sys`
  to v0.50.0, along with AWS internals, pprof, `x/mod`, `x/sync`, and modernc
  compiler dependencies.
- S3/R2 requests inherit the AWS SDK's updated default retry policy, including
  retries for bodyless HTTP 429 responses. Cover successful throttling retries
  and preservation of the HTTP error after retry exhaustion.
- Harden S3/R2 error status extraction across joined errors, treat HTTP 404 on
  multipart upload abort as already cleaned up, and bound non-2xx list and
  multipart XML responses.
- Reject RPM v6 packages consistently across `sow prune` (including single-version,
  `--protect`, superseded, and `--dry-run` inputs), `sow create`, and managed
  ingestion.
- Bound decompressed `.deb` control tar streams and compressed APT/RPM metadata
  streams against header and decompression expansion bombs, and broaden Linux
  `renameat2` unsupported-filesystem error recognition (`ENOSYS`, `EINVAL`,
  `ENOTSUP`) while preserving the fallback implementation on other platforms.
- Fix crash recovery for legacy v1 `dist.new`/`dist.init` operations with nil
  effective signing. Move unproven `c2-to-single-v1` migration stage leftovers
  intact to `abandoned/` and report their location so local GC is not blocked.
  Reopen rooted directory cursors per batch when unlinking large directories on
  macOS APFS and BSD.
- Fix `export rpm-leaf` when an unrelated peer filesystem target is unmounted,
  record the Dist's built Generation timestamp rather than the repository head
  timestamp, and accept duplicate file inputs when combining explicit files with
  parent directories in `sow add`.
- Ensure multi-statement SQLite reads run inside read-only transactions, batch
  `ListPackageObjects` Dist membership filters below SQLite's bind limit, and
  normalize legacy `RFC3339Nano` repository time-witness seeds while bounding
  observed years to `1..9999`.
- Update GoReleaser to v2.20.1 in CI and release workflows, and regenerate
  third-party notices for the Go 1.27.4 release builds.

This release keeps schema v13 and the existing CLI and public repository layout.
Workspaces already on v0.5.0 through v0.7.0 do not require a schema migration.

## 0.7.0 - 2026-11-09

- Add `--passfile PATH`, `SOW_GPG_PASSFILE`, and per-key `passfile` configuration
  for protected RPM package and RPM/APT metadata signing keys, including GPG
  agent keys. Preserve legacy metadata `passphrase` references. Apply the same
  credential selection to initialization, signing probes, export, migration,
  and interrupted-operation recovery. Password files preserve whitespace and
  remove exactly one final LF or CRLF; no default file is searched. Credential
  values stay out of process arguments, repository state, and public output.
  Passfile settings take plain paths; `file://` URIs are rejected.
- Add `sow prune DIR` for flat RPM repositories. Keep the highest EVR per package
  name and architecture, verify replacement digests, publish the filtered index,
  then delete old packages. Support read-only `--dry-run`, repeatable
  `--protect NAME` (each name must match a package), and `--metadata-timestamp`;
  preserve completion markers across interrupted cleanup. Bind replacement
  digests and indexed bytes to a stable file identity, checked before each old
  version is deleted and before completion. An in-place rewrite with restored
  size and mtime stops further deletion. RPM v6 packages are
  not supported and are reported as such.
- `prune` rejects an existing `repomd.xml` that also lists metadata SOW does not
  generate, such as comps groups, updateinfo, or modules, before changing any
  file. `create` keeps its existing index-replacement behavior so that
  repositories with legacy module metadata, including those built by Pigsty
  v4.4.0 on EL8/9, still rebuild. It now reports the dropped data
  types as a warning and in the JSON `dropped_metadata` result field.
- Accept ECDSA and EdDSA header signatures in `RPMSIGTAG_DSA`, where rpm 4.16 and
  later store them. RPM packages signed with GnuPG's default Ed25519 keys now
  verify, including after managed package signing.
- Fix configured publication targets becoming unpublishable after removing a Dist,
  architecture, or signing companion that the last publish did not change. The
  withdrawal guard now checks every pointer of the published Generation.
- Fix an unreachable filesystem target blocking publication, `--abort`, and
  target GC of other targets. Only the selected target is checked against the
  others, using prospective physical paths.
- Recover from an interrupted local GC or retained-removal plan write. An empty
  or partial plan previously blocked every later writer; nothing has been
  applied at that point, so the plan is now discarded or rebuilt.
- Allow `export rpm-leaf` for a clean Dist that later Generations did not rebuild.
- Identify the active mutation by the sole pending operation instead of
  wall-clock order, so a backward clock step no longer blocks `add`, `rm`,
  `build`, and their recovery.
- Fix Repositories migrated from the C2 layout of v0.3/v0.4 workspaces: after
  the first later Generation, `check`, `build`, `add`, and `gc` reported an
  invalid transition control target. The retained migration anchor now binds
  the Generation the migration created, so affected Repositories recover without
  manual repair. `repo rm` also accepts a completed migration instead of
  treating its retained anchor as an active transition.
- Fix RPM caret snapshot ordering in Version and Release comparisons, so
  `2.0^20250611` sorts before `2.0.1` and managed version limits retain the
  newer release instead of its earlier snapshot.
- Update the AWS SDK core to v1.47.8, S3 to v1.114.9, Smithy to v1.28.8,
  SQLite to v1.62.0, libc to v1.80.1, and Debian package parsing to v0.21.3,
  with corresponding transitive dependency updates. Upgrade YAML to
  `go.yaml.in/yaml/v4` v4.0.0 with the compatible decoder and encoder, retaining
  strict single-document validation and canonical configuration output.
- Update GoReleaser to v2.20.0 in CI and release workflows.
- Add required protected-key signing checks on EL8, EL9, and EL10. Detect the
  available `rpmsign` capabilities so EL8 skips only the unsupported repeated
  signature scenario. Keep Go 1.27.3 as the build baseline.

This release keeps schema v13 and the existing public repository layout.
Workspaces already on v0.5.0 through v0.6.1 do not require a schema migration.
A `sow.yml` that uses `passfile` cannot be loaded by v0.6.1 or older; remove those
keys before downgrading.

## 0.6.1 - 2026-10-22

- Require Go 1.27.3 and refresh runtime and test dependencies, including the
  AWS SDK, ProtonMail OpenPGP, compression, SQLite, and Debian package libraries.
  Retain the bounded, parser-only RPM compatibility patch.
- Move YAML parsing to the maintained `go.yaml.in/yaml/v3` v3.0.5 module while
  retaining the existing configuration format.
- Report the offending path or armor type when log export, RPM metadata,
  signature, and workspace validation reject invalid input, instead of displaying
  a Go formatting error caused by wrapping a nil error.
- Update pinned CI Actions, GoReleaser, deadcode, and govulncheck. Read the CI
  snapshot version from the Makefile so package builds follow the release version.

This release keeps schema v13 and the existing CLI and public repository layout.
Workspaces already on v0.5.0 or v0.6.0 do not require a schema migration.

## 0.6.0 - 2026-10-17

- Bind metadata and payload authentication to stable file-descriptor identity,
  including fast validation and reused evidence. Reject in-place rewrites with
  restored mtime, and retain the authenticated identity after concurrent hard links.
  Keep no-follow traversal checks while allowing execute-only ancestor directories.
- Read complete OpenPGP key bundles instead of silently ignoring later keys.
- Retain current and previous Plain RPM indexes so clients can finish using a
  previously fetched `repomd.xml`; unchanged runs do not advance retention.
- Persist one metadata publication time per new Managed build and reuse it across
  recovery. Migration and older journals retain their previous timestamp behavior.
  Reject timestamp drift before publishing further Dist pointers.
- Keep SQLite identity checks from releasing existing POSIX locks. Read composite
  repository state within one SQLite snapshot and validate eligible WAL databases
  once per open.
- Preserve committed command results when checkpoint or other post-commit
  maintenance fails, and show pending repository maintenance in Dist status.
- Keep C2 migration abort restartable before the first journal or manifest exists.
  Retain abandoned stage files, reject contradictory control authority, and report
  the selected Repository in JSON failures. Preserve removal-policy audit outcomes.
- Reuse authenticated payload and Dist publication evidence within each operation,
  avoid duplicate ingest stage writes and unused tree hashing, and scope membership
  reads to selected packages. Keep input staging workers independent and bounded.
- Bound parallel R2 inventory HEAD requests and prevent retry seeks from resetting
  the upload idle timeout.
- Update the build toolchain to Go 1.27.2 and staticcheck to 0.8.2. Verify the patched
  RPM module against its pinned upstream source using the already selected Go
  toolchain, including installations that use automatic toolchain downloads.
- Expand recovery, identity, client compatibility, and performance regression
  coverage. Keep deterministic source delivery and remove brittle Go runtime I/O
  instrumentation from the performance gates.

This release keeps schema v13 and the existing public repository layout. Workspaces
already on v0.5.0 do not require a schema migration.

## 0.5.0 - 2026-09-29

- Fixed historical Dist-removal cleanup deleting packages re-added to another
  Dist. Cleanup now checks current immutable object ownership.
- Reject incompatible signing policies and colliding pool paths before applying
  Desired state. Recover old unbuilt signing failures and unapplied path conflicts
  without discarding committed Desired changes or accepting altered public trees.
- Persist failed pre-apply add operations before deleting private staged bytes;
  recover interrupted rollback and empty, fully excluded Dist mutations. Cancelled
  commands return 130 and report accepted items only after Desired has committed.
- Reserve payload URLs against local and historical publication identities, and
  prohibit overwriting immutable payloads in publication plans and backends.
  Existing attempts may finish only when conflicting payloads already match
  their bound new identity; unchanged pre-commit attempts can be abandoned.
- Allow external package paths and workspace discovery through symlink ancestors,
  while retaining no-follow checks on package leaves and private repository paths.
- Add schema v13 path indexes and query only candidate pool paths. Existing
  repositories require `sow repo migrate`. Reuse RPM preflight results and matching
  Built authentication evidence; the upgraded RPM/APT contracts require one rebuild.
  Terminal cleanup inspects actual remaining stage/recovery entries, not every old log.
- Treat reader-blocked WAL checkpoints and post-prune space reclamation as deferred
  maintenance, and enable fullfsync for writable SQLite connections on macOS.
- Accept GnuPG's clear-signature final-newline convention for APT without relaxing
  content binding, and force SHA-256 for newly generated GPG metadata signatures.
- Check metadata-key usability at the current time before new mutation builds,
  independently of deterministic signing timestamps and historical verification.
  Agent signing freezes GPG time and pins the actual available signing subkey after
  one small probe per certificate/time. New APT publications reject weak signature
  digests; historical verification and frozen publication recovery remain compatible.
- Show per-input errors for wholly rejected add batches; return null for create
  failures without a result and preserve command identity on publish parse errors.
- Include third-party license notices in archives, RPMs and DEBs, pin GoReleaser,
  and update the build toolchain to Go 1.27.1 and x/crypto to v0.56.0.
  Generate and check notices from all four release package graphs, including nested
  xxhash licensing and embedded source notices.
- Tolerate concurrent read-locked hard links while authenticating Pool payloads, so
  parallel `export rpm-leaf --hardlink` runs and `check` no longer report unchanged
  bytes as integrity failures.
- Reject identical bytes added under a pool file name that differs only by case from
  a known path. On case-insensitive workspaces also reject source directories that
  differ only by case, and refuse such aliases on case-insensitive filesystem
  targets before any upload.
- Local `gc` skips publication inventory roots that exist only remotely, such as
  payloads retained by report-only R2 maintenance, instead of failing.
- `repo migrate` reports the schema change (`schema_from`, `schema_to`); an older
  schema names the migration command and fails every write command with exit 5.
- Exit 130 is reserved for the command's own SIGINT or SIGTERM; internal timeouts,
  such as a stalled R2 upload, stay runtime errors. GPG metadata signing at the
  current second waits until GnuPG can freeze the signing time.
- Recover v0.4.0 adds that omitted a non-empty, fully excluded Dist. `file://` R2
  credentials must be regular files. Re-added packages no longer read per-checkpoint
  pool-path history.
- `publish --abort` without an active attempt is rejected with exit 6 instead of a
  runtime error.


- Added `sow create --metadata-timestamp SECONDS` for an explicit RPM metadata
  publication time. Existing YUM repositories can preserve a nondecreasing
  timestamp when switching generators, including clients with an EL7 YUM cache.
  The accepted input range is 0..253402300799 Unix seconds. The default remains
  zero for reproducible output; package bytes, compressed XML, and DEB indexes
  are unaffected. Publishers remain responsible for choosing the timestamp and
  signing the resulting `repomd.xml`.
- Added regression coverage for modern createrepo_c script dependency semantics,
  including pre-transaction and post-transaction requirements, without changing
  dependency projection.
- Consolidated maintained design documentation on sow.pgsty.com, moved
  integration/performance gates from `test/` to `qa/`, and moved shared
  fixtures from root `testdata/` to `internal/testdata/`. Product behavior is
  unchanged; clean-delivery manifests now reflect the organized source layout.
- The S3-compatible integration test now runs against a digest-pinned
  `pgsty/silo` image, the MinIO-compatible object store maintained by PGSTY,
  because the upstream `minio/minio` image is no longer available on Docker Hub.

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
