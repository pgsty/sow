# Changelog

All notable changes to SOW are recorded here.

## Unreleased

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
