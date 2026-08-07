# Changelog

All notable changes to SOW are recorded here.

## 0.3.0 - Unreleased

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
- Kept frozen v0.2 workspaces readable without allowing ordinary writers to
  migrate them implicitly, and fenced local withdrawal of pointers already
  applied to a configured target.
- Rejected filesystem targets that overlap at their effective paths and kept
  RPM compatibility exports outside every configured filesystem publish root.
- Made ordinary RPM `reposync` compatibility explicitly unsupported while
  retaining the canonical SOW layout and the opt-in `sow-rpm-leaf-v1` export
  profile.
- Added local and mocked publication evidence. Real APT/DNF HTTP clients,
  exported RPM leaf compatibility, and live R2 remain release gates.

## 0.2.0 - 2026-08-05

- Added plain RPM and DEB repository generation compatible with the supported
  `createrepo_c` and `dpkg-dev` client behavior.
- Added RPM package signing through `--sign-with`/`-S`; unsigned packages are
  signed by default, while `--overwrite` deliberately re-signs every RPM.
- Added managed Workspace, Repository, Distribution, Desired Membership,
  Build, Generation, query, change, check, and operation-log workflows.
- Added bounded locking, crash recovery, migration, integrity validation, and
  deterministic repository metadata behavior.
- Added current-client, ordinary-repository, scale, race, and clean-delivery
  acceptance coverage for the P0-P3 command surface.
- Added a root Makefile for development, verification, and four-platform
  release builds.

## 0.1.0 - 2026-07-31

- Archived the original Git/CAS repository-manager MVP. Its implementation and
  historical material remain in the repository as the v1 baseline.
