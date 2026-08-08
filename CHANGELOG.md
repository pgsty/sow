# Changelog

All notable changes to SOW are recorded here.

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
