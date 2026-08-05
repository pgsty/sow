# Changelog

All notable changes to SOW are recorded here.

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
