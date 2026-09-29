# SOW - Software Object Warehouse

[![Website: sow.pgsty.com](https://img.shields.io/badge/Website-sow.pgsty.com-slategray?style=flat&logo=cilium&logoColor=white)](https://sow.pgsty.com)
[![Docs](https://img.shields.io/badge/Docs-sow.pgsty.com%2Fdocs-slategray?style=flat)](https://sow.pgsty.com/docs/)
[![Version](https://img.shields.io/github/v/release/pgsty/sow?style=flat&label=version&color=slategray&logo=github&logoColor=white)](https://github.com/pgsty/sow/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/pgsty/sow/ci.yml?style=flat&branch=main&label=CI&logo=githubactions&logoColor=white)](https://github.com/pgsty/sow/actions/workflows/ci.yml)
[![Go](https://img.shields.io/github/go-mod/go-version/pgsty/sow?style=flat&logo=go&logoColor=white&color=slategray)](go.mod)
[![License: Apache-2.0](https://img.shields.io/github/license/pgsty/sow?logo=opensourceinitiative&logoColor=green&color=slategray)](LICENSE)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/pgsty/sow)

[**sow**](https://sow.pgsty.com) is an open-source RPM / DEB repository manager from [Pigsty](https://pigsty.io).
One self-contained binary turns a directory of packages into a working YUM / APT repository,
and manages curated repositories with signing, snapshots, audit history, and incremental
publication when you need more control.

> "**S**oftware **O**bject **W**arehouse": store once, serve everywhere, ship only what changed.

[Website](https://sow.pgsty.com) | [Docs](https://sow.pgsty.com/docs/) | [Get Started](https://sow.pgsty.com/docs/start/) | [Download](https://sow.pgsty.com/download/) | [Release Notes](https://sow.pgsty.com/blog/release/) | [Discuss](https://github.com/orgs/pgsty/discussions) | [Pigsty](https://pigsty.io) | [中文](https://sow.pgsty.com/zh/)

<a href="https://sow.pgsty.com/"><picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://sow.pgsty.com/img/sow-architecture-dark.svg">
  <img src="https://sow.pgsty.com/img/sow-architecture-light.svg" alt="SOW architecture: local RPM and DEB files enter one package pool that stores each package body once, the pool is projected as YUM and APT repository views that hold metadata only, and publication uploads only the changed objects to a filesystem or S3 / R2 target.">
</picture></a>


--------

## Get Started

`sow` ships in the Pigsty infra repository for mainstream Linux distros on `amd64` / `arm64`:

```bash
# APT: Debian / Ubuntu and compatible platforms
sudo tee /etc/apt/sources.list.d/pigsty-infra.list > /dev/null <<'EOF'
deb [trusted=yes] https://repo.pigsty.io/apt/infra generic main
EOF
sudo apt update && sudo apt install -y sow
```

```bash
# YUM: RHEL / Rocky / Alma / Anolis and compatible platforms
sudo tee /etc/yum.repos.d/pigsty-infra.repo > /dev/null <<'EOF'
[pigsty-infra]
name=Pigsty Infra for $basearch
baseurl=https://repo.pigsty.io/yum/infra/$basearch
enabled=1
gpgcheck=0
module_hotfixes=1
EOF
sudo dnf makecache && sudo dnf install -y sow
```

> For mainland China users: consider replacing `repo.pigsty.io` with `repo.pigsty.cc`.

Pinned RPM / DEB packages, installer-free tarballs for Linux and macOS, and source builds
are covered on the [download page](https://sow.pgsty.com/download/) and published on
[GitHub Releases](https://github.com/pgsty/sow/releases).

Then point `sow` at a directory of packages:

```bash
sow create ./packages                       # emit YUM / APT repository metadata in place
sow create ./packages --sign-with <KEYID>   # also sign currently unsigned RPMs with a GPG key
```

That directory is now a repository. RPMs become a normal YUM/DNF repository, DEBs become a
flat APT repository, and a mixed directory gets both. Serve it with any static web server;
`--pigsty` enables the Pigsty layout conventions, and `sow help create` documents the
complete option contract. Continue with the [Quick Start](https://sow.pgsty.com/docs/start/quickstart/).


--------

## Features

- **Flat repositories**: `sow create` replaces `createrepo_c`, `dpkg-scanpackages`, and
  `reprepro`. One command indexes RPM and DEB packages in place, with optional GPG signing.
- **One pool, many views**: a managed Repository stores each package body once and projects
  metadata-only Dists for EL, Debian, and Ubuntu, so neither disk nor object storage holds
  duplicate payloads.
- **Explicit state**: Desired membership is separate from Built state, every build publishes
  an immutable Generation, and `sow check` / `status` / `changes` / `log` keep validation
  and history inspectable.
- **Incremental publication**: `sow changes` reports the exact delta and `sow publish`
  uploads only that, to filesystem or Cloudflare R2 (S3-compatible) targets, with atomic
  pointer switches and fail-closed recovery.
- **Self-contained**: one static Go binary (`CGO_ENABLED=0`). No daemon, no database
  service, no language runtime. Linux and macOS, `amd64` and `arm64`.


--------

## Managed workspaces

Plain `sow create` treats repository metadata as a deterministic result of the directory:
change the inputs and run it again. A managed workspace is for repositories that SOW should
own over time, with explicit membership, policy, signed metadata, immutable snapshots,
audit history, and publication targets:

```bash
sow init ./lab
sow repo new local --workdir ./lab
sow dist new stable --format rpm --workdir ./lab --repo local
sow add ./packages/example.rpm --workdir ./lab --repo local --dist stable
sow check --workdir ./lab --repo local
sow status --workdir ./lab --repo local
sow changes --workdir ./lab --repo local
sow log --workdir ./lab --repo local
```

`sow add` and `sow rm` converge the selected Dist to a new Built Generation by default.
Configure a `filesystem` or `r2` target in `sow.yml`, then `sow publish TARGET` uploads the
change set and `sow gc` collects unreachable local payloads. `sow help COMMAND` is the
authoritative CLI reference shipped with the binary; machine consumers can rely on the
closed `--json` envelopes and the documented exit-code contract.

Upgrading a workspace created by SOW v0.3 or v0.4? Stop writers, back up the workspace,
and run `sow repo migrate REPOSITORY --workdir DIR` once per Repository. Version 0.5 uses
schema v13 to index pool-path ownership without scanning unrelated publication history;
configuration and public layout stay unchanged. Then run `sow build` and `sow check`:
the updated RPM authentication and APT metadata contracts require one rebuild of affected
Dists. Later unchanged RPMs reuse matching Built evidence instead of repeated payload
verification. Do not reopen the migrated database with an older binary.
Publication ordering, recovery, target rebinding, the one-copy boundary,
and RPM leaf export are specified in [Commands](https://sow.pgsty.com/docs/command/) and
[Design Records](https://sow.pgsty.com/blog/design/).


--------

## Build

Building from source requires Go 1.27.1 or newer; repository signing additionally requires
a usable GPG installation and key.

```bash
make build          # write the binary to bin/sow
make test-core      # focused repository-manager tests
make test           # all Go packages plus the patched RPM module
make check          # format, module, vet, staticcheck, deadcode, focused tests
make release-local  # GoReleaser snapshot archives and packages under dist/
```

GitHub Actions runs regular checks in `CI` and Docker-backed client / S3 coverage in
`Integration`. Pushing an exact semantic-version tag creates a draft GitHub release after
the tag is validated against `main`, the source version, and the changelog; publishing that
draft is a separate manual decision. Maintainers can also run a read-only check against
hosted Cloudflare R2 with `make test-r2-live` (see the `SOW_REAL_R2_*` variables in
`internal/r2/cloudflare_integration_test.go`).

Before tagging, require successful `CI` and `Integration` runs for the exact
release commit. Inspect the draft archives and packages, their checksums and
`sow version` output before publishing the Release. Enable the website's pinned
download links only after that Release is public and its assets are available.


--------

## About

The authoritative user documentation lives in [SOW Docs](https://sow.pgsty.com/docs/);
dated architecture decisions live in [Design Records](https://sow.pgsty.com/blog/design/).
Historical implementation and verification material remains attached to versioned source
tags rather than a second documentation tree in this repository.

SOW is built by the [Pigsty](https://pigsty.io) team ([pgsty](https://github.com/pgsty)), alongside:

- [pigsty](https://github.com/pgsty/pigsty) — open-source PostgreSQL distribution with HA, PITR, IaC, monitoring, and hundreds of extensions
- [pig](https://github.com/pgsty/pig) — PostgreSQL and extension package manager for EL / Debian / Ubuntu
- [silo](https://github.com/pgsty/silo) — S3-compatible object storage, a community-maintained MinIO fork

SOW is licensed under the [Apache License, Version 2.0](LICENSE). Bundled third-party
components remain under their respective licenses.
