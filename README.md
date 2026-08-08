# SOW

SOW is a local RPM/DEB repository manager written in Go. SOW 0.2 supports two
workflows:

- `sow create` turns a directory of RPM or DEB packages into a simple
  repository. RPM packages can be signed with `--sign-with`/`-S`; adding
  `--overwrite` deliberately re-signs every RPM with that key.
- Managed workspaces model repositories and distributions explicitly, retain
  Desired and Built state, publish immutable Generations, and provide bounded
  locking, recovery, validation, queries, change reports, and operation logs.

The authoritative user and design documentation lives at
[sow.pgsty.com](https://sow.pgsty.com/docs/). The
[design section](https://sow.pgsty.com/docs/design/) describes the current
Repository-scoped single-payload model. Historical PRDs, review material, and
dated evidence remain available from Git history and version tags; they are
not a second documentation authority. The remaining [`docs/`](docs/) tree
contains only code-adjacent test and migration assets.

## Build and test

Go 1.26.5 or newer is required. Repository signing additionally requires a
usable GPG installation and key. The complete test target also runs the legacy
edge contract and therefore requires Node.js/npm.

```bash
make help
make build
make run ARGS=version
make test-core     # focused repository-manager tests
make test          # all Go modules plus edge contracts
make check         # format, module, vet, staticcheck, focused tests
```

The binary is written to `bin/sow`. Its default version is `0.2.0`; release
builds also inject that version at link time.

## Simple repositories

Place packages in one directory, then run:

```bash
sow create ./packages

# Sign currently unsigned RPM packages with one key.
sow create ./packages --sign-with 0123456789ABCDEF

# Re-sign every RPM, including packages that already carry a signature.
sow create ./packages --sign-with 0123456789ABCDEF --overwrite
```

The directory may contain RPMs, DEBs, or both; SOW emits metadata for every
format it finds. RPM output is consumable as a normal YUM/DNF repository, and
DEB output is consumable as a flat APT repository. `--pigsty` enables the
accepted Pigsty layout conventions. Run `sow help create` for the complete
option contract.

## Managed workspace

```bash
sow init ./lab
sow repo new local --workdir ./lab
sow dist new stable --format rpm --workdir ./lab --repo local
sow add ./packages/example.rpm --workdir ./lab --repo local --dist stable
sow build --workdir ./lab --repo local
sow check --workdir ./lab --repo local
sow status --workdir ./lab --repo local
sow changes --workdir ./lab --repo local
sow log --workdir ./lab --repo local
```

Managed repositories expose only `pool/ + dists/`; package hardlinks are not a
canonical layout requirement. Configure a `filesystem` or `r2` target in
`sow.yml`, then use `sow publish TARGET`. `sow gc` collects unreachable local
payloads, while `sow gc TARGET` performs target-scoped maintenance. R2 target
maintenance is deliberately report-only and never deletes remote objects.

If a publication stops before durable commit intent, `sow publish TARGET --abort`
reconciles and abandons it without copying or deleting remote objects;
already-created payload/checksum objects remain exact private inventory evidence
and may be reused. After commit intent, recovery is forward-only. A configured
target with an Applied Checkpoint also fences removal of its published Dist,
architecture, or signing pointers: retire/unbind that target, or configure a
differently named target on a new prefix, before withdrawing those views.

The one-copy boundary is one Repository per publish prefix. Publishing the same
Repository to two prefixes deliberately stores one payload copy in each prefix.
Filesystem target roots are compared by their effective canonical paths, even
when their endpoint spellings differ; an RPM leaf export must remain outside the
Repository, private state, and every configured filesystem publication root.

Default EL `dnf reposync` is not supported for the canonical parent-relative
RPM layout. When a self-contained RPM leaf is explicitly required, use
`sow export rpm-leaf DIST ARCH DIR`; it copies by default, while `--hardlink`
is an opt-in local optimization for a same-filesystem, trusted read-only export.

Use `sow help`, `sow help COMMAND`, or `sow help GROUP SUBCOMMAND` as the
authoritative CLI reference shipped with the binary. Machine consumers can use
the closed `--json` envelopes and documented exit-code contract.

## Release

```bash
make release-local
```

`make release-local` uses GoReleaser to build a local snapshot under `dist/`.
It creates Linux/macOS archives for amd64/arm64 plus RPM and DEB packages for
both Linux architectures. Linux package revisions use the project suffix
`1PGSTY`, for example `sow-0.2.0-1PGSTY.x86_64.rpm` and
`sow_0.2.0-1PGSTY_amd64.deb`.

GitHub Actions runs regular checks in `CI` and real Docker-backed client/S3
coverage in `Integration`. Pushing an exact semantic-version tag creates a
draft release:

```bash
git tag -a v0.2.0 -m "SOW v0.2.0"
git push origin v0.2.0
```

The tag workflow verifies that the tag points into `main`, agrees with the
source version, and then lets GoReleaser create a draft GitHub Release. Publishing
that draft is a separate manual decision. The workflow does not build or publish
a Docker image.

Documentation ownership and the repository boundary are described in
[`design/README.md`](design/README.md).
