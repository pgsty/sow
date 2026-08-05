# SOW

SOW 0.2 is a local RPM/DEB repository manager written in Go. It supports two
workflows:

- `sow create` turns a directory of RPM or DEB packages into a simple
  repository. RPM packages can be signed with `--sign-with`/`-S`; adding
  `--overwrite` deliberately re-signs every RPM with that key.
- Managed workspaces model repositories and distributions explicitly, retain
  Desired and Built state, publish immutable Generations, and provide bounded
  locking, recovery, validation, queries, change reports, and operation logs.

The v0.2 P0-P3 command contract and implementation evidence live under
[`design/v0.2/`](design/v0.2/). Public/user documentation is maintained in the
separate `sow.pgsty.com` checkout; newly generated files under this repository's
`docs/` directory are intentionally ignored.

## Build and test

Go 1.26.5 or newer is required. Repository signing additionally requires a
usable GPG installation and key. The complete test target also runs the legacy
edge contract and therefore requires Node.js/npm.

```bash
make help
make build
make run ARGS=version
make test-v2       # focused v0.2 tests
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

Use `sow help`, `sow help COMMAND`, or `sow help GROUP SUBCOMMAND` as the
authoritative CLI reference shipped with the binary. Machine consumers can use
the closed `--json` envelopes and documented exit-code contract.

## Release

```bash
make release
```

`make release` runs the local release gates and then creates four static
binaries under `dist/` for Linux/macOS on amd64/arm64, together with
`SHA256SUMS`. It does not create a Git tag, push a branch, or publish files to a
remote service; those are separate, explicit release actions.

Internal design ownership and the boundary from public documentation are
described in [`design/README.md`](design/README.md).
