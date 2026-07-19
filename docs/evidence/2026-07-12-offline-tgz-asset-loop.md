# Offline tgz to asset repository closed-loop evidence

Date: 2026-07-12

## Reproduction

```sh
go test ./internal/cli \
  -run '^TestMaterializeCLIProducesExactHardlinkTree$' -count=1 -v
```

The E2E invokes the production command surface with:

```text
sow materialize latest --target export \
  --tgz offline/pigsty-pkg-test.tgz \
  --asset-repo asset --asset-dest src/pigsty-pkg-test.tgz
```

## Assertions

- The export is an exact CAS-hardlinked projection of the selected canonical
  ref and stale files are reconciled away.
- The tgz is built only after scanning the completed materialized repository;
  tar path order, ownership, modes and gzip timestamp are deterministic, and
  every source byte is rehashed against the manifest while streaming.
- Before the command returns, the archive is imported into CAS, recorded at
  `asset/src/pigsty-pkg-test.tgz` in the confidentiality-derived asset view,
  and materialized as a hardlink to that CAS coordinate.
- A second identical invocation produces byte-identical tgz bytes, reports the
  asset add as unchanged, does not advance the ref, and still reconciles the
  export tree.
- `--asset-repo` without `--tgz`, `--asset-dest` without `--asset-repo`, unsafe
  destinations, live-repo overlap, and changed bytes at the immutable asset
  path fail closed.

The cloud step remains an explicit subsequent `sow publish` transaction. This
is deliberate: materialization closes artifact construction/adoption but does
not conceal paid cloud mutations or bypass publication verification.
