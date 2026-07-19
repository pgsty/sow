# Snapshot materialization contract

`sow promote stable <suite>-YYYYMMDD` captures the stable manifest into immutable
`refs/sow/snapshots/...` refs. The date must be the UTC capture date; an
operator cannot backdate or future-date a snapshot to manipulate retention.

`sow materialize <snapshot-id>` reconstructs a directly consumable repository
from those refs and the CAS pool:

- APT uses one archive root and shared `pool/` bytes. A snapshot is emitted as
  `dists/<suite>-YYYYMMDD`, with matching `Suite` and `Codename`, all three
  Packages variants, SHA-256 by-hash objects, `Release`, `Release.gpg`, and
  `InRelease`.
- YUM emits an independent snapshot tree per repo/architecture. Package bodies
  remain CAS hardlinks and a complete signed primary/filelists/other generation
  is created below `repodata/`; EL8 remains gzip and EL9/10 use zstd.
- Asset repositories remain index-free and are projected as CAS hardlinks.

The default destination is
`.sow/materialized/snapshots/<snapshot-id>/`. Views use
`.sow/materialized/<view>/`. An explicit `--target` builds the same complete
tree elsewhere below the repository root.

## Retention and on-demand rebuild

`state.snapshot_materialization_months` counts natural UTC months, including the
current month. Every successful default materialization removes expired derived
snapshot directories, but never changes a Git ref or CAS object. Stable is in a
separate permanent directory. An explicitly requested expired snapshot is kept
for that operation, so it can be served or archived; the next default stable or
recent-snapshot materialization reapplies the window. Unsafe/symlinked derived
trees fail closed instead of being recursively removed.

Default publication selects beta/latest/stable and every immutable snapshot in
the same natural-month window. `sow publish --snapshot <id>` rebuilds an older
snapshot on demand and conflicts explicitly with `--view`. Remote retention is
enabled only after `fsck --adopt-remote-inventory` establishes complete
inventory coverage; it removes the expired stable route and snapshot-owned
YUM/asset tree in the publish journal while retaining refs, CAS, generations,
and shared APT pools. See ADR-0003. Live R2/COS validation remains a separate
PoC gate and is not implied by the local protocol tests.

## Offline archive

`--tgz FILE` scans the completed repository after metadata generation and uses
that exact manifest as the tar input. The archive therefore contains packages,
indexes, signatures, by-hash objects, and repodata—not only package bodies.
Headers, file order, compression timestamps, index revision times, and snapshot
signatures are reproducible from canonical state. The materialization-only
signer disables go-crypto's randomized v4 signature notation, then self-verifies
both APT signature forms and the YUM detached signature before archive creation.

Example:

```sh
sow materialize jammy-20260712 \
  --config sow.yaml \
  --gpg-private-key-file /run/secrets/repo-signing.key \
  --tgz offline/pigsty-pkg-jammy-20260712.tgz
```

To close the derived-artifact loop in the same locked operation, name a
configured asset repository. SOW writes and verifies the deterministic archive,
imports it into CAS, advances the asset view selected by that repository's
confidentiality pool, and refreshes the asset hardlink tree before returning:

```sh
sow materialize jammy-20260712 \
  --config sow.yaml \
  --repo deb-jammy \
  --gpg-private-key-file /run/secrets/repo-signing.key \
  --tgz offline/pigsty-pkg-jammy-20260712.tgz \
  --asset-repo pro-assets \
  --asset-dest pkg/pigsty-pkg-jammy-20260712.tgz
```

The archive path itself must stay outside every configured serving repository;
`--asset-dest` is the separately validated logical path inside the asset repo.
Replay with identical canonical input is byte-identical and does not advance
the asset ref again. Cloud publication remains the explicit subsequent
`sow publish --view stable` transaction, so materialization never hides a cloud
side effect.
