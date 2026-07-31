# Current legacy source and resolute-pgdg migration baseline

Date: 2026-07-31
Scope: local read-only legacy source inventory and disposable local tests only

## Safety boundary

- `/Users/vonng/pgsty/repo` and `/Users/vonng/pgsty/pigsty` were read only.
- No Make recipe, upload, purge, cloud API, public endpoint, production
  repository, CO/COS, Cloudflare bucket, Worker, CDN, or EdgeOne resource was
  invoked.
- Cloud credentials and all real-provider/upstream opt-ins were removed from
  the audit environment. All mutating tests used temporary local trees.
- The pre-existing user change `ext/data/extension.csv` in the legacy checkout
  was not read as an inventory source, modified, staged, or removed.

## Observed current-source delta

The legacy repository remains at commit
`c2f7b5fa967d18d03b424fb7d0ee92fc5eabb6e6`. Comparing the checked-in
physical inventory with a fresh read-only enumeration found exactly two new
logical leaves:

```text
apt/pgdg/dists/resolute-pgdg/main/binary-amd64
apt/pgdg/dists/resolute-pgdg/main/binary-arm64
```

There were no removed logical leaves. The resulting physical topology is:

```text
APT indices:             76
YUM ordinary repomd:    130
YUM nested quarantine:    1
root exact keys:           7
root directory prefixes:  8
gated Pro files:          16
```

Normal repository refreshes also changed the bytes of 46 existing APT
`Packages` files and 80 existing YUM `repomd.xml` files. The fail-closed
snapshot was regenerated from the current public metadata rather than ignoring
those byte changes. Gated Pro payload contents were not opened or hashed; the
existing path/stat-only boundary and the exact empty checksum identity remain
unchanged.

The root Makefile fingerprint changed from
`434851089902ebc3f0ab402c81a3b407a420a4f4ec9c8368a10494f21d4c1a8c`
to
`a3d1f2214b84ebf6bc235a7524068e381dcc9ae4ac046c128cb01888fa3baee8`.
Byte reconstruction showed the only change was the first line:

```diff
-VERSION=v4.3.0
+VERSION=v4.5.0
```

The other six reviewed source fingerprints and the normalized 176-target
machine map digest remained unchanged.

## Contract update

- `apt-pgdg` now owns active `resolute-pgdg/main` for amd64 and arm64.
- The complete physical contract remains 98 repo IDs and grows from 135 to 136
  ledger rows and from 74 to 76 APT indices.
- Its exact configuration complexity baseline grows by 14 structural units,
  from 1,771 to 1,785, while the product limit remains 65,536.
- Exact selector evidence changed only for the three commands whose selected
  set contains all PGDG APT leaves: `ROOT-27` becomes 146 leaves and the two
  `ROOT-37` commands become 42 leaves each.
- Canonical topology count and family guards now require `pgdg=42`; all path,
  byte, source-fingerprint, root-ownership, nested-quarantine, and Pro
  fail-closed checks remain enabled.

## Reproducible verification

The following current-source commands exited zero:

```sh
docs/migration/audit-physical-topology.sh \
  --legacy-root /Users/vonng/pgsty/repo

docs/migration/audit-legacy-targets.sh \
  --legacy-root /Users/vonng/pgsty/repo

docs/migration/test-physical-migration-config.sh
docs/migration/test-audit-physical-topology.sh
docs/migration/test-audit-legacy-targets.sh
docs/migration/test-family-e2e.sh
docs/migration/test-local-adoption-rollback.sh
docs/migration/test-migrate-pigsty-yum-consumers.sh
docs/migration/test-writer-fence-preflight.sh
```

Observed audit identities:

```text
legacy physical topology audit: PASS
apt_indices=76 yum_repodata=131 yum_nested=1
root_exact_keys=7 root_directory_prefixes=8 pro_files=16

targets root=52 apt=70 yum=14 docker=40 total=176
operation_families=44 partition=exact
source_fingerprint_baseline=reviewed-production-source-2026-07-31
machine_map_sha256=54b9e81b837c4010bb16e8a25339375d57043232428a22a8019bb8703253c6ac

physical migration config hermetic suite: PASS
legacy physical topology hermetic suite: PASS
legacy migration audit negative suite: PASS
migration_family_contract=pass families=44
migration_family_negative_contracts=pass cases=5
migration_family_cli_evidence=pass tests=16
migration_family_production_mutation=none temp_roots_only=true
```

The full `internal/config` package passed ordinary/race in `1.073s/10.879s`.
The migration-focused CLI set passed ordinary/race in `87.818s/118.251s`.
All seven `docs/migration/test-*.sh` entry points were then run from a
credential-scrubbed environment; the family E2E package completed in
`217.046s`, the consumer audit reported exactly 22 mapped definitions, and the
writer-fence suite passed every local negative.

## Evidence boundary

This closes current local source/config/ledger drift and proves the migration
tooling recognizes `resolute-pgdg`. It does not assert production cutover,
remote object equivalence, CDN behavior, writer revocation, or atomicity of the
raw YUM `repomd.xml`/`.asc` compatibility pair. Those external gates remain
explicitly open.
