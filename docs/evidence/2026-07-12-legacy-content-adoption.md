# Legacy content adoption evidence — 2026-07-12

## Scope and environment

- Host: Darwin arm64
- Go: `go1.26.5 darwin/arm64`
- Feature: `sow init --adopt-content`, local APT/YUM/asset baseline to CAS/view/receipt
- Boundary: these tests use real DEB/RPM payloads, production package parsers, generated and
  signed APT/YUM metadata, explicit materialization, L1 verification, and fsck. They do not
  replace the separate containerized apt/dnf client matrix or real-cloud/CDN evidence.

## Reproduction

```bash
go test -count=1 ./internal/config ./internal/upstream ./internal/provenance ./internal/cli \
  -run 'Migration|PigstyV1|TestParseLocal|TestLegacyAdoption|TestInitAdoptContent' -v

go test -race -count=1 ./internal/config ./internal/upstream ./internal/provenance ./internal/cli \
  -run 'Migration|PigstyV1|TestParseLocal|TestLegacyAdoption|TestInitAdoptContent' -v

go vet ./internal/config ./internal/upstream ./internal/provenance ./internal/cli
git diff --check
```

All commands exited 0 on 2026-07-12. The checked-in
[`pigsty-v1-synthetic.yaml`](../migration/fixtures/pigsty-v1-synthetic.yaml) also loads through the production
config schema and contains no target, credential or private key. It is the retained 12-repo parser
shape fixture: it partitions APT by suite and YUM by EL major without claiming complete physical
topology coverage. The complete 2026-07-14 migration contract is separately bound by
[`pigsty-v1.yaml`](../migration/fixtures/pigsty-v1.yaml) and its machine ledger. In the
post-change targeted run, the CLI package completed in 42.188s without race instrumentation and
39.880s with `-race` on the concurrently loaded host; config/upstream/provenance packages also
passed in both runs.

## What was proved

| Evidence | Result |
|---|---|
| Local APT parser | raw, gzip, xz, and zstd Packages accepted through bounded production parsing |
| Local YUM parser | gzip and zstd primary metadata; repomd checksum/open-checksum checks; optional OpenPGP signature and tamper rejection |
| Pigsty-v1 APT shape | real CLI consumes `apt/pgsql/jammy/dists/jammy` through the per-suite `apt-pgsql-jammy` repo rather than a synthetic suite-root layout |
| Pigsty-v1 flat YUM shape | signed zstd repomd→primary may reference only an exact flat RPM basename or an already-canonical href; arbitrary nested/escape/wrong-bucket paths fail closed |
| Real package identity | checked-in DEB and RPM are inspected by the production body parsers and matched to index name/version/arch/path/size/SHA-256 |
| Zero rewrite | repo manifest snapshot before and after adoption is byte-identical; CLI reports `serving_tree_rewritten=false` |
| Canonical migration | flat source `foo.rpm` remains untouched during adoption; isolated candidate contains only `Packages/<name-first-letter>/foo.rpm`, with regenerated signed repodata |
| Negative closure | unsupported nested/escape href, unlisted RPM, indexed-RPM tamper and two sources colliding on one canonical destination are rejected before view ref/ledger advancement |
| Atomicity | a first asset repo imports to CAS, a later APT repo fails for missing Packages, and no view ref or receipt ledger advances; the only adoption side effect beyond the normal init baseline is a verified CAS orphan |
| Idempotence | identical adoption rerun reports `changed=false` and leaves canonical HEAD unchanged |
| Confidentiality | gated default pool to public latest fails closed; explicit Pro stable succeeds |
| Frozen semantics | frozen YUM content can be adopted/materialized/verified, while a subsequent add is rejected with conflict |
| Continued lifecycle | adopted latest is explicitly materialized, then `verify --layer L1` and `fsck` both pass for real APT and YUM trees |
| Receipts and GC | strict deterministic `sow-legacy-adoption/v1` JSONL records both physical `source_path` and canonical `canonical_path` plus size/hash/pool/config commit without fabricating upstream provenance; old receipts without `canonical_path` decode as source==canonical; receipt hashes are GC roots |
| Package rollback | real suite-nested APT/flat-YUM candidate is selected through a serving symlink, payload loss is detected, origin switches back to the untouched source, and the failed candidate is preserved outside the legacy root |

## Operational interpretation

Default `sow init` remains the manifest-only zero-byte baseline. Adoption is opt-in and itself
does not regenerate service metadata. `sow materialize latest` is a later explicit structural
migration and may regenerate signatures, APT by-hash, and YUM repodata; the migration runbook
therefore requires separate before/after layout review and real apt/dnf client evidence before
an origin switch. The only approved payload path transform is verified flat YUM
`foo.rpm` → `Packages/<首字母>/foo.rpm`; APT/assets keep their payload paths. These local fixtures
do not prove a production full-tree adoption, Nginx cutover, system apt/dnf matrix, or cloud rollback.

## 2026-07-14 unsigned legacy-YUM clarification

The physical-topology inventory found 131 legacy `repomd.xml` files and zero sibling
`repomd.xml.asc` files; see
[`physical-topology-inventory.md`](../migration/physical-topology-inventory.md). Adoption now
separates checksum membership evidence from metadata-signature evidence. With all cloud/upstream
opt-ins set to `0`, ambient AWS/Cloudflare/Tencent credentials removed, `GOPROXY=off`, and all
non-loopback proxy variables pointed at `127.0.0.1:1`, these commands passed locally:

```bash
go test -count=1 ./internal/cli \
  -run '^(TestInitAdoptContentLegacyYUMMetadataTrustIsExplicit|TestInitAdoptContentRejectsInvalidViewBeforeStateMutation|TestInitAdoptContentAssetsIsZeroRewriteAtomicAndIdempotent)$' -v
go test -count=1 ./internal/cli -run '^TestInitAdoptContent'
go test -race -count=1 ./internal/cli \
  -run '^(TestInitAdoptContentLegacyYUMMetadataTrustIsExplicit|TestInitAdoptContentRejectsInvalidViewBeforeStateMutation|TestInitAdoptContentAssetsIsZeroRewriteAtomicAndIdempotent)$'
```

Results after the final selector/trust hardening: focused normal/race tests passed in
3.365s/5.617s; the full adoption test set passed in 51.670s. The 33-repo generalization test,
which now explicitly requests `--view latest,stable`, also passed in 40.107s. The fixture proves
that an unsigned tree still requires the complete
repomd→primary→RPM checksum/size chain and reports `yum_metadata_signature=not-claimed`. An
explicit public-only `--legacy-metadata-keyring` instead requires and verifies every selected
leaf's detached signature and records the exact keyring SHA-256. Missing `.asc`, private-key
input, using the flag without adoption, and selecting no YUM repo all fail closed; invalid
keyring material is rejected before `.sow` is created. These are local fixture results only and
do not turn the physical inventory into completed full-tree migration evidence.

Adoption view selection is exact: the default and explicit `--view latest` create no stable ref;
stable is written only when explicitly selected. An unsupported `--view beta` exits with usage
status before `.sow` exists. This prevents a public migration command from silently widening into
the append-only Pro view.
