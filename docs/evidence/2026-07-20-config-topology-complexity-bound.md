# 2026-07-20 configuration topology complexity bound

## Current result

The corrected review-loop-1 implementation places two independent bounds in
the first schema-v1 validation preflight:

- 65,536 structural work units for decoded collection members, sequence
  defaults, and logical selector/metadata leaves;
- 64 MiB of derived string bytes for templated paths, copied defaults,
  canonical repetition, and selector/metadata coordinates.

Raw YAML remains independently limited to 8 MiB. Package inventory rows are
excluded from both configuration budgets and continue to use the existing
streaming, spool, chunk, and worker contracts.

Both budgets accept the exact limit and reject limit+1 with
subtraction-before-addition and division-before-multiplication. The preflight
also charges invalid zero-dimension view/repository pairs, so an invalid config
cannot make the accounting pass itself traverse an uncharged cross-product.
Omitted or explicitly empty YUM package keyrings retain internal default
provenance, ensuring a long `gpg.public_key` repeated into many repositories is
charged before canonical serialization.

Configured-arch path expansion is one pass. Sparse APT suite normalization uses
one global component-order index and per-suite sorting. Upstream, YUM
compatibility, edge-view, and edge-owner membership use indexes. Repository and
public-prefix ownership use deterministic sorting and binary search; 500
repository-path and 300 public-owner randomized cases match the former
quadratic oracle's exact first error. Edge and Nginx projection code reuses the
already expanded arch paths rather than calling a linear membership check once
per arch.

Current fixture headroom, measured by the production accounting function, is:

| Configuration | Structural units / 65,536 | Derived bytes / 64 MiB |
|---|---:|---:|
| `sow.example.yaml` | 33 | 561 |
| `docs/examples/sow-pgdg.yaml` | 200 | 5,197 |
| `docs/migration/fixtures/pigsty-v1.yaml` (98 repositories) | 1,771 | 58,182 |

## Review correction

The first candidate bounded only element cardinality. Adversarial review proved
that a single multi-MiB path or architecture could still be repeated into GiB
of expanded/canonical bytes; it also found `ExpandedPaths` self-scanning its
arch list and sparse `suite_components` scanning the complete global component
list per suite. All broad test timings and delivery identities from that
candidate are invalidated and are not completion evidence.

The main-agent audit of the replacement found and corrected four further
issues before the second adversarial review: explicit-empty package-keyring
default accounting, invalid zero-dimension default-view charging, multiple YUM
OS selector accounting, and residual edge/Nginx arch/view/repo rescans. The
one-arch non-templated compatibility-carrier behavior remains compatible.

## Corrected-source focused verification

These local commands passed on the corrected source after the final main-agent
patches:

```text
go test -count=1 -v ./internal/config -run \
  'Complexity|ExpandedPathsHandlesMany|SparseAPT|PathConflict|PublicOwnership|CurrentConfiguration|YUMCompatibility'
    PASS; package 0.705s
go test -count=1 ./internal/serving
    PASS; package 6.605s
go test -race -count=1 ./internal/config -run \
  'Complexity|DerivedStringAccounting|ExpandedPathsHandlesMany|SparseAPT|PathConflict|PublicOwnership|CurrentConfiguration'
    PASS; package 3.172s; no race report
go test -race -count=1 ./internal/serving
    PASS; package 7.167s; no race report
```

The real CLI negative cases use sub-8-MiB YAML for both structural default
amplification and long-path derived-byte amplification. Both return
`ExitConfig`, emit no success output, leave `.sow` and `.pool` absent, and
preserve the operator config bytes.

## Adversarial review closure

The second independent Blind Hunter pass returned `CLEAN` after Nginx
projection ownership and identifier lookups were indexed. The second Edge Case
Hunter pass returned no findings after rectangular zero-arch APT accounting and
default-view coordinate-shape accounting were made algebraic. The reviewers
did not reuse the first-candidate result; both inspected the corrected diff.

## Frozen-source full verification

All 707 CLI tests passed in six mutually exclusive ordinary and race shards;
no race report was emitted:

| Shard | Tests | Ordinary package / real | Race package / real |
|---|---:|---:|---:|
| `A-F` | 157 | 585.707s / 588.49s | 615.070s / 638.57s |
| `G-M` | 155 | 829.500s / 831.48s | 877.322s / 900.10s |
| `N-O` | 51 | 274.025s / 277.42s | 274.674s / 298.55s |
| `P-Q` | 150 | 948.205s / 950.18s | 1078.429s / 1101.25s |
| `R-V` | 123 | 607.523s / 610.22s | 634.762s / 658.62s |
| `W-Z/other` | 71 | 225.955s / 229.51s | 273.639s / 297.75s |

The 16 non-CLI test packages also passed ordinary and race runs in 34.68s and
89.26s aggregate wall time. `cmd/sow` has no test files. The compile-only full
module gate completed in 6.84s. The repository static gates all exited zero:
`go vet ./...` (2.00s), perf-tag compile/vet (9.87s/2.06s), and the configured
Staticcheck `inherit,-ST1005,-U1000` and `SA*,S1*` profiles (5.93s/5.98s).

Root and nested RPM-module `go mod tidy -diff` were empty and both
`go mod verify` runs passed. Nested RPM tests/vet passed, and a fresh module
extraction reported the pinned `v1.3.0` h1 with only allowlisted drift. Fixed
`govulncheck@v1.6.0`, built from the read-only local module proxy with checksum
networking disabled, reported zero reachable vulnerabilities for the root
module and no vulnerabilities for the nested RPM module. The root scan retains
one required-module advisory outside the imported/called graph.

Four `CGO_ENABLED=0 -trimpath` builds completed:

| Target | SHA-256 |
|---|---|
| `linux/amd64` | `18bd5a5662d0af33ad828b615c6510313f9db3c57349bf2a9f6e920008fd59c1` |
| `linux/arm64` | `1c79b130675f8a349b25b7d197482a9ff699cfa5e7de9323b58cf321be9f45b8` |
| `darwin/amd64` | `b586fc072b0f077a8df2809fcfc08b7e726fa57c577fce26f19b5061d16e288b` |
| `darwin/arm64` | `bd5b64573a713ff002597a62fc1e102549276f5edd69ecb8e5274b9a81e9a967` |

All seven hermetic migration suites exited zero. The physical-topology,
local-rollback, YUM-consumer, physical-config, writer-fence, legacy-audit and
family-E2E suites took 2.41s, 7.31s, 7.26s, 14.09s, 51.21s, 72.48s and 207.38s.
The family gate closed 44 command families, five mutation negatives and 16
real CLI E2E cases, and explicitly reported `external_network=disabled` and
`production_mutation=none`.

The post-document clean-delivery archive identity is intentionally not
self-recorded here. Two independent reconstructions with distinct fresh
HOME/GOMODCACHE/GOCACHE trees and the read-only local module proxy are recorded
in the delivery-root-external V-43 handoff entry; that entry is the authority
for archive equality and extracted-delivery verification.

The opt-in 50k artifact benchmark was not rerun for this configuration-only
change: package rows are explicitly excluded from the new accounting and no
artifact streaming/worker path changed. Perf-tag compilation/vet passed, while
the current 50k results remain the separately recorded NFR-01/NFR-02 evidence.

## Boundary

Baseline commit is `17621ea9c1c23a603a253fe1ed585c6740c73eca`; this report
covers the uncommitted implementation layered on it. Every command above read
local source/module-cache content and wrote only local temporary fixtures or
build outputs. No request was sent to the authorized `pro` test bucket, CO/COS,
Cloudflare production resources, or any production repository.
