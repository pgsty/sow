# Current-source local validation closure — 2026-07-16

Date: 2026-07-16 (Asia/Shanghai)
Host: Apple M5 Max, macOS 26.5.2 arm64, Go 1.26.5, Node 26.4.0,
Docker 29.4.1, Nginx 1.31.2

This report binds the post-ADR-0030, post-SQLite-writer and 2026-07-17
multi-arch compatibility-admission source, including immutable negative
provenance history, repo-ref ancestry checks, the fresh-copy full-corpus
adoption fix, and the current `yum/infra` exact-copy S0→S3 closure. Every ordinary/race/static,
compatibility, scale and portability result below is rerun on that source;
older 655/657-test closures are not reused for the final delta.

## Safety boundary

No command in this validation used the local production repository, CO/COS
production storage, Cloudflare production storage/CDN, an EdgeOne production
resource, or a production domain as a test target. The source tree
`/Users/vonng/pgsty/repo` remained read-only. The large-tree measurement used
the independent APFS copy with inode `74638033`; the production source inode
was `5551832`. Adoption writes remained confined to the separately documented
writable disposable copy.

Every Go validation run removed AWS, Cloudflare, and Tencent credential/profile
variables, pointed AWS config and credentials at `/dev/null`, disabled EC2
metadata, and fixed all real-cloud, real-edge, real-upstream, and purge-watcher
opt-ins to `0`. Offline runs used a loopback-deny proxy and `GOPROXY=off`.
Docker client tests used only already-local images. APT replaced its source list
with the temporary loopback origin; DNF used `--disablerepo='*'`. The Linux
archive runtime used Docker `--network none`.

The explicit production-isolation gate passed all production-looking bucket,
zone, domain, unregistered-resource, confirmation-token, and shipped-fixture
negative cases before a network request. Exact regression cases also reject the
offered bucket name `pro` (not a dedicated `sow-test`/`sow-ci`/`sow-sandbox`
identity) and `https://pro.pigsty.io` (a forbidden Pigsty production domain).
This proves the local gate, not a real provider acceptance run.

## Exhaustive ordinary and race closure

`go test -list '^Test' ./internal/cli` enumerated 660 default-build CLI tests.
The six CI regexes are exhaustive and disjoint:

| CLI shard | tests | ordinary | race |
|---|---:|---:|---:|
| `^Test[A-F]` | 145 | 326.638s | 374.966s |
| `^Test[G-M]` | 141 | 466.765s | 563.872s |
| `^Test[N-O]` | 51 | 163.084s | 164.200s |
| `^Test[P-Q]` | 144 | 444.015s | 669.164s |
| `^Test[R-V]` | 120 | 179.347s | 266.751s |
| `^Test([W-Z]|[^A-Z]|$)` | 59 | 36.133s | 63.533s |

All packages outside `internal/cli` passed in explicit ordinary and race runs;
no race report occurred. The full
ordinary and race closures include failure injection, process death, recovery,
manifest/cache rebuild, APT/YUM/asset lifecycle, view confidentiality, dual
target publication, purge evidence, restore, and CLI exit/help behavior.

The first post-SQLite G–M race run exposed a test-only scheduling assumption:
the cancellation test claimed both leaves were at `generation-ready`, but its
hook had no barrier and could cancel while the second recoverable journal was
still at `install-intent`. The test now explicitly waits for both commit hooks
before cancellation. Ten focused race repetitions passed in `68.628s`, then
the final complete G–M race shard passed in `563.872s`; production journal and
recovery semantics were unchanged.

The exact dual-architecture legacy carrier exposed one product defect absent
from the previous single-arch fixtures: raw Nginx admission compared one
route-root scan with the whole carrier manifest and reported the sibling arch
as 116 removed paths. `validateRawNginxCompatibilityClosure` now projects the
carrier manifest to the selected route before final ABA/drift comparison while
still rejecting unexpected files in that route. The new
`TestRawNginxCompatibilityClosureProjectsMultiArchCarrierManifest` is the
additional R–V test and covers both valid arches plus route-local drift.

The first post-delta W–Z race run also exposed a flaky test-only allocation
threshold: a streaming 32 MiB manifest audit used 16.93 MiB total allocations,
slightly above a fixed half-manifest threshold, while five isolated repeats
ranged from 14.5–16.1 MiB and had no race report. The gate was strengthened
into an 8 MiB→32 MiB allocation-slope check: it rejects either a whole-manifest
allocation or growth above 8 MiB. Three ordinary and three race repetitions
passed; the final W–Z ordinary/race shard then passed at 36.133s/63.533s.
Product validation semantics were not relaxed.

## Static, dependency, provenance, and security gates

The following current-file checks passed:

- `go vet ./...` and `go vet -tags perf ./internal/cli ./test/perf`;
- `go mod verify` and `go mod tidy -diff` in both modules;
- the nested patched RPM module's tests (`1.629s`) and vet;
- `third_party/cavaliergopher-rpm/verify-upstream.sh`, pinned to v1.3.0 sum
  `h1:UHX46sasX8MesUXXQ+UbkFLUX4eUWTlEcX8jcnRBIgI=`;
- product and approved fork-patch files are gofmt-clean;
- `git diff --check` before evidence generation;
- no non-test `cmd/`, `internal/`, or `edge/` file contains a TODO/FIXME,
  unimplemented stub, panic, or `os/exec` product dependency;
- fixed `govulncheck@v1.6.0` found zero reachable vulnerability in both
  modules. The main module had one required-module advisory outside the call
  graph; the nested module reported no vulnerability.

The fork provenance gate initially caught a one-blank-line drift in upstream
`cmd/rpmdump/main.go`. The untouched file was restored byte-for-byte to the
v1.3.0 module-cache copy; the allowlist was not widened. This was comment-only
and did not change SOW product behavior.

The vulnerability tool source came from the local read-only Go module download
cache. Only the public `vuln.go.dev` database was read, with provider credentials
cleared. Go 1.26 first rejected `GOPROXY=off` while resolving module deprecation
metadata; using the local `file://` module proxy closed that tooling condition
without downloading source.

## Fuzz gates

| target | window | observed executions | result |
|---|---:|---:|---:|
| HTTPS-relative upstream resolution | 5s | 75,990 | 6.923s PASS |
| APT Release checksum paths | 5s | 65,094 | 6.611s PASS |
| RPM OpenPGP signature packets | 10s | 989,790 | 11.482s PASS |
| patched RPM binary header reader | 10s | 2,897,788 | 11.894s PASS |

Execution counts are scheduler observations, not acceptance thresholds. No
crash corpus was added to the workspace.

## Edge contract and static binaries

`npm run build` reproduced all checked-in edge bundles byte-for-byte. The three
SHA-256 values remained:

- Cloudflare auth Worker: `db3361b6…12d06`;
- Cloudflare service-only R2 origin: `54f9dfe5…46923`;
- EdgeOne adapter: `b58a1d80…173af`.

All syntax/import checks and 41/41 isomorphic contract tests passed (115.013083ms test
duration). They cover
token/Basic verification, credential stripping, clean-URL normalization,
relative hrefs, dynamic mirrorlists, exact route ownership, provider-verifier
failure mapping, and the absence of the Workers Cache API. They do not prove a
real multi-PoP cache HIT or provider purge.

Four `CGO_ENABLED=0`, `-trimpath` builds passed:

| target | bytes | SHA-256 | format |
|---|---:|---|---|
| darwin/amd64 | 56,267,680 | `00b96797d0fbaff7f2d18beae2aeed607c56c20b1a67efba921c1b80f406c25b` | Mach-O x86_64 |
| darwin/arm64 | 53,423,074 | `5a61a18374a563e9b0e801a276adbfb0fc5084136f0bfbf863a3ede1467e39e5` | Mach-O arm64 |
| linux/amd64 | 54,459,526 | `e1829da6b3c5682d78c947e277e4bbc58bb64fdb1fca8d9309304cd3e92d6836` | static ELF x86-64 |
| linux/arm64 | 51,218,631 | `664450be38bd1c21533f081d9dfaffb256b742c546f0695b3088209315ccf650` | static ELF aarch64 |

## Current 50k and large-tree measurements

| gate | ordinary | race |
|---|---|---|
| upstream candidate spool | 50,000 in 0.85s; disk 29,265,920B; retained heap growth 0B | 10.66s; retained growth 0B; no race |
| APT streaming | 50,000 in 3.986s; 4/4 workers; chunk peak 256; spool 32,126,600B; retained +198,200B | 12.760s; retained +208,920B; no race |
| CAS materialization | 17.286s + 2.545s reconcile; 8/8 workers; retained +154,584B | 21.290s + 4.276s; retained +154,248B; no race |
| one-change publish plan | 50,000 to one object in 12.242ms; retained +40,008B | 120.153ms; retained +39,800B; no race |
| YUM streaming | 50,000 in 6.282s; metadata 5,893,061B; retained growth 0B | 48.182s; metadata 5,906,197B; retained +13,648B; no race |
| no-change publish preflight | 50,000 × 100 in 20.857ms without reading the view | 69.323ms; no race |
| full-change plan closure | 50,000 objects in 85.244ms | 785.289ms; no race |
| CDN verification | 50,000 objects in 68.920ms; configured/peak workers 8/8 | 266.326ms; 8/8; no race |

Strong YUM used four 12,500-record leaves, two generations, `Previous`, replay,
L1, and GC preflight. Every activation observed four leaf workers and at most
two install workers per leaf, for the configured combined peak of eight:

| phase | ordinary | race |
|---|---:|---:|
| generation 1 | 58.227s | 74.068s |
| generation 2 + Previous | 93.524s | 120.224s |
| replay | 77.030s | 83.699s |
| L1 verification | 30.338s | 32.419s |
| GC preflight | 36.103s | 48.556s |
| peak heap | 85,026,648B | 83,538,640B |
| process max RSS | 133,382,144B | 413,138,944B |
| complete test | 317.21s | 384.15s |

The large manifest scanner read only the independent APFS copy: 40,681 DEBs
and 31,629 RPMs, 72,310 files / 89,862,495,508 bytes total, 18 workers, 12.459s
scan time (`13.189s` package). The synthetic 50k tests used temporary fixtures;
the large test was a separate invocation with the explicit copy inode. The
production tree was never substituted.

## Real local consumers and protocol paths

With only already-local Docker images and temporary Nginx origins:

```text
SOW_RUN_DOCKER_COMPAT=1 SOW_COMPAT_NGINX=1
SOW_COMPAT_APT_IMAGE=pgsty/u22:latest
SOW_COMPAT_DNF_IMAGE=pgsty/el10:latest
SOW_COMPAT_EL9_IMAGE=pgsty/el9:latest
SOW_COMPAT_EL8_IMAGE=pgsty/el8:latest
go test -timeout 25m -count=1 -v ./test/compat

ok github.com/pgsty/sow/test/compat 119.825s
```

Unmodified apt 2.4 and EL8/9/10 DNF consumed and installed from generated
Packages/Release/InRelease/by-hash and primary/filelists/other/repomd metadata.
The run covered gzip/zstd, package and repository signatures, latest/history,
snapshot, Basic fallback, generation pinning, retained packages during a flip,
empty successor generation, Nginx exact allowlists, and detached-signature
negative states. Missing package keys and mixed signature pairs failed as
required.

The pinned MinIO image
`sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e`
passed the real S3/SigV4 client test in `1.05s` (`1.861s` package), covering
conditional mutation, publication/replay, List/HEAD/GET, server-side copy, and
delete. It is not R2 or COS evidence.

The explicit read-only official-upstream gate also ran on this source. It
fetched signed PGDG APT and YUM metadata, selected a bounded package subset,
verified exact bodies and RPM signatures, committed asymmetric provenance,
replayed with zero downloads, passed L1 and materialized both repository
types. The test took 180.91s (`181.826s` package): APT observed 4,010
candidates and downloaded 1; YUM observed 1,344 and downloaded 12; replay was
`present=1` and `present=12`. The final tree contained 13 package receipts, 45
files and 536,434 CAS bytes. Only the public PGDG origins were read.

FR-17's builder handoff was rerun with the 313,928-byte `pev2-1.22.0-1.noarch`
RPM from the writable copy and a public-only Pigsty key fetched read-only from
the documented `/key` URL. The public key SHA-256 was
`17b9c7727c3a4d3b77463299ade471b28a8ba97da263e6bbb02986a578de0882`
and its fingerprint was `9592A7BC7A682E7333376E09E7935D8DB9BD8B20`.
AlmaLinux 10 first rejected the package without that key, then installed it
with both repository and package trust configured; `rpm -K` returned
`digests signatures OK`. The test took 3.44s (`4.615s` package). The source
repository and public-key endpoint received reads only; all generated metadata
and client writes stayed in temporary storage/containers.

A Linux/arm64 test binary cross-built from the same source ran in the already
local `pgsty/u26a@sha256:2d337f1d…b531b` image with `--network none`. The
deterministic TGZ golden and every default-build `OfflineArchive*` test passed,
including process death, directory fsync, link replay, independent-root taint,
ordinary embedded gzip, marker-free deterministic gzip, 64KiB scan boundary,
malformed gzip/tar barriers, payload marker tamper, and scoped adoption recovery.

## Migration and disposable full-copy adoption

All seven hermetic migration scripts passed on current files:

- physical config and topology closure;
- 44-family / 177-line legacy target mapping and negative mutations;
- zero-byte adoption, isolated materialization, and symlink rollback;
- writer-fence positive and 13 fail-closed cases;
- family CLI E2E, including DEB/RPM add, sync, publish, GC, and materialize;
- 28 Pigsty YUM consumer definitions staged, applied, replayed, and rolled back
  on a temporary copy while the Pigsty source hashes remained unchanged.

The completed fresh-copy adoption is recorded in
[`2026-07-16-fresh-full-content-adoption.md`](2026-07-16-fresh-full-content-adoption.md).
The earlier
[`2026-07-16-legacy-tree-full-adoption-copy.md`](2026-07-16-legacy-tree-full-adoption-copy.md)
is retained as the historical discovery report. The fresh copy closed 40,659
active APT payloads, 44,372 PGDG YUM payloads, 16,582 other YUM payloads, and
958 public assets without rewriting serving bytes. Of the original 30,274
PGDG missing paths, 29,499 were restored byte-exact from official PGDG
current/archive and the stable official-404 remainder of 775 was excluded only
through complete-set digest `5d953c...866a` and 775 immutable negative
provenance receipts. Exact replay returned the same commit with
`changed=false`.

The current PGDG EL10/x86_64 generation contains 320 packages and signed zstd
primary/filelists/other metadata. A network-disabled AlmaLinux 10 client with
all external repos disabled, `repo_gpgcheck=1`, and `gpgcheck=1` completed
`dnf makecache` and installed
`postgresql18-docs-18.1-1PGDG.rhel10.x86_64` using the current official PGDG
RHEL package key. Final full-copy fsck reported 95 clean repos, 10 prune
ledgers/775 receipts and zero drift; GC dry-run reported 102,343 reachable,
zero orphan/missing objects, and zero deletes.

The historical read-only inventory in
[`2026-07-16-yum-infra-package-signature-inventory.md`](2026-07-16-yum-infra-package-signature-inventory.md)
recorded 194 signed paths and 22 unsigned paths. A later fresh read-only source
snapshot closed that input condition: all 216 current RPM paths verify against
the Pigsty package key and are byte-identical to the exact writable fixture.
That fixture completed dual-architecture S0→S3, six EL8/9/10 strong DNF
consumers, L1, fsck, and idempotent cutover replay. The source's 234-file
manifest was unchanged before and after the run. Exact commits, generations,
package counts and hashes are in
[`2026-07-17-yum-infra-current-compatibility-cutover.md`](2026-07-17-yum-infra-current-compatibility-cutover.md).
SOW did not implicitly re-sign a package and did not write the production tree.

## Remaining boundaries

This report closes the current local ordinary/race/static, fuzz, scale,
portability, edge-contract, real apt/dnf/Nginx, local MinIO, Linux archive, and
migration validation surfaces. It does not close:

- dedicated reviewed non-production R2/COS and Cloudflare/EdgeOne runs;
- production migration, writer revocation, cutover, rollback, or post-cutover
  URL compatibility;
- inactive builder/gated handoff and production execution of the validated
  raw-YUM compatibility cutover;
- post-production incident, latency, storage-cost, or CDN geography metrics.

Production CO/COS/Cloudflare resources remain permanently forbidden for tests.
Until dedicated non-production provider resources and the remaining external
decisions exist, the Goal remains active.

The 2026-07-16 owner follow-up subsequently closed two policy-only items:
apt < 1.2 is unsupported and EL8 freezes beginning with Pigsty v5.0.0. See
[ADR-0029](../adr/0029-client-support-floor-and-el8-freeze-version.md). These
decisions do not alter the validation commands or turn the apt 1.0 negative
control into a passing mutable-publication path.

## ADR-0030 repair mechanism and live corpus boundary

The owner authorized exact recovery/repair of the missing package set.
The product now retains default rejection and adds only an audit-bound
`--adopt-prune-missing-yum-confirm` path with a deterministic complete blocker
digest, two-pass drift detection, strict negative provenance and idempotent
replay. It also fixes empty YUM materialization so a fully pruned leaf produces
a valid signed zero-package repository instead of relying on a payload worker
to create the nested target directory.

The following focused gates passed before the exhaustive post-delta closure
reported above. Provider credentials were removed, real-cloud/edge/upstream
opt-ins disabled, and the runs used loopback-deny proxies plus `GOPROXY=off`:

```text
go test ./internal/provenance ./internal/cli ./internal/config \
  -run 'TestLegacyIndexPruneReceiptIsStrictAndSorted|TestLegacyAdoptionPreflightTreatsDDEBAsPackagePayload|TestLegacyAdoptionBlockerReportIsSortedAndComplete|TestInitAdoptContentRejectsUnindexedOrTamperedPackageBodies|TestPigstyV1PhysicalMigrationContract|TestDecodeFreezesEL8AndModernCompression' \
  -count=1
ok github.com/pgsty/sow/internal/provenance 0.925s
ok github.com/pgsty/sow/internal/cli 1.521s
ok github.com/pgsty/sow/internal/config 0.675s

go test ./internal/cli \
  -run '^TestInitAdoptContentPrunesMissingYUMOnlyWithExactAuditedSet$' \
  -count=1 -v
--- PASS: TestInitAdoptContentPrunesMissingYUMOnlyWithExactAuditedSet (2.72s)
ok github.com/pgsty/sow/internal/cli 4.057s
```

The E2E includes default and wrong-digest failure, index mutation between
preflight/import, exact confirmation, zero CAS payload mutation, canonical
negative-provenance decoding, idempotent replay, signed empty-repository
validation and fsck. The subsequent exhaustive ordinary/race/static/compat and
performance reruns include this code. The later fresh-copy run completed the
30,274-object disposition as 29,499 recovered objects plus 775 immutable
negative receipts and proved the resulting repository with real DNF; see the
fresh-copy report above.
