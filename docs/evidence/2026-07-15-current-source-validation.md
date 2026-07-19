# Current-source local validation closure — 2026-07-15

Date: 2026-07-15 (Asia/Shanghai)
Host: Apple M5 Max, macOS 26.5.2 arm64, Go 1.26.5

## Safety boundary

This validation did not use the local production repository, CO/COS production
storage, Cloudflare production storage/CDN, or any production domain as a test
target. The existing local repository was read only in the separately recorded
APFS-clone inventory run; every write in this report went to `t.TempDir`,
`/private/tmp`, a local Nginx process, or disposable Docker containers.

All Go runs cleared AWS, Cloudflare and Tencent credential/profile variables,
set the AWS config and credential files to `/dev/null`, disabled EC2 metadata,
fixed `SOW_RUN_REAL_CLOUD=0`, `SOW_RUN_REAL_EDGE_EVIDENCE=0`,
`SOW_RUN_REAL_UPSTREAM=0` and the purge-watcher helper to `0`, and used a
loopback-deny proxy with `GOPROXY=off` after dependencies were already present.
The real-cloud registry remains empty, so the provider harness fails before a
network request. Default and performance tests therefore provide no authority
to write, publish, purge or probe a production resource.

## Exhaustive ordinary, race and static gates

The 648 ordinary CLI tests were partitioned by the six exhaustive suffix
expressions now used by CI. The same partition was used under the race detector:

| CLI shard | ordinary | race |
|---|---:|---:|
| `^Test[A-F]` | 559.248s | 316.315s |
| `^Test[G-M]` | 789.116s | 507.033s |
| `^Test[N-O]` | 254.760s | 148.142s |
| `^Test[P-Q]` | 487.934s | 709.660s |
| `^Test[R-V]` | 581.339s | 344.415s |
| `^Test([W-Z]|[^A-Z]|$)` | 120.920s | 87.986s |

Every non-CLI Go package also passed once ordinarily and once with `-race`.
After the performance-fixture corrections described below, the changed YUM
package was rerun in full (`9.381s` ordinary, `12.782s` race), the build-tagged
performance group passed ordinarily and with race, and strong-YUM received its
own 50k ordinary/race run. No race report occurred.

The following static and delivery-surface checks passed on the current files:

- `go vet ./...` and `go vet -tags perf ./internal/cli ./test/perf`;
- `go mod verify` (`all modules verified`) and `go mod tidy -diff` (empty);
- the nested patched RPM module's tests and vet;
- fixed `govulncheck@v1.6.0` on the main module and nested RPM module: no
  reachable vulnerability in either; the main module had zero vulnerable
  imported packages and one required-module advisory outside its call graph,
  while the nested module had one imported-package advisory outside its call
  graph;
- `git diff --check` before report generation;
- edge build, three generated-bundle syntax checks, source-import closure and
  41/41 contract tests; rebuilding changed no checked-in bundle bytes;
- CI YAML parsing and repository policy/allowlist tests.

The six CLI shards replace a single long-running CI process; they do not reduce
coverage. Core packages, six ordinary CLI shards and six race CLI shards are
separate jobs, with real-cloud and upstream opt-ins pinned off globally.

Current-source fuzz windows also passed with 18 workers:

| target | window | executions observed | package result |
|---|---:|---:|---:|
| HTTPS-relative upstream resolution | 5s | 22,304 | 7.287s PASS |
| APT Release checksum paths | 5s | 18,760 | 6.962s PASS |
| RPM OpenPGP signature packets | 10s | 435,695 | 11.132s PASS |
| patched RPM binary header reader | 10s | 614,497 | 11.419s PASS |

Execution counts are scheduler observations, not acceptance thresholds. No
crash corpus or other file was added to the workspace.

## Real package-manager and S3-compatible consumers

With only locally present images and a temporary Nginx origin, the current
source passed:

```text
SOW_RUN_DOCKER_COMPAT=1 SOW_COMPAT_NGINX=1
SOW_COMPAT_APT_IMAGE=ubuntu:22.04
SOW_COMPAT_DNF_IMAGE=almalinux:10
SOW_COMPAT_EL9_IMAGE=almalinux:9
SOW_COMPAT_EL8_IMAGE=almalinux:8
go test -timeout 25m -count=1 ./test/compat

ok github.com/pgsty/sow/test/compat 120.339s
```

That package exercised real apt 2.4 consumption/install through by-hash,
Packages/Release/InRelease signatures, latest/history/snapshot and Basic
fallback; and real DNF on EL8/9/10 with gzip/zstd metadata,
`repo_gpgcheck=1`, package signature checks, generation-pinned serving,
retained-package access across a flip, and the detached-signature bridge
negative cases. The missing package-key negative failed as required.
Real-cloud, real-edge, real-upstream, legacy-APT and other explicit opt-in gates
were not enabled and are not counted as passed.

The fixed-digest local MinIO process also passed the production S3/SigV4 client
path:

```text
SOW_MINIO_TEST=1 go test -count=1 -run '^TestMinIOS3Compatibility$' -v ./internal/publish
--- PASS: TestMinIOS3Compatibility (0.79s)
ok github.com/pgsty/sow/internal/publish 1.796s
```

This covers conditional mutation, publication/replay, List/HEAD/streaming GET,
server-side copy and delete against a real S3-compatible process. It is not an
R2 or COS provider run.

## Current 50k and large-tree measurements

| Gate | Current result |
|---|---|
| Upstream candidate spool | 50,000 candidates, disk spool 29,265,920B, retained heap +20,800B, 0.47s test |
| APT streaming | 50,000 packages in 2.951s, 4/4 worker peak, chunk peak 256, spool 32,126,600B, retained heap +203,424B, raw MaxRSS 295,059,456B |
| CAS materialization | 50,000 paths in 14.989s plus 2.569s reconcile, workers/peak 8/8, retained heap +152,584B |
| One-change publish plan | 50,000 entries to one changed object in 13.147ms, retained heap +40,008B |
| Full-change publish closure | 50,000 objects in 79.683ms |
| CDN verification | 50,000 objects in 75.342ms, configured/peak workers 8/8 |
| Incremental preflight | 50,000 entries × 100 checks in 8.707ms without reading the view |
| YUM streaming | 50,000 checksum-distinct records in 6.250s, compressed metadata 5,893,488B, retained heap +21,072B |

The combined materialize/one-change/YUM performance package passed in 28.761s.
Its race run passed in 104.885s; the YUM phase itself completed in 80.84s with
retained heap +19,888B and no race report.

The YUM fixture initially reused the exact same RPM body at 50,000 locations.
The current streaming self-validator correctly rejected this as duplicate
`pkgid`, matching the frozen no-duplicate-body-per-channel contract. The test
was corrected rather than the validator weakened: each synchronous parse now
uses the same real RPM header plus a fixed-width checksum-distinguishing test
trailer. A normal/race regression proves that two different locations cannot
bypass duplicate-body rejection. These are parser-valid synthetic performance
bodies, not package-trust or install evidence; the Docker matrix above supplies
the real signed-install evidence.

The strong-YUM fixture was also corrected to use canonical configuration,
`applyCanonicalState`, SQLite rebuild/advance, and RPM identities obtained from
the production inspector. It no longer seeds fake names or bypasses the query
projection. Four leaves and 50,000 raw coordinates then passed two generations,
current+Previous retention, idempotent replay, L1 and GC preflight:

| phase | ordinary wall / peak heap | race wall / peak heap |
|---|---:|---:|
| generation 1 | 55.226s / 56,348,536B | 65.328s / 48,726,136B |
| generation 2 + Previous | 90.104s / 51,659,696B | 104.346s / 49,224,232B |
| replay | 75.429s / 49,320,896B | 74.340s / 50,928,880B |
| L1 | 31.962s / 87,174,952B | 30.706s / 80,492,248B |
| GC preflight | 35.498s / 21,279,088B | 47.030s / 21,252,008B |

Ordinary completed in 309.94s (package 311.290s); race completed in 346.78s
(package 349.037s). Every activation observed four leaf workers and two inner
install workers, so the combined peak remained exactly the configured budget
of eight. The process MaxRSS observations were 135,184,384B ordinary and
403,013,632B with race instrumentation.

Separately, the read-only production-tree clone evidence remains the larger
real-file measurement: 72,310 files / 89,862,495,508 bytes hashed with 18
workers in 9.151s (10.008s package). The original local tree was not a test
target.

## Static binaries

All four `CGO_ENABLED=0`, `-trimpath` builds passed:

| target | bytes | SHA-256 | format |
|---|---:|---|---|
| darwin/amd64 | 56,106,128 | `733972c7603d0a35556f2e63d7a91e01f655afbfb991e7ae19832d25ee9def60` | Mach-O x86_64 |
| darwin/arm64 | 53,268,546 | `b9295253e3ba01c7827a28b8cfc5ef1d19d7ed89e68d5da220f5e7b0283c2972` | Mach-O arm64 |
| linux/amd64 | 54,302,176 | `3f29c9b5321059a023c02a7bb8fcf2228e2d90d11bd2efe6105f3696a904f574` | statically linked ELF x86-64 |
| linux/arm64 | 51,052,321 | `1427f686327441421ab3f36959235ecda3acaea43988254e48e135518d6b6c66` | statically linked ELF aarch64 |

The clean-delivery archive is rebuilt after this report and the traceability
ledger are frozen. Its post-document file counts and digests are deliberately
recorded only in the external implementation handoff referenced by V-14, so
the delivered content does not contain a self-referential digest.

## Remaining boundaries

This report closes current local ordinary/race/static, real local apt/dnf,
MinIO, scale and portability validation. It does not close:

- real disposable non-production R2/COS and Cloudflare/EdgeOne provider runs;
- production migration, writer revocation, cutover, rollback or post-cutover
  URL compatibility;
- the apt-before-1.2 and raw-YUM-alias business disposition;
- post-production incident, latency, storage-cost or CDN geography metrics.

Production CO/COS/Cloudflare resources remain forbidden for testing. Until
dedicated reviewed non-production resources exist, the Goal remains active.
