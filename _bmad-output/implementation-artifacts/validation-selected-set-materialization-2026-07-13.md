# SOW selected-set and materialization validation handoff — 2026-07-13

> Current local update: 2026-07-16. The 2026-07-15 and 2026-07-14 identities
> are retained below as historical evidence only.

This artifact is intentionally outside the clean-delivery content roots. It
records the post-document archive identity without creating a self-referential
digest change inside that archive.

## 2026-07-16 current post-document source and archive identity

After the final full-copy adoption report, current-source validation report,
traceability ledger, evidence index, and delivery allowlist were frozen, the
clean-delivery program was run sequentially in two independent directories.
All AWS/Cloudflare/Tencent credentials and profiles were cleared;
real-cloud/edge/upstream/purge-watcher gates were fixed to zero; HTTP(S) was
loopback-denied. Go modules came only from the local read-only download cache:

```text
SOW_CLEAN_GOPROXY=file:///Users/vonng/go/pkg/mod/cache/download \
  ./test/compat/test-clean-delivery.sh \
  /private/tmp/sow-clean-final-e.wn6RUN/delivery

SOW_CLEAN_GOPROXY=file:///Users/vonng/go/pkg/mod/cache/download \
  ./test/compat/test-clean-delivery.sh \
  /private/tmp/sow-clean-final-f.SoJ05u/delivery
```

Both fresh runs returned exactly:

```text
PRODUCT_SOURCE_SHA256=d1d03f9b3e104be5fe3e2f719a1272f519ac78883d677dd548056db2ebb89c9f
PRODUCT_SOURCE_FILES=519
DELIVERY_CONTENT_SHA256=8e4e2af3a78d94e01784ad02df3198bec970f09d0c34f4b1a9c3d2e349021a99
DELIVERY_FILES=637
ARCHIVE_SHA256=ba6c1bc36055387080753d03e1c8eaae863bf09ddf35b5f17820b23c2a8bd00d
```

The byte-identical archives (`cmp -s` exit 0) are:

- `/private/tmp/sow-clean-final-e.wn6RUN/delivery/sow-delivery-8e4e2af3a78d94e0.tgz`
- `/private/tmp/sow-clean-final-f.SoJ05u/delivery/sow-delivery-8e4e2af3a78d94e0.tgz`

Each run reconstructed only explicit allowlist entries, used fresh
HOME/GOMODCACHE/GOCACHE, verified module sums, scanned allowed content for
secrets, checked Markdown links, tested and built the extracted source, and
generated two equal deterministic archives internally before publishing one.
The two independent published archives were then compared again. No local
production repository, CO/COS, Cloudflare, or EdgeOne production resource was
accessed or mutated.

The 657-test CLI ordinary/race closure, all non-CLI ordinary/race, static and
provenance gates, four builds, edge 41/41, fuzz, vulnerability, 50k
ordinary/race, real apt/dnf/Nginx, pinned MinIO, Linux `--network none`
archive, and seven migration suites are recorded in
`docs/evidence/2026-07-16-current-source-validation.md`. The separate writable
full-copy adoption evidence is
`docs/evidence/2026-07-16-legacy-tree-full-adoption-copy.md`.

Real reviewed non-production R2/COS/Cloudflare/EdgeOne evidence, production
migration and operational metrics remain open. Production resources are
forbidden for testing, so this identity is not a Goal-completion claim.

## 2026-07-15 historical post-document source and archive identity

After the current validation report, traceability ledger and delivery allowlist
were frozen, the clean-delivery program was run sequentially in two independent
directories. All AWS/Cloudflare/Tencent credentials and profiles were cleared;
real-cloud/edge/upstream gates were fixed to zero; HTTP(S) was loopback-denied.
Go modules came only from the local read-only download cache:

```text
SOW_CLEAN_GOPROXY=file:///Users/vonng/go/pkg/mod/cache/download \
  ./test/compat/test-clean-delivery.sh \
  /private/tmp/sow-clean-delivery-final-20260715-a

SOW_CLEAN_GOPROXY=file:///Users/vonng/go/pkg/mod/cache/download \
  ./test/compat/test-clean-delivery.sh \
  /private/tmp/sow-clean-delivery-final-20260715-b
```

Both fresh runs returned exactly:

```text
PRODUCT_SOURCE_SHA256=94bc69678365871be5cd31b80d7e94a3f7c966bc86aaa16a4b67973e69f8d0b5
PRODUCT_SOURCE_FILES=517
DELIVERY_CONTENT_SHA256=d9ed4b38098ec5018d0d3ed8c250c6f2e648e934978745993ed94be2864ba889
DELIVERY_FILES=629
ARCHIVE_SHA256=3cb2e2f9276e69e060be62574c5c820ab4a2d64fed489f317c84c05a7803bb03
```

The archives are:

- `/private/tmp/sow-clean-delivery-final-20260715-a/sow-delivery-d9ed4b38098ec501.tgz`
- `/private/tmp/sow-clean-delivery-final-20260715-b/sow-delivery-d9ed4b38098ec501.tgz`

The script rebuilt from explicit allowlists with fresh HOME/GOMODCACHE/GOCACHE,
verified module sums, tested and built the extracted source, ran migration and
edge closure, cross-built the CLI and emitted byte-identical archives. The
repository policy gate passed immediately before both runs. No local production
repository, CO/COS or Cloudflare production resource was accessed or mutated.

The current ordinary/race/static, apt/dnf, MinIO, fuzz, vulnerability, 50k and
portability measurements are in
`docs/evidence/2026-07-15-current-source-validation.md`. Real disposable
non-production dual-cloud/CDN and production migration evidence remain open,
so this identity is not a Goal-completion claim.

## 2026-07-14 historical source and archive identity

The command below was run sequentially with two independent output directories
after every delivery-root file was frozen:

```text
SOW_CLEAN_GOPROXY=https://goproxy.cn,direct \
  ./test/compat/test-clean-delivery.sh /tmp/sow-clean-final3-a
SOW_CLEAN_GOPROXY=https://goproxy.cn,direct \
  ./test/compat/test-clean-delivery.sh /tmp/sow-clean-final3-b
```

Both runs returned exactly:

```text
PRODUCT_SOURCE_SHA256=451e913efa3f290dba96de6e6c1336ecfcc1096b019b9ce8368e5a80404d5460
PRODUCT_SOURCE_FILES=349
DELIVERY_CONTENT_SHA256=2d5aab7e50b4390fc84139e5277f3e7c88e46f6a6584a155ede8231d01b75594
DELIVERY_FILES=427
ARCHIVE_SHA256=7a83b564c8983486e0adccbf415f11c0bcba1c4eb44a373bca24700a0161ecd2
```

The resulting archives are:

- `/tmp/sow-clean-final3-a/sow-delivery-2d5aab7e50b4390f.tgz`
- `/tmp/sow-clean-final3-b/sow-delivery-2d5aab7e50b4390f.tgz`

## Final merged validation

- `go test -count=1 ./...`: PASS; `internal/cli` 489.009s; every other
  internal, compat and clean-delivery package PASS.
- `go test -race -count=1 ./...`: PASS; `internal/cli` 556.048s; every other
  internal, compat and clean-delivery package PASS; no race report.
- Exact 13-test inputless asset/frozen package admission/path-scoped relink/
  writer-fence set: root ordinary 27.677s, independent ordinary 30.616s,
  independent race 33.786s.
- Core five recovery tests with `-count=3`: PASS, 43.600s; repository package
  `-count=3`: PASS, 7.872s; repository race: PASS, 4.989s.
- `go vet ./...`: PASS, 11.063s in the independent run.
- `go mod tidy -diff`: PASS, empty diff.
- `go mod verify`: PASS, all modules verified.
- Patched nested RPM module: PASS, package 0.613s.
- Edge contract: 26/26 PASS, 143.681ms test duration.
- Fixed `govulncheck@v1.6.0`: reachable vulnerabilities 0; vulnerable imported
  packages 0; one required-module advisory is not called.
- Production placeholder scan: no TODO/FIXME/XXX/not-implemented match.
- Full-repository `gofmt -l` empty and `git diff --check` PASS.
- Current-source real-client Docker/Nginx compatibility: PASS, package 99.123s;
  Docker client 58.14s, Nginx allowlists 5.03s/5.04s, YUM detached-signature
  bridge 29.17s. Real apt 2.4.14 consumed by-hash and installed; DNF
  4.20/4.14/4.7 installed with metadata/package signature checks and `rpm -K`;
  the missing-package-key negative failed as required. The real-cloud,
  real-upstream, Pigsty package-trust and legacy-APT opt-in gates were not set
  in that combined command and were therefore skipped there. They were then
  run separately against the same frozen current source, as recorded below.

## Current-source opt-in and scale gates

- Fixed-digest real MinIO/SigV4: PASS; test 0.77s, package 1.489s. Conditional
  mutation still fails closed. This is local S3-compatible evidence, not R2/COS.
- Official PGDG APT/YUM sync: PASS; test 13.99s, package 14.572s. APT observed
  4,010 candidates and downloaded 1 while filtering 4,009; YUM observed 1,344,
  downloaded 12 and filtered 1,332. Replay downloaded zero and reused 1 DEB plus
  12 RPM receipts. L1 passed and materialization closed 13 entries/45 files,
  536,434 CAS bytes and 709,521 repository bytes. RPM provenance remained v3
  with exact package-keyring, signer and header+payload-digest coverage.
- Pigsty builder package trust: PASS; test 5.98s, package 6.631s, using the real
  313,928-byte `pev2-1.22.0-1.noarch.rpm`. The missing Pigsty public key failed
  before install; with the public-only key, DNF installed and `rpm -K` returned
  `digests signatures OK`.
- Debian Jessie apt 1.0.9.8.6 fixed-alias negative PoC: PASS; test 24.21s,
  package 24.642s. Both coherent generations installed. Old InRelease plus new
  Packages and redirect/no-store/cookie generation candidates both failed with
  `Hash Sum mismatch`, so the apt<1.2 support/migration decision remains open.
- Current fuzz windows passed with 18 workers: HTTPS-relative URL resolution
  586,033 executions/5.677s; APT Release path parsing 572,139/6.085s; RPM
  OpenPGP packet parsing 3,440,781/10.570s. Counts are observations, not gates.
- The packaged edge directory was extracted from the frozen delivery archive,
  rebuilt outside the workspace and tested. All 26 tests passed in 89.699ms;
  `node --check` and source-import closure passed. Before/after bundle SHA-256
  values were identical: origin Worker `7a65b928…b9310`, auth Worker
  `931c965f…117d`, EdgeOne `8eb60435…938c`.

Current isolated scale results:

| Gate | Current result |
|---|---|
| Real manifest scan | 40,681 APT files/47,155,427,190B in 4.377s plus 31,629 YUM files/42,707,068,318B in 3.431s; total 72,310/89,862,495,508B in 7.808s with 18 workers |
| Upstream candidate spool | 50,000 candidates, retained heap +20,480B, disk spool 29,265,920B; real HTTP concurrency bound PASS |
| APT streaming | 50,000 packages in 3.063s; worker peak 4, chunk peak 256, retained +198,584B, raw max RSS 286,261,248B, spool 32,026,600B |
| YUM streaming | 50,000 packages in 4.083s; retained +46,256B, compressed metadata 152,300B |
| CAS materialize | 50,000 entries in 11.389s plus reconcile 2.631s; workers/peak 8/8, retained +154,968B |
| Publish plan | 50,000→1 change in 12.968ms; one object, retained +40,280B |
| Incremental preflight | 50,000 entries × 100 checks in 9.259ms without reading the view; retained delta -941,112B |
| Strong YUM serving | four 12.5k leaves, worker bound/peak 8/8; generation 1 24.724s, generation 2 43.298s, replay 35.029s, L1 6.762s, GC preflight 10.004s; test max RSS observation 101,662,720B |

Current local migration gates also passed without workspace edits or any
production/cloud operation:

- legacy audit script: 44.36s, 13/13 checks (4 positive, 9 fail-closed);
- local adoption/rollback: 2.96s, 7/7 assertions including two negatives;
- writer-fence preflight: 1.49s, 13/13 (2 positive, 11 fail-closed);
- targeted Go ordinary: 22.66s, 20 top-level tests plus 8 subtests;
- targeted Go race: 32.59s, the same 20+8 and no race report.

Logs are `/tmp/sow-current-migration-audit.log`,
`/tmp/sow-current-local-adoption-rollback.log`,
`/tmp/sow-current-writer-fence-preflight.log`,
`/tmp/sow-current-migration-go-test.log`, and
`/tmp/sow-current-migration-go-race.log`.

After all opt-in and scale runs, a third read-only delivery reconstruction in
`/tmp/sow-clean-final3-c-check` returned the same 349/427 file counts and the
same product, delivery and archive SHA-256 values above. Thus those runs did
not mutate the frozen delivery surface.

Final `CGO_ENABLED=0` binaries:

| Target | Bytes | SHA-256 |
|---|---:|---|
| linux/amd64 | 47,774,486 | `c9dfa92a6254a2c54eae1b57413aeb99e86204a7756aebb19d58904aa4809f9d` |
| linux/arm64 | 45,329,319 | `a4ec9c21aa7f7797af526631bc7aa938c418ff3030ece267fb295a61ee488184` |
| darwin/amd64 | 49,481,232 | `8b3ce90c2143dc7b478254f709b187995b8e52486ea9f0b3e3b6b09eb2bb938c` |
| darwin/arm64 | 47,393,026 | `a721d0f981be748e609dcd87417bb193dff9d597af0b1a9b0a842ac755221b9a` |

## Independent audit closure

The earlier read-only audit found two P2 defects after the first selected-set
fixes:

1. exact historical recovery observed the remote while its durable local
   journal was still active;
2. explicit partial target replacement deleted physical serving bytes but left
   cross-view canonical channel/target state.

Both are closed. Historical recovery now rebuilds and finishes the frozen local
CAS/metadata tree before provider-client construction. Explicit targets own the
entire serving topology of their physical root and remove obsolete channels,
retire unreferenced generations and delete orphan target registries. Tests
verify zero HTTP while the exact historical journal exists, A→B→A URL migration
without deferred GC orphans, cross-view target replacement, retirement witness,
and L1 with no `LOCAL_YUM_*` drift.

The later recovery audit then found and closed three additional admission
classes:

1. standalone asset recovery depended on the original positional input and ran
   after current subtype dispatch instead of before it;
2. asset materialization exposed a whole-manifest replacement authority rather
   than admitting replacement per configured mutable path;
3. an active package-add journal did not fence novel RPM/DEB CAS installation
   by family and exact frozen entries.

Recovery is now inputless and precedes current work. RPM/DEB recovery requires
the frozen family, trust/config/HEAD, exact unit vector and complete
path/size/SHA entries before CAS installation; both use private snapshots and
expected-object installation. Asset canonical upsert and physical relink share
the same per-path mutable policy. The final independent focused/race/stress,
vet, format and diff audit reported `NO ACTIONABLE FINDINGS`.

## Goal status and external blockers

The long Goal remains active. Local implementation and evidence do not replace
the following still-required external or business evidence:

A presence-only environment audit found the real-cloud opt-in, destructive
confirmation, R2/COS endpoints and buckets, CDN URLs and zones, two EdgeOne
tokens, and all four credential JSON variables unset. No credential value was
read or logged, and the destructive harness was not started.

- real R2 and COS publish/copy/CAS-lock/drift/failure-replay runs;
- real Cloudflare and EdgeOne deployment, entitlement provider, two-token/WAF,
  clean-cache observation, purge and multi-PoP checks;
- production migration/cutover/rollback and post-cutover latest URL checks;
- an explicit support/migration decision for apt before 1.2 and raw YUM alias
  consumers;
- the business-selected Pigsty version at which EL8 freezes;
- production G1/ANTI-01/ANTI-02/ANTI-03/NFR-07 operational and cost metrics.

None of those is reported as passed by this artifact.

## 2026-07-16 post-fresh-copy final delivery identity

The earlier counts and blockers above are historical. After the fresh-copy
PGDG/APT/YUM/asset closure, SQLite multi-connection writer fix, 659-test
ordinary/race closure, evidence refresh, and clean-delivery allowlist update,
two independent external output directories produced byte-identical archives:

```text
PRODUCT_SOURCE_SHA256=129f10ba0ad2f3950af14e6d8cb162326f8a049be068f67e65b6e7cdb3390202
PRODUCT_SOURCE_FILES=519
DELIVERY_CONTENT_SHA256=beec3b84fe25ada5df3d2fbad505e7b87e089ecc36fa7d5843610d74b69dc6d0
DELIVERY_FILES=639
ARCHIVE_SHA256=ce354195e7cd54d223f9fea65add0968299de18f52ffbb953e71b49d67ef61ab
```

Archives:

- `/private/tmp/sow-clean-delivery-post-fresh-20260716/sow-delivery-beec3b84fe25ada5.tgz`
- `/private/tmp/sow-clean-delivery-post-fresh-20260716-b/sow-delivery-beec3b84fe25ada5.tgz`

`cmp -s` returned 0. Both builds used a fresh HOME/GOMODCACHE/GOCACHE, the
read-only local Go download cache as a `file://` proxy, cleared cloud
credentials, disabled every real-cloud/edge/upstream opt-in, and a loopback
deny proxy. Repository policy, secret/link audit, module verification, focused
config tests, static CLI build, help and version all passed inside each
reconstructed delivery.

The owner has since frozen apt `< 1.2` as unsupported and EL8 as frozen from
Pigsty v5.0.0, so those are no longer decision blockers. Fresh-copy content
repair is also closed: the PGDG 30,274 missing-path set is fully disposed as
29,499 official recovered paths plus 775 exact negative-provenance receipts,
then consumed by real network-disabled DNF and audited by full fsck/GC.

The Goal remains active for three materially different boundaries:

- builder-signed replacements for the 21 unique unsigned `yum/infra` RPM
  objects, followed by real S1→S3 compatibility cutover evidence;
- dedicated, reviewed non-production R2/COS/Cloudflare/EdgeOne resources and
  real provider/cache/purge evidence; production `pro`/Pigsty resources remain
  forbidden for tests;
- production migration, consumer/Nginx cutover, writer/IAM revocation,
  rollback, post-cutover URL checks, and operational metrics.

Post-SQLite `CGO_ENABLED=0 -trimpath` cross-builds:

| Target | Bytes | SHA-256 |
|---|---:|---|
| darwin/arm64 | 53,422,786 | `ca38abb7a3521d22e01c41239060fcfb6f99d2fd1e573427b7b72858841964a4` |
| darwin/amd64 | 56,263,296 | `d9326fc5c84fc6e31723c1336a8bcc0b8a9f5e5254adf5a4f7fe22a04e4e50d5` |
| linux/arm64 | 51,216,916 | `b868469033b3a8cc68db0279a1400adf1746044524cc9ee6af5f457d85df914a` |
| linux/amd64 | 54,454,683 | `1686c6d249189c183b95ce8aeeb6f62f4de7f434343c87397b543b534ccc14d5` |

## 2026-07-17 post-current exact-copy delivery identity

This section supersedes the preceding post-fresh-copy identity. After the
current `yum/infra` 216/216 package-trust closure, dual-architecture S0→S3 and
six EL8/9/10 strong-DNF consumers, multi-arch raw-Nginx admission fix, 660-test
ordinary/race closure, current 50k reruns, migration-script rerun and final
evidence refresh, two independent clean reconstructions produced:

```text
PRODUCT_SOURCE_SHA256=4b975dce1216d3035e0458d149e06742d3de08a62f39c963477b8943e329a6dc
PRODUCT_SOURCE_FILES=519
DELIVERY_CONTENT_SHA256=b027364362673f44598b757d28c11c57e2638b950310a85136701876d889f688
DELIVERY_FILES=640
ARCHIVE_SHA256=4758b3462f5eb7a17ec4997e9e4fd09868b0927c9b25cfb558359345da13657a
```

Archives:

- `/private/tmp/sow-clean-current-a.IZD1Zs/delivery/sow-delivery-b027364362673f44.tgz`
- `/private/tmp/sow-clean-current-b.rCFqzC/delivery/sow-delivery-b027364362673f44.tgz`

`cmp -s` returned 0 and independent `shasum -a 256` checks returned the archive
digest above. Both reconstructions used fresh HOME/GOMODCACHE/GOCACHE trees,
the local read-only Go download cache as a `file://` proxy, cleared provider
credentials, disabled every real-cloud/edge/upstream opt-in, and a loopback
deny proxy. No delivery-root file was changed after these reconstructions; this
external handoff is intentionally excluded from the delivery allowlist.

Current static cross-build identities are:

| Target | Bytes | SHA-256 |
|---|---:|---|
| darwin/amd64 | 56,267,680 | `00b96797d0fbaff7f2d18beae2aeed607c56c20b1a67efba921c1b80f406c25b` |
| darwin/arm64 | 53,423,074 | `5a61a18374a563e9b0e801a276adbfb0fc5084136f0bfbf863a3ede1467e39e5` |
| linux/amd64 | 54,459,526 | `e1829da6b3c5682d78c947e277e4bbc58bb64fdb1fca8d9309304cd3e92d6836` |
| linux/arm64 | 51,218,631 | `664450be38bd1c21533f081d9dfaffb256b742c546f0695b3088209315ccf650` |

The old 22-path unsigned `yum/infra` condition is now historical, not a current
blocker. The Goal remains active only for scope that needs external execution:

- dedicated, registry-reviewed and unmistakably non-production R2/COS,
  Cloudflare and EdgeOne resources, credentials, verifier deployment, cache,
  purge and provider-log evidence;
- inactive builder/gated handoff and production repository-key injection;
- production Nginx/consumer/dual-cloud cutover, writer/IAM revocation,
  rollback, post-cutover URL checks and operational metrics.

Cloudflare bucket `pro`, `pro.pigsty.io`, and all Pigsty production resources
were neither probed nor used because the production-resource prohibition takes
precedence over their availability for testing.

## 2026-07-17 post-EL7 and builder-handoff delivery identity

This section supersedes the prior delivery identity. After the digest-pinned
CentOS 7 YUM 3.4.3 compatibility path, deterministic legacy-compatible YUM
metadata signing, complete apt 1.2/2.4 + EL7/8/9/10 client rerun, and
digest-bound external builder admission for asset/DEB/RPM, two independent
clean reconstructions produced byte-identical archives:

```text
PRODUCT_SOURCE_SHA256=b80311082c2646ff189e99f0db38e5a6363dbcf386be0ff2dbb87f3af1a9bd08
PRODUCT_SOURCE_FILES=524
DELIVERY_CONTENT_SHA256=e851d0cc9643a4aba011baab2cef0928d284e29bd01b735fa4ed3351af04122d
DELIVERY_FILES=651
ARCHIVE_SHA256=2b7fd812666343474b55bc563a53a377a54cd56962d300f65dd984887b720b89
```

Archives:

- `/tmp/sow-clean-delivery-20260717-handoff/sow-delivery-e851d0cc9643a4ab.tgz`
- `/tmp/sow-clean-delivery-20260717-handoff-b/sow-delivery-e851d0cc9643a4ab.tgz`

Both used fresh HOME/GOMODCACHE/GOCACHE trees and the read-only local Go
download cache as a `file://` proxy. `cmp -s` returned 0 and independent
`shasum -a 256` checks returned the archive digest above. The focused builder
ordinary/race tests passed in `4.237s`/`5.694s`; the complete local real-client
package including apt 1.2/2.4, EL7 YUM 3 and EL8/9/10 DNF passed in `131.021s`.
All real-cloud/edge/upstream switches were disabled and provider credentials
were cleared for the client run.

The local builder handoff mechanism is no longer a gap: every input can be
bound to `sha256:<digest>:<size>` and the real asset/DEB/RPM add paths have
positive and mismatch evidence. The remaining builder boundary is external:
the product/build owner must converge the historical `.io/.cc` same-key bodies
and preserve a real pipeline attestation with the SOW receipt/canonical commit.

The owner subsequently stated that a newly created Cloudflare bucket named
`pro` and `pro.pigsty.io` are intended for SOW testing, while reiterating that
production CO/CF repositories must never be used. No request has been made to
that resource yet: the compiled safety registry currently classifies those
production-shaped identifiers as forbidden, so their exact account/bucket/
zone identity and dedicated non-production status must be resolved without
weakening the permanent production-resource gate before any write-capable run.

## 2026-07-17 post-ROOT-COS handoff final local identity

This section supersedes every earlier delivery identity in this artifact. The
three unambiguous COS-only ROOT objects now have a pinned, read-only-source
handoff gate: `/cc`=`bin/get.cc`, `/claude`=`bin/claude` and
`/ray`=`bin/ray`, totaling 20,775 bytes. The test first checks the reviewed
source SHA-256/size constants, then runs the real CLI through init,
digest-bound add, promote, working-tree hardlink materialization, exact
default-deny Nginx rendering, L1, fsck, GC dry-run and idempotent replay. The
source identities/mtime/bodies remain unchanged and no cloud path is opened.
Focused ordinary/race packages passed in 5.196s/8.341s.

The current 663-test CLI surface passed the same six exhaustive shards used by
CI:

| Shard | Ordinary | Race |
|---|---:|---:|
| A-F | 343.016s | 404.286s |
| G-M | 483.048s | 701.343s |
| N-O | 168.334s | 162.320s |
| P-Q | 573.519s | 815.605s |
| R-V | 323.434s | 409.763s |
| W-Z/other | 67.125s | 75.636s |

All non-CLI race packages and non-CLI ordinary packages passed, as did vet,
the nested patched-RPM module, the seven migration scripts and the clean
delivery policy. A monolithic CLI package invocation exceeded Go's aggregate
10m and 20m package timers while the then-current tests themselves had run for
only 14s and 22s; the exhaustive CI-sharded runs above are the authoritative
result. The migration machine-map pin moved from `eb557046...` to
`41987f8c...` only after ROOT-02/03 replacement text recorded the new
COS-only evidence; target, family, disposition, command and rollback fields
remain unchanged, and the negative mutation suite passed.

Two final independent clean reconstructions used a fresh
HOME/GOMODCACHE/GOCACHE and the read-only local Go module download cache as a
`file://` proxy. They produced byte-identical archives:

```text
PRODUCT_SOURCE_SHA256=a4e1bc4b93a880d9503fdbf8063ee9a86af3065eba39496d7c2dd441e822cd91
PRODUCT_SOURCE_FILES=525
DELIVERY_CONTENT_SHA256=94de1c8ebf0105d2fb0a59dc5723c5aa547c50ed43443c0caf14f48d7683751c
DELIVERY_FILES=653
ARCHIVE_SHA256=422e9b6e9adbe3aa9ad224e246783b40008a6dd6cb4a89a176439a24ea028a93
```

Archives:

- `/tmp/sow-clean-delivery-20260717-root-cos-c/sow-delivery-94de1c8ebf0105d2.tgz`
- `/tmp/sow-clean-delivery-20260717-root-cos-d/sow-delivery-94de1c8ebf0105d2.tgz`

`cmp -s` returned 0 and independent `shasum -a 256` returned the archive
digest above for both files. The final `CGO_ENABLED=0 -trimpath` builds are:

| Target | Bytes | SHA-256 |
|---|---:|---|
| darwin/amd64 | 56,280,752 | `6099726fd203e527efc8c6084debea085676dfbacfbf5401039897a01f834b81` |
| darwin/arm64 | 53,440,370 | `0d1be06e4087792f9b42b6e8fe0cebf918aea04348a1a67651759777b13f1df4` |
| linux/amd64 | 54,476,572 | `c7a6f577d2bc39c1d2c0e345046cfeffbc605f4ab157c1eee644ee0d0389bb43` |
| linux/arm64 | 51,221,245 | `c8d10055ab6d5d81d152ff1521df63d26c7a14e8dd2e5426c93c8d628037a114` |

The Goal remains active. Shared `/get`, `/pig`, `/pkg` and `/beta` still need
one canonical builder-owned body and real attestation. Real Cloudflare/COS/
EdgeOne provider and CDN evidence still needs exact approved non-production
resource identities plus scoped credentials. Production migration, writer/IAM
revocation, URL rollback checks and operational metrics also remain external.
Cloudflare `pro`, `pro.pigsty.io`, CO/COS production resources and all
production repository trees were not contacted or written.

## 2026-07-17 post-ROOT-COS owner-activation identity

This section supersedes the preceding post-ROOT-COS delivery identity. After
the exact-copy gate passed, the physical Pigsty v1 migration fixture activated
only `asset-root-cos`; its affinity remains exactly `publish_targets: [cos]`.
The migration ledger binds `/cc`, `/claude` and `/ray` to the reviewed source
SHA-256 values and keeps production cutover pending. The shared
`asset-root-both` owner remains inactive, so `/get`, `/pig`, `/pkg` and `/beta`
cannot be admitted by this change.

All seven hermetic migration suites passed after activation, including their
negative mutation cases and the 44-family CLI/FS/provider-protocol E2E. The
focused ROOT read-only-source test passed again in ordinary/race mode in
3.330s/6.247s; it used only temporary SOW roots and did not open a cloud path.
`internal/config` passed ordinary/race in 0.410s/1.918s, and the clean-delivery
policy test passed in 1.758s.

Two new independent clean reconstructions used fresh
HOME/GOMODCACHE/GOCACHE trees and the read-only local Go module download cache
as a `file://` proxy. They produced byte-identical archives:

```text
PRODUCT_SOURCE_SHA256=38711ad23e1469e8959b30729c1758f56bfe29e2c8b4535f9c7fae2104e2911d
PRODUCT_SOURCE_FILES=525
DELIVERY_CONTENT_SHA256=a57617a57fd034ad20876ce925ff33357ca505989291a3767ab2d7a39be913e7
DELIVERY_FILES=653
ARCHIVE_SHA256=b0619aa3b6d174a3e94bbc46a741806af44a7198a2cf5b0e109131ef2a6bb1a0
```

Archives:

- `/tmp/sow-clean-delivery-20260717-root-cos-e/sow-delivery-a57617a57fd034ad.tgz`
- `/tmp/sow-clean-delivery-20260717-root-cos-f/sow-delivery-a57617a57fd034ad.tgz`

`cmp -s` returned 0 and independent `shasum -a 256` returned the archive
digest above for both files. The prior exhaustive ordinary/race shards,
real-client matrix, vet, nested module and four static-build results remain
applicable because this activation changed only the migration fixture, its
contract test and evidence text; the production Go implementation did not
change.

The Goal remains active. No Cloudflare resource was contacted. ADR-0032 now
admits only the inseparable owner-designated tuple `pro`,
`https://pro.pigsty.io`, and `https://beta.pro.pigsty.io` to offline review;
any subset, any variant, all
other Pigsty resources and every production repository remain rejected. The
compiled resource/deployment registries are still empty, so all network opt-ins
fail before credentials or requests. Exact account/R2 endpoint, zone ID,
beta DNS/routing, deployment identities and scoped credentials are still
required before read-only readiness.

## 2026-07-17 owner-designated Cloudflare safety identity

This section supersedes the preceding delivery identity. ADR-0032 and the
real-cloud process gate now recognize only the inseparable owner-designated
tuple `cf_r2_bucket=pro`, `cf_cdn_base=https://pro.pigsty.io`, and
`cf_beta_cdn_base=https://beta.pro.pigsty.io`. Any subset, spelling/path
variants, other Pigsty hosts, production markers, a changed zone, an unpinned
resource, or an empty registry all fail before credentials or requests. The
tuple is an acceptance transport and does not revive the standalone Pro-bucket
product design.

With all four network opt-ins explicitly set to `0`, the focused safety tests
passed ordinary/race in 1.065s/2.265s and the complete `RealCloud` family
passed in 9.941s/13.835s. `go vet ./...`, `git diff --check`, and the
clean-delivery policy also passed. No Cloudflare, CO, COS or public repository
request was made.

Two fresh HOME/GOMODCACHE/GOCACHE reconstructions used the read-only local Go
module download cache as a `file://` proxy and produced byte-identical
archives:

```text
PRODUCT_SOURCE_SHA256=b5618f4340ab16505b1d386abe82e9b7489bfd3230e89fbe392ac7c7431bc18a
PRODUCT_SOURCE_FILES=525
DELIVERY_CONTENT_SHA256=064db53d8d2efe0470d437963113849561364633471fc08503e0d1627849d3d8
DELIVERY_FILES=654
ARCHIVE_SHA256=316781d26de91bc3e3ee98a83d9c4d2bee36d11bda5348fb9d226f92ff9fae1c
```

Archives:

- `/tmp/sow-clean-delivery-20260717-cf-owner-g/sow-delivery-064db53d8d2efe04.tgz`
- `/tmp/sow-clean-delivery-20260717-cf-owner-h/sow-delivery-064db53d8d2efe04.tgz`

`cmp -s` returned 0 and independent `shasum -a 256` returned the archive
digest above for both files. The compiled resource and provider-deployment
registries remain canonical empty sets. The next Cloudflare-only read-only
gate therefore needs the exact R2 account endpoint/account ID, zone ID,
DNS/routing for `beta.pro.pigsty.io`, and bucket-list/zone-read
scoped credentials. No write-capable run is authorized at this point.

## 2026-07-17 shared-zone owner tuple identity

This section supersedes the preceding Cloudflare safety identity. The prior
pair was insufficient because provider readiness also requires a distinct beta
host in the same attested zone. The current contract therefore freezes the
reversible pre-deployment tuple to bucket `pro`, main
`https://pro.pigsty.io`, beta `https://beta.pro.pigsty.io`, and canonical
shared zone name `pigsty.io`. The shared-zone exception is entered only for the
exact tuple; every subset, URL variant, other host, other zone, registry miss,
or deployment drift fails before credentials or requests.

With all network opt-ins explicitly `0`, focused ordinary/race tests passed in
1.298s/1.881s and the complete `RealCloud` family passed in
9.498s/13.478s. `go vet ./...`, `git diff --check`, and the clean-delivery
policy passed. No cloud or public-repository request was made.

Two independent clean reconstructions produced byte-identical archives:

```text
PRODUCT_SOURCE_SHA256=8c707b7efff49b0b7f624c3b3e544fdf984bce481d9022991bf49119014ed25b
PRODUCT_SOURCE_FILES=525
DELIVERY_CONTENT_SHA256=390516204d0687acadf58147d524140284e26d692bb07b83ea9401deecf21eab
DELIVERY_FILES=654
ARCHIVE_SHA256=c4f9f6e0ab1121bc3e480572d4248c2c4d19d04092490646cc66b15c8132bc09
```

Archives:

- `/tmp/sow-clean-delivery-20260717-cf-shared-zone-i/sow-delivery-390516204d0687ac.tgz`
- `/tmp/sow-clean-delivery-20260717-cf-shared-zone-j/sow-delivery-390516204d0687ac.tgz`

`cmp -s` returned 0 and independent SHA-256 checks matched. The compiled
registries remain empty. Read-only readiness still requires exact account/R2
endpoint, zone ID, beta DNS/routing, reviewed deployment identity, a
bucket-list-only R2 credential and a zone-read-only Cloudflare token. No write
credential or mutation is authorized yet.

## 2026-07-17 shared-zone route and Logpush closure identity

This section supersedes the preceding shared-zone archive identity. The
provider collector now audits the complete shared-zone Worker route and
Logpush inventories while binding only the SOW-relevant closure. Unrelated
routes and jobs may coexist only when they provably cannot match the reviewed
main/beta hosts; an unrelated enabled job also cannot write the SOW raw-log
bucket. Unknown route/filter forms fail closed.

The focused ordinary/race tests passed in 1.338s/2.307s and the complete
offline `RealCloud` family passed in 7.549s/11.065s with all four network
opt-ins explicitly disabled. `go vet ./...`, `git diff --check`, and the
clean-delivery policy passed. No credential was loaded and no cloud or public
repository request was made.

Two independent clean reconstructions produced byte-identical archives:

```text
PRODUCT_SOURCE_SHA256=bc0b06c46585a16bb6809928cb50c2f412ed7234e22e9c1c908331ddd09f441c
PRODUCT_SOURCE_FILES=525
DELIVERY_CONTENT_SHA256=1deaf0ded10a85acc8904ffdfe8ceda9f69f2537f8e8c346156357072ca1cb78
DELIVERY_FILES=654
ARCHIVE_SHA256=97149d2cd032abf74d1f1d8889ef64741897db5d076beaa7299e9e30415a1279
```

Archives:

- `/tmp/sow-clean-delivery-20260717-cf-shared-zone-k/sow-delivery-1deaf0ded10a85ac.tgz`
- `/tmp/sow-clean-delivery-20260717-cf-shared-zone-l/sow-delivery-1deaf0ded10a85ac.tgz`

`cmp -s` returned 0 and independent SHA-256 checks matched. Both compiled
registries remain empty, so every network-capable opt-in still fails before
credential decoding, client construction, or requests. Cloudflare read-only
readiness remains the next external gate and still requires the exact account,
endpoint, zone, beta routing, deployment identities, and scoped read-only
credentials.

## 2026-07-17 canonical ROOT and Cloudflare read-only inventory identity

This section supersedes the preceding archive identity. The shared ROOT
handoff now pins the eight legacy `.io`/`.cc` sources and deterministically
builds the canonical `/get`, `/pig`, `/pkg`, and `/beta` bodies. Its ordinary
and race E2E tests passed, the physical migration owner is active for exactly
`[cf,cos]`, and all seven migration suites passed after the machine-map digest
was frozen. Source bytes, inode/mtime observations, and production repository
content remained unchanged; all SOW mutations occurred in temporary copies.

The owner-designated Cloudflare surface was then inspected read-only. The
authenticated dashboard showed account handle `PGSTY`, account ID
`72cdbd1b54f7add44ecbd3d986399481`, bucket `pro`, public access enabled,
reported size `0 B`, and no objects. A public HTTPS GET to
`https://pro.pigsty.io/` returned a TLS-verified Cloudflare 404 with no
redirect; `beta.pro.pigsty.io` did not resolve. No upload, delete, purge,
deployment, DNS edit, secret view, API credential, CO/COS resource, or
production repository was used. These facts are inventory only, not a signed
S3 readiness receipt or POC-06 pass.

Shell syntax, `internal/config` ordinary/race, `go vet ./...`,
`git diff --check`, and the clean-delivery policy all passed. The first fresh
clean-delivery attempt reached the default `proxy.golang.org` but failed only
because every module download timed out. Connectivity probing showed
`goproxy.cn` serving the pinned module zip while the default proxy remained
unreachable. Two subsequent independent fresh HOME/GOMODCACHE/GOCACHE runs
used `SOW_CLEAN_GOPROXY=https://goproxy.cn,direct`; both completed tidy-diff,
download, sum verification, tests, build, CLI smoke checks, extraction audits,
and produced byte-identical archives:

```text
PRODUCT_SOURCE_SHA256=03831b1a20113ee61c16845b4e67222823a03513f85f4210f56835ebd5bb3fb0
PRODUCT_SOURCE_FILES=526
DELIVERY_CONTENT_SHA256=af26930f5cdf945b6929d26bc0547868dd7690d4c722190e45938f1203cff47d
DELIVERY_FILES=659
ARCHIVE_SHA256=c1f0f2816097160a72e98b7971f18b1d2ab6f933a12c17e36786815d643256c9
```

Archives:

- `/tmp/sow-clean-delivery-20260717-cf-readonly-final-o/sow-delivery-af26930f5cdf945b.tgz`
- `/tmp/sow-clean-delivery-20260717-cf-readonly-final-p/sow-delivery-af26930f5cdf945b.tgz`

`cmp` returned 0 and independent `shasum -a 256` returned the archive digest
above for both files.

The Goal remains active. Both compiled real-cloud registries remain empty.
Cloudflare signed readiness still needs the exact zone ID, verified account R2
endpoint, bucket-list-only R2 credential, zone-read-only Cloudflare token,
beta DNS/routing, and reviewed deployment identity. A write-capable POC also
needs narrowly scoped write/purge credentials and the attested Worker/origin/
verifier/Logpush deployment. COS/EdgeOne still requires entirely separate,
explicitly non-production resources; no production resource can satisfy that
gap.

## 2026-07-17 provider-scoped readiness registry identity

This section supersedes the preceding clean-delivery identity. A safety audit
found that the nominally provider-scoped readiness process gate still required
the complete dual-cloud resource and provider-deployment registries. That made
the Cloudflare read-only preflight circular and unnecessarily dependent on
unrelated COS/EdgeOne resources and later Worker/Logpush identities.

ADR-0033 now gives readiness its own canonical, compiled-SHA-pinned registry.
Each entry contains exactly one provider's non-secret endpoint, bucket,
zone/name and main/beta identity. `TestMain` validates the selected entry and
fixed non-production confirmation before credential decoding or client
construction. The actual readiness operation remains limited to signed empty
bucket listing and read-only control-plane identity queries. Cloudflare now
also lists the exact R2 bucket custom-domain inventory and requires precisely
the enabled, ownership-active, SSL-active pinned main+beta bindings; a missing
beta, extra host or zone drift cannot produce a receipt. The destructive
and evidence paths still require the original full dual-cloud and deployment
registries; upload, delete, deployment, purge, logging and cache evidence were
not authorized or exercised. EdgeOne's read-only collector now also rejects a
live zone name that differs from the pinned identity.

With all four network opt-ins and both onboarding opt-ins explicitly set to
`0`, the final focused provider-readiness/process-gate/custom-domain ordinary
and race tests passed in 2.069s/1.960s. The complete offline `RealCloud` family
passed in 9.050s/12.296s. `go vet ./...`, `git diff --check`, and
`TestRepositoryPolicyClosure` also passed. No credential was loaded, no real
provider client was constructed, and no cloud, DNS, public repository or
production resource request was made by these runs.

Two independent fresh HOME/GOMODCACHE/GOCACHE reconstructions used the pinned
module graph through `SOW_CLEAN_GOPROXY=https://goproxy.cn,direct`; both passed
the clean-delivery audits and produced byte-identical archives:

```text
PRODUCT_SOURCE_SHA256=7830a7f79fcb4b88d2af3e4f8421989419c2a09f55fc7f8e82b33308087b3101
PRODUCT_SOURCE_FILES=528
DELIVERY_CONTENT_SHA256=533d7d3d9b23d8a8ab945a54b367bf4f0c85cfe945bc2798c9c00cb44f7c9b44
DELIVERY_FILES=662
ARCHIVE_SHA256=af5c99c5eabfc0ea1dceb63138ec87f7a68b567d8c8942c0a78b55ab5573d4ae
```

Archives:

- `/tmp/sow-clean-delivery-20260717-provider-domains-s/sow-delivery-533d7d3d9b23d8a8.tgz`
- `/tmp/sow-clean-delivery-20260717-provider-domains-t/sow-delivery-533d7d3d9b23d8a8.tgz`

`cmp` returned 0 and independent SHA-256 checks returned the archive digest
above for both files.

The Goal remains active. All three compiled real-cloud registries remain
empty, so every applicable opt-in still fails before network access.
Cloudflare signed readiness now needs only the exact zone ID, an enabled and
ownership/SSL-active frozen beta R2 custom domain, an independently reviewed
readiness entry, a credential scoped to list the `pro` bucket and a token
scoped to read the exact account's R2 configuration plus the exact zone. The
complete POC additionally needs isolated Worker/origin/verifier/Logpush
deployments, mutation/purge credentials and evidence resources. COS/EdgeOne
remains a separate non-production task. CO/COS/Cloudflare production
repositories and resources remain permanently forbidden test targets.

## 2026-07-17 provider attestation v2 and log-sink lease

This section supersedes the preceding clean-delivery identity. ADR-0035 and
the provider attestation v2 contract now bind each Cloudflare auth, origin and
token-verifier Worker to its exact compatibility date/flags and twice observe
active runtime, settings, schedules, exposure and the complete account
Worker/route/custom-domain inventory. Cloudflare R2 readiness also requires
an explicit TLS 1.2/1.3 minimum and the frozen six-suite Modern TLS 1.2 set.
Provider-log setup now acquires and renews an R2 conditional lease with a
separate log-control identity; successful dual-provider closure releases the
exact ETag, while a partial EdgeOne failure retains the lease for bounded CAS
recovery. Cloudflare Logpush selection uses the configured exact job ID and
audits every other enabled job for reviewed-host/raw-bucket overlap.

With every real-cloud/upstream opt-in explicitly set to `0` and all provider
credentials empty, the complete compatibility package passed ordinary/race in
11.077s/15.640s. The focused official-SDK/fake-store provider tests, Go vet,
module checks and clean-delivery policy also passed. No cloud credential was
loaded and no Cloudflare, R2, COS, EdgeOne or production repository request
was made.

Two independent fresh HOME/GOMODCACHE/GOCACHE reconstructions used the local
read-only Go module download cache through
`SOW_CLEAN_GOPROXY=file:///Users/vonng/go/pkg/mod/cache/download`. Both passed
tidy-diff, dependency download/verification, tests, static builds, CLI smoke,
secret/link/extraction audits and produced byte-identical archives:

```text
PRODUCT_SOURCE_SHA256=248b04bfc6a58437b2d952af01c3cc059d0a2d84a063520767a1209a607b559f
PRODUCT_SOURCE_FILES=531
DELIVERY_CONTENT_SHA256=5082d7251a6b59f8407fa316c9632dd2bcdb355816e4548568cde259a5aa19d3
DELIVERY_FILES=669
ARCHIVE_SHA256=f3777ee17abe9b46221ea06a6261f2e058f2ef98f56e610031288841424cbf5a
```

Archives:

- `/tmp/sow-clean-delivery-provider-attestation-final-a-20260717/sow-delivery-5082d7251a6b59f8.tgz`
- `/tmp/sow-clean-delivery-provider-attestation-final-b-20260717/sow-delivery-5082d7251a6b59f8.tgz`

`cmp` returned 0 and independent `shasum -a 256` returned the archive digest
above for both files.

The Goal remains active. All compiled real-cloud registries remain empty and
POC-06 has no live provider evidence. Cloudflare still needs an independently
reviewed resource/bootstrap/provider-deployment admission, active beta custom
domain with the frozen TLS policy, isolated least-privilege identities and an
authorized non-production run. COS/EdgeOne remains an independent
non-production task. Production repositories and resources remain forbidden
test targets.

## 2026-07-17 provider attestation v3 immutable EdgeOne log area

This section supersedes the preceding clean-delivery identity. The provider
attestation config, raw attestation and deployment identity are now v3. They
pin the EdgeOne realtime-log task's immutable `Area` to exactly `mainland` or
`overseas` and bind that observed value into the deployment, task, raw
attestation and durable acceptance-ledger digests. Missing, unknown and live
task mismatches fail closed. This preserves the current official EdgeOne
`l7-access-logs` contract while preventing a task created for the wrong area
from silently omitting acceptance traffic.

With an `env -i` environment retaining only HOME/PATH/TMPDIR/LANG and setting
every real-cloud, real-edge, real-upstream, Docker and legacy-APT opt-in to
`0`, the complete compatibility package passed ordinary/race in
10.548s/14.994s. The current focused provider ordinary/race set passed in
3.225s/6.403s. `go mod verify`, `go mod tidy -diff`, `go vet ./...`,
`TestRepositoryPolicyClosure`, allowlist sorting and `git diff --check` also
passed. No provider credential was present or loaded and no cloud or
production-repository request was made.

Two independent fresh HOME/GOMODCACHE/GOCACHE reconstructions used only the
local read-only module download cache through
`SOW_CLEAN_GOPROXY=file:///Users/vonng/go/pkg/mod/cache/download`. Both passed
the complete clean-delivery gate and produced byte-identical archives:

```text
PRODUCT_SOURCE_SHA256=70adc52de9be13187a03ffa90ec220a2213863dd207b1a495ea9ff9c7b80f4c7
PRODUCT_SOURCE_FILES=531
DELIVERY_CONTENT_SHA256=1c42b4973a9b398b963177bec773445e812b978a44006d7c586ad44be0c474ad
DELIVERY_FILES=669
ARCHIVE_SHA256=5d0b9b15ab4ba217611ad9221e07d6453ff0b09462adbcb2acc65af5eeffbfb2
```

Archives:

- `/tmp/sow-clean-delivery-provider-attestation-v3-a-20260717/sow-delivery-1c42b4973a9b398b.tgz`
- `/tmp/sow-clean-delivery-provider-attestation-v3-b-20260717/sow-delivery-1c42b4973a9b398b.tgz`

`cmp` returned 0 and independent `shasum -a 256` returned the archive digest
above for both files.

The Goal remains active. All compiled real-cloud registries remain empty and
POC-06 still has no live provider evidence. The owner-designated Cloudflare
`pro` bucket/host remains eligible only after exact registry review and scoped
credentials; no write is authorized merely by documenting the resource.
COS/EdgeOne remains an independent non-production task, and all CO/COS/
Cloudflare production repositories remain forbidden test targets.

## 2026-07-17 post-probe final delivery identity

This section supersedes only the preceding clean-delivery identity. A current
read-only public revalidation of `pro.pigsty.io` and the still-missing
`beta.pro.pigsty.io` DNS was added to the evidence set; no cloud mutation was
performed. Two fresh, parallel isolated reconstructions again used only the
local read-only module download cache and produced byte-identical archives:

```text
PRODUCT_SOURCE_SHA256=70adc52de9be13187a03ffa90ec220a2213863dd207b1a495ea9ff9c7b80f4c7
PRODUCT_SOURCE_FILES=531
DELIVERY_CONTENT_SHA256=d0ab4b4ab1d61129e43c8e5191b301805bb4e84e55c0b6b463380f297f9c2100
DELIVERY_FILES=669
ARCHIVE_SHA256=6ba3e565883088bd41ffbc41701f3974e2ff9423820e0e62157573482d60e750
```

Archives:

- `/tmp/sow-clean-delivery-provider-attestation-v3-probe-a-20260717/sow-delivery-d0ab4b4ab1d61129.tgz`
- `/tmp/sow-clean-delivery-provider-attestation-v3-probe-b-20260717/sow-delivery-d0ab4b4ab1d61129.tgz`

`cmp` returned 0 and independent `shasum -a 256` returned the archive digest
above for both files. The Goal and external blockers are unchanged.

## 2026-07-18 post-review lock and Cloudflare bootstrap closure

This section supersedes the preceding clean-delivery identity. The independent
review found two patch-level defects and no specification gap:

- successful top-level commands could print a state-lock release warning and
  still return exit 0 even though the durable lock record was not removed;
- an object or Cloudflare provider-control change could occur after the fresh
  empty-bucket readiness observation but before first-deployment mutation.

All state-lock-owning CLI paths now feed `Release` through one result
propagator. A release failure changes an otherwise successful command to
`ExitInternal`; an existing primary error and exit class are preserved while
the release failure remains visible as a warning. A concrete state test removes
the held durable record and proves `Lock.Release` reports the failure without
stranding the advisory lease.

Cloudflare bootstrap lease admission now consumes every bounded
`ListObjectsV2` page and permits exactly one object: the current lease key with
its exact size and ETag. An immediate GET must match the canonical lease bytes
and ETag. The same bucket closure is repeated after every pre-mutation renewal.
At initial admission and every mutation boundary, the exact zone plus active
main/beta R2 custom-domain/TLS digest is also re-read and compared with the
fresh readiness receipt. Foreign/missing/replaced lease objects, pagination
cycles and provider-control drift all fail before the inner Worker/route
mutation call.

Focused ordinary verification passed:

```text
internal/state 0.795s
internal/cli   1.221s
test/compat    1.362s
```

The same focused set under `-race` passed in 2.584s/2.280s/2.409s. The complete
offline compatibility package passed ordinary/race in 9.817s/13.973s. All
real-cloud, real-edge, real-upstream and Docker opt-ins were absent; no provider
credential was loaded and no Cloudflare, R2, CO, COS, EdgeOne or production
repository request was made. `go mod verify`, `go mod tidy -diff`, `go vet
./...`, an all-package compile-only test and `git diff --check` passed.

The first isolated clean-delivery attempt failed only while downloading from
`proxy.golang.org` into a deliberately empty module cache (connection timeout,
before any source audit/build assertion failed). Two subsequent independent
empty HOME/GOMODCACHE/GOCACHE runs used the read-only public module mirror
`https://goproxy.cn,direct`; both passed tidy-diff, download/verify, tests,
static build, CLI smoke, allowlist/content/link/extraction audits and produced
byte-identical archives:

```text
PRODUCT_SOURCE_SHA256=d8e00198162dbbcd1f572784d0628f08cdfd50a7b997c4355d6f5aaf803787e5
PRODUCT_SOURCE_FILES=532
DELIVERY_CONTENT_SHA256=e370b47628d57b47cfde781e5f4f4902029edc99afb4da63181060ef451c19f2
DELIVERY_FILES=670
ARCHIVE_SHA256=1a2280e2637253a7d57f4021988ab3f2d42774339b49641cbd1297899c3ff4cc
```

Archives:

- `/tmp/sow-clean-delivery-post-audit-a2-20260718/sow-delivery-e370b47628d57b47.tgz`
- `/tmp/sow-clean-delivery-post-audit-b2-20260718/sow-delivery-e370b47628d57b47.tgz`

`cmp` returned 0 and independent `shasum -a 256` returned the archive digest
above for both files. The Goal remains active: these patches close local
review findings but do not create signed Cloudflare readiness or live POC-06
evidence. CO/COS/Cloudflare production repositories remain forbidden test
targets.

At `2026-07-18T04:46:47Z`, an unauthenticated read-only DNS/HEAD recheck found
`pro.pigsty.io` on Cloudflare returning HTTP 404 with `cf-cache-status:
DYNAMIC`; `beta.pro.pigsty.io` still had no resolvable DNS record. No bucket API
or mutation was invoked.

## 2026-07-18 owner-authorized Cloudflare `pro` readiness closure

The owner explicitly authorized unrestricted testing inside the empty
Cloudflare R2 `pro` bucket and its test domains while preserving one hard
boundary: no CO/COS/Cloudflare production repository may be written or used as
a test target. Within that exact boundary, the live dashboard was changed only
to connect `beta.pro.pigsty.io` to bucket `pro` and raise the existing
`pro.pigsty.io` minimum TLS from 1.0 to 1.2.

The post-change dashboard reported the exact closure:

```text
pro.pigsty.io       min_tls=1.2 status=active access=enabled
beta.pro.pigsty.io  min_tls=1.2 status=active access=enabled
```

The exact zone ID is `da7b5a27e4f9ef6eaa1b00a89c2c77c2`. Cloudflare's
authoritative nameserver, 1.1.1.1 and 8.8.8.8 returned the same three anycast A
records for beta. Both hosts returned the expected empty-bucket Cloudflare 404.
OpenSSL 3.6.3 with legacy protocols explicitly enabled received remote protocol
version alerts for TLS 1.0/1.1 and completed verified TLS 1.2/1.3 handshakes for
both hosts.

An existing local `rclone` R2 credential was used only against `cf:pro`:

```text
rclone lsf cf:pro --max-depth 1  # empty
rclone size cf:pro --json
{"count":0,"bytes":0,"sizeless":0}
```

No credential was printed or persisted. The same credential, injected only in
the child process environment, let `TestRealCloudProviderScopedReadiness`
complete the product's Go SigV4 empty-bucket List. With a deliberately invalid
non-secret API token, the next exact-zone query failed as expected. This proves
the real storage leg but does not create or claim a readiness receipt.

The offline provider-readiness onboarding candidate passed with:

```text
resource_sha256=0af5c47472a59b2c677889d8f2039d469d88ce05f3642b43d54389405aa78a2d
registry_sha256=ed06605a86cb84ece865a6ea2eb7280d3094392d144a5841ac257268bc8f3f63
```

The pinned registry now contains exactly this one Cloudflare tuple. Focused
ordinary and race registry/resource/selection tests passed (`0.363s` and
`4.519s` package time). Destructive/full-POC, provider-deployment and bootstrap
registries remain closed.

The remaining exact blocker for the signed Cloudflare readiness receipt is a
bearer token with exact-account Workers R2 Storage Read and exact-zone Zone
Read. No such token was found in the process environment or documented local
token file. Full POC-06 retains its separate Worker/origin/verifier, purge,
provider-log, entitlement, independent-observer and EdgeOne/COS requirements.
No object, purge, Worker, route, other bucket/domain or production repository
was touched.

## 2026-07-18 post-adoption adversarial-review delivery identity

This section supersedes only the preceding clean-delivery identity. Blind and
edge review of legacy content adoption found partial-selector, two-pass index,
metadata inode-continuity, final serving-tree, provenance-anchor, exit-class,
redundant-cache, large negative-report and 50k evidence weaknesses. The current
implementation closes those local findings with scoped view/receipt union,
candidate-set equality, descriptor/path continuity, a final baseline rescan,
ancestor/time/manifest receipt validation, preserved coded exits, one canonical
cache projection path, SQLite-backed exact blocker reports with bounded inline
previews, and tuple/provenance/CAS/RSS scale assertions.

The complete `internal/cli` and `internal/upstream` ordinary packages passed in
1151.730s and 3.111s. Focused adoption/local/open-index race packages passed in
126.698s and 2.391s. `go vet ./...`, perf-tag compilation and
`git diff --check` passed. The exact 50,000-unique-asset test passed in
1032.35s: first/replay were 9m30s/7m21s, import peak was 8/8, all
payload/CAS/view/receipt/cache/provenance counts were 50,000, four streamed
tuple closures had SHA-256
`845e39df9500dcb804c7c21f89336fd534591b5aabaa15a7bfc214e1d02ca45a`,
all CAS objects were verified, sampled peak/retained heap growth was
124,347,360/538,040 bytes, OS max-RSS growth was 167,116,800 bytes, and the
serving manifest plus replay HEAD were unchanged.

Two independent fresh HOME/GOMODCACHE/GOCACHE reconstructions used only the
local read-only module download cache through
`SOW_CLEAN_GOPROXY=file:///Users/vonng/go/pkg/mod/cache/download`. Both passed
the complete clean-delivery gate and produced byte-identical archives:

```text
PRODUCT_SOURCE_SHA256=6e49b38198d472d7e1dbd2f077fe54ba4d488603696c67718acd5940fa5a7a63
PRODUCT_SOURCE_FILES=534
DELIVERY_CONTENT_SHA256=da51ec8a466b14fb5ee3c51ffb6cc3ce991d8b86f04f57c42f8be2156337d73d
DELIVERY_FILES=677
ARCHIVE_SHA256=e127faea5936fa0330863a77e0d9869fc9f5526286017f775542ec71d7c08e39
```

Archives:

- `/tmp/sow-clean-delivery-adoption-review-final-a-20260718/sow-delivery-da51ec8a466b14fb.tgz`
- `/tmp/sow-clean-delivery-adoption-review-final-b-20260718/sow-delivery-da51ec8a466b14fb.tgz`

`cmp` returned 0 and independent `shasum -a 256` returned the archive digest
above for both files. All tests in this closure were local-only. No credential
was loaded, no cloud API was called and no production or owner-designated test
bucket was read or written. The long-term Goal remains active because the
separate signed Cloudflare readiness/full POC-06, COS/EdgeOne and production
migration evidence is still incomplete.

## 2026-07-19 provenance-complete adoption delivery identity

This section supersedes the preceding post-adoption identity. The remaining
review gate required a fresh 50,000-item run after the canonical receipt and
SQLite cache provenance projections were changed from count-only evidence to
the exact ordered nine-field closure. The run also exercised the production
fixes that batch adoption projection writes in one SQLite transaction and avoid
throwaway CAS staging-file `fsync` on a verified idempotent replay.

The fixed command passed in 1156.07s. First adoption/replay were
12m09.369555208s/6m12.054509708s; payload, CAS, view, receipt, cache manifest
and cache provenance counts were all exactly 50,000. The four
`path/size/SHA256/pool` closures shared SHA-256
`845e39df9500dcb804c7c21f89336fd534591b5aabaa15a7bfc214e1d02ca45a`.
Canonical receipt and SQLite provenance streams shared SHA-256
`1577eccd1c6febec1c4f0e4ad18357a4c20580ba51d12dee92c844ed9271ce57`.
Import peak was 8/8; sampled peak/retained heap growth was
125,097,504/553,888 bytes; OS max-RSS growth was 138,985,472 bytes. All 50,000
CAS objects verified, the serving manifest was unchanged, and replay did not
advance HEAD.

The complete current packages then passed with `internal/cli` 1720.604s,
`internal/upstream` 3.817s, `internal/catalog` 5.070s and
`internal/repository` 5.994s. Focused adoption/CAS race tests, `go vet ./...`,
perf-tag vet/compile, `go mod tidy -diff`, `go mod verify` and
`git diff --check` passed.

After removing digest-bearing claims from delivery content, two final fresh
HOME/GOMODCACHE/GOCACHE reconstructions used only
`SOW_CLEAN_GOPROXY=file:///Users/vonng/go/pkg/mod/cache/download`. Both passed:

```text
PRODUCT_SOURCE_SHA256=86c345cf0020d3c69dca856000ac3fdbb52004aec86ed80aa3234e2a1f74fee5
PRODUCT_SOURCE_FILES=534
DELIVERY_CONTENT_SHA256=80bfc4a285ad0eefc2a555519339c3068db92f68eec267e08616c4cf59a2c097
DELIVERY_FILES=677
ARCHIVE_SHA256=7ed06913e8a5772fc04c8f909b58a178505188851d25e7b88c6bd742ef537aad
```

Archives:

- `/tmp/sow-clean-delivery-adoption-v3-a-20260719/sow-delivery-80bfc4a285ad0eef.tgz`
- `/tmp/sow-clean-delivery-adoption-v3-b-20260719/sow-delivery-80bfc4a285ad0eef.tgz`

Independent `cmp` returned 0 and `shasum -a 256` returned the archive digest
above for both files. This closes the legacy-adoption spec review, not the
long-term product Goal. Every operation in this closure used local temporary
directories; no credential or cloud API was used, and no production or
owner-designated test bucket was read or written.

## 2026-07-19 descriptor-teardown current delivery identity

This section supersedes the preceding provenance-complete adoption identity.
The current source additionally fails closed on retained materialization
descriptors, final parent-cache/root-binding closure, nested bound-Git parent
closure, APT/YUM package-body input and spool closure, and streaming YUM history
storage closure. Primary business-error identity and go-git's required
`os.IsNotExist` classification are preserved when teardown itself succeeds.

The complete current validation set passed before the delivery freeze: all 678
default CLI tests through six ordinary and six race shards, every non-CLI
package ordinary/race, real loopback apt 1.2/2.4, YUM 3 and EL8/9/10 DNF via
Nginx, four static Linux/macOS builds, both module integrity gates, vet,
Staticcheck, edge rebuild plus 41/41 contracts, and both fixed-version
govulncheck runs. The owner-designated non-production `cf:pro` R2 storage
protocol run also passed and left the bucket empty; it does not stand in for
Worker/CDN, COS, EdgeOne or full POC-06 evidence.

After the delivery-content documentation was frozen, two independent fresh
HOME/GOMODCACHE/GOCACHE reconstructions used only the local read-only module
download cache through
`SOW_CLEAN_GOPROXY=file:///Users/vonng/go/pkg/mod/cache/download`. Both passed
`go mod tidy -diff`, dependency download and verification, clean-delivery and
configuration tests, binary build/CLI smoke tests, extracted-manifest and link
audits, secret/path policy, and deterministic archive reconstruction. Their
outputs were identical:

```text
PRODUCT_SOURCE_SHA256=8d3662d88a5f0c4eb0227740eb5b898e48148dea2b6e8d73c227403595bba580
PRODUCT_SOURCE_FILES=535
DELIVERY_CONTENT_SHA256=2e9c8b4b3858675df988e7dc2499147125f65033675ae3bb8a00ef011d635404
DELIVERY_FILES=679
ARCHIVE_SHA256=d87110003999394efb7965525649ad9a5a54a9925f382dd9acb8bdca62e2ec23
```

Archives:

- `/tmp/sow-clean-delivery-teardown-final-a-20260719/sow-delivery-2e9c8b4b3858675d.tgz`
- `/tmp/sow-clean-delivery-teardown-final-b-20260719/sow-delivery-2e9c8b4b3858675d.tgz`

Independent `cmp` returned 0 and `shasum -a 256` returned the archive digest
above for both files. These current-source and non-production storage results
close the descriptor-teardown delivery review, not the long-term product Goal.
No production repository, `cos:` remote, production Cloudflare resource or
production control plane was read for testing or written. The remaining real
Worker/CDN, COS/EdgeOne, production migration/revocation and operational metric
evidence remains explicitly open.

## 2026-07-19 V-14 ledger-consistent delivery identity

This section supersedes the immediately preceding descriptor-teardown identity.
The product source is unchanged; the delivery identity changed only because the
traceability conclusion was corrected from “V-14 remains to be completed” to
“V-14 is closed by the external dual reconstruction”. No digest-bearing value
was placed inside the delivery root.

Two new independent fresh HOME/GOMODCACHE/GOCACHE reconstructions passed the
same complete gate and produced byte-identical archives:

```text
PRODUCT_SOURCE_SHA256=8d3662d88a5f0c4eb0227740eb5b898e48148dea2b6e8d73c227403595bba580
PRODUCT_SOURCE_FILES=535
DELIVERY_CONTENT_SHA256=83cd2984ed3fa67ee682333fb7c59c83c806d74c4f919347af4c91183a132be9
DELIVERY_FILES=679
ARCHIVE_SHA256=3206269b7e6af73fc199647ead04c50b130f043be2b14f9a83b8123c5f976e2f
```

Archives:

- `/tmp/sow-clean-delivery-teardown-final-v2-a-20260719/sow-delivery-83cd2984ed3fa67e.tgz`
- `/tmp/sow-clean-delivery-teardown-final-v2-b-20260719/sow-delivery-83cd2984ed3fa67e.tgz`

Independent `cmp` returned 0 and `shasum -a 256` returned the archive digest
above for both files. This is the current V-14 identity. It does not change the
open real-cloud, production-migration or operational-evidence boundary, and no
production resource was accessed or mutated.

## 2026-07-19 V-21 raw custom-domain current delivery identity

This section supersedes the preceding V-14 ledger-consistent identity. The
product source now adds an exact-registry, exact run-owned anonymous Cloudflare
R2 main/beta custom-domain gate to the real storage protocol. Current-object
responses must match the R2 CAS winner's body, length and ETag without redirect,
credentials, cookies or Worker headers. After storage deletion, the gate accepts
only 404 or an exact run-owned stale response with bounded canonical Age and
max-age; foreign bytes, an unpinned host, unbounded cache lifetime and a current
shared-cache HIT fail closed before being reported as evidence.

The final real non-production run `sow-r2-domain-20260719-04` passed in
31.19s (package 31.708s). Main and beta both observed the current object as
`CURRENT-MISS/FRA`; after the bucket object was identity-bound deleted, both
observed the exact run-owned object as `STALE-HIT/FRA/max-age=1800`. The latter
is recorded as provider negative-capability evidence that purge is mandatory,
not as purge or CDN negative verification. Independent `rclone lsf cf:pro`
proved the bucket empty. No control-plane token, Worker, purge API, `cos:` or
production resource was accessed.

The new custom-domain contract passed focused ordinary/race, full compat
ordinary/race and `go vet ./test/compat`; full vet, the pinned Staticcheck
profile, both module integrity gates, clean-delivery policy and `git diff
--check` also passed. Two independent final HOME/GOMODCACHE/GOCACHE
reconstructions used only the local read-only module download cache and
produced byte-identical archives:

```text
PRODUCT_SOURCE_SHA256=6d59edf0d9b590fc38796ea544f0099a318088c0b5300203dd7f003805f8aa51
PRODUCT_SOURCE_FILES=535
DELIVERY_CONTENT_SHA256=61e0e61fcddf5c3e161ff859225046560fed3f2f0d225cc036258432c562cf40
DELIVERY_FILES=679
ARCHIVE_SHA256=4d28637c59be34919b81e27d3938af052a3f529c6d962f0f80b7c30de0667426
```

Archives:

- `/tmp/sow-clean-delivery-r2-domain-final-a-20260719/sow-delivery-61e0e61fcddf5c3e.tgz`
- `/tmp/sow-clean-delivery-r2-domain-final-b-20260719/sow-delivery-61e0e61fcddf5c3e.tgz`

Independent `cmp` returned 0 and `shasum -a 256` returned the archive digest
above for both files. This is the current V-14/V-21 delivery identity. The
long-term Goal remains active for the explicitly open real Worker/purge and
negative CDN verification, COS/EdgeOne, dual-cloud transaction, production
migration/revocation and operational evidence.

## 2026-07-19 V-23 confidential edge preflight delivery identity

This section supersedes the preceding V-21 identity. The product now rejects
every confidential publication before its journal, checkpoint or first remote
mutation unless the configured client domain anonymously returns the exact
`sow-edge-runtime/v2` private denial contract. Both concrete providers share
the same context-bound gate; caller CookieJar state cannot authorize the canary
or normal L3 read-back. Public-only plans retain the prior no-network preflight.

The final 679 default CLI tests passed through all six ordinary and race shards;
all non-CLI packages passed ordinary/race. Vet, the Go-1.26.5-built pinned
Staticcheck v0.6.1 profile, both module integrity gates, RPM v1.3.0 byte
provenance, govulncheck v1.6.0, four static builds and edge 42/42 passed. The
owner-authorized `pro.pigsty.io` and `beta.pro.pigsty.io` anonymous canary probe
failed safely as expected because both remain raw R2 domains; independent
`rclone lsf cf:pro` was empty afterwards. No cloud mutation occurred in this
closure.

After the delivery content was frozen, two independent fresh
HOME/GOMODCACHE/GOCACHE reconstructions used only the local read-only module
download cache. Both returned exactly:

```text
PRODUCT_SOURCE_SHA256=38410c7825f8a7b2a6e1435a514f9b47d633f6930e3b992832b868b95a04a5aa
PRODUCT_SOURCE_FILES=536
DELIVERY_CONTENT_SHA256=e0e8522e590bf494ac8add7598e9a89bf0bcc437f602efadf590667b2cd99847
DELIVERY_FILES=682
ARCHIVE_SHA256=c37040aa115e919b1321f75cb0b6530db5fc20fd6630843aa29b5ae8a7fe021e
```

Archives:

- `/tmp/sow-clean-delivery-confidential-v23-a-20260719/sow-delivery-e0e8522e590bf494.tgz`
- `/tmp/sow-clean-delivery-confidential-v23-b-20260719/sow-delivery-e0e8522e590bf494.tgz`

Independent `cmp` returned 0 and `shasum -a 256` returned the archive digest
above for both files. This is the current V-14/V-23 delivery identity. It does
not upgrade real Worker/private-origin/purge/negative-verification,
COS/EdgeOne, production migration/revocation or operational metrics; the
long-term Goal remains active.

## 2026-07-19 V-24 R2 lease CAS-retirement delivery identity

This section supersedes the preceding V-23 identity. Cloudflare bootstrap and
provider log-sink reusable R2 lease paths no longer expose DeleteObject. Exact
live leases are conditionally Put/CAS-retired to canonical idle markers, and
the next holder can only replace the marker by ETag CAS. Cloudflare readiness
receipt/seal v3 binds either an empty bucket or one exact idle marker, including
its key/size/ETag/body digest; bootstrap additionally binds that marker to the
selected plan before acquisition.

Complete compat ordinary/race, focused vet, the pinned Staticcheck profile and
all new stale-holder, idle-takeover, recovery-replay and foreign-closure tests
passed. No cloud write occurred. Two independent delivery reconstructions used
the local read-only module download cache and returned exactly:

```text
PRODUCT_SOURCE_SHA256=7879693559e74b6c7b6b4396ae6898e4fd4f985d3317143951151889215421b0
PRODUCT_SOURCE_FILES=536
DELIVERY_CONTENT_SHA256=a586a7e7cc377224c93bb985163a5a0339d40b1a8a96d5c08ec758324b3dc1c6
DELIVERY_FILES=683
ARCHIVE_SHA256=de463b317050b519959d20ec06b090924b83b601871433acaf96d5f5c2e37112
```

Archives:

- `/tmp/sow-clean-delivery-v24-a/sow-delivery-a586a7e7cc377224.tgz`
- `/tmp/sow-clean-delivery-v24-b/sow-delivery-a586a7e7cc377224.tgz`

Independent `cmp` returned 0 and `shasum -a 256` returned the archive digest
above for both files. This is the current V-14/V-24 delivery identity. It does
not upgrade real Worker/private-origin/purge/negative verification,
COS/EdgeOne, production migration/revocation or operational metrics; the
long-term Goal remains active.

## 2026-07-19 V-25 resource-stable R2 lease delivery identity

This section supersedes the preceding V-24 identity. Bootstrap serialization
now uses one key derived from the readiness-resource SHA, not the plan SHA.
Historical same-resource idle plan bodies are CAS-replayable while live holders
fail closed and expired live holders require `recover-lease`; lease/idle v2
bodies bind the readiness-resource SHA and recovery receipt v2 binds both plan
digests plus the complete recovered lease digest. Provider log-sink serialization likewise
uses one dedicated raw-bucket-root key across deployment and raw-root rotation.
Its v2 body also binds the raw bucket. Readiness accepts only the exact resource-derived marker. The readiness
receipt/seal writer also no-replace installs complete inodes and fault-tested
resume of the receipt-only interruption window; unsafe or divergent pairs are
immutable failures.

Focused ordinary/race, complete compat ordinary/race, focused vet, the pinned
Staticcheck profile and `git diff --check` passed with every real-cloud opt-in
explicitly disabled. No cloud request or write occurred. Two independent fresh
HOME/GOMODCACHE/GOCACHE delivery reconstructions used the repository-pinned
modules through `https://goproxy.cn,direct` after the default Go proxy timed
out. Both returned exactly:

```text
PRODUCT_SOURCE_SHA256=7e040fcb5b2f2e98b264b2e63466905855e4fc32a9e80c4748360227a43b7b14
PRODUCT_SOURCE_FILES=536
DELIVERY_CONTENT_SHA256=b18ce454037a3102c7769708c09cd3ea4f118a47b893487ddedf7d4fa22bab13
DELIVERY_FILES=684
ARCHIVE_SHA256=99f44e6679dd10ea0ae082bb49249ef45215b2404f8af92ec5f28e78974a2595
```

Archives:

- `/tmp/sow-clean-delivery-v25-g/sow-delivery-b18ce454037a3102.tgz`
- `/tmp/sow-clean-delivery-v25-h/sow-delivery-b18ce454037a3102.tgz`

Independent `cmp` returned 0 and `shasum -a 256` returned the archive digest
above for both files. This is the current V-14/V-25 delivery identity. It does
not upgrade real signed provider readiness, Worker/private-origin/purge/negative
verification, provider logs, COS/EdgeOne, production migration/revocation or
operational metrics; the long-term Goal remains active.

## 2026-07-19 V-26 two-phase bootstrap recovery delivery identity

This section supersedes the preceding V-25 delivery identity while preserving
its resource-stable bootstrap key and provider log-sink rotation findings.
Expired bootstrap recovery no longer opens a remote idle marker before local
evidence exists. It conditionally advances the single key through exact live,
owning recovery-pending v1, no-replace/fsynced/reopened receipt v3 and recovery
idle v3. Pending binds the recovery run/current plan/resource and full crashed
lease; final idle binds both canonical pending and receipt digests. Live v3
appends completed pairs to a bounded canonical lineage preserved by later
holders and recoveries. Same-run replay therefore converges after every
committed phase, lost Put response, immediate acquisition/release and another
completed recovery. Cross-run, cross-plan, readiness, ordinary acquisition,
stale ETag, forged receipt/digest, unrelated live, duplicate/saturated lineage,
ordinary idle and stale-holder paths fail closed. Capacity fails before pending
CAS. No interface or test calls DeleteObject.

Focused ordinary/race were `1.126s`/`2.460s`; complete compat ordinary/race
were `10.266s`/`14.318s`. `go vet`, the pinned Staticcheck profile and
`git diff --check` passed with every real-cloud opt-in disabled. No cloud
request or write occurred. Two independent fresh HOME/GOMODCACHE/GOCACHE
delivery reconstructions used repository-pinned modules through
`https://goproxy.cn,direct` and returned exactly:

```text
PRODUCT_SOURCE_SHA256=344f731c131982537b7f9a1631e4fa1658d7f16dff55c321a7fb69df0bc08ea8
PRODUCT_SOURCE_FILES=536
DELIVERY_CONTENT_SHA256=6ef5584ca76557277e8562a930f84c9e512a50a3ba570dafe6e6cd01477eb238
DELIVERY_FILES=685
ARCHIVE_SHA256=c1e01fd8e66d6d4561a4cecb46bb55b00ce64350d4ba4089b57d2a36fec1c0c5
```

Archives:

- `/tmp/sow-clean-delivery-v26-c/sow-delivery-6ef5584ca7655727.tgz`
- `/tmp/sow-clean-delivery-v26-d/sow-delivery-6ef5584ca7655727.tgz`

Independent `cmp` returned 0 and `shasum -a 256` returned the archive digest
above for both files. This is the current V-14/V-26 delivery identity. It does
not upgrade real signed provider readiness, Worker/private-origin/purge/negative
verification, provider logs, COS/EdgeOne, production migration/revocation or
operational metrics; the long-term Goal remains active.

## 2026-07-19 V-31 legacy migration hardening delivery identity

This section supersedes the preceding V-26 identity. The delivery adds the
physical Pigsty-v1 selector golden, effective-user writable-FD writer fence,
strict approval timestamps, direct zero-byte Pro checksum identity, a dedicated
EL9 compatibility policy owner, exact aarch64/x86_64 projections, and both
architecture state-machine E2E paths. The old repository was read only; no
cloud opt-in or production mutation occurred.

The focused ordinary/race suites, 20-case writer fence, physical topology and
config gates, 176-target/44-family audits, full `go test ./...`, `go vet`, the
project Staticcheck profile, shell syntax, and patch checks passed. Two
independent clean-delivery reconstructions used only the read-only local Go
module cache and returned exactly:

```text
PRODUCT_SOURCE_SHA256=115df5f22c88b5eccb053030272462a6d95f4412358f7945d59d9737f61b8f21
PRODUCT_SOURCE_FILES=538
DELIVERY_CONTENT_SHA256=c08eb549df02e25a36ab8d95c38b900f9f429af34555ff89fc1175a44d8aad94
DELIVERY_FILES=697
ARCHIVE_SHA256=701c399a31238531f9ce91ff6491b9c36e9127a65c8d6581de33133f4be69ff7
```

Archives:

- `/tmp/sow-clean-delivery-migration-review-v31/sow-delivery-c08eb549df02e25a.tgz`
- `/tmp/sow-clean-delivery-migration-review-v31-b/sow-delivery-c08eb549df02e25a.tgz`

Independent `cmp` returned 0 and both `shasum -a 256` values matched the digest
above. This is the current V-14/V-31 delivery identity. It does not upgrade any
real Cloudflare/COS/EdgeOne publication, production writer revocation, or
operational metric; the long-term Goal remains active.

## 2026-07-19 V-32 migration review closure delivery identity

This section supersedes V-31 after the two independent final reviewers found
and the implementation closed two additional fail-closed gaps. The 44-family
gate now requires every physical compatibility architecture independently, so
removing the aarch64 state-machine evidence from one affected family is a
tested failure even when another family still names that test. The writer
fence now compares writable regular-file descriptors with the complete legacy
device/inode set, including external hard-link aliases, and its `lsof` parser
rejects malformed or missing regular-file identities instead of silently
omitting them.

The native macOS `lsof` suite passed 21 named cases, including the malformed
identity mutation. An unprivileged uid 65534 run in the already-present
`pgsty/d13:latest` image with `--network none` passed all 20 applicable Linux
procfs cases. The 44-family gate passed 5 contract mutations and 16 executable
tests; focused four-state-machine ordinary tests, the family contract race
test, `go vet ./...`, Staticcheck v0.6.1 with the repository profile, shell
syntax, Go formatting, and patch checks all passed. The prior full-repository
run remained applicable because these final changes touched only test-contract
and shell/evidence code; it had passed every package with `internal/cli` at
1202.757s. Both final reviewers returned an empty finding list. No cloud opt-in,
production mutation, or legacy-repository write occurred.

After delivery content was frozen, two independent fresh HOME/GOMODCACHE/
GOCACHE reconstructions used only the local read-only Go module download cache
and returned exactly:

```text
PRODUCT_SOURCE_SHA256=280258ad7483406096a93eb57f90e61804b2d9a2ed8d92c0cdd7fc474889bec2
PRODUCT_SOURCE_FILES=538
DELIVERY_CONTENT_SHA256=f562a11fd581da3856607e03f708595d83eee5d0f27ea71e814a5afb6caf1785
DELIVERY_FILES=697
ARCHIVE_SHA256=797553c61bd629b2176060e07122de11ea41534c980fc13c897665e92bb19df0
```

Archives:

- `/tmp/sow-clean-delivery-migration-review-v32-a/sow-delivery-f562a11fd581da38.tgz`
- `/tmp/sow-clean-delivery-migration-review-v32-b/sow-delivery-f562a11fd581da38.tgz`

Independent `cmp` returned 0 and both `shasum -a 256` values matched the
archive digest above. This is the current V-14/V-32 delivery identity. It does
not upgrade real Cloudflare/COS/EdgeOne publication, production writer
revocation, or operational metrics; the long-term Goal remains active.

## 2026-07-19 V-33 edge entitlement expiry delivery identity

This section supersedes V-32 after the shared Cloudflare/EdgeOne entitlement
contract was tightened. Static token and Basic expiry now accepts only exact
whole-second UTC RFC3339; timezone-less, numeric-offset, fractional, calendar
rollover and `24:00:00` inputs fail adapter construction. Malformed Basic
entitlement JSON also fails construction instead of surviving as a
request-time-only outage. The source contract and both generated vendor bundles
carry the same check; ADR-0004 and the operator documentation freeze the wire
format.

The source shared suite passed 46/46, then the generated-bundle freshness,
syntax/import and shared suite passed 46/46. Independent UTC and Asia/Shanghai
runs also passed 46/46, directly exercising the cross-timezone invariant. Go
config/CLI deployment-contract tests passed in 0.473s/54.164s, compat focused
tests passed in 0.653s, all packages compiled, and patch checks passed. The
logged-in Cloudflare dashboard was used only for visible read-only inventory;
it confirmed `pigsty-entitlements` is absent and performed no provider
mutation. No cloud credential entered the code/test paths.

After delivery content was frozen, two independent fresh HOME/GOMODCACHE/
GOCACHE reconstructions used only the local read-only Go module download cache
and returned exactly:

```text
PRODUCT_SOURCE_SHA256=8c91cffd261f6166c1658d341c136a4be7bc4f1bd1cfa35f0bd7f20eba201f0a
PRODUCT_SOURCE_FILES=538
DELIVERY_CONTENT_SHA256=5efaa682f3ab438cef561199ae6cb3800d355eb054fd0545b0f81543cc8967c9
DELIVERY_FILES=698
ARCHIVE_SHA256=8abbfe512351f177011f8c503d53ef2d01b7856d02e84eaecf6f3b6d3e5c0cf9
```

Archives:

- `/tmp/sow-clean-delivery-edge-expiry-v33-reviewed-a/sow-delivery-5efaa682f3ab438c.tgz`
- `/tmp/sow-clean-delivery-edge-expiry-v33-reviewed-b/sow-delivery-5efaa682f3ab438c.tgz`

Independent `cmp` returned 0 and both `shasum -a 256` values matched the
archive digest above. This is the current V-14/V-33 delivery identity. It does
not upgrade real Worker/CDN/purge/provider-log evidence, COS/EdgeOne access,
production migration, or operational metrics; the long-term Goal remains
active.

## 2026-07-19 V-34 Basic authorization wire delivery identity

This section supersedes V-33 after the shared Cloudflare/EdgeOne Basic
fallback was tightened to one bounded ASCII wire form. The scheme is
case-insensitive, separation is one or more literal SP bytes, Base64 is
canonical padded RFC 4648, and the decoded `user:password` is at most 1024
printable US-ASCII bytes with a non-empty user. The digest remains over the
exact decoded bytes. Wire aliases, missing user/separator, CTL, DEL, UTF-8 and
oversized inputs now fail with a realm-only 401 before either origin adapter is
called; empty passwords and additional password colons remain supported.

The source shared suite, generated-bundle freshness, three syntax/import gates
and independent UTC/Asia-Shanghai runs each passed 47/47. The Go compat bridge,
all-package compile gate, two vet profiles, Staticcheck, module integrity,
clean-delivery policy and current real apt/YUM/DNF/Nginx Docker matrix also
passed; the Docker package completed in 77.657s. All validation was local or
loopback/Docker. No cloud credential, Cloudflare/R2/COS/EdgeOne request, or
production repository write was used.

After delivery content was frozen, two independent fresh HOME/GOMODCACHE/
GOCACHE reconstructions used only the local read-only Go module download cache
and returned exactly:

```text
PRODUCT_SOURCE_SHA256=7b678d6745071625a0e153d1513ea3f9c269956c462cc92e4dd53020b42f8a3c
PRODUCT_SOURCE_FILES=538
DELIVERY_CONTENT_SHA256=761c8e650f5b7373ab8b56279d96eb08a5ef317f569cf9d61955041f82a3d7e5
DELIVERY_FILES=699
ARCHIVE_SHA256=1aca2e1c58fac937a7ea320bd7b16456742725fd4811808df1748955da1bae01
```

Archives:

- `/tmp/sow-clean-delivery-basic-wire-v34-reviewed-a/sow-delivery-761c8e650f5b7373.tgz`
- `/tmp/sow-clean-delivery-basic-wire-v34-reviewed-b/sow-delivery-761c8e650f5b7373.tgz`

Independent `cmp` returned 0 and both `shasum -a 256` values matched the
archive digest above. This is the current V-14/V-34 delivery identity. It does
not upgrade real Worker/CDN/purge/provider-log evidence, COS/EdgeOne access,
production migration, or operational metrics; the long-term Goal remains
active.

## 2026-07-19 V-35 remote fsck storage-only authority delivery identity

This section supersedes V-34 after `sow fsck --target` was separated from CDN
authority. R2 and COS remote audit now construct explicit storage-only clients
and resolve only the selected target's object-storage credential; full publish,
purge and post-publish CDN verification retain the existing full provider
clients. Unit, protocol and CLI tests passed with the Cloudflare CDN credential
absent and the COS CDN credential deliberately malformed, and a storage-only
client cannot be converted into a publisher.

The owner-designated empty non-production Cloudflare `pro` bucket was used by
the exact-registry opt-in test only. Run `sow-r2-fsck-20260719-02` completed
remote-inventory adoption, idempotent replay, run-owned CAS drift rejection,
canonical Git HEAD preservation, exact CAS restore and identity-bound cleanup
in 29.600s package time. Independent `rclone lsf cf:pro --recursive --max-depth
-1` returned exit 0 and empty stdout after the test. The Cloudflare API/CDN
credential was explicitly absent, and there was no Worker, Zone, purge,
custom-domain, COS/EdgeOne or production request.

The frozen source also passed all 692 default CLI tests in six ordinary and six
race shards, all non-CLI packages ordinary/race, both vet profiles, repository
Staticcheck profiles, module integrity, fixed govulncheck, four static
Linux/macOS builds and the real apt/YUM/DNF/Nginx Docker compatibility matrix.
The detailed timings, hashes and evidence boundaries are recorded in
`docs/evidence/2026-07-19-r2-fsck-storage-only-authority.md` and V-01 through
V-04/V-10/V-33 of the traceability matrix.

After delivery content was frozen, two independent fresh HOME/GOMODCACHE/
GOCACHE reconstructions used only the local read-only Go module download cache
and returned exactly:

```text
PRODUCT_SOURCE_SHA256=cc8cc83e52a137bfba3e06482b61093d25f156bdd24d43b6bd4cfd99fbd22c13
PRODUCT_SOURCE_FILES=539
DELIVERY_CONTENT_SHA256=0e5a7b39db077f4485944b352d2c7d8a61108d429251361b1e4e60e32195ba6d
DELIVERY_FILES=702
ARCHIVE_SHA256=4d7065c1a099fe733a4d8dd8b9fa2746130ce409130ee85616ddabaa8780c905
```

Archives:

- `/tmp/sow-clean-delivery-r2-fsck-v35-reviewed-a/sow-delivery-0e5a7b39db077f44.tgz`
- `/tmp/sow-clean-delivery-r2-fsck-v35-reviewed-b/sow-delivery-0e5a7b39db077f44.tgz`

Independent `cmp` returned 0 and both `shasum -a 256` values matched the
archive digest above. This is the current V-14/V-35 delivery identity. It does
not upgrade real Worker/CDN/purge/provider-log evidence, real COS/EdgeOne,
production migration or operational metrics; the long-term Goal remains
active.
