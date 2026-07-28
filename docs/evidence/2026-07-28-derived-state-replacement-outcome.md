# Derived-state replacement outcome and recovery evidence

Date: 2026-07-28

Scope: V-81, local filesystems only

Baseline: `7c8bf16`

## Closure

The shared writer now returns a zero-value-fail-closed three-state result
instead of exposing an error plus rename visibility. Before touching a
canonical destination it writes a bounded prepared intent without recursively
calling itself. Existing files are replaced with native atomic exchange so
the exact prior inode remains available; absent files use no-replace install.
The prepared phase compensates to the exact prior or durable absence. A
parent-fsynced committed carrier transfers ownership to forward cleanup.

Every intent binds the transaction ID, canonical basename, source/isolation
and cleanup names, candidate size/SHA-256 plus filesystem identity, and the
exact prior-present state and identity. Runtime validation retains the
candidate and prior descriptors across the exchange. Restart validation
streams and hashes each named regular file, compares the persisted filesystem
identity, and refuses a third identity without deleting it.

V-81 isolation uses the separate strict
`.sow-derived-isolation-<32-lower-hex>[.remove]` grammar. It cannot be consumed
by legacy `.tmp-install-*` cleanup. Transaction discovery streams directory
entries in batches of 128, fails closed on every malformed reserved
replacement/isolation name, and reports an isolation without a durable carrier
as recovery-required evidence. It caps the in-memory transaction-ID inventory
at 1,024 and validates the legal staged/main/next phase topology before
restoring or removing a carrier. A quarantined carrier is bound, parsed and
validated in place before its canonical name can be restored.

Production generated publish sources, projection intents/receipts,
materialization selection, local serving, serving topology, and offline
archive intent preparation consume the explicit result. Generated publication
sources pass the CLI recovery flag through to the writer: an ordinary publish
cannot replay an interrupted replacement, while `publish --recover` can.
Offline archive stage
ownership is now decided directly from `committed`, `not-committed`, or
`recovery-required`; the old post-error intent read-back was removed.

The asset/package projection, offline archive, materialization-selection,
local-serving, and serving-removal residue scanners arbitrate strict
replacement transactions before their legacy temporary grammar. Ordinary
non-recovery scans stop on a durable transaction; recovery scans replay its
prepared or committed phase first.

Committed replay performs a distinct parent-directory
`committed-observed` barrier and rereads the exact carrier before deleting the
prior. The outer writer then revalidates the absolute root, bound directory,
and exact destination device/inode/mode/mtime/size/SHA-256 identity before
forward cleanup. It proves the outcome again across carrier removal while
another carrier still preserves restart authority. A replaced root/parent, a
same-byte foreign destination, or a pre-terminal cleanup-hook swap is therefore
`recovery-required` with discoverable evidence.

The remaining adversarial observation—an uncooperative same-host principal
replacing the destination after the final terminal carrier unlink—is the same
already-recorded writable-directory/hardlink threat-model expansion as the
cleanup check/rename/unlink TOCTOU. V-81 serializes all SOW writers and proves
the terminal state before that unlink; preventing a different principal from
mutating the admitted directory afterward requires directory ownership and
foreign-hardlink exclusion, not another transaction phase. That follow-up
remains open and this evidence does not claim hostile-writer protection.

Generic source cleanup is authorized only by a proven `not-committed` result.
`recovery-required` retains the transaction-owned source, carrier and prior.
The source-removal coordinate is the bounded
`.sow-derived-isolation-<transaction>.source.remove` form rather than a
destination-derived name, and canonical destinations using either reserved
transaction prefix are rejected.

Materialization selected-set updates also consume the new failure boundary.
If the completed-unit journal cannot be durably replaced, the current
operation stops before the next unit, records the failure, and retains the
pre-update durable recovery fence.

## Fault and crash matrix

`internal/cli/derived_state_replacement_contract_test.go` verifies:

- the result zero value requires recovery;
- a post-destination-mutation fault restores the exact prior inode, mode and
  bytes and reports `not-committed`;
- a fault after the committed marker reports `committed` with an error,
  preserves the new canonical bytes, and replays cleanup forward;
- real child-process death for both prior-present and prior-absent
  transactions after prepared-carrier, prepared, candidate-isolation,
  destination-mutation, committed-carrier, committed, committed-observed,
  prior-quarantine, prior-unlink, intent-quarantine and intent-unlink
  barriers;
- prepared recovery restores the exact prior while committed recovery retains
  the exact candidate;
- a foreign third identity remains untouched and forces
  `recovery-required`;
- an exact Unix-epoch prior mtime is valid and rolls back exactly;
- malformed reserved carrier/isolation names and an orphan isolation are
  retained and fail closed;
- 4,097 unrelated siblings are scanned through the bounded iterator;
- root replacement, parent replacement, and a same-byte foreign destination
  inode after commit are reclassified as `recovery-required`;
- one-shot and persistent parent-directory sync failures at prepared,
  destination-mutated, committed, committed-observed, prior-cleanup and
  carrier-cleanup barriers produce the exact three-state outcome and replay;
- cleanup-hook replacement of a prepared or committed destination is detected
  before terminal evidence removal, retained, and reclassified as
  `recovery-required`;
- maximum-length destination recovery uses the bounded transaction-derived
  source-trash name without exceeding `NAME_MAX`;
- all three root scanners and all three nested scanners arbitrate a live
  transaction before legacy cleanup;
- a completed materialization unit whose journal write fails stops the
  selected set and retains the prior durable journal;
- a post-commit hook error with the exact canonical coordinates remains
  `committed` plus error;
- reserved canonical destination basenames are rejected before a source
  temporary is created.
- impossible staged-only and contradictory main/next carrier phases fail
  closed without mutation;
- malformed quarantined carriers fail validation before their pathname moves;
- the transaction inventory fails closed at its exact bound;
- a generated publish source blocks an ordinary retry and converges only with
  explicit recovery;
- payload and carrier reads reject in-place mtime mutation, offline-archive
  pre-writer size failure is explicitly not-committed, and simultaneous
  materialization trust/journal failures are both retained.

The existing derived-state suite additionally retains root/parent replacement,
in-place mutation, restrictive-umask, concurrent temporary replacement,
directory-stage crash, mutation-epoch and final-cache coverage.

## Verification

All commands below ran with provider credentials unset and
`SOW_RUN_REAL_CLOUD=0`, `SOW_RUN_REAL_EDGE_EVIDENCE=0`,
`SOW_RUN_REAL_UPSTREAM=0`, and `SOW_RUN_DOCKER_COMPAT=0`.

### Pre-review focused baseline

The initial implementation passed the following focused checks. Review fixes
changed the writer, so these results are retained only as an execution
baseline:

```bash
go test ./internal/cli -run '^TestDerivedStateReplacement' -count=1
# PASS 4.100s, including prior-present and prior-absent crash matrices

go test -race ./internal/cli -run '^TestDerivedStateReplacement' -count=1
# PASS 5.499s; no race report

go test ./internal/cli -run '^TestDerivedState' -count=1
# PASS 23.926s

go test ./internal/cli \
  -run '^(TestMaterializationSelection|TestDerivedStateReplacement)' \
  -count=1
# PASS 8.788s

go test -race ./internal/cli \
  -run '^(TestMaterializationSelection|TestDerivedStateReplacement)' \
  -count=1
# PASS 11.739s; no race report
```

### Post-second-review focused current source

After the second adversarial review fixes, current source passed:

```text
replacement + selection + archive oversize   ordinary 9.695s   race 12.964s
all TestDerivedState*                         ordinary 16.273s  race 20.797s
generated publish explicit-recovery contract ordinary 1.600s   race 2.368s
asset/package projection + offline archive   ordinary 330.479s race 324.634s
materialization selection/topology/serving   ordinary 86.014s  race 90.895s
publish CLI/recovery/generated-source paths ordinary 491.522s race 430.668s
```

These focused and adjacent results are current-source evidence and are
retained alongside the exhaustive post-review terminal gate below.

### Independent post-fix review

A fresh blind reviewer and a separate edge-case reviewer each read the full
post-fix spec, ADR, evidence, implementation and tests against baseline
`7c8bf16`. Both were read-only, ran no network or production operation, and
returned `[]`. The already-ledgered same-host hostile writer/hardlink policy
was explicitly separated from V-81's serialized SOW-writer scope.

The current Darwin-built Linux/arm64 test binary and CLI also passed in an
already-local `debian:13-slim` arm64 container as uid 65534 with
`--network none`, read-only root, all capabilities dropped,
`no-new-privileges`, a read-only source mount and only `/tmp` writable. The
first harness invocation used `/` as its working directory and could not find
the relative RPM fixture; the corrected `/workspace/internal/cli` invocation
passed. The discarded invocation had no product assertion failure.

### Post-review terminal current source

`go test -list '^Test' ./internal/cli` enumerated 859 tests. The same six
exhaustive, disjoint expressions passed on the post-fix source in both
ordinary and race modes:

| CLI shard | tests | ordinary | race |
|---|---:|---:|---:|
| `^Test[A-F]` | 245 | 995s | 969s |
| `^Test[G-M]` | 165 | 1201s | 1210s |
| `^Test[N-O]` | 73 | 474s | 439s |
| `^Test[P-Q]` | 177 | 1395s | 1480s |
| `^Test[R-V]` | 126 | 884s | 886s |
| `^Test([W-Z]\|[^A-Z]\|$)` | 73 | 382s | 392s |

All 17 main-module packages outside `internal/cli` passed in 156s ordinary
and 222s race runs. `go vet ./...`, root Staticcheck, `go mod verify`,
`go mod tidy -diff`, and `git diff --check` passed. The nested patched RPM
module passed ordinary/race tests, vet, module verification and its pinned
provenance proof. Fixed `govulncheck@v1.6.0` found zero reachable and zero
imported-package vulnerabilities in the root module; two required-module
advisories were outside the call graph. The nested module reported no
vulnerability.

Four `CGO_ENABLED=0` CLI and test-binary pairs built successfully. `file`
identified the expected Mach-O and static ELF architectures:

| target | CLI bytes | CLI SHA-256 | test bytes | test SHA-256 |
|---|---:|---|---:|---|
| darwin/amd64 | 57,976,512 | `c5b5a528…15089` | 69,584,624 | `a818c959…47d8a` |
| darwin/arm64 | 54,976,018 | `23544103…db467` | 65,395,154 | `6bdf64ee…c5ba1` |
| linux/amd64 | 56,148,502 | `11b516f9…88978` | 67,693,212 | `77a460eb…044e` |
| linux/arm64 | 52,724,591 | `4d76bee7…01ecd` | 62,911,849 | `02d4299d…8ce8` |

The local Docker compatibility package passed in 292.013s ordinary and 262s
race runs. It exercised real apt 1.2.35 and 2.4, APT Packages/Release/
InRelease/by-hash/history/snapshot/install, EL7 YUM gzip, EL8 DNF gzip,
EL9/10 DNF zstd, all three YUM metadata streams, `repomd.xml` and detached
signature transitions, package-key negatives, generation pinning, inflight
flip, Nginx exact routes, Basic fallback and local Cloudflare-token contract.
No provider credential or public origin was enabled.

`cd edge && npm run build && npm test` passed all 47 shared
Cloudflare/EdgeOne contracts; the generated `dist` file hashes were unchanged.
The HTTPS-relative, APT Release checksum-path, RPM OpenPGP packet and patched
binary RPM header fuzz targets each ran for 20 seconds and passed without a
crash corpus.

Current post-review scale results:

| gate | ordinary | race |
|---|---|---|
| CAS materialize 50k | link 14.995s, reconcile 2.573s, workers 8/8, retained +153,152B | link 15.729s, reconcile 4.051s, workers 8/8, retained +144,936B |
| 50k-to-one publish plan | 12.363ms, one changed object, retained +39,992B | 117.011ms, one changed object, retained +40,232B |
| YUM streaming 50k | generate 6.870s, retained +20,256B | generate 48.147s, retained growth 0B |
| strong YUM CLI 4×12.5k | complete 308.88s, combined worker peak 8, max RSS 134,791,168B | complete 352.17s, combined worker peak 8, max RSS 403,161,088B |

The strong-YUM run covered two generations, `Previous`, replay, L1 and GC
preflight. The current unique-content adoption run created 50,000 different
asset bodies and drove real `sow init --adopt-content`: fixture 2.595s, first
adoption 6m21.544s, replay 2m41.921s, import workers 8/8. CAS, view, receipt,
SQLite cache and provenance each contained exactly 50,000 identities; retained
heap grew 586,048B, process RSS grew 142,884,864B, the source manifest was
unchanged and replay did not advance HEAD.

Finally, the existing `/Users/vonng/pgsty/repo` was scanned read-only with 18
workers. Both runs observed the same 57,399 DEB and 34,248 RPM files:
91,647 files / 106,310,354,933 bytes total. Ordinary completed in 11.446s and
race in 13.124s. Output manifests existed only under `t.TempDir`; the source
repository was never a write target.

### Pre-review exhaustive ordinary and race baseline

`go test -list '^Test' ./internal/cli` enumerated 843 tests. The six regular
expressions below are exhaustive and disjoint. Every ordinary and race shard
passed before the independent review. Review fixes changed the writer and
selection-journal paths, so these timings are retained only as a baseline and
must not be treated as the post-review terminal gate.

| CLI shard | tests | ordinary | race |
|---|---:|---:|---:|
| `^Test[A-F]` | 233 | 929.291s | 904.673s |
| `^Test[G-M]` | 163 | 1152.344s | 1159.169s |
| `^Test[N-O]` | 72 | 416.411s | 412.924s |
| `^Test[P-Q]` | 176 | 1334.071s | 1499.740s |
| `^Test[R-V]` | 126 | 837.858s | 841.234s |
| `^Test([W-Z]\|[^A-Z]\|$)` | 73 | 325.587s | 360.460s |

All 17 main-module packages outside `internal/cli` passed in explicit ordinary
and race runs before review. Post-review reruns are required below.

### Pre-review static, module, security, and portability baseline

- Root `go vet ./...`, Staticcheck, and `go mod verify` passed.
- The nested patched RPM module passed ordinary/race tests, vet, module
  verification, and its pinned-upstream/allowlist proof using the local module
  cache. Its standalone Staticcheck still reports the two pre-existing
  vendored `U1000` findings in `package_test.go:53` and `signature.go:17`;
  root CI intentionally does not scan that separate module and V-81 did not
  modify it.
- Fixed `govulncheck@v1.6.0`, resolved only from the local module cache, found
  no reachable vulnerability in the root module and no vulnerability in the
  nested module. Two required-module advisories in the root module were
  outside the call graph.
- No check fetched source or used a provider/upstream network endpoint.

Four `CGO_ENABLED=0` test binaries passed before review:

| target | bytes | SHA-256 | format |
|---|---:|---|---|
| darwin/amd64 | 69,541,888 | `2cd67a24…e9250b` | Mach-O x86_64 |
| darwin/arm64 | 65,352,098 | `a2821161…7430e` | Mach-O arm64 |
| linux/amd64 | 67,635,971 | `7aa816f0…aab7` | static ELF x86-64 |
| linux/arm64 | 62,898,280 | `3822561a…947a` | static ELF aarch64 |

### Current 50k and large-tree evidence

All write-capable scale gates used Go test temporary directories. The local
repository `/Users/vonng/pgsty/repo` was only scanned read-only.

| gate | ordinary | race |
|---|---|---|
| unique asset adoption | fixture 5.165s; adopt 7m30.936s; replay 3m18.669s; import workers 8/8; sampled retained heap +510,464B; replay unchanged | an isolated 60m operator-budget run remained active in modernc SQLite adoption and was terminated; no race was reported, but this is **not** recorded as PASS |
| APT streaming | 50,000 in 3.430s; workers 4/4; chunk peak 256; spool 32,126,600B; retained +202,112B | 9.381s; retained +161,840B; no race |
| CAS materialization | 20.657s + 3.364s reconcile; workers 8/8; retained +16,112B | 38.764s + 7.660s; workers 8/8; retained +64,352B; no race |
| one-change publish plan | 50,000 to one object in 13.065ms; retained +39,688B | 235.115ms; retained +39,848B; no race |
| YUM streaming | 50,000 in 6.988s; metadata 5,893,447B; retained +23,256B | 79.051s; metadata 5,916,314B; retained growth 0B; no race |

The strong-YUM CLI test used four 12,500-record leaves, two generations,
`Previous`, replay, L1, and GC preflight. Every activation observed four leaf
workers, at most two install workers per leaf, and a combined peak of eight.

| phase | ordinary | race |
|---|---:|---:|
| generation 1 | 127.365s | 72.518s |
| generation 2 + Previous | 173.516s | included in complete race run |
| replay | 99.837s | 75.959s |
| L1 verification | 34.350s | 30.251s |
| GC preflight | 40.332s | 47.950s |
| peak heap | 86,048,456B | 106,735,536B |
| process max RSS | 128,647,168B | 489,668,608B |
| complete test | 503.66s | 362.41s |

The incremental 50k-ref preflight completed 100 ordinary iterations in
10.133ms and 100 race iterations in 46.397ms without reading the serving view.

The first independent read-only scan observed 57,324 APT and 34,188 YUM files:
91,512 files / 105,795,060,267 bytes total, 18 workers, 31.477s. A later race
run observed that the external source had changed to 91,652 files /
106,314,994,666 bytes and completed in 27.544s with 18 workers. SOW did not
write either tree; the changed count is recorded rather than normalized away.

The 50k adoption race timeout is a remaining instrumentation/runtime cost, not
a correctness PASS and not evidence of a data race. Ordinary 50k adoption,
all functional ordinary/race suites, and every other 50k ordinary/race gate
above passed. The attempted prepared-statement optimization regressed ordinary
adoption and was fully reverted; `internal/cli/adopt_content.go` is byte-for-byte
unchanged from baseline `7c8bf16`.

### Reproducible delivery

Two independent pre-review Step-3 reconstructions (run immediately before
appending this result) passed with identical identities:

```text
PRODUCT_SOURCE_SHA256=330a290c4b6fcd646808e59e02530a5f2568cad52f57c561a3cff212bcc3bdad
PRODUCT_SOURCE_FILES=570
DELIVERY_CONTENT_SHA256=da5513b19775dede868e0951c02dcebfa8eebce52ce03eac5e68a9fff6369fa1
DELIVERY_FILES=773
ARCHIVE_SHA256=cf1597a9736d50232b5fd648354b57b60da1f0dffb4e7c9d13dd1afe3afa31e6
```

`cmp` of the two `.tgz` files exited zero. The terminal post-review
reconstruction is run twice only after the final spec, ledger and evidence
status edit. Its hashes remain in the command artifact rather than being
inserted recursively into this archive-bound evidence file.

## External boundary

All product mutations were confined to local temporary directories and the
source worktree. The existing package repository was scanned read-only.
Cloudflare/R2, CO/COS, CDN, upstream package repositories, production
repositories and provider credentials were not accessed; only public
vulnerability metadata used by the pinned security scanner may use a tooling
network path. V-81 strengthens local FR-28/NFR-09 interruption, replay and
idempotency evidence only and does not upgrade any real-cloud or production
status.
