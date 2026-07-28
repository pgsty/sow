# Derived-state recursive directory durability evidence

Date: 2026-07-26

Scope: V-80, local filesystem and isolated Linux container only

Baseline: `818a2de`

## Defect and acceptance boundary

The shared `writeDerivedStateFile` path created an arbitrary directory tree
with one `Root.MkdirAll` call and synchronized only the final leaf after file
installation. A successful return therefore did not prove that every newly
created ancestor entry was durable. The whole tree was also created before
component identities were bound, so a replacement during creation could not
be attributed to an exact admitted parent/child chain.

The acceptance boundary is stricter than “the file exists after the call”:
each missing component must be created privately, bound without following a
symlink, installed create-only into its exact bound parent, followed by an
exact-parent durability barrier and root/parent/child coordinate
revalidation. A failed barrier may leave a safe empty component, but no
deeper component or canonical file may be created.

## Implemented closure

- The writer now walks from a retained state-root capability one component at
  a time. Every new directory begins as a random exact-`0700`
  `.tmp-derived-directory-<32-lower-hex>` stage, is opened and bound to its
  inode, installed with no-replace rename, then made durable by syncing its
  exact parent before traversal continues.
- Existing components are also parent-synced before reuse. This is the replay
  proof for a coordinate left by a failed barrier or a concurrent first
  creator whose completion is otherwise unobservable.
- Every transition revalidates the absolute state-root identity and retained
  parent/child descriptor, inode and mode. Symlinks, non-directories, unsafe
  path components, unsupported crash-stage modes and root/ancestor replacement
  fail closed. The one explicitly admitted special-mode residue,
  setgid-plus-`0700`, is repaired through its retained descriptor to exact
  `0700` before recovery continues.
- Recovery recognizes only the exact directory-stage grammar and its single
  quarantine form. Enumeration is streamed in batches of 128 entries;
  concurrent recoverers claim a stage atomically. Changed or reoccupied
  coordinates are moved outside the recoverable namespace as
  `.preserved-<nonce>` evidence and are never auto-deleted.
- A descriptor-backed mutation guard seals each known writer mutation with a
  two-or-three-second future mtime epoch and binds device, inode, ctime, mtime,
  link count, size, blocks and mode. An ordinary directory-entry mutation
  restores filesystem time and therefore invalidates the token before the
  epoch can collide with wall time. This closes the balanced case where one
  sibling directory disappears while a strict crash stage appears without
  changing the directory link count.
- A clean-parent cache is admitted only after durable recovery, final absolute
  root/directory fences and a live mutation epoch. The lease expires before
  the marker can become an ordinary filesystem timestamp. Expiry forces a
  streaming rescan. If exact descriptor timestamp sealing is unsupported,
  denied or rounded by the filesystem, the writer remains usable but deletes
  any existing cache entry, rescans at every guard boundary and never admits a
  replacement cache entry.
- Crash residues created under a restrictive inherited umask or interrupted
  around mode establishment are repaired through their retained descriptor
  to exact `0700`; the live writer does not mutate process-global umask.
- The final file install path participates in the same mutation guard.
  Source-to-isolation and isolation-to-destination mutations refresh the
  admitted token, and a guard failure after isolation restores the exact
  source or preserves all foreign reoccupations.

## Failure-injection and concurrency matrix

Current-source tests cover ancestor sync ordering and failure at depth N,
safe replay, parent/root/child replacement before bind and after sync,
concurrent first writers, two recoverers claiming one stale stage, repeated
subprocess crash/replay, root-level residue, setgid and inherited-umask
residue, recovery replacement after initial `Lstat`, quarantine
disappearance, canonical reoccupation during restore, reoccupation after
unlink, parent-sync failure while two foreign coordinates remain, cache
invalidation on inode change, late stage insertion, balanced remove-plus-stage
insertion, 5,000 unrelated siblings and fifty writes.

The final-cache negatives additionally cover state-root replacement during
link-count recovery resealing, balanced mutation immediately before cache
admission, a live-cache transition to an unsupported seal, lease expiry and
the uncached fallback. Pre-install bind/sync replacement tests prove neither
the replacement tree nor the detached admitted tree is written. Post-install
final-fence tests prove the call fails and the replacement tree stays
untouched; bytes already committed before that fence remain in the displaced
admitted tree and are reported as such rather than misclassified as a
rollback.

Preservation tests assert all foreign identities survive under
non-recoverable audit names. Replay tests assert the exact canonical bytes and
absence of strict stage residue.

## Current-source verification

Every command below explicitly unset provider credentials and set
`SOW_RUN_REAL_CLOUD=0`, `SOW_RUN_REAL_EDGE_EVIDENCE=0`,
`SOW_RUN_REAL_UPSTREAM=0` and `SOW_RUN_DOCKER_COMPAT=0`.

```bash
go test ./internal/cli -run '^TestDerivedStateWriter' -count=1
# PASS 4.296s

go test -race ./internal/cli -run '^TestDerivedStateWriter' -count=1
# PASS 6.477s; no race report

go test ./internal/cli \
  -run 'DerivedState|Projection|OfflineArchive' -count=1
# PASS 174.185s

go test -race ./internal/cli \
  -run 'DerivedState|Projection|OfflineArchive' -count=1
# PASS 235.530s; no race report
```

The final high-risk set covers concurrent first writes and recovery, late and
balanced stage insertion, final-cache root replacement, link-count recovery
resealing, live-cache downgrade, unsupported sealing, lease expiry and 5,000
ordinary siblings. It passed 20 ordinary repetitions in `114.281s`, 10 race
repetitions in `80.595s`, and 20 Linux/arm64 repetitions in a Debian 13
container with no network, read-only root, no capabilities and
`no-new-privileges`.

The first Linux tmpfs run had exposed a real rapid-balanced-mutation cache
bug, and the first twelve-way full race run exposed an independent test
harness race: a failure path read a `bytes.Buffer` while `os/exec` was still
copying child output. The implementation now uses a short-lived exact
mutation epoch with safe unsealed fallback; the harness now kills and waits
for the child before reading output and allows a 20-second loaded-machine
ready window. That SIGKILL test then passed five race repetitions in `26.580s`
and twenty in `97.885s`; the complete race shards below passed afterward.

A focused atomic coverage run completed in `4.061s`. It reports 73.3% for the
shared writer, 78.3% for recursive bind/create, 73.5% for stage recovery,
77.2% for exact empty-stage removal, 71.7% for final clean-cache admission,
80.0% for unexpected-mutation recovery and 85.7% for both root and directory
coordinate verification.

The six disjoint current-source CLI shards all passed in ordinary and race
mode:

| Test-name shard | Ordinary | Race |
|---|---:|---:|
| `^Test[A-F]` | `747.634s` | `754.071s` |
| `^Test[G-M]` | `961.659s` | `995.428s` |
| `^Test[N-O]` | `345.265s` | `351.255s` |
| `^Test[P-Q]` | `1116.576s` | `1223.690s` |
| `^Test[R-V]` | `707.962s` | `733.331s` |
| `^Test([W-Z]\|[^A-Z]\|$)` | `283.570s` | `331.380s` |

All non-CLI functional packages passed in ordinary and race mode on the same
source: APT, catalog, config, manifest, provenance, publish, repository,
serving, state, syncer, upstream, verify, views, YUM and compatibility,
including clean-delivery. The post-review delivery-ledger rerun after the
completed spec/traceability update passed in `2.758s` ordinary and `50.721s`
race.

Root `go vet ./...`, Staticcheck and `go mod verify` passed. The replaced RPM
module passed ordinary/race tests, vet and module verification; its
standalone Staticcheck continues to report only the two pre-existing
vendor-only unused symbols `openPackages` and `gpgTags`, so that check is not
misreported as green. A locally cached fixed
`govulncheck v1.6.0` found no reachable vulnerability in either module.
Static test binaries built for Darwin amd64/arm64 and Linux amd64/arm64. The
current Linux/arm64 binary passed the complete focused suite in the same
read-only, network-none Debian container.

## Current 50k and bounded-concurrency evidence

V-80 changes a shared writer used by adoption and serving workflows, so the
large-fixture gates were rerun rather than inherited from an older source
revision:

| Gate | Ordinary | Race |
|---|---|---|
| Legacy asset adoption | 50,000 unique bodies/paths; fixture `6.636s`, adopt `9m12.136s`, replay `4m40.160s`; import workers `8/8`; retained heap `+538,400B`; RSS `+134,250,496B`; full test `879.39s` | Functional-scale adoption is in the full race shards; see the explicit 50k instrumentation boundary below |
| Read-only manifest scan | 50,000 synthetic local package coordinates, 18 workers, `1.605s` | `2.167s`; no race |
| CAS materialize/reconcile | `29.575s` / `3.078s`; workers `8/8`; retained heap `+5,504B` | `25.981s` / `4.989s`; workers `8/8`; retained heap `+95,800B`; no race |
| One-change publish plan | 50,000 entries to one object in `15.626ms`; retained heap `+39,640B` | `122.421ms`; retained heap `+39,720B`; no race |
| YUM streaming | 50,000 checksum-distinct records in `7.772s`; retained heap `+24,216B` | `50.839s`; retained heap growth `0B`; no race |
| APT streaming | 50,000 records in `2.966s`; workers `4/4`, chunk peak 256, retained heap `+203,248B` | `9.042s`; workers `4/4`, chunk peak 256, retained heap `+246,696B`; no race |
| Upstream candidate spool | 50,000 candidates in `0.55s`; 29,265,920B disk spool; retained heap `+14,840B` | `8.39s`; retained heap `+26,344B`; no race |
| Full-change plan / CDN verify | 50,000 objects in `84.286ms`; CDN `99.094ms`, workers `8/8` | `972.581ms`; CDN `410.998ms`, workers `8/8`; no race |
| Incremental preflight | 50,000 entries × 100 checks in `17.589ms`, without reading the view | `81.374ms`; no race |
| Strong YUM serving | four 12,500-coordinate leaves, two generations, replay, L1 and GC passed in `361.853s`; leaf peak 4, combined worker bound 8 | same full workflow passed in `677.176s`; leaf peak 4, combined worker bound 8; no race |

The complete reproducible perf package, with a local synthetic read-only
manifest fixture, passed ordinary in `927.244s`. A deliberately broader
`-race -tags perf ./test/perf` attempt was also run, but the 50,000-row legacy
SQLite adoption remained active in `modernc` record comparison when the
operator-set 60-minute package timeout fired. It emitted no data-race, OOM or
deadlock evidence and is **not** claimed as a pass. The historical acceptance
surface does not use race-instrumented SQLite throughput as a 50k success
metric: legacy adoption is measured at 50k in ordinary mode and covered
functionally by the complete race shards, while the 50k streaming,
materialize, publish, CDN and strong-serving paths above all pass dedicated
race runs.

## External boundary

All mutations were below isolated local temporary roots. This work did not
read or write the owner-authorized `pro` bucket, Cloudflare control plane,
CO/COS, any object store, CDN, upstream package repository or production
repository. V-80 strengthens FR-28/NFR-09 local interruption, durability and
idempotency evidence only; it does not upgrade any real-cloud, provider, CDN
or production-migration status.
