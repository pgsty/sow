# Sync durable partial-commit recovery evidence

Date: 2026-07-12
Platform: Darwin 25.5.0 arm64, Go 1.26.5
Baseline commit: `84800a6` plus the in-progress product worktree

## Contract under test

`sow sync` commits authenticated upstream evidence and per-package provenance
before it invokes package ingestion. Package ingestion then commits canonical
beta/stable view refs before hardlink materialization and APT/YUM index signing.
Every boundary is durable, so a later failure must be reported as a partial
commit and an ordinary same-command retry must finish the projection. A retry
must not silently treat a package already present in the canonical view as
fully repaired when its Packages/repodata/signature files are absent.

The implementation uses a private `.sow/sync/<upstream>/progress.json` with
schema `sow-sync-progress/v1`, a sealed `replay.jsonl`, and an advisory
per-upstream lock held across the whole operation. Before progress can reference
it, replay is written, fsynced, atomically renamed and bound by SHA-256/count.
Replay is O(change-set), strictly digest-sorted, and contains only package
digest/size, arch/debug routing, safe basename and APT component. Progress
contains only fixed identities/digests, phase, canonical provenance commit and
completed component names. Neither file contains an upstream URL, credential,
signing material, local input path or error text. Writes are temporary-file +
fsync + rename + directory-fsync; read/update/remove require an exact `0600`
non-symlink regular file. Each canonical JSONL record is limited to 4,096 bytes,
with closed arch/basename/component field limits checked before progress is
written. Config and selector digests must match exactly even with `--recover`,
so a narrower retry cannot consume a wider operation. The lock is
descriptor-owned and therefore disappears on SIGKILL.

Once progress binds a provenance commit, SOW does not run discovery, executor or
provenance commit again. It verifies the frozen replay, imports only still-
missing change-set bytes from verified download cache when CAS lacks them,
ingests only replay records absent from canonical views, and rebuilds derived
APT/YUM projections from canonical beta/stable refs. Upstream mutation or
unavailability therefore cannot replace the recorded provenance commit. The
recovery projection may stream the complete canonical view, but it does not send
view-present packages back through `InspectPackage` or CAS import. Exact-prefix
`sync-<upstream>-*` transaction scratch directories, including the current
directory and SIGKILL residue, are removed only after convergence; symlink or
special-file residue fails closed. Progress is removed last.

## Real fault boundaries

The tests in `internal/cli/sync_recovery_test.go` use production CLI functions,
an on-disk Git canonical store, real SHA-256 CAS/hardlinks, real DEB/RPM parsers,
real OpenPGP signatures, and signed APT/YUM repositories served over local TLS.
Hooks are used only for two precise logical crash boundaries; the critical
post-view failures use ordinary filesystem errors, not hooks or mock adapters.

| Boundary | Injection | Durable evidence before failure | Replay evidence |
|---|---|---|---|
| after provenance commit | hook immediately after commit, then delete the served upstream tree | receipt/evidence, sealed replay and commit exist; error includes commit, phase and same-command retry action | ordinary retry makes zero additional upstream requests, preserves receipt bytes/commit, ingests from frozen cache and removes progress |
| between two APT components | hook after `contrib`, before `main` | `apt:contrib` recorded complete; both provenance receipts exist | retry ingests exactly one missing component, both component indexes converge, next retry is a no-op |
| APT view commit before materialization | a real regular file occupies `.sow/materialized/beta/apt/test` | canonical beta view and provenance committed while Packages/InRelease cannot be installed | first retry reaches durable `projection-repair` and fails on the same obstruction without changing commit; after deleting both upstream and obstruction, next retry makes zero upstream requests, emits no `added format=deb`, and converges Packages/Release/InRelease/payload/CAS hardlink |
| YUM view commit before materialization | a real regular file occupies `.sow/materialized/beta/yum/test/x86_64` | canonical beta view and RPM provenance committed while repodata cannot be installed | remove obstruction; ordinary retry emits recovery projection and no `added format=rpm`; payload, repomd and `.asc` converge |
| SIGKILL | a child test process writes committed-phase progress, holds the real advisory lock and creates transaction residue, then is killed | progress and transaction directory remain on disk; no stale advisory lock remains | a new process lock opens, decodes progress, removes current+orphan exact-prefix trees, then removes progress |

Additional negative tests prove same-upstream concurrency fails closed, config
and selector mismatch cannot be rebound by `--recover`, progress/lock symlinks
are rejected, replay field/record size boundaries close before progress commit,
atomic writes leave no temporary file, and exact-prefix cleanup does not touch
another upstream.

## Reproduction and observed results

All commands below ran successfully in this worktree:

```text
$ go test ./internal/cli -run '^(TestSync|TestBearerTransport)' -count=1 -v
PASS
ok github.com/pgsty/sow/internal/cli 8.613s

$ go test -race ./internal/cli \
    -run '^(TestSyncProgress|TestSyncOperation|TestSyncTransaction|TestSyncRecovery)' \
    -count=1
ok github.com/pgsty/sow/internal/cli 8.185s

$ go vet ./internal/cli
(no output; exit 0)

$ go test ./internal/upstream \
    -run '^TestStreamingCandidateStoreFiftyThousandBoundedMemory$' -count=1 -v
50k candidates: baseline_heap=2268824 retained_heap=2281352 growth=12528 \
disk_spool=29265920 bytes
PASS
ok github.com/pgsty/sow/internal/upstream 4.386s
```

The 50,000-candidate test classifies every candidate as already present with
zero downloads while retaining only 12,528 bytes of heap growth over baseline.
The APT/YUM post-view obstruction tests then prove the CLI recovery branch does
not invoke package add/inspection for view-present inputs. Together these bind
the large-present-set streaming property to the real canonical projection
repair behavior; they do not claim that an intentional recovery rebuild is
O(change). Full projection is restricted to an operation with durable residue,
while the completed ordinary retry removes progress and returns to the normal
change-set path.

## Requirement mapping

- FR-14: additive sync, resumable download/CAS, ordinary retry and no duplicate
  ingestion.
- FR-16 / NFR-08: provenance commit identity and byte-identical receipt replay.
- NFR-03: normal operation remains change-set based; full canonical projection
  is an explicit interrupted-operation repair and does not re-inspect 50k
  package bodies.
- NFR-09 and the local part of FR-28: interruption is detected, reported,
  safely replayed and cleaned. This is local sync evidence; it does not replace
  the separate real-cloud publication recovery gate.
