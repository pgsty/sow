# Derived-state hostile-writer admission evidence

Date: 2026-07-28

Scope: V-82, local POSIX filesystems only

Baseline: `da1645b`

## Closure

SOW now establishes the effective UID as the authority for its immediate
repository directory, `.sow`, every derived control directory and every
mutable control file. Directories reject group/other writes and freeze
UID/GID/mode across their bound descriptor and current pathname. Control files
also require link count one at every bind, read/hash, publication, replay,
quarantine and removal boundary.

The live checks preserve the V-81 durable intent schema. Existing schema-v1
replacement carriers remain recoverable only after their current filesystem
objects pass the stricter admission. Unsafe existing or raced-in objects are
not chmodded, chowned or deleted.

`state.lock` publication and stale preservation now use Linux
`RENAME_NOREPLACE` or Darwin `RENAME_EXCL`; the former hardlink protocol would
have created its own temporary alias. Publication fsyncs the exact lock
directory before the post-publication hook or success. The persistent lease,
visible record and retained descriptors are rechecked for owner, mode and
single-link identity on read, validation and release.

The single-link policy is intentionally limited to control state. CAS objects,
serving/materialized packages, compatibility trust routes and offline archive
payload stages retain their legitimate hardlink topology.

## Threat-model boundary

The proved claim covers a different local UID constrained by reliable POSIX
ownership, mode and link-count semantics. It does not claim protection from
root/capability-equivalent privilege, a same-UID writer with a pre-held
writable descriptor, extended ACL grants, kernel/bind-mount mutation, or
unreliable NFS/FUSE identity mappings. See
[ADR-0043](../adr/0043-derived-state-hostile-writer-admission.md).

## Adversarial filesystem matrix

Real temporary filesystems exercise:

- writable immediate parent, state root, locks root and nested derived
  directory rejection before any canonical/control-file creation;
- pre-existing canonical control, candidate temporary, prepared replacement
  carrier, persistent lease and active lock-record hardlink aliases;
- exact evidence preservation when mode or link authority changes;
- removal of an external alias followed by deterministic recovery replay;
- active parent-mode drift, rejection, restoration and safe convergence;
- restrictive owner umask followed by descriptor-bound exact `0600` repair;
- state-root path replacement without chmodding the replacement target;
- state-lock no-replace publication before/after process death;
- publication-parent fsync failure rollback and proof that the durability
  barrier precedes the post-publication hook.

The existing offline-archive, serving, materialization and trust-route suites
remain the non-regression proof that payload hardlinks are not admitted as
control files.

## Current-source verification

The following results were rerun by the primary task after implementation and
review fixes:

| Gate | Result |
|---|---|
| final complete `internal/state` ordinary/race | PASS (`15.291s` / `23.913s`) |
| final 17 non-CLI packages ordinary/race | PASS (slowest package `152.575s` / `141.459s`) |
| final static/module gates | PASS (`go vet ./...`, repository Staticcheck profile, `go mod verify`, `git diff --check`) |
| complete `internal/cli` with default timeout | EXPECTED HARNESS LIMIT: timed out at `10m0s` while actively fsyncing the next YUM trust test; no test failure preceded the timeout |

The default CLI result is not counted as a pass. The repository's exhaustive
contract uses six disjoint shards with explicit 20/25 minute ordinary/race
timeouts. `go test -list '^Test' ./internal/cli` enumerated 881 tests, and the
same post-fix source passed every shard:

| CLI shard | tests | ordinary | race |
|---|---:|---:|---:|
| `^Test[A-F]` | 254 | `1076.269s` | `505.372s` |
| `^Test[G-M]` | 165 | `679.284s` | `690.656s` |
| `^Test[N-O]` | 75 | `467.473s` | `466.802s` |
| `^Test[P-Q]` | 178 | `866.238s` | `947.511s` |
| `^Test[R-V]` | 130 | `955.695s` | `445.557s` |
| `^Test([W-Z]\|[^A-Z]\|$)` | 79 | `380.910s` | `415.690s` |

The first ordinary `G-M` and `P-Q` attempts were deliberately discarded after
two simultaneously oversubscribed shard batches reached their 20-minute
harness limits while still doing normal filesystem work; neither emitted an
assertion failure. The isolated final reruns above passed and are the only
results counted. All 17 main-module packages outside `internal/cli` passed in
explicit ordinary and race runs. The nested patched RPM module tests passed.
Fixed `govulncheck@v1.6.0` found zero reachable and zero imported-package
vulnerabilities; two advisories in required modules were outside the call
graph. The nested RPM module reported no vulnerabilities and its fresh pinned
v1.3.0 extraction matched the fixed h1 sum and bytewise patch allowlist.

Four CGO-free CLI builds passed:

| target | bytes | SHA-256 | format |
|---|---:|---|---|
| darwin/amd64 | 58,228,592 | `8a49ca1f9f333657a2924184ead89296b68e08a86c149345a36a5d10dcb0d1e3` | Mach-O x86_64 |
| darwin/arm64 | 55,197,042 | `9201b73a44d89bb75127123a3e61c6f30658671ddbe6a974c10ee782d1c26a7a` | Mach-O arm64 |
| linux/amd64 | 56,395,522 | `757d0680b5216123a874e328b7c1a1caffce0841940c57af9780aa5f00ada715` | static ELF x86-64 |
| linux/arm64 | 52,915,867 | `92939099064b17daff68d7e1fb98ce79217473a4e1cc067e76abbba60fd7c565` | static ELF aarch64 |

The final-source local Docker client compatibility package passed in
`148.804s`. It used
real apt 1.2.35 and 2.4, EL7 YUM, and EL8/9/10 DNF to consume the generated
signed repositories. APT Packages/Release/InRelease/by-hash/history/snapshot
and exact install passed. YUM primary/filelists/other, gzip on EL7/8, zstd on
EL9/10, package and repository signatures, generation pinning, paired
transition negatives, inflight flip, Basic fallback, local token routing and
Nginx exact-route contracts passed. The apt-before-1.2 test skipped under the
frozen support-floor contract.

The fixed-digest local MinIO test passed in `0.77s`, exercising the real
S3-compatible/SigV4, conditional mutation, replay, listing, copy and delete
protocol. Rebuilding the three shipped edge bundles produced no diff, and all
47 shared Cloudflare Worker/EdgeOne contract tests passed in `121.947ms`.
These are local
protocol and executable-contract results, not provider deployment claims.

Current 50,000-entry results:

| Gate | Result |
|---|---|
| upstream candidate spool | `0.47s`; retained heap growth `0B`; disk spool `29,265,920B` |
| bounded real HTTP download concurrency | PASS (`0.43s`) |
| APT streaming | `3.107s`; retained heap `235,704B`; worker peak 4; chunk peak 256 |
| materialize + reconcile | `14.775s` + `2.567s`; workers 8/8; retained growth `144,608B` |
| one-change publish plan | `12.719ms`; one object; retained growth `40,008B` |
| YUM streaming | `6.303s`; retained growth `0B`; compressed metadata `5,892,972B` |
| incremental publish preflight | 100 iterations in `8.638ms`; no view read |

All seven migration/rollback scripts passed. The Pigsty consumer test was
reconciled read-only against the current Pigsty checkout: 22 definitions
remain SOW-hosted; six EL8/9/10 architecture defaults now point directly to
Percona and are outside the cutover set. Only temporary copies were mutated.

## Independent post-fix review

A fresh blind reviewer and a separate hostile-filesystem reviewer read the
actual post-fix implementation and tests without modifying the worktree. The
hostile-filesystem review found one final unlink seam: `state.lock` was
revalidated before, but not after, the injected before-remove boundary. SOW
now re-admits the held descriptor and current pathname immediately before
unlink. A deterministic hardlink-at-unlink test proves the foreign alias and
canonical lock remain unchanged, external alias removal permits validation,
and the same holder can safely retry release.

The focused test passed ordinary/race (`0.751s` / `1.732s`), followed by the
complete `internal/state` package (`15.291s` / `23.913s`). Both reviewers then
re-read the final production Go bytes and independently returned `[]`.

## Terminal gates

The final-source exhaustive CLI ordinary/race shards, compatibility clients,
local object-store protocol, edge contracts, static checks and four-platform
builds all passed. Two independent clean-delivery reconstructions from the
final ledger-bound source produced byte-identical product, delivery and archive
identities; the exact identities are emitted by the reconstruction command
outside the archive to avoid making the evidence self-referential. V-82 is
therefore closed as verified.

All mutation-capable tests in this report use local temporary directories,
local disposable containers and synthetic fixtures. No provider credential
was loaded; no cloud, CO/COS, Cloudflare production resource, production
repository, or `/Users/vonng/pgsty/repo` write path was accessed. The only
tooling network access was read-only Go module/vulnerability metadata through
a non-provider package proxy.
