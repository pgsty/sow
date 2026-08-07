# Architecture Reviewer Gate — Repository-scoped single-payload design

> **Historical pre-implementation snapshot.** 以下 finding 是最初 blocked gate 的审计记录，
> 不是当前 0.3 缺陷清单；resolution/final 与
> [`../../evidence/2026-08-05-implementation.md`](../../evidence/2026-08-05-implementation.md)
> 记录后续状态。

- **Date:** 2026-08-05
- **Intent:** validate
- **Reviewed:** `design/next/specs/*`, `ARCHITECTURE-SPINE.md`, architecture memlog, `design/next/research/*`, and the inherited v0.2 spine
- **Mechanical lint:** PASS (`lint_spine.py`, 0 findings)
- **Semantic gate:** **BLOCKED**
- **Finding count:** 11 — 3 critical, 6 high, 2 medium

## Gate verdict

The core layout choice is coherent: one Repository/publish prefix owns one canonical
`pool/`, `dists/` is metadata-only, APT uses archive-root-relative `Filename: pool/...`,
RPM views compute parent-relative hrefs, default EL `reposync` is an explicitly accepted
limitation, and compatibility aliases are external artifacts.

The design is nevertheless not implementation-ready. The blocking gap is the
publication state model: Repository-scoped Built Generations, independently lagging
target prefixes, multiple mutable protocol entries, APT by-hash/stable aliases, stale
client grace, and local/remote GC do not yet form one enforceable transaction and
reachability contract. Two implementations can obey every current AD and still make
incompatible—and in some cases unsafe—publication or deletion choices.

## Requested-area assessment

| Area | Result | Assessment |
| --- | --- | --- |
| Repository/publish-prefix single payload | PARTIAL | Boundary and physical layout are clear, but Build Generation versus per-target publication ownership is contradictory, and reverse uniqueness from Package Object to Pool path is not explicit. |
| Canonical `pool/ + dists/` | PASS | Consistently fixed in SPEC, layout, spine, publication, migration, and research; canonical per-view payload aliases are forbidden. |
| RPM parent-relative href | PARTIAL | Adopted consistently and backed by the EL9 PoC, but URI escaping/resolution is not fully specified and the `/pool/...` rationale conflicts with actual DNF4 behavior. |
| APT archive-root-relative `Filename` | PASS | `Filename: pool/...` without a leading slash is consistently required; package bytes remain in the root Pool. Publication atomicity for stable APT index aliases remains unresolved. |
| `reposync` limitation | PASS | Default EL rejection and community `--safe-write-path` best effort are separated correctly from ordinary DNF compatibility. |
| External export | FAIL | Ownership boundary and copy default are clear, but the export projection, metadata rewrite/signing, closure, and exact compatibility gate are not specified. |
| Publication and GC | FAIL | Phase order is stated, but target checkpoint ownership, crash recovery, APT publication semantics, grace roots, and evidence-fenced deletion are not executable invariants. |

## Critical findings

### CR-1 — Built Generation and target publication state have conflicting owners

**Disposition:** discuss before implementation.

**Evidence**

- `SPEC.md:63` says Generation, Changeset, publication manifest, and GC are bounded by
  one Repository and one target publish prefix.
- `ARCHITECTURE-SPINE.md:50-54` repeats that Package Object, Generation, Changeset,
  checkpoint, authorization, and GC closure all have the composite
  Repository/publish-prefix boundary.
- `publication-retention.md:13-15` permits one Repository to publish to multiple
  target/prefix pairs.
- `publication-retention.md:63-71` defines one GC closure but contains no applied or
  in-flight per-target checkpoints.
- The inherited brownfield owner remains one Repository SQLite and one Repository
  Generation ledger (`v0.2` AD-3 and current state model).

**Why this blocks implementation**

Targets can legitimately lag: target A may have Generation 12 applied while target B
still serves Generation 10. One compliant implementation can treat Generation and GC
as target-neutral Repository state; another can instantiate them per target because
AD-17 says the boundary includes the target prefix. They will disagree on Changeset
identity, retention, retry, and when a Pool object may be deleted locally or remotely.

**Required resolution**

Name separate owners and invariants:

1. Repository-scoped, target-neutral Built Generation and Changeset;
2. target-scoped Publication Attempt, Applied Checkpoint, observed Inventory, grace
   deadline, and deletion evidence;
3. local GC roots, including any non-terminal operation that still needs source bytes;
4. remote GC roots computed from that target's applied/checkpointed state, not another
   target or merely the local current Generation.

The SDK/wire format may remain Deferred; these ownership and transition semantics may
not.

### CR-2 — Pointer-last is not a Repository publication transaction

**Disposition:** discuss before implementation.

**Evidence**

- `ARCHITECTURE-SPINE.md:86-90` and `publication-retention.md:27-40` require
  payload → immutable metadata → protocol pointers → grace → delete.
- A Repository can have many RPM `repomd.xml` entries plus APT `Release`/`InRelease`
  entries; `migration.md:45-50` switches them individually.
- `acceptance-matrix.md:22` requires every migration crash point to converge to a
  complete old or new generation.
- The canonical layout forbids an additional generation directory or root indirection,
  and ordinary object stores do not atomically replace multiple keys.

**Why this blocks implementation**

Pointer-last prevents a single pointer from referencing a missing immutable object; it
does not make several pointer writes atomic. A crash after two of ten pointers leaves a
mixed Repository. The documents specify neither whether mixed per-view generations are
legal nor a durable target publication journal, resume direction, compare-and-swap
precondition, or terminal checkpoint. Implementations that roll forward, roll back, or
declare per-view commits can all claim conformance.

**Required resolution**

Fix the commit unit and recovery state machine. Either explicitly permit independently
committed views and redefine Repository Generation/acceptance around that fact, or add
a Repository-level indirection that makes one visible commit possible. In either case,
specify idempotent replay, expected-current pointer/ETag checks, roll-forward versus
rollback rules, and the exact condition that records a target checkpoint as applied.

### CR-3 — APT pointer-last is incomplete without a by-hash support contract

**Disposition:** discuss before implementation.

**Evidence**

- `SPEC.md:70` says APT by-hash and old-client grace continue to hold.
- `publication-retention.md:17-22` groups checksum/by-hash metadata separately from
  `Release` and `InRelease` pointers, but does not classify stable
  `Packages`, `Packages.gz`, or `Sources` aliases.
- `acceptance-matrix.md:10` requires APT file/HTTP use but names no minimum APT version
  or mandatory Acquire-By-Hash behavior.

**Why this blocks implementation**

On a non-atomic object store, overwriting stable `Packages.gz` before `Release` lets a
client holding the old Release fetch bytes with the wrong checksum; flipping Release
first creates the inverse race for a new client. By-hash removes this race only for
clients that use the advertised hash path. Grace retention of payloads does not repair
an index checksum race.

**Required resolution**

Define whether by-hash is mandatory for supported remote APT clients and make the
publication phases explicit: immutable by-hash objects, any stable compatibility
aliases, Release/InRelease, cache policy, and deletion grace. If non-by-hash clients are
supported, state the weaker availability guarantee or introduce a serving/commit
mechanism that actually provides it. Add the corresponding stale-Release concurrent
fetch test.

## High findings

### HI-1 — `changes 0`, retained metadata, and migration grace describe incompatible physical trees

**Disposition:** discuss and tighten AD-21/AD-23.

**Evidence**

- `SPEC.md:45-46` requires `changes 0` to equal every regular file in `pool/ + dists/`.
- `publication-retention.md:41-42` calls it the current Built Generation's complete
  tree and excludes historical C2 aliases.
- `migration.md:47-50` physically retains those C2 aliases during grace but excludes
  them from the new Generation manifest.
- `publication-retention.md:53-59` and AD-21 retain old metadata identities and
  refsets, without fixing whether the old metadata bytes live in `dists/`, `.sow`, or a
  separate publication inventory.

**Impact**

During migration grace, the physical tree contains files that the supposedly exact
manifest excludes. Retained checksum-named metadata creates the same ambiguity after
normal builds. A scanner-derived manifest and a ledger-derived manifest will disagree,
and neither storage location nor rollback source for retained metadata is fixed.

**Required resolution**

Separate and name the logical Generation manifest, the current physical delivery
inventory, and grace/migration-only inventory—or require one manifest to include all
three classes. Specify where retained metadata bytes live, how they are republished,
and whether `changes` is rejected while layout migration is non-terminal. Align the
“exact tree” acceptance assertion with that model.

### HI-2 — External export does not yet define an export projection

**Disposition:** discuss before CAP-6 implementation.

**Evidence**

- `compatibility.md:34-55` fixes ownership, copy default, and disposal, but its sample
  permits `pool/... or Packages/...` and does not fix which metadata is copied or
  regenerated.
- Canonical RPM metadata contains parent-relative hrefs; copying it unchanged into a
  standalone leaf does not make the leaf self-contained.
- `acceptance-matrix.md:20-21` checks a static server/repo tool but does not require
  default `reposync`, despite export being the stated fallback for that incompatibility.

**Impact**

Two exporters can both obey AD-22 while selecting different package closures, using
different leaf layouts, preserving versus rebasing hrefs, and copying versus rebuilding
signatures. One result can silently point back outside the export. Module metadata,
neutral packages, source/debug packages, completion markers, and atomic replacement are
also unowned.

**Required resolution**

Fix the input identity (Dist/view plus Built Generation), complete package closure,
output layout, href/Filename policy, metadata regeneration and signing policy, atomic
completion marker, and overwrite ownership. Add default EL `reposync` against the RPM
export to the acceptance matrix if that is its promised fallback.

### HI-3 — The one-payload invariant lacks an explicit reverse-uniqueness rule

**Disposition:** autofix by ratifying the existing state invariant.

**Evidence**

- CAP-1 requires one canonical path per Package Object.
- `repository-layout.md:101-104` defines SHA-256 identity, a source/filename-derived
  Pool path, and conflicts for different bytes at one path, but not the inverse case:
  the same SHA-256 arriving with different source/filename/path facts.
- Current brownfield state uses SHA-256 as the `package_objects` primary key and rejects
  changed immutable facts for an existing digest.

**Impact**

An implementation can reuse the first path, create a second path because the candidate
filename differs, or reject the add. The second behavior violates CAP-1 while the
current prose does not explicitly forbid it.

**Required resolution**

State the repository-wide bijection/decision explicitly. The smallest brownfield-
compatible rule is: an existing SHA-256 is idempotent only when all immutable package
facts, including canonical Pool path, match; otherwise it is a hard conflict. Checker,
manifest, migration, and import must enforce both digest→path and path→digest uniqueness.

### HI-4 — URI canonicalization is not specified tightly enough for one shared renderer/checker

**Disposition:** discuss and make the pure-function contract normative.

**Evidence**

- `repository-layout.md:61-70` requires segment escaping and rejection of
  non-canonical escaping, but gives no exact encoding alphabet, UTF-8 rule, percent-case
  rule, or XML-escaping order.
- The generated RPM href necessarily contains literal leading `..` segments, while
  encoded traversal is rejected; the boundary between generated navigation segments
  and package-path data segments is not formally stated.
- `compatibility.md:73-80` delegates proxy normalization differences to target tests,
  but `check` still needs one deterministic local interpretation.

**Impact**

Implementations based on `path.Rel`, `net/url`, pre-escaped strings, or XML-first
escaping can emit different href bytes or disagree on `%2e`, `%2F`, `%25`, Unicode, and
double-encoding. That is both a compatibility seam and a containment seam.

**Required resolution**

Define typed inputs as unescaped canonical Repository paths; specify relative segment
calculation, the exact percent-encoding/case algorithm, XML attribute escaping as a
later layer, and a resolver that accepts only the generated literal parent prefix while
rejecting encoded separators/traversal and non-canonical re-encodings. Add adversarial
round-trip fixtures shared by renderer and checker.

### HI-5 — The `/pool/...` rejection rationale is not reality-checked for EL9 DNF4

**Disposition:** autofix the rationale; retain the rejection unless live evidence changes the decision.

**Evidence**

- `repository-layout.md:72-78` and `rpm-shared-pool-reposync-compatibility.md:109-114`
  assert that a leading slash binds the HTTP host root.
- Current DNF4 explicitly applies `location.lstrip("/")` before joining a package
  location to package/repository base URLs:
  [DNF package.py lines 270-282](https://github.com/rpm-software-management/dnf/blob/master/dnf/package.py#L270-L282)
  and
  [DNF repo.py lines 586-608](https://github.com/rpm-software-management/dnf/blob/master/dnf/repo.py#L586-L608).
- `reposync` independently treats a leading-slash location as an absolute local path
  before its safe-write containment check.

**Impact**

For the EL9/DNF4 client at issue, `/pool/...` is not reliably interpreted according to
generic RFC host-root semantics; it may become view-base-relative remotely while still
escaping the local reposync destination. The option remains unsuitable, but the present
reasoning predicts the wrong request URL and could lead tests/checker code to encode the
wrong client model.

**Required resolution**

Document generic URI resolution and each supported client's observed behavior
separately. Add an EL9 file/HTTP/default-reposync fixture for a leading-slash location;
reject it canonically because behavior is client-dependent, not prefix-relocatable, and
unsafe for reposync—not because every DNF necessarily sends a host-root request.

### HI-6 — Remote deletion is called “evidence-fenced” without an enforceable fence

**Disposition:** discuss together with CR-1.

**Evidence**

- `publication-retention.md:27-40` and AD-23 require verification, grace, and
  evidence-fenced deletion.
- `publication-retention.md:77-83` checks that pending deletions are not locally
  reachable, but does not bind a deletion to the target inventory version, pointer
  ETag/version, applied checkpoint, or grace start event.
- `ARCHITECTURE-SPINE.md:147` defers the remote checkpoint wire and CDN implementation.

**Impact**

An out-of-band writer, retried stale plan, ABA replacement at the same key, or a second
target state can invalidate a locally computed delete list. Digest verification of the
local Package Object does not prove the remote key still represents the observed old
object or that every relevant pointer has advanced.

**Required resolution**

Keep provider APIs Deferred, but require target deletion preconditions: checkpoint and
inventory identity, expected remote object version/ETag or digest, applied-pointer
proof, a persisted grace start/deadline, and idempotent “already absent” handling.
Define how unexpected remote mutation changes target state to error/reconcile rather
than proceeding with deletes.

## Medium findings

### ME-1 — Post-deletion rollback can be read as permission to restore canonical C2 aliases

**Disposition:** autofix wording.

`migration.md:60-65` correctly forbids merely restoring an old pointer after aliases
are deleted, but then allows a “compatibility export/C2 migration artifact” without
fixing its location. State that any regenerated C2 artifact is external to the
canonical Repository/publish prefix and cannot become a Generation, pointer target,
publish input, or GC root. Otherwise this escape hatch conflicts with CAP-1 and AD-20.

### ME-2 — “Supported” client and target matrices have no frozen minimum set

**Disposition:** discuss or move to an explicit open item with a release-blocking revisit condition.

`acceptance-matrix.md:10-16` refers to supported APT, EL, DNF, architectures, and
object-store targets, while the research's direct RPM proof is AlmaLinux 9.8 / DNF
4.14.0. No document names the minimum APT distributions/versions, EL releases, DNF4/5
versions, HTTP server/proxy profiles, or which one of R2/S3-compatible/COS is the
release gate. Two teams can run materially different matrices and both claim the
minimum gate. Freeze the initial matrix or explicitly mark the architecture `partial`
until it exists.

## Good-spine rubric summary

| Rubric item | Result | Notes |
| --- | --- | --- |
| Fixes all real divergence points one level down | FAIL | Publication/checkpoint/GC and export implementations can diverge. |
| Every AD is enforceable and prevents its stated divergence | FAIL | AD-17, AD-21, and AD-23 lack the state and commit semantics needed to enforce them. |
| Deferred contains no hidden architectural decision | FAIL | Checkpoint wire may be deferred, but checkpoint ownership, preconditions, and recovery semantics may not. |
| Named technology is current/reality-checked | PARTIAL | Official DNF4/5, createrepo_c, libcurl, and S3 references exist; the leading-slash DNF4 claim is inaccurate and the supported-version matrix is absent. |
| Ratifies rather than contradicts brownfield | PARTIAL | Ownership, journals, SHA identity, and path safety are largely inherited correctly; Package Object reverse uniqueness and per-target state should explicitly ratify or extend current state. |
| Covers the driving SPEC capabilities | PARTIAL | CAP-1 through CAP-5 are structurally represented; CAP-4/5/6 lack executable publication, retention, and export contracts. |
| Operational/environmental envelope is decided or deferred safely | FAIL | Local POSIX single-writer behavior is inherited, but remote concurrency, retry, checkpoint, cache, and deletion envelopes are not fixed. |

## Gate condition

Do not hand this spine to implementation as `status: final`. Resolve CR-1 through CR-3
and HI-1/HI-2/HI-6 first; then tighten the deterministic identity/path rules and freeze
the initial compatibility matrix. Re-run mechanical lint and the semantic gate after
the SPEC companions and spine are reconciled together.
