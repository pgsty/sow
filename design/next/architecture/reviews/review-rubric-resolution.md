# Architecture Reviewer Gate — resolution recheck

> **Historical pre-implementation snapshot.** 本文保留修订过程中的 BLOCKED/PARTIAL 状态；
> 后续 final closure 与当前实现证据优先，见
> [`../../evidence/2026-08-05-implementation.md`](../../evidence/2026-08-05-implementation.md)。

- **Date:** 2026-08-05
- **Intent:** validate the revised `design/next` contract against the 11 findings in
  `review-rubric.md`
- **Reviewed:** `design/next/specs/*`, `ARCHITECTURE-SPINE.md`, both memlogs,
  `design/next/research/*`, current `internal/v2/state`, and current Cloudflare R2
  API documentation
- **Mechanical lint:** PASS (`lint_spine.py`, 0 findings)
- **Original-finding closure:** **9 RESOLVED, 2 PARTIAL, 0 OPEN**
- **New findings:** **3 — 1 critical, 1 high, 1 medium**
- **Semantic gate:** **BLOCKED**

## Gate verdict

The revision materially repairs the architecture. The new
`state-publication.md` cleanly separates Repository-owned Built Generations from
target-owned publication state; fixes the per-view commit unit and forward recovery;
defines APT by-hash behavior; separates steady Generations from transition
inventories; freezes an RPM export profile; and closes the previous path, uniqueness,
and deletion-precondition gaps.

It is still not safe to hand to implementation as an approved design. One original
critical and one original medium finding remain partial, and the newly chosen first
object target cannot satisfy the design's own mandatory deletion primitive. In
addition, the same/ancestor prefix exclusion promise has no atomic ownership
namespace, so its compare-and-set guarantee is not implementable from an exact-prefix
marker alone.

## Original finding resolution

| Original finding | Status | Resolution evidence / remaining gap |
| --- | --- | --- |
| **CR-1 — Built Generation and target publication state have conflicting owners** | **RESOLVED** | `state-publication.md:34-51` defines Repository-owned Built Generation/Changeset/local roots and target-owned Attempt/Checkpoint/inventory/grace/delete evidence, including independently lagging targets. AD-17 repeats the same ownership split. |
| **CR-2 — Pointer-last is not a Repository publication transaction** | **PARTIAL** | `state-publication.md:111-138` now fixes the commit unit, persisted attempt, commit intent, expected-remote CAS, bounded mixed-view window, forward replay, verification, and Applied Checkpoint. However `migration.md:50-52` says recovery after commit intent is forward-only while `migration.md:82-90` permits restoring v0.2 pointers before alias deletion and also calls schema migration forward-only. The text does not say whether this is an explicitly authorized operator-only serving fallback, a journaled rollback state, or a prohibited automatic rollback. Two implementations can still make opposite recovery choices after the same crash. Freeze the transition/substate, authorization, CAS preconditions, and terminal effect—or remove the rollback branch. |
| **CR-3 — APT pointer-last is incomplete without a by-hash support contract** | **RESOLVED** | `state-publication.md:153-163` requires `Acquire-By-Hash: yes`, fixes immutable/stable alias/pointer order, limits the race-free promise to clients actually using by-hash, and explicitly accepts weaker non-by-hash availability. `acceptance-matrix.md:11,19` adds stale-Release concurrent fetch coverage. |
| **HI-1 — `changes 0`, retained metadata, and migration grace describe incompatible physical trees** | **RESOLVED** | `state-publication.md:95-109` limits ordinary Changes to terminal steady state, fails closed during transitions, and places retained exact metadata bytes in private verified state. `migration.md:40-75` gives C2 aliases their own journal/inventory until a terminal Generation is committed. |
| **HI-2 — External export does not yet define an export projection** | **RESOLVED** | `compatibility.md:35-74` freezes `sow-rpm-leaf-v1`: input identity, membership closure, output tree, leaf-local hrefs, RPM-MD regeneration/signing, manifest, last-installed marker, ownership/replace rules, copy default, hardlink limits, and default EL reposync acceptance. |
| **HI-3 — The one-payload invariant lacks an explicit reverse-uniqueness rule** | **RESOLVED** | `state-publication.md:91-93` and `repository-layout.md:114-129` require digest-to-path and path-to-digest uniqueness and retain the brownfield rule that an existing digest is idempotent only when all immutable facts match. |
| **HI-4 — URI canonicalization is not specified tightly enough for one shared renderer/checker** | **RESOLVED** | `repository-layout.md:62-84` fixes typed unescaped input, directory-base trailing slash, POSIX segment calculation, uppercase RFC 3986 percent encoding, XML-escape order, decode-once round trip, rejection rules, and shared golden vectors. Renderer and checker must call one pure function. |
| **HI-5 — The `/pool/...` rejection rationale is not reality-checked for EL9 DNF4** | **RESOLVED** | `repository-layout.md:86-93` now separates generic host-root URI behavior, DNF4's leading-slash stripping, and reposync's local absolute-path containment behavior. `acceptance-matrix.md:10` preserves all three as separate observations. |
| **HI-6 — Remote deletion is called evidence-fenced without an enforceable fence** | **RESOLVED** | `state-publication.md:165-178` binds deletion to repository/target/checkpoint/inventory/pointer/object identities, an immutable deadline, conditional operation, post-delete storage/public absence, and fail-closed disablement when any required primitive is unavailable. The new R2 release-gate contradiction below is a target-selection error, not a reopening of this abstract contract. |
| **ME-1 — Post-deletion rollback can be read as permission to restore canonical C2 aliases** | **RESOLVED** | `migration.md:84-89` says any regenerated C2 artifact is external to the canonical Repository/prefix and cannot be a Generation, pointer target, publish input, or GC root. |
| **ME-2 — “Supported” client and target matrices have no frozen minimum set** | **PARTIAL** | `state-publication.md:180-193` and `acceptance-matrix.md:10-17,28-31` now name AlmaLinux 9/DNF4, Fedora 42/DNF5, Ubuntu 22.04/APT 2.4, Debian 12/APT 2.6, and Cloudflare R2. But the exact pinned images/digests and ordinary HTTP origin/proxy profile remain future evidence obligations, not frozen matrix inputs. Different teams can still select materially different EL9 minors, DNF builds, and URL-normalization/cache stacks while claiming the same minimum gate. Freeze the initial fixture identities and HTTP serving profile, while retaining other proxies as unverified cells. |

### Closure count by original severity

| Original severity | RESOLVED | PARTIAL | OPEN |
| --- | ---: | ---: | ---: |
| Critical (3) | 2 | 1 | 0 |
| High (6) | 6 | 0 | 0 |
| Medium (2) | 1 | 1 | 0 |
| **Total (11)** | **9** | **2** | **0** |

## New blockers and findings

### NEW-CR-1 — The mandatory Cloudflare R2 gate cannot perform the required conditional delete

**Disposition:** change the release matrix or change the first target before
implementation.

**Evidence**

- `state-publication.md:171-178` requires an atomic conditional delete and correctly
  disables remote deletion when the target lacks it.
- The same file at `:188-189` nevertheless requires the first real Cloudflare R2
  target to pass “conditional deletion.”
- `acceptance-matrix.md:17,22,28-30` makes both real R2 and evidence-fenced GC minimum
  release gates.
- Cloudflare's current
  [Workers API reference](https://developers.cloudflare.com/r2/api/workers/workers-api-reference/)
  defines `delete(key)` without an options/precondition argument; its conditional
  operations apply only to Get and Put.
- Cloudflare's current
  [S3 compatibility table](https://developers.cloudflare.com/r2/api/s3/api/)
  lists conditional operations for Head/Get/Put but none for `DeleteObject` or
  `DeleteObjects`. The
  [R2 consistency contract](https://developers.cloudflare.com/r2/reference/consistency/)
  says concurrent Put/Delete on one key is last-writer-wins.

**Why this blocks**

A Head/GET followed by an unconditional Delete is a time-of-check/time-of-use race: a
foreign writer can replace the key between the two calls and SOW will delete the new
object. Conditional Put of a tombstone followed by Delete has the same final race.
Therefore a direct R2 adapter cannot both obey the deletion fence and pass the stated
minimum matrix.

**Required resolution**

Keep the fence. Make the initial R2 gate prove publication, checkpoint recovery, and
fail-closed **remote-delete disabled** behavior, then test conditional remote deletion
on a target that actually offers an atomic object-version precondition; or replace R2
as the first full-GC target. A serialized proxy/control plane is an architectural
change, not evidence that direct R2 has conditional delete, and would also have to
exclude out-of-band writers.

### NEW-HI-1 — Prefix-overlap ownership has no atomic arbitration namespace

**Disposition:** discuss and freeze the ownership registry before implementing AD-25.

**Evidence**

- `state-publication.md:22-32` requires canonical target identity, rejects same and
  ancestor/descendant prefixes for different owners, and requires owner CAS before
  the first write.
- AD-18 allows only `pool/ + dists/` in the public prefix, while
  `ARCHITECTURE-SPINE.md:168-175` defers the physical location of owner/checkpoint
  records. `SPEC.md:82-88` also places “global CAS” outside the design.

**Adversarial divergence**

An exact-prefix `.sow-owner` object violates the canonical public tree and cannot
atomically reject concurrent claims for `repos/a` and `repos/a/b`. A control record
outside the prefix preserves the public tree, but requires a target-wide registry,
credential scope, root-prefix rule, and a common CAS serialization point that the
current contract neither owns nor explicitly permits. Check-then-create at two
different keys is not atomic; both publishers can pass preflight and later overwrite
or delete shared keys.

**Required resolution**

Define a target-scoped control namespace outside every canonical publish prefix and an
atomic prefix-trie/registry claim protocol (including empty prefix, concurrent sibling
claims, restore/fork, release, and compromised/out-of-band state). State explicitly
that this narrow ownership-registry CAS is allowed and what credential must access it.
If no such control plane is acceptable, weaken AD-25 to a local preflight claim and do
not advertise remote cross-owner exclusion.

### NEW-ME-1 — The authoritative memlogs were not reconciled with the revision

**Disposition:** append the ratified decisions through the architecture workflow
before handoff; do not rewrite history.

`design/next/specs/.memlog.md` still records only CAP-1 through CAP-5 and the original
layout direction. `design/next/architecture/.memlog.md` stops before the new identity,
per-target publication, by-hash, export, transition, and AD-25/26/27 decisions, while
the spine now declares `status: approved-unimplemented`. A future update resumed from
the authority log can legitimately erase the very resolutions being approved here.

## Reality and brownfield check

- Current `internal/v2` still implements C2 aliases and the v0.2 Generation ledger;
  it contains no `repository_id`, target Publication Attempt, Applied Checkpoint, or
  GraceRecord. The revised documents correctly label these as approved but
  unimplemented, so this is evidence status—not a defect by itself.
- The retained GenerationFile/FileChange phase model matches current v0.2 state,
  including delete changes using the `delete` phase; the revision does not invent an
  incompatible replacement wire for that part.
- The EL9 parent-relative-href evidence remains a valid ordinary-client/repo-sync
  distinction; the revision no longer overgeneralizes leading-slash behavior.
- Cloudflare R2 is strongly consistent, but consistency does not create an atomic
  delete precondition. Last-writer-wins is precisely why the evidence fence matters.

## Good-spine rubric after revision

| Rubric item | Result | Notes |
| --- | --- | --- |
| Fixes all real divergence points one level down | **PARTIAL** | Most original seams are fixed; migration rollback and prefix-claim arbitration still diverge. |
| Every AD is enforceable and prevents its stated divergence | **FAIL** | AD-25 cannot enforce ancestor overlap under concurrency without a shared ownership registry. |
| Deferred contains no hidden architectural decision | **FAIL** | Deferring owner-record location currently hides namespace, credentials, and serialization scope. |
| Named technology is current/reality-checked | **FAIL** | The required R2 conditional-delete cell contradicts current official R2 APIs. |
| Ratifies rather than contradicts brownfield | **PASS** | Generation/Changeset phases, SHA ownership, journals, and fail-closed transitions extend the current model coherently. |
| Covers the driving SPEC capabilities | **PARTIAL** | CAP-1 through CAP-7 are mapped, but the mandatory object-target/GC success signal is presently unsatisfiable. |
| Operational/environmental envelope is decided or deferred safely | **FAIL** | HTTP fixture identity and remote owner-control scope remain open; R2 deletion is not safely satisfiable. |

## Gate condition

Do not treat `status: approved-unimplemented` as implementation handoff approval yet.
Close the CR-2 migration rollback ambiguity, split or replace the R2 deletion gate,
freeze an atomic target ownership registry, pin the initial HTTP/client fixtures, and
append the ratified revision decisions to both memlogs. Then rerun lint, rubric,
reality, and adversarial gates against the same frozen checkout.
