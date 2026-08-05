# SOW V2 P0-P1 Architecture Rubric Review

Date: 2026-08-01
Reviewer lens: BMad `good-spine` rubric walker
Verdict: **FAIL — two blocking contradictions/open decisions prevent this from being a final P0/P1 build substrate.**

## Scope and evidence

Reviewed in full:

- `ARCHITECTURE-SPINE.md`
- `docs/architecture-v2.md`
- `api-contract.md` — SHA-256 `d9d1494bf0f124e708a0bdd378623df65ed4183e2edf1f272d190e23d7141f9f`
- `prd.md` — SHA-256 `c7184f7233bfc74e365c4ebe721ad4a9031c919d8f0ea6447ab392f0a1078165`
- `addendum.md` — SHA-256 `f4c8cfba176714c87e72fd0731e57cd55f753bb9c4f45ba30529798fcb37fa59`

Deterministic spine lint passed with zero findings. The findings below are semantic and structural: enforceability, unresolved dimensions, and P0/P1 preservation.

## Critical findings

### C1 — `--pigsty` has two incompatible commit orders; the generic rule permits dangling indexes

**Evidence**

- The normative order requires new metadata to stop referencing cleanup candidates **before** packages are recovery-renamed, with `repo_complete` switched last (`api-contract.md:244-260`; `addendum.md:49-63`).
- `docs/architecture-v2.md:101-115` states that safe order correctly.
- The same document later states a generic order of “install package bytes or execute recovery rename” followed by replacing the RPM/APT protocol pointer (`docs/architecture-v2.md:174-185`). Applied to `--pigsty`, this removes a package while the old metadata may still reference it.
- AD-9 binds all P0 metadata and says “protocol pointer last” without carving out cleanup transactions (`ARCHITECTURE-SPINE.md:75-79`), so an implementation following the spine can choose the unsafe interpretation.

**Why this fails the rubric**

The Rule does not prevent its stated divergence and contradicts the P0 crash-safety contract. Two units can implement opposite orders, and one order creates a client-visible dangling reference during the commit window.

**Required resolution**

Autofix the spine and implementation architecture by separating three orders:

1. install immutable/checksum-addressed metadata;
2. switch RPM and DEB metadata pointers while all old packages still exist;
3. recovery-rename cleanup packages;
4. switch the completion marker last.

“Pointer-last” remains valid within metadata publication, but the completion marker—not the package index pointer—is the final pointer of a destructive Pigsty operation. Make this exception explicit in AD-9 and remove the contradictory generic step.

### C2 — The mandatory YUM relative-Pool gate is unresolved while the spine is marked final and the layout/schema are already seeded

**Evidence**

- The contract forbids freezing the Managed YUM layout, SQLite view path, or renderer API until real DNF/YUM plus reposync prove relative Pool locations (`api-contract.md:50-75`; `addendum.md:91-93`; `prd.md:392-398`).
- The spine is `status: final`, labels AD-13 `[ADOPTED]`, yet its Rule says the P1 path must not be frozen until that proof exists (`ARCHITECTURE-SPINE.md:8,99-103`).
- `docs/architecture-v2.md` already seeds `dist_architectures.view_path`, calls the candidate layout the “target layout”, and names `../../../pool/...`, while simultaneously calling it gated (`docs/architecture-v2.md:131-143,189-203`).
- Neither reviewed architecture artifact cites a reproducible passing PoC or its output.

**Why this fails the rubric**

This is a load-bearing structural dimension left in a contradictory state: adopted/final and unresolved at once. Builders can either freeze the candidate or wait/redesign, producing incompatible storage and renderer APIs.

**Required resolution**

Discuss/resolve before P1 implementation freezes these seams. Either:

- attach the reproducible fixture, exact client commands, outputs, and passing conclusion, then adopt the proven layout and href computation; or
- mark the spine non-final, make the layout/view-path/renderer seam an explicit blocking open question, and avoid concrete schema/API commitments until the PoC passes.

## High findings

### H1 — `config check` is not bound to state-aware architecture-removal validation

**Evidence**

- The API requires removing a family still referenced by Dist configuration, Membership, or Built Generation to fail; in P1, `config check` is the available read-only enforcement path (`api-contract.md:278-290,373-395`; `prd.md:226-235`).
- AD-11 only says unknown input families fail before mutation (`ARCHITECTURE-SPINE.md:87-91`).
- The implementation document defines strict YAML/schema checks, but places the referenced-family rejection under `init` behavior and never requires `config check` to open each Repository DB and compare the proposed config with `dist_architectures`/Built state (`docs/architecture-v2.md:145-160`).

**Risk**

A config-only implementation of `config check` can report success for a `sow.yml` that removes a still-built architecture, violating a P1 acceptance condition and letting later lifecycle commands observe an impossible effective configuration.

**Required resolution**

Add an enforceable invariant: `config check` remains mutation-free but validates the normalized proposed config against every initialized Repository's SQLite and valid protocol views; every P1 write command performs the same preflight before mutation. Define which persisted references block removal and the exit/error class.

### H2 — Managed lifecycle recovery is not executable for Dist Built Generation, and `init` has ambiguous journal ownership

**Evidence**

- `dist new` must create consumable empty indexes and a new Built Generation; `dist rm` must remove derived indexes and form a Generation (`api-contract.md:329-358,634-643`).
- The normative Repository Operation lifecycle includes a distinct `built` boundary after external static-tree publication (`api-contract.md:647-668`).
- `docs/architecture-v2.md:123-125` reduces Dist operations to `planned/staged/applied/done|rolled_back`, omitting `built`; it does not say when Repository/Dist Built Generation fields advance relative to protocol-pointer switch and deletion.
- AD-6 assigns `init` to the Workspace file journal and Dist lifecycle to SQLite (`ARCHITECTURE-SPINE.md:57-61`), while `init` must initialize configured Repository/Dist/view objects (`ARCHITECTURE-SPINE.md:93-97`; `docs/architecture-v2.md:153-160`). Neither artifact says which journal owns Dist creation performed by `init`, how the two journals compose, or which locks/recovery pass runs first.

**Risk**

Independent units can mark an operation done after DB apply but before the empty index is durable, advance Built Generation before pointer publication, or recover `init` through different journals. That breaks idempotent rerun and can reset or strand valid objects.

**Required resolution**

Add per-command state tables for `dist new`, `dist rm`, and configured-object `init`: lock set/order, durable phase, DB transaction, staged files, protocol-pointer boundary, Built Generation update, deletion/recovery rename, and forward-complete/rollback predicate. Preserve the `built` phase or define a provably equivalent state with no ambiguous window. Explicitly assign `init`'s nested Repository/Dist work to one journal hierarchy.

### H3 — The operational/environmental envelope is a silent architecture dimension

**Evidence**

- The binding NFR requires a pure-Go single binary on macOS/Linux × x86_64/aarch64, local POSIX single-writer operation, no network filesystem, no external repository generators, and GPG as the sole allowed runtime exception (`prd.md:335-343`; current P0/P1 goal constraints).
- The spine names dependencies but has no invariant for CGO/runtime-process/platform/filesystem constraints; “pure-local” and deferring multi-writer operation do not prevent a renderer or SQLite adapter from choosing an incompatible implementation (`ARCHITECTURE-SPINE.md:21-23,121-129,157-161`).
- `docs/architecture-v2.md` likewise does not state the four build targets or the external-process/CGO boundary.

**Risk**

Two units can legitimately choose incompatible implementation substrates—for example CGO SQLite or invoking `createrepo_c`/`dpkg-scanpackages`—and still appear compliant with the current spine, only failing at final cross-build/runtime acceptance.

**Required resolution**

Add one adopted operational-envelope AD binding platform targets, pure-Go/single-binary constraints, allowed external process (GPG only), local POSIX filesystem assumptions, single-writer locking, and explicit NFS/multi-writer rejection. Make dependency selection and cross-build checks enforce it.

## Rubric disposition

| Good-spine question | Result |
| --- | --- |
| Real divergence points fixed, none missed | Fail — relative Pool and lifecycle recovery remain unresolved |
| Every Rule enforceable and prevents its divergence | Fail — AD-9 permits the unsafe destructive order |
| Deferred cannot cause lower-level divergence | Fail — the YUM gate is neither resolved nor represented as a blocking open item |
| Named stack current/pinned | Pass mechanically; versions are pinned and match the current module manifest |
| Ratifies reusable brownfield assets without inheriting V1 product shape | Pass |
| Covers P0/P1 capabilities | Fail — state-aware config removal and executable lifecycle recovery are incomplete |
| Every owned structural/operational dimension decided/deferred/open | Fail — operational envelope is silent and the YUM seam is contradictory |
