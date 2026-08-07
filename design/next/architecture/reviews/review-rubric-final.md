# Final Architecture Reviewer Gate — Repository-scoped single-payload design

> **Historical pre-implementation snapshot.** 本 gate 与下列 hash 只证明当时设计可进入实现，
> 不是当前文件 hash 或 release verdict。当前实现证据与外部未验证项见
> [`../../evidence/2026-08-05-implementation.md`](../../evidence/2026-08-05-implementation.md)。

- **Date:** 2026-08-05
- **Intent:** final validate
- **Verdict:** **READY for implementation**
- **Release / compatibility verdict:** **NOT READY — implementation and evidence gates remain**
- **Mechanical lint:** PASS (`lint_spine.py`, 0 findings)
- **Design blockers:** 0 critical, 0 high, 0 medium

## Review snapshot

`design/next` is currently untracked, so Git `HEAD` alone cannot identify the reviewed
bytes. This gate binds the current working-tree inputs directly:

| Input | SHA-256 |
| --- | --- |
| `specs/SPEC.md` | `2b96a4581db1ca529e0625caa64c887c8139def997452fba70168bbd766d2148` |
| `specs/state-publication.md` | `9e267968c3123896025565a52f45c2d5340b76bbc6c373bd4a8a7134c5012965` |
| `specs/repository-layout.md` | `491cdb17b2e2c7c248944b134c9e68952450c6059c3fd41e67e5c5b9a1dc3c10` |
| `specs/compatibility.md` | `310154193bafe017886de362a45bf4bcaa6cff6fafb6d9d140e0d2099aaeb746` |
| `specs/publication-retention.md` | `8a94a4b917989d9af8dd19088765a0d998f64e1acd35b22cd6476b687f77c57d` |
| `specs/migration.md` | `5849d11199bb3ba17c403b545b98ecb2ca04003c81c9b0eefa8f315652b54e95` |
| `specs/acceptance-matrix.md` | `3c5f6e270fe9f6adf7808f101c6d6dae3d6a6276fb4d964e1ecc878a593c42e6` |
| `architecture/ARCHITECTURE-SPINE.md` | `6d64f23016be83ab5e8b908cf0a0f9b4032ed376eaea8748cecc5a04617d974c` |
| `specs/.memlog.md` | `a12188e8cc7f09fa18f3e6f9ff1c9bb37681f7905123f74ce5073f1bdc8b6f4d` |
| `architecture/.memlog.md` | `9cf495a66d1ba2fbd3f4894e92cd8252dadaf25d9a444d16170040aad15f6c73` |

## Final verdict

The current contract is internally consistent at feature-architecture altitude and
can be handed to implementation. The previous blockers are no longer hidden inside
Deferred or disguised as target capabilities: the design chooses one recovery
direction, one supported writer/authority envelope, and two explicit GC outcomes based
on target capability. It also preserves the user's non-negotiable physical invariant:
the canonical public Repository/publish prefix contains only `pool/ + dists/`.

“READY” here does **not** claim that next exists in the binary or that any next
compatibility cell has passed. The documents correctly call themselves
approved/unimplemented, and the acceptance contract prevents a release PASS without a
fixture lock and retained evidence.

## Wire-revision rebind

The latest wire edits tighten representation without changing architecture ownership
or support boundaries:

| Revised contract | Rebind result |
| --- | --- |
| Generation and target state | **PASS** — cross-file Generation identity is a 20-digit JSON string, text sizes are bounded canonical ASCII decimals, and each Built RPM view freezes an immutable signer identity/key binding. Publication Attempt/Checkpoint records remain Workspace-private semantic state rather than public-prefix control objects. |
| Retained state | **PASS** — the `sow/retained/v1` interchange wire stores the terminal manifest plus exact non-payload metadata under private `.sow`; payload entries remain references to the one canonical root Pool and no payload bytes are copied into retained state. |
| RPM compatibility export | **PASS** — a signed marker must copy the bound Built Generation view's signer identity byte-for-byte and verify with its bound or externally trusted key; it cannot derive a second identity or self-authorize. The export remains in a new external root, defaults to copy, and never becomes Repository state, publish input, or a GC root. |
| C2 migration | **PASS** — the journal fixes Generation and alias-size spelling, receipt golden vectors, recursive unknown-field rejection, and duplicate-key rejection, but legacy view-local payloads remain transition-only. Commit intent is still forward-only; R2 still migrates to a new empty non-overlapping prefix rather than deleting C2 keys in place. |
| Acceptance coverage | **PASS** — the matrix covers Generation/size boundaries, signer and `.asc` mismatches, strict nested JSON, same-owner prefix overlap, and independent target-plan replay. It still treats all next results as unverified until immutable fixture evidence exists. |

The rebind therefore introduces no new compliant-implementation fork: neither a wire
record nor an export marker may become a third public top-level tree, a second live
payload key, cross-workspace publish authority, or evidence that default EL reposync is
supported.

## Targeted blocker recheck

| Prior issue | Final status | Current resolution |
| --- | --- | --- |
| **CR-2 — migration rollback after commit intent** | **RESOLVED** | `migration.md` now makes `commit_intent` irrevocable: before it, private stage/layout may be abandoned; after it, both automatic recovery and human operation must follow the recorded CAS-bound roll-forward path through terminal manifest. The journal has an exact v1 schema, ordered pointer/alias substates, receipts, layout versions, and one persisted v0.2-to-next Repository UUID. No second compliant rollback result remains. |
| **NEW-CR-1 — R2 conditional delete** | **RESOLVED as a design contradiction** | `state-publication.md`, `publication-retention.md`, `migration.md`, and the acceptance matrix consistently classify R2 as publish/recovery capable but remote-delete disabled. Unsupported deletion ends through `retained_reported`; it cannot report reclaimed bytes or physical GC PASS. C2-to-next R2 migration uses a new empty prefix instead of deleting aliases in place. |
| **NEW-HI-1 — prefix ownership arbitration** | **RESOLVED by an explicit support boundary** | The contract no longer promises cross-workspace distributed arbitration. `target_storage_id` excludes prefix; one authoritative Workspace registry rejects local same/ancestor/descendant claims; supported publication requires a single writer and exclusive write authority for the containing namespace. Independent workspaces/out-of-band writers are unsupported, missing private binding/checkpoint is read-only reconcile, and no owner/control object is written into the public prefix. |
| **Fixture lock / prior ME-2** | **DESIGN RESOLVED; EVIDENCE PENDING** | `acceptance-matrix.md` freezes the fixture-lock schema, requires it before any PASS, pins the retained AlmaLinux 9.8/DNF 4.14 baseline, names the initial client/target cells, and requires exact client/origin/target digests and request-log semantics in the first next evidence commit. The lock file does not currently exist, correctly preventing a release claim; this is an evidence gate, not an architectural fork. |
| **Memlog reconciliation** | **RESOLVED, with one non-blocking historical note** | Both memlogs now append the final public-tree, single-writer, R2 retain/report, APT encoding, retained/export wire, and irrevocable migration decisions; the architecture memlog explicitly records AD-25 through AD-27 and the requested final review. Earlier spec-memlog CAP-4/CAP-5 shorthand predates the final CAP-4-through-CAP-7 split; later entries supersede its semantics. Before a future re-distillation, an append-only CAP-ID correction would improve navigation, but it does not leave a current design choice undecided. |
| **Canonical public tree** | **PASS** | SPEC, layout, state-publication, retention, migration, spine, README, and memlogs agree that only `pool/` and `dists/` are public. Publication state and retained bytes live under private `.sow`; export lives outside the Repository/prefix; APT by-hash is metadata under `dists`; migration-only C2 aliases belong solely to a non-terminal legacy transition and can never enter the terminal next Generation. |

## R2 current-reality check

Cloudflare's current official API still supports the design's conclusion:

- The
  [Workers API reference](https://developers.cloudflare.com/r2/api/workers/workers-api-reference/)
  exposes `delete(key)` without an options/precondition argument, while conditional
  operations are defined for Get and Put.
- The
  [R2 S3 compatibility table](https://developers.cloudflare.com/r2/api/s3/api/)
  lists conditional operations for Head/Get/Put but none for `DeleteObject` or
  `DeleteObjects`.
- R2
  [temporary credentials](https://developers.cloudflare.com/r2/api/s3/temporary-credentials/)
  can be scoped to paths, so a real fixture may prove prefix-exclusive write authority;
  the acceptance gate must bind the exact credential mode actually used.

Accordingly, “R2 remote delete disabled” is a current capability classification, not
an accidental omission. If Cloudflare later adds atomic conditional delete, that is a
new capability probe and evidence upgrade; it must not silently change this reviewed
contract.

## Public-tree containment check

The apparent exceptions are all outside the terminal canonical tree:

| Artifact | Location / state | Why it does not violate `pool/ + dists/` |
| --- | --- | --- |
| Publication Attempt, checkpoint, grace, receipt | Workspace private Repository state | Never uploaded as `.sow-owner`, checkpoint, or control object |
| Retained Generation bytes/refsets | `.sow/<repo>/retained/...` | Private recovery/interchange state; payload bytes remain in canonical Pool |
| RPM compatibility export | New external export root | Disposable derived artifact; never Generation, publish input, Membership, or GC root |
| C2 view-local aliases | Non-terminal legacy transition only | Ordinary changes/publish/GC fail closed; terminal next manifest requires zero aliases |
| R2 C2 migration | New empty non-overlapping prefix | The next prefix contains only canonical Pool plus metadata-only Dists from its first generation |

## Reviewer layers

| Layer | Result | Assessment |
| --- | --- | --- |
| Mechanical lint | **PASS** | No placeholder, duplicate AD, missing Binds/Prevents/Rule, or mechanical spine finding. |
| Good-spine rubric | **PASS** | Ownership, commit unit, recovery direction, remote capability split, physical tree, addressing, compatibility export, retention, and operational envelope are decided or deliberately excluded. |
| Reality / brownfield | **PASS for design truth** | Current source still implements v0.2 C2 aliases and lacks next target state; every forward document labels that as unimplemented rather than claiming code or target PASS. |
| Named-technology check | **PASS** | Current official R2 behavior matches the target capability split; Ubuntu 22.04 APT 2.4 and Debian 12 APT 2.6 remain real initial families, with exact patched images deferred to the mandatory fixture lock. |
| Adversarial two-implementation test | **PASS within the declared v1 scope** | Final signer inheritance, size bounds, nested strictness, overlap cases, and execution-plan vectors close the remaining wire forks. A compliant implementation still cannot add remote control keys, roll migration back after intent, delete on R2, or promise cross-workspace takeover. |

## Remaining gates — classification

| Remaining work | Class | Effect |
| --- | --- | --- |
| Replace C2 renderer/checker behavior with metadata-only views and computed RPM href | **Implementation gate** | Blocks claiming the next layout exists; does not make the design contradictory. |
| Implement Repository UUID/layout migration, target attempts/checkpoints, retained state, export, GC, and R2 adapter | **Implementation gate** | Blocks feature completion. |
| Create immutable `design/next/evidence/fixture-lock.json` with all exact image/origin/target identities | **Evidence gate** | Blocks every next PASS and release-candidate compatibility claim. |
| Run APT/DNF file+HTTP, leading-slash, default reposync, whole-root, export, target fault, GC, and migration crash matrices | **Evidence gate** | Blocks release, support, and compatibility claims. |
| Prove real R2 non-root prefix, request normalization, pointer CAS/replay, ACL, retained-candidate reporting, and exclusive writer credential | **Evidence gate** | Blocks the R2 matrix cell; physical R2 delete remains intentionally outside that PASS. |
| Cross-workspace prefix arbitration, state-less publisher adoption, default EL reposync, and R2 physical conditional delete | **Unsupported / future scope** | Must not be inferred from implementation or evidence for the approved v1 design. |

There is therefore no remaining architecture contradiction in the requested scope.
Implementation may start from this spine. Release and compatibility claims must wait
for the implementation and evidence gates above.
