# ADR-0018: Selected-set local materialization transaction

> **Historical V1 ADR.** Next keeps only the explicitly external export boundary;
> see [`../../design/next/specs/compatibility.md`](../../design/next/specs/compatibility.md).

Status: accepted — 2026-07-13; clarified — 2026-07-14 and 2026-07-15

## Context

APT, YUM, asset and local serving activation do not have the same atomicity unit. APT
publishes one `Release`/`InRelease` per suite, YUM builds one metadata closure
per repo/OS/architecture, and the strong local YUM route flips a separate
generation pointer. An asset repository has payload but no repository metadata
or repository signing key. One CLI invocation can touch several of those units and can
also append canonical ledgers between them. Protecting each inner builder in
isolation is insufficient: a repository key, RPM package keyring, config or ref
can change after the first unit becomes hostable and before the last one flips.
That would expose a mixed-trust tree even though every individual builder had
passed its own preflight.

The fixed `.sow/materialized/<view>` and
`.sow/materialized/snapshots/<id>` roots are cumulative targets. A partial
selector must not turn `ReconcileExact` into authority to delete an unselected
repo, APT suite, architecture or retained local-serving generation. Conversely,
silently continuing an interrupted partial transaction against a newly
selected set would make recovery destructive.

## Decision

1. Before the first directly hostable payload-tree mutation, signed-metadata
   activation or serving-pointer mutation, the top-level command writes one
   bounded, fsync-durable
   `.sow/materialization-journal/active.json`. The immutable identity binds the
   operation and operation-specific scope, runtime and parent canonical config
   SHA-256, pre-mutation canonical HEAD, repository signing-key identity, every
   selected YUM package-keyring identity, target identity, and the complete
   selected unit/ref vector. The bound HEAD is the pre-materialization
   canonical HEAD: an ordinary add may first stage private CAS bytes and commit
   its canonical manifest/ref because neither is directly hostable. A pure
   asset selection records the fixed
   `sow-no-repository-signing-key-v1` SHA-256 identity instead of pretending a
   repository key exists; config, ref and target identities remain mandatory.
2. The durable selected set is closed over directly hostable physical owners,
   not merely the command's logical selector. One APT physical owner contains
   every currently ref-backed suite/architecture leaf of the repo because its
   route and `pool/` are shared. One YUM physical owner contains every
   configured/ref-backed OS alias for one repo+architecture root because all
   aliases name the same repodata and payload namespace. An asset owner is the
   repository's finite public projection. APT `--arch` and YUM `--os` therefore
   remain logical transaction triggers; they cannot authorize a partial live
   physical tree or an incomplete recovery journal. Nested materializers may
   prove and use a subset of the durable set, but may never add or substitute a
   unit. Top-level recovery must reproduce the exact owner-closed set. This
   local closure does not widen the remote ref/manifest selector and does not
   widen a selected offline archive, which is built from the original logical
   refs in a separate ephemeral tree.
3. Journal phases are `prepared`, `materializing`, and `trust-drifted`, with an
   fsync-durable sorted completed-unit set. A failure before any mutation may
   remove a prepared journal. Once mutation starts, every error retains the
   journal, including an error after all units are marked complete; only an
   explicit successful selected-set finish may clear it. Exact `--recover` is
   therefore required after any started failure. Completed local selection
   state is cleared before any remote provider call, archive adoption,
   retention prune, or other unrelated canonical mutation.
   Historical restore first proves the requested target/generation unit vector,
   rebuilds its isolated local tree and clears the fence; the read-only remote
   observation used to calculate current-parent topology happens afterward.
   Canonical manifest/ref commits remain the earlier product-truth commit
   point: a stop after that commit but before selected-set creation leaves the
   previous complete hostable tree in place, never a mixed tree. L1 reports the
   resulting canonical/filesystem drift and an idempotent replay starts the
   exact materialization. The selected-set journal is mandatory before the
   first hostable-tree mutation.
4. The pre-materialization HEAD remains the ancestry root. The operation may append
   only its own derived ledger/config-baseline commits while holding the state
   lock. Recovery accepts the frozen HEAD or a descendant, requires the runtime
   config digest, allows canonical config to move only from the frozen parent
   digest to that same runtime digest, and rechecks every frozen live ref.
   Historical restore units bind their explicit ref commits rather than current
   refs.
5. Trust is forward-only across the selected set. Before the first completed
   unit, a failed boundary rolls back that unit where the inner atomic primitive
   permits it. After any unit is hostable, later units continue from the frozen
   in-memory trust snapshot so the tree converges to one generation; the final
   barrier reports drift, retains the journal, and forbids remote effects.
   Exact recovery under the original trust identities completes or verifies
   every unit and then clears the fence.
6. An active journal is a global local-mutation fence. `init`, add/rm, promote,
   sync provenance, GC, archive adoption, mutating fsck/verify recovery, and a
   different materialize/publish intent fail closed. Ordinary read-only L1 and
   fsck remain available but return an explicit recovery-required finding and a
   failing exit status. An interrupted asset `add` is recovered from its frozen
   ref and CAS before `runAdd` interprets any current positional input as asset,
   RPM, or DEB work. The original pathname is not durable authority and may be
   gone; an inputless `add --recover` is therefore the explicit recovery-only
   form. Without an active exact asset-add journal, inputless `add` remains a
   usage error. A package `add --recover` must pass an additional admission
   barrier before opening or installing into CAS: its journal must be an
   unscoped homogeneous APT or YUM add under the same frozen config, HEAD and
   trust identities; the planned materialization unit vector must equal the
   durable vector; and every proposed package path, size, SHA-256 and manifest
   entry must already exist exactly in the frozen refs. Mixed families,
   cross-family retries and same-family novel entries fail before CAS and
   retain the journal. An admitted exact RPM/DEB entry may restore a missing
   CAS object and then converge the frozen hostable tree. A package journal
   also fences a current asset input before the asset importer opens CAS.
7. Sync additionally binds upstream ID and selection SHA-256 in the operation
   scope. Temp cleanup, scope admission and recovery occur only after acquiring
   the state lock. A different upstream targeting the same repo cannot adopt
   the journal, and repair projects only the exact durable view/leaf set. Its
   internal package-add phase remains governed by this scoped sync coordinator,
   not by the unscoped standalone-add admission rule above.
8. Partial direct materialization into a fixed product-owned mutable view or
   snapshot root reconciles by ownership, not by the whole target. APT replaces
   only selected `dists/<suite>` metadata and upserts its shared `pool`; YUM
   leaves and asset repos replace their independent roots. Unselected sibling
   projections remain. Fixed mutable view roots additionally retain delayed
   clients' `_sow` generations and canonical APT by-hash generations. An
   explicit dedicated `--target` is an exact export of the current source and
   selector, never a cumulative cross-view root. A full snapshot replay is also
   exact and does not inherit a foreign `_sow` namespace. An unselected full
   mutable-view command remains exact for product content while preserving only
   those product-managed delayed-client routes. Exact-target authority includes
   the canonical serving namespace for that physical root: obsolete cross-view
   or prior-base-URL channels are removed, unreferenced generations retired and
   unclaimed target registries deleted in the same operation. Fixed/default
   roots retain their existing partial/cumulative topology semantics.
9. `materialize --tgz --asset-repo` has two ordered local transactions. The
   source view materialization finishes first; deterministic archive creation
   and its asset ref commit then make the adoption ref knowable. Adoption uses
   a fresh asset-only trust snapshot, the fixed
   `offline-archive-adoption-v1` operation scope, and `cfg.Root` as its target
   identity. `materialize --recover` recognizes and exactly converges that
   frozen asset ref from CAS before it plans the caller's current selector.
   The later ref cannot be smuggled into the earlier selected set.
10. Journal reads are size-bounded, regular-file and symlink safe. Creation and
   replacement use atomic rename plus file and directory fsync; first creation
   also fsyncs the `.sow` parent. Target paths are represented by identity
   digests so recovery records do not disclose operator-specific mount names.
11. Asset replacement authority is path-scoped at both canonical and physical
    layers. `--replace` permits a canonical upsert only when the destination
    matches `asset.mutable_paths`; every specialized add/rm/publish/adoption
    materializer independently evaluates the repository-relative manifest path
    against the same configured patterns. There is no whole-manifest
    `AllowReplace` switch. A different regular file at an immutable sibling is
    a conflict, retains a started selected-set journal, and cannot be silently
    relinked by publishing a mutable asset.

## Validation

The current-source focused evidence for physical-owner closure, incomplete
journal rejection, logical offline archives and publish recovery is recorded in
[the 2026-07-15 route-restoration report](../evidence/2026-07-15-physical-owner-route-restoration.md).
It is strictly local/protocol evidence and does not claim a real provider or
production migration run.

## Consequences

- A multi-suite or multi-leaf local result is either entirely derived from one
  frozen trust/ref/config generation, or visibly fenced for exact recovery.
- A crash may leave already hostable local units, but cannot let a later command
  mistake them for an unrelated selection or begin cloud mutation first.
- Recovery intentionally rejects convenient but ambiguous widening, narrowing,
  upstream substitution and trust rotation. Operators restore the frozen trust
  inputs, replay with `--recover`, then perform rotation as a new transaction.
- Partial fixed-target work is cumulative and bounded-memory; its manifest scan
  and ownership merge are local O(target entries), while remote publication
  remains O(change set).
- The journal is coordination evidence, not product truth. Canonical manifests
  and refs remain authoritative, and SQLite remains a rebuildable cache.
