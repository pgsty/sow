# ADR-0013: Persisted publication plans are untrusted recovery input

Status: accepted
Date: 2026-07-12

## Context

SOW persists a deterministic publication plan so an interrupted target saga can
resume without rescanning or rediscovering remote state. The plan contains
object keys, classes, client routes, verification digests, deletes and purge
URLs. Hashing the plan detects accidental mutation after the journal is
created, but it does not make a forged or stale plan semantically authoritative:
a plan could otherwise choose a different generation or route and then provide
the digest that “verifies” its own choice.

## Decision

`TargetGeneration` and the frozen publication intent remain authoritative.
Before any provider lock, upload, delete or purge, the publisher normalizes the
plan and mechanically re-derives its irreversible contracts:

1. APT/YUM generation keys must name the request generation.
2. latest, beta, stable and snapshot remote keys map to an exact closed union of
   client routes; ordinary objects cannot override verification digests.
3. Snapshot route bytes come from the shared canonical encoder. Snapshot
   payloads are create-only, and every YUM payload leaf has a complete signed
   metadata leaf.
4. A normal YUM update is a bidirectional closure among five immutable metadata
   objects, byte-identical raw aliases, the current `ChannelState` and one exact
   generation-pinned pointer. Validation uses maps and remains O(change set).
5. Serving deletes must match the request view. Snapshot retention is allowed
   only when the new target ref vector no longer reaches that snapshot.
6. The plan-derived client+clean purge set is replayed even after a committed
   checkpoint, then L3 is repeated.

Journal plan hashes and provider conditional writes remain necessary, but are
defence-in-depth after these semantic checks rather than substitutes for them.

Every newly committed remote checkpoint uses `sow-checkpoint/v2` and carries
the canonical SHA-256 of `plan.json`. A v2 checkpoint without that binding, or
a checkpoint whose binding differs from the persisted plan, is invalid before
any provider client is constructed. Strict decoding of `sow-checkpoint/v1` is
retained for existing repositories. A purge-free v1 publication remains
directly admissible. A nonempty v1 purge plan is accepted only after an
operator runs the explicit, state-locked, local-only
`sow fsck --target <one> --repair-purge-ledger` migration. That command copies
the exact provider receipt from the generation's first atomic Git publication
commit and creates a deterministic `sow-legacy-purge-plan-attestation/v1`
document binding the publication anchor, target, generation, transaction and
generation/checkpoint/plan/receipt SHA-256s. It never rewrites the v1
checkpoint, never calls a provider, and cannot attest a receipt that was absent
from the publication anchor.

Canonical purge evidence is an append-only generation ledger, not merely a
property of the latest checkpoint. L2, fsck, no-op publish, full publish,
snapshot publish and forward restore walk the target generation history and
require the exact `1..N` parent chain. For every generation with a nonempty
purge plan, the receipt must have been committed atomically with that
generation and must remain byte-identical at HEAD. The receipt binds target,
transaction, generation, generation/checkpoint/plan digests, the complete
sorted URL set, the latest completed full attempt, and the provider identity
recorded in that publication commit. A later legitimate CDN zone rotation
therefore does not invalidate earlier receipts, while a forged historical zone
still fails closed. Orphan, deleted, moved, changed or incomplete receipts are
reported locally before List, HEAD, GET, upload, purge or delete is attempted.
After the first publication, a partial control triplet, deletion of the whole
triplet, or any same-generation rewrite of generation/checkpoint/plan is also
an irreversible history-integrity finding. The scan validates one generation
at a time, retains only receipt blob identities, and uses the same 4 MiB bound
as the runtime sidecar. A successful result may be reused only inside one
`publish` invocation and only for the exact target plus canonical HEAD; failures
and changed HEADs always rescan.

## Consequences

- Corrupt or forged local recovery state fails before remote mutation.
- A later generation cannot bury missing purge evidence from an earlier
  generation; publication remains blocked until the canonical ledger is
  repaired from its immutable publication anchor.
- Accidental receipt or legacy-attestation damage has a product-level,
  additive, idempotent repair path. Derived evidence is restored exactly; a
  partial/deleted/rewritten publication envelope or orphan evidence is never
  repaired or silently grandfathered.
- CLI plan builders and recovery validators share encoders for bodies whose
  exact bytes are contractual.
- Full-change validation keeps O(N) time and is covered at 50,000 objects.
- Raw YUM alias two-key atomicity is not redefined: the generation-pinned route
  is the strong contract, and the raw compatibility window remains a migration
  blocker recorded in deferred work.
- A future plan schema change that adds a route, transformation or deletion
  class must add the corresponding request-derived binding and negative tests.
