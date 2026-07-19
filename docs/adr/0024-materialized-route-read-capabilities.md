# ADR-0024: Materialized Route Receipts Are Read Capabilities

- Status: Accepted; clarified 2026-07-15
- Date: 2026-07-14
- Scope: local APT, YUM, and asset trees rendered into static Nginx routes

## Context

A directly hosted tree is useful only if the route renderer can prove that the
bytes currently under the requested root are the exact projection of the
canonical Git refs it intends to expose. A path in `sow.yaml`, a successful old
materialization, or a fresh filesystem scan alone is not that proof: metadata
can be replaced, an unowned sibling can appear, a target can be exchanged, and
a public index can name a gated package while still referencing public bytes.

The Nginx include is therefore security authority. Emitting it without a
target-bound proof would turn an otherwise local read command into a route
confused-deputy.

## Decision

Every ordinary APT, YUM, or asset route is admitted by a canonical receipt
triple:

```text
serving/materializations/<target-sha256>/<view>/routes/<route-id>.json
serving/materializations/<target-sha256>/<view>/routes/<route-id>.exact.tsv
serving/materializations/<target-sha256>/<view>/routes/<route-id>.payload.tsv
```

`target-sha256` hashes one normalized absolute target identity; the path itself
is deliberately not recoverable from canonical state. The canonical JSON binds
the route kind and owner, view/source, exact ownership claims, `ConfigCommit`
plus the canonical config SHA-256, the complete sorted ref vector, and the
SHA-256 of both sorted manifests. Every ref-vector item also binds the Git blob
ID and declared byte size of its manifest. YUM receipts additionally bind the
derived `ServingTargetID`, which includes the view, target root and base URL;
changing only a URL therefore cannot reuse a physically identical receipt.
The route ID binds its coordinate; a separate content digest binds all frozen
inputs. Unknown files and incomplete triples under this namespace are
corruption. A historical config anchor may predate the aggregate HEAD, but it
must be its ancestor and contain the exact canonical config bytes named by the
receipt.

Receipt ownership follows physical routes, not the command's logical selector:

- one APT owner covers the complete repo-wide set of currently ref-backed
  suite/architecture leaves because `pool/` and route metadata are shared;
- one YUM owner covers one repo+architecture physical root and every configured
  OS alias whose mirrorlist the route emits;
- one asset owner covers its configured public prefix, or the finite exact-file
  set of a root-mapped projection.

A logical selector touching one of these owners is closed before the first
filesystem mutation. The directly hosted tree and its receipt are rebuilt from
the complete physical owner exactly once. This does not widen remote publish
intent or an offline archive: a selected tgz is built in a separate ephemeral
tree from the originally requested logical refs, regenerates only their
APT/YUM indexes and channels, is scanned there, and is then discarded. Thus a
shared live YUM owner can retain two OS aliases while `--os rocky --tgz` contains
only Rocky payload, repodata and mirrorlist.

The exact manifest is derived only from canonical payload plus metadata created
in a private generation directory. A live-tree scan may validate or reconcile
that expected set, but it may never become the expected set. The payload
manifest is the subset that must be canonical CAS hardlinks. Receipt staging
parses both manifests, verifies their digests, and commits only after an exact
target scan, hostable permissions, hardlink identity, and retained-byte rehash
all pass. Each validation invocation creates one isolated private scratch
workspace and keeps every claim manifest alive through both full scans and the
CAS check; an asset-only path cannot depend on some earlier metadata scan having
created the shared scratch directory.

YUM generation retirement does not silently delete a still-installed immutable
directory. A target receipt re-derives its target-specific generation set from
installed generation IDs and includes matching canonical retirement witnesses
in the exact manifest until explicit confirmed generation GC removes those
directories. Retired package entries are intentionally excluded from the
payload manifest, so a deletion witness does not resurrect them as CAS roots;
ordinary Nginx admission nevertheless proves their complete public namespace,
historical view membership, signed package identity, and signed repodata before
serving them. Unknown bytes or a generation without an active ledger or exact
canonical retirement witness fail closed. After confirmed directory removal,
the next receipt transaction drops that retired exact capability.

`sow materialize --nginx-include` opens a bound read session before consulting
receipts. For every selected physical owner it requires exactly one receipt
whose target, config, claims, and complete ref vector match the current request;
it then reprojects the canonical view, validates the receipt manifests against
the retained tree, and runs APT/YUM L1 checks through capability-bound payload
streams. Index identity as well as path/size/hash must match the canonical
package identity, so a validly signed public index cannot relabel a public body
with gated package metadata. The target, canonical state, config, trust files,
and worker-visible directory chain are reverified at the final output barrier.
No include bytes are emitted before all checks pass.

A full mutable materialization may delete stale triples only within the same
target identity and view, and only while replacing that partition with a
complete desired set. Partial materialization preserves unselected owners. An
explicit `--target` is different: it is an exact whole-tree replacement, so its
preflight enumerates every canonical partition for that target identity and its
single receipt transaction retires stale owners across prior views. Historical
restore uses the historical config/ref anchors, groups logical YUM aliases by
physical repo+arch owner for one exact scan/install, then emits one independently
tracked channel/ref per alias. Removing one alias retires only that logical
channel while a sibling still owns the physical root. The receipt commit occurs
before selected-set journal cleanup, making crash recovery safely replayable.

Ordinary `sow fsck` streams every canonical
`serving/materializations/**` descendant and verifies every triple, including
partitions outside repo selectors. This structural audit cannot infer an
arbitrary physical target from its hash; physical closure remains a
target-specific Nginx admission. For the same reason, GC must not delete a
receipt merely because the corresponding path is not presently known. Any
future receipt-retention policy needs independent, evidence-bound target
retirement authority.

## Consequences

- The static tree still needs no SOW runtime after the include is installed.
- Route generation is intentionally fail-closed when receipts are absent,
  stale, duplicated, orphaned, or inconsistent with current canonical refs.
- Local publish fast paths are receipt-dependent: unchanged payload/checkpoint
  state cannot skip materialization when the exact local read capability is
  absent or stale; replay repairs it before publication is reported complete.
- Validation remains streaming and package bodies are not copied into a second
  fixture; retained RPMs are opened through a bound payload capability.
- Old or arbitrary materialization targets remain usable only when explicitly
  presented and revalidated; their SHA-256 ledger identity is not a path index.
- Route receipt GC is deferred until a safe target-retirement contract exists;
  canonical corruption is audited now rather than silently cleaned.

## Validation

The current-source focused validation of partial APT/YUM physical closure,
receipt-dependent publish fast paths, missing-receipt repair, historical shared
YUM aliases, logical offline archives, and retired exact-versus-payload
lifecycle is recorded in
[the 2026-07-15 route-restoration report](../evidence/2026-07-15-physical-owner-route-restoration.md).
The report is local and provider-protocol evidence only; it deliberately does
not promote real-cloud, old-APT, or production-migration requirements.
