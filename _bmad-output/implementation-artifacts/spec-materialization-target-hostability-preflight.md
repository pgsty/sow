---
title: 'Materialization target hostability preflight'
type: 'hardening'
created: '2026-07-22'
status: 'done'
baseline_commit: '1cb3b06'
---

## Intent

`sow materialize latest` accepted a repository reached through macOS `/tmp`,
whose path is a symlink to `/private/tmp`. The command installed the payload,
committed the refreshed working tree and created selected-set state before the
exact Nginx route receipt rejected the non-real path chain. Retrying through
the canonical spelling then conflicted with the durable target identity.

## Contract

- Every non-render-only materialization validates its directly hostable target
  before the state lock, selected-set journal, payload link or canonical commit.
- The deepest existing target ancestor must be a real directory, contain no
  symlink in its absolute chain and be traversable by an unprivileged Nginx
  worker.
- Missing descendants remain legal so a first export can create its target;
  this read-only preflight must not create any directory or file.
- The existing capability-bound post-install validation remains mandatory as
  the TOCTOU and final exact-route admission fence.
- A failed preflight leaves canonical HEAD, the working tree, selected-set
  state and incomplete canonical transactions unchanged.

## Implementation and verification

- `runMaterialize` invokes
  `preflightMaterializedRouteTargetHostability` after argument/config/serving
  validation and before acquiring the state lock.
- The helper walks upward with `Lstat` until it finds the deepest existing
  coordinate, rejects a symlink or non-directory, then reuses the retained
  Nginx worker hostability validator for the complete absolute chain.
- The repository hardlink installer continues to create missing descendants
  through retained directory descriptors and refuses symlink components.
- A real macOS `/tmp` alias regression proves the old late failure had already
  linked one payload and advanced HEAD. The corrected run fails at preflight
  and proves all four mutation surfaces remain absent.
- Cross-platform focused tests cover a safe missing target and a symlinked
  existing ancestor; focused ordinary/race, all `TestMaterialize*`, the G-M
  ordinary/race shard, vet and Staticcheck pass.
- A freshly built real CLI completes asset init, add, beta-to-latest promote,
  working-tree materialize, L1 verify, fsck and GC under `/private/tmp`; the
  served payload and CAS object have the same inode.

## Result

The reachable macOS failure is now rejected before mutation while valid first
exports still work. No cloud, upstream, Docker or production resource was
accessed. The long-term Goal remains active.
