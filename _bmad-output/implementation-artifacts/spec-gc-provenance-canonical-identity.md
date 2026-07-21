---
title: 'GC provenance canonical identity binding'
type: 'hardening'
created: '2026-07-20'
status: 'done'
baseline_commit: '9f263c9'
---

## Intent

Canonical provenance is a CAS preservation root. A receipt whose embedded
format, artifact digest, or repository identity differs from its Git path must
not keep a different object alive while the path-named object becomes
collectable. GC therefore treats the canonical path and decoded receipt as one
joined identity, not as two independently trusted labels.

## Contract

- `provenance/deb/<sha256>.json` and `provenance/rpm/<sha256>.json` must exactly
  equal the path reconstructed from the decoded receipt format and artifact
  digest.
- Every receipt in `provenance/legacy/<repo>.jsonl` must name that exact repo.
- Every negative receipt in `provenance/legacy-pruned/<repo>.jsonl` must also
  name that exact repo; it validates evidence but never becomes a positive CAS
  root.
- The checks apply to every canonical commit inside the configured GC history
  window, not only HEAD.
- Any mismatch is a verification failure before CAS audit, confirmation-plan
  construction, or deletion. An exact confirmation digest that the old
  path-unbound implementation would have accepted must not bypass admission.
- Rejection preserves every CAS byte and the canonical Git evidence for
  diagnosis. Recovery does not rewrite or silently normalize a mismatched
  receipt.

## Implementation

- `addProvenanceRoot` reconstructs the only legal ordinary receipt path after
  strict receipt decoding and requires byte-for-byte path equality before
  adding the artifact to the reference set.
- `canonicalProvenanceLedgerRepo` extracts exactly one repo coordinate from a
  canonical JSONL namespace.
- `addLegacyProvenanceRoots` and `validateLegacyIndexPruneLedger` bind every
  streamed receipt to that coordinate before accepting it.
- `runGC` already invokes root collection before `pool.GC`; both dry-run and
  `--apply` therefore share the same fail-closed admission boundary.

## Verification

- Real filesystem CAS objects, real Git-backed canonical commits and canonical
  provenance encoders cover DEB, RPM, legacy adoption and legacy prune paths.
- Positive evidence proves three positive objects are retained, the negative
  prune receipt roots nothing, and exactly one unrelated object is orphaned.
- Negative evidence covers digest, format, legacy repo and prune repo mismatch.
- A real `sow gc --apply` receives the exact pre-fix deletion confirmation yet
  exits with `ExitVerification` before CAS planning and leaves both objects
  byte-present.
- Focused ordinary, race and atomic coverage plus the affected G-M CLI shard,
  static/module/migration and deterministic clean-delivery gates must pass
  before this specification becomes `done`.
- All cloud, upstream and Docker opt-ins stay off. No Cloudflare, CO/COS,
  EdgeOne or production repository is accessed.

## Result

The final code-bearing source passed all 712 CLI tests in six ordinary and six
`-race` shards, all non-CLI packages ordinary/race, the nested RPM module,
compile/vet/Staticcheck, module/provenance/vulnerability gates, four static
cross-builds, 47/47 edge contracts, seven migration suites and all 50k
performance gates. A preliminary isolated clean delivery passed before this
document was frozen; two post-document deliveries are rebuilt and compared
bytewise, with their non-self-referential identity recorded in the external
V-50 ledger.
