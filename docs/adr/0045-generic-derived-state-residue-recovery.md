# ADR-0045: Bounded recovery of unjournaled derived-state residue

- Status: Accepted
- Date: 2026-07-28

## Context

The shared derived-state replacement protocol durably journals replacement
authority before moving a candidate into its isolation coordinate. A process
can still die earlier, after creating a random private write temporary but
before publishing that intent. Specialized projection and serving scanners
cover their own fixed directories, while generated publication state and
package completion receipts have no global inventory.

The strict 128-bit temporary suffix is deliberately different from an unowned
final projection stage. ADR-0041 already freezes the former as recoverable
writer namespace and the latter as evidence that must be preserved.

## Decision

- The managed inventory covers only:
  - immediate files in `.sow`;
  - `.sow/generated/**`;
  - `.sow/materialization-journal`;
  - `.sow/serving-journal`;
  - `.sow/serving-removal-journal`.
- It never traverses `.sow/state`, cache, sync, stage, tmp, materialized,
  origin or repository/CAS payload trees.
- A temporary is recognized only as
  `<canonical>.tmp-<32 lower hex>`,
  `<canonical>.tmp-install-<32 lower hex>`, optionally followed by
  `.tmp-remove-<32 lower hex>`. A bare legacy 16-hex write name is predictable
  and therefore only audit evidence: ordinary writers preserve it and explicit
  recovery refuses to delete it. A legacy base already moved under a random
  32-hex removal quarantine is recoverable because that isolation nonce is the
  deletion capability. The `.tmp-` marker is reserved in canonical destination
  basenames so malformed and valid temporary spellings remain unambiguous.
- The same inventory exposes V-80's exact owner-private
  `.tmp-derived-directory-<32 lower hex>` stage and quarantine forms and
  delegates their cleanup to the existing descriptor-bound empty-directory
  recovery protocol before file transactions. Strict `.preserved-<nonce>`
  directory evidence is reported but never auto-deleted.
- Inventory is descriptor-bound, no-follow, owner-private and single-link. It
  streams directories in batches and has explicit depth, directory, entry,
  transaction and residue ceilings. Malformed related names, unsafe objects
  and excess cardinality fail closed.
- Ordinary L1 and fsck report critical findings and do not mutate.
- Explicit recovery replays all valid replacement carrier sets first. It then
  re-scans and deletes only remaining strict temporary inodes through
  no-replace quarantine, repeated root/directory/file identity checks, unlink
  and exact parent fsync. A final clean re-scan is mandatory.

## Consequences

Recovery can no longer confuse a transaction-owned source temporary with
garbage, and an unjournaled random temporary has a supported cleanup path.
Predictable legacy names and preserved directory replacements require operator
inspection instead of being converted into deletion authority.
The inventory cost is proportional to SOW control state, not repository
payload bytes, and retained record memory is bounded.

Adding a future shared-writer destination outside the managed surfaces requires
an explicit update to this ADR and its executable scope tests.

## Evidence

Implementation evidence will be recorded in
`docs/evidence/2026-07-28-generic-derived-state-residue-recovery.md` and V-84
of `docs/requirements-traceability.md`.
