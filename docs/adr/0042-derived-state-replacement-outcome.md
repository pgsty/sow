# ADR-0042: Explicit and recoverable derived-state replacement outcomes

- Status: Accepted
- Date: 2026-07-28

## Context

The shared derived-state writer used an error-only API and replaced a
canonical destination with an overwriting rename. Once that rename was
visible, a verification or parent-directory sync failure could no longer tell
its caller whether the new bytes committed. The prior inode had already been
discarded, so the writer also lacked exact rollback authority.

Reading the destination after an error cannot close that ambiguity. It proves
only what a pathname names at the time of the read, not whether a commit
barrier completed or whether a concurrent replacement owns that pathname.
Higher-level projection and archive stages therefore could not make a safe
ownership decision from the old result.

## Decision

- Every production derived-state write returns one of exactly three outcomes:
  `not-committed`, `committed`, or `recovery-required`. The zero value is
  `recovery-required`, so an uninitialized or invalid result fails closed.
- Before any canonical destination mutation, the writer durably publishes a
  non-recursive prepared intent in the exact leaf directory. It binds a random
  transaction ID, canonical basename, source and isolation names, candidate
  size/SHA-256/mode/device/inode/mtime, exact prior-present state, and the
  prior identity when present.
- An existing destination is replaced only with Linux `RENAME_EXCHANGE` or
  Darwin `RENAME_SWAP`. The exact prior inode remains at the recorded
  isolation coordinate. A missing destination is installed only with native
  no-replace rename. There is no two-rename replacement fallback.
- The prepared phase owns rollback. A pre-commit failure exchanges the exact
  prior inode back, or restores exact durable absence for a first install.
  Rollback is reported only after a parent-directory barrier and identity
  revalidation.
- The committed phase is installed by atomically exchanging the prepared
  carrier with a fully fsynced committed carrier, followed by an exact-parent
  barrier. Replay then performs a separate `committed-observed` parent barrier
  and rereads the exact committed carrier before any forward cleanup. A failed
  commit or observed barrier retains the carrier and prior as recovery
  evidence.
- Forward cleanup is delayed until the outer writer has revalidated the
  absolute root, exact parent and canonical destination. Cleanup removes the
  retained prior and carrier through transaction-owned quarantine coordinates;
  the writer proves the canonical outcome across carrier removal under the
  serialized SOW-writer admission model.
- Restart arbitration reads the strict intent carrier before any legacy temp
  cleanup. A prepared carrier rolls back; a committed carrier rolls forward.
  It validates the legal staged/main/next phase topology and validates a
  quarantined carrier in place before restoring its canonical pathname. A
  malformed phase/topology, third identity, reoccupied coordinate, or failed
  proof preserves evidence and returns `recovery-required`.
- Reserved transaction coordinates are fail-closed. The scanner reads directory
  entries in bounded batches, accepts only the exact carrier/isolation grammar,
  and treats a malformed reserved name or an isolation without a durable
  carrier as recovery-required evidence rather than unrelated residue. It
  admits at most 1,024 distinct transaction identities per leaf directory.
- A committed result may carry an error when forward cleanup is incomplete.
  Callers stop the current operation and retain higher-level recovery inputs;
  replay keeps the new canonical bytes and completes cleanup.
- A `recovery-required` result retains the transaction-owned source temporary
  as well as the carrier/prior evidence. Only a proven `not-committed` result
  authorizes generic source cleanup.
- Before a committed result leaves the shared writer, the absolute root,
  exact parent directory, and exact destination identity are revalidated.
  Root/parent replacement or a same-byte foreign destination inode therefore
  changes the result to `recovery-required`; an unrelated post-commit error
  remains `committed` plus that error.
- All production callers consume the explicit result. The old error-only
  convenience surface exists only in test code. Offline archive projection
  preparation uses the result directly to decide whether its durable stage
  remains owned; it no longer infers commit from a pathname read-back.
- Ordinary operations never replay an interrupted shared replacement
  implicitly. Callers that expose recovery, including generated publication
  sources, pass explicit recovery authorization to the writer.

The transaction carrier names are private implementation entries in the leaf
directory:

```text
.sow-derived-replacement-<32-lower-hex>.json
.sow-derived-replacement-<32-lower-hex>.json.new
.sow-derived-replacement-<32-lower-hex>.json.next
.sow-derived-isolation-<32-lower-hex>
.sow-derived-isolation-<32-lower-hex>.source.remove
```

Strict `.remove` variants are recognized only as transaction-owned cleanup
evidence. The source-removal coordinate is transaction-ID based rather than
destination-name based, so a maximum-length canonical basename cannot exceed
the filesystem `NAME_MAX` limit. Canonical destination basenames beginning
with either reserved transaction prefix are rejected. Isolation names
deliberately do not reuse the legacy
`.tmp-install-*` grammar, so legacy cleanup cannot claim an unjournaled V-81
object. Generic asset/package, offline archive, materialization-selection,
local-serving, and serving-removal scanners arbitrate these transactions
before considering legacy writer temporaries.

## Consequences

- A failed replacement now proves exact durable rollback, proves commit, or
  blocks continuation while retaining the candidate, prior, and intent
  identities. Rename visibility alone is never a commit claim.
- A selected-set journal update failure stops the materialization operation
  before the next unit and preserves the durable recovery fence; it is not
  downgraded to an in-memory drift that permits mixed continuation.
- Replacement requires native atomic exchange support and therefore remains
  limited to the product's Linux and macOS platforms.
- Each write adds small journal and parent-fsync costs. Intent bodies are
  bounded to 16 KiB, directory enumeration uses 128-entry batches, and all
  candidate/prior hashing remains streaming.
- The separately deferred hostile-hardlink and writable-directory policy is
  unchanged. This decision binds observed descriptors, inodes and bytes but
  does not broaden the same-host threat model. In particular, preventing a
  different principal from mutating an admitted directory after terminal
  evidence removal, or from swapping a pathname between the final
  check/rename/unlink instructions, requires that follow-up policy rather than
  another replacement phase.
- Unjournaled random write residue outside known scanners remains tracked by
  the existing generic-scanner deferred item; this ADR resolves the canonical
  destination replacement ambiguity, not that independent inventory feature.

## Evidence

See [the implementation report](../evidence/2026-07-28-derived-state-replacement-outcome.md),
`internal/cli/derived_state_replacement.go`,
`internal/cli/derived_state_replacement_contract_test.go`, and V-81 in the
[requirements ledger](../requirements-traceability.md).
