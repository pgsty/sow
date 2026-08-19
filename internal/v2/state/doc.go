// Package state implements SOW's private SQLite authority and immutable audit
// ledger.
//
// All writes use explicit transactions on one FULL-synchronous WAL connection.
// Schema migrations are checksum-bound and ordinary writers never cross a
// schema version implicitly. Repository status is a derived cache of
// Desired/Built membership and effective/Built configuration. A Generation
// contains the complete public manifest; side tables such as RPM view signers
// must cover that manifest exactly, including unchanged views carried from the
// predecessor Generation. A signed v10 historical view whose signer was never
// recorded is represented explicitly as unverified: it satisfies structural
// coverage but cannot become a retained trust identity, appear at the current
// head, or propagate into a successor Generation.
//
// Publication attempts, checkpoints, grace records, candidate reports, and
// receipts are private recovery evidence. They do not authorize public bytes by
// themselves: callers reconcile provider identities and content before asking
// state to advance an adjacent phase. Commit-intent attempts cannot transition
// backward or be forcibly abandoned.
package state
