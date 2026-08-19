// Package managed owns the filesystem-facing SOW workspace lifecycle.
//
// A Repository has two projections: Desired membership is operator intent;
// Built membership and its immutable Generation describe the currently
// published local tree. Repository status is derived from those projections and
// is never an independent source of truth. Every writer holds the Workspace and
// Repository lifecycle locks, stages private bytes, records a replayable SQLite
// operation, publishes filesystem pointers last, and closes the operation only
// after the public tree and Generation ledger agree.
//
// Publication is a separate target transaction. Before durable commit intent an
// attempt may be reconciled and abandoned, leaving only exact add-only evidence.
// After commit intent it is forward-only: every mutable pointer may contain the
// old checkpoint or target Generation identity, but no third identity is
// accepted. Applied checkpoints record a complete target inventory; target GC
// is the only remote-maintenance path and never treats abandoned evidence as a
// deletion candidate.
//
// Read-only previews share the same configuration and render planning rules as
// their mutating counterpart: configured architectures render the prospective
// views while Built architectures identify protocol artifacts retained from
// the current Generation. Previews may use disposable scratch storage, but must
// not mutate the Workspace, SQLite state, public Repository, or depend on the
// scratch directory residing on the Repository filesystem.
package managed
