# ADR-0025: State Locks Bind an Exact OS Process Instance

- Status: Accepted
- Date: 2026-07-15
- Scope: local canonical-state writers on Linux and macOS

## Context

The legacy state lock records only a PID, operation, and wall-clock start time.
After a crash, PID reuse can make an unrelated live process look like the old
SOW writer forever. Conversely, treating a released advisory descriptor or a
timeout as proof of death can admit two writers. Neither behavior satisfies the
recovery and safe-replay contract.

SOW must also coexist with an older writer that knows only
`.sow/locks/state.lock`. A new persistent lease cannot replace that record lock
as the compatibility fence, and a contender blocked by the legacy fence must
not chmod the active record or reconcile unrelated state permissions.

## Decision

New records use schema v1 and bind one acquisition with all of:

- a cryptographically random 256-bit lock ID;
- the PID and operation;
- a Linux `boot_id` plus `/proc/<pid>/stat` start token, or a Darwin boot-time
  plus `kinfo_proc` start time;
- an advisory flock on both the stable `state.lease` inode and the visible
  `state.lock` inode.

Identity is mandatory for a new lock. Failure to read or validate the current
process identity aborts acquisition. `Validate`, mutation-boundary capabilities,
and `Release` re-read the current process identity. A mismatch or unavailable
probe fails closed; release keeps both leases and the durable record intact so
the same holder can retry after a transient probe failure, rather than deleting
evidence it can no longer prove it owns.

The visible record is never created empty. SOW first encodes and fsyncs the
complete v1 record on a private mode-0600
`state.lock.unpublished-<lock-id>` inode while already holding that inode's
advisory lease. A create-only hardlink publishes the same inode as
`state.lock`; the prepared name is then removed and the lock directory is
fsynced before permission reconciliation or any canonical mutation begins.
This gives the record a single namespace commit point on both Linux and macOS.

An abrupt exit before that hardlink leaves only non-authoritative unpublished
evidence, so a later invocation may acquire normally without `--recover` and
must not rewrite that evidence. An exit after the hardlink leaves a complete,
leased record and follows the ordinary explicit stale-recovery path. The
unpublished name can remain as an additional hardlink if the exit occurs
between publication and cleanup; it is evidence, never an ownership signal.
Malformed or foreign unpublished entries are not guessed away automatically.

An `O_EXCL` creator that fails or loses the immediate nonblocking prepared-inode
flock removes that still-private name only after proving it is the exact inode
it created and syncing the directory. No visible record was published, so
another observer of that private inode has no mutation capability; retaining it
after an ordinary returned error would only create unnecessary unpublished
evidence.

Recovery never uses elapsed time. With the record lease held, an observed v1
identity is compared with the PID's current identity. An exact active instance
blocks; a different instance or a process that is absent/dead permits explicit
`--recover`; an unavailable probe blocks. Linux `Z`/`X` states and Darwin
`SZOMB` are dead for this purpose because zombies have already closed every
descriptor and cannot mutate state. Legacy records remain conservative: an
observable PID blocks, an absent/dead PID may be explicitly recovered, and an
unavailable probe blocks.

Before a persistent lease exists, SOW performs a read-only compatibility
preflight on an existing `state.lock`. This keeps the ordinary active-legacy
path from creating `state.lease`. There is no portable atomic transaction over
the absence of two independent directory entries: a legacy process can create
`state.lock` after the preflight but before the new process creates
`state.lease`. The second, authoritative record-flock check still blocks safely,
but that race may leave the newly created empty persistent lease. The file is a
stable protocol inode, contains no record or secret, and is never evidence of
lock ownership by itself. Strict no-write behavior is guaranteed when the
legacy record already exists at preflight; safety, not an impossible two-name
atomicity claim, governs the race.

Permission reconciliation runs only after both advisory leases are held. Every
chmod uses an already-open descriptor and verifies the descriptor, original
inode, and current directory entry before and after the change. A blocked
contender therefore cannot mutate an active lease inode or unrelated state
children.

Release removes the owned visible record while its record flock and the
persistent flock are held, then releases the record flock, then the persistent
flock. An older nonblocking record-only writer remains excluded until the
visible record is removed; no canonical mutation occurs after that removal.

## Consequences

- PID reuse no longer creates a permanent false-live lock.
- A transient identity-probe failure can stop a command and can require a later
  retry or explicit recovery; this is intentional fail-closed behavior.
- A damaged, unknown, unavailable-identity, or in-place-tampered record is
  preserved for inspection rather than guessed away.
- The persistent lease is additive. The visible record flock remains the
  compatibility authority for legacy writers.
- Linux and macOS use only Go and kernel interfaces; no shell command or
  external runtime is involved.

## Validation

`internal/state/lock_instance_test.go`, `lock_permissions_test.go`, and the
platform identity tests cover exact-instance exclusion, PID reuse, dead and
zombie classification, unavailable probes, conservative legacy migration,
blocked-contender zero-write behavior, create/failure cleanup, inode/path
replacement, descriptor-bound chmod, release evidence preservation, and real
child-process exits on both sides of the atomic record-publication point. The
focused suite is required in ordinary and race modes, with `go vet` plus Linux
and Darwin compilation, under the repository's strict offline/no-cloud test
environment.
