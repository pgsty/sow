package cli

import (
	"errors"
	"fmt"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/state"
)

// openCanonicalFSCKAdmission validates both halves of canonical local state:
// every Git object reachable from any preservation root is consumed through a
// hash-verifying retained .git capability, and the mutable index/worktree is
// proven to be an exact permission-safe projection of HEAD. The caller keeps
// the session open until its final command barrier so later same-inode object
// mutations and repository-root swaps remain observable.
func openCanonicalFSCKAdmission(cfg *config.Config, lock *state.Lock, writable *state.Store) (*localReadAdmission, state.ReachableIntegrityStats, error) {
	var stats state.ReachableIntegrityStats
	if writable == nil {
		return nil, stats, errors.New("canonical fsck worktree store is unavailable")
	}
	session, err := openLockedLocalReadAdmission(cfg, lock)
	if err != nil {
		return nil, stats, err
	}
	fail := func(err error) (*localReadAdmission, state.ReachableIntegrityStats, error) {
		return nil, stats, errors.Join(err, session.Close())
	}
	if session.canonical == nil {
		return fail(errors.New("canonical Git state is not initialized (run 'sow init' first)"))
	}
	stats, err = session.canonical.AuditReachableObjects()
	if err != nil {
		return fail(fmt.Errorf("audit reachable canonical Git objects: %w", err))
	}
	auditWorktree := func() error {
		return writable.AuditCanonicalWorktreeBound(session.worktree, session.worktreeIdentity, session.gitIdentity)
	}
	if err := auditWorktree(); err != nil {
		return fail(fmt.Errorf("audit canonical Git worktree/index: %w", err))
	}
	// The first audit proves the input snapshot; the retained final recheck
	// catches persistent same-inode worktree/index/permission changes made
	// after repository scanning but before fsck reports success.
	session.rechecks = append(session.rechecks, auditWorktree)
	return session, stats, nil
}

func closeCanonicalFSCKAdmission(session *localReadAdmission) error {
	if session == nil {
		return nil
	}
	return errors.Join(session.Verify(""), session.Close())
}

// finalizeCanonicalFSCKAdmissionForMutation completes the immutable pre-write
// snapshot audit but deliberately retains its directory capabilities. The
// subsequent writer may change refs and objects, while verifyTopology still
// detects repository/state/worktree/.git replacement across that mutation.
func finalizeCanonicalFSCKAdmissionForMutation(session *localReadAdmission) error {
	if session == nil {
		return errors.New("canonical fsck mutation admission is unavailable")
	}
	return session.Verify("")
}

func closeCanonicalFSCKMutationTopology(session *localReadAdmission) error {
	if session == nil {
		return nil
	}
	return errors.Join(session.verifyTopology(), session.Close())
}

// propagateCanonicalFSCKFinalizer makes the retained admission's final
// integrity/topology recheck part of the command result. A close failure after
// an otherwise successful fsck is verification drift. When another failure is
// already being returned, join both errors so the original exit class remains
// authoritative while the concurrent canonical-state mutation is still
// visible to the operator.
func propagateCanonicalFSCKFinalizer(finalize func() error, subject string, resultErr *error) {
	if finalize == nil || resultErr == nil {
		return
	}
	finalizeErr := finalize()
	if finalizeErr == nil {
		return
	}
	contextual := fmt.Errorf("finalize %s: %w", subject, finalizeErr)
	if *resultErr == nil {
		*resultErr = withExitCode(ExitVerification, "%v", contextual)
		return
	}
	*resultErr = errors.Join(*resultErr, contextual)
}

// auditCanonicalGraphBeforeRecovery prevents an incomplete-transaction replay
// from consuming corrupt object bytes. Worktree/index exactness is intentionally
// deferred until after recovery because a valid interrupted transaction can
// leave those mutable projections dirty by design.
func auditCanonicalGraphBeforeRecovery(cfg *config.Config, lock *state.Lock) (state.ReachableIntegrityStats, error) {
	var stats state.ReachableIntegrityStats
	session, err := openLockedLocalReadAdmission(cfg, lock)
	if err != nil {
		return stats, err
	}
	if session.canonical == nil {
		return stats, errors.Join(errors.New("canonical Git state is not initialized (run 'sow init' first)"), session.Close())
	}
	stats, err = session.canonical.AuditReachableObjects()
	if err != nil {
		return stats, errors.Join(fmt.Errorf("audit reachable canonical Git objects before recovery: %w", err), session.Close())
	}
	if err := errors.Join(session.Verify(""), session.Close()); err != nil {
		return stats, err
	}
	return stats, nil
}
