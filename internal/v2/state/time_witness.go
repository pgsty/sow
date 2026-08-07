package state

import (
	"context"
	"fmt"
	"time"
)

// ObserveRepositoryTime durably advances the Repository wall-clock
// high-water mark.  A backward clock is rejected before callers make any
// target-visible change; an initially incorrect host clock remains an
// operational trust assumption and is intentionally not guessed around.
func (s *Store) ObserveRepositoryTime(ctx context.Context, observed time.Time) error {
	if observed.IsZero() {
		return fmt.Errorf("%w: repository clock observation is zero", ErrConflict)
	}
	observed = observed.UTC()
	observedText := formatTimestamp(observed)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var currentText string
	if err := tx.QueryRowContext(ctx, `SELECT max_observed_at FROM repository_time_witness WHERE singleton = 1`).Scan(&currentText); err != nil {
		return err
	}
	current, err := time.Parse(time.RFC3339Nano, currentText)
	if err != nil || currentText != formatTimestamp(current) {
		return fmt.Errorf("%w: repository time witness is invalid", ErrSchema)
	}
	if observed.Before(current) {
		return fmt.Errorf("%w: repository clock moved backwards from %s to %s", ErrConflict, currentText, observedText)
	}
	if observed.After(current) {
		if _, err := tx.ExecContext(ctx, `UPDATE repository_time_witness SET max_observed_at = ? WHERE singleton = 1`, observedText); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.Checkpoint(ctx)
}
