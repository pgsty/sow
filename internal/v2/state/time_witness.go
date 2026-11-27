package state

import (
	"context"
	"fmt"
	"time"
)

// ObserveRepositoryTime durably advances the Repository wall-clock high-water
// mark. Backward host-clock adjustments (e.g. NTP steps) retain the existing
// high-water mark rather than failing.
func (s *Store) ObserveRepositoryTime(ctx context.Context, observed time.Time) error {
	_, err := s.ObserveRepositoryTimeEffective(ctx, observed)
	return err
}

// ObserveRepositoryTimeEffective advances the Repository wall-clock high-water
// mark and returns max(observed, highWaterMark) so callers computing grace
// deadlines never shorten retention windows across a backward NTP adjustment.
func (s *Store) ObserveRepositoryTimeEffective(ctx context.Context, observed time.Time) (time.Time, error) {
	if observed.IsZero() {
		return time.Time{}, fmt.Errorf("%w: repository clock observation is zero", ErrConflict)
	}
	observed = observed.UTC()
	if observed.Year() < 1 || observed.Year() > 9999 {
		return time.Time{}, fmt.Errorf("%w: repository clock observation year %d is outside 1..9999", ErrConflict, observed.Year())
	}
	observedText := formatTimestamp(observed)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return time.Time{}, err
	}
	defer tx.Rollback()
	var currentText string
	if err := tx.QueryRowContext(ctx, `SELECT max_observed_at FROM repository_time_witness WHERE singleton = 1`).Scan(&currentText); err != nil {
		return time.Time{}, err
	}
	current, err := time.Parse(time.RFC3339Nano, currentText)
	if err != nil || current.Year() < 1 || current.Year() > 9999 || (currentText != formatTimestamp(current) && currentText != current.UTC().Format(time.RFC3339Nano)) {
		return time.Time{}, fmt.Errorf("%w: repository time witness is invalid", ErrSchema)
	}
	if observed.Before(current) {
		// Tolerate backward NTP/wall-clock adjustments by returning and
		// retaining the existing high-water mark rather than bricking the repo.
		return current.UTC(), nil
	}
	if observed.After(current) || currentText != formatTimestamp(current) {
		if _, err := tx.ExecContext(ctx, `UPDATE repository_time_witness SET max_observed_at = ? WHERE singleton = 1`, observedText); err != nil {
			return time.Time{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return time.Time{}, err
	}
	if err := s.checkpointAfterCommit(ctx); err != nil {
		return observed, err
	}
	return observed, nil
}
