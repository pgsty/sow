package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

type OperationPackage struct {
	Sequence      int               `json:"sequence"`
	InputPath     string            `json:"input_path"`
	PackageSHA256 string            `json:"package_sha256,omitempty"`
	Coordinate    string            `json:"coordinate,omitempty"`
	Disposition   string            `json:"disposition"`
	ErrorClass    string            `json:"error_class,omitempty"`
	Message       string            `json:"message,omitempty"`
	Dists         map[string]string `json:"dists,omitempty"`
}

// RecordOperationMembershipOutcomes appends deterministic policy evidence to
// the add/remove delta already recorded atomically by ApplyDesiredMutation.
// Objects excluded everywhere are intentionally absent from package_objects,
// so their digest must instead be bound to this Operation's package evidence.
func (s *Store) RecordOperationMembershipOutcomes(ctx context.Context, operationID string, outcomes []OperationMembership) error {
	canonical := append([]OperationMembership(nil), outcomes...)
	sort.Slice(canonical, func(i, j int) bool {
		if canonical[i].DistName != canonical[j].DistName {
			return canonical[i].DistName < canonical[j].DistName
		}
		if canonical[i].PackageSHA256 != canonical[j].PackageSHA256 {
			return canonical[i].PackageSHA256 < canonical[j].PackageSHA256
		}
		return canonical[i].Action < canonical[j].Action
	})
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	operationState, err := operationStateTx(ctx, tx, operationID)
	if err != nil {
		return err
	}
	if operationState != OperationApplied && operationState != OperationRecovering {
		return fmt.Errorf("%w: record membership outcomes in %s", ErrTransition, operationState)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM operation_memberships WHERE operation_id = ? AND action IN ('keep', 'exclude', 'limit')`, operationID); err != nil {
		return err
	}
	var sequence int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(sequence) + 1, 0) FROM operation_memberships WHERE operation_id = ?`, operationID).Scan(&sequence); err != nil {
		return err
	}
	previousPackage := ""
	for _, outcome := range canonical {
		if outcome.DistName == "" || !validSHA256Text(outcome.PackageSHA256) || (outcome.Action != "keep" && outcome.Action != "exclude" && outcome.Action != "limit") {
			return errors.New("invalid operation membership outcome")
		}
		packageIdentity := outcome.DistName + "\x00" + outcome.PackageSHA256
		if packageIdentity == previousPackage {
			return errors.New("conflicting or duplicate operation membership outcome")
		}
		previousPackage = packageIdentity
		var distExists, packageEvidence int
		if err := tx.QueryRowContext(ctx, `SELECT
EXISTS(SELECT 1 FROM dists WHERE name = ?),
EXISTS(SELECT 1 FROM package_objects WHERE sha256 = ?)
	OR EXISTS(SELECT 1 FROM operation_packages WHERE operation_id = ? AND package_sha256 = ?)
	OR EXISTS(SELECT 1 FROM operation_memberships WHERE operation_id = ? AND package_sha256 = ? AND action IN ('add', 'remove'))`, outcome.DistName, outcome.PackageSHA256, operationID, outcome.PackageSHA256, operationID, outcome.PackageSHA256).Scan(&distExists, &packageEvidence); err != nil {
			return err
		}
		if distExists == 0 {
			return fmt.Errorf("%w: outcome Dist %q", ErrNotFound, outcome.DistName)
		}
		if packageEvidence == 0 {
			return fmt.Errorf("%w: outcome package %s has no Operation evidence", ErrNotFound, outcome.PackageSHA256)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO operation_memberships(operation_id, sequence, dist_name, package_sha256, action) VALUES (?, ?, ?, ?, ?)`, operationID, sequence, outcome.DistName, outcome.PackageSHA256, outcome.Action); err != nil {
			return err
		}
		sequence++
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.Checkpoint(ctx)
}

type operationPackageMessage struct {
	Version int               `json:"version"`
	Message string            `json:"message,omitempty"`
	Dists   map[string]string `json:"dists"`
}

type OperationEvent struct {
	Sequence   int       `json:"sequence"`
	State      string    `json:"state"`
	DetailJSON string    `json:"detail_json"`
	OccurredAt time.Time `json:"occurred_at"`
}

type OperationMembership struct {
	Sequence      int    `json:"sequence"`
	DistName      string `json:"dist"`
	PackageSHA256 string `json:"package_sha256"`
	Action        string `json:"action"`
}

type OperationFile struct {
	Sequence int    `json:"sequence"`
	Action   string `json:"action"`
	Phase    string `json:"phase"`
	Path     string `json:"path"`
	Size     *int64 `json:"size,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
}

type OperationDetail struct {
	Operation   Operation             `json:"operation"`
	DurationMS  int64                 `json:"duration_ms"`
	Events      []OperationEvent      `json:"events"`
	Packages    []OperationPackage    `json:"packages"`
	Memberships []OperationMembership `json:"memberships"`
	Files       []OperationFile       `json:"files"`
}

func (s *Store) RecordOperationPackages(ctx context.Context, operationID string, packages []OperationPackage) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	state, err := operationStateTx(ctx, tx, operationID)
	if err != nil {
		return err
	}
	if state != OperationPlanned && state != OperationStaged {
		return fmt.Errorf("%w: record packages in %s", ErrTransition, state)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM operation_packages WHERE operation_id = ?`, operationID); err != nil {
		return err
	}
	for sequence, item := range packages {
		if item.InputPath == "" || (item.Disposition != "accepted" && item.Disposition != "reused" && item.Disposition != "excluded" && item.Disposition != "failed" && item.Disposition != "removed") {
			return errors.New("invalid operation package record")
		}
		var digest, coordinate, errorClass, message any
		if item.PackageSHA256 != "" {
			if !validSHA256Text(item.PackageSHA256) {
				return errors.New("invalid operation package sha256")
			}
			digest = item.PackageSHA256
		}
		if item.Coordinate != "" {
			coordinate = item.Coordinate
		}
		if item.ErrorClass != "" {
			errorClass = item.ErrorClass
		}
		if item.Message != "" {
			message = item.Message
		}
		if len(item.Dists) != 0 {
			for dist, outcome := range item.Dists {
				if dist == "" || (outcome != "accepted" && outcome != "excluded" && outcome != "limited") {
					return errors.New("invalid operation package Dist outcome")
				}
			}
			encoded, err := json.Marshal(operationPackageMessage{Version: 1, Message: item.Message, Dists: item.Dists})
			if err != nil {
				return err
			}
			message = string(encoded)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO operation_packages(operation_id, sequence, input_path, package_sha256, coordinate, disposition, error_class, message) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, operationID, sequence, item.InputPath, digest, coordinate, item.Disposition, errorClass, message); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.Checkpoint(ctx)
}

func (s *Store) ListOperations(ctx context.Context, limit int, dist string) ([]Operation, error) {
	return s.listOperations(ctx, limit, dist, false)
}

// ListTerminalOperationPage returns a stable oldest-first page strictly after
// the supplied cursor. It lets audit export cover an unbounded history without
// silently truncating or retaining every Operation in memory.
func (s *Store) ListTerminalOperationPage(ctx context.Context, limit int, dist string, after *Operation) ([]Operation, error) {
	if limit < 1 || limit > 100000 {
		return nil, errors.New("invalid operation list limit")
	}
	query := `SELECT id, kind, state, payload_json, result_json, error_class, error_message, created_at, updated_at
FROM operations
WHERE state IN ('done', 'done_dirty', 'rolled_back', 'failed')`
	args := []any{}
	if dist != "" {
		query += ` AND (EXISTS (SELECT 1 FROM json_each(operations.payload_json, '$.dists') WHERE value = ?) OR json_extract(operations.payload_json, '$.name') = ?)`
		args = append(args, dist, dist)
	}
	if after != nil {
		created := formatTimestamp(after.CreatedAt)
		query += ` AND (created_at > ? OR (created_at = ? AND id > ?))`
		args = append(args, created, created, after.ID)
	}
	query += ` ORDER BY created_at ASC, id ASC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	operations := []Operation{}
	for rows.Next() {
		operation, err := scanOperation(rows)
		if err != nil {
			return nil, err
		}
		operations = append(operations, operation)
	}
	return operations, rows.Err()
}

func (s *Store) listOperations(ctx context.Context, limit int, dist string, terminalOnly bool) ([]Operation, error) {
	if limit < 1 || limit > 100000 {
		return nil, errors.New("invalid operation list limit")
	}
	query := `SELECT id, kind, state, payload_json, result_json, error_class, error_message, created_at, updated_at FROM operations`
	args := []any{}
	where := []string{}
	if terminalOnly {
		where = append(where, `state IN ('done', 'done_dirty', 'rolled_back', 'failed')`)
	}
	if dist != "" {
		where = append(where, `(EXISTS (SELECT 1 FROM json_each(operations.payload_json, '$.dists') WHERE value = ?) OR json_extract(operations.payload_json, '$.name') = ?)`)
		args = append(args, dist, dist)
	}
	if len(where) != 0 {
		query += ` WHERE ` + strings.Join(where, ` AND `)
	}
	query += ` ORDER BY created_at DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	operations := []Operation{}
	for rows.Next() {
		operation, err := scanOperation(rows)
		if err != nil {
			return nil, err
		}
		operations = append(operations, operation)
	}
	return operations, rows.Err()
}

func (s *Store) GetOperation(ctx context.Context, id string) (OperationDetail, error) {
	if !operationIDPattern.MatchString(id) {
		return OperationDetail{}, fmt.Errorf("%w: invalid operation id", ErrNotFound)
	}
	operation, err := scanOperation(s.db.QueryRowContext(ctx, `SELECT id, kind, state, payload_json, result_json, error_class, error_message, created_at, updated_at FROM operations WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return OperationDetail{}, fmt.Errorf("%w: operation %s", ErrNotFound, id)
	}
	if err != nil {
		return OperationDetail{}, err
	}
	duration := operation.UpdatedAt.Sub(operation.CreatedAt)
	if duration < 0 {
		return OperationDetail{}, errors.New("operation audit timestamps are inconsistent")
	}
	detail := OperationDetail{Operation: operation, DurationMS: duration.Milliseconds(), Events: []OperationEvent{}, Packages: []OperationPackage{}, Memberships: []OperationMembership{}, Files: []OperationFile{}}
	events, err := s.db.QueryContext(ctx, `SELECT sequence, state, detail_json, occurred_at FROM operation_events WHERE operation_id = ? ORDER BY sequence`, id)
	if err != nil {
		return OperationDetail{}, err
	}
	for events.Next() {
		var event OperationEvent
		var at string
		if err := events.Scan(&event.Sequence, &event.State, &event.DetailJSON, &at); err != nil {
			events.Close()
			return OperationDetail{}, err
		}
		event.OccurredAt, err = time.Parse(time.RFC3339Nano, at)
		if err != nil {
			events.Close()
			return OperationDetail{}, err
		}
		detail.Events = append(detail.Events, event)
	}
	if err := errors.Join(events.Err(), events.Close()); err != nil {
		return OperationDetail{}, err
	}
	packages, err := s.db.QueryContext(ctx, `SELECT sequence, input_path, package_sha256, coordinate, disposition, error_class, message FROM operation_packages WHERE operation_id = ? ORDER BY sequence`, id)
	if err != nil {
		return OperationDetail{}, err
	}
	for packages.Next() {
		var item OperationPackage
		var digest, coordinate, errorClass, message sql.NullString
		if err := packages.Scan(&item.Sequence, &item.InputPath, &digest, &coordinate, &item.Disposition, &errorClass, &message); err != nil {
			packages.Close()
			return OperationDetail{}, err
		}
		item.PackageSHA256, item.Coordinate, item.ErrorClass, item.Message = digest.String, coordinate.String, errorClass.String, message.String
		if message.Valid {
			var evidence operationPackageMessage
			if json.Unmarshal([]byte(message.String), &evidence) == nil && evidence.Version == 1 && evidence.Dists != nil {
				item.Message, item.Dists = evidence.Message, evidence.Dists
			}
		}
		detail.Packages = append(detail.Packages, item)
	}
	if err := errors.Join(packages.Err(), packages.Close()); err != nil {
		return OperationDetail{}, err
	}
	memberships, err := s.db.QueryContext(ctx, `SELECT sequence, dist_name, package_sha256, action FROM operation_memberships WHERE operation_id = ? ORDER BY sequence`, id)
	if err != nil {
		return OperationDetail{}, err
	}
	for memberships.Next() {
		var item OperationMembership
		if err := memberships.Scan(&item.Sequence, &item.DistName, &item.PackageSHA256, &item.Action); err != nil {
			memberships.Close()
			return OperationDetail{}, err
		}
		detail.Memberships = append(detail.Memberships, item)
	}
	if err := errors.Join(memberships.Err(), memberships.Close()); err != nil {
		return OperationDetail{}, err
	}
	files, err := s.db.QueryContext(ctx, `SELECT sequence, action, phase, path, size, sha256 FROM operation_files WHERE operation_id = ? ORDER BY sequence`, id)
	if err != nil {
		return OperationDetail{}, err
	}
	for files.Next() {
		var item OperationFile
		var size sql.NullInt64
		var digest sql.NullString
		if err := files.Scan(&item.Sequence, &item.Action, &item.Phase, &item.Path, &size, &digest); err != nil {
			files.Close()
			return OperationDetail{}, err
		}
		if size.Valid {
			value := size.Int64
			item.Size = &value
		}
		item.SHA256 = digest.String
		detail.Files = append(detail.Files, item)
	}
	if err := errors.Join(files.Err(), files.Close()); err != nil {
		return OperationDetail{}, err
	}
	return detail, nil
}

func (s *Store) PruneTerminalOperations(ctx context.Context, before time.Time) (int64, error) {
	if before.IsZero() {
		return 0, errors.New("invalid prune cutoff")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `DELETE FROM operations
WHERE state IN ('done', 'done_dirty', 'rolled_back', 'failed')
  AND updated_at < ?
	  AND NOT EXISTS (SELECT 1 FROM generations WHERE generations.operation_id = operations.id)`, formatTimestamp(before))
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	if err := s.Checkpoint(ctx); err != nil {
		return count, fmt.Errorf("checkpoint pruned repository audit database after committed delete: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `VACUUM`); err != nil {
		return count, fmt.Errorf("vacuum repository audit database after committed delete: %w", err)
	}
	if err := s.Checkpoint(ctx); err != nil {
		return count, fmt.Errorf("checkpoint vacuumed repository audit database after committed delete: %w", err)
	}
	return count, nil
}

// ApplyPruneOperation atomically applies the audit deletion and records its
// bounded result in the journal. Database compaction is a recoverable applied
// phase completed separately by FinishPruneOperation.
func (s *Store) ApplyPruneOperation(ctx context.Context, id string, before time.Time) (int64, error) {
	if before.IsZero() || !operationIDPattern.MatchString(id) {
		return 0, errors.New("invalid journaled prune request")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var kind, current, priorResult string
	if err := tx.QueryRowContext(ctx, `SELECT kind, state, result_json FROM operations WHERE id = ?`, id).Scan(&kind, &current, &priorResult); errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("%w: operation %q", ErrNotFound, id)
	} else if err != nil {
		return 0, err
	}
	if kind != "log.prune" {
		return 0, errors.New("prune operation has the wrong kind")
	}
	if OperationState(current) == OperationDone || OperationState(current) == OperationApplied {
		var result struct {
			Pruned int64 `json:"pruned"`
		}
		if err := json.Unmarshal([]byte(priorResult), &result); err != nil || result.Pruned < 0 {
			return 0, errors.New("completed prune operation has an invalid result")
		}
		return result.Pruned, nil
	}
	if OperationState(current) != OperationStaged && OperationState(current) != OperationRecovering {
		return 0, fmt.Errorf("%w: log prune cannot complete from %s", ErrTransition, current)
	}
	deleted, err := tx.ExecContext(ctx, `DELETE FROM operations
WHERE state IN ('done', 'done_dirty', 'rolled_back', 'failed')
  AND updated_at < ?
  AND NOT EXISTS (SELECT 1 FROM generations WHERE generations.operation_id = operations.id)`, formatTimestamp(before))
	if err != nil {
		return 0, err
	}
	count, err := deleted.RowsAffected()
	if err != nil {
		return 0, err
	}
	resultJSON, err := json.Marshal(struct {
		Before string `json:"before"`
		Pruned int64  `json:"pruned"`
	}{Before: before.UTC().Format(time.RFC3339Nano), Pruned: count})
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE operations SET result_json = ? WHERE id = ?`, string(resultJSON), id); err != nil {
		return 0, err
	}
	if err := setOperationStateTx(ctx, tx, id, OperationApplied, "", ""); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	if err := s.Checkpoint(ctx); err != nil {
		return count, fmt.Errorf("checkpoint journaled audit prune after committed delete: %w", err)
	}
	return count, nil
}

// FinishPruneOperation makes the compaction phase crash-recoverable. The
// operation remains applied until checkpoint/VACUUM/checkpoint all succeed;
// recovery may safely repeat that maintenance before recording done.
func (s *Store) FinishPruneOperation(ctx context.Context, id string) error {
	if !operationIDPattern.MatchString(id) {
		return errors.New("invalid journaled prune operation")
	}
	var kind, current string
	if err := s.db.QueryRowContext(ctx, `SELECT kind, state FROM operations WHERE id = ?`, id).Scan(&kind, &current); errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: operation %q", ErrNotFound, id)
	} else if err != nil {
		return err
	}
	if kind != "log.prune" {
		return errors.New("prune operation has the wrong kind")
	}
	if OperationState(current) == OperationDone {
		return nil
	}
	if OperationState(current) != OperationApplied {
		return fmt.Errorf("%w: log prune maintenance cannot finish from %s", ErrTransition, current)
	}
	if err := s.Checkpoint(ctx); err != nil {
		return fmt.Errorf("checkpoint journaled audit prune before compaction: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `VACUUM`); err != nil {
		return fmt.Errorf("vacuum repository audit database after committed delete: %w", err)
	}
	if err := s.Checkpoint(ctx); err != nil {
		return fmt.Errorf("checkpoint vacuumed repository audit database after committed delete: %w", err)
	}
	return s.SetOperationState(ctx, id, OperationDone, "")
}
