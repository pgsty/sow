package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// PublicationTargetHead is the private, target-scoped CAS head. Revision is
// monotonic even when two checkpoints happen to carry the same Generation.
type PublicationTargetHead struct {
	TargetIdentity     string       `json:"target_identity"`
	CheckpointIdentity string       `json:"checkpoint_identity,omitempty"`
	Generation         GenerationID `json:"generation"`
	ManifestSHA256     string       `json:"manifest_sha256,omitempty"`
	Revision           int64        `json:"revision"`
}

type PublicationTargetSnapshot struct {
	Binding PublicationTargetBinding `json:"binding"`
	Head    PublicationTargetHead    `json:"head"`
}

type PublicationMaintenance struct {
	AttemptIdentity    string    `json:"attempt_identity"`
	CheckpointIdentity string    `json:"checkpoint_identity"`
	GraceIdentity      string    `json:"grace_identity"`
	AttemptPhase       string    `json:"attempt_phase"`
	GraceState         string    `json:"grace_state"`
	NotBefore          time.Time `json:"not_before"`
}

// GetPublicationTarget returns one binding and head after recomputing every
// persisted semantic identity. Callers must never resume from unchecked rows.
func (s *Store) GetPublicationTarget(ctx context.Context, targetIdentity string) (PublicationTargetSnapshot, error) {
	if !validSHA256Text(targetIdentity) {
		return PublicationTargetSnapshot{}, errors.New("invalid publication target identity")
	}
	var out PublicationTargetSnapshot
	var checkpoint, manifest sql.NullString
	var ttl int64
	var authoritative, singleWriter, exclusive int
	err := s.db.QueryRowContext(ctx, `SELECT
 b.target_identity, b.target_storage_id, b.repository_id, b.target_name, b.provider,
 b.endpoint, b.region, b.bucket, b.prefix, b.public_endpoint, b.max_cache_ttl_ns,
 b.authoritative_workspace, b.single_writer, b.exclusive_write_authority, b.config_identity,
 h.checkpoint_identity, h.generation, h.manifest_sha256, h.revision
FROM publication_target_bindings AS b
JOIN publication_target_heads AS h ON h.target_identity = b.target_identity
WHERE b.target_identity = ?`, targetIdentity).Scan(
		&out.Binding.TargetIdentity, &out.Binding.TargetStorageID, &out.Binding.RepositoryID, &out.Binding.TargetName,
		&out.Binding.Provider, &out.Binding.Endpoint, &out.Binding.Region, &out.Binding.Bucket, &out.Binding.Prefix,
		&out.Binding.PublicEndpoint, &ttl, &authoritative, &singleWriter, &exclusive, &out.Binding.ConfigIdentity,
		&checkpoint, &out.Head.Generation, &manifest, &out.Head.Revision,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return PublicationTargetSnapshot{}, fmt.Errorf("%w: publication target", ErrNotFound)
	}
	if err != nil {
		return PublicationTargetSnapshot{}, err
	}
	out.Binding.MaxCacheTTL = time.Duration(ttl)
	out.Binding.AuthoritativeWorkspace = authoritative == 1
	out.Binding.SingleWriter = singleWriter == 1
	out.Binding.ExclusiveWriteAuthority = exclusive == 1
	out.Head.TargetIdentity = out.Binding.TargetIdentity
	out.Head.CheckpointIdentity = checkpoint.String
	out.Head.ManifestSHA256 = manifest.String
	wantStorage := publicationIdentity("sow/target-storage/v1", out.Binding.Provider, out.Binding.Endpoint, out.Binding.Region, out.Binding.Bucket)
	wantTarget := publicationIdentity("sow/target/v1", wantStorage, out.Binding.Prefix)
	wantConfig := PublicationTargetConfigIdentity(out.Binding)
	if out.Binding.TargetStorageID != wantStorage || out.Binding.TargetIdentity != wantTarget || out.Binding.ConfigIdentity != wantConfig ||
		!out.Binding.AuthoritativeWorkspace || !out.Binding.SingleWriter || !out.Binding.ExclusiveWriteAuthority ||
		(out.Head.CheckpointIdentity == "") != (out.Head.Generation == 0) ||
		(out.Head.CheckpointIdentity == "") != (out.Head.ManifestSHA256 == "") {
		return PublicationTargetSnapshot{}, fmt.Errorf("%w: publication target semantic identity or head is corrupt", ErrConflict)
	}
	return out, nil
}

func (s *Store) GetPublicationAttempt(ctx context.Context, attemptIdentity string) (PublicationAttempt, error) {
	if !validSHA256Text(attemptIdentity) {
		return PublicationAttempt{}, errors.New("invalid publication attempt identity")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return PublicationAttempt{}, err
	}
	defer tx.Rollback()
	var out PublicationAttempt
	var base sql.NullString
	var commit int
	err = tx.QueryRowContext(ctx, `SELECT attempt_identity, schema_version, repository_id, target_identity,
 base_checkpoint, target_generation, manifest_sha256, plan_sha256, phase, commit_intent
FROM publication_attempts WHERE attempt_identity = ?`, attemptIdentity).Scan(
		&out.AttemptIdentity, &out.SchemaVersion, &out.RepositoryID, &out.TargetIdentity, &base,
		&out.TargetGeneration, &out.ManifestSHA256, &out.PlanSHA256, &out.Phase, &commit,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return PublicationAttempt{}, fmt.Errorf("%w: publication attempt", ErrNotFound)
	}
	if err != nil {
		return PublicationAttempt{}, err
	}
	out.BaseCheckpoint, out.CommitIntent = base.String, commit == 1
	out.Views, err = publicationAttemptViewsTx(ctx, tx, attemptIdentity)
	if err != nil {
		return PublicationAttempt{}, err
	}
	if publicationAttemptSemanticIdentity(out) != out.AttemptIdentity || validatePublicationAttempt(out) != nil {
		return PublicationAttempt{}, fmt.Errorf("%w: publication attempt semantic identity is corrupt", ErrConflict)
	}
	if err := tx.Commit(); err != nil {
		return PublicationAttempt{}, err
	}
	return out, nil
}

func (s *Store) GetActivePublicationAttempt(ctx context.Context, targetIdentity string) (PublicationAttempt, error) {
	if !validSHA256Text(targetIdentity) {
		return PublicationAttempt{}, errors.New("invalid publication target identity")
	}
	var identity string
	err := s.db.QueryRowContext(ctx, `SELECT attempt_identity FROM publication_attempts
WHERE target_identity = ? AND phase IN (
 'planned', 'payload', 'immutable_metadata', 'pointer_prepared',
 'commit_intent', 'pointer_rollforward', 'verified', 'applied'
)`, targetIdentity).Scan(&identity)
	if errors.Is(err, sql.ErrNoRows) {
		return PublicationAttempt{}, fmt.Errorf("%w: active publication attempt", ErrNotFound)
	}
	if err != nil {
		return PublicationAttempt{}, err
	}
	return s.GetPublicationAttempt(ctx, identity)
}

// ListPublicationAbandonedObjects returns exact, path-deduplicated orphan
// inventory for one target. Conflicting evidence is corruption, not a choice
// for the caller to resolve.
func (s *Store) ListPublicationAbandonedObjects(ctx context.Context, targetIdentity string) ([]PublicationAbandonedObject, error) {
	if !validSHA256Text(targetIdentity) {
		return nil, errors.New("invalid publication target identity")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT o.path, o.phase, o.size, o.sha256, o.remote_identity
FROM publication_abandoned_objects AS o
JOIN publication_attempts AS a ON a.attempt_identity = o.attempt_identity
WHERE a.target_identity = ? ORDER BY o.path, o.attempt_identity`, targetIdentity)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []PublicationAbandonedObject{}
	for rows.Next() {
		var object PublicationAbandonedObject
		if err := rows.Scan(&object.Path, &object.Phase, &object.Size, &object.SHA256, &object.RemoteIdentity); err != nil {
			return nil, err
		}
		if len(result) != 0 && result[len(result)-1].Path == object.Path {
			if result[len(result)-1] != object {
				return nil, fmt.Errorf("%w: conflicting abandoned object evidence for %q", ErrConflict, object.Path)
			}
			continue
		}
		result = append(result, object)
	}
	if err := rows.Err(); err != nil || !sortedAbandonedObjects(result) {
		return nil, errors.Join(fmt.Errorf("%w: invalid abandoned object evidence", ErrConflict), err)
	}
	return result, nil
}

// HasWriteActivePublication reports whether public Repository bytes are still
// the only roll-forward source for an in-flight target transaction. Managed
// builds and membership/lifecycle mutations must not replace those bytes until
// publish resumes through applied; grace itself is deliberately not active.
func (s *Store) HasWriteActivePublication(ctx context.Context) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM publication_attempts WHERE phase IN (
 'planned', 'payload', 'immutable_metadata', 'pointer_prepared',
 'commit_intent', 'pointer_rollforward', 'verified', 'applied'
)`).Scan(&count)
	return count != 0, err
}

// HasPendingPublicationMaintenance prevents a new target write from crossing
// an immutable candidate report whose retention/deletion terminal transition
// has not yet been acknowledged. The explicit target GC command must resume it.
func (s *Store) HasPendingPublicationMaintenance(ctx context.Context, targetIdentity string) (bool, error) {
	if !validSHA256Text(targetIdentity) {
		return false, errors.New("invalid publication target identity")
	}
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT count(*)
FROM publication_candidate_reports AS r
JOIN publication_checkpoints AS c ON c.checkpoint_identity = r.checkpoint_identity
JOIN publication_attempts AS a ON a.attempt_identity = c.attempt_identity
WHERE r.target_identity = ? AND a.phase != 'done'`, targetIdentity).Scan(&count)
	return count != 0, err
}

func (s *Store) ListPublicationMaintenance(ctx context.Context, targetIdentity string) ([]PublicationMaintenance, error) {
	if !validSHA256Text(targetIdentity) {
		return nil, errors.New("invalid publication target identity")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT a.attempt_identity, c.checkpoint_identity, g.grace_identity,
 a.phase, g.state, g.not_before
FROM publication_grace_records AS g
JOIN publication_checkpoints AS c ON c.checkpoint_identity = g.checkpoint_identity
JOIN publication_attempts AS a ON a.attempt_identity = c.attempt_identity
WHERE g.target_identity = ? AND a.phase != 'done'
ORDER BY g.not_before, c.checkpoint_identity`, targetIdentity)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []PublicationMaintenance{}
	for rows.Next() {
		var item PublicationMaintenance
		var notBefore string
		if err := rows.Scan(&item.AttemptIdentity, &item.CheckpointIdentity, &item.GraceIdentity, &item.AttemptPhase, &item.GraceState, &notBefore); err != nil {
			return nil, err
		}
		item.NotBefore, err = time.Parse(time.RFC3339Nano, notBefore)
		if err != nil || !validSHA256Text(item.AttemptIdentity) || !validSHA256Text(item.CheckpointIdentity) || !validSHA256Text(item.GraceIdentity) || publicationPhaseRank(item.AttemptPhase) < publicationPhaseRank("grace") || item.GraceState != "grace" && item.GraceState != "deletion_verified" && item.GraceState != "retained_reported" {
			return nil, fmt.Errorf("%w: invalid publication maintenance state", ErrConflict)
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) GetAppliedCheckpoint(ctx context.Context, checkpointIdentity string) (AppliedCheckpoint, error) {
	if !validSHA256Text(checkpointIdentity) {
		return AppliedCheckpoint{}, errors.New("invalid publication checkpoint identity")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return AppliedCheckpoint{}, err
	}
	defer tx.Rollback()
	var out AppliedCheckpoint
	var complete int
	var applied string
	err = tx.QueryRowContext(ctx, `SELECT checkpoint_identity, schema_version, repository_id, target_identity,
 attempt_identity, generation, manifest_sha256, inventory_identity, inventory_complete, applied_at
FROM publication_checkpoints WHERE checkpoint_identity = ?`, checkpointIdentity).Scan(
		&out.CheckpointIdentity, &out.SchemaVersion, &out.RepositoryID, &out.TargetIdentity, &out.AttemptIdentity,
		&out.Generation, &out.ManifestSHA256, &out.InventoryIdentity, &complete, &applied,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return AppliedCheckpoint{}, fmt.Errorf("%w: publication checkpoint", ErrNotFound)
	}
	if err != nil {
		return AppliedCheckpoint{}, err
	}
	out.InventoryComplete = complete == 1
	out.AppliedAt, err = time.Parse(time.RFC3339Nano, applied)
	if err != nil {
		return AppliedCheckpoint{}, fmt.Errorf("%w: invalid checkpoint timestamp", ErrSchema)
	}
	out.Views, err = publicationCheckpointViewsTx(ctx, tx, checkpointIdentity)
	if err == nil {
		out.Inventory, err = publicationInventoryTx(ctx, tx, checkpointIdentity)
	}
	if err != nil {
		return AppliedCheckpoint{}, err
	}
	if publicationInventoryIdentity(out.Inventory) != out.InventoryIdentity || appliedCheckpointSemanticIdentity(out) != out.CheckpointIdentity || validateAppliedCheckpoint(out) != nil {
		return AppliedCheckpoint{}, fmt.Errorf("%w: publication checkpoint semantic identity is corrupt", ErrConflict)
	}
	if err := tx.Commit(); err != nil {
		return AppliedCheckpoint{}, err
	}
	return out, nil
}

func (s *Store) GetAppliedCheckpointForAttempt(ctx context.Context, attemptIdentity string) (AppliedCheckpoint, error) {
	if !validSHA256Text(attemptIdentity) {
		return AppliedCheckpoint{}, errors.New("invalid publication attempt identity")
	}
	var checkpointIdentity string
	err := s.db.QueryRowContext(ctx, `SELECT checkpoint_identity FROM publication_checkpoints WHERE attempt_identity = ?`, attemptIdentity).Scan(&checkpointIdentity)
	if errors.Is(err, sql.ErrNoRows) {
		return AppliedCheckpoint{}, fmt.Errorf("%w: publication checkpoint for attempt", ErrNotFound)
	}
	if err != nil {
		return AppliedCheckpoint{}, err
	}
	return s.GetAppliedCheckpoint(ctx, checkpointIdentity)
}

func (s *Store) GetGraceRecord(ctx context.Context, checkpointIdentity string) (GraceRecord, error) {
	if !validSHA256Text(checkpointIdentity) {
		return GraceRecord{}, errors.New("invalid publication checkpoint identity")
	}
	var out GraceRecord
	var verified, notBefore string
	err := s.db.QueryRowContext(ctx, `SELECT grace_identity, schema_version, target_identity, checkpoint_identity,
 verified_at, not_before, cache_policy_identity, state
FROM publication_grace_records WHERE checkpoint_identity = ?`, checkpointIdentity).Scan(
		&out.GraceIdentity, &out.SchemaVersion, &out.TargetIdentity, &out.CheckpointIdentity,
		&verified, &notBefore, &out.CachePolicyIdentity, &out.State,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return GraceRecord{}, fmt.Errorf("%w: publication grace", ErrNotFound)
	}
	if err != nil {
		return GraceRecord{}, err
	}
	out.VerifiedAt, err = time.Parse(time.RFC3339Nano, verified)
	if err == nil {
		out.NotBefore, err = time.Parse(time.RFC3339Nano, notBefore)
	}
	if err != nil || graceSemanticIdentity(out) != out.GraceIdentity {
		return GraceRecord{}, fmt.Errorf("%w: publication grace semantic identity is corrupt", ErrConflict)
	}
	return out, nil
}

func (s *Store) GetPublicationCandidateReport(ctx context.Context, checkpointIdentity string) (PublicationCandidateReport, error) {
	if !validSHA256Text(checkpointIdentity) {
		return PublicationCandidateReport{}, errors.New("invalid publication checkpoint identity")
	}
	var identity string
	err := s.db.QueryRowContext(ctx, `SELECT report_identity FROM publication_candidate_reports WHERE checkpoint_identity = ?`, checkpointIdentity).Scan(&identity)
	if errors.Is(err, sql.ErrNoRows) {
		return PublicationCandidateReport{}, fmt.Errorf("%w: publication candidate report", ErrNotFound)
	}
	if err != nil {
		return PublicationCandidateReport{}, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return PublicationCandidateReport{}, err
	}
	defer tx.Rollback()
	out := PublicationCandidateReport{Candidates: []PublicationCandidate{}}
	var created string
	err = tx.QueryRowContext(ctx, `SELECT report_identity, schema_version, target_identity, checkpoint_identity,
 inventory_identity, mode, created_at FROM publication_candidate_reports WHERE report_identity = ?`, identity).Scan(
		&out.ReportIdentity, &out.SchemaVersion, &out.TargetIdentity, &out.CheckpointIdentity,
		&out.InventoryIdentity, &out.Mode, &created,
	)
	if err != nil {
		return PublicationCandidateReport{}, err
	}
	out.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return PublicationCandidateReport{}, fmt.Errorf("%w: invalid candidate report timestamp", ErrSchema)
	}
	rows, err := tx.QueryContext(ctx, `SELECT path, phase, size, sha256, remote_identity FROM publication_candidates WHERE report_identity = ? ORDER BY path`, identity)
	if err != nil {
		return PublicationCandidateReport{}, err
	}
	for rows.Next() {
		var candidate PublicationCandidate
		if err := rows.Scan(&candidate.Path, &candidate.Phase, &candidate.Size, &candidate.SHA256, &candidate.RemoteIdentity); err != nil {
			rows.Close()
			return PublicationCandidateReport{}, err
		}
		out.Candidates = append(out.Candidates, candidate)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return PublicationCandidateReport{}, err
	}
	if candidateReportSemanticIdentity(out) != out.ReportIdentity || !sortedCandidates(out.Candidates) {
		return PublicationCandidateReport{}, fmt.Errorf("%w: candidate report semantic identity is corrupt", ErrConflict)
	}
	if err := tx.Commit(); err != nil {
		return PublicationCandidateReport{}, err
	}
	return out, nil
}

// ExactPublicationCandidates returns the target-wide safe difference at one
// expired grace boundary. PutPublicationCandidateReport rechecks the same
// computation transactionally before making the report immutable.
func (s *Store) ExactPublicationCandidates(ctx context.Context, checkpointIdentity string, observedAt time.Time) ([]PublicationCandidate, error) {
	if !validSHA256Text(checkpointIdentity) {
		return nil, errors.New("invalid publication checkpoint identity")
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var targetIdentity, graceState, attemptPhase, notBefore string
	if err := tx.QueryRowContext(ctx, `SELECT c.target_identity, g.state, a.phase, g.not_before
FROM publication_checkpoints AS c
JOIN publication_grace_records AS g ON g.target_identity = c.target_identity AND g.checkpoint_identity = c.checkpoint_identity
JOIN publication_attempts AS a ON a.attempt_identity = c.attempt_identity
WHERE c.checkpoint_identity = ?`, checkpointIdentity).Scan(&targetIdentity, &graceState, &attemptPhase, &notBefore); err != nil {
		return nil, err
	}
	deadline, err := time.Parse(time.RFC3339Nano, notBefore)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid publication grace deadline", ErrSchema)
	}
	if graceState != "grace" || attemptPhase != "grace" || observedAt.Before(deadline) {
		return nil, fmt.Errorf("%w: publication grace is not ready for maintenance", ErrTransition)
	}
	var active int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM publication_attempts WHERE target_identity = ? AND phase IN (
 'planned', 'payload', 'immutable_metadata', 'pointer_prepared',
 'commit_intent', 'pointer_rollforward', 'verified', 'applied'
)`, targetIdentity).Scan(&active); err != nil {
		return nil, err
	}
	if active != 0 {
		return nil, fmt.Errorf("%w: target has a write-active publication attempt", ErrTransition)
	}
	candidates, err := exactPublicationCandidatesTx(ctx, tx, checkpointIdentity)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return candidates, nil
}

func (s *Store) GetPublicationDeletionReceipt(ctx context.Context, reportIdentity, objectPath string) (PublicationDeletionReceipt, error) {
	if !validSHA256Text(reportIdentity) || !validPublicationPath(objectPath) {
		return PublicationDeletionReceipt{}, errors.New("invalid publication deletion receipt lookup")
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return PublicationDeletionReceipt{}, err
	}
	defer tx.Rollback()
	receipt, found, err := publicationDeletionReceiptByPathTx(ctx, tx, reportIdentity, objectPath)
	if err != nil {
		return PublicationDeletionReceipt{}, err
	}
	if !found {
		return PublicationDeletionReceipt{}, fmt.Errorf("%w: publication deletion receipt", ErrNotFound)
	}
	if err := tx.Commit(); err != nil {
		return PublicationDeletionReceipt{}, err
	}
	return receipt, nil
}

// PublicationLiveInventory keeps the historical checkpoint immutable while
// projecting the exact objects that still exist after terminal filesystem
// deletion receipts. A pending partial report is deliberately excluded: publish
// is blocked until that report reaches its terminal phase.
func (s *Store) PublicationLiveInventory(ctx context.Context, checkpointIdentity string) ([]PublicationInventoryObject, error) {
	checkpoint, err := s.GetAppliedCheckpoint(ctx, checkpointIdentity)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT d.report_identity, d.path
FROM publication_deletion_receipts AS d
JOIN publication_candidate_reports AS r ON r.report_identity = d.report_identity
JOIN publication_checkpoints AS c ON c.checkpoint_identity = r.checkpoint_identity
JOIN publication_attempts AS a ON a.attempt_identity = c.attempt_identity
JOIN publication_grace_records AS g ON g.checkpoint_identity = c.checkpoint_identity
WHERE r.target_identity = ? AND r.mode = 'conditional_delete'
  AND g.state = 'deletion_verified' AND a.phase IN ('deletion_verified', 'done')
ORDER BY d.path, d.report_identity`, checkpoint.TargetIdentity)
	if err != nil {
		return nil, err
	}
	deleted := make(map[string]struct{})
	for rows.Next() {
		var reportIdentity, objectPath string
		if err := rows.Scan(&reportIdentity, &objectPath); err != nil {
			rows.Close()
			return nil, err
		}
		receipt, found, err := publicationDeletionReceiptByPathTx(ctx, tx, reportIdentity, objectPath)
		if err != nil || !found {
			rows.Close()
			return nil, errors.Join(fmt.Errorf("%w: missing terminal deletion receipt", ErrConflict), err)
		}
		deleted[publicationObjectEvidenceKey(receipt.Path, receipt.Phase, receipt.Size, receipt.SHA256, receipt.RemoteIdentity)] = struct{}{}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, err
	}
	result := make([]PublicationInventoryObject, 0, len(checkpoint.Inventory))
	for _, object := range checkpoint.Inventory {
		key := publicationObjectEvidenceKey(object.Path, object.Phase, object.Size, object.SHA256, object.RemoteIdentity)
		if _, absent := deleted[key]; !absent {
			result = append(result, object)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}
