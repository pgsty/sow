package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"
)

const publicationRecordSchemaV1 = 1

type PublicationTargetBinding struct {
	TargetIdentity          string
	TargetStorageID         string
	RepositoryID            string
	TargetName              string
	Provider                string
	Endpoint                string
	Region                  string
	Bucket                  string
	Prefix                  string
	PublicEndpoint          string
	MaxCacheTTL             time.Duration
	AuthoritativeWorkspace  bool
	SingleWriter            bool
	ExclusiveWriteAuthority bool
	ConfigIdentity          string
}

type PublicationAttemptView struct {
	ViewID      string `json:"view_id"`
	PointerPath string `json:"pointer_path"`
	OldIdentity string `json:"old_identity,omitempty"`
	NewIdentity string `json:"new_identity"`
	State       string `json:"state"`
}

type PublicationAttempt struct {
	AttemptIdentity  string                   `json:"attempt_identity"`
	SchemaVersion    int                      `json:"schema_version"`
	RepositoryID     string                   `json:"repository_id"`
	TargetIdentity   string                   `json:"target_identity"`
	BaseCheckpoint   string                   `json:"base_checkpoint,omitempty"`
	TargetGeneration GenerationID             `json:"target_generation"`
	ManifestSHA256   string                   `json:"manifest_sha256"`
	PlanSHA256       string                   `json:"plan_sha256"`
	Phase            string                   `json:"phase"`
	CommitIntent     bool                     `json:"commit_intent"`
	Views            []PublicationAttemptView `json:"views"`
}

// PublicationAbandonedObject is exact target evidence for an add-only object
// that may remain after a pre-commit attempt is abandoned. It contains no
// payload bytes and is deliberately target-scoped through its attempt.
type PublicationAbandonedObject struct {
	Path           string `json:"path"`
	Phase          string `json:"phase"`
	Size           int64  `json:"size"`
	SHA256         string `json:"sha256"`
	RemoteIdentity string `json:"remote_identity"`
}

type PublicationCheckpointView struct {
	ViewID         string `json:"view_id"`
	PointerPath    string `json:"pointer_path"`
	RemoteIdentity string `json:"remote_identity"`
}

type PublicationInventoryObject struct {
	Path           string `json:"path"`
	Phase          string `json:"phase"`
	Size           int64  `json:"size"`
	SHA256         string `json:"sha256"`
	RemoteIdentity string `json:"remote_identity"`
}

type AppliedCheckpoint struct {
	CheckpointIdentity string                       `json:"checkpoint_identity"`
	SchemaVersion      int                          `json:"schema_version"`
	RepositoryID       string                       `json:"repository_id"`
	TargetIdentity     string                       `json:"target_identity"`
	AttemptIdentity    string                       `json:"attempt_identity"`
	Generation         GenerationID                 `json:"generation"`
	ManifestSHA256     string                       `json:"manifest_sha256"`
	InventoryIdentity  string                       `json:"inventory_identity"`
	InventoryComplete  bool                         `json:"inventory_complete"`
	Views              []PublicationCheckpointView  `json:"views"`
	Inventory          []PublicationInventoryObject `json:"inventory"`
	AppliedAt          time.Time                    `json:"applied_at"`
}

type GraceRecord struct {
	GraceIdentity       string    `json:"grace_identity"`
	SchemaVersion       int       `json:"schema_version"`
	TargetIdentity      string    `json:"target_identity"`
	CheckpointIdentity  string    `json:"checkpoint_identity"`
	VerifiedAt          time.Time `json:"verified_at"`
	NotBefore           time.Time `json:"not_before"`
	CachePolicyIdentity string    `json:"cache_policy_identity"`
	State               string    `json:"state"`
}

type PublicationCandidate struct {
	Path           string `json:"path"`
	Phase          string `json:"phase"`
	Size           int64  `json:"size"`
	SHA256         string `json:"sha256"`
	RemoteIdentity string `json:"remote_identity"`
}

type PublicationCandidateReport struct {
	ReportIdentity     string                 `json:"report_identity"`
	SchemaVersion      int                    `json:"schema_version"`
	TargetIdentity     string                 `json:"target_identity"`
	CheckpointIdentity string                 `json:"checkpoint_identity"`
	InventoryIdentity  string                 `json:"inventory_identity"`
	Mode               string                 `json:"mode"`
	Candidates         []PublicationCandidate `json:"candidates"`
	CreatedAt          time.Time              `json:"created_at"`
}

type PublicationDeletionReceipt struct {
	ReceiptIdentity string    `json:"receipt_identity"`
	ReportIdentity  string    `json:"report_identity"`
	Path            string    `json:"path"`
	Phase           string    `json:"phase"`
	Size            int64     `json:"size"`
	SHA256          string    `json:"sha256"`
	RemoteIdentity  string    `json:"remote_identity"`
	StorageAbsent   bool      `json:"storage_absent"`
	PublicAbsent    bool      `json:"public_absent"`
	ObservedAt      time.Time `json:"observed_at"`
}

type publicationAttemptViewIdentity struct {
	ViewID      string `json:"view_id"`
	PointerPath string `json:"pointer_path"`
	OldIdentity string `json:"old_identity,omitempty"`
	NewIdentity string `json:"new_identity"`
}

func PublicationTargetConfigIdentity(binding PublicationTargetBinding) string {
	return publicationSemanticIdentity("sow/publication-target-config/v1", struct {
		RepositoryID            string `json:"repository_id"`
		TargetName              string `json:"target_name"`
		Provider                string `json:"provider"`
		Endpoint                string `json:"endpoint"`
		Region                  string `json:"region"`
		Bucket                  string `json:"bucket"`
		Prefix                  string `json:"prefix"`
		PublicEndpoint          string `json:"public_endpoint"`
		MaxCacheTTLNS           int64  `json:"max_cache_ttl_ns"`
		AuthoritativeWorkspace  bool   `json:"authoritative_workspace"`
		SingleWriter            bool   `json:"single_writer"`
		ExclusiveWriteAuthority bool   `json:"exclusive_write_authority"`
	}{binding.RepositoryID, binding.TargetName, binding.Provider, binding.Endpoint, binding.Region, binding.Bucket, binding.Prefix, binding.PublicEndpoint, binding.MaxCacheTTL.Nanoseconds(), binding.AuthoritativeWorkspace, binding.SingleWriter, binding.ExclusiveWriteAuthority})
}

func publicationAttemptSemanticIdentity(attempt PublicationAttempt) string {
	views := make([]publicationAttemptViewIdentity, len(attempt.Views))
	for index, view := range attempt.Views {
		views[index] = publicationAttemptViewIdentity{view.ViewID, view.PointerPath, view.OldIdentity, view.NewIdentity}
	}
	return publicationSemanticIdentity("sow/publication-attempt/v1", struct {
		RepositoryID     string                           `json:"repository_id"`
		TargetIdentity   string                           `json:"target_identity"`
		BaseCheckpoint   string                           `json:"base_checkpoint,omitempty"`
		TargetGeneration GenerationID                     `json:"target_generation"`
		ManifestSHA256   string                           `json:"manifest_sha256"`
		PlanSHA256       string                           `json:"plan_sha256"`
		Views            []publicationAttemptViewIdentity `json:"views"`
	}{attempt.RepositoryID, attempt.TargetIdentity, attempt.BaseCheckpoint, attempt.TargetGeneration, attempt.ManifestSHA256, attempt.PlanSHA256, views})
}

func publicationInventoryIdentity(inventory []PublicationInventoryObject) string {
	return publicationSemanticIdentity("sow/publication-inventory/v1", inventory)
}

func appliedCheckpointSemanticIdentity(checkpoint AppliedCheckpoint) string {
	return publicationSemanticIdentity("sow/applied-checkpoint/v1", struct {
		RepositoryID      string                      `json:"repository_id"`
		TargetIdentity    string                      `json:"target_identity"`
		AttemptIdentity   string                      `json:"attempt_identity"`
		Generation        GenerationID                `json:"generation"`
		ManifestSHA256    string                      `json:"manifest_sha256"`
		InventoryIdentity string                      `json:"inventory_identity"`
		InventoryComplete bool                        `json:"inventory_complete"`
		Views             []PublicationCheckpointView `json:"views"`
	}{checkpoint.RepositoryID, checkpoint.TargetIdentity, checkpoint.AttemptIdentity, checkpoint.Generation, checkpoint.ManifestSHA256, checkpoint.InventoryIdentity, checkpoint.InventoryComplete, checkpoint.Views})
}

func graceSemanticIdentity(record GraceRecord) string {
	return publicationSemanticIdentity("sow/grace-record/v1", struct {
		TargetIdentity      string `json:"target_identity"`
		CheckpointIdentity  string `json:"checkpoint_identity"`
		VerifiedAt          string `json:"verified_at"`
		NotBefore           string `json:"not_before"`
		CachePolicyIdentity string `json:"cache_policy_identity"`
	}{record.TargetIdentity, record.CheckpointIdentity, formatTimestamp(record.VerifiedAt), formatTimestamp(record.NotBefore), record.CachePolicyIdentity})
}

func candidateReportSemanticIdentity(report PublicationCandidateReport) string {
	return publicationSemanticIdentity("sow/publication-candidate-report/v1", struct {
		TargetIdentity     string                 `json:"target_identity"`
		CheckpointIdentity string                 `json:"checkpoint_identity"`
		InventoryIdentity  string                 `json:"inventory_identity"`
		Mode               string                 `json:"mode"`
		Candidates         []PublicationCandidate `json:"candidates"`
	}{report.TargetIdentity, report.CheckpointIdentity, report.InventoryIdentity, report.Mode, report.Candidates})
}

func deletionReceiptSemanticIdentity(receipt PublicationDeletionReceipt) string {
	return publicationSemanticIdentity("sow/publication-deletion-receipt/v1", struct {
		ReportIdentity string `json:"report_identity"`
		Path           string `json:"path"`
		Phase          string `json:"phase"`
		Size           int64  `json:"size"`
		SHA256         string `json:"sha256"`
		RemoteIdentity string `json:"remote_identity"`
		StorageAbsent  bool   `json:"storage_absent"`
		PublicAbsent   bool   `json:"public_absent"`
		ObservedAt     string `json:"observed_at"`
	}{receipt.ReportIdentity, receipt.Path, receipt.Phase, receipt.Size, receipt.SHA256, receipt.RemoteIdentity, receipt.StorageAbsent, receipt.PublicAbsent, formatTimestamp(receipt.ObservedAt)})
}

func acceptSemanticIdentity(provided, computed, label string) (string, error) {
	if provided != "" && provided != computed {
		return "", fmt.Errorf("%w: %s does not match canonical semantic bytes", ErrConflict, label)
	}
	return computed, nil
}

func (s *Store) BindPublicationTarget(ctx context.Context, binding PublicationTargetBinding) error {
	identity, err := s.RepositoryIdentity(ctx)
	if err != nil {
		return err
	}
	binding.TargetStorageID, err = acceptSemanticIdentity(binding.TargetStorageID, publicationIdentity("sow/target-storage/v1", binding.Provider, binding.Endpoint, binding.Region, binding.Bucket), "target storage identity")
	if err != nil {
		return err
	}
	binding.TargetIdentity, err = acceptSemanticIdentity(binding.TargetIdentity, publicationIdentity("sow/target/v1", binding.TargetStorageID, binding.Prefix), "target identity")
	if err != nil {
		return err
	}
	binding.ConfigIdentity, err = acceptSemanticIdentity(binding.ConfigIdentity, PublicationTargetConfigIdentity(binding), "target config identity")
	if err != nil {
		return err
	}
	if binding.RepositoryID != identity.RepositoryID || !validSHA256Text(binding.TargetStorageID) || !validSHA256Text(binding.TargetIdentity) || !validSHA256Text(binding.ConfigIdentity) || binding.TargetName == "" || binding.Endpoint == "" || binding.PublicEndpoint == "" || binding.MaxCacheTTL < 0 || !binding.AuthoritativeWorkspace || !binding.SingleWriter || !binding.ExclusiveWriteAuthority {
		return errors.New("invalid publication target binding")
	}
	if binding.Provider != "filesystem" && binding.Provider != "r2" {
		return errors.New("invalid publication target provider")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT target_identity, target_name, prefix FROM publication_target_bindings WHERE target_storage_id = ? ORDER BY prefix, target_name`, binding.TargetStorageID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var targetIdentity, name, prefix string
		if err := rows.Scan(&targetIdentity, &name, &prefix); err != nil {
			rows.Close()
			return err
		}
		if targetIdentity != binding.TargetIdentity && publicationPrefixesOverlap(prefix, binding.Prefix) {
			rows.Close()
			return fmt.Errorf("%w: publication targets %q and %q have overlapping prefixes", ErrConflict, name, binding.TargetName)
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM publication_target_bindings WHERE target_identity = ? AND repository_id = ? AND target_name = ? AND target_storage_id = ? AND provider = ? AND endpoint = ? AND region = ? AND bucket = ? AND prefix = ? AND public_endpoint = ? AND max_cache_ttl_ns = ? AND config_identity = ?`,
		binding.TargetIdentity, binding.RepositoryID, binding.TargetName, binding.TargetStorageID, binding.Provider, binding.Endpoint, binding.Region, binding.Bucket, binding.Prefix, binding.PublicEndpoint, binding.MaxCacheTTL.Nanoseconds(), binding.ConfigIdentity).Scan(&count); err != nil {
		return err
	}
	if count == 1 {
		return tx.Commit()
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO publication_target_bindings(target_identity, target_storage_id, repository_id, target_name, provider, endpoint, region, bucket, prefix, public_endpoint, max_cache_ttl_ns, authoritative_workspace, single_writer, exclusive_write_authority, config_identity, bound_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, 1, ?, ?)`,
		binding.TargetIdentity, binding.TargetStorageID, binding.RepositoryID, binding.TargetName, binding.Provider, binding.Endpoint, binding.Region, binding.Bucket, binding.Prefix, binding.PublicEndpoint, binding.MaxCacheTTL.Nanoseconds(), binding.ConfigIdentity, nowText()); err != nil {
		return fmt.Errorf("%w: bind publication target: %v", ErrConflict, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO publication_target_heads(target_identity, checkpoint_identity, generation, manifest_sha256, revision, updated_at) VALUES (?, NULL, '00000000000000000000', NULL, 0, ?)`, binding.TargetIdentity, nowText()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) PutPublicationAttempt(ctx context.Context, attempt *PublicationAttempt) error {
	if attempt == nil {
		return errors.New("nil publication attempt")
	}
	if attempt.SchemaVersion == 0 {
		attempt.SchemaVersion = publicationRecordSchemaV1
	}
	if err := validatePublicationAttempt(*attempt); err != nil {
		return err
	}
	if attempt.Phase != "planned" || attempt.CommitIntent {
		return errors.New("new publication attempt must start planned without commit intent")
	}
	for _, view := range attempt.Views {
		if view.State != "pending" {
			return errors.New("new publication attempt views must start pending")
		}
	}
	computedIdentity, err := acceptSemanticIdentity(attempt.AttemptIdentity, publicationAttemptSemanticIdentity(*attempt), "publication attempt identity")
	if err != nil {
		return err
	}
	attempt.AttemptIdentity = computedIdentity
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := requirePublicationBindingTx(ctx, tx, attempt.RepositoryID, attempt.TargetIdentity); err != nil {
		return err
	}
	exists, same, err := publicationAttemptSemanticMatchTx(ctx, tx, *attempt)
	if err != nil {
		return err
	}
	if exists {
		if !same {
			return fmt.Errorf("%w: publication attempt identity has different semantic bytes", ErrConflict)
		}
		var phase string
		var commit int
		if err := tx.QueryRowContext(ctx, `SELECT phase, commit_intent FROM publication_attempts WHERE attempt_identity = ?`, attempt.AttemptIdentity).Scan(&phase, &commit); err != nil {
			return err
		}
		if phase == "abandoned" && commit == 0 {
			var head sql.NullString
			if err := tx.QueryRowContext(ctx, `SELECT checkpoint_identity FROM publication_target_heads WHERE target_identity = ?`, attempt.TargetIdentity).Scan(&head); err != nil {
				return err
			}
			if head.Valid != (attempt.BaseCheckpoint != "") || head.Valid && head.String != attempt.BaseCheckpoint {
				return fmt.Errorf("%w: abandoned publication attempt base checkpoint differs from target head", ErrConflict)
			}
			if _, err := tx.ExecContext(ctx, `UPDATE publication_attempt_views SET state = 'pending' WHERE attempt_identity = ?`, attempt.AttemptIdentity); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE publication_attempts SET phase = 'planned', updated_at = ? WHERE attempt_identity = ? AND phase = 'abandoned' AND commit_intent = 0`, nowText(), attempt.AttemptIdentity); err != nil {
				return err
			}
		}
		return tx.Commit()
	}
	var head sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT checkpoint_identity FROM publication_target_heads WHERE target_identity = ?`, attempt.TargetIdentity).Scan(&head); err != nil {
		return err
	}
	if head.Valid != (attempt.BaseCheckpoint != "") || head.Valid && head.String != attempt.BaseCheckpoint {
		return fmt.Errorf("%w: publication attempt base checkpoint differs from target head", ErrConflict)
	}
	now := nowText()
	if _, err := tx.ExecContext(ctx, `INSERT INTO publication_attempts(attempt_identity, schema_version, repository_id, target_identity, base_checkpoint, target_generation, manifest_sha256, plan_sha256, phase, commit_intent, created_at, updated_at) VALUES (?, 1, ?, ?, NULLIF(?, ''), ?, ?, ?, ?, ?, ?, ?)`, attempt.AttemptIdentity, attempt.RepositoryID, attempt.TargetIdentity, attempt.BaseCheckpoint, attempt.TargetGeneration, attempt.ManifestSHA256, attempt.PlanSHA256, attempt.Phase, boolInt(attempt.CommitIntent), now, now); err != nil {
		return fmt.Errorf("record publication attempt: %w", err)
	}
	for sequence, view := range attempt.Views {
		if _, err := tx.ExecContext(ctx, `INSERT INTO publication_attempt_views(attempt_identity, sequence, view_id, pointer_path, old_identity, new_identity, state) VALUES (?, ?, ?, ?, NULLIF(?, ''), ?, ?)`, attempt.AttemptIdentity, sequence, view.ViewID, view.PointerPath, view.OldIdentity, view.NewIdentity, view.State); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// AbandonPublicationAttempt releases a pre-commit attempt only after the
// caller has reconciled the target and supplied the exact add-only objects
// that remain there. Mutable aliases and protocol pointers are forbidden from
// this evidence set, so an abandoned attempt cannot hide a visible rollback.
func (s *Store) AbandonPublicationAttempt(ctx context.Context, attemptIdentity string, objects []PublicationAbandonedObject) error {
	if !validSHA256Text(attemptIdentity) || !sortedAbandonedObjects(objects) {
		return errors.New("invalid abandoned publication evidence")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var phase string
	var commit int
	var generation GenerationID
	var base sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT phase, commit_intent, target_generation, base_checkpoint FROM publication_attempts WHERE attempt_identity = ?`, attemptIdentity).Scan(&phase, &commit, &generation, &base); err != nil {
		return err
	}
	if phase == "abandoned" && commit == 0 {
		stored, err := publicationAbandonedObjectsTx(ctx, tx, attemptIdentity)
		if err != nil || !sameAbandonedObjects(stored, objects) {
			return errors.Join(fmt.Errorf("%w: abandoned publication evidence changed", ErrConflict), err)
		}
		return tx.Commit()
	}
	if commit != 0 || phase != "planned" && phase != "payload" && phase != "immutable_metadata" && phase != "pointer_prepared" {
		return fmt.Errorf("%w: publication attempt can no longer be abandoned", ErrTransition)
	}
	basePaths := map[string]struct{}{}
	if base.Valid {
		rows, err := tx.QueryContext(ctx, `SELECT i.path FROM publication_inventory AS i WHERE i.checkpoint_identity = ?`, base.String)
		if err != nil {
			return err
		}
		for rows.Next() {
			var objectPath string
			if err := rows.Scan(&objectPath); err != nil {
				rows.Close()
				return err
			}
			basePaths[objectPath] = struct{}{}
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return err
		}
	}
	for _, object := range objects {
		if _, existed := basePaths[object.Path]; existed {
			return fmt.Errorf("%w: abandoned object %q was not add-only", ErrConflict, object.Path)
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM generation_files WHERE generation = ? AND path = ? AND phase = ? AND size = ? AND sha256 = ?`, generation, object.Path, object.Phase, object.Size, object.SHA256).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			return fmt.Errorf("%w: abandoned object %q is outside target Generation", ErrConflict, object.Path)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO publication_abandoned_objects(attempt_identity, path, phase, size, sha256, remote_identity) VALUES (?, ?, ?, ?, ?, ?)`, attemptIdentity, object.Path, object.Phase, object.Size, object.SHA256, object.RemoteIdentity); err != nil {
			return err
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE publication_attempts SET phase = 'abandoned', updated_at = ? WHERE attempt_identity = ? AND commit_intent = 0 AND phase IN ('planned', 'payload', 'immutable_metadata', 'pointer_prepared')`, nowText(), attemptIdentity)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return fmt.Errorf("%w: publication attempt changed while abandoning", ErrConflict)
	}
	return tx.Commit()
}

func (s *Store) SetPublicationCommitIntent(ctx context.Context, attemptIdentity string) error {
	if !validSHA256Text(attemptIdentity) {
		return errors.New("invalid publication attempt identity")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var phase string
	var commit int
	if err := tx.QueryRowContext(ctx, `SELECT phase, commit_intent FROM publication_attempts WHERE attempt_identity = ?`, attemptIdentity).Scan(&phase, &commit); err != nil {
		return err
	}
	if commit == 1 && publicationPhaseRank(phase) >= publicationPhaseRank("commit_intent") {
		return tx.Commit()
	}
	var unprepared int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM publication_attempt_views WHERE attempt_identity = ? AND state != 'prepared'`, attemptIdentity).Scan(&unprepared); err != nil {
		return err
	}
	if phase != "pointer_prepared" || commit != 0 || unprepared != 0 {
		return fmt.Errorf("%w: publication attempt is not ready for commit intent", ErrTransition)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE publication_attempts SET phase = 'commit_intent', commit_intent = 1, updated_at = ? WHERE attempt_identity = ?`, nowText(), attemptIdentity); err != nil {
		return err
	}
	return tx.Commit()
}

// AdvancePublicationAttemptPhase records adjacent forward transitions. The
// verified -> applied transition belongs to PutAppliedCheckpoint so target
// head CAS and the checkpoint cannot tear apart.
func (s *Store) AdvancePublicationAttemptPhase(ctx context.Context, attemptIdentity, next string) error {
	allowedNext := map[string]bool{"payload": true, "immutable_metadata": true, "pointer_prepared": true, "pointer_rollforward": true, "verified": true}
	if !validSHA256Text(attemptIdentity) || !allowedNext[next] {
		return errors.New("invalid publication attempt phase transition")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current string
	var commit int
	if err := tx.QueryRowContext(ctx, `SELECT phase, commit_intent FROM publication_attempts WHERE attempt_identity = ?`, attemptIdentity).Scan(&current, &commit); err != nil {
		return err
	}
	if publicationPhaseRank(current) >= publicationPhaseRank(next) {
		return tx.Commit()
	}
	allowed := map[string]string{
		"planned": "payload", "payload": "immutable_metadata", "immutable_metadata": "pointer_prepared",
		"commit_intent": "pointer_rollforward", "pointer_rollforward": "verified",
	}
	if allowed[current] != next {
		return fmt.Errorf("%w: publication attempt %s -> %s", ErrTransition, current, next)
	}
	if publicationPhaseRank(next) >= publicationPhaseRank("commit_intent") && commit != 1 {
		return fmt.Errorf("%w: publication attempt lacks commit intent", ErrTransition)
	}
	if next == "verified" {
		var unverified int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM publication_attempt_views WHERE attempt_identity = ? AND state != 'verified'`, attemptIdentity).Scan(&unverified); err != nil {
			return err
		}
		if unverified != 0 {
			return fmt.Errorf("%w: not all publication views are verified", ErrTransition)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE publication_attempts SET phase = ?, updated_at = ? WHERE attempt_identity = ?`, next, nowText(), attemptIdentity); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) SetPublicationAttemptViewState(ctx context.Context, attemptIdentity, viewID, pointerPath, next string) error {
	rank := map[string]int{"pending": 0, "prepared": 1, "applied": 2, "verified": 3}
	if !validSHA256Text(attemptIdentity) || rank[next] == 0 && next != "pending" || !validPublicationPath(viewID) || !validPublicationPath(pointerPath) {
		return errors.New("invalid publication view progress")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current, phase string
	var commit int
	if err := tx.QueryRowContext(ctx, `SELECT v.state, a.phase, a.commit_intent FROM publication_attempt_views AS v JOIN publication_attempts AS a ON a.attempt_identity = v.attempt_identity WHERE v.attempt_identity = ? AND v.view_id = ? AND v.pointer_path = ?`, attemptIdentity, viewID, pointerPath).Scan(&current, &phase, &commit); err != nil {
		return err
	}
	if rank[current] >= rank[next] {
		return tx.Commit()
	}
	if rank[next] != rank[current]+1 {
		return fmt.Errorf("%w: publication view %s -> %s", ErrTransition, current, next)
	}
	if next == "prepared" && phase != "pointer_prepared" {
		return fmt.Errorf("%w: publication pointer preparation requires pointer_prepared phase", ErrTransition)
	}
	if rank[next] >= rank["applied"] && (commit != 1 || publicationPhaseRank(phase) < publicationPhaseRank("commit_intent")) {
		return fmt.Errorf("%w: publication pointer progress requires durable commit intent", ErrTransition)
	}
	if next == "verified" && publicationPhaseRank(phase) < publicationPhaseRank("pointer_rollforward") {
		return fmt.Errorf("%w: publication pointer verification requires roll-forward phase", ErrTransition)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE publication_attempt_views SET state = ? WHERE attempt_identity = ? AND view_id = ? AND pointer_path = ?`, next, attemptIdentity, viewID, pointerPath); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE publication_attempts SET updated_at = ? WHERE attempt_identity = ?`, nowText(), attemptIdentity); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) PutAppliedCheckpoint(ctx context.Context, checkpoint *AppliedCheckpoint) error {
	if checkpoint == nil {
		return errors.New("nil applied checkpoint")
	}
	if checkpoint.SchemaVersion == 0 {
		checkpoint.SchemaVersion = publicationRecordSchemaV1
	}
	if checkpoint.AppliedAt.IsZero() {
		checkpoint.AppliedAt = time.Now().UTC()
	}
	if err := validateAppliedCheckpoint(*checkpoint); err != nil {
		return err
	}
	manifest, err := s.GenerationManifest(ctx, checkpoint.Generation)
	if err != nil {
		return err
	}
	_, digest, err := ManifestBytes(manifest)
	if err != nil || digest != checkpoint.ManifestSHA256 {
		return errors.Join(errors.New("checkpoint manifest differs from Generation"), err)
	}
	// Applied means the observed inventory is complete and contains the entire
	// published Generation closure. Extra older payload/metadata candidates are
	// legal, but an incomplete observation can never advance target head.
	if !checkpoint.InventoryComplete || !inventoryContainsManifest(checkpoint.Inventory, manifest) {
		return errors.New("complete publication inventory does not contain the Generation manifest closure")
	}
	computedInventory, err := acceptSemanticIdentity(checkpoint.InventoryIdentity, publicationInventoryIdentity(checkpoint.Inventory), "publication inventory identity")
	if err != nil {
		return err
	}
	checkpoint.InventoryIdentity = computedInventory
	computedCheckpoint, err := acceptSemanticIdentity(checkpoint.CheckpointIdentity, appliedCheckpointSemanticIdentity(*checkpoint), "applied checkpoint identity")
	if err != nil {
		return err
	}
	checkpoint.CheckpointIdentity = computedCheckpoint
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := requirePublicationBindingTx(ctx, tx, checkpoint.RepositoryID, checkpoint.TargetIdentity); err != nil {
		return err
	}
	exists, same, err := appliedCheckpointSemanticMatchTx(ctx, tx, *checkpoint)
	if err != nil {
		return err
	}
	if exists {
		if !same {
			return fmt.Errorf("%w: applied checkpoint identity has different semantic bytes", ErrConflict)
		}
		return tx.Commit()
	}
	var attemptRepository, attemptTarget, attemptManifest, attemptPhase string
	var attemptGeneration GenerationID
	var commit int
	var baseCheckpoint sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT repository_id, target_identity, base_checkpoint, target_generation, manifest_sha256, phase, commit_intent FROM publication_attempts WHERE attempt_identity = ?`, checkpoint.AttemptIdentity).Scan(&attemptRepository, &attemptTarget, &baseCheckpoint, &attemptGeneration, &attemptManifest, &attemptPhase, &commit); err != nil {
		return err
	}
	if attemptRepository != checkpoint.RepositoryID || attemptTarget != checkpoint.TargetIdentity || attemptGeneration != checkpoint.Generation || attemptManifest != checkpoint.ManifestSHA256 || attemptPhase != "verified" || commit != 1 {
		return fmt.Errorf("%w: checkpoint does not match one verified publication attempt", ErrConflict)
	}
	attemptViews, err := publicationAttemptViewsTx(ctx, tx, checkpoint.AttemptIdentity)
	if err != nil {
		return err
	}
	if !checkpointViewsMatchVerifiedAttempt(checkpoint.Views, attemptViews) {
		return fmt.Errorf("%w: checkpoint views differ from verified attempt views", ErrConflict)
	}
	var headCheckpoint sql.NullString
	var headRevision int64
	if err := tx.QueryRowContext(ctx, `SELECT checkpoint_identity, revision FROM publication_target_heads WHERE target_identity = ?`, checkpoint.TargetIdentity).Scan(&headCheckpoint, &headRevision); err != nil {
		return err
	}
	if headCheckpoint.Valid != baseCheckpoint.Valid || headCheckpoint.Valid && headCheckpoint.String != baseCheckpoint.String {
		return fmt.Errorf("%w: target head changed since publication attempt planning", ErrConflict)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO publication_checkpoints(checkpoint_identity, schema_version, repository_id, target_identity, attempt_identity, generation, manifest_sha256, inventory_identity, inventory_complete, applied_at) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?)`, checkpoint.CheckpointIdentity, checkpoint.RepositoryID, checkpoint.TargetIdentity, checkpoint.AttemptIdentity, checkpoint.Generation, checkpoint.ManifestSHA256, checkpoint.InventoryIdentity, boolInt(checkpoint.InventoryComplete), formatTimestamp(checkpoint.AppliedAt)); err != nil {
		return err
	}
	for sequence, view := range checkpoint.Views {
		if _, err := tx.ExecContext(ctx, `INSERT INTO publication_checkpoint_views(checkpoint_identity, sequence, view_id, pointer_path, remote_identity) VALUES (?, ?, ?, ?, ?)`, checkpoint.CheckpointIdentity, sequence, view.ViewID, view.PointerPath, view.RemoteIdentity); err != nil {
			return err
		}
	}
	for _, object := range checkpoint.Inventory {
		if _, err := tx.ExecContext(ctx, `INSERT INTO publication_inventory(checkpoint_identity, path, phase, size, sha256, remote_identity) VALUES (?, ?, ?, ?, ?, ?)`, checkpoint.CheckpointIdentity, object.Path, object.Phase, object.Size, object.SHA256, object.RemoteIdentity); err != nil {
			return err
		}
	}
	head := ""
	if headCheckpoint.Valid {
		head = headCheckpoint.String
	}
	result, err := tx.ExecContext(ctx, `UPDATE publication_target_heads SET checkpoint_identity = ?, generation = ?, manifest_sha256 = ?, revision = revision + 1, updated_at = ? WHERE target_identity = ? AND revision = ? AND ((? = '' AND checkpoint_identity IS NULL) OR checkpoint_identity = ?)`, checkpoint.CheckpointIdentity, checkpoint.Generation, checkpoint.ManifestSHA256, nowText(), checkpoint.TargetIdentity, headRevision, head, head)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return fmt.Errorf("%w: publication target head CAS failed", ErrConflict)
	}
	updated, err := tx.ExecContext(ctx, `UPDATE publication_attempts SET phase = 'applied', updated_at = ? WHERE attempt_identity = ? AND phase = 'verified' AND commit_intent = 1`, nowText(), checkpoint.AttemptIdentity)
	if err != nil {
		return err
	}
	rows, _ = updated.RowsAffected()
	if rows != 1 {
		return fmt.Errorf("%w: verified attempt changed while applying checkpoint", ErrConflict)
	}
	return tx.Commit()
}

func (s *Store) PutGraceRecord(ctx context.Context, record *GraceRecord) error {
	if record == nil {
		return errors.New("nil grace record")
	}
	if record.SchemaVersion == 0 {
		record.SchemaVersion = publicationRecordSchemaV1
	}
	if record.State == "" {
		record.State = "grace"
	}
	if record.SchemaVersion != 1 || !validSHA256Text(record.TargetIdentity) || !validSHA256Text(record.CheckpointIdentity) || !validSHA256Text(record.CachePolicyIdentity) || record.VerifiedAt.IsZero() || record.NotBefore.IsZero() || record.NotBefore.Before(record.VerifiedAt) || record.State != "grace" {
		return errors.New("invalid grace record")
	}
	computed, err := acceptSemanticIdentity(record.GraceIdentity, graceSemanticIdentity(*record), "grace identity")
	if err != nil {
		return err
	}
	record.GraceIdentity = computed
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	exists, same, err := graceSemanticMatchTx(ctx, tx, *record)
	if err != nil {
		return err
	}
	if exists {
		if !same {
			return fmt.Errorf("%w: grace identity has different semantic bytes", ErrConflict)
		}
		return tx.Commit()
	}
	var ttlNS int64
	var attemptIdentity, attemptPhase string
	if err := tx.QueryRowContext(ctx, `SELECT b.max_cache_ttl_ns, c.attempt_identity, a.phase
FROM publication_target_bindings AS b
JOIN publication_checkpoints AS c ON c.target_identity = b.target_identity
JOIN publication_target_heads AS h ON h.target_identity = b.target_identity AND h.checkpoint_identity = c.checkpoint_identity
JOIN publication_attempts AS a ON a.attempt_identity = c.attempt_identity
WHERE b.target_identity = ? AND c.checkpoint_identity = ?`, record.TargetIdentity, record.CheckpointIdentity).Scan(&ttlNS, &attemptIdentity, &attemptPhase); err != nil {
		return err
	}
	if attemptPhase != "applied" {
		return fmt.Errorf("%w: grace requires the current applied checkpoint", ErrTransition)
	}
	minimum := 30 * 24 * time.Hour
	if cacheMinimum := time.Duration(ttlNS) + 24*time.Hour; cacheMinimum > minimum {
		minimum = cacheMinimum
	}
	if record.NotBefore.Before(record.VerifiedAt.Add(minimum)) {
		return fmt.Errorf("%w: grace is shorter than max(30d, cache TTL + 24h)", ErrConflict)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO publication_grace_records(grace_identity, schema_version, target_identity, checkpoint_identity, verified_at, not_before, cache_policy_identity, state) VALUES (?, 1, ?, ?, ?, ?, ?, 'grace')`, record.GraceIdentity, record.TargetIdentity, record.CheckpointIdentity, formatTimestamp(record.VerifiedAt), formatTimestamp(record.NotBefore), record.CachePolicyIdentity); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE publication_attempts SET phase = 'grace', updated_at = ? WHERE attempt_identity = ? AND phase = 'applied' AND commit_intent = 1`, nowText(), attemptIdentity)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return fmt.Errorf("%w: applied attempt changed while recording grace", ErrConflict)
	}
	return tx.Commit()
}

func (s *Store) PutPublicationCandidateReport(ctx context.Context, report *PublicationCandidateReport) error {
	if report == nil {
		return errors.New("nil publication candidate report")
	}
	if report.SchemaVersion == 0 {
		report.SchemaVersion = 1
	}
	if report.CreatedAt.IsZero() {
		report.CreatedAt = time.Now().UTC()
	}
	if report.SchemaVersion != 1 || !validSHA256Text(report.TargetIdentity) || !validSHA256Text(report.CheckpointIdentity) || !validSHA256Text(report.InventoryIdentity) || report.Mode != "report_only" && report.Mode != "conditional_delete" || !sortedCandidates(report.Candidates) {
		return errors.New("invalid publication candidate report")
	}
	computed, err := acceptSemanticIdentity(report.ReportIdentity, candidateReportSemanticIdentity(*report), "candidate report identity")
	if err != nil {
		return err
	}
	report.ReportIdentity = computed
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	exists, same, err := candidateReportSemanticMatchTx(ctx, tx, *report)
	if err != nil {
		return err
	}
	if exists {
		if !same {
			return fmt.Errorf("%w: candidate report identity has different semantic bytes", ErrConflict)
		}
		return tx.Commit()
	}
	var provider, inventory, attemptPhase, graceState, notBefore string
	if err := tx.QueryRowContext(ctx, `SELECT b.provider, c.inventory_identity, a.phase, g.state, g.not_before
FROM publication_target_bindings AS b
JOIN publication_checkpoints AS c ON c.target_identity = b.target_identity
JOIN publication_attempts AS a ON a.attempt_identity = c.attempt_identity
JOIN publication_grace_records AS g ON g.target_identity = c.target_identity AND g.checkpoint_identity = c.checkpoint_identity
WHERE b.target_identity = ? AND c.checkpoint_identity = ?`, report.TargetIdentity, report.CheckpointIdentity).Scan(&provider, &inventory, &attemptPhase, &graceState, &notBefore); err != nil {
		return err
	}
	deadline, err := time.Parse(time.RFC3339Nano, notBefore)
	if err != nil {
		return fmt.Errorf("%w: invalid publication grace deadline", ErrSchema)
	}
	if inventory != report.InventoryIdentity || provider == "r2" && report.Mode != "report_only" || provider == "filesystem" && report.Mode != "conditional_delete" || attemptPhase != "grace" || graceState != "grace" || report.CreatedAt.Before(deadline) {
		return fmt.Errorf("%w: candidate report capability or inventory mismatch", ErrConflict)
	}
	var writeActive int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM publication_attempts WHERE target_identity = ? AND phase IN (
 'planned', 'payload', 'immutable_metadata', 'pointer_prepared',
 'commit_intent', 'pointer_rollforward', 'verified', 'applied'
)`, report.TargetIdentity).Scan(&writeActive); err != nil {
		return err
	}
	if writeActive != 0 {
		return fmt.Errorf("%w: target has a write-active publication attempt", ErrTransition)
	}
	expected, err := exactPublicationCandidatesTx(ctx, tx, report.CheckpointIdentity)
	if err != nil {
		return err
	}
	if !samePublicationCandidates(expected, report.Candidates) {
		return fmt.Errorf("%w: candidate report is not the exact non-pointer inventory delta", ErrConflict)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO publication_candidate_reports(report_identity, schema_version, target_identity, checkpoint_identity, inventory_identity, mode, created_at) VALUES (?, 1, ?, ?, ?, ?, ?)`, report.ReportIdentity, report.TargetIdentity, report.CheckpointIdentity, report.InventoryIdentity, report.Mode, formatTimestamp(report.CreatedAt)); err != nil {
		return err
	}
	for sequence, candidate := range report.Candidates {
		if _, err := tx.ExecContext(ctx, `INSERT INTO publication_candidates(report_identity, sequence, path, phase, size, sha256, remote_identity) VALUES (?, ?, ?, ?, ?, ?, ?)`, report.ReportIdentity, sequence, candidate.Path, candidate.Phase, candidate.Size, candidate.SHA256, candidate.RemoteIdentity); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// PutPublicationDeletionReceipt records one exact filesystem conditional
// deletion only after both the storage namespace and the public endpoint have
// proved the same report-bound object absent. A replay by report/path returns
// the first durable receipt instead of minting a new observation identity.
func (s *Store) PutPublicationDeletionReceipt(ctx context.Context, receipt *PublicationDeletionReceipt) error {
	if receipt == nil {
		return errors.New("nil publication deletion receipt")
	}
	if !validSHA256Text(receipt.ReportIdentity) || !validPublicationPath(receipt.Path) || receipt.Phase != "payload" && receipt.Phase != "metadata" || receipt.Size < 0 || !validSHA256Text(receipt.SHA256) || receipt.RemoteIdentity == "" || !receipt.StorageAbsent || !receipt.PublicAbsent || receipt.ObservedAt.IsZero() {
		return errors.New("invalid publication deletion receipt")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stored, found, err := publicationDeletionReceiptByPathTx(ctx, tx, receipt.ReportIdentity, receipt.Path)
	if err != nil {
		return err
	}
	if found {
		if receipt.ReceiptIdentity != "" && receipt.ReceiptIdentity != stored.ReceiptIdentity || receipt.Phase != stored.Phase || receipt.Size != stored.Size || receipt.SHA256 != stored.SHA256 || receipt.RemoteIdentity != stored.RemoteIdentity || !stored.StorageAbsent || !stored.PublicAbsent {
			return fmt.Errorf("%w: deletion receipt path has different evidence", ErrConflict)
		}
		*receipt = stored
		return tx.Commit()
	}
	var provider, mode, attemptPhase, graceState, notBefore string
	var candidate PublicationCandidate
	if err := tx.QueryRowContext(ctx, `SELECT b.provider, r.mode, a.phase, g.state, g.not_before,
 p.path, p.phase, p.size, p.sha256, p.remote_identity
FROM publication_candidate_reports AS r
JOIN publication_candidates AS p ON p.report_identity = r.report_identity
JOIN publication_checkpoints AS c ON c.checkpoint_identity = r.checkpoint_identity
JOIN publication_attempts AS a ON a.attempt_identity = c.attempt_identity
JOIN publication_target_bindings AS b ON b.target_identity = r.target_identity
JOIN publication_grace_records AS g ON g.target_identity = r.target_identity AND g.checkpoint_identity = r.checkpoint_identity
WHERE r.report_identity = ? AND p.path = ?`, receipt.ReportIdentity, receipt.Path).Scan(
		&provider, &mode, &attemptPhase, &graceState, &notBefore,
		&candidate.Path, &candidate.Phase, &candidate.Size, &candidate.SHA256, &candidate.RemoteIdentity,
	); err != nil {
		return err
	}
	deadline, err := time.Parse(time.RFC3339Nano, notBefore)
	if err != nil {
		return fmt.Errorf("%w: invalid publication grace deadline", ErrSchema)
	}
	if provider != "filesystem" || mode != "conditional_delete" || attemptPhase != "grace" || graceState != "grace" || receipt.ObservedAt.Before(deadline) || candidate.Path != receipt.Path || candidate.Phase != receipt.Phase || candidate.Size != receipt.Size || candidate.SHA256 != receipt.SHA256 || candidate.RemoteIdentity != receipt.RemoteIdentity {
		return fmt.Errorf("%w: deletion receipt is not exact conditional-delete evidence", ErrTransition)
	}
	receipt.ReceiptIdentity, err = acceptSemanticIdentity(receipt.ReceiptIdentity, deletionReceiptSemanticIdentity(*receipt), "publication deletion receipt identity")
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO publication_deletion_receipts(
 receipt_identity, report_identity, path, phase, size, sha256, remote_identity,
 storage_absent, public_absent, observed_at
) VALUES (?, ?, ?, ?, ?, ?, ?, 1, 1, ?)`, receipt.ReceiptIdentity, receipt.ReportIdentity, receipt.Path, receipt.Phase, receipt.Size, receipt.SHA256, receipt.RemoteIdentity, formatTimestamp(receipt.ObservedAt)); err != nil {
		return err
	}
	return tx.Commit()
}

// MarkPublicationDeletionVerified advances a filesystem grace record only when
// every exact candidate has one semantically valid storage+public absence
// receipt. Empty candidate sets are valid and require zero receipts.
func (s *Store) MarkPublicationDeletionVerified(ctx context.Context, attemptIdentity, reportIdentity string, observedAt time.Time) error {
	if !validSHA256Text(attemptIdentity) || !validSHA256Text(reportIdentity) {
		return errors.New("invalid deletion verification evidence identity")
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var provider, mode, phase, graceState, notBefore, checkpointIdentity string
	if err := tx.QueryRowContext(ctx, `SELECT b.provider, r.mode, a.phase, g.state, g.not_before, c.checkpoint_identity
FROM publication_attempts AS a
JOIN publication_checkpoints AS c ON c.attempt_identity = a.attempt_identity
JOIN publication_target_bindings AS b ON b.target_identity = a.target_identity
JOIN publication_grace_records AS g ON g.target_identity = a.target_identity AND g.checkpoint_identity = c.checkpoint_identity
JOIN publication_candidate_reports AS r ON r.target_identity = a.target_identity AND r.checkpoint_identity = c.checkpoint_identity AND r.inventory_identity = c.inventory_identity
WHERE a.attempt_identity = ? AND r.report_identity = ?`, attemptIdentity, reportIdentity).Scan(&provider, &mode, &phase, &graceState, &notBefore, &checkpointIdentity); err != nil {
		return err
	}
	if provider != "filesystem" || mode != "conditional_delete" {
		return fmt.Errorf("%w: deletion verification requires filesystem conditional-delete evidence", ErrTransition)
	}
	if (phase == "deletion_verified" || phase == "done") && graceState == "deletion_verified" {
		if err := requireExactDeletionReceiptClosureTx(ctx, tx, reportIdentity); err != nil {
			return err
		}
		return tx.Commit()
	}
	deadline, err := time.Parse(time.RFC3339Nano, notBefore)
	if err != nil {
		return fmt.Errorf("%w: invalid publication grace deadline", ErrSchema)
	}
	if phase != "grace" || graceState != "grace" || observedAt.Before(deadline) {
		return fmt.Errorf("%w: grace is not expired or deletion evidence is not pending", ErrTransition)
	}
	if err := requireExactDeletionReceiptClosureTx(ctx, tx, reportIdentity); err != nil {
		return err
	}
	graceUpdate, err := tx.ExecContext(ctx, `UPDATE publication_grace_records SET state = 'deletion_verified' WHERE checkpoint_identity = ? AND state = 'grace'`, checkpointIdentity)
	if err != nil {
		return err
	}
	graceRows, _ := graceUpdate.RowsAffected()
	if graceRows != 1 {
		return fmt.Errorf("%w: grace record changed while recording deletion", ErrConflict)
	}
	result, err := tx.ExecContext(ctx, `UPDATE publication_attempts SET phase = 'deletion_verified', updated_at = ? WHERE attempt_identity = ? AND phase = 'grace' AND commit_intent = 1`, nowText(), attemptIdentity)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return fmt.Errorf("%w: grace attempt changed while recording deletion", ErrConflict)
	}
	return tx.Commit()
}

// MarkPublicationRetainedReported is the only first-version transition out of
// grace. It is R2-only and requires an expired grace plus the exact report-only
// inventory delta. No remote delete is implied or recorded.
func (s *Store) MarkPublicationRetainedReported(ctx context.Context, attemptIdentity, reportIdentity string, observedAt time.Time) error {
	if !validSHA256Text(attemptIdentity) || !validSHA256Text(reportIdentity) {
		return errors.New("invalid retained-report evidence identity")
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var provider, phase, graceState, notBefore, mode, checkpointIdentity string
	if err := tx.QueryRowContext(ctx, `SELECT b.provider, a.phase, g.state, g.not_before, r.mode, c.checkpoint_identity
FROM publication_attempts AS a
JOIN publication_checkpoints AS c ON c.attempt_identity = a.attempt_identity
JOIN publication_target_bindings AS b ON b.target_identity = a.target_identity
JOIN publication_grace_records AS g ON g.target_identity = a.target_identity AND g.checkpoint_identity = c.checkpoint_identity
JOIN publication_candidate_reports AS r ON r.target_identity = a.target_identity AND r.checkpoint_identity = c.checkpoint_identity AND r.inventory_identity = c.inventory_identity
WHERE a.attempt_identity = ? AND r.report_identity = ?`, attemptIdentity, reportIdentity).Scan(&provider, &phase, &graceState, &notBefore, &mode, &checkpointIdentity); err != nil {
		return err
	}
	if provider != "r2" || mode != "report_only" {
		return fmt.Errorf("%w: retained-report transition requires R2 report-only evidence", ErrTransition)
	}
	if (phase == "retained_reported" || phase == "done") && graceState == "retained_reported" {
		return tx.Commit()
	}
	deadline, err := time.Parse(time.RFC3339Nano, notBefore)
	if err != nil {
		return fmt.Errorf("%w: invalid grace deadline", ErrSchema)
	}
	if phase != "grace" || graceState != "grace" || observedAt.Before(deadline) {
		return fmt.Errorf("%w: grace is not expired or retention evidence is not pending", ErrTransition)
	}
	graceUpdate, err := tx.ExecContext(ctx, `UPDATE publication_grace_records SET state = 'retained_reported' WHERE checkpoint_identity = ? AND state = 'grace'`, checkpointIdentity)
	if err != nil {
		return err
	}
	graceRows, _ := graceUpdate.RowsAffected()
	if graceRows != 1 {
		return fmt.Errorf("%w: grace record changed while recording retention", ErrConflict)
	}
	result, err := tx.ExecContext(ctx, `UPDATE publication_attempts SET phase = 'retained_reported', updated_at = ? WHERE attempt_identity = ? AND phase = 'grace' AND commit_intent = 1`, nowText(), attemptIdentity)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return fmt.Errorf("%w: grace attempt changed while recording retention", ErrConflict)
	}
	return tx.Commit()
}

// CompletePublicationAttempt acknowledges either an evidence-gated R2 retained
// report or a filesystem report whose complete receipt closure is already
// deletion_verified. The report identity is the terminal evidence fence.
func (s *Store) CompletePublicationAttempt(ctx context.Context, attemptIdentity, evidenceIdentity string) error {
	if !validSHA256Text(attemptIdentity) || !validSHA256Text(evidenceIdentity) {
		return errors.New("invalid publication completion evidence")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var provider, phase, graceState, mode string
	if err := tx.QueryRowContext(ctx, `SELECT b.provider, a.phase, g.state, r.mode
FROM publication_attempts AS a
JOIN publication_checkpoints AS c ON c.attempt_identity = a.attempt_identity
JOIN publication_target_bindings AS b ON b.target_identity = a.target_identity
JOIN publication_grace_records AS g ON g.target_identity = a.target_identity AND g.checkpoint_identity = c.checkpoint_identity
JOIN publication_candidate_reports AS r ON r.target_identity = a.target_identity AND r.checkpoint_identity = c.checkpoint_identity AND r.inventory_identity = c.inventory_identity
WHERE a.attempt_identity = ? AND r.report_identity = ?`, attemptIdentity, evidenceIdentity).Scan(&provider, &phase, &graceState, &mode); err != nil {
		return err
	}
	if phase == "done" {
		if provider == "filesystem" && mode == "conditional_delete" && graceState == "deletion_verified" {
			if err := requireExactDeletionReceiptClosureTx(ctx, tx, evidenceIdentity); err != nil {
				return err
			}
			return tx.Commit()
		}
		if provider == "r2" && mode == "report_only" && graceState == "retained_reported" {
			return tx.Commit()
		}
		return fmt.Errorf("%w: completed publication evidence no longer matches provider capability", ErrTransition)
	}
	terminal := ""
	switch {
	case provider == "r2" && mode == "report_only" && graceState == "retained_reported" && phase == "retained_reported":
		terminal = "retained_reported"
	case provider == "filesystem" && mode == "conditional_delete" && graceState == "deletion_verified" && phase == "deletion_verified":
		if err := requireExactDeletionReceiptClosureTx(ctx, tx, evidenceIdentity); err != nil {
			return err
		}
		terminal = "deletion_verified"
	default:
		return fmt.Errorf("%w: publication completion lacks provider-specific terminal evidence", ErrTransition)
	}
	result, err := tx.ExecContext(ctx, `UPDATE publication_attempts SET phase = 'done', updated_at = ? WHERE attempt_identity = ? AND phase = ? AND commit_intent = 1`, nowText(), attemptIdentity, terminal)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		return fmt.Errorf("%w: publication completion changed", ErrConflict)
	}
	return tx.Commit()
}

func validatePublicationAttempt(attempt PublicationAttempt) error {
	if attempt.SchemaVersion != 1 || !IsCanonicalRepositoryID(attempt.RepositoryID) || !validSHA256Text(attempt.TargetIdentity) || attempt.BaseCheckpoint != "" && !validSHA256Text(attempt.BaseCheckpoint) || attempt.TargetGeneration == 0 || !validSHA256Text(attempt.ManifestSHA256) || !validSHA256Text(attempt.PlanSHA256) || !sortedAttemptViews(attempt.Views) {
		return errors.New("invalid publication attempt")
	}
	if attempt.Phase == "abandoned" {
		if attempt.CommitIntent {
			return errors.New("publication attempt phase/commit intent mismatch")
		}
		return nil
	}
	rank := publicationPhaseRank(attempt.Phase)
	preCommit := rank >= 0 && rank < publicationPhaseRank("commit_intent")
	if rank < 0 || preCommit == attempt.CommitIntent {
		return errors.New("publication attempt phase/commit intent mismatch")
	}
	return nil
}

func sortedAbandonedObjects(objects []PublicationAbandonedObject) bool {
	previous := ""
	for _, object := range objects {
		if !validPublicationPath(object.Path) || object.Path <= previous || object.Phase != "payload" && object.Phase != "metadata" || object.Size < 0 || !validSHA256Text(object.SHA256) || object.RemoteIdentity == "" || len(object.RemoteIdentity) > 4096 || strings.ContainsAny(object.RemoteIdentity, "\x00\r\n") {
			return false
		}
		previous = object.Path
	}
	return true
}

func sameAbandonedObjects(left, right []PublicationAbandonedObject) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func publicationAbandonedObjectsTx(ctx context.Context, tx *sql.Tx, attemptIdentity string) ([]PublicationAbandonedObject, error) {
	rows, err := tx.QueryContext(ctx, `SELECT path, phase, size, sha256, remote_identity FROM publication_abandoned_objects WHERE attempt_identity = ? ORDER BY path`, attemptIdentity)
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
		result = append(result, object)
	}
	return result, rows.Err()
}

func validateAppliedCheckpoint(value AppliedCheckpoint) error {
	if value.SchemaVersion != 1 || !value.InventoryComplete || !IsCanonicalRepositoryID(value.RepositoryID) || !validSHA256Text(value.TargetIdentity) || !validSHA256Text(value.AttemptIdentity) || value.Generation == 0 || !validSHA256Text(value.ManifestSHA256) || !sortedCheckpointViews(value.Views) || !sortedInventory(value.Inventory) || value.AppliedAt.IsZero() {
		return errors.New("invalid applied checkpoint")
	}
	return nil
}

func sortedAttemptViews(views []PublicationAttemptView) bool {
	previous := ""
	for _, view := range views {
		key := view.ViewID + "\x00" + view.PointerPath
		if !validPublicationPath(view.ViewID) || !validPublicationPath(view.PointerPath) || !validSHA256Text(view.NewIdentity) || view.State != "pending" && view.State != "prepared" && view.State != "applied" && view.State != "verified" || previous != "" && key <= previous {
			return false
		}
		previous = key
	}
	return true
}

func sortedCheckpointViews(views []PublicationCheckpointView) bool {
	previous := ""
	for _, view := range views {
		key := view.ViewID + "\x00" + view.PointerPath
		if !validPublicationPath(view.ViewID) || !validPublicationPath(view.PointerPath) || view.RemoteIdentity == "" || previous != "" && key <= previous {
			return false
		}
		previous = key
	}
	return true
}

func sortedInventory(objects []PublicationInventoryObject) bool {
	previous := ""
	for _, object := range objects {
		if !validPublicationPath(object.Path) || object.Path <= previous || object.Size < 0 || !validSHA256Text(object.SHA256) || object.RemoteIdentity == "" || object.Phase != "payload" && object.Phase != "metadata" && object.Phase != "pointer" {
			return false
		}
		previous = object.Path
	}
	return true
}

func sortedCandidates(candidates []PublicationCandidate) bool {
	previous := ""
	for _, candidate := range candidates {
		if !validPublicationPath(candidate.Path) || candidate.Path <= previous || candidate.Phase != "payload" && candidate.Phase != "metadata" || candidate.Size < 0 || !validSHA256Text(candidate.SHA256) || candidate.RemoteIdentity == "" {
			return false
		}
		previous = candidate.Path
	}
	return true
}

func inventoryContainsManifest(inventory []PublicationInventoryObject, manifest []GenerationFile) bool {
	byPath := make(map[string]PublicationInventoryObject, len(inventory))
	for _, object := range inventory {
		byPath[object.Path] = object
	}
	for _, file := range manifest {
		object, ok := byPath[file.Path]
		if !ok || object.Phase != file.Phase || object.Size != file.Size || object.SHA256 != file.SHA256 {
			return false
		}
	}
	return true
}

func publicationAttemptSemanticMatchTx(ctx context.Context, tx *sql.Tx, input PublicationAttempt) (bool, bool, error) {
	var stored PublicationAttempt
	var base sql.NullString
	var commit int
	err := tx.QueryRowContext(ctx, `SELECT attempt_identity, schema_version, repository_id, target_identity, base_checkpoint, target_generation, manifest_sha256, plan_sha256, phase, commit_intent FROM publication_attempts WHERE attempt_identity = ?`, input.AttemptIdentity).Scan(
		&stored.AttemptIdentity, &stored.SchemaVersion, &stored.RepositoryID, &stored.TargetIdentity, &base, &stored.TargetGeneration, &stored.ManifestSHA256, &stored.PlanSHA256, &stored.Phase, &commit,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	stored.BaseCheckpoint = base.String
	stored.CommitIntent = commit == 1
	stored.Views, err = publicationAttemptViewsTx(ctx, tx, input.AttemptIdentity)
	if err != nil {
		return true, false, err
	}
	return true, publicationAttemptSemanticIdentity(stored) == publicationAttemptSemanticIdentity(input), nil
}

func appliedCheckpointSemanticMatchTx(ctx context.Context, tx *sql.Tx, input AppliedCheckpoint) (bool, bool, error) {
	var stored AppliedCheckpoint
	var appliedAt string
	var inventoryComplete int
	err := tx.QueryRowContext(ctx, `SELECT checkpoint_identity, schema_version, repository_id, target_identity, attempt_identity, generation, manifest_sha256, inventory_identity, inventory_complete, applied_at FROM publication_checkpoints WHERE checkpoint_identity = ?`, input.CheckpointIdentity).Scan(
		&stored.CheckpointIdentity, &stored.SchemaVersion, &stored.RepositoryID, &stored.TargetIdentity, &stored.AttemptIdentity, &stored.Generation, &stored.ManifestSHA256, &stored.InventoryIdentity, &inventoryComplete, &appliedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	stored.InventoryComplete = inventoryComplete == 1
	stored.Views, err = publicationCheckpointViewsTx(ctx, tx, input.CheckpointIdentity)
	if err != nil {
		return true, false, err
	}
	stored.Inventory, err = publicationInventoryTx(ctx, tx, input.CheckpointIdentity)
	if err != nil {
		return true, false, err
	}
	same := stored.InventoryComplete == input.InventoryComplete && publicationInventoryIdentity(stored.Inventory) == publicationInventoryIdentity(input.Inventory) && appliedCheckpointSemanticIdentity(stored) == appliedCheckpointSemanticIdentity(input)
	return true, same, nil
}

func graceSemanticMatchTx(ctx context.Context, tx *sql.Tx, input GraceRecord) (bool, bool, error) {
	var stored GraceRecord
	var verified, notBefore string
	err := tx.QueryRowContext(ctx, `SELECT grace_identity, schema_version, target_identity, checkpoint_identity, verified_at, not_before, cache_policy_identity, state FROM publication_grace_records WHERE grace_identity = ?`, input.GraceIdentity).Scan(
		&stored.GraceIdentity, &stored.SchemaVersion, &stored.TargetIdentity, &stored.CheckpointIdentity, &verified, &notBefore, &stored.CachePolicyIdentity, &stored.State,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	stored.VerifiedAt, err = time.Parse(time.RFC3339Nano, verified)
	if err != nil {
		return true, false, err
	}
	stored.NotBefore, err = time.Parse(time.RFC3339Nano, notBefore)
	if err != nil {
		return true, false, err
	}
	return true, graceSemanticIdentity(stored) == graceSemanticIdentity(input), nil
}

func candidateReportSemanticMatchTx(ctx context.Context, tx *sql.Tx, input PublicationCandidateReport) (bool, bool, error) {
	stored := PublicationCandidateReport{Candidates: []PublicationCandidate{}}
	err := tx.QueryRowContext(ctx, `SELECT report_identity, schema_version, target_identity, checkpoint_identity, inventory_identity, mode FROM publication_candidate_reports WHERE report_identity = ?`, input.ReportIdentity).Scan(
		&stored.ReportIdentity, &stored.SchemaVersion, &stored.TargetIdentity, &stored.CheckpointIdentity, &stored.InventoryIdentity, &stored.Mode,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT path, phase, size, sha256, remote_identity FROM publication_candidates WHERE report_identity = ? ORDER BY path`, input.ReportIdentity)
	if err != nil {
		return true, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var candidate PublicationCandidate
		if err := rows.Scan(&candidate.Path, &candidate.Phase, &candidate.Size, &candidate.SHA256, &candidate.RemoteIdentity); err != nil {
			return true, false, err
		}
		stored.Candidates = append(stored.Candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return true, false, err
	}
	return true, candidateReportSemanticIdentity(stored) == candidateReportSemanticIdentity(input), nil
}

func publicationCheckpointViewsTx(ctx context.Context, tx *sql.Tx, checkpointIdentity string) ([]PublicationCheckpointView, error) {
	rows, err := tx.QueryContext(ctx, `SELECT view_id, pointer_path, remote_identity FROM publication_checkpoint_views WHERE checkpoint_identity = ? ORDER BY view_id, pointer_path`, checkpointIdentity)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	views := []PublicationCheckpointView{}
	for rows.Next() {
		var view PublicationCheckpointView
		if err := rows.Scan(&view.ViewID, &view.PointerPath, &view.RemoteIdentity); err != nil {
			return nil, err
		}
		views = append(views, view)
	}
	return views, rows.Err()
}

func publicationInventoryTx(ctx context.Context, tx *sql.Tx, checkpointIdentity string) ([]PublicationInventoryObject, error) {
	rows, err := tx.QueryContext(ctx, `SELECT path, phase, size, sha256, remote_identity FROM publication_inventory WHERE checkpoint_identity = ? ORDER BY path`, checkpointIdentity)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	inventory := []PublicationInventoryObject{}
	for rows.Next() {
		var object PublicationInventoryObject
		if err := rows.Scan(&object.Path, &object.Phase, &object.Size, &object.SHA256, &object.RemoteIdentity); err != nil {
			return nil, err
		}
		inventory = append(inventory, object)
	}
	return inventory, rows.Err()
}

func exactPublicationCandidatesTx(ctx context.Context, tx *sql.Tx, checkpointIdentity string) ([]PublicationCandidate, error) {
	var generation GenerationID
	var targetIdentity string
	if err := tx.QueryRowContext(ctx, `SELECT generation, target_identity FROM publication_checkpoints WHERE checkpoint_identity = ? AND inventory_complete = 1`, checkpointIdentity).Scan(&generation, &targetIdentity); err != nil {
		return nil, err
	}
	manifest, err := generationManifestTx(ctx, tx, generation)
	if err != nil {
		return nil, err
	}
	checkpointClosure := make(map[string]GenerationFile, len(manifest))
	protectedPaths := make(map[string]struct{}, len(manifest))
	for _, file := range manifest {
		checkpointClosure[file.Path] = file
		protectedPaths[file.Path] = struct{}{}
	}
	// A report is target-scoped, not checkpoint-local. Protect the current head,
	// every still-live grace Generation, and both sides of any write-active
	// attempt. PutPublicationCandidateReport currently rejects the latter, but
	// keeping it in the pure candidate computation makes direct callers fail
	// closed if that admission rule ever changes.
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT c.generation
FROM publication_checkpoints AS c
LEFT JOIN publication_target_heads AS h ON h.target_identity = c.target_identity AND h.checkpoint_identity = c.checkpoint_identity
LEFT JOIN publication_grace_records AS g ON g.target_identity = c.target_identity AND g.checkpoint_identity = c.checkpoint_identity
WHERE c.target_identity = ? AND (h.checkpoint_identity IS NOT NULL OR g.state = 'grace')
UNION
SELECT DISTINCT target_generation FROM publication_attempts
WHERE target_identity = ? AND phase IN (
 'planned', 'payload', 'immutable_metadata', 'pointer_prepared',
 'commit_intent', 'pointer_rollforward', 'verified', 'applied'
)
ORDER BY 1`, targetIdentity, targetIdentity)
	if err != nil {
		return nil, err
	}
	protectedGenerations := []GenerationID{}
	for rows.Next() {
		var protected GenerationID
		if err := rows.Scan(&protected); err != nil {
			rows.Close()
			return nil, err
		}
		protectedGenerations = append(protectedGenerations, protected)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, err
	}
	for _, protected := range protectedGenerations {
		files, err := generationManifestTx(ctx, tx, protected)
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			protectedPaths[file.Path] = struct{}{}
		}
	}
	baseRows, err := tx.QueryContext(ctx, `SELECT DISTINCT i.path
FROM publication_attempts AS a
JOIN publication_inventory AS i ON i.checkpoint_identity = a.base_checkpoint
WHERE a.target_identity = ? AND a.phase IN (
 'planned', 'payload', 'immutable_metadata', 'pointer_prepared',
 'commit_intent', 'pointer_rollforward', 'verified', 'applied'
)
ORDER BY i.path`, targetIdentity)
	if err != nil {
		return nil, err
	}
	for baseRows.Next() {
		var objectPath string
		if err := baseRows.Scan(&objectPath); err != nil {
			baseRows.Close()
			return nil, err
		}
		protectedPaths[objectPath] = struct{}{}
	}
	if err := errors.Join(baseRows.Err(), baseRows.Close()); err != nil {
		return nil, err
	}
	inventory, err := publicationInventoryTx(ctx, tx, checkpointIdentity)
	if err != nil {
		return nil, err
	}
	deleted := make(map[string]PublicationCandidate)
	deletedRows, err := tx.QueryContext(ctx, `SELECT d.path, d.phase, d.size, d.sha256, d.remote_identity
FROM publication_deletion_receipts AS d
JOIN publication_candidate_reports AS r ON r.report_identity = d.report_identity
JOIN publication_checkpoints AS c ON c.checkpoint_identity = r.checkpoint_identity
JOIN publication_attempts AS a ON a.attempt_identity = c.attempt_identity
JOIN publication_grace_records AS g ON g.checkpoint_identity = c.checkpoint_identity
WHERE r.target_identity = ? AND r.mode = 'conditional_delete'
  AND g.state = 'deletion_verified' AND a.phase IN ('deletion_verified', 'done')
ORDER BY d.path`, targetIdentity)
	if err != nil {
		return nil, err
	}
	for deletedRows.Next() {
		var object PublicationCandidate
		if err := deletedRows.Scan(&object.Path, &object.Phase, &object.Size, &object.SHA256, &object.RemoteIdentity); err != nil {
			deletedRows.Close()
			return nil, err
		}
		key := publicationObjectEvidenceKey(object.Path, object.Phase, object.Size, object.SHA256, object.RemoteIdentity)
		deleted[key] = object
	}
	if err := errors.Join(deletedRows.Err(), deletedRows.Close()); err != nil {
		return nil, err
	}
	candidates := []PublicationCandidate{}
	for _, object := range inventory {
		if file, ok := checkpointClosure[object.Path]; ok && file.Phase == object.Phase && file.Size == object.Size && file.SHA256 == object.SHA256 {
			continue
		}
		if object.Phase == "pointer" {
			return nil, fmt.Errorf("%w: pointer %q cannot be a retention candidate", ErrConflict, object.Path)
		}
		candidate := PublicationCandidate(object)
		if _, protected := protectedPaths[object.Path]; protected {
			continue
		}
		if _, alreadyAbsent := deleted[publicationObjectEvidenceKey(candidate.Path, candidate.Phase, candidate.Size, candidate.SHA256, candidate.RemoteIdentity)]; alreadyAbsent {
			continue
		}
		candidates = append(candidates, candidate)
	}
	return candidates, nil
}

func publicationObjectEvidenceKey(path, phase string, size int64, sha, remoteIdentity string) string {
	return fmt.Sprintf("%s\x00%s\x00%d\x00%s\x00%s", path, phase, size, sha, remoteIdentity)
}

func publicationDeletionReceiptByPathTx(ctx context.Context, tx *sql.Tx, reportIdentity, objectPath string) (PublicationDeletionReceipt, bool, error) {
	var receipt PublicationDeletionReceipt
	var storageAbsent, publicAbsent int
	var observed string
	err := tx.QueryRowContext(ctx, `SELECT receipt_identity, report_identity, path, phase, size, sha256,
 remote_identity, storage_absent, public_absent, observed_at
FROM publication_deletion_receipts WHERE report_identity = ? AND path = ?`, reportIdentity, objectPath).Scan(
		&receipt.ReceiptIdentity, &receipt.ReportIdentity, &receipt.Path, &receipt.Phase, &receipt.Size,
		&receipt.SHA256, &receipt.RemoteIdentity, &storageAbsent, &publicAbsent, &observed,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return PublicationDeletionReceipt{}, false, nil
	}
	if err != nil {
		return PublicationDeletionReceipt{}, false, err
	}
	receipt.StorageAbsent, receipt.PublicAbsent = storageAbsent == 1, publicAbsent == 1
	receipt.ObservedAt, err = time.Parse(time.RFC3339Nano, observed)
	if err != nil || !receipt.StorageAbsent || !receipt.PublicAbsent || deletionReceiptSemanticIdentity(receipt) != receipt.ReceiptIdentity {
		return PublicationDeletionReceipt{}, false, fmt.Errorf("%w: deletion receipt semantic identity is corrupt", ErrConflict)
	}
	return receipt, true, nil
}

func requireExactDeletionReceiptClosureTx(ctx context.Context, tx *sql.Tx, reportIdentity string) error {
	rows, err := tx.QueryContext(ctx, `SELECT path, phase, size, sha256, remote_identity FROM publication_candidates WHERE report_identity = ? ORDER BY path`, reportIdentity)
	if err != nil {
		return err
	}
	candidates := []PublicationCandidate{}
	for rows.Next() {
		var candidate PublicationCandidate
		if err := rows.Scan(&candidate.Path, &candidate.Phase, &candidate.Size, &candidate.SHA256, &candidate.RemoteIdentity); err != nil {
			rows.Close()
			return err
		}
		candidates = append(candidates, candidate)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}
	var receiptCount int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM publication_deletion_receipts WHERE report_identity = ?`, reportIdentity).Scan(&receiptCount); err != nil {
		return err
	}
	if receiptCount != len(candidates) {
		return fmt.Errorf("%w: conditional-delete report lacks an exact receipt closure", ErrTransition)
	}
	for _, candidate := range candidates {
		receipt, found, err := publicationDeletionReceiptByPathTx(ctx, tx, reportIdentity, candidate.Path)
		if err != nil {
			return err
		}
		if !found || receipt.Phase != candidate.Phase || receipt.Size != candidate.Size || receipt.SHA256 != candidate.SHA256 || receipt.RemoteIdentity != candidate.RemoteIdentity {
			return fmt.Errorf("%w: conditional-delete receipt differs at %q", ErrConflict, candidate.Path)
		}
	}
	return nil
}

func samePublicationCandidates(left, right []PublicationCandidate) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func publicationAttemptViewsTx(ctx context.Context, tx *sql.Tx, attemptIdentity string) ([]PublicationAttemptView, error) {
	rows, err := tx.QueryContext(ctx, `SELECT view_id, pointer_path, COALESCE(old_identity, ''), new_identity, state FROM publication_attempt_views WHERE attempt_identity = ? ORDER BY view_id, pointer_path`, attemptIdentity)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	views := []PublicationAttemptView{}
	for rows.Next() {
		var view PublicationAttemptView
		if err := rows.Scan(&view.ViewID, &view.PointerPath, &view.OldIdentity, &view.NewIdentity, &view.State); err != nil {
			return nil, err
		}
		views = append(views, view)
	}
	return views, rows.Err()
}

func checkpointViewsMatchVerifiedAttempt(checkpoint []PublicationCheckpointView, attempt []PublicationAttemptView) bool {
	if len(checkpoint) != len(attempt) {
		return false
	}
	for index := range checkpoint {
		// Attempt.NewIdentity is the target content SHA-256 known before the
		// write; Checkpoint.RemoteIdentity is the provider ETag/version observed
		// after it. Filesystem happens to use the digest for both, but object
		// providers do not, so only the view/path and verified transition match
		// here. The managed publisher separately proves remote content == SHA.
		if checkpoint[index].ViewID != attempt[index].ViewID || checkpoint[index].PointerPath != attempt[index].PointerPath || checkpoint[index].RemoteIdentity == "" || attempt[index].State != "verified" {
			return false
		}
	}
	return true
}

func requirePublicationBindingTx(ctx context.Context, tx *sql.Tx, repositoryID, targetIdentity string) error {
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM publication_target_bindings WHERE repository_id = ? AND target_identity = ?`, repositoryID, targetIdentity).Scan(&count); err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("%w: publication target binding", ErrNotFound)
	}
	return nil
}

func publicationPhaseRank(phase string) int {
	phases := []string{"planned", "payload", "immutable_metadata", "pointer_prepared", "commit_intent", "pointer_rollforward", "verified", "applied", "grace", "deletion_verified", "retained_reported", "done"}
	for index, value := range phases {
		if phase == value {
			return index
		}
	}
	return -1
}

func validPublicationPath(value string) bool {
	return value != "" && value != "." && path.Clean(value) == value && !strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "../") && !strings.ContainsAny(value, "\\\x00\r\n\t")
}
func publicationPrefixesOverlap(left, right string) bool {
	return left == "" || right == "" || left == right || strings.HasPrefix(left, right+"/") || strings.HasPrefix(right, left+"/")
}
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func publicationIdentity(domain string, fields ...string) string {
	hash := sha256.New()
	hash.Write([]byte(domain))
	for _, field := range fields {
		hash.Write([]byte{0})
		hash.Write([]byte(field))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func publicationSemanticIdentity(domain string, value any) string {
	data, _ := json.Marshal(value)
	hash := sha256.New()
	hash.Write([]byte(domain))
	hash.Write([]byte{0})
	hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil))
}
