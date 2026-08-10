package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	LayoutC2V1              = "c2-v1"
	LayoutC2ToSingleV1      = "c2-to-single-v1"
	LayoutSinglePayloadV1   = "single-payload-v1"
	DefaultRendererIdentity = "6c603eefa3ebe62caa89581b00bfc22aed2fa40904271cf31dd97f0750a92661"
)

var canonicalUUIDv4Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type RepositoryIdentity struct {
	RepositoryID            string `json:"repository_id"`
	LayoutVersion           string `json:"layout_version"`
	TransitionReceiptSHA256 string `json:"transition_receipt_sha256,omitempty"`
}

// LayoutTransitionControl is the private SQLite authority for one forward-only
// C2 migration.  Journal v1 intentionally carries no new fields: this row
// binds its immutable plan and, once committed, the exact deletion deadline.
type LayoutTransitionControl struct {
	RepositoryID         string
	BaseGeneration       GenerationID
	TargetManifestSHA256 string
	PlanIdentitySHA256   string
	PlannedAt            string
	CommitIntentAt       string
	NotBefore            string
}

func canonicalTransitionControlTime(value string) bool {
	parsed, err := time.Parse(time.RFC3339, value)
	return err == nil && parsed.Location() == time.UTC && parsed.Nanosecond() == 0 && parsed.Format("2006-01-02T15:04:05Z") == value
}

func (s *Store) LayoutTransitionControl(ctx context.Context) (*LayoutTransitionControl, error) {
	var control LayoutTransitionControl
	var commitIntentAt, notBefore sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT repository_id, base_generation, target_manifest_sha256, plan_identity_sha256, planned_at, commit_intent_at, not_before FROM layout_transition_control WHERE singleton = 1`).Scan(
		&control.RepositoryID, &control.BaseGeneration, &control.TargetManifestSHA256, &control.PlanIdentitySHA256, &control.PlannedAt, &commitIntentAt, &notBefore,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if commitIntentAt.Valid {
		control.CommitIntentAt = commitIntentAt.String
	}
	if notBefore.Valid {
		control.NotBefore = notBefore.String
	}
	if !IsCanonicalRepositoryID(control.RepositoryID) || !validSHA256Text(control.TargetManifestSHA256) || !validSHA256Text(control.PlanIdentitySHA256) || !canonicalTransitionControlTime(control.PlannedAt) ||
		(control.CommitIntentAt == "") != (control.NotBefore == "") ||
		control.CommitIntentAt != "" && (!canonicalTransitionControlTime(control.CommitIntentAt) || !canonicalTransitionControlTime(control.NotBefore)) {
		return nil, fmt.Errorf("%w: invalid layout transition control", ErrSchema)
	}
	return &control, nil
}

func (s *Store) AnchorLayoutTransitionPlan(ctx context.Context, repositoryID string, base GenerationID, targetManifestSHA256, planIdentitySHA256, plannedAt string) error {
	if !IsCanonicalRepositoryID(repositoryID) || !validSHA256Text(targetManifestSHA256) || !validSHA256Text(planIdentitySHA256) || !canonicalTransitionControlTime(plannedAt) {
		return errors.New("invalid layout transition plan anchor")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current GenerationID
	var currentRepositoryID, layout string
	if err := tx.QueryRowContext(ctx, `SELECT repository_id, built_generation, layout_version FROM repository_state WHERE singleton = 1`).Scan(&currentRepositoryID, &current, &layout); err != nil {
		return err
	}
	if currentRepositoryID != repositoryID || current != base || layout != LayoutC2ToSingleV1 {
		return fmt.Errorf("%w: transition plan differs from repository base/layout", ErrConflict)
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO layout_transition_control(singleton, repository_id, base_generation, target_manifest_sha256, plan_identity_sha256, planned_at) VALUES (1, ?, ?, ?, ?, ?) ON CONFLICT(singleton) DO NOTHING`, repositoryID, base, targetManifestSHA256, planIdentitySHA256, plannedAt)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		var existingRepositoryID string
		var existingBase GenerationID
		var existingTarget, existingPlan, existingPlannedAt string
		if err := tx.QueryRowContext(ctx, `SELECT repository_id, base_generation, target_manifest_sha256, plan_identity_sha256, planned_at FROM layout_transition_control WHERE singleton = 1`).Scan(&existingRepositoryID, &existingBase, &existingTarget, &existingPlan, &existingPlannedAt); err != nil {
			return err
		}
		if existingRepositoryID != repositoryID || existingBase != base || existingTarget != targetManifestSHA256 || existingPlan != planIdentitySHA256 || existingPlannedAt != plannedAt {
			return fmt.Errorf("%w: transition plan anchor changed", ErrConflict)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.Checkpoint(ctx)
}

func (s *Store) CommitLayoutTransitionPlan(ctx context.Context, planIdentitySHA256, commitIntentAt, notBefore string) error {
	if !validSHA256Text(planIdentitySHA256) || !canonicalTransitionControlTime(commitIntentAt) || !canonicalTransitionControlTime(notBefore) {
		return errors.New("invalid layout transition commit anchor")
	}
	start, _ := time.Parse(time.RFC3339, commitIntentAt)
	deadline, _ := time.Parse(time.RFC3339, notBefore)
	if deadline.Sub(start) < 30*24*time.Hour {
		return errors.New("layout transition grace is shorter than 30 days")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE layout_transition_control SET commit_intent_at = ?, not_before = ? WHERE singleton = 1 AND plan_identity_sha256 = ? AND commit_intent_at IS NULL AND not_before IS NULL`, commitIntentAt, notBefore, planIdentitySHA256)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		var existingPlan string
		var existingCommit, existingDeadline sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT plan_identity_sha256, commit_intent_at, not_before FROM layout_transition_control WHERE singleton = 1`).Scan(&existingPlan, &existingCommit, &existingDeadline); err != nil {
			return err
		}
		if existingPlan != planIdentitySHA256 || !existingCommit.Valid || !existingDeadline.Valid || existingCommit.String != commitIntentAt || existingDeadline.String != notBefore {
			return fmt.Errorf("%w: transition commit anchor changed", ErrConflict)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.Checkpoint(ctx)
}

func IsCanonicalRepositoryID(value string) bool {
	return canonicalUUIDv4Pattern.MatchString(value)
}

func (s *Store) RepositoryIdentity(ctx context.Context) (RepositoryIdentity, error) {
	var identity RepositoryIdentity
	var receipt sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT repository_id, layout_version, transition_receipt_sha256 FROM repository_state WHERE singleton = 1`).Scan(&identity.RepositoryID, &identity.LayoutVersion, &receipt); err != nil {
		return RepositoryIdentity{}, fmt.Errorf("read repository identity: %w", err)
	}
	if receipt.Valid {
		identity.TransitionReceiptSHA256 = receipt.String
	}
	if !IsCanonicalRepositoryID(identity.RepositoryID) || !validLayoutVersion(identity.LayoutVersion) || identity.TransitionReceiptSHA256 != "" && !validSHA256Text(identity.TransitionReceiptSHA256) {
		return RepositoryIdentity{}, fmt.Errorf("%w: invalid repository identity state", ErrSchema)
	}
	return identity, nil
}

func validLayoutVersion(layout string) bool {
	return layout == LayoutC2V1 || layout == LayoutC2ToSingleV1 || layout == LayoutSinglePayloadV1
}

// RequireTerminalLayout is the common fail-closed gate for ordinary changes,
// mutation, publication and GC entrypoints.  The transition journal, rather
// than a misleading steady-state manifest, owns non-terminal recovery.
func (s *Store) RequireTerminalLayout(ctx context.Context) error {
	identity, err := s.RepositoryIdentity(ctx)
	if err != nil {
		return err
	}
	if identity.LayoutVersion != LayoutSinglePayloadV1 {
		return fmt.Errorf("%w: repository layout %q requires explicit migration", ErrTransition, identity.LayoutVersion)
	}
	return nil
}

// AbandonLayoutTransition is legal only before a migration persists commit
// intent.  The managed journal validator owns that proof; this state primitive
// merely performs the serialized layout rollback requested by it.
func (s *Store) AbandonLayoutTransition(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var committed int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM layout_transition_control WHERE singleton = 1 AND commit_intent_at IS NOT NULL)`).Scan(&committed); err != nil {
		return err
	}
	if committed != 0 {
		return fmt.Errorf("%w: committed layout transition cannot be abandoned", ErrTransition)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM layout_transition_control WHERE singleton = 1`); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE repository_state SET layout_version = ?, transition_receipt_sha256 = NULL WHERE singleton = 1 AND layout_version = ?`, LayoutC2V1, LayoutC2ToSingleV1)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return fmt.Errorf("%w: repository is not in the C2 transition layout", ErrTransition)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.Checkpoint(ctx)
}

func (s *Store) BeginLayoutTransition(ctx context.Context) error {
	var controlCount int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM layout_transition_control`).Scan(&controlCount); err != nil {
		return err
	}
	if controlCount != 0 {
		return fmt.Errorf("%w: repository has a stale layout transition control", ErrTransition)
	}
	result, err := s.db.ExecContext(ctx, `UPDATE repository_state SET layout_version = ?, transition_receipt_sha256 = NULL WHERE singleton = 1 AND layout_version = ?`, LayoutC2ToSingleV1, LayoutC2V1)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		identity, identityErr := s.RepositoryIdentity(ctx)
		if identityErr == nil && identity.LayoutVersion == LayoutC2ToSingleV1 {
			return nil
		}
		return fmt.Errorf("%w: repository cannot enter C2 transition", ErrTransition)
	}
	return s.Checkpoint(ctx)
}

// CompleteLayoutTransition atomically installs the first terminal manifest,
// advances every Built projection to its new Generation, stores the exact
// done-journal identity as receipt, and flips the layout.  Journal deletion is
// intentionally a later managed-filesystem step.
func (s *Store) CompleteLayoutTransition(ctx context.Context, operationID string, base GenerationID, inputManifest []GenerationFile, receipt string) (GenerationID, error) {
	if !operationIDPattern.MatchString(operationID) || !validSHA256Text(receipt) {
		return 0, errors.New("invalid layout transition completion identity")
	}
	next, err := base.Next()
	if err != nil {
		return 0, err
	}
	manifest, manifestSHA, err := normalizeManifestForLayout(inputManifest, LayoutSinglePayloadV1)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var current GenerationID
	var repositoryID, layout string
	if err := tx.QueryRowContext(ctx, `SELECT repository_id, built_generation, layout_version FROM repository_state WHERE singleton = 1`).Scan(&repositoryID, &current, &layout); err != nil {
		return 0, err
	}
	if current != base || layout != LayoutC2ToSingleV1 {
		return 0, fmt.Errorf("%w: transition base/layout changed", ErrConflict)
	}
	var controlRepositoryID, controlTarget string
	var controlBase GenerationID
	var commitIntentAt, notBefore sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT repository_id, base_generation, target_manifest_sha256, commit_intent_at, not_before FROM layout_transition_control WHERE singleton = 1`).Scan(&controlRepositoryID, &controlBase, &controlTarget, &commitIntentAt, &notBefore); err != nil {
		return 0, fmt.Errorf("%w: transition commit anchor is unavailable: %v", ErrConflict, err)
	}
	if controlRepositoryID != repositoryID || controlBase != base || controlTarget != manifestSHA || !commitIntentAt.Valid || !notBefore.Valid {
		return 0, fmt.Errorf("%w: transition completion differs from committed control anchor", ErrConflict)
	}
	baseManifest, err := generationManifestTx(ctx, tx, base)
	if err != nil {
		return 0, err
	}
	changes := DiffManifests(baseManifest, manifest)
	now := nowText()
	payload := fmt.Sprintf(`{"base_generation":"%s","target_generation":"%s","transition_receipt_sha256":"%s"}`, base.String(), next.String(), receipt)
	if _, err := tx.ExecContext(ctx, `INSERT INTO operations(id, kind, state, payload_json, result_json, created_at, updated_at) VALUES (?, 'layout.migrate', 'done', ?, '{"migrated":true}', ?, ?)`, operationID, payload, now, now); err != nil {
		return 0, fmt.Errorf("record layout migration operation: %w", err)
	}
	for sequence, operationState := range []OperationState{OperationPlanned, OperationStaged, OperationBuilt, OperationDone} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO operation_events(operation_id, sequence, state, detail_json, occurred_at) VALUES (?, ?, ?, '{}', ?)`, operationID, sequence, operationState, now); err != nil {
			return 0, err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO generations(generation, previous_generation, operation_id, manifest_sha256, renderer_identity, created_at) VALUES (?, ?, ?, ?, ?, ?)`, next, base, operationID, manifestSHA, DefaultRendererIdentity, now); err != nil {
		return 0, err
	}
	if err := insertGenerationFilesTx(ctx, tx, next, manifest); err != nil {
		return 0, err
	}
	signerRows, err := tx.QueryContext(ctx, `
SELECT d.name, a.family, COALESCE(s.fingerprint, ''), COALESCE(s.public_key, X'')
FROM dists AS d
JOIN dist_architectures AS a ON a.dist_name = d.name
LEFT JOIN dist_metadata_signers AS s ON s.dist_name = d.name
WHERE d.format = 'rpm'
ORDER BY d.name, a.family`)
	if err != nil {
		return 0, err
	}
	type transitionSigner struct {
		viewID, fingerprint string
		publicKey           []byte
	}
	signers := []transitionSigner{}
	for signerRows.Next() {
		var distName, family string
		var signer transitionSigner
		if err := signerRows.Scan(&distName, &family, &signer.fingerprint, &signer.publicKey); err != nil {
			signerRows.Close()
			return 0, err
		}
		signer.viewID = "dists/" + distName + "/" + family
		signers = append(signers, signer)
	}
	if err := errors.Join(signerRows.Err(), signerRows.Close()); err != nil {
		return 0, err
	}
	for _, signer := range signers {
		identity := "none"
		var trusted any
		if signer.fingerprint != "" {
			if len(signer.publicKey) == 0 {
				return 0, errors.New("signed RPM view lacks retained public key")
			}
			digest := sha256.Sum256(signer.publicKey)
			identity, trusted = hex.EncodeToString(digest[:]), signer.publicKey
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO generation_view_signers(generation, view_id, signer_identity, trusted_public_key) VALUES (?, ?, ?, ?)`, next, signer.viewID, identity, trusted); err != nil {
			return 0, err
		}
	}
	if err := insertOperationFilesTx(ctx, tx, operationID, changes); err != nil {
		return 0, err
	}
	// Only RPM views are rewritten by the C2-to-single transition.  APT
	// Release files retain their existing generation bytes, so their Dist and
	// membership projections must retain that same generation as well.
	if _, err := tx.ExecContext(ctx, `DELETE FROM prior_built_memberships WHERE dist_name IN (SELECT name FROM dists WHERE format = 'rpm')`); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO prior_built_memberships(dist_name, package_sha256, generation)
SELECT b.dist_name, b.package_sha256, b.generation
FROM built_memberships AS b
JOIN dists AS d ON d.name = b.dist_name
WHERE d.format = 'rpm'`); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE built_memberships SET generation = ? WHERE dist_name IN (SELECT name FROM dists WHERE format = 'rpm')`, next); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE dists SET built_generation = ? WHERE format = 'rpm'`, next); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE dist_architectures SET built_generation = ? WHERE dist_name IN (SELECT name FROM dists WHERE format = 'rpm')`, next); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE repository_state SET built_generation = ?, layout_version = ?, transition_receipt_sha256 = ? WHERE singleton = 1`, next, LayoutSinglePayloadV1, receipt); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	if err := s.Checkpoint(ctx); err != nil {
		return next, err
	}
	return next, nil
}
