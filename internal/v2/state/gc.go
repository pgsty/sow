package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// LocalGCInventory is a settled snapshot of package rows which have no
// Desired, Built, or stale-client membership root. Managed GC adds retained,
// recovery, migration, and publication roots before it creates a deletion
// plan; this API deliberately never guesses about filesystem evidence.
type LocalGCInventory struct {
	RepositoryID string
	Generation   GenerationID
	Candidates   []PackageObject
}

// LocalGCInventory returns only physically pooled package objects for which
// SQLite has no live projection root. It is legal only for a clean terminal
// repository with no pending operation.
func (s *Store) LocalGCInventory(ctx context.Context) (LocalGCInventory, error) {
	if err := s.RequireTerminalLayout(ctx); err != nil {
		return LocalGCInventory{}, err
	}
	if err := s.Check(ctx); err != nil {
		return LocalGCInventory{}, err
	}
	var inventory LocalGCInventory
	var status string
	var pending int64
	if err := s.db.QueryRowContext(ctx, `SELECT repository_id, built_generation, status FROM repository_state WHERE singleton = 1`).Scan(&inventory.RepositoryID, &inventory.Generation, &status); err != nil {
		return LocalGCInventory{}, err
	}
	if status != "clean" || inventory.Generation == 0 {
		return LocalGCInventory{}, fmt.Errorf("%w: local GC requires a settled clean Built Generation", ErrConflict)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM operations WHERE state NOT IN ('done', 'done_dirty', 'rolled_back', 'failed')`).Scan(&pending); err != nil {
		return LocalGCInventory{}, err
	}
	if pending != 0 {
		return LocalGCInventory{}, fmt.Errorf("%w: local GC requires no pending operation", ErrConflict)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT p.sha256, p.format, p.coordinate, p.architecture, p.canonical_arch,
       p.pool_path, p.filename, p.size, p.name, p.source, p.version, p.epoch,
       p.release, p.kind, p.payload_sha256, p.signature_key, p.warning, p.storage,
       p.created_revision
FROM package_objects AS p
WHERE p.storage = 'pool'
  AND NOT EXISTS (SELECT 1 FROM memberships AS m WHERE m.package_sha256 = p.sha256)
  AND NOT EXISTS (SELECT 1 FROM built_memberships AS b WHERE b.package_sha256 = p.sha256)
  AND NOT EXISTS (SELECT 1 FROM prior_built_memberships AS b WHERE b.package_sha256 = p.sha256)
ORDER BY p.pool_path, p.sha256`)
	if err != nil {
		return LocalGCInventory{}, err
	}
	defer rows.Close()
	for rows.Next() {
		object, err := scanPackageObject(rows)
		if err != nil {
			return LocalGCInventory{}, err
		}
		inventory.Candidates = append(inventory.Candidates, object)
	}
	if err := rows.Err(); err != nil {
		return LocalGCInventory{}, err
	}
	return inventory, nil
}

type FinalizeLocalGCInput struct {
	OperationID    string
	RepositoryID   string
	BaseGeneration GenerationID
	Generation     GenerationID
	Objects        []PackageObject
	Manifest       []GenerationFile
	Changes        []FileChange
}

// FinalizeLocalGC atomically records the maintenance Generation and removes
// its package-object rows. Payload bytes remain in the managed tombstone until
// this transaction is durable, so a crash can never leave SQLite referencing
// a physically deleted last copy.
func (s *Store) FinalizeLocalGC(ctx context.Context, input FinalizeLocalGCInput) error {
	if input.OperationID == "" || !IsCanonicalRepositoryID(input.RepositoryID) || input.BaseGeneration == 0 || input.Generation == 0 || len(input.Objects) == 0 {
		return errors.New("invalid local GC finalization")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin local GC finalization: %w", err)
	}
	defer tx.Rollback()

	var current GenerationID
	var repositoryID, layout, status string
	if err := tx.QueryRowContext(ctx, `SELECT repository_id, built_generation, layout_version, status FROM repository_state WHERE singleton = 1`).Scan(&repositoryID, &current, &layout, &status); err != nil {
		return err
	}
	operationState, err := operationStateTx(ctx, tx, input.OperationID)
	if err != nil {
		return err
	}
	if operationState == OperationDone {
		if repositoryID == input.RepositoryID && current == input.Generation {
			return nil
		}
		return fmt.Errorf("%w: completed local GC does not match repository head", ErrConflict)
	}
	if repositoryID != input.RepositoryID || current != input.BaseGeneration || layout != LayoutSinglePayloadV1 || status != "clean" {
		return fmt.Errorf("%w: local GC base identity, layout, or settled state changed", ErrConflict)
	}
	if operationState != OperationApplied && operationState != OperationRecovering {
		return fmt.Errorf("%w: finalize local GC from %s", ErrTransition, operationState)
	}
	expected, err := input.BaseGeneration.Next()
	if err != nil || input.Generation != expected {
		return fmt.Errorf("%w: local GC target does not follow its base", ErrConflict)
	}

	objects := append([]PackageObject(nil), input.Objects...)
	sort.Slice(objects, func(i, j int) bool { return objects[i].PoolPath < objects[j].PoolPath })
	for index, object := range objects {
		if err := validatePackageObject(object); err != nil || object.Storage != "pool" || index > 0 && objects[index-1].PoolPath >= object.PoolPath {
			return errors.Join(errors.New("invalid local GC package inventory"), err)
		}
		persisted, err := getPackageObjectTx(ctx, tx, object.SHA256)
		if err != nil || !sameImmutablePackageObject(persisted, object) || persisted.Storage != "pool" {
			return errors.Join(fmt.Errorf("%w: local GC package %s changed", ErrConflict, object.SHA256), err)
		}
		var rooted int
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM memberships WHERE package_sha256 = ?)
 OR EXISTS(SELECT 1 FROM built_memberships WHERE package_sha256 = ?)
 OR EXISTS(SELECT 1 FROM prior_built_memberships WHERE package_sha256 = ?)`, object.SHA256, object.SHA256, object.SHA256).Scan(&rooted); err != nil {
			return err
		}
		if rooted != 0 {
			return fmt.Errorf("%w: local GC package %s gained a projection root", ErrConflict, object.SHA256)
		}
	}
	baseManifest, err := generationManifestTx(ctx, tx, input.BaseGeneration)
	if err != nil {
		return err
	}
	removed := make(map[string]PackageObject, len(objects))
	for _, object := range objects {
		removed[object.PoolPath] = object
	}
	target := make([]GenerationFile, 0, len(baseManifest)-len(objects))
	for _, file := range baseManifest {
		object, remove := removed[file.Path]
		if remove {
			if file.Phase != "payload" || file.Size != object.Size || file.SHA256 != object.SHA256 {
				return fmt.Errorf("%w: local GC manifest identity differs for %q", ErrConflict, file.Path)
			}
			delete(removed, file.Path)
			continue
		}
		target = append(target, file)
	}
	if len(removed) != 0 || !sameGenerationFiles(target, input.Manifest) || !equalFileChanges(DiffManifests(baseManifest, target), input.Changes) {
		return fmt.Errorf("%w: local GC target manifest or changes differ from exact base subtraction", ErrConflict)
	}
	baseInfo, err := generationInfoTx(ctx, tx, input.BaseGeneration)
	if err != nil {
		return err
	}
	if err := recordGenerationTx(ctx, tx, input.OperationID, input.Generation, input.Manifest, input.Changes, baseInfo.RendererIdentity); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO generation_view_signers(generation, view_id, signer_identity, trusted_public_key)
SELECT ?, view_id, signer_identity, trusted_public_key FROM generation_view_signers WHERE generation = ?`, input.Generation, input.BaseGeneration); err != nil {
		return err
	}
	for _, object := range objects {
		result, err := tx.ExecContext(ctx, `DELETE FROM package_objects WHERE sha256 = ? AND storage = 'pool'`, object.SHA256)
		if err != nil {
			return err
		}
		if rows, err := result.RowsAffected(); err != nil || rows != 1 {
			return errors.Join(fmt.Errorf("%w: local GC package row changed", ErrConflict), err)
		}
	}
	resultJSON, err := json.Marshal(struct {
		Generation GenerationID `json:"generation"`
		Objects    int          `json:"objects"`
	}{input.Generation, len(objects)})
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE operations SET result_json = ? WHERE id = ?`, string(resultJSON), input.OperationID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE repository_state SET built_generation = ? WHERE singleton = 1`, input.Generation); err != nil {
		return err
	}
	if err := setOperationStateTx(ctx, tx, input.OperationID, OperationDone, "", ""); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit local GC finalization: %w", err)
	}
	return s.Checkpoint(ctx)
}

func getPackageObjectTx(ctx context.Context, tx *sql.Tx, digest string) (PackageObject, error) {
	row := tx.QueryRowContext(ctx, `SELECT sha256, format, coordinate, architecture, canonical_arch,
       pool_path, filename, size, name, source, version, epoch, release, kind,
       payload_sha256, signature_key, warning, storage, created_revision
FROM package_objects WHERE sha256 = ?`, digest)
	object, err := scanPackageObject(row)
	if errors.Is(err, sql.ErrNoRows) {
		return PackageObject{}, fmt.Errorf("%w: package object %s", ErrNotFound, digest)
	}
	return object, err
}

func generationInfoTx(ctx context.Context, tx *sql.Tx, generation GenerationID) (GenerationInfo, error) {
	var info GenerationInfo
	if err := tx.QueryRowContext(ctx, `SELECT generation, previous_generation, operation_id, manifest_sha256, renderer_identity FROM generations WHERE generation = ?`, generation).Scan(
		&info.Generation, &info.PreviousGeneration, &info.OperationID, &info.ManifestSHA256, &info.RendererIdentity,
	); err != nil {
		return GenerationInfo{}, err
	}
	return info, nil
}

func sameGenerationFiles(left, right []GenerationFile) bool {
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
