package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
)

type PackageObject struct {
	SHA256          string   `json:"sha256"`
	Format          string   `json:"format"`
	Coordinate      string   `json:"coordinate"`
	Architecture    string   `json:"architecture"`
	CanonicalArch   string   `json:"canonical_arch"`
	PoolPath        string   `json:"pool_path"`
	Filename        string   `json:"filename"`
	Size            int64    `json:"size"`
	Name            string   `json:"name"`
	Source          string   `json:"source"`
	Version         string   `json:"version"`
	Epoch           string   `json:"epoch,omitempty"`
	Release         string   `json:"release,omitempty"`
	Kind            string   `json:"kind"`
	PayloadSHA256   string   `json:"payload_sha256,omitempty"`
	SignatureKey    string   `json:"signature_key,omitempty"`
	Warning         string   `json:"warning,omitempty"`
	Storage         string   `json:"storage"`
	CreatedRevision int64    `json:"created_revision"`
	Dists           []string `json:"dists"`
	BuiltDists      []string `json:"built_dists"`
}

type DesiredMutationResult struct {
	Revision       int64           `json:"revision"`
	Changed        bool            `json:"changed"`
	ChangedDists   []string        `json:"changed_dists"`
	DroppedPending []PackageObject `json:"dropped_pending"`
}

// ApplyDesiredMutation atomically installs new immutable package facts and
// complete Desired Membership sets for the named Dists. The caller must have
// durably staged every new pending object before invoking this method. It is
// deliberately a whole-set API so every Membership write path is forced to
// apply policy to the complete Dist state instead of incrementally bypassing
// it.
func (s *Store) ApplyDesiredMutation(ctx context.Context, operationID string, objects []PackageObject, desired map[string][]string, resultJSON string) (DesiredMutationResult, error) {
	return s.ApplyDesiredMutationWithSigningKeys(ctx, operationID, objects, nil, desired, resultJSON)
}

// ApplyDesiredMutationWithSigningKeys extends ApplyDesiredMutation with the
// exact public RPM certificate snapshots needed to authenticate the resulting
// Desired/Built projection. The snapshots are inserted in the same SQLite
// transaction as package facts, Memberships, the operation result, and the
// applied state transition; a rejected or rolled-back mutation therefore
// cannot leave unaudited verifier-cache side effects.
func (s *Store) ApplyDesiredMutationWithSigningKeys(ctx context.Context, operationID string, objects []PackageObject, signingKeys []RPMSigningKey, desired map[string][]string, resultJSON string) (DesiredMutationResult, error) {
	if len(desired) == 0 {
		return DesiredMutationResult{}, errors.New("desired mutation requires at least one dist")
	}
	if resultJSON == "" {
		resultJSON = `{}`
	}
	if err := validateOperationPayload(resultJSON); err != nil {
		return DesiredMutationResult{}, fmt.Errorf("invalid operation result: %w", err)
	}
	for index := range objects {
		if err := validatePackageObject(objects[index]); err != nil {
			return DesiredMutationResult{}, fmt.Errorf("package object %d: %w", index, err)
		}
	}
	keys, err := normalizeRPMSigningKeys(signingKeys)
	if err != nil {
		return DesiredMutationResult{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DesiredMutationResult{}, fmt.Errorf("begin desired mutation: %w", err)
	}
	defer tx.Rollback()
	operationState, err := operationStateTx(ctx, tx, operationID)
	if err != nil {
		return DesiredMutationResult{}, err
	}
	if operationState != OperationStaged && operationState != OperationRecovering {
		return DesiredMutationResult{}, fmt.Errorf("%w: apply desired mutation from %s", ErrTransition, operationState)
	}
	if err := retainRPMSigningKeysTx(ctx, tx, keys); err != nil {
		return DesiredMutationResult{}, fmt.Errorf("retain RPM signing verification keys: %w", err)
	}

	distNames := make([]string, 0, len(desired))
	needed := make(map[string]struct{})
	wantedByDist := make(map[string][]string, len(desired))
	for distName, digests := range desired {
		if distName == "" {
			return DesiredMutationResult{}, errors.New("desired mutation has an empty dist name")
		}
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM dists WHERE name = ?)`, distName).Scan(&exists); err != nil {
			return DesiredMutationResult{}, fmt.Errorf("inspect dist %q: %w", distName, err)
		}
		if exists == 0 {
			return DesiredMutationResult{}, fmt.Errorf("%w: dist %q", ErrNotFound, distName)
		}
		unique := make(map[string]struct{}, len(digests))
		for _, digest := range digests {
			if !validSHA256Text(digest) {
				return DesiredMutationResult{}, fmt.Errorf("dist %q has invalid package sha256 %q", distName, digest)
			}
			unique[digest] = struct{}{}
			needed[digest] = struct{}{}
		}
		canonical := make([]string, 0, len(unique))
		for digest := range unique {
			canonical = append(canonical, digest)
		}
		sort.Strings(canonical)
		wantedByDist[distName] = canonical
		distNames = append(distNames, distName)
	}
	sort.Strings(distNames)

	var currentRevision int64
	if err := tx.QueryRowContext(ctx, `SELECT desired_revision FROM repository_state WHERE singleton = 1`).Scan(&currentRevision); err != nil {
		return DesiredMutationResult{}, fmt.Errorf("read desired revision: %w", err)
	}
	nextRevision := currentRevision + 1
	newByDigest := make(map[string]PackageObject, len(objects))
	newByPortablePath := make(map[string]PackageObject, len(objects))
	newObjects := make([]PackageObject, 0, len(objects))
	for _, object := range objects {
		if _, duplicate := newByDigest[object.SHA256]; duplicate {
			return DesiredMutationResult{}, fmt.Errorf("duplicate package object %s in mutation", object.SHA256)
		}
		newByDigest[object.SHA256] = object
		if _, referenced := needed[object.SHA256]; !referenced {
			continue
		}
		portablePath := strings.ToLower(object.PoolPath)
		if prior, duplicate := newByPortablePath[portablePath]; duplicate && prior.SHA256 != object.SHA256 {
			return DesiredMutationResult{}, fmt.Errorf("%w: pool path %s collides case-insensitively with %s", ErrConflict, object.PoolPath, prior.PoolPath)
		}
		newByPortablePath[portablePath] = object
		existing, found, err := packageObjectTx(ctx, tx, object.SHA256)
		if err != nil {
			return DesiredMutationResult{}, err
		}
		if found {
			if !sameImmutablePackageObject(existing, object) {
				return DesiredMutationResult{}, fmt.Errorf("%w: sha256 %s has different package facts", ErrConflict, object.SHA256)
			}
			continue
		}
		var coordinateSHA string
		err = tx.QueryRowContext(ctx, `SELECT sha256 FROM package_objects WHERE format = ? AND coordinate = ?`, object.Format, object.Coordinate).Scan(&coordinateSHA)
		if err == nil {
			return DesiredMutationResult{}, fmt.Errorf("%w: coordinate %s:%s already maps to %s", ErrConflict, object.Format, object.Coordinate, coordinateSHA)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return DesiredMutationResult{}, fmt.Errorf("inspect package coordinate: %w", err)
		}
		var pathSHA, pathValue string
		err = tx.QueryRowContext(ctx, `SELECT sha256, pool_path FROM package_objects WHERE pool_path = ? COLLATE NOCASE`, object.PoolPath).Scan(&pathSHA, &pathValue)
		if err == nil {
			return DesiredMutationResult{}, fmt.Errorf("%w: pool path %s collides case-insensitively with %s owned by %s", ErrConflict, object.PoolPath, pathValue, pathSHA)
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return DesiredMutationResult{}, fmt.Errorf("inspect portable package pool path: %w", err)
		}
		object.CreatedRevision = nextRevision
		newObjects = append(newObjects, object)
	}

	changedDists := make([]string, 0, len(distNames))
	currentByDist := make(map[string][]string, len(distNames))
	for _, distName := range distNames {
		current, err := membershipDigestsTx(ctx, tx, distName, false)
		if err != nil {
			return DesiredMutationResult{}, err
		}
		if !sameStrings(current, wantedByDist[distName]) {
			changedDists = append(changedDists, distName)
		}
		currentByDist[distName] = current
	}
	changed := len(changedDists) != 0 || len(newObjects) != 0
	if !changed {
		nextRevision = currentRevision
	}
	for _, object := range newObjects {
		if err := insertPackageObjectTx(ctx, tx, object); err != nil {
			return DesiredMutationResult{}, err
		}
	}
	membershipSequence := 0
	for _, distName := range changedDists {
		before := make(map[string]struct{}, len(currentByDist[distName]))
		after := make(map[string]struct{}, len(wantedByDist[distName]))
		for _, digest := range currentByDist[distName] {
			before[digest] = struct{}{}
		}
		for _, digest := range wantedByDist[distName] {
			after[digest] = struct{}{}
		}
		for _, digest := range currentByDist[distName] {
			if _, retained := after[digest]; retained {
				continue
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO operation_memberships(operation_id, sequence, dist_name, package_sha256, action) VALUES (?, ?, ?, ?, 'remove')`, operationID, membershipSequence, distName, digest); err != nil {
				return DesiredMutationResult{}, err
			}
			membershipSequence++
		}
		for _, digest := range wantedByDist[distName] {
			if _, existed := before[digest]; existed {
				continue
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO operation_memberships(operation_id, sequence, dist_name, package_sha256, action) VALUES (?, ?, ?, ?, 'add')`, operationID, membershipSequence, distName, digest); err != nil {
				return DesiredMutationResult{}, err
			}
			membershipSequence++
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM memberships WHERE dist_name = ?`, distName); err != nil {
			return DesiredMutationResult{}, fmt.Errorf("replace memberships for dist %q: %w", distName, err)
		}
		for _, digest := range wantedByDist[distName] {
			if _, err := tx.ExecContext(ctx, `INSERT INTO memberships(dist_name, package_sha256, created_revision) VALUES (?, ?, ?)`, distName, digest, nextRevision); err != nil {
				return DesiredMutationResult{}, fmt.Errorf("add membership %q/%s: %w", distName, digest, err)
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE dists SET desired_revision = ? WHERE name = ?`, nextRevision, distName); err != nil {
			return DesiredMutationResult{}, fmt.Errorf("advance dist %q desired revision: %w", distName, err)
		}
	}

	dropped, err := unreferencedPendingTx(ctx, tx)
	if err != nil {
		return DesiredMutationResult{}, err
	}
	for _, object := range dropped {
		if _, err := tx.ExecContext(ctx, `DELETE FROM package_objects WHERE sha256 = ?`, object.SHA256); err != nil {
			return DesiredMutationResult{}, fmt.Errorf("drop unreferenced pending object %s: %w", object.SHA256, err)
		}
	}
	if changed {
		status, reason, err := repositoryProjectionStatusTx(ctx, tx)
		if err != nil {
			return DesiredMutationResult{}, fmt.Errorf("derive repository projection status: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE repository_state SET desired_revision = ?, status = ?, dirty_reason = ? WHERE singleton = 1`, nextRevision, status, reason); err != nil {
			return DesiredMutationResult{}, fmt.Errorf("record repository projection status: %w", err)
		}
	}
	var priorResultJSON string
	if err := tx.QueryRowContext(ctx, `SELECT result_json FROM operations WHERE id = ?`, operationID).Scan(&priorResultJSON); err != nil {
		return DesiredMutationResult{}, fmt.Errorf("read prior operation result: %w", err)
	}
	cleanup, mergedResultJSON, err := mergeDroppedPendingResult(resultJSON, priorResultJSON, dropped)
	if err != nil {
		return DesiredMutationResult{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE operations SET result_json = ? WHERE id = ?`, mergedResultJSON, operationID); err != nil {
		return DesiredMutationResult{}, fmt.Errorf("record operation result: %w", err)
	}
	if err := setOperationStateTx(ctx, tx, operationID, OperationApplied, "", ""); err != nil {
		return DesiredMutationResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return DesiredMutationResult{}, fmt.Errorf("commit desired mutation: %w", err)
	}
	result := DesiredMutationResult{Revision: nextRevision, Changed: changed, ChangedDists: changedDists, DroppedPending: cleanup}
	if err := s.Checkpoint(ctx); err != nil {
		return result, err
	}
	return result, nil
}

func mergeDroppedPendingResult(requestedJSON, priorJSON string, dropped []PackageObject) ([]PackageObject, string, error) {
	decode := func(data string) (map[string]json.RawMessage, error) {
		var value map[string]json.RawMessage
		if err := json.Unmarshal([]byte(data), &value); err != nil || value == nil {
			return nil, errors.New("operation result must be a JSON object")
		}
		return value, nil
	}
	requested, err := decode(requestedJSON)
	if err != nil {
		return nil, "", err
	}
	prior, err := decode(priorJSON)
	if err != nil {
		return nil, "", err
	}
	digests := map[string]struct{}{}
	if raw, exists := prior["dropped_pending"]; exists {
		var values []string
		if err := json.Unmarshal(raw, &values); err != nil {
			return nil, "", errors.New("operation result has malformed dropped_pending evidence")
		}
		for _, digest := range values {
			if !validSHA256Text(digest) {
				return nil, "", errors.New("operation result has invalid dropped_pending digest")
			}
			digests[digest] = struct{}{}
		}
	}
	for _, object := range dropped {
		if !validSHA256Text(object.SHA256) {
			return nil, "", errors.New("dropped pending object has invalid digest")
		}
		digests[object.SHA256] = struct{}{}
	}
	ordered := make([]string, 0, len(digests))
	for digest := range digests {
		ordered = append(ordered, digest)
	}
	sort.Strings(ordered)
	raw, err := json.Marshal(ordered)
	if err != nil {
		return nil, "", err
	}
	requested["dropped_pending"] = raw
	merged, err := json.Marshal(requested)
	if err != nil || len(merged) > MaxOperationPayloadBytes {
		return nil, "", errors.New("operation result with dropped_pending evidence exceeds its journal limit")
	}
	cleanup := make([]PackageObject, 0, len(ordered))
	for _, digest := range ordered {
		cleanup = append(cleanup, PackageObject{SHA256: digest})
	}
	return cleanup, string(merged), nil
}

func (s *Store) ListPackageObjects(ctx context.Context, distNames []string, built bool) ([]PackageObject, error) {
	table := "memberships"
	if built {
		table = "built_memberships"
	}
	return s.listPackageObjectsByMembershipTable(ctx, distNames, table)
}

// ListPriorBuiltPackageObjects returns the one-generation C2 compatibility
// projection retained for the selected Dist(s). It is distinct from current
// Built Membership and never broadens to other Dists.
func (s *Store) ListPriorBuiltPackageObjects(ctx context.Context, distNames []string) ([]PackageObject, error) {
	return s.listPackageObjectsByMembershipTable(ctx, distNames, "prior_built_memberships")
}

func (s *Store) listPackageObjectsByMembershipTable(ctx context.Context, distNames []string, table string) ([]PackageObject, error) {
	query := `SELECT DISTINCT p.sha256, p.format, p.coordinate, p.architecture, p.canonical_arch,
       p.pool_path, p.filename, p.size, p.name, p.source, p.version, p.epoch,
       p.release, p.kind, p.payload_sha256, p.signature_key, p.warning, p.storage,
       p.created_revision
FROM package_objects AS p`
	args := make([]any, 0, len(distNames))
	if len(distNames) != 0 {
		query += ` JOIN ` + table + ` AS m ON m.package_sha256 = p.sha256 WHERE m.dist_name IN (`
		for index, name := range distNames {
			if index != 0 {
				query += `,`
			}
			query += `?`
			args = append(args, name)
		}
		query += `)`
	}
	query += ` ORDER BY p.format, p.name, p.coordinate, p.sha256`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list package objects: %w", err)
	}
	defer rows.Close()
	objects := []PackageObject{}
	for rows.Next() {
		object, err := scanPackageObject(rows)
		if err != nil {
			return nil, err
		}
		objects = append(objects, object)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list package objects: %w", err)
	}
	for index := range objects {
		objects[index].Dists, err = s.packageDists(ctx, objects[index].SHA256, false)
		if err != nil {
			return nil, err
		}
		objects[index].BuiltDists, err = s.packageDists(ctx, objects[index].SHA256, true)
		if err != nil {
			return nil, err
		}
	}
	return objects, nil
}

func (s *Store) GetPackageObject(ctx context.Context, digest string) (PackageObject, error) {
	row := s.db.QueryRowContext(ctx, packageObjectSelect+` WHERE sha256 = ?`, digest)
	object, err := scanPackageObject(row)
	if errors.Is(err, sql.ErrNoRows) {
		return PackageObject{}, fmt.Errorf("%w: package object %s", ErrNotFound, digest)
	}
	if err != nil {
		return PackageObject{}, err
	}
	object.Dists, err = s.packageDists(ctx, digest, false)
	if err != nil {
		return PackageObject{}, err
	}
	object.BuiltDists, err = s.packageDists(ctx, digest, true)
	return object, err
}

func (s *Store) FindPackageByCoordinate(ctx context.Context, format, coordinate string) (PackageObject, error) {
	row := s.db.QueryRowContext(ctx, packageObjectSelect+` WHERE format = ? AND coordinate = ?`, format, coordinate)
	object, err := scanPackageObject(row)
	if errors.Is(err, sql.ErrNoRows) {
		return PackageObject{}, fmt.Errorf("%w: package coordinate %s:%s", ErrNotFound, format, coordinate)
	}
	if err != nil {
		return PackageObject{}, err
	}
	object.Dists, err = s.packageDists(ctx, object.SHA256, false)
	if err != nil {
		return PackageObject{}, err
	}
	object.BuiltDists, err = s.packageDists(ctx, object.SHA256, true)
	return object, err
}

const packageObjectSelect = `SELECT sha256, format, coordinate, architecture, canonical_arch,
       pool_path, filename, size, name, source, version, epoch, release, kind,
       payload_sha256, signature_key, warning, storage, created_revision
FROM package_objects`

func (s *Store) validatePackageObjectRows(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, packageObjectSelect+` ORDER BY sha256`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if _, err := scanPackageObject(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

func packageObjectTx(ctx context.Context, tx *sql.Tx, digest string) (PackageObject, bool, error) {
	object, err := scanPackageObject(tx.QueryRowContext(ctx, packageObjectSelect+` WHERE sha256 = ?`, digest))
	if errors.Is(err, sql.ErrNoRows) {
		return PackageObject{}, false, nil
	}
	if err != nil {
		return PackageObject{}, false, err
	}
	return object, true, nil
}

type scanner interface{ Scan(...any) error }

func scanPackageObject(row scanner) (PackageObject, error) {
	var object PackageObject
	var payload, signature, warning sql.NullString
	if err := row.Scan(
		&object.SHA256, &object.Format, &object.Coordinate, &object.Architecture, &object.CanonicalArch,
		&object.PoolPath, &object.Filename, &object.Size, &object.Name, &object.Source, &object.Version,
		&object.Epoch, &object.Release, &object.Kind, &payload, &signature, &warning, &object.Storage,
		&object.CreatedRevision,
	); err != nil {
		return PackageObject{}, err
	}
	object.PayloadSHA256 = payload.String
	object.SignatureKey = signature.String
	object.Warning = warning.String
	if err := validatePackageObject(object); err != nil {
		return PackageObject{}, fmt.Errorf("corrupt package object %s: %w", object.SHA256, err)
	}
	return object, nil
}

func insertPackageObjectTx(ctx context.Context, tx *sql.Tx, object PackageObject) error {
	var payload, signature, warning any
	if object.PayloadSHA256 != "" {
		payload = object.PayloadSHA256
	}
	if object.SignatureKey != "" {
		signature = object.SignatureKey
	}
	if object.Warning != "" {
		warning = object.Warning
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO package_objects(
sha256, format, coordinate, architecture, pool_path, size, name, source, version,
epoch, release, canonical_arch, kind, filename, payload_sha256, signature_key,
warning, storage, created_revision)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		object.SHA256, object.Format, object.Coordinate, object.Architecture, object.PoolPath,
		object.Size, object.Name, object.Source, object.Version, object.Epoch, object.Release,
		object.CanonicalArch, object.Kind, object.Filename, payload, signature, warning,
		object.Storage, object.CreatedRevision)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("%w: package object %s (%s:%s): %v", ErrConflict, object.SHA256, object.Format, object.Coordinate, err)
		}
		return fmt.Errorf("insert package object %s: %w", object.SHA256, err)
	}
	return nil
}

func membershipDigestsTx(ctx context.Context, tx *sql.Tx, distName string, built bool) ([]string, error) {
	table := "memberships"
	if built {
		table = "built_memberships"
	}
	rows, err := tx.QueryContext(ctx, `SELECT package_sha256 FROM `+table+` WHERE dist_name = ? ORDER BY package_sha256`, distName)
	if err != nil {
		return nil, fmt.Errorf("list memberships for dist %q: %w", distName, err)
	}
	defer rows.Close()
	result := []string{}
	for rows.Next() {
		var digest string
		if err := rows.Scan(&digest); err != nil {
			return nil, err
		}
		result = append(result, digest)
	}
	return result, rows.Err()
}

func (s *Store) MembershipDigests(ctx context.Context, distName string, built bool) ([]string, error) {
	table := "memberships"
	if built {
		table = "built_memberships"
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM dists WHERE name = ?)`, distName).Scan(&exists); err != nil {
		return nil, err
	}
	if exists == 0 {
		return nil, fmt.Errorf("%w: dist %q", ErrNotFound, distName)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT package_sha256 FROM `+table+` WHERE dist_name = ? ORDER BY package_sha256`, distName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []string{}
	for rows.Next() {
		var digest string
		if err := rows.Scan(&digest); err != nil {
			return nil, err
		}
		result = append(result, digest)
	}
	return result, rows.Err()
}

func (s *Store) packageDists(ctx context.Context, digest string, built bool) ([]string, error) {
	table := "memberships"
	if built {
		table = "built_memberships"
	}
	rows, err := s.db.QueryContext(ctx, `SELECT dist_name FROM `+table+` WHERE package_sha256 = ? ORDER BY dist_name`, digest)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		result = append(result, name)
	}
	return result, rows.Err()
}

func unreferencedPendingTx(ctx context.Context, tx *sql.Tx) ([]PackageObject, error) {
	rows, err := tx.QueryContext(ctx, packageObjectSelect+`
WHERE storage = 'pending'
  AND NOT EXISTS (SELECT 1 FROM memberships AS m WHERE m.package_sha256 = package_objects.sha256)
ORDER BY sha256`)
	if err != nil {
		return nil, fmt.Errorf("list unreferenced pending objects: %w", err)
	}
	defer rows.Close()
	result := []PackageObject{}
	for rows.Next() {
		object, err := scanPackageObject(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, object)
	}
	return result, rows.Err()
}

func validatePackageObject(object PackageObject) error {
	if !validSHA256Text(object.SHA256) {
		return errors.New("invalid sha256")
	}
	if object.PayloadSHA256 != "" && !validSHA256Text(object.PayloadSHA256) {
		return errors.New("invalid signature-neutral payload sha256")
	}
	if object.Format != "rpm" && object.Format != "deb" {
		return fmt.Errorf("invalid format %q", object.Format)
	}
	for label, value := range map[string]string{"coordinate": object.Coordinate, "name": object.Name, "source": object.Source, "version": object.Version, "filename": object.Filename} {
		if value == "" || strings.TrimSpace(value) != value || strings.IndexFunc(value, func(r rune) bool { return r == 0 || r < 0x20 || r == 0x7f }) >= 0 {
			return fmt.Errorf("invalid %s", label)
		}
	}
	if path.Base(object.Filename) != object.Filename || strings.Contains(object.Filename, "\\") {
		return fmt.Errorf("unsafe filename %q", object.Filename)
	}
	if object.PoolPath == "" || path.Clean(object.PoolPath) != object.PoolPath || !strings.HasPrefix(object.PoolPath, "pool/") || path.Base(object.PoolPath) != object.Filename || strings.ContainsAny(object.PoolPath, "\\\x00\r\n\t") {
		return fmt.Errorf("unsafe pool path %q", object.PoolPath)
	}
	wantPoolPath, err := canonicalPackagePoolPath(object.Source, object.Filename)
	if err != nil || object.PoolPath != wantPoolPath {
		return fmt.Errorf("unsafe or non-canonical pool path %q", object.PoolPath)
	}
	if object.Size < 0 || object.CreatedRevision < 0 {
		return errors.New("negative package size or revision")
	}
	if object.Storage != "pending" && object.Storage != "pool" {
		return fmt.Errorf("invalid storage %q", object.Storage)
	}
	validKind := map[string]bool{"main": true, "debuginfo": true, "debugsource": true, "llvmjit": true, "dbgsym": true, "dbg": true}
	if !validKind[object.Kind] {
		return fmt.Errorf("invalid kind %q", object.Kind)
	}
	switch object.Format {
	case "rpm":
		if object.Architecture == "noarch" && object.CanonicalArch != "neutral" || object.Architecture == "x86_64" && object.CanonicalArch != "x86_64" || object.Architecture == "aarch64" && object.CanonicalArch != "aarch64" || object.Architecture != "noarch" && object.Architecture != "x86_64" && object.Architecture != "aarch64" {
			return fmt.Errorf("invalid RPM architecture mapping %q/%q", object.Architecture, object.CanonicalArch)
		}
		if object.SignatureKey != "" && !validSignatureIdentity(object.SignatureKey) {
			return fmt.Errorf("invalid RPM signature identity %q", object.SignatureKey)
		}
	case "deb":
		if object.Architecture == "all" && object.CanonicalArch != "neutral" || object.Architecture == "amd64" && object.CanonicalArch != "x86_64" || object.Architecture == "arm64" && object.CanonicalArch != "aarch64" || object.Architecture != "all" && object.Architecture != "amd64" && object.Architecture != "arm64" {
			return fmt.Errorf("invalid DEB architecture mapping %q/%q", object.Architecture, object.CanonicalArch)
		}
		if object.SignatureKey != "" {
			return errors.New("DEB package object has an unexpected signature identity")
		}
	}
	return nil
}

// canonicalPackagePoolPath mirrors the public Managed path contract at the
// persistence boundary.  Keeping this check in state means forged SQLite rows
// cannot bypass the renderer's portable lower-case shard invariant.
func canonicalPackagePoolPath(source, filename string) (string, error) {
	if !safePackagePathComponent(source) || !safePackagePathComponent(filename) {
		return "", errors.New("unsafe package path component")
	}
	prefix := source[:1]
	if strings.HasPrefix(source, "lib") {
		if len(source) < 4 {
			prefix = source
		} else {
			prefix = source[:4]
		}
	}
	return path.Join("pool", strings.ToLower(prefix), source, filename), nil
}

func safePackagePathComponent(value string) bool {
	if value == "" || value == "." || value == ".." || path.Base(value) != value {
		return false
	}
	for index := 0; index < len(value); index++ {
		c := value[index]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		switch c {
		case '.', '-', '_', '+', '~', '^', ':', '%':
			continue
		default:
			return false
		}
	}
	return true
}

func validSignatureIdentity(value string) bool {
	if len(value) != 16 && len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !strings.ContainsRune("0123456789ABCDEF", r) {
			return false
		}
	}
	return true
}

func validSHA256Text(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

func sameImmutablePackageObject(left, right PackageObject) bool {
	return left.SHA256 == right.SHA256 && left.Format == right.Format && left.Coordinate == right.Coordinate &&
		left.Architecture == right.Architecture && left.CanonicalArch == right.CanonicalArch &&
		left.PoolPath == right.PoolPath && left.Filename == right.Filename && left.Size == right.Size &&
		left.Name == right.Name && left.Source == right.Source && left.Version == right.Version &&
		left.Epoch == right.Epoch && left.Release == right.Release && left.Kind == right.Kind &&
		left.PayloadSHA256 == right.PayloadSHA256 && left.SignatureKey == right.SignatureKey
}

func sameStrings(left, right []string) bool {
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
