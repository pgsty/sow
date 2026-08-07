package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"sort"
)

// PublicationRootRequirement is the private state snapshot against which a
// publication subsystem attests completeness before local GC can detach the
// last physical payload copy.
type PublicationRootRequirement struct {
	HasEvidence      bool
	StateComplete    bool
	EvidenceIdentity string
	MinimumRoots     []GenerationFile
}

// PublicationRootRequirement returns a deterministic identity for all
// publication evidence and the payload roots already provable from SQLite.
// Bindings alone count as evidence: an empty provider response is still an
// assertion which must be explicit and bound to this state snapshot.
func (s *Store) PublicationRootRequirement(ctx context.Context) (PublicationRootRequirement, error) {
	if ctx == nil {
		return PublicationRootRequirement{}, errors.New("nil publication root context")
	}
	var evidenceCount int
	if err := s.db.QueryRowContext(ctx, `SELECT
 (SELECT count(*) FROM publication_target_bindings) +
	 (SELECT count(*) FROM publication_attempts) +
	 (SELECT count(*) FROM publication_checkpoints) +
	 (SELECT count(*) FROM publication_grace_records) +
	 (SELECT count(*) FROM publication_candidate_reports) +
	 (SELECT count(*) FROM publication_abandoned_objects) +
	 (SELECT count(*) FROM publication_deletion_receipts)`).Scan(&evidenceCount); err != nil {
		return PublicationRootRequirement{}, err
	}
	if evidenceCount == 0 {
		return PublicationRootRequirement{StateComplete: true, MinimumRoots: []GenerationFile{}}, nil
	}
	result := PublicationRootRequirement{HasEvidence: true, StateComplete: true, MinimumRoots: []GenerationFile{}}
	h := sha256.New()
	queries := []struct{ label, query string }{
		{"bindings", `SELECT target_identity, target_storage_id, repository_id, target_name, provider, endpoint, region, bucket, prefix, public_endpoint, max_cache_ttl_ns, config_identity FROM publication_target_bindings ORDER BY target_identity`},
		{"heads", `SELECT target_identity, COALESCE(checkpoint_identity, ''), generation, COALESCE(manifest_sha256, ''), revision FROM publication_target_heads ORDER BY target_identity`},
		{"attempts", `SELECT attempt_identity, repository_id, target_identity, COALESCE(base_checkpoint, ''), target_generation, manifest_sha256, plan_sha256, phase, commit_intent FROM publication_attempts ORDER BY attempt_identity`},
		{"attempt_views", `SELECT attempt_identity, sequence, view_id, pointer_path, COALESCE(old_identity, ''), new_identity, state FROM publication_attempt_views ORDER BY attempt_identity, view_id, pointer_path`},
		{"abandoned_objects", `SELECT attempt_identity, path, phase, size, sha256, remote_identity FROM publication_abandoned_objects ORDER BY attempt_identity, path`},
		{"checkpoints", `SELECT checkpoint_identity, repository_id, target_identity, attempt_identity, generation, manifest_sha256, inventory_identity, inventory_complete, applied_at FROM publication_checkpoints ORDER BY checkpoint_identity`},
		{"checkpoint_views", `SELECT checkpoint_identity, sequence, view_id, pointer_path, remote_identity FROM publication_checkpoint_views ORDER BY checkpoint_identity, view_id, pointer_path`},
		{"inventory", `SELECT checkpoint_identity, path, phase, size, sha256, remote_identity FROM publication_inventory ORDER BY checkpoint_identity, path`},
		{"grace", `SELECT grace_identity, target_identity, checkpoint_identity, verified_at, not_before, cache_policy_identity, state FROM publication_grace_records ORDER BY grace_identity`},
		{"reports", `SELECT report_identity, target_identity, checkpoint_identity, inventory_identity, mode, created_at FROM publication_candidate_reports ORDER BY report_identity`},
		{"candidates", `SELECT report_identity, sequence, path, phase, size, sha256, remote_identity FROM publication_candidates ORDER BY report_identity, path`},
		{"deletion_receipts", `SELECT receipt_identity, report_identity, path, phase, size, sha256, remote_identity, storage_absent, public_absent, observed_at FROM publication_deletion_receipts ORDER BY report_identity, path`},
	}
	for _, query := range queries {
		if err := hashPublicationRows(ctx, h, query.label, s.db, query.query); err != nil {
			return PublicationRootRequirement{}, err
		}
	}
	result.EvidenceIdentity = hex.EncodeToString(h.Sum(nil))

	var bindings, heads int
	if err := s.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM publication_target_bindings), (SELECT count(*) FROM publication_target_heads)`).Scan(&bindings, &heads); err != nil {
		return PublicationRootRequirement{}, err
	}
	if bindings != heads {
		result.StateComplete = false
	}
	var incompleteCheckpoints int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM publication_checkpoints WHERE inventory_complete != 1`).Scan(&incompleteCheckpoints); err != nil {
		return PublicationRootRequirement{}, err
	}
	if incompleteCheckpoints != 0 {
		result.StateComplete = false
	}
	if err := s.validatePublicationEvidenceForGC(ctx); err != nil {
		return PublicationRootRequirement{}, err
	}
	roots := make(map[string]GenerationFile)
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT target_generation FROM publication_attempts WHERE phase NOT IN ('done', 'abandoned') ORDER BY target_generation`)
	if err != nil {
		return PublicationRootRequirement{}, err
	}
	generations := []GenerationID{}
	for rows.Next() {
		var generation GenerationID
		if err := rows.Scan(&generation); err != nil {
			rows.Close()
			return PublicationRootRequirement{}, err
		}
		generations = append(generations, generation)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return PublicationRootRequirement{}, err
	}
	for _, generation := range generations {
		manifest, err := s.GenerationManifest(ctx, generation)
		if err != nil {
			result.StateComplete = false
			continue
		}
		for _, file := range manifest {
			if file.Phase == "payload" {
				if err := addPublicationRoot(roots, file); err != nil {
					return PublicationRootRequirement{}, err
				}
			}
		}
	}

	checkpointRows, err := s.db.QueryContext(ctx, `SELECT DISTINCT c.checkpoint_identity, c.inventory_complete
FROM publication_checkpoints AS c
WHERE EXISTS (SELECT 1 FROM publication_target_heads AS h WHERE h.checkpoint_identity = c.checkpoint_identity)
   OR EXISTS (SELECT 1 FROM publication_grace_records AS g WHERE g.checkpoint_identity = c.checkpoint_identity)
   OR EXISTS (SELECT 1 FROM publication_candidate_reports AS r WHERE r.checkpoint_identity = c.checkpoint_identity)
	   OR EXISTS (SELECT 1 FROM publication_attempts AS a WHERE a.phase NOT IN ('done', 'abandoned') AND a.base_checkpoint = c.checkpoint_identity)
ORDER BY c.checkpoint_identity`)
	if err != nil {
		return PublicationRootRequirement{}, err
	}
	type checkpointEvidence struct {
		identity string
		complete bool
	}
	checkpoints := []checkpointEvidence{}
	for checkpointRows.Next() {
		var entry checkpointEvidence
		if err := checkpointRows.Scan(&entry.identity, &entry.complete); err != nil {
			checkpointRows.Close()
			return PublicationRootRequirement{}, err
		}
		checkpoints = append(checkpoints, entry)
	}
	if err := errors.Join(checkpointRows.Err(), checkpointRows.Close()); err != nil {
		return PublicationRootRequirement{}, err
	}
	for _, checkpoint := range checkpoints {
		if !checkpoint.complete {
			result.StateComplete = false
		}
	}

	// Until expiry has been acknowledged with terminal retention/deletion
	// evidence, every locally-addressable payload observed in the applied
	// checkpoint inventory remains a GC root. An applied checkpoint is also
	// protected during the small atomicity window before its grace row exists.
	inventoryRows, err := s.db.QueryContext(ctx, `SELECT DISTINCT i.path, i.size, i.sha256
FROM publication_inventory AS i
JOIN publication_checkpoints AS c ON c.checkpoint_identity = i.checkpoint_identity
JOIN publication_attempts AS a ON a.attempt_identity = c.attempt_identity
LEFT JOIN publication_grace_records AS g ON g.checkpoint_identity = c.checkpoint_identity
WHERE i.phase = 'payload'
	  AND c.inventory_complete = 1
	  AND ((a.phase = 'applied' AND g.grace_identity IS NULL)
	       OR g.state = 'grace')
	ORDER BY i.path`)
	if err != nil {
		return PublicationRootRequirement{}, err
	}
	for inventoryRows.Next() {
		var root GenerationFile
		root.Phase = "payload"
		if err := inventoryRows.Scan(&root.Path, &root.Size, &root.SHA256); err != nil {
			inventoryRows.Close()
			return PublicationRootRequirement{}, err
		}
		if err := addPublicationRoot(roots, root); err != nil {
			inventoryRows.Close()
			return PublicationRootRequirement{}, err
		}
	}
	if err := errors.Join(inventoryRows.Err(), inventoryRows.Close()); err != nil {
		return PublicationRootRequirement{}, err
	}
	for _, root := range roots {
		result.MinimumRoots = append(result.MinimumRoots, root)
	}
	sort.Slice(result.MinimumRoots, func(i, j int) bool { return result.MinimumRoots[i].Path < result.MinimumRoots[j].Path })
	return result, nil
}

func (s *Store) validatePublicationEvidenceForGC(ctx context.Context) error {
	type validationSet struct {
		query string
		check func(string) error
	}
	sets := []validationSet{
		{`SELECT target_identity FROM publication_target_bindings ORDER BY target_identity`, func(identity string) error {
			_, err := s.GetPublicationTarget(ctx, identity)
			return err
		}},
		{`SELECT attempt_identity FROM publication_attempts ORDER BY attempt_identity`, func(identity string) error {
			_, err := s.GetPublicationAttempt(ctx, identity)
			return err
		}},
		{`SELECT checkpoint_identity FROM publication_checkpoints WHERE inventory_complete = 1 ORDER BY checkpoint_identity`, func(identity string) error {
			_, err := s.GetAppliedCheckpoint(ctx, identity)
			return err
		}},
		{`SELECT checkpoint_identity FROM publication_grace_records ORDER BY checkpoint_identity`, func(identity string) error {
			_, err := s.GetGraceRecord(ctx, identity)
			return err
		}},
		{`SELECT checkpoint_identity FROM publication_candidate_reports ORDER BY checkpoint_identity`, func(identity string) error {
			_, err := s.GetPublicationCandidateReport(ctx, identity)
			return err
		}},
	}
	for _, set := range sets {
		rows, err := s.db.QueryContext(ctx, set.query)
		if err != nil {
			return err
		}
		identities := []string{}
		for rows.Next() {
			var identity string
			if err := rows.Scan(&identity); err != nil {
				rows.Close()
				return err
			}
			identities = append(identities, identity)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return err
		}
		for _, identity := range identities {
			if err := set.check(identity); err != nil {
				return fmt.Errorf("%w: publication GC evidence is corrupt: %v", ErrConflict, err)
			}
		}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT report_identity, path FROM publication_deletion_receipts ORDER BY report_identity, path`)
	if err != nil {
		return err
	}
	type receiptKey struct{ report, path string }
	receipts := []receiptKey{}
	for rows.Next() {
		var key receiptKey
		if err := rows.Scan(&key.report, &key.path); err != nil {
			rows.Close()
			return err
		}
		receipts = append(receipts, key)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}
	for _, key := range receipts {
		if _, err := s.GetPublicationDeletionReceipt(ctx, key.report, key.path); err != nil {
			return fmt.Errorf("%w: publication GC deletion evidence is corrupt: %v", ErrConflict, err)
		}
	}
	return nil
}

func addPublicationRoot(roots map[string]GenerationFile, file GenerationFile) error {
	if !validPublicationPath(file.Path) || file.Phase != "payload" || file.Size < 0 || !validSHA256Text(file.SHA256) {
		return fmt.Errorf("%w: invalid publication payload root", ErrSchema)
	}
	if existing, ok := roots[file.Path]; ok && existing != file {
		return fmt.Errorf("%w: publication evidence conflicts for payload %q", ErrConflict, file.Path)
	}
	roots[file.Path] = file
	return nil
}

func hashPublicationRows(ctx context.Context, h hash.Hash, label string, db *sql.DB, query string) error {
	writeHashField(h, []byte(label))
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return err
	}
	for rows.Next() {
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for index := range values {
			pointers[index] = &values[index]
		}
		if err := rows.Scan(pointers...); err != nil {
			return err
		}
		for _, value := range values {
			switch typed := value.(type) {
			case nil:
				writeHashField(h, nil)
			case int64:
				var buffer [8]byte
				binary.BigEndian.PutUint64(buffer[:], uint64(typed))
				writeHashField(h, buffer[:])
			case string:
				writeHashField(h, []byte(typed))
			case []byte:
				writeHashField(h, typed)
			default:
				return fmt.Errorf("unsupported publication evidence column %T", value)
			}
		}
	}
	return rows.Err()
}

func writeHashField(h hash.Hash, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	h.Write(size[:])
	h.Write(value)
}
