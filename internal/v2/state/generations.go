package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

type GenerationFile struct {
	Path   string `json:"path"`
	Phase  string `json:"phase"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type FileChange struct {
	Operation string `json:"op"`
	Path      string `json:"path"`
	Phase     string `json:"phase"`
	Size      int64  `json:"size,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
}

// MarshalJSON keeps zero-byte add/update entries lossless on the public wire
// while preserving the absence of size for deletions, whose target no longer
// exists. A scalar `omitempty` would incorrectly erase a legitimate size 0.
func (change FileChange) MarshalJSON() ([]byte, error) {
	type wireChange struct {
		Operation string `json:"op"`
		Path      string `json:"path"`
		Phase     string `json:"phase"`
		Size      *int64 `json:"size,omitempty"`
		SHA256    string `json:"sha256,omitempty"`
	}
	var size *int64
	if change.Operation != "delete" {
		value := change.Size
		size = &value
	}
	return json.Marshal(wireChange{Operation: change.Operation, Path: change.Path, Phase: change.Phase, Size: size, SHA256: change.SHA256})
}

type DistBuild struct {
	Name                      string
	Format                    string
	EffectiveConfigSHA256     string
	Architectures             []Architecture
	MetadataSignerFingerprint string
	MetadataSignerPublicKey   []byte
	MetadataSignerIdentity    string
	EffectiveSigningJSON      string
}

type FinalizeBuildInput struct {
	OperationID      string
	Generation       GenerationID
	Dists            []DistBuild
	Pooled           []string
	RPMSigningKeys   []RPMSigningKey
	Manifest         []GenerationFile
	Changes          []FileChange
	RendererIdentity string
}

type GenerationInfo struct {
	Generation         GenerationID `json:"generation"`
	PreviousGeneration GenerationID `json:"previous_generation"`
	OperationID        string       `json:"operation_id"`
	ManifestSHA256     string       `json:"manifest_sha256"`
	RendererIdentity   string       `json:"renderer_identity"`
	CreatedAt          time.Time    `json:"created_at"`
}

type GenerationViewSigner struct {
	Generation       GenerationID `json:"generation"`
	ViewID           string       `json:"view_id"`
	SignerIdentity   string       `json:"signer_identity"`
	TrustedPublicKey []byte       `json:"-"`
}

func (s *Store) GenerationViewSigner(ctx context.Context, generation GenerationID, viewID string) (GenerationViewSigner, error) {
	if generation == 0 || path.Clean(viewID) != viewID || !strings.HasPrefix(viewID, "dists/") {
		return GenerationViewSigner{}, errors.New("invalid Generation view signer lookup")
	}
	var record GenerationViewSigner
	var trusted []byte
	err := s.db.QueryRowContext(ctx, `SELECT generation, view_id, signer_identity, COALESCE(trusted_public_key, X'') FROM generation_view_signers WHERE generation = ? AND view_id = ?`, generation, viewID).Scan(
		&record.Generation, &record.ViewID, &record.SignerIdentity, &trusted,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return GenerationViewSigner{}, fmt.Errorf("%w: Generation %s view signer %q", ErrNotFound, generation, viewID)
	}
	if err != nil {
		return GenerationViewSigner{}, err
	}
	if record.SignerIdentity == "none" {
		if len(trusted) != 0 {
			return GenerationViewSigner{}, fmt.Errorf("%w: unsigned Generation view has a trusted key", ErrSchema)
		}
	} else if !validSHA256Text(record.SignerIdentity) || len(trusted) == 0 {
		return GenerationViewSigner{}, fmt.Errorf("%w: invalid Generation view signer record", ErrSchema)
	}
	record.TrustedPublicKey = trusted
	return record, nil
}

// ManifestBytes returns the exact canonical manifest wire shared by the
// Generation digest and retained state.
func ManifestBytes(input []GenerationFile) ([]byte, string, error) {
	return ManifestBytesForLayout(input, LayoutSinglePayloadV1)
}

func ManifestBytesForLayout(input []GenerationFile, layout string) ([]byte, string, error) {
	files, digest, err := normalizeManifestForLayout(input, layout)
	if err != nil {
		return nil, "", err
	}
	var output bytes.Buffer
	for _, file := range files {
		fmt.Fprintf(&output, "%s %d %s %s\n", file.SHA256, file.Size, file.Phase, file.Path)
	}
	return output.Bytes(), digest, nil
}

// GenerationRetentionIdentity returns the immutable renderer and common RPM
// view signer identity used by retained/export wire.  A Generation with
// heterogeneous RPM signing identities cannot be represented by retained/v1
// and is rejected rather than silently collapsed.
func (s *Store) GenerationRetentionIdentity(ctx context.Context, generation GenerationID) (string, string, error) {
	info, err := s.GetGeneration(ctx, generation)
	if err != nil {
		return "", "", err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT signer_identity FROM generation_view_signers WHERE generation = ? ORDER BY signer_identity`, generation)
	if err != nil {
		return "", "", err
	}
	defer rows.Close()
	identities := []string{}
	for rows.Next() {
		var identity string
		if err := rows.Scan(&identity); err != nil {
			return "", "", err
		}
		identities = append(identities, identity)
	}
	if err := rows.Err(); err != nil {
		return "", "", err
	}
	if len(identities) > 1 {
		return "", "", fmt.Errorf("%w: Generation %s has heterogeneous RPM signer identities", ErrConflict, generation)
	}
	signer := "none"
	if len(identities) == 1 {
		signer = identities[0]
	}
	return info.RendererIdentity, signer, nil
}

// BootstrapLegacyGeneration anchors a migrated V1 repository whose public
// tree and built_generation predate the physical Generation ledger. It has no
// filesystem side effect and records its complete audit operation atomically,
// so a process stop can observe either no bootstrap or the complete baseline.
func (s *Store) BootstrapLegacyGeneration(ctx context.Context, operationID string, generation GenerationID, inputManifest []GenerationFile) error {
	if !operationIDPattern.MatchString(operationID) || generation < 1 {
		return errors.New("invalid legacy generation bootstrap")
	}
	identity, err := s.RepositoryIdentity(ctx)
	if err != nil {
		return err
	}
	layout := identity.LayoutVersion
	if layout == LayoutC2ToSingleV1 {
		layout = LayoutC2V1
	}
	manifest, manifestSHA, err := normalizeManifestForLayout(inputManifest, layout)
	if err != nil {
		return err
	}
	changes := DiffManifests(nil, manifest)
	if err := validateChangesForLayout(changes, layout); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin legacy generation bootstrap: %w", err)
	}
	defer tx.Rollback()
	var current GenerationID
	var generations, pending int64
	if err := tx.QueryRowContext(ctx, `SELECT built_generation FROM repository_state WHERE singleton = 1`).Scan(&current); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM generations`).Scan(&generations); err != nil {
		return err
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM operations WHERE state NOT IN ('done', 'done_dirty', 'rolled_back', 'failed')`).Scan(&pending); err != nil {
		return err
	}
	if current != generation || generations != 0 || pending != 0 {
		return fmt.Errorf("%w: legacy generation bootstrap requires one settled unanchored current generation", ErrConflict)
	}
	now := nowText()
	payload := fmt.Sprintf(`{"generation":%q,"source":"schema-v1"}`, generation.String())
	if _, err := tx.ExecContext(ctx, `INSERT INTO operations(id, kind, state, payload_json, result_json, error_class, error_message, created_at, updated_at) VALUES (?, 'generation.bootstrap', 'done', ?, '{"bootstrapped":true}', NULL, NULL, ?, ?)`, operationID, payload, now, now); err != nil {
		return fmt.Errorf("record legacy generation bootstrap: %w", err)
	}
	for sequence, event := range []OperationState{OperationPlanned, OperationBuilt, OperationDone} {
		if _, err := tx.ExecContext(ctx, `INSERT INTO operation_events(operation_id, sequence, state, detail_json, occurred_at) VALUES (?, ?, ?, '{}', ?)`, operationID, sequence, string(event), now); err != nil {
			return fmt.Errorf("record legacy generation bootstrap event: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO generations(generation, previous_generation, operation_id, manifest_sha256, renderer_identity, created_at) VALUES (?, ?, ?, ?, ?, ?)`, generation, ZeroGeneration, operationID, manifestSHA, strings.Repeat("0", 64), now); err != nil {
		return fmt.Errorf("anchor legacy generation %d: %w", generation, err)
	}
	for _, file := range manifest {
		if _, err := tx.ExecContext(ctx, `INSERT INTO generation_files(generation, path, phase, size, sha256) VALUES (?, ?, ?, ?, ?)`, generation, file.Path, file.Phase, file.Size, file.SHA256); err != nil {
			return fmt.Errorf("record legacy generation file %q: %w", file.Path, err)
		}
	}
	for sequence, change := range changes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO operation_files(operation_id, sequence, action, phase, path, size, sha256) VALUES (?, ?, ?, ?, ?, ?, ?)`, operationID, sequence, change.Operation, change.Phase, change.Path, change.Size, change.SHA256); err != nil {
			return fmt.Errorf("record legacy generation file action: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit legacy generation bootstrap: %w", err)
	}
	return s.Checkpoint(ctx)
}

func (s *Store) GetGeneration(ctx context.Context, generation GenerationID) (GenerationInfo, error) {
	var info GenerationInfo
	var created string
	err := s.db.QueryRowContext(ctx, `SELECT generation, previous_generation, operation_id, manifest_sha256, renderer_identity, created_at FROM generations WHERE generation = ?`, generation).Scan(
		&info.Generation, &info.PreviousGeneration, &info.OperationID, &info.ManifestSHA256, &info.RendererIdentity, &created,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return GenerationInfo{}, fmt.Errorf("%w: generation %d", ErrNotFound, generation)
	}
	if err != nil {
		return GenerationInfo{}, err
	}
	info.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return GenerationInfo{}, err
	}
	return info, nil
}

func (s *Store) GenerationChanges(ctx context.Context, generation GenerationID) ([]FileChange, error) {
	info, err := s.GetGeneration(ctx, generation)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT action, path, phase, size, sha256 FROM operation_files WHERE operation_id = ? ORDER BY sequence`, info.OperationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	changes := []FileChange{}
	for rows.Next() {
		var change FileChange
		var size sql.NullInt64
		var digest sql.NullString
		if err := rows.Scan(&change.Operation, &change.Path, &change.Phase, &size, &digest); err != nil {
			return nil, err
		}
		change.Size, change.SHA256 = size.Int64, digest.String
		changes = append(changes, change)
	}
	return changes, rows.Err()
}

func (s *Store) GenerationManifest(ctx context.Context, generation GenerationID) ([]GenerationFile, error) {
	if generation == 0 {
		return []GenerationFile{}, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT path, phase, size, sha256 FROM generation_files WHERE generation = ? ORDER BY path`, generation)
	if err != nil {
		return nil, fmt.Errorf("read generation %d manifest: %w", generation, err)
	}
	defer rows.Close()
	files := []GenerationFile{}
	for rows.Next() {
		var file GenerationFile
		if err := rows.Scan(&file.Path, &file.Phase, &file.Size, &file.SHA256); err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(files) == 0 {
		var exists int
		if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM generations WHERE generation = ?)`, generation).Scan(&exists); err != nil {
			return nil, err
		}
		if exists == 0 {
			return nil, fmt.Errorf("%w: generation %d", ErrNotFound, generation)
		}
	}
	return files, nil
}

// ValidateGenerationLedger verifies the retained chain independently of the
// public filesystem: predecessor links, manifest hashes, terminal operations,
// and every phase-ordered physical delta must agree exactly.
func (s *Store) ValidateGenerationLedger(ctx context.Context) error {
	identity := RepositoryIdentity{LayoutVersion: LayoutC2V1}
	manifestLayout := LayoutC2V1
	if s.SchemaVersion() != 6 {
		var err error
		identity, err = s.RepositoryIdentity(ctx)
		if err != nil {
			return err
		}
		manifestLayout = identity.LayoutVersion
		if manifestLayout == LayoutC2ToSingleV1 {
			manifestLayout = LayoutC2V1
		}
	}
	var current GenerationID
	if err := s.db.QueryRowContext(ctx, `SELECT built_generation FROM repository_state WHERE singleton = 1`).Scan(&current); err != nil {
		return err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT generation, previous_generation, operation_id, manifest_sha256 FROM generations ORDER BY generation`)
	if err != nil {
		return err
	}
	infos := []GenerationInfo{}
	for rows.Next() {
		var info GenerationInfo
		if err := rows.Scan(&info.Generation, &info.PreviousGeneration, &info.OperationID, &info.ManifestSHA256); err != nil {
			rows.Close()
			return err
		}
		infos = append(infos, info)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}
	if len(infos) == 0 {
		if current == 0 {
			return nil
		}
		return fmt.Errorf("%w: built generation %d predates the retained ledger", ErrNotFound, current)
	}
	if current != infos[len(infos)-1].Generation {
		return fmt.Errorf("%w: current generation %d differs from ledger head %d", ErrConflict, current, infos[len(infos)-1].Generation)
	}
	previousGeneration := GenerationID(0)
	previousManifest := []GenerationFile{}
	seenOperations := make(map[string]struct{}, len(infos))
	transitionSeen := false
	for index, info := range infos {
		follows := true
		if index > 0 {
			expected, nextErr := previousGeneration.Next()
			follows = nextErr == nil && info.Generation == expected
		}
		if info.PreviousGeneration != previousGeneration || !follows {
			return fmt.Errorf("%w: generation %d does not follow retained generation %d", ErrConflict, info.Generation, previousGeneration)
		}
		if _, duplicate := seenOperations[info.OperationID]; duplicate {
			return fmt.Errorf("%w: operation %s owns more than one Generation", ErrConflict, info.OperationID)
		}
		seenOperations[info.OperationID] = struct{}{}
		var operationKind, operationState string
		if err := s.db.QueryRowContext(ctx, `SELECT kind, state FROM operations WHERE id = ?`, info.OperationID).Scan(&operationKind, &operationState); err != nil {
			return fmt.Errorf("%w: generation %d operation is unavailable", ErrConflict, info.Generation)
		}
		if OperationState(operationState) != OperationDone {
			return fmt.Errorf("%w: generation %d operation is %s", ErrConflict, info.Generation, operationState)
		}
		generationLayout := manifestLayout
		if identity.LayoutVersion == LayoutSinglePayloadV1 && identity.TransitionReceiptSHA256 != "" && !transitionSeen {
			if operationKind == "layout.migrate" {
				transitionSeen = true
				generationLayout = LayoutSinglePayloadV1
			} else {
				generationLayout = LayoutC2V1
			}
		} else if operationKind == "layout.migrate" {
			return fmt.Errorf("%w: unexpected or duplicate layout migration generation %d", ErrConflict, info.Generation)
		}
		manifest, err := s.GenerationManifest(ctx, info.Generation)
		if err != nil {
			return err
		}
		normalized, digest, err := normalizeManifestForLayout(manifest, generationLayout)
		if err != nil || digest != info.ManifestSHA256 {
			return fmt.Errorf("%w: generation %d manifest hash differs", ErrConflict, info.Generation)
		}
		changes, err := s.GenerationChanges(ctx, info.Generation)
		if err != nil {
			return err
		}
		if err := validateChangesForLayout(changes, generationLayout); err != nil || !equalFileChanges(changes, DiffManifests(previousManifest, normalized)) {
			return fmt.Errorf("%w: generation %d Changeset differs from its manifests", ErrConflict, info.Generation)
		}
		previousGeneration, previousManifest = info.Generation, normalized
	}
	if identity.LayoutVersion == LayoutSinglePayloadV1 && identity.TransitionReceiptSHA256 != "" && !transitionSeen {
		return fmt.Errorf("%w: terminal transition receipt has no layout migration Generation", ErrConflict)
	}
	return nil
}

// normalizeLegacyRetainedGenerationLedgerTx repairs the one known truncated
// ledger shape emitted by early schema-v2 builds: the first retained
// Generation still names a predecessor whose manifest was not retained.  The
// migration is deliberately strict.  It proves every retained manifest,
// terminal operation, successor link, and later Changeset before rebasing the
// first retained Generation onto 0 and replacing only that operation's delta
// with a complete baseline.  Arbitrary corrupt ledgers are never repaired.
func normalizeLegacyRetainedGenerationLedgerTx(ctx context.Context, tx *sql.Tx) error {
	var current GenerationID
	if err := tx.QueryRowContext(ctx, `SELECT built_generation FROM repository_state WHERE singleton = 1`).Scan(&current); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT generation, previous_generation, operation_id, manifest_sha256 FROM generations ORDER BY generation`)
	if err != nil {
		return err
	}
	infos := []GenerationInfo{}
	for rows.Next() {
		var info GenerationInfo
		if err := rows.Scan(&info.Generation, &info.PreviousGeneration, &info.OperationID, &info.ManifestSHA256); err != nil {
			rows.Close()
			return err
		}
		infos = append(infos, info)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}
	if len(infos) == 0 {
		// A pre-ledger repository is anchored later from its validated public
		// tree by BootstrapLegacyGeneration.  There is nothing to rebase here.
		return nil
	}
	if current != infos[len(infos)-1].Generation {
		return fmt.Errorf("%w: current generation %d differs from legacy ledger head %d", ErrConflict, current, infos[len(infos)-1].Generation)
	}
	reanchor := infos[0].PreviousGeneration > 0
	if reanchor {
		expected, nextErr := infos[0].PreviousGeneration.Next()
		if nextErr != nil || infos[0].Generation != expected {
			return fmt.Errorf("%w: first retained generation %d does not follow omitted predecessor %d", ErrConflict, infos[0].Generation, infos[0].PreviousGeneration)
		}
	}
	previousGeneration := GenerationID(0)
	previousManifest := []GenerationFile{}
	var firstManifest []GenerationFile
	seenOperations := make(map[string]struct{}, len(infos))
	for index, info := range infos {
		if index == 0 {
			if !reanchor && info.PreviousGeneration != 0 {
				return fmt.Errorf("%w: invalid first retained generation predecessor", ErrConflict)
			}
		} else {
			expected, nextErr := previousGeneration.Next()
			if info.PreviousGeneration != previousGeneration || nextErr != nil || info.Generation != expected {
				return fmt.Errorf("%w: generation %d does not follow retained generation %d", ErrConflict, info.Generation, previousGeneration)
			}
		}
		if _, duplicate := seenOperations[info.OperationID]; duplicate {
			return fmt.Errorf("%w: operation %s owns more than one legacy Generation", ErrConflict, info.OperationID)
		}
		seenOperations[info.OperationID] = struct{}{}
		var operationState string
		if err := tx.QueryRowContext(ctx, `SELECT state FROM operations WHERE id = ?`, info.OperationID).Scan(&operationState); err != nil {
			return fmt.Errorf("%w: generation %d operation is unavailable", ErrConflict, info.Generation)
		}
		if OperationState(operationState) != OperationDone {
			return fmt.Errorf("%w: generation %d operation is %s", ErrConflict, info.Generation, operationState)
		}
		manifest, err := generationManifestTx(ctx, tx, info.Generation)
		if err != nil {
			return err
		}
		normalized, digest, err := normalizeManifestForLayout(manifest, LayoutC2V1)
		if err != nil || digest != info.ManifestSHA256 {
			return fmt.Errorf("%w: generation %d manifest hash differs", ErrConflict, info.Generation)
		}
		changes, err := generationChangesTx(ctx, tx, info.OperationID)
		if err != nil {
			return err
		}
		if err := validateChangesForLayout(changes, LayoutC2V1); err != nil {
			return fmt.Errorf("%w: generation %d Changeset is invalid", ErrConflict, info.Generation)
		}
		if index == 0 && reanchor {
			if err := validateTruncatedLegacyChanges(changes, normalized); err != nil {
				return fmt.Errorf("%w: generation %d truncated Changeset is inconsistent: %v", ErrConflict, info.Generation, err)
			}
			firstManifest = append([]GenerationFile(nil), normalized...)
		} else if !equalFileChanges(changes, DiffManifests(previousManifest, normalized)) {
			return fmt.Errorf("%w: generation %d Changeset differs from its manifests", ErrConflict, info.Generation)
		}
		previousGeneration, previousManifest = info.Generation, normalized
	}
	if !reanchor {
		return nil
	}
	first := infos[0]
	if _, err := tx.ExecContext(ctx, `UPDATE generations SET previous_generation = ? WHERE generation = ? AND previous_generation = ?`, ZeroGeneration, first.Generation, first.PreviousGeneration); err != nil {
		return fmt.Errorf("rebase first retained generation: %w", err)
	}
	if err := replaceGenerationChangesTx(ctx, tx, first.OperationID, DiffManifests(nil, firstManifest)); err != nil {
		return fmt.Errorf("replace first retained generation baseline: %w", err)
	}
	return nil
}

func generationChangesTx(ctx context.Context, tx *sql.Tx, operationID string) ([]FileChange, error) {
	rows, err := tx.QueryContext(ctx, `SELECT action, path, phase, size, sha256 FROM operation_files WHERE operation_id = ? ORDER BY sequence`, operationID)
	if err != nil {
		return nil, err
	}
	changes := []FileChange{}
	for rows.Next() {
		var change FileChange
		var size sql.NullInt64
		var digest sql.NullString
		if err := rows.Scan(&change.Operation, &change.Path, &change.Phase, &size, &digest); err != nil {
			rows.Close()
			return nil, err
		}
		change.Size, change.SHA256 = size.Int64, digest.String
		changes = append(changes, change)
	}
	return changes, errors.Join(rows.Err(), rows.Close())
}

func validateTruncatedLegacyChanges(changes []FileChange, target []GenerationFile) error {
	targetByPath := make(map[string]GenerationFile, len(target))
	for _, file := range target {
		targetByPath[file.Path] = file
	}
	seen := make(map[string]struct{}, len(changes))
	canonical := append([]FileChange(nil), changes...)
	rank := map[string]int{"payload": 0, "metadata": 1, "pointer": 2, "delete": 3}
	sort.Slice(canonical, func(i, j int) bool {
		if rank[canonical[i].Phase] != rank[canonical[j].Phase] {
			return rank[canonical[i].Phase] < rank[canonical[j].Phase]
		}
		return canonical[i].Path < canonical[j].Path
	})
	if !equalFileChanges(changes, canonical) {
		return errors.New("Changeset is not in canonical phase/path order")
	}
	for _, change := range changes {
		if change.Path == "" || path.Clean(change.Path) != change.Path || change.Path == "." || strings.ContainsAny(change.Path, "\\\x00\r\n\t") || strings.HasPrefix(change.Path, "/") || strings.HasPrefix(change.Path, "../") {
			return fmt.Errorf("unsafe change path %q", change.Path)
		}
		if _, duplicate := seen[change.Path]; duplicate {
			return fmt.Errorf("duplicate change path %q", change.Path)
		}
		seen[change.Path] = struct{}{}
		file, exists := targetByPath[change.Path]
		if change.Operation == "delete" {
			if exists {
				return fmt.Errorf("deleted path %q exists in target manifest", change.Path)
			}
			continue
		}
		if !exists || change.Phase != file.Phase || change.Size != file.Size || change.SHA256 != file.SHA256 {
			return fmt.Errorf("change path %q differs from target manifest", change.Path)
		}
	}
	return nil
}

func replaceGenerationChangesTx(ctx context.Context, tx *sql.Tx, operationID string, changes []FileChange) error {
	if err := validateChangesForLayout(changes, LayoutC2V1); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM operation_files WHERE operation_id = ?`, operationID); err != nil {
		return err
	}
	for sequence, change := range changes {
		var size, digest any
		if change.Operation != "delete" {
			size, digest = change.Size, change.SHA256
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO operation_files(operation_id, sequence, action, phase, path, size, sha256) VALUES (?, ?, ?, ?, ?, ?, ?)`, operationID, sequence, change.Operation, change.Phase, change.Path, size, digest); err != nil {
			return err
		}
	}
	return nil
}

func DiffManifests(base, target []GenerationFile) []FileChange {
	baseByPath := make(map[string]GenerationFile, len(base))
	targetByPath := make(map[string]GenerationFile, len(target))
	for _, file := range base {
		baseByPath[file.Path] = file
	}
	for _, file := range target {
		targetByPath[file.Path] = file
	}
	changes := []FileChange{}
	for path, file := range targetByPath {
		previous, exists := baseByPath[path]
		operation := "add"
		if exists {
			if previous.SHA256 == file.SHA256 && previous.Size == file.Size && previous.Phase == file.Phase {
				continue
			}
			operation = "update"
		}
		changes = append(changes, FileChange{Operation: operation, Path: path, Phase: file.Phase, Size: file.Size, SHA256: file.SHA256})
	}
	for path := range baseByPath {
		if _, exists := targetByPath[path]; !exists {
			changes = append(changes, FileChange{Operation: "delete", Path: path, Phase: "delete"})
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		rank := map[string]int{"payload": 0, "metadata": 1, "pointer": 2, "delete": 3}
		if rank[changes[i].Phase] != rank[changes[j].Phase] {
			return rank[changes[i].Phase] < rank[changes[j].Phase]
		}
		return changes[i].Path < changes[j].Path
	})
	return changes
}

func recordGenerationTx(ctx context.Context, tx *sql.Tx, operationID string, generation GenerationID, inputManifest []GenerationFile, inputChanges []FileChange, rendererIdentity ...string) error {
	manifest, manifestSHA, err := normalizeManifest(inputManifest)
	if err != nil {
		return err
	}
	changes := append([]FileChange(nil), inputChanges...)
	if err := validateChanges(changes); err != nil {
		return err
	}
	var previous GenerationID
	if err := tx.QueryRowContext(ctx, `SELECT built_generation FROM repository_state WHERE singleton = 1`).Scan(&previous); err != nil {
		return err
	}
	expected, nextErr := previous.Next()
	if nextErr != nil || generation != expected {
		return fmt.Errorf("%w: generation %d does not follow %d", ErrConflict, generation, previous)
	}
	previousManifest, err := generationManifestTx(ctx, tx, previous)
	if err != nil {
		return err
	}
	expectedChanges := DiffManifests(previousManifest, manifest)
	if !equalFileChanges(changes, expectedChanges) {
		return fmt.Errorf("%w: generation %d changes do not equal the manifest delta", ErrConflict, generation)
	}
	renderer := DefaultRendererIdentity
	if len(rendererIdentity) > 1 || len(rendererIdentity) == 1 && rendererIdentity[0] != "" && !validSHA256Text(rendererIdentity[0]) {
		return errors.New("invalid renderer identity")
	}
	if len(rendererIdentity) == 1 && rendererIdentity[0] != "" {
		renderer = rendererIdentity[0]
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO generations(generation, previous_generation, operation_id, manifest_sha256, renderer_identity, created_at) VALUES (?, ?, ?, ?, ?, ?)`, generation, previous, operationID, manifestSHA, renderer, nowText()); err != nil {
		return fmt.Errorf("record generation %d: %w", generation, err)
	}
	for _, file := range manifest {
		if _, err := tx.ExecContext(ctx, `INSERT INTO generation_files(generation, path, phase, size, sha256) VALUES (?, ?, ?, ?, ?)`, generation, file.Path, file.Phase, file.Size, file.SHA256); err != nil {
			return fmt.Errorf("record generation file %q: %w", file.Path, err)
		}
	}
	for sequence, change := range changes {
		var size, digest any
		if change.Operation != "delete" {
			size, digest = change.Size, change.SHA256
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO operation_files(operation_id, sequence, action, phase, path, size, sha256) VALUES (?, ?, ?, ?, ?, ?, ?)`, operationID, sequence, change.Operation, change.Phase, change.Path, size, digest); err != nil {
			return fmt.Errorf("record generation file action: %w", err)
		}
	}
	return nil
}

func generationManifestTx(ctx context.Context, tx *sql.Tx, generation GenerationID) ([]GenerationFile, error) {
	if generation == 0 {
		return []GenerationFile{}, nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT path, phase, size, sha256 FROM generation_files WHERE generation = ? ORDER BY path`, generation)
	if err != nil {
		return nil, fmt.Errorf("read generation %d manifest: %w", generation, err)
	}
	defer rows.Close()
	files := []GenerationFile{}
	for rows.Next() {
		var file GenerationFile
		if err := rows.Scan(&file.Path, &file.Phase, &file.Size, &file.SHA256); err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM generations WHERE generation = ?)`, generation).Scan(&exists); err != nil {
		return nil, err
	}
	if exists == 0 {
		return nil, fmt.Errorf("%w: previous generation %d has no retained manifest", ErrConflict, generation)
	}
	return files, nil
}

func equalFileChanges(left, right []FileChange) bool {
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

func (s *Store) FinalizeBuild(ctx context.Context, input FinalizeBuildInput) error {
	if input.Generation < 1 || len(input.Dists) == 0 {
		return errors.New("invalid build finalization")
	}
	keys, err := normalizeRPMSigningKeys(input.RPMSigningKeys)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin build finalization: %w", err)
	}
	defer tx.Rollback()
	operationState, err := operationStateTx(ctx, tx, input.OperationID)
	if err != nil {
		return err
	}
	if operationState == OperationDone {
		return nil
	}
	if operationState != OperationBuilt {
		return fmt.Errorf("%w: finalize build from %s", ErrTransition, operationState)
	}
	if err := retainRPMSigningKeysTx(ctx, tx, keys); err != nil {
		return fmt.Errorf("retain RPM signing verification keys: %w", err)
	}
	if err := recordGenerationTx(ctx, tx, input.OperationID, input.Generation, input.Manifest, input.Changes, input.RendererIdentity); err != nil {
		return err
	}
	seenDists := make(map[string]struct{}, len(input.Dists))
	for _, dist := range input.Dists {
		if dist.Name == "" || dist.EffectiveConfigSHA256 == "" {
			return errors.New("invalid built dist projection")
		}
		if _, duplicate := seenDists[dist.Name]; duplicate {
			return fmt.Errorf("duplicate built dist %q", dist.Name)
		}
		seenDists[dist.Name] = struct{}{}
		effectiveSigning, err := normalizeEffectiveSigningJSON(dist.EffectiveSigningJSON)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM prior_built_memberships WHERE dist_name = ?`, dist.Name); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO prior_built_memberships(dist_name, package_sha256, generation) SELECT dist_name, package_sha256, generation FROM built_memberships WHERE dist_name = ?`, dist.Name); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM built_memberships WHERE dist_name = ?`, dist.Name); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO built_memberships(dist_name, package_sha256, generation) SELECT dist_name, package_sha256, ? FROM memberships WHERE dist_name = ?`, input.Generation, dist.Name); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE dists SET effective_config_sha256 = ?, built_config_sha256 = ?, built_generation = ?, effective_signing_json = ? WHERE name = ?`, dist.EffectiveConfigSHA256, dist.EffectiveConfigSHA256, input.Generation, effectiveSigning, dist.Name); err != nil {
			return err
		}
		if err := replaceDistMetadataSignerTx(ctx, tx, Dist{Name: dist.Name, MetadataSignerFingerprint: dist.MetadataSignerFingerprint, MetadataSignerPublicKey: dist.MetadataSignerPublicKey}); err != nil {
			return err
		}
		if err := replaceDistArchitecturesTx(ctx, tx, dist.Name, dist.Architectures, input.Generation); err != nil {
			return err
		}
		if dist.Format == "rpm" {
			identity := dist.MetadataSignerIdentity
			var trusted any
			if dist.MetadataSignerFingerprint == "" {
				identity = "none"
			} else {
				if !validSHA256Text(identity) || len(dist.MetadataSignerPublicKey) == 0 {
					return fmt.Errorf("invalid immutable RPM signer identity for Dist %q", dist.Name)
				}
				trusted = dist.MetadataSignerPublicKey
			}
			for _, architecture := range dist.Architectures {
				viewID := path.Join("dists", dist.Name, architecture.Family)
				if _, err := tx.ExecContext(ctx, `INSERT INTO generation_view_signers(generation, view_id, signer_identity, trusted_public_key) VALUES (?, ?, ?, ?)`, input.Generation, viewID, identity, trusted); err != nil {
					return err
				}
			}
		}
	}
	for _, digest := range input.Pooled {
		if !validSHA256Text(digest) {
			return fmt.Errorf("invalid pooled sha256 %q", digest)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE package_objects SET storage = 'pool' WHERE sha256 = ?`, digest); err != nil {
			return err
		}
	}
	status, reason, err := repositoryProjectionStatusTx(ctx, tx)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE repository_state SET built_generation = ?, status = ?, dirty_reason = ? WHERE singleton = 1`, input.Generation, status, reason); err != nil {
		return err
	}
	if err := setOperationStateTx(ctx, tx, input.OperationID, OperationDone, "", ""); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit build finalization: %w", err)
	}
	if err := s.Checkpoint(ctx); err != nil {
		return fmt.Errorf("checkpoint committed build Generation %d: %w", input.Generation, err)
	}
	return nil
}

// FinalizeNoopBuild closes a build whose policy reconciliation changed
// Desired state but whose resulting physical projection is already the current
// Built Generation. Recomputing repository status in the same transaction is
// essential: ApplyDesiredMutation conservatively marks every Desired change
// dirty, even when that change converges back to the existing Built set.
func (s *Store) FinalizeNoopBuild(ctx context.Context, operationID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin no-op build finalization: %w", err)
	}
	defer tx.Rollback()
	operationState, err := operationStateTx(ctx, tx, operationID)
	if err != nil {
		return err
	}
	if operationState == OperationDone {
		return nil
	}
	if operationState != OperationApplied {
		return fmt.Errorf("%w: finalize no-op build from %s", ErrTransition, operationState)
	}
	status, reason, err := repositoryProjectionStatusTx(ctx, tx)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE repository_state SET status = ?, dirty_reason = ? WHERE singleton = 1`, status, reason); err != nil {
		return err
	}
	if err := setOperationStateTx(ctx, tx, operationID, OperationDone, "", ""); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit no-op build finalization: %w", err)
	}
	return s.Checkpoint(ctx)
}

func replaceDistArchitecturesTx(ctx context.Context, tx *sql.Tx, distName string, architectures []Architecture, generation GenerationID) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM dist_architectures WHERE dist_name = ?`, distName); err != nil {
		return err
	}
	seen := map[string]struct{}{}
	for _, architecture := range architectures {
		if _, duplicate := seen[architecture.Family]; duplicate {
			return fmt.Errorf("duplicate architecture %q", architecture.Family)
		}
		seen[architecture.Family] = struct{}{}
		if _, err := tx.ExecContext(ctx, `INSERT INTO dist_architectures(dist_name, family, ecosystem_arch, built_generation) VALUES (?, ?, ?, ?)`, distName, architecture.Family, architecture.EcosystemArch, generation); err != nil {
			return err
		}
	}
	return nil
}

func repositoryProjectionStatusTx(ctx context.Context, tx *sql.Tx) (string, any, error) {
	var dirty int
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(
SELECT 1 FROM dists AS d
WHERE d.effective_config_sha256 != d.built_config_sha256
   OR EXISTS (SELECT package_sha256 FROM memberships WHERE dist_name = d.name
              EXCEPT SELECT package_sha256 FROM built_memberships WHERE dist_name = d.name)
   OR EXISTS (SELECT package_sha256 FROM built_memberships WHERE dist_name = d.name
              EXCEPT SELECT package_sha256 FROM memberships WHERE dist_name = d.name)
)`).Scan(&dirty)
	if err != nil {
		return "", nil, err
	}
	if dirty != 0 {
		return "dirty", "one or more dists differ from their built projections", nil
	}
	return "clean", nil, nil
}

func normalizeManifest(input []GenerationFile) ([]GenerationFile, string, error) {
	return normalizeManifestForLayout(input, LayoutSinglePayloadV1)
}

func normalizeManifestForLayout(input []GenerationFile, layout string) ([]GenerationFile, string, error) {
	if layout != LayoutC2V1 && layout != LayoutSinglePayloadV1 {
		return nil, "", fmt.Errorf("invalid manifest layout %q", layout)
	}
	files := append([]GenerationFile(nil), input...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	hash := sha256.New()
	previous := ""
	for _, file := range files {
		if file.Path == "" || !visibleASCIIPath(file.Path) || path.Clean(file.Path) != file.Path || file.Path == "." || file.Path == previous || strings.ContainsAny(file.Path, "\\\x00\r\n\t") || strings.HasPrefix(file.Path, "/") || strings.HasPrefix(file.Path, "../") || file.Size < 0 || !validSHA256Text(file.SHA256) || file.Phase != generationPhaseForLayout(file.Path, layout) {
			return nil, "", fmt.Errorf("invalid generation file %#v", file)
		}
		previous = file.Path
		fmt.Fprintf(hash, "%s %d %s %s\n", file.SHA256, file.Size, file.Phase, file.Path)
	}
	return files, hex.EncodeToString(hash.Sum(nil)), nil
}

func visibleASCIIPath(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func generationPhaseForLayout(path, layout string) string {
	if layout == LayoutC2V1 && strings.HasPrefix(path, "dists/") && strings.Contains(path, "/pool/") {
		return "payload"
	}
	if strings.HasPrefix(path, "dists/") && (strings.Contains(path, "/pool/") || strings.HasSuffix(path, ".rpm") || strings.HasSuffix(path, ".deb")) {
		return ""
	}
	if strings.HasPrefix(path, "pool/") {
		return "payload"
	}
	base := path
	if index := strings.LastIndexByte(base, '/'); index >= 0 {
		base = base[index+1:]
	}
	if base == "repomd.xml" || base == "repomd.xml.asc" || base == "Release" || base == "InRelease" || base == "Release.gpg" {
		return "pointer"
	}
	return "metadata"
}

func validateChanges(changes []FileChange) error {
	return validateChangesForLayout(changes, LayoutSinglePayloadV1)
}

func validateChangesForLayout(changes []FileChange, layout string) error {
	if layout != LayoutC2V1 && layout != LayoutSinglePayloadV1 {
		return fmt.Errorf("invalid Changeset layout %q", layout)
	}
	for _, change := range changes {
		if !visibleASCIIPath(change.Path) || path.Clean(change.Path) != change.Path || strings.HasPrefix(change.Path, "/") || strings.HasPrefix(change.Path, "../") {
			return fmt.Errorf("invalid file change path %q", change.Path)
		}
		if change.Operation != "add" && change.Operation != "update" && change.Operation != "delete" {
			return fmt.Errorf("invalid file change operation %q", change.Operation)
		}
		if change.Operation == "delete" {
			if change.Phase != "delete" {
				return errors.New("delete change must use delete phase")
			}
			continue
		}
		if change.Phase != generationPhaseForLayout(change.Path, layout) || change.Size < 0 || !validSHA256Text(change.SHA256) {
			return fmt.Errorf("invalid file change %#v", change)
		}
	}
	return nil
}
