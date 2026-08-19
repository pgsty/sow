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
	"slices"
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

// Keep bulk INSERTs below SQLite's conservative 999-bind compatibility
// ceiling. generation_files uses five binds per row and operation_files uses
// seven, so 128 rows fits both while collapsing a large manifest from one SQL
// statement per path to one statement per small batch.
const sqliteManifestInsertBatchSize = 128

func insertGenerationFilesTx(ctx context.Context, tx *sql.Tx, generation GenerationID, files []GenerationFile) error {
	for start := 0; start < len(files); start += sqliteManifestInsertBatchSize {
		end := min(start+sqliteManifestInsertBatchSize, len(files))
		var query strings.Builder
		query.WriteString(`INSERT INTO generation_files(generation, path, phase, size, sha256) VALUES `)
		args := make([]any, 0, (end-start)*5)
		for index, file := range files[start:end] {
			if index != 0 {
				query.WriteByte(',')
			}
			query.WriteString(`(?, ?, ?, ?, ?)`)
			args = append(args, generation, file.Path, file.Phase, file.Size, file.SHA256)
		}
		if _, err := tx.ExecContext(ctx, query.String(), args...); err != nil {
			return fmt.Errorf("record generation files starting at %q: %w", files[start].Path, err)
		}
	}
	return nil
}

func insertOperationFilesTx(ctx context.Context, tx *sql.Tx, operationID string, changes []FileChange) error {
	for start := 0; start < len(changes); start += sqliteManifestInsertBatchSize {
		end := min(start+sqliteManifestInsertBatchSize, len(changes))
		var query strings.Builder
		query.WriteString(`INSERT INTO operation_files(operation_id, sequence, action, phase, path, size, sha256) VALUES `)
		args := make([]any, 0, (end-start)*7)
		for offset, change := range changes[start:end] {
			if offset != 0 {
				query.WriteByte(',')
			}
			var size, digest any
			if change.Operation != "delete" {
				size, digest = change.Size, change.SHA256
			}
			query.WriteString(`(?, ?, ?, ?, ?, ?, ?)`)
			args = append(args, operationID, start+offset, change.Operation, change.Phase, change.Path, size, digest)
		}
		if _, err := tx.ExecContext(ctx, query.String(), args...); err != nil {
			return fmt.Errorf("record operation files starting at %q: %w", changes[start].Path, err)
		}
	}
	return nil
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

type generationSignerQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

// GenerationSignerUnverified marks a signed historical RPM view whose exact
// signer could not be proven during the v10-to-v11 migration. It is coverage
// evidence only and is never a trust identity or a forward-propagation source.
const GenerationSignerUnverified = "unverified"

func rpmGenerationViewSigning(manifest []GenerationFile) (map[string]bool, error) {
	views := map[string]bool{}
	for _, file := range manifest {
		parts := strings.Split(file.Path, "/")
		if len(parts) != 5 || parts[0] != "dists" || parts[3] != "repodata" || parts[4] != "repomd.xml" {
			continue
		}
		if file.Phase != "pointer" || parts[1] == "" || parts[2] == "" {
			return nil, fmt.Errorf("%w: Generation RPM view pointer %q is invalid", ErrConflict, file.Path)
		}
		views[path.Join(parts[:3]...)] = false
	}
	for _, file := range manifest {
		parts := strings.Split(file.Path, "/")
		if len(parts) != 5 || parts[0] != "dists" || parts[3] != "repodata" || parts[4] != "repomd.xml.asc" {
			continue
		}
		viewID := path.Join(parts[:3]...)
		if _, exists := views[viewID]; !exists {
			return nil, fmt.Errorf("%w: Generation RPM signature %q has no repomd pointer", ErrConflict, file.Path)
		}
		views[viewID] = true
	}
	return views, nil
}

func generationSignerViewDist(viewID string) (string, error) {
	parts := strings.Split(viewID, "/")
	if len(parts) != 3 || parts[0] != "dists" || parts[1] == "" || parts[2] == "" || path.Join(parts...) != viewID {
		return "", fmt.Errorf("%w: invalid Generation signer view %q", ErrConflict, viewID)
	}
	return parts[1], nil
}

func validateGenerationViewSignerCoverage(ctx context.Context, queryer generationSignerQueryer, generation GenerationID, manifest []GenerationFile) error {
	expectedSigning, err := rpmGenerationViewSigning(manifest)
	if err != nil {
		return err
	}
	expected := make([]string, 0, len(expectedSigning))
	for viewID := range expectedSigning {
		expected = append(expected, viewID)
	}
	sort.Strings(expected)
	rows, err := queryer.QueryContext(ctx, `SELECT view_id, signer_identity, COALESCE(trusted_public_key, X'') FROM generation_view_signers WHERE generation = ? ORDER BY view_id`, generation)
	if err != nil {
		return err
	}
	actual := []string{}
	for rows.Next() {
		var viewID, identity string
		var trusted []byte
		if err := rows.Scan(&viewID, &identity, &trusted); err != nil {
			rows.Close()
			return err
		}
		if _, err := generationSignerViewDist(viewID); err != nil {
			rows.Close()
			return err
		}
		if identity == "none" {
			if len(trusted) != 0 || expectedSigning[viewID] {
				rows.Close()
				return fmt.Errorf("%w: Generation view %q signature state differs from signer evidence", ErrConflict, viewID)
			}
		} else if identity == GenerationSignerUnverified {
			if len(trusted) != 0 || !expectedSigning[viewID] {
				rows.Close()
				return fmt.Errorf("%w: Generation view %q has invalid unverified signer evidence", ErrConflict, viewID)
			}
		} else if !validSHA256Text(identity) || len(trusted) == 0 || !expectedSigning[viewID] {
			rows.Close()
			return fmt.Errorf("%w: Generation view %q has invalid signer evidence", ErrConflict, viewID)
		} else if digest := sha256.Sum256(trusted); hex.EncodeToString(digest[:]) != identity {
			rows.Close()
			return fmt.Errorf("%w: Generation view %q signer identity differs from retained key", ErrConflict, viewID)
		}
		actual = append(actual, viewID)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}
	if !slices.Equal(actual, expected) {
		return fmt.Errorf("%w: Generation %s signer views differ from RPM manifest views: got %v want %v", ErrConflict, generation, actual, expected)
	}
	return nil
}

func generationSignerIdentity(fingerprint string, publicKey []byte, claimed string) (string, any, error) {
	if fingerprint == "" {
		if len(publicKey) != 0 || claimed != "" && claimed != "none" {
			return "", nil, errors.New("unsigned RPM metadata signer state is inconsistent")
		}
		return "none", nil, nil
	}
	if !metadataFingerprintPattern.MatchString(fingerprint) || len(publicKey) == 0 || len(publicKey) > 16<<20 {
		return "", nil, errors.New("signed RPM metadata signer state is invalid")
	}
	digest := sha256.Sum256(publicKey)
	identity := hex.EncodeToString(digest[:])
	if claimed != "" && claimed != identity {
		return "", nil, errors.New("claimed RPM metadata signer identity differs from retained key")
	}
	return identity, publicKey, nil
}

func insertGenerationDistViewSignersTx(ctx context.Context, tx *sql.Tx, generation GenerationID, name, format string, architectures []Architecture, fingerprint string, publicKey []byte, claimed string) error {
	if format != "rpm" {
		return nil
	}
	identity, trusted, err := generationSignerIdentity(fingerprint, publicKey, claimed)
	if err != nil {
		return fmt.Errorf("Dist %q Generation signer: %w", name, err)
	}
	for _, architecture := range architectures {
		viewID := path.Join("dists", name, architecture.Family)
		if _, err := generationSignerViewDist(viewID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO generation_view_signers(generation, view_id, signer_identity, trusted_public_key) VALUES (?, ?, ?, ?)`, generation, viewID, identity, trusted); err != nil {
			return err
		}
	}
	return nil
}

// insertCurrentGenerationViewSignersTx snapshots the signer identity for every
// RPM view represented by the current built Dist projection. This is used only
// when anchoring a pre-ledger repository: the public manifest proves which
// views exist, while the Dist projection retains the verification key that
// proves who signed each of those views. The subsequent coverage check makes
// the bootstrap fail closed if those two sources do not describe the same
// topology or signedness.
func insertCurrentGenerationViewSignersTx(ctx context.Context, tx *sql.Tx, generation GenerationID) error {
	rows, err := tx.QueryContext(ctx, `
SELECT d.name, a.family, COALESCE(s.fingerprint, ''), COALESCE(s.public_key, X'')
FROM dists AS d
JOIN dist_architectures AS a ON a.dist_name = d.name
LEFT JOIN dist_metadata_signers AS s ON s.dist_name = d.name
WHERE d.format = 'rpm'
ORDER BY d.name, a.family`)
	if err != nil {
		return err
	}
	type signerRow struct {
		viewID, fingerprint string
		publicKey           []byte
	}
	signers := []signerRow{}
	for rows.Next() {
		var distName, family string
		var signer signerRow
		if err := rows.Scan(&distName, &family, &signer.fingerprint, &signer.publicKey); err != nil {
			rows.Close()
			return err
		}
		signer.viewID = path.Join("dists", distName, family)
		signers = append(signers, signer)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}
	for _, signer := range signers {
		identity, trusted, err := generationSignerIdentity(signer.fingerprint, signer.publicKey, "")
		if err != nil {
			return fmt.Errorf("Generation view %q signer: %w", signer.viewID, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO generation_view_signers(generation, view_id, signer_identity, trusted_public_key) VALUES (?, ?, ?, ?)`, generation, signer.viewID, identity, trusted); err != nil {
			return err
		}
	}
	return nil
}

func carryGenerationViewSignersTx(ctx context.Context, tx *sql.Tx, base, target GenerationID, replacedDists map[string]struct{}) error {
	if base == 0 {
		return nil
	}
	if err := requireVerifiedGenerationSigners(ctx, tx, base); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT view_id, signer_identity, trusted_public_key FROM generation_view_signers WHERE generation = ? ORDER BY view_id`, base)
	if err != nil {
		return err
	}
	type signerRow struct {
		viewID, identity string
		trusted          []byte
	}
	carried := []signerRow{}
	for rows.Next() {
		var row signerRow
		if err := rows.Scan(&row.viewID, &row.identity, &row.trusted); err != nil {
			rows.Close()
			return err
		}
		dist, err := generationSignerViewDist(row.viewID)
		if err != nil {
			rows.Close()
			return err
		}
		if _, replaced := replacedDists[dist]; !replaced {
			carried = append(carried, row)
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}
	for _, row := range carried {
		var trusted any
		if row.identity != "none" {
			trusted = row.trusted
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO generation_view_signers(generation, view_id, signer_identity, trusted_public_key) VALUES (?, ?, ?, ?)`, target, row.viewID, row.identity, trusted); err != nil {
			return err
		}
	}
	return nil
}

type generationSignerEvidence struct {
	identity string
	trusted  []byte
}

type generationSignerRowQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func requireVerifiedGenerationSigners(ctx context.Context, queryer generationSignerRowQueryer, generation GenerationID) error {
	var unverified int
	if err := queryer.QueryRowContext(ctx, `SELECT EXISTS(
SELECT 1 FROM generation_view_signers WHERE generation = ? AND signer_identity = 'unverified')`, generation).Scan(&unverified); err != nil {
		return err
	}
	if unverified != 0 {
		return fmt.Errorf("%w: Generation %s has unverified historical RPM signer evidence", ErrConflict, generation)
	}
	return nil
}

func sameGenerationSignerEvidence(left, right generationSignerEvidence) bool {
	return left.identity == right.identity && bytes.Equal(left.trusted, right.trusted)
}

func generationViewContentIdentity(manifest []GenerationFile, viewID string) string {
	hash := sha256.New()
	prefix := viewID + "/"
	for _, file := range manifest {
		if !strings.HasPrefix(file.Path, prefix) {
			continue
		}
		fmt.Fprintf(hash, "%s\x00%s\x00%d\x00%s\n", file.Path, file.Phase, file.Size, file.SHA256)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// repairGenerationViewSignersTx repairs only signer identities that can be
// proven from immutable state: unsigned manifests imply signer "none"; the
// current Built topology anchors its retained signer keys; and an adjacent
// Generation with byte-identical view content carries the same signer. A
// historical signed view without any such anchor is rejected rather than
// assigned a guessed identity.
func repairGenerationViewSignersTx(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT generation FROM generations ORDER BY generation`)
	if err != nil {
		return err
	}
	type generationState struct {
		generation GenerationID
		manifest   []GenerationFile
		signing    map[string]bool
		content    map[string]string
		signers    map[string]generationSignerEvidence
		original   map[string]struct{}
	}
	states := []*generationState{}
	for rows.Next() {
		var generation GenerationID
		if err := rows.Scan(&generation); err != nil {
			rows.Close()
			return err
		}
		states = append(states, &generationState{generation: generation})
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}
	if len(states) == 0 {
		return nil
	}
	for _, state := range states {
		state.manifest, err = generationManifestTx(ctx, tx, state.generation)
		if err != nil {
			return err
		}
		state.signing, err = rpmGenerationViewSigning(state.manifest)
		if err != nil {
			return err
		}
		state.content = make(map[string]string, len(state.signing))
		state.signers = make(map[string]generationSignerEvidence, len(state.signing))
		state.original = make(map[string]struct{}, len(state.signing))
		for viewID, signed := range state.signing {
			state.content[viewID] = generationViewContentIdentity(state.manifest, viewID)
			if !signed {
				state.signers[viewID] = generationSignerEvidence{identity: "none"}
			}
		}
		signerRows, err := tx.QueryContext(ctx, `SELECT view_id, signer_identity, COALESCE(trusted_public_key, X'') FROM generation_view_signers WHERE generation = ? ORDER BY view_id`, state.generation)
		if err != nil {
			return err
		}
		for signerRows.Next() {
			var viewID string
			var evidence generationSignerEvidence
			if err := signerRows.Scan(&viewID, &evidence.identity, &evidence.trusted); err != nil {
				signerRows.Close()
				return err
			}
			signed, expected := state.signing[viewID]
			if !expected || signed != (evidence.identity != "none") {
				signerRows.Close()
				return fmt.Errorf("%w: Generation %s view %q has incompatible signer evidence", ErrConflict, state.generation, viewID)
			}
			if evidence.identity == GenerationSignerUnverified {
				if !signed || len(evidence.trusted) != 0 {
					signerRows.Close()
					return fmt.Errorf("%w: Generation %s view %q has invalid unverified signer evidence", ErrConflict, state.generation, viewID)
				}
			} else if evidence.identity != "none" {
				digest := sha256.Sum256(evidence.trusted)
				if !validSHA256Text(evidence.identity) || len(evidence.trusted) == 0 || hex.EncodeToString(digest[:]) != evidence.identity {
					signerRows.Close()
					return fmt.Errorf("%w: Generation %s view %q signer evidence is invalid", ErrConflict, state.generation, viewID)
				}
			} else if len(evidence.trusted) != 0 {
				signerRows.Close()
				return fmt.Errorf("%w: Generation %s unsigned view %q retains a key", ErrConflict, state.generation, viewID)
			}
			state.signers[viewID] = evidence
			state.original[viewID] = struct{}{}
		}
		if err := errors.Join(signerRows.Err(), signerRows.Close()); err != nil {
			return err
		}
	}

	var current GenerationID
	if err := tx.QueryRowContext(ctx, `SELECT built_generation FROM repository_state WHERE singleton = 1`).Scan(&current); err != nil {
		return err
	}
	head := states[len(states)-1]
	if head.generation != current {
		return fmt.Errorf("%w: signer repair head %s differs from current Generation %s", ErrConflict, head.generation, current)
	}
	anchorRows, err := tx.QueryContext(ctx, `
SELECT d.name, a.family, COALESCE(s.fingerprint, ''), COALESCE(s.public_key, X'')
FROM dists AS d
JOIN dist_architectures AS a ON a.dist_name = d.name
LEFT JOIN dist_metadata_signers AS s ON s.dist_name = d.name
WHERE d.format = 'rpm'
ORDER BY d.name, a.family`)
	if err != nil {
		return err
	}
	anchors := map[string]generationSignerEvidence{}
	for anchorRows.Next() {
		var distName, family, fingerprint string
		var publicKey []byte
		if err := anchorRows.Scan(&distName, &family, &fingerprint, &publicKey); err != nil {
			anchorRows.Close()
			return err
		}
		identity, trusted, err := generationSignerIdentity(fingerprint, publicKey, "")
		if err != nil {
			anchorRows.Close()
			return err
		}
		evidence := generationSignerEvidence{identity: identity}
		if trusted != nil {
			evidence.trusted = append([]byte(nil), publicKey...)
		}
		anchors[path.Join("dists", distName, family)] = evidence
	}
	if err := errors.Join(anchorRows.Err(), anchorRows.Close()); err != nil {
		return err
	}
	for viewID, signed := range head.signing {
		anchor, ok := anchors[viewID]
		if !ok || signed != (anchor.identity != "none") {
			return fmt.Errorf("%w: current Generation %s view %q lacks matching Dist signer state", ErrConflict, head.generation, viewID)
		}
		if existing, ok := head.signers[viewID]; ok && !sameGenerationSignerEvidence(existing, anchor) {
			return fmt.Errorf("%w: current Generation %s view %q differs from Dist signer state", ErrConflict, head.generation, viewID)
		}
		head.signers[viewID] = anchor
	}
	if len(anchors) != len(head.signing) {
		return fmt.Errorf("%w: current Dist signer topology differs from Generation %s", ErrConflict, head.generation)
	}

	for pass := 0; pass < len(states); pass++ {
		changed := false
		for index := 1; index < len(states); index++ {
			prior, next := states[index-1], states[index]
			for viewID := range next.signing {
				if _, exists := next.signers[viewID]; exists || prior.content[viewID] == "" || prior.content[viewID] != next.content[viewID] {
					continue
				}
				if evidence, ok := prior.signers[viewID]; ok && evidence.identity != GenerationSignerUnverified {
					next.signers[viewID] = evidence
					changed = true
				}
			}
		}
		for index := len(states) - 2; index >= 0; index-- {
			prior, next := states[index], states[index+1]
			for viewID := range prior.signing {
				if _, exists := prior.signers[viewID]; exists || next.content[viewID] == "" || prior.content[viewID] != next.content[viewID] {
					continue
				}
				if evidence, ok := next.signers[viewID]; ok && evidence.identity != GenerationSignerUnverified {
					prior.signers[viewID] = evidence
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}
	for _, state := range states {
		for viewID := range state.signing {
			evidence, ok := state.signers[viewID]
			if !ok {
				if state.generation == current {
					return fmt.Errorf("%w: cannot prove signer identity for current Generation %s view %q", ErrConflict, state.generation, viewID)
				}
				evidence = generationSignerEvidence{identity: GenerationSignerUnverified}
				state.signers[viewID] = evidence
			}
			if _, exists := state.original[viewID]; exists {
				continue
			}
			var trusted any
			if evidence.identity != "none" && evidence.identity != GenerationSignerUnverified {
				trusted = evidence.trusted
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO generation_view_signers(generation, view_id, signer_identity, trusted_public_key) VALUES (?, ?, ?, ?)`, state.generation, viewID, evidence.identity, trusted); err != nil {
				return err
			}
		}
		if err := validateGenerationViewSignerCoverage(ctx, tx, state.generation, state.manifest); err != nil {
			return err
		}
	}
	return nil
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
	if record.SignerIdentity == "none" || record.SignerIdentity == GenerationSignerUnverified {
		if len(trusted) != 0 {
			return GenerationViewSigner{}, fmt.Errorf("%w: keyless Generation signer evidence has a trusted key", ErrSchema)
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
	manifest, err := s.GenerationManifest(ctx, generation)
	if err != nil {
		return "", "", err
	}
	if err := validateGenerationViewSignerCoverage(ctx, s.db, generation, manifest); err != nil {
		return "", "", err
	}
	if err := requireVerifiedGenerationSigners(ctx, s.db, generation); err != nil {
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
	if err := insertGenerationFilesTx(ctx, tx, generation, manifest); err != nil {
		return err
	}
	if err := insertCurrentGenerationViewSignersTx(ctx, tx, generation); err != nil {
		return fmt.Errorf("anchor legacy Generation signer evidence: %w", err)
	}
	if err := validateGenerationViewSignerCoverage(ctx, tx, generation, manifest); err != nil {
		return err
	}
	if err := insertOperationFilesTx(ctx, tx, operationID, changes); err != nil {
		return err
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
		if s.SchemaVersion() >= 7 {
			if err := validateGenerationViewSignerCoverage(ctx, s.db, info.Generation, normalized); err != nil {
				return err
			}
			if info.Generation == current {
				if err := requireVerifiedGenerationSigners(ctx, s.db, info.Generation); err != nil {
					return err
				}
			}
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
	return insertOperationFilesTx(ctx, tx, operationID, changes)
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
	if err := insertGenerationFilesTx(ctx, tx, generation, manifest); err != nil {
		return err
	}
	return insertOperationFilesTx(ctx, tx, operationID, changes)
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
	generationInfo, err := generationInfoTx(ctx, tx, input.Generation)
	if err != nil {
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
		if err := insertGenerationDistViewSignersTx(ctx, tx, input.Generation, dist.Name, dist.Format, dist.Architectures, dist.MetadataSignerFingerprint, dist.MetadataSignerPublicKey, dist.MetadataSignerIdentity); err != nil {
			return err
		}
	}
	if err := carryGenerationViewSignersTx(ctx, tx, generationInfo.PreviousGeneration, input.Generation, seenDists); err != nil {
		return err
	}
	if err := validateGenerationViewSignerCoverage(ctx, tx, input.Generation, input.Manifest); err != nil {
		return err
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
