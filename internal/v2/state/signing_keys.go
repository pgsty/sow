package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

type RPMSigningKey struct {
	Fingerprint    string `json:"fingerprint"`
	SnapshotSHA256 string `json:"snapshot_sha256"`
	PublicKey      []byte `json:"public_key"`
}

func normalizeRPMSigningKey(key RPMSigningKey) (RPMSigningKey, error) {
	if !metadataFingerprintPattern.MatchString(key.Fingerprint) || key.Fingerprint != strings.ToUpper(key.Fingerprint) || len(key.PublicKey) == 0 || len(key.PublicKey) > 16<<20 {
		return RPMSigningKey{}, errors.New("invalid retained RPM signing key")
	}
	digest := sha256.Sum256(key.PublicKey)
	want := hex.EncodeToString(digest[:])
	if key.SnapshotSHA256 != "" && key.SnapshotSHA256 != want {
		return RPMSigningKey{}, errors.New("retained RPM signing snapshot digest differs from certificate bytes")
	}
	key.SnapshotSHA256 = want
	key.PublicKey = append([]byte(nil), key.PublicKey...)
	return key, nil
}

func normalizeRPMSigningKeys(input []RPMSigningKey) ([]RPMSigningKey, error) {
	bySnapshot := make(map[string]RPMSigningKey, len(input))
	for index := range input {
		key, err := normalizeRPMSigningKey(input[index])
		if err != nil {
			return nil, fmt.Errorf("RPM signing key %d: %w", index, err)
		}
		bySnapshot[key.Fingerprint+":"+key.SnapshotSHA256] = key
	}
	keys := make([]RPMSigningKey, 0, len(bySnapshot))
	for _, key := range bySnapshot {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Fingerprint != keys[j].Fingerprint {
			return keys[i].Fingerprint < keys[j].Fingerprint
		}
		return keys[i].SnapshotSHA256 < keys[j].SnapshotSHA256
	})
	return keys, nil
}

func retainRPMSigningKeysTx(ctx context.Context, tx *sql.Tx, keys []RPMSigningKey) error {
	for _, key := range keys {
		var exists int
		err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM rpm_signing_keys WHERE fingerprint = ? AND public_key = ?)`, key.Fingerprint, key.PublicKey).Scan(&exists)
		switch {
		case err == nil && exists == 1:
			continue
		case err != nil:
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO rpm_signing_keys(fingerprint, public_key) VALUES (?, ?)`, key.Fingerprint, key.PublicKey); err != nil {
			return err
		}
	}
	return nil
}

// RetainRPMSigningKeys stores only public certificates. The primary
// fingerprint identifies the key while SnapshotSHA256 identifies the exact
// certificate version; renewals of one primary identity therefore coexist
// without overwriting the verifier evidence frozen by older Generations.
func (s *Store) RetainRPMSigningKeys(ctx context.Context, input []RPMSigningKey) error {
	keys, err := normalizeRPMSigningKeys(input)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := retainRPMSigningKeysTx(ctx, tx, keys); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.Checkpoint(ctx)
}

func (s *Store) ListRPMSigningKeys(ctx context.Context) ([]RPMSigningKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT fingerprint, public_key FROM rpm_signing_keys ORDER BY fingerprint, public_key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := []RPMSigningKey{}
	for rows.Next() {
		var key RPMSigningKey
		if err := rows.Scan(&key.Fingerprint, &key.PublicKey); err != nil {
			return nil, err
		}
		normalized, err := normalizeRPMSigningKey(key)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrSchema, err)
		}
		keys = append(keys, normalized)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}

// upgradeEffectiveSigningSnapshots binds every v5 Built signing policy to the
// exact retained certificate bytes that existed before the v6 table stopped
// treating a primary fingerprint as a certificate version.
func upgradeEffectiveSigningSnapshots(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT fingerprint, public_key FROM rpm_signing_keys ORDER BY fingerprint, public_key`)
	if err != nil {
		return err
	}
	byFingerprint := map[string][]string{}
	for rows.Next() {
		var fingerprint string
		var publicKey []byte
		if err := rows.Scan(&fingerprint, &publicKey); err != nil {
			_ = rows.Close()
			return err
		}
		digest := sha256.Sum256(publicKey)
		byFingerprint[fingerprint] = append(byFingerprint[fingerprint], hex.EncodeToString(digest[:]))
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}

	distRows, err := tx.QueryContext(ctx, `SELECT name, effective_signing_json FROM dists WHERE format = 'rpm' ORDER BY name`)
	if err != nil {
		return err
	}
	type distSnapshot struct{ name, raw string }
	dists := []distSnapshot{}
	for distRows.Next() {
		var dist distSnapshot
		if err := distRows.Scan(&dist.name, &dist.raw); err != nil {
			_ = distRows.Close()
			return err
		}
		dists = append(dists, dist)
	}
	if err := errors.Join(distRows.Err(), distRows.Close()); err != nil {
		return err
	}
	for _, dist := range dists {
		var document map[string]any
		if err := json.Unmarshal([]byte(dist.raw), &document); err != nil {
			return fmt.Errorf("dist %s retained signing JSON: %w", dist.name, err)
		}
		rpm, _ := document["rpm"].(map[string]any)
		packages, _ := rpm["packages"].(map[string]any)
		mode, _ := packages["mode"].(string)
		if mode == "" || mode == "never" {
			continue
		}
		current, _ := packages["key_fingerprint"].(string)
		currentSnapshots := byFingerprint[current]
		if len(currentSnapshots) != 1 {
			return fmt.Errorf("dist %s current RPM signer %s has %d retained certificate snapshots", dist.name, current, len(currentSnapshots))
		}
		packages["key_snapshot_sha256"] = currentSnapshots[0]
		trustedSnapshots := append([]string(nil), currentSnapshots[0])
		trusted, _ := packages["trusted_key_fingerprints"].([]any)
		for _, rawFingerprint := range trusted {
			fingerprint, ok := rawFingerprint.(string)
			if !ok || len(byFingerprint[fingerprint]) == 0 {
				return fmt.Errorf("dist %s trusted RPM signer has no retained certificate snapshot", dist.name)
			}
			trustedSnapshots = append(trustedSnapshots, byFingerprint[fingerprint]...)
		}
		sort.Strings(trustedSnapshots)
		packages["trusted_key_snapshot_sha256s"] = stableUniqueStateStrings(trustedSnapshots)
		encoded, err := json.Marshal(document)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE dists SET effective_signing_json = ? WHERE name = ?`, string(encoded), dist.name); err != nil {
			return err
		}
	}
	return nil
}

func stableUniqueStateStrings(values []string) []string {
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
