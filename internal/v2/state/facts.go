package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
)

const MaxPackageFactsBytes = 64 << 20

// PackageFact is a rebuildable render cache for one immutable package object.
// Fingerprint is optional until the object has acquired its final Pool name.
// Neither operation recovery nor PackageObject validity depends on this row.
type PackageFact struct {
	PackageSHA256 string
	FactSchema    string
	Facts         []byte
	Fingerprint   *PackageFingerprint
	Corrupt       bool
}

type PackageFingerprint struct {
	Device    uint64
	Inode     uint64
	Size      int64
	MTimeNano int64
	CTimeNano int64
}

type PackageFingerprintRecord struct {
	PackageSHA256 string
	Fingerprint   *PackageFingerprint
}

func validatePackageFact(fact PackageFact) error {
	if !validSHA256Text(fact.PackageSHA256) {
		return fmt.Errorf("invalid package fact digest %q", fact.PackageSHA256)
	}
	if len(fact.FactSchema) < 1 || len(fact.FactSchema) > 128 {
		return errors.New("invalid package fact schema")
	}
	if len(fact.Facts) < 2 || len(fact.Facts) > MaxPackageFactsBytes {
		return fmt.Errorf("package facts size %d is outside 2..%d", len(fact.Facts), MaxPackageFactsBytes)
	}
	if fact.Fingerprint != nil && fact.Fingerprint.Size < 0 {
		return errors.New("invalid package fact fingerprint size")
	}
	return nil
}

// UpsertPackageFacts installs a batch without disturbing fingerprints already
// captured after Pool publication. Cache writes are intentionally independent
// of the mutation journal and are safe to replay.
func (s *Store) UpsertPackageFacts(ctx context.Context, facts []PackageFact) error {
	if len(facts) == 0 {
		return nil
	}
	for _, fact := range facts {
		if err := validatePackageFact(fact); err != nil {
			return err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	statement, err := tx.PrepareContext(ctx, `INSERT INTO package_facts(package_sha256, fact_schema, facts, facts_sha256)
VALUES (?, ?, ?, ?)
ON CONFLICT(package_sha256) DO UPDATE SET fact_schema = excluded.fact_schema, facts = excluded.facts, facts_sha256 = excluded.facts_sha256`)
	if err != nil {
		return err
	}
	for _, fact := range facts {
		digest := sha256.Sum256(fact.Facts)
		if _, err := statement.ExecContext(ctx, fact.PackageSHA256, fact.FactSchema, fact.Facts, hex.EncodeToString(digest[:])); err != nil {
			_ = statement.Close()
			return fmt.Errorf("upsert package facts %s: %w", fact.PackageSHA256, err)
		}
	}
	if err := statement.Close(); err != nil {
		return err
	}
	return tx.Commit()
}

// ListPackageFacts is the one bulk read used by a repository build. Keeping
// this API repository-wide avoids one SQLite lookup per selected package and
// lets callers match facts to their already-loaded PackageObjects in memory.
func (s *Store) ListPackageFacts(ctx context.Context) ([]PackageFact, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT package_sha256, fact_schema, facts, facts_sha256, device, inode, size, mtime_ns, ctime_ns
FROM package_facts ORDER BY package_sha256`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []PackageFact{}
	for rows.Next() {
		var fact PackageFact
		var factsSHA string
		var device, inode sql.NullString
		var size, mtime, ctime sql.NullInt64
		if err := rows.Scan(&fact.PackageSHA256, &fact.FactSchema, &fact.Facts, &factsSHA, &device, &inode, &size, &mtime, &ctime); err != nil {
			return nil, err
		}
		if err := validatePackageFact(fact); err != nil {
			fact.Corrupt = true
		} else {
			digest := sha256.Sum256(fact.Facts)
			if factsSHA != hex.EncodeToString(digest[:]) {
				fact.Corrupt = true
			}
		}
		fingerprint, fingerprintCorrupt := decodePackageFingerprint(device, inode, size, mtime, ctime)
		if fingerprintCorrupt {
			fact.Corrupt = true
		} else {
			fact.Fingerprint = fingerprint
		}
		result = append(result, fact)
	}
	return result, rows.Err()
}

// ListPackageFingerprints is the metadata-only cache view used by ordinary
// public-tree validation and final fingerprint persistence. It deliberately
// excludes facts BLOBs so a warm build neither allocates nor re-hashes package
// metadata merely to perform stat comparisons.
func (s *Store) ListPackageFingerprints(ctx context.Context) ([]PackageFingerprintRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT package_sha256, device, inode, size, mtime_ns, ctime_ns
FROM package_facts ORDER BY package_sha256`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []PackageFingerprintRecord{}
	for rows.Next() {
		var record PackageFingerprintRecord
		var device, inode sql.NullString
		var size, mtime, ctime sql.NullInt64
		if err := rows.Scan(&record.PackageSHA256, &device, &inode, &size, &mtime, &ctime); err != nil {
			return nil, err
		}
		record.Fingerprint, _ = decodePackageFingerprint(device, inode, size, mtime, ctime)
		result = append(result, record)
	}
	return result, rows.Err()
}

func decodePackageFingerprint(device, inode sql.NullString, size, mtime, ctime sql.NullInt64) (*PackageFingerprint, bool) {
	present := device.Valid || inode.Valid || size.Valid || mtime.Valid || ctime.Valid
	if !present {
		return nil, false
	}
	if !device.Valid || !inode.Valid || !size.Valid || !mtime.Valid || !ctime.Valid {
		return nil, true
	}
	dev, devErr := strconv.ParseUint(device.String, 10, 64)
	ino, inoErr := strconv.ParseUint(inode.String, 10, 64)
	if devErr != nil || inoErr != nil || size.Int64 < 0 {
		return nil, true
	}
	return &PackageFingerprint{Device: dev, Inode: ino, Size: size.Int64, MTimeNano: mtime.Int64, CTimeNano: ctime.Int64}, false
}

func (s *Store) UpdatePackageFingerprints(ctx context.Context, facts []PackageFact) error {
	if len(facts) == 0 {
		return nil
	}
	for _, fact := range facts {
		if !validSHA256Text(fact.PackageSHA256) || fact.Fingerprint == nil || fact.Fingerprint.Size < 0 {
			return errors.New("invalid package fingerprint update")
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	statement, err := tx.PrepareContext(ctx, `UPDATE package_facts
SET device = ?, inode = ?, size = ?, mtime_ns = ?, ctime_ns = ?
WHERE package_sha256 = ?`)
	if err != nil {
		return err
	}
	for _, fact := range facts {
		fingerprint := fact.Fingerprint
		result, err := statement.ExecContext(ctx, strconv.FormatUint(fingerprint.Device, 10), strconv.FormatUint(fingerprint.Inode, 10), fingerprint.Size, fingerprint.MTimeNano, fingerprint.CTimeNano, fact.PackageSHA256)
		if err != nil {
			_ = statement.Close()
			return err
		}
		changed, err := result.RowsAffected()
		if err != nil || changed != 1 {
			_ = statement.Close()
			return errors.Join(fmt.Errorf("package facts %s are unavailable for fingerprint update", fact.PackageSHA256), err)
		}
	}
	if err := statement.Close(); err != nil {
		return err
	}
	return tx.Commit()
}
