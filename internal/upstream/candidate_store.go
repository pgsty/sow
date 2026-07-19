package upstream

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"github.com/pgsty/sow/internal/provenance"
	"github.com/pgsty/sow/internal/syncer"
	_ "modernc.org/sqlite"
)

// candidateRecord keeps the authenticated package identity and the exact
// metadata proof together while candidates are spooled to disk.  Keeping the
// proof beside the candidate avoids a second repository-sized in-memory map.
type candidateRecord struct {
	Candidate syncer.Candidate
	Proof     candidateProof
}

// candidateStore is a private, rebuildable SQLite spool.  It is deliberately
// not canonical state: the signed metadata in Evidence is the trust root and
// discovery can recreate this database at any time.  A small page cache and
// file-backed temporary storage keep memory bounded for large upstreams.
type candidateStore struct {
	path      string
	db        *sql.DB
	tx        *sql.Tx
	insert    *sql.Stmt
	count     int
	finalized bool
}

func newCandidateStore(workDir string) (*candidateStore, error) {
	root, absolute, err := openDownloadRoot(workDir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err := ensureSafeSubdir(root, "candidates"); err != nil {
		return nil, fmt.Errorf("upstream: create candidate spool: %w", err)
	}
	file, err := os.CreateTemp(filepath.Join(absolute, "candidates"), ".discovery-*.sqlite")
	if err != nil {
		return nil, fmt.Errorf("upstream: create candidate spool: %w", err)
	}
	filename := file.Name()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(filename)
		return nil, err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(filename)
		return nil, err
	}

	db, err := sql.Open("sqlite", filename)
	if err != nil {
		_ = os.Remove(filename)
		return nil, fmt.Errorf("upstream: open candidate spool: %w", err)
	}
	db.SetMaxOpenConns(1)
	cleanup := func() {
		_ = db.Close()
		_ = os.Remove(filename)
		_ = os.Remove(filename + "-journal")
		_ = os.Remove(filename + "-wal")
		_ = os.Remove(filename + "-shm")
	}
	if _, err := db.Exec(`
PRAGMA journal_mode=DELETE;
PRAGMA synchronous=OFF;
PRAGMA temp_store=FILE;
PRAGMA cache_size=-2048;
PRAGMA mmap_size=0;
CREATE TABLE candidates (
  sha256 TEXT PRIMARY KEY CHECK(length(sha256) = 64),
  format TEXT NOT NULL,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  arch TEXT NOT NULL,
  url TEXT NOT NULL,
  size INTEGER NOT NULL CHECK(size >= 0),
  debug_info INTEGER NOT NULL CHECK(debug_info IN (0, 1)),
  rpm_proof BLOB,
  deb_proof BLOB,
  CHECK((format = 'rpm' AND rpm_proof IS NOT NULL AND deb_proof IS NULL) OR
        (format = 'deb' AND deb_proof IS NOT NULL AND rpm_proof IS NULL))
) WITHOUT ROWID;`); err != nil {
		cleanup()
		return nil, fmt.Errorf("upstream: initialize candidate spool: %w", err)
	}
	tx, err := db.Begin()
	if err != nil {
		cleanup()
		return nil, err
	}
	insert, err := tx.Prepare(`INSERT OR IGNORE INTO candidates
(sha256, format, name, version, arch, url, size, debug_info, rpm_proof, deb_proof)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		cleanup()
		return nil, err
	}
	return &candidateStore{path: filename, db: db, tx: tx, insert: insert}, nil
}

func (s *candidateStore) add(candidate syncer.Candidate, proof candidateProof) error {
	if s == nil || s.finalized || s.tx == nil || s.insert == nil {
		return fmt.Errorf("%w: candidate spool is not writable", ErrInvalidMetadata)
	}
	if err := candidate.Validate(); err != nil {
		return err
	}
	rpm, deb, err := encodeCandidateProof(candidate.Format, proof)
	if err != nil {
		return err
	}
	result, err := s.insert.Exec(candidate.SHA256, candidate.Format, candidate.Name, candidate.Version,
		candidate.Arch, candidate.URL, candidate.Size, candidate.DebugInfo, rpm, deb)
	if err != nil {
		return fmt.Errorf("upstream: spool candidate %s: %w", candidate.SHA256, err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 1 {
		s.count++
		return nil
	}

	prior, err := s.getFrom(s.tx, candidate.SHA256)
	if err != nil {
		return err
	}
	if prior.Candidate != candidate {
		return fmt.Errorf("%w: SHA256 %s has multiple identities", ErrConflictingPackage, candidate.SHA256)
	}
	preferred := preferredCandidateProof(prior.Proof, proof)
	if proofsEqual(preferred, prior.Proof) {
		return nil
	}
	rpm, deb, err = encodeCandidateProof(candidate.Format, preferred)
	if err != nil {
		return err
	}
	if _, err := s.tx.Exec(`UPDATE candidates SET rpm_proof = ?, deb_proof = ? WHERE sha256 = ?`, rpm, deb, candidate.SHA256); err != nil {
		return fmt.Errorf("upstream: update deterministic candidate proof: %w", err)
	}
	return nil
}

func (s *candidateStore) finalize() error {
	if s == nil || s.finalized {
		return nil
	}
	if s.insert != nil {
		if err := s.insert.Close(); err != nil {
			_ = s.tx.Rollback()
			return err
		}
		s.insert = nil
	}
	if err := s.tx.Commit(); err != nil {
		return fmt.Errorf("upstream: commit candidate spool: %w", err)
	}
	s.tx = nil
	s.finalized = true
	// Iteration and concurrent receipt lookups are read-only and may use a
	// handful of independent connections without increasing SQLite's cache.
	s.db.SetMaxOpenConns(8)
	s.db.SetMaxIdleConns(2)
	return nil
}

func (s *candidateStore) forEach(fn func(candidateRecord) error) error {
	return s.forEachContext(context.Background(), fn)
}

func (s *candidateStore) forEachContext(ctx context.Context, fn func(candidateRecord) error) error {
	if s == nil || !s.finalized || s.db == nil {
		return fmt.Errorf("%w: candidate spool is not sealed", ErrInvalidMetadata)
	}
	if ctx == nil {
		return errors.New("upstream: nil candidate iteration context")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT sha256, format, name, version, arch, url, size, debug_info, rpm_proof, deb_proof
FROM candidates ORDER BY sha256`)
	if err != nil {
		return fmt.Errorf("upstream: iterate candidate spool: %w", err)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		record, err := scanCandidate(rows)
		if err != nil {
			return err
		}
		if err := fn(record); err != nil {
			return err
		}
		seen++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("upstream: iterate candidate spool: %w", err)
	}
	if seen != s.count {
		return fmt.Errorf("%w: candidate spool count changed: got %d want %d", ErrInvalidMetadata, seen, s.count)
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanCandidate(row rowScanner) (candidateRecord, error) {
	var record candidateRecord
	var debug int
	var rpm, deb []byte
	if err := row.Scan(&record.Candidate.SHA256, &record.Candidate.Format, &record.Candidate.Name,
		&record.Candidate.Version, &record.Candidate.Arch, &record.Candidate.URL, &record.Candidate.Size,
		&debug, &rpm, &deb); err != nil {
		return candidateRecord{}, fmt.Errorf("upstream: decode candidate spool: %w", err)
	}
	record.Candidate.DebugInfo = debug == 1
	if debug != 0 && debug != 1 {
		return candidateRecord{}, fmt.Errorf("%w: invalid candidate debug flag", ErrInvalidMetadata)
	}
	if err := record.Candidate.Validate(); err != nil {
		return candidateRecord{}, fmt.Errorf("%w: invalid spooled candidate: %v", ErrInvalidMetadata, err)
	}
	proof, err := decodeCandidateProof(record.Candidate.Format, rpm, deb)
	if err != nil {
		return candidateRecord{}, err
	}
	record.Proof = proof
	return record, nil
}

func (s *candidateStore) get(digest string) (candidateRecord, error) {
	if s == nil || !s.finalized || s.db == nil {
		return candidateRecord{}, fmt.Errorf("%w: candidate spool is not sealed", ErrInvalidMetadata)
	}
	return s.getFrom(s.db, digest)
}

type rowQueryer interface {
	QueryRow(query string, args ...any) *sql.Row
}

func (s *candidateStore) getFrom(queryer rowQueryer, digest string) (candidateRecord, error) {
	row := queryer.QueryRow(`SELECT sha256, format, name, version, arch, url, size, debug_info, rpm_proof, deb_proof
FROM candidates WHERE sha256 = ?`, digest)
	record, err := scanCandidate(row)
	if errors.Is(err, sql.ErrNoRows) {
		return candidateRecord{}, os.ErrNotExist
	}
	return record, err
}

func (s *candidateStore) close() error {
	if s == nil {
		return nil
	}
	if s.insert != nil {
		_ = s.insert.Close()
	}
	if s.tx != nil {
		_ = s.tx.Rollback()
	}
	var err error
	if s.db != nil {
		err = s.db.Close()
	}
	var removeErrors []error
	for _, name := range []string{s.path, s.path + "-journal", s.path + "-wal", s.path + "-shm"} {
		if removeErr := os.Remove(name); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			removeErrors = append(removeErrors, removeErr)
		}
	}
	return errors.Join(err, errors.Join(removeErrors...))
}

func encodeCandidateProof(format string, proof candidateProof) ([]byte, []byte, error) {
	switch format {
	case "rpm":
		if proof.rpm == nil || proof.deb != nil {
			return nil, nil, fmt.Errorf("%w: RPM candidate proof is incomplete", ErrInvalidMetadata)
		}
		data, err := json.Marshal(proof.rpm)
		return data, nil, err
	case "deb":
		if proof.deb == nil || proof.rpm != nil {
			return nil, nil, fmt.Errorf("%w: DEB candidate proof is incomplete", ErrInvalidMetadata)
		}
		data, err := json.Marshal(proof.deb)
		return nil, data, err
	default:
		return nil, nil, fmt.Errorf("%w: unsupported candidate format %q", ErrInvalidMetadata, format)
	}
}

func decodeCandidateProof(format string, rpm, deb []byte) (candidateProof, error) {
	var proof candidateProof
	switch format {
	case "rpm":
		if len(rpm) == 0 || len(deb) != 0 {
			return proof, fmt.Errorf("%w: RPM candidate proof is incomplete", ErrInvalidMetadata)
		}
		proof.rpm = &provenance.RPMProof{}
		if err := json.Unmarshal(rpm, proof.rpm); err != nil {
			return candidateProof{}, fmt.Errorf("%w: decode RPM proof: %v", ErrInvalidMetadata, err)
		}
	case "deb":
		if len(deb) == 0 || len(rpm) != 0 {
			return proof, fmt.Errorf("%w: DEB candidate proof is incomplete", ErrInvalidMetadata)
		}
		proof.deb = &provenance.DEBProof{}
		if err := json.Unmarshal(deb, proof.deb); err != nil {
			return candidateProof{}, fmt.Errorf("%w: decode DEB proof: %v", ErrInvalidMetadata, err)
		}
	default:
		return proof, fmt.Errorf("%w: unsupported candidate format %q", ErrInvalidMetadata, format)
	}
	return proof, nil
}

func preferredCandidateProof(current, candidate candidateProof) candidateProof {
	if current.deb != nil && candidate.deb != nil &&
		candidate.deb.PackagesEvidenceSHA256 < current.deb.PackagesEvidenceSHA256 {
		return candidate
	}
	return current
}

func proofsEqual(left, right candidateProof) bool {
	if left.rpm != nil || right.rpm != nil {
		return left.rpm != nil && right.rpm != nil && reflect.DeepEqual(left.rpm, right.rpm)
	}
	return left.deb != nil && right.deb != nil && *left.deb == *right.deb
}
