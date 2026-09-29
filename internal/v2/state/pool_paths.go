package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ErrPoolPathConflict identifies a deterministic input conflict that an
// unapplied mutation can safely reject, rather than retry forever.
var ErrPoolPathConflict = errors.New("immutable pool path conflict")

// PoolPathOwners retains every known byte identity, including historical
// publications. Removing a local object or producing a report-only remote GC
// result does not release its URL for different bytes.
type PoolPathOwners map[string]map[poolPathOwner]struct{}

type poolPathOwner struct{ path, sha256 string }

// Check rejects different bytes at a case-folded path, and also a different
// spelling of a known path even for identical bytes: on a case-insensitive
// filesystem both spellings are one file, so they cannot be two URLs.
func (owners PoolPathOwners) Check(object PackageObject) error {
	for owner := range owners[strings.ToLower(object.PoolPath)] {
		if owner.sha256 != object.SHA256 {
			return fmt.Errorf("%w: %w: %s collides case-insensitively with existing or published content; use a different package filename", ErrConflict, ErrPoolPathConflict, object.PoolPath)
		}
		if owner.path != object.PoolPath {
			return fmt.Errorf("%w: %w: %s differs only by case from existing or published path %s; add the file under that exact name", ErrConflict, ErrPoolPathConflict, object.PoolPath, owner.path)
		}
	}
	return nil
}

func (owners PoolPathOwners) Add(object PackageObject) {
	key := strings.ToLower(object.PoolPath)
	if owners[key] == nil {
		owners[key] = map[poolPathOwner]struct{}{}
	}
	owners[key][poolPathOwner{path: object.PoolPath, sha256: object.SHA256}] = struct{}{}
}

// PackagePoolPathOwners loads only the candidate paths. An empty batch performs
// no query; unrelated retained history never enters the admission working set.
func (s *Store) PackagePoolPathOwners(ctx context.Context, paths []string) (PoolPathOwners, error) {
	return packagePoolPathOwners(ctx, s.db, paths)
}

const poolPathBatchSize = 256

func poolPathOwnersQuery(count int) string {
	placeholders := strings.TrimSuffix(strings.Repeat("?,", count), ",")
	return `SELECT pool_path, sha256 FROM package_objects WHERE lower(pool_path) IN (` + placeholders + `)
UNION ALL SELECT path, sha256 FROM publication_inventory WHERE phase = 'payload' AND lower(path) IN (` + placeholders + `)
UNION ALL SELECT path, sha256 FROM publication_abandoned_objects WHERE phase = 'payload' AND lower(path) IN (` + placeholders + `)`
}

func packagePoolPathOwners(ctx context.Context, db interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, paths []string) (PoolPathOwners, error) {
	owners := PoolPathOwners{}
	unique := make(map[string]struct{}, len(paths))
	candidates := make([]any, 0, len(paths))
	for _, path := range paths {
		folded := strings.ToLower(path)
		if _, exists := unique[folded]; !exists {
			unique[folded] = struct{}{}
			candidates = append(candidates, folded)
		}
	}
	for start := 0; start < len(candidates); start += poolPathBatchSize {
		batch := candidates[start:min(start+poolPathBatchSize, len(candidates))]
		args := make([]any, 0, 3*len(batch))
		for range 3 {
			args = append(args, batch...)
		}
		rows, err := db.QueryContext(ctx, poolPathOwnersQuery(len(batch)), args...)
		if err != nil {
			return nil, fmt.Errorf("read immutable pool path owners: %w", err)
		}
		for rows.Next() {
			var object PackageObject
			if err := rows.Scan(&object.PoolPath, &object.SHA256); err != nil {
				return nil, errors.Join(err, rows.Close())
			}
			owners.Add(object)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return nil, err
		}
	}
	return owners, nil
}
