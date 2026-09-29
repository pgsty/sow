package state

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPackagePoolPathOwnersScopesCandidatesAndUsesIndexes(t *testing.T) {
	ctx := context.Background()
	store, binding, manifest := publicationStoreFixture(t)
	defer store.Close()
	attempt, _, _ := seedPublicationGrace(t, store, binding, manifest, time.Now().UTC())
	const abandoned = "pool/o/Old/Old.rpm"
	if _, err := store.DB().Exec(`INSERT INTO publication_abandoned_objects(attempt_identity, path, phase, size, sha256, remote_identity) VALUES (?, ?, 'payload', 1, ?, 'old')`, attempt.AttemptIdentity, abandoned, strings.Repeat("2", 64)); err != nil {
		t.Fatal(err)
	}
	paths := []string{strings.ToUpper(manifest[1].Path), strings.ToLower(abandoned)}
	for i := range poolPathBatchSize + 1 {
		paths = append(paths, fmt.Sprintf("pool/n/not-present/pkg-%d.rpm", i))
	}
	paths = append(paths, manifest[1].Path)
	owners, err := store.PackagePoolPathOwners(ctx, paths)
	if err != nil || len(owners) != 2 {
		t.Fatalf("candidate owners=%v err=%v", owners, err)
	}
	if err := owners.Check(PackageObject{PoolPath: manifest[1].Path, SHA256: strings.Repeat("1", 64)}); err != nil {
		t.Fatal(err)
	}
	if err := owners.Check(PackageObject{PoolPath: strings.ToUpper(manifest[1].Path), SHA256: strings.Repeat("1", 64)}); !errors.Is(err, ErrPoolPathConflict) {
		t.Fatalf("same bytes under a case-variant spelling were accepted: %v", err)
	}
	if err := owners.Check(PackageObject{PoolPath: strings.ToUpper(abandoned), SHA256: strings.Repeat("3", 64)}); err == nil {
		t.Fatal("abandoned URL was allowed to change bytes")
	}
	if err := owners.Check(PackageObject{PoolPath: manifest[0].Path, SHA256: strings.Repeat("4", 64)}); err != nil {
		t.Fatalf("non-payload path was reserved: %v", err)
	}
	unrelated, err := store.PackagePoolPathOwners(ctx, []string{"pool/n/new/pkg.rpm"})
	if err != nil || len(unrelated) != 0 {
		t.Fatalf("unrelated history entered the candidate set: %v %v", unrelated, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if empty, err := store.PackagePoolPathOwners(cancelled, nil); err != nil || len(empty) != 0 {
		t.Fatalf("empty candidate set queried the database: %v %v", empty, err)
	}
	rows, err := store.DB().Query("EXPLAIN QUERY PLAN "+poolPathOwnersQuery(1), manifest[1].Path, manifest[1].Path, manifest[1].Path)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plans []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plans = append(plans, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	plan := strings.Join(plans, "\n")
	for _, table := range []string{"package_objects", "publication_inventory", "publication_abandoned_objects"} {
		if !strings.Contains(plan, "SEARCH "+table+" USING INDEX ") {
			t.Fatalf("candidate lookup does not search an index for %s:\n%s", table, plan)
		}
	}
	if strings.Contains(plan, "SCAN ") || strings.Contains(plan, "UNION USING TEMP") {
		t.Fatalf("candidate lookup scans or deduplicates full history:\n%s", plan)
	}
	t.Log(plan)
}

func TestV13MigrationPreservesV12ReadOnlyAndAddsPoolPathIndexes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "repo.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`DROP INDEX package_objects_pool_path_folded;
DROP INDEX publication_inventory_payload_path_folded;
DROP INDEX publication_abandoned_payload_path_folded;
DELETE FROM schema_migrations WHERE version = 13;
PRAGMA user_version = 12;`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	if reader.SchemaVersion() != 12 {
		t.Fatalf("reader schema=%d", reader.SchemaVersion())
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if writer, err := OpenExisting(path); !errors.Is(err, ErrSchema) || !errors.Is(err, ErrSchemaMigrationRequired) || strings.Contains(err.Error(), "corrupt") {
		if writer != nil {
			writer.Close()
		}
		t.Fatalf("ordinary writer did not report the explicit migration boundary: %v", err)
	}
	upgraded, err := OpenExistingForMigration(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	if upgraded.SchemaVersion() != 13 || upgraded.OpenedSchemaVersion() != 12 {
		t.Fatalf("writer schema=%d opened=%d", upgraded.SchemaVersion(), upgraded.OpenedSchemaVersion())
	}
	if err := upgraded.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// This opt-in benchmark measures the actual indexed query against synthetic
// retained inventory. Setup is outside timing and does not read package bytes.
func BenchmarkPackagePoolPathOwnersHistory(b *testing.B) {
	for _, history := range []int{1000, 1000000} {
		b.Run(fmt.Sprintf("rows=%d", history), func(b *testing.B) {
			store, binding, manifest := publicationStoreFixture(b)
			defer store.Close()
			_, checkpoint, _ := seedPublicationGrace(b, store, binding, manifest, time.Now().UTC())
			_, err := store.DB().Exec(`WITH RECURSIVE history(n) AS (
SELECT 1 UNION ALL SELECT n + 1 FROM history WHERE n < ?
) INSERT INTO publication_inventory(checkpoint_identity, path, phase, size, sha256, remote_identity)
SELECT ?, printf('pool/p/history/pkg-%07d.rpm', n), 'payload', 1, ?, 'fixture' FROM history`, history, checkpoint.CheckpointIdentity, strings.Repeat("7", 64))
			if err != nil {
				b.Fatal(err)
			}
			if err := store.Checkpoint(context.Background()); err != nil {
				b.Fatal(err)
			}
			paths := []string{manifest[1].Path, "pool/n/not-present/pkg.rpm"}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				owners, err := store.PackagePoolPathOwners(context.Background(), paths)
				if err != nil || len(owners) != 1 {
					b.Fatalf("owners=%v err=%v", owners, err)
				}
			}
		})
	}
}
