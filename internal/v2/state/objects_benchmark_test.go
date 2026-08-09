package state

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
)

// BenchmarkListPackageObjectsDistinct exercises the state shape used by a
// large Managed build: every package is a distinct object and participates in
// both Desired and Built Membership. Keep the fixture large enough to expose
// per-object membership lookups without making the ordinary test suite pay the
// setup cost.
func BenchmarkListPackageObjectsDistinct(b *testing.B) {
	benchmarkListPackageObjectsDistinct(b, 5_000)
}

func BenchmarkListPackageObjectsDistinct50K(b *testing.B) {
	benchmarkListPackageObjectsDistinct(b, 50_000)
}

func benchmarkListPackageObjectsDistinct(b *testing.B, objectCount int) {
	ctx := context.Background()
	store, err := Open(filepath.Join(b.TempDir(), "repo.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = store.Close() })
	if err := store.AddDist(ctx, Dist{
		Name: "el9", Format: "rpm", BuiltGeneration: 1,
		Architectures: []Architecture{{Family: "x86_64", EcosystemArch: "x86_64"}},
	}); err != nil {
		b.Fatal(err)
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		b.Fatal(err)
	}
	for index := range objectCount {
		digest := fmt.Sprintf("%064x", index+1)
		object := PackageObject{
			SHA256: digest, Format: "rpm", Coordinate: fmt.Sprintf("pkg-%d-0:1.0-1.x86_64", index),
			Architecture: "x86_64", CanonicalArch: "x86_64",
			PoolPath: fmt.Sprintf("pool/p/pkg-%d/pkg-%d-1.0-1.x86_64.rpm", index, index),
			Filename: fmt.Sprintf("pkg-%d-1.0-1.x86_64.rpm", index), Size: 1,
			Name: fmt.Sprintf("pkg-%d", index), Source: fmt.Sprintf("pkg-%d", index),
			Version: "1.0", Epoch: "0", Release: "1", Kind: "main", Storage: "pool",
		}
		if err := insertPackageObjectTx(ctx, tx, object); err != nil {
			_ = tx.Rollback()
			b.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO memberships(dist_name, package_sha256, created_revision) VALUES ('el9', ?, 1)`, digest); err != nil {
			_ = tx.Rollback()
			b.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO built_memberships(dist_name, package_sha256, generation) VALUES ('el9', ?, ?)`, digest, GenerationID(1)); err != nil {
			_ = tx.Rollback()
			b.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}

	b.ReportMetric(float64(objectCount), "objects/op")
	b.ResetTimer()
	for range b.N {
		objects, err := store.ListPackageObjects(ctx, []string{"el9"}, false)
		if err != nil {
			b.Fatal(err)
		}
		if len(objects) != objectCount {
			b.Fatalf("objects=%d want=%d", len(objects), objectCount)
		}
	}
}
