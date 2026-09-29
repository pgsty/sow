package managed

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/v2/state"
)

// Count calls while executing the real SQLite query and membership expansion.
// This detects repeated full loads without relying on wall-clock thresholds.
type countingReferenceStore struct {
	*state.Store
	loads int
}

func (store *countingReferenceStore) ListPackageObjects(ctx context.Context, dists []string, built bool) ([]state.PackageObject, error) {
	store.loads++
	return store.Store.ListPackageObjects(ctx, dists, built)
}

func referenceStoreFixture(t testing.TB, objects []state.PackageObject) *countingReferenceStore {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, dist := range []state.Dist{{Name: "el9", Format: "rpm", EffectiveConfigSHA256: "rpm"}, {Name: "noble", Format: "deb", EffectiveConfigSHA256: "deb"}} {
		if err := store.AddDist(context.Background(), dist); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := store.DB().Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	insert, err := tx.Prepare(`INSERT INTO package_objects
(sha256, format, coordinate, architecture, pool_path, size, name, source, version,
 epoch, release, canonical_arch, kind, filename, storage, created_revision)
VALUES (?, ?, ?, ?, ?, 1, ?, ?, '1', '', '', 'x86_64', 'main', ?, 'pool', 0)`)
	if err != nil {
		t.Fatal(err)
	}
	defer insert.Close()
	membership, err := tx.Prepare(`INSERT INTO memberships(dist_name, package_sha256, created_revision) VALUES (?, ?, 0)`)
	if err != nil {
		t.Fatal(err)
	}
	defer membership.Close()
	for _, object := range objects {
		arch, dist := "x86_64", "el9"
		if object.Format == "deb" {
			arch, dist = "amd64", "noble"
		}
		poolPath, err := managedPoolPath(object.Name, object.Filename)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := insert.Exec(object.SHA256, object.Format, object.Coordinate, arch, poolPath, object.Name, object.Name, object.Filename); err != nil {
			t.Fatal(err)
		}
		if _, err := membership.Exec(dist, object.SHA256); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return &countingReferenceStore{Store: store}
}

func TestResolvePackageReferencesLoadsOnceAndPreservesMatching(t *testing.T) {
	objects := []state.PackageObject{
		{SHA256: strings.Repeat("1", 64), Format: "rpm", Name: "foo", Coordinate: "foo-1-1.x86_64", Filename: "foo-1.rpm"},
		{SHA256: strings.Repeat("2", 64), Format: "rpm", Name: "foo", Coordinate: "foo-2-1.x86_64", Filename: "foo-2.rpm"},
		{SHA256: strings.Repeat("3", 64), Format: "rpm", Name: "other", Coordinate: "other-1-1.x86_64", Filename: "foo-1.rpm"},
		{SHA256: strings.Repeat("4", 64), Format: "deb", Name: "foo", Coordinate: "foo=1:amd64", Filename: "foo.deb"},
	}
	store := referenceStoreFixture(t, objects)
	tests := []struct {
		name       string
		references []string
		dists      []string
		nameWide   bool
		want       []string
		errText    string
		loads      int
	}{
		{"mixed references deduplicate", []string{"rpm:foo-1-1.x86_64", "sha256:" + objects[1].SHA256, "foo", "foo-2.rpm"}, []string{"el9"}, true, []string{objects[0].SHA256, objects[1].SHA256}, "", 1},
		{"format scope", []string{"foo", "deb:foo=1:amd64"}, []string{"noble"}, false, []string{objects[3].SHA256}, "", 1},
		{"all formats sorted", []string{"rpm:foo-1-1.x86_64", "deb:foo=1:amd64"}, nil, false, []string{objects[3].SHA256, objects[0].SHA256}, "", 1},
		{"bare name ambiguous", []string{"foo"}, []string{"el9"}, false, nil, "ambiguous", 1},
		{"filename stays ambiguous", []string{"foo-1.rpm"}, []string{"el9"}, true, nil, "ambiguous", 1},
		{"missing precedes later invalid", []string{"missing", " bad"}, []string{"el9"}, true, nil, `"missing" matches no Desired Membership`, 1},
		{"ambiguity precedes later invalid", []string{"foo", " bad"}, []string{"el9"}, false, nil, "ambiguous", 1},
		{"later invalid", []string{"foo-2.rpm", " bad"}, []string{"el9"}, true, nil, "invalid package reference", 1},
		{"first invalid never loads", []string{" bad", "foo"}, nil, true, nil, "invalid package reference", 0},
		{"bad digest", []string{"sha256:short"}, nil, true, nil, "64 lowercase hexadecimal", 1},
		{"empty coordinate", []string{"rpm:"}, nil, true, nil, "empty package coordinate", 1},
		{"empty batch never loads", nil, nil, true, nil, "no package references resolved", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store.loads = 0
			got, err := resolvePackageReferencesFrom(context.Background(), store.ListPackageObjects, tt.references, tt.dists, tt.nameWide)
			if tt.errText != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errText) {
					t.Fatalf("error=%v, want %q", err, tt.errText)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			var digests []string
			for _, object := range got {
				digests = append(digests, object.SHA256)
			}
			if !reflect.DeepEqual(digests, tt.want) || store.loads != tt.loads {
				t.Fatalf("digests=%v loads=%d, want %v loads=%d", digests, store.loads, tt.want, tt.loads)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolvePackageReferencesFrom(ctx, store.ListPackageObjects, []string{"foo"}, []string{"el9"}, true); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled batch = %v", err)
	}
}

// Compare the prior per-reference query pattern with the batch entry point on
// real SQLite. Synthetic objects isolate metadata loading; no payloads are read.
func BenchmarkResolvePackageReferencesBatch(b *testing.B) {
	for _, count := range []int{1000, 10000} {
		objects := make([]state.PackageObject, count)
		for index := range count {
			name := fmt.Sprintf("pkg-%05d", index)
			objects[index] = state.PackageObject{SHA256: fmt.Sprintf("%064x", index+1), Format: "rpm", Name: name, Coordinate: name + "-1-1.x86_64", Filename: name + ".rpm"}
		}
		b.Run(fmt.Sprintf("objects=%d", count), func(b *testing.B) {
			store := referenceStoreFixture(b, objects)
			references := make([]string, 100)
			for index := range references {
				references[index] = objects[index].Name
			}
			for _, repeated := range []bool{true, false} {
				name := "batch"
				if repeated {
					name = "prior_repeated_load"
				}
				b.Run(name, func(b *testing.B) {
					store.loads = 0
					b.ReportAllocs()
					b.ResetTimer()
					for range b.N {
						if repeated {
							for _, reference := range references {
								store.loads++
								if got, err := resolvePackageReference(context.Background(), store.Store, reference, []string{"el9"}, true); err != nil || len(got) != 1 {
									b.Fatalf("prior resolution=%d err=%v", len(got), err)
								}
							}
						} else if got, err := resolvePackageReferencesFrom(context.Background(), store.ListPackageObjects, references, []string{"el9"}, true); err != nil || len(got) != len(references) {
							b.Fatalf("batch resolution=%d err=%v", len(got), err)
						}
					}
					b.ReportMetric(float64(store.loads)/float64(b.N), "object-loads/op")
				})
			}
		})
	}
}
