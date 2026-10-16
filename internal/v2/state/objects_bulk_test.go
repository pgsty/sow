package state

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

func TestListPackageObjectsBulkMembershipProjection(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, distName := range []string{"el9", "el10"} {
		if err := store.AddDist(ctx, Dist{
			Name: distName, Format: "rpm", BuiltGeneration: 1,
			Architectures: []Architecture{{Family: "x86_64", EcosystemArch: "x86_64"}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	objects := make([]PackageObject, 4)
	for index := range objects {
		digest := fmt.Sprintf("%064x", index+1)
		objects[index] = PackageObject{
			SHA256: digest, Format: "rpm", Coordinate: fmt.Sprintf("pkg-%d-0:1-1.x86_64", index),
			Architecture: "x86_64", CanonicalArch: "x86_64",
			PoolPath: fmt.Sprintf("pool/p/pkg-%d/pkg-%d.rpm", index, index),
			Filename: fmt.Sprintf("pkg-%d.rpm", index), Size: 1, Name: fmt.Sprintf("pkg-%d", index),
			Source: fmt.Sprintf("pkg-%d", index), Version: "1", Epoch: "0", Release: "1",
			Kind: "main", Storage: map[bool]string{true: "pending", false: "pool"}[index == 2],
		}
		if err := insertPackageObjectTx(ctx, tx, objects[index]); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	for _, membership := range []struct {
		table, dist string
		index       int
	}{
		{"memberships", "el9", 0}, {"memberships", "el9", 1},
		{"memberships", "el10", 0}, {"memberships", "el10", 2},
		{"built_memberships", "el9", 0}, {"built_memberships", "el10", 1},
		{"prior_built_memberships", "el9", 2},
	} {
		column, value := "created_revision", any(1)
		if membership.table != "memberships" {
			column, value = "generation", GenerationID(1)
		}
		query := `INSERT INTO ` + membership.table + `(dist_name, package_sha256, ` + column + `) VALUES (?, ?, ?)`
		if _, err := tx.ExecContext(ctx, query, membership.dist, objects[membership.index].SHA256, value); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	objects[0].Dists, objects[0].BuiltDists = []string{"el10", "el9"}, []string{"el9"}
	objects[1].Dists, objects[1].BuiltDists = []string{"el9"}, []string{"el10"}
	objects[2].Dists, objects[2].BuiltDists = []string{"el10"}, []string{}
	objects[3].Dists, objects[3].BuiltDists = []string{}, []string{}
	for _, test := range []struct {
		name  string
		dists []string
		built bool
		prior bool
		want  []PackageObject
	}{
		{name: "desired", dists: []string{"el9"}, want: objects[:2]},
		{name: "duplicate and missing dists", dists: []string{"el9", "missing", "el9"}, want: objects[:2]},
		{name: "overlapping dists", dists: []string{"el9", "el10"}, want: objects[:3]},
		{name: "built", dists: []string{"el10"}, built: true, want: objects[1:2]},
		{name: "prior built", dists: []string{"el9"}, prior: true, want: objects[2:3]},
		{name: "missing dist", dists: []string{"missing"}, want: []PackageObject{}},
		{name: "empty prior built", dists: []string{"el10"}, prior: true, want: []PackageObject{}},
		{name: "all", want: objects},
		{name: "empty filter", dists: []string{}, want: objects},
		{name: "all built", built: true, want: objects},
		{name: "all prior built", prior: true, want: objects},
	} {
		t.Run(test.name, func(t *testing.T) {
			var selected []PackageObject
			var err error
			if test.prior {
				selected, err = store.ListPriorBuiltPackageObjects(ctx, test.dists)
			} else {
				selected, err = store.ListPackageObjects(ctx, test.dists, test.built)
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(selected, test.want) {
				t.Fatalf("objects=%#v want=%#v", selected, test.want)
			}
		})
	}
	pending, err := store.ListPendingPackageObjects(ctx)
	if err != nil || len(pending) != 1 || pending[0].SHA256 != objects[2].SHA256 || pending[0].Dists != nil || pending[0].BuiltDists != nil {
		t.Fatalf("pending objects=%#v err=%v", pending, err)
	}
}

func TestPackageMembershipProjectionBatches(t *testing.T) {
	const selectedCount = 1_101
	store, objects := newSparseMembershipFixture(t, 1_200, selectedCount)
	ctx := context.Background()
	conn, err := store.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Open keeps one connection, so returning it to the pool retains this real
	// SQLite limit for all listing calls below, including the 1,101-object set.
	_, limitErr := sqlite.Limit(conn, sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 500)
	closeErr := conn.Close()
	if limitErr != nil || closeErr != nil {
		t.Fatalf("set SQLite bind limit: %v; close connection: %v", limitErr, closeErr)
	}
	for _, built := range []bool{false, true} {
		selected, err := store.ListPackageObjects(ctx, []string{"selected"}, built)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(selected, objects[:selectedCount]) {
			t.Fatalf("built=%t selected objects differ: got=%d want=%d", built, len(selected), selectedCount)
		}
	}
	all, err := store.ListPackageObjects(ctx, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(all, objects) {
		t.Fatal("full membership projection differs")
	}

	// Put duplicate digests on opposite sides of the batch boundary, alongside
	// a digest with no memberships. Each object's ordered projection stays unique.
	requested := append([]PackageObject{}, objects[:selectedCount]...)
	missing := PackageObject{SHA256: fmt.Sprintf("%064x", len(objects)+1)}
	requested = append(requested, objects[0], missing, objects[selectedCount-1])
	for _, table := range []string{"memberships", "built_memberships", "prior_built_memberships"} {
		projection, err := store.packageDistsForObjects(ctx, requested, table, false)
		if err != nil {
			t.Fatal(err)
		}
		if len(projection) != selectedCount+1 || !reflect.DeepEqual(projection[missing.SHA256], []string{}) {
			t.Fatalf("table=%s missing membership projection=%#v", table, projection[missing.SHA256])
		}
		for _, object := range objects[:selectedCount] {
			want := []string{"history", "selected"}
			if table == "prior_built_memberships" {
				want = []string{}
			}
			if !reflect.DeepEqual(projection[object.SHA256], want) {
				t.Fatalf("table=%s digest=%s dists=%v want=%v", table, object.SHA256, projection[object.SHA256], want)
			}
		}
		empty, err := store.packageDistsForObjects(ctx, nil, table, false)
		if err != nil || len(empty) != 0 {
			t.Fatalf("table=%s empty projection=%v err=%v", table, empty, err)
		}
	}
	if _, err := store.packageDistsForObjects(ctx, requested, "package_objects", false); err == nil {
		t.Fatal("accepted an invalid membership table")
	}
}

// newSparseMembershipFixture keeps selected Memberships fixed while unrelated
// history grows. Every object has a history membership in both projections.
func newSparseMembershipFixture(tb testing.TB, objectCount, selectedCount int) (*Store, []PackageObject) {
	tb.Helper()
	ctx := context.Background()
	store, err := Open(filepath.Join(tb.TempDir(), "repo.db"))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = store.Close() })
	for _, distName := range []string{"selected", "history"} {
		if err := store.AddDist(ctx, Dist{
			Name: distName, Format: "rpm", BuiltGeneration: 1,
			Architectures: []Architecture{{Family: "x86_64", EcosystemArch: "x86_64"}},
		}); err != nil {
			tb.Fatal(err)
		}
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		tb.Fatal(err)
	}
	defer tx.Rollback()
	objects := make([]PackageObject, objectCount)
	for index := range objects {
		name := fmt.Sprintf("pkg-%06d", index)
		object := PackageObject{
			SHA256: fmt.Sprintf("%064x", index+1), Format: "rpm", Coordinate: name + "-0:1-1.x86_64",
			Architecture: "x86_64", CanonicalArch: "x86_64", PoolPath: "pool/p/" + name + "/" + name + ".rpm",
			Filename: name + ".rpm", Size: 1, Name: name, Source: name, Version: "1", Epoch: "0", Release: "1",
			Kind: "main", Storage: "pool", Dists: []string{"history"}, BuiltDists: []string{"history"},
		}
		if err := insertPackageObjectTx(ctx, tx, object); err != nil {
			tb.Fatal(err)
		}
		if index < selectedCount {
			object.Dists = append(object.Dists, "selected")
			object.BuiltDists = append(object.BuiltDists, "selected")
		}
		for _, distName := range object.Dists {
			if _, err := tx.ExecContext(ctx, `INSERT INTO memberships(dist_name, package_sha256, created_revision) VALUES (?, ?, 1)`, distName, object.SHA256); err != nil {
				tb.Fatal(err)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO built_memberships(dist_name, package_sha256, generation) VALUES (?, ?, ?)`, distName, object.SHA256, GenerationID(1)); err != nil {
				tb.Fatal(err)
			}
		}
		objects[index] = object
	}
	if err := tx.Commit(); err != nil {
		tb.Fatal(err)
	}
	return store, objects
}
