package state

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
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
	objects := make([]PackageObject, 3)
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
	} {
		column, value := "created_revision", any(1)
		if membership.table == "built_memberships" {
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

	selected, err := store.ListPackageObjects(ctx, []string{"el9"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 2 {
		t.Fatalf("selected objects=%d want=2", len(selected))
	}
	byDigest := map[string]PackageObject{}
	for _, object := range selected {
		byDigest[object.SHA256] = object
	}
	if object := byDigest[objects[0].SHA256]; !reflect.DeepEqual(object.Dists, []string{"el10", "el9"}) || !reflect.DeepEqual(object.BuiltDists, []string{"el9"}) {
		t.Fatalf("shared membership projection=%#v", object)
	}
	if object := byDigest[objects[1].SHA256]; !reflect.DeepEqual(object.Dists, []string{"el9"}) || !reflect.DeepEqual(object.BuiltDists, []string{"el10"}) {
		t.Fatalf("selected membership projection=%#v", object)
	}
	pending, err := store.ListPendingPackageObjects(ctx)
	if err != nil || len(pending) != 1 || pending[0].SHA256 != objects[2].SHA256 || pending[0].Dists != nil || pending[0].BuiltDists != nil {
		t.Fatalf("pending objects=%#v err=%v", pending, err)
	}
}
