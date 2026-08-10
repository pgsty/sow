package managed

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

func TestPackageQueriesAndCheapStatus(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	clean, err := Status(ctx, StatusOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo"})
	if err != nil || clean.Status != "clean" || !clean.ReadyToCopy || clean.BuiltGeneration < 1 {
		t.Fatalf("initial clean status=%#v err=%v", clean, err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	added, err := Add(ctx, AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Skip: true, Jobs: 1})
	if err != nil {
		t.Fatal(err)
	}
	listed, err := ListPackages(ctx, PackageListOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}})
	if err != nil || len(listed.Packages) != 1 || !listed.Dirty || len(listed.Packages[0].BuiltDists) != 0 {
		t.Fatalf("listed=%#v err=%v", listed, err)
	}
	object := listed.Packages[0]
	shown, err := ShowPackage(ctx, PackageShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Reference: "sha256:" + object.SHA256})
	if err != nil || shown.Package.Coordinate != object.Coordinate {
		t.Fatalf("shown=%#v err=%v", shown, err)
	}
	where, err := WherePackage(ctx, PackageWhereOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Reference: "rpm:" + object.Coordinate})
	if err != nil || len(where.Locations) != 1 || where.Locations[0].Repository != "repo" {
		t.Fatalf("where=%#v err=%v", where, err)
	}
	status, err := Status(ctx, StatusOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo"})
	if err != nil || status.Status != "dirty" || status.ReadyToCopy || status.Pending.Count != 1 || status.Pending.Bytes == 0 || status.DesiredRevision != added.Revision || !strings.Contains(strings.Join(status.DirtyReasons, "\n"), "Desired and Built membership sets differ") {
		t.Fatalf("status=%#v err=%v", status, err)
	}
	lock, err := acquireFileLock(ctx, filepath.Join(root, ".sow", "repo-locks", "repo.lock"), 0, false)
	if err != nil {
		t.Fatal(err)
	}
	locked, err := Status(ctx, StatusOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo"})
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err != nil || !locked.RepositoryLocked || !strings.Contains(locked.LockHolder, "pid=") {
		t.Fatalf("locked status=%#v err=%v", locked, err)
	}
}

func TestScopedStatusAndCheckIgnoreOtherDistDirtyPendingPayload(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	options := WorkspaceOptions{Workdir: root, CWD: root}
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{
		"el9": {Format: "rpm"}, "noble": {Format: "deb"},
	}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Skip: true, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	global, err := Status(ctx, StatusOptions{WorkspaceOptions: options, Repository: "repo"})
	if err != nil || global.Status != "dirty" || global.ReadyToCopy || global.Pending.Count != 1 {
		t.Fatalf("global status=%#v err=%v", global, err)
	}
	scoped, err := Status(ctx, StatusOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"noble"}})
	if err != nil || scoped.Status != "clean" || !scoped.ReadyToCopy || scoped.Pending.Count != 0 || len(scoped.DirtyDists) != 0 {
		t.Fatalf("noble scoped status=%#v err=%v", scoped, err)
	}
	listed, err := ListPackages(ctx, PackageListOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"noble"}})
	if err != nil || listed.Dirty || len(listed.Packages) != 0 || !reflect.DeepEqual(listed.Dists, []string{"noble"}) {
		t.Fatalf("noble scoped list=%#v err=%v", listed, err)
	}
	dirtyList, err := ListPackages(ctx, PackageListOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}})
	if err != nil || !dirtyList.Dirty || len(dirtyList.Packages) != 1 {
		t.Fatalf("el9 scoped list=%#v err=%v", dirtyList, err)
	}
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"noble"}, Jobs: 1})
	if err != nil || checked.Status != "clean" || !checked.ReadyToCopy {
		t.Fatalf("noble scoped check=%#v err=%v", checked, err)
	}
}

func TestWhereIgnoresPoolObjectWithoutDesiredMembership(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	options := WorkspaceOptions{Workdir: root, CWD: root}
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	listed, err := ListPackages(ctx, PackageListOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}})
	if err != nil || len(listed.Packages) != 1 {
		t.Fatalf("listed=%#v err=%v", listed, err)
	}
	object := listed.Packages[0]
	if _, err := Remove(ctx, RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"sha256:" + object.SHA256}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := WherePackage(ctx, PackageWhereOptions{WorkspaceOptions: options, Reference: "sha256:" + object.SHA256}); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("where returned orphaned Pool object: %v", err)
	}
	shown, err := ShowPackage(ctx, PackageShowOptions{WorkspaceOptions: options, Repository: "repo", Reference: "sha256:" + object.SHA256})
	if err != nil || len(shown.Package.Dists) != 0 {
		t.Fatalf("object-level show should retain orphaned Pool object: shown=%#v err=%v", shown, err)
	}
}

func TestPackageQueriesRejectAmbiguousBareName(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	listed, err := ListPackages(ctx, PackageListOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}})
	if err != nil || len(listed.Packages) != 1 {
		t.Fatalf("listed=%#v err=%v", listed, err)
	}
	original := listed.Packages[0]
	alternateSHA := strings.Repeat("b", 64)
	alternateCoordinate := original.Coordinate + ".alternate"
	database := filepath.Join(root, ".sow", "repo.db")
	store, err := state.OpenExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := store.DB().BeginTx(ctx, nil)
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	_, insertObjectErr := tx.ExecContext(ctx, `
		INSERT INTO package_objects(
			sha256, format, coordinate, architecture, pool_path, size,
			name, source, version, epoch, release, canonical_arch, kind, filename,
			payload_sha256, signature_key, warning, storage, created_revision
		)
		SELECT ?, format, ?, architecture, ?, size,
			name, source, '999', epoch, release, canonical_arch, kind, ?,
			NULL, signature_key, warning, 'pool', created_revision
		FROM package_objects WHERE sha256 = ?`,
		alternateSHA, alternateCoordinate, "pool/p/pgdg-redhat-nonfree-repo/alternate.rpm", "alternate.rpm", original.SHA256)
	_, insertMembershipErr := tx.ExecContext(ctx, `INSERT INTO memberships(dist_name, package_sha256, created_revision) VALUES ('el9', ?, 0)`, alternateSHA)
	var generation state.GenerationID
	generationErr := tx.QueryRowContext(ctx, `SELECT built_generation FROM repository_state WHERE singleton = 1`).Scan(&generation)
	_, insertBuiltErr := tx.ExecContext(ctx, `INSERT INTO built_memberships(dist_name, package_sha256, generation) VALUES ('el9', ?, ?)`, alternateSHA, generation)
	commitErr := tx.Commit()
	closeErr := store.Close()
	if err := errors.Join(insertObjectErr, insertMembershipErr, generationErr, insertBuiltErr, commitErr, closeErr); err != nil {
		t.Fatal(err)
	}

	for name, query := range map[string]func() error{
		"show": func() error {
			_, err := ShowPackage(ctx, PackageShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Reference: original.Name})
			return err
		},
		"where": func() error {
			_, err := WherePackage(ctx, PackageWhereOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Reference: original.Name})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := query()
			if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "ambiguous") || !strings.Contains(err.Error(), original.Coordinate) || !strings.Contains(err.Error(), alternateCoordinate) {
				t.Fatalf("ambiguity error=%v", err)
			}
		})
	}

	where, err := WherePackage(ctx, PackageWhereOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Reference: "sha256:" + original.SHA256})
	if err != nil || len(where.Locations) != 1 || where.Locations[0].SHA256 != original.SHA256 {
		t.Fatalf("exact where=%#v err=%v", where, err)
	}
	store, err = state.OpenReadOnly(database)
	if err != nil {
		t.Fatal(err)
	}
	matches, resolveErr := resolvePackageReference(ctx, store, original.Name, []string{"el9"}, true)
	closeErr = store.Close()
	if err := errors.Join(resolveErr, closeErr); err != nil || len(matches) != 2 {
		t.Fatalf("name-wide matches=%#v err=%v", matches, err)
	}
}

func TestWherePackageDistFilterSpansRepositories(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo-a"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	cfg.Repositories["repo-b"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el10": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	for _, target := range []struct {
		repository string
		dist       string
	}{{"repo-a", "el9"}, {"repo-b", "el10"}} {
		if _, err := Add(ctx, AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: target.repository, Dists: []string{target.dist}, Paths: []string{rpm}, Jobs: 1}); err != nil {
			t.Fatalf("add to %s/%s: %v", target.repository, target.dist, err)
		}
	}
	listed, err := ListPackages(ctx, PackageListOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo-a", Dists: []string{"el9"}})
	if err != nil || len(listed.Packages) != 1 {
		t.Fatalf("listed=%#v err=%v", listed, err)
	}
	result, err := WherePackage(ctx, PackageWhereOptions{
		WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root},
		Dists:            []string{"el9", "el10"},
		Reference:        "sha256:" + listed.Packages[0].SHA256,
	})
	if err != nil || len(result.Locations) != 2 || result.Locations[0].Repository != "repo-a" || result.Locations[1].Repository != "repo-b" {
		t.Fatalf("cross-repository where=%#v err=%v", result, err)
	}
	updated, err := config.Load(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	dist := updated.Repositories["repo-a"].Dists["el9"]
	dist.Limit = 1
	repository := updated.Repositories["repo-a"]
	repository.Dists["el9"] = dist
	updated.Repositories["repo-a"] = repository
	writeManagedConfig(t, root, updated)
	listed, err = ListPackages(ctx, PackageListOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo-a", Dists: []string{"el9"}})
	if err != nil || !listed.Dirty {
		t.Fatalf("config-dirty list=%#v err=%v", listed, err)
	}
	if _, err := WherePackage(ctx, PackageWhereOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Dists: []string{"missing"}, Reference: "sha256:" + listed.Packages[0].SHA256}); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "not configured in any repository") {
		t.Fatalf("missing Dist error=%v", err)
	}
}

func TestWherePackageRejectsAmbiguousBareNameAcrossRepositories(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	options := WorkspaceOptions{Workdir: root, CWD: root}
	cfg := config.Default()
	cfg.Repositories["repo-a"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	cfg.Repositories["repo-b"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	for _, repository := range []string{"repo-a", "repo-b"} {
		if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: repository, Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
			t.Fatalf("add to %s: %v", repository, err)
		}
	}
	listed, err := ListPackages(ctx, PackageListOptions{WorkspaceOptions: options, Repository: "repo-b", Dists: []string{"el9"}})
	if err != nil || len(listed.Packages) != 1 {
		t.Fatalf("repo-b list=%#v err=%v", listed, err)
	}
	original := listed.Packages[0]
	alternateSHA := strings.Repeat("c", 64)
	alternateCoordinate := original.Name + "-0:999-1." + original.CanonicalArch
	store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo-b.db"))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := store.DB().BeginTx(ctx, nil)
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	_, insertErr := tx.ExecContext(ctx, `
		INSERT INTO package_objects(
			sha256, format, coordinate, architecture, pool_path, size,
			name, source, version, epoch, release, canonical_arch, kind, filename,
			payload_sha256, signature_key, warning, storage, created_revision
		)
		SELECT ?, format, ?, architecture, ?, size,
			name, source, '999', epoch, '1', canonical_arch, kind, ?,
			NULL, signature_key, warning, 'pool', created_revision
		FROM package_objects WHERE sha256 = ?`,
		alternateSHA, alternateCoordinate, "pool/p/pgdg-redhat-nonfree-repo/alternate.rpm", "alternate.rpm", original.SHA256)
	_, deleteErr := tx.ExecContext(ctx, `DELETE FROM memberships WHERE dist_name = 'el9' AND package_sha256 = ?`, original.SHA256)
	_, membershipErr := tx.ExecContext(ctx, `INSERT INTO memberships(dist_name, package_sha256, created_revision) VALUES ('el9', ?, 0)`, alternateSHA)
	commitErr := tx.Commit()
	checkpointErr := store.Checkpoint(ctx)
	closeErr := store.Close()
	if err := errors.Join(insertErr, deleteErr, membershipErr, commitErr, checkpointErr, closeErr); err != nil {
		t.Fatal(err)
	}

	_, err = WherePackage(ctx, PackageWhereOptions{WorkspaceOptions: options, Reference: original.Name})
	if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "ambiguous across repositories") ||
		!strings.Contains(err.Error(), "repo-a:") || !strings.Contains(err.Error(), "repo-b:") ||
		!strings.Contains(err.Error(), original.Coordinate) || !strings.Contains(err.Error(), alternateCoordinate) {
		t.Fatalf("cross-Repository ambiguity error=%v", err)
	}
}

func TestStatusReportsRecoveringAndErrorWithoutRepair(t *testing.T) {
	t.Run("recovering", func(t *testing.T) {
		ctx := context.Background()
		root := t.TempDir()
		cfg := config.Default()
		cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
		writeManagedConfig(t, root, cfg)
		if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
			t.Fatal(err)
		}
		inputs := filepath.Join(root, "inputs")
		if err := os.Mkdir(inputs, 0o755); err != nil {
			t.Fatal(err)
		}
		rpm := decodeManagedFixture(t, filepath.Join("..", "..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
		injected := errors.New("injected applied failure")
		_, err := Add(ctx, AddOptions{
			WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Skip: true, Jobs: 1,
			Fault: func(point string) error {
				if point == "add.applied" {
					return injected
				}
				return nil
			},
		})
		if !errors.Is(err, injected) {
			t.Fatalf("fault=%v", err)
		}
		before, err := publicTreeSnapshot(root, "repo")
		if err != nil {
			t.Fatal(err)
		}
		status, err := Status(ctx, StatusOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo"})
		if err != nil || status.Status != "recovering" || status.ReadyToCopy || status.Operation == nil || status.Operation.State != state.OperationApplied || status.RecentOperation == nil || status.RecentOperation.ID == status.Operation.ID || (status.RecentOperation.State != state.OperationDone && status.RecentOperation.State != state.OperationDoneDirty && status.RecentOperation.State != state.OperationRolledBack && status.RecentOperation.State != state.OperationFailed) {
			t.Fatalf("recovering status=%#v err=%v", status, err)
		}
		after, err := publicTreeSnapshot(root, "repo")
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatalf("status changed public tree: before=%#v after=%#v err=%v", before, after, err)
		}
		store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
		if err != nil {
			t.Fatal(err)
		}
		pending, pendingErr := store.PendingOperations(ctx)
		closeErr := store.Close()
		if err := errors.Join(pendingErr, closeErr); err != nil || len(pending) != 1 || pending[0].State != state.OperationApplied {
			t.Fatalf("status repaired operation: pending=%#v err=%v", pending, err)
		}
	})

	t.Run("error", func(t *testing.T) {
		ctx := context.Background()
		root := t.TempDir()
		cfg := config.Default()
		cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
		writeManagedConfig(t, root, cfg)
		if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
			t.Fatal(err)
		}
		database := filepath.Join(root, ".sow", "repo.db")
		store, err := state.OpenExisting(database)
		if err != nil {
			t.Fatal(err)
		}
		_, mutationErr := store.DB().ExecContext(ctx, `DELETE FROM dists WHERE name = 'el9'`)
		closeErr := store.Close()
		if err := errors.Join(mutationErr, closeErr); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(database)
		if err != nil {
			t.Fatal(err)
		}
		status, err := Status(ctx, StatusOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo"})
		if err != nil || status.Status != "error" || status.ReadyToCopy || len(status.DirtyDists) != 1 || status.DirtyDists[0] != "el9" {
			t.Fatalf("error status=%#v err=%v", status, err)
		}
		after, err := os.ReadFile(database)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("status changed corrupt database: err=%v", err)
		}
	})

	t.Run("semantic state error", func(t *testing.T) {
		ctx := context.Background()
		root := t.TempDir()
		cfg := config.Default()
		cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
		writeManagedConfig(t, root, cfg)
		if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
			t.Fatal(err)
		}
		inputs := filepath.Join(root, "inputs")
		if err := os.Mkdir(inputs, 0o755); err != nil {
			t.Fatal(err)
		}
		rpm := decodeManagedFixture(t, filepath.Join("..", "..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
		if _, err := Add(ctx, AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
			t.Fatal(err)
		}
		database := filepath.Join(root, ".sow", "repo.db")
		store, err := state.OpenExisting(database)
		if err != nil {
			t.Fatal(err)
		}
		_, mutationErr := store.DB().ExecContext(ctx, `UPDATE built_memberships SET generation = '00000000000000000999'`)
		checkpointErr := store.Checkpoint(ctx)
		closeErr := store.Close()
		if err := errors.Join(mutationErr, checkpointErr, closeErr); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(database)
		if err != nil {
			t.Fatal(err)
		}
		status, err := Status(ctx, StatusOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo"})
		hasSemanticReason := false
		for _, reason := range status.DirtyReasons {
			if strings.Contains(reason, "semantic state relations are invalid") {
				hasSemanticReason = true
			}
		}
		if err != nil || status.Status != "error" || status.ReadyToCopy || !hasSemanticReason {
			t.Fatalf("semantic error status=%#v err=%v", status, err)
		}
		after, err := os.ReadFile(database)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("status changed semantic-corrupt database: err=%v", err)
		}
	})

	t.Run("orphan built Dist", func(t *testing.T) {
		ctx := context.Background()
		root := t.TempDir()
		cfg := config.Default()
		cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
		writeManagedConfig(t, root, cfg)
		if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
			t.Fatal(err)
		}
		database := filepath.Join(root, ".sow", "repo.db")
		before, err := os.ReadFile(database)
		if err != nil {
			t.Fatal(err)
		}
		repository := cfg.Repositories["repo"]
		delete(repository.Dists, "el9")
		cfg.Repositories["repo"] = repository
		writeManagedConfig(t, root, cfg)
		status, err := Status(ctx, StatusOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo"})
		if err != nil || status.Status != "error" || status.ReadyToCopy || len(status.DirtyDists) != 1 || status.DirtyDists[0] != "el9" {
			t.Fatalf("orphan status=%#v err=%v", status, err)
		}
		after, err := os.ReadFile(database)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("status changed orphan database: err=%v", err)
		}
	})
}

func TestStatusUsesStableReadOnlyWALSnapshotsWhileWriterHoldsLock(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	options := WorkspaceOptions{Workdir: root, CWD: root}
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	writerPaused := make(chan struct{})
	releaseWriter := make(chan struct{})
	writerDone := make(chan error, 1)
	go func() {
		_, err := Add(ctx, AddOptions{
			WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1,
			Fault: func(point string) error {
				if point == "build.pointer.el9" {
					close(writerPaused)
					<-releaseWriter
				}
				return nil
			},
		})
		writerDone <- err
	}()
	select {
	case <-writerPaused:
	case <-time.After(10 * time.Second):
		t.Fatal("writer did not reach the post-pointer pause")
	}
	for attempt := range 50 {
		status, err := Status(ctx, StatusOptions{WorkspaceOptions: options, Repository: "repo"})
		if err != nil || status.Status != "recovering" || status.ReadyToCopy || !status.RepositoryLocked || status.Operation == nil {
			close(releaseWriter)
			t.Fatalf("status attempt %d during writer=%#v err=%v", attempt, status, err)
		}
	}
	close(releaseWriter)
	select {
	case err := <-writerDone:
		if err != nil {
			t.Fatalf("writer failed after concurrent status snapshots: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("writer did not finish after status snapshots closed")
	}
	status, err := Status(ctx, StatusOptions{WorkspaceOptions: options, Repository: "repo"})
	if err != nil || status.Status != "clean" || !status.ReadyToCopy || status.RepositoryLocked {
		t.Fatalf("final status=%#v err=%v", status, err)
	}
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if err != nil || checked.Status != "clean" || !checked.ReadyToCopy {
		t.Fatalf("final check=%#v err=%v", checked, err)
	}
}

func TestStatusFencesSettledLegacyDatabaseFromFirstCurrentWriter(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	options := WorkspaceOptions{Workdir: root, CWD: root}
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(root, ".sow", "repo.db")
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(database + suffix); err != nil {
			t.Fatal(err)
		}
	}
	writerLock, err := acquireFileLock(ctx, filepath.Join(root, ".sow", "repo-locks", "repo.lock"), 0, false)
	if err != nil {
		t.Fatal(err)
	}
	type statusOutcome struct {
		result StatusResult
		err    error
	}
	statusDone := make(chan statusOutcome, 1)
	go func() {
		result, err := Status(ctx, StatusOptions{WorkspaceOptions: options, Repository: "repo"})
		statusDone <- statusOutcome{result: result, err: err}
	}()
	select {
	case outcome := <-statusDone:
		writerLock.Close()
		t.Fatalf("legacy status escaped its lifecycle fence while writer lock was held: result=%#v err=%v", outcome.result, outcome.err)
	case <-time.After(80 * time.Millisecond):
	}
	writer, err := openExistingState(database)
	if err != nil {
		writerLock.Close()
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		writerLock.Close()
		t.Fatal(err)
	}
	if err := writerLock.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case outcome := <-statusDone:
		if outcome.err != nil || outcome.result.Status != "clean" || !outcome.result.ReadyToCopy {
			t.Fatalf("fenced legacy status result=%#v err=%v", outcome.result, outcome.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("legacy status did not resume after first current writer")
	}
	assertPersistentSQLiteCoordinationFiles(t, database)
}
