package managed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

func TestOrdinaryWritersRejectSemanticStateCorruptionBeforeOperation(t *testing.T) {
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
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `UPDATE built_memberships SET generation = generation + 99`); err != nil {
		store.Close()
		t.Fatal(err)
	}
	var operationsBefore int64
	if err := store.DB().QueryRowContext(ctx, `SELECT count(*) FROM operations`).Scan(&operationsBefore); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	configBefore, err := os.ReadFile(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	publicBefore, err := publicTreeSnapshot(root, "repo")
	if err != nil {
		t.Fatal(err)
	}

	writers := map[string]func() error{
		"build": func() error {
			_, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
			return err
		},
		"add": func() error {
			_, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1})
			return err
		},
		"rm": func() error {
			_, err := Remove(ctx, RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree"}, Jobs: 1})
			return err
		},
		"dist.new": func() error {
			_, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: options, Repository: "repo", Name: "el10", Format: "rpm"})
			return err
		},
		"dist.rm": func() error {
			return RemoveDist(ctx, DistRemoveOptions{WorkspaceOptions: options, Repository: "repo", Name: "el9", Force: true})
		},
	}
	for name, run := range writers {
		t.Run(name, func(t *testing.T) {
			if err := run(); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("writer accepted corrupt semantic state: %v", err)
			}
		})
	}

	store, err = state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var operationsAfter int64
	if err := store.DB().QueryRowContext(ctx, `SELECT count(*) FROM operations`).Scan(&operationsAfter); err != nil {
		t.Fatal(err)
	}
	if operationsAfter != operationsBefore {
		t.Fatalf("rejected writers appended operations: before=%d after=%d", operationsBefore, operationsAfter)
	}
	configAfter, err := os.ReadFile(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	if string(configAfter) != string(configBefore) {
		t.Fatal("rejected writers changed workspace config")
	}
	publicAfter, err := publicTreeSnapshot(root, "repo")
	if err != nil {
		t.Fatal(err)
	}
	if !sameStringMap(publicBefore, publicAfter) {
		t.Fatal("rejected writers changed public delivery tree")
	}
}

func sameStringMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}
