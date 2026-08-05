package managed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pgsty/sow/internal/v2/config"
)

func TestActiveWorkspaceRootRejectsRealDirectoryReplacement(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "workspace")
	if _, err := Init(context.Background(), InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	workspace, err := config.Discover(config.DiscoverOptions{Workdir: root, CWD: root})
	if err != nil {
		t.Fatal(err)
	}
	guard, err := bindDiscoveredWorkspaceRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(parent, "workspace-moved")
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := durableMkdir(filepath.Join(root, "must-not-exist"), 0o755); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("replacement tree write error = %v, want integrity", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "must-not-exist")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement tree was modified: %v", err)
	}
	if err := guard.Close(); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("guard close error = %v, want integrity", err)
	}
}

func TestAddFailsClosedWhenWorkspaceRootIsReboundMidCommand(t *testing.T) {
	ctx := context.Background()
	parent := t.TempDir()
	root := filepath.Join(parent, "workspace")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	data := []byte("schema: sow/v2\nrepos:\n  repo:\n    dists:\n      el9: {format: rpm}\n")
	if err := os.WriteFile(filepath.Join(root, config.ConfigFilename), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputRoot := filepath.Join(parent, "inputs")
	if err := os.Mkdir(inputRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputRoot, "package.rpm"))
	moved := filepath.Join(parent, "workspace-moved")
	rebound := false
	_, err := Add(ctx, AddOptions{
		WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root},
		Repository:       "repo",
		Dists:            []string{"el9"},
		Paths:            []string{rpm},
		Skip:             true,
		Jobs:             1,
		Fault: func(point string) error {
			if point != "add.planned" || rebound {
				return nil
			}
			rebound = true
			if err := os.Rename(root, moved); err != nil {
				return err
			}
			if err := os.Mkdir(root, 0o755); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(root, "sentinel"), []byte("replacement"), 0o644)
		},
	})
	if !rebound || !errors.Is(err, ErrIntegrity) {
		t.Fatalf("Add rebound=%t error=%v, want integrity", rebound, err)
	}
	entries, readErr := os.ReadDir(root)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 1 || entries[0].Name() != "sentinel" {
		t.Fatalf("replacement tree was modified: %#v", entries)
	}
}
