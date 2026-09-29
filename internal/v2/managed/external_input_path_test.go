package managed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestExternalInputSymlinkAncestorAndLeaf(t *testing.T) {
	ctx := context.Background()
	root, ws := newRejectionWorkspace(t)
	inputRoot := t.TempDir()
	input := decodeManagedFixture(t, "../../testdata/pgdg-redhat-nonfree-repo.rpm.b64", filepath.Join(inputRoot, "package.rpm"))
	alias := filepath.Join(t.TempDir(), "input-alias")
	if err := os.Symlink(inputRoot, alias); err != nil {
		t.Fatal(err)
	}
	result, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: []string{filepath.Join(alias, "package.rpm")}, Jobs: 1})
	if err != nil || result.Accepted != 1 {
		t.Fatalf("add through symlink parent=%+v err=%v", result, err)
	}
	leaf := filepath.Join(root, "leaf.rpm")
	if err := os.Symlink(input, leaf); err != nil {
		t.Fatal(err)
	}
	result, err = Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: []string{leaf}, Jobs: 1})
	if !errors.Is(err, ErrRejected) || result.Accepted != 0 {
		t.Fatalf("symlink leaf accepted: %+v err=%v", result, err)
	}
	t.Setenv("TMPDIR", alias)
	if _, err := Remove(ctx, RemoveOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Jobs: 1, Check: true}); err != nil {
		t.Fatalf("rm preview with symlink TMPDIR: %v", err)
	}
}
