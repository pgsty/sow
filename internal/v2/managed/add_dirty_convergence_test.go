package managed

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pgsty/sow/internal/v2/config"
)

func TestDefaultDuplicateAddConvergesSkippedDesiredMembership(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	opts := WorkspaceOptions{Workdir: root, CWD: root}
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
	skipped, err := Add(ctx, AddOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Skip: true, Jobs: 1})
	if err != nil || !skipped.Dirty || skipped.MembershipAdded != 1 {
		t.Fatalf("skipped add=%#v err=%v", skipped, err)
	}
	converged, err := Add(ctx, AddOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1})
	if err != nil || converged.Dirty || converged.MembershipAdded != 0 || converged.Generation == skipped.Generation {
		t.Fatalf("duplicate converging add=%#v skipped=%#v err=%v", converged, skipped, err)
	}
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: opts, Repository: "repo", Jobs: 1})
	if err != nil || checked.Status != "clean" || !checked.ReadyToCopy {
		t.Fatalf("converged check=%#v err=%v", checked, err)
	}
}
