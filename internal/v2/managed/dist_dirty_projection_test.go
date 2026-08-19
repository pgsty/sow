package managed

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pgsty/sow/internal/v2/config"
)

func TestDistLifecyclePreservesUnrelatedDirtyProjection(t *testing.T) {
	setup := func(t *testing.T, dists map[string]config.DistConfig) (context.Context, string, WorkspaceOptions) {
		t.Helper()
		ctx := context.Background()
		root := t.TempDir()
		cfg := config.Default()
		cfg.Repositories["repo"] = config.RepositoryConfig{Dists: dists}
		writeManagedConfig(t, root, cfg)
		if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
			t.Fatal(err)
		}
		inputs := filepath.Join(root, "inputs")
		if err := os.Mkdir(inputs, 0o755); err != nil {
			t.Fatal(err)
		}
		rpm := decodeManagedFixture(t, filepath.Join("..", "..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
		opts := WorkspaceOptions{Workdir: root, CWD: root}
		added, err := Add(ctx, AddOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Skip: true, Jobs: 1})
		if err != nil || !added.Dirty {
			t.Fatalf("skipped add=%#v err=%v", added, err)
		}
		return ctx, root, opts
	}
	assertDirtyThenBuild := func(t *testing.T, ctx context.Context, opts WorkspaceOptions) {
		t.Helper()
		status, err := Status(ctx, StatusOptions{WorkspaceOptions: opts, Repository: "repo"})
		if err != nil || status.Status != "dirty" || len(status.DirtyDists) != 1 || status.DirtyDists[0] != "el9" {
			t.Fatalf("post-lifecycle status=%#v err=%v", status, err)
		}
		built, err := Build(ctx, BuildOptions{WorkspaceOptions: opts, Repository: "repo", Jobs: 1})
		if err != nil || built.Dirty || built.Noop {
			t.Fatalf("converging build=%#v err=%v", built, err)
		}
		checked, err := Check(ctx, CheckOptions{WorkspaceOptions: opts, Repository: "repo", Jobs: 1})
		if err != nil || checked.Status != "clean" || !checked.ReadyToCopy {
			t.Fatalf("converged check=%#v err=%v", checked, err)
		}
	}

	t.Run("dist new", func(t *testing.T) {
		ctx, _, opts := setup(t, map[string]config.DistConfig{"el9": {Format: "rpm"}})
		created, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: opts, Repository: "repo", Name: "el10", Format: "rpm"})
		if err != nil || created.Dirty {
			t.Fatalf("new Dist=%#v err=%v", created, err)
		}
		assertDirtyThenBuild(t, ctx, opts)
	})

	t.Run("dist rm", func(t *testing.T) {
		ctx, _, opts := setup(t, map[string]config.DistConfig{
			"el9":  {Format: "rpm"},
			"el10": {Format: "rpm"},
		})
		removed, err := RemoveDistResult(ctx, DistRemoveOptions{WorkspaceOptions: opts, Repository: "repo", Name: "el10", Force: true})
		if err != nil || !removed.Removed {
			t.Fatalf("remove Dist=%#v err=%v", removed, err)
		}
		assertDirtyThenBuild(t, ctx, opts)
	})
}
