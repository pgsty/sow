package managed

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

func TestSkippedMutationsCanReturnExactlyToBuiltProjection(t *testing.T) {
	for _, scenario := range []string{"pending add then remove", "built remove then add"} {
		t.Run(scenario, func(t *testing.T) {
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
			if scenario == "built remove then add" {
				if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
					t.Fatal(err)
				}
				if _, err := Remove(ctx, RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Skip: true, Jobs: 1}); err != nil {
					t.Fatal(err)
				}
				if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Skip: true, Jobs: 1}); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Skip: true, Jobs: 1}); err != nil {
					t.Fatal(err)
				}
				if _, err := Remove(ctx, RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Skip: true, Jobs: 1}); err != nil {
					t.Fatal(err)
				}
			}

			status, err := Status(ctx, StatusOptions{WorkspaceOptions: options, Repository: "repo"})
			if err != nil || status.Status != "clean" || !status.ReadyToCopy || status.Pending.Count != 0 || status.Pending.Bytes != 0 {
				t.Fatalf("reverted skipped mutation status=%#v err=%v", status, err)
			}
			checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
			if err != nil || checked.Status != "clean" || !checked.ReadyToCopy {
				t.Fatalf("reverted skipped mutation check=%#v err=%v", checked, err)
			}
			beforeGeneration := status.BuiltGeneration
			built, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
			if err != nil || !built.Noop || built.Generation != beforeGeneration || built.Dirty {
				t.Fatalf("reverted skipped mutation no-op build=%#v err=%v", built, err)
			}
		})
	}
}

func TestSkippedRevertKeepsRepositoryDirtyWhenAnotherDistDiffers(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	options := WorkspaceOptions{Workdir: root, CWD: root}
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{
		"el9": {Format: "rpm"}, "el10": {Format: "rpm"},
	}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9", "el10"}, Paths: []string{rpm}, Skip: true, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := Remove(ctx, RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Skip: true, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	status, err := Status(ctx, StatusOptions{WorkspaceOptions: options, Repository: "repo"})
	if err != nil || status.Status != "dirty" || status.ReadyToCopy || status.Pending.Count != 1 {
		t.Fatalf("remaining dirty Dist status=%#v err=%v", status, err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	summary, err := store.Summary(ctx)
	if err != nil || summary.Status != "dirty" || summary.DirtyReason == "" {
		t.Fatalf("remaining dirty Dist summary=%#v err=%v", summary, err)
	}
}
