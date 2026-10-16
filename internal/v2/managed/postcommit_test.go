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

func TestBuildTerminalCancellationRetainsResult(t *testing.T) {
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"noble": {Format: "deb"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(context.Background(), InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	repo := cfg.Repositories["repo"]
	d := repo.Dists["noble"]
	d.Exclude = []config.ExcludeRule{{Name: []string{"no-match"}}}
	repo.Dists["noble"] = d
	cfg.Repositories["repo"] = repo
	writeManagedConfig(t, root, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result, err := Build(ctx, BuildOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1, Fault: func(point string) error {
		if point == "build.finalized" {
			cancel()
		}
		return nil
	}})
	if err != nil || result.Noop || result.Dirty || result.Generation == 0 || ctx.Err() == nil {
		t.Fatalf("result=%+v err=%v context=%v", result, err, ctx.Err())
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	summary, err := store.Summary(context.Background())
	if err != nil || summary.BuiltGeneration != result.Generation || summary.DesiredRevision != result.Revision {
		t.Fatalf("summary=%+v err=%v result=%+v", summary, err, result)
	}
	op, err := store.GetOperationSummary(context.Background(), result.Operation)
	if err != nil || op.State != state.OperationDone {
		t.Fatalf("operation=%+v err=%v", op, err)
	}
	if _, err := os.Stat(mutationStageRoot(root, "repo", result.Operation)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed build stage remains: %v", err)
	}
}

func TestLocalGCTerminalCancellationRetainsResultAndCleans(t *testing.T) {
	f := newLocalGCFixture(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result, err := LocalGC(ctx, LocalGCOptions{WorkspaceOptions: f.options, Repository: "repo", Fault: func(point string) error {
		if point == "gc.committed" {
			cancel()
		}
		return nil
	}})
	if err != nil || result.Operation == "" || result.Generation != f.generation+1 || result.Objects != 1 || result.Bytes != f.object.Size || ctx.Err() == nil {
		t.Fatalf("result=%+v err=%v context=%v", result, err, ctx.Err())
	}
	store, err := state.OpenReadOnly(filepath.Join(f.root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	summary, err := store.Summary(context.Background())
	if err != nil || summary.BuiltGeneration != result.Generation {
		t.Fatalf("summary=%+v err=%v", summary, err)
	}
	op, err := store.GetOperationSummary(context.Background(), result.Operation)
	if err != nil || op.State != state.OperationDone {
		t.Fatalf("operation=%+v err=%v", op, err)
	}
	if _, err := os.Stat(localGCRecoveryRoot(f.root, "repo", result.Operation)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed GC recovery root remains: %v", err)
	}
}
