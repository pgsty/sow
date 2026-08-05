package managed

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

func TestManagedMultiDistPointerSIGKILL(t *testing.T) {
	root, rpm := managedMultiDistCrashFixture(t)
	baselineStore, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	baseline, baselineErr := baselineStore.Summary(context.Background())
	if err := errors.Join(baselineErr, baselineStore.Close()); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestManagedMultiDistSIGKILLHelper$")
	command.Env = append(os.Environ(),
		"SOW_MANAGED_MULTIDIST_HELPER=1",
		"SOW_MANAGED_MULTIDIST_ROOT="+root,
		"SOW_MANAGED_MULTIDIST_RPM="+rpm,
	)
	if err := command.Run(); err == nil {
		t.Fatal("crash helper survived SIGKILL")
	}

	// Dists sort as el10, el9. Killing at the el10 pointer deliberately
	// exposes the first target tree and the second old tree within one build.
	for _, test := range []struct {
		dist string
		want int64
	}{{"el10", 1}, {"el9", 0}} {
		for _, architecture := range []string{"x86_64", "aarch64"} {
			view, err := yumrepo.ValidateManagedUnsignedDirectory(context.Background(), filepath.Join(root, "repo", "dists", test.dist, architecture, "repodata"), yumrepo.CompressionGzip)
			if err != nil || view.Packages != test.want {
				t.Fatalf("pre-recovery %s/%s packages=%d want=%d err=%v", test.dist, architecture, view.Packages, test.want, err)
			}
		}
	}
	options := WorkspaceOptions{Workdir: root, CWD: root}
	checked, err := Check(context.Background(), CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if !errors.Is(err, ErrNotReady) || checked.Status != "recovering" || checked.ReadyToCopy {
		t.Fatalf("pre-recovery check=%+v err=%v", checked, err)
	}
	for _, layer := range checked.Layers {
		if !layer.OK {
			t.Fatalf("pre-recovery layer %s failed: %v", layer.Name, layer.Issues)
		}
	}

	if _, err := Build(context.Background(), BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1}); err != nil {
		t.Fatalf("forward recovery: %v", err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, dist := range []string{"el10", "el9"} {
		members, listErr := store.ListPackageObjects(context.Background(), []string{dist}, false)
		if listErr != nil || len(members) != 1 {
			_ = store.Close()
			t.Fatalf("post-recovery %s members=%d err=%v", dist, len(members), listErr)
		}
	}
	summary, summaryErr := store.Summary(context.Background())
	pending, pendingErr := store.PendingOperations(context.Background())
	closeErr := store.Close()
	if err := errors.Join(summaryErr, pendingErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if summary.Status != "clean" || summary.BuiltGeneration != baseline.BuiltGeneration+1 || len(pending) != 0 {
		t.Fatalf("post-recovery summary=%+v pending=%+v", summary, pending)
	}
	checked, err = Check(context.Background(), CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if err != nil || checked.Status != "clean" || !checked.ReadyToCopy {
		t.Fatalf("post-recovery check=%+v err=%v", checked, err)
	}
	entries, err := os.ReadDir(filepath.Join(root, ".sow", "repo", "stage"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("post-recovery stage entries=%v err=%v", entries, err)
	}
}

func TestManagedMultiDistSIGKILLHelper(t *testing.T) {
	if os.Getenv("SOW_MANAGED_MULTIDIST_HELPER") != "1" {
		return
	}
	root := os.Getenv("SOW_MANAGED_MULTIDIST_ROOT")
	rpm := os.Getenv("SOW_MANAGED_MULTIDIST_RPM")
	fault := func(point string) error {
		if point != "build.pointer.el10" {
			return nil
		}
		process, err := os.FindProcess(os.Getpid())
		if err != nil {
			return err
		}
		if err := process.Kill(); err != nil {
			return err
		}
		select {}
	}
	_, err := Add(context.Background(), AddOptions{
		WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root},
		Repository:       "repo",
		Dists:            []string{"el9", "el10"},
		Paths:            []string{rpm},
		Jobs:             1,
		Fault:            fault,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Fatal("crash point was not reached")
}

func managedMultiDistCrashFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{
		"el9":  {Format: "rpm"},
		"el10": {Format: "rpm"},
	}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(context.Background(), InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	return root, rpm
}
