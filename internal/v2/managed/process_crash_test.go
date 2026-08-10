package managed

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

func TestManagedMutationSIGKILLRecoveryMatrix(t *testing.T) {
	tests := []struct {
		operation string
		points    []string
		before    int64
		after     int64
	}{
		{
			operation: "add",
			points:    []string{"add.planned", "add.staged", "add.applied", "build.rendered.el9", "build.staged", "build.payload-linked.", "build.payload-targets", "build.payload.", "build.pointer.el9", "build.built", "build.finalized"},
			before:    0,
			after:     1,
		},
		{
			operation: "rm",
			points:    []string{"rm.planned", "rm.staged", "rm.applied", "build.rendered.el9", "build.staged", "build.pointer.el9", "build.built", "build.finalized"},
			before:    1,
			after:     0,
		},
		{
			operation: "build",
			points:    []string{"build.command.planned", "build.command.staged", "build.command.applied", "build.rendered.el9", "build.staged", "build.payload-linked.", "build.payload-targets", "build.payload.", "build.pointer.el9", "build.built", "build.finalized"},
			before:    0,
			after:     1,
		},
	}
	for _, test := range tests {
		for _, point := range test.points {
			t.Run(test.operation+"/"+strings.TrimSuffix(point, "."), func(t *testing.T) {
				root, rpm := newManagedCrashFixture(t, test.operation)
				cmd := exec.Command(os.Args[0], "-test.run=^TestManagedSIGKILLHelper$")
				cmd.Env = append(os.Environ(),
					"SOW_MANAGED_CRASH_HELPER=1",
					"SOW_MANAGED_CRASH_OPERATION="+test.operation,
					"SOW_MANAGED_CRASH_POINT="+point,
					"SOW_MANAGED_CRASH_ROOT="+root,
					"SOW_MANAGED_CRASH_RPM="+rpm,
				)
				if err := cmd.Run(); err == nil {
					t.Fatal("crash helper survived SIGKILL")
				}

				// The visible repository must remain a complete old or new generation
				// even before journal recovery runs.
				counts := map[int64]struct{}{}
				for _, architecture := range []string{"x86_64", "aarch64"} {
					validated, err := yumrepo.ValidateManagedUnsignedDirectory(
						context.Background(),
						filepath.Join(root, "repo", "dists", "el9", architecture, "repodata"),
						yumrepo.CompressionGzip,
					)
					if err != nil {
						t.Fatalf("public generation invalid before recovery: %v", err)
					}
					if validated.Packages != test.before && validated.Packages != test.after {
						t.Fatalf("visible package count=%d, want old=%d or new=%d", validated.Packages, test.before, test.after)
					}
					counts[validated.Packages] = struct{}{}
				}
				if len(counts) != 1 {
					t.Fatalf("architectures expose mixed generations: %#v", counts)
				}

				// Check is read-only and must distinguish a fully journal-bound
				// crash point from corruption before any mutating recovery runs.
				// A stop after FinalizeBuild is already committed and clean; every
				// earlier stop is valid-but-not-copyable recovery state.
				checked, checkErr := Check(context.Background(), CheckOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1})
				if point == "build.finalized" {
					if checkErr != nil || checked.Status != "clean" || !checked.ReadyToCopy {
						t.Fatalf("committed crash point check=%+v err=%v", checked, checkErr)
					}
				} else {
					if !errors.Is(checkErr, ErrNotReady) || checked.Status != "recovering" || checked.ReadyToCopy {
						t.Fatalf("recoverable crash point check=%+v err=%v", checked, checkErr)
					}
					for _, layer := range checked.Layers {
						if !layer.OK {
							t.Fatalf("recoverable crash point has failed %s layer: %v", layer.Name, layer.Issues)
						}
					}
				}

				if _, err := Build(context.Background(), BuildOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1}); err != nil {
					t.Fatalf("forward recovery at %s/%s: %v", test.operation, point, err)
				}
				members, err := managedCrashMemberCount(root)
				if err != nil {
					t.Fatal(err)
				}
				if members != test.after {
					if err := repeatManagedCrashOperation(root, rpm, test.operation); err != nil {
						t.Fatalf("repeat intent %s at %s: %v", test.operation, point, err)
					}
				}
				assertManagedCrashRecovery(t, root, test.after)
			})
		}
	}
}

func TestManagedSIGKILLHelper(t *testing.T) {
	if os.Getenv("SOW_MANAGED_CRASH_HELPER") != "1" {
		return
	}
	root := os.Getenv("SOW_MANAGED_CRASH_ROOT")
	rpm := os.Getenv("SOW_MANAGED_CRASH_RPM")
	operation := os.Getenv("SOW_MANAGED_CRASH_OPERATION")
	point := os.Getenv("SOW_MANAGED_CRASH_POINT")
	fault := func(got string) error {
		if got != point && !(strings.HasSuffix(point, ".") && strings.HasPrefix(got, point)) {
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
	options := WorkspaceOptions{Workdir: root, CWD: root}
	var err error
	switch operation {
	case "add":
		_, err = Add(context.Background(), AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1, Fault: fault})
	case "rm":
		_, err = Remove(context.Background(), RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Jobs: 1, Fault: fault})
	case "build":
		_, err = Build(context.Background(), BuildOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Jobs: 1, Fault: fault})
	default:
		err = errors.New("unknown managed crash operation")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Fatal("managed crash point was not reached")
}

func newManagedCrashFixture(t *testing.T, operation string) (string, string) {
	t.Helper()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(context.Background(), InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	if operation == "rm" {
		if _, err := Add(context.Background(), AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
			t.Fatal(err)
		}
	}
	if operation == "build" {
		if _, err := Add(context.Background(), AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Skip: true, Jobs: 1}); err != nil {
			t.Fatal(err)
		}
	}
	return root, rpm
}

func repeatManagedCrashOperation(root, rpm, operation string) error {
	options := WorkspaceOptions{Workdir: root, CWD: root}
	switch operation {
	case "add":
		_, err := Add(context.Background(), AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1})
		return err
	case "rm":
		_, err := Remove(context.Background(), RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Jobs: 1})
		return err
	case "build":
		_, err := Build(context.Background(), BuildOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Jobs: 1})
		return err
	default:
		return errors.New("unknown managed crash operation")
	}
}

func managedCrashMemberCount(root string) (int64, error) {
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		return 0, err
	}
	members, membersErr := store.ListPackageObjects(context.Background(), []string{"el9"}, false)
	closeErr := store.Close()
	if err := errors.Join(membersErr, closeErr); err != nil {
		return 0, err
	}
	return int64(len(members)), nil
}

func assertManagedCrashRecovery(t *testing.T, root string, wantMembers int64) {
	t.Helper()
	ctx := context.Background()
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	pending, pendingErr := store.PendingOperations(ctx)
	members, membersErr := store.ListPackageObjects(ctx, []string{"el9"}, false)
	summary, summaryErr := store.Summary(ctx)
	closeErr := store.Close()
	if err := errors.Join(pendingErr, membersErr, summaryErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 || int64(len(members)) != wantMembers || summary.Status != "clean" {
		t.Fatalf("pending=%#v members=%#v summary=%#v", pending, members, summary)
	}
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Jobs: 1})
	if err != nil || !checked.ReadyToCopy || checked.Status != "clean" {
		t.Fatalf("check=%#v err=%v", checked, err)
	}
	entries, err := os.ReadDir(filepath.Join(root, ".sow", "repo", "stage"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("operation stage not cleaned: entries=%v err=%v", entries, err)
	}
}
