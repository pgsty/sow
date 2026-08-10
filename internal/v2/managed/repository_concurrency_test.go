package managed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
)

func TestRepositoryWritersOverlapAndBlockWorkspaceLifecycle(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	options := WorkspaceOptions{Workdir: root, CWD: root}
	cfg := config.Default()
	cfg.Repositories["alpha"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	cfg.Repositories["beta"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))

	type writerResult struct {
		repository string
		result     AddResult
		err        error
	}
	start := make(chan struct{})
	arrived := make(chan string, 2)
	release := make(chan struct{})
	results := make(chan writerResult, 2)
	for _, repository := range []string{"alpha", "beta"} {
		repository := repository
		go func() {
			<-start
			result, err := Add(ctx, AddOptions{
				WorkspaceOptions: options,
				Repository:       repository,
				Dists:            []string{"el9"},
				Paths:            []string{rpm},
				Skip:             true,
				Jobs:             1,
				Fault: func(point string) error {
					if point == "add.planned" {
						arrived <- repository
						<-release
					}
					return nil
				},
			})
			results <- writerResult{repository: repository, result: result, err: err}
		}()
	}
	close(start)
	seen := map[string]bool{}
	deadline := time.After(5 * time.Second)
	for len(seen) != 2 {
		select {
		case repository := <-arrived:
			seen[repository] = true
		case <-deadline:
			close(release)
			t.Fatalf("repository writers did not overlap: arrivals=%v", seen)
		}
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{
		WorkspaceOptions: options,
		LockOptions:      LockOptions{NoWait: true},
		Name:             "blocked-lifecycle",
	}); !errors.Is(err, ErrLockUnavailable) {
		close(release)
		t.Fatalf("Workspace lifecycle did not fail fast behind Repository writers: %v", err)
	}
	close(release)
	for range 2 {
		select {
		case got := <-results:
			if got.err != nil || got.result.Repository != got.repository || got.result.Accepted != 1 || !got.result.Dirty {
				t.Fatalf("writer %s result=%#v err=%v", got.repository, got.result, got.err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("overlapping Repository writer did not finish")
		}
	}
}

func TestQueuedRepositoryWriterReloadsConfigAndReselectsAfterLifecycle(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	options := WorkspaceOptions{Workdir: root, CWD: root}
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: options, Name: "gone"}); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "input.rpm")
	if err := os.WriteFile(input, []byte("selection must fail before package inspection\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	lifecycleArrived := make(chan struct{})
	lifecycleRelease := make(chan struct{})
	lifecycleResult := make(chan error, 1)
	go func() {
		_, err := RemoveRepositoryResult(ctx, RepositoryRemoveOptions{
			WorkspaceOptions: options,
			Name:             "gone",
			Force:            true,
			Fault: func(point string) error {
				if point == "repo.rm.journal" {
					close(lifecycleArrived)
					<-lifecycleRelease
				}
				return nil
			},
		})
		lifecycleResult <- err
	}()
	select {
	case <-lifecycleArrived:
	case <-time.After(5 * time.Second):
		t.Fatal("Repository lifecycle did not reach its pre-config barrier")
	}
	type addResult struct {
		result AddResult
		err    error
	}
	queued := make(chan addResult, 1)
	go func() {
		result, err := Add(ctx, AddOptions{WorkspaceOptions: options, Paths: []string{input}, Jobs: 1})
		queued <- addResult{result: result, err: err}
	}()
	select {
	case got := <-queued:
		close(lifecycleRelease)
		t.Fatalf("Repository writer did not queue behind Workspace lifecycle: result=%#v err=%v", got.result, got.err)
	case <-time.After(75 * time.Millisecond):
	}
	close(lifecycleRelease)
	select {
	case err := <-lifecycleResult:
		if err != nil {
			t.Fatalf("Repository lifecycle failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Repository lifecycle did not finish")
	}
	select {
	case got := <-queued:
		if !errors.Is(got.err, ErrWorkspaceInput) || got.result.Repository != "" {
			t.Fatalf("queued writer reused stale Repository selection: result=%#v err=%v", got.result, got.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("queued Repository writer did not finish")
	}
}

func TestRepositoryWritersRecoverStaleWorkspaceJournalBeforeAddOrBuild(t *testing.T) {
	for _, command := range []string{"add", "build"} {
		t.Run(command, func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			options := WorkspaceOptions{Workdir: root, CWD: root}
			cfg := config.Default()
			cfg.Repositories["active"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
			cfg.Repositories["stale"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{}}
			writeManagedConfig(t, root, cfg)
			if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
				t.Fatal(err)
			}
			injected := errors.New("simulated stop after Workspace config commit")
			_, err := RemoveRepositoryResult(ctx, RepositoryRemoveOptions{
				WorkspaceOptions: options,
				Name:             "stale",
				Force:            true,
				Fault: func(point string) error {
					if point == "repo.rm.config" {
						return injected
					}
					return nil
				},
			})
			if !errors.Is(err, injected) {
				t.Fatalf("stale lifecycle fault=%v", err)
			}
			if _, err := os.Stat(workspaceJournalPath(root)); err != nil {
				t.Fatalf("stale Workspace journal is missing: %v", err)
			}

			switch command {
			case "add":
				inputs := filepath.Join(root, "inputs")
				if err := os.Mkdir(inputs, 0o755); err != nil {
					t.Fatal(err)
				}
				rpm := decodeManagedFixture(t, filepath.Join("..", "..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
				added, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "active", Dists: []string{"el9"}, Paths: []string{rpm}, Skip: true, Jobs: 1})
				if err != nil || added.Accepted != 1 || !added.Dirty {
					t.Fatalf("Add after stale Workspace journal=%#v err=%v", added, err)
				}
			case "build":
				built, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "active", Jobs: 1})
				if err != nil || !built.Noop || built.Dirty {
					t.Fatalf("Build after stale Workspace journal=%#v err=%v", built, err)
				}
			}
			if _, err := os.Lstat(workspaceJournalPath(root)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("Workspace journal remains after writer recovery: %v", err)
			}
			for _, path := range []string{
				filepath.Join(root, "stale"),
				filepath.Join(root, ".sow", "stale"),
				filepath.Join(root, ".sow", "stale.db"),
				filepath.Join(root, ".sow", "repo-locks", "stale.lock"),
			} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("stale Repository path remains after recovery: %s err=%v", path, err)
				}
			}
		})
	}
}
