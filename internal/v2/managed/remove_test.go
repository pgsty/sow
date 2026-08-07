package managed

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

func TestRemovePreviewAndBuildPreserveGenerationAboveMaxInt64(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
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
	options := WorkspaceOptions{Workdir: root, CWD: root}
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	manifest, err := scanPublicManifest(ctx, filepath.Join(root, "repo"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	high := state.GenerationID(math.MaxInt64)
	tx, err := store.DB().BeginTx(ctx, nil)
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	for _, statement := range []string{
		`DELETE FROM generation_view_signers`,
		`DELETE FROM generation_files`,
		`DELETE FROM generations`,
		`DELETE FROM prior_built_memberships`,
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			tx.Rollback()
			store.Close()
			t.Fatal(err)
		}
	}
	for _, statement := range []string{
		`UPDATE repository_state SET built_generation = ? WHERE singleton = 1`,
		`UPDATE dists SET built_generation = ?`,
		`UPDATE dist_architectures SET built_generation = ?`,
		`UPDATE built_memberships SET generation = ?`,
	} {
		if _, err := tx.ExecContext(ctx, statement, high); err != nil {
			tx.Rollback()
			store.Close()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.BootstrapLegacyGeneration(ctx, strings.Repeat("e", 64), high, manifest); err != nil {
		store.Close()
		t.Fatal(err)
	}
	summary, summaryErr := store.Summary(ctx)
	checkErr := store.Check(ctx)
	ledgerErr := store.ValidateGenerationLedger(ctx)
	if err := errors.Join(summaryErr, checkErr, ledgerErr, store.Close()); err != nil || summary.BuiltGeneration != high {
		t.Fatalf("high Generation summary=%#v err=%v", summary, err)
	}
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if err != nil || !checked.ReadyToCopy || checked.Generation != high {
		t.Fatalf("high Generation check=%#v err=%v", checked, err)
	}
	preview, err := Remove(ctx, RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Check: true, Jobs: 1})
	want, nextErr := high.Next()
	if err != nil || nextErr != nil || preview.Generation != want || len(preview.Changes) == 0 {
		t.Fatalf("high Generation preview=%#v want=%s err=%v nextErr=%v", preview, want, err, nextErr)
	}
	actual, err := Remove(ctx, RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Jobs: 1})
	if err != nil || actual.Generation != want || !reflect.DeepEqual(actual.Changes, preview.Changes) {
		t.Fatalf("high Generation remove=%#v preview=%#v err=%v", actual, preview, err)
	}
}

func TestRemoveCheckSkipAndDefaultBuild(t *testing.T) {
	newRepo := func(t *testing.T) (string, string) {
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
		rpm := decodeManagedFixture(t, filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
		if _, err := Add(context.Background(), AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
			t.Fatal(err)
		}
		return root, rpm
	}

	t.Run("check and skip", func(t *testing.T) {
		root, _ := newRepo(t)
		beforeTree, err := publicTreeSnapshot(root, "repo")
		if err != nil {
			t.Fatal(err)
		}
		dbPath := filepath.Join(root, ".sow", "repo.db")
		beforeDB, err := os.ReadFile(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		preview, err := Remove(context.Background(), RemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Check: true, Jobs: 1})
		if err != nil || !preview.Check || len(preview.Removed) != 1 || preview.Operation != "" || len(preview.Changes) == 0 {
			t.Fatalf("preview=%#v err=%v", preview, err)
		}
		previousPhase := -1
		phaseRank := map[string]int{"payload": 0, "metadata": 1, "pointer": 2, "delete": 3}
		for _, change := range preview.Changes {
			rank, ok := phaseRank[change.Phase]
			if !ok || rank < previousPhase {
				t.Fatalf("preview changes are not phase ordered: %#v", preview.Changes)
			}
			previousPhase = rank
		}
		afterTree, _ := publicTreeSnapshot(root, "repo")
		afterDB, _ := os.ReadFile(dbPath)
		if !reflect.DeepEqual(beforeTree, afterTree) || string(beforeDB) != string(afterDB) {
			t.Fatal("rm --check changed public tree or repository database")
		}
		removed, err := Remove(context.Background(), RemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Skip: true, Jobs: 1})
		if err != nil || !removed.Dirty || len(removed.Removed) != 1 {
			t.Fatalf("skip=%#v err=%v", removed, err)
		}
		afterSkipTree, _ := publicTreeSnapshot(root, "repo")
		if !reflect.DeepEqual(beforeTree, afterSkipTree) {
			t.Fatal("rm --skip changed public Pool or Dists")
		}
	})

	t.Run("default build", func(t *testing.T) {
		root, _ := newRepo(t)
		store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
		if err != nil {
			t.Fatal(err)
		}
		before, _ := store.Summary(context.Background())
		store.Close()
		result, err := Remove(context.Background(), RemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Jobs: 1})
		if err != nil || result.Dirty || result.Generation != before.BuiltGeneration+1 || len(result.Changes) == 0 {
			t.Fatalf("remove=%#v err=%v", result, err)
		}
		store, err = state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
		if err != nil {
			t.Fatal(err)
		}
		members, memberErr := store.ListPackageObjects(context.Background(), []string{"el9"}, false)
		all, allErr := store.ListPackageObjects(context.Background(), nil, false)
		store.Close()
		if err := errors.Join(memberErr, allErr); err != nil || len(members) != 0 || len(all) != 1 || all[0].Storage != "pool" {
			t.Fatalf("members=%#v all=%#v err=%v", members, all, err)
		}
	})
}

func TestRemoveOrdinaryPreApplyFailureIsTerminalAndLeavesMembership(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
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
	input := decodeManagedFixture(t, filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	options := WorkspaceOptions{Workdir: root, CWD: root}
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{input}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	result, err := Remove(ctx, RemoveOptions{
		WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Jobs: 1,
		Fault: func(point string) error {
			if point != "rm.planned" {
				return nil
			}
			store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
			if err != nil {
				return err
			}
			pending, pendingErr := store.PendingOperations(ctx)
			closeErr := store.Close()
			if err := errors.Join(pendingErr, closeErr); err != nil {
				return err
			}
			if len(pending) != 1 || pending[0].Kind != "rm" {
				return errors.New("remove operation was not pending")
			}
			return os.Mkdir(mutationStageRoot(root, "repo", pending[0].ID), 0o700)
		},
	})
	if err == nil || result.Operation == "" {
		t.Fatalf("occupied remove stage result=%#v err=%v", result, err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	detail, detailErr := store.GetOperation(ctx, result.Operation)
	members, membersErr := store.ListPackageObjects(ctx, []string{"el9"}, false)
	closeErr := store.Close()
	if err := errors.Join(detailErr, membersErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if detail.Operation.State != state.OperationFailed || detail.Operation.ErrorClass != "runtime" || len(members) != 1 {
		t.Fatalf("failed remove detail=%#v members=%#v", detail.Operation, members)
	}
	if _, err := os.Lstat(mutationStageRoot(root, "repo", result.Operation)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed remove retained stage: %v", err)
	}
	status, err := Status(ctx, StatusOptions{WorkspaceOptions: options, Repository: "repo"})
	if err != nil || status.Status != "clean" || !status.ReadyToCopy {
		t.Fatalf("failed remove changed repository: status=%#v err=%v", status, err)
	}
}

func TestRemoveSkipPostCommitCheckpointFailureRetainsCommittedProjection(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
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
	input := decodeManagedFixture(t, filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{input}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	before := managedTestSummary(t, root)
	var release func()
	result, err := Remove(ctx, RemoveOptions{
		WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root},
		Repository:       "repo",
		Dists:            []string{"el9"},
		Packages:         []string{"pgdg-redhat-nonfree-repo"},
		Skip:             true,
		Jobs:             1,
		Fault: func(point string) error {
			if point != "rm.applied" {
				return nil
			}
			var holdErr error
			release, holdErr = holdRepositoryWALSnapshot(ctx, filepath.Join(root, ".sow", "repo.db"))
			return holdErr
		},
	})
	if release != nil {
		release()
	}
	if err == nil || !strings.Contains(err.Error(), "checkpoint repository state incomplete") {
		t.Fatalf("checkpoint fault result=%#v err=%v", result, err)
	}
	if result.Revision != before.DesiredRevision+1 || result.Generation != before.BuiltGeneration || !result.Dirty {
		t.Fatalf("committed projection result=%#v before=%#v", result, before)
	}
	store, openErr := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if openErr != nil {
		t.Fatal(openErr)
	}
	detail, detailErr := store.GetOperation(ctx, result.Operation)
	store.Close()
	if detailErr != nil || detail.Operation.State != state.OperationDoneDirty {
		t.Fatalf("terminal audit=%#v err=%v", detail, detailErr)
	}
	if _, statErr := os.Stat(mutationStageRoot(root, "repo", result.Operation)); !os.IsNotExist(statErr) {
		t.Fatalf("terminal checkpoint error retained stage: %v", statErr)
	}
}

func TestRemoveSkipCleanupFailureRetainsCommittedProjection(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
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
	input := decodeManagedFixture(t, filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{input}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	before := managedTestSummary(t, root)
	outside := t.TempDir()
	var restore func()
	result, err := Remove(ctx, RemoveOptions{
		WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"},
		Packages: []string{"pgdg-redhat-nonfree-repo"}, Skip: true, Jobs: 1,
		Fault: func(point string) error {
			if point != "rm.applied" {
				return nil
			}
			var sabotageErr error
			restore, sabotageErr = sabotageOnlyMutationStage(root, outside)
			return sabotageErr
		},
	})
	if restore != nil {
		restore()
	}
	if err == nil || result.Revision != before.DesiredRevision+1 || result.Generation != before.BuiltGeneration || !result.Dirty {
		t.Fatalf("result=%#v before=%#v err=%v", result, before, err)
	}
}

func TestRemoveCheckPredictsExactImmediateBuild(t *testing.T) {
	tests := []struct {
		name      string
		format    string
		dist      string
		fixture   string
		filename  string
		reference string
		wait      bool
		signed    bool
	}{
		{name: "rpm", format: "rpm", dist: "el9", fixture: filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filename: "pgdg-redhat-nonfree-repo.rpm", reference: "pgdg-redhat-nonfree-repo"},
		{name: "deb across wall-clock second", format: "deb", dist: "jammy", fixture: filepath.Join("..", "..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"), filename: "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb", reference: "libpqtypes0", wait: true},
		{name: "signed rpm", format: "rpm", dist: "el9", fixture: filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filename: "pgdg-redhat-nonfree-repo.rpm", reference: "pgdg-redhat-nonfree-repo", signed: true},
		{name: "signed deb", format: "deb", dist: "jammy", fixture: filepath.Join("..", "..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"), filename: "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb", reference: "libpqtypes0", signed: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			cfg := config.Default()
			cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{test.dist: {Format: test.format}}}
			if test.signed {
				key, _ := managedTestPrivateKey(t, "remove-check-"+test.format)
				t.Setenv("SOW_TEST_REMOVE_METADATA_KEY", string(key))
				repository := cfg.Repositories["repo"]
				if test.format == "rpm" {
					repository.Signing.RPM.Metadata.Key = "env://SOW_TEST_REMOVE_METADATA_KEY"
				} else {
					repository.Signing.DEB.Metadata.Key = "env://SOW_TEST_REMOVE_METADATA_KEY"
				}
				cfg.Repositories["repo"] = repository
			}
			writeManagedConfig(t, root, cfg)
			if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
				t.Fatal(err)
			}
			inputs := filepath.Join(root, "inputs")
			if err := os.Mkdir(inputs, 0o755); err != nil {
				t.Fatal(err)
			}
			input := decodeManagedFixture(t, test.fixture, filepath.Join(inputs, test.filename))
			options := WorkspaceOptions{Workdir: root, CWD: root}
			if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{test.dist}, Paths: []string{input}, Jobs: 1}); err != nil {
				t.Fatal(err)
			}
			preview, err := Remove(ctx, RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{test.dist}, Packages: []string{test.reference}, Check: true, Jobs: 1})
			if err != nil {
				t.Fatal(err)
			}
			if test.wait {
				time.Sleep(1100 * time.Millisecond)
			}
			actual, err := Remove(ctx, RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{test.dist}, Packages: []string{test.reference}, Jobs: 1})
			if err != nil {
				t.Fatal(err)
			}
			if preview.Generation != actual.Generation || preview.Revision != actual.Revision || !reflect.DeepEqual(preview.Removed, actual.Removed) || !reflect.DeepEqual(preview.Changes, actual.Changes) {
				t.Fatalf("preview does not equal actual build\npreview=%#v\nactual=%#v", preview, actual)
			}
		})
	}
}

func TestRemoveRecoveryConverges(t *testing.T) {
	for _, point := range []string{"rm.planned", "rm.staged", "rm.applied", "build.staged", "build.pointer.el9", "build.built", "build.finalized"} {
		t.Run(point, func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
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
			if _, err := Add(ctx, AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
				t.Fatal(err)
			}
			injected := errors.New("injected")
			_, err := Remove(ctx, RemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Jobs: 1, Fault: func(got string) error {
				if got == point || strings.HasSuffix(point, ".") && strings.HasPrefix(got, point) {
					return injected
				}
				return nil
			}})
			if !errors.Is(err, injected) {
				t.Fatalf("fault=%v", err)
			}
			store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
			if err != nil {
				t.Fatal(err)
			}
			if err := recoverDistOperations(ctx, root, "repo", store); err != nil {
				store.Close()
				t.Fatal(err)
			}
			pending, _ := store.PendingOperations(ctx)
			members, _ := store.ListPackageObjects(ctx, []string{"el9"}, false)
			summary, _ := store.Summary(ctx)
			store.Close()
			wantMembers := 0
			if point == "rm.planned" {
				wantMembers = 1
			}
			if len(pending) != 0 || len(members) != wantMembers || summary.Status != "clean" {
				t.Fatalf("pending=%#v members=%#v summary=%#v", pending, members, summary)
			}
		})
	}
}
