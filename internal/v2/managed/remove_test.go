package managed

import (
	"bytes"
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
	"golang.org/x/sys/unix"
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
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
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
		rpm := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
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
	input := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
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
	input := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
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
	input := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
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
		{name: "rpm", format: "rpm", dist: "el9", fixture: filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filename: "pgdg-redhat-nonfree-repo.rpm", reference: "pgdg-redhat-nonfree-repo"},
		{name: "deb across wall-clock second", format: "deb", dist: "jammy", fixture: filepath.Join("..", "..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"), filename: "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb", reference: "libpqtypes0", wait: true},
		{name: "signed rpm", format: "rpm", dist: "el9", fixture: filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filename: "pgdg-redhat-nonfree-repo.rpm", reference: "pgdg-redhat-nonfree-repo", signed: true},
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

func TestRemoveCheckIncludesPendingPayloadPromotion(t *testing.T) {
	ctx, root, options, firstRPM := newMutationConvergenceFixture(t)
	first, err := Add(ctx, AddOptions{
		WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{firstRPM}, Jobs: 1,
	})
	if err != nil || len(first.Items) != 1 {
		t.Fatalf("first add=%#v err=%v", first, err)
	}
	body, err := os.ReadFile(firstRPM)
	if err != nil {
		t.Fatal(err)
	}
	updated := bytes.ReplaceAll(body, []byte("20PGDG"), []byte("21PGDG"))
	if bytes.Equal(updated, body) {
		t.Fatal("RPM fixture release marker was absent")
	}
	secondRPM := filepath.Join(root, "inputs", "package2.rpm")
	if err := os.WriteFile(secondRPM, updated, 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := Add(ctx, AddOptions{
		WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{secondRPM}, Skip: true, Jobs: 1,
	})
	if err != nil || len(second.Items) != 1 || !second.Dirty {
		t.Fatalf("second skipped add=%#v err=%v", second, err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	pendingObject, objectErr := store.GetPackageObject(ctx, second.Items[0].SHA256)
	closeErr := store.Close()
	if err := errors.Join(objectErr, closeErr); err != nil || pendingObject.Storage != "pending" {
		t.Fatalf("pending object=%#v err=%v", pendingObject, err)
	}
	removeOptions := RemoveOptions{
		WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"},
		Packages: []string{"sha256:" + first.Items[0].SHA256}, Jobs: 1,
	}
	previewOptions := removeOptions
	previewOptions.Check = true
	preview, err := Remove(ctx, previewOptions)
	if err != nil {
		t.Fatal(err)
	}
	foundPayload := false
	for _, change := range preview.Changes {
		if change.Path == pendingObject.PoolPath && change.Phase == "payload" && change.Operation == "add" {
			foundPayload = true
		}
	}
	if !foundPayload {
		t.Fatalf("preview omitted pending Pool promotion for %s: %#v", pendingObject.PoolPath, preview.Changes)
	}
	actual, err := Remove(ctx, removeOptions)
	if err != nil || !reflect.DeepEqual(preview.Changes, actual.Changes) {
		t.Fatalf("pending promotion preview differs\npreview=%#v\nactual=%#v\nerr=%v", preview, actual, err)
	}
}

func TestRemoveCheckMatchesBuildWhenPriorRPMMetadataIsAbsent(t *testing.T) {
	ctx, root, options, rpm := newMutationConvergenceFixture(t)
	if _, err := Add(ctx, AddOptions{
		WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Skip: true, Jobs: 1,
	}); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	repository := cfg.Repositories["repo"]
	dist := repository.Dists["el9"]
	dist.Architectures = []string{"x86_64", "aarch64"}
	repository.Dists["el9"] = dist
	cfg.Repositories["repo"] = repository
	writeManagedConfig(t, root, cfg)
	removeOptions := RemoveOptions{
		WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"},
		Packages: []string{"pgdg-redhat-nonfree-repo"}, Jobs: 1,
	}
	previewOptions := removeOptions
	previewOptions.Check = true
	preview, err := Remove(ctx, previewOptions)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := Remove(ctx, removeOptions)
	if err != nil || !reflect.DeepEqual(preview.Changes, actual.Changes) {
		t.Fatalf("missing prior metadata preview differs\npreview=%#v\nactual=%#v\nerr=%v", preview, actual, err)
	}
}

func TestPreviewRPMDistRejectsUnsafePriorMetadataRoot(t *testing.T) {
	ctx := context.Background()
	repositoryRoot := t.TempDir()
	priorParent := filepath.Join(repositoryRoot, "dists", "el9", "x86_64")
	if err := os.MkdirAll(priorParent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(priorParent, "repodata")); err != nil {
		t.Fatal(err)
	}
	err := previewRPMDist(
		ctx, repositoryRoot, t.TempDir(), "el9", 1, time.Unix(1_700_000_000, 0).UTC(),
		nil, []state.Architecture{{Family: "x86_64", EcosystemArch: "x86_64"}}, nil, nil, 1, nil, map[string]state.GenerationFile{},
	)
	if !errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), "metadata root is unsafe") {
		t.Fatalf("unsafe prior RPM metadata error=%v", err)
	}
}

func TestPreviewRPMDistRejectsRenderedMetadataCollision(t *testing.T) {
	ctx := context.Background()
	architectures := []state.Architecture{{Family: "x86_64", EcosystemArch: "x86_64"}}
	publishedAt := time.Unix(1_700_000_000, 0).UTC()
	seedRoot := t.TempDir()
	if _, err := RenderManagedDist(ctx, seedRoot, ManagedDistSpec{
		Name: "el9", Format: "rpm", Architectures: architectures,
		Generation: 1, Jobs: 1, PublishedAt: publishedAt,
	}); err != nil {
		t.Fatal(err)
	}
	files, err := scanPreviewFiles(ctx, filepath.Join(seedRoot, "dists", "el9"), "dists/el9/")
	if err != nil {
		t.Fatal(err)
	}
	var retained state.GenerationFile
	for _, file := range files {
		if file.Phase == "metadata" {
			retained = file
			break
		}
	}
	if retained.Path == "" {
		t.Fatalf("seed RPM preview has no immutable metadata: %#v", files)
	}
	retained.SHA256 = strings.Repeat("f", 64)
	target := map[string]state.GenerationFile{retained.Path: retained}
	err = previewRPMDist(
		ctx, t.TempDir(), t.TempDir(), "el9", 1, publishedAt,
		architectures, nil, nil, nil, 1, nil, target,
	)
	if !errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), "collision differs by content") {
		t.Fatalf("RPM metadata collision error=%v", err)
	}
}

func TestRemoveCheckRejectsWriteActivePublication(t *testing.T) {
	ctx, root, options, rpm := newMutationConvergenceFixture(t)
	added, err := Add(ctx, AddOptions{
		WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1,
	})
	if err != nil || len(added.Items) != 1 {
		t.Fatalf("add=%#v err=%v", added, err)
	}
	binding, store := bindLocalGCPublicationTarget(t, localGCFixture{root: root})
	summary, summaryErr := store.Summary(ctx)
	manifest, manifestErr := store.GenerationManifest(ctx, summary.BuiltGeneration)
	_, manifestSHA, hashErr := state.ManifestBytes(manifest)
	if err := errors.Join(summaryErr, manifestErr, hashErr); err != nil {
		store.Close()
		t.Fatal(err)
	}
	attempt := state.PublicationAttempt{
		RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity,
		TargetGeneration: summary.BuiltGeneration, ManifestSHA256: manifestSHA,
		PlanSHA256: strings.Repeat("a", 64), Phase: "planned", Views: []state.PublicationAttemptView{},
	}
	putErr := store.PutPublicationAttempt(ctx, &attempt)
	closeErr := store.Close()
	if err := errors.Join(putErr, closeErr); err != nil {
		t.Fatal(err)
	}
	base := RemoveOptions{
		WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"},
		Packages: []string{"sha256:" + added.Items[0].SHA256}, Jobs: 1,
	}
	preview := base
	preview.Check = true
	if _, err := Remove(ctx, preview); !errors.Is(err, ErrNotReady) {
		t.Fatalf("rm --check error=%v, want ErrNotReady", err)
	}
	if _, err := Remove(ctx, base); !errors.Is(err, ErrNotReady) {
		t.Fatalf("rm error=%v, want ErrNotReady", err)
	}
}

func TestConvergingNoopMutationsNormalizePublicModes(t *testing.T) {
	for _, command := range []string{"add", "rm"} {
		t.Run(command, func(t *testing.T) {
			ctx, root, options, firstRPM := newMutationConvergenceFixture(t)
			first, err := Add(ctx, AddOptions{
				WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{firstRPM}, Jobs: 1,
			})
			if err != nil || len(first.Items) != 1 {
				t.Fatalf("first add=%#v err=%v", first, err)
			}
			store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
			if err != nil {
				t.Fatal(err)
			}
			firstObject, objectErr := store.GetPackageObject(ctx, first.Items[0].SHA256)
			closeErr := store.Close()
			if err := errors.Join(objectErr, closeErr); err != nil {
				t.Fatal(err)
			}

			var generation state.GenerationID
			var dirty bool
			if command == "add" {
				if _, err := Remove(ctx, RemoveOptions{
					WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"},
					Packages: []string{"sha256:" + first.Items[0].SHA256}, Skip: true, Jobs: 1,
				}); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(filepath.Join(root, "repo", filepath.FromSlash(firstObject.PoolPath)), 0o600); err != nil {
					t.Fatal(err)
				}
				result, err := Add(ctx, AddOptions{
					WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{firstRPM}, Jobs: 1,
				})
				if err != nil {
					t.Fatal(err)
				}
				generation, dirty = result.Generation, result.Dirty
			} else {
				body, err := os.ReadFile(firstRPM)
				if err != nil {
					t.Fatal(err)
				}
				updated := bytes.ReplaceAll(body, []byte("20PGDG"), []byte("21PGDG"))
				if bytes.Equal(updated, body) {
					t.Fatal("RPM fixture release marker was absent")
				}
				secondRPM := filepath.Join(root, "inputs", "package2.rpm")
				if err := os.WriteFile(secondRPM, updated, 0o600); err != nil {
					t.Fatal(err)
				}
				second, err := Add(ctx, AddOptions{
					WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{secondRPM}, Skip: true, Jobs: 1,
				})
				if err != nil || len(second.Items) != 1 {
					t.Fatalf("second add=%#v err=%v", second, err)
				}
				if err := os.Chmod(filepath.Join(root, "repo", filepath.FromSlash(firstObject.PoolPath)), 0o600); err != nil {
					t.Fatal(err)
				}
				result, err := Remove(ctx, RemoveOptions{
					WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"},
					Packages: []string{"sha256:" + second.Items[0].SHA256}, Jobs: 1,
				})
				if err != nil {
					t.Fatal(err)
				}
				generation, dirty = result.Generation, result.Dirty
			}
			info, err := os.Stat(filepath.Join(root, "repo", filepath.FromSlash(firstObject.PoolPath)))
			mode := os.FileMode(0)
			if err == nil {
				mode = info.Mode().Perm()
			}
			if err != nil || mode != 0o644 || generation != first.Generation || dirty {
				t.Fatalf("normalized mode=%v generation=%s want=%s dirty=%t err=%v", mode, generation, first.Generation, dirty, err)
			}
		})
	}
}

func TestJournaledBuildRecoveryUsesFrozenSigningMaterial(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	options := WorkspaceOptions{Workdir: root, CWD: root}
	privateKey, _ := managedTestPrivateKey(t, "journaled-build-recovery")
	t.Setenv("SOW_TEST_RECOVERY_METADATA_KEY", string(privateKey))
	cfg := config.Default()
	repository := config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	repository.Signing.RPM.Metadata.Key = "env://SOW_TEST_RECOVERY_METADATA_KEY"
	cfg.Repositories["repo"] = repository
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	added, err := Add(ctx, AddOptions{
		WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1,
	})
	if err != nil || len(added.Items) != 1 {
		t.Fatalf("add=%#v err=%v", added, err)
	}
	injected := errors.New("injected after frozen build plan")
	interrupted, err := Remove(ctx, RemoveOptions{
		WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"},
		Packages: []string{"sha256:" + added.Items[0].SHA256}, Jobs: 1,
		Fault: func(point string) error {
			if point == "build.staged" {
				return injected
			}
			return nil
		},
	})
	if !errors.Is(err, injected) {
		t.Fatalf("interrupted remove=%#v err=%v", interrupted, err)
	}
	if err := os.Unsetenv("SOW_TEST_RECOVERY_METADATA_KEY"); err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	recoverErr := recoverDistOperations(ctx, root, "repo", store)
	detail, detailErr := store.GetOperation(ctx, interrupted.Operation)
	summary, summaryErr := store.Summary(ctx)
	closeErr := store.Close()
	if err := errors.Join(recoverErr, detailErr, summaryErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if detail.Operation.State != state.OperationDone || summary.Status != "clean" {
		t.Fatalf("recovered operation=%#v summary=%#v", detail.Operation, summary)
	}
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if err != nil || !checked.ReadyToCopy || checked.Status != "clean" {
		t.Fatalf("post-recovery check=%#v err=%v", checked, err)
	}
}

func TestJournaledBuildRecoveryKeepsFrozenScopeAcrossSigningRotation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	options := WorkspaceOptions{Workdir: root, CWD: root}
	privateKeyA, _ := managedTestPrivateKey(t, "journaled-scope-a")
	privateKeyB, _ := managedTestPrivateKey(t, "journaled-scope-b")
	t.Setenv("SOW_TEST_RECOVERY_SCOPE_KEY", string(privateKeyA))
	cfg := config.Default()
	repository := config.RepositoryConfig{Dists: map[string]config.DistConfig{
		"el9": {Format: "rpm"}, "el10": {Format: "rpm"},
	}}
	repository.Signing.RPM.Metadata.Key = "env://SOW_TEST_RECOVERY_SCOPE_KEY"
	cfg.Repositories["repo"] = repository
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	added, err := Add(ctx, AddOptions{
		WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1,
	})
	if err != nil || len(added.Items) != 1 {
		t.Fatalf("add=%#v err=%v", added, err)
	}
	injected := errors.New("injected after frozen selective build plan")
	interrupted, err := Remove(ctx, RemoveOptions{
		WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9", "el10"},
		Packages: []string{"sha256:" + added.Items[0].SHA256}, Jobs: 1,
		Fault: func(point string) error {
			if point == "build.staged" {
				return injected
			}
			return nil
		},
	})
	if !errors.Is(err, injected) {
		t.Fatalf("interrupted remove=%#v err=%v", interrupted, err)
	}
	t.Setenv("SOW_TEST_RECOVERY_SCOPE_KEY", string(privateKeyB))
	store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	recoverErr := recoverDistOperations(ctx, root, "repo", store)
	detail, detailErr := store.GetOperation(ctx, interrupted.Operation)
	closeErr := store.Close()
	if err := errors.Join(recoverErr, detailErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if detail.Operation.State != state.OperationDone {
		t.Fatalf("recovered operation=%#v", detail.Operation)
	}
	status, err := Status(ctx, StatusOptions{WorkspaceOptions: options, Repository: "repo"})
	if err != nil || status.Status != "dirty" || !reflect.DeepEqual(status.DirtyDists, []string{"el10", "el9"}) {
		t.Fatalf("rotated signing status=%#v err=%v", status, err)
	}
	t.Setenv("SOW_TEST_RECOVERY_SCOPE_KEY", string(privateKeyA))
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if err != nil || !checked.ReadyToCopy || checked.Status != "clean" {
		t.Fatalf("restored signing check=%#v err=%v", checked, err)
	}
}

func TestRemoveCheckIncludesSelectedConfigDirtyDist(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	options := WorkspaceOptions{Workdir: root, CWD: root}
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{
		"el9": {Format: "rpm"}, "el10": {Format: "rpm", Architectures: []string{"x86_64"}},
	}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	repository := cfg.Repositories["repo"]
	el10 := repository.Dists["el10"]
	el10.Architectures = []string{"x86_64", "aarch64"}
	repository.Dists["el10"] = el10
	cfg.Repositories["repo"] = repository
	writeManagedConfig(t, root, cfg)
	removeOptions := RemoveOptions{
		WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9", "el10"},
		Packages: []string{"pgdg-redhat-nonfree-repo"}, Jobs: 1,
	}
	previewOptions := removeOptions
	previewOptions.Check = true
	preview, err := Remove(ctx, previewOptions)
	if err != nil {
		t.Fatal(err)
	}
	foundEL10 := false
	for _, change := range preview.Changes {
		if strings.HasPrefix(change.Path, "dists/el10/") {
			foundEL10 = true
			break
		}
	}
	if !foundEL10 {
		t.Fatalf("preview omitted selected config-dirty el10: %#v", preview.Changes)
	}
	actual, err := Remove(ctx, removeOptions)
	if err != nil || preview.Generation != actual.Generation || preview.Revision != actual.Revision || !reflect.DeepEqual(preview.Changes, actual.Changes) {
		t.Fatalf("mixed-scope preview differs\npreview=%#v\nactual=%#v\nerr=%v", preview, actual, err)
	}
}

func TestRemovePreviewMatchesArchitectureDriftGuards(t *testing.T) {
	type fixture struct {
		format, dist, path, filename, reference string
		base, expanded                          []string
	}
	fixtures := []fixture{
		{
			format: "rpm", dist: "el9", path: filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"),
			filename: "package.rpm", reference: "pgdg-redhat-nonfree-repo", base: []string{"x86_64"}, expanded: []string{"x86_64", "aarch64"},
		},
		{
			format: "deb", dist: "noble", path: filepath.Join("..", "..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"),
			filename: "package.deb", reference: "libpqtypes0", base: []string{"aarch64"}, expanded: []string{"aarch64", "x86_64"},
		},
	}
	setup := func(t *testing.T, test fixture, architectures []string) (context.Context, string, WorkspaceOptions, config.Config) {
		t.Helper()
		ctx := context.Background()
		root := t.TempDir()
		opts := WorkspaceOptions{Workdir: root, CWD: root}
		cfg := config.Default()
		cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{
			test.dist: {Format: test.format, Architectures: architectures},
		}}
		writeManagedConfig(t, root, cfg)
		if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
			t.Fatal(err)
		}
		inputs := filepath.Join(root, "inputs")
		if err := os.Mkdir(inputs, 0o755); err != nil {
			t.Fatal(err)
		}
		input := decodeManagedFixture(t, test.path, filepath.Join(inputs, test.filename))
		if _, err := Add(ctx, AddOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{test.dist}, Paths: []string{input}, Jobs: 1}); err != nil {
			t.Fatal(err)
		}
		return ctx, root, opts, cfg
	}
	differentDeviceTMP := func(t *testing.T, workspace string) string {
		t.Helper()
		var workspaceStat unix.Stat_t
		if err := unix.Stat(workspace, &workspaceStat); err != nil {
			return ""
		}
		for _, candidate := range []string{"/dev/shm", "/var/tmp", "/tmp"} {
			var candidateStat unix.Stat_t
			if err := unix.Stat(candidate, &candidateStat); err != nil || candidateStat.Dev == workspaceStat.Dev {
				continue
			}
			temporary, err := os.MkdirTemp(candidate, "sow-rm-check-device-")
			if err != nil {
				continue
			}
			t.Cleanup(func() { _ = os.RemoveAll(temporary) })
			return temporary
		}
		return ""
	}

	for _, test := range fixtures {
		t.Run(test.format+" architecture expansion", func(t *testing.T) {
			ctx, root, opts, cfg := setup(t, test, test.base)
			repository := cfg.Repositories["repo"]
			dist := repository.Dists[test.dist]
			dist.Architectures = test.expanded
			repository.Dists[test.dist] = dist
			cfg.Repositories["repo"] = repository
			writeManagedConfig(t, root, cfg)
			if temporary := differentDeviceTMP(t, root); temporary != "" {
				t.Setenv("TMPDIR", temporary)
			}
			preview, err := Remove(ctx, RemoveOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{test.dist}, Packages: []string{test.reference}, Check: true, Jobs: 1})
			if err != nil {
				t.Fatal(err)
			}
			actual, err := Remove(ctx, RemoveOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{test.dist}, Packages: []string{test.reference}, Jobs: 1})
			if err != nil {
				t.Fatal(err)
			}
			if preview.Generation != actual.Generation || !reflect.DeepEqual(preview.Changes, actual.Changes) {
				t.Fatalf("expanded architecture preview differs\npreview=%#v\nactual=%#v", preview, actual)
			}
		})

		t.Run(test.format+" architecture removal", func(t *testing.T) {
			ctx, root, opts, cfg := setup(t, test, test.expanded)
			repository := cfg.Repositories["repo"]
			dist := repository.Dists[test.dist]
			dist.Architectures = test.base
			repository.Dists[test.dist] = dist
			cfg.Repositories["repo"] = repository
			writeManagedConfig(t, root, cfg)
			_, previewErr := Remove(ctx, RemoveOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{test.dist}, Packages: []string{test.reference}, Check: true, Jobs: 1})
			_, actualErr := Remove(ctx, RemoveOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{test.dist}, Packages: []string{test.reference}, Jobs: 1})
			if !errors.Is(previewErr, ErrRejected) || !errors.Is(actualErr, ErrRejected) {
				t.Fatalf("architecture removal previewErr=%v actualErr=%v", previewErr, actualErr)
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
			rpm := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
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
