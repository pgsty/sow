package managed

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
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
	previewStarted := time.Now()
	preview, err := Remove(ctx, RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Check: true, Jobs: 1})
	previewFinished := time.Now()
	want, nextErr := high.Next()
	if err != nil || nextErr != nil || preview.Generation != want || len(preview.Changes) == 0 {
		t.Fatalf("high Generation preview=%#v want=%s err=%v nextErr=%v", preview, want, err, nextErr)
	}
	actual, err := Remove(ctx, RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Jobs: 1})
	if err != nil || actual.Generation != want || !sameRemovalChangeSemantics(actual.Changes, preview.Changes) {
		t.Fatalf("high Generation remove=%#v preview=%#v err=%v", actual, preview, err)
	}
	assertRemovalPreviewMetadata(t, root, preview, previewStarted, previewFinished, nil)
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

func TestRemoveSkipReaderBlockedCheckpointRetainsCommittedProjection(t *testing.T) {
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
	if err != nil {
		t.Fatalf("reader-blocked checkpoint rejected durable mutation: result=%#v err=%v", result, err)
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
		t.Fatalf("terminal mutation retained stage: %v", statErr)
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

func TestRemoveCheckPredictsSemanticImmediateBuild(t *testing.T) {
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
		{name: "signed rpm", format: "rpm", dist: "el9", fixture: filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filename: "pgdg-redhat-nonfree-repo.rpm", reference: "pgdg-redhat-nonfree-repo", wait: true, signed: true},
		{name: "signed deb", format: "deb", dist: "jammy", fixture: filepath.Join("..", "..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"), filename: "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb", reference: "libpqtypes0", wait: true, signed: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			cfg := config.Default()
			cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{test.dist: {Format: test.format}}}
			var signingKey []byte
			if test.signed {
				key, _ := managedTestPrivateKey(t, "remove-check-"+test.format)
				signingKey = key
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
			previewStarted := time.Now()
			preview, err := Remove(ctx, RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{test.dist}, Packages: []string{test.reference}, Check: true, Jobs: 1})
			previewFinished := time.Now()
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
			if preview.Generation != actual.Generation || preview.Revision != actual.Revision || !reflect.DeepEqual(preview.Removed, actual.Removed) || !sameRemovalChangeSemantics(preview.Changes, actual.Changes) {
				t.Fatalf("preview does not equal actual build\npreview=%#v\nactual=%#v", preview, actual)
			}
			assertRemovalPreviewMetadata(t, root, preview, previewStarted, previewFinished, signingKey)
			checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
			if err != nil || !checked.ReadyToCopy {
				t.Fatalf("actual signed metadata check=%+v err=%v", checked, err)
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
	previewStarted := time.Now()
	preview, err := Remove(ctx, previewOptions)
	previewFinished := time.Now()
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
	if err != nil || !sameRemovalChangeSemantics(preview.Changes, actual.Changes) {
		t.Fatalf("pending promotion preview differs\npreview=%#v\nactual=%#v\nerr=%v", preview, actual, err)
	}
	assertRemovalPreviewMetadata(t, root, preview, previewStarted, previewFinished, nil)
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
	previewStarted := time.Now()
	preview, err := Remove(ctx, previewOptions)
	previewFinished := time.Now()
	if err != nil {
		t.Fatal(err)
	}
	actual, err := Remove(ctx, removeOptions)
	if err != nil || !sameRemovalChangeSemantics(preview.Changes, actual.Changes) {
		t.Fatalf("missing prior metadata preview differs\npreview=%#v\nactual=%#v\nerr=%v", preview, actual, err)
	}
	assertRemovalPreviewMetadata(t, root, preview, previewStarted, previewFinished, nil)
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
		ctx, repositoryRoot, t.TempDir(), "el9", 1, publicationIdentity{Time: time.Unix(1_700_000_000, 0).UTC()},
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
		ctx, t.TempDir(), t.TempDir(), "el9", 1, publicationIdentity{Time: publishedAt},
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
	previewStarted := time.Now()
	preview, err := Remove(ctx, previewOptions)
	previewFinished := time.Now()
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
	if err != nil || preview.Generation != actual.Generation || preview.Revision != actual.Revision || !sameRemovalChangeSemantics(preview.Changes, actual.Changes) {
		t.Fatalf("mixed-scope preview differs\npreview=%#v\nactual=%#v\nerr=%v", preview, actual, err)
	}
	assertRemovalPreviewMetadata(t, root, preview, previewStarted, previewFinished, nil)
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
			previewStarted := time.Now()
			preview, err := Remove(ctx, RemoveOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{test.dist}, Packages: []string{test.reference}, Check: true, Jobs: 1})
			previewFinished := time.Now()
			if err != nil {
				t.Fatal(err)
			}
			actual, err := Remove(ctx, RemoveOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{test.dist}, Packages: []string{test.reference}, Jobs: 1})
			if err != nil {
				t.Fatal(err)
			}
			if preview.Generation != actual.Generation || !sameRemovalChangeSemantics(preview.Changes, actual.Changes) {
				t.Fatalf("expanded architecture preview differs\npreview=%#v\nactual=%#v", preview, actual)
			}
			assertRemovalPreviewMetadata(t, root, preview, previewStarted, previewFinished, nil)
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

func TestRemovePolicyAuditNormal(t *testing.T) {
	for _, pending := range []bool{false, true} {
		name := "pool"
		if pending {
			name = "pending-skip"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			opts, digests := newRemovePolicyAuditFixture(t, root, pending)
			ctx := context.Background()
			var preview RemoveResult
			if !pending {
				var err error
				previewOpts := opts
				previewOpts.Check = true
				preview, err = Remove(ctx, previewOpts)
				if err != nil || len(preview.Removed) != 2 || preview.Operation != "" {
					t.Fatalf("policy preview=%+v err=%v", preview, err)
				}
			}
			var staged mutationManifest
			opts.Fault = func(point string) error {
				if point != "rm.staged" {
					return nil
				}
				_, staged = readRemovePolicyJournal(t, root)
				return nil
			}
			result, err := Remove(ctx, opts)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Removed) != 2 || result.Dirty != pending {
				t.Fatalf("explicit removals=%+v dirty=%v", result.Removed, result.Dirty)
			}
			if !pending && (!reflect.DeepEqual(preview.Removed, result.Removed) || preview.Generation != result.Generation) {
				t.Fatalf("preview=%+v actual=%+v", preview, result)
			}
			assertRemovePolicyJournal(t, staged, digests)
			assertRemovePolicyAudit(t, root, result.Operation, digests, pending)
		})
	}
}

func TestRemovePolicyAuditRecovery(t *testing.T) {
	for _, pending := range []bool{false, true} {
		name := "pool"
		points := []string{"rm.staged", "rm.applied", "build.pointer.jammy"}
		if pending {
			name = "pending-skip"
			points = points[:2]
		}
		for _, point := range points {
			t.Run(name+"/"+point, func(t *testing.T) {
				root := t.TempDir()
				_, digests := newRemovePolicyAuditFixture(t, root, pending)
				command := exec.Command(os.Args[0], "-test.run=^TestRemovePolicyAuditCrashHelper$")
				command.Env = append(os.Environ(), "SOW_REMOVE_POLICY_ROOT="+root, "SOW_REMOVE_POLICY_POINT="+point)
				if pending {
					command.Env = append(command.Env, "SOW_REMOVE_POLICY_SKIP=1")
				}
				output, err := command.CombinedOutput()
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatalf("crash helper did not exit by signal: %v: %s", err, output)
				}
				status, ok := exit.Sys().(syscall.WaitStatus)
				if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
					t.Fatalf("crash helper was not killed: %v: %s", err, output)
				}
				operation, manifest := readRemovePolicyJournal(t, root)
				assertRemovePolicyJournal(t, manifest, digests)
				ctx := context.Background()
				store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close()
				var first state.OperationDetail
				for attempt := 0; attempt < 2; attempt++ {
					if err := recoverDistOperations(ctx, root, "repo", store); err != nil {
						t.Fatalf("recovery %d: %v", attempt, err)
					}
					detail, err := store.GetOperation(ctx, operation.ID)
					if err != nil {
						t.Fatal(err)
					}
					if attempt == 0 {
						first = detail
					} else if !reflect.DeepEqual(first, detail) {
						t.Fatalf("repeated recovery changed completed audit: first=%+v next=%+v", first, detail)
					}
				}
				active, activeErr := store.PendingOperations(ctx)
				if err := errors.Join(activeErr, store.Close()); err != nil || len(active) != 0 {
					t.Fatalf("pending=%+v err=%v", active, err)
				}
				assertRemovePolicyAudit(t, root, operation.ID, digests, pending)
			})
		}
	}
}

func TestRemovePolicyAuditCrashHelper(t *testing.T) {
	root := os.Getenv("SOW_REMOVE_POLICY_ROOT")
	if root == "" {
		return
	}
	_, err := Remove(context.Background(), RemoveOptions{
		WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo",
		Dists: []string{"noble", "jammy"}, Packages: []string{"remove-me"}, Jobs: 1,
		Skip: os.Getenv("SOW_REMOVE_POLICY_SKIP") == "1",
		Fault: func(point string) error {
			if point != os.Getenv("SOW_REMOVE_POLICY_POINT") {
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
		},
	})
	t.Fatalf("remove crash point was not reached: %v", err)
}

func publicTreeSnapshot(root, repoName string) (map[string]string, error) {
	manifest, err := scanPublicManifest(context.Background(), filepath.Join(root, repoName))
	if err != nil {
		return nil, err
	}
	result := make(map[string]string, len(manifest))
	for _, file := range manifest {
		result[file.Path] = file.SHA256
	}
	return result, nil
}

func newRemovePolicyAuditFixture(t *testing.T, root string, pending bool) (RemoveOptions, map[string]string) {
	t.Helper()
	ctx := context.Background()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{
		"focal": {Format: "deb"}, "jammy": {Format: "deb"}, "noble": {Format: "deb"},
	}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := []string{}
	digests := map[string]string{}
	for _, item := range []struct{ label, name, version string }{
		{"explicit", "remove-me", "1.0-1"}, {"old", "policy-me", "1.0-1"},
		{"new", "policy-me", "2.0-1"}, {"keep", "keep-me", "1.0-1"},
	} {
		body, err := managedBenchmarkDEBBytes(item.name)
		if err != nil {
			t.Fatal(err)
		}
		// These equal-length versions preserve the uncompressed tar entry size.
		body = bytes.Replace(body, []byte("Version: 1.0-1\n"), []byte("Version: "+item.version+"\n"), 1)
		input := filepath.Join(root, item.label+".deb")
		if err := os.WriteFile(input, body, 0o644); err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, input)
		digests[item.label] = bytesSHA(body)
	}
	options := WorkspaceOptions{Workdir: root, CWD: root}
	dists := []string{"noble", "jammy", "focal"}
	if pending {
		// Fully dropped pending objects lose package_objects rows. Audit reasons
		// must remain bound to the operation's durable remove evidence.
		dists = dists[:2]
	}
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: dists, Paths: inputs, Skip: pending, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	repository := cfg.Repositories["repo"]
	repository.Dists["jammy"] = config.DistConfig{Format: "deb", Limit: 1, Exclude: []config.ExcludeRule{{Name: []string{"remove-me"}}}}
	repository.Dists["noble"] = config.DistConfig{Format: "deb", Limit: 1, Exclude: []config.ExcludeRule{{Name: []string{"policy-me", "remove-me"}}}}
	cfg.Repositories["repo"] = repository
	writeManagedConfig(t, root, cfg)
	return RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"noble", "jammy"}, Packages: []string{"remove-me"}, Skip: pending, Jobs: 1}, digests
}

func readRemovePolicyJournal(t *testing.T, root string) (state.Operation, mutationManifest) {
	t.Helper()
	ctx := context.Background()
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	active, err := store.PendingOperations(ctx)
	if err != nil || len(active) != 1 || active[0].Kind != "rm" {
		t.Fatalf("pending remove=%+v err=%v", active, err)
	}
	operation, _, manifest, err := loadMutationJournal(ctx, store, root, "repo", active[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	return operation, manifest
}

func removePolicyAuditMemberships(digests map[string]string) []state.OperationMembership {
	members := []state.OperationMembership{}
	for _, dist := range []string{"jammy", "noble"} {
		removed := []string{digests["explicit"], digests["old"]}
		if dist == "noble" {
			removed = append(removed, digests["new"])
		}
		sort.Strings(removed)
		for _, digest := range removed {
			members = append(members, state.OperationMembership{DistName: dist, PackageSHA256: digest, Action: "remove"})
		}
	}
	members = append(members, state.OperationMembership{DistName: "jammy", PackageSHA256: digests["old"], Action: "limit"})
	excluded := []string{digests["old"], digests["new"]}
	sort.Strings(excluded)
	for _, digest := range excluded {
		members = append(members, state.OperationMembership{DistName: "noble", PackageSHA256: digest, Action: "exclude"})
	}
	for index := range members {
		members[index].Sequence = index
	}
	return members
}

func assertRemovePolicyJournal(t *testing.T, manifest mutationManifest, digests map[string]string) {
	t.Helper()
	want := removePolicyAuditMemberships(digests)[5:]
	got := append([]state.OperationMembership(nil), manifest.Outcomes...)
	sort.Slice(got, func(i, j int) bool {
		if got[i].DistName != got[j].DistName {
			return got[i].DistName < got[j].DistName
		}
		return got[i].PackageSHA256 < got[j].PackageSHA256
	})
	for index := range want {
		want[index].Sequence = 0
	}
	if !reflect.DeepEqual(got, want) || manifest.Result["removed"] != 2 {
		t.Errorf("staged policy outcomes=%+v want=%+v result=%v", got, want, manifest.Result)
	}
}

func assertRemovePolicyAudit(t *testing.T, root, operation string, digests map[string]string, pending bool) {
	t.Helper()
	ctx := context.Background()
	opts := LogOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Operation: operation}
	logged, err := Log(ctx, opts)
	if err != nil || logged.Detail == nil {
		t.Fatalf("remove log=%+v err=%v", logged, err)
	}
	want := removePolicyAuditMemberships(digests)
	if !reflect.DeepEqual(logged.Detail.Memberships, want) {
		t.Errorf("remove audit=%+v want=%+v", logged.Detail.Memberships, want)
	}
	terminal := state.OperationDone
	if pending {
		terminal = state.OperationDoneDirty
	}
	if logged.Detail.Operation.State != terminal || len(logged.Detail.Packages) != 2 {
		t.Fatalf("operation=%+v explicit packages=%+v", logged.Detail.Operation, logged.Detail.Packages)
	}
	for index, item := range logged.Detail.Packages {
		if item.Sequence != index || item.PackageSHA256 != digests["explicit"] || item.Disposition != "removed" || item.InputPath != "remove-me" {
			t.Errorf("explicit package evidence=%+v", item)
		}
	}
	var exported bytes.Buffer
	if _, err := ExportLog(ctx, opts, &exported); err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, line := range bytes.Split(bytes.TrimSpace(exported.Bytes()), []byte("\n")) {
		var detail state.OperationDetail
		if err := json.Unmarshal(line, &detail); err != nil {
			t.Fatal(err)
		}
		if detail.Operation.ID == operation {
			found++
			if !reflect.DeepEqual(detail.Memberships, logged.Detail.Memberships) || !reflect.DeepEqual(detail.Packages, logged.Detail.Packages) {
				t.Errorf("export differs from log: %+v", detail)
			}
		}
	}
	if found != 1 {
		t.Errorf("remove operation exported %d times", found)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	wanted := map[string][]string{"jammy": {digests["new"], digests["keep"]}, "noble": {digests["keep"]}, "focal": {}}
	if !pending {
		wanted["focal"] = []string{digests["explicit"], digests["old"], digests["new"], digests["keep"]}
	}
	for dist, digests := range wanted {
		actual, err := store.MembershipDigests(ctx, dist, false)
		if err != nil || !sameStringSet(actual, digests) {
			t.Errorf("desired %s=%v want=%v err=%v", dist, actual, digests, err)
		}
	}
	if pending {
		objects, err := store.ListPackageObjects(ctx, nil, false)
		if err != nil || len(objects) != 2 {
			t.Fatalf("dropped pending objects remain: objects=%+v err=%v", objects, err)
		}
	}
}

// Metadata and signatures belong to separate operation times. The paired
// assertRemovalPreviewMetadata assertion binds their non-time contents to the
// real preview hashes; all other file bytes (including deletions) remain exact.
func sameRemovalChangeSemantics(left, right []state.FileChange) bool {
	if len(left) != len(right) {
		return false
	}
	for index, a := range left {
		b := right[index]
		if a.Operation != b.Operation || a.Path != b.Path || a.Phase != b.Phase {
			return false
		}
		if a.Operation == "delete" {
			if a.Size != b.Size || a.SHA256 != b.SHA256 {
				return false
			}
			continue
		}
		switch filepath.Base(a.Path) {
		case "repomd.xml", "repomd.xml.asc", "Release", "Release.gpg", "InRelease":
			// These files embed the operation's time or its signature.
		default:
			if a.Size != b.Size || a.SHA256 != b.SHA256 {
				return false
			}
		}
	}
	return true
}

// rm --check removes its temporary files. Recover their exact pointer bytes by
// replacing only the actual build's timestamp/Date with a second from the
// independently measured preview window, then require the preview's SHA and
// size. This preserves every other byte, including revision, checksums,
// locations, sizes, architectures and Release fields. These fixtures' prior
// publications and key activation times precede the measured window.
func assertRemovalPreviewMetadata(t *testing.T, root string, preview RemoveResult, started, finished time.Time, signingKey []byte) {
	t.Helper()
	bodies := map[string][]byte{}
	var publication time.Time
	for _, change := range preview.Changes {
		name := filepath.Base(change.Path)
		if change.Operation == "delete" || name != "repomd.xml" && name != "Release" {
			continue
		}
		actual, err := os.ReadFile(filepath.Join(root, "repo", filepath.FromSlash(change.Path)))
		if err != nil {
			t.Fatal(err)
		}
		var oldTime []byte
		if name == "repomd.xml" {
			var document struct {
				Revision uint64 `xml:"revision"`
				Data     []struct {
					Timestamp int64 `xml:"timestamp"`
				} `xml:"data"`
			}
			if err := xml.Unmarshal(actual, &document); err != nil || document.Revision != uint64(preview.Generation) || len(document.Data) != 3 {
				t.Fatalf("actual repomd revision=%d, want=%d, records=%d, err=%v", document.Revision, preview.Generation, len(document.Data), err)
			}
			oldTime = []byte(fmt.Sprintf("<timestamp>%d</timestamp>", document.Data[0].Timestamp))
			if bytes.Count(actual, oldTime) != len(document.Data) {
				t.Fatal("actual repomd timestamps differ")
			}
		} else {
			for _, line := range bytes.Split(actual, []byte("\n")) {
				if bytes.HasPrefix(line, []byte("Date: ")) {
					if oldTime != nil {
						t.Fatal("duplicate Release Date")
					}
					if _, err := time.Parse(time.RFC1123, string(line[len("Date: "):])); err != nil {
						t.Fatal(err)
					}
					oldTime = append(append([]byte{}, line...), '\n')
				}
			}
			generationLine := []byte("X-SOW-Generation: " + strconv.FormatUint(uint64(preview.Generation), 10) + "\n")
			if oldTime == nil || bytes.Count(actual, generationLine) != 1 {
				t.Fatal("actual Release lacks its Date or expected Generation")
			}
		}
		for at := started.UTC().Truncate(time.Second); !at.After(finished.UTC().Truncate(time.Second)); at = at.Add(time.Second) {
			var replacement []byte
			if name == "repomd.xml" {
				replacement = []byte(fmt.Sprintf("<timestamp>%d</timestamp>", at.Unix()))
			} else {
				replacement = []byte("Date: " + at.Format(time.RFC1123) + "\n")
			}
			candidate := bytes.ReplaceAll(actual, oldTime, replacement)
			if int64(len(candidate)) == change.Size && fmt.Sprintf("%x", sha256.Sum256(candidate)) == change.SHA256 {
				if !publication.IsZero() && !publication.Equal(at) {
					t.Fatal("preview metadata uses different publication times")
				}
				publication, bodies[change.Path] = at, candidate
				break
			}
		}
		if bodies[change.Path] == nil {
			t.Fatalf("preview %s differs from actual metadata beyond timestamp/Date within [%s, %s]", change.Path, started, finished)
		}
	}

	// Deterministic signatures let us bind the recovered preview body to the
	// public preview's signature hashes too, using the fixture's expected key.
	// Verify with OpenPGP directly, independently of managed signing validators.
	for _, change := range preview.Changes {
		name := filepath.Base(change.Path)
		if change.Operation == "delete" || name != "repomd.xml.asc" && name != "Release.gpg" && name != "InRelease" {
			continue
		}
		keys, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(signingKey))
		if err != nil || len(keys) != 1 {
			t.Fatalf("expected preview signing key: %v", err)
		}
		bodyPath := filepath.Join(filepath.Dir(change.Path), "Release")
		if name == "repomd.xml.asc" {
			bodyPath = strings.TrimSuffix(change.Path, ".asc")
		}
		body := bodies[bodyPath]
		if body == nil {
			t.Fatalf("preview signature %s lacks its hash-bound body", change.Path)
		}
		randomizedNotation := false
		cfg := &packet.Config{DefaultHash: crypto.SHA256, Time: func() time.Time { return publication }, NonDeterministicSignaturesViaNotation: &randomizedNotation}
		cfg.InsecureGenerateNonCriticalKeyFlags = name == "repomd.xml.asc"
		cfg.InsecureGenerateNonCriticalSignatureCreationTime = name == "repomd.xml.asc"
		var output bytes.Buffer
		var issuer *openpgp.Entity
		if name == "InRelease" {
			key, ok := keys[0].SigningKey(publication)
			if !ok {
				t.Fatal("expected key cannot sign preview")
			}
			writer, encodeErr := clearsign.Encode(&output, key.PrivateKey, cfg)
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			if _, err := writer.Write(body); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			block, rest := clearsign.Decode(output.Bytes())
			if block == nil || len(rest) != 0 || !bytes.Equal(bytes.TrimSuffix(block.Plaintext, []byte("\n")), bytes.TrimSuffix(body, []byte("\n"))) {
				t.Fatal("preview InRelease body differs from Release")
			}
			issuer, err = openpgp.CheckDetachedSignature(keys, bytes.NewReader(block.Bytes), block.ArmoredSignature.Body, cfg)
		} else {
			if err := openpgp.ArmoredDetachSign(&output, keys[0], bytes.NewReader(body), cfg); err != nil {
				t.Fatal(err)
			}
			issuer, err = openpgp.CheckArmoredDetachedSignature(keys, bytes.NewReader(body), bytes.NewReader(output.Bytes()), cfg)
		}
		if err != nil || issuer == nil || !bytes.Equal(issuer.PrimaryKey.Fingerprint, keys[0].PrimaryKey.Fingerprint) {
			t.Fatalf("preview signature %s is not bound to expected key: %v", change.Path, err)
		}
		if int64(output.Len()) != change.Size || fmt.Sprintf("%x", sha256.Sum256(output.Bytes())) != change.SHA256 {
			t.Fatalf("preview signature %s differs from expected body, time or key", change.Path)
		}
	}
}
