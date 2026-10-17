package managed

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/workmetrics"
	"github.com/pgsty/sow/internal/yumrepo"
)

func holdRepositoryWALSnapshot(ctx context.Context, database string) (func(), error) {
	reader, err := state.OpenExisting(database)
	if err != nil {
		return nil, err
	}
	tx, err := reader.DB().BeginTx(ctx, nil)
	if err != nil {
		reader.Close()
		return nil, err
	}
	var revision int64
	if err := tx.QueryRowContext(ctx, `SELECT desired_revision FROM repository_state WHERE singleton = 1`).Scan(&revision); err != nil {
		tx.Rollback()
		reader.Close()
		return nil, err
	}
	return func() {
		_ = tx.Rollback()
		_ = reader.Close()
	}, nil
}

func managedTestSummary(t *testing.T, root string) state.RepositorySummary {
	t.Helper()
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	summary, err := store.Summary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return summary
}

func TestPackageArchitectureDiagnosticsNameDetectedAllowedAndRepairLocation(t *testing.T) {
	dists := map[string]config.EffectiveDist{
		"noble": {Format: "deb", Architectures: []string{"x86_64"}},
	}
	message := packageCompatibilityDiagnostic("/safe/workspace", "repo", state.PackageObject{
		Format: "deb", Architecture: "arm64", CanonicalArch: "aarch64",
	}, []string{"noble"}, dists)
	for _, required := range []string{"arm64", "aarch64", "amd64", "noble=[x86_64]", "repos.repo.dists.<dist>.architectures", "/safe/workspace/sow.yml"} {
		if !strings.Contains(message, required) {
			t.Fatalf("diagnostic %q does not contain %q", message, required)
		}
	}
	_, _, err := canonicalStateArchitecture("deb", "i386")
	if err == nil {
		t.Fatal("unknown Debian architecture was accepted")
	}
	for _, required := range []string{"i386", "amd64", "arm64", "all", "sow.yml"} {
		if !strings.Contains(err.Error(), required) {
			t.Fatalf("unknown-architecture diagnostic %q does not contain %q", err, required)
		}
	}
}

func sabotageOnlyMutationStage(root, outside string) (func(), error) {
	parent := filepath.Join(root, ".sow", "repo", "stage")
	entries, err := os.ReadDir(parent)
	if err != nil {
		return nil, err
	}
	var stage string
	for _, entry := range entries {
		if entry.IsDir() {
			if stage != "" {
				return nil, errors.New("multiple mutation stages are active")
			}
			stage = filepath.Join(parent, entry.Name())
		}
	}
	if stage == "" {
		return nil, errors.New("mutation stage is missing")
	}
	held := stage + ".held"
	if err := os.Rename(stage, held); err != nil {
		return nil, err
	}
	if err := os.Symlink(outside, stage); err != nil {
		_ = os.Rename(held, stage)
		return nil, err
	}
	return func() {
		_ = os.Remove(stage)
		_ = os.RemoveAll(held)
	}, nil
}

func TestAddReaderBlockedCheckpointRetainsCommittedProjection(t *testing.T) {
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
		input := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
		return root, input
	}
	run := func(t *testing.T, root, input string, skip bool, before state.RepositorySummary, wantDirty bool) {
		t.Helper()
		ctx := context.Background()
		var release func()
		result, err := Add(ctx, AddOptions{
			WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root},
			Repository:       "repo",
			Dists:            []string{"el9"},
			Paths:            []string{input},
			Skip:             skip,
			Jobs:             1,
			Fault: func(point string) error {
				if point != "add.applied" {
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
		wantRevision := before.DesiredRevision
		if skip {
			wantRevision++
		}
		if result.Revision != wantRevision || result.Generation != before.BuiltGeneration || result.Dirty != wantDirty {
			t.Fatalf("committed projection result=%#v before=%#v", result, before)
		}
		store, openErr := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
		if openErr != nil {
			t.Fatal(openErr)
		}
		detail, detailErr := store.GetOperation(ctx, result.Operation)
		store.Close()
		wantState := state.OperationDone
		if wantDirty {
			wantState = state.OperationDoneDirty
		}
		if detailErr != nil || detail.Operation.State != wantState {
			t.Fatalf("terminal audit=%#v err=%v", detail, detailErr)
		}
		if _, statErr := os.Stat(mutationStageRoot(root, "repo", result.Operation)); !os.IsNotExist(statErr) {
			t.Fatalf("terminal mutation retained stage: %v", statErr)
		}
	}

	t.Run("skip changed", func(t *testing.T) {
		root, input := newRepo(t)
		run(t, root, input, true, managedTestSummary(t, root), true)
	})
	t.Run("no change", func(t *testing.T) {
		root, input := newRepo(t)
		if _, err := Add(context.Background(), AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{input}, Jobs: 1}); err != nil {
			t.Fatal(err)
		}
		run(t, root, input, false, managedTestSummary(t, root), false)
	})
}

func TestPostTerminalCleanupFailureRetainsCommittedProjection(t *testing.T) {
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
		input := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
		return root, input
	}
	fault := func(t *testing.T, root, point string) (func(string) error, func()) {
		t.Helper()
		outside := t.TempDir()
		var restore func()
		return func(got string) error {
				if got != point {
					return nil
				}
				var err error
				restore, err = sabotageOnlyMutationStage(root, outside)
				return err
			}, func() {
				if restore != nil {
					restore()
				}
			}
	}

	t.Run("add skip", func(t *testing.T) {
		root, input := newRepo(t)
		before := managedTestSummary(t, root)
		inject, restore := fault(t, root, "add.applied")
		result, err := Add(context.Background(), AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{input}, Skip: true, Jobs: 1, Fault: inject})
		restore()
		if err == nil || result.Revision != before.DesiredRevision+1 || result.Generation != before.BuiltGeneration || !result.Dirty {
			t.Fatalf("result=%#v before=%#v err=%v", result, before, err)
		}
	})

	t.Run("add no change", func(t *testing.T) {
		root, input := newRepo(t)
		if _, err := Add(context.Background(), AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{input}, Jobs: 1}); err != nil {
			t.Fatal(err)
		}
		before := managedTestSummary(t, root)
		inject, restore := fault(t, root, "add.applied")
		result, err := Add(context.Background(), AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{input}, Jobs: 1, Fault: inject})
		restore()
		if err == nil || result.Revision != before.DesiredRevision || result.Generation != before.BuiltGeneration || result.Dirty {
			t.Fatalf("result=%#v before=%#v err=%v", result, before, err)
		}
	})

	t.Run("build noop", func(t *testing.T) {
		root, input := newRepo(t)
		if _, err := Add(context.Background(), AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{input}, Jobs: 1}); err != nil {
			t.Fatal(err)
		}
		before := managedTestSummary(t, root)
		inject, restore := fault(t, root, "build.command.applied")
		result, err := Build(context.Background(), BuildOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Jobs: 1, Fault: inject})
		restore()
		if err == nil || !result.Noop || result.Revision != before.DesiredRevision || result.Generation != before.BuiltGeneration || result.Dirty {
			t.Fatalf("result=%#v before=%#v err=%v", result, before, err)
		}
	})
}

func TestAddRecoveryConvergesAtEveryDurablePhase(t *testing.T) {
	points := []string{"add.planned", "add.staged", "add.applied", "build.staged", "build.payload-linked.", "build.payload-targets", "build.payload.", "build.pointer.el9", "build.built", "build.finalized"}
	for _, point := range points {
		t.Run(strings.TrimSuffix(point, "."), func(t *testing.T) {
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
			injected := errors.New("injected")
			_, err := Add(ctx, AddOptions{
				WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1,
				Fault: func(got string) error {
					if got == point || strings.HasSuffix(point, ".") && strings.HasPrefix(got, point) {
						return injected
					}
					return nil
				},
			})
			if !errors.Is(err, injected) {
				t.Fatalf("fault at %s returned %v", point, err)
			}
			result, err := Add(ctx, AddOptions{
				WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1,
			})
			if err != nil || result.Dirty {
				t.Fatalf("recovery at %s result=%#v err=%v", point, result, err)
			}
			store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
			if err != nil {
				t.Fatal(err)
			}
			pending, pendingErr := store.PendingOperations(ctx)
			summary, summaryErr := store.Summary(ctx)
			objects, objectsErr := store.ListPackageObjects(ctx, []string{"el9"}, true)
			closeErr := store.Close()
			if err := errors.Join(pendingErr, summaryErr, objectsErr, closeErr); err != nil {
				t.Fatal(err)
			}
			if len(pending) != 0 || summary.Status != "clean" || len(objects) != 1 || objects[0].Storage != "pool" {
				t.Fatalf("recovery at %s pending=%#v summary=%#v objects=%#v", point, pending, summary, objects)
			}
		})
	}
}

func TestAddRecoveryPreservesJournaledJobs(t *testing.T) {
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
	injected := errors.New("injected after Desired commit")
	interrupted, err := Add(ctx, AddOptions{
		WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 3,
		Fault: func(point string) error {
			if point == "add.applied" {
				return injected
			}
			return nil
		},
	})
	if !errors.Is(err, injected) || interrupted.Operation == "" {
		t.Fatalf("interrupted add=%#v err=%v", interrupted, err)
	}
	if _, err := Add(ctx, AddOptions{
		WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1,
	}); err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	detail, detailErr := store.GetOperation(ctx, interrupted.Operation)
	closeErr := store.Close()
	if err := errors.Join(detailErr, closeErr); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range detail.Events {
		var progress struct {
			Version   int    `json:"version"`
			Kind      string `json:"kind"`
			Phase     string `json:"phase"`
			Completed int    `json:"completed"`
			Total     int    `json:"total"`
			Jobs      int    `json:"jobs"`
		}
		if err := jsonUnmarshalStrict(event.DetailJSON, &progress); err == nil && progress.Kind == "build_progress" && progress.Phase == "rendering" {
			found = true
			if progress.Jobs != 3 {
				t.Fatalf("recovered rendering jobs=%d, want journaled 3", progress.Jobs)
			}
		}
	}
	if !found {
		t.Fatalf("recovered operation lacks rendering progress: %#v", detail.Events)
	}
}

func TestMutationRecoveryJobsAcceptsLegacyJournalDefault(t *testing.T) {
	var legacy mutationOperationPayload
	if err := jsonUnmarshalStrict(`{"version":2}`, &legacy); err != nil {
		t.Fatal(err)
	}
	if jobs, err := mutationRecoveryJobs(legacy); err != nil || jobs != 1 {
		t.Fatalf("legacy recovery jobs=%d err=%v", jobs, err)
	}
	if jobs, err := mutationRecoveryJobs(mutationOperationPayload{Jobs: 4}); err != nil || jobs != 4 {
		t.Fatalf("journaled recovery jobs=%d err=%v", jobs, err)
	}
	if _, err := mutationRecoveryJobs(mutationOperationPayload{Jobs: -1}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("negative recovery jobs error=%v", err)
	}
}

func TestAddRPMAndDEBBuildsManagedRepository(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{
		"el9":   {Format: "rpm"},
		"noble": {Format: "deb"},
	}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "pgdg-redhat-nonfree-repo.rpm"))
	deb := decodeManagedFixture(t, filepath.Join("..", "..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"), filepath.Join(inputs, "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb"))
	result, err := Add(ctx, AddOptions{
		WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo",
		Dists: []string{"el9", "noble"}, Paths: []string{rpm, deb}, Jobs: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted != 2 || result.Failed != 0 || result.MembershipAdded != 2 || result.Dirty {
		t.Fatalf("result=%#v", result)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	objects, err := store.ListPackageObjects(ctx, nil, false)
	if err != nil || len(objects) != 2 {
		t.Fatalf("objects=%#v err=%v", objects, err)
	}
	for _, object := range objects {
		if object.Storage != "pool" {
			t.Fatalf("object remained %s: %#v", object.Storage, object)
		}
		info, err := os.Stat(filepath.Join(root, "repo", filepath.FromSlash(object.PoolPath)))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o644 {
			t.Fatalf("public package %s mode=%#o want=0644", object.SHA256, info.Mode().Perm())
		}
	}
	for _, family := range []string{"x86_64", "aarch64"} {
		validated, err := yumrepo.ValidateManagedUnsignedDirectory(ctx, filepath.Join(root, "repo", "dists", "el9", family, "repodata"), yumrepo.CompressionGzip)
		if err != nil || validated.Packages != 1 {
			t.Fatalf("rpm view %s=%#v err=%v", family, validated, err)
		}
	}
	packages, err := os.ReadFile(filepath.Join(root, "repo", "dists", "noble", "main", "binary-arm64", "Packages"))
	if err != nil || !strings.Contains(string(packages), "Filename: pool/") {
		t.Fatalf("Packages=%q err=%v", packages, err)
	}
	if _, err := os.Stat(filepath.Join(root, "repo", "dists", "noble", "Release")); err != nil {
		t.Fatal(err)
	}
	manifest, err := store.GenerationManifest(ctx, result.Generation)
	if err != nil || len(manifest) == 0 {
		t.Fatalf("manifest=%#v err=%v", manifest, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Add(ctx, AddOptions{
		WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo",
		Dists: []string{"el9", "noble"}, Paths: []string{rpm, deb}, Jobs: 2,
	})
	if err != nil || second.Generation != result.Generation || second.MembershipAdded != 0 || second.Dirty {
		t.Fatalf("idempotent add=%#v err=%v", second, err)
	}
}

func TestAddMixedBatchCommitsAcceptedPackagesAndReturnsPartial(t *testing.T) {
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
	valid := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "valid.rpm"))
	invalid := filepath.Join(inputs, "invalid.rpm")
	if err := os.WriteFile(invalid, []byte("not an rpm\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	options := WorkspaceOptions{Workdir: root, CWD: root}
	result, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{valid, invalid}, Jobs: 2})
	var partial *PartialError
	committed, committedOK := AddResult{}, false
	if errors.As(err, &partial) {
		committed, committedOK = partial.Result.(AddResult)
	}
	if !committedOK || committed.Operation != result.Operation {
		t.Fatalf("result=%#v partial=%#v err=%v", result, partial, err)
	}
	if result.Accepted != 1 || result.Failed != 1 || result.MembershipAdded != 1 || result.Dirty || result.Generation < 1 || len(result.Items) != 2 {
		t.Fatalf("partial committed result=%#v", result)
	}
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if err != nil || checked.Status != "clean" || !checked.ReadyToCopy {
		t.Fatalf("check after partial=%#v err=%v", checked, err)
	}
	for _, layer := range checked.Layers {
		if !layer.OK || len(layer.Issues) != 0 {
			t.Fatalf("check layer after partial=%#v", layer)
		}
	}
	detail, err := Log(ctx, LogOptions{WorkspaceOptions: options, Repository: "repo", Operation: result.Operation})
	if err != nil || detail.Detail == nil || len(detail.Detail.Packages) != 2 || detail.Detail.Operation.State != state.OperationDone {
		t.Fatalf("partial audit detail=%#v err=%v", detail, err)
	}
}

func TestPreApplyFailuresBecomeFailedButInjectedCrashesRemainRecoverable(t *testing.T) {
	setup := func(t *testing.T) (string, string, AddOptions) {
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
		input := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
		options := AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{input}, Jobs: 1}
		return root, input, options
	}
	readOperation := func(t *testing.T, root, id string) state.Operation {
		t.Helper()
		store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
		if err != nil {
			t.Fatal(err)
		}
		detail, readErr := store.GetOperation(context.Background(), id)
		closeErr := store.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			t.Fatal(err)
		}
		return detail.Operation
	}

	t.Run("ordinary stage error", func(t *testing.T) {
		root, _, options := setup(t)
		options.Fault = func(point string) error {
			if point != "add.planned" {
				return nil
			}
			store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
			if err != nil {
				return err
			}
			pending, pendingErr := store.PendingOperations(context.Background())
			closeErr := store.Close()
			if err := errors.Join(pendingErr, closeErr); err != nil {
				return err
			}
			if len(pending) != 1 {
				return fmt.Errorf("expected one pending operation, got %d", len(pending))
			}
			return os.Mkdir(mutationStageRoot(root, "repo", pending[0].ID), 0o700)
		}
		result, err := Add(context.Background(), options)
		if err == nil || result.Operation == "" {
			t.Fatalf("stage sabotage result=%#v err=%v", result, err)
		}
		operation := readOperation(t, root, result.Operation)
		if operation.State != state.OperationFailed || operation.ErrorClass != "runtime" || operation.ErrorMessage != "operation failed before Desired state was applied" {
			t.Fatalf("ordinary failure operation=%#v", operation)
		}
		if _, statErr := os.Lstat(mutationStageRoot(root, "repo", result.Operation)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("failed operation retained stage: %v", statErr)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		root, _, options := setup(t)
		runCtx, cancel := context.WithCancel(context.Background())
		options.Fault = func(point string) error {
			if point == "add.planned" {
				cancel()
			}
			return nil
		}
		result, err := Add(runCtx, options)
		if !errors.Is(err, context.Canceled) || result.Operation == "" {
			t.Fatalf("cancelled result=%#v err=%v", result, err)
		}
		operation := readOperation(t, root, result.Operation)
		if operation.State != state.OperationFailed || operation.ErrorClass != "cancelled" {
			t.Fatalf("cancelled operation=%#v", operation)
		}
	})

	t.Run("injected crash", func(t *testing.T) {
		root, _, options := setup(t)
		injected := errors.New("simulated process stop")
		options.Fault = func(point string) error {
			if point == "add.planned" {
				return injected
			}
			return nil
		}
		result, err := Add(context.Background(), options)
		if !errors.Is(err, injected) || result.Operation == "" {
			t.Fatalf("injected result=%#v err=%v", result, err)
		}
		operation := readOperation(t, root, result.Operation)
		if operation.State != state.OperationPlanned || operation.ErrorClass != "" {
			t.Fatalf("injected operation was terminalized: %#v", operation)
		}
	})
}

func TestPackageSignerFailureIsAuditedWithoutSecretMaterial(t *testing.T) {
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
	privateKey, fingerprint := managedTestPrivateKey(t, "package-failure")
	const keyEnv = "SOW_TEST_PACKAGE_FAILURE_KEY"
	t.Setenv(keyEnv, string(privateKey))
	repository := cfg.Repositories["repo"]
	repository.Signing.RPM.Packages = config.RPMPackageSigningConfig{Mode: "fill", Key: "env://" + keyEnv}
	cfg.Repositories["repo"] = repository
	writeManagedConfig(t, root, cfg)
	tools := t.TempDir()
	gpg := "#!/bin/sh\ncase \" $* \" in\n  *\" --list-secret-keys \"*) printf 'sec::::::::::\\nfpr:::::::::" + fingerprint + ":\\n';;\n  *) :;;\nesac\n"
	if err := os.WriteFile(filepath.Join(tools, "gpg"), []byte(gpg), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tools, "rpm"), []byte("#!/bin/sh\nexit 41\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))
	result, err := Add(ctx, AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{input}, Jobs: 1})
	if !errors.Is(err, ErrRejected) || result.Operation == "" || result.Failed != 1 {
		t.Fatalf("signer failure result=%#v err=%v", result, err)
	}
	store, openErr := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if openErr != nil {
		t.Fatal(openErr)
	}
	detail, detailErr := store.GetOperation(ctx, result.Operation)
	closeErr := store.Close()
	if err := errors.Join(detailErr, closeErr); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(detail)
	if detail.Operation.State != state.OperationFailed || bytes.Contains(encoded, privateKey) || bytes.Contains(encoded, []byte(fingerprint)) {
		t.Fatalf("unsafe signer failure audit: state=%s audit=%s", detail.Operation.State, encoded)
	}
}

func TestRPMSigningChildUsesBoundDirectoryAndPreservesParentCWD(t *testing.T) {
	tools := t.TempDir()
	rpm := filepath.Join(tools, "rpm")
	script := `#!/bin/sh
set -eu
target=
for arg do target=$arg; done
printf '%s\n' "$*" > rpm-call.txt
printf '\nsigned-by-child\n' >> "$target"
`
	if err := os.WriteFile(rpm, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))
	before, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	const keyID = "0123456789ABCDEF0123456789ABCDEF01234567"
	results := make(chan error, 4)
	targets := make([]string, 0, 4)
	for index := range 4 {
		parent := filepath.Join(t.TempDir(), fmt.Sprintf("stage-%d", index))
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(parent, fmt.Sprintf("package-%d.rpm", index))
		if err := os.WriteFile(target, []byte("original\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		targets = append(targets, target)
		go func() {
			results <- signManagedRPM(context.Background(), target, keyID, false)
		}()
	}
	for range targets {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("RPM signing changed parent cwd: before=%q after=%q", before, after)
	}
	for _, target := range targets {
		data, err := os.ReadFile(target)
		if err != nil || !bytes.Contains(data, []byte("signed-by-child")) {
			t.Fatalf("signed target %q data=%q err=%v", target, data, err)
		}
		call, err := os.ReadFile(filepath.Join(filepath.Dir(target), "rpm-call.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(call, []byte("/dev/fd")) || bytes.Contains(call, []byte("/proc/self/fd")) || !bytes.Contains(call, []byte("--addsign "+filepath.Base(target))) || !bytes.Contains(call, []byte("_gpg_name "+keyID)) {
			t.Fatalf("unexpected child rpm arguments: %q", call)
		}
	}
}

func TestRPMSigningChildCannotBeRedirectedByParentPathReplacement(t *testing.T) {
	tools := t.TempDir()
	rpm := filepath.Join(tools, "rpm")
	script := `#!/bin/sh
set -eu
target=
for arg do target=$arg; done
: > .entered
while [ ! -f .release ]; do sleep 0.01; done
printf '\nsigned-original\n' >> "$target"
`
	if err := os.WriteFile(rpm, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))
	root := t.TempDir()
	parent := filepath.Join(root, "stage")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "package.rpm")
	if err := os.WriteFile(target, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const keyID = "0123456789ABCDEF0123456789ABCDEF01234567"
	result := make(chan error, 1)
	go func() {
		result <- signManagedRPM(context.Background(), target, keyID, true)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(parent, ".entered")); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("RPM signing child did not enter the bound directory")
		}
		time.Sleep(10 * time.Millisecond)
	}
	moved := filepath.Join(root, "moved-stage")
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(parent, filepath.Base(target))
	if err := os.WriteFile(replacement, []byte("outside-sentinel\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moved, ".release"), []byte("go\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "pathname changed") {
			t.Fatalf("parent replacement was not rejected: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RPM signing child did not finish")
	}
	replacementData, err := os.ReadFile(replacement)
	if err != nil || string(replacementData) != "outside-sentinel\n" {
		t.Fatalf("replacement target was modified: data=%q err=%v", replacementData, err)
	}
	originalData, err := os.ReadFile(filepath.Join(moved, filepath.Base(target)))
	if err != nil || !bytes.Contains(originalData, []byte("signed-original")) {
		t.Fatalf("bound original was not signed: data=%q err=%v", originalData, err)
	}
}

func TestAllFailedAddCannotReconcileUnrelatedPolicyChange(t *testing.T) {
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
	valid := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "valid.rpm"))
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{valid}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	beforeTree, err := publicTreeSnapshot(root, "repo")
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	beforeSummary, err := store.Summary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	beforeMemberships, err := store.MembershipDigests(ctx, "el9", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {
		Format:  "rpm",
		Exclude: []config.ExcludeRule{{Name: []string{"pgdg-redhat-nonfree-repo"}}},
	}}}
	writeManagedConfig(t, root, cfg)
	invalid := filepath.Join(inputs, "invalid.rpm")
	if err := os.WriteFile(invalid, []byte("not an rpm\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	result, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{invalid}, Jobs: 1})
	if !errors.Is(err, ErrRejected) || result.Accepted != 0 || result.Failed != 1 {
		t.Fatalf("all-failed add=%#v err=%v", result, err)
	}
	afterTree, err := publicTreeSnapshot(root, "repo")
	if err != nil {
		t.Fatal(err)
	}
	if len(beforeTree) != len(afterTree) {
		t.Fatalf("all-failed add changed public tree size: before=%d after=%d", len(beforeTree), len(afterTree))
	}
	for name, digest := range beforeTree {
		if afterTree[name] != digest {
			t.Fatalf("all-failed add changed public path %s", name)
		}
	}
	store, err = state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	afterSummary, err := store.Summary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	afterMemberships, err := store.MembershipDigests(ctx, "el9", false)
	if err != nil {
		t.Fatal(err)
	}
	if beforeSummary.BuiltGeneration != afterSummary.BuiltGeneration || beforeSummary.DesiredRevision != afterSummary.DesiredRevision || strings.Join(beforeMemberships, "\n") != strings.Join(afterMemberships, "\n") {
		t.Fatalf("all-failed add changed repository projection: before=%#v/%v after=%#v/%v", beforeSummary, beforeMemberships, afterSummary, afterMemberships)
	}
	last, err := store.LastOperation(ctx)
	if err != nil || last == nil || last.ID != result.Operation || last.State != state.OperationFailed || last.ErrorClass != "rejected" || last.ErrorMessage != "no input package was accepted" {
		t.Fatalf("all-failed audit=%#v err=%v", last, err)
	}
}

func TestDistRemovalRecoversFinalPendingObjectCleanup(t *testing.T) {
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
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "pending.rpm"))
	added, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Skip: true, Jobs: 1})
	if err != nil || added.Accepted != 1 {
		t.Fatalf("skipped add=%#v err=%v", added, err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	objects, err := store.ListPackageObjects(ctx, []string{"el9"}, false)
	if err != nil || len(objects) != 1 || objects[0].Storage != "pending" {
		store.Close()
		t.Fatalf("pending objects=%#v err=%v", objects, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	pendingPath := filepath.Join(root, ".sow", "repo", "pending", objects[0].SHA256)
	injected := errors.New("injected after Dist removal SQL commit")
	_, err = RemoveDistResult(ctx, DistRemoveOptions{WorkspaceOptions: options, Repository: "repo", Name: "el9", Force: true, Fault: func(point string) error {
		if point == "dist.rm.finalized" {
			return injected
		}
		return nil
	}})
	if !errors.Is(err, injected) {
		t.Fatalf("Dist removal fault=%v", err)
	}
	if _, err := os.Stat(pendingPath); err != nil {
		t.Fatalf("fault did not preserve pending cleanup evidence: %v", err)
	}
	if _, err := RemoveDistResult(ctx, DistRemoveOptions{WorkspaceOptions: options, Repository: "repo", Name: "el9", Force: true}); err != nil {
		t.Fatalf("recover Dist removal: %v", err)
	}
	if _, err := os.Stat(pendingPath); !os.IsNotExist(err) {
		t.Fatalf("recovery retained unreachable pending bytes: %v", err)
	}
	store, err = state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.GetPackageObject(ctx, objects[0].SHA256); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("unreachable pending object remains in SQLite: %v", err)
	}
}

func decodeManagedFixture(t *testing.T, source, destination string) string {
	t.Helper()
	encoded, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, payload, 0o444); err != nil {
		t.Fatal(err)
	}
	return destination
}

func TestReAddedCoordinatesSkipPoolPathOwnerHistory(t *testing.T) {
	ctx := context.Background()
	root, ws := newRejectionWorkspace(t)
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: collidingRPMInputs(t, root)[:1], Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	objects, err := store.ListPackageObjects(ctx, nil, false)
	if err != nil || len(objects) != 1 {
		t.Fatalf("objects=%v err=%v", objects, err)
	}
	existing := objects[0]
	freshPath, err := filepath.Abs("../../../third_party/cavaliergopher-rpm/testdata/epel-release-7-5.noarch.rpm")
	if err != nil {
		t.Fatal(err)
	}
	existingPath := filepath.Join(root, "one", "centos-release-latest.rpm")
	stage := filepath.Join(root, "probe-stage")
	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}
	inspected, lookups := inspectInputs(ctx, stage, []inputFile{
		{Path: existingPath, Base: filepath.Base(existingPath)},
		{Path: freshPath, Base: filepath.Base(freshPath)},
		{Path: filepath.Join(root, "absent.rpm"), Base: "absent.rpm"},
	}, 2, store)
	candidates := newInputPoolPaths(inspected, lookups)
	if inspected[0].Err != nil || inspected[1].Err != nil || inspected[2].Err == nil {
		t.Fatalf("inspections=%+v", inspected)
	}
	if len(candidates) != 1 || candidates[0] != inspected[1].Object.PoolPath {
		t.Fatalf("path-owner candidates=%v; re-added coordinates must not query their path history", candidates)
	}
	if lookups[0].err != nil || lookups[0].object.SHA256 != existing.SHA256 || !errors.Is(lookups[1].err, state.ErrNotFound) {
		t.Fatalf("coordinate lookups=%#v", lookups)
	}
	staged, err := os.ReadDir(stage)
	if err != nil || len(staged) != 1 || staged[0].Name() != "00000001-"+filepath.Base(freshPath) {
		t.Fatalf("only the new input should have a temporary copy: %v %v", staged, err)
	}
}

func TestSourceDirectorySpellingsRejectOnlyCaseAliases(t *testing.T) {
	spellings := sourceDirectorySpellings{}
	spellings.remember("pool/c/casedemo/", "pool/c/CaseDemo/")
	if err := spellings.check(state.PackageObject{PoolPath: "pool/c/CaseDemo/CaseDemo-2-1.noarch.rpm"}); err != nil {
		t.Fatalf("same source directory rejected: %v", err)
	}
	if err := spellings.check(state.PackageObject{PoolPath: "pool/c/casedemo/casedemo-2-1.noarch.rpm"}); !errors.Is(err, state.ErrPoolPathConflict) || !strings.Contains(err.Error(), "pool/c/CaseDemo") {
		t.Fatalf("case alias of an existing source directory accepted: %v", err)
	}
	other := state.PackageObject{PoolPath: "pool/o/other/other-1-1.noarch.rpm"}
	if err := spellings.check(other); err != nil {
		t.Fatal(err)
	}
	spellings.add(other)
	if err := spellings.check(state.PackageObject{PoolPath: "pool/o/Other/Other-1-1.noarch.rpm"}); !errors.Is(err, state.ErrPoolPathConflict) {
		t.Fatalf("case alias within one batch accepted: %v", err)
	}
	var caseSensitive sourceDirectorySpellings
	if err := caseSensitive.check(state.PackageObject{PoolPath: "pool/c/casedemo/casedemo-2-1.noarch.rpm"}); err != nil {
		t.Fatalf("case-sensitive workspace rejected distinct directories: %v", err)
	}
	caseSensitive.add(other)
}

// Each descriptor's routing metadata and digest must describe one complete
// identity interval, even when a rewrite preserves size and restores mtime.
func TestIngestProbeDiscardsFactsAcrossCTimeDrift(t *testing.T) {
	for _, copyPayload := range []bool{false, true} {
		t.Run(fmt.Sprint("copy=", copyPayload), func(t *testing.T) {
			root := t.TempDir()
			data, err := managedBenchmarkDEBBytes("identity-demo")
			if err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(root, "demo.deb")
			if err := os.WriteFile(source, data, 0600); err != nil {
				t.Fatal(err)
			}
			input := inputFile{Path: source, Base: "demo.deb"}
			probe, err := openInputProbe(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			// Only a non-coordinate control field changes, with exactly the
			// same byte length. A fresh digest must not bless the old facts.
			changed := bytes.Replace(data, []byte("Description: managed build performance fixture"), []byte("Description: changed build performance fixture"), 1)
			if bytes.Equal(data, changed) || len(data) != len(changed) {
				t.Fatal("fixture mutation is not equal-length")
			}
			if err := os.WriteFile(source, changed, 0600); err != nil {
				t.Fatal(err)
			}
			// The rewrite can share a filesystem clock tick with the probe.
			restoreContentFixtureMTime(t, source, probe.opened.file, probe.before)
			ctx, metrics := workmetrics.Ensure(context.Background())
			result := inspectProbedInput(ctx, probe, filepath.Join(root, "snapshot.deb"), input.Base, copyPayload)
			if result.Err != nil {
				t.Fatal(result.Err)
			}
			if result.SHA256 != bytesSHA(changed) {
				t.Fatalf("digest=%s want=%s", result.SHA256, bytesSHA(changed))
			}
			facts, err := aptrepo.PackageFromFacts(result.Facts, source)
			if err != nil {
				t.Fatal(err)
			}
			if value, _ := facts.ControlValue("Description"); value != "changed build performance fixture" {
				t.Fatalf("stale facts were authenticated: %q", value)
			}
			if got := metrics.Snapshot().FullPackageReads; got != 2 {
				t.Fatalf("whole input attempts=%d, want exactly two", got)
			}
		})
	}
}

func TestIngestProbeRejectsCoordinateAndNamespaceReplacement(t *testing.T) {
	for _, replacement := range []string{"coordinate", "namespace"} {
		t.Run(replacement, func(t *testing.T) {
			root := t.TempDir()
			data, err := managedBenchmarkDEBBytes("identity-demo")
			if err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(root, "demo.deb")
			if err := os.WriteFile(source, data, 0600); err != nil {
				t.Fatal(err)
			}
			probe, err := openInputProbe(context.Background(), inputFile{Path: source, Base: "demo.deb"})
			if err != nil {
				t.Fatal(err)
			}
			info, _ := os.Stat(source)
			if replacement == "namespace" {
				if err := os.Rename(source, source+".held"); err != nil {
					t.Fatal(err)
				}
			} else {
				data = bytes.ReplaceAll(data, []byte("identity-demo"), []byte("identity-diff"))
			}
			if err := os.WriteFile(source, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(source, info.ModTime(), info.ModTime()); err != nil {
				t.Fatal(err)
			}
			result := inspectProbedInput(context.Background(), probe, filepath.Join(root, "snapshot.deb"), "demo.deb", false)
			if result.Err == nil {
				t.Fatalf("accepted %s: %+v", replacement, result.Object)
			}
		})
	}
}

func TestIngestSameBatchDuplicateAndRejectedPredecessor(t *testing.T) {
	for _, jobs := range []int{1, 3} {
		for _, rejectFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("jobs=%d/reject-first=%v", jobs, rejectFirst), func(t *testing.T) {
				root, ws := newRejectionWorkspace(t)
				colliding := collidingRPMInputs(t, root)
				if rejectFirst {
					if _, err := Add(context.Background(), AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: colliding[:1], Skip: true, Jobs: 1}); err != nil {
						t.Fatal(err)
					}
				}
				data, err := os.ReadFile(colliding[1])
				if err != nil {
					t.Fatal(err)
				}
				second := filepath.Join(root, "two", "renamed.rpm")
				if err := os.WriteFile(second, data, 0600); err != nil {
					t.Fatal(err)
				}
				result, err := Add(context.Background(), AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: []string{colliding[1], second}, Skip: true, Jobs: jobs})
				if rejectFirst {
					var partial *PartialError
					if !errors.As(err, &partial) || result.Accepted != 1 || result.Failed != 1 || result.Items[1].Status != "accepted" {
						t.Fatalf("result=%+v err=%v", result, err)
					}
				} else if err != nil || result.Accepted != 2 || result.Failed != 0 || result.Items[0].Status != "accepted" || result.Items[1].Status != "reused" || result.Items[0].SHA256 != result.Items[1].SHA256 {
					t.Fatalf("result=%+v err=%v", result, err)
				}
			})
		}
	}
}

func TestDuplicateIngestAuthenticatesPendingAndFallback(t *testing.T) {
	for _, scenario := range []string{"pending", "fallback", "missing", "corrupt", "symlink"} {
		t.Run(scenario, func(t *testing.T) {
			root, ws := newRejectionWorkspace(t)
			source := decodeManagedFixture(t, "../../testdata/pgdg-redhat-nonfree-repo.rpm.b64", filepath.Join(root, "package.rpm"))
			opts := AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: []string{source}, Skip: true, Jobs: 1}
			first, err := Add(context.Background(), opts)
			if err != nil {
				t.Fatal(err)
			}
			store, err := state.OpenExisting(filepath.Join(root, ".sow/repo.db"))
			if err != nil {
				t.Fatal(err)
			}
			objects, err := store.ListPackageObjects(context.Background(), nil, false)
			if err != nil || len(objects) != 1 {
				t.Fatalf("objects=%v err=%v", objects, err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			object := objects[0]
			pending := filepath.Join(root, ".sow/repo/pending", object.SHA256)
			original, err := os.ReadFile(pending)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "fallback":
				pool := filepath.Join(root, "repo", object.PoolPath)
				if err := os.MkdirAll(filepath.Dir(pool), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(pending, pool); err != nil {
					t.Fatal(err)
				}
			case "missing", "symlink":
				if err := os.Remove(pending); err != nil {
					t.Fatal(err)
				}
				if scenario == "symlink" {
					if err := os.Symlink(source, pending); err != nil {
						t.Fatal(err)
					}
				}
			case "corrupt":
				changed := append([]byte(nil), original...)
				changed[len(changed)-1] ^= 1
				if err := os.WriteFile(pending, changed, 0644); err != nil {
					t.Fatal(err)
				}
			}
			ctx, metrics := workmetrics.Ensure(context.Background())
			if scenario == "fallback" {
				// This is the source resolver's promotion fallback. A public
				// body not yet in the current manifest is intentionally not a
				// valid entry point for an ordinary Add before recovery.
				backing, err := availableManagedPackageSource(root, "repo", object)
				if err != nil || backing.Path != filepath.Join(root, "repo", object.PoolPath) {
					t.Fatalf("fallback=%+v err=%v", backing, err)
				}
				ok, err := verifyIngestReuse(ctx, backing, newPayloadEvidenceRegistry(), rpmSigningPolicy{mode: "never"}, false)
				if err != nil || !ok || metrics.Snapshot().FullPackageReads != 1 {
					t.Fatalf("fallback proof=%v err=%v metrics=%+v", ok, err, metrics.Snapshot())
				}
				return
			}
			second, err := Add(ctx, opts)
			if scenario == "pending" {
				if err != nil || second.Accepted != 1 || second.Items[0].Status != "reused" || second.Revision != first.Revision {
					t.Fatalf("result=%+v err=%v", second, err)
				}
				if got := metrics.Snapshot().PayloadByPhase["ingest"].Full; got != 2 {
					t.Fatalf("input + backing authentication=%d, want 2", got)
				}
			} else {
				if err == nil || second.Accepted != 0 {
					t.Fatalf("accepted unsafe backing: %+v %v", second, err)
				}
				if scenario == "corrupt" {
					current, _ := os.ReadFile(pending)
					if bytes.Equal(current, original) {
						t.Fatal("duplicate silently healed the corrupt body")
					}
				}
			}
		})
	}
}

type ingestTestContext struct {
	context.Context
	check func() error
}

func (ctx ingestTestContext) Err() error { return ctx.check() }

func TestIngestWholeAttemptBoundAndCancellation(t *testing.T) {
	for _, copyPayload := range []bool{false, true} {
		for _, scenario := range []string{"continuous-ctime", "cancel"} {
			t.Run(fmt.Sprintf("copy=%v/%s", copyPayload, scenario), func(t *testing.T) {
				root := t.TempDir()
				data, err := managedBenchmarkDEBBytesWithPayload("identity-demo", 128<<10)
				if err != nil {
					t.Fatal(err)
				}
				source := filepath.Join(root, "demo.deb")
				if err := os.WriteFile(source, data, 0600); err != nil {
					t.Fatal(err)
				}
				probe, err := openInputProbe(context.Background(), inputFile{Path: source, Base: "demo.deb"})
				if err != nil {
					t.Fatal(err)
				}
				calls := 0
				changing := ingestTestContext{Context: context.Background(), check: func() error {
					calls++
					if scenario == "cancel" {
						if calls >= 2 {
							return context.Canceled
						}
						return nil
					}
					before, err := snapshotRegularDescriptorIdentity(probe.opened.file)
					if err != nil {
						return err
					}
					if err := os.Link(source, source+".link"); err != nil {
						return err
					}
					if err := os.Remove(source + ".link"); err != nil {
						return err
					}
					// Each injection must advance ctime, even within one clock tick.
					restoreContentFixtureMTime(t, source, probe.opened.file, before)
					return nil
				}}
				ctx, metrics := workmetrics.Ensure(changing)
				snapshot := filepath.Join(root, "snapshot.deb")
				result := inspectProbedInput(ctx, probe, snapshot, "demo.deb", copyPayload)
				if result.Err == nil {
					t.Fatalf("accepted unstable input: %+v", result)
				}
				if scenario == "cancel" && !errors.Is(result.Err, context.Canceled) {
					t.Fatalf("cancellation lost: %v", result.Err)
				}
				if scenario == "continuous-ctime" && metrics.Snapshot().FullPackageReads != 2 {
					t.Fatalf("attempts=%+v", metrics.Snapshot())
				}
				if _, err := os.Stat(snapshot); !os.IsNotExist(err) {
					t.Fatalf("failed input left payload stage: %v", err)
				}
				if _, err := probe.opened.file.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Fatalf("source descriptor leaked: %v", err)
				}
			})
		}
	}
}

func TestDuplicateIngestRPMNeutralPolicy(t *testing.T) {
	for _, mode := range []string{"never", "fill", "always", "untrusted"} {
		t.Run(mode, func(t *testing.T) {
			var root string
			var ws WorkspaceOptions
			if mode == "never" {
				root, ws = newRejectionWorkspace(t)
				input := decodeManagedFixture(t, "../../testdata/pgdg-redhat-nonfree-repo.rpm.b64", filepath.Join(root, "package.rpm"))
				if _, err := Add(context.Background(), AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: []string{input}, Jobs: 1}); err != nil {
					t.Fatal(err)
				}
			} else {
				selected := mode
				if selected == "untrusted" {
					selected = "always"
				}
				var cfg config.Config
				root, ws, cfg = rpmPolicyCacheFixture(t, selected)
				if mode == "untrusted" {
					repo := cfg.Repositories["repo"]
					repo.Signing.RPM.Packages.Key = "file://wrong.asc"
					cfg.Repositories["repo"] = repo
					writeManagedConfig(t, root, cfg)
				}
			}
			data, err := os.ReadFile(filepath.Join(root, "package.rpm"))
			if err != nil {
				t.Fatal(err)
			}
			// The legacy lead's name is outside the neutral digest and the
			// cryptographic signature. The package metadata stays identical.
			data[10] ^= 1
			variant := filepath.Join(root, "variant.rpm")
			if err := os.WriteFile(variant, data, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, metrics := workmetrics.Ensure(context.Background())
			result, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: []string{variant}, Jobs: 1})
			if mode == "never" || mode == "untrusted" {
				if !errors.Is(err, ErrRejected) || result.Accepted != 0 {
					t.Fatalf("neutral reuse bypassed %s: %+v %v", mode, result, err)
				}
			} else {
				if err != nil || result.Accepted != 1 || result.Items[0].Status != "reused" {
					t.Fatalf("neutral %s: %+v %v", mode, result, err)
				}
				if metrics.Snapshot().SignatureStreams == 0 {
					t.Fatal("neutral reuse skipped cryptographic authorization")
				}
			}
		})
	}
}

func TestIngestSigningRejectedPredecessorDoesNotPoisonNextInput(t *testing.T) {
	root, ws := newRejectionWorkspace(t)
	cfg, err := config.Load(filepath.Join(root, "sow.yml"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile("../../testdata/PGDG-RPM-GPG-KEY-RHEL-nonfree.asc")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pgdg.asc"), key, 0600); err != nil {
		t.Fatal(err)
	}
	repo := cfg.Repositories["repo"]
	repo.Signing.RPM.Packages = config.RPMPackageSigningConfig{Mode: "always", Key: "file://pgdg.asc"}
	cfg.Repositories["repo"] = repo
	writeManagedConfig(t, root, cfg)
	tools := t.TempDir()
	if err := os.WriteFile(filepath.Join(tools, "gpg"), []byte("#!/bin/sh\nlast=\nfor arg in \"$@\"; do last=\"$arg\"; done\ncase \" $* \" in\n *\" --list-secret-keys \"*) printf 'sec::::::::::\\nfpr:::::::::%s:\\n' \"$last\";;\nesac\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tools, "rpm"), []byte("#!/bin/sh\nexit 41\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))
	good := decodeManagedFixture(t, "../../testdata/pgdg-redhat-nonfree-repo.rpm.b64", filepath.Join(root, "b-good.rpm"))
	data, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	originalSHA := bytesSHA(data)
	entries := int(binary.BigEndian.Uint32(data[104:108]))
	store := 112 + 16*entries
	changed := false
	for index := 0; index < entries; index++ {
		i := 112 + 16*index
		tag := binary.BigEndian.Uint32(data[i : i+4])
		if tag != 268 && tag != 267 && tag != 1002 && tag != 1005 {
			continue
		}
		offset := int(binary.BigEndian.Uint32(data[i+8 : i+12]))
		count := int(binary.BigEndian.Uint32(data[i+12 : i+16]))
		if count < 1 || store+offset+count > len(data) {
			t.Fatal("invalid fixture signature bounds")
		}
		data[store+offset+count-1] ^= 1
		changed = true
	}
	if !changed {
		t.Fatal("fixture has no embedded signature to corrupt")
	}
	bad := filepath.Join(root, "a-bad.rpm")
	if err := os.WriteFile(bad, data, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := Add(context.Background(), AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: []string{bad, good}, Jobs: 2})
	var partial *PartialError
	if !errors.As(err, &partial) || result.Failed != 1 || result.Accepted != 1 || result.Items[0].Status != "failed" || result.Items[1].Status != "accepted" || result.Items[1].SHA256 != originalSHA {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if !strings.Contains(result.Items[0].Error, "41") {
		t.Fatalf("first input did not reach signing failure: %s", result.Items[0].Error)
	}
}

func TestDuplicateIngestRecoveryNeedsNoExternalInput(t *testing.T) {
	for _, point := range []string{"add.staged", "add.applied"} {
		t.Run(point, func(t *testing.T) {
			root, ws := newRejectionWorkspace(t)
			source := decodeManagedFixture(t, "../../testdata/pgdg-redhat-nonfree-repo.rpm.b64", filepath.Join(root, "package.rpm"))
			opts := AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: []string{source}, Jobs: 1}
			first, err := Add(context.Background(), opts)
			if err != nil {
				t.Fatal(err)
			}
			crash := errors.New("duplicate durable boundary")
			opts.Fault = func(got string) error {
				if got == point {
					return crash
				}
				return nil
			}
			if _, err := Add(context.Background(), opts); !errors.Is(err, crash) {
				t.Fatalf("fault=%v", err)
			}
			if err := os.Remove(source); err != nil {
				t.Fatal(err)
			}
			built, err := Build(context.Background(), BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1})
			if err != nil || built.Generation != first.Generation || built.Dirty {
				t.Fatalf("recovery=%+v err=%v", built, err)
			}
			if got := managedTestSummary(t, root); got.DesiredRevision != first.Revision {
				t.Fatalf("duplicate recovery changed Desired revision: %+v", got)
			}
		})
	}
}

func TestDuplicateIngestDoesNotHealMissingOrCorruptPool(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprint("missing=", missing), func(t *testing.T) {
			root, ws := newRejectionWorkspace(t)
			source := decodeManagedFixture(t, "../../testdata/pgdg-redhat-nonfree-repo.rpm.b64", filepath.Join(root, "package.rpm"))
			opts := AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: []string{source}, Jobs: 1}
			if _, err := Add(context.Background(), opts); err != nil {
				t.Fatal(err)
			}
			object, err := inspectRPMSnapshot(context.Background(), source, filepath.Base(source))
			if err != nil {
				t.Fatal(err)
			}
			pool := filepath.Join(root, "repo", object.PoolPath)
			info, err := os.Stat(pool)
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(pool)
			if err != nil {
				t.Fatal(err)
			}
			if missing {
				if err := os.Remove(pool); err != nil {
					t.Fatal(err)
				}
			} else {
				data[len(data)-1] ^= 1
				if err := os.WriteFile(pool, data, 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(pool, info.ModTime(), info.ModTime()); err != nil {
					t.Fatal(err)
				}
			}
			result, err := Add(context.Background(), opts)
			if !errors.Is(err, ErrIntegrity) || result.Accepted != 0 || result.Operation != "" {
				t.Fatalf("unsafe pool accepted: %+v %v", result, err)
			}
			if missing {
				if _, err := os.Stat(pool); !os.IsNotExist(err) {
					t.Fatalf("missing body was healed: %v", err)
				}
			} else if after, err := os.ReadFile(pool); err != nil || !bytes.Equal(after, data) {
				t.Fatalf("corrupt body was changed: %v", err)
			}
		})
	}
}

func TestIngestSameBatchContentConflictPreservesFirstObject(t *testing.T) {
	for _, format := range []string{"rpm", "deb"} {
		t.Run(format, func(t *testing.T) {
			root := t.TempDir()
			cfg := config.Default()
			cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"main": {Format: format}}}
			writeManagedConfig(t, root, cfg)
			if _, err := Init(context.Background(), InitOptions{Dir: root}); err != nil {
				t.Fatal(err)
			}
			fixture := "../../testdata/pgdg-redhat-nonfree-repo.rpm.b64"
			if format == "deb" {
				fixture = "../../aptrepo/testdata/libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"
			}
			first := decodeManagedFixture(t, fixture, filepath.Join(root, "a."+format))
			data, err := os.ReadFile(first)
			if err != nil {
				t.Fatal(err)
			}
			sha := bytesSHA(data)
			data[len(data)-1] ^= 1
			second := filepath.Join(root, "b."+format)
			if err := os.WriteFile(second, data, 0600); err != nil {
				t.Fatal(err)
			}
			result, err := Add(context.Background(), AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"main"}, Paths: []string{first, second}, Skip: true, Jobs: 2})
			var partial *PartialError
			if !errors.As(err, &partial) || result.Accepted != 1 || result.Failed != 1 || !strings.Contains(result.Items[1].Error, "conflicts with another input") {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			pending, err := os.ReadFile(filepath.Join(root, ".sow/repo/pending", sha))
			if err != nil || bytesSHA(pending) != sha {
				t.Fatalf("first object replaced: %v", err)
			}
		})
	}
}

func TestIngestSourceCaseConflictBeforeAndWithinBatch(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprint("existing=", existing), func(t *testing.T) {
			root, ws := newRejectionWorkspace(t)
			insensitive, err := filesystemDirectoryIsCaseInsensitive(root)
			if err != nil {
				t.Fatal(err)
			}
			if !insensitive {
				t.Skip("requires a case-insensitive workspace; both spellings are valid on case-sensitive filesystems")
			}
			data, err := os.ReadFile("../../../third_party/cavaliergopher-rpm/testdata/centos-release-7-2.1511.el7.centos.2.10.x86_64.rpm")
			if err != nil {
				t.Fatal(err)
			}
			upper := bytes.ReplaceAll(data, []byte("centos-release"), []byte("Centos-release"))
			if bytes.Equal(data, upper) {
				t.Fatal("missing case mutation target")
			}
			first, second := filepath.Join(root, "a.rpm"), filepath.Join(root, "b.rpm")
			if err := os.WriteFile(first, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(second, upper, 0600); err != nil {
				t.Fatal(err)
			}
			opts := AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: []string{first, second}, Skip: true, Jobs: 2}
			if existing {
				opts.Paths = []string{first}
				if _, err := Add(context.Background(), opts); err != nil {
					t.Fatal(err)
				}
				opts.Paths = []string{second}
			}
			result, err := Add(context.Background(), opts)
			if err == nil || result.Failed != 1 || result.Accepted != len(opts.Paths)-1 || !strings.Contains(result.Items[len(result.Items)-1].Error, "differs only by case") {
				t.Fatalf("case collision=%+v err=%v", result, err)
			}
		})
	}
}
