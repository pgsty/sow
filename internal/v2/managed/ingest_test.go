package managed

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
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

func TestAddPostCommitCheckpointFailureRetainsCommittedProjection(t *testing.T) {
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
		input := decodeManagedFixture(t, filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
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
		if err == nil || !strings.Contains(err.Error(), "checkpoint repository state incomplete") {
			t.Fatalf("checkpoint fault result=%#v err=%v", result, err)
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
			t.Fatalf("terminal checkpoint error retained stage: %v", statErr)
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
		input := decodeManagedFixture(t, filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
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
			rpm := decodeManagedFixture(t, filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
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
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "pgdg-redhat-nonfree-repo.rpm"))
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
	valid := decodeManagedFixture(t, filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "valid.rpm"))
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
		input := decodeManagedFixture(t, filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
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
	input := decodeManagedFixture(t, filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
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
	valid := decodeManagedFixture(t, filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "valid.rpm"))
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
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "pending.rpm"))
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
