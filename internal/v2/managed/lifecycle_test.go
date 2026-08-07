package managed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

func TestOperationIDUsesPublicDecimalSyntax(t *testing.T) {
	seen := map[string]struct{}{}
	for range 128 {
		id, err := operationID()
		if err != nil {
			t.Fatal(err)
		}
		if id == "0" || !decimalOperationID.MatchString(id) {
			t.Fatalf("operation id %q is not a positive decimal integer", id)
		}
		if _, duplicate := seen[id]; duplicate {
			t.Fatalf("duplicate operation id %q", id)
		}
		seen[id] = struct{}{}
	}
}

func TestInitDefaultIsIdempotent(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "workspace")
	first, err := Init(ctx, InitOptions{Dir: root})
	if err != nil {
		t.Fatal(err)
	}
	if !first.ConfigCreated || first.RepositoriesInitialized != 0 || first.DistsInitialized != 0 {
		t.Fatalf("first init=%#v", first)
	}
	data, err := os.ReadFile(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := config.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed.Architectures, []string{"x86_64", "aarch64"}) || len(parsed.Repositories) != 0 {
		t.Fatalf("default config=%#v", parsed)
	}
	second, err := Init(ctx, InitOptions{Dir: root})
	if err != nil {
		t.Fatal(err)
	}
	if second.ConfigCreated || second.RepositoriesInitialized != 0 || second.DistsInitialized != 0 {
		t.Fatalf("idempotent init=%#v", second)
	}
	after, err := os.ReadFile(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(after) {
		t.Fatal("idempotent init rewrote sow.yml")
	}
}

func TestInitWorkspaceJournalRecoveryMatrix(t *testing.T) {
	ctx := context.Background()
	for _, point := range []string{"init.journal", "init.config"} {
		t.Run(point, func(t *testing.T) {
			root := t.TempDir()
			injected := errors.New("injected")
			_, err := Init(ctx, InitOptions{Dir: root, Fault: func(got string) error {
				if got == point {
					return injected
				}
				return nil
			}})
			if !errors.Is(err, injected) {
				t.Fatalf("fault=%v", err)
			}
			if _, err := os.Stat(filepath.Join(root, ".sow", "workspace-ops", "active.json")); err != nil {
				t.Fatalf("durable journal missing: %v", err)
			}
			result, err := Init(ctx, InitOptions{Dir: root})
			if err != nil {
				t.Fatalf("recover: %v", err)
			}
			if len(result.Existing) > 1 {
				t.Fatalf("unexpected recovery result: %#v", result)
			}
			cfg, err := config.Load(filepath.Join(root, config.ConfigFilename))
			if err != nil || !reflect.DeepEqual(cfg, config.Default()) {
				t.Fatalf("default config=%#v err=%v", cfg, err)
			}
			if _, err := os.Lstat(filepath.Join(root, ".sow", "workspace-ops", "active.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("journal remains: %v", err)
			}
		})
	}
}

func TestWorkspaceJournalWireLimit(t *testing.T) {
	if err := validateWorkspaceJournalWireSize(make([]byte, maxWorkspaceJournalBytes)); err != nil {
		t.Fatalf("workspace journal at limit rejected: %v", err)
	}
	if err := validateWorkspaceJournalWireSize(make([]byte, maxWorkspaceJournalBytes+1)); !errors.Is(err, ErrRejected) {
		t.Fatalf("workspace journal over limit error = %v", err)
	}
}

func TestInitReturnsCommittedProgressOnLaterFailure(t *testing.T) {
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["a"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{}}
	cfg.Repositories["b"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{}}
	writeManagedConfig(t, root, cfg)
	injected := errors.New("injected")
	result, err := Init(context.Background(), InitOptions{Dir: root, Fault: func(point string) error {
		if point == "init.repository.a" {
			return injected
		}
		return nil
	}})
	if !errors.Is(err, injected) || result.RepositoriesInitialized != 1 || !result.HasCommittedChanges() {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if _, err := os.Stat(filepath.Join(root, "a", "pool")); err != nil {
		t.Fatalf("committed repository omitted from result: %v", err)
	}
}

func TestInitReloadsConfigAfterWaitingForWorkspaceLock(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	held, err := acquireFileLock(ctx, filepath.Join(root, ".sow", "workspace.lock"), 0, false)
	if err != nil {
		t.Fatal(err)
	}
	type initResult struct {
		result InitResult
		err    error
	}
	done := make(chan initResult, 1)
	go func() {
		result, err := Init(ctx, InitOptions{Dir: root})
		done <- initResult{result: result, err: err}
	}()
	select {
	case outcome := <-done:
		held.Close()
		t.Fatalf("Init did not wait for Workspace lock: %#v", outcome)
	case <-time.After(80 * time.Millisecond):
	}
	cfg := config.Default()
	cfg.Repositories["queued"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{}}
	data, err := config.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(filepath.Join(root, config.ConfigFilename), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureRepositoryShell(root, "queued"); err != nil {
		t.Fatal(err)
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case outcome := <-done:
		if outcome.err != nil {
			t.Fatalf("Init used stale pre-lock config: result=%#v err=%v", outcome.result, outcome.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Init remained blocked after Workspace lock release")
	}
	listed, err := ListRepositories(ctx, WorkspaceOptions{Workdir: root, CWD: root})
	if err != nil || len(listed) != 1 || listed[0].Name != "queued" {
		t.Fatalf("queued repository view=%#v err=%v", listed, err)
	}
}

func TestInitCompletesDeclaredStateWithoutReset(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["pgsql"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{
		"el9": {Format: "rpm"}, "noble": {Format: "deb", Architectures: []string{"x86_64"}},
	}}
	writeManagedConfig(t, root, cfg)
	result, err := Init(ctx, InitOptions{Dir: root})
	if err != nil {
		t.Fatal(err)
	}
	if result.RepositoriesInitialized != 1 || result.DistsInitialized != 2 {
		t.Fatalf("init=%#v", result)
	}
	dbPath := filepath.Join(root, ".sow", "pgsql.db")
	store, err := state.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	// Model a real schema-v1 repository: it has a durable built generation but
	// predates the P3 generations/generation_files ledger entirely.
	if _, err := store.DB().Exec(`DELETE FROM generations`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`UPDATE repository_state SET desired_revision=77, built_generation='00000000000000000077'`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	listed, err := ListRepositories(ctx, WorkspaceOptions{Workdir: root, CWD: root})
	if err != nil || len(listed) != 1 || listed[0].Status != "dirty" || !strings.Contains(strings.Join(listed[0].DirtyReasons, "\n"), "manifest baseline") {
		t.Fatalf("legacy repository listing=%#v err=%v", listed, err)
	}
	repomd := filepath.Join(root, "pgsql", "dists", "el9", "x86_64", "repodata", "repomd.xml")
	before, err := os.ReadFile(repomd)
	if err != nil {
		t.Fatal(err)
	}
	result, err = Init(ctx, InitOptions{Dir: root})
	if err != nil {
		t.Fatal(err)
	}
	if result.RepositoriesInitialized != 0 || result.DistsInitialized != 0 {
		t.Fatalf("rerun=%#v", result)
	}
	listed, err = ListRepositories(ctx, WorkspaceOptions{Workdir: root, CWD: root})
	if err != nil || len(listed) != 1 || listed[0].Status != "clean" {
		t.Fatalf("bootstrapped repository listing=%#v err=%v", listed, err)
	}
	store, err = state.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	summary, err := store.Summary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if summary.BuiltGeneration != 77 {
		t.Fatalf("generation reset: %#v", summary)
	}
	after, err := os.ReadFile(repomd)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("valid RPM pointer was overwritten")
	}
}

func TestInitDistReconciliationIgnoresRepositoryRemovedBetweenLockPhases(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	if _, err := RemoveRepositoryResult(ctx, RepositoryRemoveOptions{
		WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo", Force: true,
	}); err != nil {
		t.Fatal(err)
	}
	created, err := initializeDeclaredDists(ctx, root, "repo", nil, LockOptions{})
	if err != nil || created != 0 {
		t.Fatalf("stale Init reconciliation created=%d err=%v", created, err)
	}
	if _, err := os.Lstat(filepath.Join(root, "repo")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("removed repository was recreated: %v", err)
	}
}

func TestInitLeavesAddedArchitecturesDirtyForBuild(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Architectures = []string{"x86_64"}
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}, "noble": {Format: "deb"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	rpmPointer := filepath.Join(root, "repo", "dists", "el9", "x86_64", "repodata", "repomd.xml")
	debPackages := filepath.Join(root, "repo", "dists", "noble", "main", "binary-amd64", "Packages.gz")
	rpmBefore, err := os.ReadFile(rpmPointer)
	if err != nil {
		t.Fatal(err)
	}
	debBefore, err := os.ReadFile(debPackages)
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	el9Before, err := store.GetDist(ctx, "el9")
	if err != nil {
		t.Fatal(err)
	}
	nobleBefore, err := store.GetDist(ctx, "noble")
	if closeErr := store.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	cfg.Architectures = []string{"x86_64", "aarch64"}
	writeManagedConfig(t, root, cfg)
	repositories, err := ListRepositories(ctx, WorkspaceOptions{Workdir: root, CWD: root})
	if err != nil || len(repositories) != 1 || repositories[0].Status != "dirty" {
		t.Fatalf("pre-init status=%#v err=%v", repositories, err)
	}
	result, err := Init(ctx, InitOptions{Dir: root})
	if err != nil {
		t.Fatal(err)
	}
	if result.DistsInitialized != 0 {
		t.Fatalf("result=%#v", result)
	}
	if after, err := os.ReadFile(rpmPointer); err != nil || string(after) != string(rpmBefore) {
		t.Fatalf("existing RPM pointer changed err=%v", err)
	}
	if after, err := os.ReadFile(debPackages); err != nil || string(after) != string(debBefore) {
		t.Fatalf("existing DEB Packages changed err=%v", err)
	}
	for _, path := range []string{
		filepath.Join(root, "repo", "dists", "el9", "aarch64", "repodata", "repomd.xml"),
		filepath.Join(root, "repo", "dists", "noble", "main", "binary-arm64", "Packages.gz"),
	} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("init unexpectedly built added architecture view %q: %v", path, err)
		}
	}
	store, err = state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	el9After, err := store.GetDist(ctx, "el9")
	if err != nil {
		t.Fatal(err)
	}
	nobleAfter, err := store.GetDist(ctx, "noble")
	if closeErr := store.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(el9After, el9Before) || !reflect.DeepEqual(nobleAfter, nobleBefore) {
		t.Fatalf("init changed built state: el9 before=%#v after=%#v noble before=%#v after=%#v", el9Before, el9After, nobleBefore, nobleAfter)
	}
	for _, distName := range []string{"el9", "noble"} {
		shown, err := ShowDist(ctx, DistShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: distName})
		if err != nil || !shown.Dirty || shown.Status != "dirty" {
			t.Fatalf("%s did not remain dirty after init: %#v err=%v", distName, shown, err)
		}
	}
	build, err := Build(ctx, BuildOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1})
	if err != nil || build.Generation <= el9Before.BuiltGeneration {
		t.Fatalf("build added empty architecture views=%#v err=%v", build, err)
	}
	for _, path := range []string{
		filepath.Join(root, "repo", "dists", "el9", "aarch64", "repodata", "repomd.xml"),
		filepath.Join(root, "repo", "dists", "noble", "main", "binary-arm64", "Packages.gz"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("build did not create added architecture view %q: %v", path, err)
		}
	}
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1})
	if err != nil || !checked.ReadyToCopy || checked.Status != "clean" {
		t.Fatalf("added architecture build is not deliverable: checked=%#v err=%v", checked, err)
	}
}

func TestExplicitDistSubsetIgnoresUnrelatedWorkspaceArchitectureChanges(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Architectures = []string{"x86_64"}
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{
		"el9": {Format: "rpm", Architectures: []string{"x86_64"}},
	}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	before, err := store.GetDist(ctx, "el9")
	store.Close()
	if err != nil {
		t.Fatal(err)
	}
	pointer := filepath.Join(root, "repo", "dists", "el9", "x86_64", "repodata", "repomd.xml")
	pointerBefore, err := os.ReadFile(pointer)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Architectures = []string{"aarch64", "x86_64"}
	writeManagedConfig(t, root, cfg)
	result, err := Init(ctx, InitOptions{Dir: root})
	if err != nil || result.DistsInitialized != 0 {
		t.Fatalf("init=%#v err=%v", result, err)
	}
	after, err := ShowDist(ctx, DistShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9"})
	if err != nil || after.Dirty || after.EffectiveConfigSHA != before.EffectiveConfigSHA256 || after.Generation != before.BuiltGeneration {
		t.Fatalf("dist=%#v before=%#v err=%v", after, before, err)
	}
	if pointerAfter, err := os.ReadFile(pointer); err != nil || string(pointerAfter) != string(pointerBefore) {
		t.Fatalf("unrelated config change rewrote view: %v", err)
	}
}

func TestDistLifecycleConvergesLegacyPublicModes(t *testing.T) {
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
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	objects, err := store.ListPackageObjects(ctx, nil, false)
	closeErr := store.Close()
	if err := errors.Join(err, closeErr); err != nil || len(objects) != 1 {
		t.Fatalf("objects=%#v err=%v", objects, err)
	}
	pool := filepath.Join(root, "repo", filepath.FromSlash(objects[0].PoolPath))
	if err := os.Chmod(pool, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: options, Repository: "repo", Name: "noble", Format: "deb"}); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(pool); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("dist.new did not normalize Pool mode: info=%v err=%v", info, err)
	}
	if checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1}); err != nil || !checked.ReadyToCopy {
		t.Fatalf("post-dist.new check=%#v err=%v", checked, err)
	}

	if err := os.Chmod(pool, 0o600); err != nil {
		t.Fatal(err)
	}
	removed, err := RemoveDistResult(ctx, DistRemoveOptions{WorkspaceOptions: options, Repository: "repo", Name: "noble"})
	if err != nil || !removed.Removed {
		t.Fatalf("dist.rm=%#v err=%v", removed, err)
	}
	if info, err := os.Stat(pool); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("dist.rm did not normalize Pool mode: info=%v err=%v", info, err)
	}
	if checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1}); err != nil || !checked.ReadyToCopy {
		t.Fatalf("post-dist.rm check=%#v err=%v", checked, err)
	}
}

func TestArchitectureReorderingDoesNotDirtyBuiltDist(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{
		"el9": {Format: "rpm", Architectures: []string{"x86_64", "aarch64"}},
	}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	before, err := ShowDist(ctx, DistShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9"})
	if err != nil {
		t.Fatal(err)
	}
	repo := cfg.Repositories["repo"]
	dist := repo.Dists["el9"]
	dist.Architectures = []string{"aarch64", "x86_64"}
	repo.Dists["el9"] = dist
	cfg.Repositories["repo"] = repo
	writeManagedConfig(t, root, cfg)
	result, err := Init(ctx, InitOptions{Dir: root})
	if err != nil || result.DistsInitialized != 0 {
		t.Fatalf("init=%#v err=%v", result, err)
	}
	after, err := ShowDist(ctx, DistShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9"})
	if err != nil || after.Dirty || after.EffectiveConfigSHA != before.EffectiveConfigSHA || after.Generation != before.Generation {
		t.Fatalf("before=%#v after=%#v err=%v", before, after, err)
	}
}

func TestInitRejectsMissingBuiltViewInsteadOfResetting(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	view := filepath.Join(root, "repo", "dists", "el9", "aarch64")
	if err := os.Rename(view, filepath.Join(root, "missing-view")); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(ctx, InitOptions{Dir: root}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("missing view init=%v", err)
	}
	repositories, err := ListRepositories(ctx, WorkspaceOptions{Workdir: root, CWD: root})
	if err != nil || repositories[0].Status != "error" {
		t.Fatalf("status=%#v err=%v", repositories, err)
	}
}

func TestEveryManagedWriteRejectsConfigThatRemovedReferencedArchitecture(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Architectures = []string{"x86_64"}
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	pointer := filepath.Join(root, "repo", "dists", "el9", "x86_64", "repodata", "repomd.xml")
	before, err := os.ReadFile(pointer)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Architectures = []string{"aarch64"}
	writeManagedConfig(t, root, cfg)

	tests := map[string]func() error{
		"init": func() error { _, err := Init(ctx, InitOptions{Dir: root}); return err },
		"repo new": func() error {
			_, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "other"})
			return err
		},
		"repo rm": func() error {
			return RemoveRepository(ctx, RepositoryRemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "missing", Force: true})
		},
		"dist new": func() error {
			_, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "other", Format: "rpm"})
			return err
		},
		"dist rm": func() error {
			return RemoveDist(ctx, DistRemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "missing", Force: true})
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			if err := run(); !errors.Is(err, ErrRejected) {
				t.Fatalf("write accepted removed architecture: %v", err)
			}
		})
	}
	if after, err := os.ReadFile(pointer); err != nil || string(after) != string(before) {
		t.Fatalf("preflight changed built metadata: err=%v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "other")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preflight created repository: %v", err)
	}
}

func TestRepositoryLifecycleProtectedForceAndFixedPaths(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	created, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "pgsql"})
	if err != nil {
		t.Fatal(err)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if created.Path != filepath.Join(realRoot, "pgsql") {
		t.Fatalf("path=%q", created.Path)
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "../escape"}); !errors.Is(err, ErrRejected) {
		t.Fatalf("escape error=%v", err)
	}
	list, err := ListRepositories(ctx, WorkspaceOptions{Workdir: root, CWD: root})
	if err != nil || len(list) != 1 || list[0].Name != "pgsql" || list[0].Generation != 0 || list[0].Status != "clean" {
		t.Fatalf("list=%#v err=%v", list, err)
	}
	if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "pgsql", Name: "noble", Format: "deb"}); err != nil {
		t.Fatal(err)
	}
	if err := RemoveRepository(ctx, RepositoryRemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "pgsql"}); !errors.Is(err, ErrRejected) {
		t.Fatalf("non-empty remove=%v", err)
	}

	cfg, err := config.Load(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	repo := cfg.Repositories["pgsql"]
	repo.Protected = true
	cfg.Repositories["pgsql"] = repo
	writeManagedConfig(t, root, cfg)
	if err := RemoveRepository(ctx, RepositoryRemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "pgsql", Force: true}); !errors.Is(err, ErrRejected) {
		t.Fatalf("protected force remove=%v", err)
	}
	repo.Protected = false
	cfg.Repositories["pgsql"] = repo
	writeManagedConfig(t, root, cfg)
	if err := RemoveRepository(ctx, RepositoryRemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "pgsql", Force: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "pgsql")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("repository tree remains: %v", err)
	}
}

func TestRepositoryNewRefusesToAdoptPreExistingOwnedPaths(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"public", "private", "database"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
				t.Fatal(err)
			}
			candidate := filepath.Join(root, "victim")
			sentinel := candidate
			switch kind {
			case "public":
				if err := os.Mkdir(candidate, 0o755); err != nil {
					t.Fatal(err)
				}
				sentinel = filepath.Join(candidate, "sentinel")
			case "private":
				candidate = filepath.Join(root, ".sow", "victim")
				if err := os.Mkdir(candidate, 0o700); err != nil {
					t.Fatal(err)
				}
				sentinel = filepath.Join(candidate, "sentinel")
			case "database":
				candidate = filepath.Join(root, ".sow", "victim.db")
				sentinel = candidate
			}
			if err := os.WriteFile(sentinel, []byte("foreign"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "victim"}); !errors.Is(err, ErrRejected) {
				t.Fatalf("adoption=%v", err)
			}
			if data, err := os.ReadFile(sentinel); err != nil || string(data) != "foreign" {
				t.Fatalf("foreign sentinel changed: %q err=%v", data, err)
			}
			cfg, err := config.Load(filepath.Join(root, config.ConfigFilename))
			if err != nil {
				t.Fatal(err)
			}
			if _, configured := cfg.Repositories["victim"]; configured {
				t.Fatal("foreign repository path was committed to config")
			}
		})
	}
}

func TestDistLifecycleRefusesToAdoptPreExistingPath(t *testing.T) {
	ctx := context.Background()
	for _, entryType := range []string{"file", "directory"} {
		t.Run(entryType, func(t *testing.T) {
			root := t.TempDir()
			if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
				t.Fatal(err)
			}
			if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(filepath.Join(root, config.ConfigFilename))
			if err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(root, "repo", "dists", "foreign")
			sentinel := target
			if entryType == "directory" {
				if err := os.Mkdir(target, 0o755); err != nil {
					t.Fatal(err)
				}
				sentinel = filepath.Join(target, "sentinel")
			}
			if err := os.WriteFile(sentinel, []byte("foreign"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "foreign", Format: "rpm"}); !errors.Is(err, ErrRejected) {
				t.Fatalf("dist adoption=%v", err)
			}
			after, err := os.ReadFile(filepath.Join(root, config.ConfigFilename))
			if err != nil || string(after) != string(before) {
				t.Fatalf("config changed: err=%v", err)
			}
			if data, err := os.ReadFile(sentinel); err != nil || string(data) != "foreign" {
				t.Fatalf("foreign Dist changed: %q err=%v", data, err)
			}
			store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
			if err != nil {
				t.Fatal(err)
			}
			pending, pendingErr := store.PendingOperations(ctx)
			_, distErr := store.GetDist(ctx, "foreign")
			store.Close()
			if pendingErr != nil || len(pending) != 0 || !errors.Is(distErr, state.ErrNotFound) {
				t.Fatalf("state mutated: pending=%#v pendingErr=%v distErr=%v", pending, pendingErr, distErr)
			}
		})
	}
}

func TestDistLifecycleEmptyIndicesAndPoolPreservation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, format string }{{"el9", "rpm"}, {"noble", "deb"}} {
		if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: tc.name, Format: tc.format}); err != nil {
			t.Fatalf("new %s: %v", tc.name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "repo", "dists", "el9", "aarch64", "repodata", "repomd.xml")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "repo", "dists", "noble", "main", "binary-arm64", "Packages.gz")); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "keep.rpm"))
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	objects, err := store.ListPackageObjects(ctx, []string{"el9"}, false)
	store.Close()
	if err != nil || len(objects) != 1 {
		t.Fatalf("objects=%#v err=%v", objects, err)
	}
	poolFile := filepath.Join(root, "repo", filepath.FromSlash(objects[0].PoolPath))
	poolBefore, err := os.ReadFile(poolFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := RemoveDist(ctx, DistRemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9", Force: true}); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(poolFile); err != nil || !bytes.Equal(data, poolBefore) {
		t.Fatalf("pool changed: size=%d err=%v", len(data), err)
	}
	list, err := ListDists(ctx, DistListOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo"})
	if err != nil || len(list) != 1 || list[0].Name != "noble" {
		t.Fatalf("dists=%#v err=%v", list, err)
	}
}

func TestConfigCheckIsReadOnlyAndStateAware(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	result, err := CheckConfig(ctx, WorkspaceOptions{Workdir: root, CWD: root})
	if err != nil || result.Repositories != 1 || result.Dists != 1 {
		t.Fatalf("check=%#v err=%v", result, err)
	}
	cfg.Architectures = []string{"x86_64"}
	writeManagedConfig(t, root, cfg)
	if _, err := CheckConfig(ctx, WorkspaceOptions{Workdir: root, CWD: root}); !errors.Is(err, ErrRejected) {
		t.Fatalf("state architecture removal=%v", err)
	}
}

func TestConfigCheckRejectsOrphanStateAndReservedPathConflicts(t *testing.T) {
	ctx := context.Background()
	t.Run("orphan database", func(t *testing.T) {
		root := t.TempDir()
		if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
			t.Fatal(err)
		}
		if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
			t.Fatal(err)
		}
		cfg := config.Default()
		writeManagedConfig(t, root, cfg)
		if _, err := CheckConfig(ctx, WorkspaceOptions{Workdir: root, CWD: root}); !errors.Is(err, ErrRejected) {
			t.Fatalf("orphan state accepted: %v", err)
		}
		if _, err := os.Stat(filepath.Join(root, ".sow", "repo.db")); err != nil {
			t.Fatalf("read-only check changed orphan database: %v", err)
		}
	})

	t.Run("public path symlink", func(t *testing.T) {
		root := t.TempDir()
		outside := t.TempDir()
		cfg := config.Default()
		cfg.Repositories["repo"] = config.RepositoryConfig{}
		writeManagedConfig(t, root, cfg)
		if err := os.Symlink(outside, filepath.Join(root, "repo")); err != nil {
			t.Fatal(err)
		}
		if _, err := CheckConfig(ctx, WorkspaceOptions{Workdir: root, CWD: root}); !errors.Is(err, ErrRejected) {
			t.Fatalf("reserved path conflict accepted: %v", err)
		}
		entries, err := os.ReadDir(outside)
		if err != nil || len(entries) != 0 {
			t.Fatalf("outside changed: entries=%v err=%v", entries, err)
		}
	})
}

func TestConfigCheckRejectsUnsafeReservedControlPathsReadOnly(t *testing.T) {
	ctx := context.Background()
	for _, relative := range []string{
		filepath.Join(".sow", "workspace-ops"),
		filepath.Join(".sow", "repo-locks"),
		filepath.Join(".sow", "workspace.lock"),
	} {
		t.Run(filepath.Base(relative), func(t *testing.T) {
			root := t.TempDir()
			outside := t.TempDir()
			if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
				t.Fatal(err)
			}
			candidate := filepath.Join(root, relative)
			if err := os.Remove(candidate); err != nil {
				t.Fatal(err)
			}
			outsideTarget := outside
			if filepath.Base(relative) == "workspace.lock" {
				outsideTarget = filepath.Join(outside, "lock")
				if err := os.WriteFile(outsideTarget, []byte("foreign"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(outsideTarget, candidate); err != nil {
				t.Fatal(err)
			}
			if _, err := CheckConfig(ctx, WorkspaceOptions{Workdir: root, CWD: root}); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("unsafe control path accepted: %v", err)
			}
			entries, err := os.ReadDir(outside)
			if err != nil || (filepath.Base(relative) != "workspace.lock" && len(entries) != 0) {
				t.Fatalf("read-only check changed outside: entries=%v err=%v", entries, err)
			}
		})
	}
}

func TestManagedShowReportsEffectiveConfigDirtyReasonsAndSafeRecentOperation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9", Format: "rpm"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	distCfg := cfg.Repositories["repo"].Dists["el9"]
	distCfg.Architectures = []string{"x86_64"}
	repoCfg := cfg.Repositories["repo"]
	repoCfg.Dists["el9"] = distCfg
	cfg.Repositories["repo"] = repoCfg
	writeManagedConfig(t, root, cfg)

	dist, err := ShowDist(ctx, DistShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9"})
	if err != nil {
		t.Fatal(err)
	}
	if !dist.Dirty || dist.Status != "dirty" || len(dist.Config.Architectures) != 1 || len(dist.Architectures) != 1 || dist.Architectures[0].Family != "x86_64" || len(dist.DirtyReasons) == 0 {
		t.Fatalf("dist show omitted effective state: %#v", dist)
	}
	repository, err := ShowRepository(ctx, RepositoryShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"})
	if err != nil {
		t.Fatal(err)
	}
	if repository.Status != "dirty" || len(repository.Config.Dists["el9"].Architectures) != 1 || len(repository.DirtyReasons) == 0 || repository.RecentOperation == nil {
		t.Fatalf("repo show omitted effective state: %#v", repository)
	}
	status, err := Status(ctx, StatusOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo"})
	if err != nil || status.Status != "dirty" || !strings.Contains(strings.Join(status.DirtyReasons, "\n"), "effective configuration differs from built state") {
		t.Fatalf("status omitted effective configuration dirty reason: status=%#v err=%v", status, err)
	}
	encoded, err := json.Marshal(repository)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"payload_json", "new_config", "old_config"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("repo show exposed recovery payload field %q: %s", forbidden, encoded)
		}
	}
}

func TestRepositoryShowReportsCommittedHotWALOperationAsRecovering(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().ExecContext(ctx, `PRAGMA wal_autocheckpoint = 0`); err != nil {
		t.Fatal(err)
	}
	const id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := store.DB().ExecContext(ctx, `
INSERT INTO operations(id, kind, state, payload_json, error_class, created_at, updated_at)
VALUES (?, 'dist.new', 'planned', '{}', NULL, '2026-08-01T00:00:00.000000000Z', '2026-08-01T00:00:00.000000000Z')`, id); err != nil {
		t.Fatal(err)
	}

	shown, err := ShowRepository(ctx, RepositoryShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"})
	if err != nil {
		t.Fatal(err)
	}
	if shown.Status != "recovering" || shown.RecentOperation != nil || !strings.Contains(strings.Join(shown.DirtyReasons, "\n"), id) {
		t.Fatalf("repo show ignored committed hot-WAL operation: %#v", shown)
	}
}

func TestInitRecoversHotWALWithoutSharedMemoryWhileReadsStayPhysical(t *testing.T) {
	const helper = "SOW_MANAGED_HOT_WAL_HELPER"
	const databaseEnv = "SOW_MANAGED_HOT_WAL_DATABASE"
	ctx := context.Background()
	if os.Getenv(helper) == "1" {
		store, err := state.OpenExisting(os.Getenv(databaseEnv))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Checkpoint(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := store.DB().ExecContext(ctx, `PRAGMA wal_autocheckpoint = 0`); err != nil {
			t.Fatal(err)
		}
		if _, err := store.DB().ExecContext(ctx, `UPDATE repository_state SET desired_revision = 1 WHERE singleton = 1`); err != nil {
			t.Fatal(err)
		}
		os.Exit(0)
	}

	root := t.TempDir()
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(root, ".sow", "repo.db")
	cmd := exec.Command(os.Args[0], "-test.run=^TestInitRecoversHotWALWithoutSharedMemoryWhileReadsStayPhysical$")
	cmd.Env = append(os.Environ(), helper+"=1", databaseEnv+"="+database)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("hot-WAL helper: %v\n%s", err, output)
	}
	if info, err := os.Stat(database + "-wal"); err != nil || info.Size() == 0 {
		t.Fatalf("helper left no hot WAL: info=%v err=%v", info, err)
	}
	if err := os.Remove(database + "-shm"); err != nil {
		t.Fatal(err)
	}
	if _, err := ShowRepository(ctx, RepositoryShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("read surface accepted hot WAL without shm: %v", err)
	}
	if _, err := os.Lstat(database + "-shm"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read surface recreated shm: %v", err)
	}
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatalf("init did not recover hot WAL without shm: %v", err)
	}
	shown, err := ShowRepository(ctx, RepositoryShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"})
	if err != nil {
		t.Fatal(err)
	}
	if shown.DesiredRevision != 1 {
		t.Fatalf("init reset committed repository state: %#v", shown)
	}
}

func TestManagedEmptyViewValidationDetectsMetadataCorruption(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name   string
		format string
		file   func(string) string
	}{
		{name: "rpm", format: "rpm", file: func(root string) string {
			return filepath.Join(root, "repo", "dists", "dist", "x86_64", "repodata", "repomd.xml")
		}},
		{name: "deb", format: "deb", file: func(root string) string {
			return filepath.Join(root, "repo", "dists", "dist", "main", "binary-amd64", "Packages")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
				t.Fatal(err)
			}
			if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
				t.Fatal(err)
			}
			if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "dist", Format: tt.format}); err != nil {
				t.Fatal(err)
			}
			filename := tt.file(root)
			if err := os.Chmod(filename, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filename, []byte("corrupt\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := CheckConfig(ctx, WorkspaceOptions{Workdir: root, CWD: root}); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("config check accepted corrupt metadata: %v", err)
			}
			info, err := ShowDist(ctx, DistShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "dist"})
			if err != nil {
				t.Fatal(err)
			}
			if info.Status != "error" || !info.Dirty || len(info.DirtyReasons) == 0 {
				t.Fatalf("dist show did not expose corruption: %#v", info)
			}
		})
	}
}

func TestRemovalMetadataBypassRequiresForceAndIsRepositoryScoped(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	for _, repo := range []string{"a", "b"} {
		if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: repo}); err != nil {
			t.Fatal(err)
		}
		if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: repo, Name: "el9", Format: "rpm"}); err != nil {
			t.Fatal(err)
		}
	}
	corrupt := filepath.Join(root, "a", "dists", "el9", "x86_64", "repodata", "repomd.xml")
	if err := os.WriteFile(corrupt, []byte("corrupt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	base := DistRemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "b", Name: "el9"}
	if err := RemoveDist(ctx, base); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("non-force removal bypassed corrupt live metadata: %v", err)
	}
	base.Force = true
	if err := RemoveDist(ctx, base); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("force removal bypassed unrelated repository corruption: %v", err)
	}

	targetRoot := t.TempDir()
	if _, err := Init(ctx, InitOptions{Dir: targetRoot}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: targetRoot, CWD: targetRoot}, Name: "repo"}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: targetRoot, CWD: targetRoot}, Repository: "repo", Name: "el9", Format: "rpm"}); err != nil {
		t.Fatal(err)
	}
	targetPointer := filepath.Join(targetRoot, "repo", "dists", "el9", "x86_64", "repodata", "repomd.xml")
	if err := os.WriteFile(targetPointer, []byte("corrupt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := RemoveDist(ctx, DistRemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: targetRoot, CWD: targetRoot}, Repository: "repo", Name: "el9"}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("non-force removal accepted target corruption: %v", err)
	}
	if err := RemoveDist(ctx, DistRemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: targetRoot, CWD: targetRoot}, Repository: "repo", Name: "el9", Force: true}); err != nil {
		t.Fatalf("force removal could not bypass target metadata corruption: %v", err)
	}

	sameRepoRoot := t.TempDir()
	if _, err := Init(ctx, InitOptions{Dir: sameRepoRoot}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: sameRepoRoot, CWD: sameRepoRoot}, Name: "repo"}); err != nil {
		t.Fatal(err)
	}
	for _, dist := range []string{"keep", "remove"} {
		if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: sameRepoRoot, CWD: sameRepoRoot}, Repository: "repo", Name: dist, Format: "rpm"}); err != nil {
			t.Fatal(err)
		}
	}
	unrelatedPointer := filepath.Join(sameRepoRoot, "repo", "dists", "keep", "x86_64", "repodata", "repomd.xml")
	if err := os.WriteFile(unrelatedPointer, []byte("corrupt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := RemoveDist(ctx, DistRemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: sameRepoRoot, CWD: sameRepoRoot}, Repository: "repo", Name: "remove", Force: true}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("force removal bypassed another Dist's corruption in the same repository: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(sameRepoRoot, "repo", "dists", "remove")); err != nil {
		t.Fatalf("failed preflight changed the target Dist: %v", err)
	}
}

func TestLifecycleRejectsSymlinkOwnedPaths(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	outside := t.TempDir()
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "evil")); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Repositories["evil"] = config.RepositoryConfig{}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); !errors.Is(err, ErrRejected) {
		t.Fatalf("symlink repository init=%v", err)
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatalf("outside touched: %v err=%v", entries, err)
	}
}

func TestPrivateSymlinkSwapCannotEscapeWorkspace(t *testing.T) {
	ctx := context.Background()
	for _, relative := range []string{filepath.Join(".sow", "workspace-ops"), filepath.Join(".sow", "repo", "stage"), filepath.Join(".sow", "repo", "recovery")} {
		t.Run(filepath.Base(relative), func(t *testing.T) {
			root := t.TempDir()
			outside := t.TempDir()
			if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
				t.Fatal(err)
			}
			if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, relative)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, path); err != nil {
				t.Fatal(err)
			}
			if relative == filepath.Join(".sow", "workspace-ops") {
				if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "other"}); err == nil {
					t.Fatal("workspace-ops symlink accepted")
				}
			} else if filepath.Base(relative) == "stage" {
				if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9", Format: "rpm"}); !errors.Is(err, ErrIntegrity) {
					t.Fatalf("stage symlink=%v", err)
				}
			} else {
				if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9", Format: "rpm"}); !errors.Is(err, ErrIntegrity) {
					t.Fatalf("recovery symlink=%v", err)
				}
			}
			entries, err := os.ReadDir(outside)
			if err != nil || len(entries) != 0 {
				t.Fatalf("outside changed: %v err=%v", entries, err)
			}
		})
	}
}

func TestPublicRepositoryChildSymlinkSwapCannotEscapeWorkspace(t *testing.T) {
	ctx := context.Background()
	for _, child := range []string{"pool", "dists"} {
		t.Run(child, func(t *testing.T) {
			root := t.TempDir()
			outside := t.TempDir()
			if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
				t.Fatal(err)
			}
			if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "repo", child)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, path); err != nil {
				t.Fatal(err)
			}
			if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9", Format: "rpm"}); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("%s symlink accepted: %v", child, err)
			}
			entries, err := os.ReadDir(outside)
			if err != nil || len(entries) != 0 {
				t.Fatalf("outside changed: %v err=%v", entries, err)
			}
		})
	}
}

func TestReadOnlyStateRootSymlinkCannotEscapeWorkspace(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	outside := t.TempDir()
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(outside, "sentinel")
	if err := os.WriteFile(sentinel, []byte("unchanged"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, ".sow"), filepath.Join(root, ".sow-real")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, ".sow")); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckConfig(ctx, WorkspaceOptions{Workdir: root, CWD: root}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("config check state symlink=%v", err)
	}
	if _, err := ListRepositories(ctx, WorkspaceOptions{Workdir: root, CWD: root}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("repo list state symlink=%v", err)
	}
	if data, err := os.ReadFile(sentinel); err != nil || string(data) != "unchanged" {
		t.Fatalf("sentinel=%q err=%v", data, err)
	}
}

func TestInitConfigConflictHasNoStateSideEffect(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, config.ConfigFilename), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(context.Background(), InitOptions{Dir: root}); !errors.Is(err, ErrRejected) {
		t.Fatalf("init conflict=%v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, ".sow")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(".sow side effect=%v", err)
	}
}

func TestDistRecoveryRejectsTreeTampering(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected")
	_, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9", Format: "rpm", Fault: func(point string) error {
		if point == "dist.new.applied" {
			return injected
		}
		return nil
	}})
	if !errors.Is(err, injected) {
		t.Fatalf("fault=%v", err)
	}
	stages, err := os.ReadDir(filepath.Join(root, ".sow", "repo", "stage"))
	if err != nil || len(stages) != 1 {
		t.Fatalf("stages=%v err=%v", stages, err)
	}
	repomd := filepath.Join(root, ".sow", "repo", "stage", stages[0].Name(), "dists", "el9", "x86_64", "repodata", "repomd.xml")
	if err := os.WriteFile(repomd, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9", Format: "rpm"}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tamper recovery=%v", err)
	}
}

func TestRepoRecoveryRejectsSourceDestinationCollision(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected")
	err := RemoveRepository(ctx, RepositoryRemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo", Force: true, Fault: func(point string) error {
		if point == "repo.rm.config" {
			return injected
		}
		return nil
	}})
	if !errors.Is(err, injected) {
		t.Fatalf("fault=%v", err)
	}
	journal, err := loadWorkspaceJournal(realPathForManagedTest(t, root))
	if err != nil || journal == nil {
		t.Fatalf("journal=%#v err=%v", journal, err)
	}
	recovery := filepath.Join(realPathForManagedTest(t, root), ".sow", "workspace-ops", "recovery-"+journal.ID)
	if err := os.Mkdir(recovery, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(recovery, "repository"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := RemoveRepository(ctx, RepositoryRemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo", Force: true}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("collision recovery=%v", err)
	}
}

func realPathForManagedTest(t *testing.T, path string) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return real
}

func TestLifecyclePublicLockNoWaitAndTimeout(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	held, err := acquireFileLock(ctx, filepath.Join(realRoot, ".sow", "workspace.lock"), 0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if _, err := Init(ctx, InitOptions{Dir: root, LockOptions: LockOptions{NoWait: true}}); !errors.Is(err, ErrLockUnavailable) {
		t.Fatalf("init no-wait=%v", err)
	}
	if _, err := Init(ctx, InitOptions{Dir: root, LockOptions: LockOptions{Timeout: 45 * time.Millisecond}}); !errors.Is(err, ErrLockUnavailable) {
		t.Fatalf("init timeout=%v", err)
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, LockOptions: LockOptions{NoWait: true}, Name: "fast"}); !errors.Is(err, ErrLockUnavailable) {
		t.Fatalf("no-wait=%v", err)
	}
	started := time.Now()
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, LockOptions: LockOptions{Timeout: 45 * time.Millisecond}, Name: "timed"}); !errors.Is(err, ErrLockUnavailable) {
		t.Fatalf("timeout=%v", err)
	}
	if elapsed := time.Since(started); elapsed < 30*time.Millisecond {
		t.Fatalf("timeout returned too early: %s", elapsed)
	}
}

func TestWorkspaceAndRepositoryLocksShareOneTimeoutBudget(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
		t.Fatal(err)
	}
	realRoot := realPathForManagedTest(t, root)
	workspaceLock, err := acquireFileLock(ctx, filepath.Join(realRoot, ".sow", "workspace.lock"), 0, false)
	if err != nil {
		t.Fatal(err)
	}
	repoLock, err := acquireFileLock(ctx, filepath.Join(realRoot, ".sow", "repo-locks", "repo.lock"), 0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer repoLock.Close()
	released := make(chan struct{})
	go func() {
		time.Sleep(60 * time.Millisecond)
		_ = workspaceLock.Close()
		close(released)
	}()
	started := time.Now()
	_, err = NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, LockOptions: LockOptions{Timeout: 120 * time.Millisecond}, Repository: "repo", Name: "el9", Format: "rpm"})
	elapsed := time.Since(started)
	<-released
	if !errors.Is(err, ErrLockUnavailable) {
		t.Fatalf("error=%v", err)
	}
	if elapsed < 100*time.Millisecond || elapsed > 170*time.Millisecond {
		t.Fatalf("timeout budget elapsed=%s", elapsed)
	}
}

func TestWorkspaceJournalRejectsKindConfigForgeryBeforeSideEffects(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
		t.Fatal(err)
	}
	configData, err := os.ReadFile(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	forgedConfig := append(append([]byte(nil), configData...), []byte("# forged same-semantics config\n")...)
	if err := writeAtomic(filepath.Join(root, config.ConfigFilename), forgedConfig, 0o644); err != nil {
		t.Fatal(err)
	}
	journal := workspaceJournal{
		Version: workspaceJournalVersion, ID: strings.Repeat("d", 64), Kind: "repo.rm", Repository: "repo",
		OldConfigSHA: bytesSHA(configData), OldConfig: configData,
		NewConfigSHA: bytesSHA(forgedConfig), NewConfig: forgedConfig, Phase: "applied",
	}
	body, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(workspaceJournalPath(root), append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "other"}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("forged repo.rm journal accepted: %v", err)
	}
	for _, path := range []string{filepath.Join(root, "repo"), filepath.Join(root, ".sow", "repo.db")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("forged journal removed %s: %v", path, err)
		}
	}
}

func TestReadSurfacesExposePendingWorkspaceRepositoryOperationWithoutWriting(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
		t.Fatal(err)
	}
	configData, err := os.ReadFile(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	journal := workspaceJournal{
		Version: workspaceJournalVersion,
		ID:      strings.Repeat("e", 64), Kind: "repo.init", Repository: "repo",
		OldConfigSHA: bytesSHA(configData), OldConfig: configData,
		NewConfigSHA: bytesSHA(configData), NewConfig: configData, Phase: "applied",
	}
	if err := persistWorkspaceJournal(root, journal); err != nil {
		t.Fatal(err)
	}
	before := persistentWorkspaceSnapshot(t, root)
	list, err := ListRepositories(ctx, WorkspaceOptions{Workdir: root, CWD: root})
	if err != nil || len(list) != 1 || list[0].Status != "recovering" || !strings.Contains(strings.Join(list[0].DirtyReasons, "\n"), journal.ID) {
		t.Fatalf("repo ls=%#v err=%v", list, err)
	}
	shown, err := ShowRepository(ctx, RepositoryShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"})
	if err != nil || shown.Status != "recovering" || !strings.Contains(strings.Join(shown.DirtyReasons, "\n"), journal.ID) {
		t.Fatalf("repo show=%#v err=%v", shown, err)
	}
	if _, err := CheckConfig(ctx, WorkspaceOptions{Workdir: root, CWD: root}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("config check accepted pending workspace operation: %v", err)
	}
	after := persistentWorkspaceSnapshot(t, root)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("read surfaces changed persistent workspace state: before=%#v after=%#v", before, after)
	}
}

func TestReadSurfacesRejectCorruptWorkspaceJournalWithoutWriting(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workspaceJournalPath(root), []byte("{\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := persistentWorkspaceSnapshot(t, root)
	checks := []struct {
		name string
		run  func() error
	}{
		{"config check", func() error { _, err := CheckConfig(ctx, WorkspaceOptions{Workdir: root, CWD: root}); return err }},
		{"repo ls", func() error { _, err := ListRepositories(ctx, WorkspaceOptions{Workdir: root, CWD: root}); return err }},
		{"repo show", func() error {
			_, err := ShowRepository(ctx, RepositoryShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"})
			return err
		}},
	}
	for _, check := range checks {
		if err := check.run(); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("%s error=%v", check.name, err)
		}
	}
	after := persistentWorkspaceSnapshot(t, root)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("read surfaces changed corrupt persistent workspace state: before=%#v after=%#v", before, after)
	}
}

func TestRepositoryReadSurfacesRejectPendingWorkspaceInitAndCommittedRemoval(t *testing.T) {
	ctx := context.Background()
	t.Run("workspace init", func(t *testing.T) {
		root := t.TempDir()
		injected := errors.New("stop after workspace config")
		_, err := Init(ctx, InitOptions{Dir: root, Fault: func(point string) error {
			if point == "init.config" {
				return injected
			}
			return nil
		}})
		if !errors.Is(err, injected) {
			t.Fatalf("fault=%v", err)
		}
		before := persistentWorkspaceSnapshot(t, root)
		if _, err := ListRepositories(ctx, WorkspaceOptions{Workdir: root, CWD: root}); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("repo ls accepted pending workspace init: %v", err)
		}
		after := persistentWorkspaceSnapshot(t, root)
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("repo ls changed pending persistent workspace state: before=%#v after=%#v", before, after)
		}
	})

	t.Run("repo rm committed config", func(t *testing.T) {
		root := t.TempDir()
		if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
			t.Fatal(err)
		}
		if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
			t.Fatal(err)
		}
		injected := errors.New("stop after repository config removal")
		_, err := RemoveRepositoryResult(ctx, RepositoryRemoveOptions{
			WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo", Force: true,
			Fault: func(point string) error {
				if point == "repo.rm.config" {
					return injected
				}
				return nil
			},
		})
		if !errors.Is(err, injected) {
			t.Fatalf("fault=%v", err)
		}
		before := persistentWorkspaceSnapshot(t, root)
		if _, err := ListRepositories(ctx, WorkspaceOptions{Workdir: root, CWD: root}); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("repo ls accepted pending committed removal: %v", err)
		}
		if _, err := ShowRepository(ctx, RepositoryShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("repo show misclassified pending committed removal: %v", err)
		}
		after := persistentWorkspaceSnapshot(t, root)
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("repo reads changed pending removal persistent state: before=%#v after=%#v", before, after)
		}
	})
}

func TestDistRecoveryRejectsUnsupportedKindAndConfigForgery(t *testing.T) {
	ctx := context.Background()
	newFixture := func(t *testing.T) (string, config.Config, []byte) {
		t.Helper()
		root := t.TempDir()
		cfg := config.Default()
		cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{
			"el9": {Format: "rpm", Architectures: []string{"x86_64"}},
		}}
		writeManagedConfig(t, root, cfg)
		if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
			t.Fatal(err)
		}
		cfg.Repositories["repo"].Dists["el9"] = config.DistConfig{Format: "rpm"}
		writeManagedConfig(t, root, cfg)
		data, err := os.ReadFile(filepath.Join(root, config.ConfigFilename))
		if err != nil {
			t.Fatal(err)
		}
		return root, cfg, data
	}
	insert := func(t *testing.T, root, kind string, payload distOperationPayload) {
		t.Helper()
		store, err := state.Open(filepath.Join(root, ".sow", "repo.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		id := strings.Repeat("e", 64)
		if err := store.BeginOperation(ctx, state.Operation{ID: id, Kind: kind, State: state.OperationPlanned, PayloadJSON: string(body)}); err != nil {
			t.Fatal(err)
		}
		if err := store.SetOperationState(ctx, id, state.OperationStaged, ""); err != nil {
			t.Fatal(err)
		}
		if err := store.SetOperationState(ctx, id, state.OperationApplied, ""); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("architecture add is not a P1 operation", func(t *testing.T) {
		root, cfg, configData := newFixture(t)
		store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
		if err != nil {
			t.Fatal(err)
		}
		summary, err := store.Summary(ctx)
		if closeErr := store.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			t.Fatal(err)
		}
		effectiveSHA, _, err := effectiveDistConfig(ctx, root, cfg, "repo", "el9")
		if err != nil {
			t.Fatal(err)
		}
		payload := distOperationPayload{
			Version: distOperationVersion, Repository: "repo", Name: "el9", Format: "rpm",
			Architectures: []state.Architecture{{Family: "aarch64", EcosystemArch: "aarch64"}},
			Generation:    summary.BuiltGeneration + 1, EffectiveConfigSHA256: effectiveSHA,
			OldConfigSHA256: bytesSHA(configData), NewConfigSHA256: bytesSHA(configData), NewConfig: configData,
			TreeSHA256: strings.Repeat("b", 64),
		}
		insert(t, root, "dist.arch.add", payload)
		if _, err := Init(ctx, InitOptions{Dir: root}); !errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), "unsupported pending operation") {
			t.Fatalf("P2 architecture-add operation accepted: %v", err)
		}
	})

	t.Run("remove config binding", func(t *testing.T) {
		root, _, configData := newFixture(t)
		store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
		if err != nil {
			t.Fatal(err)
		}
		summary, err := store.Summary(ctx)
		if closeErr := store.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			t.Fatal(err)
		}
		payload := distOperationPayload{
			Version: distOperationVersion, Repository: "repo", Name: "el9", Generation: summary.BuiltGeneration + 1,
			OldConfigSHA256: strings.Repeat("a", 64), NewConfigSHA256: bytesSHA(configData), NewConfig: configData,
			TreeSHA256: strings.Repeat("b", 64),
		}
		insert(t, root, "dist.rm", payload)
		if _, err := Init(ctx, InitOptions{Dir: root}); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("config-forged dist.rm accepted: %v", err)
		}
		if _, err := os.Stat(filepath.Join(root, "repo", "dists", "el9")); err != nil {
			t.Fatalf("forged dist.rm removed live Dist: %v", err)
		}
	})
}

func TestRepositoryWorkspaceJournalRecoveryMatrix(t *testing.T) {
	ctx := context.Background()
	for _, point := range []string{"repo.new.journal", "repo.new.config"} {
		t.Run(point, func(t *testing.T) {
			root := t.TempDir()
			if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
				t.Fatal(err)
			}
			injected := errors.New("injected")
			_, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo", Fault: func(got string) error {
				if got == point {
					return injected
				}
				return nil
			}})
			if !errors.Is(err, injected) {
				t.Fatalf("fault=%v", err)
			}
			if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
				t.Fatalf("recover: %v", err)
			}
			if _, err := os.Stat(filepath.Join(root, "repo", "pool")); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(filepath.Join(root, ".sow", "workspace-ops", "active.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("journal remains: %v", err)
			}
		})
	}
}

func TestRepositoryInitializationResumesEmptyV0DatabaseOnlyWithWorkspaceJournal(t *testing.T) {
	ctx := context.Background()
	assertConverged := func(t *testing.T, root string) {
		t.Helper()
		for _, path := range []string{
			filepath.Join(root, "repo", "pool"),
			filepath.Join(root, "repo", "dists"),
			filepath.Join(root, ".sow", "repo", "stage"),
			filepath.Join(root, ".sow", "repo", "recovery"),
		} {
			if info, err := os.Stat(path); err != nil || !info.IsDir() {
				t.Fatalf("repository shell did not converge at %s: info=%v err=%v", path, info, err)
			}
		}
		store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
		if err != nil {
			t.Fatalf("repository database did not converge to schema v1: %v", err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(workspaceJournalPath(root)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("workspace journal remains after recovery: %v", err)
		}
	}
	makePartialShell := func(t *testing.T, root string) {
		t.Helper()
		if err := os.Mkdir(filepath.Join(root, "repo"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(root, ".sow", "repo"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, ".sow", "repo.db"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("repo.new", func(t *testing.T) {
		root := t.TempDir()
		if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
			t.Fatal(err)
		}
		injected := errors.New("injected after repo.new config commit")
		_, err := NewRepository(ctx, RepositoryNewOptions{
			WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root},
			Name:             "repo",
			Fault: func(point string) error {
				if point == "repo.new.config" {
					return injected
				}
				return nil
			},
		})
		if !errors.Is(err, injected) {
			t.Fatalf("fault=%v", err)
		}
		makePartialShell(t, root)
		if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
			t.Fatalf("recover repo.new: %v", err)
		}
		assertConverged(t, root)
	})

	t.Run("repo.init", func(t *testing.T) {
		root := t.TempDir()
		cfg := config.Default()
		cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{}}
		writeManagedConfig(t, root, cfg)
		injected := errors.New("injected after repo.init journal")
		_, err := Init(ctx, InitOptions{Dir: root, Fault: func(point string) error {
			if point == "init.repo.journal.repo" {
				return injected
			}
			return nil
		}})
		if !errors.Is(err, injected) {
			t.Fatalf("fault=%v", err)
		}
		makePartialShell(t, root)
		if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
			t.Fatalf("recover repo.init: %v", err)
		}
		assertConverged(t, root)
	})

	t.Run("no journal", func(t *testing.T) {
		root := t.TempDir()
		if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
			t.Fatal(err)
		}
		dbPath := filepath.Join(root, ".sow", "repo.db")
		if err := os.WriteFile(dbPath, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); !errors.Is(err, ErrRejected) {
			t.Fatalf("unjournaled empty database was accepted: %v", err)
		}
		if info, err := os.Stat(dbPath); err != nil || info.Size() != 0 {
			t.Fatalf("rejected empty database changed: info=%v err=%v", info, err)
		}
		cfg, err := config.Load(filepath.Join(root, config.ConfigFilename))
		if err != nil {
			t.Fatal(err)
		}
		if _, exists := cfg.Repositories["repo"]; exists {
			t.Fatal("unjournaled repository was committed to config")
		}
	})
}

func TestRepositoryRemovalWorkspaceJournalRecoveryMatrix(t *testing.T) {
	ctx := context.Background()
	for _, point := range []string{"repo.rm.journal", "repo.rm.config"} {
		t.Run(point, func(t *testing.T) {
			root := t.TempDir()
			if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
				t.Fatal(err)
			}
			if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
				t.Fatal(err)
			}
			injected := errors.New("injected")
			err := RemoveRepository(ctx, RepositoryRemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo", Force: true, Fault: func(got string) error {
				if got == point {
					return injected
				}
				return nil
			}})
			if !errors.Is(err, injected) {
				t.Fatalf("fault=%v", err)
			}
			if err := RemoveRepository(ctx, RepositoryRemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo", Force: true}); err != nil {
				t.Fatalf("recover: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(root, "repo")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("repository remains: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(root, ".sow", "workspace-ops", "active.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("journal remains: %v", err)
			}
		})
	}
}

func TestDistSQLiteJournalRecoveryMatrix(t *testing.T) {
	ctx := context.Background()
	for _, point := range []string{"dist.new.planned", "dist.new.staged", "dist.new.applied", "dist.new.built", "dist.new.finalized"} {
		t.Run(point, func(t *testing.T) {
			root := t.TempDir()
			if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
				t.Fatal(err)
			}
			if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
				t.Fatal(err)
			}
			injected := errors.New("injected")
			result, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9", Format: "rpm", Fault: func(got string) error {
				if got == point {
					return injected
				}
				return nil
			}})
			if !errors.Is(err, injected) {
				t.Fatalf("fault=%v", err)
			}
			if point == "dist.new.finalized" && (result.Name != "el9" || result.Format != "rpm" || result.Generation < 1) {
				t.Fatalf("committed Dist result was lost after finalization: %#v", result)
			}
			if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9", Format: "rpm"}); err != nil {
				t.Fatalf("recover: %v", err)
			}
			store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
			if err != nil {
				t.Fatal(err)
			}
			pending, err := store.PendingOperations(ctx)
			store.Close()
			if err != nil || len(pending) != 0 {
				t.Fatalf("pending=%#v err=%v", pending, err)
			}
			if _, err := os.Stat(filepath.Join(root, "repo", "dists", "el9", "x86_64", "repodata", "repomd.xml")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDistRemovalRecoveryMatrixPreservesPool(t *testing.T) {
	ctx := context.Background()
	for _, point := range []string{"dist.rm.planned", "dist.rm.staged", "dist.rm.applied", "dist.rm.built", "dist.rm.finalized"} {
		t.Run(point, func(t *testing.T) {
			root := t.TempDir()
			if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
				t.Fatal(err)
			}
			if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
				t.Fatal(err)
			}
			if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9", Format: "rpm"}); err != nil {
				t.Fatal(err)
			}
			inputs := filepath.Join(root, "inputs")
			if err := os.Mkdir(inputs, 0o755); err != nil {
				t.Fatal(err)
			}
			rpm := decodeManagedFixture(t, filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "keep.rpm"))
			if _, err := Add(ctx, AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
				t.Fatal(err)
			}
			store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
			if err != nil {
				t.Fatal(err)
			}
			objects, err := store.ListPackageObjects(ctx, []string{"el9"}, false)
			store.Close()
			if err != nil || len(objects) != 1 {
				t.Fatalf("objects=%#v err=%v", objects, err)
			}
			poolFile := filepath.Join(root, "repo", filepath.FromSlash(objects[0].PoolPath))
			poolBefore, err := os.ReadFile(poolFile)
			if err != nil {
				t.Fatal(err)
			}
			injected := errors.New("injected")
			err = RemoveDist(ctx, DistRemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9", Force: true, Fault: func(got string) error {
				if got == point {
					return injected
				}
				return nil
			}})
			if !errors.Is(err, injected) {
				t.Fatalf("fault=%v", err)
			}
			if err := RemoveDist(ctx, DistRemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9", Force: true}); err != nil {
				t.Fatalf("recover: %v", err)
			}
			if data, err := os.ReadFile(poolFile); err != nil || !bytes.Equal(data, poolBefore) {
				t.Fatalf("pool size=%d err=%v", len(data), err)
			}
			if _, err := os.Lstat(filepath.Join(root, "repo", "dists", "el9")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("dist remains: %v", err)
			}
		})
	}
}

func TestDistPreApplyFailuresBecomeTerminalWithoutConsumingCrashRecovery(t *testing.T) {
	readLatest := func(t *testing.T, root, kind string) state.Operation {
		t.Helper()
		store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
		if err != nil {
			t.Fatal(err)
		}
		operations, listErr := store.ListOperations(context.Background(), 100, "")
		closeErr := store.Close()
		if err := errors.Join(listErr, closeErr); err != nil {
			t.Fatal(err)
		}
		for _, operation := range operations {
			if operation.Kind == kind {
				return operation
			}
		}
		t.Fatalf("operation %q was not recorded", kind)
		return state.Operation{}
	}
	createStageCollision := func(t *testing.T, root, kind string) func(string) error {
		t.Helper()
		return func(point string) error {
			if point != kind+".planned" {
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
			for _, operation := range pending {
				if operation.Kind == kind {
					return os.Mkdir(distStageRoot(root, "repo", operation.ID), 0o700)
				}
			}
			return fmt.Errorf("pending %s operation was not visible", kind)
		}
	}
	assertFailed := func(t *testing.T, root, kind, class string) state.Operation {
		t.Helper()
		operation := readLatest(t, root, kind)
		if operation.State != state.OperationFailed || operation.ErrorClass != class || operation.ErrorMessage == "" {
			t.Fatalf("ordinary %s failure operation=%#v", kind, operation)
		}
		if _, err := os.Lstat(distStageRoot(root, "repo", operation.ID)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed %s retained stage: %v", kind, err)
		}
		return operation
	}

	t.Run("dist new stage collision", func(t *testing.T) {
		root := t.TempDir()
		if _, err := Init(context.Background(), InitOptions{Dir: root}); err != nil {
			t.Fatal(err)
		}
		options := WorkspaceOptions{Workdir: root, CWD: root}
		if _, err := NewRepository(context.Background(), RepositoryNewOptions{WorkspaceOptions: options, Name: "repo"}); err != nil {
			t.Fatal(err)
		}
		_, err := NewDist(context.Background(), DistNewOptions{WorkspaceOptions: options, Repository: "repo", Name: "el9", Format: "rpm", Fault: createStageCollision(t, root, "dist.new")})
		if err == nil {
			t.Fatal("Dist creation accepted an occupied private stage")
		}
		assertFailed(t, root, "dist.new", "runtime")
		cfg, err := config.Load(filepath.Join(root, config.ConfigFilename))
		if err != nil {
			t.Fatal(err)
		}
		if _, exists := cfg.Repositories["repo"].Dists["el9"]; exists {
			t.Fatal("failed Dist creation changed Desired config")
		}
	})

	t.Run("dist init stage collision", func(t *testing.T) {
		root := t.TempDir()
		cfg := config.Default()
		cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
		writeManagedConfig(t, root, cfg)
		result, err := Init(context.Background(), InitOptions{Dir: root, Fault: createStageCollision(t, root, "dist.init")})
		if err == nil || result.DistsInitialized != 0 {
			t.Fatalf("Dist init collision result=%#v err=%v", result, err)
		}
		assertFailed(t, root, "dist.init", "runtime")
		store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
		if err != nil {
			t.Fatal(err)
		}
		_, getErr := store.GetDist(context.Background(), "el9")
		closeErr := store.Close()
		if !errors.Is(getErr, state.ErrNotFound) || closeErr != nil {
			t.Fatalf("failed Dist init committed state: get=%v close=%v", getErr, closeErr)
		}
	})

	t.Run("dist removal cancellation", func(t *testing.T) {
		root := t.TempDir()
		if _, err := Init(context.Background(), InitOptions{Dir: root}); err != nil {
			t.Fatal(err)
		}
		options := WorkspaceOptions{Workdir: root, CWD: root}
		if _, err := NewRepository(context.Background(), RepositoryNewOptions{WorkspaceOptions: options, Name: "repo"}); err != nil {
			t.Fatal(err)
		}
		if _, err := NewDist(context.Background(), DistNewOptions{WorkspaceOptions: options, Repository: "repo", Name: "el9", Format: "rpm"}); err != nil {
			t.Fatal(err)
		}
		runCtx, cancel := context.WithCancel(context.Background())
		_, err := RemoveDistResult(runCtx, DistRemoveOptions{WorkspaceOptions: options, Repository: "repo", Name: "el9", Force: true, Fault: func(point string) error {
			if point == "dist.rm.planned" {
				cancel()
			}
			return nil
		}})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled Dist removal error=%v", err)
		}
		assertFailed(t, root, "dist.rm", "cancelled")
		cfg, err := config.Load(filepath.Join(root, config.ConfigFilename))
		if err != nil {
			t.Fatal(err)
		}
		if _, exists := cfg.Repositories["repo"].Dists["el9"]; !exists {
			t.Fatal("cancelled Dist removal changed Desired config")
		}
	})

	t.Run("injected crash remains planned", func(t *testing.T) {
		root := t.TempDir()
		if _, err := Init(context.Background(), InitOptions{Dir: root}); err != nil {
			t.Fatal(err)
		}
		options := WorkspaceOptions{Workdir: root, CWD: root}
		if _, err := NewRepository(context.Background(), RepositoryNewOptions{WorkspaceOptions: options, Name: "repo"}); err != nil {
			t.Fatal(err)
		}
		injected := errors.New("simulated Dist process stop")
		_, err := NewDist(context.Background(), DistNewOptions{WorkspaceOptions: options, Repository: "repo", Name: "el9", Format: "rpm", Fault: func(point string) error {
			if point == "dist.new.planned" {
				return injected
			}
			return nil
		}})
		if !errors.Is(err, injected) {
			t.Fatalf("injected Dist failure=%v", err)
		}
		operation := readLatest(t, root, "dist.new")
		if operation.State != state.OperationPlanned || operation.ErrorClass != "" || operation.ErrorMessage != "" {
			t.Fatalf("injected Dist crash was terminalized: %#v", operation)
		}
	})
}

func TestManagedLifecycleSubprocessCrashReplayMatrix(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		op    string
		point string
	}{
		{"init", "init.repo.journal.repo"},
		{"init", "dist.init.planned"},
		{"init", "dist.init.staged"},
		{"init", "dist.init.applied"},
		{"init", "dist.init.built"},
		{"init", "dist.init.finalized"},
		{"repo-new", "repo.new.journal"},
		{"repo-new", "repo.new.config"},
		{"repo-rm", "repo.rm.journal"},
		{"repo-rm", "repo.rm.config"},
		{"dist-new", "dist.new.planned"},
		{"dist-new", "dist.new.staged"},
		{"dist-new", "dist.new.applied"},
		{"dist-new", "dist.new.built"},
		{"dist-new", "dist.new.finalized"},
		{"dist-rm", "dist.rm.planned"},
		{"dist-rm", "dist.rm.staged"},
		{"dist-rm", "dist.rm.applied"},
		{"dist-rm", "dist.rm.built"},
		{"dist-rm", "dist.rm.finalized"},
		{"workspace-init", "init.journal"},
		{"workspace-init", "init.config"},
	}
	for _, tc := range tests {
		t.Run(tc.op+"/"+tc.point, func(t *testing.T) {
			root := t.TempDir()
			prepareCrashWorkspace(t, root, tc.op)
			cmd := exec.Command(os.Args[0], "-test.run=^TestManagedCrashHelper$")
			cmd.Env = append(os.Environ(), "SOW_MANAGED_CRASH_HELPER=1", "SOW_MANAGED_CRASH_ROOT="+root, "SOW_MANAGED_CRASH_OP="+tc.op, "SOW_MANAGED_CRASH_POINT="+tc.point)
			err := cmd.Run()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 91 {
				t.Fatalf("helper error=%v", err)
			}
			if err := runManagedCrashOperation(ctx, root, tc.op, nil); err != nil {
				t.Fatalf("replay: %v", err)
			}
			cfg, err := config.Load(filepath.Join(root, config.ConfigFilename))
			if err != nil {
				t.Fatal(err)
			}
			switch tc.op {
			case "init", "dist-new":
				if _, ok := cfg.Repositories["repo"].Dists["el9"]; !ok {
					t.Fatal("dist add did not converge")
				}
				if _, err := os.Stat(filepath.Join(root, "repo", "dists", "el9", "x86_64", "repodata", "repomd.xml")); err != nil {
					t.Fatal(err)
				}
			case "repo-new":
				if _, ok := cfg.Repositories["repo"]; !ok {
					t.Fatal("repo new did not converge")
				}
			case "repo-rm":
				if _, ok := cfg.Repositories["repo"]; ok {
					t.Fatal("repo rm did not converge")
				}
			case "dist-rm":
				if _, ok := cfg.Repositories["repo"].Dists["el9"]; ok {
					t.Fatal("dist rm did not converge")
				}
			case "workspace-init":
				if len(cfg.Repositories) != 0 {
					t.Fatalf("default init created repositories: %#v", cfg.Repositories)
				}
			case "arch-add-rpm", "arch-add-deb":
				distName := "el9"
				view := filepath.Join(root, "repo", "dists", distName, "aarch64", "repodata", "repomd.xml")
				if tc.op == "arch-add-deb" {
					distName = "noble"
					view = filepath.Join(root, "repo", "dists", distName, "main", "binary-arm64", "Packages.gz")
				}
				if _, err := os.Stat(view); err != nil {
					t.Fatalf("architecture view did not converge: %v", err)
				}
			}
			for _, private := range []string{"stage", "recovery"} {
				path := filepath.Join(root, ".sow", "repo", private)
				entries, err := os.ReadDir(path)
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				if err != nil || len(entries) != 0 {
					t.Fatalf("private %s residue=%v err=%v", private, entries, err)
				}
			}
		})
	}
}

func TestManagedCrashHelper(t *testing.T) {
	if os.Getenv("SOW_MANAGED_CRASH_HELPER") != "1" {
		t.Skip("helper")
	}
	root := os.Getenv("SOW_MANAGED_CRASH_ROOT")
	op := os.Getenv("SOW_MANAGED_CRASH_OP")
	point := os.Getenv("SOW_MANAGED_CRASH_POINT")
	if err := runManagedCrashOperation(context.Background(), root, op, func(got string) error {
		if got == point {
			os.Exit(91)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Fatalf("crash point %q was not reached", point)
}

func prepareCrashWorkspace(t *testing.T, root, operation string) {
	t.Helper()
	ctx := context.Background()
	if operation == "workspace-init" {
		return
	}
	if operation == "init" {
		cfg := config.Default()
		cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
		writeManagedConfig(t, root, cfg)
		return
	}
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	if operation == "repo-new" {
		return
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
		t.Fatal(err)
	}
	if operation == "repo-rm" || operation == "dist-new" {
		return
	}
	if operation == "arch-add-rpm" || operation == "arch-add-deb" {
		cfg, err := config.Load(filepath.Join(root, config.ConfigFilename))
		if err != nil {
			t.Fatal(err)
		}
		cfg.Architectures = []string{"x86_64"}
		writeManagedConfig(t, root, cfg)
	}
	distName, format := "el9", "rpm"
	if operation == "arch-add-deb" {
		distName, format = "noble", "deb"
	}
	if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: distName, Format: format}); err != nil {
		t.Fatal(err)
	}
	if operation == "arch-add-rpm" || operation == "arch-add-deb" {
		cfg, err := config.Load(filepath.Join(root, config.ConfigFilename))
		if err != nil {
			t.Fatal(err)
		}
		cfg.Architectures = []string{"x86_64", "aarch64"}
		writeManagedConfig(t, root, cfg)
	}
}

func runManagedCrashOperation(ctx context.Context, root, operation string, fault func(string) error) error {
	switch operation {
	case "workspace-init", "arch-add-rpm", "arch-add-deb":
		_, err := Init(ctx, InitOptions{Dir: root, Fault: fault})
		return err
	case "init":
		_, err := Init(ctx, InitOptions{Dir: root, Fault: fault})
		return err
	case "repo-new":
		_, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo", Fault: fault})
		return err
	case "repo-rm":
		return RemoveRepository(ctx, RepositoryRemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo", Force: true, Fault: fault})
	case "dist-new":
		_, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9", Format: "rpm", Fault: fault})
		return err
	case "dist-rm":
		return RemoveDist(ctx, DistRemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9", Force: true, Fault: fault})
	}
	return fmt.Errorf("unknown crash operation %q", operation)
}

func writeManagedConfig(t *testing.T, root string, cfg config.Config) {
	t.Helper()
	data, err := config.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, config.ConfigFilename), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentInitOfEmptyWorkspaceIsIdempotent(t *testing.T) {
	root := filepath.Join(t.TempDir(), "workspace")
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			_, err := Init(context.Background(), InitOptions{Dir: root})
			results <- err
		}()
	}
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("concurrent init: %v", err)
		}
	}
	if _, err := CheckConfig(context.Background(), WorkspaceOptions{Workdir: root, CWD: root}); err != nil {
		t.Fatalf("final workspace: %v", err)
	}
}

func TestRepositoryNameEndingInDBUsesExactOwnedPaths(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "foo.db"}); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckConfig(ctx, WorkspaceOptions{Workdir: root, CWD: root}); err != nil {
		t.Fatalf("exact database ownership: %v", err)
	}
	if _, err := ShowRepository(ctx, RepositoryShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "foo.db"}); err != nil {
		t.Fatal(err)
	}
}

func TestInitReturnsCommittedProgressWhenLaterDistFails(t *testing.T) {
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{
		"alpha": {Format: "rpm"},
		"zeta":  {Format: "rpm"},
	}}
	writeManagedConfig(t, root, cfg)
	planned := 0
	injected := errors.New("injected second Dist failure")
	result, err := Init(context.Background(), InitOptions{Dir: root, Fault: func(point string) error {
		if point == "dist.init.planned" {
			planned++
			if planned == 2 {
				return injected
			}
		}
		return nil
	}})
	if !errors.Is(err, injected) || result.RepositoriesInitialized != 1 || result.DistsInitialized != 1 || !result.HasCommittedChanges() {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if _, err := os.Stat(filepath.Join(root, "repo", "dists", "alpha", "x86_64", "repodata", "repomd.xml")); err != nil {
		t.Fatalf("first committed Dist missing: %v", err)
	}
	if retry, err := Init(context.Background(), InitOptions{Dir: root}); err != nil || retry.DistsInitialized != 1 {
		t.Fatalf("retry=%#v err=%v", retry, err)
	}
}

func TestInitPreflightRejectsUnsafeReservedStateWithoutCommittingConfig(t *testing.T) {
	root := t.TempDir()
	lockRoot := filepath.Join(root, ".sow", "repo-locks")
	if err := os.MkdirAll(lockRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(t.TempDir(), "sentinel")
	if err := os.WriteFile(sentinel, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sentinel, filepath.Join(lockRoot, "evil.lock")); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(context.Background(), InitOptions{Dir: root}); err == nil {
		t.Fatal("init accepted an unsafe pre-existing lock")
	}
	if _, err := os.Lstat(filepath.Join(root, config.ConfigFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("init committed config after failed preflight: %v", err)
	}
	if data, err := os.ReadFile(sentinel); err != nil || string(data) != "unchanged" {
		t.Fatalf("external target changed: %q err=%v", data, err)
	}
}

func TestConfiguredRepositoryAndDistRefuseForeignPathAdoption(t *testing.T) {
	ctx := context.Background()
	t.Run("repository", func(t *testing.T) {
		root := t.TempDir()
		cfg := config.Default()
		cfg.Repositories["repo"] = config.RepositoryConfig{}
		writeManagedConfig(t, root, cfg)
		foreign := filepath.Join(root, "repo", "pool", "foreign.rpm")
		if err := os.MkdirAll(filepath.Dir(foreign), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(foreign, []byte("foreign"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := CheckConfig(ctx, WorkspaceOptions{Workdir: root, CWD: root}); !errors.Is(err, ErrRejected) {
			t.Fatalf("config check adoption=%v", err)
		}
		if _, err := Init(ctx, InitOptions{Dir: root}); !errors.Is(err, ErrRejected) {
			t.Fatalf("init adoption=%v", err)
		}
		if _, err := os.Lstat(filepath.Join(root, ".sow")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed init created state: %v", err)
		}
		if data, err := os.ReadFile(foreign); err != nil || string(data) != "foreign" {
			t.Fatalf("foreign package changed: %q err=%v", data, err)
		}
	})

	t.Run("dist", func(t *testing.T) {
		root := t.TempDir()
		if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
			t.Fatal(err)
		}
		if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(filepath.Join(root, config.ConfigFilename))
		if err != nil {
			t.Fatal(err)
		}
		repo := cfg.Repositories["repo"]
		repo.Dists = map[string]config.DistConfig{"foreign": {Format: "rpm"}}
		cfg.Repositories["repo"] = repo
		writeManagedConfig(t, root, cfg)
		target := filepath.Join(root, "repo", "dists", "foreign")
		if err := os.WriteFile(target, []byte("foreign"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := CheckConfig(ctx, WorkspaceOptions{Workdir: root, CWD: root}); !errors.Is(err, ErrRejected) {
			t.Fatalf("config check Dist adoption=%v", err)
		}
	})
}

func TestConfigCheckIsReadOnlyWithoutTemporaryScratch(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9", Format: "rpm"}); err != nil {
		t.Fatal(err)
	}
	before := persistentWorkspaceSnapshot(t, root)
	blockedTemp := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blockedTemp, []byte("blocked"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", blockedTemp)
	if _, err := CheckConfig(ctx, WorkspaceOptions{Workdir: root, CWD: root}); err != nil {
		t.Fatalf("read-only check required scratch storage: %v", err)
	}
	after := persistentWorkspaceSnapshot(t, root)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("config check changed persistent workspace state: before=%#v after=%#v", before, after)
	}
}

func TestManagedReadSurfacesArePhysicallyReadOnly(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9", Format: "rpm"}); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(root, ".sow", "repo.db")
	before := persistentWorkspaceSnapshot(t, root)
	assertPersistentSQLiteCoordinationFiles(t, database)
	if _, err := CheckConfig(ctx, WorkspaceOptions{Workdir: root, CWD: root}); err != nil {
		t.Fatal(err)
	}
	if _, err := ShowConfig(ctx, ConfigShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, All: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := ListRepositories(ctx, WorkspaceOptions{Workdir: root, CWD: root}); err != nil {
		t.Fatal(err)
	}
	if _, err := ShowRepository(ctx, RepositoryShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ListDists(ctx, DistListOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ShowDist(ctx, DistShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9"}); err != nil {
		t.Fatal(err)
	}
	after := persistentWorkspaceSnapshot(t, root)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("managed read surface changed persistent workspace state: before=%#v after=%#v", before, after)
	}
	assertPersistentSQLiteCoordinationFiles(t, database)
	if _, err := os.Lstat(database + "-journal"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("managed read surface created rollback journal: %v", err)
	}
}

// persistentWorkspaceSnapshot deliberately excludes SQLite's -shm file. A
// read-only WAL connection may update shared-memory read marks while leaving
// the database, WAL, configuration, journals, and public repository unchanged.
// Those coordination bytes are not product state; every other file is.
func persistentWorkspaceSnapshot(t *testing.T, root string) map[string][]byte {
	t.Helper()
	snapshot := map[string][]byte{}
	err := walkRootedTree(context.Background(), root, func(relative string, file *os.File, info os.FileInfo) error {
		if strings.HasSuffix(relative, ".db-shm") {
			return nil
		}
		body, err := io.ReadAll(file)
		if err != nil {
			return err
		}
		snapshot["file:"+relative+":"+info.Mode().String()] = body
		return nil
	}, func(relative string, _ *os.File, info os.FileInfo) error {
		snapshot["dir:"+relative+":"+info.Mode().String()] = nil
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func assertPersistentSQLiteCoordinationFiles(t *testing.T, database string) {
	t.Helper()
	for _, suffix := range []string{"-wal", "-shm"} {
		info, err := os.Lstat(database + suffix)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("persistent SQLite coordination file %s is unsafe or missing: info=%v err=%v", suffix, info, err)
		}
	}
	if info, err := os.Lstat(database + "-shm"); err != nil || info.Size() == 0 {
		t.Fatalf("persistent SQLite shared-memory file is unusable: info=%v err=%v", info, err)
	}
}

func TestManagedReadSurfacesSerializeWithLifecycleWriter(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9", Format: "rpm"}); err != nil {
		t.Fatal(err)
	}

	paused := make(chan struct{})
	resume := make(chan struct{})
	writerDone := make(chan error, 1)
	go func() {
		writerDone <- RemoveDist(ctx, DistRemoveOptions{
			WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root},
			Repository:       "repo",
			Name:             "el9",
			Force:            true,
			Fault: func(point string) error {
				if point == "dist.rm.applied" {
					close(paused)
					<-resume
				}
				return nil
			},
		})
	}()
	<-paused

	type readResult struct {
		name string
		err  error
	}
	results := make(chan readResult, 4)
	go func() {
		check, err := CheckConfig(ctx, WorkspaceOptions{Workdir: root, CWD: root})
		if err == nil && check.Dists != 0 {
			err = fmt.Errorf("config check saw %d dists after commit", check.Dists)
		}
		results <- readResult{"config check", err}
	}()
	go func() {
		info, err := ShowRepository(ctx, RepositoryShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"})
		if err == nil && info.Dists != 0 {
			err = fmt.Errorf("repo show saw %d dists after commit", info.Dists)
		}
		results <- readResult{"repo show", err}
	}()
	go func() {
		dists, err := ListDists(ctx, DistListOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo"})
		if err == nil && len(dists) != 0 {
			err = fmt.Errorf("dist ls saw %#v after commit", dists)
		}
		results <- readResult{"dist ls", err}
	}()
	go func() {
		_, err := ShowDist(ctx, DistShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9"})
		if errors.Is(err, ErrRejected) {
			err = nil
		}
		results <- readResult{"dist show", err}
	}()

	select {
	case result := <-results:
		close(resume)
		<-writerDone
		t.Fatalf("%s escaped the writer's exclusive workspace lock: %v", result.name, result.err)
	case <-time.After(80 * time.Millisecond):
	}
	close(resume)
	if err := <-writerDone; err != nil {
		t.Fatalf("writer misreported a committed mutation: %v", err)
	}
	for range 4 {
		result := <-results
		if result.err != nil {
			t.Fatalf("%s returned a torn post-commit view: %v", result.name, result.err)
		}
	}
	database := filepath.Join(root, ".sow", "repo.db")
	assertPersistentSQLiteCoordinationFiles(t, database)
	if _, err := os.Lstat(database + "-journal"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("writer left rollback journal after releasing its lock: %v", err)
	}
}

func TestRepositoryLifecycleOwnsDurableLockFiles(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(root, ".sow", "workspace.lock")} {
		if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("workspace lock was not initialized safely: info=%v err=%v", info, err)
		}
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
		t.Fatal(err)
	}
	repoLock := filepath.Join(root, ".sow", "repo-locks", "repo.lock")
	if info, err := os.Lstat(repoLock); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("repository lock was not initialized safely: info=%v err=%v", info, err)
	}
	if err := RemoveRepository(ctx, RepositoryRemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo", Force: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(repoLock); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("repository lock remains after removal: %v", err)
	}
}

func TestLifecycleNeverRecreatesMissingFixedLockFiles(t *testing.T) {
	ctx := context.Background()
	t.Run("workspace", func(t *testing.T) {
		root := t.TempDir()
		if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, ".sow", "workspace.lock")
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("missing workspace lock was not rejected: %v", err)
		}
		if _, err := Init(ctx, InitOptions{Dir: root}); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("init recreated missing lock in initialized state: %v", err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("workspace lock was recreated: %v", err)
		}
	})

	t.Run("repository", func(t *testing.T) {
		root := t.TempDir()
		if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
			t.Fatal(err)
		}
		if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, ".sow", "repo-locks", "repo.lock")
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9", Format: "rpm"}); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("missing repository lock was not rejected: %v", err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("repository lock was recreated: %v", err)
		}
	})
}

func TestInitRecoversEmptyStateRootBeforeWorkspaceLockCreation(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".sow"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(context.Background(), InitOptions{Dir: root}); err != nil {
		t.Fatalf("recover empty state root: %v", err)
	}
	for _, path := range []string{
		filepath.Join(root, ".sow", "workspace.lock"),
		filepath.Join(root, ".sow", "workspace-ops"),
		filepath.Join(root, ".sow", "repo-locks"),
	} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("initial state control path missing at %s: %v", path, err)
		}
	}
}

func TestMissingRepositoryDatabaseNeverResetsState(t *testing.T) {
	ctx := context.Background()
	for _, operation := range []string{"init", "repo-rm", "dist-new", "dist-rm"} {
		t.Run(operation, func(t *testing.T) {
			root := t.TempDir()
			if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
				t.Fatal(err)
			}
			if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
				t.Fatal(err)
			}
			if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9", Format: "rpm"}); err != nil {
				t.Fatal(err)
			}
			sentinel := filepath.Join(root, "repo", "pool", "keep")
			if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
				t.Fatal(err)
			}
			configBefore, err := os.ReadFile(filepath.Join(root, config.ConfigFilename))
			if err != nil {
				t.Fatal(err)
			}
			dbPath := filepath.Join(root, ".sow", "repo.db")
			if err := os.Remove(dbPath); err != nil {
				t.Fatal(err)
			}
			var operationErr error
			switch operation {
			case "init":
				_, operationErr = Init(ctx, InitOptions{Dir: root})
			case "repo-rm":
				operationErr = RemoveRepository(ctx, RepositoryRemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo", Force: true})
			case "dist-new":
				_, operationErr = NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "other", Format: "rpm"})
			case "dist-rm":
				operationErr = RemoveDist(ctx, DistRemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9", Force: true})
			}
			if operationErr == nil {
				t.Fatal("missing repository state was silently recreated")
			}
			if _, err := os.Lstat(dbPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("database recreated: %v", err)
			}
			if data, err := os.ReadFile(sentinel); err != nil || string(data) != "keep" {
				t.Fatalf("Pool changed: %q err=%v", data, err)
			}
			if data, err := os.ReadFile(filepath.Join(root, config.ConfigFilename)); err != nil || string(data) != string(configBefore) {
				t.Fatalf("config changed: err=%v", err)
			}
		})
	}
}

func TestDistRemovalMembershipGateAndPoolPreservation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9", Format: "rpm"}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "pkg.rpm"))
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	objects, err := store.ListPackageObjects(ctx, []string{"el9"}, false)
	store.Close()
	if err != nil || len(objects) != 1 {
		t.Fatalf("objects=%#v err=%v", objects, err)
	}
	poolFile := filepath.Join(root, "repo", filepath.FromSlash(objects[0].PoolPath))
	poolBefore, err := os.ReadFile(poolFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := RemoveDist(ctx, DistRemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9"}); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("non-force removal=%v", err)
	}
	result, err := RemoveDistResult(ctx, DistRemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9", Force: true})
	if err != nil || !result.Removed || result.Noop {
		t.Fatalf("force removal result=%#v err=%v", result, err)
	}
	if data, err := os.ReadFile(poolFile); err != nil || !bytes.Equal(data, poolBefore) {
		t.Fatalf("Pool package changed: size=%d err=%v", len(data), err)
	}
	store, err = state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	var packages, memberships int
	if err := store.DB().QueryRow(`SELECT (SELECT count(*) FROM package_objects), (SELECT count(*) FROM memberships)`).Scan(&packages, &memberships); err != nil {
		t.Fatal(err)
	}
	store.Close()
	if packages != 1 || memberships != 0 {
		t.Fatalf("packages=%d memberships=%d", packages, memberships)
	}
	store, err = state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	var operationID string
	if err := store.DB().QueryRow(`SELECT id FROM operations WHERE kind = 'dist.rm' ORDER BY created_at DESC, id DESC LIMIT 1`).Scan(&operationID); err != nil {
		store.Close()
		t.Fatal(err)
	}
	detail, detailErr := store.GetOperation(ctx, operationID)
	closeErr := store.Close()
	if err := errors.Join(detailErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if len(detail.Memberships) != 1 || detail.Memberships[0].DistName != "el9" || detail.Memberships[0].PackageSHA256 != objects[0].SHA256 || detail.Memberships[0].Action != "remove" || len(detail.Events) == 0 || detail.Events[len(detail.Events)-1].State != string(state.OperationDone) {
		t.Fatalf("dist removal audit=%#v", detail)
	}
	noop, err := RemoveDistResult(ctx, DistRemoveOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9", Force: true})
	if err != nil || !noop.Noop || noop.Removed {
		t.Fatalf("idempotent removal=%#v err=%v", noop, err)
	}
}

func TestMembershipArchitectureReferencesBlockConfigRemoval(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Architectures = []string{"x86_64"}
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	cfg.Architectures = []string{"x86_64", "aarch64"}
	writeManagedConfig(t, root, cfg)
	store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("b", 64)
	if _, err := store.DB().Exec(`INSERT INTO package_objects(sha256, format, coordinate, architecture, pool_path, size) VALUES (?, 'rpm', 'pkg-1-1.aarch64', 'aarch64', 'pool/pkg.rpm', 1)`, sha); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`INSERT INTO memberships(dist_name, package_sha256) VALUES ('el9', ?)`, sha); err != nil {
		t.Fatal(err)
	}
	store.Close()
	if _, err := CheckConfig(ctx, WorkspaceOptions{Workdir: root, CWD: root}); err != nil {
		t.Fatalf("config containing membership architecture rejected: %v", err)
	}
	cfg.Architectures = []string{"x86_64"}
	writeManagedConfig(t, root, cfg)
	if _, err := CheckConfig(ctx, WorkspaceOptions{Workdir: root, CWD: root}); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "membership") {
		t.Fatalf("removed membership architecture accepted: %v", err)
	}
}

func TestReadSurfacesRejectMissingRepositoryLayout(t *testing.T) {
	ctx := context.Background()
	for _, relative := range []string{filepath.Join("repo", "pool"), filepath.Join("repo", "dists"), filepath.Join(".sow", "repo", "stage"), filepath.Join(".sow", "repo", "recovery")} {
		t.Run(relative, func(t *testing.T) {
			root := t.TempDir()
			if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
				t.Fatal(err)
			}
			if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(root, relative)); err != nil {
				t.Fatal(err)
			}
			if _, err := ListRepositories(ctx, WorkspaceOptions{Workdir: root, CWD: root}); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("repo ls missing layout=%v", err)
			}
			if _, err := ShowRepository(ctx, RepositoryShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("repo show missing layout=%v", err)
			}
			if _, err := ListDists(ctx, DistListOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo"}); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("dist ls missing layout=%v", err)
			}
		})
	}
}

func TestReadSurfacesClassifyCorruptDistRowsAsIntegrity(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9", Format: "rpm"}); err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`PRAGMA ignore_check_constraints=ON`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`UPDATE dists SET built_generation='corrupt' WHERE name='el9'`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ListDists(ctx, DistListOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo"}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("dist ls corruption=%v", err)
	}
	if _, err := ShowDist(ctx, DistShowOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Name: "el9"}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("dist show corruption=%v", err)
	}
}

func TestConfigCheckRejectsSQLiteSidecarAndLockEntrySymlinks(t *testing.T) {
	ctx := context.Background()
	for _, relative := range []string{filepath.Join(".sow", "repo.db-wal"), filepath.Join(".sow", "repo-locks", "repo.lock")} {
		t.Run(filepath.Base(relative), func(t *testing.T) {
			root := t.TempDir()
			if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
				t.Fatal(err)
			}
			if _, err := NewRepository(ctx, RepositoryNewOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Name: "repo"}); err != nil {
				t.Fatal(err)
			}
			candidate := filepath.Join(root, relative)
			if err := os.Remove(candidate); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			sentinel := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(sentinel, []byte("unchanged"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(sentinel, candidate); err != nil {
				t.Fatal(err)
			}
			if _, err := CheckConfig(ctx, WorkspaceOptions{Workdir: root, CWD: root}); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("unsafe sidecar/lock accepted: %v", err)
			}
			if data, err := os.ReadFile(sentinel); err != nil || string(data) != "unchanged" {
				t.Fatalf("external target changed: %q err=%v", data, err)
			}
		})
	}
}

func TestUninitializedRepositoryOrphanSidecarIsRejectedReadOnly(t *testing.T) {
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{}
	writeManagedConfig(t, root, cfg)
	if err := os.MkdirAll(filepath.Join(root, ".sow", "workspace-ops"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, ".sow", "repo-locks"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".sow", "workspace.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	sidecar := filepath.Join(root, ".sow", "repo.db-wal")
	if err := os.WriteFile(sidecar, []byte("orphan"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckConfig(context.Background(), WorkspaceOptions{Workdir: root, CWD: root}); !errors.Is(err, ErrRejected) {
		t.Fatalf("orphan sidecar accepted: %v", err)
	}
	if data, err := os.ReadFile(sidecar); err != nil || string(data) != "orphan" {
		t.Fatalf("orphan sidecar changed: %q err=%v", data, err)
	}
}
