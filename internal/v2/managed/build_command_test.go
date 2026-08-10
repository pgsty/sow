package managed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

func TestAPTConfigOnlyBuildAdvancesGenerationWithinSameReleaseSecondAndRecovers(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	options := WorkspaceOptions{Workdir: root, CWD: root}
	configWithMarker := func(marker string) config.Config {
		cfg := config.Default()
		cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{
			"noble": {Format: "deb", Exclude: []config.ExcludeRule{{Name: []string{marker}}}},
		}}
		return cfg
	}
	readReleaseIdentity := func() (time.Time, state.GenerationID) {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(root, "repo", "dists", "noble", "Release"))
		if err != nil {
			t.Fatal(err)
		}
		at, err := parseReleaseDate(data)
		if err != nil {
			t.Fatal(err)
		}
		generation, present, err := parseReleaseGeneration(data)
		if err != nil || !present {
			t.Fatalf("Release generation=%d present=%t err=%v", generation, present, err)
		}
		return at, generation
	}

	writeManagedConfig(t, root, configWithMarker("never-match-one"))
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	initialTime, initialGeneration := readReleaseIdentity()
	if initialGeneration < 1 {
		t.Fatalf("initial generation=%d", initialGeneration)
	}

	writeManagedConfig(t, root, configWithMarker("never-match-two"))
	built, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if err != nil || built.Noop || built.Dirty || built.Generation != initialGeneration+1 {
		t.Fatalf("config-only build=%#v err=%v", built, err)
	}
	secondTime, secondGeneration := readReleaseIdentity()
	if !secondTime.Equal(initialTime) || secondGeneration != built.Generation {
		t.Fatalf("second Release time=%s generation=%d, want same time=%s generation=%d", secondTime, secondGeneration, initialTime, built.Generation)
	}
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if err != nil || checked.Status != "clean" || !checked.ReadyToCopy {
		t.Fatalf("post-build check=%#v err=%v", checked, err)
	}

	writeManagedConfig(t, root, configWithMarker("never-match-three"))
	injected := errors.New("injected after physical publication")
	_, err = Build(ctx, BuildOptions{
		WorkspaceOptions: options, Repository: "repo", Jobs: 1,
		Fault: func(point string) error {
			if point == "build.built" {
				return injected
			}
			return nil
		},
	})
	if !errors.Is(err, injected) {
		t.Fatalf("faulted config-only build error=%v", err)
	}
	faultedTime, faultedGeneration := readReleaseIdentity()
	if faultedGeneration != built.Generation+1 {
		t.Fatalf("faulted Release generation=%d, want %d", faultedGeneration, built.Generation+1)
	}
	recovering, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if !errors.Is(err, ErrNotReady) || recovering.Status != "recovering" || recovering.ReadyToCopy {
		t.Fatalf("recovering check=%#v err=%v", recovering, err)
	}
	for _, layer := range recovering.Layers {
		if !layer.OK {
			t.Fatalf("recoverable publication failed %s layer: %v", layer.Name, layer.Issues)
		}
	}
	recovered, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if err != nil || !recovered.Noop || recovered.Dirty || recovered.Generation != built.Generation+1 {
		t.Fatalf("recovered config-only build=%#v err=%v", recovered, err)
	}
	thirdTime, thirdGeneration := readReleaseIdentity()
	if !thirdTime.Equal(faultedTime) || thirdGeneration != recovered.Generation {
		t.Fatalf("recovered Release time=%s generation=%d, want staged time=%s generation=%d", thirdTime, thirdGeneration, faultedTime, recovered.Generation)
	}
	checked, err = Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if err != nil || checked.Status != "clean" || !checked.ReadyToCopy {
		t.Fatalf("post-recovery check=%#v err=%v", checked, err)
	}
}

func TestPopulatedAPTArchitectureAddBuildRetainsPriorByHashAndRecovers(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	options := WorkspaceOptions{Workdir: root, CWD: root}
	cfg := config.Default()
	cfg.Architectures = []string{"aarch64"}
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"noble": {Format: "deb"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	deb := decodeManagedFixture(t, filepath.Join("..", "..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"), filepath.Join(inputs, "libpqtypes0.deb"))
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"noble"}, Paths: []string{deb}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	priorRelease, err := os.ReadFile(filepath.Join(root, "repo", "dists", "noble", "Release"))
	if err != nil {
		t.Fatal(err)
	}
	priorChecksums, err := parseReleaseSHA256(priorRelease)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Architectures = []string{"x86_64", "aarch64"}
	writeManagedConfig(t, root, cfg)
	injected := errors.New("injected post-pointer architecture build failure")
	result, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1, Fault: func(point string) error {
		if point == "build.pointer.noble" {
			return injected
		}
		return nil
	}})
	if !errors.Is(err, injected) {
		t.Fatalf("faulted architecture build=%#v err=%v", result, err)
	}
	status, err := Status(ctx, StatusOptions{WorkspaceOptions: options, Repository: "repo"})
	if err != nil || status.Status != "recovering" && status.Status != "clean" || status.Status == "recovering" && status.ReadyToCopy {
		t.Fatalf("faulted architecture status=%#v err=%v", status, err)
	}
	recovered, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if err != nil || recovered.Generation == 0 {
		t.Fatalf("recover architecture build=%#v err=%v", recovered, err)
	}
	for relative, checksum := range priorChecksums {
		if !strings.HasPrefix(relative, "main/binary-arm64/Packages") {
			continue
		}
		retained := filepath.Join(root, "repo", "dists", "noble", filepath.Dir(relative), "by-hash", "SHA256", checksum.digest)
		if info, err := os.Stat(retained); err != nil || info.Size() != checksum.size {
			t.Fatalf("prior by-hash %q was not retained: info=%v err=%v", retained, info, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "repo", "dists", "noble", "main", "binary-amd64", "Packages.gz")); err != nil {
		t.Fatalf("new architecture view is absent: %v", err)
	}
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if err != nil || !checked.ReadyToCopy || checked.Status != "clean" {
		t.Fatalf("recovered architecture build is not deliverable: checked=%#v err=%v", checked, err)
	}
}

func TestBuildConvergesSkippedMutationAndNoopDoesNotAdvance(t *testing.T) {
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
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	publicBefore, err := publicTreeSnapshot(root, "repo")
	if err != nil {
		t.Fatal(err)
	}
	added, err := Add(ctx, AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Skip: true, Jobs: 1})
	if err != nil || !added.Dirty {
		t.Fatalf("add=%#v err=%v", added, err)
	}
	publicSkipped, _ := publicTreeSnapshot(root, "repo")
	if !reflect.DeepEqual(publicBefore, publicSkipped) {
		t.Fatal("add --skip changed public tree")
	}
	built, err := Build(ctx, BuildOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1})
	if err != nil || built.Noop || built.Dirty || built.Generation != added.Generation+1 {
		t.Fatalf("build=%#v err=%v", built, err)
	}
	publicBuilt, _ := publicTreeSnapshot(root, "repo")
	noop, err := Build(ctx, BuildOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1})
	if err != nil || !noop.Noop || noop.Generation != built.Generation || noop.Dirty {
		t.Fatalf("noop=%#v err=%v", noop, err)
	}
	publicNoop, _ := publicTreeSnapshot(root, "repo")
	if !reflect.DeepEqual(publicBuilt, publicNoop) {
		t.Fatal("no-op build changed public tree")
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	summary, err := store.Summary(ctx)
	if err != nil || summary.Status != "clean" || summary.BuiltGeneration != built.Generation {
		t.Fatalf("summary=%#v err=%v", summary, err)
	}
}

func TestNoopBuildJournalRepairsLegacyPublicModesAndRecoversMidTree(t *testing.T) {
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
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	added, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1})
	if err != nil {
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
	poolFile := filepath.Join(root, "repo", filepath.FromSlash(objects[0].PoolPath))
	repomd := filepath.Join(root, "repo", "dists", "el9", "x86_64", "repodata", "repomd.xml")
	for _, filename := range []string{poolFile, repomd} {
		if err := os.Chmod(filename, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1}); !errors.Is(err, ErrIntegrity) || checked.Status != "error" {
		t.Fatalf("bad-mode check=%#v err=%v", checked, err)
	}

	injected := errors.New("injected after one public mode repair")
	fired := false
	_, err = Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1, Fault: func(point string) error {
		if point == "build.mode" && !fired {
			fired = true
			return injected
		}
		return nil
	}})
	if !errors.Is(err, injected) || !fired {
		t.Fatalf("mid-mode build error=%v fired=%t", err, fired)
	}
	remainingBad := 0
	for _, filename := range []string{poolFile, repomd} {
		info, statErr := os.Stat(filename)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if info.Mode().Perm() != 0o644 {
			remainingBad++
		}
	}
	if remainingBad == 0 {
		t.Fatal("fault did not leave a partial public-mode repair")
	}

	recovered, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if err != nil || !recovered.Noop || recovered.Dirty || recovered.Generation != added.Generation {
		t.Fatalf("recovered mode build=%#v err=%v", recovered, err)
	}
	for _, filename := range []string{poolFile, repomd} {
		info, statErr := os.Stat(filename)
		if statErr != nil {
			t.Fatal(statErr)
		}
		if info.Mode().Perm() != 0o644 {
			t.Fatalf("recovered mode %s=%v", filename, info.Mode().Perm())
		}
	}
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if err != nil || checked.Status != "clean" || !checked.ReadyToCopy {
		t.Fatalf("post-mode-recovery check=%#v err=%v", checked, err)
	}
	store, err = state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var audited int
	if err := store.DB().QueryRowContext(ctx, `SELECT count(*) FROM operations WHERE coalesce(json_extract(result_json, '$.normalized_public_modes'), 0) > 0`).Scan(&audited); err != nil || audited == 0 {
		t.Fatalf("mode repair audit count=%d err=%v", audited, err)
	}
}

func TestBuildRejectsTamperedRPMWithRestoredMTimeBeforeCreatingOperation(t *testing.T) {
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
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	objects, err := store.ListPackageObjects(ctx, nil, false)
	if err != nil || len(objects) != 1 {
		t.Fatalf("objects=%#v err=%v", objects, err)
	}
	lastBefore, err := store.LastOperation(ctx)
	if err != nil || lastBefore == nil {
		t.Fatalf("last operation before tamper=%#v err=%v", lastBefore, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	pool := filepath.Join(root, "repo", filepath.FromSlash(objects[0].PoolPath))
	originalInfo, err := os.Stat(pool)
	if err != nil {
		t.Fatal(err)
	}
	// Ensure ctime advances independently of the restored mtime on ordinary
	// nanosecond-resolution filesystems.
	time.Sleep(2 * time.Millisecond)
	file, err := os.OpenFile(pool, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	last := []byte{0}
	if _, err := file.ReadAt(last, objects[0].Size-1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	last[0] ^= 0xff
	if _, err := file.WriteAt(last, objects[0].Size-1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(pool, originalInfo.ModTime(), originalInfo.ModTime()); err != nil {
		t.Fatal(err)
	}
	tamperedInfo, err := os.Stat(pool)
	if err != nil {
		t.Fatal(err)
	}
	if tamperedInfo.Size() != originalInfo.Size() || !tamperedInfo.ModTime().Equal(originalInfo.ModTime()) {
		t.Fatalf("tamper fixture did not preserve cheap stat fields: before=%#v after=%#v", originalInfo, tamperedInfo)
	}
	publicBefore, err := publicTreeSnapshot(root, "repo")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm", Limit: 1}}}
	writeManagedConfig(t, root, cfg)
	result, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if !errors.Is(err, ErrIntegrity) || result.Operation != "" {
		t.Fatalf("tampered build=%#v err=%v", result, err)
	}
	publicAfter, err := publicTreeSnapshot(root, "repo")
	if err != nil || !reflect.DeepEqual(publicBefore, publicAfter) {
		t.Fatalf("rejected build changed public tree: err=%v", err)
	}
	store, err = state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	lastAfter, err := store.LastOperation(ctx)
	if err != nil || lastAfter == nil || lastAfter.ID != lastBefore.ID {
		t.Fatalf("rejected build created an operation: before=%#v after=%#v err=%v", lastBefore, lastAfter, err)
	}
}

func TestDistMutationRejectsPublicGenerationDriftBeforeConfigOrOperation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	options := WorkspaceOptions{Workdir: root, CWD: root}
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	configBefore, err := os.ReadFile(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	lastBefore, err := store.LastOperation(ctx)
	closeErr := store.Close()
	if err := errors.Join(err, closeErr); err != nil || lastBefore == nil {
		t.Fatalf("last operation=%#v err=%v", lastBefore, err)
	}
	orphan := filepath.Join(root, "repo", "pool", "unexpected")
	if err := os.WriteFile(orphan, []byte("unexpected public drift\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: options, Repository: "repo", Name: "el10", Format: "rpm"})
	if !errors.Is(err, ErrIntegrity) || result.Name != "" {
		t.Fatalf("drifted Dist mutation=%#v err=%v", result, err)
	}
	configAfter, err := os.ReadFile(filepath.Join(root, config.ConfigFilename))
	if err != nil || !reflect.DeepEqual(configBefore, configAfter) {
		t.Fatalf("rejected Dist mutation changed config: err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "repo", "dists", "el10")); !os.IsNotExist(err) {
		t.Fatalf("rejected Dist mutation created public Dist: %v", err)
	}
	store, err = state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	lastAfter, err := store.LastOperation(ctx)
	if err != nil || lastAfter == nil || lastAfter.ID != lastBefore.ID {
		t.Fatalf("rejected Dist mutation created operation: before=%#v after=%#v err=%v", lastBefore, lastAfter, err)
	}
}

func TestSelectiveMutationAndBuildReportOtherDirtyDists(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{
		"el9": {Format: "rpm"}, "el10": {Format: "rpm"},
	}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	options := WorkspaceOptions{Workdir: root, CWD: root}
	if added, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Skip: true, Jobs: 1}); err != nil || !added.Dirty {
		t.Fatalf("skipped add=%#v err=%v", added, err)
	}
	added, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el10"}, Paths: []string{rpm}, Jobs: 1})
	if err != nil || !added.Dirty {
		t.Fatalf("selective default add=%#v err=%v", added, err)
	}
	noop, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el10"}, Jobs: 1})
	if err != nil || !noop.Noop || !noop.Dirty {
		t.Fatalf("selective noop build=%#v err=%v", noop, err)
	}
	status, err := Status(ctx, StatusOptions{WorkspaceOptions: options, Repository: "repo"})
	if err != nil || status.Status != "dirty" || !reflect.DeepEqual(status.DirtyDists, []string{"el9"}) {
		t.Fatalf("status=%#v err=%v", status, err)
	}
}

func TestPolicyReconcileToExistingBuiltProjectionIsCleanNoop(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	exclude := []config.ExcludeRule{{Name: []string{"pgdg-redhat-nonfree-repo"}}}
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm", Exclude: exclude}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	initial, err := Status(ctx, StatusOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo"})
	if err != nil || initial.Status != "clean" {
		t.Fatalf("initial status=%#v err=%v", initial, err)
	}
	withoutExclude := config.Default()
	withoutExclude.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, withoutExclude)
	inputs := filepath.Join(root, "inputs")
	if err := os.Mkdir(inputs, 0o755); err != nil {
		t.Fatal(err)
	}
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	options := WorkspaceOptions{Workdir: root, CWD: root}
	if added, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Skip: true, Jobs: 1}); err != nil || !added.Dirty {
		t.Fatalf("skipped add=%#v err=%v", added, err)
	}
	writeManagedConfig(t, root, cfg)
	built, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if err != nil || !built.Noop || built.Dirty || built.Generation != initial.BuiltGeneration {
		t.Fatalf("policy reconcile build=%#v err=%v", built, err)
	}
	status, err := Status(ctx, StatusOptions{WorkspaceOptions: options, Repository: "repo"})
	if err != nil || status.Status != "clean" || !status.ReadyToCopy || status.Pending.Count != 0 {
		t.Fatalf("reconciled status=%#v err=%v", status, err)
	}
}

func TestNextWriteBootstrapsMigratedGenerationLedger(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	before, err := publicTreeSnapshot(root, "repo")
	if err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(root, ".sow", "repo.db")
	store, err := state.OpenExisting(database)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := store.Summary(ctx)
	if err != nil || summary.BuiltGeneration < 1 {
		store.Close()
		t.Fatalf("summary=%#v err=%v", summary, err)
	}
	_, deleteErr := store.DB().ExecContext(ctx, `DELETE FROM generations`)
	closeErr := store.Close()
	if err := errors.Join(deleteErr, closeErr); err != nil {
		t.Fatal(err)
	}

	status, err := Status(ctx, StatusOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo"})
	if err != nil || status.Status != "dirty" || status.ReadyToCopy {
		t.Fatalf("pre-bootstrap status=%#v err=%v", status, err)
	}
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1})
	if !errors.Is(err, ErrNotReady) || checked.Status != "dirty" || checked.ReadyToCopy {
		t.Fatalf("pre-bootstrap check=%#v err=%v", checked, err)
	}
	built, err := Build(ctx, BuildOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1})
	if err != nil || !built.Noop || built.Dirty || built.Generation != summary.BuiltGeneration {
		t.Fatalf("bootstrap build=%#v err=%v", built, err)
	}
	after, err := publicTreeSnapshot(root, "repo")
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("bootstrap changed public tree: err=%v", err)
	}
	zero := state.GenerationID(0)
	changes, err := Changes(ctx, ChangesOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Base: &zero})
	if err != nil || changes.Dirty || changes.Generation != summary.BuiltGeneration || len(changes.Changes) != len(after) {
		t.Fatalf("bootstrapped changes=%#v err=%v", changes, err)
	}
	checked, err = Check(ctx, CheckOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1})
	if err != nil || checked.Status != "clean" || !checked.ReadyToCopy {
		t.Fatalf("post-bootstrap check=%#v err=%v", checked, err)
	}
	logged, err := Log(ctx, LogOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo"})
	if err != nil {
		t.Fatal(err)
	}
	foundBootstrap := false
	for _, operation := range logged.Operations {
		if operation.Kind == "generation.bootstrap" {
			foundBootstrap = true
			break
		}
	}
	if !foundBootstrap {
		t.Fatalf("bootstrap audit operation missing: %#v", logged.Operations)
	}
}

func TestBuildRetryDiscardsIncompleteDerivedStage(t *testing.T) {
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
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	options := WorkspaceOptions{Workdir: root, CWD: root}
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Skip: true, Jobs: 1}); err != nil {
		t.Fatal(err)
	}

	injected := errors.New("injected render failure")
	_, err := Build(ctx, BuildOptions{
		WorkspaceOptions: options,
		Repository:       "repo",
		Jobs:             1,
		Fault: func(point string) error {
			if point == "build.rendered.el9" {
				return injected
			}
			return nil
		},
	})
	if !errors.Is(err, injected) {
		t.Fatalf("first build error=%v, want injected failure", err)
	}

	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	operation, operationErr := store.LastOperation(ctx)
	closeErr := store.Close()
	if err := errors.Join(operationErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if operation == nil || operation.State != state.OperationApplied {
		t.Fatalf("operation=%#v, want applied operation", operation)
	}
	buildRoot := filepath.Join(mutationStageRoot(root, "repo", operation.ID), "build")
	if _, err := os.Stat(filepath.Join(buildRoot, "dists", "el9")); err != nil {
		t.Fatalf("partial rendered Dist is missing: %v", err)
	}
	marker := filepath.Join(buildRoot, "stale-marker")
	if err := os.WriteFile(marker, []byte("must be discarded\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	built, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if err != nil || built.Dirty || built.Generation < 1 {
		t.Fatalf("retry build=%#v err=%v", built, err)
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("incomplete derived stage survived retry: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(root, ".sow", "repo", "stage"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("operation stage not cleaned: entries=%v err=%v", entries, err)
	}
}

func TestBuildOrdinaryPreApplyFailureIsTerminalAndRetryable(t *testing.T) {
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
	input := decodeManagedFixture(t, filepath.Join("..", "..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	options := WorkspaceOptions{Workdir: root, CWD: root}
	added, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{input}, Skip: true, Jobs: 1})
	if err != nil || !added.Dirty {
		t.Fatalf("prepare dirty repository=%#v err=%v", added, err)
	}
	result, err := Build(ctx, BuildOptions{
		WorkspaceOptions: options, Repository: "repo", Jobs: 1,
		Fault: func(point string) error {
			if point != "build.command.planned" {
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
			if len(pending) != 1 || pending[0].Kind != "build" {
				return errors.New("build operation was not pending")
			}
			return os.Mkdir(mutationStageRoot(root, "repo", pending[0].ID), 0o700)
		},
	})
	if err == nil || result.Operation == "" {
		t.Fatalf("occupied build stage result=%#v err=%v", result, err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	detail, detailErr := store.GetOperation(ctx, result.Operation)
	objects, objectsErr := store.ListPackageObjects(ctx, []string{"el9"}, false)
	closeErr := store.Close()
	if err := errors.Join(detailErr, objectsErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if detail.Operation.State != state.OperationFailed || detail.Operation.ErrorClass != "runtime" || len(objects) != 1 || objects[0].Storage != "pending" {
		t.Fatalf("failed build detail=%#v objects=%#v", detail.Operation, objects)
	}
	if _, err := os.Lstat(mutationStageRoot(root, "repo", result.Operation)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed build retained stage: %v", err)
	}
	built, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if err != nil || built.Dirty || built.Noop || built.Generation <= added.Generation {
		t.Fatalf("retry build=%#v err=%v", built, err)
	}
}
