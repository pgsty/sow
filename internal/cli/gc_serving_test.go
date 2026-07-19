package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
)

type servingGCFixture struct {
	Root       string
	ConfigPath string
	Config     *config.Config
	Canonical  *state.Store
	Pool       *repository.Store
	Active     lifecycleGenerationFixture
	Retired    lifecycleGenerationFixture
	Targets    []serving.TargetIdentity
	Options    serving.InstallOptions
}

func setupServingGCFixture(t *testing.T) servingGCFixture {
	t.Helper()
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	active := makeLifecycleGeneration(t, root, pool, "active-serving", "8")
	retired := makeLifecycleGeneration(t, root, pool, "retired-serving", "9")
	targetA, err := serving.NewTargetIdentity("latest", ".", "https://repo.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	targetB, err := serving.NewTargetIdentity("latest", "exports/b", "https://b.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "exports", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	channelA, err := serving.NewChannelForTarget(active.Generation, targetA, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	channelB, err := serving.NewChannelForTarget(active.Generation, targetB, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	seedServingLifecycle(t, canonical, root, []serving.TargetIdentity{targetA, targetB}, []serving.Channel{channelA, channelB}, []lifecycleGenerationFixture{active, retired})
	tempDir := filepath.Join(root, ".sow", "tmp")
	if err := os.MkdirAll(tempDir, 0o700); err != nil {
		t.Fatal(err)
	}
	options := serving.InstallOptions{Workers: 2, ChunkEntries: 2, TempDir: tempDir}
	for _, targetRoot := range []string{root, filepath.Join(root, "exports", "b")} {
		for _, generation := range []lifecycleGenerationFixture{active, retired} {
			if _, err := serving.InstallGeneration(t.Context(), pool, targetRoot, generation.Generation, generation.Manifest, options); err != nil {
				t.Fatal(err)
			}
		}
	}
	expired, err := pruneCanonicalServingGenerationLedgers(t.Context(), canonical, nil)
	if err != nil || len(expired) != 1 || expired[0].Generation != retired.Generation {
		t.Fatalf("prune retired generation expired=%v err=%v", expired, err)
	}
	return servingGCFixture{
		Root: root, ConfigPath: configPath, Config: cfg, Canonical: canonical, Pool: pool,
		Active: active, Retired: retired, Targets: []serving.TargetIdentity{targetA, targetB}, Options: options,
	}
}

func gcDigest(t *testing.T, output, field string) string {
	t.Helper()
	match := regexp.MustCompile(regexp.QuoteMeta(field) + `=([0-9a-f]{64})`).FindStringSubmatch(output)
	if len(match) != 2 {
		t.Fatalf("missing %s in GC output: %s", field, output)
	}
	return match[1]
}

func runGCTestCLI(t *testing.T, arguments ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Main(arguments, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestServingGenerationGCRealCLIBindsCASDirectoriesAndTombstones(t *testing.T) {
	fixture := setupServingGCFixture(t)
	code, stdout, stderr := runGCTestCLI(t, "gc", "--config", fixture.ConfigPath, "--limit", "0", "--workers", "2", "--chunk-entries", "2")
	if code != ExitOK || !strings.Contains(stdout, "serving_generations_installed=4") || !strings.Contains(stdout, "serving_generation_orphans=2") || !strings.Contains(stdout, "serving_generation_tombstones=1") {
		t.Fatalf("initial GC dry run code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	oldPlan := gcDigest(t, stdout, "gc_set_sha256")
	if oldPlan == gcDigest(t, stdout, "orphan_set_sha256") {
		t.Fatal("serving candidates did not extend the CAS-only confirmation digest")
	}
	for _, targetRoot := range []string{fixture.Root, filepath.Join(fixture.Root, "exports", "b")} {
		if _, err := os.Stat(filepath.Join(targetRoot, "_sow", "v1", "g", fixture.Retired.Generation.ID)); err != nil {
			t.Fatalf("dry run removed retired directory below %s: %v", targetRoot, err)
		}
	}
	if reader, err := fixture.Canonical.OpenPath(serving.RetiredGenerationStatePath(fixture.Retired.Generation)); err != nil {
		t.Fatalf("dry run removed tombstone: %v", err)
	} else {
		_ = reader.Close()
	}

	drift, err := fixture.Pool.Put(t.Context(), strings.NewReader("post-confirmation-orphan"))
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runGCTestCLI(t, "gc", "--config", fixture.ConfigPath, "--apply", "--confirm", oldPlan, "--limit", "0", "--workers", "2", "--chunk-entries", "2")
	if code != ExitConflict || !strings.Contains(stderr, "confirmation differs") {
		t.Fatalf("stale GC confirmation code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, targetRoot := range []string{fixture.Root, filepath.Join(fixture.Root, "exports", "b")} {
		if _, err := os.Stat(filepath.Join(targetRoot, "_sow", "v1", "g", fixture.Retired.Generation.ID)); err != nil {
			t.Fatalf("stale confirmation removed retired directory below %s: %v", targetRoot, err)
		}
	}

	code, stdout, stderr = runGCTestCLI(t, "gc", "--config", fixture.ConfigPath, "--limit", "0", "--workers", "2", "--chunk-entries", "2")
	if code != ExitOK {
		t.Fatalf("refreshed GC dry run code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	freshPlan := gcDigest(t, stdout, "gc_set_sha256")
	if freshPlan == oldPlan {
		t.Fatal("CAS orphan drift did not change the combined confirmation")
	}
	code, stdout, stderr = runGCTestCLI(t, "gc", "--config", fixture.ConfigPath, "--apply", "--confirm", freshPlan, "--limit", "0", "--workers", "2", "--chunk-entries", "2")
	if code != ExitOK || !strings.Contains(stdout, "deleted=2") || !strings.Contains(stdout, "deleted_serving_generations=2") || !strings.Contains(stdout, "deleted_serving_tombstones=1") {
		t.Fatalf("confirmed GC apply code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, targetRoot := range []string{fixture.Root, filepath.Join(fixture.Root, "exports", "b")} {
		if _, err := os.Stat(filepath.Join(targetRoot, "_sow", "v1", "g", fixture.Retired.Generation.ID)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("retired directory remains below %s: %v", targetRoot, err)
		}
		if _, err := os.Stat(filepath.Join(targetRoot, "_sow", "v1", "g", fixture.Active.Generation.ID)); err != nil {
			t.Fatalf("shared retained directory was removed below %s: %v", targetRoot, err)
		}
	}
	if _, err := os.Stat(fixture.Pool.ObjectPath(fixture.Retired.Object.SHA256)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retired CAS object remains: %v", err)
	}
	if _, err := os.Stat(fixture.Pool.ObjectPath(drift.SHA256)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("drift CAS orphan remains: %v", err)
	}
	if _, err := os.Stat(fixture.Pool.ObjectPath(fixture.Active.Object.SHA256)); err != nil {
		t.Fatalf("reachable CAS object was removed: %v", err)
	}
	if reader, err := fixture.Canonical.OpenPath(serving.RetiredGenerationStatePath(fixture.Retired.Generation)); err == nil {
		_ = reader.Close()
		t.Fatal("retired tombstone remains after physical and CAS cleanup")
	}
}

func TestServingGenerationGCPartialDirectoryRetryRequiresFreshDigest(t *testing.T) {
	fixture := setupServingGCFixture(t)
	code, stdout, stderr := runGCTestCLI(t, "gc", "--config", fixture.ConfigPath, "--limit", "0", "--workers", "2", "--chunk-entries", "2")
	if code != ExitOK {
		t.Fatalf("initial dry run code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	stale := gcDigest(t, stdout, "gc_set_sha256")
	if err := serving.RemoveRetiredGeneration(t.Context(), fixture.Pool, fixture.Root, fixture.Retired.Generation, serving.RemoveGenerationOptions{InstallOptions: fixture.Options}); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runGCTestCLI(t, "gc", "--config", fixture.ConfigPath, "--apply", "--confirm", stale, "--limit", "0", "--workers", "2", "--chunk-entries", "2")
	if code != ExitConflict {
		t.Fatalf("partial-interruption stale apply code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr = runGCTestCLI(t, "gc", "--config", fixture.ConfigPath, "--limit", "0", "--workers", "2", "--chunk-entries", "2")
	if code != ExitOK || !strings.Contains(stdout, "serving_generation_orphans=1") {
		t.Fatalf("partial-interruption refresh code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	fresh := gcDigest(t, stdout, "gc_set_sha256")
	code, stdout, stderr = runGCTestCLI(t, "gc", "--config", fixture.ConfigPath, "--apply", "--confirm", fresh, "--limit", "0", "--workers", "2", "--chunk-entries", "2")
	if code != ExitOK || !strings.Contains(stdout, "deleted_serving_generations=1") || !strings.Contains(stdout, "deleted_serving_tombstones=1") {
		t.Fatalf("partial-interruption retry code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

func TestServingGenerationGCResumesStrictSubsetAndRejectsExtra(t *testing.T) {
	t.Run("strict-subset", func(t *testing.T) {
		fixture := setupServingGCFixture(t)
		generationRoot := filepath.Join(fixture.Root, "_sow", "v1", "g", fixture.Retired.Generation.ID)
		removed := false
		if err := filepath.WalkDir(generationRoot, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || removed || entry.IsDir() {
				return walkErr
			}
			removed = true
			return os.Remove(path)
		}); err != nil || !removed {
			t.Fatalf("remove one retired entry removed=%v err=%v", removed, err)
		}
		code, stdout, stderr := runGCTestCLI(t, "gc", "--config", fixture.ConfigPath, "--limit", "0", "--workers", "2", "--chunk-entries", "2")
		if code != ExitOK {
			t.Fatalf("strict-subset dry run code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		confirm := gcDigest(t, stdout, "gc_set_sha256")
		code, stdout, stderr = runGCTestCLI(t, "gc", "--config", fixture.ConfigPath, "--apply", "--confirm", confirm, "--limit", "0", "--workers", "2", "--chunk-entries", "2")
		if code != ExitOK || !strings.Contains(stdout, "deleted_serving_tombstones=1") {
			t.Fatalf("strict-subset apply code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
	})
	t.Run("extra-entry", func(t *testing.T) {
		fixture := setupServingGCFixture(t)
		generationRoot := filepath.Join(fixture.Root, "_sow", "v1", "g", fixture.Retired.Generation.ID)
		if err := os.WriteFile(filepath.Join(generationRoot, "foreign"), []byte("foreign"), 0o444); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := runGCTestCLI(t, "gc", "--config", fixture.ConfigPath, "--limit", "0", "--workers", "2", "--chunk-entries", "2")
		if code != ExitVerification || !strings.Contains(stderr, "extra path") {
			t.Fatalf("extra retired entry code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
	})
}

func TestRetiredGenerationDeletionBindsOpenedDirectoryAgainstSwap(t *testing.T) {
	fixture := setupServingGCFixture(t)
	generationRoot := filepath.Join(fixture.Root, "_sow", "v1", "g", fixture.Retired.Generation.ID)
	backup := generationRoot + "-moved"
	foreign := filepath.Join(generationRoot, "foreign")
	err := serving.RemoveRetiredGeneration(t.Context(), fixture.Pool, fixture.Root, fixture.Retired.Generation, serving.RemoveGenerationOptions{
		InstallOptions:       fixture.Options,
		ExpectedManifestPath: fixture.Retired.Manifest,
		AfterOpenBeforeRemove: func() error {
			if err := os.Rename(generationRoot, backup); err != nil {
				return err
			}
			if err := os.Mkdir(generationRoot, 0o755); err != nil {
				return err
			}
			return os.WriteFile(foreign, []byte("foreign"), 0o444)
		},
	})
	if err == nil || !strings.Contains(err.Error(), "changed during deletion") {
		t.Fatalf("directory swap was not rejected: %v", err)
	}
	if body, readErr := os.ReadFile(foreign); readErr != nil || string(body) != "foreign" {
		t.Fatalf("foreign replacement was deleted body=%q err=%v", body, readErr)
	}
}

func TestServingGenerationGCActivationJournalProtectsRetiredIdentity(t *testing.T) {
	fixture := setupServingGCFixture(t)
	channel, err := serving.NewChannelForTarget(fixture.Retired.Generation, fixture.Targets[0], nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	journal := localServingJournal{
		Schema: localServingJournalSchema, Phase: localServingGenerationReady, TargetRoot: ".",
		Generation: fixture.Retired.Generation, Channel: channel,
	}
	journal.ID = localServingJournalID(journal)
	if err := createLocalServingJournal(fixture.Config.StatePath(), journal); err != nil {
		t.Fatal(err)
	}
	plan, err := collectServingGenerationGCPlan(fixture.Config, fixture.Canonical, fixture.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if plan.hasServingCandidates() {
		t.Fatalf("in-flight activation was not a global keep root: %+v", plan)
	}
	if err := removeLocalServingJournal(fixture.Config.StatePath(), journal.ID); err != nil {
		t.Fatal(err)
	}
	plan, err = collectServingGenerationGCPlan(fixture.Config, fixture.Canonical, fixture.Pool)
	if err != nil || len(plan.Directories) != 2 || len(plan.Tombstones) != 1 {
		t.Fatalf("retired candidates after journal removal plan=%+v err=%v", plan, err)
	}
}

func TestServingGenerationGCFailsClosedOnReservedTreeAndMissingTarget(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, servingGCFixture)
		want   string
	}{
		{
			name: "malformed-reserved-coordinate",
			mutate: func(t *testing.T, fixture servingGCFixture) {
				t.Helper()
				if err := os.Mkdir(filepath.Join(fixture.Root, "_sow", "v1", "g", ".stage-not-owned"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			want: "unsafe installed generation entry",
		},
		{
			name: "symlink-generation-coordinate",
			mutate: func(t *testing.T, fixture servingGCFixture) {
				t.Helper()
				outside := t.TempDir()
				if err := os.Symlink(outside, filepath.Join(fixture.Root, "_sow", "v1", "g", strings.Repeat("7", 20))); err != nil {
					t.Fatal(err)
				}
			},
			want: "not a real directory",
		},
		{
			name: "special-generation-coordinate",
			mutate: func(t *testing.T, fixture servingGCFixture) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(fixture.Root, "_sow", "v1", "g", strings.Repeat("6", 20)), []byte("not-a-directory"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "not a real directory",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := setupServingGCFixture(t)
			test.mutate(t, fixture)
			code, stdout, stderr := runGCTestCLI(t, "gc", "--config", fixture.ConfigPath, "--limit", "0", "--workers", "2", "--chunk-entries", "2")
			if code != ExitVerification || !strings.Contains(stderr, test.want) {
				t.Fatalf("unsafe tree code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			if _, err := os.Stat(filepath.Join(fixture.Root, "_sow", "v1", "g", fixture.Retired.Generation.ID)); err != nil {
				t.Fatalf("failed dry run changed valid retired directory: %v", err)
			}
		})
	}
}

func TestServingGenerationGCMissingExportConvergesWithConfirmedTwoPhaseCleanup(t *testing.T) {
	fixture := setupServingGCFixture(t)
	missingRoot := filepath.Join(fixture.Root, "exports", "b")
	if err := os.RemoveAll(missingRoot); err != nil {
		t.Fatal(err)
	}
	for phase := 1; phase <= 2; phase++ {
		code, stdout, stderr := runGCTestCLI(t, "gc", "--config", fixture.ConfigPath, "--limit", "0", "--workers", "2", "--chunk-entries", "2")
		if code != ExitOK || !strings.Contains(stdout, "serving_target_orphans=1") {
			t.Fatalf("phase %d dry run code=%d stdout=%s stderr=%s", phase, code, stdout, stderr)
		}
		confirm := gcDigest(t, stdout, "gc_set_sha256")
		code, stdout, stderr = runGCTestCLI(t, "gc", "--config", fixture.ConfigPath, "--apply", "--confirm", confirm, "--limit", "0", "--workers", "2", "--chunk-entries", "2")
		if code != ExitOK {
			t.Fatalf("phase %d apply code=%d stdout=%s stderr=%s", phase, code, stdout, stderr)
		}
	}
	missingTarget := fixture.Targets[1]
	for _, canonicalPath := range []string{
		serving.TargetStatePath(missingTarget),
		serving.ChannelStatePath(serving.Channel{TargetID: missingTarget.ID, View: "latest", Repo: "repo", OS: "el10", Arch: "x86_64"}),
	} {
		if reader, err := fixture.Canonical.OpenPath(canonicalPath); err == nil {
			_ = reader.Close()
			t.Fatalf("missing export canonical path remains: %s", canonicalPath)
		}
	}
	if _, err := os.Stat(filepath.Join(fixture.Root, "_sow", "v1", "g", fixture.Active.Generation.ID)); err != nil {
		t.Fatalf("surviving target lost active generation: %v", err)
	}
}
