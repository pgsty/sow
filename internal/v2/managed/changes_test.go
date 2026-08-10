package managed

import (
	"context"
	"errors"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

func TestChangesZeroExactlyMatchesPublicDeliveryTree(t *testing.T) {
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
	added, err := Add(ctx, AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1})
	if err != nil {
		t.Fatal(err)
	}
	zero := state.GenerationID(0)
	result, err := Changes(ctx, ChangesOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Base: &zero})
	if err != nil || result.Generation != added.Generation || result.Dirty {
		t.Fatalf("changes=%#v err=%v", result, err)
	}
	public, err := scanPublicManifest(ctx, filepath.Join(root, "repo"))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Changes) != len(public) {
		t.Fatalf("changes=%d public=%d", len(result.Changes), len(public))
	}
	byPath := map[string]struct {
		digest string
		size   int64
	}{}
	for _, file := range public {
		byPath[file.Path] = struct {
			digest string
			size   int64
		}{file.SHA256, file.Size}
	}
	for _, change := range result.Changes {
		want, ok := byPath[change.Path]
		if !ok || change.Operation != "add" || change.SHA256 != want.digest || change.Size != want.size || change.Phase == "delete" {
			t.Fatalf("change=%#v want=%#v", change, want)
		}
	}
	latest, err := Changes(ctx, ChangesOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo"})
	if err != nil || latest.Base >= latest.Generation || len(latest.Changes) == 0 {
		t.Fatalf("latest=%#v err=%v", latest, err)
	}
	updated, err := config.Load(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	dist := updated.Repositories["repo"].Dists["el9"]
	dist.Limit = 1
	repository := updated.Repositories["repo"]
	repository.Dists["el9"] = dist
	updated.Repositories["repo"] = repository
	writeManagedConfig(t, root, updated)
	dirty, err := Changes(ctx, ChangesOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Base: &zero})
	if err != nil || !dirty.Dirty || dirty.Generation != result.Generation || !reflect.DeepEqual(dirty.Changes, result.Changes) {
		t.Fatalf("config-dirty changes=%#v err=%v", dirty, err)
	}
	configData, err := os.ReadFile(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	journal := workspaceJournal{
		Version: workspaceJournalVersion, ID: "123", Kind: "repo.init", Repository: "repo",
		OldConfigSHA: bytesSHA(configData), OldConfig: configData,
		NewConfigSHA: bytesSHA(configData), NewConfig: configData, Phase: "applied",
	}
	if err := persistWorkspaceJournal(root, journal); err != nil {
		t.Fatal(err)
	}
	if _, err := Changes(ctx, ChangesOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Base: &zero}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("changes accepted pending workspace operation: %v", err)
	}
}

func TestChangesRejectsTamperedGenerationLedger(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, tamperErr := store.DB().ExecContext(ctx, `
UPDATE operation_files
SET sha256 = ?
WHERE operation_id = (SELECT operation_id FROM generations ORDER BY generation DESC LIMIT 1)
  AND sequence = (
    SELECT min(sequence) FROM operation_files
    WHERE operation_id = (SELECT operation_id FROM generations ORDER BY generation DESC LIMIT 1)
      AND action != 'delete'
  )`, strings.Repeat("0", 64))
	closeErr := store.Close()
	if err := errors.Join(tamperErr, closeErr); err != nil {
		t.Fatal(err)
	}
	zero := state.GenerationID(0)
	result, err := Changes(ctx, ChangesOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Base: &zero})
	if !errors.Is(err, ErrIntegrity) || len(result.Changes) != 0 {
		t.Fatalf("changes=%#v err=%v", result, err)
	}
}

func TestChangesRejectsPublicTreeDriftWithoutEmittingPlan(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(root, "repo", "pool", "orphan-public-file")
	if err := os.WriteFile(extra, []byte("not part of the retained Generation\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	zero := state.GenerationID(0)
	result, err := Changes(ctx, ChangesOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Base: &zero})
	if !errors.Is(err, ErrIntegrity) || len(result.Changes) != 0 {
		t.Fatalf("changes emitted a plan for drifted public tree: result=%#v err=%v", result, err)
	}
}

func TestChangesRejectsCheckObservedPublicModeErrorWithoutEmittingPlan(t *testing.T) {
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
	closeErr := store.Close()
	if err := errors.Join(err, closeErr); err != nil || len(objects) != 1 {
		t.Fatalf("objects=%#v err=%v", objects, err)
	}
	if err := os.Chmod(filepath.Join(root, "repo", filepath.FromSlash(objects[0].PoolPath)), 0o600); err != nil {
		t.Fatal(err)
	}
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if !errors.Is(err, ErrIntegrity) || checked.Status != "error" {
		t.Fatalf("bad-mode check=%#v err=%v", checked, err)
	}
	zero := state.GenerationID(0)
	result, err := Changes(ctx, ChangesOptions{WorkspaceOptions: options, Repository: "repo", Base: &zero})
	if !errors.Is(err, ErrIntegrity) || len(result.Changes) != 0 {
		t.Fatalf("changes emitted a plan for public-mode error: result=%#v err=%v", result, err)
	}
}

func TestChangesConsumerReconstructsExactTreeInPhaseOrder(t *testing.T) {
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
	added, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1})
	if err != nil {
		t.Fatal(err)
	}

	zero := state.GenerationID(0)
	first, err := Changes(ctx, ChangesOptions{WorkspaceOptions: options, Repository: "repo", Base: &zero})
	if err != nil || first.Generation != added.Generation || first.Dirty {
		t.Fatalf("changes 0=%#v err=%v", first, err)
	}
	consumer := filepath.Join(root, "external-consumer")
	seen := applyExternalChanges(t, filepath.Join(root, "repo"), consumer, first.Changes)
	assertExternalTreeMatches(t, ctx, filepath.Join(root, "repo"), consumer)

	removed, err := Remove(ctx, RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Jobs: 1})
	if err != nil || removed.Generation <= added.Generation || removed.Dirty {
		t.Fatalf("remove=%#v err=%v", removed, err)
	}
	second, err := Changes(ctx, ChangesOptions{WorkspaceOptions: options, Repository: "repo", Base: &added.Generation})
	if err != nil || second.Generation != removed.Generation || second.Dirty {
		t.Fatalf("incremental changes=%#v err=%v", second, err)
	}
	for phase := range applyExternalChanges(t, filepath.Join(root, "repo"), consumer, second.Changes) {
		seen[phase] = true
	}
	assertExternalTreeMatches(t, ctx, filepath.Join(root, "repo"), consumer)
	distRemoved, err := RemoveDistResult(ctx, DistRemoveOptions{WorkspaceOptions: options, Repository: "repo", Name: "el9"})
	if err != nil || !distRemoved.Removed || distRemoved.Noop {
		t.Fatalf("remove Dist=%#v err=%v", distRemoved, err)
	}
	third, err := Changes(ctx, ChangesOptions{WorkspaceOptions: options, Repository: "repo", Base: &second.Generation})
	if err != nil || third.Generation <= second.Generation || third.Dirty {
		t.Fatalf("Dist removal changes=%#v err=%v", third, err)
	}
	for phase := range applyExternalChanges(t, filepath.Join(root, "repo"), consumer, third.Changes) {
		seen[phase] = true
	}
	assertExternalTreeMatches(t, ctx, filepath.Join(root, "repo"), consumer)
	for _, phase := range []string{"payload", "metadata", "pointer", "delete"} {
		if !seen[phase] {
			t.Fatalf("external consumer did not execute %s phase; seen=%#v", phase, seen)
		}
	}
}

func applyExternalChanges(t *testing.T, sourceRoot, targetRoot string, changes []state.FileChange) map[string]bool {
	t.Helper()
	ranks := map[string]int{"payload": 0, "metadata": 1, "pointer": 2, "delete": 3}
	previousRank := -1
	seen := map[string]bool{}
	for _, change := range changes {
		rank, ok := ranks[change.Phase]
		if !ok || rank < previousRank {
			t.Fatalf("changes are not in executable phase order: %#v", changes)
		}
		previousRank = rank
		seen[change.Phase] = true
		if change.Path == "" || path.Clean(change.Path) != change.Path || strings.HasPrefix(change.Path, "/") || strings.HasPrefix(change.Path, "../") {
			t.Fatalf("unsafe handoff path: %q", change.Path)
		}
		target := filepath.Join(targetRoot, filepath.FromSlash(change.Path))
		if change.Operation == "delete" {
			if err := os.Remove(target); err != nil {
				t.Fatalf("apply delete %s: %v", change.Path, err)
			}
			continue
		}
		if change.Operation != "add" && change.Operation != "update" {
			t.Fatalf("unsupported handoff operation: %#v", change)
		}
		data, err := os.ReadFile(filepath.Join(sourceRoot, filepath.FromSlash(change.Path)))
		if err != nil || int64(len(data)) != change.Size || bytesSHA(data) != change.SHA256 {
			t.Fatalf("source identity differs for %s: size=%d sha=%s err=%v", change.Path, len(data), bytesSHA(data), err)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		temporary := target + ".handoff-tmp"
		if err := os.WriteFile(temporary, data, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(temporary, target); err != nil {
			t.Fatal(err)
		}
	}
	return seen
}

func assertExternalTreeMatches(t *testing.T, ctx context.Context, sourceRoot, targetRoot string) {
	t.Helper()
	source, err := scanPublicManifest(ctx, sourceRoot)
	if err != nil {
		t.Fatal(err)
	}
	target, err := scanPublicManifest(ctx, targetRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(source, target) {
		t.Fatalf("external consumer tree differs:\nsource=%#v\ntarget=%#v", source, target)
	}
}
