package managed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

type localGCRootProviderFunc func(context.Context, LocalGCPublicationRootQuery) (LocalGCPublicationRootAttestation, error)

func (fn localGCRootProviderFunc) LocalGCPayloadRoots(ctx context.Context, query LocalGCPublicationRootQuery) (LocalGCPublicationRootAttestation, error) {
	return fn(ctx, query)
}

type localGCFixture struct {
	root       string
	options    WorkspaceOptions
	object     state.PackageObject
	generation state.GenerationID
}

func bindLocalGCPublicationTarget(t *testing.T, fixture localGCFixture) (state.PublicationTargetBinding, *state.Store) {
	t.Helper()
	ctx := context.Background()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{}
	cfg.Targets = map[string]config.TargetConfig{"local": {
		Repository: "repo", Provider: "filesystem", Endpoint: "file:///srv/sow/repo", Prefix: "mirror/repo",
		PublicEndpoint: "file:///srv/sow/repo/mirror/repo/", MaxCacheTTL: "0s",
		AuthoritativeWorkspace: true, SingleWriter: true, ExclusiveWriteAuthority: true,
	}}
	bindings, err := cfg.TargetBindings()
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenExisting(filepath.Join(fixture.root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	repository, err := store.RepositoryIdentity(ctx)
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	binding := state.PublicationTargetBinding{
		TargetIdentity: bindings[0].TargetIdentity, TargetStorageID: bindings[0].StorageIdentity, RepositoryID: repository.RepositoryID,
		TargetName: "local", Provider: "filesystem", Endpoint: bindings[0].Endpoint, Prefix: bindings[0].Prefix,
		PublicEndpoint: cfg.Targets["local"].PublicEndpoint, MaxCacheTTL: 0, AuthoritativeWorkspace: true, SingleWriter: true,
		ExclusiveWriteAuthority: true,
	}
	if err := store.BindPublicationTarget(ctx, binding); err != nil {
		store.Close()
		t.Fatal(err)
	}
	return binding, store
}

func newLocalGCFixture(t *testing.T, retain bool) localGCFixture {
	t.Helper()
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
	added, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1})
	if err != nil || len(added.Items) != 1 {
		t.Fatalf("add=%#v err=%v", added, err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	object, objectErr := store.GetPackageObject(ctx, added.Items[0].SHA256)
	summary, summaryErr := store.Summary(ctx)
	if err := errors.Join(objectErr, summaryErr, store.Close()); err != nil {
		t.Fatal(err)
	}
	if retain {
		if _, err := RetainAdd(ctx, RetainAddOptions{WorkspaceOptions: options, Repository: "repo", Generation: summary.BuiltGeneration}); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := Remove(ctx, RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Jobs: 1})
	if err != nil {
		t.Fatal(err)
	}
	store, err = state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, clearErr := store.DB().ExecContext(ctx, `DELETE FROM prior_built_memberships`)
	checkErr := store.Check(ctx)
	closeErr := store.Close()
	if err := errors.Join(clearErr, checkErr, closeErr); err != nil {
		t.Fatal(err)
	}
	return localGCFixture{root: root, options: options, object: object, generation: removed.Generation}
}

func TestLocalGCCollectsOnlyAfterEveryRootIsGone(t *testing.T) {
	ctx := context.Background()
	fixture := newLocalGCFixture(t, false)
	public := filepath.Join(fixture.root, "repo", filepath.FromSlash(fixture.object.PoolPath))
	if _, err := os.Stat(public); err != nil {
		t.Fatal(err)
	}
	result, err := LocalGC(ctx, LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"})
	wantGeneration, nextErr := fixture.generation.Next()
	if err != nil || nextErr != nil || result.Noop || result.Objects != 1 || result.Bytes != fixture.object.Size || result.Generation != wantGeneration {
		t.Fatalf("gc=%#v err=%v nextErr=%v", result, err, nextErr)
	}
	if _, err := os.Lstat(public); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("collected payload remains: %v", err)
	}
	store, err := state.OpenReadOnly(filepath.Join(fixture.root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, objectErr := store.GetPackageObject(ctx, fixture.object.SHA256)
	summary, summaryErr := store.Summary(ctx)
	checkErr := store.Check(ctx)
	closeErr := store.Close()
	if !errors.Is(objectErr, state.ErrNotFound) || errors.Join(summaryErr, checkErr, closeErr) != nil || summary.BuiltGeneration != wantGeneration {
		t.Fatalf("objectErr=%v summary=%#v summaryErr=%v checkErr=%v closeErr=%v", objectErr, summary, summaryErr, checkErr, closeErr)
	}
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: fixture.options, Repository: "repo", Jobs: 1})
	if err != nil || !checked.ReadyToCopy || checked.Generation != wantGeneration {
		t.Fatalf("check=%#v err=%v", checked, err)
	}
}

func TestLocalGCRetainedAndPublicationRootsFailClosed(t *testing.T) {
	t.Run("verified retained root protects payload", func(t *testing.T) {
		fixture := newLocalGCFixture(t, true)
		result, err := LocalGC(context.Background(), LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"})
		if err != nil || !result.Noop || result.Generation != fixture.generation {
			t.Fatalf("gc=%#v err=%v", result, err)
		}
		if _, err := os.Stat(filepath.Join(fixture.root, "repo", filepath.FromSlash(fixture.object.PoolPath))); err != nil {
			t.Fatalf("retained payload was removed: %v", err)
		}
	})

	t.Run("invalid retained evidence blocks before detach", func(t *testing.T) {
		fixture := newLocalGCFixture(t, false)
		foreign := filepath.Join(fixture.root, ".sow", "repo", "retained", "foreign")
		if err := os.Mkdir(foreign, 0o700); err != nil {
			t.Fatal(err)
		}
		_, err := LocalGC(context.Background(), LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"})
		if !errors.Is(err, ErrIntegrity) {
			t.Fatalf("invalid retained evidence error=%v", err)
		}
		if _, err := os.Stat(filepath.Join(fixture.root, "repo", filepath.FromSlash(fixture.object.PoolPath))); err != nil {
			t.Fatalf("payload changed on retained failure: %v", err)
		}
	})

	t.Run("unknown publication root blocks before detach", func(t *testing.T) {
		fixture := newLocalGCFixture(t, false)
		provider := localGCRootProviderFunc(func(_ context.Context, query LocalGCPublicationRootQuery) (LocalGCPublicationRootAttestation, error) {
			return LocalGCPublicationRootAttestation{EvidenceIdentity: query.EvidenceIdentity, Complete: true, Roots: []state.GenerationFile{{Path: "pool/foreign.rpm", Phase: "payload", Size: 1, SHA256: strings.Repeat("f", 64)}}}, nil
		})
		_, err := LocalGC(context.Background(), LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo", PublicationRoots: provider})
		if !errors.Is(err, ErrIntegrity) {
			t.Fatalf("unknown publication root error=%v", err)
		}
		if _, err := os.Stat(filepath.Join(fixture.root, "repo", filepath.FromSlash(fixture.object.PoolPath))); err != nil {
			t.Fatalf("payload changed on publication failure: %v", err)
		}
	})

	t.Run("foreign recovery evidence blocks before plan", func(t *testing.T) {
		fixture := newLocalGCFixture(t, false)
		foreign := filepath.Join(fixture.root, ".sow", "repo", "recovery", "foreign")
		if err := os.WriteFile(foreign, []byte("not operation-owned"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := LocalGC(context.Background(), LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"})
		if !errors.Is(err, ErrIntegrity) {
			t.Fatalf("foreign recovery evidence error=%v", err)
		}
		if body, err := os.ReadFile(foreign); err != nil || string(body) != "not operation-owned" {
			t.Fatalf("foreign recovery evidence changed: body=%q err=%v", body, err)
		}
		if _, err := os.Stat(filepath.Join(fixture.root, "repo", filepath.FromSlash(fixture.object.PoolPath))); err != nil {
			t.Fatalf("payload changed on recovery-root failure: %v", err)
		}
	})
}

func TestLocalGCUsesStateBackedPublicationAttestation(t *testing.T) {
	t.Run("binding-only evidence has an explicit empty state attestation", func(t *testing.T) {
		fixture := newLocalGCFixture(t, false)
		_, store := bindLocalGCPublicationTarget(t, fixture)
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		result, err := LocalGC(context.Background(), LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"})
		if err != nil || result.Noop || result.Objects != 1 {
			t.Fatalf("binding-only gc=%#v err=%v", result, err)
		}
	})

	t.Run("active attempt source Generation protects its payload", func(t *testing.T) {
		fixture := newLocalGCFixture(t, false)
		binding, store := bindLocalGCPublicationTarget(t, fixture)
		var sourceGeneration state.GenerationID
		if err := store.DB().QueryRow(`SELECT generation FROM generation_files WHERE path = ? AND phase = 'payload' ORDER BY generation LIMIT 1`, fixture.object.PoolPath).Scan(&sourceGeneration); err != nil {
			t.Fatal(err)
		}
		manifest, err := store.GenerationManifest(context.Background(), sourceGeneration)
		if err != nil {
			t.Fatal(err)
		}
		_, manifestSHA, err := state.ManifestBytes(manifest)
		if err != nil {
			t.Fatal(err)
		}
		attempt := state.PublicationAttempt{RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, TargetGeneration: sourceGeneration, ManifestSHA256: manifestSHA, PlanSHA256: strings.Repeat("b", 64), Phase: "planned", Views: []state.PublicationAttemptView{}}
		if err := store.PutPublicationAttempt(context.Background(), &attempt); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		result, err := LocalGC(context.Background(), LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"})
		if err != nil || !result.Noop {
			t.Fatalf("active-attempt gc=%#v err=%v", result, err)
		}
		if _, err := os.Stat(filepath.Join(fixture.root, "repo", filepath.FromSlash(fixture.object.PoolPath))); err != nil {
			t.Fatalf("active attempt payload removed: %v", err)
		}
	})

	t.Run("unresolved grace inventory protects payload outside source Generation", func(t *testing.T) {
		ctx := context.Background()
		fixture := newLocalGCFixture(t, false)
		binding, store := bindLocalGCPublicationTarget(t, fixture)
		var sourceGeneration state.GenerationID
		if err := store.DB().QueryRowContext(ctx, `SELECT g.generation
FROM generations AS g
WHERE NOT EXISTS (
  SELECT 1 FROM generation_files AS f
  WHERE f.generation = g.generation AND f.path = ?
)
ORDER BY g.generation
LIMIT 1`, fixture.object.PoolPath).Scan(&sourceGeneration); err != nil {
			t.Fatalf("find retained source Generation without payload: %v", err)
		}
		manifest, err := store.GenerationManifest(ctx, sourceGeneration)
		if err != nil {
			t.Fatal(err)
		}
		_, manifestSHA, err := state.ManifestBytes(manifest)
		if err != nil {
			t.Fatal(err)
		}
		attempt := state.PublicationAttempt{
			RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, TargetGeneration: sourceGeneration,
			ManifestSHA256: manifestSHA, PlanSHA256: strings.Repeat("c", 64), Phase: "planned", Views: []state.PublicationAttemptView{},
		}
		if err := store.PutPublicationAttempt(ctx, &attempt); err != nil {
			t.Fatal(err)
		}
		for _, phase := range []string{"payload", "immutable_metadata", "pointer_prepared"} {
			if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, phase); err != nil {
				t.Fatal(err)
			}
		}
		if err := store.SetPublicationCommitIntent(ctx, attempt.AttemptIdentity); err != nil {
			t.Fatal(err)
		}
		for _, phase := range []string{"pointer_rollforward", "verified"} {
			if err := store.AdvancePublicationAttemptPhase(ctx, attempt.AttemptIdentity, phase); err != nil {
				t.Fatal(err)
			}
		}
		inventory := make([]state.PublicationInventoryObject, 0, len(manifest)+1)
		for _, file := range manifest {
			inventory = append(inventory, state.PublicationInventoryObject{Path: file.Path, Phase: file.Phase, Size: file.Size, SHA256: file.SHA256, RemoteIdentity: "remote-current"})
		}
		inventory = append(inventory, state.PublicationInventoryObject{Path: fixture.object.PoolPath, Phase: "payload", Size: fixture.object.Size, SHA256: fixture.object.SHA256, RemoteIdentity: "remote-retained"})
		sort.Slice(inventory, func(i, j int) bool { return inventory[i].Path < inventory[j].Path })
		checkpoint := state.AppliedCheckpoint{
			RepositoryID: binding.RepositoryID, TargetIdentity: binding.TargetIdentity, AttemptIdentity: attempt.AttemptIdentity,
			Generation: sourceGeneration, ManifestSHA256: manifestSHA, InventoryComplete: true,
			Views: []state.PublicationCheckpointView{}, Inventory: inventory,
		}
		if err := store.PutAppliedCheckpoint(ctx, &checkpoint); err != nil {
			t.Fatal(err)
		}
		verified := time.Now().UTC()
		grace := state.GraceRecord{
			TargetIdentity: binding.TargetIdentity, CheckpointIdentity: checkpoint.CheckpointIdentity, VerifiedAt: verified,
			NotBefore: verified.Add(30 * 24 * time.Hour), CachePolicyIdentity: strings.Repeat("d", 64),
		}
		if err := store.PutGraceRecord(ctx, &grace); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		result, err := LocalGC(ctx, LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"})
		if err != nil || !result.Noop {
			t.Fatalf("grace-inventory gc=%#v err=%v", result, err)
		}
		if _, err := os.Stat(filepath.Join(fixture.root, "repo", filepath.FromSlash(fixture.object.PoolPath))); err != nil {
			t.Fatalf("unresolved grace inventory payload removed: %v", err)
		}
	})

	t.Run("incomplete state attestation fails closed", func(t *testing.T) {
		fixture := newLocalGCFixture(t, false)
		_, store := bindLocalGCPublicationTarget(t, fixture)
		if _, err := store.DB().Exec(`DELETE FROM publication_target_heads`); err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		_, err := LocalGC(context.Background(), LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"})
		if !errors.Is(err, ErrIntegrity) {
			t.Fatalf("incomplete publication state error=%v", err)
		}
		if _, statErr := os.Stat(filepath.Join(fixture.root, "repo", filepath.FromSlash(fixture.object.PoolPath))); statErr != nil {
			t.Fatalf("payload changed after incomplete attestation: %v", statErr)
		}
	})
}

func TestLocalGCCrashReplayBeforeAndAfterSQLiteCommit(t *testing.T) {
	for _, point := range []string{"gc.applied", "gc.committed", "gc.plan_unlinked"} {
		t.Run(point, func(t *testing.T) {
			ctx := context.Background()
			fixture := newLocalGCFixture(t, false)
			injected := errors.New("injected local GC crash")
			_, err := LocalGC(ctx, LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo", Fault: func(got string) error {
				if got == point {
					return injected
				}
				return nil
			}})
			if !errors.Is(err, injected) {
				t.Fatalf("fault=%v", err)
			}
			result, err := LocalGC(ctx, LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"})
			if err != nil || !result.Noop {
				t.Fatalf("replay=%#v err=%v", result, err)
			}
			if entries, err := os.ReadDir(filepath.Join(fixture.root, ".sow", "repo", "recovery")); err != nil || len(entries) != 0 {
				t.Fatalf("recovery remainder=%v err=%v", entries, err)
			}
			if _, err := os.Lstat(filepath.Join(fixture.root, "repo", filepath.FromSlash(fixture.object.PoolPath))); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("payload remains after replay: %v", err)
			}
			checked, err := Check(ctx, CheckOptions{WorkspaceOptions: fixture.options, Repository: "repo", Jobs: 1})
			if err != nil || !checked.ReadyToCopy {
				t.Fatalf("check=%#v err=%v", checked, err)
			}
		})
	}
}

func TestLocalGCDonePlanlessRecoveryRootFailsClosedWhenNonempty(t *testing.T) {
	ctx := context.Background()
	fixture := newLocalGCFixture(t, false)
	injected := errors.New("crash after local GC plan unlink")
	_, err := LocalGC(ctx, LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo", Fault: func(point string) error {
		if point == "gc.plan_unlinked" {
			return injected
		}
		return nil
	}})
	if !errors.Is(err, injected) {
		t.Fatalf("fault=%v", err)
	}
	recoveryEntries, err := os.ReadDir(filepath.Join(fixture.root, ".sow", "repo", "recovery"))
	if err != nil || len(recoveryEntries) != 1 {
		t.Fatalf("recovery entries=%v err=%v", recoveryEntries, err)
	}
	recoveryRoot := filepath.Join(fixture.root, ".sow", "repo", "recovery", recoveryEntries[0].Name())
	if entries, err := os.ReadDir(recoveryRoot); err != nil || len(entries) != 0 {
		t.Fatalf("planless recovery root is not initially empty: entries=%v err=%v", entries, err)
	}
	foreign := filepath.Join(recoveryRoot, "foreign")
	if err := os.WriteFile(foreign, []byte("not journal-owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LocalGC(ctx, LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"})
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("nonempty planless recovery root error=%v", err)
	}
	if body, err := os.ReadFile(foreign); err != nil || string(body) != "not journal-owned" {
		t.Fatalf("foreign remainder changed: body=%q err=%v", body, err)
	}
}
