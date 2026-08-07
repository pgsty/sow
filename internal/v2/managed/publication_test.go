package managed

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

func filesystemPublishFixture(t *testing.T) (localGCFixture, string, string) {
	t.Helper()
	fixture := newLocalGCFixture(t, false)
	endpoint, err := realDirectory(t.TempDir(), false, 0)
	if err != nil {
		t.Fatal(err)
	}
	prefix := "mirror/repo"
	endpointURL := (&url.URL{Scheme: "file", Path: endpoint}).String()
	publicURL := (&url.URL{Scheme: "file", Path: filepath.Join(endpoint, filepath.FromSlash(prefix)) + string(filepath.Separator)}).String()
	cfg, err := config.Load(filepath.Join(fixture.root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Targets = map[string]config.TargetConfig{"local": {
		Repository: "repo", Provider: "filesystem", Endpoint: endpointURL, Prefix: prefix,
		PublicEndpoint: publicURL, MaxCacheTTL: "0s",
		AuthoritativeWorkspace: true, SingleWriter: true, ExclusiveWriteAuthority: true,
	}}
	writeManagedConfig(t, fixture.root, cfg)
	return fixture, endpoint, filepath.Join(endpoint, filepath.FromSlash(prefix))
}

func TestFilesystemPublicationInitialPublishNoopAndCrashRollForward(t *testing.T) {
	ctx := context.Background()
	fixture, _, targetRoot := filesystemPublishFixture(t)
	faulted := false
	first, err := Publish(ctx, PublishOptions{
		WorkspaceOptions: fixture.options, Target: "local",
		Fault: func(point string) error {
			if !faulted && strings.HasPrefix(point, "publish.pointer.written.") {
				faulted = true
				return errors.New("crash after public pointer write")
			}
			return nil
		},
	})
	if err == nil || !faulted || first.Target != "local" || first.Repository != "repo" {
		t.Fatalf("faulted publish=%#v err=%v faulted=%t", first, err, faulted)
	}
	resumed, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local"})
	if err != nil || resumed.Phase != "grace" || resumed.Checkpoint == "" || resumed.Attempt == "" || resumed.Noop {
		t.Fatalf("resumed publish=%#v err=%v", resumed, err)
	}
	store, err := state.OpenReadOnly(filepath.Join(fixture.root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, manifestErr := store.GenerationManifest(ctx, resumed.Generation)
	closeErr := store.Close()
	if err := errors.Join(manifestErr, closeErr); err != nil {
		t.Fatal(err)
	}
	physical, err := scanPublicManifest(ctx, targetRoot)
	if err != nil || !sameGenerationManifest(manifest, physical) {
		t.Fatalf("published manifest differs err=%v\nwant=%#v\ngot=%#v", err, manifest, physical)
	}
	noop, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local"})
	if err != nil || !noop.Noop || noop.Checkpoint != resumed.Checkpoint || noop.Generation != resumed.Generation {
		t.Fatalf("noop publish=%#v err=%v", noop, err)
	}
	if err := walkRootedTree(ctx, targetRoot, func(relative string, _ *os.File, _ os.FileInfo) error {
		if strings.Contains(relative, ".sow-publish-") {
			t.Fatalf("publication stage leaked into settled prefix: %s", relative)
		}
		return nil
	}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestFilesystemPublicationRejectsNonemptyUnownedPrefix(t *testing.T) {
	ctx := context.Background()
	fixture, _, targetRoot := filesystemPublishFixture(t)
	if err := os.MkdirAll(filepath.Join(targetRoot, "pool", "foreign"), 0o755); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(targetRoot, "pool", "foreign", "object.rpm")
	if err := os.WriteFile(foreign, []byte("foreign"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local"})
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("nonempty unowned prefix error=%v", err)
	}
	if body, readErr := os.ReadFile(foreign); readErr != nil || string(body) != "foreign" {
		t.Fatalf("foreign object changed body=%q err=%v", body, readErr)
	}
}

func TestFilesystemPublicationPreCommitAbandonUnfreezesMutationAndReusesOrphans(t *testing.T) {
	ctx := context.Background()
	fixture, _, _ := filesystemPublishFixture(t)
	faulted := false
	stopped, err := Publish(ctx, PublishOptions{
		WorkspaceOptions: fixture.options, Target: "local",
		Fault: func(point string) error {
			if point == "publish.payload" {
				faulted = true
				return errors.New("stop after create-only payload")
			}
			return nil
		},
	})
	if err == nil || !faulted || stopped.Attempt == "" {
		t.Fatalf("stopped=%#v err=%v faulted=%t", stopped, err, faulted)
	}
	abandoned, err := AbandonPublication(ctx, PublicationAbandonOptions{WorkspaceOptions: fixture.options, Target: "local"})
	if err != nil || abandoned.Attempt != stopped.Attempt || abandoned.Phase != "abandoned" || abandoned.Objects == 0 {
		t.Fatalf("abandoned=%#v err=%v", abandoned, err)
	}
	removed, err := RemoveDistResult(ctx, DistRemoveOptions{WorkspaceOptions: fixture.options, Repository: "repo", Name: "el9", Force: true})
	if err != nil || !removed.Removed {
		t.Fatalf("post-abandon mutation=%#v err=%v", removed, err)
	}
	resumed, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local"})
	if err != nil || resumed.Checkpoint == "" {
		t.Fatalf("publish over exact abandoned inventory=%#v err=%v", resumed, err)
	}
}

func TestConfiguredPublishedTargetRejectsPointerWithdrawalBeforeMutation(t *testing.T) {
	ctx := context.Background()
	t.Run("dist removal", func(t *testing.T) {
		fixture, _, _ := filesystemPublishFixture(t)
		if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local"}); err != nil {
			t.Fatal(err)
		}
		if _, err := RemoveDistResult(ctx, DistRemoveOptions{WorkspaceOptions: fixture.options, Repository: "repo", Name: "el9", Force: true}); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "withdraw published pointer") {
			t.Fatalf("dist removal error=%v", err)
		}
		cfg, err := config.Load(filepath.Join(fixture.root, config.ConfigFilename))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := cfg.Repositories["repo"].Dists["el9"]; !ok {
			t.Fatal("rejected removal changed sow.yml")
		}
	})
	t.Run("signing companion removal", func(t *testing.T) {
		root, options, _, _ := prepareRPMLeafExportFixture(t, true)
		endpoint, err := realDirectory(t.TempDir(), false, 0)
		if err != nil {
			t.Fatal(err)
		}
		prefix := "mirror/repo"
		cfg, err := config.Load(filepath.Join(root, config.ConfigFilename))
		if err != nil {
			t.Fatal(err)
		}
		cfg.Targets = map[string]config.TargetConfig{"local": {
			Repository: "repo", Provider: "filesystem", Endpoint: (&url.URL{Scheme: "file", Path: endpoint}).String(), Prefix: prefix,
			PublicEndpoint: (&url.URL{Scheme: "file", Path: filepath.Join(endpoint, filepath.FromSlash(prefix)) + string(filepath.Separator)}).String(), MaxCacheTTL: "0s",
			AuthoritativeWorkspace: true, SingleWriter: true, ExclusiveWriteAuthority: true,
		}}
		writeManagedConfig(t, root, cfg)
		first, err := Publish(ctx, PublishOptions{WorkspaceOptions: options, Target: "local"})
		if err != nil {
			t.Fatal(err)
		}
		cfg, err = config.Load(filepath.Join(root, config.ConfigFilename))
		if err != nil {
			t.Fatal(err)
		}
		repository := cfg.Repositories["repo"]
		repository.Signing.RPM.Metadata.Key = ""
		cfg.Repositories["repo"] = repository
		writeManagedConfig(t, root, cfg)
		if _, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1}); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "withdraw published pointer") {
			t.Fatalf("signing companion removal error=%v", err)
		}
		store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
		if err != nil {
			t.Fatal(err)
		}
		summary, summaryErr := store.Summary(ctx)
		pending, pendingErr := store.PendingOperations(ctx)
		closeErr := store.Close()
		if err := errors.Join(summaryErr, pendingErr, closeErr); err != nil || summary.BuiltGeneration != first.Generation || len(pending) != 0 {
			t.Fatalf("rejected signing change state summary=%#v pending=%#v err=%v", summary, pending, err)
		}
	})
}

func TestFilesystemTargetGCEvidenceDeletionCrashReplayAndLiveInventory(t *testing.T) {
	ctx := context.Background()
	fixture, _, targetRoot := filesystemPublishFixture(t)
	first, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local"})
	if err != nil {
		t.Fatal(err)
	}
	future := func() time.Time { return time.Now().UTC().Add(31 * 24 * time.Hour) }
	settled, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "local", now: future})
	if err != nil || settled.CompletedAttempts != 1 || settled.Candidates != 0 {
		t.Fatalf("settle first target grace=%#v err=%v", settled, err)
	}
	collected, err := LocalGC(ctx, LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"})
	if err != nil || collected.Noop || collected.Objects != 1 {
		t.Fatalf("local gc after remote checkpoint=%#v err=%v", collected, err)
	}
	second, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local"})
	if err != nil || second.Generation == first.Generation || second.Checkpoint == first.Checkpoint {
		t.Fatalf("second publish=%#v first=%#v err=%v", second, first, err)
	}
	stalePayload := filepath.Join(targetRoot, filepath.FromSlash(fixture.object.PoolPath))
	if _, err := os.Stat(stalePayload); err != nil {
		t.Fatalf("old payload disappeared before target grace: %v", err)
	}
	pending, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "local"})
	if err != nil || !pending.Noop || pending.PendingGrace == 0 {
		t.Fatalf("premature target gc=%#v err=%v", pending, err)
	}
	faulted := false
	_, err = TargetGC(ctx, TargetGCOptions{
		WorkspaceOptions: fixture.options, Target: "local", now: future,
		Fault: func(point string) error {
			if !faulted && strings.HasPrefix(point, "target_gc.deleted.") {
				faulted = true
				return errors.New("crash after conditional unlink")
			}
			return nil
		},
	})
	if err == nil || !faulted {
		t.Fatalf("target GC did not stop at post-delete seam: %v", err)
	}
	if _, err := os.Lstat(stalePayload); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("conditionally deleted payload remains: %v", err)
	}
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local"}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("publish crossed an unfinished deletion report: %v", err)
	}
	resumed, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "local", now: future})
	if err != nil || resumed.DeletedObjects != 1 || resumed.CompletedAttempts != 1 {
		t.Fatalf("resumed target gc=%#v err=%v", resumed, err)
	}
	store, err := state.OpenExisting(filepath.Join(fixture.root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	live, liveErr := store.PublicationLiveInventory(ctx, second.Checkpoint)
	checkErr := store.Check(ctx)
	closeErr := store.Close()
	if err := errors.Join(liveErr, checkErr, closeErr); err != nil {
		t.Fatal(err)
	}
	for _, object := range live {
		if object.Path == fixture.object.PoolPath {
			t.Fatalf("terminal deletion receipt did not project out %q", object.Path)
		}
	}
	noop, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local"})
	if err != nil || !noop.Noop || noop.Checkpoint != second.Checkpoint {
		t.Fatalf("post-deletion noop publish=%#v err=%v", noop, err)
	}
}

func TestPublicationAttemptsAndCheckpointsAreTargetScoped(t *testing.T) {
	ctx := context.Background()
	fixture := newLocalGCFixture(t, false)
	cfg, err := config.Load(filepath.Join(fixture.root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	makeTarget := func(name string) (config.TargetConfig, string) {
		t.Helper()
		endpoint, err := realDirectory(t.TempDir(), false, 0)
		if err != nil {
			t.Fatal(err)
		}
		prefix := "mirror/" + name
		endpointURL := (&url.URL{Scheme: "file", Path: endpoint}).String()
		publicURL := (&url.URL{Scheme: "file", Path: filepath.Join(endpoint, filepath.FromSlash(prefix)) + string(filepath.Separator)}).String()
		return config.TargetConfig{
			Repository: "repo", Provider: "filesystem", Endpoint: endpointURL, Prefix: prefix,
			PublicEndpoint: publicURL, MaxCacheTTL: "0s", AuthoritativeWorkspace: true,
			SingleWriter: true, ExclusiveWriteAuthority: true,
		}, filepath.Join(endpoint, filepath.FromSlash(prefix))
	}
	alpha, alphaRoot := makeTarget("alpha")
	beta, betaRoot := makeTarget("beta")
	cfg.Targets = map[string]config.TargetConfig{"alpha": alpha, "beta": beta}
	writeManagedConfig(t, fixture.root, cfg)
	faulted := false
	alphaFault, err := Publish(ctx, PublishOptions{
		WorkspaceOptions: fixture.options, Target: "alpha",
		Fault: func(point string) error {
			if point == "publish.attempt" {
				faulted = true
				return errors.New("stop alpha after durable attempt")
			}
			return nil
		},
	})
	if err == nil || !faulted || alphaFault.Attempt == "" {
		t.Fatalf("alpha fault=%#v err=%v faulted=%t", alphaFault, err, faulted)
	}
	betaResult, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "beta"})
	if err != nil || betaResult.Checkpoint == "" {
		t.Fatalf("beta publish=%#v err=%v", betaResult, err)
	}
	alphaResult, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "alpha"})
	if err != nil || alphaResult.Checkpoint == "" || alphaResult.Checkpoint == betaResult.Checkpoint || alphaResult.Attempt != alphaFault.Attempt {
		t.Fatalf("alpha resume=%#v beta=%#v fault=%#v err=%v", alphaResult, betaResult, alphaFault, err)
	}
	alphaManifest, err := scanPublicManifest(ctx, alphaRoot)
	if err != nil {
		t.Fatal(err)
	}
	betaManifest, err := scanPublicManifest(ctx, betaRoot)
	if err != nil || !sameGenerationManifest(alphaManifest, betaManifest) {
		t.Fatalf("target manifests differ: alpha=%#v beta=%#v err=%v", alphaManifest, betaManifest, err)
	}
}
