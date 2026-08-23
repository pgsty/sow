package managed

import (
	"bytes"
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

func TestPublicationGraceMinimumRejectsOverflow(t *testing.T) {
	const padding = 24 * time.Hour
	maximum := time.Duration(1<<63-1) - padding
	if minimum, err := publicationGraceMinimum(maximum); err != nil || minimum != time.Duration(1<<63-1) {
		t.Fatalf("boundary grace minimum=%s err=%v", minimum, err)
	}
	if _, err := publicationGraceMinimum(maximum + time.Nanosecond); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("overflowing grace error=%v", err)
	}
}

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

func TestPublicationBackendPreflightFailureLeavesNoBindingOrFilesystemPrefix(t *testing.T) {
	ctx := context.Background()
	fixture, _, targetRoot := filesystemPublishFixture(t)
	cfg, err := config.Load(filepath.Join(fixture.root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	wrongPublicRoot := t.TempDir()
	target := cfg.Targets["local"]
	target.PublicEndpoint = (&url.URL{Scheme: "file", Path: filepath.Join(wrongPublicRoot, "different") + string(filepath.Separator)}).String()
	cfg.Targets["local"] = target
	writeManagedConfig(t, fixture.root, cfg)
	if _, err := os.Lstat(targetRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("target prefix existed before preflight: %v", err)
	}
	_, err = Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local"})
	if err == nil {
		t.Fatal("publish accepted mismatched file public endpoint")
	}
	if _, statErr := os.Lstat(targetRoot); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed preflight created target prefix: %v", statErr)
	}
	store, openErr := state.OpenReadOnly(filepath.Join(fixture.root, ".sow", "repo.db"))
	if openErr != nil {
		t.Fatal(openErr)
	}
	var bindings int
	queryErr := store.DB().QueryRowContext(ctx, `SELECT count(*) FROM publication_target_bindings`).Scan(&bindings)
	closeErr := store.Close()
	if err := errors.Join(queryErr, closeErr); err != nil || bindings != 0 {
		t.Fatalf("failed preflight bindings=%d err=%v", bindings, err)
	}
}

func TestFilesystemPublicationPreflightDetectsProspectiveCaseAliasBeforeBind(t *testing.T) {
	ctx := context.Background()
	fixture, endpoint, _ := filesystemPublishFixture(t)
	cfg, err := config.Load(filepath.Join(fixture.root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	baseURL := (&url.URL{Scheme: "file", Path: endpoint}).String()
	common := config.TargetConfig{
		Repository: "repo", Provider: "filesystem", Endpoint: baseURL, PublicEndpoint: "https://cdn.example.test/repo/", MaxCacheTTL: "0s",
		AuthoritativeWorkspace: true, SingleWriter: true, ExclusiveWriteAuthority: true,
	}
	upper, lower := common, common
	upper.Prefix, upper.PublicEndpoint = "Stable/repo", "https://upper.example.test/repo/"
	lower.Prefix, lower.PublicEndpoint = "stable/repo", "https://lower.example.test/repo/"
	cfg.Targets = map[string]config.TargetConfig{"upper": upper, "lower": lower}
	writeManagedConfig(t, fixture.root, cfg)
	caseInsensitive, err := filesystemDirectoryIsCaseInsensitive(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	preflightErr := preflightFilesystemTargetAliases(cfg, "upper")
	if !caseInsensitive {
		if preflightErr != nil {
			t.Fatalf("case-sensitive filesystem globally lowercased targets: %v", preflightErr)
		}
		return
	}
	if !errors.Is(preflightErr, ErrRejected) || !strings.Contains(preflightErr.Error(), "case alias") {
		t.Fatalf("case-insensitive alias preflight error=%v", preflightErr)
	}
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "upper"}); !errors.Is(err, ErrRejected) {
		t.Fatalf("case alias publish error=%v", err)
	}
	store, err := state.OpenReadOnly(filepath.Join(fixture.root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	var count int
	queryErr := store.DB().QueryRowContext(ctx, `SELECT count(*) FROM publication_target_bindings`).Scan(&count)
	closeErr := store.Close()
	if err := errors.Join(queryErr, closeErr); err != nil || count != 0 {
		t.Fatalf("case alias left binding count=%d err=%v", count, err)
	}
	for _, path := range []string{filepath.Join(endpoint, "Stable"), filepath.Join(endpoint, "stable")} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("case alias preflight created %s: %v", path, err)
		}
	}
}

func TestPublicationOperatorRebindRollsForwardCommitIntentAndRejectsStorageChange(t *testing.T) {
	ctx := context.Background()
	fixture, _, _ := filesystemPublishFixture(t)
	cfg, err := config.Load(filepath.Join(fixture.root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	correctPublicEndpoint := cfg.Targets["local"].PublicEndpoint
	target := cfg.Targets["local"]
	target.PublicEndpoint = "https://wrong.example.test/repo/"
	cfg.Targets["local"] = target
	writeManagedConfig(t, fixture.root, cfg)
	injected := errors.New("stop at commit intent")
	stopped, err := Publish(ctx, PublishOptions{
		WorkspaceOptions: fixture.options, Target: "local",
		Fault: func(point string) error {
			if point == "publish.commit_intent" {
				return injected
			}
			return nil
		},
	})
	if !errors.Is(err, injected) || stopped.Attempt == "" {
		t.Fatalf("stopped publication=%#v err=%v", stopped, err)
	}

	cfg, err = config.Load(filepath.Join(fixture.root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	target = cfg.Targets["local"]
	target.PublicEndpoint = correctPublicEndpoint
	cfg.Targets["local"] = target
	writeManagedConfig(t, fixture.root, cfg)
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local"}); !errors.Is(err, state.ErrConflict) || !strings.Contains(err.Error(), "--rebind") {
		t.Fatalf("ordinary publish conflict=%v", err)
	}
	resumed, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local", Rebind: true})
	if err != nil || resumed.Attempt != stopped.Attempt || resumed.Phase != "grace" {
		t.Fatalf("rebound publication=%#v stopped=%#v err=%v", resumed, stopped, err)
	}

	store, err := state.OpenReadOnly(filepath.Join(fixture.root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := cfg.TargetBindings()
	if err != nil {
		t.Fatal(err)
	}
	revisions, revisionErr := store.ListPublicationTargetBindingRevisions(ctx, bindings[0].TargetIdentity)
	closeErr := store.Close()
	if err := errors.Join(revisionErr, closeErr); err != nil || len(revisions) != 2 || !revisions[1].OperatorConfirmed {
		t.Fatalf("managed rebind revisions=%#v err=%v", revisions, err)
	}

	cfg, err = config.Load(filepath.Join(fixture.root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	target = cfg.Targets["local"]
	target.Prefix = "other/repo"
	target.PublicEndpoint = "https://cdn.example.test/other/repo/"
	cfg.Targets["local"] = target
	writeManagedConfig(t, fixture.root, cfg)
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local", Rebind: true}); !errors.Is(err, state.ErrConflict) || !strings.Contains(err.Error(), "new target") {
		t.Fatalf("storage/prefix rebind error=%v", err)
	}
}

type recordingPublicationBackend struct {
	publicationBackend
	verified []string
}

func (b *recordingPublicationBackend) VerifyPublic(ctx context.Context, file state.GenerationFile) error {
	b.verified = append(b.verified, file.Path)
	return b.publicationBackend.VerifyPublic(ctx, file)
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

func TestFilesystemPublicationIncrementalCrashRollForwardMatrix(t *testing.T) {
	cases := []struct {
		name       string
		point      string
		occurrence int
		prefix     bool
	}{
		{name: "commit-intent", point: "publish.commit_intent", occurrence: 1},
		{name: "before-first-pointer", point: "publish.pointer.before.", occurrence: 1, prefix: true},
		{name: "first-pointer-written", point: "publish.pointer.written.", occurrence: 1, prefix: true},
		{name: "first-pointer-recorded", point: "publish.pointer.recorded.", occurrence: 1, prefix: true},
		{name: "before-second-pointer", point: "publish.pointer.before.", occurrence: 2, prefix: true},
		{name: "second-pointer-written", point: "publish.pointer.written.", occurrence: 2, prefix: true},
		{name: "second-pointer-recorded", point: "publish.pointer.recorded.", occurrence: 2, prefix: true},
		{name: "verified", point: "publish.verified", occurrence: 1},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			fixture, _, _ := filesystemPublishFixture(t)
			first, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local"})
			if err != nil {
				t.Fatal(err)
			}
			maintenanceAt := time.Now().UTC().Add(31 * 24 * time.Hour)
			settled, err := TargetGC(ctx, TargetGCOptions{
				WorkspaceOptions: fixture.options, Target: "local",
				now: func() time.Time { return maintenanceAt },
			})
			if err != nil || settled.CompletedAttempts != 1 {
				t.Fatalf("settle initial publication=%#v err=%v", settled, err)
			}
			added, err := Add(ctx, AddOptions{
				WorkspaceOptions: fixture.options, Repository: "repo", Dists: []string{"el9"},
				Paths: []string{filepath.Join(fixture.root, "inputs", "package.rpm")}, Jobs: 1,
			})
			if err != nil || added.Generation == first.Generation {
				t.Fatalf("incremental source generation=%#v first=%#v err=%v", added, first, err)
			}

			seen, faulted := 0, false
			injected := errors.New("stop incremental publication")
			stopped, err := Publish(ctx, PublishOptions{
				WorkspaceOptions: fixture.options, Target: "local",
				now: func() time.Time { return maintenanceAt.Add(time.Second) },
				Fault: func(point string) error {
					matches := point == test.point
					if test.prefix {
						matches = strings.HasPrefix(point, test.point)
					}
					if !matches {
						return nil
					}
					seen++
					if seen == test.occurrence {
						faulted = true
						return injected
					}
					return nil
				},
			})
			if !errors.Is(err, injected) || !faulted || stopped.Attempt == "" {
				t.Fatalf("stopped publication=%#v err=%v seen=%d faulted=%t", stopped, err, seen, faulted)
			}
			resumed, err := Publish(ctx, PublishOptions{
				WorkspaceOptions: fixture.options, Target: "local",
				now: func() time.Time { return maintenanceAt.Add(2 * time.Second) },
			})
			if err != nil || resumed.Phase != "grace" || resumed.Attempt != stopped.Attempt || resumed.Generation != added.Generation {
				t.Fatalf("resumed publication=%#v stopped=%#v err=%v", resumed, stopped, err)
			}
		})
	}
}

func TestFilesystemPublicationIncrementalRecoveryRejectsThirdPointerIdentity(t *testing.T) {
	ctx := context.Background()
	fixture, _, targetRoot := filesystemPublishFixture(t)
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local"}); err != nil {
		t.Fatal(err)
	}
	maintenanceAt := time.Now().UTC().Add(31 * 24 * time.Hour)
	if _, err := TargetGC(ctx, TargetGCOptions{
		WorkspaceOptions: fixture.options, Target: "local",
		now: func() time.Time { return maintenanceAt },
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, AddOptions{
		WorkspaceOptions: fixture.options, Repository: "repo", Dists: []string{"el9"},
		Paths: []string{filepath.Join(fixture.root, "inputs", "package.rpm")}, Jobs: 1,
	}); err != nil {
		t.Fatal(err)
	}
	writtenPath := ""
	_, err := Publish(ctx, PublishOptions{
		WorkspaceOptions: fixture.options, Target: "local",
		now: func() time.Time { return maintenanceAt.Add(time.Second) },
		Fault: func(point string) error {
			if writtenPath == "" && strings.HasPrefix(point, "publish.pointer.written.") {
				writtenPath = strings.TrimPrefix(point, "publish.pointer.written.")
				return errors.New("stop after pointer write")
			}
			return nil
		},
	})
	if err == nil || writtenPath == "" {
		t.Fatalf("incremental publication did not stop after a pointer write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(targetRoot, filepath.FromSlash(writtenPath)), []byte("third pointer identity\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = Publish(ctx, PublishOptions{
		WorkspaceOptions: fixture.options, Target: "local",
		now: func() time.Time { return maintenanceAt.Add(2 * time.Second) },
	})
	if !errors.Is(err, ErrIntegrity) || !strings.Contains(err.Error(), "outside the recoverable old/new closure") {
		t.Fatalf("third pointer identity recovery error=%v", err)
	}
}

func TestPublicationPublicVerificationScalesWithChangeSetAndCheckpointReplay(t *testing.T) {
	ctx := context.Background()
	fixture, _, _ := filesystemPublishFixture(t)
	cfg, err := config.Load(filepath.Join(fixture.root, config.ConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	storage, err := newFilesystemPublicationBackend(cfg.Targets["local"])
	if err != nil {
		t.Fatal(err)
	}
	initialBackend := &recordingPublicationBackend{publicationBackend: storage}
	first, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local", backend: initialBackend})
	if err != nil || len(initialBackend.verified) == 0 {
		t.Fatalf("initial publication=%#v verified=%d err=%v", first, len(initialBackend.verified), err)
	}
	noopBackend := &recordingPublicationBackend{publicationBackend: storage}
	noop, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local", backend: noopBackend})
	if err != nil || !noop.Noop || len(noopBackend.verified) != 0 {
		t.Fatalf("no-op publication=%#v verified=%v err=%v", noop, noopBackend.verified, err)
	}
	maintenanceAt := time.Now().UTC().Add(31 * 24 * time.Hour)
	gcBackend := &recordingPublicationBackend{publicationBackend: storage}
	if _, err := TargetGC(ctx, TargetGCOptions{
		WorkspaceOptions: fixture.options, Target: "local", backend: gcBackend,
		now: func() time.Time { return maintenanceAt },
	}); err != nil {
		t.Fatal(err)
	}
	if len(gcBackend.verified) == 0 || len(gcBackend.verified) >= len(initialBackend.verified) {
		t.Fatalf("target GC verified=%d initial=%d", len(gcBackend.verified), len(initialBackend.verified))
	}
	for _, path := range gcBackend.verified {
		if publicFilePhase(path) != "pointer" {
			t.Fatalf("target GC streamed non-pointer %q", path)
		}
	}
	added, err := Add(ctx, AddOptions{
		WorkspaceOptions: fixture.options, Repository: "repo", Dists: []string{"el9"},
		Paths: []string{filepath.Join(fixture.root, "inputs", "package.rpm")}, Jobs: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenReadOnly(filepath.Join(fixture.root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, manifestErr := store.GenerationManifest(ctx, added.Generation)
	closeErr := store.Close()
	if err := errors.Join(manifestErr, closeErr); err != nil {
		t.Fatal(err)
	}
	incrementalBackend := &recordingPublicationBackend{publicationBackend: storage}
	injected := errors.New("stop after applied checkpoint")
	_, err = Publish(ctx, PublishOptions{
		WorkspaceOptions: fixture.options, Target: "local", backend: incrementalBackend,
		now: func() time.Time { return maintenanceAt.Add(time.Second) },
		Fault: func(point string) error {
			if point == "publish.checkpoint" {
				return injected
			}
			return nil
		},
	})
	if !errors.Is(err, injected) || len(incrementalBackend.verified) == 0 || len(incrementalBackend.verified) >= len(manifest) {
		t.Fatalf("incremental verified=%d manifest=%d err=%v", len(incrementalBackend.verified), len(manifest), err)
	}
	replayBackend := &recordingPublicationBackend{publicationBackend: storage}
	resumed, err := Publish(ctx, PublishOptions{
		WorkspaceOptions: fixture.options, Target: "local", backend: replayBackend,
		now: func() time.Time { return maintenanceAt.Add(2 * time.Second) },
	})
	if err != nil || resumed.Phase != "grace" || len(replayBackend.verified) != 0 {
		t.Fatalf("applied checkpoint replay=%#v verified=%v err=%v", resumed, replayBackend.verified, err)
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

func TestFilesystemPublicationReabandonResurrectedAttempt(t *testing.T) {
	ctx := context.Background()
	fixture, _, _ := filesystemPublishFixture(t)
	stopAtPayload := func(point string) error {
		if point == "publish.payload" {
			return errors.New("stop after payload")
		}
		return nil
	}
	first, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local", Fault: stopAtPayload})
	if err == nil || first.Attempt == "" {
		t.Fatalf("first stopped publication=%#v err=%v", first, err)
	}
	firstAbandon, err := AbandonPublication(ctx, PublicationAbandonOptions{WorkspaceOptions: fixture.options, Target: "local"})
	if err != nil || firstAbandon.Objects == 0 {
		t.Fatalf("first abandon=%#v err=%v", firstAbandon, err)
	}
	second, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local", Fault: stopAtPayload})
	if err == nil || second.Attempt != first.Attempt {
		t.Fatalf("resurrected publication=%#v first=%#v err=%v", second, first, err)
	}
	secondAbandon, err := AbandonPublication(ctx, PublicationAbandonOptions{WorkspaceOptions: fixture.options, Target: "local"})
	if err != nil || secondAbandon.Attempt != first.Attempt || secondAbandon.Phase != "abandoned" || secondAbandon.Objects != firstAbandon.Objects {
		t.Fatalf("second abandon=%#v first=%#v err=%v", secondAbandon, firstAbandon, err)
	}
	removed, err := RemoveDistResult(ctx, DistRemoveOptions{WorkspaceOptions: fixture.options, Repository: "repo", Name: "el9", Force: true})
	if err != nil || !removed.Removed {
		t.Fatalf("post-reabandon mutation=%#v err=%v", removed, err)
	}
}

func TestFilesystemTargetGCRecognizesAbandonedObjectEvidence(t *testing.T) {
	ctx := context.Background()
	fixture, _, targetRoot := filesystemPublishFixture(t)
	first, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local"})
	if err != nil {
		t.Fatal(err)
	}
	firstRPM := filepath.Join(fixture.root, "inputs", "package.rpm")
	secondRPM := filepath.Join(fixture.root, "inputs", "package2.rpm")
	body, err := os.ReadFile(firstRPM)
	if err != nil {
		t.Fatal(err)
	}
	updated := bytes.ReplaceAll(body, []byte("20PGDG"), []byte("21PGDG"))
	if bytes.Equal(updated, body) {
		t.Fatal("RPM fixture release marker was absent")
	}
	if err := os.WriteFile(secondRPM, updated, 0o600); err != nil {
		t.Fatal(err)
	}
	added, err := Add(ctx, AddOptions{
		WorkspaceOptions: fixture.options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{secondRPM}, Jobs: 1,
	})
	if err != nil || len(added.Items) != 1 {
		t.Fatalf("second package add=%#v err=%v", added, err)
	}
	store, err := state.OpenReadOnly(filepath.Join(fixture.root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	object, objectErr := store.GetPackageObject(ctx, added.Items[0].SHA256)
	closeErr := store.Close()
	if err := errors.Join(objectErr, closeErr); err != nil {
		t.Fatal(err)
	}
	stopAtPayload := func(point string) error {
		if point == "publish.payload" {
			return errors.New("stop after payload")
		}
		return nil
	}
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local", Fault: stopAtPayload}); err == nil {
		t.Fatal("incremental publication did not stop after payload")
	}
	abandoned, err := AbandonPublication(ctx, PublicationAbandonOptions{WorkspaceOptions: fixture.options, Target: "local"})
	if err != nil || abandoned.Objects == 0 {
		t.Fatalf("incremental abandon=%#v err=%v", abandoned, err)
	}
	orphanPath := filepath.Join(targetRoot, filepath.FromSlash(object.PoolPath))
	if _, err := os.Stat(orphanPath); err != nil {
		t.Fatalf("abandoned target object is absent: %v", err)
	}
	maintenanceAt := time.Now().UTC().Add(31 * 24 * time.Hour)
	collected, err := TargetGC(ctx, TargetGCOptions{
		WorkspaceOptions: fixture.options, Target: "local", now: func() time.Time { return maintenanceAt },
	})
	if err != nil || collected.CompletedAttempts != 1 {
		t.Fatalf("target GC over abandoned evidence=%#v err=%v", collected, err)
	}
	if _, err := os.Stat(orphanPath); err != nil {
		t.Fatalf("target GC removed abandoned evidence: %v", err)
	}
	resumed, err := Publish(ctx, PublishOptions{
		WorkspaceOptions: fixture.options, Target: "local", now: func() time.Time { return maintenanceAt.Add(time.Second) },
	})
	if err != nil || resumed.Checkpoint == "" || resumed.Checkpoint == first.Checkpoint {
		t.Fatalf("publication over retained abandoned evidence=%#v first=%#v err=%v", resumed, first, err)
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
	firstMaintenanceAt := time.Now().UTC().Add(31 * 24 * time.Hour)
	firstMaintenanceClock := func() time.Time { return firstMaintenanceAt }
	settled, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "local", now: firstMaintenanceClock})
	if err != nil || settled.CompletedAttempts != 1 || settled.Candidates != 0 {
		t.Fatalf("settle first target grace=%#v err=%v", settled, err)
	}
	collected, err := LocalGC(ctx, LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"})
	if err != nil || collected.Noop || collected.Objects != 1 {
		t.Fatalf("local gc after remote checkpoint=%#v err=%v", collected, err)
	}
	secondPublishAt := firstMaintenanceAt.Add(time.Second)
	secondPublishClock := func() time.Time { return secondPublishAt }
	second, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local", now: secondPublishClock})
	if err != nil || second.Generation == first.Generation || second.Checkpoint == first.Checkpoint {
		t.Fatalf("second publish=%#v first=%#v err=%v", second, first, err)
	}
	stalePayload := filepath.Join(targetRoot, filepath.FromSlash(fixture.object.PoolPath))
	if _, err := os.Stat(stalePayload); err != nil {
		t.Fatalf("old payload disappeared before target grace: %v", err)
	}
	pending, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "local", now: secondPublishClock})
	if err != nil || !pending.Noop || pending.PendingGrace == 0 {
		t.Fatalf("premature target gc=%#v err=%v", pending, err)
	}
	faulted := false
	secondMaintenanceAt := secondPublishAt.Add(31 * 24 * time.Hour)
	secondMaintenanceClock := func() time.Time { return secondMaintenanceAt }
	_, err = TargetGC(ctx, TargetGCOptions{
		WorkspaceOptions: fixture.options, Target: "local", now: secondMaintenanceClock,
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
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local", now: secondMaintenanceClock}); !errors.Is(err, ErrNotReady) {
		t.Fatalf("publish crossed an unfinished deletion report: %v", err)
	}
	resumed, err := TargetGC(ctx, TargetGCOptions{WorkspaceOptions: fixture.options, Target: "local", now: secondMaintenanceClock})
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
	noop, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local", now: secondMaintenanceClock})
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
