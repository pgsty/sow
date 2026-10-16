package managed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/workmetrics"
)

func TestCompletedDistRemovalPreservesReaddedPayload(t *testing.T) {
	for _, crash := range []string{"", "dist.rm.finalized", "add.applied"} {
		t.Run(crash, func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			opts := WorkspaceOptions{Workdir: root, CWD: root}
			cfg := config.Default()
			cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}, "el8": {Format: "rpm"}}}
			writeManagedConfig(t, root, cfg)
			if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
				t.Fatal(err)
			}
			input := decodeManagedFixture(t, "../../testdata/pgdg-redhat-nonfree-repo.rpm.b64", filepath.Join(root, "package.rpm"))
			if _, err := Add(ctx, AddOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"el9"}, Paths: []string{input}, Skip: true, Jobs: 1}); err != nil {
				t.Fatal(err)
			}
			injected := errors.New("crash before historical cleanup")
			fault := func(point string) error {
				if point == crash {
					return injected
				}
				return nil
			}
			_, err := RemoveDistResult(ctx, DistRemoveOptions{WorkspaceOptions: opts, Repository: "repo", Name: "el9", Force: true, Fault: fault})
			if crash == "dist.rm.finalized" {
				if !errors.Is(err, injected) {
					t.Fatalf("remove fault: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			_, err = Add(ctx, AddOptions{WorkspaceOptions: opts, Repository: "repo", Dists: []string{"el8"}, Paths: []string{input}, Skip: true, Jobs: 1, Fault: fault})
			if crash == "add.applied" {
				if !errors.Is(err, injected) {
					t.Fatalf("add fault: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			// Repeat after promotion too: the old deletion receipt remains in
			// history while the current object has moved from pending to pool.
			for range 2 {
				if _, err := Build(ctx, BuildOptions{WorkspaceOptions: opts, Repository: "repo", Jobs: 1}); err != nil {
					t.Fatal(err)
				}
				checked, err := Check(ctx, CheckOptions{WorkspaceOptions: opts, Repository: "repo", Jobs: 1})
				if err != nil || !checked.ReadyToCopy {
					t.Fatalf("check=%+v err=%v", checked, err)
				}
			}
			if _, err := os.Stat(filepath.Join(root, "repo/pool/p/pgdg-redhat-nonfree-repo/package.rpm")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDistLifecycleReusesPublicSnapshot(t *testing.T) {
	for _, operation := range []string{"new-rpm", "new-deb", "remove-empty", "remove-populated", "recover-new", "recover-remove"} {
		t.Run(operation, func(t *testing.T) {
			root, options, objects := distSnapshotReuseFixture(t)
			var payloadBytes, aptBytes int64
			for _, object := range objects {
				payloadBytes += object.Size
				if object.Format == "deb" {
					aptBytes += object.Size
				}
			}
			fault := func(string) error { return nil }
			injected := errors.New("stop after Dist publication")
			if strings.HasPrefix(operation, "recover-") {
				fault = func(point string) error {
					if point == "dist.new.built" || point == "dist.rm.built" {
						return injected
					}
					return nil
				}
			}
			run := func(ctx context.Context) error {
				switch operation {
				case "new-rpm", "new-deb", "recover-new":
					format := "rpm"
					if operation == "new-deb" {
						format = "deb"
					}
					_, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: options, Repository: "repo", Name: "new", Format: format, Fault: fault})
					return err
				default:
					name := "empty"
					force := operation == "remove-populated"
					if force {
						name = "rpm"
					}
					return RemoveDist(ctx, DistRemoveOptions{WorkspaceOptions: options, Repository: "repo", Name: name, Force: force, Fault: fault})
				}
			}
			if strings.HasPrefix(operation, "recover-") {
				if err := run(context.Background()); !errors.Is(err, injected) {
					t.Fatalf("prepare recovery: %v", err)
				}
				fault = nil
			}
			ctx, collector := workmetrics.Ensure(context.Background())
			if err := run(ctx); err != nil {
				t.Fatal(err)
			}
			metrics := collector.Snapshot()
			// Ordinary writes already validated the retained Generation with
			// persisted fingerprints. Forced withdrawal and recovery each need
			// one fresh content pass, but none need a second manifest pass.
			// Workspace config validation also checks the existing APT index
			// against its payload independently of the generation snapshot.
			wantReads, wantBytes := int64(1), aptBytes
			if operation == "remove-populated" || strings.HasPrefix(operation, "recover-") {
				wantReads += int64(len(objects))
				wantBytes += payloadBytes
			}
			t.Logf("operation=%s payload_size=%d reads=%d bytes=%d phases=%v", operation, payloadBytes, metrics.FullPackageReads, metrics.PayloadBytesRead, metrics.PayloadByPhase)
			if metrics.FullPackageReads != wantReads || metrics.PayloadBytesRead != wantBytes {
				t.Fatalf("redundant package reads: got %d/%d bytes, want %d/%d bytes", metrics.FullPackageReads, metrics.PayloadBytesRead, wantReads, wantBytes)
			}
			assertDistSnapshotGeneration(t, root, options)
		})
	}
}

func TestDistLifecycleRejectsChangedPublicSnapshot(t *testing.T) {
	for _, change := range []string{"rewrite", "replace", "add", "remove", "metadata"} {
		t.Run(change, func(t *testing.T) {
			root, options, objects := distSnapshotReuseFixture(t)
			generation := distSnapshotBuiltGeneration(t, root)
			path := filepath.Join(root, "repo", filepath.FromSlash(objects[0].PoolPath))
			if change == "metadata" {
				path = filepath.Join(root, "repo", "dists", "deb", "Release")
			}
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			changed := false
			_, err = NewDist(context.Background(), DistNewOptions{WorkspaceOptions: options, Repository: "repo", Name: "new", Format: "rpm", Fault: func(point string) error {
				if point != "dist.new.built" {
					return nil
				}
				changed = true
				switch change {
				case "rewrite":
					rewriteDistSnapshotFile(t, path)
				case "replace":
					body, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					replacement := filepath.Join(root, "replacement")
					if err := os.WriteFile(replacement, body, 0o644); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(replacement, path); err != nil {
						t.Fatal(err)
					}
				case "add":
					if err := os.WriteFile(path+".extra", []byte("untracked"), 0o644); err != nil {
						t.Fatal(err)
					}
				case "remove":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				case "metadata":
					rewriteDistSnapshotFile(t, path)
				}
				return nil
			}})
			if !changed || !errors.Is(err, ErrIntegrity) {
				t.Fatalf("changed=%t snapshot change accepted: %v", changed, err)
			}
			assertDistSnapshotRecoveryPending(t, root, generation)
			if change == "add" {
				if err := os.Remove(path + ".extra"); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, original, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := NewDist(context.Background(), DistNewOptions{WorkspaceOptions: options, Repository: "repo", Name: "new", Format: "rpm"}); err != nil {
				t.Fatalf("recover after restoring authentic bytes: %v", err)
			}
			assertDistSnapshotGeneration(t, root, options)
		})
	}
}

func TestDistLifecycleRejectsChangedFingerprintBeforeMutation(t *testing.T) {
	for _, change := range []string{"rewrite", "rewrite-hardlink", "replace"} {
		t.Run(change, func(t *testing.T) {
			root, options, objects := distSnapshotReuseFixture(t)
			var path string
			for _, object := range objects {
				if object.Format == "rpm" {
					path = filepath.Join(root, "repo", filepath.FromSlash(object.PoolPath))
				}
			}
			if change == "rewrite-hardlink" {
				if err := os.Link(path, filepath.Join(root, "alias")); err != nil {
					t.Fatal(err)
				}
			} else if change == "replace" {
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				replacement := filepath.Join(root, "replacement")
				if err := os.WriteFile(replacement, body, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(replacement, path); err != nil {
					t.Fatal(err)
				}
			}
			rewriteDistSnapshotFile(t, path)
			for _, remove := range []bool{false, true} {
				ctx, collector := workmetrics.Ensure(context.Background())
				var err error
				if remove {
					err = RemoveDist(ctx, DistRemoveOptions{WorkspaceOptions: options, Repository: "repo", Name: "empty"})
				} else {
					_, err = NewDist(ctx, DistNewOptions{WorkspaceOptions: options, Repository: "repo", Name: "new", Format: "rpm"})
				}
				if !errors.Is(err, ErrIntegrity) || collector.Snapshot().PayloadByPhase["current_public_generation"].Full != 1 {
					t.Fatalf("remove=%t stale fingerprint accepted without fresh authentication: err=%v metrics=%+v", remove, err, collector.Snapshot())
				}
			}
		})
	}
}

func TestDistLifecycleModeNormalizationReauthenticatesPayload(t *testing.T) {
	for _, rewrite := range []bool{false, true} {
		name := "legal-hardlink"
		if rewrite {
			name = "rewrite-after-chmod"
		}
		t.Run(name, func(t *testing.T) {
			root, options, objects := distSnapshotReuseFixture(t)
			path := filepath.Join(root, "repo", filepath.FromSlash(objects[0].PoolPath))
			alias := filepath.Join(root, "legal-alias")
			if err := os.Link(path, alias); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
			changed := false
			_, err := NewDist(context.Background(), DistNewOptions{WorkspaceOptions: options, Repository: "repo", Name: "new", Format: "rpm", Fault: func(point string) error {
				if rewrite && point == "dist.new.mode" && !changed {
					changed = true
					rewriteDistSnapshotFile(t, path)
				}
				return nil
			}})
			if rewrite {
				if !changed || !errors.Is(err, ErrIntegrity) {
					t.Fatalf("changed=%t mode callback rewrite accepted: %v", changed, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(alias)
			if err != nil || info.Mode().Perm() != 0o644 {
				t.Fatalf("legal hardlink normalization: info=%v err=%v", info, err)
			}
			assertDistSnapshotGeneration(t, root, options)
		})
	}
}

func TestDistLifecycleRecoveryAuthenticatesPayload(t *testing.T) {
	for _, change := range []string{"rpm", "deb", "target-metadata", "other-metadata", "missing", "extra"} {
		t.Run(change, func(t *testing.T) {
			root, options, objects := distSnapshotReuseFixture(t)
			generation := distSnapshotBuiltGeneration(t, root)
			ctx := context.Background()
			injected := errors.New("stop before Dist finalization")
			_, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: options, Repository: "repo", Name: "new", Format: "rpm", Fault: func(point string) error {
				if point == "dist.new.built" {
					return injected
				}
				return nil
			}})
			if !errors.Is(err, injected) {
				t.Fatalf("prepare recovery: %v", err)
			}
			path := filepath.Join(root, "repo", filepath.FromSlash(objects[0].PoolPath))
			for _, object := range objects {
				if object.Format == change {
					path = filepath.Join(root, "repo", filepath.FromSlash(object.PoolPath))
				}
			}
			if change == "target-metadata" {
				path = filepath.Join(root, "repo", "dists", "new", "aarch64", "repodata", "repomd.xml")
			} else if change == "other-metadata" {
				path = filepath.Join(root, "repo", "dists", "deb", "Release")
			}
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "extra":
				if err := os.WriteFile(path+".extra", original, 0o644); err != nil {
					t.Fatal(err)
				}
			default:
				rewriteDistSnapshotFile(t, path)
			}
			if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: options, Repository: "repo", Name: "new", Format: "rpm"}); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("recovery trusted stale payload evidence: %v", err)
			}
			assertDistSnapshotRecoveryPending(t, root, generation)
			if change == "extra" {
				if err := os.Remove(path + ".extra"); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, original, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: options, Repository: "repo", Name: "new", Format: "rpm"}); err != nil {
				t.Fatalf("recovery failed after authentic bytes were restored: %v", err)
			}
			assertDistSnapshotGeneration(t, root, options)
		})
	}
}

func distSnapshotBuiltGeneration(t *testing.T, root string) state.GenerationID {
	t.Helper()
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	summary, err := store.Summary(context.Background())
	if err := errors.Join(err, store.Close()); err != nil {
		t.Fatal(err)
	}
	return summary.BuiltGeneration
}

func assertDistSnapshotRecoveryPending(t *testing.T, root string, generation state.GenerationID) {
	t.Helper()
	if got := distSnapshotBuiltGeneration(t, root); got != generation {
		t.Fatalf("failed Dist finalized Generation %d, want %d", got, generation)
	}
	ctx := context.Background()
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.GetGeneration(ctx, generation+1); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("failed Dist retained an invalid next Generation: %v", err)
	}
	if _, err := store.GetDist(ctx, "new"); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("failed Dist became visible in state: %v", err)
	}
	pending, err := store.PendingOperations(ctx)
	if err != nil || len(pending) != 1 || pending[0].State != state.OperationBuilt && pending[0].State != state.OperationApplied {
		t.Fatalf("failed Dist lost its recoverable journal: pending=%+v err=%v", pending, err)
	}
	if _, err := os.Stat(distStageRoot(root, "repo", pending[0].ID)); err != nil {
		t.Fatalf("failed Dist removed recovery evidence: %v", err)
	}
}

func rewriteDistSnapshotFile(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil || len(body) == 0 {
		t.Fatalf("rewrite fixture: size=%d err=%v", len(body), err)
	}
	body[len(body)-1] ^= 1
	if err := os.WriteFile(path, body, info.Mode().Perm()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
}

func distSnapshotReuseFixture(t *testing.T) (string, WorkspaceOptions, []state.PackageObject) {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	options := WorkspaceOptions{Workdir: root, CWD: root}
	cfg := config.Default()
	cfg.Architectures = []string{"aarch64"}
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{
		"rpm": {Format: "rpm"}, "deb": {Format: "deb"}, "empty": {Format: "rpm"},
	}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct{ format, fixture string }{
		{"rpm", "../../testdata/pgdg-redhat-nonfree-repo.rpm.b64"},
		{"deb", "../../aptrepo/testdata/libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"},
	} {
		path := decodeManagedFixture(t, input.fixture, filepath.Join(root, "input."+input.format))
		if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{input.format}, Paths: []string{path}, Jobs: 1}); err != nil {
			t.Fatal(err)
		}
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	objects, err := store.ListPackageObjects(ctx, nil, false)
	if err := errors.Join(err, store.Close()); err != nil || len(objects) != 2 {
		t.Fatalf("fixture objects=%d err=%v", len(objects), err)
	}
	return root, options, objects
}

func assertDistSnapshotGeneration(t *testing.T, root string, options WorkspaceOptions) {
	t.Helper()
	ctx := context.Background()
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	summary, err := store.Summary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := store.GenerationManifest(ctx, summary.BuiltGeneration)
	if err != nil {
		t.Fatal(err)
	}
	physical, err := scanPublicManifest(ctx, filepath.Join(root, "repo"))
	if err != nil || !sameGenerationManifest(manifest, physical) {
		t.Fatalf("Generation differs from final public tree: %v", err)
	}
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if err != nil || !checked.ReadyToCopy {
		t.Fatalf("check=%+v err=%v", checked, err)
	}
}
