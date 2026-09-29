package managed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"golang.org/x/sys/unix"
)

func stagedRecoveryAdd(t *testing.T) (string, WorkspaceOptions, AddResult, *state.Store, mutationOperationPayload, mutationManifest) {
	t.Helper()
	root, ws := newRejectionWorkspace(t)
	paths := collidingRPMInputs(t, root)
	crash := errors.New("stop after staging")
	added, err := Add(context.Background(), AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: paths[:1], Skip: true, Jobs: 1, Fault: func(point string) error {
		if point == "add.staged" {
			return crash
		}
		return nil
	}})
	if !errors.Is(err, crash) {
		t.Fatal(err)
	}
	store, err := state.OpenExisting(filepath.Join(root, ".sow/repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	_, payload, manifest, err := loadMutationOperation(context.Background(), store, root, "repo", added.Operation)
	if err != nil {
		t.Fatal(err)
	}
	return root, ws, added, store, payload, manifest
}

func TestAddCancelAfterStagingCorrectsUncommittedResult(t *testing.T) {
	root, ws := newRejectionWorkspace(t)
	paths := collidingRPMInputs(t, root)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	added, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: paths[:1], Skip: true, Jobs: 1, Fault: func(point string) error {
		if point == "add.staged" {
			cancel()
		}
		return nil
	}})
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrRejected) || added.Accepted != 0 || added.Failed != 1 || added.MembershipAdded != 0 || added.Items[0].Status != "failed" {
		t.Fatalf("result=%+v err=%v", added, err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow/repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	detail, err := store.GetOperation(context.Background(), added.Operation)
	store.Close()
	if err != nil || detail.Operation.State != state.OperationFailed || detail.Operation.ErrorClass != "cancelled" || len(detail.Packages) != 1 || detail.Packages[0].Disposition != "failed" || !strings.Contains(detail.Operation.ResultJSON, `"accepted":0`) {
		t.Fatalf("audit=%+v err=%v", detail, err)
	}
	if _, err := Build(context.Background(), BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); err != nil {
		t.Fatal(err)
	}
}

func TestFailedAddIsTerminalBeforePendingCleanup(t *testing.T) {
	ctx := context.Background()
	root, ws, added, store, _, manifest := stagedRecoveryAdd(t)
	object := manifest.Objects[0]
	pending := filepath.Join(root, ".sow/repo/pending", object.SHA256)
	// A deterministic cleanup failure stands in for a timeout or interruption.
	if err := os.Mkdir(pending, 0700); err != nil {
		t.Fatal(err)
	}
	returned := errors.New("ordinary pre-apply failure")
	err := finalizePreApplyMutationOperation(ctx, root, "repo", added.Operation, store, returned, nil)
	detail, readErr := store.GetOperation(ctx, added.Operation)
	if !errors.Is(err, returned) || readErr != nil || detail.Operation.State != state.OperationFailed {
		t.Fatalf("terminal=%+v error=%v read=%v", detail.Operation, err, readErr)
	}
	stage := mutationStageRoot(root, "repo", added.Operation)
	if _, err := os.Stat(stage); err != nil {
		t.Fatalf("cleanup evidence was lost: %v", err)
	}
	if err := os.Remove(pending); err != nil {
		t.Fatal(err)
	}
	store.Close()
	for range 2 {
		if _, err := Build(ctx, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(stage); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stage remains: %v", err)
	}
}

func TestLegacyUncommittedMissingBytesCanBeRetried(t *testing.T) {
	ctx := context.Background()
	root, ws, added, store, _, manifest := stagedRecoveryAdd(t)
	for _, object := range manifest.Objects {
		if err := os.Remove(filepath.Join(mutationStageRoot(root, "repo", added.Operation), "objects", object.SHA256)); err != nil {
			t.Fatal(err)
		}
	}
	store.Close()
	for range 2 {
		if _, err := Build(ctx, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); err != nil {
			t.Fatal(err)
		}
	}
	read, err := state.OpenReadOnly(filepath.Join(root, ".sow/repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	op, err := read.GetOperation(ctx, added.Operation)
	read.Close()
	if err != nil || op.Operation.State != state.OperationFailed {
		t.Fatalf("operation=%+v err=%v", op, err)
	}
	input := filepath.Join(root, "one", "centos-release-latest.rpm")
	if result, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: []string{input}, Jobs: 1}); err != nil || result.Accepted != 1 {
		t.Fatalf("retry=%+v err=%v", result, err)
	}
}

func TestTerminalCleanupRetainsCorruptManifest(t *testing.T) {
	ctx := context.Background()
	root, _, added, store, payload, _ := stagedRecoveryAdd(t)
	if err := store.FailOperation(ctx, added.Operation, "rejected", "fixture", `{}`); err != nil {
		t.Fatal(err)
	}
	path := mutationManifestPath(root, "repo", added.Operation, payload.ManifestSHA256)
	if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := recoverDoneDistCleanup(ctx, root, "repo", store); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("corrupt manifest silently discarded: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("corrupt evidence removed: %v", err)
	}
}

func TestAddEmptyDesiredRecovery(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, point := range []string{"add.staged", "add.applied", "build.staged"} {
			t.Run(fmt.Sprintf("legacy=%t/%s", legacy, point), func(t *testing.T) {
				ctx := context.Background()
				root := t.TempDir()
				cfg := config.Default()
				cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{
					"excluded": {Format: "rpm", Exclude: []config.ExcludeRule{{Name: []string{"centos-release"}}}},
					"included": {Format: "rpm"},
				}}
				writeManagedConfig(t, root, cfg)
				if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
					t.Fatal(err)
				}
				ws := WorkspaceOptions{Workdir: root, CWD: root}
				input, err := filepath.Abs("../../../third_party/cavaliergopher-rpm/testdata/centos-release-7-2.1511.el7.centos.2.10.x86_64.rpm")
				if err != nil {
					t.Fatal(err)
				}
				crash := errors.New("stop empty Dist mutation")
				added, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"excluded", "included"}, Paths: []string{input}, Jobs: 1, Fault: func(got string) error {
					if got == point {
						return crash
					}
					return nil
				}})
				if !errors.Is(err, crash) {
					t.Fatal(err)
				}
				if legacy {
					store, err := state.OpenExisting(filepath.Join(root, ".sow/repo.db"))
					if err != nil {
						t.Fatal(err)
					}
					_, payload, manifest, err := loadMutationOperation(ctx, store, root, "repo", added.Operation)
					if err != nil {
						t.Fatal(err)
					}
					delete(manifest.Desired, "excluded")
					wire, err := marshalMutationManifest(manifest)
					if err != nil {
						t.Fatal(err)
					}
					payload.ManifestSHA256 = bytesSHA(wire)
					if err := writeAtomic(mutationManifestPath(root, "repo", added.Operation, payload.ManifestSHA256), wire, 0600); err != nil {
						t.Fatal(err)
					}
					pw, _ := json.Marshal(payload)
					if err := store.UpdateOperationPayload(ctx, added.Operation, string(pw)); err != nil {
						t.Fatal(err)
					}
					store.Close()
				}
				for range 2 {
					if _, err := Build(ctx, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); err != nil {
						t.Fatal(err)
					}
				}
				store, err := state.OpenReadOnly(filepath.Join(root, ".sow/repo.db"))
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close()
				members, err := store.MembershipDigests(ctx, "excluded", false)
				if err != nil || len(members) != 0 {
					t.Fatalf("excluded=%v err=%v", members, err)
				}
				members, err = store.MembershipDigests(ctx, "included", false)
				want := 1
				if legacy && point == "add.staged" {
					want = 0 // A known old, uncommitted journal can be safely retried.
				}
				if err != nil || len(members) != want {
					t.Fatalf("included=%v want=%d err=%v", members, want, err)
				}
			})
		}
	}
}

func TestTerminalCleanupDoesNotReadHistoricalOperations(t *testing.T) {
	ctx := context.Background()
	root, _ := newRejectionWorkspace(t)
	store, err := state.OpenExisting(filepath.Join(root, ".sow/repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	// Invalid payloads make a history-wide decoder observably fail. No private
	// directories remain, so none of these old rows are cleanup work.
	tx, err := store.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2000 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO operations(id,kind,state,payload_json,result_json,created_at,updated_at) VALUES (?, 'dist.rm', 'done', '{}', '{}', ?, ?)`, fmt.Sprintf("%032x", i+1), "2026-01-01T00:00:00.000000000Z", "2026-01-01T00:00:00.000000000Z"); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	operations, err := terminalCleanupOperations(ctx, root, "repo", store)
	if err != nil || len(operations) != 0 {
		t.Fatalf("historical cleanup=%d err=%v", len(operations), err)
	}
	if err := recoverDoneDistCleanup(ctx, root, "repo", store); err != nil {
		t.Fatal(err)
	}
}

func TestInputScanDoesNotResolveReplacedDirectory(t *testing.T) {
	for _, recursive := range []bool{false, true} {
		t.Run(fmt.Sprint(recursive), func(t *testing.T) {
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			tree, outside, swapped := filepath.Join(base, "tree"), filepath.Join(base, "outside"), filepath.Join(base, "swapped")
			for _, dir := range []string{tree, outside} {
				if err := os.Mkdir(dir, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "pkg.rpm"), []byte(dir), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(outside, swapped); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			var workers sync.WaitGroup
			workers.Add(1)
			go func() {
				defer workers.Done()
				for {
					select {
					case <-done:
						return
					default:
					}
					if err := exchangeDirectoriesAt(unix.AT_FDCWD, tree, unix.AT_FDCWD, swapped); err != nil {
						t.Errorf("exchange fixture: %v", err)
						return
					}
				}
			}()
			defer func() { close(done); workers.Wait() }()
			for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
				files, _ := collectInputFiles(context.Background(), []string{tree}, recursive)
				for _, file := range files {
					if !strings.HasPrefix(file.Path, tree+string(filepath.Separator)) {
						t.Fatalf("enumerated directory escaped: %s", file.Path)
					}
				}
			}
		})
	}
}

func TestCheckRecognizesJournalOwnedPendingBytes(t *testing.T) {
	ctx := context.Background()
	root, ws, added, store, _, manifest := stagedRecoveryAdd(t)
	for _, object := range manifest.Objects {
		if err := installPendingObject(ctx, root, "repo", filepath.Join(mutationStageRoot(root, "repo", added.Operation), "objects", object.SHA256), object); err != nil {
			t.Fatal(err)
		}
	}
	store.Close()
	checked, err := Check(ctx, CheckOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1})
	if !errors.Is(err, ErrNotReady) || checked.Status != "recovering" {
		t.Fatalf("check=%+v err=%v", checked, err)
	}
	for _, layer := range checked.Layers {
		if !layer.OK {
			t.Fatalf("journal-owned bytes called corrupt: %s %v", layer.Name, layer.Issues)
		}
	}
}

func TestStagedDistAcceptsOnlyExactPreviousContract(t *testing.T) {
	for _, kind := range []string{"dist.new", "dist.init"} {
		for _, known := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/known=%t", kind, known), func(t *testing.T) {
				ctx := context.Background()
				root, ws := newRejectionWorkspace(t)
				crash := errors.New("stop with bound metadata tree")
				fault := func(point string) error {
					if point == "dist.new.applied" || point == "dist.init.staged" {
						return crash
					}
					return nil
				}
				if kind == "dist.new" {
					if _, err := NewDist(ctx, DistNewOptions{WorkspaceOptions: ws, Repository: "repo", Name: "stable", Format: "deb", Fault: fault}); !errors.Is(err, crash) {
						t.Fatal(err)
					}
				} else {
					cfg, err := config.Load(filepath.Join(root, "sow.yml"))
					if err != nil {
						t.Fatal(err)
					}
					repo := cfg.Repositories["repo"]
					repo.Dists["stable"] = config.DistConfig{Format: "deb"}
					cfg.Repositories["repo"] = repo
					writeManagedConfig(t, root, cfg)
					if _, err := Init(ctx, InitOptions{Dir: root, Fault: fault}); !errors.Is(err, crash) {
						t.Fatal(err)
					}
				}
				store, err := state.OpenExisting(filepath.Join(root, ".sow/repo.db"))
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close()
				pending, err := store.PendingOperations(ctx)
				if err != nil || len(pending) != 1 {
					t.Fatalf("pending=%+v %v", pending, err)
				}
				op := pending[0]
				payload, err := decodeDistPayload(op.PayloadJSON)
				if err != nil {
					t.Fatal(err)
				}
				cfg, err := config.Parse(payload.NewConfig)
				if err != nil {
					t.Fatal(err)
				}
				previous, _, err := effectiveDistConfigFrozenPrevious(cfg, "repo", "stable", *payload.EffectiveSigning)
				if err != nil {
					t.Fatal(err)
				}
				if previous == payload.EffectiveConfigSHA256 {
					t.Fatal("fixture requires a contract change")
				}
				payload.EffectiveConfigSHA256 = previous
				if !known {
					payload.EffectiveConfigSHA256 = strings.Repeat("a", 64)
				}
				wire, _ := json.Marshal(payload)
				if err := store.UpdateOperationPayload(ctx, op.ID, string(wire)); err != nil {
					t.Fatal(err)
				}
				err = recoverDistOperations(ctx, root, "repo", store)
				if !known {
					if !errors.Is(err, ErrIntegrity) {
						t.Fatalf("unknown hash accepted: %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				dist, err := store.GetDist(ctx, "stable")
				if err != nil || dist.EffectiveConfigSHA256 != previous {
					t.Fatalf("old frozen tree mislabeled current: %+v %v", dist, err)
				}
			})
		}
	}
}

func TestAbandonDifferentAttemptPreservesEarlierOrphans(t *testing.T) {
	ctx := context.Background()
	fixture, _, targetRoot := filesystemPublishFixture(t)
	crash := errors.New("stop after payload")
	fault := func(point string) error {
		if point == "publish.payload" {
			return crash
		}
		return nil
	}
	first, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local", Fault: fault})
	if !errors.Is(err, crash) {
		t.Fatal(err)
	}
	abandoned, err := AbandonPublication(ctx, PublicationAbandonOptions{WorkspaceOptions: fixture.options, Target: "local"})
	if err != nil || abandoned.Objects == 0 {
		t.Fatalf("first abandon=%+v %v", abandoned, err)
	}
	store, err := state.OpenReadOnly(filepath.Join(fixture.root, ".sow/repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	var orphan string
	if err := store.DB().QueryRowContext(ctx, `SELECT path FROM publication_abandoned_objects WHERE attempt_identity=? AND phase='payload' LIMIT 1`, first.Attempt).Scan(&orphan); err != nil {
		t.Fatal(err)
	}
	store.Close()
	before, err := os.ReadFile(filepath.Join(targetRoot, filepath.FromSlash(orphan)))
	if err != nil {
		t.Fatal(err)
	}

	epel, err := filepath.Abs("../../../third_party/cavaliergopher-rpm/testdata/epel-release-7-5.noarch.rpm")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: fixture.options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{epel}, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := LocalGC(ctx, LocalGCOptions{WorkspaceOptions: fixture.options, Repository: "repo"}); err != nil {
		t.Fatal(err)
	}
	second, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local", Fault: fault})
	if !errors.Is(err, crash) || second.Attempt == first.Attempt {
		t.Fatalf("second=%+v %v", second, err)
	}
	if result, err := AbandonPublication(ctx, PublicationAbandonOptions{WorkspaceOptions: fixture.options, Target: "local"}); err != nil || result.Phase != "abandoned" {
		t.Fatalf("second abandon=%+v %v", result, err)
	}
	after, err := os.ReadFile(filepath.Join(targetRoot, filepath.FromSlash(orphan)))
	if err != nil || string(after) != string(before) {
		t.Fatalf("earlier orphan changed: %v", err)
	}
	if _, err := Publish(ctx, PublishOptions{WorkspaceOptions: fixture.options, Target: "local"}); err != nil {
		t.Fatal(err)
	}
}

func TestFirstAddAllExcludedCanBuildAgain(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm", Exclude: []config.ExcludeRule{{Name: []string{"centos-release"}}}}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	ws := WorkspaceOptions{Workdir: root, CWD: root}
	input, err := filepath.Abs("../../../third_party/cavaliergopher-rpm/testdata/centos-release-7-2.1511.el7.centos.2.10.x86_64.rpm")
	if err != nil {
		t.Fatal(err)
	}
	added, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: []string{input}, Jobs: 1})
	if err != nil || added.Accepted != 0 || added.Failed != 0 || len(added.Items) != 1 || added.Items[0].Status != "excluded" {
		t.Fatalf("add=%+v err=%v", added, err)
	}
	for range 2 {
		if _, err := Build(ctx, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAddCancelAfterAppliedPreservesCommittedResult(t *testing.T) {
	for _, skip := range []bool{true, false} {
		t.Run(fmt.Sprint(skip), func(t *testing.T) {
			root, ws := newRejectionWorkspace(t)
			paths := collidingRPMInputs(t, root)
			before := managedTestSummary(t, root)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			added, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: paths[:1], Jobs: 1, Skip: skip, Fault: func(point string) error {
				if point == "add.applied" {
					cancel()
				}
				return nil
			}})
			if !errors.Is(err, context.Canceled) || added.Accepted != 1 || added.Failed != 0 || added.Revision != before.DesiredRevision+1 || added.Generation != before.BuiltGeneration || !added.Dirty {
				t.Fatalf("committed cancelled result=%+v before=%+v err=%v", added, before, err)
			}
			if _, err := Build(context.Background(), BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMissingAddStageOnlyTerminatesUncommittedOperation(t *testing.T) {
	for _, applied := range []bool{false, true} {
		t.Run(fmt.Sprint(applied), func(t *testing.T) {
			ctx := context.Background()
			root, ws := newRejectionWorkspace(t)
			paths := collidingRPMInputs(t, root)
			point := "add.staged"
			if applied {
				point = "add.applied"
			}
			crash := errors.New("stop before stage loss")
			added, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: paths[:1], Skip: true, Jobs: 1, Fault: func(got string) error {
				if got == point {
					return crash
				}
				return nil
			}})
			if !errors.Is(err, crash) {
				t.Fatal(err)
			}
			if err := os.RemoveAll(mutationStageRoot(root, "repo", added.Operation)); err != nil {
				t.Fatal(err)
			}
			_, err = Build(ctx, BuildOptions{WorkspaceOptions: ws, Repository: "repo", Jobs: 1})
			if applied {
				if !errors.Is(err, ErrIntegrity) {
					t.Fatalf("missing committed evidence was ignored: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			store, err := state.OpenReadOnly(filepath.Join(root, ".sow/repo.db"))
			if err != nil {
				t.Fatal(err)
			}
			op, err := store.GetOperation(ctx, added.Operation)
			if err != nil {
				t.Fatal(err)
			}
			members, err := store.MembershipDigests(ctx, "el9", false)
			if err != nil {
				t.Fatal(err)
			}
			store.Close()
			if applied {
				if op.Operation.State != state.OperationRecovering || len(members) != 1 {
					t.Fatalf("committed data lost: %+v %v", op.Operation, members)
				}
				return
			}
			if op.Operation.State != state.OperationFailed || len(members) != 0 {
				t.Fatalf("uncommitted legacy operation stuck: %+v %v", op.Operation, members)
			}
			if _, err := Add(ctx, AddOptions{WorkspaceOptions: ws, Repository: "repo", Dists: []string{"el9"}, Paths: paths[:1], Jobs: 1}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
