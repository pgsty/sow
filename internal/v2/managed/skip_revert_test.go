package managed

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

func TestSkippedMutationsCanReturnExactlyToBuiltProjection(t *testing.T) {
	for _, scenario := range []string{"pending add then remove", "built remove then add"} {
		t.Run(scenario, func(t *testing.T) {
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
			rpm := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
			if scenario == "built remove then add" {
				if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
					t.Fatal(err)
				}
				if _, err := Remove(ctx, RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Skip: true, Jobs: 1}); err != nil {
					t.Fatal(err)
				}
				if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Skip: true, Jobs: 1}); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Skip: true, Jobs: 1}); err != nil {
					t.Fatal(err)
				}
				if _, err := Remove(ctx, RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Skip: true, Jobs: 1}); err != nil {
					t.Fatal(err)
				}
			}

			status, err := Status(ctx, StatusOptions{WorkspaceOptions: options, Repository: "repo"})
			if err != nil || status.Status != "clean" || !status.ReadyToCopy || status.Pending.Count != 0 || status.Pending.Bytes != 0 {
				t.Fatalf("reverted skipped mutation status=%#v err=%v", status, err)
			}
			checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
			if err != nil || checked.Status != "clean" || !checked.ReadyToCopy {
				t.Fatalf("reverted skipped mutation check=%#v err=%v", checked, err)
			}
			store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
			if err != nil {
				t.Fatal(err)
			}
			operation, operationErr := store.LastOperation(ctx)
			closeErr := store.Close()
			if operationErr != nil || closeErr != nil || operation == nil || operation.State != state.OperationDone {
				t.Fatalf("reverted skipped mutation operation=%#v operationErr=%v closeErr=%v", operation, operationErr, closeErr)
			}
			beforeGeneration := status.BuiltGeneration
			built, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
			if err != nil || !built.Noop || built.Generation != beforeGeneration || built.Dirty {
				t.Fatalf("reverted skipped mutation no-op build=%#v err=%v", built, err)
			}
		})
	}
}

func TestSkippedRevertKeepsRepositoryDirtyWhenAnotherDistDiffers(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	options := WorkspaceOptions{Workdir: root, CWD: root}
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
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9", "el10"}, Paths: []string{rpm}, Skip: true, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := Remove(ctx, RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Skip: true, Jobs: 1}); err != nil {
		t.Fatal(err)
	}
	status, err := Status(ctx, StatusOptions{WorkspaceOptions: options, Repository: "repo"})
	if err != nil || status.Status != "dirty" || status.ReadyToCopy || status.Pending.Count != 1 {
		t.Fatalf("remaining dirty Dist status=%#v err=%v", status, err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	summary, err := store.Summary(ctx)
	if err != nil || summary.Status != "dirty" || summary.DirtyReason == "" {
		t.Fatalf("remaining dirty Dist summary=%#v err=%v", summary, err)
	}
	operation, err := store.LastOperation(ctx)
	if err != nil || operation == nil || operation.State != state.OperationDoneDirty {
		t.Fatalf("remaining dirty Dist operation=%#v err=%v", operation, err)
	}
}

func newMutationConvergenceFixture(t *testing.T) (context.Context, string, WorkspaceOptions, string) {
	t.Helper()
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
	rpm := decodeManagedFixture(t, filepath.Join("..", "..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(inputs, "package.rpm"))
	return ctx, root, options, rpm
}

func TestDefaultRemoveConvergesSkippedAddWithoutPhysicalGeneration(t *testing.T) {
	ctx, root, options, rpm := newMutationConvergenceFixture(t)
	skipped, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Skip: true, Jobs: 1})
	if err != nil || !skipped.Dirty {
		t.Fatalf("skipped add=%#v err=%v", skipped, err)
	}
	before := managedTestSummary(t, root)
	beforeTree, err := publicTreeSnapshot(root, "repo")
	if err != nil {
		t.Fatal(err)
	}
	preview, err := Remove(ctx, RemoveOptions{
		WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"},
		Packages: []string{"pgdg-redhat-nonfree-repo"}, Check: true, Jobs: 1,
	})
	if err != nil || preview.Dirty || preview.Generation != before.BuiltGeneration || preview.Revision != before.DesiredRevision+1 || len(preview.Changes) != 0 || len(preview.Removed) != 1 {
		t.Fatalf("converging preview=%#v before=%#v err=%v", preview, before, err)
	}
	afterPreview := managedTestSummary(t, root)
	afterPreviewTree, err := publicTreeSnapshot(root, "repo")
	if err != nil {
		t.Fatal(err)
	}
	if afterPreview != before || !reflect.DeepEqual(afterPreviewTree, beforeTree) {
		t.Fatalf("preview mutated repository: before=%#v after=%#v", before, afterPreview)
	}
	removed, err := Remove(ctx, RemoveOptions{
		WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"},
		Packages: []string{"pgdg-redhat-nonfree-repo"}, Jobs: 1,
	})
	if err != nil || removed.Dirty || removed.Generation != before.BuiltGeneration || removed.Revision != before.DesiredRevision+1 || len(removed.Changes) != 0 {
		t.Fatalf("converging remove=%#v before=%#v err=%v", removed, before, err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	detail, detailErr := store.GetOperation(ctx, removed.Operation)
	pending, pendingErr := store.PendingOperations(ctx)
	summary, summaryErr := store.Summary(ctx)
	closeErr := store.Close()
	if err := errors.Join(detailErr, pendingErr, summaryErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if detail.Operation.State != state.OperationDone || len(pending) != 0 || summary.Status != "clean" || summary.BuiltGeneration != before.BuiltGeneration {
		t.Fatalf("converged detail=%#v pending=%#v summary=%#v", detail.Operation, pending, summary)
	}
}

func TestConvergingMutationRecoveryFromStagedState(t *testing.T) {
	for _, scenario := range []string{"add back to Built", "remove back to Built"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, root, options, rpm := newMutationConvergenceFixture(t)
			injected := errors.New("injected staged crash")
			var operationID string
			if scenario == "add back to Built" {
				if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
					t.Fatal(err)
				}
				if _, err := Remove(ctx, RemoveOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Skip: true, Jobs: 1}); err != nil {
					t.Fatal(err)
				}
				interrupted, err := Add(ctx, AddOptions{
					WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1,
					Fault: func(point string) error {
						if point == "add.staged" {
							return injected
						}
						return nil
					},
				})
				if !errors.Is(err, injected) {
					t.Fatalf("interrupted add=%#v err=%v", interrupted, err)
				}
				operationID = interrupted.Operation
			} else {
				if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Skip: true, Jobs: 1}); err != nil {
					t.Fatal(err)
				}
				interrupted, err := Remove(ctx, RemoveOptions{
					WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Packages: []string{"pgdg-redhat-nonfree-repo"}, Jobs: 1,
					Fault: func(point string) error {
						if point == "rm.staged" {
							return injected
						}
						return nil
					},
				})
				if !errors.Is(err, injected) {
					t.Fatalf("interrupted remove=%#v err=%v", interrupted, err)
				}
				operationID = interrupted.Operation
			}
			before := managedTestSummary(t, root)
			store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
			if err != nil {
				t.Fatal(err)
			}
			if err := recoverDistOperations(ctx, root, "repo", store); err != nil {
				store.Close()
				t.Fatal(err)
			}
			detail, detailErr := store.GetOperation(ctx, operationID)
			pending, pendingErr := store.PendingOperations(ctx)
			summary, summaryErr := store.Summary(ctx)
			closeErr := store.Close()
			if err := errors.Join(detailErr, pendingErr, summaryErr, closeErr); err != nil {
				t.Fatal(err)
			}
			if detail.Operation.State != state.OperationDone || len(pending) != 0 || summary.Status != "clean" || summary.BuiltGeneration != before.BuiltGeneration {
				t.Fatalf("recovery detail=%#v pending=%#v before=%#v summary=%#v", detail.Operation, pending, before, summary)
			}
		})
	}
}

func TestSkippedNoopAddRecoveryPreservesEmptyBuildScope(t *testing.T) {
	ctx, root, options, rpm := newMutationConvergenceFixture(t)
	if _, err := Add(ctx, AddOptions{
		WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1,
	}); err != nil {
		t.Fatal(err)
	}
	before := managedTestSummary(t, root)
	injected := errors.New("injected staged crash")
	interrupted, err := Add(ctx, AddOptions{
		WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Skip: true, Jobs: 1,
		Fault: func(point string) error {
			if point == "add.staged" {
				return injected
			}
			return nil
		},
	})
	if !errors.Is(err, injected) {
		t.Fatalf("interrupted add=%#v err=%v", interrupted, err)
	}

	store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	detail, detailErr := store.GetOperation(ctx, interrupted.Operation)
	if detailErr == nil && !json.Valid([]byte(detail.Operation.PayloadJSON)) {
		detailErr = errors.New("staged mutation payload is invalid JSON")
	}
	if detailErr == nil {
		var payload mutationOperationPayload
		detailErr = json.Unmarshal([]byte(detail.Operation.PayloadJSON), &payload)
		if detailErr == nil && payload.BuildDists == nil {
			detailErr = errors.New("empty staged build scope decoded as nil")
		}
	}
	if detailErr == nil {
		detailErr = recoverDistOperations(ctx, root, "repo", store)
	}
	detail, recoveredDetailErr := store.GetOperation(ctx, interrupted.Operation)
	pending, pendingErr := store.PendingOperations(ctx)
	after, summaryErr := store.Summary(ctx)
	closeErr := store.Close()
	if err := errors.Join(detailErr, recoveredDetailErr, pendingErr, summaryErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if detail.Operation.State != state.OperationDone || len(pending) != 0 || after != before {
		t.Fatalf("recovered no-op add detail=%#v pending=%#v before=%#v after=%#v", detail.Operation, pending, before, after)
	}
}

func assertRecoveredRenderingJobs(t *testing.T, root, operationID string, want int) {
	t.Helper()
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	detail, detailErr := store.GetOperation(context.Background(), operationID)
	closeErr := store.Close()
	if err := errors.Join(detailErr, closeErr); err != nil {
		t.Fatal(err)
	}
	for _, event := range detail.Events {
		var progress struct {
			Kind  string `json:"kind"`
			Phase string `json:"phase"`
			Jobs  int    `json:"jobs"`
		}
		if json.Unmarshal([]byte(event.DetailJSON), &progress) == nil && progress.Kind == "build_progress" && progress.Phase == "rendering" {
			if progress.Jobs != want {
				t.Fatalf("recovered rendering jobs=%d, want %d", progress.Jobs, want)
			}
			return
		}
	}
	t.Fatalf("operation %s has no recovered rendering progress: %#v", operationID, detail.Events)
}

func TestRemoveAndBuildRecoveryPreserveJournaledJobs(t *testing.T) {
	for _, command := range []string{"rm", "build"} {
		t.Run(command, func(t *testing.T) {
			ctx, root, options, rpm := newMutationConvergenceFixture(t)
			if command == "rm" {
				if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Jobs: 1}); err != nil {
					t.Fatal(err)
				}
			} else if _, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Skip: true, Jobs: 1}); err != nil {
				t.Fatal(err)
			}
			injected := errors.New("injected after Desired commit")
			operationID := ""
			if command == "rm" {
				result, err := Remove(ctx, RemoveOptions{
					WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"},
					Packages: []string{"pgdg-redhat-nonfree-repo"}, Jobs: 3,
					Fault: func(point string) error {
						if point == "rm.applied" {
							return injected
						}
						return nil
					},
				})
				if !errors.Is(err, injected) {
					t.Fatalf("interrupted remove=%#v err=%v", result, err)
				}
				operationID = result.Operation
			} else {
				result, err := Build(ctx, BuildOptions{
					WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Jobs: 4,
					Fault: func(point string) error {
						if point == "build.command.applied" {
							return injected
						}
						return nil
					},
				})
				if !errors.Is(err, injected) {
					t.Fatalf("interrupted build=%#v err=%v", result, err)
				}
				operationID = result.Operation
			}
			store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
			if err != nil {
				t.Fatal(err)
			}
			recoverErr := recoverDistOperations(ctx, root, "repo", store)
			closeErr := store.Close()
			if err := errors.Join(recoverErr, closeErr); err != nil {
				t.Fatal(err)
			}
			want := 3
			if command == "build" {
				want = 4
			}
			assertRecoveredRenderingJobs(t, root, operationID, want)
		})
	}
}
