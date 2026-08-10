package managed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

func TestLogDetailExportAndSafePrune(t *testing.T) {
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
	added, err := Add(ctx, AddOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Skip: true, Jobs: 1})
	if err != nil {
		t.Fatal(err)
	}
	built, err := Build(ctx, BuildOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Jobs: 1})
	if err != nil {
		t.Fatal(err)
	}
	listed, err := Log(ctx, LogOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Dists: []string{"el9"}})
	if err != nil || len(listed.Operations) < 2 {
		t.Fatalf("listed=%#v err=%v", listed, err)
	}
	foundLifecycle := false
	for _, operation := range listed.Operations {
		if operation.Kind == "dist.init" {
			foundLifecycle = true
		}
	}
	if !foundLifecycle {
		t.Fatalf("Dist-filtered log omitted Dist lifecycle operation: %#v", listed.Operations)
	}
	detail, err := Log(ctx, LogOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Operation: added.Operation})
	if err != nil || detail.Detail == nil || detail.Detail.DurationMS < 0 || len(detail.Detail.Events) < 3 || len(detail.Detail.Packages) != 1 || len(detail.Detail.Memberships) != 1 {
		t.Fatalf("detail=%#v err=%v", detail, err)
	}
	var exported bytes.Buffer
	count, err := ExportLog(ctx, LogOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo"}, &exported)
	if err != nil || count < 2 || len(strings.Split(strings.TrimSpace(exported.String()), "\n")) != count {
		t.Fatalf("count=%d export=%q err=%v", count, exported.String(), err)
	}
	for _, line := range strings.Split(strings.TrimSpace(exported.String()), "\n") {
		var record state.OperationDetail
		if err := json.Unmarshal([]byte(line), &record); err != nil || record.Operation.ID == "" {
			t.Fatalf("line=%q record=%#v err=%v", line, record, err)
		}
	}
	pruned, err := PruneLog(ctx, LogPruneOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Before: time.Now().Add(time.Hour)})
	if err != nil || pruned.Pruned == 0 {
		t.Fatalf("pruned=%#v err=%v", pruned, err)
	}
	buildDetail, err := Log(ctx, LogOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Operation: built.Operation})
	if err != nil || buildDetail.Detail == nil || len(buildDetail.Detail.Files) == 0 {
		t.Fatalf("generation operation was pruned: %#v err=%v", buildDetail, err)
	}
	zero := state.GenerationID(0)
	if changes, err := Changes(ctx, ChangesOptions{WorkspaceOptions: WorkspaceOptions{Workdir: root, CWD: root}, Repository: "repo", Base: &zero}); err != nil || changes.Generation != built.Generation || len(changes.Changes) == 0 {
		t.Fatalf("changes after prune=%#v err=%v", changes, err)
	}
}

func TestLogAuditsPerDistAddAndBuildPolicyOutcomes(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	options := WorkspaceOptions{Workdir: root, CWD: root}
	exclude := []config.ExcludeRule{{Name: []string{"pgdg-redhat-nonfree-repo"}}}
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{
		"el9":  {Format: "rpm"},
		"el10": {Format: "rpm", Exclude: exclude},
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
	added, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9", "el10"}, Paths: []string{rpm}, Skip: true, Jobs: 1})
	if err != nil || added.Accepted != 1 || len(added.Items) != 1 || !reflect.DeepEqual(added.Items[0].Dists, map[string]string{"el9": "accepted", "el10": "excluded"}) {
		t.Fatalf("add=%#v err=%v", added, err)
	}
	logged, err := Log(ctx, LogOptions{WorkspaceOptions: options, Repository: "repo", Operation: added.Operation})
	if err != nil || logged.Detail == nil || len(logged.Detail.Packages) != 1 {
		t.Fatalf("add log=%#v err=%v", logged, err)
	}
	if !reflect.DeepEqual(logged.Detail.Packages[0].Dists, added.Items[0].Dists) {
		t.Fatalf("package Dist evidence=%#v", logged.Detail.Packages[0])
	}
	if !hasMembershipAudit(logged.Detail.Memberships, "el9", added.Items[0].SHA256, "add") || !hasMembershipAudit(logged.Detail.Memberships, "el10", added.Items[0].SHA256, "exclude") {
		t.Fatalf("add membership evidence=%#v", logged.Detail.Memberships)
	}

	// Tightening el9 policy makes build remove the prior membership and retain
	// both the state delta and the policy reason in one terminal Operation.
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{
		"el9":  {Format: "rpm", Exclude: exclude},
		"el10": {Format: "rpm", Exclude: exclude},
	}}
	writeManagedConfig(t, root, cfg)
	built, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9", "el10"}, Jobs: 1})
	if err != nil || built.Dirty {
		t.Fatalf("build=%#v err=%v", built, err)
	}
	logged, err = Log(ctx, LogOptions{WorkspaceOptions: options, Repository: "repo", Operation: built.Operation})
	if err != nil || logged.Detail == nil {
		t.Fatalf("build log=%#v err=%v", logged, err)
	}
	if !hasMembershipAudit(logged.Detail.Memberships, "el9", added.Items[0].SHA256, "remove") || !hasMembershipAudit(logged.Detail.Memberships, "el9", added.Items[0].SHA256, "exclude") {
		t.Fatalf("build membership evidence=%#v", logged.Detail.Memberships)
	}
	var exported bytes.Buffer
	if count, err := ExportLog(ctx, LogOptions{WorkspaceOptions: options, Repository: "repo"}, &exported); err != nil || count == 0 || !strings.Contains(exported.String(), `"dists":{"el10":"excluded","el9":"accepted"}`) || !strings.Contains(exported.String(), `"action":"exclude"`) {
		t.Fatalf("export count=%d body=%q err=%v", count, exported.String(), err)
	}
}

func hasMembershipAudit(items []state.OperationMembership, dist, digest, action string) bool {
	for _, item := range items {
		if item.DistName == dist && item.PackageSHA256 == digest && item.Action == action {
			return true
		}
	}
	return false
}

func TestLogExportPaginatesWithoutTruncation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	options := WorkspaceOptions{Workdir: root, CWD: root}
	var baseline bytes.Buffer
	baselineCount, err := ExportLog(ctx, LogOptions{WorkspaceOptions: options, Repository: "repo"}, &baseline)
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	const extra = exportLogPageSize + 17
	inserted := make(map[string]bool, extra)
	for index := range extra {
		id := fmt.Sprintf("8%018d", index+1)
		created := time.Date(2020, 1, 1, 0, 0, 0, index+1, time.UTC).Format("2006-01-02T15:04:05.000000000Z")
		if _, err := store.DB().ExecContext(ctx, `INSERT INTO operations(id, kind, state, payload_json, result_json, created_at, updated_at) VALUES (?, 'synthetic', 'done', ?, '{}', ?, ?)`, id, `{"version":1,"repository":"repo","kind":"synthetic","dists":["el9"]}`, created, created); err != nil {
			store.Close()
			t.Fatal(err)
		}
		inserted[id] = false
	}
	if err := store.Checkpoint(ctx); err != nil {
		store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	var exported bytes.Buffer
	count, err := ExportLog(ctx, LogOptions{WorkspaceOptions: options, Repository: "repo"}, &exported)
	if err != nil || count != baselineCount+extra {
		t.Fatalf("count=%d baseline=%d err=%v", count, baselineCount, err)
	}
	for _, line := range strings.Split(strings.TrimSpace(exported.String()), "\n") {
		var detail state.OperationDetail
		if err := json.Unmarshal([]byte(line), &detail); err != nil {
			t.Fatal(err)
		}
		if _, ok := inserted[detail.Operation.ID]; ok {
			inserted[detail.Operation.ID] = true
		}
	}
	for id, seen := range inserted {
		if !seen {
			t.Fatalf("terminal operation %s was omitted from export", id)
		}
	}
}

func TestLogCanFilterRemovedHistoricalDist(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	options := WorkspaceOptions{Workdir: root, CWD: root}
	cfg := config.Default()
	cfg.Repositories["repo"] = config.RepositoryConfig{Dists: map[string]config.DistConfig{"el9": {Format: "rpm"}}}
	writeManagedConfig(t, root, cfg)
	if _, err := Init(ctx, InitOptions{Dir: root}); err != nil {
		t.Fatal(err)
	}
	removed, err := RemoveDistResult(ctx, DistRemoveOptions{WorkspaceOptions: options, Repository: "repo", Name: "el9"})
	if err != nil || !removed.Removed {
		t.Fatalf("remove Dist=%#v err=%v", removed, err)
	}
	history, err := Log(ctx, LogOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, operation := range history.Operations {
		if operation.Kind == "dist.rm" {
			found = true
		}
	}
	if !found {
		t.Fatalf("removed Dist history omitted removal operation: %#v", history.Operations)
	}
}

func TestLogPruneRecoversFirstAndPreservesCurrentGeneration(t *testing.T) {
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

	injected := errors.New("injected pointer failure")
	failedBuild, err := Build(ctx, BuildOptions{
		WorkspaceOptions: options,
		Repository:       "repo",
		Jobs:             1,
		Fault: func(point string) error {
			if point == "build.pointer.el9" {
				return injected
			}
			return nil
		},
	})
	if !errors.Is(err, injected) || failedBuild.Operation == "" {
		t.Fatalf("failed build=%#v err=%v", failedBuild, err)
	}
	var beforeRecovery bytes.Buffer
	count, err := ExportLog(ctx, LogOptions{WorkspaceOptions: options, Repository: "repo"}, &beforeRecovery)
	if err != nil || count == 0 || strings.Contains(beforeRecovery.String(), failedBuild.Operation) {
		t.Fatalf("terminal export included pending operation: count=%d export=%q err=%v", count, beforeRecovery.String(), err)
	}

	pruned, err := PruneLog(ctx, LogPruneOptions{WorkspaceOptions: options, Repository: "repo", Before: time.Now().Add(time.Hour)})
	if err != nil || pruned.Pruned == 0 {
		t.Fatalf("prune after recovery=%#v err=%v", pruned, err)
	}
	status, err := Status(ctx, StatusOptions{WorkspaceOptions: options, Repository: "repo"})
	if err != nil || status.Status != "clean" || !status.ReadyToCopy || status.BuiltGeneration < 1 {
		t.Fatalf("status after prune=%#v err=%v", status, err)
	}
	zero := state.GenerationID(0)
	changes, err := Changes(ctx, ChangesOptions{WorkspaceOptions: options, Repository: "repo", Base: &zero})
	if err != nil || changes.Generation != status.BuiltGeneration || len(changes.Changes) == 0 {
		t.Fatalf("changes after recovered prune=%#v err=%v", changes, err)
	}
	detail, err := Log(ctx, LogOptions{WorkspaceOptions: options, Repository: "repo", Operation: failedBuild.Operation})
	if err != nil || detail.Detail == nil || detail.Detail.Operation.State != state.OperationDone || len(detail.Detail.Files) == 0 {
		t.Fatalf("recovered generation operation was pruned: %#v err=%v", detail, err)
	}
	noop, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
	if err != nil || !noop.Noop || noop.Generation != status.BuiltGeneration || noop.Dirty {
		t.Fatalf("post-prune build=%#v err=%v", noop, err)
	}
	store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	pending, pendingErr := store.PendingOperations(ctx)
	closeErr := store.Close()
	if err := errors.Join(pendingErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending operations after prune: %#v", pending)
	}
	entries, err := os.ReadDir(filepath.Join(root, ".sow", "repo", "stage"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("stage after prune: entries=%v err=%v", entries, err)
	}
}

func TestLogPruneCrashPhasesRecoverWithoutLosingGenerationOrChanges(t *testing.T) {
	for _, point := range []string{
		"log.prune.planned",
		"log.prune.staged",
		"log.prune.applied",
		"log.prune.done",
	} {
		t.Run(strings.TrimPrefix(point, "log.prune."), func(t *testing.T) {
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
			added, err := Add(ctx, AddOptions{WorkspaceOptions: options, Repository: "repo", Dists: []string{"el9"}, Paths: []string{rpm}, Skip: true, Jobs: 1})
			if err != nil {
				t.Fatal(err)
			}
			built, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
			if err != nil || built.Dirty || built.Noop {
				t.Fatalf("baseline build=%#v err=%v", built, err)
			}
			zero := state.GenerationID(0)
			before, err := Changes(ctx, ChangesOptions{WorkspaceOptions: options, Repository: "repo", Base: &zero})
			if err != nil || before.Generation != built.Generation || len(before.Changes) == 0 {
				t.Fatalf("baseline changes=%#v err=%v", before, err)
			}

			injected := errors.New("injected log prune crash")
			pruned, err := PruneLog(ctx, LogPruneOptions{
				WorkspaceOptions: options,
				Repository:       "repo",
				Before:           time.Now().Add(time.Hour),
				Fault: func(observed string) error {
					if observed == point {
						return injected
					}
					return nil
				},
			})
			if !errors.Is(err, injected) || pruned.Operation == "" {
				t.Fatalf("faulted prune=%#v err=%v", pruned, err)
			}

			// The next ordinary writer must recover planned/staged/applied prune
			// state before doing its own no-op build. At the done fault point the
			// same path proves that repeating after the committed terminal state
			// has no side effect.
			noop, err := Build(ctx, BuildOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
			if err != nil || !noop.Noop || noop.Dirty || noop.Generation != built.Generation {
				t.Fatalf("post-crash writer=%#v err=%v", noop, err)
			}
			status, err := Status(ctx, StatusOptions{WorkspaceOptions: options, Repository: "repo"})
			if err != nil || status.Status != "clean" || !status.ReadyToCopy || status.BuiltGeneration != built.Generation {
				t.Fatalf("post-recovery status=%#v err=%v", status, err)
			}
			checked, err := Check(ctx, CheckOptions{WorkspaceOptions: options, Repository: "repo", Jobs: 1})
			if err != nil || checked.Status != "clean" || !checked.ReadyToCopy {
				t.Fatalf("post-recovery check=%#v err=%v", checked, err)
			}
			after, err := Changes(ctx, ChangesOptions{WorkspaceOptions: options, Repository: "repo", Base: &zero})
			if err != nil || after.Generation != before.Generation || !reflect.DeepEqual(after.Changes, before.Changes) {
				t.Fatalf("changes changed across prune crash:\nbefore=%#v\nafter=%#v\nerr=%v", before, after, err)
			}
			if _, err := Log(ctx, LogOptions{WorkspaceOptions: options, Repository: "repo", Operation: added.Operation}); !errors.Is(err, ErrRejected) {
				t.Fatalf("eligible terminal operation survived prune: %v", err)
			}
			generationDetail, err := Log(ctx, LogOptions{WorkspaceOptions: options, Repository: "repo", Operation: built.Operation})
			if err != nil || generationDetail.Detail == nil || generationDetail.Detail.Operation.State != state.OperationDone || len(generationDetail.Detail.Files) == 0 {
				t.Fatalf("referenced generation operation was pruned: %#v err=%v", generationDetail, err)
			}
			pruneDetail, err := Log(ctx, LogOptions{WorkspaceOptions: options, Repository: "repo", Operation: pruned.Operation})
			if err != nil || pruneDetail.Detail == nil || pruneDetail.Detail.Operation.State != state.OperationDone {
				t.Fatalf("prune journal did not recover to done: %#v err=%v", pruneDetail, err)
			}
			var result struct {
				Pruned int64 `json:"pruned"`
			}
			if err := json.Unmarshal([]byte(pruneDetail.Detail.Operation.ResultJSON), &result); err != nil || result.Pruned < 1 {
				t.Fatalf("prune result=%q decoded=%#v err=%v", pruneDetail.Detail.Operation.ResultJSON, result, err)
			}
			store, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
			if err != nil {
				t.Fatal(err)
			}
			pending, pendingErr := store.PendingOperations(ctx)
			closeErr := store.Close()
			if err := errors.Join(pendingErr, closeErr); err != nil {
				t.Fatal(err)
			}
			if len(pending) != 0 {
				t.Fatalf("pending operations after recovery: %#v", pending)
			}
		})
	}
}
