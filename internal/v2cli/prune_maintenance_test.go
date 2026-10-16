package v2cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/v2/managed"
	"github.com/pgsty/sow/internal/v2/state"
)

func TestMainDistReadsPendingMaintenance(t *testing.T) {
	for _, kind := range []string{"local.gc", "log.prune"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			assertCLISuccess(t, []string{"init", root}, "initialized")
			assertCLISuccess(t, []string{"repo", "new", "repo", "-C", root}, "created repo")
			for _, dist := range []string{"el9", "el10"} {
				assertCLISuccess(t, []string{"dist", "new", dist, "--format", "rpm", "-C", root, "-r", "repo"}, "created "+dist)
			}
			if kind == "local.gc" {
				rpm := decodeCLIFixture(t, filepath.Join("..", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(t.TempDir(), "pkg.rpm"))
				assertCLISuccess(t, []string{"add", rpm, "-C", root, "-r", "repo", "-d", "el9", "--json"}, `"accepted":1`)
				// Removing the owning Dist leaves an unreferenced Pool object for
				// the real GC command without editing its journal or root tables.
				assertCLISuccess(t, []string{"dist", "rm", "el9", "--force", "-C", root, "-r", "repo", "--json"}, `"removed":true`)
				assertCLISuccess(t, []string{"dist", "new", "el9", "--format", "rpm", "-C", root, "-r", "repo"}, "created el9")
			}
			ctx := context.Background()
			options := managed.WorkspaceOptions{Workdir: root, CWD: root}
			injected := errors.New("stop maintenance after its durable plan")
			fault := func(point string) error {
				if point == "gc.planned" || point == "log.prune.planned" {
					return injected
				}
				return nil
			}
			var err error
			if kind == "local.gc" {
				_, err = managed.LocalGC(ctx, managed.LocalGCOptions{WorkspaceOptions: options, Repository: "repo", Fault: fault})
			} else {
				_, err = managed.PruneLog(ctx, managed.LogPruneOptions{WorkspaceOptions: options, Repository: "repo", Before: time.Now().Add(time.Hour), Fault: fault})
			}
			if !errors.Is(err, injected) {
				t.Fatalf("maintenance did not reach its durable plan: %v", err)
			}
			store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
			if err != nil {
				t.Fatal(err)
			}
			pending, pendingErr := store.PendingOperations(ctx)
			if err := errors.Join(pendingErr, store.Close()); err != nil || len(pending) != 1 || pending[0].Kind != kind {
				t.Fatalf("pending=%#v err=%v", pending, err)
			}
			id := pending[0].ID
			for _, operationState := range []state.OperationState{state.OperationPlanned, state.OperationRecovering, state.OperationFailed} {
				if operationState != state.OperationPlanned {
					store, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
					if err != nil {
						t.Fatal(err)
					}
					if err := errors.Join(store.SetOperationState(ctx, id, operationState, ""), store.Close()); err != nil {
						t.Fatal(err)
					}
				}
				wantStatus := "recovering"
				if operationState == state.OperationFailed {
					wantStatus = "clean"
				}
				reason := fmt.Sprintf("operation %s is %s", id, operationState)
				for _, command := range [][]string{{"dist", "ls"}, {"dist", "show", "el9"}, {"dist", "show", "el10"}} {
					args := append(append([]string{}, command...), "-C", root, "-r", "repo")
					stdout, stderr, code := runCLI(args)
					if code != ExitOK || stderr != "" || operationState != state.OperationFailed && !strings.Contains(stdout, reason) {
						t.Fatalf("%v human %s: code=%d stdout=%q stderr=%q", command, operationState, code, stdout, stderr)
					}
					stdout, stderr, code = runCLI(append(args, "--json"))
					if code != ExitOK || stderr != "" {
						t.Fatalf("%v JSON %s: code=%d stdout=%q stderr=%q", command, operationState, code, stdout, stderr)
					}
					var envelope struct {
						Schema     string          `json:"schema"`
						Command    string          `json:"command"`
						OK         bool            `json:"ok"`
						Repository string          `json:"repository"`
						Operation  any             `json:"operation"`
						Result     json.RawMessage `json:"result"`
						Errors     []CLIError      `json:"errors"`
					}
					decoder := json.NewDecoder(strings.NewReader(stdout))
					decoder.DisallowUnknownFields()
					if err := decoder.Decode(&envelope); err != nil || envelope.Schema != OutputSchema || envelope.Command != strings.Join(command[:2], " ") || !envelope.OK || envelope.Repository != "repo" || envelope.Operation != nil || len(envelope.Errors) != 0 {
						t.Fatalf("envelope=%#v err=%v", envelope, err)
					}
					var dists []managed.DistInfo
					if command[1] == "ls" {
						var result struct {
							Dists []managed.DistInfo `json:"dists"`
						}
						if err := json.Unmarshal(envelope.Result, &result); err != nil || len(result.Dists) != 2 {
							t.Fatalf("dist list result=%s err=%v", envelope.Result, err)
						}
						dists = result.Dists
					} else {
						var result managed.DistInfo
						if err := json.Unmarshal(envelope.Result, &result); err != nil || result.Name != command[2] {
							t.Fatalf("dist show result=%s err=%v", envelope.Result, err)
						}
						dists = []managed.DistInfo{result}
					}
					for _, dist := range dists {
						if dist.Status != wantStatus || dist.Dirty != (wantStatus == "recovering") || wantStatus == "recovering" && !strings.Contains(strings.Join(dist.DirtyReasons, "\n"), reason) {
							t.Fatalf("%s dist state=%#v, want %s", operationState, dist, wantStatus)
						}
					}
				}
			}
		})
	}
}

func TestMainPruneDefersMaintenanceAndAddWorksWhileReaderRemains(t *testing.T) {
	root := t.TempDir()
	assertCLISuccess(t, []string{"init", root}, "initialized")
	assertCLISuccess(t, []string{"repo", "new", "repo", "-C", root}, "created repo")
	assertCLISuccess(t, []string{"dist", "new", "noble", "--format", "deb", "-C", root, "-r", "repo"}, "created noble")
	ctx := context.Background()
	writer, err := state.OpenExisting(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.BeginOperation(ctx, state.Operation{ID: "999", Kind: "add", State: state.OperationPlanned, PayloadJSON: `{}`}); err != nil {
		t.Fatal(err)
	}
	if err := writer.FailOperation(ctx, "999", "cancelled", "cancelled", `{}`); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := state.OpenReadOnly(filepath.Join(root, ".sow", "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	snapshot, err := reader.DB().BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Rollback()
	var count int
	if err := snapshot.QueryRow(`SELECT count(*) FROM operations WHERE id = '999'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("pin reader: count=%d err=%v", count, err)
	}
	cutoff := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	args := []string{"log", "prune", cutoff, "-C", root, "-r", "repo"}
	stdout, stderr, code := runCLI(args)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, "log deletion committed; space reclamation deferred") {
		t.Fatalf("prune human code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	stdout, stderr, code = runCLI(append(args, "--json"))
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"compaction_deferred":true`) {
		t.Fatalf("prune JSON code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	deb := decodeCLIFixture(t, filepath.Join("..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"), filepath.Join(t.TempDir(), "pkg.deb"))
	assertCLISuccess(t, []string{"add", deb, "-C", root, "-r", "repo", "-d", "noble", "--json"}, `"accepted":1`)
	if err := snapshot.QueryRow(`SELECT count(*) FROM operations WHERE id = '999'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("reader snapshot changed: count=%d err=%v", count, err)
	}
}
