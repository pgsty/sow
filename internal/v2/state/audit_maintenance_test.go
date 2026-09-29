package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestPruneCompletesWithPinnedReaderAndAllowsFurtherWrites(t *testing.T) {
	ctx := context.Background()
	writer, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	for _, op := range []Operation{{ID: "1", Kind: "add", State: OperationPlanned, PayloadJSON: `{}`}, {ID: "2", Kind: "log.prune", State: OperationStaged, PayloadJSON: `{}`}} {
		if err := writer.BeginOperation(ctx, op); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.FailOperation(ctx, "1", "cancelled", "cancelled", `{}`); err != nil {
		t.Fatal(err)
	}
	reader, err := OpenReadOnly(writer.path)
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
	if err := snapshot.QueryRow(`SELECT count(*) FROM operations WHERE id = '1'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("pin old audit record: count=%d err=%v", count, err)
	}
	started := time.Now()
	pruned, err := writer.ApplyPruneOperation(ctx, "2", time.Now().Add(time.Hour))
	if err != nil || pruned != 1 {
		t.Fatalf("pruned=%d err=%v", pruned, err)
	}
	if err := writer.FinishPruneOperation(ctx, "2"); err != nil {
		t.Fatal(err)
	}
	operation, err := writer.GetOperationSummary(ctx, "2")
	if err != nil || operation.State != OperationDone {
		t.Fatalf("prune journal=%v err=%v", operation, err)
	}
	var result struct {
		Pruned             int  `json:"pruned"`
		CompactionDeferred bool `json:"compaction_deferred"`
	}
	if err := json.Unmarshal([]byte(operation.ResultJSON), &result); err != nil || result.Pruned != 1 || !result.CompactionDeferred {
		t.Fatalf("prune result=%s err=%v", operation.ResultJSON, err)
	}
	if err := writer.BeginOperation(ctx, Operation{ID: "3", Kind: "add", State: OperationPlanned, PayloadJSON: `{}`}); err != nil {
		t.Fatalf("new write blocked by completed prune: %v", err)
	}
	if err := writer.FailOperation(ctx, "3", "cancelled", "cancelled", `{}`); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed >= 4*time.Second {
		t.Fatalf("maintenance used the normal 5-second busy wait: %s", elapsed)
	}
	if err := snapshot.QueryRow(`SELECT count(*) FROM operations WHERE id = '1'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("reader lost its old snapshot: count=%d err=%v", count, err)
	}
	if err := snapshot.Rollback(); err != nil {
		t.Fatal(err)
	}
	if deferred, err := writer.compactAudit(ctx); err != nil || deferred {
		t.Fatalf("reclaim after reader exit: deferred=%t err=%v", deferred, err)
	}
	if err := writer.DB().QueryRow(`SELECT count(*) FROM operations WHERE id = '1'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("logical prune lost: count=%d err=%v", count, err)
	}
}

func TestPruneDoesNotHideVacuumErrors(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.DB().Exec(`PRAGMA query_only = ON`); err != nil {
		t.Fatal(err)
	}
	defer store.DB().Exec(`PRAGMA query_only = OFF`)
	if deferred, err := store.compactAudit(context.Background()); err == nil || deferred {
		t.Fatalf("read-only failure was treated as maintenance busy: deferred=%t err=%v", deferred, err)
	}
}

func TestFailOperationCorrectsUncommittedPackageAuditOnly(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.BeginOperation(ctx, Operation{ID: "1", Kind: "add", State: OperationStaged, PayloadJSON: `{}`}); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordOperationPackages(ctx, "1", []OperationPackage{
		{InputPath: "one.rpm", Disposition: "accepted", Dists: map[string]string{"el9": "accepted"}},
		{InputPath: "two.rpm", Disposition: "reused"},
		{InputPath: "three.rpm", Disposition: "excluded"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetOperationState(ctx, "1", OperationRecovering, ""); err != nil {
		t.Fatal(err)
	}
	if err := store.FailOperation(ctx, "1", "cancelled", "cancelled by user", `{"accepted":0}`); err != nil {
		t.Fatal(err)
	}
	detail, err := store.GetOperation(ctx, "1")
	if err != nil || detail.Operation.State != OperationFailed || len(detail.Packages) != 3 {
		t.Fatalf("failure audit=%v err=%v", detail, err)
	}
	for _, pkg := range detail.Packages[:2] {
		if pkg.Disposition != "failed" || pkg.ErrorClass != "cancelled" || len(pkg.Dists) != 0 {
			t.Fatalf("uncommitted success survived failure: %#v", pkg)
		}
	}
	if detail.Packages[2].Disposition != "excluded" {
		t.Fatal("preexisting policy outcome changed")
	}
	if err := store.BeginOperation(ctx, Operation{ID: "2", Kind: "add", State: OperationStaged, PayloadJSON: `{}`}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetOperationState(ctx, "2", OperationApplied, ""); err != nil {
		t.Fatal(err)
	}
	if err := store.SetOperationState(ctx, "2", OperationRecovering, ""); err != nil {
		t.Fatal(err)
	}
	if err := store.FailOperation(ctx, "2", "cancelled", "cancelled", `{}`); !errors.Is(err, ErrTransition) {
		t.Fatalf("committed history accepted failure: %v", err)
	}
	operation, err := store.GetOperationSummary(ctx, "2")
	if err != nil || operation.State != OperationRecovering {
		t.Fatalf("committed operation modified: %v %v", operation, err)
	}
}
