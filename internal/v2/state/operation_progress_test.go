package state

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestRecordOperationProgressPreservesStateAndAuditsDetail(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "repo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.BeginOperation(ctx, Operation{ID: "1", Kind: "build", State: OperationPlanned, PayloadJSON: `{}`}); err != nil {
		t.Fatal(err)
	}
	progress := `{"version":1,"kind":"build_progress","phase":"rendering","completed":1,"total":2}`
	if err := store.RecordOperationProgress(ctx, "1", progress); err != nil {
		t.Fatal(err)
	}
	detail, err := store.GetOperation(ctx, "1")
	if err != nil {
		t.Fatal(err)
	}
	if detail.Operation.State != OperationPlanned || len(detail.Events) != 2 || detail.Events[1].State != string(OperationPlanned) || detail.Events[1].DetailJSON != progress {
		t.Fatalf("operation progress detail=%#v", detail)
	}
	if err := store.SetOperationState(ctx, "1", OperationFailed, "test"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordOperationProgress(ctx, "1", progress); !errors.Is(err, ErrTransition) {
		t.Fatalf("terminal progress error=%v", err)
	}
}
