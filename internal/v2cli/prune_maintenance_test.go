package v2cli

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/v2/state"
)

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
