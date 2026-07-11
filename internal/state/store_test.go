package state

import (
	"os"
	"path/filepath"
	"testing"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func TestStoreCommitsAndIsIdempotent(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, ".sow")
	stage := filepath.Join(root, "asset.tsv")
	manifest := "asset/file\t1\tca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb\n"
	if err := os.WriteFile(stage, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	store := New(stateDir)
	first, committed, err := store.Install(map[string]string{"asset": stage}, "baseline")
	if err != nil {
		t.Fatal(err)
	}
	if !committed || first.IsZero() {
		t.Fatalf("first install did not commit: %s %v", first, committed)
	}
	second, committed, err := store.Install(map[string]string{"asset": stage}, "same")
	if err != nil {
		t.Fatal(err)
	}
	if committed || second != first {
		t.Fatalf("idempotent install created commit: first=%s second=%s committed=%v", first, second, committed)
	}
	repository, err := git.PlainOpen(filepath.Join(stateDir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	log, err := repository.Log(&git.LogOptions{})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	if err := log.ForEach(func(_ *object.Commit) error {
		count++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("commit count=%d want=1", count)
	}
}
