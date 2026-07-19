package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
)

func TestIsAncestorRejectsOrphanAndNonCommitObjects(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), ".sow"))
	firstFile := filepath.Join(t.TempDir(), "first.tsv")
	if err := os.WriteFile(firstFile, []byte("a\t1\t"+strings.Repeat("0", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, _, err := store.Install(map[string]string{"test": firstFile}, "first")
	if err != nil {
		t.Fatal(err)
	}
	secondFile := filepath.Join(t.TempDir(), "second.tsv")
	if err := os.WriteFile(secondFile, []byte("b\t1\t"+strings.Repeat("1", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, _, err := store.Install(map[string]string{"test": secondFile}, "second")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := store.IsAncestor(first, second); err != nil || !ok {
		t.Fatalf("first should be ancestor of second: ok=%t err=%v", ok, err)
	}
	if ok, err := store.IsAncestor(second, first); err != nil || ok {
		t.Fatalf("second should not be ancestor of first: ok=%t err=%v", ok, err)
	}
	if ok, err := store.IsAncestor(second, second); err != nil || !ok {
		t.Fatalf("commit should be its own ancestor: ok=%t err=%v", ok, err)
	}
	if _, err := store.IsAncestor(plumbing.ZeroHash, second); err == nil {
		t.Fatal("zero ancestor was accepted")
	}
	if _, err := store.IsAncestor(plumbing.NewHash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), second); err == nil {
		t.Fatal("missing commit object was accepted")
	}
}
