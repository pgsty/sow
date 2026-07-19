package state

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
)

func TestInstallPathsAndCompareAndSetRefs(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, ".sow")
	stage := filepath.Join(root, "view.tsv")
	if err := os.WriteFile(stage, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	store := New(stateDir)
	path, err := ViewPath("beta", "asset", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	first, committed, err := store.InstallPaths(map[string]string{path: stage}, "create beta")
	if err != nil || !committed {
		t.Fatalf("install first=%s committed=%v err=%v", first, committed, err)
	}
	ref, err := ViewRef("beta", "asset", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceRef(ref, plumbing.ZeroHash, first, false); err != nil {
		t.Fatal(err)
	}
	atFirst, err := store.OpenPathAt(first, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := atFirst.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceRef(ref, plumbing.ZeroHash, first, false); err != nil {
		t.Fatalf("idempotent advance failed: %v", err)
	}

	if err := os.WriteFile(stage, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, committed, err := store.InstallPaths(map[string]string{path: stage}, "change beta")
	if err != nil || !committed || second == first {
		t.Fatalf("install second=%s committed=%v err=%v", second, committed, err)
	}
	if err := store.AdvanceRef(ref, plumbing.ZeroHash, second, false); !errors.Is(err, ErrRefConflict) {
		t.Fatalf("stale mutable update err=%v", err)
	}
	if err := store.AdvanceRef(ref, first, second, false); err != nil {
		t.Fatal(err)
	}

	snapshot, err := SnapshotRef("jammy-20260711", "asset", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceRef(snapshot, plumbing.ZeroHash, first, true); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceRef(snapshot, first, first, true); err != nil {
		t.Fatalf("append-only idempotence failed: %v", err)
	}
	if err := store.AdvanceRef(snapshot, first, second, true); !errors.Is(err, ErrImmutableRef) {
		t.Fatalf("append-only rewrite err=%v", err)
	}
}

func TestCanonicalPathsRejectTraversal(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), ".sow"))
	for _, invalid := range []string{"../escape", ".git/config", "views\\escape", "/absolute"} {
		if _, _, err := store.InstallPaths(map[string]string{invalid: "unused"}, "bad"); err == nil {
			t.Fatalf("accepted invalid path %q", invalid)
		}
	}
}

func TestAPTByHashLedgerPathIsScopedAndSafe(t *testing.T) {
	got, err := APTByHashLedgerPath("views", "latest", "apt-main", "trixie")
	if err != nil || got != "retention/apt-by-hash/views/latest/apt-main/trixie.json" {
		t.Fatalf("ledger path=%q err=%v", got, err)
	}
	for _, input := range []struct{ namespace, name, repo, suite string }{
		{"remotes", "latest", "apt-main", "trixie"},
		{"views", "../latest", "apt-main", "trixie"},
		{"views", "latest", "apt/main", "trixie"},
		{"views", "latest", "apt-main", "../trixie"},
	} {
		if _, err := APTByHashLedgerPath(input.namespace, input.name, input.repo, input.suite); err == nil {
			t.Fatalf("unsafe ledger coordinate accepted: %+v", input)
		}
	}
}
