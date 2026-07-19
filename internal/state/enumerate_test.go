package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func TestBlobIdentityAtDistinguishesMissingUnchangedAndChangedBlobs(t *testing.T) {
	root := t.TempDir()
	store := New(filepath.Join(root, ".sow"))
	stage := filepath.Join(root, "state.json")
	if err := os.WriteFile(stage, []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, changed, err := store.InstallPaths(map[string]string{"remotes/cf/plan.json": stage}, "first")
	if err != nil || !changed {
		t.Fatalf("first commit=%s changed=%t err=%v", first, changed, err)
	}
	identity, exists, err := store.BlobIdentityAt(first, "remotes/cf/plan.json")
	if err != nil || !exists || identity.Hash.IsZero() || identity.Size != 4 {
		t.Fatalf("first identity=%#v exists=%t err=%v", identity, exists, err)
	}
	if _, exists, err := store.BlobIdentityAt(first, "remotes/cf/missing.json"); err != nil || exists {
		t.Fatalf("missing exists=%t err=%v", exists, err)
	}
	if _, _, err := store.BlobIdentityAt(plumbing.ZeroHash, "remotes/cf/plan.json"); err == nil {
		t.Fatal("zero commit identity lookup passed")
	}
	if err := os.WriteFile(stage, []byte("two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, changed, err := store.InstallPaths(map[string]string{"remotes/cf/plan.json": stage}, "second")
	if err != nil || !changed {
		t.Fatalf("second commit=%s changed=%t err=%v", second, changed, err)
	}
	secondIdentity, exists, err := store.BlobIdentityAt(second, "remotes/cf/plan.json")
	if err != nil || !exists || secondIdentity.Hash == identity.Hash || secondIdentity.Size != identity.Size {
		t.Fatalf("second identity=%#v first=%#v exists=%t err=%v", secondIdentity, identity, exists, err)
	}
	retainedIdentity, exists, err := store.BlobIdentityAt(first, "remotes/cf/plan.json")
	if err != nil || !exists || retainedIdentity != identity {
		t.Fatalf("historical identity=%#v want=%#v exists=%t err=%v", retainedIdentity, identity, exists, err)
	}
}

func TestIsAncestorUsesCanonicalCommitGraph(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), ".sow"))
	stage := filepath.Join(t.TempDir(), "value")
	if err := os.WriteFile(stage, []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, changed, err := store.InstallPaths(map[string]string{"tests/value": stage}, "first")
	if err != nil || !changed {
		t.Fatalf("first=%s changed=%t err=%v", first, changed, err)
	}
	if err := os.WriteFile(stage, []byte("two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, changed, err := store.InstallPaths(map[string]string{"tests/value": stage}, "second")
	if err != nil || !changed {
		t.Fatalf("second=%s changed=%t err=%v", second, changed, err)
	}
	if ancestor, err := store.IsAncestor(first, second); err != nil || !ancestor {
		t.Fatalf("first ancestor of second=%t err=%v", ancestor, err)
	}
	if ancestor, err := store.IsAncestor(second, first); err != nil || ancestor {
		t.Fatalf("second ancestor of first=%t err=%v", ancestor, err)
	}
	if ancestor, err := store.IsAncestor(first, first); err != nil || !ancestor {
		t.Fatalf("commit ancestor of itself=%t err=%v", ancestor, err)
	}
}

func TestReachableCommitsIncludesOffHeadDirectRefHistory(t *testing.T) {
	root := t.TempDir()
	store := New(filepath.Join(root, ".sow"))
	stage := filepath.Join(root, "value")
	if err := os.WriteFile(stage, []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, changed, err := store.InstallPaths(map[string]string{"tests/value": stage}, "first")
	if err != nil || !changed {
		t.Fatalf("first=%s changed=%t err=%v", first, changed, err)
	}
	if err := os.WriteFile(stage, []byte("two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, changed, err := store.InstallPaths(map[string]string{"tests/value": stage}, "second")
	if err != nil || !changed {
		t.Fatalf("second=%s changed=%t err=%v", second, changed, err)
	}
	repository, err := git.PlainOpen(filepath.Join(root, ".sow", "state"))
	if err != nil {
		t.Fatal(err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := worktree.Reset(&git.ResetOptions{Mode: git.HardReset, Commit: first}); err != nil {
		t.Fatal(err)
	}
	worktreePath := filepath.Join(root, ".sow", "state", "tests", "value")
	if err := os.WriteFile(worktreePath, []byte("sibling\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.Add("tests/value"); err != nil {
		t.Fatal(err)
	}
	signature := &object.Signature{Name: "sow-test", Email: "sow-test@localhost", When: time.Now().UTC()}
	sibling, err := worktree.Commit("off-head sibling", &git.CommitOptions{Author: signature, Committer: signature})
	if err != nil {
		t.Fatal(err)
	}
	if err := worktree.Reset(&git.ResetOptions{Mode: git.HardReset, Commit: second}); err != nil {
		t.Fatal(err)
	}
	if err := repository.Storer.SetReference(plumbing.NewHashReference("refs/sow/test/offhead", sibling)); err != nil {
		t.Fatal(err)
	}
	history, err := store.History()
	if err != nil {
		t.Fatal(err)
	}
	for _, commit := range history {
		if commit == sibling {
			t.Fatal("HEAD-only history unexpectedly included sibling")
		}
	}
	reachable, err := store.ReachableCommits()
	if err != nil {
		t.Fatal(err)
	}
	want := map[plumbing.Hash]bool{first: false, second: false, sibling: false}
	for _, commit := range reachable {
		if _, exists := want[commit]; exists {
			want[commit] = true
		}
	}
	for commit, found := range want {
		if !found {
			t.Fatalf("reachable commits omitted %s: %v", commit, reachable)
		}
	}
}
