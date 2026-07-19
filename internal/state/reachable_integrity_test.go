package state

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func TestAuditReachableObjectsConsumesBoundGraph(t *testing.T) {
	fixture := newBoundObjectFixture(t, []byte("canonical graph payload\n"))
	stats, err := fixture.store.AuditReachableObjects()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Roots != 1 || stats.Commits != 1 || stats.Blobs != 1 || stats.BlobBytes != int64(len("canonical graph payload\n")) {
		t.Fatalf("unexpected reachability stats: %+v", stats)
	}
	if err := fixture.store.VerifyReadSnapshot(); err != nil {
		t.Fatalf("final bound replay: %v", err)
	}
}

func TestAuditReachableObjectsRejectsCorruptReachableBlob(t *testing.T) {
	fixture := newBoundObjectFixture(t, []byte("canonical graph payload\n"))
	objectType, payload := readLooseObjectPayload(t, fixture.dotGitPath, fixture.blob)
	overwriteLooseObjectPayload(t, fixture.dotGitPath, fixture.blob, objectType, mutateSameSize(payload))
	if _, err := fixture.store.AuditReachableObjects(); !errors.Is(err, ErrGitObjectIntegrity) {
		t.Fatalf("reachability audit accepted hash-mismatched blob: %v", err)
	}
}

func TestAuditReachableObjectsTraversesUnreferencedAncestorFromHead(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, ".sow")
	writable := New(stateDir)
	firstStage := filepath.Join(root, "first.tsv")
	secondStage := filepath.Join(root, "second.tsv")
	if err := os.WriteFile(firstStage, []byte("first historical body\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	firstCommit, changed, err := writable.InstallPaths(map[string]string{"history/value.tsv": firstStage}, "first")
	if err != nil || !changed {
		t.Fatalf("first commit changed=%t err=%v", changed, err)
	}
	plain, err := writable.OpenRepository()
	if err != nil {
		t.Fatal(err)
	}
	firstObject, err := plain.CommitObject(firstCommit)
	if err != nil {
		t.Fatal(err)
	}
	firstTree, err := firstObject.Tree()
	if err != nil {
		t.Fatal(err)
	}
	firstFile, err := firstTree.File("history/value.tsv")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondStage, []byte("second current body\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := writable.InstallPaths(map[string]string{"history/value.tsv": secondStage}, "second"); err != nil || !changed {
		t.Fatalf("second commit changed=%t err=%v", changed, err)
	}

	dotGitPath := filepath.Join(stateDir, "state", ".git")
	dotGit, err := os.OpenRoot(dotGitPath)
	if err != nil {
		t.Fatal(err)
	}
	repository, closeRepository, err := OpenBoundRepository(dotGit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closeRepository() })
	bound, err := NewReadOnlyRepository(stateDir, repository)
	if err != nil {
		t.Fatal(err)
	}
	objectType, payload := readLooseObjectPayload(t, dotGitPath, firstFile.Hash)
	overwriteLooseObjectPayload(t, dotGitPath, firstFile.Hash, objectType, mutateSameSize(payload))
	if _, err := bound.AuditReachableObjects(); !errors.Is(err, ErrGitObjectIntegrity) {
		t.Fatalf("reachability audit accepted corrupt ancestor blob: %v", err)
	}
}

func TestAuditReachableObjectsRequiresBoundStore(t *testing.T) {
	if _, err := New(filepath.Join(t.TempDir(), ".sow")).AuditReachableObjects(); err == nil {
		t.Fatal("ordinary path-based store unexpectedly passed reachability audit")
	}
}

func TestAuditReachableObjectsRejectsMissingChildTree(t *testing.T) {
	fixture := newBoundObjectFixture(t, []byte("canonical graph payload\n"))
	installReachabilityTestRef(t, fixture.root, []object.TreeEntry{{
		Name: "missing", Mode: filemode.Dir, Hash: plumbing.NewHash(strings.Repeat("1", 40)),
	}})
	bound := reopenReachabilityTestStore(t, fixture.root)
	if _, err := bound.AuditReachableObjects(); err == nil || !strings.Contains(err.Error(), "open canonical subtree") {
		t.Fatalf("reachability audit accepted a missing child tree: %v", err)
	}
}

func TestAuditReachableObjectsRejectsGitlink(t *testing.T) {
	fixture := newBoundObjectFixture(t, []byte("canonical graph payload\n"))
	installReachabilityTestRef(t, fixture.root, []object.TreeEntry{{
		Name: "external", Mode: filemode.Submodule, Hash: fixture.head,
	}})
	bound := reopenReachabilityTestStore(t, fixture.root)
	if _, err := bound.AuditReachableObjects(); err == nil || !strings.Contains(err.Error(), "unsupported Git mode") {
		t.Fatalf("reachability audit accepted a gitlink: %v", err)
	}
}

func TestAuditReachableObjectsRejectsAmbiguousTreeEntries(t *testing.T) {
	fixture := newBoundObjectFixture(t, []byte("canonical graph payload\n"))
	tests := []struct {
		name    string
		entries []object.TreeEntry
	}{
		{
			name: "duplicate-name",
			entries: []object.TreeEntry{
				{Name: "duplicate", Mode: filemode.Regular, Hash: fixture.blob},
				{Name: "duplicate", Mode: filemode.Regular, Hash: fixture.blob},
			},
		},
		{
			name: "slash-bearing-name",
			entries: []object.TreeEntry{
				{Name: "forged/path", Mode: filemode.Regular, Hash: fixture.blob},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			installReachabilityTestRef(t, fixture.root, test.entries)
			bound := reopenReachabilityTestStore(t, fixture.root)
			if _, err := bound.AuditReachableObjects(); err == nil || !strings.Contains(err.Error(), "non-canonical tree") {
				t.Fatalf("reachability audit accepted %s tree entries: %v", test.name, err)
			}
		})
	}
}

func installReachabilityTestRef(t *testing.T, root string, entries []object.TreeEntry) {
	t.Helper()
	writable := New(filepath.Join(root, ".sow"))
	repository, err := writable.OpenRepository()
	if err != nil {
		t.Fatal(err)
	}
	treeObject := &plumbing.MemoryObject{}
	if err := (&object.Tree{Entries: entries}).Encode(treeObject); err != nil {
		t.Fatal(err)
	}
	treeHash, err := repository.Storer.SetEncodedObject(treeObject)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1, 0).UTC()
	commitObject := &plumbing.MemoryObject{}
	if err := (&object.Commit{
		Author:    object.Signature{Name: "sow", Email: "sow@localhost", When: now},
		Committer: object.Signature{Name: "sow", Email: "sow@localhost", When: now},
		TreeHash:  treeHash, Message: "reachability test preservation root\n",
	}).Encode(commitObject); err != nil {
		t.Fatal(err)
	}
	commitHash, err := repository.Storer.SetEncodedObject(commitObject)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Storer.SetReference(plumbing.NewHashReference("refs/heads/reachability-test", commitHash)); err != nil {
		t.Fatal(err)
	}
}

func reopenReachabilityTestStore(t *testing.T, root string) *Store {
	t.Helper()
	stateDir := filepath.Join(root, ".sow")
	dotGit, err := os.OpenRoot(filepath.Join(stateDir, "state", ".git"))
	if err != nil {
		t.Fatal(err)
	}
	repository, closeRepository, err := OpenBoundRepository(dotGit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closeRepository() })
	bound, err := NewReadOnlyRepository(stateDir, repository)
	if err != nil {
		t.Fatal(err)
	}
	return bound
}

func TestAuditCanonicalWorktreeRejectsSameInodeMtimeRestoredBytes(t *testing.T) {
	fixture := newBoundObjectFixture(t, []byte("canonical graph payload\n"))
	name := filepath.Join(fixture.root, ".sow", "state", "proof", "value.bin")
	before, err := os.Lstat(name)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	mutated := mutateSameSize([]byte("canonical graph payload\n"))
	if _, err := file.Write(mutated); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(name, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(name)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() {
		t.Fatalf("same-inode fixture changed identity: %v", err)
	}
	if err := New(filepath.Join(fixture.root, ".sow")).AuditCanonicalWorktree(); err == nil || !strings.Contains(err.Error(), "differ from HEAD") {
		t.Fatalf("worktree audit accepted same-inode mtime-restored bytes: %v", err)
	}
}

func TestAuditCanonicalWorktreeRejectsIndexFlags(t *testing.T) {
	fixture := newBoundObjectFixture(t, []byte("canonical graph payload\n"))
	writable := New(filepath.Join(fixture.root, ".sow"))
	repository, err := writable.OpenRepository()
	if err != nil {
		t.Fatal(err)
	}
	canonicalIndex, err := repository.Storer.Index()
	if err != nil || len(canonicalIndex.Entries) != 1 {
		t.Fatalf("fixture index: entries=%d err=%v", len(canonicalIndex.Entries), err)
	}
	canonicalIndex.Version = 3
	canonicalIndex.Entries[0].SkipWorktree = true
	if err := repository.Storer.SetIndex(canonicalIndex); err != nil {
		t.Fatal(err)
	}
	if err := writable.AuditCanonicalWorktree(); err == nil || !strings.Contains(err.Error(), "index entry") {
		t.Fatalf("worktree audit accepted skip-worktree index entry: %v", err)
	}
}

func TestAuditCanonicalWorktreeRejectsUntrackedFileBelowExtraDirectory(t *testing.T) {
	fixture := newBoundObjectFixture(t, []byte("canonical graph payload\n"))
	extra := filepath.Join(fixture.root, ".sow", "state", "untracked-extra")
	if err := os.Mkdir(extra, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(extra, "ignored"), []byte("untracked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := New(filepath.Join(fixture.root, ".sow")).AuditCanonicalWorktree(); err == nil || !strings.Contains(err.Error(), "untracked") {
		t.Fatalf("worktree audit accepted an untracked file: %v", err)
	}
}

func TestAuditCanonicalWorktreeRejectsNonCanonicalFilePermissions(t *testing.T) {
	fixture := newBoundObjectFixture(t, []byte("canonical graph payload\n"))
	name := filepath.Join(fixture.root, ".sow", "state", "proof", "value.bin")
	if err := os.Chmod(name, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := New(filepath.Join(fixture.root, ".sow")).AuditCanonicalWorktree(); err == nil || !strings.Contains(err.Error(), "non-canonical permissions") {
		t.Fatalf("worktree audit accepted non-canonical file permissions: %v", err)
	}
}

func TestAuditCanonicalWorktreeDoesNotInitializeMissingRepository(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	if err := New(stateDir).AuditCanonicalWorktree(); err == nil {
		t.Fatal("worktree audit accepted a missing repository")
	}
	if _, err := os.Lstat(filepath.Join(stateDir, "state")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("worktree audit initialized missing canonical state: %v", err)
	}
}
