package state

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
)

func TestBoundRepositoryReadsRetainedGitAfterRootReplacement(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	original := New(filepath.Join(root, ".sow"))
	stage := filepath.Join(parent, "original.txt")
	if err := os.WriteFile(stage, []byte("original canonical state\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	originalHead, changed, err := original.InstallPaths(map[string]string{
		"proof/original.txt": stage, "manifests/bound-test.tsv": stage,
	}, "original")
	if err != nil || !changed || originalHead.IsZero() {
		t.Fatalf("install original canonical state changed=%t head=%s err=%v", changed, originalHead, err)
	}
	repoRef, err := RepoRef("bound-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := original.AdvanceRef(repoRef, plumbing.ZeroHash, originalHead, false); err != nil {
		t.Fatal(err)
	}
	dotGit, err := os.OpenRoot(filepath.Join(root, ".sow", "state", ".git"))
	if err != nil {
		t.Fatal(err)
	}
	repository, closeRepository, err := OpenBoundRepository(dotGit)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := closeRepository(); err != nil {
			t.Errorf("close bound repository: %v", err)
		}
	}()
	bound, err := NewReadOnlyRepository(filepath.Join(root, ".sow"), repository)
	if err != nil {
		t.Fatal(err)
	}

	displaced := root + "-displaced"
	if err := os.Rename(root, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	replacement := New(filepath.Join(root, ".sow"))
	replacementStage := filepath.Join(parent, "replacement.txt")
	if err := os.WriteFile(replacementStage, []byte("replacement canonical state\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	replacementHead, changed, err := replacement.InstallPaths(map[string]string{
		"proof/replacement.txt": replacementStage, "manifests/bound-test.tsv": replacementStage,
	}, "replacement")
	if err != nil || !changed || replacementHead.IsZero() || replacementHead == originalHead {
		t.Fatalf("install replacement canonical state changed=%t head=%s original=%s err=%v", changed, replacementHead, originalHead, err)
	}
	if err := replacement.AdvanceRef(repoRef, plumbing.ZeroHash, replacementHead, false); err != nil {
		t.Fatal(err)
	}

	got, err := bound.HeadHash()
	if err != nil || got != originalHead {
		t.Fatalf("bound Git reader was redirected to replacement: got=%s want=%s err=%v", got, originalHead, err)
	}
	refHead, exists, err := bound.Ref(repoRef)
	if err != nil || !exists || refHead != originalHead {
		t.Fatalf("bound ref snapshot was redirected: got=%s exists=%t want=%s err=%v", refHead, exists, originalHead, err)
	}
	worktreeReader, err := bound.OpenPath("proof/original.txt")
	if err != nil {
		t.Fatal(err)
	}
	worktreeBody, readErr := io.ReadAll(worktreeReader)
	closeErr := worktreeReader.Close()
	if readErr != nil || closeErr != nil || string(worktreeBody) != "original canonical state\n" {
		t.Fatalf("bound aggregate file differs: body=%q read=%v close=%v", worktreeBody, readErr, closeErr)
	}
	reader, err := bound.OpenPathAt(originalHead, "proof/original.txt")
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(reader)
	closeErr = reader.Close()
	if readErr != nil || closeErr != nil || string(body) != "original canonical state\n" {
		t.Fatalf("bound canonical blob differs: body=%q read=%v close=%v", body, readErr, closeErr)
	}
	if _, err := bound.OpenPathAt(replacementHead, "proof/replacement.txt"); err == nil {
		t.Fatal("replacement-only Git object was visible through retained repository")
	}
	manifestReader, err := bound.OpenManifest("bound-test")
	if err != nil {
		t.Fatal(err)
	}
	manifestBody, readErr := io.ReadAll(manifestReader)
	closeErr = manifestReader.Close()
	if readErr != nil || closeErr != nil || string(manifestBody) != "original canonical state\n" {
		t.Fatalf("bound manifest was redirected to replacement: body=%q read=%v close=%v", manifestBody, readErr, closeErr)
	}

	mutations := []struct {
		name string
		run  func() error
	}{
		{name: "install", run: func() error {
			_, _, err := bound.Install(map[string]string{"blocked": stage}, "blocked install")
			return err
		}},
		{name: "install paths", run: func() error {
			_, _, err := bound.InstallPaths(map[string]string{"proof/blocked.txt": stage}, "blocked install paths")
			return err
		}},
		{name: "apply", run: func() error {
			_, _, err := bound.Apply(t.Context(), "blocked", "blocked apply", map[string]string{"proof/blocked.txt": stage}, nil, ApplyOptions{})
			return err
		}},
		{name: "advance ref", run: func() error {
			return bound.AdvanceRef(repoRef, originalHead, originalHead, false)
		}},
		{name: "delete ref", run: func() error {
			return bound.DeleteRef(repoRef, originalHead)
		}},
		{name: "recover", run: func() error {
			_, err := bound.Recover(t.Context())
			return err
		}},
		{name: "transaction journal read", run: func() error {
			_, _, err := bound.Transaction("invalid-but-must-not-reach-path")
			return err
		}},
		{name: "incomplete journal read", run: func() error {
			_, err := bound.IncompleteTransactions()
			return err
		}},
		{name: "require no incomplete journal", run: func() error {
			return bound.RequireNoIncompleteTransactions()
		}},
	}
	for _, mutation := range mutations {
		if err := mutation.run(); !errors.Is(err, ErrReadOnly) {
			t.Errorf("%s error=%v, want ErrReadOnly", mutation.name, err)
		}
	}
	if current, err := replacement.HeadHash(); err != nil || current != replacementHead {
		t.Fatalf("read-only mutation reached replacement state: got=%s want=%s err=%v", current, replacementHead, err)
	}
	if current, exists, err := replacement.Ref(repoRef); err != nil || !exists || current != replacementHead {
		t.Fatalf("read-only mutation changed replacement ref: got=%s exists=%t want=%s err=%v", current, exists, replacementHead, err)
	}
	if err := replacement.requireCanonicalWorktreeMatchesHead(); err != nil {
		t.Fatalf("read-only mutation dirtied replacement worktree/index: %v", err)
	}
	for _, relative := range []string{"journal", "transactions", filepath.Join("state", "proof", "blocked.txt")} {
		if _, err := os.Lstat(filepath.Join(root, ".sow", relative)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("read-only mutation created replacement path %s: %v", relative, err)
		}
	}
	if backups, err := filepath.Glob(filepath.Join(root, ".sow", "install-backup-*")); err != nil || len(backups) != 0 {
		t.Fatalf("read-only mutation left replacement backup paths %v: %v", backups, err)
	}
}

func TestBoundRootFSMissingNestedPathPreservesOSNotExistClassification(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "refs"), 0o755); err != nil {
		t.Fatal(err)
	}
	boundRoot, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	group := &boundRootFSGroup{roots: []*os.Root{boundRoot}}
	filesystem := &boundRootFS{root: boundRoot, group: group, label: ".git"}
	defer func() {
		if err := group.Close(); err != nil {
			t.Errorf("close bound filesystem: %v", err)
		}
	}()

	checks := []struct {
		name string
		run  func() error
	}{
		{name: "open", run: func() error { _, err := filesystem.Open("refs/missing"); return err }},
		{name: "stat", run: func() error { _, err := filesystem.Stat("refs/missing"); return err }},
		{name: "lstat", run: func() error { _, err := filesystem.Lstat("refs/missing"); return err }},
		{name: "readlink", run: func() error { _, err := filesystem.Readlink("refs/missing"); return err }},
	}
	for _, check := range checks {
		if err := check.run(); !os.IsNotExist(err) {
			t.Errorf("%s missing-path classification changed: %T %v", check.name, err, err)
		}
	}
}

func TestReadOnlyRepositoryPinsHeadAndRefsAndDetectsLiveMovement(t *testing.T) {
	root := t.TempDir()
	store := New(filepath.Join(root, ".sow"))
	first := filepath.Join(root, "first.txt")
	if err := os.WriteFile(first, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	initial, changed, err := store.InstallPaths(map[string]string{"proof/value.txt": first}, "first")
	if err != nil || !changed {
		t.Fatalf("initial install changed=%t err=%v", changed, err)
	}
	repoRef, err := RepoRef("snapshot-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceRef(repoRef, plumbing.ZeroHash, initial, false); err != nil {
		t.Fatal(err)
	}
	dotGit, err := os.OpenRoot(filepath.Join(root, ".sow", "state", ".git"))
	if err != nil {
		t.Fatal(err)
	}
	repository, closeRepository, err := OpenBoundRepository(dotGit)
	if err != nil {
		t.Fatal(err)
	}
	defer closeRepository()
	bound, err := NewReadOnlyRepository(filepath.Join(root, ".sow"), repository)
	if err != nil {
		t.Fatal(err)
	}

	second := filepath.Join(root, "second.txt")
	if err := os.WriteFile(second, []byte("second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	next, changed, err := store.InstallPaths(map[string]string{"proof/value.txt": second}, "second")
	if err != nil || !changed || next == initial {
		t.Fatalf("second install changed=%t initial=%s next=%s err=%v", changed, initial, next, err)
	}
	if err := store.AdvanceRef(repoRef, initial, next, false); err != nil {
		t.Fatal(err)
	}

	if head, err := bound.HeadHash(); err != nil || head != initial {
		t.Fatalf("read-only HEAD moved: got=%s want=%s err=%v", head, initial, err)
	}
	if ref, exists, err := bound.Ref(repoRef); err != nil || !exists || ref != initial {
		t.Fatalf("read-only ref moved: got=%s exists=%t want=%s err=%v", ref, exists, initial, err)
	}
	reader, err := bound.OpenPath("proof/value.txt")
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || string(body) != "first\n" {
		t.Fatalf("read-only canonical bytes moved: body=%q read=%v close=%v", body, readErr, closeErr)
	}
	if err := bound.VerifyReadSnapshot(); err == nil {
		t.Fatal("live canonical HEAD/ref movement was not detected")
	}
}

func TestBoundRepositoryRejectsIntermediateObjectDirectorySymlink(t *testing.T) {
	root := t.TempDir()
	store := New(filepath.Join(root, ".sow"))
	stage := filepath.Join(root, "value.txt")
	if err := os.WriteFile(stage, []byte("object proof\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	head, changed, err := store.InstallPaths(map[string]string{"proof/value.txt": stage}, "object proof")
	if err != nil || !changed || head.IsZero() {
		t.Fatalf("install changed=%t head=%s err=%v", changed, head, err)
	}
	dotGitPath := filepath.Join(root, ".sow", "state", ".git")
	dotGit, err := os.OpenRoot(dotGitPath)
	if err != nil {
		t.Fatal(err)
	}
	repository, closeRepository, err := OpenBoundRepository(dotGit)
	if err != nil {
		t.Fatal(err)
	}
	defer closeRepository()
	bound, err := NewReadOnlyRepository(filepath.Join(root, ".sow"), repository)
	if err != nil {
		t.Fatal(err)
	}

	shard := head.String()[:2]
	objects := filepath.Join(dotGitPath, "objects")
	realShard := filepath.Join(objects, shard+"-real")
	if err := os.Rename(filepath.Join(objects, shard), realShard); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(realShard), filepath.Join(objects, shard)); err != nil {
		t.Fatal(err)
	}
	if _, err := bound.OpenPathAt(head, "proof/value.txt"); err == nil || !strings.Contains(err.Error(), "symlinked") {
		t.Fatalf("intermediate Git object-directory symlink was accepted: %v", err)
	}
}
