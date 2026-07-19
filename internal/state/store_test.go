package state

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
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

func TestInstallPathsFailureRestoresWorktreeAndGitIndex(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, ".sow")
	store := New(stateDir)
	writeStage := func(name, body string) string {
		t.Helper()
		filename := filepath.Join(root, name)
		if err := os.WriteFile(filename, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return filename
	}

	const canonical = "views/latest/asset/all/all.tsv"
	baseline, changed, err := store.InstallPaths(map[string]string{
		canonical: writeStage("baseline.tsv", "old\n"),
	}, "baseline")
	if err != nil || !changed || baseline.IsZero() {
		t.Fatalf("baseline commit=%s changed=%v err=%v", baseline, changed, err)
	}

	// Resolve HEAD from a packed nested ref while a regular file blocks creation
	// of that ref's parent directory. Add and index persistence succeed, but the
	// final HEAD update deterministically fails without a production test hook.
	gitDir := filepath.Join(stateDir, "state", ".git")
	blockedRef := "refs/heads/blocked/nested"
	if err := os.WriteFile(filepath.Join(gitDir, "packed-refs"), []byte(baseline.String()+" "+blockedRef+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "refs", "heads", "blocked"), []byte("not a directory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: "+blockedRef+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.InstallPaths(map[string]string{
		canonical: writeStage("failed.tsv", "must-not-leak\n"),
	}, "injected HEAD update failure"); err == nil {
		t.Fatal("install unexpectedly committed through blocked nested ref")
	}

	repository, err := git.PlainOpen(filepath.Join(stateDir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	status, err := worktree.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !status.IsClean() {
		t.Fatalf("failed install left worktree/index dirty: %s", status.String())
	}

	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/master\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(gitDir, "refs", "heads", "blocked")); err != nil {
		t.Fatal(err)
	}
	next, changed, err := store.InstallPaths(map[string]string{
		"metadata/unrelated.tsv": writeStage("unrelated.tsv", "unrelated\n"),
	}, "unrelated change")
	if err != nil || !changed || next == baseline {
		t.Fatalf("next commit=%s changed=%v err=%v", next, changed, err)
	}
	file, err := store.OpenPathAt(next, canonical)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read canonical at next commit: %v", errors.Join(readErr, closeErr))
	}
	if string(body) != "old\n" {
		t.Fatalf("failed staged content leaked into later commit: %q", body)
	}
}

func TestRollbackInstallBackupsRetainsEvidenceOnRestoreFailure(t *testing.T) {
	root := t.TempDir()
	backupDir := filepath.Join(root, "backup")
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(backupDir, "000000")
	if err := os.WriteFile(backup, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(root, "state", "value.tsv")
	if err := os.MkdirAll(filepath.Join(destination, "blocker"), 0o700); err != nil {
		t.Fatal(err)
	}
	err := rollbackInstallBackups([]installBackup{{dst: destination, path: backup, exists: true}})
	if err == nil || !strings.Contains(err.Error(), "remove failed canonical state") {
		t.Fatalf("rollback obstruction was hidden: %v", err)
	}
	if body, readErr := os.ReadFile(backup); readErr != nil || string(body) != "old\n" {
		t.Fatalf("failed rollback destroyed its only backup: body=%q err=%v", body, readErr)
	}
}
