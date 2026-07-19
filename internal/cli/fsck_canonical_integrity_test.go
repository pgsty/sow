package cli

import (
	"bytes"
	"compress/zlib"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/state"
)

func TestFSCKRejectsHashMismatchedCurrentAndHistoricalBlobsBeforeRepositoryScan(t *testing.T) {
	tests := []struct {
		name       string
		historical bool
	}{
		{name: "current"},
		{name: "historical", historical: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, configPath := initializeCanonicalFSCKFixture(t)
			canonical := state.New(filepath.Join(root, ".sow"))
			first := filepath.Join(t.TempDir(), "first")
			if err := os.WriteFile(first, []byte("first canonical audit body\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			firstCommit, changed, err := canonical.InstallPaths(map[string]string{"tests/integrity": first}, "test: first integrity body")
			if err != nil || !changed {
				t.Fatalf("install first integrity body changed=%t err=%v", changed, err)
			}
			blob := canonicalBlobAt(t, canonical, firstCommit, "tests/integrity")
			if test.historical {
				second := filepath.Join(t.TempDir(), "second")
				if err := os.WriteFile(second, []byte("second canonical audit body\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if _, changed, err := canonical.InstallPaths(map[string]string{"tests/integrity": second}, "test: second integrity body"); err != nil || !changed {
					t.Fatalf("install second integrity body changed=%t err=%v", changed, err)
				}
			}
			corruptCLILooseObjectInPlace(t, filepath.Join(root, ".sow", "state", ".git"), blob)

			var stdout, stderr bytes.Buffer
			code := Main([]string{"fsck", "--config", configPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
			if code != ExitVerification || !strings.Contains(stderr.String(), "canonical Git object integrity failure") {
				t.Fatalf("fsck accepted %s hash mismatch code=%d stdout=%s stderr=%s", test.name, code, stdout.String(), stderr.String())
			}
			for _, forbidden := range []string{"fsck repo=", "fsck target=", "fsck clean"} {
				if strings.Contains(stdout.String(), forbidden) {
					t.Fatalf("fsck reached %q after %s canonical corruption: %s", forbidden, test.name, stdout.String())
				}
			}
		})
	}
}

func TestCanonicalFSCKFinalBarrierRechecksWorktreeBytes(t *testing.T) {
	root, configPath := initializeCanonicalFSCKFixture(t)
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	lock, err := state.AcquireLock(cfg.StatePath(), "test-fsck", false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Release() })
	session, _, err := openCanonicalFSCKAdmission(cfg, lock, state.New(cfg.StatePath()))
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(root, ".sow", "state", "manifests", "asset.tsv")
	mutateCLIFileSameInodeAndRestoreMtime(t, name)
	if err := closeCanonicalFSCKAdmission(session); err == nil || !strings.Contains(err.Error(), "differ from HEAD") {
		t.Fatalf("final fsck barrier accepted worktree byte mutation: %v", err)
	}
}

func TestLockedReadAdmissionRetainsWorktreeDirectoryIdentity(t *testing.T) {
	root, configPath := initializeCanonicalFSCKFixture(t)
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	lock, err := state.AcquireLock(cfg.StatePath(), "test-fsck", false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Release() })
	session, _, err := openCanonicalFSCKAdmission(cfg, lock, state.New(cfg.StatePath()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	worktree := filepath.Join(root, ".sow", "state")
	displaced := worktree + "-old"
	if err := os.Rename(worktree, displaced); err != nil {
		t.Fatal(err)
	}
	replacementRoot, _ := initializeCanonicalFSCKFixture(t)
	if err := os.Rename(filepath.Join(replacementRoot, ".sow", "state"), worktree); err != nil {
		t.Fatal(err)
	}
	if len(session.rechecks) != 1 {
		t.Fatalf("canonical admission worktree rechecks=%d want=1", len(session.rechecks))
	}
	if err := session.rechecks[0](); err == nil || !strings.Contains(err.Error(), "root changed before audit") {
		t.Fatalf("bound canonical worktree audit accepted a replacement checkout: %v", err)
	}
	if err := session.verifyTopology(); err == nil || !strings.Contains(err.Error(), ".sow/state") {
		t.Fatalf("locked read admission accepted worktree-root replacement: %v", err)
	}
}

func TestLockedReadAdmissionRejectsLockFromAnotherRepository(t *testing.T) {
	_, configPathA := initializeCanonicalFSCKFixture(t)
	_, configPathB := initializeCanonicalFSCKFixture(t)
	cfgA, err := config.Load(configPathA, "")
	if err != nil {
		t.Fatal(err)
	}
	cfgB, err := config.Load(configPathB, "")
	if err != nil {
		t.Fatal(err)
	}
	lockB, err := state.AcquireLock(cfgB.StatePath(), "test-other-repository", false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lockB.Release() })
	if session, err := openLockedLocalReadAdmission(cfgA, lockB); err == nil || session != nil || !strings.Contains(err.Error(), "different canonical state root") {
		t.Fatalf("locked admission accepted another repository's lock session=%v err=%v", session, err)
	}
}

func TestCanonicalFSCKMutationTopologyRejectsGitDirectoryReplacement(t *testing.T) {
	root, configPath := initializeCanonicalFSCKFixture(t)
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	lock, err := state.AcquireLock(cfg.StatePath(), "test-fsck", false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Release() })
	session, _, err := openCanonicalFSCKAdmission(cfg, lock, state.New(cfg.StatePath()))
	if err != nil {
		t.Fatal(err)
	}
	if err := finalizeCanonicalFSCKAdmissionForMutation(session); err != nil {
		t.Fatal(err)
	}
	dotGit := filepath.Join(root, ".sow", "state", ".git")
	if err := os.Rename(dotGit, dotGit+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dotGit, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := closeCanonicalFSCKMutationTopology(session); err == nil || !strings.Contains(err.Error(), ".sow/state/.git") {
		t.Fatalf("fsck mutation topology accepted .git replacement: %v", err)
	}
}

func TestFSCKRecoverAuditsObjectGraphBeforeTransactionReplay(t *testing.T) {
	root, configPath := initializeCanonicalFSCKFixture(t)
	canonical := state.New(filepath.Join(root, ".sow"))
	stageDir := filepath.Join(root, ".sow", "test-stage")
	if err := os.Mkdir(stageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(stageDir, "recover-stage")
	if err := os.WriteFile(stage, []byte("recovery graph body\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("stop after canonical commit")
	commit, changed, err := canonical.Apply(t.Context(), "test-recovery", "test: incomplete recovery", map[string]string{"tests/recovery": stage}, nil, state.ApplyOptions{
		AfterCommit: func() error { return injected },
	})
	if !errors.Is(err, injected) || !changed || commit.IsZero() {
		t.Fatalf("create incomplete recovery commit=%s changed=%t err=%v", commit, changed, err)
	}
	blob := canonicalBlobAt(t, canonical, commit, "tests/recovery")
	corruptCLILooseObjectInPlace(t, filepath.Join(root, ".sow", "state", ".git"), blob)

	var stdout, stderr bytes.Buffer
	code := Main([]string{"fsck", "--recover", "--config", configPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitVerification || !strings.Contains(stderr.String(), "before recovery") || !strings.Contains(stderr.String(), "canonical Git object integrity failure") {
		t.Fatalf("fsck recovery consumed corrupt graph code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "recovered transaction=") || strings.Contains(stdout.String(), "fsck repo=") {
		t.Fatalf("fsck replayed/scanned after corrupt pre-recovery graph: %s", stdout.String())
	}
}

func initializeCanonicalFSCKFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "asset"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "asset", "payload"), []byte("payload\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"init", "--config", configPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("init code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	return root, configPath
}

func canonicalBlobAt(t *testing.T, canonical *state.Store, commit plumbing.Hash, name string) plumbing.Hash {
	t.Helper()
	repository, err := canonical.OpenRepository()
	if err != nil {
		t.Fatal(err)
	}
	commitObject, err := repository.CommitObject(commit)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := commitObject.Tree()
	if err != nil {
		t.Fatal(err)
	}
	file, err := tree.File(name)
	if err != nil {
		t.Fatal(err)
	}
	return file.Hash
}

func corruptCLILooseObjectInPlace(t *testing.T, dotGit string, hash plumbing.Hash) {
	t.Helper()
	encoded := hash.String()
	name := filepath.Join(dotGit, "objects", encoded[:2], encoded[2:])
	before, err := os.Lstat(name)
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	decompressed, err := zlib.NewReader(input)
	if err != nil {
		_ = input.Close()
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(decompressed)
	closeErr := errors.Join(decompressed.Close(), input.Close())
	if readErr != nil || closeErr != nil {
		t.Fatal(errors.Join(readErr, closeErr))
	}
	separator := bytes.IndexByte(body, 0)
	if separator < 0 || separator == len(body)-1 {
		t.Fatal("loose object fixture has no mutable payload")
	}
	body[len(body)-1] ^= 0x01
	if err := os.Chmod(name, 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := os.OpenFile(name, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	compressed := zlib.NewWriter(output)
	_, writeErr := compressed.Write(body)
	closeErr = errors.Join(compressed.Close(), output.Close())
	if writeErr != nil || closeErr != nil {
		t.Fatal(errors.Join(writeErr, closeErr))
	}
	if err := os.Chmod(name, before.Mode().Perm()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(name)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("loose-object corruption replaced the inode: %v", err)
	}
}

func mutateCLIFileSameInodeAndRestoreMtime(t *testing.T, name string) {
	t.Helper()
	before, err := os.Lstat(name)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(name)
	if err != nil || len(body) == 0 {
		t.Fatalf("read mutation fixture: %v", err)
	}
	body[len(body)-1] ^= 0x01
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.Write(body)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal(errors.Join(writeErr, closeErr))
	}
	if err := os.Chtimes(name, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(name)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() {
		t.Fatalf("same-inode worktree mutation changed identity: %v", err)
	}
}
