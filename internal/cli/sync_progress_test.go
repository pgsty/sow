package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/upstream"
)

func TestSyncProgressIsAtomicPrivateSecretFreeAndSymlinkSafe(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	if err := os.Mkdir(stateDir, 0o711); err != nil {
		t.Fatal(err)
	}
	operation, err := acquireSyncOperation(context.Background(), stateDir, "pgdg")
	if err != nil {
		t.Fatal(err)
	}
	defer operation.Close()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	progress := &syncProgress{
		Schema: syncProgressSchema, Upstream: "pgdg", Repository: "apt-test", Format: "apt",
		ConfigSHA256: strings.Repeat("a", 64), SelectionSHA256: strings.Repeat("b", 64),
		ReplaySHA256: emptySyncReplaySHA256, ReplayCount: 0,
		ProvenanceInputSHA256: strings.Repeat("d", 64),
		ProvenanceCommit:      strings.Repeat("c", 40), Phase: syncPhaseIngesting, CurrentUnit: "apt:main",
		CompletedUnits: []string{"apt:contrib"}, CreatedAt: now, UpdatedAt: now,
	}
	if err := operation.Write(progress); err != nil {
		t.Fatal(err)
	}
	progressPath := filepath.Join(operation.dir, syncProgressFilename)
	info, err := os.Lstat(progressPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("progress mode=%v err=%v", info, err)
	}
	body, err := os.ReadFile(progressPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret", "token", "passphrase", "error", "https://"} {
		if strings.Contains(strings.ToLower(string(body)), forbidden) {
			t.Fatalf("progress persisted forbidden field/value %q: %s", forbidden, body)
		}
	}
	loaded, err := operation.Load()
	if err != nil || !reflect.DeepEqual(loaded, progress) {
		t.Fatalf("loaded=%#v want=%#v err=%v", loaded, progress, err)
	}
	entries, err := os.ReadDir(operation.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".progress-") {
			t.Fatalf("atomic progress temporary file leaked: %s", entry.Name())
		}
	}

	if err := operation.RemoveProgress(); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(external, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, progressPath); err != nil {
		t.Fatal(err)
	}
	if err := operation.Write(progress); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("symlink progress replacement err=%v", err)
	}
	if body, err := os.ReadFile(external); err != nil || string(body) != "sentinel" {
		t.Fatalf("outside file changed body=%q err=%v", body, err)
	}
}

func TestSyncProgressExchangeRejectsDestinationAliasWithoutOverwrite(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	if err := os.Mkdir(stateDir, 0o711); err != nil {
		t.Fatal(err)
	}
	operation, err := acquireSyncOperation(context.Background(), stateDir, "pgdg")
	if err != nil {
		t.Fatal(err)
	}
	defer operation.Close()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	progress := &syncProgress{
		Schema: syncProgressSchema, Upstream: "pgdg", Repository: "apt-test", Format: "apt",
		ConfigSHA256: strings.Repeat("a", 64), SelectionSHA256: strings.Repeat("b", 64),
		ReplaySHA256: emptySyncReplaySHA256, ReplayCount: 0,
		ProvenanceInputSHA256: strings.Repeat("d", 64),
		Phase:                 syncPhasePrepared, CompletedUnits: []string{}, CreatedAt: now, UpdatedAt: now,
	}
	if err := operation.Write(progress); err != nil {
		t.Fatal(err)
	}
	progressPath := filepath.Join(operation.dir, syncProgressFilename)
	original, err := os.ReadFile(progressPath)
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "progress-alias")
	previous := derivedStateControlBeforeExchangeHook
	derivedStateControlBeforeExchangeHook = func(source, destination string) error {
		if destination != syncProgressFilename || !strings.HasPrefix(source, ".progress-") {
			return errors.New("unexpected sync progress exchange coordinates")
		}
		return os.Link(progressPath, alias)
	}
	t.Cleanup(func() { derivedStateControlBeforeExchangeHook = previous })
	updated := *progress
	updated.UpdatedAt = time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)
	if err := operation.Write(&updated); err == nil || !strings.Contains(err.Error(), "link count") {
		t.Fatalf("aliased progress destination was overwritten: %v", err)
	}
	derivedStateControlBeforeExchangeHook = previous
	current, currentErr := os.ReadFile(progressPath)
	aliased, aliasErr := os.ReadFile(alias)
	if currentErr != nil || aliasErr != nil ||
		!reflect.DeepEqual(current, original) || !reflect.DeepEqual(aliased, original) {
		t.Fatalf("failed progress exchange changed evidence current=%q alias=%q currentErr=%v aliasErr=%v", current, aliased, currentErr, aliasErr)
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := operation.Write(&updated); err != nil {
		t.Fatalf("progress did not converge after external alias removal: %v", err)
	}
}

func TestSyncOperationLockFailsClosedAndReleasesWithDescriptor(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	if err := os.Mkdir(stateDir, 0o711); err != nil {
		t.Fatal(err)
	}
	first, err := acquireSyncOperation(context.Background(), stateDir, "pgdg")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireSyncOperation(context.Background(), stateDir, "pgdg"); err == nil || !strings.Contains(err.Error(), "already active") {
		t.Fatalf("concurrent same-upstream lock err=%v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := acquireSyncOperation(context.Background(), stateDir, "pgdg")
	if err != nil {
		t.Fatalf("descriptor release did not make operation replayable: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}

	unsafeDir := filepath.Join(stateDir, "sync", "unsafe")
	if err := os.Mkdir(unsafeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "lock")
	if err := os.WriteFile(outside, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(unsafeDir, ".operation.lock")); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireSyncOperation(context.Background(), stateDir, "unsafe"); err == nil || !strings.Contains(err.Error(), "private regular") {
		t.Fatalf("unsafe operation lock err=%v", err)
	}
}

func TestSyncControlDirectoriesAndLockRejectHostileWriterAdmission(t *testing.T) {
	t.Run("writable directory is never chmodded", func(t *testing.T) {
		stateDir := filepath.Join(t.TempDir(), ".sow")
		if err := os.Mkdir(stateDir, 0o711); err != nil {
			t.Fatal(err)
		}
		syncDir := filepath.Join(stateDir, "sync")
		if err := os.Mkdir(syncDir, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(syncDir, 0o777); err != nil {
			t.Fatal(err)
		}
		if _, err := acquireSyncOperation(context.Background(), stateDir, "pgdg"); err == nil ||
			!strings.Contains(err.Error(), "group/other writable") {
			t.Fatalf("writable sync directory was admitted: %v", err)
		}
		info, err := os.Lstat(syncDir)
		if err != nil || info.Mode().Perm() != 0o777 {
			t.Fatalf("unsafe pre-existing directory was mutated: mode=%v err=%v", info.Mode().Perm(), err)
		}
	})

	t.Run("persistent lock hardlink is preserved", func(t *testing.T) {
		stateDir := filepath.Join(t.TempDir(), ".sow")
		if err := os.Mkdir(stateDir, 0o711); err != nil {
			t.Fatal(err)
		}
		operation, err := acquireSyncOperation(context.Background(), stateDir, "pgdg")
		if err != nil {
			t.Fatal(err)
		}
		lockPath := filepath.Join(operation.dir, ".operation.lock")
		if err := operation.Close(); err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(t.TempDir(), "operation-lock-alias")
		if err := os.Link(lockPath, alias); err != nil {
			t.Fatal(err)
		}
		if _, err := acquireSyncOperation(context.Background(), stateDir, "pgdg"); err == nil ||
			!strings.Contains(err.Error(), "private regular") {
			t.Fatalf("hardlink-aliased operation lock was admitted: %v", err)
		}
		left, leftErr := os.Lstat(lockPath)
		right, rightErr := os.Lstat(alias)
		if leftErr != nil || rightErr != nil || !os.SameFile(left, right) {
			t.Fatalf("operation-lock alias evidence was not preserved: left=%v right=%v", leftErr, rightErr)
		}
	})
}

func TestSyncProgressAndReplayRejectHardlinkAliases(t *testing.T) {
	t.Run("progress", func(t *testing.T) {
		stateDir := filepath.Join(t.TempDir(), ".sow")
		if err := os.Mkdir(stateDir, 0o711); err != nil {
			t.Fatal(err)
		}
		operation, err := acquireSyncOperation(context.Background(), stateDir, "pgdg")
		if err != nil {
			t.Fatal(err)
		}
		defer operation.Close()
		progress := validSyncProgressFixture()
		if err := operation.Write(&progress); err != nil {
			t.Fatal(err)
		}
		progressPath := filepath.Join(operation.dir, syncProgressFilename)
		alias := filepath.Join(t.TempDir(), "progress-alias")
		if err := os.Link(progressPath, alias); err != nil {
			t.Fatal(err)
		}
		if _, err := operation.Load(); err == nil || !strings.Contains(err.Error(), "single-link") {
			t.Fatalf("hardlink-aliased progress was read: %v", err)
		}
		if err := operation.RemoveProgress(); err == nil || !strings.Contains(err.Error(), "unsafe") {
			t.Fatalf("hardlink-aliased progress was removed: %v", err)
		}
		left, leftErr := os.Lstat(progressPath)
		right, rightErr := os.Lstat(alias)
		if leftErr != nil || rightErr != nil || !os.SameFile(left, right) {
			t.Fatalf("progress alias evidence was not preserved: left=%v right=%v", leftErr, rightErr)
		}
	})

	t.Run("replay callback interval", func(t *testing.T) {
		stateDir := filepath.Join(t.TempDir(), ".sow")
		if err := os.Mkdir(stateDir, 0o711); err != nil {
			t.Fatal(err)
		}
		operation, err := acquireSyncOperation(context.Background(), stateDir, "pgdg")
		if err != nil {
			t.Fatal(err)
		}
		defer operation.Close()
		records := []syncReplayRecord{
			{Format: "deb", SHA256: strings.Repeat("1", 64), Size: 1, Name: "one", Version: "1", Arch: "amd64", Basename: "one.deb", Component: "main"},
			{Format: "deb", SHA256: strings.Repeat("2", 64), Size: 1, Name: "two", Version: "1", Arch: "amd64", Basename: "two.deb", Component: "main"},
		}
		sha, count, err := operation.WriteReplay(records, "", 0)
		if err != nil {
			t.Fatal(err)
		}
		progress := &syncProgress{ReplaySHA256: sha, ReplayCount: count}
		replayPath := filepath.Join(operation.dir, syncReplayFilename)
		alias := filepath.Join(t.TempDir(), "replay-alias")
		callbacks := 0
		err = operation.ForEachReplay(progress, func(syncReplayRecord) error {
			callbacks++
			if callbacks == 1 {
				return os.Link(replayPath, alias)
			}
			return nil
		})
		if err == nil || !strings.Contains(err.Error(), "link count") {
			t.Fatalf("replay callback interval accepted a new hardlink alias: callbacks=%d err=%v", callbacks, err)
		}
		if callbacks != 1 {
			t.Fatalf("replay continued callbacks after authority drift: %d", callbacks)
		}
		if err := operation.RemoveReplay(); err == nil || !strings.Contains(err.Error(), "unsafe") {
			t.Fatalf("hardlink-aliased replay was removed: %v", err)
		}
		left, leftErr := os.Lstat(replayPath)
		right, rightErr := os.Lstat(alias)
		if leftErr != nil || rightErr != nil || !os.SameFile(left, right) {
			t.Fatalf("replay alias evidence was not preserved: left=%v right=%v", leftErr, rightErr)
		}
	})
}

func validSyncProgressFixture() syncProgress {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return syncProgress{
		Schema: syncProgressSchema, Upstream: "pgdg", Repository: "apt-test", Format: "apt",
		ConfigSHA256: strings.Repeat("a", 64), SelectionSHA256: strings.Repeat("b", 64),
		ReplaySHA256: emptySyncReplaySHA256, ReplayCount: 0,
		ProvenanceInputSHA256: strings.Repeat("d", 64),
		ProvenanceCommit:      strings.Repeat("c", 40), Phase: syncPhaseIngesting, CurrentUnit: "apt:main",
		CompletedUnits: []string{}, CreatedAt: now, UpdatedAt: now,
	}
}

func TestSyncOperationSIGKILLLeavesReplayableProgressAndResidue(t *testing.T) {
	if os.Getenv("SOW_TEST_SYNC_SIGKILL_CHILD") == "1" {
		stateDir := os.Getenv("SOW_TEST_SYNC_SIGKILL_STATE")
		operation, err := acquireSyncOperation(context.Background(), stateDir, "pgdg")
		if err != nil {
			panic(err)
		}
		defer operation.Close()
		now := time.Now().UTC().Format(time.RFC3339Nano)
		progress := &syncProgress{
			Schema: syncProgressSchema, Upstream: "pgdg", Repository: "apt-test", Format: "apt",
			ConfigSHA256: strings.Repeat("a", 64), SelectionSHA256: strings.Repeat("b", 64),
			ReplaySHA256: emptySyncReplaySHA256, ReplayCount: 0,
			ProvenanceInputSHA256: strings.Repeat("d", 64),
			ProvenanceCommit:      strings.Repeat("c", 40), Phase: syncPhaseIngesting, CurrentUnit: "apt:main",
			CompletedUnits: []string{}, CreatedAt: now, UpdatedAt: now,
		}
		replaySHA, replayCount, err := operation.WriteReplay(nil, "", 0)
		if err != nil {
			panic(err)
		}
		progress.ReplaySHA256, progress.ReplayCount = replaySHA, replayCount
		if err := operation.Write(progress); err != nil {
			panic(err)
		}
		orphan := filepath.Join(stateDir, "transactions", "sync-pgdg-killed")
		if err := os.MkdirAll(orphan, 0o700); err != nil {
			panic(err)
		}
		if err := os.WriteFile(filepath.Join(orphan, "journal"), []byte("durable"), 0o600); err != nil {
			panic(err)
		}
		fmt.Fprintln(os.Stdout, "ready")
		select {}
	}

	stateDir := filepath.Join(t.TempDir(), ".sow")
	if err := os.Mkdir(stateDir, 0o711); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestSyncOperationSIGKILLLeavesReplayableProgressAndResidue$")
	command.Env = append(os.Environ(), "SOW_TEST_SYNC_SIGKILL_CHILD=1", "SOW_TEST_SYNC_SIGKILL_STATE="+stateDir)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() && scanner.Text() == "ready" {
			ready <- nil
			return
		}
		ready <- errors.Join(scanner.Err(), errors.New("SIGKILL child did not become ready"))
	}()
	select {
	case err := <-ready:
		if err != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal("timed out waiting for SIGKILL child")
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("SIGKILL child exited successfully")
	}

	operation, err := acquireSyncOperation(context.Background(), stateDir, "pgdg")
	if err != nil {
		t.Fatalf("advisory lock remained stale after SIGKILL: %v", err)
	}
	defer operation.Close()
	progress, err := operation.Load()
	if err != nil || progress == nil || progress.Phase != syncPhaseIngesting || progress.ProvenanceCommit != strings.Repeat("c", 40) {
		t.Fatalf("durable progress after SIGKILL=%#v err=%v", progress, err)
	}
	current := filepath.Join(stateDir, "transactions", "sync-pgdg-replay")
	if err := os.Mkdir(current, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := cleanupSyncTransactionResidue(stateDir, "pgdg", current); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(stateDir, "transactions", "sync-pgdg-killed")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("SIGKILL residue remains: %v", err)
	}
	if err := operation.RemoveProgress(); err != nil {
		t.Fatal(err)
	}
}

func TestSyncProgressRequiresExactIntentEvenWithRecover(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	original := syncProgress{
		Schema: syncProgressSchema, Upstream: "pgdg", Repository: "apt-test", Format: "apt",
		ConfigSHA256: strings.Repeat("a", 64), SelectionSHA256: strings.Repeat("b", 64),
		ReplaySHA256: emptySyncReplaySHA256, ReplayCount: 0,
		ProvenanceInputSHA256: strings.Repeat("d", 64),
		ProvenanceCommit:      strings.Repeat("c", 40), Phase: syncPhaseProvenanceCommitted,
		CompletedUnits: []string{}, CreatedAt: now, UpdatedAt: now,
	}
	for _, test := range []struct {
		name string
		edit func(*syncProgress)
	}{
		{name: "config", edit: func(value *syncProgress) { value.ConfigSHA256 = strings.Repeat("d", 64) }},
		{name: "selector", edit: func(value *syncProgress) { value.SelectionSHA256 = strings.Repeat("e", 64) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			progress, wanted := original, original
			test.edit(&wanted)
			if err := reconcileSyncProgress(&progress, &wanted, false); err == nil || !strings.Contains(err.Error(), "exact original") {
				t.Fatalf("mismatch err=%v", err)
			}
			if err := reconcileSyncProgress(&progress, &wanted, true); err == nil || !strings.Contains(err.Error(), "cannot rebind") {
				t.Fatalf("--recover unexpectedly rebound durable intent: %v", err)
			}
			if progress.ConfigSHA256 != original.ConfigSHA256 || progress.SelectionSHA256 != original.SelectionSHA256 {
				t.Fatal("mismatch mutated durable sync identity")
			}
		})
	}
	if !errors.Is((&durableSyncPartialError{err: context.Canceled}), context.Canceled) {
		t.Fatal("partial error does not preserve cause identity")
	}
}

func TestPreparedSyncProgressCannotClaimCanonicalOrProjectionWork(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	valid := syncProgress{
		Schema: syncProgressSchema, Upstream: "pgdg", Repository: "apt-test", Format: "apt",
		ConfigSHA256: strings.Repeat("a", 64), SelectionSHA256: strings.Repeat("b", 64),
		ReplaySHA256: emptySyncReplaySHA256, ProvenanceInputSHA256: strings.Repeat("c", 64),
		Phase: syncPhasePrepared, CompletedUnits: []string{}, CreatedAt: now, UpdatedAt: now,
	}
	for _, test := range []struct {
		name string
		edit func(*syncProgress)
	}{
		{name: "transaction", edit: func(value *syncProgress) { value.ProvenanceTransaction = strings.Repeat("d", 32) }},
		{name: "commit", edit: func(value *syncProgress) { value.ProvenanceCommit = strings.Repeat("e", 40) }},
		{name: "current-unit", edit: func(value *syncProgress) { value.CurrentUnit = "apt:main" }},
		{name: "completed-unit", edit: func(value *syncProgress) { value.CompletedUnits = []string{"apt:main"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.edit(&candidate)
			if _, err := candidate.canonical(); err == nil || !strings.Contains(err.Error(), "prepared sync phase") {
				t.Fatalf("invalid prepared progress accepted: %#v err=%v", candidate, err)
			}
		})
	}
}

func TestSyncTransactionCleanupUsesExactPrefixAndFailsClosedOnSymlink(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	transactionDir := filepath.Join(stateDir, "transactions")
	current := filepath.Join(transactionDir, "sync-pgdg-current")
	orphan := filepath.Join(transactionDir, "sync-pgdg-orphan")
	unrelated := filepath.Join(transactionDir, "sync-other-keep")
	for _, path := range []string{current, orphan, unrelated} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "regular"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	outside := t.TempDir()
	unsafe := filepath.Join(transactionDir, "sync-pgdg-unsafe")
	if err := os.Symlink(outside, unsafe); err != nil {
		t.Fatal(err)
	}
	if err := cleanupSyncTransactionResidue(stateDir, "pgdg", current); err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("symlink residue cleanup err=%v", err)
	}
	for _, path := range []string{current, orphan, unrelated, outside} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("fail-closed cleanup changed %s: %v", path, err)
		}
	}
	if err := os.Remove(unsafe); err != nil {
		t.Fatal(err)
	}
	if err := cleanupSyncTransactionResidue(stateDir, "pgdg", current); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{current, orphan} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("matching residue remains %s: %v", path, err)
		}
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("exact-prefix cleanup removed unrelated transaction: %v", err)
	}
}

func TestCompletedSyncDownloadCleanupFailsClosedOnUnsafeEntry(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	operation, err := acquireSyncOperation(context.Background(), stateDir, "pgdg")
	if err != nil {
		t.Fatal(err)
	}
	defer operation.Close()
	record := syncReplayRecord{
		Format: "deb", SHA256: strings.Repeat("a", 64), Size: 7,
		Name: "example", Version: "1", Arch: "amd64", Basename: "example_1_amd64.deb", Component: "main",
	}
	replaySHA, replayCount, err := operation.WriteReplay([]syncReplayRecord{record}, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	progress := &syncProgress{ReplaySHA256: replaySHA, ReplayCount: replayCount}
	downloads := filepath.Join(operation.dir, "downloads")
	if err := os.Mkdir(downloads, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	unsafe := filepath.Join(downloads, record.SHA256+".download")
	if err := os.Symlink(outside, unsafe); err != nil {
		t.Fatal(err)
	}
	if err := operation.RemoveReplayDownloads(progress); err == nil || !strings.Contains(err.Error(), "unsafe sync download file") {
		t.Fatalf("unsafe completed download was accepted: %v", err)
	}
	body, err := os.ReadFile(outside)
	if err != nil || string(body) != "outside" {
		t.Fatalf("cleanup changed symlink target: body=%q err=%v", body, err)
	}
}

func TestSyncReplayExchangeRejectsDestinationAliasWithoutOverwrite(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	if err := os.Mkdir(stateDir, 0o711); err != nil {
		t.Fatal(err)
	}
	operation, err := acquireSyncOperation(context.Background(), stateDir, "pgdg")
	if err != nil {
		t.Fatal(err)
	}
	defer operation.Close()
	record := syncReplayRecord{
		Format: "deb", SHA256: strings.Repeat("a", 64), Size: 7,
		Name: "example", Version: "1", Arch: "amd64", Basename: "example_1_amd64.deb", Component: "main",
	}
	if _, _, err := operation.WriteReplay([]syncReplayRecord{record}, "", 0); err != nil {
		t.Fatal(err)
	}
	replayPath := filepath.Join(operation.dir, syncReplayFilename)
	original, err := os.ReadFile(replayPath)
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "replay-alias")
	previous := derivedStateControlBeforeExchangeHook
	derivedStateControlBeforeExchangeHook = func(source, destination string) error {
		if destination != syncReplayFilename || !strings.HasPrefix(source, ".replay-") {
			return errors.New("unexpected sync replay exchange coordinates")
		}
		return os.Link(replayPath, alias)
	}
	t.Cleanup(func() { derivedStateControlBeforeExchangeHook = previous })
	updated := record
	updated.SHA256 = strings.Repeat("b", 64)
	updated.Basename = "example_2_amd64.deb"
	updated.Version = "2"
	if _, _, err := operation.WriteReplay([]syncReplayRecord{updated}, "", 0); err == nil ||
		!strings.Contains(err.Error(), "link count") {
		t.Fatalf("aliased replay destination was overwritten: %v", err)
	}
	derivedStateControlBeforeExchangeHook = previous
	current, currentErr := os.ReadFile(replayPath)
	aliased, aliasErr := os.ReadFile(alias)
	if currentErr != nil || aliasErr != nil ||
		!reflect.DeepEqual(current, original) || !reflect.DeepEqual(aliased, original) {
		t.Fatalf("failed replay exchange changed evidence current=%q alias=%q currentErr=%v aliasErr=%v", current, aliased, currentErr, aliasErr)
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if _, _, err := operation.WriteReplay([]syncReplayRecord{updated}, "", 0); err != nil {
		t.Fatalf("replay did not converge after external alias removal: %v", err)
	}
}

func TestCompletedSyncDownloadCleanupRemovesHistoricalAndFailedResidue(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	operation, err := acquireSyncOperation(context.Background(), stateDir, "pgdg")
	if err != nil {
		t.Fatal(err)
	}
	defer operation.Close()
	record := syncReplayRecord{
		Format: "deb", SHA256: strings.Repeat("a", 64), Size: 7,
		Name: "example", Version: "1", Arch: "amd64", Basename: "example_1_amd64.deb", Component: "main",
	}
	replaySHA, replayCount, err := operation.WriteReplay([]syncReplayRecord{record}, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	progress := &syncProgress{ReplaySHA256: replaySHA, ReplayCount: replayCount}
	downloads := filepath.Join(operation.dir, "downloads")
	if err := os.Mkdir(downloads, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		record.SHA256 + ".download",
		strings.Repeat("b", 64) + ".download",
		strings.Repeat("c", 64) + ".part",
		strings.Repeat("d", 64) + ".lock",
	} {
		if err := os.WriteFile(filepath.Join(downloads, name), []byte("residue"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := operation.RemoveReplayDownloads(progress); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(downloads); err != nil || len(entries) != 0 {
		t.Fatalf("recognized transport residue remains: entries=%v err=%v", entries, err)
	}
	if err := os.WriteFile(filepath.Join(downloads, "unexpected"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := operation.RemoveReplayDownloads(progress); err == nil || !strings.Contains(err.Error(), "unknown sync download residue") {
		t.Fatalf("unknown transport residue was ignored: %v", err)
	}
}

func TestSyncReplayRecordFieldBoundariesAreClosedBeforeProgress(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), ".sow")
	if err := os.Mkdir(stateDir, 0o711); err != nil {
		t.Fatal(err)
	}
	operation, err := acquireSyncOperation(context.Background(), stateDir, "pgdg")
	if err != nil {
		t.Fatal(err)
	}
	defer operation.Close()
	valid := syncReplayRecord{
		Format: "deb", SHA256: strings.Repeat("a", 64), Size: 1,
		Name: strings.Repeat("n", 1024), Version: strings.Repeat("v", 1024),
		Arch: strings.Repeat("x", 128), Basename: strings.Repeat("b", 1020) + ".deb",
		Component: strings.Repeat("c", 256),
	}
	sha, count, err := operation.WriteReplay([]syncReplayRecord{valid}, "", 0)
	if err != nil || !syncProgressSHA256Pattern.MatchString(sha) || count != 1 {
		t.Fatalf("closed-boundary replay sha=%s count=%d err=%v", sha, count, err)
	}
	for _, test := range []struct {
		name string
		edit func(*syncReplayRecord)
	}{
		{name: "name", edit: func(value *syncReplayRecord) { value.Name += "n" }},
		{name: "version", edit: func(value *syncReplayRecord) { value.Version += "v" }},
		{name: "arch", edit: func(value *syncReplayRecord) { value.Arch += "x" }},
		{name: "basename", edit: func(value *syncReplayRecord) { value.Basename = strings.Repeat("b", 1021) + ".deb" }},
		{name: "component", edit: func(value *syncReplayRecord) { value.Component += "c" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			invalid := valid
			test.edit(&invalid)
			if _, _, err := operation.WriteReplay([]syncReplayRecord{invalid}, "", 0); err == nil || !strings.Contains(err.Error(), "sync replay record") {
				t.Fatalf("oversized %s accepted err=%v", test.name, err)
			}
		})
	}
	info, err := os.Stat(filepath.Join(operation.dir, syncReplayFilename))
	if err != nil || info.Size() > syncReplayMaxRecordBytes {
		t.Fatalf("valid replay size=%v err=%v", info, err)
	}
}

func TestSyncProvenanceInputIdentityRejectsChangedEvidence(t *testing.T) {
	discovery := &upstream.Discovery{Format: "deb", Evidence: []upstream.Evidence{{
		Kind: "apt-inrelease", SHA256: strings.Repeat("a", 64), Size: 42, Verified: true,
	}}}
	first, err := syncProvenanceInputSHA256(discovery, emptySyncReplaySHA256, 0)
	if err != nil {
		t.Fatal(err)
	}
	discovery.Evidence[0].SHA256 = strings.Repeat("b", 64)
	second, err := syncProvenanceInputSHA256(discovery, emptySyncReplaySHA256, 0)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("changed upstream evidence rebound prepared sync intent")
	}
}

func TestCanonicalSyncContractRejectsInPlaceKeyRotationBeforeInitialConfigCommit(t *testing.T) {
	fixture := newSyncAPTRecoveryFixture(t, []string{"main"})
	cfg, err := config.Load(fixture.configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	repo, exists := cfg.RepoByName("apt-test")
	if !exists {
		t.Fatal("fixture repository missing")
	}
	source := cfg.Upstreams[0]
	expected, err := syncSelectionSHA256(cfg, repo, source)
	if err != nil {
		t.Fatal(err)
	}
	_, rotatedPublic := generateRepositorySigningKey(t, "sync-precommit-rotation")
	if err := os.WriteFile(filepath.Join(fixture.root, "upstream.asc"), rotatedPublic, 0o644); err != nil {
		t.Fatal(err)
	}
	configExists, err := validateCanonicalSyncContract(state.New(cfg.StatePath()), cfg, repo, source, expected)
	if err == nil || configExists || !strings.Contains(err.Error(), "signing-key contract changed") {
		t.Fatalf("pre-commit same-path key rotation exists=%v err=%v", configExists, err)
	}
}

func TestSyncSelectionNormalizesRepositoryKeyArmorFraming(t *testing.T) {
	fixture := newSyncAPTRecoveryFixture(t, []string{"main"})
	cfg, err := config.Load(fixture.configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	repo, exists := cfg.RepoByName("apt-test")
	if !exists {
		t.Fatal("fixture repository missing")
	}
	source := cfg.Upstreams[0]
	repositoryKeyPath := filepath.Join(fixture.root, "repository-public.asc")
	originalKey, err := os.ReadFile(filepath.Join(fixture.root, "upstream.asc"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(repositoryKeyPath, originalKey, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg.GPG.PublicKey = filepath.Base(repositoryKeyPath)
	armoredSelection, err := syncSelectionSHA256(cfg, repo, source)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := repositoryKeyPath
	armored, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	packets, err := decodeRepositoryPublicKeyPackets(armored)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, packets, 0o644); err != nil {
		t.Fatal(err)
	}
	binarySelection, err := syncSelectionSHA256(cfg, repo, source)
	if err != nil {
		t.Fatal(err)
	}
	if armoredSelection != binarySelection {
		t.Fatalf("armor-only repository key reformat changed sync identity: %s != %s", armoredSelection, binarySelection)
	}
}

func TestSyncSelectionBindsInPlaceUpstreamAndPackageKeyringRotation(t *testing.T) {
	root := t.TempDir()
	_, repositoryPublic := generateRepositorySigningKey(t, "sync-selection-repository")
	_, upstreamPublic := generateRepositorySigningKey(t, "sync-selection-upstream")
	_, rotatedUpstreamPublic := generateRepositorySigningKey(t, "sync-selection-upstream-rotated")
	_, packagePublic := generateRepositorySigningKey(t, "sync-selection-package")
	_, rotatedPackagePublic := generateRepositorySigningKey(t, "sync-selection-package-rotated")
	for name, body := range map[string][]byte{
		"repository.pgp": repositoryPublic,
		"upstream.pgp":   upstreamPublic,
		"packages.pgp":   packagePublic,
	} {
		if err := os.WriteFile(filepath.Join(root, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{
		Path: filepath.Join(root, "sow.yaml"),
		GPG:  config.GPGConfig{PublicKey: "repository.pgp"},
		Views: map[string]config.View{
			"beta":   {Access: "public", AllowedPools: []string{"public"}},
			"stable": {Access: "pro", AllowedPools: []string{"public", "gated"}, AppendOnly: true},
		},
	}
	repo := config.Repo{
		ID: "rpm", Type: "yum", DefaultPool: "public", Arches: []string{"x86_64", "noarch"},
		OS:  config.OSConfig{Family: "rhel", Major: 9, Lifecycle: "active"},
		YUM: &config.YUMConfig{Compression: "zstd", PackageKeyring: "packages.pgp", NoarchMode: config.YUMNoarchReplicate},
	}
	source := config.Upstream{
		ID: "pgdg", Type: "yum", Repo: repo.ID, URL: "https://example.invalid/yum/9/x86_64/",
		Arches: []string{"x86_64", "noarch"}, Keyring: "upstream.pgp",
	}

	initial, err := syncSelectionSHA256(cfg, repo, source)
	if err != nil {
		t.Fatal(err)
	}
	separateRepo := repo
	separateYUM := *repo.YUM
	separateYUM.NoarchMode = config.YUMNoarchSeparate
	separateRepo.YUM = &separateYUM
	separateSelection, err := syncSelectionSHA256(cfg, separateRepo, source)
	if err != nil {
		t.Fatal(err)
	}
	if separateSelection == initial {
		t.Fatal("YUM noarch routing mode change did not invalidate frozen sync identity")
	}
	if err := os.WriteFile(filepath.Join(root, source.Keyring), rotatedUpstreamPublic, 0o644); err != nil {
		t.Fatal(err)
	}
	upstreamRotated, err := syncSelectionSHA256(cfg, repo, source)
	if err != nil {
		t.Fatal(err)
	}
	if upstreamRotated == initial {
		t.Fatal("in-place upstream metadata keyring rotation did not change frozen sync identity")
	}

	if err := os.WriteFile(filepath.Join(root, source.Keyring), upstreamPublic, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, repo.YUM.PackageKeyring), rotatedPackagePublic, 0o644); err != nil {
		t.Fatal(err)
	}
	packageRotated, err := syncSelectionSHA256(cfg, repo, source)
	if err != nil {
		t.Fatal(err)
	}
	if packageRotated == initial {
		t.Fatal("in-place RPM package keyring rotation did not change frozen sync identity")
	}
}
