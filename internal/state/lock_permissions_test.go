package state

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAcquireLockBuildsTraverseOnlyServingCorridorAndProtectsControlChildren(t *testing.T) {
	root := t.TempDir()
	stateRoot := filepath.Join(root, ".sow")
	for _, directory := range []string{
		filepath.Join(stateRoot, "state"),
		filepath.Join(stateRoot, "sync"),
		filepath.Join(stateRoot, "materialized"),
		filepath.Join(stateRoot, "origin"),
	} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	directSecret := filepath.Join(stateRoot, "secret")
	if err := os.WriteFile(directSecret, []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directSecret, 0o644); err != nil {
		t.Fatal(err)
	}
	lock, err := AcquireLock(stateRoot, "permission-test", false)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	assertStateMode(t, stateRoot, 0o711)
	assertStateMode(t, filepath.Join(stateRoot, "materialized"), 0o755)
	assertStateMode(t, filepath.Join(stateRoot, "origin"), 0o755)
	assertStateMode(t, filepath.Join(stateRoot, "state"), 0o700)
	assertStateMode(t, filepath.Join(stateRoot, "sync"), 0o700)
	assertStateMode(t, filepath.Join(stateRoot, "locks"), 0o700)
	assertStateMode(t, directSecret, 0o600)
}

func TestAcquireLockRejectsSymlinkedStateChildBeforeOpeningCorridor(t *testing.T) {
	root := t.TempDir()
	stateRoot := filepath.Join(root, ".sow")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(stateRoot, "state")); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(stateRoot, "permission-test", false); err == nil {
		t.Fatal("symlinked state child was accepted")
	}
	assertStateMode(t, stateRoot, 0o700)
}

func TestAcquireLockRejectsWritableExistingStateDirectoriesWithoutMutation(t *testing.T) {
	t.Run("immediate parent", func(t *testing.T) {
		parent := t.TempDir()
		stateRoot := filepath.Join(parent, ".sow")
		if err := os.Mkdir(stateRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o777); err != nil {
			t.Fatal(err)
		}
		before := snapshotFilesystemEntry(t, stateRoot)
		if _, err := AcquireLock(stateRoot, "unsafe-state-parent", false); err == nil || !strings.Contains(err.Error(), "group/other writable") {
			t.Fatalf("writable immediate parent was accepted: %v", err)
		}
		assertFilesystemEntryUnchanged(t, stateRoot, before)
		if _, err := os.Lstat(filepath.Join(stateRoot, "locks")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unsafe immediate-parent rejection created locks: %v", err)
		}
	})

	t.Run("state root", func(t *testing.T) {
		stateRoot := filepath.Join(t.TempDir(), ".sow")
		if err := os.Mkdir(stateRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(stateRoot, 0o720); err != nil {
			t.Fatal(err)
		}
		fixed := time.Date(2020, 2, 3, 4, 5, 6, 0, time.UTC)
		if err := os.Chtimes(stateRoot, fixed, fixed); err != nil {
			t.Fatal(err)
		}
		before := snapshotFilesystemEntry(t, stateRoot)
		if _, err := AcquireLock(stateRoot, "unsafe-state-root", false); err == nil || !strings.Contains(err.Error(), "group/other writable") {
			t.Fatalf("writable existing state root was accepted: %v", err)
		}
		assertFilesystemEntryUnchanged(t, stateRoot, before)
		if _, err := os.Lstat(filepath.Join(stateRoot, "locks")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unsafe state-root rejection created locks: %v", err)
		}
	})

	t.Run("locks root", func(t *testing.T) {
		stateRoot := filepath.Join(t.TempDir(), ".sow")
		locksRoot := filepath.Join(stateRoot, "locks")
		if err := os.MkdirAll(locksRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		control := filepath.Join(locksRoot, "control")
		if err := os.WriteFile(control, []byte("unchanged\n"), 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(locksRoot, 0o702); err != nil {
			t.Fatal(err)
		}
		fixed := time.Date(2021, 3, 4, 5, 6, 7, 0, time.UTC)
		if err := os.Chtimes(locksRoot, fixed, fixed); err != nil {
			t.Fatal(err)
		}
		beforeState := snapshotFilesystemEntry(t, stateRoot)
		beforeLocks := snapshotFilesystemEntry(t, locksRoot)
		beforeControl := snapshotFilesystemEntry(t, control)
		if _, err := AcquireLock(stateRoot, "unsafe-lock-root", false); err == nil || !strings.Contains(err.Error(), "group/other writable") {
			t.Fatalf("writable existing locks root was accepted: %v", err)
		}
		assertFilesystemEntryUnchanged(t, stateRoot, beforeState)
		assertFilesystemEntryUnchanged(t, locksRoot, beforeLocks)
		assertFilesystemEntryUnchanged(t, control, beforeControl)
		for _, name := range []string{"state.lease", "state.lock"} {
			if _, err := os.Lstat(filepath.Join(locksRoot, name)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unsafe locks-root rejection created %s: %v", name, err)
			}
		}
	})
}

func TestStateLockRejectsHardlinkAliases(t *testing.T) {
	t.Run("preexisting persistent lease alias", func(t *testing.T) {
		stateRoot := filepath.Join(t.TempDir(), ".sow")
		locksRoot := filepath.Join(stateRoot, "locks")
		if err := os.MkdirAll(locksRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		lease := filepath.Join(locksRoot, "state.lease")
		alias := filepath.Join(locksRoot, "state.lease.alias")
		if err := os.WriteFile(lease, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(lease, alias); err != nil {
			t.Fatal(err)
		}
		before := snapshotFilesystemEntry(t, lease)
		if _, err := AcquireLock(stateRoot, "aliased-lease", false); err == nil || !strings.Contains(err.Error(), "link count 2") {
			t.Fatalf("aliased persistent lease was accepted: %v", err)
		}
		assertFilesystemEntryUnchanged(t, lease, before)
		if _, err := os.Lstat(filepath.Join(locksRoot, "state.lock")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("aliased lease rejection published a lock record: %v", err)
		}
	})

	t.Run("active record alias", func(t *testing.T) {
		stateRoot := filepath.Join(t.TempDir(), ".sow")
		lock, err := AcquireLock(stateRoot, "active-alias", false)
		if err != nil {
			t.Fatal(err)
		}
		lockPath := filepath.Join(stateRoot, "locks", "state.lock")
		alias := filepath.Join(stateRoot, "locks", "state.lock.alias")
		if err := os.Link(lockPath, alias); err != nil {
			t.Fatal(err)
		}
		if err := lock.Validate(); err == nil || !strings.Contains(err.Error(), "link count 2") {
			t.Fatalf("active record alias was accepted: %v", err)
		}
		if err := os.Remove(alias); err != nil {
			t.Fatal(err)
		}
		if err := lock.Validate(); err != nil {
			t.Fatalf("holder did not converge after alias removal: %v", err)
		}
		if err := lock.Release(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestStateLockRejectsImmediateParentModeDriftAndConverges(t *testing.T) {
	parent := t.TempDir()
	stateRoot := filepath.Join(parent, ".sow")
	lock, err := AcquireLock(stateRoot, "parent-mode-drift", false)
	if err != nil {
		t.Fatal(err)
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o720); err != nil {
		t.Fatal(err)
	}
	if err := lock.Validate(); err == nil || !strings.Contains(err.Error(), "security identity changed") {
		t.Fatalf("immediate-parent mode drift was accepted: %v", err)
	}
	if err := os.Chmod(parent, parentInfo.Mode().Perm()); err != nil {
		t.Fatal(err)
	}
	if err := lock.Validate(); err != nil {
		t.Fatalf("holder did not converge after restoring parent mode: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestPermissionReconciliationNeverFollowsSwappedStateChildSymlink(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), ".sow")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(stateRoot, "secret")
	displaced := filepath.Join(stateRoot, "secret.displaced")
	servingRoot := filepath.Join(stateRoot, "materialized")
	victim := filepath.Join(servingRoot, "victim")
	if err := os.Mkdir(servingRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("secret\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victim, []byte("victim\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(victim, 0o666); err != nil {
		t.Fatal(err)
	}
	beforeVictim := snapshotFilesystemEntry(t, victim)
	swapped := false
	restore := replaceStatePermissionFault(func(stage, name string) error {
		if stage != statePermissionAfterChildLstat || name != "secret" || swapped {
			return nil
		}
		swapped = true
		if err := os.Rename(secret, displaced); err != nil {
			return err
		}
		return os.Symlink("materialized/victim", secret)
	})
	defer restore()
	if _, err := AcquireLock(stateRoot, "child-symlink-swap", false); err == nil || !strings.Contains(err.Error(), "descriptor-bound chmod") {
		t.Fatalf("child symlink swap was accepted: %v", err)
	}
	if !swapped {
		t.Fatal("child symlink fault seam was not reached")
	}
	assertFilesystemEntryUnchanged(t, victim, beforeVictim)
	if info, err := os.Lstat(secret); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("attack symlink was unexpectedly followed or removed: info=%v err=%v", info, err)
	}
	if _, err := os.Lstat(filepath.Join(stateRoot, "locks", "state.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed permission reconciliation retained state.lock: %v", err)
	}
}

func TestStateBootstrapNeverCreatesThroughReplacedParent(t *testing.T) {
	parent := t.TempDir()
	repository := filepath.Join(parent, "repository")
	displaced := repository + ".original"
	if err := os.Mkdir(repository, 0o700); err != nil {
		t.Fatal(err)
	}
	replacementCanary := filepath.Join(repository, "replacement-canary")
	swapped := false
	restore := replaceStatePermissionFault(func(stage, _ string) error {
		if stage != statePermissionAfterBootstrapParentLstat || swapped {
			return nil
		}
		swapped = true
		if err := os.Rename(repository, displaced); err != nil {
			return err
		}
		if err := os.Mkdir(repository, 0o700); err != nil {
			return err
		}
		return os.WriteFile(replacementCanary, []byte("replacement must survive\n"), 0o600)
	})
	defer restore()
	stateRoot := filepath.Join(repository, ".sow")
	if _, err := AcquireLock(stateRoot, "bootstrap-parent-swap", false); err == nil ||
		!strings.Contains(err.Error(), "parent changed") {
		t.Fatalf("bootstrap accepted a replaced immediate parent: %v", err)
	}
	if !swapped {
		t.Fatal("bootstrap parent fault seam was not reached")
	}
	if _, err := os.Lstat(stateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bootstrap created state through the replacement parent: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(displaced, ".sow")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bootstrap mutated the displaced original parent: %v", err)
	}
	if body, err := os.ReadFile(replacementCanary); err != nil || string(body) != "replacement must survive\n" {
		t.Fatalf("replacement parent canary changed: body=%q err=%v", body, err)
	}
}

func TestPermissionReconciliationRejectsHardlinkAliasBeforeChmod(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), ".sow")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(stateRoot, "secret")
	if err := os.WriteFile(secret, []byte("secret\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "secret-alias")
	linked := false
	restore := replaceStatePermissionFault(func(stage, name string) error {
		if stage != statePermissionAfterChildLstat || name != "secret" || linked {
			return nil
		}
		linked = true
		return os.Link(secret, alias)
	})
	defer restore()
	if _, err := AcquireLock(stateRoot, "child-hardlink-alias", false); err == nil ||
		!strings.Contains(err.Error(), "link count") {
		t.Fatalf("permission reconciliation accepted a new control-file hardlink: %v", err)
	}
	if !linked {
		t.Fatal("control-file hardlink fault seam was not reached")
	}
	secretInfo, secretErr := os.Lstat(secret)
	aliasInfo, aliasErr := os.Lstat(alias)
	if secretErr != nil || aliasErr != nil || !os.SameFile(secretInfo, aliasInfo) ||
		secretInfo.Mode().Perm() != 0o640 || aliasInfo.Mode().Perm() != 0o640 {
		t.Fatalf("hardlink evidence changed: secret=%v alias=%v secretErr=%v aliasErr=%v", secretInfo, aliasInfo, secretErr, aliasErr)
	}
	if body, err := os.ReadFile(alias); err != nil || string(body) != "secret\n" {
		t.Fatalf("hardlink evidence body=%q err=%v", body, err)
	}
}

func TestPermissionReconciliationChmodsBoundStateRootAfterPathSwap(t *testing.T) {
	parent := t.TempDir()
	stateRoot := filepath.Join(parent, ".sow")
	displaced := filepath.Join(parent, ".sow.displaced")
	victim := filepath.Join(parent, "victim")
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	beforeVictim := snapshotFilesystemEntry(t, victim)
	swapped := false
	restore := replaceStatePermissionFault(func(stage, name string) error {
		if stage != statePermissionBeforeRootChmod || name != "." || swapped {
			return nil
		}
		swapped = true
		if err := os.Rename(stateRoot, displaced); err != nil {
			return err
		}
		return os.Symlink("victim", stateRoot)
	})
	defer restore()
	if _, err := AcquireLock(stateRoot, "state-root-swap", false); err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("state-root path swap was accepted: %v", err)
	}
	if !swapped {
		t.Fatal("state-root fault seam was not reached")
	}
	assertFilesystemEntryUnchanged(t, victim, beforeVictim)
	assertStateMode(t, displaced, 0o711)
	if _, err := os.Lstat(filepath.Join(displaced, "locks", "state.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed root validation retained bound state.lock: %v", err)
	}
}

func TestLockRootSwapFailsValidationAndReleaseCannotDeleteReplacementLock(t *testing.T) {
	parent := t.TempDir()
	repositoryPath := filepath.Join(parent, "repository")
	if err := os.Mkdir(repositoryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(repositoryPath, ".sow")
	first, err := AcquireLock(statePath, "first-holder", false)
	if err != nil {
		t.Fatal(err)
	}
	displaced := repositoryPath + ".original"
	if err := os.Rename(repositoryPath, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(repositoryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	second, err := AcquireLock(statePath, "replacement-holder", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Validate(); err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("first holder accepted replacement state root: %v", err)
	}
	replacementLock := filepath.Join(statePath, "locks", "state.lock")
	replacementBefore, err := os.Lstat(replacementLock)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Release(); err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("release accepted a replaced lock coordinate: %v", err)
	}
	replacementAfter, err := os.Lstat(replacementLock)
	if err != nil || !os.SameFile(replacementBefore, replacementAfter) {
		t.Fatalf("first release removed or replaced second holder lock: %v", err)
	}
	if err := second.Validate(); err != nil {
		t.Fatalf("replacement holder lost its lock: %v", err)
	}
	if err := second.Release(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(repositoryPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(displaced, repositoryPath); err != nil {
		t.Fatal(err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("release bound original lock after restoring its coordinate: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(repositoryPath, ".sow", "locks", "state.lock")); !os.IsNotExist(err) {
		t.Fatalf("original bound lock remains after release: %v", err)
	}
}

func assertStateMode(t *testing.T, filename string, wanted os.FileMode) {
	t.Helper()
	info, err := os.Lstat(filename)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != wanted {
		t.Fatalf("%s mode=%#o want=%#o", filename, info.Mode().Perm(), wanted)
	}
}

type filesystemEntrySnapshot struct {
	info       os.FileInfo
	mode       os.FileMode
	modTime    time.Time
	size       int64
	changeTime int64
	hasChange  bool
}

func snapshotFilesystemEntry(t *testing.T, filename string) filesystemEntrySnapshot {
	t.Helper()
	info, err := os.Lstat(filename)
	if err != nil {
		t.Fatal(err)
	}
	changeTime, hasChange := filesystemChangeTime(info)
	return filesystemEntrySnapshot{
		info: info, mode: info.Mode(), modTime: info.ModTime(), size: info.Size(),
		changeTime: changeTime, hasChange: hasChange,
	}
}

func assertFilesystemEntryUnchanged(t *testing.T, filename string, before filesystemEntrySnapshot) {
	t.Helper()
	after, err := os.Lstat(filename)
	if err != nil {
		t.Fatal(err)
	}
	afterChange, afterHasChange := filesystemChangeTime(after)
	if !os.SameFile(before.info, after) || after.Mode() != before.mode ||
		!after.ModTime().Equal(before.modTime) || after.Size() != before.size ||
		afterHasChange != before.hasChange || (before.hasChange && afterChange != before.changeTime) {
		t.Fatalf("filesystem entry changed: path=%s before=%+v after_mode=%v after_mtime=%s after_size=%d after_ctime=%d has_ctime=%t", filename, before, after.Mode(), after.ModTime(), after.Size(), afterChange, afterHasChange)
	}
}

func filesystemChangeTime(info os.FileInfo) (int64, bool) {
	value := reflect.ValueOf(info.Sys())
	if !value.IsValid() {
		return 0, false
	}
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return 0, false
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return 0, false
	}
	for _, fieldName := range []string{"Ctimespec", "Ctim"} {
		stamp := value.FieldByName(fieldName)
		if !stamp.IsValid() || stamp.Kind() != reflect.Struct {
			continue
		}
		seconds := stamp.FieldByName("Sec")
		nanoseconds := stamp.FieldByName("Nsec")
		if seconds.IsValid() && nanoseconds.IsValid() && seconds.CanInt() && nanoseconds.CanInt() {
			return seconds.Int()*int64(time.Second) + nanoseconds.Int(), true
		}
	}
	return 0, false
}
