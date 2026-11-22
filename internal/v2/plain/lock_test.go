package plain

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateLockNoWaitTimeoutAndWait(t *testing.T) {
	dir := t.TempDir()
	writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "1.0-1", "amd64"), "alpha")
	holder, err := acquireDirectoryLock(context.Background(), dir, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Create(context.Background(), Options{Dir: dir, NoWait: true}); err == nil || KindOf(err) != KindLock {
		t.Fatalf("no-wait error = %v, kind = %s", err, KindOf(err))
	}
	started := time.Now()
	if _, err := Create(context.Background(), Options{Dir: dir, Timeout: 60 * time.Millisecond}); err == nil || KindOf(err) != KindLock {
		t.Fatalf("timeout error = %v, kind = %s", err, KindOf(err))
	}
	if elapsed := time.Since(started); elapsed < 45*time.Millisecond || elapsed > time.Second {
		t.Fatalf("timeout elapsed %s", elapsed)
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = holder.Close()
	}()
	if _, err := Create(context.Background(), Options{Dir: dir, Timeout: time.Second}); err != nil {
		t.Fatalf("wait for lock: %v", err)
	}
}

func TestDirectoryReplacementCannotAcquireIndependentPlainLock(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "repo")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	holder, err := acquireDirectoryLock(context.Background(), dir, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	detached := filepath.Join(parent, "detached")
	if err := os.Rename(dir, detached); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := holder.Validate(); err == nil || KindOf(err) != KindIntegrity {
		t.Fatalf("replaced lock target validation = %v, kind=%s", err, KindOf(err))
	}
	if _, err := acquireDirectoryLock(context.Background(), detached, 0, true); err == nil || KindOf(err) != KindLock {
		t.Fatalf("moved inode lost its lock: %v", err)
	}
}

func TestSiblingDirectoriesAcquirePlainLocksConcurrently(t *testing.T) {
	parent := t.TempDir()
	left := filepath.Join(parent, "el8")
	right := filepath.Join(parent, "el9")
	for _, dir := range []string{left, right} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	leftLock, err := acquireDirectoryLock(context.Background(), left, 0, true)
	if err != nil {
		t.Fatalf("lock el8: %v", err)
	}
	defer leftLock.Close()
	rightLock, err := acquireDirectoryLock(context.Background(), right, 0, true)
	if err != nil {
		t.Fatalf("sibling el9 blocked by el8 parent lock: %v", err)
	}
	defer rightLock.Close()
}

func TestDirectoryLockDoesNotRelockFilesystemRoot(t *testing.T) {
	root := string(filepath.Separator)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lock, err := acquireDirectoryLock(ctx, root, 500*time.Millisecond, false)
	if err != nil {
		t.Fatalf("lock filesystem root: %v", err)
	}
	if lock.targetFile == nil {
		t.Fatal("filesystem root did not bind target descriptor")
	}
	if err := lock.Validate(); err != nil {
		t.Fatalf("validate filesystem root lock: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("close filesystem root lock: %v", err)
	}
}

func TestCreateRejectsInvalidLockOptionsBeforeTouchingDirectory(t *testing.T) {
	_, err := Create(context.Background(), Options{Dir: t.TempDir(), NoWait: true, Timeout: time.Second})
	if err == nil || KindOf(err) != KindUsage {
		t.Fatalf("invalid lock options error = %v, kind = %s", err, KindOf(err))
	}
}

func TestQueuedWaiterOnBusyRepoDoesNotBlockIdleSiblingRepo(t *testing.T) {
	parent := t.TempDir()
	el8 := filepath.Join(parent, "el8")
	el9 := filepath.Join(parent, "el9")
	for _, dir := range []string{el8, el9} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		writeDEBFixture(t, dir, "alpha.deb", debControl("alpha", "1.0-1", "amd64"), "alpha")
	}

	holder, err := acquireDirectoryLock(context.Background(), el8, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close() }()

	waiterDone := make(chan error, 1)
	go func() {
		_, waitErr := Create(context.Background(), Options{Dir: el8, Timeout: 5 * time.Second})
		waiterDone <- waitErr
	}()
	// Give the queued el8 waiter time to reach target lock contention.
	time.Sleep(80 * time.Millisecond)

	started := time.Now()
	if _, err := Create(context.Background(), Options{Dir: el9, Timeout: 500 * time.Millisecond}); err != nil {
		t.Fatalf("idle sibling el9 blocked while waiter queued on el8: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 450*time.Millisecond {
		t.Fatalf("idle sibling el9 took too long (%s) while el8 was queued", elapsed)
	}

	if err := holder.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-waiterDone; err != nil {
		t.Fatalf("queued el8 waiter failed after holder release: %v", err)
	}
}
