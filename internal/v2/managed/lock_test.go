package managed

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileLockNoWaitTimeoutAndWait(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "workspace.lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := acquireFileLock(context.Background(), path, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := acquireFileLock(context.Background(), path, 0, true); !errors.Is(err, ErrLockUnavailable) {
		t.Fatalf("no-wait error=%v", err)
	}
	started := time.Now()
	if _, err := acquireFileLock(context.Background(), path, 45*time.Millisecond, false); !errors.Is(err, ErrLockUnavailable) {
		t.Fatalf("timeout error=%v", err)
	}
	if elapsed := time.Since(started); elapsed < 30*time.Millisecond {
		t.Fatalf("timeout returned too early: %s", elapsed)
	}

	acquired := make(chan error, 1)
	go func() {
		second, err := acquireFileLock(context.Background(), path, time.Second, false)
		if err == nil {
			err = second.Close()
		}
		acquired <- err
	}()
	time.Sleep(40 * time.Millisecond)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-acquired; err != nil {
		t.Fatalf("waiting lock: %v", err)
	}
}

func TestFileLockRejectsSymlinkAndInvalidOptions(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "workspace.lock")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireFileLock(context.Background(), link, 0, false); err == nil {
		t.Fatal("symlink lock succeeded")
	}
	if _, err := acquireSharedFileLock(context.Background(), link); err == nil {
		t.Fatal("shared symlink lock succeeded")
	}
	for _, options := range []struct {
		timeout time.Duration
		noWait  bool
	}{{-time.Second, false}, {time.Second, true}} {
		if _, err := acquireFileLock(context.Background(), filepath.Join(dir, "other.lock"), options.timeout, options.noWait); err == nil {
			t.Fatalf("options %+v succeeded", options)
		}
	}
}

func TestSharedFileLockRequiresExistingFileAndCoordinatesWithWriter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "repo.lock")
	if _, err := acquireSharedFileLock(context.Background(), path); err == nil {
		t.Fatal("shared lock created a missing lock file")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("shared lock changed missing path: %v", err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := acquireSharedFileLock(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := acquireSharedFileLock(context.Background(), path)
	if err != nil {
		first.Close()
		t.Fatal(err)
	}
	if _, err := acquireFileLock(context.Background(), path, 0, true); !errors.Is(err, ErrLockUnavailable) {
		t.Fatalf("exclusive lock bypassed shared readers: %v", err)
	}
	if err := errors.Join(second.Close(), first.Close()); err != nil {
		t.Fatal(err)
	}

	writer, err := acquireFileLock(context.Background(), path, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Millisecond)
	defer cancel()
	if _, err := acquireSharedFileLock(ctx, path); !errors.Is(err, ErrLockUnavailable) || !errors.Is(err, context.DeadlineExceeded) {
		writer.Close()
		t.Fatalf("shared reader did not honor context cancellation: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExclusiveFileLockNeverRecreatesUnlinkedLockInode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "repo.lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	held, err := acquireFileLock(context.Background(), path, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireFileLock(context.Background(), path, 0, false); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("missing lock was not classified as integrity failure: %v", err)
	}
	if _, err := acquireSharedFileLock(context.Background(), path); err == nil {
		t.Fatal("shared lock recreated an unlinked lock inode")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock path was recreated beside held unlinked inode: %v", err)
	}
}
