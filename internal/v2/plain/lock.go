package plain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

type directoryLock struct {
	path       string
	pathInfo   os.FileInfo
	targetFile *os.File
}

func acquireDirectoryLock(ctx context.Context, dir string, timeout time.Duration, noWait bool) (*directoryLock, error) {
	deadline := time.Time{}
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	parent := filepath.Dir(dir)
	var parentFile *os.File
	if parent != dir {
		openedParent, err := os.Open(parent)
		if err != nil && !errors.Is(err, os.ErrPermission) {
			return nil, &Error{Kind: KindRuntime, Op: "open parent lock", Path: parent, Err: err}
		}
		if err == nil {
			parentFile = openedParent
			if err := flockUntil(ctx, parentFile, deadline, timeout, noWait); err != nil {
				_ = parentFile.Close()
				return nil, &Error{Kind: KindLock, Op: "lock parent", Path: parent, Err: err}
			}
			parentInfo, statErr := parentFile.Stat()
			if statErr != nil || !parentInfo.IsDir() {
				_ = unlockAndClose(parentFile)
				return nil, &Error{Kind: KindIntegrity, Op: "bind parent lock", Path: parent, Err: errors.Join(statErr, errors.New("parent lock is not a directory"))}
			}
		}
	}
	releaseParent := func() error {
		if parentFile == nil {
			return nil
		}
		f := parentFile
		parentFile = nil
		return unlockAndClose(f)
	}

	pathInfo, err := os.Lstat(dir)
	if err != nil || !pathInfo.IsDir() || pathInfo.Mode()&os.ModeSymlink != 0 {
		_ = releaseParent()
		return nil, &Error{Kind: KindRuntime, Op: "bind lock target", Path: dir, Err: errors.Join(err, errors.New("target is not a real directory"))}
	}
	targetFile, err := os.Open(dir)
	if err != nil {
		_ = releaseParent()
		return nil, &Error{Kind: KindRuntime, Op: "open target lock", Path: dir, Err: err}
	}
	opened, openErr := targetFile.Stat()
	current, pathErr := os.Lstat(dir)
	if openErr != nil || pathErr != nil || !opened.IsDir() || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() || !os.SameFile(pathInfo, opened) || !os.SameFile(pathInfo, current) {
		_ = targetFile.Close()
		_ = releaseParent()
		return nil, &Error{Kind: KindIntegrity, Op: "bind lock target", Path: dir, Err: errors.Join(openErr, pathErr, errors.New("target changed while locking"))}
	}
	if err := unix.Flock(int(targetFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = targetFile.Close()
			_ = releaseParent()
			return nil, &Error{Kind: KindLock, Op: "lock", Path: dir, Err: err}
		}
		// Release the parent lock before waiting on a busy target so queued
		// operations on one flat repository never block sibling directories.
		if releaseErr := releaseParent(); releaseErr != nil {
			_ = targetFile.Close()
			return nil, &Error{Kind: KindRuntime, Op: "release parent lock", Path: parent, Err: releaseErr}
		}
		if err := flockUntil(ctx, targetFile, deadline, timeout, noWait); err != nil {
			_ = targetFile.Close()
			return nil, &Error{Kind: KindLock, Op: "lock", Path: dir, Err: err}
		}
	}
	openedAfter, openAfterErr := targetFile.Stat()
	currentAfter, pathAfterErr := os.Lstat(dir)
	if openAfterErr != nil || pathAfterErr != nil || !openedAfter.IsDir() || currentAfter.Mode()&os.ModeSymlink != 0 || !currentAfter.IsDir() || !os.SameFile(pathInfo, openedAfter) || !os.SameFile(pathInfo, currentAfter) {
		_ = unlockAndClose(targetFile)
		_ = releaseParent()
		return nil, &Error{Kind: KindIntegrity, Op: "bind lock target", Path: dir, Err: errors.Join(openAfterErr, pathAfterErr, errors.New("target changed while locking"))}
	}
	// Release the parent lock immediately once targetFile is bound and locked so
	// sibling flat repositories (e.g. el8/el9/el10) run concurrently.
	if err := releaseParent(); err != nil {
		_ = unlockAndClose(targetFile)
		return nil, &Error{Kind: KindRuntime, Op: "release parent lock", Path: parent, Err: err}
	}
	return &directoryLock{path: dir, pathInfo: pathInfo, targetFile: targetFile}, nil
}

func flockUntil(ctx context.Context, file *os.File, deadline time.Time, timeout time.Duration, noWait bool) error {
	for {
		err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return err
		}
		if noWait {
			return errors.New("lock is already held")
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return fmt.Errorf("timed out after %s", timeout)
		}
		wait := 25 * time.Millisecond
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining < wait {
				wait = remaining
			}
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (lock *directoryLock) Validate() error {
	if lock == nil || lock.targetFile == nil || lock.pathInfo == nil {
		return &Error{Kind: KindIntegrity, Op: "validate lock target", Err: errors.New("lock is not held")}
	}
	opened, openErr := lock.targetFile.Stat()
	current, pathErr := os.Lstat(lock.path)
	if openErr != nil || pathErr != nil || !opened.IsDir() || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() || !os.SameFile(lock.pathInfo, opened) || !os.SameFile(lock.pathInfo, current) {
		return &Error{Kind: KindIntegrity, Op: "validate lock target", Path: lock.path, Err: errors.Join(openErr, pathErr, errors.New("target directory changed while locked"))}
	}
	return nil
}

func (lock *directoryLock) Close() error {
	if lock == nil {
		return nil
	}
	err := unlockAndClose(lock.targetFile)
	lock.targetFile = nil
	return err
}

func unlockAndClose(file *os.File) error {
	if file == nil {
		return nil
	}
	return errors.Join(unix.Flock(int(file.Fd()), unix.LOCK_UN), file.Close())
}
