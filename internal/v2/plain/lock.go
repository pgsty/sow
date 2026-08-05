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
	parentFile *os.File
	targetFile *os.File
	targetLock bool
}

func acquireDirectoryLock(ctx context.Context, dir string, timeout time.Duration, noWait bool) (*directoryLock, error) {
	deadline := time.Time{}
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	parent := filepath.Dir(dir)
	parentFile, err := os.Open(parent)
	if err != nil {
		return nil, &Error{Kind: KindRuntime, Op: "open parent lock", Path: parent, Err: err}
	}
	if err := flockUntil(ctx, parentFile, deadline, timeout, noWait); err != nil {
		_ = parentFile.Close()
		return nil, &Error{Kind: KindLock, Op: "lock parent", Path: parent, Err: err}
	}
	parentInfo, err := parentFile.Stat()
	if err != nil || !parentInfo.IsDir() {
		_ = unlockAndClose(parentFile)
		return nil, &Error{Kind: KindIntegrity, Op: "bind parent lock", Path: parent, Err: errors.Join(err, errors.New("parent lock is not a directory"))}
	}
	pathInfo, err := os.Lstat(dir)
	if err != nil || !pathInfo.IsDir() || pathInfo.Mode()&os.ModeSymlink != 0 {
		_ = unlockAndClose(parentFile)
		return nil, &Error{Kind: KindRuntime, Op: "bind lock target", Path: dir, Err: errors.Join(err, errors.New("target is not a real directory"))}
	}
	targetFile, err := os.Open(dir)
	if err != nil {
		_ = unlockAndClose(parentFile)
		return nil, &Error{Kind: KindRuntime, Op: "open target lock", Path: dir, Err: err}
	}
	opened, openErr := targetFile.Stat()
	current, pathErr := os.Lstat(dir)
	if openErr != nil || pathErr != nil || !opened.IsDir() || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() || !os.SameFile(pathInfo, opened) || !os.SameFile(pathInfo, current) {
		_ = targetFile.Close()
		_ = unlockAndClose(parentFile)
		return nil, &Error{Kind: KindIntegrity, Op: "bind lock target", Path: dir, Err: errors.Join(openErr, pathErr, errors.New("target changed while locking"))}
	}
	targetLock := !os.SameFile(parentInfo, pathInfo)
	if targetLock {
		if err := flockUntil(ctx, targetFile, deadline, timeout, noWait); err != nil {
			_ = targetFile.Close()
			_ = unlockAndClose(parentFile)
			return nil, &Error{Kind: KindLock, Op: "lock", Path: dir, Err: err}
		}
	}
	return &directoryLock{path: dir, pathInfo: pathInfo, parentFile: parentFile, targetFile: targetFile, targetLock: targetLock}, nil
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
	targetErr := error(nil)
	if lock.targetLock {
		targetErr = unlockAndClose(lock.targetFile)
	} else if lock.targetFile != nil {
		targetErr = lock.targetFile.Close()
	}
	err := errors.Join(targetErr, unlockAndClose(lock.parentFile))
	lock.targetFile = nil
	lock.parentFile = nil
	lock.targetLock = false
	return err
}

func unlockAndClose(file *os.File) error {
	if file == nil {
		return nil
	}
	return errors.Join(unix.Flock(int(file.Fd()), unix.LOCK_UN), file.Close())
}
