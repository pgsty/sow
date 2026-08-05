package managed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

var ErrLockUnavailable = errors.New("managed: lock unavailable")

type fileLock struct {
	file      *os.File
	exclusive bool
	rootGuard *workspaceRootGuard
}

func acquireFileLock(ctx context.Context, filename string, timeout time.Duration, noWait bool) (*fileLock, error) {
	if ctx == nil {
		return nil, errors.New("managed: nil lock context")
	}
	if timeout < 0 || (noWait && timeout != 0) {
		return nil, errors.New("managed: invalid lock wait options")
	}
	file, err := openExistingLockFile(filename, os.O_RDWR)
	if err != nil {
		return nil, fmt.Errorf("%w: acquire lifecycle lock: %v", ErrIntegrity, err)
	}
	return waitFileLock(ctx, file, unix.LOCK_EX, timeout, noWait)
}

// acquireSharedFileLock opens an already initialized lifecycle lock without
// O_CREATE and holds a shared flock until Close. Read-only commands have no
// public wait flags; they wait until the caller's context is cancelled.
func acquireSharedFileLock(ctx context.Context, filename string) (*fileLock, error) {
	return acquireSharedFileLockWithOptions(ctx, filename, 0, false)
}

func acquireSharedFileLockWithOptions(ctx context.Context, filename string, timeout time.Duration, noWait bool) (*fileLock, error) {
	if ctx == nil {
		return nil, errors.New("managed: nil lock context")
	}
	if timeout < 0 || (noWait && timeout != 0) {
		return nil, errors.New("managed: invalid lock wait options")
	}
	file, err := openExistingLockFile(filename, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	return waitFileLock(ctx, file, unix.LOCK_SH, timeout, noWait)
}

func classifyReadLockError(scope string, err error) error {
	if errors.Is(err, ErrLockUnavailable) {
		return fmt.Errorf("%s: %w", scope, err)
	}
	return fmt.Errorf("%w: %s: %v", ErrIntegrity, scope, err)
}

func openExistingLockFile(filename string, flags int) (*os.File, error) {
	if err := verifyActiveWorkspaceRoot(filename); err != nil {
		return nil, err
	}
	parent := filepath.Dir(filename)
	base := filepath.Base(filename)
	if base == "." || base == string(filepath.Separator) {
		return nil, errors.New("managed: invalid lock filename")
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("managed: lock parent is not a real directory: %w", err)
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, fmt.Errorf("managed: bind lock parent: %w", err)
	}
	defer root.Close()
	if existing, statErr := root.Lstat(base); statErr == nil {
		if !existing.Mode().IsRegular() || existing.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("managed: lock path is not a regular file")
		}
	} else if errors.Is(statErr, os.ErrNotExist) {
		return nil, fmt.Errorf("managed: lock file is missing: %w", statErr)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, fmt.Errorf("managed: inspect lock: %w", statErr)
	}
	file, err := root.OpenFile(base, flags, 0o600)
	if err != nil {
		return nil, fmt.Errorf("managed: open lock: %w", err)
	}
	opened, openErr := file.Stat()
	current, pathErr := root.Lstat(base)
	var openedRaw unix.Stat_t
	rawErr := unix.Fstat(int(file.Fd()), &openedRaw)
	if openErr != nil || pathErr != nil || rawErr != nil || !opened.Mode().IsRegular() || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || !os.SameFile(opened, current) || openedRaw.Nlink != 1 {
		_ = file.Close()
		return nil, fmt.Errorf("managed: lock path changed, is multiply linked, or is unsafe while opening: %w", errors.Join(openErr, pathErr, rawErr))
	}
	if err := verifyActiveWorkspaceRoot(filename); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func waitFileLock(ctx context.Context, file *os.File, operation int, timeout time.Duration, noWait bool) (*fileLock, error) {
	deadline := time.Time{}
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	for {
		err := unix.Flock(int(file.Fd()), operation|unix.LOCK_NB)
		if err == nil {
			lock := &fileLock{file: file, exclusive: operation&unix.LOCK_EX != 0}
			if lock.exclusive {
				if err := lock.writeHolder(); err != nil {
					_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
					_ = file.Close()
					return nil, err
				}
			}
			return lock, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = file.Close()
			return nil, fmt.Errorf("%w: %v", ErrLockUnavailable, err)
		}
		if noWait || (!deadline.IsZero() && !time.Now().Before(deadline)) {
			_ = file.Close()
			return nil, ErrLockUnavailable
		}
		wait := 20 * time.Millisecond
		if !deadline.IsZero() && time.Until(deadline) < wait {
			wait = time.Until(deadline)
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			_ = file.Close()
			return nil, fmt.Errorf("%w: %w", ErrLockUnavailable, ctx.Err())
		case <-timer.C:
		}
	}
}

func (lock *fileLock) Close() error {
	if lock == nil {
		return nil
	}
	var clearErr error
	if lock.exclusive && lock.file != nil {
		clearErr = lock.clearHolder()
	}
	var unlockErr error
	if lock.file != nil {
		unlockErr = errors.Join(unix.Flock(int(lock.file.Fd()), unix.LOCK_UN), lock.file.Close())
		lock.file = nil
	}
	guardErr := lock.rootGuard.Close()
	lock.rootGuard = nil
	err := errors.Join(clearErr, unlockErr, guardErr)
	return err
}

func (lock *fileLock) writeHolder() error {
	if err := lock.file.Truncate(0); err != nil {
		return fmt.Errorf("managed: truncate lock holder metadata: %w", err)
	}
	if _, err := lock.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	body := fmt.Sprintf("pid=%d acquired=%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339Nano))
	if _, err := io.WriteString(lock.file, body); err != nil {
		return fmt.Errorf("managed: write lock holder metadata: %w", err)
	}
	return lock.file.Sync()
}

func (lock *fileLock) clearHolder() error {
	if err := lock.file.Truncate(0); err != nil {
		return err
	}
	if _, err := lock.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return lock.file.Sync()
}

func probeFileLock(filename string) (bool, string, error) {
	file, err := openExistingLockFile(filename, os.O_RDONLY)
	if err != nil {
		return false, "", err
	}
	defer file.Close()
	err = unix.Flock(int(file.Fd()), unix.LOCK_SH|unix.LOCK_NB)
	if err == nil {
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		return false, "", nil
	}
	if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
		return false, "", err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return true, "", nil
	}
	body, _ := io.ReadAll(io.LimitReader(file, 4096))
	return true, strings.TrimSpace(string(body)), nil
}
