package state

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// O_PATH pins the inode without creating a file description whose close would
// release this process's POSIX locks held by SQLite connections.
func bindDatabaseFile(path string, mustExist bool) (*os.File, os.FileInfo, bool, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) && !mustExist {
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, fmt.Errorf("bind repository sqlite: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	var openedRaw, entryRaw unix.Stat_t
	rawErr := unix.Fstat(fd, &openedRaw)
	entryErr := unix.Lstat(path, &entryRaw)
	if err != nil || rawErr != nil || entryErr != nil || !info.Mode().IsRegular() || openedRaw.Nlink != 1 || entryRaw.Nlink != 1 || openedRaw.Dev != entryRaw.Dev || openedRaw.Ino != entryRaw.Ino {
		_ = file.Close()
		return nil, nil, false, fmt.Errorf("bind repository sqlite: %w", errors.Join(err, rawErr, entryErr, errors.New("database is not a private single-link regular file")))
	}
	current, err := os.Lstat(path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || !os.SameFile(info, current) {
		_ = file.Close()
		return nil, nil, false, fmt.Errorf("bind repository sqlite: %w", errors.Join(err, errors.New("database changed while binding")))
	}
	return file, info, true, nil
}
