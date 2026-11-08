package signing

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Bind the parent chain as well as the leaf so neither symlinks nor directory
// replacement can redirect a read. O_NONBLOCK prevents a raced FIFO from hanging.
func readFile(path string) ([]byte, error) {
	badFile := errors.New("passfile is missing, unreadable, unsafe, empty, oversized, or changed during reading")
	path = physicalPath(path)
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
	fd, err := unix.Open("/", directoryAccess|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, badFile
	}
	fds := []int{fd}
	defer func() {
		for _, opened := range fds {
			_ = unix.Close(opened)
		}
	}()
	for _, part := range parts[:len(parts)-1] {
		fd, err = unix.Openat(fd, part, directoryAccess|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, badFile
		}
		fds = append(fds, fd)
	}
	name := parts[len(parts)-1]
	leaf, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, badFile
	}
	file := os.NewFile(uintptr(leaf), "passfile")
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > MaxBytes {
		return nil, badFile
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxBytes+1))
	after, statErr := file.Stat()
	var entry, opened unix.Stat_t
	pathErr := unix.Fstatat(fd, name, &entry, unix.AT_SYMLINK_NOFOLLOW)
	openErr := unix.Fstat(leaf, &opened)
	if err != nil || statErr != nil || pathErr != nil || openErr != nil ||
		len(data) != int(before.Size()) || !os.SameFile(before, after) || before.Size() != after.Size() ||
		!before.ModTime().Equal(after.ModTime()) || entry.Dev != opened.Dev || entry.Ino != opened.Ino ||
		entry.Size != opened.Size || uint32(entry.Mode)&unix.S_IFMT != unix.S_IFREG {
		Clear(data)
		return nil, badFile
	}
	for i := 1; i < len(fds); i++ {
		if unix.Fstat(fds[i], &opened) != nil || unix.Fstatat(fds[i-1], parts[i-1], &entry, unix.AT_SYMLINK_NOFOLLOW) != nil ||
			entry.Dev != opened.Dev || entry.Ino != opened.Ino || uint32(entry.Mode)&unix.S_IFMT != unix.S_IFDIR {
			Clear(data)
			return nil, badFile
		}
	}
	return data, nil
}
