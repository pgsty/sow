//go:build linux

package repository

import (
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

func openMaterializeDirectory(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func openMaterializeDirectoryAt(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func openMaterializeEntryAt(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func createMaterializeFileAt(parent *os.File, name string, mode os.FileMode) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(mode.Perm()))
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func mkdirMaterializeAt(parent *os.File, name string, mode os.FileMode) error {
	return unix.Mkdirat(int(parent.Fd()), name, uint32(mode.Perm()))
}

func linkMaterializeFileAt(source *os.File, parent *os.File, name string) error {
	if err := unix.Linkat(int(source.Fd()), "", int(parent.Fd()), name, unix.AT_EMPTY_PATH); err == nil {
		return nil
	}
	return unix.Linkat(unix.AT_FDCWD, "/proc/self/fd/"+strconv.FormatUint(uint64(source.Fd()), 10), int(parent.Fd()), name, unix.AT_SYMLINK_FOLLOW)
}

func unlinkMaterializeAt(parent *os.File, name string) error {
	return unix.Unlinkat(int(parent.Fd()), name, 0)
}

func lstatMaterializeAt(parent *os.File, name string) (materializeFileIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return materializeFileIdentity{}, err
	}
	return materializeFileIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

func fstatMaterialize(file *os.File) (materializeFileIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return materializeFileIdentity{}, err
	}
	return materializeFileIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

func renameMaterializeNoReplaceAt(parent *os.File, oldName, newName string) error {
	return unix.Renameat2(int(parent.Fd()), oldName, int(parent.Fd()), newName, unix.RENAME_NOREPLACE)
}

func exchangeMaterializeAt(parent *os.File, first, second string) error {
	return unix.Renameat2(int(parent.Fd()), first, int(parent.Fd()), second, unix.RENAME_EXCHANGE)
}
