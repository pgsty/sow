//go:build darwin

package repository

import (
	"os"
	"unsafe"

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
	const maxPathLength = 1024
	buffer := make([]byte, maxPathLength)
	//lint:ignore SA1019 x/sys has no libSystem F_GETPATH wrapper; descriptor-bound lookup requires fcntl here.
	_, _, errno := unix.Syscall(unix.SYS_FCNTL, source.Fd(), uintptr(unix.F_GETPATH), uintptr(unsafe.Pointer(&buffer[0])))
	if errno != 0 {
		return errno
	}
	return unix.Linkat(unix.AT_FDCWD, unix.ByteSliceToString(buffer), int(parent.Fd()), name, 0)
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
	return unix.RenameatxNp(int(parent.Fd()), oldName, int(parent.Fd()), newName, unix.RENAME_EXCL)
}

func exchangeMaterializeAt(parent *os.File, first, second string) error {
	return unix.RenameatxNp(int(parent.Fd()), first, int(parent.Fd()), second, unix.RENAME_SWAP)
}
