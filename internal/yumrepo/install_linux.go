//go:build linux

package yumrepo

import "golang.org/x/sys/unix"

func installImmutable(staged, dest string) error {
	return unix.Renameat2(unix.AT_FDCWD, staged, unix.AT_FDCWD, dest, unix.RENAME_NOREPLACE)
}
