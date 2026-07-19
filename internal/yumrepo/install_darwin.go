//go:build darwin

package yumrepo

import "golang.org/x/sys/unix"

func installImmutable(staged, dest string) error {
	return unix.RenamexNp(staged, dest, unix.RENAME_EXCL)
}
