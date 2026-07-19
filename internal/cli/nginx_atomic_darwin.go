//go:build darwin

package cli

import "golang.org/x/sys/unix"

func exchangeNginxIncludeFiles(dirfd uintptr, left, right string) error {
	return unix.RenameatxNp(int(dirfd), left, int(dirfd), right, unix.RENAME_SWAP)
}

func renameNginxIncludeNoReplace(dirfd uintptr, oldName, newName string) error {
	return unix.RenameatxNp(int(dirfd), oldName, int(dirfd), newName, unix.RENAME_EXCL)
}
