//go:build linux

package cli

import "golang.org/x/sys/unix"

func exchangeNginxIncludeFiles(dirfd uintptr, left, right string) error {
	return unix.Renameat2(int(dirfd), left, int(dirfd), right, unix.RENAME_EXCHANGE)
}

func renameNginxIncludeNoReplace(dirfd uintptr, oldName, newName string) error {
	return unix.Renameat2(int(dirfd), oldName, int(dirfd), newName, unix.RENAME_NOREPLACE)
}
