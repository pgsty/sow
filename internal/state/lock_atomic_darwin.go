//go:build darwin

package state

import "golang.org/x/sys/unix"

func renameStateLockNoReplace(directoryFD uintptr, oldName, newName string) error {
	return unix.RenameatxNp(
		int(directoryFD),
		oldName,
		int(directoryFD),
		newName,
		unix.RENAME_EXCL,
	)
}
