//go:build linux

package state

import "golang.org/x/sys/unix"

func renameStateLockNoReplace(directoryFD uintptr, oldName, newName string) error {
	return unix.Renameat2(
		int(directoryFD),
		oldName,
		int(directoryFD),
		newName,
		unix.RENAME_NOREPLACE,
	)
}
