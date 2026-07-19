//go:build linux

package cli

import "golang.org/x/sys/unix"

func renameYUMCompatibilityCandidateNoReplace(dirfd uintptr, oldName, newName string) error {
	return unix.Renameat2(int(dirfd), oldName, int(dirfd), newName, unix.RENAME_NOREPLACE)
}
