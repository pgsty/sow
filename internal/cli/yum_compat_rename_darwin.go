//go:build darwin

package cli

import "golang.org/x/sys/unix"

func renameYUMCompatibilityCandidateNoReplace(dirfd uintptr, oldName, newName string) error {
	return unix.RenameatxNp(int(dirfd), oldName, int(dirfd), newName, unix.RENAME_EXCL)
}
