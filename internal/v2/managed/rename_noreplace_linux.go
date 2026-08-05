//go:build linux

package managed

import "golang.org/x/sys/unix"

func renameAtNoReplace(sourceFD int, source string, targetFD int, target string) error {
	return unix.Renameat2(sourceFD, source, targetFD, target, unix.RENAME_NOREPLACE)
}
