//go:build darwin

package managed

import "golang.org/x/sys/unix"

func renameAtNoReplace(sourceFD int, source string, targetFD int, target string) error {
	return unix.RenameatxNp(sourceFD, source, targetFD, target, unix.RENAME_EXCL|unix.RENAME_NOFOLLOW_ANY)
}
