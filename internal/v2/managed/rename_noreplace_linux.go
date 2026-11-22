//go:build linux

package managed

import (
	"errors"

	"golang.org/x/sys/unix"
)

func renameAtNoReplace(sourceFD int, source string, targetFD int, target string) error {
	err := unix.Renameat2(sourceFD, source, targetFD, target, unix.RENAME_NOREPLACE)
	if err == nil || !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.EOPNOTSUPP) && !errors.Is(err, unix.ENOTSUP) {
		return err
	}
	return linkUnlinkAtNoReplace(sourceFD, source, targetFD, target)
}
