//go:build darwin

package managed

import (
	"errors"

	"golang.org/x/sys/unix"
)

func renameAtNoReplace(sourceFD int, source string, targetFD int, target string) error {
	err := unix.RenameatxNp(sourceFD, source, targetFD, target, unix.RENAME_EXCL|unix.RENAME_NOFOLLOW_ANY)
	if err == nil || !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.EOPNOTSUPP) && !errors.Is(err, unix.ENOTSUP) {
		return err
	}
	return linkUnlinkAtNoReplace(sourceFD, source, targetFD, target)
}
