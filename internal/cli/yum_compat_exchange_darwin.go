//go:build darwin

package cli

import "golang.org/x/sys/unix"

func exchangeYUMCompatibilityDirectories(dirfd uintptr, left, right string) error {
	return unix.RenameatxNp(int(dirfd), left, int(dirfd), right, unix.RENAME_SWAP)
}
