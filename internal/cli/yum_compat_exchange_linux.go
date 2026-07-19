//go:build linux

package cli

import "golang.org/x/sys/unix"

func exchangeYUMCompatibilityDirectories(dirfd uintptr, left, right string) error {
	return unix.Renameat2(int(dirfd), left, int(dirfd), right, unix.RENAME_EXCHANGE)
}
