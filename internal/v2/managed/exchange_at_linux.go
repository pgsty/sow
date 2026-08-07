//go:build linux

package managed

import "golang.org/x/sys/unix"

func exchangeDirectoriesAt(leftFD int, left string, rightFD int, right string) error {
	return unix.Renameat2(leftFD, left, rightFD, right, unix.RENAME_EXCHANGE)
}
