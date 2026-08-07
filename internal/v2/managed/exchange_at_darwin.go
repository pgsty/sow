//go:build darwin

package managed

import "golang.org/x/sys/unix"

func exchangeDirectoriesAt(leftFD int, left string, rightFD int, right string) error {
	return unix.RenameatxNp(leftFD, left, rightFD, right, unix.RENAME_SWAP)
}
