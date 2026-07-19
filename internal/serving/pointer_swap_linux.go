//go:build linux

package serving

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func atomicSwapFiles(root, left, right string) error {
	directory := filepath.Dir(left)
	if filepath.Dir(right) != directory {
		return os.ErrInvalid
	}
	handle, err := os.Open(filepath.Join(root, directory))
	if err != nil {
		return err
	}
	defer handle.Close()
	return unix.Renameat2(int(handle.Fd()), filepath.Base(left), int(handle.Fd()), filepath.Base(right), unix.RENAME_EXCHANGE)
}
