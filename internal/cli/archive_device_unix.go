//go:build linux || darwin

package cli

import (
	"errors"
	"os"
	"syscall"
)

func sameArchiveFilesystem(left, right os.FileInfo) (bool, error) {
	if left == nil || right == nil {
		return false, errors.New("archive filesystem identity is unavailable")
	}
	leftStat, leftOK := left.Sys().(*syscall.Stat_t)
	rightStat, rightOK := right.Sys().(*syscall.Stat_t)
	if !leftOK || !rightOK {
		return false, errors.New("archive filesystem device identity is unavailable")
	}
	return uint64(leftStat.Dev) == uint64(rightStat.Dev), nil
}
