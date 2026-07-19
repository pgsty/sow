//go:build !linux && !darwin

package cli

import (
	"errors"
	"os"
)

func sameArchiveFilesystem(os.FileInfo, os.FileInfo) (bool, error) {
	return false, errors.New("atomic offline archive filesystem preflight is unsupported on this platform")
}
