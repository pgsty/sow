//go:build !linux && !darwin

package cli

import "os"

func yumCompatibilityDirectoryIdentity(os.FileInfo) (device, inode uint64, supported bool) {
	return 0, 0, false
}
