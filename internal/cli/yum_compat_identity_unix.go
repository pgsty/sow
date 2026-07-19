//go:build linux || darwin

package cli

import (
	"os"
	"syscall"
)

func yumCompatibilityDirectoryIdentity(info os.FileInfo) (device, inode uint64, supported bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return 0, 0, false
	}
	return uint64(stat.Dev), uint64(stat.Ino), true
}
