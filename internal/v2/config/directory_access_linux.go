//go:build linux

package config

import "golang.org/x/sys/unix"

// O_PATH permits directory lookup and fstat without directory read access.
// O_DIRECTORY and O_NOFOLLOW remain set by the caller. See open(2):
// https://man7.org/linux/man-pages/man2/open.2.html
const directorySearchAccess = unix.O_PATH
