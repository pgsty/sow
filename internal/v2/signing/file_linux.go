//go:build linux

package signing

import "golang.org/x/sys/unix"

const directoryAccess = unix.O_PATH

func physicalPath(path string) string { return path }
