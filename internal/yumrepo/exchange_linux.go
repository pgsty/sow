//go:build linux

package yumrepo

import "golang.org/x/sys/unix"

var errNativeExchangeUnsupported = unix.ENOSYS

func nativeExchange(first, second string) error {
	return unix.Renameat2(unix.AT_FDCWD, first, unix.AT_FDCWD, second, unix.RENAME_EXCHANGE)
}
