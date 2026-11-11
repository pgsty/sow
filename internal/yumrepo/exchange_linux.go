//go:build linux

package yumrepo

import (
	"errors"

	"golang.org/x/sys/unix"
)

func isNativeExchangeUnsupported(err error) bool {
	return errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP)
}

func nativeExchange(first, second string) error {
	return unix.Renameat2(unix.AT_FDCWD, first, unix.AT_FDCWD, second, unix.RENAME_EXCHANGE)
}
