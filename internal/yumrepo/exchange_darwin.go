//go:build darwin

package yumrepo

import (
	"errors"

	"golang.org/x/sys/unix"
)

func isNativeExchangeUnsupported(err error) bool {
	return errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EINVAL)
}

func nativeExchange(first, second string) error {
	return unix.RenamexNp(first, second, unix.RENAME_SWAP)
}
