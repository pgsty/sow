//go:build darwin

package yumrepo

import (
	"errors"

	"golang.org/x/sys/unix"
)

func isNativeExchangeUnsupported(err error) bool {
	return errors.Is(err, unix.ENOTSUP)
}

func nativeExchange(first, second string) error {
	return unix.RenamexNp(first, second, unix.RENAME_SWAP)
}
