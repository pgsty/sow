//go:build darwin

package yumrepo

import "golang.org/x/sys/unix"

var errNativeExchangeUnsupported = unix.ENOTSUP

func nativeExchange(first, second string) error {
	return unix.RenamexNp(first, second, unix.RENAME_SWAP)
}
