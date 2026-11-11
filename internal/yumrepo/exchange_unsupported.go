//go:build !linux && !darwin

package yumrepo

import "errors"

var errNativeExchangeUnsupported = errors.New("native atomic directory exchange unavailable on this platform")

func isNativeExchangeUnsupported(err error) bool {
	return errors.Is(err, errNativeExchangeUnsupported)
}

func nativeExchange(first, second string) error {
	return errNativeExchangeUnsupported
}
