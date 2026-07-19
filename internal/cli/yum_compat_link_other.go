//go:build !linux && !darwin

package cli

import "errors"

func linkYUMCompatibilityAcrossRoots(uintptr, string, uintptr, string) error {
	return errors.New("cross-root YUM compatibility hardlinks require Linux or macOS linkat support")
}
