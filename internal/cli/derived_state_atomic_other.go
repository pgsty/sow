//go:build !darwin && !linux

package cli

import "errors"

func exchangeDerivedStateFiles(uintptr, string, string) error {
	return errors.New("derived state replacement requires Linux or macOS atomic exchange support")
}
