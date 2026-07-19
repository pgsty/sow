//go:build !darwin && !linux

package cli

import "errors"

func exchangeYUMCompatibilityDirectories(uintptr, string, string) error {
	return errors.New("YUM compatibility canonical-state transactions require Linux or macOS atomic directory exchange support")
}
