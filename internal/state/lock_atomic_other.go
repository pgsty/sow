//go:build !linux && !darwin

package state

import "errors"

func renameStateLockNoReplace(uintptr, string, string) error {
	return errors.New("atomic no-replace state lock publication is unsupported on this platform")
}
