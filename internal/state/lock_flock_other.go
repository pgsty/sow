//go:build !linux && !darwin

package state

import (
	"errors"
	"os"
)

func tryStateLockLease(file *os.File) (bool, error) {
	return false, errors.New("state lock advisory leases are unsupported on this platform")
}

func releaseStateLockLease(file *os.File) error {
	return errors.New("state lock advisory leases are unsupported on this platform")
}
