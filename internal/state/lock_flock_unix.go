//go:build linux || darwin

package state

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func tryStateLockLease(file *os.File) (bool, error) {
	if file == nil {
		return false, errors.New("state lock lease file is unavailable")
	}
	for {
		err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.EWOULDBLOCK), errors.Is(err, unix.EAGAIN):
			return false, nil
		default:
			return false, fmt.Errorf("acquire state lock advisory lease: %w", err)
		}
	}
}

func releaseStateLockLease(file *os.File) error {
	if file == nil {
		return errors.New("state lock lease file is unavailable")
	}
	for {
		err := unix.Flock(int(file.Fd()), unix.LOCK_UN)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("release state lock advisory lease: %w", err)
		}
		return nil
	}
}
