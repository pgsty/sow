//go:build linux || darwin

package cli

import (
	"errors"

	"golang.org/x/sys/unix"
)

func linkArchiveAcrossRoots(sourceFD uintptr, source string, destinationFD uintptr, destination string) error {
	return unix.Linkat(int(sourceFD), source, int(destinationFD), destination, 0)
}

func archiveLinkCrossDevice(err error) bool {
	return errors.Is(err, unix.EXDEV)
}
