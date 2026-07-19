//go:build linux || darwin

package cli

import "golang.org/x/sys/unix"

func linkYUMCompatibilityAcrossRoots(sourceFD uintptr, source string, targetFD uintptr, target string) error {
	return unix.Linkat(int(sourceFD), source, int(targetFD), target, 0)
}
