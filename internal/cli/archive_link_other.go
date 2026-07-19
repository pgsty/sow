//go:build !linux && !darwin

package cli

import "errors"

var errArchiveCrossRootLinkUnsupported = errors.New("atomic cross-directory archive link is unsupported on this platform")

func linkArchiveAcrossRoots(uintptr, string, uintptr, string) error {
	return errArchiveCrossRootLinkUnsupported
}

func archiveLinkCrossDevice(error) bool {
	return false
}
