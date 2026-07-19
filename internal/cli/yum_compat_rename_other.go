//go:build !darwin && !linux

package cli

import "errors"

func renameYUMCompatibilityCandidateNoReplace(uintptr, string, string) error {
	return errors.New("YUM compatibility candidate transactions require Linux or macOS no-replace rename support")
}
