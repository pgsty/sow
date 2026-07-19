package cli

import (
	"fmt"
	"io"
)

type stateLockReleaser interface {
	Release() error
}

// propagateStateLockRelease makes the durable lock teardown part of command
// success. A caller that already has a primary error keeps that error (and its
// exit class), while still receiving a diagnostic about the teardown failure.
func propagateStateLockRelease(lock stateLockReleaser, resultErr *error, stderr io.Writer) {
	if lock == nil || resultErr == nil {
		return
	}
	releaseErr := lock.Release()
	if releaseErr == nil {
		return
	}
	if *resultErr != nil {
		if stderr != nil {
			fmt.Fprintf(stderr, "warning: release state lock: %v\n", releaseErr)
		}
		return
	}
	*resultErr = withExitCode(ExitInternal, "release state lock: %v", releaseErr)
}
