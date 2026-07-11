package cli

import (
	"errors"
	"fmt"
)

const (
	ExitOK             = 0
	ExitInternal       = 1
	ExitUsage          = 2
	ExitConfig         = 3
	ExitVerification   = 4
	ExitNetworkAuth    = 5
	ExitConflict       = 6
	ExitPartialPublish = 7
)

type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func withExitCode(code int, format string, args ...any) error {
	return &exitError{code: code, err: fmt.Errorf(format, args...)}
}

func exitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	var target *exitError
	if errors.As(err, &target) {
		return target.code
	}
	return ExitInternal
}
