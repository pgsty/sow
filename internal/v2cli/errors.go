package v2cli

import (
	"errors"
	"fmt"
)

const (
	ExitOK        = 0
	ExitRuntime   = 1
	ExitUsage     = 2
	ExitPartial   = 3
	ExitLock      = 4
	ExitIntegrity = 5
	ExitRejected  = 6
)

// Error categories are public sentinels so domain packages can classify an
// error without importing the command dispatcher. Wrap one with %w and retain
// the original diagnostic as additional context.
var (
	ErrUsage     = errUsage
	ErrDiscovery = errors.New("workspace discovery error")
	ErrConfig    = errors.New("configuration error")
	ErrLock      = errors.New("lock unavailable")
	ErrIntegrity = errors.New("integrity or recovery error")
	ErrRejected  = errors.New("operation rejected")
)

// ExitError explicitly assigns one of the public CLI exit codes while
// retaining the underlying error for errors.Is/errors.As callers.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *ExitError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// WithExitCode returns nil for a nil error. Invalid and success codes on a
// non-nil error are deliberately reduced to the runtime class so callers can
// never make an error look successful or invent an undocumented exit code.
func WithExitCode(code int, err error) error {
	if err == nil {
		return nil
	}
	if code == ExitOK || !validExitCode(code) {
		code = ExitRuntime
	}
	return &ExitError{Code: code, Err: err}
}

// Errorf creates a classified error using one of ErrUsage, ErrDiscovery,
// ErrConfig, ErrLock, ErrIntegrity, or ErrRejected. An unknown category is a
// programming mistake and safely maps to ExitRuntime.
func Errorf(category error, format string, args ...any) error {
	detail := fmt.Errorf(format, args...)
	if category == nil {
		return detail
	}
	return fmt.Errorf("%w: %v", category, detail)
}

// ExitCode applies the V2 public error taxonomy. Explicit ExitError values take
// precedence; otherwise a wrapped category sentinel is used. Unknown errors
// are ordinary runtime failures.
func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	var classified *ExitError
	if errors.As(err, &classified) && classified != nil && validExitCode(classified.Code) && classified.Code != ExitOK {
		return classified.Code
	}
	switch {
	case errors.Is(err, ErrUsage), errors.Is(err, ErrDiscovery), errors.Is(err, ErrConfig):
		return ExitUsage
	case errors.Is(err, ErrLock):
		return ExitLock
	case errors.Is(err, ErrIntegrity):
		return ExitIntegrity
	case errors.Is(err, ErrRejected):
		return ExitRejected
	default:
		return ExitRuntime
	}
}

func validExitCode(code int) bool {
	switch code {
	case ExitOK, ExitRuntime, ExitUsage, ExitPartial, ExitLock, ExitIntegrity, ExitRejected:
		return true
	default:
		return false
	}
}

func errorClass(code int) string {
	switch code {
	case ExitUsage:
		return "usage"
	case ExitPartial:
		return "partial"
	case ExitLock:
		return "lock"
	case ExitIntegrity:
		return "integrity"
	case ExitRejected:
		return "rejected"
	default:
		return "runtime"
	}
}
