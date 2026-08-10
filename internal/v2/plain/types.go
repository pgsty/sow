// Package plain implements the SOW V2 P0 flat-directory repository operation.
// It deliberately has no dependency on workspace configuration or SQLite.
package plain

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"time"
)

type ErrorKind string

const (
	KindUsage     ErrorKind = "usage"
	KindRuntime   ErrorKind = "runtime"
	KindLock      ErrorKind = "lock"
	KindIntegrity ErrorKind = "integrity"
	KindRejected  ErrorKind = "rejected"
)

type Error struct {
	Kind ErrorKind
	Op   string
	Path string
	Err  error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	where := e.Op
	if e.Path != "" {
		where += " " + e.Path
	}
	if where == "" {
		return e.Err.Error()
	}
	return fmt.Sprintf("plain: %s: %v", where, e.Err)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func KindOf(err error) ErrorKind {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Kind
	}
	return KindRuntime
}

type FaultPoint string

const (
	FaultAfterContentScan     FaultPoint = "after-content-scan"
	FaultBeforeStatValidation FaultPoint = "before-stat-validation"
	FaultAfterMarkerWithdrawn FaultPoint = "after-marker-withdrawn"
	FaultBeforeRPMPackage     FaultPoint = "before-rpm-package-replace"
	FaultAfterRPMPackage      FaultPoint = "after-rpm-package-replace"
	FaultBeforeRPMPointer     FaultPoint = "before-rpm-pointer"
	FaultAfterRPMPointer      FaultPoint = "after-rpm-pointer"
	FaultBeforeDEBPackages    FaultPoint = "before-deb-packages"
	FaultAfterDEBPackages     FaultPoint = "after-deb-packages"
	FaultBeforeDEBGzip        FaultPoint = "before-deb-packages-gz"
	FaultAfterDEBGzip         FaultPoint = "after-deb-packages-gz"
	FaultBeforeRPMRemoval     FaultPoint = "before-rpm-index-removal"
	FaultAfterRPMRemoval      FaultPoint = "after-rpm-index-removal"
	FaultBeforeDEBRemoval     FaultPoint = "before-deb-index-removal"
	FaultAfterDEBRemoval      FaultPoint = "after-deb-index-removal"
	FaultAfterPackageRename   FaultPoint = "after-package-rename"
	FaultBeforeMarker         FaultPoint = "before-marker"
	FaultAfterMarker          FaultPoint = "after-marker"
)

var signingKeyPattern = regexp.MustCompile(`(?i)^(?:[0-9a-f]{16}|[0-9a-f]{40}|[0-9a-f]{64})$`)

// RPMSignFunc signs one caller-owned stage copy. Production uses rpm(8);
// tests inject a structural signer so unit coverage never needs a host key.
type RPMSignFunc func(context.Context, string, string, bool) error

type Fault struct {
	Point    FaultPoint
	Package  string
	Sequence int
}

type Options struct {
	Dir       string
	Jobs      int
	Pigsty    bool
	SignWith  string
	Overwrite bool
	Timeout   time.Duration
	NoWait    bool
	SignRPM   RPMSignFunc

	// Fault is an internal verification hook. Production callers leave it nil.
	Fault func(Fault) error
}

type Result struct {
	Dir          string   `json:"dir"`
	RPM          int      `json:"rpm"`
	DEB          int      `json:"deb"`
	Kept         []string `json:"kept"`
	Removed      []string `json:"removed"`
	Signed       []string `json:"signed,omitempty"`
	Signer       string   `json:"signer,omitempty"`
	Marker       bool     `json:"marker"`
	MarkerSHA256 string   `json:"marker_sha256,omitempty"`
	Noop         bool     `json:"noop"`
	Recovered    bool     `json:"recovered"`
}

func normalizeOptions(ctx context.Context, opts Options) (Options, error) {
	if ctx == nil {
		return Options{}, &Error{Kind: KindUsage, Op: "create", Err: errors.New("nil context")}
	}
	if opts.Dir == "" {
		opts.Dir = "."
	}
	if opts.Jobs == 0 {
		opts.Jobs = runtime.NumCPU()
	}
	if opts.Jobs < 1 {
		return Options{}, &Error{Kind: KindUsage, Op: "create", Err: errors.New("jobs must be at least 1")}
	}
	if opts.Timeout < 0 {
		return Options{}, &Error{Kind: KindUsage, Op: "create", Err: errors.New("timeout must not be negative")}
	}
	if opts.NoWait && opts.Timeout != 0 {
		return Options{}, &Error{Kind: KindUsage, Op: "create", Err: errors.New("no-wait and non-zero timeout are mutually exclusive")}
	}
	if opts.SignWith != "" {
		key := strings.TrimPrefix(strings.TrimPrefix(opts.SignWith, "0x"), "0X")
		if !signingKeyPattern.MatchString(key) {
			return Options{}, &Error{Kind: KindUsage, Op: "create", Err: errors.New("sign-with must be a 16, 40, or 64 hexadecimal GPG key ID/fingerprint")}
		}
		opts.SignWith = strings.ToUpper(key)
	}
	if opts.Overwrite && opts.SignWith == "" {
		return Options{}, &Error{Kind: KindUsage, Op: "create", Err: errors.New("overwrite requires --sign-with")}
	}
	return opts, nil
}
