package verify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pgsty/sow/internal/manifest"
)

// Stream opens a fresh, independently closable evidence stream.
type Stream func() (io.ReadCloser, error)

// FileStream adapts a path without opening it until the check executes.
func FileStream(filename string) Stream {
	return func() (io.ReadCloser, error) { return os.Open(filename) }
}

// ReaderStream adapts immutable in-memory evidence.
func ReaderStream(data string) Stream {
	return func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(data)), nil }
}

// ManifestComparisonCheck compares two canonical, sorted manifest streams.
// It is used for canonical-vs-ref, canonical-vs-cache, local-vs-remote (L2),
// and full object-list fsck comparisons.
type ManifestComparisonCheck struct {
	CheckID    string
	AtLayer    Layer
	Subject    string
	Desired    Stream
	Actual     Stream
	CodePrefix string
}

func (c ManifestComparisonCheck) ID() string   { return c.CheckID }
func (c ManifestComparisonCheck) Layer() Layer { return c.AtLayer }

func (c ManifestComparisonCheck) Verify(ctx context.Context, recorder *Recorder) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.Desired == nil || c.Actual == nil {
		return errors.New("manifest comparison requires desired and actual streams")
	}
	desired, err := c.Desired()
	if err != nil {
		return fmt.Errorf("open desired manifest evidence: %w", err)
	}
	actual, err := c.Actual()
	if err != nil {
		_ = desired.Close()
		return fmt.Errorf("open actual manifest evidence: %w", err)
	}
	prefix := normalizeCodePrefix(c.CodePrefix, "MANIFEST")
	_, diffErr := manifest.Diff(desired, actual, func(change manifest.Change) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		code, message := prefix+"_CHANGED", "manifest entry differs"
		switch change.Kind {
		case manifest.Added:
			code, message = prefix+"_UNEXPECTED", "actual manifest contains an unexpected path"
		case manifest.Removed:
			code, message = prefix+"_MISSING", "actual manifest is missing a desired path"
		}
		recorder.Add(Finding{Layer: c.AtLayer, Severity: SeverityError, Category: CategoryDrift, Code: code, Subject: change.Path(), Message: message, Fields: []Field{{Key: "scope", Value: c.Subject}}})
		return nil
	})
	if diffErr != nil {
		if errors.Is(diffErr, context.Canceled) || errors.Is(diffErr, context.DeadlineExceeded) {
			return diffErr
		}
		recorder.Add(Finding{Layer: c.AtLayer, Severity: SeverityCritical, Category: CategoryIntegrity, Code: prefix + "_INVALID", Subject: c.Subject, Message: "manifest evidence is malformed or unreadable"})
	}
	if closeErr := errors.Join(desired.Close(), actual.Close()); closeErr != nil {
		return errors.New("close manifest evidence")
	}
	return nil
}

// RefPointerCheck verifies the commit identity associated with a ref. Manifest
// bytes should additionally be compared with ManifestComparisonCheck.
type RefPointerCheck struct {
	CheckID        string
	AtLayer        Layer
	RefName        string
	ExpectedCommit string
	ActualCommit   string
}

func (c RefPointerCheck) ID() string   { return c.CheckID }
func (c RefPointerCheck) Layer() Layer { return c.AtLayer }

func (c RefPointerCheck) Verify(ctx context.Context, recorder *Recorder) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(c.RefName) == "" || !canonicalCommit(c.ExpectedCommit) || !canonicalCommit(c.ActualCommit) {
		recorder.Add(Finding{Layer: c.AtLayer, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "REF_POINTER_INVALID", Subject: c.RefName, Message: "ref name or commit identity is malformed"})
		return nil
	}
	if c.ExpectedCommit != c.ActualCommit {
		recorder.Add(Finding{Layer: c.AtLayer, Severity: SeverityError, Category: CategoryDrift, Code: "REF_POINTER_DRIFT", Subject: c.RefName, Message: "ref points to a different canonical commit", Fields: []Field{{Key: "actual", Value: c.ActualCommit}, {Key: "expected", Value: c.ExpectedCommit}}})
	}
	return nil
}

func canonicalCommit(value string) bool {
	if len(value) != 40 || value != strings.ToLower(value) {
		return false
	}
	for _, r := range value {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

func normalizeCodePrefix(value, fallback string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		return fallback
	}
	for _, r := range value {
		if !(r == '_' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return fallback
		}
	}
	return value
}
