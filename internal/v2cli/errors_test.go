package v2cli

import (
	"errors"
	"fmt"
	"testing"
)

func TestExitCodeTaxonomy(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "success", want: ExitOK},
		{name: "runtime", err: errors.New("disk read failed"), want: ExitRuntime},
		{name: "parser usage", err: usageError("unknown option"), want: ExitUsage},
		{name: "usage", err: fmt.Errorf("outer: %w", ErrUsage), want: ExitUsage},
		{name: "discovery", err: fmt.Errorf("outer: %w", ErrDiscovery), want: ExitUsage},
		{name: "config", err: fmt.Errorf("outer: %w", ErrConfig), want: ExitUsage},
		{name: "explicit partial", err: WithExitCode(ExitPartial, errors.New("one item failed")), want: ExitPartial},
		{name: "lock", err: fmt.Errorf("outer: %w", ErrLock), want: ExitLock},
		{name: "integrity", err: fmt.Errorf("outer: %w", ErrIntegrity), want: ExitIntegrity},
		{name: "rejected", err: fmt.Errorf("outer: %w", ErrRejected), want: ExitRejected},
		{name: "explicit", err: WithExitCode(ExitIntegrity, ErrRejected), want: ExitIntegrity},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ExitCode(test.err); got != test.want {
				t.Fatalf("ExitCode(%v)=%d want=%d", test.err, got, test.want)
			}
		})
	}
}

func TestWithExitCodeRejectsUndocumentedCodes(t *testing.T) {
	base := errors.New("base")
	for _, code := range []int{ExitOK, 7, -1} {
		err := WithExitCode(code, base)
		if got := ExitCode(err); got != ExitRuntime {
			t.Errorf("WithExitCode(%d) mapped to %d, want %d", code, got, ExitRuntime)
		}
		if !errors.Is(err, base) {
			t.Errorf("WithExitCode(%d) lost wrapped error", code)
		}
	}
	if err := WithExitCode(ExitLock, nil); err != nil {
		t.Fatalf("nil error became %v", err)
	}
}

func TestErrorfClassifiesWithoutLosingMessage(t *testing.T) {
	err := Errorf(ErrRejected, "repository %q is protected", "prod")
	if !errors.Is(err, ErrRejected) || ExitCode(err) != ExitRejected {
		t.Fatalf("classification failed: %v", err)
	}
	if got, want := err.Error(), `operation rejected: repository "prod" is protected`; got != want {
		t.Fatalf("message=%q want=%q", got, want)
	}
}

func TestDocumentedExitCodeSet(t *testing.T) {
	for _, code := range []int{ExitOK, ExitRuntime, ExitUsage, ExitPartial, ExitLock, ExitIntegrity, ExitRejected} {
		if !validExitCode(code) {
			t.Errorf("documented exit code %d rejected", code)
		}
	}
	for _, code := range []int{7} {
		if validExitCode(code) {
			t.Errorf("out-of-scope exit code %d accepted", code)
		}
	}
}
