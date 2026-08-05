package managed

import (
	"context"
	"io"
)

// structuralDetachedVerifier is used only by cheap lifecycle layout checks.
// Full `check` replaces it with the configured cryptographic verifier.
type structuralDetachedVerifier struct{}

func (structuralDetachedVerifier) Verify(context.Context, io.Reader, io.Reader) error { return nil }
