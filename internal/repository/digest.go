package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrObjectConflict means a CAS coordinate is already occupied by bytes
	// other than the bytes being imported. CAS objects are never overwritten.
	ErrObjectConflict = errors.New("CAS object conflict")
	// ErrObjectCorrupt means an object does not match its SHA-256 coordinate or
	// recorded size.
	ErrObjectCorrupt = errors.New("CAS object is corrupt")
	// ErrUnsafePath means a path would escape a materialization root or traverse
	// a symlink/non-directory component.
	ErrUnsafePath = errors.New("unsafe repository path")
	// ErrHardlinkRequired means the pool and materialization target cannot share
	// bytes through hardlinks. Copying is deliberately not a fallback.
	ErrHardlinkRequired = errors.New("hardlink materialization is required")
	// ErrMaterializeConflict means a destination path contains different bytes.
	ErrMaterializeConflict = errors.New("materialization path conflict")
	// ErrGCProtection means destructive GC was requested without confirming the
	// exact orphan set returned by a current dry run.
	ErrGCProtection = errors.New("GC protection check failed")
	// ErrReferencedObjectMissing means a canonical root names an object absent
	// from the pool. Destructive GC refuses to run in this state.
	ErrReferencedObjectMissing = errors.New("referenced CAS object is missing")
)

// Digest is the canonical binary representation of a SHA-256 object name.
type Digest [sha256.Size]byte

func (d Digest) String() string { return hex.EncodeToString(d[:]) }

// ParseDigest accepts only the canonical lowercase 64-character encoding used
// in .pool/sha256/<aa>/<hash>.
func ParseDigest(value string) (Digest, error) {
	var digest Digest
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return digest, fmt.Errorf("invalid canonical SHA-256 %q", value)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return digest, fmt.Errorf("invalid SHA-256 %q: %w", value, err)
	}
	copy(digest[:], decoded)
	return digest, nil
}

// Object is an immutable CAS coordinate and its verified byte length.
type Object struct {
	SHA256 Digest
	Size   int64
}

func (o Object) HashString() string { return o.SHA256.String() }

func (o Object) validate() error {
	if o.Size < 0 {
		return fmt.Errorf("negative CAS object size %d", o.Size)
	}
	return nil
}
