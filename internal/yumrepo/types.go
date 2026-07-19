// Package yumrepo builds standard RPM repository metadata without invoking
// createrepo_c, rpm, gpg, or any other external process.
package yumrepo

import (
	"context"
	"errors"
	"io"
	"time"
)

var (
	ErrInvalidPackage      = errors.New("invalid RPM package")
	ErrUnsafeLocation      = errors.New("unsafe YUM package location")
	ErrUnsortedInput       = errors.New("RPM inputs are not in canonical location order")
	ErrGenerationExists    = errors.New("immutable repodata generation already exists")
	ErrGenerationConflict  = errors.New("immutable repodata generation conflicts with existing bytes")
	ErrAtomicUnsupported   = errors.New("atomic directory exchange is unsupported")
	ErrInvalidRepodata     = errors.New("invalid YUM repodata")
	ErrSignatureValidation = errors.New("repomd signature validation failed")
	ErrEmbeddedSignature   = errors.New("invalid or missing embedded RPM signature")
	ErrRPMPackageSignature = errors.New("RPM package signature verification failed")
)

// EmbeddedRPMSignature is bounded, non-cryptographic metadata for one
// signature packet retained in an RPM signature-header tag. Verification
// against a package keyring is deliberately outside this type's contract.
// SignatureCreatedAt is the packet-claimed time and becomes authenticated only
// after VerifyEmbeddedRPMSignatures succeeds. Structural inspection permits a
// missing value so verification can report it as a trust-policy failure.
type EmbeddedRPMSignature struct {
	HeaderTag          string
	HeaderTagID        int
	PacketSHA256       string
	PacketSize         int64
	PacketVersion      int
	PublicKeyAlgorithm int
	HashAlgorithm      int
	IssuerKeyID        string
	SignatureCreatedAt time.Time
}

// RPMSignatureCoverage records the exact package bytes authenticated by an
// embedded signature. Modern RSA/DSA signatures authenticate the main header;
// when present, its signed payload digest is checked separately. Historical
// header signatures without that digest report header-only coverage and are
// accepted only alongside a full header+payload signature. Legacy PGP/GPG
// signatures authenticate the main header and payload directly.
type RPMSignatureCoverage string

const (
	RPMSignatureCoverageHeader              RPMSignatureCoverage = "header"
	RPMSignatureCoverageHeaderPayloadDigest RPMSignatureCoverage = "header+payload-digest"
	RPMSignatureCoverageHeaderPayload       RPMSignatureCoverage = "header+payload"
)

// VerifiedEmbeddedRPMSignature is auditable proof that one RPM signature was
// verified with a key in the caller-supplied trust ring. SignerFingerprint is
// the fingerprint of the exact primary key or signing subkey that verified the
// packet; SignerPrimaryFingerprint identifies its containing OpenPGP entity.
type VerifiedEmbeddedRPMSignature struct {
	EmbeddedRPMSignature
	Coverage                 RPMSignatureCoverage
	SignedBytes              int64
	SignerKeyID              string
	SignerFingerprint        string
	SignerPrimaryFingerprint string
	PublicKeyAlgorithmName   string
	HashAlgorithmName        string
	PayloadDigestAlgorithm   string
	PayloadDigest            string
}

// Compression is the only metadata compression policy supported by sow/v1.
type Compression string

const (
	CompressionGzip Compression = "gzip"
	CompressionZstd Compression = "zstd"
)

// CompressionForEL freezes the PRD policy: EL8 is gzip; EL9 and EL10 are zstd.
func CompressionForEL(major int) (Compression, error) {
	switch major {
	case 8:
		return CompressionGzip, nil
	case 9, 10:
		return CompressionZstd, nil
	default:
		return "", errors.New("YUM metadata policy is defined only for EL8, EL9, and EL10")
	}
}

// PackageInput names an existing RPM. Basename defaults to the filesystem
// basename of Path. FileTime, when non-zero, overrides the file mtime recorded
// in primary metadata and is useful for reproducible materialization.
type PackageInput struct {
	Path     string
	Basename string
	FileTime time.Time
}

// PackageInfo is the stable identity and placement projection consumed by CLI
// inference and canonical-order preparation. InspectPackage obtains it from the
// same file descriptor and parser used by generation.
type PackageInfo struct {
	Name     string
	Version  string
	Release  string
	Epoch    int64
	Arch     string
	SHA256   string
	Size     int64
	Location string
}

// PackageIterator supplies RPMs without requiring the generator to retain a
// repository-wide package collection. Inputs must be ordered by the derived
// Packages/<bucket>/<basename> location; the generator validates that contract.
type PackageIterator interface {
	Next(context.Context) (PackageInput, error)
}

// IteratorFunc adapts a function to PackageIterator. It returns io.EOF at end.
type IteratorFunc func(context.Context) (PackageInput, error)

func (f IteratorFunc) Next(ctx context.Context) (PackageInput, error) {
	if f == nil {
		return PackageInput{}, errors.New("yumrepo: nil iterator function")
	}
	return f(ctx)
}

// SliceIterator is a small convenience adapter. The caller remains responsible
// for canonical order; use PackageLocation when preparing the slice.
type SliceIterator struct {
	Inputs []PackageInput
	next   int
}

func (s *SliceIterator) Next(ctx context.Context) (PackageInput, error) {
	if s == nil {
		return PackageInput{}, errors.New("yumrepo: nil slice iterator")
	}
	if ctx == nil {
		return PackageInput{}, errors.New("yumrepo: nil context")
	}
	if err := ctx.Err(); err != nil {
		return PackageInput{}, err
	}
	if s.next >= len(s.Inputs) {
		return PackageInput{}, io.EOF
	}
	in := s.Inputs[s.next]
	s.next++
	return in, nil
}

// DetachedSigner signs and verifies an ASCII-armored detached signature. The
// verification half prevents a broken or misconfigured signer from publishing
// a generation that merely contains a non-empty .asc file.
type DetachedSigner interface {
	Sign(context.Context, io.Reader, io.Writer) error
	Verify(context.Context, io.Reader, io.Reader) error
}

// DetachedVerifier is sufficient for validating and atomically activating an
// already-built directory.
type DetachedVerifier interface {
	Verify(context.Context, io.Reader, io.Reader) error
}

// Options contains every input that affects generated bytes. Revision is also
// used as the repomd data timestamp; it must be non-negative. No wall clock is
// consulted, so replaying the same ordered inputs is reproducible.
//
// Frozen and Compression form an explicit, narrow compatibility policy for
// legacy EL7 repositories. Compatibility marks the separately modelled frozen
// cross-EL URL projection; it is not an operating-system claim and therefore
// requires ELMajor=0, Frozen=true and explicit gzip. Compression may be omitted
// for EL8-EL10, whose policy is derived by CompressionForEL, but an explicit
// value must agree with it.
type Options struct {
	ELMajor       int
	Frozen        bool
	Compatibility bool
	Compression   Compression
	Revision      int64
	Signer        DetachedSigner
}

// CompressionForOptions resolves the metadata compression policy used by both
// generation and activation. CompressionForEL deliberately continues to reject
// EL7; only an explicitly frozen EL7 Options value with gzip is eligible for
// the legacy compatibility path.
func CompressionForOptions(opts Options) (Compression, error) {
	if opts.Compatibility {
		if opts.ELMajor != 0 || !opts.Frozen || opts.Compression != CompressionGzip {
			return "", errors.New("frozen cross-EL compatibility projections require ELMajor=0, Frozen=true, and explicit gzip metadata compression")
		}
		return CompressionGzip, nil
	}
	if opts.ELMajor == 7 {
		if !opts.Frozen {
			return "", errors.New("YUM metadata policy permits EL7 only for frozen legacy repositories")
		}
		if opts.Compression != CompressionGzip {
			return "", errors.New("frozen legacy EL7 repositories require explicit gzip metadata compression")
		}
		return CompressionGzip, nil
	}

	compression, err := CompressionForEL(opts.ELMajor)
	if err != nil {
		return "", err
	}
	if opts.Compression != "" && opts.Compression != compression {
		return "", errors.New("configured YUM metadata compression does not match the EL policy")
	}
	return compression, nil
}

// Artifact describes one compressed XML data object referenced by repomd.xml.
type Artifact struct {
	Type        string
	Path        string
	SHA256      string
	OpenSHA256  string
	Size        int64
	OpenSize    int64
	Timestamp   int64
	Packages    int64
	Compression Compression
}

// Generation is a complete immutable repodata directory.
type Generation struct {
	Dir          string
	Artifacts    [3]Artifact
	Packages     int64
	Revision     int64
	RepomdSHA256 string
	Reused       bool
}
