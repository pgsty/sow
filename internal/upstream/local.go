package upstream

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/pgsty/sow/internal/syncer"
)

// LocalPackage is the package membership asserted by one existing repository
// index. Location is relative to the repository root and has already passed
// the same URL/path hardening used by remote sync discovery. The package body
// remains untrusted until the caller hashes it and runs the production DEB or
// RPM parser.
type LocalPackage struct {
	Format    string
	Name      string
	Version   string
	Arch      string
	Location  string
	Size      int64
	SHA256    string
	DebugInfo bool
}

// ParseLocalAPTIndex streams one raw, gzip, xz, or zstd Packages index. It is
// deliberately independent of Release metadata: legacy adoption proves the
// exact local membership and bytes but does not manufacture upstream signature
// provenance. A later materialize creates SOW-owned signed metadata.
func ParseLocalAPTIndex(ctx context.Context, filename string, limits Limits, accept func(LocalPackage) error) error {
	if ctx == nil || accept == nil {
		return fmt.Errorf("%w: local APT context and callback are required", ErrInvalidMetadata)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := limits.validate(); err != nil {
		return err
	}
	limits = limits.withDefaults()
	if !supportedLocalIndex(filename, "Packages") {
		return fmt.Errorf("%w: unsupported local APT index %q", ErrInvalidMetadata, filepath.Base(filename))
	}
	stream, err := openIndex(filename, filename, limits)
	if err != nil {
		return err
	}
	base, err := normalizeBase("https://local-adoption.invalid/")
	if err != nil {
		_ = stream.Close()
		return err
	}
	parseErr := parseDebPackagesLimited(&interruptibleReader{ctx: ctx, r: stream}, base, limits.StanzaBytes, limits.PackageCount, func(candidate syncer.Candidate, _ string) error {
		location, err := localLocation(candidate.URL)
		if err != nil {
			return err
		}
		return accept(LocalPackage{
			Format: "deb", Name: candidate.Name, Version: candidate.Version, Arch: candidate.Arch,
			Location: location, Size: candidate.Size, SHA256: candidate.SHA256, DebugInfo: candidate.DebugInfo,
		})
	})
	return errors.Join(parseErr, stream.Close())
}

// ParseLocalYUMRepository validates repomd -> primary checksums and streams
// primary package membership. When keyring is non-nil, repomd.xml.asc is also
// mandatory and verified. No signature claim is emitted when keyring is nil.
func ParseLocalYUMRepository(ctx context.Context, root string, limits Limits, keyring openpgp.KeyRing, accept func(LocalPackage) error) error {
	if ctx == nil || accept == nil {
		return fmt.Errorf("%w: local YUM context and callback are required", ErrInvalidMetadata)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := limits.validate(); err != nil {
		return err
	}
	limits = limits.withDefaults()
	rootInfo, err := os.Lstat(root)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return fmt.Errorf("%w: local YUM root is not a real directory", ErrInvalidMetadata)
	}
	repomdPath := filepath.Join(root, "repodata", "repomd.xml")
	repomd, err := readLocalRegular(repomdPath, limits.RepomdBytes)
	if err != nil {
		return err
	}
	if keyring != nil {
		signature, err := readLocalRegular(repomdPath+".asc", limits.SignatureBytes)
		if err != nil {
			return fmt.Errorf("%w: read repomd.xml.asc: %v", ErrSignature, err)
		}
		if err := verifyDetached(repomd, signature, keyring); err != nil {
			return fmt.Errorf("%w: repomd.xml.asc: %v", ErrSignature, err)
		}
	}
	primary, err := parseRepomd(repomd, limits.XMLDepth, limits.XMLTokenBytes)
	if err != nil {
		return err
	}
	primaryPath, err := localPathBelow(root, primary.Location)
	if err != nil {
		return err
	}
	compressedSHA, compressedSize, primaryIdentity, err := hashLocalRegular(ctx, primaryPath, limits.IndexCompressedBytes)
	if err != nil {
		return err
	}
	if compressedSize != primary.Size || compressedSHA != primary.SHA256 {
		return fmt.Errorf("%w: primary compressed checksum or size mismatch", ErrInvalidMetadata)
	}
	stream, err := openIndex(primaryPath, primary.Location, limits, primaryIdentity)
	if err != nil {
		return err
	}
	base, err := normalizeBase("https://local-adoption.invalid/")
	if err != nil {
		_ = stream.Close()
		return err
	}
	parseErr := parsePrimaryLimited(&interruptibleReader{ctx: ctx, r: newXMLTokenLimitReader(stream, limits.XMLTokenBytes)}, base, limits.XMLDepth, limits.PackageCount, func(candidate syncer.Candidate) error {
		location, err := localLocation(candidate.URL)
		if err != nil {
			return err
		}
		return accept(LocalPackage{
			Format: "rpm", Name: candidate.Name, Version: candidate.Version, Arch: candidate.Arch,
			Location: location, Size: candidate.Size, SHA256: candidate.SHA256, DebugInfo: candidate.DebugInfo,
		})
	})
	openSHA, openSize := stream.digest()
	closeErr := stream.Close()
	if parseErr != nil || closeErr != nil {
		return errors.Join(parseErr, closeErr)
	}
	if primary.OpenSHA256 != "" && primary.OpenSHA256 != openSHA {
		return fmt.Errorf("%w: primary open-checksum mismatch", ErrInvalidMetadata)
	}
	if primary.HasOpenSize && primary.OpenSize != openSize {
		return fmt.Errorf("%w: primary open-size mismatch", ErrInvalidMetadata)
	}
	return nil
}

func supportedLocalIndex(filename, base string) bool {
	name := filepath.Base(filename)
	for _, suffix := range []string{"", ".gz", ".xz", ".zst", ".zstd"} {
		if name == base+suffix {
			return true
		}
	}
	return false
}

func localLocation(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "local-adoption.invalid" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%w: local package URL is invalid", ErrInvalidMetadata)
	}
	location := strings.TrimPrefix(parsed.Path, "/")
	if err := validateRelativePath(location); err != nil {
		return "", err
	}
	return location, nil
}

func localPathBelow(root, relative string) (string, error) {
	if err := validateRelativePath(relative); err != nil {
		return "", err
	}
	full := filepath.Join(root, filepath.FromSlash(relative))
	rel, err := filepath.Rel(root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("%w: local metadata path escapes repository", ErrInvalidMetadata)
	}
	return full, nil
}

func readLocalRegular(filename string, limit int64) ([]byte, error) {
	before, err := os.Lstat(filename)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > limit {
		return nil, fmt.Errorf("%w: metadata file is absent, unsafe, or oversized", ErrInvalidMetadata)
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%w: metadata file changed while opening", ErrInvalidMetadata)
	}
	body, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(body)) > limit {
		return nil, errors.Join(readErr, closeErr, ErrMetadataTooLarge)
	}
	after, err := os.Lstat(filename)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) {
		return nil, fmt.Errorf("%w: metadata file changed while reading", ErrInvalidMetadata)
	}
	return body, nil
}

func hashLocalRegular(ctx context.Context, filename string, limit int64) (string, int64, os.FileInfo, error) {
	before, err := os.Lstat(filename)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > limit {
		return "", 0, nil, fmt.Errorf("%w: metadata file is absent, unsafe, or oversized", ErrInvalidMetadata)
	}
	file, err := os.Open(filename)
	if err != nil {
		return "", 0, nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() {
		_ = file.Close()
		return "", 0, nil, fmt.Errorf("%w: metadata file changed while opening", ErrInvalidMetadata)
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(hasher, &interruptibleReader{ctx: ctx, r: io.LimitReader(file, limit+1)})
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || written > limit {
		return "", 0, nil, errors.Join(copyErr, closeErr, ErrMetadataTooLarge)
	}
	after, err := os.Lstat(filename)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) || written != opened.Size() {
		return "", 0, nil, fmt.Errorf("%w: metadata file changed while hashing", ErrInvalidMetadata)
	}
	return hex.EncodeToString(hasher.Sum(nil)), written, opened, nil
}
