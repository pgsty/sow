package yumrepo

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
)

const (
	maxRepomdBytes    = 4 << 20
	maxSignatureBytes = 4 << 20
)

type repomdDocument struct {
	XMLName  xml.Name       `xml:"repomd"`
	Revision string         `xml:"revision"`
	Data     []repomdRecord `xml:"data"`
}

type repomdRecord struct {
	Type         string      `xml:"type,attr"`
	Checksum     checksumXML `xml:"checksum"`
	OpenChecksum checksumXML `xml:"open-checksum"`
	Location     locationXML `xml:"location"`
	Timestamp    int64       `xml:"timestamp"`
	Size         int64       `xml:"size"`
	OpenSize     int64       `xml:"open-size"`
}

type checksumXML struct {
	Type  string `xml:"type,attr"`
	Value string `xml:",chardata"`
}

type locationXML struct {
	Href string `xml:"href,attr"`
}

// ManagedRPMPackageExpectation binds one package identity in an RPM view to
// its canonical Pool object. PoolPath is deliberately typed so callers cannot
// pass the rendered href as repository state.
type ManagedRPMPackageExpectation struct {
	SHA256   string
	Size     int64
	PoolPath ManagedPoolPath
}

type managedRPMViewValidation struct {
	repositoryBase *url.URL
	view           ManagedRPMViewPath
	expected       map[string]ManagedRPMPackageExpectation
	seen           map[string]struct{}
}

type rpmViewValidation interface {
	check(identity, href string, size int64) error
	finish() error
}

// legacyC2RPMViewValidation exists only for the explicit v0.2 layout
// migration gate.  C2 metadata names a view-local hardlink with the canonical
// pool/... path; forward renderers and ordinary validators never use it.
type legacyC2RPMViewValidation struct {
	expected map[string]ManagedRPMPackageExpectation
	seen     map[string]struct{}
}

func newLegacyC2RPMViewValidation(view ManagedRPMViewPath, expected []ManagedRPMPackageExpectation) (*legacyC2RPMViewValidation, error) {
	parsedView, err := ParseManagedRPMViewPath(view.String())
	if err != nil || parsedView != view {
		return nil, fmt.Errorf("%w: invalid legacy C2 RPM view path", ErrInvalidRepodata)
	}
	validation := &legacyC2RPMViewValidation{expected: make(map[string]ManagedRPMPackageExpectation, len(expected)), seen: make(map[string]struct{}, len(expected))}
	for _, item := range expected {
		parsedPool, poolErr := ParseManagedPoolPath(item.PoolPath.String())
		if !validSHA256(item.SHA256) || item.Size < 0 || poolErr != nil || parsedPool != item.PoolPath || !safeManagedRPMBasename(item.PoolPath.Filename()) {
			return nil, fmt.Errorf("%w: invalid legacy C2 RPM package expectation", ErrInvalidRepodata)
		}
		if _, duplicate := validation.expected[item.SHA256]; duplicate {
			return nil, fmt.Errorf("%w: duplicate legacy C2 RPM package expectation %s", ErrInvalidRepodata, item.SHA256)
		}
		validation.expected[item.SHA256] = item
	}
	return validation, nil
}

func (validation *legacyC2RPMViewValidation) check(identity, href string, size int64) error {
	expected, exists := validation.expected[identity]
	if !exists {
		return fmt.Errorf("%w: legacy C2 metadata references unexpected package %q", ErrInvalidRepodata, identity)
	}
	if _, duplicate := validation.seen[identity]; duplicate {
		return fmt.Errorf("%w: legacy C2 metadata repeats package %s", ErrInvalidRepodata, identity)
	}
	if size != expected.Size || href != expected.PoolPath.String() {
		return fmt.Errorf("%w: legacy C2 package %s size or view-local href differs", ErrInvalidRepodata, identity)
	}
	validation.seen[identity] = struct{}{}
	return nil
}

func (validation *legacyC2RPMViewValidation) finish() error {
	if validation == nil {
		return fmt.Errorf("%w: legacy C2 metadata closure is unavailable", ErrInvalidRepodata)
	}
	if len(validation.seen) != len(validation.expected) {
		return fmt.Errorf("%w: legacy C2 metadata closure has %d packages, want %d", ErrInvalidRepodata, len(validation.seen), len(validation.expected))
	}
	return nil
}

func newManagedRPMViewValidation(repositoryBase *url.URL, view ManagedRPMViewPath, expected []ManagedRPMPackageExpectation) (*managedRPMViewValidation, error) {
	if err := validateRepositoryBaseURI(repositoryBase); err != nil {
		return nil, fmt.Errorf("%w: invalid managed RPM view base: %v", ErrInvalidRepodata, err)
	}
	parsedView, err := ParseManagedRPMViewPath(view.String())
	if err != nil || parsedView != view {
		return nil, fmt.Errorf("%w: invalid managed RPM view path", ErrInvalidRepodata)
	}
	baseCopy := *repositoryBase
	validation := &managedRPMViewValidation{
		repositoryBase: &baseCopy, view: view,
		expected: make(map[string]ManagedRPMPackageExpectation, len(expected)), seen: make(map[string]struct{}, len(expected)),
	}
	for _, item := range expected {
		parsedPool, poolErr := ParseManagedPoolPath(item.PoolPath.String())
		if !validSHA256(item.SHA256) || item.Size < 0 || poolErr != nil || parsedPool != item.PoolPath || !safeManagedRPMBasename(item.PoolPath.Filename()) {
			return nil, fmt.Errorf("%w: invalid managed RPM package expectation", ErrInvalidRepodata)
		}
		if _, duplicate := validation.expected[item.SHA256]; duplicate {
			return nil, fmt.Errorf("%w: duplicate managed RPM package expectation %s", ErrInvalidRepodata, item.SHA256)
		}
		validation.expected[item.SHA256] = item
	}
	return validation, nil
}

func (validation *managedRPMViewValidation) check(identity, href string, size int64) error {
	if validation == nil {
		return nil
	}
	expected, exists := validation.expected[identity]
	if !exists {
		return fmt.Errorf("%w: managed RPM metadata references unexpected package %q", ErrInvalidRepodata, identity)
	}
	if _, duplicate := validation.seen[identity]; duplicate {
		return fmt.Errorf("%w: managed RPM metadata repeats package %s", ErrInvalidRepodata, identity)
	}
	if size != expected.Size {
		return fmt.Errorf("%w: managed RPM package %s size %d differs from canonical Pool size %d", ErrInvalidRepodata, identity, size, expected.Size)
	}
	if err := ValidateRPMHrefRoundTrip(validation.repositoryBase, validation.view, expected.PoolPath, href); err != nil {
		return fmt.Errorf("%w: managed RPM package %s href is invalid: %v", ErrInvalidRepodata, identity, err)
	}
	validation.seen[identity] = struct{}{}
	return nil
}

func (validation *managedRPMViewValidation) finish() error {
	if validation == nil {
		return fmt.Errorf("%w: managed RPM view validation is unavailable", ErrInvalidRepodata)
	}
	if len(validation.seen) != len(validation.expected) {
		return fmt.Errorf("%w: managed RPM metadata closure has %d packages, want %d", ErrInvalidRepodata, len(validation.seen), len(validation.expected))
	}
	return nil
}

// ValidateDirectory cryptographically and structurally validates a complete
// repodata generation. It rejects extra sqlite/modulemd/zchunk files, unsafe
// hrefs, checksum or size drift, malformed XML/counts, and a bad detached
// signature. All package XML is decompressed and decoded as a bounded stream.
func ValidateDirectory(ctx context.Context, dir string, compression Compression, verifier DetachedVerifier) (*Generation, error) {
	return validateDirectory(ctx, dir, compression, verifier, false)
}

// ValidateFlatUnsignedDirectory validates the unsigned flat rpm-md shape used
// by sow create. Package hrefs must be single RPM basenames and no detached
// repomd signature is accepted or required.
func ValidateFlatUnsignedDirectory(ctx context.Context, dir string, compression Compression) (*Generation, error) {
	return validateDirectoryMode(ctx, dir, compression, nil, true, false, false)
}

// ValidateManagedUnsignedDirectory validates unsigned managed rpm-md. Package
// hrefs must be canonical encode-once parent-relative references to a Pool
// path. Use ValidateManagedRPMViewUnsignedDirectory when the actual view URI
// and exact package closure are available.
func ValidateManagedUnsignedDirectory(ctx context.Context, dir string, compression Compression) (*Generation, error) {
	return validateDirectoryModeRetained(ctx, dir, compression, nil, false, true, false, false, true, nil)
}

// ValidateManagedDirectory validates signed managed rpm-md while permitting
// checksum-named artifacts retained from prior generations for in-flight
// client closure. repomd.xml and its detached signature always describe only
// the current three metadata artifacts.
func ValidateManagedDirectory(ctx context.Context, dir string, compression Compression, verifier DetachedVerifier) (*Generation, error) {
	return validateDirectoryModeRetained(ctx, dir, compression, verifier, false, true, true, false, true, nil)
}

// ValidateManagedRPMViewUnsignedDirectory performs full managed rpm-md
// validation and additionally proves every primary href, size, and digest
// against the expected canonical Pool closure at the actual Repository URI.
func ValidateManagedRPMViewUnsignedDirectory(ctx context.Context, dir string, compression Compression, repositoryBase *url.URL, view ManagedRPMViewPath, expected []ManagedRPMPackageExpectation) (*Generation, error) {
	validation, err := newManagedRPMViewValidation(repositoryBase, view, expected)
	if err != nil {
		return nil, err
	}
	generation, err := validateDirectoryModeRetained(ctx, dir, compression, nil, false, true, false, false, true, validation)
	if err != nil {
		return nil, err
	}
	if err := validation.finish(); err != nil {
		return nil, err
	}
	return generation, nil
}

// ValidateManagedRPMViewDirectory is the signed counterpart of
// ValidateManagedRPMViewUnsignedDirectory.
func ValidateManagedRPMViewDirectory(ctx context.Context, dir string, compression Compression, verifier DetachedVerifier, repositoryBase *url.URL, view ManagedRPMViewPath, expected []ManagedRPMPackageExpectation) (*Generation, error) {
	validation, err := newManagedRPMViewValidation(repositoryBase, view, expected)
	if err != nil {
		return nil, err
	}
	generation, err := validateDirectoryModeRetained(ctx, dir, compression, verifier, false, true, true, false, true, validation)
	if err != nil {
		return nil, err
	}
	if err := validation.finish(); err != nil {
		return nil, err
	}
	return generation, nil
}

// ValidateLegacyC2RPMViewUnsignedDirectory validates the frozen v0.2
// view-local pool/... href contract.  It is an admission gate for explicit
// migration only and must not be used by a forward renderer.
func ValidateLegacyC2RPMViewUnsignedDirectory(ctx context.Context, dir string, compression Compression, view ManagedRPMViewPath, expected []ManagedRPMPackageExpectation) (*Generation, error) {
	validation, err := newLegacyC2RPMViewValidation(view, expected)
	if err != nil {
		return nil, err
	}
	generation, err := validateDirectoryModeRetained(ctx, dir, compression, nil, false, true, false, false, true, validation)
	if err != nil {
		return nil, err
	}
	if err := validation.finish(); err != nil {
		return nil, err
	}
	return generation, nil
}

// ValidateLegacyC2RPMViewDirectory is the signed counterpart of
// ValidateLegacyC2RPMViewUnsignedDirectory.
func ValidateLegacyC2RPMViewDirectory(ctx context.Context, dir string, compression Compression, verifier DetachedVerifier, view ManagedRPMViewPath, expected []ManagedRPMPackageExpectation) (*Generation, error) {
	validation, err := newLegacyC2RPMViewValidation(view, expected)
	if err != nil {
		return nil, err
	}
	generation, err := validateDirectoryModeRetained(ctx, dir, compression, verifier, false, true, true, false, true, validation)
	if err != nil {
		return nil, err
	}
	if err := validation.finish(); err != nil {
		return nil, err
	}
	return generation, nil
}

func validateDirectory(ctx context.Context, dir string, compression Compression, verifier DetachedVerifier, flatCompatibility bool) (*Generation, error) {
	return validateDirectoryMode(ctx, dir, compression, verifier, flatCompatibility, true, false)
}

func validateDirectoryMode(ctx context.Context, dir string, compression Compression, verifier DetachedVerifier, flatCompatibility, signed, requireEmpty bool) (*Generation, error) {
	return validateDirectoryModeRetained(ctx, dir, compression, verifier, flatCompatibility, false, signed, requireEmpty, false, nil)
}

func validateDirectoryModeRetained(ctx context.Context, dir string, compression Compression, verifier DetachedVerifier, flatCompatibility, managed, signed, requireEmpty, retained bool, viewValidation rpmViewValidation) (*Generation, error) {
	dir = filepath.Clean(dir)
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve %q: %v", ErrInvalidRepodata, dir, err)
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return nil, fmt.Errorf("%w: stat %q: %v", ErrInvalidRepodata, dir, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %q is not a real directory", ErrInvalidRepodata, dir)
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return nil, fmt.Errorf("%w: open %q: %v", ErrInvalidRepodata, dir, err)
	}
	defer root.Close()
	opened, openErr := root.Stat(".")
	current, pathErr := os.Lstat(absolute)
	if openErr != nil || pathErr != nil || !opened.IsDir() || current.Mode()&os.ModeSymlink != 0 ||
		!current.IsDir() || !os.SameFile(info, opened) || !os.SameFile(info, current) {
		return nil, fmt.Errorf("%w: generation directory changed while binding: %v", ErrInvalidRepodata, errors.Join(openErr, pathErr))
	}
	generation, err := validateRootMode(ctx, root, dir, compression, verifier, flatCompatibility, managed, signed, requireEmpty, retained, viewValidation)
	if err != nil {
		return nil, err
	}
	opened, openErr = root.Stat(".")
	current, pathErr = os.Lstat(absolute)
	if openErr != nil || pathErr != nil || !opened.IsDir() || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() ||
		!os.SameFile(info, opened) || !os.SameFile(info, current) {
		return nil, fmt.Errorf("%w: generation directory changed during validation: %v", ErrInvalidRepodata, errors.Join(openErr, pathErr))
	}
	return generation, nil
}

func validateRootMode(ctx context.Context, root *os.Root, diagnostic string, compression Compression, verifier DetachedVerifier, flatCompatibility, managed, signed, requireEmpty, retained bool, viewValidation rpmViewValidation) (*Generation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrInvalidRepodata)
	}
	if root == nil {
		return nil, fmt.Errorf("%w: nil repodata root", ErrInvalidRepodata)
	}
	if signed && verifier == nil {
		return nil, fmt.Errorf("%w: detached verifier is required", ErrInvalidRepodata)
	}
	if compression != CompressionGzip && compression != CompressionZstd {
		return nil, fmt.Errorf("%w: unsupported compression %q", ErrInvalidRepodata, compression)
	}
	if diagnostic == "" {
		diagnostic = "."
	}
	boundIdentity, err := root.Stat(".")
	if err != nil || !boundIdentity.IsDir() {
		return nil, fmt.Errorf("%w: retained repodata root is not a directory: %v", ErrInvalidRepodata, err)
	}
	var repomdBytes []byte
	var validatedEntries []validatedRegularEntry
	if signed {
		repomdBytes, validatedEntries, err = verifyRepomdSignatureRoot(ctx, root, verifier)
	} else {
		repomdBytes, validatedEntries, err = readUnsignedRepomdRoot(root)
	}
	if err != nil {
		return nil, err
	}
	if bytesContainsDirective(repomdBytes) {
		return nil, fmt.Errorf("%w: XML directives are forbidden", ErrInvalidRepodata)
	}
	var document repomdDocument
	decoder := xml.NewDecoder(strings.NewReader(string(repomdBytes)))
	decoder.Strict = true
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("%w: decode repomd.xml: %v", ErrInvalidRepodata, err)
	}
	if document.XMLName.Space != repoNS || document.XMLName.Local != "repomd" {
		return nil, fmt.Errorf("%w: repomd root is {%s}%s", ErrInvalidRepodata, document.XMLName.Space, document.XMLName.Local)
	}
	revisionText := strings.TrimSpace(document.Revision)
	revision, err := strconv.ParseUint(revisionText, 10, 64)
	if err != nil || strconv.FormatUint(revision, 10) != revisionText {
		return nil, fmt.Errorf("%w: invalid revision %q", ErrInvalidRepodata, document.Revision)
	}
	if len(document.Data) != 3 {
		return nil, fmt.Errorf("%w: expected exactly primary, filelists, and other; got %d records", ErrInvalidRepodata, len(document.Data))
	}

	wantedOrder := []string{"primary", "filelists", "other"}
	byType := make(map[string]repomdRecord, 3)
	for _, record := range document.Data {
		if _, exists := byType[record.Type]; exists {
			return nil, fmt.Errorf("%w: duplicate %q record", ErrInvalidRepodata, record.Type)
		}
		byType[record.Type] = record
	}
	repomdSum := sha256.Sum256(repomdBytes)
	generation := &Generation{Dir: diagnostic, Revision: revision, RepomdSHA256: hex.EncodeToString(repomdSum[:])}
	// Identity validation stays in memory for ordinary repositories. Large
	// metadata sets lazily create private external-sort runs; empty repositories
	// and bounded read-only checks never require temporary storage.
	identityTemp := ""
	var packageCount int64 = -1
	var identitySHA string
	for i, kind := range wantedOrder {
		record, ok := byType[kind]
		if !ok {
			return nil, fmt.Errorf("%w: missing %q record", ErrInvalidRepodata, kind)
		}
		artifact, count, identities, validatedEntry, err := validateArtifactRoot(ctx, root, kind, record, compression, flatCompatibility, managed, identityTemp, requireEmpty, viewValidation)
		if err != nil {
			return nil, err
		}
		validatedEntries = append(validatedEntries, validatedEntry)
		currentIdentitySHA := digestBytes(nil)
		if requireEmpty {
			if count != 0 {
				return nil, fmt.Errorf("%w: %s metadata is not empty", ErrInvalidRepodata, kind)
			}
		} else {
			currentIdentitySHA = identities
		}
		if identitySHA == "" {
			identitySHA = currentIdentitySHA
		} else if currentIdentitySHA != identitySHA {
			return nil, fmt.Errorf("%w: %s package identity set differs from primary", ErrInvalidRepodata, kind)
		}
		if packageCount == -1 {
			packageCount = count
		} else if count != packageCount {
			return nil, fmt.Errorf("%w: %s package count %d differs from %d", ErrInvalidRepodata, kind, count, packageCount)
		}
		generation.Artifacts[i] = artifact
	}
	generation.IdentitySHA256 = identitySHA
	generation.Packages = packageCount
	if err := rejectExtraGenerationFilesRootMode(ctx, root, generation, signed, retained); err != nil {
		return nil, err
	}
	if err := verifyValidatedGenerationEntriesRoot(ctx, root, validatedEntries); err != nil {
		return nil, err
	}
	// Re-list after the final content/identity proofs so an entry added while
	// those proofs were running cannot hide behind a previously exact listing.
	if err := rejectExtraGenerationFilesRootMode(ctx, root, generation, signed, retained); err != nil {
		return nil, err
	}
	currentIdentity, err := root.Stat(".")
	if err != nil || !currentIdentity.IsDir() || !os.SameFile(boundIdentity, currentIdentity) {
		return nil, fmt.Errorf("%w: retained repodata root changed during validation: %v", ErrInvalidRepodata, err)
	}
	return generation, nil
}

func verifyRepomdSignatureRoot(ctx context.Context, root *os.Root, verifier DetachedVerifier) ([]byte, []validatedRegularEntry, error) {
	message, err := openBoundRegularFile(root, "repomd.xml", 1, maxRepomdBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: invalid repomd.xml: %v", ErrInvalidRepodata, err)
	}
	messageBytes, messageErr := message.ReadAll(maxRepomdBytes)
	messageEntry := validatedRegularEntry{
		name: "repomd.xml", identity: message.identity, sha256: digestBytes(messageBytes),
	}
	messageCloseErr := message.Close()
	if messageErr != nil || messageCloseErr != nil {
		return nil, nil, errors.Join(messageErr, messageCloseErr)
	}
	signature, err := openBoundRegularFile(root, "repomd.xml.asc", 1, maxSignatureBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: invalid repomd.xml.asc: %v", ErrInvalidRepodata, err)
	}
	signatureBytes, signatureErr := signature.ReadAll(maxSignatureBytes)
	signatureEntry := validatedRegularEntry{
		name: "repomd.xml.asc", identity: signature.identity, sha256: digestBytes(signatureBytes),
	}
	signatureCloseErr := signature.Close()
	if signatureErr != nil || signatureCloseErr != nil {
		return nil, nil, errors.Join(signatureErr, signatureCloseErr)
	}
	if err := verifier.Verify(ctx, bytes.NewReader(messageBytes), bytes.NewReader(signatureBytes)); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrSignatureValidation, err)
	}
	return messageBytes, []validatedRegularEntry{messageEntry, signatureEntry}, nil
}

func readUnsignedRepomdRoot(root *os.Root) ([]byte, []validatedRegularEntry, error) {
	message, err := openBoundRegularFile(root, "repomd.xml", 1, maxRepomdBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: invalid repomd.xml: %v", ErrInvalidRepodata, err)
	}
	messageBytes, readErr := message.ReadAll(maxRepomdBytes)
	entry := validatedRegularEntry{name: "repomd.xml", identity: message.identity, sha256: digestBytes(messageBytes)}
	closeErr := message.Close()
	if readErr != nil || closeErr != nil {
		return nil, nil, errors.Join(readErr, closeErr)
	}
	return messageBytes, []validatedRegularEntry{entry}, nil
}

func validateArtifactRoot(ctx context.Context, root *os.Root, kind string, record repomdRecord, compression Compression, flatCompatibility, managed bool, identityTemp string, requireEmpty bool, viewValidation rpmViewValidation) (Artifact, int64, string, validatedRegularEntry, error) {
	if record.Checksum.Type != "sha256" || record.OpenChecksum.Type != "sha256" ||
		!validSHA256(record.Checksum.Value) || !validSHA256(record.OpenChecksum.Value) {
		return Artifact{}, 0, "", validatedRegularEntry{}, fmt.Errorf("%w: %s requires SHA256 checksums", ErrInvalidRepodata, kind)
	}
	extension := ".gz"
	if compression == CompressionZstd {
		extension = ".zst"
	}
	wantBase := record.Checksum.Value + "-" + kind + ".xml" + extension
	wantHref := "repodata/" + wantBase
	if record.Location.Href != wantHref || path.Clean(record.Location.Href) != record.Location.Href ||
		strings.Contains(record.Location.Href, "\\") {
		return Artifact{}, 0, "", validatedRegularEntry{}, fmt.Errorf("%w: unsafe or non-canonical %s href %q", ErrInvalidRepodata, kind, record.Location.Href)
	}
	file, err := openBoundRegularFile(root, wantBase, 0, record.Size)
	if err != nil {
		return Artifact{}, 0, "", validatedRegularEntry{}, fmt.Errorf("%w: missing regular artifact %q", ErrInvalidRepodata, wantBase)
	}
	defer file.Close()
	if file.identity.Size() != record.Size || record.Size < 0 || record.OpenSize < 0 || record.Timestamp < 0 {
		return Artifact{}, 0, "", validatedRegularEntry{}, fmt.Errorf("%w: invalid %s size/timestamp", ErrInvalidRepodata, kind)
	}
	compressedSHA, err := hashReaderContext(ctx, file.file)
	if err != nil {
		return Artifact{}, 0, "", validatedRegularEntry{}, err
	}
	if compressedSHA != record.Checksum.Value {
		return Artifact{}, 0, "", validatedRegularEntry{}, fmt.Errorf("%w: %s compressed checksum mismatch", ErrInvalidRepodata, kind)
	}
	if err := file.Reset(); err != nil {
		return Artifact{}, 0, "", validatedRegularEntry{}, err
	}
	openSHA, openSize, count, identities, err := validateOpenXML(ctx, file.file, kind, compression, flatCompatibility, managed, identityTemp, requireEmpty, viewValidation)
	if err != nil {
		return Artifact{}, 0, "", validatedRegularEntry{}, err
	}
	if err := file.Check(); err != nil {
		return Artifact{}, 0, "", validatedRegularEntry{}, err
	}
	if openSHA != record.OpenChecksum.Value || openSize != record.OpenSize {
		return Artifact{}, 0, "", validatedRegularEntry{}, fmt.Errorf("%w: %s open checksum/size mismatch", ErrInvalidRepodata, kind)
	}
	validatedEntry := validatedRegularEntry{name: wantBase, identity: file.identity, sha256: compressedSHA}
	if err := file.Close(); err != nil {
		return Artifact{}, 0, "", validatedRegularEntry{}, err
	}
	return Artifact{
		Type: kind, Path: wantHref, SHA256: record.Checksum.Value,
		OpenSHA256: record.OpenChecksum.Value, Size: record.Size, OpenSize: record.OpenSize,
		Timestamp: record.Timestamp, Packages: count, Compression: compression,
	}, count, identities, validatedEntry, nil
}

func validateOpenXML(ctx context.Context, source io.Reader, kind string, compression Compression, flatCompatibility, managed bool, identityTemp string, requireEmpty bool, viewValidation rpmViewValidation) (string, int64, int64, string, error) {
	var reader io.Reader
	var closer io.Closer
	switch compression {
	case CompressionGzip:
		gz, err := gzip.NewReader(source)
		if err != nil {
			return "", 0, 0, "", fmt.Errorf("%w: open gzip %s: %v", ErrInvalidRepodata, kind, err)
		}
		reader, closer = gz, gz
	case CompressionZstd:
		zr, err := zstd.NewReader(source, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(64<<20))
		if err != nil {
			return "", 0, 0, "", fmt.Errorf("%w: open zstd %s: %v", ErrInvalidRepodata, kind, err)
		}
		reader, closer = zr, zr.IOReadCloser()
	default:
		return "", 0, 0, "", fmt.Errorf("%w: unsupported compression", ErrInvalidRepodata)
	}
	defer closer.Close()
	h := sha256.New()
	counter := &countingWriter{w: h}
	tee := io.TeeReader(&contextReader{ctx: ctx, r: reader}, counter)
	var spool *metadataIdentitySpool
	if !requireEmpty {
		spool = newMetadataIdentitySpool(ctx, identityTemp, kind)
	}
	count, err := validateMetadataXMLMode(tee, kind, flatCompatibility, managed, spool, viewValidation)
	if err != nil {
		spool.Close()
		return "", 0, 0, "", err
	}
	identities := ""
	if requireEmpty {
		if count != 0 {
			return "", 0, 0, "", fmt.Errorf("%w: %s metadata is not empty", ErrInvalidRepodata, kind)
		}
	} else {
		identities, err = spool.Finish()
		if err != nil {
			return "", 0, 0, "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), counter.n, count, identities, nil
}

func validateMetadataXML(reader io.Reader, kind string) (int64, error) {
	return validateMetadataXMLMode(reader, kind, false, false, nil, nil)
}

func validateMetadataXMLMode(reader io.Reader, kind string, flatCompatibility, managed bool, identities *metadataIdentitySpool, viewValidation rpmViewValidation) (int64, error) {
	wantedLocal, wantedNS := "metadata", commonNS
	switch kind {
	case "filelists":
		wantedLocal, wantedNS = "filelists", filelistsNS
	case "other":
		wantedLocal, wantedNS = "otherdata", otherNS
	case "primary":
	default:
		return 0, fmt.Errorf("%w: unknown XML kind %q", ErrInvalidRepodata, kind)
	}
	decoder := xml.NewDecoder(bufio.NewReaderSize(reader, 128*1024))
	decoder.Strict = true
	depth := 0
	var declared, actual int64 = -1, 0
	var packageName, packageIdentity strings.Builder
	var packageHref string
	var packageSize int64
	var capturePackageName, capturePackageIdentity, packageLocationSeen, packageSizeSeen bool
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("%w: decode %s XML: %v", ErrInvalidRepodata, kind, err)
		}
		switch value := token.(type) {
		case xml.Directive:
			return 0, fmt.Errorf("%w: XML directives are forbidden", ErrInvalidRepodata)
		case xml.StartElement:
			depth++
			if depth == 1 {
				if value.Name.Space != wantedNS || value.Name.Local != wantedLocal {
					return 0, fmt.Errorf("%w: %s root is {%s}%s", ErrInvalidRepodata, kind, value.Name.Space, value.Name.Local)
				}
				for _, attr := range value.Attr {
					if attr.Name.Local == "packages" {
						declared, err = strconv.ParseInt(attr.Value, 10, 64)
						if err != nil || declared < 0 {
							return 0, fmt.Errorf("%w: invalid %s package count", ErrInvalidRepodata, kind)
						}
					}
				}
				if declared < 0 {
					return 0, fmt.Errorf("%w: %s lacks package count", ErrInvalidRepodata, kind)
				}
			} else if depth == 2 && value.Name.Local == "package" {
				if value.Name.Space != wantedNS {
					return 0, fmt.Errorf("%w: %s package has namespace %q", ErrInvalidRepodata, kind, value.Name.Space)
				}
				actual++
				packageName.Reset()
				packageIdentity.Reset()
				packageHref = ""
				packageSize = 0
				packageLocationSeen = false
				packageSizeSeen = false
				if kind != "primary" {
					for _, attr := range value.Attr {
						if attr.Name.Local == "pkgid" {
							packageIdentity.WriteString(strings.TrimSpace(attr.Value))
						}
					}
				}
			} else if kind == "primary" && depth == 3 && value.Name.Space == commonNS && value.Name.Local == "name" {
				capturePackageName = true
			} else if kind == "primary" && depth == 3 && value.Name.Space == commonNS && value.Name.Local == "checksum" {
				typeSHA256, packageID := false, false
				for _, attr := range value.Attr {
					typeSHA256 = typeSHA256 || attr.Name.Local == "type" && attr.Value == "sha256"
					packageID = packageID || attr.Name.Local == "pkgid" && attr.Value == "YES"
				}
				if !typeSHA256 || !packageID {
					return 0, fmt.Errorf("%w: primary package requires SHA256 pkgid checksum", ErrInvalidRepodata)
				}
				capturePackageIdentity = true
			} else if kind == "primary" && depth == 3 && value.Name.Space == commonNS && value.Name.Local == "size" {
				if packageSizeSeen {
					return 0, fmt.Errorf("%w: primary package has duplicate size", ErrInvalidRepodata)
				}
				packageSizeSeen = true
				packageSize = -1
				for _, attr := range value.Attr {
					if attr.Name.Local == "package" {
						parsed, parseErr := strconv.ParseInt(attr.Value, 10, 64)
						if parseErr != nil {
							return 0, fmt.Errorf("%w: primary package has invalid package size", ErrInvalidRepodata)
						}
						packageSize = parsed
					}
				}
				if packageSize < 0 {
					return 0, fmt.Errorf("%w: primary package has invalid package size", ErrInvalidRepodata)
				}
			} else if kind == "primary" && depth == 3 && value.Name.Space == commonNS && value.Name.Local == "location" {
				if packageLocationSeen {
					return 0, fmt.Errorf("%w: primary package has duplicate location", ErrInvalidRepodata)
				}
				var href string
				for _, attr := range value.Attr {
					if attr.Name.Local == "href" {
						href = attr.Value
					}
				}
				if viewValidation == nil {
					if err := validatePackageHrefForModes(packageName.String(), href, flatCompatibility, managed); err != nil {
						return 0, err
					}
				} else if href == "" {
					return 0, fmt.Errorf("%w: primary package has an empty location href", ErrInvalidRepodata)
				}
				packageHref = href
				packageLocationSeen = true
			}
		case xml.CharData:
			if capturePackageName {
				packageName.Write([]byte(value))
			}
			if capturePackageIdentity {
				packageIdentity.Write([]byte(value))
			}
		case xml.EndElement:
			if kind == "primary" && depth == 3 && value.Name.Space == commonNS && value.Name.Local == "name" {
				capturePackageName = false
			}
			if kind == "primary" && depth == 3 && value.Name.Space == commonNS && value.Name.Local == "checksum" {
				capturePackageIdentity = false
			}
			if kind == "primary" && depth == 2 && value.Name.Space == commonNS && value.Name.Local == "package" {
				if !packageLocationSeen || !packageSizeSeen {
					return 0, fmt.Errorf("%w: primary package %q lacks location or size", ErrInvalidRepodata, packageName.String())
				}
				if viewValidation != nil {
					if err := viewValidation.check(strings.TrimSpace(packageIdentity.String()), packageHref, packageSize); err != nil {
						return 0, err
					}
				}
			}
			if depth == 2 && value.Name.Space == wantedNS && value.Name.Local == "package" {
				identity := strings.TrimSpace(packageIdentity.String())
				if !validSHA256(identity) {
					return 0, fmt.Errorf("%w: %s package has invalid pkgid identity", ErrInvalidRepodata, kind)
				}
				if identities != nil {
					if err := identities.Add(identity); err != nil {
						return 0, err
					}
				}
			}
			depth--
			if depth < 0 {
				return 0, fmt.Errorf("%w: unbalanced %s XML", ErrInvalidRepodata, kind)
			}
		}
	}
	if depth != 0 || declared != actual {
		return 0, fmt.Errorf("%w: %s declares %d packages but contains %d", ErrInvalidRepodata, kind, declared, actual)
	}
	return actual, nil
}

func validatePackageHref(name, href string) error {
	return validatePackageHrefForMode(name, href, false)
}

func validatePackageHrefForMode(name, href string, flatCompatibility bool) error {
	return validatePackageHrefForModes(name, href, flatCompatibility, false)
}

func validatePackageHrefForModes(name, href string, flatCompatibility, managed bool) error {
	if managed {
		_, pool, err := ParseManagedRPMHref(href)
		if err != nil || name == "" || !safeManagedRPMBasename(pool.Filename()) {
			return fmt.Errorf("%w: package href %q is not a canonical managed parent-relative reference", ErrInvalidRepodata, href)
		}
		return nil
	}
	if href == "" || path.Clean(href) != href || strings.ContainsAny(href, "\\%?#\x00\r\n\t") {
		return fmt.Errorf("%w: unsafe package href %q", ErrInvalidRepodata, href)
	}
	if flatCompatibility {
		if href != path.Base(href) || strings.Contains(href, "/") || !strings.HasSuffix(href, ".rpm") || href == ".rpm" {
			return fmt.Errorf("%w: package href %q violates frozen flat <basename>.rpm compatibility", ErrInvalidRepodata, href)
		}
		return nil
	}
	parts := strings.Split(href, "/")
	if len(parts) != 3 || parts[0] != "Packages" || len(parts[1]) != 1 {
		return fmt.Errorf("%w: package href %q violates Packages/<bucket>/<basename>", ErrInvalidRepodata, href)
	}
	want, err := PackageLocation(name, parts[2])
	if err != nil || want != href {
		return fmt.Errorf("%w: package href %q does not match RPM name %q", ErrInvalidRepodata, href, name)
	}
	return nil
}

const metadataIdentityChunkEntries = 4096

type metadataIdentitySpool struct {
	ctx   context.Context
	root  string
	kind  string
	chunk []string
	runs  []string
	owned bool
	done  bool
}

func newMetadataIdentitySpool(ctx context.Context, root, kind string) *metadataIdentitySpool {
	return &metadataIdentitySpool{ctx: ctx, root: root, kind: kind, chunk: make([]string, 0, metadataIdentityChunkEntries)}
}

func (s *metadataIdentitySpool) Add(identity string) error {
	if s == nil {
		return nil
	}
	if s.done || !validSHA256(identity) {
		return fmt.Errorf("%w: invalid %s package identity", ErrInvalidRepodata, s.kind)
	}
	if err := s.ctx.Err(); err != nil {
		return err
	}
	s.chunk = append(s.chunk, identity)
	if len(s.chunk) == cap(s.chunk) {
		return s.flush()
	}
	return nil
}

func (s *metadataIdentitySpool) flush() error {
	if len(s.chunk) == 0 {
		return nil
	}
	sort.Strings(s.chunk)
	for index := 1; index < len(s.chunk); index++ {
		if s.chunk[index] == s.chunk[index-1] {
			return fmt.Errorf("%w: %s metadata contains duplicate pkgid %s", ErrInvalidRepodata, s.kind, s.chunk[index])
		}
	}
	if s.root == "" {
		root, err := os.MkdirTemp("", "sow-yum-identity-")
		if err != nil {
			return fmt.Errorf("%w: create package identity scratch: %v", ErrInvalidRepodata, err)
		}
		s.root, s.owned = root, true
	}
	name := filepath.Join(s.root, fmt.Sprintf("%s-%08d.ids", s.kind, len(s.runs)))
	file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	writer := bufio.NewWriterSize(file, 128*1024)
	for index, identity := range s.chunk {
		if index%256 == 0 {
			if err := s.ctx.Err(); err != nil {
				file.Close()
				return err
			}
		}
		if _, err := writer.WriteString(identity + "\n"); err != nil {
			file.Close()
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		file.Close()
		return err
	}
	if err := errors.Join(file.Sync(), file.Close()); err != nil {
		return err
	}
	s.runs = append(s.runs, name)
	s.chunk = s.chunk[:0]
	return nil
}

func (s *metadataIdentitySpool) Finish() (string, error) {
	if s == nil || s.done {
		return "", fmt.Errorf("%w: package identity spool is unavailable", ErrInvalidRepodata)
	}
	if len(s.runs) == 0 {
		sort.Strings(s.chunk)
		hasher := sha256.New()
		previous := ""
		for index, identity := range s.chunk {
			if index > 0 && identity == previous {
				return "", fmt.Errorf("%w: %s metadata contains duplicate pkgid %s", ErrInvalidRepodata, s.kind, identity)
			}
			if _, err := io.WriteString(hasher, identity+"\n"); err != nil {
				return "", err
			}
			previous = identity
		}
		s.done = true
		return hex.EncodeToString(hasher.Sum(nil)), nil
	}
	if err := s.flush(); err != nil {
		return "", err
	}
	s.done = true
	defer s.cleanup()
	var cursors metadataIdentityHeap
	for _, runName := range s.runs {
		if err := s.ctx.Err(); err != nil {
			closeMetadataIdentityCursors(cursors)
			return "", err
		}
		file, err := os.Open(runName)
		if err != nil {
			closeMetadataIdentityCursors(cursors)
			return "", err
		}
		scanner := bufio.NewScanner(file)
		if !scanner.Scan() {
			scanErr := scanner.Err()
			file.Close()
			if scanErr != nil {
				closeMetadataIdentityCursors(cursors)
				return "", scanErr
			}
			continue
		}
		cursors = append(cursors, &metadataIdentityCursor{value: scanner.Text(), scanner: scanner, file: file})
	}
	heap.Init(&cursors)
	hasher := sha256.New()
	writer := bufio.NewWriterSize(hasher, 128*1024)
	previous := ""
	for merged := 0; cursors.Len() != 0; merged++ {
		if merged%256 == 0 {
			if err := s.ctx.Err(); err != nil {
				closeMetadataIdentityCursors(cursors)
				return "", err
			}
		}
		cursor := heap.Pop(&cursors).(*metadataIdentityCursor)
		if cursor.value == previous {
			cursor.file.Close()
			closeMetadataIdentityCursors(cursors)
			return "", fmt.Errorf("%w: %s metadata contains duplicate pkgid %s", ErrInvalidRepodata, s.kind, cursor.value)
		}
		if _, err := writer.WriteString(cursor.value + "\n"); err != nil {
			cursor.file.Close()
			closeMetadataIdentityCursors(cursors)
			return "", err
		}
		previous = cursor.value
		if cursor.scanner.Scan() {
			cursor.value = cursor.scanner.Text()
			heap.Push(&cursors, cursor)
			continue
		}
		scanErr := cursor.scanner.Err()
		closeErr := cursor.file.Close()
		if scanErr != nil || closeErr != nil {
			closeMetadataIdentityCursors(cursors)
			return "", errors.Join(scanErr, closeErr)
		}
	}
	if err := writer.Flush(); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func (s *metadataIdentitySpool) Close() {
	if s != nil {
		s.done = true
		s.cleanup()
	}
}

func (s *metadataIdentitySpool) cleanup() {
	if s != nil && s.owned && s.root != "" {
		_ = os.RemoveAll(s.root)
		s.root, s.owned = "", false
	}
}

type metadataIdentityCursor struct {
	value   string
	scanner *bufio.Scanner
	file    *os.File
}

type metadataIdentityHeap []*metadataIdentityCursor

func (h metadataIdentityHeap) Len() int           { return len(h) }
func (h metadataIdentityHeap) Less(i, j int) bool { return h[i].value < h[j].value }
func (h metadataIdentityHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *metadataIdentityHeap) Push(value any)    { *h = append(*h, value.(*metadataIdentityCursor)) }
func (h *metadataIdentityHeap) Pop() any {
	old := *h
	value := old[len(old)-1]
	*h = old[:len(old)-1]
	return value
}

func closeMetadataIdentityCursors(cursors metadataIdentityHeap) {
	for _, cursor := range cursors {
		_ = cursor.file.Close()
	}
}

type boundRegularFile struct {
	root     *os.Root
	name     string
	file     *os.File
	identity os.FileInfo
	closed   bool
}

type validatedRegularEntry struct {
	name     string
	identity os.FileInfo
	sha256   string
}

func digestBytes(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func verifyValidatedGenerationEntriesRoot(ctx context.Context, root *os.Root, entries []validatedRegularEntry) error {
	if ctx == nil || root == nil || len(entries) == 0 {
		return fmt.Errorf("%w: validated generation entry proofs are unavailable", ErrInvalidRepodata)
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry.name == "" || entry.identity == nil || !validSHA256(entry.sha256) {
			return fmt.Errorf("%w: invalid validated generation entry proof", ErrInvalidRepodata)
		}
		if _, exists := seen[entry.name]; exists {
			return fmt.Errorf("%w: duplicate validated generation entry proof %q", ErrInvalidRepodata, entry.name)
		}
		seen[entry.name] = struct{}{}
		file, err := openBoundRegularFile(root, entry.name, entry.identity.Size(), entry.identity.Size())
		if err != nil {
			return fmt.Errorf("%w: validated entry %q changed after inspection: %v", ErrInvalidRepodata, entry.name, err)
		}
		sameIdentity := os.SameFile(entry.identity, file.identity) &&
			entry.identity.Mode() == file.identity.Mode() &&
			entry.identity.Size() == file.identity.Size() &&
			entry.identity.ModTime().Equal(file.identity.ModTime())
		if !sameIdentity {
			_ = file.Close()
			return fmt.Errorf("%w: validated entry %q changed after inspection", ErrInvalidRepodata, entry.name)
		}
		digest, hashErr := hashReaderContext(ctx, file.file)
		closeErr := file.Close()
		if hashErr != nil || closeErr != nil {
			return errors.Join(
				fmt.Errorf("%w: revalidate entry %q", ErrInvalidRepodata, entry.name),
				hashErr,
				closeErr,
			)
		}
		if digest != entry.sha256 {
			return fmt.Errorf("%w: validated entry %q content changed after inspection", ErrInvalidRepodata, entry.name)
		}
	}
	return nil
}

func openBoundRegularFile(root *os.Root, name string, minimum, maximum int64) (*boundRegularFile, error) {
	if root == nil || name == "" || filepath.IsAbs(name) || filepath.Clean(name) != name ||
		name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) ||
		minimum < 0 || maximum < minimum {
		return nil, errors.New("unsafe bounded regular file request")
	}
	before, err := root.Lstat(name)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() ||
		before.Size() < minimum || before.Size() > maximum {
		return nil, errors.Join(err, fmt.Errorf("%s is not a bounded regular file", name))
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	opened, openErr := file.Stat()
	current, pathErr := root.Lstat(name)
	if openErr != nil || pathErr != nil || !opened.Mode().IsRegular() ||
		current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() ||
		!os.SameFile(before, opened) || !os.SameFile(before, current) {
		_ = file.Close()
		return nil, errors.Join(openErr, pathErr, fmt.Errorf("%s changed while opening", name))
	}
	return &boundRegularFile{root: root, name: name, file: file, identity: opened}, nil
}

func (file *boundRegularFile) Check() error {
	if file == nil || file.root == nil || file.file == nil || file.closed {
		return errors.New("bounded regular file is unavailable")
	}
	opened, openErr := file.file.Stat()
	current, pathErr := file.root.Lstat(file.name)
	if openErr != nil || pathErr != nil || !opened.Mode().IsRegular() ||
		current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() ||
		!os.SameFile(file.identity, opened) || !os.SameFile(file.identity, current) ||
		opened.Size() != file.identity.Size() || current.Size() != file.identity.Size() ||
		opened.Mode() != file.identity.Mode() || current.Mode() != file.identity.Mode() ||
		!opened.ModTime().Equal(file.identity.ModTime()) || !current.ModTime().Equal(file.identity.ModTime()) {
		return errors.Join(openErr, pathErr, fmt.Errorf("%s changed while reading", file.name))
	}
	return nil
}

func (file *boundRegularFile) Reset() error {
	if err := file.Check(); err != nil {
		return err
	}
	if _, err := file.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	return file.Check()
}

func (file *boundRegularFile) ReadAll(maximum int64) ([]byte, error) {
	if file == nil || maximum < 0 {
		return nil, errors.New("invalid bounded regular file read")
	}
	if err := file.Check(); err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(file.file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maximum || int64(len(body)) != file.identity.Size() {
		return nil, fmt.Errorf("%s exceeded its bound or changed size", file.name)
	}
	if err := file.Check(); err != nil {
		return nil, err
	}
	return body, nil
}

func (file *boundRegularFile) Close() error {
	if file == nil || file.closed {
		return nil
	}
	checkErr := file.Check()
	file.closed = true
	closeErr := file.file.Close()
	file.file = nil
	return errors.Join(checkErr, closeErr)
}

var retainedMetadataName = regexp.MustCompile(`^([0-9a-f]{64})-(?:primary|filelists|other)\.xml\.(?:gz|zst)$`)

func rejectExtraGenerationFilesRootMode(ctx context.Context, root *os.Root, generation *Generation, signed, allowRetained bool) error {
	wanted := map[string]struct{}{"repomd.xml": {}}
	if signed {
		wanted["repomd.xml.asc"] = struct{}{}
	}
	for _, artifact := range generation.Artifacts {
		wanted[strings.TrimPrefix(artifact.Path, "repodata/")] = struct{}{}
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	if len(entries) < len(wanted) || (!allowRetained && len(entries) != len(wanted)) {
		return fmt.Errorf("%w: generation contains extra or missing files", ErrInvalidRepodata)
	}
	for _, entry := range entries {
		info, err := root.Lstat(entry.Name())
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("%w: unexpected generation entry %q", ErrInvalidRepodata, entry.Name())
		}
		if _, ok := wanted[entry.Name()]; ok {
			continue
		}
		match := retainedMetadataName.FindStringSubmatch(entry.Name())
		if !allowRetained || len(match) != 2 {
			return fmt.Errorf("%w: unexpected generation entry %q", ErrInvalidRepodata, entry.Name())
		}
		file, err := root.Open(entry.Name())
		if err != nil {
			return fmt.Errorf("%w: open retained generation entry %q", ErrInvalidRepodata, entry.Name())
		}
		digest, hashErr := hashReaderContext(ctx, file)
		closeErr := file.Close()
		if hashErr != nil || closeErr != nil || digest != match[1] {
			return fmt.Errorf("%w: retained generation entry %q checksum mismatch", ErrInvalidRepodata, entry.Name())
		}
	}
	return nil
}

func hashFileContext(ctx context.Context, filename string) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.CopyBuffer(h, &contextReader{ctx: ctx, r: f}, make([]byte, copyBufferSize)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashReaderContext(ctx context.Context, reader io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.CopyBuffer(h, &contextReader{ctx: ctx, r: reader}, make([]byte, copyBufferSize)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func bytesContainsDirective(data []byte) bool {
	upper := strings.ToUpper(string(data))
	return strings.Contains(upper, "<!DOCTYPE") || strings.Contains(upper, "<!ENTITY")
}
