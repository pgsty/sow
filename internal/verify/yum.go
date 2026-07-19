package verify

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/klauspost/compress/zstd"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/yumrepo"
)

const yumCommonNamespace = "http://linux.duke.edu/metadata/common"

var yumIdentitySegment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._~-]*$`)

var errYUMPackageSignature = errors.New("YUM package signature verification failed")

// PayloadReadSeekCloser is the narrow retained-file capability required for
// embedded RPM signature verification.
type PayloadReadSeekCloser interface {
	io.ReadSeeker
	io.ReaderAt
	io.Closer
}

// PayloadOpener opens one entry from ActualPayload without requiring it to be
// copied below YUMCheck.Root. Callers must bind the returned reader to the same
// immutable evidence represented by the manifest entry.
type PayloadOpener func(manifest.Entry) (PayloadReadSeekCloser, error)

// YUMCheck uses yumrepo.ValidateDirectory for the signed metadata generation,
// then streams primary.xml to prove the exact bidirectional
// primary<->Packages byte closure.
type YUMCheck struct {
	CheckID        string
	Root           string
	Compression    yumrepo.Compression
	Verifier       yumrepo.DetachedVerifier
	PackageKeyring openpgp.KeyRing
	VerifyAt       time.Time
	Workers        int
	ChunkEntries   int
	TempDir        string
	// ActualPayload and OpenPayload are an all-or-nothing capability mode. It
	// validates metadata/index closure against a retained CAS-backed manifest
	// and opens RPMs through the caller's bound root, avoiding a second package
	// tree or repository-sized byte copy. Nil preserves filesystem L1 behavior.
	ActualPayload Stream
	OpenPayload   PayloadOpener
	// ExpectedIdentities optionally binds full NEVRA/location/size/checksum
	// identity from primary.xml to the selected canonical views.
	ExpectedIdentities Stream
}

func (c YUMCheck) ID() string   { return c.CheckID }
func (c YUMCheck) Layer() Layer { return LayerL1 }

func (c YUMCheck) Verify(ctx context.Context, recorder *Recorder) (resultErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.Verifier == nil {
		return errors.New("YUM check requires a detached signature verifier")
	}
	if c.PackageKeyring == nil || c.VerifyAt.IsZero() {
		return errors.New("YUM check requires an RPM package keyring and verification time")
	}
	if (c.ActualPayload == nil) != (c.OpenPayload == nil) {
		return errors.New("YUM capability payload manifest and opener must be supplied together")
	}
	if err := realDirectory(c.Root); err != nil {
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "YUM_ROOT_UNSAFE", Subject: c.CheckID, Message: "YUM repository root is absent, symlinked, or not a directory"})
		return nil
	}
	generation, err := yumrepo.ValidateDirectory(ctx, filepath.Join(c.Root, "repodata"), c.Compression, c.Verifier)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		code := "YUM_METADATA_INVALID"
		if errors.Is(err, yumrepo.ErrSignatureValidation) {
			code = "YUM_SIGNATURE_INVALID"
		}
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: code, Subject: c.CheckID, Message: "YUM repodata structure, checksums, compression, or detached signature is invalid"})
		return nil
	}
	primary := generation.Artifacts[0]
	if primary.Type != "primary" || !safeRelative(primary.Path) {
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "YUM_PRIMARY_INVALID", Subject: c.CheckID, Message: "validated YUM generation does not expose a canonical primary artifact"})
		return nil
	}
	tempRoot, removeTemp, err := verificationTemp(c.TempDir, "sow-verify-yum-")
	if err != nil {
		return err
	}
	if removeTemp {
		defer joinVerificationCleanup(&resultErr, func() error { return os.RemoveAll(tempRoot) })
	}
	if c.ActualPayload == nil && scratchVisibleToScope(c.Root, "Packages", tempRoot) {
		return errors.New("YUM verification scratch directory is inside Packages")
	}
	if c.ActualPayload == nil {
		if err := auditTreeShape(ctx, filepath.Join(c.Root, "Packages"), false); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "YUM_PACKAGE_TREE_UNSAFE", Subject: c.CheckID, Message: "YUM Packages tree contains a symlink, special file, or reserved shadow point"})
			return nil
		}
	}
	expected, identities, canonicalIdentities, err := c.primaryManifests(ctx, tempRoot, primary)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "YUM_PRIMARY_CLOSURE_INVALID", Subject: c.CheckID, Message: "primary metadata package checksums, sizes, or locations are invalid"})
		return nil
	}
	defer joinVerificationCleanup(&resultErr, expected.Close)
	defer joinVerificationCleanup(&resultErr, identities.Close)
	defer joinVerificationCleanup(&resultErr, canonicalIdentities.Close)
	identityPath, err := identities.Finish(ctx)
	if err != nil {
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "YUM_PACKAGE_IDENTITY_CONFLICT", Subject: c.CheckID, Message: "primary metadata contains conflicting package identities"})
		return nil
	}
	for _, artifact := range generation.Artifacts[1:] {
		identity, err := c.secondaryIdentityManifest(ctx, tempRoot, artifact)
		if err != nil {
			recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "YUM_METADATA_IDENTITY_INVALID", Subject: c.CheckID, Message: "filelists or other metadata has invalid package identities"})
			return nil
		}
		secondaryPath, finishErr := identity.Finish(ctx)
		equal := false
		if finishErr == nil {
			equal, finishErr = equalManifestFiles(identityPath, secondaryPath)
		}
		if closeErr := identity.Close(); closeErr != nil {
			finishErr = errors.Join(finishErr, closeErr)
		}
		if finishErr != nil || !equal {
			recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "YUM_METADATA_IDENTITY_DRIFT", Subject: c.CheckID, Message: "primary, filelists, and other metadata do not name the same package identities"})
			return nil
		}
	}
	actualIdentities, err := canonicalIdentities.Finish(ctx)
	if err != nil {
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "YUM_CANONICAL_IDENTITY_CONFLICT", Subject: c.CheckID, Message: "primary metadata contains conflicting canonical package identities"})
		return nil
	}
	if c.ExpectedIdentities != nil {
		comparison := ManifestComparisonCheck{CheckID: c.CheckID + "/identity", AtLayer: LayerL1, Subject: c.CheckID, Desired: c.ExpectedIdentities, Actual: FileStream(actualIdentities), CodePrefix: "YUM_CANONICAL_IDENTITY"}
		if err := comparison.Verify(ctx, recorder); err != nil {
			return err
		}
	}
	expectedPath, err := expected.Finish(ctx)
	if err != nil {
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "YUM_PACKAGE_REFERENCE_CONFLICT", Subject: c.CheckID, Message: "primary metadata contains conflicting references to one package path"})
		return nil
	}
	bodyIdentities, closeBodyIdentities, err := c.packageBodyIdentities(ctx, tempRoot, expectedPath)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		code := "YUM_PACKAGE_BODY_INVALID"
		message := "an indexed RPM body is unreadable, changed, or has invalid header identity"
		if errors.Is(err, errYUMPackageSignature) {
			code = "YUM_PACKAGE_SIGNATURE_INVALID"
			message = "an indexed RPM is unsigned, untrusted, cryptographically invalid, or has an invalid signed payload digest"
		}
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: code, Subject: c.CheckID, Message: message})
		return nil
	}
	defer joinVerificationCleanup(&resultErr, closeBodyIdentities)
	bodyComparison := ManifestComparisonCheck{CheckID: c.CheckID + "/body-identity", AtLayer: LayerL1, Subject: c.CheckID, Desired: FileStream(actualIdentities), Actual: FileStream(bodyIdentities), CodePrefix: "YUM_BODY_IDENTITY"}
	if err := bodyComparison.Verify(ctx, recorder); err != nil {
		return err
	}
	actualPayload := c.ActualPayload
	if actualPayload == nil {
		actualPath := filepath.Join(tempRoot, "actual-packages.tsv")
		_, err = manifest.Scan(ctx, c.Root, manifest.Scope{Path: "Packages"}, actualPath, manifest.ScanOptions{Workers: c.Workers, ChunkEntries: c.ChunkEntries, TempDir: tempRoot})
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "YUM_PACKAGE_TREE_UNSAFE", Subject: c.CheckID, Message: "YUM Packages tree is absent, symlinked, special, or changed while hashing"})
			return nil
		}
		actualPayload = FileStream(actualPath)
	}
	comparison := ManifestComparisonCheck{CheckID: c.CheckID + "/packages", AtLayer: LayerL1, Subject: c.CheckID, Desired: FileStream(expectedPath), Actual: actualPayload, CodePrefix: "YUM_PACKAGE"}
	return comparison.Verify(ctx, recorder)
}

func (c YUMCheck) packageBodyIdentities(ctx context.Context, tempRoot, manifestPath string) (string, func() error, error) {
	return buildPackageBodyIdentityManifest(ctx, tempRoot, manifestPath, c.Workers, c.ChunkEntries, func(ctx context.Context, entry manifest.Entry) (manifest.Entry, error) {
		if !strings.HasPrefix(entry.Path, "Packages/") || !strings.HasSuffix(path.Base(entry.Path), ".rpm") {
			return manifest.Entry{}, fmt.Errorf("unsafe indexed RPM path %q", entry.Path)
		}
		var packageFile PayloadReadSeekCloser
		var err error
		if c.OpenPayload != nil {
			packageFile, err = c.OpenPayload(entry)
		} else {
			var local *os.File
			local, _, err = openRegularBelow(c.Root, entry.Path, entry.Size)
			packageFile = local
		}
		if err != nil {
			return manifest.Entry{}, err
		}
		if packageFile == nil {
			return manifest.Entry{}, errors.New("package opener returned a nil RPM descriptor")
		}
		if _, err := yumrepo.VerifyEmbeddedRPMSignatures(ctx, packageFile, c.PackageKeyring, c.VerifyAt); err != nil {
			return manifest.Entry{}, errors.Join(fmt.Errorf("%w: %v", errYUMPackageSignature, err), packageFile.Close())
		}
		info, inspectErr := yumrepo.InspectPackageReader(ctx, packageFile, path.Base(entry.Path))
		closeErr := packageFile.Close()
		if inspectErr != nil || closeErr != nil {
			return manifest.Entry{}, errors.Join(inspectErr, closeErr)
		}
		if info.Location != entry.Path || info.Size != entry.Size || info.SHA256 != entry.HashString() {
			return manifest.Entry{}, errors.New("RPM body identity, location, size, or checksum differs from indexed payload evidence")
		}
		return YUMPackageIdentityEntry(info.Name, info.Epoch, info.Version, info.Release, info.Arch, info.Location, info.Size, info.SHA256)
	})
}

func (c YUMCheck) primaryManifests(ctx context.Context, tempRoot string, artifact yumrepo.Artifact) (*manifestSpool, *manifestSpool, *manifestSpool, error) {
	reader, closeArtifact, err := c.openArtifact(artifact)
	if err != nil {
		return nil, nil, nil, err
	}
	spool, err := newManifestSpool(tempRoot, c.ChunkEntries)
	if err != nil {
		_ = closeArtifact()
		return nil, nil, nil, err
	}
	identities, err := newManifestSpool(tempRoot, c.ChunkEntries)
	if err != nil {
		_ = spool.Close()
		_ = closeArtifact()
		return nil, nil, nil, err
	}
	canonicalIdentities, err := newManifestSpool(tempRoot, c.ChunkEntries)
	if err != nil {
		_ = spool.Close()
		_ = identities.Close()
		_ = closeArtifact()
		return nil, nil, nil, err
	}
	_, _, parseErr := parseYUMPrimaryDetailed(ctx, reader, spool, identities, canonicalIdentities, "")
	parseErr = errors.Join(parseErr, closeArtifact())
	if parseErr != nil {
		_ = spool.Close()
		_ = identities.Close()
		_ = canonicalIdentities.Close()
		return nil, nil, nil, parseErr
	}
	return spool, identities, canonicalIdentities, nil
}

func (c YUMCheck) secondaryIdentityManifest(ctx context.Context, tempRoot string, artifact yumrepo.Artifact) (*manifestSpool, error) {
	reader, closeArtifact, err := c.openArtifact(artifact)
	if err != nil {
		return nil, err
	}
	spool, err := newManifestSpool(tempRoot, c.ChunkEntries)
	if err != nil {
		_ = closeArtifact()
		return nil, err
	}
	_, parseErr := parseYUMSecondaryIdentities(ctx, reader, artifact.Type, spool)
	parseErr = errors.Join(parseErr, closeArtifact())
	if parseErr != nil {
		_ = spool.Close()
		return nil, parseErr
	}
	return spool, nil
}

func (c YUMCheck) openArtifact(artifact yumrepo.Artifact) (io.Reader, func() error, error) {
	f, _, err := openRegularBelow(c.Root, artifact.Path, artifact.Size)
	if err != nil {
		return nil, nil, err
	}
	var reader io.Reader
	var closer io.Closer
	switch c.Compression {
	case yumrepo.CompressionGzip:
		gz, err := gzip.NewReader(f)
		if err != nil {
			_ = f.Close()
			return nil, nil, err
		}
		reader, closer = gz, gz
	case yumrepo.CompressionZstd:
		zr, err := zstd.NewReader(f, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(64<<20))
		if err != nil {
			_ = f.Close()
			return nil, nil, err
		}
		reader, closer = zr, zr.IOReadCloser()
	default:
		_ = f.Close()
		return nil, nil, errors.New("unsupported YUM compression")
	}
	return reader, func() error { return errors.Join(closer.Close(), f.Close()) }, nil
}

type yumPrimaryPackage struct {
	name       string
	arch       string
	version    string
	release    string
	epoch      int64
	href       string
	checksum   string
	size       int64
	checksumOK bool
	sizeOK     bool
	hrefOK     bool
	nameOK     bool
	archOK     bool
	versionOK  bool
}

type yumPackageSample struct {
	Entry   manifest.Entry
	Name    string
	Arch    string
	Version string
	Release string
	Epoch   int64
}

func parseYUMPrimary(ctx context.Context, input io.Reader, spool, identities *manifestSpool) (int64, error) {
	_, count, err := parseYUMPrimaryDetailed(ctx, input, spool, identities, nil, "")
	return count, err
}

func parseYUMPrimaryWithSample(ctx context.Context, input io.Reader, spool, identities *manifestSpool) (yumPackageSample, int64, error) {
	return parseYUMPrimaryDetailed(ctx, input, spool, identities, nil, "")
}

func parseYUMPrimaryWithSampleForArch(ctx context.Context, input io.Reader, spool, identities *manifestSpool, architecture string) (yumPackageSample, int64, error) {
	return parseYUMPrimaryDetailed(ctx, input, spool, identities, nil, architecture)
}

func parseYUMPrimaryDetailed(ctx context.Context, input io.Reader, spool, identities, canonicalIdentities *manifestSpool, architecture string) (yumPackageSample, int64, error) {
	decoder := xml.NewDecoder(&contextReader{ctx: ctx, reader: input})
	decoder.Strict = true
	depth := 0
	var declared, actual int64 = -1, 0
	var current *yumPrimaryPackage
	var sample yumPackageSample
	var captureName, captureArch, captureChecksum bool
	var text strings.Builder
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return sample, 0, err
		}
		switch value := token.(type) {
		case xml.Directive:
			return sample, 0, errors.New("XML directives are forbidden")
		case xml.StartElement:
			depth++
			if depth == 1 && (value.Name.Space != yumCommonNamespace || value.Name.Local != "metadata") {
				return sample, 0, errors.New("invalid primary root")
			}
			if depth == 1 {
				for _, attribute := range value.Attr {
					if attribute.Name.Local == "packages" {
						parsed, err := strconv.ParseInt(attribute.Value, 10, 64)
						if err != nil || parsed < 0 || declared >= 0 {
							return sample, 0, errors.New("invalid primary package count")
						}
						declared = parsed
					}
				}
				if declared < 0 {
					return sample, 0, errors.New("primary metadata lacks package count")
				}
			}
			if depth == 2 && value.Name.Space == yumCommonNamespace && value.Name.Local == "package" {
				if current != nil {
					return sample, 0, errors.New("nested primary package")
				}
				actual++
				current = &yumPrimaryPackage{size: -1}
				continue
			}
			if current == nil || depth != 3 || value.Name.Space != yumCommonNamespace {
				continue
			}
			switch value.Name.Local {
			case "name":
				if current.nameOK || captureName {
					return sample, 0, errors.New("duplicate primary package name")
				}
				captureName = true
				text.Reset()
			case "arch":
				if current.archOK || captureArch {
					return sample, 0, errors.New("duplicate primary package architecture")
				}
				captureArch = true
				text.Reset()
			case "checksum":
				if current.checksumOK {
					return sample, 0, errors.New("duplicate primary checksum")
				}
				typeSHA, pkgID := false, false
				for _, attr := range value.Attr {
					switch attr.Name.Local {
					case "type":
						typeSHA = attr.Value == "sha256"
					case "pkgid":
						pkgID = strings.EqualFold(attr.Value, "yes")
					}
				}
				if !typeSHA || !pkgID {
					return sample, 0, errors.New("primary checksum is not a SHA256 package ID")
				}
				captureChecksum = true
				text.Reset()
			case "version":
				if current.versionOK {
					return sample, 0, errors.New("duplicate primary package version")
				}
				attributes := make(map[string]string, 3)
				for _, attr := range value.Attr {
					name := attr.Name.Local
					if name != "epoch" && name != "ver" && name != "rel" {
						continue
					}
					if _, duplicate := attributes[name]; duplicate {
						return sample, 0, errors.New("duplicate primary package version attribute")
					}
					attributes[name] = attr.Value
				}
				epoch, err := strconv.ParseInt(attributes["epoch"], 10, 64)
				if err != nil || epoch < 0 || !safeYUMVersionValue(attributes["ver"]) || !safeYUMVersionValue(attributes["rel"]) {
					return sample, 0, errors.New("invalid primary package version")
				}
				current.epoch, current.version, current.release, current.versionOK = epoch, attributes["ver"], attributes["rel"], true
			case "size":
				if current.sizeOK {
					return sample, 0, errors.New("duplicate primary size")
				}
				for _, attr := range value.Attr {
					if attr.Name.Local == "package" {
						parsed, err := strconv.ParseInt(attr.Value, 10, 64)
						if err != nil || parsed < 0 {
							return sample, 0, errors.New("invalid primary package size")
						}
						current.size, current.sizeOK = parsed, true
					}
				}
			case "location":
				if current.hrefOK {
					return sample, 0, errors.New("duplicate primary location")
				}
				for _, attr := range value.Attr {
					if attr.Name.Local == "href" {
						current.href, current.hrefOK = attr.Value, true
					}
				}
			}
		case xml.CharData:
			if captureName || captureArch || captureChecksum {
				text.Write([]byte(value))
			}
		case xml.EndElement:
			if current != nil && depth == 3 && value.Name.Space == yumCommonNamespace {
				switch value.Name.Local {
				case "name":
					current.name = strings.TrimSpace(text.String())
					current.nameOK = true
					captureName = false
				case "arch":
					current.arch = strings.TrimSpace(text.String())
					current.archOK = true
					captureArch = false
				case "checksum":
					current.checksum = strings.TrimSpace(text.String())
					current.checksumOK = true
					captureChecksum = false
				}
			}
			if current != nil && depth == 2 && value.Name.Space == yumCommonNamespace && value.Name.Local == "package" {
				entry, identity, err := yumPackageEntries(*current)
				if err != nil {
					return sample, 0, err
				}
				if err := spool.Add(entry); err != nil {
					return sample, 0, err
				}
				if err := identities.Add(identity); err != nil {
					return sample, 0, err
				}
				if canonicalIdentities != nil {
					canonicalIdentity, err := YUMPackageIdentityEntry(current.name, current.epoch, current.version, current.release, current.arch, entry.Path, entry.Size, entry.HashString())
					if err != nil {
						return sample, 0, err
					}
					if err := canonicalIdentities.Add(canonicalIdentity); err != nil {
						return sample, 0, err
					}
				}
				if sample.Name == "" && (architecture == "" || current.arch == "noarch" || current.arch == architecture) {
					sample = yumPackageSample{Entry: entry, Name: current.name, Arch: current.arch, Version: current.version, Release: current.release, Epoch: current.epoch}
				}
				current = nil
			}
			depth--
			if depth < 0 {
				return sample, 0, errors.New("unbalanced primary XML")
			}
		}
	}
	if depth != 0 || current != nil || declared != actual {
		return sample, 0, errors.New("truncated primary XML or package count mismatch")
	}
	return sample, actual, nil
}

func yumPackageEntries(pkg yumPrimaryPackage) (manifest.Entry, manifest.Entry, error) {
	if !pkg.nameOK || pkg.name == "" || !pkg.archOK || pkg.arch == "" || !pkg.versionOK || !pkg.hrefOK || !pkg.sizeOK || !pkg.checksumOK || !lowerSHA256(pkg.checksum) || !safeRelative(pkg.href) {
		return manifest.Entry{}, manifest.Entry{}, errors.New("primary package lacks a safe identity, location, size, or SHA256")
	}
	wanted, err := yumrepo.PackageLocation(pkg.name, path.Base(pkg.href))
	if err != nil || wanted != pkg.href {
		return manifest.Entry{}, manifest.Entry{}, errors.New("primary package location violates Packages/<bucket>/<basename>")
	}
	decoded, _ := hex.DecodeString(pkg.checksum)
	var digest [sha256.Size]byte
	copy(digest[:], decoded)
	identity, err := yumIdentityEntry(pkg.name, pkg.arch, pkg.checksum)
	return manifest.Entry{Path: pkg.href, Size: pkg.size, SHA256: digest}, identity, err
}

func safeYUMVersionValue(value string) bool {
	return value != "" && len(value) <= 1024 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n\t")
}

func parseYUMSecondaryIdentities(ctx context.Context, input io.Reader, kind string, spool *manifestSpool) (int64, error) {
	wantedRoot, wantedNamespace := "", ""
	switch kind {
	case "filelists":
		wantedRoot, wantedNamespace = "filelists", "http://linux.duke.edu/metadata/filelists"
	case "other":
		wantedRoot, wantedNamespace = "otherdata", "http://linux.duke.edu/metadata/other"
	default:
		return 0, errors.New("unsupported secondary YUM metadata kind")
	}
	decoder := xml.NewDecoder(&contextReader{ctx: ctx, reader: input})
	decoder.Strict = true
	depth := 0
	var declared, actual int64 = -1, 0
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, err
		}
		switch value := token.(type) {
		case xml.Directive:
			return 0, errors.New("XML directives are forbidden")
		case xml.StartElement:
			depth++
			if depth == 1 && (value.Name.Space != wantedNamespace || value.Name.Local != wantedRoot) {
				return 0, errors.New("invalid secondary metadata root")
			}
			if depth == 1 {
				for _, attribute := range value.Attr {
					if attribute.Name.Local == "packages" {
						parsed, err := strconv.ParseInt(attribute.Value, 10, 64)
						if err != nil || parsed < 0 || declared >= 0 {
							return 0, errors.New("invalid secondary package count")
						}
						declared = parsed
					}
				}
				if declared < 0 {
					return 0, errors.New("secondary metadata lacks package count")
				}
			}
			if depth != 2 || value.Name.Space != wantedNamespace || value.Name.Local != "package" {
				continue
			}
			actual++
			attributes := make(map[string]string, 3)
			for _, attr := range value.Attr {
				name := attr.Name.Local
				if name != "pkgid" && name != "name" && name != "arch" {
					continue
				}
				if _, duplicate := attributes[name]; duplicate {
					return 0, errors.New("duplicate secondary package identity attribute")
				}
				attributes[name] = attr.Value
			}
			entry, err := yumIdentityEntry(attributes["name"], attributes["arch"], attributes["pkgid"])
			if err != nil {
				return 0, err
			}
			if err := spool.Add(entry); err != nil {
				return 0, err
			}
		case xml.EndElement:
			depth--
			if depth < 0 {
				return 0, errors.New("unbalanced secondary metadata XML")
			}
		}
	}
	if depth != 0 || declared != actual {
		return 0, errors.New("truncated secondary metadata XML or package count mismatch")
	}
	return actual, nil
}

func yumIdentityEntry(name, arch, pkgID string) (manifest.Entry, error) {
	if !yumIdentitySegment.MatchString(name) || !yumIdentitySegment.MatchString(arch) || !lowerSHA256(pkgID) {
		return manifest.Entry{}, errors.New("invalid YUM package identity")
	}
	identityBytes := []byte(name + "\x00" + arch + "\x00" + pkgID)
	digest := sha256.Sum256(identityBytes)
	return manifest.Entry{Path: "pkgid/" + pkgID, Size: int64(len(identityBytes)), SHA256: digest}, nil
}
