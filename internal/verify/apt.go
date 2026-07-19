package verify

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/ulikunitz/xz"
	debversion "pault.ag/go/debian/version"
)

const (
	defaultAPTMetadataLimit = int64(1 << 30)
	defaultAPTLineLimit     = 4 << 20
	aptSignatureLimit       = int64(16 << 20)
)

var (
	aptPackageName        = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)
	aptArchName           = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)
	errAPTFindingRecorded = errors.New("APT finding already recorded")
)

// APTSignatureVerifier is implemented by *aptrepo.Signer. Its narrow form
// keeps verification independent of key-loading policy.
type APTSignatureVerifier interface {
	Verify(release, inRelease, detached []byte, at time.Time) error
}

// APTCheck validates every actual suite below dists/, every signed Release
// artifact and by-hash copy, every Packages compression variant, and the exact
// bidirectional Packages<->pool closure. ExpectedSuites, when non-empty, also
// freezes the configured suite set. SelectedSuites narrows an explicit CLI
// audit to complete suites (never architectures); shared pool extras belonging
// to unselected suites are retained and ignored while selected references must
// still exist byte-for-byte.
type APTCheck struct {
	CheckID                 string
	Root                    string
	ExpectedSuites          []string
	SelectedSuites          []string
	ExpectedSuiteComponents map[string][]string
	Verifier                APTSignatureVerifier
	VerifyAt                time.Time
	Workers                 int
	ChunkEntries            int
	TempDir                 string
	MaxMetadataBytes        int64
	// ActualPayload supplies the already capability-validated pool manifest.
	// When set, verification never opens or scans Root/pool; this is used by
	// read-only Nginx admission to validate signed metadata against a retained
	// CAS-backed payload without copying repository-sized package bodies into a
	// private fixture. The default nil path preserves ordinary filesystem L1.
	ActualPayload Stream
	// OpenPayload is paired with ActualPayload and opens the exact retained
	// package descriptor represented by one manifest entry. It lets L1 inspect
	// DEB control identity without copying package bodies into Root or scratch.
	OpenPayload PayloadOpener
	// ExpectedIdentities optionally binds the signed Package/Version/
	// Architecture/component/location tuple in addition to payload bytes.
	ExpectedIdentities Stream
}

func (c APTCheck) ID() string   { return c.CheckID }
func (c APTCheck) Layer() Layer { return LayerL1 }

func (c APTCheck) Verify(ctx context.Context, recorder *Recorder) (resultErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.Verifier == nil {
		return errors.New("APT check requires a signature verifier")
	}
	if c.VerifyAt.IsZero() {
		return errors.New("APT check requires an explicit verification time")
	}
	if (c.ActualPayload == nil) != (c.OpenPayload == nil) {
		return errors.New("APT capability payload manifest and opener must be supplied together")
	}
	if err := realDirectory(c.Root); err != nil {
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "APT_ROOT_UNSAFE", Subject: c.CheckID, Message: "APT archive root is absent, symlinked, or not a directory"})
		return nil
	}
	tempRoot, removeTemp, err := verificationTemp(c.TempDir, "sow-verify-apt-")
	if err != nil {
		return err
	}
	if removeTemp {
		defer joinVerificationCleanup(&resultErr, func() error { return os.RemoveAll(tempRoot) })
	}
	if c.ActualPayload == nil && scratchVisibleToScope(c.Root, "pool", tempRoot) {
		return errors.New("APT verification scratch directory is inside the pool")
	}
	if c.ActualPayload == nil {
		if err := auditTreeShape(ctx, filepath.Join(c.Root, "pool"), false); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "APT_POOL_UNSAFE", Subject: c.CheckID, Message: "APT pool contains a symlink, special file, or reserved shadow point"})
			return nil
		}
	}
	global, err := newManifestSpool(tempRoot, c.ChunkEntries)
	if err != nil {
		return fmt.Errorf("create APT closure spool: %w", err)
	}
	defer joinVerificationCleanup(&resultErr, global.Close)
	identities, err := newManifestSpool(tempRoot, c.ChunkEntries)
	if err != nil {
		return fmt.Errorf("create APT identity spool: %w", err)
	}
	defer joinVerificationCleanup(&resultErr, identities.Close)
	bodyIdentities, err := newManifestSpool(tempRoot, c.ChunkEntries)
	if err != nil {
		return fmt.Errorf("create APT body identity spool: %w", err)
	}
	defer joinVerificationCleanup(&resultErr, bodyIdentities.Close)

	suites, err := discoverSuites(c.Root)
	if err != nil {
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "APT_DISTS_UNSAFE", Subject: c.CheckID, Message: "APT dists tree contains a symlink, special file, or unsafe suite"})
		return nil
	}
	if len(suites) == 0 {
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "APT_SUITE_MISSING", Subject: c.CheckID, Message: "APT archive has no distribution suites"})
		return nil
	}
	if len(c.SelectedSuites) == 0 && len(c.ExpectedSuites) != 0 && !sameStrings(suites, canonicalStrings(c.ExpectedSuites)) {
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityError, Category: CategoryDrift, Code: "APT_SUITE_SET_DRIFT", Subject: c.CheckID, Message: "actual APT suite set differs from configured suites", Fields: []Field{{Key: "actual", Value: strings.Join(suites, ",")}, {Key: "expected", Value: strings.Join(canonicalStrings(c.ExpectedSuites), ",")}}})
	}

	verifiedSuites := suites
	if len(c.SelectedSuites) != 0 {
		selected := canonicalStrings(c.SelectedSuites)
		actual := make(map[string]struct{}, len(suites))
		for _, suite := range suites {
			actual[suite] = struct{}{}
		}
		allowed := make(map[string]struct{}, len(c.ExpectedSuites))
		for _, suite := range canonicalStrings(c.ExpectedSuites) {
			allowed[suite] = struct{}{}
		}
		verifiedSuites = verifiedSuites[:0]
		for _, suite := range selected {
			if !safeSegment(suite) {
				return errors.New("APT selected suite is unsafe")
			}
			if len(allowed) != 0 {
				if _, configured := allowed[suite]; !configured {
					return fmt.Errorf("APT selected suite %s is not configured", suite)
				}
			}
			if _, exists := actual[suite]; !exists {
				recorder.Add(Finding{Layer: LayerL1, Severity: SeverityError, Category: CategoryDrift, Code: "APT_SELECTED_SUITE_MISSING", Subject: suite, Message: "selected APT suite is absent from the archive"})
				continue
			}
			verifiedSuites = append(verifiedSuites, suite)
		}
	}

	validSuites := 0
	for _, suite := range verifiedSuites {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.verifySuite(ctx, recorder, tempRoot, global, identities, bodyIdentities, suite); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			if !errors.Is(err, errAPTFindingRecorded) {
				recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "APT_METADATA_INVALID", Subject: suite, Message: "APT suite metadata, by-hash closure, or Packages index is invalid"})
			}
			continue
		}
		validSuites++
	}
	if validSuites != len(verifiedSuites) {
		return nil
	}
	actualIdentities, err := identities.Finish(ctx)
	if err != nil {
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "APT_IDENTITY_CONFLICT", Subject: c.CheckID, Message: "APT indexes contain conflicting package identities"})
		return nil
	}
	if c.ExpectedIdentities != nil {
		comparison := ManifestComparisonCheck{CheckID: c.CheckID + "/identity", AtLayer: LayerL1, Subject: c.CheckID, Desired: c.ExpectedIdentities, Actual: FileStream(actualIdentities), CodePrefix: "APT_IDENTITY"}
		if err := comparison.Verify(ctx, recorder); err != nil {
			return err
		}
	}
	signedBodyIdentities, err := bodyIdentities.Finish(ctx)
	if err != nil {
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "APT_BODY_IDENTITY_CONFLICT", Subject: c.CheckID, Message: "APT indexes assign conflicting identities to one DEB body"})
		return nil
	}
	expectedPool, err := global.Finish(ctx)
	if err != nil {
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "APT_POOL_REFERENCE_CONFLICT", Subject: c.CheckID, Message: "APT indexes contain conflicting references to one pool path"})
		return nil
	}
	if err := c.verifyPackageBodyIdentities(ctx, recorder, tempRoot, expectedPool, signedBodyIdentities); err != nil {
		return err
	}
	actualPayload := c.ActualPayload
	if actualPayload == nil {
		actualPool := filepath.Join(tempRoot, "actual-pool.tsv")
		_, err = manifest.Scan(ctx, c.Root, manifest.Scope{Path: "pool"}, actualPool, manifest.ScanOptions{Workers: c.Workers, ChunkEntries: c.ChunkEntries, TempDir: tempRoot})
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "APT_POOL_UNSAFE", Subject: c.CheckID, Message: "APT pool is absent, contains a symlink or special file, or changed while hashing"})
			return nil
		}
		actualPayload = FileStream(actualPool)
	}
	if len(c.SelectedSuites) != 0 {
		actual, openErr := actualPayload()
		if openErr != nil {
			return openErr
		}
		actualPath := filepath.Join(tempRoot, "selected-actual-pool.tsv")
		copyErr := manifest.AtomicCopy(actualPath, actual, 0o600)
		closeErr := actual.Close()
		if copyErr != nil || closeErr != nil {
			return errors.Join(copyErr, closeErr)
		}
		return verifyAPTManifestSubset(ctx, recorder, c.CheckID, expectedPool, actualPath)
	}
	comparison := ManifestComparisonCheck{CheckID: c.CheckID + "/pool", AtLayer: LayerL1, Subject: c.CheckID, Desired: FileStream(expectedPool), Actual: actualPayload, CodePrefix: "APT_POOL"}
	return comparison.Verify(ctx, recorder)
}

func (c APTCheck) verifyPackageBodyIdentities(ctx context.Context, recorder *Recorder, tempRoot, payloadPath, signedIdentities string) (resultErr error) {
	actual, closeActual, err := buildPackageBodyIdentityManifest(ctx, tempRoot, payloadPath, c.Workers, c.ChunkEntries, func(ctx context.Context, entry manifest.Entry) (manifest.Entry, error) {
		parts := strings.Split(entry.Path, "/")
		if len(parts) < 4 || parts[0] != "pool" || !safeSegment(parts[1]) || !strings.HasSuffix(path.Base(entry.Path), ".deb") {
			return manifest.Entry{}, fmt.Errorf("unsafe indexed DEB path %q", entry.Path)
		}
		component := parts[1]
		var packageFile PayloadReadSeekCloser
		var openErr error
		if c.OpenPayload != nil {
			packageFile, openErr = c.OpenPayload(entry)
		} else {
			var local *os.File
			local, _, openErr = openRegularBelow(c.Root, entry.Path, entry.Size)
			packageFile = local
		}
		if openErr != nil {
			return manifest.Entry{}, openErr
		}
		pkg, inspectErr := aptrepo.InspectPackageReaderAs(ctx, packageFile, component, path.Base(entry.Path))
		closeErr := packageFile.Close()
		if inspectErr != nil || closeErr != nil {
			return manifest.Entry{}, errors.Join(inspectErr, closeErr)
		}
		if pkg.PoolPath != entry.Path || pkg.Size != entry.Size || pkg.SHA256 != entry.HashString() {
			return manifest.Entry{}, errors.New("DEB body identity, location, size, or checksum differs from indexed payload evidence")
		}
		return APTPackageBodyIdentityEntry(pkg.Name, pkg.Version, pkg.Architecture, component, pkg.PoolPath, pkg.Size, pkg.SHA256)
	})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "APT_PACKAGE_BODY_INVALID", Subject: c.CheckID, Message: "an indexed DEB body is unreadable, changed, or has invalid control identity"})
		return nil
	}
	defer joinVerificationCleanup(&resultErr, closeActual)
	comparison := ManifestComparisonCheck{CheckID: c.CheckID + "/body-identity", AtLayer: LayerL1, Subject: c.CheckID, Desired: FileStream(signedIdentities), Actual: FileStream(actual), CodePrefix: "APT_BODY_IDENTITY"}
	return comparison.Verify(ctx, recorder)
}

func verifyAPTManifestSubset(ctx context.Context, recorder *Recorder, checkID, expectedPath, actualPath string) error {
	expected, err := os.Open(expectedPath)
	if err != nil {
		return err
	}
	actual, err := os.Open(actualPath)
	if err != nil {
		_ = expected.Close()
		return err
	}
	_, diffErr := manifest.Diff(expected, actual, func(change manifest.Change) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		switch change.Kind {
		case manifest.Added:
			// A shared pool entry may be owned exclusively by an unselected
			// suite. Partial suite verification cannot classify it as orphaned.
			return nil
		case manifest.Removed:
			recorder.Add(Finding{Layer: LayerL1, Severity: SeverityError, Category: CategoryDrift, Code: "APT_POOL_MISSING", Subject: change.Path(), Message: "actual APT pool is missing a selected-suite path", Fields: []Field{{Key: "scope", Value: checkID}}})
		case manifest.Changed:
			recorder.Add(Finding{Layer: LayerL1, Severity: SeverityError, Category: CategoryDrift, Code: "APT_POOL_CHANGED", Subject: change.Path(), Message: "selected-suite APT pool entry differs", Fields: []Field{{Key: "scope", Value: checkID}}})
		}
		return nil
	})
	closeErr := errors.Join(expected.Close(), actual.Close())
	if diffErr != nil {
		if errors.Is(diffErr, context.Canceled) || errors.Is(diffErr, context.DeadlineExceeded) {
			return diffErr
		}
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "APT_POOL_INVALID", Subject: checkID, Message: "APT pool evidence is malformed or unreadable"})
	}
	if closeErr != nil {
		return errors.New("close APT pool evidence")
	}
	return nil
}

func (c APTCheck) verifySuite(ctx context.Context, recorder *Recorder, tempRoot string, global, identities, bodyIdentities *manifestSpool, suite string) error {
	base := path.Join("dists", suite)
	release, err := readRegularBelow(c.Root, path.Join(base, "Release"), aptSignatureLimit)
	if err != nil {
		return err
	}
	inRelease, err := readRegularBelow(c.Root, path.Join(base, "InRelease"), aptSignatureLimit)
	if err != nil {
		return err
	}
	detached, err := readRegularBelow(c.Root, path.Join(base, "Release.gpg"), aptSignatureLimit)
	if err != nil {
		return err
	}
	if err := c.Verifier.Verify(release, inRelease, detached, c.VerifyAt.UTC()); err != nil {
		recorder.Add(Finding{Layer: LayerL1, Severity: SeverityCritical, Category: CategoryIntegrity, Code: "APT_SIGNATURE_INVALID", Subject: suite, Message: "InRelease or Release.gpg does not verify against the exact Release bytes"})
		return errAPTFindingRecorded
	}
	document, err := parseAPTRelease(release)
	if err != nil {
		return err
	}
	if document.Fields["suite"] != suite || document.Fields["acquire-by-hash"] != "yes" {
		return errors.New("suite identity or Acquire-By-Hash contract mismatch")
	}
	components := strings.Fields(document.Fields["components"])
	architectures := strings.Fields(document.Fields["architectures"])
	if len(components) == 0 || len(architectures) == 0 || hasUnsafeOrDuplicate(components) || hasUnsafeOrDuplicate(architectures) {
		return errors.New("invalid component or architecture set")
	}
	if c.ExpectedSuiteComponents != nil {
		expected, exists := c.ExpectedSuiteComponents[suite]
		if !exists || len(expected) == 0 || hasUnsafeOrDuplicate(expected) {
			return errors.New("configured APT suite component contract is unavailable or invalid")
		}
		if !sameStrings(canonicalStrings(components), canonicalStrings(expected)) {
			recorder.Add(Finding{Layer: LayerL1, Severity: SeverityError, Category: CategoryDrift, Code: "APT_COMPONENT_SET_DRIFT", Subject: suite, Message: "signed APT component set differs from configured suite components", Fields: []Field{{Key: "actual", Value: strings.Join(canonicalStrings(components), ",")}, {Key: "expected", Value: strings.Join(canonicalStrings(expected), ",")}}})
			return errAPTFindingRecorded
		}
	}

	artifacts := make(map[string]aptReleaseArtifact, len(document.Artifacts))
	for _, artifact := range document.Artifacts {
		if _, exists := artifacts[artifact.Path]; exists {
			return errors.New("duplicate Release artifact")
		}
		artifacts[artifact.Path] = artifact
		actualHash, actualSize, err := hashRegularBelow(ctx, c.Root, path.Join(base, artifact.Path), c.metadataLimit())
		if err != nil || actualHash != artifact.SHA256 || actualSize != artifact.Size {
			return errors.New("Release artifact checksum mismatch")
		}
		byHash := path.Join(base, path.Dir(artifact.Path), "by-hash", "SHA256", artifact.SHA256)
		byHashValue, byHashSize, err := hashRegularBelow(ctx, c.Root, byHash, c.metadataLimit())
		if err != nil || byHashValue != artifact.SHA256 || byHashSize != artifact.Size {
			return errors.New("by-hash artifact checksum mismatch")
		}
	}

	for _, component := range components {
		if !safeSegment(component) {
			return errors.New("unsafe APT component")
		}
		for _, architecture := range architectures {
			if !aptArchName.MatchString(architecture) {
				return errors.New("unsafe APT architecture")
			}
			prefix := path.Join(component, "binary-"+architecture, "Packages")
			variants := []struct {
				path        string
				compression string
			}{{prefix, "plain"}, {prefix + ".gz", "gzip"}, {prefix + ".xz", "xz"}}
			var canonical string
			for index, variant := range variants {
				if _, ok := artifacts[variant.path]; !ok {
					return errors.New("Release lacks a required Packages variant")
				}
				var identityOutput *manifestSpool
				var bodyIdentityOutput *manifestSpool
				if index == 0 {
					identityOutput = identities
					bodyIdentityOutput = bodyIdentities
				}
				spool, err := c.parsePackages(ctx, tempRoot, path.Join(base, variant.path), suite, component, architecture, variant.compression, identityOutput, bodyIdentityOutput)
				if err != nil {
					return err
				}
				manifestPath, err := spool.Finish(ctx)
				if err != nil {
					_ = spool.Close()
					return err
				}
				if index == 0 {
					canonical = manifestPath
					if err := addManifestToSpool(global, manifestPath); err != nil {
						_ = spool.Close()
						return err
					}
				} else {
					equal, err := equalManifestFiles(canonical, manifestPath)
					if err != nil || !equal {
						_ = spool.Close()
						return errors.New("Packages compression variants have different contents")
					}
				}
				// Keep each small spool until this index group completes by copying
				// the canonical bytes when needed; the first spool stays alive until
				// every comparison finishes, while non-first spools can close now.
				if index != 0 {
					_ = spool.Close()
				}
				if index == len(variants)-1 {
					_ = os.RemoveAll(filepath.Dir(canonical))
				}
			}
		}
	}
	if len(artifacts) != len(components)*len(architectures)*3 {
		return errors.New("Release contains unsupported or unaccounted index artifacts")
	}
	return nil
}

func (c APTCheck) parsePackages(ctx context.Context, tempRoot, relative, suite, component, architecture, compression string, identities, bodyIdentities *manifestSpool) (*manifestSpool, error) {
	file, _, err := openRegularBelow(c.Root, relative, c.metadataLimit())
	if err != nil {
		return nil, err
	}
	var reader io.Reader = file
	var closer io.Closer
	switch compression {
	case "plain":
	case "gzip":
		gz, err := gzip.NewReader(file)
		if err != nil {
			_ = file.Close()
			return nil, err
		}
		reader, closer = gz, gz
	case "xz":
		xzReader, err := xz.NewReader(file)
		if err != nil {
			_ = file.Close()
			return nil, err
		}
		reader = xzReader
	default:
		_ = file.Close()
		return nil, errors.New("unsupported Packages compression")
	}
	spool, err := newManifestSpool(tempRoot, c.ChunkEntries)
	if err != nil {
		if closer != nil {
			_ = closer.Close()
		}
		_ = file.Close()
		return nil, err
	}
	parseErr := parsePackagesStreamWithIdentity(ctx, &maxBytesReader{reader: reader, remaining: c.metadataLimit()}, suite, component, architecture, spool, identities, bodyIdentities)
	if closer != nil {
		parseErr = errors.Join(parseErr, closer.Close())
	}
	parseErr = errors.Join(parseErr, file.Close())
	if parseErr != nil {
		_ = spool.Close()
		return nil, parseErr
	}
	return spool, nil
}

func (c APTCheck) metadataLimit() int64 {
	if c.MaxMetadataBytes <= 0 {
		return defaultAPTMetadataLimit
	}
	return c.MaxMetadataBytes
}

type aptReleaseArtifact struct {
	Path   string
	Size   int64
	SHA256 string
}

type aptReleaseDocument struct {
	Fields    map[string]string
	Artifacts []aptReleaseArtifact
}

func parseAPTRelease(data []byte) (aptReleaseDocument, error) {
	document := aptReleaseDocument{Fields: make(map[string]string)}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 64*1024), defaultAPTLineLimit)
	inSHA := false
	lastPath := ""
	for scanner.Scan() {
		line := scanner.Text()
		if strings.ContainsAny(line, "\x00\r") {
			return document, errors.New("unsafe Release line")
		}
		if strings.HasPrefix(line, " ") {
			if !inSHA {
				return document, errors.New("unexpected Release continuation")
			}
			fields := strings.Fields(line)
			if len(fields) != 3 || !lowerSHA256(fields[0]) || !safeRelative(fields[2]) || fields[2] <= lastPath {
				return document, errors.New("invalid or unsorted Release SHA256 entry")
			}
			size, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil || size < 0 {
				return document, errors.New("invalid Release artifact size")
			}
			document.Artifacts = append(document.Artifacts, aptReleaseArtifact{Path: fields[2], Size: size, SHA256: fields[0]})
			lastPath = fields[2]
			continue
		}
		inSHA = false
		name, value, ok := strings.Cut(line, ":")
		if !ok || name == "" || strings.TrimSpace(name) != name {
			return document, errors.New("malformed Release field")
		}
		key := strings.ToLower(name)
		if _, exists := document.Fields[key]; exists {
			return document, errors.New("duplicate Release field")
		}
		document.Fields[key] = strings.TrimSpace(value)
		if key == "sha256" {
			if document.Fields[key] != "" {
				return document, errors.New("SHA256 field must use continuation records")
			}
			inSHA = true
		}
	}
	if err := scanner.Err(); err != nil {
		return document, err
	}
	for _, required := range []string{"suite", "components", "architectures", "acquire-by-hash", "sha256"} {
		if _, ok := document.Fields[required]; !ok {
			return document, errors.New("Release lacks required field")
		}
	}
	if len(document.Artifacts) == 0 {
		return document, errors.New("Release has no SHA256 artifacts")
	}
	return document, nil
}

type aptPackageSample struct {
	Entry        manifest.Entry
	Name         string
	Version      string
	Architecture string
	Component    string
}

func parsePackagesStream(ctx context.Context, input io.Reader, component, architecture string, spool *manifestSpool) error {
	_, err := parsePackagesStreamDetailed(ctx, input, "identity-suite", component, architecture, spool, nil, nil)
	return err
}

func parsePackagesStreamWithSample(ctx context.Context, input io.Reader, component, architecture string, spool *manifestSpool) (aptPackageSample, error) {
	return parsePackagesStreamDetailed(ctx, input, "identity-suite", component, architecture, spool, nil, nil)
}

func parsePackagesStreamWithIdentity(ctx context.Context, input io.Reader, suite, component, architecture string, spool, identities, bodyIdentities *manifestSpool) error {
	_, err := parsePackagesStreamDetailed(ctx, input, suite, component, architecture, spool, identities, bodyIdentities)
	return err
}

func parsePackagesStreamDetailed(ctx context.Context, input io.Reader, suite, component, architecture string, spool, identities, bodyIdentities *manifestSpool) (aptPackageSample, error) {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64*1024), defaultAPTLineLimit)
	paragraph := make(map[string]string)
	seenFields := make(map[string]struct{})
	lastKey := ""
	var sample aptPackageSample
	flush := func() error {
		if len(seenFields) == 0 {
			return nil
		}
		entry, err := aptParagraphEntry(paragraph, component, architecture)
		if err != nil {
			return err
		}
		if err := spool.Add(entry); err != nil {
			return err
		}
		if identities != nil {
			identity, err := APTPackageIdentityEntry(suite, architecture, paragraph["package"], paragraph["version"], paragraph["architecture"], component,
				paragraph["filename"], entry.Size, entry.HashString())
			if err != nil {
				return err
			}
			if err := identities.Add(identity); err != nil {
				return err
			}
		}
		if bodyIdentities != nil {
			identity, err := APTPackageBodyIdentityEntry(paragraph["package"], paragraph["version"], paragraph["architecture"], component,
				paragraph["filename"], entry.Size, entry.HashString())
			if err != nil {
				return err
			}
			if err := bodyIdentities.Add(identity); err != nil {
				return err
			}
		}
		if sample.Name == "" {
			sample = aptPackageSample{Entry: entry, Name: paragraph["package"], Version: paragraph["version"], Architecture: paragraph["architecture"], Component: component}
		}
		paragraph = make(map[string]string)
		seenFields = make(map[string]struct{})
		lastKey = ""
		return nil
	}
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return sample, err
		}
		line := scanner.Text()
		if strings.ContainsAny(line, "\x00\r") {
			return sample, errors.New("unsafe Packages line")
		}
		if line == "" {
			if err := flush(); err != nil {
				return sample, err
			}
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if lastKey == "" {
				return sample, errors.New("orphan Packages continuation")
			}
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || name == "" || strings.TrimSpace(name) != name {
			return sample, errors.New("malformed Packages field")
		}
		key := strings.ToLower(name)
		if _, exists := seenFields[key]; exists {
			return sample, errors.New("duplicate case-insensitive Packages field")
		}
		if len(seenFields) >= 1024 {
			return sample, errors.New("Packages paragraph has too many fields")
		}
		seenFields[key] = struct{}{}
		switch key {
		case "package", "source", "version", "architecture", "filename", "size", "sha256":
			paragraph[key] = strings.TrimSpace(value)
		}
		lastKey = key
	}
	if err := scanner.Err(); err != nil {
		return sample, err
	}
	return sample, flush()
}

func aptParagraphEntry(fields map[string]string, component, architecture string) (manifest.Entry, error) {
	for _, required := range []string{"package", "version", "architecture", "filename", "size", "sha256"} {
		if fields[required] == "" {
			return manifest.Entry{}, errors.New("Packages paragraph lacks required field")
		}
	}
	if !aptPackageName.MatchString(fields["package"]) || !aptArchName.MatchString(fields["architecture"]) || fields["architecture"] != "all" && fields["architecture"] != architecture {
		return manifest.Entry{}, errors.New("Packages identity or architecture is invalid")
	}
	if _, err := debversion.Parse(fields["version"]); err != nil {
		return manifest.Entry{}, errors.New("Packages Version is invalid")
	}
	filename := fields["filename"]
	if !safeRelative(filename) || !strings.HasSuffix(filename, ".deb") || !strings.HasPrefix(filename, "pool/"+component+"/") {
		return manifest.Entry{}, errors.New("Packages Filename is unsafe or belongs to another component")
	}
	source := fields["source"]
	if source == "" {
		source = fields["package"]
	}
	if at := strings.IndexByte(source, ' '); at >= 0 {
		source = source[:at]
	}
	if !aptPackageName.MatchString(source) {
		return manifest.Entry{}, errors.New("Packages Source is invalid")
	}
	wanted, err := aptrepo.PoolPath(component, source, path.Base(filename))
	if err != nil || wanted != filename {
		return manifest.Entry{}, errors.New("Packages Filename is not the canonical pool path")
	}
	size, err := strconv.ParseInt(fields["size"], 10, 64)
	if err != nil || size < 0 || !lowerSHA256(fields["sha256"]) {
		return manifest.Entry{}, errors.New("Packages size or SHA256 is invalid")
	}
	decoded, _ := hex.DecodeString(fields["sha256"])
	var digest [sha256.Size]byte
	copy(digest[:], decoded)
	return manifest.Entry{Path: filename, Size: size, SHA256: digest}, nil
}

func addManifestToSpool(destination *manifestSpool, filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	reader := manifest.NewReader(f)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := destination.Add(entry); err != nil {
			return err
		}
	}
}

func equalManifestFiles(left, right string) (bool, error) {
	l, err := os.Open(left)
	if err != nil {
		return false, err
	}
	defer l.Close()
	r, err := os.Open(right)
	if err != nil {
		return false, err
	}
	defer r.Close()
	stats, err := manifest.Diff(l, r, nil)
	return err == nil && stats.Clean(), err
}

func discoverSuites(root string) ([]string, error) {
	dists := filepath.Join(root, "dists")
	if err := realDirectory(dists); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dists)
	if err != nil {
		return nil, err
	}
	suites := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !safeSegment(entry.Name()) {
			return nil, errors.New("unsafe suite")
		}
		info, err := os.Lstat(filepath.Join(dists, entry.Name()))
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, errors.New("suite is not a real directory")
		}
		suites = append(suites, entry.Name())
	}
	sort.Strings(suites)
	return suites, nil
}

func verificationTemp(base, prefix string) (string, bool, error) {
	if base != "" {
		if err := os.MkdirAll(base, 0o700); err != nil {
			return "", false, err
		}
	}
	dir, err := os.MkdirTemp(base, prefix)
	return dir, true, err
}

func canonicalStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	for index := 1; index < len(result); {
		if result[index] == result[index-1] {
			result = append(result[:index], result[index+1:]...)
			continue
		}
		index++
	}
	return result
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func hasUnsafeOrDuplicate(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !safeSegment(value) {
			return true
		}
		if _, ok := seen[value]; ok {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func lowerSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

type maxBytesReader struct {
	reader    io.Reader
	remaining int64
}

func (r *maxBytesReader) Read(buffer []byte) (int, error) {
	if r.remaining == 0 {
		var probe [1]byte
		n, err := r.reader.Read(probe[:])
		if n != 0 {
			return 0, errors.New("decompressed metadata exceeds configured limit")
		}
		return 0, err
	}
	if int64(len(buffer)) > r.remaining {
		buffer = buffer[:r.remaining]
	}
	n, err := r.reader.Read(buffer)
	r.remaining -= int64(n)
	return n, err
}
