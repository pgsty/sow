package verify

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/ulikunitz/xz"
)

const defaultClientPackageLimit = int64(8 << 30)

type APTInReleaseVerifier interface {
	VerifyInRelease([]byte, time.Time) ([]byte, error)
}

// APTProtocolProbe follows the authenticated apt wire chain through a CDN:
// InRelease -> Release SHA256 -> by-hash Packages -> DEB bytes/control.
type APTProtocolProbe struct {
	Client         *http.Client
	CDNBaseURL     string
	RepositoryPath string
	Suite          string
	Component      string
	// ExpectedComponents freezes the complete signed Release component set for
	// this suite. A nil value preserves the lower-level single-component probe
	// API, while production L4 callers always provide the suite's exact config
	// contract so an otherwise installable phantom component cannot hide.
	ExpectedComponents []string
	Architecture       string
	Headers            http.Header
	Verifier           APTInReleaseVerifier
	VerifyAt           time.Time
	TempDir            string
	ChunkEntries       int
	MaxMetadataBytes   int64
	MaxPackageBytes    int64
	AllowHTTP          bool
}

// APTRepositoryProbe applies apt's component search semantics without hiding
// integrity or transport failures. An empty component may fall through to the
// next configured component, but a malformed signed closure never does.
type APTRepositoryProbe struct {
	Components []APTProtocolProbe
}

func (p APTRepositoryProbe) Run(ctx context.Context) (ClientEvidence, error) {
	if len(p.Components) == 0 {
		return ClientEvidence{}, fmt.Errorf("%w: APT repository has no configured components", ErrClientCoverage)
	}
	for _, component := range p.Components {
		evidence, err := component.Run(ctx)
		if err == nil {
			return evidence, nil
		}
		if !errors.Is(err, ErrClientCoverage) {
			return ClientEvidence{}, err
		}
	}
	return ClientEvidence{}, fmt.Errorf("%w: APT repository components contain no installable package", ErrClientCoverage)
}

func (p APTProtocolProbe) Run(ctx context.Context) (ClientEvidence, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if p.Verifier == nil || p.VerifyAt.IsZero() || !safeRelative(p.RepositoryPath) || !safeSegment(p.Suite) || !safeSegment(p.Component) || !aptArchName.MatchString(p.Architecture) ||
		p.ExpectedComponents != nil && (len(p.ExpectedComponents) == 0 || hasUnsafeOrDuplicate(p.ExpectedComponents)) {
		return ClientEvidence{}, fmt.Errorf("%w: invalid APT probe configuration", ErrClientCoverage)
	}
	fetcher, err := newProtocolFetcher(p.CDNBaseURL, p.Client, p.Headers, p.AllowHTTP)
	if err != nil {
		return ClientEvidence{}, err
	}
	metadataLimit := p.MaxMetadataBytes
	if metadataLimit <= 0 {
		metadataLimit = defaultAPTMetadataLimit
	}
	packageLimit := p.MaxPackageBytes
	if packageLimit <= 0 {
		packageLimit = defaultClientPackageLimit
	}
	tempRoot, remove, err := verificationTemp(p.TempDir, "sow-client-apt-")
	if err != nil {
		return ClientEvidence{}, fmt.Errorf("%w: create APT probe spool", ErrClientCoverage)
	}
	if remove {
		defer os.RemoveAll(tempRoot)
	}

	inReleasePath := path.Join(p.RepositoryPath, "dists", p.Suite, "InRelease")
	inRelease, err := fetcher.readRelative(ctx, inReleasePath, aptSignatureLimit)
	if err != nil {
		return ClientEvidence{}, err
	}
	release, err := p.Verifier.VerifyInRelease(inRelease, p.VerifyAt.UTC())
	if err != nil {
		return ClientEvidence{}, fmt.Errorf("%w: APT InRelease signature rejected", ErrClientIntegrity)
	}
	document, err := parseAPTRelease(release)
	actualComponents := strings.Fields(document.Fields["components"])
	if err != nil || document.Fields["suite"] != p.Suite || document.Fields["acquire-by-hash"] != "yes" || !containsStringValue(actualComponents, p.Component) || !containsStringValue(strings.Fields(document.Fields["architectures"]), p.Architecture) {
		return ClientEvidence{}, fmt.Errorf("%w: APT Release contract rejected", ErrClientIntegrity)
	}
	if p.ExpectedComponents != nil && !sameStrings(canonicalStrings(actualComponents), canonicalStrings(p.ExpectedComponents)) {
		return ClientEvidence{}, fmt.Errorf("%w: APT Release component set differs from the configured suite contract", ErrClientIntegrity)
	}
	prefix := path.Join(p.Component, "binary-"+p.Architecture, "Packages")
	artifacts := make(map[string]aptReleaseArtifact, len(document.Artifacts))
	for _, artifact := range document.Artifacts {
		artifacts[artifact.Path] = artifact
	}
	variant := ""
	var artifact aptReleaseArtifact
	for _, candidate := range []string{prefix + ".xz", prefix + ".gz", prefix} {
		if value, exists := artifacts[candidate]; exists {
			variant, artifact = candidate, value
			break
		}
	}
	if variant == "" || artifact.Size > metadataLimit {
		return ClientEvidence{}, fmt.Errorf("%w: APT Release has no bounded Packages artifact", ErrClientCoverage)
	}
	byHash := path.Join(p.RepositoryPath, "dists", p.Suite, path.Dir(variant), "by-hash", "SHA256", artifact.SHA256)
	metadataFile := filepath.Join(tempRoot, "Packages"+path.Ext(variant))
	if err := fetcher.downloadRelative(ctx, byHash, metadataFile, artifact.Size, artifact.SHA256, metadataLimit); err != nil {
		return ClientEvidence{}, err
	}

	spool, err := newManifestSpool(tempRoot, p.ChunkEntries)
	if err != nil {
		return ClientEvidence{}, fmt.Errorf("%w: create APT Packages spool", ErrClientCoverage)
	}
	defer spool.Close()
	metadata, err := os.Open(metadataFile)
	if err != nil {
		return ClientEvidence{}, fmt.Errorf("%w: reopen APT Packages", ErrClientCoverage)
	}
	reader, closeCompression, err := aptClientMetadataReader(metadata, variant)
	if err != nil {
		_ = metadata.Close()
		return ClientEvidence{}, fmt.Errorf("%w: decompress APT Packages", ErrClientIntegrity)
	}
	sample, parseErr := parsePackagesStreamWithSample(ctx, &maxBytesReader{reader: reader, remaining: metadataLimit}, p.Component, p.Architecture, spool)
	parseErr = errors.Join(parseErr, closeCompression(), metadata.Close())
	if parseErr != nil {
		return ClientEvidence{}, fmt.Errorf("%w: parse APT Packages", ErrClientIntegrity)
	}
	if _, err := spool.Finish(ctx); err != nil {
		return ClientEvidence{}, fmt.Errorf("%w: APT Packages reference conflict", ErrClientIntegrity)
	}
	if sample.Name == "" {
		return ClientEvidence{}, fmt.Errorf("%w: APT Packages is empty", ErrClientCoverage)
	}

	packageDirectory := filepath.Join(tempRoot, "package")
	if err := os.Mkdir(packageDirectory, 0o700); err != nil {
		return ClientEvidence{}, fmt.Errorf("%w: create APT package spool", ErrClientCoverage)
	}
	packageFile := filepath.Join(packageDirectory, path.Base(sample.Entry.Path))
	if err := fetcher.downloadRelative(ctx, path.Join(p.RepositoryPath, sample.Entry.Path), packageFile, sample.Entry.Size, sample.Entry.HashString(), packageLimit); err != nil {
		return ClientEvidence{}, err
	}
	inspected, err := aptrepo.InspectPackage(ctx, packageFile, p.Component)
	if err != nil || inspected.PoolPath != sample.Entry.Path || inspected.Name != sample.Name || inspected.Version != sample.Version || inspected.Size != sample.Entry.Size || inspected.SHA256 != sample.Entry.HashString() || inspected.Architecture != "all" && inspected.Architecture != p.Architecture {
		return ClientEvidence{}, fmt.Errorf("%w: downloaded DEB does not match authenticated Packages metadata", ErrClientIntegrity)
	}
	releaseDigest := sha256.Sum256(release)
	transcript := fmt.Sprintf("client=apt\nprotocol=apt-by-hash-v1\nsuite=%s\nrelease_sha256=%s\npackages_sha256=%s\npackage=%s\nversion=%s\npackage_sha256=%s\n",
		p.Suite, hex.EncodeToString(releaseDigest[:]), artifact.SHA256, inspected.Name, inspected.Version, inspected.SHA256)
	transcriptDigest := sha256.Sum256([]byte(transcript))
	return ClientEvidence{
		Client: "apt", Protocol: "apt-by-hash-v1", Version: "sow-purego/1 (apt>=1.2 wire)",
		TranscriptSHA256: hex.EncodeToString(transcriptDigest[:]), TranscriptSummary: "InRelease->Release-SHA256->by-hash-Packages->DEB",
		MetadataObjects: 2, InstalledObjects: 1, PackageName: inspected.Name, PackageVersion: inspected.Version, PackageSHA256: inspected.SHA256,
	}, nil
}

func aptClientMetadataReader(file *os.File, variant string) (io.Reader, func() error, error) {
	switch {
	case strings.HasSuffix(variant, ".xz"):
		reader, err := (xz.ReaderConfig{DictCap: 64 << 20}).NewReader(file)
		return reader, func() error { return nil }, err
	case strings.HasSuffix(variant, ".gz"):
		reader, err := gzip.NewReader(file)
		if err != nil {
			return nil, func() error { return nil }, err
		}
		return reader, reader.Close, nil
	default:
		return file, func() error { return nil }, nil
	}
}

func containsStringValue(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
