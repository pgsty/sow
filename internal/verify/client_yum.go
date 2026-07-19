package verify

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/klauspost/compress/zstd"
	"github.com/pgsty/sow/internal/yumrepo"
)

const (
	clientRepomdLimit     = int64(4 << 20)
	clientMirrorlistLimit = int64(64 << 10)
	clientMetadataLimit   = int64(1 << 30)
	yumRepoNamespace      = "http://linux.duke.edu/metadata/repo"
)

// YUMProtocolProbe follows the dnf/rpm-md wire chain through its mirrorlist:
// mirror generation -> signed repomd pair -> three metadata streams -> RPM.
type YUMProtocolProbe struct {
	Client         *http.Client
	CDNBaseURL     string
	MirrorlistPath string
	// ExpectedGenerationURL is the exact canonical channel target committed in
	// the target generation. It is required in mirrorlist mode and includes the
	// selected public, Basic, or runtime-token route. A signed repository at a
	// different generation is authentic but is not evidence for this channel.
	ExpectedGenerationURL string
	// RepositoryPath selects an already pinned repository root, such as an
	// immutable snapshot route. Exactly one of MirrorlistPath and
	// RepositoryPath must be set.
	RepositoryPath   string
	Architecture     string
	Headers          http.Header
	Compression      yumrepo.Compression
	Verifier         yumrepo.DetachedVerifier
	PackageKeyring   openpgp.KeyRing
	VerifyAt         time.Time
	TempDir          string
	ChunkEntries     int
	MaxMetadataBytes int64
	MaxPackageBytes  int64
	AllowHTTP        bool
}

type clientRepomd struct {
	XMLName  xml.Name             `xml:"repomd"`
	Revision string               `xml:"revision"`
	Data     []clientRepomdRecord `xml:"data"`
}

type clientRepomdRecord struct {
	Type     string `xml:"type,attr"`
	Checksum struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	} `xml:"checksum"`
	OpenChecksum struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	} `xml:"open-checksum"`
	Location struct {
		Href string `xml:"href,attr"`
	} `xml:"location"`
	Size     int64 `xml:"size"`
	OpenSize int64 `xml:"open-size"`
}

func (p YUMProtocolProbe) Run(ctx context.Context) (ClientEvidence, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	mirrorlistMode := p.MirrorlistPath != "" && p.RepositoryPath == "" && safeRelative(p.MirrorlistPath)
	directMode := p.RepositoryPath != "" && p.MirrorlistPath == "" && safeRelative(p.RepositoryPath)
	if p.Verifier == nil || p.PackageKeyring == nil || p.VerifyAt.IsZero() || !mirrorlistMode && !directMode || !yumIdentitySegment.MatchString(p.Architecture) ||
		p.Compression != yumrepo.CompressionGzip && p.Compression != yumrepo.CompressionZstd {
		return ClientEvidence{}, fmt.Errorf("%w: invalid YUM probe configuration", ErrClientCoverage)
	}
	fetcher, err := newProtocolFetcher(p.CDNBaseURL, p.Client, p.Headers, p.AllowHTTP)
	if err != nil {
		return ClientEvidence{}, err
	}
	metadataLimit := p.MaxMetadataBytes
	if metadataLimit <= 0 {
		metadataLimit = clientMetadataLimit
	}
	packageLimit := p.MaxPackageBytes
	if packageLimit <= 0 {
		packageLimit = defaultClientPackageLimit
	}
	tempRoot, remove, err := verificationTemp(p.TempDir, "sow-client-yum-")
	if err != nil {
		return ClientEvidence{}, fmt.Errorf("%w: create YUM probe spool", ErrClientCoverage)
	}
	if remove {
		defer os.RemoveAll(tempRoot)
	}

	var generationURL *url.URL
	metadataObjects := int64(5)
	transcriptSummary := "snapshot-route->repomd+asc->primary+filelists+other->RPM"
	if mirrorlistMode {
		expectedGenerationURL, err := fetcher.absolute(p.ExpectedGenerationURL)
		if err != nil || expectedGenerationURL.String() != p.ExpectedGenerationURL || !strings.HasSuffix(expectedGenerationURL.Path, "/") {
			return ClientEvidence{}, fmt.Errorf("%w: invalid expected YUM generation route", ErrClientCoverage)
		}
		mirrorlist, err := fetcher.readRelative(ctx, p.MirrorlistPath, clientMirrorlistLimit)
		if err != nil {
			return ClientEvidence{}, err
		}
		generationURL, err = parseMirrorlistURL(fetcher, mirrorlist)
		if err != nil {
			return ClientEvidence{}, err
		}
		if generationURL.String() != expectedGenerationURL.String() {
			return ClientEvidence{}, fmt.Errorf("%w: mirrorlist generation route differs from the committed channel", ErrClientIntegrity)
		}
		metadataObjects = 6
		transcriptSummary = "mirrorlist->repomd+asc->primary+filelists+other->RPM"
	} else {
		generationURL, err = fetcher.resolve(p.RepositoryPath)
		if err != nil {
			return ClientEvidence{}, err
		}
	}
	repomdURL := appendProtocolURL(generationURL, "repodata/repomd.xml")
	signatureURL := appendProtocolURL(generationURL, "repodata/repomd.xml.asc")
	repomd, err := fetcher.readURL(ctx, repomdURL, clientRepomdLimit)
	if err != nil {
		return ClientEvidence{}, err
	}
	signature, err := fetcher.readURL(ctx, signatureURL, clientRepomdLimit)
	if err != nil {
		return ClientEvidence{}, err
	}
	if err := p.Verifier.Verify(ctx, bytes.NewReader(repomd), bytes.NewReader(signature)); err != nil {
		return ClientEvidence{}, fmt.Errorf("%w: repomd detached signature rejected", ErrClientIntegrity)
	}
	records, revision, err := parseClientRepomd(repomd, p.Compression, metadataLimit)
	if err != nil {
		return ClientEvidence{}, err
	}

	primaryPackages, err := newManifestSpool(tempRoot, p.ChunkEntries)
	if err != nil {
		return ClientEvidence{}, fmt.Errorf("%w: create YUM package spool", ErrClientCoverage)
	}
	defer primaryPackages.Close()
	primaryIDs, err := newManifestSpool(tempRoot, p.ChunkEntries)
	if err != nil {
		return ClientEvidence{}, fmt.Errorf("%w: create YUM identity spool", ErrClientCoverage)
	}
	defer primaryIDs.Close()
	var sample yumPackageSample
	var packageCount int64 = -1
	for _, kind := range []string{"primary", "filelists", "other"} {
		record := records[kind]
		artifactFile := filepath.Join(tempRoot, path.Base(record.Location.Href))
		if err := fetcher.downloadURL(ctx, appendProtocolURL(generationURL, record.Location.Href), artifactFile, record.Size, strings.TrimSpace(record.Checksum.Value), metadataLimit); err != nil {
			return ClientEvidence{}, err
		}
		reader, closeArtifact, err := openYUMClientArtifact(artifactFile, p.Compression)
		if err != nil {
			return ClientEvidence{}, fmt.Errorf("%w: decompress YUM %s", ErrClientIntegrity, kind)
		}
		digest := sha256.New()
		counter := &digestCounter{hash: digest}
		limited := &maxBytesReader{reader: reader, remaining: metadataLimit}
		stream := io.TeeReader(limited, counter)
		var count int64
		var parseErr error
		if kind == "primary" {
			sample, count, parseErr = parseYUMPrimaryWithSampleForArch(ctx, stream, primaryPackages, primaryIDs, p.Architecture)
		} else {
			secondary, spoolErr := newManifestSpool(tempRoot, p.ChunkEntries)
			if spoolErr != nil {
				_ = closeArtifact()
				return ClientEvidence{}, fmt.Errorf("%w: create YUM secondary spool", ErrClientCoverage)
			}
			count, parseErr = parseYUMSecondaryIdentities(ctx, stream, kind, secondary)
			if parseErr == nil {
				var primaryPath, secondaryPath string
				primaryPath, parseErr = primaryIDs.Finish(ctx)
				if parseErr == nil {
					secondaryPath, parseErr = secondary.Finish(ctx)
				}
				if parseErr == nil {
					var equal bool
					equal, parseErr = equalManifestFiles(primaryPath, secondaryPath)
					if parseErr == nil && !equal {
						parseErr = errors.New("YUM metadata package identities differ")
					}
				}
			}
			_ = secondary.Close()
		}
		parseErr = errors.Join(parseErr, closeArtifact())
		if parseErr != nil || counter.size != record.OpenSize || hex.EncodeToString(digest.Sum(nil)) != strings.TrimSpace(record.OpenChecksum.Value) {
			return ClientEvidence{}, fmt.Errorf("%w: YUM %s open metadata rejected", ErrClientIntegrity, kind)
		}
		if packageCount < 0 {
			packageCount = count
		} else if packageCount != count {
			return ClientEvidence{}, fmt.Errorf("%w: YUM metadata package counts differ", ErrClientIntegrity)
		}
	}
	if packageCount <= 0 || sample.Name == "" {
		return ClientEvidence{}, fmt.Errorf("%w: YUM metadata has no packages", ErrClientCoverage)
	}
	if _, err := primaryPackages.Finish(ctx); err != nil {
		return ClientEvidence{}, fmt.Errorf("%w: YUM primary package references conflict", ErrClientIntegrity)
	}

	packageDir := filepath.Join(tempRoot, "package")
	if err := os.Mkdir(packageDir, 0o700); err != nil {
		return ClientEvidence{}, fmt.Errorf("%w: create RPM spool", ErrClientCoverage)
	}
	packageFile := filepath.Join(packageDir, path.Base(sample.Entry.Path))
	if err := fetcher.downloadURL(ctx, appendProtocolURL(generationURL, sample.Entry.Path), packageFile, sample.Entry.Size, sample.Entry.HashString(), packageLimit); err != nil {
		return ClientEvidence{}, err
	}
	packageReader, err := os.Open(packageFile)
	if err != nil {
		return ClientEvidence{}, fmt.Errorf("%w: open downloaded RPM for package-signature verification", ErrClientCoverage)
	}
	_, signatureErr := yumrepo.VerifyEmbeddedRPMSignatures(ctx, packageReader, p.PackageKeyring, p.VerifyAt)
	closeErr := packageReader.Close()
	if signatureErr != nil || closeErr != nil {
		if errors.Is(signatureErr, context.Canceled) || errors.Is(signatureErr, context.DeadlineExceeded) {
			return ClientEvidence{}, signatureErr
		}
		return ClientEvidence{}, fmt.Errorf("%w: downloaded RPM package signature rejected", ErrClientIntegrity)
	}
	info, err := yumrepo.InspectPackage(ctx, yumrepo.PackageInput{Path: packageFile, Basename: path.Base(sample.Entry.Path)})
	if err != nil || !yumPackageMatchesAuthenticatedSample(info, sample) {
		return ClientEvidence{}, fmt.Errorf("%w: downloaded RPM does not match authenticated primary metadata", ErrClientIntegrity)
	}
	version := info.Version + "-" + info.Release
	if info.Epoch > 0 {
		version = strconv.FormatInt(info.Epoch, 10) + ":" + version
	}
	repomdDigest := sha256.Sum256(repomd)
	transcript := fmt.Sprintf("client=dnf\nprotocol=rpm-md-v1\narchitecture=%s\nrevision=%s\nrepomd_sha256=%s\npackage=%s\nversion=%s\npackage_sha256=%s\n",
		p.Architecture, revision, hex.EncodeToString(repomdDigest[:]), info.Name, version, info.SHA256)
	transcriptDigest := sha256.Sum256([]byte(transcript))
	return ClientEvidence{
		Client: "dnf", Protocol: "rpm-md-v1", Version: "sow-purego/1 (dnf4/5 rpm-md wire)",
		TranscriptSHA256: hex.EncodeToString(transcriptDigest[:]), TranscriptSummary: transcriptSummary,
		MetadataObjects: metadataObjects, InstalledObjects: 1, PackageName: info.Name, PackageVersion: version, PackageSHA256: info.SHA256,
	}, nil
}

func yumPackageMatchesAuthenticatedSample(info yumrepo.PackageInfo, sample yumPackageSample) bool {
	return info.Name == sample.Name && info.Arch == sample.Arch && info.Version == sample.Version && info.Release == sample.Release && info.Epoch == sample.Epoch &&
		info.Location == sample.Entry.Path && info.Size == sample.Entry.Size && info.SHA256 == sample.Entry.HashString()
}

func parseMirrorlistURL(fetcher *protocolFetcher, body []byte) (*url.URL, error) {
	var lines []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) != 1 || !strings.HasSuffix(lines[0], "/") {
		return nil, fmt.Errorf("%w: mirrorlist must contain one generation base URL", ErrClientIntegrity)
	}
	return fetcher.absolute(lines[0])
}

func appendProtocolURL(base *url.URL, relative string) *url.URL {
	result := *base
	result.Path = path.Join(base.Path, relative)
	result.RawPath = ""
	return &result
}

func parseClientRepomd(body []byte, compression yumrepo.Compression, maximum int64) (map[string]clientRepomdRecord, string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(body))
	decoder.Strict = true
	var document clientRepomd
	if err := decoder.Decode(&document); err != nil || document.XMLName.Space != yumRepoNamespace || document.XMLName.Local != "repomd" {
		return nil, "", fmt.Errorf("%w: malformed repomd.xml", ErrClientIntegrity)
	}
	if strings.Contains(string(body), "<!") {
		return nil, "", fmt.Errorf("%w: XML directives are forbidden", ErrClientIntegrity)
	}
	revision, err := strconv.ParseInt(strings.TrimSpace(document.Revision), 10, 64)
	if err != nil || revision < 0 || len(document.Data) != 3 {
		return nil, "", fmt.Errorf("%w: invalid repomd revision or record set", ErrClientIntegrity)
	}
	extension := ".gz"
	if compression == yumrepo.CompressionZstd {
		extension = ".zst"
	}
	result := make(map[string]clientRepomdRecord, 3)
	for _, record := range document.Data {
		checksum := strings.TrimSpace(record.Checksum.Value)
		openChecksum := strings.TrimSpace(record.OpenChecksum.Value)
		if (record.Type != "primary" && record.Type != "filelists" && record.Type != "other") || record.Checksum.Type != "sha256" || record.OpenChecksum.Type != "sha256" ||
			!lowerSHA256(checksum) || !lowerSHA256(openChecksum) || record.Size < 0 || record.Size > maximum || record.OpenSize < 0 || record.OpenSize > maximum ||
			record.Location.Href != "repodata/"+checksum+"-"+record.Type+".xml"+extension {
			return nil, "", fmt.Errorf("%w: invalid repomd data record", ErrClientIntegrity)
		}
		if _, duplicate := result[record.Type]; duplicate {
			return nil, "", fmt.Errorf("%w: duplicate repomd data record", ErrClientIntegrity)
		}
		result[record.Type] = record
	}
	return result, strings.TrimSpace(document.Revision), nil
}

func openYUMClientArtifact(filename string, compression yumrepo.Compression) (io.Reader, func() error, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}
	switch compression {
	case yumrepo.CompressionGzip:
		reader, err := gzip.NewReader(file)
		if err != nil {
			_ = file.Close()
			return nil, nil, err
		}
		return reader, func() error { return errors.Join(reader.Close(), file.Close()) }, nil
	case yumrepo.CompressionZstd:
		reader, err := zstd.NewReader(file, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(64<<20))
		if err != nil {
			_ = file.Close()
			return nil, nil, err
		}
		return reader, func() error { reader.Close(); return file.Close() }, nil
	default:
		_ = file.Close()
		return nil, nil, errors.New("unsupported YUM compression")
	}
}

type digestCounter struct {
	hash hash.Hash
	size int64
}

func (w *digestCounter) Write(data []byte) (int, error) {
	n, err := w.hash.Write(data)
	w.size += int64(n)
	return n, err
}
