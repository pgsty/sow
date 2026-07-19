package yumrepo

import (
	"bufio"
	"compress/gzip"
	"container/heap"
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

// ValidateDirectory cryptographically and structurally validates a complete
// repodata generation. It rejects extra sqlite/modulemd/zchunk files, unsafe
// hrefs, checksum or size drift, malformed XML/counts, and a bad detached
// signature. All package XML is decompressed and decoded as a bounded stream.
func ValidateDirectory(ctx context.Context, dir string, compression Compression, verifier DetachedVerifier) (*Generation, error) {
	return validateDirectory(ctx, dir, compression, verifier, false)
}

// ValidateFlatCompatibilityDirectory applies the same signed, exact-generation
// validation as ValidateDirectory, but requires every primary location href to
// be a single flat RPM basename. This mode exists only for admitting the frozen
// yum/infra/{arch} legacy URL contract; canonical SOW YUM repositories must
// continue to use ValidateDirectory and Packages/<bucket>/<basename> hrefs.
func ValidateFlatCompatibilityDirectory(ctx context.Context, dir string, compression Compression, verifier DetachedVerifier) (*Generation, error) {
	return validateDirectory(ctx, dir, compression, verifier, true)
}

func validateDirectory(ctx context.Context, dir string, compression Compression, verifier DetachedVerifier, flatCompatibility bool) (*Generation, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrInvalidRepodata)
	}
	if verifier == nil {
		return nil, fmt.Errorf("%w: detached verifier is required", ErrInvalidRepodata)
	}
	if compression != CompressionGzip && compression != CompressionZstd {
		return nil, fmt.Errorf("%w: unsupported compression %q", ErrInvalidRepodata, compression)
	}
	dir = filepath.Clean(dir)
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: stat %q: %v", ErrInvalidRepodata, dir, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %q is not a real directory", ErrInvalidRepodata, dir)
	}
	if err := verifyRepomdSignature(ctx, dir, verifier); err != nil {
		return nil, err
	}
	repomdBytes, err := readRegularFileLimited(filepath.Join(dir, "repomd.xml"), maxRepomdBytes)
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
	revision, err := strconv.ParseInt(strings.TrimSpace(document.Revision), 10, 64)
	if err != nil || revision < 0 {
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
	generation := &Generation{Dir: dir, Revision: revision, RepomdSHA256: hex.EncodeToString(repomdSum[:])}
	// Validation must never create scratch below a directly hosted repository
	// leaf. A private mode-0700 system temp directory keeps concurrent clients
	// from observing identity runs and allows read-only repository mounts.
	identityTemp, err := os.MkdirTemp("", "sow-yum-identity-")
	if err != nil {
		return nil, fmt.Errorf("%w: create package identity scratch: %v", ErrInvalidRepodata, err)
	}
	defer os.RemoveAll(identityTemp)
	var packageCount int64 = -1
	var identitySHA string
	for i, kind := range wantedOrder {
		record, ok := byType[kind]
		if !ok {
			return nil, fmt.Errorf("%w: missing %q record", ErrInvalidRepodata, kind)
		}
		artifact, count, identities, err := validateArtifact(ctx, dir, kind, record, compression, flatCompatibility, identityTemp)
		if err != nil {
			return nil, err
		}
		currentIdentitySHA, err := hashFileContext(ctx, identities)
		if err != nil {
			return nil, err
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
	generation.Packages = packageCount
	if err := rejectExtraGenerationFiles(dir, generation); err != nil {
		return nil, err
	}
	return generation, nil
}

func verifyRepomdSignature(ctx context.Context, dir string, verifier DetachedVerifier) error {
	messageInfo, err := os.Lstat(filepath.Join(dir, "repomd.xml"))
	if err != nil || !messageInfo.Mode().IsRegular() || messageInfo.Size() <= 0 || messageInfo.Size() > maxRepomdBytes {
		return fmt.Errorf("%w: invalid repomd.xml", ErrInvalidRepodata)
	}
	message, err := os.Open(filepath.Join(dir, "repomd.xml"))
	if err != nil {
		return fmt.Errorf("%w: open repomd.xml: %v", ErrInvalidRepodata, err)
	}
	defer message.Close()
	sigInfo, err := os.Lstat(filepath.Join(dir, "repomd.xml.asc"))
	if err != nil || !sigInfo.Mode().IsRegular() || sigInfo.Size() <= 0 || sigInfo.Size() > maxSignatureBytes {
		return fmt.Errorf("%w: invalid repomd.xml.asc", ErrInvalidRepodata)
	}
	signature, err := os.Open(filepath.Join(dir, "repomd.xml.asc"))
	if err != nil {
		return fmt.Errorf("%w: open repomd.xml.asc: %v", ErrInvalidRepodata, err)
	}
	defer signature.Close()
	if err := verifier.Verify(ctx, io.LimitReader(message, maxRepomdBytes+1), io.LimitReader(signature, maxSignatureBytes+1)); err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureValidation, err)
	}
	return nil
}

func validateArtifact(ctx context.Context, dir, kind string, record repomdRecord, compression Compression, flatCompatibility bool, identityTemp string) (Artifact, int64, string, error) {
	if record.Checksum.Type != "sha256" || record.OpenChecksum.Type != "sha256" ||
		!validSHA256(record.Checksum.Value) || !validSHA256(record.OpenChecksum.Value) {
		return Artifact{}, 0, "", fmt.Errorf("%w: %s requires SHA256 checksums", ErrInvalidRepodata, kind)
	}
	extension := ".gz"
	if compression == CompressionZstd {
		extension = ".zst"
	}
	wantBase := record.Checksum.Value + "-" + kind + ".xml" + extension
	wantHref := "repodata/" + wantBase
	if record.Location.Href != wantHref || path.Clean(record.Location.Href) != record.Location.Href ||
		strings.Contains(record.Location.Href, "\\") {
		return Artifact{}, 0, "", fmt.Errorf("%w: unsafe or non-canonical %s href %q", ErrInvalidRepodata, kind, record.Location.Href)
	}
	filename := filepath.Join(dir, wantBase)
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() {
		return Artifact{}, 0, "", fmt.Errorf("%w: missing regular artifact %q", ErrInvalidRepodata, wantBase)
	}
	if info.Size() != record.Size || record.Size < 0 || record.OpenSize < 0 || record.Timestamp < 0 {
		return Artifact{}, 0, "", fmt.Errorf("%w: invalid %s size/timestamp", ErrInvalidRepodata, kind)
	}
	compressedSHA, err := hashFileContext(ctx, filename)
	if err != nil {
		return Artifact{}, 0, "", err
	}
	if compressedSHA != record.Checksum.Value {
		return Artifact{}, 0, "", fmt.Errorf("%w: %s compressed checksum mismatch", ErrInvalidRepodata, kind)
	}
	openSHA, openSize, count, identities, err := validateOpenXML(ctx, filename, kind, compression, flatCompatibility, identityTemp)
	if err != nil {
		return Artifact{}, 0, "", err
	}
	if openSHA != record.OpenChecksum.Value || openSize != record.OpenSize {
		return Artifact{}, 0, "", fmt.Errorf("%w: %s open checksum/size mismatch", ErrInvalidRepodata, kind)
	}
	return Artifact{
		Type: kind, Path: wantHref, SHA256: record.Checksum.Value,
		OpenSHA256: record.OpenChecksum.Value, Size: record.Size, OpenSize: record.OpenSize,
		Timestamp: record.Timestamp, Packages: count, Compression: compression,
	}, count, identities, nil
}

func validateOpenXML(ctx context.Context, filename, kind string, compression Compression, flatCompatibility bool, identityTemp string) (string, int64, int64, string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", 0, 0, "", err
	}
	defer f.Close()
	var reader io.Reader
	var closer io.Closer
	switch compression {
	case CompressionGzip:
		gz, err := gzip.NewReader(f)
		if err != nil {
			return "", 0, 0, "", fmt.Errorf("%w: open gzip %s: %v", ErrInvalidRepodata, kind, err)
		}
		reader, closer = gz, gz
	case CompressionZstd:
		zr, err := zstd.NewReader(f, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(64<<20))
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
	spool := newMetadataIdentitySpool(ctx, identityTemp, kind)
	count, err := validateMetadataXMLMode(tee, kind, flatCompatibility, spool)
	if err != nil {
		spool.Close()
		return "", 0, 0, "", err
	}
	identities, err := spool.Finish()
	if err != nil {
		return "", 0, 0, "", err
	}
	return hex.EncodeToString(h.Sum(nil)), counter.n, count, identities, nil
}

func validateMetadataXML(reader io.Reader, kind string) (int64, error) {
	return validateMetadataXMLMode(reader, kind, false, nil)
}

func validateMetadataXMLMode(reader io.Reader, kind string, flatCompatibility bool, identities *metadataIdentitySpool) (int64, error) {
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
	var capturePackageName, capturePackageIdentity, packageLocationSeen bool
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
				packageLocationSeen = false
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
				if err := validatePackageHrefForMode(packageName.String(), href, flatCompatibility); err != nil {
					return 0, err
				}
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
			if kind == "primary" && depth == 2 && value.Name.Space == commonNS && value.Name.Local == "package" && !packageLocationSeen {
				return 0, fmt.Errorf("%w: primary package %q lacks location", ErrInvalidRepodata, packageName.String())
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
	if err := s.flush(); err != nil {
		return "", err
	}
	s.done = true
	outputName := filepath.Join(s.root, s.kind+".identities")
	output, err := os.OpenFile(outputName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	committed := false
	defer func() {
		_ = output.Close()
		if !committed {
			_ = os.Remove(outputName)
		}
	}()
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
	writer := bufio.NewWriterSize(output, 128*1024)
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
	if err := errors.Join(output.Sync(), output.Close()); err != nil {
		return "", err
	}
	committed = true
	return outputName, nil
}

func (s *metadataIdentitySpool) Close() {
	if s != nil {
		s.done = true
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

func rejectExtraGenerationFiles(dir string, generation *Generation) error {
	wanted := map[string]struct{}{"repomd.xml": {}, "repomd.xml.asc": {}}
	for _, artifact := range generation.Artifacts {
		wanted[strings.TrimPrefix(artifact.Path, "repodata/")] = struct{}{}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) != len(wanted) {
		return fmt.Errorf("%w: generation contains extra or missing files", ErrInvalidRepodata)
	}
	for _, entry := range entries {
		if _, ok := wanted[entry.Name()]; !ok || entry.IsDir() {
			return fmt.Errorf("%w: unexpected generation entry %q", ErrInvalidRepodata, entry.Name())
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

func readRegularFileLimited(filename string, limit int64) ([]byte, error) {
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
		return nil, fmt.Errorf("%w: invalid regular file %q", ErrInvalidRepodata, filepath.Base(filename))
	}
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: file %q exceeds size limit", ErrInvalidRepodata, filepath.Base(filename))
	}
	return data, nil
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
