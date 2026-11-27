package aptrepo

import (
	"archive/tar"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/klauspost/compress/zstd"
	"github.com/pgsty/sow/internal/workmetrics"
	"github.com/xi2/xz"
	"pault.ag/go/debian/control"
	"pault.ag/go/debian/dependency"
	"pault.ag/go/debian/version"
)

var (
	debianNamePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)
	componentPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)
	architecturePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	sha256Pattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

const PackageFactsSchema = "aptrepo/package-facts/v1"

const (
	maxDebArMembers         = 128
	maxDebControlCompressed = int64(32 << 20)
	maxDebControlExpanded   = int64(128 << 20)
	maxDebControlFile       = int64(16 << 20)
	maxDebControlMembers    = 4096
	maxDebDecoderMemory     = uint64(64 << 20)
)

// Package is the metadata SOW needs from an existing Debian binary package.
// The original control paragraph is retained internally so Packages output
// preserves every field parsed by pault.ag/go/debian, including fields unknown
// to this package.
type Package struct {
	Name         string
	Source       string
	Version      string
	Architecture string
	Component    string
	SourcePath   string
	PoolPath     string
	Size         int64
	SHA256       string

	debianVersion version.Version
	paragraph     control.Paragraph
}

// InspectPackage parses an existing package using its current basename.
func InspectPackage(ctx context.Context, filePath, component string) (Package, error) {
	return InspectPackageAs(ctx, filePath, component, filepath.Base(filePath))
}

// ControlValue returns one parsed binary control field without exposing the
// mutable paragraph used to produce Packages.
func (p Package) ControlValue(name string) (string, bool) {
	v, ok := p.paragraph.Values[name]
	return v, ok
}

// InspectFlatPackage performs the single full-file hash used by Plain create.
// It parses control metadata from the same descriptor and relies on the
// caller's final stat snapshot check instead of rehashing the entire payload.
func InspectFlatPackage(ctx context.Context, filePath, component string) (Package, error) {
	return inspectPackagePath(ctx, filePath, component, filepath.Base(filePath), true)
}

// InspectPackageAs parses an existing package using an explicit public
// basename. Managed CAS readers use the descriptor-based facts API instead.
func InspectPackageAs(ctx context.Context, filePath, component, originalBasename string) (Package, error) {
	return inspectPackagePath(ctx, filePath, component, originalBasename, false)
}

func inspectPackagePath(ctx context.Context, filePath, component, originalBasename string, singlePass bool) (Package, error) {
	if ctx == nil {
		return Package{}, errors.New("aptrepo: nil context")
	}
	if err := ctx.Err(); err != nil {
		return Package{}, err
	}
	if err := validateComponent(component); err != nil {
		return Package{}, err
	}
	f, err := os.OpenFile(filePath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return Package{}, fmt.Errorf("aptrepo: open deb: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return Package{}, fmt.Errorf("aptrepo: stat deb: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Package{}, errors.New("aptrepo: deb input is not a regular file")
	}
	var pkg Package
	if singlePass {
		pkg, err = inspectPackageReaderAs(ctx, f, component, originalBasename, false)
	} else {
		pkg, err = InspectPackageReaderAs(ctx, f, component, originalBasename)
	}
	if err != nil {
		return Package{}, err
	}
	if err := f.Close(); err != nil {
		return Package{}, fmt.Errorf("aptrepo: close deb: %w", err)
	}
	closed = true
	pkg.SourcePath = filePath
	return pkg, nil
}

// PackageReader is the caller-owned descriptor surface needed by Debian's ar
// parser plus deterministic hashing.
type PackageReader interface {
	io.Reader
	io.ReaderAt
	io.Seeker
}

// UnverifiedPackageCoordinate is a routing hint read from bounded ar/control
// metadata. It proves neither the identity nor the contents of the package.
// In particular it must never be persisted as authenticated package facts.
type UnverifiedPackageCoordinate struct {
	Name, Source, Version, Architecture string
}

// ProbePackageCoordinateReader reads no package payload hash. The caller must
// keep the same descriptor, bind its complete identity before this call, and
// authenticate all bytes before using any metadata to accept the package.
func ProbePackageCoordinateReader(ctx context.Context, reader PackageReader, component, originalBasename string, size int64) (UnverifiedPackageCoordinate, error) {
	if size < 0 {
		return UnverifiedPackageCoordinate{}, errors.New("aptrepo: invalid provisional deb size")
	}
	pkg, err := parsePackageReaderAs(ctx, reader, component, originalBasename, "", size)
	if err != nil {
		return UnverifiedPackageCoordinate{}, err
	}
	return UnverifiedPackageCoordinate{Name: pkg.Name, Source: pkg.Source, Version: pkg.Version, Architecture: pkg.Architecture}, nil
}

// InspectPackageReaderAs parses and hashes one Debian package through a
// caller-owned seekable descriptor. The caller is responsible for binding the
// descriptor to the intended path/inode and for closing it. The reader is
// rewound and hashed both before and after control parsing so the returned
// identity and digest always describe the same bytes.
func InspectPackageReaderAs(ctx context.Context, reader PackageReader, component, originalBasename string) (Package, error) {
	return inspectPackageReaderAs(ctx, reader, component, originalBasename, true)
}

// InspectPackageReaderKnown parses control metadata after the caller has
// already copied and SHA-256-authenticated the complete descriptor. Only the
// bounded ar/control members are read; the package payload is not rehashed.
func InspectPackageReaderKnown(ctx context.Context, reader PackageReader, component, originalBasename, digest string, size int64) (Package, error) {
	if !sha256Pattern.MatchString(digest) || size < 0 {
		return Package{}, errors.New("aptrepo: invalid known deb identity")
	}
	return parsePackageReaderAs(ctx, reader, component, originalBasename, digest, size)
}

func inspectPackageReaderAs(ctx context.Context, reader PackageReader, component, originalBasename string, rehash bool) (Package, error) {
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return Package{}, fmt.Errorf("aptrepo: rewind deb before hashing: %w", err)
	}
	initialDigest, initialSize, err := hashReader(ctx, reader)
	if err != nil {
		return Package{}, fmt.Errorf("aptrepo: hash deb before parsing: %w", err)
	}
	workmetrics.RecordFullPackageRead(ctx, initialSize)
	pkg, err := parsePackageReaderAs(ctx, reader, component, originalBasename, initialDigest, initialSize)
	if err != nil {
		return Package{}, err
	}
	if rehash {
		if _, err := reader.Seek(0, io.SeekStart); err != nil {
			return Package{}, fmt.Errorf("aptrepo: rewind deb for hashing: %w", err)
		}
		digest, size, err := hashReader(ctx, reader)
		if err != nil {
			return Package{}, fmt.Errorf("aptrepo: hash deb: %w", err)
		}
		workmetrics.RecordFullPackageRead(ctx, size)
		if initialDigest != digest || initialSize != size {
			return Package{}, errors.New("aptrepo: deb changed while being inspected")
		}
	}

	return pkg, nil
}

func parsePackageReaderAs(ctx context.Context, reader PackageReader, component, originalBasename, digest string, size int64) (Package, error) {
	if ctx == nil {
		return Package{}, errors.New("aptrepo: nil context")
	}
	if err := ctx.Err(); err != nil {
		return Package{}, err
	}
	if reader == nil {
		return Package{}, errors.New("aptrepo: nil deb reader")
	}
	if err := validateComponent(component); err != nil {
		return Package{}, err
	}
	base := originalBasename
	if filepath.Base(base) != base || !safeDebBasename(base) {
		return Package{}, fmt.Errorf("aptrepo: unsafe deb filename %q", base)
	}
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return Package{}, fmt.Errorf("aptrepo: rewind deb for parsing: %w", err)
	}
	debianControl, err := loadDebControl(ctx, reader, size)
	if err != nil {
		return Package{}, fmt.Errorf("aptrepo: parse deb control: %w", err)
	}
	name := strings.TrimSpace(debianControl.Package)
	source := sourcePackageName(debianControl.Source, name)
	arch := debianControl.Architecture.String()
	if !debianNamePattern.MatchString(name) {
		return Package{}, fmt.Errorf("aptrepo: unsafe package name %q", name)
	}
	if !debianNamePattern.MatchString(source) {
		return Package{}, fmt.Errorf("aptrepo: unsafe source package name %q", source)
	}
	if !architecturePattern.MatchString(arch) {
		return Package{}, fmt.Errorf("aptrepo: unsafe architecture %q", arch)
	}
	poolPath, err := PoolPath(component, source, base)
	if err != nil {
		return Package{}, err
	}
	return Package{
		Name:          name,
		Source:        source,
		Version:       debianControl.Version.String(),
		Architecture:  arch,
		Component:     component,
		SourcePath:    "",
		PoolPath:      poolPath,
		Size:          size,
		SHA256:        digest,
		debianVersion: debianControl.Version,
		paragraph:     cloneParagraph(debianControl.Paragraph),
	}, nil
}

type packageFactsEnvelope struct {
	Schema       string            `json:"schema"`
	Name         string            `json:"name"`
	Source       string            `json:"source"`
	Version      string            `json:"version"`
	Architecture string            `json:"architecture"`
	Component    string            `json:"component"`
	PoolPath     string            `json:"pool_path"`
	Size         int64             `json:"size"`
	SHA256       string            `json:"sha256"`
	Order        []string          `json:"control_order"`
	Values       map[string]string `json:"control_values"`
}

func MarshalPackageFacts(pkg Package) ([]byte, error) {
	validated := pkg
	if validated.SourcePath == "" {
		validated.SourcePath = "facts"
	}
	if err := validatePackageMetadata(validated); err != nil {
		return nil, err
	}
	facts := packageFactsEnvelope{
		Schema: PackageFactsSchema, Name: pkg.Name, Source: pkg.Source, Version: pkg.Version,
		Architecture: pkg.Architecture, Component: pkg.Component, PoolPath: pkg.PoolPath,
		Size: pkg.Size, SHA256: pkg.SHA256, Order: append([]string(nil), pkg.paragraph.Order...),
		Values: cloneParagraph(pkg.paragraph).Values,
	}
	return json.Marshal(facts)
}

func PackageFromFacts(data []byte, sourcePath string) (Package, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var facts packageFactsEnvelope
	if err := decoder.Decode(&facts); err != nil {
		return Package{}, fmt.Errorf("aptrepo: decode package facts: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Package{}, errors.New("aptrepo: package facts contain trailing data")
	}
	if facts.Schema != PackageFactsSchema || sourcePath == "" {
		return Package{}, errors.New("aptrepo: unsupported package facts")
	}
	parsedVersion, err := version.Parse(facts.Version)
	if err != nil {
		return Package{}, fmt.Errorf("aptrepo: invalid package facts version: %w", err)
	}
	pkg := Package{
		Name: facts.Name, Source: facts.Source, Version: facts.Version, Architecture: facts.Architecture,
		Component: facts.Component, SourcePath: sourcePath, PoolPath: facts.PoolPath, Size: facts.Size, SHA256: facts.SHA256,
		debianVersion: parsedVersion,
		paragraph:     control.Paragraph{Order: append([]string(nil), facts.Order...), Values: make(map[string]string, len(facts.Values))},
	}
	for key, value := range facts.Values {
		pkg.paragraph.Values[key] = value
	}
	if err := validatePackageMetadata(pkg); err != nil {
		return Package{}, fmt.Errorf("aptrepo: invalid package facts: %w", err)
	}
	return pkg, nil
}

type debBinaryControl struct {
	control.Paragraph

	Package       string `required:"true"`
	Source        string
	Version       version.Version `required:"true"`
	Architecture  dependency.Arch `required:"true"`
	Maintainer    string
	InstalledSize int    `control:"Installed-Size"`
	MultiArch     string `control:"Multi-Arch"`
	Depends       dependency.Dependency
	Recommends    dependency.Dependency
	Suggests      dependency.Dependency
	Breaks        dependency.Dependency
	Replaces      dependency.Dependency
	BuiltUsing    dependency.Dependency `control:"Built-Using"`
	Section       string
	Priority      string
	Homepage      string
	Description   string
}

type debArEntry struct {
	Name string
	Size int64
	Data *io.SectionReader
}

func loadDebControl(ctx context.Context, reader io.ReaderAt, size int64) (debBinaryControl, error) {
	controlMember, err := scanDebArMembers(ctx, reader, size)
	if err != nil {
		return debBinaryControl{}, err
	}
	return loadDebControlArchive(ctx, controlMember)
}

func scanDebArMembers(ctx context.Context, reader io.ReaderAt, size int64) (*debArEntry, error) {
	if size < 8 {
		return nil, errors.New("truncated ar archive")
	}
	magic := make([]byte, 8)
	if _, err := reader.ReadAt(magic, 0); err != nil || string(magic) != "!<arch>\n" {
		return nil, errors.Join(err, errors.New("invalid ar archive header"))
	}
	var versionSeen bool
	var dataSeen bool
	var controlMember *debArEntry
	offset := int64(8)
	for count := 0; offset < size; count++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if count >= maxDebArMembers {
			return nil, fmt.Errorf("ar archive exceeds %d members", maxDebArMembers)
		}
		if size-offset < 60 {
			return nil, errors.New("truncated ar member header")
		}
		header := make([]byte, 60)
		if _, err := reader.ReadAt(header, offset); err != nil {
			return nil, err
		}
		if header[58] != '`' || header[59] != '\n' {
			return nil, errors.New("malformed ar member header terminator")
		}
		memberSize, err := strconv.ParseInt(strings.TrimSpace(string(header[48:58])), 10, 64)
		if err != nil || memberSize < 0 {
			return nil, fmt.Errorf("invalid ar member size %q", strings.TrimSpace(string(header[48:58])))
		}
		dataOffset := offset + 60
		if memberSize > size-dataOffset {
			return nil, errors.New("ar member extends beyond package")
		}
		memberName := strings.TrimSuffix(strings.TrimSpace(string(header[0:16])), "/")
		memberData := io.NewSectionReader(reader, dataOffset, memberSize)
		switch {
		case memberName == "debian-binary":
			if versionSeen {
				return nil, errors.New("duplicate debian-binary member")
			}
			versionSeen = true
			if memberSize == 0 || memberSize > 64 {
				return nil, fmt.Errorf("unexpected debian-binary size %d", memberSize)
			}
			versionBytes, err := io.ReadAll(memberData)
			if err != nil {
				return nil, err
			}
			if !strings.HasPrefix(strings.TrimSpace(string(versionBytes)), "2.") {
				return nil, fmt.Errorf("unsupported debian binary version %q", versionBytes)
			}
		case memberName == "control.tar" || strings.HasPrefix(memberName, "control.tar."):
			if controlMember != nil {
				return nil, errors.New("duplicate control archive member")
			}
			if memberSize <= 0 || memberSize > maxDebControlCompressed {
				return nil, fmt.Errorf("control archive compressed size %d exceeds limit", memberSize)
			}
			controlMember = &debArEntry{Name: memberName, Size: memberSize, Data: memberData}
		case memberName == "data.tar" || strings.HasPrefix(memberName, "data.tar."):
			if dataSeen {
				return nil, errors.New("duplicate data archive member")
			}
			if memberSize == 0 {
				return nil, errors.New("empty data archive member")
			}
			dataSeen = true
		}
		offset = dataOffset + memberSize
		if memberSize&1 != 0 {
			if offset >= size {
				return nil, errors.New("ar member is missing alignment padding")
			}
			offset++
		}
	}
	if offset != size {
		return nil, errors.New("ar archive length is inconsistent")
	}
	if !versionSeen {
		return nil, errors.New("missing debian-binary member")
	}
	if controlMember == nil {
		return nil, errors.New("missing control archive member")
	}
	if !dataSeen {
		return nil, errors.New("missing data archive member")
	}
	return controlMember, nil
}

func loadDebControlArchive(ctx context.Context, member *debArEntry) (parsed debBinaryControl, resultErr error) {
	stream, err := openDebControlStream(ctx, member)
	if err != nil {
		return debBinaryControl{}, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, stream.Close())
	}()
	const maxDebControlTarOverhead = 4 << 20
	limitedStream := &io.LimitedReader{R: stream, N: maxDebControlExpanded + maxDebControlTarOverhead + 1}
	archive := tar.NewReader(limitedStream)
	found := false
	expanded := int64(0)
	for members := 0; ; members++ {
		if err := ctx.Err(); err != nil {
			return debBinaryControl{}, err
		}
		if members >= maxDebControlMembers {
			return debBinaryControl{}, fmt.Errorf("control archive exceeds %d members", maxDebControlMembers)
		}
		header, err := archive.Next()
		if limitedStream.N == 0 {
			return debBinaryControl{}, fmt.Errorf("control archive expands beyond %d bytes", maxDebControlExpanded)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return debBinaryControl{}, err
		}
		if header.Size < 0 || header.Size > maxDebControlExpanded-expanded {
			return debBinaryControl{}, fmt.Errorf("control archive expands beyond %d bytes", maxDebControlExpanded)
		}
		expanded += header.Size
		if path.Clean(header.Name) != "control" {
			continue
		}
		if found {
			return debBinaryControl{}, errors.New("duplicate control file in control archive")
		}
		// Some historical control archives encode a regular file with the
		// original NUL typeflag. Keep accepting that wire value without relying
		// on archive/tar's deprecated TypeRegA alias.
		if header.Typeflag != tar.TypeReg && header.Typeflag != byte(0) {
			return debBinaryControl{}, errors.New("control file in control archive is not regular")
		}
		if header.Size > maxDebControlFile {
			return debBinaryControl{}, fmt.Errorf("control file exceeds %d bytes", maxDebControlFile)
		}
		limited := &io.LimitedReader{R: archive, N: maxDebControlFile + 1}
		body, err := io.ReadAll(limited)
		if err != nil {
			return debBinaryControl{}, err
		}
		if int64(len(body)) != header.Size || limited.N == 0 {
			return debBinaryControl{}, fmt.Errorf("control file exceeds %d bytes or is truncated", maxDebControlFile)
		}
		if !utf8.Valid(body) {
			var normalized bytes.Buffer
			for _, b := range body {
				normalized.WriteRune(rune(b))
			}
			body = normalized.Bytes()
		}
		if err := validateBinaryControlDocument(body); err != nil {
			return debBinaryControl{}, err
		}
		if err := control.Unmarshal(&parsed, bytes.NewReader(body)); err != nil {
			return debBinaryControl{}, err
		}
		if len(parsed.Paragraph.Order) > 1 {
			dedup := make([]string, 0, len(parsed.Paragraph.Order))
			seenOrder := make(map[string]struct{}, len(parsed.Paragraph.Order))
			for _, field := range parsed.Paragraph.Order {
				if _, ok := seenOrder[field]; ok {
					continue
				}
				seenOrder[field] = struct{}{}
				dedup = append(dedup, field)
			}
			parsed.Paragraph.Order = dedup
		}
		found = true
	}
	if !found {
		return debBinaryControl{}, errors.New("missing control file in control archive")
	}
	return parsed, nil
}

func validateBinaryControlDocument(body []byte) error {
	if len(body) == 0 {
		return errors.New("empty binary control paragraph")
	}
	type controlField struct {
		rawName string
		lines   []string
	}
	seen := make(map[string]controlField)
	var currentKey string
	var currentRawName string
	var currentLines []string
	flushCurrent := func(lineNo int) error {
		if currentKey == "" {
			return nil
		}
		if prev, duplicate := seen[currentKey]; duplicate {
			if prev.rawName != currentRawName || !sameStrings(prev.lines, currentLines) {
				return fmt.Errorf("binary control line %d repeats field %q", lineNo, currentRawName)
			}
		} else {
			seen[currentKey] = controlField{rawName: currentRawName, lines: append([]string(nil), currentLines...)}
		}
		currentKey = ""
		currentRawName = ""
		currentLines = nil
		return nil
	}
	haveField, haveCurrentField, paragraphEnded := false, false, false
	lines := bytes.Split(body, []byte{'\n'})
	for index, raw := range lines {
		line := raw
		if len(line) != 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		for _, value := range line {
			// Permit printable US-ASCII, HTAB, and legacy 8-bit Latin-1 bytes
			// (>= 0x80), while rejecting NUL and ASCII control characters.
			if (value < 0x20 && value != '\t') || value == 0x7f {
				return fmt.Errorf("binary control line %d contains a forbidden control byte", index+1)
			}
		}
		if len(line) == 0 {
			if !haveField {
				continue
			}
			if err := flushCurrent(index + 1); err != nil {
				return err
			}
			paragraphEnded = true
			haveCurrentField = false
			continue
		}
		if paragraphEnded {
			return fmt.Errorf("binary control contains more than one paragraph at line %d", index+1)
		}
		if line[0] == ' ' || line[0] == '\t' {
			if !haveCurrentField {
				return fmt.Errorf("binary control line %d has an orphan continuation", index+1)
			}
			currentLines = append(currentLines, string(line))
			continue
		}
		if err := flushCurrent(index + 1); err != nil {
			return err
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 || !validBinaryControlFieldName(line[:colon]) {
			return fmt.Errorf("binary control line %d has an invalid field name", index+1)
		}
		currentRawName = string(line[:colon])
		currentKey = strings.ToLower(currentRawName)
		currentLines = []string{strings.TrimSpace(string(line[colon+1:]))}
		haveField, haveCurrentField = true, true
	}
	if err := flushCurrent(len(lines)); err != nil {
		return err
	}
	if !haveField {
		return errors.New("empty binary control paragraph")
	}
	return nil
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func validBinaryControlFieldName(name []byte) bool {
	if len(name) == 0 || name[0] == '#' {
		return false
	}
	for _, value := range name {
		// deb822 field names are printable US-ASCII other than colon and may
		// not contain whitespace or controls.
		if value < 0x21 || value > 0x7e || value == ':' {
			return false
		}
	}
	return true
}

func openDebControlStream(ctx context.Context, member *debArEntry) (io.ReadCloser, error) {
	input := io.Reader(&contextReader{ctx: ctx, r: member.Data})
	switch filepath.Ext(member.Name) {
	case ".tar":
		return io.NopCloser(input), nil
	case ".gz":
		return gzip.NewReader(input)
	case ".bz2":
		return io.NopCloser(bzip2.NewReader(input)), nil
	case ".xz":
		reader, err := xz.NewReader(input, uint32(maxDebDecoderMemory))
		if err != nil {
			return nil, err
		}
		return io.NopCloser(reader), nil
	case ".zst":
		reader, err := zstd.NewReader(input,
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderLowmem(true),
			zstd.WithDecoderMaxMemory(maxDebDecoderMemory),
			zstd.WithDecoderMaxWindow(maxDebDecoderMemory),
		)
		if err != nil {
			return nil, err
		}
		return reader.IOReadCloser(), nil
	default:
		return nil, fmt.Errorf("unsupported control archive compression %q", member.Name)
	}
}

// PoolPath returns the human-readable, archive-root-relative pool location
// used by Debian repositories: pool/<component>/<prefix>/<source>/<filename>.
func PoolPath(component, source, filename string) (string, error) {
	if err := validateComponent(component); err != nil {
		return "", err
	}
	if !debianNamePattern.MatchString(source) {
		return "", fmt.Errorf("aptrepo: unsafe source package name %q", source)
	}
	if path.Base(filename) != filename || !safeDebBasename(filename) {
		return "", fmt.Errorf("aptrepo: unsafe deb filename %q", filename)
	}
	prefix := source[:1]
	if strings.HasPrefix(source, "lib") {
		if len(source) < 4 {
			prefix = source
		} else {
			prefix = source[:4]
		}
	}
	return path.Join("pool", component, prefix, source, filename), nil
}

// safeDebBasename accepts Debian package basenames (including common percent
// escapes such as %3a for epoch colons or %2b for '+') while rejecting encoded
// control characters, path separators, dots, double-encoding, and URL-special
// delimiters.
func safeDebBasename(value string) bool {
	if len(value) <= len(".deb") || !strings.HasSuffix(value, ".deb") || (!asciiAlphaNumeric(value[0]) && value[0] != '_') {
		return false
	}
	for i := 1; i < len(value); i++ {
		c := value[i]
		if asciiAlphaNumeric(c) || strings.ContainsRune("+._:~-@", rune(c)) {
			continue
		}
		if c == '%' && i+2 < len(value) && isHexDigit(value[i+1]) && isHexDigit(value[i+2]) {
			if !isSafeDebPercentEscapedByte(value[i+1], value[i+2]) {
				return false
			}
			i += 2
			continue
		}
		return false
	}
	return true
}

func debHexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

func isSafeDebPercentEscapedByte(hi, lo byte) bool {
	b := (debHexNibble(hi) << 4) | debHexNibble(lo)
	if b <= 0x20 || b >= 0x7f {
		return false
	}
	switch b {
	case '/', '\\', '.', '%', '?', '#', '"', '<', '>':
		return false
	}
	return true
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func asciiAlphaNumeric(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func sourcePackageName(source, fallback string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return fallback
	}
	if i := strings.IndexAny(source, " \t("); i >= 0 {
		source = source[:i]
	}
	return source
}

// CompareVersions applies Debian's native epoch/upstream/revision ordering.
// It returns a negative value when left is older, zero when equal, and a
// positive value when newer.
func CompareVersions(left, right string) (int, error) {
	leftVersion, err := version.Parse(left)
	if err != nil {
		return 0, fmt.Errorf("aptrepo: parse Debian version %q: %w", left, err)
	}
	rightVersion, err := version.Parse(right)
	if err != nil {
		return 0, fmt.Errorf("aptrepo: parse Debian version %q: %w", right, err)
	}
	return version.Compare(leftVersion, rightVersion), nil
}

func validateComponent(component string) error {
	if !componentPattern.MatchString(component) {
		return fmt.Errorf("aptrepo: unsafe component %q", component)
	}
	return nil
}

func hashPackage(ctx context.Context, filePath string) (string, int64, error) {
	f, err := os.OpenFile(filePath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", 0, fmt.Errorf("aptrepo: open deb for hashing: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", 0, errors.Join(err, errors.New("aptrepo: deb input must be a regular file"))
	}

	digest, size, err := hashReader(ctx, f)
	if err != nil {
		return "", 0, fmt.Errorf("aptrepo: hash deb: %w", err)
	}
	workmetrics.RecordFullPackageRead(ctx, size)
	return digest, size, nil
}

func hashReader(ctx context.Context, r io.Reader) (string, int64, error) {
	h := sha256.New()
	n, err := io.CopyBuffer(h, &contextReader{ctx: ctx, r: r}, make([]byte, 128*1024))
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func cloneParagraph(p control.Paragraph) control.Paragraph {
	clone := control.Paragraph{
		Order:  append([]string(nil), p.Order...),
		Values: make(map[string]string, len(p.Values)),
	}
	for k, v := range p.Values {
		clone.Values[k] = v
	}
	return clone
}
