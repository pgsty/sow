package aptrepo

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/kjk/lzma"
	"github.com/klauspost/compress/zstd"
	"github.com/xi2/xz"
	"pault.ag/go/debian/control"
	"pault.ag/go/debian/deb"
	"pault.ag/go/debian/version"
)

var (
	debianNamePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)
	componentPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)
	architecturePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
)

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

// ControlValue returns one parsed binary control field without exposing the
// mutable paragraph used to produce Packages.
func (p Package) ControlValue(name string) (string, bool) {
	v, ok := p.paragraph.Values[name]
	return v, ok
}

// InspectPackage parses an existing .deb with pault.ag/go/debian's ar and
// control decoders and computes its immutable payload metadata. It deliberately
// does not open data.tar: repository metadata inspection never needs installed
// payload contents, and opening that compressor would make memory depend on its
// advertised window. The input file is never mutated.
func InspectPackage(ctx context.Context, filePath, component string) (Package, error) {
	return InspectPackageAs(ctx, filePath, component, filepath.Base(filePath))
}

// InspectFlatPackage performs the single full-file hash used by Plain create.
// It parses control metadata from the same descriptor and relies on the
// caller's final stat snapshot check instead of rehashing the entire payload.
func InspectFlatPackage(ctx context.Context, filePath, component string) (Package, error) {
	return inspectPackagePath(ctx, filePath, component, filepath.Base(filePath), true)
}

// InspectPackageAs parses an existing .deb while using originalBasename as
// its externally visible pool filename. CAS objects are named by digest, so a
// rebuildable derived catalog must be able to inspect those immutable bytes
// without first materializing or copying them back to their public filename.
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
	pathInfo, err := os.Lstat(filePath)
	if err != nil {
		return Package{}, fmt.Errorf("aptrepo: lstat deb: %w", err)
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 {
		return Package{}, errors.New("aptrepo: deb input is not a regular file")
	}

	f, err := os.Open(filePath)
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
	if !info.Mode().IsRegular() || !os.SameFile(pathInfo, info) {
		return Package{}, errors.New("aptrepo: deb changed while opening")
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
	after, err := f.Stat()
	if err != nil {
		return Package{}, fmt.Errorf("aptrepo: stat deb after inspection: %w", err)
	}
	pathAfter, pathErr := os.Lstat(filePath)
	if pkg.Size != info.Size() || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) ||
		pathErr != nil || !pathAfter.Mode().IsRegular() || pathAfter.Mode()&os.ModeSymlink != 0 || !os.SameFile(pathInfo, pathAfter) {
		return Package{}, errors.New("aptrepo: deb changed while being inspected")
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

// InspectPackageReaderAs parses and hashes one Debian package through a
// caller-owned seekable descriptor. The caller is responsible for binding the
// descriptor to the intended path/inode and for closing it. The reader is
// rewound and hashed both before and after control parsing so the returned
// identity and digest always describe the same bytes.
func InspectPackageReaderAs(ctx context.Context, reader PackageReader, component, originalBasename string) (Package, error) {
	return inspectPackageReaderAs(ctx, reader, component, originalBasename, true)
}

func inspectPackageReaderAs(ctx context.Context, reader PackageReader, component, originalBasename string, rehash bool) (Package, error) {
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
		return Package{}, fmt.Errorf("aptrepo: rewind deb before hashing: %w", err)
	}
	initialDigest, initialSize, err := hashReader(ctx, reader)
	if err != nil {
		return Package{}, fmt.Errorf("aptrepo: hash deb before parsing: %w", err)
	}
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return Package{}, fmt.Errorf("aptrepo: rewind deb for parsing: %w", err)
	}

	debianControl, err := loadDebControl(ctx, reader, initialSize)
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
	digest, size := initialDigest, initialSize
	if rehash {
		if _, err := reader.Seek(0, io.SeekStart); err != nil {
			return Package{}, fmt.Errorf("aptrepo: rewind deb for hashing: %w", err)
		}
		digest, size, err = hashReader(ctx, reader)
		if err != nil {
			return Package{}, fmt.Errorf("aptrepo: hash deb: %w", err)
		}
		if initialDigest != digest || initialSize != size {
			return Package{}, errors.New("aptrepo: deb changed while being inspected")
		}
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

func loadDebControl(ctx context.Context, reader io.ReaderAt, size int64) (deb.Control, error) {
	if err := validateDebArLayout(ctx, reader, size); err != nil {
		return deb.Control{}, err
	}
	archive, err := deb.LoadAr(reader)
	if err != nil {
		return deb.Control{}, err
	}
	var versionSeen bool
	var dataSeen bool
	var controlMember *deb.ArEntry
	for {
		if err := ctx.Err(); err != nil {
			return deb.Control{}, err
		}
		member, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return deb.Control{}, err
		}
		switch {
		case member.Name == "debian-binary":
			if versionSeen {
				return deb.Control{}, errors.New("duplicate debian-binary member")
			}
			versionSeen = true
			if member.Size != int64(len("2.0\n")) {
				return deb.Control{}, fmt.Errorf("unexpected debian-binary size %d", member.Size)
			}
			versionBytes, err := io.ReadAll(member.Data)
			if err != nil {
				return deb.Control{}, err
			}
			if string(versionBytes) != "2.0\n" {
				return deb.Control{}, fmt.Errorf("unsupported debian binary version %q", versionBytes)
			}
		case member.Name == "control.tar" || strings.HasPrefix(member.Name, "control.tar."):
			if controlMember != nil {
				return deb.Control{}, errors.New("duplicate control archive member")
			}
			if member.Size <= 0 || member.Size > maxDebControlCompressed {
				return deb.Control{}, fmt.Errorf("control archive compressed size %d exceeds limit", member.Size)
			}
			controlMember = member
		case member.Name == "data.tar" || strings.HasPrefix(member.Name, "data.tar."):
			if dataSeen {
				return deb.Control{}, errors.New("duplicate data archive member")
			}
			if member.Size == 0 {
				return deb.Control{}, errors.New("empty data archive member")
			}
			dataSeen = true
		}
	}
	if !versionSeen {
		return deb.Control{}, errors.New("missing debian-binary member")
	}
	if controlMember == nil {
		return deb.Control{}, errors.New("missing control archive member")
	}
	if !dataSeen {
		return deb.Control{}, errors.New("missing data archive member")
	}
	return loadDebControlArchive(ctx, controlMember)
}

func validateDebArLayout(ctx context.Context, reader io.ReaderAt, size int64) error {
	if size < 8 {
		return errors.New("truncated ar archive")
	}
	magic := make([]byte, 8)
	if _, err := reader.ReadAt(magic, 0); err != nil || string(magic) != "!<arch>\n" {
		return errors.Join(err, errors.New("invalid ar archive header"))
	}
	offset := int64(8)
	for count := 0; offset < size; count++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if count >= maxDebArMembers {
			return fmt.Errorf("ar archive exceeds %d members", maxDebArMembers)
		}
		if size-offset < 60 {
			return errors.New("truncated ar member header")
		}
		header := make([]byte, 60)
		if _, err := reader.ReadAt(header, offset); err != nil {
			return err
		}
		if header[58] != '`' || header[59] != '\n' {
			return errors.New("malformed ar member header terminator")
		}
		memberSize, err := strconv.ParseInt(strings.TrimSpace(string(header[48:58])), 10, 64)
		if err != nil || memberSize < 0 {
			return fmt.Errorf("invalid ar member size %q", strings.TrimSpace(string(header[48:58])))
		}
		dataOffset := offset + 60
		if memberSize > size-dataOffset {
			return errors.New("ar member extends beyond package")
		}
		offset = dataOffset + memberSize
		if memberSize&1 != 0 {
			if offset >= size {
				return errors.New("ar member is missing alignment padding")
			}
			offset++
		}
	}
	if offset != size {
		return errors.New("ar archive length is inconsistent")
	}
	return nil
}

func loadDebControlArchive(ctx context.Context, member *deb.ArEntry) (parsed deb.Control, resultErr error) {
	stream, err := openDebControlStream(ctx, member)
	if err != nil {
		return deb.Control{}, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, stream.Close())
	}()
	archive := tar.NewReader(stream)
	found := false
	expanded := int64(0)
	for members := 0; ; members++ {
		if err := ctx.Err(); err != nil {
			return deb.Control{}, err
		}
		if members >= maxDebControlMembers {
			return deb.Control{}, fmt.Errorf("control archive exceeds %d members", maxDebControlMembers)
		}
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return deb.Control{}, err
		}
		if header.Size < 0 || header.Size > maxDebControlExpanded-expanded {
			return deb.Control{}, fmt.Errorf("control archive expands beyond %d bytes", maxDebControlExpanded)
		}
		expanded += header.Size
		if path.Clean(header.Name) != "control" {
			continue
		}
		if found {
			return deb.Control{}, errors.New("duplicate control file in control archive")
		}
		// Some historical control archives encode a regular file with the
		// original NUL typeflag. Keep accepting that wire value without relying
		// on archive/tar's deprecated TypeRegA alias.
		if header.Typeflag != tar.TypeReg && header.Typeflag != byte(0) {
			return deb.Control{}, errors.New("control file in control archive is not regular")
		}
		if header.Size > maxDebControlFile {
			return deb.Control{}, fmt.Errorf("control file exceeds %d bytes", maxDebControlFile)
		}
		limited := &io.LimitedReader{R: archive, N: maxDebControlFile + 1}
		body, err := io.ReadAll(limited)
		if err != nil {
			return deb.Control{}, err
		}
		if int64(len(body)) != header.Size || limited.N == 0 {
			return deb.Control{}, fmt.Errorf("control file exceeds %d bytes or is truncated", maxDebControlFile)
		}
		if err := validateBinaryControlDocument(body); err != nil {
			return deb.Control{}, err
		}
		if err := control.Unmarshal(&parsed, bytes.NewReader(body)); err != nil {
			return deb.Control{}, err
		}
		found = true
	}
	if !found {
		return deb.Control{}, errors.New("missing control file in control archive")
	}
	return parsed, nil
}

func validateBinaryControlDocument(body []byte) error {
	if len(body) == 0 {
		return errors.New("empty binary control paragraph")
	}
	seen := make(map[string]struct{})
	haveField, haveCurrentField, paragraphEnded := false, false, false
	for index, raw := range bytes.Split(body, []byte{'\n'}) {
		line := raw
		if len(line) != 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		for _, value := range line {
			if value == '\r' || value == 0 || value == 0x7f || (value < 0x20 && value != '\t') {
				return fmt.Errorf("binary control line %d contains a forbidden control byte", index+1)
			}
		}
		if len(line) == 0 {
			if !haveField {
				return fmt.Errorf("binary control line %d starts an empty paragraph", index+1)
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
			continue
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 || !validBinaryControlFieldName(line[:colon]) {
			return fmt.Errorf("binary control line %d has an invalid field name", index+1)
		}
		name := strings.ToLower(string(line[:colon]))
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("binary control line %d repeats field %q", index+1, line[:colon])
		}
		seen[name] = struct{}{}
		haveField, haveCurrentField = true, true
	}
	if !haveField {
		return errors.New("empty binary control paragraph")
	}
	return nil
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

func openDebControlStream(ctx context.Context, member *deb.ArEntry) (io.ReadCloser, error) {
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
	case ".lzma":
		buffered := bufio.NewReader(input)
		header, err := buffered.Peek(5)
		if err != nil {
			return nil, err
		}
		if dictionary := uint64(binary.LittleEndian.Uint32(header[1:5])); dictionary > maxDebDecoderMemory {
			return nil, fmt.Errorf("lzma dictionary %d exceeds limit", dictionary)
		}
		return lzma.NewReader(buffered), nil
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

// safeDebBasename accepts Debian's common epoch filename spelling while
// keeping URL and filesystem path interpretation unambiguous. APT archives in
// the wild encode the version's ':' as %3a (or %3A); no other percent escape
// is needed for a Debian package basename, so encoded separators, dots,
// percent signs, NULs, and double-encoding remain rejected.
func safeDebBasename(value string) bool {
	if len(value) <= len(".deb") || !strings.HasSuffix(value, ".deb") || !asciiAlphaNumeric(value[0]) {
		return false
	}
	for i := 1; i < len(value); i++ {
		c := value[i]
		if asciiAlphaNumeric(c) || strings.ContainsRune("+._:~-", rune(c)) {
			continue
		}
		if c == '%' && i+2 < len(value) && value[i+1] == '3' && (value[i+2] == 'a' || value[i+2] == 'A') {
			i += 2
			continue
		}
		return false
	}
	return true
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

func validateSegment(kind, value string) error {
	if value == "" || value == "." || value == ".." || strings.ContainsAny(value, "/\\\x00\r\n\t") {
		return fmt.Errorf("aptrepo: unsafe %s %q", kind, value)
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && !strings.ContainsRune("+._-", r) {
			return fmt.Errorf("aptrepo: unsafe %s %q", kind, value)
		}
	}
	return nil
}

func hashPackage(ctx context.Context, filePath string) (string, int64, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", 0, fmt.Errorf("aptrepo: open deb for hashing: %w", err)
	}
	defer f.Close()

	digest, size, err := hashReader(ctx, f)
	if err != nil {
		return "", 0, fmt.Errorf("aptrepo: hash deb: %w", err)
	}
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
