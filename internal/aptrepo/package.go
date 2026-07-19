package aptrepo

import (
	"archive/tar"
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
	"strings"

	"pault.ag/go/debian/control"
	"pault.ag/go/debian/deb"
	"pault.ag/go/debian/version"
)

var (
	debianNamePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)
	componentPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)
	architecturePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	filenamePattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._:~-]*\.deb$`)
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

// InspectPackageAs parses an existing .deb while using originalBasename as
// its externally visible pool filename. CAS objects are named by digest, so a
// rebuildable derived catalog must be able to inspect those immutable bytes
// without first materializing or copying them back to their public filename.
func InspectPackageAs(ctx context.Context, filePath, component, originalBasename string) (Package, error) {
	if ctx == nil {
		return Package{}, errors.New("aptrepo: nil context")
	}
	if err := ctx.Err(); err != nil {
		return Package{}, err
	}
	if err := validateComponent(component); err != nil {
		return Package{}, err
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
	if !info.Mode().IsRegular() {
		return Package{}, errors.New("aptrepo: deb input is not a regular file")
	}
	pkg, err := InspectPackageReaderAs(ctx, f, component, originalBasename)
	if err != nil {
		return Package{}, err
	}
	after, err := f.Stat()
	if err != nil {
		return Package{}, fmt.Errorf("aptrepo: stat deb after inspection: %w", err)
	}
	if pkg.Size != info.Size() || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
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
	if filepath.Base(base) != base || !filenamePattern.MatchString(base) {
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

	debianControl, err := loadDebControl(reader)
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
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return Package{}, fmt.Errorf("aptrepo: rewind deb for hashing: %w", err)
	}
	digest, size, err := hashReader(ctx, reader)
	if err != nil {
		return Package{}, fmt.Errorf("aptrepo: hash deb: %w", err)
	}
	if initialDigest != digest || initialSize != size {
		return Package{}, errors.New("aptrepo: deb changed while being inspected")
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

func loadDebControl(reader io.ReaderAt) (deb.Control, error) {
	archive, err := deb.LoadAr(reader)
	if err != nil {
		return deb.Control{}, err
	}
	var versionSeen bool
	var dataSeen bool
	var controlMember *deb.ArEntry
	for {
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
	return loadDebControlArchive(controlMember)
}

func loadDebControlArchive(member *deb.ArEntry) (parsed deb.Control, resultErr error) {
	archive, closer, err := member.Tarfile()
	if err != nil {
		return deb.Control{}, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, closer.Close())
	}()
	found := false
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return deb.Control{}, err
		}
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
		if err := control.Unmarshal(&parsed, archive); err != nil {
			return deb.Control{}, err
		}
		found = true
	}
	if !found {
		return deb.Control{}, errors.New("missing control file in control archive")
	}
	return parsed, nil
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
	if path.Base(filename) != filename || !filenamePattern.MatchString(filename) {
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
