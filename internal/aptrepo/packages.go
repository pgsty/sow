package aptrepo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"pault.ag/go/debian/control"
	"pault.ag/go/debian/version"
)

var (
	ErrPackagesOutOfOrder       = errors.New("aptrepo: Packages entries are not in deterministic order")
	ErrDuplicatePackageIdentity = errors.New("aptrepo: duplicate package identity")
)

var preferredControlOrder = []string{
	"Package", "Source", "Version", "Architecture", "Maintainer",
	"Installed-Size", "Pre-Depends", "Depends", "Recommends", "Suggests",
	"Breaks", "Conflicts", "Replaces", "Provides", "Built-Using",
	"Section", "Priority", "Multi-Arch", "Homepage", "Description",
}

var derivedIndexFields = map[string]struct{}{
	"filename": {}, "size": {}, "md5sum": {}, "sha1": {}, "sha256": {},
}

type encodedParagraph struct {
	control.Paragraph
}

// PackagesWriter emits one Debian Packages paragraph at a time through
// pault.ag/go/debian/control.Encoder. Callers that already have an externally
// sorted stream can keep memory bounded to one Package; an out-of-order entry
// is rejected rather than silently producing non-deterministic output.
type PackagesWriter struct {
	encoder *control.Encoder
	last    *Package
}

func NewPackagesWriter(w io.Writer) (*PackagesWriter, error) {
	if w == nil {
		return nil, errors.New("aptrepo: nil Packages writer")
	}
	encoder, err := control.NewEncoder(w)
	if err != nil {
		return nil, fmt.Errorf("aptrepo: create control encoder: %w", err)
	}
	return &PackagesWriter{encoder: encoder}, nil
}

func (w *PackagesWriter) Write(pkg Package) error {
	return w.writeAt(pkg, pkg.PoolPath)
}

// WriteManaged emits one parsed package with the frozen componentless managed
// pool/<prefix>/<source>/<basename> Filename. The parsed control paragraph and
// package hashes remain unchanged; only the repository-relative location is
// projected differently from a conventional component-bearing APT archive.
func (w *PackagesWriter) WriteManaged(pkg Package, filename string) error {
	if err := validateManagedPoolPath(pkg.Source, pathBase(filename), filename); err != nil {
		return err
	}
	return w.writeAt(pkg, filename)
}

func (w *PackagesWriter) writeAt(pkg Package, filename string) error {
	if err := validatePackageMetadata(pkg); err != nil {
		return err
	}
	if w.last != nil && comparePackages(*w.last, pkg) > 0 {
		return ErrPackagesOutOfOrder
	}
	if w.last != nil && w.last.Name == pkg.Name && version.Compare(w.last.debianVersion, pkg.debianVersion) == 0 && w.last.Architecture == pkg.Architecture {
		return ErrDuplicatePackageIdentity
	}
	paragraph := packageParagraph(pkg)
	paragraph.Values["Filename"] = filename
	if err := w.encoder.Encode(encodedParagraph{Paragraph: paragraph}); err != nil {
		return fmt.Errorf("aptrepo: encode Packages paragraph: %w", err)
	}
	copyForOrder := pkg
	w.last = &copyForOrder
	return nil
}

func validateManagedPoolPath(source, basename, filename string) error {
	if !debianNamePattern.MatchString(source) || !safeDebBasename(basename) || filename == "" || strings.ContainsAny(filename, "\\\x00\r\n\t") {
		return fmt.Errorf("aptrepo: unsafe managed pool path %q", filename)
	}
	prefix := source[:1]
	if strings.HasPrefix(source, "lib") {
		if len(source) < 4 {
			prefix = source
		} else {
			prefix = source[:4]
		}
	}
	want := strings.Join([]string{"pool", prefix, source, basename}, "/")
	if filename != want {
		return fmt.Errorf("aptrepo: managed pool path %q is not canonical; want %q", filename, want)
	}
	return nil
}

// WritePackages sorts a copy of packages and streams the resulting paragraphs
// to w. For very large indexes, callers can sort externally and use
// PackagesWriter directly to avoid retaining the full index in memory.
func WritePackages(w io.Writer, packages []Package) error {
	sorted := append([]Package(nil), packages...)
	SortPackages(sorted)
	writer, err := NewPackagesWriter(w)
	if err != nil {
		return err
	}
	for _, pkg := range sorted {
		if err := writer.Write(pkg); err != nil {
			return err
		}
	}
	return nil
}

// WriteFlatPackages emits a Packages index for a directory where package
// files live beside the index. It is intentionally narrower than the managed
// archive renderer: every Filename is exactly ./<source basename>, while all
// control metadata and checksums still come from a successfully parsed .deb.
// Package sources are rehashed before their paragraphs are emitted so callers
// cannot publish metadata for bytes that changed after inspection.
func WriteFlatPackages(ctx context.Context, w io.Writer, packages []Package) error {
	return writeFlatPackages(ctx, w, packages, true)
}

// WriteInspectedFlatPackages renders packages already returned by
// InspectFlatPackage without reopening their payloads. Plain create performs
// one directory-wide stat validation after all RPM and DEB metadata is staged.
func WriteInspectedFlatPackages(ctx context.Context, w io.Writer, packages []Package) error {
	return writeFlatPackages(ctx, w, packages, false)
}

func writeFlatPackages(ctx context.Context, w io.Writer, packages []Package, verifySource bool) error {
	if ctx == nil {
		return errors.New("aptrepo: nil context")
	}
	if w == nil {
		return errors.New("aptrepo: nil Packages writer")
	}
	sorted := append([]Package(nil), packages...)
	SortPackages(sorted)
	encoder, err := control.NewEncoder(w)
	if err != nil {
		return fmt.Errorf("aptrepo: create flat control encoder: %w", err)
	}
	var previous *Package
	for _, pkg := range sorted {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := validatePackageMetadata(pkg); err != nil {
			return err
		}
		if previous != nil && previous.Name == pkg.Name && version.Compare(previous.debianVersion, pkg.debianVersion) == 0 && previous.Architecture == pkg.Architecture {
			return ErrDuplicatePackageIdentity
		}
		if verifySource {
			if err := verifyPackageSource(ctx, pkg); err != nil {
				return err
			}
		}
		base := filepath.Base(pkg.SourcePath)
		if !safeDebBasename(base) || filepath.Join(filepath.Dir(pkg.SourcePath), base) != filepath.Clean(pkg.SourcePath) {
			return fmt.Errorf("aptrepo: unsafe flat deb source %q", pkg.SourcePath)
		}
		paragraph := packageParagraph(pkg)
		paragraph.Values["Filename"] = "./" + base
		if err := encoder.Encode(encodedParagraph{Paragraph: paragraph}); err != nil {
			return fmt.Errorf("aptrepo: encode flat Packages paragraph: %w", err)
		}
		copyForOrder := pkg
		previous = &copyForOrder
	}
	return nil
}

// SortPackages orders packages by name, Debian version semantics,
// architecture, pool path and finally digest.
func SortPackages(packages []Package) {
	sort.SliceStable(packages, func(i, j int) bool {
		return comparePackages(packages[i], packages[j]) < 0
	})
}

// ComparePackages applies the canonical Packages ordering without allocating
// or sorting a temporary slice. Managed renderers use it in their outer sort.
func ComparePackages(a, b Package) int {
	return comparePackages(a, b)
}

func comparePackages(a, b Package) int {
	if c := strings.Compare(a.Name, b.Name); c != 0 {
		return c
	}
	if c := version.Compare(a.debianVersion, b.debianVersion); c != 0 {
		return c
	}
	if c := strings.Compare(a.Architecture, b.Architecture); c != 0 {
		return c
	}
	if c := strings.Compare(a.PoolPath, b.PoolPath); c != 0 {
		return c
	}
	return strings.Compare(a.SHA256, b.SHA256)
}

func validatePackageMetadata(pkg Package) error {
	if !debianNamePattern.MatchString(pkg.Name) {
		return fmt.Errorf("aptrepo: unsafe package name %q", pkg.Name)
	}
	if !debianNamePattern.MatchString(pkg.Source) {
		return fmt.Errorf("aptrepo: unsafe source package name %q", pkg.Source)
	}
	if err := validateComponent(pkg.Component); err != nil {
		return err
	}
	if !architecturePattern.MatchString(pkg.Architecture) {
		return fmt.Errorf("aptrepo: unsafe architecture %q", pkg.Architecture)
	}
	if pkg.SourcePath == "" {
		return errors.New("aptrepo: package source path is required")
	}
	if pkg.paragraph.Values == nil {
		return errors.New("aptrepo: package is not backed by parsed deb control metadata")
	}
	fieldNames := make(map[string]string, len(pkg.paragraph.Values))
	for name := range pkg.paragraph.Values {
		folded := strings.ToLower(name)
		if previous, exists := fieldNames[folded]; exists && previous != name {
			return fmt.Errorf("aptrepo: duplicate case-insensitive control field %q", name)
		}
		fieldNames[folded] = name
	}
	if pkg.paragraph.Values["Package"] != pkg.Name || pkg.paragraph.Values["Architecture"] != pkg.Architecture {
		return fmt.Errorf("aptrepo: package identity does not match parsed deb control metadata: package=%q/%q architecture=%q/%q",
			pkg.Name, pkg.paragraph.Values["Package"], pkg.Architecture, pkg.paragraph.Values["Architecture"])
	}
	rawVersion, err := version.Parse(pkg.paragraph.Values["Version"])
	if err != nil || version.Compare(rawVersion, pkg.debianVersion) != 0 {
		return fmt.Errorf("aptrepo: package version does not match parsed deb control metadata: version=%q/%q",
			pkg.Version, pkg.paragraph.Values["Version"])
	}
	if sourcePackageName(pkg.paragraph.Values["Source"], pkg.Name) != pkg.Source || pkg.debianVersion.String() != pkg.Version {
		return errors.New("aptrepo: package source or version does not match parsed deb control metadata")
	}
	if pkg.Size < 0 {
		return errors.New("aptrepo: negative package size")
	}
	if len(pkg.SHA256) != 64 {
		return errors.New("aptrepo: invalid package SHA256")
	}
	for _, r := range pkg.SHA256 {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return errors.New("aptrepo: invalid package SHA256")
		}
	}
	expectedPoolPath, err := PoolPath(pkg.Component, pkg.Source, pathBase(pkg.PoolPath))
	if err != nil || expectedPoolPath != pkg.PoolPath {
		return fmt.Errorf("aptrepo: unsafe or non-canonical pool path %q", pkg.PoolPath)
	}
	return nil
}

func pathBase(value string) string {
	if i := strings.LastIndexByte(value, '/'); i >= 0 {
		return value[i+1:]
	}
	return value
}

func packageParagraph(pkg Package) control.Paragraph {
	values := make(map[string]string, len(pkg.paragraph.Values)+3)
	for key, value := range pkg.paragraph.Values {
		if _, derived := derivedIndexFields[strings.ToLower(key)]; derived {
			continue
		}
		if value == "" {
			continue
		}
		if strings.EqualFold(key, "Description") {
			// The control decoder retains its final continuation newline. The
			// canonical dpkg-scanpackages paragraph does not emit a synthetic
			// trailing blank continuation line.
			value = strings.TrimRight(value, "\n")
		}
		values[key] = value
	}

	order := make([]string, 0, len(values)+3)
	seen := make(map[string]struct{}, len(values)+3)
	for _, key := range preferredControlOrder {
		if _, ok := values[key]; ok {
			order = append(order, key)
			seen[key] = struct{}{}
		}
	}
	extras := make([]string, 0, len(values))
	for key := range values {
		if _, ok := seen[key]; !ok {
			extras = append(extras, key)
		}
	}
	sort.Strings(extras)
	order = append(order, extras...)

	values["Filename"] = pkg.PoolPath
	values["Size"] = strconv.FormatInt(pkg.Size, 10)
	values["SHA256"] = pkg.SHA256
	order = append(order, "Filename", "Size", "SHA256")
	return control.Paragraph{Order: order, Values: values}
}
