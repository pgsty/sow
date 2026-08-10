package yumrepo

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"

	crpm "github.com/cavaliergopher/rpm"
)

var (
	rpmHashBufferPool = sync.Pool{New: func() any {
		buffer := make([]byte, 128*1024)
		return &buffer
	}}
	rpmReaderPool = sync.Pool{New: func() any {
		return bufio.NewReaderSize(strings.NewReader(""), 128*1024)
	}}
)

const (
	tagName            = 1000
	tagVersion         = 1001
	tagRelease         = 1002
	tagEpoch           = 1003
	tagSummary         = 1004
	tagDescription     = 1005
	tagBuildTime       = 1006
	tagBuildHost       = 1007
	tagVendor          = 1011
	tagLicense         = 1014
	tagPackager        = 1015
	tagGroup           = 1016
	tagURL             = 1020
	tagArch            = 1022
	tagOldFilenames    = 1027
	tagFileModes       = 1030
	tagFileFlags       = 1037
	tagSourceRPM       = 1044
	tagProvideNames    = 1047
	tagRequireFlags    = 1048
	tagRequireNames    = 1049
	tagRequireEVRs     = 1050
	tagConflictFlags   = 1053
	tagConflictNames   = 1054
	tagConflictEVRs    = 1055
	tagChangelogTime   = 1080
	tagChangelogName   = 1081
	tagChangelogText   = 1082
	tagObsoleteNames   = 1090
	tagProvideFlags    = 1112
	tagProvideEVRs     = 1113
	tagObsoleteFlags   = 1114
	tagObsoleteEVRs    = 1115
	tagDirIndexes      = 1116
	tagBaseNames       = 1117
	tagDirNames        = 1118
	tagRecommendNames  = 5046
	tagRecommendEVRs   = 5047
	tagRecommendFlags  = 5048
	tagSuggestNames    = 5049
	tagSuggestEVRs     = 5050
	tagSuggestFlags    = 5051
	tagSupplementNames = 5052
	tagSupplementEVRs  = 5053
	tagSupplementFlags = 5054
	tagEnhanceNames    = 5055
	tagEnhanceEVRs     = 5056
	tagEnhanceFlags    = 5057
)

type dependency struct {
	Name    string
	Flags   string
	Epoch   string
	Version string
	Release string
	Pre     bool
	// MissingOK is the legacy pre-RPM-4.12 weak-require marker. It is an
	// inspection-only fact and is projected into recommends before rendering.
	MissingOK bool
}

type rpmFile struct {
	Name  string
	Mode  int64
	Flags int64
}

type changelog struct {
	Author string
	Date   int64
	Text   string
}

type packageMetadata struct {
	Name, Version, Release, Arch string
	Epoch                        int64
	Checksum, Location           string
	Summary, Description         string
	Packager, URL                string
	FileTime, BuildTime          int64
	PackageSize                  int64
	InstalledSize, ArchiveSize   uint64
	License, Vendor, Group       string
	BuildHost, SourceRPM         string
	HeaderStart, HeaderEnd       int
	Provides, Requires           []dependency
	CatalogRequires              []dependency
	Conflicts, Obsoletes         []dependency
	Suggests, Enhances           []dependency
	Recommends, Supplements      []dependency
	Files                        []rpmFile
	Changelogs                   []changelog
}

// PackageLocation implements the frozen Packages/<bucket>/<original-basename>
// contract. Bucket is the lowercase first ASCII alphanumeric of RPM Name, or
// underscore when the name has no ASCII alphanumeric character.
func PackageLocation(name, basename string) (string, error) {
	return packageLocation(name, basename, false)
}

func packageLocation(name, basename string, managed bool) (string, error) {
	if name == "" || !utf8.ValidString(name) {
		return "", fmt.Errorf("%w: missing or invalid RPM name", ErrUnsafeLocation)
	}
	validBasename := safeRPMBasename(basename)
	if managed {
		validBasename = safeManagedRPMBasename(basename)
	}
	if basename == "" || basename == "." || basename == ".." || !strings.HasSuffix(basename, ".rpm") ||
		path.Base(basename) != basename || filepath.Base(basename) != basename ||
		!validBasename {
		return "", fmt.Errorf("%w: invalid basename %q", ErrUnsafeLocation, basename)
	}
	bucket := byte('_')
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'A' && c <= 'Z' {
			bucket = c + ('a' - 'A')
			break
		}
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			bucket = c
			break
		}
	}
	return "Packages/" + string(bucket) + "/" + basename, nil
}

func safeRPMBasename(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '.', '-', '_', '+', '~', '^':
			continue
		default:
			return false
		}
	}
	return true
}

func safeManagedRPMBasename(value string) bool {
	return value != ".rpm" && strings.HasSuffix(value, ".rpm") && safeManagedPackageComponent(value)
}

// InspectPackage hashes and parses one real RPM and returns its stable package
// identity. Hashing and cavaliergopher/rpm header parsing reuse one open file
// descriptor; this is the exact path used by Generate, not a second parser.
func InspectPackage(ctx context.Context, in PackageInput) (PackageInfo, error) {
	if ctx == nil {
		return PackageInfo{}, fmt.Errorf("yumrepo: nil context")
	}
	metadata, err := readPackage(ctx, in)
	if err != nil {
		return PackageInfo{}, err
	}
	return packageInfo(metadata), nil
}

// InspectFlatPackage performs the one content pass used by Plain create and
// retains the complete parsed rpm-md projection for later rendering. The
// returned FlatPackage never opens the source again.
func InspectFlatPackage(ctx context.Context, in PackageInput) (*FlatPackage, PackageInfo, error) {
	if ctx == nil {
		return nil, PackageInfo{}, fmt.Errorf("yumrepo: nil context")
	}
	metadata, err := readFlatPackage(ctx, in)
	if err != nil {
		return nil, PackageInfo{}, err
	}
	return &FlatPackage{metadata: metadata}, packageInfo(metadata), nil
}

func packageInfo(metadata *packageMetadata) PackageInfo {
	source := sourceNameFromRPM(metadata.SourceRPM, metadata.Name, metadata.Version, metadata.Release)
	return PackageInfo{
		Name: metadata.Name, Source: source, SourceRPM: metadata.SourceRPM, Version: metadata.Version, Release: metadata.Release,
		Epoch: metadata.Epoch, Arch: metadata.Arch, SHA256: metadata.Checksum,
		Size: metadata.PackageSize, Location: metadata.Location,
	}
}

func readFlatPackage(ctx context.Context, in PackageInput) (*packageMetadata, error) {
	if in.PoolPath != "" || in.ViewPath.String() != "" || in.Location != "" {
		return nil, fmt.Errorf("%w: flat package input carries managed placement", ErrUnsafeLocation)
	}
	in.FileTime = unixEpoch
	metadata, err := readPackage(ctx, in)
	if err != nil {
		return nil, err
	}
	base := in.Basename
	if base == "" {
		base = filepath.Base(in.Path)
	}
	if _, err := PackageLocation(metadata.Name, base); err != nil {
		return nil, err
	}
	metadata.Location = base
	return metadata, nil
}

// InspectPackageReader parses and hashes one RPM through a caller-owned
// seekable descriptor. The caller binds the descriptor to its intended
// path/inode and closes it. Hashing before and after header parsing guarantees
// that the returned NEVRA and digest describe one stable byte sequence.
func InspectPackageReader(ctx context.Context, input io.ReadSeeker, originalBasename string) (PackageInfo, error) {
	if ctx == nil {
		return PackageInfo{}, fmt.Errorf("yumrepo: nil context")
	}
	if err := ctx.Err(); err != nil {
		return PackageInfo{}, err
	}
	if input == nil {
		return PackageInfo{}, fmt.Errorf("%w: nil RPM reader", ErrInvalidPackage)
	}
	if originalBasename == "" || path.Base(originalBasename) != originalBasename || filepath.Base(originalBasename) != originalBasename ||
		!strings.HasSuffix(originalBasename, ".rpm") || !safeManagedRPMBasename(originalBasename) {
		return PackageInfo{}, fmt.Errorf("%w: invalid RPM basename %q", ErrInvalidPackage, originalBasename)
	}
	hashRPM := func() (string, int64, error) {
		if _, err := input.Seek(0, io.SeekStart); err != nil {
			return "", 0, err
		}
		hasher := sha256.New()
		buffer := rpmHashBufferPool.Get().(*[]byte)
		defer rpmHashBufferPool.Put(buffer)
		size, err := io.CopyBuffer(hasher, &contextReader{ctx: ctx, r: input}, *buffer)
		if err != nil {
			return "", 0, err
		}
		return hex.EncodeToString(hasher.Sum(nil)), size, nil
	}
	firstHash, firstSize, err := hashRPM()
	if err != nil {
		return PackageInfo{}, fmt.Errorf("%w: hash RPM reader: %v", ErrInvalidPackage, err)
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return PackageInfo{}, fmt.Errorf("%w: rewind RPM reader: %v", ErrInvalidPackage, err)
	}
	reader := rpmReaderPool.Get().(*bufio.Reader)
	reader.Reset(input)
	pkg, err := crpm.Read(reader)
	reader.Reset(strings.NewReader(""))
	rpmReaderPool.Put(reader)
	if err != nil {
		return PackageInfo{}, fmt.Errorf("%w: parse RPM reader: %v", ErrInvalidPackage, err)
	}
	if err := validatePackageSizeTags(pkg); err != nil {
		return PackageInfo{}, fmt.Errorf("%w: parse RPM reader: %v", ErrInvalidPackage, err)
	}
	name := tagString(&pkg.Header, tagName)
	version := tagString(&pkg.Header, tagVersion)
	release := tagString(&pkg.Header, tagRelease)
	architecture, err := normalizedRPMArchitecture(&pkg.Header, originalBasename)
	if err != nil {
		return PackageInfo{}, fmt.Errorf("%w: %v", ErrInvalidPackage, err)
	}
	epoch := tagInt(&pkg.Header, tagEpoch)
	sourceRPM := tagString(&pkg.Header, tagSourceRPM)
	if name == "" || version == "" || release == "" || architecture == "" ||
		!validXMLString(name) || !validXMLString(version) || !validXMLString(release) || !validXMLString(architecture) || epoch < 0 {
		return PackageInfo{}, fmt.Errorf("%w: RPM reader lacks required NEVRA fields", ErrInvalidPackage)
	}
	location, err := packageLocation(name, originalBasename, true)
	if err != nil {
		return PackageInfo{}, err
	}
	secondHash, secondSize, err := hashRPM()
	if err != nil {
		return PackageInfo{}, fmt.Errorf("%w: rehash RPM reader: %v", ErrInvalidPackage, err)
	}
	if firstHash != secondHash || firstSize != secondSize {
		return PackageInfo{}, fmt.Errorf("%w: RPM reader changed while being inspected", ErrInvalidPackage)
	}
	return PackageInfo{Name: name, Source: sourceNameFromRPM(sourceRPM, name, version, release), SourceRPM: sourceRPM, Version: version, Release: release, Epoch: epoch, Arch: architecture,
		SHA256: secondHash, Size: secondSize, Location: location}, nil
}

func readPackage(ctx context.Context, in PackageInput) (*packageMetadata, error) {
	return readPackageWithManagedBasename(ctx, in, false)
}

// readPackageWithManagedBasename permits the wider managed-pool basename
// alphabet without pretending the input already carries a managed view/href
// triple. RPM leaf exports need exactly this mode: the payload basename is
// already admitted by ParseManagedPoolPath, while the generated href is local
// to the exported leaf rather than a canonical managed Repository view.
func readPackageWithManagedBasename(ctx context.Context, in PackageInput, allowManagedBasename bool) (*packageMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if in.Path == "" {
		return nil, fmt.Errorf("%w: empty path", ErrInvalidPackage)
	}
	pathInfo, err := os.Lstat(in.Path)
	if err != nil {
		return nil, fmt.Errorf("%w: stat %q: %v", ErrInvalidPackage, in.Path, err)
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %q is not a regular file", ErrInvalidPackage, in.Path)
	}
	f, err := os.Open(in.Path)
	if err != nil {
		return nil, fmt.Errorf("%w: open %q: %v", ErrInvalidPackage, in.Path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(pathInfo, info) {
		return nil, fmt.Errorf("%w: %q changed while opening", ErrInvalidPackage, in.Path)
	}

	h := sha256.New()
	buffer := rpmHashBufferPool.Get().(*[]byte)
	defer rpmHashBufferPool.Put(buffer)
	if _, err := io.CopyBuffer(h, &contextReader{ctx: ctx, r: f}, *buffer); err != nil {
		return nil, fmt.Errorf("%w: hash %q: %v", ErrInvalidPackage, in.Path, err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("%w: rewind %q: %v", ErrInvalidPackage, in.Path, err)
	}
	reader := rpmReaderPool.Get().(*bufio.Reader)
	reader.Reset(f)
	pkg, err := crpm.Read(reader)
	reader.Reset(strings.NewReader(""))
	rpmReaderPool.Put(reader)
	if err != nil {
		return nil, fmt.Errorf("%w: parse %q: %v", ErrInvalidPackage, in.Path, err)
	}
	if err := validatePackageSizeTags(pkg); err != nil {
		return nil, fmt.Errorf("%w: parse %q: %v", ErrInvalidPackage, in.Path, err)
	}
	afterInfo, err := f.Stat()
	if err != nil || !afterInfo.Mode().IsRegular() || afterInfo.Size() != info.Size() ||
		!afterInfo.ModTime().Equal(info.ModTime()) || afterInfo.Mode() != info.Mode() {
		return nil, fmt.Errorf("%w: %q changed while hashing/parsing", ErrInvalidPackage, in.Path)
	}
	pathAfter, err := os.Lstat(in.Path)
	if err != nil || !pathAfter.Mode().IsRegular() || pathAfter.Mode()&os.ModeSymlink != 0 || !os.SameFile(pathInfo, pathAfter) {
		return nil, fmt.Errorf("%w: %q changed while hashing/parsing", ErrInvalidPackage, in.Path)
	}

	basename := in.Basename
	if basename == "" {
		basename = filepath.Base(in.Path)
	}
	name := tagString(&pkg.Header, tagName)
	managedInput := in.PoolPath != "" || in.ViewPath.String() != "" || in.Location != ""
	location, err := packageLocation(name, basename, managedInput || allowManagedBasename)
	if err != nil {
		return nil, err
	}
	if managedInput {
		if in.PoolPath == "" || in.ViewPath.String() == "" || in.Location == "" {
			return nil, fmt.Errorf("%w: managed package input requires PoolPath, ViewPath, and Location", ErrUnsafeLocation)
		}
		pool, err := ParseManagedPoolPath(in.PoolPath)
		if err != nil || pool.Filename() != basename {
			return nil, fmt.Errorf("%w: managed package PoolPath does not match basename %q", ErrUnsafeLocation, basename)
		}
		_, hrefPool, err := ParseManagedRPMHref(in.Location)
		if err != nil || hrefPool != pool {
			return nil, fmt.Errorf("%w: managed package href does not resolve to PoolPath %q", ErrUnsafeLocation, in.PoolPath)
		}
		view, err := ParseManagedRPMViewPath(in.ViewPath.String())
		wantHref, hrefErr := RPMParentRelativeHref(view, pool)
		if err != nil || hrefErr != nil || view != in.ViewPath || wantHref.String() != in.Location {
			return nil, fmt.Errorf("%w: managed package href is not canonical for ViewPath %q", ErrUnsafeLocation, in.ViewPath.String())
		}
		source := sourceNameFromRPM(tagString(&pkg.Header, tagSourceRPM), name, tagString(&pkg.Header, tagVersion), tagString(&pkg.Header, tagRelease))
		if pool.Source() != source {
			return nil, fmt.Errorf("%w: managed Pool source %q differs from RPM source %q", ErrUnsafeLocation, pool.Source(), source)
		}
		location = in.Location
	}
	architecture, err := normalizedRPMArchitecture(&pkg.Header, basename)
	if err != nil {
		return nil, fmt.Errorf("%w: %q: %v", ErrInvalidPackage, in.Path, err)
	}
	m := &packageMetadata{
		Name:          name,
		Version:       tagString(&pkg.Header, tagVersion),
		Release:       tagString(&pkg.Header, tagRelease),
		Arch:          architecture,
		Epoch:         tagInt(&pkg.Header, tagEpoch),
		Checksum:      hex.EncodeToString(h.Sum(nil)),
		Location:      location,
		Summary:       joinTag(&pkg.Header, tagSummary),
		Description:   joinTag(&pkg.Header, tagDescription),
		Packager:      tagString(&pkg.Header, tagPackager),
		URL:           tagString(&pkg.Header, tagURL),
		FileTime:      info.ModTime().Unix(),
		BuildTime:     tagInt(&pkg.Header, tagBuildTime),
		PackageSize:   info.Size(),
		InstalledSize: pkg.Size(),
		ArchiveSize:   pkg.ArchiveSize(),
		License:       tagString(&pkg.Header, tagLicense),
		Vendor:        tagString(&pkg.Header, tagVendor),
		Group:         tagString(&pkg.Header, tagGroup),
		BuildHost:     tagString(&pkg.Header, tagBuildHost),
		SourceRPM:     tagString(&pkg.Header, tagSourceRPM),
	}
	if m.Provides, err = readDependencies(&pkg.Header, tagProvideNames, tagProvideFlags, tagProvideEVRs, false); err != nil {
		return nil, fmt.Errorf("%w: %q provides: %v", ErrInvalidPackage, in.Path, err)
	}
	if m.Requires, err = readDependencies(&pkg.Header, tagRequireNames, tagRequireFlags, tagRequireEVRs, true); err != nil {
		return nil, fmt.Errorf("%w: %q requires: %v", ErrInvalidPackage, in.Path, err)
	}
	// Keep the header-exact requires for the legacy disposable catalog. The
	// rpm-md renderer deliberately applies createrepo-compatible projection
	// below (weak MISSINGOK split, rpmlib/self/file filtering and deduplication),
	// but that lossy view must not change catalog rebuild semantics.
	m.CatalogRequires = append([]dependency(nil), m.Requires...)
	var legacyRecommends []dependency
	m.Requires, legacyRecommends = partitionLegacyWeakRequires(m.Requires)
	if m.Conflicts, err = readDependencies(&pkg.Header, tagConflictNames, tagConflictFlags, tagConflictEVRs, false); err != nil {
		return nil, fmt.Errorf("%w: %q conflicts: %v", ErrInvalidPackage, in.Path, err)
	}
	if m.Obsoletes, err = readDependencies(&pkg.Header, tagObsoleteNames, tagObsoleteFlags, tagObsoleteEVRs, false); err != nil {
		return nil, fmt.Errorf("%w: %q obsoletes: %v", ErrInvalidPackage, in.Path, err)
	}
	if m.Suggests, err = readDependencies(&pkg.Header, tagSuggestNames, tagSuggestFlags, tagSuggestEVRs, false); err != nil {
		return nil, fmt.Errorf("%w: %q suggests: %v", ErrInvalidPackage, in.Path, err)
	}
	if m.Enhances, err = readDependencies(&pkg.Header, tagEnhanceNames, tagEnhanceFlags, tagEnhanceEVRs, false); err != nil {
		return nil, fmt.Errorf("%w: %q enhances: %v", ErrInvalidPackage, in.Path, err)
	}
	if m.Recommends, err = readDependencies(&pkg.Header, tagRecommendNames, tagRecommendFlags, tagRecommendEVRs, false); err != nil {
		return nil, fmt.Errorf("%w: %q recommends: %v", ErrInvalidPackage, in.Path, err)
	}
	m.Recommends = stableUniqueDependencies(append(m.Recommends, legacyRecommends...), false)
	if m.Supplements, err = readDependencies(&pkg.Header, tagSupplementNames, tagSupplementFlags, tagSupplementEVRs, false); err != nil {
		return nil, fmt.Errorf("%w: %q supplements: %v", ErrInvalidPackage, in.Path, err)
	}
	if m.Files, err = readFiles(&pkg.Header); err != nil {
		return nil, fmt.Errorf("%w: %q files: %v", ErrInvalidPackage, in.Path, err)
	}
	m.Requires = normalizeRPMRequires(m.Requires, m.Provides, m.Files)
	if m.Changelogs, err = readChangelogs(&pkg.Header); err != nil {
		return nil, fmt.Errorf("%w: %q changelogs: %v", ErrInvalidPackage, in.Path, err)
	}
	if !in.FileTime.IsZero() {
		m.FileTime = in.FileTime.Unix()
	}
	m.HeaderStart, m.HeaderEnd = pkg.HeaderRange()
	if m.Name == "" || m.Version == "" || m.Release == "" || m.Arch == "" ||
		!validXMLString(m.Name) || !validXMLString(m.Version) || !validXMLString(m.Release) || !validXMLString(m.Arch) {
		return nil, fmt.Errorf("%w: %q lacks required NEVRA fields", ErrInvalidPackage, in.Path)
	}
	if m.Epoch < 0 || m.FileTime < 0 || m.BuildTime < 0 || m.PackageSize < 0 {
		return nil, fmt.Errorf("%w: %q has negative time or size metadata", ErrInvalidPackage, in.Path)
	}
	return m, nil
}

// CompareEVR applies RPM's native epoch/version/release ordering. It returns a
// negative value when the left EVR is older, zero when equal, and a positive
// value when newer.
func CompareEVR(leftEpoch int64, leftVersion, leftRelease string, rightEpoch int64, rightVersion, rightRelease string) int {
	if leftEpoch < rightEpoch {
		return -1
	}
	if leftEpoch > rightEpoch {
		return 1
	}
	if compared := crpm.CompareVersions(leftVersion, rightVersion); compared != 0 {
		return compared
	}
	return crpm.CompareVersions(leftRelease, rightRelease)
}

func sourceNameFromRPM(sourceRPM, fallback, version, release string) string {
	base := strings.TrimSpace(sourceRPM)
	for _, suffix := range []string{".src.rpm", ".nosrc.rpm"} {
		if strings.HasSuffix(base, suffix) {
			base = strings.TrimSuffix(base, suffix)
			break
		}
	}
	if tail := "-" + version + "-" + release; version != "" && release != "" && strings.HasSuffix(base, tail) {
		base = strings.TrimSuffix(base, tail)
	}
	if base == "" || !safeManagedPackageComponent(base) {
		return fallback
	}
	return base
}

func safeManagedPackageComponent(value string) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	for index := 0; index < len(value); index++ {
		c := value[index]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		switch c {
		case '.', '-', '_', '+', '~', '^', ':', '%':
			continue
		default:
			return false
		}
	}
	return true
}

func normalizedRPMArchitecture(header *crpm.Header, basename string) (string, error) {
	// Filename is not package identity. Source-package rejection and every
	// architecture decision must use the parsed RPM header, so a binary RPM
	// merely renamed to *.src.rpm is still indexed as its real architecture.
	// Valid source RPMs carry src/nosrc in RPMTAG_ARCH and are rejected by the
	// P0 caller after inspection.
	_ = basename
	return tagString(header, tagArch), nil
}

func validatePackageSizeTags(pkg *crpm.Package) error {
	if pkg == nil {
		return fmt.Errorf("nil RPM package")
	}
	checks := []struct {
		label  string
		header *crpm.Header
		tag    int
	}{
		{"long installed size", &pkg.Header, 5009},
		{"installed size", &pkg.Header, 1009},
		{"header long archive size", &pkg.Header, 271},
		{"header archive size", &pkg.Header, 1046},
		{"signature long archive size", &pkg.Signature, 271},
		{"signature archive size", &pkg.Signature, 1007},
	}
	for _, check := range checks {
		if value := check.header.GetTag(check.tag).Int64(); value < 0 {
			return fmt.Errorf("negative %s", check.label)
		}
	}
	return nil
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

func tagString(h *crpm.Header, id int) string    { return h.GetTag(id).String() }
func tagStrings(h *crpm.Header, id int) []string { return h.GetTag(id).StringSlice() }
func tagInt(h *crpm.Header, id int) int64        { return h.GetTag(id).Int64() }
func tagInts(h *crpm.Header, id int) []int64     { return h.GetTag(id).Int64Slice() }
func joinTag(h *crpm.Header, id int) string      { return strings.Join(tagStrings(h, id), "\n") }

func readDependencies(h *crpm.Header, namesID, flagsID, evrsID int, requires bool) ([]dependency, error) {
	names, flags, evrs := tagStrings(h, namesID), tagInts(h, flagsID), tagStrings(h, evrsID)
	if len(names) != len(flags) || len(names) != len(evrs) {
		return nil, fmt.Errorf("misaligned RPM dependency tags: names=%d flags=%d evrs=%d", len(names), len(flags), len(evrs))
	}
	out := make([]dependency, 0, len(names))
	for i, name := range names {
		if name == "" || !validXMLString(name) {
			return nil, fmt.Errorf("invalid dependency name at index %d", i)
		}
		rawFlags, evr := flags[i], evrs[i]
		if !validXMLString(evr) {
			return nil, fmt.Errorf("invalid dependency EVR at index %d", i)
		}
		epoch, version, release := splitEVR(evr)
		out = append(out, dependency{
			Name: name, Flags: dependencyFlags(rawFlags), Epoch: epoch,
			Version: version, Release: release,
			Pre:       requires && rawFlags&((1<<5)|(1<<6)|(1<<7)|(1<<9)|(1<<10)) != 0,
			MissingOK: requires && rawFlags&(1<<19) != 0,
		})
	}
	return out, nil
}

func partitionLegacyWeakRequires(requires []dependency) (hard, weak []dependency) {
	for _, dep := range requires {
		if dep.MissingOK {
			dep.MissingOK = false
			dep.Pre = false
			weak = append(weak, dep)
			continue
		}
		hard = append(hard, dep)
	}
	return hard, weak
}

func stableUniqueDependencies(dependencies []dependency, includePre bool) []dependency {
	seen := make(map[dependencyIdentity]struct{}, len(dependencies))
	result := make([]dependency, 0, len(dependencies))
	for _, dep := range dependencies {
		identity := identityOfDependency(dep, includePre)
		if _, duplicate := seen[identity]; duplicate {
			continue
		}
		seen[identity] = struct{}{}
		result = append(result, dep)
	}
	return result
}

func dependencyFlags(flags int64) string {
	less, greater, equal := flags&(1<<1) != 0, flags&(1<<2) != 0, flags&(1<<3) != 0
	switch {
	case less && equal:
		return "LE"
	case greater && equal:
		return "GE"
	case less:
		return "LT"
	case greater:
		return "GT"
	case equal:
		return "EQ"
	default:
		return ""
	}
}

type dependencyIdentity struct {
	Name, Flags, Epoch, Version, Release string
	Pre                                  bool
}

func identityOfDependency(dep dependency, includePre bool) dependencyIdentity {
	return dependencyIdentity{
		Name: dep.Name, Flags: dep.Flags, Epoch: dep.Epoch, Version: dep.Version, Release: dep.Release,
		Pre: includePre && dep.Pre,
	}
}

// normalizeRPMRequires follows the projection used by createrepo_c rather
// than copying every raw RPMTAG_REQUIRE* row into primary.xml. RPM's rpmlib
// capabilities are internal to RPM, primary files owned by the same package
// are already represented as files, exact self-provides are redundant, and
// repeated requirements add no solver information. The historical yum format
// also retains only the highest libc.so.6 symbol requirement.
func normalizeRPMRequires(requires, provides []dependency, files []rpmFile) []dependency {
	provided := make(map[dependencyIdentity]struct{}, len(provides))
	for _, dep := range provides {
		provided[identityOfDependency(dep, false)] = struct{}{}
	}
	ownedPrimaryFiles := make(map[string]struct{})
	for _, file := range files {
		if isPrimaryRPMFile(file.Name) {
			ownedPrimaryFiles[file.Name] = struct{}{}
		}
	}

	lastByName := make(map[string]dependencyIdentity)
	result := make([]dependency, 0, len(requires))
	var highestLibc *dependency
	for _, dep := range requires {
		if strings.HasPrefix(dep.Name, "rpmlib(") {
			continue
		}
		if strings.HasPrefix(dep.Name, "/") {
			if _, owned := ownedPrimaryFiles[dep.Name]; owned {
				continue
			}
		}
		if _, selfProvided := provided[identityOfDependency(dep, false)]; selfProvided {
			continue
		}
		identity := identityOfDependency(dep, true)
		if previous, seen := lastByName[dep.Name]; seen && previous == identity {
			continue
		}
		if strings.HasPrefix(dep.Name, "libc.so.6") {
			if highestLibc == nil || compareLibcRequirement(highestLibc.Name, dep.Name) < 0 {
				candidate := dep
				highestLibc = &candidate
			}
			continue
		}
		result = append(result, dep)
		lastByName[dep.Name] = identity
	}
	if highestLibc != nil {
		result = append(result, *highestLibc)
	}
	return result
}

func isPrimaryRPMFile(name string) bool {
	return strings.HasPrefix(name, "/etc/") || name == "/usr/lib/sendmail" || strings.Contains(name, "bin/")
}

// compareLibcRequirement compares the first parenthesized symbol versions in
// libc.so.6 requirements. It returns a negative number when left is older.
func compareLibcRequirement(left, right string) int {
	leftVersion, leftVersioned := libcRequirementVersion(left)
	rightVersion, rightVersioned := libcRequirementVersion(right)
	switch {
	case leftVersioned && !rightVersioned:
		return 1
	case !leftVersioned && rightVersioned:
		return -1
	case !leftVersioned:
		return 0
	default:
		return crpm.CompareVersions(leftVersion, rightVersion)
	}
}

func libcRequirementVersion(name string) (string, bool) {
	start := strings.IndexByte(name, '(')
	if start < 0 {
		return "", false
	}
	endRelative := strings.IndexByte(name[start+1:], ')')
	if endRelative < 0 {
		return "", false
	}
	content := name[start+1 : start+1+endRelative]
	firstDigit := strings.IndexFunc(content, func(r rune) bool { return r >= '0' && r <= '9' })
	if firstDigit < 0 {
		return "", false
	}
	return content[firstDigit:], true
}

func splitEVR(evr string) (epoch, version, release string) {
	if evr == "" {
		return "", "", ""
	}
	if i := strings.IndexByte(evr, ':'); i >= 0 {
		epoch, evr = evr[:i], evr[i+1:]
	} else {
		epoch = "0"
	}
	if i := strings.LastIndexByte(evr, '-'); i >= 0 {
		version, release = evr[:i], evr[i+1:]
	} else {
		version = evr
	}
	return epoch, version, release
}

func readFiles(h *crpm.Header) ([]rpmFile, error) {
	base, dirs, indexes := tagStrings(h, tagBaseNames), tagStrings(h, tagDirNames), tagInts(h, tagDirIndexes)
	modes, flags := tagInts(h, tagFileModes), tagInts(h, tagFileFlags)
	if len(base) == 0 {
		base = tagStrings(h, tagOldFilenames)
		dirs, indexes = nil, nil
	} else if len(indexes) != len(base) || len(dirs) == 0 {
		return nil, fmt.Errorf("misaligned RPM file path tags: basenames=%d dirindexes=%d dirnames=%d", len(base), len(indexes), len(dirs))
	}
	if len(modes) != len(base) {
		return nil, fmt.Errorf("misaligned RPM file modes: files=%d modes=%d", len(base), len(modes))
	}
	if len(flags) != 0 && len(flags) != len(base) {
		return nil, fmt.Errorf("misaligned RPM file flags: files=%d flags=%d", len(base), len(flags))
	}
	out := make([]rpmFile, 0, len(base))
	for i, basename := range base {
		name := basename
		if len(dirs) > 0 {
			if indexes[i] < 0 || indexes[i] >= int64(len(dirs)) {
				return nil, fmt.Errorf("file %d has out-of-range directory index %d", i, indexes[i])
			}
			name = dirs[indexes[i]] + basename
		}
		if name == "" || !validXMLString(name) {
			return nil, fmt.Errorf("invalid file path at index %d", i)
		}
		mode, flag := modes[i], int64(0)
		if i < len(flags) {
			flag = flags[i]
		}
		out = append(out, rpmFile{Name: name, Mode: mode, Flags: flag})
	}
	return out, nil
}

func readChangelogs(h *crpm.Header) ([]changelog, error) {
	names, dates, texts := tagStrings(h, tagChangelogName), tagInts(h, tagChangelogTime), tagStrings(h, tagChangelogText)
	if len(names) != len(dates) || len(names) != len(texts) {
		return nil, fmt.Errorf("misaligned RPM changelog tags: names=%d dates=%d texts=%d", len(names), len(dates), len(texts))
	}
	// RPM stores changelogs newest first. createrepo_c's current default keeps
	// the newest ten, emits them oldest first, and makes equal timestamps
	// strictly increasing so libdnf presents the newest entry first.
	const createrepoChangelogLimit = 10
	count := len(names)
	if count > createrepoChangelogLimit {
		count = createrepoChangelogLimit
	}
	out := make([]changelog, 0, count)
	for i := count - 1; i >= 0; i-- {
		date := dates[i]
		if len(out) != 0 && date <= out[len(out)-1].Date {
			date = out[len(out)-1].Date + 1
		}
		out = append(out, changelog{Author: names[i], Date: date, Text: texts[i]})
	}
	return out, nil
}
