package yumrepo

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	crpm "github.com/cavaliergopher/rpm"
)

const PackageFactsSchema = "yumrepo/package-facts/v1"

var factsSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// PackageFacts is the view-independent rpm-md projection parsed once at
// ingestion. Its internals stay opaque so callers cannot mutate cached facts.
type PackageFacts struct {
	metadata *packageMetadata
}

// ParsedManagedPackage is one immutable facts record projected into a single
// managed RPM view/href. GenerateManagedParsed consumes it without opening the
// RPM payload.
type ParsedManagedPackage struct {
	metadata *packageMetadata
}

type packageFactsEnvelope struct {
	Schema   string          `json:"schema"`
	Metadata packageMetadata `json:"metadata"`
}

func InspectManagedPackageFacts(ctx context.Context, input PackageInput) (*PackageFacts, PackageInfo, error) {
	if input.PoolPath != "" || input.ViewPath.String() != "" || input.Location != "" {
		return nil, PackageInfo{}, fmt.Errorf("%w: fact inspection carries managed placement", ErrUnsafeLocation)
	}
	if input.Basename == "" {
		input.Basename = filepath.Base(input.Path)
	}
	input.FileTime = unixEpoch
	metadata, err := readPackageWithManagedBasename(ctx, input, true)
	if err != nil {
		return nil, PackageInfo{}, err
	}
	metadata.Location = ""
	metadata.FileTime = 0
	if err := validatePackageFactsMetadata(metadata); err != nil {
		return nil, PackageInfo{}, err
	}
	return &PackageFacts{metadata: metadata}, packageInfo(metadata), nil
}

// InspectManagedPackageFactsReaderKnown parses the bounded RPM headers after
// the caller has already copied and authenticated the complete descriptor.
// It trusts only the supplied SHA/size identity and performs no payload pass.
func InspectManagedPackageFactsReaderKnown(ctx context.Context, input io.ReadSeeker, originalBasename, digest string, size int64) (*PackageFacts, PackageInfo, error) {
	if ctx == nil {
		return nil, PackageInfo{}, errors.New("yumrepo: nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, PackageInfo{}, err
	}
	if input == nil || !factsSHA256Pattern.MatchString(digest) || size < 0 || originalBasename == "" ||
		path.Base(originalBasename) != originalBasename || filepath.Base(originalBasename) != originalBasename || !safeManagedRPMBasename(originalBasename) {
		return nil, PackageInfo{}, fmt.Errorf("%w: invalid known RPM identity", ErrInvalidPackage)
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return nil, PackageInfo{}, fmt.Errorf("%w: rewind RPM facts reader: %v", ErrInvalidPackage, err)
	}
	reader := rpmReaderPool.Get().(*bufio.Reader)
	reader.Reset(input)
	pkg, err := crpm.Read(reader)
	reader.Reset(strings.NewReader(""))
	rpmReaderPool.Put(reader)
	if err != nil {
		return nil, PackageInfo{}, fmt.Errorf("%w: parse RPM facts reader: %v", ErrInvalidPackage, err)
	}
	if err := validatePackageSizeTags(pkg); err != nil {
		return nil, PackageInfo{}, fmt.Errorf("%w: parse RPM facts reader: %v", ErrInvalidPackage, err)
	}
	metadata, err := packageMetadataFromParsedRPM(pkg, PackageInput{Path: "authenticated-rpm", Basename: originalBasename, FileTime: unixEpoch}, originalBasename, digest, size, 0, true)
	if err != nil {
		return nil, PackageInfo{}, err
	}
	metadata.Location = ""
	metadata.FileTime = 0
	if err := validatePackageFactsMetadata(metadata); err != nil {
		return nil, PackageInfo{}, err
	}
	return &PackageFacts{metadata: metadata}, packageInfo(metadata), nil
}

func (facts *PackageFacts) MarshalBinary() ([]byte, error) {
	if facts == nil || facts.metadata == nil {
		return nil, fmt.Errorf("%w: nil RPM package facts", ErrInvalidPackage)
	}
	if err := validatePackageFactsMetadata(facts.metadata); err != nil {
		return nil, err
	}
	return json.Marshal(packageFactsEnvelope{Schema: PackageFactsSchema, Metadata: *facts.metadata})
}

func ParsePackageFacts(data []byte) (*PackageFacts, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var envelope packageFactsEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("%w: decode RPM package facts: %v", ErrInvalidPackage, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: RPM package facts contain trailing data", ErrInvalidPackage)
	}
	if envelope.Schema != PackageFactsSchema {
		return nil, fmt.Errorf("%w: unsupported RPM package facts schema", ErrInvalidPackage)
	}
	if err := validatePackageFactsMetadata(&envelope.Metadata); err != nil {
		return nil, err
	}
	return &PackageFacts{metadata: &envelope.Metadata}, nil
}

func (facts *PackageFacts) PackageInfo() (PackageInfo, error) {
	if facts == nil || facts.metadata == nil {
		return PackageInfo{}, fmt.Errorf("%w: nil RPM package facts", ErrInvalidPackage)
	}
	if err := validatePackageFactsMetadata(facts.metadata); err != nil {
		return PackageInfo{}, err
	}
	return packageInfo(facts.metadata), nil
}

func ProjectManagedPackageFacts(facts *PackageFacts, input PackageInput) (*ParsedManagedPackage, error) {
	if facts == nil || facts.metadata == nil {
		return nil, fmt.Errorf("%w: nil RPM package facts", ErrInvalidPackage)
	}
	if err := validatePackageFactsMetadata(facts.metadata); err != nil {
		return nil, err
	}
	if input.PoolPath == "" || input.ViewPath.String() == "" || input.Location == "" {
		return nil, fmt.Errorf("%w: managed fact projection requires PoolPath, ViewPath, and Location", ErrUnsafeLocation)
	}
	basename := input.Basename
	if basename == "" {
		basename = filepath.Base(input.Path)
	}
	pool, err := ParseManagedPoolPath(input.PoolPath)
	if err != nil || pool.Filename() != basename {
		return nil, fmt.Errorf("%w: managed package PoolPath does not match basename %q", ErrUnsafeLocation, basename)
	}
	_, hrefPool, err := ParseManagedRPMHref(input.Location)
	if err != nil || hrefPool != pool {
		return nil, fmt.Errorf("%w: managed package href does not resolve to PoolPath %q", ErrUnsafeLocation, input.PoolPath)
	}
	view, err := ParseManagedRPMViewPath(input.ViewPath.String())
	wantHref, hrefErr := RPMParentRelativeHref(view, pool)
	if err != nil || hrefErr != nil || view != input.ViewPath || wantHref.String() != input.Location {
		return nil, fmt.Errorf("%w: managed package href is not canonical for ViewPath %q", ErrUnsafeLocation, input.ViewPath.String())
	}
	source := sourceNameFromRPM(facts.metadata.SourceRPM, facts.metadata.Name, facts.metadata.Version, facts.metadata.Release)
	if pool.Source() != source {
		return nil, fmt.Errorf("%w: managed Pool source %q differs from RPM source %q", ErrUnsafeLocation, pool.Source(), source)
	}
	metadata := *facts.metadata
	metadata.Location = input.Location
	metadata.FileTime = 0
	return &ParsedManagedPackage{metadata: &metadata}, nil
}

func validatePackageFactsMetadata(metadata *packageMetadata) error {
	if metadata == nil || metadata.Name == "" || metadata.Version == "" || metadata.Release == "" || metadata.Arch == "" ||
		!validXMLString(metadata.Name) || !validXMLString(metadata.Version) || !validXMLString(metadata.Release) || !validXMLString(metadata.Arch) {
		return fmt.Errorf("%w: RPM package facts lack required NEVRA fields", ErrInvalidPackage)
	}
	if !factsSHA256Pattern.MatchString(metadata.Checksum) || metadata.PackageSize < 0 || metadata.Epoch < 0 || metadata.FileTime != 0 || metadata.BuildTime < 0 || metadata.Location != "" || metadata.HeaderStart < 0 || metadata.HeaderEnd < metadata.HeaderStart {
		return fmt.Errorf("%w: RPM package facts have invalid identity or sizes", ErrInvalidPackage)
	}
	stringsToCheck := []string{
		metadata.Summary, metadata.Description, metadata.Packager, metadata.URL, metadata.License, metadata.Vendor,
		metadata.Group, metadata.BuildHost, metadata.SourceRPM,
	}
	for _, value := range stringsToCheck {
		if !validXMLString(value) {
			return fmt.Errorf("%w: RPM package facts contain invalid text", ErrInvalidPackage)
		}
	}
	dependencySets := [][]dependency{
		metadata.Provides, metadata.Requires, metadata.CatalogRequires, metadata.Conflicts, metadata.Obsoletes,
		metadata.Suggests, metadata.Enhances, metadata.Recommends, metadata.Supplements,
	}
	for _, dependencies := range dependencySets {
		for _, dependency := range dependencies {
			if dependency.Name == "" || !validXMLString(dependency.Name) || !validXMLString(dependency.Flags) || !validXMLString(dependency.Epoch) || !validXMLString(dependency.Version) || !validXMLString(dependency.Release) {
				return fmt.Errorf("%w: RPM package facts contain invalid dependency", ErrInvalidPackage)
			}
		}
	}
	for _, file := range metadata.Files {
		if file.Name == "" || !validXMLString(file.Name) || file.Mode < 0 || file.Flags < 0 {
			return fmt.Errorf("%w: RPM package facts contain invalid file metadata", ErrInvalidPackage)
		}
	}
	for _, entry := range metadata.Changelogs {
		if entry.Date < 0 || !validXMLString(entry.Author) || !validXMLString(entry.Text) {
			return fmt.Errorf("%w: RPM package facts contain invalid changelog", ErrInvalidPackage)
		}
	}
	return nil
}
