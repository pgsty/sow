package verify

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/pgsty/sow/internal/manifest"
)

// APTPackageIdentityEntry projects the signed Packages identity separately
// from its payload checksum. IndexArchitecture names the Packages index while
// PackageArchitecture preserves the paragraph's exact Architecture value,
// including the Debian "all" case.
func APTPackageIdentityEntry(suite, indexArchitecture, name, version, packageArchitecture, component, filename string, size int64, sha string) (manifest.Entry, error) {
	if !safeSegment(suite) || !aptArchName.MatchString(indexArchitecture) || !aptPackageName.MatchString(name) || !aptArchName.MatchString(packageArchitecture) ||
		!safeSegment(component) || !safeRelative(filename) || size < 0 || !lowerSHA256(sha) {
		return manifest.Entry{}, errors.New("invalid APT canonical package identity")
	}
	key := path.Join("apt", suite, indexArchitecture, component, filename)
	return packageIdentityEntry(key, []string{suite, indexArchitecture, name, version, packageArchitecture, component, filename, strconv.FormatInt(size, 10), sha})
}

// APTPackageBodyIdentityEntry is the index-independent identity used to prove
// that every signed Packages paragraph describes the DEB body at Filename.
// A single Architecture: all package may occur in several binary indexes; the
// filename key deliberately coalesces those identical references while still
// rejecting any signed identity conflict for the shared body.
func APTPackageBodyIdentityEntry(name, version, packageArchitecture, component, filename string, size int64, sha string) (manifest.Entry, error) {
	if !aptPackageName.MatchString(name) || !aptArchName.MatchString(packageArchitecture) || !safeSegment(component) ||
		!safeRelative(filename) || size < 0 || !lowerSHA256(sha) {
		return manifest.Entry{}, errors.New("invalid APT package body identity")
	}
	return packageIdentityEntry(filename, []string{name, version, packageArchitecture, component, filename, strconv.FormatInt(size, 10), sha})
}

// YUMPackageIdentityEntry binds the full primary.xml NEVRA and location to the
// same size/checksum closure used for payload verification.
func YUMPackageIdentityEntry(name string, epoch int64, version, release, architecture, location string, size int64, sha string) (manifest.Entry, error) {
	if !yumIdentitySegment.MatchString(name) || epoch < 0 || !safeYUMVersionValue(version) || !safeYUMVersionValue(release) ||
		!yumIdentitySegment.MatchString(architecture) || !safeRelative(location) || size < 0 || !lowerSHA256(sha) {
		return manifest.Entry{}, errors.New("invalid YUM canonical package identity")
	}
	return packageIdentityEntry(location, []string{name, strconv.FormatInt(epoch, 10), version, release, architecture, location, strconv.FormatInt(size, 10), sha})
}

func packageIdentityEntry(key string, fields []string) (manifest.Entry, error) {
	if !safeRelative(key) {
		return manifest.Entry{}, fmt.Errorf("unsafe package identity key %q", key)
	}
	for _, field := range fields {
		if field == "" || strings.ContainsAny(field, "\x00\r\n\t") {
			return manifest.Entry{}, errors.New("unsafe empty package identity field")
		}
	}
	body := []byte(strings.Join(fields, "\x00"))
	digest := sha256.Sum256(body)
	return manifest.Entry{Path: key, Size: int64(len(body)), SHA256: digest}, nil
}
