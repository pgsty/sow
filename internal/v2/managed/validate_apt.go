package managed

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pgsty/sow/internal/v2/state"
	"pault.ag/go/debian/control"
	debversion "pault.ag/go/debian/version"
)

type releaseChecksum struct {
	digest string
	size   int64
}

// validateManagedAPTDist is retained for lifecycle path validation, where the
// caller may not yet have a frozen verifier but must still reject a partial
// InRelease/Release.gpg pair. Full `sow check` reports index and signature as
// separate layers through the two narrower validators below.
func validateManagedAPTDist(ctx context.Context, repositoryRoot, distName string, architectures []state.Architecture, verifier APTMetadataVerifier, expectedSigning *bool, expectedPackages map[string]map[string]state.PackageObject) error {
	if err := validateManagedAPTIndex(ctx, repositoryRoot, distName, architectures, expectedPackages, nil); err != nil {
		return err
	}
	if expectedSigning != nil {
		return validateManagedAPTSignature(ctx, repositoryRoot, distName, verifier, *expectedSigning)
	}
	_, inErr := readOptionalBoundedRegular(repositoryRoot, filepath.ToSlash(filepath.Join("dists", distName, "InRelease")), 16<<20)
	_, detachedErr := readOptionalBoundedRegular(repositoryRoot, filepath.ToSlash(filepath.Join("dists", distName, "Release.gpg")), 16<<20)
	if errors.Is(inErr, os.ErrNotExist) && errors.Is(detachedErr, os.ErrNotExist) {
		return nil
	} else if inErr != nil || detachedErr != nil {
		return errors.New("InRelease and Release.gpg must be a complete safe pair")
	}
	if verifier != nil {
		return validateManagedAPTSignature(ctx, repositoryRoot, distName, verifier, true)
	}
	return nil
}

func validateManagedAPTIndex(ctx context.Context, repositoryRoot, distName string, architectures []state.Architecture, expectedPackages map[string]map[string]state.PackageObject, expectedGeneration *int64) error {
	releaseRelative := filepath.ToSlash(filepath.Join("dists", distName, "Release"))
	release, err := readRootedRegular(repositoryRoot, releaseRelative, 16<<20, false)
	if err != nil {
		return fmt.Errorf("Release is missing, unsafe, or unbounded: %w", err)
	}
	if err := validateManagedAPTReleaseFields(release, distName, architectures, expectedGeneration != nil); err != nil {
		return err
	}
	checksums, err := parseReleaseSHA256(release)
	if err != nil {
		return err
	}
	if _, err := parseReleaseDate(release); err != nil {
		return err
	}
	generation, present, err := parseReleaseGeneration(release)
	if err != nil {
		return err
	}
	if expectedGeneration != nil && (!present || generation != *expectedGeneration) {
		return fmt.Errorf("Release generation=%d present=%t, want %d", generation, present, *expectedGeneration)
	}
	expectedReleasePaths := map[string]struct{}{}
	for _, architecture := range architectures {
		plainRelativeRoot := filepath.ToSlash(filepath.Join("dists", distName, "main", "binary-"+architecture.EcosystemArch, "Packages"))
		plainDigest, plainSize, err := digestManagedIndex(ctx, repositoryRoot, plainRelativeRoot, false)
		if err != nil {
			return err
		}
		decodedDigest, decodedSize, err := digestManagedIndex(ctx, repositoryRoot, plainRelativeRoot+".gz", true)
		if err != nil || decodedDigest != plainDigest || decodedSize != plainSize {
			return fmt.Errorf("Packages.gz does not expand exactly to Packages for %s", architecture.EcosystemArch)
		}
		gzipDigest, gzipSize, err := digestManagedIndex(ctx, repositoryRoot, plainRelativeRoot+".gz", false)
		if err != nil {
			return err
		}
		plainRelative := filepath.ToSlash(filepath.Join("main", "binary-"+architecture.EcosystemArch, "Packages"))
		for relative, want := range map[string]releaseChecksum{
			plainRelative:         {digest: plainDigest, size: plainSize},
			plainRelative + ".gz": {digest: gzipDigest, size: gzipSize},
		} {
			got, ok := checksums[relative]
			if !ok || got != want {
				return fmt.Errorf("Release SHA256 entry for %s differs", relative)
			}
			expectedReleasePaths[relative] = struct{}{}
			indexedRelative := filepath.ToSlash(filepath.Join("dists", distName, filepath.FromSlash(relative)))
			byHashRelative := filepath.ToSlash(filepath.Join(filepath.Dir(indexedRelative), "by-hash", "SHA256", want.digest))
			same, err := sameRootedRegularFile(repositoryRoot, indexedRelative, byHashRelative)
			if errors.Is(err, os.ErrNotExist) && plainSize == 0 {
				// Schema-v1/P1 empty Dists predate managed by-hash projection.
				// The first non-empty build replaces them with the full shape.
				continue
			}
			if err != nil || !same {
				return fmt.Errorf("by-hash entry for %s is not its regular hardlink", relative)
			}
		}
		if err := validateManagedPackagesParagraphs(ctx, repositoryRoot, plainRelativeRoot, architecture.EcosystemArch, expectedPackages[architecture.EcosystemArch]); err != nil {
			return err
		}
	}
	if len(checksums) != len(expectedReleasePaths) {
		return fmt.Errorf("Release SHA256 contains %d entries, want exactly %d", len(checksums), len(expectedReleasePaths))
	}
	for relative := range checksums {
		if _, ok := expectedReleasePaths[relative]; !ok {
			return fmt.Errorf("Release SHA256 contains unexpected path %s", relative)
		}
	}
	return nil
}

func validateManagedAPTReleaseFields(data []byte, distName string, architectures []state.Architecture, requireGeneration bool) error {
	fields := map[string]string{}
	inChecksums := false
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		if line == "SHA256:" {
			if inChecksums {
				return errors.New("Release repeats SHA256")
			}
			inChecksums = true
			continue
		}
		if inChecksums {
			if !strings.HasPrefix(line, " ") {
				return errors.New("Release contains a field after SHA256")
			}
			continue
		}
		key, value, found := strings.Cut(line, ":")
		if !found || key == "" || strings.TrimSpace(key) != key || !strings.HasPrefix(value, " ") {
			return errors.New("Release has an invalid field")
		}
		value = strings.TrimSpace(value)
		if _, duplicate := fields[key]; duplicate {
			return fmt.Errorf("Release repeats %s", key)
		}
		fields[key] = value
	}
	if !inChecksums {
		return errors.New("Release omits SHA256")
	}
	expectedArchitectures := make([]string, 0, len(architectures))
	for _, architecture := range architectures {
		expectedArchitectures = append(expectedArchitectures, architecture.EcosystemArch)
	}
	sort.Strings(expectedArchitectures)
	expected := map[string]string{
		"Origin": "SOW", "Label": distName, "Suite": distName, "Codename": distName,
		"Architectures": strings.Join(expectedArchitectures, " "), "Components": "main",
		"Acquire-By-Hash": "yes", "Description": "SOW managed distribution",
	}
	for key, value := range expected {
		if fields[key] != value {
			return fmt.Errorf("Release %s=%q, want %q", key, fields[key], value)
		}
	}
	allowed := map[string]struct{}{"Date": {}, "X-SOW-Generation": {}}
	for key := range expected {
		allowed[key] = struct{}{}
	}
	for key := range fields {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("Release contains unexpected field %s", key)
		}
	}
	date, err := time.Parse(time.RFC1123, fields["Date"])
	if err != nil || date.UTC().Format(time.RFC1123) != fields["Date"] {
		return errors.New("Release Date is absent or non-canonical")
	}
	if requireGeneration && fields["X-SOW-Generation"] == "" {
		return errors.New("Release omits X-SOW-Generation")
	}
	return nil
}

func validateManagedAPTSignature(ctx context.Context, repositoryRoot, distName string, verifier APTMetadataVerifier, signed bool) error {
	releaseRelative := filepath.ToSlash(filepath.Join("dists", distName, "Release"))
	release, err := readRootedRegular(repositoryRoot, releaseRelative, 16<<20, false)
	if err != nil {
		return fmt.Errorf("Release is missing, unsafe, or unbounded: %w", err)
	}
	releaseTime, err := parseReleaseDate(release)
	if err != nil {
		return err
	}
	inRelease, inErr := readOptionalBoundedRegular(repositoryRoot, filepath.ToSlash(filepath.Join("dists", distName, "InRelease")), 16<<20)
	detached, detachedErr := readOptionalBoundedRegular(repositoryRoot, filepath.ToSlash(filepath.Join("dists", distName, "Release.gpg")), 16<<20)
	present := inErr == nil && detachedErr == nil
	if errors.Is(inErr, os.ErrNotExist) && errors.Is(detachedErr, os.ErrNotExist) {
		present = false
	} else if inErr != nil || detachedErr != nil {
		return errors.New("InRelease and Release.gpg must be a complete safe pair")
	}
	if present != signed {
		return fmt.Errorf("APT metadata signature presence=%t want=%t", present, signed)
	}
	if !signed {
		return nil
	}
	if verifier == nil {
		return errors.New("retained APT metadata verifier is unavailable")
	}
	if err := verifier.Verify(ctx, release, inRelease, detached, releaseTime); err != nil {
		return fmt.Errorf("verify APT metadata signature: %w", err)
	}
	return nil
}

func parseReleaseDate(data []byte) (time.Time, error) {
	value := ""
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "Date:") {
			continue
		}
		if value != "" {
			return time.Time{}, errors.New("Release repeats Date")
		}
		value = strings.TrimSpace(strings.TrimPrefix(line, "Date:"))
	}
	parsed, err := time.Parse(time.RFC1123, value)
	if err != nil {
		return time.Time{}, errors.New("Release has an invalid Date")
	}
	return parsed.UTC(), nil
}

func parseReleaseGeneration(data []byte) (int64, bool, error) {
	value := ""
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "X-SOW-Generation:") {
			continue
		}
		if value != "" {
			return 0, false, errors.New("Release repeats X-SOW-Generation")
		}
		value = strings.TrimSpace(strings.TrimPrefix(line, "X-SOW-Generation:"))
	}
	if value == "" {
		return 0, false, nil
	}
	generation, err := strconv.ParseInt(value, 10, 64)
	if err != nil || generation < 1 || strconv.FormatInt(generation, 10) != value {
		return 0, false, errors.New("Release has an invalid X-SOW-Generation")
	}
	return generation, true, nil
}

func readOptionalBoundedRegular(root, relative string, maximum int64) ([]byte, error) {
	return readRootedRegular(root, relative, maximum, false)
}

func parseReleaseSHA256(data []byte) (map[string]releaseChecksum, error) {
	lines := strings.Split(string(data), "\n")
	result := map[string]releaseChecksum{}
	inSHA := false
	for _, line := range lines {
		if line == "SHA256:" {
			inSHA = true
			continue
		}
		if !inSHA {
			continue
		}
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			break
		}
		fields := strings.Fields(line)
		if len(fields) != 3 || !lowercaseSHA256.MatchString(fields[0]) || strings.ContainsAny(fields[2], "\\\x00\r\n\t") || filepath.IsAbs(fields[2]) || filepath.Clean(fields[2]) != filepath.FromSlash(fields[2]) {
			return nil, errors.New("invalid Release SHA256 entry")
		}
		size, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || size < 0 {
			return nil, errors.New("invalid Release SHA256 size")
		}
		if _, duplicate := result[fields[2]]; duplicate {
			return nil, errors.New("duplicate Release SHA256 path")
		}
		result[fields[2]] = releaseChecksum{digest: fields[0], size: size}
	}
	return result, nil
}

func digestManagedIndex(ctx context.Context, root, relative string, compressed bool) (string, int64, error) {
	opened, err := openRootedRegular(root, relative)
	if err != nil {
		return "", 0, err
	}
	var reader io.Reader = opened.file
	var zipper *gzip.Reader
	if compressed {
		zipper, err = gzip.NewReader(opened.file)
		if err != nil {
			_ = opened.CloseVerified()
			return "", 0, err
		}
		reader = zipper
	}
	hash := sha256.New()
	size, copyErr := io.Copy(hash, &managedContextReader{ctx: ctx, reader: reader})
	var gzipErr error
	if zipper != nil {
		gzipErr = zipper.Close()
	}
	if err := errors.Join(copyErr, gzipErr, opened.CloseVerified()); err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func validateManagedPackagesParagraphs(ctx context.Context, repositoryRoot, relative, nativeArch string, expected map[string]state.PackageObject) error {
	opened, err := openRootedRegular(repositoryRoot, relative)
	if err != nil {
		return err
	}
	finish := func(cause error) error { return errors.Join(cause, opened.CloseVerified()) }
	reader, err := control.NewParagraphReader(opened.file, nil)
	if err != nil {
		return finish(err)
	}
	seen := map[string]struct{}{}
	seenSHA := map[string]struct{}{}
	for {
		if err := ctx.Err(); err != nil {
			return finish(err)
		}
		paragraph, err := reader.Next()
		if errors.Is(err, io.EOF) {
			if closeErr := finish(nil); closeErr != nil {
				return closeErr
			}
			if expected != nil {
				if len(seenSHA) != len(expected) {
					return fmt.Errorf("managed Packages contains %d package objects, want %d from Built state", len(seenSHA), len(expected))
				}
				for digest := range expected {
					if _, ok := seenSHA[digest]; !ok {
						return errors.New("managed Packages omits a Built package object")
					}
				}
			}
			return nil
		}
		if err != nil {
			return finish(err)
		}
		values := paragraph.Values
		name, versionText, arch := values["Package"], values["Version"], values["Architecture"]
		parsedVersion, versionErr := debversion.Parse(versionText)
		if name == "" || versionErr != nil || (arch != nativeArch && arch != "all") || !lowercaseSHA256.MatchString(values["SHA256"]) {
			return finish(errors.New("invalid managed Packages identity"))
		}
		canonicalVersion := parsedVersion.String()
		size, err := strconv.ParseInt(values["Size"], 10, 64)
		if err != nil || size < 0 {
			return finish(errors.New("invalid managed Packages size"))
		}
		source := strings.Fields(values["Source"])
		sourceName := name
		if len(source) != 0 {
			sourceName = source[0]
		}
		want, err := managedPoolPath(sourceName, filepath.Base(values["Filename"]))
		if err != nil || want != values["Filename"] {
			return finish(errors.New("invalid managed Packages Filename"))
		}
		pool, err := openRootedRegular(repositoryRoot, want)
		if err != nil || pool.before.Size() != size {
			if pool != nil {
				_ = pool.CloseVerified()
			}
			return finish(errors.New("managed Packages references missing Pool bytes"))
		}
		poolHash := sha256.New()
		_, hashErr := io.Copy(poolHash, &managedContextReader{ctx: ctx, reader: pool.file})
		poolErr := pool.CloseVerified()
		if hashErr != nil || poolErr != nil || hex.EncodeToString(poolHash.Sum(nil)) != values["SHA256"] {
			return finish(errors.New("managed Packages checksum differs from Pool bytes"))
		}
		coordinate := name + "\x00" + canonicalVersion + "\x00" + arch
		if _, duplicate := seen[coordinate]; duplicate {
			return finish(errors.New("duplicate managed Packages coordinate"))
		}
		seen[coordinate] = struct{}{}
		if expected != nil {
			object, ok := expected[values["SHA256"]]
			if !ok || object.Name != name || object.Version != canonicalVersion || object.Architecture != arch || object.Size != size || object.PoolPath != want || object.Source != sourceName {
				return finish(errors.New("managed Packages facts differ from Built state"))
			}
		}
		if _, duplicate := seenSHA[values["SHA256"]]; duplicate {
			return finish(errors.New("managed Packages repeats a package object"))
		}
		seenSHA[values["SHA256"]] = struct{}{}
	}
}

func sameRootedRegularFile(root, leftRelative, rightRelative string) (bool, error) {
	left, err := openRootedRegular(root, leftRelative)
	if err != nil {
		return false, err
	}
	right, err := openRootedRegular(root, rightRelative)
	if err != nil {
		return false, errors.Join(err, left.CloseVerified())
	}
	same := os.SameFile(left.before, right.before)
	return same, errors.Join(left.CloseVerified(), right.CloseVerified())
}
