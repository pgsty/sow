package aptrepo

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"pault.ag/go/debian/control"
)

// GenerateEmptyUnsigned creates the smallest complete unsigned APT Dist tree.
// The caller must pass a private staging root and is responsible for the
// eventual atomic directory install. This adapter intentionally emits only the
// P1 contract surface: Release plus Packages and Packages.gz for every native
// architecture; it does not invent signing configuration or by-hash state.
func GenerateEmptyUnsigned(ctx context.Context, root string, cfg RepositoryConfig) (BuildResult, error) {
	if ctx == nil {
		return BuildResult{}, errors.New("aptrepo: nil context")
	}
	if err := ctx.Err(); err != nil {
		return BuildResult{}, err
	}
	validated, err := validateRepositoryConfig(cfg)
	if err != nil {
		return BuildResult{}, err
	}
	if len(validated.Components) != 1 || validated.Components[0] != "main" {
		return BuildResult{}, errors.New("aptrepo: empty P1 distribution requires the fixed main component")
	}
	if err := validateOutputRoot(root); err != nil {
		return BuildResult{}, err
	}

	result := BuildResult{ReleasePath: path.Join("dists", validated.Suite, "Release")}
	indexes := make([]Artifact, 0, len(validated.Architectures)*2)
	for _, architecture := range validated.Architectures {
		base, err := IndexBasePath(validated.Suite, "main", architecture)
		if err != nil {
			return BuildResult{}, err
		}
		packagesPath := path.Join(base, "Packages")
		packages, err := writeArtifact(ctx, root, packagesPath, func(io.Writer) error { return nil })
		if err != nil {
			return BuildResult{}, err
		}
		compressed, err := writeArtifact(ctx, root, packagesPath+".gz", func(writer io.Writer) error {
			zw, err := gzip.NewWriterLevel(writer, gzip.BestCompression)
			if err != nil {
				return err
			}
			zw.Header.ModTime = cfg.Date.UTC()
			zw.Header.OS = 255
			return zw.Close()
		})
		if err != nil {
			return BuildResult{}, err
		}
		indexes = append(indexes, packages, compressed)
	}
	release := renderUnsignedRelease(validated, indexes)
	releaseArtifact, err := writeArtifact(ctx, root, result.ReleasePath, func(writer io.Writer) error {
		_, err := writer.Write(release)
		return err
	})
	if err != nil {
		return BuildResult{}, err
	}
	result.Artifacts = append(indexes, releaseArtifact)
	for _, artifact := range result.Artifacts {
		if err := verifyArtifact(path.Join(root, artifact.Path), artifact); err != nil {
			return BuildResult{}, fmt.Errorf("aptrepo: verify empty distribution: %w", err)
		}
	}
	return result, nil
}

func renderUnsignedRelease(cfg RepositoryConfig, indexes []Artifact) []byte {
	var output strings.Builder
	write := func(name, value string) {
		output.WriteString(name)
		output.WriteString(": ")
		output.WriteString(value)
		output.WriteByte('\n')
	}
	write("Origin", cfg.Origin)
	write("Label", cfg.Label)
	write("Suite", cfg.Suite)
	write("Codename", cfg.Codename)
	write("Date", releaseTime(cfg.Date))
	write("Architectures", strings.Join(cfg.Architectures, " "))
	write("Components", "main")
	if cfg.Description != "" {
		write("Description", cfg.Description)
	}
	output.WriteString("SHA256:\n")
	sort.Slice(indexes, func(i, j int) bool { return indexes[i].Path < indexes[j].Path })
	prefix := path.Join("dists", cfg.Suite) + "/"
	for _, artifact := range indexes {
		output.WriteByte(' ')
		output.WriteString(artifact.SHA256)
		output.WriteByte(' ')
		output.WriteString(strconv.FormatInt(artifact.Size, 10))
		output.WriteByte(' ')
		output.WriteString(strings.TrimPrefix(artifact.Path, prefix))
		output.WriteByte('\n')
	}
	return []byte(output.String())
}

// ValidateEmptyUnsigned proves the complete P1 unsigned APT Dist closure.
// It accepts only Release plus an empty Packages/Packages.gz pair for each
// declared native architecture. This is intentionally narrower than the P2
// renderer contract: signed metadata and non-empty indexes are not silently
// treated as implemented by the P1 control plane.
func ValidateEmptyUnsigned(ctx context.Context, root, suite string, architectures []string) error {
	if ctx == nil {
		return errors.New("aptrepo: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateSegment("suite", suite); err != nil {
		return err
	}
	if err := validateOutputRoot(root); err != nil {
		return err
	}
	architectures = append([]string(nil), architectures...)
	for _, architecture := range architectures {
		if !architecturePattern.MatchString(architecture) || architecture == "all" {
			return fmt.Errorf("aptrepo: unsafe empty distribution architecture %q", architecture)
		}
	}
	sort.Strings(architectures)
	if len(architectures) == 0 || hasDuplicate(architectures) {
		return errors.New("aptrepo: empty distribution needs unique native architectures")
	}

	distRelative := path.Join("dists", suite)
	distRoot := filepath.Join(root, filepath.FromSlash(distRelative))
	if err := ensureOutputParent(root, path.Join(distRelative, "Release"), false); err != nil {
		return err
	}
	distInfo, err := os.Lstat(distRoot)
	if err != nil || !distInfo.IsDir() || distInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("aptrepo: empty distribution root is missing or unsafe: %w", err)
	}
	releasePath := filepath.Join(distRoot, "Release")
	if _, err := regularFileInfo(releasePath); err != nil {
		return err
	}
	release, err := os.ReadFile(releasePath)
	if err != nil {
		return fmt.Errorf("aptrepo: read empty distribution Release: %w", err)
	}
	paragraphs, err := control.NewParagraphReader(bytes.NewReader(release), nil)
	if err != nil {
		return fmt.Errorf("aptrepo: parse empty distribution Release: %w", err)
	}
	paragraph, err := paragraphs.Next()
	if err != nil {
		return fmt.Errorf("aptrepo: read empty distribution Release: %w", err)
	}
	if _, err := paragraphs.Next(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("aptrepo: empty distribution Release has trailing paragraph")
		}
		return fmt.Errorf("aptrepo: parse trailing Release content: %w", err)
	}
	values := paragraph.Values
	if values["Suite"] != suite || values["Codename"] != suite || values["Components"] != "main" ||
		strings.Join(strings.Fields(values["Architectures"]), " ") != strings.Join(architectures, " ") {
		return errors.New("aptrepo: empty distribution Release dimensions do not match the built state")
	}

	type checksum struct {
		digest string
		size   int64
	}
	checksums := make(map[string]checksum, len(architectures)*2)
	for _, line := range strings.Split(values["SHA256"], "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 3 || len(fields[0]) != sha256.Size*2 || fields[0] != strings.ToLower(fields[0]) {
			return fmt.Errorf("aptrepo: malformed empty distribution SHA256 line %q", line)
		}
		if _, err := hex.DecodeString(fields[0]); err != nil {
			return fmt.Errorf("aptrepo: malformed empty distribution digest: %w", err)
		}
		size, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || size < 0 {
			return fmt.Errorf("aptrepo: malformed empty distribution size %q", fields[1])
		}
		if _, duplicate := checksums[fields[2]]; duplicate {
			return fmt.Errorf("aptrepo: duplicate Release checksum path %q", fields[2])
		}
		checksums[fields[2]] = checksum{digest: fields[0], size: size}
	}

	expectedFiles := map[string]struct{}{"Release": {}}
	for _, architecture := range architectures {
		base := path.Join("main", "binary-"+architecture, "Packages")
		for _, relative := range []string{base, base + ".gz"} {
			expected, ok := checksums[relative]
			if !ok {
				return fmt.Errorf("aptrepo: Release is missing checksum for %q", relative)
			}
			fullPath := filepath.Join(distRoot, filepath.FromSlash(relative))
			if err := ensureOutputParent(root, path.Join(distRelative, relative), false); err != nil {
				return err
			}
			actualDigest, actualSize, err := digestFile(ctx, fullPath, false)
			if err != nil {
				return err
			}
			if actualDigest != expected.digest || actualSize != expected.size {
				return fmt.Errorf("aptrepo: Release checksum mismatch for %q", relative)
			}
			expectedFiles[filepath.FromSlash(relative)] = struct{}{}
		}
		packages := filepath.Join(distRoot, "main", "binary-"+architecture, "Packages")
		if err := ValidateFlatPackages(ctx, packages, packages+".gz", nil); err != nil {
			return fmt.Errorf("aptrepo: invalid empty index for %s: %w", architecture, err)
		}
	}
	if len(checksums) != len(architectures)*2 {
		return errors.New("aptrepo: Release contains unexpected empty distribution checksum entries")
	}
	if err := filepath.WalkDir(distRoot, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current == distRoot || entry.IsDir() {
			if entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("aptrepo: symlink in empty distribution: %s", current)
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("aptrepo: symlink in empty distribution: %s", current)
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("aptrepo: non-regular file in empty distribution: %s", current)
		}
		relative, err := filepath.Rel(distRoot, current)
		if err != nil {
			return err
		}
		if _, ok := expectedFiles[relative]; !ok {
			return fmt.Errorf("aptrepo: unexpected file in empty distribution: %s", relative)
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}
