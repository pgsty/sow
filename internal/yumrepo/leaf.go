package yumrepo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// GenerateRPMLeaf builds the repodata directory for sow-rpm-leaf-v1. Package
// locations are the leaf-local canonical pool/... paths supplied by the
// caller; this is deliberately distinct from both canonical managed views and
// the historical C2 admission format.
func GenerateRPMLeaf(ctx context.Context, dest string, revision uint64, packages PackageIterator, signer DetachedSigner) (*Generation, error) {
	if ctx == nil || packages == nil {
		return nil, errors.New("yumrepo: invalid RPM leaf generation input")
	}
	if signer != nil {
		if err := preflightSigner(ctx, signer); err != nil {
			return nil, err
		}
	}
	dest = filepath.Clean(dest)
	if dest == "." || dest == string(filepath.Separator) {
		return nil, errors.New("yumrepo: unsafe RPM leaf destination")
	}
	parent := filepath.Dir(dest)
	if info, err := os.Lstat(parent); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("yumrepo: RPM leaf parent is not a real directory: %w", err)
	}
	if _, err := os.Lstat(dest); err == nil {
		return nil, fmt.Errorf("%w: %s", ErrGenerationExists, dest)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	tmp, err := os.MkdirTemp(parent, ".repodata.leaf-")
	if err != nil {
		return nil, err
	}
	installed := false
	defer func() {
		if !installed {
			_ = os.RemoveAll(tmp)
		}
	}()
	if err := os.Chmod(tmp, 0o755); err != nil {
		return nil, err
	}
	bodies, err := openBodyFiles(tmp)
	if err != nil {
		return nil, err
	}
	var count int64
	var previous string
	expected := []ManagedRPMPackageExpectation{}
	for {
		if err := ctx.Err(); err != nil {
			bodies.closeDiscard()
			return nil, err
		}
		input, nextErr := packages.Next(ctx)
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			bodies.closeDiscard()
			return nil, nextErr
		}
		pool, poolErr := ParseManagedPoolPath(input.PoolPath)
		if poolErr != nil || pool.Filename() != input.Basename {
			bodies.closeDiscard()
			return nil, fmt.Errorf("%w: invalid RPM leaf Pool path", ErrUnsafeLocation)
		}
		plain := input
		plain.PoolPath, plain.ViewPath, plain.Location = "", ManagedRPMViewPath{}, ""
		plain.FileTime = unixEpoch
		metadata, readErr := readPackageWithManagedBasename(ctx, plain, true)
		if readErr != nil {
			bodies.closeDiscard()
			return nil, readErr
		}
		if sourceNameFromRPM(metadata.SourceRPM, metadata.Name, metadata.Version, metadata.Release) != pool.Source() {
			bodies.closeDiscard()
			return nil, fmt.Errorf("%w: RPM leaf Pool source differs from RPM source", ErrUnsafeLocation)
		}
		metadata.Location = encodeRepositoryPath(pool.String())
		if previous != "" && metadata.Location <= previous {
			bodies.closeDiscard()
			return nil, fmt.Errorf("%w: %q follows %q", ErrUnsortedInput, metadata.Location, previous)
		}
		if err := bodies.bodies.writePackage(metadata); err != nil {
			bodies.closeDiscard()
			return nil, err
		}
		expected = append(expected, ManagedRPMPackageExpectation{SHA256: metadata.Checksum, Size: metadata.PackageSize, PoolPath: pool})
		previous, count = metadata.Location, count+1
	}
	if err := bodies.finish(); err != nil {
		return nil, err
	}
	types := []struct{ name, body string }{{"primary", bodies.primaryFile.Name()}, {"filelists", bodies.filelistsFile.Name()}, {"other", bodies.otherFile.Name()}}
	generation := &Generation{Dir: dest, Packages: count, Revision: revision}
	for index, item := range types {
		raw := filepath.Join(tmp, item.name+".xml")
		if err := assembleXML(raw, item.name, item.body, count); err != nil {
			return nil, err
		}
		artifact, err := compressXML(ctx, tmp, item.name, raw, CompressionGzip, count, 0)
		if err != nil {
			return nil, err
		}
		generation.Artifacts[index] = artifact
	}
	for _, item := range types {
		if err := os.Remove(item.body); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	if err := writeRepomd(filepath.Join(tmp, "repomd.xml"), generation); err != nil {
		return nil, err
	}
	repomd, err := os.ReadFile(filepath.Join(tmp, "repomd.xml"))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(repomd)
	generation.RepomdSHA256 = hex.EncodeToString(sum[:])
	if signer != nil {
		if err := signRepomd(ctx, tmp, signer); err != nil {
			return nil, err
		}
		if _, err := ValidateRPMLeafDirectory(ctx, tmp, CompressionGzip, signer, expected); err != nil {
			return nil, fmt.Errorf("yumrepo: generated signed RPM leaf failed validation: %w", err)
		}
	} else if _, err := ValidateRPMLeafUnsignedDirectory(ctx, tmp, CompressionGzip, expected); err != nil {
		return nil, fmt.Errorf("yumrepo: generated RPM leaf failed validation: %w", err)
	}
	if err := syncDirectory(tmp); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return nil, err
	}
	installed = true
	if err := syncDirectory(parent); err != nil {
		return nil, err
	}
	return generation, nil
}

type rpmLeafValidation struct {
	expected map[string]ManagedRPMPackageExpectation
	seen     map[string]struct{}
}

func newRPMLeafValidation(expected []ManagedRPMPackageExpectation) (*rpmLeafValidation, error) {
	v := &rpmLeafValidation{expected: make(map[string]ManagedRPMPackageExpectation, len(expected)), seen: make(map[string]struct{}, len(expected))}
	for _, item := range expected {
		pool, err := ParseManagedPoolPath(item.PoolPath.String())
		if !validSHA256(item.SHA256) || item.Size < 0 || err != nil || pool != item.PoolPath || !safeManagedRPMBasename(pool.Filename()) {
			return nil, fmt.Errorf("%w: invalid RPM leaf package expectation", ErrInvalidRepodata)
		}
		if _, duplicate := v.expected[item.SHA256]; duplicate {
			return nil, fmt.Errorf("%w: duplicate RPM leaf package expectation", ErrInvalidRepodata)
		}
		v.expected[item.SHA256] = item
	}
	return v, nil
}

func (v *rpmLeafValidation) check(identity, href string, size int64) error {
	item, exists := v.expected[identity]
	if !exists || size != item.Size || href != encodeRepositoryPath(item.PoolPath.String()) {
		return fmt.Errorf("%w: RPM leaf package closure differs", ErrInvalidRepodata)
	}
	if _, duplicate := v.seen[identity]; duplicate {
		return fmt.Errorf("%w: RPM leaf repeats package %s", ErrInvalidRepodata, identity)
	}
	v.seen[identity] = struct{}{}
	return nil
}

func (v *rpmLeafValidation) finish() error {
	if v == nil || len(v.seen) != len(v.expected) {
		return fmt.Errorf("%w: RPM leaf package closure is incomplete", ErrInvalidRepodata)
	}
	return nil
}

// ValidateRPMLeafUnsignedDirectory validates exact unsigned leaf-local RPM-MD.
func ValidateRPMLeafUnsignedDirectory(ctx context.Context, dir string, compression Compression, expected []ManagedRPMPackageExpectation) (*Generation, error) {
	return validateRPMLeafDirectory(ctx, dir, compression, nil, false, expected)
}

// ValidateRPMLeafDirectory validates exact signed leaf-local RPM-MD.
func ValidateRPMLeafDirectory(ctx context.Context, dir string, compression Compression, verifier DetachedVerifier, expected []ManagedRPMPackageExpectation) (*Generation, error) {
	return validateRPMLeafDirectory(ctx, dir, compression, verifier, true, expected)
}

func validateRPMLeafDirectory(ctx context.Context, dir string, compression Compression, verifier DetachedVerifier, signed bool, expected []ManagedRPMPackageExpectation) (*Generation, error) {
	v, err := newRPMLeafValidation(expected)
	if err != nil {
		return nil, err
	}
	generation, err := validateDirectoryModeRetained(ctx, dir, compression, verifier, false, false, signed, false, false, v)
	if err != nil {
		return nil, err
	}
	if err := v.finish(); err != nil {
		return nil, err
	}
	return generation, nil
}
