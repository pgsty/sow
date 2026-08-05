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

// GenerateFlatUnsigned builds the unsigned flat rpm-md repository used by
// `sow create`. It deliberately has no EL policy, modulemd, signature, or
// Packages/<bucket> placement: every package location is its safe basename.
// The destination is installed only after a complete structural validation.
func GenerateFlatUnsigned(ctx context.Context, dest string, revision int64, packages PackageIterator) (*Generation, error) {
	if ctx == nil {
		return nil, errors.New("yumrepo: nil context")
	}
	if packages == nil {
		return nil, errors.New("yumrepo: nil package iterator")
	}
	if revision < 0 {
		return nil, errors.New("yumrepo: revision must be non-negative")
	}
	dest = filepath.Clean(dest)
	if dest == "." || dest == string(filepath.Separator) {
		return nil, errors.New("yumrepo: unsafe flat generation destination")
	}
	parent := filepath.Dir(dest)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return nil, fmt.Errorf("yumrepo: create flat generation parent: %w", err)
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("yumrepo: flat generation parent %q is not a real directory", parent)
	}
	if _, err := os.Lstat(dest); err == nil {
		return nil, fmt.Errorf("%w: %s", ErrGenerationExists, dest)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("yumrepo: inspect flat generation destination: %w", err)
	}
	tmp, err := os.MkdirTemp(parent, "."+filepath.Base(dest)+".build-")
	if err != nil {
		return nil, fmt.Errorf("yumrepo: create flat generation staging directory: %w", err)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		_ = os.RemoveAll(tmp)
		return nil, fmt.Errorf("yumrepo: chmod flat generation staging directory: %w", err)
	}
	installed := false
	defer func() {
		if !installed {
			_ = os.RemoveAll(tmp)
		}
	}()

	bodies, err := openBodyFiles(tmp)
	if err != nil {
		return nil, err
	}
	var count int64
	var previous string
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
			return nil, fmt.Errorf("yumrepo: read flat package input: %w", nextErr)
		}
		input.FileTime = unixEpoch
		metadata, readErr := readPackage(ctx, input)
		if readErr != nil {
			bodies.closeDiscard()
			return nil, readErr
		}
		base := input.Basename
		if base == "" {
			base = filepath.Base(input.Path)
		}
		if _, err := PackageLocation(metadata.Name, base); err != nil {
			bodies.closeDiscard()
			return nil, err
		}
		metadata.Location = base
		if previous != "" && metadata.Location <= previous {
			bodies.closeDiscard()
			return nil, fmt.Errorf("%w: %q follows %q", ErrUnsortedInput, metadata.Location, previous)
		}
		if err := bodies.bodies.writePackage(metadata); err != nil {
			bodies.closeDiscard()
			return nil, fmt.Errorf("yumrepo: write flat XML package %q: %w", metadata.Location, err)
		}
		previous = metadata.Location
		count++
	}
	if err := bodies.finish(); err != nil {
		return nil, err
	}

	types := []struct{ name, body string }{
		{"primary", bodies.primaryFile.Name()},
		{"filelists", bodies.filelistsFile.Name()},
		{"other", bodies.otherFile.Name()},
	}
	generation := &Generation{Dir: dest, Packages: count, Revision: revision}
	for i, item := range types {
		rawPath := filepath.Join(tmp, item.name+".xml")
		if err := assembleXML(rawPath, item.name, item.body, count); err != nil {
			return nil, err
		}
		artifact, err := compressXML(ctx, tmp, item.name, rawPath, CompressionGzip, count, revision)
		if err != nil {
			return nil, err
		}
		generation.Artifacts[i] = artifact
	}
	for _, item := range types {
		if err := os.Remove(item.body); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("yumrepo: remove flat XML spool: %w", err)
		}
	}
	if err := writeRepomd(filepath.Join(tmp, "repomd.xml"), generation); err != nil {
		return nil, err
	}
	repomd, err := os.ReadFile(filepath.Join(tmp, "repomd.xml"))
	if err != nil {
		return nil, fmt.Errorf("yumrepo: read flat repomd.xml: %w", err)
	}
	sum := sha256.Sum256(repomd)
	generation.RepomdSHA256 = hex.EncodeToString(sum[:])
	validated, err := ValidateFlatUnsignedDirectory(ctx, tmp, CompressionGzip)
	if err != nil {
		return nil, fmt.Errorf("yumrepo: generated flat repodata failed self-validation: %w", err)
	}
	if validated.Packages != generation.Packages || validated.Revision != generation.Revision || validated.RepomdSHA256 != generation.RepomdSHA256 {
		return nil, errors.New("yumrepo: generated flat repodata changed generation identity during validation")
	}
	if err := syncDirectory(tmp); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return nil, fmt.Errorf("yumrepo: install flat generation: %w", err)
	}
	installed = true
	if err := syncDirectory(parent); err != nil {
		return nil, err
	}
	return generation, nil
}
