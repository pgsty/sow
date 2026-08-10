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
	"sync"
)

// GenerateManaged builds one managed architecture view whose package hrefs
// are canonical parent-relative references to Repository-root Pool objects.
// A nil signer produces an unsigned repomd.xml; a non-nil signer also produces
// and self-verifies repomd.xml.asc.
func GenerateManaged(ctx context.Context, dest string, revision uint64, packages PackageIterator, signer DetachedSigner) (*Generation, error) {
	return GenerateManagedConcurrent(ctx, dest, revision, packages, signer, 1)
}

// GenerateManagedConcurrent is GenerateManaged with bounded parallel package
// parsing. Results are written in iterator order, so worker count cannot affect
// metadata bytes or package selection.
func GenerateManagedConcurrent(ctx context.Context, dest string, revision uint64, packages PackageIterator, signer DetachedSigner, workers int) (*Generation, error) {
	if ctx == nil {
		return nil, errors.New("yumrepo: nil context")
	}
	if packages == nil {
		return nil, errors.New("yumrepo: nil package iterator")
	}
	if workers < 1 {
		return nil, errors.New("yumrepo: managed generation workers must be positive")
	}
	var queued []*packageMetadata
	exhausted := false
	next := func(ctx context.Context) (*packageMetadata, error) {
		if len(queued) != 0 {
			metadata := queued[0]
			queued = queued[1:]
			return metadata, nil
		}
		if exhausted {
			return nil, io.EOF
		}
		batch := make([]PackageInput, 0, workers)
		for len(batch) < workers {
			input, err := packages.Next(ctx)
			if errors.Is(err, io.EOF) {
				exhausted = true
				break
			}
			if err != nil {
				return nil, err
			}
			if input.PoolPath == "" || input.ViewPath.String() == "" || input.Location == "" {
				return nil, errors.New("yumrepo: managed package input requires an explicit PoolPath, ViewPath, and rendered href")
			}
			input.FileTime = unixEpoch
			batch = append(batch, input)
		}
		if len(batch) == 0 {
			return nil, io.EOF
		}
		type parsedPackage struct {
			metadata *packageMetadata
			err      error
		}
		parsed := make([]parsedPackage, len(batch))
		var group sync.WaitGroup
		group.Add(len(batch))
		for index := range batch {
			go func() {
				defer group.Done()
				parsed[index].metadata, parsed[index].err = readPackage(ctx, batch[index])
			}()
		}
		group.Wait()
		for _, result := range parsed {
			if result.err != nil {
				return nil, result.err
			}
			queued = append(queued, result.metadata)
		}
		metadata := queued[0]
		queued = queued[1:]
		return metadata, nil
	}
	return generateManagedMetadata(ctx, dest, revision, signer, workers, next)
}

// GenerateManagedParsed renders package facts that were authenticated and
// parsed at ingestion. It performs no package payload I/O.
func GenerateManagedParsed(ctx context.Context, dest string, revision uint64, packages []*ParsedManagedPackage, signer DetachedSigner) (*Generation, error) {
	return GenerateManagedParsedConcurrent(ctx, dest, revision, packages, signer, 1)
}

func GenerateManagedParsedConcurrent(ctx context.Context, dest string, revision uint64, packages []*ParsedManagedPackage, signer DetachedSigner, workers int) (*Generation, error) {
	if ctx == nil {
		return nil, errors.New("yumrepo: nil context")
	}
	if workers < 1 {
		return nil, errors.New("yumrepo: managed generation workers must be positive")
	}
	index := 0
	next := func(context.Context) (*packageMetadata, error) {
		if index >= len(packages) {
			return nil, io.EOF
		}
		pkg := packages[index]
		index++
		if pkg == nil || pkg.metadata == nil {
			return nil, fmt.Errorf("%w: nil parsed managed package", ErrInvalidPackage)
		}
		return pkg.metadata, nil
	}
	return generateManagedMetadata(ctx, dest, revision, signer, workers, next)
}

func generateManagedMetadata(ctx context.Context, dest string, revision uint64, signer DetachedSigner, workers int, next func(context.Context) (*packageMetadata, error)) (*Generation, error) {
	if signer != nil {
		if err := preflightSigner(ctx, signer); err != nil {
			return nil, err
		}
	}
	dest = filepath.Clean(dest)
	if dest == "." || dest == string(filepath.Separator) {
		return nil, errors.New("yumrepo: unsafe managed generation destination")
	}
	parent := filepath.Dir(dest)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return nil, fmt.Errorf("yumrepo: create managed generation parent: %w", err)
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("yumrepo: managed generation parent is not a real directory: %w", err)
	}
	if _, err := os.Lstat(dest); err == nil {
		return nil, fmt.Errorf("%w: %s", ErrGenerationExists, dest)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	tmp, err := os.MkdirTemp(parent, "."+filepath.Base(dest)+".build-")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		_ = os.RemoveAll(tmp)
		return nil, err
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
		metadata, nextErr := next(ctx)
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			bodies.closeDiscard()
			return nil, nextErr
		}
		if metadata == nil {
			bodies.closeDiscard()
			return nil, fmt.Errorf("%w: nil managed package metadata", ErrInvalidPackage)
		}
		if previous != "" && metadata.Location <= previous {
			bodies.closeDiscard()
			return nil, fmt.Errorf("%w: %q follows %q", ErrUnsortedInput, metadata.Location, previous)
		}
		if err := bodies.bodies.writePackage(metadata); err != nil {
			bodies.closeDiscard()
			return nil, err
		}
		previous = metadata.Location
		count++
	}
	if err := bodies.finish(); err != nil {
		return nil, err
	}
	types := []struct{ name, body string }{
		{"primary", bodies.primaryFile.Name()}, {"filelists", bodies.filelistsFile.Name()}, {"other", bodies.otherFile.Name()},
	}
	generation := &Generation{Dir: dest, Packages: count, Revision: revision}
	artifactWorkers := workers
	if artifactWorkers > len(types) {
		artifactWorkers = len(types)
	}
	indices := make(chan int)
	artifactErrors := make([]error, len(types))
	var artifacts sync.WaitGroup
	artifacts.Add(artifactWorkers)
	for range artifactWorkers {
		go func() {
			defer artifacts.Done()
			for index := range indices {
				item := types[index]
				rawPath := filepath.Join(tmp, item.name+".xml")
				if err := assembleXML(rawPath, item.name, item.body, count); err != nil {
					artifactErrors[index] = err
					continue
				}
				generation.Artifacts[index], artifactErrors[index] = compressXML(ctx, tmp, item.name, rawPath, CompressionGzip, count, 0)
			}
		}()
	}
	for index := range types {
		indices <- index
	}
	close(indices)
	artifacts.Wait()
	for _, err := range artifactErrors {
		if err != nil {
			return nil, err
		}
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
		validated, err := ValidateManagedDirectory(ctx, tmp, CompressionGzip, signer)
		if err != nil {
			return nil, fmt.Errorf("yumrepo: generated managed signed repodata failed self-validation: %w", err)
		}
		if validated.Packages != count || validated.Revision != revision || validated.RepomdSHA256 != generation.RepomdSHA256 {
			return nil, errors.New("yumrepo: managed signed generation identity changed during validation")
		}
	} else {
		validated, err := ValidateManagedUnsignedDirectory(ctx, tmp, CompressionGzip)
		if err != nil {
			return nil, fmt.Errorf("yumrepo: generated managed repodata failed self-validation: %w", err)
		}
		if validated.Packages != count || validated.Revision != revision || validated.RepomdSHA256 != generation.RepomdSHA256 {
			return nil, errors.New("yumrepo: managed generation identity changed during validation")
		}
	}
	if err := syncDirectory(tmp); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return nil, fmt.Errorf("yumrepo: install managed generation: %w", err)
	}
	installed = true
	if err := syncDirectory(parent); err != nil {
		return nil, err
	}
	return generation, nil
}
