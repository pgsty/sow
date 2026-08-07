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
	exhausted := false
	for !exhausted {
		if err := ctx.Err(); err != nil {
			bodies.closeDiscard()
			return nil, err
		}
		batch := make([]PackageInput, 0, workers)
		for len(batch) < workers {
			input, nextErr := packages.Next(ctx)
			if errors.Is(nextErr, io.EOF) {
				exhausted = true
				break
			}
			if nextErr != nil {
				bodies.closeDiscard()
				return nil, nextErr
			}
			if input.PoolPath == "" || input.ViewPath.String() == "" || input.Location == "" {
				bodies.closeDiscard()
				return nil, errors.New("yumrepo: managed package input requires an explicit PoolPath, ViewPath, and rendered href")
			}
			input.FileTime = unixEpoch
			batch = append(batch, input)
		}
		if len(batch) == 0 {
			break
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
				bodies.closeDiscard()
				return nil, result.err
			}
			metadata := result.metadata
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
	}
	if err := bodies.finish(); err != nil {
		return nil, err
	}
	types := []struct{ name, body string }{
		{"primary", bodies.primaryFile.Name()}, {"filelists", bodies.filelistsFile.Name()}, {"other", bodies.otherFile.Name()},
	}
	generation := &Generation{Dir: dest, Packages: count, Revision: revision}
	for index, item := range types {
		rawPath := filepath.Join(tmp, item.name+".xml")
		if err := assembleXML(rawPath, item.name, item.body, count); err != nil {
			return nil, err
		}
		artifact, err := compressXML(ctx, tmp, item.name, rawPath, CompressionGzip, count, 0)
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
