package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

type aptCanonicalLeaf struct {
	arch          string
	commit        plumbing.Hash
	canonicalPath string
}

type aptLeafSpools struct {
	arch   string
	spools map[string]*aptrepo.SortedPackageSpool
	err    error
}

// buildAPTStreamingSpools inspects one canonical leaf at a time with bounded
// concurrency. Each component/architecture pair owns a bounded external sort;
// the returned iterators retain no repository-wide package slice.
func buildAPTStreamingSpools(ctx context.Context, canonical *state.Store, repo config.Repo, components []string, leaves []aptCanonicalLeaf, archiveRoot, tempRoot string, workers, chunkEntries int) ([]aptrepo.StreamingIndex, func() error, error) {
	if len(leaves) == 0 {
		return nil, func() error { return nil }, nil
	}
	if len(components) == 0 {
		return nil, func() error { return nil }, errors.New("APT suite has no configured components")
	}
	if workers < 1 || chunkEntries < 1 {
		return nil, func() error { return nil }, errors.New("APT streaming workers and chunk entries must be positive")
	}
	if workers > 64 {
		workers = 64
	}
	if workers > len(leaves) {
		workers = len(leaves)
	}
	if err := os.MkdirAll(tempRoot, 0o700); err != nil {
		return nil, func() error { return nil }, fmt.Errorf("create APT spool parent: %w", err)
	}
	tempInfo, err := os.Lstat(tempRoot)
	if err != nil || !tempInfo.IsDir() || tempInfo.Mode()&os.ModeSymlink != 0 {
		return nil, func() error { return nil }, errors.Join(err, errors.New("APT spool parent must be a real directory"))
	}
	spoolRoot, err := os.MkdirTemp(tempRoot, "apt-index-spool-")
	if err != nil {
		return nil, func() error { return nil }, fmt.Errorf("create APT index spool: %w", err)
	}
	allSpools := make([]*aptrepo.SortedPackageSpool, 0, len(leaves)*len(components))
	cleanup := func() error {
		var closeErr error
		for _, spool := range allSpools {
			closeErr = errors.Join(closeErr, spool.Close())
		}
		closeErr = errors.Join(closeErr, os.RemoveAll(spoolRoot))
		return closeErr
	}

	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan aptCanonicalLeaf)
	results := make(chan aptLeafSpools, len(leaves))
	var group sync.WaitGroup
	group.Add(workers)
	for range workers {
		go func() {
			defer group.Done()
			for leaf := range jobs {
				built := buildAPTLeafSpools(workerCtx, canonical, repo, components, leaf, archiveRoot, spoolRoot, chunkEntries)
				if built.err != nil {
					cancel()
				}
				results <- built
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, leaf := range leaves {
			select {
			case jobs <- leaf:
			case <-workerCtx.Done():
				return
			}
		}
	}()
	go func() {
		group.Wait()
		close(results)
	}()

	byArch := make(map[string]map[string]*aptrepo.SortedPackageSpool, len(leaves))
	var firstErr error
	for built := range results {
		if built.err != nil {
			if firstErr == nil {
				firstErr = built.err
			}
			continue
		}
		byArch[built.arch] = built.spools
		for _, spool := range built.spools {
			allSpools = append(allSpools, spool)
		}
	}
	if firstErr != nil {
		_ = cleanup()
		return nil, func() error { return nil }, firstErr
	}
	if err := ctx.Err(); err != nil {
		_ = cleanup()
		return nil, func() error { return nil }, err
	}

	arches := make([]string, 0, len(byArch))
	for arch := range byArch {
		arches = append(arches, arch)
	}
	sort.Strings(arches)
	indexes := make([]aptrepo.StreamingIndex, 0, len(arches)*len(components))
	for _, component := range components {
		for _, arch := range arches {
			spool := byArch[arch][component]
			if spool == nil {
				_ = cleanup()
				return nil, func() error { return nil }, fmt.Errorf("missing APT spool for %s/%s", component, arch)
			}
			indexes = append(indexes, aptrepo.StreamingIndex{Component: component, Architecture: arch, Packages: spool})
		}
	}
	return indexes, cleanup, nil
}

func buildAPTLeafSpools(ctx context.Context, canonical *state.Store, repo config.Repo, components []string, leaf aptCanonicalLeaf, archiveRoot, spoolRoot string, chunkEntries int) aptLeafSpools {
	result := aptLeafSpools{arch: leaf.arch, spools: make(map[string]*aptrepo.SortedPackageSpool, len(components))}
	closeOnError := func(err error) aptLeafSpools {
		for _, spool := range result.spools {
			_ = spool.Close()
		}
		result.spools = nil
		result.err = err
		return result
	}
	for _, component := range components {
		spool, err := aptrepo.NewSortedPackageSpool(spoolRoot, chunkEntries)
		if err != nil {
			return closeOnError(err)
		}
		result.spools[component] = spool
	}
	reader, err := canonical.OpenPathAt(leaf.commit, leaf.canonicalPath)
	if err != nil {
		return closeOnError(err)
	}
	viewReader := views.NewReader(reader)
	for {
		entry, readErr := viewReader.Next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_ = reader.Close()
			return closeOnError(readErr)
		}
		prefix := strings.TrimSuffix(repo.Path, "/") + "/"
		if !strings.HasPrefix(entry.Path, prefix) {
			_ = reader.Close()
			return closeOnError(fmt.Errorf("APT canonical path escapes repo %q", entry.Path))
		}
		relative := strings.TrimPrefix(entry.Path, prefix)
		component, componentErr := aptComponentFromPoolPath(relative)
		if componentErr != nil || !contains(components, component) {
			_ = reader.Close()
			return closeOnError(fmt.Errorf("invalid APT pool path %q", entry.Path))
		}
		pkg, inspectErr := aptrepo.InspectPackage(ctx, filepath.Join(archiveRoot, filepath.FromSlash(relative)), component)
		if inspectErr != nil {
			_ = reader.Close()
			return closeOnError(inspectErr)
		}
		if pkg.SHA256 != entry.SHA256 || pkg.Size != entry.Size || pkg.Name != entry.Name || pkg.Version != entry.Version || (pkg.Architecture != "all" && pkg.Architecture != leaf.arch) {
			_ = reader.Close()
			return closeOnError(fmt.Errorf("APT package metadata disagrees with canonical path %s", entry.Path))
		}
		if err := result.spools[component].Add(ctx, pkg); err != nil {
			_ = reader.Close()
			return closeOnError(err)
		}
	}
	if err := reader.Close(); err != nil {
		return closeOnError(err)
	}
	for _, component := range components {
		if err := result.spools[component].Seal(ctx); err != nil {
			return closeOnError(err)
		}
	}
	return result
}
