package manifest

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"
)

type rootFileJob struct {
	parent   *os.Root
	file     *os.File
	name     string
	rootPath string
	opened   os.FileInfo
}

func (j rootFileJob) close() error {
	return errors.Join(j.file.Close(), j.parent.Close())
}

type boundRootComponent struct {
	name     string
	identity os.FileInfo
}

type boundScanScope struct {
	root       *os.Root
	identity   os.FileInfo
	prefix     string
	owned      bool
	components []boundRootComponent
}

func (s *boundScanScope) close() error {
	if s == nil || !s.owned {
		return nil
	}
	return s.root.Close()
}

// ScanRoot is the capability-bound counterpart of Scan. The caller supplies a
// retained os.Root; renaming its public pathname cannot redirect traversal or
// file reads to a replacement repository. Every path component below that
// root is opened and checked separately so an intermediate symlink cannot
// redirect a scope, directory walk, or worker file read within the root.
// Scope semantics and manifest output are otherwise identical to Scan.
func ScanRoot(ctx context.Context, root *os.Root, scope Scope, dst string, options ScanOptions) (stats ScanStats, returnErr error) {
	if ctx == nil || root == nil {
		return ScanStats{}, errors.New("bound manifest scan dependencies are unavailable")
	}
	options.defaults(".")
	if options.Workers < 1 || options.ChunkEntries < 1 {
		return ScanStats{}, errors.New("workers and chunk entries must be positive")
	}
	if err := validatePatterns(append(append([]string{}, scope.Include...), scope.Exclude...)); err != nil {
		return ScanStats{}, err
	}
	binding, err := openBoundScanScope(root, scope.Path)
	if err != nil {
		return ScanStats{}, err
	}
	defer func() {
		returnErr = errors.Join(returnErr, binding.close())
	}()
	if err := os.MkdirAll(options.TempDir, 0o700); err != nil {
		return ScanStats{}, fmt.Errorf("create scan temp directory: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan rootFileJob, options.Workers*2)
	results := make(chan scanResult, options.Workers*2)
	walkErrors := make(chan error, 1)
	go func() {
		defer close(jobs)
		walkErrors <- walkRootScope(ctx, binding.root, binding.prefix, scope, jobs)
	}()

	var workers sync.WaitGroup
	workers.Add(options.Workers)
	for range options.Workers {
		go func() {
			defer workers.Done()
			buffer := make([]byte, 256*1024)
			for job := range jobs {
				entry, hashErr := hashRootFile(ctx, job, buffer)
				jobErr := errors.Join(hashErr, job.close())
				select {
				case results <- scanResult{entry: entry, err: jobErr}:
				case <-ctx.Done():
					// The result consumer cancels only after receiving the first
					// failure. Once canceled, keep draining jobs so every retained
					// file and directory capability is closed.
				}
			}
		}()
	}
	go func() {
		workers.Wait()
		close(results)
	}()

	var firstErr error
	chunk := make([]Entry, 0, options.ChunkEntries)
	var runs []string
	for result := range results {
		if result.err != nil {
			if firstErr == nil {
				firstErr = result.err
				cancel()
			}
			continue
		}
		if firstErr != nil {
			continue
		}
		stats.Files++
		stats.Bytes += result.entry.Size
		chunk = append(chunk, result.entry)
		if len(chunk) == options.ChunkEntries {
			run, flushErr := flushRun(options.TempDir, chunk)
			if flushErr != nil {
				firstErr = flushErr
				cancel()
			} else {
				runs = append(runs, run)
			}
			chunk = make([]Entry, 0, options.ChunkEntries)
		}
	}
	if walkErr := <-walkErrors; walkErr != nil && firstErr == nil {
		firstErr = walkErr
	}
	if ctxErr := ctx.Err(); ctxErr != nil && firstErr == nil {
		firstErr = ctxErr
	}
	if firstErr == nil {
		firstErr = binding.verify(root)
	}
	if firstErr == nil && len(chunk) > 0 {
		run, flushErr := flushRun(options.TempDir, chunk)
		if flushErr != nil {
			firstErr = flushErr
		} else {
			runs = append(runs, run)
		}
	}
	defer removeFiles(runs)
	if firstErr != nil {
		return stats, firstErr
	}
	if err := mergeRuns(runs, dst, options.TempDir); err != nil {
		return stats, err
	}
	return stats, nil
}

func openBoundScanScope(root *os.Root, scopePath string) (*boundScanScope, error) {
	if scopePath == "" {
		scopePath = "."
	}
	if strings.ContainsAny(scopePath, "\\\x00\t\r\n") || path.IsAbs(scopePath) || path.Clean(scopePath) != scopePath || scopePath == ".." || strings.HasPrefix(scopePath, "../") {
		return nil, errors.New("manifest scope must be a safe root-relative path")
	}
	if scopePath == "." {
		identity, err := root.Stat(".")
		if err != nil {
			return nil, err
		}
		return &boundScanScope{root: root, identity: identity}, nil
	}

	current := root
	owned := false
	components := strings.Split(scopePath, "/")
	boundComponents := make([]boundRootComponent, 0, len(components))
	for _, component := range components {
		next, identity, err := openBoundRootDirectory(current, component)
		if err != nil {
			if owned {
				err = errors.Join(err, current.Close())
			}
			return nil, fmt.Errorf("open manifest scope %q: %w", scopePath, err)
		}
		boundComponents = append(boundComponents, boundRootComponent{name: component, identity: identity})
		if owned {
			if err := current.Close(); err != nil {
				_ = next.Close()
				return nil, fmt.Errorf("close manifest scope component: %w", err)
			}
		}
		current = next
		owned = true
	}
	identity, err := current.Stat(".")
	if err != nil {
		return nil, errors.Join(err, current.Close())
	}
	return &boundScanScope{
		root:       current,
		identity:   identity,
		prefix:     scopePath,
		owned:      true,
		components: boundComponents,
	}, nil
}

func (s *boundScanScope) verify(root *os.Root) error {
	if s == nil || !s.owned {
		return nil
	}
	current := root
	owned := false
	for _, component := range s.components {
		next, identity, err := openBoundRootDirectory(current, component.name)
		if err == nil && !os.SameFile(identity, component.identity) {
			err = fmt.Errorf("manifest scope component %q was replaced during scan", component.name)
		}
		if owned {
			err = errors.Join(err, current.Close())
		}
		if err != nil {
			if next != nil {
				_ = next.Close()
			}
			return fmt.Errorf("bound manifest scope was replaced during scan: %w", err)
		}
		current = next
		owned = true
	}
	identity, err := current.Stat(".")
	if err == nil && !os.SameFile(identity, s.identity) {
		err = errors.New("manifest scope directory identity changed during scan")
	}
	if owned {
		err = errors.Join(err, current.Close())
	}
	if err != nil {
		return fmt.Errorf("bound manifest scope was replaced during scan: %w", err)
	}
	return nil
}

func openBoundRootDirectory(parent *os.Root, name string) (*os.Root, os.FileInfo, error) {
	if !safeRootChildName(name) {
		return nil, nil, fmt.Errorf("unsafe manifest path component %q", name)
	}
	before, err := parent.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, nil, fmt.Errorf("manifest directory %q is symlinked or not a directory", name)
	}
	opened, err := parent.OpenRoot(name)
	if err != nil {
		return nil, nil, err
	}
	bound, statErr := opened.Stat(".")
	after, lstatErr := parent.Lstat(name)
	if statErr != nil || lstatErr != nil || after.Mode()&os.ModeSymlink != 0 || !after.IsDir() ||
		!os.SameFile(before, bound) || !os.SameFile(before, after) {
		return nil, nil, errors.Join(statErr, lstatErr, opened.Close(), fmt.Errorf("manifest directory %q changed while opening", name))
	}
	return opened, bound, nil
}

func walkRootScope(ctx context.Context, root *os.Root, prefix string, scope Scope, jobs chan<- rootFileJob) error {
	return walkRootDirectory(ctx, root, "", prefix, scope, jobs)
}

func walkRootDirectory(ctx context.Context, current *os.Root, relative, prefix string, scope Scope, jobs chan<- rootFileJob) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	directory, err := current.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		if !safeRootChildName(name) {
			return fmt.Errorf("repo contains unsafe path component %q", name)
		}
		relBase := name
		if relative != "" {
			relBase = path.Join(relative, name)
		}
		if containsShadowPoint(relBase) {
			continue
		}
		info, err := current.Lstat(name)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("repo contains symlink %q; materialize it before scanning", relBase)
		}
		if info.IsDir() {
			if matchesAny(scope.Exclude, relBase) || matchesAny(scope.Exclude, relBase+"/_sow_probe_") {
				continue
			}
			child, identity, err := openBoundRootDirectory(current, name)
			if err != nil {
				return fmt.Errorf("open repo directory %q: %w", relBase, err)
			}
			walkErr := walkRootDirectory(ctx, child, relBase, prefix, scope, jobs)
			coordinateErr := verifyBoundRootDirectory(current, name, identity, relBase)
			if err := errors.Join(walkErr, coordinateErr, child.Close()); err != nil {
				return err
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("repo contains non-regular file %q (%s)", relBase, info.Mode())
		}
		if !selected(relBase, scope.Include, scope.Exclude) {
			continue
		}
		rootPath := relBase
		if prefix != "" {
			rootPath = path.Join(prefix, relBase)
		}
		if strings.ContainsAny(rootPath, "\t\r\n") {
			return fmt.Errorf("path cannot be represented in TSV manifest: %q", rootPath)
		}
		job, err := openBoundRootFile(current, name, rootPath)
		if err != nil {
			return err
		}
		select {
		case jobs <- job:
		case <-ctx.Done():
			return errors.Join(ctx.Err(), job.close())
		}
	}
	return nil
}

func openBoundRootFile(parent *os.Root, name, rootPath string) (rootFileJob, error) {
	if !safeRootChildName(name) {
		return rootFileJob{}, fmt.Errorf("unsafe manifest file component %q", name)
	}
	parentIdentity, err := parent.Stat(".")
	if err != nil {
		return rootFileJob{}, err
	}
	retained, err := parent.OpenRoot(".")
	if err != nil {
		return rootFileJob{}, err
	}
	retainedIdentity, statErr := retained.Stat(".")
	if statErr != nil || !os.SameFile(parentIdentity, retainedIdentity) {
		return rootFileJob{}, errors.Join(statErr, retained.Close(), fmt.Errorf("manifest parent for %q changed while retaining", rootPath))
	}
	before, err := retained.Lstat(name)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return rootFileJob{}, errors.Join(err, retained.Close(), fmt.Errorf("open %q: path is absent, symlinked, or not regular", rootPath))
	}
	file, err := retained.Open(name)
	if err != nil {
		return rootFileJob{}, errors.Join(fmt.Errorf("open %q: %w", rootPath, err), retained.Close())
	}
	opened, statErr := file.Stat()
	after, lstatErr := retained.Lstat(name)
	if statErr != nil || lstatErr != nil || after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() ||
		!sameRootFileInfo(before, opened) || !sameRootFileInfo(before, after) {
		return rootFileJob{}, errors.Join(statErr, lstatErr, file.Close(), retained.Close(), fmt.Errorf("file changed while opening: %q", rootPath))
	}
	return rootFileJob{parent: retained, file: file, name: name, rootPath: rootPath, opened: opened}, nil
}

func verifyBoundRootDirectory(parent *os.Root, name string, identity os.FileInfo, relative string) error {
	coordinate, err := parent.Lstat(name)
	if err != nil {
		return err
	}
	if coordinate.Mode()&os.ModeSymlink != 0 || !coordinate.IsDir() || !os.SameFile(identity, coordinate) {
		return fmt.Errorf("repo directory %q was replaced during scan", relative)
	}
	return nil
}

func hashRootFile(ctx context.Context, job rootFileJob, buffer []byte) (Entry, error) {
	if err := ctx.Err(); err != nil {
		return Entry{}, err
	}
	coordinateBefore, err := job.parent.Lstat(job.name)
	if err != nil || coordinateBefore.Mode()&os.ModeSymlink != 0 || !coordinateBefore.Mode().IsRegular() || !sameRootFileInfo(job.opened, coordinateBefore) {
		return Entry{}, errors.Join(err, fmt.Errorf("file changed before scanning: %q", job.rootPath))
	}
	hasher := sha256.New()
	written, copyErr := io.CopyBuffer(hasher, job.file, buffer)
	afterRead, restatErr := job.file.Stat()
	coordinate, coordinateErr := job.parent.Lstat(job.name)
	if copyErr != nil || restatErr != nil || coordinateErr != nil || coordinate.Mode()&os.ModeSymlink != 0 ||
		!coordinate.Mode().IsRegular() || written != job.opened.Size() ||
		!sameRootFileInfo(job.opened, afterRead) || !sameRootFileInfo(job.opened, coordinate) {
		return Entry{}, errors.Join(copyErr, restatErr, coordinateErr, fmt.Errorf("file changed while scanning: %q", job.rootPath))
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return Entry{Path: job.rootPath, Size: written, SHA256: digest}, nil
}

func sameRootFileInfo(left, right os.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right) && left.Mode() == right.Mode() &&
		left.Size() == right.Size() && left.ModTime().Equal(right.ModTime())
}

func safeRootChildName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsRune(name, '/') && !strings.ContainsRune(name, 0)
}
