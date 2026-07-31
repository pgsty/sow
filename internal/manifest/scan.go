package manifest

import (
	"bufio"
	"container/heap"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/bmatcuk/doublestar/v4"
)

type Scope struct {
	Path    string
	Include []string
	Exclude []string
}

// ValidateScope validates the lexical scope contract independently of
// filesystem existence. Optional-tree verifiers must call this before
// deciding that a missing path represents a valid empty repository.
func ValidateScope(scope Scope) error {
	scopePath := scope.Path
	if scopePath == "" {
		scopePath = "."
	}
	if strings.ContainsAny(scopePath, "\\\x00\t\r\n") ||
		filepath.IsAbs(scopePath) || path.IsAbs(scopePath) ||
		path.Clean(scopePath) != scopePath ||
		scopePath == ".." || strings.HasPrefix(scopePath, "../") {
		return errors.New("manifest scope must be a safe root-relative path")
	}
	return validatePatterns(append(append([]string{}, scope.Include...), scope.Exclude...))
}

type ScanOptions struct {
	Workers      int
	ChunkEntries int
	TempDir      string
	// ShadowPolicy controls how reserved operator directory names are treated.
	// The zero value preserves the ordinary repository-scan contract: any path
	// containing .sow, .pool, or .git is excluded. Exact export reconciliation
	// may exclude only those names at the scan-scope root, while isolated
	// immutable-generation validation must include them so a nested secret or
	// symlink cannot hide from exactness checks.
	ShadowPolicy ShadowPolicy
}

type ShadowPolicy uint8

const (
	ShadowExcludeAll ShadowPolicy = iota
	ShadowExcludeScopeRoot
	ShadowIncludeAll
)

func (policy ShadowPolicy) valid() bool {
	return policy <= ShadowIncludeAll
}

type ScanStats struct {
	Files int64
	Bytes int64
}

func (o *ScanOptions) defaults(root string) {
	if o.Workers <= 0 {
		o.Workers = runtime.NumCPU()
	}
	if o.Workers > 64 {
		o.Workers = 64
	}
	if o.ChunkEntries <= 0 {
		o.ChunkEntries = 4096
	}
	if o.TempDir == "" {
		o.TempDir = filepath.Join(root, ".sow", "tmp")
	}
}

type fileJob struct {
	fullPath string
	rootPath string
}

type scanResult struct {
	entry Entry
	err   error
}

func Scan(ctx context.Context, root string, scope Scope, dst string, options ScanOptions) (ScanStats, error) {
	options.defaults(root)
	if options.Workers < 1 || options.ChunkEntries < 1 {
		return ScanStats{}, errors.New("workers and chunk entries must be positive")
	}
	if !options.ShadowPolicy.valid() {
		return ScanStats{}, errors.New("invalid manifest shadow-point policy")
	}
	if err := ValidateScope(scope); err != nil {
		return ScanStats{}, err
	}
	rootAbs, baseAbs, err := resolveScope(root, scope.Path)
	if err != nil {
		return ScanStats{}, err
	}
	if err := os.MkdirAll(options.TempDir, 0o700); err != nil {
		return ScanStats{}, fmt.Errorf("create scan temp directory: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan fileJob, options.Workers*2)
	results := make(chan scanResult, options.Workers*2)
	walkErrors := make(chan error, 1)

	go func() {
		defer close(jobs)
		walkErrors <- walkScope(ctx, rootAbs, baseAbs, scope, options.ShadowPolicy, jobs)
	}()

	var workers sync.WaitGroup
	workers.Add(options.Workers)
	for range options.Workers {
		go func() {
			defer workers.Done()
			buffer := make([]byte, 256*1024)
			for job := range jobs {
				entry, err := hashFile(ctx, job, buffer)
				select {
				case results <- scanResult{entry: entry, err: err}:
				case <-ctx.Done():
					return
				}
				if err != nil {
					return
				}
			}
		}()
	}
	go func() {
		workers.Wait()
		close(results)
	}()

	var firstErr error
	var stats ScanStats
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
			run, err := flushRun(options.TempDir, chunk)
			if err != nil {
				firstErr = err
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
	if firstErr == nil && len(chunk) > 0 {
		run, err := flushRun(options.TempDir, chunk)
		if err != nil {
			firstErr = err
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

func resolveScope(root, scopePath string) (string, string, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", "", fmt.Errorf("resolve root: %w", err)
	}
	rootReal, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return "", "", fmt.Errorf("resolve root symlinks: %w", err)
	}
	base := filepath.Join(rootReal, filepath.FromSlash(scopePath))
	baseReal, err := filepath.EvalSymlinks(base)
	if err != nil {
		return "", "", fmt.Errorf("resolve repo path %q: %w", scopePath, err)
	}
	inside, err := filepath.Rel(rootReal, baseReal)
	if err != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("repo path %q escapes root", scopePath)
	}
	info, err := os.Stat(baseReal)
	if err != nil {
		return "", "", fmt.Errorf("stat repo path %q: %w", scopePath, err)
	}
	if !info.IsDir() {
		return "", "", fmt.Errorf("repo path %q is not a directory", scopePath)
	}
	return rootReal, baseReal, nil
}

func walkScope(ctx context.Context, root, base string, scope Scope, shadowPolicy ShadowPolicy, jobs chan<- fileJob) error {
	return filepath.WalkDir(base, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		relBase, err := filepath.Rel(base, current)
		if err != nil {
			return err
		}
		relBase = filepath.ToSlash(relBase)
		if relBase == "." {
			return nil
		}
		if skipShadowPoint(relBase, shadowPolicy) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("repo contains symlink %q; materialize it before scanning", relBase)
		}
		if entry.IsDir() {
			if matchesAny(scope.Exclude, relBase) || matchesAny(scope.Exclude, relBase+"/_sow_probe_") {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("repo contains non-regular file %q (%s)", relBase, info.Mode())
		}
		if !selected(relBase, scope.Include, scope.Exclude) {
			return nil
		}
		rootPath, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		rootPath = filepath.ToSlash(rootPath)
		if strings.ContainsAny(rootPath, "\t\r\n") {
			return fmt.Errorf("path cannot be represented in TSV manifest: %q", rootPath)
		}
		select {
		case jobs <- fileJob{fullPath: current, rootPath: rootPath}:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
}

func hashFile(ctx context.Context, job fileJob, buffer []byte) (Entry, error) {
	select {
	case <-ctx.Done():
		return Entry{}, ctx.Err()
	default:
	}
	f, err := os.Open(job.fullPath)
	if err != nil {
		return Entry{}, fmt.Errorf("open %q: %w", job.rootPath, err)
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return Entry{}, fmt.Errorf("stat %q: %w", job.rootPath, err)
	}
	hasher := sha256.New()
	written, err := io.CopyBuffer(hasher, f, buffer)
	if err != nil {
		return Entry{}, fmt.Errorf("hash %q: %w", job.rootPath, err)
	}
	after, err := f.Stat()
	if err != nil {
		return Entry{}, fmt.Errorf("restat %q: %w", job.rootPath, err)
	}
	pathInfo, err := os.Stat(job.fullPath)
	if err != nil {
		return Entry{}, fmt.Errorf("restat path %q: %w", job.rootPath, err)
	}
	if written != before.Size() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || !os.SameFile(before, pathInfo) {
		return Entry{}, fmt.Errorf("file changed while scanning: %q", job.rootPath)
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return Entry{Path: job.rootPath, Size: written, SHA256: digest}, nil
}

func selected(rel string, includes, excludes []string) bool {
	if matchesAny(excludes, rel) {
		return false
	}
	return len(includes) == 0 || matchesAny(includes, rel)
}

func matchesAny(patterns []string, value string) bool {
	for _, pattern := range patterns {
		matched, _ := doublestar.Match(pattern, value)
		if matched {
			return true
		}
	}
	return false
}

func validatePatterns(patterns []string) error {
	for _, pattern := range patterns {
		if !doublestar.ValidatePattern(pattern) {
			return fmt.Errorf("invalid path pattern %q", pattern)
		}
	}
	return nil
}

func containsShadowPoint(rel string) bool {
	for _, component := range strings.Split(rel, "/") {
		if component == ".sow" || component == ".pool" || component == ".git" {
			return true
		}
	}
	return false
}

func skipShadowPoint(rel string, policy ShadowPolicy) bool {
	switch policy {
	case ShadowExcludeAll:
		return containsShadowPoint(rel)
	case ShadowExcludeScopeRoot:
		return !strings.Contains(rel, "/") && containsShadowPoint(rel)
	case ShadowIncludeAll:
		return false
	default:
		// Public entry points reject invalid policies before walking. Failing
		// closed here keeps direct in-package calls from silently weakening a
		// scan if a future policy is added incompletely.
		return true
	}
}

func flushRun(tempDir string, entries []Entry) (string, error) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Path == entries[i].Path {
			return "", fmt.Errorf("duplicate manifest path %q", entries[i].Path)
		}
	}
	f, err := os.CreateTemp(tempDir, "manifest-run-*.tsv")
	if err != nil {
		return "", err
	}
	name := f.Name()
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	w := bufio.NewWriterSize(f, 256*1024)
	for _, entry := range entries {
		if err := WriteEntry(w, entry); err != nil {
			return "", err
		}
	}
	if err := w.Flush(); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	ok = true
	return name, nil
}

type runCursor struct {
	entry  Entry
	reader *Reader
	file   *os.File
	index  int
}

type runHeap []*runCursor

func (h runHeap) Len() int           { return len(h) }
func (h runHeap) Less(i, j int) bool { return h[i].entry.Path < h[j].entry.Path }
func (h runHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *runHeap) Push(value any)    { *h = append(*h, value.(*runCursor)) }
func (h *runHeap) Pop() any {
	old := *h
	value := old[len(old)-1]
	*h = old[:len(old)-1]
	return value
}

func mergeRuns(runs []string, dst, tempDir string) error {
	merged, err := os.CreateTemp(tempDir, "manifest-merged-*.tsv")
	if err != nil {
		return err
	}
	mergedName := merged.Name()
	defer os.Remove(mergedName)
	writer := bufio.NewWriterSize(merged, 256*1024)
	var cursors runHeap
	for index, name := range runs {
		f, err := os.Open(name)
		if err != nil {
			closeCursors(cursors)
			_ = merged.Close()
			return err
		}
		reader := NewReader(f)
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			_ = f.Close()
			continue
		}
		if err != nil {
			_ = f.Close()
			closeCursors(cursors)
			_ = merged.Close()
			return err
		}
		cursors = append(cursors, &runCursor{entry: entry, reader: reader, file: f, index: index})
	}
	heap.Init(&cursors)
	last := ""
	for cursors.Len() > 0 {
		cursor := heap.Pop(&cursors).(*runCursor)
		if cursor.entry.Path == last {
			closeCursors(cursors)
			_ = cursor.file.Close()
			_ = merged.Close()
			return fmt.Errorf("duplicate manifest path %q across sorted runs", last)
		}
		if err := WriteEntry(writer, cursor.entry); err != nil {
			closeCursors(cursors)
			_ = cursor.file.Close()
			_ = merged.Close()
			return err
		}
		last = cursor.entry.Path
		next, err := cursor.reader.Next()
		if errors.Is(err, io.EOF) {
			_ = cursor.file.Close()
			continue
		}
		if err != nil {
			closeCursors(cursors)
			_ = cursor.file.Close()
			_ = merged.Close()
			return err
		}
		cursor.entry = next
		heap.Push(&cursors, cursor)
	}
	if err := writer.Flush(); err != nil {
		_ = merged.Close()
		return err
	}
	if _, err := merged.Seek(0, io.SeekStart); err != nil {
		_ = merged.Close()
		return err
	}
	if err := AtomicCopy(dst, merged, 0o644); err != nil {
		_ = merged.Close()
		return err
	}
	return merged.Close()
}

func closeCursors(cursors runHeap) {
	for _, cursor := range cursors {
		_ = cursor.file.Close()
	}
}

func removeFiles(paths []string) {
	for _, name := range paths {
		_ = os.Remove(name)
	}
}
