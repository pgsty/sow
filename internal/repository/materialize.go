package repository

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/pgsty/sow/internal/manifest"
)

// MaterializeStats describes hardlink work performed for one manifest stream.
type MaterializeStats struct {
	Entries  int64
	Bytes    int64
	Linked   int64
	Existing int64
	Relinked int64
	// PeakWorkers is the maximum number of simultaneous CAS verify/link jobs.
	PeakWorkers int64
}

type MaterializeOptions struct {
	// AllowReplacePath permits a different existing file only for an exact
	// caller-authorized logical path. The callback must be concurrency-safe and
	// must not perform filesystem I/O; it is evaluated by bounded workers after
	// the manifest path has passed validation. A nil callback fails closed.
	AllowReplacePath func(string) bool
	// Workers bounds concurrent CAS verification and hardlink installation.
	// Zero selects a conservative CPU-based default.
	Workers int
}

type materializeTestPhase uint8

const (
	materializeTestBeforeDirectLink materializeTestPhase = iota + 1
	materializeTestAfterDirectLink
	materializeTestBeforeReplacementLink
	materializeTestAfterReplacementTempProof
	materializeTestBeforeReplacementExchange
	materializeTestBeforeCleanupQuarantine
	materializeTestAfterParentCacheClose
	materializeTestAfterBindingClose
)

type materializeTestHook func(phase materializeTestPhase, source, destination string) error

type materializeFileIdentity struct {
	device uint64
	inode  uint64
}

func (identity materializeFileIdentity) valid() bool {
	return identity.device != 0 || identity.inode != 0
}

// Materialize streams a sorted manifest and creates its directly hostable tree
// below targetRoot. An empty targetRoot means the repository root; a relative
// targetRoot is resolved below it. Targets outside the repository are rejected.
//
// Every resulting file is a hardlink to its verified CAS object. An existing
// byte-identical copy is atomically replaced by a hardlink; different bytes are
// a conflict. There is intentionally no copy fallback.
func (s *Store) Materialize(ctx context.Context, source io.Reader, targetRoot string) (MaterializeStats, error) {
	return s.MaterializeWithOptions(ctx, source, targetRoot, MaterializeOptions{})
}

func (s *Store) MaterializeWithOptions(ctx context.Context, source io.Reader, targetRoot string, options MaterializeOptions) (MaterializeStats, error) {
	return s.materializeWithOptions(ctx, source, targetRoot, options, nil)
}

// materializeWithOptions carries an in-package fault-injection seam used only
// by repository tests to replace a CAS coordinate after its descriptor was
// verified but before a hardlink resolves that coordinate again.
func (s *Store) materializeWithOptions(ctx context.Context, source io.Reader, targetRoot string, options MaterializeOptions, testHook materializeTestHook) (stats MaterializeStats, resultErr error) {
	if source == nil {
		return stats, errors.New("nil manifest reader")
	}
	if s.readOnly {
		return stats, fmt.Errorf("%w: read-only CAS cannot materialize paths", ErrUnsafePath)
	}
	target, _, err := s.materializationTargetLocation(targetRoot)
	if err != nil {
		return stats, err
	}
	binding, err := bindMaterializationTarget(s.root, target, true)
	if err != nil {
		return stats, err
	}
	defer func() {
		closeErr := binding.close()
		if testHook != nil {
			closeErr = errors.Join(closeErr, testHook(materializeTestAfterBindingClose, "", target))
		}
		if closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	if err := s.preflightHardlink(binding); err != nil {
		return stats, err
	}

	workers := options.Workers
	if workers == 0 {
		workers = min(runtime.NumCPU(), 32)
	}
	if workers < 1 || workers > 1024 {
		return stats, errors.New("materialization workers must be between 1 and 1024")
	}
	type result struct {
		entry    manifest.Entry
		outcome  materializeOutcome
		err      error
		teardown bool
	}
	jobs := make(chan manifest.Entry, workers)
	results := make(chan result, workers)
	stop := make(chan struct{})
	var stopOnce sync.Once
	stopWork := func() { stopOnce.Do(func() { close(stop) }) }
	var group sync.WaitGroup
	var activeWorkers, peakWorkers atomic.Int64
	group.Add(workers + 1)
	for range workers {
		go func() {
			defer group.Done()
			var parentCache materializationParentCache
			defer func() {
				closeErr := parentCache.close()
				if testHook != nil {
					closeErr = errors.Join(closeErr, testHook(materializeTestAfterParentCacheClose, "", target))
				}
				if closeErr != nil {
					results <- result{err: fmt.Errorf("close materialization parent cache: %w", closeErr), teardown: true}
					stopWork()
				}
			}()
			for entry := range jobs {
				active := activeWorkers.Add(1)
				for observed := peakWorkers.Load(); active > observed && !peakWorkers.CompareAndSwap(observed, active); observed = peakWorkers.Load() {
				}
				object := Object{SHA256: Digest(entry.SHA256), Size: entry.Size}
				sourceHandle, err := openVerifiedMaterializeCAS(ctx, binding, object)
				if err != nil {
					activeWorkers.Add(-1)
					results <- result{entry: entry, err: fmt.Errorf("materialize %q: %w", entry.Path, err)}
					stopWork()
					continue
				}
				allowReplace := options.AllowReplacePath != nil && options.AllowReplacePath(entry.Path)
				outcome, err := s.materializeOne(ctx, binding, &parentCache, entry.Path, object, sourceHandle, allowReplace, testHook)
				if closeErr := sourceHandle.close(); closeErr != nil {
					err = errors.Join(err, fmt.Errorf("materialize %q: close verified CAS source: %w", entry.Path, closeErr))
				}
				activeWorkers.Add(-1)
				results <- result{entry: entry, outcome: outcome, err: err}
				if err != nil {
					_ = parentCache.close()
					stopWork()
				}
			}
		}()
	}
	go func() {
		defer group.Done()
		defer close(jobs)
		reader := manifest.NewReader(source)
		for {
			if err := ctx.Err(); err != nil {
				results <- result{err: err}
				stopWork()
				return
			}
			entry, err := reader.Next()
			if errors.Is(err, io.EOF) {
				return
			}
			if err != nil {
				results <- result{err: fmt.Errorf("read materialization manifest: %w", err)}
				stopWork()
				return
			}
			if err := validateMaterializedPath(entry.Path); err != nil {
				results <- result{entry: entry, err: err}
				stopWork()
				return
			}
			select {
			case jobs <- entry:
			case <-stop:
				return
			case <-ctx.Done():
				results <- result{err: ctx.Err()}
				stopWork()
				return
			}
		}
	}()
	go func() {
		group.Wait()
		close(results)
	}()
	var firstErr, teardownErr error
	for item := range results {
		if item.err != nil {
			if item.teardown {
				teardownErr = errors.Join(teardownErr, item.err)
				continue
			}
			if firstErr == nil || errors.Is(firstErr, context.Canceled) {
				firstErr = item.err
			}
			continue
		}
		stats.Entries++
		stats.Bytes += item.entry.Size
		switch item.outcome {
		case materializedLinked:
			stats.Linked++
		case materializedExisting:
			stats.Existing++
		case materializedRelinked:
			stats.Relinked++
		}
	}
	stats.PeakWorkers = peakWorkers.Load()
	if err := ctx.Err(); err != nil {
		return stats, errors.Join(err, firstErr, teardownErr)
	}
	if firstErr != nil || teardownErr != nil {
		return stats, errors.Join(firstErr, teardownErr)
	}
	if stats.Linked != 0 || stats.Relinked != 0 {
		if err := binding.verifyCoordinate(); err != nil {
			return stats, err
		}
		if err := syncMaterializationDirectories(binding.target, binding.targetRel == ""); err != nil {
			return stats, err
		}
		if err := binding.verifyCoordinate(); err != nil {
			return stats, err
		}
	}
	return stats, nil
}

func (s *Store) resolveMaterializationRoot(targetRoot string) (string, error) {
	target, rel, err := s.materializationTargetLocation(targetRoot)
	if err != nil {
		return "", err
	}
	created, err := ensureDirectory(s.root, rel, 0o755)
	if err != nil {
		return "", err
	}
	if created != target {
		return "", fmt.Errorf("%w: materialization target changed from %q to %q", ErrUnsafePath, target, created)
	}
	return target, nil
}

func (s *Store) materializationTargetLocation(targetRoot string) (string, string, error) {
	var target string
	if targetRoot == "" {
		target = s.root
	} else if filepath.IsAbs(targetRoot) {
		target = filepath.Clean(targetRoot)
	} else {
		if strings.ContainsAny(targetRoot, "\\\x00\t\r\n") {
			return "", "", fmt.Errorf("%w: invalid materialization root %q", ErrUnsafePath, targetRoot)
		}
		target = filepath.Join(s.root, filepath.Clean(targetRoot))
	}
	rel, err := relativeInside(s.root, target)
	if err != nil {
		return "", "", err
	}
	if rel == ".pool" || strings.HasPrefix(rel, ".pool"+string(filepath.Separator)) {
		return "", "", fmt.Errorf("%w: materialization target cannot be inside the CAS pool", ErrUnsafePath)
	}
	return target, rel, nil
}

type materializationBinding struct {
	root       *os.File
	rootInfo   os.FileInfo
	rootPath   string
	target     *os.File
	targetInfo os.FileInfo
	targetPath string
	targetRel  string
}

type materializationParent struct {
	file    *os.File
	info    os.FileInfo
	path    string
	rel     string
	binding *materializationBinding
}

type materializationParentCache struct {
	rel    string
	parent *materializationParent
}

type materializeCASHandle struct {
	binding   *materializationBinding
	shard     *os.File
	shardInfo os.FileInfo
	shardRel  string
	name      string
	file      *os.File
	info      os.FileInfo
	object    Object
}

func openVerifiedMaterializeCAS(ctx context.Context, binding *materializationBinding, object Object) (*materializeCASHandle, error) {
	if err := object.validate(); err != nil {
		return nil, err
	}
	hash := object.HashString()
	shardRel := filepath.Join(".pool", "sha256", hash[:2])
	shard, err := openMaterializeDirectoryPathAt(binding.root, shardRel, false)
	if err != nil {
		return nil, fmt.Errorf("%w: open bound CAS shard for %s: %v", ErrObjectCorrupt, hash, err)
	}
	shardInfo, err := shard.Stat()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("%w: stat bound CAS shard for %s: %v", ErrObjectCorrupt, hash, err), shard.Close())
	}
	file, info, err := openMaterializeRegularAt(shard, hash)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("%w: open bound CAS object %s: %v", ErrObjectCorrupt, hash, err), shard.Close())
	}
	handle := &materializeCASHandle{
		binding: binding, shard: shard, shardInfo: shardInfo, shardRel: shardRel,
		name: hash, file: file, info: info, object: object,
	}
	if err := handle.verifyBytes(ctx); err != nil {
		_ = handle.close()
		return nil, err
	}
	return handle, nil
}

func (handle *materializeCASHandle) close() error {
	if handle == nil {
		return nil
	}
	return errors.Join(handle.file.Close(), handle.shard.Close())
}

func (handle *materializeCASHandle) verifyCoordinate() (resultErr error) {
	currentShard, err := openMaterializeDirectoryPathAt(handle.binding.root, handle.shardRel, false)
	if err != nil {
		return fmt.Errorf("%w: CAS shard coordinate disappeared: %v", ErrObjectCorrupt, err)
	}
	defer func() {
		if closeErr := currentShard.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	currentShardInfo, err := currentShard.Stat()
	if err != nil || !os.SameFile(handle.shardInfo, currentShardInfo) {
		return errors.Join(err, fmt.Errorf("%w: CAS shard coordinate was replaced", ErrObjectCorrupt))
	}
	coordinate, coordinateInfo, err := openMaterializeRegularAt(currentShard, handle.name)
	if err != nil {
		return fmt.Errorf("%w: CAS coordinate disappeared or became unsafe: %v", ErrObjectCorrupt, err)
	}
	closeErr := coordinate.Close()
	if closeErr != nil || !os.SameFile(handle.info, coordinateInfo) {
		return errors.Join(closeErr, fmt.Errorf("%w: CAS coordinate no longer names the retained verified inode", ErrObjectCorrupt))
	}
	return nil
}

func (handle *materializeCASHandle) verifyBytes(ctx context.Context) error {
	if handle == nil || handle.file == nil || handle.info == nil {
		return fmt.Errorf("%w: retained CAS descriptor is absent", ErrObjectCorrupt)
	}
	before, err := handle.file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() != handle.object.Size || !os.SameFile(handle.info, before) {
		return errors.Join(err, fmt.Errorf("%w: retained CAS object identity or size changed", ErrObjectCorrupt))
	}
	if _, err := handle.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("%w: rewind retained CAS object: %v", ErrObjectCorrupt, err)
	}
	matches, hashErr := fileMatchesDigest(ctx, handle.file, handle.object)
	after, statErr := handle.file.Stat()
	if hashErr != nil || statErr != nil || !matches || after.Size() != handle.object.Size || !os.SameFile(before, after) {
		return errors.Join(hashErr, statErr, fmt.Errorf("%w: retained CAS object changed after initial verification", ErrObjectCorrupt))
	}
	if _, err := handle.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("%w: rewind retained CAS object after recheck: %v", ErrObjectCorrupt, err)
	}
	return handle.verifyCoordinate()
}

func (cache *materializationParentCache) open(binding *materializationBinding, relative string) (*materializationParent, error) {
	if cache.parent != nil && cache.rel == relative {
		return cache.parent, nil
	}
	if err := cache.close(); err != nil {
		return nil, err
	}
	parent, err := binding.openParent(relative)
	if err != nil {
		return nil, err
	}
	cache.rel = relative
	cache.parent = parent
	return parent, nil
}

func (cache *materializationParentCache) close() error {
	if cache == nil || cache.parent == nil {
		return nil
	}
	err := cache.parent.file.Close()
	cache.rel = ""
	cache.parent = nil
	return err
}

func bindMaterializationTarget(repositoryRoot, target string, create bool) (*materializationBinding, error) {
	rel, err := relativeInside(repositoryRoot, target)
	if err != nil {
		return nil, err
	}
	if rel == "." {
		rel = ""
	}
	root, err := openMaterializeDirectory(repositoryRoot)
	if err != nil {
		return nil, fmt.Errorf("%w: bind repository root %q: %v", ErrUnsafePath, repositoryRoot, err)
	}
	rootInfo, err := root.Stat()
	if err != nil || !rootInfo.IsDir() {
		return nil, errors.Join(err, fmt.Errorf("%w: repository root %q is not a directory", ErrUnsafePath, repositoryRoot), root.Close())
	}
	targetHandle, err := openMaterializeDirectoryPathAt(root, rel, create)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("%w: bind materialization target %q: %v", ErrUnsafePath, target, err), root.Close())
	}
	targetInfo, err := targetHandle.Stat()
	if err != nil || !targetInfo.IsDir() {
		return nil, errors.Join(err, fmt.Errorf("%w: materialization target %q is not a directory", ErrUnsafePath, target), targetHandle.Close(), root.Close())
	}
	binding := &materializationBinding{
		root: root, rootInfo: rootInfo, rootPath: repositoryRoot,
		target: targetHandle, targetInfo: targetInfo, targetPath: target, targetRel: rel,
	}
	if err := binding.verifyCoordinate(); err != nil {
		return nil, errors.Join(err, binding.close())
	}
	return binding, nil
}

func (b *materializationBinding) close() error {
	if b == nil {
		return nil
	}
	return errors.Join(b.target.Close(), b.root.Close())
}

func (b *materializationBinding) verifyCoordinate() (resultErr error) {
	currentRoot, err := openMaterializeDirectory(b.rootPath)
	if err != nil {
		return fmt.Errorf("%w: repository root coordinate changed: %v", ErrUnsafePath, err)
	}
	defer func() {
		if closeErr := currentRoot.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	currentRootInfo, err := currentRoot.Stat()
	if err != nil || !os.SameFile(b.rootInfo, currentRootInfo) {
		return errors.Join(err, fmt.Errorf("%w: repository root coordinate was replaced", ErrUnsafePath))
	}
	currentTarget, err := openMaterializeDirectoryPathAt(currentRoot, b.targetRel, false)
	if err != nil {
		return fmt.Errorf("%w: materialization target coordinate changed: %v", ErrUnsafePath, err)
	}
	defer func() {
		if closeErr := currentTarget.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	currentTargetInfo, err := currentTarget.Stat()
	if err != nil || !os.SameFile(b.targetInfo, currentTargetInfo) {
		return errors.Join(err, fmt.Errorf("%w: materialization target coordinate was replaced", ErrUnsafePath))
	}
	return nil
}

func (b *materializationBinding) openParent(relative string) (*materializationParent, error) {
	parent, err := openMaterializeDirectoryPathAt(b.target, relative, true)
	if err != nil {
		return nil, fmt.Errorf("%w: open materialization parent %q: %v", ErrUnsafePath, relative, err)
	}
	info, err := parent.Stat()
	if err != nil || !info.IsDir() {
		return nil, errors.Join(err, fmt.Errorf("%w: materialization parent %q is not a directory", ErrUnsafePath, relative), parent.Close())
	}
	result := &materializationParent{
		file: parent, info: info, path: filepath.Join(b.targetPath, relative), rel: relative, binding: b,
	}
	return result, nil
}

func (p *materializationParent) verifyCoordinate() (resultErr error) {
	current, err := openMaterializeDirectoryPathAt(p.binding.target, p.rel, false)
	if err != nil {
		return fmt.Errorf("%w: materialization parent %q changed: %v", ErrUnsafePath, p.path, err)
	}
	defer func() {
		if closeErr := current.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	currentInfo, err := current.Stat()
	if err != nil || !os.SameFile(p.info, currentInfo) {
		return errors.Join(err, fmt.Errorf("%w: materialization parent %q was replaced", ErrUnsafePath, p.path))
	}
	return nil
}

func openMaterializeDirectoryPathAt(start *os.File, relative string, create bool) (*os.File, error) {
	current, err := openMaterializeDirectoryAt(start, ".")
	if err != nil {
		return nil, err
	}
	if relative == "" || relative == "." {
		return current, nil
	}
	components := strings.Split(filepath.Clean(relative), string(filepath.Separator))
	for _, component := range components {
		if component == "" || component == "." || component == ".." || strings.ContainsAny(component, "/\\\x00") {
			return nil, errors.Join(fmt.Errorf("%w: invalid materialization directory component %q", ErrUnsafePath, component), current.Close())
		}
		next, openErr := openMaterializeDirectoryAt(current, component)
		if errors.Is(openErr, fs.ErrNotExist) && create {
			mkdirErr := mkdirMaterializeAt(current, component, 0o755)
			if mkdirErr != nil && !errors.Is(mkdirErr, fs.ErrExist) {
				return nil, errors.Join(mkdirErr, current.Close())
			}
			next, openErr = openMaterializeDirectoryAt(current, component)
		}
		if openErr != nil {
			return nil, errors.Join(openErr, current.Close())
		}
		if err := current.Close(); err != nil {
			return nil, errors.Join(err, next.Close())
		}
		current = next
	}
	return current, nil
}

func (*Store) preflightHardlink(binding *materializationBinding) (resultErr error) {
	temporaryRoot, err := openMaterializeDirectoryPathAt(binding.root, filepath.Join(".pool", "sha256", ".tmp"), false)
	if err != nil {
		return fmt.Errorf("%w: open bound CAS temporary root: %v", ErrUnsafePath, err)
	}
	defer func() { resultErr = errors.Join(resultErr, temporaryRoot.Close()) }()
	probe, probeName, err := createUniqueMaterializeFileAt(temporaryRoot, "hardlink-probe-", 0o600)
	if err != nil {
		return fmt.Errorf("create bound hardlink probe: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, probe.Close()) }()
	probeIdentity, err := fstatMaterialize(probe)
	if err != nil {
		return fmt.Errorf("identify bound hardlink probe: %w", err)
	}
	probePresent := true
	defer func() {
		if probePresent {
			resultErr = errors.Join(resultErr, quarantineRemoveMaterializeEntry(temporaryRoot, ".pool/sha256/.tmp", probeName, probeIdentity, nil))
		}
	}()
	if _, err := probe.Write([]byte("sow-hardlink-probe")); err != nil {
		return fmt.Errorf("write hardlink probe: %w", err)
	}
	if err := probe.Sync(); err != nil {
		return fmt.Errorf("sync hardlink probe: %w", err)
	}

	if err := binding.verifyCoordinate(); err != nil {
		return err
	}
	linked, err := createUniqueHardlinkFromFileAt(probe, binding.target, ".sow-hardlink-probe-")
	if err != nil {
		return fmt.Errorf("%w: bound pool and target %q: %v", ErrHardlinkRequired, binding.targetPath, err)
	}
	linkedPresent := true
	defer func() {
		if linkedPresent {
			resultErr = errors.Join(resultErr, quarantineRemoveMaterializeEntry(binding.target, binding.targetPath, linked, probeIdentity, nil))
		}
	}()
	poolInfo, err := probe.Stat()
	if err != nil {
		return fmt.Errorf("stat pool hardlink probe: %w", err)
	}
	linkedFile, targetInfo, err := openMaterializeRegularAt(binding.target, linked)
	if err != nil {
		return fmt.Errorf("stat target hardlink probe: %w", err)
	}
	if err := linkedFile.Close(); err != nil {
		return fmt.Errorf("close target hardlink probe: %w", err)
	}
	if !os.SameFile(poolInfo, targetInfo) {
		return fmt.Errorf("%w: filesystem did not create the same inode", ErrHardlinkRequired)
	}
	linkedIdentity, err := lstatMaterializeAt(binding.target, linked)
	if err != nil {
		return fmt.Errorf("identify target hardlink probe: %w", err)
	}
	if err := quarantineRemoveMaterializeEntry(binding.target, binding.targetPath, linked, linkedIdentity, nil); err != nil {
		return fmt.Errorf("remove target hardlink probe: %w", err)
	}
	linkedPresent = false
	if err := quarantineRemoveMaterializeEntry(temporaryRoot, ".pool/sha256/.tmp", probeName, probeIdentity, nil); err != nil {
		return fmt.Errorf("remove bound pool hardlink probe: %w", err)
	}
	probePresent = false
	if err := temporaryRoot.Sync(); err != nil {
		return fmt.Errorf("sync CAS temporary root after hardlink probe: %w", err)
	}
	if err := binding.target.Sync(); err != nil {
		return fmt.Errorf("sync materialization target after hardlink probe: %w", err)
	}
	if err := binding.verifyCoordinate(); err != nil {
		return err
	}
	return nil
}

type materializeOutcome uint8

const (
	materializedLinked materializeOutcome = iota + 1
	materializedExisting
	materializedRelinked
)

func (s *Store) materializeOne(ctx context.Context, binding *materializationBinding, parentCache *materializationParentCache, relativePath string, object Object, sourceHandle *materializeCASHandle, allowReplace bool, testHook materializeTestHook) (materializeOutcome, error) {
	parentRel := filepath.Dir(filepath.FromSlash(relativePath))
	if parentRel == "." {
		parentRel = ""
	}
	parent, err := parentCache.open(binding, parentRel)
	if err != nil {
		return 0, fmt.Errorf("materialize %q: %w", relativePath, err)
	}
	destinationName := filepath.Base(filepath.FromSlash(relativePath))
	destination := filepath.Join(parent.path, destinationName)
	source := s.ObjectPath(object.SHA256)
	if sourceHandle == nil || sourceHandle.file == nil {
		return 0, fmt.Errorf("materialize %q: %w: verified CAS source is nil", relativePath, ErrObjectCorrupt)
	}
	sourceFile := sourceHandle.file
	sourceInfo, err := sourceFile.Stat()
	if err != nil {
		return 0, fmt.Errorf("materialize %q: stat verified CAS source: %w", relativePath, err)
	}
	if !sourceInfo.Mode().IsRegular() || sourceInfo.Size() != object.Size {
		return 0, fmt.Errorf("materialize %q: %w: source size changed", relativePath, ErrObjectCorrupt)
	}
	sourceIdentity, err := fstatMaterialize(sourceFile)
	if err != nil {
		return 0, fmt.Errorf("materialize %q: %w: identify retained CAS source: %v", relativePath, ErrObjectCorrupt, err)
	}

	if testHook != nil {
		if err := testHook(materializeTestBeforeDirectLink, source, destination); err != nil {
			return 0, fmt.Errorf("materialize %q: direct-link test hook: %w", relativePath, err)
		}
	}
	if err := sourceHandle.verifyCoordinate(); err != nil {
		return 0, fmt.Errorf("materialize %q: %w", relativePath, err)
	}
	if err := linkMaterializeFileAt(sourceFile, parent.file, destinationName); err == nil {
		createdIdentity := sourceIdentity
		if testHook != nil {
			if hookErr := testHook(materializeTestAfterDirectLink, source, destination); hookErr != nil {
				cleanupErr := quarantineRemoveMaterializeEntry(parent.file, parent.path, destinationName, createdIdentity, testHook)
				return 0, errors.Join(fmt.Errorf("materialize %q: post-link test hook: %w", relativePath, hookErr), cleanupErr)
			}
		}
		linkedFile, linkedInfo, proofErr := openVerifiedMaterializeEntry(parent.file, destinationName, sourceInfo)
		if proofErr != nil {
			cleanupErr := quarantineRemoveMaterializeEntry(parent.file, parent.path, destinationName, createdIdentity, testHook)
			return 0, errors.Join(
				fmt.Errorf("materialize %q: %w: new destination is not the verified CAS inode: %v", relativePath, ErrObjectCorrupt, proofErr),
				cleanupErr,
			)
		}
		_ = linkedInfo
		if err := linkedFile.Close(); err != nil {
			cleanupErr := quarantineRemoveMaterializeEntry(parent.file, parent.path, destinationName, createdIdentity, testHook)
			return 0, errors.Join(fmt.Errorf("materialize %q: close new destination: %w", relativePath, err), cleanupErr)
		}
		if err := sourceHandle.verifyBytes(ctx); err != nil {
			cleanupErr := quarantineRemoveMaterializeEntry(parent.file, parent.path, destinationName, createdIdentity, testHook)
			return 0, errors.Join(fmt.Errorf("materialize %q: %w", relativePath, err), cleanupErr)
		}
		if err := verifyMaterializeEntryIdentity(parent.file, destinationName, sourceInfo); err != nil {
			cleanupErr := quarantineRemoveMaterializeEntry(parent.file, parent.path, destinationName, createdIdentity, testHook)
			return 0, errors.Join(fmt.Errorf("materialize %q: %w", relativePath, err), cleanupErr)
		}
		if err := parent.verifyCoordinate(); err != nil {
			cleanupErr := quarantineRemoveMaterializeEntry(parent.file, parent.path, destinationName, createdIdentity, testHook)
			return 0, errors.Join(fmt.Errorf("materialize %q: %w", relativePath, err), cleanupErr)
		}
		return materializedLinked, nil
	} else if !errors.Is(err, fs.ErrExist) {
		return 0, fmt.Errorf("materialize %q: %w: %v", relativePath, ErrHardlinkRequired, err)
	}
	destinationFile, destinationInfo, err := openMaterializeRegularAt(parent.file, destinationName)
	if err != nil {
		return 0, fmt.Errorf("materialize %q: %w: %v", relativePath, ErrMaterializeConflict, err)
	}
	if os.SameFile(sourceInfo, destinationInfo) {
		if err := destinationFile.Close(); err != nil {
			return 0, fmt.Errorf("materialize %q: close existing hardlink: %w", relativePath, err)
		}
		if err := sourceHandle.verifyBytes(ctx); err != nil {
			return 0, fmt.Errorf("materialize %q: %w", relativePath, err)
		}
		if err := verifyMaterializeEntryIdentity(parent.file, destinationName, sourceInfo); err != nil {
			return 0, fmt.Errorf("materialize %q: %w", relativePath, err)
		}
		if err := parent.verifyCoordinate(); err != nil {
			return 0, fmt.Errorf("materialize %q: %w", relativePath, err)
		}
		return materializedExisting, nil
	}
	if destinationInfo.Size() != object.Size && !allowReplace {
		return 0, errors.Join(
			fmt.Errorf("materialize %q: %w: existing size %d, wanted %d", relativePath, ErrMaterializeConflict, destinationInfo.Size(), object.Size),
			destinationFile.Close(),
		)
	}
	matches, hashErr := fileMatchesDigest(ctx, destinationFile, object)
	closeErr := destinationFile.Close()
	if hashErr != nil {
		return 0, fmt.Errorf("materialize %q: verify existing file: %w", relativePath, hashErr)
	}
	if closeErr != nil {
		return 0, fmt.Errorf("materialize %q: close existing file: %w", relativePath, closeErr)
	}
	if !matches && !allowReplace {
		return 0, fmt.Errorf("materialize %q: %w: existing bytes differ", relativePath, ErrMaterializeConflict)
	}

	if testHook != nil {
		if err := testHook(materializeTestBeforeReplacementLink, source, destination); err != nil {
			return 0, fmt.Errorf("materialize %q: replacement-link test hook: %w", relativePath, err)
		}
	}
	if err := sourceHandle.verifyCoordinate(); err != nil {
		return 0, fmt.Errorf("materialize %q: %w", relativePath, err)
	}
	temporaryName, err := createUniqueHardlinkFromFileAt(sourceFile, parent.file, ".sow-materialize-")
	if err != nil {
		return 0, fmt.Errorf("materialize %q: %w: create replacement link: %v", relativePath, ErrHardlinkRequired, err)
	}
	temporary := filepath.Join(parent.path, temporaryName)
	temporaryFile, _, proofErr := openVerifiedMaterializeEntry(parent.file, temporaryName, sourceInfo)
	if proofErr != nil {
		cleanupErr := cleanupMaterializeTemporary(parent.file, parent.path, temporaryName, nil)
		return 0, errors.Join(
			fmt.Errorf("materialize %q: %w: replacement link is not the verified CAS inode: %v", relativePath, ErrObjectCorrupt, proofErr),
			cleanupErr,
		)
	}
	if err := temporaryFile.Close(); err != nil {
		temporaryIdentity, _ := lstatMaterializeAt(parent.file, temporaryName)
		cleanupErr := quarantineRemoveMaterializeEntry(parent.file, parent.path, temporaryName, temporaryIdentity, nil)
		return 0, errors.Join(fmt.Errorf("materialize %q: close replacement link: %w", relativePath, err), cleanupErr)
	}
	if testHook != nil {
		if err := testHook(materializeTestAfterReplacementTempProof, temporary, destination); err != nil {
			cleanupErr := cleanupMaterializeTemporary(parent.file, parent.path, temporaryName, nil)
			return 0, errors.Join(fmt.Errorf("materialize %q: post-temp test hook: %w", relativePath, err), cleanupErr)
		}
	}
	if err := verifyMaterializeEntryIdentity(parent.file, temporaryName, sourceInfo); err != nil {
		cleanupErr := cleanupMaterializeTemporary(parent.file, parent.path, temporaryName, nil)
		return 0, errors.Join(fmt.Errorf("materialize %q: %w: replacement temporary changed before exchange", relativePath, ErrMaterializeConflict), err, cleanupErr)
	}
	if err := verifyMaterializeEntryIdentity(parent.file, destinationName, destinationInfo); err != nil {
		cleanupErr := cleanupMaterializeTemporary(parent.file, parent.path, temporaryName, nil)
		return 0, errors.Join(
			fmt.Errorf("materialize %q: %w: destination changed during relink", relativePath, ErrMaterializeConflict),
			cleanupErr,
		)
	}
	preTemporaryIdentity, tempIdentityErr := lstatMaterializeAt(parent.file, temporaryName)
	preDestinationIdentity, destinationIdentityErr := lstatMaterializeAt(parent.file, destinationName)
	if tempIdentityErr != nil || destinationIdentityErr != nil {
		cleanupErr := cleanupMaterializeTemporary(parent.file, parent.path, temporaryName, nil)
		return 0, errors.Join(
			fmt.Errorf("materialize %q: %w: bind exchange inputs", relativePath, ErrMaterializeConflict),
			tempIdentityErr, destinationIdentityErr, cleanupErr,
		)
	}
	if testHook != nil {
		if err := testHook(materializeTestBeforeReplacementExchange, temporary, destination); err != nil {
			cleanupErr := cleanupMaterializeTemporary(parent.file, parent.path, temporaryName, nil)
			return 0, errors.Join(fmt.Errorf("materialize %q: pre-exchange test hook: %w", relativePath, err), cleanupErr)
		}
	}
	if err := exchangeMaterializeAt(parent.file, temporaryName, destinationName); err != nil {
		cleanupErr := cleanupMaterializeTemporary(parent.file, parent.path, temporaryName, nil)
		return 0, errors.Join(fmt.Errorf("materialize %q: descriptor-bound atomic exchange: %w", relativePath, err), cleanupErr)
	}
	installedIdentity, installedIdentityErr := lstatMaterializeAt(parent.file, destinationName)
	displacedIdentity, displacedIdentityErr := lstatMaterializeAt(parent.file, temporaryName)
	installedInfo, installedErr := materializeEntryInfo(parent.file, destinationName)
	displacedInfo, displacedErr := materializeEntryInfo(parent.file, temporaryName)
	if installedIdentityErr != nil || displacedIdentityErr != nil || installedErr != nil || displacedErr != nil ||
		installedIdentity != preTemporaryIdentity || displacedIdentity != preDestinationIdentity ||
		!os.SameFile(sourceInfo, installedInfo) || !os.SameFile(destinationInfo, displacedInfo) {
		rollbackErr := rollbackMaterializeExchange(parent, temporaryName, destinationName, displacedIdentity, installedIdentity, nil)
		return 0, errors.Join(
			fmt.Errorf("materialize %q: %w: exchange inputs changed concurrently", relativePath, ErrMaterializeConflict),
			installedIdentityErr, displacedIdentityErr, installedErr, displacedErr, rollbackErr,
		)
	}
	if err := parent.verifyCoordinate(); err != nil {
		rollbackErr := rollbackMaterializeExchange(parent, temporaryName, destinationName, displacedIdentity, installedIdentity, nil)
		return 0, errors.Join(fmt.Errorf("materialize %q: %w", relativePath, err), rollbackErr)
	}
	if err := sourceHandle.verifyBytes(ctx); err != nil {
		rollbackErr := rollbackMaterializeExchange(parent, temporaryName, destinationName, displacedIdentity, installedIdentity, nil)
		return 0, errors.Join(fmt.Errorf("materialize %q: %w", relativePath, err), rollbackErr)
	}
	if err := verifyMaterializeEntryIdentity(parent.file, destinationName, sourceInfo); err != nil {
		rollbackErr := rollbackMaterializeExchange(parent, temporaryName, destinationName, displacedIdentity, installedIdentity, nil)
		return 0, errors.Join(fmt.Errorf("materialize %q: %w", relativePath, err), rollbackErr)
	}
	if err := quarantineRemoveMaterializeEntry(parent.file, parent.path, temporaryName, displacedIdentity, testHook); err != nil {
		rollbackErr := rollbackMaterializeExchange(parent, temporaryName, destinationName, displacedIdentity, installedIdentity, nil)
		return 0, errors.Join(fmt.Errorf("materialize %q: retire displaced destination: %w", relativePath, err), rollbackErr)
	}
	if err := verifyMaterializeEntryIdentity(parent.file, destinationName, sourceInfo); err != nil {
		return 0, errors.Join(
			fmt.Errorf("materialize %q: %w: installed destination changed after commit", relativePath, ErrMaterializeConflict),
			err,
		)
	}
	if err := parent.verifyCoordinate(); err != nil {
		return 0, fmt.Errorf("materialize %q: %w", relativePath, err)
	}
	return materializedRelinked, nil
}

func openMaterializeRegularAt(parent *os.File, name string) (*os.File, os.FileInfo, error) {
	file, err := openMaterializeEntryAt(parent, name)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, info, errors.Join(err, fmt.Errorf("%w: %q is not a regular file", ErrUnsafePath, name), file.Close())
	}
	openedIdentity, identityErr := fstatMaterialize(file)
	currentIdentity, currentErr := lstatMaterializeAt(parent, name)
	if identityErr != nil || currentErr != nil || openedIdentity != currentIdentity {
		return nil, info, errors.Join(identityErr, currentErr, fmt.Errorf("%w: materialization entry %q changed while opening", ErrUnsafePath, name), file.Close())
	}
	return file, info, nil
}

func materializeEntryInfo(parent *os.File, name string) (os.FileInfo, error) {
	file, info, err := openMaterializeRegularAt(parent, name)
	if file != nil {
		err = errors.Join(err, file.Close())
	}
	return info, err
}

func openVerifiedMaterializeEntry(parent *os.File, name string, verified os.FileInfo) (*os.File, os.FileInfo, error) {
	file, info, err := openMaterializeRegularAt(parent, name)
	if err != nil {
		return nil, info, err
	}
	if verified == nil || !os.SameFile(verified, info) {
		return nil, info, errors.Join(fmt.Errorf("%w: materialization entry %q is not the retained CAS inode", ErrObjectCorrupt, name), file.Close())
	}
	return file, info, nil
}

func verifyMaterializeEntryIdentity(parent *os.File, name string, expected os.FileInfo) error {
	file, _, err := openVerifiedMaterializeEntry(parent, name, expected)
	if file != nil {
		err = errors.Join(err, file.Close())
	}
	return err
}

func cleanupMaterializeTemporary(parent *os.File, parentPath, name string, testHook materializeTestHook) error {
	identity, err := lstatMaterializeAt(parent, name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return quarantineRemoveMaterializeEntry(parent, parentPath, name, identity, testHook)
}

// quarantineRemoveMaterializeEntry first moves a name to an unpredictable
// sibling with RENAME_NOREPLACE/RENAME_EXCL. The identity check therefore
// cannot race with deleting a concurrent replacement at the logical name: a
// mismatch is restored without overwrite and is never unlinked.
func quarantineRemoveMaterializeEntry(parent *os.File, parentPath, name string, expected materializeFileIdentity, testHook materializeTestHook) error {
	if !expected.valid() {
		return nil
	}
	for attempt := 0; attempt < 32; attempt++ {
		quarantine, err := randomMaterializeName(".sow-materialize-quarantine-")
		if err != nil {
			return err
		}
		if testHook != nil {
			if hookErr := testHook(materializeTestBeforeCleanupQuarantine, filepath.Join(parentPath, name), filepath.Join(parentPath, quarantine)); hookErr != nil {
				return hookErr
			}
		}
		err = renameMaterializeNoReplaceAt(parent, name, quarantine)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		quarantined, inspectErr := lstatMaterializeAt(parent, quarantine)
		if inspectErr != nil || quarantined != expected {
			restoreErr := renameMaterializeNoReplaceAt(parent, quarantine, name)
			return errors.Join(
				inspectErr,
				fmt.Errorf("%w: materialization entry %q was replaced before cleanup", ErrUnsafePath, filepath.Join(parentPath, name)),
				restoreErr,
			)
		}
		if err := unlinkMaterializeAt(parent, quarantine); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	return errors.New("could not allocate materialization quarantine name")
}

func rollbackMaterializeExchange(parent *materializationParent, temporaryName, destinationName string, currentTemporary, currentDestination materializeFileIdentity, testHook materializeTestHook) error {
	if !currentTemporary.valid() || !currentDestination.valid() {
		return fmt.Errorf("%w: cannot roll back exchange without both inode identities", ErrUnsafePath)
	}
	actualTemporary, err := lstatMaterializeAt(parent.file, temporaryName)
	if err != nil || actualTemporary != currentTemporary {
		return fmt.Errorf("%w: temporary changed before exchange rollback: %v", ErrUnsafePath, err)
	}
	actualDestination, err := lstatMaterializeAt(parent.file, destinationName)
	if err != nil || actualDestination != currentDestination {
		return fmt.Errorf("%w: destination changed before exchange rollback: %v", ErrUnsafePath, err)
	}
	if err := exchangeMaterializeAt(parent.file, temporaryName, destinationName); err != nil {
		return fmt.Errorf("roll back descriptor-bound exchange: %w", err)
	}
	restoredDestination, err := lstatMaterializeAt(parent.file, destinationName)
	if err != nil || restoredDestination != currentTemporary {
		return fmt.Errorf("%w: restored destination failed identity proof: %v", ErrUnsafePath, err)
	}
	return quarantineRemoveMaterializeEntry(parent.file, parent.path, temporaryName, currentDestination, testHook)
}

// syncMaterializationDirectories is the durability barrier for a completed
// batch. Per-file directory fsync turns a 50k hardlink materialization into
// 50k serialized storage barriers; replay safety lets SOW install all links
// first and sync each real directory once before reporting success.
func syncMaterializationDirectories(root *os.File, skipReserved bool) (resultErr error) {
	bound, err := openMaterializeDirectoryAt(root, ".")
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := bound.Close(); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	return syncMaterializationDirectory(bound, skipReserved)
}

func syncMaterializationDirectory(directory *os.File, skipReserved bool) error {
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if skipReserved && (entry.Name() == ".pool" || entry.Name() == ".sow") {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlink in materialization tree at %q", ErrUnsafePath, entry.Name())
		}
		if !entry.IsDir() {
			continue
		}
		child, err := openMaterializeDirectoryAt(directory, entry.Name())
		if err != nil {
			return fmt.Errorf("%w: open materialization directory %q: %v", ErrUnsafePath, entry.Name(), err)
		}
		childErr := syncMaterializationDirectory(child, false)
		closeErr := child.Close()
		if childErr != nil || closeErr != nil {
			return errors.Join(childErr, closeErr)
		}
	}
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync materialization directory: %w", err)
	}
	return nil
}

func fileMatchesDigest(ctx context.Context, file *os.File, object Object) (bool, error) {
	hasher := sha256.New()
	buffer := acquireCopyBuffer()
	defer releaseCopyBuffer(buffer)
	written, err := io.CopyBuffer(hasher, contextReader{ctx: ctx, reader: file}, *buffer)
	if err != nil {
		return false, err
	}
	if written != object.Size {
		return false, nil
	}
	var actual Digest
	copy(actual[:], hasher.Sum(nil))
	return actual == object.SHA256, nil
}

func createUniqueMaterializeFileAt(directory *os.File, prefix string, mode os.FileMode) (*os.File, string, error) {
	for attempt := 0; attempt < 32; attempt++ {
		candidate, err := randomMaterializeName(prefix)
		if err != nil {
			return nil, "", err
		}
		file, err := createMaterializeFileAt(directory, candidate, mode)
		if err == nil {
			return file, candidate, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", errors.New("could not allocate unique materialization file name")
}

func createUniqueHardlinkFromFileAt(source *os.File, directory *os.File, prefix string) (string, error) {
	for attempt := 0; attempt < 32; attempt++ {
		candidate, err := randomMaterializeName(prefix)
		if err != nil {
			return "", err
		}
		if err := linkMaterializeFileAt(source, directory, candidate); err == nil {
			return candidate, nil
		} else if !errors.Is(err, fs.ErrExist) {
			return "", err
		}
	}
	return "", errors.New("could not allocate unique descriptor hardlink name")
}

func randomMaterializeName(prefix string) (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(random[:]), nil
}
