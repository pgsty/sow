package repository

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"github.com/pgsty/sow/internal/manifest"
)

// ReconcileStats reports stale paths removed after a successful hardlink
// materialization. Verification always performs a full local scan because
// materialize is an explicit, expensive operation rather than a publish fast
// path.
type ReconcileStats struct {
	RemovedFiles int64
}

// ReconcileExact removes regular files not present in desiredManifest and then
// proves the target is byte-for-byte equal. It never follows symlinks and does
// not remove a file until Materialize has already verified every desired CAS
// object. An interruption can leave stale files, but replay is safe and exact.
func (s *Store) ReconcileExact(ctx context.Context, desiredManifest, targetRoot string, workers, chunkEntries int) (ReconcileStats, error) {
	var result ReconcileStats
	if s.readOnly {
		return result, fmt.Errorf("%w: read-only CAS cannot reconcile materialized paths", ErrUnsafePath)
	}
	target, err := s.resolveMaterializationRoot(targetRoot)
	if err != nil {
		return result, err
	}
	current, err := os.CreateTemp(s.tempRoot, "materialized-current-*.tsv")
	if err != nil {
		return result, err
	}
	currentPath := current.Name()
	if err := current.Close(); err != nil {
		os.Remove(currentPath)
		return result, err
	}
	defer os.Remove(currentPath)
	shadowPolicy := manifest.ShadowIncludeAll
	if target == s.root {
		// The repository root owns these three operator directories. A
		// sub-target is an exact export and has no such exemption.
		shadowPolicy = manifest.ShadowExcludeScopeRoot
	}
	if _, err := manifest.Scan(ctx, target, manifest.Scope{Path: "."}, currentPath, manifest.ScanOptions{
		Workers: workers, ChunkEntries: chunkEntries, TempDir: s.tempRoot, ShadowPolicy: shadowPolicy,
	}); err != nil {
		return result, fmt.Errorf("scan materialized target: %w", err)
	}
	desired, err := os.Open(desiredManifest)
	if err != nil {
		return result, err
	}
	actual, err := os.Open(currentPath)
	if err != nil {
		desired.Close()
		return result, err
	}
	diff, compareErr := manifest.Diff(desired, actual, func(change manifest.Change) error {
		switch change.Kind {
		case manifest.Added:
			if err := removeExactMaterializedPath(target, change.New.Path, target != s.root); err != nil {
				return err
			}
			result.RemovedFiles++
			return nil
		case manifest.Removed:
			return fmt.Errorf("materialized target is missing desired path %q", change.Old.Path)
		case manifest.Changed:
			return fmt.Errorf("materialized target path %q differs after hardlink installation", change.New.Path)
		default:
			return fmt.Errorf("unknown materialization diff kind %q", change.Kind)
		}
	})
	closeErr := errors.Join(desired.Close(), actual.Close())
	if compareErr != nil || closeErr != nil {
		return result, errors.Join(compareErr, closeErr)
	}
	if diff.Removed != 0 || diff.Changed != 0 {
		return result, errors.New("materialized target was incomplete after CAS installation")
	}
	if result.RemovedFiles > 0 {
		if err := removeEmptyDirectories(target); err != nil {
			return result, err
		}
	}
	if err := verifyMaterializedExact(ctx, target, desiredManifest, currentPath, s.tempRoot, workers, chunkEntries, shadowPolicy); err != nil {
		return result, err
	}
	return result, nil
}

func removeMaterializedPathWithHook(root, relative string, beforeRemove func(string) error) (resultErr error) {
	return removeExactMaterializedPathWithHook(root, relative, false, beforeRemove)
}

func removeExactMaterializedPath(root, relative string, allowReservedPrefix bool) error {
	return removeExactMaterializedPathWithHook(root, relative, allowReservedPrefix, nil)
}

func removeExactMaterializedPathWithHook(root, relative string, allowReservedPrefix bool, beforeRemove func(string) error) (resultErr error) {
	if err := validateMaterializedPathPolicy(relative, allowReservedPrefix); err != nil {
		return err
	}
	fullPath := filepath.Join(root, filepath.FromSlash(relative))
	if _, err := relativeInside(root, fullPath); err != nil {
		return err
	}
	binding, err := bindMaterializationTarget(root, root, false)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, binding.close()) }()
	parentRel := filepath.Dir(filepath.FromSlash(relative))
	if parentRel == "." {
		parentRel = ""
	}
	parentFile, err := openMaterializeDirectoryPathAt(binding.target, parentRel, false)
	if err != nil {
		return fmt.Errorf("%w: open stale materialization parent %q: %v", ErrUnsafePath, parentRel, err)
	}
	defer func() { resultErr = errors.Join(resultErr, parentFile.Close()) }()
	parentInfo, err := parentFile.Stat()
	if err != nil || !parentInfo.IsDir() {
		return errors.Join(err, fmt.Errorf("%w: stale materialization parent %q is not a directory", ErrUnsafePath, parentRel))
	}
	parent := &materializationParent{
		file: parentFile, info: parentInfo, path: filepath.Join(root, parentRel), rel: parentRel, binding: binding,
	}
	name := filepath.Base(filepath.FromSlash(relative))
	file, _, err := openMaterializeRegularAt(parentFile, name)
	if err != nil {
		return fmt.Errorf("%w: refuse to prune unsafe path %q: %v", ErrUnsafePath, relative, err)
	}
	expected, identityErr := fstatMaterialize(file)
	closeErr := file.Close()
	if identityErr != nil || closeErr != nil {
		return errors.Join(identityErr, closeErr, fmt.Errorf("identify stale materialized path %q", relative))
	}
	if beforeRemove != nil {
		if err := beforeRemove(fullPath); err != nil {
			return err
		}
	}
	removeErr := quarantineRemoveMaterializeEntry(parentFile, parent.path, name, expected, nil)
	syncErr := parentFile.Sync()
	coordinateErr := errors.Join(parent.verifyCoordinate(), binding.verifyCoordinate())
	if removeErr != nil || syncErr != nil || coordinateErr != nil {
		return fmt.Errorf("prune stale materialized path %q: %w", relative, errors.Join(removeErr, syncErr, coordinateErr))
	}
	return nil
}

func removeEmptyDirectories(root string) error {
	var directories []string
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlink in materialization target %q", ErrUnsafePath, path)
		}
		if entry.IsDir() && path != root {
			directories = append(directories, path)
		}
		return nil
	}); err != nil {
		return err
	}
	sort.Slice(directories, func(i, j int) bool { return len(directories[i]) > len(directories[j]) })
	for _, directory := range directories {
		if err := os.Remove(directory); err != nil && !errors.Is(err, fs.ErrNotExist) {
			// A non-empty directory belongs to the desired tree.
			if !errors.Is(err, syscall.ENOTEMPTY) && !errors.Is(err, syscall.EEXIST) {
				return err
			}
		}
	}
	return syncDirectory(root)
}

func verifyMaterializedExact(ctx context.Context, target, desiredManifest, scratch, tempDir string, workers, chunkEntries int, shadowPolicy manifest.ShadowPolicy) error {
	if _, err := manifest.Scan(ctx, target, manifest.Scope{Path: "."}, scratch, manifest.ScanOptions{
		Workers: workers, ChunkEntries: chunkEntries, TempDir: tempDir, ShadowPolicy: shadowPolicy,
	}); err != nil {
		return fmt.Errorf("verify materialized target: %w", err)
	}
	desired, err := os.Open(desiredManifest)
	if err != nil {
		return err
	}
	actual, err := os.Open(scratch)
	if err != nil {
		desired.Close()
		return err
	}
	diff, diffErr := manifest.Diff(desired, actual, nil)
	closeErr := errors.Join(desired.Close(), actual.Close())
	if diffErr != nil || closeErr != nil {
		return errors.Join(diffErr, closeErr)
	}
	if !diff.Clean() {
		return fmt.Errorf("materialized target failed exact verification: added=%d removed=%d changed=%d", diff.Added, diff.Removed, diff.Changed)
	}
	return nil
}
