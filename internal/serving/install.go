package serving

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
)

type InstallOptions struct {
	Workers      int
	ChunkEntries int
	TempDir      string
}

type InstallResult struct {
	Created     bool
	Entries     int64
	Bytes       int64
	PeakWorkers int64
}

// installTargetRoot binds one install transaction to the directory inode that
// was validated at entry. SOW's supported local concurrency model has one
// writer, so namespace mutation by another process is not a supported writer
// race. The binding nevertheless makes phase-boundary drift fail closed and
// keeps stage rename/removal anchored to the original directory even if an
// operator renames the target while an install is in flight.
type installTargetRoot struct {
	path     string
	root     *os.Root
	identity os.FileInfo
}

type installMutationHook func(phase string) error
type installMutationHookContextKey struct{}

// withInstallMutationHook is deliberately unexported. It is a deterministic
// fault-injection seam for proving that every target-tree mutation rechecks the
// bound inode after the hook and before using any path-based helper.
func withInstallMutationHook(ctx context.Context, hook installMutationHook) context.Context {
	return context.WithValue(ctx, installMutationHookContextKey{}, hook)
}

func bindInstallTargetRoot(path string) (*installTargetRoot, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.Join(err, errors.New("serving target root is not a real directory"))
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("bind serving target root: %w", err)
	}
	opened, err := root.Stat(".")
	if err != nil || !opened.IsDir() || !os.SameFile(before, opened) {
		_ = root.Close()
		return nil, errors.Join(err, errors.New("serving target root changed while binding its inode"))
	}
	return &installTargetRoot{path: path, root: root, identity: opened}, nil
}

func (r *installTargetRoot) Close() error {
	if r == nil || r.root == nil {
		return nil
	}
	return r.root.Close()
}

func (r *installTargetRoot) Check(phase string) error {
	if r == nil || r.root == nil {
		return errors.New("nil serving target root binding")
	}
	bound, boundErr := r.root.Stat(".")
	current, pathErr := os.Lstat(r.path)
	if boundErr != nil || pathErr != nil || !bound.IsDir() || !current.IsDir() ||
		current.Mode()&os.ModeSymlink != 0 || !os.SameFile(r.identity, bound) || !os.SameFile(r.identity, current) {
		return errors.Join(boundErr, pathErr, fmt.Errorf("serving target root identity changed %s", phase))
	}
	return nil
}

func (r *installTargetRoot) Mutate(ctx context.Context, phase string, mutation func() error) error {
	if mutation == nil {
		return errors.New("nil serving target mutation")
	}
	if err := r.Check("before " + phase); err != nil {
		return err
	}
	if hook, ok := ctx.Value(installMutationHookContextKey{}).(installMutationHook); ok && hook != nil {
		if err := hook(phase); err != nil {
			return fmt.Errorf("serving target mutation hook %s: %w", phase, err)
		}
	}
	// The second check is intentional: tests (and real operator mistakes) may
	// replace the namespace entry between phase admission and the mutation.
	if err := r.Check("immediately before " + phase); err != nil {
		return err
	}
	mutationErr := mutation()
	identityErr := r.Check("after " + phase)
	if mutationErr != nil {
		mutationErr = fmt.Errorf("%s: %w", phase, mutationErr)
	}
	return errors.Join(mutationErr, identityErr)
}

func InstallGeneration(ctx context.Context, pool *repository.Store, targetRoot string, generation Generation, manifestPath string, options InstallOptions) (InstallResult, error) {
	var result InstallResult
	if pool == nil {
		return result, errors.New("nil CAS store")
	}
	if err := generation.Validate(); err != nil {
		return result, err
	}
	if err := validateGenerationManifest(generation, manifestPath); err != nil {
		return result, err
	}
	targetRoot, err := validateTargetRoot(pool.Root(), targetRoot)
	if err != nil {
		return result, err
	}
	target, err := bindInstallTargetRoot(targetRoot)
	if err != nil {
		return result, err
	}
	defer target.Close()
	if options.Workers < 1 || options.ChunkEntries < 1 || options.TempDir == "" {
		return result, errors.New("generation install requires positive workers/chunk entries and a temp directory")
	}
	if err := target.Check("before CAS adoption"); err != nil {
		return result, err
	}
	if err := ensureManifestCAS(ctx, pool, targetRoot, manifestPath); err != nil {
		return result, err
	}
	if err := target.Check("after CAS adoption"); err != nil {
		return result, err
	}

	generationBase := filepath.Join(targetRoot, "_sow", "v1", "g")
	if err := target.Mutate(ctx, "ensure-generation-base", func() error {
		return ensureRealDirectories(targetRoot, filepath.Join("_sow", "v1", "g"))
	}); err != nil {
		return result, err
	}
	final := filepath.Join(generationBase, generation.ID)
	finalRelative := filepath.Join("_sow", "v1", "g", generation.ID)
	if _, err := target.root.Lstat(finalRelative); err == nil {
		if err := target.Check("before occupied generation validation"); err != nil {
			return result, err
		}
		if err := validateTreeAgainstManifest(ctx, final, manifestPath, options); err != nil {
			return result, fmt.Errorf("occupied generation %s collides or drifted: %w", generation.ID, err)
		}
		if err := target.Check("after occupied generation validation"); err != nil {
			return result, err
		}
		manifestFile, err := os.Open(manifestPath)
		if err != nil {
			return result, err
		}
		var materialized repository.MaterializeStats
		var materializeErr error
		mutationErr := target.Mutate(ctx, "repair-occupied-generation", func() error {
			materialized, materializeErr = pool.MaterializeWithOptions(ctx, manifestFile, final, repository.MaterializeOptions{Workers: options.Workers})
			return materializeErr
		})
		closeErr := manifestFile.Close()
		if mutationErr != nil || closeErr != nil {
			return result, errors.Join(mutationErr, closeErr)
		}
		if err := target.Mutate(ctx, "publish-occupied-generation", func() error {
			return PublishHostableTree(final)
		}); err != nil {
			return result, fmt.Errorf("repair occupied generation %s permissions: %w", generation.ID, err)
		}
		if err := target.Check("before final occupied generation validation"); err != nil {
			return result, err
		}
		if err := ValidateInstalledGeneration(ctx, pool, targetRoot, generation, manifestPath, options); err != nil {
			return result, fmt.Errorf("validate occupied generation %s: %w", generation.ID, err)
		}
		if err := target.Check("after final occupied generation validation"); err != nil {
			return result, err
		}
		stats, err := manifestStats(manifestPath)
		if err != nil {
			return result, err
		}
		return InstallResult{Entries: stats.Files, Bytes: stats.Bytes, PeakWorkers: materialized.PeakWorkers}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, err
	}

	var stage, stageRelative string
	if err := target.Mutate(ctx, "create-generation-stage", func() error {
		var createErr error
		stage, stageRelative, createErr = createGenerationStageBound(target, generation.ID)
		return createErr
	}); err != nil {
		return result, fmt.Errorf("create generation stage: %w", err)
	}
	keepStage := false
	defer func() {
		if !keepStage {
			_ = target.root.RemoveAll(stageRelative)
		}
	}()
	source, err := os.Open(manifestPath)
	if err != nil {
		return result, err
	}
	var materialized repository.MaterializeStats
	var materializeErr error
	mutationErr := target.Mutate(ctx, "materialize-generation-stage", func() error {
		materialized, materializeErr = pool.MaterializeWithOptions(ctx, source, stage, repository.MaterializeOptions{Workers: options.Workers})
		return materializeErr
	})
	closeErr := source.Close()
	if mutationErr != nil || closeErr != nil {
		return result, errors.Join(mutationErr, closeErr)
	}
	if err := target.Check("before staged generation validation"); err != nil {
		return result, err
	}
	if err := validateTreeAgainstManifest(ctx, stage, manifestPath, options); err != nil {
		return result, fmt.Errorf("verify staged generation: %w", err)
	}
	if err := target.Check("after staged generation validation"); err != nil {
		return result, err
	}
	if err := target.Mutate(ctx, "sync-generation-stage", func() error {
		return syncTree(stage)
	}); err != nil {
		return result, err
	}
	if err := target.Mutate(ctx, "publish-generation-stage", func() error {
		return PublishHostableTree(stage)
	}); err != nil {
		return result, fmt.Errorf("make generation hostable: %w", err)
	}
	renameErr := target.Mutate(ctx, "install-generation-stage", func() error {
		return target.root.Rename(stageRelative, finalRelative)
	})
	if renameErr != nil {
		if err := target.Check("before occupied install reconciliation"); err != nil {
			return result, errors.Join(renameErr, err)
		}
		if validateErr := ValidateInstalledGeneration(ctx, pool, targetRoot, generation, manifestPath, options); validateErr != nil {
			return result, errors.Join(fmt.Errorf("install immutable generation: %w", renameErr), validateErr)
		}
		if err := target.Check("after occupied install reconciliation"); err != nil {
			return result, errors.Join(renameErr, err)
		}
		return InstallResult{Entries: materialized.Entries, Bytes: materialized.Bytes, PeakWorkers: materialized.PeakWorkers}, nil
	}
	keepStage = true
	if err := target.Mutate(ctx, "sync-generation-parent", func() error {
		directory, err := target.root.Open(filepath.Join("_sow", "v1", "g"))
		if err != nil {
			return err
		}
		return errors.Join(directory.Sync(), directory.Close())
	}); err != nil {
		return result, err
	}
	if err := target.Check("before installed generation validation"); err != nil {
		return result, err
	}
	if err := ValidateInstalledGeneration(ctx, pool, targetRoot, generation, manifestPath, options); err != nil {
		return result, fmt.Errorf("verify installed generation: %w", err)
	}
	if err := target.Check("after installed generation validation"); err != nil {
		return result, err
	}
	return InstallResult{Created: true, Entries: materialized.Entries, Bytes: materialized.Bytes, PeakWorkers: materialized.PeakWorkers}, nil
}

func ValidateInstalledGeneration(ctx context.Context, pool *repository.Store, targetRoot string, generation Generation, manifestPath string, options InstallOptions) (resultErr error) {
	if pool == nil {
		return errors.New("nil CAS store")
	}
	if err := generation.Validate(); err != nil {
		return err
	}
	if err := validateGenerationManifest(generation, manifestPath); err != nil {
		return err
	}
	confinedRoot, err := validateTargetRoot(pool.Root(), targetRoot)
	if err != nil {
		return err
	}
	if _, err := installedGenerationRoot(confinedRoot, generation.ID); err != nil {
		return err
	}
	root, err := os.OpenRoot(confinedRoot)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	return ValidateInstalledGenerationRoot(ctx, pool, root, generation, manifestPath, options)
}

func ScanInstalledGeneration(ctx context.Context, pool *repository.Store, targetRoot string, generation Generation, destination string, options InstallOptions) error {
	if pool == nil {
		return errors.New("nil CAS store")
	}
	if err := generation.Validate(); err != nil {
		return err
	}
	confinedRoot, err := validateTargetRoot(pool.Root(), targetRoot)
	if err != nil {
		return err
	}
	root, err := installedGenerationRoot(confinedRoot, generation.ID)
	if err != nil {
		return err
	}
	_, err = manifest.Scan(ctx, root, manifest.Scope{Path: "."}, destination, manifest.ScanOptions{
		Workers: options.Workers, ChunkEntries: options.ChunkEntries, TempDir: options.TempDir,
	})
	return err
}

func createGenerationStageBound(target *installTargetRoot, generationID string) (string, string, error) {
	for range 8 {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return "", "", err
		}
		name := ".stage-" + generationID + "-" + hex.EncodeToString(nonce[:])
		relative := filepath.Join("_sow", "v1", "g", name)
		if err := target.root.Mkdir(relative, 0o700); err == nil {
			return filepath.Join(target.path, relative), relative, nil
		} else if !errors.Is(err, os.ErrExist) {
			return "", "", fmt.Errorf("create generation stage: %w", err)
		}
	}
	return "", "", errors.New("create generation stage: nonce collision limit exceeded")
}

func installedGenerationRoot(targetRoot, generationID string) (string, error) {
	root, err := os.OpenRoot(targetRoot)
	if err != nil {
		return "", err
	}
	defer root.Close()
	prefix := ""
	for _, component := range []string{"_sow", "v1", "g", generationID} {
		prefix = filepath.Join(prefix, component)
		info, err := root.Lstat(prefix)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", errors.Join(err, fmt.Errorf("generation parent %s is not a real directory", prefix))
		}
	}
	return filepath.Join(targetRoot, "_sow", "v1", "g", generationID), nil
}

func validateGenerationManifest(generation Generation, manifestPath string) error {
	file, err := os.Open(manifestPath)
	if err != nil {
		return err
	}
	derived, deriveErr := DeriveGeneration(Identity{
		View: generation.View, Repo: generation.Repo, OS: generation.OS, Arch: generation.Arch,
		LegacyRoot: generation.LegacyRoot, RefCommit: generation.RefCommit,
		ConfigSHA256: generation.ConfigSHA256, RepositoryKeySHA256: generation.RepositoryKeySHA256,
	}, file)
	closeErr := file.Close()
	if deriveErr != nil || closeErr != nil {
		return errors.Join(deriveErr, closeErr)
	}
	want, err := generation.Canonical()
	if err != nil {
		return err
	}
	actual, err := derived.Canonical()
	if err != nil {
		return err
	}
	if string(want) != string(actual) {
		return errors.New("generation record does not match exact manifest and identity")
	}
	return nil
}

func ensureManifestCAS(ctx context.Context, pool *repository.Store, targetRoot, manifestPath string) error {
	file, err := os.Open(manifestPath)
	if err != nil {
		return err
	}
	defer file.Close()
	reader := manifest.NewReader(file)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		digest := repository.Digest(entry.SHA256)
		object := repository.Object{SHA256: digest, Size: entry.Size}
		existing, openErr := pool.Open(digest)
		if openErr == nil {
			info, statErr := existing.Stat()
			closeErr := existing.Close()
			if statErr != nil || closeErr != nil || info.Size() != entry.Size {
				return errors.Join(statErr, closeErr, fmt.Errorf("CAS coordinate %s has the wrong size", digest))
			}
			continue
		}
		if !errors.Is(openErr, os.ErrNotExist) {
			return openErr
		}
		source := filepath.Join(targetRoot, filepath.FromSlash(entry.Path))
		imported, err := pool.Import(ctx, source)
		if err != nil {
			return fmt.Errorf("import generation source %s: %w", entry.Path, err)
		}
		if imported != object {
			return fmt.Errorf("generation source %s changed after manifest scan", entry.Path)
		}
	}
}

func validateTargetRoot(repositoryRoot, targetRoot string) (string, error) {
	rootReal, err := filepath.EvalSymlinks(repositoryRoot)
	if err != nil {
		return "", err
	}
	targetAbs, err := filepath.Abs(targetRoot)
	if err != nil {
		return "", err
	}
	if err := validateDirectoryChainToRepositoryRoot(rootReal, targetAbs); err != nil {
		return "", err
	}
	targetReal, err := filepath.EvalSymlinks(targetAbs)
	if err != nil {
		return "", err
	}
	requestedInfo, err := os.Lstat(targetAbs)
	if err != nil || requestedInfo.Mode()&os.ModeSymlink != 0 || !requestedInfo.IsDir() {
		return "", errors.Join(err, errors.New("serving target root may not be a symlink"))
	}
	relative, err := filepath.Rel(rootReal, targetReal)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("serving target root escapes repository root")
	}
	info, err := os.Lstat(targetReal)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.Join(err, errors.New("serving target root is not a real directory"))
	}
	return targetReal, nil
}

func validateDirectoryChainToRepositoryRoot(repositoryRoot, target string) error {
	rootInfo, err := os.Stat(repositoryRoot)
	if err != nil {
		return err
	}
	current := filepath.Clean(target)
	for {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.Join(err, fmt.Errorf("serving target parent %s is not a real directory", current))
		}
		if os.SameFile(rootInfo, info) {
			return nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return errors.New("serving target root is not below the repository root")
		}
		current = parent
	}
}

func ensureRealDirectories(root, relative string) error {
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer rootHandle.Close()
	if err := rootHandle.MkdirAll(relative, 0o755); err != nil {
		return err
	}
	prefix := ""
	for _, component := range strings.Split(filepath.Clean(relative), string(filepath.Separator)) {
		prefix = filepath.Join(prefix, component)
		info, err := rootHandle.Lstat(prefix)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.Join(err, fmt.Errorf("serving directory %s is not a real directory", prefix))
		}
		if info.Mode().Perm() != 0o755 {
			if err := rootHandle.Chmod(prefix, 0o755); err != nil {
				return err
			}
		}
	}
	directory, err := rootHandle.Open(filepath.Clean(relative))
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func validateTreeAgainstManifest(ctx context.Context, root, manifestPath string, options InstallOptions) error {
	actual, err := os.CreateTemp(options.TempDir, "serving-generation-*.tsv")
	if err != nil {
		return err
	}
	actualPath := actual.Name()
	if err := actual.Close(); err != nil {
		return err
	}
	defer os.Remove(actualPath)
	if _, err := manifest.Scan(ctx, root, manifest.Scope{Path: "."}, actualPath, manifest.ScanOptions{
		Workers: options.Workers, ChunkEntries: options.ChunkEntries, TempDir: options.TempDir,
	}); err != nil {
		return err
	}
	wanted, err := os.Open(manifestPath)
	if err != nil {
		return err
	}
	observed, err := os.Open(actualPath)
	if err != nil {
		wanted.Close()
		return err
	}
	diff, diffErr := manifest.Diff(wanted, observed, nil)
	closeErr := errors.Join(wanted.Close(), observed.Close())
	if diffErr != nil || closeErr != nil {
		return errors.Join(diffErr, closeErr)
	}
	if !diff.Clean() {
		return fmt.Errorf("generation manifest drift: added=%d removed=%d changed=%d", diff.Added, diff.Removed, diff.Changed)
	}
	return nil
}

func manifestStats(manifestPath string) (manifest.ScanStats, error) {
	file, err := os.Open(manifestPath)
	if err != nil {
		return manifest.ScanStats{}, err
	}
	defer file.Close()
	var result manifest.ScanStats
	reader := manifest.NewReader(file)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return result, nil
		}
		if err != nil {
			return result, err
		}
		result.Files++
		result.Bytes += entry.Size
	}
}

func syncTree(root string) error {
	return filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("generation contains symlink %s", current)
		}
		if entry.IsDir() {
			return syncDirectory(current)
		}
		return nil
	})
}

// PublishHostableTree turns a private derived tree into the frozen
// directly-hostable representation. Directory and regular-file modes are set
// explicitly rather than left to the process umask. For generation payloads,
// the files are immutable CAS hardlinks, so chmod preserves the same 0444
// inode contract in both coordinates.
func PublishHostableTree(root string) error {
	return filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.Join(err, fmt.Errorf("hostable generation contains unsafe coordinate %s", current))
		}
		if info.IsDir() {
			if err := os.Chmod(current, 0o755); err != nil {
				return err
			}
			return syncDirectory(current)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("hostable serving coordinate %s is not a regular file", current)
		}
		if info.Mode().Perm() != 0o444 {
			if err := os.Chmod(current, 0o444); err != nil {
				return err
			}
			handle, err := os.Open(current)
			if err != nil {
				return err
			}
			if err := errors.Join(handle.Sync(), handle.Close()); err != nil {
				return err
			}
		}
		return nil
	})
}

func validateHostableTree(root string) error {
	return filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.Join(err, fmt.Errorf("served generation contains unsafe coordinate %s", current))
		}
		if info.IsDir() {
			if info.Mode().Perm() != 0o755 {
				return fmt.Errorf("served generation directory %s mode=%#o want=0755", current, info.Mode().Perm())
			}
			return nil
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o444 {
			return fmt.Errorf("served generation file %s is not world-readable", current)
		}
		return nil
	})
}

func syncDirectory(directory string) error {
	handle, err := os.Open(directory)
	if err != nil {
		return err
	}
	return errors.Join(handle.Sync(), handle.Close())
}
