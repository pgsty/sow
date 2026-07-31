package serving

import (
	"context"
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

type generationValidationHook func(phase, relative string) error
type generationValidationHookContextKey struct{}

const (
	generationValidationAfterManifestScan = "after-manifest-scan"
	generationValidationAfterCASVerified  = "after-cas-verified"
)

// withGenerationValidationHook is a deterministic test seam for the boundary
// between the full manifest scan and the retained hardlink/CAS verification.
// Production callers never install it.
func withGenerationValidationHook(ctx context.Context, hook generationValidationHook) context.Context {
	return context.WithValue(ctx, generationValidationHookContextKey{}, hook)
}

func runGenerationValidationHook(ctx context.Context, phase, relative string) error {
	hook, _ := ctx.Value(generationValidationHookContextKey{}).(generationValidationHook)
	if hook == nil {
		return nil
	}
	if err := hook(phase, relative); err != nil {
		return fmt.Errorf("installed generation validation hook %s: %w", phase, err)
	}
	return nil
}

// ValidateInstalledGenerationRoot validates an immutable generation through a
// retained serving-root capability. Public target-path replacement cannot
// redirect any tree or hardlink read to another repository.
func ValidateInstalledGenerationRoot(ctx context.Context, pool *repository.Store, targetRoot *os.Root, generation Generation, manifestPath string, options InstallOptions) error {
	if ctx == nil || pool == nil || targetRoot == nil {
		return errors.New("bound installed-generation validation dependencies are unavailable")
	}
	if err := generation.Validate(); err != nil {
		return err
	}
	if err := validateGenerationManifest(generation, manifestPath); err != nil {
		return err
	}
	relative := filepath.Join("_sow", "v1", "g", generation.ID)
	if err := validateHostableDirectoryParentsRoot(targetRoot, relative); err != nil {
		return err
	}
	generationRoot, identity, err := openServingDirectoryRoot(targetRoot, relative)
	if err != nil {
		return err
	}
	defer generationRoot.Close()
	if err := validateTreeAgainstManifestRoot(ctx, generationRoot, manifestPath, options); err != nil {
		return err
	}
	if err := runGenerationValidationHook(ctx, generationValidationAfterManifestScan, ""); err != nil {
		return err
	}
	if err := validateHostableTreeRoot(generationRoot); err != nil {
		return err
	}
	if err := validateTreeHardlinksRoot(ctx, pool, generationRoot, manifestPath); err != nil {
		return err
	}
	current, err := targetRoot.Lstat(relative)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() || current.Mode().Perm() != 0o755 || !os.SameFile(identity, current) {
		return errors.Join(err, errors.New("installed generation coordinate was replaced during validation"))
	}
	return validateHostableDirectoryParentsRoot(targetRoot, relative)
}

// ValidateInstalledGenerationCanonicalSubset validates every canonical
// generation entry and hardlink while allowing additional regular files to be
// present temporarily. This is only for an exact-reconcile preflight: callers
// must immediately reconcile against the same canonical manifest so all
// additional entries are removed. Missing or changed canonical bytes,
// symlinks, special files, unsafe parents, or non-hostable canonical entries
// still fail closed.
func ValidateInstalledGenerationCanonicalSubset(ctx context.Context, pool *repository.Store, targetRoot string, generation Generation, manifestPath string, options InstallOptions) (resultErr error) {
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
	return validateInstalledGenerationCanonicalSubsetRoot(ctx, pool, root, generation, manifestPath, options)
}

func validateInstalledGenerationCanonicalSubsetRoot(ctx context.Context, pool *repository.Store, targetRoot *os.Root, generation Generation, manifestPath string, options InstallOptions) error {
	if ctx == nil || pool == nil || targetRoot == nil {
		return errors.New("bound installed-generation subset validation dependencies are unavailable")
	}
	if err := generation.Validate(); err != nil {
		return err
	}
	if err := validateGenerationManifest(generation, manifestPath); err != nil {
		return err
	}
	relative := filepath.Join("_sow", "v1", "g", generation.ID)
	if err := validateHostableDirectoryParentsRoot(targetRoot, relative); err != nil {
		return err
	}
	generationRoot, identity, err := openServingDirectoryRoot(targetRoot, relative)
	if err != nil {
		return err
	}
	defer generationRoot.Close()
	if err := validateTreeContainsManifestRoot(ctx, generationRoot, manifestPath, options); err != nil {
		return err
	}
	if err := runGenerationValidationHook(ctx, generationValidationAfterManifestScan, ""); err != nil {
		return err
	}
	if err := validateManifestHostableFilesRoot(generationRoot, manifestPath); err != nil {
		return err
	}
	if err := validateTreeHardlinksRoot(ctx, pool, generationRoot, manifestPath); err != nil {
		return err
	}
	current, err := targetRoot.Lstat(relative)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() || current.Mode().Perm() != 0o755 || !os.SameFile(identity, current) {
		return errors.Join(err, errors.New("installed generation coordinate was replaced during subset validation"))
	}
	return validateHostableDirectoryParentsRoot(targetRoot, relative)
}

func openServingDirectoryRoot(root *os.Root, relative string) (*os.Root, os.FileInfo, error) {
	if root == nil || relative == "" || relative == "." || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, nil, errors.New("unsafe bound serving directory")
	}
	before, err := root.Lstat(relative)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, nil, errors.Join(err, fmt.Errorf("bound serving directory %s is absent, symlinked, or not a directory", relative))
	}
	opened, err := root.OpenRoot(relative)
	if err != nil {
		return nil, nil, err
	}
	bound, statErr := opened.Stat(".")
	after, lstatErr := root.Lstat(relative)
	if statErr != nil || lstatErr != nil || !os.SameFile(before, bound) || !os.SameFile(before, after) {
		return nil, nil, errors.Join(statErr, lstatErr, opened.Close(), fmt.Errorf("bound serving directory %s changed while opening", relative))
	}
	return opened, bound, nil
}

func validateTreeContainsManifestRoot(ctx context.Context, root *os.Root, manifestPath string, options InstallOptions) error {
	if options.Workers < 1 || options.ChunkEntries < 1 || options.TempDir == "" {
		return errors.New("bound generation subset validation requires positive workers/chunk entries and a temp directory")
	}
	actual, err := os.CreateTemp(options.TempDir, "serving-generation-subset-*.tsv")
	if err != nil {
		return err
	}
	actualPath := actual.Name()
	if err := actual.Close(); err != nil {
		return err
	}
	defer os.Remove(actualPath)
	if _, err := manifest.ScanRoot(ctx, root, manifest.Scope{Path: "."}, actualPath, manifest.ScanOptions{
		Workers: options.Workers, ChunkEntries: options.ChunkEntries, TempDir: options.TempDir,
		ShadowPolicy: manifest.ShadowIncludeAll,
	}); err != nil {
		return err
	}
	wanted, err := os.Open(manifestPath)
	if err != nil {
		return err
	}
	observed, err := os.Open(actualPath)
	if err != nil {
		_ = wanted.Close()
		return err
	}
	diff, diffErr := manifest.Diff(wanted, observed, nil)
	closeErr := errors.Join(wanted.Close(), observed.Close())
	if diffErr != nil || closeErr != nil {
		return errors.Join(diffErr, closeErr)
	}
	if diff.Removed != 0 || diff.Changed != 0 {
		return fmt.Errorf("generation canonical subset drift: added=%d removed=%d changed=%d", diff.Added, diff.Removed, diff.Changed)
	}
	return nil
}

func validateManifestHostableFilesRoot(root *os.Root, manifestPath string) error {
	file, err := os.Open(manifestPath)
	if err != nil {
		return err
	}
	defer file.Close()
	reader := manifest.NewReader(file)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := ValidateHostableFileRoot(root, filepath.FromSlash(entry.Path)); err != nil {
			return fmt.Errorf("canonical generation path %s is not directly hostable: %w", entry.Path, err)
		}
	}
}

func validateTreeAgainstManifestRoot(ctx context.Context, root *os.Root, manifestPath string, options InstallOptions) error {
	if options.Workers < 1 || options.ChunkEntries < 1 || options.TempDir == "" {
		return errors.New("bound generation validation requires positive workers/chunk entries and a temp directory")
	}
	actual, err := os.CreateTemp(options.TempDir, "serving-generation-bound-*.tsv")
	if err != nil {
		return err
	}
	actualPath := actual.Name()
	if err := actual.Close(); err != nil {
		return err
	}
	defer os.Remove(actualPath)
	if _, err := manifest.ScanRoot(ctx, root, manifest.Scope{Path: "."}, actualPath, manifest.ScanOptions{
		Workers: options.Workers, ChunkEntries: options.ChunkEntries, TempDir: options.TempDir,
		ShadowPolicy: manifest.ShadowIncludeAll,
	}); err != nil {
		return err
	}
	wanted, err := os.Open(manifestPath)
	if err != nil {
		return err
	}
	observed, err := os.Open(actualPath)
	if err != nil {
		_ = wanted.Close()
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

func validateHostableTreeRoot(root *os.Root) error {
	return fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := root.Lstat(name)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.Join(err, fmt.Errorf("served generation contains unsafe coordinate %s", name))
		}
		if info.IsDir() {
			if info.Mode().Perm() != 0o755 {
				return fmt.Errorf("served generation directory %s mode=%#o want=0755", name, info.Mode().Perm())
			}
			return nil
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o444 {
			return fmt.Errorf("served generation file %s mode=%#o want=0444", name, info.Mode().Perm())
		}
		return nil
	})
}

func validateTreeHardlinksRoot(ctx context.Context, pool *repository.Store, root *os.Root, manifestPath string) error {
	file, err := os.Open(manifestPath)
	if err != nil {
		return err
	}
	defer file.Close()
	reader := manifest.NewReader(file)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := filepath.FromSlash(entry.Path)
		before, err := root.Lstat(name)
		if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
			return errors.Join(err, fmt.Errorf("generation path %s is not a regular CAS hardlink", entry.Path))
		}
		target, err := root.Open(name)
		if err != nil {
			return err
		}
		targetInfo, targetStatErr := target.Stat()
		afterOpen, lstatErr := root.Lstat(name)
		if targetStatErr != nil || lstatErr != nil || !os.SameFile(before, targetInfo) || !os.SameFile(before, afterOpen) {
			return errors.Join(targetStatErr, lstatErr, target.Close(), fmt.Errorf("generation path %s changed while opening", entry.Path))
		}
		objectIdentity := repository.Object{SHA256: repository.Digest(entry.SHA256), Size: entry.Size}
		object, err := pool.OpenVerified(ctx, objectIdentity)
		if err != nil {
			_ = target.Close()
			return fmt.Errorf("open generation CAS object for %s: %w", entry.Path, err)
		}
		if err := runGenerationValidationHook(ctx, generationValidationAfterCASVerified, entry.Path); err != nil {
			return errors.Join(err, target.Close(), object.Close())
		}
		objectInfo, objectStatErr := object.Stat()
		lastTarget, lastTargetErr := target.Stat()
		lastCoordinate, coordinateErr := root.Lstat(name)
		reverifyErr := repository.VerifyOpenedObject(ctx, object, objectIdentity)
		closeErr := errors.Join(target.Close(), object.Close())
		if objectStatErr != nil || lastTargetErr != nil || coordinateErr != nil || reverifyErr != nil || closeErr != nil ||
			targetInfo.Size() != entry.Size || objectInfo.Size() != entry.Size || !os.SameFile(targetInfo, objectInfo) ||
			!os.SameFile(targetInfo, lastTarget) || !os.SameFile(targetInfo, lastCoordinate) {
			return errors.Join(objectStatErr, lastTargetErr, coordinateErr, reverifyErr, closeErr, fmt.Errorf("generation path %s is not the canonical CAS hardlink with stable verified bytes", entry.Path))
		}
	}
}
