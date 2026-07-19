package serving

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
)

type RemoveGenerationOptions struct {
	InstallOptions
	// ExpectedManifestPath is the canonical retired deletion witness. When
	// present, an interrupted removal may resume from any strict subset of the
	// original generation, while changed or additional entries still fail.
	ExpectedManifestPath  string
	BeforeRemove          func() error
	AfterOpenBeforeRemove func() error
}

// ListInstalledGenerationIDs audits the reserved generation directory and
// returns only exact immutable-generation coordinates. Temporary, malformed,
// symlinked, or special entries fail closed.
func ListInstalledGenerationIDs(repositoryRoot, targetRoot string) ([]string, error) {
	confinedRoot, err := validateTargetRoot(repositoryRoot, targetRoot)
	if err != nil {
		return nil, err
	}
	base, exists, err := existingRealDirectory(confinedRoot, filepath.Join("_sow", "v1", "g"))
	if err != nil || !exists {
		return nil, err
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !generationIDPattern.MatchString(entry.Name()) {
			return nil, fmt.Errorf("unsafe installed generation entry %q", entry.Name())
		}
		info, err := os.Lstat(filepath.Join(base, entry.Name()))
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.Join(err, fmt.Errorf("installed generation %q is not a real directory", entry.Name()))
		}
		result = append(result, entry.Name())
	}
	sort.Strings(result)
	return result, nil
}

// ListInstalledGenerationIDsIfPresent distinguishes a deliberately removed
// derived export from an unsafe target coordinate. Every existing path
// component is opened below the real repository root and must be a real
// directory; a first missing component reports exists=false, while symlinks,
// special files, and escapes fail closed.
func ListInstalledGenerationIDsIfPresent(repositoryRoot, targetRoot string) ([]string, bool, error) {
	repositoryAbs, err := filepath.Abs(repositoryRoot)
	if err != nil {
		return nil, false, err
	}
	repositoryReal, err := filepath.EvalSymlinks(repositoryRoot)
	if err != nil {
		return nil, false, err
	}
	targetAbs, err := filepath.Abs(targetRoot)
	if err != nil {
		return nil, false, err
	}
	// Compute the coordinate from the caller's lexical namespace before
	// opening it below the real root. On macOS /var aliases /private/var; mixing
	// only one realpath with one lexical path would falsely report an escape.
	relative, err := filepath.Rel(repositoryAbs, targetAbs)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, false, errors.Join(err, errors.New("serving target root escapes repository root"))
	}
	root, err := os.OpenRoot(repositoryReal)
	if err != nil {
		return nil, false, err
	}
	defer root.Close()
	if relative != "." {
		prefix := ""
		for _, component := range strings.Split(relative, string(filepath.Separator)) {
			parent := prefix
			prefix = filepath.Join(prefix, component)
			info, inspectErr := root.Lstat(prefix)
			if errors.Is(inspectErr, os.ErrNotExist) {
				return nil, false, syncOpenRootDirectory(root, parent)
			}
			if inspectErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return nil, false, errors.Join(inspectErr, fmt.Errorf("serving target parent %s is not a real directory", prefix))
			}
		}
	}
	ids, err := ListInstalledGenerationIDs(repositoryReal, filepath.Join(repositoryReal, relative))
	if err != nil {
		return nil, true, err
	}
	if err := syncDeepestGenerationParent(root, relative); err != nil {
		return nil, true, err
	}
	return ids, true, nil
}

func syncDeepestGenerationParent(root *os.Root, targetRelative string) error {
	for _, suffix := range []string{filepath.Join("_sow", "v1", "g"), filepath.Join("_sow", "v1"), "_sow", "."} {
		candidate := targetRelative
		if suffix != "." {
			candidate = filepath.Join(targetRelative, suffix)
		}
		info, err := root.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.Join(err, fmt.Errorf("serving generation parent %s is not a real directory", candidate))
		}
		return syncOpenRootDirectory(root, candidate)
	}
	return errors.New("serving target disappeared during durability barrier")
}

func syncOpenRootDirectory(root *os.Root, relative string) error {
	if relative == "" {
		relative = "."
	}
	handle, err := root.Open(relative)
	if err != nil {
		return err
	}
	return errors.Join(handle.Sync(), handle.Close())
}

// RemoveRetiredGeneration validates the exact tree against its retired
// generation identity immediately before deleting the derived hardlink tree.
// A failure before deletion leaves the directory intact and is safely
// retryable with a fresh explicit GC confirmation.
func RemoveRetiredGeneration(ctx context.Context, pool *repository.Store, targetRoot string, generation Generation, options RemoveGenerationOptions) error {
	validate := func() error {
		if options.ExpectedManifestPath == "" {
			return ValidateRetiredGeneration(ctx, pool, targetRoot, generation, options.InstallOptions)
		}
		return ValidateRetiredGenerationRemainder(ctx, pool, targetRoot, generation, options.ExpectedManifestPath, options.InstallOptions)
	}
	if err := validate(); err != nil {
		return err
	}
	confinedRoot, err := validateTargetRoot(pool.Root(), targetRoot)
	if err != nil {
		return err
	}
	if options.BeforeRemove != nil {
		if err := options.BeforeRemove(); err != nil {
			return err
		}
	}
	parentRoot, err := os.OpenRoot(confinedRoot)
	if err != nil {
		return err
	}
	defer parentRoot.Close()
	relative := filepath.Join("_sow", "v1", "g", generation.ID)
	prefix := ""
	for _, component := range []string{"_sow", "v1", "g", generation.ID} {
		prefix = filepath.Join(prefix, component)
		info, inspectErr := parentRoot.Lstat(prefix)
		if errors.Is(inspectErr, os.ErrNotExist) {
			return nil
		}
		if inspectErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.Join(inspectErr, fmt.Errorf("generation deletion parent %s is not a real directory", prefix))
		}
	}
	final := filepath.Join(confinedRoot, relative)
	validatedInfo, err := os.Lstat(final)
	if err != nil {
		return err
	}
	candidateRoot, err := os.OpenRoot(final)
	if err != nil {
		return err
	}
	openedInfo, err := candidateRoot.Lstat(".")
	if err != nil || !os.SameFile(validatedInfo, openedInfo) {
		return errors.Join(err, candidateRoot.Close(), errors.New("retired generation changed while binding deletion root"))
	}
	// Re-scan only after opening the candidate directory. The post-scan inode
	// comparison binds the witness validation to the exact root whose children
	// will be removed, so a same-name directory swap cannot redirect deletion.
	if err := validate(); err != nil {
		return errors.Join(err, candidateRoot.Close())
	}
	boundInfo, err := parentRoot.Lstat(relative)
	if err != nil || !os.SameFile(openedInfo, boundInfo) {
		return errors.Join(err, candidateRoot.Close(), errors.New("retired generation changed while validating bound deletion root"))
	}
	if options.AfterOpenBeforeRemove != nil {
		if err := options.AfterOpenBeforeRemove(); err != nil {
			return errors.Join(err, candidateRoot.Close())
		}
	}
	directory, err := candidateRoot.Open(".")
	if err != nil {
		return errors.Join(err, candidateRoot.Close())
	}
	entries, readErr := directory.Readdirnames(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr, candidateRoot.Close())
	}
	sort.Strings(entries)
	for _, entry := range entries {
		if entry == "." || entry == ".." || strings.ContainsAny(entry, "/\\\x00") {
			return errors.Join(candidateRoot.Close(), fmt.Errorf("unsafe generation deletion entry %q", entry))
		}
		if err := candidateRoot.RemoveAll(entry); err != nil {
			return errors.Join(err, candidateRoot.Close())
		}
	}
	if err := candidateRoot.Close(); err != nil {
		return err
	}
	currentInfo, err := parentRoot.Lstat(relative)
	if err != nil || !os.SameFile(validatedInfo, currentInfo) {
		return errors.Join(err, errors.New("retired generation coordinate changed during deletion; refusing replacement"))
	}
	if err := parentRoot.Remove(relative); err != nil {
		return err
	}
	if _, err := parentRoot.Lstat(relative); !errors.Is(err, os.ErrNotExist) {
		return errors.Join(err, errors.New("retired generation directory remains after removal"))
	}
	base := filepath.Join(confinedRoot, "_sow", "v1", "g")
	if err := syncDirectory(base); err != nil {
		return err
	}
	return nil
}

// ValidateRetiredGenerationRemainder proves that an interrupted RemoveAll
// left only canonical members of the retired generation. Missing entries are
// legal; every remaining path, size, digest, type, and hostable mode must
// still match the deletion witness, and extra entries fail closed.
func ValidateRetiredGenerationRemainder(ctx context.Context, pool *repository.Store, targetRoot string, generation Generation, expectedManifestPath string, options InstallOptions) error {
	if pool == nil {
		return errors.New("nil CAS store")
	}
	if err := generation.Validate(); err != nil {
		return err
	}
	if options.Workers < 1 || options.ChunkEntries < 1 || options.TempDir == "" {
		return errors.New("retired generation removal requires positive workers/chunk entries and a temp directory")
	}
	if err := validateGenerationManifest(generation, expectedManifestPath); err != nil {
		return fmt.Errorf("retired generation deletion witness differs from identity: %w", err)
	}
	confinedRoot, err := validateTargetRoot(pool.Root(), targetRoot)
	if err != nil {
		return err
	}
	root, err := installedGenerationRoot(confinedRoot, generation.ID)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	actual, err := os.CreateTemp(options.TempDir, "retired-generation-remainder-*.tsv")
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
	if err := validateManifestSubset(expectedManifestPath, actualPath); err != nil {
		return fmt.Errorf("retired generation remainder differs from deletion witness: %w", err)
	}
	return validateHostableTree(root)
}

func validateManifestSubset(expectedPath, observedPath string) error {
	expectedFile, err := os.Open(expectedPath)
	if err != nil {
		return err
	}
	defer expectedFile.Close()
	observedFile, err := os.Open(observedPath)
	if err != nil {
		return err
	}
	defer observedFile.Close()
	expected := manifest.NewReader(expectedFile)
	observed := manifest.NewReader(observedFile)
	wanted, wantedErr := expected.Next()
	for {
		actual, actualErr := observed.Next()
		if errors.Is(actualErr, io.EOF) {
			return nil
		}
		if actualErr != nil {
			return actualErr
		}
		for wantedErr == nil && wanted.Path < actual.Path {
			wanted, wantedErr = expected.Next()
		}
		if errors.Is(wantedErr, io.EOF) || (wantedErr == nil && actual.Path < wanted.Path) {
			return fmt.Errorf("extra path %s", actual.Path)
		}
		if wantedErr != nil {
			return wantedErr
		}
		if actual != wanted {
			return fmt.Errorf("changed path %s", actual.Path)
		}
		wanted, wantedErr = expected.Next()
	}
}

func ValidateRetiredGeneration(ctx context.Context, pool *repository.Store, targetRoot string, generation Generation, options InstallOptions) error {
	if pool == nil {
		return errors.New("nil CAS store")
	}
	if err := generation.Validate(); err != nil {
		return err
	}
	if options.Workers < 1 || options.ChunkEntries < 1 || options.TempDir == "" {
		return errors.New("retired generation removal requires positive workers/chunk entries and a temp directory")
	}
	manifestFile, err := os.CreateTemp(options.TempDir, "retired-generation-*.tsv")
	if err != nil {
		return err
	}
	manifestPath := manifestFile.Name()
	if err := manifestFile.Close(); err != nil {
		return err
	}
	defer os.Remove(manifestPath)
	if err := ScanInstalledGeneration(ctx, pool, targetRoot, generation, manifestPath, options); err != nil {
		return err
	}
	if err := validateGenerationManifest(generation, manifestPath); err != nil {
		return fmt.Errorf("retired generation directory differs from canonical identity: %w", err)
	}
	return nil
}
