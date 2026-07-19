package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
)

type manifestSelectionScopes struct {
	Replace []string
	Upsert  []string
}

// publicationSelectionScopes returns the filesystem ownership predicate for
// the selected projections. Most repositories own their complete source root.
// A partial APT projection is different: suite metadata is an exact replace
// scope, while the shared pool is an upsert-only namespace. Old pool bytes may
// still be referenced by an unselected suite or historical generation and are
// therefore never removed merely because a selector omitted them.
func publicationSelectionScopes(cfg *config.Config, prepared preparedPublication, roots map[string]struct{}) (manifestSelectionScopes, error) {
	var result manifestSelectionScopes
	for _, projection := range prepared.projections {
		if roots != nil {
			if _, selected := roots[projection.sourceRoot]; !selected {
				continue
			}
		}
		if prepared.restoreSourceGeneration != 0 {
			// Historical restore reconstructs the complete frozen intent into
			// an isolated exact tree. Its source root is therefore authoritative
			// as a whole even when snapshot suite names differ from source refs.
			result.Replace = append(result.Replace, projection.sourceRoot)
			continue
		}
		if projection.repo.Type != "apt" {
			result.Replace = append(result.Replace, projection.sourceRoot)
			continue
		}
		original, exists := cfg.RepoByName(projection.repo.ID)
		if !exists || original.Type != "apt" || original.APT == nil || projection.repo.APT == nil {
			return result, fmt.Errorf("APT publication projection %s is absent from canonical configuration", projection.repo.ID)
		}
		metadataSuites := uniqueSorted(projection.aptMetadataSuites)
		if len(metadataSuites) == 0 {
			return result, fmt.Errorf("APT publication projection %s has no metadata suite scope", projection.repo.ID)
		}
		ordinarySuites := uniqueSorted(projection.repo.APT.Suites)
		fullProjection := repoSelectionIsFull(original, projection.repo) && sameStringSet(metadataSuites, ordinarySuites)
		if fullProjection {
			result.Replace = append(result.Replace, projection.sourceRoot)
			continue
		}
		if projection.selectedPayloadManifest == "" {
			return result, fmt.Errorf("partial APT publication projection %s lacks an exact selected payload manifest", projection.repo.ID)
		}
		for _, suite := range metadataSuites {
			result.Replace = append(result.Replace, path.Join(projection.sourceRoot, "dists", suite))
		}
		result.Upsert = append(result.Upsert, path.Join(projection.sourceRoot, "pool"))
	}
	for _, identity := range prepared.compatibilityRollbacks {
		// The rollback projection above exact-replaces RouteRoot with verified S0
		// bytes. This second disjoint scope revokes the S3-only trust namespace.
		result.Replace = append(result.Replace, path.Dir(config.YUMCompatibilityPackageTrustRoute(identity.ID)))
	}
	var err error
	result.Replace, result.Upsert, err = normalizeManifestSelectionScopes(result.Replace, result.Upsert)
	return result, err
}

// ReplaceManifestScopes builds a complete target manifest by replacing every
// old entry below scopes with the selected manifest. Both inputs must be
// canonical, strictly sorted manifests. Every selected entry must be below
// exactly one of the normalized, non-overlapping directory scopes.
//
// The merge retains only one entry from each input in memory. The destination
// is created exclusively, synced before success, and removed on every error.
func ReplaceManifestScopes(oldPath, selectedPath, destinationPath string, scopes []string) error {
	return ReplaceManifestSelection(oldPath, selectedPath, destinationPath, manifestSelectionScopes{Replace: scopes})
}

// ReplaceManifestSelection builds a cumulative target manifest using two
// bounded ownership modes. Replace scopes are exact subtrees: all old entries
// are removed before selected entries are merged. Upsert scopes preserve old
// extras and replace only exact selected paths. This is the APT shared-pool
// primitive used by partial suite publication and remains O(1) memory.
func ReplaceManifestSelection(oldPath, selectedPath, destinationPath string, selection manifestSelectionScopes) error {
	replace, upsert, err := normalizeManifestSelectionScopes(selection.Replace, selection.Upsert)
	if err != nil {
		return err
	}
	oldFile, err := openRegularManifest(oldPath)
	if err != nil {
		return fmt.Errorf("open old target manifest: %w", err)
	}
	defer oldFile.Close()
	selectedFile, err := openRegularManifest(selectedPath)
	if err != nil {
		return fmt.Errorf("open selected manifest: %w", err)
	}
	defer selectedFile.Close()

	oldReader := manifest.NewReader(oldFile)
	selectedReader := manifest.NewReader(selectedFile)
	return writeExclusiveManifest(destinationPath, func(destination io.Writer) error {
		oldEntry, oldErr := nextManifestEntryOutsideScopes(oldReader, replace)
		selectedEntry, selectedErr := nextSelectedManifestEntryInSelection(selectedReader, replace, upsert)
		var lastPath string
		for !errors.Is(oldErr, io.EOF) || !errors.Is(selectedErr, io.EOF) {
			if oldErr != nil && !errors.Is(oldErr, io.EOF) {
				return fmt.Errorf("read old target manifest: %w", oldErr)
			}
			if selectedErr != nil && !errors.Is(selectedErr, io.EOF) {
				return fmt.Errorf("read selected manifest: %w", selectedErr)
			}

			var entry manifest.Entry
			switch {
			case errors.Is(oldErr, io.EOF):
				entry = selectedEntry
				selectedEntry, selectedErr = nextSelectedManifestEntryInSelection(selectedReader, replace, upsert)
			case errors.Is(selectedErr, io.EOF):
				entry = oldEntry
				oldEntry, oldErr = nextManifestEntryOutsideScopes(oldReader, replace)
			case oldEntry.Path < selectedEntry.Path:
				entry = oldEntry
				oldEntry, oldErr = nextManifestEntryOutsideScopes(oldReader, replace)
			case selectedEntry.Path < oldEntry.Path:
				entry = selectedEntry
				selectedEntry, selectedErr = nextSelectedManifestEntryInSelection(selectedReader, replace, upsert)
			default:
				// Exact upserts replace a prior target entry without claiming the
				// entire shared namespace. An equal path in a replace scope can
				// only occur for a malformed overlapping predicate, because old
				// replace entries were already skipped above.
				entry = selectedEntry
				oldEntry, oldErr = nextManifestEntryOutsideScopes(oldReader, replace)
				selectedEntry, selectedErr = nextSelectedManifestEntryInSelection(selectedReader, replace, upsert)
			}
			if lastPath != "" && entry.Path <= lastPath {
				return fmt.Errorf("output manifest is not strictly sorted: %q after %q", entry.Path, lastPath)
			}
			if err := manifest.WriteEntry(destination, entry); err != nil {
				return fmt.Errorf("write target manifest entry %q: %w", entry.Path, err)
			}
			lastPath = entry.Path
		}
		return nil
	})
}

// DropManifestScopes copies sourcePath to destinationPath while omitting every
// entry below scopes. It is used to force a selected YUM repodata scope to be
// represented as additions in the next streaming publish plan.
func DropManifestScopes(sourcePath, destinationPath string, scopes []string) error {
	normalized, err := normalizeManifestScopes(scopes)
	if err != nil {
		return err
	}
	source, err := openRegularManifest(sourcePath)
	if err != nil {
		return fmt.Errorf("open source manifest: %w", err)
	}
	defer source.Close()
	reader := manifest.NewReader(source)
	return writeExclusiveManifest(destinationPath, func(destination io.Writer) error {
		for {
			entry, err := nextManifestEntryOutsideScopes(reader, normalized)
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("read source manifest: %w", err)
			}
			if err := manifest.WriteEntry(destination, entry); err != nil {
				return fmt.Errorf("write filtered manifest entry %q: %w", entry.Path, err)
			}
		}
	})
}

// DropManifestSelection produces a publish-plan baseline. Replace scopes are
// removed wholesale; within upsert scopes only exact paths present in the
// selected manifest are removed. Entries outside the selection are retained,
// so forcing a newly introduced partial APT suite to be additions cannot turn
// sibling suites or historical pool bytes into retransfers.
func DropManifestSelection(sourcePath, selectedPath, destinationPath string, selection manifestSelectionScopes) error {
	replace, upsert, err := normalizeManifestSelectionScopes(selection.Replace, selection.Upsert)
	if err != nil {
		return err
	}
	source, err := openRegularManifest(sourcePath)
	if err != nil {
		return fmt.Errorf("open source manifest: %w", err)
	}
	defer source.Close()
	selected, err := openRegularManifest(selectedPath)
	if err != nil {
		return fmt.Errorf("open selected manifest: %w", err)
	}
	defer selected.Close()
	sourceReader := manifest.NewReader(source)
	selectedReader := manifest.NewReader(selected)
	return writeExclusiveManifest(destinationPath, func(destination io.Writer) error {
		selectedEntry, selectedErr := selectedReader.Next()
		for {
			entry, sourceErr := sourceReader.Next()
			if errors.Is(sourceErr, io.EOF) {
				for !errors.Is(selectedErr, io.EOF) {
					if selectedErr != nil {
						return fmt.Errorf("read selected manifest: %w", selectedErr)
					}
					selectedEntry, selectedErr = selectedReader.Next()
				}
				return nil
			}
			if sourceErr != nil {
				return fmt.Errorf("read source manifest: %w", sourceErr)
			}
			for selectedErr == nil && selectedEntry.Path < entry.Path {
				selectedEntry, selectedErr = selectedReader.Next()
			}
			if selectedErr != nil && !errors.Is(selectedErr, io.EOF) {
				return fmt.Errorf("read selected manifest: %w", selectedErr)
			}
			drop := manifestEntryInScopes(entry.Path, replace)
			if !drop && manifestEntryInScopes(entry.Path, upsert) && selectedErr == nil && selectedEntry.Path == entry.Path {
				drop = true
			}
			if drop {
				continue
			}
			if err := manifest.WriteEntry(destination, entry); err != nil {
				return fmt.Errorf("write filtered manifest entry %q: %w", entry.Path, err)
			}
		}
	})
}

// DiffChangedPaths returns only added and content-changed source paths. Removed
// paths are intentionally omitted because remote objects remain reachable for
// rollback. Memory use is proportional to the returned change set.
func DiffChangedPaths(oldPath, newPath string) ([]string, error) {
	oldFile, err := openRegularManifest(oldPath)
	if err != nil {
		return nil, fmt.Errorf("open old manifest: %w", err)
	}
	defer oldFile.Close()
	newFile, err := openRegularManifest(newPath)
	if err != nil {
		return nil, fmt.Errorf("open new manifest: %w", err)
	}
	defer newFile.Close()

	var paths []string
	_, err = manifest.Diff(oldFile, newFile, func(change manifest.Change) error {
		if change.Kind == manifest.Added || change.Kind == manifest.Changed {
			paths = append(paths, change.Path())
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("diff manifests: %w", err)
	}
	return paths, nil
}

func normalizeManifestScopes(scopes []string) ([]string, error) {
	normalized := make([]string, 0, len(scopes))
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if scope == "" || strings.Contains(scope, "\\") || strings.HasPrefix(scope, "/") || manifestScopeHasControl(scope) {
			return nil, fmt.Errorf("unsafe manifest scope %q", scope)
		}
		clean := path.Clean(scope)
		if clean != scope || clean == ".." || strings.HasPrefix(clean, "../") {
			return nil, fmt.Errorf("non-canonical manifest scope %q", scope)
		}
		if _, exists := seen[scope]; exists {
			return nil, fmt.Errorf("duplicate manifest scope %q", scope)
		}
		if scope == "." && len(scopes) != 1 {
			return nil, errors.New("root manifest scope overlaps every other scope")
		}
		for ancestor := path.Dir(scope); ancestor != "."; ancestor = path.Dir(ancestor) {
			if _, exists := seen[ancestor]; exists {
				return nil, fmt.Errorf("overlapping manifest scopes %q and %q", ancestor, scope)
			}
		}
		for existing := range seen {
			if strings.HasPrefix(existing, scope+"/") {
				return nil, fmt.Errorf("overlapping manifest scopes %q and %q", scope, existing)
			}
		}
		seen[scope] = struct{}{}
		normalized = append(normalized, scope)
	}
	sort.Strings(normalized)
	return normalized, nil
}

func normalizeManifestSelectionScopes(replace, upsert []string) ([]string, []string, error) {
	replace, err := normalizeManifestScopes(replace)
	if err != nil {
		return nil, nil, err
	}
	upsert, err = normalizeManifestScopes(upsert)
	if err != nil {
		return nil, nil, err
	}
	for _, left := range replace {
		for _, right := range upsert {
			if manifestEntryInScopes(left, []string{right}) || manifestEntryInScopes(right, []string{left}) {
				return nil, nil, fmt.Errorf("replace and upsert manifest scopes overlap %q and %q", left, right)
			}
		}
	}
	return replace, upsert, nil
}

func manifestScopeHasControl(scope string) bool {
	for _, character := range scope {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func manifestEntryInScopes(entryPath string, scopes []string) bool {
	for _, scope := range scopes {
		if scope == "." || entryPath == scope || strings.HasPrefix(entryPath, scope+"/") {
			return true
		}
	}
	return false
}

func nextManifestEntryOutsideScopes(reader *manifest.Reader, scopes []string) (manifest.Entry, error) {
	for {
		entry, err := reader.Next()
		if err != nil {
			return manifest.Entry{}, err
		}
		if !manifestEntryInScopes(entry.Path, scopes) {
			return entry, nil
		}
	}
}

func nextSelectedManifestEntry(reader *manifest.Reader, scopes []string) (manifest.Entry, error) {
	entry, err := reader.Next()
	if err != nil {
		return manifest.Entry{}, err
	}
	if !manifestEntryInScopes(entry.Path, scopes) {
		return manifest.Entry{}, fmt.Errorf("selected manifest entry %q is outside selected scopes", entry.Path)
	}
	return entry, nil
}

func nextSelectedManifestEntryInSelection(reader *manifest.Reader, replace, upsert []string) (manifest.Entry, error) {
	entry, err := reader.Next()
	if err != nil {
		return manifest.Entry{}, err
	}
	if !manifestEntryInScopes(entry.Path, replace) && !manifestEntryInScopes(entry.Path, upsert) {
		return manifest.Entry{}, fmt.Errorf("selected manifest entry %q is outside selected scopes", entry.Path)
	}
	return entry, nil
}

func openRegularManifest(filename string) (*os.File, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", filename)
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		file.Close()
		return nil, fmt.Errorf("%s changed while opening", filename)
	}
	return file, nil
}

func writeExclusiveManifest(filename string, write func(io.Writer) error) (resultErr error) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create output manifest: %w", err)
	}
	closed := false
	committed := false
	defer func() {
		if committed {
			return
		}
		var closeErr error
		if !closed {
			closeErr = file.Close()
		}
		cleanupErr := errors.Join(closeErr, os.Remove(filename))
		if cleanupErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("clean failed output manifest: %w", cleanupErr))
		}
	}()

	if err := write(file); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync output manifest: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close output manifest: %w", err)
	}
	closed = true
	directory, err := os.Open(filepath.Dir(filename))
	if err != nil {
		return fmt.Errorf("open output manifest directory: %w", err)
	}
	if err := errors.Join(directory.Sync(), directory.Close()); err != nil {
		return fmt.Errorf("sync output manifest directory: %w", err)
	}
	committed = true
	return nil
}
