package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/state"
)

// scanRepoManifest expands the frozen YUM {arch} path contract while keeping
// one canonical repo manifest. Each scan is already sorted; bounded pairwise
// merges preserve global path order without loading the repository in memory.
func scanRepoManifest(ctx context.Context, cfg *config.Config, repo config.Repo, destination string, options manifest.ScanOptions) (manifest.ScanStats, error) {
	original, exists := cfg.RepoByName(repo.ID)
	if !exists {
		return manifest.ScanStats{}, fmt.Errorf("repository %s is not present in canonical configuration", repo.ID)
	}
	// APT suites and architectures share one filesystem root. Scan using the
	// configured include/exclude contract, then stream-filter the sorted result
	// to the selected logical scope. YUM {arch} roots can be narrowed before the
	// scan and therefore avoid hashing unselected leaves entirely.
	if repo.Type == "apt" && !repoSelectionIsFull(original, repo) {
		tempRoot := filepath.Join(cfg.StatePath(), "tmp")
		if err := os.MkdirAll(tempRoot, 0o700); err != nil {
			return manifest.ScanStats{}, err
		}
		full, err := os.CreateTemp(tempRoot, "scan-apt-full-*.tsv")
		if err != nil {
			return manifest.ScanStats{}, err
		}
		fullPath := full.Name()
		if err := full.Close(); err != nil {
			return manifest.ScanStats{}, err
		}
		defer os.Remove(fullPath)
		if _, err := manifest.Scan(ctx, cfg.Root, manifest.Scope{Path: original.Path, Include: original.Include, Exclude: original.Exclude}, fullPath, options); err != nil {
			return manifest.ScanStats{}, err
		}
		return filterManifestFile(fullPath, destination, func(entry manifest.Entry) bool {
			return repoSelectionContains(original, repo, entry.Path)
		})
	}
	paths, err := repo.ExpandedPaths()
	if err != nil {
		return manifest.ScanStats{}, err
	}
	if len(paths) == 1 {
		stats, err := manifest.Scan(ctx, cfg.Root, manifest.Scope{Path: paths[0], Include: repo.Include, Exclude: repo.Exclude}, destination, options)
		if err != nil {
			return stats, err
		}
		if err := validateAssetProjectionManifest(repo, destination); err != nil {
			_ = os.Remove(destination)
			return stats, err
		}
		return stats, nil
	}
	tempRoot := filepath.Join(cfg.StatePath(), "tmp")
	if err := os.MkdirAll(tempRoot, 0o700); err != nil {
		return manifest.ScanStats{}, err
	}
	workDir, err := os.MkdirTemp(tempRoot, "scan-repo-")
	if err != nil {
		return manifest.ScanStats{}, err
	}
	defer os.RemoveAll(workDir)
	var total manifest.ScanStats
	var aggregate string
	for index, repoPath := range paths {
		part := filepath.Join(workDir, fmt.Sprintf("part-%06d.tsv", index))
		stats, err := manifest.Scan(ctx, cfg.Root, manifest.Scope{Path: repoPath, Include: repo.Include, Exclude: repo.Exclude}, part, options)
		if err != nil {
			return total, err
		}
		total.Files += stats.Files
		total.Bytes += stats.Bytes
		if aggregate == "" {
			aggregate = part
			continue
		}
		merged := filepath.Join(workDir, fmt.Sprintf("merged-%06d.tsv", index))
		if err := mergeManifestFiles(aggregate, part, merged); err != nil {
			return total, err
		}
		aggregate = merged
	}
	if aggregate == "" {
		return total, errors.New("repository path expansion produced no paths")
	}
	source, err := os.Open(aggregate)
	if err != nil {
		return total, err
	}
	copyErr := manifest.AtomicCopy(destination, source, 0o600)
	closeErr := source.Close()
	if copyErr != nil || closeErr != nil {
		return total, errors.Join(copyErr, closeErr)
	}
	if err := validateAssetProjectionManifest(repo, destination); err != nil {
		_ = os.Remove(destination)
		return total, err
	}
	return total, nil
}

// scanRepoManifestRoot performs the YUM/asset subset of scanRepoManifest
// through a retained repository capability. Compatibility admission uses this
// path so a public repository-root rename cannot redirect its baseline scan.
// All merge scratch remains in the caller-provided external TempDir.
func scanRepoManifestRoot(ctx context.Context, root *os.Root, cfg *config.Config, repo config.Repo, destination string, options manifest.ScanOptions) (manifest.ScanStats, error) {
	if root == nil || cfg == nil {
		return manifest.ScanStats{}, errors.New("bound repository scan dependencies are unavailable")
	}
	original, exists := cfg.RepoByName(repo.ID)
	if !exists {
		return manifest.ScanStats{}, fmt.Errorf("repository %s is not present in canonical configuration", repo.ID)
	}
	if repo.Type == "apt" && !repoSelectionIsFull(original, repo) {
		return manifest.ScanStats{}, errors.New("bound partial APT scan is unavailable")
	}
	paths, err := repo.ExpandedPaths()
	if err != nil {
		return manifest.ScanStats{}, err
	}
	if len(paths) == 1 {
		stats, err := manifest.ScanRoot(ctx, root, manifest.Scope{Path: paths[0], Include: repo.Include, Exclude: repo.Exclude}, destination, options)
		if err != nil {
			return stats, err
		}
		if err := validateAssetProjectionManifest(repo, destination); err != nil {
			_ = os.Remove(destination)
			return stats, err
		}
		return stats, nil
	}
	if options.TempDir == "" {
		return manifest.ScanStats{}, errors.New("bound repository scan requires an external temporary directory")
	}
	workDir, err := os.MkdirTemp(options.TempDir, "scan-bound-repo-")
	if err != nil {
		return manifest.ScanStats{}, err
	}
	defer os.RemoveAll(workDir)
	var total manifest.ScanStats
	var aggregate string
	for index, repoPath := range paths {
		part := filepath.Join(workDir, fmt.Sprintf("part-%06d.tsv", index))
		stats, scanErr := manifest.ScanRoot(ctx, root, manifest.Scope{Path: repoPath, Include: repo.Include, Exclude: repo.Exclude}, part, options)
		if scanErr != nil {
			return total, scanErr
		}
		total.Files += stats.Files
		total.Bytes += stats.Bytes
		if aggregate == "" {
			aggregate = part
			continue
		}
		merged := filepath.Join(workDir, fmt.Sprintf("merged-%06d.tsv", index))
		if err := mergeManifestFiles(aggregate, part, merged); err != nil {
			return total, err
		}
		aggregate = merged
	}
	if aggregate == "" {
		return total, errors.New("repository path expansion produced no paths")
	}
	source, err := os.Open(aggregate)
	if err != nil {
		return total, err
	}
	copyErr := manifest.AtomicCopy(destination, source, 0o600)
	closeErr := source.Close()
	if copyErr != nil || closeErr != nil {
		return total, errors.Join(copyErr, closeErr)
	}
	if err := validateAssetProjectionManifest(repo, destination); err != nil {
		_ = os.Remove(destination)
		return total, err
	}
	return total, nil
}

func repoSelectionIsFull(original, selected config.Repo) bool {
	if original.ID != selected.ID || original.Type != selected.Type {
		return false
	}
	if !sameStringSet(original.Arches, selected.Arches) {
		return false
	}
	if original.Type == "apt" {
		if original.APT == nil || selected.APT == nil {
			return original.APT == selected.APT
		}
		return sameStringSet(original.APT.Suites, selected.APT.Suites)
	}
	return true
}

func sameStringSet(left, right []string) bool {
	left = uniqueSorted(left)
	right = uniqueSorted(right)
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// repoSelectionContains defines the paths owned by a selected manifest scope.
// APT pool bytes and suite point metadata are shared by leaf indices and must
// remain in every selected suite scope; pretending those paths belong to one
// architecture would allow an inconsistent Release/pool pair to pass fsck.
func repoSelectionContains(original, selected config.Repo, manifestPath string) bool {
	if repoSelectionIsFull(original, selected) {
		return true
	}
	switch original.Type {
	case "yum":
		for _, arch := range selected.Arches {
			prefix, err := original.PathForArch(arch)
			if err == nil && pathWithin(manifestPath, prefix) {
				return true
			}
		}
		return false
	case "apt":
		if original.APT == nil || selected.APT == nil || !pathWithin(manifestPath, original.Path) {
			return false
		}
		rel := strings.TrimPrefix(manifestPath, strings.TrimSuffix(original.Path, "/")+"/")
		if !strings.HasPrefix(rel, "dists/") {
			return true // pool and other repository-global files are shared
		}
		parts := strings.Split(rel, "/")
		if len(parts) < 3 || !contains(selected.APT.Suites, parts[1]) {
			return false
		}
		if sameStringSet(original.Arches, selected.Arches) {
			return true
		}
		tail := strings.Join(parts[2:], "/")
		if tail == "InRelease" || tail == "Release" || tail == "Release.gpg" {
			return true
		}
		for _, arch := range selected.Arches {
			for _, marker := range []string{"binary-" + arch, "installer-" + arch, "Contents-" + arch, "Commands-" + arch, "Components-" + arch} {
				if strings.Contains(tail, marker) {
					return true
				}
			}
		}
		return false
	case "asset":
		return pathWithin(manifestPath, original.Path)
	default:
		return false
	}
}

func pathWithin(candidate, prefix string) bool {
	prefix = strings.TrimSuffix(filepath.ToSlash(filepath.Clean(prefix)), "/")
	candidate = filepath.ToSlash(candidate)
	return candidate == prefix || strings.HasPrefix(candidate, prefix+"/")
}

func filterManifestFile(sourcePath, destination string, keep func(manifest.Entry) bool) (manifest.ScanStats, error) {
	source, err := os.Open(sourcePath)
	if err != nil {
		return manifest.ScanStats{}, err
	}
	defer source.Close()
	return filterManifestReader(source, destination, keep)
}

// filterManifestReader keeps canonical snapshot readers descriptor-bound.
// A read-only canonical Store deliberately exposes OpenPath/OpenManifest as an
// already-unlinked temporary file so no mutable pathname can be reopened
// behind the admission snapshot. Callers therefore must consume the retained
// descriptor instead of passing File.Name back through os.Open.
func filterManifestReader(source io.Reader, destination string, keep func(manifest.Entry) bool) (manifest.ScanStats, error) {
	if source == nil {
		return manifest.ScanStats{}, errors.New("nil manifest filter source")
	}
	temp, err := os.CreateTemp(filepath.Dir(destination), ".manifest-filter-*.tmp")
	if err != nil {
		return manifest.ScanStats{}, err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	writer := bufio.NewWriterSize(temp, 256*1024)
	reader := manifest.NewReader(source)
	var stats manifest.ScanStats
	for {
		entry, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			_ = temp.Close()
			return stats, nextErr
		}
		if !keep(entry) {
			continue
		}
		if err := manifest.WriteEntry(writer, entry); err != nil {
			_ = temp.Close()
			return stats, err
		}
		stats.Files++
		stats.Bytes += entry.Size
	}
	if err := errors.Join(writer.Flush(), temp.Sync(), temp.Close()); err != nil {
		return stats, err
	}
	tempSource, err := os.Open(tempPath)
	if err != nil {
		return stats, err
	}
	copyErr := manifest.AtomicCopy(destination, tempSource, 0o600)
	return stats, errors.Join(copyErr, tempSource.Close())
}

// mergeRepoManifestSelection replaces only the selected scope in an existing
// canonical repo manifest. Both inputs remain sorted and the merge is bounded.
func mergeRepoManifestSelection(cfg *config.Config, repo config.Repo, existingPath, selectedPath, destination, tempDir string) error {
	original, exists := cfg.RepoByName(repo.ID)
	if !exists {
		return fmt.Errorf("repository %s is not present in canonical configuration", repo.ID)
	}
	if repoSelectionIsFull(original, repo) {
		source, err := os.Open(selectedPath)
		if err != nil {
			return err
		}
		return errors.Join(manifest.AtomicCopy(destination, source, 0o600), source.Close())
	}
	if err := os.MkdirAll(tempDir, 0o700); err != nil {
		return err
	}
	preserved, err := os.CreateTemp(tempDir, "manifest-preserved-*.tsv")
	if err != nil {
		return err
	}
	preservedPath := preserved.Name()
	if err := preserved.Close(); err != nil {
		return err
	}
	defer os.Remove(preservedPath)
	if _, err := filterManifestFile(existingPath, preservedPath, func(entry manifest.Entry) bool {
		return !repoSelectionContains(original, repo, entry.Path)
	}); err != nil {
		return err
	}
	return mergeManifestFiles(preservedPath, selectedPath, destination)
}

func filteredRepoBaseline(cfg *config.Config, repo config.Repo, baseline io.Reader, destination string) error {
	original, exists := cfg.RepoByName(repo.ID)
	if !exists {
		return fmt.Errorf("repository %s is not present in canonical configuration", repo.ID)
	}
	if baseline == nil {
		return errors.New("repository baseline reader is unavailable")
	}
	if repoSelectionIsFull(original, repo) {
		return manifest.AtomicCopy(destination, baseline, 0o600)
	}
	_, err := filterManifestReader(baseline, destination, func(entry manifest.Entry) bool {
		return repoSelectionContains(original, repo, entry.Path)
	})
	return err
}

func stageRepoManifestUpdate(cfg *config.Config, store *state.Store, repo config.Repo, selectedPath, destination, tempDir string) error {
	original, exists := cfg.RepoByName(repo.ID)
	if !exists {
		return fmt.Errorf("repository %s is not present in canonical configuration", repo.ID)
	}
	if repoSelectionIsFull(original, repo) {
		source, err := os.Open(selectedPath)
		if err != nil {
			return err
		}
		return errors.Join(manifest.AtomicCopy(destination, source, 0o600), source.Close())
	}
	existingPath := store.ManifestPath(repo.ID)
	if _, err := os.Stat(existingPath); errors.Is(err, os.ErrNotExist) {
		source, openErr := os.Open(selectedPath)
		if openErr != nil {
			return openErr
		}
		return errors.Join(manifest.AtomicCopy(destination, source, 0o600), source.Close())
	} else if err != nil {
		return err
	}
	return mergeRepoManifestSelection(cfg, repo, existingPath, selectedPath, destination, tempDir)
}

// filterAPTPublicationManifest projects a fully materialized shared APT root
// onto selected suite-wide transactions. Every selected suite keeps all of
// its generated metadata because Release/InRelease covers every configured
// architecture. Shared pool bytes are included only when one of those suite
// refs actually references them; unselected-suite pending bytes stay out.
func filterAPTPublicationManifest(scannedPath, selectedPayloadPath string, projection publicationProjection, original config.Repo, destination string) error {
	if selectedPayloadPath == "" {
		return errors.New("selected APT payload manifest is missing")
	}
	scanned, err := os.Open(scannedPath)
	if err != nil {
		return err
	}
	defer scanned.Close()
	payloads, err := os.Open(selectedPayloadPath)
	if err != nil {
		return err
	}
	defer payloads.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = output.Close()
		if !committed {
			_ = os.Remove(destination)
		}
	}()
	writer := bufio.NewWriterSize(output, 256*1024)
	scanReader := manifest.NewReader(scanned)
	payloadReader := manifest.NewReader(payloads)
	payload, payloadErr := payloadReader.Next()
	for {
		entry, nextErr := scanReader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return nextErr
		}
		if !pathWithin(entry.Path, projection.sourceRoot) {
			return fmt.Errorf("publication scan path %q escapes source root %q", entry.Path, projection.sourceRoot)
		}
		relative := strings.TrimPrefix(entry.Path, strings.TrimSuffix(projection.sourceRoot, "/")+"/")
		logical := path.Join(projection.legacyRoot, relative)
		keep := false
		if strings.HasPrefix(logical, strings.TrimSuffix(original.Path, "/")+"/pool/") {
			for payloadErr == nil && payload.Path < logical {
				payload, payloadErr = payloadReader.Next()
			}
			if payloadErr != nil && !errors.Is(payloadErr, io.EOF) {
				return payloadErr
			}
			keep = payloadErr == nil && payload.Path == logical
		} else {
			relativeLogical := strings.TrimPrefix(logical, strings.TrimSuffix(original.Path, "/")+"/")
			parts := strings.Split(relativeLogical, "/")
			keep = len(parts) >= 3 && parts[0] == "dists" && contains(projection.aptMetadataSuites, parts[1])
		}
		if keep {
			if err := manifest.WriteEntry(writer, entry); err != nil {
				return err
			}
		}
	}
	if err := errors.Join(writer.Flush(), output.Sync(), output.Close()); err != nil {
		return err
	}
	committed = true
	return nil
}
