package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
)

var historicalCompatibilityMetadataPattern = regexp.MustCompile(`^([0-9a-f]{64})-(primary|filelists|other)\.xml\.gz$`)

type historicalCompatibilityRestore struct {
	identity      pub.CompatibilityState
	projection    config.YUMCompatibilityProjection
	owner         config.Repo
	candidatePath string
	entries       int64
	bytes         int64
}

// stageHistoricalCompatibilityRestores copies only commit-bound candidate
// manifests into the transaction. candidate.tsv is the frozen S2 clean tree:
// payload, flat aliases and signed metadata are restored from CAS byte-for-byte
// and are never regenerated with today's repository key.
func stageHistoricalCompatibilityRestores(canonical *state.Store, cfg *config.Config, commit plumbing.Hash, generation pub.TargetGeneration, txDir string) ([]historicalCompatibilityRestore, error) {
	if canonical == nil || cfg == nil || commit.IsZero() {
		return nil, errors.New("historical compatibility restore dependencies are unavailable")
	}
	result := make([]historicalCompatibilityRestore, 0, len(generation.Compatibility))
	for index, identity := range generation.Compatibility {
		projection, exists, err := config.YUMCompatibilityProjectionByID(cfg.CompatibilityProjections, identity.ID)
		if err != nil || !exists {
			return nil, errors.Join(err, fmt.Errorf("historical compatibility projection %s is absent from current immutable configuration", identity.ID))
		}
		owner, exists := cfg.RepoByName(projection.Source.Repo)
		if !exists || owner.Type != "yum" || owner.YUM == nil {
			return nil, fmt.Errorf("historical compatibility projection %s has no YUM owner", identity.ID)
		}
		candidateCanonical, _ := state.YUMCompatibilityCandidateManifestPath(identity.ID)
		candidatePath := filepath.Join(txDir, fmt.Sprintf("restore-compat-candidate-%06d.tsv", index))
		if err := copyCanonicalPathAt(canonical, commit, candidateCanonical, candidatePath, identity.CandidateManifestSize); err != nil {
			return nil, fmt.Errorf("stage historical compatibility candidate %s: %w", identity.ID, err)
		}
		payloadCanonical, _ := state.YUMCompatibilityManifestPath(identity.ID)
		payload, err := canonical.OpenPathAt(commit, payloadCanonical)
		if err != nil {
			return nil, err
		}
		candidate, err := os.Open(candidatePath)
		if err != nil {
			_ = payload.Close()
			return nil, err
		}
		entries, bytes, validateErr := validateHistoricalCompatibilityCandidate(candidate, payload, identity)
		closeErr := errors.Join(candidate.Close(), payload.Close())
		if validateErr != nil || closeErr != nil {
			return nil, errors.Join(validateErr, closeErr)
		}
		rootedCandidatePath := filepath.Join(txDir, fmt.Sprintf("restore-compat-rooted-%06d.tsv", index))
		if err := prefixManifest(candidatePath, rootedCandidatePath, identity.RouteRoot); err != nil {
			return nil, fmt.Errorf("root historical compatibility candidate %s: %w", identity.ID, err)
		}
		result = append(result, historicalCompatibilityRestore{
			identity: identity, projection: projection, owner: owner, candidatePath: rootedCandidatePath, entries: entries, bytes: bytes,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].identity.ID < result[j].identity.ID })
	return result, nil
}

func copyCanonicalPathAt(canonical *state.Store, commit plumbing.Hash, canonicalPath, destination string, expectedSize int64) error {
	if expectedSize < 0 {
		return errors.New("negative canonical file size")
	}
	source, err := canonical.OpenPathAt(commit, canonicalPath)
	if err != nil {
		return err
	}
	destinationFile, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		_ = source.Close()
		return err
	}
	written, copyErr := io.Copy(destinationFile, io.LimitReader(source, expectedSize+1))
	closeErr := errors.Join(source.Close(), destinationFile.Sync(), destinationFile.Close())
	if copyErr != nil || closeErr != nil || written != expectedSize {
		_ = os.Remove(destination)
		return errors.Join(copyErr, closeErr, fmt.Errorf("canonical file size=%d want=%d", written, expectedSize))
	}
	return nil
}

// validateHistoricalCompatibilityCandidate proves candidate.tsv is exactly the
// payload witness plus one gzip primary/filelists/other and the signed repomd
// pair. The merge is streaming; memory is independent of package count.
func validateHistoricalCompatibilityCandidate(candidate io.Reader, payload io.Reader, identity pub.CompatibilityState) (int64, int64, error) {
	if candidate == nil || payload == nil || identity.RouteRoot == "" {
		return 0, 0, errors.New("historical compatibility candidate validation inputs are incomplete")
	}
	candidateReader := manifest.NewReader(candidate)
	payloadReader := manifest.NewReader(payload)
	payloadEntry, payloadErr := payloadReader.Next()
	metadata := make(map[string]int)
	var entries, bytes int64
	for {
		entry, err := candidateReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return entries, bytes, err
		}
		entries++
		bytes += entry.Size
		relative := entry.Path
		if relative == "" || path.Clean(relative) != relative || strings.HasPrefix(relative, "../") || strings.HasPrefix(relative, "/") {
			return entries, bytes, fmt.Errorf("candidate path %s is unsafe", entry.Path)
		}
		if kind, metadataEntry, err := historicalCompatibilityMetadataKind(relative, entry, identity); err != nil {
			return entries, bytes, err
		} else if metadataEntry {
			metadata[kind]++
			continue
		}
		if payloadErr != nil {
			if errors.Is(payloadErr, io.EOF) {
				return entries, bytes, fmt.Errorf("candidate has extra payload path %s", entry.Path)
			}
			return entries, bytes, payloadErr
		}
		rootedEntry := entry
		rootedEntry.Path = path.Join(identity.RouteRoot, entry.Path)
		if rootedEntry != payloadEntry {
			return entries, bytes, fmt.Errorf("candidate payload %s differs from frozen payload manifest entry %s", rootedEntry.Path, payloadEntry.Path)
		}
		payloadEntry, payloadErr = payloadReader.Next()
	}
	if payloadErr != nil && !errors.Is(payloadErr, io.EOF) {
		return entries, bytes, payloadErr
	}
	if !errors.Is(payloadErr, io.EOF) {
		return entries, bytes, fmt.Errorf("candidate omits frozen payload path %s", payloadEntry.Path)
	}
	for _, kind := range []string{"primary", "filelists", "other", "repomd.xml", "repomd.xml.asc"} {
		if metadata[kind] != 1 {
			return entries, bytes, fmt.Errorf("candidate requires exactly one %s metadata object, got %d", kind, metadata[kind])
		}
	}
	return entries, bytes, nil
}

func historicalCompatibilityMetadataKind(relative string, entry manifest.Entry, identity pub.CompatibilityState) (string, bool, error) {
	if !strings.HasPrefix(relative, "repodata/") {
		parts := strings.Split(relative, "/")
		canonicalPackage := len(parts) == 3 && parts[0] == "Packages" && len(parts[1]) == 1 && path.Base(parts[2]) == parts[2] && strings.HasSuffix(parts[2], ".rpm")
		flatAlias := len(parts) == 1 && strings.HasSuffix(parts[0], ".rpm")
		if !canonicalPackage && !flatAlias {
			return "", false, fmt.Errorf("candidate contains unexpected compatibility payload path %s", entry.Path)
		}
		return "", false, nil
	}
	name := strings.TrimPrefix(relative, "repodata/")
	if strings.Contains(name, "/") || name == "" {
		return "", false, fmt.Errorf("candidate contains nested or empty repodata path %s", entry.Path)
	}
	switch name {
	case "repomd.xml":
		if entry.HashString() != identity.RepomdSHA256 {
			return "", false, fmt.Errorf("candidate repomd SHA-256=%s want=%s", entry.HashString(), identity.RepomdSHA256)
		}
		return name, true, nil
	case "repomd.xml.asc":
		return name, true, nil
	}
	match := historicalCompatibilityMetadataPattern.FindStringSubmatch(name)
	if len(match) != 3 || match[1] != entry.HashString() {
		return "", false, fmt.Errorf("candidate contains unsupported or non-content-addressed metadata %s", entry.Path)
	}
	return match[2], true, nil
}

func pathBelowRoot(value, root string) (string, bool) {
	prefix := strings.TrimSuffix(root, "/") + "/"
	if !strings.HasPrefix(value, prefix) {
		return "", false
	}
	relative := strings.TrimPrefix(value, prefix)
	return relative, relative != "" && path.Clean(relative) == relative && !strings.HasPrefix(relative, "../")
}

func historicalCompatibilityManifestPaths(restores []historicalCompatibilityRestore) []string {
	result := make([]string, 0, len(restores))
	for _, restore := range restores {
		result = append(result, restore.candidatePath)
	}
	return result
}

func historicalCompatibilityPublicationProjections(restores []historicalCompatibilityRestore, restoreRelative string) []publicationProjection {
	result := make([]publicationProjection, 0, len(restores))
	for _, restore := range restores {
		result = append(result, publicationProjection{
			view: "latest", repo: restore.owner, os: restore.projection.Source.OS, arch: restore.projection.Source.Arch,
			compatibilityID: restore.identity.ID,
			sourceRoot:      restore.identity.RouteRoot, localRoot: path.Join(restoreRelative, restore.identity.RouteRoot),
			canonicalRoot: restore.identity.RouteRoot, remoteRoot: restore.identity.RouteRoot, legacyRoot: restore.identity.RouteRoot,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].sourceRoot < result[j].sourceRoot })
	return result
}
