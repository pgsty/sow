package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
)

type aptByHashDeleteCandidate struct {
	deletion    pub.PlannedDelete
	ledgerPath  string
	scope       string
	repo        string
	suite       string
	relative    string
	releasePath string
}

// augmentAuthorizedRemoteDeletes translates only two evidence-backed removed
// source paths into remote mutations. Ordinary APT/YUM/package removals remain
// in Plan.Removed and keep their remote bytes for history and rollback. A
// forward-only beta/latest restore may use the asset class, but only after the
// old manifest has been bound to the currently committed parent generation;
// restore never receives APT by-hash retention authority.
func augmentAuthorizedRemoteDeletes(
	canonical *state.Store,
	prepared preparedPublication,
	classifier publicationClassifier,
	oldManifestPath, desiredManifestPath string,
	plan *pub.Plan,
) error {
	if canonical == nil || plan == nil {
		return errors.New("remote deletion planning requires canonical state and a plan")
	}
	if len(plan.Removed) == 0 {
		return nil
	}
	if prepared.restoreSourceGeneration != 0 {
		if prepared.restoreParentContentSHA256 == "" {
			return fmt.Errorf("%w: restore asset deletion has no parent content manifest binding", pub.ErrDrift)
		}
		actual, err := hashRegularPath(oldManifestPath)
		if err != nil {
			return fmt.Errorf("hash restore parent content manifest: %w", err)
		}
		if actual != prepared.restoreParentContentSHA256 {
			return fmt.Errorf("%w: restore parent content manifest digest=%s want=%s", pub.ErrDrift, actual, prepared.restoreParentContentSHA256)
		}
	}
	removedEntries, err := manifestEntriesByPath(oldManifestPath, stringSet(plan.Removed))
	if err != nil {
		return fmt.Errorf("read remote deletion baseline: %w", err)
	}
	if len(removedEntries) != len(plan.Removed) {
		return fmt.Errorf("%w: deletion baseline resolved %d of %d removed entries", pub.ErrDrift, len(removedEntries), len(plan.Removed))
	}

	var byHash []aptByHashDeleteCandidate
	for _, sourcePath := range plan.Removed {
		entry := removedEntries[sourcePath]
		// The target-wide baseline can also lose expired snapshot scopes while
		// publishing a selected view. Those paths are owned by the dedicated
		// retention plan, not by this asset/by-hash authorization pass.
		if !matchesPublicationProjection(classifier.projections, sourcePath) {
			continue
		}
		projection, relative, err := classifier.projection(sourcePath)
		if err != nil {
			return err
		}
		if projection.isYUMCompatibilityRollback() {
			// Exact S0 rollback deletions require the content-bound S3 parent
			// plan and are admitted only by augmentRolledBackCompatibilityDeletes.
			continue
		}
		remoteKey, class, err := classifier.classify(entry)
		if err != nil {
			return err
		}
		switch projection.repo.Type {
		case "asset":
			if prepared.restoreSourceGeneration != 0 && prepared.view != "beta" && prepared.view != "latest" {
				return fmt.Errorf("%w: asset path removal restore is unsupported for append-only or immutable intent %s", pub.ErrDrift, prepared.label())
			}
			if class != pub.ObjectImmutable && class != pub.ObjectPointer {
				return fmt.Errorf("asset removal %s has unsafe publish class %s", sourcePath, class)
			}
			cdnPath := remoteKey
			switch prepared.view {
			case "beta":
				cdnPath = betaCDNPath(remoteKey)
			case "stable":
				cdnPath = proCDNPath(remoteKey)
			case "latest":
			default:
				return fmt.Errorf("asset deletion is unsupported for publication intent %s", prepared.label())
			}
			plan.Deletes = append(plan.Deletes, pub.PlannedDelete{
				Class: pub.DeleteAssetServing, SourcePath: sourcePath, RemoteKey: remoteKey,
				Size: entry.Size, SHA256: entry.HashString(), CDNPath: cdnPath,
			})
		case "apt":
			if prepared.restoreSourceGeneration != 0 {
				// Restore removes only the public beta/latest index entry points.
				// Pool payloads and immutable generation archives remain preservation
				// roots for history and future forward restores.
				if (prepared.view == "beta" || prepared.view == "latest") && strings.HasPrefix(relative, "dists/") {
					cdnPath := strings.TrimPrefix(remoteKey, ".sow/beta/")
					plan.Deletes = append(plan.Deletes, pub.PlannedDelete{
						Class: pub.DeleteRestoreIndexServing, SourcePath: sourcePath, RemoteKey: remoteKey,
						Size: entry.Size, SHA256: entry.HashString(), CDNPath: cdnPath,
					})
				}
				continue
			}
			if !isAPTByHashRelativePath(relative) {
				continue
			}
			if prepared.view != "beta" && prepared.view != "latest" && prepared.view != "stable" {
				continue
			}
			if class != pub.ObjectImmutable {
				return fmt.Errorf("APT by-hash removal %s has unsafe publish class %s", sourcePath, class)
			}
			parts := strings.Split(relative, "/")
			suite := parts[1]
			ledgerPath, err := state.APTByHashLedgerPath("views", prepared.view, projection.repo.ID, suite)
			if err != nil {
				return err
			}
			byHash = append(byHash, aptByHashDeleteCandidate{
				deletion: pub.PlannedDelete{
					Class: pub.DeleteAPTByHash, SourcePath: sourcePath, RemoteKey: remoteKey,
					Size: entry.Size, SHA256: entry.HashString(),
				},
				ledgerPath: ledgerPath, scope: "views/" + prepared.view, repo: projection.repo.ID,
				suite: suite, relative: relative,
				releasePath: path.Join(projection.sourceRoot, "dists", suite, "Release"),
			})
		case "yum":
			if prepared.restoreSourceGeneration == 0 || (prepared.view != "beta" && prepared.view != "latest") || !strings.HasPrefix(relative, "repodata/") {
				continue
			}
			if class != pub.ObjectMetadata {
				return fmt.Errorf("YUM restore removal %s has unsafe publish class %s", sourcePath, class)
			}
			legacyKey := path.Join(projection.legacyRoot, relative)
			if prepared.view == "beta" {
				legacyKey = path.Join(".sow/beta", legacyKey)
			}
			plan.Deletes = append(plan.Deletes, pub.PlannedDelete{
				Class: pub.DeleteRestoreIndexServing, SourcePath: sourcePath, RemoteKey: legacyKey,
				Size: entry.Size, SHA256: entry.HashString(), CDNPath: strings.TrimPrefix(legacyKey, ".sow/beta/"),
			})
		}
	}
	if prepared.restoreSourceGeneration == 0 {
		if err := authorizeAPTByHashDeletes(canonical, desiredManifestPath, byHash, plan); err != nil {
			return err
		}
	}
	return nil
}

func matchesPublicationProjection(projections []publicationProjection, sourcePath string) bool {
	for _, projection := range projections {
		root := strings.TrimSuffix(projection.sourceRoot, "/")
		if sourcePath == root || strings.HasPrefix(sourcePath, root+"/") {
			return true
		}
	}
	return false
}

func authorizeAPTByHashDeletes(canonical *state.Store, desiredManifestPath string, candidates []aptByHashDeleteCandidate, plan *pub.Plan) error {
	if len(candidates) == 0 {
		return nil
	}
	releaseWanted := make(map[string]struct{})
	for _, candidate := range candidates {
		releaseWanted[candidate.releasePath] = struct{}{}
	}
	releases, err := manifestEntriesByPath(desiredManifestPath, releaseWanted)
	if err != nil {
		return fmt.Errorf("read live APT Release closure: %w", err)
	}

	type ledgerState struct {
		ledger aptrepo.ByHashLedger
		paths  map[string]struct{}
	}
	ledgers := make(map[string]ledgerState)
	for _, candidate := range candidates {
		current, exists := ledgers[candidate.ledgerPath]
		if !exists {
			reader, err := canonical.OpenPath(candidate.ledgerPath)
			if err != nil {
				return fmt.Errorf("%w: current APT by-hash ledger %s is unavailable: %v", pub.ErrDrift, candidate.ledgerPath, err)
			}
			ledger, decodeErr := aptrepo.DecodeByHashLedger(reader)
			closeErr := reader.Close()
			if decodeErr != nil || closeErr != nil {
				return errors.Join(decodeErr, closeErr)
			}
			if ledger.Scope != candidate.scope || ledger.Repo != candidate.repo || ledger.Suite != candidate.suite {
				return fmt.Errorf("%w: current APT by-hash ledger %s has the wrong identity", pub.ErrDrift, candidate.ledgerPath)
			}
			release, ok := releases[candidate.releasePath]
			if !ok || release.HashString() != ledger.LiveGeneration {
				return fmt.Errorf("%w: live Release %s does not match sealed ledger generation", pub.ErrDrift, candidate.releasePath)
			}
			paths := make(map[string]struct{})
			for _, generation := range ledger.Generations {
				for _, value := range generation.Paths {
					paths[value] = struct{}{}
				}
			}
			current = ledgerState{ledger: ledger, paths: paths}
			ledgers[candidate.ledgerPath] = current
		}
		if _, retained := current.paths[candidate.relative]; retained {
			// A shared hash can be referenced by both an expired and a retained
			// generation. The current sealed ledger wins and remote bytes stay.
			continue
		}
		owned, err := historicalAPTByHashLedgerContains(canonical, candidate)
		if err != nil {
			return err
		}
		if !owned {
			return fmt.Errorf("%w: removed APT by-hash path %s has no sealed historical ledger ownership", pub.ErrDrift, candidate.deletion.SourcePath)
		}
		plan.Deletes = append(plan.Deletes, candidate.deletion)
	}
	return nil
}

func historicalAPTByHashLedgerContains(canonical *state.Store, candidate aptByHashDeleteCandidate) (bool, error) {
	history, err := canonical.History()
	if err != nil {
		return false, err
	}
	for _, commit := range history {
		reader, err := canonical.OpenPathAt(commit, candidate.ledgerPath)
		if errors.Is(err, object.ErrFileNotFound) {
			continue
		}
		if err != nil {
			return false, err
		}
		ledger, decodeErr := aptrepo.DecodeByHashLedger(reader)
		closeErr := reader.Close()
		if decodeErr != nil || closeErr != nil {
			return false, fmt.Errorf("%w: historical APT by-hash ledger %s at %s is invalid: %v", pub.ErrDrift, candidate.ledgerPath, commit, errors.Join(decodeErr, closeErr))
		}
		if ledger.Scope != candidate.scope || ledger.Repo != candidate.repo || ledger.Suite != candidate.suite {
			return false, fmt.Errorf("%w: historical APT by-hash ledger %s at %s has the wrong identity", pub.ErrDrift, candidate.ledgerPath, commit)
		}
		for _, generation := range ledger.Generations {
			for _, value := range generation.Paths {
				if value == candidate.relative {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func manifestEntriesByPath(filename string, wanted map[string]struct{}) (map[string]manifest.Entry, error) {
	result := make(map[string]manifest.Entry, len(wanted))
	if len(wanted) == 0 {
		return result, nil
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	reader := manifest.NewReader(file)
	for {
		entry, readErr := reader.Next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_ = file.Close()
			return nil, readErr
		}
		if _, ok := wanted[entry.Path]; ok {
			result[entry.Path] = entry
		}
	}
	return result, file.Close()
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func isAPTByHashRelativePath(value string) bool {
	parts := strings.Split(value, "/")
	return len(parts) == 7 && parts[0] == "dists" && parts[1] != "" && parts[2] != "" &&
		strings.HasPrefix(parts[3], "binary-") && parts[4] == "by-hash" && parts[5] == "SHA256" && isLowerHexDelete(parts[6], 64)
}

func isLowerHexDelete(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

// negativeOnlyPublicationAllowed is the sole exception to the normal
// unchanged positive CDN probe. A pure asset-removal change is completely
// evidenced by storage absence plus exact CDN 404/410 for every removed
// serving URL, even if another intent or repository still has unrelated
// target content. Mixed snapshot/by-hash deletions still require a positive
// probe from their retained publication closure.
func negativeOnlyPublicationAllowed(plan pub.Plan) (bool, error) {
	if len(plan.Objects) != 0 || len(plan.Deletes) == 0 {
		return false, nil
	}
	for _, deletion := range plan.Deletes {
		if (deletion.Class != pub.DeleteAssetServing && deletion.Class != pub.DeleteRestoreIndexServing) || deletion.CDNPath == "" {
			return false, nil
		}
	}
	if len(plan.PurgeURLs) == 0 || len(plan.VerifyAbsent) != len(plan.Deletes) {
		return false, fmt.Errorf("%w: negative-only deletion closure is incomplete", pub.ErrVerification)
	}
	return true, nil
}
