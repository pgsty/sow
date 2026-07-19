package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
)

// validatePublishTargetAffinitySelection is a pure, pre-lock gate. In
// particular, an explicit --repo cos-only --target cf request must fail before
// credentials are resolved or any remote observation is possible.
func validatePublishTargetAffinitySelection(repos []config.Repo, targets []string, explicitRepos bool) error {
	if explicitRepos {
		for _, repo := range repos {
			matched := false
			for _, target := range targets {
				if repo.PublishesToTarget(target) {
					matched = true
					break
				}
			}
			if !matched {
				return fmt.Errorf("explicitly selected repository %s publishes to none of the selected targets", repo.ID)
			}
		}
	}
	for _, target := range targets {
		matched := false
		for _, repo := range repos {
			if repo.PublishesToTarget(target) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("none of the selected repositories publish to target %s", target)
		}
	}
	return nil
}

func reposPublishingToTarget(repos []config.Repo, target string) []config.Repo {
	result := make([]config.Repo, 0, len(repos))
	for _, repo := range repos {
		if repo.PublishesToTarget(target) {
			result = append(result, repo)
		}
	}
	return result
}

func reposPublishingToTargets(repos []config.Repo, targets []string) []config.Repo {
	result := make([]config.Repo, 0, len(repos))
	for _, repo := range repos {
		for _, target := range targets {
			if repo.PublishesToTarget(target) {
				result = append(result, repo)
				break
			}
		}
	}
	return result
}

func validatePublishTargetViewAffinitySelection(cfg *config.Config, repos []config.Repo, targets, views []string) error {
	for _, viewName := range views {
		view, exists := cfg.Views[viewName]
		if !exists {
			return fmt.Errorf("publication view %s is not configured", viewName)
		}
		for _, target := range targets {
			matched := false
			for _, repo := range repos {
				if repo.PublishesToTarget(target) && viewIncludesRepo(view, repo.ID) {
					matched = true
					break
				}
			}
			if !matched {
				return fmt.Errorf("view %s contains no selected repository assigned to target %s", viewName, target)
			}
		}
	}
	return nil
}

func validateLocalPublishedTargetAffinity(canonical *state.Store, cfg *config.Config, targets []string) error {
	for _, target := range targets {
		generation, _, exists, err := readLocalTargetGeneration(canonical, target)
		if err != nil {
			return fmt.Errorf("inspect local target %s affinity: %w", target, err)
		}
		if exists {
			if err := validatePublishedTargetAffinity(cfg, target, &generation); err != nil {
				return err
			}
			if len(generation.Compatibility) == 0 {
				continue
			}
			commit, recorded, err := targetGenerationPublicationState(canonical, target, generation.Generation)
			if err != nil {
				return fmt.Errorf("inspect local target %s committed compatibility state: %w", target, err)
			}
			currentBody, currentErr := generation.Canonical()
			recordedBody, recordedErr := recorded.Canonical()
			if currentErr != nil || recordedErr != nil || !bytes.Equal(currentBody, recordedBody) {
				return errors.Join(currentErr, recordedErr, fmt.Errorf("local target %s generation differs from its committed publication state", target))
			}
			if err := validateHistoricalGenerationCompatibility(cfg, canonical, target, recorded, commit); err != nil {
				return err
			}
		}
	}
	return nil
}

// publicationPreparedForTarget narrows an already materialized local intent
// to one target without changing the shared prepared value. Its manifest is a
// new streaming projection of the union manifest: target-owned repositories
// and repositories shared with the target are retained, while entries owned
// only by sibling targets are omitted before any desired/content/plan build.
func publicationPreparedForTarget(prepared preparedPublication, target, workspace string) (preparedPublication, error) {
	result := prepared
	result.projections = nil
	result.routeLeaves = nil
	ownedRoots := make(map[string]struct{})
	for _, projection := range prepared.projections {
		if !projection.repo.PublishesToTarget(target) {
			continue
		}
		result.projections = append(result.projections, projection)
		ownedRoots[projection.sourceRoot] = struct{}{}
	}
	for _, leaf := range prepared.routeLeaves {
		if leaf.repo.PublishesToTarget(target) {
			result.routeLeaves = append(result.routeLeaves, leaf)
		}
	}
	result.yumOwnerLeaves = make(map[string][]viewLeaf)
	for _, projection := range result.projections {
		if projection.repo.Type != "yum" || projection.compatibilityID != "" {
			continue
		}
		key := yumPublicationOwnerKey(projection.repo.ID, projection.arch)
		if leaves, exists := prepared.yumOwnerLeaves[key]; exists {
			result.yumOwnerLeaves[key] = append([]viewLeaf(nil), leaves...)
		}
	}
	if len(result.projections) == 0 {
		return result, fmt.Errorf("%w: publication %s has no repository assigned to target %s", pub.ErrDrift, prepared.label(), target)
	}
	result.scopes = make([]string, 0, len(prepared.scopes))
	for _, scope := range prepared.scopes {
		if _, owned := ownedRoots[scope]; owned {
			result.scopes = append(result.scopes, scope)
		}
	}
	result.restoreRemovedProjectionRoots = filterBoolMapByKeys(prepared.restoreRemovedProjectionRoots, ownedRoots)
	result.compatibilitySelected = make(map[string]config.YUMCompatibilityProjection)
	result.compatibilityOwners = make(map[string]config.Repo)
	for id, projection := range prepared.compatibilitySelected {
		owner, exists := prepared.compatibilityOwners[id]
		if !exists {
			return result, fmt.Errorf("%w: compatibility projection %s has no prepared owner", pub.ErrDrift, id)
		}
		if !owner.PublishesToTarget(target) {
			continue
		}
		result.compatibilitySelected[id] = projection
		result.compatibilityOwners[id] = owner
	}

	// Historical restore is exact, not a selector. Silently dropping an old ref
	// after affinity changed would turn restore into an undocumented deletion.
	if prepared.refOverrides != nil {
		for name := range prepared.refOverrides {
			repoID, err := publicationRefRepoID(name)
			if err != nil {
				return result, err
			}
			repo, exists := projectionRepoByID(prepared.projections, repoID)
			if !exists {
				return result, fmt.Errorf("%w: historical ref %s has no prepared repository projection", pub.ErrDrift, name)
			}
			if !repo.PublishesToTarget(target) {
				return result, fmt.Errorf("%w: historical ref %s belongs to repo %s which no longer publishes to target %s", pub.ErrDrift, name, repoID, target)
			}
		}
	}
	if prepared.manifestPath == "" {
		return result, fmt.Errorf("%w: publication %s has no prepared manifest", pub.ErrDrift, prepared.label())
	}
	for sourceRoot := range ownedRoots {
		if !contains(result.scopes, sourceRoot) {
			return result, fmt.Errorf("%w: publication %s repository root %s has no prepared manifest scope for target %s", pub.ErrDrift, prepared.label(), sourceRoot, target)
		}
	}
	if workspace == "" {
		return result, fmt.Errorf("%w: publication %s target %s has no isolated workspace", pub.ErrDrift, prepared.label(), target)
	}
	unionScopes, err := normalizeManifestScopes(prepared.scopes)
	if err != nil {
		return result, fmt.Errorf("%w: normalize publication %s union scopes: %v", pub.ErrDrift, prepared.label(), err)
	}
	targetScopes, err := normalizeManifestScopes(result.scopes)
	if err != nil {
		return result, fmt.Errorf("%w: normalize publication %s target %s scopes: %v", pub.ErrDrift, prepared.label(), target, err)
	}
	if slices.Equal(unionScopes, targetScopes) {
		// A target owning the whole prepared union can consume the frozen union
		// manifest directly. Besides avoiding an unnecessary O(repository) copy,
		// this is required when an interrupted-publication recovery deliberately
		// reuses the preparation workspace: source and destination would otherwise
		// be the same O_EXCL path. Keep the streaming scope check so the shortcut
		// cannot bless a corrupt or unrelated manifest entry.
		if err := validateTargetPublicationManifest(prepared.manifestPath, unionScopes); err != nil {
			return result, fmt.Errorf("validate publication %s manifest for target %s: %w", prepared.label(), target, err)
		}
		result.manifestPath = prepared.manifestPath
		return result, nil
	}
	targetManifest := filepath.Join(workspace, fmt.Sprintf("selected-target-%s-%s.tsv", target, prepared.label()))
	if err := filterTargetPublicationManifest(prepared.manifestPath, targetManifest, unionScopes, targetScopes); err != nil {
		return result, fmt.Errorf("filter publication %s manifest for target %s: %w", prepared.label(), target, err)
	}
	result.manifestPath = targetManifest
	return result, nil
}

// filterTargetPublicationManifest copies one canonical union manifest while
// retaining only target scopes. It keeps one manifest entry in memory and also
// verifies that every source entry belongs to the prepared union scope, so the
// affinity filter cannot hide an unrelated or corrupt path.
func filterTargetPublicationManifest(sourcePath, destinationPath string, unionScopes, targetScopes []string) error {
	unionScopes, err := normalizeManifestScopes(unionScopes)
	if err != nil {
		return fmt.Errorf("normalize prepared union scopes: %w", err)
	}
	targetScopes, err = normalizeManifestScopes(targetScopes)
	if err != nil {
		return fmt.Errorf("normalize prepared target scopes: %w", err)
	}
	if len(targetScopes) == 0 {
		return errors.New("target manifest requires at least one scope")
	}
	for _, scope := range targetScopes {
		if !contains(unionScopes, scope) {
			return fmt.Errorf("target manifest scope %q is outside the prepared union", scope)
		}
	}

	source, err := openRegularManifest(sourcePath)
	if err != nil {
		return fmt.Errorf("open prepared union manifest: %w", err)
	}
	defer source.Close()
	reader := manifest.NewReader(source)
	return writeExclusiveManifest(destinationPath, func(destination io.Writer) error {
		for {
			entry, err := reader.Next()
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("read prepared union manifest: %w", err)
			}
			if !manifestEntryInScopes(entry.Path, unionScopes) {
				return fmt.Errorf("prepared manifest entry %q is outside union scopes", entry.Path)
			}
			if !manifestEntryInScopes(entry.Path, targetScopes) {
				continue
			}
			if err := manifest.WriteEntry(destination, entry); err != nil {
				return fmt.Errorf("write target manifest entry %q: %w", entry.Path, err)
			}
		}
	})
}

// validateTargetPublicationManifest retains the same trust boundary as the
// narrowing copy while allowing a whole-union target to share its immutable
// prepared manifest. Memory use is one manifest entry.
func validateTargetPublicationManifest(sourcePath string, scopes []string) error {
	source, err := openRegularManifest(sourcePath)
	if err != nil {
		return fmt.Errorf("open prepared union manifest: %w", err)
	}
	defer source.Close()
	reader := manifest.NewReader(source)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read prepared union manifest: %w", err)
		}
		if !manifestEntryInScopes(entry.Path, scopes) {
			return fmt.Errorf("prepared manifest entry %q is outside union scopes", entry.Path)
		}
	}
}

func filterBoolMapByKeys(input map[string]bool, keys map[string]struct{}) map[string]bool {
	if input == nil {
		return nil
	}
	result := make(map[string]bool)
	for key, value := range input {
		if _, keep := keys[key]; keep {
			result[key] = value
		}
	}
	return result
}

func projectionRepoByID(projections []publicationProjection, id string) (config.Repo, bool) {
	for _, projection := range projections {
		if projection.repo.ID == id {
			return projection.repo, true
		}
	}
	return config.Repo{}, false
}

// validatePublishedTargetAffinity makes affinity narrowing fail closed. An old
// target generation may retain content for a repo only while that repo remains
// assigned to the target; removing it requires a separately audited full
// reconciliation rather than an incremental publication silently retaining or
// deleting the stale scope.
func validatePublishedTargetAffinity(cfg *config.Config, target string, parent *pub.TargetGeneration) error {
	if parent == nil {
		return nil
	}
	for _, ref := range parent.Refs {
		repoID, err := publicationRefRepoID(ref.Name)
		if err != nil {
			return err
		}
		repo, exists := cfg.RepoByName(repoID)
		if !exists {
			return fmt.Errorf("%w: target %s ref %s names a repository absent from canonical config", pub.ErrDrift, target, ref.Name)
		}
		if !repo.PublishesToTarget(target) {
			return fmt.Errorf("%w: target %s still contains ref %s for repo %s after target affinity narrowed; perform an explicit full target reconciliation", pub.ErrDrift, target, ref.Name, repoID)
		}
	}
	for _, channel := range parent.Channels {
		repo, err := publicationChannelOwnerRepo(cfg, channel)
		if err != nil {
			return fmt.Errorf("%w: %v", pub.ErrDrift, err)
		}
		if !repo.PublishesToTarget(target) {
			return fmt.Errorf("%w: target %s still contains channel %s for owner repo %s after target affinity changed; perform an explicit full target reconciliation", pub.ErrDrift, target, channel.RemoteKey, repo.ID)
		}
	}
	return nil
}

func publicationRefRepoID(name string) (string, error) {
	parts := strings.Split(name, "/")
	if len(parts) != 7 || parts[0] != "refs" || parts[1] != "sow" || parts[2] != "views" && parts[2] != "snapshots" || parts[4] == "" {
		return "", fmt.Errorf("%w: invalid publication ref %q", pub.ErrDrift, name)
	}
	return parts[4], nil
}

func affinityRepoIDs(repos []config.Repo) []string {
	result := make([]string, 0, len(repos))
	for _, repo := range repos {
		result = append(result, repo.ID)
	}
	sort.Strings(result)
	return result
}
