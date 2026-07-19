package cli

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/pgsty/sow/internal/config"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
)

type publicationPreflightResult struct {
	target    string
	unchanged bool
	err       error
}

// runPublicationPreflightsConcurrently prevents one provider's control-plane
// observation from serializing its sibling. Errors remain target-local so the
// caller can preserve partial-publication semantics; the shared worker budget
// is divided across the concurrent preflights and their inner local scans.
func runPublicationPreflightsConcurrently(
	ctx context.Context,
	targets []string,
	totalWorkers int,
	run func(context.Context, string, int) (bool, error),
) ([]publicationPreflightResult, error) {
	if run == nil {
		return nil, errors.New("publication preflight callback is unavailable")
	}
	if totalWorkers < 1 {
		return nil, errors.New("worker count must be positive")
	}
	if len(targets) == 0 {
		return nil, nil
	}
	// Provider control-plane reads are latency-bound and there are at most two
	// product targets. Always give both targets an outer goroutine, even when
	// the caller requests one CPU worker; otherwise a stalled CF observation can
	// prevent COS from proving an unchanged publication at all. Inner scans keep
	// the divided worker budget and never receive zero workers.
	innerWorkers := max(1, totalWorkers/len(targets))
	preflightCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make([]publicationPreflightResult, len(targets))
	var group sync.WaitGroup
	for index, target := range targets {
		index, target := index, target
		group.Add(1)
		go func() {
			defer group.Done()
			result := publicationPreflightResult{target: target}
			if err := preflightCtx.Err(); err != nil {
				result.err = err
				results[index] = result
				return
			}
			result.unchanged, result.err = run(preflightCtx, target, innerWorkers)
			results[index] = result
			// The unchanged path is only an optimization. As soon as any target
			// needs the full pipeline (or its provider observation fails), cancel
			// sibling optimization calls so a healthy changed target can proceed.
			// Verification failures remain target-local and must not erase the
			// sibling's chance to prove a real no-op.
			if result.err == nil && !result.unchanged || result.err != nil && !errors.Is(result.err, pub.ErrVerification) {
				cancel()
			}
		}()
	}
	group.Wait()
	return results, nil
}

// publicationUnchangedPreflight proves that a selected view cannot produce a
// content change before SOW materializes packages or scans repository trees.
// It deliberately has no optimistic/force mode: an incomplete transaction,
// control-plane disagreement, changed ref commit, changed config, or pending
// snapshot retention work returns false and sends the caller through the full
// publication pipeline.
func publicationUnchangedPreflight(
	ctx context.Context,
	cfg *config.Config,
	canonical *state.Store,
	pool *repository.Store,
	repos []config.Repo,
	viewName, target, txDir string,
	values commonFlags,
) (bool, error) {
	view, exists := cfg.Views[viewName]
	if !exists {
		return false, nil
	}
	if err := validateCanonicalPurgeLedgerForPublish(ctx, canonical, cfg, target); err != nil {
		return false, err
	}
	if viewName == "latest" {
		if err := preflightLocalYUMCompatibilityS0Rollback(ctx, cfg, canonical, pool, repos, target, txDir, values); err != nil {
			return false, err
		}
	}
	client, err := newPublishTargetClient(cfg, target, viewName, view.Access == "pro")
	if err != nil {
		return false, err
	}
	observation, err := observeRemoteTargetControl(ctx, canonical, client, target, txDir)
	if err != nil {
		return false, err
	}
	if err := validatePublishedTargetAffinity(cfg, target, observation.parent); err != nil {
		return false, err
	}
	if observation.parent == nil || observation.resumeGeneration != nil || observation.resumeCheckpoint != nil || observation.resumeLock != nil {
		return false, nil
	}
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		return false, err
	}
	activeCompatibility := make(map[string]struct{})
	for _, projection := range cfg.CompatibilityProjections {
		if owner, exists := cfg.RepoByName(projection.Source.Repo); exists && owner.PublishesToTarget(target) {
			active, err := publicationYUMCompatibilityActiveAt(canonical, head, projection.ID)
			if err != nil {
				return false, err
			}
			if active {
				activeCompatibility[projection.ID] = struct{}{}
			}
		}
	}
	if len(activeCompatibility) != len(observation.parent.Compatibility) {
		return false, nil
	}
	parentCompatibility := make(map[string]struct{}, len(observation.parent.Compatibility))
	for _, identity := range observation.parent.Compatibility {
		if _, duplicate := parentCompatibility[identity.ID]; duplicate {
			return false, nil
		}
		parentCompatibility[identity.ID] = struct{}{}
		if _, active := activeCompatibility[identity.ID]; !active {
			return false, nil
		}
	}
	if len(parentCompatibility) != 0 {
		if err := validateGenerationCompatibility(cfg, canonical, target, *observation.parent); err != nil {
			return false, err
		}
	}
	configSHA, err := publicationConfigSHA256ForGeneration(cfg, *observation.parent)
	if err != nil {
		return false, err
	}
	if observation.parent.ConfigSHA256 != configSHA {
		return false, nil
	}
	repositoryKeySHA, err := repositoryTrustAnchorSHA256ForRefs(cfg, observation.parent.Refs)
	if err != nil {
		return false, err
	}
	if observation.parent.RepositoryKeySHA256 != repositoryKeySHA {
		return false, nil
	}
	refsCurrent, err := selectedPublicationRefCommitsCurrent(canonical, cfg, repos, viewName, target, view, values, observation.parent)
	if err != nil || !refsCurrent {
		return false, err
	}
	if viewName == "stable" {
		retentionCurrent, err := publishedSnapshotRetentionCurrent(observation.parent, timeNowUTC(), cfg.State.SnapshotMaterializationMonths)
		if err != nil || !retentionCurrent {
			return false, err
		}
	}
	return true, nil
}

func selectedPublicationRefCommitsCurrent(canonical *state.Store, cfg *config.Config, repos []config.Repo, viewName, target string, view config.View, values commonFlags, parent *pub.TargetGeneration) (bool, error) {
	if parent == nil {
		return false, nil
	}
	parentRefs := make(map[string]pub.RefState, len(parent.Refs))
	for _, ref := range parent.Refs {
		parentRefs[ref.Name] = ref
	}
	selected := suiteClosedSelectedLeaves(cfg, repos, values)
	comparison := make(map[string]viewLeaf, len(selected))
	var selectedExistingYUM []viewLeaf
	for _, leaf := range selected {
		if !viewIncludesRepo(view, leaf.repo.ID) || !leaf.repo.PublishesToTarget(target) {
			continue
		}
		comparison[servingLeafKey(leaf.repo.ID, leaf.os, leaf.arch)] = leaf
		if leaf.repo.Type == "yum" && viewLeafExists(canonical, viewName, leaf) {
			selectedExistingYUM = append(selectedExistingYUM, leaf)
		}
	}
	if len(selectedExistingYUM) != 0 {
		source := materializeCanonicalSource{ID: viewName, Public: view.Access == "public"}
		closed, err := materializedRoutePhysicalClosureLeaves(cfg, canonical, source, selectedExistingYUM)
		if err != nil {
			return false, err
		}
		for _, leaf := range closed {
			comparison[servingLeafKey(leaf.repo.ID, leaf.os, leaf.arch)] = leaf
		}
	}
	keys := make([]string, 0, len(comparison))
	for key := range comparison {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	matched := 0
	for _, key := range keys {
		leaf := comparison[key]
		ref, err := state.ViewRef(viewName, leaf.repo.ID, leaf.os, leaf.arch)
		if err != nil {
			return false, err
		}
		commit, exists, err := canonical.Ref(ref)
		if err != nil {
			return false, err
		}
		published, wasPublished := parentRefs[ref.String()]
		if !exists {
			if wasPublished {
				return false, nil
			}
			continue
		}
		matched++
		if !wasPublished || published.Commit != commit.String() {
			return false, nil
		}
	}
	return matched > 0, nil
}

func publishedSnapshotRetentionCurrent(parent *pub.TargetGeneration, now time.Time, months int) (bool, error) {
	for _, ref := range parent.Refs {
		id, snapshot := snapshotIDFromPublicationRef(ref.Name)
		if !snapshot {
			continue
		}
		retained, err := retainMaterializedSnapshot(id, now, months)
		if err != nil {
			return false, err
		}
		if !retained {
			return false, nil
		}
	}
	return true, nil
}

func publicationPreflightDir(root, viewName, target string) string {
	return filepath.Join(root, "preflight-"+viewName+"-"+target)
}
