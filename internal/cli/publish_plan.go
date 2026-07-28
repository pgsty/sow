package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

type targetPublication struct {
	target          string
	client          *publishTargetClient
	request         pub.Request
	trust           *publicationTrustSnapshot
	desiredManifest string
	planPath        string
	unchanged       bool
	restore         *restoreAuditSource
}

func buildTargetPublication(ctx context.Context, cfg *config.Config, canonical *state.Store, repos []config.Repo, prepared preparedPublication, target string, desiredCommit plumbing.Hash, txDir string, values commonFlags) (targetPublication, error) {
	publication := targetPublication{target: target}
	prepared, err := publicationPreparedForTarget(prepared, target, txDir)
	if err != nil {
		return publication, err
	}
	if err := prepared.validateYUMOwnerVectors(); err != nil {
		return publication, fmt.Errorf("%w: %v", pub.ErrDrift, err)
	}
	if err := validateCanonicalPurgeLedgerForPublish(ctx, canonical, cfg, target); err != nil {
		return publication, err
	}
	// S0 rollback authority is entirely local and immutable. Prepare it before
	// credentials, provider clients, inventory reads, or checkpoints exist so a
	// missing/tampered carrier or parent closure produces zero provider calls.
	prepared, err = prepareRolledBackYUMCompatibilityTarget(ctx, cfg, canonical, prepared, target, txDir, values)
	if err != nil {
		return publication, err
	}
	requireBasic := prepared.view == "snapshot" || cfg.Views[prepared.view].Access == "pro"
	client, err := newPublishTargetClient(cfg, target, prepared.view, requireBasic)
	if err != nil {
		return publication, err
	}
	publication.client = client
	observation, err := observeRemoteTarget(ctx, canonical, client, target, txDir)
	if err != nil {
		return publication, err
	}
	if err := validatePublishedTargetAffinity(cfg, target, observation.parent); err != nil {
		return publication, err
	}
	observedPrepared, err := bindRolledBackYUMCompatibility(prepared, observation.parent)
	if err != nil {
		return publication, err
	}
	if prepared.compatibilityRollbackParentSHA256 != "" {
		if observation.parent == nil {
			return publication, fmt.Errorf("%w: remote target %s lost the locally committed compatibility parent", pub.ErrDrift, target)
		}
		body, canonicalErr := observation.parent.Canonical()
		if canonicalErr != nil || digestBytesCLI(body) != prepared.compatibilityRollbackParentSHA256 || !sameCompatibilityRollbackSet(prepared.compatibilityRollbacks, observedPrepared.compatibilityRollbacks) {
			return publication, errors.Join(canonicalErr, fmt.Errorf("%w: remote target %s does not reproduce the locally verified compatibility parent", pub.ErrDrift, target))
		}
	}
	prepared.compatibilityRollbacks = observedPrepared.compatibilityRollbacks
	resumeTransactionID := ""
	if observation.resumeCheckpoint != nil {
		resumeTransactionID = observation.resumeCheckpoint.TransactionID
	} else if observation.resumeLock != nil {
		resumeTransactionID = observation.resumeLock.TransactionID
	}
	if resumeTransactionID != "" {
		sourceGeneration, restoreTransaction := restoreSourceGenerationFromTransactionID(resumeTransactionID)
		switch {
		case prepared.restoreSourceGeneration != 0 && (!restoreTransaction || prepared.restoreSourceGeneration != sourceGeneration):
			if restoreTransaction {
				return publication, fmt.Errorf("%w: target %s has interrupted restore transaction %s; replay with --restore-generation %d --target %s", pub.ErrDrift, target, resumeTransactionID, sourceGeneration, target)
			}
			return publication, fmt.Errorf("%w: target %s has interrupted ordinary publication transaction %s; recover that publication before starting restore", pub.ErrDrift, target, resumeTransactionID)
		case prepared.restoreSourceGeneration == 0 && restoreTransaction:
			return publication, fmt.Errorf("%w: target %s has interrupted restore transaction %s; replay with --restore-generation %d --target %s", pub.ErrDrift, target, resumeTransactionID, sourceGeneration, target)
		}
	}
	retention := snapshotRetentionPlan{baseline: observation.oldManifestPath, expired: make(map[string]struct{})}
	if prepared.restoreSourceGeneration == 0 && (prepared.view == "stable" || prepared.view == "snapshot") {
		retention, err = planRemoteSnapshotRetention(canonical, target, observation.oldManifestPath, filepath.Join(txDir, fmt.Sprintf("retained-%s-%s.tsv", target, prepared.label())), prepared.snapshotID, cfg.State.SnapshotMaterializationMonths)
		if err != nil {
			return publication, fmt.Errorf("plan remote snapshot retention: %w", err)
		}
	}
	desiredManifest := filepath.Join(txDir, fmt.Sprintf("desired-%s-%s.tsv", target, prepared.label()))
	desiredSelection, err := publicationSelectionScopes(cfg, prepared, nil)
	if err != nil {
		return publication, err
	}
	if err := ReplaceManifestSelection(retention.baseline, prepared.manifestPath, desiredManifest, desiredSelection); err != nil {
		return publication, err
	}
	publication.desiredManifest = desiredManifest
	contentSHA, err := hashRegularPath(desiredManifest)
	if err != nil {
		return publication, err
	}
	refs, err := desiredPublicationRefs(canonical, observation.parent, cfg, repos, prepared, values, retention.expired)
	if err != nil {
		return publication, err
	}
	rpmTrust, err := loadPublicationRPMTrustSnapshot(cfg, refs)
	if err != nil {
		return publication, err
	}
	compatibility, err := desiredPublicationCompatibility(canonical, observation.parent, prepared)
	if err != nil {
		return publication, err
	}
	configSHA := publicationConfigSHAWithCompatibility(rpmTrust.ConfigSHA256, compatibility)
	if err := preflightPublicationRefsRPMPackageTrust(ctx, cfg, canonical, target, refs, compatibility, observation.parent, rpmTrust, values.workers); err != nil {
		return publication, fmt.Errorf("%w: target %s reachable RPM package trust: %v", pub.ErrVerification, target, err)
	}
	repositoryKeySHA, err := desiredPublicationRepositoryKeySHA(cfg, target, prepared, refs, observation.parent)
	if err != nil {
		return publication, err
	}
	rawChangedPaths, err := DiffChangedPaths(observation.oldManifestPath, desiredManifest)
	if err != nil {
		return publication, err
	}
	parentGeneration := uint64(0)
	if observation.parent != nil {
		parentGeneration = observation.parent.Generation
	}
	changedYUM := changedYUMProjections(prepared, rawChangedPaths)
	if prepared.restoreSourceGeneration != 0 {
		// Restore exact-replaces every reconstructed YUM root. Even when its bytes
		// equal the current parent, the forward plan must carry the immutable
		// generation metadata, raw alias pair, and routed channel as one closure.
		for _, projection := range prepared.projections {
			if projection.repo.Type == "yum" && !prepared.restoreRemovedProjectionRoots[projection.sourceRoot] {
				for _, channelProjection := range prepared.yumChannelProjections(projection) {
					changedYUM[channelRemoteKey(prepared.view, channelProjection)] = true
				}
			}
		}
	}
	// A latest scope may have been imported from an already-serving legacy
	// bucket before another intent advanced the target generation. Raw YUM
	// repodata proves only the legacy client path, not SOW's immutable
	// generation namespace or generation-pinned channel. Force repodata only
	// for selected leaves whose latest channel has never been established;
	// package payloads remain unchanged and therefore are not retransferred.
	if prepared.view == "latest" {
		parentChannels := make(map[string]struct{})
		if observation.parent != nil {
			for _, channel := range observation.parent.Channels {
				if channel.View == prepared.view {
					parentChannels[channel.RemoteKey] = struct{}{}
				}
			}
		}
		for _, projection := range prepared.projections {
			if projection.repo.Type == "yum" && !projection.isYUMCompatibilityRollback() {
				for _, channelProjection := range prepared.yumChannelProjections(projection) {
					key := channelRemoteKey(prepared.view, channelProjection)
					if _, established := parentChannels[key]; !established {
						changedYUM[key] = true
					}
				}
			}
		}
	}
	if prepared.view == "snapshot" {
		changedYUM = nil
	}
	channels, err := desiredPublicationChannels(observation.parent, prepared, parentGeneration+1, changedYUM, compatibility)
	if err != nil {
		return publication, err
	}
	if observation.resumeGeneration == nil && observation.resumeCheckpoint == nil && observation.resumeLock == nil && len(retention.deletes) == 0 && generationStateEqual(observation.parent, configSHA, repositoryKeySHA, contentSHA, refs, compatibility, channels) {
		publication.unchanged = true
		return publication, nil
	}
	generation := pub.TargetGeneration{
		Schema: pub.TargetGenerationSchema, Target: pub.TargetName(target),
		Generation: parentGeneration + 1, ParentGeneration: parentGeneration,
		DesiredCommit: desiredCommit.String(), IntentView: prepared.view, IntentSnapshot: prepared.snapshotID, ConfigSHA256: configSHA, RepositoryKeySHA256: repositoryKeySHA,
		Refs: refs, Compatibility: compatibility, Channels: channels, ContentManifestSHA256: contentSHA,
	}
	if observation.resumeGeneration != nil {
		generation = *observation.resumeGeneration
	}
	if observation.resumeCheckpoint != nil && observation.resumeGeneration == nil {
		generation.DesiredCommit = observation.resumeCheckpoint.DesiredCommit
		if !prepared.intentMatches(observation.resumeCheckpoint.IntentView, observation.resumeCheckpoint.IntentSnapshot) {
			return publication, fmt.Errorf("%w: interrupted target %s publication belongs to %s/%s, not %s", pub.ErrDrift, target, observation.resumeCheckpoint.IntentView, observation.resumeCheckpoint.IntentSnapshot, prepared.label())
		}
	}
	if observation.resumeLock != nil && !prepared.intentMatches(observation.resumeLock.IntentView, observation.resumeLock.IntentSnapshot) {
		return publication, fmt.Errorf("%w: interrupted COS target %s publication belongs to %s/%s, not %s", pub.ErrDrift, target, observation.resumeLock.IntentView, observation.resumeLock.IntentSnapshot, prepared.label())
	}
	if observation.resumeLock != nil {
		if desiredCommit, bound := publicationDesiredCommitFromTransactionID(observation.resumeLock.TransactionID); bound {
			generation.DesiredCommit = desiredCommit.String()
		}
	}
	if err := validateDesiredActiveYUMCompatibilityCompleteness(cfg, canonical, target, generation, desiredCommit); err != nil {
		return publication, fmt.Errorf("%w: desired target %s compatibility vector is incomplete: %v", pub.ErrDrift, target, err)
	}
	if err := validateGenerationCompatibility(cfg, canonical, target, generation); err != nil {
		return publication, fmt.Errorf("%w: desired target %s compatibility vector is invalid: %v", pub.ErrDrift, target, err)
	}
	canonicalGeneration, err := generation.Canonical()
	if err != nil {
		return publication, err
	}
	if !prepared.intentMatches(generation.IntentView, generation.IntentSnapshot) || generation.ConfigSHA256 != configSHA || generation.RepositoryKeySHA256 != repositoryKeySHA || generation.ContentManifestSHA256 != contentSHA || !sameRefStates(generation.Refs, refs) || !sameCompatibilityStates(generation.Compatibility, compatibility) || !sameChannelStates(generation.Channels, channels) || generation.ParentGeneration != parentGeneration || generation.Generation != parentGeneration+1 {
		transactionID := ""
		if observation.resumeCheckpoint != nil {
			transactionID = observation.resumeCheckpoint.TransactionID
		} else if observation.resumeLock != nil {
			transactionID = observation.resumeLock.TransactionID
		}
		if sourceGeneration, restore := restoreSourceGenerationFromTransactionID(transactionID); restore {
			return publication, fmt.Errorf("%w: resumed target %s generation belongs to restore transaction %s; replay with --restore-generation %d --target %s", pub.ErrDrift, target, transactionID, sourceGeneration, target)
		}
		return publication, fmt.Errorf("%w: resumed target %s generation no longer matches local desired state transaction=%s", pub.ErrDrift, target, transactionID)
	}
	transactionID := fmt.Sprintf("sow-%s-%020d-head-%s-%s", target, generation.Generation, generation.DesiredCommit, digestBytesCLI(canonicalGeneration)[:16])
	if prepared.restoreSourceGeneration != 0 {
		transactionID = fmt.Sprintf("sow-restore-%s-%020d-from-%020d-head-%s-%s", target, generation.Generation, prepared.restoreSourceGeneration, generation.DesiredCommit, digestBytesCLI(canonicalGeneration)[:16])
	}
	updatedAt, err := canonical.CommitTime(plumbing.NewHash(generation.DesiredCommit))
	if err != nil {
		return publication, err
	}
	updatedAt = updatedAt.UTC().Truncate(time.Second)
	if observation.resumeCheckpoint != nil {
		checkpoint := observation.resumeCheckpoint
		if checkpoint.GenerationSHA256 != digestBytesCLI(canonicalGeneration) || checkpoint.ContentManifestSHA256 != contentSHA || checkpoint.Generation != generation.Generation || checkpoint.ParentGeneration != generation.ParentGeneration {
			if sourceGeneration, restore := restoreSourceGenerationFromTransactionID(checkpoint.TransactionID); restore {
				return publication, fmt.Errorf("%w: target %s checkpoint belongs to restore transaction %s; replay with --restore-generation %d --target %s", pub.ErrDrift, target, checkpoint.TransactionID, sourceGeneration, target)
			}
			return publication, fmt.Errorf("%w: remote target %s checkpoint does not identify the reconstructed generation", pub.ErrDrift, target)
		}
		transactionID = checkpoint.TransactionID
		updatedAt, err = time.Parse(time.RFC3339Nano, checkpoint.UpdatedAt)
		if err != nil {
			return publication, fmt.Errorf("decode resumed checkpoint time: %w", err)
		}
	}
	if observation.resumeLock != nil {
		lock := observation.resumeLock
		if lock.GenerationSHA256 != digestBytesCLI(canonicalGeneration) || lock.Generation != generation.Generation || lock.ParentGeneration != generation.ParentGeneration {
			if sourceGeneration, restore := restoreSourceGenerationFromTransactionID(lock.TransactionID); restore {
				return publication, fmt.Errorf("%w: target %s lock belongs to restore transaction %s; replay with --restore-generation %d --target %s", pub.ErrDrift, target, lock.TransactionID, sourceGeneration, target)
			}
			return publication, fmt.Errorf("%w: COS target %s lock does not identify the reconstructed generation", pub.ErrDrift, target)
		}
		transactionID = lock.TransactionID
		updatedAt, err = time.Parse(time.RFC3339Nano, lock.UpdatedAt)
		if err != nil {
			return publication, fmt.Errorf("decode resumed COS lock time: %w", err)
		}
	}
	planBaseline := filepath.Join(txDir, fmt.Sprintf("plan-old-%s-%s.tsv", target, prepared.label()))
	forcedYUMScopes := changedYUMMetadataScopes(prepared, changedYUM)
	introducedScopes, err := unpublishedLatestProjectionScopes(observation.parent, prepared)
	if err != nil {
		return publication, err
	}
	introducedSet := make(map[string]struct{}, len(introducedScopes))
	for _, scope := range introducedScopes {
		introducedSet[scope] = struct{}{}
	}
	planSelection, err := publicationSelectionScopes(cfg, prepared, introducedSet)
	if err != nil {
		return publication, err
	}
	for _, scope := range forcedYUMScopes {
		covered := false
		for _, replaced := range planSelection.Replace {
			if scope == replaced || strings.HasPrefix(scope, strings.TrimSuffix(replaced, "/")+"/") {
				covered = true
				break
			}
		}
		if !covered {
			planSelection.Replace = append(planSelection.Replace, scope)
		}
	}
	if err := DropManifestSelection(observation.oldManifestPath, prepared.manifestPath, planBaseline, planSelection); err != nil {
		return publication, err
	}
	changedPaths, err := DiffChangedPaths(planBaseline, desiredManifest)
	if err != nil {
		return publication, err
	}
	stablePools, err := resolveStablePublicationPools(canonical, cfg, prepared, changedPaths)
	if err != nil {
		return publication, err
	}
	oldFile, err := os.Open(planBaseline)
	if err != nil {
		return publication, err
	}
	desiredFile, err := os.Open(desiredManifest)
	if err != nil {
		oldFile.Close()
		return publication, err
	}
	classifier := publicationClassifier{view: prepared.view, snapshotID: prepared.snapshotID, generation: generation.Generation, projections: prepared.projections, stablePools: stablePools}
	plan, planErr := pub.BuildPlan(oldFile, desiredFile, classifier.classify)
	closeErr := errors.Join(oldFile.Close(), desiredFile.Close())
	if planErr != nil || closeErr != nil {
		return publication, errors.Join(planErr, closeErr)
	}
	if err := augmentPublicationPlan(cfg, target, prepared, generation, txDir, values.recover, classifier, &plan); err != nil {
		return publication, err
	}
	if err := markAdoptedImmutableObjects(canonical, target, observation.oldManifestPath, &plan); err != nil {
		return publication, err
	}
	if prepared.restoreSourceGeneration != 0 {
		sourceCommit := plumbing.NewHash(prepared.restoreSourceCommit)
		if sourceCommit.IsZero() {
			return publication, fmt.Errorf("%w: restore source commit is invalid", pub.ErrDrift)
		}
		if err := markHistoricallyAdoptedImmutableObjects(canonical, target, sourceCommit, prepared.restoreSourceGeneration, &plan); err != nil {
			return publication, err
		}
	}
	if err := augmentAuthorizedRemoteDeletes(canonical, prepared, classifier, observation.oldManifestPath, desiredManifest, &plan); err != nil {
		return publication, fmt.Errorf("plan authorized remote deletions: %w", err)
	}
	if err := augmentRemovedYUMChannelDeletes(canonical, target, prepared, observation.parent, generation.Channels, &plan); err != nil {
		return publication, fmt.Errorf("plan removed YUM channels: %w", err)
	}
	if err := augmentRolledBackCompatibilityDeletes(canonical, target, prepared, observation.parent, observation.oldManifestPath, &plan); err != nil {
		return publication, fmt.Errorf("plan rolled-back YUM compatibility routes: %w", err)
	}
	if err := localizeIsolatedPublicationSources(&plan, classifier, prepared.restoreSourceGeneration != 0); err != nil {
		return publication, err
	}
	if prepared.restoreSourceGeneration != 0 {
		publication.restore = &restoreAuditSource{
			Generation: prepared.restoreSourceGeneration,
			SHA256:     prepared.restoreSourceSHA256,
			PlanSHA256: prepared.restoreSourcePlanSHA256,
			Commit:     prepared.restoreSourceCommit,
			Refs:       restoreRefStateSlice(prepared.refOverrides),
		}
	}
	plan.Deletes = append(plan.Deletes, retention.deletes...)
	cdnBase := cfg.Targets[target].CDN.BaseURL
	if prepared.view == "beta" {
		cdnBase = cfg.Targets[target].CDN.BetaBaseURL
	}
	plan, err = plan.WithCDN(cdnBase)
	if err != nil {
		return publication, err
	}
	if err := validateRolledBackCompatibilityPublicationPlan(prepared, plan); err != nil {
		return publication, fmt.Errorf("%w: rolled-back compatibility publication closure: %v", pub.ErrVerification, err)
	}
	if err := validateDesiredCompatibilityPublicationPlan(canonical, desiredCommit, generation, plan); err != nil {
		return publication, fmt.Errorf("%w: desired compatibility publication closure: %v", pub.ErrVerification, err)
	}
	if len(plan.Objects) == 0 {
		negativeOnly, negativeErr := negativeOnlyPublicationAllowed(plan)
		if negativeErr != nil {
			return publication, negativeErr
		}
		if negativeOnly {
			// A pure asset removal has complete exact storage/CDN negative
			// closure for every authorized deletion, so no positive probe exists.
		} else if len(plan.Deletes) == 0 && (observation.parent == nil || observation.parent.ContentManifestSHA256 != contentSHA || len(introducedScopes) != 0) {
			return publication, fmt.Errorf("%w: a publication with no changed objects cannot prove changed remote content", pub.ErrVerification)
		} else {
			excluded := make(map[string]struct{}, len(plan.VerifyAbsent))
			for _, expectation := range plan.VerifyAbsent {
				excluded[expectation.URL] = struct{}{}
			}
			probes, probeErr := previousIntentCDNProbes(canonical, target, prepared, excluded)
			if probeErr != nil {
				return publication, probeErr
			}
			plan.Probes = probes
		}
	}
	planBody, err := plan.Canonical()
	if err != nil {
		return publication, err
	}
	planPath := filepath.Join(txDir, fmt.Sprintf("plan-%s-%s.json", target, prepared.label()))
	if err := writeExclusiveBytes(planPath, planBody); err != nil {
		return publication, err
	}
	publication.planPath = planPath
	publication.request = pub.Request{
		TransactionID: transactionID, Generation: generation, Plan: plan,
		Expected: observation.expected, UpdatedAt: updatedAt,
	}
	publication.trust, err = capturePublicationTrust(generation, rpmTrust)
	if err != nil {
		return publication, fmt.Errorf("capture publication trust: %w", err)
	}
	return publication, nil
}

// markAdoptedImmutableObjects upgrades only immutable plan entries that are
// already named by the target's old content baseline and by a complete,
// separately byte-verified remote inventory. The persistent class makes the
// saga and later L2 audits re-read origin bytes instead of healing, uploading,
// or trusting legacy objects that lack sow-sha256 metadata.
func markAdoptedImmutableObjects(canonical *state.Store, target, oldManifestPath string, plan *pub.Plan) error {
	if canonical == nil || plan == nil {
		return errors.New("adopted immutable classification requires canonical state and a plan")
	}
	type candidate struct {
		index    int
		baseline bool
		found    bool
	}
	candidates := make(map[string]*candidate)
	for index, object := range plan.Objects {
		if object.Class != pub.ObjectImmutable {
			continue
		}
		if _, duplicate := candidates[object.RemoteKey]; duplicate {
			return fmt.Errorf("%w: duplicate immutable remote key %s", pub.ErrDrift, object.RemoteKey)
		}
		candidates[object.RemoteKey] = &candidate{index: index}
	}
	if len(candidates) == 0 {
		return nil
	}
	baseline, err := openRegularManifest(oldManifestPath)
	if err != nil {
		return fmt.Errorf("open adopted content baseline: %w", err)
	}
	baselineReader := manifest.NewReader(baseline)
	baselineCount := 0
	for {
		entry, readErr := baselineReader.Next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_ = baseline.Close()
			return fmt.Errorf("%w: read adopted content baseline: %v", pub.ErrDrift, readErr)
		}
		item, exists := candidates[entry.Path]
		if !exists {
			continue
		}
		object := plan.Objects[item.index]
		if entry.Size != object.Size || entry.HashString() != object.SHA256 {
			_ = baseline.Close()
			return fmt.Errorf("%w: immutable remote key %s conflicts with the target content baseline", pub.ErrDrift, entry.Path)
		}
		item.baseline = true
		baselineCount++
	}
	if closeErr := baseline.Close(); closeErr != nil {
		return closeErr
	}
	if baselineCount == 0 {
		return nil
	}
	coverage, exists, err := readOptionalCanonical(canonical, remoteStatePath(target, "inventory.coverage"))
	if err != nil {
		return fmt.Errorf("%w: read adopted remote inventory coverage: %v", pub.ErrDrift, err)
	}
	if !exists || string(coverage) != remoteInventoryComplete {
		return nil
	}
	inventory, inventoryExists, err := openOptionalCanonical(canonical, remoteStatePath(target, "inventory.tsv"))
	if err != nil {
		return fmt.Errorf("%w: open adopted remote inventory: %v", pub.ErrDrift, err)
	}
	if !inventoryExists {
		return fmt.Errorf("%w: complete adopted remote inventory manifest is missing", pub.ErrDrift)
	}
	inventoryReader := manifest.NewReader(inventory)
	for {
		entry, readErr := inventoryReader.Next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_ = inventory.Close()
			return fmt.Errorf("%w: read adopted remote inventory: %v", pub.ErrDrift, readErr)
		}
		item, exists := candidates[entry.Path]
		if !exists || !item.baseline {
			continue
		}
		object := plan.Objects[item.index]
		if entry.Size != object.Size || entry.HashString() != object.SHA256 {
			_ = inventory.Close()
			return fmt.Errorf("%w: adopted immutable %s disagrees with complete remote inventory", pub.ErrDrift, entry.Path)
		}
		item.found = true
	}
	if closeErr := inventory.Close(); closeErr != nil {
		return closeErr
	}
	for key, item := range candidates {
		if !item.baseline {
			continue
		}
		if !item.found {
			return fmt.Errorf("%w: adopted immutable %s is missing from complete remote inventory", pub.ErrDrift, key)
		}
		plan.Objects[item.index].Class = pub.ObjectAdoptedImmutable
	}
	return nil
}

// unpublishedLatestProjectionScopes returns only selected source roots whose
// exact latest ref vector is absent from the cumulative target generation.
// This prevents a partial-selector migration from borrowing an already
// published repository's CDN probe as evidence for a newly introduced scope.
func unpublishedLatestProjectionScopes(parent *pub.TargetGeneration, prepared preparedPublication) ([]string, error) {
	if prepared.view != "latest" {
		return nil, nil
	}
	published := make(map[string]struct{})
	publishedChannels := make(map[string]struct{})
	if parent != nil {
		for _, ref := range parent.Refs {
			published[ref.Name] = struct{}{}
		}
		for _, channel := range parent.Channels {
			publishedChannels[channel.RemoteKey] = struct{}{}
		}
	}
	var scopes []string
	for _, projection := range prepared.projections {
		if projection.isYUMCompatibilityRollback() {
			continue
		}
		if projection.compatibilityID != "" {
			// The source latest ref can predate introduction of the old-URL
			// projection. Only the independent compatibility channel proves this
			// exact public scope was already published.
			if _, exists := publishedChannels[channelRemoteKey(prepared.view, projection)]; !exists {
				scopes = append(scopes, projection.sourceRoot)
			}
			continue
		}
		var leaves []viewLeaf
		switch projection.repo.Type {
		case "asset":
			leaves = []viewLeaf{{repo: projection.repo, os: "all", arch: "all"}}
		case "yum":
			leaves = prepared.yumLeavesForProjection(projection)
		case "apt":
			for _, suite := range projection.repo.APT.Suites {
				for _, arch := range projection.repo.Arches {
					leaves = append(leaves, viewLeaf{repo: projection.repo, os: suite, arch: arch})
				}
			}
		default:
			return nil, fmt.Errorf("%w: unsupported publication projection type %s", pub.ErrDrift, projection.repo.Type)
		}
		missing := len(leaves) == 0
		for _, leaf := range leaves {
			ref, err := state.ViewRef(prepared.view, leaf.repo.ID, leaf.os, leaf.arch)
			if err != nil {
				return nil, err
			}
			if _, exists := published[ref.String()]; !exists {
				missing = true
				break
			}
		}
		if missing {
			scopes = append(scopes, projection.sourceRoot)
		}
	}
	sort.Strings(scopes)
	return scopes, nil
}

func previousIntentCDNProbes(canonical *state.Store, target string, prepared preparedPublication, excluded map[string]struct{}) ([]pub.VerifyObject, error) {
	generationPath, err := remoteIntentStatePath(target, prepared.view, prepared.snapshotID, "generation.json")
	if err != nil {
		return nil, err
	}
	checkpointPath, _ := remoteIntentStatePath(target, prepared.view, prepared.snapshotID, "checkpoint.json")
	planPath, _ := remoteIntentStatePath(target, prepared.view, prepared.snapshotID, "plan.json")
	history, err := canonical.History()
	if err != nil {
		return nil, err
	}
	leaves := preparedL3CoverageLeaves(prepared)
	uncovered := make(map[string]struct{}, len(leaves))
	for _, leaf := range leaves {
		uncovered[l3LeafKey(leaf)] = struct{}{}
	}
	liveness := make(map[string]bool, len(excluded))
	for rawURL := range excluded {
		liveness[rawURL] = false
	}
	seenURL := make(map[string]struct{})
	var selected []pub.VerifyObject
	for _, commit := range history {
		generationBody, generationExists, readErr := readCanonicalBytesAt(canonical, commit, generationPath, 16<<20)
		if readErr != nil {
			return nil, readErr
		}
		checkpointBody, checkpointExists, readErr := readCanonicalBytesAt(canonical, commit, checkpointPath, 16<<20)
		if readErr != nil {
			return nil, readErr
		}
		planBody, planExists, readErr := readCanonicalBytesAt(canonical, commit, planPath, 64<<20)
		if readErr != nil {
			return nil, readErr
		}
		if !generationExists || !checkpointExists || !planExists {
			continue
		}
		generation, generationErr := pub.DecodeTargetGeneration(generationBody)
		checkpoint, checkpointErr := pub.DecodeCheckpoint(checkpointBody)
		plan, planErr := pub.DecodePlan(planBody)
		if generationErr != nil || checkpointErr != nil || planErr != nil || string(generation.Target) != target ||
			!prepared.intentMatches(generation.IntentView, generation.IntentSnapshot) ||
			checkpoint.Phase != pub.PhaseCheckpointCommitted || checkpoint.Generation != generation.Generation ||
			checkpoint.ParentGeneration != generation.ParentGeneration || checkpoint.DesiredCommit != generation.DesiredCommit ||
			checkpoint.GenerationSHA256 != digestBytesCLI(generationBody) || checkpoint.ContentManifestSHA256 != generation.ContentManifestSHA256 ||
			!pub.SamePublicationIntent(checkpoint.IntentView, checkpoint.IntentSnapshot, generation.IntentView, generation.IntentSnapshot) {
			continue
		}
		candidates := historicalLiveProbeCandidates(plan, liveness)
		if len(candidates) == 0 {
			continue
		}
		for _, candidate := range candidates {
			if _, duplicate := seenURL[candidate.URL]; duplicate {
				continue
			}
			seenURL[candidate.URL] = struct{}{}
			if len(leaves) == 0 {
				return []pub.VerifyObject{candidate}, nil
			}
			_, closes := l3ExpectationSelection(candidate.URL, leaves, prepared.view, prepared.snapshotID)
			useful := false
			for _, key := range closes {
				if _, needed := uncovered[key]; needed {
					useful = true
				}
			}
			if !useful {
				continue
			}
			selected = append(selected, candidate)
			for _, key := range closes {
				delete(uncovered, key)
			}
			if len(uncovered) == 0 {
				sort.Slice(selected, func(i, j int) bool { return selected[i].URL < selected[j].URL })
				return selected, nil
			}
		}
	}
	if len(uncovered) != 0 {
		missing := make([]string, 0, len(uncovered))
		for key := range uncovered {
			missing = append(missing, strings.ReplaceAll(key, "\x00", "/"))
		}
		sort.Strings(missing)
		return nil, fmt.Errorf("%w: zero-object publication has no prior committed, non-deleted CDN expectation covering %s", pub.ErrVerification, strings.Join(missing, ", "))
	}
	return nil, fmt.Errorf("%w: zero-object publication has no prior committed, non-deleted CDN expectation to revalidate", pub.ErrVerification)
}

// historicalLiveProbeCandidates consumes committed intent plans newest first.
// The first event observed for one CDN URL is therefore authoritative for its
// current liveness: a newer VerifyAbsent tombstone hides every older positive
// expectation, while an even newer explicit positive can legitimately revive
// the URL. This prevents a zero-object generation from reaching behind a
// deletion and turning a stale object into its success probe.
func historicalLiveProbeCandidates(plan pub.Plan, liveness map[string]bool) []pub.VerifyObject {
	if liveness == nil {
		liveness = make(map[string]bool)
	}
	for _, absent := range plan.VerifyAbsent {
		if _, known := liveness[absent.URL]; !known {
			liveness[absent.URL] = false
		}
	}
	candidates := append([]pub.VerifyObject(nil), plan.Probes...)
	candidates = append(candidates, plan.Verify...)
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].URL < candidates[j].URL })
	result := make([]pub.VerifyObject, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if _, duplicate := seen[candidate.URL]; duplicate {
			continue
		}
		seen[candidate.URL] = struct{}{}
		live, known := liveness[candidate.URL]
		if !known {
			live = true
			liveness[candidate.URL] = true
		}
		if live {
			result = append(result, candidate)
		}
	}
	return result
}

// preparedL3CoverageLeaves returns the target-filtered logical coordinates
// whose CDN routes a zero-object transaction must still revalidate. Current
// preparation paths populate routeLeaves exactly; the projection fallback is
// retained for audited historical restore records created before that field
// existed in runtime preparation state.
func preparedL3CoverageLeaves(prepared preparedPublication) []viewLeaf {
	byKey := make(map[string]viewLeaf)
	for _, leaf := range prepared.routeLeaves {
		byKey[l3LeafKey(leaf)] = leaf
	}
	if len(byKey) == 0 {
		for _, projection := range prepared.projections {
			if projection.isYUMCompatibilityTrust() || projection.isYUMCompatibilityRollback() {
				continue
			}
			switch projection.repo.Type {
			case "asset":
				leaf := viewLeaf{repo: projection.repo, os: "all", arch: "all"}
				byKey[l3LeafKey(leaf)] = leaf
			case "apt":
				if projection.repo.APT == nil {
					continue
				}
				for _, suite := range projection.repo.APT.Suites {
					for _, arch := range projection.repo.Arches {
						leaf := viewLeaf{repo: projection.repo, os: suite, arch: arch}
						byKey[l3LeafKey(leaf)] = leaf
					}
				}
			case "yum":
				for _, leaf := range prepared.yumLeavesForProjection(projection) {
					byKey[l3LeafKey(leaf)] = leaf
				}
			}
		}
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	leaves := make([]viewLeaf, 0, len(keys))
	for _, key := range keys {
		leaves = append(leaves, byKey[key])
	}
	return leaves
}

func desiredPublicationRefs(canonical *state.Store, parent *pub.TargetGeneration, cfg *config.Config, repos []config.Repo, prepared preparedPublication, values commonFlags, expiredSnapshots map[string]struct{}) ([]pub.RefState, error) {
	byName := make(map[string]pub.RefState)
	if parent != nil {
		for _, ref := range parent.Refs {
			if prepared.refOverrides != nil && publicationRefMatchesIntent(ref.Name, prepared.view, prepared.snapshotID) {
				continue
			}
			if snapshotID, ok := snapshotIDFromPublicationRef(ref.Name); ok {
				if _, expired := expiredSnapshots[snapshotID]; expired {
					continue
				}
			}
			byName[ref.Name] = ref
		}
	}
	if prepared.refOverrides != nil {
		if len(prepared.refOverrides) == 0 {
			return nil, errors.New("historical restore has no canonical refs")
		}
		for name, ref := range prepared.refOverrides {
			if name != ref.Name || !publicationRefMatchesIntent(name, prepared.view, prepared.snapshotID) {
				return nil, fmt.Errorf("historical restore ref %s is outside %s", name, prepared.label())
			}
			byName[name] = ref
		}
		refs := make([]pub.RefState, 0, len(byName))
		for _, ref := range byName {
			refs = append(refs, ref)
		}
		sort.Slice(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })
		return refs, nil
	}
	selected := make(map[string]viewLeaf)
	for _, projection := range prepared.projections {
		if projection.isYUMCompatibilityTrust() || projection.isYUMCompatibilityRollback() {
			continue
		}
		switch projection.repo.Type {
		case "apt":
			for _, suite := range projection.repo.APT.Suites {
				for _, arch := range projection.repo.Arches {
					leaf := viewLeaf{repo: projection.repo, os: suite, arch: arch}
					selected[projection.repo.ID+"\x00"+suite+"\x00"+arch] = leaf
				}
			}
		case "asset":
			leaf := viewLeaf{repo: projection.repo, os: "all", arch: "all"}
			selected[projection.repo.ID+"\x00all\x00all"] = leaf
		case "yum":
			for _, leaf := range prepared.yumLeavesForProjection(projection) {
				selected[leaf.repo.ID+"\x00"+leaf.os+"\x00"+leaf.arch] = leaf
			}
		}
	}
	for _, leaf := range selected {
		var refName plumbing.ReferenceName
		var err error
		if prepared.view == "snapshot" {
			refName, err = state.SnapshotRef(prepared.snapshotID, leaf.repo.ID, leaf.os, leaf.arch)
		} else {
			refName, err = state.ViewRef(prepared.view, leaf.repo.ID, leaf.os, leaf.arch)
		}
		if err != nil {
			return nil, err
		}
		commit, exists, err := canonical.Ref(refName)
		if err != nil {
			return nil, err
		}
		if !exists {
			continue
		}
		var viewPath string
		if prepared.view == "snapshot" {
			viewPath, _ = state.SnapshotPath(prepared.snapshotID, leaf.repo.ID, leaf.os, leaf.arch)
		} else {
			viewPath, _ = state.ViewPath(prepared.view, leaf.repo.ID, leaf.os, leaf.arch)
		}
		reader, err := canonical.OpenPathAt(commit, viewPath)
		if err != nil {
			return nil, err
		}
		hash, err := hashReader(reader)
		if err != nil {
			return nil, err
		}
		byName[refName.String()] = pub.RefState{Name: refName.String(), Commit: commit.String(), ManifestSHA256: hash}
	}
	refs := make([]pub.RefState, 0, len(byName))
	for _, ref := range byName {
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })
	return refs, nil
}

func desiredPublicationCompatibility(canonical *state.Store, parent *pub.TargetGeneration, prepared preparedPublication) ([]pub.CompatibilityState, error) {
	if prepared.restoreSourceGeneration != 0 {
		result := append([]pub.CompatibilityState(nil), prepared.restoreCompatibility...)
		sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
		return result, nil
	}
	byID := make(map[string]pub.CompatibilityState)
	if parent != nil {
		for _, compatibility := range parent.Compatibility {
			byID[compatibility.ID] = compatibility
		}
	}
	for id := range prepared.compatibilityRollbacks {
		delete(byID, id)
	}
	for _, projection := range prepared.projections {
		if !projection.isYUMCompatibility() {
			continue
		}
		witnessPath, err := state.YUMCompatibilityProjectionPath(projection.compatibilityID)
		if err != nil {
			return nil, err
		}
		body, exists, err := readOptionalCanonical(canonical, witnessPath)
		if err != nil || !exists {
			return nil, errors.Join(err, fmt.Errorf("YUM compatibility witness %s is missing", projection.compatibilityID))
		}
		witness, err := decodeYUMCompatibilityWitness(body)
		if err != nil {
			return nil, err
		}
		if witness.ID != projection.compatibilityID || witness.Root != projection.remotePathRoot() {
			return nil, fmt.Errorf("YUM compatibility projection %s disagrees with its witness", projection.compatibilityID)
		}
		head, err := canonical.HeadHash()
		if err != nil || head.IsZero() {
			return nil, errors.Join(err, errors.New("canonical HEAD is unavailable for YUM compatibility publication"))
		}
		witnessBlob, exists, err := canonical.BlobIdentityAt(head, witnessPath)
		if err != nil || !exists || witnessBlob.Size != int64(len(body)) {
			return nil, errors.Join(err, fmt.Errorf("YUM compatibility witness %s has no exact Git identity", witness.ID))
		}
		manifestPath, _ := state.YUMCompatibilityManifestPath(witness.ID)
		manifestBlob, exists, err := canonical.BlobIdentityAt(head, manifestPath)
		if err != nil || !exists || manifestBlob.Hash.String() != witness.PayloadManifestGit || manifestBlob.Size != witness.PayloadManifestLen {
			return nil, errors.Join(err, fmt.Errorf("YUM compatibility payload manifest %s has no exact Git identity", witness.ID))
		}
		trustPath, _ := state.YUMCompatibilityPackageTrustPath(witness.ID)
		trustBlob, exists, err := canonical.BlobIdentityAt(head, trustPath)
		if err != nil || !exists || trustBlob.Hash.String() != witness.PackageTrustGit || trustBlob.Size != witness.PackageTrustLen {
			return nil, errors.Join(err, fmt.Errorf("YUM compatibility package trust %s has no exact Git identity", witness.ID))
		}
		repositoryTrustPath, _ := state.YUMCompatibilityRepositoryTrustPath(witness.ID)
		repositoryTrustBlob, exists, err := canonical.BlobIdentityAt(head, repositoryTrustPath)
		if err != nil || !exists || repositoryTrustBlob.Size < 1 {
			return nil, errors.Join(err, fmt.Errorf("YUM compatibility repository trust %s has no exact Git identity", witness.ID))
		}
		repositoryTrustSHA, exists, err := hashCanonicalPathOptionalAt(canonical, head, repositoryTrustPath)
		if err != nil || !exists {
			return nil, errors.Join(err, fmt.Errorf("YUM compatibility repository trust %s cannot be hashed", witness.ID))
		}
		freezeRef, _ := state.YUMCompatibilityRef(witness.ID)
		freezeCommit, exists, err := canonical.Ref(freezeRef)
		if err != nil || !exists || freezeCommit.IsZero() {
			return nil, errors.Join(err, fmt.Errorf("YUM compatibility freeze ref %s is missing", freezeRef))
		}
		candidateManifestPath, _ := state.YUMCompatibilityCandidateManifestPath(witness.ID)
		candidateManifestBlob, exists, err := canonical.BlobIdentityAt(head, candidateManifestPath)
		if err != nil || !exists || candidateManifestBlob.Size < 1 {
			return nil, errors.Join(err, fmt.Errorf("YUM compatibility candidate manifest %s is missing", witness.ID))
		}
		candidateManifestSHA, exists, err := hashCanonicalPathOptionalAt(canonical, head, candidateManifestPath)
		if err != nil || !exists {
			return nil, errors.Join(err, fmt.Errorf("YUM compatibility candidate manifest %s cannot be hashed", witness.ID))
		}
		candidateReceiptPath, _ := state.YUMCompatibilityCandidateReceiptPath(witness.ID)
		candidateReceiptBody, exists, err := readOptionalCanonical(canonical, candidateReceiptPath)
		if err != nil || !exists || len(candidateReceiptBody) == 0 || len(candidateReceiptBody) > maximumYUMCompatibilityWitnessBytes {
			return nil, errors.Join(err, fmt.Errorf("YUM compatibility candidate receipt %s is missing or too large", witness.ID))
		}
		candidateReceipt, err := decodeYUMCompatibilityCandidate(candidateReceiptBody)
		if err != nil || candidateReceipt.ID != witness.ID || candidateReceipt.Root != witness.Root || candidateReceipt.Carrier != witness.Carrier || candidateReceipt.OwnerRepo != witness.SourceRepo ||
			candidateReceipt.SourceRef != witness.SourceRef || candidateReceipt.SourceCommit != witness.SourceCommit || candidateReceipt.SourceManifestSHA256 != witness.SourceManifestSHA || candidateReceipt.SourceManifestGit != witness.SourceManifestGit || candidateReceipt.SourceManifestSize != witness.SourceManifestLen ||
			candidateReceipt.AdoptionSHA256 != witness.AdoptionSHA || candidateReceipt.AdoptionGit != witness.AdoptionGit || candidateReceipt.AdoptionSize != witness.AdoptionLen ||
			candidateReceipt.PackageTrustSHA256 != witness.PackageTrustSHA || candidateReceipt.PackageTrustGit != witness.PackageTrustGit || candidateReceipt.PackageTrustSize != witness.PackageTrustLen ||
			candidateReceipt.RepositoryTrustSHA256 != repositoryTrustSHA || candidateReceipt.RepositoryTrustGit != repositoryTrustBlob.Hash.String() || candidateReceipt.RepositoryTrustSize != repositoryTrustBlob.Size ||
			candidateReceipt.CandidateManifestSHA256 != candidateManifestSHA || candidateReceipt.CandidateManifestGit != candidateManifestBlob.Hash.String() || candidateReceipt.CandidateManifestSize != candidateManifestBlob.Size {
			return nil, errors.Join(err, fmt.Errorf("YUM compatibility candidate receipt %s differs from frozen witness/tree", witness.ID))
		}
		candidateReceiptBlob, exists, err := canonical.BlobIdentityAt(head, candidateReceiptPath)
		if err != nil || !exists || candidateReceiptBlob.Size != int64(len(candidateReceiptBody)) {
			return nil, errors.Join(err, fmt.Errorf("YUM compatibility candidate receipt %s has no exact Git identity", witness.ID))
		}
		for frozenPath, want := range map[string]state.BlobIdentity{
			candidateManifestPath: candidateManifestBlob,
			candidateReceiptPath:  candidateReceiptBlob,
			repositoryTrustPath:   repositoryTrustBlob,
		} {
			frozenBlob, frozenExists, frozenErr := canonical.BlobIdentityAt(freezeCommit, frozenPath)
			if frozenErr != nil || !frozenExists || frozenBlob != want {
				return nil, errors.Join(frozenErr, fmt.Errorf("YUM compatibility freeze %s does not preserve %s", freezeRef, frozenPath))
			}
		}
		cutoverPath, _ := state.YUMCompatibilityCutoverPath(witness.ID)
		cutoverBody, cutoverExists, err := readOptionalCanonical(canonical, cutoverPath)
		if err != nil {
			return nil, err
		}
		active, err := publicationYUMCompatibilityActiveAt(canonical, head, witness.ID)
		if err != nil || !active || !cutoverExists {
			return nil, errors.Join(err, fmt.Errorf("YUM compatibility projection %s has no active S3 cutover ledger", witness.ID))
		}
		var cutoverSHA, cutoverGit string
		var cutoverSize int64
		if cutoverExists {
			cutoverBlob, blobExists, blobErr := canonical.BlobIdentityAt(head, cutoverPath)
			if blobErr != nil || !blobExists || len(cutoverBody) == 0 || cutoverBlob.Size != int64(len(cutoverBody)) {
				return nil, errors.Join(blobErr, fmt.Errorf("YUM compatibility cutover identity %s has no exact Git identity", witness.ID))
			}
			cutoverSHA, cutoverGit, cutoverSize = digestBytesCLI(cutoverBody), cutoverBlob.Hash.String(), cutoverBlob.Size
		}
		byID[witness.ID] = pub.CompatibilityState{
			ID: witness.ID, Root: witness.Root, Carrier: witness.Carrier, OwnerRepo: witness.SourceRepo,
			SourceRef: witness.SourceRef, SourceCommit: witness.SourceCommit, FreezeRef: freezeRef.String(), FreezeCommit: freezeCommit.String(), SourceRoot: witness.SourceRoot,
			SourceManifestSHA256: witness.SourceManifestSHA, SourceManifestGit: witness.SourceManifestGit, SourceManifestSize: witness.SourceManifestLen,
			AdoptionSHA256: witness.AdoptionSHA, AdoptionGit: witness.AdoptionGit, AdoptionSize: witness.AdoptionLen,
			WitnessSHA256: digestBytesCLI(body), WitnessGit: witnessBlob.Hash.String(), WitnessSize: witnessBlob.Size,
			PayloadManifestSHA256: witness.PayloadManifestSHA, PayloadManifestGit: manifestBlob.Hash.String(), PayloadManifestSize: manifestBlob.Size,
			PackageTrustSHA256: witness.PackageTrustSHA, PackageTrustGit: trustBlob.Hash.String(), PackageTrustSize: trustBlob.Size,
			CandidateManifestSHA256: candidateManifestSHA, CandidateManifestGit: candidateManifestBlob.Hash.String(), CandidateManifestSize: candidateManifestBlob.Size,
			CandidateReceiptSHA256: digestBytesCLI(candidateReceiptBody), CandidateReceiptGit: candidateReceiptBlob.Hash.String(), CandidateReceiptSize: candidateReceiptBlob.Size,
			RepomdSHA256: candidateReceipt.RepomdSHA256, RepositoryKeySHA256: candidateReceipt.RepositoryKeySHA256,
			CutoverSHA256: cutoverSHA, CutoverGit: cutoverGit, CutoverSize: cutoverSize,
			RouteTarget: "compatibility", RouteRoot: witness.Root,
			ChannelRemoteKey: expectedYUMCompatibilityChannelKey(prepared.view, config.YUMCompatibilityProjection{
				ID: witness.ID, Source: config.YUMCompatibilitySource{Arch: witness.SourceArch},
			}),
		}
	}
	result := make([]pub.CompatibilityState, 0, len(byID))
	for _, compatibility := range byID {
		result = append(result, compatibility)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func publicationConfigSHAWithCompatibility(base string, compatibility []pub.CompatibilityState) string {
	if len(compatibility) == 0 {
		return base
	}
	hasher := sha256.New()
	_, _ = hasher.Write([]byte("sow-publication-config-with-compatibility-v2\x00" + base))
	ordered := append([]pub.CompatibilityState(nil), compatibility...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	for _, item := range ordered {
		for _, field := range []string{
			item.ID, item.Root, item.Carrier, item.OwnerRepo, item.SourceRef, item.SourceCommit, item.FreezeRef, item.FreezeCommit, item.SourceRoot,
			item.SourceManifestSHA256, fmt.Sprint(item.SourceManifestSize), item.SourceManifestGit,
			item.AdoptionSHA256, fmt.Sprint(item.AdoptionSize), item.AdoptionGit,
			item.WitnessSHA256, fmt.Sprint(item.WitnessSize), item.WitnessGit,
			item.PayloadManifestSHA256, fmt.Sprint(item.PayloadManifestSize), item.PayloadManifestGit,
			item.PackageTrustSHA256, fmt.Sprint(item.PackageTrustSize), item.PackageTrustGit,
			item.CandidateManifestSHA256, fmt.Sprint(item.CandidateManifestSize), item.CandidateManifestGit,
			item.CandidateReceiptSHA256, fmt.Sprint(item.CandidateReceiptSize), item.CandidateReceiptGit,
			item.RepomdSHA256, item.RepositoryKeySHA256,
			item.CutoverSHA256, fmt.Sprint(item.CutoverSize), item.CutoverGit,
			item.RouteTarget, item.RouteRoot, item.ChannelRemoteKey,
		} {
			_, _ = hasher.Write([]byte("\x00" + field))
		}
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func desiredPublicationRepositoryKeySHA(cfg *config.Config, target string, prepared preparedPublication, refs []pub.RefState, parent *pub.TargetGeneration) (string, error) {
	requiresTrust, err := publicationRefsRequireRepositoryTrust(cfg, refs)
	if err != nil || !requiresTrust {
		return "", err
	}
	previousKeySHA := ""
	if parent != nil {
		previousKeySHA = parent.RepositoryKeySHA256
	}
	currentKeySHA, err := repositoryTrustAnchorSHA256ForRefs(cfg, refs)
	if err != nil {
		return "", err
	}
	if preparedHasPackageProjection(prepared) {
		if prepared.repositoryKeySHA256 == "" {
			return "", fmt.Errorf("%w: package metadata was prepared without a captured repository signing identity", pub.ErrDrift)
		}
		if prepared.repositoryKeySHA256 != currentKeySHA {
			return "", fmt.Errorf("%w: gpg.public_key changed after package metadata signing; discard this transaction and retry", pub.ErrDrift)
		}
		currentKeySHA = prepared.repositoryKeySHA256
	}
	if parent != nil {
		parentRequiresTrust := previousKeySHA != ""
		if prepared.restoreSourceGeneration == 0 {
			parentRequiresTrust, err = publicationRefsRequireRepositoryTrust(cfg, parent.Refs)
			if err != nil {
				return "", err
			}
		}
		if parentRequiresTrust && previousKeySHA != currentKeySHA {
			return "", fmt.Errorf("%w: repository signing key changed for published target %s; online replacement is outside the single-key publication contract", pub.ErrDrift, target)
		}
	}
	return currentKeySHA, nil
}

func preparedHasPackageProjection(prepared preparedPublication) bool {
	for _, projection := range prepared.projections {
		if prepared.restoreRemovedProjectionRoots[projection.sourceRoot] {
			continue
		}
		if projection.isYUMCompatibilityRollback() {
			continue
		}
		if projection.repo.Type == "apt" || projection.repo.Type == "yum" {
			return true
		}
	}
	return false
}

func snapshotIDFromPublicationRef(name string) (string, bool) {
	const prefix = "refs/sow/snapshots/"
	if !strings.HasPrefix(name, prefix) {
		return "", false
	}
	remainder := strings.TrimPrefix(name, prefix)
	id, _, found := strings.Cut(remainder, "/")
	if !found || pub.ValidatePublicationIntent("snapshot", id) != nil {
		return "", false
	}
	return id, true
}

func generationStateEqual(parent *pub.TargetGeneration, configSHA, repositoryKeySHA, contentSHA string, refs []pub.RefState, compatibility []pub.CompatibilityState, channels []pub.ChannelState) bool {
	return parent != nil && parent.ConfigSHA256 == configSHA && parent.RepositoryKeySHA256 == repositoryKeySHA && parent.ContentManifestSHA256 == contentSHA && sameRefStates(parent.Refs, refs) && sameCompatibilityStates(parent.Compatibility, compatibility) && sameChannelStates(parent.Channels, channels)
}

func sameCompatibilityStates(left, right []pub.CompatibilityState) bool {
	if len(left) != len(right) {
		return false
	}
	left = append([]pub.CompatibilityState(nil), left...)
	right = append([]pub.CompatibilityState(nil), right...)
	sort.Slice(left, func(i, j int) bool { return left[i].ID < left[j].ID })
	sort.Slice(right, func(i, j int) bool { return right[i].ID < right[j].ID })
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sameRefStates(left, right []pub.RefState) bool {
	if len(left) != len(right) {
		return false
	}
	left = append([]pub.RefState(nil), left...)
	right = append([]pub.RefState(nil), right...)
	sort.Slice(left, func(i, j int) bool { return left[i].Name < left[j].Name })
	sort.Slice(right, func(i, j int) bool { return right[i].Name < right[j].Name })
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sameChannelStates(left, right []pub.ChannelState) bool {
	if len(left) != len(right) {
		return false
	}
	left = append([]pub.ChannelState(nil), left...)
	right = append([]pub.ChannelState(nil), right...)
	sort.Slice(left, func(i, j int) bool { return left[i].RemoteKey < left[j].RemoteKey })
	sort.Slice(right, func(i, j int) bool { return right[i].RemoteKey < right[j].RemoteKey })
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func changedYUMProjections(prepared preparedPublication, changedPaths []string) map[string]bool {
	changed := make(map[string]bool)
	for _, projection := range prepared.projections {
		if projection.repo.Type != "yum" || projection.isYUMCompatibilityTrust() || projection.isYUMCompatibilityRollback() {
			continue
		}
		root := strings.TrimSuffix(projection.sourceRoot, "/")
		for _, changedPath := range changedPaths {
			if changedPath == root || strings.HasPrefix(changedPath, root+"/") {
				for _, channelProjection := range prepared.yumChannelProjections(projection) {
					changed[channelRemoteKey(prepared.view, channelProjection)] = true
				}
				break
			}
		}
	}
	return changed
}

func changedYUMMetadataScopes(prepared preparedPublication, changed map[string]bool) []string {
	var scopes []string
	for _, projection := range prepared.projections {
		if prepared.restoreRemovedProjectionRoots[projection.sourceRoot] {
			// A topology-removal restore needs the parent repodata entries in
			// the diff baseline so they become evidence-bound removals. Dropping
			// the scope here would erase the very deletion proof we need.
			continue
		}
		if projection.repo.Type == "yum" && !projection.isYUMCompatibilityTrust() && !projection.isYUMCompatibilityRollback() {
			for _, channelProjection := range prepared.yumChannelProjections(projection) {
				if changed[channelRemoteKey(prepared.view, channelProjection)] {
					scopes = append(scopes, path.Join(projection.sourceRoot, "repodata"))
					break
				}
			}
		}
	}
	sort.Strings(scopes)
	return scopes
}

func desiredPublicationChannels(parent *pub.TargetGeneration, prepared preparedPublication, generation uint64, changed map[string]bool, compatibility []pub.CompatibilityState) ([]pub.ChannelState, error) {
	byKey := make(map[string]pub.ChannelState)
	rolledBack := make(map[string]struct{}, len(prepared.compatibilityRollbacks))
	for _, identity := range prepared.compatibilityRollbacks {
		rolledBack[identity.ChannelRemoteKey] = struct{}{}
	}
	if parent != nil {
		for _, channel := range parent.Channels {
			if _, remove := rolledBack[channel.RemoteKey]; remove {
				continue
			}
			if prepared.restoreSourceGeneration != 0 && channel.OS == "cross-el" {
				// Historical compatibility is an exact vector. Never retain a
				// current-parent cross-EL channel absent from the restore source.
				continue
			}
			if prepared.restoreSourceGeneration != 0 && prepared.restoreRemovedChannelKeys[channel.RemoteKey] {
				continue
			}
			byKey[channel.RemoteKey] = channel
		}
	}
	if prepared.restoreSourceGeneration != 0 {
		identities := make(map[string]pub.CompatibilityState, len(compatibility))
		for _, identity := range compatibility {
			identities[identity.ChannelRemoteKey] = identity
		}
		for _, historical := range prepared.restoreCompatibilityChannels {
			identity, exists := identities[historical.RemoteKey]
			if !exists || historical.View != "latest" || historical.Repo != identity.ID || historical.OS != "cross-el" || historical.LegacyRoot != identity.RouteRoot {
				return nil, fmt.Errorf("%w: historical compatibility channel %s has no exact frozen identity", pub.ErrDrift, historical.RemoteKey)
			}
			historical.Generation = generation
			body, err := historical.CanonicalBody()
			if err != nil {
				return nil, err
			}
			historical.BodySHA256 = digestBytesCLI(body)
			byKey[historical.RemoteKey] = historical
		}
		if len(prepared.restoreCompatibilityChannels) != len(identities) {
			return nil, fmt.Errorf("%w: historical compatibility channel vector does not bijectively match identities", pub.ErrDrift)
		}
	}
	for _, physicalProjection := range prepared.projections {
		if physicalProjection.repo.Type != "yum" || physicalProjection.isYUMCompatibilityTrust() || physicalProjection.isYUMCompatibilityRollback() {
			continue
		}
		for _, projection := range prepared.yumChannelProjections(physicalProjection) {
			remoteKey := channelRemoteKey(prepared.view, projection)
			if prepared.restoreSourceGeneration != 0 && prepared.restoreRemovedChannelKeys[remoteKey] {
				continue
			}
			if !changed[remoteKey] {
				continue
			}
			channelRoot := projection.remotePathRoot()
			if projection.isYUMCompatibility() {
				found := false
				for _, identity := range compatibility {
					if identity.ID == projection.compatibilityID && identity.ChannelRemoteKey == remoteKey {
						channelRoot, found = identity.RouteRoot, true
						break
					}
				}
				if !found {
					return nil, fmt.Errorf("%w: compatibility projection %s has no frozen publication identity", pub.ErrDrift, projection.compatibilityID)
				}
			}
			channelView := prepared.view
			if projection.isYUMCompatibility() {
				channelView = "latest"
			}
			channel := pub.ChannelState{
				View: channelView, Generation: generation, RemoteKey: remoteKey, LegacyRoot: channelRoot,
			}
			channel.Repo, channel.OS, channel.Arch = projection.channelCoordinates()
			body, err := channel.CanonicalBody()
			if err != nil {
				return nil, err
			}
			channel.BodySHA256 = digestBytesCLI(body)
			byKey[remoteKey] = channel
		}
	}
	channels := make([]pub.ChannelState, 0, len(byKey))
	for _, channel := range byKey {
		channels = append(channels, channel)
	}
	sort.Slice(channels, func(i, j int) bool { return channels[i].RemoteKey < channels[j].RemoteKey })
	return channels, nil
}

func augmentRemovedYUMChannelDeletes(canonical *state.Store, target string, prepared preparedPublication, parent *pub.TargetGeneration, desired []pub.ChannelState, plan *pub.Plan) error {
	if prepared.restoreSourceGeneration == 0 || len(prepared.restoreRemovedChannelKeys) == 0 {
		return nil
	}
	if prepared.view != "beta" && prepared.view != "latest" {
		return fmt.Errorf("%w: removed YUM channels are allowed only for beta/latest restore", pub.ErrDrift)
	}
	desiredKeys := make(map[string]struct{}, len(desired))
	for _, channel := range desired {
		desiredKeys[channel.RemoteKey] = struct{}{}
	}
	if parent == nil {
		return fmt.Errorf("%w: removed YUM channel has no committed parent", pub.ErrDrift)
	}
	unresolved := make(map[string]struct{}, len(prepared.restoreRemovedChannelKeys))
	for key := range prepared.restoreRemovedChannelKeys {
		unresolved[key] = struct{}{}
	}
	for _, channel := range parent.Channels {
		if _, remove := unresolved[channel.RemoteKey]; !remove {
			continue
		}
		if _, retained := desiredKeys[channel.RemoteKey]; retained {
			return fmt.Errorf("%w: removed channel %s remains in desired generation", pub.ErrDrift, channel.RemoteKey)
		}
		if channel.View != prepared.view || channel.Generation == 0 || channel.LegacyRoot == "" {
			return fmt.Errorf("%w: parent channel %s has invalid restore identity", pub.ErrDrift, channel.RemoteKey)
		}
		remoteKey := path.Join("_sow/v1/mirrorlist", channel.View, channel.Repo, channel.OS, channel.Arch+".txt")
		evidence, err := historicalPublicMirrorlistEvidence(canonical, target, channel, remoteKey)
		if err != nil {
			return err
		}
		plan.Deletes = append(plan.Deletes, pub.PlannedDelete{
			Class: pub.DeleteRestoreIndexServing, SourcePath: remoteKey, RemoteKey: remoteKey,
			Size: evidence.Size, SHA256: evidence.SHA256, CDNPath: remoteKey,
		})
		delete(unresolved, channel.RemoteKey)
	}
	if len(unresolved) != 0 {
		missing := make([]string, 0, len(unresolved))
		for key := range unresolved {
			missing = append(missing, key)
		}
		sort.Strings(missing)
		return fmt.Errorf("%w: removed YUM topology has no exact parent channel state for %s", pub.ErrDrift, strings.Join(missing, ","))
	}
	return nil
}

func historicalPublicMirrorlistEvidence(canonical *state.Store, target string, channel pub.ChannelState, remoteKey string) (pub.PlannedObject, error) {
	var result pub.PlannedObject
	commit, generation, err := targetGenerationPublicationState(canonical, target, channel.Generation)
	if err != nil {
		return result, fmt.Errorf("%w: locate parent channel generation %d: %v", pub.ErrDrift, channel.Generation, err)
	}
	closure, exists, err := loadHistoricalPublicationClosureAt(canonical, target, commit)
	if err != nil || !exists {
		return result, errors.Join(err, fmt.Errorf("%w: parent channel generation %d lacks a complete successful-publication closure", pub.ErrDrift, channel.Generation))
	}
	if closure.generation.Generation != generation.Generation || closure.generation.Target != generation.Target ||
		closure.generation.DesiredCommit != generation.DesiredCommit ||
		!pub.SamePublicationIntent(closure.generation.IntentView, closure.generation.IntentSnapshot, generation.IntentView, generation.IntentSnapshot) {
		return result, fmt.Errorf("%w: parent channel generation %d closure identity changed", pub.ErrDrift, channel.Generation)
	}
	generation = closure.generation
	if generation.IntentView != channel.View || generation.IntentSnapshot != "" {
		return result, fmt.Errorf("%w: parent channel %s generation %d belongs to intent %s/%s", pub.ErrDrift, channel.RemoteKey, channel.Generation, generation.IntentView, generation.IntentSnapshot)
	}
	found := false
	for _, object := range closure.plan.Objects {
		if object.RemoteKey != remoteKey {
			continue
		}
		if found {
			return result, fmt.Errorf("%w: parent channel %s has duplicate mirrorlist evidence", pub.ErrDrift, channel.RemoteKey)
		}
		if object.Class != pub.ObjectPointer || object.CDNPath != remoteKey || object.Size < 0 || object.SHA256 == "" {
			return result, fmt.Errorf("%w: parent channel %s mirrorlist evidence is not an exact public pointer", pub.ErrDrift, channel.RemoteKey)
		}
		result, found = object, true
	}
	if !found {
		return result, fmt.Errorf("%w: parent channel %s generation %d has no exact mirrorlist evidence", pub.ErrDrift, channel.RemoteKey, channel.Generation)
	}
	return result, nil
}

func channelRemoteKey(viewName string, projection publicationProjection) string {
	if projection.isYUMCompatibility() {
		viewName = "latest"
	}
	repo, osName, arch := projection.channelCoordinates()
	return path.Join(".sow/channels", viewName, repo, osName, arch+".json")
}

type publicationClassifier struct {
	view        string
	snapshotID  string
	generation  uint64
	projections []publicationProjection
	stablePools map[string]string
}

func (classifier publicationClassifier) classify(entry manifest.Entry) (string, pub.ObjectClass, error) {
	projection, relative, err := classifier.projection(entry.Path)
	if err != nil {
		return "", "", err
	}
	if projection.repo.Type == "asset" {
		logical := path.Join(projection.canonicalPathRoot(), relative)
		if err := validateAssetProjectionPath(projection.repo, logical); err != nil {
			return "", "", fmt.Errorf("invalid asset publication path %s: %w", entry.Path, err)
		}
	}
	remote := path.Join(projection.remotePathRoot(), relative)
	if projection.isYUMCompatibilityTrust() {
		if relative != "packages.pgp" && relative != "repository.pgp" {
			return "", "", fmt.Errorf("unexpected YUM compatibility trust path %s", entry.Path)
		}
		return remote, pub.ObjectImmutable, nil
	}
	remotePayload := func() (string, error) {
		if classifier.view != "stable" && classifier.view != "snapshot" {
			return remote, nil
		}
		pool, exists := classifier.stablePools[entry.Path]
		if !exists {
			return "", fmt.Errorf("stable payload %s has no canonical pool classification", entry.Path)
		}
		if pool == "gated" {
			return path.Join(".sow/gated", remote), nil
		}
		if pool != "public" {
			return "", fmt.Errorf("stable payload %s has unknown pool %q", entry.Path, pool)
		}
		return remote, nil
	}
	metadataKey := func() string {
		switch classifier.view {
		case "beta":
			return path.Join(".sow/beta", remote)
		case "stable", "snapshot":
			return path.Join(".sow/gated", remote)
		default:
			return remote
		}
	}
	switch projection.repo.Type {
	case "apt":
		if strings.HasPrefix(relative, "pool/") {
			key, err := remotePayload()
			return key, pub.ObjectImmutable, err
		}
		if !strings.HasPrefix(relative, "dists/") {
			return "", "", fmt.Errorf("unexpected APT publication path %s", entry.Path)
		}
		if classifier.view == "snapshot" {
			return path.Join(".sow/gated/generations", fmt.Sprintf("%020d", classifier.generation), "apt", remote), pub.ObjectMetadata, nil
		}
		key := metadataKey()
		switch {
		case strings.HasSuffix(relative, "/InRelease"):
			return key, pub.ObjectPointer, nil
		case strings.Contains(relative, "/by-hash/SHA256/"):
			return key, pub.ObjectImmutable, nil
		default:
			return key, pub.ObjectLegacyMetadata, nil
		}
	case "yum":
		if projection.isYUMCompatibilityRollback() {
			if path.Base(relative) == relative && strings.HasSuffix(relative, ".rpm") {
				return remote, pub.ObjectImmutable, nil
			}
			if !strings.HasPrefix(relative, "repodata/") {
				return "", "", fmt.Errorf("unexpected compatibility S0 rollback path %s", entry.Path)
			}
			if relative == "repodata/repomd.xml" {
				return remote, pub.ObjectCompatibilityRollbackPointer, nil
			}
			return remote, pub.ObjectCompatibilityRollbackMetadata, nil
		}
		canonicalPayload := strings.HasPrefix(relative, "Packages/")
		flatCompatibilityPayload := projection.isYUMCompatibility() && path.Base(relative) == relative && strings.HasSuffix(relative, ".rpm")
		if canonicalPayload || flatCompatibilityPayload {
			if classifier.view == "snapshot" {
				return path.Join(".sow/gated/snapshots", classifier.snapshotID, "yum", remote), pub.ObjectImmutable, nil
			}
			key, err := remotePayload()
			return key, pub.ObjectImmutable, err
		}
		if !strings.HasPrefix(relative, "repodata/") {
			return "", "", fmt.Errorf("unexpected YUM publication path %s", entry.Path)
		}
		generation := fmt.Sprintf("%020d", classifier.generation)
		prefix := ".sow/generations"
		if classifier.view == "stable" || classifier.view == "snapshot" {
			prefix = ".sow/gated/generations"
		}
		return path.Join(prefix, generation, "yum", projection.remotePathRoot(), relative), pub.ObjectMetadata, nil
	case "asset":
		if classifier.view == "snapshot" {
			return path.Join(".sow/gated/snapshots", classifier.snapshotID, "asset", remote), pub.ObjectImmutable, nil
		}
		key := metadataKey()
		for _, pattern := range projection.repo.Asset.MutablePaths {
			matched, err := doublestar.Match(pattern, relative)
			if err != nil {
				return "", "", err
			}
			if matched {
				return key, pub.ObjectPointer, nil
			}
		}
		return key, pub.ObjectImmutable, nil
	default:
		return "", "", fmt.Errorf("unsupported repository type %s", projection.repo.Type)
	}
}

func (classifier publicationClassifier) projection(sourcePath string) (publicationProjection, string, error) {
	var matched *publicationProjection
	for index := range classifier.projections {
		projection := &classifier.projections[index]
		if sourcePath == projection.sourceRoot || strings.HasPrefix(sourcePath, strings.TrimSuffix(projection.sourceRoot, "/")+"/") {
			if matched != nil {
				return publicationProjection{}, "", fmt.Errorf("publication path %s matches overlapping projections", sourcePath)
			}
			matched = projection
		}
	}
	if matched == nil {
		return publicationProjection{}, "", fmt.Errorf("publication path %s is outside selected repositories", sourcePath)
	}
	relative := strings.TrimPrefix(sourcePath, strings.TrimSuffix(matched.sourceRoot, "/")+"/")
	if relative == sourcePath || relative == "" {
		return publicationProjection{}, "", fmt.Errorf("publication path %s is not a file below its projection", sourcePath)
	}
	return *matched, relative, nil
}

func resolveStablePublicationPools(canonical *state.Store, cfg *config.Config, prepared preparedPublication, changedPaths []string) (map[string]string, error) {
	result := make(map[string]string)
	if prepared.view != "stable" && prepared.view != "snapshot" {
		return result, nil
	}
	neededLogical := make(map[string]string)
	for _, sourcePath := range changedPaths {
		projection, relative, err := (publicationClassifier{projections: prepared.projections}).projection(sourcePath)
		if err != nil {
			return nil, err
		}
		payload := projection.repo.Type == "asset" || projection.repo.Type == "apt" && strings.HasPrefix(relative, "pool/") || projection.repo.Type == "yum" && strings.HasPrefix(relative, "Packages/")
		if payload {
			neededLogical[path.Join(projection.canonicalPathRoot(), relative)] = sourcePath
		}
	}
	if len(neededLogical) == 0 {
		return result, nil
	}
	seenRefs := make(map[string]struct{})
	for _, projection := range prepared.projections {
		var leaves []viewLeaf
		switch projection.repo.Type {
		case "apt":
			for _, suite := range projection.repo.APT.Suites {
				for _, arch := range projection.repo.Arches {
					leaves = append(leaves, viewLeaf{repo: projection.repo, os: suite, arch: arch})
				}
			}
		case "asset":
			leaves = []viewLeaf{{repo: projection.repo, os: "all", arch: "all"}}
		case "yum":
			leaves = prepared.yumLeavesForProjection(projection)
		}
		for _, leaf := range leaves {
			var ref plumbing.ReferenceName
			if prepared.view == "snapshot" {
				ref, _ = state.SnapshotRef(prepared.snapshotID, leaf.repo.ID, leaf.os, leaf.arch)
			} else {
				ref, _ = state.ViewRef("stable", leaf.repo.ID, leaf.os, leaf.arch)
			}
			if _, duplicate := seenRefs[ref.String()]; duplicate {
				continue
			}
			seenRefs[ref.String()] = struct{}{}
			var commit plumbing.Hash
			if prepared.refOverrides != nil {
				historical, exists := prepared.refOverrides[ref.String()]
				if !exists {
					continue
				}
				commit = plumbing.NewHash(historical.Commit)
			} else {
				current, exists, err := canonical.Ref(ref)
				if err != nil {
					return nil, err
				}
				if !exists {
					continue
				}
				commit = current
			}
			var viewPath string
			if prepared.view == "snapshot" {
				viewPath, _ = state.SnapshotPath(prepared.snapshotID, leaf.repo.ID, leaf.os, leaf.arch)
			} else {
				viewPath, _ = state.ViewPath("stable", leaf.repo.ID, leaf.os, leaf.arch)
			}
			reader, err := canonical.OpenPathAt(commit, viewPath)
			if err != nil {
				return nil, err
			}
			viewReader := views.NewReader(reader)
			for {
				entry, readErr := viewReader.Next()
				if errors.Is(readErr, io.EOF) {
					break
				}
				if readErr != nil {
					reader.Close()
					return nil, readErr
				}
				if source, wanted := neededLogical[entry.Path]; wanted {
					if previous, exists := result[source]; exists && previous != entry.Pool {
						reader.Close()
						return nil, fmt.Errorf("stable path %s has conflicting pool classifications", entry.Path)
					}
					result[source] = entry.Pool
				}
			}
			if err := reader.Close(); err != nil {
				return nil, err
			}
		}
	}
	if len(result) != len(neededLogical) {
		return nil, fmt.Errorf("stable payload classification is incomplete: resolved %d of %d changed paths", len(result), len(neededLogical))
	}
	return result, nil
}

func augmentPublicationPlan(cfg *config.Config, target string, prepared preparedPublication, generation pub.TargetGeneration, txDir string, recover bool, classifier publicationClassifier, plan *pub.Plan) error {
	if plan == nil {
		return errors.New("nil publication plan")
	}
	cdnBase := strings.TrimSuffix(cfg.Targets[target].CDN.BaseURL, "/")
	if prepared.view == "beta" {
		cdnBase = strings.TrimSuffix(cfg.Targets[target].CDN.BetaBaseURL, "/")
	}
	original := append([]pub.PlannedObject(nil), plan.Objects...)
	seenRemote := make(map[string]struct{}, len(original)*2)
	for index := range plan.Objects {
		object := &plan.Objects[index]
		seenRemote[object.RemoteKey] = struct{}{}
		projection, _, err := classifier.projection(object.SourcePath)
		if err != nil {
			return err
		}
		if prepared.view == "snapshot" {
			object.CDNPath = snapshotCDNPath(prepared.snapshotID, projection, object.SourcePath)
			if projection.repo.Type == "apt" && object.Class == pub.ObjectImmutable {
				_, relative, projectErr := classifier.projection(object.SourcePath)
				if projectErr != nil {
					return projectErr
				}
				if strings.HasPrefix(relative, "pool/") {
					object.Class = pub.ObjectReuseImmutable
				}
			}
			if projection.repo.Type == "yum" && object.Class == pub.ObjectImmutable {
				_, relative, projectErr := classifier.projection(object.SourcePath)
				if projectErr != nil {
					return projectErr
				}
				pool := classifier.stablePools[object.SourcePath]
				copySource := path.Join(projection.remotePathRoot(), relative)
				if pool == "gated" {
					copySource = path.Join(".sow/gated", copySource)
				} else if pool != "public" {
					return fmt.Errorf("snapshot YUM payload %s has no source pool classification", object.SourcePath)
				}
				object.Class = pub.ObjectCopyImmutable
				object.CopySource = copySource
			}
		} else if prepared.view == "beta" {
			object.CDNPath = betaCDNPath(object.RemoteKey)
		} else if prepared.view == "stable" {
			object.CDNPath = proCDNPath(object.RemoteKey)
		}
		if prepared.view != "snapshot" && projection.repo.Type == "yum" && object.Class == pub.ObjectMetadata {
			object.CDNPath = generationYUMCDNPath(prepared.view, object.RemoteKey)
		}
	}
	for _, object := range original {
		projection, relative, err := classifier.projection(object.SourcePath)
		if err != nil {
			return err
		}
		if prepared.view != "snapshot" && projection.repo.Type == "apt" && (object.Class == pub.ObjectLegacyMetadata || object.Class == pub.ObjectPointer) {
			legacy := trimPublicationNamespace(object.RemoteKey)
			prefix := ".sow/generations"
			if prepared.view == "stable" {
				prefix = ".sow/gated/generations"
			}
			archiveKey := path.Join(prefix, fmt.Sprintf("%020d", generation.Generation), "apt", legacy)
			if _, duplicate := seenRemote[archiveKey]; !duplicate {
				archive := object
				archive.RemoteKey = archiveKey
				archive.Class = pub.ObjectMetadata
				archive.CDNPath = generationAPTCDNPath(prepared.view, generation.Generation, legacy)
				plan.Objects = append(plan.Objects, archive)
				seenRemote[archiveKey] = struct{}{}
			}
		}
		if prepared.view != "snapshot" && projection.repo.Type == "asset" && object.Class == pub.ObjectPointer {
			archiveKey := path.Join("objects/sha256", object.SHA256)
			if prepared.view == "stable" && strings.HasPrefix(object.RemoteKey, ".sow/gated/") {
				archiveKey = path.Join(".sow/gated/objects/sha256", object.SHA256)
			}
			if _, duplicate := seenRemote[archiveKey]; !duplicate {
				archive := object
				archive.RemoteKey = archiveKey
				archive.Class = pub.ObjectImmutable
				archive.CDNPath = archiveKey
				if prepared.view == "beta" {
					archive.CDNPath = strings.TrimPrefix(archiveKey, ".sow/beta/")
				} else if prepared.view == "stable" {
					archive.CDNPath = proCDNPath(archiveKey)
				}
				plan.Objects = append(plan.Objects, archive)
				seenRemote[archiveKey] = struct{}{}
			}
		}
		if prepared.view != "snapshot" && projection.repo.Type == "yum" && object.Class == pub.ObjectMetadata {
			legacyKey := path.Join(projection.remotePathRoot(), relative)
			switch prepared.view {
			case "beta":
				legacyKey = path.Join(".sow/beta", legacyKey)
			case "stable":
				legacyKey = path.Join(".sow/gated", legacyKey)
			}
			if _, duplicate := seenRemote[legacyKey]; !duplicate {
				alias := object
				alias.RemoteKey = legacyKey
				if strings.HasSuffix(relative, "repodata/repomd.xml") || strings.HasSuffix(relative, "repodata/repomd.xml.asc") {
					alias.Class = pub.ObjectYUMAliasPointer
				} else {
					alias.Class = pub.ObjectYUMAliasMetadata
				}
				alias.CDNPath = legacyKey
				if prepared.view == "beta" {
					alias.CDNPath = betaCDNPath(legacyKey)
				} else if prepared.view == "stable" {
					alias.CDNPath = proCDNPath(legacyKey)
				}
				plan.Objects = append(plan.Objects, alias)
				seenRemote[legacyKey] = struct{}{}
			}
		}
	}
	if prepared.view == "snapshot" {
		source, body, err := writeSnapshotRouteSource(cfg, target, prepared.snapshotID, generation.Generation, recover)
		if err != nil {
			return err
		}
		plan.Objects = append(plan.Objects, pub.PlannedObject{
			SourcePath: source, RemoteKey: path.Join(".sow/snapshots", prepared.snapshotID+".json"),
			Size: int64(len(body)), SHA256: digestBytesCLI(body), Class: pub.ObjectPointer,
			CDNPath: path.Join("pro/v1/basic/_sow/v1/snapshots", prepared.snapshotID, "_route.json"),
		})
		return nil
	}
	currentChannels := make(map[string]pub.ChannelState)
	for _, channel := range generation.Channels {
		if channel.Generation == generation.Generation && channel.View == prepared.view {
			currentChannels[channel.RemoteKey] = channel
		}
	}
	for _, physicalProjection := range prepared.projections {
		if physicalProjection.repo.Type != "yum" || physicalProjection.isYUMCompatibilityTrust() || physicalProjection.isYUMCompatibilityRollback() {
			continue
		}
		for _, projection := range prepared.yumChannelProjections(physicalProjection) {
			remoteKey := channelRemoteKey(prepared.view, projection)
			channel, publishChannel := currentChannels[remoteKey]
			if !publishChannel {
				continue
			}
			channelSource, channelBody, err := writeChannelSource(cfg, target, channel, recover)
			if err != nil {
				return err
			}
			channelSHA := sha256.Sum256(channelBody)
			channelRepo, channelOS, channelArch := channel.Repo, channel.OS, channel.Arch
			mirrorPath := path.Join("_sow/v1/mirrorlist", prepared.view, channelRepo, channelOS, channelArch+".txt")
			prefix := ""
			if prepared.view == "stable" {
				prefix = "pro/v1/basic"
			}
			cdnPath := path.Join(prefix, mirrorPath)
			// The sealed channel is the only authority for both the immutable
			// generation and served root. Re-deriving either value from the current
			// projection would let a route transition emit a mirrorlist whose bytes
			// disagree with ChannelState and its checkpoint identity.
			bodyPrefix := ""
			if prepared.view == "stable" {
				bodyPrefix = "/pro/v1/basic"
			}
			generationPath := "_sow/v1/g/" + fmt.Sprintf("%020d", channel.Generation) + "/" + channel.LegacyRoot
			clientURL, err := config.CanonicalRouteURL(cdnBase+bodyPrefix, generationPath, true)
			if err != nil {
				return fmt.Errorf("render YUM channel %s: %w", channel.RemoteKey, err)
			}
			rendered := []byte(clientURL + "\n")
			if prepared.view != "stable" {
				mirrorSource, err := writeStaticMirrorlistSource(cfg, target, prepared.view, projection, rendered, recover)
				if err != nil {
					return err
				}
				plan.Objects = append(plan.Objects, pub.PlannedObject{
					SourcePath: mirrorSource, RemoteKey: mirrorPath,
					Size: int64(len(rendered)), SHA256: digestBytesCLI(rendered), Class: pub.ObjectPointer,
					CDNPath: mirrorPath,
				})
				continue
			}
			plan.Objects = append(plan.Objects, pub.PlannedObject{
				SourcePath: channelSource,
				RemoteKey:  remoteKey,
				Size:       int64(len(channelBody)), SHA256: hex.EncodeToString(channelSHA[:]), Class: pub.ObjectPointer,
				CDNPath: cdnPath, VerificationSize: int64(len(rendered)), VerificationSHA256: digestBytesCLI(rendered),
			})
		}
	}
	return nil
}

func writeStaticMirrorlistSource(cfg *config.Config, target, viewName string, projection publicationProjection, body []byte, recover bool) (string, error) {
	repo, osName, arch := projection.channelCoordinates()
	stateRelative := filepath.ToSlash(filepath.Join("generated", "mirrorlists", target, viewName, repo, osName, arch+".txt"))
	result, err := writeDerivedStateFileOutcomeWithRecovery(cfg.StatePath(), stateRelative, body, recover)
	if err := consumeDerivedStateReplacement(result, err); err != nil {
		return "", err
	}
	return filepath.ToSlash(filepath.Join(".sow", stateRelative)), nil
}

func snapshotCDNPath(snapshotID string, projection publicationProjection, sourcePath string) string {
	relative := strings.TrimPrefix(sourcePath, strings.TrimSuffix(projection.sourceRoot, "/")+"/")
	kind := projection.repo.Type
	if kind == "asset" {
		kind = "assets"
	}
	return path.Join("pro/v1/basic/_sow/v1/snapshots", snapshotID, kind, projection.remotePathRoot(), relative)
}

func writeSnapshotRouteSource(cfg *config.Config, target, snapshotID string, generation uint64, recover bool) (string, []byte, error) {
	body, err := pub.SnapshotRouteBody(snapshotID, generation)
	if err != nil {
		return "", nil, err
	}
	stateRelative := filepath.ToSlash(filepath.Join("generated", "snapshot-routes", target, snapshotID+".json"))
	result, err := writeDerivedStateFileOutcomeWithRecovery(cfg.StatePath(), stateRelative, body, recover)
	if err := consumeDerivedStateReplacement(result, err); err != nil {
		return "", nil, err
	}
	return filepath.ToSlash(filepath.Join(".sow", stateRelative)), body, nil
}

func betaCDNPath(remoteKey string) string {
	return strings.TrimPrefix(remoteKey, ".sow/beta/")
}

func proCDNPath(remoteKey string) string {
	clean := strings.TrimPrefix(remoteKey, ".sow/gated/")
	return path.Join("pro/v1/basic", clean)
}

func generationYUMCDNPath(viewName, remoteKey string) string {
	clean := strings.TrimPrefix(remoteKey, ".sow/gated/")
	clean = strings.TrimPrefix(clean, ".sow/generations/")
	clean = strings.TrimPrefix(clean, "generations/")
	parts := strings.SplitN(clean, "/", 2)
	if len(parts) != 2 {
		return ""
	}
	prefix := ""
	if viewName == "stable" {
		prefix = "pro/v1/basic"
	}
	return path.Join(prefix, "_sow/v1/g", parts[0], strings.TrimPrefix(parts[1], "yum/"))
}

func generationAPTCDNPath(viewName string, generation uint64, legacy string) string {
	prefix := ""
	if viewName == "stable" {
		prefix = "pro/v1/basic"
	}
	return path.Join(prefix, "_sow/v1/a", fmt.Sprintf("%020d", generation), legacy)
}

func trimPublicationNamespace(remoteKey string) string {
	for _, prefix := range []string{".sow/beta/", ".sow/gated/"} {
		if strings.HasPrefix(remoteKey, prefix) {
			return strings.TrimPrefix(remoteKey, prefix)
		}
	}
	return remoteKey
}

func writeChannelSource(cfg *config.Config, target string, channel pub.ChannelState, recover bool) (string, []byte, error) {
	body, err := channel.CanonicalBody()
	if err != nil {
		return "", nil, err
	}
	if digestBytesCLI(body) != channel.BodySHA256 {
		return "", nil, errors.New("channel body does not match canonical target state")
	}
	stateRelative := filepath.ToSlash(filepath.Join("generated", "channels", target, channel.View, channel.Repo, channel.OS, channel.Arch+".json"))
	result, err := writeDerivedStateFileOutcomeWithRecovery(cfg.StatePath(), stateRelative, body, recover)
	if err := consumeDerivedStateReplacement(result, err); err != nil {
		return "", nil, err
	}
	return filepath.ToSlash(filepath.Join(".sow", stateRelative)), body, nil
}

var derivedStateWriteHook func(string) error
var derivedStateBeforeInstallHook func(string) error
var derivedStateAfterVerifyHook func(string) error

// These derived-state directory seams are replaceable only by focused
// durability/failure-injection tests. Production synchronizes the exact bound
// parent and never installs a traversal hook.
var derivedStateDirectorySync = func(parent *os.Root, _ string) error {
	return syncBoundArchiveDirectory(parent)
}
var derivedStateDirectoryBeforeCreateHook func(string) error
var derivedStateDirectoryAfterStageMkdirHook func(string) error
var derivedStateDirectoryBeforeStageInstallHook func(string) error
var derivedStateDirectoryBeforeBindHook func(string) error
var derivedStateDirectoryAfterSyncHook func(string) error
var derivedStateDirectoryBeforeRemovalHook func(string) error
var derivedStateDirectoryAfterRemovalHook func(string) error
var derivedStateDirectoryRecoveryScanHook func(string)
var derivedStateDirectoryRecoveryAfterLstatHook func(string) error
var derivedStateDirectoryBeforeFinalCacheHook func(string) error
var derivedStateDirectoryParentSync = func(parent *os.File) error {
	return parent.Sync()
}

type derivedStateDirectoryCachedIdentity struct {
	info       os.FileInfo
	token      string
	validUntil time.Time
}

type derivedStateDirectoryMutationEpoch struct {
	token      string
	validUntil time.Time
}

var derivedStateDirectoryStageState = struct {
	sync.Mutex
	active       map[string]os.FileInfo
	dirty        map[string]struct{}
	cleanParents map[string]derivedStateDirectoryCachedIdentity
}{
	active:       make(map[string]os.FileInfo),
	dirty:        make(map[string]struct{}),
	cleanParents: make(map[string]derivedStateDirectoryCachedIdentity),
}

type derivedStateDirectoryWriterLock struct {
	mutex sync.Mutex
	refs  int
}

var derivedStateDirectoryWriterLocks = struct {
	sync.Mutex
	entries map[string]*derivedStateDirectoryWriterLock
}{
	entries: make(map[string]*derivedStateDirectoryWriterLock),
}

func lockDerivedStateDirectoryWriter(path string) func() {
	derivedStateDirectoryWriterLocks.Lock()
	entry := derivedStateDirectoryWriterLocks.entries[path]
	if entry == nil {
		entry = &derivedStateDirectoryWriterLock{}
		derivedStateDirectoryWriterLocks.entries[path] = entry
	}
	entry.refs++
	derivedStateDirectoryWriterLocks.Unlock()

	entry.mutex.Lock()
	return func() {
		entry.mutex.Unlock()
		derivedStateDirectoryWriterLocks.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(derivedStateDirectoryWriterLocks.entries, path)
		}
		derivedStateDirectoryWriterLocks.Unlock()
	}
}

func cacheDerivedStateDirectoryIdentity(info os.FileInfo) (derivedStateDirectoryCachedIdentity, bool) {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return derivedStateDirectoryCachedIdentity{}, false
	}
	if _, err := admitDerivedStateDirectory(info, "derived state recovery-cache directory"); err != nil {
		return derivedStateDirectoryCachedIdentity{}, false
	}
	token, ok := derivedStateDirectoryIdentityToken(info)
	if !ok {
		return derivedStateDirectoryCachedIdentity{}, false
	}
	return derivedStateDirectoryCachedIdentity{info: info, token: token}, true
}

func sameCachedDerivedStateDirectoryIdentity(cached derivedStateDirectoryCachedIdentity, current os.FileInfo) bool {
	token, ok := derivedStateDirectoryIdentityToken(current)
	return ok && cached.info != nil && !cached.validUntil.IsZero() && time.Now().Before(cached.validUntil) &&
		os.SameFile(cached.info, current) &&
		sameDerivedStateDirectorySecurity(cached.info, current) && cached.token == token
}

type derivedStateDirectoryMutationGuard struct {
	root       *os.Root
	directory  *os.File
	cacheKey   string
	relative   string
	expected   os.FileInfo
	token      string
	validUntil time.Time
}

func newDerivedStateDirectoryMutationGuard(root *os.Root, directory *os.File, stateRoot, relative string, expected os.FileInfo) (*derivedStateDirectoryMutationGuard, error) {
	if stateRoot == "" || !filepath.IsAbs(stateRoot) {
		return nil, errors.New("derived state directory mutation guard lacks an absolute cache coordinate")
	}
	guard := &derivedStateDirectoryMutationGuard{
		root:      root,
		directory: directory,
		cacheKey:  filepath.Join(stateRoot, relative),
		relative:  relative,
		expected:  expected,
	}
	if err := guard.admitKnownMutation(); err != nil {
		return nil, err
	}
	return guard, nil
}

func (g *derivedStateDirectoryMutationGuard) current() (os.FileInfo, error) {
	if g == nil || g.root == nil || g.directory == nil || g.relative == "" || g.expected == nil {
		return nil, errors.New("derived state directory mutation guard is invalid")
	}
	fresh, statErr := g.directory.Stat()
	current, lstatErr := g.root.Lstat(g.relative)
	if statErr != nil || lstatErr != nil || fresh == nil || current == nil ||
		!os.SameFile(g.expected, fresh) || !os.SameFile(g.expected, current) ||
		!sameDerivedStateDirectorySecurity(g.expected, fresh) ||
		!sameDerivedStateDirectorySecurity(g.expected, current) {
		return nil, errors.Join(statErr, lstatErr, errors.New("derived state directory changed across mutation guard"))
	}
	if _, err := admitDerivedStateDirectory(fresh, "bound derived state mutation directory"); err != nil {
		return nil, err
	}
	if _, err := admitDerivedStateDirectory(current, "current derived state mutation directory"); err != nil {
		return nil, err
	}
	return fresh, nil
}

func (g *derivedStateDirectoryMutationGuard) admitKnownMutation() error {
	if _, err := g.current(); err != nil {
		return err
	}
	epoch, err := derivedStateDirectoryMutationSealer(
		g.directory,
		atomic.AddUint64(&derivedStateDirectoryMutationSealCounter, 1),
	)
	if err != nil {
		return err
	}
	if epoch.token == "" || epoch.validUntil.IsZero() {
		// Some writable filesystems do not let a non-owner set directory
		// timestamps. Correctness then falls back to a full recovery scan at
		// every guard boundary and never admits a clean-cache entry.
		derivedStateDirectoryStageState.Lock()
		delete(derivedStateDirectoryStageState.cleanParents, g.cacheKey)
		derivedStateDirectoryStageState.Unlock()
		g.token = ""
		g.validUntil = time.Time{}
		return nil
	}
	fresh, err := g.current()
	if err != nil {
		return err
	}
	currentToken, ok := derivedStateDirectoryIdentityToken(fresh)
	if !ok || currentToken != epoch.token {
		return errors.New("derived state directory changed while sealing a known mutation")
	}
	g.token = epoch.token
	g.validUntil = epoch.validUntil
	return nil
}

func (g *derivedStateDirectoryMutationGuard) recoverUnexpectedMutation(root, parent *os.Root, parentHandle *os.File, stateRoot string, rootIdentity os.FileInfo) error {
	fresh, err := g.current()
	if err != nil {
		return err
	}
	token, ok := derivedStateDirectoryIdentityToken(fresh)
	if !ok {
		return errors.New("derived state directory lacks a stable recovery identity")
	}
	if g.token != "" && !g.validUntil.IsZero() && time.Now().Before(g.validUntil) && token == g.token {
		return nil
	}
	if g.token == "" || g.validUntil.IsZero() {
		derivedStateDirectoryStageState.Lock()
		delete(derivedStateDirectoryStageState.cleanParents, g.cacheKey)
		derivedStateDirectoryStageState.Unlock()
	}
	if err := recoverDerivedStateDirectoryStages(root, parent, parentHandle, stateRoot, g.relative, rootIdentity, fresh); err != nil {
		return err
	}
	return g.admitKnownMutation()
}

func claimDerivedStateDirectoryStage(path string, parentIdentity os.FileInfo) bool {
	if parentIdentity == nil || !parentIdentity.IsDir() || parentIdentity.Mode()&os.ModeSymlink != 0 {
		return false
	}
	derivedStateDirectoryStageState.Lock()
	defer derivedStateDirectoryStageState.Unlock()
	if _, exists := derivedStateDirectoryStageState.active[path]; exists {
		return false
	}
	delete(derivedStateDirectoryStageState.cleanParents, filepath.Dir(path))
	derivedStateDirectoryStageState.active[path] = parentIdentity
	return true
}

func finishDerivedStateDirectoryStage(path string, clean bool) {
	derivedStateDirectoryStageState.Lock()
	delete(derivedStateDirectoryStageState.active, path)
	if clean {
		delete(derivedStateDirectoryStageState.dirty, path)
	} else {
		derivedStateDirectoryStageState.dirty[path] = struct{}{}
	}
	derivedStateDirectoryStageState.Unlock()
}

func isDerivedStateTemporaryName(name, canonical string) bool {
	suffix, ok := strings.CutPrefix(name, canonical)
	if !ok || suffix == "" {
		return false
	}
	if index := strings.Index(suffix, ".tmp-remove-"); index >= 0 {
		if !exactLowerHex(suffix[index+len(".tmp-remove-"):], 32) {
			return false
		}
		suffix = suffix[:index]
	}
	if value, ok := strings.CutPrefix(suffix, ".tmp-install-"); ok {
		return exactLowerHex(value, 32)
	}
	if value, ok := strings.CutPrefix(suffix, ".tmp-"); ok {
		return exactLowerHex(value, 16, 32)
	}
	return false
}

func exactLowerHex(value string, lengths ...int) bool {
	validLength := false
	for _, length := range lengths {
		if len(value) == length {
			validLength = true
			break
		}
	}
	if !validLength {
		return false
	}
	for _, current := range []byte(value) {
		if (current < '0' || current > '9') && (current < 'a' || current > 'f') {
			return false
		}
	}
	return true
}

const derivedStateDirectoryStagePrefix = ".tmp-derived-directory-"
const derivedStateDirectoryStageQuarantineSuffix = ".quarantine"
const derivedStateDirectoryStagePreservedMarker = ".preserved-"

var errDerivedStateDirectoryStagePreserved = errors.New("derived state directory replacement preserved")
var derivedStateDirectoryPreserveCounter uint64
var derivedStateDirectoryMutationSealCounter uint64
var derivedStateDirectoryMutationSealer = sealDerivedStateDirectoryMutation

func derivedStateDirectoryStageBase(name string) (string, bool) {
	value, ok := strings.CutPrefix(name, derivedStateDirectoryStagePrefix)
	if !ok {
		return "", false
	}
	value = strings.TrimSuffix(value, derivedStateDirectoryStageQuarantineSuffix)
	if !exactLowerHex(value, 32) {
		return "", false
	}
	base := derivedStateDirectoryStagePrefix + value
	if name != base && name != base+derivedStateDirectoryStageQuarantineSuffix {
		return "", false
	}
	return base, true
}

func writeDerivedStateFileTransaction(stateRoot, relative string, body []byte, result *derivedStateReplacementResult, recover bool) (resultErr error) {
	if result == nil {
		return errors.New("derived state replacement result is required")
	}
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("unsafe derived state path")
	}
	if _, _, _, related := classifyStrictDerivedStateTemporaryName(filepath.Base(relative)); related {
		return errors.New("derived state destination uses the reserved temporary-name grammar")
	}
	expectedDigest := sha256.Sum256(body)
	expectedSize := len(body)
	stateRoot, err := filepath.Abs(stateRoot)
	if err != nil {
		return err
	}
	rootBefore, err := os.Lstat(stateRoot)
	if err != nil || rootBefore.Mode()&os.ModeSymlink != 0 || !rootBefore.IsDir() {
		return errors.Join(err, errors.New("derived state root is not a real directory"))
	}
	if err := verifyDerivedStateImmediateParent(stateRoot); err != nil {
		return err
	}
	if _, err := admitDerivedStateDirectory(rootBefore, "derived state root"); err != nil {
		return err
	}
	root, err := os.OpenRoot(stateRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	rootIdentity, err := root.Stat(".")
	if err != nil || rootIdentity == nil || !os.SameFile(rootBefore, rootIdentity) {
		return errors.Join(err, errors.New("derived state root changed while binding"))
	}
	if err := verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity); err != nil {
		return err
	}
	directory := filepath.Dir(relative)
	unlockDirectoryWriter := lockDerivedStateDirectoryWriter(filepath.Join(stateRoot, directory))
	defer unlockDirectoryWriter()
	parent, directoryHandle, directoryIdentity, err := bindOrCreateDurableDerivedStateDirectory(root, stateRoot, rootIdentity, directory)
	if err != nil {
		return err
	}
	defer parent.Close()
	defer directoryHandle.Close()
	mutationGuard, err := newDerivedStateDirectoryMutationGuard(root, directoryHandle, stateRoot, directory, directoryIdentity)
	if err != nil {
		return err
	}
	recoverUnexpectedDirectoryMutation := func() error {
		if err := verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity); err != nil {
			return err
		}
		return mutationGuard.recoverUnexpectedMutation(root, parent, directoryHandle, stateRoot, rootIdentity)
	}
	sets, err := listDerivedStateReplacementCarrierSets(directoryHandle)
	if err != nil {
		return err
	}
	if len(sets) != 0 {
		if !recover {
			return errors.Join(
				errors.New("interrupted derived state replacement requires --recover"),
				errDerivedStateReplacementRecoveryRequired,
			)
		}
		if err := recoverBoundDerivedStateReplacementTransactions(parent, directoryHandle, mutationGuard, recoverUnexpectedDirectoryMutation); err != nil {
			return err
		}
	}
	if err := requireNoUnjournaledDerivedStateTemporaries(directoryHandle); err != nil {
		return errors.Join(err, errDerivedStateReplacementRecoveryRequired)
	}
	result.Outcome = derivedStateReplacementNotCommitted
	nonce, err := state.NewTransactionID()
	if err != nil {
		return err
	}
	destination := filepath.Base(relative)
	if isDerivedStateReplacementReservedName(destination) {
		return errors.New("derived state destination uses a reserved replacement coordinate")
	}
	_, destinationErr := parent.Lstat(destination)
	destinationWasAbsent := errors.Is(destinationErr, os.ErrNotExist)
	if destinationErr != nil && !destinationWasAbsent {
		return destinationErr
	}
	if err := recoverUnexpectedDirectoryMutation(); err != nil {
		return err
	}
	temporary := destination + ".tmp-" + nonce
	file, err := parent.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	identity, err := file.Stat()
	if err != nil || identity == nil || identity.Mode()&os.ModeSymlink != 0 || !identity.Mode().IsRegular() || identity.Mode().Perm()&0o077 != 0 {
		file.Close()
		return errors.Join(err, errors.New("derived state temporary is not a private regular file"))
	}
	defer func() {
		var cleanupErr error
		if result.Outcome == derivedStateReplacementNotCommitted {
			cleanupErr = removeExactDerivedStateTemporary(parent, temporary, identity)
		}
		closeErr := file.Close()
		if errors.Is(closeErr, os.ErrClosed) {
			closeErr = nil
		}
		if closeErr != nil || cleanupErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("finalize derived state temporary: %w", errors.Join(closeErr, cleanupErr)))
		}
	}()
	if err := mutationGuard.admitKnownMutation(); err != nil {
		return err
	}
	if _, err := verifyBoundDerivedStateControlFile(
		parent,
		temporary,
		file,
		identity,
		"derived state temporary before chmod",
	); err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	hardened, statErr := file.Stat()
	current, lstatErr := parent.Lstat(temporary)
	if statErr != nil || lstatErr != nil || hardened == nil || current == nil ||
		!os.SameFile(identity, hardened) || !os.SameFile(identity, current) ||
		hardened.Mode() != 0o600 || current.Mode() != 0o600 ||
		!sameDerivedStateControlFileAuthority(identity, hardened) ||
		!sameDerivedStateControlFileAuthority(identity, current) {
		return errors.Join(statErr, lstatErr, errors.New("derived state temporary did not acquire its exact private mode"))
	}
	identity = hardened
	if derivedStateWriteHook != nil {
		if err := derivedStateWriteHook(filepath.Join(directory, temporary)); err != nil {
			return err
		}
	}
	if _, err := verifyBoundDerivedStateControlFile(
		parent,
		temporary,
		file,
		identity,
		"derived state temporary before write",
	); err != nil {
		return err
	}
	written, err := file.Write(body)
	if err != nil || written != expectedSize {
		return errors.Join(err, errors.New("derived state temporary write was incomplete"))
	}
	if err := file.Sync(); err != nil {
		return err
	}
	after, statErr := file.Stat()
	current, lstatErr = parent.Lstat(temporary)
	if statErr != nil || lstatErr != nil || after == nil || current == nil ||
		!os.SameFile(identity, after) || !os.SameFile(identity, current) || after.Size() != int64(expectedSize) ||
		after.Mode() != 0o600 || current.Mode() != 0o600 ||
		!sameDerivedStateControlFileSecurity(identity, after) ||
		!sameDerivedStateControlFileSecurity(identity, current) {
		return errors.Join(statErr, lstatErr, errors.New("derived state temporary changed while writing"))
	}
	identity = after
	if derivedStateBeforeInstallHook != nil {
		if err := derivedStateBeforeInstallHook(filepath.Join(directory, temporary)); err != nil {
			return err
		}
	}
	if err := errors.Join(
		verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity),
		verifyBoundDerivedStateDirectory(root, directoryHandle, directory, directoryIdentity),
	); err != nil {
		return err
	}
	if err := recoverUnexpectedDirectoryMutation(); err != nil {
		return err
	}
	replacement, err := installExactDerivedStateTemporaryOutcome(parent, directoryHandle, file, identity, expectedDigest, temporary, destination, mutationGuard, recoverUnexpectedDirectoryMutation)
	*result = replacement
	reconcileCommittedOutcome := func(cause error) error {
		if result.Outcome != derivedStateReplacementCommitted {
			return cause
		}
		proofErr := errors.Join(
			verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity),
			verifyBoundDerivedStateDirectory(root, directoryHandle, directory, directoryIdentity),
			verifyDerivedStateReplacementCoordinate(parent, destination, result.DestinationIdentity),
		)
		if proofErr == nil {
			return cause
		}
		result.Outcome = derivedStateReplacementRecoveryRequired
		return errors.Join(cause, proofErr, errDerivedStateReplacementRecoveryRequired)
	}
	resultErr = reconcileCommittedOutcome(err)
	if resultErr != nil || replacement.Outcome != derivedStateReplacementCommitted {
		return resultErr
	}
	if err := recoverUnexpectedDirectoryMutation(); err != nil {
		return reconcileCommittedOutcome(err)
	}
	if derivedStateDirectoryBeforeFinalCacheHook != nil {
		if err := derivedStateDirectoryBeforeFinalCacheHook(directory); err != nil {
			return reconcileCommittedOutcome(err)
		}
	}
	if err := reconcileCommittedOutcome(nil); err != nil {
		return err
	}
	cleanupOutcome, cleanupErr := recoverBoundDerivedStateReplacementTransaction(
		parent,
		directoryHandle,
		replacement.TransactionID,
		mutationGuard,
		recoverUnexpectedDirectoryMutation,
	)
	result.Outcome = cleanupOutcome
	if cleanupErr != nil {
		return reconcileCommittedOutcome(cleanupErr)
	}
	if cleanupOutcome != derivedStateReplacementCommitted {
		result.Outcome = derivedStateReplacementRecoveryRequired
		return errors.Join(
			errors.New("committed derived state replacement replay changed outcome"),
			errDerivedStateReplacementRecoveryRequired,
		)
	}
	if err := reconcileCommittedOutcome(nil); err != nil {
		return err
	}
	return reconcileCommittedOutcome(markDerivedStateDirectoryRecoveryClean(
		root,
		parent,
		directoryHandle,
		stateRoot,
		directory,
		rootIdentity,
		directoryIdentity,
		destinationWasAbsent,
		mutationGuard,
		recoverUnexpectedDirectoryMutation,
	))
}

func markDerivedStateDirectoryRecoveryClean(
	root, parent *os.Root,
	directory *os.File,
	stateRoot, relative string,
	rootIdentity, expected os.FileInfo,
	destinationWasAbsent bool,
	mutationGuard *derivedStateDirectoryMutationGuard,
	recoverUnexpectedMutation func() error,
) error {
	if root == nil || parent == nil || directory == nil || stateRoot == "" || relative == "" ||
		rootIdentity == nil || expected == nil || mutationGuard == nil || recoverUnexpectedMutation == nil {
		return errors.New("derived state recovery cache binding is invalid")
	}
	if err := recoverUnexpectedMutation(); err != nil {
		return err
	}
	fresh, statErr := directory.Stat()
	current, lstatErr := root.Lstat(relative)
	if statErr != nil || lstatErr != nil || fresh == nil || current == nil ||
		!os.SameFile(expected, fresh) || !os.SameFile(expected, current) ||
		!sameDerivedStateDirectorySecurity(expected, fresh) ||
		!sameDerivedStateDirectorySecurity(expected, current) {
		return errors.Join(statErr, lstatErr, errors.New("derived state directory changed before final recovery cache admission"))
	}
	freshToken, tokenOK := derivedStateDirectoryIdentityToken(fresh)
	sealed := mutationGuard.token != "" && !mutationGuard.validUntil.IsZero() && time.Now().Before(mutationGuard.validUntil)
	if sealed && (!tokenOK || freshToken != mutationGuard.token) {
		return errors.New("derived state directory mutation seal changed before final recovery cache admission")
	}
	expectedLinks, expectedLinksOK := derivedStateDirectoryLinkCount(expected)
	freshLinks, freshLinksOK := derivedStateDirectoryLinkCount(fresh)
	if !expectedLinksOK || !freshLinksOK {
		return errors.New("derived state directory lacks a stable link-count identity")
	}
	expectedLinkDelta := derivedStateDirectoryExpectedLinkDelta(destinationWasAbsent)
	if expectedLinks > ^uint64(0)-expectedLinkDelta || expectedLinks+expectedLinkDelta != freshLinks {
		// Regular-file staging does not change the parent directory's link
		// count. A changed count means a subdirectory appeared or disappeared
		// after the admission scan; rescan before cache admission so a strict
		// crash-stage name cannot be laundered into the clean cache.
		if err := recoverDerivedStateDirectoryStages(root, parent, directory, stateRoot, relative, rootIdentity, fresh); err != nil {
			return err
		}
		if err := mutationGuard.admitKnownMutation(); err != nil {
			return err
		}
	}
	if err := recoverUnexpectedMutation(); err != nil {
		return err
	}
	if err := verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity); err != nil {
		return err
	}
	finalIdentity, finalStatErr := directory.Stat()
	finalPathIdentity, finalPathErr := root.Lstat(relative)
	if finalStatErr != nil || finalPathErr != nil || finalIdentity == nil || finalPathIdentity == nil ||
		!os.SameFile(expected, finalIdentity) || !os.SameFile(expected, finalPathIdentity) ||
		!sameDerivedStateDirectorySecurity(expected, finalIdentity) ||
		!sameDerivedStateDirectorySecurity(expected, finalPathIdentity) {
		return errors.Join(finalStatErr, finalPathErr, errors.New("derived state directory changed at final recovery cache admission"))
	}
	finalToken, finalTokenOK := derivedStateDirectoryIdentityToken(finalIdentity)
	sealed = mutationGuard.token != "" && !mutationGuard.validUntil.IsZero() && time.Now().Before(mutationGuard.validUntil)
	if sealed && (!finalTokenOK || finalToken != mutationGuard.token) {
		return errors.New("derived state directory mutation seal changed at final recovery cache admission")
	}
	if err := verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity); err != nil {
		return err
	}
	if !sealed {
		return nil
	}
	cached, ok := cacheDerivedStateDirectoryIdentity(finalIdentity)
	if !ok {
		return errors.New("derived state directory lacks a stable recovery-cache identity")
	}
	cached.validUntil = mutationGuard.validUntil
	parentKey := filepath.Join(stateRoot, relative)
	derivedStateDirectoryStageState.Lock()
	defer derivedStateDirectoryStageState.Unlock()
	for active := range derivedStateDirectoryStageState.active {
		if filepath.Dir(active) == parentKey {
			return nil
		}
	}
	for dirty := range derivedStateDirectoryStageState.dirty {
		if filepath.Dir(dirty) == parentKey {
			return nil
		}
	}
	derivedStateDirectoryStageState.cleanParents[parentKey] = cached
	return nil
}

// bindOrCreateDurableDerivedStateDirectory walks a state-root-relative
// directory one component at a time. A newly-created child is bound before its
// entry is made durable by syncing the exact parent, and every retained
// capability is checked again before traversal continues.
func bindOrCreateDurableDerivedStateDirectory(root *os.Root, stateRoot string, rootIdentity os.FileInfo, relative string) (*os.Root, *os.File, os.FileInfo, error) {
	if root == nil || stateRoot == "" || !filepath.IsAbs(stateRoot) || rootIdentity == nil || !rootIdentity.IsDir() || rootIdentity.Mode()&os.ModeSymlink != 0 ||
		relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, nil, nil, errors.New("derived state directory traversal binding is invalid")
	}
	current, err := root.OpenRoot(".")
	if err != nil {
		return nil, nil, nil, err
	}
	currentIdentity, err := current.Stat(".")
	if err != nil || currentIdentity == nil || !os.SameFile(rootIdentity, currentIdentity) ||
		!sameDerivedStateDirectorySecurity(rootIdentity, currentIdentity) {
		_ = current.Close()
		return nil, nil, nil, errors.Join(err, errors.New("derived state root changed while starting directory traversal"))
	}
	currentHandle, err := bindDerivedStateDirectory(root, current, ".", currentIdentity)
	if err != nil {
		_ = current.Close()
		return nil, nil, nil, err
	}
	fail := func(cause error) (*os.Root, *os.File, os.FileInfo, error) {
		closeHandleErr := currentHandle.Close()
		closeRootErr := current.Close()
		if errors.Is(closeHandleErr, os.ErrClosed) {
			closeHandleErr = nil
		}
		if errors.Is(closeRootErr, os.ErrClosed) {
			closeRootErr = nil
		}
		return nil, nil, nil, errors.Join(cause, closeHandleErr, closeRootErr)
	}
	if err := verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity); err != nil {
		return fail(err)
	}
	if relative == "." {
		if err := recoverDerivedStateDirectoryStages(root, current, currentHandle, stateRoot, ".", rootIdentity, currentIdentity); err != nil {
			return fail(err)
		}
		return current, currentHandle, currentIdentity, nil
	}

	currentRelative := "."
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." || filepath.Base(component) != component {
			return fail(errors.New("derived state directory contains an unsafe component"))
		}
		if err := errors.Join(
			verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity),
			verifyBoundDerivedStateDirectory(root, currentHandle, currentRelative, currentIdentity),
		); err != nil {
			return fail(err)
		}
		if err := recoverDerivedStateDirectoryStages(root, current, currentHandle, stateRoot, currentRelative, rootIdentity, currentIdentity); err != nil {
			return fail(err)
		}

		nextRelative := filepath.Join(currentRelative, component)
		before, statErr := current.Lstat(component)
		created := false
		var next *os.Root
		var nextHandle *os.File
		var opened os.FileInfo
		if errors.Is(statErr, os.ErrNotExist) {
			if derivedStateDirectoryBeforeCreateHook != nil {
				if err := derivedStateDirectoryBeforeCreateHook(nextRelative); err != nil {
					return fail(err)
				}
			}
			stageName, stageKey, stagedRoot, stagedHandle, stagedIdentity, stageErr := createBoundDerivedStateDirectoryStage(root, current, stateRoot, currentRelative, currentIdentity)
			stageClean := false
			if stageKey != "" {
				defer func(key string, clean *bool) {
					finishDerivedStateDirectoryStage(key, *clean)
				}(stageKey, &stageClean)
			}
			if stageErr != nil {
				return fail(stageErr)
			}
			closeStage := func() error {
				return errors.Join(stagedHandle.Close(), stagedRoot.Close())
			}
			stageRelative := filepath.Join(currentRelative, stageName)
			var stageAdmissionErr error
			if derivedStateDirectoryBeforeStageInstallHook != nil {
				stageAdmissionErr = derivedStateDirectoryBeforeStageInstallHook(stageRelative)
			}
			stageAdmissionErr = errors.Join(
				stageAdmissionErr,
				verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity),
				verifyBoundDerivedStateDirectory(root, currentHandle, currentRelative, currentIdentity),
				verifyBoundDerivedStateDirectory(root, stagedHandle, stageRelative, stagedIdentity),
			)
			if stageAdmissionErr != nil {
				cleanupErr := removeExactEmptyDerivedStateDirectory(current, currentHandle, stagedRoot, stagedHandle, stageName, stageName, stagedIdentity)
				stageClean = cleanupErr == nil || errors.Is(cleanupErr, errDerivedStateDirectoryStagePreserved)
				closeErr := closeStage()
				return fail(errors.Join(stageAdmissionErr, cleanupErr, closeErr))
			}
			renameErr := renameYUMCompatibilityCandidateNoReplace(currentHandle.Fd(), stageName, component)
			if renameErr != nil {
				cleanupErr := removeExactEmptyDerivedStateDirectory(current, currentHandle, stagedRoot, stagedHandle, stageName, stageName, stagedIdentity)
				stageClean = cleanupErr == nil || errors.Is(cleanupErr, errDerivedStateDirectoryStagePreserved)
				closeErr := closeStage()
				if cleanupErr != nil {
					return fail(errors.Join(renameErr, cleanupErr, closeErr, fmt.Errorf("derived state directory stage %s requires recovery", stageName)))
				}
				if !errors.Is(renameErr, os.ErrExist) {
					return fail(errors.Join(renameErr, closeErr))
				}
				if closeErr != nil {
					return fail(closeErr)
				}
				// A concurrent winner is not claimed as this invocation's create.
				// Re-observe it as an existing coordinate and durably sync its
				// parent before reuse below.
				before, statErr = current.Lstat(component)
			} else {
				created = true
				next = stagedRoot
				nextHandle = stagedHandle
				opened = stagedIdentity
				stageCurrent, stageErr := current.Lstat(stageName)
				if stageErr == nil || stageCurrent != nil || !errors.Is(stageErr, os.ErrNotExist) {
					_ = closeStage()
					return fail(errors.Join(stageErr, fmt.Errorf("derived state directory stage %s remained after install", stageName)))
				}
				// The private stage coordinate is now absent. Later failures may
				// roll back the canonical component, but they cannot make this
				// random stage name recoverable again.
				stageClean = true
				if derivedStateDirectoryBeforeBindHook != nil {
					if err := derivedStateDirectoryBeforeBindHook(nextRelative); err != nil {
						_ = closeStage()
						return fail(err)
					}
				}
				currentChild, currentErr := current.Lstat(component)
				if currentErr != nil || currentChild == nil || currentChild.Mode() != os.ModeDir|0o700 ||
					!os.SameFile(opened, currentChild) {
					stageClean = false
					cleanupErr := removeExactEmptyDerivedStateDirectory(current, currentHandle, stagedRoot, stagedHandle, component, stageName, stagedIdentity)
					stageClean = cleanupErr == nil || errors.Is(cleanupErr, errDerivedStateDirectoryStagePreserved)
					closeErr := closeStage()
					return fail(errors.Join(currentErr, cleanupErr, closeErr, fmt.Errorf("derived state directory %s changed while installing", nextRelative)))
				}
				before, statErr = currentChild, nil
			}
		}
		if !created {
			if statErr != nil || before == nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
				return fail(errors.Join(statErr, fmt.Errorf("derived state directory %s is not a real directory", nextRelative)))
			}
			if derivedStateDirectoryBeforeBindHook != nil {
				if err := derivedStateDirectoryBeforeBindHook(nextRelative); err != nil {
					return fail(err)
				}
			}

			var openErr error
			next, openErr = current.OpenRoot(component)
			if openErr != nil {
				return fail(openErr)
			}
			var openedErr error
			opened, openedErr = next.Stat(".")
			after, afterErr := current.Lstat(component)
			if openedErr != nil || afterErr != nil || opened == nil || after == nil ||
				opened.Mode()&os.ModeSymlink != 0 || after.Mode()&os.ModeSymlink != 0 || !opened.IsDir() || !after.IsDir() ||
				!os.SameFile(before, opened) || !os.SameFile(before, after) || opened.Mode() != before.Mode() || after.Mode() != before.Mode() {
				_ = next.Close()
				return fail(errors.Join(openedErr, afterErr, fmt.Errorf("derived state directory %s changed while binding", nextRelative)))
			}
			var bindErr error
			nextHandle, bindErr = bindDerivedStateDirectory(root, next, nextRelative, opened)
			if bindErr != nil {
				_ = next.Close()
				return fail(bindErr)
			}
		}
		closeNext := func() {
			_ = nextHandle.Close()
			_ = next.Close()
		}

		// Existing entries are also parent-synced. This is the durable replay
		// proof for a coordinate that may have survived a prior failed fsync or
		// a concurrent creator whose completion is not observable here.
		if err := derivedStateDirectorySync(current, nextRelative); err != nil {
			closeNext()
			return fail(fmt.Errorf("sync parent for derived state directory %s: %w", nextRelative, err))
		}
		if created {
			if derivedStateDirectoryAfterSyncHook != nil {
				if err := derivedStateDirectoryAfterSyncHook(nextRelative); err != nil {
					closeNext()
					return fail(err)
				}
			}
		}
		if err := errors.Join(
			verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity),
			verifyBoundDerivedStateDirectory(root, currentHandle, currentRelative, currentIdentity),
			verifyBoundDerivedStateDirectory(root, nextHandle, nextRelative, opened),
		); err != nil {
			closeNext()
			return fail(err)
		}

		_ = currentHandle.Close()
		_ = current.Close()
		current = next
		currentHandle = nextHandle
		currentIdentity = opened
		currentRelative = nextRelative
	}
	if err := errors.Join(
		verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity),
		verifyBoundDerivedStateDirectory(root, currentHandle, currentRelative, currentIdentity),
	); err != nil {
		return fail(err)
	}
	if err := recoverDerivedStateDirectoryStages(root, current, currentHandle, stateRoot, currentRelative, rootIdentity, currentIdentity); err != nil {
		return fail(err)
	}
	return current, currentHandle, currentIdentity, nil
}

func mkdirExactPrivateDerivedStateDirectory(parent *os.Root, name string) error {
	if parent == nil || filepath.Base(name) != name || name == "" || name == "." || name == ".." {
		return errors.New("derived state private directory creation binding is invalid")
	}
	// Owner-mask normalization happens once, before concurrent execution, in
	// umask_unix.go. Never mutate the process-global umask on a live write path.
	return parent.Mkdir(name, 0o700)
}

func createBoundDerivedStateDirectoryStage(root, parent *os.Root, stateRoot, parentRelative string, parentIdentity os.FileInfo) (string, string, *os.Root, *os.File, os.FileInfo, error) {
	if root == nil || parent == nil || stateRoot == "" || !filepath.IsAbs(stateRoot) || parentRelative == "" ||
		parentIdentity == nil || !parentIdentity.IsDir() || parentIdentity.Mode()&os.ModeSymlink != 0 {
		return "", "", nil, nil, nil, errors.New("derived state directory stage binding is invalid")
	}
	for attempt := 0; attempt < 32; attempt++ {
		nonce, err := state.NewTransactionID()
		if err != nil {
			return "", "", nil, nil, nil, err
		}
		name := derivedStateDirectoryStagePrefix + nonce
		stageRelative := filepath.Join(parentRelative, name)
		stageKey := filepath.Join(stateRoot, stageRelative)
		if !claimDerivedStateDirectoryStage(stageKey, parentIdentity) {
			continue
		}
		if err := mkdirExactPrivateDerivedStateDirectory(parent, name); err != nil {
			if errors.Is(err, os.ErrExist) {
				finishDerivedStateDirectoryStage(stageKey, false)
				continue
			}
			finishDerivedStateDirectoryStage(stageKey, true)
			return "", "", nil, nil, nil, err
		}
		before, statErr := parent.Lstat(name)
		if statErr != nil || before == nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
			return name, stageKey, nil, nil, nil, errors.Join(statErr, fmt.Errorf("derived state directory stage %s requires replay recovery after failing real-directory admission", stageRelative))
		}
		stage, openErr := parent.OpenRoot(name)
		if openErr != nil {
			return name, stageKey, nil, nil, nil, fmt.Errorf("derived state directory stage %s requires replay recovery: %w", stageRelative, openErr)
		}
		opened, openedErr := stage.Stat(".")
		after, afterErr := parent.Lstat(name)
		if openedErr != nil || afterErr != nil || opened == nil || after == nil ||
			opened.Mode()&os.ModeSymlink != 0 || after.Mode()&os.ModeSymlink != 0 || !opened.IsDir() || !after.IsDir() ||
			!os.SameFile(before, opened) || !os.SameFile(before, after) {
			_ = stage.Close()
			return name, stageKey, nil, nil, nil, errors.Join(openedErr, afterErr, fmt.Errorf("derived state directory stage %s requires replay recovery after changing while binding", stageRelative))
		}
		handle, bindErr := bindDerivedStateDirectory(root, stage, stageRelative, opened)
		if bindErr != nil {
			_ = stage.Close()
			return name, stageKey, nil, nil, nil, errors.Join(bindErr, fmt.Errorf("derived state directory stage %s requires replay recovery", stageRelative))
		}
		if chmodErr := handle.Chmod(0o700); chmodErr != nil {
			_ = handle.Close()
			_ = stage.Close()
			return name, stageKey, nil, nil, nil, errors.Join(chmodErr, fmt.Errorf("derived state directory stage %s requires replay recovery after private-mode repair", stageRelative))
		}
		hardened, hardenedErr := handle.Stat()
		stageCurrent, stageErr := stage.Stat(".")
		pathCurrent, pathErr := parent.Lstat(name)
		if hardenedErr != nil || stageErr != nil || pathErr != nil || hardened == nil || stageCurrent == nil || pathCurrent == nil ||
			hardened.Mode() != os.ModeDir|0o700 || stageCurrent.Mode() != os.ModeDir|0o700 || pathCurrent.Mode() != os.ModeDir|0o700 ||
			!os.SameFile(before, hardened) || !os.SameFile(before, stageCurrent) || !os.SameFile(before, pathCurrent) ||
			!sameDerivedStateDirectoryAuthority(before, hardened) ||
			!sameDerivedStateDirectoryAuthority(before, stageCurrent) ||
			!sameDerivedStateDirectoryAuthority(before, pathCurrent) {
			_ = handle.Close()
			_ = stage.Close()
			return name, stageKey, nil, nil, nil, errors.Join(hardenedErr, stageErr, pathErr, fmt.Errorf("derived state directory stage %s requires replay recovery after failing exact private mode", stageRelative))
		}
		if err := verifyBoundDerivedStateDirectory(root, handle, stageRelative, hardened); err != nil {
			_ = handle.Close()
			_ = stage.Close()
			return name, stageKey, nil, nil, nil, errors.Join(err, fmt.Errorf("derived state directory stage %s requires replay recovery after mode repair", stageRelative))
		}
		if derivedStateDirectoryAfterStageMkdirHook != nil {
			if err := derivedStateDirectoryAfterStageMkdirHook(stageRelative); err != nil {
				_ = handle.Close()
				_ = stage.Close()
				return name, stageKey, nil, nil, nil, fmt.Errorf("derived state directory stage %s requires replay recovery: %w", stageRelative, err)
			}
		}
		return name, stageKey, stage, handle, hardened, nil
	}
	return "", "", nil, nil, nil, errors.New("cannot allocate a unique derived state directory stage")
}

func recoverDerivedStateDirectoryStages(root, parent *os.Root, parentHandle *os.File, stateRoot, parentRelative string, rootIdentity, parentIdentity os.FileInfo) error {
	if root == nil || parent == nil || parentHandle == nil || stateRoot == "" || parentRelative == "" || rootIdentity == nil || parentIdentity == nil {
		return errors.New("derived state directory stage recovery binding is invalid")
	}
	parentKey := filepath.Join(stateRoot, parentRelative)
	derivedStateDirectoryStageState.Lock()
	defer derivedStateDirectoryStageState.Unlock()
	if cleanIdentity, clean := derivedStateDirectoryStageState.cleanParents[parentKey]; clean {
		if sameCachedDerivedStateDirectoryIdentity(cleanIdentity, parentIdentity) {
			return nil
		}
		delete(derivedStateDirectoryStageState.cleanParents, parentKey)
	}
	if derivedStateDirectoryRecoveryScanHook != nil {
		derivedStateDirectoryRecoveryScanHook(parentRelative)
	}
	observed := make(map[string]struct{})
	directory, err := parent.Open(".")
	if err != nil {
		return err
	}
	closeDirectory := func(cause error) error { return errors.Join(cause, directory.Close()) }
	recordStageFailure := func(stageKey string, cause error) error {
		delete(derivedStateDirectoryStageState.active, stageKey)
		if errors.Is(cause, errDerivedStateDirectoryStagePreserved) {
			delete(derivedStateDirectoryStageState.dirty, stageKey)
		} else {
			derivedStateDirectoryStageState.dirty[stageKey] = struct{}{}
		}
		return closeDirectory(cause)
	}
	preserveChangedCoordinate := func(cause error, name, base string, admitted os.FileInfo) error {
		current, currentErr := parent.Lstat(name)
		if errors.Is(currentErr, os.ErrNotExist) {
			return errors.Join(cause, fmt.Errorf("%w after %s disappeared", errDerivedStateDirectoryStagePreserved, name))
		}
		if currentErr != nil || current == nil || admitted == nil || os.SameFile(admitted, current) {
			return errors.Join(cause, currentErr)
		}
		paths, preserveErr := preserveDerivedStateDirectoryReplacement(parent, parentHandle, base, name)
		if preserveErr != nil {
			return errors.Join(cause, preserveErr)
		}
		return errors.Join(cause, fmt.Errorf("%w at %s", errDerivedStateDirectoryStagePreserved, paths))
	}
	for {
		entries, readErr := directory.ReadDir(128)
		for _, entry := range entries {
			name := entry.Name()
			base, ok := derivedStateDirectoryStageBase(name)
			if !ok {
				continue
			}
			stageKey := filepath.Join(parentKey, base)
			observed[stageKey] = struct{}{}
			if _, active := derivedStateDirectoryStageState.active[stageKey]; active {
				continue
			}
			// Recovery owns this exact stage key until the bound quarantine
			// transaction either commits or returns an error. This closes two
			// concurrent scanners over the same stale directory entry.
			derivedStateDirectoryStageState.active[stageKey] = parentIdentity
			stageRelative := filepath.Join(parentRelative, name)
			before, statErr := parent.Lstat(name)
			if errors.Is(statErr, os.ErrNotExist) {
				delete(derivedStateDirectoryStageState.active, stageKey)
				delete(derivedStateDirectoryStageState.dirty, stageKey)
				if err := errors.Join(
					verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity),
					verifyBoundDerivedStateDirectory(root, parentHandle, parentRelative, parentIdentity),
				); err != nil {
					return closeDirectory(err)
				}
				continue
			}
			recoverableMode := before != nil &&
				(before.Mode() == os.ModeDir|0o700 || before.Mode() == os.ModeDir|os.ModeSetgid|0o700)
			if statErr != nil || before == nil || !recoverableMode {
				return recordStageFailure(stageKey, errors.Join(statErr, fmt.Errorf("derived state directory stage residue %s is not an owner-private crash-recoverable directory", stageRelative)))
			}
			if derivedStateDirectoryRecoveryAfterLstatHook != nil {
				if hookErr := derivedStateDirectoryRecoveryAfterLstatHook(stageRelative); hookErr != nil {
					return recordStageFailure(stageKey, preserveChangedCoordinate(hookErr, name, base, before))
				}
			}
			stage, openErr := parent.OpenRoot(name)
			if openErr != nil {
				return recordStageFailure(stageKey, preserveChangedCoordinate(openErr, name, base, before))
			}
			opened, openedErr := stage.Stat(".")
			after, afterErr := parent.Lstat(name)
			if openedErr != nil || afterErr != nil || opened == nil || after == nil ||
				opened.Mode() != before.Mode() || after.Mode() != before.Mode() ||
				!os.SameFile(before, opened) || !os.SameFile(before, after) {
				_ = stage.Close()
				cause := errors.Join(openedErr, afterErr, fmt.Errorf("derived state directory stage residue %s changed while binding", stageRelative))
				return recordStageFailure(stageKey, preserveChangedCoordinate(cause, name, base, before))
			}
			handle, bindErr := bindDerivedStateDirectory(root, stage, stageRelative, opened)
			if bindErr != nil {
				_ = stage.Close()
				return recordStageFailure(stageKey, preserveChangedCoordinate(bindErr, name, base, before))
			}
			if opened.Mode() != os.ModeDir|0o700 {
				if chmodErr := handle.Chmod(0o700); chmodErr != nil {
					_ = handle.Close()
					_ = stage.Close()
					cause := errors.Join(chmodErr, fmt.Errorf("repair crash residue mode for %s", stageRelative))
					return recordStageFailure(stageKey, preserveChangedCoordinate(cause, name, base, before))
				}
				hardened, hardenedErr := handle.Stat()
				stageCurrent, stageErr := stage.Stat(".")
				pathCurrent, pathErr := parent.Lstat(name)
				if hardenedErr != nil || stageErr != nil || pathErr != nil || hardened == nil || stageCurrent == nil || pathCurrent == nil ||
					hardened.Mode() != os.ModeDir|0o700 || stageCurrent.Mode() != os.ModeDir|0o700 || pathCurrent.Mode() != os.ModeDir|0o700 ||
					!os.SameFile(before, hardened) || !os.SameFile(before, stageCurrent) || !os.SameFile(before, pathCurrent) ||
					!sameDerivedStateDirectoryAuthority(before, hardened) ||
					!sameDerivedStateDirectoryAuthority(before, stageCurrent) ||
					!sameDerivedStateDirectoryAuthority(before, pathCurrent) {
					_ = handle.Close()
					_ = stage.Close()
					cause := errors.Join(hardenedErr, stageErr, pathErr, fmt.Errorf("crash residue %s changed while repairing private mode", stageRelative))
					return recordStageFailure(stageKey, preserveChangedCoordinate(cause, name, base, before))
				}
				opened = hardened
			}
			removeErr := removeExactEmptyDerivedStateDirectory(parent, parentHandle, stage, handle, name, base, opened)
			closeStageErr := errors.Join(handle.Close(), stage.Close())
			delete(derivedStateDirectoryStageState.active, stageKey)
			if removeErr != nil || closeStageErr != nil {
				if errors.Is(removeErr, errDerivedStateDirectoryStagePreserved) && closeStageErr == nil {
					delete(derivedStateDirectoryStageState.dirty, stageKey)
				} else {
					derivedStateDirectoryStageState.dirty[stageKey] = struct{}{}
				}
				return closeDirectory(errors.Join(removeErr, closeStageErr, fmt.Errorf("recover derived state directory stage %s", stageRelative)))
			}
			delete(derivedStateDirectoryStageState.dirty, stageKey)
			if err := errors.Join(
				verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity),
				verifyBoundDerivedStateDirectory(root, parentHandle, parentRelative, parentIdentity),
			); err != nil {
				return closeDirectory(err)
			}
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return closeDirectory(readErr)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
	}
	if err := directory.Close(); err != nil {
		return err
	}
	if err := derivedStateDirectoryParentSync(parentHandle); err != nil {
		return fmt.Errorf("sync derived state directory after recovery scan: %w", err)
	}
	if err := errors.Join(
		verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity),
		verifyBoundDerivedStateDirectory(root, parentHandle, parentRelative, parentIdentity),
	); err != nil {
		return err
	}
	finalIdentity, finalStatErr := parentHandle.Stat()
	finalPathIdentity, finalPathErr := root.Lstat(parentRelative)
	if finalStatErr != nil || finalPathErr != nil || finalIdentity == nil || finalPathIdentity == nil ||
		!os.SameFile(parentIdentity, finalIdentity) || !os.SameFile(parentIdentity, finalPathIdentity) ||
		!sameDerivedStateDirectorySecurity(parentIdentity, finalIdentity) ||
		!sameDerivedStateDirectorySecurity(parentIdentity, finalPathIdentity) {
		return errors.Join(finalStatErr, finalPathErr, errors.New("derived state directory changed after recovery scan"))
	}
	for dirty := range derivedStateDirectoryStageState.dirty {
		if filepath.Dir(dirty) == parentKey {
			if _, exists := observed[dirty]; !exists {
				delete(derivedStateDirectoryStageState.dirty, dirty)
			}
		}
	}
	return nil
}

func preserveDerivedStateDirectoryReplacement(parent *os.Root, parentHandle *os.File, base, source string) (string, error) {
	parsedBase, validBase := derivedStateDirectoryStageBase(base)
	if parent == nil || parentHandle == nil || !validBase || parsedBase != base ||
		filepath.Base(source) != source || source == "" || source == "." || source == ".." {
		return "", errors.New("derived state replacement preservation binding is invalid")
	}
	preservedPaths := make([]string, 0, 2)
	for replacement := 0; replacement < 32; replacement++ {
		before, beforeErr := parent.Lstat(source)
		if errors.Is(beforeErr, os.ErrNotExist) && len(preservedPaths) > 0 {
			return strings.Join(preservedPaths, ","), nil
		}
		if beforeErr != nil || before == nil {
			return strings.Join(preservedPaths, ","), errors.Join(beforeErr, fmt.Errorf("derived state directory replacement retained at %s", source))
		}
		preserved := ""
		for allocation := 0; allocation < 64; allocation++ {
			nonce, nonceErr := state.NewTransactionID()
			if nonceErr != nil {
				nonce = fmt.Sprintf("%032x", atomic.AddUint64(&derivedStateDirectoryPreserveCounter, 1))
			}
			candidate := base + derivedStateDirectoryStagePreservedMarker + nonce
			renameErr := renameYUMCompatibilityCandidateNoReplace(parentHandle.Fd(), source, candidate)
			if errors.Is(renameErr, os.ErrExist) {
				continue
			}
			if renameErr != nil {
				return strings.Join(preservedPaths, ","), errors.Join(renameErr, fmt.Errorf("derived state directory replacement retained at %s", source))
			}
			preserved = candidate
			break
		}
		if preserved == "" {
			return strings.Join(preservedPaths, ","), fmt.Errorf("cannot allocate a preserved derived state directory name for %s", source)
		}
		after, afterErr := parent.Lstat(preserved)
		if afterErr != nil || after == nil || !os.SameFile(before, after) {
			return strings.Join(append(preservedPaths, preserved), ","), errors.Join(afterErr, fmt.Errorf("derived state directory replacement identity changed at %s", preserved))
		}
		preservedPaths = append(preservedPaths, preserved)
		syncErr := derivedStateDirectoryParentSync(parentHandle)
		_, sourceErr := parent.Lstat(source)
		if errors.Is(sourceErr, os.ErrNotExist) {
			if syncErr != nil {
				return strings.Join(preservedPaths, ","), errors.Join(syncErr, fmt.Errorf("sync preserved derived state directory replacement at %s", preserved))
			}
			return strings.Join(preservedPaths, ","), nil
		}
		if sourceErr != nil {
			return strings.Join(preservedPaths, ","), errors.Join(syncErr, sourceErr)
		}
		if syncErr != nil {
			// Preserve the newly observed occupant before reporting the failed
			// durability barrier. A later clean rescan will retry the barrier.
			continue
		}
		// A second actor reoccupied the recoverable source while the first
		// replacement was being preserved. Preserve that identity too.
	}
	return strings.Join(preservedPaths, ","), fmt.Errorf("derived state directory coordinate %s was continuously reoccupied", source)
}

func removeExactEmptyDerivedStateDirectory(parent *os.Root, parentHandle *os.File, stage *os.Root, stageHandle *os.File, coordinate, quarantineBase string, expected os.FileInfo) error {
	base, validBase := derivedStateDirectoryStageBase(quarantineBase)
	if parent == nil || parentHandle == nil || stage == nil || stageHandle == nil || expected == nil ||
		filepath.Base(coordinate) != coordinate || coordinate == "" || coordinate == "." || coordinate == ".." ||
		!validBase || base != quarantineBase || !expected.IsDir() || expected.Mode()&os.ModeSymlink != 0 {
		return errors.New("derived state directory stage removal binding is invalid")
	}
	quarantine := base + derivedStateDirectoryStageQuarantineSuffix
	alreadyQuarantined := coordinate == quarantine
	moved := false
	preserveReplacement := func(source string) (string, error) {
		return preserveDerivedStateDirectoryReplacement(parent, parentHandle, base, source)
	}
	preserveRetiredReplacements := func(cause error, sources ...string) error {
		preserved := make([]string, 0, len(sources))
		seen := make(map[string]struct{}, len(sources))
		for _, source := range sources {
			if _, duplicate := seen[source]; !duplicate {
				seen[source] = struct{}{}
			}
		}
		var lastErr error
		for round := 0; round < 32; round++ {
			for source := range seen {
				_, statErr := parent.Lstat(source)
				if errors.Is(statErr, os.ErrNotExist) {
					continue
				}
				if statErr != nil {
					return errors.Join(cause, statErr)
				}
				paths, preserveErr := preserveReplacement(source)
				if paths != "" {
					preserved = append(preserved, paths)
				}
				lastErr = errors.Join(lastErr, preserveErr)
			}
			syncErr := derivedStateDirectoryParentSync(parentHandle)
			allAbsent := true
			for source := range seen {
				_, statErr := parent.Lstat(source)
				if statErr == nil {
					allAbsent = false
					continue
				}
				if !errors.Is(statErr, os.ErrNotExist) {
					return errors.Join(cause, statErr)
				}
			}
			if allAbsent {
				if syncErr != nil {
					return errors.Join(cause, lastErr, syncErr)
				}
				return errors.Join(cause, fmt.Errorf("%w at %s", errDerivedStateDirectoryStagePreserved, strings.Join(preserved, ",")))
			}
			lastErr = errors.Join(lastErr, syncErr)
			// A later successful parent sync covers all prior preservation
			// renames, so keep draining reoccupations after a transient failure.
		}
		return errors.Join(cause, lastErr, fmt.Errorf("derived state directory recovery coordinates were continuously reoccupied; preserved=%s", strings.Join(preserved, ",")))
	}
	restore := func(cause error) error {
		if !moved {
			return cause
		}
		preserved := make([]string, 0, 1)
		for attempt := 0; attempt < 32; attempt++ {
			restoreErr := renameYUMCompatibilityCandidateNoReplace(parentHandle.Fd(), quarantine, coordinate)
			if restoreErr == nil {
				syncErr := derivedStateDirectoryParentSync(parentHandle)
				restored, restoredErr := parent.Lstat(coordinate)
				quarantined, quarantineErr := parent.Lstat(quarantine)
				if restoredErr == nil && restored != nil && os.SameFile(expected, restored) && errors.Is(quarantineErr, os.ErrNotExist) {
					if len(preserved) > 0 {
						return errors.Join(cause, syncErr, fmt.Errorf("foreign derived state directory replacements preserved at %s", strings.Join(preserved, ",")))
					}
					return errors.Join(cause, syncErr)
				}
				if quarantineErr == nil && quarantined != nil && os.SameFile(expected, quarantined) {
					if restoredErr == nil && restored != nil && !os.SameFile(expected, restored) {
						paths, preserveErr := preserveReplacement(coordinate)
						if preserveErr != nil {
							return errors.Join(cause, syncErr, preserveErr)
						}
						preserved = append(preserved, paths)
					}
					continue
				}
				return preserveRetiredReplacements(
					errors.Join(cause, syncErr, restoredErr, quarantineErr, errors.New("restored derived state directory changed before revalidation")),
					coordinate, quarantine,
				)
			}
			if !errors.Is(restoreErr, os.ErrExist) {
				return errors.Join(cause, restoreErr, fmt.Errorf("derived state directory replacement retained at %s", quarantine))
			}
			paths, preserveErr := preserveReplacement(coordinate)
			if preserveErr != nil {
				return errors.Join(cause, restoreErr, preserveErr, fmt.Errorf("derived state directory replacement retained at %s", quarantine))
			}
			if paths != "" {
				preserved = append(preserved, paths)
			}
		}
		return errors.Join(cause, fmt.Errorf("cannot restore derived state directory quarantine after repeated coordinate reoccupation at %s", coordinate))
	}
	restoreOrPreserve := func(cause error) error {
		current, currentErr := parent.Lstat(quarantine)
		if currentErr == nil && current != nil && os.SameFile(expected, current) {
			return restore(cause)
		}
		if errors.Is(currentErr, os.ErrNotExist) {
			return preserveRetiredReplacements(errors.Join(cause, errors.New("derived state directory quarantine disappeared")), coordinate, quarantine)
		}
		sources := []string{quarantine}
		if moved {
			sources = append(sources, coordinate)
		}
		return preserveRetiredReplacements(errors.Join(cause, currentErr), sources...)
	}
	verifyCoordinate := func(name string) error {
		opened, statErr := stageHandle.Stat()
		current, lstatErr := parent.Lstat(name)
		if statErr != nil || lstatErr != nil || opened == nil || current == nil ||
			opened.Mode()&os.ModeSymlink != 0 || current.Mode()&os.ModeSymlink != 0 || !opened.IsDir() || !current.IsDir() ||
			!os.SameFile(expected, opened) || !os.SameFile(expected, current) {
			return errors.Join(statErr, lstatErr, errors.New("derived state directory stage changed before removal"))
		}
		return nil
	}
	verifyEmpty := func() error {
		directory, err := stage.Open(".")
		if err != nil {
			return err
		}
		entries, readErr := directory.ReadDir(1)
		closeErr := directory.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return errors.Join(readErr, closeErr)
		}
		if len(entries) != 0 {
			return errors.Join(closeErr, errors.New("derived state directory stage is not empty"))
		}
		return closeErr
	}
	verifyAbsent := func(name string) error {
		_, err := parent.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("derived state directory coordinate %s was reoccupied", name)
	}
	if alreadyQuarantined {
		if err := errors.Join(verifyCoordinate(quarantine), verifyEmpty()); err != nil {
			return restoreOrPreserve(err)
		}
	} else {
		if err := errors.Join(verifyCoordinate(coordinate), verifyEmpty()); err != nil {
			current, currentErr := parent.Lstat(coordinate)
			if currentErr == nil && current != nil && !os.SameFile(expected, current) {
				return preserveRetiredReplacements(err, coordinate, quarantine)
			}
			return errors.Join(err, currentErr)
		}
		if err := renameYUMCompatibilityCandidateNoReplace(parentHandle.Fd(), coordinate, quarantine); err != nil {
			return err
		}
		moved = true
		if err := errors.Join(verifyAbsent(coordinate), verifyCoordinate(quarantine), verifyEmpty()); err != nil {
			return restoreOrPreserve(err)
		}
	}
	if err := derivedStateDirectoryParentSync(parentHandle); err != nil {
		return restore(fmt.Errorf("sync derived state directory quarantine: %w", err))
	}
	if derivedStateDirectoryBeforeRemovalHook != nil {
		if err := derivedStateDirectoryBeforeRemovalHook(quarantine); err != nil {
			return restoreOrPreserve(err)
		}
	}
	if err := errors.Join(verifyCoordinate(quarantine), verifyEmpty()); err != nil {
		return restoreOrPreserve(err)
	}
	if moved {
		if err := verifyAbsent(coordinate); err != nil {
			return restore(err)
		}
	}
	if err := parent.Remove(quarantine); err != nil {
		return restore(fmt.Errorf("remove exact derived state directory quarantine: %w", err))
	}
	var postRemoveErr error
	if derivedStateDirectoryAfterRemovalHook != nil {
		if err := derivedStateDirectoryAfterRemovalHook(quarantine); err != nil {
			postRemoveErr = err
		}
	}
	syncErr := derivedStateDirectoryParentSync(parentHandle)
	finalSources := []string{quarantine}
	if moved {
		finalSources = append(finalSources, coordinate)
	}
	var reoccupied []string
	for _, source := range finalSources {
		if err := verifyAbsent(source); err != nil {
			reoccupied = append(reoccupied, source)
		}
	}
	if len(reoccupied) > 0 {
		postRemoveErr = errors.Join(
			postRemoveErr,
			preserveRetiredReplacements(errors.New("derived state directory coordinate was reoccupied after exact removal"), reoccupied...),
		)
	}
	return errors.Join(postRemoveErr, syncErr)
}

func verifyBoundDerivedStateRoot(root *os.Root, path string, expected os.FileInfo) error {
	if root == nil || path == "" || expected == nil {
		return errors.New("derived state root verification binding is invalid")
	}
	opened, statErr := root.Stat(".")
	current, lstatErr := os.Lstat(path)
	if statErr != nil || lstatErr != nil || opened == nil || current == nil ||
		opened.Mode()&os.ModeSymlink != 0 || current.Mode()&os.ModeSymlink != 0 ||
		!opened.IsDir() || !current.IsDir() ||
		!os.SameFile(expected, opened) || !os.SameFile(expected, current) ||
		!sameDerivedStateDirectorySecurity(expected, opened) ||
		!sameDerivedStateDirectorySecurity(expected, current) {
		return errors.Join(statErr, lstatErr, errors.New("derived state root coordinate changed"))
	}
	if err := verifyDerivedStateImmediateParent(path); err != nil {
		return err
	}
	if _, err := admitDerivedStateDirectory(opened, "bound derived state root"); err != nil {
		return err
	}
	if _, err := admitDerivedStateDirectory(current, "current derived state root"); err != nil {
		return err
	}
	return nil
}

func bindDerivedStateDirectory(root, parent *os.Root, relative string, expected os.FileInfo) (*os.File, error) {
	if root == nil || parent == nil || expected == nil || relative == "" || !expected.IsDir() || expected.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("derived state directory binding is invalid")
	}
	directory, err := parent.Open(".")
	if err != nil {
		return nil, err
	}
	if err := verifyBoundDerivedStateDirectory(root, directory, relative, expected); err != nil {
		directory.Close()
		return nil, err
	}
	return directory, nil
}

func verifyBoundDerivedStateDirectory(root *os.Root, directory *os.File, relative string, expected os.FileInfo) error {
	if root == nil || directory == nil || expected == nil || relative == "" {
		return errors.New("derived state directory verification binding is invalid")
	}
	opened, statErr := directory.Stat()
	current, lstatErr := root.Lstat(relative)
	if statErr != nil || lstatErr != nil || opened == nil || current == nil ||
		opened.Mode()&os.ModeSymlink != 0 || current.Mode()&os.ModeSymlink != 0 ||
		!opened.IsDir() || !current.IsDir() ||
		!os.SameFile(expected, opened) || !os.SameFile(expected, current) ||
		!sameDerivedStateDirectorySecurity(expected, opened) ||
		!sameDerivedStateDirectorySecurity(expected, current) {
		return errors.Join(statErr, lstatErr, errors.New("derived state directory coordinate changed"))
	}
	if _, err := admitDerivedStateDirectory(opened, "bound derived state control directory"); err != nil {
		return err
	}
	if _, err := admitDerivedStateDirectory(current, "current derived state control directory"); err != nil {
		return err
	}
	return nil
}

func verifyExactDerivedStateBytes(file *os.File, expected os.FileInfo, expectedDigest [sha256.Size]byte) error {
	if file == nil || expected == nil || expected.Size() < 0 {
		return errors.New("derived state byte verification binding is invalid")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	hasher := sha256.New()
	written, readErr := io.CopyBuffer(hasher, io.LimitReader(file, expected.Size()+1), make([]byte, 256*1024))
	after, statErr := file.Stat()
	var actual [sha256.Size]byte
	copy(actual[:], hasher.Sum(nil))
	if readErr != nil || statErr != nil || after == nil || written != expected.Size() || actual != expectedDigest ||
		!os.SameFile(expected, after) || after.Size() != expected.Size() ||
		after.Mode() != expected.Mode() || !after.ModTime().Equal(expected.ModTime()) ||
		!sameDerivedStateControlFileSecurity(expected, after) {
		return errors.Join(readErr, statErr, errors.New("derived state install candidate bytes changed before publication"))
	}
	return nil
}

func removeExactDerivedStateTemporary(parent *os.Root, name string, expected os.FileInfo) error {
	if parent == nil || expected == nil || filepath.Base(name) != name || name == "" || name == "." {
		return errors.New("derived state temporary cleanup binding is invalid")
	}
	current, err := parent.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() ||
		current.Mode().Perm()&0o077 != 0 || !os.SameFile(expected, current) {
		return errors.Join(err, errors.New("derived state temporary was replaced; refuse cleanup"))
	}
	if _, err := admitDerivedStateControlFile(current, fmt.Sprintf("derived state temporary %s", name)); err != nil {
		return err
	}
	file, err := parent.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, statErr := file.Stat()
	current, lstatErr := parent.Lstat(name)
	if statErr != nil || lstatErr != nil || opened == nil || current == nil ||
		!os.SameFile(expected, opened) || !os.SameFile(expected, current) ||
		!sameDerivedStateControlFileSecurity(expected, opened) ||
		!sameDerivedStateControlFileSecurity(expected, current) {
		return errors.Join(statErr, lstatErr, errors.New("derived state temporary changed before cleanup"))
	}
	directory, err := parent.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return commitExactPrivateStateFileRemoval(parent, directory, file, expected, name, func() error {
		after, err := file.Stat()
		if err != nil || after == nil || !os.SameFile(expected, after) ||
			after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() || after.Mode().Perm()&0o077 != 0 ||
			!sameDerivedStateControlFileSecurity(expected, after) {
			return errors.Join(err, errors.New("derived state temporary changed during cleanup"))
		}
		return nil
	})
}

func hashReader(reader io.ReadCloser) (string, error) {
	hasher := sha256.New()
	_, copyErr := io.Copy(hasher, reader)
	closeErr := reader.Close()
	if copyErr != nil || closeErr != nil {
		return "", errors.Join(copyErr, closeErr)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func writeExclusiveBytes(filename string, data []byte) error {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	return errors.Join(writeErr, file.Sync(), file.Close())
}
