package managed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

type PublishOptions struct {
	WorkspaceOptions
	LockOptions
	Target  string
	Fault   func(string) error
	backend publicationBackend
	now     func() time.Time
}

type PublishResult struct {
	Repository string             `json:"repository"`
	Target     string             `json:"target"`
	Provider   string             `json:"provider"`
	Generation state.GenerationID `json:"generation"`
	Attempt    string             `json:"attempt,omitempty"`
	Checkpoint string             `json:"checkpoint,omitempty"`
	Phase      string             `json:"phase"`
	Objects    int                `json:"objects"`
	Noop       bool               `json:"noop"`
}

type PublicationAbandonOptions struct {
	WorkspaceOptions
	LockOptions
	Target  string
	backend publicationBackend
}

type PublicationAbandonResult struct {
	Repository string `json:"repository"`
	Target     string `json:"target"`
	Provider   string `json:"provider"`
	Attempt    string `json:"attempt"`
	Phase      string `json:"phase"`
	Objects    int    `json:"objects"`
}

func Publish(ctx context.Context, opts PublishOptions) (result PublishResult, resultErr error) {
	if ctx == nil || opts.Target == "" {
		return result, fmt.Errorf("%w: publish requires a context and target", ErrRejected)
	}
	ws, _, rootGuard, err := workspace(opts.WorkspaceOptions)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, rootGuard.Close()) }()
	cfg, _, repoName, workspaceLock, repoLock, err := acquirePublicationLocks(ctx, ws, opts.Target, opts.LockOptions)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close(), repoLock.Close()) }()
	targetConfig, configured := cfg.Targets[opts.Target]
	if !configured || targetConfig.Repository != repoName {
		return result, fmt.Errorf("%w: target %q is not bound to selected repository", ErrRejected, opts.Target)
	}
	result.Repository, result.Target, result.Provider = repoName, opts.Target, targetConfig.Provider
	store, err := openExistingState(filepath.Join(ws.Root, ".sow", repoName+".db"))
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	if err := store.RequireTerminalLayout(ctx); err != nil {
		return result, fmt.Errorf("%w: publish is unavailable during layout transition: %v", ErrNotReady, err)
	}
	observedAt := publicationObservedTime(opts.now)
	if err := store.ObserveRepositoryTime(ctx, observedAt); err != nil {
		return result, fmt.Errorf("%w: publish clock preflight: %v", ErrIntegrity, err)
	}
	if err := recoverDistOperations(ctx, ws.Root, repoName, store); err != nil {
		return result, err
	}
	identity, err := store.RepositoryIdentity(ctx)
	if err != nil {
		return result, err
	}
	binding, err := publicationTargetBinding(cfg, opts.Target, identity.RepositoryID)
	if err != nil {
		return result, err
	}
	if err := store.BindPublicationTarget(ctx, binding); err != nil {
		return result, fmt.Errorf("%w: bind publication target: %v", ErrIntegrity, err)
	}
	pendingMaintenance, err := store.HasPendingPublicationMaintenance(ctx, binding.TargetIdentity)
	if err != nil {
		return result, err
	}
	if pendingMaintenance {
		return result, fmt.Errorf("%w: target %q has an unfinished candidate report; resume with gc %s", ErrNotReady, opts.Target, opts.Target)
	}
	if targetConfig.Provider == "filesystem" {
		targetRoot, err := filesystemPublicationRoot(targetConfig)
		if err != nil {
			return result, err
		}
		if err := rejectPublicationSourceTargetOverlap(filepath.Join(ws.Root, repoName), filepath.Join(ws.Root, ".sow"), targetRoot); err != nil {
			return result, err
		}
	}
	backend := opts.backend
	if backend == nil {
		backend, err = newPublicationBackend(targetConfig)
		if err != nil {
			return result, err
		}
	} else if backend.Provider() != targetConfig.Provider {
		return result, fmt.Errorf("%w: publication backend provider differs from target", ErrRejected)
	}
	active, activeErr := store.GetActivePublicationAttempt(ctx, binding.TargetIdentity)
	if activeErr == nil && active.Phase == "applied" {
		checkpoint, err := store.GetAppliedCheckpointForAttempt(ctx, active.AttemptIdentity)
		if err != nil {
			return result, err
		}
		if err := verifyPublishedGeneration(ctx, backend, store, checkpoint.Generation, checkpoint.ManifestSHA256); err != nil {
			return result, err
		}
		if err := putPublicationGrace(ctx, store, binding, checkpoint); err != nil {
			return result, err
		}
		if err := callFault(opts.Fault, "publish.grace"); err != nil {
			return result, err
		}
		result.Generation, result.Attempt, result.Checkpoint, result.Phase = checkpoint.Generation, active.AttemptIdentity, checkpoint.CheckpointIdentity, "grace"
		result.Objects = len(checkpoint.Inventory)
		return result, nil
	}
	if activeErr != nil && !errors.Is(activeErr, state.ErrNotFound) {
		return result, activeErr
	}
	targetGeneration, targetManifest, manifestSHA, err := publicationSourceGeneration(ctx, ws.Root, repoName, store, active, activeErr == nil)
	if err != nil {
		return result, err
	}
	result.Generation = targetGeneration
	targetSnapshot, err := store.GetPublicationTarget(ctx, binding.TargetIdentity)
	if err != nil {
		return result, err
	}
	baseManifest := []state.GenerationFile{}
	baseInventory := []state.PublicationInventoryObject{}
	if targetSnapshot.Head.CheckpointIdentity != "" {
		checkpoint, err := store.GetAppliedCheckpoint(ctx, targetSnapshot.Head.CheckpointIdentity)
		if err != nil {
			return result, err
		}
		if checkpoint.TargetIdentity != binding.TargetIdentity || checkpoint.RepositoryID != identity.RepositoryID || checkpoint.Generation != targetSnapshot.Head.Generation || checkpoint.ManifestSHA256 != targetSnapshot.Head.ManifestSHA256 {
			return result, fmt.Errorf("%w: target head and checkpoint differ", ErrIntegrity)
		}
		baseManifest, err = store.GenerationManifest(ctx, checkpoint.Generation)
		if err != nil {
			return result, err
		}
		baseInventory, err = store.PublicationLiveInventory(ctx, checkpoint.CheckpointIdentity)
		if err != nil {
			return result, err
		}
	}
	changes := state.DiffManifests(baseManifest, targetManifest)
	plan, err := state.BuildPublicationPlan(state.PublicationPlanInput{
		RepositoryID: identity.RepositoryID, TargetIdentity: binding.TargetIdentity,
		BaseCheckpoint: targetSnapshot.Head.CheckpointIdentity, TargetGeneration: targetGeneration,
		BaseManifest: baseManifest, TargetManifest: targetManifest, Changes: changes,
	})
	if err != nil {
		return result, fmt.Errorf("%w: build target publication plan: %v", ErrIntegrity, err)
	}
	ignoredStages := publicationStagePaths(plan, active.AttemptIdentity, activeErr == nil)
	remoteBefore, err := backend.List(ctx, ignoredStages)
	if err != nil {
		return result, err
	}
	orphans, err := store.ListPublicationAbandonedObjects(ctx, binding.TargetIdentity)
	if err != nil {
		return result, err
	}
	baseInventory, err = recognizePublicationAbandonedObjects(remoteBefore, baseInventory, orphans)
	if err != nil {
		return result, err
	}
	if activeErr != nil {
		if err := requireExactRemoteInventory(remoteBefore, baseInventory); err != nil {
			return result, err
		}
		if len(changes) == 0 {
			if err := verifyPublishedGeneration(ctx, backend, store, targetGeneration, manifestSHA); err != nil {
				return result, err
			}
			result.Checkpoint, result.Phase, result.Objects, result.Noop = targetSnapshot.Head.CheckpointIdentity, "applied", len(remoteBefore), true
			return result, nil
		}
	} else {
		if active.RepositoryID != identity.RepositoryID || active.TargetIdentity != binding.TargetIdentity || active.BaseCheckpoint != plan.BaseCheckpoint || active.TargetGeneration != plan.TargetGeneration || active.ManifestSHA256 != plan.ManifestSHA256 || active.PlanSHA256 != plan.PlanSHA256 {
			return result, fmt.Errorf("%w: active publication attempt differs from the only recoverable plan", ErrIntegrity)
		}
		if err := requireRecoverableRemoteInventory(remoteBefore, baseInventory, targetManifest); err != nil {
			return result, err
		}
	}
	attemptViews := publicationAttemptViews(plan, baseInventory)
	if activeErr != nil {
		active = state.PublicationAttempt{
			RepositoryID: identity.RepositoryID, TargetIdentity: binding.TargetIdentity,
			BaseCheckpoint: plan.BaseCheckpoint, TargetGeneration: targetGeneration,
			ManifestSHA256: manifestSHA, PlanSHA256: plan.PlanSHA256, Phase: "planned", Views: attemptViews,
		}
		if err := store.PutPublicationAttempt(ctx, &active); err != nil {
			return result, err
		}
		result.Attempt = active.AttemptIdentity
		if err := callFault(opts.Fault, "publish.attempt"); err != nil {
			return result, err
		}
	} else if !sameAttemptViewIntent(active.Views, attemptViews) {
		return result, fmt.Errorf("%w: active publication view intent differs from plan", ErrIntegrity)
	}
	result.Attempt = active.AttemptIdentity
	for _, operation := range plan.Payload {
		if _, err := backend.Put(ctx, filepath.Join(ws.Root, repoName), operation, active.AttemptIdentity); err != nil {
			return result, err
		}
	}
	if err := store.AdvancePublicationAttemptPhase(ctx, active.AttemptIdentity, "payload"); err != nil {
		return result, err
	}
	if err := callFault(opts.Fault, "publish.payload"); err != nil {
		return result, err
	}
	for _, operation := range plan.ImmutableMetadata {
		if _, err := backend.Put(ctx, filepath.Join(ws.Root, repoName), operation, active.AttemptIdentity); err != nil {
			return result, err
		}
	}
	if err := store.AdvancePublicationAttemptPhase(ctx, active.AttemptIdentity, "immutable_metadata"); err != nil {
		return result, err
	}
	if err := callFault(opts.Fault, "publish.immutable_metadata"); err != nil {
		return result, err
	}
	if err := store.AdvancePublicationAttemptPhase(ctx, active.AttemptIdentity, "pointer_prepared"); err != nil {
		return result, err
	}
	for _, view := range attemptViews {
		if err := store.SetPublicationAttemptViewState(ctx, active.AttemptIdentity, view.ViewID, view.PointerPath, "prepared"); err != nil {
			return result, err
		}
	}
	if err := callFault(opts.Fault, "publish.pointer_prepared"); err != nil {
		return result, err
	}
	if err := store.SetPublicationCommitIntent(ctx, active.AttemptIdentity); err != nil {
		return result, err
	}
	if err := callFault(opts.Fault, "publish.commit_intent"); err != nil {
		return result, err
	}
	// APT stable compatibility aliases are mutable public names. They belong
	// after durable commit intent even though Release/InRelease remain the
	// protocol commit pointers; otherwise a pre-commit abandon could strand an
	// alias whose bytes no longer match the old Release file.
	for _, operation := range plan.StableAliases {
		if _, err := backend.Put(ctx, filepath.Join(ws.Root, repoName), operation, active.AttemptIdentity); err != nil {
			return result, err
		}
	}
	for _, unit := range plan.CommitUnits {
		for _, operation := range unit.Pointers {
			if err := callFault(opts.Fault, "publish.pointer.before."+operation.Path); err != nil {
				return result, err
			}
			if _, err := backend.Put(ctx, filepath.Join(ws.Root, repoName), operation, active.AttemptIdentity); err != nil {
				return result, err
			}
			if err := callFault(opts.Fault, "publish.pointer.written."+operation.Path); err != nil {
				return result, err
			}
			if err := store.SetPublicationAttemptViewState(ctx, active.AttemptIdentity, unit.ViewID, operation.Path, "applied"); err != nil {
				return result, err
			}
			if err := callFault(opts.Fault, "publish.pointer.recorded."+operation.Path); err != nil {
				return result, err
			}
		}
	}
	if err := store.AdvancePublicationAttemptPhase(ctx, active.AttemptIdentity, "pointer_rollforward"); err != nil {
		return result, err
	}
	for _, file := range targetManifest {
		object, ok, err := backend.Head(ctx, file.Path)
		if err != nil || !ok || object.Size != file.Size || object.SHA256 != file.SHA256 {
			return result, errors.Join(fmt.Errorf("%w: target verification failed for %q", ErrIntegrity, file.Path), err)
		}
	}
	for _, view := range attemptViews {
		if err := store.SetPublicationAttemptViewState(ctx, active.AttemptIdentity, view.ViewID, view.PointerPath, "verified"); err != nil {
			return result, err
		}
	}
	if err := store.AdvancePublicationAttemptPhase(ctx, active.AttemptIdentity, "verified"); err != nil {
		return result, err
	}
	if err := callFault(opts.Fault, "publish.verified"); err != nil {
		return result, err
	}
	remoteAfter, err := backend.List(ctx, nil)
	if err != nil {
		return result, err
	}
	inventory, err := publicationInventory(remoteAfter, targetManifest, baseInventory)
	if err != nil {
		return result, err
	}
	checkpointViews, err := publicationCheckpointViews(ctx, backend, attemptViews)
	if err != nil {
		return result, err
	}
	for _, file := range targetManifest {
		if err := backend.VerifyPublic(ctx, file); err != nil {
			return result, err
		}
	}
	appliedAt := publicationObservedTime(opts.now)
	if err := store.ObserveRepositoryTime(ctx, appliedAt); err != nil {
		return result, fmt.Errorf("%w: publish checkpoint clock: %v", ErrIntegrity, err)
	}
	checkpoint := state.AppliedCheckpoint{
		RepositoryID: identity.RepositoryID, TargetIdentity: binding.TargetIdentity,
		AttemptIdentity: active.AttemptIdentity, Generation: targetGeneration, ManifestSHA256: manifestSHA,
		InventoryComplete: true, Views: checkpointViews, Inventory: inventory, AppliedAt: appliedAt,
	}
	if err := store.PutAppliedCheckpoint(ctx, &checkpoint); err != nil {
		return result, err
	}
	if err := callFault(opts.Fault, "publish.checkpoint"); err != nil {
		return result, err
	}
	if err := putPublicationGrace(ctx, store, binding, checkpoint); err != nil {
		return result, err
	}
	if err := callFault(opts.Fault, "publish.grace"); err != nil {
		return result, err
	}
	result.Checkpoint, result.Phase, result.Objects = checkpoint.CheckpointIdentity, "grace", len(inventory)
	return result, nil
}

func publicationObservedTime(now func() time.Time) time.Time {
	if now != nil {
		return now().UTC()
	}
	return time.Now().UTC()
}

// AbandonPublication abandons only a reconciled pre-commit attempt. Payload
// and checksum-addressed metadata already uploaded as create-only objects are
// retained as exact private inventory evidence; no object is copied or
// deleted, and mutable aliases/pointers are never eligible.
func AbandonPublication(ctx context.Context, opts PublicationAbandonOptions) (result PublicationAbandonResult, resultErr error) {
	if ctx == nil || opts.Target == "" {
		return result, fmt.Errorf("%w: publication abandon requires a context and target", ErrRejected)
	}
	ws, _, rootGuard, err := workspace(opts.WorkspaceOptions)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, rootGuard.Close()) }()
	cfg, _, repoName, workspaceLock, repoLock, err := acquirePublicationLocks(ctx, ws, opts.Target, opts.LockOptions)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close(), repoLock.Close()) }()
	targetConfig := cfg.Targets[opts.Target]
	result.Repository, result.Target, result.Provider = repoName, opts.Target, targetConfig.Provider
	store, err := openExistingState(filepath.Join(ws.Root, ".sow", repoName+".db"))
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	if err := store.RequireTerminalLayout(ctx); err != nil {
		return result, fmt.Errorf("%w: publication abandon requires terminal Repository layout: %v", ErrNotReady, err)
	}
	identity, err := store.RepositoryIdentity(ctx)
	if err != nil {
		return result, err
	}
	binding, err := publicationTargetBinding(cfg, opts.Target, identity.RepositoryID)
	if err != nil {
		return result, err
	}
	active, err := store.GetActivePublicationAttempt(ctx, binding.TargetIdentity)
	if err != nil {
		return result, err
	}
	if active.CommitIntent {
		return result, fmt.Errorf("%w: publication attempt %s has commit intent and must roll forward", ErrRejected, active.AttemptIdentity)
	}
	backend := opts.backend
	if backend == nil {
		backend, err = newPublicationBackend(targetConfig)
		if err != nil {
			return result, err
		}
	} else if backend.Provider() != targetConfig.Provider {
		return result, fmt.Errorf("%w: publication backend provider differs from target", ErrRejected)
	}
	targetManifest, err := store.GenerationManifest(ctx, active.TargetGeneration)
	if err != nil {
		return result, err
	}
	baseManifest := []state.GenerationFile{}
	baseInventory := []state.PublicationInventoryObject{}
	if active.BaseCheckpoint != "" {
		checkpoint, err := store.GetAppliedCheckpoint(ctx, active.BaseCheckpoint)
		if err != nil {
			return result, err
		}
		baseManifest, err = store.GenerationManifest(ctx, checkpoint.Generation)
		if err != nil {
			return result, err
		}
		baseInventory, err = store.PublicationLiveInventory(ctx, active.BaseCheckpoint)
		if err != nil {
			return result, err
		}
	}
	plan, err := state.BuildPublicationPlan(state.PublicationPlanInput{
		RepositoryID: identity.RepositoryID, TargetIdentity: binding.TargetIdentity,
		BaseCheckpoint: active.BaseCheckpoint, TargetGeneration: active.TargetGeneration,
		BaseManifest: baseManifest, TargetManifest: targetManifest,
		Changes: state.DiffManifests(baseManifest, targetManifest),
	})
	if err != nil || plan.PlanSHA256 != active.PlanSHA256 || plan.ManifestSHA256 != active.ManifestSHA256 {
		return result, errors.Join(fmt.Errorf("%w: publication abandon plan differs from active attempt", ErrIntegrity), err)
	}
	preCommit := append(append([]state.PublicationPlanOperation{}, plan.Payload...), plan.ImmutableMetadata...)
	if filesystem, ok := backend.(*filesystemPublicationBackend); ok {
		for _, operation := range preCommit {
			if err := filesystem.removeStageIfPresent(ctx, filesystemStagePath(operation.Path, active.AttemptIdentity)); err != nil {
				return result, err
			}
		}
	}
	remote, err := backend.List(ctx, nil)
	if err != nil {
		return result, err
	}
	objects, err := reconcileAbandonedPublicationInventory(remote, baseInventory, preCommit)
	if err != nil {
		return result, err
	}
	if err := store.AbandonPublicationAttempt(ctx, active.AttemptIdentity, objects); err != nil {
		return result, err
	}
	result.Attempt, result.Phase, result.Objects = active.AttemptIdentity, "abandoned", len(objects)
	return result, nil
}

func acquirePublicationLocks(ctx context.Context, ws config.Workspace, target string, opts LockOptions) (config.Config, string, string, *fileLock, *fileLock, error) {
	preflight, err := config.LoadWorkspace(ws)
	if err != nil {
		return config.Config{}, "", "", nil, nil, err
	}
	targetConfig, ok := preflight.Targets[target]
	if !ok {
		return config.Config{}, "", "", nil, nil, fmt.Errorf("%w: target %q is not configured", ErrRejected, target)
	}
	cfg, sha, repo, workspaceLock, repoLock, err := acquireSelectedRepositoryLocks(ctx, ws, targetConfig.Repository, opts)
	if err != nil {
		return config.Config{}, "", "", nil, nil, err
	}
	if locked, ok := cfg.Targets[target]; !ok || locked.Repository != repo || locked != targetConfig {
		return config.Config{}, "", "", nil, nil, errors.Join(fmt.Errorf("%w: target configuration changed while acquiring locks", ErrIntegrity), repoLock.Close(), workspaceLock.Close())
	}
	physicalRoots := map[string]string{}
	for name, candidate := range cfg.Targets {
		if candidate.Provider != "filesystem" {
			continue
		}
		root, rootErr := filesystemPublicationRoot(candidate)
		if rootErr != nil {
			return config.Config{}, "", "", nil, nil, errors.Join(fmt.Errorf("%w: filesystem target %q: %v", ErrRejected, name, rootErr), repoLock.Close(), workspaceLock.Close())
		}
		for otherName, otherRoot := range physicalRoots {
			if pathsOverlap(root, otherRoot) {
				return config.Config{}, "", "", nil, nil, errors.Join(fmt.Errorf("%w: filesystem targets %q and %q overlap physically", ErrRejected, name, otherName), repoLock.Close(), workspaceLock.Close())
			}
		}
		physicalRoots[name] = root
	}
	return cfg, sha, repo, workspaceLock, repoLock, nil
}

func publicationTargetBinding(cfg config.Config, targetName, repositoryID string) (state.PublicationTargetBinding, error) {
	bindings, err := cfg.TargetBindings()
	if err != nil {
		return state.PublicationTargetBinding{}, err
	}
	for _, binding := range bindings {
		if binding.Name != targetName {
			continue
		}
		target := cfg.Targets[targetName]
		ttl, err := time.ParseDuration(target.MaxCacheTTL)
		if err != nil {
			return state.PublicationTargetBinding{}, err
		}
		return state.PublicationTargetBinding{
			TargetIdentity: binding.TargetIdentity, TargetStorageID: binding.StorageIdentity,
			RepositoryID: repositoryID, TargetName: targetName, Provider: binding.Provider,
			Endpoint: binding.Endpoint, Region: binding.Region, Bucket: binding.Bucket, Prefix: binding.Prefix,
			PublicEndpoint: target.PublicEndpoint, MaxCacheTTL: ttl,
			AuthoritativeWorkspace: target.AuthoritativeWorkspace, SingleWriter: target.SingleWriter,
			ExclusiveWriteAuthority: target.ExclusiveWriteAuthority,
		}, nil
	}
	return state.PublicationTargetBinding{}, fmt.Errorf("%w: target %q has no canonical binding", ErrRejected, targetName)
}

func projectedPublicationPointers(cfg config.Config, repoName string, dists []mutationBuildDist) map[string]struct{} {
	result := map[string]struct{}{}
	for _, dist := range dists {
		if cfg.Repositories[repoName].Dists[dist.Name].Format == "deb" {
			root := filepath.ToSlash(filepath.Join("dists", dist.Name))
			result[root+"/Release"] = struct{}{}
			if dist.MetadataSignerFingerprint != "" {
				result[root+"/Release.gpg"] = struct{}{}
				result[root+"/InRelease"] = struct{}{}
			}
			continue
		}
		for _, architecture := range dist.Architectures {
			root := filepath.ToSlash(filepath.Join("dists", dist.Name, architecture.Family, "repodata"))
			result[root+"/repomd.xml"] = struct{}{}
			if dist.MetadataSignerFingerprint != "" {
				result[root+"/repomd.xml.asc"] = struct{}{}
			}
		}
	}
	return result
}

// rejectPublishedPointerWithdrawal prevents an ordinary local mutation from
// creating a Generation that the configured target protocol cannot publish.
// A target can be deliberately retired/unbound in workspace config first;
// while it remains configured, every pointer in its applied checkpoint for an
// affected Dist must remain present in the prospective view.
func rejectPublishedPointerWithdrawal(ctx context.Context, cfg config.Config, repoName string, store *state.Store, affectedDists []string, prospective map[string]struct{}) error {
	if len(affectedDists) == 0 {
		return nil
	}
	identity, err := store.RepositoryIdentity(ctx)
	if err != nil {
		return err
	}
	affected := make(map[string]struct{}, len(affectedDists))
	for _, dist := range affectedDists {
		affected[filepath.ToSlash(filepath.Join("dists", dist))] = struct{}{}
	}
	for targetName, targetConfig := range cfg.Targets {
		if targetConfig.Repository != repoName {
			continue
		}
		binding, err := publicationTargetBinding(cfg, targetName, identity.RepositoryID)
		if err != nil {
			return err
		}
		target, err := store.GetPublicationTarget(ctx, binding.TargetIdentity)
		if errors.Is(err, state.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if target.Head.CheckpointIdentity == "" {
			continue
		}
		checkpoint, err := store.GetAppliedCheckpoint(ctx, target.Head.CheckpointIdentity)
		if err != nil {
			return err
		}
		for _, view := range checkpoint.Views {
			touches := false
			for prefix := range affected {
				if view.ViewID == prefix || strings.HasPrefix(view.ViewID, prefix+"/") {
					touches = true
					break
				}
			}
			if !touches {
				continue
			}
			if _, kept := prospective[view.PointerPath]; !kept {
				return fmt.Errorf("%w: mutation would withdraw published pointer %q from configured target %q; retire or move that target binding/prefix before removing the view, architecture, or signing companion", ErrRejected, view.PointerPath, targetName)
			}
		}
	}
	return nil
}

func newPublicationBackend(target config.TargetConfig) (publicationBackend, error) {
	switch target.Provider {
	case "filesystem":
		return newFilesystemPublicationBackend(target)
	case "r2":
		return newR2PublicationBackend(target)
	default:
		return nil, fmt.Errorf("%w: unsupported publication provider %q", ErrRejected, target.Provider)
	}
}

func publicationSourceGeneration(ctx context.Context, root, repoName string, store *state.Store, active state.PublicationAttempt, recovering bool) (state.GenerationID, []state.GenerationFile, string, error) {
	summary, err := store.Summary(ctx)
	if err != nil {
		return 0, nil, "", err
	}
	generation := summary.BuiltGeneration
	if recovering {
		generation = active.TargetGeneration
	}
	if generation == 0 {
		return 0, nil, "", fmt.Errorf("%w: repository has no Built Generation", ErrNotReady)
	}
	manifest, err := store.GenerationManifest(ctx, generation)
	if err != nil {
		return 0, nil, "", err
	}
	physical, err := scanPublicManifest(ctx, filepath.Join(root, repoName))
	if err != nil || !sameGenerationManifest(manifest, physical) {
		return 0, nil, "", errors.Join(fmt.Errorf("%w: publication source is not the exact target Generation", ErrIntegrity), err)
	}
	_, digest, err := state.ManifestBytes(manifest)
	return generation, manifest, digest, err
}

func rejectPublicationSourceTargetOverlap(source, private, target string) error {
	physicalTarget, _, err := prospectiveRealDirectory(target)
	if err != nil || physicalTarget != filepath.Clean(target) {
		return fmt.Errorf("%w: filesystem publish prefix is not a canonical physical path: %v", ErrRejected, err)
	}
	for _, rawProtected := range []string{source, private} {
		protected, _, physicalErr := prospectiveRealDirectory(rawProtected)
		if physicalErr != nil {
			return physicalErr
		}
		rel, err := filepath.Rel(protected, physicalTarget)
		inside := err == nil && (rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
		reverse, reverseErr := filepath.Rel(physicalTarget, protected)
		contains := reverseErr == nil && (reverse == "." || reverse != ".." && !strings.HasPrefix(reverse, ".."+string(filepath.Separator)))
		if inside || contains {
			return fmt.Errorf("%w: filesystem publish prefix overlaps Repository/private state", ErrRejected)
		}
	}
	return nil
}

func pathsOverlap(left, right string) bool {
	rel, leftErr := filepath.Rel(left, right)
	reverse, rightErr := filepath.Rel(right, left)
	return leftErr == nil && (rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) ||
		rightErr == nil && (reverse == "." || reverse != ".." && !strings.HasPrefix(reverse, ".."+string(filepath.Separator)))
}

func publicationStagePaths(plan state.PublicationPlan, attemptIdentity string, active bool) map[string]struct{} {
	result := map[string]struct{}{}
	if !active || len(attemptIdentity) != 64 {
		return result
	}
	appendOperations := func(operations []state.PublicationPlanOperation) {
		for _, operation := range operations {
			if operation.Operation == "add" || operation.Operation == "update" {
				result[filesystemStagePath(operation.Path, attemptIdentity)] = struct{}{}
			}
		}
	}
	appendOperations(plan.Payload)
	appendOperations(plan.ImmutableMetadata)
	appendOperations(plan.StableAliases)
	for _, unit := range plan.CommitUnits {
		appendOperations(unit.Pointers)
	}
	return result
}

func requireExactRemoteInventory(remote []publicationRemoteObject, expected []state.PublicationInventoryObject) error {
	if len(remote) != len(expected) {
		return fmt.Errorf("%w: remote prefix inventory count differs from private checkpoint", ErrIntegrity)
	}
	for index := range remote {
		if remote[index].Path != expected[index].Path || remote[index].Size != expected[index].Size || remote[index].SHA256 != expected[index].SHA256 || remote[index].RemoteIdentity != expected[index].RemoteIdentity {
			return fmt.Errorf("%w: remote prefix differs from private checkpoint at %q", ErrIntegrity, remote[index].Path)
		}
	}
	return nil
}

func recognizePublicationAbandonedObjects(remote []publicationRemoteObject, base []state.PublicationInventoryObject, abandoned []state.PublicationAbandonedObject) ([]state.PublicationInventoryObject, error) {
	baseByPath := make(map[string]state.PublicationInventoryObject, len(base))
	abandonedByPath := make(map[string]state.PublicationAbandonedObject, len(abandoned))
	result := append([]state.PublicationInventoryObject(nil), base...)
	for _, object := range base {
		baseByPath[object.Path] = object
	}
	for _, object := range abandoned {
		abandonedByPath[object.Path] = object
	}
	for _, object := range remote {
		if prior, ok := baseByPath[object.Path]; ok {
			if prior.Size != object.Size || prior.SHA256 != object.SHA256 || prior.RemoteIdentity != object.RemoteIdentity {
				return nil, fmt.Errorf("%w: remote base object %q changed", ErrIntegrity, object.Path)
			}
			continue
		}
		orphan, ok := abandonedByPath[object.Path]
		if !ok || orphan.Size != object.Size || orphan.SHA256 != object.SHA256 || orphan.RemoteIdentity != object.RemoteIdentity {
			continue // The exact-inventory check reports the unknown path.
		}
		result = append(result, state.PublicationInventoryObject(orphan))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, nil
}

func reconcileAbandonedPublicationInventory(remote []publicationRemoteObject, base []state.PublicationInventoryObject, eligible []state.PublicationPlanOperation) ([]state.PublicationAbandonedObject, error) {
	baseByPath := make(map[string]state.PublicationInventoryObject, len(base))
	eligibleByPath := make(map[string]state.PublicationPlanOperation, len(eligible))
	seenBase := make(map[string]struct{}, len(base))
	for _, object := range base {
		baseByPath[object.Path] = object
	}
	for _, operation := range eligible {
		if operation.Operation == "add" {
			eligibleByPath[operation.Path] = operation
		}
	}
	result := []state.PublicationAbandonedObject{}
	for _, object := range remote {
		if prior, ok := baseByPath[object.Path]; ok {
			if prior.Size != object.Size || prior.SHA256 != object.SHA256 || prior.RemoteIdentity != object.RemoteIdentity {
				return nil, fmt.Errorf("%w: pre-commit attempt changed existing object %q and cannot be abandoned", ErrRejected, object.Path)
			}
			seenBase[object.Path] = struct{}{}
			continue
		}
		operation, ok := eligibleByPath[object.Path]
		if !ok || operation.Size != object.Size || operation.SHA256 != object.SHA256 {
			return nil, fmt.Errorf("%w: target object %q is outside the reconciled pre-commit add-only closure", ErrIntegrity, object.Path)
		}
		result = append(result, state.PublicationAbandonedObject{Path: object.Path, Phase: operation.Phase, Size: object.Size, SHA256: object.SHA256, RemoteIdentity: object.RemoteIdentity})
	}
	for _, object := range base {
		if _, ok := seenBase[object.Path]; !ok {
			return nil, fmt.Errorf("%w: pre-commit target lost base object %q", ErrIntegrity, object.Path)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, nil
}

func requireRecoverableRemoteInventory(remote []publicationRemoteObject, base []state.PublicationInventoryObject, target []state.GenerationFile) error {
	baseMap := make(map[string]state.PublicationInventoryObject, len(base))
	targetMap := make(map[string]state.GenerationFile, len(target))
	seen := make(map[string]struct{}, len(remote))
	for _, object := range base {
		baseMap[object.Path] = object
	}
	for _, file := range target {
		targetMap[file.Path] = file
	}
	for _, object := range remote {
		seen[object.Path] = struct{}{}
		prior, priorOK := baseMap[object.Path]
		next, nextOK := targetMap[object.Path]
		priorMatch := priorOK && object.Size == prior.Size && object.SHA256 == prior.SHA256 && object.RemoteIdentity == prior.RemoteIdentity
		nextMatch := nextOK && object.Size == next.Size && object.SHA256 == next.SHA256
		if !priorMatch && !nextMatch {
			return fmt.Errorf("%w: remote object %q is outside the recoverable old/new closure", ErrIntegrity, object.Path)
		}
	}
	for _, prior := range base {
		if _, ok := seen[prior.Path]; !ok {
			return fmt.Errorf("%w: base checkpoint object %q disappeared during publication", ErrIntegrity, prior.Path)
		}
	}
	return nil
}

func publicationAttemptViews(plan state.PublicationPlan, base []state.PublicationInventoryObject) []state.PublicationAttemptView {
	old := make(map[string]string, len(base))
	for _, object := range base {
		old[object.Path] = object.RemoteIdentity
	}
	views := []state.PublicationAttemptView{}
	for _, unit := range plan.CommitUnits {
		for _, pointer := range unit.Pointers {
			views = append(views, state.PublicationAttemptView{
				ViewID: unit.ViewID, PointerPath: pointer.Path, OldIdentity: old[pointer.Path],
				NewIdentity: pointer.SHA256, State: "pending",
			})
		}
	}
	sort.Slice(views, func(i, j int) bool {
		if views[i].ViewID != views[j].ViewID {
			return views[i].ViewID < views[j].ViewID
		}
		return views[i].PointerPath < views[j].PointerPath
	})
	return views
}

func sameAttemptViewIntent(actual, expected []state.PublicationAttemptView) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if actual[index].ViewID != expected[index].ViewID || actual[index].PointerPath != expected[index].PointerPath || actual[index].OldIdentity != expected[index].OldIdentity || actual[index].NewIdentity != expected[index].NewIdentity {
			return false
		}
	}
	return true
}

func publicationInventory(remote []publicationRemoteObject, target []state.GenerationFile, base []state.PublicationInventoryObject) ([]state.PublicationInventoryObject, error) {
	targetMap := make(map[string]state.GenerationFile, len(target))
	baseMap := make(map[string]state.PublicationInventoryObject, len(base))
	for _, file := range target {
		targetMap[file.Path] = file
	}
	for _, object := range base {
		baseMap[object.Path] = object
	}
	inventory := make([]state.PublicationInventoryObject, 0, len(remote))
	seen := make(map[string]struct{}, len(remote))
	for _, object := range remote {
		seen[object.Path] = struct{}{}
		if file, ok := targetMap[object.Path]; ok {
			if object.Size != file.Size || object.SHA256 != file.SHA256 {
				return nil, fmt.Errorf("%w: remote target object %q differs from Generation", ErrIntegrity, object.Path)
			}
			inventory = append(inventory, state.PublicationInventoryObject{Path: object.Path, Phase: file.Phase, Size: object.Size, SHA256: object.SHA256, RemoteIdentity: object.RemoteIdentity})
			continue
		}
		prior, ok := baseMap[object.Path]
		if !ok || object.Size != prior.Size || object.SHA256 != prior.SHA256 || object.RemoteIdentity != prior.RemoteIdentity {
			return nil, fmt.Errorf("%w: remote prefix contains unknown object %q", ErrIntegrity, object.Path)
		}
		inventory = append(inventory, prior)
	}
	for _, file := range target {
		if _, ok := seen[file.Path]; !ok {
			return nil, fmt.Errorf("%w: remote inventory is missing Generation object %q", ErrIntegrity, file.Path)
		}
	}
	sort.Slice(inventory, func(i, j int) bool { return inventory[i].Path < inventory[j].Path })
	return inventory, nil
}

func publicationCheckpointViews(ctx context.Context, backend publicationBackend, views []state.PublicationAttemptView) ([]state.PublicationCheckpointView, error) {
	result := make([]state.PublicationCheckpointView, 0, len(views))
	for _, view := range views {
		object, ok, err := backend.Head(ctx, view.PointerPath)
		if err != nil || !ok || object.SHA256 != view.NewIdentity {
			return nil, errors.Join(fmt.Errorf("%w: publication pointer %q did not verify", ErrIntegrity, view.PointerPath), err)
		}
		result = append(result, state.PublicationCheckpointView{ViewID: view.ViewID, PointerPath: view.PointerPath, RemoteIdentity: object.RemoteIdentity})
	}
	return result, nil
}

func verifyPublishedGeneration(ctx context.Context, backend publicationBackend, store *state.Store, generation state.GenerationID, manifestSHA string) error {
	manifest, err := store.GenerationManifest(ctx, generation)
	if err != nil {
		return err
	}
	_, digest, err := state.ManifestBytes(manifest)
	if err != nil || digest != manifestSHA {
		return errors.Join(fmt.Errorf("%w: checkpoint Generation manifest changed", ErrIntegrity), err)
	}
	for _, file := range manifest {
		object, ok, headErr := backend.Head(ctx, file.Path)
		if headErr != nil || !ok || object.Size != file.Size || object.SHA256 != file.SHA256 {
			return errors.Join(fmt.Errorf("%w: published Generation differs at %q", ErrIntegrity, file.Path), headErr)
		}
		if err := backend.VerifyPublic(ctx, file); err != nil {
			return err
		}
	}
	return nil
}

func putPublicationGrace(ctx context.Context, store *state.Store, binding state.PublicationTargetBinding, checkpoint state.AppliedCheckpoint) error {
	minimum := 30 * 24 * time.Hour
	if cacheMinimum := binding.MaxCacheTTL + 24*time.Hour; cacheMinimum > minimum {
		minimum = cacheMinimum
	}
	cacheHash := sha256.New()
	cacheHash.Write([]byte("sow/cache-policy/v1"))
	cacheHash.Write([]byte{0})
	cacheHash.Write([]byte(binding.PublicEndpoint))
	cacheHash.Write([]byte{0})
	cacheHash.Write([]byte(binding.MaxCacheTTL.String()))
	grace := state.GraceRecord{
		TargetIdentity: binding.TargetIdentity, CheckpointIdentity: checkpoint.CheckpointIdentity,
		VerifiedAt: checkpoint.AppliedAt.UTC(), NotBefore: checkpoint.AppliedAt.UTC().Add(minimum),
		CachePolicyIdentity: hex.EncodeToString(cacheHash.Sum(nil)), State: "grace",
	}
	return store.PutGraceRecord(ctx, &grace)
}
