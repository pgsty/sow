package managed

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

func Changes(ctx context.Context, opts ChangesOptions) (result ChangesResult, resultErr error) {
	result = ChangesResult{Changes: []state.FileChange{}}
	ws, cfg, workspaceLock, err := readWorkspace(ctx, opts.WorkspaceOptions, true)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close()) }()
	repoName, err := selectRepo(ws, cfg, opts.Repository)
	if err != nil {
		return result, err
	}
	result.Repository = repoName
	store, repoLock, err := openReadRepository(ctx, ws.Root, repoName)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, repoLock.Close()) }()
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	layout := inspectRepositoryReadLayout(ctx, ws.Root, repoName, store)
	legacyC2 := layout.FrozenC2
	if !legacyC2 {
		if layout.IdentityErr != nil || layout.TransitionErr != nil || layout.ControlErr != nil {
			return result, fmt.Errorf("%w: changes are unavailable because repository layout evidence is invalid", ErrIntegrity)
		}
		if err := store.RequireTerminalLayout(ctx); err != nil {
			return result, fmt.Errorf("%w: changes are unavailable during repository layout transition: %v", ErrNotReady, err)
		}
		if layout.Transition != nil || layout.Control != nil {
			return result, fmt.Errorf("%w: changes are unavailable while stale transition evidence exists", ErrIntegrity)
		}
	}
	workspaceOperation, err := inspectWorkspaceJournal(ws.Root)
	if err != nil {
		return result, fmt.Errorf("%w: workspace journal evidence is invalid", ErrIntegrity)
	}
	if workspaceOperation != nil && (workspaceOperation.Repository == "" || workspaceOperation.Repository == repoName) {
		return result, fmt.Errorf("%w: changes are unavailable while workspace operation %s is %s", ErrIntegrity, workspaceOperation.ID, workspaceOperation.Phase)
	}
	pending, err := store.PendingOperations(ctx)
	if err != nil {
		return result, err
	}
	if len(pending) != 0 {
		return result, fmt.Errorf("%w: changes are unavailable while operation %s is %s", ErrIntegrity, pending[0].ID, pending[0].State)
	}
	checked, checkErr := checkLocked(ctx, ws, cfg, repoName, sortedDistConfigNames(cfg.Repositories[repoName]), false, store, runtime.GOMAXPROCS(0))
	hasLayerError := false
	for _, layer := range checked.Layers {
		if !layer.OK {
			hasLayerError = true
			break
		}
	}
	if hasLayerError || checked.Status == "error" || checked.Status == "recovering" {
		return result, fmt.Errorf("%w: changes are unavailable because delivery integrity check failed: %v", ErrIntegrity, checkErr)
	}
	if checkErr != nil && !errors.Is(checkErr, ErrNotReady) {
		return result, fmt.Errorf("%w: changes delivery integrity check failed: %v", ErrIntegrity, checkErr)
	}
	summary, err := store.Summary(ctx)
	if err != nil {
		return result, err
	}
	if err := store.ValidateGenerationLedger(ctx); err != nil {
		return result, fmt.Errorf("%w: generation ledger is invalid: %v", ErrIntegrity, err)
	}
	observedStatus, err := changesRepositoryStatus(ctx, ws.Root, repoName, cfg, store, summary)
	if err != nil {
		return result, err
	}
	if observedStatus == "error" || observedStatus == "recovering" {
		return result, fmt.Errorf("%w: changes are unavailable while repository state is %s", ErrIntegrity, observedStatus)
	}
	result.Generation, result.Dirty = summary.BuiltGeneration, observedStatus != "clean"
	if summary.BuiltGeneration == 0 {
		manifestLayout := state.LayoutSinglePayloadV1
		if legacyC2 {
			manifestLayout = state.LayoutC2V1
		}
		physical, scanErr := scanPublicManifestForLayout(ctx, filepath.Join(ws.Root, repoName), manifestLayout)
		if scanErr != nil || len(physical) != 0 {
			return result, fmt.Errorf("%w: Generation 0 public delivery tree is not empty or readable: %v", ErrIntegrity, scanErr)
		}
		result.Base = 0
		return result, nil
	}
	retainedCurrent, err := store.GenerationManifest(ctx, summary.BuiltGeneration)
	if err != nil {
		return result, fmt.Errorf("%w: current generation manifest is unavailable", ErrIntegrity)
	}
	manifestLayout := state.LayoutSinglePayloadV1
	if legacyC2 {
		manifestLayout = state.LayoutC2V1
	}
	physicalCurrent, err := scanPublicManifestForLayout(ctx, filepath.Join(ws.Root, repoName), manifestLayout)
	if err != nil || !sameGenerationManifest(retainedCurrent, physicalCurrent) {
		return result, fmt.Errorf("%w: current public delivery tree differs from Generation %d: %v", ErrIntegrity, summary.BuiltGeneration, err)
	}
	if opts.Base == nil {
		info, err := store.GetGeneration(ctx, summary.BuiltGeneration)
		if err != nil {
			return result, fmt.Errorf("%w: current generation has no retained Changeset", ErrIntegrity)
		}
		result.Base = info.PreviousGeneration
		result.Changes, err = store.GenerationChanges(ctx, summary.BuiltGeneration)
		return result, err
	}
	base := *opts.Base
	if base > summary.BuiltGeneration {
		return result, fmt.Errorf("%w: base generation %d is outside 0..%d", ErrRejected, base, summary.BuiltGeneration)
	}
	result.Base = base
	if base == summary.BuiltGeneration {
		return result, nil
	}
	target := retainedCurrent
	if base == 0 {
		result.Changes = state.DiffManifests(nil, target)
		return result, nil
	}
	baseManifest, err := store.GenerationManifest(ctx, base)
	if errors.Is(err, state.ErrNotFound) {
		return result, fmt.Errorf("%w: base generation %d is not retained", ErrRejected, base)
	}
	if err != nil {
		return result, err
	}
	result.Changes = state.DiffManifests(baseManifest, target)
	return result, nil
}

func changesRepositoryStatus(ctx context.Context, root, repoName string, cfg config.Config, store *state.Store, summary state.RepositorySummary) (string, error) {
	status := summary.Status
	if summary.BuiltGeneration > 0 {
		if _, generationErr := store.GetGeneration(ctx, summary.BuiltGeneration); errors.Is(generationErr, state.ErrNotFound) {
			status = statusAtLeast(status, "dirty")
		} else if generationErr != nil {
			return "", fmt.Errorf("%w: read current Generation: %v", ErrIntegrity, generationErr)
		}
	}
	storedDists, err := store.ListDists(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: read Dist state: %v", ErrIntegrity, err)
	}
	storedByName := make(map[string]state.Dist, len(storedDists))
	for _, dist := range storedDists {
		storedByName[dist.Name] = dist
		configured, ok := cfg.Repositories[repoName].Dists[dist.Name]
		if !ok {
			return "error", nil
		}
		if configured.Format != dist.Format {
			status = statusAtLeast(status, "dirty")
		}
	}
	for _, distName := range sortedDistConfigNames(cfg.Repositories[repoName]) {
		dist, ok := storedByName[distName]
		if !ok {
			status = statusAtLeast(status, "dirty")
			continue
		}
		desired, desiredErr := store.MembershipDigests(ctx, distName, false)
		built, builtErr := store.MembershipDigests(ctx, distName, true)
		effectiveSHA, configDirty, configErr := observedEffectiveDistConfig(ctx, root, cfg, repoName, distName, dist)
		if err := errors.Join(desiredErr, builtErr, configErr); err != nil {
			return "", fmt.Errorf("%w: inspect Dist %q for changes: %v", ErrIntegrity, distName, err)
		}
		if !sameStringSet(desired, built) || configDirty || effectiveSHA != "" && effectiveSHA != dist.EffectiveConfigSHA256 {
			status = statusAtLeast(status, "dirty")
		}
	}
	return status, nil
}

// changesSelectedDistsStatus reports the Desired/Built state of exactly the
// selected Dist projection. Repository-wide integrity errors remain visible,
// but ordinary dirty or recovering work in another Dist must not leak into a
// scoped query.
func changesSelectedDistsStatus(ctx context.Context, root, repoName string, cfg config.Config, store *state.Store, summary state.RepositorySummary, selected []string) (string, error) {
	status := "clean"
	if summary.Status == "error" {
		status = "error"
	}
	if summary.BuiltGeneration > 0 {
		if _, generationErr := store.GetGeneration(ctx, summary.BuiltGeneration); errors.Is(generationErr, state.ErrNotFound) {
			status = statusAtLeast(status, "dirty")
		} else if generationErr != nil {
			return "", fmt.Errorf("%w: read current Generation: %v", ErrIntegrity, generationErr)
		}
	}
	storedDists, err := store.ListDists(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: read Dist state: %v", ErrIntegrity, err)
	}
	for _, dist := range storedDists {
		if _, ok := cfg.Repositories[repoName].Dists[dist.Name]; !ok {
			status = "error"
		}
	}
	for _, distName := range selected {
		dist, err := store.GetDist(ctx, distName)
		if errors.Is(err, state.ErrNotFound) {
			status = statusAtLeast(status, "dirty")
			continue
		}
		if err != nil {
			return "", fmt.Errorf("%w: read Dist %q state: %v", ErrIntegrity, distName, err)
		}
		configured, ok := cfg.Repositories[repoName].Dists[distName]
		if !ok {
			status = "error"
			continue
		}
		desired, desiredErr := store.MembershipDigests(ctx, distName, false)
		built, builtErr := store.MembershipDigests(ctx, distName, true)
		effectiveSHA, configDirty, configErr := observedEffectiveDistConfig(ctx, root, cfg, repoName, distName, dist)
		if err := errors.Join(desiredErr, builtErr, configErr); err != nil {
			return "", fmt.Errorf("%w: inspect Dist %q for changes: %v", ErrIntegrity, distName, err)
		}
		if configured.Format != dist.Format || !sameStringSet(desired, built) || configDirty || effectiveSHA != "" && effectiveSHA != dist.EffectiveConfigSHA256 {
			status = statusAtLeast(status, "dirty")
		}
	}
	pending, err := store.PendingOperations(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: read pending operations: %v", ErrIntegrity, err)
	}
	if len(pendingOperationsForSelectedDists(pending, selected, true)) != 0 {
		status = statusAtLeast(status, "recovering")
	}
	if workspaceOperation, inspectErr := inspectWorkspaceJournal(root); inspectErr != nil {
		status = "error"
	} else if workspaceOperation != nil && (workspaceOperation.Repository == "" || workspaceOperation.Repository == repoName) {
		status = statusAtLeast(status, "recovering")
	}
	return status, nil
}

func observedRepositoryDirty(ctx context.Context, root, repoName string, cfg config.Config, store *state.Store) (bool, error) {
	summary, err := store.Summary(ctx)
	if err != nil {
		return false, err
	}
	status, err := changesRepositoryStatus(ctx, root, repoName, cfg, store, summary)
	if err != nil {
		return false, err
	}
	return status != "clean", nil
}
