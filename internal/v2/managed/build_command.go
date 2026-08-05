package managed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
)

func Build(ctx context.Context, opts BuildOptions) (result BuildResult, resultErr error) {
	if ctx == nil {
		return result, errors.New("managed: nil context")
	}
	if opts.Jobs < 1 {
		return result, fmt.Errorf("%w: build jobs must be at least 1", ErrRejected)
	}
	ws, _, rootGuard, err := workspace(opts.WorkspaceOptions)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, rootGuard.Close()) }()
	cfg, configSHA, repoName, workspaceLock, repoLock, err := acquireSelectedRepositoryLocks(ctx, ws, opts.Repository, opts.LockOptions)
	if err != nil {
		return result, err
	}
	result.Repository = repoName
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close()) }()
	defer func() { resultErr = errors.Join(resultErr, repoLock.Close()) }()
	store, err := openExistingState(filepath.Join(ws.Root, ".sow", repoName+".db"))
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	if err := recoverDistOperations(ctx, ws.Root, repoName, store); err != nil {
		return result, err
	}
	distNames, effective, err := selectedBuildDists(cfg, repoName, opts.Dists)
	if err != nil {
		return result, err
	}
	selectedFormats := configuredSigningFormats(cfg, repoName, distNames)
	if _, err := checkConfigAtRootForLockedRepository(ctx, ws.Root, cfg, repoName, selectedFormats); err != nil {
		return result, err
	}
	if err := validateCurrentPublicGeneration(ctx, ws.Root, repoName, store); err != nil {
		return result, err
	}
	result.Dists = distNames
	desired := make(map[string][]string, len(distNames))
	outcomes := []state.OperationMembership{}
	affectedDists := []string{}
	for _, distName := range distNames {
		current, err := store.ListPackageObjects(ctx, []string{distName}, false)
		if err != nil {
			return result, err
		}
		policy, err := ApplyPolicy(current, effective[distName])
		if err != nil {
			return result, err
		}
		desired[distName] = []string{}
		for _, object := range policy.Kept {
			desired[distName] = append(desired[distName], object.SHA256)
		}
		for _, object := range policy.Excluded {
			outcomes = append(outcomes, state.OperationMembership{DistName: distName, PackageSHA256: object.SHA256, Action: "exclude"})
		}
		for _, object := range policy.Limited {
			outcomes = append(outcomes, state.OperationMembership{DistName: distName, PackageSHA256: object.SHA256, Action: "limit"})
		}
		built, err := store.MembershipDigests(ctx, distName, true)
		if err != nil {
			return result, err
		}
		effectiveSHA, _, err := effectiveDistConfig(ctx, ws.Root, cfg, repoName, distName)
		if err != nil {
			return result, err
		}
		distState, err := store.GetDist(ctx, distName)
		if err != nil {
			return result, err
		}
		if !sameStringSet(desired[distName], built) || effectiveSHA != distState.EffectiveConfigSHA256 {
			affectedDists = append(affectedDists, distName)
		}
	}
	sort.Strings(affectedDists)
	physicalChange := len(affectedDists) != 0
	manifest := mutationManifest{Version: mutationOperationVersion, Objects: []state.PackageObject{}, Desired: desired, Result: map[string]int{"dists": len(distNames)}, Outcomes: outcomes}
	var preflight *mutationBuildPreflight
	if physicalChange {
		preflight, err = prepareMutationBuildPreflight(ctx, ws.Root, repoName, cfg, affectedDists, manifest, store, nil)
		if err != nil {
			return result, err
		}
		manifest.RPMSigningKeys = append([]state.RPMSigningKey(nil), preflight.rpmPolicy.retainedKeys...)
	}
	manifestData, err := marshalMutationManifest(manifest)
	if err != nil {
		return result, err
	}
	id, err := operationID()
	if err != nil {
		return result, err
	}
	result.Operation = id
	payload := mutationOperationPayload{Version: mutationOperationVersion, Repository: repoName, Kind: "build", ConfigSHA256: configSHA, Dists: distNames, BuildDists: affectedDists, Noop: !physicalChange}
	payloadData, _ := json.Marshal(payload)
	defer func() {
		resultErr = finalizePreApplyMutationOperation(ctx, ws.Root, repoName, id, store, resultErr, func() any {
			return map[string]any{"dists": len(result.Dists), "desired_revision": result.Revision, "built_generation": result.Generation}
		})
	}()
	if err := store.BeginOperation(ctx, state.Operation{ID: id, Kind: "build", State: state.OperationPlanned, PayloadJSON: string(payloadData)}); err != nil {
		return result, err
	}
	if err := callFault(opts.Fault, "build.command.planned"); err != nil {
		return result, err
	}
	stageRoot := mutationStageRoot(ws.Root, repoName, id)
	if err := durableMkdir(stageRoot, 0o700); err != nil {
		return result, err
	}
	payload.ManifestSHA256 = bytesSHA(manifestData)
	if err := writeAtomic(mutationManifestPath(ws.Root, repoName, id, payload.ManifestSHA256), manifestData, 0o600); err != nil {
		return result, err
	}
	payloadData, _ = json.Marshal(payload)
	if err := store.UpdateOperationPayload(ctx, id, string(payloadData)); err != nil {
		return result, err
	}
	if err := store.SetOperationState(ctx, id, state.OperationStaged, ""); err != nil {
		return result, err
	}
	if err := callFault(opts.Fault, "build.command.staged"); err != nil {
		return result, err
	}
	mutation, err := store.ApplyDesiredMutation(ctx, id, nil, desired, manifestResultJSON(manifest.Result))
	result.Revision = mutation.Revision
	if err != nil {
		if mutation.Revision != 0 {
			retainCommittedProjection(ctx, ws.Root, repoName, cfg, store, &result.Generation, &result.Dirty)
		}
		return result, err
	}
	if err := store.RecordOperationMembershipOutcomes(ctx, id, manifest.Outcomes); err != nil {
		retainCommittedProjection(ctx, ws.Root, repoName, cfg, store, &result.Generation, &result.Dirty)
		return result, err
	}
	for _, object := range mutation.DroppedPending {
		if err := removePendingObject(ws.Root, repoName, object); err != nil {
			return result, err
		}
	}
	if err := callFault(opts.Fault, "build.command.applied"); err != nil {
		return result, err
	}
	if !physicalChange {
		if _, err := normalizeCurrentPublicTree(ctx, ws.Root, repoName, id, store, opts.Fault); err != nil {
			return result, err
		}
		if err := store.FinalizeNoopBuild(ctx, id); err != nil {
			if summary, summaryErr := store.Summary(ctx); summaryErr == nil {
				result.Generation = summary.BuiltGeneration
				if operation, operationErr := store.GetOperation(ctx, id); operationErr == nil && operation.Operation.State == state.OperationDone {
					result.Noop = true
				}
			}
			return result, err
		}
		result.Noop = true
		retainCommittedProjection(ctx, ws.Root, repoName, cfg, store, &result.Generation, &result.Dirty)
		if err := cleanupMutationStage(ws.Root, repoName, id); err != nil {
			return result, err
		}
		return result, nil
	}
	generation, err := buildAppliedMutation(ctx, ws.Root, repoName, cfg, affectedDists, id, store, opts.Jobs, opts.Fault, preflight)
	result.Generation = generation
	if err != nil {
		retainCommittedProjection(ctx, ws.Root, repoName, cfg, store, &result.Generation, &result.Dirty)
		return result, err
	}
	result.Dirty, err = observedRepositoryDirty(ctx, ws.Root, repoName, cfg, store)
	if err != nil {
		return result, err
	}
	return result, nil
}

func selectedBuildDists(cfg config.Config, repoName string, explicit []string) ([]string, map[string]config.EffectiveDist, error) {
	names := stableUniqueStrings(explicit)
	if len(names) == 0 {
		names = sortedDistConfigNames(cfg.Repositories[repoName])
	}
	if len(names) == 0 {
		return nil, nil, fmt.Errorf("%w: repository %q has no configured Dists", ErrRejected, repoName)
	}
	sort.Strings(names)
	effective := make(map[string]config.EffectiveDist, len(names))
	for _, name := range names {
		if _, exists := cfg.Repositories[repoName].Dists[name]; !exists {
			return nil, nil, fmt.Errorf("%w: dist %q is not configured in repository %q", ErrRejected, name, repoName)
		}
		view, err := config.EffectiveView(cfg, config.ViewOptions{Repository: repoName, Dist: name})
		if err != nil {
			return nil, nil, err
		}
		effective[name] = view.Repositories[repoName].Dists[name]
	}
	return names, effective, nil
}

func manifestResultJSON(result map[string]int) string {
	data, _ := json.Marshal(result)
	return string(data)
}
