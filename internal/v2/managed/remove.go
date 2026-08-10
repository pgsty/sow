package managed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/workmetrics"
	"github.com/pgsty/sow/internal/yumrepo"
)

func Remove(ctx context.Context, opts RemoveOptions) (result RemoveResult, resultErr error) {
	result = RemoveResult{Check: opts.Check, Removed: []RemovedMembership{}, Changes: []state.FileChange{}}
	if ctx == nil {
		return result, errors.New("managed: nil context")
	}
	ctx, _ = workmetrics.Ensure(ctx)
	if len(opts.Packages) == 0 || opts.Jobs < 1 || opts.Check && opts.Skip {
		return result, fmt.Errorf("%w: invalid remove options", ErrRejected)
	}
	if opts.Check && (opts.Timeout != 0 || opts.NoWait) {
		return result, fmt.Errorf("%w: --check cannot be combined with lock wait options", ErrRejected)
	}
	if opts.Check {
		return previewRemove(ctx, opts)
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
	if err := validateRepositoryLayout(ws.Root, repoName); err != nil {
		return result, err
	}
	store, err := openExistingState(filepath.Join(ws.Root, ".sow", repoName+".db"))
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	if err := recoverDistOperations(ctx, ws.Root, repoName, store); err != nil {
		return result, err
	}
	if err := requireNoWriteActivePublication(ctx, store); err != nil {
		return result, err
	}
	distNames, effectiveDists, err := selectedMutationDists(ws, cfg, repoName, opts.Dists)
	if err != nil {
		return result, err
	}
	if _, err := checkConfigAtRootForLockedRepository(ctx, ws.Root, cfg, repoName, signingFormatMask{}); err != nil {
		return result, err
	}
	currentSnapshot, err := validateCurrentPublicGenerationSnapshot(ctx, ws.Root, repoName, store)
	if err != nil {
		return result, err
	}
	objects, err := resolvePackageReferences(ctx, store, opts.Packages, distNames, true)
	if err != nil {
		return result, err
	}
	desired, removed, err := desiredAfterRemoval(ctx, store, distNames, effectiveDists, objects)
	if err != nil {
		return result, err
	}
	result.Removed, result.Dists = removed, distNames
	buildDists, err := changedDesiredDists(ctx, store, desired)
	if err != nil {
		return result, err
	}
	manifest := mutationManifest{Version: mutationOperationVersion, Objects: []state.PackageObject{}, Desired: desired, Result: map[string]int{"removed": len(removed)}}
	var preflight *mutationBuildPreflight
	if !opts.Skip && len(buildDists) != 0 {
		preflight, err = prepareMutationBuildPreflight(ctx, ws.Root, repoName, cfg, buildDists, manifest, store, nil, currentSnapshot)
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
	payload := mutationOperationPayload{Version: mutationOperationVersion, Repository: repoName, Kind: "rm", ConfigSHA256: configSHA, Skip: opts.Skip, Dists: distNames, BuildDists: buildDists}
	payloadData, _ := json.Marshal(payload)
	defer func() {
		resultErr = finalizePreApplyMutationOperation(ctx, ws.Root, repoName, id, store, resultErr, func() any {
			return map[string]any{"removed": len(result.Removed), "dists": len(result.Dists)}
		})
	}()
	if err := store.BeginOperation(ctx, state.Operation{ID: id, Kind: "rm", State: state.OperationPlanned, PayloadJSON: string(payloadData)}); err != nil {
		return result, err
	}
	auditPackages := make([]state.OperationPackage, 0, len(removed))
	for _, item := range removed {
		auditPackages = append(auditPackages, state.OperationPackage{InputPath: item.Name, PackageSHA256: item.SHA256, Coordinate: item.Coordinate, Disposition: "removed"})
	}
	if err := store.RecordOperationPackages(ctx, id, auditPackages); err != nil {
		return result, err
	}
	if err := callFault(opts.Fault, "rm.planned"); err != nil {
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
	if err := callFault(opts.Fault, "rm.staged"); err != nil {
		return result, err
	}
	resultJSON, _ := json.Marshal(manifest.Result)
	mutation, err := store.ApplyDesiredMutation(ctx, id, nil, desired, string(resultJSON))
	result.Revision = mutation.Revision
	if err != nil {
		if mutation.Revision != 0 {
			retainCommittedProjection(ctx, ws.Root, repoName, cfg, store, &result.Generation, &result.Dirty)
		}
		return result, err
	}
	if !sameStringSet(mutation.ChangedDists, payload.BuildDists) {
		return result, fmt.Errorf("%w: applied remove Dist changes differ from its staged build scope", ErrIntegrity)
	}
	for _, object := range mutation.DroppedPending {
		if err := removePendingObject(ws.Root, repoName, object); err != nil {
			return result, err
		}
	}
	if err := callFault(opts.Fault, "rm.applied"); err != nil {
		return result, err
	}
	if opts.Skip {
		if err := store.SetOperationState(ctx, id, state.OperationDoneDirty, ""); err != nil {
			if retainCommittedTerminalProjection(ctx, ws.Root, repoName, cfg, store, id, state.OperationDoneDirty, &result.Generation, &result.Dirty) {
				err = errors.Join(err, cleanupMutationStage(ws.Root, repoName, id))
			}
			return result, err
		}
		retainCommittedProjection(ctx, ws.Root, repoName, cfg, store, &result.Generation, &result.Dirty)
		if err := cleanupMutationStage(ws.Root, repoName, id); err != nil {
			return result, err
		}
		return result, nil
	}
	generation, err := buildAppliedMutation(ctx, ws.Root, repoName, cfg, payload.BuildDists, id, store, opts.Jobs, opts.Fault, preflight)
	result.Generation = generation
	if err != nil {
		retainCommittedProjection(ctx, ws.Root, repoName, cfg, store, &result.Generation, &result.Dirty)
		return result, err
	}
	result.Changes, err = store.GenerationChanges(ctx, generation)
	if err != nil {
		return result, err
	}
	result.Dirty, err = observedRepositoryDirty(ctx, ws.Root, repoName, cfg, store)
	if err != nil {
		return result, err
	}
	return result, nil
}

func previewRemove(ctx context.Context, opts RemoveOptions) (result RemoveResult, resultErr error) {
	result = RemoveResult{Check: true, Removed: []RemovedMembership{}, Changes: []state.FileChange{}}
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
	if err := validateRepositoryLayout(ws.Root, repoName); err != nil {
		return result, err
	}
	repoLock, err := acquireSharedFileLock(ctx, filepath.Join(ws.Root, ".sow", "repo-locks", repoName+".lock"))
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, repoLock.Close()) }()
	store, err := openReadOnlyState(filepath.Join(ws.Root, ".sow", repoName+".db"))
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	pending, err := store.PendingOperations(ctx)
	if err != nil || len(pending) != 0 {
		return result, fmt.Errorf("%w: repository has an operation pending recovery", ErrIntegrity)
	}
	if err := validateCurrentPublicGeneration(ctx, ws.Root, repoName, store); err != nil {
		return result, err
	}
	distNames, effectiveDists, err := selectedMutationDists(ws, cfg, repoName, opts.Dists)
	if err != nil {
		return result, err
	}
	objects, err := resolvePackageReferences(ctx, store, opts.Packages, distNames, true)
	if err != nil {
		return result, err
	}
	desired, removed, err := desiredAfterRemoval(ctx, store, distNames, effectiveDists, objects)
	result.Removed = removed
	result.Dists = distNames
	affected := []string{}
	if err == nil {
		affected, err = changedDesiredDists(ctx, store, desired)
		if err == nil {
			result.Changes, err = previewRemovalChanges(ctx, ws.Root, repoName, cfg, affected, desired, store, opts.Jobs)
		}
	}
	if summary, summaryErr := store.Summary(ctx); summaryErr == nil {
		// A successful default rm immediately commits one Desired revision and
		// one physical Generation. --check reports that predicted identity while
		// remaining entirely read-only.
		nextGeneration, nextErr := summary.BuiltGeneration.Next()
		if nextErr != nil {
			if err == nil {
				err = fmt.Errorf("%w: %v", ErrRejected, nextErr)
			}
		} else {
			result.Revision, result.Generation = summary.DesiredRevision+1, nextGeneration
		}
		if dirty, dirtyErr := predictedDirtyAfterBuild(ctx, ws.Root, repoName, cfg, store, affected); dirtyErr == nil {
			result.Dirty = dirty
		} else if err == nil {
			err = dirtyErr
		}
	} else if err == nil {
		err = summaryErr
	}
	return result, err
}

func predictedDirtyAfterBuild(ctx context.Context, root, repoName string, cfg config.Config, store *state.Store, builtDists []string) (bool, error) {
	builtSet := map[string]struct{}{}
	for _, name := range builtDists {
		builtSet[name] = struct{}{}
	}
	stored, err := store.ListDists(ctx)
	if err != nil {
		return false, err
	}
	byName := make(map[string]state.Dist, len(stored))
	for _, dist := range stored {
		byName[dist.Name] = dist
		configured, ok := cfg.Repositories[repoName].Dists[dist.Name]
		if !ok || configured.Format != dist.Format {
			return true, nil
		}
	}
	for _, name := range sortedDistConfigNames(cfg.Repositories[repoName]) {
		dist, ok := byName[name]
		if !ok {
			return true, nil
		}
		if _, rebuilt := builtSet[name]; rebuilt {
			// The preview renderer has already proven current Desired bytes,
			// policy, signing identity and metadata for this Dist. A successful
			// default rm commits that exact projection as Built.
			continue
		}
		desired, desiredErr := store.MembershipDigests(ctx, name, false)
		built, builtErr := store.MembershipDigests(ctx, name, true)
		_, configDirty, configErr := observedEffectiveDistConfig(ctx, root, cfg, repoName, name, dist)
		if err := errors.Join(desiredErr, builtErr, configErr); err != nil {
			return false, err
		}
		if !sameStringSet(desired, built) || configDirty {
			return true, nil
		}
	}
	return false, nil
}

func previewRemovalChanges(ctx context.Context, root, repoName string, cfg config.Config, distNames []string, desired map[string][]string, store *state.Store, jobs int) ([]state.FileChange, error) {
	if jobs < 1 {
		return nil, fmt.Errorf("%w: remove jobs must be at least 1", ErrRejected)
	}
	summary, err := store.Summary(ctx)
	if err != nil {
		return nil, err
	}
	nextGeneration, err := summary.BuiltGeneration.Next()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	base, err := scanPublicManifest(ctx, filepath.Join(root, repoName))
	if err != nil {
		return nil, err
	}
	target := make(map[string]state.GenerationFile, len(base))
	for _, file := range base {
		target[file.Path] = file
	}
	previewRoot, err := os.MkdirTemp("", "sow-rm-check-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = removeOwnedDirectory(previewRoot, filepath.Dir(previewRoot)) }()
	formats := configuredSigningFormats(cfg, repoName, distNames)
	publicationTime, err := nextMutationPublicationTime(ctx, root, cfg.Repositories[repoName], store, summary.BuiltGeneration, formats.rpm, formats.deb)
	if err != nil {
		return nil, err
	}
	metadataSnapshot, err := loadMetadataSignerSnapshotForFormats(ctx, root, cfg.Repositories[repoName], publicationTime, formats.rpm, formats.deb)
	if err != nil {
		return nil, err
	}
	rpmSigner, debSigner := metadataSnapshot.RPMSigner, metadataSnapshot.APTSigner
	allSources := make(map[string]ManagedPackageSource)
	for _, distName := range distNames {
		for _, digest := range desired[distName] {
			if _, exists := allSources[digest]; exists {
				continue
			}
			object, err := store.GetPackageObject(ctx, digest)
			if err != nil {
				return nil, err
			}
			source, err := availableManagedPackageSource(root, repoName, object)
			if err != nil {
				return nil, err
			}
			allSources[digest] = source
		}
	}
	if err := loadManagedPackageFacts(ctx, allSources, store, jobs); err != nil {
		return nil, err
	}
	for _, distName := range distNames {
		dist, err := store.GetDist(ctx, distName)
		if err != nil {
			return nil, err
		}
		architectures, err := configuredArchitectureState(cfg, repoName, distName, dist.Format)
		if err != nil {
			return nil, err
		}
		sources := make([]ManagedPackageSource, 0, len(desired[distName]))
		for _, digest := range desired[distName] {
			sources = append(sources, allSources[digest])
		}
		distPrefix := "dists/" + distName + "/"
		for path := range target {
			if strings.HasPrefix(path, distPrefix) {
				delete(target, path)
			}
		}
		if dist.Format == "rpm" {
			if err := previewRPMDist(ctx, filepath.Join(root, repoName), previewRoot, distName, nextGeneration, publicationTime, architectures, sources, rpmSigner, jobs, base, target); err != nil {
				return nil, err
			}
			continue
		}
		spec := ManagedDistSpec{Name: distName, Format: dist.Format, Architectures: architectures, Generation: nextGeneration, Jobs: jobs, PublishedAt: publicationTime, Packages: sources, APTSigner: debSigner}
		rendered, err := RenderManagedDist(ctx, previewRoot, spec)
		if err != nil {
			return nil, err
		}
		if err := retainPriorAPTByHash(ctx, filepath.Join(root, repoName, "dists", distName), rendered.Path, architectures); err != nil {
			return nil, err
		}
		files, err := scanPreviewFiles(ctx, rendered.Path, distPrefix)
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			target[file.Path] = file
		}
	}
	targetManifest := make([]state.GenerationFile, 0, len(target))
	for _, file := range target {
		targetManifest = append(targetManifest, file)
	}
	sort.Slice(targetManifest, func(i, j int) bool { return targetManifest[i].Path < targetManifest[j].Path })
	return state.DiffManifests(base, targetManifest), nil
}

func previewRPMDist(ctx context.Context, repositoryRoot, previewRoot, distName string, generation state.GenerationID, publicationTime time.Time, architectures []state.Architecture, sources []ManagedPackageSource, signer yumrepo.DetachedSigner, jobs int, base []state.GenerationFile, target map[string]state.GenerationFile) error {
	baseByPath := make(map[string]state.GenerationFile, len(base))
	for _, file := range base {
		baseByPath[file.Path] = file
	}
	for _, architecture := range architectures {
		priorRoot := filepath.Join(repositoryRoot, "dists", distName, architecture.Family, "repodata")
		var prior *yumrepo.Generation
		var err error
		if _, statErr := os.Lstat(filepath.Join(priorRoot, "repomd.xml.asc")); statErr == nil {
			prior, err = yumrepo.ValidateManagedDirectory(ctx, priorRoot, yumrepo.CompressionGzip, structuralDetachedVerifier{})
		} else if errors.Is(statErr, os.ErrNotExist) {
			prior, err = yumrepo.ValidateManagedUnsignedDirectory(ctx, priorRoot, yumrepo.CompressionGzip)
		} else {
			err = statErr
		}
		if err != nil || prior == nil {
			return fmt.Errorf("%w: validate prior RPM metadata for removal preview: %v", ErrIntegrity, err)
		}
		for _, artifact := range prior.Artifacts {
			path := filepath.ToSlash(filepath.Join("dists", distName, architecture.Family, filepath.FromSlash(artifact.Path)))
			file, exists := baseByPath[path]
			if !exists || file.SHA256 != artifact.SHA256 || file.Size != artifact.Size {
				return fmt.Errorf("%w: prior RPM artifact is absent from current Generation", ErrIntegrity)
			}
			target[path] = file
		}
	}
	if _, err := RenderManagedDist(ctx, previewRoot, ManagedDistSpec{
		Name: distName, Format: "rpm", Architectures: architectures, Generation: generation,
		Jobs: jobs, PublishedAt: publicationTime, Packages: sources, RPMSigner: signer,
	}); err != nil {
		return err
	}
	files, err := scanPreviewFiles(ctx, filepath.Join(previewRoot, "dists", distName), "dists/"+distName+"/")
	if err != nil {
		return err
	}
	for _, file := range files {
		target[file.Path] = file
	}
	return nil
}

func scanPreviewFiles(ctx context.Context, root, prefix string) ([]state.GenerationFile, error) {
	files := []state.GenerationFile{}
	err := walkRootedTree(ctx, root, func(relative string, file *os.File, info os.FileInfo) error {
		digest, err := hashOpenedFileContext(ctx, file)
		if err != nil {
			return err
		}
		path := prefix + relative
		phase := publicFilePhase(path)
		if phase == "" {
			return fmt.Errorf("%w: removal preview dists contains package payload %s", ErrIntegrity, path)
		}
		files = append(files, state.GenerationFile{Path: path, Phase: phase, Size: info.Size(), SHA256: digest})
		return nil
	}, nil)
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func desiredAfterRemoval(ctx context.Context, store *state.Store, distNames []string, effective map[string]config.EffectiveDist, removedObjects []state.PackageObject) (map[string][]string, []RemovedMembership, error) {
	remove := map[string]state.PackageObject{}
	for _, object := range removedObjects {
		remove[object.SHA256] = object
	}
	desired := make(map[string][]string, len(distNames))
	removed := []RemovedMembership{}
	currentObjects, err := store.ListPackageObjects(ctx, distNames, false)
	if err != nil {
		return nil, nil, err
	}
	currentByDist := packageObjectsByDist(currentObjects, distNames, false)
	for _, distName := range distNames {
		desired[distName] = []string{}
		current := currentByDist[distName]
		remaining := make([]state.PackageObject, 0, len(current))
		for _, object := range current {
			if _, drop := remove[object.SHA256]; drop {
				removed = append(removed, RemovedMembership{Dist: distName, SHA256: object.SHA256, Coordinate: object.Format + ":" + object.Coordinate, Name: object.Name})
				continue
			}
			remaining = append(remaining, object)
		}
		policy, err := ApplyPolicy(remaining, effective[distName])
		if err != nil {
			return nil, nil, err
		}
		for _, object := range policy.Kept {
			desired[distName] = append(desired[distName], object.SHA256)
		}
	}
	if len(removed) == 0 {
		return nil, nil, fmt.Errorf("%w: package references match no Membership in the selected Dists", ErrRejected)
	}
	sort.Slice(removed, func(i, j int) bool {
		if removed[i].Dist != removed[j].Dist {
			return removed[i].Dist < removed[j].Dist
		}
		return removed[i].Coordinate < removed[j].Coordinate
	})
	return desired, removed, nil
}

func publicTreeSnapshot(root, repoName string) (map[string]string, error) {
	manifest, err := scanPublicManifest(context.Background(), filepath.Join(root, repoName))
	if err != nil {
		return nil, err
	}
	result := make(map[string]string, len(manifest))
	for _, file := range manifest {
		result[file.Path] = file.SHA256
	}
	return result, nil
}
