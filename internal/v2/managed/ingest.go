package managed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/workmetrics"
)

// Version 2 binds the exact affected Build Dist set. A pre-release v1 pending
// journal did not carry that recovery-critical field and is deliberately
// rejected rather than reconstructed by guesswork; terminal v1 audit rows
// remain readable because log surfaces do not reinterpret their payload.
const (
	mutationOperationVersion = 2
	maxMutationManifestBytes = 64 << 20
)

var errMutationRecoveryArtifactTooLarge = errors.New("managed: mutation recovery artifact exceeds its bounded wire format")

type mutationOperationPayload struct {
	Version        int      `json:"version"`
	Repository     string   `json:"repository"`
	Kind           string   `json:"kind"`
	ConfigSHA256   string   `json:"config_sha256"`
	Skip           bool     `json:"skip"`
	Noop           bool     `json:"noop,omitempty"`
	Jobs           int      `json:"jobs,omitempty"`
	Dists          []string `json:"dists"`
	BuildDists     []string `json:"build_dists"`
	ManifestSHA256 string   `json:"manifest_sha256,omitempty"`
}

func changedDesiredDists(ctx context.Context, store *state.Store, desired map[string][]string) ([]string, error) {
	changed := []string{}
	for _, distName := range mapsKeys(desired) {
		current, err := store.MembershipDigests(ctx, distName, false)
		if err != nil {
			return nil, err
		}
		if !sameStringSet(current, desired[distName]) {
			changed = append(changed, distName)
		}
	}
	sort.Strings(changed)
	return changed, nil
}

func validateMutationBuildDists(payload mutationOperationPayload) error {
	if payload.BuildDists == nil {
		return fmt.Errorf("%w: mutation build Dist binding is absent", ErrIntegrity)
	}
	selected := map[string]struct{}{}
	for _, name := range payload.Dists {
		selected[name] = struct{}{}
	}
	seen := map[string]struct{}{}
	for _, name := range payload.BuildDists {
		if _, ok := selected[name]; !ok {
			return fmt.Errorf("%w: mutation build Dist %q is outside selected scope", ErrIntegrity, name)
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("%w: mutation build Dist %q is duplicated", ErrIntegrity, name)
		}
		seen[name] = struct{}{}
	}
	return nil
}

func mutationRecoveryJobs(payload mutationOperationPayload) (int, error) {
	if payload.Jobs == 0 {
		// Active journals written before jobs became durable always recovered
		// with one worker. Preserve that safe compatibility behavior.
		return 1, nil
	}
	if payload.Jobs < 1 {
		return 0, fmt.Errorf("%w: mutation recovery jobs must be at least 1", ErrIntegrity)
	}
	return payload.Jobs, nil
}

type mutationManifest struct {
	Version        int                         `json:"version"`
	Objects        []state.PackageObject       `json:"objects"`
	Desired        map[string][]string         `json:"desired"`
	Result         map[string]int              `json:"result"`
	Outcomes       []state.OperationMembership `json:"outcomes,omitempty"`
	RPMSigningKeys []state.RPMSigningKey       `json:"rpm_signing_keys,omitempty"`
	Build          *mutationBuildManifest      `json:"build,omitempty"`
}

type mutationBuildManifest struct {
	Generation         state.GenerationID  `json:"generation"`
	BaseManifestSHA256 string              `json:"base_manifest_sha256"`
	Dists              []mutationBuildDist `json:"dists"`
	Pooled             []string            `json:"pooled"`
}

type mutationBuildDist struct {
	Name                      string                        `json:"name"`
	TreeSHA256                string                        `json:"tree_sha256"`
	EffectiveConfigSHA256     string                        `json:"effective_config_sha256"`
	Architectures             []state.Architecture          `json:"architectures"`
	MetadataSignerFingerprint string                        `json:"metadata_signer_fingerprint,omitempty"`
	MetadataSignerPublicKey   []byte                        `json:"metadata_signer_public_key,omitempty"`
	EffectiveSigning          config.EffectiveSigningConfig `json:"effective_signing"`
}

func marshalMutationManifest(manifest mutationManifest) ([]byte, error) {
	return marshalMutationManifestLimit(manifest, maxMutationManifestBytes)
}

func marshalMutationManifestLimit(manifest mutationManifest, limit int) ([]byte, error) {
	data, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	if limit < 1 || len(data) > limit {
		return nil, fmt.Errorf("%w: %w: manifest is %d bytes, maximum is %d", ErrRejected, errMutationRecoveryArtifactTooLarge, len(data), limit)
	}
	return data, nil
}

type batchCoordinate struct {
	inputSHA string
	payload  string
	object   state.PackageObject
	new      bool
}

func Add(ctx context.Context, opts AddOptions) (result AddResult, resultErr error) {
	result = AddResult{Items: []MutationItem{}}
	if ctx == nil {
		return result, errors.New("managed: nil context")
	}
	ctx, _ = workmetrics.Ensure(ctx)
	ctx = withMetadataSignerCache(ctx)
	if len(opts.Paths) == 0 {
		return result, fmt.Errorf("%w: add requires at least one input path", ErrRejected)
	}
	if opts.Jobs < 1 {
		return result, fmt.Errorf("%w: add jobs must be at least 1", ErrRejected)
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
	id, err := operationID()
	if err != nil {
		return result, err
	}
	result.Operation = id
	payload := mutationOperationPayload{Version: mutationOperationVersion, Repository: repoName, Kind: "add", ConfigSHA256: configSHA, Skip: opts.Skip, Jobs: opts.Jobs, Dists: distNames}
	payloadData, _ := json.Marshal(payload)
	defer func() {
		resultErr = finalizePreApplyMutationOperation(ctx, ws.Root, repoName, id, store, resultErr, func() any {
			// This callback only runs after the journal proves Desired was not applied.
			for index := range result.Items {
				item := &result.Items[index]
				if item.Status == "accepted" || item.Status == "reused" {
					item.Status, item.Error, item.Dists = "failed", "operation failed before Desired state was applied", nil
					result.Failed++
				}
			}
			result.Accepted, result.MembershipAdded, result.MembershipRemoved = 0, 0, 0
			return map[string]any{
				"accepted":            result.Accepted,
				"failed":              result.Failed,
				"memberships_added":   result.MembershipAdded,
				"memberships_removed": result.MembershipRemoved,
			}
		})
		if ctx.Err() != nil {
			retainCommittedProjection(ctx, ws.Root, repoName, cfg, store, &result.Generation, &result.Dirty)
		}
	}()
	if err := store.BeginOperation(ctx, state.Operation{ID: id, Kind: "add", State: state.OperationPlanned, PayloadJSON: string(payloadData)}); err != nil {
		return result, err
	}
	if err := callFault(opts.Fault, "add.planned"); err != nil {
		return result, err
	}
	stageRoot := mutationStageRoot(ws.Root, repoName, id)
	if err := durableMkdir(stageRoot, 0o700); err != nil {
		return result, err
	}
	inputsRoot := filepath.Join(stageRoot, "inputs")
	objectsRoot := filepath.Join(stageRoot, "objects")
	if err := durableMkdir(inputsRoot, 0o700); err != nil {
		return result, err
	}
	if err := durableMkdir(objectsRoot, 0o700); err != nil {
		return result, err
	}

	files, scanFailures := collectInputFiles(ctx, opts.Paths, opts.Recursive)
	result.Items = append(result.Items, scanFailures...)
	result.Failed += len(scanFailures)
	accepted := make([]state.PackageObject, 0, len(files))
	newObjects := make(map[string]state.PackageObject)
	newObjectFacts := make(map[string]state.PackageFact)
	newObjectStage := make(map[string]string)
	byCoordinate := make(map[string]batchCoordinate)
	itemObjects := make(map[int]state.PackageObject)
	inspected := inspectInputs(ctx, inputsRoot, files, opts.Jobs)
	lookups, candidatePaths := lookupInputCoordinates(ctx, store, inspected)
	pathOwners, err := store.PackagePoolPathOwners(ctx, candidatePaths)
	if err != nil {
		return result, err
	}
	sourceDirectories, err := loadSourceDirectorySpellings(ctx, ws.Root, repoName, store, candidatePaths)
	if err != nil {
		return result, err
	}
	rpmPolicy := rpmSigningPolicy{mode: "never"}
	needsRPMPolicy := false
	for index := range files {
		if inspected[index].Err == nil && inspected[index].Object.Format == "rpm" && len(compatibleDists(inspected[index].Object, distNames, effectiveDists)) != 0 {
			needsRPMPolicy = true
			break
		}
	}
	if needsRPMPolicy {
		rpmPolicy, err = loadRPMSigningPolicy(ctx, ws.Root, cfg.Repositories[repoName].Signing.RPM.Packages)
		if err != nil {
			return result, err
		}
	}
	for sequence, input := range files {
		item := MutationItem{Input: input.Display, Status: "failed", Dists: map[string]string{}}
		reused := false
		snapshot := filepath.Join(inputsRoot, fmt.Sprintf("%08d-%s", sequence, input.Base))
		inspection := inspected[sequence]
		if inspection.Err != nil {
			item.Error = inspection.Err.Error()
			result.Failed++
			result.Items = append(result.Items, item)
			continue
		}
		inputSHA, object := inspection.SHA256, inspection.Object
		factSchema, factBlob := inspection.FactSchema, inspection.Facts
		item.Format, item.Coordinate = object.Format, object.Coordinate
		compatible := compatibleDists(object, distNames, effectiveDists)
		if len(compatible) == 0 {
			item.Error = packageCompatibilityDiagnostic(ws.Root, repoName, object, distNames, effectiveDists)
			result.Failed++
			result.Items = append(result.Items, item)
			continue
		}
		coordinateKey := object.Format + "\x00" + object.Coordinate
		if prior, exists := byCoordinate[coordinateKey]; exists {
			reusable := prior.inputSHA == inputSHA
			if object.Format == "rpm" && rpmPolicy.mode != "never" {
				reusable = prior.payload == object.PayloadSHA256
			}
			if !reusable {
				item.Error = "logical coordinate conflicts with another input in this batch"
				result.Failed++
				result.Items = append(result.Items, item)
				continue
			}
			object = prior.object
			reused = true
			_ = removeOwnedRegularPath(ws.Root, snapshot, -1)
		} else {
			existing, lookupErr := lookups[sequence].object, lookups[sequence].err
			switch {
			case lookupErr == nil:
				reusable := existing.SHA256 == object.SHA256
				if !reusable && object.Format == "rpm" && existing.PayloadSHA256 == object.PayloadSHA256 && rpmPolicy.mode != "never" {
					source, sourceErr := availableManagedPackageSource(ws.Root, repoName, existing)
					if sourceErr == nil {
						opened, openErr := source.open()
						if openErr == nil {
							reusable = rpmPolicy.permitsNeutralReuseReader(ctx, opened.file)
							openErr = opened.CloseVerified()
						}
						if openErr != nil {
							sourceErr = openErr
						}
					}
					if sourceErr != nil {
						item.Error = sourceErr.Error()
						result.Failed++
						result.Items = append(result.Items, item)
						continue
					}
				}
				if !reusable {
					item.Error = "logical coordinate already maps to different content"
					result.Failed++
					result.Items = append(result.Items, item)
					continue
				}
				object = existing
				reused = true
				_ = removeOwnedRegularPath(ws.Root, snapshot, -1)
				byCoordinate[coordinateKey] = batchCoordinate{inputSHA: inputSHA, payload: object.PayloadSHA256, object: object}
			case errors.Is(lookupErr, state.ErrNotFound):
				if object.Format == "rpm" {
					unsignedSHA := object.SHA256
					object, err = rpmPolicy.prepare(ctx, snapshot, input.Base, object)
					if err != nil {
						item.Error = err.Error()
						result.Failed++
						result.Items = append(result.Items, item)
						continue
					}
					if object.SHA256 != unsignedSHA {
						parsed, refreshedSchema, refreshedFacts, refreshErr := inspectSnapshotWithFacts(ctx, snapshot, input.Base, object.SHA256, object.PayloadSHA256)
						if refreshErr != nil || !sameManagedPackageFacts(object, parsed) {
							item.Error = errors.Join(errors.New("managed: signed RPM facts differ from prepared object"), refreshErr).Error()
							result.Failed++
							result.Items = append(result.Items, item)
							continue
						}
						factSchema, factBlob = refreshedSchema, refreshedFacts
					}
				}
				if err := errors.Join(pathOwners.Check(object), sourceDirectories.check(object)); err != nil {
					item.Error = err.Error()
					result.Failed++
					result.Items = append(result.Items, item)
					continue
				}
				objectStage := filepath.Join(objectsRoot, object.SHA256)
				if existingStage, duplicate := newObjectStage[object.SHA256]; duplicate {
					_ = existingStage
					_ = removeOwnedRegularPath(ws.Root, snapshot, -1)
				} else if err := durableRename(ws.Root, snapshot, objectStage); err != nil {
					item.Error = err.Error()
					result.Failed++
					result.Items = append(result.Items, item)
					continue
				} else {
					newObjects[object.SHA256] = object
					newObjectFacts[object.SHA256] = state.PackageFact{PackageSHA256: object.SHA256, FactSchema: factSchema, Facts: append([]byte(nil), factBlob...)}
					newObjectStage[object.SHA256] = objectStage
				}
				pathOwners.Add(object)
				sourceDirectories.add(object)
				byCoordinate[coordinateKey] = batchCoordinate{inputSHA: inputSHA, payload: object.PayloadSHA256, object: object, new: true}
			default:
				item.Error = lookupErr.Error()
				result.Failed++
				result.Items = append(result.Items, item)
				continue
			}
		}
		item.Status, item.SHA256 = "accepted", object.SHA256
		if reused {
			item.Status = "reused"
		}
		for _, dist := range compatible {
			item.Dists[dist] = "candidate"
		}
		accepted = append(accepted, object)
		result.Items = append(result.Items, item)
		itemObjects[len(result.Items)-1] = object
	}

	desired := make(map[string][]string, len(distNames))
	outcomes := []state.OperationMembership{}
	keptByDist := make(map[string]map[string]struct{}, len(distNames))
	excludedByDist := make(map[string]map[string]string, len(distNames))
	existingObjects, err := store.ListPackageObjects(ctx, distNames, false)
	if err != nil {
		return result, err
	}
	existingByDist := packageObjectsByDist(existingObjects, distNames, false)
	for _, distName := range distNames {
		desired[distName] = []string{}
		existing := existingByDist[distName]
		candidates := append(append([]state.PackageObject(nil), existing...), accepted...)
		policyResult, err := ApplyPolicy(candidates, effectiveDists[distName])
		if err != nil {
			return result, err
		}
		keptByDist[distName] = make(map[string]struct{}, len(policyResult.Kept))
		for _, object := range policyResult.Kept {
			desired[distName] = append(desired[distName], object.SHA256)
			keptByDist[distName][object.SHA256] = struct{}{}
		}
		excludedByDist[distName] = map[string]string{}
		for _, object := range policyResult.Excluded {
			excludedByDist[distName][object.SHA256] = "excluded"
			outcomes = append(outcomes, state.OperationMembership{DistName: distName, PackageSHA256: object.SHA256, Action: "exclude"})
		}
		for _, object := range policyResult.Limited {
			excludedByDist[distName][object.SHA256] = "limited"
			outcomes = append(outcomes, state.OperationMembership{DistName: distName, PackageSHA256: object.SHA256, Action: "limit"})
		}
		before := make(map[string]struct{}, len(existing))
		for _, object := range existing {
			before[object.SHA256] = struct{}{}
		}
		for digest := range keptByDist[distName] {
			if _, present := before[digest]; !present {
				result.MembershipAdded++
			}
		}
		for digest := range before {
			if _, retained := keptByDist[distName][digest]; !retained {
				result.MembershipRemoved++
			}
		}
	}
	for itemIndex, object := range itemObjects {
		item := &result.Items[itemIndex]
		acceptedSomewhere := false
		for distName := range item.Dists {
			if _, kept := keptByDist[distName][object.SHA256]; kept {
				item.Dists[distName] = "accepted"
				acceptedSomewhere = true
			} else if disposition := excludedByDist[distName][object.SHA256]; disposition != "" {
				item.Dists[distName] = disposition
			}
		}
		if acceptedSomewhere {
			result.Accepted++
		} else {
			item.Status = "excluded"
		}
	}
	if err := store.RecordOperationPackages(ctx, id, mutationPackageRecords(result.Items)); err != nil {
		return result, err
	}
	if result.Failed != 0 && result.Accepted == 0 {
		resultData, marshalErr := json.Marshal(map[string]int{"accepted": result.Accepted, "failed": result.Failed})
		if marshalErr != nil {
			return result, marshalErr
		}
		if err := store.FailOperation(ctx, id, "rejected", "no input package was accepted", string(resultData)); err != nil {
			return result, err
		}
		if err := cleanupMutationStage(ws.Root, repoName, id); err != nil {
			return result, err
		}
		summary, err := store.Summary(ctx)
		if err != nil {
			return result, err
		}
		result.Generation, result.Revision = summary.BuiltGeneration, summary.DesiredRevision
		result.Dirty, err = observedRepositoryDirty(ctx, ws.Root, repoName, cfg, store)
		if err != nil {
			return result, err
		}
		return result, fmt.Errorf("%w: no input package was accepted", ErrRejected)
	}

	referencedNew := []state.PackageObject{}
	for digest, object := range newObjects {
		if desiredContains(desired, digest) {
			referencedNew = append(referencedNew, object)
		} else {
			_ = removeOwnedRegularPath(ws.Root, newObjectStage[digest], -1)
		}
	}
	sort.Slice(referencedNew, func(i, j int) bool { return referencedNew[i].SHA256 < referencedNew[j].SHA256 })
	manifest := mutationManifest{Version: mutationOperationVersion, Objects: referencedNew, Desired: desired, Result: map[string]int{"accepted": result.Accepted, "failed": result.Failed}, Outcomes: outcomes, RPMSigningKeys: rpmPolicy.retainedKeys}
	desiredChangedDists, err := changedDesiredDists(ctx, store, desired)
	if err != nil {
		return result, err
	}
	// Preserve an explicitly bound empty build scope as [] in the recovery
	// journal. A nil slice encodes as JSON null and is deliberately rejected by
	// validateMutationBuildDists as an absent pre-v2 binding.
	payload.BuildDists = append([]string{}, desiredChangedDists...)
	if !opts.Skip {
		payload.BuildDists, err = distsNeedingBuild(ctx, ws.Root, repoName, cfg, store, desired)
		if err != nil {
			return result, err
		}
	}
	payload.Noop = !opts.Skip && len(payload.BuildDists) == 0
	var preflight *mutationBuildPreflight
	if !opts.Skip && len(payload.BuildDists) != 0 {
		var preparedPolicy *rpmSigningPolicy
		if needsRPMPolicy {
			preparedPolicy = &rpmPolicy
		}
		preflight, err = prepareMutationBuildPreflight(ctx, ws.Root, repoName, cfg, payload.BuildDists, manifest, store, preparedPolicy, currentSnapshot, opts.Jobs)
		if err != nil {
			return result, err
		}
		manifest.RPMSigningKeys = append([]state.RPMSigningKey(nil), preflight.rpmPolicy.retainedKeys...)
	}
	manifestData, err := marshalMutationManifest(manifest)
	if err != nil {
		return result, err
	}
	payload.ManifestSHA256 = bytesSHA(manifestData)
	manifestPath := mutationManifestPath(ws.Root, repoName, id, payload.ManifestSHA256)
	if err := writeAtomic(manifestPath, manifestData, 0o600); err != nil {
		return result, err
	}
	payloadData, _ = json.Marshal(payload)
	if err := store.UpdateOperationPayload(ctx, id, string(payloadData)); err != nil {
		return result, err
	}
	if err := store.SetOperationState(ctx, id, state.OperationStaged, ""); err != nil {
		return result, err
	}
	if err := callFault(opts.Fault, "add.staged"); err != nil {
		return result, err
	}
	for _, object := range referencedNew {
		if err := installPendingObject(ctx, ws.Root, repoName, newObjectStage[object.SHA256], object); err != nil {
			return result, err
		}
		if err := rememberRPMBuildAuthorization(ws.Root, repoName, object, preflight); err != nil {
			return result, err
		}
	}
	resultSummary, _ := json.Marshal(manifest.Result)
	mutationResult, err := store.ApplyDesiredMutationWithSigningKeys(ctx, id, referencedNew, manifest.RPMSigningKeys, desired, string(resultSummary))
	result.Revision = mutationResult.Revision
	if err != nil {
		if mutationResult.Revision != 0 {
			retainCommittedProjection(ctx, ws.Root, repoName, cfg, store, &result.Generation, &result.Dirty)
		}
		return result, err
	}
	facts := make([]state.PackageFact, 0, len(referencedNew))
	for _, object := range referencedNew {
		fact, exists := newObjectFacts[object.SHA256]
		if !exists {
			return result, fmt.Errorf("%w: package facts are unavailable for new object %s", ErrIntegrity, object.SHA256)
		}
		facts = append(facts, fact)
	}
	if err := store.UpsertPackageFacts(ctx, facts); err != nil {
		return result, err
	}
	if !sameStringSet(mutationResult.ChangedDists, desiredChangedDists) {
		return result, fmt.Errorf("%w: applied add Dist changes differ from its staged Desired change set", ErrIntegrity)
	}
	if err := store.RecordOperationMembershipOutcomes(ctx, id, manifest.Outcomes); err != nil {
		retainCommittedProjection(ctx, ws.Root, repoName, cfg, store, &result.Generation, &result.Dirty)
		return result, err
	}
	for _, object := range mutationResult.DroppedPending {
		if err := removePendingObject(ws.Root, repoName, object); err != nil {
			return result, err
		}
	}
	if err := callFault(opts.Fault, "add.applied"); err != nil {
		return result, err
	}
	if opts.Skip {
		terminal, err := mutationTerminalStateForProjection(ctx, ws.Root, repoName, cfg, store)
		if err != nil {
			return result, err
		}
		if err := store.SetOperationState(ctx, id, terminal, ""); err != nil {
			if retainCommittedTerminalProjection(ctx, ws.Root, repoName, cfg, store, id, terminal, &result.Generation, &result.Dirty) {
				err = errors.Join(err, cleanupMutationStage(ws.Root, repoName, id))
			}
			return result, err
		}
		retainCommittedProjection(ctx, ws.Root, repoName, cfg, store, &result.Generation, &result.Dirty)
		if err := cleanupMutationStage(ws.Root, repoName, id); err != nil {
			return result, err
		}
	} else if len(payload.BuildDists) != 0 {
		generation, err := buildAppliedMutation(ctx, ws.Root, repoName, cfg, payload.BuildDists, id, store, opts.Jobs, opts.Fault, preflight)
		result.Generation = generation
		if err != nil {
			retainCommittedProjection(ctx, ws.Root, repoName, cfg, store, &result.Generation, &result.Dirty)
			return result, err
		}
	} else {
		if _, err := normalizeCurrentPublicTreeWithSnapshot(ctx, ws.Root, repoName, id, store, opts.Fault, currentSnapshot); err != nil {
			return result, err
		}
		if err := store.FinalizeNoopBuild(ctx, id); err != nil {
			if retainCommittedTerminalProjection(ctx, ws.Root, repoName, cfg, store, id, state.OperationDone, &result.Generation, &result.Dirty) {
				err = errors.Join(err, cleanupMutationStage(ws.Root, repoName, id))
			}
			return result, err
		}
		retainCommittedProjection(ctx, ws.Root, repoName, cfg, store, &result.Generation, &result.Dirty)
		if err := cleanupMutationStage(ws.Root, repoName, id); err != nil {
			return result, err
		}
	}
	result.Dirty, err = observedRepositoryDirty(ctx, ws.Root, repoName, cfg, store)
	if err != nil {
		return result, err
	}
	if result.Failed != 0 && result.Accepted != 0 {
		return result, &PartialError{Result: result}
	}
	return result, nil
}

// retainCommittedProjection preserves the externally observable repository
// result when a SQLite transaction committed but its following WAL checkpoint
// failed. The original error remains authoritative; this helper only prevents
// non-zero JSON output from falsely reporting pre-commit revision/generation
// or cleanliness. It is also safe before commit because it only snapshots the
// currently committed projection.
// sourceDirectorySpellings guards a case-insensitive workspace, where two pool
// source directories that differ only by case are one physical directory. It is
// nil, and every check passes, on case-sensitive filesystems.
type sourceDirectorySpellings map[string]map[string]struct{}

func poolSourceDirectory(poolPath string) string {
	return poolPath[:strings.LastIndex(poolPath, "/")+1]
}

func loadSourceDirectorySpellings(ctx context.Context, root, repoName string, store *state.Store, candidatePaths []string) (sourceDirectorySpellings, error) {
	if len(candidatePaths) == 0 {
		return nil, nil
	}
	insensitive, err := filesystemDirectoryIsCaseInsensitive(filepath.Join(root, repoName))
	if err != nil || !insensitive {
		return nil, err
	}
	directories := make([]string, 0, len(candidatePaths))
	for _, candidate := range candidatePaths {
		directories = append(directories, poolSourceDirectory(candidate))
	}
	existing, err := store.PackagePoolDirectorySpellings(ctx, directories)
	if err != nil {
		return nil, err
	}
	spellings := sourceDirectorySpellings{}
	for folded, exact := range existing {
		for _, spelling := range exact {
			spellings.remember(folded, spelling)
		}
	}
	return spellings, nil
}

func (spellings sourceDirectorySpellings) remember(folded, exact string) {
	if spellings[folded] == nil {
		spellings[folded] = map[string]struct{}{}
	}
	spellings[folded][exact] = struct{}{}
}

func (spellings sourceDirectorySpellings) check(object state.PackageObject) error {
	if spellings == nil {
		return nil
	}
	directory := poolSourceDirectory(object.PoolPath)
	known := spellings[strings.ToLower(directory)]
	if _, same := known[directory]; same || len(known) == 0 {
		return nil
	}
	others := make([]string, 0, len(known))
	for other := range known {
		others = append(others, strings.TrimSuffix(other, "/"))
	}
	sort.Strings(others)
	return fmt.Errorf("%w: %w: package source directory %s differs only by case from %s; this workspace is on a case-insensitive filesystem where both are one directory", state.ErrConflict, state.ErrPoolPathConflict, strings.TrimSuffix(directory, "/"), others[0])
}

func (spellings sourceDirectorySpellings) add(object state.PackageObject) {
	if spellings == nil {
		return
	}
	directory := poolSourceDirectory(object.PoolPath)
	spellings.remember(strings.ToLower(directory), directory)
}

type coordinateLookup struct {
	object state.PackageObject
	err    error
}

// lookupInputCoordinates resolves each inspected input's logical coordinate
// once. Only a new coordinate can create a Package Object, so only its pool
// path enters the path-owner query; re-added packages never read the
// per-checkpoint publication history of their paths.
func lookupInputCoordinates(ctx context.Context, store *state.Store, inspected []inspectedInput) ([]coordinateLookup, []string) {
	lookups := make([]coordinateLookup, len(inspected))
	candidatePaths := make([]string, 0, len(inspected))
	for index, input := range inspected {
		if input.Err != nil {
			continue
		}
		existing, err := store.FindPackageByCoordinate(ctx, input.Object.Format, input.Object.Coordinate)
		lookups[index] = coordinateLookup{object: existing, err: err}
		if errors.Is(err, state.ErrNotFound) {
			candidatePaths = append(candidatePaths, input.Object.PoolPath)
		}
	}
	return lookups, candidatePaths
}

func retainCommittedProjection(ctx context.Context, root, repoName string, cfg config.Config, store *state.Store, generation *state.GenerationID, dirty *bool) {
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.WithoutCancel(ctx), operationFailureFinalizeTimeout)
		defer cancel()
	}
	if summary, err := store.Summary(ctx); err == nil {
		*generation = summary.BuiltGeneration
		*dirty = summary.Status != "clean"
	}
	if observed, err := observedRepositoryDirty(ctx, root, repoName, cfg, store); err == nil {
		*dirty = observed
	}
}

func retainCommittedTerminalProjection(ctx context.Context, root, repoName string, cfg config.Config, store *state.Store, operationID string, terminal state.OperationState, generation *state.GenerationID, dirty *bool) bool {
	retainCommittedProjection(ctx, root, repoName, cfg, store, generation, dirty)
	detail, err := store.GetOperation(ctx, operationID)
	return err == nil && detail.Operation.State == terminal
}

func mutationTerminalStateForProjection(ctx context.Context, root, repoName string, cfg config.Config, store *state.Store) (state.OperationState, error) {
	dirty, err := observedRepositoryDirty(ctx, root, repoName, cfg, store)
	if err != nil {
		return "", err
	}
	if dirty {
		return state.OperationDoneDirty, nil
	}
	return state.OperationDone, nil
}

func mutationPackageRecords(items []MutationItem) []state.OperationPackage {
	records := make([]state.OperationPackage, 0, len(items))
	for _, item := range items {
		disposition := item.Status
		if disposition != "accepted" && disposition != "reused" && disposition != "excluded" && disposition != "failed" {
			disposition = "failed"
		}
		record := state.OperationPackage{InputPath: item.Input, PackageSHA256: item.SHA256, Coordinate: item.Coordinate, Disposition: disposition, Message: item.Error, Dists: item.Dists}
		if item.Error != "" {
			record.ErrorClass = "package"
		}
		records = append(records, record)
	}
	return records
}

func selectedMutationDists(ws config.Workspace, cfg config.Config, repoName string, explicit []string) ([]string, map[string]config.EffectiveDist, error) {
	names := stableUniqueStrings(explicit)
	if len(names) == 0 {
		name, inside, err := config.DistContainingCWD(ws, cfg, repoName)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrWorkspaceInput, err)
		}
		if inside {
			names = []string{name}
		} else if len(cfg.Repositories[repoName].Dists) == 1 {
			for candidate := range cfg.Repositories[repoName].Dists {
				names = []string{candidate}
			}
		} else if len(cfg.Repositories[repoName].Dists) == 0 {
			return nil, nil, fmt.Errorf("%w: repository %q has no configured Dists", ErrWorkspaceInput, repoName)
		} else {
			candidates := sortedDistConfigNames(cfg.Repositories[repoName])
			return nil, nil, fmt.Errorf("%w: repository %q has multiple Dists (%s); select one or more with --dist", ErrWorkspaceInput, repoName, strings.Join(candidates, ", "))
		}
	}
	sort.Strings(names)
	result := make(map[string]config.EffectiveDist, len(names))
	for _, name := range names {
		if err := config.ValidateName(name); err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrRejected, err)
		}
		if _, exists := cfg.Repositories[repoName].Dists[name]; !exists {
			return nil, nil, fmt.Errorf("%w: dist %q is not configured in repository %q", ErrRejected, name, repoName)
		}
		view, err := config.EffectiveView(cfg, config.ViewOptions{Repository: repoName, Dist: name})
		if err != nil {
			return nil, nil, err
		}
		result[name] = view.Repositories[repoName].Dists[name]
	}
	return names, result, nil
}

func compatibleDists(object state.PackageObject, names []string, dists map[string]config.EffectiveDist) []string {
	result := []string{}
	for _, name := range names {
		dist := dists[name]
		if dist.Format != object.Format {
			continue
		}
		if object.CanonicalArch == "neutral" {
			result = append(result, name)
			continue
		}
		for _, architecture := range dist.Architectures {
			if architecture == object.CanonicalArch {
				result = append(result, name)
				break
			}
		}
	}
	return result
}

func packageCompatibilityDiagnostic(root, repoName string, object state.PackageObject, names []string, dists map[string]config.EffectiveDist) string {
	matchingFormat := []string{}
	allowedCanonical := map[string]struct{}{}
	selected := make([]string, 0, len(names))
	for _, name := range names {
		dist := dists[name]
		selected = append(selected, fmt.Sprintf("%s(%s)", name, dist.Format))
		if dist.Format != object.Format {
			continue
		}
		matchingFormat = append(matchingFormat, fmt.Sprintf("%s=[%s]", name, strings.Join(dist.Architectures, ", ")))
		for _, architecture := range dist.Architectures {
			allowedCanonical[architecture] = struct{}{}
		}
	}
	configPath := filepath.Join(root, config.ConfigFilename)
	if len(matchingFormat) == 0 {
		return fmt.Sprintf("package format %q has no compatible selected Dist (selected: %s); select or configure a %s Dist under repos.%s.dists in %s", object.Format, strings.Join(selected, ", "), object.Format, repoName, configPath)
	}
	canonical := mapsKeysSet(allowedCanonical)
	ecosystem := make([]string, 0, len(canonical))
	for _, architecture := range canonical {
		value := architecture
		if object.Format == "deb" {
			if architecture == "x86_64" {
				value = "amd64"
			} else if architecture == "aarch64" {
				value = "arm64"
			}
		}
		ecosystem = append(ecosystem, value)
	}
	return fmt.Sprintf("detected %s architecture %q (canonical %q) is not allowed by selected Dists %s; allowed canonical architectures are [%s] (%s values [%s]); update repos.%s.dists.<dist>.architectures in %s or select a compatible Dist", object.Format, object.Architecture, object.CanonicalArch, strings.Join(matchingFormat, ", "), strings.Join(canonical, ", "), object.Format, strings.Join(ecosystem, ", "), repoName, configPath)
}

func mapsKeysSet(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func desiredContains(desired map[string][]string, digest string) bool {
	for _, packages := range desired {
		for _, candidate := range packages {
			if candidate == digest {
				return true
			}
		}
	}
	return false
}

func installPendingObject(ctx context.Context, root, repoName, staged string, object state.PackageObject) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	pendingRelative := filepath.Join(".sow", repoName, "pending", object.SHA256)
	pendingSource := ManagedPackageSource{Object: object, Owner: root, Relative: pendingRelative, Path: filepath.Join(root, pendingRelative)}
	if opened, err := pendingSource.open(); err == nil {
		digest, hashErr := hashOpenedFileContext(ctx, opened.file)
		verifyErr := opened.CloseVerified()
		if err := ctx.Err(); err != nil {
			return errors.Join(err, verifyErr)
		}
		if hashErr != nil || verifyErr != nil || digest != object.SHA256 {
			return fmt.Errorf("%w: pending object %s checksum mismatch", ErrIntegrity, object.SHA256)
		}
		stagedRelative, relativeErr := relativeToRoot(root, staged)
		if relativeErr != nil {
			return relativeErr
		}
		return removeRootedRegular(root, stagedRelative, object.Size)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: pending object %s conflicts: %v", ErrIntegrity, object.SHA256, err)
	}
	stagedRelative, err := relativeToRoot(root, staged)
	if err != nil {
		return err
	}
	// Pending lives below a private directory, so storing the immutable object
	// in its final public mode does not expose it. It also avoids a second
	// per-file chmod+fsync when a later build hardlinks it into Pool.
	//
	// renameRootedRegular authenticates the held inode once, then fsyncs the
	// payload before this pending name becomes durable. Payload promotion
	// depends on that barrier to skip its own inode
	// fsync; see managedPayloadFileMode.
	if err := renameRootedRegular(ctx, root, stagedRelative, pendingRelative, object.Size, object.SHA256, managedPayloadFileMode, managedPendingDirectoryMode); err != nil {
		return fmt.Errorf("managed: staged object %s cannot be installed: %w", object.SHA256, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func removePendingObject(root, repoName string, object state.PackageObject) error {
	expectedSize := object.Size
	if object.Format == "" {
		// Recovery journals intentionally retain only the immutable digest after
		// the PackageObject row has been deleted in the committing transaction.
		expectedSize = -1
	}
	return removeRootedRegular(root, filepath.Join(".sow", repoName, "pending", object.SHA256), expectedSize)
}

func mutationStageRoot(root, repoName, id string) string {
	return filepath.Join(root, ".sow", repoName, "stage", id)
}

func cleanupMutationStage(root, repoName, id string) error {
	return removeOwnedDirectory(mutationStageRoot(root, repoName, id), filepath.Join(root, ".sow", repoName, "stage"))
}

const operationFailureFinalizeTimeout = 5 * time.Second

// finalizePreApplyMutationOperation turns an ordinary in-process error into a
// terminal failed audit record only while no Desired transaction has applied.
// Injected crash simulation, panic/SIGKILL, and applied/built errors deliberately
// retain a non-terminal journal for deterministic recovery.
func finalizePreApplyMutationOperation(parent context.Context, root, repoName, id string, store *state.Store, returned error, result func() any) error {
	if returned == nil || isInjectedFault(returned) || store == nil || id == "" {
		return returned
	}
	if parent == nil {
		parent = context.Background()
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), operationFailureFinalizeTimeout)
	defer cancel()
	operation, err := store.GetOperationSummary(cleanupCtx, id)
	if errors.Is(err, state.ErrNotFound) {
		return returned
	}
	if err != nil {
		return errors.Join(returned, fmt.Errorf("managed: inspect failed operation journal: %w", err))
	}
	if operation.State != state.OperationPlanned && operation.State != state.OperationStaged {
		return returned
	}
	resultJSON := `{}`
	if result != nil {
		if data, marshalErr := json.Marshal(result()); marshalErr == nil && len(data) <= state.MaxOperationPayloadBytes {
			resultJSON = string(data)
		}
	}
	class, message := safeOperationFailure(returned)
	if err := store.FailOperation(cleanupCtx, id, class, message, resultJSON); err != nil {
		return errors.Join(returned, fmt.Errorf("managed: persist pre-apply failure: %w", err))
	}
	// The terminal record is durable before deleting the only internal copy.
	// Keep its manifest until every pending object has been cleaned, so an
	// interrupted cleanup is retried from the directory on the next write.
	if err := cleanupFailedMutation(cleanupCtx, root, repoName, store, operation); err != nil {
		return errors.Join(returned, fmt.Errorf("managed: clean terminal failed operation: %w; the failure is recorded and the next write command (for example sow build) removes the remaining temporary files", err))
	}
	return returned
}

func cleanupFailedMutation(ctx context.Context, root, repoName string, store *state.Store, operation state.Operation) error {
	if operation.Kind == "add" {
		var payload mutationOperationPayload
		if err := jsonUnmarshalStrict(operation.PayloadJSON, &payload); err != nil || payload.Repository != repoName || payload.Kind != "add" {
			return fmt.Errorf("%w: failed add payload is not cleanup-safe", ErrIntegrity)
		}
		if payload.ManifestSHA256 != "" {
			manifest, err := readMutationManifest(root, repoName, operation.ID, payload.ManifestSHA256)
			if err != nil {
				// Once terminal, an absent manifest is the tail of stage removal:
				// pending cleanup always completed before that removal started.
				// Permission, I/O, parse and digest errors preserve the evidence.
				if errors.Is(err, os.ErrNotExist) {
					return cleanupMutationStage(root, repoName, operation.ID)
				}
				return err
			}
			for _, object := range manifest.Objects {
				if err := ctx.Err(); err != nil {
					return err
				}
				if _, err := store.GetPackageObject(ctx, object.SHA256); errors.Is(err, state.ErrNotFound) {
					if err := removePendingObject(root, repoName, object); err != nil {
						return err
					}
				} else if err != nil {
					return err
				}
				// A later command may have committed this digest after failure.
				// Its present owner wins over the old cleanup journal.
			}
		}
	}
	return cleanupMutationStage(root, repoName, operation.ID)
}

func safeOperationFailure(err error) (string, string) {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "cancelled", "operation context ended before Desired state was applied"
	case errors.Is(err, ErrRejected):
		return "rejected", "operation was rejected before Desired state was applied"
	case errors.Is(err, ErrIntegrity):
		return "integrity", "integrity validation failed before Desired state was applied"
	default:
		return "runtime", "operation failed before Desired state was applied"
	}
}

func stableUniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := []string{}
	for _, value := range values {
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func mutationManifestPath(root, repoName, id, digest string) string {
	return filepath.Join(mutationStageRoot(root, repoName, id), "manifest."+digest+".json")
}

func readMutationManifest(root, repoName, id, expectedSHA string) (mutationManifest, error) {
	var manifest mutationManifest
	if !lowercaseSHA256.MatchString(expectedSHA) {
		return manifest, fmt.Errorf("%w: mutation manifest digest is malformed", ErrIntegrity)
	}
	stageOwner := filepath.Join(root, ".sow", repoName, "stage")
	relative := filepath.Join(id, "manifest."+expectedSHA+".json")
	data, err := readRootedPrivateRegular(stageOwner, relative, maxMutationManifestBytes, false)
	if err != nil {
		return manifest, fmt.Errorf("%w: mutation manifest cannot be read: %w", ErrIntegrity, err)
	}
	if bytesSHA(data) != expectedSHA {
		return manifest, fmt.Errorf("%w: mutation manifest differs from journal", ErrIntegrity)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil || manifest.Version != mutationOperationVersion || manifest.Desired == nil {
		return mutationManifest{}, fmt.Errorf("%w: invalid mutation manifest", ErrIntegrity)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return mutationManifest{}, fmt.Errorf("%w: mutation manifest has trailing content", ErrIntegrity)
	}
	buildDists := func() []mutationBuildDist {
		if manifest.Build == nil {
			return nil
		}
		return manifest.Build.Dists
	}()
	seenBuildDists := make(map[string]struct{}, len(buildDists))
	for _, dist := range buildDists {
		if config.ValidateName(dist.Name) != nil || !lowercaseSHA256.MatchString(dist.TreeSHA256) || !lowercaseSHA256.MatchString(dist.EffectiveConfigSHA256) || len(dist.Architectures) == 0 {
			return mutationManifest{}, fmt.Errorf("%w: invalid mutation build Dist binding", ErrIntegrity)
		}
		if _, duplicate := seenBuildDists[dist.Name]; duplicate {
			return mutationManifest{}, fmt.Errorf("%w: mutation build repeats Dist %q", ErrIntegrity, dist.Name)
		}
		seenBuildDists[dist.Name] = struct{}{}
		identity := metadataSignerIdentity{Fingerprint: dist.MetadataSignerFingerprint, PublicKey: dist.MetadataSignerPublicKey}
		if err := validateMetadataSignerIdentity(identity); err != nil {
			return mutationManifest{}, fmt.Errorf("%w: mutation build signer identity for Dist %q is invalid", ErrIntegrity, dist.Name)
		}
	}
	normalizedKeys, err := normalizeRetainedRPMSigningKeys(manifest.RPMSigningKeys)
	if err != nil || len(normalizedKeys) != len(manifest.RPMSigningKeys) {
		return mutationManifest{}, fmt.Errorf("%w: invalid retained RPM signing key manifest", ErrIntegrity)
	}
	for index := range normalizedKeys {
		actual := manifest.RPMSigningKeys[index]
		expected := normalizedKeys[index]
		if actual.Fingerprint != expected.Fingerprint || actual.SnapshotSHA256 != expected.SnapshotSHA256 || string(actual.PublicKey) != string(expected.PublicKey) {
			return mutationManifest{}, fmt.Errorf("%w: non-canonical retained RPM signing key manifest", ErrIntegrity)
		}
	}
	desiredSets := make(map[string]map[string]struct{}, len(manifest.Desired))
	for dist, digests := range manifest.Desired {
		if config.ValidateName(dist) != nil {
			return mutationManifest{}, fmt.Errorf("%w: invalid mutation manifest Dist", ErrIntegrity)
		}
		desiredSets[dist] = make(map[string]struct{}, len(digests))
		for _, digest := range digests {
			if !lowercaseSHA256.MatchString(digest) {
				return mutationManifest{}, fmt.Errorf("%w: invalid mutation manifest package digest", ErrIntegrity)
			}
			desiredSets[dist][digest] = struct{}{}
		}
	}
	seenOutcomes := make(map[string]struct{}, len(manifest.Outcomes))
	for _, outcome := range manifest.Outcomes {
		desired, exists := desiredSets[outcome.DistName]
		if !lowercaseSHA256.MatchString(outcome.PackageSHA256) || config.ValidateName(outcome.DistName) != nil || (!exists && outcome.Action == "keep") || (outcome.Action != "keep" && outcome.Action != "exclude" && outcome.Action != "limit") {
			return mutationManifest{}, fmt.Errorf("%w: invalid mutation policy outcome", ErrIntegrity)
		}
		identity := outcome.DistName + "\x00" + outcome.PackageSHA256
		if _, duplicate := seenOutcomes[identity]; duplicate {
			return mutationManifest{}, fmt.Errorf("%w: duplicate mutation policy outcome", ErrIntegrity)
		}
		seenOutcomes[identity] = struct{}{}
		_, retained := desired[outcome.PackageSHA256]
		if outcome.Action == "keep" && !retained || outcome.Action != "keep" && retained {
			return mutationManifest{}, fmt.Errorf("%w: mutation policy outcome contradicts Desired Membership", ErrIntegrity)
		}
	}
	return manifest, nil
}

// normalizeLegacyMutationDesired restores only empty entries omitted by old
// add journals. The original bytes/hash remain authoritative and unchanged.
func normalizeLegacyMutationDesired(ctx context.Context, store *state.Store, operation state.Operation, payload mutationOperationPayload, manifest *mutationManifest) error {
	for _, outcome := range manifest.Outcomes {
		if !stringSetSubset([]string{outcome.DistName}, payload.Dists) {
			return fmt.Errorf("%w: mutation policy outcome is outside its Dist scope", ErrIntegrity)
		}
	}
	if sameStringSet(payload.Dists, mapsKeys(manifest.Desired)) {
		return nil
	}
	if operation.Kind != "add" || !stringSetSubset(mapsKeys(manifest.Desired), payload.Dists) {
		return fmt.Errorf("%w: mutation manifest Dist set differs from journal", ErrIntegrity)
	}
	detail, err := store.GetOperation(ctx, operation.ID)
	if err != nil {
		return err
	}
	if !mutationHasAppliedEvent(detail.Events) {
		return fmt.Errorf("%w: legacy empty Dist journal was not applied", ErrIntegrity)
	}
	for _, dist := range payload.Dists {
		if _, exists := manifest.Desired[dist]; exists {
			continue
		}
		actual, err := store.MembershipDigests(ctx, dist, false)
		if err != nil {
			return err
		}
		if len(actual) != 0 {
			return fmt.Errorf("%w: omitted Desired Dist %s is not empty", ErrIntegrity, dist)
		}
		manifest.Desired[dist] = []string{}
	}
	return nil
}

func mutationHasAppliedEvent(events []state.OperationEvent) bool {
	for _, event := range events {
		switch state.OperationState(event.State) {
		case state.OperationApplied, state.OperationBuilt, state.OperationDone, state.OperationDoneDirty:
			return true
		}
	}
	return false
}

func mutationObjectCopiesMissing(root, repoName, operationID string, object state.PackageObject) (bool, error) {
	for _, path := range []string{
		filepath.Join(root, ".sow", repoName, "pending", object.SHA256),
		filepath.Join(mutationStageRoot(root, repoName, operationID), "objects", object.SHA256),
		filepath.Join(root, repoName, filepath.FromSlash(object.PoolPath)),
	} {
		if _, err := os.Lstat(path); err == nil {
			return false, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	return true, nil
}

func recoverMutationOperation(ctx context.Context, root, repoName string, store *state.Store, operation state.Operation) error {
	if operation.Kind != "add" && operation.Kind != "rm" && operation.Kind != "build" {
		return fmt.Errorf("%w: unsupported pending mutation %q", ErrIntegrity, operation.Kind)
	}
	var payload mutationOperationPayload
	if err := jsonUnmarshalStrict(operation.PayloadJSON, &payload); err != nil || payload.Version != mutationOperationVersion || payload.Repository != repoName || payload.Kind != operation.Kind || !lowercaseSHA256.MatchString(payload.ConfigSHA256) || len(payload.Dists) == 0 {
		return fmt.Errorf("%w: invalid pending mutation payload", ErrIntegrity)
	}
	if operation.State == state.OperationPlanned || operation.State == state.OperationRecovering && payload.ManifestSHA256 == "" {
		if err := cleanupMutationStage(root, repoName, operation.ID); err != nil {
			return err
		}
		return store.SetOperationState(ctx, operation.ID, state.OperationRolledBack, "")
	}
	if operation.State != state.OperationRecovering {
		if err := store.SetOperationState(ctx, operation.ID, state.OperationRecovering, ""); err != nil {
			return err
		}
	}
	// Read the bound manifest before the usual loader: v0.4.0 could omit
	// empty Desired entries, or delete a pending copy before persisting failed.
	detail, err := store.GetOperation(ctx, operation.ID)
	if err != nil {
		return err
	}
	applied := mutationHasAppliedEvent(detail.Events)
	manifest, err := readMutationManifest(root, repoName, operation.ID, payload.ManifestSHA256)
	if err != nil {
		if operation.Kind == "add" && !applied && errors.Is(err, os.ErrNotExist) {
			// Old cleanup could remove the entire stage before recording failure.
			// The atomic event history proves there is no committed Desired data
			// to reconstruct; an absent manifest is not an excuse to ignore any
			// other read, parse, digest or permission failure.
			return finishUnbuiltMutation(ctx, root, repoName, store, operation, mutationManifest{}, "uncommitted legacy add has no stage manifest; rerun add from the original input")
		}
		return err
	}
	if applied && manifest.Build == nil && operation.Kind == "add" && stringSetSubset(mapsKeys(manifest.Desired), payload.Dists) && !sameStringSet(payload.Dists, mapsKeys(manifest.Desired)) {
		for _, dist := range payload.Dists {
			if _, exists := manifest.Desired[dist]; exists {
				continue
			}
			actual, err := store.MembershipDigests(ctx, dist, false)
			if err != nil {
				return err
			}
			if len(actual) != 0 {
				// v0.4.0 applied this journal without the omitted Dist, so that Dist
				// is unchanged. Preserve applied Desired; the next build applies policy.
				return finishUnbuiltMutation(ctx, root, repoName, store, operation, manifest, "legacy add left a fully excluded Dist unchanged; run build to apply its policy")
			}
		}
	}
	if !applied && manifest.Build == nil {
		if operation.Kind == "add" && stringSetSubset(mapsKeys(manifest.Desired), payload.Dists) && !sameStringSet(payload.Dists, mapsKeys(manifest.Desired)) {
			return finishUnbuiltMutation(ctx, root, repoName, store, operation, manifest, "legacy add omitted an empty Dist before Desired was applied; rerun add")
		}
		for _, object := range manifest.Objects {
			missing, err := mutationObjectCopiesMissing(root, repoName, operation.ID, object)
			if err != nil {
				return err
			}
			if missing {
				return finishUnbuiltMutation(ctx, root, repoName, store, operation, manifest, "uncommitted add has no internal byte copy; rerun add from the original input")
			}
		}
	}
	_, payload, manifest, err = loadMutationJournal(ctx, store, root, repoName, operation.ID)
	if err != nil {
		return err
	}
	if !sameStringSet(payload.Dists, mapsKeys(manifest.Desired)) {
		return fmt.Errorf("%w: mutation manifest Dist set differs from journal", ErrIntegrity)
	}
	if err := validateMutationBuildDists(payload); err != nil {
		return err
	}
	if manifest.Build != nil {
		buildDistNames := make([]string, 0, len(manifest.Build.Dists))
		for _, buildDist := range manifest.Build.Dists {
			buildDistNames = append(buildDistNames, buildDist.Name)
		}
		if !sameStringSet(buildDistNames, payload.BuildDists) {
			return fmt.Errorf("%w: mutation build Dist set differs from operation", ErrIntegrity)
		}
	}
	configSHA, configErr := config.FileSHA(filepath.Join(root, config.ConfigFilename))
	if configErr != nil {
		return configErr
	}
	if configSHA != payload.ConfigSHA256 {
		detail, err := store.GetOperation(ctx, operation.ID)
		if err != nil {
			return err
		}
		renderingStarted := false
		for _, event := range detail.Events {
			var progress struct{ Kind, Phase string }
			if json.Unmarshal([]byte(event.DetailJSON), &progress) == nil && progress.Kind == "build_progress" && progress.Phase == "rendering" {
				renderingStarted = true
			}
		}
		if manifest.Build != nil || payload.Skip || !renderingStarted {
			return fmt.Errorf("%w: current config differs from active mutation", ErrIntegrity)
		}
		return finishUnbuiltMutation(ctx, root, repoName, store, operation, manifest, "configuration changed before a build plan was frozen; Desired changes preserved if already applied")
	}
	for _, object := range manifest.Objects {
		if err := ensureMutationObjectAvailable(ctx, root, repoName, operation.ID, object); err != nil {
			return err
		}
	}
	cfg, err := config.Load(filepath.Join(root, config.ConfigFilename))
	if err != nil {
		return err
	}
	if payload.Skip && payload.Noop {
		return fmt.Errorf("%w: skipped mutation cannot be journaled as a no-op build", ErrIntegrity)
	}
	noop := false
	var preflight *mutationBuildPreflight
	if !payload.Skip {
		requiredBuildDists, requiredErr := distsNeedingRecoveredBuild(ctx, root, repoName, cfg, store, manifest)
		if requiredErr != nil {
			return requiredErr
		}
		if !sameStringSet(requiredBuildDists, payload.BuildDists) {
			if manifest.Build == nil {
				previous, previousErr := distsNeedingRecoveredBuildPrevious(ctx, root, repoName, cfg, store, manifest)
				if previousErr != nil {
					return previousErr
				}
				if sameStringSet(previous, payload.BuildDists) {
					return finishUnbuiltMutation(ctx, root, repoName, store, operation, manifest, "metadata authentication contract changed before a build was frozen; rerun build")
				}
			}
			return fmt.Errorf("%w: recovered physical build scope differs from the staged journal", ErrIntegrity)
		}
		noop = len(requiredBuildDists) == 0
		if payload.Noop && !noop {
			return fmt.Errorf("%w: mutation journal marks a required physical build as no-op", ErrIntegrity)
		}
		if !noop && manifest.Build == nil {
			preflight, err = prepareMutationBuildPreflight(ctx, root, repoName, cfg, payload.BuildDists, manifest, store, nil, nil, payload.Jobs)
			if errors.Is(err, errImmutableRPMSigningPolicy) || errors.Is(err, errMetadataSigningPolicy) {
				return finishUnbuiltMutation(ctx, root, repoName, store, operation, manifest, "signing policy rejected the operation before public build; Desired changes preserved if already applied")
			}
			if err != nil {
				return err
			}
		}
	}
	resultJSON, err := json.Marshal(manifest.Result)
	if err != nil {
		return err
	}
	mutation, err := store.ApplyDesiredMutationWithSigningKeys(ctx, operation.ID, manifest.Objects, manifest.RPMSigningKeys, manifest.Desired, string(resultJSON))
	if errors.Is(err, state.ErrPoolPathConflict) && manifest.Build == nil {
		return finishUnbuiltMutation(ctx, root, repoName, store, operation, manifest, "immutable pool path conflict before Desired state was applied")
	}
	if err != nil {
		return err
	}
	if payload.Skip && !stringSetSubset(mutation.ChangedDists, payload.BuildDists) {
		return fmt.Errorf("%w: recovered Desired changes exceed the staged build scope", ErrIntegrity)
	}
	if err := store.RecordOperationMembershipOutcomes(ctx, operation.ID, manifest.Outcomes); err != nil {
		return err
	}
	for _, object := range mutation.DroppedPending {
		if err := removePendingObject(root, repoName, object); err != nil {
			return err
		}
	}
	if payload.Skip {
		terminal, err := mutationTerminalStateForProjection(ctx, root, repoName, cfg, store)
		if err != nil {
			return err
		}
		if err := store.SetOperationState(ctx, operation.ID, terminal, ""); err != nil {
			return err
		}
		return cleanupMutationStage(root, repoName, operation.ID)
	}
	if noop {
		if _, err := normalizeCurrentPublicTree(ctx, root, repoName, operation.ID, store, nil); err != nil {
			return err
		}
		if err := store.FinalizeNoopBuild(ctx, operation.ID); err != nil {
			return err
		}
		return cleanupMutationStage(root, repoName, operation.ID)
	}
	jobs, err := mutationRecoveryJobs(payload)
	if err != nil {
		return err
	}
	_, err = buildAppliedMutation(ctx, root, repoName, cfg, payload.BuildDists, operation.ID, store, jobs, nil, preflight)
	return err
}

func ensureMutationObjectAvailable(ctx context.Context, root, repoName, operationID string, object state.PackageObject) error {
	staged := filepath.Join(mutationStageRoot(root, repoName, operationID), "objects", object.SHA256)
	pending := filepath.Join(root, ".sow", repoName, "pending", object.SHA256)
	if _, err := os.Lstat(pending); err == nil {
		return installPendingObject(ctx, root, repoName, staged, object)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := os.Lstat(staged); err == nil {
		return installPendingObject(ctx, root, repoName, staged, object)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	public := filepath.Join(root, repoName, filepath.FromSlash(object.PoolPath))
	source := ManagedPackageSource{Object: object, Owner: root, Relative: filepath.Join(repoName, filepath.FromSlash(object.PoolPath)), Path: public}
	opened, err := source.open()
	if err != nil {
		return fmt.Errorf("%w: mutation object %s has no durable byte copy", ErrIntegrity, object.SHA256)
	}
	digest, hashErr := hashOpenedFileContext(ctx, opened.file)
	verifyErr := opened.CloseVerified()
	if hashErr != nil || verifyErr != nil || digest != object.SHA256 {
		return fmt.Errorf("%w: public mutation object %s checksum mismatch", ErrIntegrity, object.SHA256)
	}
	return nil
}

func mapsKeys(values map[string][]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func sameStringSet(left, right []string) bool {
	left = stableUniqueStrings(left)
	right = stableUniqueStrings(right)
	sort.Strings(left)
	sort.Strings(right)
	return len(left) == len(right) && strings.Join(left, "\x00") == strings.Join(right, "\x00")
}

func stringSetSubset(subset, superset []string) bool {
	allowed := make(map[string]struct{}, len(superset))
	for _, value := range superset {
		allowed[value] = struct{}{}
	}
	for _, value := range subset {
		if _, ok := allowed[value]; !ok {
			return false
		}
	}
	return true
}
