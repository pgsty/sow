package managed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

const maxMutationBaseManifestBytes = 64 << 20

func marshalMutationBaseManifest(manifest []state.GenerationFile) ([]byte, error) {
	return marshalMutationBaseManifestLimit(manifest, maxMutationBaseManifestBytes)
}

func marshalMutationBaseManifestLimit(manifest []state.GenerationFile, limit int) ([]byte, error) {
	data, err := jsonMarshal(manifest)
	if err != nil {
		return nil, err
	}
	if limit < 1 || len(data) > limit {
		return nil, fmt.Errorf("%w: %w: base manifest is %d bytes, maximum is %d", ErrRejected, errMutationRecoveryArtifactTooLarge, len(data), limit)
	}
	return data, nil
}

type mutationBuildPreflight struct {
	distNames        []string
	generation       int64
	publicationTime  time.Time
	baseManifest     []state.GenerationFile
	metadataSnapshot metadataSignerSnapshot
	rpmPolicy        rpmSigningPolicy
	projectedDists   []mutationBuildDist
}

// prepareMutationBuildPreflight freezes every signer identity used by the
// immediate build and proves, before Desired state is applied, that both
// recovery artifacts fit the same bounds enforced by their readers. Pooled is
// conservatively projected as every Desired digest; the real build can only be
// smaller because already-public objects are omitted.
func prepareMutationBuildPreflight(ctx context.Context, root, repoName string, cfg config.Config, distNames []string, manifest mutationManifest, store *state.Store, preparedRPMPolicy *rpmSigningPolicy) (*mutationBuildPreflight, error) {
	if len(distNames) == 0 {
		return nil, nil
	}
	summary, err := store.Summary(ctx)
	if err != nil {
		return nil, err
	}
	generation := summary.BuiltGeneration + 1
	baseManifest, err := scanPublicManifest(ctx, filepath.Join(root, repoName))
	if err != nil {
		return nil, err
	}
	baseData, err := marshalMutationBaseManifest(baseManifest)
	if err != nil {
		return nil, err
	}
	formats := configuredSigningFormats(cfg, repoName, distNames)
	publicationTime, err := nextMutationPublicationTime(ctx, root, cfg.Repositories[repoName], store, summary.BuiltGeneration, formats.rpm, formats.deb)
	if err != nil {
		return nil, err
	}
	metadataSnapshot, err := loadMetadataSignerSnapshotForFormats(ctx, root, cfg.Repositories[repoName], publicationTime, formats.rpm, formats.deb)
	if err != nil {
		return nil, err
	}
	rpmPolicy := rpmSigningPolicy{mode: "never"}
	if formats.rpm {
		if preparedRPMPolicy != nil {
			rpmPolicy = *preparedRPMPolicy
		} else {
			rpmPolicy, err = loadRPMSigningPolicy(ctx, root, cfg.Repositories[repoName].Signing.RPM.Packages)
			if err != nil {
				return nil, err
			}
		}
	}
	if len(manifest.RPMSigningKeys) != 0 && !sameRetainedRPMSigningKeys(manifest.RPMSigningKeys, rpmPolicy.retainedKeys) {
		return nil, fmt.Errorf("%w: RPM package signing certificates changed after package preparation", ErrIntegrity)
	}
	projectedDists := make([]mutationBuildDist, 0, len(distNames))
	for _, distName := range distNames {
		distConfig := cfg.Repositories[repoName].Dists[distName]
		architectures, err := configuredArchitectureState(cfg, repoName, distName, distConfig.Format)
		if err != nil {
			return nil, err
		}
		frozenSigning, err := frozenEffectiveSigningForFormats(cfg.Repositories[repoName].Signing, rpmPolicy, metadataSnapshot, distConfig.Format == "rpm", distConfig.Format == "deb")
		if err != nil {
			return nil, err
		}
		effectiveSHA, _, err := effectiveDistConfigFrozen(cfg, repoName, distName, frozenSigning)
		if err != nil {
			return nil, err
		}
		identity := metadataSnapshot.RPM
		if distConfig.Format == "deb" {
			identity = metadataSnapshot.DEB
		}
		projectedDists = append(projectedDists, mutationBuildDist{
			Name: distName, TreeSHA256: strings.Repeat("0", 64), EffectiveConfigSHA256: effectiveSHA, Architectures: architectures,
			MetadataSignerFingerprint: identity.Fingerprint, MetadataSignerPublicKey: identity.PublicKey,
			EffectiveSigning: frozenSigning,
		})
	}
	sort.Slice(projectedDists, func(i, j int) bool { return projectedDists[i].Name < projectedDists[j].Name })
	pooledSet := map[string]struct{}{}
	for _, digests := range manifest.Desired {
		for _, digest := range digests {
			pooledSet[digest] = struct{}{}
		}
	}
	pooled := make([]string, 0, len(pooledSet))
	for digest := range pooledSet {
		pooled = append(pooled, digest)
	}
	sort.Strings(pooled)
	projected := manifest
	projected.RPMSigningKeys = append([]state.RPMSigningKey(nil), rpmPolicy.retainedKeys...)
	projected.Build = &mutationBuildManifest{
		Generation: generation, BaseManifestSHA256: bytesSHA(baseData),
		Dists: projectedDists, Pooled: pooled,
	}
	if _, err := marshalMutationManifest(projected); err != nil {
		return nil, err
	}
	return &mutationBuildPreflight{
		distNames: append([]string(nil), distNames...), generation: generation, publicationTime: publicationTime,
		baseManifest: append([]state.GenerationFile(nil), baseManifest...), metadataSnapshot: metadataSnapshot,
		rpmPolicy: rpmPolicy, projectedDists: projectedDists,
	}, nil
}

func sameRetainedRPMSigningKeys(left, right []state.RPMSigningKey) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Fingerprint != right[index].Fingerprint || left[index].SnapshotSHA256 != right[index].SnapshotSHA256 || !bytes.Equal(left[index].PublicKey, right[index].PublicKey) {
			return false
		}
	}
	return true
}

func samePreparedBuildDists(actual, expected []mutationBuildDist) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		left, right := actual[index], expected[index]
		left.TreeSHA256, right.TreeSHA256 = "", ""
		leftData, leftErr := json.Marshal(left)
		rightData, rightErr := json.Marshal(right)
		if leftErr != nil || rightErr != nil || !bytes.Equal(leftData, rightData) {
			return false
		}
	}
	return true
}

func buildAppliedMutation(ctx context.Context, root, repoName string, cfg config.Config, distNames []string, operationID string, store *state.Store, jobs int, fault func(string) error, preflight *mutationBuildPreflight) (int64, error) {
	summary, err := store.Summary(ctx)
	if err != nil {
		return 0, err
	}
	operation, _, manifest, err := loadMutationOperation(ctx, store, root, repoName, operationID)
	if err != nil {
		return 0, err
	}
	if operation.State != state.OperationApplied && operation.State != state.OperationBuilt && operation.State != state.OperationRecovering {
		return 0, fmt.Errorf("%w: build mutation from %s", ErrIntegrity, operation.State)
	}
	buildRoot := filepath.Join(mutationStageRoot(root, repoName, operationID), "build")
	if err := (yumrepo.NativeDirectoryExchanger{}).Probe(filepath.Join(root, repoName, "dists")); err != nil {
		return 0, fmt.Errorf("%w: atomic Dist exchange is unavailable: %v", ErrRejected, err)
	}
	var generation int64
	var baseManifest []state.GenerationFile
	var buildDists []mutationBuildDist
	var pooled []string
	var retainedRPMKeys []state.RPMSigningKey
	if manifest.Build == nil {
		var publicationTime time.Time
		if preflight != nil {
			if preflight.generation != summary.BuiltGeneration+1 || !sameStringSet(preflight.distNames, distNames) {
				return 0, fmt.Errorf("%w: mutation build preflight no longer matches repository state", ErrIntegrity)
			}
			generation = preflight.generation
			publicationTime = preflight.publicationTime
			baseManifest = append([]state.GenerationFile(nil), preflight.baseManifest...)
		} else {
			generation = summary.BuiltGeneration + 1
			baseManifest, err = scanPublicManifest(ctx, filepath.Join(root, repoName))
			if err != nil {
				return 0, err
			}
			formats := configuredSigningFormats(cfg, repoName, distNames)
			publicationTime, err = nextMutationPublicationTime(ctx, root, cfg.Repositories[repoName], store, summary.BuiltGeneration, formats.rpm, formats.deb)
			if err != nil {
				return 0, err
			}
		}
		buildDists, pooled, retainedRPMKeys, err = stageMutationBuild(ctx, root, repoName, cfg, distNames, generation, publicationTime, buildRoot, store, jobs, fault, preflight)
		if err != nil {
			return 0, err
		}
		if err := persistMutationBuildPlan(ctx, store, root, repoName, operationID, generation, buildDists, pooled, retainedRPMKeys, baseManifest); err != nil {
			if errors.Is(err, errMutationRecoveryArtifactTooLarge) {
				terminalErr := store.SetOperationState(context.WithoutCancel(ctx), operationID, state.OperationDoneDirty, "")
				if terminalErr == nil {
					terminalErr = cleanupMutationStage(root, repoName, operationID)
				}
				return 0, errors.Join(err, terminalErr)
			}
			return 0, err
		}
		if err := callFault(fault, "build.staged"); err != nil {
			return 0, err
		}
		_, _, manifest, err = loadMutationOperation(ctx, store, root, repoName, operationID)
		if err != nil {
			return 0, err
		}
	} else {
		generation = manifest.Build.Generation
		buildDists = append([]mutationBuildDist(nil), manifest.Build.Dists...)
		pooled = append([]string(nil), manifest.Build.Pooled...)
		retainedRPMKeys = append([]state.RPMSigningKey(nil), manifest.RPMSigningKeys...)
		baseManifest, err = readMutationBaseManifest(root, repoName, operationID, manifest.Build.BaseManifestSHA256)
		if err != nil {
			return 0, err
		}
	}
	if generation != summary.BuiltGeneration+1 || generation < 1 || len(buildDists) == 0 {
		return 0, fmt.Errorf("%w: mutation build generation is inconsistent", ErrIntegrity)
	}
	stateBuilds := make([]state.DistBuild, 0, len(buildDists))
	for _, dist := range buildDists {
		effectiveSigningJSON, err := json.Marshal(dist.EffectiveSigning)
		if err != nil {
			return 0, err
		}
		stateBuilds = append(stateBuilds, state.DistBuild{
			Name: dist.Name, EffectiveConfigSHA256: dist.EffectiveConfigSHA256, Architectures: dist.Architectures,
			MetadataSignerFingerprint: dist.MetadataSignerFingerprint, MetadataSignerPublicKey: dist.MetadataSignerPublicKey,
			EffectiveSigningJSON: string(effectiveSigningJSON),
		})
	}
	for _, digest := range pooled {
		object, err := store.GetPackageObject(ctx, digest)
		if err != nil {
			return 0, err
		}
		if err := promotePendingObject(ctx, root, repoName, object); err != nil {
			return 0, err
		}
		if err := callFault(fault, "build.payload."+digest); err != nil {
			return 0, err
		}
	}
	exchanger := yumrepo.NativeDirectoryExchanger{}
	for _, dist := range buildDists {
		live := filepath.Join(root, repoName, "dists", dist.Name)
		staged := filepath.Join(buildRoot, "dists", dist.Name)
		liveDigest, _, liveErr := digestTree(ctx, live)
		if liveErr == nil && liveDigest == dist.TreeSHA256 {
			continue
		}
		stagedDigest, _, stagedErr := digestTree(ctx, staged)
		if stagedErr != nil || stagedDigest != dist.TreeSHA256 {
			return 0, fmt.Errorf("%w: neither live nor staged Dist %q matches the journal build", ErrIntegrity, dist.Name)
		}
		if err := requireSameDevice(live, staged); err != nil {
			return 0, err
		}
		if err := exchanger.Exchange(live, staged); err != nil {
			return 0, fmt.Errorf("managed: atomically publish Dist %q: %w", dist.Name, err)
		}
		if err := syncDir(filepath.Dir(live)); err != nil {
			return 0, err
		}
		if err := syncDir(filepath.Dir(staged)); err != nil {
			return 0, err
		}
		if err := callFault(fault, "build.pointer."+dist.Name); err != nil {
			return 0, err
		}
	}
	targetManifest, normalizedModes, err := normalizeManagedPublicTree(ctx, filepath.Join(root, repoName), fault, "build.mode")
	if err != nil {
		return 0, err
	}
	if err := recordNormalizedPublicModes(ctx, store, operationID, normalizedModes); err != nil {
		return 0, err
	}
	if err := callFault(fault, "build.modes"); err != nil {
		return 0, err
	}
	if operation.State != state.OperationBuilt {
		if err := store.SetOperationState(ctx, operationID, state.OperationBuilt, ""); err != nil {
			return 0, err
		}
	}
	if err := callFault(fault, "build.built"); err != nil {
		return 0, err
	}
	changes := state.DiffManifests(baseManifest, targetManifest)
	if len(changes) == 0 {
		return 0, fmt.Errorf("%w: changed Desired State produced no physical Generation change", ErrIntegrity)
	}
	if err := store.FinalizeBuild(ctx, state.FinalizeBuildInput{OperationID: operationID, Generation: generation, Dists: stateBuilds, Pooled: pooled, RPMSigningKeys: retainedRPMKeys, Manifest: targetManifest, Changes: changes}); err != nil {
		// FinalizeBuild commits SQLite before its WAL checkpoint. If that
		// durability-maintenance step alone fails, report both the committed
		// Generation identity and the error instead of falsely returning 0.
		if after, summaryErr := store.Summary(ctx); summaryErr == nil && after.BuiltGeneration == generation {
			return generation, err
		}
		return 0, err
	}
	if err := callFault(fault, "build.finalized"); err != nil {
		return generation, err
	}
	if err := cleanupMutationStage(root, repoName, operationID); err != nil {
		return generation, err
	}
	return generation, nil
}

func stageMutationBuild(ctx context.Context, root, repoName string, cfg config.Config, distNames []string, generation int64, publicationTime time.Time, buildRoot string, store *state.Store, jobs int, fault func(string) error, preflight *mutationBuildPreflight) (buildDists []mutationBuildDist, pooled []string, retainedRPMKeys []state.RPMSigningKey, resultErr error) {
	// A build plan is journaled only after every Dist has rendered and synced.
	// Therefore an existing build root while manifest.Build is still nil is
	// necessarily an incomplete prior attempt (ordinary error or process
	// crash). Discard only that owned derived subtree and render it afresh.
	// Once the build plan exists this function is not called: recovery instead
	// verifies and publishes the exact digest-bound staged trees.
	if _, err := os.Lstat(buildRoot); err == nil {
		if err := removeOwnedDirectory(buildRoot, filepath.Dir(buildRoot)); err != nil {
			return nil, nil, nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil, err
	}
	if err := durableMkdir(buildRoot, 0o700); err != nil {
		return nil, nil, nil, err
	}
	distStates := make(map[string]state.Dist, len(distNames))
	distObjects := make(map[string][]state.PackageObject, len(distNames))
	allSourcesBySHA := map[string]ManagedPackageSource{}
	rpmObjectsBySHA := map[string]state.PackageObject{}
	wantRPM, wantDEB := false, false
	for _, distName := range distNames {
		distState, err := store.GetDist(ctx, distName)
		if err != nil {
			return nil, nil, nil, err
		}
		objects, err := store.ListPackageObjects(ctx, []string{distName}, false)
		if err != nil {
			return nil, nil, nil, err
		}
		distStates[distName], distObjects[distName] = distState, objects
		for _, object := range objects {
			if _, exists := allSourcesBySHA[object.SHA256]; exists {
				continue
			}
			source, err := availableManagedPackageSource(root, repoName, object)
			if err != nil {
				return nil, nil, nil, err
			}
			allSourcesBySHA[object.SHA256] = source
		}
		if distState.Format == "rpm" {
			wantRPM = true
			for _, object := range objects {
				rpmObjectsBySHA[object.SHA256] = object
			}
		} else {
			wantDEB = true
		}
	}
	var (
		metadataSnapshot metadataSignerSnapshot
		err              error
	)
	rpmPolicy := rpmSigningPolicy{mode: "never"}
	if preflight != nil {
		if preflight.generation != generation || !preflight.publicationTime.Equal(publicationTime) || !sameStringSet(preflight.distNames, distNames) {
			return nil, nil, nil, fmt.Errorf("%w: mutation signing preflight does not match the staged build", ErrIntegrity)
		}
		metadataSnapshot = preflight.metadataSnapshot
		rpmPolicy = preflight.rpmPolicy
	} else {
		metadataSnapshot, err = loadMetadataSignerSnapshotForFormats(ctx, root, cfg.Repositories[repoName], publicationTime, wantRPM, wantDEB)
		if err != nil {
			return nil, nil, nil, err
		}
		if wantRPM {
			rpmPolicy, err = loadRPMSigningPolicy(ctx, root, cfg.Repositories[repoName].Signing.RPM.Packages)
			if err != nil {
				return nil, nil, nil, err
			}
		}
	}
	rpmObjects := make([]state.PackageObject, 0, len(rpmObjectsBySHA))
	for _, object := range rpmObjectsBySHA {
		rpmObjects = append(rpmObjects, object)
	}
	sort.Slice(rpmObjects, func(i, j int) bool { return rpmObjects[i].SHA256 < rpmObjects[j].SHA256 })
	if err := validateBuildRPMSigning(ctx, root, repoName, rpmObjects, rpmPolicy, jobs); err != nil {
		return nil, nil, nil, err
	}
	retainedRPMKeys = append(retainedRPMKeys, rpmPolicy.retainedKeys...)
	allSources := make([]ManagedPackageSource, 0, len(allSourcesBySHA))
	for _, source := range allSourcesBySHA {
		allSources = append(allSources, source)
	}
	sort.Slice(allSources, func(i, j int) bool { return allSources[i].Object.SHA256 < allSources[j].Object.SHA256 })
	pendingLinks, err := newPendingLinkTracker(allSources)
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, pendingLinks.Close()) }()
	buildDists = make([]mutationBuildDist, 0, len(distNames))
	pooledSet := map[string]struct{}{}
	for _, distName := range distNames {
		distState, objects := distStates[distName], distObjects[distName]
		frozenSigning, err := frozenEffectiveSigningForFormats(cfg.Repositories[repoName].Signing, rpmPolicy, metadataSnapshot, distState.Format == "rpm", distState.Format == "deb")
		if err != nil {
			return nil, nil, nil, err
		}
		sources := make([]ManagedPackageSource, 0, len(objects))
		for _, object := range objects {
			source, err := availableManagedPackageSource(root, repoName, object)
			if err != nil {
				return nil, nil, nil, err
			}
			sources = append(sources, source)
			if object.Storage == "pending" {
				pooledSet[object.SHA256] = struct{}{}
			}
		}
		architectures, err := configuredArchitectureState(cfg, repoName, distName, distState.Format)
		if err != nil {
			return nil, nil, nil, err
		}
		effectiveSHA, _, err := effectiveDistConfigFrozen(cfg, repoName, distName, frozenSigning)
		if err != nil {
			return nil, nil, nil, err
		}
		aliases := []ManagedPackageSource{}
		if distState.Format == "rpm" {
			priorBuilt, err := store.ListPackageObjects(ctx, []string{distName}, true)
			if err != nil {
				return nil, nil, nil, err
			}
			for _, object := range priorBuilt {
				source, err := availableManagedPackageSource(root, repoName, object)
				if err != nil {
					return nil, nil, nil, err
				}
				aliases = append(aliases, source)
			}
		}
		spec := ManagedDistSpec{Name: distName, Format: distState.Format, Architectures: architectures, Generation: generation, Jobs: jobs, PublishedAt: publicationTime, Packages: sources, Aliases: aliases, pendingLinks: pendingLinks}
		if distState.Format == "rpm" {
			spec.RPMSigner = metadataSnapshot.RPMSigner
		} else {
			spec.APTSigner = metadataSnapshot.APTSigner
		}
		rendered, err := RenderManagedDist(ctx, buildRoot, spec)
		if err != nil {
			return nil, nil, nil, err
		}
		if distState.Format == "rpm" {
			if err := retainPriorRPMMetadata(ctx, filepath.Join(root, repoName, "dists", distName), rendered.Path, distState.Architectures); err != nil {
				return nil, nil, nil, err
			}
		} else if err := retainPriorAPTByHash(ctx, filepath.Join(root, repoName, "dists", distName), rendered.Path, distState.Architectures); err != nil {
			return nil, nil, nil, err
		}
		// Retained protocol objects are part of the staged Dist identity and
		// therefore must be bound into the crash-recovery journal digest.
		rendered.TreeSHA256, _, err = digestTree(ctx, rendered.Path)
		if err != nil {
			return nil, nil, nil, err
		}
		identity := metadataSnapshot.RPM
		if distState.Format == "deb" {
			identity = metadataSnapshot.DEB
		}
		buildDists = append(buildDists, mutationBuildDist{
			Name: distName, TreeSHA256: rendered.TreeSHA256, EffectiveConfigSHA256: effectiveSHA, Architectures: architectures,
			MetadataSignerFingerprint: identity.Fingerprint, MetadataSignerPublicKey: identity.PublicKey,
			EffectiveSigning: frozenSigning,
		})
		if err := callFault(fault, "build.rendered."+distName); err != nil {
			return nil, nil, nil, err
		}
	}
	pooled = make([]string, 0, len(pooledSet))
	for digest := range pooledSet {
		pooled = append(pooled, digest)
	}
	sort.Strings(pooled)
	sort.Slice(buildDists, func(i, j int) bool { return buildDists[i].Name < buildDists[j].Name })
	if preflight != nil && (!samePreparedBuildDists(buildDists, preflight.projectedDists) || !sameRetainedRPMSigningKeys(retainedRPMKeys, preflight.rpmPolicy.retainedKeys)) {
		return nil, nil, nil, fmt.Errorf("%w: staged build differs from its signer-frozen preflight", ErrIntegrity)
	}
	return buildDists, pooled, retainedRPMKeys, nil
}

// validateBuildRPMSigning enforces the active package-signing policy only for
// RPM objects reachable from the selected target Dists. RenderManagedDist
// independently authenticates every source digest against immutable state;
// DEB rendering also compares package facts. Keeping this pass signing-only
// avoids two redundant full-repository parses before every selective build.
func validateBuildRPMSigning(ctx context.Context, root, repoName string, objects []state.PackageObject, rpmPolicy rpmSigningPolicy, jobs int) error {
	if jobs < 1 {
		jobs = 1
	}
	if jobs > len(objects) {
		jobs = len(objects)
	}
	issues := make([]error, len(objects))
	if jobs > 0 {
		indices := make(chan int)
		var group sync.WaitGroup
		group.Add(jobs)
		for range jobs {
			go func() {
				defer group.Done()
				for index := range indices {
					object := objects[index]
					source, err := availableManagedPackageSource(root, repoName, object)
					if err != nil {
						issues[index] = err
						continue
					}
					opened, err := source.open()
					if err != nil {
						issues[index] = err
						continue
					}
					if object.Format != "rpm" {
						issues[index] = errors.Join(fmt.Errorf("%w: non-RPM object reached RPM signing validation", ErrIntegrity), opened.CloseVerified())
						continue
					}
					if err := rpmPolicy.authorizeDesiredReader(ctx, opened.file); err != nil {
						issues[index] = errors.Join(fmt.Errorf("%w: immutable RPM %s does not satisfy package signing mode %s: %v", ErrRejected, object.SHA256, rpmPolicy.mode, err), opened.CloseVerified())
						continue
					}
					issues[index] = opened.CloseVerified()
				}
			}()
		}
		for index := range objects {
			indices <- index
		}
		close(indices)
		group.Wait()
	}
	for _, issue := range issues {
		if issue != nil {
			return issue
		}
	}
	return ctx.Err()
}

// retainPriorRPMMetadata keeps checksum-named metadata artifacts from the
// previous view reachable after the pointer exchange. A client that fetched
// the old repomd.xml immediately before publication can therefore still fetch
// every artifact named by it from the new directory. Protocol pointers remain
// exclusively those generated for the new view.
func retainPriorRPMMetadata(ctx context.Context, liveDist, stagedDist string, architectures []state.Architecture) error {
	for _, architecture := range architectures {
		sourceRoot := filepath.Join(liveDist, architecture.Family, "repodata")
		info, err := os.Lstat(sourceRoot)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: prior RPM metadata root is unsafe", ErrIntegrity)
		}
		targetRoot := filepath.Join(stagedDist, architecture.Family, "repodata")
		var previous *yumrepo.Generation
		_, ascErr := os.Lstat(filepath.Join(sourceRoot, "repomd.xml.asc"))
		if ascErr == nil {
			previous, err = yumrepo.ValidateManagedDirectory(ctx, sourceRoot, yumrepo.CompressionGzip, structuralDetachedVerifier{})
		} else if errors.Is(ascErr, os.ErrNotExist) {
			previous, err = yumrepo.ValidateManagedUnsignedDirectory(ctx, sourceRoot, yumrepo.CompressionGzip)
		} else {
			err = ascErr
		}
		if err != nil || previous == nil {
			return fmt.Errorf("%w: prior RPM metadata pointer is invalid: %v", ErrIntegrity, err)
		}
		for _, artifact := range previous.Artifacts {
			name := strings.TrimPrefix(artifact.Path, "repodata/")
			if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, "/\\\x00\r\n\t") {
				return fmt.Errorf("%w: unsafe prior RPM metadata reference", ErrIntegrity)
			}
			if targetInfo, err := openRootedRegular(targetRoot, name); err == nil {
				if targetInfo.before.Size() != artifact.Size {
					_ = targetInfo.CloseVerified()
					return fmt.Errorf("%w: RPM metadata artifact collision", ErrIntegrity)
				}
				targetDigest, hashErr := hashRegularDescriptor(ctx, targetInfo.file)
				verifyErr := targetInfo.CloseVerified()
				if hashErr != nil || verifyErr != nil || targetDigest != artifact.SHA256 {
					return fmt.Errorf("%w: RPM metadata artifact collision differs by content", ErrIntegrity)
				}
				continue
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if err := linkRootedRegular(ctx, sourceRoot, name, targetRoot, name, artifact.Size, artifact.SHA256, 0o755); err != nil {
				return fmt.Errorf("managed: retain prior RPM metadata artifact: %w", err)
			}
		}
		if err := syncDir(targetRoot); err != nil {
			return err
		}
	}
	return nil
}

// retainPriorAPTByHash carries forward exactly the immutable index objects
// named by the immediately preceding Release. A client that fetched that old
// pointer just before the atomic Dist exchange can finish its by-hash reads,
// while the next build naturally drops anything older than one generation.
// This gives a bounded two-generation window instead of accumulating every
// historical index object.
func retainPriorAPTByHash(ctx context.Context, liveDist, stagedDist string, architectures []state.Architecture) error {
	release, err := readRootedRegular(liveDist, "Release", 16<<20, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: prior APT Release is missing, unsafe, or unbounded", ErrIntegrity)
	}
	checksums, err := parseReleaseSHA256(release)
	if err != nil {
		return fmt.Errorf("%w: prior APT Release is invalid: %v", ErrIntegrity, err)
	}
	byHashEnabled := bytes.Contains(release, []byte("\nAcquire-By-Hash: yes\n")) || bytes.HasPrefix(release, []byte("Acquire-By-Hash: yes\n"))
	for _, architecture := range architectures {
		binaryRelative := filepath.ToSlash(filepath.Join("main", "binary-"+architecture.EcosystemArch))
		for _, base := range []string{"Packages", "Packages.gz"} {
			relative := binaryRelative + "/" + base
			want, exists := checksums[relative]
			if !exists {
				return fmt.Errorf("%w: prior APT Release lacks %s", ErrIntegrity, relative)
			}
			indexedInfo, indexedErr := openRootedRegular(liveDist, relative)
			if indexedErr != nil || indexedInfo.before.Size() != want.size {
				if indexedInfo != nil {
					_ = indexedInfo.CloseVerified()
				}
				return fmt.Errorf("%w: prior APT index %s is unsafe or differs in size", ErrIntegrity, relative)
			}
			sourceRelative := filepath.ToSlash(filepath.Join(filepath.Dir(relative), "by-hash", "SHA256", want.digest))
			sourceInfo, sourceErr := openRootedRegular(liveDist, sourceRelative)
			if errors.Is(sourceErr, os.ErrNotExist) && !byHashEnabled {
				_ = indexedInfo.CloseVerified()
				// Empty P1 Dists predate Acquire-By-Hash and have no immutable
				// object to retain. Their direct index remains an old-protocol
				// pointer and is superseded by the first managed build.
				continue
			}
			if sourceErr != nil || sourceInfo.before.Size() != want.size || !os.SameFile(indexedInfo.before, sourceInfo.before) {
				_ = indexedInfo.CloseVerified()
				if sourceInfo != nil {
					_ = sourceInfo.CloseVerified()
				}
				return fmt.Errorf("%w: prior APT by-hash object for %s is absent or not its index hardlink", ErrIntegrity, relative)
			}
			hash := sha256.New()
			_, hashErr := io.Copy(hash, &managedContextReader{ctx: ctx, reader: sourceInfo.file})
			verifyErr := errors.Join(indexedInfo.CloseVerified(), sourceInfo.CloseVerified())
			if hashErr != nil || verifyErr != nil || hex.EncodeToString(hash.Sum(nil)) != want.digest {
				return fmt.Errorf("%w: prior APT by-hash object for %s differs from Release", ErrIntegrity, relative)
			}
			targetRelative := filepath.ToSlash(filepath.Join(binaryRelative, "by-hash", "SHA256", want.digest))
			if targetInfo, targetErr := openRootedRegular(stagedDist, targetRelative); targetErr == nil {
				if targetInfo.before.Size() != want.size {
					_ = targetInfo.CloseVerified()
					return fmt.Errorf("%w: APT by-hash retention collision for %s", ErrIntegrity, relative)
				}
				targetHash := sha256.New()
				_, digestErr := io.Copy(targetHash, &managedContextReader{ctx: ctx, reader: targetInfo.file})
				verifyErr := targetInfo.CloseVerified()
				if digestErr != nil || verifyErr != nil || hex.EncodeToString(targetHash.Sum(nil)) != want.digest {
					return fmt.Errorf("%w: APT by-hash retention collision for %s", ErrIntegrity, relative)
				}
				continue
			} else if !errors.Is(targetErr, os.ErrNotExist) {
				return targetErr
			}
			if err := linkRootedRegular(ctx, liveDist, sourceRelative, stagedDist, targetRelative, want.size, want.digest, 0o755); err != nil {
				return fmt.Errorf("managed: retain prior APT by-hash object: %w", err)
			}
		}
		targetRoot := filepath.Join(stagedDist, "main", "binary-"+architecture.EcosystemArch, "by-hash", "SHA256")
		if err := syncDir(targetRoot); err != nil {
			return err
		}
	}
	return nil
}

func persistMutationBuildPlan(ctx context.Context, store *state.Store, root, repoName, operationID string, generation int64, dists []mutationBuildDist, pooled []string, retainedRPMKeys []state.RPMSigningKey, base []state.GenerationFile) error {
	operation, err := store.LastOperation(ctx)
	if err != nil || operation == nil || operation.ID != operationID {
		return fmt.Errorf("%w: active mutation operation is not the latest journal entry", ErrIntegrity)
	}
	var payload mutationOperationPayload
	if err := jsonUnmarshalStrict(operation.PayloadJSON, &payload); err != nil {
		return err
	}
	manifest, err := readMutationManifest(root, repoName, operationID, payload.ManifestSHA256)
	if err != nil {
		return err
	}
	baseData, err := marshalMutationBaseManifest(base)
	if err != nil {
		return err
	}
	manifest.RPMSigningKeys = retainedRPMKeys
	manifest.Build = &mutationBuildManifest{Generation: generation, BaseManifestSHA256: bytesSHA(baseData), Dists: dists, Pooled: pooled}
	data, err := marshalMutationManifest(manifest)
	if err != nil {
		return err
	}
	if err := writeAtomic(mutationBaseManifestPath(root, repoName, operationID), baseData, 0o600); err != nil {
		return err
	}
	newManifestSHA := bytesSHA(data)
	if err := writeAtomic(mutationManifestPath(root, repoName, operationID, newManifestSHA), data, 0o600); err != nil {
		return err
	}
	payload.ManifestSHA256 = newManifestSHA
	payloadData, err := jsonMarshal(payload)
	if err != nil {
		return err
	}
	return store.UpdateOperationPayload(ctx, operationID, string(payloadData))
}

func mutationBaseManifestPath(root, repoName, id string) string {
	return filepath.Join(mutationStageRoot(root, repoName, id), "base-manifest.json")
}

func readMutationBaseManifest(root, repoName, id, expectedSHA string) ([]state.GenerationFile, error) {
	if !lowercaseSHA256.MatchString(expectedSHA) {
		return nil, fmt.Errorf("%w: invalid mutation base manifest digest", ErrIntegrity)
	}
	stageOwner := filepath.Join(root, ".sow", repoName, "stage")
	data, err := readRootedPrivateRegular(stageOwner, filepath.Join(id, "base-manifest.json"), maxMutationBaseManifestBytes, false)
	if err != nil || bytesSHA(data) != expectedSHA {
		return nil, fmt.Errorf("%w: mutation base manifest is missing or differs from journal", ErrIntegrity)
	}
	var manifest []state.GenerationFile
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("%w: decode mutation base manifest", ErrIntegrity)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("%w: mutation base manifest has trailing content", ErrIntegrity)
	}
	return manifest, nil
}

func loadMutationOperation(ctx context.Context, store *state.Store, root, repoName, operationID string) (state.Operation, mutationOperationPayload, mutationManifest, error) {
	operation, err := store.LastOperation(ctx)
	if err != nil || operation == nil || operation.ID != operationID {
		return state.Operation{}, mutationOperationPayload{}, mutationManifest{}, fmt.Errorf("%w: active mutation operation is not the latest journal entry", ErrIntegrity)
	}
	var payload mutationOperationPayload
	if err := jsonUnmarshalStrict(operation.PayloadJSON, &payload); err != nil {
		return state.Operation{}, mutationOperationPayload{}, mutationManifest{}, err
	}
	if payload.Version != mutationOperationVersion || payload.Repository != repoName || payload.Kind != operation.Kind || !lowercaseSHA256.MatchString(payload.ConfigSHA256) || payload.ManifestSHA256 == "" || len(payload.Dists) == 0 {
		return state.Operation{}, mutationOperationPayload{}, mutationManifest{}, fmt.Errorf("%w: invalid mutation operation binding", ErrIntegrity)
	}
	if err := validateMutationBuildDists(payload); err != nil {
		return state.Operation{}, mutationOperationPayload{}, mutationManifest{}, err
	}
	configSHA, err := config.FileSHA(filepath.Join(root, config.ConfigFilename))
	if err != nil || configSHA != payload.ConfigSHA256 {
		return state.Operation{}, mutationOperationPayload{}, mutationManifest{}, fmt.Errorf("%w: current config differs from active mutation", ErrIntegrity)
	}
	manifest, err := readMutationManifest(root, repoName, operationID, payload.ManifestSHA256)
	if err != nil {
		return state.Operation{}, mutationOperationPayload{}, mutationManifest{}, err
	}
	return *operation, payload, manifest, nil
}

func availableManagedPackageSource(root, repoName string, object state.PackageObject) (ManagedPackageSource, error) {
	publicOwner := filepath.Join(root, repoName)
	publicRelative := filepath.FromSlash(object.PoolPath)
	candidates := []ManagedPackageSource{}
	if object.Storage == "pending" {
		owner := filepath.Join(root, ".sow", repoName, "pending")
		candidates = append(candidates, ManagedPackageSource{Object: object, Owner: owner, Relative: object.SHA256, Path: filepath.Join(owner, object.SHA256)})
	}
	candidates = append(candidates, ManagedPackageSource{Object: object, Owner: publicOwner, Relative: publicRelative, Path: filepath.Join(publicOwner, publicRelative)})
	for _, candidate := range candidates {
		opened, err := candidate.open()
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return ManagedPackageSource{}, fmt.Errorf("%w: package object %s is unsafe: %v", ErrIntegrity, object.SHA256, err)
		}
		if err := opened.CloseVerified(); err != nil {
			return ManagedPackageSource{}, fmt.Errorf("%w: package object %s is unsafe: %v", ErrIntegrity, object.SHA256, err)
		}
		return candidate, nil
	}
	return ManagedPackageSource{}, fmt.Errorf("%w: package object %s is missing", ErrIntegrity, object.SHA256)
}

func promotePendingObject(ctx context.Context, root, repoName string, object state.PackageObject) error {
	sourceRelative := filepath.Join(".sow", repoName, "pending", object.SHA256)
	targetRelative := filepath.Join(repoName, filepath.FromSlash(object.PoolPath))
	targetSource := ManagedPackageSource{Object: object, Owner: root, Relative: targetRelative, Path: filepath.Join(root, targetRelative)}
	if opened, err := targetSource.open(); err == nil {
		digest, hashErr := hashOpenedFileContext(ctx, opened.file)
		modeErr := errors.Join(opened.file.Chmod(0o644), opened.file.Sync())
		verifyErr := opened.CloseVerified()
		if hashErr != nil || modeErr != nil || verifyErr != nil || digest != object.SHA256 {
			return fmt.Errorf("%w: public Pool object checksum mismatch", ErrIntegrity)
		}
		return removeRootedRegular(root, sourceRelative, object.Size)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: public Pool path conflicts for %s: %v", ErrIntegrity, object.SHA256, err)
	}
	source := ManagedPackageSource{Object: object, Owner: root, Relative: sourceRelative, Path: filepath.Join(root, sourceRelative)}
	opened, err := source.open()
	if err != nil {
		return err
	}
	digest, hashErr := hashOpenedFileContext(ctx, opened.file)
	verifyErr := opened.CloseVerified()
	if hashErr != nil || verifyErr != nil || digest != object.SHA256 {
		return fmt.Errorf("%w: pending object %s checksum mismatch", ErrIntegrity, object.SHA256)
	}
	return renameRootedRegular(ctx, root, sourceRelative, targetRelative, object.Size, object.SHA256, 0o644, 0o755)
}

// normalizeManagedPublicTree authenticates the complete public byte tree while
// converging its delivery modes.  Mode changes are not Generation changes, so
// this step is journal-replayed before an operation can be finalized.  Every
// entry is descriptor-bound and every file is hashed before its mode is
// changed; a fault after any individual repair leaves an idempotently
// recoverable operation.
func normalizeManagedPublicTree(ctx context.Context, repositoryRoot string, fault func(string) error, modeFaultPoint string) ([]state.GenerationFile, int, error) {
	files := []state.GenerationFile{}
	normalized := 0
	err := walkRootedTree(ctx, repositoryRoot, func(relative string, file *os.File, info os.FileInfo) error {
		if !strings.HasPrefix(relative, "pool/") && !strings.HasPrefix(relative, "dists/") {
			return fmt.Errorf("%w: public Repository contains an unmanaged root entry", ErrIntegrity)
		}
		hash := sha256.New()
		if _, err := io.Copy(hash, &managedContextReader{ctx: ctx, reader: file}); err != nil {
			return err
		}
		files = append(files, state.GenerationFile{Path: relative, Phase: publicFilePhase(relative), Size: info.Size(), SHA256: hex.EncodeToString(hash.Sum(nil))})
		if info.Mode().Perm() == 0o644 {
			return nil
		}
		if err := errors.Join(file.Chmod(0o644), file.Sync()); err != nil {
			return err
		}
		normalized++
		return callFault(fault, modeFaultPoint)
	}, func(relative string, directory *os.File, info os.FileInfo) error {
		if relative != "" && !strings.HasPrefix(filepath.ToSlash(relative)+"/", "pool/") && !strings.HasPrefix(filepath.ToSlash(relative)+"/", "dists/") {
			return fmt.Errorf("%w: public Repository contains an unmanaged root directory", ErrIntegrity)
		}
		if info.Mode().Perm() == 0o755 {
			return nil
		}
		if err := errors.Join(directory.Chmod(0o755), directory.Sync()); err != nil {
			return err
		}
		normalized++
		return callFault(fault, modeFaultPoint)
	})
	if err != nil {
		return nil, normalized, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, normalized, nil
}

func normalizeCurrentPublicTree(ctx context.Context, root, repoName, operationID string, store *state.Store, fault func(string) error) (int, error) {
	physical, normalized, err := normalizeManagedPublicTree(ctx, filepath.Join(root, repoName), fault, "build.mode")
	if err != nil {
		return normalized, err
	}
	summary, err := store.Summary(ctx)
	if err != nil {
		return normalized, err
	}
	retained := []state.GenerationFile{}
	if summary.BuiltGeneration > 0 {
		retained, err = store.GenerationManifest(ctx, summary.BuiltGeneration)
		if err != nil {
			return normalized, fmt.Errorf("%w: current Generation manifest is unavailable: %v", ErrIntegrity, err)
		}
	}
	if !sameGenerationManifest(retained, physical) {
		return normalized, fmt.Errorf("%w: public tree differs from current Generation while normalizing modes", ErrIntegrity)
	}
	if err := recordNormalizedPublicModes(ctx, store, operationID, normalized); err != nil {
		return normalized, err
	}
	if err := callFault(fault, "build.modes"); err != nil {
		return normalized, err
	}
	return normalized, nil
}

func recordNormalizedPublicModes(ctx context.Context, store *state.Store, operationID string, count int) error {
	if count == 0 {
		return nil
	}
	detail, err := store.GetOperation(ctx, operationID)
	if err != nil {
		return err
	}
	result := map[string]json.RawMessage{}
	if err := json.Unmarshal([]byte(detail.Operation.ResultJSON), &result); err != nil || result == nil {
		return fmt.Errorf("%w: operation result is invalid while recording public mode repair", ErrIntegrity)
	}
	prior := 0
	if raw, exists := result["normalized_public_modes"]; exists {
		if err := json.Unmarshal(raw, &prior); err != nil || prior < 0 {
			return fmt.Errorf("%w: operation public mode repair audit is invalid", ErrIntegrity)
		}
	}
	value, _ := json.Marshal(prior + count)
	result["normalized_public_modes"] = value
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return store.UpdateOperationResult(ctx, operationID, string(data))
}

func scanPublicManifest(ctx context.Context, repositoryRoot string) ([]state.GenerationFile, error) {
	files := []state.GenerationFile{}
	err := walkRootedTree(ctx, repositoryRoot, func(relative string, file *os.File, info os.FileInfo) error {
		if !strings.HasPrefix(relative, "pool/") && !strings.HasPrefix(relative, "dists/") {
			return fmt.Errorf("%w: public Repository contains an unmanaged root entry", ErrIntegrity)
		}
		hash := sha256.New()
		if _, err := io.Copy(hash, &managedContextReader{ctx: ctx, reader: file}); err != nil {
			return err
		}
		files = append(files, state.GenerationFile{Path: relative, Phase: publicFilePhase(relative), Size: info.Size(), SHA256: hex.EncodeToString(hash.Sum(nil))})
		return nil
	}, nil)
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func publicFilePhase(path string) string {
	if strings.HasPrefix(path, "pool/") || strings.Contains(path, "/pool/") {
		return "payload"
	}
	base := filepath.Base(path)
	if base == "repomd.xml" || base == "repomd.xml.asc" || base == "Release" || base == "InRelease" || base == "Release.gpg" {
		return "pointer"
	}
	return "metadata"
}

func hashOpenedFileContext(ctx context.Context, file *os.File) (string, error) {
	if file == nil {
		return "", errors.New("managed: nil hash target")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, &managedContextReader{ctx: ctx, reader: file}); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func jsonMarshal(value any) ([]byte, error) {
	return json.Marshal(value)
}

func jsonUnmarshalStrict(data string, value any) error {
	decoder := json.NewDecoder(strings.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("%w: invalid operation payload", ErrIntegrity)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("%w: operation payload has trailing content", ErrIntegrity)
	}
	return nil
}
