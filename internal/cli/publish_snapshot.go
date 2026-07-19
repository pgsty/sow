package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

func publishSnapshotSet(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, repos []config.Repo, snapshotIDs, targetNames []string, txDir string, values commonFlags, privateKey, passphrase []byte, repositoryKeySHA string, stdout io.Writer) (partialResult bool, resultErr error) {
	prepared, err := prepareSnapshotPublicationSet(ctx, cfg, canonical, pool, repos, snapshotIDs, txDir, values, privateKey, passphrase, repositoryKeySHA, stdout)
	if err != nil {
		return false, err
	}
	desiredCommit, err := canonical.HeadHash()
	if err != nil || desiredCommit.IsZero() {
		return false, withExitCode(ExitConflict, "publish requires an initialized canonical state: %v", err)
	}

	// A provider owns one ordered snapshot sequence. Recovery inspection and all
	// selected snapshots run inside that provider's sequence, so a slow or
	// unavailable sibling cannot hold a cross-target inspection/snapshot
	// barrier. Canonical Git persistence is the only shared critical section.
	var persistMutex sync.Mutex
	outcomes, err := runTargetPublicationSequencesConcurrently(ctx, targetNames, txDir, values.workers,
		func(ctx context.Context, target, targetDir string, workers int, output io.Writer) error {
			inspectDir := filepath.Join(targetDir, "inspect")
			if err := os.Mkdir(inspectDir, 0o700); err != nil {
				return withExitCode(ExitInternal, "create target recovery inspection: %v", err)
			}
			view, interruptedSnapshot, interrupted, inspectErr := interruptedPublicationIntent(ctx, cfg, canonical, target, inspectDir)
			if inspectErr != nil {
				return inspectErr
			}
			if interrupted {
				publication, selected := prepared[interruptedSnapshot]
				if view != "snapshot" || !selected {
					return withExitCode(ExitConflict, "target %s has an interrupted %s/%s publication; select that exact intent before publishing %v", target, view, interruptedSnapshot, snapshotIDs)
				}
				recoveryDir := filepath.Join(targetDir, "recover-snapshot-"+interruptedSnapshot)
				if err := os.Mkdir(recoveryDir, 0o700); err != nil {
					return withExitCode(ExitInternal, "create snapshot recovery transaction: %v", err)
				}
				outcome := publishPreparedTarget(ctx, cfg, canonical, repos, publication, target, desiredCommit, recoveryDir, values, workers, &persistMutex)
				if failure := emitTargetPublicationOutcome(output, publication, outcome); failure != nil {
					return failure
				}
			}
			for _, snapshotID := range snapshotIDs {
				if interrupted && snapshotID == interruptedSnapshot {
					continue
				}
				publication := prepared[snapshotID]
				intentDir := filepath.Join(targetDir, "snapshot-"+snapshotID)
				if err := os.Mkdir(intentDir, 0o700); err != nil {
					return withExitCode(ExitInternal, "create snapshot publication transaction: %v", err)
				}
				outcome := publishPreparedTarget(ctx, cfg, canonical, repos, publication, target, desiredCommit, intentDir, values, workers, &persistMutex)
				if failure := emitTargetPublicationOutcome(output, publication, outcome); failure != nil {
					return failure
				}
			}
			return nil
		})
	if err != nil {
		return false, withExitCode(ExitInternal, "run target snapshot publication sequences: %v", err)
	}
	partial := false
	for _, outcome := range outcomes {
		if len(outcome.output) != 0 {
			_, _ = stdout.Write(outcome.output)
		}
		if outcome.err == nil {
			continue
		}
		partial = true
		if len(outcome.output) == 0 {
			fmt.Fprintf(stdout, "publish target=%s view=snapshot status=failed-sequence error=%q\n", outcome.target, redactPublishError(outcome.err))
		}
		if len(targetNames) == 1 {
			return false, publishTargetExitError(outcome.err)
		}
	}
	return partial, nil
}

// prepareSnapshotPublicationSet freezes and materializes a complete immutable
// snapshot set before any provider mutation begins. The returned publications
// are read-only and may be consumed by independent target-major sequences.
func prepareSnapshotPublicationSet(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, repos []config.Repo, snapshotIDs []string, txDir string, values commonFlags, privateKey, passphrase []byte, repositoryKeySHA string, stdout io.Writer) (prepared map[string]preparedPublication, resultErr error) {
	requests := make([]materializationSelectionRequest, 0, len(snapshotIDs))
	for _, snapshotID := range snapshotIDs {
		leaves, err := selectedSnapshotPublicationLeaves(canonical, cfg, repos, snapshotID, values)
		if err != nil {
			return nil, withExitCode(ExitVerification, "expand snapshot publication selectors: %v", err)
		}
		targetRoot := defaultMaterializationTarget(snapshotID, true)
		if !filepath.IsAbs(targetRoot) {
			targetRoot = filepath.Join(cfg.Root, filepath.FromSlash(targetRoot))
		}
		requests = append(requests, materializationSelectionRequest{
			Source: materializeCanonicalSource{ID: snapshotID, Snapshot: true}, Leaves: leaves,
			TargetRoot: targetRoot, IncludeMetadata: true,
		})
	}
	values, selectionOwner, err := beginMaterializationSelectionForRequests(cfg, canonical, values, "publish", requests)
	if err != nil {
		return nil, withExitCode(ExitConflict, "begin snapshot selected-set materialization: %v", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, finishMaterializationSelectedSet(cfg, values.materializeTrust, selectionOwner, resultErr))
	}()
	prepared = make(map[string]preparedPublication, len(snapshotIDs))
	for _, snapshotID := range snapshotIDs {
		directory := filepath.Join(txDir, "snapshot-"+snapshotID)
		if err := os.Mkdir(directory, 0o700); err != nil {
			return nil, withExitCode(ExitInternal, "create snapshot publication transaction: %v", err)
		}
		publication, err := preparePublicationSnapshot(ctx, cfg, canonical, pool, repos, snapshotID, directory, values, privateKey, passphrase, stdout)
		if err != nil {
			return nil, err
		}
		publication.repositoryKeySHA256 = repositoryKeySHA
		prepared[snapshotID] = publication
	}
	selectionErr := finishMaterializationSelectedSet(cfg, values.materializeTrust, selectionOwner, nil)
	selectionOwner = false
	if selectionErr != nil {
		return nil, withExitCode(ExitConflict, "%v", selectionErr)
	}
	return prepared, nil
}

// preparePublicationSnapshot builds the exact hostable tree represented by
// immutable snapshot refs. It deliberately uses the same materializer and
// metadata generators as `sow materialize <snapshot>`: package files remain
// CAS hardlinks, while APT and YUM metadata is regenerated and signed from the
// immutable manifests and canonical commit timestamps.
func preparePublicationSnapshot(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, repos []config.Repo, snapshotID, txDir string, values commonFlags, privateKey, passphrase []byte, stdout io.Writer) (preparedPublication, error) {
	prepared := preparedPublication{view: "snapshot", snapshotID: snapshotID}
	if err := views.ValidateSnapshotID(snapshotID); err != nil {
		return prepared, withExitCode(ExitConfig, "%v", err)
	}
	if _, err := retainMaterializedSnapshot(snapshotID, timeNowUTC(), cfg.State.SnapshotMaterializationMonths); err != nil {
		return prepared, withExitCode(ExitConfig, "%v", err)
	}

	var inputs []views.ProjectionInput
	var readers []io.ReadCloser
	var leaves []viewLeaf
	closeReaders := func() error {
		var closeErr error
		for _, reader := range readers {
			closeErr = errors.Join(closeErr, reader.Close())
		}
		readers = nil
		return closeErr
	}
	defer closeReaders()
	selected, err := selectedSnapshotPublicationLeaves(canonical, cfg, repos, snapshotID, values)
	if err != nil {
		return prepared, withExitCode(ExitVerification, "expand snapshot publication selectors: %v", err)
	}
	prepared.routeLeaves = append([]viewLeaf(nil), selected...)
	for _, leaf := range selected {
		ref, err := state.SnapshotRef(snapshotID, leaf.repo.ID, leaf.os, leaf.arch)
		if err != nil {
			return prepared, withExitCode(ExitInternal, "%v", err)
		}
		canonicalPath, err := state.SnapshotPath(snapshotID, leaf.repo.ID, leaf.os, leaf.arch)
		if err != nil {
			return prepared, withExitCode(ExitInternal, "%v", err)
		}
		commit, exists, err := canonical.Ref(ref)
		if err != nil {
			return prepared, withExitCode(ExitInternal, "read %s: %v", ref, err)
		}
		if !exists {
			continue
		}
		if err := validateViewAt(canonical, commit, canonicalPath, leaf, false); err != nil {
			return prepared, withExitCode(ExitVerification, "validate %s: %v", ref, err)
		}
		reader, err := canonical.OpenPathAt(commit, canonicalPath)
		if err != nil {
			return prepared, withExitCode(ExitInternal, "%v", err)
		}
		readers = append(readers, reader)
		inputs = append(inputs, views.ProjectionInput{Label: ref.String(), Reader: reader})
		leaves = append(leaves, leaf)
	}
	if len(inputs) == 0 {
		return prepared, withExitCode(ExitConfig, "selectors matched no %s snapshot refs", snapshotID)
	}
	payloadManifest := filepath.Join(txDir, "snapshot-payload.tsv")
	payload, err := os.OpenFile(payloadManifest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return prepared, withExitCode(ExitInternal, "create snapshot payload manifest: %v", err)
	}
	entries, bytes, projectErr := views.ProjectManifest(inputs, payload)
	closeErr := errors.Join(payload.Sync(), payload.Close(), closeReaders())
	if projectErr != nil || closeErr != nil {
		return prepared, withExitCode(ExitVerification, "project snapshot %s: %v", snapshotID, errors.Join(projectErr, closeErr))
	}

	target := defaultMaterializationTarget(snapshotID, true)
	payloadReader, err := os.Open(payloadManifest)
	if err != nil {
		return prepared, withExitCode(ExitInternal, "%v", err)
	}
	if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustPayloadBefore); err != nil {
		_ = payloadReader.Close()
		return prepared, withExitCode(ExitConflict, "%v", err)
	}
	materialized, materializeErr := pool.MaterializeWithOptions(ctx, payloadReader, target, repository.MaterializeOptions{Workers: values.workers})
	closeErr = payloadReader.Close()
	if materializeErr != nil || closeErr != nil {
		return prepared, withExitCode(ExitConflict, "materialize snapshot %s: %v", snapshotID, errors.Join(materializeErr, closeErr))
	}
	if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustPayloadAfter); err != nil {
		return prepared, withExitCode(ExitConflict, "%v", err)
	}
	targetAbs := filepath.Join(cfg.Root, filepath.FromSlash(target))
	currentManifest := filepath.Join(txDir, "snapshot-current.tsv")
	if _, err := manifest.Scan(ctx, targetAbs, manifest.Scope{Path: "."}, currentManifest, manifest.ScanOptions{Workers: values.workers, ChunkEntries: values.chunk, TempDir: filepath.Join(cfg.StatePath(), "tmp")}); err != nil {
		return prepared, withExitCode(ExitVerification, "scan current snapshot %s: %v", snapshotID, err)
	}
	localSelection, err := snapshotMaterializationSelection(cfg, leaves, snapshotID)
	if err != nil {
		return prepared, withExitCode(ExitConfig, "resolve snapshot selector ownership: %v", err)
	}
	reconcileManifest := filepath.Join(txDir, "snapshot-reconcile.tsv")
	if err := ReplaceManifestSelection(currentManifest, payloadManifest, reconcileManifest, localSelection); err != nil {
		return prepared, withExitCode(ExitVerification, "merge snapshot selector ownership: %v", err)
	}
	if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustExactReconcileBefore); err != nil {
		return prepared, withExitCode(ExitConflict, "%v", err)
	}
	reconciled, err := pool.ReconcileExact(ctx, reconcileManifest, target, values.workers, values.chunk)
	if err != nil {
		return prepared, withExitCode(ExitVerification, "reconcile snapshot %s: %v", snapshotID, err)
	}
	if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustExactReconcileAfter); err != nil {
		return prepared, withExitCode(ExitConflict, "%v", err)
	}
	metadata, err := materializeRepositoryMetadata(ctx, cfg, canonical, leaves, materializeCanonicalSource{ID: snapshotID, Snapshot: true}, targetAbs, txDir, privateKey, passphrase, values)
	if err != nil {
		return prepared, withExitCode(ExitVerification, "build repository metadata for %s: %v", snapshotID, err)
	}
	if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustServingPublishBefore); err != nil {
		return prepared, withExitCode(ExitConflict, "%v", err)
	}
	if err := serving.PublishHostableTree(targetAbs); err != nil {
		return prepared, withExitCode(ExitVerification, "publish directly hostable snapshot %s: %v", snapshotID, err)
	}
	if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustServingPublishAfter); err != nil {
		return prepared, withExitCode(ExitConflict, "%v", err)
	}
	if err := completeMaterializedAssetUnits(values, cfg, leaves, materializeCanonicalSource{ID: snapshotID, Snapshot: true}, targetAbs); err != nil {
		return prepared, withExitCode(ExitConflict, "complete snapshot asset materialization units: %v", err)
	}

	seenAPT := make(map[string]struct{})
	seenAsset := make(map[string]struct{})
	for _, leaf := range leaves {
		switch leaf.repo.Type {
		case "apt":
			if _, duplicate := seenAPT[leaf.repo.ID]; duplicate {
				continue
			}
			seenAPT[leaf.repo.ID] = struct{}{}
			root := filepath.ToSlash(filepath.Join(target, filepath.FromSlash(leaf.repo.Path)))
			prepared.projections = append(prepared.projections, publicationProjection{
				view: "snapshot", repo: leaf.repo, sourceRoot: root,
				canonicalRoot: leaf.repo.Path, remoteRoot: leaf.repo.Path, legacyRoot: leaf.repo.Path,
				selectedPayloadManifest: payloadManifest, aptMetadataSuites: []string{snapshotID},
			})
		case "asset":
			if _, duplicate := seenAsset[leaf.repo.ID]; duplicate {
				continue
			}
			seenAsset[leaf.repo.ID] = struct{}{}
			root := filepath.ToSlash(filepath.Join(target, filepath.FromSlash(leaf.repo.Path)))
			prepared.projections = append(prepared.projections, publicationProjection{
				view: "snapshot", repo: leaf.repo, os: "all", arch: "all", sourceRoot: root,
				canonicalRoot: leaf.repo.Path, remoteRoot: leaf.repo.AssetPublicRoot(), legacyRoot: leaf.repo.Path,
			})
		case "yum":
			legacy, pathErr := leaf.repo.PathForArch(leaf.arch)
			if pathErr != nil {
				return prepared, withExitCode(ExitConfig, "%v", pathErr)
			}
			root := filepath.ToSlash(filepath.Join(target, filepath.FromSlash(legacy)))
			prepared.projections = append(prepared.projections, publicationProjection{
				view: "snapshot", repo: leaf.repo, os: leaf.os, arch: leaf.arch, sourceRoot: root,
				canonicalRoot: legacy, remoteRoot: legacy, legacyRoot: legacy,
			})
		}
	}
	sort.Slice(prepared.projections, func(i, j int) bool { return prepared.projections[i].sourceRoot < prepared.projections[j].sourceRoot })
	var manifests []string
	for index, projection := range prepared.projections {
		scanPath := filepath.Join(txDir, fmt.Sprintf("scan-snapshot-%06d.tsv", index))
		if _, err := manifest.Scan(ctx, cfg.Root, manifest.Scope{Path: projection.sourceRoot}, scanPath, manifest.ScanOptions{Workers: values.workers, ChunkEntries: values.chunk, TempDir: filepath.Join(cfg.StatePath(), "tmp")}); err != nil {
			return prepared, withExitCode(ExitVerification, "scan snapshot publication source %s: %v", projection.sourceRoot, err)
		}
		if projection.repo.Type == "apt" {
			original, exists := cfg.RepoByName(projection.repo.ID)
			if !exists {
				return prepared, withExitCode(ExitConfig, "APT snapshot repository %s is absent from canonical configuration", projection.repo.ID)
			}
			filtered := filepath.Join(txDir, fmt.Sprintf("scan-snapshot-%06d-selected.tsv", index))
			if err := filterAPTPublicationManifest(scanPath, projection.selectedPayloadManifest, projection, original, filtered); err != nil {
				return prepared, withExitCode(ExitVerification, "filter selected APT snapshot source %s: %v", projection.sourceRoot, err)
			}
			scanPath = filtered
		}
		manifests = append(manifests, scanPath)
		prepared.scopes = append(prepared.scopes, projection.sourceRoot)
	}
	prepared.manifestPath = filepath.Join(txDir, "selected-snapshot-"+snapshotID+".tsv")
	if err := mergePublicationManifests(manifests, prepared.manifestPath, txDir); err != nil {
		return prepared, withExitCode(ExitInternal, "merge snapshot publication manifest: %v", err)
	}
	sort.Strings(prepared.scopes)
	fmt.Fprintf(stdout, "publish materialized snapshot=%s entries=%d bytes=%d linked=%d relinked=%d pruned=%d apt_suites=%d yum_repos=%d\n", snapshotID, entries, bytes, materialized.Linked, materialized.Relinked, reconciled.RemovedFiles, metadata.APTSuites, metadata.YUMRepos)
	return prepared, nil
}

// selectedSnapshotPublicationLeaves widens any selected APT suite to every
// configured architecture once at least one explicitly selected ref exists.
// Release/InRelease is a suite-wide pointer, so --arch is a trigger for the
// transaction rather than permission to publish an architecture fragment.
func selectedSnapshotPublicationLeaves(canonical *state.Store, cfg *config.Config, repos []config.Repo, snapshotID string, values commonFlags) ([]viewLeaf, error) {
	candidates := selectedLeaves(repos, values)
	result := make([]viewLeaf, 0, len(candidates))
	type aptSuite struct {
		repo  config.Repo
		suite string
	}
	selectedSuites := make(map[string]aptSuite)
	for _, leaf := range candidates {
		if leaf.repo.Type != "apt" {
			result = append(result, leaf)
			continue
		}
		original, exists := cfg.RepoByName(leaf.repo.ID)
		if !exists || original.Type != "apt" || original.APT == nil {
			return nil, fmt.Errorf("APT repository %s is absent from canonical configuration", leaf.repo.ID)
		}
		present := make(map[string]bool, len(original.Arches))
		found := false
		for _, arch := range original.Arches {
			ref, err := state.SnapshotRef(snapshotID, leaf.repo.ID, leaf.os, arch)
			if err != nil {
				return nil, err
			}
			if _, exists, err := canonical.Ref(ref); err != nil {
				return nil, err
			} else if exists {
				present[arch] = true
				found = true
			}
		}
		if !found {
			continue
		}
		for _, arch := range original.Arches {
			if present[arch] {
				continue
			}
			missing, _ := state.SnapshotRef(snapshotID, leaf.repo.ID, leaf.os, arch)
			return nil, fmt.Errorf("APT snapshot suite %s/%s is incomplete: configured sibling ref %s is missing", leaf.repo.ID, leaf.os, missing)
		}
		selectedRepo := original
		selectedRepo.APT = original.APT.NarrowSuites([]string{leaf.os})
		selectedRepo.Arches = append([]string(nil), original.Arches...)
		selectedSuites[leaf.repo.ID+"\x00"+leaf.os] = aptSuite{repo: selectedRepo, suite: leaf.os}
	}
	keys := make([]string, 0, len(selectedSuites))
	for key := range selectedSuites {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		selection := selectedSuites[key]
		for _, arch := range uniqueSorted(selection.repo.Arches) {
			result = append(result, viewLeaf{repo: selection.repo, os: selection.suite, arch: arch})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		left := result[i].repo.ID + "\x00" + result[i].os + "\x00" + result[i].arch
		right := result[j].repo.ID + "\x00" + result[j].os + "\x00" + result[j].arch
		return left < right
	})
	return result, nil
}

// snapshotMaterializationSelection maps logical paths below the fixed
// .sow/materialized/snapshots/<id> root to selector-owned exact scopes. APT
// pool entries are upsert-only because suites share them; YUM and asset leaves
// own independent roots and can be reconciled exactly.
func snapshotMaterializationSelection(cfg *config.Config, leaves []viewLeaf, snapshotID string) (manifestSelectionScopes, error) {
	return directMaterializationSelection(cfg, leaves, materializeCanonicalSource{ID: snapshotID, Snapshot: true})
}

// directMaterializationSelection maps a CLI selector to the exact filesystem
// scopes it owns below a materialization target. APT suites replace metadata
// atomically while their shared pool is upsert-only; YUM leaves and asset
// repositories own independent trees. Snapshot APT metadata is named after the
// immutable snapshot ID rather than its source suite.
func directMaterializationSelection(cfg *config.Config, leaves []viewLeaf, source materializeCanonicalSource) (manifestSelectionScopes, error) {
	replace := make(map[string]struct{})
	upsert := make(map[string]struct{})
	for _, leaf := range leaves {
		original, exists := cfg.RepoByName(leaf.repo.ID)
		if !exists {
			return manifestSelectionScopes{}, fmt.Errorf("repository %s is absent from canonical configuration", leaf.repo.ID)
		}
		switch original.Type {
		case "apt":
			outputSuite := leaf.os
			if source.Snapshot {
				outputSuite = source.ID
			}
			replace[path.Join(original.Path, "dists", outputSuite)] = struct{}{}
			upsert[path.Join(original.Path, "pool")] = struct{}{}
		case "yum":
			root, err := original.PathForArch(leaf.arch)
			if err != nil {
				return manifestSelectionScopes{}, err
			}
			replace[root] = struct{}{}
			if source.ID == "latest" && !source.Snapshot && source.RefCommits == nil {
				projection, matched, err := config.YUMCompatibilityProjectionForSource(cfg.CompatibilityProjections, original.ID, source.ID, leaf.os, leaf.arch)
				if err != nil {
					return manifestSelectionScopes{}, err
				}
				if matched {
					replace[projection.Root] = struct{}{}
				}
			}
		case "asset":
			replace[original.Path] = struct{}{}
		default:
			return manifestSelectionScopes{}, fmt.Errorf("unsupported repository type %q", original.Type)
		}
	}
	result := manifestSelectionScopes{Replace: make([]string, 0, len(replace)), Upsert: make([]string, 0, len(upsert))}
	for scope := range replace {
		result.Replace = append(result.Replace, scope)
	}
	for scope := range upsert {
		result.Upsert = append(result.Upsert, scope)
	}
	var err error
	result.Replace, result.Upsert, err = normalizeManifestSelectionScopes(result.Replace, result.Upsert)
	return result, err
}

func selectedPublishSnapshots(selected []string) ([]string, error) {
	seen := make(map[string]struct{}, len(selected))
	result := make([]string, 0, len(selected))
	for _, snapshotID := range selected {
		if err := views.ValidateSnapshotID(snapshotID); err != nil {
			return nil, err
		}
		if strings.ContainsAny(snapshotID, "\x00\r\n\t") {
			return nil, errors.New("unsafe snapshot ID")
		}
		if _, duplicate := seen[snapshotID]; duplicate {
			continue
		}
		seen[snapshotID] = struct{}{}
		result = append(result, snapshotID)
	}
	sort.Strings(result)
	return result, nil
}

func discoverRecentSnapshots(canonical *state.Store, now time.Time, months int) ([]string, error) {
	refs, err := canonical.SOWRefs()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	for _, ref := range refs {
		name := ref.Name.String()
		const prefix = "refs/sow/snapshots/"
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		remainder := strings.TrimPrefix(name, prefix)
		snapshotID, _, found := strings.Cut(remainder, "/")
		if !found || views.ValidateSnapshotID(snapshotID) != nil {
			return nil, fmt.Errorf("invalid canonical snapshot ref %s", name)
		}
		retained, err := retainMaterializedSnapshot(snapshotID, now, months)
		if err != nil {
			return nil, err
		}
		if retained {
			seen[snapshotID] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for snapshotID := range seen {
		result = append(result, snapshotID)
	}
	sort.Strings(result)
	return result, nil
}
