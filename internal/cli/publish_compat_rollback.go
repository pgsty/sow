package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
)

// prepareRolledBackYUMCompatibilityTarget reconstructs a remote rollback from
// local, immutable evidence before a provider client exists. The remote parent
// is deliberately not an authority: it will only be compared with the exact
// local parent digest after observation.
func prepareRolledBackYUMCompatibilityTarget(
	ctx context.Context,
	cfg *config.Config,
	canonical *state.Store,
	prepared preparedPublication,
	target, txDir string,
	values commonFlags,
) (preparedPublication, error) {
	if cfg == nil || canonical == nil {
		return prepared, errors.New("compatibility rollback preflight dependencies are unavailable")
	}
	parent, parentBody, exists, err := readLocalTargetGeneration(canonical, target)
	if err != nil || !exists {
		// A target which has never committed compatibility has nothing to undo.
		return prepared, err
	}
	if err := validatePublishedTargetAffinity(cfg, target, &parent); err != nil {
		return prepared, err
	}
	prepared, err = bindRolledBackYUMCompatibility(prepared, &parent)
	if err != nil || len(prepared.compatibilityRollbacks) == 0 {
		return prepared, err
	}
	if prepared.view != "latest" || prepared.restoreSourceGeneration != 0 || prepared.repositoryPool == nil {
		return prepared, fmt.Errorf("%w: compatibility S0 rollback requires an ordinary latest publication and writable CAS", pub.ErrDrift)
	}

	stateCommit, recorded, err := targetGenerationPublicationState(canonical, target, parent.Generation)
	if err != nil {
		return prepared, fmt.Errorf("%w: locate local compatibility parent generation: %v", pub.ErrDrift, err)
	}
	recordedBody, err := recorded.Canonical()
	if err != nil || !bytes.Equal(recordedBody, parentBody) {
		return prepared, errors.Join(err, fmt.Errorf("%w: local compatibility parent differs from committed publication history", pub.ErrDrift))
	}
	closure, closureExists, err := loadHistoricalPublicationClosureAt(canonical, target, stateCommit)
	if err != nil || !closureExists {
		return prepared, errors.Join(err, fmt.Errorf("%w: local compatibility parent lacks a content-bound publication closure", pub.ErrDrift))
	}
	if err := validateHistoricalGenerationCompatibility(cfg, canonical, target, closure.generation, stateCommit); err != nil {
		return prepared, fmt.Errorf("%w: local compatibility parent identity: %v", pub.ErrDrift, err)
	}
	if err := validateHistoricalCompatibilityPublicationClosure(canonical, stateCommit, closure.generation, closure.plan); err != nil {
		return prepared, fmt.Errorf("%w: local compatibility parent closure: %v", pub.ErrDrift, err)
	}

	ids := make([]string, 0, len(prepared.compatibilityRollbacks))
	for id := range prepared.compatibilityRollbacks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rollbackManifests := make([]string, 0, len(ids)+1)
	rollbackManifests = append(rollbackManifests, prepared.manifestPath)
	for _, id := range ids {
		identity := prepared.compatibilityRollbacks[id]
		projection, selected := prepared.compatibilitySelected[id]
		owner, owned := prepared.compatibilityOwners[id]
		if !selected || !owned || id != identity.ID || projection.ID != id || projection.Root != identity.RouteRoot ||
			owner.ID != projection.Source.Repo || !owner.PublishesToTarget(target) {
			return prepared, fmt.Errorf("%w: compatibility rollback %s lost exact selector/target affinity", pub.ErrDrift, id)
		}
		if err := requireYUMCompatibilityCanonicalRollback(canonical, id, identity); err != nil {
			return prepared, fmt.Errorf("%w: compatibility rollback %s authority: %v", pub.ErrDrift, id, err)
		}
		staged, err := stageFrozenYUMCompatibilityS0Rollback(ctx, cfg, canonical, prepared.repositoryPool, projection, owner, identity, target, filepath.Join(txDir, "rollback-"+id), values)
		if err != nil {
			return prepared, fmt.Errorf("%w: stage compatibility %s exact S0 rollback: %v", pub.ErrVerification, id, err)
		}
		prepared.projections = append(prepared.projections, staged.projection)
		prepared.scopes = append(prepared.scopes, staged.projection.sourceRoot)
		rollbackManifests = append(rollbackManifests, staged.manifestPath)
	}
	merged := filepath.Join(txDir, "selected-target-"+target+"-"+prepared.label()+"-s0-rollback.tsv")
	mergeDir := filepath.Join(txDir, "rollback-merge-"+target)
	if err := os.MkdirAll(mergeDir, 0o700); err != nil {
		return prepared, err
	}
	if err := mergePublicationManifests(rollbackManifests, merged, mergeDir); err != nil {
		return prepared, fmt.Errorf("merge exact S0 rollback manifest: %w", err)
	}
	prepared.manifestPath = merged
	prepared.scopes = uniqueSorted(prepared.scopes)
	prepared.compatibilityRollbackParentSHA256 = digestBytesCLI(parentBody)
	return prepared, nil
}

func requireYUMCompatibilityCanonicalRollback(canonical *state.Store, id string, identity pub.CompatibilityState) error {
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		return errors.Join(err, errors.New("canonical HEAD is unavailable"))
	}
	ledgerPath, err := state.YUMCompatibilityCutoverPath(id)
	if err != nil {
		return err
	}
	body, exists, err := readCanonicalBytesAt(canonical, head, ledgerPath, maximumYUMCompatibilityLedgerBytes)
	if err != nil || !exists {
		return errors.Join(err, errors.New("append-only rollback ledger is missing"))
	}
	events, err := decodeYUMCompatibilityCutoverLedger(body)
	if err != nil || len(events) == 0 || yumCompatibilityLedgerStage(events) != yumCompatibilityStageRolledBack {
		return errors.Join(err, errors.New("append-only ledger does not end in rollback"))
	}
	last := events[len(events)-1]
	if last.ID != id || last.Action != "rollback" || last.FreezeCommit != identity.FreezeCommit || last.CandidateManifestSHA256 != identity.CandidateManifestSHA256 {
		return errors.New("rollback event differs from the published compatibility identity")
	}
	return nil
}

// preflightLocalYUMCompatibilityS0Rollback runs the same immutable/local
// rollback preparation used by the full planner before the incremental fast
// path is allowed to construct a provider client.
func preflightLocalYUMCompatibilityS0Rollback(
	ctx context.Context,
	cfg *config.Config,
	canonical *state.Store,
	pool *repository.Store,
	repos []config.Repo,
	target, txDir string,
	values commonFlags,
) error {
	if pool == nil {
		return errors.New("compatibility rollback preflight has no repository CAS")
	}
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		return errors.Join(err, errors.New("compatibility rollback preflight has no canonical HEAD"))
	}
	selected, err := selectedLatestYUMCompatibilityForViews(cfg, repos, []string{"latest"}, values)
	if err != nil {
		return fmt.Errorf("select compatibility rollback preflight projections: %w", err)
	}
	prepared := preparedPublication{
		view: "latest", repositoryPool: pool,
		compatibilitySelected: make(map[string]config.YUMCompatibilityProjection),
		compatibilityOwners:   make(map[string]config.Repo),
	}
	for _, projection := range selected {
		owner, exists := cfg.RepoByName(projection.Source.Repo)
		if !exists || !owner.PublishesToTarget(target) {
			continue
		}
		active, err := publicationYUMCompatibilityActiveAt(canonical, head, projection.ID)
		if err != nil {
			return err
		}
		if active {
			continue
		}
		prepared.compatibilitySelected[projection.ID] = projection
		prepared.compatibilityOwners[projection.ID] = owner
	}
	if len(prepared.compatibilitySelected) == 0 {
		return nil
	}
	empty := filepath.Join(txDir, "rollback-preflight-empty.tsv")
	file, err := os.OpenFile(empty, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := errors.Join(file.Sync(), file.Close()); err != nil {
		return err
	}
	prepared.manifestPath = empty
	_, err = prepareRolledBackYUMCompatibilityTarget(ctx, cfg, canonical, prepared, target, txDir, values)
	return err
}

type compatibilityS0RollbackStage struct {
	projection   publicationProjection
	manifestPath string
}

func stageFrozenYUMCompatibilityS0Rollback(
	ctx context.Context,
	cfg *config.Config,
	canonical *state.Store,
	pool *repository.Store,
	projection config.YUMCompatibilityProjection,
	owner config.Repo,
	identity pub.CompatibilityState,
	target string,
	txDir string,
	values commonFlags,
) (compatibilityS0RollbackStage, error) {
	var result compatibilityS0RollbackStage
	if err := os.MkdirAll(txDir, 0o700); err != nil {
		return result, err
	}
	carrier, exists := cfg.RepoByName(projection.Carrier)
	if !exists {
		return result, errors.New("compatibility S0 carrier is absent")
	}
	workflow := yumCompatibilityWorkflow{cfg: cfg, projection: projection, carrier: carrier, owner: owner}
	adoption, err := validateYUMCompatibilityAdoptedStateWithPool(ctx, workflow, canonical, pool, txDir, values)
	if err != nil {
		return result, err
	}
	if adoption.BaselineCommit == "" || identity.SourceCommit == "" || identity.Carrier != adoption.Carrier || identity.OwnerRepo != adoption.OwnerRepo {
		return result, errors.New("published compatibility identity differs from S1 adoption")
	}

	baseline := filepath.Join(txDir, "carrier-s0-rooted.tsv")
	baselineRef, baselineCommit, baselineSHA, baselineGit, baselineSize, err := requireYUMCompatibilityCarrierBaseline(ctx, cfg, canonical, carrier, baseline, values)
	if err != nil {
		return result, err
	}
	if baselineRef.String() != adoption.BaselineRef || baselineCommit.String() != adoption.BaselineCommit ||
		baselineSHA != adoption.BaselineManifestSHA256 || baselineGit.String() != adoption.BaselineManifestGit || baselineSize != adoption.BaselineManifestSize {
		return result, errors.New("current carrier baseline differs from immutable S1 adoption")
	}

	// The immutable source manifest proves the exact flat RPM membership that
	// the legacy S0 primary advertises. Both the live carrier and the isolated
	// staged tree are structurally and cryptographically verified against it.
	sourcePath, _ := state.YUMCompatibilitySourcePath(projection.ID)
	localSource := filepath.Join(txDir, "source.tsv")
	if err := copyCanonicalPathAt(canonical, plumbing.NewHash(identity.SourceCommit), sourcePath, localSource, adoption.SourceManifestSize); err != nil {
		return result, err
	}
	aliases := filepath.Join(txDir, "aliases.tsv")
	if _, _, err := writeYUMCompatibilityAliases(localSource, aliases); err != nil {
		return result, err
	}
	keyring, err := loadFrozenCompatibilityPackageKeyring(canonical, identity)
	if err != nil {
		return result, err
	}
	liveRoot := filepath.Join(cfg.Root, filepath.FromSlash(projection.Root))
	if err := verifyLegacyYUMCompatibilityRoot(ctx, liveRoot, aliases, keyring); err != nil {
		return result, fmt.Errorf("verify current exact S0 carrier: %w", err)
	}

	if err := importYUMCompatibilityManifestObjects(ctx, pool, cfg.Root, baseline); err != nil {
		return result, fmt.Errorf("import exact S0 carrier into CAS: %w", err)
	}
	relative := filepath.Join(txDir, "carrier-s0-relative.tsv")
	if err := rewriteManifestRoot(baseline, relative, projection.Root, "."); err != nil {
		return result, err
	}
	if target != "cf" && target != "cos" {
		return result, fmt.Errorf("unsupported compatibility rollback target %q", target)
	}
	// Target builders run concurrently. Keep their replayable S0 trees on
	// disjoint paths so one target cannot reconcile files while its sibling is
	// scanning or uploading the same local source.
	stageRoot := filepath.ToSlash(filepath.Join(config.StateDirectory, "materialized", "compatibility", projection.ID, "s0", target, adoption.BaselineManifestSHA256))
	manifestFile, err := os.Open(relative)
	if err != nil {
		return result, err
	}
	_, materializeErr := pool.MaterializeWithOptions(ctx, manifestFile, stageRoot, repository.MaterializeOptions{
		Workers: values.workers, AllowReplacePath: func(string) bool { return true },
	})
	closeErr := manifestFile.Close()
	if materializeErr != nil || closeErr != nil {
		return result, errors.Join(materializeErr, closeErr)
	}
	if _, err := pool.ReconcileExact(ctx, relative, stageRoot, values.workers, values.chunk); err != nil {
		return result, err
	}
	stagePhysical := filepath.Join(cfg.Root, filepath.FromSlash(stageRoot))
	if err := verifyLegacyYUMCompatibilityRoot(ctx, stagePhysical, aliases, keyring); err != nil {
		return result, fmt.Errorf("verify isolated exact S0 tree: %w", err)
	}

	rooted := filepath.Join(txDir, "carrier-s0-desired.tsv")
	if err := prefixManifest(relative, rooted, projection.Root); err != nil {
		return result, err
	}
	if err := compareManifestFiles(baseline, rooted); err != nil {
		return result, fmt.Errorf("S0 rooted manifest identity: %w", err)
	}
	result.manifestPath = rooted
	result.projection = publicationProjection{
		view: "latest", repo: owner, os: projection.Source.OS, arch: projection.Source.Arch,
		compatibilityID: projection.ID, compatibilityRollback: true,
		sourceRoot: projection.Root, localRoot: stageRoot,
		canonicalRoot: projection.Root, remoteRoot: projection.Root, legacyRoot: projection.Root,
	}
	return result, nil
}

func compareManifestFiles(leftPath, rightPath string) error {
	left, err := os.Open(leftPath)
	if err != nil {
		return err
	}
	right, err := os.Open(rightPath)
	if err != nil {
		left.Close()
		return err
	}
	stats, diffErr := manifest.Diff(left, right, nil)
	closeErr := errors.Join(left.Close(), right.Close())
	if diffErr != nil || closeErr != nil {
		return errors.Join(diffErr, closeErr)
	}
	if !stats.Clean() {
		return fmt.Errorf("manifests differ: added=%d removed=%d changed=%d", stats.Added, stats.Removed, stats.Changed)
	}
	return nil
}

func sameCompatibilityRollbackSet(left, right map[string]pub.CompatibilityState) bool {
	if len(left) != len(right) {
		return false
	}
	for id, identity := range left {
		if other, exists := right[id]; !exists || other != identity {
			return false
		}
	}
	return true
}
