package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

type publicationMaterializationRecoveryKind string

const (
	publicationMaterializationRecoveryViews     publicationMaterializationRecoveryKind = "views"
	publicationMaterializationRecoverySnapshots publicationMaterializationRecoveryKind = "snapshots"
	publicationMaterializationRecoveryRestore   publicationMaterializationRecoveryKind = "restore"
)

type publicationMaterializationRecovery struct {
	kind           publicationMaterializationRecoveryKind
	leavesBySource map[string][]viewLeaf
	allLeaves      []viewLeaf
}

// decodePublicationMaterializationRecovery treats the durable unit vector as
// the selector authority. Current CLI selectors describe work to start only
// after this exact local transaction has converged; they must never widen or
// narrow recovery.
func decodePublicationMaterializationRecovery(cfg *config.Config, journal materializationSelectionJournal) (publicationMaterializationRecovery, error) {
	result := publicationMaterializationRecovery{leavesBySource: make(map[string][]viewLeaf)}
	seen := make(map[string]map[string]struct{})
	for _, unit := range journal.Units {
		kind, err := publicationMaterializationUnitRecoveryKind(cfg, unit)
		if err != nil {
			return result, err
		}
		if result.kind == "" {
			result.kind = kind
		} else if result.kind != kind {
			return result, errors.New("durable publication materialization mixes mutable, snapshot, or restore intents")
		}
		repo, exists := cfg.RepoByName(unit.Repo)
		if !exists || !repo.IsActive() {
			return result, fmt.Errorf("durable publication materialization repo %s is not active in canonical configuration", unit.Repo)
		}
		leaves, err := publicationMaterializationUnitLeaves(cfg, repo, unit, kind)
		if err != nil {
			return result, err
		}
		if kind == publicationMaterializationRecoveryViews && !viewIncludesRepo(cfg.Views[unit.Source], repo.ID) {
			return result, fmt.Errorf("durable publication materialization repo %s is not admitted by view %s", repo.ID, unit.Source)
		}
		if seen[unit.Source] == nil {
			seen[unit.Source] = make(map[string]struct{})
		}
		for _, leaf := range leaves {
			key := leaf.repo.ID + "\x00" + leaf.os + "\x00" + leaf.arch
			if _, duplicate := seen[unit.Source][key]; duplicate {
				continue
			}
			seen[unit.Source][key] = struct{}{}
			result.leavesBySource[unit.Source] = append(result.leavesBySource[unit.Source], leaf)
			result.allLeaves = append(result.allLeaves, leaf)
		}
	}
	if result.kind == "" || len(result.allLeaves) == 0 {
		return result, errors.New("durable publication materialization has no recoverable package units")
	}
	for source := range result.leavesBySource {
		sortViewLeaves(result.leavesBySource[source])
	}
	sortViewLeaves(result.allLeaves)
	return result, nil
}

// requireClosedPublicationRecoveryViewLeaves rejects legacy or forged durable
// journals that describe only one logical alias/suite of a physical route.
// Recovery must replay the exact durable set, so it cannot safely widen such a
// journal after a crash; fail closed and require an operator to resolve that
// obsolete intent rather than performing a last-writer-wins partial repair.
func requireClosedPublicationRecoveryViewLeaves(cfg *config.Config, canonical *state.Store, recovery publicationMaterializationRecovery) error {
	if recovery.kind != publicationMaterializationRecoveryViews {
		return nil
	}
	for viewName, leaves := range recovery.leavesBySource {
		view, exists := cfg.Views[viewName]
		if !exists {
			return fmt.Errorf("durable publication view %s is not configured", viewName)
		}
		closed, err := materializedRoutePhysicalClosureLeaves(cfg, canonical, materializeCanonicalSource{ID: viewName, Public: view.Access == "public"}, leaves)
		if err != nil {
			return fmt.Errorf("close durable publication view %s physical owners: %w", viewName, err)
		}
		if !sameViewLeafSet(closed, leaves) {
			return fmt.Errorf("durable publication view %s has an incomplete physical route owner vector", viewName)
		}
	}
	return nil
}

// requireExactHistoricalMaterializationRecovery validates the requested
// restore identity without constructing a provider client. Unit IDs bind the
// historical ref vector and the hash of the target-specific restore root, so a
// different generation or target fails before even a read-only remote observe.
func requireExactHistoricalMaterializationRecovery(cfg *config.Config, canonical *state.Store, journal materializationSelectionJournal, target string, generation uint64) error {
	historical, err := loadHistoricalTargetPublication(canonical, target, generation)
	if err != nil {
		return err
	}
	leavesByRef, err := configuredHistoricalLeaves(cfg, historical.Generation)
	if err != nil {
		return err
	}
	leaves := make([]viewLeaf, 0, len(leavesByRef))
	refCommits := make(map[string]plumbing.Hash, len(leavesByRef))
	for name, historicalLeaf := range leavesByRef {
		leaves = append(leaves, historicalLeaf.leaf)
		refCommits[name] = plumbing.NewHash(historicalLeaf.ref.Commit)
	}
	_, restoreRoot := historicalRestoreMaterializationPaths(cfg, target, historical.Generation)
	source := materializeCanonicalSource{ID: historical.Generation.IntentView, RefCommits: refCommits}
	if view, exists := cfg.Views[source.ID]; exists {
		source.Public = view.Access == "public"
	}
	if historical.Generation.IntentView == "snapshot" {
		source.ID, source.Snapshot, source.Public = historical.Generation.IntentSnapshot, true, false
	}
	units, err := planMaterializationSelectedUnits(cfg, canonical, []materializationSelectionRequest{{
		Source: source, Leaves: leaves, TargetRoot: restoreRoot, IncludeMetadata: true,
	}})
	if err != nil {
		return err
	}
	if len(units) != len(journal.Units) {
		return fmt.Errorf("durable historical materialization does not match --restore-generation %d --target %s", generation, target)
	}
	for index := range units {
		if units[index].ID != journal.Units[index].ID {
			return fmt.Errorf("durable historical materialization does not match --restore-generation %d --target %s", generation, target)
		}
	}
	return nil
}

func publicationMaterializationUnitRecoveryKind(cfg *config.Config, unit materializationSelectedUnit) (publicationMaterializationRecoveryKind, error) {
	// yum-compat deliberately pins an ancestor of the mutable latest source
	// ref, so Historical describes ref semantics rather than a restore intent.
	// Recover it as part of the exact latest view selected set.
	if unit.Kind == "yum-compat" {
		view, exists := cfg.Views[unit.Source]
		if !exists || unit.Source != "latest" || view.Access != "public" || !unit.Historical {
			return "", fmt.Errorf("durable YUM compatibility unit %s is not a pinned public latest projection", unit.ID)
		}
		return publicationMaterializationRecoveryViews, nil
	}
	if unit.Historical {
		_, mutableView := cfg.Views[unit.Source]
		immutableSnapshot := views.ValidateSnapshotID(unit.Source) == nil
		if (!mutableView || unit.Source == "snapshot") && !immutableSnapshot {
			return "", fmt.Errorf("historical publication materialization source %s is not a configured view", unit.Source)
		}
		return publicationMaterializationRecoveryRestore, nil
	}
	if _, exists := cfg.Views[unit.Source]; exists && unit.Source != "snapshot" {
		return publicationMaterializationRecoveryViews, nil
	}
	if err := views.ValidateSnapshotID(unit.Source); err == nil {
		return publicationMaterializationRecoverySnapshots, nil
	}
	return "", fmt.Errorf("durable publication materialization source %s is neither a mutable view nor a snapshot", unit.Source)
}

func publicationMaterializationUnitLeaves(cfg *config.Config, repo config.Repo, unit materializationSelectedUnit, kind publicationMaterializationRecoveryKind) ([]viewLeaf, error) {
	snapshot := kind == publicationMaterializationRecoverySnapshots || (kind == publicationMaterializationRecoveryRestore && views.ValidateSnapshotID(unit.Source) == nil)
	expectedRef := func(arch string) (string, error) {
		if snapshot {
			ref, err := state.SnapshotRef(unit.Source, repo.ID, unit.OS, arch)
			return ref.String(), err
		}
		ref, err := state.ViewRef(unit.Source, repo.ID, unit.OS, arch)
		return ref.String(), err
	}
	switch unit.Kind {
	case "asset":
		if repo.Type != "asset" || repo.Asset == nil || unit.OS != "all" || unit.Arch != "all" || len(unit.Refs) != 1 {
			return nil, fmt.Errorf("durable asset publication unit %s has invalid repo coordinates", unit.ID)
		}
		name, err := expectedRef("all")
		if err != nil {
			return nil, err
		}
		if unit.Refs[0].Name != name {
			return nil, fmt.Errorf("durable asset publication unit %s ref does not match its coordinates", unit.ID)
		}
		return []viewLeaf{{repo: repo, os: "all", arch: "all"}}, nil
	case "apt":
		if repo.Type != "apt" || repo.APT == nil || unit.Arch != "" || !contains(repo.APT.Suites, unit.OS) {
			return nil, fmt.Errorf("durable APT publication unit %s has invalid repo/suite/arch coordinates", unit.ID)
		}
		refs := make(map[string]struct{}, len(unit.Refs))
		for _, ref := range unit.Refs {
			refs[ref.Name] = struct{}{}
		}
		leaves := make([]viewLeaf, 0, len(unit.Refs))
		for _, arch := range uniqueSorted(repo.Arches) {
			name, err := expectedRef(arch)
			if err != nil {
				return nil, err
			}
			if _, exists := refs[name]; !exists {
				continue
			}
			delete(refs, name)
			leaves = append(leaves, viewLeaf{repo: repo, os: unit.OS, arch: arch})
		}
		if len(leaves) == 0 || len(refs) != 0 {
			return nil, fmt.Errorf("durable APT publication unit %s ref vector is not representable by current coordinates", unit.ID)
		}
		return leaves, nil
	case "yum-compat":
		if repo.Type != "yum" || repo.YUM == nil || len(unit.Refs) != 1 || !unit.Historical {
			return nil, fmt.Errorf("durable YUM compatibility unit %s has invalid owner/ref coordinates", unit.ID)
		}
		projection, exists, err := config.YUMCompatibilityProjectionForSource(cfg.CompatibilityProjections, repo.ID, unit.Source, unit.OS, unit.Arch)
		if err != nil || !exists || projection.Source.OS != unit.OS || projection.Source.Arch != unit.Arch {
			return nil, errors.Join(err, fmt.Errorf("durable YUM compatibility unit %s does not match configured pinned source", unit.ID))
		}
		sourceRef, err := state.YUMCompatibilitySourceRef(projection.ID)
		if err != nil || unit.Refs[0].Name != sourceRef.String() ||
			(projection.Source.Commit != config.YUMCompatibilityPinAtFirstFreeze && projection.Source.Commit != unit.Refs[0].Commit) {
			return nil, errors.Join(err, fmt.Errorf("durable YUM compatibility unit %s source ref is not the immutable adoption", unit.ID))
		}
		// Ordinary yum/serving units in the same selected set carry the active
		// owner leaves. Compatibility is an additional frozen route closure and
		// must not synthesize or widen an ordinary OS selector during recovery.
		return nil, nil
	case "yum", "serving":
		if repo.Type != "yum" || repo.YUM == nil || !contains(repo.Arches, unit.Arch) || !contains(repo.OSSelectorValues(), unit.OS) || len(unit.Refs) != 1 {
			return nil, fmt.Errorf("durable YUM publication unit %s has invalid repo/OS/arch coordinates", unit.ID)
		}
		if unit.Kind == "serving" && kind != publicationMaterializationRecoveryViews {
			return nil, fmt.Errorf("durable %s publication cannot contain a serving unit", kind)
		}
		name, err := expectedRef(unit.Arch)
		if err != nil {
			return nil, err
		}
		if unit.Refs[0].Name != name {
			return nil, fmt.Errorf("durable YUM publication unit %s ref does not match its coordinates", unit.ID)
		}
		return []viewLeaf{{repo: repo, os: unit.OS, arch: unit.Arch}}, nil
	default:
		return nil, fmt.Errorf("unsupported durable publication materialization unit kind %s", unit.Kind)
	}
}

func sortViewLeaves(leaves []viewLeaf) {
	sort.Slice(leaves, func(i, j int) bool {
		left := leaves[i].repo.ID + "\x00" + leaves[i].os + "\x00" + leaves[i].arch
		right := leaves[j].repo.ID + "\x00" + leaves[j].os + "\x00" + leaves[j].arch
		return left < right
	})
}

func publicationRecoveryRepos(cfg *config.Config, leaves []viewLeaf) ([]config.Repo, error) {
	type dimensions struct {
		oses   map[string]struct{}
		arches map[string]struct{}
	}
	selected := make(map[string]dimensions)
	for _, leaf := range leaves {
		dims := selected[leaf.repo.ID]
		if dims.oses == nil {
			dims.oses = make(map[string]struct{})
			dims.arches = make(map[string]struct{})
		}
		dims.oses[leaf.os] = struct{}{}
		dims.arches[leaf.arch] = struct{}{}
		selected[leaf.repo.ID] = dims
	}
	ids := make([]string, 0, len(selected))
	for id := range selected {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]config.Repo, 0, len(ids))
	for _, id := range ids {
		repo, exists := cfg.RepoByName(id)
		if !exists || !repo.IsActive() {
			return nil, fmt.Errorf("publication recovery repo %s is not active", id)
		}
		dims := selected[id]
		// RepoByName returns a value whose slice still shares the canonical
		// configuration backing array. Allocate the narrowed dimension so
		// recovery planning cannot mutate cfg while satisfying S1011.
		repo.Arches = append([]string(nil), uniqueSorted(mapKeys(dims.arches))...)
		if repo.APT != nil {
			repo.APT = repo.APT.NarrowSuites(uniqueSorted(mapKeys(dims.oses)))
		}
		result = append(result, repo)
	}
	return result, nil
}

func mapKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	return result
}

func mergePublicationRecoveryRepos(current, recovery []config.Repo) []config.Repo {
	byID := make(map[string]config.Repo, len(current)+len(recovery))
	for _, repo := range current {
		byID[repo.ID] = repo
	}
	for _, repo := range recovery {
		if _, exists := byID[repo.ID]; !exists {
			byID[repo.ID] = repo
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]config.Repo, 0, len(ids))
	for _, id := range ids {
		result = append(result, byID[id])
	}
	return result
}

func publicationReposRequireSigning(repos []config.Repo) bool {
	for _, repo := range repos {
		if repo.Type == "apt" || repo.Type == "yum" {
			return true
		}
	}
	return false
}

func exactPublicationRecoveryValues(values commonFlags, trust *materializationTrustSnapshot) commonFlags {
	values.repos = csvFlag{}
	values.oses = csvFlag{}
	values.arches = csvFlag{}
	values.recover = true
	values.materializeTrust = trust
	values.materializeOperation = "publish"
	return values
}

func recoverPublicationSnapshotMaterializationSelection(
	ctx context.Context,
	cfg *config.Config,
	canonical *state.Store,
	pool *repository.Store,
	plan publicationMaterializationRecovery,
	txDir string,
	values commonFlags,
	privateKey, passphrase []byte,
	stdout io.Writer,
) (resultErr error) {
	snapshotIDs := make([]string, 0, len(plan.leavesBySource))
	requests := make([]materializationSelectionRequest, 0, len(plan.leavesBySource))
	reposBySnapshot := make(map[string][]config.Repo, len(plan.leavesBySource))
	for snapshotID, leaves := range plan.leavesBySource {
		if err := views.ValidateSnapshotID(snapshotID); err != nil {
			return withExitCode(ExitConflict, "durable publication snapshot %s is invalid: %v", snapshotID, err)
		}
		repos, err := publicationRecoveryRepos(cfg, leaves)
		if err != nil {
			return withExitCode(ExitConflict, "%v", err)
		}
		reposBySnapshot[snapshotID] = repos
		targetRoot := defaultMaterializationTarget(snapshotID, true)
		if !filepath.IsAbs(targetRoot) {
			targetRoot = filepath.Join(cfg.Root, filepath.FromSlash(targetRoot))
		}
		requests = append(requests, materializationSelectionRequest{
			Source: materializeCanonicalSource{ID: snapshotID, Snapshot: true}, Leaves: leaves,
			TargetRoot: targetRoot, IncludeMetadata: true,
		})
		snapshotIDs = append(snapshotIDs, snapshotID)
	}
	sort.Strings(snapshotIDs)
	values, owner, err := beginMaterializationSelectionForRequests(cfg, canonical, values, "publish", requests)
	if err != nil {
		return withExitCode(ExitConflict, "resume exact snapshot selected-set materialization: %v", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, finishMaterializationSelectedSet(cfg, values.materializeTrust, owner, resultErr))
	}()
	for _, snapshotID := range snapshotIDs {
		directory := filepath.Join(txDir, "recover-local-snapshot-"+snapshotID)
		if err := os.Mkdir(directory, 0o700); err != nil {
			return withExitCode(ExitInternal, "create local snapshot recovery transaction: %v", err)
		}
		if _, err := preparePublicationSnapshot(ctx, cfg, canonical, pool, reposBySnapshot[snapshotID], snapshotID, directory, values, privateKey, passphrase, stdout); err != nil {
			return err
		}
	}
	finishErr := finishMaterializationSelectedSet(cfg, values.materializeTrust, owner, nil)
	owner = false
	if finishErr != nil {
		return withExitCode(ExitConflict, "%v", finishErr)
	}
	return nil
}
