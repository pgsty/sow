package cli

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
)

const materializedRouteLedgerRootPrefix = "serving/materializations/"

type materializedRouteLedgerAuditStats struct {
	Partitions int
	Ledgers    int
	Files      int
}

type materializedRouteHistoricalAuditCache struct {
	lifecycles map[plumbing.Hash]canonicalServingLifecycle
}

func newMaterializedRouteHistoricalAuditCache() *materializedRouteHistoricalAuditCache {
	return &materializedRouteHistoricalAuditCache{lifecycles: make(map[plumbing.Hash]canonicalServingLifecycle)}
}

func (cache *materializedRouteHistoricalAuditCache) lifecycleAt(canonical *state.Store, commit plumbing.Hash) (canonicalServingLifecycle, error) {
	if cache == nil {
		return canonicalServingLifecycle{}, errors.New("materialized route historical audit cache is unavailable")
	}
	if lifecycle, exists := cache.lifecycles[commit]; exists {
		return lifecycle, nil
	}
	lifecycle, err := loadCanonicalServingLifecycleAt(canonical, commit)
	if err != nil {
		return canonicalServingLifecycle{}, err
	}
	cache.lifecycles[commit] = lifecycle
	return lifecycle, nil
}

// auditCanonicalMaterializedRouteLedgers performs the repository-wide,
// canonical half of the materialization audit. Target paths are deliberately
// represented only by their SHA-256 identity in canonical state, so fsck cannot
// safely infer and inspect an arbitrary physical tree from this ledger alone.
// Physical closure is instead proved by target-bound Nginx admission. Here we
// fail closed on every canonical partition, including partitions outside a
// repo selector: unknown files, incomplete triples, wrong receipt paths,
// payload/exact/claim closure, and stale config/ref vectors are canonical
// corruption, not selectable repo drift.
func auditCanonicalMaterializedRouteLedgers(canonical *state.Store, stageDir string) (materializedRouteLedgerAuditStats, error) {
	var stats materializedRouteLedgerAuditStats
	if canonical == nil || stageDir == "" {
		return stats, fmt.Errorf("invalid canonical materialized-route audit input")
	}
	head, err := canonical.HeadHash()
	if err != nil {
		return stats, fmt.Errorf("resolve canonical HEAD for materialized-route audit: %w", err)
	}
	if head.IsZero() {
		return stats, fmt.Errorf("resolve canonical HEAD for materialized-route audit: canonical repository is uninitialized")
	}

	partitions := make(map[string][]string)
	err = canonical.ForEachFileAt(head, "", func(name string) error {
		if name == strings.TrimSuffix(materializedRouteLedgerRootPrefix, "/") {
			return fmt.Errorf("canonical materialized-route namespace root is a blob, not a directory")
		}
		if !strings.HasPrefix(name, materializedRouteLedgerRootPrefix) {
			return nil
		}
		stats.Files++
		if !serving.IsMaterializedRouteLedgerStatePath(name) {
			return fmt.Errorf("unknown canonical materialized-route ledger path %s", name)
		}
		parts := strings.Split(name, "/")
		if len(parts) < 6 {
			return fmt.Errorf("invalid canonical materialized-route ledger path %s", name)
		}
		key := parts[2] + "\x00" + parts[3]
		partitions[key] = append(partitions[key], name)
		return nil
	})
	if err != nil {
		return stats, err
	}

	keys := make([]string, 0, len(partitions))
	for key := range partitions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	historical := newMaterializedRouteHistoricalAuditCache()
	for _, key := range keys {
		parts := strings.Split(key, "\x00")
		if len(parts) != 2 {
			return stats, fmt.Errorf("invalid canonical materialized-route partition identity")
		}
		files := append([]string(nil), partitions[key]...)
		sort.Strings(files)
		ledgerCount, err := auditCanonicalMaterializedRoutePartition(canonical, head, parts[0], parts[1], files, stageDir, historical)
		if err != nil {
			return stats, fmt.Errorf("audit canonical materialized-route partition target=%s view=%s: %w", parts[0], parts[1], err)
		}
		stats.Partitions++
		stats.Ledgers += ledgerCount
	}
	return stats, nil
}

func auditCanonicalMaterializedRoutePartition(canonical *state.Store, head plumbing.Hash, targetSHA, view string, files []string, stageDir string, historical *materializedRouteHistoricalAuditCache) (_ int, resultErr error) {
	partitionStage, err := os.MkdirTemp(stageDir, "fsck-materialized-route-")
	if err != nil {
		return 0, err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(partitionStage)) }()
	ledgers, err := loadMaterializedRouteLedgersFromFilesAt(canonical, head, files, partitionStage)
	if err != nil {
		return 0, err
	}
	seenOwners := make(map[materializedRouteOwnerID]struct{}, len(ledgers))
	for _, ledger := range ledgers {
		if ledger.Receipt.View != view || ledger.Receipt.TargetSHA256 != targetSHA {
			return 0, fmt.Errorf("receipt %s does not match its canonical target/view partition", ledger.Receipt.ID)
		}
		ownerID := materializedRouteOwnerID{kind: ledger.Receipt.Kind, repo: ledger.Receipt.Repo, arch: ledger.Receipt.Arch}
		if _, duplicate := seenOwners[ownerID]; duplicate {
			return 0, fmt.Errorf("multiple canonical receipts claim semantic route owner %s", ownerID)
		}
		seenOwners[ownerID] = struct{}{}
		exact, err := os.Open(ledger.ExactManifest)
		if err != nil {
			return 0, err
		}
		payload, err := os.Open(ledger.PayloadManifest)
		if err != nil {
			_ = exact.Close()
			return 0, err
		}
		closureErr := serving.ValidateMaterializedRouteManifestClosure(ledger.Receipt, exact, payload)
		closeErr := errors.Join(exact.Close(), payload.Close())
		if closureErr != nil || closeErr != nil {
			return 0, errors.Join(closureErr, closeErr)
		}
		if err := auditHistoricalMaterializedRouteInputs(canonical, head, ledger, partitionStage, historical); err != nil {
			return 0, fmt.Errorf("audit receipt %s historical inputs: %w", ledger.Receipt.ID, err)
		}
	}
	return len(ledgers), nil
}

type historicalMaterializedRouteRef struct {
	os            string
	arch          string
	canonicalPath string
}

func auditHistoricalMaterializedRouteInputs(canonical *state.Store, head plumbing.Hash, ledger materializedRouteLedger, stageDir string, historicalCache *materializedRouteHistoricalAuditCache) error {
	route := ledger.Receipt
	if route.Source != route.View || route.View == "snapshot" || route.OS != "all" {
		return errors.New("ordinary materialized route has invalid historical source/view/OS identity")
	}
	historical, err := loadMaterializedRouteConfigAnchor(canonical, head, route.ConfigCommit, route.ConfigSHA256)
	if err != nil {
		return err
	}
	viewConfig, exists := historical.Views[route.Source]
	if !exists {
		return fmt.Errorf("historical config has no route view %s", route.Source)
	}
	repo, exists := historical.RepoByName(route.Repo)
	if !exists || !repo.IsActive() || repo.Type != route.Kind || !viewIncludesRepo(viewConfig, repo.ID) {
		return fmt.Errorf("historical config does not own route %s/%s", route.Kind, route.Repo)
	}
	owner, allowed, requireComplete, err := historicalMaterializedRouteOwner(repo, route)
	if err != nil {
		return err
	}
	if !sameMaterializedRouteClaims(route.Claims, owner.claims) {
		return errors.New("receipt claims differ from its historical config owner")
	}
	if requireComplete && len(route.Refs) != len(allowed) {
		return fmt.Errorf("receipt historical ref vector has %d entries; want %d", len(route.Refs), len(allowed))
	}
	seen := make(map[string]struct{}, len(route.Refs))
	for _, frozen := range route.Refs {
		coordinate, allowedRef := allowed[frozen.Name]
		if !allowedRef {
			return fmt.Errorf("receipt ref %s is outside its historical config owner", frozen.Name)
		}
		if _, duplicate := seen[frozen.Name]; duplicate {
			return fmt.Errorf("duplicate historical route ref %s", frozen.Name)
		}
		seen[frozen.Name] = struct{}{}
		commit := plumbing.NewHash(frozen.Commit)
		reachable, err := canonical.IsAncestor(commit, head)
		if err != nil || !reachable {
			return errors.Join(err, fmt.Errorf("receipt ref %s commit %s is not reachable from canonical HEAD", frozen.Name, commit))
		}
		blob, exists, err := canonical.BlobIdentityAt(commit, coordinate.canonicalPath)
		if err != nil || !exists || blob.Hash.String() != frozen.ManifestBlob || blob.Size != frozen.ManifestSize {
			return errors.Join(err, fmt.Errorf("receipt ref %s manifest blob identity differs", frozen.Name))
		}
		leaf := viewLeaf{repo: repo, os: coordinate.os, arch: coordinate.arch}
		if err := validateViewAt(canonical, commit, coordinate.canonicalPath, leaf, viewConfig.Access == "public"); err != nil {
			return fmt.Errorf("validate receipt ref %s manifest: %w", frozen.Name, err)
		}
		owner.leaves = append(owner.leaves, materializedRouteOwnerLeaf{
			os: coordinate.os, arch: coordinate.arch, ref: plumbing.ReferenceName(frozen.Name), commit: commit,
			canonicalPath: coordinate.canonicalPath, manifestBlob: blob.Hash, manifestSize: blob.Size,
		})
	}
	projected := filepath.Join(stageDir, "projected-"+route.ID+".tsv")
	if err := projectMaterializedRouteOwnerPayload(canonical, owner, projected); err != nil {
		return fmt.Errorf("project frozen receipt refs: %w", err)
	}
	livePayload := filepath.Join(stageDir, "live-payload-"+route.ID+".tsv")
	if _, err := filterManifestFile(ledger.PayloadManifest, livePayload, func(entry manifest.Entry) bool {
		return materializedRouteCurrentClaimOwns(owner, entry.Path)
	}); err != nil {
		return err
	}
	left, err := os.Open(projected)
	if err != nil {
		return err
	}
	right, err := os.Open(livePayload)
	if err != nil {
		_ = left.Close()
		return err
	}
	diff, diffErr := manifest.Diff(left, right, nil)
	closeErr := errors.Join(left.Close(), right.Close())
	if diffErr != nil || closeErr != nil {
		return errors.Join(diffErr, closeErr)
	}
	if !diff.Clean() {
		return fmt.Errorf("receipt live payload differs from frozen refs: added=%d removed=%d changed=%d", diff.Added, diff.Removed, diff.Changed)
	}
	if route.Kind == "yum" {
		anchor := plumbing.NewHash(route.ConfigCommit)
		lifecycle, err := historicalCache.lifecycleAt(canonical, anchor)
		if err != nil {
			return fmt.Errorf("load historical YUM serving lifecycle: %w", err)
		}
		target, exists := lifecycle.Targets[route.ServingTargetID]
		if !exists {
			return fmt.Errorf("historical YUM serving target %s is absent", route.ServingTargetID)
		}
		yumStage := filepath.Join(stageDir, "historical-yum-"+route.ID)
		if err := os.Mkdir(yumStage, 0o700); err != nil {
			return err
		}
		generationCandidates, err := materializedYUMGenerationIDsFromManifest(ledger.ExactManifest, owner.relativeRoot)
		if err != nil {
			return fmt.Errorf("read historical YUM receipt generation set: %w", err)
		}
		exactParts, generationPayloadParts, err := materializedYUMServingExpectedForTargetAt(canonical, anchor, lifecycle, target, route.Source, owner, yumStage, route.ConfigSHA256, generationCandidates)
		if err != nil {
			return fmt.Errorf("replay historical YUM serving state: %w", err)
		}
		expectedAux := filepath.Join(yumStage, "historical-yum-exact.tsv")
		if err := mergePublicationManifests(exactParts, expectedAux, yumStage); err != nil {
			return err
		}
		actualAux := filepath.Join(yumStage, "receipt-yum-exact.tsv")
		if _, err := filterManifestFile(ledger.ExactManifest, actualAux, func(entry manifest.Entry) bool {
			return !materializedRouteCurrentClaimOwns(owner, entry.Path)
		}); err != nil {
			return err
		}
		if equal, err := manifestFilesEqual(expectedAux, actualAux); err != nil || !equal {
			return errors.Join(err, errors.New("receipt YUM generation or mirrorlist exact bytes differ from historical lifecycle"))
		}
		expectedGenerationPayload := filepath.Join(yumStage, "historical-yum-payload.tsv")
		if err := mergePublicationManifests(generationPayloadParts, expectedGenerationPayload, yumStage); err != nil {
			return err
		}
		actualGenerationPayload := filepath.Join(yumStage, "receipt-yum-payload.tsv")
		if _, err := filterManifestFile(ledger.PayloadManifest, actualGenerationPayload, func(entry manifest.Entry) bool {
			return !materializedRouteCurrentClaimOwns(owner, entry.Path)
		}); err != nil {
			return err
		}
		if equal, err := manifestFilesEqual(expectedGenerationPayload, actualGenerationPayload); err != nil || !equal {
			return errors.Join(err, errors.New("receipt YUM generation payload differs from historical lifecycle"))
		}
	}
	return nil
}

func historicalMaterializedRouteOwner(repo config.Repo, route serving.MaterializedRoute) (materializedRouteOwner, map[string]historicalMaterializedRouteRef, bool, error) {
	owner := materializedRouteOwner{kind: route.Kind, repo: repo, arch: route.Arch}
	allowed := make(map[string]historicalMaterializedRouteRef)
	add := func(osName, arch string) error {
		ref, err := state.ViewRef(route.Source, repo.ID, osName, arch)
		if err != nil {
			return err
		}
		canonicalPath, err := state.ViewPath(route.Source, repo.ID, osName, arch)
		if err != nil {
			return err
		}
		allowed[ref.String()] = historicalMaterializedRouteRef{os: osName, arch: arch, canonicalPath: canonicalPath}
		return nil
	}
	switch repo.Type {
	case "asset":
		if route.Arch != "all" || repo.Asset == nil {
			return owner, nil, false, errors.New("historical asset route has invalid arch or config")
		}
		owner.relativeRoot = repo.Path
		if repo.AssetPublicRoot() == "." {
			for _, key := range repo.Asset.RootKeys {
				owner.claims = append(owner.claims, serving.MaterializedRouteClaim{Kind: serving.MaterializedRouteClaimExactFile, RelativeRoot: path.Join(repo.Path, key)})
			}
		} else {
			owner.claims = []serving.MaterializedRouteClaim{{Kind: serving.MaterializedRouteClaimPrefix, RelativeRoot: repo.Path}}
		}
		return owner, allowed, true, add("all", "all")
	case "apt":
		if route.Arch != "all" || repo.APT == nil {
			return owner, nil, false, errors.New("historical APT route has invalid arch or config")
		}
		owner.relativeRoot = repo.Path
		owner.claims = []serving.MaterializedRouteClaim{{Kind: serving.MaterializedRouteClaimPrefix, RelativeRoot: repo.Path}}
		for _, suite := range repo.APT.Suites {
			for _, arch := range repo.Arches {
				if err := add(suite, arch); err != nil {
					return owner, nil, false, err
				}
			}
		}
		return owner, allowed, false, nil
	case "yum":
		if repo.YUM == nil || !materializedRouteContainsString(repo.Arches, route.Arch) {
			return owner, nil, false, errors.New("historical YUM route has invalid arch or config")
		}
		root, err := repo.PathForArch(route.Arch)
		if err != nil {
			return owner, nil, false, err
		}
		owner.relativeRoot = root
		owner.claims = []serving.MaterializedRouteClaim{
			{Kind: serving.MaterializedRouteClaimPrefix, RelativeRoot: root},
			{Kind: serving.MaterializedRouteClaimGeneration, RelativeRoot: "_sow/v1/g", Leaf: root},
		}
		for _, osName := range repo.OSSelectorValues() {
			owner.claims = append(owner.claims, serving.MaterializedRouteClaim{Kind: serving.MaterializedRouteClaimExactFile, RelativeRoot: serving.MirrorlistPath(route.Source, repo.ID, osName, route.Arch)})
			if err := add(osName, route.Arch); err != nil {
				return owner, nil, false, err
			}
		}
		return owner, allowed, true, nil
	default:
		return owner, nil, false, fmt.Errorf("unsupported historical route kind %s", repo.Type)
	}
}

func materializedRouteContainsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// materializedRouteAuditStagePath is kept narrow so callers never place audit
// copies in a served repository tree by accident.
func materializedRouteAuditStagePath(transactionDir string) string {
	return filepath.Join(transactionDir, "materialized-route-ledgers")
}
