package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"

	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
)

const packageMaterializationTrustSchema = "sow-package-materialization-trust/v1"

// packageMaterializationTrustReceipt binds the external signing inputs that
// are intentionally not part of sow.yaml. The adjacent MaterializedRoute
// receipt binds the complete canonical ref vector and exact physical bytes.
// Both must match before add/rm may take the true no-op path.
type packageMaterializationTrustReceipt struct {
	Schema                  string `json:"schema"`
	RouteContentSHA256      string `json:"route_content_sha256"`
	RepositoryKeySHA256     string `json:"repository_key_sha256"`
	YUMPackageKeyringSHA256 string `json:"yum_package_keyring_sha256,omitempty"`
}

func (receipt packageMaterializationTrustReceipt) validate(kind string) error {
	if receipt.Schema != packageMaterializationTrustSchema || !validMaterializationTrustSHA256(receipt.RouteContentSHA256) ||
		!validMaterializationTrustSHA256(receipt.RepositoryKeySHA256) {
		return errors.New("invalid package materialization trust receipt")
	}
	if kind == "yum" {
		if !validMaterializationTrustSHA256(receipt.YUMPackageKeyringSHA256) {
			return errors.New("invalid YUM package materialization trust receipt")
		}
	} else if receipt.YUMPackageKeyringSHA256 != "" {
		return errors.New("non-YUM package materialization receipt names an RPM keyring")
	}
	return nil
}

func (receipt packageMaterializationTrustReceipt) canonical(kind string) ([]byte, error) {
	if err := receipt.validate(kind); err != nil {
		return nil, err
	}
	return json.Marshal(receipt)
}

func decodePackageMaterializationTrust(body []byte, kind string) (packageMaterializationTrustReceipt, error) {
	var receipt packageMaterializationTrustReceipt
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return receipt, errors.New("package materialization trust receipt has trailing data")
	}
	canonical, err := receipt.canonical(kind)
	if err != nil {
		return receipt, err
	}
	if !bytes.Equal(body, canonical) {
		return receipt, errors.New("package materialization trust receipt is not canonical")
	}
	return receipt, nil
}

type packageMaterializationReceiptPaths struct {
	receipt string
	exact   string
	payload string
	trust   string
}

type packageMaterializationTarget struct {
	root   *os.Root
	path   string
	opened os.FileInfo
}

func openPackageMaterializationTarget(target string) (*packageMaterializationTarget, error) {
	before, err := os.Lstat(target)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.Join(err, errors.New("package materialization target is not a real directory"))
	}
	root, err := os.OpenRoot(target)
	if err != nil {
		return nil, err
	}
	opened, statErr := root.Stat(".")
	after, pathErr := os.Lstat(target)
	if statErr != nil || pathErr != nil || !os.SameFile(before, opened) || !os.SameFile(before, after) {
		_ = root.Close()
		return nil, errors.Join(statErr, pathErr, errors.New("package materialization target changed while binding"))
	}
	return &packageMaterializationTarget{root: root, path: target, opened: opened}, nil
}

func (target *packageMaterializationTarget) Verify() error {
	if target == nil || target.root == nil {
		return errors.New("package materialization target is unavailable")
	}
	opened, statErr := target.root.Stat(".")
	current, pathErr := os.Lstat(target.path)
	if statErr != nil || pathErr != nil || !os.SameFile(target.opened, opened) || !os.SameFile(target.opened, current) {
		return errors.Join(statErr, pathErr, errors.New("package materialization target coordinate changed"))
	}
	return nil
}

func (target *packageMaterializationTarget) Close() error {
	if target == nil || target.root == nil {
		return nil
	}
	return target.root.Close()
}

func packageMaterializationStatePaths(route serving.MaterializedRoute) (packageMaterializationReceiptPaths, error) {
	if err := route.Validate(); err != nil {
		return packageMaterializationReceiptPaths{}, err
	}
	base := path.Join("materializations", "packages", route.TargetSHA256, route.View, "routes", route.ID)
	return packageMaterializationReceiptPaths{
		receipt: base + ".json",
		exact:   base + ".exact.tsv",
		payload: base + ".payload.tsv",
		trust:   base + ".trust.json",
	}, nil
}

func packageMaterializationRouteIdentity(cfg *config.Config, canonical *state.Store, owner materializedRouteOwner, view, targetSHA, configSHA, configCommit string) (serving.MaterializedRouteIdentity, error) {
	refs := make([]serving.MaterializedRouteRef, 0, len(owner.leaves))
	for _, leaf := range owner.leaves {
		refs = append(refs, serving.MaterializedRouteRef{
			Name: leaf.ref.String(), Commit: leaf.commit.String(), ManifestBlob: leaf.manifestBlob.String(), ManifestSize: leaf.manifestSize,
		})
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })
	servingTargetID := ""
	if owner.kind == "yum" {
		// This receipt covers the raw package/index owner, not the independently
		// versioned mirrorlist generation surface. A valid, target-bound digest is
		// nevertheless required by the shared receipt schema.
		servingTargetID = targetSHA
	}
	identity := serving.MaterializedRouteIdentity{
		Kind: owner.kind, View: view, Source: view, TargetSHA256: targetSHA,
		Claims: packageMaterializationClaims(owner), ConfigSHA256: configSHA, ConfigCommit: configCommit,
		ServingTargetID: servingTargetID, Repo: owner.repo.ID, OS: "all", Arch: owner.arch, Refs: refs,
	}
	if cfg == nil || canonical == nil {
		return identity, errors.New("package materialization route dependencies are unavailable")
	}
	return identity, nil
}

func packageMaterializationClaims(owner materializedRouteOwner) []serving.MaterializedRouteClaim {
	// Package write verbs own only the raw package/index prefix. Immutable YUM
	// generations and mirrorlists have their own materialize/publish receipts
	// and must never be inferred from an add/rm cache witness.
	return []serving.MaterializedRouteClaim{{Kind: serving.MaterializedRouteClaimPrefix, RelativeRoot: owner.relativeRoot}}
}

// completePackageMaterializationOwners returns the complete *extant* ref
// vector for each selected package write owner. Ordinary serving routes require
// every configured YUM alias because they emit every mirrorlist. Package write
// verbs are different: a newly initialized repo may not have created every
// optional logical alias yet, but every alias that does exist shares one raw
// repo+arch root and must participate in the same rebuild and receipt.
func completePackageMaterializationOwners(cfg *config.Config, canonical *state.Store, source materializeCanonicalSource, selected []viewLeaf) ([]materializedRouteOwner, error) {
	if cfg == nil || canonical == nil || source.Snapshot || len(selected) == 0 {
		return nil, nil
	}
	selectedSet := make(map[string]struct{}, len(selected))
	touched := make(map[materializedRouteOwnerID]config.Repo)
	for _, leaf := range selected {
		if leaf.repo.Type != "apt" && leaf.repo.Type != "yum" {
			continue
		}
		selectedSet[servingLeafKey(leaf.repo.ID, leaf.os, leaf.arch)] = struct{}{}
		arch := "all"
		if leaf.repo.Type == "yum" {
			arch = leaf.arch
		}
		touched[materializedRouteOwnerID{kind: leaf.repo.Type, repo: leaf.repo.ID, arch: arch}] = leaf.repo
	}
	ids := make([]materializedRouteOwnerID, 0, len(touched))
	for id := range touched {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	result := make([]materializedRouteOwner, 0, len(ids))
	for _, id := range ids {
		repo, exists := cfg.RepoByName(id.repo)
		if !exists || repo.Type != id.kind {
			return nil, fmt.Errorf("package materialization owner %s is absent from configuration", id)
		}
		owner := materializedRouteOwner{kind: repo.Type, repo: repo, arch: id.arch}
		var coordinates []routeCoordinate
		switch repo.Type {
		case "apt":
			if repo.APT == nil {
				return nil, fmt.Errorf("APT package materialization owner %s has no repository contract", id)
			}
			owner.relativeRoot = repo.Path
			for _, suite := range repo.APT.Suites {
				for _, arch := range repo.Arches {
					coordinates = append(coordinates, routeCoordinate{os: suite, arch: arch})
				}
			}
		case "yum":
			if repo.YUM == nil {
				return nil, fmt.Errorf("YUM package materialization owner %s has no repository contract", id)
			}
			root, err := repo.PathForArch(id.arch)
			if err != nil {
				return nil, err
			}
			owner.relativeRoot = root
			for _, osName := range repo.OSSelectorValues() {
				coordinates = append(coordinates, routeCoordinate{os: osName, arch: id.arch})
			}
		default:
			continue
		}
		complete, selectedOwner, err := populateMaterializedRouteOwner(canonical, source, &owner, coordinates, selectedSet, false)
		if err != nil {
			return nil, err
		}
		if complete && selectedOwner {
			result = append(result, owner)
		}
	}
	return result, nil
}

func packageMaterializationPhysicalClosureLeaves(cfg *config.Config, canonical *state.Store, source materializeCanonicalSource, selected []viewLeaf) ([]viewLeaf, error) {
	owners, err := completePackageMaterializationOwners(cfg, canonical, source, selected)
	if err != nil {
		return nil, err
	}
	closed := make(map[string]viewLeaf, len(selected))
	for _, leaf := range selected {
		closed[servingLeafKey(leaf.repo.ID, leaf.os, leaf.arch)] = leaf
	}
	for _, owner := range owners {
		for _, leaf := range owner.leaves {
			value := viewLeaf{repo: owner.repo, os: leaf.os, arch: leaf.arch}
			closed[servingLeafKey(value.repo.ID, value.os, value.arch)] = value
		}
	}
	result := make([]viewLeaf, 0, len(closed))
	for _, leaf := range closed {
		result = append(result, leaf)
	}
	sort.Slice(result, func(i, j int) bool {
		return servingLeafKey(result[i].repo.ID, result[i].os, result[i].arch) < servingLeafKey(result[j].repo.ID, result[j].os, result[j].arch)
	})
	return result, nil
}

func packageMaterializationPhysicalClosureRequests(cfg *config.Config, canonical *state.Store, requests []materializationSelectionRequest) ([]materializationSelectionRequest, error) {
	result := append([]materializationSelectionRequest(nil), requests...)
	for index := range result {
		closed, err := packageMaterializationPhysicalClosureLeaves(cfg, canonical, result[index].Source, result[index].Leaves)
		if err != nil {
			return nil, err
		}
		result[index].Leaves = closed
	}
	return result, nil
}

func packageMaterializationTrustFor(snapshot *materializationTrustSnapshot, owner materializedRouteOwner, contentSHA string) (packageMaterializationTrustReceipt, error) {
	if snapshot == nil || !validMaterializationTrustSHA256(snapshot.repositoryKeySHA256) {
		return packageMaterializationTrustReceipt{}, errors.New("package materialization trust snapshot is unavailable")
	}
	receipt := packageMaterializationTrustReceipt{
		Schema: packageMaterializationTrustSchema, RouteContentSHA256: contentSHA,
		RepositoryKeySHA256: snapshot.repositoryKeySHA256,
	}
	if owner.kind == "yum" {
		frozen, exists := snapshot.yum[owner.repo.ID]
		if !exists || !validMaterializationTrustSHA256(frozen.digest) {
			return receipt, fmt.Errorf("repo %s is absent from the RPM package trust snapshot", owner.repo.ID)
		}
		receipt.YUMPackageKeyringSHA256 = frozen.digest
	}
	return receipt, receipt.validate(owner.kind)
}

// packageMaterializationReceiptsReady is a fail-safe optimization. Any absent,
// malformed, stale, or physically drifted receipt returns false so the normal
// generator/materializer path repairs the route. Canonical/ref/config access
// failures and cancellation remain hard errors rather than being hidden by the
// optimization.
func packageMaterializationReceiptsReady(
	ctx context.Context,
	cfg *config.Config,
	canonical *state.Store,
	pool *repository.Store,
	view string,
	leaves []viewLeaf,
	values commonFlags,
	snapshot *materializationTrustSnapshot,
) (bool, error) {
	if ctx == nil || cfg == nil || canonical == nil || pool == nil || snapshot == nil {
		return false, nil
	}
	targetRoot, err := defaultMutableServingTarget(cfg, view)
	if err != nil {
		return false, err
	}
	source := materializeCanonicalSource{ID: view, Public: cfg.Views[view].Access == "public"}
	owners, err := completePackageMaterializationOwners(cfg, canonical, source, leaves)
	if err != nil {
		return false, err
	}
	packageOwners := owners[:0]
	for _, owner := range owners {
		if owner.kind == "apt" || owner.kind == "yum" {
			packageOwners = append(packageOwners, owner)
		}
	}
	if len(packageOwners) == 0 {
		return false, nil
	}
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		return false, errors.Join(err, errors.New("canonical HEAD is unavailable for package materialization readiness"))
	}
	configSHA, err := cfg.CanonicalSHA256()
	if err != nil {
		return false, err
	}
	targetSHA, err := serving.MaterializedRouteTargetSHA256(targetRoot)
	if err != nil {
		return false, err
	}
	txDir, err := newTransactionDir(cfg.StatePath(), "package-ready-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(txDir)
	bound, err := openPackageMaterializationTarget(targetRoot)
	if err != nil {
		return false, nil
	}
	defer bound.Close()
	options := serving.InstallOptions{Workers: values.workers, ChunkEntries: values.chunk, TempDir: filepath.Join(cfg.StatePath(), "tmp")}
	for index, owner := range packageOwners {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		identity, err := packageMaterializationRouteIdentity(cfg, canonical, owner, view, targetSHA, configSHA, head.String())
		if err != nil {
			return false, err
		}
		coordinate, err := serving.NewMaterializedRoute(identity, bytes.NewReader(nil), bytes.NewReader(nil))
		if err != nil {
			return false, err
		}
		paths, err := packageMaterializationStatePaths(coordinate)
		if err != nil {
			return false, err
		}
		body, exists, readErr := readCanonicalBytesAt(canonical, head, paths.receipt, materializedRouteReceiptMaxBytes)
		if readErr != nil || !exists {
			return false, nil
		}
		route, decodeErr := serving.DecodeMaterializedRoute(body)
		if decodeErr != nil || route.ID != coordinate.ID || route.Kind != owner.kind || route.View != view || route.Source != view ||
			route.TargetSHA256 != targetSHA || route.ConfigSHA256 != configSHA || route.Repo != owner.repo.ID || route.OS != "all" || route.Arch != owner.arch ||
			route.ServingTargetID != identity.ServingTargetID || !sameMaterializedRouteClaims(route.Claims, identity.Claims) || !sameMaterializedRouteRefs(route.Refs, identity.Refs) {
			return false, nil
		}
		if _, err := loadMaterializedRouteConfigAnchor(canonical, head, route.ConfigCommit, configSHA); err != nil {
			return false, nil
		}
		if owner.kind == "apt" {
			suites := make(map[string]struct{})
			for _, leaf := range owner.leaves {
				suites[leaf.os] = struct{}{}
			}
			for suite := range suites {
				ledgerPath, pathErr := state.APTByHashLedgerPath("views", view, owner.repo.ID, suite)
				if pathErr != nil {
					return false, pathErr
				}
				reader, openErr := canonical.OpenPathAt(head, ledgerPath)
				if openErr != nil {
					return false, nil
				}
				ledger, decodeErr := aptrepo.DecodeByHashLedger(reader)
				closeErr := reader.Close()
				if decodeErr != nil || closeErr != nil || ledger.Scope != "views/"+view || ledger.Repo != owner.repo.ID || ledger.Suite != suite || ledger.LiveGeneration == "" {
					return false, nil
				}
			}
		}
		trustBody, trustExists, trustErr := readCanonicalBytesAt(canonical, head, paths.trust, materializedRouteReceiptMaxBytes)
		if trustErr != nil || !trustExists {
			return false, nil
		}
		trust, trustErr := decodePackageMaterializationTrust(trustBody, owner.kind)
		wantedTrust, wantedErr := packageMaterializationTrustFor(snapshot, owner, route.ContentSHA256)
		if trustErr != nil || wantedErr != nil || trust != wantedTrust {
			return false, nil
		}
		routeDir := filepath.Join(txDir, fmt.Sprintf("route-%03d", index))
		if err := os.Mkdir(routeDir, 0o700); err != nil {
			return false, err
		}
		exact := filepath.Join(routeDir, "exact.tsv")
		payload := filepath.Join(routeDir, "payload.tsv")
		if err := copyCanonicalMaterializedRouteManifest(canonical, head, paths.exact, exact, route.ExactManifestSHA256); err != nil {
			return false, nil
		}
		if err := copyCanonicalMaterializedRouteManifest(canonical, head, paths.payload, payload, route.PayloadManifestSHA256); err != nil {
			return false, nil
		}
		if err := serving.ValidateMaterializedRouteRoot(ctx, pool, bound.root, route, exact, payload, options); err != nil {
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			return false, nil
		}
	}
	if err := bound.Verify(); err != nil {
		return false, nil
	}
	return true, nil
}

func packageMaterializationRequestsReady(
	ctx context.Context,
	cfg *config.Config,
	canonical *state.Store,
	pool *repository.Store,
	requests []materializationSelectionRequest,
	values commonFlags,
	snapshot *materializationTrustSnapshot,
) (bool, error) {
	if len(requests) == 0 {
		return false, nil
	}
	for _, request := range requests {
		if request.Source.Snapshot || request.Source.RefCommits != nil {
			return false, nil
		}
		ready, err := packageMaterializationReceiptsReady(ctx, cfg, canonical, pool, request.Source.ID, request.Leaves, values, snapshot)
		if err != nil || !ready {
			return ready, err
		}
	}
	return true, nil
}

func packageMaterializationLeavesByView(requests []materializationSelectionRequest) map[string][]viewLeaf {
	result := make(map[string][]viewLeaf)
	for _, request := range requests {
		result[request.Source.ID] = append(result[request.Source.ID], request.Leaves...)
	}
	return result
}

// persistPackageMaterializationReceipts records the exact route only after the
// package generator, exact reconcile, and hostability barrier have all passed.
// localExact is keyed by physical owner and remains relative to that owner's
// configured root; this function prefixes it into the fixed view target.
func persistPackageMaterializationReceipts(
	ctx context.Context,
	cfg *config.Config,
	canonical *state.Store,
	pool *repository.Store,
	view string,
	leaves []viewLeaf,
	localExact map[materializedRouteOwnerID]string,
	txDir string,
	values commonFlags,
	snapshot *materializationTrustSnapshot,
) (string, bool, int, error) {
	if len(localExact) == 0 {
		return "", false, 0, nil
	}
	targetRoot, err := defaultMutableServingTarget(cfg, view)
	if err != nil {
		return "", false, 0, err
	}
	source := materializeCanonicalSource{ID: view, Public: cfg.Views[view].Access == "public"}
	owners, err := completePackageMaterializationOwners(cfg, canonical, source, leaves)
	if err != nil {
		return "", false, 0, err
	}
	var packageOwners []materializedRouteOwner
	for _, owner := range owners {
		if owner.kind == "apt" || owner.kind == "yum" {
			packageOwners = append(packageOwners, owner)
		}
	}
	if len(packageOwners) == 0 {
		return "", false, 0, errors.New("package materialization produced no complete physical owners")
	}
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		return "", false, 0, errors.Join(err, errors.New("canonical HEAD is unavailable for package materialization receipt"))
	}
	configSHA, err := cfg.CanonicalSHA256()
	if err != nil {
		return "", false, 0, err
	}
	if _, err := loadMaterializedRouteConfigAnchor(canonical, head, head.String(), configSHA); err != nil {
		return "", false, 0, err
	}
	targetSHA, err := serving.MaterializedRouteTargetSHA256(targetRoot)
	if err != nil {
		return "", false, 0, err
	}
	bound, err := openPackageMaterializationTarget(targetRoot)
	if err != nil {
		return "", false, 0, err
	}
	defer bound.Close()
	options := serving.InstallOptions{Workers: values.workers, ChunkEntries: values.chunk, TempDir: filepath.Join(cfg.StatePath(), "tmp")}
	staged := make(map[string]string, len(packageOwners)*4)
	var routes []serving.MaterializedRoute
	stageRoot := filepath.Join(txDir, "package-materialization-receipts")
	if err := os.Mkdir(stageRoot, 0o700); err != nil {
		return "", false, 0, err
	}
	for index, owner := range packageOwners {
		ownerExact, exists := localExact[owner.id()]
		if !exists || ownerExact == "" {
			return "", false, 0, fmt.Errorf("package materialization owner %s has no exact generator receipt", owner.id())
		}
		routeDir := filepath.Join(stageRoot, fmt.Sprintf("route-%03d", index))
		if err := os.Mkdir(routeDir, 0o700); err != nil {
			return "", false, 0, err
		}
		exact := filepath.Join(routeDir, "exact.tsv")
		if err := prefixManifestPaths(ownerExact, exact, owner.relativeRoot); err != nil {
			return "", false, 0, err
		}
		payload := filepath.Join(routeDir, "payload.tsv")
		if err := projectMaterializedRouteOwnerPayload(canonical, owner, payload); err != nil {
			return "", false, 0, err
		}
		identity, err := packageMaterializationRouteIdentity(cfg, canonical, owner, view, targetSHA, configSHA, head.String())
		if err != nil {
			return "", false, 0, err
		}
		route, err := deriveMaterializedRouteReceipt(identity, exact, payload)
		if err != nil {
			return "", false, 0, err
		}
		paths, err := packageMaterializationStatePaths(route)
		if err != nil {
			return "", false, 0, err
		}
		if existingBody, exists, readErr := readCanonicalBytesAt(canonical, head, paths.receipt, materializedRouteReceiptMaxBytes); readErr == nil && exists {
			if previous, decodeErr := serving.DecodeMaterializedRoute(existingBody); decodeErr == nil && sameMaterializedRouteFrozenInputs(previous, route) {
				if _, anchorErr := loadMaterializedRouteConfigAnchor(canonical, head, previous.ConfigCommit, configSHA); anchorErr == nil {
					identity.ConfigCommit = previous.ConfigCommit
					route, err = deriveMaterializedRouteReceipt(identity, exact, payload)
					if err != nil {
						return "", false, 0, err
					}
				}
			}
		}
		if err := serving.ValidateMaterializedRouteRoot(ctx, pool, bound.root, route, exact, payload, options); err != nil {
			return "", false, 0, fmt.Errorf("validate package materialization owner %s: %w", owner.id(), err)
		}
		trust, err := packageMaterializationTrustFor(snapshot, owner, route.ContentSHA256)
		if err != nil {
			return "", false, 0, err
		}
		trustBody, err := trust.canonical(owner.kind)
		if err != nil {
			return "", false, 0, err
		}
		normal, err := stageMaterializedRouteLedger(routeDir, route, exact, payload)
		if err != nil {
			return "", false, 0, err
		}
		normalReceipt, normalExact, normalPayload, err := materializedRouteLedgerPaths(route)
		if err != nil {
			return "", false, 0, err
		}
		for canonicalPath, filename := range map[string]string{
			paths.receipt: normal[normalReceipt], paths.exact: normal[normalExact], paths.payload: normal[normalPayload],
		} {
			if filename == "" {
				return "", false, 0, fmt.Errorf("package materialization stage %s is unavailable", canonicalPath)
			}
			staged[canonicalPath] = filename
		}
		trustStage := filepath.Join(routeDir, "trust.json")
		if err := manifest.AtomicCopy(trustStage, bytes.NewReader(trustBody), 0o600); err != nil {
			return "", false, 0, err
		}
		staged[paths.trust] = trustStage
		routes = append(routes, route)
	}
	if err := bound.Verify(); err != nil {
		return "", false, 0, err
	}
	expectations := make([]materializedRouteExpected, 0, len(routes))
	for _, route := range routes {
		expectations = append(expectations, materializedRouteExpected{receipt: route})
	}
	refs, err := materializedRouteRefBarriers(expectations)
	if err != nil {
		return "", false, 0, err
	}
	commit, changed, err := applyCanonicalConfig(ctx, cfg, canonical, "package-materialization-receipt", "sow: record exact package materialization", staged, refs, state.ApplyOptions{})
	if err != nil {
		return commit.String(), changed, 0, err
	}
	if err := bound.Verify(); err != nil {
		return commit.String(), changed, 0, err
	}
	return commit.String(), changed, len(routes), nil
}

type packageMaterializationInvocation struct {
	Kind string
	View string
	Repo string
	OS   string
	Arch string
}

type packageMaterializationHookKey struct{}

// withPackageMaterializationHook is a deterministic test-only seam. It lets
// no-op tests prove that neither a package generator nor a materializer was
// entered; production contexts never carry the hook.
func withPackageMaterializationHook(ctx context.Context, hook func(packageMaterializationInvocation) error) context.Context {
	return context.WithValue(ctx, packageMaterializationHookKey{}, hook)
}

func runPackageMaterializationHook(ctx context.Context, invocation packageMaterializationInvocation) error {
	if ctx == nil {
		return nil
	}
	hook, _ := ctx.Value(packageMaterializationHookKey{}).(func(packageMaterializationInvocation) error)
	if hook == nil {
		return nil
	}
	return hook(invocation)
}
