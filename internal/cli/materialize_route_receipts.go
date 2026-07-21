package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

// A materializedRouteOwner is one complete physical Nginx ownership unit. It
// deliberately aggregates every canonical leaf that shares the same physical
// route: APT and assets are repo-wide; YUM is one arch-wide prefix across all
// configured OS coordinates.
type materializedRouteOwner struct {
	kind         string
	repo         config.Repo
	arch         string
	relativeRoot string
	claims       []serving.MaterializedRouteClaim
	leaves       []materializedRouteOwnerLeaf
}

type materializedRouteOwnerLeaf struct {
	os            string
	arch          string
	ref           plumbing.ReferenceName
	commit        plumbing.Hash
	canonicalPath string
	manifestBlob  plumbing.Hash
	manifestSize  int64
}

type materializedRouteExpected struct {
	receipt     serving.MaterializedRoute
	exactPath   string
	payloadPath string
}

// materializedRouteCleanupScope states how an exact materialization replaces
// canonical Nginx route receipts. A partial write to a fixed mutable view must
// preserve untouched owners; a full fixed-view replacement retires stale
// owners in that view; an explicit target is an exact whole-tree replacement
// and therefore retires every old view partition for that target identity.
type materializedRouteCleanupScope uint8

const (
	materializedRouteCleanupPreserve materializedRouteCleanupScope = iota
	materializedRouteCleanupSameView
	materializedRouteCleanupTargetWide
)

func (scope materializedRouteCleanupScope) validate() error {
	switch scope {
	case materializedRouteCleanupPreserve, materializedRouteCleanupSameView, materializedRouteCleanupTargetWide:
		return nil
	default:
		return fmt.Errorf("invalid materialized route cleanup scope %d", scope)
	}
}

// loadMaterializedRouteConfigAnchor proves the independent config commit
// frozen in a route receipt. The anchor may predate newer ref commits and may
// remain stable across idempotent rematerialization; it must nevertheless be
// reachable from the aggregate HEAD and contain the exact canonical config
// bytes named by ConfigSHA256.
func loadMaterializedRouteConfigAnchor(canonical *state.Store, head plumbing.Hash, commitText, wantSHA256 string) (*config.Config, error) {
	if canonical == nil || head.IsZero() || len(commitText) != 40 || len(wantSHA256) != sha256.Size*2 {
		return nil, errors.New("invalid materialized route config anchor")
	}
	commit := plumbing.NewHash(commitText)
	reachable, err := canonical.IsAncestor(commit, head)
	if err != nil || !reachable {
		return nil, errors.Join(err, fmt.Errorf("materialized route config commit %s is not reachable from canonical HEAD", commit))
	}
	body, exists, err := readCanonicalConfigBytesAt(canonical, commit)
	if err != nil || !exists {
		return nil, errors.Join(err, fmt.Errorf("materialized route config commit %s has no canonical config", commit))
	}
	digest := sha256.Sum256(body)
	if hex.EncodeToString(digest[:]) != wantSHA256 {
		return nil, errors.New("materialized route config commit does not match config SHA-256")
	}
	historical, err := config.Decode(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("decode materialized route historical config: %w", err)
	}
	canonicalBody, err := historical.Canonical()
	if err != nil || !bytes.Equal(canonicalBody, body) {
		return nil, errors.Join(err, errors.New("materialized route config anchor is not canonical"))
	}
	return historical, nil
}

func deriveMaterializedRouteReceipt(identity serving.MaterializedRouteIdentity, exactPath, payloadPath string) (serving.MaterializedRoute, error) {
	var result serving.MaterializedRoute
	exact, err := os.Open(exactPath)
	if err != nil {
		return result, err
	}
	payload, err := os.Open(payloadPath)
	if err != nil {
		return result, errors.Join(err, exact.Close())
	}
	result, deriveErr := serving.NewMaterializedRoute(identity, exact, payload)
	closeErr := errors.Join(exact.Close(), payload.Close())
	return result, errors.Join(deriveErr, closeErr)
}

// materializedRouteOwnerID is deliberately structural. Route segments permit
// hyphens, so concatenating kind/repo/arch would make distinct owners collide
// (for example repo=a-b,arch=c versus repo=a,arch=b-c).
type materializedRouteOwnerID struct {
	kind string
	repo string
	arch string
}

func (owner materializedRouteOwner) id() materializedRouteOwnerID {
	return materializedRouteOwnerID{kind: owner.kind, repo: owner.repo.ID, arch: owner.arch}
}

func (id materializedRouteOwnerID) String() string {
	return fmt.Sprintf("kind=%q repo=%q arch=%q", id.kind, id.repo, id.arch)
}

func (id materializedRouteOwnerID) tempToken() string {
	digest := sha256.Sum256([]byte(id.kind + "\x00" + id.repo + "\x00" + id.arch))
	return fmt.Sprintf("%x", digest[:12])
}

type materializedRouteCommitHookKey struct{}
type materializedRouteBeforeValidationHookKey struct{}

// withMaterializedRouteCommitHook is a deterministic test seam for the narrow
// crash window after the canonical Git commit and before transaction cleanup.
// Production contexts never carry this value.
func withMaterializedRouteCommitHook(ctx context.Context, hook func() error) context.Context {
	return context.WithValue(ctx, materializedRouteCommitHookKey{}, hook)
}

func materializedRouteCommitHookFromContext(ctx context.Context) func() error {
	if ctx == nil {
		return nil
	}
	hook, _ := ctx.Value(materializedRouteCommitHookKey{}).(func() error)
	return hook
}

// withMaterializedRouteBeforeValidationHook is a test-only seam at the exact
// boundary between physical reconciliation/hostability and receipt validation.
// It proves that an unexpected file appearing in that window is rejected and
// never promoted into the canonical expected manifest.
func withMaterializedRouteBeforeValidationHook(ctx context.Context, hook func() error) context.Context {
	return context.WithValue(ctx, materializedRouteBeforeValidationHookKey{}, hook)
}

func runMaterializedRouteBeforeValidationHook(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	hook, _ := ctx.Value(materializedRouteBeforeValidationHookKey{}).(func() error)
	if hook == nil {
		return nil
	}
	return hook()
}

// persistPreparedMaterializedRoutes persists receipts for the ordinary latest
// working tree. Exact APT/YUM input comes from the pre-reconcile deterministic
// materializers carried on each projection; an asset exact tree is rebuilt
// from its frozen ref because assets have no generated metadata.
func persistPreparedMaterializedRoutes(
	ctx context.Context,
	cfg *config.Config,
	canonical *state.Store,
	pool *repository.Store,
	view string,
	targetRoot string,
	servingBaseURL string,
	selected []viewLeaf,
	prepared preparedPublication,
	txDir string,
	values commonFlags,
	cleanupOverride ...materializedRouteCleanupScope,
) (string, bool, int, error) {
	source := materializeCanonicalSource{ID: view, Public: cfg.Views[view].Access == "public"}
	owners, err := completeSelectedMaterializedRouteOwners(cfg, canonical, source, selected)
	if err != nil {
		return "", false, 0, err
	}
	base := make(map[materializedRouteOwnerID]string)
	for _, owner := range owners {
		ownerID := owner.id()
		token := ownerID.tempToken()
		switch owner.kind {
		case "asset":
			payload := filepath.Join(txDir, "route-prepared-"+token+"-asset.tsv")
			if err := projectMaterializedRouteOwnerPayload(canonical, owner, payload); err != nil {
				return "", false, 0, err
			}
			base[ownerID] = payload
		case "apt", "yum":
			var candidates []string
			for _, projection := range prepared.projections {
				if projection.repo.ID != owner.repo.ID || projection.repo.Type != owner.kind || owner.kind == "yum" && projection.arch != owner.arch {
					continue
				}
				if projection.routeExactManifest == "" {
					return "", false, 0, fmt.Errorf("prepared %s route %s has no frozen exact manifest", owner.kind, ownerID)
				}
				candidates = append(candidates, projection.routeExactManifest)
			}
			if len(candidates) == 0 {
				return "", false, 0, fmt.Errorf("prepared %s route %s is absent", owner.kind, ownerID)
			}
			for _, candidate := range candidates[1:] {
				equal, err := manifestFilesEqual(candidates[0], candidate)
				if err != nil || !equal {
					return "", false, 0, errors.Join(err, fmt.Errorf("prepared physical route %s has conflicting exact manifests", ownerID))
				}
			}
			global := filepath.Join(txDir, "route-prepared-"+token+"-exact.tsv")
			if err := prefixManifestPaths(candidates[0], global, owner.relativeRoot); err != nil {
				return "", false, 0, err
			}
			base[ownerID] = global
		}
	}
	cleanupScope := materializedRouteCleanupPreserve
	if localServingSelectionIsFull(values) {
		cleanupScope = materializedRouteCleanupSameView
	}
	if len(cleanupOverride) > 1 {
		return "", false, 0, errors.New("materialized route cleanup override may be specified only once")
	}
	if len(cleanupOverride) == 1 {
		cleanupScope = cleanupOverride[0]
	}
	return persistMaterializedRouteOwners(ctx, cfg, canonical, pool, source, targetRoot, servingBaseURL, owners, base, txDir, values, cleanupScope)
}

// persistDirectMaterializedRoutes persists receipts for beta/stable/latest
// derived targets. selectedExactPath was assembled from frozen refs plus the
// metadata generated before exact reconciliation; it is never a live-tree
// scan. Snapshot trees are intentionally excluded because Nginx has no
// snapshot route surface. A snapshot exported onto an explicit exact target
// still reaches this function with target-wide cleanup so receipts for the
// replaced ordinary tree are retired without creating a snapshot receipt.
func persistDirectMaterializedRoutes(
	ctx context.Context,
	cfg *config.Config,
	canonical *state.Store,
	pool *repository.Store,
	source materializeCanonicalSource,
	targetRoot string,
	servingBaseURL string,
	selected []viewLeaf,
	selectedExactPath string,
	txDir string,
	values commonFlags,
	cleanupScope materializedRouteCleanupScope,
) (string, bool, int, error) {
	if source.Snapshot && cleanupScope == materializedRouteCleanupPreserve {
		return "", false, 0, nil
	}
	owners, err := completeSelectedMaterializedRouteOwners(cfg, canonical, source, selected)
	if err != nil {
		return "", false, 0, err
	}
	base := make(map[materializedRouteOwnerID]string, len(owners))
	for _, owner := range owners {
		ownerID := owner.id()
		filename := filepath.Join(txDir, "route-direct-"+ownerID.tempToken()+"-exact.tsv")
		if _, err := filterManifestFile(selectedExactPath, filename, func(entry manifest.Entry) bool {
			// Root-mapped assets expose only configured exact keys below their
			// physical repo.Path. Use the claim set for every kind so this finite
			// ownership can never widen to an unrelated sibling file.
			return materializedRouteCurrentClaimOwns(owner, entry.Path)
		}); err != nil {
			return "", false, 0, err
		}
		base[ownerID] = filename
	}
	return persistMaterializedRouteOwners(ctx, cfg, canonical, pool, source, targetRoot, servingBaseURL, owners, base, txDir, values, cleanupScope)
}

func completeSelectedMaterializedRouteOwners(cfg *config.Config, canonical *state.Store, source materializeCanonicalSource, selected []viewLeaf) ([]materializedRouteOwner, error) {
	if cfg == nil || canonical == nil || source.Snapshot {
		return nil, nil
	}
	view, exists := cfg.Views[source.ID]
	if !exists {
		return nil, fmt.Errorf("materialized route view %s is not configured", source.ID)
	}
	selectedSet := make(map[string]struct{}, len(selected))
	for _, leaf := range selected {
		selectedSet[servingLeafKey(leaf.repo.ID, leaf.os, leaf.arch)] = struct{}{}
	}
	var result []materializedRouteOwner
	for _, repo := range cfg.Repos {
		if !repo.IsActive() || !viewIncludesRepo(view, repo.ID) {
			continue
		}
		switch repo.Type {
		case "asset":
			owner := materializedRouteOwner{kind: "asset", repo: repo, arch: "all", relativeRoot: repo.Path}
			if repo.Asset == nil {
				return nil, fmt.Errorf("asset route %s has no projection", repo.ID)
			}
			if repo.AssetPublicRoot() == "." {
				for _, key := range repo.Asset.RootKeys {
					owner.claims = append(owner.claims, serving.MaterializedRouteClaim{Kind: serving.MaterializedRouteClaimExactFile, RelativeRoot: path.Join(repo.Path, key)})
				}
			} else {
				owner.claims = []serving.MaterializedRouteClaim{{Kind: serving.MaterializedRouteClaimPrefix, RelativeRoot: repo.Path}}
			}
			complete, selectedOwner, err := populateMaterializedRouteOwner(canonical, source, &owner, []routeCoordinate{{os: "all", arch: "all"}}, selectedSet, true)
			if err != nil {
				return nil, err
			}
			if complete && selectedOwner {
				result = append(result, owner)
			}
		case "apt":
			if repo.APT == nil {
				return nil, fmt.Errorf("APT route %s has no repository contract", repo.ID)
			}
			owner := materializedRouteOwner{
				kind: "apt", repo: repo, arch: "all", relativeRoot: repo.Path,
				claims: []serving.MaterializedRouteClaim{{Kind: serving.MaterializedRouteClaimPrefix, RelativeRoot: repo.Path}},
			}
			var coordinates []routeCoordinate
			for _, suite := range repo.APT.Suites {
				for _, arch := range repo.Arches {
					coordinates = append(coordinates, routeCoordinate{os: suite, arch: arch})
				}
			}
			complete, selectedOwner, err := populateMaterializedRouteOwner(canonical, source, &owner, coordinates, selectedSet, false)
			if err != nil {
				return nil, err
			}
			if complete && selectedOwner {
				result = append(result, owner)
			}
		case "yum":
			if repo.YUM == nil {
				return nil, fmt.Errorf("YUM route %s has no repository contract", repo.ID)
			}
			for _, arch := range repo.Arches {
				root, err := repo.PathForArch(arch)
				if err != nil {
					return nil, err
				}
				owner := materializedRouteOwner{
					kind: "yum", repo: repo, arch: arch, relativeRoot: root,
					claims: []serving.MaterializedRouteClaim{
						{Kind: serving.MaterializedRouteClaimPrefix, RelativeRoot: root},
						{Kind: serving.MaterializedRouteClaimGeneration, RelativeRoot: "_sow/v1/g", Leaf: root},
					},
				}
				var coordinates []routeCoordinate
				for _, osName := range repo.OSSelectorValues() {
					coordinates = append(coordinates, routeCoordinate{os: osName, arch: arch})
					owner.claims = append(owner.claims, serving.MaterializedRouteClaim{
						Kind:         serving.MaterializedRouteClaimExactFile,
						RelativeRoot: serving.MirrorlistPath(source.ID, repo.ID, osName, arch),
					})
				}
				// Every configured YUM mirrorlist is emitted by the Nginx contract,
				// so a route is receipt-eligible only when every coordinate has a
				// canonical ref and was rebuilt by this selected operation.
				complete, selectedOwner, err := populateMaterializedRouteOwner(canonical, source, &owner, coordinates, selectedSet, true)
				if err != nil {
					return nil, err
				}
				if complete && selectedOwner {
					result = append(result, owner)
				}
			}
		}
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := result[i].id(), result[j].id()
		if left.kind != right.kind {
			return left.kind < right.kind
		}
		if left.repo != right.repo {
			return left.repo < right.repo
		}
		return left.arch < right.arch
	})
	return result, nil
}

// materializedRoutePhysicalClosureLeaves expands logical selectors to the
// smallest complete physical ownership units an ordinary Nginx route can
// expose. It never changes canonical refs or includes another repo/YUM arch:
// APT closes to every current suite/arch ref in the touched repo, YUM closes
// to every configured OS ref for the touched repo+arch, and assets remain one
// all/all leaf. Missing mandatory YUM/asset coordinates fail before callers
// start a selected-set mutation.
func materializedRoutePhysicalClosureLeaves(cfg *config.Config, canonical *state.Store, source materializeCanonicalSource, selected []viewLeaf) ([]viewLeaf, error) {
	if source.Snapshot || len(selected) == 0 {
		return append([]viewLeaf(nil), selected...), nil
	}
	touched := make(map[materializedRouteOwnerID]struct{})
	for _, leaf := range selected {
		repo, exists := cfg.RepoByName(leaf.repo.ID)
		if !exists {
			return nil, fmt.Errorf("selected route repository %s is absent from canonical configuration", leaf.repo.ID)
		}
		arch := "all"
		if repo.Type == "yum" {
			arch = leaf.arch
		}
		touched[materializedRouteOwnerID{kind: repo.Type, repo: repo.ID, arch: arch}] = struct{}{}
	}
	owners, err := completeSelectedMaterializedRouteOwners(cfg, canonical, source, selected)
	if err != nil {
		return nil, err
	}
	complete := make(map[materializedRouteOwnerID]materializedRouteOwner, len(owners))
	for _, owner := range owners {
		complete[owner.id()] = owner
	}
	ids := make([]materializedRouteOwnerID, 0, len(touched))
	for id := range touched {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	var result []viewLeaf
	for _, id := range ids {
		owner, exists := complete[id]
		if !exists {
			return nil, fmt.Errorf("selected physical route owner %s has an incomplete canonical ref vector", id)
		}
		for _, leaf := range owner.leaves {
			result = append(result, viewLeaf{repo: owner.repo, os: leaf.os, arch: leaf.arch})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		left := servingLeafKey(result[i].repo.ID, result[i].os, result[i].arch)
		right := servingLeafKey(result[j].repo.ID, result[j].os, result[j].arch)
		return left < right
	})
	return result, nil
}

type routeCoordinate struct{ os, arch string }

func populateMaterializedRouteOwner(canonical *state.Store, source materializeCanonicalSource, owner *materializedRouteOwner, coordinates []routeCoordinate, selected map[string]struct{}, requireEveryRef bool) (complete, selectedOwner bool, resultErr error) {
	complete = true
	for _, coordinate := range coordinates {
		ref, canonicalPath, err := source.leaf(owner.repo.ID, coordinate.os, coordinate.arch)
		if err != nil {
			return false, false, err
		}
		commit, exists, err := canonical.Ref(ref)
		if err != nil {
			return false, false, err
		}
		_, selectedLeaf := selected[servingLeafKey(owner.repo.ID, coordinate.os, coordinate.arch)]
		selectedOwner = selectedOwner || selectedLeaf
		if !exists {
			if requireEveryRef {
				complete = false
			}
			continue
		}
		blob, blobExists, err := canonical.BlobIdentityAt(commit, canonicalPath)
		if err != nil || !blobExists {
			return false, false, errors.Join(err, fmt.Errorf("materialized route ref %s lacks canonical manifest %s", ref, canonicalPath))
		}
		owner.leaves = append(owner.leaves, materializedRouteOwnerLeaf{
			os: coordinate.os, arch: coordinate.arch, ref: ref, commit: commit, canonicalPath: canonicalPath,
			manifestBlob: blob.Hash, manifestSize: blob.Size,
		})
	}
	if len(owner.leaves) == 0 {
		complete = false
	}
	return complete, selectedOwner, nil
}

func persistMaterializedRouteOwners(
	ctx context.Context,
	cfg *config.Config,
	canonical *state.Store,
	pool *repository.Store,
	source materializeCanonicalSource,
	targetPath string,
	servingBaseURL string,
	owners []materializedRouteOwner,
	baseExact map[materializedRouteOwnerID]string,
	txDir string,
	values commonFlags,
	cleanupScope materializedRouteCleanupScope,
) (string, bool, int, error) {
	if err := cleanupScope.validate(); err != nil {
		return "", false, 0, err
	}
	if len(owners) == 0 && cleanupScope == materializedRouteCleanupPreserve {
		return "", false, 0, nil
	}
	configSHA, err := cfg.CanonicalSHA256()
	if err != nil {
		return "", false, 0, err
	}
	configCommit, err := canonical.HeadHash()
	if err != nil || configCommit.IsZero() {
		return "", false, 0, errors.Join(err, errors.New("materialized route has no canonical config commit"))
	}
	if _, err := loadMaterializedRouteConfigAnchor(canonical, configCommit, configCommit.String(), configSHA); err != nil {
		return "", false, 0, fmt.Errorf("materialized route requires the active config to be committed by sow init: %w", err)
	}
	targetSHA, err := materializationTargetSHA256(targetPath)
	if err != nil {
		return "", false, 0, err
	}
	var lifecycle canonicalServingLifecycle
	var installedGenerationIDs map[string]struct{}
	for _, owner := range owners {
		if owner.kind != "yum" {
			continue
		}
		lifecycle, err = loadCanonicalServingLifecycle(canonical)
		if err != nil {
			return "", false, 0, err
		}
		ids, exists, listErr := serving.ListInstalledGenerationIDsIfPresent(cfg.Root, targetPath)
		if listErr != nil || !exists {
			return "", false, 0, errors.Join(listErr, errors.New("materialized YUM route target has no installed generation root"))
		}
		installedGenerationIDs = make(map[string]struct{}, len(ids))
		for _, id := range ids {
			installedGenerationIDs[id] = struct{}{}
		}
		break
	}
	expectations := make([]materializedRouteExpected, 0, len(owners))
	for index, owner := range owners {
		ownerID := owner.id()
		base, exists := baseExact[ownerID]
		if !exists || base == "" {
			return "", false, 0, fmt.Errorf("materialized route %s has no frozen exact input", ownerID)
		}
		routeDir := filepath.Join(txDir, fmt.Sprintf("route-ledger-%03d", index))
		if err := os.Mkdir(routeDir, 0o700); err != nil {
			return "", false, 0, err
		}
		payload := filepath.Join(routeDir, "payload-current.tsv")
		if err := projectMaterializedRouteOwnerPayload(canonical, owner, payload); err != nil {
			return "", false, 0, err
		}
		currentExact := filepath.Join(routeDir, "exact-current.tsv")
		if _, err := filterManifestFile(base, currentExact, func(entry manifest.Entry) bool {
			return materializedRouteCurrentClaimOwns(owner, entry.Path)
		}); err != nil {
			return "", false, 0, err
		}
		currentPayload := filepath.Join(routeDir, "payload-exposed.tsv")
		if _, err := filterManifestFile(payload, currentPayload, func(entry manifest.Entry) bool {
			return materializedRouteCurrentClaimOwns(owner, entry.Path)
		}); err != nil {
			return "", false, 0, err
		}
		exactParts := []string{currentExact}
		payloadParts := []string{currentPayload}
		servingTargetID := ""
		if owner.kind == "yum" {
			target, err := localServingTargetIdentity(cfg, source.ID, targetPath, servingBaseURL)
			if err != nil {
				return "", false, 0, err
			}
			servingTargetID = target.ID
			yumExact, yumPayload, err := materializedYUMServingExpected(cfg, canonical, lifecycle, source.ID, targetPath, servingBaseURL, owner, routeDir, configSHA, installedGenerationIDs)
			if err != nil {
				return "", false, 0, err
			}
			exactParts = append(exactParts, yumExact...)
			payloadParts = append(payloadParts, yumPayload...)
		}
		exact := filepath.Join(routeDir, "exact.tsv")
		if err := mergePublicationManifests(exactParts, exact, routeDir); err != nil {
			return "", false, 0, err
		}
		finalPayload := filepath.Join(routeDir, "payload.tsv")
		if err := mergePublicationManifests(payloadParts, finalPayload, routeDir); err != nil {
			return "", false, 0, err
		}
		refs := make([]serving.MaterializedRouteRef, 0, len(owner.leaves))
		for _, leaf := range owner.leaves {
			refs = append(refs, serving.MaterializedRouteRef{
				Name: leaf.ref.String(), Commit: leaf.commit.String(), ManifestBlob: leaf.manifestBlob.String(), ManifestSize: leaf.manifestSize,
			})
		}
		identity := serving.MaterializedRouteIdentity{
			Kind: owner.kind, View: source.ID, Source: source.ID, TargetSHA256: targetSHA,
			Claims: owner.claims, ConfigSHA256: configSHA, ConfigCommit: configCommit.String(), ServingTargetID: servingTargetID,
			Repo: owner.repo.ID, OS: "all", Arch: owner.arch, Refs: refs,
		}
		receipt, err := deriveMaterializedRouteReceipt(identity, exact, finalPayload)
		if err != nil {
			return "", false, 0, err
		}
		receiptPath, err := serving.MaterializedRouteReceiptStatePath(receipt)
		if err != nil {
			return "", false, 0, err
		}
		existingBody, existing, err := readCanonicalBytesAt(canonical, configCommit, receiptPath, materializedRouteReceiptMaxBytes)
		if err != nil {
			return "", false, 0, err
		}
		if existing {
			previous, err := serving.DecodeMaterializedRoute(existingBody)
			if err != nil {
				return "", false, 0, fmt.Errorf("decode existing materialized route receipt %s: %w", receiptPath, err)
			}
			if sameMaterializedRouteFrozenInputs(previous, receipt) {
				if _, err := loadMaterializedRouteConfigAnchor(canonical, configCommit, previous.ConfigCommit, configSHA); err != nil {
					return "", false, 0, fmt.Errorf("reuse materialized route config anchor: %w", err)
				}
				identity.ConfigCommit = previous.ConfigCommit
				receipt, err = deriveMaterializedRouteReceipt(identity, exact, finalPayload)
				if err != nil {
					return "", false, 0, err
				}
			}
		}
		expectations = append(expectations, materializedRouteExpected{receipt: receipt, exactPath: exact, payloadPath: finalPayload})
	}

	if err := serving.ValidateWorkerTraversableAbsoluteDirectory(targetPath); err != nil {
		return "", false, 0, fmt.Errorf("materialized route target is not Nginx-worker traversable: %w", err)
	}
	bound, err := openBoundMaterializedRouteTarget(targetPath)
	if err != nil {
		return "", false, 0, err
	}
	defer bound.Close()
	if err := runMaterializedRouteBeforeValidationHook(ctx); err != nil {
		return "", false, 0, fmt.Errorf("materialized route before-validation hook: %w", err)
	}
	options := serving.InstallOptions{Workers: values.workers, ChunkEntries: values.chunk, TempDir: filepath.Join(cfg.StatePath(), "tmp")}
	for _, expected := range expectations {
		if err := serving.ValidateMaterializedRouteRoot(ctx, pool, bound.root, expected.receipt, expected.exactPath, expected.payloadPath, options); err != nil {
			return "", false, 0, fmt.Errorf("validate materialized route %s/%s/%s: %w", expected.receipt.Repo, expected.receipt.OS, expected.receipt.Arch, err)
		}
	}
	if err := bound.Verify(); err != nil {
		return "", false, 0, err
	}

	stageDir := filepath.Join(txDir, "route-ledger-stage")
	if err := os.Mkdir(stageDir, 0o700); err != nil {
		return "", false, 0, err
	}
	staged := make(map[string]string, len(expectations)*3)
	desired := make(map[string]struct{}, len(expectations)*3)
	for _, expected := range expectations {
		paths, err := stageMaterializedRouteLedger(stageDir, expected.receipt, expected.exactPath, expected.payloadPath)
		if err != nil {
			return "", false, 0, err
		}
		for canonicalPath, stagePath := range paths {
			if _, duplicate := staged[canonicalPath]; duplicate {
				return "", false, 0, fmt.Errorf("duplicate materialized route ledger path %s", canonicalPath)
			}
			staged[canonicalPath] = stagePath
			desired[canonicalPath] = struct{}{}
		}
	}
	deletePaths, err := materializedRouteLedgerCleanupPaths(canonical, targetSHA, source.ID, desired, stageDir, cleanupScope)
	if err != nil {
		return "", false, 0, err
	}
	if len(staged) == 0 && len(deletePaths) == 0 {
		if err := bound.Verify(); err != nil {
			return "", false, 0, err
		}
		return "", false, 0, nil
	}
	refUpdates, err := materializedRouteRefBarriers(expectations)
	if err != nil {
		return "", false, 0, err
	}
	if err := bound.Verify(); err != nil {
		return "", false, 0, err
	}
	commit, changed, err := applyCanonicalConfig(ctx, cfg, canonical, "materialize-route-ledger", "sow: admit exact local Nginx routes", staged, refUpdates, state.ApplyOptions{
		DeletePaths: deletePaths, AfterCommit: materializedRouteCommitHookFromContext(ctx),
	})
	if err != nil {
		return commit.String(), changed, 0, err
	}
	if err := bound.Verify(); err != nil {
		return commit.String(), changed, 0, fmt.Errorf("materialized route target changed after receipt commit: %w", err)
	}
	if err := serving.ValidateWorkerTraversableAbsoluteDirectory(targetPath); err != nil {
		return commit.String(), changed, 0, fmt.Errorf("materialized route target lost Nginx-worker traversability after receipt commit: %w", err)
	}
	for _, expected := range expectations {
		if err := serving.ValidateMaterializedRouteRoot(ctx, pool, bound.root, expected.receipt, expected.exactPath, expected.payloadPath, options); err != nil {
			return commit.String(), changed, 0, fmt.Errorf("materialized route %s/%s/%s changed after receipt commit: %w", expected.receipt.Repo, expected.receipt.OS, expected.receipt.Arch, err)
		}
	}
	return commit.String(), changed, len(expectations), nil
}

// sameMaterializedRouteFrozenInputs permits an older ConfigCommit anchor to be
// reused only for a byte-for-byte identical input state. ConfigCommit and the
// derived ContentSHA256 are the only fields intentionally excluded: if refs,
// claims, or either exact manifest changes, the current HEAD must become the
// new lifecycle/config anchor so historical fsck can replay that state.
func sameMaterializedRouteFrozenInputs(left, right serving.MaterializedRoute) bool {
	return left.Schema == right.Schema && left.ID == right.ID && left.Kind == right.Kind &&
		left.View == right.View && left.Source == right.Source && left.TargetSHA256 == right.TargetSHA256 &&
		left.ConfigSHA256 == right.ConfigSHA256 && left.Repo == right.Repo && left.OS == right.OS &&
		left.Arch == right.Arch && left.ServingTargetID == right.ServingTargetID && left.ExactManifestSHA256 == right.ExactManifestSHA256 &&
		left.PayloadManifestSHA256 == right.PayloadManifestSHA256 && slices.Equal(left.Claims, right.Claims) &&
		slices.Equal(left.Refs, right.Refs)
}

func materializedRouteRefBarriers(expectations []materializedRouteExpected) ([]state.RefUpdate, error) {
	byName := make(map[string]plumbing.Hash)
	for _, expected := range expectations {
		for _, ref := range expected.receipt.Refs {
			commit := plumbing.NewHash(ref.Commit)
			if previous, exists := byName[ref.Name]; exists && previous != commit {
				return nil, fmt.Errorf("materialized route ref %s has conflicting barriers %s and %s", ref.Name, previous, commit)
			}
			byName[ref.Name] = commit
		}
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]state.RefUpdate, 0, len(names))
	for _, name := range names {
		commit := byName[name]
		result = append(result, state.RefUpdate{Name: plumbing.ReferenceName(name), Expected: commit, Target: commit})
	}
	return result, nil
}

func projectMaterializedRouteOwnerPayload(canonical *state.Store, owner materializedRouteOwner, destination string) (resultErr error) {
	inputs := make([]views.ProjectionInput, 0, len(owner.leaves))
	readers := make([]io.ReadCloser, 0, len(owner.leaves))
	defer func() {
		for _, reader := range readers {
			resultErr = errors.Join(resultErr, reader.Close())
		}
	}()
	for _, leaf := range owner.leaves {
		reader, err := canonical.OpenPathAt(leaf.commit, leaf.canonicalPath)
		if err != nil {
			return err
		}
		readers = append(readers, reader)
		inputs = append(inputs, views.ProjectionInput{Label: leaf.ref.String(), Reader: reader})
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, _, projectErr := views.ProjectManifest(inputs, output)
	closeErr := errors.Join(output.Sync(), output.Close())
	for _, reader := range readers {
		closeErr = errors.Join(closeErr, reader.Close())
	}
	readers = nil
	return errors.Join(projectErr, closeErr)
}

func materializedRouteCurrentClaimOwns(owner materializedRouteOwner, candidate string) bool {
	for _, claim := range owner.claims {
		switch claim.Kind {
		case serving.MaterializedRouteClaimPrefix:
			if pathWithin(candidate, claim.RelativeRoot) {
				return true
			}
		case serving.MaterializedRouteClaimExactFile:
			if candidate == claim.RelativeRoot && !strings.HasPrefix(candidate, "_sow/v1/mirrorlist/") {
				return true
			}
		}
	}
	return false
}

func materializedYUMServingExpected(cfg *config.Config, canonical *state.Store, lifecycle canonicalServingLifecycle, view, targetRoot, servingBaseURL string, owner materializedRouteOwner, routeDir, configSHA string, generationCandidates map[string]struct{}) ([]string, []string, error) {
	target, err := localServingTargetIdentity(cfg, view, targetRoot, servingBaseURL)
	if err != nil {
		return nil, nil, err
	}
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		return nil, nil, errors.Join(err, errors.New("canonical HEAD is unavailable for YUM serving receipt"))
	}
	return materializedYUMServingExpectedForTargetAt(canonical, head, lifecycle, target, view, owner, routeDir, configSHA, generationCandidates)
}

func materializedYUMServingExpectedForTargetAt(canonical *state.Store, commit plumbing.Hash, lifecycle canonicalServingLifecycle, target serving.TargetIdentity, view string, owner materializedRouteOwner, routeDir, configSHA string, generationCandidates map[string]struct{}) ([]string, []string, error) {
	if canonical == nil || commit.IsZero() {
		return nil, nil, errors.New("historical YUM serving receipt input is unavailable")
	}
	if err := target.Validate(view); err != nil {
		return nil, nil, fmt.Errorf("validate YUM serving target identity: %w", err)
	}
	leaves := make(map[string]materializedRouteOwnerLeaf, len(owner.leaves))
	for _, leaf := range owner.leaves {
		leaves[leaf.os] = leaf
	}
	channels := make(map[string]serving.Channel)
	for _, record := range lifecycle.Channels {
		channel := record.Channel
		if channel.TargetID != target.ID || channel.View != view || channel.Repo != owner.repo.ID || channel.Arch != owner.arch {
			continue
		}
		leaf, expected := leaves[channel.OS]
		if !expected {
			return nil, nil, fmt.Errorf("canonical channel %s widens materialized route %s", record.Path, owner.id())
		}
		if channel.RefCommit != leaf.commit.String() || channel.ConfigSHA256 != configSHA || channel.LegacyRoot != owner.relativeRoot || channel.TargetRoot != target.Root || channel.BaseURL != target.BaseURL {
			return nil, nil, fmt.Errorf("canonical channel %s differs from materialized route identity", record.Path)
		}
		if _, duplicate := channels[channel.OS]; duplicate {
			return nil, nil, fmt.Errorf("duplicate canonical channel for materialized route %s os=%q", owner.id(), channel.OS)
		}
		channels[channel.OS] = channel
	}
	var exactParts, payloadParts []string
	generationPaths := make(map[string]canonicalServingGeneration)
	oses := make([]string, 0, len(leaves))
	for osName := range leaves {
		oses = append(oses, osName)
	}
	sort.Strings(oses)
	for index, osName := range oses {
		channel, exists := channels[osName]
		if !exists {
			return nil, nil, fmt.Errorf("materialized YUM route %s lacks canonical mirrorlist %s", owner.id(), osName)
		}
		body, err := channel.MirrorlistBody()
		if err != nil {
			return nil, nil, err
		}
		pointer := filepath.Join(routeDir, fmt.Sprintf("mirrorlist-%03d.tsv", index))
		if err := writeManifestEntryForBytes(pointer, channel.MirrorlistPath, body); err != nil {
			return nil, nil, err
		}
		exactParts = append(exactParts, pointer)
		retained, err := serving.RetainedGenerationManifestPaths(channel)
		if err != nil {
			return nil, nil, err
		}
		for _, canonicalPath := range retained {
			generation, exists := lifecycle.Generations[canonicalPath]
			if !exists {
				return nil, nil, fmt.Errorf("canonical retained generation %s is missing", canonicalPath)
			}
			generationPaths[canonicalPath] = generation
		}
	}
	paths := make([]string, 0, len(generationPaths))
	activeGenerationIDs := make(map[string]struct{}, len(generationPaths))
	for canonicalPath := range generationPaths {
		paths = append(paths, canonicalPath)
		activeGenerationIDs[generationPaths[canonicalPath].Generation.ID] = struct{}{}
	}
	sort.Strings(paths)
	for index, canonicalPath := range paths {
		record := generationPaths[canonicalPath]
		staged := filepath.Join(routeDir, fmt.Sprintf("generation-%03d-canonical.tsv", index))
		exists, err := stageCanonicalServingManifestAt(canonical, commit, record.Generation, staged)
		if err != nil || !exists {
			return nil, nil, errors.Join(err, fmt.Errorf("stage canonical retained generation %s", canonicalPath))
		}
		global := filepath.Join(routeDir, fmt.Sprintf("generation-%03d-exact.tsv", index))
		prefix := path.Join("_sow/v1/g", record.Generation.ID)
		if err := prefixManifestPaths(staged, global, prefix); err != nil {
			return nil, nil, err
		}
		exactParts = append(exactParts, global)
		payload := filepath.Join(routeDir, fmt.Sprintf("generation-%03d-payload.tsv", index))
		if _, err := filterManifestFile(global, payload, func(entry manifest.Entry) bool {
			return strings.HasPrefix(entry.Path, prefix+"/"+owner.relativeRoot+"/Packages/") && strings.HasSuffix(entry.Path, ".rpm")
		}); err != nil {
			return nil, nil, err
		}
		payloadParts = append(payloadParts, payload)
	}
	retiredIDs := make([]string, 0, len(generationCandidates))
	for id := range generationCandidates {
		if _, active := activeGenerationIDs[id]; !active {
			retiredIDs = append(retiredIDs, id)
		}
	}
	sort.Strings(retiredIDs)
	allowedOS := make(map[string]struct{}, len(owner.leaves))
	for _, leaf := range owner.leaves {
		allowedOS[leaf.os] = struct{}{}
	}
	for _, id := range retiredIDs {
		var matched *canonicalServingRetiredGeneration
		for _, record := range lifecycle.Retired {
			generation := record.Retired.Generation
			if generation.ID != id || generation.View != view || generation.Repo != owner.repo.ID || generation.Arch != owner.arch || generation.LegacyRoot != owner.relativeRoot {
				continue
			}
			if _, allowed := allowedOS[generation.OS]; !allowed {
				continue
			}
			copy := record
			if matched != nil && matched.Retired.Generation != copy.Retired.Generation {
				return nil, nil, fmt.Errorf("ambiguous retired YUM generation %s for route %s", id, owner.id())
			}
			matched = &copy
		}
		// The candidate set can be target-wide and therefore contain generation
		// IDs owned by another repo/arch. Those owners validate the same physical
		// directory independently; only a matching canonical tombstone belongs in
		// this route's exact capability.
		if matched == nil {
			continue
		}
		staged := filepath.Join(routeDir, fmt.Sprintf("retired-generation-%s-canonical.tsv", id))
		source, err := canonical.OpenPathAt(commit, matched.ManifestPath)
		if err != nil {
			return nil, nil, fmt.Errorf("stage retired YUM generation %s: %w", id, err)
		}
		copyErr := manifest.AtomicCopy(staged, source, 0o600)
		closeErr := source.Close()
		if copyErr != nil || closeErr != nil {
			return nil, nil, errors.Join(copyErr, closeErr)
		}
		global := filepath.Join(routeDir, fmt.Sprintf("retired-generation-%s-exact.tsv", id))
		if err := prefixManifestPaths(staged, global, path.Join("_sow/v1/g", id)); err != nil {
			return nil, nil, err
		}
		exactParts = append(exactParts, global)
	}
	return exactParts, payloadParts, nil
}

// materializedYUMGenerationIDsFromManifest extracts only generation IDs whose
// exact entries belong to one physical YUM owner. It is used at read admission
// to re-derive a target-specific retired set from the receipt, while every byte
// still comes from an active ledger or canonical retirement witness.
func materializedYUMGenerationIDsFromManifest(filename, legacyRoot string) (map[string]struct{}, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	result := make(map[string]struct{})
	reader := manifest.NewReader(file)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return result, nil
		}
		if err != nil {
			return nil, err
		}
		_, id, _, ok := splitNginxYUMGenerationPath(entry.Path, legacyRoot)
		if ok {
			result[id] = struct{}{}
		}
	}
}

func writeManifestEntryForBytes(destination, relative string, body []byte) error {
	if relative == "" || path.Clean(relative) != relative || path.IsAbs(relative) {
		return fmt.Errorf("unsafe materialized route exact file %q", relative)
	}
	digest := sha256.Sum256(body)
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	writeErr := manifest.WriteEntry(file, manifest.Entry{Path: relative, Size: int64(len(body)), SHA256: digest})
	return errors.Join(writeErr, file.Sync(), file.Close())
}

func prefixManifestPaths(sourcePath, destinationPath, prefix string) (resultErr error) {
	prefix = strings.TrimSuffix(filepath.ToSlash(prefix), "/")
	if prefix == "" || prefix == "." || path.Clean(prefix) != prefix || path.IsAbs(prefix) {
		return fmt.Errorf("unsafe materialized route manifest prefix %q", prefix)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, source.Close()) }()
	destination, err := os.OpenFile(destinationPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	reader := manifest.NewReader(source)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			_ = destination.Close()
			return err
		}
		entry.Path = path.Join(prefix, entry.Path)
		if err := manifest.WriteEntry(destination, entry); err != nil {
			_ = destination.Close()
			return err
		}
	}
	return errors.Join(destination.Sync(), destination.Close())
}

func manifestFilesEqual(leftPath, rightPath string) (bool, error) {
	left, err := os.Open(leftPath)
	if err != nil {
		return false, err
	}
	right, err := os.Open(rightPath)
	if err != nil {
		left.Close()
		return false, err
	}
	leftHasher, rightHasher := sha256.New(), sha256.New()
	leftBytes, leftErr := io.Copy(leftHasher, left)
	rightBytes, rightErr := io.Copy(rightHasher, right)
	closeErr := errors.Join(left.Close(), right.Close())
	if leftErr != nil || rightErr != nil || closeErr != nil {
		return false, errors.Join(leftErr, rightErr, closeErr)
	}
	return leftBytes == rightBytes && string(leftHasher.Sum(nil)) == string(rightHasher.Sum(nil)), nil
}

type boundMaterializedRouteTarget struct {
	path     string
	root     *os.Root
	identity os.FileInfo
}

// preflightMaterializedRouteTargetHostability validates the deepest existing
// ancestor of a target that materialization may create. It is deliberately
// read-only and runs before any state or payload mutation. Missing descendants
// are allowed because the installer creates them with the product-owned public
// directory policy; the completed target is capability-bound and revalidated
// by openBoundMaterializedRouteTarget before a receipt can be committed.
func preflightMaterializedRouteTargetHostability(targetPath string) error {
	abs, err := filepath.Abs(filepath.Clean(targetPath))
	if err != nil {
		return err
	}
	current := abs
	for {
		info, err := os.Lstat(current)
		switch {
		case err == nil:
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("materialization target existing ancestor %s is a symlink; Nginx routes require a real symlink-free directory chain", current)
			}
			if !info.IsDir() {
				return fmt.Errorf("materialization target existing ancestor %s is not a directory", current)
			}
			if err := serving.ValidateWorkerTraversableAbsoluteDirectory(current); err != nil {
				return fmt.Errorf("materialization target existing ancestor %s is not a symlink-free Nginx-worker traversable directory: %w", current, err)
			}
			return nil
		case errors.Is(err, os.ErrNotExist):
			parent := filepath.Dir(current)
			if parent == current {
				return errors.New("materialization target has no existing directory ancestor")
			}
			current = parent
		default:
			return fmt.Errorf("inspect materialization target existing ancestor %s: %w", current, err)
		}
	}
}

func openBoundMaterializedRouteTarget(target string) (*boundMaterializedRouteTarget, error) {
	abs, err := filepath.Abs(filepath.Clean(target))
	if err != nil {
		return nil, err
	}
	if err := serving.ValidateWorkerTraversableAbsoluteDirectory(abs); err != nil {
		return nil, fmt.Errorf("materialized route target is not Nginx-worker traversable: %w", err)
	}
	before, err := os.Lstat(abs)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.Join(err, errors.New("materialized route target is not a real directory"))
	}
	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, err
	}
	opened, statErr := root.Stat(".")
	after, lstatErr := os.Lstat(abs)
	if statErr != nil || lstatErr != nil || !os.SameFile(before, opened) || !os.SameFile(before, after) {
		return nil, errors.Join(statErr, lstatErr, root.Close(), errors.New("materialized route target changed while binding"))
	}
	return &boundMaterializedRouteTarget{path: abs, root: root, identity: opened}, nil
}

func (target *boundMaterializedRouteTarget) Verify() error {
	if target == nil || target.root == nil || target.identity == nil {
		return errors.New("materialized route target binding is unavailable")
	}
	bound, boundErr := target.root.Stat(".")
	current, pathErr := os.Lstat(target.path)
	if boundErr != nil || pathErr != nil || !bound.IsDir() || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(target.identity, bound) || !os.SameFile(target.identity, current) {
		return errors.Join(boundErr, pathErr, errors.New("materialized route target identity changed"))
	}
	if err := serving.ValidateWorkerTraversableAbsoluteDirectory(target.path); err != nil {
		return fmt.Errorf("materialized route target is not Nginx-worker traversable: %w", err)
	}
	return nil
}

func (target *boundMaterializedRouteTarget) Close() error {
	if target == nil || target.root == nil {
		return nil
	}
	return target.root.Close()
}

// preflightMaterializedRouteCleanup validates every receipt triple that a
// replacement may retire. Callers use this before payload/metadata mutation so
// an orphan, unknown future record, or corrupt cross-view ledger fails closed
// while the explicit target still contains its prior exact tree.
func preflightMaterializedRouteCleanup(canonical *state.Store, targetPath, view, stageDir string, scope materializedRouteCleanupScope) error {
	if err := scope.validate(); err != nil {
		return err
	}
	if scope == materializedRouteCleanupPreserve {
		return nil
	}
	if err := os.MkdirAll(stageDir, 0o700); err != nil {
		return err
	}
	targetSHA, err := materializationTargetSHA256(targetPath)
	if err != nil {
		return err
	}
	_, err = materializedRouteLedgerCleanupPaths(canonical, targetSHA, view, nil, stageDir, scope)
	return err
}

func materializedRouteLedgerCleanupPaths(canonical *state.Store, targetSHA, view string, desired map[string]struct{}, stageDir string, scope materializedRouteCleanupScope) ([]string, error) {
	if err := scope.validate(); err != nil {
		return nil, err
	}
	if scope == materializedRouteCleanupPreserve {
		return nil, nil
	}
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		return nil, errors.Join(err, errors.New("canonical HEAD is unavailable for route ledger replacement"))
	}
	var ledgers []materializedRouteLedger
	switch scope {
	case materializedRouteCleanupSameView:
		ledgers, err = loadMaterializedRouteLedgersAt(canonical, head, targetSHA, view, stageDir)
	case materializedRouteCleanupTargetWide:
		ledgers, err = loadTargetMaterializedRouteLedgersAt(canonical, head, targetSHA, stageDir)
	}
	if err != nil {
		return nil, err
	}
	var result []string
	for _, ledger := range ledgers {
		paths := []string{ledger.ReceiptPath, ledger.ExactCanonicalPath, ledger.PayloadCanonicalPath}
		_, keepReceipt := desired[ledger.ReceiptPath]
		_, keepExact := desired[ledger.ExactCanonicalPath]
		_, keepPayload := desired[ledger.PayloadCanonicalPath]
		if keepReceipt || keepExact || keepPayload {
			if !keepReceipt || !keepExact || !keepPayload {
				return nil, fmt.Errorf("desired materialized-route ledger %s is not a complete triple", ledger.ReceiptPath)
			}
			continue
		}
		result = append(result, paths...)
	}
	sort.Strings(result)
	return result, nil
}

// loadTargetMaterializedRouteLedgersAt enumerates every view partition below
// one target. It rejects any path that is not a known ledger member, then
// validates each partition as complete receipt/exact/payload triples before a
// target-wide replacement is allowed to delete anything.
func loadTargetMaterializedRouteLedgersAt(canonical *state.Store, commit plumbing.Hash, targetSHA, stageDir string) ([]materializedRouteLedger, error) {
	prefix, err := serving.MaterializedRouteTargetStatePrefix(targetSHA)
	if err != nil {
		return nil, err
	}
	namespaceRoot := strings.TrimSuffix(prefix, "/")
	if _, exists, err := canonical.BlobIdentityAt(commit, namespaceRoot); err != nil {
		return nil, err
	} else if exists {
		return nil, fmt.Errorf("materialized route target namespace root is a blob: %s", namespaceRoot)
	}
	files, err := canonical.ListFilesAt(commit, prefix)
	if err != nil {
		return nil, err
	}
	partitions := make(map[string][]string)
	for _, name := range files {
		if !strings.HasPrefix(name, prefix) || !serving.IsMaterializedRouteLedgerStatePath(name) {
			return nil, fmt.Errorf("orphan or unknown materialized route ledger path %s", name)
		}
		relative := strings.TrimPrefix(name, prefix)
		parts := strings.Split(relative, "/")
		if len(parts) != 3 || parts[1] != "routes" {
			return nil, fmt.Errorf("orphan or unknown materialized route ledger path %s", name)
		}
		partitions[parts[0]] = append(partitions[parts[0]], name)
	}
	views := make([]string, 0, len(partitions))
	for partitionView := range partitions {
		views = append(views, partitionView)
	}
	sort.Strings(views)
	var result []materializedRouteLedger
	for _, partitionView := range views {
		partitionStage := filepath.Join(stageDir, "cleanup-"+partitionView)
		if err := os.MkdirAll(partitionStage, 0o700); err != nil {
			return nil, err
		}
		loaded, err := loadMaterializedRouteLedgersFromFilesAt(canonical, commit, partitions[partitionView], partitionStage)
		if err != nil {
			return nil, fmt.Errorf("validate materialized route target %s view %s: %w", targetSHA, partitionView, err)
		}
		result = append(result, loaded...)
	}
	return result, nil
}
