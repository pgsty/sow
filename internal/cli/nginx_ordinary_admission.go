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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/verify"
	"github.com/pgsty/sow/internal/views"
	"github.com/pgsty/sow/internal/yumrepo"
)

// admitNginxOrdinaryRoutesWithSession is the authority boundary between a
// declarative Nginx route and an ordinary materialized APT/YUM/asset tree. A
// config alone is intentionally insufficient: every emitted ownership unit
// must have one canonical receipt, the complete canonical ref vector must
// still match, its public payload must be reprojectable, and the retained
// physical tree must replay the exact receipt at the final output barrier.
func admitNginxOrdinaryRoutesWithSession(ctx context.Context, cfg *config.Config, repos []config.Repo, view, targetPath string, values commonFlags, session *localReadAdmission) error {
	if ctx == nil || cfg == nil || session == nil || session.canonical == nil || session.root == nil {
		return errors.New("ordinary Nginx route admission requires initialized canonical state")
	}
	viewConfig, exists := cfg.Views[view]
	if !exists {
		return fmt.Errorf("ordinary Nginx route view %q is not configured", view)
	}
	head, err := session.HeadHash()
	if err != nil || head.IsZero() {
		return errors.Join(err, errors.New("ordinary Nginx route canonical HEAD is unavailable"))
	}
	configSHA, err := cfg.CanonicalSHA256()
	if err != nil {
		return err
	}
	targetSHA, err := serving.MaterializedRouteTargetSHA256(targetPath)
	if err != nil {
		return err
	}

	stageDir, err := os.MkdirTemp("", "sow-nginx-ordinary-admission-")
	if err != nil {
		return err
	}
	if err := session.retainCleanup(func() error { return os.RemoveAll(stageDir) }); err != nil {
		_ = os.RemoveAll(stageDir)
		return err
	}
	ledgers, err := loadMaterializedRouteLedgersAt(session.canonical, head, targetSHA, view, stageDir)
	if err != nil {
		return fmt.Errorf("load canonical ordinary route ledgers: %w", err)
	}

	source := materializeCanonicalSource{ID: view, Public: viewConfig.Access == "public"}
	owners, err := completeSelectedMaterializedRouteOwners(cfg, session.canonical, source, selectedLeaves(repos, values))
	if err != nil {
		return err
	}
	wantOwners := selectedNginxOrdinaryRouteOwnerCount(viewConfig, repos)
	if len(owners) != wantOwners {
		return fmt.Errorf("ordinary Nginx selectors emit %d ownership units but only %d have complete canonical ref vectors", wantOwners, len(owners))
	}
	matched, err := matchNginxOrdinaryRouteLedgers(session.canonical, head, owners, ledgers, view, targetSHA, configSHA)
	if err != nil {
		return err
	}

	targetRoot, targetRelative, err := bindNginxOrdinaryTarget(session, cfg, targetPath)
	if err != nil {
		return err
	}
	pool, err := session.OpenPool()
	if err != nil {
		return err
	}
	options := serving.InstallOptions{Workers: values.workers, ChunkEntries: values.chunk, TempDir: stageDir}
	var lifecycle canonicalServingLifecycle
	for _, item := range matched {
		if item.owner.kind == "yum" {
			lifecycle, err = loadCanonicalServingLifecycle(session.canonical)
			if err != nil {
				return err
			}
			break
		}
	}

	trust := ordinaryRouteTrust{verifyAt: timeNowUTC()}
	for index, item := range matched {
		routeDir := filepath.Join(stageDir, fmt.Sprintf("route-%03d-%s", index, item.owner.id().tempToken()))
		if err := os.Mkdir(routeDir, 0o700); err != nil {
			return err
		}
		if err := validateNginxOrdinaryRoute(ctx, cfg, session, head, targetRoot, targetRelative, pool, source, item, lifecycle, routeDir, options, &trust); err != nil {
			return fmt.Errorf("ordinary Nginx route %s: %w", item.owner.id(), err)
		}
		ownerCopy, ledgerCopy := item.owner, item.ledger
		session.rechecks = append(session.rechecks, func() error {
			if err := serving.ValidateMaterializedRouteRoot(ctx, pool, targetRoot, ledgerCopy.Receipt, ledgerCopy.ExactManifest, ledgerCopy.PayloadManifest, options); err != nil {
				return fmt.Errorf("final ordinary route replay %s: %w", ownerCopy.id(), err)
			}
			return nil
		})
	}
	return nil
}

type matchedNginxOrdinaryRoute struct {
	owner  materializedRouteOwner
	ledger materializedRouteLedger
}

func selectedNginxOrdinaryRouteOwnerCount(view config.View, repos []config.Repo) int {
	result := 0
	for _, repo := range repos {
		if !repo.IsActive() || !viewIncludesRepo(view, repo.ID) {
			continue
		}
		if repo.Type == "yum" {
			result += len(repo.Arches)
		} else {
			result++
		}
	}
	return result
}

func matchNginxOrdinaryRouteLedgers(canonical *state.Store, head plumbing.Hash, owners []materializedRouteOwner, ledgers []materializedRouteLedger, view, targetSHA, configSHA string) ([]matchedNginxOrdinaryRoute, error) {
	if canonical == nil || head.IsZero() {
		return nil, errors.New("ordinary Nginx route canonical anchor is unavailable")
	}
	result := make([]matchedNginxOrdinaryRoute, 0, len(owners))
	anchors := make(map[string]struct{})
	for _, owner := range owners {
		var candidates []materializedRouteLedger
		for _, ledger := range ledgers {
			route := ledger.Receipt
			if route.Kind == owner.kind && route.Repo == owner.repo.ID && route.OS == "all" && route.Arch == owner.arch {
				candidates = append(candidates, ledger)
			}
		}
		if len(candidates) != 1 {
			return nil, fmt.Errorf("selected route %s has %d canonical receipts; want exactly one", owner.id(), len(candidates))
		}
		route := candidates[0].Receipt
		if route.View != view || route.Source != view || route.TargetSHA256 != targetSHA || route.ConfigSHA256 != configSHA {
			return nil, fmt.Errorf("selected route %s receipt has stale view, source, target, or configuration identity", owner.id())
		}
		anchorKey := route.ConfigCommit + "\x00" + route.ConfigSHA256
		if _, checked := anchors[anchorKey]; !checked {
			if _, err := loadMaterializedRouteConfigAnchor(canonical, head, route.ConfigCommit, route.ConfigSHA256); err != nil {
				return nil, fmt.Errorf("selected route %s receipt has an invalid historical config anchor: %w", owner.id(), err)
			}
			anchors[anchorKey] = struct{}{}
		}
		if !sameMaterializedRouteClaims(route.Claims, owner.claims) {
			return nil, fmt.Errorf("selected route %s receipt claims differ from the renderer", owner.id())
		}
		refs := make([]serving.MaterializedRouteRef, 0, len(owner.leaves))
		for _, leaf := range owner.leaves {
			refs = append(refs, serving.MaterializedRouteRef{
				Name: leaf.ref.String(), Commit: leaf.commit.String(), ManifestBlob: leaf.manifestBlob.String(), ManifestSize: leaf.manifestSize,
			})
		}
		sort.Slice(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })
		if !sameMaterializedRouteRefs(route.Refs, refs) {
			return nil, fmt.Errorf("selected route %s receipt has a stale or incomplete canonical ref vector", owner.id())
		}
		result = append(result, matchedNginxOrdinaryRoute{owner: owner, ledger: candidates[0]})
	}
	return result, nil
}

func sameMaterializedRouteClaims(left, right []serving.MaterializedRouteClaim) bool {
	right = append([]serving.MaterializedRouteClaim(nil), right...)
	sort.Slice(right, func(i, j int) bool {
		if right[i].Kind != right[j].Kind {
			return right[i].Kind < right[j].Kind
		}
		if right[i].RelativeRoot != right[j].RelativeRoot {
			return right[i].RelativeRoot < right[j].RelativeRoot
		}
		return right[i].Leaf < right[j].Leaf
	})
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sameMaterializedRouteRefs(left, right []serving.MaterializedRouteRef) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func bindNginxOrdinaryTarget(session *localReadAdmission, cfg *config.Config, targetPath string) (*os.Root, string, error) {
	configured, err := filepath.Abs(filepath.Clean(cfg.Root))
	if err != nil {
		return nil, "", err
	}
	target, err := filepath.Abs(filepath.Clean(targetPath))
	if err != nil {
		return nil, "", err
	}
	relative, err := filepath.Rel(configured, target)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return nil, "", errors.Join(err, errors.New("ordinary Nginx target escapes the retained repository root"))
	}
	if err := serving.ValidateWorkerTraversableAbsoluteDirectory(target); err != nil {
		return nil, "", fmt.Errorf("ordinary Nginx target is not worker-traversable: %w", err)
	}
	if relative == "." || relative == "" {
		session.rechecks = append(session.rechecks, func() error { return serving.ValidateWorkerTraversableAbsoluteDirectory(target) })
		return session.root, ".", nil
	}
	bound, identity, err := openRealYUMCompatibilityDirectory(session.root, relative, false)
	if err != nil {
		return nil, "", fmt.Errorf("bind ordinary Nginx target: %w", err)
	}
	if err := session.retainCleanup(bound.Close); err != nil {
		_ = bound.Close()
		return nil, "", err
	}
	relativeSlash := filepath.ToSlash(relative)
	session.rechecks = append(session.rechecks, func() error {
		return errors.Join(
			serving.ValidateWorkerTraversableAbsoluteDirectory(target),
			verifyBoundYUMCompatibilityDirectory(session.root, relative, identity),
		)
	})
	return bound, relativeSlash, nil
}

type ordinaryRouteTrust struct {
	verifyAt    time.Time
	aptVerifier verify.APTSignatureVerifier
	yumVerifier yumrepo.DetachedVerifier
	packageKeys map[string]openpgp.KeyRing
}

func (trust *ordinaryRouteTrust) repository(session *localReadAdmission, cfg *config.Config) error {
	if trust == nil || trust.verifyAt.IsZero() {
		return errors.New("ordinary route verification time is unavailable")
	}
	if trust.aptVerifier != nil && trust.yumVerifier != nil {
		return nil
	}
	body, err := session.ReadFile(cfg.Path, cfg.GPG.PublicKey, "ordinary route repository public key", maxSecretBytes)
	if err != nil {
		return err
	}
	_, packets, err := parseRepositoryPublicTrustAnchor(body)
	if err != nil {
		return err
	}
	aptVerifier, err := verify.NewAPTVerifier(bytes.NewReader(packets))
	if err != nil {
		return err
	}
	yumVerifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(packets), trust.verifyAt)
	if err != nil {
		return err
	}
	trust.aptVerifier, trust.yumVerifier = aptVerifier, yumVerifier
	return nil
}

func (trust *ordinaryRouteTrust) packageKeyring(session *localReadAdmission, cfg *config.Config, repo config.Repo) (openpgp.KeyRing, error) {
	if repo.YUM == nil || repo.YUM.PackageKeyring == "" {
		return nil, fmt.Errorf("YUM repo %s has no package keyring", repo.ID)
	}
	if trust.packageKeys == nil {
		trust.packageKeys = make(map[string]openpgp.KeyRing)
	}
	if keyring := trust.packageKeys[repo.YUM.PackageKeyring]; keyring != nil {
		return keyring, nil
	}
	body, err := session.ReadFile(cfg.Path, repo.YUM.PackageKeyring, "ordinary route RPM package keyring", maxSecretBytes)
	if err != nil {
		return nil, err
	}
	keyring, err := yumrepo.ParseRPMPackageKeyring(body)
	if err != nil {
		return nil, err
	}
	trust.packageKeys[repo.YUM.PackageKeyring] = keyring
	return keyring, nil
}

func validateNginxOrdinaryRoute(
	ctx context.Context,
	cfg *config.Config,
	session *localReadAdmission,
	head plumbing.Hash,
	targetRoot *os.Root,
	targetRelative string,
	pool *repository.Store,
	source materializeCanonicalSource,
	item matchedNginxOrdinaryRoute,
	lifecycle canonicalServingLifecycle,
	routeDir string,
	options serving.InstallOptions,
	trust *ordinaryRouteTrust,
) error {
	if pool == nil {
		return errors.New("ordinary route CAS capability is unavailable")
	}
	owner, ledger := item.owner, item.ledger
	for _, leaf := range owner.leaves {
		if err := validateViewAt(session.canonical, leaf.commit, leaf.canonicalPath, viewLeaf{repo: owner.repo, os: leaf.os, arch: leaf.arch}, source.Public); err != nil {
			return fmt.Errorf("validate bound canonical leaf %s: %w", leaf.ref, err)
		}
	}
	projected := filepath.Join(routeDir, "payload-projected.tsv")
	if err := projectMaterializedRouteOwnerPayload(session.canonical, owner, projected); err != nil {
		return err
	}
	currentPayload := filepath.Join(routeDir, "payload-current.tsv")
	if _, err := filterManifestFile(projected, currentPayload, func(entry manifest.Entry) bool {
		return materializedRouteCurrentClaimOwns(owner, entry.Path)
	}); err != nil {
		return err
	}
	payloadParts := []string{currentPayload}
	publicNamespaceParts := []string{currentPayload}
	if owner.kind == "yum" {
		target, err := nginxOrdinaryYUMServingTarget(lifecycle, targetRelative, source.ID, owner)
		if err != nil {
			return err
		}
		if target.ID != ledger.Receipt.ServingTargetID {
			return errors.New("YUM receipt serving target differs from the canonical target registry")
		}
		generationCandidates, err := materializedYUMGenerationIDsFromManifest(ledger.ExactManifest, owner.relativeRoot)
		if err != nil {
			return fmt.Errorf("read YUM receipt generation set: %w", err)
		}
		exactParts, generationParts, err := materializedYUMServingExpectedForTargetAt(session.canonical, head, lifecycle, target, source.ID, owner, routeDir, ledger.Receipt.ConfigSHA256, generationCandidates)
		if err != nil {
			return err
		}
		payloadParts = append(payloadParts, generationParts...)
		publicGenerationParts, err := nginxYUMPublicGenerationPayloadParts(exactParts, owner, routeDir)
		if err != nil {
			return err
		}
		publicNamespaceParts = append(publicNamespaceParts, publicGenerationParts...)
		expectedAux := filepath.Join(routeDir, "exact-yum-aux-expected.tsv")
		if err := mergeNginxPublicationManifests(exactParts, expectedAux, routeDir); err != nil {
			return err
		}
		actualAux := filepath.Join(routeDir, "exact-yum-aux-actual.tsv")
		if _, err := filterManifestFile(ledger.ExactManifest, actualAux, func(entry manifest.Entry) bool {
			return !materializedRouteCurrentClaimOwns(owner, entry.Path)
		}); err != nil {
			return err
		}
		if equal, err := manifestFilesEqual(expectedAux, actualAux); err != nil || !equal {
			return errors.Join(err, errors.New("YUM generation or mirrorlist bytes differ from canonical lifecycle state"))
		}
		if err := validateNginxYUMGenerationPublicPayload(session.canonical, lifecycle, owner, source, publicGenerationParts, routeDir); err != nil {
			return err
		}
	} else {
		publicNamespaceParts = append(publicNamespaceParts, payloadParts[1:]...)
	}
	expectedPayload := filepath.Join(routeDir, "payload-expected.tsv")
	if err := mergeNginxPublicationManifests(payloadParts, expectedPayload, routeDir); err != nil {
		return err
	}
	if equal, err := manifestFilesEqual(expectedPayload, ledger.PayloadManifest); err != nil || !equal {
		return errors.Join(err, errors.New("receipt payload differs from its bound canonical public projection"))
	}
	if err := validateNginxOrdinaryExactShape(owner, ledger.ExactManifest); err != nil {
		return err
	}
	exactPayload := filepath.Join(routeDir, "payload-from-exact.tsv")
	if _, err := filterManifestFile(ledger.ExactManifest, exactPayload, func(entry manifest.Entry) bool {
		return nginxOrdinaryPayloadPath(owner, entry.Path)
	}); err != nil {
		return err
	}
	expectedPublicNamespace := filepath.Join(routeDir, "payload-public-namespace.tsv")
	if err := mergeNginxPublicationManifests(publicNamespaceParts, expectedPublicNamespace, routeDir); err != nil {
		return err
	}
	if equal, err := manifestFilesEqual(expectedPublicNamespace, exactPayload); err != nil || !equal {
		return errors.Join(err, errors.New("route package namespace is not exactly the reprojected canonical payload"))
	}
	if err := serving.ValidateMaterializedRouteRoot(ctx, pool, targetRoot, ledger.Receipt, ledger.ExactManifest, ledger.PayloadManifest, options); err != nil {
		return err
	}
	return validateNginxOrdinaryMetadataClosure(ctx, cfg, session, targetRoot, owner, source, lifecycle, ledger.ExactManifest, expectedPayload, routeDir, options, trust)
}

// nginxYUMPublicGenerationPayloadParts derives the complete package namespace
// exposed below immutable generation URLs. Active retained generations are CAS
// roots and therefore also occur in the receipt payload manifest. Retired
// generations deliberately are not CAS roots, but their still-installed bytes
// remain publicly routable until explicit, confirmed generation GC removes the
// directory. They must consequently remain in the exact namespace and pass the
// same historical public-view proof without being reintroduced as GC roots.
func nginxYUMPublicGenerationPayloadParts(exactParts []string, owner materializedRouteOwner, routeDir string) ([]string, error) {
	result := make([]string, 0, len(exactParts))
	for index, exactPart := range exactParts {
		part := filepath.Join(routeDir, fmt.Sprintf("generation-public-exact-%06d.tsv", index))
		stats, err := filterManifestFile(exactPart, part, func(entry manifest.Entry) bool {
			_, _, relative, ok := splitNginxYUMGenerationPath(entry.Path, owner.relativeRoot)
			return ok && strings.HasPrefix(relative, "Packages/") && strings.HasSuffix(relative, ".rpm")
		})
		if err != nil {
			return nil, err
		}
		if stats.Files == 0 {
			if err := os.Remove(part); err != nil {
				return nil, err
			}
			continue
		}
		result = append(result, part)
	}
	return result, nil
}

func nginxOrdinaryYUMServingTarget(lifecycle canonicalServingLifecycle, targetRelative, view string, owner materializedRouteOwner) (serving.TargetIdentity, error) {
	targetID := ""
	for _, leaf := range owner.leaves {
		var matched []serving.Channel
		for _, record := range lifecycle.Channels {
			channel := record.Channel
			if channel.View == view && channel.Repo == owner.repo.ID && channel.OS == leaf.os && channel.Arch == owner.arch && channel.TargetRoot == targetRelative {
				matched = append(matched, channel)
			}
		}
		if len(matched) != 1 {
			return serving.TargetIdentity{}, fmt.Errorf("YUM leaf %s/%s/%s has %d channels for target root %s", owner.repo.ID, leaf.os, owner.arch, len(matched), targetRelative)
		}
		if targetID == "" {
			targetID = matched[0].TargetID
		} else if targetID != matched[0].TargetID {
			return serving.TargetIdentity{}, errors.New("one physical YUM owner resolves to multiple serving targets")
		}
	}
	target, exists := lifecycle.Targets[targetID]
	if !exists || target.Root != targetRelative || target.BaseURL == "" {
		return serving.TargetIdentity{}, errors.New("YUM ordinary route has no matching canonical target registry")
	}
	return target, nil
}

func validateNginxOrdinaryExactShape(owner materializedRouteOwner, exactPath string) (resultErr error) {
	file, err := os.Open(exactPath)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	reader := manifest.NewReader(file)
	mirrorlists := make(map[string]struct{})
	for _, claim := range owner.claims {
		if claim.Kind == serving.MaterializedRouteClaimExactFile {
			mirrorlists[claim.RelativeRoot] = struct{}{}
		}
	}
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		switch owner.kind {
		case "asset":
			// Asset exact bytes are all payload and are compared below.
			continue
		case "apt":
			relative, ok := trimPathPrefix(entry.Path, owner.relativeRoot)
			if !ok || relative != "pool" && !strings.HasPrefix(relative, "pool/") && relative != "dists" && !strings.HasPrefix(relative, "dists/") {
				return fmt.Errorf("APT route exposes unclassified path %s", entry.Path)
			}
		case "yum":
			if _, exact := mirrorlists[entry.Path]; exact {
				continue
			}
			if relative, ok := trimPathPrefix(entry.Path, owner.relativeRoot); ok {
				if relative == "Packages" || strings.HasPrefix(relative, "Packages/") || relative == "repodata" || strings.HasPrefix(relative, "repodata/") {
					continue
				}
			}
			if _, _, relative, ok := splitNginxYUMGenerationPath(entry.Path, owner.relativeRoot); ok &&
				(relative == "Packages" || strings.HasPrefix(relative, "Packages/") || relative == "repodata" || strings.HasPrefix(relative, "repodata/")) {
				continue
			}
			return fmt.Errorf("YUM route exposes unclassified path %s", entry.Path)
		}
	}
}

func nginxOrdinaryPayloadPath(owner materializedRouteOwner, candidate string) bool {
	switch owner.kind {
	case "asset":
		return true
	case "apt":
		relative, ok := trimPathPrefix(candidate, owner.relativeRoot)
		return ok && strings.HasPrefix(relative, "pool/")
	case "yum":
		if relative, ok := trimPathPrefix(candidate, owner.relativeRoot); ok && strings.HasPrefix(relative, "Packages/") {
			return true
		}
		_, _, relative, ok := splitNginxYUMGenerationPath(candidate, owner.relativeRoot)
		return ok && strings.HasPrefix(relative, "Packages/")
	default:
		return false
	}
}

func trimPathPrefix(candidate, prefix string) (string, bool) {
	if candidate == prefix {
		return "", true
	}
	prefix = strings.TrimSuffix(prefix, "/") + "/"
	if !strings.HasPrefix(candidate, prefix) {
		return "", false
	}
	return strings.TrimPrefix(candidate, prefix), true
}

func splitNginxYUMGenerationPath(candidate, leaf string) (base, generation, relative string, ok bool) {
	const prefix = "_sow/v1/g/"
	if !strings.HasPrefix(candidate, prefix) {
		return "", "", "", false
	}
	remainder := strings.TrimPrefix(candidate, prefix)
	parts := strings.SplitN(remainder, "/", 2)
	if len(parts) != 2 || len(parts[0]) != 20 {
		return "", "", "", false
	}
	for _, value := range parts[0] {
		if value < '0' || value > '9' {
			return "", "", "", false
		}
	}
	relative, ok = trimPathPrefix(parts[1], leaf)
	if !ok {
		return "", "", "", false
	}
	base = path.Join("_sow/v1/g", parts[0], leaf)
	return base, parts[0], relative, true
}

// validateNginxYUMGenerationPublicPayload prevents an old immutable generation
// from becoming a confidentiality bypass. Generation manifests are canonical
// integrity evidence, but package admission additionally requires every
// retained payload byte to appear in a canonical leaf that independently
// satisfies the selected view's public/pro closure.
func validateNginxYUMGenerationPublicPayload(canonical *state.Store, lifecycle canonicalServingLifecycle, owner materializedRouteOwner, source materializeCanonicalSource, generationPayloadParts []string, routeDir string) error {
	if len(generationPayloadParts) == 0 {
		return errors.New("YUM route has no canonical generation payload evidence")
	}
	var generations []serving.Generation
	for _, record := range lifecycle.Generations {
		generations = append(generations, record.Generation)
	}
	for _, record := range lifecycle.Retired {
		generations = append(generations, record.Retired.Generation)
	}
	sort.Slice(generations, func(i, j int) bool {
		left := generations[i].RefCommit + "\x00" + generations[i].OS + "\x00" + generations[i].ID
		right := generations[j].RefCommit + "\x00" + generations[j].OS + "\x00" + generations[j].ID
		return left < right
	})
	seen := make(map[string]struct{})
	var allowParts []string
	for index, generation := range generations {
		if generation.View != source.ID || generation.Repo != owner.repo.ID || generation.Arch != owner.arch || generation.LegacyRoot != owner.relativeRoot {
			continue
		}
		key := generation.OS + "\x00" + generation.RefCommit
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		commit := plumbing.NewHash(generation.RefCommit)
		if commit.IsZero() || commit.String() != generation.RefCommit {
			return fmt.Errorf("YUM generation %s has an invalid source commit", generation.ID)
		}
		canonicalPath, err := state.ViewPath(source.ID, owner.repo.ID, generation.OS, owner.arch)
		if err != nil {
			return err
		}
		leaf := viewLeaf{repo: owner.repo, os: generation.OS, arch: owner.arch}
		if err := validateViewAt(canonical, commit, canonicalPath, leaf, source.Public); err != nil {
			return fmt.Errorf("YUM generation %s source view is not admissible: %w", generation.ID, err)
		}
		part := filepath.Join(routeDir, fmt.Sprintf("generation-public-source-%06d.tsv", index))
		projectionOwner := materializedRouteOwner{kind: "yum", repo: owner.repo, arch: owner.arch, relativeRoot: owner.relativeRoot,
			leaves: []materializedRouteOwnerLeaf{{os: generation.OS, arch: owner.arch, commit: commit, canonicalPath: canonicalPath}}}
		if err := projectMaterializedRouteOwnerPayload(canonical, projectionOwner, part); err != nil {
			return err
		}
		allowParts = append(allowParts, part)
	}
	if len(allowParts) == 0 {
		return errors.New("YUM generation payload has no admissible canonical source history")
	}
	allowed := filepath.Join(routeDir, "generation-public-allowed.tsv")
	if err := mergeCompatibleNginxManifestSet(allowParts, allowed, routeDir); err != nil {
		return err
	}
	for index, part := range generationPayloadParts {
		prefix, err := nginxGenerationManifestPrefix(part, owner.relativeRoot)
		if err != nil {
			return err
		}
		if prefix == "" {
			// An empty YUM generation has signed repodata but no Packages
			// payload. There is no package byte to prove against view history.
			continue
		}
		global := filepath.Join(routeDir, fmt.Sprintf("generation-public-payload-%06d.tsv", index))
		if err := stripManifestPrefix(part, global, prefix); err != nil {
			return err
		}
		if err := requireManifestSubset(global, allowed); err != nil {
			return fmt.Errorf("generation payload is not in an admissible canonical view: %w", err)
		}
	}
	return nil
}

func nginxGenerationManifestPrefix(manifestPath, leaf string) (string, error) {
	file, err := os.Open(manifestPath)
	if err != nil {
		return "", err
	}
	reader := manifest.NewReader(file)
	entry, readErr := reader.Next()
	closeErr := file.Close()
	if errors.Is(readErr, io.EOF) {
		return "", closeErr
	}
	if readErr != nil || closeErr != nil {
		return "", errors.Join(readErr, closeErr)
	}
	base, _, _, ok := splitNginxYUMGenerationPath(entry.Path, leaf)
	if !ok {
		return "", fmt.Errorf("invalid generation payload path %s", entry.Path)
	}
	return strings.TrimSuffix(base, "/"+leaf), nil
}

func mergeNginxPublicationManifests(inputs []string, destination, tempDir string) (resultErr error) {
	mergeDir, err := os.MkdirTemp(tempDir, "merge-publication-")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(mergeDir)) }()
	return mergePublicationManifests(inputs, destination, mergeDir)
}

func mergeCompatibleNginxManifestSet(inputs []string, destination, tempDir string) (resultErr error) {
	if len(inputs) == 0 {
		file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		return errors.Join(file.Sync(), file.Close())
	}
	mergeDir, err := os.MkdirTemp(tempDir, "merge-compatible-nginx-")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(mergeDir)) }()
	current := inputs[0]
	for index := 1; index < len(inputs); index++ {
		next := filepath.Join(mergeDir, fmt.Sprintf("part-%06d.tsv", index))
		if err := mergeCompatibleManifestFiles(current, inputs[index], next); err != nil {
			return err
		}
		if current != inputs[0] {
			_ = os.Remove(current)
		}
		current = next
	}
	source, err := os.Open(current)
	if err != nil {
		return err
	}
	copyErr := manifest.AtomicCopy(destination, source, 0o600)
	return errors.Join(copyErr, source.Close())
}

func requireManifestSubset(subsetPath, allowedPath string) (resultErr error) {
	subset, err := os.Open(subsetPath)
	if err != nil {
		return err
	}
	allowed, err := os.Open(allowedPath)
	if err != nil {
		_ = subset.Close()
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, subset.Close(), allowed.Close()) }()
	subsetReader, allowedReader := manifest.NewReader(subset), manifest.NewReader(allowed)
	allowedEntry, allowedErr := allowedReader.Next()
	for {
		entry, err := subsetReader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		for allowedErr == nil && allowedEntry.Path < entry.Path {
			allowedEntry, allowedErr = allowedReader.Next()
		}
		if allowedErr != nil && !errors.Is(allowedErr, io.EOF) {
			return allowedErr
		}
		if allowedErr != nil || allowedEntry.Path != entry.Path || allowedEntry.Size != entry.Size || allowedEntry.SHA256 != entry.SHA256 {
			return fmt.Errorf("payload %s is absent or differs", entry.Path)
		}
	}
}

func validateNginxOrdinaryMetadataClosure(ctx context.Context, cfg *config.Config, session *localReadAdmission, targetRoot *os.Root, owner materializedRouteOwner, source materializeCanonicalSource, lifecycle canonicalServingLifecycle, exactPath, expectedPayload, routeDir string, options serving.InstallOptions, trust *ordinaryRouteTrust) error {
	if owner.kind == "asset" {
		return nil
	}
	if err := trust.repository(session, cfg); err != nil {
		return err
	}
	switch owner.kind {
	case "apt":
		metadataRoot := filepath.Join(routeDir, "apt-metadata")
		if err := stageNginxOrdinaryMetadata(targetRoot, exactPath, owner.relativeRoot, "dists", metadataRoot); err != nil {
			return err
		}
		payload := filepath.Join(routeDir, "apt-payload-local.tsv")
		if err := stripManifestPrefix(expectedPayload, payload, owner.relativeRoot); err != nil {
			return err
		}
		identities := filepath.Join(routeDir, "apt-identities.tsv")
		if err := nginxAPTExpectedIdentities(ctx, session.canonical, targetRoot, owner, identities, routeDir); err != nil {
			return err
		}
		baseCopy := owner.relativeRoot
		report := verify.Run(ctx, verify.Request{Layers: []verify.Layer{verify.LayerL1}, Workers: 1, Checks: []verify.Check{verify.APTCheck{
			CheckID: "nginx-apt-" + owner.repo.ID, Root: metadataRoot,
			ExpectedSuites: owner.repo.APT.Suites, ExpectedSuiteComponents: aptSuiteComponentContract(owner.repo.APT),
			Verifier: trust.aptVerifier, VerifyAt: trust.verifyAt, Workers: options.Workers, ChunkEntries: options.ChunkEntries,
			TempDir: routeDir, ActualPayload: verify.FileStream(payload), ExpectedIdentities: verify.FileStream(identities),
			OpenPayload: func(entry manifest.Entry) (verify.PayloadReadSeekCloser, error) {
				return openNginxBoundPayload(targetRoot, path.Join(baseCopy, entry.Path), entry)
			},
		}}})
		return requireNginxMetadataReport(report)
	case "yum":
		packageKeyring, err := trust.packageKeyring(session, cfg, owner.repo)
		if err != nil {
			return err
		}
		bases, err := nginxYUMMetadataBases(exactPath, owner.relativeRoot)
		if err != nil {
			return err
		}
		checks := make([]verify.Check, 0, len(bases))
		for index, base := range bases {
			metadataRoot := filepath.Join(routeDir, fmt.Sprintf("yum-metadata-%03d", index))
			if err := stageNginxOrdinaryMetadata(targetRoot, exactPath, base, "repodata", metadataRoot); err != nil {
				return err
			}
			localPayload := filepath.Join(routeDir, fmt.Sprintf("yum-payload-%03d.tsv", index))
			identities := filepath.Join(routeDir, fmt.Sprintf("yum-identities-%03d.tsv", index))
			if err := nginxYUMIndexedEvidence(ctx, session.canonical, targetRoot, lifecycle, owner, source, base, localPayload, identities, routeDir, index); err != nil {
				return err
			}
			baseCopy := base
			checks = append(checks, verify.YUMCheck{
				CheckID: "nginx-yum-" + owner.repo.ID + "-" + owner.arch + fmt.Sprintf("-%03d", index), Root: metadataRoot,
				Compression: yumrepo.Compression(owner.repo.YUM.Compression), Verifier: trust.yumVerifier,
				PackageKeyring: packageKeyring, VerifyAt: trust.verifyAt, Workers: options.Workers, ChunkEntries: options.ChunkEntries,
				TempDir: routeDir, ActualPayload: verify.FileStream(localPayload),
				ExpectedIdentities: verify.FileStream(identities),
				OpenPayload: func(entry manifest.Entry) (verify.PayloadReadSeekCloser, error) {
					return openNginxBoundPayload(targetRoot, path.Join(baseCopy, entry.Path), entry)
				},
			})
		}
		report := verify.Run(ctx, verify.Request{Layers: []verify.Layer{verify.LayerL1}, Workers: min(options.Workers, len(checks)), Checks: checks})
		return requireNginxMetadataReport(report)
	default:
		return fmt.Errorf("unsupported ordinary route metadata kind %s", owner.kind)
	}
}

func nginxAPTExpectedIdentities(ctx context.Context, canonical *state.Store, targetRoot *os.Root, owner materializedRouteOwner, destination, tempDir string) error {
	var parts []string
	for index, leaf := range owner.leaves {
		reader, err := canonical.OpenPathAt(leaf.commit, leaf.canonicalPath)
		if err != nil {
			return err
		}
		part := filepath.Join(tempDir, fmt.Sprintf("apt-identity-leaf-%03d.tsv", index))
		output, err := os.OpenFile(part, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			_ = reader.Close()
			return err
		}
		stream := views.NewReader(reader)
		for {
			entry, err := stream.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return errors.Join(err, reader.Close(), output.Close())
			}
			relative, ok := trimPathPrefix(entry.Path, owner.relativeRoot)
			components := strings.Split(relative, "/")
			if !ok || len(components) < 3 || components[0] != "pool" {
				return errors.Join(reader.Close(), output.Close(), fmt.Errorf("APT canonical identity path %s is outside pool", entry.Path))
			}
			payloadEntry, err := nginxViewPayloadEntry(relative, entry)
			if err != nil {
				return errors.Join(err, reader.Close(), output.Close())
			}
			packageFile, err := openNginxBoundPayload(targetRoot, path.Join(owner.relativeRoot, relative), payloadEntry)
			if err != nil {
				return errors.Join(err, reader.Close(), output.Close())
			}
			pkg, inspectErr := aptrepo.InspectPackageReaderAs(ctx, packageFile, components[1], path.Base(relative))
			closeErr := packageFile.Close()
			if inspectErr != nil || closeErr != nil {
				return errors.Join(inspectErr, closeErr, reader.Close(), output.Close())
			}
			if pkg.Name != entry.Name || pkg.Version != entry.Version || pkg.PoolPath != relative || pkg.Size != entry.Size || pkg.SHA256 != entry.SHA256 ||
				(pkg.Architecture != leaf.arch && pkg.Architecture != "all") {
				return errors.Join(reader.Close(), output.Close(), fmt.Errorf("APT canonical view identity for %s differs from its bound DEB body", entry.Path))
			}
			identity, err := verify.APTPackageIdentityEntry(leaf.os, leaf.arch, pkg.Name, pkg.Version, pkg.Architecture, components[1], relative, pkg.Size, pkg.SHA256)
			if err != nil {
				return errors.Join(err, reader.Close(), output.Close())
			}
			if err := manifest.WriteEntry(output, identity); err != nil {
				return errors.Join(err, reader.Close(), output.Close())
			}
		}
		if err := errors.Join(reader.Close(), output.Sync(), output.Close()); err != nil {
			return err
		}
		parts = append(parts, part)
	}
	return mergeCompatibleNginxManifestSet(parts, destination, tempDir)
}

func nginxYUMIndexedEvidence(ctx context.Context, canonical *state.Store, targetRoot *os.Root, lifecycle canonicalServingLifecycle, owner materializedRouteOwner, source materializeCanonicalSource, base, payloadDestination, identityDestination, tempDir string, index int) error {
	leaves := owner.leaves
	if base != owner.relativeRoot {
		_, generationID, _, ok := splitNginxYUMGenerationPath(base+"/Packages/x/placeholder.rpm", owner.relativeRoot)
		if !ok {
			return fmt.Errorf("invalid YUM generation base %s", base)
		}
		var generation *serving.Generation
		for _, record := range lifecycle.Generations {
			candidate := record.Generation
			if candidate.ID == generationID && candidate.View == source.ID && candidate.Repo == owner.repo.ID && candidate.Arch == owner.arch && candidate.LegacyRoot == owner.relativeRoot {
				copy := candidate
				if generation != nil && *generation != copy {
					return fmt.Errorf("ambiguous canonical generation %s", generationID)
				}
				generation = &copy
			}
		}
		for _, record := range lifecycle.Retired {
			candidate := record.Retired.Generation
			if candidate.ID == generationID && candidate.View == source.ID && candidate.Repo == owner.repo.ID && candidate.Arch == owner.arch && candidate.LegacyRoot == owner.relativeRoot {
				copy := candidate
				if generation != nil && *generation != copy {
					return fmt.Errorf("ambiguous canonical generation %s", generationID)
				}
				generation = &copy
			}
		}
		if generation == nil {
			return fmt.Errorf("YUM generation %s has no canonical identity source", generationID)
		}
		generationLeaves, err := nginxYUMGenerationOwnerLeaves(lifecycle, source, owner, *generation)
		if err != nil {
			return err
		}
		leaves = generationLeaves
	}
	projection := materializedRouteOwner{kind: "yum", repo: owner.repo, arch: owner.arch, relativeRoot: owner.relativeRoot, leaves: leaves}
	globalPayload := filepath.Join(tempDir, fmt.Sprintf("yum-indexed-%03d-global.tsv", index))
	if err := projectMaterializedRouteOwnerPayload(canonical, projection, globalPayload); err != nil {
		return err
	}
	if err := stripManifestPrefix(globalPayload, payloadDestination, owner.relativeRoot); err != nil {
		return err
	}
	var identityParts []string
	for leafIndex, leaf := range leaves {
		reader, err := canonical.OpenPathAt(leaf.commit, leaf.canonicalPath)
		if err != nil {
			return err
		}
		part := filepath.Join(tempDir, fmt.Sprintf("yum-indexed-%03d-identity-%03d.tsv", index, leafIndex))
		output, err := os.OpenFile(part, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			_ = reader.Close()
			return err
		}
		stream := views.NewReader(reader)
		for {
			entry, err := stream.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return errors.Join(err, reader.Close(), output.Close())
			}
			location, ok := trimPathPrefix(entry.Path, owner.relativeRoot)
			if !ok || !strings.HasPrefix(location, "Packages/") {
				return errors.Join(reader.Close(), output.Close(), fmt.Errorf("YUM canonical identity path %s is outside Packages", entry.Path))
			}
			epoch, version, release, err := splitCanonicalRPMDisplayVersion(entry.Version)
			if err != nil {
				return errors.Join(err, reader.Close(), output.Close())
			}
			payloadEntry, err := nginxViewPayloadEntry(location, entry)
			if err != nil {
				return errors.Join(err, reader.Close(), output.Close())
			}
			packageFile, err := openNginxBoundPayload(targetRoot, path.Join(base, location), payloadEntry)
			if err != nil {
				return errors.Join(err, reader.Close(), output.Close())
			}
			pkg, inspectErr := yumrepo.InspectPackageReader(ctx, packageFile, path.Base(location))
			closeErr := packageFile.Close()
			if inspectErr != nil || closeErr != nil {
				return errors.Join(inspectErr, closeErr, reader.Close(), output.Close())
			}
			if pkg.Name != entry.Name || pkg.Epoch != epoch || pkg.Version != version || pkg.Release != release || pkg.Location != location ||
				pkg.Size != entry.Size || pkg.SHA256 != entry.SHA256 || (pkg.Arch != leaf.arch && pkg.Arch != "noarch") {
				return errors.Join(reader.Close(), output.Close(), fmt.Errorf("YUM canonical view identity for %s differs from its bound RPM body", entry.Path))
			}
			identity, err := verify.YUMPackageIdentityEntry(pkg.Name, pkg.Epoch, pkg.Version, pkg.Release, pkg.Arch, location, pkg.Size, pkg.SHA256)
			if err != nil {
				return errors.Join(err, reader.Close(), output.Close())
			}
			if err := manifest.WriteEntry(output, identity); err != nil {
				return errors.Join(err, reader.Close(), output.Close())
			}
		}
		if err := errors.Join(reader.Close(), output.Sync(), output.Close()); err != nil {
			return err
		}
		identityParts = append(identityParts, part)
	}
	return mergeCompatibleNginxManifestSet(identityParts, identityDestination, tempDir)
}

// nginxYUMGenerationOwnerLeaves reconstructs the complete logical alias
// vector behind one immutable physical repo+arch manifest. Local serving
// generations intentionally bind one channel ref each, so their content IDs
// differ across OS aliases even though each generation directory contains the
// same owner-wide repodata and payload union. Matching the exact manifest
// digest across canonical lifecycle records recovers that union without
// trusting the live tree or widening to unrelated history.
func nginxYUMGenerationOwnerLeaves(lifecycle canonicalServingLifecycle, source materializeCanonicalSource, owner materializedRouteOwner, generation serving.Generation) ([]materializedRouteOwnerLeaf, error) {
	if generation.View != source.ID || generation.Repo != owner.repo.ID || generation.Arch != owner.arch || generation.LegacyRoot != owner.relativeRoot {
		return nil, errors.New("YUM generation differs from its physical route owner")
	}
	compatible := func(candidate serving.Generation) bool {
		return candidate.ManifestSHA256 == generation.ManifestSHA256 &&
			candidate.View == generation.View && candidate.Repo == generation.Repo && candidate.Arch == generation.Arch &&
			candidate.LegacyRoot == generation.LegacyRoot && candidate.ConfigSHA256 == generation.ConfigSHA256 &&
			candidate.RepositoryKeySHA256 == generation.RepositoryKeySHA256
	}
	byKey := make(map[string]materializedRouteOwnerLeaf)
	add := func(candidate serving.Generation) error {
		if !compatible(candidate) {
			return nil
		}
		commit := plumbing.NewHash(candidate.RefCommit)
		if commit.IsZero() || commit.String() != candidate.RefCommit {
			return fmt.Errorf("YUM generation %s has an invalid source commit", candidate.ID)
		}
		canonicalPath, err := state.ViewPath(source.ID, owner.repo.ID, candidate.OS, owner.arch)
		if err != nil {
			return err
		}
		key := candidate.OS + "\x00" + candidate.RefCommit
		byKey[key] = materializedRouteOwnerLeaf{os: candidate.OS, arch: owner.arch, commit: commit, canonicalPath: canonicalPath}
		return nil
	}
	for _, record := range lifecycle.Generations {
		if err := add(record.Generation); err != nil {
			return nil, err
		}
	}
	for _, record := range lifecycle.Retired {
		if err := add(record.Retired.Generation); err != nil {
			return nil, err
		}
	}
	if len(byKey) == 0 {
		return nil, fmt.Errorf("YUM generation %s has no complete physical-owner source vector", generation.ID)
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	leaves := make([]materializedRouteOwnerLeaf, 0, len(keys))
	for _, key := range keys {
		leaves = append(leaves, byKey[key])
	}
	return leaves, nil
}

func nginxViewPayloadEntry(relative string, entry views.Entry) (manifest.Entry, error) {
	decoded, err := hex.DecodeString(entry.SHA256)
	if err != nil || len(decoded) != sha256.Size {
		return manifest.Entry{}, errors.New("canonical view payload has invalid SHA256")
	}
	result := manifest.Entry{Path: relative, Size: entry.Size}
	copy(result.SHA256[:], decoded)
	if err := result.Validate(); err != nil {
		return manifest.Entry{}, err
	}
	return result, nil
}

func splitCanonicalRPMDisplayVersion(value string) (epoch int64, version, release string, resultErr error) {
	evr := value
	if index := strings.IndexByte(evr, ':'); index >= 0 {
		epoch, resultErr = strconv.ParseInt(evr[:index], 10, 64)
		if resultErr != nil || epoch < 0 {
			return 0, "", "", errors.New("invalid canonical RPM epoch")
		}
		evr = evr[index+1:]
	}
	index := strings.LastIndexByte(evr, '-')
	if index <= 0 || index == len(evr)-1 {
		return 0, "", "", errors.New("canonical RPM version lacks release")
	}
	return epoch, evr[:index], evr[index+1:], nil
}

func requireNginxMetadataReport(report verify.Report) error {
	if report.Exit == verify.ExitSuccess {
		return nil
	}
	if len(report.Findings) != 0 {
		return fmt.Errorf("metadata/index closure failed: %s: %s", report.Findings[0].Code, report.Findings[0].Message)
	}
	return fmt.Errorf("metadata/index closure failed with outcome %s", report.Outcome)
}

func nginxYUMMetadataBases(exactPath, leaf string) (result []string, resultErr error) {
	file, err := os.Open(exactPath)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	set := map[string]struct{}{leaf: {}}
	reader := manifest.NewReader(file)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if base, _, _, ok := splitNginxYUMGenerationPath(entry.Path, leaf); ok {
			set[base] = struct{}{}
		}
	}
	for base := range set {
		result = append(result, base)
	}
	sort.Strings(result)
	return result, nil
}

// stageNginxOrdinaryMetadata copies only bounded metadata bytes into a private
// verifier tree. Package bodies never cross this path: L1 consumes their
// canonical manifest and retained-root opener instead.
func stageNginxOrdinaryMetadata(targetRoot *os.Root, exactPath, base, metadataDirectory, destination string) (resultErr error) {
	if err := os.Mkdir(destination, 0o700); err != nil {
		return err
	}
	file, err := os.Open(exactPath)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	reader := manifest.NewReader(file)
	count := 0
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		relative, within := trimPathPrefix(entry.Path, base)
		if !within || !strings.HasPrefix(relative, metadataDirectory+"/") {
			continue
		}
		if err := copyNginxBoundMetadataEntry(targetRoot, entry, destination, relative); err != nil {
			return err
		}
		count++
	}
	if count == 0 {
		return fmt.Errorf("route %s has no %s metadata", base, metadataDirectory)
	}
	return nil
}

func copyNginxBoundMetadataEntry(targetRoot *os.Root, entry manifest.Entry, destinationRoot, relative string) (resultErr error) {
	name := filepath.FromSlash(entry.Path)
	before, err := targetRoot.Lstat(name)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() != entry.Size {
		return errors.Join(err, fmt.Errorf("metadata %s is not the expected regular file", entry.Path))
	}
	source, err := targetRoot.Open(name)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, source.Close()) }()
	opened, statErr := source.Stat()
	after, lstatErr := targetRoot.Lstat(name)
	if statErr != nil || lstatErr != nil || !os.SameFile(before, opened) || !os.SameFile(before, after) {
		return errors.Join(statErr, lstatErr, errors.New("metadata changed while opening"))
	}
	destination := filepath.Join(destinationRoot, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(output, hasher), source)
	closeErr := errors.Join(output.Sync(), output.Close())
	last, lastErr := source.Stat()
	coordinate, coordinateErr := targetRoot.Lstat(name)
	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if copyErr != nil || closeErr != nil || lastErr != nil || coordinateErr != nil || written != entry.Size || actualSHA != entry.HashString() ||
		!os.SameFile(opened, last) || !os.SameFile(opened, coordinate) {
		return errors.Join(copyErr, closeErr, lastErr, coordinateErr, fmt.Errorf("metadata %s changed or differs while staging", entry.Path))
	}
	return nil
}

type nginxBoundPayloadFile struct {
	file     *os.File
	root     *os.Root
	relative string
	identity os.FileInfo
	size     int64
}

func openNginxBoundPayload(root *os.Root, relative string, entry manifest.Entry) (verify.PayloadReadSeekCloser, error) {
	if root == nil || !(strings.HasPrefix(entry.Path, "Packages/") || strings.HasPrefix(entry.Path, "pool/")) {
		return nil, errors.New("invalid bound package payload request")
	}
	name := filepath.FromSlash(relative)
	before, err := root.Lstat(name)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() != entry.Size {
		return nil, errors.Join(err, fmt.Errorf("bound package payload %s is unavailable", relative))
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	after, lstatErr := root.Lstat(name)
	if statErr != nil || lstatErr != nil || !os.SameFile(before, opened) || !os.SameFile(before, after) {
		return nil, errors.Join(statErr, lstatErr, file.Close(), errors.New("bound package payload changed while opening"))
	}
	return &nginxBoundPayloadFile{file: file, root: root, relative: name, identity: opened, size: entry.Size}, nil
}

func (file *nginxBoundPayloadFile) Read(buffer []byte) (int, error) { return file.file.Read(buffer) }
func (file *nginxBoundPayloadFile) ReadAt(buffer []byte, offset int64) (int, error) {
	return file.file.ReadAt(buffer, offset)
}
func (file *nginxBoundPayloadFile) Seek(offset int64, whence int) (int64, error) {
	return file.file.Seek(offset, whence)
}
func (file *nginxBoundPayloadFile) Close() error {
	if file == nil || file.file == nil {
		return nil
	}
	last, statErr := file.file.Stat()
	coordinate, coordinateErr := file.root.Lstat(file.relative)
	closeErr := file.file.Close()
	file.file = nil
	if statErr != nil || coordinateErr != nil || closeErr != nil || !os.SameFile(file.identity, last) || !os.SameFile(file.identity, coordinate) || last.Size() != file.size {
		return errors.Join(statErr, coordinateErr, closeErr, errors.New("bound package payload changed while verifying"))
	}
	return nil
}
