package cli

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
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
)

const localServingJournalSchema = "sow-local-serving-journal/v1"

const localServingJournalMaxBytes = 1 << 20

const localServingCanonicalManifestMaxBytes = 1 << 30

var (
	localServingJournalNamePattern = regexp.MustCompile(`^[0-9a-f]{32}\.json$`)
)

type localServingPhase string

type localServingRecoveryTrustBoundary string

const (
	localServingInstallIntent   localServingPhase = "install-intent"
	localServingGenerationReady localServingPhase = "generation-ready"
	localServingStateCommitted  localServingPhase = "state-committed"
	localServingPointerFlipped  localServingPhase = "pointer-flipped"
)

const (
	localServingRecoveryTrustEntry           localServingRecoveryTrustBoundary = "entry"
	localServingRecoveryTrustBeforeCanonical localServingRecoveryTrustBoundary = "before-canonical"
	localServingRecoveryTrustAfterCanonical  localServingRecoveryTrustBoundary = "after-canonical"
	localServingRecoveryTrustAfterPointer    localServingRecoveryTrustBoundary = "after-pointer"
)

type localServingJournal struct {
	Schema               string             `json:"schema"`
	ID                   string             `json:"id"`
	Phase                localServingPhase  `json:"phase"`
	TargetRoot           string             `json:"target_root"`
	PackageKeyringSHA256 string             `json:"package_keyring_sha256,omitempty"`
	Generation           serving.Generation `json:"generation"`
	Channel              serving.Channel    `json:"channel"`
}

type localServingActivationOptions struct {
	AfterPhase                        func(localServingPhase) error
	AfterGenerationInstallBeforeReady func() error
	// AfterLeafWorkerStart is a test-only scheduling seam. Production leaves it
	// nil; concurrency tests use it to prove that the bounded outer worker pool
	// actually admits more than one independent repo/OS/arch leaf.
	AfterLeafWorkerStart func(localYUMServingLeaf) error
	// BeforeLeafCommitTurn and AfterLeafCommit are test-only seams around the
	// deterministic canonical ledger/pointer commit turn.
	BeforeLeafCommitTurn func(localYUMServingLeaf) error
	AfterLeafCommit      func(localYUMServingLeaf) error
}

type localServingActivationResult struct {
	Generations        int
	Created            int
	Pointers           int
	PeakLeafWorkers    int
	PeakInstallWorkers int64
}

type localServingLeafActivationResult struct {
	activation localServingActivationResult
	output     string
}

type localServingCommitOrder struct {
	mutex  sync.Mutex
	ready  *sync.Cond
	next   int
	failed error
}

func newLocalServingCommitOrder() *localServingCommitOrder {
	order := &localServingCommitOrder{}
	order.ready = sync.NewCond(&order.mutex)
	return order
}

func (order *localServingCommitOrder) Wait(index int) error {
	order.mutex.Lock()
	defer order.mutex.Unlock()
	for order.next != index {
		order.ready.Wait()
	}
	if order.failed != nil {
		return fmt.Errorf("earlier local serving leaf failed before deterministic commit turn: %w", order.failed)
	}
	return nil
}

// Finish advances the turn even when a leaf fails before Wait. That property
// prevents a prepared later leaf from waiting forever and propagates the first
// error so no later canonical ledger/pointer commit can overtake it.
func (order *localServingCommitOrder) Finish(index int, leafErr error) {
	order.mutex.Lock()
	defer order.mutex.Unlock()
	for order.next != index {
		order.ready.Wait()
	}
	if leafErr != nil && order.failed == nil {
		order.failed = leafErr
	}
	order.next++
	order.ready.Broadcast()
}

type localYUMServingLeaf struct {
	repo config.Repo
	os   string
	arch string
}

func localServingLeavesFromViewLeaves(leaves []viewLeaf) []localYUMServingLeaf {
	result := make([]localYUMServingLeaf, 0, len(leaves))
	for _, leaf := range leaves {
		if leaf.repo.Type == "yum" {
			result = append(result, localYUMServingLeaf(leaf))
		}
	}
	return result
}

func localServingLeavesFromPrepared(prepared preparedPublication) []localYUMServingLeaf {
	var result []localYUMServingLeaf
	for _, projection := range prepared.projections {
		if projection.repo.Type == "yum" && projection.compatibilityID == "" {
			for _, leaf := range prepared.yumLeavesForProjection(projection) {
				result = append(result, localYUMServingLeaf(leaf))
			}
		}
	}
	return result
}

// preserveLocalServingRoutes extends the exact-reconcile input with the
// existing immutable _sow tree. Normal materialization may replace raw
// payload/index aliases, but delayed clients retain every generation they were
// already handed. The newly desired generation is installed only after raw
// metadata is complete and then joins this preservation set on the next run.
func preserveLocalServingRoutes(ctx context.Context, cfg *config.Config, targetRoot, desiredPath, txDir string, values commonFlags) (string, error) {
	routeRoot := filepath.Join(targetRoot, "_sow")
	info, err := os.Lstat(routeRoot)
	if errors.Is(err, os.ErrNotExist) {
		return desiredPath, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.Join(err, errors.New("local serving route root is not a real directory"))
	}
	routes := filepath.Join(txDir, "preserved-local-serving.tsv")
	if _, err := manifest.Scan(ctx, targetRoot, manifest.Scope{Path: "_sow"}, routes, manifest.ScanOptions{
		Workers: values.workers, ChunkEntries: values.chunk, TempDir: filepath.Join(cfg.StatePath(), "tmp"),
	}); err != nil {
		return "", err
	}
	merged := filepath.Join(txDir, "desired-with-local-serving.tsv")
	if err := mergeManifestFiles(desiredPath, routes, merged); err != nil {
		return "", err
	}
	return merged, nil
}

// preserveCanonicalLocalServingRoutes extends an explicit export's exact
// manifest with only the immutable generations, mirrorlists, and compatibility
// trust anchors positively owned by canonical lifecycle records for this exact
// target/view/leaf set. Unlike fixed product roots, explicit targets must not
// retain arbitrary or foreign bytes merely because they already live below
// the reserved _sow namespace.
func preserveCanonicalLocalServingRoutes(
	ctx context.Context,
	cfg *config.Config,
	canonical *state.Store,
	pool *repository.Store,
	targetRoot, view, desiredPath, txDir string,
	desiredLeaves []localYUMServingLeaf,
	compatibilityPrepared preparedPublication,
	values commonFlags,
) (string, error) {
	if cfg == nil || canonical == nil || pool == nil {
		return "", errors.New("canonical local serving preservation dependencies are unavailable")
	}
	targetRelative, err := localServingTargetRelative(cfg, targetRoot)
	if err != nil {
		return "", err
	}
	lifecycle, err := loadCanonicalServingLifecycle(canonical)
	if err != nil {
		return "", err
	}
	desired := make(map[string]struct{}, len(desiredLeaves))
	for _, leaf := range desiredLeaves {
		desired[servingLeafKey(leaf.repo.ID, leaf.os, leaf.arch)] = struct{}{}
	}
	projections, err := selectedPreparedYUMCompatibilityProjections(cfg, compatibilityPrepared)
	if err != nil {
		return "", err
	}
	selectedCompatibility := make(map[string]struct{}, len(projections))
	for _, projection := range projections {
		selectedCompatibility[projection.ID] = struct{}{}
	}
	stage := filepath.Join(txDir, "preserve-canonical-serving")
	if err := os.Mkdir(stage, 0o700); err != nil {
		return "", err
	}
	parts := []string{desiredPath}
	partIndex := 0
	nextPart := func(label string) string {
		partIndex++
		return filepath.Join(stage, fmt.Sprintf("%03d-%s.tsv", partIndex, label))
	}
	matchedLeaves := make(map[string]string, len(desired))
	matchedCompatibility := make(map[string]struct{})
	preservedGenerations := make(map[string]serving.Generation)
	installOptions := serving.InstallOptions{
		Workers: values.workers, ChunkEntries: values.chunk, TempDir: filepath.Join(cfg.StatePath(), "tmp"),
	}
	for _, record := range lifecycle.Channels {
		channel := record.Channel
		if channel.TargetRoot != targetRelative || channel.View != view {
			continue
		}
		leafKey := servingLeafKey(channel.Repo, channel.OS, channel.Arch)
		if _, wanted := desired[leafKey]; !wanted {
			continue
		}
		if prior, duplicate := matchedLeaves[leafKey]; duplicate {
			return "", fmt.Errorf("canonical channels %s and %s both own explicit serving leaf %s", prior, record.Path, leafKey)
		}
		matchedLeaves[leafKey] = record.Path

		pointerBody, exists, err := serving.ReadMirrorlist(targetRoot, channel.MirrorlistPath)
		if err != nil {
			return "", err
		}
		if exists {
			wanted, err := channel.MirrorlistBody()
			if err != nil {
				return "", err
			}
			if !bytes.Equal(pointerBody, wanted) {
				return "", fmt.Errorf("explicit target mirrorlist %s differs from canonical lifecycle", channel.MirrorlistPath)
			}
			if err := serving.ValidateMirrorlistPermissions(targetRoot, channel.MirrorlistPath); err != nil {
				return "", err
			}
			pointerManifest := nextPart("mirrorlist")
			if err := writeManifestEntryForBytes(pointerManifest, channel.MirrorlistPath, wanted); err != nil {
				return "", err
			}
			parts = append(parts, pointerManifest)
		}

		manifestPaths, err := serving.RetainedGenerationManifestPaths(channel)
		if err != nil {
			return "", err
		}
		for _, manifestPath := range manifestPaths {
			generationRecord, exists := lifecycle.Generations[manifestPath]
			if !exists {
				return "", fmt.Errorf("canonical channel %s retains missing generation %s", record.Path, manifestPath)
			}
			generation := generationRecord.Generation
			if prior, duplicate := preservedGenerations[generation.ID]; duplicate {
				if prior != generation {
					return "", fmt.Errorf("canonical generation ID %s has conflicting identities", generation.ID)
				}
				continue
			}
			generationRoot := filepath.Join(targetRoot, "_sow", "v1", "g", generation.ID)
			info, err := os.Lstat(generationRoot)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return "", errors.Join(err, fmt.Errorf("explicit target generation %s is not a real directory", generation.ID))
			}
			canonicalManifest := nextPart("generation-canonical")
			staged, err := stageCanonicalServingManifest(canonical, generation, canonicalManifest)
			if err != nil || !staged {
				return "", errors.Join(err, fmt.Errorf("canonical manifest for retained generation %s is unavailable", generation.ID))
			}
			if err := serving.ValidateInstalledGenerationCanonicalSubset(ctx, pool, targetRoot, generation, canonicalManifest, installOptions); err != nil {
				return "", fmt.Errorf("validate retained explicit generation %s: %w", generation.ID, err)
			}
			prefixed := nextPart("generation-prefixed")
			if err := prefixManifestPaths(canonicalManifest, prefixed, path.Join("_sow/v1/g", generation.ID)); err != nil {
				return "", err
			}
			parts = append(parts, prefixed)
			preservedGenerations[generation.ID] = generation
		}
		if _, compatibility := selectedCompatibility[channel.Repo]; compatibility {
			matchedCompatibility[channel.Repo] = struct{}{}
		}
	}

	for _, projection := range projections {
		if _, matched := matchedCompatibility[projection.ID]; !matched {
			continue
		}
		evidence, err := loadFrozenYUMCompatibilityServingEvidence(cfg, canonical, projection)
		if err != nil {
			return "", err
		}
		trust := []struct {
			route string
			body  []byte
		}{
			{route: config.YUMCompatibilityPackageTrustRoute(projection.ID), body: evidence.packageTrust},
			{route: config.YUMCompatibilityRepositoryTrustRoute(projection.ID), body: evidence.repositoryTrust},
		}
		for _, item := range trust {
			filename := filepath.Join(targetRoot, filepath.FromSlash(item.route))
			if _, err := os.Lstat(filename); errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				return "", err
			}
			current, err := readStableRegularLimited(filename, maxSecretBytes)
			if err != nil {
				return "", err
			}
			if !bytes.Equal(current, item.body) {
				return "", fmt.Errorf("explicit target trust route %s differs from frozen evidence", item.route)
			}
			if err := serving.ValidateHostableFile(targetRoot, item.route); err != nil {
				return "", fmt.Errorf("explicit target trust route %s is not directly hostable: %w", item.route, err)
			}
			trustManifest := nextPart("compatibility-trust")
			if err := writeManifestEntryForBytes(trustManifest, item.route, item.body); err != nil {
				return "", err
			}
			parts = append(parts, trustManifest)
		}
	}
	if len(parts) == 1 {
		return desiredPath, nil
	}
	merged := filepath.Join(stage, "desired-with-canonical-serving.tsv")
	if err := mergePublicationManifests(parts, merged, stage); err != nil {
		return "", err
	}
	return merged, nil
}

func preflightMutableYUMServing(cfg *config.Config, repos []config.Repo, view, override string, explicitTarget bool) (string, error) {
	hasYUM := false
	viewConfig, mutableView := cfg.Views[view]
	for _, repo := range repos {
		if repo.Type == "yum" && (!mutableView || viewIncludesRepo(viewConfig, repo.ID)) {
			hasYUM = true
			break
		}
	}
	if !hasYUM {
		return "", nil
	}
	if view != "latest" && view != "beta" && view != "stable" {
		return "", nil
	}
	if explicitTarget {
		if override == "" {
			return "", errors.New("--serving-base-url is required when exporting a mutable YUM view to an explicit --target")
		}
		wantPath := ""
		if view == "stable" {
			wantPath = "/pro/v1/basic"
		}
		if err := config.ValidateServingBaseURL(strings.TrimSuffix(override, "/"), wantPath); err != nil {
			return "", fmt.Errorf("--serving-base-url: %w", err)
		}
		return strings.TrimSuffix(override, "/"), nil
	}
	return cfg.ServingBaseURL(view)
}

func defaultMutableServingTarget(cfg *config.Config, view string) (string, error) {
	switch view {
	case "latest":
		return cfg.Root, nil
	case "beta":
		return filepath.Join(cfg.Root, config.StateDirectory, "materialized", "beta"), nil
	case "stable":
		return filepath.Join(cfg.Root, config.StateDirectory, "origin", "gated"), nil
	default:
		return "", fmt.Errorf("view %q has no mutable serving root", view)
	}
}

func localServingTargetIdentity(cfg *config.Config, view, targetRoot, baseURL string) (serving.TargetIdentity, error) {
	targetAbs, err := filepath.Abs(targetRoot)
	if err != nil {
		return serving.TargetIdentity{}, err
	}
	relative, err := filepath.Rel(cfg.Root, targetAbs)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return serving.TargetIdentity{}, errors.New("local serving target escapes repository root")
	}
	if relative == "" {
		relative = "."
	}
	return serving.NewTargetIdentity(view, filepath.ToSlash(relative), baseURL)
}

func localYUMServingReady(cfg *config.Config, canonical *state.Store, repos []config.Repo, view, repositoryKeySHA string, values commonFlags, requireRouteCapability ...bool) (bool, error) {
	if len(requireRouteCapability) > 1 {
		return false, errors.New("local serving route-capability mode may be specified only once")
	}
	baseURL, err := preflightMutableYUMServing(cfg, repos, view, "", false)
	if err != nil {
		return false, err
	}
	routeLeaves, err := selectedMutableRoutePhysicalLeaves(cfg, canonical, repos, view, values)
	if err != nil {
		return false, err
	}
	if len(routeLeaves) == 0 {
		return true, nil
	}
	leaves := localServingLeavesFromViewLeaves(routeLeaves)
	configSHA, err := cfg.CanonicalSHA256()
	if err != nil {
		return false, err
	}
	targetRoot, err := defaultMutableServingTarget(cfg, view)
	if err != nil {
		return false, err
	}
	var targetIdentity serving.TargetIdentity
	if len(leaves) != 0 {
		targetIdentity, err = localServingTargetIdentity(cfg, view, targetRoot, baseURL)
		if err != nil {
			return false, err
		}
	}
	pool, err := repository.NewStore(cfg.Root)
	if err != nil {
		return false, err
	}
	txDir, err := newTransactionDir(cfg.StatePath(), "serving-ready-")
	if err != nil {
		return false, err
	}
	defer os.RemoveAll(txDir)
	for index, leaf := range leaves {
		ref, err := state.ViewRef(view, leaf.repo.ID, leaf.os, leaf.arch)
		if err != nil {
			return false, err
		}
		commit, exists, err := canonical.Ref(ref)
		if err != nil {
			return false, err
		}
		if !exists {
			continue
		}
		channelPath := serving.ChannelStatePath(serving.Channel{TargetID: targetIdentity.ID, View: view, Repo: leaf.repo.ID, OS: leaf.os, Arch: leaf.arch})
		channelBody, exists, err := readOptionalCanonical(canonical, channelPath)
		if err != nil {
			return false, err
		}
		if !exists {
			return false, nil
		}
		channel, err := serving.DecodeChannel(channelBody)
		if err != nil {
			return false, fmt.Errorf("decode local serving channel %s: %w", channelPath, err)
		}
		legacyRoot, err := leaf.repo.PathForArch(leaf.arch)
		if err != nil {
			return false, err
		}
		if channel.View != view || channel.Repo != leaf.repo.ID || channel.OS != leaf.os || channel.Arch != leaf.arch || channel.LegacyRoot != legacyRoot ||
			channel.RefCommit != commit.String() || channel.ConfigSHA256 != configSHA || channel.RepositoryKeySHA256 != repositoryKeySHA || channel.BaseURL != baseURL ||
			channel.TargetID != targetIdentity.ID || channel.TargetRoot != targetIdentity.Root {
			return false, nil
		}
		installOptions := serving.InstallOptions{Workers: values.workers, ChunkEntries: values.chunk, TempDir: filepath.Join(cfg.StatePath(), "tmp")}
		if _, err := ensureLocalServingChannelGenerations(context.Background(), canonical, pool, targetRoot, channel, 0, filepath.Join(txDir, fmt.Sprintf("channel-%06d", index)), installOptions, false); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return false, nil
			}
			return false, fmt.Errorf("validate retained local serving generations: %w", err)
		}
		pointerBody, pointerExists, err := serving.ReadMirrorlist(targetRoot, channel.MirrorlistPath)
		if err != nil {
			return false, err
		}
		wanted, err := channel.MirrorlistBody()
		if err != nil {
			return false, err
		}
		if !pointerExists || !bytes.Equal(pointerBody, wanted) {
			return false, nil
		}
		if err := serving.ValidateMirrorlistPermissions(targetRoot, channel.MirrorlistPath); err != nil {
			return false, fmt.Errorf("validate local serving mirrorlist permissions: %w", err)
		}
	}
	if len(requireRouteCapability) == 0 || !requireRouteCapability[0] {
		return true, nil
	}
	return localMaterializedRouteReceiptsReady(context.Background(), cfg, canonical, pool, view, targetRoot, routeLeaves, txDir, values)
}

// localMaterializedRouteReceiptsReady keeps the unchanged fast path behind the
// same capability Nginx consumes. Missing or stale expected receipts are a
// repairable cache miss and force full preparation; malformed/orphan canonical
// ledger state remains an error because a partial rewrite cannot prove what it
// is allowed to replace.
func localMaterializedRouteReceiptsReady(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, view, targetRoot string, selected []viewLeaf, txDir string, values commonFlags) (bool, error) {
	viewConfig, exists := cfg.Views[view]
	if !exists {
		return false, fmt.Errorf("unknown materialized route view %q", view)
	}
	source := materializeCanonicalSource{ID: view, Public: viewConfig.Access == "public"}
	owners, err := completeSelectedMaterializedRouteOwners(cfg, canonical, source, selected)
	if err != nil {
		return false, err
	}
	if len(owners) == 0 {
		return true, nil
	}
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		return false, err
	}
	targetSHA, err := serving.MaterializedRouteTargetSHA256(targetRoot)
	if err != nil {
		return false, err
	}
	ledgers, err := loadMaterializedRouteLedgersAt(canonical, head, targetSHA, view, txDir)
	if err != nil {
		return false, err
	}
	configSHA, err := cfg.CanonicalSHA256()
	if err != nil {
		return false, err
	}
	matched, err := matchNginxOrdinaryRouteLedgers(canonical, head, owners, ledgers, view, targetSHA, configSHA)
	if err != nil {
		return false, nil
	}
	bound, err := openBoundMaterializedRouteTarget(targetRoot)
	if err != nil {
		return false, nil
	}
	defer bound.Close()
	options := serving.InstallOptions{Workers: values.workers, ChunkEntries: values.chunk, TempDir: filepath.Join(cfg.StatePath(), "tmp")}
	for _, item := range matched {
		if err := serving.ValidateMaterializedRouteRoot(ctx, pool, bound.root, item.ledger.Receipt, item.ledger.ExactManifest, item.ledger.PayloadManifest, options); err != nil {
			return false, nil
		}
	}
	if err := bound.Verify(); err != nil {
		return false, nil
	}
	return true, nil
}

func stageCanonicalServingManifest(canonical *state.Store, generation serving.Generation, destination string) (bool, error) {
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		return false, errors.Join(err, errors.New("canonical HEAD is unavailable for serving manifest staging"))
	}
	return stageCanonicalServingManifestAt(canonical, head, generation, destination)
}

func stageCanonicalServingManifestAt(canonical *state.Store, commit plumbing.Hash, generation serving.Generation, destination string) (bool, error) {
	source, err := canonical.OpenPathAt(commit, serving.GenerationManifestStatePath(generation))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	limited := &io.LimitedReader{R: source, N: localServingCanonicalManifestMaxBytes + 1}
	copyErr := manifest.AtomicCopy(destination, limited, 0o600)
	closeErr := source.Close()
	if copyErr != nil || closeErr != nil {
		return false, errors.Join(copyErr, closeErr)
	}
	if limited.N == 0 {
		_ = os.Remove(destination)
		return false, fmt.Errorf("canonical serving generation manifest exceeds %d-byte safety limit", localServingCanonicalManifestMaxBytes)
	}
	return true, nil
}

// ensureLocalServingChannelGenerations resolves every retained pin to its
// exact canonical generation and proves the corresponding physical copy. In
// repair mode an absent copy is rebuilt from CAS; an occupied but drifted copy
// still fails closed. start=1 skips the current generation after a caller has
// already installed it and validates only Previous.
func ensureLocalServingChannelGenerations(
	ctx context.Context,
	canonical *state.Store,
	pool *repository.Store,
	targetRoot string,
	channel serving.Channel,
	start int,
	manifestPrefix string,
	installOptions serving.InstallOptions,
	repair bool,
) (int, error) {
	coordinates, err := channel.RetainedGenerationCoordinates()
	if err != nil {
		return 0, err
	}
	pins, err := channel.RetainedGenerationPins()
	if err != nil {
		return 0, err
	}
	if start < 0 || start > len(coordinates) || len(coordinates) != len(pins) {
		return 0, errors.New("invalid retained generation validation range")
	}
	created := 0
	for index := start; index < len(coordinates); index++ {
		coordinate := coordinates[index]
		jsonPath, err := coordinate.JSONPath()
		if err != nil {
			return created, err
		}
		body, exists, err := readOptionalCanonical(canonical, jsonPath)
		if err != nil || !exists {
			return created, errors.Join(err, fmt.Errorf("retained serving generation record is missing: %s", jsonPath))
		}
		generation, err := serving.DecodeGeneration(body)
		if err != nil {
			return created, fmt.Errorf("decode retained serving generation %s: %w", jsonPath, err)
		}
		pin, err := serving.PinGeneration(generation)
		if err != nil || pin != pins[index] {
			return created, errors.Join(err, fmt.Errorf("retained serving generation pin differs from %s", jsonPath))
		}
		if index == 0 && (generation.LegacyRoot != channel.LegacyRoot || generation.RefCommit != channel.RefCommit || generation.ConfigSHA256 != channel.ConfigSHA256 || generation.RepositoryKeySHA256 != channel.RepositoryKeySHA256) {
			return created, errors.New("current serving channel identity differs from its generation")
		}
		manifestPath := fmt.Sprintf("%s-%06d.tsv", manifestPrefix, index)
		exists, err = stageCanonicalServingManifest(canonical, generation, manifestPath)
		if err != nil || !exists {
			return created, errors.Join(err, fmt.Errorf("retained serving generation manifest is missing: %s", jsonPath))
		}
		if repair {
			installed, err := serving.InstallGeneration(ctx, pool, targetRoot, generation, manifestPath, installOptions)
			if err != nil {
				return created, fmt.Errorf("restore retained serving generation %s: %w", generation.ID, err)
			}
			if installed.Created {
				created++
			}
			continue
		}
		if err := serving.ValidateInstalledGeneration(ctx, pool, targetRoot, generation, manifestPath, installOptions); err != nil {
			return created, fmt.Errorf("validate retained serving generation %s: %w", generation.ID, err)
		}
	}
	return created, nil
}

func activateLocalYUMServing(
	ctx context.Context,
	cfg *config.Config,
	canonical *state.Store,
	pool *repository.Store,
	source materializeCanonicalSource,
	targetRoot, baseURL, repositoryKeySHA, txDir string,
	leaves []localYUMServingLeaf,
	values commonFlags,
	options localServingActivationOptions,
	stdout io.Writer,
) (result localServingActivationResult, resultErr error) {
	if len(leaves) == 0 {
		return result, nil
	}
	if source.Snapshot {
		return result, errors.New("immutable snapshots do not use mutable YUM serving channels")
	}
	configSHA, err := cfg.CanonicalSHA256()
	if err != nil {
		return result, err
	}
	targetRoot, err = filepath.Abs(targetRoot)
	if err != nil {
		return result, err
	}
	targetRelative, err := filepath.Rel(cfg.Root, targetRoot)
	if err != nil || targetRelative == ".." || strings.HasPrefix(targetRelative, ".."+string(filepath.Separator)) {
		return result, errors.New("local serving target escapes repository root")
	}
	if targetRelative == "" {
		targetRelative = "."
	}
	targetRelative = filepath.ToSlash(targetRelative)
	targetIdentity, err := serving.NewTargetIdentity(source.ID, targetRelative, baseURL)
	if err != nil {
		return result, err
	}
	transactionLeaves := make([]viewLeaf, 0, len(leaves))
	for _, leaf := range leaves {
		transactionLeaves = append(transactionLeaves, viewLeaf(leaf))
	}
	values, selectionOwner, err := beginMaterializationSelectionForSource(cfg, canonical, values, selectedMaterializationOperation(values, "materialize"), source, transactionLeaves, targetRoot, false, true)
	if err != nil {
		return result, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, finishMaterializationSelectedSet(cfg, values.materializeTrust, selectionOwner, resultErr))
	}()
	leaves = append([]localYUMServingLeaf(nil), leaves...)
	sort.Slice(leaves, func(i, j int) bool {
		left := leaves[i].repo.ID + "\x00" + leaves[i].os + "\x00" + leaves[i].arch
		right := leaves[j].repo.ID + "\x00" + leaves[j].os + "\x00" + leaves[j].arch
		return left < right
	})
	// Canonical state is a single Git worktree. Independent leaf reads and
	// physical generation installs may overlap, but no read is allowed to race
	// a canonical commit. The write side also covers the pointer flip so the
	// externally visible channel order remains deterministic and recoverable.
	var canonicalGate sync.RWMutex
	var activeLeaves, peakLeaves atomic.Int64
	commitOrder := newLocalServingCommitOrder()
	workerBudget := values.workers
	if options.AfterPhase != nil || options.AfterGenerationInstallBeforeReady != nil {
		// Fault-injection hooks describe one exact phase boundary. Preserve their
		// historical deterministic semantics rather than invoking them from
		// multiple goroutines.
		workerBudget = 1
	}
	tasks := make([]boundedOrderedTask[localServingLeafActivationResult], 0, len(leaves))
	for index, leaf := range leaves {
		index, leaf := index, leaf
		key := leaf.repo.ID + "/" + leaf.os + "/" + leaf.arch
		tasks = append(tasks, boundedOrderedTask[localServingLeafActivationResult]{key: key, run: func(ctx context.Context, innerWorkers int) (leafResult localServingLeafActivationResult, leafErr error) {
			active := activeLeaves.Add(1)
			for observed := peakLeaves.Load(); active > observed && !peakLeaves.CompareAndSwap(observed, active); observed = peakLeaves.Load() {
			}
			defer func() {
				activeLeaves.Add(-1)
				commitOrder.Finish(index, leafErr)
			}()
			if options.AfterLeafWorkerStart != nil {
				if err := options.AfterLeafWorkerStart(leaf); err != nil {
					return localServingLeafActivationResult{}, err
				}
			}
			taskValues := values
			taskValues.workers = innerWorkers
			var err error
			taskValues.materializeUnit, err = materializationUnitFor(values, "serving", source.ID, leaf.repo.ID, leaf.os, leaf.arch, targetRoot)
			if err != nil {
				return localServingLeafActivationResult{}, err
			}
			leafResult, err = activateLocalYUMServingLeaf(ctx, cfg, canonical, pool, source, targetRoot, targetRelative, targetIdentity,
				configSHA, repositoryKeySHA, txDir, index, leaf, taskValues, options, &canonicalGate, commitOrder)
			if err == nil {
				err = markMaterializationUnitComplete(taskValues, cfg)
			}
			return leafResult, err
		}})
	}
	leafResults, err := runBoundedOrdered(ctx, workerBudget, tasks)
	result.PeakLeafWorkers = int(peakLeaves.Load())
	if err != nil {
		return result, err
	}
	for _, leafResult := range leafResults {
		result.Generations += leafResult.activation.Generations
		result.Created += leafResult.activation.Created
		result.Pointers += leafResult.activation.Pointers
		result.PeakInstallWorkers = max(result.PeakInstallWorkers, leafResult.activation.PeakInstallWorkers)
		if _, err := io.WriteString(stdout, leafResult.output); err != nil {
			return result, err
		}
	}
	return result, nil
}

func activateLocalYUMServingLeaf(
	ctx context.Context,
	cfg *config.Config,
	canonical *state.Store,
	pool *repository.Store,
	source materializeCanonicalSource,
	targetRoot, targetRelative string,
	targetIdentity serving.TargetIdentity,
	configSHA, repositoryKeySHA, txDir string,
	index int,
	leaf localYUMServingLeaf,
	values commonFlags,
	options localServingActivationOptions,
	canonicalGate *sync.RWMutex,
	commitOrder *localServingCommitOrder,
) (localServingLeafActivationResult, error) {
	var outcome localServingLeafActivationResult
	var output bytes.Buffer
	result := &outcome.activation
	if _, err := requireMaterializationYUMTrust(values, cfg, leaf.repo, nil, materializeTrustServingLeafBefore); err != nil {
		return outcome, err
	}
	restoreMirrorlist := func(channel serving.Channel) (bool, error) {
		return restoreLocalServingMirrorlistGuarded(values, cfg, leaf.repo, targetRoot, channel)
	}
	legacyRoot, err := leaf.repo.PathForArch(leaf.arch)
	if err != nil {
		return outcome, err
	}
	installOptions := serving.InstallOptions{Workers: values.workers, ChunkEntries: values.chunk, TempDir: filepath.Join(cfg.StatePath(), "tmp")}
	waitCommitTurn := func() error {
		if options.BeforeLeafCommitTurn != nil {
			if err := options.BeforeLeafCommitTurn(leaf); err != nil {
				return err
			}
		}
		return commitOrder.Wait(index)
	}
	var (
		identity        serving.Identity
		current         *serving.Channel
		parent          *serving.Channel
		generation      serving.Generation
		installed       serving.InstallResult
		pointerRestored bool
		replayed        bool
	)
	canonicalManifest := filepath.Join(txDir, fmt.Sprintf("local-serving-current-%06d.tsv", index))
	canonicalGate.RLock()
	readErr := func() error {
		_, _, commit, err := source.resolveLeaf(canonical, leaf.repo.ID, leaf.os, leaf.arch)
		if err != nil {
			return err
		}
		identity = serving.Identity{
			View: source.ID, Repo: leaf.repo.ID, OS: leaf.os, Arch: leaf.arch, LegacyRoot: legacyRoot,
			RefCommit: commit.String(), ConfigSHA256: configSHA, RepositoryKeySHA256: repositoryKeySHA,
		}
		coordinate := serving.Generation{View: source.ID, Repo: leaf.repo.ID, OS: leaf.os, Arch: leaf.arch}
		current, err = readLocalServingChannel(canonical, coordinate, targetIdentity)
		if err != nil {
			return err
		}
		parent = current
		if parent == nil {
			parent, err = findServingTargetMigrationParent(canonical, targetIdentity, coordinate)
			if err != nil {
				return err
			}
		}
		generation, installed, pointerRestored, replayed, err = replayCurrentLocalYUMServing(ctx, canonical, pool, targetRoot, targetIdentity, current, identity, cfg.State.YUMGenerationRetention, canonicalManifest, installOptions, restoreMirrorlist)
		return err
	}()
	canonicalGate.RUnlock()
	if readErr != nil {
		return outcome, readErr
	}
	if replayed {
		result.PeakInstallWorkers = max(result.PeakInstallWorkers, installed.PeakWorkers)
		result.Generations++
		if installed.Created {
			result.Created++
		}
		if pointerRestored {
			result.Pointers++
		}
		pointerStatus := "unchanged"
		if pointerRestored {
			pointerStatus = "restored"
		}
		fmt.Fprintf(&output, "serving view=%s repo=%s os=%s arch=%s generation=%s created=%t pointer=%s\n", source.ID, leaf.repo.ID, leaf.os, leaf.arch, generation.ID, installed.Created, pointerStatus)
		if err := waitCommitTurn(); err != nil {
			return outcome, err
		}
		outcome.output = output.String()
		return outcome, nil
	}

	rawManifestPath := filepath.Join(txDir, fmt.Sprintf("local-serving-raw-%06d.tsv", index))
	if _, err := manifest.Scan(ctx, targetRoot, manifest.Scope{Path: legacyRoot}, rawManifestPath, manifest.ScanOptions{
		Workers: values.workers, ChunkEntries: values.chunk, TempDir: filepath.Join(cfg.StatePath(), "tmp"),
	}); err != nil {
		return outcome, fmt.Errorf("scan local YUM serving leaf %s: %w", legacyRoot, err)
	}
	manifestPath := rawManifestPath
	if parent != nil {
		closureDir := filepath.Join(txDir, fmt.Sprintf("local-serving-closure-%06d", index))
		if err := os.Mkdir(closureDir, 0o700); err != nil {
			return outcome, err
		}
		manifestPath = filepath.Join(closureDir, "manifest.tsv")
		canonicalGate.RLock()
		err := mergeRetainedYUMPackageClosure(canonical, parent, cfg.State.YUMGenerationRetention, rawManifestPath, manifestPath, closureDir)
		canonicalGate.RUnlock()
		if err != nil {
			return outcome, fmt.Errorf("assemble retained YUM package closure for %s: %w", legacyRoot, err)
		}
	}
	manifestFile, err := os.Open(manifestPath)
	if err != nil {
		return outcome, err
	}
	generation, deriveErr := serving.DeriveGeneration(identity, manifestFile)
	closeErr := manifestFile.Close()
	if deriveErr != nil || closeErr != nil {
		return outcome, errors.Join(deriveErr, closeErr)
	}
	desiredWithoutParent, err := serving.NewChannelForTarget(generation, targetIdentity, nil, cfg.State.YUMGenerationRetention)
	if err != nil {
		return outcome, err
	}
	desiredCurrent := desiredWithoutParent
	if current != nil {
		desiredCurrent.Previous = append([]serving.GenerationPin(nil), current.Previous...)
		if len(desiredCurrent.Previous) > cfg.State.YUMGenerationRetention {
			desiredCurrent.Previous = desiredCurrent.Previous[:cfg.State.YUMGenerationRetention]
		}
	}
	if current != nil && localServingChannelMatches(*current, desiredCurrent) {
		canonicalGate.RLock()
		restoreErr := func() error {
			if err := requireExistingCanonicalServingGeneration(canonical, generation, manifestPath); err != nil {
				return err
			}
			canonicalManifest := filepath.Join(txDir, fmt.Sprintf("local-serving-canonical-%06d.tsv", index))
			exists, err := stageCanonicalServingManifest(canonical, generation, canonicalManifest)
			if err != nil || !exists {
				return errors.Join(err, errors.New("canonical serving generation manifest disappeared"))
			}
			installed, err = serving.InstallGeneration(ctx, pool, targetRoot, generation, canonicalManifest, installOptions)
			if err != nil {
				return fmt.Errorf("restore unchanged local YUM generation %s: %w", generation.ID, err)
			}
			previousCreated, err := ensureLocalServingChannelGenerations(ctx, canonical, pool, targetRoot, *current, 1, filepath.Join(txDir, fmt.Sprintf("unchanged-retained-%06d", index)), installOptions, true)
			if err != nil {
				return err
			}
			result.Created += previousCreated
			pointerRestored, err = restoreMirrorlist(*current)
			return err
		}()
		canonicalGate.RUnlock()
		if restoreErr != nil {
			return outcome, fmt.Errorf("restore unchanged local YUM channel: %w", restoreErr)
		}
		result.PeakInstallWorkers = max(result.PeakInstallWorkers, installed.PeakWorkers)
		result.Generations++
		if installed.Created {
			result.Created++
		}
		if pointerRestored {
			result.Pointers++
		}
		pointerStatus := "unchanged"
		if pointerRestored {
			pointerStatus = "restored"
		}
		fmt.Fprintf(&output, "serving view=%s repo=%s os=%s arch=%s generation=%s created=%t pointer=%s\n", source.ID, leaf.repo.ID, leaf.os, leaf.arch, generation.ID, installed.Created || result.Created != 0, pointerStatus)
		if err := waitCommitTurn(); err != nil {
			return outcome, err
		}
		outcome.output = output.String()
		return outcome, nil
	}
	if parent != nil {
		canonicalGate.RLock()
		parentCreated, parentErr := ensureLocalServingChannelGenerations(ctx, canonical, pool, targetRoot, *parent, 0, filepath.Join(txDir, fmt.Sprintf("parent-retained-%06d", index)), installOptions, true)
		if parentErr == nil {
			var restored bool
			restored, parentErr = restoreMirrorlist(*parent)
			if restored {
				result.Pointers++
			}
		}
		canonicalGate.RUnlock()
		if parentErr != nil {
			return outcome, fmt.Errorf("restore local YUM parent retention set: %w", parentErr)
		}
		result.Created += parentCreated
	}
	if err := requireCurrentServingParent(targetRoot, parent, desiredWithoutParent.MirrorlistPath); err != nil {
		return outcome, err
	}
	var channel serving.Channel
	if parent != nil && parent.TargetID != targetIdentity.ID {
		channel, err = serving.NewChannelForTargetMigration(generation, targetIdentity, parent, cfg.State.YUMGenerationRetention)
	} else {
		channel, err = serving.NewChannelForTarget(generation, targetIdentity, parent, cfg.State.YUMGenerationRetention)
	}
	if err != nil {
		return outcome, err
	}
	packageKeyringSHA256, err := materializationYUMTrustDigest(values, cfg, leaf.repo)
	if err != nil {
		return outcome, err
	}
	journal := localServingJournal{
		Schema: localServingJournalSchema, Phase: localServingInstallIntent, TargetRoot: targetRelative,
		PackageKeyringSHA256: packageKeyringSHA256, Generation: generation, Channel: channel,
	}
	journal.ID = localServingJournalID(journal)
	if err := createLocalServingJournal(cfg.StatePath(), journal); err != nil {
		return outcome, err
	}
	if err := runLocalServingPhaseHook(options, journal.Phase); err != nil {
		return outcome, err
	}
	installed, err = serving.InstallGeneration(ctx, pool, targetRoot, generation, manifestPath, installOptions)
	if err != nil {
		return outcome, fmt.Errorf("install local YUM generation %s: %w", generation.ID, err)
	}
	result.PeakInstallWorkers = max(result.PeakInstallWorkers, installed.PeakWorkers)
	if options.AfterGenerationInstallBeforeReady != nil {
		if err := options.AfterGenerationInstallBeforeReady(); err != nil {
			return outcome, err
		}
	}
	journal.Phase = localServingGenerationReady
	if err := updateLocalServingJournal(cfg.StatePath(), journal); err != nil {
		return outcome, err
	}
	if err := runLocalServingPhaseHook(options, journal.Phase); err != nil {
		return outcome, err
	}
	result.Generations++
	if installed.Created {
		result.Created++
	}
	if err := waitCommitTurn(); err != nil {
		return outcome, err
	}
	var changed bool
	canonicalGate.Lock()
	commitErr := func() error {
		if _, err := requireMaterializationYUMTrust(values, cfg, leaf.repo, nil, materializeTrustServingPointerBefore); err != nil {
			return err
		}
		if _, _, err := persistLocalServingLedger(ctx, canonical, generation, channel, manifestPath, txDir); err != nil {
			return stateMutationError("commit local YUM serving ledger", err)
		}
		journal.Phase = localServingStateCommitted
		if err := updateLocalServingJournal(cfg.StatePath(), journal); err != nil {
			return err
		}
		if err := runLocalServingPhaseHook(options, journal.Phase); err != nil {
			return err
		}
		if _, err := requireMaterializationYUMTrust(values, cfg, leaf.repo, nil, materializeTrustServingLedgerAfter); err != nil {
			return err
		}
		var err error
		changed, err = serving.ReconcileMirrorlist(targetRoot, channel)
		if err != nil {
			return fmt.Errorf("flip local YUM mirrorlist: %w", err)
		}
		rollbackUntrustedPointer := func(trustErr error) error {
			if rollbackErr := rollbackLocalServingMirrorlist(targetRoot, parent, channel); rollbackErr != nil {
				return errors.Join(trustErr, fmt.Errorf("roll back untrusted local YUM mirrorlist: %w", rollbackErr))
			}
			changed = false
			journal.Phase = localServingStateCommitted
			if journalErr := updateLocalServingJournal(cfg.StatePath(), journal); journalErr != nil {
				return errors.Join(trustErr, fmt.Errorf("persist recoverable local serving trust failure: %w", journalErr))
			}
			return trustErr
		}
		if _, trustErr := requireMaterializationYUMTrust(values, cfg, leaf.repo, nil, materializeTrustServingPointerAfter); trustErr != nil {
			return rollbackUntrustedPointer(trustErr)
		}
		journal.Phase = localServingPointerFlipped
		if err := updateLocalServingJournal(cfg.StatePath(), journal); err != nil {
			return err
		}
		if err := runLocalServingPhaseHook(options, journal.Phase); err != nil {
			return err
		}
		if _, trustErr := requireMaterializationYUMTrust(values, cfg, leaf.repo, nil, materializeTrustServingPointerAfter); trustErr != nil {
			return rollbackUntrustedPointer(trustErr)
		}
		if options.AfterLeafCommit != nil {
			if err := options.AfterLeafCommit(leaf); err != nil {
				return err
			}
		}
		if _, trustErr := requireMaterializationYUMTrust(values, cfg, leaf.repo, nil, materializeTrustServingPointerAfter); trustErr != nil {
			return rollbackUntrustedPointer(trustErr)
		}
		return nil
	}()
	canonicalGate.Unlock()
	if commitErr != nil {
		return outcome, commitErr
	}
	if changed {
		result.Pointers++
	}
	if err := serving.ValidateInstalledGeneration(ctx, pool, targetRoot, generation, manifestPath, installOptions); err != nil {
		return outcome, err
	}
	if err := removeLocalServingJournal(cfg.StatePath(), journal.ID); err != nil {
		return outcome, err
	}
	fmt.Fprintf(&output, "serving view=%s repo=%s os=%s arch=%s generation=%s created=%t pointer=%t\n", source.ID, leaf.repo.ID, leaf.os, leaf.arch, generation.ID, installed.Created, changed)
	outcome.output = output.String()
	return outcome, nil
}

func runLocalServingPhaseHook(options localServingActivationOptions, phase localServingPhase) error {
	if options.AfterPhase == nil {
		return nil
	}
	return options.AfterPhase(phase)
}

func restoreLocalServingMirrorlistGuarded(values commonFlags, cfg *config.Config, repo config.Repo, targetRoot string, channel serving.Channel) (bool, error) {
	if _, err := requireMaterializationYUMTrust(values, cfg, repo, nil, materializeTrustServingRestoreBefore); err != nil {
		return false, err
	}
	changed, err := serving.RestoreMirrorlist(targetRoot, channel)
	if err != nil {
		return false, err
	}
	if _, trustErr := requireMaterializationYUMTrust(values, cfg, repo, nil, materializeTrustServingRestoreAfter); trustErr != nil {
		if !changed {
			return false, trustErr
		}
		_, rollbackErr := serving.RemoveMirrorlist(targetRoot, channel)
		if rollbackErr != nil {
			return false, errors.Join(trustErr, fmt.Errorf("roll back untrusted restored mirrorlist: %w", rollbackErr))
		}
		return false, trustErr
	}
	return changed, nil
}

func rollbackLocalServingMirrorlist(targetRoot string, parent *serving.Channel, current serving.Channel) error {
	if parent == nil {
		return serving.RollbackMirrorlist(targetRoot, current, nil, false)
	}
	if err := parent.Validate(); err != nil {
		return fmt.Errorf("validate local serving rollback parent: %w", err)
	}
	expectedTargetID := current.TargetID
	if current.ParentTargetID != "" {
		expectedTargetID = current.ParentTargetID
	}
	if parent.View != current.View || parent.Repo != current.Repo || parent.OS != current.OS || parent.Arch != current.Arch ||
		parent.MirrorlistPath != current.MirrorlistPath || parent.Generation != current.ParentGeneration ||
		parent.MirrorlistSHA256 != current.ParentMirrorlistSHA256 || parent.TargetID != expectedTargetID || parent.TargetRoot != current.TargetRoot {
		return errors.New("local serving rollback parent differs from the sealed channel parent")
	}
	prior, err := parent.MirrorlistBody()
	if err != nil {
		return fmt.Errorf("render local serving rollback parent: %w", err)
	}
	return serving.RollbackMirrorlist(targetRoot, current, prior, true)
}

func localServingChannelMatches(current, wanted serving.Channel) bool {
	return current.View == wanted.View && current.Repo == wanted.Repo && current.OS == wanted.OS && current.Arch == wanted.Arch &&
		current.Generation == wanted.Generation && current.ContentSHA256 == wanted.ContentSHA256 && current.ManifestSHA256 == wanted.ManifestSHA256 && current.LegacyRoot == wanted.LegacyRoot &&
		current.RefCommit == wanted.RefCommit && current.ConfigSHA256 == wanted.ConfigSHA256 && current.RepositoryKeySHA256 == wanted.RepositoryKeySHA256 &&
		current.BaseURL == wanted.BaseURL && current.MirrorlistPath == wanted.MirrorlistPath && current.MirrorlistSHA256 == wanted.MirrorlistSHA256 &&
		current.TargetID == wanted.TargetID && current.TargetRoot == wanted.TargetRoot && slices.Equal(current.Previous, wanted.Previous)
}

// replayCurrentLocalYUMServing preserves idempotency in units of real
// ref/config/key/target changes. A successor generation may intentionally
// contain unindexed payloads needed by transactions that read older metadata;
// rebuilding its closure on every identical command would consume that safety
// window without a real publication flip. The canonical manifest is therefore
// the only legal replay source when the frozen input identity is unchanged.
func replayCurrentLocalYUMServing(
	ctx context.Context,
	canonical *state.Store,
	pool *repository.Store,
	targetRoot string,
	target serving.TargetIdentity,
	current *serving.Channel,
	identity serving.Identity,
	previousRetention int,
	manifestPath string,
	installOptions serving.InstallOptions,
	restoreMirrorlist func(serving.Channel) (bool, error),
) (serving.Generation, serving.InstallResult, bool, bool, error) {
	var generation serving.Generation
	var installed serving.InstallResult
	if current == nil || previousRetention < 1 || current.TargetID != target.ID || current.TargetRoot != target.Root || current.BaseURL != target.BaseURL ||
		current.View != identity.View || current.Repo != identity.Repo || current.OS != identity.OS || current.Arch != identity.Arch || current.LegacyRoot != identity.LegacyRoot ||
		current.RefCommit != identity.RefCommit || current.ConfigSHA256 != identity.ConfigSHA256 || current.RepositoryKeySHA256 != identity.RepositoryKeySHA256 ||
		len(current.Previous) > previousRetention {
		return generation, installed, false, false, nil
	}
	body, exists, err := readOptionalCanonical(canonical, serving.GenerationStatePath(serving.Generation{
		ID: current.Generation, View: current.View, Repo: current.Repo, OS: current.OS, Arch: current.Arch,
	}))
	if err != nil || !exists {
		return generation, installed, false, false, errors.Join(err, errors.New("canonical serving channel points to a missing generation record"))
	}
	generation, err = serving.DecodeGeneration(body)
	if err != nil {
		return generation, installed, false, false, err
	}
	if generation.ID != current.Generation || generation.ContentSHA256 != current.ContentSHA256 || generation.ManifestSHA256 != current.ManifestSHA256 ||
		generation.View != current.View || generation.Repo != current.Repo || generation.OS != current.OS || generation.Arch != current.Arch || generation.LegacyRoot != current.LegacyRoot ||
		generation.RefCommit != current.RefCommit || generation.ConfigSHA256 != current.ConfigSHA256 || generation.RepositoryKeySHA256 != current.RepositoryKeySHA256 {
		return generation, installed, false, false, errors.New("canonical serving channel differs from its immutable generation")
	}
	manifestExists, err := stageCanonicalServingManifest(canonical, generation, manifestPath)
	if err != nil || !manifestExists {
		return generation, installed, false, false, errors.Join(err, errors.New("canonical serving generation manifest disappeared"))
	}
	if err := requireExistingCanonicalServingGeneration(canonical, generation, manifestPath); err != nil {
		return generation, installed, false, false, err
	}
	installed, err = serving.InstallGeneration(ctx, pool, targetRoot, generation, manifestPath, installOptions)
	if err != nil {
		return generation, installed, false, false, fmt.Errorf("restore unchanged local YUM generation %s: %w", generation.ID, err)
	}
	previousCreated, err := ensureLocalServingChannelGenerations(ctx, canonical, pool, targetRoot, *current, 1, strings.TrimSuffix(manifestPath, ".tsv")+"-retained", installOptions, true)
	if err != nil {
		return generation, installed, false, false, err
	}
	if previousCreated != 0 {
		installed.Created = true
	}
	if restoreMirrorlist == nil {
		return generation, installed, false, false, errors.New("local serving mirrorlist restore guard is unavailable")
	}
	pointerChanged, err := restoreMirrorlist(*current)
	if err != nil {
		return generation, installed, false, false, fmt.Errorf("restore committed local YUM mirrorlist: %w", err)
	}
	return generation, installed, pointerChanged, true, nil
}

func readLocalServingChannel(canonical *state.Store, generation serving.Generation, target serving.TargetIdentity) (*serving.Channel, error) {
	path := serving.ChannelStatePath(serving.Channel{TargetID: target.ID, View: generation.View, Repo: generation.Repo, OS: generation.OS, Arch: generation.Arch})
	body, exists, err := readOptionalCanonical(canonical, path)
	if err != nil || !exists {
		return nil, err
	}
	channel, err := serving.DecodeChannel(body)
	if err != nil {
		return nil, fmt.Errorf("decode canonical local serving channel %s: %w", path, err)
	}
	return &channel, nil
}

func findServingTargetMigrationParent(canonical *state.Store, target serving.TargetIdentity, generation serving.Generation) (*serving.Channel, error) {
	channels, _, err := loadCanonicalServingChannelIndex(canonical)
	if err != nil {
		return nil, err
	}
	var result *serving.Channel
	for _, record := range channels {
		candidate := record.Channel
		if candidate.TargetID == target.ID || candidate.TargetRoot != target.Root || candidate.View != generation.View || candidate.Repo != generation.Repo || candidate.OS != generation.OS || candidate.Arch != generation.Arch {
			continue
		}
		if result != nil {
			return nil, errors.New("multiple canonical serving targets claim the same physical mirrorlist coordinate")
		}
		copy := candidate
		result = &copy
	}
	return result, nil
}

func requireCurrentServingParent(targetRoot string, parent *serving.Channel, mirrorlistPath string) error {
	body, exists, err := serving.ReadMirrorlist(targetRoot, mirrorlistPath)
	if err != nil {
		return err
	}
	if parent == nil {
		if exists {
			return errors.New("local mirrorlist exists without a canonical parent channel")
		}
		return nil
	}
	wanted, err := parent.MirrorlistBody()
	if err != nil {
		return err
	}
	if !exists || !bytes.Equal(body, wanted) {
		return errors.New("local mirrorlist differs from its canonical parent channel")
	}
	return nil
}

func persistLocalServingLedger(ctx context.Context, canonical *state.Store, generation serving.Generation, channel serving.Channel, manifestPath, txDir string) (string, bool, error) {
	target := serving.TargetIdentity{Schema: serving.TargetSchema, ID: channel.TargetID, Root: channel.TargetRoot, BaseURL: channel.BaseURL}
	targetBody, err := target.Canonical(channel.View)
	if err != nil {
		return "", false, err
	}
	generationBody, err := generation.Canonical()
	if err != nil {
		return "", false, err
	}
	channelBody, err := channel.Canonical()
	if err != nil {
		return "", false, err
	}
	if err := requireCanonicalServingGeneration(canonical, generation, manifestPath); err != nil {
		return "", false, err
	}
	if err := requireCanonicalServingChannelParent(canonical, channel, channelBody); err != nil {
		return "", false, err
	}
	var deletePaths []string
	retiredPath := serving.RetiredGenerationStatePath(generation)
	if retiredBody, exists, err := readOptionalCanonical(canonical, retiredPath); err != nil {
		return "", false, err
	} else if exists {
		retired, err := serving.DecodeRetiredGeneration(retiredBody)
		if err != nil || retired.Generation != generation {
			return "", false, errors.Join(err, errors.New("retired serving generation identity differs from reactivated generation"))
		}
		retiredManifestPath := serving.RetiredGenerationManifestStatePath(generation)
		if err := validateCanonicalServingManifest(canonical, retiredManifestPath, generation); err != nil {
			return "", false, fmt.Errorf("validate retired serving generation deletion witness: %w", err)
		}
		deletePaths = append(deletePaths, retiredPath, retiredManifestPath)
	}
	if channel.ParentTargetID != "" {
		parentPath := serving.ChannelStatePath(serving.Channel{TargetID: channel.ParentTargetID, View: channel.View, Repo: channel.Repo, OS: channel.OS, Arch: channel.Arch})
		if _, exists, err := readOptionalCanonical(canonical, parentPath); err != nil {
			return "", false, err
		} else if exists {
			deletePaths = append(deletePaths, parentPath)
		}
	}
	if err := requireCanonicalServingTarget(canonical, target, targetBody); err != nil {
		return "", false, err
	}
	stageDir, err := os.MkdirTemp(txDir, "serving-ledger-")
	if err != nil {
		return "", false, err
	}
	generationStage := filepath.Join(stageDir, "generation.json")
	channelStage := filepath.Join(stageDir, "channel.json")
	manifestStage := filepath.Join(stageDir, "generation.tsv")
	targetStage := filepath.Join(stageDir, "target.json")
	if err := writeExclusiveBytes(targetStage, targetBody); err != nil {
		return "", false, err
	}
	if err := writeExclusiveBytes(generationStage, generationBody); err != nil {
		return "", false, err
	}
	if err := writeExclusiveBytes(channelStage, channelBody); err != nil {
		return "", false, err
	}
	manifestSource, err := os.Open(manifestPath)
	if err != nil {
		return "", false, err
	}
	copyErr := manifest.AtomicCopy(manifestStage, manifestSource, 0o600)
	closeErr := manifestSource.Close()
	if copyErr != nil || closeErr != nil {
		return "", false, errors.Join(copyErr, closeErr)
	}
	commit, changed, err := applyCanonicalState(ctx, canonical, "materialize-serving", "sow: advance local YUM serving channel", map[string]string{
		serving.TargetStatePath(target):                 targetStage,
		serving.GenerationStatePath(generation):         generationStage,
		serving.GenerationManifestStatePath(generation): manifestStage,
		serving.ChannelStatePath(channel):               channelStage,
	}, nil, state.ApplyOptions{DeletePaths: deletePaths})
	return commit.String(), changed, err
}

func requireCanonicalServingTarget(canonical *state.Store, target serving.TargetIdentity, wanted []byte) error {
	body, exists, err := readOptionalCanonical(canonical, serving.TargetStatePath(target))
	if err != nil || !exists {
		return err
	}
	if !bytes.Equal(body, wanted) {
		return errors.New("canonical serving target ID is occupied by different identity bytes")
	}
	return nil
}

func requireCanonicalServingGeneration(canonical *state.Store, generation serving.Generation, manifestPath string) error {
	wantedJSON, err := generation.Canonical()
	if err != nil {
		return err
	}
	jsonBody, jsonExists, err := readOptionalCanonical(canonical, serving.GenerationStatePath(generation))
	if err != nil {
		return err
	}
	manifestSource, manifestExists, err := openOptionalCanonicalFile(canonical, serving.GenerationManifestStatePath(generation))
	if err != nil {
		return err
	}
	if jsonExists != manifestExists {
		if manifestSource != nil {
			_ = manifestSource.Close()
		}
		return errors.New("canonical serving generation JSON/manifest closure is incomplete")
	}
	if !jsonExists {
		return nil
	}
	if !bytes.Equal(jsonBody, wantedJSON) {
		_ = manifestSource.Close()
		return errors.New("canonical immutable serving generation differs from occupied generation ID")
	}
	canonicalDigest, err := hashReader(manifestSource)
	if err != nil {
		return err
	}
	wantedManifest, err := os.Open(manifestPath)
	if err != nil {
		return err
	}
	wantedDigest, err := hashReader(wantedManifest)
	if err != nil {
		return err
	}
	if canonicalDigest != wantedDigest {
		return errors.New("canonical immutable serving generation differs from occupied generation ID")
	}
	return nil
}

func requireExistingCanonicalServingGeneration(canonical *state.Store, generation serving.Generation, manifestPath string) error {
	if err := requireCanonicalServingGeneration(canonical, generation, manifestPath); err != nil {
		return err
	}
	_, jsonExists, err := readOptionalCanonical(canonical, serving.GenerationStatePath(generation))
	if err != nil {
		return err
	}
	manifestSource, manifestExists, err := openOptionalCanonicalFile(canonical, serving.GenerationManifestStatePath(generation))
	if err != nil {
		return err
	}
	if manifestSource != nil {
		if err := manifestSource.Close(); err != nil {
			return err
		}
	}
	if !jsonExists || !manifestExists {
		return errors.New("canonical serving channel points to a missing generation ledger")
	}
	return nil
}

func openOptionalCanonicalFile(canonical *state.Store, canonicalPath string) (*os.File, bool, error) {
	file, err := canonical.OpenPath(canonicalPath)
	if errors.Is(err, os.ErrNotExist) || err != nil && strings.Contains(err.Error(), "no such file or directory") {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return file, true, nil
}

func requireCanonicalServingChannelParent(canonical *state.Store, desired serving.Channel, desiredBody []byte) error {
	currentBody, exists, err := readOptionalCanonical(canonical, serving.ChannelStatePath(desired))
	if err != nil || !exists {
		if err != nil {
			return err
		}
		if desired.ParentGeneration == "" {
			return nil
		}
		if desired.ParentTargetID == "" {
			return errors.New("canonical serving parent channel disappeared")
		}
		parentPath := serving.ChannelStatePath(serving.Channel{TargetID: desired.ParentTargetID, View: desired.View, Repo: desired.Repo, OS: desired.OS, Arch: desired.Arch})
		parentBody, parentExists, err := readOptionalCanonical(canonical, parentPath)
		if err != nil || !parentExists {
			return errors.Join(err, errors.New("canonical migrated serving parent channel disappeared"))
		}
		parent, err := serving.DecodeChannel(parentBody)
		if err != nil {
			return err
		}
		if parent.TargetID != desired.ParentTargetID || parent.TargetRoot != desired.TargetRoot || parent.Generation != desired.ParentGeneration || parent.MirrorlistSHA256 != desired.ParentMirrorlistSHA256 {
			return errors.New("canonical migrated serving parent channel changed after pointer intent")
		}
		return nil
	}
	if bytes.Equal(currentBody, desiredBody) {
		return nil
	}
	current, err := serving.DecodeChannel(currentBody)
	if err != nil {
		return err
	}
	if desired.ParentGeneration == "" || current.Generation != desired.ParentGeneration || current.MirrorlistSHA256 != desired.ParentMirrorlistSHA256 {
		return errors.New("canonical serving channel changed after pointer intent")
	}
	return nil
}

func localServingJournalID(journal localServingJournal) string {
	digest := sha256.Sum256([]byte(journal.Channel.TargetID + "\x00" + journal.TargetRoot + "\x00" + journal.Channel.MirrorlistPath))
	return hex.EncodeToString(digest[:16])
}

func (journal localServingJournal) validate() error {
	if journal.Schema != localServingJournalSchema || journal.ID != localServingJournalID(journal) || len(journal.ID) != 32 {
		return errors.New("invalid local serving journal envelope")
	}
	if journal.Phase != localServingInstallIntent && journal.Phase != localServingGenerationReady && journal.Phase != localServingStateCommitted && journal.Phase != localServingPointerFlipped {
		return errors.New("invalid local serving journal phase")
	}
	if journal.TargetRoot == "" || filepath.IsAbs(journal.TargetRoot) || filepath.ToSlash(filepath.Clean(filepath.FromSlash(journal.TargetRoot))) != journal.TargetRoot || strings.HasPrefix(journal.TargetRoot, "../") || strings.ContainsAny(journal.TargetRoot, "\\\x00\t\r\n") {
		return errors.New("invalid local serving journal target")
	}
	if journal.PackageKeyringSHA256 != "" && !validMaterializationTrustSHA256(journal.PackageKeyringSHA256) {
		return errors.New("invalid local serving journal RPM package trust identity")
	}
	if err := journal.Generation.Validate(); err != nil {
		return err
	}
	if err := journal.Channel.Validate(); err != nil {
		return err
	}
	if journal.Channel.View != journal.Generation.View || journal.Channel.Repo != journal.Generation.Repo || journal.Channel.OS != journal.Generation.OS || journal.Channel.Arch != journal.Generation.Arch ||
		journal.Channel.Generation != journal.Generation.ID || journal.Channel.ContentSHA256 != journal.Generation.ContentSHA256 || journal.Channel.ManifestSHA256 != journal.Generation.ManifestSHA256 ||
		journal.Channel.LegacyRoot != journal.Generation.LegacyRoot || journal.Channel.RefCommit != journal.Generation.RefCommit || journal.Channel.ConfigSHA256 != journal.Generation.ConfigSHA256 ||
		journal.Channel.RepositoryKeySHA256 != journal.Generation.RepositoryKeySHA256 || journal.Channel.TargetRoot != journal.TargetRoot || journal.Channel.TargetID == "" {
		return errors.New("journal generation and channel identity differ")
	}
	target, err := serving.NewTargetIdentity(journal.Channel.View, journal.TargetRoot, journal.Channel.BaseURL)
	if err != nil || target.ID != journal.Channel.TargetID {
		return errors.Join(err, errors.New("journal serving target identity differs from its channel"))
	}
	return nil
}

func localServingJournalRelative(id string) string {
	return filepath.Join("serving-journal", id+".json")
}

func createLocalServingJournal(stateRoot string, journal localServingJournal) error {
	directory, _, err := localServingJournalDirectory(stateRoot, true)
	if err != nil {
		return err
	}
	filename := filepath.Join(directory, journal.ID+".json")
	if _, err := os.Lstat(filename); err == nil {
		return errors.New("incomplete local serving journal already exists; retry with --recover")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return updateLocalServingJournal(stateRoot, journal)
}

func updateLocalServingJournal(stateRoot string, journal localServingJournal) error {
	if err := journal.validate(); err != nil {
		return err
	}
	body, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	result, err := writeDerivedStateFileOutcome(stateRoot, localServingJournalRelative(journal.ID), body)
	return consumeDerivedStateReplacement(result, err)
}

func removeLocalServingJournal(stateRoot, id string) error {
	if !localServingJournalNamePattern.MatchString(id + ".json") {
		return errors.New("invalid local serving journal ID")
	}
	directory, exists, err := localServingJournalDirectory(stateRoot, false)
	if err != nil || !exists {
		return errors.Join(err, errors.New("local serving journal directory is missing"))
	}
	name := id + ".json"
	return removeExactProjectionIntent(directory, name, localServingJournalMaxBytes, func(body []byte) error {
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		var journal localServingJournal
		if err := decoder.Decode(&journal); err != nil {
			return err
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return errors.New("local serving journal has trailing JSON")
		}
		if err := journal.validate(); err != nil {
			return err
		}
		if journal.ID != id {
			return errors.New("local serving journal ID changed before removal")
		}
		return nil
	})
}

func listLocalServingJournals(stateRoot string) ([]localServingJournal, error) {
	directory, exists, err := localServingJournalDirectory(stateRoot, false)
	if err != nil || !exists {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	var journals []localServingJournal
	for _, entry := range entries {
		if !localServingJournalNamePattern.MatchString(entry.Name()) {
			return nil, fmt.Errorf("unsafe local serving journal entry %q", entry.Name())
		}
		body, err := readBoundedExactRegularFile(directory, entry.Name(), localServingJournalMaxBytes)
		if err != nil {
			return nil, err
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		var journal localServingJournal
		if err := decoder.Decode(&journal); err != nil {
			return nil, err
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return nil, errors.New("local serving journal has trailing JSON")
		}
		if err := journal.validate(); err != nil {
			return nil, err
		}
		if entry.Name() != journal.ID+".json" {
			return nil, errors.New("local serving journal filename does not match ID")
		}
		journals = append(journals, journal)
	}
	sort.Slice(journals, func(i, j int) bool { return journals[i].ID < journals[j].ID })
	return journals, nil
}

func localServingJournalDirectory(stateRoot string, create bool) (string, bool, error) {
	return ensureDerivedStateControlDirectory(
		stateRoot,
		"serving-journal",
		"local serving journal directory",
		create,
	)
}

func readBoundedExactRegularFile(directory, name string, limit int64) ([]byte, error) {
	if filepath.Base(name) != name || name == "" || name == "." || limit < 0 {
		return nil, errors.New("derived state control-file read coordinate is invalid")
	}
	directory, root, directoryIdentity, err := bindAdmittedDerivedStateDirectory(directory, "derived state control-file directory")
	if err != nil {
		return nil, err
	}
	defer root.Close()
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() > limit {
		return nil, errors.Join(err, fmt.Errorf("%s is not an exact regular file within the %d-byte limit", name, limit))
	}
	if _, err := admitDerivedStateControlFile(before, fmt.Sprintf("derived state control file %s", name)); err != nil {
		return nil, err
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, errors.Join(statErr, file.Close(), errors.New("local serving journal changed while opening"))
	}
	body, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	after, restatErr := file.Stat()
	current, lstatErr := root.Lstat(name)
	closeErr := file.Close()
	if readErr != nil || restatErr != nil || lstatErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, restatErr, lstatErr, closeErr)
	}
	if after == nil || current == nil || len(body) > int(limit) || !os.SameFile(before, after) || !os.SameFile(before, current) ||
		before.Size() != after.Size() || before.Size() != current.Size() || before.Mode() != after.Mode() || before.Mode() != current.Mode() ||
		!before.ModTime().Equal(after.ModTime()) || !before.ModTime().Equal(current.ModTime()) ||
		!sameDerivedStateControlFileSecurity(before, after) ||
		!sameDerivedStateControlFileSecurity(before, current) {
		return nil, errors.New("local serving journal exceeded its limit or changed while reading")
	}
	if err := verifyBoundDerivedStateRoot(root, directory, directoryIdentity); err != nil {
		return nil, err
	}
	return body, nil
}

func cleanupLocalServingJournalTemps(stateRoot string) error {
	directory, exists, err := localServingJournalDirectory(stateRoot, false)
	if err != nil || !exists {
		return err
	}
	if err := recoverDerivedStateReplacementTransactions(stateRoot, "serving-journal", true); err != nil {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	removed := false
	for _, entry := range entries {
		if !isLocalServingJournalTemporaryName(entry.Name()) {
			continue
		}
		exact, err := removeExactProjectionResidueBounded(directory, entry.Name(), localServingJournalMaxBytes)
		if err != nil {
			return errors.Join(err, fmt.Errorf("unsafe local serving journal temporary entry %q", entry.Name()))
		}
		removed = removed || exact
	}
	if removed {
		return syncLocalDirectory(directory)
	}
	return nil
}

func isLocalServingJournalTemporaryName(name string) bool {
	const canonicalBytes = 32 + len(".json")
	return len(name) > canonicalBytes && localServingJournalNamePattern.MatchString(name[:canonicalBytes]) &&
		isDerivedStateTemporaryName(name, name[:canonicalBytes])
}

func requireNoLocalServingTransactions(stateRoot string) error {
	journals, err := listLocalServingJournals(stateRoot)
	if err != nil {
		return err
	}
	if len(journals) != 0 {
		return errors.New("incomplete local serving transaction requires `sow materialize ... --recover`")
	}
	return nil
}

func prepareLocalServingState(ctx context.Context, cfg *config.Config, canonical *state.Store, recover bool, values commonFlags, stdout io.Writer) error {
	if recover {
		if err := cleanupLocalServingJournalTemps(cfg.StatePath()); err != nil {
			return withExitCode(ExitConflict, "clean interrupted local serving journal write: %v", err)
		}
		migrated, err := migrateLegacyServingChannels(ctx, cfg, canonical)
		if err != nil {
			return withExitCode(ExitConflict, "migrate legacy local serving channels: %v", err)
		}
		if migrated != 0 {
			fmt.Fprintf(stdout, "recovered legacy-local-serving-channels=%d\n", migrated)
		}
	}
	seenRoots := make(map[string]struct{})
	for _, view := range []string{"latest", "beta", "stable"} {
		targetRoot, err := defaultMutableServingTarget(cfg, view)
		if err != nil {
			return withExitCode(ExitInternal, "resolve %s local serving root: %v", view, err)
		}
		if _, exists := seenRoots[targetRoot]; exists {
			continue
		}
		seenRoots[targetRoot] = struct{}{}
		if _, err := serving.CleanupTransactionTemps(cfg.Root, targetRoot); err != nil {
			return withExitCode(ExitConflict, "clean interrupted local serving temporary files below %s: %v", view, err)
		}
	}
	journals, err := listLocalServingJournals(cfg.StatePath())
	if err != nil {
		return withExitCode(ExitConflict, "inspect local serving recovery: %v", err)
	}
	if len(journals) == 0 {
		return nil
	}
	if !recover {
		return withExitCode(ExitConflict, "incomplete local serving transaction exists; retry materialize with --recover")
	}
	pool, err := repository.NewStore(cfg.Root)
	if err != nil {
		return withExitCode(ExitConflict, "open CAS for local serving recovery: %v", err)
	}
	requireRecoveryTrust := func(boundary localServingRecoveryTrustBoundary, journal localServingJournal) error {
		if values.localServingRecoveryTrustHook != nil {
			values.localServingRecoveryTrustHook(boundary)
		}
		return requireLocalServingJournalTrust(cfg, journal)
	}
	for _, journal := range journals {
		if err := requireRecoveryTrust(localServingRecoveryTrustEntry, journal); err != nil {
			return withExitCode(ExitConflict, "local serving recovery trust changed for journal %s: %v", journal.ID, err)
		}
		targetRoot := cfg.Root
		if journal.TargetRoot != "." {
			targetRoot = filepath.Join(cfg.Root, filepath.FromSlash(journal.TargetRoot))
		}
		if _, err := serving.CleanupTransactionTemps(cfg.Root, targetRoot); err != nil {
			return withExitCode(ExitConflict, "clean interrupted local serving transaction %s: %v", journal.ID, err)
		}
		txDir, err := newTransactionDir(cfg.StatePath(), "serving-recover-")
		if err != nil {
			return withExitCode(ExitInternal, "create local serving recovery transaction: %v", err)
		}
		manifestPath := filepath.Join(txDir, "generation.tsv")
		installOptions := serving.InstallOptions{Workers: values.workers, ChunkEntries: values.chunk, TempDir: filepath.Join(cfg.StatePath(), "tmp")}
		scanErr := serving.ScanInstalledGeneration(ctx, pool, targetRoot, journal.Generation, manifestPath, installOptions)
		committed := journal.Phase == localServingStateCommitted || journal.Phase == localServingPointerFlipped
		if errors.Is(scanErr, os.ErrNotExist) && journal.Phase == localServingGenerationReady {
			committed, err = localServingJournalCanonicalCommitted(canonical, journal)
			if err != nil {
				_ = os.RemoveAll(txDir)
				return withExitCode(ExitVerification, "inspect generation-ready local serving journal: %v", err)
			}
		}
		if errors.Is(scanErr, os.ErrNotExist) && !committed && (journal.Phase == localServingInstallIntent || journal.Phase == localServingGenerationReady) {
			if err := removeLocalServingJournal(cfg.StatePath(), journal.ID); err != nil {
				_ = os.RemoveAll(txDir)
				return withExitCode(ExitInternal, "abandon uninstalled local serving intent: %v", err)
			}
			_ = os.RemoveAll(txDir)
			fmt.Fprintf(stdout, "recovered local-serving=%s action=abandon-uninstalled view=%s repo=%s os=%s arch=%s generation=%s\n", journal.ID, journal.Channel.View, journal.Channel.Repo, journal.Channel.OS, journal.Channel.Arch, journal.Generation.ID)
			continue
		}
		if errors.Is(scanErr, os.ErrNotExist) && committed {
			exists, err := stageCanonicalServingManifest(canonical, journal.Generation, manifestPath)
			if err != nil || !exists {
				_ = os.RemoveAll(txDir)
				return withExitCode(ExitVerification, "recover committed local serving generation %s: %v", journal.Generation.ID, errors.Join(err, errors.New("canonical manifest is missing")))
			}
			if err := ensureLocalServingRecoveryTarget(cfg.Root, journal.TargetRoot); err != nil {
				_ = os.RemoveAll(txDir)
				return withExitCode(ExitConflict, "recreate committed local serving target: %v", err)
			}
			scanErr = nil
		}
		if scanErr != nil {
			_ = os.RemoveAll(txDir)
			return withExitCode(ExitVerification, "recover local serving generation %s: %v", journal.Generation.ID, scanErr)
		}
		if _, err := serving.InstallGeneration(ctx, pool, targetRoot, journal.Generation, manifestPath, installOptions); err != nil {
			_ = os.RemoveAll(txDir)
			return withExitCode(ExitVerification, "verify local serving generation %s: %v", journal.Generation.ID, err)
		}
		if _, err := ensureLocalServingChannelGenerations(ctx, canonical, pool, targetRoot, journal.Channel, 1, filepath.Join(txDir, "retained"), installOptions, true); err != nil {
			_ = os.RemoveAll(txDir)
			return withExitCode(ExitVerification, "recover retained local serving generations: %v", err)
		}
		if err := requireRecoveryTrust(localServingRecoveryTrustBeforeCanonical, journal); err != nil {
			_ = os.RemoveAll(txDir)
			return withExitCode(ExitConflict, "local serving recovery trust changed before canonical commit: %v", err)
		}
		if _, _, err := persistLocalServingLedger(ctx, canonical, journal.Generation, journal.Channel, manifestPath, txDir); err != nil {
			_ = os.RemoveAll(txDir)
			return stateMutationError("recover local serving ledger", err)
		}
		if err := requireRecoveryTrust(localServingRecoveryTrustAfterCanonical, journal); err != nil {
			_ = os.RemoveAll(txDir)
			return withExitCode(ExitConflict, "local serving recovery trust changed after canonical commit: %v", err)
		}
		priorMirrorlist, priorExists, err := serving.ReadMirrorlist(targetRoot, journal.Channel.MirrorlistPath)
		if err != nil {
			_ = os.RemoveAll(txDir)
			return withExitCode(ExitConflict, "capture local serving recovery pointer parent: %v", err)
		}
		pointerChanged, err := recoverCommittedMirrorlist(targetRoot, journal.Channel)
		if err != nil {
			_ = os.RemoveAll(txDir)
			return withExitCode(ExitConflict, "recover local serving mirrorlist: %v", err)
		}
		if trustErr := requireRecoveryTrust(localServingRecoveryTrustAfterPointer, journal); trustErr != nil {
			if pointerChanged {
				trustErr = errors.Join(trustErr, serving.RollbackMirrorlist(targetRoot, journal.Channel, priorMirrorlist, priorExists))
			}
			_ = os.RemoveAll(txDir)
			return withExitCode(ExitConflict, "local serving recovery trust changed after pointer activation: %v", trustErr)
		}
		if err := serving.ValidateInstalledGeneration(ctx, pool, targetRoot, journal.Generation, manifestPath, installOptions); err != nil {
			_ = os.RemoveAll(txDir)
			return withExitCode(ExitVerification, "verify recovered local serving generation: %v", err)
		}
		if err := removeLocalServingJournal(cfg.StatePath(), journal.ID); err != nil {
			_ = os.RemoveAll(txDir)
			return withExitCode(ExitInternal, "complete local serving recovery: %v", err)
		}
		_ = os.RemoveAll(txDir)
		fmt.Fprintf(stdout, "recovered local-serving=%s view=%s repo=%s os=%s arch=%s generation=%s\n", journal.ID, journal.Channel.View, journal.Channel.Repo, journal.Channel.OS, journal.Channel.Arch, journal.Generation.ID)
	}
	return nil
}

func requireLocalServingJournalTrust(cfg *config.Config, journal localServingJournal) error {
	if cfg == nil || !validMaterializationTrustSHA256(journal.Generation.RepositoryKeySHA256) || !validMaterializationTrustSHA256(journal.PackageKeyringSHA256) {
		return errors.New("journal trust identities are incomplete")
	}
	repo, exists := cfg.RepoByName(journal.Channel.Repo)
	if !exists || repo.Type != "yum" || repo.YUM == nil {
		return errors.New("journal YUM repository is not present in current configuration")
	}
	_, packets, err := loadRepositoryPublicTrustAnchor(cfg.Path, cfg.GPG.PublicKey)
	if err != nil {
		return err
	}
	if repositoryTrustAnchorDigest(packets) != journal.Generation.RepositoryKeySHA256 {
		return errors.New("repository public key differs from the interrupted local serving transaction")
	}
	_, packageKeyringSHA256, err := loadRPMPackageKeyring(cfg.Path, repo.YUM.PackageKeyring)
	if err != nil {
		return err
	}
	if packageKeyringSHA256 != journal.PackageKeyringSHA256 {
		return errors.New("RPM package keyring differs from the interrupted local serving transaction")
	}
	return nil
}

func localServingJournalCanonicalCommitted(canonical *state.Store, journal localServingJournal) (bool, error) {
	path := serving.ChannelStatePath(journal.Channel)
	body, exists, err := readOptionalCanonical(canonical, path)
	if err != nil || !exists {
		return false, err
	}
	wanted, err := journal.Channel.Canonical()
	if err != nil {
		return false, err
	}
	if !bytes.Equal(body, wanted) {
		return false, errors.New("generation-ready journal differs from committed canonical channel")
	}
	_, generationExists, err := readOptionalCanonical(canonical, serving.GenerationStatePath(journal.Generation))
	if err != nil {
		return false, err
	}
	manifest, manifestExists, err := openOptionalCanonicalFile(canonical, serving.GenerationManifestStatePath(journal.Generation))
	if manifest != nil {
		err = errors.Join(err, manifest.Close())
	}
	return generationExists && manifestExists, err
}

func ensureLocalServingRecoveryTarget(repositoryRoot, relative string) error {
	root, err := os.OpenRoot(repositoryRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	if relative == "." {
		return nil
	}
	relativePath := filepath.FromSlash(relative)
	if filepath.IsAbs(relativePath) || filepath.Clean(relativePath) != relativePath || strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) {
		return errors.New("invalid local serving recovery target")
	}
	created := make(map[string]struct{})
	prefix := ""
	for _, component := range strings.Split(relativePath, string(filepath.Separator)) {
		prefix = filepath.Join(prefix, component)
		if info, err := root.Lstat(prefix); errors.Is(err, os.ErrNotExist) {
			created[prefix] = struct{}{}
		} else if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.Join(err, fmt.Errorf("serving recovery target parent %s is unsafe", prefix))
		}
	}
	if err := root.MkdirAll(relativePath, 0o755); err != nil {
		return err
	}
	for directory := range created {
		info, err := root.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.Join(err, fmt.Errorf("created serving recovery target %s is unsafe", directory))
		}
		if err := root.Chmod(directory, 0o755); err != nil {
			return err
		}
	}
	barriers := make(map[string]struct{}, len(created)*2)
	for directory := range created {
		barriers[directory] = struct{}{}
		parent := filepath.Dir(directory)
		if parent == "" {
			parent = "."
		}
		barriers[parent] = struct{}{}
	}
	barrierPaths := make([]string, 0, len(barriers))
	for directory := range barriers {
		barrierPaths = append(barrierPaths, directory)
	}
	sort.Slice(barrierPaths, func(i, j int) bool { return len(barrierPaths[i]) > len(barrierPaths[j]) })
	for _, directory := range barrierPaths {
		handle, err := root.Open(directory)
		if err != nil {
			return err
		}
		if err := errors.Join(handle.Sync(), handle.Close()); err != nil {
			return err
		}
	}
	return nil
}

func recoverCommittedMirrorlist(targetRoot string, channel serving.Channel) (bool, error) {
	body, exists, err := serving.ReadMirrorlist(targetRoot, channel.MirrorlistPath)
	if err != nil || !exists {
		if err != nil {
			return false, err
		}
		return serving.RestoreMirrorlist(targetRoot, channel)
	}
	desired, err := channel.MirrorlistBody()
	if err != nil {
		return false, err
	}
	if bytes.Equal(body, desired) {
		return serving.RestoreMirrorlist(targetRoot, channel)
	}
	if channel.ParentMirrorlistSHA256 == "" {
		return false, errors.New("mirrorlist differs from committed first-install state")
	}
	digest := sha256.Sum256(body)
	if hex.EncodeToString(digest[:]) != channel.ParentMirrorlistSHA256 {
		return false, errors.New("mirrorlist differs from parent and committed desired state")
	}
	return serving.ReconcileMirrorlist(targetRoot, channel)
}
