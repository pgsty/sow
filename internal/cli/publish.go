package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
)

type publicationProjection struct {
	view string
	repo config.Repo
	// physicalRepo is the complete configured repository contract that was
	// reconciled on disk. repo remains the logical remote selector so a partial
	// APT publication can rebuild one replayable repo-wide Nginx owner without
	// advancing an unselected suite/ref or uploading its pending bytes.
	physicalRepo config.Repo
	os           string
	arch         string
	// compatibilityID marks a frozen cross-EL legacy URL projection. repo is
	// still the source repo so target affinity and trust are inherited, while
	// channel/path ownership uses this independent identity.
	compatibilityID string
	// compatibilityTrust marks the second, disjoint projection owned by one
	// active S3 compatibility bridge. Its two files are the immutable frozen
	// repository/package public trust anchors; it never owns a YUM channel or
	// repository payload route.
	compatibilityTrust bool
	// compatibilityRollback marks an isolated, exact S0 carrier projection.
	// It is created only after the local committed S3 parent and immutable
	// adoption history have been verified, and never owns a channel/ref.
	compatibilityRollback bool
	sourceRoot            string
	// localRoot differs from sourceRoot only for historical restore. The
	// desired manifest keeps the original directly-hostable source paths while
	// the publisher reads reconstructed bytes from an isolated transaction
	// tree, so restore never rewrites the current local serving tree.
	localRoot string
	// canonicalRoot is the physical, directly-hostable repository root used by
	// canonical manifests and view entries. remoteRoot is the independently
	// projected public ownership root used for object keys and CDN paths. They
	// differ only for asset repositories with asset.public_path.
	canonicalRoot string
	remoteRoot    string
	// legacyRoot is retained as a compatibility alias for canonicalRoot while
	// older scan/working-tree call sites are migrated. New publication routing
	// must use canonicalPathRoot or remotePathRoot explicitly.
	legacyRoot              string
	selectedPayloadManifest string
	// routeExactManifest is the physical-owner-relative expected tree captured
	// before reconciliation.  It is intentionally not populated from the later
	// publication source scan, which may include preserved local serving state.
	routeExactManifest string
	// aptMetadataSuites names the suite directories emitted below sourceRoot.
	// For ordinary views these are the selected source suites. Snapshot APT
	// metadata is renamed to the immutable snapshot ID while refs retain their
	// source-suite names, so the output scope must be recorded separately.
	aptMetadataSuites []string
}

func (projection publicationProjection) isYUMCompatibility() bool {
	return projection.compatibilityID != "" && !projection.compatibilityTrust && !projection.compatibilityRollback
}

func (projection publicationProjection) isYUMCompatibilityTrust() bool {
	return projection.compatibilityID != "" && projection.compatibilityTrust
}

func (projection publicationProjection) isYUMCompatibilityRollback() bool {
	return projection.compatibilityID != "" && projection.compatibilityRollback
}

func (projection publicationProjection) channelCoordinates() (repo, osName, arch string) {
	if projection.compatibilityID != "" {
		return projection.compatibilityID, "cross-el", projection.arch
	}
	return projection.repo.ID, projection.os, projection.arch
}

func (projection publicationProjection) canonicalPathRoot() string {
	if projection.canonicalRoot != "" {
		return projection.canonicalRoot
	}
	if projection.legacyRoot != "" {
		return projection.legacyRoot
	}
	return projection.repo.Path
}

func (projection publicationProjection) remotePathRoot() string {
	if projection.remoteRoot != "" {
		return projection.remoteRoot
	}
	if projection.repo.Type == "asset" {
		return projection.repo.AssetPublicRoot()
	}
	return projection.canonicalPathRoot()
}

type preparedPublication struct {
	view         string
	snapshotID   string
	manifestPath string
	scopes       []string
	projections  []publicationProjection
	// routeLeaves is the complete physical-owner ref vector materialized by this
	// preparation. It is deliberately separate from projections: APT projections
	// preserve the caller's suite/arch selection for remote publication, whereas
	// one directly hosted APT route owns the complete repository tree.
	routeLeaves []viewLeaf
	// yumOwnerLeaves keeps the complete logical ref/channel vector behind one
	// physical repo+arch projection. A YUM repository may expose both its suite
	// and family-major selector for the same on-disk root; the root is scanned,
	// reconciled, and classified once while every logical ref and mirrorlist is
	// retained. The map is runtime preparation state, never canonical data.
	yumOwnerLeaves          map[string][]viewLeaf
	refOverrides            map[string]pub.RefState
	restoreSourceGeneration uint64
	restoreSourceSHA256     string
	restoreSourcePlanSHA256 string
	restoreSourceCommit     string
	// restoreParentContentSHA256 binds every destructive restore decision to
	// the exact content manifest named by the currently committed parent
	// generation. It is deliberately populated only by the audited historical
	// restore path; ordinary publications never infer destructive authority
	// from this field.
	restoreParentContentSHA256 string
	// restoreRemovedProjectionRoots identifies empty exact-replace scopes that
	// exist in the current parent but not in the historical ref vector. They are
	// present only to classify evidence-bound serving-index deletions and must
	// never be mistaken for desired package projections.
	restoreRemovedProjectionRoots map[string]bool
	// restoreRemovedChannelKeys removes public YUM mirrorlist state for topology
	// leaves absent from the restored generation.
	restoreRemovedChannelKeys map[string]bool
	// restoreCompatibility and restoreCompatibilityChannels are copied from the
	// selected historical generation after commit-bound validation. Restore must
	// never inherit today's parent cross-EL vector and thereby publish a hybrid
	// of historical payload with current compatibility ownership.
	restoreCompatibility         []pub.CompatibilityState
	restoreCompatibilityChannels []pub.ChannelState
	restoreRoot                  string
	repositoryKeySHA256          string
	// compatibilitySelected is the selector/target authority set. Active
	// members are represented by payload+trust projections; inactive members
	// are intentionally absent until a previously published S3 bridge must be
	// deactivated after an append-only rollback record.
	compatibilitySelected  map[string]config.YUMCompatibilityProjection
	compatibilityOwners    map[string]config.Repo
	compatibilityRollbacks map[string]pub.CompatibilityState
	// repositoryPool is a runtime capability, never canonical state. It lets a
	// target-specific rollback import and isolate the verified live S0 carrier
	// before any provider client is constructed.
	repositoryPool *repository.Store
	// compatibilityRollbackParentSHA256 binds the locally prepared S0 rollback
	// to the exact committed parent generation that remote observation must
	// later reproduce.
	compatibilityRollbackParentSHA256 string
}

func (prepared preparedPublication) label() string {
	if prepared.snapshotID != "" {
		return prepared.snapshotID
	}
	return prepared.view
}

func yumPublicationOwnerKey(repoID, arch string) string {
	return repoID + "\x00" + arch
}

// yumLeavesForProjection returns every logical coordinate owned by one
// ordinary YUM physical projection. Historical and compatibility projections
// predate grouped preparation and intentionally retain their one-coordinate
// representation.
func (prepared preparedPublication) yumLeavesForProjection(projection publicationProjection) []viewLeaf {
	if projection.repo.Type != "yum" || projection.compatibilityID != "" {
		return []viewLeaf{{repo: projection.repo, os: projection.os, arch: projection.arch}}
	}
	if leaves := prepared.yumOwnerLeaves[yumPublicationOwnerKey(projection.repo.ID, projection.arch)]; len(leaves) != 0 {
		return append([]viewLeaf(nil), leaves...)
	}
	return []viewLeaf{{repo: projection.repo, os: projection.os, arch: projection.arch}}
}

// yumChannelProjections expands a physical projection only at logical channel
// boundaries. Filesystem scans and classifiers must continue to consume the
// single original projection so aliases cannot overlap one source root.
func (prepared preparedPublication) yumChannelProjections(projection publicationProjection) []publicationProjection {
	if projection.repo.Type != "yum" || projection.compatibilityID != "" {
		return []publicationProjection{projection}
	}
	leaves := prepared.yumLeavesForProjection(projection)
	result := make([]publicationProjection, 0, len(leaves))
	for _, leaf := range leaves {
		alias := projection
		alias.os, alias.arch = leaf.os, leaf.arch
		result = append(result, alias)
	}
	return result
}

// validateYUMOwnerVectors is the fail-closed boundary between one physical
// publication projection and its logical ref/channel aliases. Multi-selector
// mutable YUM repositories may never fall back to the anchor coordinate: that
// would silently omit a sibling ref while still replacing their shared root.
func (prepared preparedPublication) validateYUMOwnerVectors() error {
	projected := make(map[string]struct{})
	for _, projection := range prepared.projections {
		if projection.repo.Type != "yum" || projection.compatibilityID != "" {
			continue
		}
		key := yumPublicationOwnerKey(projection.repo.ID, projection.arch)
		if _, duplicate := projected[key]; duplicate {
			return fmt.Errorf("prepared YUM physical owner %s/%s is duplicated", projection.repo.ID, projection.arch)
		}
		projected[key] = struct{}{}
		leaves, mapped := prepared.yumOwnerLeaves[key]
		if !mapped {
			if prepared.view != "snapshot" && len(uniqueSorted(projection.repo.OSSelectorValues())) > 1 {
				return fmt.Errorf("prepared YUM physical owner %s/%s has no complete logical alias vector", projection.repo.ID, projection.arch)
			}
			continue
		}
		if len(leaves) == 0 {
			return fmt.Errorf("prepared YUM physical owner %s/%s has an empty logical alias vector", projection.repo.ID, projection.arch)
		}
		seen := make(map[string]struct{}, len(leaves))
		anchor := false
		for _, leaf := range leaves {
			if leaf.repo.ID != projection.repo.ID || leaf.repo.Type != "yum" || leaf.arch != projection.arch || leaf.os == "" {
				return fmt.Errorf("prepared YUM physical owner %s/%s contains a foreign logical alias", projection.repo.ID, projection.arch)
			}
			leafKey := servingLeafKey(leaf.repo.ID, leaf.os, leaf.arch)
			if _, duplicate := seen[leafKey]; duplicate {
				return fmt.Errorf("prepared YUM physical owner %s/%s duplicates logical alias %s", projection.repo.ID, projection.arch, leaf.os)
			}
			seen[leafKey] = struct{}{}
			anchor = anchor || leaf.os == projection.os
		}
		if !anchor {
			return fmt.Errorf("prepared YUM physical owner %s/%s alias vector omits anchor %s", projection.repo.ID, projection.arch, projection.os)
		}
	}
	for key := range prepared.yumOwnerLeaves {
		if _, exists := projected[key]; !exists {
			return fmt.Errorf("prepared YUM alias vector %q has no physical projection", key)
		}
	}
	return nil
}

func (prepared preparedPublication) intentMatches(view, snapshot string) bool {
	return pub.SamePublicationIntent(prepared.view, prepared.snapshotID, view, snapshot)
}

func (prepared preparedPublication) outputSelection() string {
	if prepared.snapshotID != "" {
		return "view=snapshot snapshot=" + prepared.snapshotID
	}
	return "view=" + prepared.view
}

func runPublish(ctx context.Context, args []string, stdout, stderr io.Writer) (resultErr error) {
	ctx = withRunPublishPurgeLedgerAuditCache(ctx)
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	fs.SetOutput(stderr)
	values := commonFlags{}
	addCommonFlags(fs, &values)
	var viewFlags, snapshotFlags, targetFlags csvFlag
	fs.Var(&viewFlags, "view", "select beta, latest, or stable (repeatable; default all in release order)")
	fs.Var(&snapshotFlags, "snapshot", "publish one immutable <suite>-YYYYMMDD snapshot (repeatable; conflicts with --view)")
	fs.Var(&targetFlags, "target", "select cf or cos (repeatable; default every configured target)")
	var restoreGeneration uint64
	restoreRequested := false
	fs.Func("restore-generation", "restore one locally recorded historical target generation as a new publication generation", func(value string) error {
		if restoreRequested {
			return errors.New("--restore-generation may be specified only once")
		}
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err != nil || parsed == 0 {
			return errors.New("--restore-generation requires a positive decimal generation")
		}
		restoreGeneration = parsed
		restoreRequested = true
		return nil
	})
	privateKeyFile := fs.String("gpg-private-key-file", "", "read the OpenPGP private key from a protected file")
	passphraseFile := fs.String("gpg-passphrase-file", "", "read the OpenPGP passphrase from a protected file")
	fs.Usage = func() {
		printSubcommandUsage(fs,
			"sow publish [--view beta|latest|stable | --snapshot <suite>-YYYYMMDD | --restore-generation N --target cf|cos] [--repo NAME] [--os OS] [--arch ARCH] [--workers N] [--recover]",
			"Restore creates a new forward generation from one locally recorded successful target generation; it never rewinds a checkpoint.",
			"Restore requires exactly one explicit target and cannot be combined with view, snapshot, repo, OS, or arch selectors.",
			"Append-only stable refs must be identical to the current target vector; ref removal and stable regression fail closed.",
		)
	}
	if help, err := parseFlagSet(fs, args); err != nil || help {
		return err
	}
	if fs.NArg() != 0 {
		return withExitCode(ExitUsage, "publish accepts no positional arguments")
	}
	if len(viewFlags.values()) != 0 && len(snapshotFlags.values()) != 0 {
		return withExitCode(ExitUsage, "publish --view and --snapshot are mutually exclusive")
	}
	if restoreRequested && (len(viewFlags.values()) != 0 || len(snapshotFlags.values()) != 0 || len(values.repos.values()) != 0 || len(values.oses.values()) != 0 || len(values.arches.values()) != 0) {
		return withExitCode(ExitUsage, "publish --restore-generation cannot be combined with --view, --snapshot, --repo, --os, or --arch")
	}
	defaultSelection := len(viewFlags.values()) == 0 && len(snapshotFlags.values()) == 0
	cfg, repos, err := loadAndSelect(values)
	if err != nil {
		return err
	}
	// Do not clean restore trees, acquire publication state, materialize local
	// routes, or construct a provider client while a compatibility link flip is
	// incomplete. The matching compatibility command is the only recovery
	// authority for its durable cutover journal.
	if err := requireNoPendingYUMCompatibilityCutoverJournals(cfg.StatePath()); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	viewNames, err := selectedPublishViews(viewFlags.values())
	if err != nil {
		return withExitCode(ExitConfig, "%v", err)
	}
	snapshotNames, err := selectedPublishSnapshots(snapshotFlags.values())
	if err != nil {
		return withExitCode(ExitConfig, "%v", err)
	}
	if len(snapshotNames) != 0 {
		viewNames = nil
	}
	if !restoreRequested {
		for _, viewName := range viewNames {
			if _, err := preflightMutableYUMServing(cfg, repos, viewName, "", false); err != nil {
				return withExitCode(ExitConfig, "%v", err)
			}
		}
	}
	targetNames, err := selectedPublishTargets(cfg, targetFlags.values())
	if err != nil {
		return withExitCode(ExitConfig, "%v", err)
	}
	if err := validatePublishTargetAffinitySelection(repos, targetNames, len(values.repos.values()) != 0); err != nil {
		return withExitCode(ExitConfig, "%v", err)
	}
	if !restoreRequested && len(snapshotNames) == 0 {
		if err := validatePublishTargetViewAffinitySelection(cfg, repos, targetNames, viewNames); err != nil {
			return withExitCode(ExitConfig, "%v", err)
		}
	}
	repos = reposPublishingToTargets(repos, targetNames)
	if restoreRequested && (len(targetFlags.values()) == 0 || len(targetNames) != 1) {
		return withExitCode(ExitUsage, "publish --restore-generation requires exactly one explicit --target")
	}
	lock, err := state.AcquireLock(cfg.StatePath(), "publish", values.recover)
	if err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	defer propagateStateLockRelease(lock, &resultErr, stderr)
	if err := requireNoForeignMaterializationIntent(cfg, "publish", values.recover); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	removedStaleRestores, err := cleanupStaleRestoreMaterializations(cfg.Root)
	if err != nil {
		return withExitCode(ExitConflict, "clean stale restore materializations: %v", err)
	}
	if removedStaleRestores {
		fmt.Fprintln(stdout, "recovery stale_restore_materializations=removed")
	}
	canonical := state.New(cfg.StatePath())
	if err := prepareCanonicalStateCore(ctx, canonical, values.recover, stdout); err != nil {
		return err
	}
	if err := requireCanonicalConfigBaseline(cfg, canonical); err != nil {
		return withExitCode(ExitConflict, "canonical config changed while publish was waiting for the state lock: %v", err)
	}
	if err := validateLocalPublishedTargetAffinity(canonical, cfg, targetNames); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	var materializationRecoveryJournal materializationSelectionJournal
	materializationRecoveryActive := false
	if values.recover {
		if materializationRecoveryJournal, materializationRecoveryActive, err = readMaterializationSelectionJournal(cfg.StatePath()); err != nil {
			return withExitCode(ExitConflict, "inspect publication materialization recovery: %v", err)
		}
	}
	if err := prepareLocalServingState(ctx, cfg, canonical, values.recover, values, stdout); err != nil {
		return err
	}
	if err := prepareLocalServingTopologyRemovals(ctx, cfg, canonical, values.recover); err != nil {
		return withExitCode(ExitConflict, "recover local YUM serving topology: %v", err)
	}
	txDir, err := newTransactionDir(cfg.StatePath(), "publish-")
	if err != nil {
		return withExitCode(ExitInternal, "create publish transaction: %v", err)
	}
	defer os.RemoveAll(txDir)
	pool, err := repository.NewStore(cfg.Root)
	if err != nil {
		return withExitCode(ExitConflict, "open CAS: %v", err)
	}
	var materializationRecovery publicationMaterializationRecovery
	var materializationRecoveryRepos []config.Repo
	if materializationRecoveryActive {
		materializationRecovery, err = decodePublicationMaterializationRecovery(cfg, materializationRecoveryJournal)
		if err != nil {
			return withExitCode(ExitConflict, "decode publication materialization recovery: %v", err)
		}
		if err := requireClosedPublicationRecoveryViewLeaves(cfg, canonical, materializationRecovery); err != nil {
			return withExitCode(ExitConflict, "validate publication materialization recovery owner closure: %v", err)
		}
		if materializationRecovery.kind == publicationMaterializationRecoveryRestore {
			if !restoreRequested {
				return withExitCode(ExitConflict, "incomplete historical publication materialization requires its exact --restore-generation and --target with --recover")
			}
			if err := requireExactHistoricalMaterializationRecovery(cfg, canonical, materializationRecoveryJournal, targetNames[0], restoreGeneration); err != nil {
				return withExitCode(ExitConflict, "validate historical publication materialization recovery: %v", err)
			}
			// Historical recovery is identity-checked by the restore materializer
			// again before the journal can clear. The pure-local check above guarantees
			// the read-only remote observation cannot run for a mismatched request.
			return restorePublishedGeneration(ctx, cfg, canonical, pool, repos, targetNames[0], restoreGeneration, txDir, values, *privateKeyFile, *passphraseFile, stdout)
		}
		materializationRecoveryRepos, err = publicationRecoveryRepos(cfg, materializationRecovery.allLeaves)
		if err != nil {
			return withExitCode(ExitConflict, "resolve publication materialization recovery repos: %v", err)
		}
	}
	if restoreRequested && !materializationRecoveryActive {
		return restorePublishedGeneration(ctx, cfg, canonical, pool, repos, targetNames[0], restoreGeneration, txDir, values, *privateKeyFile, *passphraseFile, stdout)
	}
	secretRepos := mergePublicationRecoveryRepos(repos, materializationRecoveryRepos)
	privateKey, passphrase, loadedRepositoryKeySHA, err := loadPublishSigningSecretsWithIdentity(cfg, secretRepos, *privateKeyFile, *passphraseFile)
	if err != nil {
		return withExitCode(ExitConfig, "%v", err)
	}
	defer clearSecret(privateKey)
	defer clearSecret(passphrase)
	if materializationRecoveryActive {
		recoveryTrust, err := captureMaterializationTrust(cfg, materializationRecovery.allLeaves, privateKey, loadedRepositoryKeySHA)
		if err != nil {
			return withExitCode(ExitConflict, "capture publication recovery materialization trust: %v", err)
		}
		recoveryValues := exactPublicationRecoveryValues(values, recoveryTrust)
		switch materializationRecovery.kind {
		case publicationMaterializationRecoveryViews:
			if err := recoverPublicationViewMaterializationSelection(ctx, cfg, canonical, pool, materializationRecovery, txDir, recoveryValues, privateKey, passphrase, loadedRepositoryKeySHA, materializationRecoveryJournal, stdout); err != nil {
				return err
			}
		case publicationMaterializationRecoverySnapshots:
			if err := recoverPublicationSnapshotMaterializationSelection(ctx, cfg, canonical, pool, materializationRecovery, txDir, recoveryValues, privateKey, passphrase, stdout); err != nil {
				return err
			}
		default:
			return withExitCode(ExitConflict, "unsupported publication materialization recovery kind %s", materializationRecovery.kind)
		}
		materializationRecoveryActive = false
	}
	if restoreRequested {
		// A mutable-view or snapshot materialization journal is a local transaction
		// fence. Its durable selector must converge and the journal must be removed
		// before historical restore is allowed to observe or mutate any remote.
		return restorePublishedGeneration(ctx, cfg, canonical, pool, repos, targetNames[0], restoreGeneration, txDir, values, *privateKeyFile, *passphraseFile, stdout)
	}
	repositoryKeySHA := ""
	if publicationReposRequireSigning(repos) {
		repositoryKeySHA = loadedRepositoryKeySHA
	}
	trustLeaves := selectedLeaves(repos, values)
	// An explicit view publication can only materialize repositories admitted
	// by that view. Default publication also emits retained snapshots, and an
	// explicit snapshot may contain historical refs outside current view
	// membership, so those two modes deliberately freeze every selected package
	// repository instead of narrowing the trust set here.
	if !defaultSelection && len(snapshotNames) == 0 {
		filtered := trustLeaves[:0]
		for _, leaf := range trustLeaves {
			for _, viewName := range viewNames {
				if viewIncludesRepo(cfg.Views[viewName], leaf.repo.ID) {
					filtered = append(filtered, leaf)
					break
				}
			}
		}
		trustLeaves = filtered
	}
	values.materializeTrust, err = captureMaterializationTrust(cfg, trustLeaves, privateKey, repositoryKeySHA)
	if err != nil {
		return withExitCode(ExitConflict, "capture publication materialization trust: %v", err)
	}
	values.materializeOperation = "publish"
	if err := preflightPublishedRepositoryKeyContinuity(cfg, canonical, targetNames, repositoryKeySHA); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	if len(snapshotNames) != 0 {
		partial, err := publishSnapshotSet(ctx, cfg, canonical, pool, repos, snapshotNames, targetNames, txDir, values, privateKey, passphrase, repositoryKeySHA, stdout)
		if err != nil {
			return err
		}
		if partial {
			return withExitCode(ExitPartialPublish, "one or more cloud targets remain behind; successful targets were committed independently")
		}
		return nil
	}
	recoveryIntent := make(map[string]string)
	recoverySnapshot := make(map[string]string)
	failedTargets := make(map[string]error)
	partial := false
	var defaultSnapshots []string
	if defaultSelection {
		defaultSnapshots, err = discoverRecentSnapshots(canonical, timeNowUTC(), cfg.State.SnapshotMaterializationMonths)
		if err != nil {
			return withExitCode(ExitConfig, "discover retained snapshots: %v", err)
		}
	}

	// A single target may inspect its interrupted intent before local preparation
	// without creating a sibling barrier. Multi-target inspection stays inside
	// each target-major sequence below. No remote mutation starts until selected
	// local views and known snapshots have been frozen.
	if len(viewNames) > 1 && len(targetNames) == 1 {
		for _, target := range targetNames {
			if failedTargets[target] != nil {
				continue
			}
			inspectDir := filepath.Join(txDir, "inspect-"+target)
			if err := os.Mkdir(inspectDir, 0o700); err != nil {
				return withExitCode(ExitInternal, "create target recovery inspection: %v", err)
			}
			intentView, intentSnapshot, interrupted, inspectErr := interruptedPublicationIntent(ctx, cfg, canonical, target, inspectDir)
			if inspectErr != nil {
				if len(targetNames) == 1 {
					return publishTargetExitError(inspectErr)
				}
				failedTargets[target] = inspectErr
				partial = true
				fmt.Fprintf(stdout, "publish target=%s status=failed-before-recovery error=%q\n", target, redactPublishError(inspectErr))
				continue
			}
			if !interrupted {
				continue
			}
			if intentSnapshot != "" {
				if !defaultSelection {
					return withExitCode(ExitConflict, "target %s has an interrupted snapshot/%s publication; use the default selection or include that exact --snapshot", target, intentSnapshot)
				}
				recoverySnapshot[target] = intentSnapshot
				continue
			}
			if !contains(viewNames, intentView) {
				intentErr := fmt.Errorf("target %s has an interrupted %s publication; include --view %s to recover it", target, intentView, intentView)
				if len(targetNames) == 1 {
					return withExitCode(ExitConflict, "%v", intentErr)
				}
				failedTargets[target] = intentErr
				partial = true
				fmt.Fprintf(stdout, "publish target=%s view=%s status=blocked-recovery error=%q\n", target, intentView, redactPublishError(intentErr))
				continue
			}
			recoveryIntent[target] = intentView
		}
	}

	preparedViews := make(map[string]preparedPublication, len(viewNames))
	viewTxDirs := make(map[string]string, len(viewNames))
	preflightUnchanged := make(map[string]map[string]bool, len(viewNames))
	var viewsToPrepare []string
	for _, viewName := range viewNames {
		localServingReady, err := localYUMServingReady(cfg, canonical, repos, viewName, repositoryKeySHA, values, true)
		if err != nil {
			return withExitCode(ExitConflict, "preflight local YUM serving view %s: %v", viewName, err)
		}
		needsPreparation := !localServingReady
		if len(targetNames) > 1 {
			// Multi-target remote observation belongs inside each independent
			// target-major sequence. Preparing the local union eagerly avoids a
			// cross-provider preflight barrier; buildTargetPublication still performs
			// the exact unchanged/drift checks for each target.
			viewsToPrepare = append(viewsToPrepare, viewName)
			continue
		}
		var preflightTargets []string
		preflightDirs := make(map[string]string)
		for _, target := range targetNames {
			if failedTargets[target] != nil {
				continue
			}
			if !localServingReady {
				continue
			}
			// Interrupted work must reconstruct the exact frozen generation;
			// never short-circuit it through a current-ref comparison.
			if recoveryIntent[target] == viewName || recoverySnapshot[target] != "" {
				needsPreparation = true
				continue
			}
			preflightDir := publicationPreflightDir(txDir, viewName, target)
			if err := os.Mkdir(preflightDir, 0o700); err != nil {
				return withExitCode(ExitInternal, "create %s/%s publication preflight: %v", viewName, target, err)
			}
			preflightTargets = append(preflightTargets, target)
			preflightDirs[target] = preflightDir
		}
		preflightResults, err := runPublicationPreflightsConcurrently(ctx, preflightTargets, values.workers,
			func(ctx context.Context, target string, workers int) (bool, error) {
				targetValues := values
				targetValues.workers = workers
				return publicationUnchangedPreflight(ctx, cfg, canonical, pool, repos, viewName, target, preflightDirs[target], targetValues)
			})
		if err != nil {
			return withExitCode(ExitInternal, "run %s publication preflights: %v", viewName, err)
		}
		for _, result := range preflightResults {
			target, unchanged, preflightErr := result.target, result.unchanged, result.err
			if errors.Is(preflightErr, pub.ErrVerification) {
				if len(targetNames) == 1 {
					return withExitCode(ExitVerification, "%v", preflightErr)
				}
				failedTargets[target] = preflightErr
				partial = true
				fmt.Fprintf(stdout, "publish target=%s view=%s status=failed-preflight-verification error=%q\n", target, viewName, redactPublishError(preflightErr))
				continue
			}
			if preflightErr != nil || !unchanged {
				// The full path below owns error classification and drift
				// evidence. A failed optimization never weakens validation.
				needsPreparation = true
				continue
			}
			if preflightUnchanged[viewName] == nil {
				preflightUnchanged[viewName] = make(map[string]bool)
			}
			preflightUnchanged[viewName][target] = true
			fmt.Fprintf(stdout, "publish target=%s view=%s status=unchanged preflight=ref-vector\n", target, viewName)
		}
		if !needsPreparation {
			continue
		}
		viewsToPrepare = append(viewsToPrepare, viewName)
	}
	var selectionOwner bool
	if len(viewsToPrepare) != 0 {
		requests := make([]materializationSelectionRequest, 0, len(viewsToPrepare)*2)
		for _, viewName := range viewsToPrepare {
			viewConfig := cfg.Views[viewName]
			leaves, err := selectedMutableRoutePhysicalLeaves(cfg, canonical, repos, viewName, values)
			if err != nil {
				return withExitCode(ExitConflict, "close publication view %s physical route owners: %v", viewName, err)
			}
			source := materializeCanonicalSource{ID: viewName, Public: viewConfig.Access == "public"}
			requests = append(requests, materializationSelectionRequest{
				Source: source, Leaves: leaves, TargetRoot: cfg.Root, IncludeMetadata: true,
				// Frozen compatibility candidates are staged read-only from CAS into
				// a digest-named, non-hosted tree. They are deliberately outside the
				// legacy-root materialization journal because publish cannot perform
				// an implicit local cutover.
				IncludeCompatibility: false, ExpandAPT: true,
			})
			servingTarget, targetErr := defaultMutableServingTarget(cfg, viewName)
			if targetErr != nil {
				return withExitCode(ExitConfig, "%v", targetErr)
			}
			requests = append(requests, materializationSelectionRequest{
				Source: source, Leaves: leaves, TargetRoot: servingTarget, IncludeServing: true,
			})
		}
		values, selectionOwner, err = beginMaterializationSelectionForRequests(cfg, canonical, values, "publish", requests)
		if err != nil {
			return withExitCode(ExitConflict, "begin publication selected-set materialization: %v", err)
		}
		defer func() {
			resultErr = errors.Join(resultErr, finishMaterializationSelectedSet(cfg, values.materializeTrust, selectionOwner, resultErr))
		}()
	}
	for _, viewName := range viewsToPrepare {
		viewTxDir := filepath.Join(txDir, "view-"+viewName)
		if err := os.Mkdir(viewTxDir, 0o700); err != nil {
			return withExitCode(ExitInternal, "create %s publication transaction: %v", viewName, err)
		}
		prepared, err := preparePublicationView(ctx, cfg, canonical, pool, repos, viewName, viewTxDir, values, privateKey, passphrase, stdout)
		if err != nil {
			return err
		}
		prepared.repositoryKeySHA256 = repositoryKeySHA
		preparedViews[viewName] = prepared
		viewTxDirs[viewName] = viewTxDir
	}
	if prepared, exists := preparedViews["latest"]; exists {
		workingRepos, err := preparedWorkingTreeRepos(prepared)
		if err != nil {
			return withExitCode(ExitInternal, "resolve latest working repositories: %v", err)
		}
		if _, _, err := refreshWorkingTreeBaselines(ctx, cfg, canonical, workingRepos, txDir, values, "publish-working-tree", state.ApplyOptions{}, stdout); err != nil {
			return stateMutationError("commit latest working tree", err)
		}
	}
	for _, viewName := range viewNames {
		prepared, exists := preparedViews[viewName]
		var leaves []localYUMServingLeaf
		if exists {
			leaves = localServingLeavesFromPrepared(prepared)
		} else {
			leaves, err = desiredLocalYUMServingLeaves(canonical, cfg, repos, viewName, values)
			if err != nil {
				return withExitCode(ExitVerification, "resolve local YUM serving topology for %s: %v", viewName, err)
			}
		}
		compatibilityPrepared := preparedPublication{view: viewName}
		if viewName == "latest" {
			compatibilitySource := prepared
			if !exists {
				compatibilitySource = preparedPublication{view: viewName}
				for _, leaf := range leaves {
					compatibilitySource.projections = append(compatibilitySource.projections, publicationProjection{view: viewName, repo: leaf.repo, os: leaf.os, arch: leaf.arch})
				}
			}
			compatibilityPrepared, err = activeLocalYUMCompatibilityPrepared(cfg, canonical, compatibilitySource)
			if err != nil {
				return withExitCode(ExitVerification, "resolve active local YUM compatibility routes: %v", err)
			}
			leaves = append(leaves, localYUMCompatibilityTopologyLeaves(compatibilityPrepared)...)
		}
		targetRoot, err := defaultMutableServingTarget(cfg, viewName)
		if err != nil {
			return withExitCode(ExitConfig, "%v", err)
		}
		var targetIdentity *serving.TargetIdentity
		baseURL := ""
		if len(leaves) != 0 {
			baseURL, err = cfg.ServingBaseURL(viewName)
			if err != nil {
				return withExitCode(ExitConfig, "%v", err)
			}
			identity, err := localServingTargetIdentity(cfg, viewName, targetRoot, baseURL)
			if err != nil {
				return withExitCode(ExitConfig, "%v", err)
			}
			targetIdentity = &identity
		}
		if exists && len(localServingLeavesFromPrepared(prepared)) != 0 {
			source := materializeCanonicalSource{ID: viewName, Public: cfg.Views[viewName].Access == "public"}
			if _, err := activateLocalYUMServing(ctx, cfg, canonical, pool, source, targetRoot, baseURL, repositoryKeySHA, viewTxDirs[viewName], localServingLeavesFromPrepared(prepared), values, localServingActivationOptions{}, stdout); err != nil {
				return withExitCode(ExitVerification, "activate local YUM serving view %s: %v", viewName, err)
			}
		}
		if viewName == "latest" {
			compatibilityTxDir := txDir
			if exists {
				compatibilityTxDir = viewTxDirs[viewName]
			}
			if _, err := activateLocalYUMCompatibilityServing(ctx, cfg, canonical, pool, targetRoot, baseURL, compatibilityTxDir, compatibilityPrepared, values, stdout); err != nil {
				return withExitCode(ExitVerification, "activate local YUM compatibility routes: %v", err)
			}
		}
		topology, err := reconcileLocalServingTopology(ctx, cfg, canonical, targetRoot, viewName, targetIdentity, leaves, localServingSelectionIsFull(values), false)
		if err != nil {
			return withExitCode(ExitVerification, "reconcile local YUM serving topology for %s: %v", viewName, err)
		}
		if topology.ChannelsRemoved != 0 || topology.LedgersExpired != 0 {
			fmt.Fprintf(stdout, "serving-topology view=%s channels_removed=%d pointers_removed=%d generation_ledgers_expired=%d\n", viewName, topology.ChannelsRemoved, topology.PointersRemoved, topology.LedgersExpired)
		}
		if targetRoot != cfg.Root {
			if _, err := os.Lstat(targetRoot); err == nil {
				if err := serving.PublishHostableTree(targetRoot); err != nil {
					return withExitCode(ExitVerification, "publish directly hostable %s tree: %v", viewName, err)
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return withExitCode(ExitVerification, "inspect %s serving tree: %v", viewName, err)
			}
		}
	}
	if _, err := pruneLocalServingLifecycle(ctx, cfg, canonical); err != nil {
		return withExitCode(ExitVerification, "apply local YUM serving retention: %v", err)
	}
	// Route receipts are the canonical read capability for Nginx. Commit them
	// only after every raw tree, generation, mirrorlist, topology removal, and
	// retention prune has converged, but before releasing the selected-set
	// barrier. A crash can therefore never expose an unreceipted completed local
	// publication as a successful transaction.
	for _, viewName := range viewsToPrepare {
		prepared := preparedViews[viewName]
		targetRoot, err := defaultMutableServingTarget(cfg, viewName)
		if err != nil {
			return withExitCode(ExitConfig, "%v", err)
		}
		baseURL, err := preflightMutableYUMServing(cfg, repos, viewName, "", false)
		if err != nil {
			return withExitCode(ExitConfig, "%v", err)
		}
		routeCommit, routeChanged, routeCount, err := persistPreparedMaterializedRoutes(
			ctx, cfg, canonical, pool, viewName, targetRoot, baseURL, prepared.routeLeaves, prepared, viewTxDirs[viewName], values,
		)
		if err != nil {
			return withExitCode(ExitVerification, "persist exact local Nginx route receipts for %s: %v", viewName, err)
		}
		if routeCount != 0 || routeChanged {
			fmt.Fprintf(stdout, "publish route-receipts view=%s receipts=%d commit=%s changed=%t\n", viewName, routeCount, routeCommit, routeChanged)
		}
	}
	selectionErr := finishMaterializationSelectedSet(cfg, values.materializeTrust, selectionOwner, nil)
	selectionOwner = false
	if selectionErr != nil {
		return withExitCode(ExitConflict, "%v", selectionErr)
	}
	preparedSnapshots := make(map[string]preparedPublication, len(defaultSnapshots)+len(recoverySnapshot))
	if defaultSelection {
		snapshotIDsToPrepare := append([]string(nil), defaultSnapshots...)
		for _, target := range targetNames {
			if snapshotID := recoverySnapshot[target]; snapshotID != "" && !contains(snapshotIDsToPrepare, snapshotID) {
				snapshotIDsToPrepare = append(snapshotIDsToPrepare, snapshotID)
			}
		}
		sort.Strings(snapshotIDsToPrepare)
		if len(snapshotIDsToPrepare) != 0 {
			snapshotDir := filepath.Join(txDir, "prepared-snapshots")
			if err := os.Mkdir(snapshotDir, 0o700); err != nil {
				return withExitCode(ExitInternal, "create prepared snapshot transaction: %v", err)
			}
			preparedSnapshots, err = prepareSnapshotPublicationSet(ctx, cfg, canonical, pool, repos, snapshotIDsToPrepare, snapshotDir, values, privateKey, passphrase, repositoryKeySHA, stdout)
			if err != nil {
				return err
			}
		}
	}
	desiredCommit, err := canonical.HeadHash()
	if err != nil || desiredCommit.IsZero() {
		return withExitCode(ExitConflict, "publish requires an initialized canonical state: %v", err)
	}

	// Each provider owns one strictly ordered release sequence: recover its exact
	// interrupted snapshot/view, advance beta/latest/stable, then publish every
	// retained snapshot. No provider observation or intent boundary waits for a
	// sibling. Canonical persistence is serialized, as is the rare local-only
	// materialization of an interrupted snapshot outside the retained window.
	healthyTargets := make([]string, 0, len(targetNames))
	for _, target := range targetNames {
		if failedTargets[target] == nil {
			healthyTargets = append(healthyTargets, target)
		}
	}
	var persistMutex sync.Mutex
	var snapshotPrepareMutex sync.Mutex
	preparedSnapshot := func(ctx context.Context, snapshotID string, output io.Writer) (preparedPublication, error) {
		snapshotPrepareMutex.Lock()
		defer snapshotPrepareMutex.Unlock()
		if prepared, exists := preparedSnapshots[snapshotID]; exists {
			return prepared, nil
		}
		if !defaultSelection {
			return preparedPublication{}, withExitCode(ExitConflict, "snapshot %s is outside the selected publication intent", snapshotID)
		}
		// The selected-set final barrier requires a stable canonical HEAD. Hold
		// the same coordinator used by remote-ref persistence while the missing
		// immutable snapshot is materialized; provider upload/verification remains
		// concurrent and never holds this lock.
		persistMutex.Lock()
		defer persistMutex.Unlock()
		snapshotDir := filepath.Join(txDir, "recovery-snapshot-"+snapshotID)
		if err := os.Mkdir(snapshotDir, 0o700); err != nil {
			return preparedPublication{}, withExitCode(ExitInternal, "create interrupted snapshot materialization: %v", err)
		}
		prepared, err := prepareSnapshotPublicationSet(ctx, cfg, canonical, pool, repos, []string{snapshotID}, snapshotDir, values, privateKey, passphrase, repositoryKeySHA, output)
		if err != nil {
			return preparedPublication{}, err
		}
		publication, exists := prepared[snapshotID]
		if !exists {
			return preparedPublication{}, withExitCode(ExitInternal, "interrupted snapshot %s was not prepared", snapshotID)
		}
		preparedSnapshots[snapshotID] = publication
		return publication, nil
	}
	sequenceOutcomes, err := runTargetPublicationSequencesConcurrently(ctx, healthyTargets, txDir, values.workers,
		func(ctx context.Context, target, targetDir string, workers int, output io.Writer) error {
			recoveredView := recoveryIntent[target]
			recoveredSnapshot := recoverySnapshot[target]
			if len(targetNames) > 1 {
				inspectDir := filepath.Join(targetDir, "inspect")
				if err := os.Mkdir(inspectDir, 0o700); err != nil {
					return withExitCode(ExitInternal, "create target recovery inspection: %v", err)
				}
				intentView, intentSnapshot, interrupted, inspectErr := interruptedPublicationIntent(ctx, cfg, canonical, target, inspectDir)
				if inspectErr != nil {
					selected := preparedPublication{view: viewNames[0]}
					_ = emitTargetPublicationOutcome(output, selected, targetPublicationPipelineOutcome{
						target: target, status: "failed-before-saga", err: inspectErr,
					})
					return inspectErr
				}
				if interrupted {
					if intentSnapshot != "" {
						if !defaultSelection {
							return withExitCode(ExitConflict, "target %s has an interrupted snapshot/%s publication; use the default selection or include that exact --snapshot", target, intentSnapshot)
						}
						recoveredSnapshot = intentSnapshot
					} else if !contains(viewNames, intentView) {
						return withExitCode(ExitConflict, "target %s has an interrupted %s publication; include --view %s to recover it", target, intentView, intentView)
					} else {
						recoveredView = intentView
					}
				}
			}
			if recoveredSnapshot != "" {
				prepared, err := preparedSnapshot(ctx, recoveredSnapshot, output)
				if err != nil {
					return err
				}
				intentDir := filepath.Join(targetDir, "recover-snapshot-"+recoveredSnapshot)
				if err := os.Mkdir(intentDir, 0o700); err != nil {
					return withExitCode(ExitInternal, "create snapshot recovery transaction: %v", err)
				}
				outcome := publishPreparedTarget(ctx, cfg, canonical, repos, prepared, target, desiredCommit, intentDir, values, workers, &persistMutex)
				if failure := emitTargetPublicationOutcome(output, prepared, outcome); failure != nil {
					fmt.Fprintf(output, "publish target=%s view=snapshot status=failed-recovery error=%q\n", target, redactPublishError(failure))
					return failure
				}
			}
			if recoveredView != "" {
				prepared, exists := preparedViews[recoveredView]
				if !exists {
					return withExitCode(ExitConflict, "target %s interrupted view %s has no frozen prepared publication", target, recoveredView)
				}
				intentDir := filepath.Join(targetDir, "recover-view-"+recoveredView)
				if err := os.Mkdir(intentDir, 0o700); err != nil {
					return withExitCode(ExitInternal, "create view recovery transaction: %v", err)
				}
				outcome := publishPreparedTarget(ctx, cfg, canonical, repos, prepared, target, desiredCommit, intentDir, values, workers, &persistMutex)
				if failure := emitTargetPublicationOutcome(output, prepared, outcome); failure != nil {
					return failure
				}
			}
			for _, viewName := range viewNames {
				if viewName == recoveredView || preflightUnchanged[viewName][target] {
					continue
				}
				prepared, exists := preparedViews[viewName]
				if !exists {
					return withExitCode(ExitConflict, "target %s view %s requires a prepared publication", target, viewName)
				}
				intentDir := filepath.Join(targetDir, "view-"+viewName)
				if err := os.Mkdir(intentDir, 0o700); err != nil {
					return withExitCode(ExitInternal, "create view publication transaction: %v", err)
				}
				outcome := publishPreparedTarget(ctx, cfg, canonical, repos, prepared, target, desiredCommit, intentDir, values, workers, &persistMutex)
				if failure := emitTargetPublicationOutcome(output, prepared, outcome); failure != nil {
					return failure
				}
			}
			for _, snapshotID := range defaultSnapshots {
				prepared, err := preparedSnapshot(ctx, snapshotID, output)
				if err != nil {
					return err
				}
				intentDir := filepath.Join(targetDir, "snapshot-"+snapshotID)
				if err := os.Mkdir(intentDir, 0o700); err != nil {
					return withExitCode(ExitInternal, "create retained snapshot publication transaction: %v", err)
				}
				outcome := publishPreparedTarget(ctx, cfg, canonical, repos, prepared, target, desiredCommit, intentDir, values, workers, &persistMutex)
				if failure := emitTargetPublicationOutcome(output, prepared, outcome); failure != nil {
					return failure
				}
			}
			return nil
		})
	if err != nil {
		return withExitCode(ExitInternal, "run target publication sequences: %v", err)
	}
	for _, outcome := range sequenceOutcomes {
		if len(outcome.output) != 0 {
			_, _ = stdout.Write(outcome.output)
		}
		if outcome.err == nil {
			continue
		}
		failedTargets[outcome.target] = outcome.err
		partial = true
		if len(outcome.output) == 0 {
			fmt.Fprintf(stdout, "publish target=%s status=failed-sequence error=%q\n", outcome.target, redactPublishError(outcome.err))
		}
	}
	if len(targetNames) == 1 && len(failedTargets) != 0 {
		return publishTargetExitError(failedTargets[targetNames[0]])
	}
	if partial {
		return withExitCode(ExitPartialPublish, "one or more cloud targets remain behind; successful targets were committed independently")
	}
	return nil
}

// recoverPublicationViewMaterializationSelection closes one interrupted local
// view set before normal publication preflight is allowed to inspect or mutate
// any remote target. The durable journal, not today's default view list,
// determines the exact recovery batch; after it converges the caller reruns the
// ordinary O(change-set) preflight for any additional selected views.
func recoverPublicationViewMaterializationSelection(
	ctx context.Context,
	cfg *config.Config,
	canonical *state.Store,
	pool *repository.Store,
	plan publicationMaterializationRecovery,
	txDir string,
	values commonFlags,
	privateKey, passphrase []byte,
	repositoryKeySHA string,
	journal materializationSelectionJournal,
	stdout io.Writer,
) (resultErr error) {
	if plan.kind != publicationMaterializationRecoveryViews {
		return withExitCode(ExitConflict, "durable publication materialization is not a mutable-view recovery")
	}
	type recoveryKinds struct {
		metadata      bool
		serving       bool
		compatibility bool
	}
	byView := make(map[string]recoveryKinds)
	for _, unit := range journal.Units {
		kinds := byView[unit.Source]
		switch unit.Kind {
		case "apt", "yum", "asset":
			kinds.metadata = true
		case "yum-compat":
			kinds.metadata = true
			kinds.compatibility = true
		case "serving":
			kinds.serving = true
		default:
			return withExitCode(ExitConflict, "unsupported durable publication materialization unit kind %s", unit.Kind)
		}
		byView[unit.Source] = kinds
	}
	viewNames := make([]string, 0, len(byView))
	for viewName := range byView {
		viewNames = append(viewNames, viewName)
	}
	sort.Strings(viewNames)
	if len(viewNames) == 0 {
		return withExitCode(ExitConflict, "durable publication materialization has no recoverable view units")
	}

	requests := make([]materializationSelectionRequest, 0, len(viewNames)*2)
	reposByView := make(map[string][]config.Repo, len(viewNames))
	servingTargets := make(map[string]string, len(viewNames))
	for _, viewName := range viewNames {
		viewConfig := cfg.Views[viewName]
		leaves := plan.leavesBySource[viewName]
		repos, err := publicationRecoveryRepos(cfg, leaves)
		if err != nil {
			return withExitCode(ExitConflict, "resolve recovered local view %s repos: %v", viewName, err)
		}
		reposByView[viewName] = repos
		source := materializeCanonicalSource{ID: viewName, Public: viewConfig.Access == "public"}
		targetRoot, err := defaultMutableServingTarget(cfg, viewName)
		if err != nil {
			return withExitCode(ExitConfig, "%v", err)
		}
		servingTargets[viewName] = targetRoot
		if byView[viewName].metadata {
			requests = append(requests, materializationSelectionRequest{
				Source: source, Leaves: leaves, TargetRoot: cfg.Root, IncludeMetadata: true,
				IncludeCompatibility: byView[viewName].compatibility,
			})
		}
		if byView[viewName].serving {
			requests = append(requests, materializationSelectionRequest{Source: source, Leaves: leaves, TargetRoot: targetRoot, IncludeServing: true})
		}
	}
	recoveryValues := values
	recoveryValues.materializeCompatibility = make(map[string]bool, len(byView))
	for viewName, kinds := range byView {
		recoveryValues.materializeCompatibility[viewName] = kinds.compatibility
	}
	recoveryValues, selectionOwner, err := beginMaterializationSelectionForRequests(cfg, canonical, recoveryValues, "publish", requests)
	if err != nil {
		return withExitCode(ExitConflict, "resume exact publication selected-set materialization: %v", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, finishMaterializationSelectedSet(cfg, recoveryValues.materializeTrust, selectionOwner, resultErr))
	}()

	prepared := make(map[string]preparedPublication, len(viewNames))
	viewDirs := make(map[string]string, len(viewNames))
	for _, viewName := range viewNames {
		directory := filepath.Join(txDir, "recover-local-view-"+viewName)
		if err := os.Mkdir(directory, 0o700); err != nil {
			return withExitCode(ExitInternal, "create local publication recovery transaction: %v", err)
		}
		viewDirs[viewName] = directory
		if !byView[viewName].metadata {
			continue
		}
		publication, err := preparePublicationView(ctx, cfg, canonical, pool, reposByView[viewName], viewName, directory, recoveryValues, privateKey, passphrase, stdout)
		if err != nil {
			return err
		}
		prepared[viewName] = publication
	}
	if latest, exists := prepared["latest"]; exists {
		workingRepos, err := preparedWorkingTreeRepos(latest)
		if err != nil {
			return withExitCode(ExitInternal, "resolve recovered latest working repositories: %v", err)
		}
		if _, _, err := refreshWorkingTreeBaselines(ctx, cfg, canonical, workingRepos, txDir, recoveryValues, "publish-working-tree", state.ApplyOptions{}, stdout); err != nil {
			return stateMutationError("commit recovered latest working tree", err)
		}
	}
	for _, viewName := range viewNames {
		if !byView[viewName].serving {
			continue
		}
		leaves := localServingLeavesFromPrepared(prepared[viewName])
		if _, exists := prepared[viewName]; !exists {
			leaves, err = desiredLocalYUMServingLeaves(canonical, cfg, reposByView[viewName], viewName, recoveryValues)
			if err != nil {
				return withExitCode(ExitVerification, "resolve recovered local YUM serving leaves for %s: %v", viewName, err)
			}
		}
		baseURL, err := cfg.ServingBaseURL(viewName)
		if err != nil {
			return withExitCode(ExitConfig, "%v", err)
		}
		source := materializeCanonicalSource{ID: viewName, Public: cfg.Views[viewName].Access == "public"}
		if _, err := activateLocalYUMServing(ctx, cfg, canonical, pool, source, servingTargets[viewName], baseURL, repositoryKeySHA, viewDirs[viewName], leaves, recoveryValues, localServingActivationOptions{}, stdout); err != nil {
			return withExitCode(ExitVerification, "recover local YUM serving view %s: %v", viewName, err)
		}
	}
	if _, err := pruneLocalServingLifecycle(ctx, cfg, canonical); err != nil {
		return withExitCode(ExitVerification, "apply recovered local YUM serving retention: %v", err)
	}
	for _, viewName := range viewNames {
		publication, exists := prepared[viewName]
		if !exists {
			continue
		}
		baseURL, err := preflightMutableYUMServing(cfg, reposByView[viewName], viewName, "", false)
		if err != nil {
			return withExitCode(ExitConfig, "%v", err)
		}
		routeCommit, routeChanged, routeCount, err := persistPreparedMaterializedRoutes(
			ctx, cfg, canonical, pool, viewName, servingTargets[viewName], baseURL, publication.routeLeaves, publication, viewDirs[viewName], recoveryValues, materializedRouteCleanupPreserve,
		)
		if err != nil {
			return withExitCode(ExitVerification, "recover exact local Nginx route receipts for %s: %v", viewName, err)
		}
		if routeCount != 0 || routeChanged {
			fmt.Fprintf(stdout, "recovery route-receipts view=%s receipts=%d commit=%s changed=%t\n", viewName, routeCount, routeCommit, routeChanged)
		}
	}
	finishErr := finishMaterializationSelectedSet(cfg, recoveryValues.materializeTrust, selectionOwner, nil)
	selectionOwner = false
	if finishErr != nil {
		return withExitCode(ExitConflict, "%v", finishErr)
	}
	return nil
}

func interruptedPublicationIntent(ctx context.Context, cfg *config.Config, canonical *state.Store, target, txDir string) (string, string, bool, error) {
	client, err := newPublishTargetClient(cfg, target, "latest", false)
	if err != nil {
		return "", "", false, err
	}
	observation, err := observeRemoteTarget(ctx, canonical, client, target, txDir)
	if err != nil {
		return "", "", false, err
	}
	if observation.resumeLock != nil {
		return observation.resumeLock.IntentView, observation.resumeLock.IntentSnapshot, true, nil
	}
	if observation.resumeCheckpoint == nil {
		return "", "", false, nil
	}
	intent := observation.resumeCheckpoint.IntentView
	snapshot := observation.resumeCheckpoint.IntentSnapshot
	if observation.resumeGeneration != nil && !pub.SamePublicationIntent(observation.resumeGeneration.IntentView, observation.resumeGeneration.IntentSnapshot, intent, snapshot) {
		return "", "", false, fmt.Errorf("remote target %s checkpoint/generation intent mismatch", target)
	}
	return intent, snapshot, true, nil
}

func selectedPublishViews(selected []string) ([]string, error) {
	order := []string{"beta", "latest", "stable"}
	if len(selected) == 0 {
		return order, nil
	}
	for _, value := range selected {
		if value != "beta" && value != "latest" && value != "stable" {
			return nil, fmt.Errorf("unsupported publish view %q", value)
		}
	}
	var result []string
	for _, value := range order {
		if contains(selected, value) {
			result = append(result, value)
		}
	}
	return result, nil
}

func selectedPublishTargets(cfg *config.Config, selected []string) ([]string, error) {
	if len(selected) == 0 {
		for name := range cfg.Targets {
			selected = append(selected, name)
		}
	}
	if len(selected) == 0 {
		return nil, errors.New("publish requires at least one configured target")
	}
	deduplicated := make([]string, 0, len(selected))
	seen := make(map[string]struct{}, len(selected))
	for _, name := range selected {
		if name != "cf" && name != "cos" {
			return nil, fmt.Errorf("unsupported publish target %q", name)
		}
		if _, exists := cfg.Targets[name]; !exists {
			return nil, fmt.Errorf("publish target %q is not configured", name)
		}
		if _, duplicate := seen[name]; !duplicate {
			seen[name] = struct{}{}
			deduplicated = append(deduplicated, name)
		}
	}
	sort.Strings(deduplicated)
	return deduplicated, nil
}

func loadPublishSigningSecrets(cfg *config.Config, repos []config.Repo, privateKeyFile, passphraseFile string) ([]byte, []byte, error) {
	privateKey, passphrase, _, err := loadPublishSigningSecretsWithIdentity(cfg, repos, privateKeyFile, passphraseFile)
	return privateKey, passphrase, err
}

func preflightPublishedRepositoryKeyContinuity(cfg *config.Config, canonical *state.Store, targets []string, capturedKeySHA string) error {
	for _, target := range targets {
		generation, _, exists, err := readLocalTargetGeneration(canonical, target)
		if err != nil {
			return fmt.Errorf("inspect target %s repository signing identity: %w", target, err)
		}
		if !exists {
			continue
		}
		if err := validatePublishedRepositoryKeyContinuity(cfg, target, generation, capturedKeySHA); err != nil {
			return err
		}
	}
	return nil
}

func validatePublishedRepositoryKeyContinuity(cfg *config.Config, target string, generation pub.TargetGeneration, capturedKeySHA string) error {
	currentKeySHA, err := repositoryTrustAnchorSHA256ForRefs(cfg, generation.Refs)
	if err != nil {
		return fmt.Errorf("target %s repository signing identity: %w", target, err)
	}
	if generation.RepositoryKeySHA256 != currentKeySHA {
		return fmt.Errorf("%w: repository signing key changed for published target %s; restore the recorded key to replay, or perform an explicit offline target migration", pub.ErrDrift, target)
	}
	if capturedKeySHA != "" && currentKeySHA != "" && capturedKeySHA != currentKeySHA {
		return fmt.Errorf("%w: injected repository signing key differs from published target %s", pub.ErrDrift, target)
	}
	return nil
}

func loadPublishSigningSecretsWithIdentity(cfg *config.Config, repos []config.Repo, privateKeyFile, passphraseFile string) ([]byte, []byte, string, error) {
	required := false
	for _, repo := range repos {
		if repo.Type == "apt" || repo.Type == "yum" {
			required = true
			break
		}
	}
	if !required {
		return nil, nil, "", nil
	}
	privateKey, err := resolveSecret(cfg.GPG.PrivateKey, privateKeyFile, false)
	if err != nil {
		return nil, nil, "", fmt.Errorf("resolve repository signing key: %w", err)
	}
	passphrase, err := resolveSecret(cfg.GPG.Passphrase, passphraseFile, true)
	if err != nil {
		clearSecret(privateKey)
		return nil, nil, "", fmt.Errorf("resolve repository signing passphrase: %w", err)
	}
	identity, err := repositorySigningKeyIdentity(cfg, privateKey)
	if err != nil {
		clearSecret(privateKey)
		clearSecret(passphrase)
		return nil, nil, "", fmt.Errorf("repository signing trust preflight failed: %w", err)
	}
	return privateKey, passphrase, identity, nil
}

func preparePublicationView(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, repos []config.Repo, viewName, txDir string, values commonFlags, privateKey, passphrase []byte, stdout io.Writer) (preparedPublication, error) {
	return preparePublicationViewWithVerb(ctx, cfg, canonical, pool, repos, viewName, txDir, values, privateKey, passphrase, "publish", stdout)
}

type boundedOrderedTask[T any] struct {
	key string
	run func(context.Context, int) (T, error)
}

// runBoundedOrdered executes independent repo/leaf work concurrently while
// dividing the caller's worker budget across inner hashing/index pools. The
// outer and inner bounds therefore never multiply into workers squared. Task
// results and errors are returned in stable key order regardless of schedule.
func runBoundedOrdered[T any](ctx context.Context, totalWorkers int, tasks []boundedOrderedTask[T]) ([]T, error) {
	if len(tasks) == 0 {
		return nil, nil
	}
	if totalWorkers < 1 {
		return nil, errors.New("worker count must be positive")
	}
	sort.Slice(tasks, func(i, j int) bool { return tasks[i].key < tasks[j].key })
	for index := 1; index < len(tasks); index++ {
		if tasks[index-1].key == tasks[index].key {
			return nil, fmt.Errorf("duplicate bounded task key %s", tasks[index].key)
		}
	}
	outerWorkers := min(totalWorkers, len(tasks))
	innerWorkers := max(1, totalWorkers/outerWorkers)
	results := make([]T, len(tasks))
	errorsByIndex := make([]error, len(tasks))
	jobs := make(chan int, len(tasks))
	for index := range tasks {
		jobs <- index
	}
	close(jobs)
	var group sync.WaitGroup
	for range outerWorkers {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range jobs {
				if err := ctx.Err(); err != nil {
					errorsByIndex[index] = err
					continue
				}
				results[index], errorsByIndex[index] = tasks[index].run(ctx, innerWorkers)
			}
		}()
	}
	group.Wait()
	for index, err := range errorsByIndex {
		if err != nil {
			return nil, fmt.Errorf("%s: %w", tasks[index].key, err)
		}
	}
	return results, nil
}

type publicationPreparationResult struct {
	projection      publicationProjection
	extraProjection *publicationProjection
	yumOwnerLeaves  []viewLeaf
	output          string
	aptLedgers      map[string]string
	byHashRemoved   int
}

func preparePublicationViewWithVerb(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, repos []config.Repo, viewName, txDir string, values commonFlags, privateKey, passphrase []byte, verb string, stdout io.Writer) (prepared preparedPublication, resultErr error) {
	prepared = preparedPublication{view: viewName, repositoryPool: pool}
	var err error
	viewConfig, exists := cfg.Views[viewName]
	if !exists || !viewIncludesRepoSet(viewConfig, repos) {
		return prepared, withExitCode(ExitConfig, "view %s contains none of the selected repositories", viewName)
	}
	source := materializeCanonicalSource{ID: viewName, Public: viewConfig.Access == "public"}
	var requestedLeaves []viewLeaf
	for _, leaf := range suiteClosedSelectedLeaves(cfg, repos, values) {
		if viewIncludesRepo(viewConfig, leaf.repo.ID) && viewLeafExists(canonical, viewName, leaf) {
			requestedLeaves = append(requestedLeaves, leaf)
		}
	}
	transactionLeaves, err := materializedRoutePhysicalClosureLeaves(cfg, canonical, source, requestedLeaves)
	if err != nil {
		return prepared, withExitCode(ExitConflict, "close %s selectors to physical route owners: %v", viewName, err)
	}
	physicalRepos, err := materializedRoutePhysicalRepos(cfg, transactionLeaves)
	if err != nil {
		return prepared, withExitCode(ExitConflict, "resolve %s physical route repositories: %v", viewName, err)
	}
	logicalRepos := make(map[string]config.Repo, len(repos))
	logicalLeaves := make(map[string][]viewLeaf, len(repos))
	for _, repo := range repos {
		logicalRepos[repo.ID] = repo
	}
	for _, leaf := range requestedLeaves {
		logicalLeaves[leaf.repo.ID] = append(logicalLeaves[leaf.repo.ID], leaf)
	}
	prepared.routeLeaves = append([]viewLeaf(nil), transactionLeaves...)
	var compatibility []config.YUMCompatibilityProjection
	if verb == "publish" && viewName == "latest" {
		compatibility, err = selectedYUMCompatibilityProjections(cfg, source, transactionLeaves, values)
		if err != nil {
			return prepared, withExitCode(ExitConfig, "select YUM compatibility projections: %v", err)
		}
		prepared.compatibilitySelected = make(map[string]config.YUMCompatibilityProjection, len(compatibility))
		prepared.compatibilityOwners = make(map[string]config.Repo, len(compatibility))
		for _, projection := range compatibility {
			prepared.compatibilitySelected[projection.ID] = projection
			owner, exists := cfg.RepoByName(projection.Source.Repo)
			if !exists {
				return prepared, withExitCode(ExitConfig, "YUM compatibility projection %s owner %s is unavailable", projection.ID, projection.Source.Repo)
			}
			prepared.compatibilityOwners[projection.ID] = owner
		}
	}
	values, selectionOwner, err := beginMaterializationSelectionForSource(cfg, canonical, values, selectedMaterializationOperation(values, verb), source, transactionLeaves, cfg.Root, true, false, true)
	if err != nil {
		return prepared, withExitCode(ExitConflict, "begin %s selected-set materialization: %v", viewName, err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, finishMaterializationSelectedSet(cfg, values.materializeTrust, selectionOwner, resultErr))
	}()
	var tasks []boundedOrderedTask[publicationPreparationResult]
	for _, repo := range physicalRepos {
		if !viewIncludesRepo(viewConfig, repo.ID) {
			continue
		}
		logicalRepo, selected := logicalRepos[repo.ID]
		if !selected {
			continue
		}
		switch repo.Type {
		case "asset":
			leaf := viewLeaf{repo: repo, os: "all", arch: "all"}
			if !viewLeafExists(canonical, viewName, leaf) {
				continue
			}
			repo, logicalRepo := repo, logicalRepo
			tasks = append(tasks, boundedOrderedTask[publicationPreparationResult]{key: "asset/" + repo.ID, run: func(ctx context.Context, workers int) (publicationPreparationResult, error) {
				taskValues := values
				taskValues.workers = workers
				materialized, reconciled, err := materializeAssetView(ctx, cfg, canonical, pool, repo, viewName, txDir, taskValues)
				if err != nil {
					return publicationPreparationResult{}, withExitCode(ExitVerification, "materialize asset %s/%s: %v", viewName, repo.ID, err)
				}
				sourceRoot := repositoryViewTarget(repo.Path, viewName)
				return publicationPreparationResult{
					projection: publicationProjection{
						view: viewName, repo: logicalRepo, physicalRepo: repo, os: "all", arch: "all", sourceRoot: sourceRoot,
						canonicalRoot: repo.Path, remoteRoot: repo.AssetPublicRoot(), legacyRoot: repo.Path,
					},
					output: fmt.Sprintf("%s materialized view=%s repo=%s entries=%d linked=%d relinked=%d pruned=%d", verb, viewName, repo.ID, materialized.Entries, materialized.Linked, materialized.Relinked, reconciled.RemovedFiles),
				}, nil
			}})
		case "apt":
			repo, logicalRepo := repo, logicalPublicationRepo(cfg, logicalRepo, logicalLeaves[repo.ID])
			selectedLeaves := append([]viewLeaf(nil), logicalLeaves[repo.ID]...)
			tasks = append(tasks, boundedOrderedTask[publicationPreparationResult]{key: "apt/" + repo.ID, run: func(ctx context.Context, workers int) (publicationPreparationResult, error) {
				taskValues := values
				taskValues.workers = workers
				taskValues.oses = csvFlag{}
				taskValues.arches = csvFlag{}
				result, err := materializeAPTRepo(ctx, cfg, canonical, pool, repo, viewName, txDir, taskValues, privateKey, passphrase)
				if err != nil {
					return publicationPreparationResult{}, withExitCode(ExitVerification, "materialize APT %s/%s: %v", viewName, repo.ID, err)
				}
				selectedPayload := filepath.Join(txDir, "publish-selected-apt-"+repo.ID+".tsv")
				if _, _, err := projectCanonicalMaterializationLeaves(canonical, source, selectedLeaves, selectedPayload); err != nil {
					return publicationPreparationResult{}, withExitCode(ExitVerification, "project selected APT %s/%s payload: %v", viewName, repo.ID, err)
				}
				return publicationPreparationResult{
					projection: publicationProjection{
						view: viewName, repo: logicalRepo, physicalRepo: repo, sourceRoot: result.Target,
						canonicalRoot: repo.Path, remoteRoot: repo.Path, legacyRoot: repo.Path,
						selectedPayloadManifest: selectedPayload,
						routeExactManifest:      result.ExactManifest,
						aptMetadataSuites:       append([]string(nil), logicalRepo.APT.Suites...),
					},
					output:        fmt.Sprintf("%s materialized view=%s repo=%s suites=%d linked=%d relinked=%d pruned=%d", verb, viewName, repo.ID, len(result.Builds), result.Packages.Linked, result.Packages.Relinked, result.Reconciled.RemovedFiles),
					aptLedgers:    result.Ledgers,
					byHashRemoved: result.ByHashRemoved,
				}, nil
			}})
		case "yum":
			byArch := make(map[string][]viewLeaf)
			for _, leaf := range transactionLeaves {
				if leaf.repo.ID != repo.ID {
					continue
				}
				byArch[leaf.arch] = append(byArch[leaf.arch], leaf)
			}
			arches := make([]string, 0, len(byArch))
			for arch := range byArch {
				arches = append(arches, arch)
			}
			sort.Strings(arches)
			for _, arch := range arches {
				repo, logicalRepo, ownerLeaves := repo, logicalRepo, append([]viewLeaf(nil), byArch[arch]...)
				key := "yum/" + repo.ID + "/" + arch
				tasks = append(tasks, boundedOrderedTask[publicationPreparationResult]{key: key, run: func(ctx context.Context, workers int) (publicationPreparationResult, error) {
					taskValues := values
					taskValues.workers = workers
					taskValues.oses = csvFlag{}
					taskValues.arches = csvFlag{}
					result, err := materializeYUMOwner(ctx, cfg, canonical, pool, repo, ownerLeaves, viewName, txDir, taskValues, privateKey, passphrase)
					if err != nil {
						return publicationPreparationResult{}, withExitCode(ExitVerification, "materialize YUM %s/%s/%s: %v", viewName, repo.ID, arch, err)
					}
					legacy, _ := repo.PathForArch(arch)
					anchorLeaf := ownerLeaves[0]
					return publicationPreparationResult{
						projection: publicationProjection{
							view: viewName, repo: logicalRepo, physicalRepo: repo, os: anchorLeaf.os, arch: arch, sourceRoot: result.Target,
							canonicalRoot: legacy, remoteRoot: legacy, legacyRoot: legacy,
							selectedPayloadManifest: result.PayloadManifest,
							routeExactManifest:      result.ExactManifest,
						},
						yumOwnerLeaves: append([]viewLeaf(nil), ownerLeaves...),
						output:         fmt.Sprintf("%s materialized view=%s repo=%s aliases=%d arch=%s linked=%d relinked=%d pruned=%d repomd_sha256=%s", verb, viewName, repo.ID, len(ownerLeaves), arch, result.Packages.Linked, result.Packages.Relinked, result.Reconciled.RemovedFiles, result.Generation.RepomdSHA256),
					}, nil
				}})
			}
		}
	}
	if verb == "publish" {
		compatibilityCommit, err := canonical.HeadHash()
		if err != nil || compatibilityCommit.IsZero() {
			return prepared, withExitCode(ExitConflict, "read YUM compatibility cutover state: %v", err)
		}
		for _, compatibilityProjection := range compatibility {
			compatibilityProjection := compatibilityProjection
			active, err := publicationYUMCompatibilityActiveAt(canonical, compatibilityCommit, compatibilityProjection.ID)
			if err != nil {
				return prepared, withExitCode(ExitVerification, "validate YUM compatibility cutover ledger %s: %v", compatibilityProjection.ID, err)
			}
			if !active {
				continue
			}
			tasks = append(tasks, boundedOrderedTask[publicationPreparationResult]{key: "yum-compat/" + compatibilityProjection.ID, run: func(ctx context.Context, workers int) (publicationPreparationResult, error) {
				taskValues := values
				taskValues.workers = workers
				stage, err := stageFrozenYUMCompatibilityPublication(ctx, cfg, canonical, pool, compatibilityProjection, txDir, taskValues)
				if err != nil {
					return publicationPreparationResult{}, withExitCode(ExitVerification, "stage frozen YUM compatibility %s: %v", compatibilityProjection.ID, err)
				}
				return publicationPreparationResult{
					projection: stage.projection, extraProjection: &stage.trustProjection,
					output: fmt.Sprintf("publish staged frozen compatibility=%s source=%s/%s/%s entries=%d bytes=%d linked=%d relinked=%d pruned=%d repomd_sha256=%s served_tree_rewritten=false",
						compatibilityProjection.ID, compatibilityProjection.Source.Repo, compatibilityProjection.Source.OS, compatibilityProjection.Source.Arch,
						stage.entries, stage.bytes, stage.linked, stage.relinked, stage.pruned, stage.repomd),
				}, nil
			}})
		}
	}
	preparedResults, err := runBoundedOrdered(ctx, values.workers, tasks)
	if err != nil {
		return prepared, err
	}
	ledgerStages := make(map[string]string)
	var byHashRemoved int
	for _, result := range preparedResults {
		prepared.projections = append(prepared.projections, result.projection)
		if len(result.yumOwnerLeaves) != 0 {
			if prepared.yumOwnerLeaves == nil {
				prepared.yumOwnerLeaves = make(map[string][]viewLeaf)
			}
			key := yumPublicationOwnerKey(result.projection.repo.ID, result.projection.arch)
			if _, duplicate := prepared.yumOwnerLeaves[key]; duplicate {
				return prepared, withExitCode(ExitInternal, "duplicate prepared YUM physical owner %s/%s", result.projection.repo.ID, result.projection.arch)
			}
			prepared.yumOwnerLeaves[key] = append([]viewLeaf(nil), result.yumOwnerLeaves...)
		}
		if result.extraProjection != nil {
			prepared.projections = append(prepared.projections, *result.extraProjection)
		}
		fmt.Fprintln(stdout, result.output)
		if err := mergeAPTByHashStages(ledgerStages, result.aptLedgers); err != nil {
			return prepared, withExitCode(ExitInternal, "merge APT by-hash retention stages: %v", err)
		}
		byHashRemoved += result.byHashRemoved
	}
	if err := prepared.validateYUMOwnerVectors(); err != nil {
		return prepared, withExitCode(ExitVerification, "%v", err)
	}
	if len(prepared.projections) == 0 {
		return prepared, withExitCode(ExitConfig, "selectors matched no %s view refs", viewName)
	}
	if len(ledgerStages) != 0 {
		ledgerCommit, ledgerChanged, err := persistAPTByHashStages(ctx, canonical, verb, ledgerStages)
		if err != nil {
			return prepared, stateMutationError("commit APT by-hash retention", err)
		}
		fmt.Fprintf(stdout, "%s apt-by-hash view=%s retained=%d removed=%d commit=%s changed=%t\n", verb, viewName, cfg.State.APTByHashRetention, byHashRemoved, ledgerCommit, ledgerChanged)
	}
	var scanTasks []boundedOrderedTask[string]
	for index, projection := range prepared.projections {
		index, projection := index, projection
		scanTasks = append(scanTasks, boundedOrderedTask[string]{key: projection.sourceRoot, run: func(ctx context.Context, workers int) (string, error) {
			filename := filepath.Join(txDir, fmt.Sprintf("scan-%s-%06d.tsv", viewName, index))
			scanRoot := projection.sourceRoot
			if projection.localRoot != "" {
				scanRoot = projection.localRoot
			}
			if _, err := manifest.Scan(ctx, cfg.Root, manifest.Scope{Path: scanRoot}, filename, manifest.ScanOptions{Workers: workers, ChunkEntries: values.chunk, TempDir: filepath.Join(cfg.StatePath(), "tmp")}); err != nil {
				return "", withExitCode(ExitVerification, "scan publication source %s: %v", scanRoot, err)
			}
			if projection.localRoot != "" {
				logical := filepath.Join(txDir, fmt.Sprintf("scan-%s-%06d-logical.tsv", viewName, index))
				if err := rewriteManifestRoot(filename, logical, projection.localRoot, projection.sourceRoot); err != nil {
					return "", withExitCode(ExitInternal, "map isolated publication source %s: %v", projection.localRoot, err)
				}
				filename = logical
			}
			original, exists := cfg.RepoByName(projection.repo.ID)
			if projection.repo.Type == "apt" && exists && !repoSelectionIsFull(original, projection.repo) {
				filtered := filepath.Join(txDir, fmt.Sprintf("scan-%s-%06d-selected.tsv", viewName, index))
				if err := filterAPTPublicationManifest(filename, projection.selectedPayloadManifest, projection, original, filtered); err != nil {
					return "", withExitCode(ExitVerification, "filter selected APT publication source %s: %v", projection.sourceRoot, err)
				}
				filename = filtered
			}
			return filename, nil
		}})
		prepared.scopes = append(prepared.scopes, projection.sourceRoot)
	}
	manifests, err := runBoundedOrdered(ctx, values.workers, scanTasks)
	if err != nil {
		return prepared, err
	}
	prepared.manifestPath = filepath.Join(txDir, "selected-"+viewName+".tsv")
	if err := mergePublicationManifests(manifests, prepared.manifestPath, txDir); err != nil {
		return prepared, withExitCode(ExitInternal, "merge %s publication manifest: %v", viewName, err)
	}
	sort.Strings(prepared.scopes)
	return prepared, nil
}

func viewIncludesRepoSet(view config.View, repos []config.Repo) bool {
	for _, repo := range repos {
		if viewIncludesRepo(view, repo.ID) {
			return true
		}
	}
	return false
}

// logicalPublicationRepo restores the suite-wide APT transaction boundary
// while preserving the caller's repo selector. The physical materializer uses
// the full configured repo; remote refs and manifests consume this detached
// logical contract so unselected suites remain at their previously published
// generation.
func logicalPublicationRepo(cfg *config.Config, selected config.Repo, leaves []viewLeaf) config.Repo {
	if selected.Type != "apt" || selected.APT == nil {
		return selected
	}
	configured, exists := cfg.RepoByName(selected.ID)
	if !exists || configured.Type != "apt" || configured.APT == nil {
		return selected
	}
	suites := make([]string, 0, len(leaves))
	for _, leaf := range leaves {
		if leaf.repo.ID == selected.ID {
			suites = append(suites, leaf.os)
		}
	}
	selected.Arches = append([]string(nil), configured.Arches...)
	selected.APT = configured.APT.NarrowSuites(uniqueSorted(suites))
	return selected
}

// selectedMutableRoutePhysicalLeaves resolves the caller's logical selector
// first, then closes only touched on-disk owners. APT closes repo-wide, YUM
// closes repo+arch across aliases, and assets remain all/all. Reusing this at
// every publish fast/slow/recovery boundary prevents a narrow selector from
// acquiring a journal or Nginx capability for only part of one physical tree.
func selectedMutableRoutePhysicalLeaves(cfg *config.Config, canonical *state.Store, repos []config.Repo, viewName string, values commonFlags) ([]viewLeaf, error) {
	viewConfig, exists := cfg.Views[viewName]
	if !exists {
		return nil, fmt.Errorf("unknown materialized route view %q", viewName)
	}
	source := materializeCanonicalSource{ID: viewName, Public: viewConfig.Access == "public"}
	var requested []viewLeaf
	for _, leaf := range suiteClosedSelectedLeaves(cfg, repos, values) {
		if viewIncludesRepo(viewConfig, leaf.repo.ID) && viewLeafExists(canonical, viewName, leaf) {
			requested = append(requested, leaf)
		}
	}
	return materializedRoutePhysicalClosureLeaves(cfg, canonical, source, requested)
}

func viewLeafExists(canonical *state.Store, viewName string, leaf viewLeaf) bool {
	ref, err := state.ViewRef(viewName, leaf.repo.ID, leaf.os, leaf.arch)
	if err != nil {
		return false
	}
	_, exists, err := canonical.Ref(ref)
	return err == nil && exists
}

// suiteClosedSelectedLeaves treats an APT architecture selector as a suite
// transaction trigger. InRelease/Release is shared by every configured
// architecture, so publish preflight and verification must both observe every
// sibling ref instead of accepting an incoherent partial --arch projection.
func suiteClosedSelectedLeaves(cfg *config.Config, repos []config.Repo, values commonFlags) []viewLeaf {
	var leaves []viewLeaf
	for _, repo := range repos {
		leafValues := values
		if repo.Type == "apt" {
			if original, exists := cfg.RepoByName(repo.ID); exists {
				repo.Arches = append([]string(nil), original.Arches...)
			}
			leafValues.arches = csvFlag{}
		}
		leaves = append(leaves, selectedLeaves([]config.Repo{repo}, leafValues)...)
	}
	sort.Slice(leaves, func(i, j int) bool {
		left := leaves[i].repo.ID + "\x00" + leaves[i].os + "\x00" + leaves[i].arch
		right := leaves[j].repo.ID + "\x00" + leaves[j].os + "\x00" + leaves[j].arch
		return left < right
	})
	return leaves
}

func mergePublicationManifests(inputs []string, destination, txDir string) error {
	if len(inputs) == 0 {
		file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		return errors.Join(file.Sync(), file.Close())
	}
	current := inputs[0]
	for index := 1; index < len(inputs); index++ {
		next := filepath.Join(txDir, fmt.Sprintf("merge-publication-%06d.tsv", index))
		if err := mergeManifestFiles(current, inputs[index], next); err != nil {
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
