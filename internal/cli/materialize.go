package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
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

func runMaterialize(ctx context.Context, args []string, stdout, stderr io.Writer) (resultErr error) {
	fs := flag.NewFlagSet("materialize", flag.ContinueOnError)
	fs.SetOutput(stderr)
	values := commonFlags{}
	addCommonFlags(fs, &values)
	targetFlag := fs.String("target", "", "export to a dedicated directory (omitted latest: refresh configured serving trees)")
	tgzFlag := fs.String("tgz", "", "write a deterministic offline tgz from the exact materialized manifest")
	assetRepoFlag := fs.String("asset-repo", "", "adopt the generated tgz into this asset repository before returning")
	assetDestFlag := fs.String("asset-dest", "", "asset path for the generated tgz (defaults to its basename; requires --asset-repo)")
	servingBaseURLFlag := fs.String("serving-base-url", "", "absolute serving base URL for an explicit mutable YUM --target export")
	privateKeyFile := fs.String("gpg-private-key-file", "", "read the repository OpenPGP private key from a protected file")
	passphraseFile := fs.String("gpg-passphrase-file", "", "read the OpenPGP passphrase from a protected file")
	nginxIncludeFlag := fs.String("nginx-include", "", "render a deterministic default-deny Nginx location include and exit ('-' writes stdout)")
	nginxAuthUserFileFlag := fs.String("nginx-auth-user-file", "", "absolute htpasswd path outside the repository (required only for stable --nginx-include)")
	edgeContractFlag := fs.String("edge-contract", "", "render a state-admitted secret-free edge deployment contract for one configured target and exit")
	fs.Usage = func() {
		printSubcommandUsage(fs, "sow materialize <view-or-snapshot> [--target DIR [--serving-base-url URL]] [--tgz FILE [--asset-repo NAME] [--asset-dest PATH]] [--gpg-private-key-file FILE] [--gpg-passphrase-file FILE] [--config sow.yaml] [--repo NAME] [--os OS] [--arch ARCH] [--recover]", "Nginx render-only mode: sow materialize <latest|beta|stable> --nginx-include <-|ABS_FILE> [--nginx-auth-user-file ABS_FILE] [--target DIR] [selectors]", "Edge render-only mode: sow materialize latest --edge-contract TARGET [--config sow.yaml]")
	}
	var positional []string
	flagArgs := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		positional = append(positional, args[0])
		flagArgs = args[1:]
	}
	if help, err := parseFlagSet(fs, flagArgs); err != nil || help {
		return err
	}
	positional = append(positional, fs.Args()...)
	if len(positional) != 1 {
		return withExitCode(ExitUsage, "materialize requires exactly one view or snapshot ID")
	}
	if *assetRepoFlag != "" && *tgzFlag == "" {
		return withExitCode(ExitUsage, "--asset-repo requires --tgz")
	}
	if *assetDestFlag != "" && *assetRepoFlag == "" {
		return withExitCode(ExitUsage, "--asset-dest requires --asset-repo")
	}
	if *servingBaseURLFlag != "" && *targetFlag == "" {
		return withExitCode(ExitUsage, "--serving-base-url requires an explicit --target")
	}
	if *nginxAuthUserFileFlag != "" && *nginxIncludeFlag == "" {
		return withExitCode(ExitUsage, "--nginx-auth-user-file requires --nginx-include")
	}
	if *edgeContractFlag != "" && *nginxIncludeFlag != "" {
		return withExitCode(ExitUsage, "--edge-contract and --nginx-include are separate render-only modes")
	}
	refID := positional[0]
	cfg, repos, err := loadAndSelect(values)
	if err != nil {
		return err
	}
	// A committed compatibility event and its serving-link flip are one local
	// transaction. Fence every materialize mode, including render-only Nginx
	// and edge contracts, before it can emit a route derived from half-applied
	// S3 state or mutate any materialization/serving bookkeeping.
	if err := requireNoPendingYUMCompatibilityCutoverJournals(cfg.StatePath()); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	var archiveAssetRepos []config.Repo
	archiveAssetDestination := *assetDestFlag
	archiveAssetLogicalPath := ""
	if *assetRepoFlag != "" {
		assetRepo, exists := cfg.RepoByName(*assetRepoFlag)
		if !exists || assetRepo.Type != "asset" {
			return withExitCode(ExitConfig, "--asset-repo %q is not a configured asset repository", *assetRepoFlag)
		}
		archiveAssetRepos = []config.Repo{assetRepo}
		if archiveAssetDestination == "" {
			archiveAssetDestination = filepath.Base(*tgzFlag)
		}
		logical, err := assetLogicalPath(assetRepo.Path, archiveAssetDestination)
		if err != nil {
			return withExitCode(ExitUsage, "offline archive asset destination: %v", err)
		}
		if err := validateAssetProjectionPath(assetRepo, logical); err != nil {
			return withExitCode(ExitUsage, "offline archive asset destination: %v", err)
		}
		archiveAssetLogicalPath = logical
	}
	viewConfig, isView := cfg.Views[refID]
	if isView && refID == "snapshot" {
		return withExitCode(ExitUsage, "materialize requires a concrete snapshot ID, not the snapshot namespace")
	}
	if !isView {
		if err := views.ValidateSnapshotID(refID); err != nil {
			return withExitCode(ExitConfig, "%v", err)
		}
	}
	targetIsDefault := *targetFlag == ""
	materializeWorkingTree := targetIsDefault && isView && refID == "latest"
	target := *targetFlag
	if target == "" && !materializeWorkingTree {
		target = defaultMaterializationTarget(refID, !isView)
	}
	if !targetIsDefault {
		if err := validateDedicatedTarget(cfg, target); err != nil {
			return withExitCode(ExitUsage, "%v", err)
		}
	}
	targetAbs := cfg.Root
	if !materializeWorkingTree {
		targetAbs = target
		if !filepath.IsAbs(targetAbs) {
			targetAbs = filepath.Join(cfg.Root, filepath.FromSlash(target))
		}
	}
	if *nginxIncludeFlag != "" {
		if !isView {
			return withExitCode(ExitUsage, "--nginx-include supports only latest, beta, or stable, not snapshots")
		}
		if *tgzFlag != "" || *assetRepoFlag != "" || *assetDestFlag != "" || *servingBaseURLFlag != "" ||
			*privateKeyFile != "" || *passphraseFile != "" || values.recover {
			return withExitCode(ExitUsage, "--nginx-include is render-only and cannot be combined with archive, signing, serving-base-url, or recovery options")
		}
		return renderMaterializeNginxInclude(ctx, cfg, repos, refID, targetAbs, *nginxAuthUserFileFlag, *nginxIncludeFlag, values, stdout)
	}
	if *edgeContractFlag != "" {
		if refID != "latest" {
			return withExitCode(ExitUsage, "--edge-contract is target-wide and must be rendered from latest")
		}
		if *targetFlag != "" || *tgzFlag != "" || *assetRepoFlag != "" || *assetDestFlag != "" || *servingBaseURLFlag != "" ||
			*privateKeyFile != "" || *passphraseFile != "" || values.recover || len(values.repos.values()) != 0 || len(values.oses.values()) != 0 || len(values.arches.values()) != 0 {
			return withExitCode(ExitUsage, "--edge-contract is a full-target render-only mode and cannot be combined with export, archive, signing, recovery, or selectors")
		}
		return renderMaterializeEdgeContract(ctx, cfg, *edgeContractFlag, values, stdout)
	}
	archivePath := ""
	if *tgzFlag != "" {
		archivePath = *tgzFlag
		if !filepath.IsAbs(archivePath) {
			archivePath = filepath.Join(cfg.Root, filepath.FromSlash(archivePath))
		}
		if err := validateArchiveDestination(cfg, values.configPath, targetAbs, archivePath); err != nil {
			return withExitCode(ExitUsage, "offline archive destination: %v", err)
		}
	}
	servingBaseURL, err := preflightMutableYUMServing(cfg, repos, refID, *servingBaseURLFlag, !targetIsDefault)
	if err != nil {
		return withExitCode(ExitConfig, "%v", err)
	}
	// Exact local route receipts make every materialization target an Nginx
	// serving root. Reject an existing symlink/private/non-directory ancestor
	// before acquiring the state lock or creating a selected-set journal. The
	// retained-root admission after installation remains the TOCTOU fence.
	if err := preflightMaterializedRouteTargetHostability(targetAbs); err != nil {
		return withExitCode(ExitVerification, "preflight directly hostable materialization target: %v", err)
	}
	lock, err := state.AcquireLock(cfg.StatePath(), "materialize", values.recover)
	if err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	defer propagateStateLockRelease(lock, &resultErr, stderr)
	if err := requireNoForeignMaterializationIntent(cfg, "materialize", values.recover); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}

	canonical := state.New(cfg.StatePath())
	if err := requireProjectionTransactionsCompatibleBeforeRecovery(cfg, canonical, "materialize"); err != nil {
		return withExitCode(ExitConflict, "materialize projection transaction preflight: %v", err)
	}
	if err := preflightPendingAssetProjection(cfg, canonical, "materialize"); err != nil {
		return withExitCode(ExitConflict, "materialize projection content preflight: %v", err)
	}
	if err := prepareCanonicalStateCore(ctx, canonical, values.recover, stdout); err != nil {
		return err
	}
	if err := requireCanonicalConfigBaseline(cfg, canonical); err != nil {
		return withExitCode(ExitConflict, "canonical config changed while materialize was waiting for the state lock: %v", err)
	}
	if _, err := recoverPendingAssetProjectionLocked(ctx, cfg, canonical, values, "materialize", stdout); err != nil {
		return withExitCode(ExitVerification, "recover pending offline archive asset projection: %v", err)
	}
	archiveRecovered, err := recoverPendingOfflineArchiveProjection(ctx, cfg, canonical, values, stdout)
	if err != nil {
		return withExitCode(ExitVerification, "recover pending offline archive projection: %v", err)
	}
	if values.recover {
		if err := cleanupAbandonedMaterializeScratch(cfg.StatePath()); err != nil {
			return withExitCode(ExitConflict, "clean abandoned private materialize scratch: %v", err)
		}
	}
	if archiveRecovered {
		return nil
	}
	configHead, err := canonical.HeadHash()
	if err != nil || configHead.IsZero() {
		return withExitCode(ExitConflict, "materialize has no canonical config commit: %v", err)
	}
	configSHA, err := cfg.CanonicalSHA256()
	if err != nil {
		return withExitCode(ExitConfig, "derive materialize config identity: %v", err)
	}
	if _, err := loadMaterializedRouteConfigAnchor(canonical, configHead, configHead.String(), configSHA); err != nil {
		return withExitCode(ExitConflict, "materialize requires the active config to be committed by sow init before changing any target: %v", err)
	}
	routeCleanupScope := materializedRouteCleanupPreserve
	if !targetIsDefault {
		routeCleanupScope = materializedRouteCleanupTargetWide
	} else if isView && localServingSelectionIsFull(values) {
		routeCleanupScope = materializedRouteCleanupSameView
	}
	if routeCleanupScope != materializedRouteCleanupPreserve {
		preflightDir, err := newTransactionDir(cfg.StatePath(), "materialize-route-preflight-")
		if err != nil {
			return withExitCode(ExitInternal, "create route receipt cleanup preflight: %v", err)
		}
		defer os.RemoveAll(preflightDir)
		if err := preflightMaterializedRouteCleanup(canonical, targetAbs, refID, preflightDir, routeCleanupScope); err != nil {
			return withExitCode(ExitConflict, "preflight exact local Nginx route receipt cleanup: %v", err)
		}
	}
	// Offline archive adoption is a second, domain-separated selected-set
	// transaction because its asset ref does not exist until after the primary
	// materialization and archive commit. Recover that frozen unit before current
	// selectors are allowed to plan or mutate a new target.
	if _, err := recoverOfflineArchiveAdoptionMaterialization(ctx, cfg, canonical, values, stdout); err != nil {
		return err
	}
	if !targetIsDefault {
		if _, err := serving.CleanupTransactionTemps(cfg.Root, targetAbs); err != nil {
			return withExitCode(ExitConflict, "clean interrupted local serving temporary files below explicit target: %v", err)
		}
	}
	if err := prepareLocalServingState(ctx, cfg, canonical, values.recover, values, stdout); err != nil {
		return err
	}
	if err := prepareLocalServingTopologyRemovals(ctx, cfg, canonical, values.recover); err != nil {
		return withExitCode(ExitConflict, "recover local YUM serving topology: %v", err)
	}
	txDir, err := newTransactionDir(cfg.StatePath(), "materialize-")
	if err != nil {
		return withExitCode(ExitInternal, "create materialize transaction: %v", err)
	}
	defer os.RemoveAll(txDir)
	if materializeWorkingTree {
		pool, err := repository.NewStore(cfg.Root)
		if err != nil {
			return withExitCode(ExitConflict, "open CAS: %v", err)
		}
		privateKey, passphrase, repositoryKeySHA, err := loadPublishSigningSecretsWithIdentity(cfg, repos, *privateKeyFile, *passphraseFile)
		if err != nil {
			return withExitCode(ExitConfig, "%v", err)
		}
		defer clearSecret(privateKey)
		defer clearSecret(passphrase)
		var requestedLeaves []viewLeaf
		for _, leaf := range selectedLeaves(repos, values) {
			if viewIncludesRepo(viewConfig, leaf.repo.ID) && viewLeafExists(canonical, refID, leaf) {
				requestedLeaves = append(requestedLeaves, leaf)
			}
		}
		workingSource := materializeCanonicalSource{ID: refID, Public: viewConfig.Access == "public"}
		var archiveSourceProof offlineArchiveSourceProof
		var archiveAdoptionPreflight *offlineArchiveAdoptionPreflight
		var archiveMarker string
		if archivePath != "" {
			archiveSourceProof, err = deriveOfflineArchiveSourceProof(cfg, canonical, workingSource, requestedLeaves, archiveAssetLogicalPath)
			if err != nil {
				return withExitCode(ExitVerification, "derive exact latest archive source proof: %v", err)
			}
			archiveMarker, err = offlineArchiveMarkerForSource(archiveSourceProof)
			if err != nil {
				return withExitCode(ExitVerification, "derive exact latest archive marker: %v", err)
			}
			if len(archiveAssetRepos) != 0 {
				preflight, preflightErr := prepareOfflineArchiveAdoptionFromProof(cfg, archiveSourceProof, archiveAssetRepos[0], archiveAssetDestination)
				err = preflightErr
				if err != nil {
					return withExitCode(ExitVerification, "preflight offline archive confidentiality: %v", err)
				}
				archiveAdoptionPreflight = &preflight
			}
		}
		transactionLeaves, err := materializedRoutePhysicalClosureLeaves(cfg, canonical, materializeCanonicalSource{ID: refID, Public: viewConfig.Access == "public"}, requestedLeaves)
		if err != nil {
			return withExitCode(ExitConflict, "close working-tree selectors to physical route owners: %v", err)
		}
		physicalRepos, err := materializedRoutePhysicalRepos(cfg, transactionLeaves)
		if err != nil {
			return withExitCode(ExitConfig, "%v", err)
		}
		values.materializeTrust, err = captureMaterializationTrust(cfg, transactionLeaves, privateKey, repositoryKeySHA)
		if err != nil {
			return withExitCode(ExitConfig, "capture materialization trust: %v", err)
		}
		values.materializeOperation = "materialize"
		values, selectionOwner, err := beginMaterializationSelectionForSource(cfg, canonical, values, "materialize",
			materializeCanonicalSource{ID: refID, Public: viewConfig.Access == "public"}, transactionLeaves, cfg.Root, true, true, true)
		if err != nil {
			return withExitCode(ExitConflict, "begin working-tree selected-set materialization: %v", err)
		}
		defer func() {
			resultErr = errors.Join(resultErr, finishMaterializationSelectedSet(cfg, values.materializeTrust, selectionOwner, resultErr))
		}()
		physicalValues := values
		physicalValues.oses = csvFlag{}
		physicalValues.arches = csvFlag{}
		prepared, err := preparePublicationViewWithVerb(ctx, cfg, canonical, pool, physicalRepos, refID, txDir, physicalValues, privateKey, passphrase, "materialize", stdout)
		if err != nil {
			return err
		}
		workingRepos, err := preparedWorkingTreeRepos(prepared)
		if err != nil {
			return withExitCode(ExitInternal, "resolve latest working repositories: %v", err)
		}
		if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustServingActivateBefore); err != nil {
			return withExitCode(ExitConflict, "%v", err)
		}
		commit, changed, err := refreshWorkingTreeBaselines(ctx, cfg, canonical, workingRepos, txDir, values, "materialize-working-tree", state.ApplyOptions{}, stdout)
		if err != nil {
			return stateMutationError("commit latest working tree", err)
		}
		servingLeaves := localServingLeavesFromPrepared(prepared)
		if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustServingActivateBefore); err != nil {
			return withExitCode(ExitConflict, "%v", err)
		}
		servingResult, err := activateLocalYUMServing(ctx, cfg, canonical, pool,
			materializeCanonicalSource{ID: refID, Public: viewConfig.Access == "public"}, cfg.Root, servingBaseURL, repositoryKeySHA, txDir,
			servingLeaves, values, localServingActivationOptions{}, stdout)
		if err != nil {
			return withExitCode(ExitVerification, "activate local YUM serving routes: %v", err)
		}
		compatibilityPrepared, err := activeLocalYUMCompatibilityPrepared(cfg, canonical, prepared)
		if err != nil {
			return withExitCode(ExitVerification, "resolve active local YUM compatibility routes: %v", err)
		}
		compatibilityServing, err := activateLocalYUMCompatibilityServing(ctx, cfg, canonical, pool, cfg.Root, servingBaseURL, txDir, compatibilityPrepared, values, stdout)
		if err != nil {
			return withExitCode(ExitVerification, "activate local YUM compatibility routes: %v", err)
		}
		servingLeaves = append(servingLeaves, localYUMCompatibilityTopologyLeaves(compatibilityPrepared)...)
		if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustServingActivateAfter); err != nil {
			return withExitCode(ExitConflict, "%v", err)
		}
		var servingTarget *serving.TargetIdentity
		if len(servingLeaves) != 0 {
			identity, err := localServingTargetIdentity(cfg, refID, cfg.Root, servingBaseURL)
			if err != nil {
				return withExitCode(ExitVerification, "resolve local YUM serving target: %v", err)
			}
			servingTarget = &identity
		}
		topology, err := reconcileLocalServingTopology(ctx, cfg, canonical, cfg.Root, refID, servingTarget, servingLeaves, localServingSelectionIsFull(values), false)
		if err != nil {
			return withExitCode(ExitVerification, "reconcile local YUM serving topology: %v", err)
		}
		if !localServingSelectionIsFull(values) {
			topology.LedgersExpired, err = pruneLocalServingLifecycle(ctx, cfg, canonical)
			if err != nil {
				return withExitCode(ExitVerification, "apply local YUM serving retention: %v", err)
			}
		}
		routeCommit, routeChanged, routeCount, err := persistPreparedMaterializedRoutes(
			ctx, cfg, canonical, pool, refID, cfg.Root, servingBaseURL, transactionLeaves, prepared, txDir, values,
		)
		if err != nil {
			return withExitCode(ExitVerification, "persist exact local Nginx route receipts: %v", err)
		}
		workingArchiveRoot := cfg.Root
		workingArchiveManifest := prepared.manifestPath
		if archivePath != "" {
			archiveTree, archiveErr := buildSelectedWorkingArchive(
				ctx, cfg, canonical, pool,
				materializeCanonicalSource{ID: refID, Public: viewConfig.Access == "public"}, requestedLeaves,
				compatibilityPrepared, servingBaseURL, repositoryKeySHA, txDir, privateKey, passphrase, values,
			)
			err = archiveErr
			if err != nil {
				return withExitCode(ExitVerification, "build exact latest archive manifest: %v", err)
			}
			workingArchiveRoot = archiveTree.Root
			workingArchiveManifest = archiveTree.Manifest
			if len(archiveAssetRepos) != 0 {
				excluded := path.Join(strings.TrimSuffix(archiveAssetRepos[0].Path, "/"), archiveAssetDestination)
				filtered := filepath.Join(txDir, "latest-archive-without-self.tsv")
				if err := excludeManifestPath(workingArchiveManifest, filtered, excluded); err != nil {
					return withExitCode(ExitVerification, "exclude adopted archive from latest input: %v", err)
				}
				workingArchiveManifest = filtered
			}
		}
		selectionErr := finishMaterializationSelectedSet(cfg, values.materializeTrust, selectionOwner, nil)
		selectionOwner = false
		if selectionErr != nil {
			return withExitCode(ExitConflict, "%v", selectionErr)
		}
		pruned, err := pruneExpiredSnapshotMaterializations(cfg.Root, "", cfg.State.SnapshotMaterializationMonths, timeNowUTC())
		if err != nil {
			return withExitCode(ExitVerification, "apply snapshot materialization retention: %v", err)
		}
		fmt.Fprintf(stdout, "materialized ref=%s target=working-tree repos=%d commit=%s changed=%t route_receipt_commit=%s route_receipt_changed=%t route_receipts=%d serving_generations=%d serving_created=%d serving_pointers=%d compatibility_generations=%d compatibility_created=%d compatibility_pointers=%d compatibility_trust_files=%d serving_channels_removed=%d serving_generation_ledgers_expired=%d pruned_snapshots=%d\n", refID, len(workingRepos), commit, changed, routeCommit, routeChanged, routeCount, servingResult.Generations, servingResult.Created, servingResult.Pointers, compatibilityServing.Generations, compatibilityServing.Created, compatibilityServing.Pointers, compatibilityServing.TrustFiles, topology.ChannelsRemoved, topology.LedgersExpired, len(pruned))
		if archivePath != "" {
			if err := validateArchiveDestination(cfg, values.configPath, cfg.Root, archivePath); err != nil {
				return withExitCode(ExitUsage, "offline archive destination changed before write: %v", err)
			}
			archive, archiveIntent, err := writeMaterializedOfflineArchive(ctx, cfg, canonical, archiveSourceProof,
				workingArchiveRoot, workingArchiveManifest, archivePath, cfg.Root, true, txDir, archiveMarker, archiveAdoptionPreflight)
			if err != nil {
				return withExitCode(ExitVerification, "build offline tgz: %v", err)
			}
			fmt.Fprintf(stdout, "archive path=%s entries=%d bytes=%d size=%d sha256=%s\n", archive.Path, archive.Entries, archive.Bytes, archive.Size, archive.SHA256)
			if archiveIntent.ArchiveAdoption != nil {
				if offlineArchiveAfterProjectionBeforeAdoptionHook != nil {
					if err := offlineArchiveAfterProjectionBeforeAdoptionHook(archiveIntent); err != nil {
						return withExitCode(ExitConflict, "offline archive adoption fault: %v", err)
					}
				}
				if err := completeOfflineArchiveProjectionAdoption(ctx, cfg, canonical, archiveIntent, values, stdout); err != nil {
					return err
				}
			}
		}
		return nil
	}
	source := materializeCanonicalSource{ID: refID, Snapshot: !isView, Public: isView && viewConfig.Access == "public"}
	var inputs []views.ProjectionInput
	var matchedLeaves []viewLeaf
	var readers []io.ReadCloser
	closeReaders := func() error {
		var closeErr error
		for _, reader := range readers {
			closeErr = errors.Join(closeErr, reader.Close())
		}
		readers = nil
		return closeErr
	}
	defer closeReaders()
	var selectedMaterializationLeaves []viewLeaf
	if isView {
		// APT Release/InRelease is a suite-wide pointer. An architecture
		// selector therefore triggers the selected suite, but cannot narrow the
		// materialized repository to an incoherent architecture fragment.
		selectedMaterializationLeaves = suiteClosedSelectedLeaves(cfg, repos, values)
	} else {
		selectedMaterializationLeaves, err = selectedSnapshotPublicationLeaves(canonical, cfg, repos, refID, values)
		if err != nil {
			return withExitCode(ExitVerification, "expand snapshot materialization selectors: %v", err)
		}
	}
	for _, leaf := range selectedMaterializationLeaves {
		if isView && !viewIncludesRepo(viewConfig, leaf.repo.ID) {
			continue
		}
		var refPath string
		var refName plumbing.ReferenceName
		if isView {
			name, buildErr := state.ViewRef(refID, leaf.repo.ID, leaf.os, leaf.arch)
			if buildErr != nil {
				return withExitCode(ExitInternal, "%v", buildErr)
			}
			refName = name
			refPath, err = state.ViewPath(refID, leaf.repo.ID, leaf.os, leaf.arch)
		} else {
			name, buildErr := state.SnapshotRef(refID, leaf.repo.ID, leaf.os, leaf.arch)
			if buildErr != nil {
				return withExitCode(ExitInternal, "%v", buildErr)
			}
			refName = name
			refPath, err = state.SnapshotPath(refID, leaf.repo.ID, leaf.os, leaf.arch)
		}
		if err != nil {
			return withExitCode(ExitInternal, "%v", err)
		}
		nameString := refName.String()
		commit, hashExists, hashErr := canonical.Ref(refName)
		if hashErr != nil {
			return withExitCode(ExitInternal, "read %s: %v", nameString, hashErr)
		}
		if !hashExists {
			continue
		}
		public := isView && viewConfig.Access == "public"
		if err := validateViewAt(canonical, commit, refPath, leaf, public); err != nil {
			return withExitCode(ExitVerification, "validate %s: %v", nameString, err)
		}
		reader, err := canonical.OpenPathAt(commit, refPath)
		if err != nil {
			return withExitCode(ExitInternal, "%v", err)
		}
		readers = append(readers, reader)
		inputs = append(inputs, views.ProjectionInput{Label: nameString, Reader: reader})
		matchedLeaves = append(matchedLeaves, leaf)
	}
	if len(inputs) == 0 {
		return withExitCode(ExitConfig, "selectors matched no %s refs", refID)
	}
	var archiveSourceProof offlineArchiveSourceProof
	var archiveAdoptionPreflight *offlineArchiveAdoptionPreflight
	var archiveMarker string
	if archivePath != "" {
		archiveSourceProof, err = deriveOfflineArchiveSourceProof(cfg, canonical, source, matchedLeaves, archiveAssetLogicalPath)
		if err != nil {
			return withExitCode(ExitVerification, "derive exact %s archive source proof: %v", refID, err)
		}
		archiveMarker, err = offlineArchiveMarkerForSource(archiveSourceProof)
		if err != nil {
			return withExitCode(ExitVerification, "derive exact %s archive marker: %v", refID, err)
		}
		if len(archiveAssetRepos) != 0 {
			preflight, preflightErr := prepareOfflineArchiveAdoptionFromProof(cfg, archiveSourceProof, archiveAssetRepos[0], archiveAssetDestination)
			err = preflightErr
			if err != nil {
				return withExitCode(ExitVerification, "preflight offline archive confidentiality: %v", err)
			}
			archiveAdoptionPreflight = &preflight
		}
	}
	desiredPath := filepath.Join(txDir, "desired.tsv")
	desired, err := os.OpenFile(desiredPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return withExitCode(ExitInternal, "create projected manifest: %v", err)
	}
	entryCount, byteCount, projectErr := views.ProjectManifest(inputs, desired)
	closeErr := errors.Join(desired.Sync(), desired.Close(), closeReaders())
	if projectErr != nil || closeErr != nil {
		return withExitCode(ExitVerification, "project %s: %v", refID, errors.Join(projectErr, closeErr))
	}
	requestedMatchedLeaves := append([]viewLeaf(nil), matchedLeaves...)
	requestedDesiredPath := desiredPath
	physicalLeaves, err := materializedRoutePhysicalClosureLeaves(cfg, canonical, source, matchedLeaves)
	if err != nil {
		return withExitCode(ExitConflict, "close selectors to physical route owners: %v", err)
	}
	if !sameViewLeafSet(physicalLeaves, matchedLeaves) {
		physicalDesiredPath := filepath.Join(txDir, "desired-physical.tsv")
		entryCount, byteCount, err = projectCanonicalMaterializationLeaves(canonical, source, physicalLeaves, physicalDesiredPath)
		if err != nil {
			return withExitCode(ExitVerification, "project complete physical route owners for %s: %v", refID, err)
		}
		desiredPath = physicalDesiredPath
		matchedLeaves = physicalLeaves
	}
	privateKey, passphrase, repositoryKeySHA, err := loadMaterializeSigningSecretsWithIdentity(cfg, matchedLeaves, *privateKeyFile, *passphraseFile)
	if err != nil {
		return withExitCode(ExitConfig, "%v", err)
	}
	defer clearSecret(privateKey)
	defer clearSecret(passphrase)
	values.materializeTrust, err = captureMaterializationTrust(cfg, matchedLeaves, privateKey, repositoryKeySHA)
	if err != nil {
		return withExitCode(ExitConfig, "capture materialization trust: %v", err)
	}
	values.materializeOperation = "materialize"
	values, selectionOwner, err := beginMaterializationSelectionForSource(cfg, canonical, values, "materialize", source, matchedLeaves, targetAbs, true, isView)
	if err != nil {
		return withExitCode(ExitConflict, "begin selected-set materialization: %v", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, finishMaterializationSelectedSet(cfg, values.materializeTrust, selectionOwner, resultErr))
	}()
	pool, err := repository.NewStore(cfg.Root)
	if err != nil {
		return withExitCode(ExitConflict, "open CAS: %v", err)
	}
	desiredReader, err := os.Open(desiredPath)
	if err != nil {
		return withExitCode(ExitInternal, "%v", err)
	}
	if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustPayloadBefore); err != nil {
		desiredReader.Close()
		return withExitCode(ExitConflict, "%v", err)
	}
	materialized, materializeErr := pool.MaterializeWithOptions(ctx, desiredReader, target, repository.MaterializeOptions{
		Workers: values.workers, AllowReplacePath: directMaterializationMutableAssetPath(matchedLeaves),
	})
	closeErr = desiredReader.Close()
	if materializeErr != nil || closeErr != nil {
		return withExitCode(ExitConflict, "materialize %s: %v", refID, errors.Join(materializeErr, closeErr))
	}
	if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustPayloadAfter); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	// Generate and atomically flip metadata before pruning old payloads. The
	// prior signed APT/YUM generation therefore remains consumable throughout
	// preparation, and a metadata failure leaves its complete old payload
	// closure in place instead of exposing an empty dists/repodata window.
	metadata, err := materializeRepositoryMetadata(ctx, cfg, canonical, matchedLeaves, source, targetAbs, txDir, privateKey, passphrase, values)
	if err != nil {
		return withExitCode(ExitVerification, "build repository metadata for %s: %v", refID, err)
	}
	selectedExactPath, err := materializedRepositoryExactManifest(desiredPath, metadata.ExactManifests, txDir)
	if err != nil {
		return withExitCode(ExitVerification, "build exact selected materialization manifest for %s: %v", refID, err)
	}
	requestedExactPath := selectedExactPath
	if archivePath != "" && !sameViewLeafSet(requestedMatchedLeaves, matchedLeaves) {
		requestedExactPath, err = selectedMaterializationArchiveExact(cfg, source, requestedMatchedLeaves, requestedDesiredPath, metadata.ExactManifests, txDir)
		if err != nil {
			return withExitCode(ExitVerification, "build requested archive selector manifest for %s: %v", refID, err)
		}
	}
	var servingLeaves []localYUMServingLeaf
	var compatibilityServingLeaves []localYUMServingLeaf
	var compatibilityPrepared preparedPublication
	if isView {
		servingLeaves = localServingLeavesFromViewLeaves(matchedLeaves)
		prepared := preparedPublication{view: refID}
		for _, leaf := range matchedLeaves {
			prepared.projections = append(prepared.projections, publicationProjection{view: refID, repo: leaf.repo, os: leaf.os, arch: leaf.arch})
		}
		compatibilityPrepared, err = activeLocalYUMCompatibilityPrepared(cfg, canonical, prepared)
		if err != nil {
			return withExitCode(ExitVerification, "resolve active local YUM compatibility routes: %v", err)
		}
		compatibilityServingLeaves = localYUMCompatibilityTopologyLeaves(compatibilityPrepared)
	}
	reconcilePath := selectedExactPath
	if targetIsDefault && !localServingSelectionIsFull(values) {
		// A selector owns only its exact subtree. Scan after the upsert so old
		// selected entries can be removed while unselected repositories/suites,
		// shared APT pool objects and retained _sow generations survive. This is
		// also what makes repeated partial writes into the fixed snapshot root
		// cumulative instead of destructive.
		currentPath := filepath.Join(txDir, "materialized-current.tsv")
		if _, err := manifest.Scan(ctx, targetAbs, manifest.Scope{Path: "."}, currentPath, manifest.ScanOptions{
			Workers: values.workers, ChunkEntries: values.chunk, TempDir: filepath.Join(cfg.StatePath(), "tmp"),
		}); err != nil {
			return withExitCode(ExitVerification, "scan current partial materialization target: %v", err)
		}
		selection, err := directPhysicalOwnerMaterializationSelection(cfg, matchedLeaves, source)
		if err != nil {
			return withExitCode(ExitConfig, "resolve materialization selector ownership: %v", err)
		}
		reconcilePath = filepath.Join(txDir, "materialized-cumulative.tsv")
		if err := ReplaceManifestSelection(currentPath, selectedExactPath, reconcilePath, selection); err != nil {
			return withExitCode(ExitVerification, "merge materialization selector ownership: %v", err)
		}
	} else if targetIsDefault && isView {
		// Mutable view roots retain strong-serving generations already handed
		// to delayed clients. The fixed product roots are cumulative and retain
		// the complete existing canonical namespace until topology retention
		// removes an expired generation.
		reconcilePath, err = preserveLocalServingRoutes(ctx, cfg, targetAbs, selectedExactPath, txDir, values)
		if err != nil {
			return withExitCode(ExitVerification, "preserve delayed-client serving generations: %v", err)
		}
	} else if isView {
		// An explicit target is an exact export. Preserve only route bytes
		// positively owned by canonical lifecycle records for this exact
		// target/view/leaf set; arbitrary or foreign _sow content is pruned.
		preservedServingLeaves := append([]localYUMServingLeaf(nil), servingLeaves...)
		preservedServingLeaves = append(preservedServingLeaves, compatibilityServingLeaves...)
		reconcilePath, err = preserveCanonicalLocalServingRoutes(
			ctx, cfg, canonical, pool, targetAbs, refID, selectedExactPath, txDir, preservedServingLeaves, compatibilityPrepared, values,
		)
		if err != nil {
			return withExitCode(ExitVerification, "preserve exact canonical serving generations: %v", err)
		}
	}
	if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustExactReconcileBefore); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	reconciled, err := pool.ReconcileExact(ctx, reconcilePath, target, values.workers, values.chunk)
	if err != nil {
		return withExitCode(ExitVerification, "reconcile materialized %s: %v", refID, err)
	}
	if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustExactReconcileAfter); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	var servingResult localServingActivationResult
	var compatibilityServing localYUMCompatibilityServingResult
	var topology localServingTopologyResult
	selectedArchivePath := requestedExactPath
	if isView {
		if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustServingActivateBefore); err != nil {
			return withExitCode(ExitConflict, "%v", err)
		}
		servingResult, err = activateLocalYUMServing(ctx, cfg, canonical, pool, source, targetAbs, servingBaseURL, repositoryKeySHA, txDir,
			servingLeaves, values, localServingActivationOptions{}, stdout)
		if err != nil {
			return withExitCode(ExitVerification, "activate local YUM serving routes: %v", err)
		}
		compatibilityServing, err = activateLocalYUMCompatibilityServing(ctx, cfg, canonical, pool, targetAbs, servingBaseURL, txDir, compatibilityPrepared, values, stdout)
		if err != nil {
			return withExitCode(ExitVerification, "activate local YUM compatibility routes: %v", err)
		}
		servingLeaves = append(servingLeaves, compatibilityServingLeaves...)
		if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustServingActivateAfter); err != nil {
			return withExitCode(ExitConflict, "%v", err)
		}
		var servingTarget *serving.TargetIdentity
		if len(servingLeaves) != 0 {
			identity, err := localServingTargetIdentity(cfg, refID, targetAbs, servingBaseURL)
			if err != nil {
				return withExitCode(ExitVerification, "resolve local YUM serving target: %v", err)
			}
			servingTarget = &identity
		}
		topology, err = reconcileLocalServingTopology(ctx, cfg, canonical, targetAbs, refID, servingTarget, servingLeaves, localServingSelectionIsFull(values), !targetIsDefault)
		if err != nil {
			return withExitCode(ExitVerification, "reconcile local YUM serving topology: %v", err)
		}
		if !localServingSelectionIsFull(values) {
			topology.LedgersExpired, err = pruneLocalServingLifecycle(ctx, cfg, canonical)
			if err != nil {
				return withExitCode(ExitVerification, "apply local YUM serving retention: %v", err)
			}
		}
		if archivePath != "" && len(servingLeaves) != 0 {
			archiveServingLeaves := localServingLeavesFromViewLeaves(requestedMatchedLeaves)
			for _, leaf := range servingLeaves {
				if _, ordinary := cfg.RepoByName(leaf.repo.ID); !ordinary {
					archiveServingLeaves = append(archiveServingLeaves, leaf)
				}
			}
			selectedArchivePath, err = selectedLocalServingArchiveManifest(ctx, cfg, canonical, targetAbs, refID, servingBaseURL, archiveServingLeaves, requestedExactPath, txDir, values)
			if err != nil {
				return withExitCode(ExitVerification, "build exact selected serving archive manifest: %v", err)
			}
		}
	}
	if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustServingPublishBefore); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	if err := serving.PublishHostableTree(targetAbs); err != nil {
		return withExitCode(ExitVerification, "publish directly hostable materialized tree: %v", err)
	}
	if err := requireAllMaterializationTrust(values, cfg, privateKey, materializeTrustServingPublishAfter); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	if err := completeMaterializedAssetUnits(values, cfg, matchedLeaves, source, targetAbs); err != nil {
		return withExitCode(ExitConflict, "complete asset materialization units: %v", err)
	}
	if _, err := serving.CleanupTransactionTemps(cfg.Root, targetAbs); err != nil {
		return withExitCode(ExitVerification, "clean local serving temporary files before exact scan: %v", err)
	}
	routeCommit, routeChanged, routeCount, err := persistDirectMaterializedRoutes(
		ctx, cfg, canonical, pool, source, targetAbs, servingBaseURL, matchedLeaves, selectedExactPath, txDir, values,
		routeCleanupScope,
	)
	if err != nil {
		return withExitCode(ExitVerification, "persist exact local Nginx route receipts: %v", err)
	}
	selectionErr := finishMaterializationSelectedSet(cfg, values.materializeTrust, selectionOwner, nil)
	selectionOwner = false
	if selectionErr != nil {
		return withExitCode(ExitConflict, "%v", selectionErr)
	}
	exactPath := filepath.Join(txDir, "materialized-exact.tsv")
	exact, err := manifest.Scan(ctx, targetAbs, manifest.Scope{Path: "."}, exactPath, manifest.ScanOptions{
		Workers: values.workers, ChunkEntries: values.chunk, TempDir: filepath.Join(cfg.StatePath(), "tmp"),
	})
	if err != nil {
		return withExitCode(ExitVerification, "scan complete materialized repository %s: %v", refID, err)
	}
	prunedSnapshots := 0
	if targetIsDefault {
		keep := ""
		if !isView {
			keep = refID
		}
		pruned, err := pruneExpiredSnapshotMaterializations(cfg.Root, keep, cfg.State.SnapshotMaterializationMonths, timeNowUTC())
		if err != nil {
			return withExitCode(ExitVerification, "apply snapshot materialization retention: %v", err)
		}
		prunedSnapshots = len(pruned)
	}
	fmt.Fprintf(stdout, "materialized ref=%s target=%s entries=%d bytes=%d files=%d repository_bytes=%d linked=%d existing=%d relinked=%d pruned=%d apt_suites=%d yum_repos=%d route_receipt_commit=%s route_receipt_changed=%t route_receipts=%d pruned_snapshots=%d\n",
		refID, target, entryCount, byteCount, exact.Files, exact.Bytes, materialized.Linked, materialized.Existing, materialized.Relinked, reconciled.RemovedFiles, metadata.APTSuites, metadata.YUMRepos, routeCommit, routeChanged, routeCount, prunedSnapshots)
	if servingResult.Generations != 0 || topology.ChannelsRemoved != 0 || topology.PointersRemoved != 0 || topology.LedgersExpired != 0 {
		fmt.Fprintf(stdout, "materialized serving_generations=%d serving_created=%d serving_pointers=%d serving_channels_removed=%d serving_generation_ledgers_expired=%d\n", servingResult.Generations, servingResult.Created, servingResult.Pointers, topology.ChannelsRemoved, topology.LedgersExpired)
	}
	if compatibilityServing.Generations != 0 || compatibilityServing.Created != 0 || compatibilityServing.Pointers != 0 || compatibilityServing.TrustFiles != 0 {
		fmt.Fprintf(stdout, "materialized compatibility_generations=%d compatibility_created=%d compatibility_pointers=%d compatibility_trust_files=%d\n", compatibilityServing.Generations, compatibilityServing.Created, compatibilityServing.Pointers, compatibilityServing.TrustFiles)
	}
	if archivePath != "" {
		if err := validateArchiveDestination(cfg, values.configPath, targetAbs, archivePath); err != nil {
			return withExitCode(ExitUsage, "offline archive destination changed before write: %v", err)
		}
		archiveManifest := exactPath
		if !localServingSelectionIsFull(values) {
			archiveManifest = selectedArchivePath
		}
		if len(archiveAssetRepos) != 0 {
			excluded := path.Join(strings.TrimSuffix(archiveAssetRepos[0].Path, "/"), archiveAssetDestination)
			filtered := filepath.Join(txDir, "archive-without-self.tsv")
			if err := excludeManifestPath(archiveManifest, filtered, excluded); err != nil {
				return withExitCode(ExitVerification, "exclude adopted archive from its own input: %v", err)
			}
			archiveManifest = filtered
		}
		archive, archiveIntent, err := writeMaterializedOfflineArchive(ctx, cfg, canonical, archiveSourceProof,
			targetAbs, archiveManifest, archivePath, targetAbs, false, txDir, archiveMarker, archiveAdoptionPreflight)
		if err != nil {
			return withExitCode(ExitVerification, "build offline tgz: %v", err)
		}
		fmt.Fprintf(stdout, "archive path=%s entries=%d bytes=%d size=%d sha256=%s\n", archive.Path, archive.Entries, archive.Bytes, archive.Size, archive.SHA256)
		if archiveIntent.ArchiveAdoption != nil {
			if offlineArchiveAfterProjectionBeforeAdoptionHook != nil {
				if err := offlineArchiveAfterProjectionBeforeAdoptionHook(archiveIntent); err != nil {
					return withExitCode(ExitConflict, "offline archive adoption fault: %v", err)
				}
			}
			if err := completeOfflineArchiveProjectionAdoption(ctx, cfg, canonical, archiveIntent, values, stdout); err != nil {
				return err
			}
		}
	}
	return nil
}

// cleanupAbandonedMaterializeScratch runs only while the caller holds the
// exclusive state lock and explicitly requested recovery. Materialize scratch
// directories are never referenced by durable canonical or selected-set
// journals; recovery reconstructs them from frozen Git/CAS state. Removing
// exact-prefix leftovers therefore closes the SIGKILL case without exposing or
// trusting the private pre-receipt archive bytes they may contain.
func cleanupAbandonedMaterializeScratch(statePath string) error {
	parent := filepath.Join(statePath, "transactions")
	entries, err := os.ReadDir(parent)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "materialize-") {
			continue
		}
		name := filepath.Join(parent, entry.Name())
		info, err := os.Lstat(name)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("abandoned materialize scratch %s is not a directory", entry.Name())
		}
		if err := os.RemoveAll(name); err != nil {
			return err
		}
	}
	directory, err := os.Open(parent)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func materializedRepositoryExactManifest(payloadPath string, metadataPaths []string, txDir string) (string, error) {
	manifestDir := filepath.Join(txDir, "direct-materialization-exact")
	if err := os.Mkdir(manifestDir, 0o700); err != nil {
		return "", err
	}
	inputs := make([]string, 0, 1+len(metadataPaths))
	inputs = append(inputs, payloadPath)
	inputs = append(inputs, metadataPaths...)
	destination := filepath.Join(manifestDir, "selected-exact.tsv")
	if err := mergePublicationManifests(inputs, destination, manifestDir); err != nil {
		return "", err
	}
	return destination, nil
}

func selectedLocalServingArchiveManifest(ctx context.Context, cfg *config.Config, canonical *state.Store, targetRoot, view, baseURL string, leaves []localYUMServingLeaf, baseManifest, txDir string, values commonFlags) (string, error) {
	targetIdentity, err := localServingTargetIdentity(cfg, view, targetRoot, baseURL)
	if err != nil {
		return "", err
	}
	type scanScope struct {
		path    string
		include []string
	}
	byKey := make(map[string]scanScope)
	for _, leaf := range leaves {
		channelPath := serving.ChannelStatePath(serving.Channel{TargetID: targetIdentity.ID, View: view, Repo: leaf.repo.ID, OS: leaf.os, Arch: leaf.arch})
		body, exists, err := readOptionalCanonical(canonical, channelPath)
		if err != nil || !exists {
			return "", errors.Join(err, fmt.Errorf("local serving channel %s is missing", channelPath))
		}
		channel, err := serving.DecodeChannel(body)
		if err != nil {
			return "", fmt.Errorf("decode local serving channel %s: %w", channelPath, err)
		}
		if channel.TargetID != targetIdentity.ID || channel.View != view || channel.Repo != leaf.repo.ID || channel.OS != leaf.os || channel.Arch != leaf.arch {
			return "", fmt.Errorf("local serving channel %s differs from selected archive coordinates", channelPath)
		}
		pointerDir, pointerName := path.Split(channel.MirrorlistPath)
		pointerDir = strings.TrimSuffix(pointerDir, "/")
		if pointerDir == "" || pointerName == "" {
			return "", fmt.Errorf("local serving channel %s has an unsafe mirrorlist path", channelPath)
		}
		pointer := scanScope{path: pointerDir, include: []string{pointerName}}
		byKey[pointer.path+"\x00"+pointerName] = pointer
		generationRoot := path.Join("_sow/v1/g", channel.Generation, channel.LegacyRoot)
		byKey[generationRoot+"\x00"] = scanScope{path: generationRoot}
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	archiveDir := filepath.Join(txDir, "selected-serving-archive")
	if err := os.Mkdir(archiveDir, 0o700); err != nil {
		return "", err
	}
	inputs := []string{baseManifest}
	for index, key := range keys {
		scope := byKey[key]
		filename := filepath.Join(archiveDir, fmt.Sprintf("serving-%06d.tsv", index))
		if _, err := manifest.Scan(ctx, targetRoot, manifest.Scope{Path: scope.path, Include: scope.include}, filename, manifest.ScanOptions{
			Workers: values.workers, ChunkEntries: values.chunk, TempDir: filepath.Join(cfg.StatePath(), "tmp"),
		}); err != nil {
			return "", fmt.Errorf("scan serving archive scope %s: %w", scope.path, err)
		}
		inputs = append(inputs, filename)
	}
	destination := filepath.Join(archiveDir, "selected-serving-exact.tsv")
	if err := mergePublicationManifests(inputs, destination, archiveDir); err != nil {
		return "", err
	}
	return destination, nil
}

func directMaterializationMutableAssetPath(leaves []viewLeaf) func(string) bool {
	byID := make(map[string]config.Repo)
	for _, leaf := range leaves {
		if leaf.repo.Type == "asset" && leaf.repo.Asset != nil && len(leaf.repo.Asset.MutablePaths) != 0 {
			byID[leaf.repo.ID] = leaf.repo
		}
	}
	if len(byID) == 0 {
		return nil
	}
	repos := make([]config.Repo, 0, len(byID))
	for _, repo := range byID {
		repos = append(repos, repo)
	}
	sort.Slice(repos, func(i, j int) bool { return repos[i].ID < repos[j].ID })
	return func(logicalPath string) bool {
		logicalPath = filepath.ToSlash(logicalPath)
		for _, repo := range repos {
			prefix := strings.TrimSuffix(repo.Path, "/") + "/"
			if !strings.HasPrefix(logicalPath, prefix) || len(logicalPath) == len(prefix) {
				continue
			}
			mutable, err := assetMutablePath(repo, strings.TrimPrefix(logicalPath, prefix))
			return err == nil && mutable
		}
		return false
	}
}

func completeMaterializedAssetUnits(values commonFlags, cfg *config.Config, leaves []viewLeaf, source materializeCanonicalSource, targetRoot string) error {
	seen := make(map[string]struct{})
	for _, leaf := range leaves {
		if leaf.repo.Type != "asset" {
			continue
		}
		if _, duplicate := seen[leaf.repo.ID]; duplicate {
			continue
		}
		seen[leaf.repo.ID] = struct{}{}
		unit, err := materializationUnitFor(values, "asset", source.ID, leaf.repo.ID, "all", "all", targetRoot)
		if err != nil {
			return err
		}
		assetValues := values
		assetValues.materializeUnit = unit
		if err := markMaterializationUnitComplete(assetValues, cfg); err != nil {
			return err
		}
	}
	return nil
}

func excludeManifestPath(sourcePath, destinationPath, excluded string) (resultErr error) {
	excluded = filepath.ToSlash(excluded)
	if excluded == "" || path.Clean(excluded) != excluded || strings.HasPrefix(excluded, "/") || strings.ContainsAny(excluded, "\x00\t\r\n") {
		return errors.New("excluded manifest path is unsafe")
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
	complete := false
	defer func() {
		if !complete {
			_ = os.Remove(destinationPath)
		}
	}()
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
		if entry.Path == excluded {
			continue
		}
		if err := manifest.WriteEntry(destination, entry); err != nil {
			_ = destination.Close()
			return err
		}
	}
	if err := errors.Join(destination.Sync(), destination.Close()); err != nil {
		return err
	}
	complete = true
	return nil
}

func validateDedicatedTarget(cfg *config.Config, target string) error {
	if target == "" || strings.ContainsAny(target, "\x00\t\r\n") {
		return errors.New("materialization target is empty or unsafe")
	}
	abs := target
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(cfg.Root, filepath.FromSlash(target))
	}
	abs, err := filepath.Abs(filepath.Clean(abs))
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(cfg.Root, abs)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("materialization target must be a dedicated directory below the repository root")
	}
	relSlash := filepath.ToSlash(rel)
	if containsReservedMaterializationComponent(relSlash) {
		return errors.New("materialization target overlaps a reserved control directory")
	}
	if err := validatePathComponentsBelowRoot(cfg.Root, abs, true); err != nil {
		return err
	}
	for _, repo := range cfg.Repos {
		path := strings.TrimSuffix(repo.Path, "/")
		if relSlash == path || strings.HasPrefix(relSlash, path+"/") || strings.HasPrefix(path, relSlash+"/") {
			return fmt.Errorf("materialization target overlaps configured repo %s at %s", repo.ID, repo.Path)
		}
	}
	return nil
}

func validateArchiveDestination(cfg *config.Config, configPath, materializedRoot, destination string) error {
	if destination == "" || strings.ContainsAny(destination, "\x00\t\r\n") {
		return errors.New("destination is empty or unsafe")
	}
	rootAbs, err := filepath.Abs(cfg.Root)
	if err != nil {
		return err
	}
	destinationAbs, err := filepath.Abs(filepath.Clean(destination))
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(rootAbs, destinationAbs)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("destination must be a file below the repository root")
	}
	relSlash := filepath.ToSlash(rel)
	if containsReservedMaterializationComponent(relSlash) {
		return errors.New("destination overlaps a reserved .sow/.pool/.git/_sow namespace")
	}
	if err := validatePathComponentsBelowRoot(rootAbs, destinationAbs, false); err != nil {
		return err
	}
	materializedAbs, err := filepath.Abs(filepath.Clean(materializedRoot))
	if err != nil {
		return err
	}
	if filepath.Clean(materializedAbs) != filepath.Clean(rootAbs) && pathsOverlap(destinationAbs, materializedAbs) {
		return errors.New("destination overlaps the materialized tree")
	}
	if configPath != "" {
		configAbs, err := filepath.Abs(filepath.Clean(configPath))
		if err != nil {
			return err
		}
		if pathsOverlap(destinationAbs, configAbs) {
			return errors.New("destination overlaps the active configuration file")
		}
	}
	for _, repo := range cfg.Repos {
		repoRoot := filepath.Join(rootAbs, filepath.FromSlash(strings.TrimSuffix(repo.Path, "/")))
		if pathsOverlap(destinationAbs, repoRoot) {
			return fmt.Errorf("destination overlaps configured repo %s at %s", repo.ID, repo.Path)
		}
	}
	if info, err := os.Lstat(destinationAbs); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("destination is not an exact regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func containsReservedMaterializationComponent(relative string) bool {
	for _, component := range strings.Split(filepath.ToSlash(relative), "/") {
		switch component {
		case config.StateDirectory, config.PoolDirectory, ".git", "_sow":
			return true
		}
	}
	return false
}

func validatePathComponentsBelowRoot(root, target string, targetMayBeDirectory bool) error {
	rootAbs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return err
	}
	targetAbs, err := filepath.Abs(filepath.Clean(target))
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(rootAbs, targetAbs)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("path escapes repository root")
	}
	rootInfo, err := os.Lstat(rootAbs)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return errors.Join(err, errors.New("repository root is not a real directory"))
	}
	current := rootAbs
	components := strings.Split(relative, string(filepath.Separator))
	for index, component := range components {
		if component == "." || component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path component %s is a symlink", current)
		}
		last := index == len(components)-1
		if !last && !info.IsDir() {
			return fmt.Errorf("path parent %s is not a directory", current)
		}
		if last && targetMayBeDirectory && !info.IsDir() {
			return fmt.Errorf("materialization target %s is not a directory", current)
		}
	}
	return nil
}

func pathsOverlap(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if left == right {
		return true
	}
	leftRel, leftErr := filepath.Rel(left, right)
	rightRel, rightErr := filepath.Rel(right, left)
	return leftErr == nil && leftRel != ".." && !strings.HasPrefix(leftRel, ".."+string(filepath.Separator)) ||
		rightErr == nil && rightRel != ".." && !strings.HasPrefix(rightRel, ".."+string(filepath.Separator))
}
