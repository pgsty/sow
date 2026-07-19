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

	"github.com/bmatcuk/doublestar/v4"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

func runAdd(ctx context.Context, args []string, stdout, stderr io.Writer) (resultErr error) {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	values := commonFlags{}
	addCommonFlags(fs, &values)
	destination := fs.String("dest", "", "asset path relative to the selected repository (single input only)")
	replace := fs.Bool("replace", false, "replace an existing mutable asset path")
	inputType := fs.String("type", "auto", "input type: auto, asset, rpm, or deb")
	privateKeyFile := fs.String("gpg-private-key-file", "", "read the OpenPGP private key from a protected file")
	passphraseFile := fs.String("gpg-passphrase-file", "", "read the OpenPGP passphrase from a protected file")
	component := fs.String("component", "", "APT component when it cannot be inferred")
	var expectedObjects orderedValueFlag
	fs.Var(&expectedObjects, "expected-object", "bind each input in order to sha256:<lowercase-64-hex>:<size> (repeatable builder handoff)")
	fs.Usage = func() {
		printSubcommandUsage(fs, "sow add [<file>...] [--repo NAME] [--dest PATH] [--expected-object sha256:HEX:SIZE] [--replace] [--config sow.yaml]",
			"An omitted input list is valid only with --recover to finish a durable interrupted asset add.")
	}
	flagArgs, positionals := partitionInterspersedFlagArgs(fs, args)
	if help, err := parseFlagSet(fs, flagArgs); err != nil || help {
		return err
	}
	if len(positionals) == 0 && !values.recover {
		return withExitCode(ExitUsage, "add requires at least one input file")
	}
	expected, handoffReceipt, err := parseBuilderHandoffObjects(positionals, expectedObjects.values())
	if err != nil {
		return withExitCode(ExitUsage, "%v", err)
	}
	cfg, selected, err := loadAndSelect(values)
	if err != nil {
		return err
	}
	format := ""
	if len(positionals) != 0 {
		format, err = detectAddFormat(positionals, *inputType)
		if err != nil {
			return withExitCode(ExitUsage, "%v", err)
		}
	}
	// An interrupted asset add has already committed its immutable input bytes
	// to CAS and its exact destination view ref before the selected-set journal
	// can exist. Recover that frozen ref/CAS projection before interpreting any
	// positional arguments as a new request. In particular, recovery must not
	// reopen the operator's original input paths: they are not durable state and
	// may no longer exist.
	if values.recover {
		if len(positionals) == 0 {
			packageRecovered, err := recoverPendingPackageProjection(ctx, cfg, values, "add", *privateKeyFile, *passphraseFile, stdout, stderr)
			if err != nil {
				return withExitCode(ExitVerification, "recover package add projection: %v", err)
			}
			if packageRecovered {
				return nil
			}
			recovered, err := recoverPendingAssetAddMaterialization(ctx, cfg, values, true, stdout, stderr)
			if err != nil {
				return err
			}
			if recovered {
				return nil
			}
			return withExitCode(ExitUsage, "add requires at least one input file")
		}
		if _, err := recoverPendingAssetAddMaterialization(ctx, cfg, values, false, stdout, stderr); err != nil {
			return err
		}
	}
	if *destination != "" && len(positionals) != 1 {
		return withExitCode(ExitUsage, "--dest requires exactly one input file")
	}
	switch format {
	case "rpm":
		if *destination != "" || *replace || *component != "" {
			return withExitCode(ExitUsage, "RPM add does not accept --dest, --replace, or --component")
		}
		if err := runAddRPMExpected(ctx, cfg, selected, positionals, expected, values, *privateKeyFile, *passphraseFile, stdout, stderr); err != nil {
			return err
		}
		if err := rebuildCatalogProjection(ctx, cfg, stdout); err != nil {
			return err
		}
		emitBuilderHandoffReceipt(stdout, handoffReceipt, len(positionals))
		return nil
	case "deb":
		if *destination != "" || *replace {
			return withExitCode(ExitUsage, "DEB add does not accept --dest or --replace")
		}
		if err := runAddDEBExpected(ctx, cfg, selected, positionals, expected, values, *component, *privateKeyFile, *passphraseFile, stdout, stderr); err != nil {
			return err
		}
		if err := rebuildCatalogProjection(ctx, cfg, stdout); err != nil {
			return err
		}
		emitBuilderHandoffReceipt(stdout, handoffReceipt, len(positionals))
		return nil
	case "asset":
		// Continue through the asset transaction below.
	default:
		return withExitCode(ExitUsage, "unsupported add input type %q", format)
	}
	lock, err := state.AcquireLock(cfg.StatePath(), "add", values.recover)
	if err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	defer propagateStateLockRelease(lock, &resultErr, stderr)
	if err := requireNoForeignMaterializationIntent(cfg, "add", values.recover); err != nil {
		return withExitCode(ExitConflict, "durable materialization intent: %v", err)
	}
	if err := requireNoMaterializationIntentBeforeAssetAdd(cfg); err != nil {
		return withExitCode(ExitConflict, "asset add recovery admission: %v", err)
	}
	canonical := state.New(cfg.StatePath())
	if err := prepareCanonicalState(ctx, canonical, values.recover, stdout); err != nil {
		return err
	}
	if err := requireCanonicalConfigBaseline(cfg, canonical); err != nil {
		return withExitCode(ExitConflict, "canonical config changed while add was waiting for the state lock: %v", err)
	}
	txDir, err := newTransactionDir(cfg.StatePath(), "add-")
	if err != nil {
		return withExitCode(ExitInternal, "create add transaction: %v", err)
	}
	defer os.RemoveAll(txDir)
	if err := addAssetFiles(ctx, cfg, selected, positionals, expected, values, *destination, *replace, canonical, txDir, "add", stdout); err != nil {
		return err
	}
	emitBuilderHandoffReceipt(stdout, handoffReceipt, len(positionals))
	return nil
}

// recoverPendingAssetAddMaterialization closes an interrupted asset selected
// set before runAdd dispatches the current positional inputs by subtype. A
// non-asset add journal is left to the DEB/RPM recovery path; an inputless retry
// has no subtype to dispatch to and therefore requires the durable envelope to
// decode as one exact asset add.
func recoverPendingAssetAddMaterialization(ctx context.Context, cfg *config.Config, values commonFlags, inputless bool, stdout, stderr io.Writer) (recovered bool, resultErr error) {
	lock, err := state.AcquireLock(cfg.StatePath(), "add", true)
	if err != nil {
		return false, withExitCode(ExitConflict, "%v", err)
	}
	defer propagateStateLockRelease(lock, &resultErr, stderr)
	if err := requireNoForeignMaterializationIntent(cfg, "add", true); err != nil {
		return false, withExitCode(ExitConflict, "durable materialization intent: %v", err)
	}
	if !inputless {
		if _, exists, err := readPackageProjectionIntent(cfg.StatePath()); err != nil {
			return false, withExitCode(ExitConflict, "read package projection before asset retry: %v", err)
		} else if exists {
			return false, nil
		}
	}
	canonical := state.New(cfg.StatePath())
	if err := requireProjectionTransactionsCompatibleBeforeRecovery(cfg, canonical, "add"); err != nil {
		return false, withExitCode(ExitConflict, "asset add recovery transaction preflight: %v", err)
	}
	if err := preflightPendingAssetProjection(cfg, canonical, "add"); err != nil {
		return false, withExitCode(ExitConflict, "asset add recovery projection preflight: %v", err)
	}
	if err := prepareCanonicalState(ctx, canonical, true, stdout); err != nil {
		return false, err
	}
	if err := requireCanonicalConfigBaseline(cfg, canonical); err != nil {
		return false, withExitCode(ExitConflict, "canonical config changed while add recovery was waiting for the state lock: %v", err)
	}
	// Validate an already-started selected set before the pending bridge is
	// allowed to drive it. Rehashing a journal must not turn a non-exact add
	// envelope into a generic bridge recovery error or clear either fence.
	preJournal, preJournalExists, err := readMaterializationSelectionJournal(cfg.StatePath())
	if err != nil {
		return false, withExitCode(ExitConflict, "read add materialization recovery intent: %v", err)
	}
	if preJournalExists {
		containsAsset := false
		for _, unit := range preJournal.Units {
			containsAsset = containsAsset || unit.Kind == "asset"
		}
		if containsAsset {
			if _, _, err := decodeAssetAddMaterialization(cfg, preJournal); err != nil {
				return false, withExitCode(ExitConflict, "decode asset add materialization: %v", err)
			}
		}
	}
	projectionRecovered, err := recoverPendingAssetProjectionLocked(ctx, cfg, canonical, values, "add", stdout)
	if err != nil {
		return false, withExitCode(ExitVerification, "recover asset add materialization: %v", err)
	}
	if projectionRecovered && inputless {
		return true, nil
	}
	journal, exists, err := readMaterializationSelectionJournal(cfg.StatePath())
	if err != nil {
		return false, withExitCode(ExitConflict, "read add materialization recovery intent: %v", err)
	}
	if !exists {
		return projectionRecovered, nil
	}
	assetCandidate := false
	packageCandidate := true
	for _, unit := range journal.Units {
		if unit.Kind == "asset" {
			assetCandidate = true
		}
		if unit.Kind != "apt" && unit.Kind != "yum" {
			packageCandidate = false
		}
	}
	if !assetCandidate && !inputless {
		if packageCandidate {
			return false, nil
		}
		return false, withExitCode(ExitConflict, "durable add materialization is neither an exact asset add nor a package selected set")
	}

	repo, viewName, err := decodeAssetAddMaterialization(cfg, journal)
	if err != nil {
		return false, withExitCode(ExitConflict, "decode asset add materialization: %v", err)
	}
	leaf := viewLeaf{repo: repo, os: "all", arch: "all"}
	trust, err := captureMaterializationTrust(cfg, []viewLeaf{leaf}, nil, "")
	if err != nil {
		return false, withExitCode(ExitConfig, "capture asset add recovery trust: %v", err)
	}
	recoveryValues := values
	recoveryValues.materializeTrust = trust
	recoveryValues.materializeOperation = "add"
	recoveryValues.materializeScope = ""
	recoveryValues.materializeSource = ""
	recoveryValues.materializeTarget = ""
	recoveryValues.materializeUnit = ""

	txDir, err := newTransactionDir(cfg.StatePath(), "add-recover-")
	if err != nil {
		return false, withExitCode(ExitInternal, "create asset add recovery transaction: %v", err)
	}
	defer os.RemoveAll(txDir)
	pool, err := repository.NewStore(cfg.Root)
	if err != nil {
		return false, withExitCode(ExitConflict, "open CAS for asset add recovery: %v", err)
	}
	// A recovery attempt is itself a started convergence operation. Promote an
	// inherited prepared fence before entering the materializer so even a
	// pre-payload validation/CAS failure cannot be mistaken for an empty new
	// transaction and clear the only durable recovery intent.
	if journal.Phase == materializationSelectionPrepared {
		journal.Phase = materializationSelectionMaterializing
		if err := writeMaterializationSelectionJournal(cfg.StatePath(), journal); err != nil {
			return false, withExitCode(ExitConflict, "start asset add recovery: %v", err)
		}
	}
	materialized, reconciled, err := materializeAssetView(ctx, cfg, canonical, pool, repo, viewName, txDir, recoveryValues)
	if err != nil {
		return false, withExitCode(ExitVerification, "recover asset add materialization: %v", err)
	}
	fmt.Fprintf(stdout, "recovered asset add repo=%s view=%s entries=%d linked=%d existing=%d relinked=%d pruned=%d\n",
		repo.ID, viewName, materialized.Entries, materialized.Linked, materialized.Existing, materialized.Relinked, reconciled.RemovedFiles)
	return true, nil
}

func decodeAssetAddMaterialization(cfg *config.Config, journal materializationSelectionJournal) (config.Repo, string, error) {
	if cfg == nil {
		return config.Repo{}, "", errors.New("configuration is unavailable")
	}
	if journal.Operation != "add" || journal.OperationScope != "" ||
		journal.RepositoryKeySHA256 != materializationNoRepositoryKeySHA256 || len(journal.YUMKeyrings) != 0 || len(journal.Units) != 1 {
		return config.Repo{}, "", errors.New("durable add envelope is not an exact asset-only materialization")
	}
	unit := journal.Units[0]
	if unit.Kind != "asset" || unit.Historical || unit.OS != "all" || unit.Arch != "all" || len(unit.Refs) != 1 {
		return config.Repo{}, "", errors.New("durable add unit has invalid asset coordinates")
	}
	repo, exists := cfg.RepoByName(unit.Repo)
	if !exists || !repo.IsActive() || repo.Type != "asset" || repo.Asset == nil {
		return config.Repo{}, "", fmt.Errorf("durable add repo %s is not an active asset repository", unit.Repo)
	}
	wantedView := "beta"
	if repo.DefaultPool == "gated" {
		wantedView = "stable"
	}
	view, exists := cfg.Views[wantedView]
	if !exists || !viewIncludesRepo(view, repo.ID) || unit.Source != wantedView {
		return config.Repo{}, "", fmt.Errorf("durable add source %s is not the configured destination for repo %s", unit.Source, repo.ID)
	}
	wantedRef, err := state.ViewRef(wantedView, repo.ID, "all", "all")
	if err != nil {
		return config.Repo{}, "", err
	}
	if unit.Refs[0].Name != wantedRef.String() {
		return config.Repo{}, "", errors.New("durable add ref does not match its asset coordinates")
	}
	targetSHA, err := materializationTargetSHA256(cfg.Root)
	if err != nil {
		return config.Repo{}, "", err
	}
	if unit.TargetSHA256 != targetSHA {
		return config.Repo{}, "", errors.New("durable add target is not the configured repository root")
	}
	return repo, wantedView, nil
}

// addAssetFiles imports immutable bytes into CAS, advances the appropriate
// confidentiality-derived asset view, and refreshes its hardlink projection.
// The caller owns the repository lock and has prepared canonical state. This
// lets materialize close the offline-artifact loop without recursively
// invoking the CLI or dropping the lock between archive creation and adoption.
func addAssetFiles(ctx context.Context, cfg *config.Config, selected []config.Repo, inputs []string, expectedInputs map[string]repository.Object, values commonFlags, destination string, replace bool, canonical *state.Store, txDir, operation string, stdout io.Writer) error {
	var candidates []config.Repo
	for _, repo := range selected {
		if repo.Type == "asset" {
			candidates = append(candidates, repo)
		}
	}
	if len(candidates) != 1 {
		return withExitCode(ExitConfig, "asset add requires exactly one selected asset repo; matched %d", len(candidates))
	}
	if destination != "" && len(inputs) != 1 {
		return withExitCode(ExitUsage, "asset destination requires exactly one input file")
	}
	repo := candidates[0]
	// Asset materialization has no repository-signing key, but it still needs a
	// durable selected-set coordinator before the first directly hostable
	// mutation. Always capture a fresh asset-only snapshot here so standalone add
	// and offline-archive adoption cannot inherit an unrelated outer transaction.
	assetLeaf := viewLeaf{repo: repo, os: "all", arch: "all"}
	assetTrust, err := captureMaterializationTrust(cfg, []viewLeaf{assetLeaf}, nil, "")
	if err != nil {
		return withExitCode(ExitConfig, "capture asset materialization trust: %v", err)
	}
	values.materializeTrust = assetTrust
	values.materializeOperation = operation
	logicalPaths := make([]string, len(inputs))
	for index, input := range inputs {
		relative := destination
		if relative == "" {
			relative = filepath.Base(input)
		}
		logicalPath, err := assetLogicalPath(repo.Path, relative)
		if err != nil {
			return withExitCode(ExitUsage, "%v", err)
		}
		if err := validateAssetProjectionPath(repo, logicalPath); err != nil {
			return withExitCode(ExitUsage, "%v", err)
		}
		if replace {
			mutable, err := assetMutablePath(repo, strings.TrimPrefix(logicalPath, strings.TrimSuffix(repo.Path, "/")+"/"))
			if err != nil {
				return withExitCode(ExitConfig, "validate mutable asset path %s: %v", logicalPath, err)
			}
			if !mutable {
				return withExitCode(ExitConflict, "asset path %s is immutable; --replace requires an asset.mutable_paths match", logicalPath)
			}
		}
		logicalPaths[index] = logicalPath
	}
	archiveContract := cloneOfflineArchiveAdoptionContract(values.offlineArchiveAdoption)
	if values.materializeScope == offlineArchiveAdoptionMaterializationScope || archiveContract != nil {
		if operation != "materialize" || values.materializeScope != offlineArchiveAdoptionMaterializationScope || archiveContract == nil || len(inputs) != 1 || replace {
			return withExitCode(ExitConflict, "offline archive adoption requires one immutable input and its exact materialize contract")
		}
		if err := requireOfflineArchiveAdoptionContract(cfg, canonical, archiveContract); err != nil {
			return withExitCode(ExitVerification, "verify offline archive adoption contract before CAS import: %v", err)
		}
		if archiveContract.Destination.Repo != repo.ID || archiveContract.Destination.Path != logicalPaths[0] || archiveContract.Destination.Pool != repo.DefaultPool {
			return withExitCode(ExitConflict, "offline archive adoption destination differs from its frozen repo/pool/path")
		}
		assetTrust.archiveAdoption = cloneOfflineArchiveAdoptionContract(archiveContract)
	}
	expectedObjects := make([]repository.Object, len(inputs))
	for index, input := range inputs {
		if err := requireAssetInputOutsideState(cfg, input); err != nil {
			return withExitCode(ExitConflict, "asset input import admission: %v", err)
		}
		inspected, err := inspectOfflineArchiveInputContext(ctx, input)
		if err != nil {
			return withExitCode(ExitConflict, "inspect stable asset input %s before admission: %v", input, err)
		}
		observed := inspected.Object
		expectedObjects[index] = observed
		digestText, size := observed.HashString(), observed.Size
		if err := verifyExpectedBuilderInput(input, digestText, size, expectedInputs); err != nil {
			return withExitCode(ExitVerification, "%v", err)
		}
		receipt, err := requireOfflineArchiveTaintAdmission(canonical, repo, digestText, size)
		if err != nil {
			return withExitCode(ExitVerification, "asset confidentiality admission before CAS import: %v", err)
		}
		var contractedSource *offlineArchiveSourceProof
		if archiveContract != nil {
			contractedSource = &archiveContract.Source
		}
		if err := requireOfflineArchiveMarkerAdmission(inspected.Marker, repo, receipt, contractedSource); err != nil {
			return withExitCode(ExitVerification, "asset offline archive marker admission before CAS import: %v", err)
		}
		if archiveContract != nil {
			if receipt == nil {
				return withExitCode(ExitVerification, "offline archive adoption has no canonical digest taint receipt")
			}
			if digestText != archiveContract.ArchiveSHA256 || size != archiveContract.ArchiveSize {
				return withExitCode(ExitVerification, "offline archive input differs from its finalized contract")
			}
		}
	}
	pool, err := repository.NewStore(cfg.Root)
	if err != nil {
		return withExitCode(ExitConflict, "open CAS: %v", err)
	}
	entries := make([]views.Entry, 0, len(inputs))
	for index, input := range inputs {
		object, err := pool.ImportExpected(ctx, input, expectedObjects[index])
		if err != nil {
			return withExitCode(ExitConflict, "import %s: %v", input, err)
		}
		logicalPath := logicalPaths[index]
		entries = append(entries, views.Entry{
			Repo: repo.ID, OS: "all", Arch: "all", Name: path.Base(logicalPath),
			Version: object.HashString()[:16], Path: logicalPath, Size: object.Size,
			SHA256: object.HashString(), Pool: repo.DefaultPool,
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	viewName := "beta"
	if repo.DefaultPool == "gated" {
		viewName = "stable"
	}
	viewConfig := cfg.Views[viewName]
	viewPath, err := state.ViewPath(viewName, repo.ID, "all", "all")
	if err != nil {
		return withExitCode(ExitInternal, "%v", err)
	}
	viewRef, err := state.ViewRef(viewName, repo.ID, "all", "all")
	if err != nil {
		return withExitCode(ExitInternal, "%v", err)
	}
	expected, exists, err := canonical.Ref(viewRef)
	if err != nil {
		return withExitCode(ExitInternal, "read %s: %v", viewRef, err)
	}
	if exists {
		leaf := viewLeaf{repo: repo, os: "all", arch: "all"}
		if err := validateViewAt(canonical, expected, viewPath, leaf, viewConfig.Access == "public"); err != nil {
			return withExitCode(ExitVerification, "validate %s: %v", viewRef, err)
		}
	}
	existing, err := openViewAt(canonical, expected, viewPath, exists)
	if err != nil {
		return withExitCode(ExitInternal, "%v", err)
	}
	stage, err := os.CreateTemp(txDir, "asset-view-*.tsv")
	if err != nil {
		existing.Close()
		return withExitCode(ExitInternal, "%v", err)
	}
	stats, mutationErr := views.Mutate(existing, stage, views.Mutation{
		Upserts: entries, AllowReplace: replace, AppendOnly: viewConfig.AppendOnly,
		AppendOnlyReplacementPaths: assetReplacementPaths(entries, replace),
		Public:                     viewConfig.Access == "public",
	})
	closeErr := errors.Join(existing.Close(), stage.Sync(), stage.Close())
	if mutationErr != nil || closeErr != nil {
		return withExitCode(ExitConflict, "update %s: %v", viewRef, errors.Join(mutationErr, closeErr))
	}
	commit := expected
	var projectionIntent *assetProjectionIntent
	if stats.Changed() {
		// Fence the exact desired view and local transaction ID before Apply.
		// This bridge survives every process-stop point until the selected-set
		// journal can bind the actual ref commit inside materializeAssetView.
		var fenceErr error
		if archiveContract != nil {
			fenceErr = requireOfflineArchiveAdoptionOwnerBeforeCanonicalMutation(cfg, archiveContract)
		} else {
			fenceErr = requireNoMaterializationIntentBeforeCanonicalMutation(cfg)
		}
		if fenceErr != nil {
			return withExitCode(ExitConflict, "%v", fenceErr)
		}
		intent, durableStage, err := prepareAssetProjectionIntent(cfg, canonical, operation, values.materializeScope, repo, viewName, viewPath, viewRef, expected, stage.Name(), archiveContract)
		if err != nil {
			return withExitCode(ExitConflict, "persist pending asset projection before canonical mutation: %v", err)
		}
		projectionIntent = &intent
		if assetProjectionMutationHook != nil {
			if err := assetProjectionMutationHook("after-fence-before-apply"); err != nil {
				return withExitCode(ExitConflict, "pending asset projection fault: %v", err)
			}
		}
		staged := map[string]string{viewPath: durableStage}
		configHash := intent.ConfigSHA256
		staged["config/sow.yaml"] = filepath.Join(cfg.StatePath(), intent.ConfigStage)
		applyOptions := state.ApplyOptions{TransactionID: intent.TransactionID}
		if assetProjectionMutationHook != nil {
			applyOptions.AfterIntent = func() error { return assetProjectionMutationHook("after-transaction-intent-before-commit") }
			applyOptions.AfterCommit = func() error { return assetProjectionMutationHook("after-canonical-commit-before-ref") }
		}
		commit, _, err = applyCanonicalConfig(ctx, cfg, canonical, operation, intent.Message, staged, []state.RefUpdate{{Name: viewRef, Expected: expected}}, applyOptions)
		if err != nil {
			return stateMutationError("commit asset add", err)
		}
		if assetProjectionMutationHook != nil {
			if err := assetProjectionMutationHook("after-ref-before-materialize"); err != nil {
				return withExitCode(ExitConflict, "pending asset projection fault: %v", err)
			}
		}
		fmt.Fprintf(stdout, "added repo=%s view=%s files=%d replaced=%d commit=%s config_sha256=%s\n", repo.ID, viewName, stats.Added, stats.Replaced, commit, configHash)
	} else {
		fmt.Fprintf(stdout, "add unchanged repo=%s view=%s files=%d commit=%s\n", repo.ID, viewName, len(entries), commit)
	}
	materialized, reconciled, err := materializeAssetView(ctx, cfg, canonical, pool, repo, viewName, txDir, values)
	if err != nil {
		return withExitCode(ExitVerification, "materialize asset view: %v", err)
	}
	if projectionIntent != nil {
		if err := removeAssetProjectionIntent(cfg.StatePath(), *projectionIntent); err != nil {
			return withExitCode(ExitConflict, "complete pending asset projection: %v", err)
		}
	}
	fmt.Fprintf(stdout, "asset tree repo=%s view=%s entries=%d linked=%d existing=%d relinked=%d pruned=%d\n",
		repo.ID, viewName, materialized.Entries, materialized.Linked, materialized.Existing, materialized.Relinked, reconciled.RemovedFiles)
	return nil
}

func requireAssetInputOutsideState(cfg *config.Config, input string) error {
	if cfg == nil {
		return errors.New("asset input configuration is unavailable")
	}
	inputReal, err := filepath.EvalSymlinks(input)
	if err != nil {
		return err
	}
	inputReal, err = filepath.Abs(inputReal)
	if err != nil {
		return err
	}
	stateReal, err := filepath.EvalSymlinks(cfg.StatePath())
	if err != nil {
		return err
	}
	stateReal, err = filepath.Abs(stateReal)
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(stateReal, inputReal)
	if err != nil {
		return err
	}
	if relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("asset inputs cannot be read from SOW private state")
	}
	return nil
}

func assetReplacementPaths(entries []views.Entry, replace bool) []string {
	if !replace {
		return nil
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		paths = append(paths, entry.Path)
	}
	return paths
}

func packageDestinationView(repo config.Repo, debugInfo bool) string {
	if repo.DefaultPool == "gated" || debugInfo {
		return "stable"
	}
	return "beta"
}

func assetMutablePath(repo config.Repo, relative string) (bool, error) {
	if repo.Asset == nil {
		return false, errors.New("repository is not an asset repository")
	}
	for _, pattern := range repo.Asset.MutablePaths {
		matched, err := doublestar.Match(pattern, relative)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

func assetMaterializationMutablePath(repo config.Repo) func(string) bool {
	if repo.Asset == nil || len(repo.Asset.MutablePaths) == 0 {
		return nil
	}
	return func(relative string) bool {
		mutable, err := assetMutablePath(repo, filepath.ToSlash(relative))
		return err == nil && mutable
	}
}

func detectAddFormat(inputs []string, override string) (string, error) {
	if override != "auto" && override != "asset" && override != "rpm" && override != "deb" {
		return "", fmt.Errorf("--type must be auto, asset, rpm, or deb")
	}
	if override != "auto" {
		return override, nil
	}
	format := ""
	for _, input := range inputs {
		current := "asset"
		switch strings.ToLower(filepath.Ext(input)) {
		case ".rpm":
			current = "rpm"
		case ".deb":
			current = "deb"
		}
		if format == "" {
			format = current
		} else if format != current {
			return "", errors.New("one add transaction cannot mix asset, RPM, and DEB inputs")
		}
	}
	return format, nil
}

func splitLeadingPositionals(args []string) ([]string, []string) {
	index := 0
	for index < len(args) && !strings.HasPrefix(args[index], "-") {
		index++
	}
	return append([]string(nil), args[:index]...), args[index:]
}

// partitionInterspersedFlagArgs lets add accept the conventional artifact-first
// spelling while still honoring options that appear after any input. The
// standard flag package stops at its first positional, which could otherwise
// silently leave a later --config or --repo in the input list and operate on
// defaults. Known non-boolean options keep their following value even when it
// begins with a dash; the first standalone -- makes every remaining argument a
// literal input. Unknown flag-shaped arguments stay in flagArgs so flag.Parse
// rejects them before configuration is read or repository state is mutated.
func partitionInterspersedFlagArgs(fs *flag.FlagSet, args []string) (flagArgs, positionals []string) {
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "--" {
			positionals = append(positionals, args[index+1:]...)
			break
		}
		if !strings.HasPrefix(argument, "-") || argument == "-" {
			positionals = append(positionals, argument)
			continue
		}

		flagArgs = append(flagArgs, argument)
		name := strings.TrimPrefix(strings.TrimPrefix(argument, "-"), "-")
		if _, _, assigned := strings.Cut(name, "="); assigned {
			continue
		}
		registered := fs.Lookup(name)
		if registered == nil {
			continue
		}
		boolean, isBoolean := registered.Value.(interface{ IsBoolFlag() bool })
		if isBoolean && boolean.IsBoolFlag() {
			continue
		}
		if index+1 < len(args) {
			index++
			flagArgs = append(flagArgs, args[index])
		}
	}
	return flagArgs, positionals
}

func assetLogicalPath(repoPath, relative string) (string, error) {
	relative = strings.TrimPrefix(filepath.ToSlash(relative), "./")
	if err := validateAssetRelativeRoute(relative); err != nil {
		return "", err
	}
	return path.Join(repoPath, relative), nil
}

func materializeAssetView(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, repo config.Repo, viewName, txDir string, values commonFlags) (materialized repository.MaterializeStats, reconciled repository.ReconcileStats, resultErr error) {
	leaf := viewLeaf{repo: repo, os: "all", arch: "all"}
	// Every caller of this specialized materializer writes repositoryViewTarget
	// below cfg.Root. In particular, an offline archive may have been produced
	// from an explicit export elsewhere; inheriting that export path would make
	// the durable unit identify a tree it never mutates.
	targetRoot := cfg.Root
	values, selectionOwner, err := beginMaterializationSelectionForSource(cfg, canonical, values, selectedMaterializationOperation(values, "materialize"), materializeCanonicalSource{ID: viewName, Public: cfg.Views[viewName].Access == "public"}, []viewLeaf{leaf}, targetRoot, true, false)
	if err != nil {
		return materialized, reconciled, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, finishMaterializationSelectedSet(cfg, values.materializeTrust, selectionOwner, resultErr))
	}()
	values.materializeUnit, err = materializationUnitFor(values, "asset", viewName, repo.ID, "all", "all", targetRoot)
	if err != nil {
		return materialized, reconciled, err
	}
	viewPath, err := state.ViewPath(viewName, repo.ID, "all", "all")
	if err != nil {
		return materialized, reconciled, err
	}
	viewRef, err := state.ViewRef(viewName, repo.ID, "all", "all")
	if err != nil {
		return materialized, reconciled, err
	}
	commit, exists, err := canonical.Ref(viewRef)
	if err != nil || !exists {
		return materialized, reconciled, errors.Join(err, fmt.Errorf("view ref %s is missing", viewRef))
	}
	if err := validateViewAt(canonical, commit, viewPath, leaf, cfg.Views[viewName].Access == "public"); err != nil {
		return materialized, reconciled, err
	}
	reader, err := canonical.OpenPathAt(commit, viewPath)
	if err != nil {
		return materialized, reconciled, err
	}
	projectedPath := filepath.Join(txDir, fmt.Sprintf("asset-%s-%s-full.tsv", repo.ID, viewName))
	projected, err := os.OpenFile(projectedPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		reader.Close()
		return materialized, reconciled, err
	}
	_, _, projectErr := views.ProjectManifest([]views.ProjectionInput{{Label: viewRef.String(), Reader: reader}}, projected)
	closeErr := errors.Join(reader.Close(), projected.Sync(), projected.Close())
	if projectErr != nil || closeErr != nil {
		return materialized, reconciled, errors.Join(projectErr, closeErr)
	}
	relativeManifest := filepath.Join(txDir, fmt.Sprintf("asset-%s-%s-relative.tsv", repo.ID, viewName))
	if err := stripManifestPrefix(projectedPath, relativeManifest, repo.Path); err != nil {
		return materialized, reconciled, err
	}
	target := repo.Path
	switch viewName {
	case "beta":
		target = filepath.ToSlash(filepath.Join(config.StateDirectory, "materialized", "beta", repo.Path))
	case "stable":
		target = filepath.ToSlash(filepath.Join(config.StateDirectory, "origin", "gated", repo.Path))
	}
	desired, err := os.Open(relativeManifest)
	if err != nil {
		return materialized, reconciled, err
	}
	if err := requireAllMaterializationTrust(values, cfg, nil, materializeTrustPayloadBefore); err != nil {
		desired.Close()
		return materialized, reconciled, err
	}
	materialized, materializeErr := pool.MaterializeWithOptions(ctx, desired, target, repository.MaterializeOptions{
		// The stripped manifest is repository-relative, so evaluate the frozen
		// asset.mutable_paths contract against each exact repository path. Never
		// widen one mutable add or a publish retry to the rest of the asset tree.
		AllowReplacePath: assetMaterializationMutablePath(repo), Workers: values.workers,
	})
	closeErr = desired.Close()
	if materializeErr != nil || closeErr != nil {
		return materialized, reconciled, errors.Join(materializeErr, closeErr)
	}
	if err := requireAllMaterializationTrust(values, cfg, nil, materializeTrustPayloadAfter); err != nil {
		return materialized, reconciled, err
	}
	if err := requireAllMaterializationTrust(values, cfg, nil, materializeTrustExactReconcileBefore); err != nil {
		return materialized, reconciled, err
	}
	reconciled, err = pool.ReconcileExact(ctx, relativeManifest, target, values.workers, values.chunk)
	if err != nil {
		return materialized, reconciled, err
	}
	if err := requireAllMaterializationTrust(values, cfg, nil, materializeTrustExactReconcileAfter); err != nil {
		return materialized, reconciled, err
	}
	if err := requireAllMaterializationTrust(values, cfg, nil, materializeTrustServingPublishBefore); err != nil {
		return materialized, reconciled, err
	}
	if err := serving.PublishHostableTree(filepath.Join(cfg.Root, filepath.FromSlash(target))); err != nil {
		return materialized, reconciled, fmt.Errorf("publish hostable asset tree: %w", err)
	}
	if err := requireAllMaterializationTrust(values, cfg, nil, materializeTrustServingPublishAfter); err != nil {
		return materialized, reconciled, err
	}
	if err := markMaterializationUnitComplete(values, cfg); err != nil {
		return materialized, reconciled, err
	}
	return materialized, reconciled, nil
}

func stripManifestPrefix(sourcePath, destinationPath, prefix string) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	destination, err := os.OpenFile(destinationPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		source.Close()
		return err
	}
	reader := manifest.NewReader(source)
	prefix = strings.TrimSuffix(filepath.ToSlash(prefix), "/") + "/"
	for {
		entry, readErr := reader.Next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return errors.Join(readErr, source.Close(), destination.Close())
		}
		if !strings.HasPrefix(entry.Path, prefix) || len(entry.Path) == len(prefix) {
			return errors.Join(fmt.Errorf("manifest path %q is outside repo prefix %q", entry.Path, prefix), source.Close(), destination.Close())
		}
		entry.Path = strings.TrimPrefix(entry.Path, prefix)
		if err := manifest.WriteEntry(destination, entry); err != nil {
			return errors.Join(err, source.Close(), destination.Close())
		}
	}
	return errors.Join(source.Close(), destination.Sync(), destination.Close())
}
