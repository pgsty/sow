package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
	"github.com/pgsty/sow/internal/yumrepo"
)

type assetRemovalMutation struct {
	leaf     viewLeaf
	viewPath string
	viewRef  plumbing.ReferenceName
	expected plumbing.Hash
}

func runRemove(ctx context.Context, args []string, stdout, stderr io.Writer) (resultErr error) {
	fs := flag.NewFlagSet("rm", flag.ContinueOnError)
	fs.SetOutput(stderr)
	values := commonFlags{}
	addCommonFlags(fs, &values)
	viewName := fs.String("view", "beta", "mutable view to remove from")
	privateKeyFile := fs.String("gpg-private-key-file", "", "read the OpenPGP private key from a protected file")
	passphraseFile := fs.String("gpg-passphrase-file", "", "read the OpenPGP passphrase from a protected file")
	fs.Usage = func() {
		printSubcommandUsage(fs, "sow rm <package-name-or-path>... [--view beta|latest] [--repo NAME] [--os OS] [--arch ARCH]")
	}
	selectors, flagArgs := splitLeadingPositionals(args)
	parseArgs, literalSelectors := splitFlagDelimiter(fs, flagArgs)
	if help, err := parseFlagSet(fs, parseArgs); err != nil || help {
		return err
	}
	// flag stops at the first positional. Any flag-shaped token left in that
	// unparsed tail is almost certainly an option the operator expected us to
	// honor; treating it as a package selector could silently remove from the
	// default beta view. Literal leading-dash selectors remain available after
	// the conventional `--` delimiter.
	for _, argument := range fs.Args() {
		if strings.HasPrefix(argument, "-") && argument != "-" {
			return withExitCode(ExitUsage, "rm option %q appears after a positional argument; move options before selectors or use -- for a literal selector", argument)
		}
	}
	selectors = append(selectors, fs.Args()...)
	selectors = append(selectors, literalSelectors...)
	if len(selectors) == 0 && !values.recover {
		return withExitCode(ExitUsage, "rm requires at least one package name or path")
	}
	cfg, repos, err := loadAndSelect(values)
	if err != nil {
		return err
	}
	if values.recover {
		packageRecovered, packageRecoverErr := recoverPendingPackageProjection(ctx, cfg, values, "rm", *privateKeyFile, *passphraseFile, stdout, stderr)
		if packageRecoverErr != nil {
			return withExitCode(ExitVerification, "recover package removal projection: %v", packageRecoverErr)
		}
		if packageRecovered && len(selectors) == 0 {
			return nil
		}
		recovered, recoverErr := recoverPendingAssetRemoveProjection(ctx, cfg, values, len(selectors) == 0, stdout, stderr)
		if recoverErr != nil {
			return recoverErr
		}
		if len(selectors) == 0 {
			if recovered {
				return nil
			}
			return withExitCode(ExitUsage, "rm requires at least one package name or path")
		}
	}
	viewConfig, exists := cfg.Views[*viewName]
	if !exists || *viewName == "snapshot" {
		return withExitCode(ExitConfig, "unknown removable view %q", *viewName)
	}
	if viewConfig.AppendOnly {
		return withExitCode(ExitConflict, "view %s is append-only", *viewName)
	}
	needsSigning := false
	for _, repo := range repos {
		if repo.Type != "asset" {
			needsSigning = true
			if repo.Type == "apt" && repo.APT != nil {
				for _, suite := range repo.APT.Suites {
					if repo.LifecycleForSuite(suite) == "frozen" {
						return withExitCode(ExitConflict, "repo %s suite %s is frozen; historical package removal is forbidden", repo.ID, suite)
					}
				}
			} else if repo.OS.Lifecycle == "frozen" {
				return withExitCode(ExitConflict, "repo %s is frozen; historical package removal is forbidden", repo.ID)
			}
		}
	}
	var privateKey, passphrase []byte
	var repositoryKeySHA string
	if needsSigning {
		privateKey, err = resolveSecret(cfg.GPG.PrivateKey, *privateKeyFile, false)
		if err != nil {
			return withExitCode(ExitConfig, "resolve OpenPGP private key: %v", err)
		}
		defer clearSecret(privateKey)
		passphrase, err = resolveSecret(cfg.GPG.Passphrase, *passphraseFile, true)
		if err != nil {
			return withExitCode(ExitConfig, "resolve OpenPGP passphrase: %v", err)
		}
		defer clearSecret(passphrase)
		repositoryKeySHA, err = repositorySigningKeyIdentity(cfg, privateKey)
		if err != nil {
			return withExitCode(ExitConfig, "repository signing trust preflight failed: %v", err)
		}
		if _, err := aptrepo.NewSigner(bytes.NewReader(privateKey), passphrase); err != nil {
			return withExitCode(ExitConfig, "OpenPGP signing preflight failed")
		}
		if _, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(privateKey), passphrase, time.Now().UTC()); err != nil {
			return withExitCode(ExitConfig, "OpenPGP signing preflight failed")
		}
	}
	lock, err := state.AcquireLock(cfg.StatePath(), "rm", values.recover)
	if err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	defer propagateStateLockRelease(lock, &resultErr, stderr)
	if needsSigning {
		if err := requireNoForeignMaterializationIntent(cfg, "rm", values.recover); err != nil {
			return withExitCode(ExitConflict, "%v", err)
		}
	} else if err := requireNoMaterializationIntentBeforeCanonicalMutation(cfg); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	canonical := state.New(cfg.StatePath())
	if err := prepareCanonicalState(ctx, canonical, values.recover, stdout); err != nil {
		return err
	}
	if err := requireCanonicalConfigBaseline(cfg, canonical); err != nil {
		return withExitCode(ExitConflict, "canonical config changed while rm was waiting for the state lock: %v", err)
	}
	if needsSigning {
		if err := requireRepositorySigningKeyIdentity(cfg, privateKey, repositoryKeySHA); err != nil {
			return withExitCode(ExitConflict, "repository signing key changed while rm was acquiring canonical state: %v", err)
		}
	}
	txDir, err := newTransactionDir(cfg.StatePath(), "rm-")
	if err != nil {
		return withExitCode(ExitInternal, "create rm transaction: %v", err)
	}
	defer os.RemoveAll(txDir)
	staged := make(map[string]string)
	var updates []state.RefUpdate
	candidateLeaves := make(map[string]viewLeaf)
	materializeLeaves := make(map[string]viewLeaf)
	var removed int64
	var foundRefs int
	var assetMutations []assetRemovalMutation
	var packageMutations int
	var packageProjectionMutations []packageProjectionMutation
	packageFamilies := make(map[string]struct{})
	for _, leaf := range selectedLeaves(repos, values) {
		if !viewIncludesRepo(viewConfig, leaf.repo.ID) {
			continue
		}
		viewRef, err := state.ViewRef(*viewName, leaf.repo.ID, leaf.os, leaf.arch)
		if err != nil {
			return withExitCode(ExitInternal, "%v", err)
		}
		expected, exists, err := canonical.Ref(viewRef)
		if err != nil {
			return withExitCode(ExitInternal, "read %s: %v", viewRef, err)
		}
		if !exists {
			continue
		}
		foundRefs++
		leafKey := strings.Join([]string{leaf.repo.ID, leaf.os, leaf.arch}, "\x00")
		candidateLeaves[leafKey] = leaf
		viewPath, err := state.ViewPath(*viewName, leaf.repo.ID, leaf.os, leaf.arch)
		if err != nil {
			return withExitCode(ExitInternal, "%v", err)
		}
		paths, err := collectRemovalPaths(canonical, expected, viewPath, leaf, selectors, viewConfig.Access == "public")
		if err != nil {
			return withExitCode(ExitVerification, "scan %s: %v", viewRef, err)
		}
		if len(paths) == 0 {
			continue
		}
		existing, err := canonical.OpenPathAt(expected, viewPath)
		if err != nil {
			return withExitCode(ExitInternal, "%v", err)
		}
		stage, err := os.CreateTemp(txDir, "remove-view-*.tsv")
		if err != nil {
			existing.Close()
			return withExitCode(ExitInternal, "%v", err)
		}
		stats, mutationErr := views.Mutate(existing, stage, views.Mutation{RemovePaths: paths, Public: viewConfig.Access == "public"})
		closeErr := errors.Join(existing.Close(), stage.Sync(), stage.Close())
		if mutationErr != nil || closeErr != nil {
			return withExitCode(ExitConflict, "remove from %s: %v", viewRef, errors.Join(mutationErr, closeErr))
		}
		if stats.Removed == 0 {
			continue
		}
		staged[viewPath] = stage.Name()
		updates = append(updates, state.RefUpdate{Name: viewRef, Expected: expected})
		removed += stats.Removed
		materializeLeaves[leafKey] = leaf
		if leaf.repo.Type == "asset" {
			assetMutations = append(assetMutations, assetRemovalMutation{leaf: leaf, viewPath: viewPath, viewRef: viewRef, expected: expected})
		} else {
			packageMutations++
			packageFamilies[leaf.repo.Type] = struct{}{}
			packageProjectionMutations = append(packageProjectionMutations, packageProjectionMutation{
				leaf: leaf, view: *viewName, viewPath: viewPath, viewRef: viewRef.String(), expected: expected.String(),
			})
		}
	}
	if foundRefs == 0 {
		return withExitCode(ExitConfig, "selectors matched no %s view refs", *viewName)
	}
	if len(assetMutations) > 1 || len(assetMutations) != 0 && packageMutations != 0 {
		return withExitCode(ExitConflict, "asset removal must mutate exactly one asset repository and no package repository per transaction")
	}
	assetMutation := len(assetMutations) == 1
	if assetMutation {
		// The asset bridge and its selected set carry no package-signing trust.
		// Even if broad CLI selectors also named an unchanged package repo, the
		// canonical mutation and physical transaction are asset-only.
		needsSigning = false
		values.materializeTrust, err = captureMaterializationTrust(cfg, []viewLeaf{assetMutations[0].leaf}, nil, "")
		if err != nil {
			return withExitCode(ExitConflict, "capture asset removal materialization trust: %v", err)
		}
		values.materializeOperation = "rm"
	}
	pool, err := repository.NewStore(cfg.Root)
	if err != nil {
		return withExitCode(ExitInternal, "open CAS: %v", err)
	}
	if needsSigning {
		trustLeaves := sortedRemovalLeaves(candidateLeaves)
		values.materializeTrust, err = captureMaterializationTrust(cfg, trustLeaves, privateKey, repositoryKeySHA)
		if err != nil {
			return withExitCode(ExitConflict, "capture removal materialization trust before canonical commit: %v", err)
		}
		values.materializeOperation = "rm"
	}
	if removed == 0 && needsSigning && removalLeavesArePackages(candidateLeaves) {
		ready, readyErr := packageMaterializationReceiptsReady(ctx, cfg, canonical, pool, *viewName, sortedRemovalLeaves(candidateLeaves), values, values.materializeTrust)
		if readyErr != nil {
			return withExitCode(ExitVerification, "verify unchanged removal materialization readiness: %v", readyErr)
		}
		if ready {
			fmt.Fprintf(stdout, "rm unchanged view=%s selectors=%d packages=0 physical=no-op\n", *viewName, len(selectors))
			return nil
		}
	}
	source := materializeCanonicalSource{ID: *viewName, Public: viewConfig.Access == "public"}
	var projectionIntent *assetProjectionIntent
	var packageIntent *packageProjectionIntent
	if removed == 0 {
		materializeLeaves = candidateLeaves
	}
	if needsSigning {
		closed, closeErr := packageMaterializationPhysicalClosureLeaves(cfg, canonical, source, sortedRemovalLeaves(materializeLeaves))
		if closeErr != nil {
			return withExitCode(ExitConflict, "close removal physical owners: %v", closeErr)
		}
		materializeLeaves = removalLeafMap(closed)
	}
	if removed == 0 {
		fmt.Fprintf(stdout, "rm unchanged view=%s selectors=%d repair=materialization\n", *viewName, len(selectors))
	} else {
		if err := requireNoMaterializationIntentBeforeCanonicalMutation(cfg); err != nil {
			return withExitCode(ExitConflict, "%v", err)
		}
		if needsSigning {
			if err := requireRepositorySigningKeyIdentity(cfg, privateKey, repositoryKeySHA); err != nil {
				return withExitCode(ExitConflict, "repository signing key changed before removal commit: %v", err)
			}
		}
		canonicalConfig, configHash, err := stageCanonicalConfig(cfg, txDir)
		if err != nil {
			return withExitCode(ExitInternal, "stage canonical config: %v", err)
		}
		staged["config/sow.yaml"] = canonicalConfig
		message := "sow rm: " + *viewName
		applyOptions := state.ApplyOptions{}
		if assetMutation {
			mutation := assetMutations[0]
			intent, durableStage, intentErr := prepareAssetProjectionIntent(cfg, canonical, "rm", "", mutation.leaf.repo, *viewName, mutation.viewPath, mutation.viewRef, mutation.expected, staged[mutation.viewPath], nil)
			if intentErr != nil {
				return withExitCode(ExitConflict, "persist pending asset removal projection before canonical mutation: %v", intentErr)
			}
			projectionIntent = &intent
			staged[mutation.viewPath] = durableStage
			staged["config/sow.yaml"] = filepath.Join(cfg.StatePath(), intent.ConfigStage)
			message = intent.Message
			applyOptions.TransactionID = intent.TransactionID
			if assetProjectionMutationHook != nil {
				if hookErr := assetProjectionMutationHook("after-fence-before-apply"); hookErr != nil {
					return withExitCode(ExitConflict, "pending asset removal projection fault: %v", hookErr)
				}
				applyOptions.AfterIntent = func() error { return assetProjectionMutationHook("after-transaction-intent-before-commit") }
				applyOptions.AfterCommit = func() error { return assetProjectionMutationHook("after-canonical-commit-before-ref") }
			}
		} else if packageMutations != 0 {
			family := "mixed"
			if len(packageFamilies) == 1 {
				for value := range packageFamilies {
					family = value
				}
			}
			if err := freezePackageProjectionSigningTime(values.materializeTrust, family, privateKey, passphrase); err != nil {
				return withExitCode(ExitConflict, "validate package removal projection signing time under lock: %v", err)
			}
			intent, durable, intentErr := preparePackageProjectionIntent(cfg, canonical, "rm", family, packageProjectionMutations, staged, values.materializeTrust, privateKey, passphrase)
			if intentErr != nil {
				return withExitCode(ExitConflict, "persist pending package removal projection before canonical mutation: %v", intentErr)
			}
			packageIntent = &intent
			staged = durable
			message = intent.Message
			applyOptions.TransactionID = intent.TransactionID
			if packageProjectionMutationHook != nil {
				if hookErr := packageProjectionMutationHook("after-fence-before-apply"); hookErr != nil {
					return withExitCode(ExitConflict, "pending package removal projection fault: %v", hookErr)
				}
				applyOptions.AfterIntent = func() error { return packageProjectionMutationHook("after-transaction-intent-before-commit") }
				applyOptions.AfterCommit = func() error { return packageProjectionMutationHook("after-canonical-commit-before-ref") }
			}
		}
		commit, _, err := applyCanonicalConfig(ctx, cfg, canonical, "rm", message, staged, updates, applyOptions)
		if err != nil {
			return stateMutationError("commit removal", err)
		}
		if projectionIntent != nil && assetProjectionMutationHook != nil {
			if hookErr := assetProjectionMutationHook("after-ref-before-materialize"); hookErr != nil {
				return withExitCode(ExitConflict, "pending asset removal projection fault: %v", hookErr)
			}
		}
		if packageIntent != nil && packageProjectionMutationHook != nil {
			if hookErr := packageProjectionMutationHook("after-ref-before-materialize"); hookErr != nil {
				return withExitCode(ExitConflict, "pending package removal projection fault: %v", hookErr)
			}
		}
		if packageIntent != nil {
			defer func() {
				if resultErr == nil {
					resultErr = removePackageProjectionIntent(cfg.StatePath(), *packageIntent)
				}
			}()
		}
		fmt.Fprintf(stdout, "removed view=%s entries=%d commit=%s config_sha256=%s\n", *viewName, removed, commit, configHash)
	}
	leafKeys := make([]string, 0, len(materializeLeaves))
	for key := range materializeLeaves {
		leafKeys = append(leafKeys, key)
	}
	sort.Strings(leafKeys)
	if needsSigning {
		transactionLeaves := make([]viewLeaf, 0, len(materializeLeaves))
		for _, leaf := range materializeLeaves {
			transactionLeaves = append(transactionLeaves, leaf)
		}
		var selectionOwner bool
		var beginErr error
		values, selectionOwner, beginErr = beginMaterializationSelectionForSource(cfg, canonical, values, "rm", materializeCanonicalSource{ID: *viewName, Public: viewConfig.Access == "public"}, transactionLeaves, cfg.Root, true, false, true)
		if beginErr != nil {
			return withExitCode(ExitConflict, "begin removal selected-set materialization: %v", beginErr)
		}
		defer func() {
			resultErr = errors.Join(resultErr, finishMaterializationSelectedSet(cfg, values.materializeTrust, selectionOwner, resultErr))
		}()
	}
	materializedAPT := make(map[string]struct{})
	materializedYUM := make(map[materializedRouteOwnerID]struct{})
	materializedAsset := make(map[string]struct{})
	ledgerStages := make(map[string]string)
	exactByOwner := make(map[materializedRouteOwnerID]string)
	var byHashRemoved int
	for _, key := range leafKeys {
		leaf := materializeLeaves[key]
		switch leaf.repo.Type {
		case "asset":
			if _, done := materializedAsset[leaf.repo.ID]; done {
				continue
			}
			materialized, reconciled, err := materializeAssetView(ctx, cfg, canonical, pool, leaf.repo, *viewName, txDir, values)
			if err != nil {
				return withExitCode(ExitVerification, "materialize removal for %s: %v", leaf.repo.ID, err)
			}
			materializedAsset[leaf.repo.ID] = struct{}{}
			fmt.Fprintf(stdout, "asset tree repo=%s view=%s entries=%d pruned=%d\n", leaf.repo.ID, *viewName, materialized.Entries, reconciled.RemovedFiles)
		case "yum":
			ownerID := materializedRouteOwnerID{kind: "yum", repo: leaf.repo.ID, arch: leaf.arch}
			if _, done := materializedYUM[ownerID]; done {
				continue
			}
			ownerLeaves := removalYUMOwnerLeaves(materializeLeaves, leaf.repo.ID, leaf.arch)
			if err := runPackageMaterializationHook(ctx, packageMaterializationInvocation{Kind: "yum", View: *viewName, Repo: leaf.repo.ID, OS: leaf.os, Arch: leaf.arch}); err != nil {
				return withExitCode(ExitVerification, "YUM removal materialization hook: %v", err)
			}
			if err := requireRepositorySigningKeyIdentity(cfg, privateKey, repositoryKeySHA); err != nil {
				return withExitCode(ExitConflict, "repository signing key changed before YUM removal materialization: %v", err)
			}
			result, err := materializeYUMOwner(ctx, cfg, canonical, pool, leaf.repo, ownerLeaves, *viewName, txDir, values, privateKey, passphrase)
			if err != nil {
				return withExitCode(ExitVerification, "rebuild YUM owner %s/%s: %v", leaf.repo.ID, leaf.arch, err)
			}
			if err := requireRepositorySigningKeyIdentity(cfg, privateKey, repositoryKeySHA); err != nil {
				return withExitCode(ExitConflict, "repository signing key changed during YUM removal materialization: %v", err)
			}
			materializedYUM[ownerID] = struct{}{}
			exactByOwner[ownerID] = result.ExactManifest
			fmt.Fprintf(stdout, "yum repo=%s view=%s os=%s arch=%s packages=%d repomd_sha256=%s pruned=%d\n",
				leaf.repo.ID, *viewName, removalLeafOSList(ownerLeaves), leaf.arch, result.Generation.Packages, result.Generation.RepomdSHA256, result.Reconciled.RemovedFiles)
		case "apt":
			if _, done := materializedAPT[leaf.repo.ID]; done {
				continue
			}
			if err := requireRepositorySigningKeyIdentity(cfg, privateKey, repositoryKeySHA); err != nil {
				return withExitCode(ExitConflict, "repository signing key changed before APT removal materialization: %v", err)
			}
			if err := runPackageMaterializationHook(ctx, packageMaterializationInvocation{Kind: "apt", View: *viewName, Repo: leaf.repo.ID, OS: leaf.os, Arch: leaf.arch}); err != nil {
				return withExitCode(ExitVerification, "APT removal materialization hook: %v", err)
			}
			result, err := materializeAPTRepo(ctx, cfg, canonical, pool, leaf.repo, *viewName, txDir, values, privateKey, passphrase)
			if err != nil {
				return withExitCode(ExitVerification, "rebuild APT repo %s: %v", leaf.repo.ID, err)
			}
			if err := requireRepositorySigningKeyIdentity(cfg, privateKey, repositoryKeySHA); err != nil {
				return withExitCode(ExitConflict, "repository signing key changed during APT removal materialization: %v", err)
			}
			if err := mergeAPTByHashStages(ledgerStages, result.Ledgers); err != nil {
				return withExitCode(ExitInternal, "merge APT by-hash retention stages: %v", err)
			}
			byHashRemoved += result.ByHashRemoved
			materializedAPT[leaf.repo.ID] = struct{}{}
			exactByOwner[materializedRouteOwnerID{kind: "apt", repo: leaf.repo.ID, arch: "all"}] = result.ExactManifest
			fmt.Fprintf(stdout, "apt repo=%s view=%s suites=%d pruned=%d\n", leaf.repo.ID, *viewName, len(result.Builds), result.Reconciled.RemovedFiles)
		default:
			return withExitCode(ExitInternal, "unsupported repository type %q", leaf.repo.Type)
		}
	}
	if len(ledgerStages) != 0 {
		ledgerCommit, ledgerChanged, err := persistAPTByHashStages(ctx, canonical, "rm", ledgerStages)
		if err != nil {
			return stateMutationError("commit APT by-hash retention", err)
		}
		fmt.Fprintf(stdout, "apt by-hash retained=%d removed=%d commit=%s changed=%t\n", cfg.State.APTByHashRetention, byHashRemoved, ledgerCommit, ledgerChanged)
	}
	if needsSigning && len(exactByOwner) != 0 {
		receiptCommit, receiptChanged, receipts, receiptErr := persistPackageMaterializationReceipts(ctx, cfg, canonical, pool, *viewName, sortedRemovalLeaves(materializeLeaves), exactByOwner, txDir, values, values.materializeTrust)
		if receiptErr != nil {
			return withExitCode(ExitVerification, "persist removal materialization readiness: %v", receiptErr)
		}
		fmt.Fprintf(stdout, "package materialization view=%s receipts=%d commit=%s changed=%t\n", *viewName, receipts, receiptCommit, receiptChanged)
	}
	if *viewName == "latest" {
		workingRepos := workingTreeReposFromLeaves(materializeLeaves)
		if _, _, err := refreshWorkingTreeBaselines(ctx, cfg, canonical, workingRepos, txDir, values, "rm-working-tree", state.ApplyOptions{}, stdout); err != nil {
			return stateMutationError("commit latest working tree after removal", err)
		}
	}
	if projectionIntent != nil {
		if err := removeAssetProjectionIntent(cfg.StatePath(), *projectionIntent); err != nil {
			return withExitCode(ExitConflict, "complete pending asset removal projection: %v", err)
		}
	}
	return rebuildCatalogProjection(ctx, cfg, stdout)
}

// recoverPendingAssetRemoveProjection converges the durable pre-Apply bridge
// before runRemove asks the operator for any original selector again. The
// staged canonical manifest is the removal request; inputless --recover never
// reconstructs business intent from the possibly stale physical tree.
func recoverPendingAssetRemoveProjection(ctx context.Context, cfg *config.Config, values commonFlags, inputless bool, stdout, stderr io.Writer) (recovered bool, resultErr error) {
	lock, err := state.AcquireLock(cfg.StatePath(), "rm", true)
	if err != nil {
		return false, withExitCode(ExitConflict, "%v", err)
	}
	defer propagateStateLockRelease(lock, &resultErr, stderr)
	if err := requireNoForeignMaterializationIntent(cfg, "rm", true); err != nil {
		return false, withExitCode(ExitConflict, "durable materialization intent: %v", err)
	}
	canonical := state.New(cfg.StatePath())
	if err := requireProjectionTransactionsCompatibleBeforeRecovery(cfg, canonical, "rm"); err != nil {
		return false, withExitCode(ExitConflict, "asset rm recovery transaction preflight: %v", err)
	}
	if err := preflightPendingAssetProjection(cfg, canonical, "rm"); err != nil {
		return false, withExitCode(ExitConflict, "asset rm recovery projection preflight: %v", err)
	}
	if err := prepareCanonicalState(ctx, canonical, true, stdout); err != nil {
		return false, err
	}
	if err := requireCanonicalConfigBaseline(cfg, canonical); err != nil {
		return false, withExitCode(ExitConflict, "canonical config changed while rm recovery was waiting for the state lock: %v", err)
	}
	recovered, err = recoverPendingAssetProjectionLocked(ctx, cfg, canonical, values, "rm", stdout)
	if err != nil {
		return false, withExitCode(ExitVerification, "recover asset removal materialization: %v", err)
	}
	if inputless && !recovered {
		if _, exists, readErr := readMaterializationSelectionJournal(cfg.StatePath()); readErr != nil {
			return false, withExitCode(ExitConflict, "read rm materialization recovery intent: %v", readErr)
		} else if exists {
			return false, withExitCode(ExitConflict, "inputless rm recovery has no exact asset projection bridge")
		}
	}
	return recovered, nil
}

func sortedRemovalLeaves(leaves map[string]viewLeaf) []viewLeaf {
	result := make([]viewLeaf, 0, len(leaves))
	for _, leaf := range leaves {
		result = append(result, leaf)
	}
	sort.Slice(result, func(i, j int) bool {
		left := strings.Join([]string{result[i].repo.ID, result[i].os, result[i].arch}, "\x00")
		right := strings.Join([]string{result[j].repo.ID, result[j].os, result[j].arch}, "\x00")
		return left < right
	})
	return result
}

func removalLeafMap(leaves []viewLeaf) map[string]viewLeaf {
	result := make(map[string]viewLeaf, len(leaves))
	for _, leaf := range leaves {
		result[strings.Join([]string{leaf.repo.ID, leaf.os, leaf.arch}, "\x00")] = leaf
	}
	return result
}

func removalLeavesArePackages(leaves map[string]viewLeaf) bool {
	if len(leaves) == 0 {
		return false
	}
	for _, leaf := range leaves {
		if leaf.repo.Type != "apt" && leaf.repo.Type != "yum" {
			return false
		}
	}
	return true
}

func removalYUMOwnerLeaves(leaves map[string]viewLeaf, repoID, arch string) []viewLeaf {
	var result []viewLeaf
	for _, leaf := range leaves {
		if leaf.repo.Type == "yum" && leaf.repo.ID == repoID && leaf.arch == arch {
			result = append(result, leaf)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].os < result[j].os })
	return result
}

func removalLeafOSList(leaves []viewLeaf) string {
	values := make([]string, 0, len(leaves))
	for _, leaf := range leaves {
		values = append(values, leaf.os)
	}
	return strings.Join(values, ",")
}

// splitFlagDelimiter removes the first conventional option delimiter from an
// rm flag tail. Values after it are business selectors and must never be fed
// back to flag.Parse, even when they begin with a dash.
func splitFlagDelimiter(fs *flag.FlagSet, args []string) (parseArgs, literals []string) {
	expectsValue := false
	for index, argument := range args {
		if expectsValue {
			expectsValue = false
			continue
		}
		if argument == "--" {
			return append([]string(nil), args[:index]...), append([]string(nil), args[index+1:]...)
		}
		if !strings.HasPrefix(argument, "-") || argument == "-" {
			continue
		}
		name := strings.TrimPrefix(strings.TrimPrefix(argument, "-"), "-")
		if _, _, assigned := strings.Cut(name, "="); assigned {
			continue
		}
		registered := fs.Lookup(name)
		if registered == nil {
			continue
		}
		boolean, isBoolean := registered.Value.(interface{ IsBoolFlag() bool })
		expectsValue = !isBoolean || !boolean.IsBoolFlag()
	}
	return append([]string(nil), args...), nil
}

func collectRemovalPaths(canonical *state.Store, commit plumbing.Hash, viewPath string, leaf viewLeaf, selectors []string, public bool) ([]string, error) {
	reader, err := canonical.OpenPathAt(commit, viewPath)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	viewReader := views.NewReader(reader)
	var matches []string
	for {
		entry, err := viewReader.Next()
		if errors.Is(err, io.EOF) {
			return matches, nil
		}
		if err != nil {
			return nil, err
		}
		if entry.Repo != leaf.repo.ID || entry.OS != leaf.os || entry.Arch != leaf.arch {
			return nil, fmt.Errorf("view leaf contains cross-leaf entry %s/%s/%s", entry.Repo, entry.OS, entry.Arch)
		}
		if public && entry.Pool != "public" {
			return nil, fmt.Errorf("confidentiality closure violation: public view references gated path %s", entry.Path)
		}
		if leaf.repo.Type == "asset" {
			if err := validateAssetProjectionPath(leaf.repo, entry.Path); err != nil {
				return nil, err
			}
		}
		for _, selector := range selectors {
			if selector == entry.Path || selector == strings.TrimPrefix(entry.Path, leaf.repo.Path+"/") || selector == entry.Name {
				matches = append(matches, entry.Path)
				break
			}
		}
	}
}
