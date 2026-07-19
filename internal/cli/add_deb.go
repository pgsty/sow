package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

type debInputPlan struct {
	input    string
	snapshot string
	info     aptrepo.Package
	repo     config.Repo
	suite    string
	arches   []string
}

type debLeafPlan = packageAddLeafPlan

// runAddDEB adopts existing Debian binary packages. It deliberately refuses
// to guess when repository, component, suite, or architecture selection is
// ambiguous: a wrong guess would create a durable but misleading APT index.
func runAddDEB(ctx context.Context, cfg *config.Config, selected []config.Repo, inputs []string, values commonFlags, componentFlag, privateKeyFile, passphraseFile string, stdout, stderr io.Writer) error {
	return runAddDEBExpected(ctx, cfg, selected, inputs, nil, values, componentFlag, privateKeyFile, passphraseFile, stdout, stderr)
}

func runAddDEBExpected(ctx context.Context, cfg *config.Config, selected []config.Repo, inputs []string, expected map[string]repository.Object, values commonFlags, componentFlag, privateKeyFile, passphraseFile string, stdout, stderr io.Writer) (resultErr error) {
	inputDir, err := os.MkdirTemp("", "sow-add-deb-input-")
	if err != nil {
		return withExitCode(ExitInternal, "create private DEB input snapshot: %v", err)
	}
	defer os.RemoveAll(inputDir)
	plans := make([]debInputPlan, 0, len(inputs))
	for index, input := range inputs {
		snapshot, err := snapshotDEBInput(ctx, input, inputDir, index)
		if err != nil {
			return withExitCode(ExitConflict, "snapshot DEB %s: %v", input, err)
		}
		var candidates []debInputPlan
		for _, repo := range selected {
			if repo.Type != "apt" || repo.APT == nil {
				continue
			}
			component, ok, err := resolveAPTComponent(repo, input, componentFlag)
			if err != nil {
				return withExitCode(ExitConfig, "%v", err)
			}
			if !ok {
				continue
			}
			info, err := aptrepo.InspectPackageAs(ctx, snapshot, component, filepath.Base(input))
			if err != nil {
				return withExitCode(ExitConflict, "inspect DEB %s: %v", input, err)
			}
			// Preserve the operator-visible source coordinate for suite inference
			// and diagnostics. The private snapshot remains the only coordinate
			// ever admitted to CAS.
			info.SourcePath = input
			if err := verifyExpectedPackageInput(values, input, info.SHA256, info.Size, expected); err != nil {
				return withExitCode(ExitVerification, "%v", err)
			}
			arches := debLeafArches(repo, info.Architecture, values.arches.values())
			if len(arches) == 0 {
				continue
			}
			for _, suite := range debSuiteCandidates(repo, info, values.oses.values()) {
				if !repo.APT.HasComponent(suite, component) {
					continue
				}
				candidates = append(candidates, debInputPlan{input: input, snapshot: snapshot, info: info, repo: repo, suite: suite, arches: arches})
			}
		}
		if len(candidates) != 1 {
			labels := make([]string, 0, len(candidates))
			for _, candidate := range candidates {
				labels = append(labels, candidate.repo.ID+"/"+candidate.suite)
			}
			sort.Strings(labels)
			return withExitCode(ExitConfig, "DEB %s must match exactly one APT repo/suite after component, OS, and arch selection; matched [%s]", path.Base(input), strings.Join(labels, ","))
		}
		if candidates[0].repo.LifecycleForSuite(candidates[0].suite) == "frozen" {
			return withExitCode(ExitConflict, "repo %s suite %s is frozen; new DEB content is forbidden", candidates[0].repo.ID, candidates[0].suite)
		}
		plans = append(plans, candidates[0])
	}
	groups, err := planDEBLeafGroups(plans)
	if err != nil {
		return withExitCode(ExitConflict, "plan DEB add: %v", err)
	}

	privateKey, err := resolveSecret(cfg.GPG.PrivateKey, privateKeyFile, false)
	if err != nil {
		return withExitCode(ExitConfig, "resolve OpenPGP private key: %v", err)
	}
	defer clearSecret(privateKey)
	passphrase, err := resolveSecret(cfg.GPG.Passphrase, passphraseFile, true)
	if err != nil {
		return withExitCode(ExitConfig, "resolve OpenPGP passphrase: %v", err)
	}
	defer clearSecret(passphrase)
	verificationTime, observedProjectionID, err := packageAddSigningVerificationTime(cfg, values, "apt")
	if err != nil {
		return withExitCode(ExitConflict, "DEB package projection recovery time: %v", err)
	}
	repositoryKeySHA, err := repositorySigningKeyIdentityAt(cfg, privateKey, verificationTime)
	if err != nil {
		return withExitCode(ExitConfig, "repository signing trust preflight failed: %v", err)
	}
	signer, err := aptrepo.NewSigner(bytes.NewReader(privateKey), passphrase)
	if err != nil || signer.Validate(verificationTime) != nil {
		return withExitCode(ExitConfig, "OpenPGP signing preflight failed")
	}
	materializationOperation := "add"
	if values.syncInternal {
		materializationOperation = "sync"
	}

	lock, err := state.AcquireLock(cfg.StatePath(), "add", values.recover)
	if err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	defer propagateStateLockRelease(lock, &resultErr, stderr)
	if err := requireNoForeignMaterializationIntent(cfg, materializationOperation, values.recover); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	if err := requirePackageAddRecoveryFamilyBeforePrepare(cfg, values, "apt"); err != nil {
		return withExitCode(ExitConflict, "DEB add recovery admission: %v", err)
	}
	canonical := state.New(cfg.StatePath())
	recoveryProjection, err := preflightPositionalPackageProjection(cfg, canonical, values, "apt", privateKey, repositoryKeySHA, groups)
	if err != nil {
		return withExitCode(ExitConflict, "DEB package projection recovery preflight: %v", err)
	}
	if observedProjectionID != "" && (recoveryProjection == nil || recoveryProjection.ID != observedProjectionID) {
		return withExitCode(ExitConflict, "DEB package projection changed while waiting for the state lock")
	}
	if recoveryProjection != nil {
		recoveryPool, err := repository.NewStore(cfg.Root)
		if err != nil {
			return withExitCode(ExitConflict, "open CAS for exact DEB recovery: %v", err)
		}
		for _, plan := range plans {
			digest, err := repository.ParseDigest(plan.info.SHA256)
			if err != nil {
				return withExitCode(ExitInternal, "parse inspected DEB recovery digest %s: %v", plan.input, err)
			}
			wanted := repository.Object{SHA256: digest, Size: plan.info.Size}
			if object, err := recoveryPool.ImportExpected(ctx, plan.snapshot, wanted); err != nil || object != wanted {
				return withExitCode(ExitConflict, "repair exact DEB recovery object %s: %v", plan.input, err)
			}
		}
	}
	if err := prepareCanonicalState(ctx, canonical, values.recover, stdout); err != nil {
		return err
	}
	if recoveryProjection != nil {
		if _, err := ensurePackageProjectionCanonical(ctx, cfg, canonical, *recoveryProjection); err != nil {
			return withExitCode(ExitConflict, "recover DEB package projection canonical state: %v", err)
		}
	}
	if !values.syncInternal {
		if err := requireCanonicalConfigBaseline(cfg, canonical); err != nil {
			return withExitCode(ExitConflict, "canonical config changed while DEB add was waiting for the state lock: %v", err)
		}
	} else if err := validateCanonicalHistoryContracts(cfg); err != nil {
		return withExitCode(ExitConflict, "repository history contract changed while DEB sync was waiting for the state lock: %v", err)
	}
	if values.syncInternal {
		if len(selected) != 1 || values.syncUpstreamContract == nil {
			return withExitCode(ExitInternal, "internal DEB sync contract is incomplete")
		}
		if _, err := validateCanonicalSyncContract(canonical, cfg, selected[0], *values.syncUpstreamContract, values.syncSelectionSHA256); err != nil {
			return withExitCode(ExitConflict, "canonical DEB sync contract changed: %v", err)
		}
	}
	if err := requireRepositorySigningKeyIdentityAt(cfg, privateKey, repositoryKeySHA, verificationTime); err != nil {
		return withExitCode(ExitConflict, "repository signing key changed while DEB add was acquiring canonical state: %v", err)
	}
	trustLeaves := make([]viewLeaf, 0, len(plans))
	trustLeafSeen := make(map[string]struct{})
	for _, plan := range plans {
		for _, arch := range plan.arches {
			key := strings.Join([]string{plan.repo.ID, plan.suite, arch}, "\x00")
			if _, exists := trustLeafSeen[key]; exists {
				continue
			}
			trustLeafSeen[key] = struct{}{}
			trustLeaves = append(trustLeaves, viewLeaf{repo: plan.repo, os: plan.suite, arch: arch})
		}
	}
	values.materializeTrust, err = captureMaterializationTrustAt(cfg, trustLeaves, privateKey, repositoryKeySHA, verificationTime)
	if err != nil {
		return withExitCode(ExitConflict, "capture DEB materialization trust after acquiring canonical state: %v", err)
	}
	if recoveryProjection != nil {
		if err := bindPackageProjectionSigningTime(values.materializeTrust, *recoveryProjection); err != nil {
			return withExitCode(ExitConflict, "restore DEB projection signing time: %v", err)
		}
	}
	values.materializeOperation = materializationOperation
	if values.syncInternal {
		values.materializeScope = syncMaterializationScope(values.syncUpstreamContract.ID, values.syncSelectionSHA256)
	}
	requests, err := packageAddMaterializationRequests(cfg, groups)
	if err != nil {
		return withExitCode(ExitInternal, "plan DEB materialization: %v", err)
	}
	requests, err = packageMaterializationPhysicalClosureRequests(cfg, canonical, requests)
	if err != nil {
		return withExitCode(ExitConflict, "close DEB physical owners: %v", err)
	}
	if err := requireExactPackageAddRecoveryBeforeCAS(cfg, canonical, values, "apt", requests, groups); err != nil {
		return withExitCode(ExitConflict, "DEB add recovery admission before CAS: %v", err)
	}
	if recoveryProjection != nil {
		defer func() {
			if resultErr == nil {
				resultErr = removePackageProjectionIntent(cfg.StatePath(), *recoveryProjection)
			}
		}()
	}
	txDir, err := newTransactionDir(cfg.StatePath(), "add-deb-")
	if err != nil {
		return withExitCode(ExitInternal, "create DEB add transaction: %v", err)
	}
	defer os.RemoveAll(txDir)
	pool, err := repository.NewStore(cfg.Root)
	if err != nil {
		return withExitCode(ExitConflict, "open CAS: %v", err)
	}

	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	staged := make(map[string]string)
	var updates []state.RefUpdate
	var projectionMutations []packageProjectionMutation
	var added, unchanged int64
	for _, key := range keys {
		group := groups[key]
		sort.Slice(group.entries, func(i, j int) bool { return group.entries[i].Path < group.entries[j].Path })
		viewConfig := cfg.Views[group.view]
		viewPath, err := state.ViewPath(group.view, group.repo.ID, group.leaf.os, group.leaf.arch)
		if err != nil {
			return withExitCode(ExitInternal, "%v", err)
		}
		viewRef, err := state.ViewRef(group.view, group.repo.ID, group.leaf.os, group.leaf.arch)
		if err != nil {
			return withExitCode(ExitInternal, "%v", err)
		}
		expected, exists, err := canonical.Ref(viewRef)
		if err != nil {
			return withExitCode(ExitInternal, "read %s: %v", viewRef, err)
		}
		if exists {
			if err := validateViewAt(canonical, expected, viewPath, group.leaf, viewConfig.Access == "public"); err != nil {
				return withExitCode(ExitVerification, "validate %s: %v", viewRef, err)
			}
		}
		existing, err := openViewAt(canonical, expected, viewPath, exists)
		if err != nil {
			return withExitCode(ExitInternal, "%v", err)
		}
		stage, err := os.CreateTemp(txDir, "deb-view-*.tsv")
		if err != nil {
			existing.Close()
			return withExitCode(ExitInternal, "%v", err)
		}
		stats, mutationErr := views.Mutate(existing, stage, views.Mutation{
			Upserts: group.entries, AppendOnly: viewConfig.AppendOnly, Public: viewConfig.Access == "public",
		})
		closeErr := errors.Join(existing.Close(), stage.Sync(), stage.Close())
		if mutationErr != nil || closeErr != nil {
			return withExitCode(ExitConflict, "update %s: %v", viewRef, errors.Join(mutationErr, closeErr))
		}
		added += stats.Added
		unchanged += stats.Unchanged
		if stats.Changed() {
			staged[viewPath] = stage.Name()
			updates = append(updates, state.RefUpdate{Name: viewRef, Expected: expected})
			projectionMutations = append(projectionMutations, packageProjectionMutation{
				leaf: group.leaf, view: group.view, viewPath: viewPath, viewRef: viewRef.String(), expected: expected.String(),
			})
		}
	}

	commit := debStateCommit(canonical, groups)
	recoveryJournal := false
	if !values.syncInternal {
		_, recoveryJournal, err = readMaterializationSelectionJournal(cfg.StatePath())
		if err != nil {
			return withExitCode(ExitConflict, "read DEB add recovery intent: %v", err)
		}
	}
	if len(staged) == 0 && !values.syncInternal && !recoveryJournal {
		ready, readyErr := packageMaterializationRequestsReady(ctx, cfg, canonical, pool, requests, values, values.materializeTrust)
		if readyErr != nil {
			return withExitCode(ExitVerification, "verify unchanged DEB materialization readiness: %v", readyErr)
		}
		if ready {
			fmt.Fprintf(stdout, "add unchanged format=deb packages=%d leaves=%d commit=%s physical=no-op\n", unchanged, len(groups), commit)
			return nil
		}
	}
	for _, plan := range plans {
		digest, err := repository.ParseDigest(plan.info.SHA256)
		if err != nil {
			return withExitCode(ExitInternal, "parse inspected DEB digest %s: %v", plan.input, err)
		}
		expectedObject := repository.Object{SHA256: digest, Size: plan.info.Size}
		// Stage and compare the stable input with its inspected identity before
		// installation so a post-admission path swap cannot create a novel CAS
		// orphan even though the add itself fails closed. A receipt-proven no-op
		// returns above without reopening or mutating CAS.
		object, err := pool.ImportExpected(ctx, plan.snapshot, expectedObject)
		if err != nil {
			return withExitCode(ExitConflict, "import DEB %s: %v", plan.input, err)
		}
		if object != expectedObject {
			return withExitCode(ExitInternal, "DEB %s expected import returned the wrong object", plan.input)
		}
	}
	var projectionIntent *packageProjectionIntent
	if len(staged) > 0 {
		if err := requireNoMaterializationIntentBeforeCanonicalMutation(cfg); err != nil {
			return withExitCode(ExitConflict, "%v", err)
		}
		if err := requireRepositorySigningKeyIdentityAt(cfg, privateKey, repositoryKeySHA, verificationTime); err != nil {
			return withExitCode(ExitConflict, "repository signing key changed before DEB view commit: %v", err)
		}
		var configHash string
		applyOptions := state.ApplyOptions{}
		message := "sow add DEB"
		if !values.syncInternal {
			if err := freezePackageProjectionSigningTime(values.materializeTrust, "apt", privateKey, passphrase); err != nil {
				return withExitCode(ExitConflict, "validate DEB projection signing time under lock: %v", err)
			}
			intent, durable, intentErr := preparePackageProjectionIntent(cfg, canonical, "add", "apt", projectionMutations, staged, values.materializeTrust, privateKey, passphrase)
			if intentErr != nil {
				return withExitCode(ExitConflict, "persist pending DEB projection before canonical mutation: %v", intentErr)
			}
			projectionIntent = &intent
			staged = durable
			message = intent.Message
			applyOptions.TransactionID = intent.TransactionID
			if packageProjectionMutationHook != nil {
				if hookErr := packageProjectionMutationHook("after-fence-before-apply"); hookErr != nil {
					return withExitCode(ExitConflict, "pending DEB projection fault: %v", hookErr)
				}
				applyOptions.AfterIntent = func() error { return packageProjectionMutationHook("after-transaction-intent-before-commit") }
				applyOptions.AfterCommit = func() error { return packageProjectionMutationHook("after-canonical-commit-before-ref") }
			}
		}
		if values.syncInternal {
			configHash, _, err = canonicalConfigFileIdentity(canonical)
			if err != nil {
				return withExitCode(ExitVerification, "hash preserved canonical sync config: %v", err)
			}
			commit, _, err = applyCanonicalState(ctx, canonical, "add", message, staged, updates, applyOptions)
		} else {
			configHash = projectionIntent.ConfigSHA256
			commit, _, err = applyCanonicalConfig(ctx, cfg, canonical, "add", message, staged, updates, applyOptions)
		}
		if err != nil {
			return stateMutationError("commit DEB add", err)
		}
		if projectionIntent != nil && packageProjectionMutationHook != nil {
			if hookErr := packageProjectionMutationHook("after-ref-before-materialize"); hookErr != nil {
				return withExitCode(ExitConflict, "pending DEB projection fault: %v", hookErr)
			}
		}
		if projectionIntent != nil {
			defer func() {
				if resultErr == nil {
					resultErr = removePackageProjectionIntent(cfg.StatePath(), *projectionIntent)
				}
			}()
		}
		fmt.Fprintf(stdout, "added format=deb packages=%d leaves=%d commit=%s config_sha256=%s\n", added, len(groups), commit, configHash)
	} else {
		fmt.Fprintf(stdout, "add unchanged format=deb packages=%d leaves=%d commit=%s repair=materialization\n", unchanged, len(groups), commit)
	}

	materializations := make(map[string]*debLeafPlan)
	for _, group := range groups {
		materializations[group.repo.ID+"\x00"+group.view] = group
	}
	materializationKeys := make([]string, 0, len(materializations))
	for key := range materializations {
		materializationKeys = append(materializationKeys, key)
	}
	sort.Strings(materializationKeys)
	values, selectionOwner, err := beginMaterializationSelectionForRequests(cfg, canonical, values, selectedMaterializationOperation(values, "add"), requests)
	if err != nil {
		return withExitCode(ExitConflict, "begin DEB selected-set materialization: %v", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, finishMaterializationSelectedSet(cfg, values.materializeTrust, selectionOwner, resultErr))
	}()
	ledgerStages := make(map[string]string)
	exactByView := make(map[string]map[materializedRouteOwnerID]string)
	var byHashRemoved int
	for _, key := range materializationKeys {
		group := materializations[key]
		if err := runPackageMaterializationHook(ctx, packageMaterializationInvocation{Kind: "apt", View: group.view, Repo: group.repo.ID, OS: group.leaf.os, Arch: group.leaf.arch}); err != nil {
			return withExitCode(ExitVerification, "APT materialization hook: %v", err)
		}
		if err := requireRepositorySigningKeyIdentityAt(cfg, privateKey, repositoryKeySHA, packageProjectionMaterializationTime(values, verificationTime)); err != nil {
			return withExitCode(ExitConflict, "repository signing key changed before APT materialization: %v", err)
		}
		result, err := materializeAPTRepo(ctx, cfg, canonical, pool, group.repo, group.view, txDir, values, privateKey, passphrase)
		if err != nil {
			return withExitCode(ExitVerification, "build APT repo %s: %v", group.repo.ID, err)
		}
		if err := requireRepositorySigningKeyIdentityAt(cfg, privateKey, repositoryKeySHA, packageProjectionMaterializationTime(values, verificationTime)); err != nil {
			return withExitCode(ExitConflict, "repository signing key changed during APT materialization: %v", err)
		}
		if err := mergeAPTByHashStages(ledgerStages, result.Ledgers); err != nil {
			return withExitCode(ExitInternal, "merge APT by-hash retention stages: %v", err)
		}
		byHashRemoved += result.ByHashRemoved
		if exactByView[group.view] == nil {
			exactByView[group.view] = make(map[materializedRouteOwnerID]string)
		}
		exactByView[group.view][materializedRouteOwnerID{kind: "apt", repo: group.repo.ID, arch: "all"}] = result.ExactManifest
		suites := make([]string, 0, len(result.Builds))
		for suite := range result.Builds {
			suites = append(suites, suite)
		}
		sort.Strings(suites)
		for _, suite := range suites {
			build := result.Builds[suite]
			fmt.Fprintf(stdout, "apt repo=%s view=%s suite=%s artifacts=%d release=%s inrelease=%s pruned=%d\n",
				group.repo.ID, group.view, suite, len(build.Artifacts), build.ReleasePath, build.InReleasePath, result.Reconciled.RemovedFiles)
		}
	}
	ledgerCommit, ledgerChanged, err := persistAPTByHashStages(ctx, canonical, "add", ledgerStages)
	if err != nil {
		return stateMutationError("commit APT by-hash retention", err)
	}
	fmt.Fprintf(stdout, "apt by-hash retained=%d removed=%d commit=%s changed=%t\n", cfg.State.APTByHashRetention, byHashRemoved, ledgerCommit, ledgerChanged)
	leavesByView := packageMaterializationLeavesByView(requests)
	viewNames := make([]string, 0, len(exactByView))
	for viewName := range exactByView {
		viewNames = append(viewNames, viewName)
	}
	sort.Strings(viewNames)
	for _, viewName := range viewNames {
		receiptCommit, receiptChanged, receipts, err := persistPackageMaterializationReceipts(ctx, cfg, canonical, pool, viewName, leavesByView[viewName], exactByView[viewName], txDir, values, values.materializeTrust)
		if err != nil {
			return withExitCode(ExitVerification, "persist DEB materialization readiness: %v", err)
		}
		fmt.Fprintf(stdout, "package materialization view=%s kind=apt receipts=%d commit=%s changed=%t\n", viewName, receipts, receiptCommit, receiptChanged)
	}
	return nil
}

func planDEBLeafGroups(plans []debInputPlan) (map[string]*debLeafPlan, error) {
	groups := make(map[string]*debLeafPlan)
	for _, plan := range plans {
		debugInfo := isDebugDEB(plan.info.Name)
		viewName := packageDestinationView(plan.repo, debugInfo)
		for _, arch := range plan.arches {
			leaf := viewLeaf{repo: plan.repo, os: plan.suite, arch: arch}
			key := strings.Join([]string{viewName, plan.repo.ID, plan.suite, arch}, "\x00")
			group := groups[key]
			if group == nil {
				group = &debLeafPlan{repo: plan.repo, leaf: leaf, view: viewName}
				groups[key] = group
			}
			entry := views.Entry{
				Repo: plan.repo.ID, OS: plan.suite, Arch: arch, Name: plan.info.Name,
				Version: plan.info.Version, Path: path.Join(plan.repo.Path, plan.info.PoolPath),
				Size: plan.info.Size, SHA256: plan.info.SHA256, Pool: plan.repo.DefaultPool, DebugInfo: debugInfo,
			}
			if err := entry.Validate(); err != nil {
				return nil, err
			}
			if err := appendUniqueDEBEntry(group, entry); err != nil {
				return nil, err
			}
		}
	}
	return groups, nil
}

func snapshotDEBInput(ctx context.Context, source, directory string, index int) (destination string, returnErr error) {
	if ctx == nil {
		return "", errors.New("nil context")
	}
	before, err := os.Lstat(source)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return "", errors.Join(err, errors.New("DEB input must be a regular non-symlink file"))
	}
	input, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer func() { returnErr = errors.Join(returnErr, input.Close()) }()
	opened, err := input.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return "", errors.Join(err, errors.New("DEB input changed while opening"))
	}
	output, err := os.CreateTemp(directory, fmt.Sprintf("%06d-*.deb", index))
	if err != nil {
		return "", err
	}
	destination = output.Name()
	keep := false
	defer func() {
		closeErr := output.Close()
		if returnErr == nil && closeErr != nil {
			returnErr = closeErr
		}
		if !keep {
			_ = os.Remove(destination)
		}
	}()
	buffer := make([]byte, 128*1024)
	written, err := io.CopyBuffer(output, &addRPMContextReader{ctx: ctx, reader: input}, buffer)
	if err != nil {
		return "", err
	}
	after, statErr := input.Stat()
	current, pathErr := os.Lstat(source)
	if statErr != nil || pathErr != nil || !os.SameFile(before, after) || !os.SameFile(before, current) ||
		written != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return "", errors.Join(statErr, pathErr, errors.New("DEB input changed while snapshotting"))
	}
	if err := output.Sync(); err != nil {
		return "", err
	}
	if err := output.Chmod(0o400); err != nil {
		return "", err
	}
	keep = true
	return destination, nil
}

func isDebugDEB(name string) bool {
	name = strings.ToLower(name)
	return strings.HasSuffix(name, "-dbgsym") || strings.HasSuffix(name, "-dbg")
}

func appendUniqueDEBEntry(group *debLeafPlan, entry views.Entry) error {
	for _, existing := range group.entries {
		if existing.Path != entry.Path {
			continue
		}
		if existing == entry {
			return nil
		}
		return fmt.Errorf("DEB pool path conflict %q", entry.Path)
	}
	group.entries = append(group.entries, entry)
	return nil
}

func resolveAPTComponent(repo config.Repo, input, explicit string) (string, bool, error) {
	if explicit != "" {
		if !contains(repo.APT.Components, explicit) {
			return "", false, nil
		}
		return explicit, true, nil
	}
	if len(repo.APT.Components) == 1 {
		return repo.APT.Components[0], true, nil
	}
	components := strings.Split(filepath.ToSlash(filepath.Clean(input)), "/")
	for index := 0; index+1 < len(components); index++ {
		if components[index] == "pool" && contains(repo.APT.Components, components[index+1]) {
			return components[index+1], true, nil
		}
	}
	return "", false, nil
}

func debLeafArches(repo config.Repo, packageArch string, selected []string) []string {
	var result []string
	for _, arch := range repo.Arches {
		if len(selected) > 0 && !contains(selected, arch) {
			continue
		}
		if packageArch == "all" || packageArch == arch {
			result = append(result, arch)
		}
	}
	return result
}

func debSuiteCandidates(repo config.Repo, pkg aptrepo.Package, selected []string) []string {
	if len(selected) > 0 {
		var result []string
		for _, suite := range repo.APT.Suites {
			if contains(selected, suite) {
				result = append(result, suite)
			}
		}
		return result
	}
	if len(repo.APT.Suites) == 1 {
		return append([]string(nil), repo.APT.Suites...)
	}
	value := strings.ToLower(pkg.Version + " " + filepath.Base(pkg.SourcePath))
	aliases := map[string][]string{
		"noble":    {"noble", "24.04", "pgdg24"},
		"jammy":    {"jammy", "22.04", "pgdg22"},
		"focal":    {"focal", "20.04", "pgdg20"},
		"bionic":   {"bionic", "18.04", "pgdg18"},
		"trixie":   {"trixie", "debian13", "pgdg13"},
		"bookworm": {"bookworm", "debian12", "pgdg12"},
		"bullseye": {"bullseye", "debian11", "pgdg11"},
	}
	var result []string
	for _, suite := range repo.APT.Suites {
		needles := append([]string{strings.ToLower(suite)}, aliases[strings.ToLower(suite)]...)
		for _, needle := range needles {
			if needle != "" && strings.Contains(value, needle) {
				result = append(result, suite)
				break
			}
		}
	}
	return result
}

func debStateCommit(canonical *state.Store, groups map[string]*debLeafPlan) plumbing.Hash {
	for _, group := range groups {
		ref, _ := state.ViewRef(group.view, group.repo.ID, group.leaf.os, group.leaf.arch)
		if hash, exists, _ := canonical.Ref(ref); exists {
			return hash
		}
	}
	return plumbing.ZeroHash
}
