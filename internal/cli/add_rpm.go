package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
	"github.com/pgsty/sow/internal/yumrepo"
)

type rpmInputPlan struct {
	input    string
	snapshot string
	info     yumrepo.PackageInfo
	repo     config.Repo
	arches   []string
}

type rpmLeafPlan = packageAddLeafPlan

type rpmMaterializationOwnerPlan struct {
	repo   config.Repo
	view   string
	arch   string
	leaves []viewLeaf
}

func runAddRPM(ctx context.Context, cfg *config.Config, selected []config.Repo, inputs []string, values commonFlags, privateKeyFile, passphraseFile string, stdout, stderr io.Writer) error {
	return runAddRPMExpected(ctx, cfg, selected, inputs, nil, values, privateKeyFile, passphraseFile, stdout, stderr)
}

func runAddRPMExpected(ctx context.Context, cfg *config.Config, selected []config.Repo, inputs []string, expected map[string]repository.Object, values commonFlags, privateKeyFile, passphraseFile string, stdout, stderr io.Writer) (resultErr error) {
	inputDir, err := os.MkdirTemp("", "sow-add-rpm-input-")
	if err != nil {
		return withExitCode(ExitInternal, "create private RPM input snapshot: %v", err)
	}
	defer os.RemoveAll(inputDir)
	plans := make([]rpmInputPlan, 0, len(inputs))
	for index, input := range inputs {
		snapshot, err := snapshotRPMInput(ctx, input, inputDir, index)
		if err != nil {
			return withExitCode(ExitConflict, "snapshot RPM %s: %v", input, err)
		}
		info, err := yumrepo.InspectPackage(ctx, yumrepo.PackageInput{Path: snapshot, Basename: path.Base(input)})
		if err != nil {
			return withExitCode(ExitConflict, "inspect RPM %s: %v", input, err)
		}
		if err := verifyExpectedPackageInput(values, input, info.SHA256, info.Size, expected); err != nil {
			return withExitCode(ExitVerification, "%v", err)
		}
		candidates, err := rpmInputCandidates(input, info, selected, values.arches.values())
		if err != nil {
			return withExitCode(ExitConfig, "infer RPM %s target: %v", path.Base(input), err)
		}
		if len(candidates) != 1 {
			var names []string
			for _, candidate := range candidates {
				names = append(names, candidate.repo.ID)
			}
			sort.Strings(names)
			return withExitCode(ExitConfig, "RPM %s (%s, release %s) must match exactly one YUM repo; matched [%s]; use --repo/--os when the RPM has no EL dist tag", path.Base(input), info.Arch, info.Release, strings.Join(names, ","))
		}
		if candidates[0].repo.OS.Lifecycle == "frozen" {
			return withExitCode(ExitConflict, "repo %s is frozen; new RPM content is forbidden", candidates[0].repo.ID)
		}
		candidate := candidates[0]
		candidate.snapshot = snapshot
		plans = append(plans, candidate)
	}
	groups, err := planRPMLeafGroups(plans)
	if err != nil {
		return withExitCode(ExitConfig, "plan RPM add: %v", err)
	}
	// Package trust is checked before the state lock, CAS import, or any view
	// mutation. A repository keyring is a public bundle and may contain old and
	// new signers during rotation; every input must verify under its target
	// repository's exact bundle.
	verificationTime, observedProjectionID, err := packageAddSigningVerificationTime(cfg, values, "yum")
	if err != nil {
		return withExitCode(ExitConflict, "RPM package projection recovery time: %v", err)
	}
	keyrings := make(map[string]openpgp.KeyRing)
	packageKeyringSHA256 := make(map[string]string)
	packageKeyringRepos := make(map[string]config.Repo)
	for index := range plans {
		plan := &plans[index]
		keyring := keyrings[plan.repo.ID]
		if keyring == nil {
			var keyringSHA256 string
			keyring, keyringSHA256, err = loadRPMPackageKeyring(cfg.Path, plan.repo.YUM.PackageKeyring)
			if err != nil || keyring == nil {
				return withExitCode(ExitConfig, "load repo %s RPM package keyring: %v", plan.repo.ID, errors.Join(err, errors.New("public package trust bundle is required")))
			}
			keyrings[plan.repo.ID] = keyring
			packageKeyringSHA256[plan.repo.ID] = keyringSHA256
			packageKeyringRepos[plan.repo.ID] = plan.repo
		}
		verifiedFile, _, err := openVerifiedRPMFile(ctx, plan.snapshot, plan.info.Size, keyring, verificationTime)
		if err != nil {
			return withExitCode(ExitVerification, "verify RPM package signature %s: %v", plan.input, err)
		}
		// Signature verification owns one stable descriptor only for the
		// duration of that proof. ImportExpected later reopens the private
		// snapshot and binds it to the inspected digest, so retaining every FD
		// across a large batch provides no safety and can exhaust process limits.
		if err := verifiedFile.Close(); err != nil {
			return withExitCode(ExitVerification, "close verified RPM package %s: %v", plan.input, err)
		}
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
	repositoryKeySHA, err := repositorySigningKeyIdentityAt(cfg, privateKey, verificationTime)
	if err != nil {
		return withExitCode(ExitConfig, "repository signing trust preflight failed: %v", err)
	}
	if _, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(privateKey), passphrase, verificationTime); err != nil {
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
	if err := requirePackageAddRecoveryFamilyBeforePrepare(cfg, values, "yum"); err != nil {
		return withExitCode(ExitConflict, "RPM add recovery admission: %v", err)
	}
	canonical := state.New(cfg.StatePath())
	recoveryProjection, err := preflightPositionalPackageProjection(cfg, canonical, values, "yum", privateKey, repositoryKeySHA, groups)
	if err != nil {
		return withExitCode(ExitConflict, "RPM package projection recovery preflight: %v", err)
	}
	if observedProjectionID != "" && (recoveryProjection == nil || recoveryProjection.ID != observedProjectionID) {
		return withExitCode(ExitConflict, "RPM package projection changed while waiting for the state lock")
	}
	if recoveryProjection != nil {
		recoveryPool, err := repository.NewStore(cfg.Root)
		if err != nil {
			return withExitCode(ExitConflict, "open CAS for exact RPM recovery: %v", err)
		}
		for _, plan := range plans {
			digest, err := repository.ParseDigest(plan.info.SHA256)
			if err != nil {
				return withExitCode(ExitInternal, "parse inspected RPM recovery digest %s: %v", plan.input, err)
			}
			wanted := repository.Object{SHA256: digest, Size: plan.info.Size}
			if object, err := recoveryPool.ImportExpected(ctx, plan.snapshot, wanted); err != nil || object != wanted {
				return withExitCode(ExitConflict, "repair exact RPM recovery object %s: %v", plan.input, err)
			}
		}
	}
	if err := prepareCanonicalState(ctx, canonical, values.recover, stdout); err != nil {
		return err
	}
	if recoveryProjection != nil {
		if _, err := ensurePackageProjectionCanonical(ctx, cfg, canonical, *recoveryProjection); err != nil {
			return withExitCode(ExitConflict, "recover RPM package projection canonical state: %v", err)
		}
	}
	if !values.syncInternal {
		if err := requireCanonicalConfigBaseline(cfg, canonical); err != nil {
			return withExitCode(ExitConflict, "canonical config changed while RPM add was waiting for the state lock: %v", err)
		}
	} else if err := validateCanonicalHistoryContracts(cfg); err != nil {
		return withExitCode(ExitConflict, "repository history contract changed while RPM sync was waiting for the state lock: %v", err)
	}
	if values.syncInternal {
		if len(selected) != 1 || values.syncUpstreamContract == nil {
			return withExitCode(ExitInternal, "internal RPM sync contract is incomplete")
		}
		if _, err := validateCanonicalSyncContract(canonical, cfg, selected[0], *values.syncUpstreamContract, values.syncSelectionSHA256); err != nil {
			return withExitCode(ExitConflict, "canonical RPM sync contract changed: %v", err)
		}
	}
	if err := requireRepositorySigningKeyIdentityAt(cfg, privateKey, repositoryKeySHA, verificationTime); err != nil {
		return withExitCode(ExitConflict, "repository signing key changed while RPM add was acquiring canonical state: %v", err)
	}
	if err := requireRPMPackageKeyringIdentities(cfg, packageKeyringRepos, packageKeyringSHA256); err != nil {
		return withExitCode(ExitConflict, "RPM package trust changed while add was acquiring canonical state: %v", err)
	}
	trustLeaves := make([]viewLeaf, 0, len(plans))
	trustLeafSeen := make(map[string]struct{})
	for _, plan := range plans {
		for _, arch := range plan.arches {
			osName := "el" + fmt.Sprint(plan.repo.OS.Major)
			key := strings.Join([]string{plan.repo.ID, osName, arch}, "\x00")
			if _, exists := trustLeafSeen[key]; exists {
				continue
			}
			trustLeafSeen[key] = struct{}{}
			trustLeaves = append(trustLeaves, viewLeaf{repo: plan.repo, os: osName, arch: arch})
		}
	}
	values.materializeTrust, err = captureMaterializationTrustAt(cfg, trustLeaves, privateKey, repositoryKeySHA, verificationTime)
	if err != nil {
		return withExitCode(ExitConflict, "capture RPM materialization trust after acquiring canonical state: %v", err)
	}
	if recoveryProjection != nil {
		if err := bindPackageProjectionSigningTime(values.materializeTrust, *recoveryProjection); err != nil {
			return withExitCode(ExitConflict, "restore RPM projection signing time: %v", err)
		}
	}
	values.materializeOperation = materializationOperation
	if values.syncInternal {
		values.materializeScope = syncMaterializationScope(values.syncUpstreamContract.ID, values.syncSelectionSHA256)
	}
	requests, err := packageAddMaterializationRequests(cfg, groups)
	if err != nil {
		return withExitCode(ExitInternal, "plan RPM materialization: %v", err)
	}
	requests, err = packageMaterializationPhysicalClosureRequests(cfg, canonical, requests)
	if err != nil {
		return withExitCode(ExitConflict, "close RPM physical owners: %v", err)
	}
	if err := requireExactPackageAddRecoveryBeforeCAS(cfg, canonical, values, "yum", requests, groups); err != nil {
		return withExitCode(ExitConflict, "RPM add recovery admission before CAS: %v", err)
	}
	if recoveryProjection != nil {
		defer func() {
			if resultErr == nil {
				resultErr = removePackageProjectionIntent(cfg.StatePath(), *recoveryProjection)
			}
		}()
	}
	txDir, err := newTransactionDir(cfg.StatePath(), "add-rpm-")
	if err != nil {
		return withExitCode(ExitInternal, "create RPM add transaction: %v", err)
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
		stage, err := os.CreateTemp(txDir, "rpm-view-*.tsv")
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
	commit := stateCommitForGroups(canonical, groups)
	configHash := ""
	recoveryJournal := false
	if !values.syncInternal {
		_, recoveryJournal, err = readMaterializationSelectionJournal(cfg.StatePath())
		if err != nil {
			return withExitCode(ExitConflict, "read RPM add recovery intent: %v", err)
		}
	}
	if len(staged) == 0 && !values.syncInternal && !recoveryJournal {
		ready, readyErr := packageMaterializationRequestsReady(ctx, cfg, canonical, pool, requests, values, values.materializeTrust)
		if readyErr != nil {
			return withExitCode(ExitVerification, "verify unchanged RPM materialization readiness: %v", readyErr)
		}
		if ready {
			fmt.Fprintf(stdout, "add unchanged format=rpm packages=%d leaves=%d commit=%s physical=no-op\n", unchanged, len(groups), commit)
			return nil
		}
	}
	for _, plan := range plans {
		digest, err := repository.ParseDigest(plan.info.SHA256)
		if err != nil {
			return withExitCode(ExitInternal, "parse inspected RPM digest %s: %v", plan.input, err)
		}
		expectedObject := repository.Object{SHA256: digest, Size: plan.info.Size}
		// ImportExpected compares the private, signature-verified snapshot with
		// the inspected identity before install. A post-proof mutation can only
		// discard its temporary object; it can never leave a novel CAS orphan. A
		// receipt-proven no-op returns above without reopening or mutating CAS.
		object, err := pool.ImportExpected(ctx, plan.snapshot, expectedObject)
		if err != nil {
			return withExitCode(ExitConflict, "import RPM %s: %v", plan.input, err)
		}
		if object != expectedObject {
			return withExitCode(ExitInternal, "RPM %s expected import returned the wrong object", plan.input)
		}
	}
	var projectionIntent *packageProjectionIntent
	if len(staged) > 0 {
		if err := requireNoMaterializationIntentBeforeCanonicalMutation(cfg); err != nil {
			return withExitCode(ExitConflict, "%v", err)
		}
		if err := requireRepositorySigningKeyIdentityAt(cfg, privateKey, repositoryKeySHA, verificationTime); err != nil {
			return withExitCode(ExitConflict, "repository signing key changed before RPM view commit: %v", err)
		}
		if err := requireRPMPackageKeyringIdentities(cfg, packageKeyringRepos, packageKeyringSHA256); err != nil {
			return withExitCode(ExitConflict, "RPM package trust changed before view commit: %v", err)
		}
		applyOptions := state.ApplyOptions{}
		message := "sow add RPM"
		if !values.syncInternal {
			if err := freezePackageProjectionSigningTime(values.materializeTrust, "yum", privateKey, passphrase); err != nil {
				return withExitCode(ExitConflict, "validate RPM projection signing time under lock: %v", err)
			}
			intent, durable, intentErr := preparePackageProjectionIntent(cfg, canonical, "add", "yum", projectionMutations, staged, values.materializeTrust, privateKey, passphrase)
			if intentErr != nil {
				return withExitCode(ExitConflict, "persist pending RPM projection before canonical mutation: %v", intentErr)
			}
			projectionIntent = &intent
			staged = durable
			message = intent.Message
			applyOptions.TransactionID = intent.TransactionID
			if packageProjectionMutationHook != nil {
				if hookErr := packageProjectionMutationHook("after-fence-before-apply"); hookErr != nil {
					return withExitCode(ExitConflict, "pending RPM projection fault: %v", hookErr)
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
			return stateMutationError("commit RPM add", err)
		}
		if projectionIntent != nil && packageProjectionMutationHook != nil {
			if hookErr := packageProjectionMutationHook("after-ref-before-materialize"); hookErr != nil {
				return withExitCode(ExitConflict, "pending RPM projection fault: %v", hookErr)
			}
		}
		if projectionIntent != nil {
			defer func() {
				if resultErr == nil {
					resultErr = removePackageProjectionIntent(cfg.StatePath(), *projectionIntent)
				}
			}()
		}
		fmt.Fprintf(stdout, "added format=rpm packages=%d leaves=%d commit=%s config_sha256=%s\n", added, len(groups), commit, configHash)
	} else {
		fmt.Fprintf(stdout, "add unchanged format=rpm packages=%d leaves=%d commit=%s repair=materialization\n", unchanged, len(groups), commit)
	}
	values, selectionOwner, err := beginMaterializationSelectionForRequests(cfg, canonical, values, selectedMaterializationOperation(values, "add"), requests)
	if err != nil {
		return withExitCode(ExitConflict, "begin RPM selected-set materialization: %v", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, finishMaterializationSelectedSet(cfg, values.materializeTrust, selectionOwner, resultErr))
	}()
	exactByView := make(map[string]map[materializedRouteOwnerID]string)
	ownerPlans, err := rpmMaterializationOwners(requests)
	if err != nil {
		return withExitCode(ExitInternal, "plan YUM physical owners: %v", err)
	}
	for _, owner := range ownerPlans {
		if err := runPackageMaterializationHook(ctx, packageMaterializationInvocation{Kind: "yum", View: owner.view, Repo: owner.repo.ID, OS: removalLeafOSList(owner.leaves), Arch: owner.arch}); err != nil {
			return withExitCode(ExitVerification, "YUM materialization hook: %v", err)
		}
		if err := requireRepositorySigningKeyIdentityAt(cfg, privateKey, repositoryKeySHA, packageProjectionMaterializationTime(values, verificationTime)); err != nil {
			return withExitCode(ExitConflict, "repository signing key changed before YUM materialization: %v", err)
		}
		if err := requireRPMPackageKeyringIdentities(cfg, packageKeyringRepos, packageKeyringSHA256); err != nil {
			return withExitCode(ExitConflict, "RPM package trust changed before YUM materialization: %v", err)
		}
		result, err := materializeYUMOwner(ctx, cfg, canonical, pool, owner.repo, owner.leaves, owner.view, txDir, values, privateKey, passphrase)
		if err != nil {
			return withExitCode(ExitVerification, "build YUM owner %s/%s (%s): %v", owner.repo.ID, owner.arch, removalLeafOSList(owner.leaves), err)
		}
		if err := requireRepositorySigningKeyIdentityAt(cfg, privateKey, repositoryKeySHA, packageProjectionMaterializationTime(values, verificationTime)); err != nil {
			return withExitCode(ExitConflict, "repository signing key changed during YUM materialization: %v", err)
		}
		if err := requireRPMPackageKeyringIdentities(cfg, packageKeyringRepos, packageKeyringSHA256); err != nil {
			return withExitCode(ExitConflict, "RPM package trust changed during YUM materialization: %v", err)
		}
		if exactByView[owner.view] == nil {
			exactByView[owner.view] = make(map[materializedRouteOwnerID]string)
		}
		exactByView[owner.view][materializedRouteOwnerID{kind: "yum", repo: owner.repo.ID, arch: owner.arch}] = result.ExactManifest
		fmt.Fprintf(stdout, "yum repo=%s view=%s os=%s arch=%s packages=%d revision=%d repomd_sha256=%s pruned=%d\n",
			owner.repo.ID, owner.view, removalLeafOSList(owner.leaves), owner.arch, result.Generation.Packages, result.Generation.Revision, result.Generation.RepomdSHA256, result.Reconciled.RemovedFiles)
	}
	leavesByView := packageMaterializationLeavesByView(requests)
	viewNames := make([]string, 0, len(exactByView))
	for viewName := range exactByView {
		viewNames = append(viewNames, viewName)
	}
	sort.Strings(viewNames)
	for _, viewName := range viewNames {
		receiptCommit, receiptChanged, receipts, err := persistPackageMaterializationReceipts(ctx, cfg, canonical, pool, viewName, leavesByView[viewName], exactByView[viewName], txDir, values, values.materializeTrust)
		if err != nil {
			return withExitCode(ExitVerification, "persist RPM materialization readiness: %v", err)
		}
		fmt.Fprintf(stdout, "package materialization view=%s kind=yum receipts=%d commit=%s changed=%t\n", viewName, receipts, receiptCommit, receiptChanged)
	}
	return nil
}

func rpmMaterializationOwners(requests []materializationSelectionRequest) ([]rpmMaterializationOwnerPlan, error) {
	owners := make(map[string]*rpmMaterializationOwnerPlan)
	seenLeaves := make(map[string]map[string]struct{})
	for _, request := range requests {
		for _, leaf := range request.Leaves {
			if leaf.repo.Type != "yum" {
				continue
			}
			key := strings.Join([]string{request.Source.ID, leaf.repo.ID, leaf.arch}, "\x00")
			owner := owners[key]
			if owner == nil {
				owner = &rpmMaterializationOwnerPlan{repo: leaf.repo, view: request.Source.ID, arch: leaf.arch}
				owners[key] = owner
				seenLeaves[key] = make(map[string]struct{})
			} else if owner.repo.ID != leaf.repo.ID || owner.view != request.Source.ID || owner.arch != leaf.arch {
				return nil, errors.New("YUM materialization owner crosses a physical boundary")
			}
			leafKey := leaf.os + "\x00" + leaf.arch
			if _, exists := seenLeaves[key][leafKey]; exists {
				continue
			}
			seenLeaves[key][leafKey] = struct{}{}
			owner.leaves = append(owner.leaves, leaf)
		}
	}
	keys := make([]string, 0, len(owners))
	for key := range owners {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]rpmMaterializationOwnerPlan, 0, len(keys))
	for _, key := range keys {
		owner := owners[key]
		sort.Slice(owner.leaves, func(i, j int) bool { return owner.leaves[i].os < owner.leaves[j].os })
		if len(owner.leaves) == 0 {
			return nil, errors.New("empty YUM materialization owner")
		}
		result = append(result, *owner)
	}
	if len(result) == 0 {
		return nil, errors.New("RPM add selected no YUM materialization owners")
	}
	return result, nil
}

func planRPMLeafGroups(plans []rpmInputPlan) (map[string]*rpmLeafPlan, error) {
	groups := make(map[string]*rpmLeafPlan)
	for _, plan := range plans {
		debugInfo := isDebugRPM(plan.info.Name)
		viewName := packageDestinationView(plan.repo, debugInfo)
		version := plan.info.Version + "-" + plan.info.Release
		if plan.info.Epoch > 0 {
			version = fmt.Sprintf("%d:%s", plan.info.Epoch, version)
		}
		for _, arch := range plan.arches {
			effectiveRoot, err := plan.repo.PathForArch(arch)
			if err != nil {
				return nil, err
			}
			leaf := viewLeaf{repo: plan.repo, os: "el" + fmt.Sprint(plan.repo.OS.Major), arch: arch}
			key := strings.Join([]string{viewName, plan.repo.ID, leaf.os, arch}, "\x00")
			group := groups[key]
			if group == nil {
				group = &rpmLeafPlan{repo: plan.repo, leaf: leaf, view: viewName}
				groups[key] = group
			}
			entry := views.Entry{
				Repo: plan.repo.ID, OS: leaf.os, Arch: arch, Name: plan.info.Name,
				Version: version, Path: path.Join(effectiveRoot, plan.info.Location),
				Size: plan.info.Size, SHA256: plan.info.SHA256, Pool: plan.repo.DefaultPool,
				DebugInfo: debugInfo,
			}
			if err := entry.Validate(); err != nil {
				return nil, err
			}
			group.entries = append(group.entries, entry)
		}
	}
	return groups, nil
}

func requireRPMPackageKeyringIdentities(cfg *config.Config, repos map[string]config.Repo, expected map[string]string) error {
	names := make([]string, 0, len(expected))
	for name := range expected {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		repo, exists := repos[name]
		if !exists || repo.YUM == nil || !syncProgressSHA256Pattern.MatchString(expected[name]) {
			return fmt.Errorf("invalid frozen RPM package trust identity for repo %s", name)
		}
		_, current, err := loadRPMPackageKeyring(cfg.Path, repo.YUM.PackageKeyring)
		if err != nil {
			return fmt.Errorf("reload repo %s RPM package keyring: %w", name, err)
		}
		if current != expected[name] {
			return fmt.Errorf("repo %s RPM package keyring changed after verification", name)
		}
	}
	return nil
}

func verifyStableRPMFile(ctx context.Context, filename string, expectedSize int64, keyring openpgp.KeyRing, at time.Time) ([]yumrepo.VerifiedEmbeddedRPMSignature, error) {
	file, verified, err := openVerifiedRPMFile(ctx, filename, expectedSize, keyring, at)
	if file != nil {
		err = errors.Join(err, file.Close())
	}
	return verified, err
}

func openVerifiedRPMFile(ctx context.Context, filename string, expectedSize int64, keyring openpgp.KeyRing, at time.Time) (*os.File, []yumrepo.VerifiedEmbeddedRPMSignature, error) {
	before, err := os.Lstat(filename)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() != expectedSize {
		return nil, nil, errors.Join(err, errors.New("RPM is not a stable regular file of the expected size"))
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, nil, errors.Join(err, errors.New("RPM changed while opening"))
	}
	verified, verifyErr := yumrepo.VerifyEmbeddedRPMSignatures(ctx, file, keyring, at)
	after, statErr := file.Stat()
	if verifyErr != nil || statErr != nil {
		_ = file.Close()
		return nil, nil, errors.Join(verifyErr, statErr)
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		_ = file.Close()
		return nil, nil, errors.New("RPM changed during package signature verification")
	}
	return file, verified, nil
}

func snapshotRPMInput(ctx context.Context, source, directory string, index int) (destination string, returnErr error) {
	if ctx == nil {
		return "", errors.New("nil context")
	}
	before, err := os.Lstat(source)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return "", errors.Join(err, errors.New("RPM input must be a regular non-symlink file"))
	}
	input, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer func() { returnErr = errors.Join(returnErr, input.Close()) }()
	opened, err := input.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return "", errors.Join(err, errors.New("RPM input changed while opening"))
	}
	output, err := os.CreateTemp(directory, fmt.Sprintf("%06d-*.rpm", index))
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
		return "", errors.Join(statErr, pathErr, errors.New("RPM input changed while snapshotting"))
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

type addRPMContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *addRPMContextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

func rpmInputCandidates(input string, info yumrepo.PackageInfo, selected []config.Repo, archSelectors []string) ([]rpmInputPlan, error) {
	major, inferred, err := inferRPMELMajor(info.Release)
	if err != nil {
		return nil, err
	}
	var candidates []rpmInputPlan
	for _, repo := range selected {
		if repo.Type != "yum" {
			continue
		}
		if inferred && repo.OS.Major != major {
			continue
		}
		arches := rpmLeafArches(repo, info.Arch, archSelectors)
		if len(arches) == 0 {
			continue
		}
		candidates = append(candidates, rpmInputPlan{input: input, info: info, repo: repo, arches: arches})
	}
	return candidates, nil
}

func inferRPMELMajor(release string) (int, bool, error) {
	var majors []int
	for _, token := range strings.FieldsFunc(strings.ToLower(release), func(value rune) bool {
		return value == '.' || value == '_' || value == '+' || value == '~' || value == '-'
	}) {
		digits := ""
		switch {
		case strings.HasPrefix(token, "rhel"):
			digits = strings.TrimPrefix(token, "rhel")
		case strings.HasPrefix(token, "el"):
			digits = strings.TrimPrefix(token, "el")
		default:
			continue
		}
		if digits != "8" && digits != "9" && digits != "10" {
			continue
		}
		major, err := strconv.Atoi(digits)
		if err != nil {
			return 0, false, err
		}
		majors = append(majors, major)
	}
	if len(majors) == 0 {
		return 0, false, nil
	}
	major := majors[0]
	for _, candidate := range majors[1:] {
		if candidate != major {
			return 0, false, fmt.Errorf("conflicting EL dist tags in RPM release %q", release)
		}
	}
	return major, true, nil
}

func rpmLeafArches(repo config.Repo, packageArch string, selected []string) []string {
	var result []string
	for _, arch := range repo.Arches {
		if len(selected) > 0 && !contains(selected, arch) {
			continue
		}
		if rpmLeafAcceptsPackageArch(repo, arch, packageArch) {
			result = append(result, arch)
		}
	}
	return result
}

// rpmLeafAcceptsPackageArch is the single routing contract shared by direct
// add, upstream sync/replay, and legacy adoption. Empty NoarchMode values occur
// only in older programmatic fixtures and retain the schema-v1 replicate
// default; decoded canonical configuration always stores an explicit mode.
func rpmLeafAcceptsPackageArch(repo config.Repo, leafArch, packageArch string) bool {
	if repo.Type != "yum" || !contains(repo.Arches, leafArch) {
		return false
	}
	mode := config.YUMNoarchReplicate
	if repo.YUM != nil && repo.YUM.NoarchMode != "" {
		mode = repo.YUM.NoarchMode
	}
	if mode == config.YUMNoarchSeparate {
		if packageArch == "noarch" {
			return leafArch == "noarch"
		}
		return leafArch != "noarch" && leafArch == packageArch
	}
	return packageArch == "noarch" || packageArch == leafArch
}

func isDebugRPM(name string) bool {
	return strings.HasSuffix(name, "-debuginfo") || strings.HasSuffix(name, "-debugsource") || strings.Contains(name, "debuginfo-")
}

func stateCommitForGroups(canonical *state.Store, groups map[string]*rpmLeafPlan) plumbing.Hash {
	for _, group := range groups {
		ref, _ := state.ViewRef(group.view, group.repo.ID, group.leaf.os, group.leaf.arch)
		if hash, exists, _ := canonical.Ref(ref); exists {
			return hash
		}
	}
	return plumbing.ZeroHash
}
