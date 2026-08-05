package managed

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/v2/config"
	"github.com/pgsty/sow/internal/v2/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

func Check(ctx context.Context, opts CheckOptions) (result CheckResult, resultErr error) {
	result = CheckResult{Layers: []CheckLayer{}}
	if ctx == nil {
		return result, errors.New("managed: nil context")
	}
	if opts.Jobs < 1 {
		return result, fmt.Errorf("%w: check jobs must be at least 1", ErrRejected)
	}
	ws, cfg, workspaceLock, err := readWorkspace(ctx, opts.WorkspaceOptions, true)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, workspaceLock.Close()) }()
	repoName, err := selectRepo(ws, cfg, opts.Repository)
	if err != nil {
		return result, err
	}
	result.Repository = repoName
	distNames, err := validateOptionalDists(cfg, repoName, opts.Dists)
	if err != nil {
		return result, err
	}
	scoped := len(distNames) != 0
	if !scoped {
		distNames = sortedDistConfigNames(cfg.Repositories[repoName])
	}
	store, repoLock, err := openReadRepository(ctx, ws.Root, repoName)
	if err != nil {
		return result, err
	}
	defer func() { resultErr = errors.Join(resultErr, repoLock.Close()) }()
	defer func() { resultErr = errors.Join(resultErr, store.Close()) }()
	return checkLocked(ctx, ws, cfg, repoName, distNames, scoped, store, opts.Jobs)
}

// checkLocked is the single non-repairing delivery-integrity predicate shared
// by `check` and `changes`. Callers must hold the Workspace and Repository
// shared locks for the supplied config/state snapshot.
func checkLocked(ctx context.Context, ws config.Workspace, cfg config.Config, repoName string, distNames []string, scoped bool, store *state.Store, jobsLimit int) (result CheckResult, resultErr error) {
	result = CheckResult{Repository: repoName, Layers: []CheckLayer{}}
	addLayer := func(name string, checked int64, issues []string) {
		if issues == nil {
			issues = []string{}
		}
		result.Layers = append(result.Layers, CheckLayer{Name: name, OK: len(issues) == 0, Checked: checked, Issues: issues})
	}
	configIssues, configChecked := validateSelectedCheckConfiguration(ctx, cfg, repoName, distNames, scoped, store)
	addLayer("config", configChecked, configIssues)

	stateIssues := []string{}
	if err := store.Check(ctx); err != nil {
		stateIssues = append(stateIssues, err.Error())
	}
	var quick string
	if err := store.DB().QueryRowContext(ctx, `PRAGMA quick_check`).Scan(&quick); err != nil || quick != "ok" {
		stateIssues = append(stateIssues, fmt.Sprintf("SQLite quick_check=%q err=%v", quick, err))
	}
	var foreignKeys int
	if err := store.DB().QueryRowContext(ctx, `SELECT count(*) FROM pragma_foreign_key_check`).Scan(&foreignKeys); err != nil || foreignKeys != 0 {
		stateIssues = append(stateIssues, fmt.Sprintf("SQLite foreign_key_check=%d err=%v", foreignKeys, err))
	}
	summary, err := store.Summary(ctx)
	if err != nil {
		return result, err
	}
	result.Generation, result.Revision, result.Status = summary.BuiltGeneration, summary.DesiredRevision, "clean"
	if !scoped || summary.Status == "error" {
		result.Status = summary.Status
	}
	workspaceOperation, workspaceOperationErr := inspectWorkspaceJournal(ws.Root)
	if workspaceOperationErr != nil {
		stateIssues = append(stateIssues, "workspace journal evidence is invalid")
		result.Status = "error"
	} else if workspaceOperation != nil && (workspaceOperation.Repository == "" || workspaceOperation.Repository == repoName) {
		result.Status = statusAtLeast(result.Status, "recovering")
	}
	allPendingOperations, err := store.PendingOperations(ctx)
	if err != nil {
		return result, err
	}
	repositoryRecoveryView, recoveryErr := inspectMutationRecoveryView(ctx, ws.Root, repoName, store, summary, allPendingOperations)
	if recoveryErr != nil {
		stateIssues = append(stateIssues, recoveryErr.Error())
	}
	pendingOperations := pendingOperationsForSelectedDists(allPendingOperations, distNames, scoped)
	if len(pendingOperations) != 0 {
		result.Status = statusAtLeast(result.Status, "recovering")
	}
	var recoveryView *mutationRecoveryView
	if len(pendingOperations) != 0 {
		recoveryView = repositoryRecoveryView
	}
	addLayer("state", 1, stateIssues)
	publicModeIssues, publicModeCount := validateManagedPublicModes(ctx, filepath.Join(ws.Root, repoName))
	addLayer("public-modes", publicModeCount, publicModeIssues)

	objectsByDigest := map[string]state.PackageObject{}
	allObjects, err := store.ListPackageObjects(ctx, nil, false)
	if err != nil {
		return result, err
	}
	// Public Pool integrity is repository-wide even for a scoped Dist check.
	// Objects may remain deliberately reachable from a retained Generation
	// after Desired/Built/prior-Built membership has moved on.
	for _, object := range allObjects {
		if object.Storage == "pool" {
			objectsByDigest[object.SHA256] = object
		}
	}
	for _, built := range []bool{false, true} {
		selectedObjects, listErr := store.ListPackageObjects(ctx, distNames, built)
		if listErr != nil {
			return result, listErr
		}
		for _, object := range selectedObjects {
			objectsByDigest[object.SHA256] = object
		}
	}
	priorObjects, err := store.ListPriorBuiltPackageObjects(ctx, distNames)
	if err != nil {
		return result, err
	}
	for _, object := range priorObjects {
		objectsByDigest[object.SHA256] = object
	}
	objects := make([]state.PackageObject, 0, len(objectsByDigest))
	for _, object := range objectsByDigest {
		objects = append(objects, object)
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].SHA256 < objects[j].SHA256 })
	packageIssues := []string{}
	signatureIssues := []string{}
	var signatureChecked int64
	rpmSigningConfig := cfg.Repositories[repoName].Signing.RPM.Packages
	rpmPolicy, policyErr := loadRPMSigningPolicy(ctx, ws.Root, rpmSigningConfig)
	retainedRPMKeys, retainedErr := loadRetainedRPMKeyrings(ctx, store)
	if retainedErr != nil {
		signatureIssues = append(signatureIssues, retainedErr.Error())
	}
	objectIssues := make([][]string, len(objects))
	objectSignatureIssues := make([][]string, len(objects))
	for _, object := range objects {
		if object.Format == "rpm" {
			signatureChecked++
		}
	}
	workers := jobsLimit
	if workers > len(objects) {
		workers = len(objects)
	}
	if workers > 0 {
		jobs := make(chan int)
		var group sync.WaitGroup
		group.Add(workers)
		for range workers {
			go func() {
				defer group.Done()
				for index := range jobs {
					object := objects[index]
					source, sourceErr := availableManagedPackageSource(ws.Root, repoName, object)
					if sourceErr != nil {
						objectIssues[index] = append(objectIssues[index], sourceErr.Error())
						continue
					}
					opened, openErr := source.open()
					if openErr != nil {
						objectIssues[index] = append(objectIssues[index], openErr.Error())
						continue
					}
					if object.Storage == "pool" {
						if opened.before.Mode().Perm() != 0o644 {
							objectIssues[index] = append(objectIssues[index], fmt.Sprintf("public package %s mode is not 0644", object.SHA256))
							_ = opened.CloseVerified()
							continue
						}
					}
					digest, hashErr := hashOpenedFileContext(ctx, opened.file)
					if hashErr != nil || digest != object.SHA256 {
						objectIssues[index] = append(objectIssues[index], fmt.Sprintf("package %s checksum differs", object.SHA256))
						_ = opened.CloseVerified()
						continue
					}
					parsed, inspectErr := inspectSnapshotReader(ctx, opened.file, object.Filename)
					if inspectErr != nil || !sameManagedPackageFacts(object, parsed) {
						objectIssues[index] = append(objectIssues[index], fmt.Sprintf("package %s facts differ from SQLite: %v", object.SHA256, inspectErr))
						_ = opened.CloseVerified()
						continue
					}
					if object.Format == "deb" {
						if object.SignatureKey != "" {
							objectIssues[index] = append(objectIssues[index], fmt.Sprintf("DEB %s has an unexpected package signature identity", object.SHA256))
						}
						if closeErr := opened.CloseVerified(); closeErr != nil {
							objectIssues[index] = append(objectIssues[index], closeErr.Error())
						}
						continue
					}
					if retainedErr != nil {
						_ = opened.CloseVerified()
						continue
					}
					if signatureErr := validateStoredRPMIdentity(ctx, opened.file, object, retainedRPMKeys); signatureErr != nil {
						objectSignatureIssues[index] = append(objectSignatureIssues[index], fmt.Sprintf("RPM %s retained signature proof is invalid: %v", object.SHA256, signatureErr))
					}
					if closeErr := opened.CloseVerified(); closeErr != nil {
						objectIssues[index] = append(objectIssues[index], closeErr.Error())
					}
				}
			}()
		}
		for index := range objects {
			jobs <- index
		}
		close(jobs)
		group.Wait()
	}
	for _, issues := range objectIssues {
		packageIssues = append(packageIssues, issues...)
	}
	for _, issues := range objectSignatureIssues {
		signatureIssues = append(signatureIssues, issues...)
	}
	poolIssues, _ := validatePublicPoolObjectBijection(ctx, filepath.Join(ws.Root, repoName), allObjects, recoveryView)
	packageIssues = append(packageIssues, poolIssues...)
	pendingExpected := make(map[string]state.PackageObject)
	for _, object := range objects {
		if object.Storage == "pending" {
			pendingExpected[object.SHA256] = object
		}
	}
	allPendingExpected := make(map[string]state.PackageObject)
	for _, object := range allObjects {
		if object.Storage == "pending" {
			allPendingExpected[object.SHA256] = object
		}
	}
	pendingRoot := filepath.Join(ws.Root, ".sow", repoName, "pending")
	seen := make(map[string]struct{}, len(pendingExpected))
	pendingErr := walkRootedTree(ctx, pendingRoot, func(relative string, _ *os.File, info os.FileInfo) error {
		name := filepath.ToSlash(relative)
		object, expected := allPendingExpected[name]
		if strings.Contains(name, "/") || !expected || info.Size() != object.Size {
			return fmt.Errorf("pending store entry %q is orphaned or unsafe", name)
		}
		if _, selected := pendingExpected[name]; selected {
			seen[name] = struct{}{}
		}
		return nil
	}, nil)
	if pendingErr != nil {
		packageIssues = append(packageIssues, fmt.Sprintf("pending store cannot be read safely: %v", pendingErr))
	}
	for digest := range pendingExpected {
		if _, ok := seen[digest]; !ok {
			if recoveryView != nil {
				if _, promoted := recoveryView.pooledPublic[digest]; promoted {
					continue
				}
			}
			packageIssues = append(packageIssues, fmt.Sprintf("pending package %s is absent from the pending store", digest))
		}
	}
	addLayer("package-bytes", int64(len(objects)), packageIssues)

	membershipIssues := []string{}
	dirtyDists := []string{}
	for _, distName := range distNames {
		effectiveView, viewErr := config.EffectiveView(cfg, config.ViewOptions{Repository: repoName, Dist: distName})
		if viewErr != nil {
			membershipIssues = append(membershipIssues, viewErr.Error())
			continue
		}
		effective := effectiveView.Repositories[repoName].Dists[distName]
		desiredObjects, listErr := store.ListPackageObjects(ctx, []string{distName}, false)
		if listErr != nil {
			membershipIssues = append(membershipIssues, listErr.Error())
			continue
		}
		policy, applyErr := ApplyPolicy(desiredObjects, effective)
		if applyErr != nil {
			membershipIssues = append(membershipIssues, applyErr.Error())
			continue
		}
		wanted := make([]string, 0, len(policy.Kept))
		for _, object := range policy.Kept {
			wanted = append(wanted, object.SHA256)
		}
		desired, _ := store.MembershipDigests(ctx, distName, false)
		built, _ := store.MembershipDigests(ctx, distName, true)
		if !sameStringSet(wanted, desired) {
			membershipIssues = append(membershipIssues, fmt.Sprintf("Dist %s Desired Membership violates current policy", distName))
		}
		if cfg.Repositories[repoName].Dists[distName].Format == "rpm" && policyErr == nil {
			for _, object := range desiredObjects {
				source, sourceErr := availableManagedPackageSource(ws.Root, repoName, object)
				if sourceErr != nil {
					membershipIssues = append(membershipIssues, sourceErr.Error())
					continue
				}
				opened, openErr := source.open()
				if openErr != nil {
					membershipIssues = append(membershipIssues, openErr.Error())
					continue
				}
				policyCheckErr := rpmPolicy.authorizeDesiredReader(ctx, opened.file)
				if closeErr := opened.CloseVerified(); closeErr != nil {
					policyCheckErr = errors.Join(policyCheckErr, closeErr)
				}
				if policyCheckErr != nil {
					// Current Desired authorization is mutable policy, not proof that
					// the immutable object or retained Built Generation is corrupt.
					// A key/mode rotation therefore makes this Dist dirty; build owns
					// the actionable policy rejection while Built check continues to
					// authenticate against its frozen certificate snapshots.
					dirtyDists = append(dirtyDists, distName)
				}
			}
		}
		distState, stateErr := store.GetDist(ctx, distName)
		effectiveSHA, configDirty, hashErr := observedEffectiveDistConfig(ctx, ws.Root, cfg, repoName, distName, distState)
		if stateErr != nil || hashErr != nil || !sameStringSet(desired, built) || configDirty || effectiveSHA != "" && effectiveSHA != distState.EffectiveConfigSHA256 {
			dirtyDists = append(dirtyDists, distName)
		}
	}
	if len(dirtyDists) != 0 {
		result.Status = statusAtLeast(result.Status, "dirty")
	}
	addLayer("desired-membership", summary.MembershipCount, membershipIssues)

	indexIssues := []string{}
	for _, distName := range distNames {
		dist, distErr := store.GetDist(ctx, distName)
		if distErr != nil {
			indexIssues = append(indexIssues, distErr.Error())
			continue
		}
		builtObjects, listErr := store.ListPackageObjects(ctx, []string{distName}, true)
		if listErr != nil {
			indexIssues = append(indexIssues, listErr.Error())
			continue
		}
		if dist.Format == "rpm" {
			frozenSigning, signingErr := decodeRetainedEffectiveSigning(dist.EffectiveSigningJSON)
			if signingErr != nil {
				signatureIssues = append(signatureIssues, fmt.Sprintf("Dist %s retained signing policy is invalid: %v", distName, signingErr))
			} else {
				for _, object := range builtObjects {
					signatureChecked++
					if signingErr := validateBuiltRPMAuthorization(ctx, ws.Root, repoName, object, frozenSigning.RPM.Packages, retainedRPMKeys); signingErr != nil {
						signatureIssues = append(signatureIssues, fmt.Sprintf("Dist %s built RPM %s signing authorization is invalid: %v", distName, object.SHA256, signingErr))
					}
				}
			}
		}
		priorBuiltObjects, listErr := store.ListPriorBuiltPackageObjects(ctx, []string{distName})
		if listErr != nil {
			indexIssues = append(indexIssues, listErr.Error())
			continue
		}
		validationObjects := builtObjects
		validationArchitectures := dist.Architectures
		recoveringTarget, targetIsPublic := mutationBuildDist{}, false
		if recoveryView != nil {
			recoveringTarget, targetIsPublic = recoveryView.targetDists[distName]
		}
		if targetIsPublic {
			validationObjects, listErr = store.ListPackageObjects(ctx, []string{distName}, false)
			if listErr != nil {
				indexIssues = append(indexIssues, listErr.Error())
				continue
			}
			validationArchitectures = recoveringTarget.Architectures
		}
		if dist.Format == "rpm" {
			aliasObjects := append(append([]state.PackageObject(nil), builtObjects...), priorBuiltObjects...)
			verifier, signed, verifierErr := builtRPMMetadataVerifier(ctx, store, dist)
			if targetIsPublic {
				aliasObjects = append(append([]state.PackageObject(nil), validationObjects...), builtObjects...)
				for index := range aliasObjects {
					if _, promoted := recoveryView.pooledPublic[aliasObjects[index].SHA256]; promoted {
						aliasObjects[index].Storage = "pool"
					}
				}
				verifier, signed, verifierErr = recoveringRPMMetadataVerifier(recoveringTarget, recoveryView.operation)
			}
			if verifierErr != nil {
				signatureIssues = append(signatureIssues, fmt.Sprintf("Dist %s retained metadata signer is invalid: %v", distName, verifierErr))
			}
			for _, architecture := range validationArchitectures {
				signatureChecked++
				repodata := filepath.Join(ws.Root, repoName, "dists", distName, architecture.Family, "repodata")
				if aliasErr := validateRPMViewAliases(ctx, filepath.Join(ws.Root, repoName), distName, architecture.Family, aliasObjects); aliasErr != nil {
					indexIssues = append(indexIssues, aliasErr.Error())
				}
				if verifierErr == nil {
					if signatureErr := validateRPMMetadataSignature(ctx, repodata, verifier, signed); signatureErr != nil {
						signatureIssues = append(signatureIssues, fmt.Sprintf("Dist %s/%s RPM metadata signature differs: %v", distName, architecture.Family, signatureErr))
					}
				}
				var generation *yumrepo.Generation
				var validateErr error
				if signed {
					generation, validateErr = yumrepo.ValidateManagedDirectory(ctx, repodata, yumrepo.CompressionGzip, structuralDetachedVerifier{})
				} else {
					generation, validateErr = yumrepo.ValidateManagedUnsignedDirectory(ctx, repodata, yumrepo.CompressionGzip)
				}
				expected := int64(0)
				expectedIdentities := []string{}
				for _, object := range validationObjects {
					if object.CanonicalArch != "neutral" && object.CanonicalArch != architecture.Family {
						continue
					}
					expected++
					expectedIdentities = append(expectedIdentities, object.SHA256)
				}
				sort.Strings(expectedIdentities)
				expectedIdentitySHA := bytesSHA([]byte(strings.Join(expectedIdentities, "\n")))
				if len(expectedIdentities) != 0 {
					expectedIdentitySHA = bytesSHA([]byte(strings.Join(expectedIdentities, "\n") + "\n"))
				}
				if validateErr != nil || generation == nil || generation.Packages != expected || generation.IdentitySHA256 != expectedIdentitySHA {
					indexIssues = append(indexIssues, fmt.Sprintf("Dist %s/%s rpm-md package count or index differs: %v", distName, architecture.Family, validateErr))
				}
			}
		} else {
			verifier, signed, verifierErr := builtAPTMetadataVerifier(ctx, store, dist)
			if targetIsPublic {
				verifier, signed, verifierErr = recoveringAPTMetadataVerifier(recoveringTarget)
			}
			expectedPackages := make(map[string]map[string]state.PackageObject, len(validationArchitectures))
			for _, architecture := range validationArchitectures {
				expectedPackages[architecture.EcosystemArch] = map[string]state.PackageObject{}
				for _, object := range validationObjects {
					if object.CanonicalArch == "neutral" || object.CanonicalArch == architecture.Family {
						expectedPackages[architecture.EcosystemArch][object.SHA256] = object
					}
				}
			}
			var validateErr error
			if verifierErr != nil {
				signatureIssues = append(signatureIssues, fmt.Sprintf("Dist %s retained metadata signer is invalid: %v", distName, verifierErr))
			} else if signatureErr := validateManagedAPTSignature(ctx, filepath.Join(ws.Root, repoName), distName, verifier, signed); signatureErr != nil {
				signatureIssues = append(signatureIssues, fmt.Sprintf("Dist %s APT metadata signature differs: %v", distName, signatureErr))
			}
			signatureChecked++
			expectedGeneration := dist.BuiltGeneration
			if targetIsPublic && recoveryView != nil && recoveryView.manifest.Build != nil {
				expectedGeneration = recoveryView.manifest.Build.Generation
			}
			validateErr = validateManagedAPTIndex(ctx, filepath.Join(ws.Root, repoName), distName, validationArchitectures, expectedPackages, &expectedGeneration)
			if validateErr != nil {
				indexIssues = append(indexIssues, fmt.Sprintf("Dist %s APT index differs: %v", distName, validateErr))
			}
		}
	}
	addLayer("index", int64(len(distNames)), indexIssues)
	addLayer("signature", signatureChecked, signatureIssues)

	manifestIssues := []string{}
	legacyManifest := false
	ledgerErr := store.ValidateGenerationLedger(ctx)
	if errors.Is(ledgerErr, state.ErrNotFound) {
		if summary.BuiltGeneration > 0 {
			manifestIssues = append(manifestIssues, "current legacy P1 Generation has no retained physical manifest")
			legacyManifest = true
			result.Status = statusAtLeast(result.Status, "dirty")
		}
	} else if ledgerErr != nil {
		manifestIssues = append(manifestIssues, ledgerErr.Error())
	} else if repositoryRecoveryView != nil {
		// inspectMutationRecoveryView already proved that the visible tree is
		// exactly one journal-permitted mix of the retained base Generation,
		// promoted payloads, and atomically exchanged old/new Dist trees.
		// It is intentionally not equal to the last committed Generation yet.
	} else {
		physical, scanErr := scanPublicManifest(ctx, filepath.Join(ws.Root, repoName))
		if scanErr != nil {
			manifestIssues = append(manifestIssues, fmt.Sprintf("public delivery tree cannot be scanned: %v", scanErr))
		} else if summary.BuiltGeneration == 0 {
			if len(physical) != 0 {
				manifestIssues = append(manifestIssues, "Generation 0 public delivery tree is not empty")
			}
		} else {
			retained, retainedErr := store.GenerationManifest(ctx, summary.BuiltGeneration)
			if retainedErr != nil {
				manifestIssues = append(manifestIssues, retainedErr.Error())
			} else if !sameGenerationManifest(retained, physical) {
				manifestIssues = append(manifestIssues, "current Generation manifest differs from public tree")
			}
		}
	}
	addLayer("generation-manifest", int64(summary.BuiltGeneration), manifestIssues)

	integrityIssues := []string{}
	for _, layer := range result.Layers {
		if !layer.OK && !(legacyManifest && layer.Name == "generation-manifest" && len(layer.Issues) == 1 && strings.Contains(layer.Issues[0], "legacy P1")) {
			integrityIssues = append(integrityIssues, layer.Issues...)
		}
	}
	if len(integrityIssues) != 0 {
		result.Status = "error"
		return result, fmt.Errorf("%w: %s", ErrIntegrity, strings.Join(integrityIssues, "; "))
	}
	result.ReadyToCopy = result.Status == "clean"
	if !result.ReadyToCopy {
		return result, fmt.Errorf("%w: repository status is %s", ErrNotReady, result.Status)
	}
	return result, nil
}

func validateSelectedCheckConfiguration(ctx context.Context, cfg config.Config, repoName string, distNames []string, scoped bool, store *state.Store) ([]string, int64) {
	issues := []string{}
	checked := int64(len(distNames) + 1)
	if !scoped {
		stored, err := store.ListDists(ctx)
		if err != nil {
			issues = append(issues, fmt.Sprintf("built Dist inventory is unavailable: %v", err))
		} else {
			checked += int64(len(stored))
			for _, dist := range stored {
				if _, configured := cfg.Repositories[repoName].Dists[dist.Name]; !configured {
					issues = append(issues, fmt.Sprintf("built Dist %s is absent from repository %s configuration", dist.Name, repoName))
				}
			}
		}
	}
	selected := make(map[string]struct{}, len(distNames))
	for _, distName := range distNames {
		selected[distName] = struct{}{}
		dist, err := store.GetDist(ctx, distName)
		if err != nil {
			issues = append(issues, fmt.Sprintf("Dist %s state is unavailable: %v", distName, err))
			continue
		}
		if configured := cfg.Repositories[repoName].Dists[distName]; configured.Format != dist.Format {
			issues = append(issues, fmt.Sprintf("Dist %s format differs between configuration and built state", distName))
		}
	}
	rawReferences, err := store.ArchitectureReferences(ctx)
	if err != nil {
		issues = append(issues, fmt.Sprintf("state architecture references are unavailable: %v", err))
	} else {
		references := make([]config.StateArchitectureReference, 0, len(rawReferences))
		for _, ref := range rawReferences {
			if _, ok := selected[ref.Dist]; !ok {
				continue
			}
			family, neutral := ref.Architecture, false
			var canonicalErr error
			if ref.Source == "built generation" {
				if family != "x86_64" && family != "aarch64" {
					canonicalErr = fmt.Errorf("unknown canonical architecture %q", family)
				}
			} else {
				family, neutral, canonicalErr = canonicalStateArchitecture(ref.Format, ref.Architecture)
			}
			if canonicalErr != nil {
				issues = append(issues, fmt.Sprintf("Dist %s %s architecture is invalid: %v", ref.Dist, ref.Source, canonicalErr))
				continue
			}
			if !neutral {
				references = append(references, config.StateArchitectureReference{Repository: repoName, Dist: ref.Dist, Architecture: family, Source: ref.Source})
			}
		}
		if err := config.ValidateStateArchitectureReferences(cfg, references); err != nil {
			issues = append(issues, err.Error())
		}
	}
	sort.Strings(issues)
	return issues, checked
}

func validateRPMMetadataSignature(ctx context.Context, repodata string, verifier yumrepo.DetachedVerifier, signed bool) error {
	signature, signatureErr := readOptionalBoundedRegular(repodata, "repomd.xml.asc", 16<<20)
	if !signed {
		if signatureErr == nil {
			return errors.New("unexpected repomd.xml.asc for unsigned Built metadata")
		}
		if errors.Is(signatureErr, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("inspect repomd.xml.asc: %w", signatureErr)
	}
	if verifier == nil {
		return errors.New("retained RPM metadata verifier is unavailable")
	}
	if signatureErr != nil {
		return fmt.Errorf("read repomd.xml.asc: %w", signatureErr)
	}
	message, err := readRootedRegular(repodata, "repomd.xml", 16<<20, false)
	if err != nil {
		return fmt.Errorf("read repomd.xml: %w", err)
	}
	if err := verifier.Verify(ctx, bytes.NewReader(message), bytes.NewReader(signature)); err != nil {
		return fmt.Errorf("verify repomd.xml.asc: %w", err)
	}
	return nil
}

func validateManagedPublicModes(ctx context.Context, repositoryRoot string) ([]string, int64) {
	issues := []string{}
	var checked int64
	inspect := func(root string) error {
		return walkRootedTree(ctx, root, func(relative string, _ *os.File, info os.FileInfo) error {
			checked++
			if info.Mode().Perm() != 0o644 {
				return fmt.Errorf("public file %s mode is %#o, want 0644", filepath.Join(root, filepath.FromSlash(relative)), info.Mode().Perm())
			}
			return nil
		}, func(relative string, _ *os.File, info os.FileInfo) error {
			checked++
			if info.Mode().Perm() != 0o755 {
				return fmt.Errorf("public directory %s mode is %#o, want 0755", filepath.Join(root, filepath.FromSlash(relative)), info.Mode().Perm())
			}
			return nil
		})
	}
	rootInfo, err := os.Lstat(repositoryRoot)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || rootInfo.Mode().Perm() != 0o755 {
		issues = append(issues, "public repository root is missing, unsafe, or not mode 0755")
		return issues, checked
	}
	checked++
	for _, name := range []string{"pool", "dists"} {
		if err := inspect(filepath.Join(repositoryRoot, name)); err != nil {
			issues = append(issues, err.Error())
		}
	}
	return issues, checked
}

func validatePublicPoolObjectBijection(ctx context.Context, repositoryRoot string, objects []state.PackageObject, recoveryView *mutationRecoveryView) ([]string, int64) {
	issues := []string{}
	expected := make(map[string]state.PackageObject)
	for _, object := range objects {
		publicDuringRecovery := false
		if recoveryView != nil {
			_, publicDuringRecovery = recoveryView.pooledPublic[object.SHA256]
		}
		if object.Storage != "pool" && !publicDuringRecovery {
			continue
		}
		path := filepath.ToSlash(object.PoolPath)
		if prior, duplicate := expected[path]; duplicate && prior.SHA256 != object.SHA256 {
			issues = append(issues, fmt.Sprintf("public Pool path %s maps to multiple Package Objects", path))
			continue
		}
		expected[path] = object
	}
	seen := make(map[string]struct{}, len(expected))
	poolRoot := filepath.Join(repositoryRoot, "pool")
	var checked int64
	err := walkRootedTree(ctx, poolRoot, func(relative string, _ *os.File, info os.FileInfo) error {
		checked++
		poolPath := path.Join("pool", filepath.ToSlash(relative))
		object, exists := expected[poolPath]
		if !exists {
			return fmt.Errorf("public Pool file %s has no Package Object", poolPath)
		}
		if info.Size() != object.Size {
			return fmt.Errorf("public Pool file %s size differs from Package Object", poolPath)
		}
		seen[poolPath] = struct{}{}
		return nil
	}, nil)
	if err != nil {
		issues = append(issues, fmt.Sprintf("public Pool cannot be matched to Package Objects: %v", err))
	}
	for poolPath := range expected {
		if _, exists := seen[poolPath]; !exists {
			issues = append(issues, fmt.Sprintf("Package Object for %s is absent from public Pool", poolPath))
		}
	}
	sort.Strings(issues)
	return issues, checked
}

func builtGenerationPublicationTime(ctx context.Context, store *state.Store, generation int64) (time.Time, error) {
	info, err := store.GetGeneration(ctx, generation)
	if err != nil {
		return time.Time{}, err
	}
	detail, err := store.GetOperation(ctx, info.OperationID)
	if err != nil || detail.Operation.CreatedAt.IsZero() {
		return time.Time{}, errors.New("built Generation has no retained publication identity")
	}
	return detail.Operation.CreatedAt.UTC(), nil
}

func builtMetadataIdentityAndTime(ctx context.Context, store *state.Store, dist state.Dist) (metadataSignerIdentity, time.Time, bool, error) {
	identity := metadataSignerIdentity{Fingerprint: dist.MetadataSignerFingerprint, PublicKey: dist.MetadataSignerPublicKey}
	signed := identity.Fingerprint != "" || len(identity.PublicKey) != 0
	if !signed {
		return metadataSignerIdentity{}, time.Time{}, false, nil
	}
	if err := validateMetadataSignerIdentity(identity); err != nil {
		return metadataSignerIdentity{}, time.Time{}, false, err
	}
	at, err := builtGenerationPublicationTime(ctx, store, dist.BuiltGeneration)
	if err != nil {
		return metadataSignerIdentity{}, time.Time{}, false, err
	}
	return identity, at, true, nil
}

func builtRPMMetadataVerifier(ctx context.Context, store *state.Store, dist state.Dist) (yumrepo.DetachedVerifier, bool, error) {
	identity, at, signed, err := builtMetadataIdentityAndTime(ctx, store, dist)
	if err != nil || !signed {
		return nil, signed, err
	}
	verifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(identity.PublicKey), at)
	return verifier, true, err
}

func builtAPTMetadataVerifier(ctx context.Context, store *state.Store, dist state.Dist) (APTMetadataVerifier, bool, error) {
	identity, _, signed, err := builtMetadataIdentityAndTime(ctx, store, dist)
	if err != nil || !signed {
		return nil, signed, err
	}
	verifier, err := aptrepo.NewVerifierBytes(identity.PublicKey)
	if err != nil {
		return nil, true, err
	}
	return &inProcessAPTMetadataVerifier{verifier: verifier}, true, nil
}

func validateRPMViewAliases(ctx context.Context, repositoryRoot, distName, family string, objects []state.PackageObject) error {
	expected := make(map[string]state.PackageObject)
	for _, object := range objects {
		if object.Format != "rpm" || object.Storage != "pool" || (object.CanonicalArch != "neutral" && object.CanonicalArch != family) {
			continue
		}
		expected[object.PoolPath] = object
		canonical, canonicalErr := openRootedRegular(repositoryRoot, object.PoolPath)
		aliasRelative := filepath.ToSlash(filepath.Join("dists", distName, family, filepath.FromSlash(object.PoolPath)))
		alias, aliasErr := openRootedRegular(repositoryRoot, aliasRelative)
		if canonicalErr != nil || aliasErr != nil {
			if canonical != nil {
				_ = canonical.CloseVerified()
			}
			if alias != nil {
				_ = alias.CloseVerified()
			}
			return fmt.Errorf("Dist %s/%s alias for %s is missing or unsafe", distName, family, object.SHA256)
		}
		same := os.SameFile(canonical.before, alias.before)
		verifyErr := errors.Join(canonical.CloseVerified(), alias.CloseVerified())
		if !same || verifyErr != nil {
			return fmt.Errorf("Dist %s/%s alias for %s is not the canonical Pool hardlink", distName, family, object.SHA256)
		}
	}
	viewPool := filepath.Join(repositoryRoot, "dists", distName, family, "pool")
	info, err := os.Lstat(viewPool)
	if errors.Is(err, os.ErrNotExist) && len(expected) == 0 {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("Dist %s/%s Pool alias root is missing or unsafe", distName, family)
	}
	seen := make(map[string]struct{}, len(expected))
	err = walkRootedTree(ctx, viewPool, func(relative string, _ *os.File, _ os.FileInfo) error {
		relative = path.Join("pool", relative)
		if _, ok := expected[relative]; !ok {
			return fmt.Errorf("view Pool contains unexpected alias %s", relative)
		}
		seen[relative] = struct{}{}
		return nil
	}, nil)
	if err != nil {
		return fmt.Errorf("Dist %s/%s C2 alias projection is invalid: %v", distName, family, err)
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("Dist %s/%s C2 alias projection has %d files, want %d", distName, family, len(seen), len(expected))
	}
	return nil
}

func sameManagedPackageFacts(expected, actual state.PackageObject) bool {
	return expected.SHA256 == actual.SHA256 && expected.Format == actual.Format && expected.Coordinate == actual.Coordinate &&
		expected.Architecture == actual.Architecture && expected.CanonicalArch == actual.CanonicalArch && expected.PoolPath == actual.PoolPath &&
		expected.Filename == actual.Filename && expected.Size == actual.Size && expected.Name == actual.Name && expected.Source == actual.Source &&
		expected.Version == actual.Version && expected.Epoch == actual.Epoch && expected.Release == actual.Release && expected.Kind == actual.Kind &&
		expected.PayloadSHA256 == actual.PayloadSHA256
}

func sameGenerationManifest(left, right []state.GenerationFile) bool {
	left = append([]state.GenerationFile(nil), left...)
	right = append([]state.GenerationFile(nil), right...)
	sort.Slice(left, func(i, j int) bool { return left[i].Path < left[j].Path })
	sort.Slice(right, func(i, j int) bool { return right[i].Path < right[j].Path })
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
