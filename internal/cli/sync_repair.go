package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
)

// repairSyncProjection rebuilds only derived repository projections from
// canonical view refs. It is intentionally used only when a durable sync
// progress record was found at command start. The normal path remains bounded
// by the discovered change set; recovery may project the canonical view but
// never reinspects or reimports every already-present package.
func repairSyncProjection(ctx context.Context, cfg *config.Config, canonical *state.Store, pool *repository.Store, repo config.Repo, source config.Upstream, values commonFlags, selectionSHA, txDir, privateKeyFile, passphraseFile string, stdout, stderr io.Writer) (resultErr error) {
	privateKey, err := resolveSecret(cfg.GPG.PrivateKey, privateKeyFile, false)
	if err != nil {
		return withExitCode(ExitConfig, "resolve OpenPGP private key for sync recovery: %v", err)
	}
	defer clearSecret(privateKey)
	passphrase, err := resolveSecret(cfg.GPG.Passphrase, passphraseFile, true)
	if err != nil {
		return withExitCode(ExitConfig, "resolve OpenPGP passphrase for sync recovery: %v", err)
	}
	defer clearSecret(passphrase)
	repositoryKeySHA, err := repositorySigningKeyIdentity(cfg, privateKey)
	if err != nil {
		return withExitCode(ExitConfig, "repository signing trust preflight failed during sync recovery: %v", err)
	}

	lock, err := state.AcquireLock(cfg.StatePath(), "sync-repair-"+source.ID, values.recover)
	if err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	defer propagateStateLockRelease(lock, &resultErr, stderr)
	if err := requireNoForeignMaterializationIntent(cfg, "sync", values.recover); err != nil {
		return withExitCode(ExitConflict, "%v", err)
	}
	if err := prepareCanonicalState(ctx, canonical, values.recover, stdout); err != nil {
		return err
	}
	if err := validateCanonicalHistoryContracts(cfg); err != nil {
		return withExitCode(ExitConflict, "repository history contract changed while sync repair was waiting for the state lock: %v", err)
	}
	contract, err := resolveCanonicalSyncContract(canonical, cfg, repo, source, selectionSHA)
	if err != nil {
		return withExitCode(ExitConflict, "canonical sync recovery contract changed: %v", err)
	}
	if !contract.Exists || contract.Config == nil {
		return withExitCode(ExitConflict, "canonical sync recovery contract is unavailable")
	}
	projectionCfg := contract.Config
	projectionRepo := contract.Repo
	viewsToRepair, err := syncProjectionViews(canonical, projectionCfg, projectionRepo)
	if err != nil {
		return withExitCode(ExitVerification, "inspect sync recovery refs: %v", err)
	}
	if len(viewsToRepair) == 0 {
		fmt.Fprintf(stdout, "sync recovery upstream=%s projection=unchanged refs=0\n", source.ID)
		return nil
	}
	activeSelection, selectionActive, err := readMaterializationSelectionJournal(projectionCfg.StatePath())
	if err != nil {
		return withExitCode(ExitConflict, "read sync materialization selection: %v", err)
	}
	availableViews := make(map[string]bool, len(viewsToRepair))
	for _, viewName := range viewsToRepair {
		availableViews[viewName] = true
	}
	repairLeaves := make(map[string][]viewLeaf)
	if selectionActive {
		if activeSelection.Operation != "sync" {
			return withExitCode(ExitConflict, "materialization operation %s blocks sync repair", activeSelection.Operation)
		}
		seenLeaves := make(map[string]struct{})
		for _, unit := range activeSelection.Units {
			if unit.Repo != projectionRepo.ID || unit.Kind != projectionRepo.Type {
				return withExitCode(ExitConflict, "durable sync materialization unit %s does not belong to repo %s", unit.ID, projectionRepo.ID)
			}
			if !availableViews[unit.Source] || projectionCfg.Views[unit.Source].Access == "" {
				return withExitCode(ExitConflict, "durable sync materialization source %s is no longer repairable", unit.Source)
			}
			switch projectionRepo.Type {
			case "apt":
				for _, arch := range projectionRepo.Arches {
					key := strings.Join([]string{unit.Source, projectionRepo.ID, unit.OS, arch}, "\x00")
					if _, exists := seenLeaves[key]; exists {
						continue
					}
					seenLeaves[key] = struct{}{}
					repairLeaves[unit.Source] = append(repairLeaves[unit.Source], viewLeaf{repo: projectionRepo, os: unit.OS, arch: arch})
				}
			case "yum":
				key := strings.Join([]string{unit.Source, projectionRepo.ID, unit.OS, unit.Arch}, "\x00")
				if _, exists := seenLeaves[key]; exists {
					continue
				}
				seenLeaves[key] = struct{}{}
				repairLeaves[unit.Source] = append(repairLeaves[unit.Source], viewLeaf{repo: projectionRepo, os: unit.OS, arch: unit.Arch})
			}
		}
		viewsToRepair = viewsToRepair[:0]
		for viewName := range repairLeaves {
			viewsToRepair = append(viewsToRepair, viewName)
		}
		sort.Strings(viewsToRepair)
		if len(viewsToRepair) == 0 {
			return withExitCode(ExitConflict, "durable sync materialization has no recoverable units")
		}
	}

	repairValues := values
	repairValues.recover = values.recover
	repairValues.repos = csvFlag{items: []string{projectionRepo.ID}}
	repairValues.arches = csvFlag{items: append([]string(nil), projectionRepo.Arches...)}
	if projectionRepo.Type == "apt" && projectionRepo.APT != nil {
		repairValues.oses = csvFlag{items: append([]string(nil), projectionRepo.APT.Suites...)}
	}
	trustLeaves := selectedLeaves([]config.Repo{projectionRepo}, repairValues)
	if selectionActive {
		trustLeaves = trustLeaves[:0]
		for _, viewName := range viewsToRepair {
			trustLeaves = append(trustLeaves, repairLeaves[viewName]...)
		}
	}
	repairValues.materializeTrust, err = captureMaterializationTrust(projectionCfg, trustLeaves, privateKey, repositoryKeySHA)
	if err != nil {
		return withExitCode(ExitConflict, "capture canonical sync-repair materialization trust: %v", err)
	}
	repairValues.materializeOperation = "sync"
	repairValues.materializeScope = syncMaterializationScope(source.ID, selectionSHA)
	requests := make([]materializationSelectionRequest, 0, len(viewsToRepair))
	for _, viewName := range viewsToRepair {
		leaves := trustLeaves
		if selectionActive {
			leaves = repairLeaves[viewName]
		}
		requests = append(requests, materializationSelectionRequest{
			Source: materializeCanonicalSource{ID: viewName, Public: projectionCfg.Views[viewName].Access == "public"},
			Leaves: leaves, TargetRoot: projectionCfg.Root, IncludeMetadata: true, ExpandAPT: true,
		})
	}
	repairValues, selectionOwner, err := beginMaterializationSelectionForRequests(projectionCfg, canonical, repairValues, "sync", requests)
	if err != nil {
		return withExitCode(ExitConflict, "begin sync-repair selected-set materialization: %v", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, finishMaterializationSelectedSet(projectionCfg, repairValues.materializeTrust, selectionOwner, resultErr))
	}()
	if source.Type == "apt" {
		ledgerStages := make(map[string]string)
		for _, viewName := range viewsToRepair {
			result, err := materializeAPTRepo(ctx, projectionCfg, canonical, pool, projectionRepo, viewName, txDir, repairValues, privateKey, passphrase)
			if err != nil {
				return withExitCode(ExitVerification, "repair APT repo %s view %s: %v", projectionRepo.ID, viewName, err)
			}
			if err := mergeAPTByHashStages(ledgerStages, result.Ledgers); err != nil {
				return withExitCode(ExitInternal, "merge recovered APT by-hash retention stages: %v", err)
			}
			fmt.Fprintf(stdout, "sync recovery upstream=%s repo=%s view=%s format=apt suites=%d packages=%d pruned=%d\n",
				source.ID, projectionRepo.ID, viewName, len(result.Builds), result.Packages.Entries, result.Reconciled.RemovedFiles)
		}
		commit, changed, err := persistAPTByHashStages(ctx, canonical, "sync", ledgerStages)
		if err != nil {
			return stateMutationError("commit recovered APT by-hash retention", err)
		}
		fmt.Fprintf(stdout, "sync recovery upstream=%s apt_by_hash_commit=%s changed=%t\n", source.ID, commit, changed)
		return nil
	}

	for _, viewName := range viewsToRepair {
		leaves := selectedLeaves([]config.Repo{projectionRepo}, repairValues)
		if selectionActive {
			leaves = repairLeaves[viewName]
		}
		for _, leaf := range leaves {
			osName, arch := leaf.os, leaf.arch
			ref, err := state.ViewRef(viewName, projectionRepo.ID, osName, arch)
			if err != nil {
				return withExitCode(ExitInternal, "%v", err)
			}
			if _, exists, err := canonical.Ref(ref); err != nil {
				return withExitCode(ExitInternal, "read %s: %v", ref, err)
			} else if !exists {
				continue
			}
			leaf := viewLeaf{repo: projectionRepo, os: osName, arch: arch}
			result, err := materializeYUMLeaf(ctx, projectionCfg, canonical, pool, projectionRepo, leaf, viewName, txDir, repairValues, privateKey, passphrase)
			if err != nil {
				return withExitCode(ExitVerification, "repair YUM repo %s/%s/%s view %s: %v", projectionRepo.ID, osName, arch, viewName, err)
			}
			fmt.Fprintf(stdout, "sync recovery upstream=%s repo=%s view=%s format=yum os=%s arch=%s packages=%d repomd_sha256=%s pruned=%d\n",
				source.ID, projectionRepo.ID, viewName, osName, arch, result.Generation.Packages, result.Generation.RepomdSHA256, result.Reconciled.RemovedFiles)
		}
	}
	return nil
}

func ingestSyncChangeSet(ctx context.Context, cfg *config.Config, repo config.Repo, source config.Upstream, values commonFlags, inputs stagedSyncInputs, privateKeyFile, passphraseFile string, stdout, stderr io.Writer, operation *syncOperation, progress *syncProgress, hooks syncExecutionHooks) error {
	if len(inputs.paths) == 0 {
		return nil
	}
	commit := progress.ProvenanceCommit
	ingestValues := values
	ingestValues.recover = values.recover
	ingestValues.repos = csvFlag{items: []string{repo.ID}}
	ingestValues.arches = csvFlag{items: append([]string(nil), source.Arches...)}
	contract := source
	ingestValues.syncInternal = true
	ingestValues.syncSelectionSHA256 = progress.SelectionSHA256
	ingestValues.syncUpstreamContract = &contract
	if source.Type == "apt" {
		ingestValues.oses = csvFlag{items: []string{source.Suite}}
		components := make([]string, 0, len(inputs.byComponent))
		for component := range inputs.byComponent {
			components = append(components, component)
		}
		sort.Strings(components)
		for _, component := range components {
			unit := "apt:" + component
			advanceSyncProgress(progress, syncPhaseIngesting, commit, unit, false)
			if err := operation.Write(progress); err != nil {
				return withExitCode(ExitInternal, "persist APT ingestion phase: %v", err)
			}
			if err := runAddDEBExpected(ctx, cfg, []config.Repo{repo}, inputs.byComponent[component], inputs.expected, ingestValues, component, privateKeyFile, passphraseFile, stdout, stderr); err != nil {
				return err
			}
			advanceSyncProgress(progress, syncPhaseProvenanceCommitted, commit, unit, true)
			if err := operation.Write(progress); err != nil {
				return withExitCode(ExitInternal, "persist completed APT component: %v", err)
			}
			if hooks.AfterAPTComponent != nil {
				if err := hooks.AfterAPTComponent(source, component); err != nil {
					return err
				}
			}
		}
		return nil
	}
	unit := "yum:" + repo.ID
	advanceSyncProgress(progress, syncPhaseIngesting, commit, unit, false)
	if err := operation.Write(progress); err != nil {
		return withExitCode(ExitInternal, "persist YUM ingestion phase: %v", err)
	}
	if err := runAddRPMExpected(ctx, cfg, []config.Repo{repo}, inputs.paths, inputs.expected, ingestValues, privateKeyFile, passphraseFile, stdout, stderr); err != nil {
		return err
	}
	advanceSyncProgress(progress, syncPhaseProvenanceCommitted, commit, unit, true)
	if err := operation.Write(progress); err != nil {
		return withExitCode(ExitInternal, "persist completed YUM ingestion: %v", err)
	}
	return nil
}

func syncProjectionViews(canonical *state.Store, cfg *config.Config, repo config.Repo) ([]string, error) {
	var result []string
	for _, viewName := range []string{"beta", "stable"} {
		viewConfig, exists := cfg.Views[viewName]
		if !exists || !viewIncludesRepo(viewConfig, repo.ID) {
			continue
		}
		var refs []plumbing.ReferenceName
		if repo.Type == "apt" {
			for _, suite := range repo.APT.Suites {
				for _, arch := range repo.Arches {
					ref, err := state.ViewRef(viewName, repo.ID, suite, arch)
					if err != nil {
						return nil, err
					}
					refs = append(refs, ref)
				}
			}
		} else {
			osName := "el" + fmt.Sprint(repo.OS.Major)
			for _, arch := range repo.Arches {
				ref, err := state.ViewRef(viewName, repo.ID, osName, arch)
				if err != nil {
					return nil, err
				}
				refs = append(refs, ref)
			}
		}
		sort.Slice(refs, func(i, j int) bool { return refs[i] < refs[j] })
		for _, ref := range refs {
			if _, exists, err := canonical.Ref(ref); err != nil {
				return nil, err
			} else if exists {
				result = append(result, viewName)
				break
			}
		}
	}
	return result, nil
}
