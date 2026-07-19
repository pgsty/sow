package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
)

const offlineArchiveAdoptionMaterializationScope = "offline-archive-adoption-v1"

// offlineArchiveAfterProjectionBeforeAdoptionHook is a process-stop seam used
// by SIGKILL tests. Production leaves it nil.
var offlineArchiveAfterProjectionBeforeAdoptionHook func(offlineArchiveProjectionIntent) error

func completeOfflineArchiveProjectionAdoption(
	ctx context.Context,
	cfg *config.Config,
	canonical *state.Store,
	intent offlineArchiveProjectionIntent,
	values commonFlags,
	stdout io.Writer,
) error {
	if intent.ArchiveAdoption == nil {
		return errors.New("offline archive projection has no adoption contract")
	}
	current, exists, err := readOfflineArchiveProjectionIntent(cfg.StatePath())
	if err != nil || !exists || current.ID != intent.ID || !offlineArchiveAdoptionContractEqual(current.ArchiveAdoption, intent.ArchiveAdoption) {
		return errors.Join(err, errors.New("offline archive adoption owner changed before completion"))
	}
	if err := requireOfflineArchiveAdoptionContract(cfg, canonical, intent.ArchiveAdoption); err != nil {
		return fmt.Errorf("verify frozen offline archive adoption contract: %w", err)
	}
	repo, exists := cfg.RepoByName(intent.ArchiveAdoption.Destination.Repo)
	if !exists || !repo.IsActive() || repo.Type != "asset" || repo.Asset == nil {
		return fmt.Errorf("offline archive adoption repo %s is not active", intent.ArchiveAdoption.Destination.Repo)
	}
	prefix := strings.TrimSuffix(repo.Path, "/") + "/"
	if !strings.HasPrefix(intent.ArchiveAdoption.Destination.Path, prefix) {
		return errors.New("offline archive adoption destination is outside its configured repo")
	}
	destinationRelative := strings.TrimPrefix(intent.ArchiveAdoption.Destination.Path, prefix)
	txDir, err := newTransactionDir(cfg.StatePath(), "materialize-archive-adopt-")
	if err != nil {
		return withExitCode(ExitInternal, "create offline archive adoption transaction: %v", err)
	}
	defer os.RemoveAll(txDir)
	adoptionValues := values
	adoptionValues.materializeTrust = nil
	adoptionValues.materializeScope = offlineArchiveAdoptionMaterializationScope
	adoptionValues.materializeTarget = ""
	adoptionValues.offlineArchiveAdoption = cloneOfflineArchiveAdoptionContract(intent.ArchiveAdoption)
	if err := addAssetFiles(ctx, cfg, []config.Repo{repo}, []string{intent.Destination}, nil, adoptionValues, destinationRelative, false, canonical, txDir, "materialize", stdout); err != nil {
		return err
	}
	if err := removeOfflineArchiveProjectionIntent(cfg.StatePath(), intent); err != nil {
		return withExitCode(ExitConflict, "complete offline archive adoption owner: %v", err)
	}
	fmt.Fprintf(stdout, "archive adopted repo=%s dest=%s sha256=%s\n", repo.ID, destinationRelative, intent.ArchiveSHA256)
	return nil
}

// recoverOfflineArchiveAdoptionMaterialization converges the second local
// transaction created by materialize --tgz --asset-repo before the current CLI
// selectors are allowed to start new work. The archive bytes and canonical
// asset ref were committed before this journal was written, so recovery needs
// only the frozen asset unit and CAS; it deliberately does not rebuild or
// re-adopt the archive.
func recoverOfflineArchiveAdoptionMaterialization(
	ctx context.Context,
	cfg *config.Config,
	canonical *state.Store,
	values commonFlags,
	stdout io.Writer,
) (bool, error) {
	journal, exists, err := readMaterializationSelectionJournal(cfg.StatePath())
	if err != nil || !exists || journal.OperationScope != offlineArchiveAdoptionMaterializationScope {
		return false, err
	}
	if !values.recover {
		return true, withExitCode(ExitConflict, "offline archive adoption requires retry with --recover")
	}
	repo, viewName, err := decodeOfflineArchiveAdoptionMaterialization(cfg, journal)
	if err != nil {
		return true, withExitCode(ExitConflict, "decode offline archive adoption materialization: %v", err)
	}
	if err := requireOfflineArchiveAdoptionContract(cfg, canonical, journal.ArchiveAdoption); err != nil {
		return true, withExitCode(ExitConflict, "verify frozen offline archive adoption contract: %v", err)
	}
	destinationCommit := plumbing.NewHash(journal.Units[0].Refs[0].Commit)
	if err := requireOfflineArchiveDestinationEntry(canonical, journal.ArchiveAdoption, destinationCommit); err != nil {
		return true, withExitCode(ExitConflict, "verify frozen offline archive destination entry: %v", err)
	}
	receipt, err := requireOfflineArchiveTaintAdmission(canonical, repo, journal.ArchiveAdoption.ArchiveSHA256, journal.ArchiveAdoption.ArchiveSize)
	if err != nil || receipt == nil {
		return true, withExitCode(ExitConflict, "verify canonical offline archive taint receipt: %v", errors.Join(err, errors.New("receipt is missing")))
	}
	leaf := viewLeaf{repo: repo, os: "all", arch: "all"}
	trust, err := captureMaterializationTrust(cfg, []viewLeaf{leaf}, nil, "")
	if err != nil {
		return true, withExitCode(ExitConfig, "capture offline archive adoption trust: %v", err)
	}
	trust.archiveAdoption = cloneOfflineArchiveAdoptionContract(journal.ArchiveAdoption)
	recoveryValues := values
	recoveryValues.materializeTrust = trust
	recoveryValues.materializeOperation = "materialize"
	recoveryValues.materializeScope = offlineArchiveAdoptionMaterializationScope
	recoveryValues.materializeSource = ""
	recoveryValues.materializeTarget = ""
	recoveryValues.materializeUnit = ""
	recoveryValues.offlineArchiveAdoption = cloneOfflineArchiveAdoptionContract(journal.ArchiveAdoption)

	txDir, err := newTransactionDir(cfg.StatePath(), "materialize-archive-recover-")
	if err != nil {
		return true, withExitCode(ExitInternal, "create offline archive adoption recovery transaction: %v", err)
	}
	defer os.RemoveAll(txDir)
	pool, err := repository.NewStore(cfg.Root)
	if err != nil {
		return true, withExitCode(ExitConflict, "open CAS for offline archive adoption recovery: %v", err)
	}
	digest, err := repository.ParseDigest(journal.ArchiveAdoption.ArchiveSHA256)
	if err != nil {
		return true, withExitCode(ExitConflict, "parse offline archive adoption recovery digest: %v", err)
	}
	inspected, err := inspectOfflineArchiveInputContext(ctx, pool.ObjectPath(digest))
	if err != nil || inspected.Object.HashString() != journal.ArchiveAdoption.ArchiveSHA256 || inspected.Object.Size != journal.ArchiveAdoption.ArchiveSize {
		return true, withExitCode(ExitConflict, "inspect offline archive adoption recovery bytes: %v", errors.Join(err, errors.New("CAS object differs from contract")))
	}
	if err := requireOfflineArchiveMarkerAdmission(inspected.Marker, repo, receipt, &journal.ArchiveAdoption.Source); err != nil {
		return true, withExitCode(ExitConflict, "verify offline archive adoption recovery marker: %v", err)
	}
	materialized, reconciled, err := materializeAssetView(ctx, cfg, canonical, pool, repo, viewName, txDir, recoveryValues)
	if err != nil {
		return true, withExitCode(ExitVerification, "recover offline archive adoption materialization: %v", err)
	}
	fmt.Fprintf(stdout, "recovered offline archive adoption repo=%s view=%s entries=%d linked=%d existing=%d pruned=%d\n",
		repo.ID, viewName, materialized.Entries, materialized.Linked, materialized.Existing, reconciled.RemovedFiles)
	return true, nil
}

func decodeOfflineArchiveAdoptionMaterialization(cfg *config.Config, journal materializationSelectionJournal) (config.Repo, string, error) {
	if cfg == nil {
		return config.Repo{}, "", errors.New("configuration is unavailable")
	}
	if journal.Operation != "materialize" || journal.OperationScope != offlineArchiveAdoptionMaterializationScope ||
		journal.RepositoryKeySHA256 != materializationNoRepositoryKeySHA256 || len(journal.YUMKeyrings) != 0 || len(journal.Units) != 1 || journal.ArchiveAdoption == nil {
		return config.Repo{}, "", errors.New("durable archive adoption envelope is not an exact asset-only materialization")
	}
	unit := journal.Units[0]
	if unit.Kind != "asset" || unit.Historical || unit.OS != "all" || unit.Arch != "all" || len(unit.Refs) != 1 {
		return config.Repo{}, "", errors.New("durable archive adoption unit has invalid asset coordinates")
	}
	repo, exists := cfg.RepoByName(unit.Repo)
	if !exists || !repo.IsActive() || repo.Type != "asset" || repo.Asset == nil {
		return config.Repo{}, "", fmt.Errorf("durable archive adoption repo %s is not an active asset repository", unit.Repo)
	}
	wantedView := "beta"
	if repo.DefaultPool == "gated" {
		wantedView = "stable"
	}
	view, exists := cfg.Views[wantedView]
	if !exists || !viewIncludesRepo(view, repo.ID) || unit.Source != wantedView {
		return config.Repo{}, "", fmt.Errorf("durable archive adoption source %s is not the configured destination for repo %s", unit.Source, repo.ID)
	}
	wantedRef, err := state.ViewRef(wantedView, repo.ID, "all", "all")
	if err != nil {
		return config.Repo{}, "", err
	}
	if unit.Refs[0].Name != wantedRef.String() {
		return config.Repo{}, "", errors.New("durable archive adoption ref does not match its asset coordinates")
	}
	targetSHA, err := materializationTargetSHA256(cfg.Root)
	if err != nil {
		return config.Repo{}, "", err
	}
	if unit.TargetSHA256 != targetSHA {
		return config.Repo{}, "", errors.New("durable archive adoption target is not the configured repository root")
	}
	if journal.ArchiveAdoption.Destination.Repo != repo.ID || journal.ArchiveAdoption.Destination.Pool != repo.DefaultPool ||
		journal.ArchiveAdoption.Destination.View != wantedView {
		return config.Repo{}, "", errors.New("durable archive adoption contract differs from its destination unit")
	}
	return repo, wantedView, nil
}
