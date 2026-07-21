package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
)

const (
	assetProjectionIntentSchema   = "sow-asset-projection-intent/v1"
	assetProjectionIntentRelative = "asset-projection-intent.json"
	assetProjectionIntentMaxBytes = 1 << 20
	assetProjectionStagePrefix    = "asset-projection-stage-"
)

var assetProjectionTransactionIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// assetProjectionMutationHook is a deterministic process-crash seam. The
// durable intent is production state; only this callback is test-only.
var assetProjectionMutationHook func(string) error

// projectionIntentRemovalHook is a deterministic replacement seam between
// validating a durable projection intent and committing its removal. The
// pathname remains production state; only this callback is test-only.
var projectionIntentRemovalHook func(string) error

type assetProjectionIntent struct {
	Schema          string                          `json:"schema"`
	ID              string                          `json:"id"`
	Operation       string                          `json:"operation"`
	OperationScope  string                          `json:"operation_scope,omitempty"`
	TransactionID   string                          `json:"transaction_id"`
	Message         string                          `json:"message"`
	ConfigSHA256    string                          `json:"config_sha256"`
	ConfigSize      int64                           `json:"config_size"`
	ConfigStage     string                          `json:"config_stage_relative"`
	ExpectedHead    string                          `json:"expected_head"`
	ExpectedRef     string                          `json:"expected_ref"`
	Repo            string                          `json:"repo"`
	View            string                          `json:"view"`
	ViewPath        string                          `json:"view_path"`
	ViewRef         string                          `json:"view_ref"`
	TargetSHA256    string                          `json:"target_sha256"`
	ManifestSHA256  string                          `json:"manifest_sha256"`
	ManifestSize    int64                           `json:"manifest_size"`
	StageRelative   string                          `json:"stage_relative"`
	ArchiveAdoption *offlineArchiveAdoptionContract `json:"archive_adoption,omitempty"`
}

func assetProjectionIntentMessage(operation, operationScope, repo, transactionID string, archive *offlineArchiveAdoptionContract) string {
	scope := operationScope
	if scope == "" {
		scope = "ordinary"
	}
	archiveID := "none"
	if archive != nil {
		archiveID = archive.ID
	}
	return fmt.Sprintf("sow %s: asset %s projection %s scope=%s archive=%s", operation, repo, transactionID, scope, archiveID)
}

func assetProjectionIntentID(intent assetProjectionIntent) (string, error) {
	intent.ID = ""
	body, err := json.Marshal(intent)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

func (intent assetProjectionIntent) validate() error {
	validView := intent.View == "beta" || intent.View == "stable" || intent.Operation == "rm" && intent.View == "latest"
	if intent.Schema != assetProjectionIntentSchema || !validMaterializationTrustSHA256(intent.ID) ||
		!materializationOperationPattern.MatchString(intent.Operation) ||
		(intent.OperationScope != "" && !validMaterializationJournalString(intent.OperationScope, 256)) ||
		!assetProjectionTransactionIDPattern.MatchString(intent.TransactionID) ||
		!validMaterializationJournalString(intent.Message, 1024) || !validMaterializationTrustSHA256(intent.ConfigSHA256) ||
		intent.ConfigSize <= 0 || intent.ConfigStage != assetProjectionStagePrefix+intent.TransactionID+"-config.yaml" ||
		!materializationCommitPattern.MatchString(intent.ExpectedHead) || !materializationCommitPattern.MatchString(intent.ExpectedRef) ||
		!validMaterializationJournalString(intent.Repo, 256) || !validView ||
		!validOfflineArchivePath(intent.ViewPath) || !strings.HasPrefix(intent.ViewRef, "refs/sow/views/") ||
		!validMaterializationTrustSHA256(intent.TargetSHA256) || !validMaterializationTrustSHA256(intent.ManifestSHA256) ||
		intent.ManifestSize < 0 || intent.StageRelative != assetProjectionStagePrefix+intent.TransactionID+".tsv" {
		return errors.New("invalid pending asset projection intent envelope")
	}
	if plumbing.ReferenceName(intent.ViewRef).Validate() != nil {
		return errors.New("invalid pending asset projection ref")
	}
	if intent.Message != assetProjectionIntentMessage(intent.Operation, intent.OperationScope, intent.Repo, intent.TransactionID, intent.ArchiveAdoption) {
		return errors.New("pending asset projection message does not bind its operation contract")
	}
	if intent.OperationScope == offlineArchiveAdoptionMaterializationScope {
		if intent.Operation != "materialize" || intent.ArchiveAdoption == nil {
			return errors.New("offline archive pending projection omits its contract")
		}
		if err := intent.ArchiveAdoption.validate(); err != nil {
			return err
		}
	} else if intent.ArchiveAdoption != nil {
		return errors.New("archive contract is attached to another pending projection scope")
	}
	wanted, err := assetProjectionIntentID(intent)
	if err != nil || wanted != intent.ID {
		return errors.Join(err, errors.New("pending asset projection intent ID mismatch"))
	}
	return nil
}

func prepareAssetProjectionIntent(cfg *config.Config, canonical *state.Store, operation, operationScope string, repo config.Repo, viewName, viewPath string, viewRef plumbing.ReferenceName, expected plumbing.Hash, staged string, archive *offlineArchiveAdoptionContract) (assetProjectionIntent, string, error) {
	var intent assetProjectionIntent
	if cfg == nil || canonical == nil {
		return intent, "", errors.New("pending asset projection state is unavailable")
	}
	if _, exists, err := readAssetProjectionIntent(cfg.StatePath()); err != nil || exists {
		return intent, "", errors.Join(err, errors.New("another pending asset projection intent already exists"))
	}
	transactionID, err := state.NewTransactionID()
	if err != nil {
		return intent, "", err
	}
	stageRelative := assetProjectionStagePrefix + transactionID + ".tsv"
	stageAbsolute := filepath.Join(cfg.StatePath(), stageRelative)
	object, err := installPendingAssetProjectionStage(cfg.StatePath(), stageRelative, staged)
	if err != nil {
		return intent, "", err
	}
	committed := false
	configStageRelative := assetProjectionStagePrefix + transactionID + "-config.yaml"
	configStageAbsolute := filepath.Join(cfg.StatePath(), configStageRelative)
	defer func() {
		if !committed {
			_ = os.Remove(stageAbsolute)
			_ = os.Remove(configStageAbsolute)
			_ = syncLocalDirectory(cfg.StatePath())
		}
	}()
	head, err := canonical.HeadHash()
	if err != nil {
		return intent, "", err
	}
	canonicalConfig, err := cfg.Canonical()
	if err != nil {
		return intent, "", err
	}
	configDigest := sha256.Sum256(canonicalConfig)
	configSHA := hex.EncodeToString(configDigest[:])
	if err := writeDerivedStateFile(cfg.StatePath(), configStageRelative, canonicalConfig); err != nil {
		return intent, "", err
	}
	targetSHA, err := materializationTargetSHA256(cfg.Root)
	if err != nil {
		return intent, "", err
	}
	intent = assetProjectionIntent{
		Schema: assetProjectionIntentSchema, Operation: operation, OperationScope: operationScope,
		TransactionID: transactionID, Message: assetProjectionIntentMessage(operation, operationScope, repo.ID, transactionID, archive),
		ConfigSHA256: configSHA, ConfigSize: int64(len(canonicalConfig)), ConfigStage: configStageRelative,
		ExpectedHead: head.String(), ExpectedRef: expected.String(), Repo: repo.ID, View: viewName,
		ViewPath: viewPath, ViewRef: viewRef.String(), TargetSHA256: targetSHA, ManifestSHA256: object.HashString(),
		ManifestSize: object.Size, StageRelative: stageRelative, ArchiveAdoption: cloneOfflineArchiveAdoptionContract(archive),
	}
	intent.ID, _ = assetProjectionIntentID(intent)
	if err := writeAssetProjectionIntent(cfg.StatePath(), intent); err != nil {
		return assetProjectionIntent{}, "", err
	}
	committed = true
	return intent, stageAbsolute, nil
}

func installPendingAssetProjectionStage(stateRoot, relative, source string) (repository.Object, error) {
	var result repository.Object
	inspected, err := inspectOfflineArchiveInput(source)
	if err != nil {
		return result, err
	}
	root, err := os.OpenRoot(stateRoot)
	if err != nil {
		return result, err
	}
	defer root.Close()
	if _, err := root.Lstat(relative); err == nil {
		return result, errors.New("pending asset projection stage already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, err
	}
	temporary := relative + ".tmp"
	_ = root.Remove(temporary)
	input, err := os.Open(source)
	if err != nil {
		return result, err
	}
	output, err := root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		input.Close()
		return result, err
	}
	installed := false
	defer func() {
		input.Close()
		output.Close()
		if !installed {
			_ = root.Remove(temporary)
		}
	}()
	hasher := sha256.New()
	written, copyErr := io.CopyBuffer(io.MultiWriter(output, hasher), input, make([]byte, 256*1024))
	closeErr := errors.Join(input.Close(), output.Sync(), output.Close())
	if copyErr != nil || closeErr != nil || written != inspected.Object.Size || hex.EncodeToString(hasher.Sum(nil)) != inspected.Object.HashString() {
		return result, errors.Join(copyErr, closeErr, errors.New("pending asset projection stage differs from admitted manifest"))
	}
	if err := root.Rename(temporary, relative); err != nil {
		return result, err
	}
	installed = true
	directory, err := root.Open(".")
	if err != nil {
		return result, err
	}
	if err := errors.Join(directory.Sync(), directory.Close()); err != nil {
		return result, err
	}
	return inspected.Object, nil
}

func writeAssetProjectionIntent(stateRoot string, intent assetProjectionIntent) error {
	if err := intent.validate(); err != nil {
		return err
	}
	body, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	if len(body) > assetProjectionIntentMaxBytes {
		return errors.New("pending asset projection intent exceeds size limit")
	}
	return writeDerivedStateFile(stateRoot, assetProjectionIntentRelative, body)
}

func readAssetProjectionIntent(stateRoot string) (assetProjectionIntent, bool, error) {
	var intent assetProjectionIntent
	filename := filepath.Join(stateRoot, assetProjectionIntentRelative)
	info, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return intent, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > assetProjectionIntentMaxBytes {
		return intent, false, errors.Join(err, errors.New("pending asset projection intent is not a private exact regular file"))
	}
	body, err := readBoundedExactRegularFile(stateRoot, assetProjectionIntentRelative, assetProjectionIntentMaxBytes)
	if err != nil {
		return intent, false, err
	}
	intent, err = decodeAssetProjectionIntent(body)
	return intent, err == nil, err
}

func removeAssetProjectionIntent(stateRoot string, intent assetProjectionIntent) error {
	if err := removeExactProjectionIntent(stateRoot, assetProjectionIntentRelative, assetProjectionIntentMaxBytes, func(body []byte) error {
		current, err := decodeAssetProjectionIntent(body)
		if err != nil || current.ID != intent.ID {
			return errors.Join(err, errors.New("pending asset projection intent changed before completion"))
		}
		return nil
	}); err != nil {
		return err
	}
	stage := filepath.Join(stateRoot, intent.StageRelative)
	if err := os.Remove(stage); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Remove(filepath.Join(stateRoot, intent.ConfigStage)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncLocalDirectory(stateRoot)
}

func decodeAssetProjectionIntent(body []byte) (assetProjectionIntent, error) {
	var intent assetProjectionIntent
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&intent); err != nil {
		return assetProjectionIntent{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return assetProjectionIntent{}, errors.New("pending asset projection intent has trailing content")
	}
	return intent, intent.validate()
}

func cleanupAssetProjectionIntentResidue(stateRoot string, recover bool) error {
	entries, err := os.ReadDir(stateRoot)
	if err != nil {
		return err
	}
	intent, exists, readErr := readAssetProjectionIntent(stateRoot)
	if readErr != nil {
		return readErr
	}
	removed := false
	for _, entry := range entries {
		name := entry.Name()
		isTemporary := strings.HasPrefix(name, assetProjectionIntentRelative+".tmp-") ||
			strings.HasPrefix(name, assetProjectionStagePrefix) && (strings.HasSuffix(name, ".tmp") || strings.Contains(name, ".tmp-"))
		isProjectionStage := strings.HasPrefix(name, assetProjectionStagePrefix) && (strings.HasSuffix(name, ".tsv") || strings.HasSuffix(name, "-config.yaml"))
		isWantedStage := exists && (name == intent.StageRelative || name == intent.ConfigStage)
		isOrphanStage := isProjectionStage && !isWantedStage
		if !isTemporary && !isOrphanStage {
			continue
		}
		if !recover {
			return errors.New("interrupted pending asset projection residue requires --recover")
		}
		info, err := os.Lstat(filepath.Join(stateRoot, name))
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return errors.Join(err, fmt.Errorf("unsafe pending asset projection residue %s", name))
		}
		if err := os.Remove(filepath.Join(stateRoot, name)); err != nil {
			return err
		}
		removed = true
	}
	if removed {
		return syncLocalDirectory(stateRoot)
	}
	return nil
}

func requireAssetProjectionIntentMatchesConfig(cfg *config.Config, intent assetProjectionIntent) (config.Repo, plumbing.ReferenceName, error) {
	if cfg == nil {
		return config.Repo{}, "", errors.New("configuration is unavailable")
	}
	configSHA, err := cfg.CanonicalSHA256()
	if err != nil || configSHA != intent.ConfigSHA256 {
		return config.Repo{}, "", errors.Join(err, errors.New("pending asset projection configuration changed"))
	}
	repo, exists := cfg.RepoByName(intent.Repo)
	if !exists || !repo.IsActive() || repo.Type != "asset" || repo.Asset == nil {
		return config.Repo{}, "", errors.New("pending asset projection repo is not an active asset repository")
	}
	wantedView := intent.View
	if intent.Operation != "rm" {
		wantedView = "beta"
		if repo.DefaultPool == "gated" {
			wantedView = "stable"
		}
	} else {
		view, exists := cfg.Views[wantedView]
		if !exists || view.AppendOnly || !viewIncludesRepo(view, repo.ID) {
			return config.Repo{}, "", errors.New("pending asset removal view is no longer a mutable repository member")
		}
	}
	wantedPath, _ := state.ViewPath(wantedView, repo.ID, "all", "all")
	wantedRef, _ := state.ViewRef(wantedView, repo.ID, "all", "all")
	targetSHA, targetErr := materializationTargetSHA256(cfg.Root)
	if targetErr != nil || intent.View != wantedView || intent.ViewPath != wantedPath || intent.ViewRef != wantedRef.String() || intent.TargetSHA256 != targetSHA {
		return config.Repo{}, "", errors.Join(targetErr, errors.New("pending asset projection coordinates differ from configuration"))
	}
	if intent.ArchiveAdoption != nil {
		if err := requireOfflineArchiveAdoptionContract(cfg, state.New(cfg.StatePath()), intent.ArchiveAdoption); err != nil {
			return config.Repo{}, "", err
		}
	}
	return repo, wantedRef, nil
}

func verifyPendingAssetProjectionStage(cfg *config.Config, intent assetProjectionIntent) (string, error) {
	stage := filepath.Join(cfg.StatePath(), intent.StageRelative)
	inspected, err := inspectOfflineArchiveInput(stage)
	if err != nil || inspected.Object.HashString() != intent.ManifestSHA256 || inspected.Object.Size != intent.ManifestSize {
		return "", errors.Join(err, errors.New("pending asset projection staged manifest differs from intent"))
	}
	configStage := filepath.Join(cfg.StatePath(), intent.ConfigStage)
	configObject, err := inspectOfflineArchiveInput(configStage)
	if err != nil || configObject.Object.HashString() != intent.ConfigSHA256 || configObject.Object.Size != intent.ConfigSize {
		return "", errors.Join(err, errors.New("pending asset projection staged config differs from intent"))
	}
	return stage, nil
}

func transactionProjectionTargetMatches(record state.TransactionRecord, target plumbing.Hash) bool {
	switch record.Phase {
	case "intent":
		return target.IsZero() && record.Commit.IsZero()
	case "committed", "complete":
		return !record.Commit.IsZero() && target == record.Commit
	default:
		return false
	}
}

func requireAssetProjectionTransactionCompatible(cfg *config.Config, intent assetProjectionIntent, record state.TransactionRecord, exists bool) error {
	if !exists {
		return nil
	}
	if record.Operation != intent.Operation || record.Message != intent.Message || record.ExpectedHead.String() != intent.ExpectedHead || len(record.Refs) != 1 {
		return errors.New("pending asset projection differs from its pre-existing local transaction")
	}
	ref := record.Refs[0]
	if ref.Name.String() != intent.ViewRef || ref.Expected.String() != intent.ExpectedRef || ref.Delete || ref.Immutable || !transactionProjectionTargetMatches(record, ref.Target) {
		return errors.New("pending asset projection ref differs from its pre-existing local transaction")
	}
	canonicalConfig, err := cfg.Canonical()
	if err != nil {
		return err
	}
	wantedFiles := map[string]state.TransactionFileRecord{
		intent.ViewPath:   {Canonical: intent.ViewPath, Size: intent.ManifestSize, SHA256: intent.ManifestSHA256},
		"config/sow.yaml": {Canonical: "config/sow.yaml", Size: int64(len(canonicalConfig)), SHA256: intent.ConfigSHA256},
	}
	if len(record.Files) != len(wantedFiles) {
		return errors.New("pending asset projection file set differs from its pre-existing local transaction")
	}
	for _, file := range record.Files {
		wanted, exists := wantedFiles[file.Canonical]
		if !exists || file.Delete || file.Size != wanted.Size || file.SHA256 != wanted.SHA256 {
			return errors.New("pending asset projection file identity differs from its pre-existing local transaction")
		}
	}
	return nil
}

func requireProjectionTransactionsCompatibleBeforeRecovery(cfg *config.Config, canonical *state.Store, operation string) error {
	assetIntent, assetExists, err := readAssetProjectionIntent(cfg.StatePath())
	if err != nil {
		return err
	}
	if assetExists && assetIntent.Operation == operation {
		record, exists, err := canonical.Transaction(assetIntent.TransactionID)
		if err != nil {
			return err
		}
		if err := requireAssetProjectionTransactionCompatible(cfg, assetIntent, record, exists); err != nil {
			return err
		}
	}
	packageIntent, packageExists, err := readPackageProjectionIntent(cfg.StatePath())
	if err != nil {
		return err
	}
	if packageExists && packageIntent.Operation == operation {
		record, exists, err := canonical.Transaction(packageIntent.TransactionID)
		if err != nil {
			return err
		}
		if err := requirePackageProjectionTransactionCompatible(cfg, packageIntent, record, exists); err != nil {
			return err
		}
	}
	return nil
}

func preflightPendingAssetProjection(cfg *config.Config, canonical *state.Store, operation string) error {
	intent, exists, err := readAssetProjectionIntent(cfg.StatePath())
	if err != nil || !exists {
		return err
	}
	if intent.Operation != operation {
		return fmt.Errorf("pending asset projection %s blocks %s", intent.Operation, operation)
	}
	repo, _, err := requireAssetProjectionIntentMatchesConfig(cfg, intent)
	if err != nil {
		return err
	}
	stage, err := verifyPendingAssetProjectionStage(cfg, intent)
	if err != nil {
		return err
	}
	stagedView, err := os.Open(stage)
	if err != nil {
		return err
	}
	leaf := viewLeaf{repo: repo, os: "all", arch: "all"}
	validateErr := validateViewEntries(canonical, stagedView, leaf, cfg.Views[intent.View].Access == "public")
	closeErr := stagedView.Close()
	if validateErr != nil || closeErr != nil {
		return errors.Join(validateErr, closeErr, errors.New("pending asset projection staged view violates current confidentiality closure"))
	}
	return nil
}

func recoverPendingAssetProjectionLocked(ctx context.Context, cfg *config.Config, canonical *state.Store, values commonFlags, operation string, stdout io.Writer) (bool, error) {
	if err := cleanupAssetProjectionIntentResidue(cfg.StatePath(), values.recover); err != nil {
		return false, err
	}
	intent, exists, err := readAssetProjectionIntent(cfg.StatePath())
	if err != nil || !exists {
		return false, err
	}
	if !values.recover {
		return true, fmt.Errorf("pending asset projection %s requires --recover", intent.Operation)
	}
	if intent.Operation != operation {
		return true, fmt.Errorf("pending asset projection %s blocks %s", intent.Operation, operation)
	}
	repo, viewRef, err := requireAssetProjectionIntentMatchesConfig(cfg, intent)
	if err != nil {
		return true, err
	}
	stage, err := verifyPendingAssetProjectionStage(cfg, intent)
	if err != nil {
		return true, err
	}
	leaf := viewLeaf{repo: repo, os: "all", arch: "all"}
	stagedView, err := os.Open(stage)
	if err != nil {
		return true, err
	}
	validateErr := validateViewEntries(canonical, stagedView, leaf, cfg.Views[intent.View].Access == "public")
	closeErr := stagedView.Close()
	if validateErr != nil || closeErr != nil {
		return true, errors.Join(validateErr, closeErr, errors.New("pending asset projection staged view violates current confidentiality closure"))
	}
	record, transactionExists, err := canonical.Transaction(intent.TransactionID)
	if err != nil {
		return true, err
	}
	if !transactionExists {
		head, err := canonical.HeadHash()
		if err != nil || head.String() != intent.ExpectedHead {
			return true, errors.Join(err, errors.New("pending asset projection pre-commit HEAD changed"))
		}
		current, refExists, err := canonical.Ref(viewRef)
		expected := plumbing.NewHash(intent.ExpectedRef)
		if err != nil || refExists != !expected.IsZero() || refExists && current != expected {
			return true, errors.Join(err, errors.New("pending asset projection pre-commit ref changed"))
		}
		txDir, err := newTransactionDir(cfg.StatePath(), "asset-projection-reapply-")
		if err != nil {
			return true, err
		}
		defer os.RemoveAll(txDir)
		_, _, err = applyCanonicalConfig(ctx, cfg, canonical, intent.Operation, intent.Message,
			map[string]string{intent.ViewPath: stage, "config/sow.yaml": filepath.Join(cfg.StatePath(), intent.ConfigStage)},
			[]state.RefUpdate{{Name: viewRef, Expected: expected}}, state.ApplyOptions{TransactionID: intent.TransactionID})
		if err != nil {
			return true, err
		}
		record, transactionExists, err = canonical.Transaction(intent.TransactionID)
		if err != nil || !transactionExists {
			return true, errors.Join(err, errors.New("reapplied pending asset projection transaction is missing"))
		}
	}
	if record.Phase != "complete" || record.Operation != intent.Operation || record.Message != intent.Message || record.Commit.IsZero() {
		return true, errors.New("pending asset projection transaction did not recover to its exact completed commit")
	}
	if err := requireAssetProjectionTransactionCompatible(cfg, intent, record, true); err != nil {
		return true, err
	}
	if record.ExpectedHead.String() != intent.ExpectedHead || len(record.Refs) != 1 || record.Refs[0].Name.String() != intent.ViewRef ||
		record.Refs[0].Expected.String() != intent.ExpectedRef || record.Refs[0].Target != record.Commit || record.Refs[0].Delete || record.Refs[0].Immutable {
		return true, errors.New("pending asset projection old-state coordinates differ from its local transaction")
	}
	commit := record.Commit
	current, refExists, err := canonical.Ref(viewRef)
	if err != nil || !refExists || current != commit {
		return true, errors.Join(err, errors.New("pending asset projection ref differs from recovered transaction commit"))
	}
	reader, err := canonical.OpenPathAt(commit, intent.ViewPath)
	if err != nil {
		return true, err
	}
	hasher := sha256.New()
	size, hashErr := io.Copy(hasher, reader)
	closeErr = reader.Close()
	if hashErr != nil || closeErr != nil || size != intent.ManifestSize || hex.EncodeToString(hasher.Sum(nil)) != intent.ManifestSHA256 {
		return true, errors.Join(hashErr, closeErr, errors.New("recovered asset projection commit differs from pending manifest"))
	}
	if intent.ArchiveAdoption != nil {
		if err := requireOfflineArchiveDestinationEntry(canonical, intent.ArchiveAdoption, commit); err != nil {
			return true, err
		}
	}
	trust, err := captureMaterializationTrust(cfg, []viewLeaf{leaf}, nil, "")
	if err != nil {
		return true, err
	}
	trust.archiveAdoption = cloneOfflineArchiveAdoptionContract(intent.ArchiveAdoption)
	recoveryValues := values
	recoveryValues.materializeTrust = trust
	recoveryValues.materializeOperation = intent.Operation
	recoveryValues.materializeScope = intent.OperationScope
	recoveryValues.offlineArchiveAdoption = cloneOfflineArchiveAdoptionContract(intent.ArchiveAdoption)
	txDir, err := newTransactionDir(cfg.StatePath(), "asset-projection-recover-")
	if err != nil {
		return true, err
	}
	defer os.RemoveAll(txDir)
	pool, err := repository.NewStore(cfg.Root)
	if err != nil {
		return true, err
	}
	materialized, reconciled, err := materializeAssetView(ctx, cfg, canonical, pool, repo, intent.View, txDir, recoveryValues)
	if err != nil {
		return true, err
	}
	if intent.Operation == "rm" && intent.View == "latest" {
		if _, _, err := refreshWorkingTreeBaselines(ctx, cfg, canonical, []config.Repo{repo}, txDir, recoveryValues, "rm-working-tree", state.ApplyOptions{}, stdout); err != nil {
			return true, err
		}
	}
	if err := rebuildCatalogProjection(ctx, cfg, stdout); err != nil {
		return true, err
	}
	if err := removeAssetProjectionIntent(cfg.StatePath(), intent); err != nil {
		return true, err
	}
	fmt.Fprintf(stdout, "recovered pending asset projection operation=%s repo=%s view=%s commit=%s entries=%d linked=%d existing=%d relinked=%d pruned=%d\n",
		intent.Operation, repo.ID, intent.View, commit, materialized.Entries, materialized.Linked, materialized.Existing, materialized.Relinked, reconciled.RemovedFiles)
	if intent.Operation == "add" {
		fmt.Fprintf(stdout, "recovered asset add repo=%s view=%s entries=%d linked=%d existing=%d relinked=%d pruned=%d\n",
			repo.ID, intent.View, materialized.Entries, materialized.Linked, materialized.Existing, materialized.Relinked, reconciled.RemovedFiles)
	}
	return true, nil
}
