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
	"github.com/pgsty/sow/internal/state"
)

const (
	offlineArchiveProjectionIntentSchema   = "sow-offline-archive-projection-intent/v1"
	offlineArchiveProjectionIntentRelative = "offline-archive-projection-intent.json"
	offlineArchiveProjectionIntentMaxBytes = 1 << 20
	offlineArchiveProjectionStageDir       = "offline-archive-projection"
	offlineArchiveProjectionStagePrefix    = "offline-archive-projection-stage-"
)

var offlineArchiveProjectionStagePattern = regexp.MustCompile(`^offline-archive-projection-stage-[0-9a-f]{32}\.tgz$`)

// offlineArchiveProjectionStageSync is replaceable only by focused durability
// tests. Production binds it to an fsync of the private stage directory.
var offlineArchiveProjectionStageSync = syncBoundArchiveDirectory

// offlineArchiveProjectionIntentWrite is replaceable only by focused
// durability tests that emulate rename success followed by directory-fsync
// failure.
var offlineArchiveProjectionIntentWrite = writeDerivedStateFile

// offlineArchiveProjectionIntent is the durable bridge between the canonical
// digest-level taint receipt and the operator-visible archive name. The stage
// is a second hard link to the completed 0444 inode below the private state
// root. Its directory entry is fsynced before this intent and before the
// receipt, so recovery never has to regenerate bytes from a mutable view.
type offlineArchiveProjectionIntent struct {
	Schema          string                          `json:"schema"`
	ID              string                          `json:"id"`
	TransactionID   string                          `json:"transaction_id"`
	ConfigSHA256    string                          `json:"config_sha256"`
	Source          offlineArchiveSourceProof       `json:"source"`
	ArchiveSHA256   string                          `json:"archive_sha256"`
	ArchiveSize     int64                           `json:"archive_size"`
	ArchiveEntries  int64                           `json:"archive_entries"`
	ArchiveBytes    int64                           `json:"archive_bytes"`
	StageRelative   string                          `json:"stage_relative"`
	Destination     string                          `json:"destination"`
	ValidationRoot  string                          `json:"validation_root"`
	ArchiveAdoption *offlineArchiveAdoptionContract `json:"archive_adoption,omitempty"`
}

func offlineArchiveProjectionIntentID(intent offlineArchiveProjectionIntent) (string, error) {
	intent.ID = ""
	body, err := json.Marshal(intent)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

func validArchiveProjectionAbsolutePath(value string) bool {
	return value != "" && len(value) <= 16*1024 && filepath.IsAbs(value) && filepath.Clean(value) == value && !strings.ContainsRune(value, 0)
}

func (intent offlineArchiveProjectionIntent) validate() error {
	if intent.Schema != offlineArchiveProjectionIntentSchema || !validMaterializationTrustSHA256(intent.ID) ||
		!assetProjectionTransactionIDPattern.MatchString(intent.TransactionID) || !validMaterializationTrustSHA256(intent.ConfigSHA256) ||
		!validMaterializationTrustSHA256(intent.ArchiveSHA256) || intent.ArchiveSize <= 0 || intent.ArchiveEntries < 0 || intent.ArchiveBytes < 0 ||
		intent.StageRelative != filepath.Join(offlineArchiveProjectionStageDir, offlineArchiveProjectionStagePrefix+intent.TransactionID+".tgz") ||
		!validArchiveProjectionAbsolutePath(intent.Destination) || !validArchiveProjectionAbsolutePath(intent.ValidationRoot) {
		return errors.New("invalid pending offline archive projection intent envelope")
	}
	if err := intent.Source.validate(); err != nil {
		return err
	}
	if intent.ArchiveAdoption != nil {
		if err := intent.ArchiveAdoption.validate(); err != nil {
			return err
		}
		if !offlineArchiveSourceProofEqual(intent.ArchiveAdoption.Source, intent.Source) ||
			intent.ArchiveAdoption.ArchiveSHA256 != intent.ArchiveSHA256 || intent.ArchiveAdoption.ArchiveSize != intent.ArchiveSize {
			return errors.New("pending offline archive projection adoption differs from its frozen archive")
		}
	}
	wanted, err := offlineArchiveProjectionIntentID(intent)
	if err != nil || wanted != intent.ID {
		return errors.Join(err, errors.New("pending offline archive projection intent ID mismatch"))
	}
	return nil
}

func writeOfflineArchiveProjectionIntent(stateRoot string, intent offlineArchiveProjectionIntent) error {
	if err := intent.validate(); err != nil {
		return err
	}
	body, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	if len(body) > offlineArchiveProjectionIntentMaxBytes {
		return errors.New("pending offline archive projection intent exceeds size limit")
	}
	return offlineArchiveProjectionIntentWrite(stateRoot, offlineArchiveProjectionIntentRelative, body)
}

func readOfflineArchiveProjectionIntent(stateRoot string) (offlineArchiveProjectionIntent, bool, error) {
	var intent offlineArchiveProjectionIntent
	filename := filepath.Join(stateRoot, offlineArchiveProjectionIntentRelative)
	info, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return intent, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 ||
		info.Size() <= 0 || info.Size() > offlineArchiveProjectionIntentMaxBytes {
		return intent, false, errors.Join(err, errors.New("pending offline archive projection intent is not a private exact regular file"))
	}
	body, err := readBoundedExactRegularFile(stateRoot, offlineArchiveProjectionIntentRelative, offlineArchiveProjectionIntentMaxBytes)
	if err != nil {
		return intent, false, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&intent); err != nil {
		return offlineArchiveProjectionIntent{}, false, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return offlineArchiveProjectionIntent{}, false, errors.New("pending offline archive projection intent has trailing content")
	}
	if err := intent.validate(); err != nil {
		return offlineArchiveProjectionIntent{}, false, err
	}
	return intent, true, nil
}

func installOfflineArchiveProjectionStage(stateRoot string, result archiveResult, transactionID string) (string, error) {
	stateAbs, err := archiveAbsolutePath(stateRoot)
	if err != nil {
		return "", err
	}
	stageAbs, err := archiveAbsolutePath(result.Stage)
	if err != nil {
		return "", err
	}
	sourceRelative, err := filepath.Rel(stateAbs, stageAbs)
	if err != nil || sourceRelative == ".." || strings.HasPrefix(sourceRelative, ".."+string(filepath.Separator)) || filepath.IsAbs(sourceRelative) {
		return "", errors.Join(err, errors.New("completed archive stage is outside private state"))
	}
	destinationName := offlineArchiveProjectionStagePrefix + transactionID + ".tgz"
	destinationRelative := filepath.Join(offlineArchiveProjectionStageDir, destinationName)
	root, err := os.OpenRoot(stateAbs)
	if err != nil {
		return "", err
	}
	defer root.Close()
	stageDirectoryCreated := false
	if info, err := root.Lstat(offlineArchiveProjectionStageDir); errors.Is(err, os.ErrNotExist) {
		if err := root.Mkdir(offlineArchiveProjectionStageDir, 0o700); err != nil {
			return "", err
		}
		stageDirectoryCreated = true
	} else if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return "", errors.Join(err, errors.New("offline archive projection stage directory is not private"))
	}
	if stageDirectoryCreated {
		if err := syncBoundArchiveDirectory(root); err != nil {
			return "", err
		}
	}
	if _, err := root.Lstat(destinationRelative); err == nil {
		return "", errors.New("offline archive projection stage already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := root.Link(sourceRelative, destinationRelative); err != nil {
		return "", err
	}
	committed := false
	defer func() {
		if !committed {
			_ = root.Remove(destinationRelative)
			_ = syncBoundArchiveDirectory(root)
		}
	}()
	expected := result
	expected.Stage = filepath.Join(stateAbs, destinationRelative)
	if err := requireBoundArchiveFile(root, destinationRelative, expected); err != nil {
		return "", err
	}
	// This fsync is the durable private-stage boundary. It precedes both the
	// operation intent and canonical taint receipt.
	stageRoot, err := root.OpenRoot(offlineArchiveProjectionStageDir)
	if err != nil {
		return "", err
	}
	defer stageRoot.Close()
	if err := offlineArchiveProjectionStageSync(stageRoot); err != nil {
		return "", err
	}
	committed = true
	return destinationRelative, nil
}

func prepareOfflineArchiveProjectionIntent(cfg *config.Config, source offlineArchiveSourceProof, result archiveResult, validationRoot string, adoption *offlineArchiveAdoptionContract) (offlineArchiveProjectionIntent, error) {
	var intent offlineArchiveProjectionIntent
	if cfg == nil {
		return intent, errors.New("offline archive projection configuration is unavailable")
	}
	if _, exists, err := readOfflineArchiveProjectionIntent(cfg.StatePath()); err != nil || exists {
		return intent, errors.Join(err, errors.New("another pending offline archive projection intent already exists"))
	}
	transactionID, err := state.NewTransactionID()
	if err != nil {
		return intent, err
	}
	stageRelative, err := installOfflineArchiveProjectionStage(cfg.StatePath(), result, transactionID)
	if err != nil {
		return intent, err
	}
	keepStage := false
	defer func() {
		if !keepStage {
			_ = discardOfflineArchiveProjectionStage(cfg.StatePath(), stageRelative)
		}
	}()
	configSHA, err := cfg.CanonicalSHA256()
	if err != nil {
		return intent, err
	}
	destination, err := archiveAbsolutePath(result.Path)
	if err != nil {
		return intent, err
	}
	validationRoot, err = archiveAbsolutePath(validationRoot)
	if err != nil {
		return intent, err
	}
	intent = offlineArchiveProjectionIntent{
		Schema: offlineArchiveProjectionIntentSchema, TransactionID: transactionID, ConfigSHA256: configSHA,
		Source: source, ArchiveSHA256: result.SHA256, ArchiveSize: result.Size, ArchiveEntries: result.Entries,
		ArchiveBytes: result.Bytes, StageRelative: stageRelative, Destination: destination, ValidationRoot: validationRoot,
		ArchiveAdoption: cloneOfflineArchiveAdoptionContract(adoption),
	}
	intent.Source.Refs = append([]offlineArchiveSourceRef(nil), source.Refs...)
	intent.ID, _ = offlineArchiveProjectionIntentID(intent)
	if err := writeOfflineArchiveProjectionIntent(cfg.StatePath(), intent); err != nil {
		current, exists, readErr := readOfflineArchiveProjectionIntent(cfg.StatePath())
		if readErr == nil && exists && current.ID == intent.ID {
			// Atomic rename may have succeeded even when the subsequent parent
			// directory fsync reported failure. Keep the already-fsynced stage:
			// the exact installed intent is a recoverable, fail-closed owner.
			keepStage = true
			return intent, errors.Join(err, errors.New("offline archive projection intent may require --recover after directory sync failure"))
		}
		return offlineArchiveProjectionIntent{}, errors.Join(err, readErr)
	}
	keepStage = true
	return intent, nil
}

func discardOfflineArchiveProjectionStage(stateRoot, stageRelative string) error {
	root, stageRoot, err := bindOfflineArchiveProjectionRoots(stateRoot, false)
	if err != nil {
		return err
	}
	defer root.Close()
	if stageRoot == nil {
		return nil
	}
	defer stageRoot.Close()
	stageName := filepath.Base(stageRelative)
	if !offlineArchiveProjectionStagePattern.MatchString(stageName) || filepath.Join(offlineArchiveProjectionStageDir, stageName) != stageRelative {
		return errors.New("invalid offline archive projection stage cleanup path")
	}
	if err := stageRoot.Remove(stageName); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncBoundArchiveDirectory(stageRoot)
}

func removeOfflineArchiveProjectionIntent(stateRoot string, intent offlineArchiveProjectionIntent) error {
	current, exists, err := readOfflineArchiveProjectionIntent(stateRoot)
	if err != nil || !exists || current.ID != intent.ID {
		return errors.Join(err, errors.New("pending offline archive projection intent changed before completion"))
	}
	root, stageRoot, err := bindOfflineArchiveProjectionRoots(stateRoot, false)
	if err != nil {
		return err
	}
	defer root.Close()
	if stageRoot != nil {
		defer stageRoot.Close()
		stageName := filepath.Base(intent.StageRelative)
		if info, statErr := stageRoot.Lstat(stageName); statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return errors.New("offline archive projection stage changed before completion")
			}
			if err := stageRoot.Remove(stageName); err != nil {
				return err
			}
			if err := syncBoundArchiveDirectory(stageRoot); err != nil {
				return err
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
	}
	if err := root.Remove(offlineArchiveProjectionIntentRelative); err != nil {
		return err
	}
	return syncBoundArchiveDirectory(root)
}

func cleanupOfflineArchiveProjectionResidue(stateRoot string, recover bool) error {
	root, stageRoot, err := bindOfflineArchiveProjectionRoots(stateRoot, false)
	if err != nil {
		return err
	}
	defer root.Close()
	if stageRoot != nil {
		defer stageRoot.Close()
	}
	rootDirectory, err := root.Open(".")
	if err != nil {
		return err
	}
	rootEntries, readErr := rootDirectory.ReadDir(-1)
	closeErr := rootDirectory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	rootRemoved := false
	for _, entry := range rootEntries {
		name := entry.Name()
		if !strings.HasPrefix(name, offlineArchiveProjectionIntentRelative+".tmp-") {
			continue
		}
		if !recover {
			return errors.New("interrupted offline archive projection residue requires --recover")
		}
		info, err := root.Lstat(name)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return errors.Join(err, fmt.Errorf("unsafe offline archive projection residue %s", name))
		}
		if err := root.Remove(name); err != nil {
			return err
		}
		rootRemoved = true
	}
	if rootRemoved {
		if err := syncBoundArchiveDirectory(root); err != nil {
			return err
		}
	}
	if stageRoot == nil {
		return nil
	}
	stageDirectory, err := stageRoot.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := stageDirectory.ReadDir(-1)
	closeErr = stageDirectory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	intent, exists, readErr := readOfflineArchiveProjectionIntent(stateRoot)
	if readErr != nil {
		return readErr
	}
	removed := false
	for _, entry := range entries {
		name := entry.Name()
		stage := offlineArchiveProjectionStagePattern.MatchString(name)
		wanted := exists && filepath.Base(intent.StageRelative) == name
		if !(stage && !wanted) {
			continue
		}
		if !recover {
			return errors.New("interrupted offline archive projection residue requires --recover")
		}
		info, err := stageRoot.Lstat(name)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return errors.Join(err, fmt.Errorf("unsafe offline archive projection residue %s", name))
		}
		if err := stageRoot.Remove(name); err != nil {
			return err
		}
		removed = true
	}
	if removed {
		return syncBoundArchiveDirectory(stageRoot)
	}
	return nil
}

func bindOfflineArchiveProjectionRoots(stateRoot string, requireStage bool) (*os.Root, *os.Root, error) {
	stateAbs, err := archiveAbsolutePath(stateRoot)
	if err != nil {
		return nil, nil, err
	}
	root, _, err := walkAbsoluteArchiveDirectory(stateAbs, false)
	if err != nil {
		return nil, nil, err
	}
	before, err := root.Lstat(offlineArchiveProjectionStageDir)
	if errors.Is(err, os.ErrNotExist) && !requireStage {
		return root, nil, nil
	}
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() || before.Mode().Perm()&0o077 != 0 {
		root.Close()
		return nil, nil, errors.Join(err, errors.New("offline archive projection stage directory is not private"))
	}
	stageRoot, err := root.OpenRoot(offlineArchiveProjectionStageDir)
	if err != nil {
		root.Close()
		return nil, nil, err
	}
	after, afterErr := root.Lstat(offlineArchiveProjectionStageDir)
	opened, openedErr := stageRoot.Stat(".")
	if afterErr != nil || openedErr != nil || after.Mode()&os.ModeSymlink != 0 || !after.IsDir() ||
		!os.SameFile(before, after) || !os.SameFile(before, opened) {
		stageRoot.Close()
		root.Close()
		return nil, nil, errors.Join(afterErr, openedErr, errors.New("offline archive projection stage directory changed while binding"))
	}
	return root, stageRoot, nil
}

func requireFrozenOfflineArchiveSourceProof(cfg *config.Config, canonical *state.Store, proof offlineArchiveSourceProof) error {
	if err := proof.validate(); err != nil {
		return err
	}
	leaves := make([]viewLeaf, 0, len(proof.Refs))
	refCommits := make(map[string]plumbing.Hash, len(proof.Refs))
	for _, frozen := range proof.Refs {
		repo, exists := cfg.RepoByName(frozen.Repo)
		if !exists || !repo.IsActive() {
			return fmt.Errorf("offline archive source repo %s is not active", frozen.Repo)
		}
		leaves = append(leaves, viewLeaf{repo: repo, os: frozen.OS, arch: frozen.Arch})
		refCommits[frozen.Name] = plumbing.NewHash(frozen.Commit)
	}
	source := materializeCanonicalSource{ID: proof.ID, Snapshot: proof.Snapshot, Public: proof.Access == "public", RefCommits: refCommits}
	derived, err := deriveOfflineArchiveSourceProof(cfg, canonical, source, leaves, proof.ExcludedPath)
	if err != nil {
		return err
	}
	if !offlineArchiveSourceProofEqual(derived, proof) {
		return errors.New("offline archive source proof differs from frozen canonical refs/entries")
	}
	return nil
}

func requireOfflineArchiveProjectionMarker(inspected inspectedOfflineArchiveInput, intent offlineArchiveProjectionIntent) error {
	if inspected.Object.HashString() != intent.ArchiveSHA256 || inspected.Object.Size != intent.ArchiveSize || inspected.Marker == nil {
		return errors.New("offline archive projection bytes differ from durable intent")
	}
	digest, err := offlineArchiveSourceProofSHA256(intent.Source)
	if err != nil || inspected.Marker.SourceSHA256 != digest || inspected.Marker.Access != intent.Source.Access ||
		inspected.Marker.Confidentiality != intent.Source.Confidentiality {
		return errors.Join(err, errors.New("offline archive projection marker differs from frozen source"))
	}
	return nil
}

func installRecoveredOfflineArchiveProjection(cfg *config.Config, intent offlineArchiveProjectionIntent) error {
	result := archiveResult{
		Path: intent.Destination, Stage: filepath.Join(cfg.StatePath(), intent.StageRelative), Entries: intent.ArchiveEntries,
		Bytes: intent.ArchiveBytes, Size: intent.ArchiveSize, SHA256: intent.ArchiveSHA256,
	}
	stateAbs, err := archiveAbsolutePath(cfg.StatePath())
	if err != nil {
		return err
	}
	privateStageDir := filepath.Join(stateAbs, offlineArchiveProjectionStageDir)
	privateRoot, privateIdentity, err := bindPrivateArchiveStage(privateStageDir)
	if err != nil {
		return err
	}
	defer privateRoot.Close()
	stageName := filepath.Base(intent.StageRelative)
	stageInfo, stageErr := privateRoot.Lstat(stageName)
	stageExists := stageErr == nil
	if stageErr != nil && !errors.Is(stageErr, os.ErrNotExist) {
		return stageErr
	}
	if stageExists && (stageInfo.Mode()&os.ModeSymlink != 0 || !stageInfo.Mode().IsRegular()) {
		return errors.New("offline archive recovery stage is not a regular file")
	}
	destinationParent := filepath.Dir(intent.Destination)
	destinationName := filepath.Base(intent.Destination)
	destinationRoot, destinationIdentity, err := bindArchiveDestinationParent(destinationParent)
	if err != nil {
		return err
	}
	defer destinationRoot.Close()
	if info, err := destinationRoot.Lstat(destinationName); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("archive destination is not a regular file")
		}
		if err := requireBoundArchiveFile(destinationRoot, destinationName, result); err != nil {
			return fmt.Errorf("archive destination exists with different bytes: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else {
		if !stageExists {
			return errors.New("offline archive recovery has neither its durable stage nor exact destination")
		}
		if err := preflightArchiveAtomicFilesystem(privateIdentity, destinationParent); err != nil {
			return err
		}
		if err := requireBoundArchiveDestinationParent(destinationParent, destinationRoot, destinationIdentity); err != nil {
			return err
		}
		if err := installBoundArchiveNoClobber(privateRoot, stageName, destinationRoot, destinationName, result); err != nil {
			return err
		}
	}
	if err := archiveDirectorySync(destinationRoot); err != nil {
		return err
	}
	if err := requireBoundArchiveDestinationParent(destinationParent, destinationRoot, destinationIdentity); err != nil {
		return err
	}
	return requireBoundArchiveFile(destinationRoot, destinationName, result)
}

func writeMaterializedOfflineArchive(
	ctx context.Context,
	cfg *config.Config,
	canonical *state.Store,
	source offlineArchiveSourceProof,
	materializedRoot, manifestPath, destination, validationRoot string,
	allowInsideRoot bool,
	privateStageDir, marker string,
	adoptionPreflight *offlineArchiveAdoptionPreflight,
) (archiveResult, offlineArchiveProjectionIntent, error) {
	var intent offlineArchiveProjectionIntent
	result, err := writeDeterministicTGZWithLifecycle(ctx, materializedRoot, manifestPath, destination, allowInsideRoot, privateStageDir, marker, archiveCommitLifecycle{
		Precommit: func(result archiveResult) error {
			var adoption *offlineArchiveAdoptionContract
			var err error
			if adoptionPreflight != nil {
				adoption, err = finalizeOfflineArchiveAdoption(*adoptionPreflight, result)
				if err != nil {
					return err
				}
			}
			prepared, err := prepareOfflineArchiveProjectionIntent(cfg, source, result, validationRoot, adoption)
			if err != nil {
				return err
			}
			intent = prepared
			_, err = persistOfflineArchiveTaintReceipt(ctx, cfg, canonical, source, result, privateStageDir)
			return err
		},
		Complete: func(archiveResult) error {
			if intent.ID == "" {
				return errors.New("offline archive projection intent was not prepared")
			}
			if intent.ArchiveAdoption != nil {
				// The outer archive owner remains durable until the asset ref,
				// selected-set journal, and directly hostable tree all converge.
				return nil
			}
			return removeOfflineArchiveProjectionIntent(cfg.StatePath(), intent)
		},
	})
	return result, intent, err
}

func recoverPendingOfflineArchiveProjection(ctx context.Context, cfg *config.Config, canonical *state.Store, values commonFlags, stdout io.Writer) (bool, error) {
	intent, exists, err := readOfflineArchiveProjectionIntent(cfg.StatePath())
	if err != nil || !exists {
		return false, err
	}
	if !values.recover {
		return true, errors.New("pending offline archive projection requires materialize --recover")
	}
	configSHA, err := cfg.CanonicalSHA256()
	if err != nil || configSHA != intent.ConfigSHA256 {
		return true, errors.Join(err, errors.New("pending offline archive projection config differs from durable intent"))
	}
	if err := validateArchiveDestination(cfg, values.configPath, intent.ValidationRoot, intent.Destination); err != nil {
		return true, fmt.Errorf("validate frozen offline archive destination: %w", err)
	}
	if err := requireFrozenOfflineArchiveSourceProof(cfg, canonical, intent.Source); err != nil {
		return true, fmt.Errorf("verify frozen offline archive source: %w", err)
	}
	stagePath := filepath.Join(cfg.StatePath(), intent.StageRelative)
	inspected, stageErr := inspectOfflineArchiveInputContext(ctx, stagePath)
	if errors.Is(stageErr, os.ErrNotExist) {
		inspected, stageErr = inspectOfflineArchiveInputContext(ctx, intent.Destination)
	}
	if stageErr != nil {
		return true, fmt.Errorf("inspect durable offline archive projection bytes: %w", stageErr)
	}
	if err := requireOfflineArchiveProjectionMarker(inspected, intent); err != nil {
		return true, err
	}
	receipt, receiptExists, err := readOfflineArchiveTaintReceipt(canonical, intent.ArchiveSHA256)
	if err != nil {
		return true, err
	}
	if receiptExists {
		receiptSourceSHA, receiptSourceErr := offlineArchiveSourceProofSHA256(receipt.Source)
		intentSourceSHA, intentSourceErr := offlineArchiveSourceProofSHA256(intent.Source)
		if receipt.ArchiveSize != intent.ArchiveSize || receipt.Confidentiality != intent.Source.Confidentiality ||
			receiptSourceErr != nil || intentSourceErr != nil || receiptSourceSHA != intentSourceSHA {
			return true, errors.Join(receiptSourceErr, intentSourceErr, errors.New("canonical archive taint receipt differs from durable projection intent"))
		}
	} else {
		txDir, err := newTransactionDir(cfg.StatePath(), "materialize-archive-intent-recover-")
		if err != nil {
			return true, err
		}
		defer os.RemoveAll(txDir)
		result := archiveResult{Path: intent.Destination, Stage: stagePath, Entries: intent.ArchiveEntries, Bytes: intent.ArchiveBytes, Size: intent.ArchiveSize, SHA256: intent.ArchiveSHA256}
		if _, err := persistOfflineArchiveTaintReceipt(ctx, cfg, canonical, intent.Source, result, txDir); err != nil {
			return true, err
		}
	}
	if err := installRecoveredOfflineArchiveProjection(cfg, intent); err != nil {
		return true, fmt.Errorf("install frozen offline archive projection: %w", err)
	}
	if intent.ArchiveAdoption != nil {
		if err := completeOfflineArchiveProjectionAdoption(ctx, cfg, canonical, intent, values, stdout); err != nil {
			return true, err
		}
		fmt.Fprintf(stdout, "recovered offline archive path=%s entries=%d bytes=%d size=%d sha256=%s\n", intent.Destination, intent.ArchiveEntries, intent.ArchiveBytes, intent.ArchiveSize, intent.ArchiveSHA256)
		return true, nil
	}
	if err := removeOfflineArchiveProjectionIntent(cfg.StatePath(), intent); err != nil {
		return true, err
	}
	fmt.Fprintf(stdout, "recovered offline archive path=%s entries=%d bytes=%d size=%d sha256=%s\n", intent.Destination, intent.ArchiveEntries, intent.ArchiveBytes, intent.ArchiveSize, intent.ArchiveSHA256)
	return true, nil
}
