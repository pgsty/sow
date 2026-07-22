package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
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
var projectionStageCleanupHook func(string) error
var projectionResidueCleanupHook func(string) error

// projectionStageInstallHook brackets the source-admission and final-install
// boundaries for deterministic filesystem-race tests. Production never sets
// it.
var projectionStageInstallHook func(phase, path string) error

// The installer is replaceable only by focused durability tests that emulate
// a successful atomic install followed by a reported durability error.
var assetProjectionIntentInstall = installProjectionIntentBytes

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

func assetProjectionExpectedStages(intent assetProjectionIntent) map[string]state.FileIdentity {
	return map[string]state.FileIdentity{
		intent.ViewPath: {
			Size:   intent.ManifestSize,
			SHA256: intent.ManifestSHA256,
		},
		"config/sow.yaml": {
			Size:   intent.ConfigSize,
			SHA256: intent.ConfigSHA256,
		},
	}
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

func prepareAssetProjectionIntent(cfg *config.Config, canonical *state.Store, operation, operationScope string, repo config.Repo, viewName, viewPath string, viewRef plumbing.ReferenceName, expected plumbing.Hash, staged string, archive *offlineArchiveAdoptionContract) (intent assetProjectionIntent, stageAbsolute string, resultErr error) {
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
	stageAbsolute = filepath.Join(cfg.StatePath(), stageRelative)
	installed := make([]projectionStageIdentity, 0, 2)
	keepStages := false
	defer func() {
		if resultErr != nil && !keepStages {
			resultErr = errors.Join(resultErr, rollbackInstalledProjectionStages(installed))
		}
	}()
	object, stageIdentity, err := installPendingProjectionStage(cfg.StatePath(), stageRelative, staged)
	if err != nil {
		return intent, "", err
	}
	installed = append(installed, stageIdentity)
	configStageRelative := assetProjectionStagePrefix + transactionID + "-config.yaml"
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
	_, configIdentity, err := installProjectionStageBytesBound(cfg.StatePath(), configStageRelative, canonicalConfig, stageIdentity.root)
	if err != nil {
		return intent, "", err
	}
	installed = append(installed, configIdentity)
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
	if err := verifyInstalledProjectionStages(installed); err != nil {
		return assetProjectionIntent{}, "", err
	}
	if err := installAssetProjectionIntent(cfg.StatePath(), intent, stageIdentity.root); err != nil {
		if rootErr := verifyProjectionStageRootIdentity(cfg.StatePath(), stageIdentity.root); rootErr != nil {
			keepStages = true
			return intent, "", errors.Join(err, rootErr, errors.New("restore the exact projection state root, then retry with --recover"))
		}
		current, exists, readErr := readAssetProjectionIntent(cfg.StatePath())
		rootErr := verifyProjectionStageRootIdentity(cfg.StatePath(), stageIdentity.root)
		if rootErr != nil {
			keepStages = true
			return intent, "", errors.Join(err, readErr, rootErr, errors.New("restore the exact projection state root, then retry with --recover"))
		}
		if readErr != nil {
			keepStages = true
			return intent, "", errors.Join(err, readErr, errors.New("pending asset projection intent commit is ambiguous; retry with --recover"))
		}
		if exists && current.ID == intent.ID {
			keepStages = true
			return intent, "", errors.Join(err, errors.New("pending asset projection intent may require --recover after directory sync failure"))
		}
		return assetProjectionIntent{}, "", err
	}
	keepStages = true
	if err := verifyInstalledProjectionStages(installed); err != nil {
		return intent, "", errors.Join(err, errors.New("pending asset projection intent committed with changed stages; retry with --recover"))
	}
	return intent, stageAbsolute, nil
}

func installPendingAssetProjectionStage(stateRoot, relative, source string) (repository.Object, error) {
	object, _, err := installPendingProjectionStage(stateRoot, relative, source)
	return object, err
}

func installPendingProjectionStage(stateRoot, relative, source string) (repository.Object, projectionStageIdentity, error) {
	return installPendingProjectionStageBound(stateRoot, relative, source, nil)
}

func installPendingProjectionStageBound(stateRoot, relative, source string, boundRoot os.FileInfo) (repository.Object, projectionStageIdentity, error) {
	var result repository.Object
	var installed projectionStageIdentity
	input, before, err := openExactOfflineArchiveInput(source)
	if err != nil {
		return result, installed, err
	}
	inspected, err := inspectOfflineArchiveOpenFile(context.Background(), source, input, before, defaultOfflineArchiveInspectionLimits)
	if err != nil {
		return result, installed, errors.Join(err, input.Close())
	}
	if projectionStageInstallHook != nil {
		if err := projectionStageInstallHook("after-source-inspection", source); err != nil {
			return result, installed, errors.Join(err, input.Close())
		}
	}
	afterHook, err := os.Lstat(source)
	if err != nil || afterHook == nil || !os.SameFile(before, afterHook) || afterHook.Mode() != before.Mode() ||
		afterHook.Size() != before.Size() || !afterHook.ModTime().Equal(before.ModTime()) {
		return result, installed, errors.Join(err, input.Close(), errors.New("pending projection stage source coordinate changed before copy"))
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return result, installed, errors.Join(err, input.Close())
	}
	verifySource := func() error {
		openedAfter, statErr := input.Stat()
		currentAfter, lstatErr := os.Lstat(source)
		if statErr != nil || lstatErr != nil || openedAfter == nil || currentAfter == nil ||
			!os.SameFile(before, openedAfter) || !os.SameFile(before, currentAfter) ||
			openedAfter.Mode() != before.Mode() || currentAfter.Mode() != before.Mode() ||
			openedAfter.Size() != before.Size() || currentAfter.Size() != before.Size() ||
			!openedAfter.ModTime().Equal(before.ModTime()) || !currentAfter.ModTime().Equal(before.ModTime()) {
			return errors.Join(statErr, lstatErr, errors.New("pending projection stage source changed while copying"))
		}
		return nil
	}
	result, installed, installErr := installProjectionStageReader(stateRoot, relative, inspected.Object, input, verifySource, boundRoot)
	closeErr := input.Close()
	if installErr != nil || closeErr != nil {
		if installErr == nil && installed.valid() {
			_, cleanupErr := removeInstalledProjectionStage(installed)
			if cleanupErr != nil {
				cleanupErr = fmt.Errorf("pending projection stage cleanup failed; retry with --recover: %w", cleanupErr)
			}
			return repository.Object{}, projectionStageIdentity{}, errors.Join(closeErr, cleanupErr)
		}
		return repository.Object{}, projectionStageIdentity{}, errors.Join(installErr, closeErr)
	}
	return result, installed, nil
}

func installProjectionStageBytes(stateRoot, relative string, body []byte) (repository.Object, projectionStageIdentity, error) {
	return installProjectionStageBytesBound(stateRoot, relative, body, nil)
}

func installProjectionStageBytesBound(stateRoot, relative string, body []byte, boundRoot os.FileInfo) (repository.Object, projectionStageIdentity, error) {
	digest := sha256.Sum256(body)
	parsed, err := repository.ParseDigest(hex.EncodeToString(digest[:]))
	if err != nil {
		return repository.Object{}, projectionStageIdentity{}, err
	}
	expected := repository.Object{SHA256: parsed, Size: int64(len(body))}
	return installProjectionStageReader(stateRoot, relative, expected, bytes.NewReader(body), nil, boundRoot)
}

func installProjectionStageReader(stateRoot, relative string, expected repository.Object, input io.Reader, verifySource func() error, boundRoot os.FileInfo) (result repository.Object, installed projectionStageIdentity, resultErr error) {
	if filepath.Base(relative) != relative || relative == "" || relative == "." || input == nil ||
		expected.Size < 0 || expected.Size == math.MaxInt64 || !validMaterializationTrustSHA256(expected.HashString()) {
		return result, installed, errors.New("pending projection stage install capability is invalid")
	}
	stateRoot, err := filepath.Abs(stateRoot)
	if err != nil {
		return result, installed, err
	}
	rootBefore, err := os.Lstat(stateRoot)
	if err != nil || rootBefore == nil || rootBefore.Mode()&os.ModeSymlink != 0 || !rootBefore.IsDir() {
		return result, installed, errors.Join(err, errors.New("pending projection stage root is not a real directory"))
	}
	root, err := os.OpenRoot(stateRoot)
	if err != nil {
		return result, installed, err
	}
	defer root.Close()
	rootIdentity, err := root.Stat(".")
	if err != nil || rootIdentity == nil || !os.SameFile(rootBefore, rootIdentity) {
		return result, installed, errors.Join(err, errors.New("pending projection stage root changed while binding"))
	}
	if boundRoot != nil && (!os.SameFile(boundRoot, rootIdentity) || boundRoot.Mode() != rootIdentity.Mode()) {
		return result, installed, errors.New("pending projection stage root differs from the prepared transaction root")
	}
	if err := verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity); err != nil {
		return result, installed, err
	}
	if _, err := root.Lstat(relative); err == nil {
		return result, installed, errors.New("pending projection stage already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, installed, err
	}
	directory, err := root.Open(".")
	if err != nil {
		return result, installed, err
	}
	defer directory.Close()
	nonce, err := state.NewTransactionID()
	if err != nil {
		return result, installed, err
	}
	temporary := relative + ".tmp-" + nonce
	file, err := root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return result, installed, err
	}
	closed := false
	committed := false
	identity, err := file.Stat()
	if err != nil || identity == nil {
		closeErr := file.Close()
		return result, installed, errors.Join(err, closeErr, fmt.Errorf("pending projection stage temporary %s could not be bound; retry with --recover", temporary))
	}
	createdIdentity := identity
	currentName := temporary
	installed = projectionStageIdentity{stateRoot: stateRoot, root: rootIdentity, relative: temporary, inode: identity, size: expected.Size, sha256: expected.HashString()}
	defer func() {
		if !closed {
			closeErr := file.Close()
			closed = true
			if closeErr != nil {
				resultErr = errors.Join(resultErr, closeErr)
			}
		}
		if resultErr != nil && !committed {
			cleanupErr := removeExactDerivedStateTemporary(root, currentName, createdIdentity)
			if cleanupErr != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("pending projection stage cleanup failed; retry with --recover: %w", cleanupErr))
			}
			installed = projectionStageIdentity{}
			result = repository.Object{}
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return result, installed, err
	}
	identity, err = file.Stat()
	current, lstatErr := root.Lstat(temporary)
	if err != nil || lstatErr != nil || identity == nil || current == nil ||
		!os.SameFile(createdIdentity, identity) || !os.SameFile(createdIdentity, current) ||
		!privateExactProjectionStage(identity, 0) || !privateExactProjectionStage(current, 0) ||
		identity.Mode().Perm() != 0o600 || current.Mode().Perm() != 0o600 {
		return result, installed, errors.Join(err, lstatErr, errors.New("pending projection stage temporary is not an exact mode-0600 regular file"))
	}
	createdIdentity = identity
	installed.inode = identity
	hasher := sha256.New()
	written, copyErr := io.CopyBuffer(io.MultiWriter(file, hasher), io.LimitReader(input, expected.Size+1), make([]byte, 256*1024))
	if copyErr != nil || written != expected.Size || hex.EncodeToString(hasher.Sum(nil)) != expected.HashString() {
		return result, installed, errors.Join(copyErr, errors.New("pending projection stage differs from admitted bytes"))
	}
	if verifySource != nil {
		if err := verifySource(); err != nil {
			return result, installed, err
		}
	}
	if err := file.Sync(); err != nil {
		return result, installed, err
	}
	after, statErr := file.Stat()
	current, lstatErr = root.Lstat(temporary)
	if statErr != nil || lstatErr != nil || after == nil || current == nil ||
		!os.SameFile(identity, after) || !os.SameFile(identity, current) || !privateExactProjectionStage(after, expected.Size) ||
		!privateExactProjectionStage(current, expected.Size) {
		return result, installed, errors.Join(statErr, lstatErr, errors.New("pending projection stage temporary changed while writing"))
	}
	identity = after
	installed.inode = identity
	var expectedDigest [sha256.Size]byte
	copy(expectedDigest[:], expected.SHA256[:])
	if err := verifyExactDerivedStateBytes(file, identity, expectedDigest); err != nil {
		return result, installed, err
	}
	if err := verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity); err != nil {
		return result, installed, err
	}
	isolationNonce, err := state.NewTransactionID()
	if err != nil {
		return result, installed, err
	}
	isolation := relative + ".tmp-install-" + isolationNonce
	if err := renameYUMCompatibilityCandidateNoReplace(directory.Fd(), temporary, isolation); err != nil {
		return result, installed, err
	}
	currentName = isolation
	installed.relative = isolation
	if err := directory.Sync(); err != nil {
		return result, installed, err
	}
	if projectionStageInstallHook != nil {
		if err := projectionStageInstallHook("before-install", filepath.Join(stateRoot, isolation)); err != nil {
			return result, installed, err
		}
	}
	if verifySource != nil {
		if err := verifySource(); err != nil {
			return result, installed, err
		}
	}
	if err := verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity); err != nil {
		return result, installed, err
	}
	isolated, lstatErr := root.Lstat(isolation)
	opened, statErr := file.Stat()
	if lstatErr != nil || statErr != nil || isolated == nil || opened == nil ||
		!os.SameFile(identity, isolated) || !os.SameFile(identity, opened) ||
		!privateExactProjectionStage(isolated, expected.Size) || !privateExactProjectionStage(opened, expected.Size) {
		return result, installed, errors.Join(lstatErr, statErr, errors.New("pending projection stage candidate changed before installation"))
	}
	if err := verifyExactDerivedStateBytes(file, identity, expectedDigest); err != nil {
		return result, installed, err
	}
	if err := renameYUMCompatibilityCandidateNoReplace(directory.Fd(), isolation, relative); err != nil {
		return result, installed, err
	}
	currentName = relative
	installed.relative = relative
	if err := directory.Sync(); err != nil {
		return result, installed, err
	}
	destination, lstatErr := root.Lstat(relative)
	opened, statErr = file.Stat()
	if lstatErr != nil || statErr != nil || destination == nil || opened == nil ||
		!os.SameFile(identity, destination) || !os.SameFile(identity, opened) ||
		!privateExactProjectionStage(destination, expected.Size) || !privateExactProjectionStage(opened, expected.Size) {
		return result, installed, errors.Join(lstatErr, statErr, errors.New("pending projection stage destination changed during installation"))
	}
	if err := verifyExactDerivedStateBytes(file, identity, expectedDigest); err != nil {
		return result, installed, err
	}
	if projectionStageInstallHook != nil {
		if err := projectionStageInstallHook("after-destination-verify", filepath.Join(stateRoot, relative)); err != nil {
			return result, installed, err
		}
		if err := verifyExactDerivedStateBytes(file, identity, expectedDigest); err != nil {
			return result, installed, err
		}
	}
	destination, lstatErr = root.Lstat(relative)
	opened, statErr = file.Stat()
	if lstatErr != nil || statErr != nil || destination == nil || opened == nil ||
		!os.SameFile(identity, destination) || !os.SameFile(identity, opened) ||
		!privateExactProjectionStage(destination, expected.Size) || !privateExactProjectionStage(opened, expected.Size) ||
		destination.Mode() != identity.Mode() || opened.Mode() != identity.Mode() ||
		!destination.ModTime().Equal(identity.ModTime()) || !opened.ModTime().Equal(identity.ModTime()) {
		return result, installed, errors.Join(lstatErr, statErr, errors.New("pending projection stage destination changed after verification"))
	}
	if err := verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity); err != nil {
		return result, installed, err
	}
	if err := file.Close(); err != nil {
		closed = true
		return result, installed, err
	}
	closed = true
	committed = true
	result = expected
	return result, installed, nil
}

func writeAssetProjectionIntent(stateRoot string, intent assetProjectionIntent) error {
	body, err := marshalAssetProjectionIntent(intent)
	if err != nil {
		return err
	}
	return writeDerivedStateFile(stateRoot, assetProjectionIntentRelative, body)
}

func installAssetProjectionIntent(stateRoot string, intent assetProjectionIntent, boundRoot os.FileInfo) error {
	body, err := marshalAssetProjectionIntent(intent)
	if err != nil {
		return err
	}
	return assetProjectionIntentInstall(stateRoot, assetProjectionIntentRelative, body, boundRoot)
}

func marshalAssetProjectionIntent(intent assetProjectionIntent) ([]byte, error) {
	if err := intent.validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(intent)
	if err != nil {
		return nil, err
	}
	if len(body) > assetProjectionIntentMaxBytes {
		return nil, errors.New("pending asset projection intent exceeds size limit")
	}
	return body, nil
}

func installProjectionIntentBytes(stateRoot, relative string, body []byte, boundRoot os.FileInfo) error {
	_, _, err := installProjectionStageBytesBound(stateRoot, relative, body, boundRoot)
	return err
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
	// Intent removal is the completion commit. Stage/config cleanup is exact,
	// private garbage collection; a mismatch remains for --recover and must not
	// turn the completed projection back into a reported transaction failure.
	_, _ = removeExactProjectionStage(stateRoot, intent.StageRelative, intent.ManifestSize, intent.ManifestSHA256)
	_, _ = removeExactProjectionStage(stateRoot, intent.ConfigStage, intent.ConfigSize, intent.ConfigSHA256)
	return nil
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
	preserved := make([]string, 0)
	for _, entry := range entries {
		name := entry.Name()
		isIntentTemporary := isDerivedStateTemporaryName(name, assetProjectionIntentRelative)
		isStageTemporary := isProjectionStageTemporaryName(name, isAssetProjectionStageFinalName)
		isPreserved := isProjectionStagePreservedName(name, isAssetProjectionStageFinalName)
		isProjectionStage := isAssetProjectionStageFinalName(name)
		isWantedStage := exists && (name == intent.StageRelative || name == intent.ConfigStage)
		isOrphanStage := isProjectionStage && !isWantedStage
		if isPreserved || isWantedStage {
			continue
		}
		if !isIntentTemporary && !isStageTemporary && !isOrphanStage {
			if strings.HasPrefix(name, assetProjectionStagePrefix) || strings.HasPrefix(name, assetProjectionIntentRelative+".") {
				return fmt.Errorf("unsafe pending asset projection residue name %q", name)
			}
			continue
		}
		if !recover {
			return errors.New("interrupted pending asset projection residue requires --recover")
		}
		if isOrphanStage {
			retained, moved, err := preserveExactProjectionResidue(stateRoot, name)
			if err != nil {
				return errors.Join(err, fmt.Errorf("unsafe pending asset projection residue %s", name))
			}
			if moved {
				preserved = append(preserved, retained)
			}
			continue
		}
		exact, err := removeExactProjectionResidue(stateRoot, name)
		if err != nil {
			return errors.Join(err, fmt.Errorf("unsafe pending asset projection residue %s", name))
		}
		removed = removed || exact
	}
	if removed {
		if err := syncLocalDirectory(stateRoot); err != nil {
			return err
		}
	}
	if len(preserved) != 0 {
		return fmt.Errorf("preserved orphan asset projection residue at %s; inspect it, then retry with --recover", strings.Join(preserved, ", "))
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
			[]state.RefUpdate{{Name: viewRef, Expected: expected}}, state.ApplyOptions{
				TransactionID:  intent.TransactionID,
				ExpectedStages: assetProjectionExpectedStages(intent),
			})
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
