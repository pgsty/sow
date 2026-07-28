package cli

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

const (
	packageProjectionIntentSchema   = "sow-package-projection-intent/v3"
	packageProjectionIntentRelative = "package-projection-intent.json"
	packageProjectionIntentMaxBytes = 4 << 20
	packageProjectionStagePrefix    = "package-projection-stage-"
	packageProjectionAttestationMax = 64 << 10

	packageProjectionCompletionSchema = "sow-package-projection-completion/v1"
	packageProjectionCompletionPrefix = "package-projection-complete-"
	packageProjectionCompletionMax    = 16 << 10
)

var packageProjectionMutationHook func(string) error
var packageProjectionBeforeLockHook func() error
var packageProjectionCleanupHook func(packageProjectionIntent)
var packageProjectionNow = func() time.Time { return time.Now().UTC() }
var packageProjectionIntentInstall = installProjectionIntentBytes

type packageProjectionMutation struct {
	leaf     viewLeaf
	view     string
	viewPath string
	viewRef  string
	expected string
}

type packageProjectionIntentUnit struct {
	Repo           string `json:"repo"`
	View           string `json:"view"`
	OS             string `json:"os"`
	Arch           string `json:"arch"`
	ViewPath       string `json:"view_path"`
	ViewRef        string `json:"view_ref"`
	ExpectedRef    string `json:"expected_ref"`
	ManifestSHA256 string `json:"manifest_sha256"`
	ManifestSize   int64  `json:"manifest_size"`
	StageRelative  string `json:"stage_relative"`
}

type packageProjectionYUMKeyring struct {
	Repo   string `json:"repo"`
	SHA256 string `json:"sha256"`
}

type packageProjectionIntent struct {
	Schema                  string                        `json:"schema"`
	ID                      string                        `json:"id"`
	Operation               string                        `json:"operation"`
	Family                  string                        `json:"family"`
	SigningTime             string                        `json:"signing_time"`
	TransactionID           string                        `json:"transaction_id"`
	Message                 string                        `json:"message"`
	ConfigSHA256            string                        `json:"config_sha256"`
	ConfigSize              int64                         `json:"config_size"`
	ConfigStage             string                        `json:"config_stage_relative"`
	ExpectedHead            string                        `json:"expected_head"`
	TargetSHA256            string                        `json:"target_sha256"`
	RepositoryKeySHA256     string                        `json:"repository_key_sha256"`
	YUMPackageKeyringSHA256 []packageProjectionYUMKeyring `json:"yum_package_keyrings"`
	Units                   []packageProjectionIntentUnit `json:"units"`
	Attestation             string                        `json:"attestation"`
}

func packageProjectionExpectedStages(intent packageProjectionIntent) map[string]state.FileIdentity {
	expected := make(map[string]state.FileIdentity, len(intent.Units)+1)
	for _, unit := range intent.Units {
		expected[unit.ViewPath] = state.FileIdentity{Size: unit.ManifestSize, SHA256: unit.ManifestSHA256}
	}
	expected["config/sow.yaml"] = state.FileIdentity{Size: intent.ConfigSize, SHA256: intent.ConfigSHA256}
	return expected
}

type packageProjectionCompletionReceipt struct {
	Schema        string `json:"schema"`
	ID            string `json:"id"`
	IntentID      string `json:"intent_id"`
	TransactionID string `json:"transaction_id"`
	Commit        string `json:"commit"`
}

func packageProjectionTrustSHA256(repositoryKeySHA256 string, yum []packageProjectionYUMKeyring) string {
	body, _ := json.Marshal(struct {
		RepositoryKeySHA256 string                        `json:"repository_key_sha256"`
		YUMKeyrings         []packageProjectionYUMKeyring `json:"yum_package_keyrings"`
	}{repositoryKeySHA256, yum})
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

func packageProjectionMessage(operation, family, signingTime, transactionID string, units int, repositoryKeySHA256 string, yum []packageProjectionYUMKeyring) string {
	return fmt.Sprintf("sow %s: package projection family=%s signing_time=%s transaction=%s units=%d trust=%s", operation, family, signingTime, transactionID, units, packageProjectionTrustSHA256(repositoryKeySHA256, yum))
}

func parsePackageProjectionSigningTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Nanosecond() != 0 || parsed.Before(time.Unix(1, 0).UTC()) || value != parsed.UTC().Format(time.RFC3339) {
		return time.Time{}, errors.Join(err, errors.New("invalid pending package projection signing time"))
	}
	return parsed.UTC(), nil
}

// freezePackageProjectionSigningTime is called only while the mutation lock is
// held and immediately before a durable package intent is created. It proves
// the repository key is valid at the recorded instant; callers must not use it
// to authorize a new transaction from an older intent timestamp.
func freezePackageProjectionSigningTime(snapshot *materializationTrustSnapshot, family string, privateKey, passphrase []byte) error {
	if snapshot == nil || (family != "apt" && family != "yum" && family != "mixed") {
		return errors.New("package projection signing snapshot or family is invalid")
	}
	at := packageProjectionNow().UTC().Truncate(time.Second)
	if _, err := parsePackageProjectionSigningTime(at.Format(time.RFC3339)); err != nil {
		return err
	}
	if family == "apt" || family == "mixed" {
		signer, err := aptrepo.NewSigner(bytes.NewReader(privateKey), passphrase)
		if err != nil || signer.Validate(at) != nil {
			return errors.Join(err, errors.New("package projection APT signing key is not valid at intent creation"))
		}
	}
	if family == "yum" || family == "mixed" {
		if _, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(privateKey), passphrase, at); err != nil {
			return errors.Join(err, errors.New("package projection YUM signing key is not valid at intent creation"))
		}
	}
	snapshot.verificationTime = at
	return nil
}

func requirePackageProjectionSigningSecret(intent packageProjectionIntent, privateKey, passphrase []byte) (time.Time, error) {
	at, err := parsePackageProjectionSigningTime(intent.SigningTime)
	if err != nil {
		return time.Time{}, err
	}
	if intent.Family == "apt" || intent.Family == "mixed" {
		signer, signerErr := aptrepo.NewSigner(bytes.NewReader(privateKey), passphrase)
		if signerErr != nil || signer.Validate(at) != nil {
			return time.Time{}, errors.Join(signerErr, errors.New("pending package projection APT signing secret was not valid at its frozen signing time"))
		}
	}
	if intent.Family == "yum" || intent.Family == "mixed" {
		if _, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(privateKey), passphrase, at); err != nil {
			return time.Time{}, errors.Join(err, errors.New("pending package projection YUM signing secret was not valid at its frozen signing time"))
		}
	}
	return at, nil
}

func bindPackageProjectionSigningTime(snapshot *materializationTrustSnapshot, intent packageProjectionIntent) error {
	if snapshot == nil {
		return errors.New("package projection materialization trust is unavailable")
	}
	at, err := parsePackageProjectionSigningTime(intent.SigningTime)
	if err != nil {
		return err
	}
	snapshot.verificationTime = at
	return nil
}

func packageProjectionIntentID(intent packageProjectionIntent) (string, error) {
	intent.ID = ""
	body, err := json.Marshal(intent)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

func packageProjectionAttestationPayload(intent packageProjectionIntent) ([]byte, error) {
	intent.ID = ""
	intent.Attestation = ""
	return json.Marshal(intent)
}

// attestPackageProjectionIntent turns the frozen local bridge into
// non-recomputable evidence. A stale or corrupted bridge that has no local
// transaction journal can therefore authorize only the exact envelope signed
// while the repository key was valid, never a rehashed historical timestamp.
func attestPackageProjectionIntent(intent *packageProjectionIntent, privateKey, passphrase []byte) error {
	if intent == nil || intent.ID != "" || intent.Attestation != "" {
		return errors.New("package projection attestation input is invalid")
	}
	at, err := parsePackageProjectionSigningTime(intent.SigningTime)
	if err != nil {
		return err
	}
	payload, err := packageProjectionAttestationPayload(*intent)
	if err != nil {
		return err
	}
	signer, err := aptrepo.NewSigner(bytes.NewReader(privateKey), passphrase)
	if err != nil {
		return errors.Join(err, errors.New("create package projection intent signer"))
	}
	var signature bytes.Buffer
	if err := signer.DetachedSign(&signature, bytes.NewReader(payload), at); err != nil {
		return errors.Join(err, errors.New("sign package projection intent"))
	}
	encoded := base64.StdEncoding.EncodeToString(signature.Bytes())
	if len(encoded) == 0 || len(encoded) > packageProjectionAttestationMax {
		return errors.New("package projection intent attestation exceeds size limit")
	}
	intent.Attestation = encoded
	return nil
}

func requirePackageProjectionIntentAttestation(cfg *config.Config, intent packageProjectionIntent) error {
	at, err := parsePackageProjectionSigningTime(intent.SigningTime)
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(intent.Attestation)
	if err != nil || len(signature) == 0 || len(signature) > packageProjectionAttestationMax {
		return errors.Join(err, errors.New("pending package projection attestation is invalid"))
	}
	payload, err := packageProjectionAttestationPayload(intent)
	if err != nil {
		return err
	}
	entity, packets, err := loadRepositoryPublicTrustAnchorAt(cfg.Path, cfg.GPG.PublicKey, at)
	if err != nil {
		return err
	}
	if repositoryTrustAnchorDigest(packets) != intent.RepositoryKeySHA256 {
		return errors.New("pending package projection attestation trust changed")
	}
	verification := &packet.Config{DefaultHash: crypto.SHA256, Time: func() time.Time { return at }}
	if _, err := openpgp.CheckArmoredDetachedSignature(openpgp.EntityList{entity}, bytes.NewReader(payload), bytes.NewReader(signature), verification); err != nil {
		return errors.New("pending package projection attestation verification failed")
	}
	return nil
}

func (intent packageProjectionIntent) validate() error {
	if _, err := parsePackageProjectionSigningTime(intent.SigningTime); err != nil {
		return err
	}
	attestation, attestationErr := base64.StdEncoding.Strict().DecodeString(intent.Attestation)
	if intent.Schema != packageProjectionIntentSchema || !validMaterializationTrustSHA256(intent.ID) ||
		(intent.Operation != "add" && intent.Operation != "rm") || (intent.Family != "apt" && intent.Family != "yum" && intent.Family != "mixed") ||
		!assetProjectionTransactionIDPattern.MatchString(intent.TransactionID) || !validMaterializationTrustSHA256(intent.ConfigSHA256) ||
		intent.ConfigSize <= 0 || intent.ConfigStage != packageProjectionStagePrefix+intent.TransactionID+"-config.yaml" ||
		!materializationCommitPattern.MatchString(intent.ExpectedHead) || !validMaterializationTrustSHA256(intent.TargetSHA256) ||
		!validMaterializationTrustSHA256(intent.RepositoryKeySHA256) || len(intent.Units) == 0 || attestationErr != nil || len(attestation) == 0 || len(intent.Attestation) > packageProjectionAttestationMax ||
		intent.Message != packageProjectionMessage(intent.Operation, intent.Family, intent.SigningTime, intent.TransactionID, len(intent.Units), intent.RepositoryKeySHA256, intent.YUMPackageKeyringSHA256) {
		return errors.New("invalid pending package projection envelope")
	}
	previousTrustRepo := ""
	for _, trust := range intent.YUMPackageKeyringSHA256 {
		if trust.Repo <= previousTrustRepo || !validMaterializationJournalString(trust.Repo, 256) || !validMaterializationTrustSHA256(trust.SHA256) {
			return errors.New("invalid or unsorted pending package projection YUM trust")
		}
		previousTrustRepo = trust.Repo
	}
	if intent.Family == "apt" && len(intent.YUMPackageKeyringSHA256) != 0 || intent.Family == "yum" && len(intent.YUMPackageKeyringSHA256) == 0 {
		return errors.New("pending package projection trust does not match family")
	}
	previous := ""
	for index, unit := range intent.Units {
		key := strings.Join([]string{unit.View, unit.Repo, unit.OS, unit.Arch}, "\x00")
		wantedStage := fmt.Sprintf("%s%s-%03d.tsv", packageProjectionStagePrefix, intent.TransactionID, index)
		if key <= previous || !validMaterializationJournalString(unit.Repo, 256) ||
			(unit.View != "beta" && unit.View != "latest" && unit.View != "stable") ||
			!validMaterializationJournalString(unit.OS, 256) || !validMaterializationJournalString(unit.Arch, 256) ||
			!validOfflineArchivePath(unit.ViewPath) || !strings.HasPrefix(unit.ViewRef, "refs/sow/views/") ||
			!materializationCommitPattern.MatchString(unit.ExpectedRef) || !validMaterializationTrustSHA256(unit.ManifestSHA256) || unit.ManifestSize < 0 ||
			unit.StageRelative != wantedStage {
			return errors.New("invalid or unsorted pending package projection unit")
		}
		if plumbing.ReferenceName(unit.ViewRef).Validate() != nil {
			return errors.New("invalid pending package projection ref")
		}
		previous = key
	}
	wanted, err := packageProjectionIntentID(intent)
	if err != nil || wanted != intent.ID {
		return errors.Join(err, errors.New("pending package projection ID mismatch"))
	}
	return nil
}

func writePackageProjectionIntent(stateRoot string, intent packageProjectionIntent) error {
	body, err := marshalPackageProjectionIntent(intent)
	if err != nil {
		return err
	}
	result, err := writeDerivedStateFileOutcome(stateRoot, packageProjectionIntentRelative, body)
	return consumeDerivedStateReplacement(result, err)
}

func installPackageProjectionIntent(stateRoot string, intent packageProjectionIntent, boundRoot os.FileInfo) error {
	body, err := marshalPackageProjectionIntent(intent)
	if err != nil {
		return err
	}
	return packageProjectionIntentInstall(stateRoot, packageProjectionIntentRelative, body, boundRoot)
}

func marshalPackageProjectionIntent(intent packageProjectionIntent) ([]byte, error) {
	if err := intent.validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(intent)
	if err != nil || len(body) > packageProjectionIntentMaxBytes {
		return nil, errors.Join(err, errors.New("pending package projection exceeds size limit"))
	}
	return body, nil
}

func readPackageProjectionIntent(stateRoot string) (packageProjectionIntent, bool, error) {
	var intent packageProjectionIntent
	filename := filepath.Join(stateRoot, packageProjectionIntentRelative)
	info, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return intent, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > packageProjectionIntentMaxBytes {
		return intent, false, errors.Join(err, errors.New("pending package projection is not a private exact regular file"))
	}
	body, err := readBoundedExactRegularFile(stateRoot, packageProjectionIntentRelative, packageProjectionIntentMaxBytes)
	if err != nil {
		return intent, false, err
	}
	intent, err = decodePackageProjectionIntent(body)
	if err != nil {
		return intent, false, err
	}
	return intent, true, intent.validate()
}

func decodePackageProjectionIntent(body []byte) (packageProjectionIntent, error) {
	var intent packageProjectionIntent
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&intent); err != nil {
		return intent, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return intent, errors.New("pending package projection has trailing content")
	}
	return intent, nil
}

func packageProjectionCompletionReceiptID(receipt packageProjectionCompletionReceipt) (string, error) {
	receipt.ID = ""
	body, err := json.Marshal(receipt)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

func (receipt packageProjectionCompletionReceipt) validate(intentID string) error {
	if receipt.Schema != packageProjectionCompletionSchema || receipt.IntentID != intentID ||
		!validMaterializationTrustSHA256(receipt.ID) || !validMaterializationTrustSHA256(receipt.IntentID) ||
		!assetProjectionTransactionIDPattern.MatchString(receipt.TransactionID) ||
		!materializationCommitPattern.MatchString(receipt.Commit) || plumbing.NewHash(receipt.Commit).IsZero() {
		return errors.New("invalid package projection completion receipt")
	}
	wanted, err := packageProjectionCompletionReceiptID(receipt)
	if err != nil || wanted != receipt.ID {
		return errors.Join(err, errors.New("package projection completion receipt ID mismatch"))
	}
	return nil
}

func packageProjectionCompletionRelative(intentID string) (string, error) {
	if !validMaterializationTrustSHA256(intentID) {
		return "", errors.New("invalid package projection completion intent ID")
	}
	return packageProjectionCompletionPrefix + intentID + ".json", nil
}

func readPackageProjectionCompletionReceipt(stateRoot, intentID string) (packageProjectionCompletionReceipt, bool, error) {
	var receipt packageProjectionCompletionReceipt
	relative, err := packageProjectionCompletionRelative(intentID)
	if err != nil {
		return receipt, false, err
	}
	filename := filepath.Join(stateRoot, relative)
	info, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return receipt, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > packageProjectionCompletionMax {
		return receipt, false, errors.Join(err, errors.New("package projection completion receipt is not a private exact regular file"))
	}
	body, err := readBoundedExactRegularFile(stateRoot, relative, packageProjectionCompletionMax)
	if err != nil {
		return receipt, false, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, false, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return receipt, false, errors.New("package projection completion receipt has trailing content")
	}
	return receipt, true, receipt.validate(intentID)
}

func writePackageProjectionCompletionReceipt(stateRoot string, intent packageProjectionIntent) (packageProjectionCompletionReceipt, error) {
	var receipt packageProjectionCompletionReceipt
	record, exists, err := state.New(stateRoot).Transaction(intent.TransactionID)
	if err != nil || !exists || record.Phase != "complete" || record.Commit.IsZero() ||
		record.Operation != intent.Operation || record.Message != intent.Message || record.ExpectedHead.String() != intent.ExpectedHead {
		return receipt, errors.Join(err, errors.New("package projection canonical transaction is not complete"))
	}
	receipt = packageProjectionCompletionReceipt{
		Schema: packageProjectionCompletionSchema, IntentID: intent.ID,
		TransactionID: intent.TransactionID, Commit: record.Commit.String(),
	}
	receipt.ID, err = packageProjectionCompletionReceiptID(receipt)
	if err != nil {
		return packageProjectionCompletionReceipt{}, err
	}
	if err := receipt.validate(intent.ID); err != nil {
		return packageProjectionCompletionReceipt{}, err
	}
	if current, exists, err := readPackageProjectionCompletionReceipt(stateRoot, intent.ID); err != nil {
		return packageProjectionCompletionReceipt{}, err
	} else if exists {
		if current != receipt {
			return packageProjectionCompletionReceipt{}, errors.New("package projection completion receipt changed")
		}
		return current, nil
	}
	relative, _ := packageProjectionCompletionRelative(intent.ID)
	body, err := json.Marshal(receipt)
	if err != nil || len(body) > packageProjectionCompletionMax {
		return packageProjectionCompletionReceipt{}, errors.Join(err, errors.New("package projection completion receipt exceeds size limit"))
	}
	result, err := writeDerivedStateFileOutcome(stateRoot, relative, body)
	if err := consumeDerivedStateReplacement(result, err); err != nil {
		return packageProjectionCompletionReceipt{}, err
	}
	return receipt, nil
}

func cleanupPackageProjectionIntentResidue(stateRoot string, recover bool) error {
	if err := recoverDerivedStateReplacementTransactions(stateRoot, ".", recover); err != nil {
		return err
	}
	entries, err := os.ReadDir(stateRoot)
	if err != nil {
		return err
	}
	intent, exists, readErr := readPackageProjectionIntent(stateRoot)
	if readErr != nil {
		return readErr
	}
	wanted := make(map[string]struct{})
	if exists {
		wanted[intent.ConfigStage] = struct{}{}
		for _, unit := range intent.Units {
			wanted[unit.StageRelative] = struct{}{}
		}
	}
	removed := false
	preserved := make([]string, 0)
	for _, entry := range entries {
		name := entry.Name()
		isIntentTemporary := isDerivedStateTemporaryName(name, packageProjectionIntentRelative)
		isStageTemporary := isProjectionStageTemporaryName(name, isPackageProjectionStageFinalName)
		isPreserved := isProjectionStagePreservedName(name, isPackageProjectionStageFinalName)
		isProjectionStage := isPackageProjectionStageFinalName(name)
		if isPreserved {
			continue
		}
		_, retained := wanted[name]
		if retained && isProjectionStage {
			continue
		}
		isOrphanStage := isProjectionStage && !retained
		if !isIntentTemporary && !isStageTemporary && !isOrphanStage {
			if strings.HasPrefix(name, packageProjectionStagePrefix) || strings.HasPrefix(name, packageProjectionIntentRelative+".") {
				return fmt.Errorf("unsafe pending package projection residue name %q", name)
			}
			continue
		}
		if !recover {
			return errors.New("interrupted pending package projection residue requires --recover")
		}
		if isOrphanStage {
			retainedName, moved, err := preserveExactProjectionResidue(stateRoot, name)
			if err != nil {
				return errors.Join(err, fmt.Errorf("unsafe pending package projection residue %s", name))
			}
			if moved {
				preserved = append(preserved, retainedName)
			}
			continue
		}
		exact, err := removeExactProjectionResidue(stateRoot, name)
		if err != nil {
			return errors.Join(err, errors.New("unsafe pending package projection residue"))
		}
		removed = removed || exact
	}
	if removed {
		if err := syncLocalDirectory(stateRoot); err != nil {
			return err
		}
	}
	if len(preserved) != 0 {
		return fmt.Errorf("preserved orphan package projection residue at %s; inspect it, then retry with --recover", strings.Join(preserved, ", "))
	}
	return nil
}

func preparePackageProjectionIntent(cfg *config.Config, canonical *state.Store, operation, family string, mutations []packageProjectionMutation, staged map[string]string, trust *materializationTrustSnapshot, privateKey, passphrase []byte) (intent packageProjectionIntent, durable map[string]string, resultErr error) {
	if len(mutations) == 0 || (family != "apt" && family != "yum" && family != "mixed") {
		return intent, nil, errors.New("pending package projection mutation set is empty or invalid")
	}
	if trust == nil || !validMaterializationTrustSHA256(trust.repositoryKeySHA256) {
		return intent, nil, errors.New("pending package projection materialization trust is unavailable")
	}
	if trust.verificationTime.IsZero() {
		return intent, nil, errors.New("pending package projection signing time was not validated under the state lock")
	}
	signingTime := trust.verificationTime.UTC().Truncate(time.Second)
	if _, err := parsePackageProjectionSigningTime(signingTime.Format(time.RFC3339)); err != nil {
		return intent, nil, err
	}
	if _, exists, err := readPackageProjectionIntent(cfg.StatePath()); err != nil || exists {
		return intent, nil, errors.Join(err, errors.New("another pending package projection already exists"))
	}
	transactionID, err := state.NewTransactionID()
	if err != nil {
		return intent, nil, err
	}
	sort.Slice(mutations, func(i, j int) bool {
		left := strings.Join([]string{mutations[i].view, mutations[i].leaf.repo.ID, mutations[i].leaf.os, mutations[i].leaf.arch}, "\x00")
		right := strings.Join([]string{mutations[j].view, mutations[j].leaf.repo.ID, mutations[j].leaf.os, mutations[j].leaf.arch}, "\x00")
		return left < right
	})
	head, err := canonical.HeadHash()
	if err != nil {
		return intent, nil, err
	}
	canonicalConfig, err := cfg.Canonical()
	if err != nil {
		return intent, nil, err
	}
	configDigest := sha256.Sum256(canonicalConfig)
	configSHA := hex.EncodeToString(configDigest[:])
	targetSHA, err := materializationTargetSHA256(cfg.Root)
	if err != nil {
		return intent, nil, err
	}
	durable = make(map[string]string, len(staged))
	for path, source := range staged {
		durable[path] = source
	}
	installed := make([]projectionStageIdentity, 0, len(mutations)+1)
	keepStages := false
	defer func() {
		if resultErr != nil && !keepStages {
			resultErr = errors.Join(resultErr, rollbackInstalledProjectionStages(installed))
		}
	}()
	intent = packageProjectionIntent{
		Schema: packageProjectionIntentSchema, Operation: operation, Family: family, SigningTime: signingTime.Format(time.RFC3339), TransactionID: transactionID,
		ConfigSHA256: configSHA, ConfigSize: int64(len(canonicalConfig)), ConfigStage: packageProjectionStagePrefix + transactionID + "-config.yaml",
		ExpectedHead: head.String(), TargetSHA256: targetSHA, RepositoryKeySHA256: trust.repositoryKeySHA256,
	}
	_, configIdentity, err := installProjectionStageBytes(cfg.StatePath(), intent.ConfigStage, canonicalConfig)
	if err != nil {
		return packageProjectionIntent{}, nil, err
	}
	installed = append(installed, configIdentity)
	durable["config/sow.yaml"] = filepath.Join(cfg.StatePath(), intent.ConfigStage)
	repoIDs := make([]string, 0, len(trust.yum))
	for repoID := range trust.yum {
		repoIDs = append(repoIDs, repoID)
	}
	sort.Strings(repoIDs)
	for _, repoID := range repoIDs {
		frozen := trust.yum[repoID]
		if !validMaterializationTrustSHA256(frozen.digest) {
			return packageProjectionIntent{}, nil, fmt.Errorf("package projection YUM trust for repo %s is invalid", repoID)
		}
		intent.YUMPackageKeyringSHA256 = append(intent.YUMPackageKeyringSHA256, packageProjectionYUMKeyring{Repo: repoID, SHA256: frozen.digest})
	}
	for index, mutation := range mutations {
		source, exists := staged[mutation.viewPath]
		if !exists {
			return packageProjectionIntent{}, nil, fmt.Errorf("package projection stage %s is absent", mutation.viewPath)
		}
		stageRelative := fmt.Sprintf("%s%s-%03d.tsv", packageProjectionStagePrefix, transactionID, index)
		object, stageIdentity, err := installPendingProjectionStageBound(cfg.StatePath(), stageRelative, source, configIdentity.root)
		if err != nil {
			return packageProjectionIntent{}, nil, err
		}
		installed = append(installed, stageIdentity)
		durable[mutation.viewPath] = filepath.Join(cfg.StatePath(), stageRelative)
		intent.Units = append(intent.Units, packageProjectionIntentUnit{
			Repo: mutation.leaf.repo.ID, View: mutation.view, OS: mutation.leaf.os, Arch: mutation.leaf.arch,
			ViewPath: mutation.viewPath, ViewRef: mutation.viewRef, ExpectedRef: mutation.expected,
			ManifestSHA256: object.HashString(), ManifestSize: object.Size, StageRelative: stageRelative,
		})
	}
	intent.Message = packageProjectionMessage(operation, family, intent.SigningTime, transactionID, len(intent.Units), intent.RepositoryKeySHA256, intent.YUMPackageKeyringSHA256)
	if err := attestPackageProjectionIntent(&intent, privateKey, passphrase); err != nil {
		return packageProjectionIntent{}, nil, err
	}
	intent.ID, err = packageProjectionIntentID(intent)
	if err != nil {
		return packageProjectionIntent{}, nil, err
	}
	if err := verifyInstalledProjectionStages(installed); err != nil {
		return packageProjectionIntent{}, nil, err
	}
	if err := installPackageProjectionIntent(cfg.StatePath(), intent, configIdentity.root); err != nil {
		if rootErr := verifyProjectionStageRootIdentity(cfg.StatePath(), configIdentity.root); rootErr != nil {
			keepStages = true
			return intent, nil, errors.Join(err, rootErr, errors.New("restore the exact projection state root, then retry with --recover"))
		}
		current, exists, readErr := readPackageProjectionIntent(cfg.StatePath())
		rootErr := verifyProjectionStageRootIdentity(cfg.StatePath(), configIdentity.root)
		if rootErr != nil {
			keepStages = true
			return intent, nil, errors.Join(err, readErr, rootErr, errors.New("restore the exact projection state root, then retry with --recover"))
		}
		if readErr != nil {
			keepStages = true
			return intent, nil, errors.Join(err, readErr, errors.New("pending package projection intent commit is ambiguous; retry with --recover"))
		}
		if exists && current.ID == intent.ID {
			keepStages = true
			return intent, nil, errors.Join(err, errors.New("pending package projection intent may require --recover after directory sync failure"))
		}
		return packageProjectionIntent{}, nil, err
	}
	keepStages = true
	if err := verifyInstalledProjectionStages(installed); err != nil {
		return intent, nil, errors.Join(err, errors.New("pending package projection intent committed with changed stages; retry with --recover"))
	}
	return intent, durable, nil
}

func removePackageProjectionIntent(stateRoot string, intent packageProjectionIntent) error {
	current, exists, err := readPackageProjectionIntent(stateRoot)
	if err != nil || !exists || current.ID != intent.ID {
		return errors.Join(err, errors.New("pending package projection changed before completion"))
	}
	// The per-intent receipt is the durable proof consumed by a recovery caller
	// that observed this bridge before blocking on the global lock. It is
	// committed while the unique intent and all frozen stages still exist, so a
	// missing bridge can never be mistaken for successful recovery by absence.
	if _, err := writePackageProjectionCompletionReceipt(stateRoot, intent); err != nil {
		return err
	}
	if err := removeExactProjectionIntent(stateRoot, packageProjectionIntentRelative, packageProjectionIntentMaxBytes, func(body []byte) error {
		current, err := decodePackageProjectionIntent(body)
		if err != nil {
			return errors.Join(err, errors.New("pending package projection changed before completion"))
		}
		if err := current.validate(); err != nil || current.ID != intent.ID {
			return errors.Join(err, errors.New("pending package projection changed before completion"))
		}
		return nil
	}); err != nil {
		return err
	}
	// Intent removal is the completion commit. Make that directory update
	// durable before touching its only frozen stages. Once the intent pathname
	// has disappeared, cleanup failures are never reported as a transaction
	// failure: the operation is complete and residue is recoverable garbage, not
	// an instruction that can still be replayed.
	if err := syncLocalDirectory(stateRoot); err != nil {
		return nil
	}
	if packageProjectionCleanupHook != nil {
		packageProjectionCleanupHook(intent)
	}
	removed := false
	for _, unit := range intent.Units {
		if exact, _ := removeExactProjectionStage(stateRoot, unit.StageRelative, unit.ManifestSize, unit.ManifestSHA256); exact {
			removed = true
		}
	}
	if exact, _ := removeExactProjectionStage(stateRoot, intent.ConfigStage, intent.ConfigSize, intent.ConfigSHA256); exact {
		removed = true
	}
	if removed {
		_ = syncLocalDirectory(stateRoot)
	}
	return nil
}

func requirePackageProjectionConfig(cfg *config.Config, canonical *state.Store, intent packageProjectionIntent) ([]packageProjectionMutation, error) {
	configSHA, err := cfg.CanonicalSHA256()
	if err != nil || configSHA != intent.ConfigSHA256 {
		return nil, errors.Join(err, errors.New("pending package projection configuration changed"))
	}
	configStage := filepath.Join(cfg.StatePath(), intent.ConfigStage)
	configObject, err := inspectOfflineArchiveInput(configStage)
	if err != nil || configObject.Object.HashString() != intent.ConfigSHA256 || configObject.Object.Size != intent.ConfigSize {
		return nil, errors.Join(err, errors.New("pending package projection staged config changed"))
	}
	targetSHA, err := materializationTargetSHA256(cfg.Root)
	if err != nil || targetSHA != intent.TargetSHA256 {
		return nil, errors.Join(err, errors.New("pending package projection target changed"))
	}
	result := make([]packageProjectionMutation, 0, len(intent.Units))
	for _, unit := range intent.Units {
		repo, exists := cfg.RepoByName(unit.Repo)
		if !exists || !repo.IsActive() || (repo.Type != "apt" && repo.Type != "yum") || intent.Family != "mixed" && repo.Type != intent.Family {
			return nil, fmt.Errorf("pending package projection repo %s changed", unit.Repo)
		}
		view, exists := cfg.Views[unit.View]
		if !exists || !viewIncludesRepo(view, repo.ID) || intent.Operation == "rm" && view.AppendOnly {
			return nil, fmt.Errorf("pending package projection view %s changed", unit.View)
		}
		wantedPath, _ := state.ViewPath(unit.View, repo.ID, unit.OS, unit.Arch)
		wantedRef, _ := state.ViewRef(unit.View, repo.ID, unit.OS, unit.Arch)
		if wantedPath != unit.ViewPath || wantedRef.String() != unit.ViewRef {
			return nil, errors.New("pending package projection coordinates changed")
		}
		stage := filepath.Join(cfg.StatePath(), unit.StageRelative)
		inspected, err := inspectOfflineArchiveInput(stage)
		if err != nil || inspected.Object.HashString() != unit.ManifestSHA256 || inspected.Object.Size != unit.ManifestSize {
			return nil, errors.Join(err, errors.New("pending package projection staged manifest changed"))
		}
		leaf := viewLeaf{repo: repo, os: unit.OS, arch: unit.Arch}
		stagedView, err := os.Open(stage)
		if err != nil {
			return nil, err
		}
		validateErr := validateViewEntries(canonical, stagedView, leaf, view.Access == "public")
		closeErr := stagedView.Close()
		if validateErr != nil || closeErr != nil {
			return nil, errors.Join(validateErr, closeErr, errors.New("pending package projection staged view violates current confidentiality closure"))
		}
		result = append(result, packageProjectionMutation{
			leaf: leaf, view: unit.View, viewPath: unit.ViewPath,
			viewRef: unit.ViewRef, expected: unit.ExpectedRef,
		})
	}
	return result, nil
}

func captureAndRequirePackageProjectionTrust(cfg *config.Config, intent packageProjectionIntent, mutations []packageProjectionMutation, privateKey []byte, repositoryKeySHA string) (*materializationTrustSnapshot, error) {
	signingTime, err := parsePackageProjectionSigningTime(intent.SigningTime)
	if err != nil {
		return nil, err
	}
	expectedYUM := make(map[string]string, len(intent.YUMPackageKeyringSHA256))
	leaves := make([]viewLeaf, 0, len(mutations)+len(intent.YUMPackageKeyringSHA256))
	seenRepo := make(map[string]struct{})
	for _, mutation := range mutations {
		leaves = append(leaves, mutation.leaf)
		seenRepo[mutation.leaf.repo.ID] = struct{}{}
	}
	for _, frozen := range intent.YUMPackageKeyringSHA256 {
		expectedYUM[frozen.Repo] = frozen.SHA256
		repo, exists := cfg.RepoByName(frozen.Repo)
		if !exists || repo.Type != "yum" || repo.YUM == nil {
			return nil, fmt.Errorf("pending package projection YUM trust repo %s changed", frozen.Repo)
		}
		if _, exists := seenRepo[repo.ID]; !exists {
			leaves = append(leaves, viewLeaf{repo: repo})
			seenRepo[repo.ID] = struct{}{}
		}
	}
	for _, mutation := range mutations {
		if mutation.leaf.repo.Type == "yum" {
			if _, exists := expectedYUM[mutation.leaf.repo.ID]; !exists {
				return nil, fmt.Errorf("pending package projection omits YUM trust for repo %s", mutation.leaf.repo.ID)
			}
		}
	}
	snapshot, err := captureMaterializationTrustAt(cfg, leaves, privateKey, repositoryKeySHA, signingTime)
	if err != nil {
		return nil, err
	}
	if snapshot == nil || snapshot.repositoryKeySHA256 != intent.RepositoryKeySHA256 || len(snapshot.yum) != len(expectedYUM) {
		return nil, errors.New("pending package projection repository trust changed")
	}
	for repoID, expected := range expectedYUM {
		current, exists := snapshot.yum[repoID]
		if !exists || current.digest != expected {
			return nil, fmt.Errorf("pending package projection RPM package keyring for repo %s changed", repoID)
		}
	}
	snapshot.verificationTime = signingTime
	return snapshot, nil
}

func requirePackageProjectionTransactionCompatible(cfg *config.Config, intent packageProjectionIntent, record state.TransactionRecord, exists bool) error {
	if !exists {
		return nil
	}
	if record.Operation != intent.Operation || record.Message != intent.Message || record.ExpectedHead.String() != intent.ExpectedHead || len(record.Refs) != len(intent.Units) {
		return errors.New("pending package projection differs from its pre-existing local transaction")
	}
	refs := make(map[string]state.TransactionRefRecord, len(record.Refs))
	for _, ref := range record.Refs {
		refs[ref.Name.String()] = ref
	}
	wantedFiles := make(map[string]state.TransactionFileRecord, len(intent.Units)+1)
	for _, unit := range intent.Units {
		ref, exists := refs[unit.ViewRef]
		targetMatches := transactionProjectionTargetMatches(record, ref.Target)
		if record.Phase == "aborted" {
			targetMatches = record.Commit.IsZero() && ref.Target.IsZero()
		}
		if !exists || ref.Expected.String() != unit.ExpectedRef || ref.Delete || ref.Immutable || !targetMatches {
			return errors.New("pending package projection ref differs from its pre-existing local transaction")
		}
		wantedFiles[unit.ViewPath] = state.TransactionFileRecord{Canonical: unit.ViewPath, Size: unit.ManifestSize, SHA256: unit.ManifestSHA256}
	}
	canonicalConfig, err := cfg.Canonical()
	if err != nil {
		return err
	}
	wantedFiles["config/sow.yaml"] = state.TransactionFileRecord{Canonical: "config/sow.yaml", Size: int64(len(canonicalConfig)), SHA256: intent.ConfigSHA256}
	if len(record.Files) != len(wantedFiles) {
		return errors.New("pending package projection file set differs from its pre-existing local transaction")
	}
	for _, file := range record.Files {
		wanted, exists := wantedFiles[file.Canonical]
		if !exists || file.Delete || file.Size != wanted.Size || file.SHA256 != wanted.SHA256 {
			return errors.New("pending package projection file identity differs from its pre-existing local transaction")
		}
	}
	return nil
}

func requirePackageProjectionCompletionCompatible(intent packageProjectionIntent, receipt packageProjectionCompletionReceipt, record state.TransactionRecord, exists bool) error {
	if !exists || record.ID != intent.TransactionID || record.Phase != "complete" || record.Commit.IsZero() ||
		record.Operation != intent.Operation || record.Message != intent.Message || record.ExpectedHead.String() != intent.ExpectedHead ||
		receipt.IntentID != intent.ID || receipt.TransactionID != intent.TransactionID || receipt.Commit != record.Commit.String() ||
		len(record.Refs) != len(intent.Units) || len(record.Files) != len(intent.Units)+1 {
		return errors.New("completed package projection transaction differs from its observed intent")
	}
	refs := make(map[string]state.TransactionRefRecord, len(record.Refs))
	for _, ref := range record.Refs {
		refs[ref.Name.String()] = ref
	}
	files := make(map[string]state.TransactionFileRecord, len(record.Files))
	for _, file := range record.Files {
		files[file.Canonical] = file
	}
	configFile, exists := files["config/sow.yaml"]
	if !exists || configFile.Delete || configFile.Size != intent.ConfigSize || configFile.SHA256 != intent.ConfigSHA256 {
		return errors.New("completed package projection config differs from its observed intent")
	}
	for _, unit := range intent.Units {
		ref, refExists := refs[unit.ViewRef]
		file, fileExists := files[unit.ViewPath]
		if !refExists || ref.Expected.String() != unit.ExpectedRef || ref.Target != record.Commit || ref.Delete || ref.Immutable ||
			!fileExists || file.Delete || file.Size != unit.ManifestSize || file.SHA256 != unit.ManifestSHA256 {
			return errors.New("completed package projection unit differs from its observed intent")
		}
	}
	return nil
}

// ensurePackageProjectionCanonical finishes only the canonical transaction
// already proven by the caller. It does not materialize physical repositories
// or clear either higher-level recovery fence.
func ensurePackageProjectionCanonical(ctx context.Context, cfg *config.Config, canonical *state.Store, intent packageProjectionIntent) (state.TransactionRecord, error) {
	record, transactionExists, err := canonical.Transaction(intent.TransactionID)
	if err != nil {
		return state.TransactionRecord{}, err
	}
	if transactionExists {
		if err := requirePackageProjectionTransactionCompatible(cfg, intent, record, true); err != nil {
			return state.TransactionRecord{}, err
		}
		if record.Phase == "aborted" {
			if _, err := canonical.RecoverAborted(ctx, record); err != nil {
				return state.TransactionRecord{}, fmt.Errorf("retry aborted package projection transaction: %w", err)
			}
			record, transactionExists, err = canonical.Transaction(intent.TransactionID)
			if err != nil || !transactionExists {
				return state.TransactionRecord{}, errors.Join(err, errors.New("retried package projection transaction is missing"))
			}
		}
	}
	if !transactionExists {
		head, err := canonical.HeadHash()
		if err != nil || head.String() != intent.ExpectedHead {
			return state.TransactionRecord{}, errors.Join(err, errors.New("pending package projection pre-commit HEAD changed"))
		}
		staged := make(map[string]string, len(intent.Units)+1)
		updates := make([]state.RefUpdate, 0, len(intent.Units))
		for _, unit := range intent.Units {
			current, refExists, err := canonical.Ref(plumbing.ReferenceName(unit.ViewRef))
			expected := plumbing.NewHash(unit.ExpectedRef)
			if err != nil || refExists != !expected.IsZero() || refExists && current != expected {
				return state.TransactionRecord{}, errors.Join(err, errors.New("pending package projection pre-commit ref changed"))
			}
			staged[unit.ViewPath] = filepath.Join(cfg.StatePath(), unit.StageRelative)
			updates = append(updates, state.RefUpdate{Name: plumbing.ReferenceName(unit.ViewRef), Expected: expected})
		}
		staged["config/sow.yaml"] = filepath.Join(cfg.StatePath(), intent.ConfigStage)
		if _, _, err := applyCanonicalConfig(ctx, cfg, canonical, intent.Operation, intent.Message, staged, updates, state.ApplyOptions{
			TransactionID:  intent.TransactionID,
			ExpectedStages: packageProjectionExpectedStages(intent),
		}); err != nil {
			return state.TransactionRecord{}, err
		}
		record, transactionExists, err = canonical.Transaction(intent.TransactionID)
		if err != nil || !transactionExists {
			return state.TransactionRecord{}, errors.Join(err, errors.New("reapplied package projection transaction is missing"))
		}
	}
	if record.Phase != "complete" || record.Operation != intent.Operation || record.Message != intent.Message || record.ExpectedHead.String() != intent.ExpectedHead || record.Commit.IsZero() || len(record.Refs) != len(intent.Units) {
		return state.TransactionRecord{}, errors.New("pending package projection transaction differs from intent")
	}
	if err := requirePackageProjectionTransactionCompatible(cfg, intent, record, true); err != nil {
		return state.TransactionRecord{}, err
	}
	refEvidence := make(map[string]state.TransactionRefRecord, len(record.Refs))
	for _, ref := range record.Refs {
		refEvidence[ref.Name.String()] = ref
	}
	for index, unit := range intent.Units {
		ref, exists := refEvidence[unit.ViewRef]
		if !exists || ref.Expected.String() != unit.ExpectedRef || ref.Target != record.Commit || ref.Delete || ref.Immutable {
			return state.TransactionRecord{}, errors.New("pending package projection old-state ref differs from transaction")
		}
		current, exists, err := canonical.Ref(plumbing.ReferenceName(unit.ViewRef))
		if err != nil || !exists || current != record.Commit {
			return state.TransactionRecord{}, errors.Join(err, errors.New("pending package projection current ref differs from transaction"))
		}
		reader, err := canonical.OpenPathAt(record.Commit, unit.ViewPath)
		if err != nil {
			return state.TransactionRecord{}, err
		}
		hasher := sha256.New()
		size, hashErr := io.Copy(hasher, reader)
		closeErr := reader.Close()
		if hashErr != nil || closeErr != nil || size != intent.Units[index].ManifestSize || hex.EncodeToString(hasher.Sum(nil)) != unit.ManifestSHA256 {
			return state.TransactionRecord{}, errors.Join(hashErr, closeErr, errors.New("pending package projection committed manifest changed"))
		}
	}
	return record, nil
}

func recoverPendingPackageProjection(ctx context.Context, cfg *config.Config, values commonFlags, operation, privateKeyFile, passphraseFile string, stdout, stderr io.Writer) (recovered bool, resultErr error) {
	intent, exists, err := readPackageProjectionIntent(cfg.StatePath())
	if err != nil || !exists {
		return false, err
	}
	if !values.recover || intent.Operation != operation {
		return true, fmt.Errorf("pending package projection %s requires matching --recover", intent.Operation)
	}
	observedIntent := intent
	observedID := intent.ID
	if packageProjectionBeforeLockHook != nil {
		if err := packageProjectionBeforeLockHook(); err != nil {
			return true, err
		}
	}
	lock, err := state.AcquireLock(cfg.StatePath(), operation, true)
	if err != nil {
		return true, err
	}
	defer propagateStateLockRelease(lock, &resultErr, stderr)
	// The pre-lock read is admission only. Another process may have recovered
	// the exact bridge while this caller waited, or a new bridge may now occupy
	// the pathname. Re-read under the global lock and treat only complete
	// disappearance (including its selected-set fence) as idempotent success.
	intent, exists, err = readPackageProjectionIntent(cfg.StatePath())
	if err != nil {
		return true, err
	}
	if !exists {
		if _, assetExists, err := readAssetProjectionIntent(cfg.StatePath()); err != nil || assetExists {
			return true, errors.Join(err, errors.New("another materialization projection replaced the recovered package intent"))
		}
		if _, journalExists, err := readMaterializationSelectionJournal(cfg.StatePath()); err != nil || journalExists {
			return true, errors.Join(err, errors.New("package intent disappeared while its selected-set journal remains"))
		}
		receipt, receiptExists, err := readPackageProjectionCompletionReceipt(cfg.StatePath(), observedIntent.ID)
		if err != nil || !receiptExists {
			return true, errors.Join(err, errors.New("package intent disappeared without an exact durable completion receipt"))
		}
		canonical := state.New(cfg.StatePath())
		record, transactionExists, err := canonical.Transaction(observedIntent.TransactionID)
		if err != nil {
			return true, err
		}
		if err := requirePackageProjectionCompletionCompatible(observedIntent, receipt, record, transactionExists); err != nil {
			return true, err
		}
		fmt.Fprintln(stdout, "pending package projection was already recovered while waiting for the state lock")
		return true, nil
	}
	if intent.ID != observedID {
		return true, errors.New("pending package projection changed while waiting for the state lock")
	}
	if intent.Operation != operation {
		return true, fmt.Errorf("pending package projection %s replaced matching %s recovery", intent.Operation, operation)
	}
	if err := requireNoForeignMaterializationIntent(cfg, operation, true); err != nil {
		return true, err
	}
	canonical := state.New(cfg.StatePath())
	if err := requireProjectionTransactionsCompatibleBeforeRecovery(cfg, canonical, operation); err != nil {
		return true, err
	}
	mutations, err := requirePackageProjectionConfig(cfg, canonical, intent)
	if err != nil {
		return true, err
	}
	privateKey, err := resolveSecret(cfg.GPG.PrivateKey, privateKeyFile, false)
	if err != nil {
		return true, err
	}
	defer clearSecret(privateKey)
	passphrase, err := resolveSecret(cfg.GPG.Passphrase, passphraseFile, true)
	if err != nil {
		return true, err
	}
	defer clearSecret(passphrase)
	signingTime, err := requirePackageProjectionSigningSecret(intent, privateKey, passphrase)
	if err != nil {
		return true, err
	}
	repositoryKeySHA, err := repositorySigningKeyIdentityAt(cfg, privateKey, signingTime)
	if err != nil {
		return true, err
	}
	if err := requirePackageProjectionIntentAttestation(cfg, intent); err != nil {
		return true, err
	}
	trust, err := captureAndRequirePackageProjectionTrust(cfg, intent, mutations, privateKey, repositoryKeySHA)
	if err != nil {
		return true, err
	}
	if err := prepareCanonicalState(ctx, canonical, true, stdout); err != nil {
		return true, err
	}
	if err := requireCanonicalConfigBaseline(cfg, canonical); err != nil {
		return true, err
	}
	record, err := ensurePackageProjectionCanonical(ctx, cfg, canonical, intent)
	if err != nil {
		return true, err
	}
	recoveryValues := values
	recoveryValues.materializeTrust = trust
	recoveryValues.materializeOperation = operation
	if err := materializePendingPackageProjection(ctx, cfg, canonical, intent, mutations, recoveryValues, privateKey, passphrase, repositoryKeySHA, stdout); err != nil {
		return true, err
	}
	if err := removePackageProjectionIntent(cfg.StatePath(), intent); err != nil {
		return true, err
	}
	fmt.Fprintf(stdout, "recovered pending package projection operation=%s family=%s units=%d commit=%s\n", operation, intent.Family, len(intent.Units), record.Commit)
	return true, nil
}

func materializePendingPackageProjection(ctx context.Context, cfg *config.Config, canonical *state.Store, intent packageProjectionIntent, mutations []packageProjectionMutation, values commonFlags, privateKey, passphrase []byte, repositoryKeySHA string, stdout io.Writer) (resultErr error) {
	byView := make(map[string][]viewLeaf)
	for _, mutation := range mutations {
		byView[mutation.view] = append(byView[mutation.view], mutation.leaf)
	}
	txDir, err := newTransactionDir(cfg.StatePath(), "package-projection-recover-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(txDir)
	pool, err := repository.NewStore(cfg.Root)
	if err != nil {
		return err
	}
	ledgerStages := make(map[string]string)
	exactByView := make(map[string]map[materializedRouteOwnerID]string)
	viewNames := make([]string, 0, len(byView))
	for view := range byView {
		viewNames = append(viewNames, view)
	}
	sort.Strings(viewNames)
	closedByView := make(map[string][]viewLeaf)
	requests := make([]materializationSelectionRequest, 0, len(viewNames))
	for _, view := range viewNames {
		source := materializeCanonicalSource{ID: view, Public: cfg.Views[view].Access == "public"}
		closed, err := packageMaterializationPhysicalClosureLeaves(cfg, canonical, source, byView[view])
		if err != nil {
			return err
		}
		closedByView[view] = closed
		requests = append(requests, materializationSelectionRequest{
			Source: source, Leaves: closed, TargetRoot: cfg.Root, IncludeMetadata: true, ExpandAPT: true,
		})
	}
	// Adopt or create the complete durable unit vector once. Every APT repo and
	// YUM physical owner below is then a nested subset. Starting recovery in the
	// first owner would incorrectly demand that one subset equal a pre-existing
	// multi-owner journal and permanently reject an otherwise exact replay.
	values, selectionOwner, err := beginMaterializationSelectionForRequests(cfg, canonical, values, intent.Operation, requests)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, finishMaterializationSelectedSet(cfg, values.materializeTrust, selectionOwner, resultErr))
	}()
	for _, view := range viewNames {
		closed := closedByView[view]
		aptDone := make(map[string]struct{})
		yumDone := make(map[materializedRouteOwnerID]struct{})
		for _, leaf := range closed {
			if exactByView[view] == nil {
				exactByView[view] = make(map[materializedRouteOwnerID]string)
			}
			switch leaf.repo.Type {
			case "apt":
				if _, exists := aptDone[leaf.repo.ID]; exists {
					continue
				}
				if err := requireRepositorySigningKeyIdentityAt(cfg, privateKey, repositoryKeySHA, values.materializeTrust.verificationTime); err != nil {
					return err
				}
				result, err := materializeAPTRepo(ctx, cfg, canonical, pool, leaf.repo, view, txDir, values, privateKey, passphrase)
				if err != nil {
					return err
				}
				if err := mergeAPTByHashStages(ledgerStages, result.Ledgers); err != nil {
					return err
				}
				exactByView[view][materializedRouteOwnerID{kind: "apt", repo: leaf.repo.ID, arch: "all"}] = result.ExactManifest
				aptDone[leaf.repo.ID] = struct{}{}
			case "yum":
				ownerID := materializedRouteOwnerID{kind: "yum", repo: leaf.repo.ID, arch: leaf.arch}
				if _, exists := yumDone[ownerID]; exists {
					continue
				}
				var ownerLeaves []viewLeaf
				for _, candidate := range closed {
					if candidate.repo.ID == leaf.repo.ID && candidate.repo.Type == "yum" && candidate.arch == leaf.arch {
						ownerLeaves = append(ownerLeaves, candidate)
					}
				}
				result, err := materializeYUMOwner(ctx, cfg, canonical, pool, leaf.repo, ownerLeaves, view, txDir, values, privateKey, passphrase)
				if err != nil {
					return err
				}
				exactByView[view][ownerID] = result.ExactManifest
				yumDone[ownerID] = struct{}{}
			}
		}
	}
	if len(ledgerStages) != 0 {
		if _, _, err := persistAPTByHashStages(ctx, canonical, intent.Operation, ledgerStages); err != nil {
			return err
		}
	}
	for _, view := range viewNames {
		if _, _, _, err := persistPackageMaterializationReceipts(ctx, cfg, canonical, pool, view, closedByView[view], exactByView[view], txDir, values, values.materializeTrust); err != nil {
			return err
		}
		if intent.Operation == "rm" && view == "latest" {
			if _, _, err := refreshWorkingTreeBaselines(ctx, cfg, canonical, workingTreeReposFromLeaves(removalLeafMap(closedByView[view])), txDir, values, "rm-working-tree", state.ApplyOptions{}, stdout); err != nil {
				return err
			}
		}
	}
	return rebuildCatalogProjection(ctx, cfg, stdout)
}
