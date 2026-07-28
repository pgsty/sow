package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/verify"
)

const preservedProjectionAuditMaximum = 1024

var errPreservedProjectionRetirementConflict = errors.New("preserved projection retirement confirmation conflict")

type preservedProjectionAuditRecord struct {
	Kind            string
	Name            string
	Size            int64
	SHA256          string
	RetirementToken string
}

type preservedProjectionAudit struct {
	stateRoot string
	records   []preservedProjectionAuditRecord
	findings  []verify.Finding
}

func classifyPreservedProjectionAuditName(name string) (kind string, valid, related bool) {
	switch {
	case isProjectionStagePreservedName(name, isAssetProjectionStageFinalName):
		return "asset", true, true
	case isProjectionStagePreservedName(name, isPackageProjectionStageFinalName):
		return "package", true, true
	case strings.HasPrefix(name, assetProjectionStagePrefix) && strings.Contains(name, ".preserved-"),
		strings.HasPrefix(name, packageProjectionStagePrefix) && strings.Contains(name, ".preserved-"):
		return "", false, true
	default:
		return "", false, false
	}
}

func preservedProjectionRetirementToken(kind, name string, identity derivedStateReplacementIdentity, security derivedStateSecurityIdentity) (string, error) {
	if (kind != "asset" && kind != "package") || filepath.Base(name) != name || name == "" ||
		identity.Size < 0 || !validMaterializationTrustSHA256(identity.SHA256) ||
		identity.Device == 0 && identity.Inode == 0 || security.links != 1 {
		return "", errors.New("preserved projection retirement identity is invalid")
	}
	hasher := sha256.New()
	fmt.Fprintf(
		hasher,
		"sow-preserved-projection-retirement-v1\x00%s\x00%s\x00%d\x00%s\x00%d\x00%d\x00%d\x00%d\x00%d\x00%d\x00%d",
		kind,
		name,
		identity.Size,
		identity.SHA256,
		identity.Mode,
		identity.Device,
		identity.Inode,
		identity.ModTimeNS,
		security.uid,
		security.gid,
		security.links,
	)
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func inspectPreservedProjectionAudits(stateRoot string) (preservedProjectionAudit, error) {
	var result preservedProjectionAudit
	stateRoot, root, rootIdentity, err := bindAdmittedDerivedStateDirectory(stateRoot, "preserved projection audit state root")
	if err != nil {
		return result, err
	}
	result.stateRoot = stateRoot
	defer root.Close()
	directory, err := root.Open(".")
	if err != nil {
		return result, err
	}
	defer directory.Close()

	for {
		entries, readErr := directory.ReadDir(128)
		for _, entry := range entries {
			name := entry.Name()
			kind, valid, related := classifyPreservedProjectionAuditName(name)
			if !related {
				continue
			}
			if !valid {
				return result, fmt.Errorf("unsafe preserved projection audit quarantine name %q", name)
			}
			if len(result.records) >= preservedProjectionAuditMaximum {
				return result, fmt.Errorf("preserved projection audit quarantine count exceeds %d", preservedProjectionAuditMaximum)
			}
			file, inode, err := bindExactProjectionResidue(root, name, -1)
			if err != nil {
				return result, fmt.Errorf("bind preserved projection audit quarantine %s: %w", name, err)
			}
			if inode.Size() == math.MaxInt64 {
				_ = file.Close()
				return result, fmt.Errorf("preserved projection audit quarantine %s is too large to inspect safely", name)
			}
			identity, identityErr := replacementIdentityFromFile(file, inode, nil)
			_, coordinateErr := verifyBoundDerivedStateControlFile(root, name, file, inode, "preserved projection audit quarantine")
			rootErr := verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity)
			closeErr := file.Close()
			if identityErr != nil || coordinateErr != nil || rootErr != nil || closeErr != nil {
				return result, fmt.Errorf(
					"inspect preserved projection audit quarantine %s: %w",
					name,
					errors.Join(identityErr, coordinateErr, rootErr, closeErr),
				)
			}
			security, err := admitDerivedStateControlFile(inode, "preserved projection audit quarantine")
			if err != nil {
				return result, fmt.Errorf("admit preserved projection audit quarantine %s: %w", name, err)
			}
			token, err := preservedProjectionRetirementToken(kind, name, identity, security)
			if err != nil {
				return result, fmt.Errorf("construct preserved projection retirement token for %s: %w", name, err)
			}
			result.records = append(result.records, preservedProjectionAuditRecord{
				Kind: kind, Name: name, Size: identity.Size, SHA256: identity.SHA256, RetirementToken: token,
			})
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return result, readErr
		}
	}
	if err := verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity); err != nil {
		return result, err
	}
	sort.Slice(result.records, func(i, j int) bool { return result.records[i].Name < result.records[j].Name })
	for _, record := range result.records {
		result.findings = append(result.findings, verify.Finding{
			Layer: verify.LayerL1, Severity: verify.SeverityCritical, Category: verify.CategoryIntegrity,
			Code: "PRESERVED_PROJECTION_AUDIT_QUARANTINE", Subject: "state/" + record.Name,
			Message: "a preserved projection orphan requires operator inspection and explicit capability-bound retirement",
			Fields: []verify.Field{
				{Key: "kind", Value: record.Kind},
				{Key: "name", Value: record.Name},
				{Key: "retire_token", Value: record.RetirementToken},
				{Key: "sha256", Value: record.SHA256},
				{Key: "size", Value: fmt.Sprint(record.Size)},
			},
		})
	}
	return result, nil
}

func invalidPreservedProjectionAudit(err error) preservedProjectionAudit {
	return preservedProjectionAudit{findings: []verify.Finding{{
		Layer: verify.LayerL1, Severity: verify.SeverityCritical, Category: verify.CategoryIntegrity,
		Code: "PRESERVED_PROJECTION_AUDIT_INVALID", Subject: "state/projection-audit-quarantine",
		Message: "preserved projection audit inventory is unreadable, unsafe, or exceeds its bounded cardinality",
		Fields:  []verify.Field{{Key: "reason", Value: err.Error()}},
	}}}
}

func (audit preservedProjectionAudit) pending() bool { return len(audit.findings) != 0 }

func (audit preservedProjectionAudit) verifyCheck() verify.Check {
	findings := append([]verify.Finding(nil), audit.findings...)
	return verify.CheckFunc{
		CheckID: "state/projection-audit-quarantine", CheckLayer: verify.LayerL1,
		Run: func(_ context.Context, recorder *verify.Recorder) error {
			for _, finding := range findings {
				recorder.Add(finding)
			}
			return nil
		},
	}
}

func (audit preservedProjectionAudit) writeFSCKDrift(output io.Writer) {
	for _, finding := range audit.findings {
		if finding.Code == "PRESERVED_PROJECTION_AUDIT_INVALID" {
			reason := ""
			if len(finding.Fields) != 0 {
				reason = finding.Fields[0].Value
			}
			fmt.Fprintf(output, "drift code=%s subject=%q reason=%q\n", finding.Code, finding.Subject, reason)
			continue
		}
		record := audit.recordBySubject(finding.Subject)
		fmt.Fprintf(
			output,
			"drift code=%s subject=%q kind=%s size=%d sha256=%s retire_token=%s\n",
			finding.Code,
			finding.Subject,
			record.Kind,
			record.Size,
			record.SHA256,
			record.RetirementToken,
		)
	}
}

func (audit preservedProjectionAudit) recordBySubject(subject string) preservedProjectionAuditRecord {
	name := strings.TrimPrefix(subject, "state/")
	for _, record := range audit.records {
		if record.Name == name {
			return record
		}
	}
	return preservedProjectionAuditRecord{}
}

func (audit preservedProjectionAudit) retire(name, confirmation string) (preservedProjectionAuditRecord, bool, bool, error) {
	_, valid, _ := classifyPreservedProjectionAuditName(name)
	if !valid || filepath.Base(name) != name {
		return preservedProjectionAuditRecord{}, false, false, fmt.Errorf("%w: invalid preserved projection name", errPreservedProjectionRetirementConflict)
	}
	if !exactLowerHex(confirmation, sha256.Size*2) {
		return preservedProjectionAuditRecord{}, false, false, fmt.Errorf("%w: confirmation must be one lowercase SHA-256", errPreservedProjectionRetirementConflict)
	}
	record, retired, absent, err := retireCurrentPreservedProjectionAudit(audit.stateRoot, name, confirmation)
	if err != nil {
		return record, false, false, fmt.Errorf("%w: %v", errPreservedProjectionRetirementConflict, err)
	}
	return record, retired, absent, nil
}

func requirePreservedProjectionRetirementQuiescent(cfg *config.Config) error {
	if cfg == nil {
		return errors.New("preserved projection retirement configuration is unavailable")
	}
	if err := requireNoMaterializationIntentBeforeCanonicalMutation(cfg); err != nil {
		return err
	}
	if err := state.New(cfg.StatePath()).RequireNoIncompleteTransactions(); err != nil {
		return err
	}
	if pending, err := pendingCatalogProjectionMutation(cfg.StatePath()); err != nil {
		return err
	} else if pending {
		return errors.New("pending SQLite catalog projection blocks preserved projection retirement")
	}
	if err := requireNoPendingYUMCompatibilityCutoverJournals(cfg.StatePath()); err != nil {
		return err
	}
	if err := requireNoLocalServingTransactions(cfg.StatePath()); err != nil {
		return err
	}
	if err := requireNoLocalServingTopologyRemovals(cfg.StatePath()); err != nil {
		return err
	}
	if err := requireNoDerivedStateReplacementTransactionsReadOnly(cfg.StatePath()); err != nil {
		return err
	}
	return nil
}

func requireNoDerivedStateReplacementTransactionsReadOnly(stateRoot string) error {
	audit, err := inspectDerivedStateResidues(stateRoot)
	if err != nil {
		return err
	}
	if audit.pending() {
		return errors.New("interrupted derived state replacement or temporary residue blocks preserved projection retirement")
	}
	return nil
}

func retireCurrentPreservedProjectionAudit(stateRoot, name, confirmation string) (preservedProjectionAuditRecord, bool, bool, error) {
	kind, valid, _ := classifyPreservedProjectionAuditName(name)
	if stateRoot == "" || !valid || !exactLowerHex(confirmation, sha256.Size*2) {
		return preservedProjectionAuditRecord{}, false, false, errors.New("preserved projection retirement capability is invalid")
	}
	stateRoot, root, rootIdentity, err := bindAdmittedDerivedStateDirectory(stateRoot, "preserved projection retirement state root")
	if err != nil {
		return preservedProjectionAuditRecord{}, false, false, err
	}
	defer root.Close()
	if _, err := root.Lstat(name); errors.Is(err, os.ErrNotExist) {
		return preservedProjectionAuditRecord{Kind: kind, Name: name}, false, true, verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity)
	} else if err != nil {
		return preservedProjectionAuditRecord{}, false, false, err
	}
	file, inode, err := bindExactProjectionResidue(root, name, -1)
	if err != nil {
		return preservedProjectionAuditRecord{}, false, false, err
	}
	defer file.Close()
	if inode.Size() == math.MaxInt64 {
		return preservedProjectionAuditRecord{}, false, false, errors.New("preserved projection audit quarantine is too large to retire safely")
	}
	identity, err := replacementIdentityFromFile(file, inode, nil)
	if err != nil {
		return preservedProjectionAuditRecord{}, false, false, err
	}
	security, err := admitDerivedStateControlFile(inode, "preserved projection audit quarantine")
	if err != nil {
		return preservedProjectionAuditRecord{}, false, false, err
	}
	token, err := preservedProjectionRetirementToken(kind, name, identity, security)
	if err != nil {
		return preservedProjectionAuditRecord{}, false, false, err
	}
	record := preservedProjectionAuditRecord{
		Kind: kind, Name: name, Size: identity.Size, SHA256: identity.SHA256, RetirementToken: token,
	}
	if token != confirmation {
		return record, false, false, fmt.Errorf("current token is %s", token)
	}
	if _, err := verifyBoundDerivedStateControlFile(root, name, file, inode, "preserved projection audit quarantine"); err != nil {
		return record, false, false, err
	}
	if err := verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity); err != nil {
		return record, false, false, err
	}
	directory, err := root.Open(".")
	if err != nil {
		return record, false, false, err
	}
	defer directory.Close()
	if err := commitExactPrivateStateFileRemoval(root, directory, file, inode, name, func() error {
		currentIdentity, identityErr := replacementIdentityFromFile(file, inode, nil)
		rootErr := verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity)
		if identityErr != nil || rootErr != nil || currentIdentity != identity {
			return errors.Join(identityErr, rootErr, errors.New("preserved projection audit bytes or identity changed before retirement"))
		}
		return nil
	}); err != nil {
		return record, false, false, err
	}
	return record, true, false, nil
}
