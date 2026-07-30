package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pgsty/sow/internal/verify"
)

const (
	derivedStateResidueMaximumDepth           = 32
	derivedStateResidueMaximumDirectories     = 65536
	derivedStateResidueMaximumEntries         = 262144
	derivedStateResidueMaximumTransactions    = 4096
	derivedStateResidueMaximumTemporaries     = 4096
	derivedStateResidueMaximumDirectoryStages = 4096
)

var derivedStateResidueManagedDirectories = []struct {
	relative  string
	recursive bool
}{
	{relative: ".", recursive: false},
	{relative: "generated", recursive: true},
	{relative: "materialization-journal", recursive: false},
	{relative: "serving-journal", recursive: false},
	{relative: "serving-removal-journal", recursive: false},
}

type derivedStateTemporaryResidueRecord struct {
	Directory string
	Name      string
	Canonical string
	Kind      string
	Size      int64
}

type derivedStateReplacementResidueRecord struct {
	Directory     string
	TransactionID string
}

type derivedStateDirectoryResidueRecord struct {
	Directory string
	Name      string
	Kind      string
}

type derivedStateResidueAudit struct {
	stateRoot         string
	temporaries       []derivedStateTemporaryResidueRecord
	legacyEvidence    []derivedStateTemporaryResidueRecord
	replacements      []derivedStateReplacementResidueRecord
	directoryStages   []derivedStateDirectoryResidueRecord
	directoryEvidence []derivedStateDirectoryResidueRecord
	findings          []verify.Finding
}

type derivedStateResidueRecoveryStats struct {
	DirectoryStages int
	Transactions    int
	Temporaries     int
}

func classifyStrictDerivedStateTemporaryName(name string) (canonical, kind string, valid, related bool) {
	if strings.HasPrefix(name, derivedStateDirectoryStagePrefix) {
		// Directory-stage and preserved-directory evidence have their own V-80
		// recovery grammar. They are never file-writer temporaries.
		return "", "", false, false
	}
	related = strings.Contains(name, ".tmp-")
	if filepath.Base(name) != name || name == "" || name == "." {
		return "", "", false, related
	}
	type candidate struct {
		canonical string
		kind      string
	}
	candidates := make(map[string]candidate)
	for _, marker := range []string{".tmp-install-", ".tmp-"} {
		offset := 0
		for {
			index := strings.Index(name[offset:], marker)
			if index < 0 {
				break
			}
			index += offset
			current := name[:index]
			suffix := strings.TrimPrefix(name, current)
			// A pure removal suffix belongs to the final managed coordinate.
			// When the candidate prefix is itself temporary-shaped, the same
			// name is either the already-recognized write/install+removal
			// grammar or a malformed nested removal. Do not admit that inner
			// split as a second (or attacker-chosen) canonical coordinate.
			nestedPureRemoval := strings.HasPrefix(suffix, ".tmp-remove-") &&
				strings.Contains(current, ".tmp-")
			if current != "" && !nestedPureRemoval && isDerivedStateTemporaryName(name, current) {
				currentKind := "write"
				hasRemoval := strings.Contains(suffix, ".tmp-remove-")
				if strings.HasPrefix(suffix, ".tmp-install-") {
					currentKind = "install"
				}
				if hasRemoval {
					currentKind = "removal"
				} else if legacyNonce, legacy := strings.CutPrefix(suffix, ".tmp-"); legacy &&
					exactLowerHex(legacyNonce, 16) {
					currentKind = "legacy"
				}
				candidates[current] = candidate{canonical: current, kind: currentKind}
			}
			offset = index + len(marker)
			if offset >= len(name) {
				break
			}
		}
	}
	if len(candidates) != 1 {
		return "", "", false, related
	}
	for _, current := range candidates {
		return current.canonical, current.kind, true, true
	}
	return "", "", false, related
}

func classifyDerivedStateDirectoryResidueName(name string) (kind string, valid, related bool) {
	if !strings.HasPrefix(name, derivedStateDirectoryStagePrefix) {
		return "", false, false
	}
	if base, ok := derivedStateDirectoryStageBase(name); ok {
		if name == base+derivedStateDirectoryStageQuarantineSuffix {
			return "quarantine", true, true
		}
		return "stage", true, true
	}
	value := strings.TrimPrefix(name, derivedStateDirectoryStagePrefix)
	stageNonce, preservedNonce, preserved := strings.Cut(value, derivedStateDirectoryStagePreservedMarker)
	if preserved && exactLowerHex(stageNonce, 32) && exactLowerHex(preservedNonce, 32) {
		return "preserved", true, true
	}
	return "", false, true
}

func requireNoUnjournaledDerivedStateTemporaries(directory *os.File) error {
	if directory == nil {
		return errors.New("derived state temporary inventory directory is unavailable")
	}
	if _, err := directory.Seek(0, io.SeekStart); err != nil {
		return err
	}
	for {
		entries, readErr := directory.ReadDir(128)
		for _, entry := range entries {
			_, kind, valid, related := classifyStrictDerivedStateTemporaryName(entry.Name())
			if related && !valid {
				return fmt.Errorf("malformed reserved derived state temporary coordinate %s", entry.Name())
			}
			if valid && kind != "legacy" {
				return fmt.Errorf(
					"interrupted unjournaled derived state temporary %s requires 'sow fsck --recover'",
					entry.Name(),
				)
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func openExistingManagedDerivedStateDirectory(
	root *os.Root,
	stateRoot string,
	rootIdentity os.FileInfo,
	relative string,
) (*os.Root, *os.File, os.FileInfo, bool, error) {
	if root == nil || stateRoot == "" || rootIdentity == nil || relative == "" ||
		filepath.IsAbs(relative) || filepath.Clean(relative) != relative ||
		relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, nil, nil, false, errors.New("managed derived state directory binding is invalid")
	}
	current, err := root.OpenRoot(".")
	if err != nil {
		return nil, nil, nil, false, err
	}
	fail := func(cause error) (*os.Root, *os.File, os.FileInfo, bool, error) {
		return nil, nil, nil, false, errors.Join(cause, current.Close())
	}
	identity := rootIdentity
	if relative != "." {
		for _, component := range strings.Split(relative, string(filepath.Separator)) {
			if component == "" || component == "." || component == ".." || filepath.Base(component) != component {
				return fail(errors.New("managed derived state directory contains an unsafe component"))
			}
			before, statErr := current.Lstat(component)
			if errors.Is(statErr, os.ErrNotExist) {
				_ = current.Close()
				return nil, nil, nil, false, nil
			}
			if statErr != nil || before == nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
				return fail(errors.Join(statErr, fmt.Errorf("managed derived state component %s is not a real directory", component)))
			}
			if _, admissionErr := admitDerivedStateDirectory(before, "managed derived state directory"); admissionErr != nil {
				return fail(admissionErr)
			}
			next, openErr := current.OpenRoot(component)
			if openErr != nil {
				return fail(openErr)
			}
			opened, openedErr := next.Stat(".")
			atPath, pathErr := current.Lstat(component)
			if openedErr != nil || pathErr != nil || opened == nil || atPath == nil ||
				!os.SameFile(before, opened) || !os.SameFile(before, atPath) ||
				!sameDerivedStateDirectorySecurity(before, opened) ||
				!sameDerivedStateDirectorySecurity(before, atPath) {
				_ = next.Close()
				return fail(errors.Join(openedErr, pathErr, fmt.Errorf("managed derived state component %s changed while binding", component)))
			}
			if err := current.Close(); err != nil {
				_ = next.Close()
				return nil, nil, nil, false, err
			}
			current = next
			identity = opened
		}
	}
	handle, err := current.Open(".")
	if err != nil {
		return fail(err)
	}
	if err := errors.Join(
		verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity),
		verifyBoundDerivedStateDirectory(root, handle, relative, identity),
	); err != nil {
		_ = handle.Close()
		return fail(err)
	}
	return current, handle, identity, true, nil
}

func inspectDerivedStateResidues(stateRoot string) (derivedStateResidueAudit, error) {
	var audit derivedStateResidueAudit
	stateRoot, root, rootIdentity, err := bindAdmittedDerivedStateDirectory(stateRoot, "derived state residue inventory root")
	if err != nil {
		return audit, err
	}
	defer root.Close()
	audit.stateRoot = stateRoot
	directories := 0
	entriesSeen := 0
	transactionsSeen := 0
	directoryStagesSeen := 0

	var scan func(string, bool, int) error
	scan = func(relative string, recursive bool, depth int) error {
		if depth > derivedStateResidueMaximumDepth {
			return fmt.Errorf("derived state residue inventory depth exceeds %d", derivedStateResidueMaximumDepth)
		}
		directoryRoot, directory, directoryIdentity, exists, err := openExistingManagedDerivedStateDirectory(
			root, stateRoot, rootIdentity, relative,
		)
		if err != nil || !exists {
			return err
		}
		defer directoryRoot.Close()
		defer directory.Close()
		directories++
		if directories > derivedStateResidueMaximumDirectories {
			return fmt.Errorf("derived state residue inventory directory count exceeds %d", derivedStateResidueMaximumDirectories)
		}
		sets, err := listDerivedStateReplacementCarrierSets(directory)
		if err != nil {
			return fmt.Errorf("inventory derived state replacement carriers in %s: %w", filepath.ToSlash(relative), err)
		}
		for _, set := range sets {
			transactionsSeen++
			if transactionsSeen > derivedStateResidueMaximumTransactions {
				return fmt.Errorf("derived state residue inventory transaction count exceeds %d", derivedStateResidueMaximumTransactions)
			}
			if _, err := inspectDerivedStateReplacementCarrierTopology(directoryRoot, set); err != nil {
				return fmt.Errorf(
					"inspect derived state replacement transaction %s in %s: %w",
					set.transactionID,
					filepath.ToSlash(relative),
					err,
				)
			}
			audit.replacements = append(audit.replacements, derivedStateReplacementResidueRecord{
				Directory: filepath.ToSlash(relative), TransactionID: set.transactionID,
			})
		}
		if _, err := directory.Seek(0, io.SeekStart); err != nil {
			return err
		}
		for {
			batch, readErr := directory.ReadDir(128)
			for _, entry := range batch {
				entriesSeen++
				if entriesSeen > derivedStateResidueMaximumEntries {
					return fmt.Errorf("derived state residue inventory entry count exceeds %d", derivedStateResidueMaximumEntries)
				}
				name := entry.Name()
				info, statErr := directoryRoot.Lstat(name)
				if statErr != nil || info == nil {
					return errors.Join(statErr, fmt.Errorf("inspect managed derived state entry %s/%s", filepath.ToSlash(relative), name))
				}
				directoryKind, directoryValid, directoryRelated := classifyDerivedStateDirectoryResidueName(name)
				if directoryRelated {
					if !directoryValid {
						return fmt.Errorf("malformed reserved derived state directory coordinate %s/%s", filepath.ToSlash(relative), name)
					}
					directoryStagesSeen++
					if directoryStagesSeen > derivedStateResidueMaximumDirectoryStages {
						return fmt.Errorf("derived state directory residue count exceeds %d", derivedStateResidueMaximumDirectoryStages)
					}
					record := derivedStateDirectoryResidueRecord{
						Directory: filepath.ToSlash(relative),
						Name:      name,
						Kind:      directoryKind,
					}
					if directoryKind == "preserved" {
						audit.directoryEvidence = append(audit.directoryEvidence, record)
						continue
					}
					recoverableMode := info != nil &&
						(info.Mode() == os.ModeDir|0o700 || info.Mode() == os.ModeDir|os.ModeSetgid|0o700)
					if !recoverableMode {
						return fmt.Errorf(
							"derived state directory stage residue %s/%s is not an owner-private crash-recoverable directory",
							filepath.ToSlash(relative),
							name,
						)
					}
					if _, admissionErr := admitDerivedStateDirectory(info, "derived state directory stage residue"); admissionErr != nil {
						return fmt.Errorf(
							"admit derived state directory stage residue %s/%s: %w",
							filepath.ToSlash(relative),
							name,
							admissionErr,
						)
					}
					stage, openErr := directoryRoot.OpenRoot(name)
					if openErr != nil {
						return fmt.Errorf("open derived state directory stage residue %s/%s: %w", filepath.ToSlash(relative), name, openErr)
					}
					opened, openedErr := stage.Stat(".")
					after, afterErr := directoryRoot.Lstat(name)
					closeErr := stage.Close()
					if openedErr != nil || afterErr != nil || closeErr != nil || opened == nil || after == nil ||
						!os.SameFile(info, opened) || !os.SameFile(info, after) ||
						!sameDerivedStateDirectoryAuthority(info, opened) ||
						!sameDerivedStateDirectoryAuthority(info, after) ||
						opened.Mode() != info.Mode() || after.Mode() != info.Mode() {
						return errors.Join(
							openedErr,
							afterErr,
							closeErr,
							fmt.Errorf("derived state directory stage residue %s/%s changed while binding", filepath.ToSlash(relative), name),
						)
					}
					if err := errors.Join(
						verifyBoundDerivedStateDirectory(root, directory, relative, directoryIdentity),
						verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity),
					); err != nil {
						return err
					}
					audit.directoryStages = append(audit.directoryStages, record)
					continue
				}
				canonical, kind, valid, related := classifyStrictDerivedStateTemporaryName(name)
				if info.Mode()&os.ModeSymlink != 0 {
					if recursive || related {
						return fmt.Errorf("managed derived state tree contains symlink %s/%s", filepath.ToSlash(relative), name)
					}
					continue
				}
				if info.IsDir() {
					if valid {
						return fmt.Errorf("derived state temporary coordinate %s/%s is a directory", filepath.ToSlash(relative), name)
					}
					if !recursive {
						continue
					}
					child := filepath.Join(relative, name)
					if len(child) > 16*1024 {
						return errors.New("managed derived state directory path exceeds 16 KiB")
					}
					if err := scan(child, true, depth+1); err != nil {
						return err
					}
					continue
				}
				if related && !valid {
					return fmt.Errorf("malformed reserved derived state temporary coordinate %s/%s", filepath.ToSlash(relative), name)
				}
				if valid {
					if len(audit.temporaries)+len(audit.legacyEvidence) >= derivedStateResidueMaximumTemporaries {
						return fmt.Errorf("derived state temporary residue count exceeds %d", derivedStateResidueMaximumTemporaries)
					}
					if _, admissionErr := admitDerivedStateControlFile(info, "derived state temporary residue"); admissionErr != nil {
						return fmt.Errorf("admit derived state temporary residue %s/%s: %w", filepath.ToSlash(relative), name, admissionErr)
					}
					file, identity, bindErr := bindExactProjectionResidue(directoryRoot, name, -1)
					if bindErr != nil {
						return fmt.Errorf("bind derived state temporary residue %s/%s: %w", filepath.ToSlash(relative), name, bindErr)
					}
					coordinateErr := verifyBoundDerivedStateDirectory(root, directory, relative, directoryIdentity)
					rootErr := verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity)
					closeErr := file.Close()
					if coordinateErr != nil || rootErr != nil || closeErr != nil {
						return errors.Join(coordinateErr, rootErr, closeErr)
					}
					record := derivedStateTemporaryResidueRecord{
						Directory: filepath.ToSlash(relative),
						Name:      name,
						Canonical: canonical,
						Kind:      kind,
						Size:      identity.Size(),
					}
					if kind == "legacy" {
						audit.legacyEvidence = append(audit.legacyEvidence, record)
					} else {
						audit.temporaries = append(audit.temporaries, record)
					}
					continue
				}
				if !recursive {
					continue
				}
				if !info.Mode().IsRegular() {
					return fmt.Errorf("managed derived state tree contains special object %s/%s", filepath.ToSlash(relative), name)
				}
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				return readErr
			}
		}
		return errors.Join(
			verifyBoundDerivedStateDirectory(root, directory, relative, directoryIdentity),
			verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity),
		)
	}

	for _, managed := range derivedStateResidueManagedDirectories {
		if err := scan(filepath.FromSlash(managed.relative), managed.recursive, 0); err != nil {
			return audit, err
		}
	}
	sort.Slice(audit.temporaries, func(i, j int) bool {
		left := audit.temporaries[i].Directory + "/" + audit.temporaries[i].Name
		right := audit.temporaries[j].Directory + "/" + audit.temporaries[j].Name
		return left < right
	})
	sort.Slice(audit.legacyEvidence, func(i, j int) bool {
		left := audit.legacyEvidence[i].Directory + "/" + audit.legacyEvidence[i].Name
		right := audit.legacyEvidence[j].Directory + "/" + audit.legacyEvidence[j].Name
		return left < right
	})
	sort.Slice(audit.replacements, func(i, j int) bool {
		left := audit.replacements[i].Directory + "/" + audit.replacements[i].TransactionID
		right := audit.replacements[j].Directory + "/" + audit.replacements[j].TransactionID
		return left < right
	})
	sort.Slice(audit.directoryStages, func(i, j int) bool {
		left := audit.directoryStages[i].Directory + "/" + audit.directoryStages[i].Name
		right := audit.directoryStages[j].Directory + "/" + audit.directoryStages[j].Name
		return left < right
	})
	sort.Slice(audit.directoryEvidence, func(i, j int) bool {
		left := audit.directoryEvidence[i].Directory + "/" + audit.directoryEvidence[i].Name
		right := audit.directoryEvidence[j].Directory + "/" + audit.directoryEvidence[j].Name
		return left < right
	})
	for _, record := range audit.directoryStages {
		audit.findings = append(audit.findings, verify.Finding{
			Layer: verify.LayerL1, Severity: verify.SeverityCritical, Category: verify.CategoryIntegrity,
			Code:    "DERIVED_STATE_DIRECTORY_STAGE_PENDING",
			Subject: derivedStateResidueSubject(record.Directory, record.Name),
			Message: "a strict derived state directory stage requires explicit recovery",
			Fields: []verify.Field{
				{Key: "directory", Value: record.Directory},
				{Key: "kind", Value: record.Kind},
				{Key: "name", Value: record.Name},
			},
		})
	}
	for _, record := range audit.directoryEvidence {
		audit.findings = append(audit.findings, verify.Finding{
			Layer: verify.LayerL1, Severity: verify.SeverityCritical, Category: verify.CategoryIntegrity,
			Code:    "DERIVED_STATE_DIRECTORY_EVIDENCE",
			Subject: derivedStateResidueSubject(record.Directory, record.Name),
			Message: "preserved derived state directory evidence requires operator inspection and is never auto-deleted",
			Fields: []verify.Field{
				{Key: "directory", Value: record.Directory},
				{Key: "kind", Value: record.Kind},
				{Key: "name", Value: record.Name},
			},
		})
	}
	for _, record := range audit.replacements {
		audit.findings = append(audit.findings, verify.Finding{
			Layer: verify.LayerL1, Severity: verify.SeverityCritical, Category: verify.CategoryIntegrity,
			Code:    "DERIVED_STATE_REPLACEMENT_PENDING",
			Subject: derivedStateResidueSubject(record.Directory, ".sow-derived-replacement-"+record.TransactionID),
			Message: "a durable derived state replacement transaction requires explicit recovery",
			Fields: []verify.Field{
				{Key: "directory", Value: record.Directory},
				{Key: "transaction_id", Value: record.TransactionID},
			},
		})
	}
	for _, record := range audit.temporaries {
		audit.findings = append(audit.findings, verify.Finding{
			Layer: verify.LayerL1, Severity: verify.SeverityCritical, Category: verify.CategoryIntegrity,
			Code:    "DERIVED_STATE_TEMPORARY_RESIDUE",
			Subject: derivedStateResidueSubject(record.Directory, record.Name),
			Message: "an unjournaled strict derived state temporary requires explicit recovery",
			Fields: []verify.Field{
				{Key: "canonical", Value: record.Canonical},
				{Key: "directory", Value: record.Directory},
				{Key: "kind", Value: record.Kind},
				{Key: "name", Value: record.Name},
				{Key: "size", Value: fmt.Sprint(record.Size)},
			},
		})
	}
	for _, record := range audit.legacyEvidence {
		audit.findings = append(audit.findings, verify.Finding{
			Layer: verify.LayerL1, Severity: verify.SeverityCritical, Category: verify.CategoryIntegrity,
			Code:    "DERIVED_STATE_LEGACY_TEMPORARY_EVIDENCE",
			Subject: derivedStateResidueSubject(record.Directory, record.Name),
			Message: "a predictable legacy derived state temporary requires operator inspection and is never auto-deleted",
			Fields: []verify.Field{
				{Key: "canonical", Value: record.Canonical},
				{Key: "directory", Value: record.Directory},
				{Key: "kind", Value: record.Kind},
				{Key: "name", Value: record.Name},
				{Key: "size", Value: fmt.Sprint(record.Size)},
			},
		})
	}
	sort.Slice(audit.findings, func(i, j int) bool {
		if audit.findings[i].Subject == audit.findings[j].Subject {
			return audit.findings[i].Code < audit.findings[j].Code
		}
		return audit.findings[i].Subject < audit.findings[j].Subject
	})
	return audit, nil
}

func derivedStateResidueSubject(directory, name string) string {
	if directory == "." {
		return "state/" + name
	}
	return "state/" + strings.TrimPrefix(directory, "./") + "/" + name
}

func invalidDerivedStateResidueAudit(err error) derivedStateResidueAudit {
	return derivedStateResidueAudit{findings: []verify.Finding{{
		Layer: verify.LayerL1, Severity: verify.SeverityCritical, Category: verify.CategoryIntegrity,
		Code: "DERIVED_STATE_RESIDUE_INVENTORY_INVALID", Subject: "state/derived-state-residue",
		Message: "derived state residue inventory is unreadable, unsafe, malformed, or exceeds a bound",
		Fields:  []verify.Field{{Key: "reason", Value: err.Error()}},
	}}}
}

func (audit derivedStateResidueAudit) pending() bool { return len(audit.findings) != 0 }

func (audit derivedStateResidueAudit) verifyCheck() verify.Check {
	findings := append([]verify.Finding(nil), audit.findings...)
	return verify.CheckFunc{
		CheckID: "state/derived-state-residue", CheckLayer: verify.LayerL1,
		Run: func(_ context.Context, recorder *verify.Recorder) error {
			for _, finding := range findings {
				recorder.Add(finding)
			}
			return nil
		},
	}
}

func (audit derivedStateResidueAudit) writeFSCKDrift(output io.Writer) {
	for _, finding := range audit.findings {
		fmt.Fprintf(output, "drift code=%s subject=%q", finding.Code, finding.Subject)
		for _, field := range finding.Fields {
			fmt.Fprintf(output, " %s=%q", field.Key, field.Value)
		}
		fmt.Fprintln(output)
	}
}

func recoverDerivedStateResidues(stateRoot string, audit derivedStateResidueAudit) (derivedStateResidueRecoveryStats, error) {
	var stats derivedStateResidueRecoveryStats
	if audit.stateRoot == "" {
		return stats, errors.New("derived state residue recovery requires a valid inventory")
	}
	absoluteRoot, err := filepath.Abs(filepath.Clean(stateRoot))
	if err != nil || absoluteRoot != audit.stateRoot {
		return stats, errors.Join(err, errors.New("derived state residue inventory belongs to another state root"))
	}
	if len(audit.directoryEvidence) != 0 {
		return stats, errors.New("preserved derived state directory evidence requires operator inspection and cannot be auto-recovered")
	}
	if len(audit.legacyEvidence) != 0 {
		return stats, errors.New("predictable legacy derived state temporary evidence requires operator inspection and cannot be auto-recovered")
	}
	stageDirectories := make(map[string]struct{})
	for _, record := range audit.directoryStages {
		stageDirectories[record.Directory] = struct{}{}
	}
	orderedStageDirectories := make([]string, 0, len(stageDirectories))
	for directory := range stageDirectories {
		orderedStageDirectories = append(orderedStageDirectories, directory)
	}
	sort.Strings(orderedStageDirectories)
	for _, directory := range orderedStageDirectories {
		if err := recoverManagedDerivedStateDirectoryStages(stateRoot, filepath.FromSlash(directory)); err != nil {
			return stats, fmt.Errorf("recover derived state directory stages in %s: %w", directory, err)
		}
	}
	stats.DirectoryStages = len(audit.directoryStages)

	afterDirectoryStages, err := inspectDerivedStateResidues(stateRoot)
	if err != nil {
		return stats, err
	}
	if len(afterDirectoryStages.directoryStages) != 0 {
		return stats, errors.New("derived state directory-stage recovery left pending residue")
	}
	if len(afterDirectoryStages.directoryEvidence) != 0 {
		return stats, errors.New("derived state directory-stage recovery preserved foreign evidence for operator inspection")
	}
	if len(afterDirectoryStages.legacyEvidence) != 0 {
		return stats, errors.New("predictable legacy derived state temporary evidence appeared during recovery")
	}
	directories := make(map[string]struct{})
	for _, record := range afterDirectoryStages.replacements {
		directories[record.Directory] = struct{}{}
	}
	ordered := make([]string, 0, len(directories))
	for directory := range directories {
		ordered = append(ordered, directory)
	}
	sort.Strings(ordered)
	for _, directory := range ordered {
		if err := recoverDerivedStateReplacementTransactions(stateRoot, filepath.FromSlash(directory), true); err != nil {
			return stats, fmt.Errorf("recover derived state replacement transactions in %s: %w", directory, err)
		}
	}
	stats.Transactions = len(afterDirectoryStages.replacements)

	afterTransactions, err := inspectDerivedStateResidues(stateRoot)
	if err != nil {
		return stats, err
	}
	if len(afterTransactions.replacements) != 0 {
		return stats, errors.New("derived state replacement recovery left pending transaction carriers")
	}
	if len(afterTransactions.directoryStages) != 0 {
		return stats, errors.New("derived state directory-stage residue appeared during replacement recovery")
	}
	if len(afterTransactions.directoryEvidence) != 0 || len(afterTransactions.legacyEvidence) != 0 {
		return stats, errors.New("non-recoverable derived state evidence appeared during replacement recovery")
	}
	for _, record := range afterTransactions.temporaries {
		removed, err := removeManagedDerivedStateTemporary(
			stateRoot,
			filepath.FromSlash(record.Directory),
			record.Name,
		)
		if err != nil {
			return stats, fmt.Errorf("remove derived state temporary %s: %w", derivedStateResidueSubject(record.Directory, record.Name), err)
		}
		if removed {
			stats.Temporaries++
		}
	}
	finalAudit, err := inspectDerivedStateResidues(stateRoot)
	if err != nil {
		return stats, err
	}
	if finalAudit.pending() {
		return stats, errors.New("derived state residue recovery did not converge to a clean inventory")
	}
	return stats, nil
}

func recoverManagedDerivedStateDirectoryStages(stateRoot, directoryRelative string) error {
	stateRoot, root, rootIdentity, err := bindAdmittedDerivedStateDirectory(
		stateRoot,
		"derived state directory-stage recovery root",
	)
	if err != nil {
		return err
	}
	defer root.Close()
	directoryRoot, directory, directoryIdentity, exists, err := openExistingManagedDerivedStateDirectory(
		root,
		stateRoot,
		rootIdentity,
		directoryRelative,
	)
	if err != nil || !exists {
		return errors.Join(err, func() error {
			if !exists {
				return errors.New("derived state directory-stage recovery parent disappeared")
			}
			return nil
		}())
	}
	defer directoryRoot.Close()
	defer directory.Close()
	return recoverDerivedStateDirectoryStages(
		root,
		directoryRoot,
		directory,
		stateRoot,
		directoryRelative,
		rootIdentity,
		directoryIdentity,
	)
}

func removeManagedDerivedStateTemporary(stateRoot, directoryRelative, name string) (bool, error) {
	canonical, kind, valid, _ := classifyStrictDerivedStateTemporaryName(name)
	if !valid || kind == "legacy" {
		return false, errors.New("derived state temporary removal grammar is invalid")
	}
	stateRoot, root, rootIdentity, err := bindAdmittedDerivedStateDirectory(stateRoot, "derived state temporary recovery root")
	if err != nil {
		return false, err
	}
	defer root.Close()
	directoryRoot, directory, directoryIdentity, exists, err := openExistingManagedDerivedStateDirectory(
		root, stateRoot, rootIdentity, directoryRelative,
	)
	if err != nil || !exists {
		return false, errors.Join(err, func() error {
			if !exists {
				return errors.New("derived state temporary recovery directory disappeared")
			}
			return nil
		}())
	}
	defer directoryRoot.Close()
	defer directory.Close()
	if _, err := directoryRoot.Lstat(name); errors.Is(err, os.ErrNotExist) {
		return false, errors.Join(
			verifyBoundDerivedStateDirectory(root, directory, directoryRelative, directoryIdentity),
			verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity),
		)
	} else if err != nil {
		return false, err
	}
	file, identity, err := bindExactProjectionResidue(directoryRoot, name, -1)
	if err != nil {
		return false, err
	}
	defer file.Close()
	quarantineBase := name
	suffix := strings.TrimPrefix(name, canonical)
	if index := strings.Index(suffix, ".tmp-remove-"); index >= 0 {
		quarantineBase = canonical + suffix[:index]
	}
	err = commitExactPrivateStateFileRemovalAtPolicy(directoryRoot, directory, file, identity, name, quarantineBase, true, func() error {
		current, statErr := file.Stat()
		if statErr != nil || current == nil || !os.SameFile(identity, current) ||
			current.Size() != identity.Size() || current.Mode() != identity.Mode() ||
			!current.ModTime().Equal(identity.ModTime()) ||
			!sameDerivedStateControlFileSecurity(identity, current) {
			return errors.Join(statErr, errors.New("derived state temporary changed before recovery commit"))
		}
		return errors.Join(
			verifyBoundDerivedStateDirectory(root, directory, directoryRelative, directoryIdentity),
			verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity),
		)
	})
	if err != nil {
		return false, err
	}
	return true, nil
}
