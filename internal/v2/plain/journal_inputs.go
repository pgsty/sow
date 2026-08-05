package plain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// inputFact binds a durable operation to the exact live package set that was
// parsed to produce its staged metadata.  Recovery never trusts a staged index
// unless these header facts and the package bytes still agree.
type inputFact struct {
	Format         packageFormat `json:"format"`
	Base           string        `json:"base"`
	Coordinate     string        `json:"coordinate"`
	SHA256         string        `json:"sha256"`
	OriginalSHA256 string        `json:"original_sha256,omitempty"`
	Name           string        `json:"name"`
	Version        string        `json:"version"`
	Arch           string        `json:"arch"`
	Removed        bool          `json:"removed"`
	Signed         bool          `json:"signed,omitempty"`
}

func journalInputs(scan scanResult) []inputFact {
	removed := make(map[string]struct{}, len(scan.removed))
	for _, fact := range scan.removed {
		removed[fact.base] = struct{}{}
	}
	inputs := make([]inputFact, 0, len(scan.all))
	for _, fact := range scan.all {
		_, remove := removed[fact.base]
		originalSHA := ""
		if fact.signed && fact.originalSHA256 != fact.sha256 {
			originalSHA = fact.originalSHA256
		}
		inputs = append(inputs, inputFact{
			Format: fact.format, Base: fact.base, Coordinate: fact.coordinate,
			SHA256: fact.sha256, OriginalSHA256: originalSHA,
			Name: fact.name, Version: fact.version,
			Arch: fact.arch, Removed: remove, Signed: fact.signed,
		})
	}
	return inputs
}

func validateInputPlan(root string, journal operationJournal) error {
	invalid := func(detail string) error {
		return &Error{Kind: KindIntegrity, Op: "validate journal inputs", Path: root, Err: errors.New(detail)}
	}
	if len(journal.Inputs) == 0 {
		return invalid("journal has no bound package inputs")
	}
	removedActions := make(map[string]fileAction)
	signedActions := make(map[string]fileAction)
	for _, action := range journal.Actions {
		if isPackageMoveAction(journal, action) {
			removedActions[action.Package] = action
		} else if isSignedPackageAction(journal, action) {
			signedActions[action.Package] = action
		}
	}
	previous := ""
	seen := make(map[string]struct{}, len(journal.Inputs))
	for _, input := range journal.Inputs {
		if input.Base == "" || filepath.Base(input.Base) != input.Base || input.Base <= previous {
			return invalid("journal package inputs are not unique basename order")
		}
		previous = input.Base
		if _, duplicate := seen[input.Base]; duplicate {
			return invalid("journal repeats a package input")
		}
		seen[input.Base] = struct{}{}
		if !validSHA256(input.SHA256) || input.Name == "" || input.Version == "" || input.Arch == "" || input.Coordinate == "" {
			return invalid("journal package input has incomplete identity facts")
		}
		switch input.Format {
		case formatRPM:
			if !strings.HasSuffix(input.Base, ".rpm") || isSourceRPMArch(input.Arch) {
				return invalid("journal contains a source or malformed RPM input")
			}
		case formatDEB:
			if !strings.HasSuffix(input.Base, ".deb") {
				return invalid("journal contains a malformed DEB input")
			}
		default:
			return invalid("journal contains an unknown package format")
		}
		action, hasRemoval := removedActions[input.Base]
		if input.Removed != hasRemoval {
			return invalid("journal cleanup actions do not match bound package inputs")
		}
		if input.Removed {
			if !journal.Pigsty || action.SHA256 != input.SHA256 {
				return invalid("journal has an unauthorized package cleanup input")
			}
		}
		signAction, hasSignAction := signedActions[input.Base]
		if input.Signed {
			if input.Format != formatRPM || input.Removed || journal.SignWith == "" {
				return invalid("journal has an unauthorized signed package input")
			}
			if input.OriginalSHA256 == "" {
				if hasSignAction {
					return invalid("unchanged signed package unexpectedly has an install action")
				}
			} else if !validSHA256(input.OriginalSHA256) || input.OriginalSHA256 == input.SHA256 || !hasSignAction || signAction.SHA256 != input.SHA256 {
				return invalid("signed package input does not match its replacement action")
			}
		} else if input.OriginalSHA256 != "" || hasSignAction {
			return invalid("unsigned journal input carries package replacement evidence")
		}
	}
	if len(removedActions) != countRemovedInputs(journal.Inputs) {
		return invalid("journal has a package cleanup action without a bound input")
	}
	if len(signedActions) != countChangedSignedInputs(journal.Inputs) {
		return invalid("journal has a signed package action without a bound input")
	}
	return nil
}

func countRemovedInputs(inputs []inputFact) int {
	count := 0
	for _, input := range inputs {
		if input.Removed {
			count++
		}
	}
	return count
}

func countChangedSignedInputs(inputs []inputFact) int {
	count := 0
	for _, input := range inputs {
		if input.Signed && input.OriginalSHA256 != "" {
			count++
		}
	}
	return count
}

func validateJournalInputs(ctx context.Context, root string, journal operationJournal) error {
	if err := validateInputPlan(root, journal); err != nil {
		return err
	}
	live, err := livePackageBasenames(root)
	if err != nil {
		return err
	}
	expected := make(map[string]inputFact, len(journal.Inputs))
	removalTargets := make(map[string]string)
	for _, action := range journal.Actions {
		if action.Package != "" {
			removalTargets[action.Package] = action.Target
		}
	}
	for _, input := range journal.Inputs {
		expected[input.Base] = input
		path := filepath.Join(root, input.Base)
		if input.Removed {
			trashPath := filepath.Join(root, removalTargets[input.Base])
			resolved, absent, err := locateRecoveryInput(path, trashPath, journal.Next == len(journal.Actions))
			if err != nil {
				return &Error{Kind: KindIntegrity, Op: "verify recovery input", Path: input.Base, Err: err}
			}
			if absent {
				continue
			}
			path = resolved
		} else if _, ok := live[input.Base]; !ok {
			return &Error{Kind: KindIntegrity, Op: "verify recovery input", Path: input.Base, Err: errors.New("retained package is missing or is not a regular file")}
		}
		fact, err := inspectPackageFact(ctx, path, input.Base, input.Format)
		if err != nil {
			return &Error{Kind: KindIntegrity, Op: "verify recovery input", Path: path, Err: err}
		}
		if err := validateJournalInputFact(path, journal, input, fact); err != nil {
			return err
		}
	}
	for base := range live {
		if _, ok := expected[base]; !ok {
			return &Error{Kind: KindIntegrity, Op: "verify recovery input", Path: base, Err: errors.New("live package set gained an unbound package")}
		}
	}
	return nil
}

func validateJournalPackageInput(ctx context.Context, root string, journal operationJournal, input inputFact) error {
	if input.Removed {
		return &Error{Kind: KindIntegrity, Op: "verify recovery input", Path: input.Base, Err: errors.New("signed replacement input is marked for removal")}
	}
	path := filepath.Join(root, input.Base)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return &Error{Kind: KindIntegrity, Op: "verify recovery input", Path: path, Err: errors.Join(err, errors.New("retained package is missing or is not a regular file"))}
	}
	fact, err := inspectPackageFact(ctx, path, input.Base, input.Format)
	if err != nil {
		return &Error{Kind: KindIntegrity, Op: "verify recovery input", Path: path, Err: err}
	}
	return validateJournalInputFact(path, journal, input, fact)
}

func validateJournalInputFact(path string, journal operationJournal, input inputFact, fact packageFact) error {
	if fact.format == formatRPM && isSourceRPMArch(fact.arch) {
		return &Error{Kind: KindIntegrity, Op: "verify recovery input", Path: path, Err: fmt.Errorf("RPM header architecture %q is not binary", fact.arch)}
	}
	digestMatches := fact.sha256 == input.SHA256 || (input.OriginalSHA256 != "" && fact.sha256 == input.OriginalSHA256)
	if !digestMatches || fact.coordinate != input.Coordinate || fact.name != input.Name || fact.version != input.Version || fact.arch != input.Arch {
		return &Error{Kind: KindIntegrity, Op: "verify recovery input", Path: path, Err: errors.New("package bytes or parsed identity differ from the durable operation")}
	}
	if journal.Pigsty && shouldRemove(fact) != input.Removed {
		return &Error{Kind: KindIntegrity, Op: "verify recovery input", Path: path, Err: errors.New("package no longer matches the recorded Pigsty cleanup classification")}
	}
	return nil
}

func livePackageBasenames(root string) (map[string]struct{}, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, &Error{Kind: KindRuntime, Op: "list recovery inputs", Path: root, Err: err}
	}
	live := make(map[string]struct{})
	for _, entry := range entries {
		base := entry.Name()
		if !strings.HasSuffix(base, ".rpm") && !strings.HasSuffix(base, ".deb") {
			continue
		}
		info, err := os.Lstat(filepath.Join(root, base))
		if err != nil {
			return nil, &Error{Kind: KindRuntime, Op: "inspect recovery input", Path: base, Err: err}
		}
		if info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			live[base] = struct{}{}
		}
	}
	return live, nil
}

func locateRecoveryInput(source, target string, allowAbsent bool) (path string, absent bool, err error) {
	sourceInfo, sourceErr := os.Lstat(source)
	targetInfo, targetErr := os.Lstat(target)
	sourceExists := sourceErr == nil
	targetExists := targetErr == nil
	if sourceErr != nil && !errors.Is(sourceErr, os.ErrNotExist) {
		return "", false, sourceErr
	}
	if targetErr != nil && !errors.Is(targetErr, os.ErrNotExist) {
		return "", false, targetErr
	}
	if sourceExists && targetExists {
		return "", false, errors.New("package exists in both live and recovery paths")
	}
	if !sourceExists && !targetExists {
		if allowAbsent {
			return "", true, nil
		}
		return "", false, errors.New("package is absent from both live and recovery paths")
	}
	path, info := source, sourceInfo
	if targetExists {
		path, info = target, targetInfo
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", false, errors.New("package recovery input is not a regular file")
	}
	return path, false, nil
}

func resultFromJournal(root string, journal operationJournal, changed bool) Result {
	result := Result{Dir: root, Kept: []string{}, Removed: []string{}, Recovered: true, Noop: !changed, Marker: journal.Pigsty, Signer: journal.SignWith}
	for _, input := range journal.Inputs {
		if input.Removed {
			result.Removed = append(result.Removed, input.Base)
			continue
		}
		result.Kept = append(result.Kept, input.Base)
		if input.Signed {
			result.Signed = append(result.Signed, input.Base)
		}
		if input.Format == formatRPM {
			result.RPM++
		} else {
			result.DEB++
		}
	}
	if journal.Pigsty && len(journal.Actions) != 0 {
		result.MarkerSHA256 = journal.Actions[len(journal.Actions)-1].SHA256
	}
	return result
}
