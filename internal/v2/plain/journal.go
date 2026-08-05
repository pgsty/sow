package plain

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

const (
	journalFilename = ".sow-plain-operation.json"
	journalVersion  = 5
	maxJournalBytes = 64 << 20
)

type priorFileState struct {
	Exists bool   `json:"exists"`
	SHA256 string `json:"sha256,omitempty"`
	Backup string `json:"backup,omitempty"`
	Mode   uint32 `json:"mode,omitempty"`
	UID    uint32 `json:"uid,omitempty"`
	GID    uint32 `json:"gid,omitempty"`
}

type priorDirectoryState struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
}

type fileAction struct {
	Kind    string          `json:"kind"`
	Source  string          `json:"source"`
	Target  string          `json:"target"`
	SHA256  string          `json:"sha256"`
	Replace bool            `json:"replace,omitempty"`
	Before  FaultPoint      `json:"before,omitempty"`
	After   FaultPoint      `json:"after,omitempty"`
	Package string          `json:"package,omitempty"`
	Prior   *priorFileState `json:"prior,omitempty"`
}

type operationJournal struct {
	Version   int                   `json:"version"`
	Pigsty    bool                  `json:"pigsty"`
	SignWith  string                `json:"sign_with,omitempty"`
	Overwrite bool                  `json:"overwrite,omitempty"`
	Stage     string                `json:"stage"`
	Trash     string                `json:"trash"`
	Inputs    []inputFact           `json:"inputs"`
	Actions   []fileAction          `json:"actions"`
	Dirs      []priorDirectoryState `json:"dirs,omitempty"`
	Next      int                   `json:"next"`
}

// journalPersistenceError records the point of no return for the initial
// journal publication. installed means the rename to journalFilename already
// succeeded, so callers must retain Stage and Trash even if the subsequent
// durability barrier failed.
type journalPersistenceError struct {
	err       error
	installed bool
}

func (e *journalPersistenceError) Error() string { return e.err.Error() }
func (e *journalPersistenceError) Unwrap() error { return e.err }

func journalWasInstalled(err error) bool {
	var persistenceErr *journalPersistenceError
	return errors.As(err, &persistenceErr) && persistenceErr.installed
}

func buildJournal(ctx context.Context, root string, staged stagedBuild, scan scanResult, opts Options) (_ operationJournal, resultErr error) {
	trash, err := os.MkdirTemp(root, ".sow-plain-recovery-")
	if err != nil {
		return operationJournal{}, &Error{Kind: KindRuntime, Op: "create recovery trash", Path: root, Err: err}
	}
	keep := false
	defer func() {
		if !keep {
			resultErr = errors.Join(resultErr, os.RemoveAll(trash))
		}
	}()
	journal := operationJournal{
		Version:   journalVersion,
		Pigsty:    opts.Pigsty,
		SignWith:  opts.SignWith,
		Overwrite: opts.Overwrite,
		Stage:     filepath.Base(staged.dir),
		Trash:     filepath.Base(trash),
		Inputs:    journalInputs(scan),
	}
	if opts.Pigsty {
		marker := filepath.Join(root, "repo_complete")
		if info, err := os.Lstat(marker); err == nil {
			if !info.Mode().IsRegular() {
				return operationJournal{}, &Error{Kind: KindIntegrity, Op: "inspect marker", Path: marker, Err: errors.New("repo_complete is not a regular file")}
			}
			digest, err := hashFile(ctx, marker)
			if err != nil {
				return operationJournal{}, err
			}
			journal.Actions = append(journal.Actions, fileAction{
				Kind: "move", Source: "repo_complete", Target: filepath.Join(journal.Trash, "old-marker"), SHA256: digest,
				After: FaultAfterMarkerWithdrawn,
			})
		} else if !errors.Is(err, os.ErrNotExist) {
			return operationJournal{}, &Error{Kind: KindRuntime, Op: "inspect marker", Path: marker, Err: err}
		}
	}
	for _, fact := range scan.kept {
		if fact.format != formatRPM || !fact.signed || fact.originalSHA256 == fact.sha256 {
			continue
		}
		journal.Actions = append(journal.Actions, fileAction{
			Kind: "install", Source: filepath.Join(journal.Stage, "packages", fact.base), Target: fact.base,
			SHA256: fact.sha256, Replace: true, Before: FaultBeforeRPMPackage, After: FaultAfterRPMPackage, Package: fact.base,
		})
	}
	if staged.rpmPresent {
		repodata := filepath.Join(staged.dir, "repodata")
		entries, err := os.ReadDir(repodata)
		if err != nil {
			return operationJournal{}, &Error{Kind: KindRuntime, Op: "list staged repodata", Path: repodata, Err: err}
		}
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			if entry.Name() != "repomd.xml" {
				names = append(names, entry.Name())
			}
		}
		sort.Strings(names)
		for _, name := range names {
			digest, err := hashFile(ctx, filepath.Join(repodata, name))
			if err != nil {
				return operationJournal{}, err
			}
			journal.Actions = append(journal.Actions, fileAction{
				Kind: "install", Source: filepath.Join(journal.Stage, "repodata", name), Target: filepath.Join("repodata", name), SHA256: digest,
			})
		}
		digest, err := hashFile(ctx, filepath.Join(repodata, "repomd.xml"))
		if err != nil {
			return operationJournal{}, err
		}
		journal.Actions = append(journal.Actions, fileAction{
			Kind: "install", Source: filepath.Join(journal.Stage, "repodata", "repomd.xml"), Target: filepath.Join("repodata", "repomd.xml"), SHA256: digest, Replace: true,
			Before: FaultBeforeRPMPointer, After: FaultAfterRPMPointer,
		})
	}
	if staged.debPresent {
		for _, item := range []struct {
			name          string
			before, after FaultPoint
		}{
			{"Packages", FaultBeforeDEBPackages, FaultAfterDEBPackages},
			{"Packages.gz", FaultBeforeDEBGzip, FaultAfterDEBGzip},
		} {
			digest, err := hashFile(ctx, filepath.Join(staged.dir, item.name))
			if err != nil {
				return operationJournal{}, err
			}
			journal.Actions = append(journal.Actions, fileAction{
				Kind: "install", Source: filepath.Join(journal.Stage, item.name), Target: item.name, SHA256: digest, Replace: true,
				Before: item.before, After: item.after,
			})
		}
	}
	obsolete, err := obsoleteMetadataActions(ctx, root, journal, staged)
	if err != nil {
		return operationJournal{}, err
	}
	journal.Actions = append(journal.Actions, obsolete...)
	if opts.Pigsty {
		for _, fact := range scan.removed {
			journal.Actions = append(journal.Actions, fileAction{
				Kind: "move", Source: fact.base, Target: filepath.Join(journal.Trash, "packages", fact.base), SHA256: fact.sha256,
				After: FaultAfterPackageRename, Package: fact.base,
			})
		}
		journal.Actions = append(journal.Actions, fileAction{
			Kind: "install", Source: filepath.Join(journal.Stage, "repo_complete"), Target: "repo_complete", SHA256: staged.markerSHA, Replace: true,
			Before: FaultBeforeMarker, After: FaultAfterMarker,
		})
	}
	if err := bindPriorDirectories(root, &journal); err != nil {
		return operationJournal{}, err
	}
	if err := bindPriorFiles(ctx, root, &journal); err != nil {
		return operationJournal{}, err
	}
	if err := validateJournal(root, journal); err != nil {
		return operationJournal{}, err
	}
	if err := validateJournalInputs(ctx, root, journal); err != nil {
		return operationJournal{}, err
	}
	if journal.Pigsty {
		if err := validatePigstyMarker(root, journal); err != nil {
			return operationJournal{}, err
		}
	}
	keep = true
	return journal, nil
}

func persistJournal(root string, journal operationJournal) error {
	if err := validateJournal(root, journal); err != nil {
		return err
	}
	if err := validateJournalWireSize(root, journal, true); err != nil {
		return err
	}
	for _, relative := range []string{journal.Stage, journal.Trash} {
		path, err := safePath(root, relative)
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return &Error{Kind: KindIntegrity, Op: "sync journal dependency", Path: path, Err: errors.Join(err, errors.New("operation directory is not a real directory"))}
		}
		if err := syncDir(path); err != nil {
			return &Error{Kind: KindRuntime, Op: "sync journal dependency", Path: path, Err: err}
		}
	}
	if err := syncDir(root); err != nil {
		return &Error{Kind: KindRuntime, Op: "sync journal parent", Path: root, Err: err}
	}
	return writeJournal(root, journal)
}

// persistCommittedJournal records that every public action is already in its
// final state. Unlike persistJournal, this path deliberately does not require
// stage or recovery directories to exist: losing one of those private paths is
// precisely the condition in which committed-state recovery is needed. The
// caller must first prove and fsync the complete public generation.
func persistCommittedJournal(root string, journal operationJournal) error {
	journal.Next = len(journal.Actions)
	if err := validateJournal(root, journal); err != nil {
		return err
	}
	return writeJournal(root, journal)
}

func writeJournal(root string, journal operationJournal) error {
	return writeJournalUsing(root, journal, syncDir)
}

func writeJournalUsing(root string, journal operationJournal, syncParent func(string) error) error {
	if syncParent == nil {
		return &Error{Kind: KindRuntime, Op: "sync journal directory", Path: root, Err: errors.New("nil directory sync function")}
	}
	body, err := json.Marshal(journal)
	if err != nil {
		return &Error{Kind: KindRuntime, Op: "marshal journal", Err: err}
	}
	if len(body)+1 > maxJournalBytes {
		return &Error{Kind: KindRejected, Op: "marshal journal", Path: root, Err: fmt.Errorf("journal exceeds %d bytes", maxJournalBytes)}
	}
	tmp, err := os.CreateTemp(root, ".sow-plain-journal-write-")
	if err != nil {
		return &Error{Kind: KindRuntime, Op: "create journal", Path: root, Err: err}
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return &Error{Kind: KindRuntime, Op: "chmod journal", Path: tmpName, Err: err}
	}
	if _, err := tmp.Write(append(body, '\n')); err != nil {
		return &Error{Kind: KindRuntime, Op: "write journal", Path: tmpName, Err: err}
	}
	if err := errors.Join(tmp.Sync(), tmp.Close()); err != nil {
		return &Error{Kind: KindRuntime, Op: "sync journal", Path: tmpName, Err: err}
	}
	if err := os.Rename(tmpName, filepath.Join(root, journalFilename)); err != nil {
		return &Error{Kind: KindRuntime, Op: "install journal", Path: root, Err: err}
	}
	if err := syncParent(root); err != nil {
		return &journalPersistenceError{
			installed: true,
			err:       &Error{Kind: KindRuntime, Op: "sync journal directory", Path: root, Err: err},
		}
	}
	ok = true
	return nil
}

func loadJournal(root string) (*operationJournal, error) {
	path := filepath.Join(root, journalFilename)
	bound, err := os.OpenRoot(root)
	if err != nil {
		return nil, &Error{Kind: KindRuntime, Op: "bind journal root", Path: root, Err: err}
	}
	defer bound.Close()
	info, err := bound.Lstat(journalFilename)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, &Error{Kind: KindRuntime, Op: "inspect journal", Path: path, Err: err}
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxJournalBytes {
		return nil, &Error{Kind: KindIntegrity, Op: "inspect journal", Path: path, Err: errors.New("journal is not a bounded regular file")}
	}
	file, err := bound.OpenFile(journalFilename, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, &Error{Kind: KindIntegrity, Op: "bind journal", Path: path, Err: err}
	}
	opened, openErr := file.Stat()
	current, pathErr := bound.Lstat(journalFilename)
	if openErr != nil || pathErr != nil || !opened.Mode().IsRegular() || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() ||
		!os.SameFile(info, opened) || !os.SameFile(info, current) || opened.Size() > maxJournalBytes {
		_ = file.Close()
		return nil, &Error{Kind: KindIntegrity, Op: "bind journal", Path: path, Err: errors.Join(openErr, pathErr, errors.New("journal changed while opening"))}
	}
	body, readErr := io.ReadAll(io.LimitReader(file, maxJournalBytes+1))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, &Error{Kind: KindRuntime, Op: "read journal", Path: path, Err: err}
	}
	if len(body) > maxJournalBytes {
		return nil, &Error{Kind: KindIntegrity, Op: "read journal", Path: path, Err: errors.New("journal exceeds bounded read limit")}
	}
	var journal operationJournal
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&journal); err != nil {
		return nil, &Error{Kind: KindIntegrity, Op: "decode journal", Path: path, Err: err}
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, &Error{Kind: KindIntegrity, Op: "decode journal", Path: path, Err: errors.New("journal contains trailing JSON")}
	}
	if err := validateJournal(root, journal); err != nil {
		return nil, err
	}
	return &journal, nil
}

func validateJournalWireSize(root string, journal operationJournal, completedNext bool) error {
	if completedNext {
		journal.Next = len(journal.Actions)
	}
	body, err := json.Marshal(journal)
	if err != nil {
		return &Error{Kind: KindRuntime, Op: "marshal journal", Path: root, Err: err}
	}
	if len(body)+1 > maxJournalBytes {
		return &Error{Kind: KindRejected, Op: "marshal journal", Path: root, Err: fmt.Errorf("journal exceeds %d bytes", maxJournalBytes)}
	}
	return nil
}

func validateJournal(root string, journal operationJournal) error {
	if journal.Version != journalVersion || journal.Next < 0 || journal.Next > len(journal.Actions) {
		return &Error{Kind: KindIntegrity, Op: "validate journal", Path: root, Err: errors.New("unsupported or invalid journal state")}
	}
	if journal.SignWith != "" {
		if !signingKeyPattern.MatchString(journal.SignWith) || journal.SignWith != strings.ToUpper(journal.SignWith) {
			return &Error{Kind: KindIntegrity, Op: "validate journal", Path: root, Err: errors.New("journal signing key is not a canonical GPG key ID/fingerprint")}
		}
	} else if journal.Overwrite {
		return &Error{Kind: KindIntegrity, Op: "validate journal", Path: root, Err: errors.New("journal overwrite mode has no signing key")}
	}
	if !isOwnedTemporary(journal.Stage, ".sow-plain-stage-") || !isOwnedTemporary(journal.Trash, ".sow-plain-recovery-") {
		return &Error{Kind: KindIntegrity, Op: "validate journal", Path: root, Err: errors.New("journal temporary paths are outside the plain operation")}
	}
	for _, action := range journal.Actions {
		if action.Kind != "install" && action.Kind != "move" {
			return &Error{Kind: KindIntegrity, Op: "validate journal", Path: root, Err: fmt.Errorf("unknown action %q", action.Kind)}
		}
		if !validSHA256(action.SHA256) {
			return &Error{Kind: KindIntegrity, Op: "validate journal", Path: root, Err: errors.New("journal action has invalid SHA-256")}
		}
		if _, err := safePath(root, action.Source); err != nil {
			return err
		}
		if _, err := safePath(root, action.Target); err != nil {
			return err
		}
	}
	if err := validatePriorPlan(root, journal); err != nil {
		return err
	}
	if err := validateActionPlan(root, journal); err != nil {
		return err
	}
	return nil
}

func validateActionPlan(root string, journal operationJournal) error {
	invalid := func(detail string) error {
		return &Error{Kind: KindIntegrity, Op: "validate journal plan", Path: root, Err: errors.New(detail)}
	}
	if len(journal.Actions) == 0 {
		return invalid("journal action plan is empty")
	}
	seenSources := make(map[string]struct{}, len(journal.Actions))
	seenTargets := make(map[string]struct{}, len(journal.Actions))
	for _, action := range journal.Actions {
		if _, duplicate := seenSources[action.Source]; duplicate {
			return invalid("journal repeats an action source")
		}
		if _, duplicate := seenTargets[action.Target]; duplicate {
			return invalid("journal repeats an action target")
		}
		seenSources[action.Source] = struct{}{}
		seenTargets[action.Target] = struct{}{}
	}

	index := 0
	if isOldMarkerAction(journal, journal.Actions[index]) {
		if !journal.Pigsty {
			return invalid("non-Pigsty journal withdraws repo_complete")
		}
		index++
	}
	previousSignedPackage := ""
	for index < len(journal.Actions) && isSignedPackageAction(journal, journal.Actions[index]) {
		if journal.SignWith == "" || journal.Actions[index].Package <= previousSignedPackage {
			return invalid("signed RPM replacement actions are not in unique basename order")
		}
		previousSignedPackage = journal.Actions[index].Package
		index++
	}

	rpmKinds := make(map[string]struct{}, 3)
	for index < len(journal.Actions) && isRPMDataAction(journal, journal.Actions[index]) {
		base := filepath.Base(journal.Actions[index].Target)
		kind := ""
		for _, candidate := range []string{"primary", "filelists", "other"} {
			if strings.HasSuffix(base, "-"+candidate+".xml.gz") {
				kind = candidate
				break
			}
		}
		if kind == "" {
			return invalid("journal contains an unknown RPM metadata artifact")
		}
		if _, duplicate := rpmKinds[kind]; duplicate {
			return invalid("journal repeats an RPM metadata kind")
		}
		rpmKinds[kind] = struct{}{}
		index++
	}
	rpmPointer := false
	if index < len(journal.Actions) && isRPMPointerAction(journal, journal.Actions[index]) {
		rpmPointer = true
		index++
	}
	if rpmPointer != (len(rpmKinds) != 0) || (rpmPointer && len(rpmKinds) != 3) {
		return invalid("RPM metadata actions are not a complete pointer-last set")
	}

	debMetadata := false
	if index < len(journal.Actions) && isDEBPackagesAction(journal, journal.Actions[index], false) {
		debMetadata = true
		index++
		if index >= len(journal.Actions) || !isDEBPackagesAction(journal, journal.Actions[index], true) {
			return invalid("DEB metadata actions are not a complete Packages pair")
		}
		index++
	}
	if !rpmPointer && !debMetadata {
		return invalid("journal has no complete RPM or DEB metadata set")
	}
	staleRPMKinds := make(map[string]struct{}, 3)
	for index < len(journal.Actions) && isRPMStaleAction(journal, journal.Actions[index]) {
		base := filepath.Base(journal.Actions[index].Source)
		kind := ""
		for _, candidate := range []string{"primary", "filelists", "other"} {
			if strings.HasSuffix(base, "-"+candidate+".xml.gz") {
				kind = candidate
				break
			}
		}
		if kind == "" {
			return invalid("stale RPM cleanup contains an unknown artifact")
		}
		if _, duplicate := staleRPMKinds[kind]; duplicate {
			return invalid("stale RPM cleanup repeats an artifact kind")
		}
		staleRPMKinds[kind] = struct{}{}
		index++
	}
	if len(staleRPMKinds) != 0 && !rpmPointer {
		return invalid("stale RPM cleanup has no replacement pointer")
	}

	rpmRemoval := false
	if index < len(journal.Actions) && isRPMRemovalAction(journal, journal.Actions[index]) {
		rpmRemoval = true
		if journal.Actions[index].Source != filepath.Join("repodata", "repomd.xml") {
			return invalid("RPM index removal does not withdraw repomd.xml first")
		}
		index++
		removedKinds := make(map[string]struct{}, 3)
		for index < len(journal.Actions) && isRPMRemovalAction(journal, journal.Actions[index]) {
			base := filepath.Base(journal.Actions[index].Source)
			kind := ""
			for _, candidate := range []string{"primary", "filelists", "other"} {
				if strings.HasSuffix(base, "-"+candidate+".xml.gz") {
					kind = candidate
					break
				}
			}
			if kind == "" {
				return invalid("RPM index removal contains an unknown artifact")
			}
			if _, duplicate := removedKinds[kind]; duplicate {
				return invalid("RPM index removal repeats an artifact kind")
			}
			removedKinds[kind] = struct{}{}
			index++
		}
		if len(removedKinds) != 3 {
			return invalid("RPM index removal is not a complete pointer-first set")
		}
	}
	debRemoval := false
	if index < len(journal.Actions) && isDEBRemovalAction(journal, journal.Actions[index], true) {
		debRemoval = true
		index++
		if index >= len(journal.Actions) || !isDEBRemovalAction(journal, journal.Actions[index], false) {
			return invalid("DEB index removal is not a complete compressed-first pair")
		}
		index++
	}
	if rpmPointer && rpmRemoval {
		return invalid("journal both installs and removes the RPM index")
	}
	if debMetadata && debRemoval {
		return invalid("journal both installs and removes the DEB index")
	}
	hasRPMInput, hasDEBInput := false, false
	for _, input := range journal.Inputs {
		if input.Format == formatRPM {
			hasRPMInput = true
		} else if input.Format == formatDEB {
			hasDEBInput = true
		}
	}
	if rpmPointer != hasRPMInput || debMetadata != hasDEBInput || (rpmRemoval && hasRPMInput) || (debRemoval && hasDEBInput) {
		return invalid("metadata actions do not match the bound package formats")
	}

	for index < len(journal.Actions) && journal.Actions[index].Package != "" {
		if !journal.Pigsty || !isPackageMoveAction(journal, journal.Actions[index]) {
			return invalid("journal contains an invalid package recovery action")
		}
		index++
	}
	if journal.Pigsty {
		if index >= len(journal.Actions) || !isFinalMarkerAction(journal, journal.Actions[index]) {
			return invalid("Pigsty journal does not end with repo_complete")
		}
		index++
	}
	if index != len(journal.Actions) {
		return invalid("journal action order or kind is outside the closed plan")
	}
	return nil
}

func validatePigstyMarker(root string, journal operationJournal) error {
	final := journal.Actions[len(journal.Actions)-1]
	source := filepath.Join(root, final.Source)
	target := filepath.Join(root, final.Target)
	markerPath := source
	info, err := os.Lstat(source)
	if errors.Is(err, os.ErrNotExist) {
		markerPath = target
		info, err = os.Lstat(target)
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return &Error{Kind: KindIntegrity, Op: "validate Pigsty marker", Path: markerPath, Err: errors.Join(err, errors.New("staged or installed marker is not a regular file"))}
	}
	body, err := os.ReadFile(markerPath)
	if err != nil {
		return &Error{Kind: KindIntegrity, Op: "validate Pigsty marker", Path: markerPath, Err: err}
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != final.SHA256 {
		return &Error{Kind: KindIntegrity, Op: "validate Pigsty marker", Path: markerPath, Err: errors.New("marker digest differs from the journal")}
	}
	var expected strings.Builder
	for _, input := range journal.Inputs {
		if input.Removed {
			continue
		}
		fmt.Fprintf(&expected, "%s  %s\n", input.SHA256, input.Base)
	}
	if bodyString := string(body); bodyString != expected.String() {
		return &Error{Kind: KindIntegrity, Op: "validate Pigsty marker", Path: markerPath, Err: errors.New("marker does not exactly describe the retained top-level packages")}
	}
	return nil
}

func isOldMarkerAction(journal operationJournal, action fileAction) bool {
	return action.Kind == "move" && action.Source == "repo_complete" &&
		action.Target == filepath.Join(journal.Trash, "old-marker") && action.Package == "" && !action.Replace &&
		action.Before == "" && action.After == FaultAfterMarkerWithdrawn
}

func isRPMDataAction(journal operationJournal, action fileAction) bool {
	if action.Kind != "install" || action.Replace || action.Package != "" || action.Before != "" || action.After != "" {
		return false
	}
	if filepath.Dir(action.Target) != "repodata" || filepath.Base(action.Target) == "repomd.xml" {
		return false
	}
	return action.Source == filepath.Join(journal.Stage, action.Target)
}

func isRPMPointerAction(journal operationJournal, action fileAction) bool {
	target := filepath.Join("repodata", "repomd.xml")
	return action.Kind == "install" && action.Source == filepath.Join(journal.Stage, target) && action.Target == target &&
		action.Replace && action.Package == "" && action.Before == FaultBeforeRPMPointer && action.After == FaultAfterRPMPointer
}

func isDEBPackagesAction(journal operationJournal, action fileAction, compressed bool) bool {
	name := "Packages"
	before, after := FaultBeforeDEBPackages, FaultAfterDEBPackages
	if compressed {
		name = "Packages.gz"
		before, after = FaultBeforeDEBGzip, FaultAfterDEBGzip
	}
	return action.Kind == "install" && action.Source == filepath.Join(journal.Stage, name) && action.Target == name &&
		action.Replace && action.Package == "" && action.Before == before && action.After == after
}

func isSignedPackageAction(journal operationJournal, action fileAction) bool {
	if action.Kind != "install" || !action.Replace || action.Package == "" || action.Target != action.Package || filepath.Base(action.Package) != action.Package ||
		action.Before != FaultBeforeRPMPackage || action.After != FaultAfterRPMPackage || !strings.HasSuffix(action.Package, ".rpm") {
		return false
	}
	return action.Source == filepath.Join(journal.Stage, "packages", action.Package)
}

func isPackageMoveAction(journal operationJournal, action fileAction) bool {
	if action.Kind != "move" || action.Replace || action.Before != "" || action.After != FaultAfterPackageRename ||
		action.Source != action.Package || filepath.Base(action.Source) != action.Source {
		return false
	}
	if !strings.HasSuffix(action.Source, ".rpm") && !strings.HasSuffix(action.Source, ".deb") {
		return false
	}
	return action.Target == filepath.Join(journal.Trash, "packages", action.Source)
}

func isFinalMarkerAction(journal operationJournal, action fileAction) bool {
	return action.Kind == "install" && action.Source == filepath.Join(journal.Stage, "repo_complete") && action.Target == "repo_complete" &&
		action.Replace && action.Package == "" && action.Before == FaultBeforeMarker && action.After == FaultAfterMarker
}

func rootEntryIsDirectory(root *os.Root, relative string) bool {
	info, err := root.Lstat(relative)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

func committedJournalState(ctx context.Context, root *os.Root, journal *operationJournal) (bool, error) {
	for _, action := range journal.Actions {
		switch {
		case action.Kind == "install":
			digest, exists, err := existingDigestRoot(ctx, root, action.Target)
			if err != nil {
				return false, err
			}
			if !exists || digest != action.SHA256 {
				return false, nil
			}
		case action.Kind == "move" && isOldMarkerAction(*journal, action):
			// The final Pigsty marker intentionally reuses repo_complete after
			// the old marker has been moved into recovery trash.
			continue
		case action.Kind == "move":
			_, sourceExists, err := existingDigestRoot(ctx, root, action.Source)
			if err != nil {
				return false, err
			}
			if sourceExists {
				return false, nil
			}
			if digest, targetExists, err := existingDigestRoot(ctx, root, action.Target); err != nil {
				return false, err
			} else if targetExists && digest != action.SHA256 {
				return false, &Error{Kind: KindIntegrity, Op: "verify completed recovery", Path: action.Target, Err: errors.New("recovery bytes changed")}
			} else if !targetExists && journal.Next != len(journal.Actions) {
				return false, nil
			}
		}
	}
	return true, nil
}

func executeJournal(ctx context.Context, root string, journal *operationJournal, fault func(Fault) error) (bool, error) {
	changed, err := executeJournalOnce(ctx, root, journal, fault)
	if err == nil {
		return changed, nil
	}
	// A returned error is not a process crash: before giving control back to
	// the caller, synchronously replay the durable plan without the fault hook.
	// This makes an ordinary error boundary converge to one complete new state
	// instead of exposing a mixed RPM/DEB generation. True process termination
	// never reaches this branch and is recovered by the next invocation.
	recoveredChanged, recoveryErr := executeJournalOnce(context.WithoutCancel(ctx), root, journal, nil)
	if recoveryErr == nil {
		// The durable plan reached its complete new state. Reporting the
		// transient hook/action error now would expose a successful commit as a
		// failed Plain Operation and, worse, allow callers to assume that the old
		// indexes are still live. A completed roll-forward is the operation's
		// success result.
		return changed || recoveredChanged, nil
	}
	// The second failure is persistent. If all new public files nevertheless
	// reached the journaled generation, establish fresh durability barriers and
	// report success. Otherwise restore every pre-operation live file before an
	// error is allowed to cross the public API boundary.
	if committed, committedErr := confirmCommittedDurable(context.WithoutCancel(ctx), root, journal); committedErr == nil && committed {
		// Record the proved public generation as complete before attempting private
		// cleanup. Once that completed hint is durable, a cleanup failure must not
		// turn a correct new marker and index generation into a false public failure:
		// the next invocation will verify the committed state and retry cleanup only.
		journal.Next = len(journal.Actions)
		if persistErr := persistCommittedJournal(root, *journal); persistErr != nil {
			return changed || recoveredChanged, errors.Join(err, recoveryErr, persistErr)
		}
		_ = cleanupJournal(root, *journal)
		return changed || recoveredChanged, nil
	} else if committedErr != nil {
		recoveryErr = errors.Join(recoveryErr, committedErr)
	}
	rollbackErr := rollbackJournal(context.WithoutCancel(ctx), root, *journal)
	return changed || recoveredChanged, errors.Join(err, recoveryErr, rollbackErr)
}

func executeJournalOnce(ctx context.Context, root string, journal *operationJournal, fault func(Fault) error) (bool, error) {
	if err := rejectDefaultJournalMarker(root, *journal); err != nil {
		return false, err
	}
	if err := validateJournalInputs(ctx, root, *journal); err != nil {
		return false, err
	}
	if journal.Pigsty {
		if err := validatePigstyMarker(root, *journal); err != nil {
			return false, err
		}
	}
	inputs := make(map[string]inputFact, len(journal.Inputs))
	for _, input := range journal.Inputs {
		inputs[input.Base] = input
	}
	bound, err := os.OpenRoot(root)
	if err != nil {
		return false, &Error{Kind: KindRuntime, Op: "bind plain root", Path: root, Err: err}
	}
	defer bound.Close()
	stageExists := rootEntryIsDirectory(bound, journal.Stage)
	trashExists := rootEntryIsDirectory(bound, journal.Trash)
	if journal.Next == len(journal.Actions) {
		committed, err := committedJournalState(ctx, bound, journal)
		if err != nil {
			return false, err
		}
		if committed {
			return false, cleanupJournal(root, *journal)
		}
	}
	if !stageExists || !trashExists {
		return false, &Error{Kind: KindIntegrity, Op: "recover operation", Path: root, Err: errors.New("incomplete operation lost its stage or recovery directory")}
	}
	if err := validateRollbackEvidence(ctx, bound, root, *journal); err != nil {
		return false, err
	}
	changed := false
	initialNext := journal.Next
	for index := 0; index < len(journal.Actions); index++ {
		if err := ctx.Err(); err != nil {
			return changed, &Error{Kind: KindRuntime, Op: "commit", Path: root, Err: err}
		}
		action := journal.Actions[index]
		if index >= initialNext {
			if err := inject(fault, action.Before, action.Package, index); err != nil {
				return changed, err
			}
		}
		if err := rejectDefaultJournalMarker(root, *journal); err != nil {
			return changed, err
		}
		if isSignedPackageAction(*journal, action) {
			input, ok := inputs[action.Package]
			if !ok {
				return changed, &Error{Kind: KindIntegrity, Op: "verify recovery input", Path: action.Package, Err: errors.New("signed action has no bound input")}
			}
			if err := validateJournalPackageInput(ctx, root, *journal, input); err != nil {
				return changed, err
			}
		} else if isPublicationAction(*journal, action) {
			if err := validateJournalInputs(ctx, root, *journal); err != nil {
				return changed, err
			}
		}
		actionChanged, err := applyAction(ctx, bound, root, *journal, action)
		if err != nil {
			return changed, err
		}
		changed = changed || actionChanged
		if index >= initialNext {
			if err := inject(fault, action.After, action.Package, index); err != nil {
				return changed, err
			}
		}
		if journal.Next < index+1 {
			journal.Next = index + 1
			if shouldPersistJournalProgress(*journal, action) {
				if err := persistJournal(root, *journal); err != nil {
					return changed, err
				}
			}
		}
	}
	if err := cleanupJournal(root, *journal); err != nil {
		return changed, err
	}
	return changed, nil
}

// Next is a recovery hint, never authorization. Per-package actions are
// independently digest-bound and replay-safe, so persisting the complete O(N)
// journal after each of N packages would be quadratic without improving the
// recovery proof. A later constant-count metadata/marker boundary records the
// aggregate progress.
func shouldPersistJournalProgress(journal operationJournal, action fileAction) bool {
	return !isSignedPackageAction(journal, action) && !isPackageMoveAction(journal, action)
}

func journalChangesPublicState(ctx context.Context, root string, journal operationJournal) (bool, error) {
	bound, err := os.OpenRoot(root)
	if err != nil {
		return false, &Error{Kind: KindRuntime, Op: "bind no-op check", Path: root, Err: err}
	}
	defer bound.Close()
	markerUnchanged := false
	if journal.Pigsty {
		final := journal.Actions[len(journal.Actions)-1]
		digest, exists, err := existingDigestRoot(ctx, bound, final.Target)
		if err != nil {
			return false, err
		}
		markerUnchanged = exists && digest == final.SHA256
	}
	for _, action := range journal.Actions {
		if markerUnchanged && (isOldMarkerAction(journal, action) || isFinalMarkerAction(journal, action)) {
			continue
		}
		if isSignedPackageAction(journal, action) {
			return true, nil
		}
		switch action.Kind {
		case "install":
			digest, exists, err := existingDigestRoot(ctx, bound, action.Target)
			if err != nil {
				return false, err
			}
			if !exists || digest != action.SHA256 {
				return true, nil
			}
		case "move":
			_, exists, err := existingDigestRoot(ctx, bound, action.Source)
			if err != nil {
				return false, err
			}
			if exists {
				return true, nil
			}
		}
	}
	return false, nil
}

func discardUnpublishedJournal(root string, journal operationJournal) error {
	bound, err := os.OpenRoot(root)
	if err != nil {
		return &Error{Kind: KindRuntime, Op: "bind no-op cleanup", Path: root, Err: err}
	}
	defer bound.Close()
	for _, relative := range []string{journal.Stage, journal.Trash} {
		info, err := bound.Lstat(relative)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return &Error{Kind: KindIntegrity, Op: "discard no-op state", Path: filepath.Join(root, relative), Err: errors.Join(err, errors.New("operation directory is not a real directory"))}
		}
		if err := bound.RemoveAll(relative); err != nil {
			return &Error{Kind: KindRuntime, Op: "discard no-op state", Path: filepath.Join(root, relative), Err: err}
		}
	}
	if err := syncRootDir(bound, "."); err != nil {
		return &Error{Kind: KindRuntime, Op: "sync no-op cleanup", Path: root, Err: err}
	}
	return nil
}

func rejectDefaultJournalMarker(root string, journal operationJournal) error {
	if journal.Pigsty {
		return nil
	}
	marker := filepath.Join(root, "repo_complete")
	if _, err := os.Lstat(marker); err == nil {
		return &Error{Kind: KindRejected, Op: "journal marker gate", Path: marker, Err: errors.New("repo_complete exists while a default create journal is pending")}
	} else if !errors.Is(err, os.ErrNotExist) {
		return &Error{Kind: KindRuntime, Op: "journal marker gate", Path: marker, Err: err}
	}
	return nil
}

func isPublicationAction(journal operationJournal, action fileAction) bool {
	return isSignedPackageAction(journal, action) || isRPMPointerAction(journal, action) || isDEBPackagesAction(journal, action, false) ||
		isDEBPackagesAction(journal, action, true) || isFinalMarkerAction(journal, action)
}

func applyAction(ctx context.Context, bound *os.Root, root string, journal operationJournal, action fileAction) (bool, error) {
	source, err := safePath(root, action.Source)
	if err != nil {
		return false, err
	}
	target, err := safePath(root, action.Target)
	if err != nil {
		return false, err
	}
	if err := validateRealDirectoryRoot(bound, filepath.Dir(action.Source)); err != nil {
		return false, err
	}
	permission := os.FileMode(0o700)
	if action.Target == "repomd.xml" || action.Target == "Packages" || action.Target == "Packages.gz" || action.Target == "repo_complete" || strings.HasPrefix(action.Target, "repodata"+string(filepath.Separator)) {
		permission = 0o755
	}
	if err := ensureRealDirectoryRoot(bound, filepath.Dir(action.Target), permission); err != nil {
		return false, err
	}
	sourceDigest, sourceExists, err := existingDigestRoot(ctx, bound, action.Source)
	if err != nil {
		return false, err
	}
	targetDigest, targetExists, err := existingDigestRoot(ctx, bound, action.Target)
	if err != nil {
		return false, err
	}
	if targetExists && targetDigest == action.SHA256 {
		if sourceExists {
			if isOldMarkerAction(journal, action) {
				// repo_complete is both the old-marker source and final-marker
				// target.  Live+trash is a legal completed state only when the
				// staged final marker has disappeared and the live bytes match
				// the journal's final action. This also covers an unchanged repeat
				// where the old and new marker digests are identical.
				final := journal.Actions[len(journal.Actions)-1]
				_, finalSourceExists, finalSourceErr := existingDigestRoot(ctx, bound, final.Source)
				if finalSourceErr != nil {
					return false, finalSourceErr
				}
				if !finalSourceExists && sourceDigest == final.SHA256 {
					return false, nil
				}
			}
			if sourceDigest != action.SHA256 || action.Kind != "install" {
				return false, &Error{Kind: KindIntegrity, Op: "replay action", Path: action.Target, Err: errors.New("both source and target exist with ambiguous evidence")}
			}
			if err := bound.Remove(action.Source); err != nil {
				return false, &Error{Kind: KindRuntime, Op: "discard duplicate stage", Path: source, Err: err}
			}
		}
		if err := syncAppliedAction(bound, action); err != nil {
			return false, err
		}
		return false, nil
	}
	if !sourceExists || sourceDigest != action.SHA256 {
		return false, &Error{Kind: KindIntegrity, Op: "replay action", Path: action.Source, Err: errors.New("expected source bytes are missing or changed")}
	}
	if targetExists && !action.Replace {
		return false, &Error{Kind: KindIntegrity, Op: "install immutable metadata", Path: action.Target, Err: errors.New("target exists with conflicting bytes")}
	}
	if err := validateRealDirectoryRoot(bound, filepath.Dir(action.Source)); err != nil {
		return false, err
	}
	if err := ensureRealDirectoryRoot(bound, filepath.Dir(action.Target), permission); err != nil {
		return false, err
	}
	if targetExists {
		info, err := bound.Lstat(action.Target)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return false, &Error{Kind: KindIntegrity, Op: "replace pointer", Path: target, Err: errors.Join(err, errors.New("target is not a regular file"))}
		}
	}
	if err := bound.Rename(action.Source, action.Target); err != nil {
		return false, &Error{Kind: KindRuntime, Op: "rename", Path: action.Target, Err: err}
	}
	if err := syncRootDir(bound, filepath.Dir(action.Target)); err != nil {
		return false, &Error{Kind: KindRuntime, Op: "sync action", Path: filepath.Dir(target), Err: err}
	}
	if filepath.Dir(action.Source) != filepath.Dir(action.Target) {
		if err := syncRootDir(bound, filepath.Dir(action.Source)); err != nil {
			return false, &Error{Kind: KindRuntime, Op: "sync action source", Path: filepath.Dir(source), Err: err}
		}
	}
	return true, nil
}

func syncAppliedAction(root *os.Root, action fileAction) error {
	seen := make(map[string]struct{}, 2)
	for _, directory := range []string{filepath.Dir(action.Target), filepath.Dir(action.Source)} {
		if _, duplicate := seen[directory]; duplicate {
			continue
		}
		seen[directory] = struct{}{}
		info, err := root.Lstat(directory)
		if directory == "." {
			info, err = root.Stat(".")
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return &Error{Kind: KindIntegrity, Op: "sync replayed action", Path: directory, Err: errors.Join(err, errors.New("action parent is not a real directory"))}
		}
		if err := syncRootDir(root, directory); err != nil {
			return &Error{Kind: KindRuntime, Op: "sync replayed action", Path: directory, Err: err}
		}
	}
	return nil
}

func cleanupJournal(root string, journal operationJournal) error {
	bound, err := os.OpenRoot(root)
	if err != nil {
		return &Error{Kind: KindRuntime, Op: "bind cleanup root", Path: root, Err: err}
	}
	defer bound.Close()
	if journalRemovesRPM(journal) {
		info, err := bound.Lstat("repodata")
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return &Error{Kind: KindIntegrity, Op: "remove obsolete rpm directory", Path: filepath.Join(root, "repodata"), Err: errors.New("repodata is not a real directory")}
			}
			directory, err := bound.Open("repodata")
			if err != nil {
				return &Error{Kind: KindRuntime, Op: "inspect obsolete rpm directory", Path: filepath.Join(root, "repodata"), Err: err}
			}
			entries, readErr := directory.ReadDir(1)
			closeErr := directory.Close()
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				return &Error{Kind: KindRuntime, Op: "inspect obsolete rpm directory", Path: filepath.Join(root, "repodata"), Err: errors.Join(readErr, closeErr)}
			}
			if closeErr != nil {
				return &Error{Kind: KindRuntime, Op: "close obsolete rpm directory", Path: filepath.Join(root, "repodata"), Err: closeErr}
			}
			if len(entries) == 0 {
				if err := bound.Remove("repodata"); err != nil {
					return &Error{Kind: KindIntegrity, Op: "remove obsolete rpm directory", Path: filepath.Join(root, "repodata"), Err: err}
				}
				if err := syncRootDir(bound, "."); err != nil {
					return &Error{Kind: KindRuntime, Op: "sync obsolete rpm directory removal", Path: root, Err: err}
				}
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return &Error{Kind: KindRuntime, Op: "inspect obsolete rpm directory", Path: filepath.Join(root, "repodata"), Err: err}
		}
	}
	for _, relative := range []string{journal.Stage, journal.Trash} {
		path, err := safePath(root, relative)
		if err != nil {
			return err
		}
		info, statErr := bound.Lstat(relative)
		if errors.Is(statErr, os.ErrNotExist) {
			continue
		}
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return &Error{Kind: KindIntegrity, Op: "clean operation", Path: path, Err: errors.Join(statErr, errors.New("operation directory is not a real directory"))}
		}
		if err := bound.RemoveAll(relative); err != nil {
			return &Error{Kind: KindRuntime, Op: "clean operation", Path: path, Err: err}
		}
	}
	if err := bound.Remove(journalFilename); err != nil && !errors.Is(err, os.ErrNotExist) {
		return &Error{Kind: KindRuntime, Op: "remove journal", Path: root, Err: err}
	}
	if err := syncDir(root); err != nil {
		return &Error{Kind: KindRuntime, Op: "sync completed operation", Path: root, Err: err}
	}
	return nil
}

func existingDigestRoot(ctx context.Context, root *os.Root, relative string) (string, bool, error) {
	info, err := root.Lstat(relative)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, &Error{Kind: KindRuntime, Op: "inspect action path", Path: relative, Err: err}
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", false, &Error{Kind: KindIntegrity, Op: "inspect action path", Path: relative, Err: errors.New("path is not a regular file")}
	}
	file, err := root.Open(relative)
	if err != nil {
		return "", false, &Error{Kind: KindRuntime, Op: "open action path", Path: relative, Err: err}
	}
	opened, openErr := file.Stat()
	current, pathErr := root.Lstat(relative)
	if openErr != nil || pathErr != nil || !opened.Mode().IsRegular() || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || !os.SameFile(info, opened) || !os.SameFile(info, current) {
		_ = file.Close()
		return "", false, &Error{Kind: KindIntegrity, Op: "bind action path", Path: relative, Err: errors.Join(openErr, pathErr, errors.New("file changed while opening"))}
	}
	h := sha256.New()
	_, copyErr := io.Copy(h, &contextReader{ctx: ctx, reader: file})
	closeErr := file.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return "", false, &Error{Kind: KindRuntime, Op: "hash action path", Path: relative, Err: err}
	}
	return hex.EncodeToString(h.Sum(nil)), true, nil
}

func ensureRealDirectoryRoot(root *os.Root, relative string, perm os.FileMode) error {
	return ensureRealDirectoryRootUsing(root, relative, perm, syncRootDir)
}

func ensureRealDirectoryRootUsing(root *os.Root, relative string, perm os.FileMode, syncParent func(*os.Root, string) error) error {
	if relative == "." {
		return nil
	}
	if syncParent == nil {
		return &Error{Kind: KindRuntime, Op: "create directory", Path: relative, Err: errors.New("nil directory sync function")}
	}
	if filepath.IsAbs(relative) || filepath.Clean(relative) != relative || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return &Error{Kind: KindIntegrity, Op: "create directory", Path: relative, Err: errors.New("directory escapes plain root")}
	}
	current := ""
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := root.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := root.Mkdir(current, perm); err != nil {
				return &Error{Kind: KindRuntime, Op: "create directory", Path: current, Err: err}
			}
			// Mkdir applies the process umask. Public repository directories have
			// an explicit contract, so restore the requested mode before making
			// the new entry durable.
			if err := root.Chmod(current, perm); err != nil {
				return &Error{Kind: KindRuntime, Op: "chmod directory", Path: current, Err: err}
			}
			if err := syncParent(root, filepath.Dir(current)); err != nil {
				return &Error{Kind: KindRuntime, Op: "sync created directory parent", Path: filepath.Dir(current), Err: err}
			}
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return &Error{Kind: KindIntegrity, Op: "inspect directory", Path: current, Err: errors.Join(err, errors.New("path component is not a real directory"))}
		}
		// Re-sync existing components as well. If a prior attempt created the
		// directory but its parent fsync failed, replay cannot otherwise tell
		// that the directory entry still needs a durability barrier.
		if err := syncParent(root, filepath.Dir(current)); err != nil {
			return &Error{Kind: KindRuntime, Op: "sync directory parent", Path: filepath.Dir(current), Err: err}
		}
	}
	return nil
}

func validateRealDirectoryRoot(root *os.Root, relative string) error {
	if relative == "." {
		return nil
	}
	if filepath.IsAbs(relative) || filepath.Clean(relative) != relative || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return &Error{Kind: KindIntegrity, Op: "inspect directory", Path: relative, Err: errors.New("directory escapes plain root")}
	}
	current := ""
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := root.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return &Error{Kind: KindIntegrity, Op: "inspect directory", Path: current, Err: errors.Join(err, errors.New("path component is not a real directory"))}
		}
	}
	return nil
}

func syncRootDir(root *os.Root, relative string) error {
	if relative == "" {
		relative = "."
	}
	dir, err := root.Open(relative)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func safePath(root, relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", &Error{Kind: KindIntegrity, Op: "resolve journal path", Path: relative, Err: errors.New("unsafe relative path")}
	}
	target := filepath.Join(root, relative)
	rel, err := filepath.Rel(root, target)
	if err != nil || rel != relative {
		return "", &Error{Kind: KindIntegrity, Op: "resolve journal path", Path: relative, Err: errors.New("path escapes plain root")}
	}
	return target, nil
}

func isOwnedTemporary(value, prefix string) bool {
	return filepath.Base(value) == value && strings.HasPrefix(value, prefix) && len(value) > len(prefix)
}

func validSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	for _, r := range value {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

func inject(fault func(Fault) error, point FaultPoint, packageName string, sequence int) error {
	if fault == nil || point == "" {
		return nil
	}
	if err := fault(Fault{Point: point, Package: packageName, Sequence: sequence}); err != nil {
		return &Error{Kind: KindRuntime, Op: "fault injection", Err: err}
	}
	return nil
}
