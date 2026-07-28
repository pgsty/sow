package cli

import (
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

	"github.com/pgsty/sow/internal/state"
)

// derivedStateReplacementOutcome is deliberately fail-closed: an
// uninitialized result requires recovery rather than being mistaken for a
// successful or safely rolled-back replacement.
type derivedStateReplacementOutcome uint8

const (
	derivedStateReplacementRecoveryRequired derivedStateReplacementOutcome = iota
	derivedStateReplacementNotCommitted
	derivedStateReplacementCommitted
)

type derivedStateReplacementResult struct {
	Outcome             derivedStateReplacementOutcome
	TransactionID       string
	DestinationIdentity derivedStateReplacementIdentity
}

var errDerivedStateReplacementRecoveryRequired = errors.New("derived state replacement requires recovery")
var errDerivedStateReplacementTestCrash = errors.New("simulated derived state replacement process death")

const (
	derivedStateReplacementIntentPrefix    = ".sow-derived-replacement-"
	derivedStateReplacementIsolationPrefix = ".sow-derived-isolation-"
	derivedStateReplacementIntentMaxBytes  = 16 * 1024
	derivedStateReplacementMaxTransactions = 1024
	derivedStateReplacementIntentSchema    = 1
)

const (
	derivedStateReplacementPrepared       = "prepared"
	derivedStateReplacementCommittedPhase = "committed"
)

type derivedStateReplacementIdentity struct {
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Mode      uint32 `json:"mode"`
	Device    uint64 `json:"device"`
	Inode     uint64 `json:"inode"`
	ModTimeNS int64  `json:"mtime_ns"`
}

type derivedStateReplacementIntent struct {
	Schema         int                             `json:"schema"`
	TransactionID  string                          `json:"transaction_id"`
	Phase          string                          `json:"phase"`
	Destination    string                          `json:"destination"`
	Source         string                          `json:"source"`
	SourceTrash    string                          `json:"source_trash"`
	Candidate      string                          `json:"candidate"`
	CandidateTrash string                          `json:"candidate_trash"`
	CandidateID    derivedStateReplacementIdentity `json:"candidate_identity"`
	PriorPresent   bool                            `json:"prior_present"`
	PriorID        derivedStateReplacementIdentity `json:"prior_identity,omitempty"`
}

var derivedStateReplacementParentSync = func(parent *os.File, _ string) error {
	return parent.Sync()
}

// derivedStateReplacementPhaseHook is a test-only fault/crash seam. Returning
// an error never converts visibility into a commit claim; the caller still
// executes compensation or leaves the durable intent for replay.
var derivedStateReplacementPhaseHook func(string) error

// derivedStateReplacementAfterCarrierReadHook is a deterministic test seam
// for an in-place carrier mutation between the bounded read and its final
// descriptor/path identity proof. Production never sets it.
var derivedStateReplacementAfterCarrierReadHook func(string) error

func derivedStateReplacementIntentName(transactionID string) string {
	return derivedStateReplacementIntentPrefix + transactionID + ".json"
}

func derivedStateReplacementIsolationName(transactionID string) string {
	return derivedStateReplacementIsolationPrefix + transactionID
}

func derivedStateReplacementSourceTrashName(transactionID string) string {
	return derivedStateReplacementIsolationPrefix + transactionID + ".source.remove"
}

func isDerivedStateReplacementReservedName(name string) bool {
	return strings.HasPrefix(name, derivedStateReplacementIntentPrefix) ||
		strings.HasPrefix(name, derivedStateReplacementIsolationPrefix)
}

func (intent derivedStateReplacementIntent) validate() error {
	if intent.Schema != derivedStateReplacementIntentSchema ||
		!exactLowerHex(intent.TransactionID, 32) ||
		filepath.Base(intent.Destination) != intent.Destination ||
		intent.Destination == "" || intent.Destination == "." ||
		isDerivedStateReplacementReservedName(intent.Destination) ||
		!isDerivedStateTemporaryName(intent.Source, intent.Destination) ||
		intent.SourceTrash != derivedStateReplacementSourceTrashName(intent.TransactionID) ||
		intent.Candidate != derivedStateReplacementIsolationName(intent.TransactionID) ||
		intent.CandidateTrash != intent.Candidate+".remove" ||
		(intent.Phase != derivedStateReplacementPrepared && intent.Phase != derivedStateReplacementCommittedPhase) {
		return errors.New("invalid derived state replacement intent")
	}
	if err := intent.CandidateID.validate(true); err != nil {
		return fmt.Errorf("invalid derived state replacement candidate identity: %w", err)
	}
	if intent.PriorPresent {
		if err := intent.PriorID.validate(false); err != nil {
			return fmt.Errorf("invalid derived state replacement prior identity: %w", err)
		}
	} else if intent.PriorID != (derivedStateReplacementIdentity{}) {
		return errors.New("absent derived state replacement prior has an identity")
	}
	return nil
}

func (identity derivedStateReplacementIdentity) validate(private bool) error {
	if identity.Size < 0 || len(identity.SHA256) != sha256.Size*2 ||
		identity.Device == 0 || identity.Inode == 0 {
		return errors.New("incomplete replacement identity")
	}
	if _, err := hex.DecodeString(identity.SHA256); err != nil {
		return err
	}
	mode := os.FileMode(identity.Mode)
	if !mode.IsRegular() || mode&os.ModeSymlink != 0 {
		return errors.New("replacement identity is not a regular file")
	}
	if private && mode.Perm()&0o077 != 0 {
		return errors.New("replacement identity is not private")
	}
	return nil
}

func consumeDerivedStateReplacement(result derivedStateReplacementResult, operationErr error) error {
	switch result.Outcome {
	case derivedStateReplacementCommitted:
		return operationErr
	case derivedStateReplacementNotCommitted:
		if operationErr != nil {
			return operationErr
		}
		return errors.New("derived state replacement reported not-committed without an error")
	case derivedStateReplacementRecoveryRequired:
		return errors.Join(operationErr, errDerivedStateReplacementRecoveryRequired)
	default:
		return errors.Join(operationErr, fmt.Errorf("%w: invalid outcome %d", errDerivedStateReplacementRecoveryRequired, result.Outcome))
	}
}

func writeDerivedStateFileOutcome(stateRoot, relative string, body []byte) (derivedStateReplacementResult, error) {
	return writeDerivedStateFileOutcomeWithRecovery(stateRoot, relative, body, false)
}

func writeDerivedStateFileOutcomeWithRecovery(stateRoot, relative string, body []byte, recover bool) (derivedStateReplacementResult, error) {
	result := derivedStateReplacementResult{}
	err := writeDerivedStateFileTransaction(stateRoot, relative, body, &result, recover)
	return result, err
}

func replacementIdentityFromFile(file *os.File, info os.FileInfo, knownDigest *[sha256.Size]byte) (derivedStateReplacementIdentity, error) {
	if file == nil || info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return derivedStateReplacementIdentity{}, errors.New("derived state replacement identity binding is invalid")
	}
	digest := [sha256.Size]byte{}
	if knownDigest != nil {
		digest = *knownDigest
	} else {
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return derivedStateReplacementIdentity{}, err
		}
		hasher := sha256.New()
		written, readErr := io.CopyBuffer(hasher, io.LimitReader(file, info.Size()+1), make([]byte, 256*1024))
		after, statErr := file.Stat()
		if readErr != nil || statErr != nil || after == nil || written != info.Size() ||
			!os.SameFile(info, after) || after.Size() != info.Size() || after.Mode() != info.Mode() ||
			!after.ModTime().Equal(info.ModTime()) {
			return derivedStateReplacementIdentity{}, errors.Join(readErr, statErr, errors.New("derived state replacement object changed while hashing"))
		}
		copy(digest[:], hasher.Sum(nil))
	}
	after, statErr := file.Stat()
	if statErr != nil || after == nil || !os.SameFile(info, after) ||
		after.Size() != info.Size() || after.Mode() != info.Mode() ||
		!after.ModTime().Equal(info.ModTime()) {
		return derivedStateReplacementIdentity{}, errors.Join(statErr, errors.New("derived state replacement object changed before identity capture"))
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return derivedStateReplacementIdentity{}, errors.New("derived state replacement object lacks a filesystem identity")
	}
	identity := derivedStateReplacementIdentity{
		Size:      info.Size(),
		SHA256:    hex.EncodeToString(digest[:]),
		Mode:      uint32(info.Mode()),
		Device:    uint64(stat.Dev),
		Inode:     uint64(stat.Ino),
		ModTimeNS: info.ModTime().UnixNano(),
	}
	if err := identity.validate(info.Mode().Perm()&0o077 == 0); err != nil {
		return derivedStateReplacementIdentity{}, err
	}
	return identity, nil
}

func bindDerivedStateReplacementObject(parent *os.Root, name string) (*os.File, os.FileInfo, derivedStateReplacementIdentity, error) {
	if parent == nil || filepath.Base(name) != name || name == "" || name == "." {
		return nil, nil, derivedStateReplacementIdentity{}, errors.New("derived state replacement object coordinate is invalid")
	}
	before, err := parent.Lstat(name)
	if err != nil || before == nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, before, derivedStateReplacementIdentity{}, errors.Join(err, errors.New("derived state replacement object is not a regular file"))
	}
	file, err := parent.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, before, derivedStateReplacementIdentity{}, err
	}
	opened, statErr := file.Stat()
	current, lstatErr := parent.Lstat(name)
	if statErr != nil || lstatErr != nil || opened == nil || current == nil ||
		!os.SameFile(before, opened) || !os.SameFile(before, current) ||
		opened.Mode() != before.Mode() || current.Mode() != before.Mode() {
		file.Close()
		return nil, opened, derivedStateReplacementIdentity{}, errors.Join(statErr, lstatErr, errors.New("derived state replacement object changed while binding"))
	}
	identity, identityErr := replacementIdentityFromFile(file, opened, nil)
	if identityErr != nil {
		file.Close()
		return nil, opened, derivedStateReplacementIdentity{}, identityErr
	}
	return file, opened, identity, nil
}

func verifyHeldDerivedStateReplacementObject(file *os.File, expected os.FileInfo, identity derivedStateReplacementIdentity) error {
	if file == nil || expected == nil {
		return errors.New("derived state replacement held-object binding is invalid")
	}
	current, err := file.Stat()
	if err != nil || current == nil || !os.SameFile(expected, current) ||
		current.Size() != identity.Size || uint32(current.Mode()) != identity.Mode ||
		current.ModTime().UnixNano() != identity.ModTimeNS {
		return errors.Join(err, errors.New("derived state replacement held object changed"))
	}
	actual, err := replacementIdentityFromFile(file, current, nil)
	if err != nil || actual != identity {
		return errors.Join(err, errors.New("derived state replacement held object bytes changed"))
	}
	return nil
}

func observeDerivedStateReplacementObject(parent *os.Root, name string) (derivedStateReplacementIdentity, bool, error) {
	_, err := parent.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return derivedStateReplacementIdentity{}, false, nil
	}
	if err != nil {
		return derivedStateReplacementIdentity{}, false, err
	}
	file, _, identity, err := bindDerivedStateReplacementObject(parent, name)
	if file != nil {
		err = errors.Join(err, file.Close())
	}
	return identity, true, err
}

func verifyDerivedStateReplacementCoordinate(parent *os.Root, name string, expected derivedStateReplacementIdentity) error {
	current, exists, err := observeDerivedStateReplacementObject(parent, name)
	if err != nil || !exists || current != expected {
		return errors.Join(err, fmt.Errorf("derived state replacement coordinate %s has a foreign identity", name))
	}
	return nil
}

func derivedStateReplacementIntentBody(intent derivedStateReplacementIntent) ([]byte, error) {
	if err := intent.validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(intent)
	if err != nil || len(body) == 0 || len(body) > derivedStateReplacementIntentMaxBytes {
		return nil, errors.Join(err, errors.New("derived state replacement intent exceeds its size limit"))
	}
	return body, nil
}

func callDerivedStateReplacementPhaseHook(phase string) error {
	if derivedStateReplacementPhaseHook == nil {
		return nil
	}
	return derivedStateReplacementPhaseHook(phase)
}

func syncDerivedStateReplacementParent(directory *os.File, mutationGuard *derivedStateDirectoryMutationGuard, recoverUnexpectedMutation func() error, phase string) error {
	if directory == nil || mutationGuard == nil || recoverUnexpectedMutation == nil {
		return errors.New("derived state replacement sync binding is invalid")
	}
	if err := derivedStateReplacementParentSync(directory, phase); err != nil {
		return fmt.Errorf("sync derived state replacement phase %s: %w", phase, err)
	}
	if err := recoverUnexpectedMutation(); err != nil {
		return err
	}
	return callDerivedStateReplacementPhaseHook(phase)
}

func createDerivedStateReplacementCarrier(
	parent *os.Root,
	directory *os.File,
	name string,
	body []byte,
	mutationGuard *derivedStateDirectoryMutationGuard,
	recoverUnexpectedMutation func() error,
	phase string,
) (os.FileInfo, error) {
	if parent == nil || directory == nil || filepath.Base(name) != name || name == "" ||
		len(body) == 0 || len(body) > derivedStateReplacementIntentMaxBytes {
		return nil, errors.New("derived state replacement carrier binding is invalid")
	}
	file, err := parent.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	identity, statErr := file.Stat()
	if statErr != nil || identity == nil || !identity.Mode().IsRegular() ||
		identity.Mode()&os.ModeSymlink != 0 || identity.Mode().Perm()&0o077 != 0 {
		file.Close()
		return identity, errors.Join(statErr, errors.New("derived state replacement carrier is not an exact private regular file"))
	}
	if err := mutationGuard.admitKnownMutation(); err != nil {
		file.Close()
		return identity, err
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return identity, err
	}
	identity, statErr = file.Stat()
	currentAfterMode, currentModeErr := parent.Lstat(name)
	if statErr != nil || currentModeErr != nil || identity == nil || currentAfterMode == nil ||
		!os.SameFile(identity, currentAfterMode) || identity.Mode() != 0o600 || currentAfterMode.Mode() != 0o600 {
		file.Close()
		return identity, errors.Join(statErr, currentModeErr, errors.New("derived state replacement carrier did not acquire exact private mode"))
	}
	written, writeErr := file.Write(body)
	syncErr := file.Sync()
	after, afterErr := file.Stat()
	current, currentErr := parent.Lstat(name)
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || afterErr != nil || currentErr != nil || closeErr != nil ||
		written != len(body) || after == nil || current == nil ||
		!os.SameFile(identity, after) || !os.SameFile(identity, current) ||
		after.Size() != int64(len(body)) || after.Mode() != 0o600 || current.Mode() != 0o600 {
		return identity, errors.Join(writeErr, syncErr, afterErr, currentErr, closeErr, errors.New("derived state replacement carrier write was not exact"))
	}
	if err := syncDerivedStateReplacementParent(directory, mutationGuard, recoverUnexpectedMutation, phase); err != nil {
		return after, err
	}
	return after, nil
}

func publishPreparedDerivedStateReplacementIntent(
	parent *os.Root,
	directory *os.File,
	intent derivedStateReplacementIntent,
	mutationGuard *derivedStateDirectoryMutationGuard,
	recoverUnexpectedMutation func() error,
) error {
	body, err := derivedStateReplacementIntentBody(intent)
	if err != nil {
		return err
	}
	main := derivedStateReplacementIntentName(intent.TransactionID)
	staged := main + ".new"
	identity, err := createDerivedStateReplacementCarrier(parent, directory, staged, body, mutationGuard, recoverUnexpectedMutation, "prepared-carrier")
	if err != nil {
		return err
	}
	if err := renameYUMCompatibilityCandidateNoReplace(directory.Fd(), staged, main); err != nil {
		return err
	}
	if err := mutationGuard.admitKnownMutation(); err != nil {
		return err
	}
	current, statErr := parent.Lstat(main)
	stagedCurrent, stagedErr := parent.Lstat(staged)
	if statErr != nil || current == nil || !os.SameFile(identity, current) ||
		!errors.Is(stagedErr, os.ErrNotExist) || stagedCurrent != nil {
		return errors.Join(statErr, stagedErr, errors.New("derived state prepared intent changed while publishing"))
	}
	return syncDerivedStateReplacementParent(directory, mutationGuard, recoverUnexpectedMutation, "prepared")
}

func publishCommittedDerivedStateReplacementIntent(
	parent *os.Root,
	directory *os.File,
	intent derivedStateReplacementIntent,
	mutationGuard *derivedStateDirectoryMutationGuard,
	recoverUnexpectedMutation func() error,
) error {
	intent.Phase = derivedStateReplacementCommittedPhase
	body, err := derivedStateReplacementIntentBody(intent)
	if err != nil {
		return err
	}
	main := derivedStateReplacementIntentName(intent.TransactionID)
	next := main + ".next"
	if _, err := createDerivedStateReplacementCarrier(parent, directory, next, body, mutationGuard, recoverUnexpectedMutation, "committed-carrier"); err != nil {
		return err
	}
	if err := exchangeDerivedStateFiles(directory.Fd(), main, next); err != nil {
		return err
	}
	if err := mutationGuard.admitKnownMutation(); err != nil {
		return err
	}
	mainIntent, _, _, mainErr := readDerivedStateReplacementCarrier(parent, main)
	nextIntent, _, _, nextErr := readDerivedStateReplacementCarrier(parent, next)
	if mainErr != nil || nextErr != nil ||
		mainIntent.Phase != derivedStateReplacementCommittedPhase ||
		nextIntent.Phase != derivedStateReplacementPrepared {
		return errors.Join(mainErr, nextErr, errors.New("derived state committed intent exchange changed"))
	}
	return syncDerivedStateReplacementParent(directory, mutationGuard, recoverUnexpectedMutation, "committed")
}

func readDerivedStateReplacementCarrier(parent *os.Root, name string) (derivedStateReplacementIntent, os.FileInfo, []byte, error) {
	var intent derivedStateReplacementIntent
	if parent == nil || filepath.Base(name) != name || name == "" {
		return intent, nil, nil, errors.New("derived state replacement carrier coordinate is invalid")
	}
	before, err := parent.Lstat(name)
	if err != nil || before == nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() ||
		before.Mode() != 0o600 || before.Size() <= 0 || before.Size() > derivedStateReplacementIntentMaxBytes {
		return intent, before, nil, errors.Join(err, errors.New("derived state replacement carrier is not an exact private file"))
	}
	file, err := parent.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return intent, before, nil, err
	}
	defer file.Close()
	body, readErr := io.ReadAll(io.LimitReader(file, derivedStateReplacementIntentMaxBytes+1))
	var hookErr error
	if readErr == nil && derivedStateReplacementAfterCarrierReadHook != nil {
		hookErr = derivedStateReplacementAfterCarrierReadHook(name)
	}
	opened, statErr := file.Stat()
	current, lstatErr := parent.Lstat(name)
	if readErr != nil || hookErr != nil || statErr != nil || lstatErr != nil || opened == nil || current == nil ||
		len(body) == 0 || len(body) > derivedStateReplacementIntentMaxBytes ||
		!os.SameFile(before, opened) || !os.SameFile(before, current) ||
		opened.Size() != int64(len(body)) || opened.Mode() != 0o600 || current.Mode() != 0o600 ||
		!opened.ModTime().Equal(before.ModTime()) || !current.ModTime().Equal(before.ModTime()) {
		return intent, opened, body, errors.Join(readErr, hookErr, statErr, lstatErr, errors.New("derived state replacement carrier changed while reading"))
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&intent); err != nil {
		return intent, opened, body, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return intent, opened, body, errors.New("derived state replacement carrier has trailing JSON")
	}
	if err := intent.validate(); err != nil {
		return intent, opened, body, err
	}
	return intent, opened, body, nil
}

type derivedStateReplacementCarrierSet struct {
	transactionID  string
	main           string
	staged         string
	next           string
	mainTrash      string
	stagedTrash    string
	nextTrash      string
	isolation      string
	isolationTrash string
	sourceTrash    string
}

func parseDerivedStateReplacementCarrierName(name string) (string, string, bool) {
	value, ok := strings.CutPrefix(name, derivedStateReplacementIntentPrefix)
	if !ok || len(value) < 32+len(".json") {
		return "", "", false
	}
	transactionID := value[:32]
	if !exactLowerHex(transactionID, 32) {
		return "", "", false
	}
	suffix := value[32:]
	switch suffix {
	case ".json":
		return transactionID, "main", true
	case ".json.new":
		return transactionID, "staged", true
	case ".json.next":
		return transactionID, "next", true
	case ".json.remove":
		return transactionID, "main-trash", true
	case ".json.new.remove":
		return transactionID, "staged-trash", true
	case ".json.next.remove":
		return transactionID, "next-trash", true
	default:
		return "", "", false
	}
}

func parseDerivedStateReplacementIsolationName(name string) (string, string, bool) {
	value, ok := strings.CutPrefix(name, derivedStateReplacementIsolationPrefix)
	if !ok || len(value) < 32 {
		return "", "", false
	}
	transactionID := value[:32]
	if !exactLowerHex(transactionID, 32) {
		return "", "", false
	}
	switch value[32:] {
	case "":
		return transactionID, "isolation", true
	case ".remove":
		return transactionID, "isolation-trash", true
	case ".source.remove":
		return transactionID, "source-trash", true
	default:
		return "", "", false
	}
}

func sameDerivedStateReplacementTransaction(left, right derivedStateReplacementIntent) bool {
	left.Phase = ""
	right.Phase = ""
	return left == right
}

func listDerivedStateReplacementCarrierSets(directory *os.File) ([]derivedStateReplacementCarrierSet, error) {
	if directory == nil {
		return nil, errors.New("derived state replacement directory binding is missing")
	}
	if _, err := directory.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	sets := make(map[string]*derivedStateReplacementCarrierSet)
	for {
		entries, readErr := directory.ReadDir(128)
		for _, entry := range entries {
			name := entry.Name()
			transactionID, kind, ok := parseDerivedStateReplacementCarrierName(name)
			if !ok {
				transactionID, kind, ok = parseDerivedStateReplacementIsolationName(name)
			}
			if !ok {
				if strings.HasPrefix(name, derivedStateReplacementIntentPrefix) ||
					strings.HasPrefix(name, derivedStateReplacementIsolationPrefix) {
					return nil, errors.Join(
						fmt.Errorf("malformed reserved derived state replacement coordinate %s", name),
						errDerivedStateReplacementRecoveryRequired,
					)
				}
				continue
			}
			set := sets[transactionID]
			if set == nil {
				if len(sets) >= derivedStateReplacementMaxTransactions {
					return nil, errors.Join(
						fmt.Errorf("derived state replacement transaction count exceeds %d", derivedStateReplacementMaxTransactions),
						errDerivedStateReplacementRecoveryRequired,
					)
				}
				set = &derivedStateReplacementCarrierSet{transactionID: transactionID}
				sets[transactionID] = set
			}
			switch kind {
			case "main":
				set.main = name
			case "staged":
				set.staged = name
			case "next":
				set.next = name
			case "main-trash":
				set.mainTrash = name
			case "staged-trash":
				set.stagedTrash = name
			case "next-trash":
				set.nextTrash = name
			case "isolation":
				set.isolation = name
			case "isolation-trash":
				set.isolationTrash = name
			case "source-trash":
				set.sourceTrash = name
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}
	transactionIDs := make([]string, 0, len(sets))
	for transactionID := range sets {
		transactionIDs = append(transactionIDs, transactionID)
	}
	sort.Strings(transactionIDs)
	result := make([]derivedStateReplacementCarrierSet, 0, len(transactionIDs))
	for _, transactionID := range transactionIDs {
		result = append(result, *sets[transactionID])
	}
	return result, nil
}

func restoreDerivedStateReplacementTrash(
	parent *os.Root,
	directory *os.File,
	trash, canonical string,
	mutationGuard *derivedStateDirectoryMutationGuard,
	recoverUnexpectedMutation func() error,
) error {
	if trash == "" {
		return nil
	}
	if _, err := parent.Lstat(canonical); err == nil {
		return fmt.Errorf("derived state replacement cleanup coordinate %s was reoccupied; evidence retained at %s", canonical, trash)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := renameYUMCompatibilityCandidateNoReplace(directory.Fd(), trash, canonical); err != nil {
		return err
	}
	if err := mutationGuard.admitKnownMutation(); err != nil {
		return err
	}
	return syncDerivedStateReplacementParent(directory, mutationGuard, recoverUnexpectedMutation, "restore-cleanup-evidence")
}

func removeDerivedStateReplacementObject(
	parent *os.Root,
	directory *os.File,
	name, trash string,
	expected derivedStateReplacementIdentity,
	mutationGuard *derivedStateDirectoryMutationGuard,
	recoverUnexpectedMutation func() error,
	phase string,
) error {
	if filepath.Base(name) != name || filepath.Base(trash) != trash || name == "" || trash == "" || name == trash {
		return errors.New("derived state replacement cleanup coordinate is invalid")
	}
	current, exists, err := observeDerivedStateReplacementObject(parent, name)
	if !exists && err == nil {
		trashCurrent, trashExists, trashErr := observeDerivedStateReplacementObject(parent, trash)
		if trashErr != nil {
			return trashErr
		}
		if !trashExists {
			return nil
		}
		if trashCurrent != expected {
			return fmt.Errorf("derived state replacement cleanup evidence %s has a foreign identity", trash)
		}
		if err := restoreDerivedStateReplacementTrash(parent, directory, trash, name, mutationGuard, recoverUnexpectedMutation); err != nil {
			return err
		}
		current, exists = expected, true
	}
	if err != nil || !exists || current != expected {
		return errors.Join(err, fmt.Errorf("derived state replacement cleanup refused foreign coordinate %s", name))
	}
	if err := renameYUMCompatibilityCandidateNoReplace(directory.Fd(), name, trash); err != nil {
		return err
	}
	if err := mutationGuard.admitKnownMutation(); err != nil {
		return err
	}
	if err := syncDerivedStateReplacementParent(directory, mutationGuard, recoverUnexpectedMutation, phase+"-quarantine"); err != nil {
		return err
	}
	if err := verifyDerivedStateReplacementCoordinate(parent, trash, expected); err != nil {
		return err
	}
	if err := parent.Remove(trash); err != nil {
		return err
	}
	if err := mutationGuard.admitKnownMutation(); err != nil {
		return err
	}
	return syncDerivedStateReplacementParent(directory, mutationGuard, recoverUnexpectedMutation, phase+"-remove")
}

func removeDerivedStateReplacementCarrier(
	parent *os.Root,
	directory *os.File,
	name, trash string,
	mutationGuard *derivedStateDirectoryMutationGuard,
	recoverUnexpectedMutation func() error,
	phase string,
) error {
	intent, info, body, err := readDerivedStateReplacementCarrier(parent, name)
	if err != nil {
		return err
	}
	_ = intent
	digest := sha256.Sum256(body)
	identity, err := replacementIdentityFromFileMustDigest(parent, name, info, digest)
	if err != nil {
		return err
	}
	return removeDerivedStateReplacementObject(parent, directory, name, trash, identity, mutationGuard, recoverUnexpectedMutation, phase)
}

func replacementIdentityFromFileMustDigest(parent *os.Root, name string, expected os.FileInfo, digest [sha256.Size]byte) (derivedStateReplacementIdentity, error) {
	file, err := parent.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return derivedStateReplacementIdentity{}, err
	}
	defer file.Close()
	current, statErr := file.Stat()
	pathCurrent, lstatErr := parent.Lstat(name)
	if statErr != nil || lstatErr != nil || current == nil || pathCurrent == nil ||
		!os.SameFile(expected, current) || !os.SameFile(expected, pathCurrent) {
		return derivedStateReplacementIdentity{}, errors.Join(statErr, lstatErr, errors.New("derived state replacement carrier changed before cleanup"))
	}
	return replacementIdentityFromFile(file, current, &digest)
}

func classifyDerivedStateReplacementIdentity(
	parent *os.Root,
	name string,
	candidate derivedStateReplacementIdentity,
	prior *derivedStateReplacementIdentity,
) (string, error) {
	current, exists, err := observeDerivedStateReplacementObject(parent, name)
	if err != nil {
		return "", err
	}
	if !exists {
		return "absent", nil
	}
	if current == candidate {
		return "candidate", nil
	}
	if prior != nil && current == *prior {
		return "prior", nil
	}
	return "foreign", fmt.Errorf("derived state replacement coordinate %s has a third identity current=%+v candidate=%+v prior=%+v", name, current, candidate, prior)
}

func restoreDerivedStateReplacementCandidateTrash(
	parent *os.Root,
	directory *os.File,
	intent derivedStateReplacementIntent,
	expected derivedStateReplacementIdentity,
	mutationGuard *derivedStateDirectoryMutationGuard,
	recoverUnexpectedMutation func() error,
) error {
	trashState, trashErr := classifyDerivedStateReplacementIdentity(parent, intent.CandidateTrash, expected, nil)
	if trashErr != nil {
		return trashErr
	}
	if trashState == "absent" {
		return nil
	}
	_, candidateErr := parent.Lstat(intent.Candidate)
	if !errors.Is(candidateErr, os.ErrNotExist) {
		if candidateErr != nil {
			return candidateErr
		}
		return errors.New("derived state replacement candidate cleanup coordinates are ambiguous")
	}
	return restoreDerivedStateReplacementTrash(parent, directory, intent.CandidateTrash, intent.Candidate, mutationGuard, recoverUnexpectedMutation)
}

func replayPreparedDerivedStateReplacement(
	parent *os.Root,
	directory *os.File,
	intent derivedStateReplacementIntent,
	mutationGuard *derivedStateDirectoryMutationGuard,
	recoverUnexpectedMutation func() error,
) (derivedStateReplacementOutcome, error) {
	var prior *derivedStateReplacementIdentity
	if intent.PriorPresent {
		prior = &intent.PriorID
	}
	if err := restoreDerivedStateReplacementCandidateTrash(parent, directory, intent, intent.CandidateID, mutationGuard, recoverUnexpectedMutation); err != nil {
		return derivedStateReplacementRecoveryRequired, errors.Join(err, errDerivedStateReplacementRecoveryRequired)
	}
	sourceState, sourceErr := classifyDerivedStateReplacementIdentity(parent, intent.Source, intent.CandidateID, nil)
	sourceTrashState, sourceTrashErr := classifyDerivedStateReplacementIdentity(parent, intent.SourceTrash, intent.CandidateID, nil)
	if sourceErr != nil || sourceTrashErr != nil {
		return derivedStateReplacementRecoveryRequired, errors.Join(sourceErr, sourceTrashErr, errDerivedStateReplacementRecoveryRequired)
	}
	if sourceState == "absent" && sourceTrashState == "candidate" {
		if err := restoreDerivedStateReplacementTrash(parent, directory, intent.SourceTrash, intent.Source, mutationGuard, recoverUnexpectedMutation); err != nil {
			return derivedStateReplacementRecoveryRequired, errors.Join(err, errDerivedStateReplacementRecoveryRequired)
		}
		sourceState = "candidate"
		sourceTrashState = "absent"
	}
	if sourceTrashState != "absent" {
		return derivedStateReplacementRecoveryRequired, errors.Join(
			errors.New("derived state replacement source cleanup coordinates are ambiguous"),
			errDerivedStateReplacementRecoveryRequired,
		)
	}
	destinationState, destinationErr := classifyDerivedStateReplacementIdentity(parent, intent.Destination, intent.CandidateID, prior)
	candidateState, candidateErr := classifyDerivedStateReplacementIdentity(parent, intent.Candidate, intent.CandidateID, prior)
	if destinationErr != nil || candidateErr != nil {
		return derivedStateReplacementRecoveryRequired, errors.Join(destinationErr, candidateErr, errDerivedStateReplacementRecoveryRequired)
	}
	if intent.PriorPresent {
		switch {
		case destinationState == "candidate" && candidateState == "prior" && sourceState == "absent":
			if err := exchangeDerivedStateFiles(directory.Fd(), intent.Candidate, intent.Destination); err != nil {
				return derivedStateReplacementRecoveryRequired, errors.Join(err, errDerivedStateReplacementRecoveryRequired)
			}
			if err := mutationGuard.admitKnownMutation(); err != nil {
				return derivedStateReplacementRecoveryRequired, errors.Join(err, errDerivedStateReplacementRecoveryRequired)
			}
			if err := syncDerivedStateReplacementParent(directory, mutationGuard, recoverUnexpectedMutation, "prepared-rollback-exchange"); err != nil {
				return derivedStateReplacementRecoveryRequired, errors.Join(err, errDerivedStateReplacementRecoveryRequired)
			}
			destinationState = "prior"
			candidateState = "candidate"
		case destinationState == "prior" && candidateState == "candidate" && sourceState == "absent":
			if err := syncDerivedStateReplacementParent(directory, mutationGuard, recoverUnexpectedMutation, "prepared-rollback-observed"); err != nil {
				return derivedStateReplacementRecoveryRequired, errors.Join(err, errDerivedStateReplacementRecoveryRequired)
			}
		case destinationState == "prior" && candidateState == "absent" && (sourceState == "candidate" || sourceState == "absent"):
			if err := syncDerivedStateReplacementParent(directory, mutationGuard, recoverUnexpectedMutation, "prepared-source-observed"); err != nil {
				return derivedStateReplacementRecoveryRequired, errors.Join(err, errDerivedStateReplacementRecoveryRequired)
			}
		default:
			return derivedStateReplacementRecoveryRequired, errors.Join(
				fmt.Errorf("prepared derived state replacement has destination=%s source=%s candidate=%s", destinationState, sourceState, candidateState),
				errDerivedStateReplacementRecoveryRequired,
			)
		}
	} else {
		switch {
		case destinationState == "candidate" && candidateState == "absent" && sourceState == "absent":
			if err := renameYUMCompatibilityCandidateNoReplace(directory.Fd(), intent.Destination, intent.Candidate); err != nil {
				return derivedStateReplacementRecoveryRequired, errors.Join(err, errDerivedStateReplacementRecoveryRequired)
			}
			if err := mutationGuard.admitKnownMutation(); err != nil {
				return derivedStateReplacementRecoveryRequired, errors.Join(err, errDerivedStateReplacementRecoveryRequired)
			}
			if err := syncDerivedStateReplacementParent(directory, mutationGuard, recoverUnexpectedMutation, "prepared-rollback-absence"); err != nil {
				return derivedStateReplacementRecoveryRequired, errors.Join(err, errDerivedStateReplacementRecoveryRequired)
			}
			destinationState = "absent"
			candidateState = "candidate"
		case destinationState == "absent" && candidateState == "candidate" && sourceState == "absent":
			if err := syncDerivedStateReplacementParent(directory, mutationGuard, recoverUnexpectedMutation, "prepared-absence-observed"); err != nil {
				return derivedStateReplacementRecoveryRequired, errors.Join(err, errDerivedStateReplacementRecoveryRequired)
			}
		case destinationState == "absent" && candidateState == "absent" && (sourceState == "candidate" || sourceState == "absent"):
			if err := syncDerivedStateReplacementParent(directory, mutationGuard, recoverUnexpectedMutation, "prepared-new-source-observed"); err != nil {
				return derivedStateReplacementRecoveryRequired, errors.Join(err, errDerivedStateReplacementRecoveryRequired)
			}
		default:
			return derivedStateReplacementRecoveryRequired, errors.Join(
				fmt.Errorf("prepared new derived state replacement has destination=%s source=%s candidate=%s", destinationState, sourceState, candidateState),
				errDerivedStateReplacementRecoveryRequired,
			)
		}
	}
	destinationState, destinationErr = classifyDerivedStateReplacementIdentity(parent, intent.Destination, intent.CandidateID, prior)
	candidateState, candidateErr = classifyDerivedStateReplacementIdentity(parent, intent.Candidate, intent.CandidateID, prior)
	sourceState, sourceErr = classifyDerivedStateReplacementIdentity(parent, intent.Source, intent.CandidateID, nil)
	if destinationErr != nil || candidateErr != nil ||
		sourceErr != nil ||
		(intent.PriorPresent && destinationState != "prior") ||
		(!intent.PriorPresent && destinationState != "absent") ||
		(sourceState == "candidate" && candidateState == "candidate") ||
		(sourceState != "candidate" && sourceState != "absent") ||
		(candidateState != "candidate" && candidateState != "absent") {
		return derivedStateReplacementRecoveryRequired, errors.Join(destinationErr, candidateErr, sourceErr, errDerivedStateReplacementRecoveryRequired)
	}
	switch {
	case sourceState == "candidate":
		if err := removeDerivedStateReplacementObject(
			parent,
			directory,
			intent.Source,
			intent.SourceTrash,
			intent.CandidateID,
			mutationGuard,
			recoverUnexpectedMutation,
			"prepared-source-cleanup",
		); err != nil {
			return derivedStateReplacementNotCommitted, err
		}
	case candidateState == "candidate":
		if err := removeDerivedStateReplacementObject(
			parent,
			directory,
			intent.Candidate,
			intent.CandidateTrash,
			intent.CandidateID,
			mutationGuard,
			recoverUnexpectedMutation,
			"prepared-candidate-cleanup",
		); err != nil {
			return derivedStateReplacementNotCommitted, err
		}
	default:
		if err := syncDerivedStateReplacementParent(directory, mutationGuard, recoverUnexpectedMutation, "prepared-candidate-absence"); err != nil {
			return derivedStateReplacementNotCommitted, err
		}
	}
	return derivedStateReplacementNotCommitted, nil
}

func replayCommittedDerivedStateReplacement(
	parent *os.Root,
	directory *os.File,
	intent derivedStateReplacementIntent,
	mutationGuard *derivedStateDirectoryMutationGuard,
	recoverUnexpectedMutation func() error,
) (derivedStateReplacementOutcome, error) {
	var prior *derivedStateReplacementIdentity
	if intent.PriorPresent {
		prior = &intent.PriorID
	}
	destinationState, destinationErr := classifyDerivedStateReplacementIdentity(parent, intent.Destination, intent.CandidateID, prior)
	if destinationErr != nil || destinationState != "candidate" {
		return derivedStateReplacementRecoveryRequired, errors.Join(destinationErr, errDerivedStateReplacementRecoveryRequired)
	}
	sourceState, sourceErr := classifyDerivedStateReplacementIdentity(parent, intent.Source, intent.CandidateID, nil)
	sourceTrashState, sourceTrashErr := classifyDerivedStateReplacementIdentity(parent, intent.SourceTrash, intent.CandidateID, nil)
	if sourceErr != nil || sourceTrashErr != nil || sourceState != "absent" || sourceTrashState != "absent" {
		return derivedStateReplacementRecoveryRequired, errors.Join(sourceErr, sourceTrashErr, errDerivedStateReplacementRecoveryRequired)
	}
	if intent.PriorPresent {
		candidateState, candidateErr := classifyDerivedStateReplacementIdentity(parent, intent.Candidate, intent.CandidateID, prior)
		trashState, trashErr := classifyDerivedStateReplacementIdentity(parent, intent.CandidateTrash, intent.CandidateID, prior)
		if candidateErr != nil || trashErr != nil {
			return derivedStateReplacementRecoveryRequired, errors.Join(candidateErr, trashErr, errDerivedStateReplacementRecoveryRequired)
		}
		switch {
		case candidateState == "prior" && trashState == "absent":
		case candidateState == "absent" && trashState == "prior":
			if err := restoreDerivedStateReplacementTrash(parent, directory, intent.CandidateTrash, intent.Candidate, mutationGuard, recoverUnexpectedMutation); err != nil {
				return derivedStateReplacementCommitted, err
			}
		case candidateState == "absent" && trashState == "absent":
			if err := syncDerivedStateReplacementParent(directory, mutationGuard, recoverUnexpectedMutation, "committed-prior-absence"); err != nil {
				return derivedStateReplacementCommitted, err
			}
			return derivedStateReplacementCommitted, nil
		default:
			return derivedStateReplacementRecoveryRequired, errors.Join(
				fmt.Errorf("committed derived state replacement has prior=%s trash=%s", candidateState, trashState),
				errDerivedStateReplacementRecoveryRequired,
			)
		}
		if err := removeDerivedStateReplacementObject(
			parent,
			directory,
			intent.Candidate,
			intent.CandidateTrash,
			intent.PriorID,
			mutationGuard,
			recoverUnexpectedMutation,
			"committed-prior-cleanup",
		); err != nil {
			return derivedStateReplacementCommitted, err
		}
	} else {
		candidateState, candidateErr := classifyDerivedStateReplacementIdentity(parent, intent.Candidate, intent.CandidateID, nil)
		trashState, trashErr := classifyDerivedStateReplacementIdentity(parent, intent.CandidateTrash, intent.CandidateID, nil)
		if candidateErr != nil || trashErr != nil || candidateState != "absent" || trashState != "absent" {
			return derivedStateReplacementRecoveryRequired, errors.Join(candidateErr, trashErr, errDerivedStateReplacementRecoveryRequired)
		}
		if err := syncDerivedStateReplacementParent(directory, mutationGuard, recoverUnexpectedMutation, "committed-new-absence"); err != nil {
			return derivedStateReplacementCommitted, err
		}
	}
	return derivedStateReplacementCommitted, nil
}

type derivedStateReplacementCarrierTopology struct {
	main      derivedStateReplacementIntent
	staged    derivedStateReplacementIntent
	next      derivedStateReplacementIntent
	hasMain   bool
	hasStaged bool
	hasNext   bool
}

func (topology derivedStateReplacementCarrierTopology) validate() error {
	if !topology.hasMain && !topology.hasStaged && !topology.hasNext {
		return errors.New("derived state replacement has no durable carrier")
	}
	var authoritative derivedStateReplacementIntent
	switch {
	case topology.hasMain:
		authoritative = topology.main
	case topology.hasStaged:
		authoritative = topology.staged
	default:
		return errors.New("derived state replacement lacks an authoritative carrier")
	}
	for _, carrier := range []struct {
		present bool
		intent  derivedStateReplacementIntent
	}{
		{present: topology.hasMain, intent: topology.main},
		{present: topology.hasStaged, intent: topology.staged},
		{present: topology.hasNext, intent: topology.next},
	} {
		if carrier.present && !sameDerivedStateReplacementTransaction(authoritative, carrier.intent) {
			return errors.New("derived state replacement carriers describe different transactions")
		}
	}
	if topology.hasStaged {
		if topology.hasMain || topology.hasNext ||
			topology.staged.Phase != derivedStateReplacementPrepared {
			return errors.New("derived state replacement staged carrier has an impossible topology")
		}
		return nil
	}
	if !topology.hasMain {
		return errors.New("derived state replacement auxiliary carrier lacks its main carrier")
	}
	if !topology.hasNext {
		return nil
	}
	if topology.main.Phase == derivedStateReplacementPrepared &&
		topology.next.Phase == derivedStateReplacementCommittedPhase {
		return nil
	}
	if topology.main.Phase == derivedStateReplacementCommittedPhase &&
		topology.next.Phase == derivedStateReplacementPrepared {
		return nil
	}
	return errors.New("derived state replacement main and next carriers have an impossible phase topology")
}

func inspectDerivedStateReplacementCarrierTopology(
	parent *os.Root,
	set derivedStateReplacementCarrierSet,
) (derivedStateReplacementCarrierTopology, error) {
	var topology derivedStateReplacementCarrierTopology
	for _, coordinate := range []struct {
		canonical string
		trash     string
		assign    func(derivedStateReplacementIntent)
	}{
		{canonical: set.main, trash: set.mainTrash, assign: func(intent derivedStateReplacementIntent) {
			topology.main, topology.hasMain = intent, true
		}},
		{canonical: set.staged, trash: set.stagedTrash, assign: func(intent derivedStateReplacementIntent) {
			topology.staged, topology.hasStaged = intent, true
		}},
		{canonical: set.next, trash: set.nextTrash, assign: func(intent derivedStateReplacementIntent) {
			topology.next, topology.hasNext = intent, true
		}},
	} {
		if coordinate.canonical != "" && coordinate.trash != "" {
			return topology, fmt.Errorf("derived state replacement carrier and cleanup evidence both exist for %s", set.transactionID)
		}
		name := coordinate.canonical
		if name == "" {
			name = coordinate.trash
		}
		if name == "" {
			continue
		}
		intent, _, _, err := readDerivedStateReplacementCarrier(parent, name)
		if err != nil {
			return topology, err
		}
		if intent.TransactionID != set.transactionID {
			return topology, errors.New("derived state replacement carrier transaction ID mismatch")
		}
		coordinate.assign(intent)
	}
	if err := topology.validate(); err != nil {
		return topology, err
	}
	return topology, nil
}

func normalizeDerivedStateReplacementCarrierTrash(
	parent *os.Root,
	directory *os.File,
	set *derivedStateReplacementCarrierSet,
	mutationGuard *derivedStateDirectoryMutationGuard,
	recoverUnexpectedMutation func() error,
) error {
	if set == nil {
		return errors.New("derived state replacement carrier set is missing")
	}
	for _, coordinate := range []struct {
		canonical *string
		trash     *string
	}{
		{canonical: &set.main, trash: &set.mainTrash},
		{canonical: &set.staged, trash: &set.stagedTrash},
		{canonical: &set.next, trash: &set.nextTrash},
	} {
		if *coordinate.trash == "" {
			continue
		}
		if *coordinate.canonical != "" {
			return fmt.Errorf("derived state replacement carrier and cleanup evidence both exist for %s", set.transactionID)
		}
		canonical := strings.TrimSuffix(*coordinate.trash, ".remove")
		if err := restoreDerivedStateReplacementTrash(parent, directory, *coordinate.trash, canonical, mutationGuard, recoverUnexpectedMutation); err != nil {
			return err
		}
		*coordinate.canonical = canonical
		*coordinate.trash = ""
	}
	return nil
}

func proveDerivedStateReplacementOutcome(
	parent *os.Root,
	intent derivedStateReplacementIntent,
	outcome derivedStateReplacementOutcome,
	recoverUnexpectedMutation func() error,
) error {
	if parent == nil || recoverUnexpectedMutation == nil {
		return errors.New("derived state replacement outcome proof binding is invalid")
	}
	if err := recoverUnexpectedMutation(); err != nil {
		return err
	}
	var prior *derivedStateReplacementIdentity
	if intent.PriorPresent {
		prior = &intent.PriorID
	}
	destinationState, err := classifyDerivedStateReplacementIdentity(parent, intent.Destination, intent.CandidateID, prior)
	if err != nil {
		return err
	}
	switch outcome {
	case derivedStateReplacementNotCommitted:
		if intent.PriorPresent && destinationState == "prior" {
			return nil
		}
		if !intent.PriorPresent && destinationState == "absent" {
			return nil
		}
	case derivedStateReplacementCommitted:
		if destinationState == "candidate" {
			return nil
		}
	default:
		return errDerivedStateReplacementRecoveryRequired
	}
	return fmt.Errorf("derived state replacement outcome %d has destination state %s", outcome, destinationState)
}

func recoverOneDerivedStateReplacementTransaction(
	parent *os.Root,
	directory *os.File,
	set derivedStateReplacementCarrierSet,
	mutationGuard *derivedStateDirectoryMutationGuard,
	recoverUnexpectedMutation func() error,
) (derivedStateReplacementOutcome, error) {
	if _, err := inspectDerivedStateReplacementCarrierTopology(parent, set); err != nil {
		return derivedStateReplacementRecoveryRequired, errors.Join(err, errDerivedStateReplacementRecoveryRequired)
	}
	if err := normalizeDerivedStateReplacementCarrierTrash(parent, directory, &set, mutationGuard, recoverUnexpectedMutation); err != nil {
		return derivedStateReplacementRecoveryRequired, errors.Join(err, errDerivedStateReplacementRecoveryRequired)
	}
	carrierNames := make([]string, 0, 3)
	for _, name := range []string{set.main, set.staged, set.next} {
		if name != "" {
			carrierNames = append(carrierNames, name)
		}
	}
	if len(carrierNames) == 0 {
		return derivedStateReplacementRecoveryRequired, errors.Join(
			errors.New("derived state replacement has no durable carrier"),
			errDerivedStateReplacementRecoveryRequired,
		)
	}
	intents := make(map[string]derivedStateReplacementIntent, len(carrierNames))
	for _, name := range carrierNames {
		intent, _, _, err := readDerivedStateReplacementCarrier(parent, name)
		if err != nil {
			return derivedStateReplacementRecoveryRequired, errors.Join(err, errDerivedStateReplacementRecoveryRequired)
		}
		if intent.TransactionID != set.transactionID {
			return derivedStateReplacementRecoveryRequired, errors.Join(
				errors.New("derived state replacement carrier transaction ID mismatch"),
				errDerivedStateReplacementRecoveryRequired,
			)
		}
		intents[name] = intent
	}
	topology := derivedStateReplacementCarrierTopology{}
	if set.main != "" {
		topology.main, topology.hasMain = intents[set.main], true
	}
	if set.staged != "" {
		topology.staged, topology.hasStaged = intents[set.staged], true
	}
	if set.next != "" {
		topology.next, topology.hasNext = intents[set.next], true
	}
	if err := topology.validate(); err != nil {
		return derivedStateReplacementRecoveryRequired, errors.Join(err, errDerivedStateReplacementRecoveryRequired)
	}
	authoritativeName := set.main
	if authoritativeName == "" {
		if set.staged == "" || set.next != "" {
			return derivedStateReplacementRecoveryRequired, errors.Join(
				errors.New("derived state replacement lacks its authoritative prepared carrier"),
				errDerivedStateReplacementRecoveryRequired,
			)
		}
		authoritativeName = set.staged
	}
	authoritative := intents[authoritativeName]
	for name, intent := range intents {
		if !sameDerivedStateReplacementTransaction(authoritative, intent) {
			return derivedStateReplacementRecoveryRequired, errors.Join(
				fmt.Errorf("derived state replacement carrier %s describes another transaction", name),
				errDerivedStateReplacementRecoveryRequired,
			)
		}
	}
	if authoritative.Phase == derivedStateReplacementCommittedPhase {
		if err := syncDerivedStateReplacementParent(
			directory,
			mutationGuard,
			recoverUnexpectedMutation,
			"committed-observed",
		); err != nil {
			return derivedStateReplacementRecoveryRequired, errors.Join(err, errDerivedStateReplacementRecoveryRequired)
		}
		observed, _, _, err := readDerivedStateReplacementCarrier(parent, authoritativeName)
		if err != nil || observed.Phase != derivedStateReplacementCommittedPhase ||
			!sameDerivedStateReplacementTransaction(authoritative, observed) {
			return derivedStateReplacementRecoveryRequired, errors.Join(
				err,
				errors.New("derived state committed intent changed across its observed barrier"),
				errDerivedStateReplacementRecoveryRequired,
			)
		}
		authoritative = observed
	}
	var outcome derivedStateReplacementOutcome
	var replayErr error
	switch authoritative.Phase {
	case derivedStateReplacementPrepared:
		outcome, replayErr = replayPreparedDerivedStateReplacement(parent, directory, authoritative, mutationGuard, recoverUnexpectedMutation)
	case derivedStateReplacementCommittedPhase:
		outcome, replayErr = replayCommittedDerivedStateReplacement(parent, directory, authoritative, mutationGuard, recoverUnexpectedMutation)
	default:
		return derivedStateReplacementRecoveryRequired, errors.Join(
			errors.New("derived state replacement carrier has an unknown phase"),
			errDerivedStateReplacementRecoveryRequired,
		)
	}
	if proofErr := proveDerivedStateReplacementOutcome(parent, authoritative, outcome, recoverUnexpectedMutation); proofErr != nil {
		return derivedStateReplacementRecoveryRequired, errors.Join(replayErr, proofErr, errDerivedStateReplacementRecoveryRequired)
	}
	if replayErr != nil {
		return outcome, replayErr
	}
	for _, name := range []string{set.staged, set.next, set.main} {
		if name == "" {
			continue
		}
		removeErr := removeDerivedStateReplacementCarrier(
			parent,
			directory,
			name,
			name+".remove",
			mutationGuard,
			recoverUnexpectedMutation,
			"replacement-intent-cleanup",
		)
		proofErr := proveDerivedStateReplacementOutcome(parent, authoritative, outcome, recoverUnexpectedMutation)
		if proofErr != nil {
			return derivedStateReplacementRecoveryRequired, errors.Join(removeErr, proofErr, errDerivedStateReplacementRecoveryRequired)
		}
		if removeErr != nil {
			return outcome, removeErr
		}
	}
	return outcome, nil
}

func recoverBoundDerivedStateReplacementTransactions(
	parent *os.Root,
	directory *os.File,
	mutationGuard *derivedStateDirectoryMutationGuard,
	recoverUnexpectedMutation func() error,
) error {
	if parent == nil || directory == nil || mutationGuard == nil || recoverUnexpectedMutation == nil {
		return errors.New("derived state replacement recovery binding is invalid")
	}
	sets, err := listDerivedStateReplacementCarrierSets(directory)
	if err != nil {
		return err
	}
	for _, set := range sets {
		if _, err := recoverOneDerivedStateReplacementTransaction(parent, directory, set, mutationGuard, recoverUnexpectedMutation); err != nil {
			return fmt.Errorf("recover derived state replacement %s: %w", set.transactionID, err)
		}
	}
	return nil
}

func recoverBoundDerivedStateReplacementTransaction(
	parent *os.Root,
	directory *os.File,
	transactionID string,
	mutationGuard *derivedStateDirectoryMutationGuard,
	recoverUnexpectedMutation func() error,
) (derivedStateReplacementOutcome, error) {
	sets, err := listDerivedStateReplacementCarrierSets(directory)
	if err != nil {
		return derivedStateReplacementRecoveryRequired, err
	}
	for _, set := range sets {
		if set.transactionID == transactionID {
			return recoverOneDerivedStateReplacementTransaction(parent, directory, set, mutationGuard, recoverUnexpectedMutation)
		}
	}
	return derivedStateReplacementRecoveryRequired, errors.Join(
		fmt.Errorf("derived state replacement %s lost its durable intent", transactionID),
		errDerivedStateReplacementRecoveryRequired,
	)
}

func recoverDerivedStateReplacementTransactions(stateRoot, directoryRelative string, recover bool) error {
	if directoryRelative == "" {
		directoryRelative = "."
	}
	if filepath.IsAbs(directoryRelative) || filepath.Clean(directoryRelative) != directoryRelative ||
		strings.HasPrefix(directoryRelative, ".."+string(filepath.Separator)) {
		return errors.New("unsafe derived state replacement recovery directory")
	}
	absoluteRoot, err := filepath.Abs(stateRoot)
	if err != nil {
		return err
	}
	rootBefore, err := os.Lstat(absoluteRoot)
	if err != nil || rootBefore == nil || rootBefore.Mode()&os.ModeSymlink != 0 || !rootBefore.IsDir() {
		return errors.Join(err, errors.New("derived state root is not a real directory"))
	}
	root, err := os.OpenRoot(absoluteRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	rootIdentity, err := root.Stat(".")
	if err != nil || rootIdentity == nil || !os.SameFile(rootBefore, rootIdentity) {
		return errors.Join(err, errors.New("derived state root changed while binding replacement recovery"))
	}
	directoryBefore, err := root.Lstat(directoryRelative)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || directoryBefore == nil || directoryBefore.Mode()&os.ModeSymlink != 0 || !directoryBefore.IsDir() {
		return errors.Join(err, errors.New("derived state replacement recovery directory is not real"))
	}
	unlock := lockDerivedStateDirectoryWriter(filepath.Join(absoluteRoot, directoryRelative))
	defer unlock()
	parent, err := root.OpenRoot(directoryRelative)
	if err != nil {
		return err
	}
	defer parent.Close()
	directory, err := parent.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	directoryIdentity, statErr := directory.Stat()
	directoryCurrent, currentErr := root.Lstat(directoryRelative)
	if statErr != nil || currentErr != nil || directoryIdentity == nil || directoryCurrent == nil ||
		!os.SameFile(directoryBefore, directoryIdentity) || !os.SameFile(directoryBefore, directoryCurrent) ||
		directoryIdentity.Mode() != directoryBefore.Mode() || directoryCurrent.Mode() != directoryBefore.Mode() {
		return errors.Join(statErr, currentErr, errors.New("derived state replacement recovery directory changed while binding"))
	}
	mutationGuard, err := newDerivedStateDirectoryMutationGuard(root, directory, absoluteRoot, directoryRelative, directoryIdentity)
	if err != nil {
		return err
	}
	recoverUnexpectedMutation := func() error {
		if err := verifyBoundDerivedStateRoot(root, absoluteRoot, rootIdentity); err != nil {
			return err
		}
		return mutationGuard.recoverUnexpectedMutation(root, parent, directory, absoluteRoot, rootIdentity)
	}
	if err := recoverUnexpectedMutation(); err != nil {
		return err
	}
	sets, err := listDerivedStateReplacementCarrierSets(directory)
	if err != nil {
		return err
	}
	if len(sets) != 0 && !recover {
		return errors.New("interrupted derived state replacement requires --recover")
	}
	return recoverBoundDerivedStateReplacementTransactions(parent, directory, mutationGuard, recoverUnexpectedMutation)
}

func installExactDerivedStateTemporaryOutcome(
	parent *os.Root,
	directory, file *os.File,
	expected os.FileInfo,
	expectedDigest [sha256.Size]byte,
	source, destination string,
	mutationGuard *derivedStateDirectoryMutationGuard,
	recoverUnexpectedMutation func() error,
) (derivedStateReplacementResult, error) {
	result := derivedStateReplacementResult{Outcome: derivedStateReplacementNotCommitted}
	if parent == nil || directory == nil || file == nil || expected == nil || mutationGuard == nil || recoverUnexpectedMutation == nil ||
		filepath.Base(source) != source || filepath.Base(destination) != destination || source == destination || source == "" || destination == "" {
		return result, errors.New("derived state install binding is invalid")
	}
	transactionID, err := state.NewTransactionID()
	if err != nil {
		return result, err
	}
	result.TransactionID = transactionID
	isolation := derivedStateReplacementIsolationName(transactionID)
	candidateTrash := isolation + ".remove"
	sourceTrash := derivedStateReplacementSourceTrashName(transactionID)
	candidateIdentity, err := replacementIdentityFromFile(file, expected, &expectedDigest)
	if err != nil {
		return result, err
	}
	result.DestinationIdentity = candidateIdentity
	if err := recoverUnexpectedMutation(); err != nil {
		return result, err
	}
	if err := verifyDerivedStateReplacementCoordinate(parent, source, candidateIdentity); err != nil {
		return result, err
	}

	intent := derivedStateReplacementIntent{
		Schema:         derivedStateReplacementIntentSchema,
		TransactionID:  transactionID,
		Phase:          derivedStateReplacementPrepared,
		Destination:    destination,
		Source:         source,
		SourceTrash:    sourceTrash,
		Candidate:      isolation,
		CandidateTrash: candidateTrash,
		CandidateID:    candidateIdentity,
	}
	var priorFile *os.File
	var priorInfo os.FileInfo
	destinationBefore, destinationErr := parent.Lstat(destination)
	switch {
	case errors.Is(destinationErr, os.ErrNotExist):
	case destinationErr != nil:
		return result, destinationErr
	case destinationBefore == nil || destinationBefore.Mode()&os.ModeSymlink != 0 || !destinationBefore.Mode().IsRegular():
		return result, errors.New("derived state destination is not a regular file")
	default:
		var priorIdentity derivedStateReplacementIdentity
		priorFile, priorInfo, priorIdentity, err = bindDerivedStateReplacementObject(parent, destination)
		if err != nil {
			return result, err
		}
		intent.PriorPresent = true
		intent.PriorID = priorIdentity
	}
	closePrior := func() error {
		if priorFile == nil {
			return nil
		}
		err := priorFile.Close()
		priorFile = nil
		return err
	}
	defer closePrior()

	if err := publishPreparedDerivedStateReplacementIntent(parent, directory, intent, mutationGuard, recoverUnexpectedMutation); err != nil {
		if errors.Is(err, errDerivedStateReplacementTestCrash) {
			result.Outcome = derivedStateReplacementRecoveryRequired
			return result, errors.Join(err, errDerivedStateReplacementRecoveryRequired)
		}
		if _, statErr := parent.Lstat(derivedStateReplacementIntentName(transactionID)); statErr == nil {
			outcome, replayErr := recoverBoundDerivedStateReplacementTransaction(parent, directory, transactionID, mutationGuard, recoverUnexpectedMutation)
			result.Outcome = outcome
			return result, errors.Join(err, replayErr)
		}
		if _, statErr := parent.Lstat(derivedStateReplacementIntentName(transactionID) + ".new"); statErr == nil {
			outcome, replayErr := recoverBoundDerivedStateReplacementTransaction(parent, directory, transactionID, mutationGuard, recoverUnexpectedMutation)
			result.Outcome = outcome
			return result, errors.Join(err, replayErr)
		}
		return result, err
	}
	compensatePrepared := func(cause error) (derivedStateReplacementResult, error) {
		if errors.Is(cause, errDerivedStateReplacementTestCrash) {
			result.Outcome = derivedStateReplacementRecoveryRequired
			return result, errors.Join(cause, errDerivedStateReplacementRecoveryRequired)
		}
		outcome, replayErr := recoverBoundDerivedStateReplacementTransaction(parent, directory, transactionID, mutationGuard, recoverUnexpectedMutation)
		result.Outcome = outcome
		return result, errors.Join(cause, replayErr)
	}
	if err := renameYUMCompatibilityCandidateNoReplace(directory.Fd(), source, isolation); err != nil {
		return compensatePrepared(err)
	}
	if err := mutationGuard.admitKnownMutation(); err != nil {
		return compensatePrepared(err)
	}
	if err := syncDerivedStateReplacementParent(directory, mutationGuard, recoverUnexpectedMutation, "candidate-isolated"); err != nil {
		return compensatePrepared(err)
	}
	isolatedState, isolatedErr := classifyDerivedStateReplacementIdentity(parent, isolation, candidateIdentity, nil)
	if isolatedErr != nil || isolatedState != "candidate" {
		return compensatePrepared(errors.Join(isolatedErr, errors.New("derived state candidate changed after isolation")))
	}
	if err := verifyHeldDerivedStateReplacementObject(file, expected, candidateIdentity); err != nil {
		return compensatePrepared(err)
	}
	if priorFile != nil {
		if err := verifyHeldDerivedStateReplacementObject(priorFile, priorInfo, intent.PriorID); err != nil {
			return compensatePrepared(err)
		}
	}
	if derivedStateAfterVerifyHook != nil {
		if err := derivedStateAfterVerifyHook(isolation); err != nil {
			return compensatePrepared(err)
		}
	}
	if err := recoverUnexpectedMutation(); err != nil {
		return compensatePrepared(err)
	}
	destinationState, destinationStateErr := classifyDerivedStateReplacementIdentity(parent, destination, candidateIdentity, func() *derivedStateReplacementIdentity {
		if intent.PriorPresent {
			return &intent.PriorID
		}
		return nil
	}())
	isolationState, isolationStateErr := classifyDerivedStateReplacementIdentity(parent, isolation, candidateIdentity, func() *derivedStateReplacementIdentity {
		if intent.PriorPresent {
			return &intent.PriorID
		}
		return nil
	}())
	if destinationStateErr != nil || isolationStateErr != nil ||
		(intent.PriorPresent && (destinationState != "prior" || isolationState != "candidate")) ||
		(!intent.PriorPresent && (destinationState != "absent" || isolationState != "candidate")) {
		return compensatePrepared(errors.Join(destinationStateErr, isolationStateErr, errors.New("derived state replacement inputs changed before commit")))
	}
	if intent.PriorPresent {
		err = exchangeDerivedStateFiles(directory.Fd(), isolation, destination)
	} else {
		err = renameYUMCompatibilityCandidateNoReplace(directory.Fd(), isolation, destination)
	}
	if err != nil {
		return compensatePrepared(err)
	}
	if err := mutationGuard.admitKnownMutation(); err != nil {
		return compensatePrepared(err)
	}
	if err := syncDerivedStateReplacementParent(directory, mutationGuard, recoverUnexpectedMutation, "destination-mutated"); err != nil {
		return compensatePrepared(err)
	}
	if err := verifyDerivedStateReplacementCoordinate(parent, destination, candidateIdentity); err != nil {
		return compensatePrepared(err)
	}
	if intent.PriorPresent {
		if err := verifyDerivedStateReplacementCoordinate(parent, isolation, intent.PriorID); err != nil {
			return compensatePrepared(err)
		}
		if err := verifyHeldDerivedStateReplacementObject(priorFile, priorInfo, intent.PriorID); err != nil {
			return compensatePrepared(err)
		}
	} else if _, err := parent.Lstat(isolation); !errors.Is(err, os.ErrNotExist) {
		return compensatePrepared(errors.Join(err, errors.New("new derived state replacement retained an unexpected isolation coordinate")))
	}
	if err := verifyHeldDerivedStateReplacementObject(file, expected, candidateIdentity); err != nil {
		return compensatePrepared(err)
	}
	if err := publishCommittedDerivedStateReplacementIntent(parent, directory, intent, mutationGuard, recoverUnexpectedMutation); err != nil {
		if errors.Is(err, errDerivedStateReplacementTestCrash) {
			result.Outcome = derivedStateReplacementRecoveryRequired
			return result, errors.Join(err, errDerivedStateReplacementRecoveryRequired)
		}
		outcome, replayErr := recoverBoundDerivedStateReplacementTransaction(parent, directory, transactionID, mutationGuard, recoverUnexpectedMutation)
		result.Outcome = outcome
		return result, errors.Join(err, replayErr)
	}
	result.Outcome = derivedStateReplacementCommitted
	if err := errors.Join(file.Close(), closePrior()); err != nil {
		return result, err
	}
	return result, nil
}
