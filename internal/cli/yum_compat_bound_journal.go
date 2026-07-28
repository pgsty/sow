package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/state"
)

func yumCompatibilityCutoverJournalName(id string) (string, error) {
	if !validYUMCompatibilityEventID(id) {
		return "", errors.New("invalid YUM compatibility cutover journal ID")
	}
	return "yum-compatibility-cutover-" + id + ".journal.json", nil
}

func requireNoPendingYUMCompatibilityCutoverJournalsBound(workflow yumCompatibilityWorkflow, exceptID string) error {
	if workflow.root == nil || workflow.root.stateRoot == nil {
		return errors.New("bound state root is unavailable for cutover journal admission")
	}
	directory, err := workflow.root.stateRoot.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	prefix := "yum-compatibility-cutover-"
	allowed := prefix + exceptID + ".journal.json"
	allowedNext := allowed + ".next"
	var pending []string
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || (!strings.HasSuffix(name, ".journal.json") && !strings.HasSuffix(name, ".journal.json.next")) {
			continue
		}
		if exceptID != "" && (name == allowed || name == allowedNext) {
			continue
		}
		pending = append(pending, name)
	}
	sort.Strings(pending)
	if len(pending) != 0 {
		return fmt.Errorf("pending YUM compatibility cutover journal %s blocks this command; rerun the matching sow compatibility transition with its original --confirm token and --recover", pending[0])
	}
	return nil
}

func writeYUMCompatibilityCutoverJournalBound(workflow yumCompatibilityWorkflow, journal yumCompatibilityCutoverJournal, exclusive bool) (resultErr error) {
	if workflow.root == nil || workflow.root.stateRoot == nil {
		return errors.New("bound state root is unavailable for cutover journal write")
	}
	name, err := yumCompatibilityCutoverJournalName(journal.ID)
	if err != nil {
		return err
	}
	body, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if _, err := decodeYUMCompatibilityCutoverJournalBody(body, journal.ID); err != nil {
		return err
	}
	if err := requireYUMCompatibilityMutationBoundary(workflow, "admit bound cutover journal write"); err != nil {
		return err
	}
	if workflow.mutationHook != nil {
		if err := workflow.mutationHook("write-cutover-journal"); err != nil {
			return fmt.Errorf("YUM compatibility cutover journal mutation hook: %w", err)
		}
	}
	if exclusive {
		if _, err := workflow.root.stateRoot.Lstat(name); err == nil {
			return os.ErrExist
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		temporary, temporaryInfo, err := writeYUMCompatibilityBoundStateFile(workflow.root.stateRoot, "."+name+"-", body)
		if err != nil {
			return err
		}
		keep := true
		defer func() {
			if keep {
				resultErr = errors.Join(resultErr, removeExactYUMCompatibilityBoundControlFile(workflow.root.stateRoot, temporary, temporaryInfo))
			}
		}()
		if err := publishYUMCompatibilityBoundControlFileNoReplace(workflow.root.stateRoot, temporary, name, temporaryInfo); err != nil {
			return err
		}
		keep = false
	} else {
		current, exists, err := readYUMCompatibilityCutoverJournalBoundAt(workflow.root.stateRoot, name, journal.ID)
		if err != nil || !exists {
			return errors.Join(err, errors.New("prepared cutover journal disappeared before phase update"))
		}
		if current.Phase != yumCompatibilityCutoverPrepared || journal.Phase != yumCompatibilityCutoverCommitted || !sameYUMCompatibilityCutoverJournalIdentity(current, journal) {
			return errors.New("cutover journal phase update does not extend the exact prepared event")
		}
		pending := name + ".next"
		if _, err := workflow.root.stateRoot.Lstat(pending); err == nil {
			return errPartialYUMCompatibilityCutoverJournalNext
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		temporary, temporaryInfo, err := writeYUMCompatibilityBoundStateFile(workflow.root.stateRoot, "."+pending+"-", body)
		if err != nil {
			return err
		}
		pendingCleanupIdentity := temporaryInfo
		keep := true
		defer func() {
			if keep {
				resultErr = errors.Join(
					resultErr,
					removeExactYUMCompatibilityBoundControlFile(workflow.root.stateRoot, temporary, temporaryInfo),
					removeExactYUMCompatibilityBoundControlFile(workflow.root.stateRoot, pending, pendingCleanupIdentity),
				)
			}
		}()
		if err := publishYUMCompatibilityBoundControlFileNoReplace(workflow.root.stateRoot, temporary, pending, temporaryInfo); err != nil {
			return err
		}
		pendingInfo, pendingErr := workflow.root.stateRoot.Lstat(pending)
		if pendingErr != nil || pendingInfo == nil ||
			!os.SameFile(temporaryInfo, pendingInfo) ||
			!sameDerivedStateControlFileSecurity(temporaryInfo, pendingInfo) {
			return errors.Join(pendingErr, errors.New("cutover journal pending phase changed before replacement"))
		}
		directory, err := workflow.root.stateRoot.Open(".")
		if err != nil {
			return err
		}
		exchange, exchangeErr := exchangeBoundDerivedStateControlFiles(
			workflow.root.stateRoot,
			directory,
			pending,
			temporaryInfo,
			name,
			maximumYUMCompatibilityWitnessBytes,
			func(observed []byte) error {
				prepared, err := decodeYUMCompatibilityCutoverJournalBody(observed, journal.ID)
				if err != nil || prepared != current {
					return errors.Join(err, errors.New("prepared cutover journal changed before phase exchange"))
				}
				return nil
			},
		)
		closeErr := directory.Close()
		if exchange.Exchanged && exchange.Displaced != nil {
			pendingCleanupIdentity = exchange.Displaced
			if exchangeErr != nil || closeErr != nil {
				// The namespace already advanced. Preserve the complete
				// committed/prepared pair for deterministic recovery.
				keep = false
			}
		}
		if exchangeErr != nil || closeErr != nil {
			return errors.Join(exchangeErr, closeErr, errPartialYUMCompatibilityCutoverJournalNext)
		}
		if err := removeExactYUMCompatibilityBoundControlFile(
			workflow.root.stateRoot,
			pending,
			pendingCleanupIdentity,
		); err != nil {
			return err
		}
		keep = false
	}
	if err := syncYUMCompatibilityRootDirectory(workflow.root.stateRoot); err != nil {
		return err
	}
	observed, exists, err := readYUMCompatibilityCutoverJournalBoundAt(workflow.root.stateRoot, name, journal.ID)
	if err != nil || !exists || observed != journal {
		return errors.Join(err, errors.New("bound cutover journal read-back differs after write"))
	}
	return requireYUMCompatibilityMutationBoundary(workflow, "finish bound cutover journal write")
}

func writeYUMCompatibilityBoundStateFile(root *os.Root, prefix string, body []byte) (string, os.FileInfo, error) {
	nonce, err := randomYUMCompatibilityBoundNonce()
	if err != nil {
		return "", nil, err
	}
	name := prefix + nonce
	info, err := writeYUMCompatibilityBoundControlFile(root, name, body)
	return name, info, err
}

func writeYUMCompatibilityBoundControlFile(root *os.Root, name string, body []byte) (os.FileInfo, error) {
	if root == nil || !validYUMCompatibilityTreeSegment(name) || len(body) == 0 ||
		len(body) > maximumYUMCompatibilityWitnessBytes {
		return nil, errors.New("bound YUM compatibility control-file write capability is invalid")
	}
	file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	created, statErr := file.Stat()
	if statErr != nil || created == nil || created.Mode().Perm() != 0o600 {
		closeErr := file.Close()
		return nil, errors.Join(statErr, closeErr, errors.New("bound state temporary was unsafe at creation"))
	}
	if derivedStateControlBeforeWriteHook != nil {
		if err := derivedStateControlBeforeWriteHook("yum-bound", name); err != nil {
			closeErr := file.Close()
			return nil, errors.Join(err, closeErr)
		}
	}
	if _, err := verifyBoundDerivedStateControlFile(
		root,
		name,
		file,
		created,
		"bound YUM compatibility journal before write",
	); err != nil {
		closeErr := file.Close()
		return nil, errors.Join(err, closeErr)
	}
	_, writeErr := file.Write(body)
	syncErr := file.Sync()
	info, statErr := file.Stat()
	closeErr := file.Close()
	current, lstatErr := root.Lstat(name)
	var infoAdmissionErr, currentAdmissionErr error
	if info != nil {
		_, infoAdmissionErr = admitDerivedStateControlFile(info, "bound YUM compatibility journal temporary")
	}
	if current != nil {
		_, currentAdmissionErr = admitDerivedStateControlFile(current, "current bound YUM compatibility journal temporary")
	}
	if writeErr != nil || syncErr != nil || statErr != nil || closeErr != nil || lstatErr != nil ||
		infoAdmissionErr != nil || currentAdmissionErr != nil || info == nil || current == nil ||
		info.Mode().Perm() != 0o600 || current.Mode().Perm() != 0o600 ||
		!os.SameFile(info, current) || !sameDerivedStateControlFileSecurity(info, current) {
		if info != nil {
			_ = removeExactYUMCompatibilityBoundControlFile(root, name, info)
		}
		return nil, errors.Join(writeErr, syncErr, statErr, closeErr, lstatErr, infoAdmissionErr, currentAdmissionErr, errors.New("bound state temporary changed while writing"))
	}
	return info, nil
}

func publishYUMCompatibilityBoundControlFileNoReplace(root *os.Root, source, destination string, expected os.FileInfo) error {
	if root == nil || expected == nil || !validYUMCompatibilityTreeSegment(source) || !validYUMCompatibilityTreeSegment(destination) {
		return errors.New("bound YUM compatibility control-file publication capability is invalid")
	}
	sourceInfo, err := root.Lstat(source)
	if err != nil || sourceInfo == nil || !os.SameFile(expected, sourceInfo) ||
		!sameDerivedStateControlFileSecurity(expected, sourceInfo) {
		return errors.Join(err, errors.New("bound YUM compatibility control-file source changed before publication"))
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := renameYUMCompatibilityCandidateNoReplace(directory.Fd(), source, destination); err != nil {
		return err
	}
	installed, installedErr := root.Lstat(destination)
	_, sourceErr := root.Lstat(source)
	if installedErr != nil || !errors.Is(sourceErr, os.ErrNotExist) || installed == nil ||
		!os.SameFile(expected, installed) ||
		!sameDerivedStateControlFileSecurity(expected, installed) {
		return errors.Join(installedErr, sourceErr, errors.New("bound YUM compatibility control-file publication changed its identity"))
	}
	return directory.Sync()
}

func removeExactYUMCompatibilityBoundFile(root *os.Root, name string, expected os.FileInfo) error {
	if root == nil || expected == nil || !validYUMCompatibilityTreeSegment(name) {
		return errors.New("exact bound temporary cleanup capability is unavailable")
	}
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !os.SameFile(expected, info) {
		return errors.Join(err, fmt.Errorf("bound temporary %s was replaced; refuse cleanup", name))
	}
	file, err := root.Open(name)
	if err != nil {
		return err
	}
	opened, statErr := file.Stat()
	closeErr := file.Close()
	current, lstatErr := root.Lstat(name)
	if statErr != nil || closeErr != nil || lstatErr != nil || !os.SameFile(expected, opened) || !os.SameFile(expected, current) {
		return errors.Join(statErr, closeErr, lstatErr, fmt.Errorf("bound temporary %s changed before cleanup", name))
	}
	if err := root.Remove(name); err != nil {
		return err
	}
	return syncYUMCompatibilityRootDirectory(root)
}

func removeExactYUMCompatibilityBoundControlFile(root *os.Root, name string, expected os.FileInfo) error {
	if root == nil || expected == nil || !validYUMCompatibilityTreeSegment(name) {
		return errors.New("exact bound control-file cleanup capability is unavailable")
	}
	if _, err := admitDerivedStateControlFile(expected, "expected bound YUM compatibility control file"); err != nil {
		return err
	}
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info == nil || !os.SameFile(expected, info) ||
		!sameDerivedStateControlFileSecurity(expected, info) {
		return errors.Join(err, fmt.Errorf("bound control file %s was replaced or aliased; preserve it for audit", name))
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, statErr := file.Stat()
	current, lstatErr := root.Lstat(name)
	if statErr != nil || lstatErr != nil || opened == nil || current == nil ||
		!os.SameFile(expected, opened) || !os.SameFile(expected, current) ||
		!sameDerivedStateControlFileSecurity(expected, opened) ||
		!sameDerivedStateControlFileSecurity(expected, current) {
		return errors.Join(statErr, lstatErr, fmt.Errorf("bound control file %s changed before cleanup", name))
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return commitExactPrivateStateFileRemoval(root, directory, file, expected, name, func() error {
		after, statErr := file.Stat()
		if statErr != nil || after == nil || !os.SameFile(expected, after) ||
			!sameDerivedStateControlFileSecurity(expected, after) {
			return errors.Join(statErr, fmt.Errorf("bound control file %s changed during cleanup", name))
		}
		return nil
	})
}

func readYUMCompatibilityCutoverJournalBoundAt(root *os.Root, name, id string) (yumCompatibilityCutoverJournal, bool, error) {
	var result yumCompatibilityCutoverJournal
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return result, false, nil
	}
	if err != nil || info == nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > maximumYUMCompatibilityWitnessBytes {
		return result, false, errors.Join(err, fmt.Errorf("%w: cutover journal is not a bounded regular file", errPartialYUMCompatibilityCutoverJournalEncoding))
	}
	if _, err := admitDerivedStateControlFile(info, "bound YUM compatibility cutover journal"); err != nil {
		return result, false, fmt.Errorf("%w: %v", errPartialYUMCompatibilityCutoverJournalEncoding, err)
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return result, false, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || opened == nil || !os.SameFile(info, opened) ||
		!sameDerivedStateControlFileSecurity(info, opened) {
		return result, false, errors.Join(statErr, file.Close(), fmt.Errorf("%w: cutover journal changed while opening", errPartialYUMCompatibilityCutoverJournalEncoding))
	}
	body, readErr := io.ReadAll(io.LimitReader(file, maximumYUMCompatibilityWitnessBytes+1))
	after, restatErr := file.Stat()
	closeErr := file.Close()
	current, lstatErr := root.Lstat(name)
	if readErr != nil || restatErr != nil || closeErr != nil || lstatErr != nil || len(body) > maximumYUMCompatibilityWitnessBytes ||
		after == nil || current == nil ||
		!os.SameFile(opened, after) || !os.SameFile(opened, current) ||
		!sameDerivedStateControlFileSecurity(info, after) ||
		!sameDerivedStateControlFileSecurity(info, current) ||
		int64(len(body)) != opened.Size() {
		return result, false, errors.Join(readErr, restatErr, closeErr, lstatErr, fmt.Errorf("%w: cutover journal changed while reading", errPartialYUMCompatibilityCutoverJournalEncoding))
	}
	result, err = decodeYUMCompatibilityCutoverJournalBody(body, id)
	return result, true, err
}

func readYUMCompatibilityCutoverJournalPairBound(workflow yumCompatibilityWorkflow, id string, recover bool) (yumCompatibilityCutoverJournalPair, error) {
	var pair yumCompatibilityCutoverJournalPair
	if workflow.root == nil || workflow.root.stateRoot == nil {
		return pair, errors.New("bound state root is unavailable for cutover journal read")
	}
	base, err := yumCompatibilityCutoverJournalName(id)
	if err != nil {
		return pair, err
	}
	next := base + ".next"
	nextInfo, nextErr := workflow.root.stateRoot.Lstat(next)
	if nextErr == nil {
		if _, admissionErr := admitDerivedStateControlFile(nextInfo, "pending bound YUM compatibility cutover journal"); admissionErr != nil {
			return pair, admissionErr
		}
		if !recover {
			return pair, fmt.Errorf("incomplete cutover journal phase update exists at %s; rerun the same compatibility command with --recover", next)
		}
		if nextInfo.Mode()&os.ModeSymlink != 0 || !nextInfo.Mode().IsRegular() {
			return pair, errors.New("cutover journal pending phase update is not a regular file")
		}
	} else if !errors.Is(nextErr, os.ErrNotExist) {
		return pair, nextErr
	}
	pair.Main, pair.MainExists, err = readYUMCompatibilityCutoverJournalBoundAt(workflow.root.stateRoot, base, id)
	if err != nil {
		return pair, err
	}
	pair.Next, pair.NextExists, err = readYUMCompatibilityCutoverJournalBoundAt(workflow.root.stateRoot, next, id)
	if err != nil {
		if errors.Is(err, errPartialYUMCompatibilityCutoverJournalEncoding) {
			return pair, fmt.Errorf("%w: %v", errPartialYUMCompatibilityCutoverJournalNext, err)
		}
		return pair, fmt.Errorf("cutover journal pending phase update conflicts with the durable transaction: %w", err)
	}
	if !pair.NextExists || !pair.MainExists {
		return pair, nil
	}
	mainInfo, mainErr := workflow.root.stateRoot.Lstat(base)
	nextInfo, nextErr = workflow.root.stateRoot.Lstat(next)
	if mainErr != nil || nextErr != nil || mainInfo.Mode()&os.ModeSymlink != 0 || !mainInfo.Mode().IsRegular() || nextInfo.Mode()&os.ModeSymlink != 0 || !nextInfo.Mode().IsRegular() {
		return pair, errors.Join(mainErr, nextErr, errors.New("cutover journal pair is not two safe regular files"))
	}
	if os.SameFile(mainInfo, nextInfo) {
		return pair, errors.New("cutover journal pair is hardlink-aliased; preserve both names for operator audit")
	}
	forwardPair := pair.Main.Phase == yumCompatibilityCutoverPrepared &&
		pair.Next.Phase == yumCompatibilityCutoverCommitted
	exchangedPair := pair.Main.Phase == yumCompatibilityCutoverCommitted &&
		pair.Next.Phase == yumCompatibilityCutoverPrepared
	if (!forwardPair && !exchangedPair) ||
		!sameYUMCompatibilityCutoverJournalIdentity(pair.Main, pair.Next) {
		return pair, errors.New("cutover journal pending phase update differs from the exact prepared event")
	}
	return pair, nil
}

func removeYUMCompatibilityCutoverJournalBound(workflow yumCompatibilityWorkflow, id string) error {
	name, err := yumCompatibilityCutoverJournalName(id)
	if err != nil {
		return err
	}
	for _, target := range []string{name, name + ".next"} {
		info, statErr := workflow.root.stateRoot.Lstat(target)
		if errors.Is(statErr, os.ErrNotExist) {
			continue
		}
		if statErr != nil {
			return statErr
		}
		if err := removeExactYUMCompatibilityBoundControlFile(workflow.root.stateRoot, target, info); err != nil {
			return err
		}
	}
	if err := syncYUMCompatibilityRootDirectory(workflow.root.stateRoot); err != nil {
		return err
	}
	return requireYUMCompatibilityMutationBoundary(workflow, "finish bound cutover journal removal")
}

func removeYUMCompatibilityCutoverNextBound(workflow yumCompatibilityWorkflow, id string) error {
	name, err := yumCompatibilityCutoverJournalName(id)
	if err != nil {
		return err
	}
	target := name + ".next"
	info, statErr := workflow.root.stateRoot.Lstat(target)
	if errors.Is(statErr, os.ErrNotExist) {
		return syncYUMCompatibilityRootDirectory(workflow.root.stateRoot)
	}
	if statErr != nil {
		return statErr
	}
	if err := removeExactYUMCompatibilityBoundControlFile(workflow.root.stateRoot, target, info); err != nil {
		return err
	}
	return syncYUMCompatibilityRootDirectory(workflow.root.stateRoot)
}

func recoverYUMCompatibilityCutoverJournalBound(workflow yumCompatibilityWorkflow, canonical *state.Store, id string, recover bool) error {
	pair, err := readYUMCompatibilityCutoverJournalPairBound(workflow, id, recover)
	if errors.Is(err, errPartialYUMCompatibilityCutoverJournalNext) && recover {
		return recoverPartialYUMCompatibilityCutoverNextBound(workflow, canonical, id, pair)
	}
	if err != nil {
		return err
	}
	if !pair.MainExists && pair.NextExists {
		return recoverOrphanYUMCompatibilityCutoverNextBound(workflow, canonical, id, pair.Next)
	}
	if !pair.MainExists {
		return nil
	}
	journal := pair.Main
	if !recover {
		return fmt.Errorf("incomplete cutover transaction exists at %s; rerun with --recover", journal.ID)
	}
	stateAtHead, stateErr := loadYUMCompatibilityCutoverStateAt(canonical, plumbing.ZeroHash, id)
	committed := stateErr == nil && len(stateAtHead.Events) != 0 && stateAtHead.Last.EventSHA256 == journal.EventSHA256
	if stateErr != nil {
		return stateErr
	}
	if pair.NextExists && !committed {
		return errors.New("committed cutover journal phase update has no exact canonical event")
	}
	if journal.Phase == yumCompatibilityCutoverCommitted && !committed {
		return errors.New("cutover journal claims a committed event that is absent from canonical state")
	}
	if committed {
		eventJournal, err := physicalYUMCompatibilityCutoverJournal(workflow.cfg, stateAtHead.Last)
		if err != nil || eventJournal.ServingLink != journal.ServingLink || eventJournal.FromTarget != journal.FromTarget || eventJournal.ToTarget != journal.ToTarget || eventJournal.Action != journal.Action {
			return errors.Join(err, errors.New("cutover crash journal differs from canonical event"))
		}
		if err := reconcileYUMCompatibilityServingLinkBound(workflow, journal); err != nil {
			return err
		}
	}
	return removeYUMCompatibilityCutoverJournalBound(workflow, id)
}

func recoverPartialYUMCompatibilityCutoverNextBound(workflow yumCompatibilityWorkflow, canonical *state.Store, id string, pair yumCompatibilityCutoverJournalPair) error {
	stateAtHead, err := loadYUMCompatibilityCutoverStateAt(canonical, plumbing.ZeroHash, id)
	if err != nil {
		return err
	}
	if pair.MainExists {
		expected, exact, err := exactYUMCompatibilityJournalForCanonicalLast(workflow.cfg, stateAtHead, pair.Main)
		if err != nil || !exact {
			return errors.Join(err, errors.New("partial cutover journal update has no exact canonical event for its durable base"))
		}
		if err := removeYUMCompatibilityCutoverNextBound(workflow, id); err != nil {
			return err
		}
		if err := reconcileYUMCompatibilityServingLinkBound(workflow, expected); err != nil {
			return err
		}
		return removeYUMCompatibilityCutoverJournalBound(workflow, id)
	}
	if len(stateAtHead.Events) != 0 {
		expected, err := physicalYUMCompatibilityCutoverJournal(workflow.cfg, stateAtHead.Last)
		if err != nil {
			return err
		}
		if err := reconcileYUMCompatibilityServingLinkBound(workflow, expected); err != nil {
			return err
		}
	}
	return removeYUMCompatibilityCutoverJournalBound(workflow, id)
}

func recoverOrphanYUMCompatibilityCutoverNextBound(workflow yumCompatibilityWorkflow, canonical *state.Store, id string, next yumCompatibilityCutoverJournal) error {
	stateAtHead, err := loadYUMCompatibilityCutoverStateAt(canonical, plumbing.ZeroHash, id)
	if err != nil {
		return err
	}
	expected, exact, err := exactYUMCompatibilityJournalForCanonicalLast(workflow.cfg, stateAtHead, next)
	if err != nil {
		return err
	}
	if next.Phase == yumCompatibilityCutoverCommitted && !exact {
		return errors.New("orphan committed cutover journal has no exact canonical event")
	}
	if exact {
		if err := reconcileYUMCompatibilityServingLinkBound(workflow, expected); err != nil {
			return err
		}
	}
	return removeYUMCompatibilityCutoverJournalBound(workflow, id)
}
