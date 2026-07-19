package state

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	lockRecordSchemaV1      = 1
	lockIdentityObserved    = "observed"
	lockIdentityUnavailable = "unavailable"
	lockIDBytes             = 32
	maxLockRecordBytes      = 16 << 10

	stateLeaseFaultChmod         = "chmod"
	stateLeaseFaultIdentity      = "identity"
	stateLeaseFaultBeforePublish = "before-publish"
	stateLeaseFaultAfterPublish  = "after-publish"

	stateLockUnpublishedPrefix = "state.lock.unpublished-"

	statePermissionAfterChildLstat = "after-child-lstat"
	statePermissionBeforeRootChmod = "before-root-chmod"
)

type lockRecord struct {
	SchemaVersion   int              `json:"schema_version,omitempty"`
	PID             int              `json:"pid"`
	Operation       string           `json:"operation"`
	StartedAt       time.Time        `json:"started_at"`
	LockID          string           `json:"lock_id,omitempty"`
	IdentityStatus  string           `json:"identity_status,omitempty"`
	ProcessIdentity *processIdentity `json:"process_identity,omitempty"`
}

type Lock struct {
	mu            sync.Mutex
	path          string
	statePath     string
	stateRoot     *os.Root
	stateIdentity os.FileInfo
	locksRoot     *os.Root
	locksFile     *os.File
	locksIdentity os.FileInfo
	leaseIdentity os.FileInfo
	leaseFile     *os.File
	localLeaseID  uint64
	lockIdentity  os.FileInfo
	lockFile      *os.File
	localRecordID uint64
	lockRecord    lockRecord
}

var localStateLockLeases = struct {
	sync.Mutex
	next uint64
	held map[uint64]os.FileInfo
}{held: make(map[uint64]os.FileInfo)}

var errStateLockPublicationCollision = errors.New("state lock appeared during atomic publication")

var stateLockLeaseTrySource = struct {
	sync.RWMutex
	try func(*os.File) (bool, error)
}{try: tryStateLockLease}

var stateLockLeaseFaultSource = struct {
	sync.RWMutex
	fault func(string, string) error
}{}

var statePermissionFaultSource = struct {
	sync.RWMutex
	fault func(string, string) error
}{}

func callStateLockLeaseTry(file *os.File) (bool, error) {
	stateLockLeaseTrySource.RLock()
	try := stateLockLeaseTrySource.try
	stateLockLeaseTrySource.RUnlock()
	return try(file)
}

func replaceStateLockLeaseTry(try func(*os.File) (bool, error)) func() {
	stateLockLeaseTrySource.Lock()
	previous := stateLockLeaseTrySource.try
	stateLockLeaseTrySource.try = try
	stateLockLeaseTrySource.Unlock()
	return func() {
		stateLockLeaseTrySource.Lock()
		stateLockLeaseTrySource.try = previous
		stateLockLeaseTrySource.Unlock()
	}
}

func callStateLockLeaseFault(name, stage string) error {
	stateLockLeaseFaultSource.RLock()
	fault := stateLockLeaseFaultSource.fault
	stateLockLeaseFaultSource.RUnlock()
	if fault == nil {
		return nil
	}
	return fault(name, stage)
}

func replaceStateLockLeaseFault(fault func(string, string) error) func() {
	stateLockLeaseFaultSource.Lock()
	previous := stateLockLeaseFaultSource.fault
	stateLockLeaseFaultSource.fault = fault
	stateLockLeaseFaultSource.Unlock()
	return func() {
		stateLockLeaseFaultSource.Lock()
		stateLockLeaseFaultSource.fault = previous
		stateLockLeaseFaultSource.Unlock()
	}
}

func callStatePermissionFault(stage, name string) error {
	statePermissionFaultSource.RLock()
	fault := statePermissionFaultSource.fault
	statePermissionFaultSource.RUnlock()
	if fault == nil {
		return nil
	}
	return fault(stage, name)
}

func replaceStatePermissionFault(fault func(string, string) error) func() {
	statePermissionFaultSource.Lock()
	previous := statePermissionFaultSource.fault
	statePermissionFaultSource.fault = fault
	statePermissionFaultSource.Unlock()
	return func() {
		statePermissionFaultSource.Lock()
		statePermissionFaultSource.fault = previous
		statePermissionFaultSource.Unlock()
	}
}

// openAdvisoryLease serializes the open-to-flock window within this process
// and relies on flock for inter-process exclusion. The local registry is
// necessary on BSD-derived systems where flock ownership is process-scoped.
func openAdvisoryLease(root *os.Root, name string, flags int, mode os.FileMode) (*os.File, os.FileInfo, uint64, bool, error) {
	localStateLockLeases.Lock()
	defer localStateLockLeases.Unlock()
	createdEntry := flags&os.O_CREATE != 0 && flags&os.O_EXCL != 0
	file, err := root.OpenFile(name, flags, mode)
	if err != nil {
		return nil, nil, 0, false, err
	}
	opened, statErr := file.Stat()
	current, lstatErr := root.Lstat(name)
	if statErr != nil || lstatErr != nil || opened == nil || !opened.Mode().IsRegular() ||
		current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		closeErr := file.Close()
		return nil, nil, 0, false, errors.Join(statErr, lstatErr, closeErr, fmt.Errorf("state advisory lease %s changed while opening", name))
	}
	for _, held := range localStateLockLeases.held {
		if os.SameFile(held, opened) {
			return nil, nil, 0, false, file.Close()
		}
	}
	acquired, lockErr := callStateLockLeaseTry(file)
	if lockErr != nil {
		var cleanupErr error
		if createdEntry {
			cleanupErr = removeCreatedLeaseEntryAfterFailure(root, name, file, opened)
		}
		closeErr := file.Close()
		return nil, nil, 0, false, errors.Join(lockErr, cleanupErr, closeErr)
	}
	if !acquired {
		var cleanupErr error
		if createdEntry {
			cleanupErr = removeCreatedLeaseEntryAfterFailure(root, name, file, opened)
		}
		closeErr := file.Close()
		return nil, nil, 0, false, errors.Join(cleanupErr, closeErr)
	}
	failAfterAcquire := func(failure error) (*os.File, os.FileInfo, uint64, bool, error) {
		// A create-only lease entry belongs to this acquisition attempt. Remove it
		// while its advisory lease is still held, prove the path is still the same
		// inode, and fsync the directory before releasing the lease. Otherwise a
		// chmod or post-flock identity failure would strand private debris.
		var cleanupErr error
		if createdEntry {
			cleanupErr = removeCreatedLeaseEntryAfterFailure(root, name, file, opened)
		}
		unlockErr := releaseStateLockLease(file)
		closeErr := file.Close()
		return nil, nil, 0, false, errors.Join(failure, cleanupErr, unlockErr, closeErr)
	}
	// Never mutate a lease inode before proving exclusive ownership. This is
	// essential for compatibility with an older process that flocks only
	// state.lock: a blocked new contender must not chmod or otherwise touch the
	// live legacy record. The same ordering protects an active persistent lease.
	if mode != 0 {
		if faultErr := callStateLockLeaseFault(name, stateLeaseFaultChmod); faultErr != nil {
			return failAfterAcquire(faultErr)
		}
		if chmodErr := file.Chmod(mode.Perm()); chmodErr != nil {
			return failAfterAcquire(chmodErr)
		}
	}
	if faultErr := callStateLockLeaseFault(name, stateLeaseFaultIdentity); faultErr != nil {
		return failAfterAcquire(faultErr)
	}
	opened, statErr = file.Stat()
	current, lstatErr = root.Lstat(name)
	permissionsUnsafe := mode != 0 && opened != nil && opened.Mode().Perm() != mode.Perm()
	if statErr != nil || lstatErr != nil || opened == nil || !opened.Mode().IsRegular() || permissionsUnsafe ||
		current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return failAfterAcquire(errors.Join(statErr, lstatErr, fmt.Errorf("state advisory lease %s changed while securing permissions", name)))
	}
	localStateLockLeases.next++
	leaseID := localStateLockLeases.next
	localStateLockLeases.held[leaseID] = opened
	return file, opened, leaseID, true, nil
}

func removeCreatedLeaseEntryAfterFailure(root *os.Root, name string, file *os.File, identity os.FileInfo) error {
	if root == nil || filepath.Base(name) != name || name == "." || name == "" || file == nil || identity == nil {
		return errors.New("created state lease entry identity is unavailable after advisory lease failure")
	}
	opened, statErr := file.Stat()
	current, lstatErr := root.Lstat(name)
	if statErr != nil || lstatErr != nil || opened == nil || !opened.Mode().IsRegular() ||
		current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() ||
		!os.SameFile(identity, opened) || !os.SameFile(identity, current) {
		return errors.Join(statErr, lstatErr, errors.New("refusing to remove a created state lease entry whose inode changed after advisory lease failure"))
	}
	if err := root.Remove(name); err != nil {
		return err
	}
	return syncRootDirectory(root)
}

func syncRootDirectory(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func closeStateLockLease(file *os.File, leaseID uint64) error {
	if file == nil {
		return errors.New("state lock advisory lease file is unavailable")
	}
	unlockErr := releaseStateLockLease(file)
	closeErr := file.Close()
	localStateLockLeases.Lock()
	delete(localStateLockLeases.held, leaseID)
	localStateLockLeases.Unlock()
	return errors.Join(unlockErr, closeErr)
}

func removeLeasedStateLock(root *os.Root, directory *os.File, file *os.File, identity os.FileInfo) error {
	return removeLeasedStateEntry(root, directory, file, identity, "state.lock")
}

func removeLeasedStateEntry(root *os.Root, directory *os.File, file *os.File, identity os.FileInfo, name string) error {
	if root == nil || directory == nil || file == nil || identity == nil {
		return errors.New("state lock removal lease is incomplete")
	}
	if filepath.Base(name) != name || name == "." || name == "" {
		return errors.New("state lock removal name is unsafe")
	}
	opened, statErr := file.Stat()
	current, lstatErr := root.Lstat(name)
	if statErr != nil || lstatErr != nil || opened == nil || !opened.Mode().IsRegular() ||
		current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() ||
		!os.SameFile(identity, opened) || !os.SameFile(identity, current) {
		return errors.Join(statErr, lstatErr, errors.New("refusing to unlink a state lock outside the held advisory lease"))
	}
	if err := root.Remove(name); err != nil {
		return err
	}
	return directory.Sync()
}

// publishPreparedStateLock makes the visible record crash-atomic. The record is
// fully encoded and fsynced on a private inode while its advisory lease is
// already held. A create-only hardlink then publishes those exact bytes as
// state.lock in one namespace operation. A crash before the link leaves only
// non-authoritative evidence; a crash after it leaves a complete recoverable
// record, never a zero-byte or partially encoded authoritative lock.
func publishPreparedStateLock(root *os.Root, directory *os.File, record lockRecord) (*os.File, os.FileInfo, uint64, bool, error) {
	if root == nil || directory == nil {
		return nil, nil, 0, false, errors.New("state lock publication root is unavailable")
	}
	if _, err := record.kind(); err != nil {
		return nil, nil, 0, false, fmt.Errorf("validate prepared state lock record: %w", err)
	}
	pendingName := stateLockUnpublishedPrefix + record.LockID
	file, identity, leaseID, acquired, err := openAdvisoryLease(
		root, pendingName, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600,
	)
	if err != nil || !acquired {
		return nil, nil, 0, acquired, err
	}
	published := false
	fail := func(failure error) (*os.File, os.FileInfo, uint64, bool, error) {
		cleanupErr := removePreparedStateLockAttempt(root, directory, file, identity, pendingName, published)
		leaseErr := closeStateLockLease(file, leaseID)
		return nil, nil, 0, false, errors.Join(failure, cleanupErr, leaseErr)
	}
	if err := json.NewEncoder(file).Encode(record); err != nil {
		return fail(fmt.Errorf("encode prepared state lock: %w", err))
	}
	if err := file.Sync(); err != nil {
		return fail(fmt.Errorf("sync prepared state lock: %w", err))
	}
	prepared, statErr := file.Stat()
	current, lstatErr := root.Lstat(pendingName)
	if statErr != nil || lstatErr != nil || prepared == nil || current == nil ||
		!prepared.Mode().IsRegular() || prepared.Mode().Perm() != 0o600 ||
		current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || current.Mode().Perm() != 0o600 ||
		!os.SameFile(identity, prepared) || !os.SameFile(identity, current) {
		return fail(errors.Join(statErr, lstatErr, errors.New("prepared state lock changed before publication")))
	}
	if faultErr := callStateLockLeaseFault("state.lock", stateLeaseFaultBeforePublish); faultErr != nil {
		return fail(faultErr)
	}
	if err := root.Link(pendingName, "state.lock"); err != nil {
		if errors.Is(err, os.ErrExist) {
			cleanupErr := removePreparedStateLockAttempt(root, directory, file, identity, pendingName, false)
			leaseErr := closeStateLockLease(file, leaseID)
			if cleanupErr != nil || leaseErr != nil {
				return nil, nil, 0, false, fmt.Errorf("discard prepared state lock after publication collision: %w", errors.Join(cleanupErr, leaseErr))
			}
			return nil, nil, 0, false, errStateLockPublicationCollision
		}
		return fail(err)
	}
	published = true
	visible, visibleErr := root.Lstat("state.lock")
	current, lstatErr = root.Lstat(pendingName)
	if visibleErr != nil || lstatErr != nil || visible == nil || current == nil ||
		visible.Mode()&os.ModeSymlink != 0 || !visible.Mode().IsRegular() || visible.Mode().Perm() != 0o600 ||
		current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || current.Mode().Perm() != 0o600 ||
		!os.SameFile(identity, visible) || !os.SameFile(identity, current) {
		return fail(errors.Join(visibleErr, lstatErr, errors.New("published state lock does not match the prepared inode")))
	}
	observed, readErr := readLockFileAt(root, "state.lock", file, identity)
	if readErr != nil || !sameLockRecord(record, observed) {
		return fail(errors.Join(readErr, errors.New("published state lock bytes do not match the prepared record")))
	}
	if faultErr := callStateLockLeaseFault("state.lock", stateLeaseFaultAfterPublish); faultErr != nil {
		return fail(faultErr)
	}
	if err := removeLeasedStateEntry(root, directory, file, identity, pendingName); err != nil {
		return fail(fmt.Errorf("remove unpublished state lock name: %w", err))
	}
	return file, identity, leaseID, true, nil
}

func removePreparedStateLockAttempt(root *os.Root, directory *os.File, file *os.File, identity os.FileInfo, pendingName string, published bool) error {
	if root == nil || directory == nil || file == nil || identity == nil ||
		!strings.HasPrefix(pendingName, stateLockUnpublishedPrefix) || filepath.Base(pendingName) != pendingName {
		return errors.New("prepared state lock cleanup binding is incomplete")
	}
	var cleanupErr error
	removeExact := func(name string) {
		current, err := root.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		opened, statErr := file.Stat()
		if err != nil || statErr != nil || current == nil || opened == nil ||
			current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() ||
			!os.SameFile(identity, current) || !os.SameFile(identity, opened) {
			cleanupErr = errors.Join(cleanupErr, err, statErr, fmt.Errorf("refusing to remove prepared state lock name %s after its inode changed", name))
			return
		}
		if err := root.Remove(name); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if published {
		removeExact("state.lock")
	}
	removeExact(pendingName)
	return errors.Join(cleanupErr, directory.Sync())
}

func preserveLeasedStateLock(root *os.Root, directory *os.File, file *os.File, identity os.FileInfo, staleName string) error {
	if root == nil || directory == nil || file == nil || identity == nil || filepath.Base(staleName) != staleName || staleName == "" {
		return errors.New("stale state lock preservation lease is incomplete")
	}
	opened, statErr := file.Stat()
	current, lstatErr := root.Lstat("state.lock")
	if statErr != nil || lstatErr != nil || opened == nil || !opened.Mode().IsRegular() ||
		current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() ||
		!os.SameFile(identity, opened) || !os.SameFile(identity, current) {
		return errors.Join(statErr, lstatErr, errors.New("refusing to preserve a state lock outside the held advisory lease"))
	}
	// Link is create-only and cannot overwrite prior recovery evidence. The
	// source remains the visible leased lock until the evidence link exists.
	if err := root.Link("state.lock", staleName); err != nil {
		return err
	}
	stale, staleErr := root.Lstat(staleName)
	if staleErr != nil || stale.Mode()&os.ModeSymlink != 0 || !stale.Mode().IsRegular() || !os.SameFile(identity, stale) {
		return errors.Join(staleErr, errors.New("preserved stale state lock does not match the leased inode"))
	}
	return removeLeasedStateLock(root, directory, file, identity)
}

func bootstrapStateLockRoot(stateDir string) (string, error) {
	statePath, err := filepath.Abs(filepath.Clean(stateDir))
	if err != nil {
		return "", err
	}
	parent := filepath.Dir(statePath)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return "", errors.Join(err, errors.New("state parent is not a real directory"))
	}
	stateInfo, err := os.Lstat(statePath)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(statePath, 0o700); err != nil {
			return "", err
		}
		stateInfo, err = os.Lstat(statePath)
		if err != nil || !stateInfo.IsDir() || stateInfo.Mode()&os.ModeSymlink != 0 {
			return "", errors.Join(err, errors.New("new state root is not a real directory"))
		}
		if err := secureCreatedDirectory(statePath, stateInfo, 0o700); err != nil {
			return "", fmt.Errorf("secure new state root: %w", err)
		}
		if err := syncStateDirectory(parent); err != nil {
			return "", err
		}
		stateInfo, err = os.Lstat(statePath)
	}
	if err != nil || !stateInfo.IsDir() || stateInfo.Mode()&os.ModeSymlink != 0 {
		return "", errors.Join(err, errors.New("state root is not a real directory"))
	}
	if err := rejectWritableStateDirectory(stateInfo, "state root"); err != nil {
		return "", err
	}
	return statePath, nil
}

func rejectWritableStateDirectory(info os.FileInfo, description string) error {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a real directory", description)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is group/other writable (mode %#o); refusing to establish a state lease", description, info.Mode().Perm())
	}
	return nil
}

func secureCreatedDirectory(path string, identity os.FileInfo, mode os.FileMode) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	opened, statErr := file.Stat()
	current, lstatErr := os.Lstat(path)
	if statErr != nil || lstatErr != nil || opened == nil || current == nil ||
		!opened.IsDir() || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() ||
		!os.SameFile(identity, opened) || !os.SameFile(identity, current) {
		return errors.Join(statErr, lstatErr, file.Close(), errors.New("created directory changed while binding permissions"))
	}
	chmodErr := file.Chmod(mode.Perm())
	syncErr := file.Sync()
	after, afterErr := file.Stat()
	current, currentErr := os.Lstat(path)
	closeErr := file.Close()
	if chmodErr != nil || syncErr != nil || afterErr != nil || currentErr != nil || after == nil || current == nil ||
		after.Mode().Perm() != mode.Perm() || current.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(identity, after) || !os.SameFile(identity, current) {
		return errors.Join(chmodErr, syncErr, afterErr, currentErr, closeErr, errors.New("created directory changed while securing permissions"))
	}
	return closeErr
}

// preflightStateLockWithoutPersistentLease preserves compatibility with a
// legacy process that owns only state.lock. It is deliberately read-only: if
// state.lease is absent and an existing record cannot be recovered right now,
// the contender returns without creating or chmodding anything in locks/.
func preflightStateLockWithoutPersistentLease(locksRoot *os.Root, recoverStale bool) (bool, error) {
	if locksRoot == nil {
		return true, errors.New("state lock directory binding is unavailable")
	}
	if _, err := locksRoot.Lstat("state.lease"); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return true, fmt.Errorf("inspect persistent state lease: %w", err)
	}
	if _, err := locksRoot.Lstat("state.lock"); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return true, fmt.Errorf("inspect legacy-compatible state lock: %w", err)
	}
	file, identity, leaseID, acquired, err := openAdvisoryLease(
		locksRoot, "state.lock", os.O_RDONLY|syscall.O_NONBLOCK, 0,
	)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return true, fmt.Errorf("open existing state lock preflight: %w", err)
	}
	if !acquired {
		return true, errors.New("state is locked by an active process instance holding the advisory lease")
	}
	record, recordErr := readLockFileAt(locksRoot, "state.lock", file, identity)
	if recordErr != nil {
		leaseErr := closeStateLockLease(file, leaseID)
		return true, fmt.Errorf("state lock record is unsafe and cannot be recovered automatically: %w", errors.Join(recordErr, leaseErr))
	}
	staleReason, statusErr := staleLockRecordReason(record)
	leaseErr := closeStateLockLease(file, leaseID)
	if statusErr != nil {
		return true, errors.Join(statusErr, leaseErr)
	}
	if !recoverStale {
		return true, errors.Join(
			fmt.Errorf("stale state lock from pid %d (%s; %s) exists; rerun with --recover", record.PID, record.Operation, staleReason),
			leaseErr,
		)
	}
	if leaseErr != nil {
		return true, fmt.Errorf("release recoverable state lock preflight lease: %w", leaseErr)
	}
	return false, nil
}

func AcquireLock(stateDir, operation string, recoverStale bool) (*Lock, error) {
	statePath, err := bootstrapStateLockRoot(stateDir)
	if err != nil {
		return nil, fmt.Errorf("bootstrap protected state lock root: %w", err)
	}
	stateInfo, err := os.Lstat(statePath)
	if err != nil || !stateInfo.IsDir() || stateInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.Join(err, errors.New("state root is not a real directory"))
	}
	stateRoot, err := os.OpenRoot(statePath)
	if err != nil {
		return nil, fmt.Errorf("bind state root: %w", err)
	}
	closeState := true
	defer func() {
		if closeState {
			_ = stateRoot.Close()
		}
	}()
	boundState, err := stateRoot.Stat(".")
	if err != nil || !os.SameFile(stateInfo, boundState) {
		return nil, errors.Join(err, errors.New("state root changed while binding"))
	}
	if err := rejectWritableStateDirectory(boundState, "bound state root"); err != nil {
		return nil, err
	}
	locksInfo, err := stateRoot.Lstat("locks")
	createdLocks := false
	if errors.Is(err, os.ErrNotExist) {
		if err := stateRoot.Mkdir("locks", 0o700); err != nil {
			return nil, fmt.Errorf("create lock directory: %w", err)
		}
		createdLocks = true
		locksInfo, err = stateRoot.Lstat("locks")
		if err == nil {
			err = syncRootDirectory(stateRoot)
		}
	}
	if err != nil || !locksInfo.IsDir() || locksInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.Join(err, errors.New("state lock directory is not real"))
	}
	if err := rejectWritableStateDirectory(locksInfo, "state lock directory"); err != nil {
		return nil, err
	}
	locksRoot, err := stateRoot.OpenRoot("locks")
	if err != nil {
		return nil, fmt.Errorf("bind state lock directory: %w", err)
	}
	closeLocks := true
	defer func() {
		if closeLocks {
			_ = locksRoot.Close()
		}
	}()
	boundLocks, err := locksRoot.Stat(".")
	if err != nil || !os.SameFile(locksInfo, boundLocks) {
		return nil, errors.Join(err, errors.New("state lock directory changed while binding"))
	}
	if err := rejectWritableStateDirectory(boundLocks, "bound state lock directory"); err != nil {
		return nil, err
	}
	if createdLocks && boundLocks.Mode().Perm() != 0o700 {
		createdDirectory, openErr := locksRoot.Open(".")
		if openErr != nil {
			return nil, fmt.Errorf("open new state lock directory: %w", openErr)
		}
		chmodErr := createdDirectory.Chmod(0o700)
		syncErr := createdDirectory.Sync()
		secured, statErr := createdDirectory.Stat()
		closeErr := createdDirectory.Close()
		current, lstatErr := stateRoot.Lstat("locks")
		if chmodErr != nil || syncErr != nil || statErr != nil || closeErr != nil || lstatErr != nil || secured == nil ||
			secured.Mode().Perm() != 0o700 || current.Mode()&os.ModeSymlink != 0 ||
			!os.SameFile(boundLocks, secured) || !os.SameFile(boundLocks, current) {
			return nil, errors.Join(chmodErr, syncErr, statErr, closeErr, lstatErr, errors.New("new state lock directory changed while securing permissions"))
		}
		boundLocks = secured
	}
	locksFile, err := locksRoot.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open bound state lock directory: %w", err)
	}
	closeLocksFile := true
	defer func() {
		if closeLocksFile {
			_ = locksFile.Close()
		}
	}()
	lockPath := filepath.Join(statePath, "locks", "state.lock")
	lock := &Lock{
		path: lockPath, statePath: statePath, stateRoot: stateRoot, stateIdentity: boundState,
		locksRoot: locksRoot, locksFile: locksFile, locksIdentity: boundLocks,
	}
	if err := lock.validatePathIdentity(); err != nil {
		return nil, err
	}
	// A legacy writer knows only state.lock. When no persistent lease exists,
	// inspect that record under its own advisory lease before creating any new
	// lock-directory entry. Active, unsafe, and non-recovered stale legacy
	// records therefore block a new contender without even creating state.lease.
	if handled, preflightErr := preflightStateLockWithoutPersistentLease(locksRoot, recoverStale); handled {
		return nil, preflightErr
	}
	leaseFile, leaseIdentity, localLeaseID, acquired, err := openAdvisoryLease(
		locksRoot, "state.lease", os.O_CREATE|os.O_RDWR, 0o600,
	)
	if err != nil {
		return nil, fmt.Errorf("acquire persistent state lease: %w", err)
	}
	if !acquired {
		return nil, errors.New("state is locked by an active process instance holding the persistent lease")
	}
	leaseOpen := true
	defer func() {
		if leaseOpen {
			_ = closeStateLockLease(leaseFile, localLeaseID)
		}
	}()
	lock.leaseFile = leaseFile
	lock.leaseIdentity = leaseIdentity
	lock.localLeaseID = localLeaseID
	if err := errors.Join(leaseFile.Sync(), locksFile.Sync(), lock.validatePathIdentity()); err != nil {
		return nil, fmt.Errorf("validate persistent state lease: %w", err)
	}
	var prepared *lockRecord
	for attempt := 0; attempt < 3; attempt++ {
		_, visibleErr := locksRoot.Lstat("state.lock")
		if errors.Is(visibleErr, os.ErrNotExist) {
			var record lockRecord
			if prepared != nil {
				record = *prepared
			} else {
				record, err = newLockRecord(operation)
				if err != nil {
					return nil, err
				}
			}
			file, fileIdentity, recordLeaseID, acquired, createErr := publishPreparedStateLock(locksRoot, locksFile, record)
			if createErr == nil && acquired {
				prepared = nil
				lockIdentity, statErr := file.Stat()
				if statErr != nil || lockIdentity == nil ||
					!lockIdentity.Mode().IsRegular() || !os.SameFile(fileIdentity, lockIdentity) {
					removeErr := removeLeasedStateLock(locksRoot, locksFile, file, fileIdentity)
					leaseErr := closeStateLockLease(file, recordLeaseID)
					return nil, errors.Join(statErr, removeErr, leaseErr)
				}
				lock.lockIdentity = lockIdentity
				lock.lockFile = file
				lock.localRecordID = recordLeaseID
				lock.lockRecord = record
				closePublished := func() error {
					removeErr := lock.removeOwnedLock()
					leaseErr := closeStateLockLease(file, recordLeaseID)
					lock.lockIdentity, lock.lockFile = nil, nil
					lock.localRecordID = 0
					lock.lockRecord = lockRecord{}
					return errors.Join(removeErr, leaseErr)
				}
				if validateErr := lock.validatePathIdentity(); validateErr != nil {
					return nil, fmt.Errorf("validate state lock before protected corridor preparation: %w", errors.Join(validateErr, closePublished()))
				}
				// Permission reconciliation can mutate unrelated state children. It
				// runs only after both the persistent lease and the legacy-compatible
				// record lease are owned and a complete record is visible, so blocked
				// contenders stay read-only and a crash never leaves a partial record.
				if prepareErr := prepareStateRootPermissions(stateRoot, boundState); prepareErr != nil {
					return nil, fmt.Errorf("prepare protected state/serving corridor: %w", errors.Join(prepareErr, closePublished()))
				}
				if validateErr := lock.validatePathIdentity(); validateErr != nil {
					return nil, fmt.Errorf("validate state after protected corridor preparation: %w", errors.Join(validateErr, closePublished()))
				}
				if err := errors.Join(locksFile.Sync(), lock.validatePathIdentity()); err != nil {
					return nil, fmt.Errorf("validate acquired state lock: %w", errors.Join(err, closePublished()))
				}
				closeState, closeLocks, closeLocksFile = false, false, false
				leaseOpen = false
				return lock, nil
			}
			if createErr == nil && !acquired {
				return nil, errors.New("state is locked by an active process instance holding the advisory lease")
			}
			if !errors.Is(createErr, errStateLockPublicationCollision) {
				return nil, fmt.Errorf("publish state lock: %w", createErr)
			}
		} else if visibleErr != nil {
			return nil, fmt.Errorf("inspect existing state lock: %w", visibleErr)
		}

		// Existing evidence remains byte- and metadata-stable until it has been
		// safely classified and explicit recovery is authorized. In particular,
		// passing mode zero prevents openAdvisoryLease from chmodding a malformed,
		// live legacy, or merely non-recovered stale record.
		file, fileIdentity, recordLeaseID, acquired, openErr := openAdvisoryLease(
			locksRoot, "state.lock", os.O_RDONLY|syscall.O_NONBLOCK, 0,
		)
		if errors.Is(openErr, os.ErrNotExist) {
			continue
		}
		if openErr != nil {
			return nil, fmt.Errorf("open existing state lock lease: %w", openErr)
		}
		if !acquired {
			return nil, errors.New("state is locked by an active process instance holding the advisory lease")
		}
		record, recordErr := readLockFileAt(locksRoot, "state.lock", file, fileIdentity)
		if recordErr != nil {
			leaseErr := closeStateLockLease(file, recordLeaseID)
			return nil, fmt.Errorf("state lock record is unsafe and cannot be recovered automatically: %w", errors.Join(recordErr, leaseErr))
		}
		staleReason, statusErr := staleLockRecordReason(record)
		if statusErr != nil {
			leaseErr := closeStateLockLease(file, recordLeaseID)
			return nil, errors.Join(statusErr, leaseErr)
		}
		if !recoverStale {
			leaseErr := closeStateLockLease(file, recordLeaseID)
			return nil, errors.Join(
				fmt.Errorf("stale state lock from pid %d (%s; %s) exists; rerun with --recover", record.PID, record.Operation, staleReason),
				leaseErr,
			)
		}
		preparedRecord, prepareErr := newLockRecord(operation)
		if prepareErr != nil {
			leaseErr := closeStateLockLease(file, recordLeaseID)
			return nil, errors.Join(fmt.Errorf("prepare replacement state lock before recovery: %w", prepareErr), leaseErr)
		}
		staleName := fmt.Sprintf("state.lock.stale-%d-%s", time.Now().UTC().UnixNano(), preparedRecord.LockID)
		if err := preserveLeasedStateLock(locksRoot, locksFile, file, fileIdentity, staleName); err != nil {
			leaseErr := closeStateLockLease(file, recordLeaseID)
			return nil, errors.Join(fmt.Errorf("preserve stale lock: %w", err), leaseErr)
		}
		if err := lock.validatePathIdentity(); err != nil {
			leaseErr := closeStateLockLease(file, recordLeaseID)
			return nil, errors.Join(fmt.Errorf("validate state root after preserving stale lock: %w", err), leaseErr)
		}
		if err := closeStateLockLease(file, recordLeaseID); err != nil {
			return nil, fmt.Errorf("release preserved stale state lock lease: %w", err)
		}
		prepared = &preparedRecord
	}
	return nil, errors.New("could not acquire state lock after recovering stale lock")
}

// Validate proves that the repository still resolves to the exact state and
// lock directories bound by AcquireLock, and that the durable lock entry is
// still the inode created by this holder. Compatibility workflows call it at
// every mutation boundary so a path replacement fails closed.
func (l *Lock) Validate() error {
	if l == nil {
		return errors.New("state lock is unavailable")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.validatePathIdentity()
}

// ValidateStateDir proves both continued ownership and that this lock belongs
// to the exact canonical state root a caller is about to admit. Validate alone
// is insufficient for cross-component capability passing: a perfectly valid
// lock from repository B must never authorize repository A's mutation window.
func (l *Lock) ValidateStateDir(stateDir string) error {
	if l == nil {
		return errors.New("state lock is unavailable")
	}
	expected, err := filepath.Abs(filepath.Clean(stateDir))
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if expected != l.statePath {
		return fmt.Errorf("state lock belongs to a different canonical state root: have=%s want=%s", l.statePath, expected)
	}
	return l.validatePathIdentity()
}

func (l *Lock) validatePathIdentity() error {
	if l.stateRoot == nil || l.locksRoot == nil || l.locksFile == nil || l.stateIdentity == nil || l.locksIdentity == nil {
		return errors.New("state lock binding is closed")
	}
	boundState, stateErr := l.stateRoot.Stat(".")
	boundLocks, locksErr := l.locksRoot.Stat(".")
	locksFileInfo, locksFileErr := l.locksFile.Stat()
	pathState, pathErr := os.Lstat(l.statePath)
	stateLocks, stateLocksErr := l.stateRoot.Lstat("locks")
	if stateErr != nil || locksErr != nil || locksFileErr != nil || pathErr != nil || stateLocksErr != nil ||
		pathState.Mode()&os.ModeSymlink != 0 || !pathState.IsDir() || stateLocks.Mode()&os.ModeSymlink != 0 || !stateLocks.IsDir() ||
		!os.SameFile(l.stateIdentity, boundState) || !os.SameFile(l.stateIdentity, pathState) ||
		!os.SameFile(l.locksIdentity, boundLocks) || !os.SameFile(l.locksIdentity, locksFileInfo) || !os.SameFile(l.locksIdentity, stateLocks) {
		return errors.Join(stateErr, locksErr, locksFileErr, pathErr, stateLocksErr, errors.New("state or lock directory was replaced after lock acquisition"))
	}
	if l.leaseIdentity != nil {
		if l.leaseFile == nil || l.localLeaseID == 0 {
			return errors.New("persistent state lease binding is unavailable")
		}
		opened, openedErr := l.leaseFile.Stat()
		current, currentErr := l.locksRoot.Lstat("state.lease")
		if openedErr != nil || currentErr != nil || opened == nil || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0o600 ||
			current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || current.Mode().Perm() != 0o600 ||
			!os.SameFile(l.leaseIdentity, opened) || !os.SameFile(l.leaseIdentity, current) {
			return errors.Join(openedErr, currentErr, errors.New("persistent state lease was replaced or widened after acquisition"))
		}
	}
	if l.lockIdentity != nil {
		if l.lockFile == nil || l.localRecordID == 0 {
			return errors.New("state lock advisory lease is unavailable")
		}
		opened, openedErr := l.lockFile.Stat()
		current, err := l.locksRoot.Lstat("state.lock")
		if openedErr != nil || err != nil || opened == nil || !opened.Mode().IsRegular() ||
			current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() ||
			!os.SameFile(l.lockIdentity, opened) || !os.SameFile(l.lockIdentity, current) {
			return errors.Join(openedErr, err, errors.New("state lock entry no longer belongs to this holder"))
		}
		record, err := readLockFileAt(l.locksRoot, "state.lock", l.lockFile, l.lockIdentity)
		if err != nil || !sameLockRecord(l.lockRecord, record) {
			return errors.Join(err, errors.New("state lock record no longer identifies this holder"))
		}
		if err := l.validateHolderProcessIdentity(); err != nil {
			return err
		}
	}
	return nil
}

func (l *Lock) validateHolderProcessIdentity() error {
	if l == nil || l.lockRecord.SchemaVersion != lockRecordSchemaV1 ||
		l.lockRecord.PID != os.Getpid() || l.lockRecord.IdentityStatus != lockIdentityObserved ||
		l.lockRecord.ProcessIdentity == nil {
		return errors.New("state lock holder process-instance identity is unavailable")
	}
	observed, err := readProcessIdentity(os.Getpid())
	if err != nil {
		return fmt.Errorf("revalidate state lock holder process-instance identity: %w", err)
	}
	if observed != *l.lockRecord.ProcessIdentity {
		return errors.New("current process instance does not match the state lock holder identity")
	}
	return nil
}

func sameLockRecord(expected, observed lockRecord) bool {
	if expected.SchemaVersion != observed.SchemaVersion || expected.PID != observed.PID ||
		expected.Operation != observed.Operation || !expected.StartedAt.Equal(observed.StartedAt) ||
		expected.LockID != observed.LockID || expected.IdentityStatus != observed.IdentityStatus {
		return false
	}
	if expected.ProcessIdentity == nil || observed.ProcessIdentity == nil {
		return expected.ProcessIdentity == nil && observed.ProcessIdentity == nil
	}
	return *expected.ProcessIdentity == *observed.ProcessIdentity
}

// prepareStateRootPermissions reconciles the deliberate dual use of .sow:
// control data remains below private immediate children, while the frozen
// materialized/ and origin/ serving corridors must be traversable by an
// unprivileged Nginx worker. Every chmod is performed through an already-open
// descriptor whose inode is compared with the bound Root and its current
// directory entry. A path swapped to a symlink can therefore make the command
// fail, but can never redirect chmod to the replacement target.
func prepareStateRootPermissions(stateRoot *os.Root, stateIdentity os.FileInfo) error {
	if stateRoot == nil || stateIdentity == nil {
		return errors.New("bound state root is unavailable for permission reconciliation")
	}
	stateFile, err := stateRoot.Open(".")
	if err != nil {
		return err
	}
	closeState := true
	defer func() {
		if closeState {
			_ = stateFile.Close()
		}
	}()
	openedState, statErr := stateFile.Stat()
	boundState, boundErr := stateRoot.Stat(".")
	if statErr != nil || boundErr != nil || openedState == nil || boundState == nil ||
		!openedState.IsDir() || !boundState.IsDir() ||
		!os.SameFile(stateIdentity, openedState) || !os.SameFile(stateIdentity, boundState) {
		return errors.Join(statErr, boundErr, errors.New("bound state root changed before permission reconciliation"))
	}
	entries, err := stateFile.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		child, lstatErr := stateRoot.Lstat(name)
		if lstatErr != nil || child == nil || child.Mode()&os.ModeSymlink != 0 {
			return errors.Join(lstatErr, fmt.Errorf("state child %s is unsafe", name))
		}
		servingCorridor := name == "materialized" || name == "origin"
		var wanted os.FileMode
		switch {
		case child.IsDir() && servingCorridor:
			wanted = 0o755
		case child.IsDir():
			wanted = 0o700
		case child.Mode().IsRegular() && !servingCorridor:
			wanted = 0o600
		default:
			return fmt.Errorf("state child %s is neither a protected control file nor a serving directory", name)
		}
		if faultErr := callStatePermissionFault(statePermissionAfterChildLstat, name); faultErr != nil {
			return faultErr
		}
		if err := secureBoundStateChild(stateRoot, name, child, wanted); err != nil {
			return fmt.Errorf("secure state child %s: %w", name, err)
		}
	}
	if faultErr := callStatePermissionFault(statePermissionBeforeRootChmod, "."); faultErr != nil {
		return faultErr
	}
	chmodErr := stateFile.Chmod(0o711)
	syncErr := stateFile.Sync()
	afterState, afterErr := stateFile.Stat()
	boundState, boundErr = stateRoot.Stat(".")
	if chmodErr != nil || syncErr != nil || afterErr != nil || boundErr != nil || afterState == nil || boundState == nil ||
		afterState.Mode().Perm() != 0o711 || !os.SameFile(stateIdentity, afterState) || !os.SameFile(stateIdentity, boundState) {
		return errors.Join(chmodErr, syncErr, afterErr, boundErr, errors.New("bound state root changed while securing permissions"))
	}
	closeState = false
	return stateFile.Close()
}

func secureBoundStateChild(stateRoot *os.Root, name string, identity os.FileInfo, mode os.FileMode) error {
	// O_NONBLOCK prevents a hostile replacement with a FIFO from hanging the
	// lock holder between Lstat and OpenFile. No chmod occurs until the opened
	// descriptor, the original identity, and a second Lstat all agree.
	file, err := stateRoot.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	closeFile := true
	defer func() {
		if closeFile {
			_ = file.Close()
		}
	}()
	opened, statErr := file.Stat()
	current, lstatErr := stateRoot.Lstat(name)
	if statErr != nil || lstatErr != nil || opened == nil || current == nil ||
		current.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(identity, opened) || !os.SameFile(identity, current) {
		return errors.Join(statErr, lstatErr, errors.New("state child changed before descriptor-bound chmod"))
	}
	if identity.IsDir() != opened.IsDir() || identity.Mode().IsRegular() != opened.Mode().IsRegular() {
		return errors.New("state child type changed before descriptor-bound chmod")
	}
	chmodErr := file.Chmod(mode.Perm())
	syncErr := file.Sync()
	after, afterErr := file.Stat()
	current, lstatErr = stateRoot.Lstat(name)
	if chmodErr != nil || syncErr != nil || afterErr != nil || lstatErr != nil || after == nil || current == nil ||
		after.Mode().Perm() != mode.Perm() || current.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(identity, after) || !os.SameFile(identity, current) {
		return errors.Join(chmodErr, syncErr, afterErr, lstatErr, errors.New("state child changed during descriptor-bound chmod"))
	}
	closeFile = false
	return file.Close()
}

type lockRecordKind uint8

const (
	lockRecordLegacy lockRecordKind = iota
	lockRecordProcessIdentityV1
)

func newLockRecord(operation string) (lockRecord, error) {
	identity, err := readProcessIdentity(os.Getpid())
	if err != nil {
		return lockRecord{}, fmt.Errorf("read current process-instance identity for state lock: %w", err)
	}
	idBytes := make([]byte, lockIDBytes)
	if _, err := rand.Read(idBytes); err != nil {
		return lockRecord{}, fmt.Errorf("generate state lock ID: %w", err)
	}
	record := lockRecord{
		SchemaVersion:   lockRecordSchemaV1,
		PID:             os.Getpid(),
		Operation:       operation,
		StartedAt:       time.Now().UTC(),
		LockID:          hex.EncodeToString(idBytes),
		IdentityStatus:  lockIdentityObserved,
		ProcessIdentity: &identity,
	}
	if _, err := record.kind(); err != nil {
		return lockRecord{}, err
	}
	return record, nil
}

func (r lockRecord) kind() (lockRecordKind, error) {
	if r.PID <= 0 || r.Operation == "" || len(r.Operation) > 256 || r.StartedAt.IsZero() {
		return 0, errors.New("lock record is incomplete")
	}
	for _, character := range r.Operation {
		if character < 0x20 || character == 0x7f {
			return 0, errors.New("lock operation contains control characters")
		}
	}
	switch r.SchemaVersion {
	case 0:
		if r.LockID != "" || r.IdentityStatus != "" || r.ProcessIdentity != nil {
			return 0, errors.New("legacy lock record contains partial process identity fields")
		}
		return lockRecordLegacy, nil
	case lockRecordSchemaV1:
		decoded, err := hex.DecodeString(r.LockID)
		if err != nil || len(decoded) != lockIDBytes || hex.EncodeToString(decoded) != r.LockID {
			return 0, errors.New("state lock ID is not canonical")
		}
		switch r.IdentityStatus {
		case lockIdentityObserved:
			if r.ProcessIdentity == nil {
				return 0, errors.New("observed state lock process identity is missing")
			}
			if err := r.ProcessIdentity.validate(); err != nil {
				return 0, fmt.Errorf("state lock process identity is invalid: %w", err)
			}
		case lockIdentityUnavailable:
			if r.ProcessIdentity != nil {
				return 0, errors.New("unavailable state lock process identity contains an observed token")
			}
		default:
			return 0, fmt.Errorf("unsupported state lock identity status %q", r.IdentityStatus)
		}
		return lockRecordProcessIdentityV1, nil
	default:
		return 0, fmt.Errorf("unsupported state lock schema version %d", r.SchemaVersion)
	}
}

// staleLockRecordReason is called only while the caller holds the record's
// advisory lease. Releasing that lease is not by itself proof that a recorded
// process instance is gone: a holder may have lost the descriptor while still
// running. Only a missing PID or a different OS process-instance identity can
// authorize explicit stale recovery. Missing diagnostic evidence remains
// fail-closed, as does every legacy record whose PID is still alive.
func staleLockRecordReason(record lockRecord) (string, error) {
	kind, err := record.kind()
	if err != nil {
		return "", fmt.Errorf("classify state lock: %w", err)
	}
	if kind == lockRecordLegacy {
		_, identityErr := readProcessIdentity(record.PID)
		if identityErr == nil {
			return "", fmt.Errorf("state is locked by legacy pid %d running %q since %s; the legacy record has no process-instance identity or advisory lease, so automatic recovery is unsafe while that PID is alive", record.PID, record.Operation, record.StartedAt.Format(time.RFC3339))
		}
		if errors.Is(identityErr, errProcessIdentityNotFound) {
			return "legacy holder PID is no longer alive", nil
		}
		return "", fmt.Errorf("state lock legacy pid %d process-instance identity cannot be probed safely; automatic recovery is unsafe: %w", record.PID, identityErr)
	}
	if record.IdentityStatus == lockIdentityUnavailable {
		return "", fmt.Errorf("state lock pid %d has no creation-time process-instance identity; automatic recovery is unsafe even though its advisory lease was released", record.PID)
	}
	observed, identityErr := readProcessIdentity(record.PID)
	if identityErr == nil {
		if observed == *record.ProcessIdentity {
			return "", fmt.Errorf("state is locked by the recorded process instance pid %d running %q since %s; its advisory lease was released but the exact instance is still observable", record.PID, record.Operation, record.StartedAt.Format(time.RFC3339))
		}
		return "PID now belongs to a different process instance", nil
	}
	if errors.Is(identityErr, errProcessIdentityNotFound) {
		return "recorded process instance no longer exists", nil
	}
	return "", fmt.Errorf("state lock pid %d process-instance identity cannot be probed safely; refusing automatic recovery after advisory lease release: %w", record.PID, identityErr)
}

func readLockFileAt(root *os.Root, name string, file *os.File, identity os.FileInfo) (lockRecord, error) {
	info, err := root.Lstat(name)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return lockRecord{}, errors.Join(err, errors.New("lock entry is not a regular file"))
	}
	if info.Mode().Perm()&0o022 != 0 {
		return lockRecord{}, fmt.Errorf("lock entry is group/other writable (mode %#o)", info.Mode().Perm())
	}
	if info.Size() <= 0 || info.Size() > maxLockRecordBytes {
		return lockRecord{}, fmt.Errorf("lock entry size %d is outside the accepted range", info.Size())
	}
	if file == nil || identity == nil {
		return lockRecord{}, errors.New("lock entry lease is unavailable")
	}
	opened, err := file.Stat()
	if err != nil || opened == nil || !os.SameFile(identity, info) || !os.SameFile(identity, opened) || !opened.Mode().IsRegular() {
		return lockRecord{}, errors.Join(err, errors.New("lock entry changed while opening"))
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return lockRecord{}, err
	}
	var record lockRecord
	decoder := json.NewDecoder(io.LimitReader(file, maxLockRecordBytes+1))
	decoder.DisallowUnknownFields()
	decodeErr := decoder.Decode(&record)
	if decodeErr == nil {
		var extra any
		if trailingErr := decoder.Decode(&extra); !errors.Is(trailingErr, io.EOF) {
			decodeErr = errors.Join(trailingErr, errors.New("lock entry contains trailing JSON content"))
		}
	}
	after, statErr := file.Stat()
	current, lstatErr := root.Lstat(name)
	if decodeErr != nil || statErr != nil || lstatErr != nil || !os.SameFile(identity, after) || !os.SameFile(identity, current) {
		return lockRecord{}, errors.Join(decodeErr, statErr, lstatErr, errors.New("lock entry changed while reading"))
	}
	if _, err := record.kind(); err != nil {
		return lockRecord{}, err
	}
	return record, nil
}

func processAlive(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = process.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, os.ErrPermission)
}

func (l *Lock) Release() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.path == "" {
		return nil
	}
	// A failed identity probe is retryable. Keep both advisory leases and the
	// durable record intact so the original holder can retry Release after the
	// platform probe recovers; closing here would strand an exact-live record
	// that this Lock could no longer remove.
	if err := l.validateHolderProcessIdentity(); err != nil {
		return err
	}
	removeErr := l.removeOwnedLock()
	recordLeaseErr := closeStateLockLease(l.lockFile, l.localRecordID)
	persistentLeaseErr := closeStateLockLease(l.leaseFile, l.localLeaseID)
	closeFileErr := l.locksFile.Close()
	closeLocksErr := l.locksRoot.Close()
	closeStateErr := l.stateRoot.Close()
	l.path = ""
	l.stateRoot, l.locksRoot, l.locksFile = nil, nil, nil
	l.stateIdentity, l.locksIdentity, l.leaseIdentity, l.lockIdentity = nil, nil, nil, nil
	l.leaseFile, l.lockFile = nil, nil
	l.localLeaseID, l.localRecordID = 0, 0
	l.lockRecord = lockRecord{}
	return errors.Join(removeErr, recordLeaseErr, persistentLeaseErr, closeFileErr, closeLocksErr, closeStateErr)
}

func (l *Lock) removeOwnedLock() error {
	if l == nil || l.locksRoot == nil || l.locksFile == nil || l.leaseFile == nil || l.leaseIdentity == nil || l.localLeaseID == 0 ||
		l.lockFile == nil || l.lockIdentity == nil || l.localRecordID == 0 {
		return errors.New("state lock ownership binding is unavailable")
	}
	current, err := l.locksRoot.Lstat("state.lock")
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("refusing to release a state lock whose durable record is missing")
	}
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || !os.SameFile(l.lockIdentity, current) {
		return errors.Join(err, errors.New("refusing to remove a state lock entry not owned by this holder"))
	}
	record, err := readLockFileAt(l.locksRoot, "state.lock", l.lockFile, l.lockIdentity)
	if err != nil || !sameLockRecord(l.lockRecord, record) {
		return errors.Join(err, errors.New("refusing to remove a state lock record not owned by this holder"))
	}
	return removeLeasedStateLock(l.locksRoot, l.locksFile, l.lockFile, l.lockIdentity)
}
