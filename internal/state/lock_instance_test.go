package state

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const lockHelperStateEnv = "SOW_TEST_STATE_LOCK_HELPER_ROOT"
const lockHelperModeEnv = "SOW_TEST_STATE_LOCK_HELPER_MODE"

func TestStateLockHelperProcess(t *testing.T) {
	statePath := os.Getenv(lockHelperStateEnv)
	if statePath == "" {
		return
	}
	switch os.Getenv(lockHelperModeEnv) {
	case "barrier":
		if _, err := fmt.Fprintln(os.Stdout, "armed"); err != nil {
			t.Fatal(err)
		}
		var start [1]byte
		if _, err := io.ReadFull(os.Stdin, start[:]); err != nil {
			t.Fatal(err)
		}
		lock, err := AcquireLock(statePath, "barrier-holder", false)
		if err != nil {
			if _, printErr := fmt.Fprintln(os.Stdout, "blocked"); printErr != nil {
				t.Fatal(printErr)
			}
			return
		}
		if _, err := fmt.Fprintln(os.Stdout, "acquired"); err != nil {
			t.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, os.Stdin)
		releaseErr := lock.Release()
		if readErr != nil || releaseErr != nil {
			t.Fatal(errors.Join(readErr, releaseErr))
		}
		return
	case "legacy-record-flock":
		runLegacyRecordFlockHelper(t, statePath)
		return
	}
	lock, err := AcquireLock(statePath, "helper-holder", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintln(os.Stdout, "ready"); err != nil {
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, os.Stdin)
	releaseErr := lock.Release()
	if readErr != nil || releaseErr != nil {
		t.Fatal(errors.Join(readErr, releaseErr))
	}
}

func runLegacyRecordFlockHelper(t *testing.T, statePath string) {
	locksPath := filepath.Join(statePath, "locks")
	if err := os.MkdirAll(locksPath, 0o700); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(locksPath, "state.lock")
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	acquired, err := tryStateLockLease(file)
	if err != nil || !acquired {
		t.Fatalf("legacy helper record lease acquired=%t err=%v", acquired, err)
	}
	record := fixtureLegacyLockRecord(os.Getpid())
	if err := json.NewEncoder(file).Encode(record); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := file.Chmod(0o640); err != nil {
		t.Fatal(err)
	}
	fixed := time.Date(2021, 2, 3, 4, 5, 6, 0, time.UTC)
	if err := os.Chtimes(lockPath, fixed, fixed); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintln(os.Stdout, "ready"); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		t.Fatal(err)
	}
	removeErr := os.Remove(lockPath)
	unlockErr := releaseStateLockLease(file)
	closeErr := file.Close()
	if err := errors.Join(removeErr, unlockErr, closeErr); err != nil {
		t.Fatal(err)
	}
}

func TestStateLockExactLiveInstanceBlocksRecoveryAcrossProcesses(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), ".sow")
	command := exec.Command(os.Args[0], "-test.run=^TestStateLockHelperProcess$")
	command.Env = append(os.Environ(), lockHelperStateEnv+"="+statePath)
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		_ = stdin.Close()
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	ready, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || ready != "ready\n" {
		t.Fatalf("helper did not acquire state lock: ready=%q err=%v stderr=%s", ready, err, stderr.String())
	}
	lockPath := filepath.Join(statePath, "locks", "state.lock")
	before, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeLock := snapshotFilesystemEntry(t, lockPath)
	leasePath := filepath.Join(statePath, "locks", "state.lease")
	beforeLeaseBody, err := os.ReadFile(leasePath)
	if err != nil {
		t.Fatal(err)
	}
	beforeLease, err := os.Lstat(leasePath)
	if err != nil {
		t.Fatal(err)
	}
	controlPath := filepath.Join(statePath, "active-holder-control")
	if err := os.WriteFile(controlPath, []byte("control\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(controlPath, 0o666); err != nil {
		t.Fatal(err)
	}
	fixedControl := time.Date(2023, 4, 5, 6, 7, 8, 0, time.UTC)
	if err := os.Chtimes(controlPath, fixedControl, fixedControl); err != nil {
		t.Fatal(err)
	}
	beforeControl, err := os.Lstat(controlPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(statePath, "competitor", true); err == nil || !strings.Contains(err.Error(), "active process instance") {
		t.Fatalf("exact live holder was not protected from recovery: %v", err)
	}
	after, err := os.ReadFile(lockPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("blocked recovery changed the live lock record: err=%v", err)
	}
	assertFilesystemEntryUnchanged(t, lockPath, beforeLock)
	afterLeaseBody, err := os.ReadFile(leasePath)
	if err != nil {
		t.Fatal(err)
	}
	afterLease, err := os.Lstat(leasePath)
	if err != nil || !bytes.Equal(beforeLeaseBody, afterLeaseBody) || afterLease.Mode().Perm() != beforeLease.Mode().Perm() || !afterLease.ModTime().Equal(beforeLease.ModTime()) {
		t.Fatalf("blocked recovery changed the persistent lease: before=%v after=%v err=%v", beforeLease, afterLease, err)
	}
	afterControl, err := os.Lstat(controlPath)
	if err != nil || afterControl.Mode().Perm() != beforeControl.Mode().Perm() || !afterControl.ModTime().Equal(beforeControl.ModTime()) {
		t.Fatalf("blocked recovery changed unrelated state child: before=%v after=%v err=%v", beforeControl, afterControl, err)
	}
	if stale := staleLockFiles(t, statePath); len(stale) != 0 {
		t.Fatalf("blocked recovery preserved a live record as stale: %v", stale)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("helper release failed: %v stderr=%s", err, stderr.String())
	}
	waited = true
	if _, err := os.Lstat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("helper release retained state lock: %v", err)
	}
}

func TestStateLockTwoProcessesFirstAcquireIsSerializedByPersistentLease(t *testing.T) {
	type helper struct {
		command *exec.Cmd
		stdin   io.WriteCloser
		stdout  *bufio.Reader
		stderr  bytes.Buffer
		waited  bool
	}
	statePath := filepath.Join(t.TempDir(), ".sow")
	helpers := make([]*helper, 0, 2)
	defer func() {
		for _, process := range helpers {
			_ = process.stdin.Close()
			if !process.waited {
				_ = process.command.Process.Kill()
				_ = process.command.Wait()
			}
		}
	}()
	for index := 0; index < 2; index++ {
		process := &helper{command: exec.Command(os.Args[0], "-test.run=^TestStateLockHelperProcess$")}
		process.command.Env = append(os.Environ(), lockHelperStateEnv+"="+statePath, lockHelperModeEnv+"=barrier")
		stdin, err := process.command.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		stdout, err := process.command.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		process.stdin = stdin
		process.stdout = bufio.NewReader(stdout)
		process.command.Stderr = &process.stderr
		if err := process.command.Start(); err != nil {
			t.Fatal(err)
		}
		helpers = append(helpers, process)
	}
	for index, process := range helpers {
		line, err := process.stdout.ReadString('\n')
		if err != nil || line != "armed\n" {
			t.Fatalf("helper %d did not reach first-acquire barrier: line=%q err=%v stderr=%s", index, line, err, process.stderr.String())
		}
	}
	for _, process := range helpers {
		if _, err := process.stdin.Write([]byte{'x'}); err != nil {
			t.Fatal(err)
		}
	}
	results := make([]string, len(helpers))
	for index, process := range helpers {
		line, err := process.stdout.ReadString('\n')
		if err != nil {
			t.Fatalf("helper %d first-acquire result: %v stderr=%s", index, err, process.stderr.String())
		}
		results[index] = strings.TrimSpace(line)
	}
	acquired, blocked := 0, 0
	for _, result := range results {
		switch result {
		case "acquired":
			acquired++
		case "blocked":
			blocked++
		default:
			t.Fatalf("unexpected first-acquire results: %v", results)
		}
	}
	if acquired != 1 || blocked != 1 {
		t.Fatalf("persistent lease did not serialize first acquire: results=%v", results)
	}
	for _, process := range helpers {
		if err := process.stdin.Close(); err != nil {
			t.Fatal(err)
		}
		if err := process.command.Wait(); err != nil {
			t.Fatalf("first-acquire helper exit: %v stderr=%s", err, process.stderr.String())
		}
		process.waited = true
	}
	if _, err := os.Lstat(filepath.Join(statePath, "locks", "state.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("serialized first acquire retained state.lock: %v", err)
	}
	leaseInfo, err := os.Lstat(filepath.Join(statePath, "locks", "state.lease"))
	if err != nil || !leaseInfo.Mode().IsRegular() || leaseInfo.Mode().Perm() != 0o600 {
		t.Fatalf("persistent lease missing or unsafe after first-acquire race: mode=%v err=%v", leaseInfo, err)
	}
}

func TestStateLockRespectsLegacyRecordOnlyFlock(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), ".sow")
	controlPath := filepath.Join(statePath, "legacy-blocked-control")
	if err := os.MkdirAll(statePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(controlPath, []byte("control\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(controlPath, 0o666); err != nil {
		t.Fatal(err)
	}
	fixedControl := time.Date(2022, 3, 4, 5, 6, 7, 0, time.UTC)
	if err := os.Chtimes(controlPath, fixedControl, fixedControl); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestStateLockHelperProcess$")
	command.Env = append(os.Environ(), lockHelperStateEnv+"="+statePath, lockHelperModeEnv+"=legacy-record-flock")
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		_ = stdin.Close()
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "ready\n" {
		t.Fatalf("legacy record helper not ready: line=%q err=%v stderr=%s", line, err, stderr.String())
	}
	lockPath := filepath.Join(statePath, "locks", "state.lock")
	locksPath := filepath.Join(statePath, "locks")
	beforeBody, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeLock := snapshotFilesystemEntry(t, lockPath)
	beforeLocks := snapshotFilesystemEntry(t, locksPath)
	beforeControl, err := os.Lstat(controlPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(statePath, "new-holder", true); err == nil || !strings.Contains(err.Error(), "active process instance") {
		t.Fatalf("new protocol ignored legacy record-only flock: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(statePath, "locks", "state.lease")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("blocked legacy contender wrote persistent lease state: %v", err)
	}
	afterBody, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeBody, afterBody) {
		t.Fatal("blocked contender mutated active legacy record bytes")
	}
	assertFilesystemEntryUnchanged(t, lockPath, beforeLock)
	assertFilesystemEntryUnchanged(t, locksPath, beforeLocks)
	afterControl, err := os.Lstat(controlPath)
	if err != nil || afterControl.Mode().Perm() != beforeControl.Mode().Perm() || !afterControl.ModTime().Equal(beforeControl.ModTime()) {
		t.Fatalf("blocked legacy contender mutated unrelated state child: before=%v after=%v err=%v", beforeControl, afterControl, err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("legacy record helper exit: %v stderr=%s", err, stderr.String())
	}
	waited = true
	lock, err := AcquireLock(statePath, "new-holder", false)
	if err != nil {
		t.Fatalf("new protocol did not proceed after legacy record flock release: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestStateLockSameProcessReentryBlocks(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), ".sow")
	first, err := AcquireLock(statePath, "first", false)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Release()
	controlPath := filepath.Join(statePath, "blocked-contender-control")
	if err := os.WriteFile(controlPath, []byte("control\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(controlPath, 0o666); err != nil {
		t.Fatal(err)
	}
	fixed := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := os.Chtimes(controlPath, fixed, fixed); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(controlPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(statePath, "second", true); err == nil || !strings.Contains(err.Error(), "active process instance") {
		t.Fatalf("same-process reentry bypassed the local lease registry: %v", err)
	}
	after, err := os.Lstat(controlPath)
	if err != nil || after.Mode().Perm() != before.Mode().Perm() || !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("blocked contender mutated unrelated state child: before=%v after=%v err=%v", before, after, err)
	}
}

func TestStateLockRecoversSamePIDDifferentProcessInstance(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), ".sow")
	oldIdentity := fixtureProcessIdentity("100")
	newIdentity := fixtureProcessIdentity("200")
	oldRecord := fixtureV1LockRecord(os.Getpid(), oldIdentity)
	writeLockRecordFixture(t, statePath, oldRecord)
	restore := replaceProcessIdentityReader(func(pid int) (processIdentity, error) {
		if pid != os.Getpid() {
			return processIdentity{}, errProcessIdentityNotFound
		}
		return newIdentity, nil
	})
	defer restore()
	before := readLockBytes(t, statePath)
	if _, err := AcquireLock(statePath, "replacement", false); err == nil || !strings.Contains(err.Error(), "different process instance") {
		t.Fatalf("PID reuse was not classified as stale: %v", err)
	}
	if after := readLockBytes(t, statePath); !bytes.Equal(before, after) {
		t.Fatal("non-recovery PID-reuse check changed the lock record")
	}
	recovered, err := AcquireLock(statePath, "replacement", true)
	if err != nil {
		t.Fatalf("recover same PID/different process instance: %v", err)
	}
	current := readLockRecordFixture(t, statePath)
	if current.ProcessIdentity == nil || *current.ProcessIdentity != newIdentity || current.LockID == oldRecord.LockID {
		t.Fatalf("replacement lock did not bind the new process instance: %+v", current)
	}
	stale := staleLockFiles(t, statePath)
	if len(stale) != 1 {
		t.Fatalf("PID reuse recovery stale records=%v want=1", stale)
	}
	staleRecord := readLockRecordPath(t, stale[0])
	if staleRecord.ProcessIdentity == nil || *staleRecord.ProcessIdentity != oldIdentity || staleRecord.LockID != oldRecord.LockID {
		t.Fatalf("PID reuse recovery did not preserve the old identity: %+v", staleRecord)
	}
	if err := recovered.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestStateLockRecoversDeadProcessInstance(t *testing.T) {
	deadPID := definitelyDeadPID(t)
	currentIdentity, err := readPlatformProcessIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	restore := replaceProcessIdentityReader(func(pid int) (processIdentity, error) {
		if pid == deadPID {
			return processIdentity{}, errProcessIdentityNotFound
		}
		if pid == os.Getpid() {
			return currentIdentity, nil
		}
		return processIdentity{}, errProcessIdentityNotFound
	})
	defer restore()
	statePath := filepath.Join(t.TempDir(), ".sow")
	writeLockRecordFixture(t, statePath, fixtureV1LockRecord(deadPID, fixtureProcessIdentity("300")))
	if _, err := AcquireLock(statePath, "replacement", false); err == nil || !strings.Contains(err.Error(), "no longer exists") {
		t.Fatalf("dead process record was not reported stale: %v", err)
	}
	lock, err := AcquireLock(statePath, "replacement", true)
	if err != nil {
		t.Fatalf("recover dead process record: %v", err)
	}
	if len(staleLockFiles(t, statePath)) != 1 {
		t.Fatal("dead process recovery did not preserve exactly one stale record")
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestStateLockLegacyMigrationIsConservative(t *testing.T) {
	t.Run("live PID remains blocked", func(t *testing.T) {
		statePath := filepath.Join(t.TempDir(), ".sow")
		writeLockRecordFixture(t, statePath, fixtureLegacyLockRecord(os.Getpid()))
		before := readLockBytes(t, statePath)
		locksPath := filepath.Join(statePath, "locks")
		beforeLocks := snapshotFilesystemEntry(t, locksPath)
		if _, err := AcquireLock(statePath, "replacement", true); err == nil || !strings.Contains(err.Error(), "legacy") || !strings.Contains(err.Error(), "unsafe") {
			t.Fatalf("live legacy PID was automatically recovered: %v", err)
		}
		if after := readLockBytes(t, statePath); !bytes.Equal(before, after) {
			t.Fatal("blocked legacy recovery changed the record")
		}
		if _, err := os.Lstat(filepath.Join(locksPath, "state.lease")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("blocked legacy PID recovery wrote persistent lease state: %v", err)
		}
		assertFilesystemEntryUnchanged(t, locksPath, beforeLocks)
	})
	t.Run("dead PID migrates with explicit recovery", func(t *testing.T) {
		statePath := filepath.Join(t.TempDir(), ".sow")
		writeLockRecordFixture(t, statePath, fixtureLegacyLockRecord(definitelyDeadPID(t)))
		lock, err := AcquireLock(statePath, "replacement", true)
		if err != nil {
			t.Fatalf("recover dead legacy PID: %v", err)
		}
		if len(staleLockFiles(t, statePath)) != 1 {
			t.Fatal("legacy migration did not preserve the old record")
		}
		if record := readLockRecordFixture(t, statePath); record.SchemaVersion != lockRecordSchemaV1 {
			t.Fatalf("legacy recovery did not write v1 record: %+v", record)
		}
		if err := lock.Release(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestStateLockV1RecoveryRequiresProofRecordedInstanceIsGone(t *testing.T) {
	exactIdentity := fixtureProcessIdentity("450")
	tests := []struct {
		name   string
		record lockRecord
		reader func(int) (processIdentity, error)
		want   string
	}{
		{
			name:   "exact recorded instance remains observable",
			record: fixtureV1LockRecord(os.Getpid(), exactIdentity),
			reader: func(pid int) (processIdentity, error) {
				if pid == os.Getpid() {
					return exactIdentity, nil
				}
				return processIdentity{}, errProcessIdentityNotFound
			},
			want: "exact instance is still observable",
		},
		{
			name: "creation-time identity unavailable",
			record: lockRecord{
				SchemaVersion:  lockRecordSchemaV1,
				PID:            definitelyDeadPID(t),
				Operation:      "identity-unavailable-holder",
				StartedAt:      time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC),
				LockID:         strings.Repeat("4", 64),
				IdentityStatus: lockIdentityUnavailable,
			},
			reader: func(int) (processIdentity, error) {
				return processIdentity{}, errProcessIdentityNotFound
			},
			want: "no creation-time process-instance identity",
		},
		{
			name:   "current identity probe unavailable",
			record: fixtureV1LockRecord(os.Getpid(), fixtureProcessIdentity("451")),
			reader: func(int) (processIdentity, error) {
				return processIdentity{}, errProcessIdentityUnavailable
			},
			want: "cannot be probed safely",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			restore := replaceProcessIdentityReader(test.reader)
			defer restore()
			for _, recoverStale := range []bool{false, true} {
				mode := "ordinary"
				if recoverStale {
					mode = "recover"
				}
				t.Run(mode, func(t *testing.T) {
					statePath := filepath.Join(t.TempDir(), ".sow")
					writeLockRecordFixture(t, statePath, test.record)
					lockPath := filepath.Join(statePath, "locks", "state.lock")
					if err := os.Chmod(lockPath, 0o640); err != nil {
						t.Fatal(err)
					}
					fixed := time.Date(2018, 2, 3, 4, 5, 6, 0, time.UTC)
					if err := os.Chtimes(lockPath, fixed, fixed); err != nil {
						t.Fatal(err)
					}
					beforeBody := readLockBytes(t, statePath)
					before := snapshotFilesystemEntry(t, lockPath)
					if _, err := AcquireLock(statePath, "unsafe-replacement", recoverStale); err == nil || !strings.Contains(err.Error(), test.want) {
						t.Fatalf("unsafe v1 recovery was not blocked: %v", err)
					}
					if afterBody := readLockBytes(t, statePath); !bytes.Equal(beforeBody, afterBody) {
						t.Fatal("blocked v1 recovery changed lock evidence")
					}
					assertFilesystemEntryUnchanged(t, lockPath, before)
					if stale := staleLockFiles(t, statePath); len(stale) != 0 {
						t.Fatalf("blocked v1 recovery preserved false stale evidence: %v", stale)
					}
				})
			}
		})
	}
}

func TestStateLockIdentityProbeUnavailableFailsClosed(t *testing.T) {
	restore := replaceProcessIdentityReader(func(int) (processIdentity, error) {
		return processIdentity{}, errProcessIdentityUnavailable
	})
	defer restore()
	statePath := filepath.Join(t.TempDir(), ".sow")
	if _, err := AcquireLock(statePath, "unavailable-identity", false); !errors.Is(err, errProcessIdentityUnavailable) {
		t.Fatalf("identity probe failure did not fail closed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(statePath, "locks", "state.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("identity probe failure retained a state.lock record: %v", err)
	}
	lease, err := os.Lstat(filepath.Join(statePath, "locks", "state.lease"))
	if err != nil || !lease.Mode().IsRegular() || lease.Mode().Perm() != 0o600 {
		t.Fatalf("identity probe failure left an unsafe persistent lease: mode=%v err=%v", lease, err)
	}
}

func TestProcessIdentityCachePinsOnlyTheFirstSuccessfulObservation(t *testing.T) {
	var cache processIdentityCache
	first := fixtureProcessIdentity("700")
	drift := fixtureProcessIdentity("701")
	calls := 0
	reader := func(int) (processIdentity, error) {
		calls++
		switch calls {
		case 1:
			return processIdentity{}, errProcessIdentityUnavailable
		case 2:
			return first, nil
		default:
			return drift, nil
		}
	}
	if _, err := cache.read(os.Getpid(), reader); !errors.Is(err, errProcessIdentityUnavailable) {
		t.Fatalf("transient identity error=%v", err)
	}
	observed, err := cache.read(os.Getpid(), reader)
	if err != nil || observed != first {
		t.Fatalf("first successful identity=%+v err=%v", observed, err)
	}
	observed, err = cache.read(os.Getpid(), reader)
	if err != nil || observed != first || calls != 2 {
		t.Fatalf("cached identity=%+v calls=%d err=%v", observed, calls, err)
	}
}

func TestStateLockHolderRevalidatesProcessInstanceBeforeValidateAndRelease(t *testing.T) {
	acquiredIdentity := fixtureProcessIdentity("601")
	tests := []struct {
		name          string
		probeIdentity processIdentity
		probeErr      error
		want          string
	}{
		{
			name:          "identity mismatch",
			probeIdentity: fixtureProcessIdentity("602"),
			want:          "does not match",
		},
		{
			name:     "identity unavailable",
			probeErr: errProcessIdentityUnavailable,
			want:     "revalidate",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statePath := filepath.Join(t.TempDir(), ".sow")
			currentIdentity := acquiredIdentity
			var currentErr error
			restore := replaceProcessIdentityReader(func(pid int) (processIdentity, error) {
				if pid != os.Getpid() {
					return processIdentity{}, errProcessIdentityNotFound
				}
				return currentIdentity, currentErr
			})
			defer restore()
			lock, err := AcquireLock(statePath, "holder-revalidation", false)
			if err != nil {
				t.Fatal(err)
			}
			currentIdentity, currentErr = test.probeIdentity, test.probeErr

			before := readLockBytes(t, statePath)
			if err := lock.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("holder validation accepted %s: %v", test.name, err)
			}
			if err := lock.Release(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("holder release accepted %s: %v", test.name, err)
			}
			after := readLockBytes(t, statePath)
			if !bytes.Equal(before, after) {
				t.Fatalf("failed holder revalidation deleted or rewrote lock evidence")
			}
			currentIdentity, currentErr = acquiredIdentity, nil
			if err := lock.Release(); err != nil {
				t.Fatalf("holder could not retry release after identity probe recovery: %v", err)
			}
		})
	}
}

func TestStateLockCreateLeaseFailureLeavesNoOrphan(t *testing.T) {
	leaseFailure := errors.New("injected advisory lease failure")
	restore := replaceStateLockLeaseTry(func(file *os.File) (bool, error) {
		if filepath.Base(file.Name()) == "state.lock" {
			return false, leaseFailure
		}
		return tryStateLockLease(file)
	})
	defer restore()
	statePath := filepath.Join(t.TempDir(), ".sow")
	if _, err := AcquireLock(statePath, "lease-failure", false); !errors.Is(err, leaseFailure) {
		t.Fatalf("create lease failure was not returned: %v", err)
	}
	lockPath := filepath.Join(statePath, "locks", "state.lock")
	if _, err := os.Lstat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("create lease failure left an orphan state.lock: %v", err)
	}
	assertStateMode(t, statePath, 0o700)
	assertStateMode(t, filepath.Join(statePath, "locks"), 0o700)
	restore()
	lock, err := AcquireLock(statePath, "after-lease-failure", false)
	if err != nil {
		t.Fatalf("clean retry after lease failure: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestStateLockCreatedButUnacquiredLeaseLeavesNoOrphan(t *testing.T) {
	restore := replaceStateLockLeaseTry(func(file *os.File) (bool, error) {
		if filepath.Base(file.Name()) == "state.lock" {
			return false, nil
		}
		return tryStateLockLease(file)
	})
	defer restore()
	statePath := filepath.Join(t.TempDir(), ".sow")
	if _, err := AcquireLock(statePath, "lease-contended-after-create", false); err == nil || !strings.Contains(err.Error(), "active process instance") {
		t.Fatalf("created-but-unacquired lease did not report contention: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(statePath, "locks", "state.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created-but-unacquired lease left an empty state.lock: %v", err)
	}
}

func TestStateLockCreatePostFlockFailureLeavesNoOrphan(t *testing.T) {
	for _, stage := range []string{stateLeaseFaultChmod, stateLeaseFaultIdentity} {
		t.Run(stage, func(t *testing.T) {
			injected := fmt.Errorf("injected post-flock %s failure", stage)
			restore := replaceStateLockLeaseFault(func(name, observedStage string) error {
				if name == "state.lock" && observedStage == stage {
					return injected
				}
				return nil
			})
			defer restore()
			statePath := filepath.Join(t.TempDir(), ".sow")
			if _, err := AcquireLock(statePath, "post-flock-failure", false); !errors.Is(err, injected) {
				t.Fatalf("post-flock failure was not returned: %v", err)
			}
			lockPath := filepath.Join(statePath, "locks", "state.lock")
			if _, err := os.Lstat(lockPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("post-flock %s failure left an orphan state.lock: %v", stage, err)
			}
			restore()
			lock, err := AcquireLock(statePath, "after-post-flock-failure", false)
			if err != nil {
				t.Fatalf("clean retry after post-flock %s failure: %v", stage, err)
			}
			if err := lock.Release(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPersistentStateLeaseRejectsSymlinkWithoutTouchingTarget(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), ".sow")
	locksPath := filepath.Join(statePath, "locks")
	if err := os.MkdirAll(locksPath, 0o700); err != nil {
		t.Fatal(err)
	}
	targetPath := filepath.Join(locksPath, "lease-target")
	target := []byte("must remain untouched\n")
	if err := os.WriteFile(targetPath, target, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("lease-target", filepath.Join(locksPath, "state.lease")); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(statePath, "symlink-lease", false); err == nil {
		t.Fatal("symlinked persistent lease was accepted")
	}
	afterData, readErr := os.ReadFile(targetPath)
	after, statErr := os.Lstat(targetPath)
	if readErr != nil || statErr != nil || !bytes.Equal(afterData, target) || after.Mode().Perm() != before.Mode().Perm() || !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("symlink rejection touched target: read=%v stat=%v before=%v after=%v data=%q", readErr, statErr, before, after, afterData)
	}
	if _, err := os.Lstat(filepath.Join(locksPath, "state.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("symlinked lease rejection created state.lock: %v", err)
	}
}

func TestPersistentStateLeaseReplacementFailsValidationAndCannotBypassRecordFlock(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), ".sow")
	first, err := AcquireLock(statePath, "first-holder", false)
	if err != nil {
		t.Fatal(err)
	}
	leasePath := filepath.Join(statePath, "locks", "state.lease")
	displacedPath := leasePath + ".displaced"
	if err := os.Rename(leasePath, displacedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leasePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := first.Validate(); err == nil || !strings.Contains(err.Error(), "persistent state lease") {
		t.Fatalf("holder accepted replacement persistent lease: %v", err)
	}
	before := readLockBytes(t, statePath)
	if _, err := AcquireLock(statePath, "replacement-holder", true); err == nil || !strings.Contains(err.Error(), "active process instance") {
		t.Fatalf("replacement lease bypassed held legacy-compatible record flock: %v", err)
	}
	if after := readLockBytes(t, statePath); !bytes.Equal(before, after) {
		t.Fatal("replacement-lease contender changed the held record")
	}
	if err := first.Release(); err != nil {
		t.Fatalf("bound holder could not safely release after lease path replacement: %v", err)
	}
	second, err := AcquireLock(statePath, "replacement-holder", false)
	if err != nil {
		t.Fatalf("replacement persistent lease was unusable after old holder release: %v", err)
	}
	if err := second.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestStateLockReleaseReportsMissingDurableRecord(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), ".sow")
	lock, err := AcquireLock(statePath, "release-failure", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(statePath, "locks", "state.lock")); err != nil {
		t.Fatal(err)
	}
	if err := lock.Release(); err == nil || !strings.Contains(err.Error(), "durable record is missing") {
		t.Fatalf("release did not report the missing durable record: %v", err)
	}

	// Release still closes its advisory leases after reporting the durable
	// identity failure, so a subsequent operation can create a fresh record.
	next, err := AcquireLock(statePath, "after-release-failure", false)
	if err != nil {
		t.Fatalf("release failure stranded the advisory lease: %v", err)
	}
	if err := next.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestPersistentStateLeasePermissionsArePrivateAndNonRegularEntryFailsClosed(t *testing.T) {
	t.Run("widened regular lease is reconciled", func(t *testing.T) {
		statePath := filepath.Join(t.TempDir(), ".sow")
		locksPath := filepath.Join(statePath, "locks")
		if err := os.MkdirAll(locksPath, 0o700); err != nil {
			t.Fatal(err)
		}
		leasePath := filepath.Join(locksPath, "state.lease")
		if err := os.WriteFile(leasePath, nil, 0o666); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(leasePath, 0o666); err != nil {
			t.Fatal(err)
		}
		lock, err := AcquireLock(statePath, "permission-reconcile", false)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(leasePath)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("persistent lease mode=%v err=%v want=0600", info, err)
		}
		if err := lock.Release(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("directory lease is rejected", func(t *testing.T) {
		statePath := filepath.Join(t.TempDir(), ".sow")
		if err := os.MkdirAll(filepath.Join(statePath, "locks", "state.lease"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := AcquireLock(statePath, "directory-lease", false); err == nil {
			t.Fatal("directory persistent lease was accepted")
		}
		if _, err := os.Lstat(filepath.Join(statePath, "locks", "state.lock")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("directory lease rejection created state.lock: %v", err)
		}
	})
}

func TestPreserveStaleLockNeverOverwritesEvidence(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), ".sow")
	writeLockRecordFixture(t, statePath, fixtureV1LockRecord(definitelyDeadPID(t), fixtureProcessIdentity("400")))
	locksRoot, err := os.OpenRoot(filepath.Join(statePath, "locks"))
	if err != nil {
		t.Fatal(err)
	}
	defer locksRoot.Close()
	directory, err := locksRoot.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	file, identity, leaseID, acquired, err := openAdvisoryLease(locksRoot, "state.lock", os.O_RDONLY, 0)
	if err != nil || !acquired {
		t.Fatalf("open fixture lease acquired=%t err=%v", acquired, err)
	}
	defer closeStateLockLease(file, leaseID)
	const staleName = "state.lock.stale-collision"
	prior := []byte("prior evidence\n")
	if err := locksRoot.WriteFile(staleName, prior, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := preserveLeasedStateLock(locksRoot, directory, file, identity, staleName); err == nil {
		t.Fatal("stale preservation overwrote an existing evidence path")
	}
	after, err := locksRoot.ReadFile(staleName)
	if err != nil || !bytes.Equal(after, prior) {
		t.Fatalf("existing stale evidence changed: data=%q err=%v", after, err)
	}
	if _, err := locksRoot.Lstat("state.lock"); err != nil {
		t.Fatalf("failed no-clobber preservation removed the active name: %v", err)
	}
}

func TestStateLockMalformedIdentityFailsClosed(t *testing.T) {
	started := "2026-07-15T00:00:00Z"
	cases := map[string]string{
		"unknown schema":          fmt.Sprintf(`{"schema_version":2,"pid":%d,"operation":"x","started_at":%q,"lock_id":%q,"identity_status":"unavailable"}`+"\n", os.Getpid(), started, strings.Repeat("a", 64)),
		"partial legacy identity": fmt.Sprintf(`{"pid":%d,"operation":"x","started_at":%q,"identity_status":"unavailable"}`+"\n", os.Getpid(), started),
		"invalid lock id":         fmt.Sprintf(`{"schema_version":1,"pid":%d,"operation":"x","started_at":%q,"lock_id":"nope","identity_status":"unavailable"}`+"\n", os.Getpid(), started),
		"invalid identity token":  fmt.Sprintf(`{"schema_version":1,"pid":%d,"operation":"x","started_at":%q,"lock_id":%q,"identity_status":"observed","process_identity":{"scheme":"linux-proc-v1","boot_token":"bad","start_token":"1"}}`+"\n", os.Getpid(), started, strings.Repeat("a", 64)),
		"unknown field":           fmt.Sprintf(`{"schema_version":1,"pid":%d,"operation":"x","started_at":%q,"lock_id":%q,"identity_status":"unavailable","surprise":true}`+"\n", os.Getpid(), started, strings.Repeat("a", 64)),
		"trailing document":       fmt.Sprintf(`{"schema_version":1,"pid":%d,"operation":"x","started_at":%q,"lock_id":%q,"identity_status":"unavailable"} {}`+"\n", os.Getpid(), started, strings.Repeat("a", 64)),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			statePath := filepath.Join(t.TempDir(), ".sow")
			writeRawLockFixture(t, statePath, []byte(raw))
			before := readLockBytes(t, statePath)
			if _, err := AcquireLock(statePath, "replacement", true); err == nil || !strings.Contains(err.Error(), "cannot be recovered automatically") {
				t.Fatalf("malformed lock was automatically recovered: %v", err)
			}
			if after := readLockBytes(t, statePath); !bytes.Equal(before, after) {
				t.Fatal("malformed-lock rejection changed the evidence")
			}
			if len(staleLockFiles(t, statePath)) != 0 {
				t.Fatal("malformed-lock rejection created a stale record")
			}
		})
	}
}

func TestExistingStateLockClassificationFailuresDoNotMutateEvidence(t *testing.T) {
	tests := []struct {
		name    string
		write   func(*testing.T, string)
		reader  func(int) (processIdentity, error)
		recover bool
		want    string
		mode    os.FileMode
	}{
		{
			name: "malformed record",
			write: func(t *testing.T, statePath string) {
				writeRawLockFixture(t, statePath, []byte("{not-json}\n"))
			},
			recover: true,
			want:    "cannot be recovered automatically",
			mode:    0o640,
		},
		{
			name: "stale record without explicit recovery",
			write: func(t *testing.T, statePath string) {
				writeLockRecordFixture(t, statePath, fixtureV1LockRecord(definitelyDeadPID(t), fixtureProcessIdentity("401")))
			},
			reader: func(int) (processIdentity, error) {
				return processIdentity{}, errProcessIdentityNotFound
			},
			recover: false,
			want:    "rerun with --recover",
			mode:    0o640,
		},
		{
			name: "group-writable record",
			write: func(t *testing.T, statePath string) {
				writeLockRecordFixture(t, statePath, fixtureV1LockRecord(definitelyDeadPID(t), fixtureProcessIdentity("402")))
			},
			recover: true,
			want:    "cannot be recovered automatically",
			mode:    0o620,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.reader != nil {
				restore := replaceProcessIdentityReader(test.reader)
				defer restore()
			}
			statePath := filepath.Join(t.TempDir(), ".sow")
			test.write(t, statePath)
			lockPath := filepath.Join(statePath, "locks", "state.lock")
			if err := os.Chmod(lockPath, test.mode); err != nil {
				t.Fatal(err)
			}
			fixed := time.Date(2019, 1, 2, 3, 4, 5, 0, time.UTC)
			if err := os.Chtimes(lockPath, fixed, fixed); err != nil {
				t.Fatal(err)
			}
			beforeBody, err := os.ReadFile(lockPath)
			if err != nil {
				t.Fatal(err)
			}
			before := snapshotFilesystemEntry(t, lockPath)
			if _, err := AcquireLock(statePath, "classification-failure", test.recover); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unexpected classification result: %v", err)
			}
			afterBody, err := os.ReadFile(lockPath)
			if err != nil || !bytes.Equal(beforeBody, afterBody) {
				t.Fatalf("classification failure changed lock bytes: err=%v", err)
			}
			assertFilesystemEntryUnchanged(t, lockPath, before)
		})
	}
}

func TestStateLockHolderDetectsInPlaceIdentityTamper(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), ".sow")
	lock, err := AcquireLock(statePath, "holder", false)
	if err != nil {
		t.Fatal(err)
	}
	record := readLockRecordFixture(t, statePath)
	if record.LockID == strings.Repeat("a", 64) {
		record.LockID = strings.Repeat("b", 64)
	} else {
		record.LockID = strings.Repeat("a", 64)
	}
	lockPath := filepath.Join(statePath, "locks", "state.lock")
	file, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	encodeErr := json.NewEncoder(file).Encode(record)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(encodeErr, syncErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if err := lock.Validate(); err == nil || !strings.Contains(err.Error(), "no longer identifies") {
		t.Fatalf("holder accepted in-place lock identity tamper: %v", err)
	}
	if err := lock.Release(); err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Fatalf("release removed a tampered lock identity: %v", err)
	}
	if _, err := os.Lstat(lockPath); err != nil {
		t.Fatalf("tampered lock evidence was removed: %v", err)
	}
}

func TestLinuxProcStatStartTokenParser(t *testing.T) {
	stat := "42 (command with ) parentheses) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242 20 21\n"
	if token, err := parseLinuxProcStatStartToken(42, []byte(stat)); err != nil || token != "424242" {
		t.Fatalf("parse proc stat start token=%q err=%v", token, err)
	}
	zombie := strings.Replace(stat, ") S ", ") Z ", 1)
	state, token, err := parseLinuxProcStatIdentity(42, []byte(zombie))
	if err != nil || token != "424242" || state != "Z" || !linuxProcessStateIsDead(state) {
		t.Fatalf("parse zombie proc stat state=%q token=%q dead=%t err=%v", state, token, linuxProcessStateIsDead(state), err)
	}
	for _, malformed := range []string{
		"41 (wrong pid) S 1 2 3",
		"42 missing-parenthesis S 1 2 3",
		"42 (short) S 1 2 3",
		"42 (bad start) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 nope",
	} {
		if _, err := parseLinuxProcStatStartToken(42, []byte(malformed)); err == nil {
			t.Fatalf("accepted malformed proc stat %q", malformed)
		}
	}
}

func fixtureProcessIdentity(start string) processIdentity {
	return processIdentity{
		Scheme:     processIdentityLinuxV1,
		BootToken:  "11111111-2222-3333-4444-555555555555",
		StartToken: start,
	}
}

func fixtureV1LockRecord(pid int, identity processIdentity) lockRecord {
	return lockRecord{
		SchemaVersion:   lockRecordSchemaV1,
		PID:             pid,
		Operation:       "fixture-holder",
		StartedAt:       time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC),
		LockID:          strings.Repeat("1", 64),
		IdentityStatus:  lockIdentityObserved,
		ProcessIdentity: &identity,
	}
}

func fixtureLegacyLockRecord(pid int) lockRecord {
	return lockRecord{
		PID:       pid,
		Operation: "legacy-holder",
		StartedAt: time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC),
	}
}

func definitelyDeadPID(t *testing.T) int {
	t.Helper()
	for pid := 1_000_000_000; pid > 999_999_900; pid-- {
		if !processAlive(pid) {
			return pid
		}
	}
	t.Fatal("could not find a definitely dead PID for the lock test")
	return 0
}

func writeLockRecordFixture(t *testing.T, statePath string, record lockRecord) {
	t.Helper()
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	writeRawLockFixture(t, statePath, append(data, '\n'))
}

func writeRawLockFixture(t *testing.T, statePath string, data []byte) {
	t.Helper()
	lockDirectory := filepath.Join(statePath, "locks")
	if err := os.MkdirAll(lockDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lockDirectory, "state.lock"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readLockBytes(t *testing.T, statePath string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(statePath, "locks", "state.lock"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func readLockRecordFixture(t *testing.T, statePath string) lockRecord {
	t.Helper()
	return decodeLockRecordFixture(t, readLockBytes(t, statePath))
}

func readLockRecordPath(t *testing.T, path string) lockRecord {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return decodeLockRecordFixture(t, data)
}

func decodeLockRecordFixture(t *testing.T, data []byte) lockRecord {
	t.Helper()
	var record lockRecord
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	return record
}

func staleLockFiles(t *testing.T, statePath string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(statePath, "locks", "state.lock.stale-*"))
	if err != nil {
		t.Fatal(err)
	}
	return files
}
