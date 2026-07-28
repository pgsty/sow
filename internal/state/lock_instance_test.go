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
	"syscall"
	"testing"
	"time"
)

const lockHelperStateEnv = "SOW_TEST_STATE_LOCK_HELPER_ROOT"
const lockHelperModeEnv = "SOW_TEST_STATE_LOCK_HELPER_MODE"
const stateLockCrashExitCode = 86

func TestStateLockHelperProcess(t *testing.T) {
	statePath := os.Getenv(lockHelperStateEnv)
	if statePath == "" {
		return
	}
	switch os.Getenv(lockHelperModeEnv) {
	case "crash-before-publish":
		crashStateLockPublish(t, stateLeaseFaultBeforePublish)
		return
	case "crash-after-publish":
		crashStateLockPublish(t, stateLeaseFaultAfterPublish)
		return
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

func crashStateLockPublish(t *testing.T, crashStage string) {
	restore := replaceStateLockLeaseFault(func(name, stage string) error {
		if name == "state.lock" && stage == crashStage {
			os.Exit(stateLockCrashExitCode)
		}
		return nil
	})
	defer restore()
	if _, err := AcquireLock(os.Getenv(lockHelperStateEnv), "crash-during-lock-publication", false); err != nil {
		t.Fatal(err)
	}
	t.Fatal("state lock publication crash seam was not reached")
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
	if _, err := AcquireLock(statePath, "new-holder", false); err == nil || !strings.Contains(err.Error(), "group/other writable") {
		t.Fatalf("unsafe control child was repaired or accepted after legacy record flock release: %v", err)
	}
	afterUnsafe, err := os.Lstat(controlPath)
	if err != nil || afterUnsafe.Mode().Perm() != beforeControl.Mode().Perm() ||
		!afterUnsafe.ModTime().Equal(beforeControl.ModTime()) {
		t.Fatalf("unsafe control child changed after rejection: before=%v after=%v err=%v", beforeControl, afterUnsafe, err)
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
		if strings.HasPrefix(filepath.Base(file.Name()), stateLockUnpublishedPrefix) {
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
		if strings.HasPrefix(filepath.Base(file.Name()), stateLockUnpublishedPrefix) {
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
				if strings.HasPrefix(name, stateLockUnpublishedPrefix) && observedStage == stage {
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

func TestStateLockLeaseRejectsHardlinkBeforeChmodWithoutMutatingAlias(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), ".sow")
	if err := os.MkdirAll(filepath.Join(statePath, "locks"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(statePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(statePath, "locks"), 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "state-lock-alias")
	fired := false
	restoreFault := replaceStateLockLeaseFault(func(name, stage string) error {
		if fired || stage != stateLeaseFaultChmod || !strings.HasPrefix(name, stateLockUnpublishedPrefix) {
			return nil
		}
		fired = true
		return os.Link(filepath.Join(statePath, "locks", name), alias)
	})
	defer restoreFault()
	previousUmask := syscall.Umask(0o777)
	defer syscall.Umask(previousUmask)

	if _, err := AcquireLock(statePath, "hardlink-before-chmod", false); err == nil ||
		!strings.Contains(err.Error(), "link count") {
		t.Fatalf("hardlink-aliased lease was chmodded or admitted: %v", err)
	}
	if !fired {
		t.Fatal("hardlink race was not injected")
	}
	aliasInfo, err := os.Lstat(alias)
	if err != nil {
		t.Fatal(err)
	}
	if aliasInfo.Mode().Perm() != 0 {
		t.Fatalf("hardlink alias mode changed before rejection: %#o", aliasInfo.Mode().Perm())
	}
	pending, err := filepath.Glob(filepath.Join(statePath, "locks", stateLockUnpublishedPrefix+"*"))
	if err != nil || len(pending) != 1 {
		t.Fatalf("hardlink evidence paths=%v err=%v", pending, err)
	}
	pendingInfo, err := os.Lstat(pending[0])
	if err != nil || !os.SameFile(aliasInfo, pendingInfo) {
		t.Fatalf("hardlink evidence was not preserved: pending=%v err=%v", pendingInfo, err)
	}
}

func TestStateLockPublicationCrashNeverLeavesPartialAuthoritativeRecord(t *testing.T) {
	tests := []struct {
		name             string
		helperMode       string
		visibleAfterExit bool
	}{
		{name: "before atomic publish", helperMode: "crash-before-publish"},
		{name: "after atomic publish", helperMode: "crash-after-publish", visibleAfterExit: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			statePath := filepath.Join(t.TempDir(), ".sow")
			command := exec.Command(os.Args[0], "-test.run=^TestStateLockHelperProcess$")
			command.Env = append(os.Environ(), lockHelperStateEnv+"="+statePath, lockHelperModeEnv+"="+test.helperMode)
			err := command.Run()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != stateLockCrashExitCode {
				t.Fatalf("publication crash helper exit=%v want=%d", err, stateLockCrashExitCode)
			}

			lockPath := filepath.Join(statePath, "locks", "state.lock")
			visibleInfo, visibleErr := os.Lstat(lockPath)
			pending := unpublishedLockFiles(t, statePath)
			var evidencePath string
			if test.visibleAfterExit {
				if len(pending) != 0 {
					t.Fatalf("post-publish crash retained a hardlink-era pending alias: %v", pending)
				}
				if visibleErr != nil || visibleInfo == nil || !visibleInfo.Mode().IsRegular() || visibleInfo.Mode().Perm() != 0o600 {
					t.Fatalf("post-publish crash did not leave one complete canonical record: visible=%v err=%v", visibleInfo, visibleErr)
				}
				evidencePath = lockPath
			} else {
				if len(pending) != 1 {
					t.Fatalf("pre-publish crash pending evidence=%v want exactly one", pending)
				}
				if !errors.Is(visibleErr, os.ErrNotExist) {
					t.Fatalf("pre-publish crash exposed an authoritative state.lock: %v", visibleErr)
				}
				evidencePath = pending[0]
			}
			evidenceInfo, err := os.Lstat(evidencePath)
			if err != nil || evidenceInfo == nil || !evidenceInfo.Mode().IsRegular() || evidenceInfo.Mode().Perm() != 0o600 {
				t.Fatalf("crash lock evidence is unsafe: info=%v err=%v", evidenceInfo, err)
			}
			evidenceBody, err := os.ReadFile(evidencePath)
			if err != nil {
				t.Fatal(err)
			}
			evidenceRecord := decodeLockRecordFixture(t, evidenceBody)
			if _, err := evidenceRecord.kind(); err != nil || evidenceRecord.PID != command.Process.Pid {
				t.Fatalf("crash lock record is incomplete: record=%+v err=%v child_pid=%d", evidenceRecord, err, command.Process.Pid)
			}

			if test.visibleAfterExit {
				if _, err := AcquireLock(statePath, "after-publish-crash", false); err == nil || !strings.Contains(err.Error(), "rerun with --recover") {
					t.Fatalf("complete crashed publication was not reported as recoverable stale evidence: %v", err)
				}
				lock, err := AcquireLock(statePath, "after-publish-crash", true)
				if err != nil {
					t.Fatalf("recover complete crash-published record: %v", err)
				}
				stale := staleLockFiles(t, statePath)
				if len(stale) != 1 {
					t.Fatalf("post-publish crash recovery stale evidence=%v want one", stale)
				}
				staleBody, err := os.ReadFile(stale[0])
				if err != nil || !bytes.Equal(staleBody, evidenceBody) {
					t.Fatalf("post-publish crash recovery changed old evidence: err=%v", err)
				}
				if err := lock.Release(); err != nil {
					t.Fatal(err)
				}
			} else {
				lock, err := AcquireLock(statePath, "after-unpublished-crash", false)
				if err != nil {
					t.Fatalf("unpublished crash evidence incorrectly required recovery: %v", err)
				}
				if err := lock.Release(); err != nil {
					t.Fatal(err)
				}
			}

			if !test.visibleAfterExit {
				afterEvidence, err := os.Lstat(evidencePath)
				afterBody, readErr := os.ReadFile(evidencePath)
				if err != nil || readErr != nil || !os.SameFile(evidenceInfo, afterEvidence) || !bytes.Equal(evidenceBody, afterBody) {
					t.Fatalf("later acquisition changed unpublished crash evidence: stat=%v read=%v", err, readErr)
				}
			}
			if _, err := os.Lstat(lockPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("successful release retained authoritative state.lock: %v", err)
			}
		})
	}
}

func TestStateLockPublicationFailureRemovesPreparedAndVisibleNames(t *testing.T) {
	for _, stage := range []string{stateLeaseFaultBeforePublish, stateLeaseFaultAfterPublish} {
		t.Run(stage, func(t *testing.T) {
			injected := fmt.Errorf("injected state lock publication failure at %s", stage)
			restore := replaceStateLockLeaseFault(func(name, observedStage string) error {
				if name == "state.lock" && observedStage == stage {
					return injected
				}
				return nil
			})
			defer restore()
			statePath := filepath.Join(t.TempDir(), ".sow")
			if _, err := AcquireLock(statePath, "publication-failure", false); !errors.Is(err, injected) {
				t.Fatalf("publication failure was not returned: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(statePath, "locks", "state.lock")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("publication failure retained authoritative state.lock: %v", err)
			}
			if pending := unpublishedLockFiles(t, statePath); len(pending) != 0 {
				t.Fatalf("publication failure retained prepared names: %v", pending)
			}
			restore()
			lock, err := AcquireLock(statePath, "after-publication-failure", false)
			if err != nil {
				t.Fatalf("clean retry after publication failure: %v", err)
			}
			if err := lock.Release(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestStateLockPublicationSyncIsRequiredBeforePublishedHook(t *testing.T) {
	t.Run("sync failure rolls back visible coordinate", func(t *testing.T) {
		injected := errors.New("injected publication parent sync failure")
		previousSync := stateLockPublicationParentSync
		stateLockPublicationParentSync = func(*os.File) error { return injected }
		t.Cleanup(func() { stateLockPublicationParentSync = previousSync })
		statePath := filepath.Join(t.TempDir(), ".sow")
		if _, err := AcquireLock(statePath, "publication-sync-failure", false); !errors.Is(err, injected) {
			t.Fatalf("publication sync failure was not returned: %v", err)
		}
		for _, name := range []string{"state.lock"} {
			if _, err := os.Lstat(filepath.Join(statePath, "locks", name)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("publication sync failure retained %s: %v", name, err)
			}
		}
		if pending := unpublishedLockFiles(t, statePath); len(pending) != 0 {
			t.Fatalf("publication sync failure retained prepared names: %v", pending)
		}
	})

	t.Run("durability barrier precedes published hook", func(t *testing.T) {
		previousSync := stateLockPublicationParentSync
		synced := false
		stateLockPublicationParentSync = func(directory *os.File) error {
			synced = true
			return directory.Sync()
		}
		t.Cleanup(func() { stateLockPublicationParentSync = previousSync })
		injected := errors.New("stop after durable publication")
		restoreFault := replaceStateLockLeaseFault(func(name, stage string) error {
			if name == "state.lock" && stage == stateLeaseFaultAfterPublish {
				if !synced {
					return errors.New("published hook ran before parent sync")
				}
				return injected
			}
			return nil
		})
		defer restoreFault()
		statePath := filepath.Join(t.TempDir(), ".sow")
		if _, err := AcquireLock(statePath, "publication-sync-order", false); !errors.Is(err, injected) {
			t.Fatalf("post-sync publication hook did not run in order: %v", err)
		}
	})
}

func TestPartialUnpublishedStateLockIsPreservedButNeverAuthoritative(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), ".sow")
	locksPath := filepath.Join(statePath, "locks")
	if err := os.MkdirAll(locksPath, 0o700); err != nil {
		t.Fatal(err)
	}
	pendingPath := filepath.Join(locksPath, stateLockUnpublishedPrefix+strings.Repeat("a", 64))
	partial := []byte(`{"schema_version":1`)
	if err := os.WriteFile(pendingPath, partial, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(pendingPath)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := AcquireLock(statePath, "after-partial-unpublished-record", false)
	if err != nil {
		t.Fatalf("partial unpublished evidence blocked ordinary acquisition: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(pendingPath)
	afterBody, readErr := os.ReadFile(pendingPath)
	if err != nil || readErr != nil || !os.SameFile(before, after) || !bytes.Equal(partial, afterBody) {
		t.Fatalf("ordinary acquisition changed partial unpublished evidence: stat=%v read=%v", err, readErr)
	}
	if _, err := os.Lstat(filepath.Join(locksPath, "state.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successful release retained authoritative state.lock: %v", err)
	}
}

func TestStateLockAtomicPublishCollisionCleansOnlyPreparedInode(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), ".sow")
	lockPath := filepath.Join(statePath, "locks", "state.lock")
	collisionRecord := fixtureLegacyLockRecord(definitelyDeadPID(t))
	var collisionBody []byte
	injected := false
	restore := replaceStateLockLeaseFault(func(name, stage string) error {
		if name != "state.lock" || stage != stateLeaseFaultBeforePublish || injected {
			return nil
		}
		injected = true
		file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
		if err != nil {
			return err
		}
		encodeErr := json.NewEncoder(file).Encode(collisionRecord)
		syncErr := file.Sync()
		closeErr := file.Close()
		if err := errors.Join(encodeErr, syncErr, closeErr); err != nil {
			return err
		}
		collisionBody, err = os.ReadFile(lockPath)
		return err
	})
	defer restore()
	if _, err := AcquireLock(statePath, "atomic-publish-collision", false); err == nil || !strings.Contains(err.Error(), "rerun with --recover") {
		t.Fatalf("collision record was not classified after atomic link lost the race: %v", err)
	}
	if !injected {
		t.Fatal("atomic publication collision seam was not reached")
	}
	if pending := unpublishedLockFiles(t, statePath); len(pending) != 0 {
		t.Fatalf("atomic publication collision retained its private prepared inode: %v", pending)
	}
	after, err := os.ReadFile(lockPath)
	if err != nil || !bytes.Equal(after, collisionBody) {
		t.Fatalf("atomic publication collision changed the winning record: read=%v", err)
	}
	restore()
	lock, err := AcquireLock(statePath, "recover-atomic-publish-collision", true)
	if err != nil {
		t.Fatalf("recover collision winner: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestStateLockVisibleReplacementFailsBeforePermissionReconciliation(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), ".sow")
	if err := os.MkdirAll(statePath, 0o700); err != nil {
		t.Fatal(err)
	}
	controlPath := filepath.Join(statePath, "must-not-be-reconciled")
	if err := os.WriteFile(controlPath, []byte("control\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(controlPath, 0o666); err != nil {
		t.Fatal(err)
	}
	beforeControl, err := os.Lstat(controlPath)
	if err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(statePath, "locks", "state.lock")
	displacedPath := lockPath + ".displaced-during-publish"
	replacement := []byte("foreign replacement must remain untouched\n")
	replaced := false
	restore := replaceStateLockLeaseFault(func(name, stage string) error {
		if name != "state.lock" || stage != stateLeaseFaultAfterPublish || replaced {
			return nil
		}
		replaced = true
		if err := os.Rename(lockPath, displacedPath); err != nil {
			return err
		}
		return os.WriteFile(lockPath, replacement, 0o600)
	})
	defer restore()
	if _, err := AcquireLock(statePath, "visible-replacement", false); err == nil || !strings.Contains(err.Error(), "before protected corridor preparation") {
		t.Fatalf("visible state.lock replacement was not rejected before permission reconciliation: %v", err)
	}
	if !replaced {
		t.Fatal("visible replacement seam was not reached")
	}
	afterControl, err := os.Lstat(controlPath)
	if err != nil || afterControl.Mode().Perm() != beforeControl.Mode().Perm() || !afterControl.ModTime().Equal(beforeControl.ModTime()) {
		t.Fatalf("failed pre-mutation validation reconciled unrelated control permissions: before=%v after=%v err=%v", beforeControl, afterControl, err)
	}
	afterReplacement, err := os.ReadFile(lockPath)
	if err != nil || !bytes.Equal(afterReplacement, replacement) {
		t.Fatalf("failed pre-mutation validation changed replacement state.lock: read=%v", err)
	}
	displaced, err := os.Lstat(displacedPath)
	if err != nil || !displaced.Mode().IsRegular() {
		t.Fatalf("failed pre-mutation validation removed displaced original evidence: info=%v err=%v", displaced, err)
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
	if err := first.Release(); err == nil || !strings.Contains(err.Error(), "persistent state lease") {
		t.Fatalf("release did not preserve a replaced persistent lease: %v", err)
	}
	replacementPath := leasePath + ".replacement"
	if err := os.Rename(leasePath, replacementPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(displacedPath, leasePath); err != nil {
		t.Fatal(err)
	}
	if err := first.Release(); err != nil {
		t.Fatalf("bound holder could not retry release after restoring its exact persistent lease: %v", err)
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
	lockPath := filepath.Join(statePath, "locks", "state.lock")
	displacedPath := filepath.Join(statePath, "locks", "state.lock.displaced-test")
	if err := os.Rename(lockPath, displacedPath); err != nil {
		t.Fatal(err)
	}
	if err := lock.Release(); err == nil || !strings.Contains(err.Error(), "durable record is missing") {
		t.Fatalf("release did not report the missing durable record: %v", err)
	}
	if err := os.Rename(displacedPath, lockPath); err != nil {
		t.Fatal(err)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("holder could not retry release after restoring its exact durable record: %v", err)
	}
	next, err := AcquireLock(statePath, "after-release-failure", false)
	if err != nil {
		t.Fatalf("release failure stranded the advisory lease: %v", err)
	}
	if err := next.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestStateLockReleaseRetainsLeaseWhenExactRemovalDidNotCommit(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), ".sow")
	lock, err := AcquireLock(statePath, "retryable-release", false)
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected pre-remove failure")
	restore := replaceStateLockLeaseFault(func(name, stage string) error {
		if name == "state.lock" && stage == stateLeaseFaultBeforeRemove {
			return injected
		}
		return nil
	})
	t.Cleanup(restore)
	if err := lock.Release(); !errors.Is(err, injected) {
		t.Fatalf("release did not report pre-remove failure: %v", err)
	}
	if err := lock.Validate(); err != nil {
		t.Fatalf("pre-remove failure discarded the live binding: %v", err)
	}
	if _, err := AcquireLock(statePath, "blocked-contender", false); err == nil ||
		!strings.Contains(err.Error(), "active process instance") {
		t.Fatalf("pre-remove failure released the persistent lease: %v", err)
	}
	restore()
	if err := lock.Release(); err != nil {
		t.Fatalf("release retry after pre-remove failure: %v", err)
	}
	next, err := AcquireLock(statePath, "after-retry", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := next.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestStateLockReleaseClosesLeaseAfterRemovalCommittedWithSyncError(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), ".sow")
	lock, err := AcquireLock(statePath, "committed-release", false)
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected post-remove sync failure")
	restore := replaceStateLockLeaseFault(func(name, stage string) error {
		if name == "state.lock" && stage == stateLeaseFaultAfterRemove {
			return injected
		}
		return nil
	})
	t.Cleanup(restore)
	if err := lock.Release(); !errors.Is(err, injected) {
		t.Fatalf("release did not report committed removal sync failure: %v", err)
	}
	restore()
	next, err := AcquireLock(statePath, "after-committed-removal", false)
	if err != nil {
		t.Fatalf("committed removal sync failure stranded the lease: %v", err)
	}
	if err := next.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestPersistentStateLeasePermissionsArePrivateAndNonRegularEntryFailsClosed(t *testing.T) {
	t.Run("widened regular lease is rejected without mutation", func(t *testing.T) {
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
		before := snapshotFilesystemEntry(t, leasePath)
		if _, err := AcquireLock(statePath, "permission-reconcile", false); err == nil ||
			!strings.Contains(err.Error(), "group/other writable") {
			t.Fatalf("widened persistent lease was accepted: %v", err)
		}
		assertFilesystemEntryUnchanged(t, leasePath, before)
		if _, err := os.Lstat(filepath.Join(locksPath, "state.lock")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("widened lease rejection created state.lock: %v", err)
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
			want:    "group/other writable",
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
	originalBody, err := os.ReadFile(filepath.Join(statePath, "locks", "state.lock"))
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
	if err := lock.Release(); err == nil || !strings.Contains(err.Error(), "no longer identifies") {
		t.Fatalf("release removed a tampered lock identity: %v", err)
	}
	if _, err := os.Lstat(lockPath); err != nil {
		t.Fatalf("tampered lock evidence was removed: %v", err)
	}
	file, err = os.OpenFile(lockPath, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.Write(originalBody)
	syncErr = file.Sync()
	closeErr = file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("holder could not retry release after restoring its exact record: %v", err)
	}
}

func TestStateLockReleaseRejectsHardlinkAtUnlinkBoundary(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), ".sow")
	lock, err := AcquireLock(statePath, "unlink-boundary", false)
	if err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(statePath, "locks", "state.lock")
	alias := filepath.Join(t.TempDir(), "state-lock-alias")
	linked := false
	restore := replaceStateLockLeaseFault(func(name, stage string) error {
		if linked || name != "state.lock" || stage != stateLeaseFaultBeforeRemove {
			return nil
		}
		linked = true
		return os.Link(lockPath, alias)
	})
	defer restore()

	if err := lock.Release(); err == nil || !strings.Contains(err.Error(), "link count") {
		t.Fatalf("release accepted a hardlink introduced at the unlink boundary: %v", err)
	}
	if !linked {
		t.Fatal("unlink-boundary fault seam was not reached")
	}
	lockInfo, lockErr := os.Lstat(lockPath)
	aliasInfo, aliasErr := os.Lstat(alias)
	if lockErr != nil || aliasErr != nil || !os.SameFile(lockInfo, aliasInfo) {
		t.Fatalf("release removed hardlinked lock evidence: lock=%v alias=%v lockErr=%v aliasErr=%v", lockInfo, aliasInfo, lockErr, aliasErr)
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := lock.Validate(); err != nil {
		t.Fatalf("holder could not revalidate after external alias removal: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("holder could not retry exact release after alias removal: %v", err)
	}
	if _, err := os.Lstat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state lock remains after successful retry: %v", err)
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

func unpublishedLockFiles(t *testing.T, statePath string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(statePath, "locks", stateLockUnpublishedPrefix+"*"))
	if err != nil {
		t.Fatal(err)
	}
	return files
}
