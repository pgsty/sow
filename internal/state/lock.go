package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type lockRecord struct {
	PID       int       `json:"pid"`
	Operation string    `json:"operation"`
	StartedAt time.Time `json:"started_at"`
}

type Lock struct {
	path string
}

func AcquireLock(stateDir, operation string, recoverStale bool) (*Lock, error) {
	lockDir := filepath.Join(stateDir, "locks")
	if err := os.MkdirAll(lockDir, 0o700); err != nil {
		return nil, fmt.Errorf("create lock directory: %w", err)
	}
	lockPath := filepath.Join(lockDir, "state.lock")
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			record := lockRecord{PID: os.Getpid(), Operation: operation, StartedAt: time.Now().UTC()}
			encodeErr := json.NewEncoder(f).Encode(record)
			syncErr := f.Sync()
			closeErr := f.Close()
			if encodeErr != nil || syncErr != nil || closeErr != nil {
				_ = os.Remove(lockPath)
				return nil, errors.Join(encodeErr, syncErr, closeErr)
			}
			return &Lock{path: lockPath}, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("acquire state lock: %w", err)
		}
		record, recordErr := readLock(lockPath)
		if recordErr == nil && processAlive(record.PID) {
			return nil, fmt.Errorf("state is locked by pid %d running %s since %s", record.PID, record.Operation, record.StartedAt.Format(time.RFC3339))
		}
		if !recoverStale {
			if recordErr != nil {
				return nil, fmt.Errorf("stale or unreadable state lock exists at %s; rerun with --recover: %w", lockPath, recordErr)
			}
			return nil, fmt.Errorf("stale state lock from pid %d (%s) exists; rerun with --recover", record.PID, record.Operation)
		}
		stale := fmt.Sprintf("%s.stale-%d", lockPath, time.Now().UTC().UnixNano())
		if err := os.Rename(lockPath, stale); err != nil {
			return nil, fmt.Errorf("preserve stale lock: %w", err)
		}
	}
	return nil, errors.New("could not acquire state lock after recovering stale lock")
}

func readLock(path string) (lockRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return lockRecord{}, err
	}
	defer f.Close()
	var record lockRecord
	if err := json.NewDecoder(f).Decode(&record); err != nil {
		return lockRecord{}, err
	}
	if record.PID <= 0 || record.Operation == "" || record.StartedAt.IsZero() {
		return lockRecord{}, errors.New("lock record is incomplete")
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
	if l == nil || l.path == "" {
		return nil
	}
	err := os.Remove(l.path)
	l.path = ""
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
