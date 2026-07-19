package publish

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const journalSchema = "sow-publish-journal/v1"

type publishJournal struct {
	Schema                   string     `json:"schema"`
	Target                   TargetName `json:"target"`
	TransactionID            string     `json:"transaction_id"`
	Generation               uint64     `json:"generation"`
	GenerationSHA256         string     `json:"generation_sha256"`
	PlanSHA256               string     `json:"plan_sha256"`
	CheckpointSHA256         string     `json:"checkpoint_sha256"`
	ExpectedExists           bool       `json:"expected_exists"`
	ExpectedGeneration       uint64     `json:"expected_generation"`
	ExpectedCheckpointSHA256 string     `json:"expected_checkpoint_sha256,omitempty"`
	ExpectedETag             string     `json:"expected_etag,omitempty"`
	RequestUpdatedAt         string     `json:"request_updated_at"`
	Phase                    Phase      `json:"phase"`
	LockToken                string     `json:"lock_token,omitempty"`
	CompletedObjects         []string   `json:"completed_objects"`
	CreatedAt                string     `json:"created_at"`
	UpdatedAt                string     `json:"updated_at"`
}

type journalStore struct {
	dir string
	now func() time.Time
}

func (s journalStore) path(target TargetName, transactionID string) (string, error) {
	if err := target.Validate(); err != nil {
		return "", err
	}
	if !transactionIDPat.MatchString(transactionID) {
		return "", errors.New("invalid publish transaction ID")
	}
	if s.dir == "" {
		return "", errors.New("publish journal directory is required")
	}
	return filepath.Join(s.dir, fmt.Sprintf("%s-%s.json", target, transactionID)), nil
}

type journalUnlock func() error

func propagateJournalUnlock(unlock journalUnlock, resultErr *error) {
	if unlock == nil || resultErr == nil {
		return
	}
	*resultErr = errors.Join(*resultErr, unlock())
}

func (s journalStore) acquire(ctx context.Context, target TargetName, transactionID string) (journalUnlock, error) {
	if _, err := s.path(target, transactionID); err != nil {
		return nil, err
	}
	if err := s.ensureDirectory(); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(s.dir)
	if err != nil {
		return nil, fmt.Errorf("open publish journal root: %w", err)
	}
	lockName := fmt.Sprintf(".%s-%s.lock", target, transactionID)
	if info, err := root.Lstat(lockName); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return nil, errors.Join(errors.New("unsafe publish journal lock file"), root.Close())
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.Join(err, root.Close())
	}
	lock, err := root.OpenFile(lockName, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("open publish journal lock: %w", err), root.Close())
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	for {
		err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			ticker.Stop()
			unlock := journalUnlock(func() error {
				return errors.Join(unix.Flock(int(lock.Fd()), unix.LOCK_UN), lock.Close())
			})
			if closeErr := root.Close(); closeErr != nil {
				return nil, errors.Join(fmt.Errorf("close publish journal root: %w", closeErr), unlock())
			}
			return unlock, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			ticker.Stop()
			return nil, errors.Join(fmt.Errorf("lock publish journal: %w", err), lock.Close(), root.Close())
		}
		select {
		case <-ctx.Done():
			ticker.Stop()
			return nil, errors.Join(ctx.Err(), lock.Close(), root.Close())
		case <-ticker.C:
		}
	}
}

func (s journalStore) ensureDirectory() error {
	if s.dir == "" {
		return errors.New("publish journal directory is required")
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("create publish journal directory: %w", err)
	}
	info, err := os.Lstat(s.dir)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("publish journal directory must be a private non-symlink directory")
	}
	return nil
}

func (s journalStore) loadOrCreate(request Request, generationSHA, planSHA, checkpointSHA string) (*publishJournal, bool, string, error) {
	path, err := s.path(request.Generation.Target, request.TransactionID)
	if err != nil {
		return nil, false, "", err
	}
	data, err := readJournalFile(path)
	if err == nil {
		journal, err := decodeJournal(data)
		if err != nil {
			return nil, false, path, err
		}
		if journal.Target != request.Generation.Target || journal.TransactionID != request.TransactionID ||
			journal.Generation != request.Generation.Generation || journal.GenerationSHA256 != generationSHA ||
			journal.PlanSHA256 != planSHA || journal.CheckpointSHA256 != checkpointSHA ||
			journal.ExpectedExists != request.Expected.Exists || journal.ExpectedGeneration != request.Expected.Generation ||
			journal.ExpectedCheckpointSHA256 != request.Expected.CheckpointSHA256 || journal.ExpectedETag != request.Expected.ETag ||
			journal.RequestUpdatedAt != request.UpdatedAt.UTC().Format(time.RFC3339Nano) {
			return nil, false, path, ErrJournalConflict
		}
		return &journal, false, path, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, path, err
	}
	now := s.now
	if now == nil {
		now = time.Now
	}
	stamp := now().UTC().Format(time.RFC3339Nano)
	journal := publishJournal{
		Schema: journalSchema, Target: request.Generation.Target, TransactionID: request.TransactionID,
		Generation: request.Generation.Generation, GenerationSHA256: generationSHA, PlanSHA256: planSHA,
		CheckpointSHA256: checkpointSHA,
		ExpectedExists:   request.Expected.Exists, ExpectedGeneration: request.Expected.Generation,
		ExpectedCheckpointSHA256: request.Expected.CheckpointSHA256, ExpectedETag: request.Expected.ETag,
		RequestUpdatedAt: request.UpdatedAt.UTC().Format(time.RFC3339Nano),
		Phase:            PhasePlanned, CreatedAt: stamp, UpdatedAt: stamp,
	}
	if err := s.write(path, &journal); err != nil {
		return nil, false, path, err
	}
	return &journal, true, path, nil
}

func (s journalStore) advance(path string, journal *publishJournal, phase Phase, lockToken string) error {
	if err := phase.Validate(); err != nil {
		return err
	}
	if phaseOrder[phase] < phaseOrder[journal.Phase] {
		return fmt.Errorf("publish journal cannot move backward from %s to %s", journal.Phase, phase)
	}
	journal.Phase = phase
	if lockToken != "" {
		journal.LockToken = lockToken
	}
	now := s.now
	if now == nil {
		now = time.Now
	}
	journal.UpdatedAt = now().UTC().Format(time.RFC3339Nano)
	return s.write(path, journal)
}

func (s journalStore) completeObject(path string, journal *publishJournal, identity string) error {
	if strings.ContainsAny(identity, "\x00\r\n\t") || identity == "" {
		return errors.New("invalid journal object identity")
	}
	index := sort.SearchStrings(journal.CompletedObjects, identity)
	if index < len(journal.CompletedObjects) && journal.CompletedObjects[index] == identity {
		return nil
	}
	journal.CompletedObjects = append(journal.CompletedObjects, "")
	copy(journal.CompletedObjects[index+1:], journal.CompletedObjects[index:])
	journal.CompletedObjects[index] = identity
	now := s.now
	if now == nil {
		now = time.Now
	}
	journal.UpdatedAt = now().UTC().Format(time.RFC3339Nano)
	return s.write(path, journal)
}

func (s journalStore) write(path string, journal *publishJournal) error {
	data, err := journal.canonical()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	tmp, tmpName, err := createRootTemp(root, ".publish-journal-")
	if err != nil {
		return err
	}
	cleanup := func() { _ = root.Remove(tmpName) }
	defer cleanup()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := root.Rename(tmpName, filepath.Base(path)); err != nil {
		return err
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func (j publishJournal) canonical() ([]byte, error) {
	if j.Schema != journalSchema || j.Target.Validate() != nil || !transactionIDPat.MatchString(j.TransactionID) || j.Generation == 0 ||
		!hexSHA256Pattern.MatchString(j.GenerationSHA256) || !hexSHA256Pattern.MatchString(j.PlanSHA256) ||
		!hexSHA256Pattern.MatchString(j.CheckpointSHA256) {
		return nil, errors.New("invalid publish journal identity")
	}
	if j.ExpectedGeneration+1 != j.Generation || j.ExpectedExists != (j.ExpectedGeneration != 0) {
		return nil, errors.New("invalid publish journal parent expectation")
	}
	if j.ExpectedExists {
		if !hexSHA256Pattern.MatchString(j.ExpectedCheckpointSHA256) {
			return nil, errors.New("invalid publish journal parent checkpoint digest")
		}
	} else if j.ExpectedCheckpointSHA256 != "" || j.ExpectedETag != "" {
		return nil, errors.New("initial publish journal cannot carry parent identity")
	}
	if len(j.ExpectedETag) > 1024 || strings.ContainsAny(j.ExpectedETag, "\x00\r\n\t") {
		return nil, errors.New("invalid publish journal parent ETag")
	}
	if err := j.Phase.Validate(); err != nil {
		return nil, err
	}
	if !isCanonicalUTCTime(j.CreatedAt) {
		return nil, errors.New("invalid publish journal creation time")
	}
	if !isCanonicalUTCTime(j.UpdatedAt) || !isCanonicalUTCTime(j.RequestUpdatedAt) {
		return nil, errors.New("invalid publish journal update time")
	}
	if len(j.LockToken) > 2048 || strings.ContainsAny(j.LockToken, "\x00\r\n\t") {
		return nil, errors.New("invalid publish journal lock token")
	}
	j.CompletedObjects = append([]string(nil), j.CompletedObjects...)
	sort.Strings(j.CompletedObjects)
	for i, identity := range j.CompletedObjects {
		if identity == "" || strings.ContainsAny(identity, "\x00\r\n\t") || (i != 0 && j.CompletedObjects[i-1] == identity) {
			return nil, errors.New("invalid publish journal completed object set")
		}
	}
	return json.Marshal(j)
}

func isCanonicalUTCTime(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.Location() == time.UTC && parsed.Format(time.RFC3339Nano) == value
}

func readJournalFile(path string) ([]byte, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	name := filepath.Base(path)
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("publish journal must be a private regular file")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("publish journal changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxControlObjectSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxControlObjectSize {
		return nil, errors.New("publish journal exceeds safety limit")
	}
	return data, nil
}

func createRootTemp(root *os.Root, prefix string) (*os.File, string, error) {
	for attempt := 0; attempt < 16; attempt++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", err
		}
		name := prefix + hex.EncodeToString(random[:])
		file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err == nil {
			return file, name, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", errors.New("could not allocate a private temporary file")
}

func createUnlinkedTemp(dir, prefix string) (*os.File, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	file, name, err := createRootTemp(root, prefix)
	if err != nil {
		return nil, err
	}
	if err := root.Remove(name); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func decodeJournal(data []byte) (publishJournal, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var journal publishJournal
	if err := decoder.Decode(&journal); err != nil {
		return publishJournal{}, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return publishJournal{}, err
	}
	canonical, err := journal.canonical()
	if err != nil {
		return publishJournal{}, err
	}
	if !bytes.Equal(data, canonical) {
		return publishJournal{}, errors.New("publish journal is not canonical JSON")
	}
	return journal, nil
}
