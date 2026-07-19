package provenance

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type Store struct {
	root              string
	directorySync     func(string) error
	directorySyncMu   sync.Mutex
	syncedDirectories map[string]struct{}
}

func NewStore(canonicalStateDir string) *Store {
	return &Store{
		root:              filepath.Join(canonicalStateDir, "provenance"),
		directorySync:     syncProvenanceDirectory,
		syncedDirectories: make(map[string]struct{}),
	}
}

func (s *Store) Put(receipt Receipt) (string, bool, error) {
	data, err := receipt.CanonicalJSON()
	if err != nil {
		return "", false, err
	}
	id, err := receipt.ID()
	if err != nil {
		return "", false, err
	}
	path := filepath.Join(s.root, receipt.Format, receipt.ArtifactSHA256+".json")
	existing, err := os.ReadFile(path)
	if err == nil {
		if !bytes.Equal(existing, data) {
			return "", false, fmt.Errorf("provenance conflict for %s artifact %s", receipt.Format, receipt.ArtifactSHA256)
		}
		if err := s.syncDirectory(filepath.Dir(path), false); err != nil {
			return "", false, fmt.Errorf("sync existing provenance directory: %w", err)
		}
		return id, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", false, err
	}
	if err := putImmutable(path, data); err != nil {
		if errors.Is(err, os.ErrExist) {
			existing, readErr := os.ReadFile(path)
			if readErr == nil && bytes.Equal(existing, data) {
				if syncErr := s.syncDirectory(filepath.Dir(path), true); syncErr != nil {
					return "", false, fmt.Errorf("sync concurrent provenance directory: %w", syncErr)
				}
				return id, false, nil
			}
			if readErr != nil {
				return "", false, errors.Join(err, readErr)
			}
			return "", false, fmt.Errorf("provenance conflict for %s artifact %s", receipt.Format, receipt.ArtifactSHA256)
		}
		return "", false, err
	}
	if err := s.syncDirectory(filepath.Dir(path), true); err != nil {
		return "", false, fmt.Errorf("sync new provenance directory: %w", err)
	}
	return id, true, nil
}

// syncDirectory makes replay after a post-link fsync failure converge without
// imposing one directory fsync per already-durable receipt. A newly linked or
// concurrently observed entry always forces a fresh sync; an existing entry
// needs one successful sync per Store lifetime.
func (s *Store) syncDirectory(path string, force bool) error {
	if s == nil {
		return errors.New("provenance store is unavailable")
	}
	s.directorySyncMu.Lock()
	defer s.directorySyncMu.Unlock()
	if !force {
		if _, ok := s.syncedDirectories[path]; ok {
			return nil
		}
	}
	syncDirectory := s.directorySync
	if syncDirectory == nil {
		syncDirectory = syncProvenanceDirectory
	}
	if err := syncDirectory(path); err != nil {
		return err
	}
	if s.syncedDirectories == nil {
		s.syncedDirectories = make(map[string]struct{})
	}
	s.syncedDirectories[path] = struct{}{}
	return nil
}

func putImmutable(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".receipt-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
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
	if err := os.Link(tmpPath, path); err != nil {
		return err
	}
	return nil
}

func syncProvenanceDirectory(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(handle.Sync(), handle.Close())
}

func (s *Store) Get(format, artifactSHA string) (Receipt, error) {
	if format != "rpm" && format != "deb" {
		return Receipt{}, fmt.Errorf("invalid provenance format %q", format)
	}
	if err := validateHash("artifact_sha256", artifactSHA); err != nil {
		return Receipt{}, err
	}
	data, err := os.ReadFile(filepath.Join(s.root, format, artifactSHA+".json"))
	if err != nil {
		return Receipt{}, err
	}
	return Decode(data)
}
