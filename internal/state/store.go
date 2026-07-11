package state

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/pgsty/sow/internal/manifest"
)

type Store struct {
	stateDir string
	workDir  string
}

func New(stateDir string) *Store {
	return &Store{stateDir: stateDir, workDir: filepath.Join(stateDir, "state")}
}

func (s *Store) StateDir() string { return s.stateDir }

func (s *Store) ManifestPath(repo string) string {
	return filepath.Join(s.workDir, "manifests", repo+".tsv")
}

func (s *Store) OpenManifest(repo string) (*os.File, error) {
	f, err := os.Open(s.ManifestPath(repo))
	if err != nil {
		return nil, fmt.Errorf("open baseline manifest for %s: %w", repo, err)
	}
	return f, nil
}

func (s *Store) Install(staged map[string]string, message string) (plumbing.Hash, bool, error) {
	repository, err := s.ensureRepository()
	if err != nil {
		return plumbing.ZeroHash, false, err
	}
	worktree, err := repository.Worktree()
	if err != nil {
		return plumbing.ZeroHash, false, fmt.Errorf("open state worktree: %w", err)
	}
	names := make([]string, 0, len(staged))
	for name := range staged {
		names = append(names, name)
	}
	sort.Strings(names)
	type backup struct {
		dst    string
		path   string
		exists bool
	}
	backups := make([]backup, 0, len(names))
	changed := false
	rollback := true
	backupDir, err := os.MkdirTemp(s.stateDir, "install-backup-*")
	if err != nil {
		return plumbing.ZeroHash, false, fmt.Errorf("create state backup: %w", err)
	}
	defer func() {
		if rollback {
			for i := len(backups) - 1; i >= 0; i-- {
				item := backups[i]
				_ = os.Remove(item.dst)
				if item.exists {
					_ = os.Rename(item.path, item.dst)
				}
			}
		}
		_ = os.RemoveAll(backupDir)
	}()
	for _, name := range names {
		src := staged[name]
		dst := s.ManifestPath(name)
		equal, err := filesEqual(src, dst)
		if err != nil {
			return plumbing.ZeroHash, false, err
		}
		if equal {
			continue
		}
		changed = true
		item := backup{dst: dst, path: filepath.Join(backupDir, name+".tsv")}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return plumbing.ZeroHash, false, err
		}
		if _, err := os.Stat(dst); err == nil {
			if err := os.Rename(dst, item.path); err != nil {
				return plumbing.ZeroHash, false, fmt.Errorf("backup manifest %s: %w", name, err)
			}
			item.exists = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return plumbing.ZeroHash, false, err
		}
		backups = append(backups, item)
		source, err := os.Open(src)
		if err != nil {
			return plumbing.ZeroHash, false, err
		}
		copyErr := manifest.AtomicCopy(dst, source, 0o644)
		closeErr := source.Close()
		if copyErr != nil || closeErr != nil {
			return plumbing.ZeroHash, false, errors.Join(copyErr, closeErr)
		}
	}
	if !changed {
		head, err := repository.Head()
		if errors.Is(err, plumbing.ErrReferenceNotFound) {
			return plumbing.ZeroHash, false, errors.New("state repository has no baseline commit")
		}
		if err != nil {
			return plumbing.ZeroHash, false, err
		}
		rollback = false
		return head.Hash(), false, nil
	}
	for _, name := range names {
		rel := filepath.ToSlash(filepath.Join("manifests", name+".tsv"))
		if _, err := worktree.Add(rel); err != nil {
			return plumbing.ZeroHash, false, fmt.Errorf("stage %s: %w", rel, err)
		}
	}
	status, err := worktree.Status()
	if err != nil {
		return plumbing.ZeroHash, false, err
	}
	if status.IsClean() {
		return plumbing.ZeroHash, false, errors.New("manifest files changed but Git index is clean")
	}
	now := time.Now().UTC()
	hash, err := worktree.Commit(message, &git.CommitOptions{Author: &object.Signature{
		Name: "sow", Email: "sow@localhost", When: now,
	}})
	if err != nil {
		return plumbing.ZeroHash, false, fmt.Errorf("commit manifest baseline: %w", err)
	}
	rollback = false
	return hash, true, nil
}

func (s *Store) ensureRepository() (*git.Repository, error) {
	if err := os.MkdirAll(s.workDir, 0o700); err != nil {
		return nil, fmt.Errorf("create state worktree: %w", err)
	}
	repository, err := git.PlainOpen(s.workDir)
	if err == nil {
		return repository, nil
	}
	if !errors.Is(err, git.ErrRepositoryNotExists) {
		return nil, fmt.Errorf("open state Git repository: %w", err)
	}
	repository, err = git.PlainInit(s.workDir, false)
	if err != nil {
		return nil, fmt.Errorf("initialize state Git repository: %w", err)
	}
	return repository, nil
}

func filesEqual(left, right string) (bool, error) {
	leftFile, err := os.Open(left)
	if err != nil {
		return false, err
	}
	defer leftFile.Close()
	rightFile, err := os.Open(right)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer rightFile.Close()
	leftInfo, err := leftFile.Stat()
	if err != nil {
		return false, err
	}
	rightInfo, err := rightFile.Stat()
	if err != nil {
		return false, err
	}
	if leftInfo.Size() != rightInfo.Size() {
		return false, nil
	}
	leftBuffer := make([]byte, 256*1024)
	rightBuffer := make([]byte, 256*1024)
	for {
		leftN, leftErr := leftFile.Read(leftBuffer)
		rightN, rightErr := rightFile.Read(rightBuffer)
		if leftN != rightN || !bytes.Equal(leftBuffer[:leftN], rightBuffer[:rightN]) {
			return false, nil
		}
		if errors.Is(leftErr, io.EOF) && errors.Is(rightErr, io.EOF) {
			return true, nil
		}
		if leftErr != nil && !errors.Is(leftErr, io.EOF) {
			return false, leftErr
		}
		if rightErr != nil && !errors.Is(rightErr, io.EOF) {
			return false, rightErr
		}
	}
}
