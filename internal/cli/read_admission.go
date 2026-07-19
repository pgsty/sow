package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
)

// localReadAdmission owns one capability-bound repository/Git snapshot for a
// complete render operation. Nginx and edge contracts must not close one
// snapshot and then reopen public paths for another part of the same output:
// doing so can synthesize compatibility(A)+snapshot(B) during A->B->A swaps.
type localReadAdmission struct {
	rootPath         string
	root             *os.Root
	rootIdentity     os.FileInfo
	state            *os.Root
	stateIdentity    os.FileInfo
	worktree         *os.Root
	worktreeIdentity os.FileInfo
	worktreeRelative string
	gitIdentity      os.FileInfo
	gitRelative      string
	gitAbsent        bool
	closeGit         func() error
	canonical        *state.Store
	ownedLock        *state.Lock
	pool             *repository.Store
	files            []*localReadAdmissionFile
	rechecks         []func() error
	cleanups         []func() error
}

type localReadAdmissionFile struct {
	absolute     string
	rootPath     string
	root         *os.Root
	rootIdentity os.FileInfo
	relative     string
	identity     os.FileInfo
	body         []byte
}

func openLocalReadAdmission(cfg *config.Config) (_ *localReadAdmission, resultErr error) {
	return openLocalReadAdmissionWithLock(cfg, nil)
}

// openLockedLocalReadAdmission is the full-fsck counterpart to ordinary
// serving admission. The caller must retain the exact cooperative state lock
// for the whole session; the admission validates that capability instead of
// rejecting the expected lock pathname. Ownership of the lock stays with the
// caller and is never released by Close.
func openLockedLocalReadAdmission(cfg *config.Config, lock *state.Lock) (*localReadAdmission, error) {
	if lock == nil {
		return nil, errors.New("locked local read admission requires an owned state lock")
	}
	if cfg == nil {
		return nil, errors.New("locked local read admission configuration is unavailable")
	}
	if err := lock.ValidateStateDir(cfg.StatePath()); err != nil {
		return nil, fmt.Errorf("validate state lock before read admission: %w", err)
	}
	return openLocalReadAdmissionWithLock(cfg, lock)
}

func openLocalReadAdmissionWithLock(cfg *config.Config, ownedLock *state.Lock) (_ *localReadAdmission, resultErr error) {
	if cfg == nil {
		return nil, errors.New("local read admission configuration is unavailable")
	}
	root, rootIdentity, err := openBoundYUMCompatibilityRepositoryRoot(cfg.Root)
	if err != nil {
		return nil, fmt.Errorf("bind repository read admission root: %w", err)
	}
	session := &localReadAdmission{rootPath: cfg.Root, root: root, rootIdentity: rootIdentity, ownedLock: ownedLock}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, session.Close())
		}
	}()
	session.gitRelative = filepath.Join(config.StateDirectory, "state", ".git")
	if _, err := root.Lstat(session.gitRelative); errors.Is(err, os.ErrNotExist) {
		session.gitAbsent = true
		return session, nil
	} else if err != nil {
		return nil, fmt.Errorf("inspect canonical read admission state: %w", err)
	}
	session.state, session.stateIdentity, err = openRealYUMCompatibilityDirectory(root, config.StateDirectory, false)
	if err != nil {
		return nil, fmt.Errorf("bind canonical read admission state root: %w", err)
	}
	session.worktreeRelative = filepath.Join(config.StateDirectory, "state")
	session.worktree, session.worktreeIdentity, err = openRealYUMCompatibilityDirectory(root, session.worktreeRelative, false)
	if err != nil {
		return nil, fmt.Errorf("bind canonical read admission worktree root: %w", err)
	}
	dotGit, gitIdentity, err := openRealYUMCompatibilityDirectory(root, session.gitRelative, false)
	if err != nil {
		return nil, fmt.Errorf("bind canonical read admission Git metadata: %w", err)
	}
	repository, closeGit, err := state.OpenBoundRepository(dotGit)
	if err != nil {
		_ = dotGit.Close()
		return nil, fmt.Errorf("open capability-bound canonical Git metadata: %w", err)
	}
	session.closeGit = closeGit
	session.gitIdentity = gitIdentity
	session.canonical, err = state.NewReadOnlyRepository(cfg.StatePath(), repository)
	if err != nil {
		return nil, err
	}
	if ownedLock != nil {
		if err := ownedLock.ValidateStateDir(cfg.StatePath()); err != nil {
			return nil, fmt.Errorf("validate owned state lock after canonical binding: %w", err)
		}
	} else if err := session.requireNoMutationLock(); err != nil {
		return nil, err
	}
	return session, nil
}

func (s *localReadAdmission) HeadHash() (plumbing.Hash, error) {
	if s == nil || s.canonical == nil {
		return plumbing.ZeroHash, nil
	}
	return s.canonical.HeadHash()
}

func (s *localReadAdmission) OpenPool() (*repository.Store, error) {
	if s == nil || s.root == nil {
		return nil, errors.New("local read admission is unavailable")
	}
	if s.pool != nil {
		return s.pool, nil
	}
	pool, err := repository.OpenStore(s.rootPath)
	if err != nil {
		return nil, err
	}
	if err := pool.VerifyRootIdentity(s.rootIdentity); err != nil {
		_ = pool.Close()
		return nil, fmt.Errorf("bind read admission CAS to repository root: %w", err)
	}
	s.pool = pool
	return pool, nil
}

func (s *localReadAdmission) Binding() *yumCompatibilityReadBinding {
	if s == nil || s.root == nil {
		return nil
	}
	return &yumCompatibilityReadBinding{repositoryRoot: s.root, rootIdentity: s.rootIdentity}
}

// retainCleanup transfers ownership of a capability or private scratch tree
// to the read-admission session. Ordinary-route admission must keep its bound
// target root and canonical sidecar copies alive until every final replay has
// completed; cleaning them in the helper would turn the output barrier into a
// pathname reopen or a no-op.
func (s *localReadAdmission) retainCleanup(cleanup func() error) error {
	if s == nil || cleanup == nil {
		return errors.New("local read admission cleanup is unavailable")
	}
	s.cleanups = append(s.cleanups, cleanup)
	return nil
}

func (s *localReadAdmission) ReadFile(configPath, relative, label string, maximum int64) ([]byte, error) {
	if s == nil || s.root == nil || relative == "" || maximum < 1 {
		return nil, fmt.Errorf("%s read admission is unavailable", label)
	}
	filename := relative
	if !filepath.IsAbs(filename) {
		filename = filepath.Join(filepath.Dir(configPath), filepath.FromSlash(relative))
	}
	absolute, err := filepath.Abs(filename)
	if err != nil {
		return nil, fmt.Errorf("resolve %s path: %w", label, err)
	}
	rootPath, err := filepath.Abs(filepath.Dir(configPath))
	if err != nil {
		return nil, fmt.Errorf("resolve %s admission root: %w", label, err)
	}
	if err := serving.ValidateWorkerTraversableAbsoluteDirectory(rootPath); err != nil {
		return nil, fmt.Errorf("%s configuration path is not traversable by the Nginx worker: %w", label, err)
	}
	workerRelative, err := filepath.Rel(rootPath, absolute)
	if err != nil || workerRelative == ".." || strings.HasPrefix(workerRelative, ".."+string(filepath.Separator)) || filepath.IsAbs(workerRelative) {
		return nil, errors.Join(err, fmt.Errorf("%s escapes the configuration directory", label))
	}
	rootBefore, err := os.Lstat(rootPath)
	if err != nil || rootBefore.Mode()&os.ModeSymlink != 0 || !rootBefore.IsDir() {
		return nil, errors.Join(err, fmt.Errorf("%s configuration directory must be a real non-symlink directory", label))
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, fmt.Errorf("bind %s configuration directory: %w", label, err)
	}
	rootOpened, statErr := root.Stat(".")
	rootAfter, lstatErr := os.Lstat(rootPath)
	if statErr != nil || lstatErr != nil || !os.SameFile(rootBefore, rootOpened) || !os.SameFile(rootBefore, rootAfter) {
		return nil, errors.Join(statErr, lstatErr, root.Close(), fmt.Errorf("%s configuration directory changed while opening", label))
	}
	workerRelative = filepath.ToSlash(workerRelative)
	if err := serving.ValidateWorkerReadableFileRoot(root, workerRelative); err != nil {
		return nil, errors.Join(err, root.Close(), fmt.Errorf("%s is not readable by the Nginx worker", label))
	}
	name := filepath.FromSlash(workerRelative)
	before, err := root.Lstat(name)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maximum {
		_ = root.Close()
		return nil, errors.Join(err, fmt.Errorf("%s must be a bounded regular non-symlink file", label))
	}
	file, err := root.Open(name)
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("open %s: %w", label, err)
	}
	opened, statErr := file.Stat()
	afterOpen, lstatErr := root.Lstat(name)
	if statErr != nil || lstatErr != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) || !os.SameFile(before, afterOpen) {
		return nil, errors.Join(statErr, lstatErr, file.Close(), root.Close(), fmt.Errorf("%s changed while opening", label))
	}
	body, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	last, lastErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || lastErr != nil || closeErr != nil || len(body) == 0 || int64(len(body)) > maximum || !os.SameFile(opened, last) || opened.Size() != int64(len(body)) || !opened.ModTime().Equal(last.ModTime()) {
		return nil, errors.Join(readErr, lastErr, closeErr, root.Close(), fmt.Errorf("read stable %s", label))
	}
	entry := &localReadAdmissionFile{absolute: absolute, rootPath: rootPath, root: root, rootIdentity: rootOpened, relative: workerRelative, identity: opened, body: body}
	if err := entry.Verify(); err != nil {
		return nil, errors.Join(err, root.Close())
	}
	s.files = append(s.files, entry)
	return append([]byte(nil), body...), nil
}

func (f *localReadAdmissionFile) Verify() error {
	if f == nil || f.root == nil || f.rootIdentity == nil || f.identity == nil {
		return errors.New("bound admission file is unavailable")
	}
	if err := serving.ValidateWorkerTraversableAbsoluteDirectory(f.rootPath); err != nil {
		return errors.Join(err, fmt.Errorf("bound admission root %s is not traversable by the Nginx worker", f.rootPath))
	}
	rootThrough, rootErr := f.root.Stat(".")
	rootAtPath, rootPathErr := os.Lstat(f.rootPath)
	if rootErr != nil || rootPathErr != nil || rootAtPath.Mode()&os.ModeSymlink != 0 || !rootAtPath.IsDir() ||
		!os.SameFile(f.rootIdentity, rootThrough) || !os.SameFile(f.rootIdentity, rootAtPath) {
		return errors.Join(rootErr, rootPathErr, fmt.Errorf("bound admission root %s changed", f.rootPath))
	}
	if err := serving.ValidateWorkerReadableFileRoot(f.root, f.relative); err != nil {
		return errors.Join(err, fmt.Errorf("bound admission file %s is no longer readable by the Nginx worker", f.absolute))
	}
	name := filepath.FromSlash(f.relative)
	before, parentErr := f.root.Lstat(name)
	if parentErr != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || !os.SameFile(f.identity, before) {
		return errors.Join(parentErr, fmt.Errorf("bound admission file %s changed", f.absolute))
	}
	file, openErr := f.root.Open(name)
	if openErr != nil {
		return errors.Join(openErr, fmt.Errorf("reopen bound admission file %s", f.absolute))
	}
	opened, statErr := file.Stat()
	body, readErr := io.ReadAll(io.LimitReader(file, int64(len(f.body))+1))
	last, lastErr := file.Stat()
	closeErr := file.Close()
	after, lstatErr := f.root.Lstat(name)
	atPath, pathErr := os.Lstat(f.absolute)
	if statErr != nil || readErr != nil || lastErr != nil || closeErr != nil || lstatErr != nil || pathErr != nil ||
		opened.Mode()&os.ModeSymlink != 0 || after.Mode()&os.ModeSymlink != 0 || atPath.Mode()&os.ModeSymlink != 0 ||
		!opened.Mode().IsRegular() || !after.Mode().IsRegular() || !atPath.Mode().IsRegular() ||
		!os.SameFile(f.identity, opened) || !os.SameFile(f.identity, last) || !os.SameFile(f.identity, after) || !os.SameFile(f.identity, atPath) ||
		!bytes.Equal(body, f.body) || opened.Size() != int64(len(f.body)) || last.Size() != int64(len(f.body)) {
		return errors.Join(statErr, readErr, lastErr, closeErr, lstatErr, pathErr, fmt.Errorf("bound admission file %s changed", f.absolute))
	}
	return nil
}

func (s *localReadAdmission) requireNoMutationLock() error {
	if s == nil || s.root == nil {
		return errors.New("local read admission is unavailable")
	}
	lock := filepath.Join(config.StateDirectory, "locks", "state.lock")
	if _, err := s.root.Lstat(lock); err == nil {
		return errors.New("canonical state is being mutated during read admission")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *localReadAdmission) Verify(targetRoot string) error {
	if s == nil || s.root == nil {
		return errors.New("local read admission is unavailable")
	}
	var snapshotErr, poolErr error
	if s.canonical != nil {
		snapshotErr = s.canonical.VerifyReadSnapshot()
	}
	if s.pool != nil {
		poolErr = s.pool.VerifyRootIdentity(s.rootIdentity)
	}
	topologyErr := s.verifyTopology()
	var servedErr error
	if targetRoot != "" {
		configured, err := resolveNginxPathPrefix(s.rootPath)
		served, otherErr := resolveNginxPathPrefix(targetRoot)
		servedErr = errors.Join(err, otherErr)
		if servedErr == nil {
			relative, relErr := filepath.Rel(configured, served)
			if relErr != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				servedErr = errors.Join(relErr, errors.New("served root changed or escapes the bound repository root"))
			}
		}
	}
	var fileErr, recheckErr error
	for _, file := range s.files {
		fileErr = errors.Join(fileErr, file.Verify())
	}
	for _, recheck := range s.rechecks {
		recheckErr = errors.Join(recheckErr, recheck())
	}
	if snapshotErr != nil || topologyErr != nil || poolErr != nil || servedErr != nil || fileErr != nil || recheckErr != nil {
		return errors.Join(snapshotErr, topologyErr, poolErr, servedErr, fileErr, recheckErr, errors.New("capability-bound read admission changed"))
	}
	return nil
}

// verifyTopology is the retained-directory barrier shared by read-only fsck
// and the narrow adopt/repair mutation window. The latter intentionally
// changes refs and objects, so it cannot replay the pre-mutation Git snapshot;
// it must still prove that repository root, .sow, worktree, .git, and the exact
// cooperative lock are the same filesystem objects throughout the write.
func (s *localReadAdmission) verifyTopology() error {
	if s == nil || s.root == nil {
		return errors.New("local read admission topology is unavailable")
	}
	var stateErr, worktreeErr, gitErr error
	if s.canonical != nil {
		stateErr = verifyBoundYUMCompatibilityDirectory(s.root, config.StateDirectory, s.stateIdentity)
		worktreeErr = verifyBoundYUMCompatibilityDirectory(s.root, s.worktreeRelative, s.worktreeIdentity)
		gitErr = verifyBoundYUMCompatibilityDirectory(s.root, s.gitRelative, s.gitIdentity)
	} else if s.gitAbsent {
		if _, err := s.root.Lstat(s.gitRelative); !errors.Is(err, os.ErrNotExist) {
			gitErr = errors.Join(err, errors.New("canonical Git metadata appeared during read admission"))
		}
	}
	var lockErr error
	if s.ownedLock != nil {
		lockErr = s.ownedLock.ValidateStateDir(filepath.Join(s.rootPath, config.StateDirectory))
	} else {
		lockErr = s.requireNoMutationLock()
	}
	rootErr := verifyYUMCompatibilityRepositoryRootPath(s.rootPath, s.rootIdentity)
	if stateErr != nil || worktreeErr != nil || gitErr != nil || lockErr != nil || rootErr != nil {
		return errors.Join(stateErr, worktreeErr, gitErr, lockErr, rootErr, errors.New("capability-bound read admission topology changed"))
	}
	return nil
}

func (s *localReadAdmission) Close() error {
	if s == nil {
		return nil
	}
	var result error
	if s.pool != nil {
		result = errors.Join(result, s.pool.Close())
		s.pool = nil
	}
	if s.closeGit != nil {
		result = errors.Join(result, s.closeGit())
		s.closeGit = nil
	}
	if s.state != nil {
		result = errors.Join(result, s.state.Close())
		s.state = nil
	}
	if s.worktree != nil {
		result = errors.Join(result, s.worktree.Close())
		s.worktree = nil
	}
	for index := len(s.files) - 1; index >= 0; index-- {
		if s.files[index] != nil && s.files[index].root != nil {
			result = errors.Join(result, s.files[index].root.Close())
			s.files[index].root = nil
		}
	}
	s.files = nil
	s.rechecks = nil
	for index := len(s.cleanups) - 1; index >= 0; index-- {
		if s.cleanups[index] != nil {
			result = errors.Join(result, s.cleanups[index]())
		}
	}
	s.cleanups = nil
	if s.root != nil {
		result = errors.Join(result, s.root.Close())
		s.root = nil
	}
	return result
}
