package state

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/pgsty/sow/internal/manifest"
)

type Store struct {
	stateDir       string
	workDir        string
	readRepository *git.Repository
	readHead       plumbing.Hash
	readRefs       map[plumbing.ReferenceName]plumbing.Hash
}

// ErrReadOnly is returned before a capability-bound Store can perform any
// path or Git mutation. Admission readers intentionally retain only read
// capabilities; falling through to path-based journals would reintroduce the
// root-replacement ambiguity those readers are meant to eliminate.
var ErrReadOnly = errors.New("canonical state store is read-only")

func (s *Store) requireWritable() error {
	if s == nil {
		return errors.New("canonical state store is unavailable")
	}
	if s.readRepository != nil {
		return ErrReadOnly
	}
	return nil
}

func New(stateDir string) *Store {
	return &Store{stateDir: stateDir, workDir: filepath.Join(stateDir, "state")}
}

// NewReadOnlyRepository constructs a canonical state reader backed by an
// already-open Git repository. It is used by capability-bound admission code:
// every object and reference read stays rooted at the caller's retained
// filesystem handles, and no missing state directory can be initialized as a
// side effect. The caller owns the repository storage and its filesystem
// handles for the complete Store lifetime.
func NewReadOnlyRepository(stateDir string, repository *git.Repository) (*Store, error) {
	if repository == nil {
		return nil, errors.New("read-only canonical Git repository is unavailable")
	}
	if _, ok := repository.Storer.(*verifiedObjectStorer); !ok {
		return nil, errors.New("read-only canonical Git repository lacks object-integrity verification")
	}
	head, refs, err := snapshotRepositoryState(repository)
	if err != nil {
		return nil, err
	}
	store := &Store{
		stateDir: stateDir, workDir: filepath.Join(stateDir, "state"), readRepository: repository,
		readHead: head, readRefs: refs,
	}
	// HEAD and the loose/packed ref vector are separate Git files. A mutation
	// between those reads must not create a synthetic mixed admission snapshot.
	if err := store.VerifyReadSnapshot(); err != nil {
		return nil, fmt.Errorf("stabilize read-only canonical snapshot: %w", err)
	}
	return store, nil
}

func snapshotRepositoryState(repository *git.Repository) (plumbing.Hash, map[plumbing.ReferenceName]plumbing.Hash, error) {
	var head plumbing.Hash
	reference, err := repository.Head()
	if err == nil {
		head = reference.Hash()
	} else if !errors.Is(err, plumbing.ErrReferenceNotFound) {
		return plumbing.ZeroHash, nil, fmt.Errorf("snapshot read-only canonical HEAD: %w", err)
	}
	refs := make(map[plumbing.ReferenceName]plumbing.Hash)
	iterator, err := repository.References()
	if err != nil {
		return plumbing.ZeroHash, nil, fmt.Errorf("snapshot read-only canonical refs: %w", err)
	}
	err = iterator.ForEach(func(reference *plumbing.Reference) error {
		if reference.Type() == plumbing.HashReference {
			refs[reference.Name()] = reference.Hash()
		}
		return nil
	})
	iterator.Close()
	if err != nil {
		return plumbing.ZeroHash, nil, err
	}
	return head, refs, nil
}

// VerifyReadSnapshot compares the live repository HEAD and complete direct-ref
// vector with the immutable snapshot used by this Store. Read APIs deliberately
// keep returning the snapshot; callers invoke this at an admission boundary to
// reject concurrent Git movement without ever mixing live HEAD with cached refs.
func (s *Store) VerifyReadSnapshot() error {
	if s == nil || s.readRepository == nil {
		return errors.New("canonical state store is not a read-only snapshot")
	}
	head, refs, err := snapshotRepositoryState(s.readRepository)
	if err != nil {
		return err
	}
	if head != s.readHead || len(refs) != len(s.readRefs) {
		return errors.New("canonical Git HEAD or reference vector changed")
	}
	for name, hash := range s.readRefs {
		if refs[name] != hash {
			return fmt.Errorf("canonical Git reference %s changed", name)
		}
	}
	verifier, ok := s.readRepository.Storer.(*verifiedObjectStorer)
	if !ok {
		return errors.New("read-only canonical Git repository lost object-integrity verification")
	}
	if err := verifier.VerifyAccessedObjects(); err != nil {
		return fmt.Errorf("verify canonical Git object snapshot: %w", err)
	}
	return nil
}

func (s *Store) StateDir() string { return s.stateDir }

// OpenRepository returns the existing canonical Git reader without creating
// state. A Store made by NewReadOnlyRepository returns its capability-bound
// repository; an ordinary Store opens the already-present embedded Git tree.
func (s *Store) OpenRepository() (*git.Repository, error) {
	if s == nil {
		return nil, errors.New("canonical state store is unavailable")
	}
	if s.readRepository != nil {
		return s.readRepository, nil
	}
	repository, err := git.PlainOpen(s.workDir)
	if err != nil {
		return nil, fmt.Errorf("open canonical state repository: %w", err)
	}
	return repository, nil
}

// HasBoundRepository reports whether every Git read is served by the retained
// repository supplied to NewReadOnlyRepository.
func (s *Store) HasBoundRepository() bool {
	return s != nil && s.readRepository != nil
}

// AuditCanonicalWorktree proves that the embedded Git index and checkout are
// an exact, permission-safe projection of HEAD. Full fsck calls this only after
// a capability-bound graph audit has validated the object bytes it names.
// Admission-bound read Stores have no worktree authority and are rejected.
func (s *Store) AuditCanonicalWorktree() (resultErr error) {
	if s == nil {
		return errors.New("canonical state store is unavailable")
	}
	if s.readRepository != nil {
		return ErrReadOnly
	}
	rootBefore, err := os.Lstat(s.workDir)
	if err != nil || !rootBefore.IsDir() || rootBefore.Mode()&os.ModeSymlink != 0 {
		return errors.Join(err, errors.New("canonical worktree root is not a real directory"))
	}
	root, err := os.OpenRoot(s.workDir)
	if err != nil {
		return fmt.Errorf("bind canonical worktree root: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	rootOpened, statErr := root.Stat(".")
	rootAfter, pathErr := os.Lstat(s.workDir)
	if statErr != nil || pathErr != nil || !os.SameFile(rootBefore, rootOpened) || !os.SameFile(rootBefore, rootAfter) {
		return errors.Join(statErr, pathErr, errors.New("canonical worktree root changed while binding"))
	}
	return s.auditCanonicalWorktreeBound(root, rootOpened, nil)
}

// AuditCanonicalWorktreeBound is the full-fsck variant of
// AuditCanonicalWorktree. It consumes the exact worktree capability retained
// by the caller's read-admission session, so a pathname A->B->A exchange cannot
// combine canonical graph A with checkout or index B. Ownership of root stays
// with the caller.
func (s *Store) AuditCanonicalWorktreeBound(root *os.Root, rootIdentity, gitIdentity os.FileInfo) error {
	if s == nil {
		return errors.New("canonical state store is unavailable")
	}
	if s.readRepository != nil {
		return ErrReadOnly
	}
	if root == nil || rootIdentity == nil || gitIdentity == nil {
		return errors.New("bound canonical worktree identity is unavailable")
	}
	return s.auditCanonicalWorktreeBound(root, rootIdentity, gitIdentity)
}

func (s *Store) auditCanonicalWorktreeBound(root *os.Root, rootIdentity, expectedGitIdentity os.FileInfo) (resultErr error) {
	rootOpened, statErr := root.Stat(".")
	rootAtPath, pathErr := os.Lstat(s.workDir)
	if statErr != nil || pathErr != nil || rootAtPath.Mode()&os.ModeSymlink != 0 || !rootAtPath.IsDir() ||
		!os.SameFile(rootIdentity, rootOpened) || !os.SameFile(rootIdentity, rootAtPath) {
		return errors.Join(statErr, pathErr, errors.New("canonical worktree root changed before audit"))
	}
	gitInfo, err := root.Lstat(".git")
	if err != nil || !gitInfo.IsDir() || gitInfo.Mode()&os.ModeSymlink != 0 {
		return errors.Join(err, errors.New("canonical worktree .git is not a real directory"))
	}
	if expectedGitIdentity != nil && !os.SameFile(expectedGitIdentity, gitInfo) {
		return errors.New("canonical worktree .git differs from the retained read-admission identity")
	}
	dotGit, err := root.OpenRoot(".git")
	if err != nil {
		return fmt.Errorf("bind canonical worktree .git: %w", err)
	}
	openedGit, statErr := dotGit.Stat(".")
	gitAfterOpen, pathErr := root.Lstat(".git")
	if statErr != nil || pathErr != nil || !os.SameFile(gitInfo, openedGit) || !os.SameFile(gitInfo, gitAfterOpen) {
		return errors.Join(statErr, pathErr, dotGit.Close(), errors.New("canonical worktree .git changed while binding"))
	}
	repository, closeRepository, err := OpenBoundRepository(dotGit)
	if err != nil {
		return fmt.Errorf("open bound canonical worktree repository: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, closeRepository()) }()
	bound, err := NewReadOnlyRepository(s.stateDir, repository)
	if err != nil {
		return err
	}
	head, err := bound.HeadHash()
	if err != nil || head.IsZero() {
		return errors.Join(err, errors.New("canonical state repository has no HEAD"))
	}
	if err := s.auditCanonicalWorktreeAt(repository, head, root, rootIdentity, gitInfo); err != nil {
		return err
	}
	if err := bound.VerifyReadSnapshot(); err != nil {
		return fmt.Errorf("finalize bound canonical worktree Git snapshot: %w", err)
	}
	return nil
}

type canonicalWorktreeEntry struct {
	hash plumbing.Hash
	mode filemode.FileMode
}

// auditCanonicalWorktreeAt does not trust go-git's stat-cache based Status
// result as integrity evidence. A same-size write followed by mtime restoration
// can make Status reuse the index hash without reading the changed bytes. This
// audit instead compares the exact HEAD tree, index semantics, filesystem
// namespace, modes, and streamed worktree blob IDs.
func (s *Store) auditCanonicalWorktreeAt(repository *git.Repository, head plumbing.Hash, root *os.Root, rootIdentity, gitIdentity os.FileInfo) error {
	commit, err := repository.CommitObject(head)
	if err != nil {
		return fmt.Errorf("open canonical HEAD commit %s: %w", head, err)
	}
	tree, err := commit.Tree()
	if err != nil {
		return fmt.Errorf("open canonical HEAD tree %s: %w", head, err)
	}
	expected := make(map[string]canonicalWorktreeEntry)
	expectedDirectories := map[string]struct{}{".": {}}
	type treeWork struct {
		tree   *object.Tree
		prefix string
	}
	pending := []treeWork{{tree: tree}}
	for len(pending) != 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if err := validateCanonicalTreeEntries(current.tree.Entries); err != nil {
			return fmt.Errorf("canonical HEAD contains a non-canonical tree at %q: %w", current.prefix, err)
		}
		for _, entry := range current.tree.Entries {
			name := entry.Name
			if current.prefix != "" {
				name = current.prefix + "/" + entry.Name
			}
			if err := validateStatePath(name); err != nil {
				return fmt.Errorf("canonical HEAD contains unsafe path %q: %w", name, err)
			}
			switch entry.Mode {
			case filemode.Dir:
				subtree, err := repository.TreeObject(entry.Hash)
				if err != nil {
					return fmt.Errorf("open canonical HEAD subtree %s for %s: %w", entry.Hash, name, err)
				}
				expectedDirectories[name] = struct{}{}
				pending = append(pending, treeWork{tree: subtree, prefix: name})
			case filemode.Regular:
				if _, duplicate := expected[name]; duplicate {
					return fmt.Errorf("canonical HEAD contains duplicate path %s", name)
				}
				expected[name] = canonicalWorktreeEntry{hash: entry.Hash, mode: entry.Mode}
			default:
				return fmt.Errorf("canonical HEAD path %s has unsupported Git mode %s", name, entry.Mode)
			}
		}
	}

	canonicalIndex, err := repository.Storer.Index()
	if err != nil {
		return fmt.Errorf("read canonical Git index: %w", err)
	}
	if len(canonicalIndex.Entries) != len(expected) {
		return fmt.Errorf("canonical Git index entry count=%d want=%d", len(canonicalIndex.Entries), len(expected))
	}
	seenIndex := make(map[string]struct{}, len(canonicalIndex.Entries))
	for _, entry := range canonicalIndex.Entries {
		if entry == nil {
			return errors.New("canonical Git index contains a nil entry")
		}
		if err := validateStatePath(entry.Name); err != nil {
			return fmt.Errorf("canonical Git index contains unsafe path %q: %w", entry.Name, err)
		}
		if _, duplicate := seenIndex[entry.Name]; duplicate {
			return fmt.Errorf("canonical Git index contains duplicate path %s", entry.Name)
		}
		seenIndex[entry.Name] = struct{}{}
		want, exists := expected[entry.Name]
		if !exists || entry.Hash != want.hash || entry.Mode != want.mode || entry.Stage != 0 || entry.SkipWorktree || entry.IntentToAdd {
			return fmt.Errorf("canonical Git index entry %s differs from HEAD", entry.Name)
		}
	}

	if root == nil || rootIdentity == nil || gitIdentity == nil {
		return errors.New("canonical worktree audit capability is unavailable")
	}

	seenFiles := make(map[string]struct{}, len(expected))
	observedDirectories := map[string]os.FileInfo{".": rootIdentity}
	directories := []string{"."}
	for len(directories) != 0 {
		directory := directories[len(directories)-1]
		directories = directories[:len(directories)-1]
		directoryBefore := observedDirectories[directory]
		directoryName := filepath.FromSlash(directory)
		openedDirectory, err := root.Open(directoryName)
		if err != nil {
			return fmt.Errorf("open canonical worktree directory %s: %w", directory, err)
		}
		directoryOpened, statErr := openedDirectory.Stat()
		directoryAfterOpen, pathErr := root.Lstat(directoryName)
		if statErr != nil || pathErr != nil || directoryAfterOpen.Mode()&os.ModeSymlink != 0 || !directoryAfterOpen.IsDir() ||
			!os.SameFile(directoryBefore, directoryOpened) || !os.SameFile(directoryBefore, directoryAfterOpen) {
			return errors.Join(statErr, pathErr, openedDirectory.Close(), fmt.Errorf("canonical worktree directory %s changed while opening", directory))
		}
		for {
			entries, readErr := openedDirectory.ReadDir(256)
			for _, directoryEntry := range entries {
				name := directoryEntry.Name()
				if directory != "." {
					name = directory + "/" + name
				}
				if directory == "." && directoryEntry.Name() == ".git" {
					continue
				}
				if err := validateStatePath(name); err != nil {
					_ = openedDirectory.Close()
					return fmt.Errorf("canonical worktree contains unsafe path %q: %w", name, err)
				}
				info, err := root.Lstat(filepath.FromSlash(name))
				if err != nil || info.Mode()&os.ModeSymlink != 0 {
					_ = openedDirectory.Close()
					return errors.Join(err, fmt.Errorf("canonical worktree path %s is absent or symlinked", name))
				}
				if info.IsDir() {
					observedDirectories[name] = info
					directories = append(directories, name)
					continue
				}
				want, exists := expected[name]
				if !exists || !canonicalFileModeMatches(info.Mode(), want.mode) {
					_ = openedDirectory.Close()
					return fmt.Errorf("canonical worktree path %s is untracked or has non-canonical permissions", name)
				}
				if err := auditCanonicalWorktreeFile(root, name, info, want); err != nil {
					_ = openedDirectory.Close()
					return err
				}
				seenFiles[name] = struct{}{}
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				_ = openedDirectory.Close()
				return fmt.Errorf("enumerate canonical worktree directory %s: %w", directory, readErr)
			}
		}
		directoryLast, statErr := openedDirectory.Stat()
		directoryAfterRead, pathErr := root.Lstat(directoryName)
		closeErr := openedDirectory.Close()
		if statErr != nil || pathErr != nil || closeErr != nil || directoryAfterRead.Mode()&os.ModeSymlink != 0 || !directoryAfterRead.IsDir() ||
			!os.SameFile(directoryBefore, directoryLast) || !os.SameFile(directoryBefore, directoryAfterRead) {
			return errors.Join(statErr, pathErr, closeErr, fmt.Errorf("canonical worktree directory %s changed while enumerating", directory))
		}
	}
	if len(seenFiles) != len(expected) {
		return fmt.Errorf("canonical worktree file namespace differs from HEAD: files=%d/%d", len(seenFiles), len(expected))
	}
	for name := range expectedDirectories {
		if _, exists := observedDirectories[name]; !exists {
			return fmt.Errorf("canonical worktree is missing HEAD directory %s", name)
		}
	}
	for name, before := range observedDirectories {
		after, err := root.Lstat(filepath.FromSlash(name))
		if err != nil || !after.IsDir() || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, after) {
			return errors.Join(err, fmt.Errorf("canonical worktree directory %s changed during audit", name))
		}
	}
	gitAfter, gitErr := root.Lstat(".git")
	if gitErr != nil || !gitAfter.IsDir() || gitAfter.Mode()&os.ModeSymlink != 0 || !os.SameFile(gitIdentity, gitAfter) {
		return errors.Join(gitErr, errors.New("canonical worktree .git changed during audit"))
	}
	rootLast, statErr := root.Stat(".")
	rootAtPath, pathErr := os.Lstat(s.workDir)
	if statErr != nil || pathErr != nil || rootAtPath.Mode()&os.ModeSymlink != 0 || !rootAtPath.IsDir() ||
		!os.SameFile(rootIdentity, rootLast) || !os.SameFile(rootIdentity, rootAtPath) {
		return errors.Join(statErr, pathErr, errors.New("canonical worktree root changed during audit"))
	}
	return nil
}

func auditCanonicalWorktreeFile(root *os.Root, name string, before os.FileInfo, expected canonicalWorktreeEntry) error {
	file, err := root.Open(filepath.FromSlash(name))
	if err != nil {
		return fmt.Errorf("open canonical worktree file %s: %w", name, err)
	}
	opened, statErr := file.Stat()
	afterOpen, pathErr := root.Lstat(filepath.FromSlash(name))
	if statErr != nil || pathErr != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) || !os.SameFile(before, afterOpen) {
		return errors.Join(statErr, pathErr, file.Close(), fmt.Errorf("canonical worktree file %s changed while opening", name))
	}
	hasher := plumbing.NewHasher(plumbing.BlobObject, opened.Size())
	n, copyErr := io.Copy(hasher, file)
	last, lastErr := file.Stat()
	closeErr := file.Close()
	after, lstatErr := root.Lstat(filepath.FromSlash(name))
	if copyErr != nil || lastErr != nil || closeErr != nil || lstatErr != nil || n != opened.Size() ||
		!os.SameFile(before, last) || !os.SameFile(before, after) || !canonicalFileModeMatches(last.Mode(), expected.mode) || hasher.Sum() != expected.hash {
		return errors.Join(copyErr, lastErr, closeErr, lstatErr, fmt.Errorf("canonical worktree file %s bytes, identity, or permissions differ from HEAD", name))
	}
	return nil
}

func (s *Store) ManifestPath(repo string) string {
	return filepath.Join(s.workDir, "manifests", repo+".tsv")
}

func (s *Store) OpenManifest(repo string) (*os.File, error) {
	if err := validateStateSegment(repo); err != nil {
		return nil, fmt.Errorf("invalid repository manifest name %q: %w", repo, err)
	}
	if s != nil && s.readRepository != nil {
		return s.OpenPath(filepath.ToSlash(filepath.Join("manifests", repo+".tsv")))
	}
	f, err := os.Open(s.ManifestPath(repo))
	if err != nil {
		return nil, fmt.Errorf("open baseline manifest for %s: %w", repo, err)
	}
	return f, nil
}

func (s *Store) Install(staged map[string]string, message string) (plumbing.Hash, bool, error) {
	if err := s.requireWritable(); err != nil {
		return plumbing.ZeroHash, false, err
	}
	paths := make(map[string]string, len(staged))
	for name, source := range staged {
		if err := validateStateSegment(name); err != nil {
			return plumbing.ZeroHash, false, fmt.Errorf("invalid repository manifest name %q: %w", name, err)
		}
		paths[filepath.ToSlash(filepath.Join("manifests", name+".tsv"))] = source
	}
	return s.InstallPaths(paths, message)
}

// InstallPaths atomically installs canonical state files and commits their
// aggregate state to the embedded repository. Paths are relative POSIX paths
// below .sow/state and may not address .git or escape the worktree.
func (s *Store) InstallPaths(staged map[string]string, message string) (hash plumbing.Hash, changed bool, resultErr error) {
	if err := s.requireWritable(); err != nil {
		return plumbing.ZeroHash, false, err
	}
	return s.installPathChanges(staged, nil, message)
}

type installBackup struct {
	dst    string
	path   string
	exists bool
}

func rollbackInstallBackups(backups []installBackup) error {
	var result error
	for i := len(backups) - 1; i >= 0; i-- {
		item := backups[i]
		removeErr := os.Remove(item.dst)
		if errors.Is(removeErr, os.ErrNotExist) {
			removeErr = nil
		}
		if removeErr != nil {
			result = errors.Join(result, fmt.Errorf("remove failed canonical state %s: %w", item.dst, removeErr))
			continue
		}
		if item.exists {
			if err := os.Rename(item.path, item.dst); err != nil {
				result = errors.Join(result, fmt.Errorf("restore canonical state %s from %s: %w", item.dst, item.path, err))
				continue
			}
		}
		if err := syncStateInstallDirectory(filepath.Dir(item.dst)); err != nil {
			result = errors.Join(result, fmt.Errorf("sync restored canonical state parent %s: %w", filepath.Dir(item.dst), err))
		}
	}
	return result
}

func syncStateInstallDirectory(path string) error {
	handle, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(handle.Sync(), handle.Close())
}

// installPathChanges atomically installs and removes canonical state files in
// one embedded-Git commit. Callers that need recoverable deletion must reach it
// through Store.Apply so the exact delete set is journaled before mutation.
func (s *Store) installPathChanges(staged map[string]string, deleted []string, message string) (hash plumbing.Hash, changed bool, resultErr error) {
	if err := s.requireWritable(); err != nil {
		return plumbing.ZeroHash, false, err
	}
	if len(staged) == 0 && len(deleted) == 0 {
		return plumbing.ZeroHash, false, errors.New("no canonical state files supplied")
	}
	repository, err := s.ensureRepository()
	if err != nil {
		return plumbing.ZeroHash, false, err
	}
	worktree, err := repository.Worktree()
	if err != nil {
		return plumbing.ZeroHash, false, fmt.Errorf("open state worktree: %w", err)
	}
	if err := s.requireCanonicalWorktreeMatchesRepositoryHead(repository); err != nil {
		return plumbing.ZeroHash, false, err
	}
	originalIndex, err := repository.Storer.Index()
	if err != nil {
		return plumbing.ZeroHash, false, fmt.Errorf("snapshot state Git index: %w", err)
	}
	names := make([]string, 0, len(staged))
	for name := range staged {
		if err := validateStatePath(name); err != nil {
			return plumbing.ZeroHash, false, fmt.Errorf("invalid canonical state path %q: %w", name, err)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	deleteNames := append([]string(nil), deleted...)
	sort.Strings(deleteNames)
	for index, name := range deleteNames {
		if err := validateStatePath(name); err != nil {
			return plumbing.ZeroHash, false, fmt.Errorf("invalid canonical state deletion %q: %w", name, err)
		}
		if _, replaced := staged[name]; replaced {
			return plumbing.ZeroHash, false, fmt.Errorf("canonical state path %q cannot be installed and deleted together", name)
		}
		if index != 0 && deleteNames[index-1] == name {
			return plumbing.ZeroHash, false, fmt.Errorf("duplicate canonical state deletion %q", name)
		}
	}
	backups := make([]installBackup, 0, len(names)+len(deleteNames))
	deletedExisting := make([]string, 0, len(deleteNames))
	rollback := true
	indexTouched := false
	backupDir, err := os.MkdirTemp(s.stateDir, "install-backup-*")
	if err != nil {
		return plumbing.ZeroHash, false, fmt.Errorf("create state backup: %w", err)
	}
	defer func() {
		if rollback {
			rollbackErr := rollbackInstallBackups(backups)
			if indexTouched {
				if err := repository.Storer.SetIndex(originalIndex); err != nil {
					rollbackErr = errors.Join(rollbackErr, fmt.Errorf("restore state Git index: %w", err))
				}
			}
			if rollbackErr != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("rollback canonical state failed; backup retained at %s: %w", backupDir, rollbackErr))
				return
			}
		}
		_ = os.RemoveAll(backupDir)
	}()
	for _, name := range names {
		src := staged[name]
		dst := filepath.Join(s.workDir, filepath.FromSlash(name))
		equal, err := filesEqual(src, dst)
		if err != nil {
			return plumbing.ZeroHash, false, err
		}
		if equal {
			continue
		}
		changed = true
		item := installBackup{dst: dst, path: filepath.Join(backupDir, fmt.Sprintf("%06d", len(backups)))}
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
	for _, name := range deleteNames {
		dst := filepath.Join(s.workDir, filepath.FromSlash(name))
		info, err := os.Lstat(dst)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return plumbing.ZeroHash, false, err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return plumbing.ZeroHash, false, fmt.Errorf("canonical state deletion %s is not a regular non-symlink file", name)
		}
		changed = true
		item := installBackup{dst: dst, path: filepath.Join(backupDir, fmt.Sprintf("%06d", len(backups))), exists: true}
		if err := os.Rename(dst, item.path); err != nil {
			return plumbing.ZeroHash, false, fmt.Errorf("backup deleted canonical state %s: %w", name, err)
		}
		backups = append(backups, item)
		deletedExisting = append(deletedExisting, name)
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
		indexTouched = true
		if _, err := worktree.Add(name); err != nil {
			return plumbing.ZeroHash, false, fmt.Errorf("stage %s: %w", name, err)
		}
	}
	for _, name := range deletedExisting {
		indexTouched = true
		if _, err := worktree.Remove(name); err != nil {
			return plumbing.ZeroHash, false, fmt.Errorf("stage canonical deletion %s: %w", name, err)
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
	hash, err = worktree.Commit(message, &git.CommitOptions{Author: &object.Signature{
		Name: "sow", Email: "sow@localhost", When: now,
	}})
	if err != nil {
		return plumbing.ZeroHash, false, fmt.Errorf("commit manifest baseline: %w", err)
	}
	rollback = false
	return hash, true, nil
}

func (s *Store) requireCanonicalWorktreeMatchesHead() error {
	repository, err := s.ensureRepository()
	if err != nil {
		return err
	}
	return s.requireCanonicalWorktreeMatchesRepositoryHead(repository)
}

func (s *Store) requireCanonicalWorktreeMatchesRepositoryHead(repository *git.Repository) error {
	head, err := repository.Head()
	if errors.Is(err, plumbing.ErrReferenceNotFound) {
		worktree, worktreeErr := repository.Worktree()
		if worktreeErr != nil {
			return worktreeErr
		}
		return requireCleanWorktree(worktree)
	}
	if err != nil {
		return err
	}
	if err := s.requireCanonicalWorktreeMatchesCommit(repository, head.Hash()); err != nil {
		return fmt.Errorf("canonical state worktree/index is dirty or has non-canonical permissions; recover or repair it before starting a transaction: %w", err)
	}
	return nil
}

func requireCleanWorktree(worktree *git.Worktree) error {
	status, err := worktree.Status()
	if err != nil {
		return fmt.Errorf("inspect canonical state worktree: %w", err)
	}
	if !status.IsClean() {
		return errors.New("canonical state worktree/index is dirty; recover or repair it before starting a transaction")
	}
	return nil
}

func validateStateSegment(value string) error {
	if value == "" || value == "." || value == ".." || strings.ContainsAny(value, "/\\\x00\t\r\n") {
		return errors.New("must be one safe path segment")
	}
	return nil
}

func validateStatePath(value string) error {
	if value == "" || filepath.IsAbs(value) || strings.ContainsAny(value, "\\\x00\t\r\n") {
		return errors.New("must be a safe relative POSIX path")
	}
	clean := path.Clean(value)
	if clean != value || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return errors.New("must be a normalized path inside the state worktree")
	}
	for _, segment := range strings.Split(clean, "/") {
		if segment == ".git" {
			return errors.New("may not address the embedded Git metadata")
		}
	}
	return nil
}

func (s *Store) ensureRepository() (*git.Repository, error) {
	if s != nil && s.readRepository != nil {
		return s.readRepository, nil
	}
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
