package state

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
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
	// beforeBoundStageInstall is a deterministic state-package test seam. It is
	// invoked only after source descriptors are retained and before any
	// canonical mutation; production stores leave it nil.
	beforeBoundStageInstall func() error
	// beforeBoundStageCopy runs after the final source-coordinate check and
	// immediately before the bounded descriptor read. It exists only for
	// deterministic in-place mutation tests.
	beforeBoundStageCopy func() error
	// beforeBoundCommit runs after every pre-commit vector check. It lets tests
	// prove the post-commit exact-tree verifier rolls back a commit assembled
	// from an index changed in the final race window.
	beforeBoundCommit func() error
	// afterBoundCommit runs after go-git updates the canonical branch but before
	// post-commit HEAD/index/tree validation. It exists only for deterministic
	// final-race and compare-and-set rollback tests.
	afterBoundCommit func(plumbing.Hash) error
	// beforeUnbornHeadCreate and beforeRawHeadRestore are deterministic seams
	// for exact loose-reference create/CAS tests. Production stores leave them nil.
	beforeUnbornHeadCreate func() error
	beforeRawHeadRestore   func() error
	// syncReferenceDirectory overrides ref-parent durability only in tests so
	// published-but-fsync-error compensation is deterministic.
	syncReferenceDirectory func(string) error
	// beforeReferenceRelease injects a failure after commit validation but
	// before the held native Git locks are released. Production stores leave it nil.
	beforeReferenceRelease func() error
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

type byteCountingReader struct {
	reader io.Reader
	count  int64
}

func (reader *byteCountingReader) Read(buffer []byte) (int, error) {
	count, err := reader.reader.Read(buffer)
	reader.count += int64(count)
	return count, err
}

func fileMatchesIdentity(filename string, identity FileIdentity) (bool, error) {
	info, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false, fmt.Errorf("canonical state file %s is not a regular non-symlink", filename)
	}
	if info.Mode().Perm() != 0o644 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false, nil
	}
	if info.Size() != identity.Size {
		return false, nil
	}
	digest, size, err := hashRegularFile(filename)
	if err != nil {
		return false, err
	}
	return size == identity.Size && digest == identity.SHA256, nil
}

func boundStageSharesPath(bound *boundStagedFile, filename string) (bool, error) {
	info, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false, fmt.Errorf("canonical state file %s is not a regular non-symlink", filename)
	}
	return os.SameFile(bound.info, info), nil
}

func (s *Store) copyBoundStage(destination string, bound *boundStagedFile) error {
	if err := s.verifyBoundStageCoordinate(bound); err != nil {
		return err
	}
	if _, err := bound.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if s.beforeBoundStageCopy != nil {
		if err := s.beforeBoundStageCopy(); err != nil {
			return err
		}
	}
	hasher := sha256.New()
	reader := &byteCountingReader{reader: io.TeeReader(io.LimitReader(bound.file, bound.identity.Size+1), hasher)}
	copyErr := manifest.AtomicCopy(destination, reader, 0o644)
	coordinateErr := s.verifyBoundStageCoordinate(bound)
	var identityErr error
	if reader.count != bound.identity.Size || hex.EncodeToString(hasher.Sum(nil)) != bound.identity.SHA256 {
		identityErr = fmt.Errorf("%w: staged file %s changed while installing canonical state", ErrFileConflict, bound.canonical)
	}
	if copyErr != nil || coordinateErr != nil || identityErr != nil {
		return errors.Join(copyErr, coordinateErr, identityErr)
	}
	return nil
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

type repositoryHeadSnapshot struct {
	raw    *plumbing.Reference
	target *plumbing.Reference
	name   plumbing.ReferenceName
	hash   plumbing.Hash
}

func snapshotRepositoryHead(repository *git.Repository) (repositoryHeadSnapshot, error) {
	raw, err := repository.Storer.Reference(plumbing.HEAD)
	if err != nil {
		return repositoryHeadSnapshot{}, err
	}
	name := plumbing.HEAD
	if raw.Type() == plumbing.SymbolicReference {
		name = raw.Target()
	}
	target, err := repository.Storer.Reference(name)
	if errors.Is(err, plumbing.ErrReferenceNotFound) {
		return repositoryHeadSnapshot{raw: raw, name: name}, nil
	}
	if err != nil {
		return repositoryHeadSnapshot{}, err
	}
	return repositoryHeadSnapshot{raw: raw, target: target, name: name, hash: target.Hash()}, nil
}

func referencesEqual(left, right *plumbing.Reference) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Type() == right.Type() && left.Name() == right.Name() && left.Hash() == right.Hash() && left.Target() == right.Target()
}

func referenceBody(reference *plumbing.Reference) (string, error) {
	if reference == nil {
		return "", errors.New("Git reference is unavailable")
	}
	switch reference.Type() {
	case plumbing.SymbolicReference:
		return "ref: " + reference.Target().String() + "\n", nil
	case plumbing.HashReference:
		return reference.Hash().String() + "\n", nil
	default:
		return "", fmt.Errorf("unsupported Git reference type %s", reference.Type())
	}
}

func canonicalLooseReferencePath(workDir string, name plumbing.ReferenceName) (string, error) {
	if err := name.Validate(); err != nil {
		return "", err
	}
	value := name.String()
	if value != plumbing.HEAD.String() && !strings.HasPrefix(value, "refs/") {
		return "", fmt.Errorf("unsupported loose Git reference %s", value)
	}
	return filepath.Join(workDir, ".git", filepath.FromSlash(value)), nil
}

type boundGitRoot struct {
	root     *os.Root
	path     string
	identity os.FileInfo
}

type boundReferenceParent struct {
	root     *os.Root
	git      *boundGitRoot
	relative string
	path     string
	identity os.FileInfo
}

func bindGitRoot(workDir string) (*boundGitRoot, error) {
	gitPath := filepath.Join(workDir, ".git")
	before, err := os.Lstat(gitPath)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.Join(err, errors.New("canonical .git is not a real directory"))
	}
	root, err := os.OpenRoot(gitPath)
	if err != nil {
		return nil, err
	}
	opened, statErr := root.Stat(".")
	after, pathErr := os.Lstat(gitPath)
	if statErr != nil || pathErr != nil || !os.SameFile(before, opened) || !os.SameFile(before, after) {
		return nil, errors.Join(statErr, pathErr, root.Close(), errors.New("canonical .git changed while binding reference root"))
	}
	return &boundGitRoot{root: root, path: gitPath, identity: before}, nil
}

func (bound *boundGitRoot) relative(filename string) (string, error) {
	relative, err := filepath.Rel(bound.path, filename)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.Join(err, errors.New("Git reference path escapes the bound .git directory"))
	}
	return relative, nil
}

func (bound *boundGitRoot) verify() error {
	opened, statErr := bound.root.Stat(".")
	current, pathErr := os.Lstat(bound.path)
	if statErr != nil || pathErr != nil || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() ||
		!os.SameFile(bound.identity, opened) || !os.SameFile(bound.identity, current) {
		return errors.Join(statErr, pathErr, errors.New("canonical .git changed during reference mutation"))
	}
	return nil
}

func bindReferenceParent(bound *boundGitRoot, filename string) (*boundReferenceParent, string, error) {
	if err := ensureRealReferenceParentAt(bound, filename); err != nil {
		return nil, "", err
	}
	relative := filepath.Dir(filename)
	base := filepath.Base(filename)
	before, err := bound.root.Lstat(relative)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, "", errors.Join(err, fmt.Errorf("Git reference parent %s is not a real directory", relative))
	}
	root, err := bound.root.OpenRoot(relative)
	if err != nil {
		return nil, "", err
	}
	opened, statErr := root.Stat(".")
	after, pathErr := bound.root.Lstat(relative)
	if statErr != nil || pathErr != nil || !os.SameFile(before, opened) || !os.SameFile(before, after) {
		return nil, "", errors.Join(statErr, pathErr, root.Close(), errors.New("Git reference parent changed while binding"))
	}
	return &boundReferenceParent{
		root: root, git: bound, relative: relative,
		path: filepath.Join(bound.path, relative), identity: before,
	}, base, nil
}

func (parent *boundReferenceParent) verify() error {
	if err := parent.git.verify(); err != nil {
		return err
	}
	opened, statErr := parent.root.Stat(".")
	current, pathErr := parent.git.root.Lstat(parent.relative)
	if statErr != nil || pathErr != nil || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() ||
		!os.SameFile(parent.identity, opened) || !os.SameFile(parent.identity, current) {
		return errors.Join(statErr, pathErr, errors.New("Git reference parent changed during mutation"))
	}
	return nil
}

func (parent *boundReferenceParent) sync(testHook func(string) error) (resultErr error) {
	if testHook != nil {
		if err := testHook(parent.path); err != nil {
			return err
		}
	}
	if err := parent.verify(); err != nil {
		return err
	}
	directory, err := parent.root.Open(".")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, directory.Close()) }()
	if err := directory.Sync(); err != nil {
		return err
	}
	return parent.verify()
}

func ensureRealReferenceParentAt(bound *boundGitRoot, filename string) error {
	if err := bound.verify(); err != nil {
		return err
	}
	directory := filepath.Dir(filename)
	if directory == "." {
		return nil
	}
	current := ""
	for _, component := range strings.Split(directory, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return fmt.Errorf("invalid Git reference parent component %q", component)
		}
		current = filepath.Join(current, component)
		info, err := bound.root.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if mkdirErr := bound.root.Mkdir(current, 0o755); mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
				return mkdirErr
			}
			info, err = bound.root.Lstat(current)
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.Join(err, fmt.Errorf("Git reference parent %s is not a real directory", current))
		}
	}
	return bound.verify()
}

func closeLockedReference(file *os.File) error {
	return errors.Join(releaseStateLockLease(file), file.Close())
}

func openLockedReferenceAt(root *os.Root, name string) (*os.File, os.FileInfo, error) {
	file, err := root.OpenFile(name, os.O_RDWR|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, nil, errors.Join(err, file.Close(), fmt.Errorf("Git reference %s is not a regular file", name))
	}
	locked, err := tryStateLockLease(file)
	if err != nil || !locked {
		return nil, nil, errors.Join(err, file.Close(), fmt.Errorf("%w: Git reference %s is being modified", ErrRefConflict, name))
	}
	pathInfo, err := root.Lstat(name)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) {
		return nil, nil, errors.Join(err, releaseStateLockLease(file), file.Close(), fmt.Errorf("%w: Git reference %s changed while locking", ErrRefConflict, name))
	}
	return file, info, nil
}

func readLockedReference(file *os.File) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	body, err := io.ReadAll(io.LimitReader(file, 1025))
	if err != nil {
		return "", err
	}
	if len(body) > 1024 {
		return "", errors.New("Git reference exceeds the bounded size limit")
	}
	return string(body), nil
}

const referenceLockMarkerV1 = "sow-reference-lock-v1"

type referenceLockMarker struct {
	pid        int
	identity   processIdentity
	tempName   string
	markerName string
}

func (marker referenceLockMarker) encode() string {
	parts := []string{
		referenceLockMarkerV1,
		strconv.Itoa(marker.pid),
		marker.identity.Scheme,
		marker.identity.BootToken,
		marker.identity.StartToken,
		marker.tempName,
	}
	if marker.markerName != "" {
		parts = append(parts, marker.markerName)
	}
	return strings.Join(append(parts, ""), "\n")
}

func parseReferenceLockMarker(body string) (referenceLockMarker, error) {
	parts := strings.Split(body, "\n")
	if (len(parts) != 7 && len(parts) != 8) || parts[0] != referenceLockMarkerV1 || parts[len(parts)-1] != "" {
		return referenceLockMarker{}, errors.New("Git reference lock is not a SOW-owned marker")
	}
	pid, err := strconv.Atoi(parts[1])
	if err != nil || pid <= 0 {
		return referenceLockMarker{}, errors.New("SOW Git reference lock PID is invalid")
	}
	identity := processIdentity{Scheme: parts[2], BootToken: parts[3], StartToken: parts[4]}
	if err := identity.validate(); err != nil {
		return referenceLockMarker{}, err
	}
	if parts[5] == "" || filepath.Base(parts[5]) != parts[5] || !strings.HasPrefix(parts[5], ".sow-ref-") {
		return referenceLockMarker{}, errors.New("SOW Git reference lock temporary name is invalid")
	}
	markerName := ""
	if len(parts) == 8 {
		markerName = parts[6]
		if markerName == "" || filepath.Base(markerName) != markerName || !strings.HasPrefix(markerName, ".sow-lock-") {
			return referenceLockMarker{}, errors.New("SOW Git reference lock marker name is invalid")
		}
	}
	return referenceLockMarker{pid: pid, identity: identity, tempName: parts[5], markerName: markerName}, nil
}

func removeReferenceAt(root *os.Root, name string) error {
	if name == "" {
		return nil
	}
	err := root.Remove(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func writeExclusiveSyncedFileAt(root *os.Root, name, body string) (resultErr error) {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	remove := true
	closed := false
	defer func() {
		var closeErr error
		if !closed {
			closeErr = file.Close()
		}
		if remove {
			removeErr := root.Remove(name)
			if errors.Is(removeErr, os.ErrNotExist) {
				removeErr = nil
			}
			closeErr = errors.Join(closeErr, removeErr)
		}
		resultErr = errors.Join(resultErr, closeErr)
	}()
	if _, err := io.WriteString(file, body); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	closeErr := file.Close()
	closed = true
	if closeErr != nil {
		return closeErr
	}
	remove = false
	return nil
}

func readBoundedRegularFileAt(root *os.Root, name string, limit int64) (body string, identity os.FileInfo, resultErr error) {
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	identity, err = file.Stat()
	if err != nil || !identity.Mode().IsRegular() {
		return "", nil, errors.Join(err, errors.New("Git reference lock is not a regular file"))
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return "", nil, errors.Join(err, errors.New("Git reference lock exceeds its bounded size"))
	}
	after, err := root.Lstat(name)
	if err != nil || !os.SameFile(identity, after) {
		return "", nil, errors.Join(err, errors.New("Git reference lock changed while reading"))
	}
	return string(data), identity, nil
}

func recoverStaleReferenceLock(parent *boundReferenceParent, lockPath string, syncDirectory func(string) error) error {
	body, identity, err := readBoundedRegularFileAt(parent.root, lockPath, 4096)
	if err != nil {
		return fmt.Errorf("%w: inspect Git reference lock %s: %v", ErrRefConflict, lockPath, err)
	}
	marker, err := parseReferenceLockMarker(body)
	if err != nil {
		return fmt.Errorf("%w: Git reference lock %s is not recoverable by SOW: %v", ErrRefConflict, lockPath, err)
	}
	observed, identityErr := readProcessIdentity(marker.pid)
	if identityErr == nil && observed == marker.identity {
		return fmt.Errorf("%w: Git reference lock %s belongs to a live process instance", ErrRefConflict, lockPath)
	}
	if identityErr != nil && !errors.Is(identityErr, errProcessIdentityNotFound) {
		return fmt.Errorf("%w: cannot prove Git reference lock %s is stale: %v", ErrRefConflict, lockPath, identityErr)
	}
	after, err := parent.root.Lstat(lockPath)
	if err != nil || !os.SameFile(identity, after) {
		return errors.Join(err, fmt.Errorf("%w: Git reference lock %s changed before stale recovery", ErrRefConflict, lockPath))
	}
	temporary := marker.tempName
	tempInfo, tempErr := parent.root.Lstat(temporary)
	if tempErr == nil && tempInfo.Mode().IsRegular() {
		tempErr = parent.root.Remove(temporary)
	} else if errors.Is(tempErr, os.ErrNotExist) {
		tempErr = nil
	} else if tempErr == nil {
		tempErr = errors.New("stale Git reference temporary is not a regular file")
	}
	if tempErr != nil {
		return tempErr
	}
	if marker.markerName != "" {
		markerErr := removeReferenceAt(parent.root, marker.markerName)
		if markerErr != nil {
			return markerErr
		}
	}
	if err := parent.root.Remove(lockPath); err != nil {
		return err
	}
	return parent.sync(syncDirectory)
}

func prepareReferencePublication(parent *boundReferenceParent, reference, body string, syncDirectory func(string) error) (lockPath, temporary, markerTemporary string, resultErr error) {
	identity, err := readProcessIdentity(os.Getpid())
	if err != nil {
		return "", "", "", err
	}
	token, err := NewTransactionID()
	if err != nil {
		return "", "", "", err
	}
	marker := referenceLockMarker{
		pid: os.Getpid(), identity: identity,
		tempName: ".sow-ref-" + token, markerName: ".sow-lock-" + token,
	}
	lockPath = reference + ".lock"
	for attempt := 0; attempt < 2; attempt++ {
		if err = writeExclusiveSyncedFileAt(parent.root, marker.markerName, marker.encode()); err != nil {
			return "", "", "", err
		}
		err = parent.root.Link(marker.markerName, lockPath)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrExist) && !errors.Is(err, syscall.EEXIST) {
			return "", "", "", errors.Join(err, removeReferenceAt(parent.root, marker.markerName))
		}
		if removeErr := removeReferenceAt(parent.root, marker.markerName); removeErr != nil {
			return "", "", "", removeErr
		}
		if recoverErr := recoverStaleReferenceLock(parent, lockPath, syncDirectory); recoverErr != nil {
			return "", "", "", recoverErr
		}
	}
	if err != nil {
		return "", "", "", err
	}
	markerTemporary = marker.markerName
	if err := removeReferenceAt(parent.root, markerTemporary); err != nil {
		return "", "", "", errors.Join(err, removeReferenceAt(parent.root, lockPath))
	}
	markerTemporary = ""
	if err := parent.sync(nil); err != nil {
		return "", "", "", errors.Join(err, removeReferenceAt(parent.root, lockPath))
	}
	removeLock := true
	defer func() {
		if removeLock {
			resultErr = errors.Join(resultErr, removeReferenceAt(parent.root, temporary), removeReferenceAt(parent.root, markerTemporary), removeReferenceAt(parent.root, lockPath))
		}
	}()
	temporary = marker.tempName
	if err := writeExclusiveSyncedFileAt(parent.root, temporary, body); err != nil {
		return "", "", "", err
	}
	removeLock = false
	return lockPath, temporary, markerTemporary, nil
}

// heldReferenceMutation keeps Git's native <ref>.lock published until the
// caller has validated the commit and either accepted or rolled back the
// canonical worktree/index. This closes the otherwise-valid native Git writer
// window between reference publication and post-commit verification.
type heldReferenceMutation struct {
	bound           *boundGitRoot
	parent          *boundReferenceParent
	referenceBase   string
	lock            string
	temporary       string
	markerTemporary string
	beforeBody      string
	afterBody       string
	beforeExists    bool
	published       bool
	closed          bool
}

type heldRepositoryHeadMutation struct {
	raw    *heldReferenceMutation
	target *heldReferenceMutation
}

func (mutation *heldRepositoryHeadMutation) close() error {
	if mutation == nil {
		return nil
	}
	return errors.Join(mutation.target.close(), mutation.raw.close())
}

func (mutation *heldRepositoryHeadMutation) rollback(syncDirectory func(string) error) error {
	if mutation == nil {
		return nil
	}
	return mutation.target.rollback(syncDirectory)
}

func (mutation *heldReferenceMutation) close() error {
	if mutation == nil || mutation.closed {
		return nil
	}
	mutation.closed = true
	cleanupErr := errors.Join(
		removeReferenceAt(mutation.parent.root, mutation.temporary),
		removeReferenceAt(mutation.parent.root, mutation.markerTemporary),
		removeReferenceAt(mutation.parent.root, mutation.lock),
	)
	cleanupErr = errors.Join(cleanupErr, mutation.parent.sync(nil), mutation.parent.root.Close(), mutation.bound.root.Close())
	return cleanupErr
}

func (mutation *heldReferenceMutation) rollback(syncDirectory func(string) error) error {
	if mutation == nil || !mutation.published {
		return nil
	}
	current, _, err := readBoundedRegularFileAt(mutation.parent.root, mutation.referenceBase, 1024)
	if err != nil || current != mutation.afterBody {
		return errors.Join(err, fmt.Errorf("%w: canonical Git reference changed before held rollback", ErrRefConflict))
	}
	if !mutation.beforeExists {
		if err := mutation.parent.root.Remove(mutation.referenceBase); err != nil {
			return err
		}
	} else {
		token, err := NewTransactionID()
		if err != nil {
			return err
		}
		rollbackTemporary := ".sow-ref-rollback-" + token
		if err := writeExclusiveSyncedFileAt(mutation.parent.root, rollbackTemporary, mutation.beforeBody); err != nil {
			return err
		}
		defer func() { _ = removeReferenceAt(mutation.parent.root, rollbackTemporary) }()
		if err := mutation.parent.root.Rename(rollbackTemporary, mutation.referenceBase); err != nil {
			return err
		}
	}
	mutation.published = false
	return mutation.parent.sync(syncDirectory)
}

func (mutation *heldReferenceMutation) replaceWhileLocked(expected, replacement *plumbing.Reference, syncDirectory func(string) error) error {
	if mutation == nil || expected == nil || replacement == nil || expected.Name() != replacement.Name() {
		return errors.New("held Git reference replacement has invalid coordinates")
	}
	want, err := referenceBody(expected)
	if err != nil {
		return err
	}
	next, err := referenceBody(replacement)
	if err != nil {
		return err
	}
	current, _, err := readBoundedRegularFileAt(mutation.parent.root, mutation.referenceBase, 1024)
	if err != nil || current != want {
		return errors.Join(err, fmt.Errorf("%w: held Git reference changed before exact replacement", ErrRefConflict))
	}
	token, err := NewTransactionID()
	if err != nil {
		return err
	}
	temporary := ".sow-ref-held-" + token
	if err := writeExclusiveSyncedFileAt(mutation.parent.root, temporary, next); err != nil {
		return err
	}
	defer func() { _ = removeReferenceAt(mutation.parent.root, temporary) }()
	if err := mutation.parent.root.Rename(temporary, mutation.referenceBase); err != nil {
		return err
	}
	return mutation.parent.sync(syncDirectory)
}

func beginHeldReferenceCoordinateLock(workDir string, name plumbing.ReferenceName) (*heldReferenceMutation, error) {
	filename, err := canonicalLooseReferencePath(workDir, name)
	if err != nil {
		return nil, err
	}
	bound, err := bindGitRoot(workDir)
	if err != nil {
		return nil, err
	}
	referenceName, err := bound.relative(filename)
	if err != nil {
		return nil, errors.Join(err, bound.root.Close())
	}
	parent, referenceBase, err := bindReferenceParent(bound, referenceName)
	if err != nil {
		return nil, errors.Join(err, bound.root.Close())
	}
	lock, temporary, markerTemporary, err := prepareReferencePublication(parent, referenceBase, "", nil)
	if err != nil {
		return nil, errors.Join(err, parent.root.Close(), bound.root.Close())
	}
	return &heldReferenceMutation{
		bound: bound, parent: parent, referenceBase: referenceBase,
		lock: lock, temporary: temporary, markerTemporary: markerTemporary,
	}, nil
}

func beginHeldReferenceReplacement(workDir string, expected, replacement *plumbing.Reference, syncDirectory func(string) error) (*heldReferenceMutation, bool, error) {
	if expected == nil || replacement == nil || expected.Name() != replacement.Name() {
		return nil, false, errors.New("held Git reference replacement requires one stable reference name")
	}
	filename, err := canonicalLooseReferencePath(workDir, expected.Name())
	if err != nil {
		return nil, false, err
	}
	bound, err := bindGitRoot(workDir)
	if err != nil {
		return nil, false, err
	}
	referenceName, err := bound.relative(filename)
	if err != nil {
		return nil, false, errors.Join(err, bound.root.Close())
	}
	parent, referenceBase, err := bindReferenceParent(bound, referenceName)
	if err != nil {
		return nil, false, errors.Join(err, bound.root.Close())
	}
	want, err := referenceBody(expected)
	if err != nil {
		return nil, false, errors.Join(err, parent.root.Close(), bound.root.Close())
	}
	next, err := referenceBody(replacement)
	if err != nil {
		return nil, false, errors.Join(err, parent.root.Close(), bound.root.Close())
	}
	lock, temporary, markerTemporary, err := prepareReferencePublication(parent, referenceBase, next, syncDirectory)
	if err != nil {
		return nil, false, errors.Join(err, parent.root.Close(), bound.root.Close())
	}
	mutation := &heldReferenceMutation{
		bound: bound, parent: parent, referenceBase: referenceBase,
		lock: lock, temporary: temporary, markerTemporary: markerTemporary,
		beforeBody: want, afterBody: next, beforeExists: true,
	}
	fail := func(published bool, failure error) (*heldReferenceMutation, bool, error) {
		if published {
			mutation.published = true
			return mutation, true, failure
		}
		return nil, false, errors.Join(failure, mutation.close())
	}
	file, identity, err := openLockedReferenceAt(parent.root, referenceBase)
	if errors.Is(err, os.ErrNotExist) {
		readerRoot, rootErr := bound.root.OpenRoot(".")
		if rootErr != nil {
			return fail(false, rootErr)
		}
		repository, closeRepository, openErr := OpenBoundRepository(readerRoot)
		if openErr != nil {
			return fail(false, openErr)
		}
		current, refErr := repository.Storer.Reference(expected.Name())
		closeErr := closeRepository()
		if refErr != nil || closeErr != nil || !referencesEqual(current, expected) {
			return fail(false, errors.Join(refErr, closeErr, fmt.Errorf("%w: packed Git reference %s changed before exact replacement", ErrRefConflict, expected.Name())))
		}
		if err := parent.verify(); err != nil {
			return fail(false, err)
		}
		if err := parent.root.Link(temporary, referenceBase); err != nil {
			return fail(false, err)
		}
		mutation.published = true
		if err := parent.root.Remove(temporary); err != nil {
			return fail(true, err)
		}
		return mutation, true, parent.sync(syncDirectory)
	}
	if err != nil {
		return fail(false, err)
	}
	current, readErr := readLockedReference(file)
	pathInfo, pathErr := parent.root.Lstat(referenceBase)
	closeErr := closeLockedReference(file)
	if readErr != nil || pathErr != nil || closeErr != nil || current != want || !os.SameFile(identity, pathInfo) {
		return fail(false, errors.Join(readErr, pathErr, closeErr, fmt.Errorf("%w: Git reference %s changed before held replacement", ErrRefConflict, expected.Name())))
	}
	if err := parent.verify(); err != nil {
		return fail(false, err)
	}
	if err := parent.root.Rename(temporary, referenceBase); err != nil {
		return fail(false, err)
	}
	mutation.published = true
	return mutation, true, parent.sync(syncDirectory)
}

func beginHeldReferenceCreate(workDir string, reference *plumbing.Reference, syncDirectory func(string) error) (*heldReferenceMutation, bool, error) {
	filename, err := canonicalLooseReferencePath(workDir, reference.Name())
	if err != nil {
		return nil, false, err
	}
	body, err := referenceBody(reference)
	if err != nil {
		return nil, false, err
	}
	bound, err := bindGitRoot(workDir)
	if err != nil {
		return nil, false, err
	}
	referenceName, err := bound.relative(filename)
	if err != nil {
		return nil, false, errors.Join(err, bound.root.Close())
	}
	parent, referenceBase, err := bindReferenceParent(bound, referenceName)
	if err != nil {
		return nil, false, errors.Join(err, bound.root.Close())
	}
	lock, temporary, markerTemporary, err := prepareReferencePublication(parent, referenceBase, body, syncDirectory)
	if err != nil {
		return nil, false, errors.Join(err, parent.root.Close(), bound.root.Close())
	}
	mutation := &heldReferenceMutation{
		bound: bound, parent: parent, referenceBase: referenceBase,
		lock: lock, temporary: temporary, markerTemporary: markerTemporary,
		afterBody: body,
	}
	if err := parent.verify(); err != nil {
		return nil, false, errors.Join(err, mutation.close())
	}
	if err := parent.root.Link(temporary, referenceBase); err != nil {
		if errors.Is(err, os.ErrExist) || errors.Is(err, syscall.EEXIST) {
			err = errors.Join(err, fmt.Errorf("%w: initial canonical HEAD target appeared before commit", ErrRefConflict))
		}
		return nil, false, errors.Join(err, mutation.close())
	}
	mutation.published = true
	if err := parent.root.Remove(temporary); err != nil {
		return mutation, true, err
	}
	return mutation, true, parent.sync(syncDirectory)
}

func replaceLooseReferenceExact(workDir string, expected, replacement *plumbing.Reference, syncDirectory func(string) error) (published bool, resultErr error) {
	if expected == nil || replacement == nil || expected.Name() != replacement.Name() {
		return false, errors.New("exact Git reference replacement requires one stable reference name")
	}
	filename, err := canonicalLooseReferencePath(workDir, expected.Name())
	if err != nil {
		return false, err
	}
	bound, err := bindGitRoot(workDir)
	if err != nil {
		return false, err
	}
	defer func() { resultErr = errors.Join(resultErr, bound.root.Close()) }()
	referenceName, err := bound.relative(filename)
	if err != nil {
		return false, err
	}
	parent, referenceBase, err := bindReferenceParent(bound, referenceName)
	if err != nil {
		return false, err
	}
	defer func() { resultErr = errors.Join(resultErr, parent.root.Close()) }()
	want, err := referenceBody(expected)
	if err != nil {
		return false, err
	}
	next, err := referenceBody(replacement)
	if err != nil {
		return false, err
	}
	lock, temporary, markerTemporary, err := prepareReferencePublication(parent, referenceBase, next, syncDirectory)
	if err != nil {
		return false, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, removeReferenceAt(parent.root, temporary), removeReferenceAt(parent.root, markerTemporary), removeReferenceAt(parent.root, lock))
	}()
	file, identity, err := openLockedReferenceAt(parent.root, referenceBase)
	if errors.Is(err, os.ErrNotExist) {
		readerRoot, rootErr := bound.root.OpenRoot(".")
		if rootErr != nil {
			return false, rootErr
		}
		repository, closeRepository, openErr := OpenBoundRepository(readerRoot)
		if openErr != nil {
			return false, openErr
		}
		defer func() { resultErr = errors.Join(resultErr, closeRepository()) }()
		current, refErr := repository.Storer.Reference(expected.Name())
		if refErr != nil || !referencesEqual(current, expected) {
			return false, errors.Join(refErr, fmt.Errorf("%w: packed Git reference %s changed before exact replacement", ErrRefConflict, expected.Name()))
		}
		if err := parent.verify(); err != nil {
			return false, err
		}
		if err := parent.root.Link(temporary, referenceBase); err != nil {
			return false, err
		}
		if err := parent.root.Remove(temporary); err != nil {
			return true, err
		}
		published = true
		cleanupErr := errors.Join(removeReferenceAt(parent.root, temporary), removeReferenceAt(parent.root, lock))
		return true, errors.Join(
			parent.sync(syncDirectory),
			cleanupErr,
		)
	}
	if err != nil {
		return false, err
	}
	defer func() { resultErr = errors.Join(resultErr, closeLockedReference(file)) }()
	current, err := readLockedReference(file)
	if err != nil || current != want {
		return false, errors.Join(err, fmt.Errorf("%w: Git reference %s changed before exact replacement", ErrRefConflict, expected.Name()))
	}
	pathInfo, err := parent.root.Lstat(referenceBase)
	if err != nil || !os.SameFile(identity, pathInfo) {
		return false, errors.Join(err, fmt.Errorf("%w: Git reference %s changed before exact replacement", ErrRefConflict, expected.Name()))
	}
	if err := parent.verify(); err != nil {
		return false, err
	}
	if err := parent.root.Rename(temporary, referenceBase); err != nil {
		return false, err
	}
	published = true
	cleanupErr := errors.Join(removeReferenceAt(parent.root, temporary), removeReferenceAt(parent.root, lock))
	return true, errors.Join(
		parent.sync(syncDirectory),
		cleanupErr,
	)
}

func requireRepositoryHead(repository *git.Repository, expected repositoryHeadSnapshot) error {
	current, err := snapshotRepositoryHead(repository)
	if err != nil {
		return err
	}
	if !referencesEqual(current.raw, expected.raw) || !referencesEqual(current.target, expected.target) || current.name != expected.name {
		return fmt.Errorf("%w: canonical raw HEAD or target changed during state installation", ErrRefConflict)
	}
	return nil
}

func requireRepositoryHeadCommit(repository *git.Repository, expected repositoryHeadSnapshot, commit plumbing.Hash) error {
	current, err := snapshotRepositoryHead(repository)
	if err != nil {
		return err
	}
	rawMatches := referencesEqual(current.raw, expected.raw)
	if expected.raw.Type() == plumbing.HashReference {
		rawMatches = current.raw.Type() == plumbing.HashReference && current.raw.Name() == expected.raw.Name() && current.raw.Hash() == commit
	}
	if !rawMatches || current.name != expected.name || current.target == nil || current.target.Hash() != commit {
		return fmt.Errorf("%w: canonical raw HEAD or target changed after state commit", ErrRefConflict)
	}
	return nil
}

func requireCanonicalIndexVector(repository *git.Repository, expected map[string]canonicalWorktreeEntry) error {
	current, err := repository.Storer.Index()
	if err != nil {
		return err
	}
	if len(current.Entries) != len(expected) {
		return fmt.Errorf("%w: canonical Git index namespace changed during state installation", ErrRefConflict)
	}
	seen := make(map[string]struct{}, len(current.Entries))
	for _, entry := range current.Entries {
		if entry == nil || entry.Stage != 0 || entry.SkipWorktree || entry.IntentToAdd {
			return fmt.Errorf("%w: canonical Git index contains noncanonical merge, sparse, or intent-to-add state", ErrRefConflict)
		}
		want, exists := expected[entry.Name]
		if !exists || entry.Hash != want.hash || entry.Mode != want.mode {
			return fmt.Errorf("%w: canonical Git index entry %s changed during state installation", ErrRefConflict, entry.Name)
		}
		if _, duplicate := seen[entry.Name]; duplicate {
			return fmt.Errorf("%w: canonical Git index contains duplicate entry %s", ErrRefConflict, entry.Name)
		}
		seen[entry.Name] = struct{}{}
	}
	return nil
}

func requireCommitMatchesIndexVector(repository *git.Repository, hash, parent plumbing.Hash, expected map[string]canonicalWorktreeEntry) error {
	commit, err := repository.CommitObject(hash)
	if err != nil {
		return err
	}
	if parent.IsZero() {
		if len(commit.ParentHashes) != 0 {
			return fmt.Errorf("%w: initial canonical commit unexpectedly has parents", ErrRefConflict)
		}
	} else if len(commit.ParentHashes) != 1 || commit.ParentHashes[0] != parent {
		return fmt.Errorf("%w: canonical commit parent changed during state installation", ErrRefConflict)
	}
	tree, err := commit.Tree()
	if err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(expected))
	if err := requireTreeMatchesIndexVector(repository, tree, "", expected, seen, 0); err != nil {
		return err
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("%w: canonical commit tree is incomplete", ErrRefConflict)
	}
	return nil
}

func requireTreeMatchesIndexVector(repository *git.Repository, tree *object.Tree, prefix string, expected map[string]canonicalWorktreeEntry, seen map[string]struct{}, depth int) error {
	if depth > 1024 {
		return fmt.Errorf("%w: canonical commit tree exceeds maximum depth", ErrRefConflict)
	}
	for _, entry := range tree.Entries {
		name := path.Join(prefix, entry.Name)
		if entry.Mode == filemode.Dir {
			child, err := object.GetTree(repository.Storer, entry.Hash)
			if err != nil {
				return fmt.Errorf("read canonical commit subtree %s: %w", name, err)
			}
			if err := requireTreeMatchesIndexVector(repository, child, name, expected, seen, depth+1); err != nil {
				return err
			}
			continue
		}
		want, exists := expected[name]
		if !exists || entry.Hash != want.hash || entry.Mode != want.mode {
			return fmt.Errorf("%w: canonical commit contains unexpected tree entry %s", ErrRefConflict, name)
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("%w: canonical commit contains duplicate tree entry %s", ErrRefConflict, name)
		}
		seen[name] = struct{}{}
	}
	return nil
}

func (mutation *heldRepositoryHeadMutation) restoreRawHead(store *Store, repository *git.Repository, snapshot repositoryHeadSnapshot) error {
	currentRaw, err := repository.Storer.Reference(plumbing.HEAD)
	if err != nil {
		return err
	}
	if referencesEqual(currentRaw, snapshot.raw) {
		return nil
	}
	if store.beforeRawHeadRestore != nil {
		if err := store.beforeRawHeadRestore(); err != nil {
			return err
		}
	}
	guard := mutation.raw
	if guard == nil && mutation.target != nil && mutation.target.referenceBase == plumbing.HEAD.String() {
		guard = mutation.target
	}
	if guard == nil {
		_, rawErr := replaceLooseReferenceExact(store.workDir, currentRaw, snapshot.raw, store.syncReferenceDirectory)
		return rawErr
	}
	return guard.replaceWhileLocked(currentRaw, snapshot.raw, store.syncReferenceDirectory)
}

type canonicalTreeBuildNode struct {
	files map[string]canonicalWorktreeEntry
	dirs  map[string]*canonicalTreeBuildNode
}

func canonicalTreeFromIndexVector(repository *git.Repository, expected map[string]canonicalWorktreeEntry) (plumbing.Hash, error) {
	root := &canonicalTreeBuildNode{files: make(map[string]canonicalWorktreeEntry), dirs: make(map[string]*canonicalTreeBuildNode)}
	paths := make([]string, 0, len(expected))
	for name := range expected {
		paths = append(paths, name)
	}
	sort.Strings(paths)
	for _, name := range paths {
		parts := strings.Split(name, "/")
		node := root
		for index, part := range parts {
			if part == "" {
				return plumbing.ZeroHash, fmt.Errorf("invalid empty canonical tree component in %s", name)
			}
			if index == len(parts)-1 {
				if _, exists := node.dirs[part]; exists {
					return plumbing.ZeroHash, fmt.Errorf("canonical tree path %s conflicts with a directory", name)
				}
				node.files[part] = expected[name]
				continue
			}
			if _, exists := node.files[part]; exists {
				return plumbing.ZeroHash, fmt.Errorf("canonical tree directory %s conflicts with a file", strings.Join(parts[:index+1], "/"))
			}
			child := node.dirs[part]
			if child == nil {
				child = &canonicalTreeBuildNode{files: make(map[string]canonicalWorktreeEntry), dirs: make(map[string]*canonicalTreeBuildNode)}
				node.dirs[part] = child
			}
			node = child
		}
	}
	return storeCanonicalTreeNode(repository, root)
}

func storeCanonicalTreeNode(repository *git.Repository, node *canonicalTreeBuildNode) (plumbing.Hash, error) {
	entries := make([]object.TreeEntry, 0, len(node.files)+len(node.dirs))
	for name, file := range node.files {
		if _, err := repository.Storer.EncodedObject(plumbing.BlobObject, file.hash); err != nil {
			return plumbing.ZeroHash, fmt.Errorf("read canonical blob %s: %w", file.hash, err)
		}
		entries = append(entries, object.TreeEntry{Name: name, Mode: file.mode, Hash: file.hash})
	}
	for name, child := range node.dirs {
		hash, err := storeCanonicalTreeNode(repository, child)
		if err != nil {
			return plumbing.ZeroHash, err
		}
		entries = append(entries, object.TreeEntry{Name: name, Mode: filemode.Dir, Hash: hash})
	}
	sort.Sort(object.TreeEntrySorter(entries))
	tree := &object.Tree{Entries: entries}
	encoded := repository.Storer.NewEncodedObject()
	if err := tree.Encode(encoded); err != nil {
		return plumbing.ZeroHash, err
	}
	return repository.Storer.SetEncodedObject(encoded)
}

func createCanonicalCommit(repository *git.Repository, expected map[string]canonicalWorktreeEntry, parent plumbing.Hash, message string, signature object.Signature) (plumbing.Hash, error) {
	tree, err := canonicalTreeFromIndexVector(repository, expected)
	if err != nil {
		return plumbing.ZeroHash, err
	}
	commit := &object.Commit{Author: signature, Committer: signature, Message: message, TreeHash: tree}
	if !parent.IsZero() {
		commit.ParentHashes = []plumbing.Hash{parent}
	}
	encoded := repository.Storer.NewEncodedObject()
	if err := commit.Encode(encoded); err != nil {
		return plumbing.ZeroHash, err
	}
	return repository.Storer.SetEncodedObject(encoded)
}

func (s *Store) advanceRepositoryHead(repository *git.Repository, snapshot repositoryHeadSnapshot, commit plumbing.Hash) (*heldRepositoryHeadMutation, bool, error) {
	if err := requireRepositoryHead(repository, snapshot); err != nil {
		return nil, false, err
	}
	var rawLock *heldReferenceMutation
	if snapshot.raw.Type() == plumbing.SymbolicReference {
		var err error
		rawLock, err = beginHeldReferenceCoordinateLock(s.workDir, plumbing.HEAD)
		if err != nil {
			return nil, false, err
		}
		if err := requireRepositoryHead(repository, snapshot); err != nil {
			return nil, false, errors.Join(err, rawLock.close())
		}
	}
	finish := func(target *heldReferenceMutation, published bool, err error) (*heldRepositoryHeadMutation, bool, error) {
		if target == nil {
			return nil, published, errors.Join(err, rawLock.close())
		}
		return &heldRepositoryHeadMutation{raw: rawLock, target: target}, published, err
	}
	next := plumbing.NewHashReference(snapshot.name, commit)
	if snapshot.target != nil {
		mutation, published, err := beginHeldReferenceReplacement(s.workDir, snapshot.target, next, s.syncReferenceDirectory)
		if err != nil {
			return finish(mutation, published, fmt.Errorf("%w: compare-and-set canonical HEAD target: %w", ErrRefConflict, err))
		}
		return finish(mutation, true, nil)
	}
	if _, err := repository.Storer.Reference(snapshot.name); !errors.Is(err, plumbing.ErrReferenceNotFound) {
		return finish(nil, false, errors.Join(err, fmt.Errorf("%w: initial canonical HEAD target appeared before commit", ErrRefConflict)))
	}
	if s.beforeUnbornHeadCreate != nil {
		if err := s.beforeUnbornHeadCreate(); err != nil {
			return finish(nil, false, err)
		}
	}
	mutation, published, err := beginHeldReferenceCreate(s.workDir, next, s.syncReferenceDirectory)
	return finish(mutation, published, err)
}

// installPathChanges atomically installs and removes canonical state files in
// one embedded-Git commit. Callers that need recoverable deletion must reach it
// through Store.Apply so the exact delete set is journaled before mutation.
func (s *Store) installPathChanges(staged map[string]string, deleted []string, message string) (hash plumbing.Hash, changed bool, resultErr error) {
	if err := s.requireWritable(); err != nil {
		return plumbing.ZeroHash, false, err
	}
	bound, err := s.bindStagedFiles(staged, nil, false)
	if err != nil {
		return plumbing.ZeroHash, false, err
	}
	return s.installPathChangesBound(bound, deleted, message)
}

func (s *Store) installPathChangesBound(bound *boundStageSet, deleted []string, message string) (hash plumbing.Hash, changed bool, resultErr error) {
	return s.installPathChangesBoundAt(bound, deleted, message, nil)
}

func (s *Store) installPathChangesBoundAt(bound *boundStageSet, deleted []string, message string, expectedHead *repositoryHeadSnapshot) (hash plumbing.Hash, changed bool, resultErr error) {
	if err := s.requireWritable(); err != nil {
		return plumbing.ZeroHash, false, err
	}
	if bound == nil {
		return plumbing.ZeroHash, false, errors.New("staged file bindings are unavailable")
	}
	defer func() { resultErr = errors.Join(resultErr, bound.close()) }()
	if len(bound.files) == 0 && len(deleted) == 0 {
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
	baselineHead, err := snapshotRepositoryHead(repository)
	if err != nil {
		return plumbing.ZeroHash, false, fmt.Errorf("snapshot canonical HEAD: %w", err)
	}
	if expectedHead != nil {
		if err := requireRepositoryHead(repository, *expectedHead); err != nil {
			return plumbing.ZeroHash, false, err
		}
		baselineHead = *expectedHead
	}
	originalIndex, err := repository.Storer.Index()
	if err != nil {
		return plumbing.ZeroHash, false, fmt.Errorf("snapshot state Git index: %w", err)
	}
	expectedIndex := make(map[string]canonicalWorktreeEntry, len(originalIndex.Entries)+len(bound.files))
	for _, entry := range originalIndex.Entries {
		if entry == nil || entry.Stage != 0 || entry.SkipWorktree || entry.IntentToAdd {
			return plumbing.ZeroHash, false, fmt.Errorf("%w: canonical Git index contains noncanonical merge, sparse, or intent-to-add state", ErrRefConflict)
		}
		if _, duplicate := expectedIndex[entry.Name]; duplicate {
			return plumbing.ZeroHash, false, fmt.Errorf("canonical Git index contains duplicate entry %s", entry.Name)
		}
		expectedIndex[entry.Name] = canonicalWorktreeEntry{hash: entry.Hash, mode: entry.Mode}
	}
	names := make([]string, 0, len(bound.files))
	for name := range bound.files {
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
		if _, replaced := bound.files[name]; replaced {
			return plumbing.ZeroHash, false, fmt.Errorf("canonical state path %q cannot be installed and deleted together", name)
		}
		if index != 0 && deleteNames[index-1] == name {
			return plumbing.ZeroHash, false, fmt.Errorf("duplicate canonical state deletion %q", name)
		}
	}
	if s.beforeBoundStageInstall != nil {
		if err := s.beforeBoundStageInstall(); err != nil {
			return plumbing.ZeroHash, false, err
		}
	}
	if err := requireRepositoryHead(repository, baselineHead); err != nil {
		return plumbing.ZeroHash, false, err
	}
	if err := requireCanonicalIndexVector(repository, expectedIndex); err != nil {
		return plumbing.ZeroHash, false, err
	}
	backups := make([]installBackup, 0, len(names)+len(deleteNames))
	rollback := true
	indexTouched := false
	var headMutation *heldRepositoryHeadMutation
	backupDir, err := os.MkdirTemp(s.stateDir, "install-backup-*")
	if err != nil {
		return plumbing.ZeroHash, false, fmt.Errorf("create state backup: %w", err)
	}
	defer func() {
		retainBackup := false
		if rollback {
			rollbackErr := rollbackInstallBackups(backups)
			if indexTouched {
				if err := repository.Storer.SetIndex(originalIndex); err != nil {
					rollbackErr = errors.Join(rollbackErr, fmt.Errorf("restore state Git index: %w", err))
				}
			}
			if rollbackErr != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("rollback canonical state failed; backup retained at %s: %w", backupDir, rollbackErr))
				retainBackup = true
			}
		}
		if !retainBackup {
			_ = os.RemoveAll(backupDir)
		}
		if headMutation != nil {
			if !rollback && s.beforeReferenceRelease != nil {
				resultErr = errors.Join(resultErr, s.beforeReferenceRelease())
			}
			resultErr = errors.Join(resultErr, headMutation.close())
		}
	}()
	for _, name := range names {
		source := bound.files[name]
		dst := filepath.Join(s.workDir, filepath.FromSlash(name))
		if err := s.verifyBoundStage(source); err != nil {
			return plumbing.ZeroHash, false, err
		}
		sharesDestination, err := boundStageSharesPath(source, dst)
		if err != nil {
			return plumbing.ZeroHash, false, err
		}
		if sharesDestination {
			return plumbing.ZeroHash, false, fmt.Errorf("%w: staged file %s is hard-linked to its canonical destination", ErrFileConflict, name)
		}
		equal, err := fileMatchesIdentity(dst, source.identity)
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
		if err := s.copyBoundStage(dst, source); err != nil {
			return plumbing.ZeroHash, false, err
		}
		expectedHash, err := s.boundStageGitHash(source)
		if err != nil {
			return plumbing.ZeroHash, false, err
		}
		indexTouched = true
		stagedHash, err := worktree.Add(name)
		if err != nil {
			return plumbing.ZeroHash, false, fmt.Errorf("stage %s: %w", name, err)
		}
		if stagedHash != expectedHash {
			return plumbing.ZeroHash, false, fmt.Errorf("%w: canonical state path %s changed while staging Git identity", ErrFileConflict, name)
		}
		expectedIndex[name] = canonicalWorktreeEntry{hash: expectedHash, mode: filemode.Regular}
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
		indexTouched = true
		if _, err := worktree.Remove(name); err != nil {
			return plumbing.ZeroHash, false, fmt.Errorf("stage canonical deletion %s: %w", name, err)
		}
		delete(expectedIndex, name)
	}
	for _, name := range names {
		source := bound.files[name]
		if err := s.verifyBoundStage(source); err != nil {
			return plumbing.ZeroHash, false, err
		}
		matches, err := fileMatchesIdentity(filepath.Join(s.workDir, filepath.FromSlash(name)), source.identity)
		if err != nil || !matches {
			return plumbing.ZeroHash, false, errors.Join(err, fmt.Errorf("%w: canonical state path %s changed after descriptor copy", ErrFileConflict, name))
		}
	}
	if err := bound.close(); err != nil {
		return plumbing.ZeroHash, false, err
	}
	if err := requireRepositoryHead(repository, baselineHead); err != nil {
		return plumbing.ZeroHash, false, err
	}
	if err := requireCanonicalIndexVector(repository, expectedIndex); err != nil {
		return plumbing.ZeroHash, false, err
	}
	if !changed {
		if baselineHead.hash.IsZero() {
			return plumbing.ZeroHash, false, errors.New("state repository has no baseline commit")
		}
		if err := s.AuditCanonicalWorktree(); err != nil {
			return plumbing.ZeroHash, false, err
		}
		rollback = false
		return baselineHead.hash, false, nil
	}
	status, err := worktree.Status()
	if err != nil {
		return plumbing.ZeroHash, false, err
	}
	if status.IsClean() {
		return plumbing.ZeroHash, false, errors.New("manifest files changed but Git index is clean")
	}
	for name, file := range status {
		if file.Worktree != git.Unmodified {
			return plumbing.ZeroHash, false, fmt.Errorf("%w: canonical state worktree path %s changed after staging", ErrFileConflict, filepath.ToSlash(name))
		}
	}
	if s.beforeBoundCommit != nil {
		if err := s.beforeBoundCommit(); err != nil {
			return plumbing.ZeroHash, false, err
		}
	}
	if err := requireRepositoryHead(repository, baselineHead); err != nil {
		return plumbing.ZeroHash, false, err
	}
	if err := requireCanonicalIndexVector(repository, expectedIndex); err != nil {
		return plumbing.ZeroHash, false, err
	}
	now := time.Now().UTC()
	hash, err = createCanonicalCommit(repository, expectedIndex, baselineHead.hash, message, object.Signature{
		Name: "sow", Email: "sow@localhost", When: now,
	})
	if err != nil {
		return plumbing.ZeroHash, false, fmt.Errorf("create canonical state commit: %w", err)
	}
	var advanced bool
	var advanceErr error
	headMutation, advanced, advanceErr = s.advanceRepositoryHead(repository, baselineHead, hash)
	if advanceErr != nil {
		if advanced && headMutation != nil {
			advanceErr = errors.Join(
				advanceErr,
				headMutation.rollback(s.syncReferenceDirectory),
				headMutation.restoreRawHead(s, repository, baselineHead),
			)
		}
		return plumbing.ZeroHash, false, advanceErr
	}
	var afterCommitErr error
	if s.afterBoundCommit != nil {
		afterCommitErr = s.afterBoundCommit(hash)
	}
	_, commitErr := repository.CommitObject(hash)
	postCommitErr := errors.Join(
		afterCommitErr,
		commitErr,
		requireRepositoryHeadCommit(repository, baselineHead, hash),
		requireCanonicalIndexVector(repository, expectedIndex),
		requireCommitMatchesIndexVector(repository, hash, baselineHead.hash, expectedIndex),
		s.AuditCanonicalWorktree(),
	)
	if postCommitErr != nil {
		rollbackHeadErr := headMutation.rollback(s.syncReferenceDirectory)
		rawHeadErr := headMutation.restoreRawHead(s, repository, baselineHead)
		return plumbing.ZeroHash, false, errors.Join(postCommitErr, rollbackHeadErr, rawHeadErr)
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
