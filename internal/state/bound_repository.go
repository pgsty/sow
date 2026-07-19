package state

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/go-git/go-billy/v5"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/storage/filesystem"
)

// ErrGitObjectIntegrity reports that canonical Git bytes do not match the
// object identity requested by a read-only admission session.
var ErrGitObjectIntegrity = errors.New("canonical Git object integrity failure")

// OpenBoundRepository opens an embedded .git directory that has already been
// retained with os.OpenRoot. Every go-git read is resolved through that root,
// so renaming the public repository pathname cannot redirect admission to a
// replacement tree. Ownership of dotGit transfers to the returned close
// function, which must outlive every repository operation.
func OpenBoundRepository(dotGit *os.Root) (_ *git.Repository, closeRepository func() error, resultErr error) {
	if dotGit == nil {
		return nil, nil, errors.New("bound canonical .git root is unavailable")
	}
	group := &boundRootFSGroup{roots: []*os.Root{dotGit}}
	rootFS := &boundRootFS{root: dotGit, group: group, label: ".git"}
	storage := filesystem.NewStorageWithOptions(rootFS, noObjectCache{}, filesystem.Options{
		LargeObjectThreshold: 1 << 20,
	})
	repository, err := git.Open(storage, nil)
	if err != nil {
		return nil, nil, errors.Join(err, storage.Close(), group.Close())
	}
	// go-git's filesystem reader treats the requested hash primarily as the
	// loose pathname or pack-index key. Bind the decoded bytes back to that
	// identity and retain the access set for the session's final recheck.
	repository.Storer = newVerifiedObjectStorer(storage, rootFS)
	var once sync.Once
	var closeErr error
	closeRepository = func() error {
		once.Do(func() {
			closeErr = errors.Join(storage.Close(), group.Close())
		})
		return closeErr
	}
	return repository, closeRepository, nil
}

type boundRootFSGroup struct {
	mu     sync.Mutex
	roots  []*os.Root
	closed bool
}

func (g *boundRootFSGroup) add(root *os.Root) error {
	if g == nil || root == nil {
		return errors.New("bound filesystem root is unavailable")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return fs.ErrClosed
	}
	g.roots = append(g.roots, root)
	return nil
}

func (g *boundRootFSGroup) Close() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	roots := append([]*os.Root(nil), g.roots...)
	g.roots = nil
	g.mu.Unlock()
	var result error
	for index := len(roots) - 1; index >= 0; index-- {
		result = errors.Join(result, roots[index].Close())
	}
	return result
}

// boundRootFS is deliberately read-only. Mutating billy methods exist only to
// satisfy the interface and always fail with fs.ErrPermission.
type boundRootFS struct {
	root  *os.Root
	group *boundRootFSGroup
	label string
}

func (f *boundRootFS) Capabilities() billy.Capability {
	return billy.ReadCapability | billy.SeekCapability
}

func (f *boundRootFS) Create(string) (billy.File, error) { return nil, fs.ErrPermission }

func (f *boundRootFS) Open(name string) (billy.File, error) {
	return f.OpenFile(name, os.O_RDONLY, 0)
}

func (f *boundRootFS) OpenFile(name string, flag int, _ os.FileMode) (result billy.File, resultErr error) {
	if flag&(os.O_WRONLY|os.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_EXCL|os.O_TRUNC) != 0 {
		return nil, fs.ErrPermission
	}
	clean, err := cleanBoundGitPath(name)
	if err != nil {
		return nil, err
	}
	parent, base, closeParent, err := f.openParent(clean)
	if err != nil {
		return nil, err
	}
	defer func() {
		closeErr := closeParent()
		if closeErr != nil {
			if result != nil {
				closeErr = errors.Join(closeErr, result.Close())
				result = nil
			}
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	before, err := parent.Lstat(base)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.Join(err, fmt.Errorf("unsafe bound Git path %q", clean))
	}
	opened, err := parent.OpenFile(base, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	openedInfo, statErr := opened.Stat()
	after, lstatErr := parent.Lstat(base)
	if statErr != nil || lstatErr != nil || !os.SameFile(before, openedInfo) || !os.SameFile(before, after) {
		return nil, errors.Join(statErr, lstatErr, opened.Close(), fmt.Errorf("bound Git path %q changed while opening", clean))
	}
	return &boundBillyFile{File: opened}, nil
}

func (f *boundRootFS) Stat(name string) (result os.FileInfo, resultErr error) {
	clean, err := cleanBoundGitPath(name)
	if err != nil {
		return nil, err
	}
	parent, base, closeParent, err := f.openParent(clean)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := closeParent(); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	info, err := parent.Lstat(base)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("unsafe bound Git path %q", clean)
	}
	return info, nil
}

func (f *boundRootFS) Rename(string, string) error { return fs.ErrPermission }
func (f *boundRootFS) Remove(string) error         { return fs.ErrPermission }

func (f *boundRootFS) Join(elements ...string) string {
	return path.Join(elements...)
}

func (f *boundRootFS) TempFile(string, string) (billy.File, error) {
	return nil, fs.ErrPermission
}

func (f *boundRootFS) ReadDir(name string) (result []os.FileInfo, resultErr error) {
	clean, err := cleanBoundGitPath(name)
	if err != nil {
		return nil, err
	}
	directory, closeDirectory, err := f.openDirectory(clean)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := closeDirectory(); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	entries, err := fs.ReadDir(directory.FS(), ".")
	if err != nil {
		return nil, err
	}
	result = make([]os.FileInfo, 0, len(entries))
	for _, entry := range entries {
		info, infoErr := entry.Info()
		if infoErr != nil {
			return nil, infoErr
		}
		result = append(result, info)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name() < result[j].Name() })
	return result, nil
}

func (f *boundRootFS) MkdirAll(string, os.FileMode) error { return fs.ErrPermission }

func (f *boundRootFS) Lstat(name string) (result os.FileInfo, resultErr error) {
	clean, err := cleanBoundGitPath(name)
	if err != nil {
		return nil, err
	}
	parent, base, closeParent, err := f.openParent(clean)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := closeParent(); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	return parent.Lstat(base)
}

func (f *boundRootFS) Symlink(string, string) error { return fs.ErrPermission }

func (f *boundRootFS) Readlink(name string) (result string, resultErr error) {
	clean, err := cleanBoundGitPath(name)
	if err != nil {
		return "", err
	}
	parent, base, closeParent, err := f.openParent(clean)
	if err != nil {
		return "", err
	}
	defer func() {
		if closeErr := closeParent(); closeErr != nil {
			resultErr = errors.Join(resultErr, closeErr)
		}
	}()
	return parent.Readlink(base)
}

func (f *boundRootFS) Chroot(name string) (billy.Filesystem, error) {
	clean, err := cleanBoundGitPath(name)
	if err != nil {
		return nil, err
	}
	child, closeChild, err := f.openDirectory(clean)
	if err != nil {
		return nil, err
	}
	if err := f.group.add(child); err != nil {
		return nil, errors.Join(err, closeChild())
	}
	return &boundRootFS{root: child, group: f.group, label: path.Join(f.label, clean)}, nil
}

// openParent resolves every directory component through a retained os.Root.
// os.Root confines traversal to its root, but it intentionally follows
// symlinks inside that root. Git metadata must reject those intermediate
// aliases as well: otherwise refs/objects could be redirected to a different
// subtree even though the final component itself is a regular file.
func (f *boundRootFS) openParent(clean string) (*os.Root, string, func() error, error) {
	parts := strings.Split(clean, "/")
	if clean == "." || len(parts) == 1 {
		return f.root, clean, func() error { return nil }, nil
	}
	current := f.root
	owned := false
	fail := func(err error) (*os.Root, string, func() error, error) {
		if owned {
			err = errors.Join(err, current.Close())
		}
		return nil, "", nil, err
	}
	for _, segment := range parts[:len(parts)-1] {
		before, err := current.Lstat(segment)
		if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
			return fail(errors.Join(err, fmt.Errorf("bound Git directory component %q is absent, symlinked, or not a directory", segment)))
		}
		next, err := current.OpenRoot(segment)
		if err != nil {
			return fail(err)
		}
		opened, statErr := next.Stat(".")
		after, lstatErr := current.Lstat(segment)
		if statErr != nil || lstatErr != nil || !os.SameFile(before, opened) || !os.SameFile(before, after) {
			return fail(errors.Join(statErr, lstatErr, next.Close(), fmt.Errorf("bound Git directory component %q changed while opening", segment)))
		}
		if owned {
			previous := current
			owned = false
			if err := previous.Close(); err != nil {
				return nil, "", nil, errors.Join(err, next.Close())
			}
		}
		current = next
		owned = true
	}
	closeParent := func() error {
		if !owned {
			return nil
		}
		owned = false
		return current.Close()
	}
	return current, parts[len(parts)-1], closeParent, nil
}

func (f *boundRootFS) openDirectory(clean string) (*os.Root, func() error, error) {
	parent, base, closeParent, err := f.openParent(clean)
	if err != nil {
		return nil, nil, err
	}
	before, err := parent.Lstat(base)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, nil, errors.Join(err, closeParent(), fmt.Errorf("bound Git directory %q is absent, symlinked, or not a directory", clean))
	}
	child, err := parent.OpenRoot(base)
	if err != nil {
		return nil, nil, errors.Join(err, closeParent())
	}
	opened, statErr := child.Stat(".")
	after, lstatErr := parent.Lstat(base)
	closeErr := closeParent()
	if statErr != nil || lstatErr != nil || closeErr != nil || !os.SameFile(before, opened) || !os.SameFile(before, after) {
		return nil, nil, errors.Join(statErr, lstatErr, closeErr, child.Close(), fmt.Errorf("bound Git directory %q changed while opening", clean))
	}
	return child, child.Close, nil
}

func (f *boundRootFS) Root() string { return f.label }

func cleanBoundGitPath(name string) (string, error) {
	if strings.ContainsAny(name, "\\\x00\r\n") || path.IsAbs(name) {
		return "", errors.New("unsafe bound Git path")
	}
	clean := path.Clean(name)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", errors.New("bound Git path escapes its root")
	}
	return clean, nil
}

type boundBillyFile struct{ *os.File }

func (f *boundBillyFile) Write([]byte) (int, error) { return 0, fs.ErrPermission }
func (f *boundBillyFile) Lock() error               { return nil }
func (f *boundBillyFile) Unlock() error             { return nil }
func (f *boundBillyFile) Truncate(int64) error      { return fs.ErrPermission }
