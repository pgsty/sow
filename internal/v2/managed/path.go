package managed

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/pgsty/sow/internal/v2/config"
	"golang.org/x/sys/unix"
)

var errRootedDirectoryChangedDuringEnumeration = errors.New("managed: rooted directory changed during enumeration")

type rootedRegularFile struct {
	file        *os.File
	directories []*os.File
	components  []string
	before      os.FileInfo
	stat        unix.Stat_t
	root        rootedDirectoryBinding
}

type rootedCreatedRegular struct {
	file   *os.File
	parent *rootedDirectoryChain
	name   string
	stat   unix.Stat_t
	done   bool
}

// rootedRegularIdentity is a metadata snapshot taken only after a file's
// content has been authenticated. It lets a later namespace step reject path
// replacement without re-hashing large immutable payloads.
type rootedRegularIdentity struct {
	device      uint64
	inode       uint64
	size        int64
	modUnixNano int64
	mode        os.FileMode
}

func newRootedRegularIdentity(info os.FileInfo, raw unix.Stat_t) rootedRegularIdentity {
	if info == nil {
		return rootedRegularIdentity{}
	}
	return rootedRegularIdentity{
		device: uint64(raw.Dev), inode: uint64(raw.Ino), size: raw.Size,
		modUnixNano: info.ModTime().UnixNano(), mode: info.Mode().Perm(),
	}
}

func (identity rootedRegularIdentity) valid(expectedSize int64) bool {
	return identity.inode != 0 && identity.size >= 0 && identity.size == expectedSize
}

func (identity rootedRegularIdentity) matchesInfo(info os.FileInfo, raw unix.Stat_t) bool {
	return info != nil && info.Mode().IsRegular() && info.Size() == identity.size && info.ModTime().UnixNano() == identity.modUnixNano && identity.matchesStat(raw)
}

func (identity rootedRegularIdentity) matchesStat(raw unix.Stat_t) bool {
	return uint32(raw.Mode)&unix.S_IFMT == unix.S_IFREG && uint64(raw.Dev) == identity.device && uint64(raw.Ino) == identity.inode && raw.Size == identity.size && os.FileMode(raw.Mode).Perm() == identity.mode
}

func (identity rootedRegularIdentity) sameInode(other rootedRegularIdentity) bool {
	return identity.device == other.device && identity.inode == other.inode
}

func snapshotRootedRegularIdentity(opened *rootedRegularFile) (rootedRegularIdentity, error) {
	if opened == nil || opened.file == nil {
		return rootedRegularIdentity{}, errors.New("managed: invalid rooted identity source")
	}
	info, infoErr := opened.file.Stat()
	var raw unix.Stat_t
	statErr := unix.Fstat(int(opened.file.Fd()), &raw)
	if infoErr != nil || statErr != nil || info == nil || !info.Mode().IsRegular() || uint32(raw.Mode)&unix.S_IFMT != unix.S_IFREG {
		return rootedRegularIdentity{}, errors.Join(errors.New("managed: rooted identity source is not regular"), infoErr, statErr)
	}
	return newRootedRegularIdentity(info, raw), nil
}

type rootedDirectoryBinding struct {
	path   string
	before os.FileInfo
	stat   unix.Stat_t
}

func openBoundRootDirectory(root string) (*os.File, rootedDirectoryBinding, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, rootedDirectoryBinding{}, fmt.Errorf("managed: resolve rooted owner: %w", err)
	}
	absolute = filepath.Clean(normalizePlatformPhysicalPath(absolute))
	active, hasActive := activeWorkspaceRootForPath(absolute)
	if hasActive {
		if err := verifyActiveWorkspaceRoot(absolute); err != nil {
			return nil, rootedDirectoryBinding{}, err
		}
	}
	before, err := os.Lstat(absolute)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, rootedDirectoryBinding{}, errors.New("managed: rooted owner is missing or unsafe")
	}
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, rootedDirectoryBinding{}, fmt.Errorf("managed: open rooted owner: %w", err)
	}
	components := strings.Split(strings.TrimPrefix(absolute, string(filepath.Separator)), string(filepath.Separator))
	if absolute == string(filepath.Separator) {
		components = nil
	}
	currentPath := string(filepath.Separator)
	for _, component := range components {
		if component == "" || component == "." || component == ".." || filepath.Base(component) != component {
			_ = unix.Close(fd)
			return nil, rootedDirectoryBinding{}, errors.New("managed: rooted owner has an unsafe component")
		}
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return nil, rootedDirectoryBinding{}, fmt.Errorf("managed: open rooted owner component: %w", openErr)
		}
		fd = next
		currentPath = filepath.Join(currentPath, component)
		if hasActive && currentPath == active.path {
			var openedRoot unix.Stat_t
			if err := unix.Fstat(fd, &openedRoot); err != nil || uint64(openedRoot.Dev) != active.device || uint64(openedRoot.Ino) != active.inode || uint32(openedRoot.Mode)&unix.S_IFMT != unix.S_IFDIR {
				_ = unix.Close(fd)
				return nil, rootedDirectoryBinding{}, fmt.Errorf("%w: active workspace root identity changed while opening", ErrIntegrity)
			}
		}
	}
	handle := os.NewFile(uintptr(fd), absolute)
	opened, openedErr := handle.Stat()
	afterOpen, pathErr := os.Lstat(absolute)
	var raw unix.Stat_t
	statErr := unix.Fstat(fd, &raw)
	activeErr := error(nil)
	if hasActive {
		activeErr = verifyActiveWorkspaceRoot(absolute)
	}
	if openedErr != nil || pathErr != nil || statErr != nil || activeErr != nil || !opened.IsDir() || !afterOpen.IsDir() ||
		afterOpen.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, opened) || !os.SameFile(opened, afterOpen) {
		_ = handle.Close()
		return nil, rootedDirectoryBinding{}, errors.Join(errors.New("managed: rooted owner changed while opening"), activeErr)
	}
	return handle, rootedDirectoryBinding{path: absolute, before: before, stat: raw}, nil
}

func verifyBoundRootDirectory(handle *os.File, binding rootedDirectoryBinding) error {
	if handle == nil || binding.path == "" || binding.before == nil {
		return errors.New("managed: invalid rooted owner binding")
	}
	opened, openedErr := handle.Stat()
	afterPath, pathErr := os.Lstat(binding.path)
	var raw unix.Stat_t
	statErr := unix.Fstat(int(handle.Fd()), &raw)
	if openedErr != nil || pathErr != nil || statErr != nil || !opened.IsDir() || !afterPath.IsDir() ||
		afterPath.Mode()&os.ModeSymlink != 0 || !os.SameFile(binding.before, opened) || !os.SameFile(opened, afterPath) ||
		raw.Dev != binding.stat.Dev || raw.Ino != binding.stat.Ino || uint32(raw.Mode)&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("managed: rooted owner pathname changed during access")
	}
	return nil
}

// openRootedRegular opens every path component relative to one held root
// descriptor with O_NOFOLLOW. It therefore cannot be redirected through a
// swapped parent symlink or escape the caller-owned tree.
func openRootedRegular(root, relative string) (*rootedRegularFile, error) {
	relative = filepath.Clean(filepath.FromSlash(relative))
	if relative == "." || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("managed: rooted file path escapes its owner")
	}
	components := strings.Split(relative, string(filepath.Separator))
	for _, component := range components {
		if component == "" || component == "." || component == ".." || filepath.Base(component) != component {
			return nil, errors.New("managed: rooted file path has an unsafe component")
		}
	}
	rootHandle, rootBinding, err := openBoundRootDirectory(root)
	if err != nil {
		return nil, fmt.Errorf("managed: open rooted file owner: %w", err)
	}
	directories := []*os.File{rootHandle}
	closeAll := func() {
		for index := len(directories) - 1; index >= 0; index-- {
			_ = directories[index].Close()
		}
	}
	for _, component := range components[:len(components)-1] {
		fd, err := unix.Openat(int(directories[len(directories)-1].Fd()), component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("managed: rooted file parent is missing or unsafe: %w", err)
		}
		directories = append(directories, os.NewFile(uintptr(fd), component))
	}
	fd, err := unix.Openat(int(directories[len(directories)-1].Fd()), components[len(components)-1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		closeAll()
		return nil, fmt.Errorf("managed: rooted regular file is missing or unsafe: %w", err)
	}
	file := os.NewFile(uintptr(fd), relative)
	info, infoErr := file.Stat()
	var raw unix.Stat_t
	statErr := unix.Fstat(fd, &raw)
	if infoErr != nil || statErr != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		closeAll()
		return nil, errors.New("managed: rooted entry is not a regular file")
	}
	return &rootedRegularFile{file: file, directories: directories, components: components, before: info, stat: raw, root: rootBinding}, nil
}

func (opened *rootedRegularFile) CloseVerified() error {
	if opened == nil || opened.file == nil || len(opened.directories) == 0 {
		return errors.New("managed: invalid rooted regular file")
	}
	after, afterErr := opened.file.Stat()
	var afterRaw unix.Stat_t
	fstatErr := unix.Fstat(int(opened.file.Fd()), &afterRaw)
	pathRaw, pathErr := rootedLstatAt(int(opened.directories[0].Fd()), opened.components)
	rootErr := verifyBoundRootDirectory(opened.directories[0], opened.root)
	closeErr := opened.file.Close()
	for index := len(opened.directories) - 1; index >= 0; index-- {
		closeErr = errors.Join(closeErr, opened.directories[index].Close())
	}
	if afterErr != nil || fstatErr != nil || pathErr != nil || !after.Mode().IsRegular() || !os.SameFile(opened.before, after) ||
		after.Size() != opened.before.Size() || !after.ModTime().Equal(opened.before.ModTime()) ||
		afterRaw.Dev != opened.stat.Dev || afterRaw.Ino != opened.stat.Ino || afterRaw.Size != opened.stat.Size ||
		pathRaw.Dev != opened.stat.Dev || pathRaw.Ino != opened.stat.Ino || pathRaw.Size != opened.stat.Size || uint32(pathRaw.Mode)&unix.S_IFMT != unix.S_IFREG || rootErr != nil {
		return errors.Join(errors.New("managed: rooted regular file changed during access"), rootErr, closeErr)
	}
	return closeErr
}

func openRootedPrivateRegular(root, relative string) (*rootedRegularFile, error) {
	opened, err := openRootedRegular(root, relative)
	if err != nil {
		return nil, err
	}
	if opened.stat.Nlink != 1 {
		return nil, errors.Join(errors.New("managed: private regular file is multiply linked"), opened.CloseVerified())
	}
	return opened, nil
}

// createRootedRegular creates one no-replace regular file beneath a held root.
// The returned file remains private to the caller until Commit verifies the
// directory entry and fsyncs both the file and its parent. Abort only unlinks
// the exact inode created by this call.
func createRootedRegular(root, relative string, mode os.FileMode) (*rootedCreatedRegular, error) {
	components, err := rootedPathComponents(relative, false)
	if err != nil {
		return nil, err
	}
	parentRelative := filepath.Join(components[:len(components)-1]...)
	if parentRelative == "" {
		parentRelative = "."
	}
	parent, err := openRootedDirectoryChain(root, parentRelative, false, 0)
	if err != nil {
		return nil, err
	}
	finishError := func(result error) (*rootedCreatedRegular, error) {
		return nil, errors.Join(result, parent.close(true))
	}
	name := components[len(components)-1]
	fd, err := unix.Openat(int(parent.directory().Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(mode.Perm()))
	if err != nil {
		return finishError(err)
	}
	file := os.NewFile(uintptr(fd), relative)
	var opened, entry unix.Stat_t
	statErr := unix.Fstat(fd, &opened)
	entryErr := unix.Fstatat(int(parent.directory().Fd()), name, &entry, unix.AT_SYMLINK_NOFOLLOW)
	if statErr != nil || entryErr != nil || uint32(opened.Mode)&unix.S_IFMT != unix.S_IFREG || opened.Dev != entry.Dev || opened.Ino != entry.Ino {
		closeErr := file.Close()
		if entryErr == nil && opened.Dev == entry.Dev && opened.Ino == entry.Ino && uint32(entry.Mode)&unix.S_IFMT == unix.S_IFREG {
			closeErr = errors.Join(closeErr, unlinkRootedEntryIfInode(parent, name, entry))
		}
		return finishError(errors.Join(errors.New("managed: created regular file changed while opening"), statErr, entryErr, closeErr))
	}
	created := &rootedCreatedRegular{file: file, parent: parent, name: name, stat: opened}
	if err := file.Chmod(mode); err != nil {
		return nil, errors.Join(err, created.Abort())
	}
	return created, nil
}

func (created *rootedCreatedRegular) Commit() error {
	if created == nil || created.done || created.file == nil || created.parent == nil {
		return errors.New("managed: invalid rooted created regular file")
	}
	var opened, entry unix.Stat_t
	result := errors.Join(created.file.Sync(), unix.Fstat(int(created.file.Fd()), &opened), unix.Fstatat(int(created.parent.directory().Fd()), created.name, &entry, unix.AT_SYMLINK_NOFOLLOW), created.parent.verify())
	if opened.Dev != created.stat.Dev || opened.Ino != created.stat.Ino || entry.Dev != created.stat.Dev || entry.Ino != created.stat.Ino || opened.Size != entry.Size || uint32(opened.Mode)&unix.S_IFMT != unix.S_IFREG || uint32(entry.Mode)&unix.S_IFMT != unix.S_IFREG {
		result = errors.Join(result, errors.New("managed: created regular file changed before commit"))
	}
	if result != nil {
		return errors.Join(result, created.Abort())
	}
	result = errors.Join(created.parent.directory().Sync(), created.file.Close(), created.parent.close(true))
	created.done, created.file, created.parent = true, nil, nil
	return result
}

func (created *rootedCreatedRegular) Abort() error {
	if created == nil || created.done {
		return nil
	}
	created.done = true
	var result error
	if created.parent != nil {
		var entry unix.Stat_t
		entryErr := unix.Fstatat(int(created.parent.directory().Fd()), created.name, &entry, unix.AT_SYMLINK_NOFOLLOW)
		if entryErr == nil && entry.Dev == created.stat.Dev && entry.Ino == created.stat.Ino && uint32(entry.Mode)&unix.S_IFMT == unix.S_IFREG {
			result = unlinkRootedEntryIfInode(created.parent, created.name, entry)
		} else if !errors.Is(entryErr, unix.ENOENT) {
			result = errors.Join(errors.New("managed: created regular cleanup target changed"), entryErr)
		}
	}
	if created.file != nil {
		result = errors.Join(result, created.file.Close())
	}
	if created.parent != nil {
		result = errors.Join(result, created.parent.close(true))
	}
	created.file, created.parent = nil, nil
	return result
}

func rootedLstatAt(rootFD int, components []string) (unix.Stat_t, error) {
	current, err := unix.Dup(rootFD)
	if err != nil {
		return unix.Stat_t{}, err
	}
	for _, component := range components[:len(components)-1] {
		next, err := unix.Openat(current, component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		if err != nil {
			_ = unix.Close(current)
			return unix.Stat_t{}, err
		}
		_ = unix.Close(current)
		current = next
	}
	defer unix.Close(current)
	var result unix.Stat_t
	err = unix.Fstatat(current, components[len(components)-1], &result, unix.AT_SYMLINK_NOFOLLOW)
	return result, err
}

type rootedDirectoryChain struct {
	binding     rootedDirectoryBinding
	directories []*os.File
	components  []string
}

type rootedDirectoryEntry struct {
	Name string
	Stat unix.Stat_t
}

func listRootedDirectory(root string) ([]rootedDirectoryEntry, error) {
	handle, binding, err := openBoundRootDirectory(root)
	if err != nil {
		return nil, err
	}
	before, beforeErr := handle.Stat()
	if beforeErr != nil || !before.IsDir() {
		return nil, errors.Join(errors.New("managed: rooted directory is unsafe before enumeration"), beforeErr, handle.Close())
	}
	names, readErr := handle.Readdirnames(-1)
	sort.Strings(names)
	entries := make([]rootedDirectoryEntry, 0, len(names))
	for _, name := range names {
		if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, `/\`) {
			readErr = errors.Join(readErr, errors.New("managed: rooted directory contains an unsafe entry name"))
			break
		}
		var raw unix.Stat_t
		if err := unix.Fstatat(int(handle.Fd()), name, &raw, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			readErr = errors.Join(readErr, err)
			break
		}
		entries = append(entries, rootedDirectoryEntry{Name: name, Stat: raw})
	}
	after, afterErr := handle.Stat()
	if afterErr != nil || !after.IsDir() || !os.SameFile(before, after) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		readErr = errors.Join(readErr, errRootedDirectoryChangedDuringEnumeration, afterErr)
	}
	return entries, errors.Join(readErr, verifyBoundRootDirectory(handle, binding), handle.Close())
}

func rootedPathComponents(relative string, allowRoot bool) ([]string, error) {
	clean := filepath.Clean(filepath.FromSlash(relative))
	if clean == "." && allowRoot {
		return nil, nil
	}
	if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return nil, errors.New("managed: rooted path escapes its owner")
	}
	components := strings.Split(clean, string(filepath.Separator))
	for _, component := range components {
		if component == "" || component == "." || component == ".." || filepath.Base(component) != component || strings.ContainsAny(component, `/\`) {
			return nil, errors.New("managed: rooted path has an unsafe component")
		}
	}
	return components, nil
}

func relativeToRoot(root, target string) (string, error) {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	if err != nil {
		return "", err
	}
	if _, err := rootedPathComponents(relative, false); err != nil {
		return "", err
	}
	return relative, nil
}

func openRootedDirectoryChain(root, relative string, create bool, mode os.FileMode) (*rootedDirectoryChain, error) {
	rootHandle, binding, err := openBoundRootDirectory(root)
	if err != nil {
		return nil, err
	}
	return openRootedDirectoryChainFromHandle(rootHandle, binding, relative, create, mode)
}

func openRootedDirectoryChainFromHandle(rootHandle *os.File, binding rootedDirectoryBinding, relative string, create bool, mode os.FileMode) (*rootedDirectoryChain, error) {
	chain, _, err := openRootedDirectoryChainFromHandleMode(rootHandle, binding, relative, create, mode, true)
	return chain, err
}

// openRootedDirectoryChainFromHandleDeferredCreateSync records every directory
// whose inode or child entries must participate in a later group barrier. New
// namespace state is safe before that barrier because its journaled source
// names remain durable and untouched.
func openRootedDirectoryChainFromHandleDeferredCreateSync(rootHandle *os.File, binding rootedDirectoryBinding, relative string, mode os.FileMode) (*rootedDirectoryChain, []string, error) {
	return openRootedDirectoryChainFromHandleMode(rootHandle, binding, relative, true, mode, false)
}

func openRootedDirectoryChainFromHandleMode(rootHandle *os.File, binding rootedDirectoryBinding, relative string, create bool, mode os.FileMode, syncCreated bool) (*rootedDirectoryChain, []string, error) {
	components, err := rootedPathComponents(relative, true)
	if err != nil {
		_ = rootHandle.Close()
		return nil, nil, err
	}
	chain := &rootedDirectoryChain{binding: binding, directories: []*os.File{rootHandle}, components: components}
	barriers := []string{}
	closeOnError := func(result error) (*rootedDirectoryChain, []string, error) {
		return nil, barriers, errors.Join(result, chain.close(false))
	}
	for index, component := range components {
		parent := chain.directories[len(chain.directories)-1]
		fd, openErr := unix.Openat(int(parent.Fd()), component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		created := false
		if errors.Is(openErr, unix.ENOENT) && create {
			mkdirErr := unix.Mkdirat(int(parent.Fd()), component, uint32(mode.Perm()))
			if mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				return closeOnError(fmt.Errorf("managed: create rooted directory: %w", mkdirErr))
			}
			created = mkdirErr == nil
			fd, openErr = unix.Openat(int(parent.Fd()), component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		}
		if openErr != nil {
			return closeOnError(fmt.Errorf("managed: open rooted directory: %w", openErr))
		}
		child := os.NewFile(uintptr(fd), filepath.Join(components[:index+1]...))
		var openedRaw, pathRaw unix.Stat_t
		fstatErr := unix.Fstat(fd, &openedRaw)
		pathErr := unix.Fstatat(int(parent.Fd()), component, &pathRaw, unix.AT_SYMLINK_NOFOLLOW)
		if fstatErr != nil || pathErr != nil || openedRaw.Dev != pathRaw.Dev || openedRaw.Ino != pathRaw.Ino || uint32(openedRaw.Mode)&unix.S_IFMT != unix.S_IFDIR {
			_ = child.Close()
			return closeOnError(errors.New("managed: rooted directory changed while opening"))
		}
		if create && !syncCreated {
			// A directory that already exists may have been created by an earlier
			// attempt that stopped before its barrier. Re-sync the complete chain,
			// not only entries created in this process, so replay can safely remove
			// the last durable pending name after the group barrier.
			childRelative := filepath.Join(components[:index+1]...)
			parentRelative := filepath.Join(components[:index]...)
			if parentRelative == "" {
				parentRelative = "."
			}
			barriers = append(barriers, childRelative, parentRelative)
		}
		if create {
			var modeErr error
			if created || os.FileMode(openedRaw.Mode).Perm() != mode.Perm() {
				modeErr = child.Chmod(mode)
			}
			// The ordinary helper preserves its historical conservative contract:
			// every opened ancestor participates in the durability barrier. Only the
			// explicitly deferred group-commit variant postpones these syncs.
			if syncCreated {
				modeErr = errors.Join(modeErr, child.Sync())
			}
			if created {
				if syncCreated {
					modeErr = errors.Join(modeErr, parent.Sync())
				}
			}
			if modeErr != nil {
				_ = child.Close()
				return closeOnError(modeErr)
			}
		}
		chain.directories = append(chain.directories, child)
	}
	return chain, barriers, nil
}

func duplicateRootedDirectoryChainRoot(chain *rootedDirectoryChain) (*os.File, rootedDirectoryBinding, error) {
	if chain == nil || len(chain.directories) == 0 {
		return nil, rootedDirectoryBinding{}, errors.New("managed: invalid rooted directory chain")
	}
	if err := chain.verify(); err != nil {
		return nil, rootedDirectoryBinding{}, err
	}
	fd, err := unix.Dup(int(chain.directories[0].Fd()))
	if err != nil {
		return nil, rootedDirectoryBinding{}, err
	}
	unix.CloseOnExec(fd)
	return os.NewFile(uintptr(fd), chain.binding.path), chain.binding, nil
}

func (chain *rootedDirectoryChain) directory() *os.File {
	if chain == nil || len(chain.directories) == 0 {
		return nil
	}
	return chain.directories[len(chain.directories)-1]
}

func (chain *rootedDirectoryChain) close(verify bool) error {
	if chain == nil || len(chain.directories) == 0 {
		return errors.New("managed: invalid rooted directory chain")
	}
	var verifyErr error
	if verify {
		verifyErr = chain.verify()
	}
	closeErr := error(nil)
	for index := len(chain.directories) - 1; index >= 0; index-- {
		closeErr = errors.Join(closeErr, chain.directories[index].Close())
	}
	chain.directories = nil
	return errors.Join(verifyErr, closeErr)
}

func (chain *rootedDirectoryChain) verify() error {
	if chain == nil || len(chain.directories) == 0 {
		return errors.New("managed: invalid rooted directory chain")
	}
	verifyErr := verifyBoundRootDirectory(chain.directories[0], chain.binding)
	for index := 1; index < len(chain.directories); index++ {
		var openedRaw unix.Stat_t
		pathRaw, pathErr := rootedLstatAt(int(chain.directories[0].Fd()), chain.components[:index])
		fstatErr := unix.Fstat(int(chain.directories[index].Fd()), &openedRaw)
		if pathErr != nil || fstatErr != nil || openedRaw.Dev != pathRaw.Dev || openedRaw.Ino != pathRaw.Ino || uint32(openedRaw.Mode)&unix.S_IFMT != unix.S_IFDIR {
			verifyErr = errors.Join(verifyErr, errors.New("managed: rooted directory pathname changed during access"), pathErr, fstatErr)
		}
	}
	return verifyErr
}

// renameRootedRegular moves one immutable regular file between two paths
// beneath the same bound owner. linkat supplies atomic no-replace creation;
// only after the target entry is proven to be the held, digest-bound inode is
// the source link removed. A crash between those two actions leaves two exact
// links, which the operation journal can safely collapse on replay.
func renameRootedRegular(ctx context.Context, root, sourceRelative, targetRelative string, expectedSize int64, expectedSHA string, fileMode, directoryMode os.FileMode) error {
	if ctx == nil {
		return errors.New("managed: nil rooted rename context")
	}
	sourceComponents, err := rootedPathComponents(sourceRelative, false)
	if err != nil {
		return err
	}
	targetComponents, err := rootedPathComponents(targetRelative, false)
	if err != nil {
		return err
	}
	sourceParent, err := openRootedDirectoryChain(root, filepath.Join(sourceComponents[:len(sourceComponents)-1]...), false, directoryMode)
	if err != nil {
		return err
	}
	targetRootHandle, targetRootBinding, err := duplicateRootedDirectoryChainRoot(sourceParent)
	if err != nil {
		return errors.Join(err, sourceParent.close(true))
	}
	targetParent, err := openRootedDirectoryChainFromHandle(targetRootHandle, targetRootBinding, filepath.Join(targetComponents[:len(targetComponents)-1]...), true, directoryMode)
	if err != nil {
		return errors.Join(err, sourceParent.close(true))
	}
	finish := func(result error) error {
		return errors.Join(result, targetParent.close(true), sourceParent.close(true))
	}
	if err := errors.Join(sourceParent.verify(), targetParent.verify()); err != nil {
		return finish(err)
	}
	sourceName := sourceComponents[len(sourceComponents)-1]
	targetName := targetComponents[len(targetComponents)-1]
	fd, err := unix.Openat(int(sourceParent.directory().Fd()), sourceName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return finish(err)
	}
	file := os.NewFile(uintptr(fd), sourceName)
	closeFile := func(result error) error { return finish(errors.Join(result, file.Close())) }
	var before unix.Stat_t
	statErr := unix.Fstat(fd, &before)
	if statErr != nil || uint32(before.Mode)&unix.S_IFMT != unix.S_IFREG || before.Size != expectedSize {
		return closeFile(errors.Join(errors.New("managed: rooted rename source is not the expected regular file"), statErr))
	}
	var sourceEntry unix.Stat_t
	entryErr := unix.Fstatat(int(sourceParent.directory().Fd()), sourceName, &sourceEntry, unix.AT_SYMLINK_NOFOLLOW)
	if entryErr != nil || sourceEntry.Dev != before.Dev || sourceEntry.Ino != before.Ino || sourceEntry.Size != before.Size || uint32(sourceEntry.Mode)&unix.S_IFMT != unix.S_IFREG {
		return closeFile(errors.Join(errors.New("managed: rooted rename source entry changed while opening"), entryErr))
	}
	digest, err := hashRegularDescriptor(ctx, file)
	if err != nil || digest != expectedSHA {
		return closeFile(errors.Join(errors.New("managed: rooted rename source digest differs"), err))
	}
	if err := errors.Join(sourceParent.verify(), targetParent.verify()); err != nil {
		return closeFile(err)
	}
	linkErr := unix.Linkat(int(sourceParent.directory().Fd()), sourceName, int(targetParent.directory().Fd()), targetName, 0)
	if linkErr != nil && !errors.Is(linkErr, unix.EEXIST) {
		return closeFile(linkErr)
	}
	var targetRaw unix.Stat_t
	targetErr := unix.Fstatat(int(targetParent.directory().Fd()), targetName, &targetRaw, unix.AT_SYMLINK_NOFOLLOW)
	if targetErr != nil || targetRaw.Dev != before.Dev || targetRaw.Ino != before.Ino || targetRaw.Size != before.Size || uint32(targetRaw.Mode)&unix.S_IFMT != unix.S_IFREG {
		var cleanupErr error
		if linkErr == nil && targetErr == nil {
			cleanupErr = unlinkRootedEntryIfInode(targetParent, targetName, targetRaw)
		}
		return closeFile(errors.Join(errors.New("managed: rooted rename target is not the expected inode"), linkErr, targetErr, cleanupErr))
	}
	if err := errors.Join(file.Chmod(fileMode), file.Sync()); err != nil {
		return closeFile(err)
	}
	digest, err = hashRegularDescriptor(ctx, file)
	if err != nil || digest != expectedSHA {
		return closeFile(errors.Join(errors.New("managed: rooted rename source changed during publication"), err))
	}
	if err := errors.Join(sourceParent.verify(), targetParent.verify()); err != nil {
		return closeFile(err)
	}
	var sourceBeforeUnlink unix.Stat_t
	sourceErr := unix.Fstatat(int(sourceParent.directory().Fd()), sourceName, &sourceBeforeUnlink, unix.AT_SYMLINK_NOFOLLOW)
	if sourceErr != nil || sourceBeforeUnlink.Dev != before.Dev || sourceBeforeUnlink.Ino != before.Ino || sourceBeforeUnlink.Size != before.Size || uint32(sourceBeforeUnlink.Mode)&unix.S_IFMT != unix.S_IFREG {
		return closeFile(errors.Join(errors.New("managed: rooted rename source changed before unlink"), sourceErr))
	}
	// The one file Sync above makes both content and final mode durable. Persist
	// the target link before removing the source link, then persist the source
	// removal. This ordering cannot durably lose both names.
	if err := targetParent.directory().Sync(); err != nil {
		return closeFile(err)
	}
	if err := unix.Unlinkat(int(sourceParent.directory().Fd()), sourceName, 0); err != nil {
		return closeFile(err)
	}
	var sourceAfter unix.Stat_t
	sourceErr = unix.Fstatat(int(sourceParent.directory().Fd()), sourceName, &sourceAfter, unix.AT_SYMLINK_NOFOLLOW)
	targetErr = unix.Fstatat(int(targetParent.directory().Fd()), targetName, &targetRaw, unix.AT_SYMLINK_NOFOLLOW)
	if !errors.Is(sourceErr, unix.ENOENT) || targetErr != nil || targetRaw.Dev != before.Dev || targetRaw.Ino != before.Ino {
		return closeFile(errors.Join(errors.New("managed: rooted rename final entries are inconsistent"), sourceErr, targetErr))
	}
	return closeFile(sourceParent.directory().Sync())
}

func hashRegularDescriptor(ctx context.Context, file *os.File) (string, error) {
	if file == nil {
		return "", errors.New("managed: nil regular descriptor")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, &managedContextReader{ctx: ctx, reader: file}); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// linkRootedRegularDeferredTargetSync creates and authenticates one hardlink
// without persisting the target directory entry. It is restricted to a
// journaled group-commit caller that keeps the already-durable source name
// until syncRootedDirectory has persisted every target parent in the batch.
// The returned relative directories are the barriers the caller must sync.
func linkRootedRegularDeferredTargetSync(ctx context.Context, root, sourceRelative, targetRelative string, expectedSize int64, expectedSHA string, fileMode, directoryMode os.FileMode) ([]string, rootedRegularIdentity, error) {
	if ctx == nil || expectedSize < 0 || !lowercaseSHA256.MatchString(expectedSHA) {
		return nil, rootedRegularIdentity{}, errors.New("managed: invalid deferred rooted link identity")
	}
	sourceComponents, err := rootedPathComponents(sourceRelative, false)
	if err != nil {
		return nil, rootedRegularIdentity{}, err
	}
	targetComponents, err := rootedPathComponents(targetRelative, false)
	if err != nil {
		return nil, rootedRegularIdentity{}, err
	}
	targetParentRelative := filepath.Join(targetComponents[:len(targetComponents)-1]...)
	if targetParentRelative == "" {
		targetParentRelative = "."
	}
	sourceParent, err := openRootedDirectoryChain(root, filepath.Join(sourceComponents[:len(sourceComponents)-1]...), false, directoryMode)
	if err != nil {
		return nil, rootedRegularIdentity{}, err
	}
	targetRootHandle, targetRootBinding, err := duplicateRootedDirectoryChainRoot(sourceParent)
	if err != nil {
		return nil, rootedRegularIdentity{}, errors.Join(err, sourceParent.close(true))
	}
	targetParent, barriers, err := openRootedDirectoryChainFromHandleDeferredCreateSync(targetRootHandle, targetRootBinding, targetParentRelative, directoryMode)
	if err != nil {
		return barriers, rootedRegularIdentity{}, errors.Join(err, sourceParent.close(true))
	}
	barriers = append(barriers, targetParentRelative)
	identity := rootedRegularIdentity{}
	finish := func(result error) ([]string, rootedRegularIdentity, error) {
		return barriers, identity, errors.Join(result, targetParent.close(true), sourceParent.close(true))
	}
	if err := errors.Join(sourceParent.verify(), targetParent.verify()); err != nil {
		return finish(err)
	}
	sourceName := sourceComponents[len(sourceComponents)-1]
	targetName := targetComponents[len(targetComponents)-1]
	fd, err := unix.Openat(int(sourceParent.directory().Fd()), sourceName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return finish(err)
	}
	file := os.NewFile(uintptr(fd), sourceName)
	closeFile := func(result error) ([]string, rootedRegularIdentity, error) {
		return finish(errors.Join(result, file.Close()))
	}
	beforeInfo, infoErr := file.Stat()
	var before, sourceEntry unix.Stat_t
	statErr := unix.Fstat(fd, &before)
	entryErr := unix.Fstatat(int(sourceParent.directory().Fd()), sourceName, &sourceEntry, unix.AT_SYMLINK_NOFOLLOW)
	if infoErr != nil || statErr != nil || entryErr != nil || !beforeInfo.Mode().IsRegular() || before.Size != expectedSize ||
		sourceEntry.Dev != before.Dev || sourceEntry.Ino != before.Ino || sourceEntry.Size != before.Size || uint32(sourceEntry.Mode)&unix.S_IFMT != unix.S_IFREG {
		return closeFile(errors.Join(errors.New("managed: deferred rooted link source is not the expected regular file"), infoErr, statErr, entryErr))
	}
	if err := errors.Join(sourceParent.verify(), targetParent.verify()); err != nil {
		return closeFile(err)
	}
	digest, hashErr := hashRegularDescriptor(ctx, file)
	if hashErr != nil || digest != expectedSHA {
		return closeFile(errors.Join(errors.New("managed: deferred rooted link source digest differs"), hashErr))
	}
	var authenticated, authenticatedEntry unix.Stat_t
	authenticatedInfo, authenticatedInfoErr := file.Stat()
	authenticatedErr := unix.Fstat(fd, &authenticated)
	authenticatedEntryErr := unix.Fstatat(int(sourceParent.directory().Fd()), sourceName, &authenticatedEntry, unix.AT_SYMLINK_NOFOLLOW)
	if authenticatedInfoErr != nil || authenticatedErr != nil || authenticatedEntryErr != nil || !authenticatedInfo.Mode().IsRegular() ||
		!authenticatedInfo.ModTime().Equal(beforeInfo.ModTime()) || authenticated.Dev != before.Dev || authenticated.Ino != before.Ino || authenticated.Size != before.Size ||
		authenticatedEntry.Dev != before.Dev || authenticatedEntry.Ino != before.Ino || authenticatedEntry.Size != before.Size || uint32(authenticatedEntry.Mode)&unix.S_IFMT != unix.S_IFREG {
		return closeFile(errors.Join(errors.New("managed: deferred rooted link source changed while authenticating"), authenticatedInfoErr, authenticatedErr, authenticatedEntryErr))
	}
	modeChanged := authenticatedInfo.Mode().Perm() != fileMode.Perm()
	if modeChanged {
		if err := file.Chmod(fileMode); err != nil {
			return closeFile(err)
		}
	}
	if modeChanged {
		if err := file.Sync(); err != nil {
			return closeFile(err)
		}
	}
	var publishSource, publishEntry unix.Stat_t
	publishInfo, publishInfoErr := file.Stat()
	publishSourceErr := unix.Fstat(fd, &publishSource)
	publishEntryErr := unix.Fstatat(int(sourceParent.directory().Fd()), sourceName, &publishEntry, unix.AT_SYMLINK_NOFOLLOW)
	if publishInfoErr != nil || publishSourceErr != nil || publishEntryErr != nil || !publishInfo.Mode().IsRegular() || publishInfo.Mode().Perm() != fileMode.Perm() ||
		!publishInfo.ModTime().Equal(beforeInfo.ModTime()) || publishSource.Dev != before.Dev || publishSource.Ino != before.Ino || publishSource.Size != before.Size ||
		publishEntry.Dev != before.Dev || publishEntry.Ino != before.Ino || publishEntry.Size != before.Size || uint32(publishEntry.Mode)&unix.S_IFMT != unix.S_IFREG || os.FileMode(publishEntry.Mode).Perm() != fileMode.Perm() {
		return closeFile(errors.Join(errors.New("managed: deferred rooted link source changed before publication"), publishInfoErr, publishSourceErr, publishEntryErr))
	}
	if err := errors.Join(sourceParent.verify(), targetParent.verify()); err != nil {
		return closeFile(err)
	}
	linkErr := unix.Linkat(int(sourceParent.directory().Fd()), sourceName, int(targetParent.directory().Fd()), targetName, 0)
	if linkErr != nil && !errors.Is(linkErr, unix.EEXIST) {
		return closeFile(linkErr)
	}
	var targetRaw unix.Stat_t
	targetErr := unix.Fstatat(int(targetParent.directory().Fd()), targetName, &targetRaw, unix.AT_SYMLINK_NOFOLLOW)
	if targetErr != nil || targetRaw.Dev != before.Dev || targetRaw.Ino != before.Ino || targetRaw.Size != before.Size || uint32(targetRaw.Mode)&unix.S_IFMT != unix.S_IFREG {
		var cleanupErr error
		if linkErr == nil && targetErr == nil {
			cleanupErr = unlinkRootedEntryIfInode(targetParent, targetName, targetRaw)
		}
		return closeFile(errors.Join(errors.New("managed: deferred rooted link target is not the source inode"), linkErr, targetErr, cleanupErr))
	}
	afterInfo, afterInfoErr := file.Stat()
	var after, sourceAfter, targetAfter unix.Stat_t
	afterErr := unix.Fstat(fd, &after)
	sourceErr := unix.Fstatat(int(sourceParent.directory().Fd()), sourceName, &sourceAfter, unix.AT_SYMLINK_NOFOLLOW)
	targetErr = unix.Fstatat(int(targetParent.directory().Fd()), targetName, &targetAfter, unix.AT_SYMLINK_NOFOLLOW)
	if afterInfoErr != nil || afterErr != nil || sourceErr != nil || targetErr != nil || !afterInfo.Mode().IsRegular() ||
		!afterInfo.ModTime().Equal(beforeInfo.ModTime()) || after.Dev != before.Dev || after.Ino != before.Ino || after.Size != before.Size ||
		sourceAfter.Dev != before.Dev || sourceAfter.Ino != before.Ino || sourceAfter.Size != before.Size ||
		targetAfter.Dev != before.Dev || targetAfter.Ino != before.Ino || targetAfter.Size != before.Size ||
		uint32(sourceAfter.Mode)&unix.S_IFMT != unix.S_IFREG || uint32(targetAfter.Mode)&unix.S_IFMT != unix.S_IFREG ||
		os.FileMode(sourceAfter.Mode).Perm() != fileMode.Perm() || os.FileMode(targetAfter.Mode).Perm() != fileMode.Perm() {
		var cleanupErr error
		if linkErr == nil && targetErr == nil {
			cleanupErr = unlinkRootedEntryIfInode(targetParent, targetName, targetAfter)
		}
		return closeFile(errors.Join(errors.New("managed: deferred rooted link changed during publication"), afterInfoErr, afterErr, sourceErr, targetErr, cleanupErr))
	}
	// Pending content and its final mode were fsync'd before the journal reached
	// promotion. Linkat changes namespace metadata only; the target-directory
	// barrier commits that hardlink while the durable pending name is retained.
	// Avoiding another per-object inode fsync is the central local single-writer
	// performance tradeoff of this group commit.
	identity = newRootedRegularIdentity(afterInfo, after)
	return closeFile(errors.Join(sourceParent.verify(), targetParent.verify()))
}

// linkRootedRegular creates one no-replace hardlink between two descriptor-
// rooted trees. The source directory entry, held inode, size, and digest are
// bound before publication; the target must resolve to that exact inode.
func linkRootedRegular(ctx context.Context, sourceRoot, sourceRelative, targetRoot, targetRelative string, expectedSize int64, expectedSHA string, directoryMode os.FileMode) error {
	if ctx == nil {
		return errors.New("managed: nil rooted link context")
	}
	sourceComponents, err := rootedPathComponents(sourceRelative, false)
	if err != nil {
		return err
	}
	targetComponents, err := rootedPathComponents(targetRelative, false)
	if err != nil {
		return err
	}
	sourceParent, err := openRootedDirectoryChain(sourceRoot, filepath.Join(sourceComponents[:len(sourceComponents)-1]...), false, directoryMode)
	if err != nil {
		return err
	}
	var targetParent *rootedDirectoryChain
	sourceAbsolute, sourceAbsErr := filepath.Abs(sourceRoot)
	targetAbsolute, targetAbsErr := filepath.Abs(targetRoot)
	if sourceAbsErr == nil && targetAbsErr == nil && filepath.Clean(sourceAbsolute) == filepath.Clean(targetAbsolute) {
		targetRootHandle, targetRootBinding, duplicateErr := duplicateRootedDirectoryChainRoot(sourceParent)
		if duplicateErr != nil {
			return errors.Join(duplicateErr, sourceParent.close(true))
		}
		targetParent, err = openRootedDirectoryChainFromHandle(targetRootHandle, targetRootBinding, filepath.Join(targetComponents[:len(targetComponents)-1]...), true, directoryMode)
	} else {
		targetParent, err = openRootedDirectoryChain(targetRoot, filepath.Join(targetComponents[:len(targetComponents)-1]...), true, directoryMode)
	}
	if err != nil {
		return errors.Join(err, sourceParent.close(true))
	}
	finish := func(result error) error {
		return errors.Join(result, targetParent.close(true), sourceParent.close(true))
	}
	if err := errors.Join(sourceParent.verify(), targetParent.verify()); err != nil {
		return finish(err)
	}
	sourceName := sourceComponents[len(sourceComponents)-1]
	targetName := targetComponents[len(targetComponents)-1]
	fd, err := unix.Openat(int(sourceParent.directory().Fd()), sourceName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return finish(err)
	}
	file := os.NewFile(uintptr(fd), sourceName)
	closeFile := func(result error) error { return finish(errors.Join(result, file.Close())) }
	var sourceRaw, sourceEntry unix.Stat_t
	statErr := unix.Fstat(fd, &sourceRaw)
	entryErr := unix.Fstatat(int(sourceParent.directory().Fd()), sourceName, &sourceEntry, unix.AT_SYMLINK_NOFOLLOW)
	if statErr != nil || entryErr != nil || uint32(sourceRaw.Mode)&unix.S_IFMT != unix.S_IFREG ||
		sourceRaw.Size != expectedSize || sourceEntry.Dev != sourceRaw.Dev || sourceEntry.Ino != sourceRaw.Ino || sourceEntry.Size != sourceRaw.Size || uint32(sourceEntry.Mode)&unix.S_IFMT != unix.S_IFREG {
		return closeFile(errors.Join(errors.New("managed: rooted link source is not the expected regular file"), statErr, entryErr))
	}
	digest, hashErr := hashRegularDescriptor(ctx, file)
	if hashErr != nil || digest != expectedSHA {
		return closeFile(errors.Join(errors.New("managed: rooted link source digest differs"), hashErr))
	}
	if err := errors.Join(file.Sync(), sourceParent.verify(), targetParent.verify()); err != nil {
		return closeFile(err)
	}
	linkErr := unix.Linkat(int(sourceParent.directory().Fd()), sourceName, int(targetParent.directory().Fd()), targetName, 0)
	if linkErr != nil && !errors.Is(linkErr, unix.EEXIST) {
		return closeFile(fmt.Errorf("%w: create required same-filesystem hardlink alias: %v", ErrRejected, linkErr))
	}
	var targetRaw unix.Stat_t
	targetErr := unix.Fstatat(int(targetParent.directory().Fd()), targetName, &targetRaw, unix.AT_SYMLINK_NOFOLLOW)
	if targetErr != nil || targetRaw.Dev != sourceRaw.Dev || targetRaw.Ino != sourceRaw.Ino || targetRaw.Size != sourceRaw.Size || uint32(targetRaw.Mode)&unix.S_IFMT != unix.S_IFREG {
		var cleanupErr error
		if linkErr == nil && targetErr == nil {
			cleanupErr = unlinkRootedEntryIfInode(targetParent, targetName, targetRaw)
		}
		return closeFile(errors.Join(fmt.Errorf("%w: rooted hardlink target is not the source inode", ErrIntegrity), linkErr, targetErr, cleanupErr))
	}
	digest, hashErr = hashRegularDescriptor(ctx, file)
	if hashErr != nil || digest != expectedSHA {
		return closeFile(errors.Join(errors.New("managed: rooted link source changed during publication"), hashErr))
	}
	return closeFile(errors.Join(file.Sync(), targetParent.directory().Sync(), sourceParent.verify(), targetParent.verify()))
}

func unlinkRootedEntryIfInode(parent *rootedDirectoryChain, name string, expected unix.Stat_t) error {
	if parent == nil || parent.directory() == nil || name == "" || filepath.Base(name) != name {
		return errors.New("managed: invalid rooted cleanup target")
	}
	if err := parent.verify(); err != nil {
		return err
	}
	var current unix.Stat_t
	if err := unix.Fstatat(int(parent.directory().Fd()), name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if current.Dev != expected.Dev || current.Ino != expected.Ino || uint32(current.Mode)&unix.S_IFMT != uint32(expected.Mode)&unix.S_IFMT {
		return errors.New("managed: rooted cleanup entry changed before unlink")
	}
	if err := unix.Unlinkat(int(parent.directory().Fd()), name, 0); err != nil {
		return err
	}
	var after unix.Stat_t
	if err := unix.Fstatat(int(parent.directory().Fd()), name, &after, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return errors.Join(errors.New("managed: rooted cleanup entry remains after unlink"), err)
	}
	return parent.directory().Sync()
}

// removeRootedRegularBoundToTarget removes an authenticated source name only
// while both source and target still resolve to the identities captured during
// publication. It avoids a second payload hash while preserving the rooted
// path-replacement checks across the target barrier and pending cleanup window.
// A nil source identity means replay already observed the pending name absent;
// in that case the target is still rebound and verified before returning. The
// caller must sync the shared source parent after its complete cleanup batch.
func removeRootedRegularBoundToTarget(root, sourceRelative, targetRelative string, sourceIdentity *rootedRegularIdentity, targetIdentity rootedRegularIdentity, expectedSize int64) error {
	if !targetIdentity.valid(expectedSize) || sourceIdentity != nil && !sourceIdentity.valid(expectedSize) {
		return errors.New("managed: invalid rooted promotion identity")
	}
	sourceComponents, err := rootedPathComponents(sourceRelative, false)
	if err != nil {
		return err
	}
	targetComponents, err := rootedPathComponents(targetRelative, false)
	if err != nil {
		return err
	}
	sourceParent, err := openRootedDirectoryChain(root, filepath.Join(sourceComponents[:len(sourceComponents)-1]...), false, 0)
	if err != nil {
		return err
	}
	targetRootHandle, targetRootBinding, err := duplicateRootedDirectoryChainRoot(sourceParent)
	if err != nil {
		return errors.Join(err, sourceParent.close(true))
	}
	targetParent, err := openRootedDirectoryChainFromHandle(targetRootHandle, targetRootBinding, filepath.Join(targetComponents[:len(targetComponents)-1]...), false, 0)
	if err != nil {
		return errors.Join(err, sourceParent.close(true))
	}
	var sourceFile, targetFile *os.File
	finish := func(result error) error {
		if sourceFile != nil {
			result = errors.Join(result, sourceFile.Close())
		}
		if targetFile != nil {
			result = errors.Join(result, targetFile.Close())
		}
		return errors.Join(result, targetParent.close(true), sourceParent.close(true))
	}
	if err := errors.Join(sourceParent.verify(), targetParent.verify()); err != nil {
		return finish(err)
	}
	sourceName := sourceComponents[len(sourceComponents)-1]
	targetName := targetComponents[len(targetComponents)-1]
	targetFD, err := unix.Openat(int(targetParent.directory().Fd()), targetName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return finish(err)
	}
	targetFile = os.NewFile(uintptr(targetFD), targetName)
	targetInfo, targetInfoErr := targetFile.Stat()
	var targetRaw, targetEntry unix.Stat_t
	targetStatErr := unix.Fstat(targetFD, &targetRaw)
	targetEntryErr := unix.Fstatat(int(targetParent.directory().Fd()), targetName, &targetEntry, unix.AT_SYMLINK_NOFOLLOW)
	if targetInfoErr != nil || targetStatErr != nil || targetEntryErr != nil || !targetIdentity.matchesInfo(targetInfo, targetRaw) || !targetIdentity.matchesStat(targetEntry) {
		return finish(errors.Join(errors.New("managed: promoted target changed before pending cleanup"), targetInfoErr, targetStatErr, targetEntryErr))
	}
	if sourceIdentity == nil {
		var unexpected unix.Stat_t
		if sourceErr := unix.Fstatat(int(sourceParent.directory().Fd()), sourceName, &unexpected, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(sourceErr, unix.ENOENT) {
			return finish(errors.Join(errors.New("managed: absent pending source reappeared before cleanup"), sourceErr))
		}
		return finish(nil)
	}
	sourceFD, err := unix.Openat(int(sourceParent.directory().Fd()), sourceName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return finish(err)
	}
	sourceFile = os.NewFile(uintptr(sourceFD), sourceName)
	sourceInfo, sourceInfoErr := sourceFile.Stat()
	var sourceRaw, sourceEntry unix.Stat_t
	sourceStatErr := unix.Fstat(sourceFD, &sourceRaw)
	sourceEntryErr := unix.Fstatat(int(sourceParent.directory().Fd()), sourceName, &sourceEntry, unix.AT_SYMLINK_NOFOLLOW)
	if sourceInfoErr != nil || sourceStatErr != nil || sourceEntryErr != nil || !sourceIdentity.matchesInfo(sourceInfo, sourceRaw) || !sourceIdentity.matchesStat(sourceEntry) {
		return finish(errors.Join(errors.New("managed: pending source changed before cleanup"), sourceInfoErr, sourceStatErr, sourceEntryErr))
	}
	if err := errors.Join(sourceParent.verify(), targetParent.verify()); err != nil {
		return finish(err)
	}
	var sourceBefore, targetBefore unix.Stat_t
	sourceBeforeErr := unix.Fstatat(int(sourceParent.directory().Fd()), sourceName, &sourceBefore, unix.AT_SYMLINK_NOFOLLOW)
	targetBeforeErr := unix.Fstatat(int(targetParent.directory().Fd()), targetName, &targetBefore, unix.AT_SYMLINK_NOFOLLOW)
	if sourceBeforeErr != nil || targetBeforeErr != nil || !sourceIdentity.matchesStat(sourceBefore) || !targetIdentity.matchesStat(targetBefore) {
		return finish(errors.Join(errors.New("managed: promotion names changed before pending unlink"), sourceBeforeErr, targetBeforeErr))
	}
	if err := unix.Unlinkat(int(sourceParent.directory().Fd()), sourceName, 0); err != nil {
		return finish(err)
	}
	var sourceAfter, targetAfter, targetFDStat unix.Stat_t
	sourceAfterErr := unix.Fstatat(int(sourceParent.directory().Fd()), sourceName, &sourceAfter, unix.AT_SYMLINK_NOFOLLOW)
	targetAfterErr := unix.Fstatat(int(targetParent.directory().Fd()), targetName, &targetAfter, unix.AT_SYMLINK_NOFOLLOW)
	targetFDErr := unix.Fstat(targetFD, &targetFDStat)
	targetAfterInfo, targetAfterInfoErr := targetFile.Stat()
	if !errors.Is(sourceAfterErr, unix.ENOENT) || targetAfterErr != nil || targetFDErr != nil || targetAfterInfoErr != nil ||
		!targetIdentity.matchesStat(targetAfter) || !targetIdentity.matchesInfo(targetAfterInfo, targetFDStat) {
		return finish(errors.Join(errors.New("managed: promotion names changed during pending unlink"), sourceAfterErr, targetAfterErr, targetFDErr, targetAfterInfoErr))
	}
	return finish(nil)
}

func removeRootedRegular(root, relative string, expectedSize int64) error {
	components, err := rootedPathComponents(relative, false)
	if err != nil {
		return err
	}
	parent, err := openRootedDirectoryChain(root, filepath.Join(components[:len(components)-1]...), false, 0o700)
	if err != nil {
		return err
	}
	finish := func(result error) error { return errors.Join(result, parent.close(true)) }
	name := components[len(components)-1]
	fd, err := unix.Openat(int(parent.directory().Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return finish(nil)
	}
	if err != nil {
		return finish(err)
	}
	file := os.NewFile(uintptr(fd), name)
	var before unix.Stat_t
	statErr := unix.Fstat(fd, &before)
	if statErr != nil || uint32(before.Mode)&unix.S_IFMT != unix.S_IFREG || expectedSize >= 0 && before.Size != expectedSize {
		return finish(errors.Join(fmt.Errorf("managed: rooted removal target is unsafe: size=%d expected=%d mode=%#o", before.Size, expectedSize, uint32(before.Mode)), statErr, file.Close()))
	}
	var entry unix.Stat_t
	entryErr := unix.Fstatat(int(parent.directory().Fd()), name, &entry, unix.AT_SYMLINK_NOFOLLOW)
	if entryErr != nil || entry.Dev != before.Dev || entry.Ino != before.Ino || entry.Size != before.Size || uint32(entry.Mode)&unix.S_IFMT != unix.S_IFREG {
		return finish(errors.Join(errors.New("managed: rooted removal entry changed while opening"), entryErr, file.Close()))
	}
	if err := parent.verify(); err != nil {
		return finish(errors.Join(err, file.Close()))
	}
	if err := unix.Unlinkat(int(parent.directory().Fd()), name, 0); err != nil {
		return finish(errors.Join(err, file.Close()))
	}
	var after unix.Stat_t
	afterErr := unix.Fstatat(int(parent.directory().Fd()), name, &after, unix.AT_SYMLINK_NOFOLLOW)
	if !errors.Is(afterErr, unix.ENOENT) {
		return finish(errors.Join(errors.New("managed: rooted removal entry still exists"), afterErr, file.Close()))
	}
	return finish(errors.Join(file.Close(), parent.directory().Sync()))
}

// removeRootedRegularExact unlinks only the plan-bound regular inode after
// checking its complete content identity. A missing entry (or missing parent
// left by an earlier successful replay step) is already complete.
func removeRootedRegularExact(ctx context.Context, root, relative string, expectedSize int64, expectedSHA string) error {
	if ctx == nil || expectedSize < 0 || !lowercaseSHA256.MatchString(expectedSHA) {
		return errors.New("managed: invalid exact rooted removal identity")
	}
	components, err := rootedPathComponents(relative, false)
	if err != nil {
		return err
	}
	parent, err := openRootedDirectoryChain(root, filepath.Join(components[:len(components)-1]...), false, 0o700)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	finish := func(result error) error { return errors.Join(result, parent.close(true)) }
	name := components[len(components)-1]
	fd, err := unix.Openat(int(parent.directory().Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return finish(nil)
	}
	if err != nil {
		return finish(err)
	}
	file := os.NewFile(uintptr(fd), name)
	closeFile := func(result error) error { return finish(errors.Join(result, file.Close())) }
	var before unix.Stat_t
	statErr := unix.Fstat(fd, &before)
	if statErr != nil || uint32(before.Mode)&unix.S_IFMT != unix.S_IFREG || before.Size != expectedSize {
		return closeFile(errors.Join(errors.New("managed: exact rooted removal target differs in size or kind"), statErr))
	}
	digest, hashErr := hashRegularDescriptor(ctx, file)
	if hashErr != nil || digest != expectedSHA {
		return closeFile(errors.Join(errors.New("managed: exact rooted removal target differs in digest"), hashErr))
	}
	var entry, afterHash unix.Stat_t
	entryErr := unix.Fstatat(int(parent.directory().Fd()), name, &entry, unix.AT_SYMLINK_NOFOLLOW)
	afterErr := unix.Fstat(fd, &afterHash)
	if entryErr != nil || afterErr != nil || entry.Dev != before.Dev || entry.Ino != before.Ino || entry.Size != before.Size ||
		afterHash.Dev != before.Dev || afterHash.Ino != before.Ino || afterHash.Size != before.Size ||
		uint32(entry.Mode)&unix.S_IFMT != unix.S_IFREG || uint32(afterHash.Mode)&unix.S_IFMT != unix.S_IFREG {
		return closeFile(errors.Join(errors.New("managed: exact rooted removal entry changed while hashing"), entryErr, afterErr))
	}
	if err := parent.verify(); err != nil {
		return closeFile(err)
	}
	if err := unix.Unlinkat(int(parent.directory().Fd()), name, 0); err != nil {
		return closeFile(err)
	}
	var after unix.Stat_t
	if err := unix.Fstatat(int(parent.directory().Fd()), name, &after, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return closeFile(errors.Join(errors.New("managed: exact rooted removal entry remains after unlink"), err))
	}
	return closeFile(parent.directory().Sync())
}

// removeRootedEmptyDirectory removes one exact directory entry and never
// traverses it. Unknown children therefore make the operation fail closed.
func removeRootedEmptyDirectory(root, relative string) error {
	components, err := rootedPathComponents(relative, false)
	if err != nil {
		return err
	}
	parent, err := openRootedDirectoryChain(root, filepath.Join(components[:len(components)-1]...), false, 0)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	finish := func(result error) error { return errors.Join(result, parent.close(true)) }
	name := components[len(components)-1]
	fd, err := unix.Openat(int(parent.directory().Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if errors.Is(err, unix.ENOENT) {
		return finish(nil)
	}
	if err != nil {
		return finish(err)
	}
	directory := os.NewFile(uintptr(fd), name)
	closeDirectory := func(result error) error { return finish(errors.Join(result, directory.Close())) }
	var opened, entry unix.Stat_t
	statErr := unix.Fstat(fd, &opened)
	entryErr := unix.Fstatat(int(parent.directory().Fd()), name, &entry, unix.AT_SYMLINK_NOFOLLOW)
	if statErr != nil || entryErr != nil || opened.Dev != entry.Dev || opened.Ino != entry.Ino ||
		uint32(opened.Mode)&unix.S_IFMT != unix.S_IFDIR || uint32(entry.Mode)&unix.S_IFMT != unix.S_IFDIR || opened.Dev != parent.binding.stat.Dev {
		return closeDirectory(errors.Join(errors.New("managed: exact empty directory changed while opening"), statErr, entryErr))
	}
	names, readErr := directory.Readdirnames(1)
	if len(names) != 0 || !errors.Is(readErr, io.EOF) {
		return closeDirectory(errors.Join(fmt.Errorf("%w: exact empty directory %q contains an unknown entry", ErrIntegrity, relative), readErr))
	}
	if err := errors.Join(directory.Sync(), parent.verify()); err != nil {
		return closeDirectory(err)
	}
	var before unix.Stat_t
	entryErr = unix.Fstatat(int(parent.directory().Fd()), name, &before, unix.AT_SYMLINK_NOFOLLOW)
	if entryErr != nil || before.Dev != opened.Dev || before.Ino != opened.Ino || uint32(before.Mode)&unix.S_IFMT != unix.S_IFDIR {
		return closeDirectory(errors.Join(errors.New("managed: exact empty directory changed before unlink"), entryErr))
	}
	if err := unix.Unlinkat(int(parent.directory().Fd()), name, unix.AT_REMOVEDIR); err != nil {
		return closeDirectory(err)
	}
	var after unix.Stat_t
	if err := unix.Fstatat(int(parent.directory().Fd()), name, &after, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return closeDirectory(errors.Join(errors.New("managed: exact empty directory remains after unlink"), err))
	}
	return closeDirectory(parent.directory().Sync())
}

func removeOwnedRegularPath(root, target string, expectedSize int64) error {
	relative, err := relativeToRoot(root, target)
	if err != nil {
		return err
	}
	return removeRootedRegular(root, relative, expectedSize)
}

func readRootedRegular(root, relative string, maximum int64, allowEmpty bool) ([]byte, error) {
	if maximum < 0 {
		return nil, errors.New("managed: invalid rooted read limit")
	}
	opened, err := openRootedRegular(root, relative)
	if err != nil {
		return nil, err
	}
	if opened.before.Size() > maximum || !allowEmpty && opened.before.Size() == 0 {
		_ = opened.CloseVerified()
		return nil, errors.New("managed: rooted regular file is empty or unbounded")
	}
	data, readErr := io.ReadAll(io.LimitReader(opened.file, maximum+1))
	verifyErr := opened.CloseVerified()
	if readErr != nil || verifyErr != nil || int64(len(data)) != opened.before.Size() || int64(len(data)) > maximum {
		return nil, errors.Join(errors.New("managed: rooted regular file changed while reading"), readErr, verifyErr)
	}
	return data, nil
}

func readRootedPrivateRegular(root, relative string, maximum int64, allowEmpty bool) ([]byte, error) {
	if maximum < 0 {
		return nil, errors.New("managed: invalid private rooted read bound")
	}
	opened, err := openRootedPrivateRegular(root, relative)
	if err != nil {
		return nil, err
	}
	if opened.before.Size() > maximum || (!allowEmpty && opened.before.Size() == 0) {
		return nil, errors.Join(errors.New("managed: private rooted regular file has invalid size"), opened.CloseVerified())
	}
	data, readErr := io.ReadAll(io.LimitReader(opened.file, maximum+1))
	verifyErr := opened.CloseVerified()
	if readErr != nil || verifyErr != nil || int64(len(data)) > maximum || int64(len(data)) != opened.before.Size() {
		return nil, errors.Join(errors.New("managed: private rooted regular file changed or exceeds bound"), readErr, verifyErr)
	}
	return data, nil
}

// walkRootedTree enumerates through held directory descriptors and opens every
// child with O_NOFOLLOW. Directory modification during traversal and entry
// replacement between readdir and open are both rejected.
func walkRootedTree(ctx context.Context, root string, visitFile func(string, *os.File, os.FileInfo) error, visitDirectory func(string, *os.File, os.FileInfo) error) error {
	handle, rootBinding, err := openBoundRootDirectory(root)
	if err != nil {
		return fmt.Errorf("managed: open rooted tree: %w", err)
	}
	var walk func(*os.File, string) error
	walk = func(directory *os.File, relative string) error {
		before, err := directory.Stat()
		if err != nil || !before.IsDir() {
			return errors.New("managed: rooted tree directory is unsafe")
		}
		entries, err := directory.Readdir(-1)
		if err != nil {
			return err
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			name := entry.Name()
			if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, `/\`) {
				return errors.New("managed: rooted tree has an unsafe entry name")
			}
			childRelative := name
			if relative != "" {
				childRelative = filepath.Join(relative, name)
			}
			flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
			if entry.IsDir() {
				flags |= unix.O_DIRECTORY
			}
			childFD, err := unix.Openat(int(directory.Fd()), name, flags, 0)
			if err != nil {
				return errors.New("managed: rooted tree entry changed or is unsafe")
			}
			child := os.NewFile(uintptr(childFD), childRelative)
			opened, statErr := child.Stat()
			if statErr != nil || !os.SameFile(entry, opened) {
				_ = child.Close()
				return errors.New("managed: rooted tree entry changed while opening")
			}
			if opened.IsDir() {
				err = walk(child, childRelative)
			} else if opened.Mode().IsRegular() {
				if visitFile != nil {
					err = visitFile(filepath.ToSlash(childRelative), child, opened)
				}
				after, afterErr := child.Stat()
				if err == nil && (afterErr != nil || !os.SameFile(opened, after) || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime())) {
					err = errors.New("managed: rooted tree file changed during visit")
				}
			} else {
				err = errors.New("managed: rooted tree contains a non-regular entry")
			}
			closeErr := child.Close()
			if err = errors.Join(err, closeErr); err != nil {
				return err
			}
		}
		if visitDirectory != nil {
			if err := visitDirectory(filepath.ToSlash(relative), directory, before); err != nil {
				return err
			}
		}
		after, err := directory.Stat()
		if err != nil || !os.SameFile(before, after) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
			return errors.New("managed: rooted tree directory changed during traversal")
		}
		return nil
	}
	walkErr := walk(handle, "")
	rootErr := verifyBoundRootDirectory(handle, rootBinding)
	closeErr := handle.Close()
	return errors.Join(walkErr, rootErr, closeErr)
}

// walkRootedInputFiles is the permissive input-scanning counterpart to
// walkRootedTree: symlinks and special files are ignored, never followed.
// Every visited regular file and directory is still descriptor-bound and any
// entry replacement during the scan fails the whole input directory.
func walkRootedInputFiles(ctx context.Context, root string, visit func(string, *os.File, os.FileInfo) error) error {
	handle, rootBinding, err := openBoundRootDirectory(root)
	if err != nil {
		return err
	}
	var walk func(*os.File, string) error
	walk = func(directory *os.File, relative string) error {
		before, err := directory.Stat()
		if err != nil || !before.IsDir() {
			return errors.Join(errors.New("managed: input directory is unsafe"), err)
		}
		entries, err := directory.Readdir(-1)
		if err != nil {
			return err
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			name := entry.Name()
			if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, `/\`) {
				return errors.New("managed: input directory contains an unsafe entry name")
			}
			if entry.Mode()&os.ModeSymlink != 0 || !entry.IsDir() && !entry.Mode().IsRegular() {
				continue
			}
			childRelative := name
			if relative != "" {
				childRelative = filepath.Join(relative, name)
			}
			flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
			if entry.IsDir() {
				flags |= unix.O_DIRECTORY
			}
			childFD, err := unix.Openat(int(directory.Fd()), name, flags, 0)
			if err != nil {
				return errors.New("managed: input entry changed or became unsafe")
			}
			child := os.NewFile(uintptr(childFD), childRelative)
			opened, statErr := child.Stat()
			if statErr != nil || !os.SameFile(entry, opened) {
				_ = child.Close()
				return errors.Join(errors.New("managed: input entry changed while opening"), statErr)
			}
			if opened.IsDir() {
				err = walk(child, childRelative)
			} else if visit != nil {
				err = visit(filepath.ToSlash(childRelative), child, opened)
			}
			after, afterErr := child.Stat()
			if err == nil && (afterErr != nil || !os.SameFile(opened, after) || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime())) {
				err = errors.Join(errors.New("managed: input entry changed during scan"), afterErr)
			}
			if err = errors.Join(err, child.Close()); err != nil {
				return err
			}
		}
		after, err := directory.Stat()
		if err != nil || !os.SameFile(before, after) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
			return errors.Join(errors.New("managed: input directory changed during scan"), err)
		}
		return nil
	}
	return errors.Join(walk(handle, ""), verifyBoundRootDirectory(handle, rootBinding), handle.Close())
}

func realDirectory(path string, create bool, mode os.FileMode) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if _, err := os.Lstat(abs); errors.Is(err, os.ErrNotExist) && create {
		ancestor := abs
		var missing []string
		for {
			parent := filepath.Dir(ancestor)
			if parent == ancestor {
				return "", fmt.Errorf("%w: no existing ancestor for %q", ErrRejected, abs)
			}
			missing = append(missing, filepath.Base(ancestor))
			ancestor = parent
			if _, statErr := os.Lstat(ancestor); statErr == nil {
				break
			} else if !errors.Is(statErr, os.ErrNotExist) {
				return "", statErr
			}
		}
		physical, evalErr := filepath.EvalSymlinks(ancestor)
		if evalErr != nil {
			return "", evalErr
		}
		for i := len(missing) - 1; i >= 0; i-- {
			physical = filepath.Join(physical, missing[i])
			if _, err := durableEnsureDir(physical, mode); err != nil {
				return "", err
			}
			info, err := os.Lstat(physical)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("%w: created path %q is not a real directory", ErrRejected, physical)
			}
		}
		abs = physical
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: path %q is not a real directory", ErrRejected, abs)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	return filepath.Abs(real)
}

// prospectiveRealDirectory resolves the nearest existing directory without
// creating any component, then appends the missing suffix. The returned path
// uses the directory-entry spelling observed by the filesystem, so symlink
// aliases and case aliases cannot pass an overlap check on macOS.
func prospectiveRealDirectory(path string) (physical string, exists bool, err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", false, err
	}
	abs = filepath.Clean(abs)
	ancestor := abs
	missing := []string{}
	for {
		info, statErr := os.Lstat(ancestor)
		if statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				resolved, evalErr := filepath.EvalSymlinks(ancestor)
				if evalErr != nil {
					return "", false, evalErr
				}
				ancestor = resolved
				info, statErr = os.Stat(ancestor)
			}
			if statErr != nil || !info.IsDir() {
				return "", false, fmt.Errorf("%w: existing path %q is not a directory", ErrRejected, ancestor)
			}
			break
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return "", false, statErr
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return "", false, fmt.Errorf("%w: no existing directory ancestor for %q", ErrRejected, abs)
		}
		missing = append(missing, filepath.Base(ancestor))
		ancestor = parent
	}
	resolved, err := filepath.EvalSymlinks(ancestor)
	if err != nil {
		return "", false, err
	}
	resolved, err = canonicalDirectoryEntrySpelling(resolved)
	if err != nil {
		return "", false, err
	}
	for index := len(missing) - 1; index >= 0; index-- {
		resolved = filepath.Join(resolved, missing[index])
	}
	return filepath.Clean(resolved), len(missing) == 0, nil
}

func canonicalDirectoryEntrySpelling(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	volume := filepath.VolumeName(abs)
	root := volume + string(filepath.Separator)
	relative, err := filepath.Rel(root, abs)
	if err != nil {
		return "", err
	}
	if relative == "." {
		return root, nil
	}
	current := root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		requested := filepath.Join(current, component)
		requestedInfo, err := os.Stat(requested)
		if err != nil || !requestedInfo.IsDir() {
			return "", errors.Join(fmt.Errorf("%w: inspect directory component %q", ErrRejected, requested), err)
		}
		entries, err := os.ReadDir(current)
		if err != nil {
			return "", err
		}
		matched := ""
		for _, entry := range entries {
			entryInfo, infoErr := entry.Info()
			if infoErr == nil && entryInfo.IsDir() && os.SameFile(requestedInfo, entryInfo) {
				matched = entry.Name()
				break
			}
		}
		if matched == "" {
			return "", fmt.Errorf("%w: cannot bind directory spelling for %q", ErrRejected, requested)
		}
		current = filepath.Join(current, matched)
	}
	return current, nil
}

func ownedPath(root string, parts ...string) (string, error) {
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || filepath.Base(part) != part || strings.ContainsAny(part, `/\`) {
			return "", fmt.Errorf("%w: unsafe path component %q", ErrRejected, part)
		}
	}
	target := filepath.Join(append([]string{root}, parts...)...)
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: path escapes workspace", ErrRejected)
	}
	return target, nil
}

func rejectSymlinkChain(root, relative string, allowMissing bool) error {
	current := root
	for _, part := range strings.Split(filepath.ToSlash(relative), "/") {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && allowMissing {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: symlink in owned path %q", ErrRejected, current)
		}
	}
	return nil
}

func openPhysicalDirectoryChain(path string) (*rootedDirectoryChain, error) {
	handle, binding, err := openBoundRootDirectory(path)
	if err != nil {
		return nil, err
	}
	return &rootedDirectoryChain{binding: binding, directories: []*os.File{handle}}, nil
}

func randomOwnedEntryName(prefix string) (string, error) {
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(entropy[:]), nil
}

func writeAtomic(filename string, data []byte, mode os.FileMode) error {
	parent := filepath.Dir(filename)
	name := filepath.Base(filename)
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return errors.New("managed: unsafe atomic write target")
	}
	parentChain, err := openPhysicalDirectoryChain(parent)
	if err != nil {
		return fmt.Errorf("atomic write parent is not a real directory: %w", err)
	}
	finishParent := func(result error) error { return errors.Join(result, parentChain.close(true)) }
	var tempName string
	var fd int
	for range 16 {
		tempName, err = randomOwnedEntryName(".sow-write-")
		if err != nil {
			return finishParent(err)
		}
		fd, err = unix.Openat(int(parentChain.directory().Fd()), tempName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(mode.Perm()))
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		break
	}
	if err != nil {
		return finishParent(err)
	}
	tmp := os.NewFile(uintptr(fd), tempName)
	var tempRaw unix.Stat_t
	if err := unix.Fstat(fd, &tempRaw); err != nil || uint32(tempRaw.Mode)&unix.S_IFMT != unix.S_IFREG {
		return finishParent(errors.Join(errors.New("managed: atomic temporary is unsafe"), err, tmp.Close()))
	}
	renamed := false
	cleanupTemp := func() error {
		if renamed {
			return nil
		}
		var entry unix.Stat_t
		if err := unix.Fstatat(int(parentChain.directory().Fd()), tempName, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if errors.Is(err, unix.ENOENT) {
				return nil
			}
			return err
		}
		if entry.Dev != tempRaw.Dev || entry.Ino != tempRaw.Ino || uint32(entry.Mode)&unix.S_IFMT != unix.S_IFREG {
			return errors.New("managed: atomic temporary changed before cleanup")
		}
		return unix.Unlinkat(int(parentChain.directory().Fd()), tempName, 0)
	}
	finish := func(result error) error {
		return finishParent(errors.Join(result, cleanupTemp(), tmp.Close()))
	}
	if err := tmp.Chmod(mode); err != nil {
		return finish(err)
	}
	written, err := tmp.Write(data)
	if err != nil || written != len(data) {
		return finish(errors.Join(err, io.ErrShortWrite))
	}
	if err := errors.Join(tmp.Sync(), parentChain.verify()); err != nil {
		return finish(err)
	}
	if err := unix.Renameat(int(parentChain.directory().Fd()), tempName, int(parentChain.directory().Fd()), name); err != nil {
		return finish(err)
	}
	renamed = true
	var targetRaw unix.Stat_t
	targetErr := unix.Fstatat(int(parentChain.directory().Fd()), name, &targetRaw, unix.AT_SYMLINK_NOFOLLOW)
	if targetErr != nil || targetRaw.Dev != tempRaw.Dev || targetRaw.Ino != tempRaw.Ino || targetRaw.Size != int64(len(data)) || uint32(targetRaw.Mode)&unix.S_IFMT != unix.S_IFREG {
		return finish(errors.Join(errors.New("managed: atomic write target is not the staged inode"), targetErr))
	}
	return finish(parentChain.directory().Sync())
}

func syncDir(path string) error {
	chain, err := openPhysicalDirectoryChain(path)
	if err != nil {
		return err
	}
	return errors.Join(chain.directory().Sync(), chain.close(true))
}

func syncRootedDirectory(root, relative string) error {
	chain, err := openRootedDirectoryChain(root, relative, false, 0)
	if err != nil {
		return err
	}
	if err := chain.verify(); err != nil {
		return errors.Join(err, chain.close(false))
	}
	return errors.Join(chain.directory().Sync(), chain.close(true))
}

func normalizeDirectoryMode(path string, mode os.FileMode) error {
	chain, err := openPhysicalDirectoryChain(path)
	if err != nil {
		return fmt.Errorf("open directory for mode normalization: %w", err)
	}
	if err := chain.directory().Chmod(mode); err != nil {
		return errors.Join(err, chain.close(true))
	}
	return errors.Join(chain.directory().Sync(), chain.close(true))
}

// durableMkdir makes a single directory entry durable before returning.  The
// caller is still responsible for fsyncing files and child directories added
// beneath it.
func durableMkdir(path string, mode os.FileMode) error {
	return durableMkdirWithHook(path, mode, nil)
}

func durableMkdirWithHook(path string, mode os.FileMode, afterBind func() error) error {
	name := filepath.Base(path)
	parent, err := openPhysicalDirectoryChain(filepath.Dir(path))
	if err != nil {
		return err
	}
	finish := func(result error) error { return errors.Join(result, parent.close(true)) }
	if err := unix.Mkdirat(int(parent.directory().Fd()), name, uint32(mode.Perm())); err != nil {
		return finish(err)
	}
	fd, err := unix.Openat(int(parent.directory().Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return finish(err)
	}
	directory := os.NewFile(uintptr(fd), name)
	var opened, entry unix.Stat_t
	statErr := unix.Fstat(fd, &opened)
	entryErr := unix.Fstatat(int(parent.directory().Fd()), name, &entry, unix.AT_SYMLINK_NOFOLLOW)
	if statErr != nil || entryErr != nil || opened.Dev != entry.Dev || opened.Ino != entry.Ino || uint32(opened.Mode)&unix.S_IFMT != unix.S_IFDIR {
		return finish(errors.Join(errors.New("managed: created directory changed while opening"), statErr, entryErr, directory.Close()))
	}
	if err := errors.Join(directory.Chmod(mode), directory.Sync()); err != nil {
		return finish(errors.Join(err, directory.Close()))
	}
	if afterBind != nil {
		if err := afterBind(); err != nil {
			return finish(errors.Join(err, directory.Close()))
		}
	}
	result := parent.directory().Sync()
	var finalOpened, finalEntry unix.Stat_t
	result = errors.Join(result,
		unix.Fstat(fd, &finalOpened),
		unix.Fstatat(int(parent.directory().Fd()), name, &finalEntry, unix.AT_SYMLINK_NOFOLLOW),
		parent.verify(),
	)
	if finalOpened.Dev != opened.Dev || finalOpened.Ino != opened.Ino ||
		finalEntry.Dev != opened.Dev || finalEntry.Ino != opened.Ino ||
		uint32(finalOpened.Mode)&unix.S_IFMT != unix.S_IFDIR || uint32(finalEntry.Mode)&unix.S_IFMT != unix.S_IFDIR ||
		uint32(finalOpened.Mode)&0o777 != uint32(mode.Perm()) || uint32(finalEntry.Mode)&0o777 != uint32(mode.Perm()) {
		result = errors.Join(result, errors.New("managed: created directory changed before commit"))
	}
	return finish(errors.Join(result, directory.Close()))
}

func durableEnsureDir(path string, mode os.FileMode) (bool, error) {
	if err := durableMkdir(path, mode); err == nil {
		return true, nil
	} else if !errors.Is(err, os.ErrExist) {
		return false, err
	}
	if err := normalizeDirectoryMode(path, mode); err != nil {
		return false, fmt.Errorf("%w: concurrently created path %q is not a real directory: %v", ErrRejected, path, err)
	}
	return false, nil
}

func durableEnsureDirectoryTree(root, target string, mode os.FileMode) error {
	root = filepath.Clean(root)
	target = filepath.Clean(target)
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: directory tree target escapes its owner", ErrRejected)
	}
	chain, err := openRootedDirectoryChain(root, relative, true, mode)
	if err != nil {
		return err
	}
	return chain.close(true)
}

func durableEnsureRegularFile(path string, mode os.FileMode) (bool, error) {
	return durableEnsureRegularFileWithHook(path, mode, nil)
}

func durableEnsureRegularFileWithHook(path string, mode os.FileMode, afterBind func() error) (bool, error) {
	name := filepath.Base(path)
	parent, err := openPhysicalDirectoryChain(filepath.Dir(path))
	if err != nil {
		return false, err
	}
	finish := func(created bool, result error) (bool, error) {
		return created, errors.Join(result, parent.close(true))
	}
	fd, err := unix.Openat(int(parent.directory().Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(mode.Perm()))
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Openat(int(parent.directory().Fd()), name, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		return finish(false, err)
	}
	file := os.NewFile(uintptr(fd), name)
	var opened, entry unix.Stat_t
	statErr := unix.Fstat(fd, &opened)
	entryErr := unix.Fstatat(int(parent.directory().Fd()), name, &entry, unix.AT_SYMLINK_NOFOLLOW)
	if statErr != nil || entryErr != nil || opened.Dev != entry.Dev || opened.Ino != entry.Ino || uint32(opened.Mode)&unix.S_IFMT != unix.S_IFREG {
		return finish(false, errors.Join(fmt.Errorf("%w: existing file %q is not a safe regular file", ErrRejected, path), statErr, entryErr, file.Close()))
	}
	if created {
		if err := errors.Join(file.Chmod(mode), file.Sync()); err != nil {
			return finish(true, errors.Join(err, file.Close()))
		}
	}
	if afterBind != nil {
		if err := afterBind(); err != nil {
			return finish(created, errors.Join(err, file.Close()))
		}
	}
	var result error
	if created {
		result = parent.directory().Sync()
	}
	var finalOpened, finalEntry unix.Stat_t
	result = errors.Join(result,
		unix.Fstat(fd, &finalOpened),
		unix.Fstatat(int(parent.directory().Fd()), name, &finalEntry, unix.AT_SYMLINK_NOFOLLOW),
		parent.verify(),
	)
	if finalOpened.Dev != opened.Dev || finalOpened.Ino != opened.Ino ||
		finalEntry.Dev != opened.Dev || finalEntry.Ino != opened.Ino ||
		uint32(finalOpened.Mode)&unix.S_IFMT != unix.S_IFREG || uint32(finalEntry.Mode)&unix.S_IFMT != unix.S_IFREG {
		result = errors.Join(result, fmt.Errorf("%w: regular file %q changed before commit", ErrIntegrity, path))
	}
	return finish(created, errors.Join(result, file.Close()))
}

// durableRename persists both sides of a no-replace cross-directory rename.
// Both parent descriptors are derived from one held owner descriptor, so an
// ancestor replacement cannot splice the source and target into two different
// workspace trees. Syncing only the destination parent is insufficient: after
// a power loss the source entry may otherwise reappear.
func durableRename(root, source, target string) error {
	return durableRenameWithHook(root, source, target, nil)
}

func durableRenameWithHook(root, source, target string, afterSourceParent func() error) error {
	sourceName := filepath.Base(source)
	targetName := filepath.Base(target)
	if sourceName == "" || sourceName == "." || sourceName == ".." || targetName == "" || targetName == "." || targetName == ".." || strings.ContainsAny(sourceName+targetName, `/\`) {
		return errors.New("managed: unsafe durable rename target")
	}
	sourceRelative, err := relativeToRoot(root, source)
	if err != nil {
		return err
	}
	targetRelative, err := relativeToRoot(root, target)
	if err != nil {
		return err
	}
	sourceComponents, err := rootedPathComponents(sourceRelative, false)
	if err != nil {
		return err
	}
	targetComponents, err := rootedPathComponents(targetRelative, false)
	if err != nil {
		return err
	}
	sourceParentRelative := filepath.Join(sourceComponents[:len(sourceComponents)-1]...)
	if sourceParentRelative == "" {
		sourceParentRelative = "."
	}
	targetParentRelative := filepath.Join(targetComponents[:len(targetComponents)-1]...)
	if targetParentRelative == "" {
		targetParentRelative = "."
	}
	sourceParent, err := openRootedDirectoryChain(root, sourceParentRelative, false, 0)
	if err != nil {
		return err
	}
	if afterSourceParent != nil {
		if err := afterSourceParent(); err != nil {
			return errors.Join(err, sourceParent.close(true))
		}
	}
	targetRoot, targetBinding, err := duplicateRootedDirectoryChainRoot(sourceParent)
	if err != nil {
		return errors.Join(err, sourceParent.close(true))
	}
	targetParent, err := openRootedDirectoryChainFromHandle(targetRoot, targetBinding, targetParentRelative, false, 0)
	if err != nil {
		return errors.Join(err, sourceParent.close(true))
	}
	finish := func(result error) error {
		return errors.Join(result, targetParent.close(true), sourceParent.close(true))
	}
	if err := errors.Join(sourceParent.verify(), targetParent.verify()); err != nil {
		return finish(err)
	}
	var sourceEntry unix.Stat_t
	if err := unix.Fstatat(int(sourceParent.directory().Fd()), sourceName, &sourceEntry, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return finish(err)
	}
	entryType := uint32(sourceEntry.Mode) & unix.S_IFMT
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if entryType == unix.S_IFDIR {
		flags |= unix.O_DIRECTORY
	} else if entryType != unix.S_IFREG {
		return finish(errors.New("managed: durable rename source is not a regular file or directory"))
	}
	fd, err := unix.Openat(int(sourceParent.directory().Fd()), sourceName, flags, 0)
	if err != nil {
		return finish(err)
	}
	held := os.NewFile(uintptr(fd), sourceName)
	closeHeld := func(result error) error { return finish(errors.Join(result, held.Close())) }
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil || opened.Dev != sourceEntry.Dev || opened.Ino != sourceEntry.Ino || uint32(opened.Mode)&unix.S_IFMT != entryType {
		return closeHeld(errors.Join(errors.New("managed: durable rename source changed while opening"), err))
	}
	var targetEntry unix.Stat_t
	if err := unix.Fstatat(int(targetParent.directory().Fd()), targetName, &targetEntry, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return closeHeld(errors.Join(errors.New("managed: durable rename target already exists or is unsafe"), err))
	}
	if err := errors.Join(sourceParent.verify(), targetParent.verify()); err != nil {
		return closeHeld(err)
	}
	if err := renameAtNoReplace(int(sourceParent.directory().Fd()), sourceName, int(targetParent.directory().Fd()), targetName); err != nil {
		return closeHeld(err)
	}
	var afterTarget, afterSource unix.Stat_t
	targetErr := unix.Fstatat(int(targetParent.directory().Fd()), targetName, &afterTarget, unix.AT_SYMLINK_NOFOLLOW)
	sourceErr := unix.Fstatat(int(sourceParent.directory().Fd()), sourceName, &afterSource, unix.AT_SYMLINK_NOFOLLOW)
	if targetErr != nil || !errors.Is(sourceErr, unix.ENOENT) || afterTarget.Dev != opened.Dev || afterTarget.Ino != opened.Ino || uint32(afterTarget.Mode)&unix.S_IFMT != entryType {
		return closeHeld(errors.Join(errors.New("managed: durable rename final entries are inconsistent"), targetErr, sourceErr))
	}
	return closeHeld(errors.Join(sourceParent.directory().Sync(), targetParent.directory().Sync()))
}

// exchangeRootedDirectories atomically swaps two directory entries reached
// from one held owner descriptor.  Both parents and both leaf inodes are
// rebound immediately before the kernel exchange and verified afterwards.
func exchangeRootedDirectories(root, leftRelative, rightRelative string) error {
	return exchangeRootedDirectoriesWithHook(root, leftRelative, rightRelative, nil)
}

func exchangeRootedDirectoriesWithHook(root, leftRelative, rightRelative string, afterBind func() error) error {
	leftComponents, err := rootedPathComponents(leftRelative, false)
	if err != nil {
		return err
	}
	rightComponents, err := rootedPathComponents(rightRelative, false)
	if err != nil {
		return err
	}
	leftParent, err := openRootedDirectoryChain(root, filepath.Join(leftComponents[:len(leftComponents)-1]...), false, 0)
	if err != nil {
		return err
	}
	rightRoot, rightBinding, err := duplicateRootedDirectoryChainRoot(leftParent)
	if err != nil {
		return errors.Join(err, leftParent.close(true))
	}
	rightParent, err := openRootedDirectoryChainFromHandle(rightRoot, rightBinding, filepath.Join(rightComponents[:len(rightComponents)-1]...), false, 0)
	if err != nil {
		return errors.Join(err, leftParent.close(true))
	}
	finish := func(result error) error { return errors.Join(result, rightParent.close(true), leftParent.close(true)) }
	leftName, rightName := leftComponents[len(leftComponents)-1], rightComponents[len(rightComponents)-1]
	openLeaf := func(parent *rootedDirectoryChain, name string) (*os.File, unix.Stat_t, error) {
		var entry unix.Stat_t
		if err := unix.Fstatat(int(parent.directory().Fd()), name, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil || uint32(entry.Mode)&unix.S_IFMT != unix.S_IFDIR {
			return nil, unix.Stat_t{}, errors.Join(errors.New("managed: rooted exchange leaf is not a directory"), err)
		}
		fd, err := unix.Openat(int(parent.directory().Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		if err != nil {
			return nil, unix.Stat_t{}, err
		}
		leaf := os.NewFile(uintptr(fd), name)
		var opened unix.Stat_t
		if err := unix.Fstat(fd, &opened); err != nil || opened.Dev != entry.Dev || opened.Ino != entry.Ino || uint32(opened.Mode)&unix.S_IFMT != unix.S_IFDIR {
			return nil, unix.Stat_t{}, errors.Join(errors.New("managed: rooted exchange leaf changed while opening"), err, leaf.Close())
		}
		return leaf, opened, nil
	}
	left, leftStat, err := openLeaf(leftParent, leftName)
	if err != nil {
		return finish(err)
	}
	right, rightStat, err := openLeaf(rightParent, rightName)
	if err != nil {
		return finish(errors.Join(err, left.Close()))
	}
	closeLeaves := func(result error) error { return finish(errors.Join(result, right.Close(), left.Close())) }
	if leftStat.Dev != rightStat.Dev {
		return closeLeaves(fmt.Errorf("%w: rooted exchange crosses filesystems", ErrRejected))
	}
	if afterBind != nil {
		if err := afterBind(); err != nil {
			return closeLeaves(err)
		}
	}
	if err := errors.Join(leftParent.verify(), rightParent.verify()); err != nil {
		return closeLeaves(err)
	}
	if err := exchangeDirectoriesAt(int(leftParent.directory().Fd()), leftName, int(rightParent.directory().Fd()), rightName); err != nil {
		return closeLeaves(err)
	}
	var afterLeft, afterRight unix.Stat_t
	leftErr := unix.Fstatat(int(leftParent.directory().Fd()), leftName, &afterLeft, unix.AT_SYMLINK_NOFOLLOW)
	rightErr := unix.Fstatat(int(rightParent.directory().Fd()), rightName, &afterRight, unix.AT_SYMLINK_NOFOLLOW)
	if leftErr != nil || rightErr != nil || afterLeft.Dev != rightStat.Dev || afterLeft.Ino != rightStat.Ino ||
		afterRight.Dev != leftStat.Dev || afterRight.Ino != leftStat.Ino || uint32(afterLeft.Mode)&unix.S_IFMT != unix.S_IFDIR || uint32(afterRight.Mode)&unix.S_IFMT != unix.S_IFDIR {
		return closeLeaves(errors.Join(errors.New("managed: rooted directory exchange result is inconsistent"), leftErr, rightErr))
	}
	return closeLeaves(errors.Join(leftParent.directory().Sync(), rightParent.directory().Sync()))
}

// readBoundedRegularNoFollow binds every parent component and the regular file
// itself with no-follow descriptors. It rejects symlink components and any
// parent or final-entry replacement during the bounded read.
func readBoundedRegularNoFollow(filename string, maximum int64) ([]byte, error) {
	return readBoundedRegularNoFollowWithHook(filename, maximum, nil)
}

func readBoundedRegularNoFollowWithHook(filename string, maximum int64, afterOpen func() error) ([]byte, error) {
	if maximum < 1 {
		return nil, errors.New("managed: invalid bounded read limit")
	}
	name := filepath.Base(filename)
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return nil, errors.New("managed: bounded file has an unsafe name")
	}
	parent, err := openPhysicalDirectoryChain(filepath.Dir(filename))
	if err != nil {
		return nil, errors.New("managed: bounded file parent is missing or unsafe")
	}
	finishParent := func(result error) error { return errors.Join(result, parent.close(true)) }
	var before unix.Stat_t
	if err := unix.Fstatat(int(parent.directory().Fd()), name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil || uint32(before.Mode)&unix.S_IFMT != unix.S_IFREG || before.Size < 1 || before.Size > maximum {
		return nil, finishParent(errors.New("managed: bounded file is missing, unsafe, empty, or oversized"))
	}
	fd, err := unix.Openat(int(parent.directory().Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, finishParent(errors.New("managed: cannot bind bounded regular file"))
	}
	file := os.NewFile(uintptr(fd), filename)
	finish := func(result error) error { return finishParent(errors.Join(result, file.Close())) }
	var openedRaw unix.Stat_t
	opened, statErr := file.Stat()
	if statErr != nil || unix.Fstat(fd, &openedRaw) != nil || !opened.Mode().IsRegular() || openedRaw.Dev != before.Dev || openedRaw.Ino != before.Ino || openedRaw.Size != before.Size {
		return nil, finish(errors.New("managed: bounded file changed while opening"))
	}
	if afterOpen != nil {
		if err := afterOpen(); err != nil {
			return nil, finish(err)
		}
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	if readErr != nil || int64(len(data)) != opened.Size() || int64(len(data)) > maximum {
		return nil, finish(errors.New("managed: bounded file changed while reading"))
	}
	afterFD, fdErr := file.Stat()
	var afterPath unix.Stat_t
	pathErr := unix.Fstatat(int(parent.directory().Fd()), name, &afterPath, unix.AT_SYMLINK_NOFOLLOW)
	if fdErr != nil || pathErr != nil || !afterFD.Mode().IsRegular() || !os.SameFile(opened, afterFD) ||
		afterFD.Size() != opened.Size() || !afterFD.ModTime().Equal(opened.ModTime()) || afterPath.Dev != openedRaw.Dev ||
		afterPath.Ino != openedRaw.Ino || afterPath.Size != openedRaw.Size || uint32(afterPath.Mode)&unix.S_IFMT != unix.S_IFREG {
		return nil, finish(errors.New("managed: bounded file changed during read"))
	}
	if err := finish(nil); err != nil {
		return nil, err
	}
	return data, nil
}

func bytesSHA(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func operationID() (string, error) {
	for {
		var data [8]byte
		if _, err := rand.Read(data[:]); err != nil {
			return "", err
		}
		value := binary.BigEndian.Uint64(data[:]) & ((uint64(1) << 63) - 1)
		if value != 0 {
			return strconv.FormatUint(value, 10), nil
		}
	}
}

func callFault(fn func(string) error, point string) error {
	if err := verifyAllActiveWorkspaceRoots(); err != nil {
		return err
	}
	if fn == nil {
		return nil
	}
	if err := fn(point); err != nil {
		return &injectedFaultError{point: point, err: err}
	}
	return verifyAllActiveWorkspaceRoots()
}

type injectedFaultError struct {
	point string
	err   error
}

func (err *injectedFaultError) Error() string {
	if err == nil {
		return "managed: injected fault"
	}
	return fmt.Sprintf("managed: injected fault at %s: %v", err.point, err.err)
}

func (err *injectedFaultError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.err
}

func isInjectedFault(err error) bool {
	var injected *injectedFaultError
	return errors.As(err, &injected)
}

func requireSameDevice(left, right string) error {
	var leftStat, rightStat unix.Stat_t
	if err := unix.Stat(left, &leftStat); err != nil {
		return fmt.Errorf("managed: stat stage device: %w", err)
	}
	if err := unix.Stat(right, &rightStat); err != nil {
		return fmt.Errorf("managed: stat target device: %w", err)
	}
	if leftStat.Dev != rightStat.Dev {
		return fmt.Errorf("%w: stage and target are on different filesystems", ErrRejected)
	}
	return nil
}

func validateWorkspaceOpsLayout(root string) error {
	for _, path := range []string{filepath.Join(root, ".sow"), filepath.Join(root, ".sow", "workspace-ops")} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: workspace operation path %q is missing or unsafe", ErrIntegrity, path)
		}
	}
	return nil
}

func validateReadOnlyStateRoot(root string, allowMissing bool) (bool, error) {
	path := filepath.Join(root, ".sow")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && allowMissing {
		return false, nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("%w: state root %q is missing or unsafe", ErrIntegrity, path)
	}
	return true, nil
}

// validateLegacyRepositoryPrivateLayout validates the private directory set
// that was already part of the frozen v0.2 Repository contract.  Read-only
// discovery must start from this smaller set: retained/ and transitions/ are
// later schema additions and therefore cannot be required before the database schema
// has identified the Repository as current.
func validateLegacyRepositoryPrivateLayout(root, repoName string) error {
	if err := config.ValidateName(repoName); err != nil {
		return fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	for _, path := range []string{
		filepath.Join(root, ".sow"),
		filepath.Join(root, ".sow", repoName),
		filepath.Join(root, ".sow", repoName, "stage"),
		filepath.Join(root, ".sow", repoName, "pending"),
		filepath.Join(root, ".sow", repoName, "recovery"),
	} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: repository private path %q is missing or unsafe", ErrIntegrity, path)
		}
	}
	lockPath := filepath.Join(root, ".sow", "repo-locks", repoName+".lock")
	info, err := os.Lstat(lockPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: repository lock path %q is missing or unsafe", ErrIntegrity, lockPath)
	}
	return nil
}

func validateCurrentRepositoryPrivateLayout(root, repoName string) error {
	if err := validateLegacyRepositoryPrivateLayout(root, repoName); err != nil {
		return err
	}
	for _, path := range []string{
		filepath.Join(root, ".sow", repoName, "retained"),
		filepath.Join(root, ".sow", repoName, "transitions"),
	} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: repository private path %q is missing or unsafe", ErrIntegrity, path)
		}
	}
	return nil
}

func validateRepositoryPublicLayout(root, repoName string) error {
	for _, path := range []string{
		filepath.Join(root, repoName),
		filepath.Join(root, repoName, "pool"),
		filepath.Join(root, repoName, "dists"),
	} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: repository public path %q is missing or unsafe", ErrIntegrity, path)
		}
	}
	return nil
}

func validateRepositoryLayoutForRead(root, repoName string, schemaVersion int) error {
	if err := validateLegacyRepositoryPrivateLayout(root, repoName); err != nil {
		return err
	}
	if schemaVersion != 6 {
		if err := validateCurrentRepositoryPrivateLayout(root, repoName); err != nil {
			return err
		}
	}
	return validateRepositoryPublicLayout(root, repoName)
}

func validateRepositoryPrivateLayout(root, repoName string) error {
	return validateCurrentRepositoryPrivateLayout(root, repoName)
}

func validateRepositoryLayout(root, repoName string) error {
	if err := validateRepositoryPrivateLayout(root, repoName); err != nil {
		return err
	}
	return validateRepositoryPublicLayout(root, repoName)
}

func removeOwnedDirectory(path, parent string) error {
	rel, err := relativeToRoot(parent, path)
	if err != nil {
		return fmt.Errorf("%w: removal path escapes owner", ErrIntegrity)
	}
	components, err := rootedPathComponents(rel, false)
	if err != nil {
		return fmt.Errorf("%w: removal path escapes owner", ErrIntegrity)
	}
	parentChain, err := openRootedDirectoryChain(parent, filepath.Join(components[:len(components)-1]...), false, 0o700)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	finish := func(result error) error { return errors.Join(result, parentChain.close(true)) }
	name := components[len(components)-1]
	fd, err := unix.Openat(int(parentChain.directory().Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if errors.Is(err, unix.ENOENT) {
		return finish(nil)
	}
	if err != nil {
		return finish(fmt.Errorf("%w: removal path is missing or unsafe: %v", ErrIntegrity, err))
	}
	directory := os.NewFile(uintptr(fd), name)
	closeDirectory := func(result error) error { return finish(errors.Join(result, directory.Close())) }
	var openedRaw, entryRaw unix.Stat_t
	statErr := unix.Fstat(fd, &openedRaw)
	entryErr := unix.Fstatat(int(parentChain.directory().Fd()), name, &entryRaw, unix.AT_SYMLINK_NOFOLLOW)
	if statErr != nil || entryErr != nil || uint32(openedRaw.Mode)&unix.S_IFMT != unix.S_IFDIR ||
		openedRaw.Dev != entryRaw.Dev || openedRaw.Ino != entryRaw.Ino || openedRaw.Dev != parentChain.binding.stat.Dev {
		return closeDirectory(errors.Join(fmt.Errorf("%w: removal directory changed while opening", ErrIntegrity), statErr, entryErr))
	}
	if err := emptyRootedDirectory(directory, uint64(openedRaw.Dev)); err != nil {
		return closeDirectory(err)
	}
	if err := parentChain.verify(); err != nil {
		return closeDirectory(err)
	}
	var beforeRemove unix.Stat_t
	entryErr = unix.Fstatat(int(parentChain.directory().Fd()), name, &beforeRemove, unix.AT_SYMLINK_NOFOLLOW)
	if entryErr != nil || beforeRemove.Dev != openedRaw.Dev || beforeRemove.Ino != openedRaw.Ino || uint32(beforeRemove.Mode)&unix.S_IFMT != unix.S_IFDIR {
		return closeDirectory(errors.Join(fmt.Errorf("%w: removal directory changed before unlink", ErrIntegrity), entryErr))
	}
	if err := unix.Unlinkat(int(parentChain.directory().Fd()), name, unix.AT_REMOVEDIR); err != nil {
		return closeDirectory(err)
	}
	var after unix.Stat_t
	afterErr := unix.Fstatat(int(parentChain.directory().Fd()), name, &after, unix.AT_SYMLINK_NOFOLLOW)
	if !errors.Is(afterErr, unix.ENOENT) {
		return closeDirectory(errors.Join(fmt.Errorf("%w: removal directory remains after unlink", ErrIntegrity), afterErr))
	}
	return closeDirectory(parentChain.directory().Sync())
}

// removeRootedEmptyDirectoryTree removes only directories beneath relative.
// Any regular file, symlink, device, or other unknown entry fails closed; the
// caller must unlink every journal-owned file separately before pruning.
func removeRootedEmptyDirectoryTree(root, relative string) error {
	components, err := rootedPathComponents(relative, false)
	if err != nil {
		return err
	}
	parent, err := openRootedDirectoryChain(root, filepath.Join(components[:len(components)-1]...), false, 0)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	finish := func(result error) error { return errors.Join(result, parent.close(true)) }
	name := components[len(components)-1]
	fd, err := unix.Openat(int(parent.directory().Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if errors.Is(err, unix.ENOENT) {
		return finish(nil)
	}
	if err != nil {
		return finish(err)
	}
	directory := os.NewFile(uintptr(fd), name)
	closeDirectory := func(result error) error { return finish(errors.Join(result, directory.Close())) }
	var opened, entry unix.Stat_t
	statErr := unix.Fstat(fd, &opened)
	entryErr := unix.Fstatat(int(parent.directory().Fd()), name, &entry, unix.AT_SYMLINK_NOFOLLOW)
	if statErr != nil || entryErr != nil || opened.Dev != entry.Dev || opened.Ino != entry.Ino || uint32(opened.Mode)&unix.S_IFMT != unix.S_IFDIR {
		return closeDirectory(errors.Join(errors.New("managed: empty-only prune root changed while opening"), statErr, entryErr))
	}
	if err := pruneRootedDirectoriesOnly(directory, uint64(opened.Dev)); err != nil {
		return closeDirectory(err)
	}
	if err := parent.verify(); err != nil {
		return closeDirectory(err)
	}
	var before unix.Stat_t
	entryErr = unix.Fstatat(int(parent.directory().Fd()), name, &before, unix.AT_SYMLINK_NOFOLLOW)
	if entryErr != nil || before.Dev != opened.Dev || before.Ino != opened.Ino || uint32(before.Mode)&unix.S_IFMT != unix.S_IFDIR {
		return closeDirectory(errors.Join(errors.New("managed: empty-only prune root changed before removal"), entryErr))
	}
	if err := unix.Unlinkat(int(parent.directory().Fd()), name, unix.AT_REMOVEDIR); err != nil {
		return closeDirectory(err)
	}
	return closeDirectory(parent.directory().Sync())
}

func pruneRootedDirectoriesOnly(directory *os.File, ownerDevice uint64) error {
	if directory == nil {
		return errors.New("managed: invalid empty-only prune directory")
	}
	names, err := directory.Readdirnames(-1)
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, `/\`) {
			return fmt.Errorf("%w: unsafe empty-only prune entry", ErrIntegrity)
		}
		var entry unix.Stat_t
		if err := unix.Fstatat(int(directory.Fd()), name, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if uint32(entry.Mode)&unix.S_IFMT != unix.S_IFDIR || uint64(entry.Dev) != ownerDevice {
			return fmt.Errorf("%w: empty-only prune found unknown entry %q", ErrIntegrity, name)
		}
		fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		if err != nil {
			return err
		}
		child := os.NewFile(uintptr(fd), name)
		var opened unix.Stat_t
		if err := unix.Fstat(fd, &opened); err != nil || opened.Dev != entry.Dev || opened.Ino != entry.Ino || uint32(opened.Mode)&unix.S_IFMT != unix.S_IFDIR {
			return errors.Join(errors.New("managed: empty-only prune child changed while opening"), err, child.Close())
		}
		if err := pruneRootedDirectoriesOnly(child, ownerDevice); err != nil {
			return errors.Join(err, child.Close())
		}
		var before unix.Stat_t
		entryErr := unix.Fstatat(int(directory.Fd()), name, &before, unix.AT_SYMLINK_NOFOLLOW)
		if entryErr != nil || before.Dev != opened.Dev || before.Ino != opened.Ino || uint32(before.Mode)&unix.S_IFMT != unix.S_IFDIR {
			return errors.Join(errors.New("managed: empty-only prune child changed before removal"), entryErr, child.Close())
		}
		if err := unix.Unlinkat(int(directory.Fd()), name, unix.AT_REMOVEDIR); err != nil {
			return errors.Join(err, child.Close())
		}
		if err := child.Close(); err != nil {
			return err
		}
	}
	return directory.Sync()
}

func emptyRootedDirectory(directory *os.File, ownerDevice uint64) error {
	if directory == nil {
		return errors.New("managed: invalid rooted removal directory")
	}
	for {
		names, readErr := directory.Readdirnames(128)
		for _, name := range names {
			if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, `/\`) {
				return fmt.Errorf("%w: unsafe entry in removal directory", ErrIntegrity)
			}
			var entry unix.Stat_t
			if err := unix.Fstatat(int(directory.Fd()), name, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return err
			}
			if uint32(entry.Mode)&unix.S_IFMT == unix.S_IFDIR {
				if uint64(entry.Dev) != ownerDevice {
					return fmt.Errorf("%w: removal directory crosses a filesystem boundary", ErrIntegrity)
				}
				fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
				if err != nil {
					return err
				}
				child := os.NewFile(uintptr(fd), name)
				var opened unix.Stat_t
				statErr := unix.Fstat(fd, &opened)
				if statErr != nil || opened.Dev != entry.Dev || opened.Ino != entry.Ino || uint32(opened.Mode)&unix.S_IFMT != unix.S_IFDIR {
					return errors.Join(fmt.Errorf("%w: removal child changed while opening", ErrIntegrity), statErr, child.Close())
				}
				if err := emptyRootedDirectory(child, ownerDevice); err != nil {
					return errors.Join(err, child.Close())
				}
				var beforeRemove unix.Stat_t
				entryErr := unix.Fstatat(int(directory.Fd()), name, &beforeRemove, unix.AT_SYMLINK_NOFOLLOW)
				if entryErr != nil || beforeRemove.Dev != opened.Dev || beforeRemove.Ino != opened.Ino || uint32(beforeRemove.Mode)&unix.S_IFMT != unix.S_IFDIR {
					return errors.Join(fmt.Errorf("%w: removal child changed before unlink", ErrIntegrity), entryErr, child.Close())
				}
				if err := unix.Unlinkat(int(directory.Fd()), name, unix.AT_REMOVEDIR); err != nil {
					return errors.Join(err, child.Close())
				}
				if err := child.Close(); err != nil {
					return err
				}
			} else {
				if err := unix.Unlinkat(int(directory.Fd()), name, 0); err != nil {
					return err
				}
			}
		}
		if errors.Is(readErr, io.EOF) {
			return directory.Sync()
		}
		if readErr != nil {
			return readErr
		}
	}
}
