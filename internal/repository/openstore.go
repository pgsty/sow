package repository

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

type readOnlyStoreTestPoint uint8

const (
	readOnlyStoreTestAfterShardOpen readOnlyStoreTestPoint = iota + 1
	readOnlyStoreTestAfterObjectOpen
)

type readOnlyStoreTestHook func(readOnlyStoreTestPoint, string) error

// openReadOnlyStore binds the configured root once. The root's parent is also
// retained so a persistent public-coordinate replacement can be rejected
// without using the replacement as read authority. If A is temporarily
// replaced by B and restored before an operation (A -> B -> A), the operation
// deliberately continues through retained A; B is never traversed for object
// bytes and receives no writes.
func openReadOnlyStore(root string) (_ *Store, resultErr error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve repository root %q: %w", root, err)
	}
	entry, err := os.Lstat(absRoot)
	if err != nil || entry.Mode()&os.ModeSymlink != 0 || !entry.IsDir() {
		return nil, errors.Join(err, fmt.Errorf("%w: repository root %q is absent, symlinked, or not a directory", ErrUnsafePath, root))
	}
	parentPath, err := filepath.EvalSymlinks(filepath.Dir(absRoot))
	if err != nil {
		return nil, fmt.Errorf("resolve repository parent %q: %w", root, err)
	}
	rootName := filepath.Base(absRoot)
	rootParent, err := openStableReadOnlyDirectory(parentPath)
	if err != nil {
		return nil, fmt.Errorf("open existing repository parent: %w", err)
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, rootParent.Close())
		}
	}()
	rootHandle, rootInfo, err := openStableReadOnlyDirectoryAt(rootParent, rootName)
	if err != nil {
		return nil, fmt.Errorf("open existing repository root: %w", err)
	}
	current, currentErr := os.Lstat(absRoot)
	if currentErr != nil || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() || !os.SameFile(entry, rootInfo) || !os.SameFile(entry, current) {
		_ = rootHandle.Close()
		return nil, errors.Join(currentErr, fmt.Errorf("%w: repository root changed during read-only admission", ErrUnsafePath))
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, rootHandle.Close())
		}
	}()
	poolParent, _, err := openStableReadOnlyDirectoryAt(rootHandle, ".pool")
	if err != nil {
		return nil, fmt.Errorf("open existing CAS parent: %w", err)
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, poolParent.Close())
		}
	}()
	pool, _, err := openStableReadOnlyDirectoryAt(poolParent, "sha256")
	if err != nil {
		return nil, fmt.Errorf("open existing CAS root: %w", err)
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, pool.Close())
		}
	}()

	realRoot := filepath.Join(parentPath, rootName)
	store := &Store{
		root: realRoot, poolRoot: filepath.Join(realRoot, ".pool", "sha256"), readOnly: true,
		readRootParent: rootParent, readRootName: rootName, readRoot: rootHandle,
		readPoolParent: poolParent, readPool: pool,
	}
	if !rootInfo.IsDir() {
		return nil, fmt.Errorf("%w: repository root is not a directory", ErrUnsafePath)
	}
	if err := store.verifyReadOnlyPoolBase(); err != nil {
		return nil, err
	}
	return store, nil
}

func openStableReadOnlyDirectory(name string) (*os.File, error) {
	entry, err := os.Lstat(name)
	if err != nil || entry.Mode()&os.ModeSymlink != 0 || !entry.IsDir() {
		return nil, errors.Join(err, fmt.Errorf("%w: %q is absent, symlinked, or not a directory", ErrUnsafePath, name))
	}
	opened, err := openMaterializeDirectory(name)
	if err != nil {
		return nil, errors.Join(err, fmt.Errorf("%w: bind directory %q", ErrUnsafePath, name))
	}
	bound, statErr := opened.Stat()
	current, lstatErr := os.Lstat(name)
	if statErr != nil || lstatErr != nil || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() ||
		!os.SameFile(entry, bound) || !os.SameFile(entry, current) {
		return nil, errors.Join(statErr, lstatErr, opened.Close(), fmt.Errorf("%w: directory %q changed while binding", ErrUnsafePath, name))
	}
	return opened, nil
}

func openStableReadOnlyDirectoryAt(parent *os.File, name string) (*os.File, os.FileInfo, error) {
	if parent == nil || name == "" || name == "." || name == ".." || filepath.IsAbs(name) || filepath.Base(name) != name {
		return nil, nil, fmt.Errorf("%w: invalid bound directory component %q", ErrUnsafePath, name)
	}
	before, err := lstatMaterializeAt(parent, name)
	if err != nil {
		return nil, nil, err
	}
	opened, err := openMaterializeDirectoryAt(parent, name)
	if err != nil {
		return nil, nil, errors.Join(err, fmt.Errorf("%w: component %q is symlinked or not a directory", ErrUnsafePath, name))
	}
	info, statErr := opened.Stat()
	after, lstatErr := lstatMaterializeAt(parent, name)
	openedIdentity, identityErr := fstatMaterialize(opened)
	if statErr != nil || identityErr != nil || lstatErr != nil || !info.IsDir() || before != openedIdentity || before != after {
		return nil, nil, errors.Join(statErr, identityErr, lstatErr, opened.Close(), fmt.Errorf("%w: bound directory component %q changed while opening", ErrUnsafePath, name))
	}
	return opened, info, nil
}

func sameReadOnlyDirectory(expected *os.File, parent *os.File, name string) error {
	if expected == nil || parent == nil {
		return fmt.Errorf("%w: retained read-only directory is closed or absent", ErrUnsafePath)
	}
	want, err := fstatMaterialize(expected)
	if err != nil {
		return errors.Join(err, fmt.Errorf("%w: inspect retained directory %q", ErrUnsafePath, name))
	}
	current, _, err := openStableReadOnlyDirectoryAt(parent, name)
	if err != nil {
		return err
	}
	defer current.Close()
	got, err := fstatMaterialize(current)
	if err != nil || want != got {
		return errors.Join(err, fmt.Errorf("%w: read-only CAS directory component %q was replaced", ErrUnsafePath, name))
	}
	return nil
}

func (s *Store) verifyReadOnlyPoolBase() error {
	if s == nil || !s.readOnly {
		return nil
	}
	if err := sameReadOnlyDirectory(s.readRoot, s.readRootParent, s.readRootName); err != nil {
		return err
	}
	if err := sameReadOnlyDirectory(s.readPoolParent, s.readRoot, ".pool"); err != nil {
		return err
	}
	if err := sameReadOnlyDirectory(s.readPool, s.readPoolParent, "sha256"); err != nil {
		return err
	}
	// .tmp is optional for admission. If present it must still be a real
	// directory, but OpenStore never creates or writes it.
	temp, _, err := openStableReadOnlyDirectoryAt(s.readPool, ".tmp")
	if err == nil {
		return temp.Close()
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return fmt.Errorf("inspect existing CAS temporary directory: %w", err)
}

func (s *Store) openReadOnlyObject(digest Digest) (*os.File, error) {
	if err := s.verifyReadOnlyPoolBase(); err != nil {
		return nil, err
	}
	hash := digest.String()
	shardName := hash[:2]
	shard, shardInfo, err := openStableReadOnlyDirectoryAt(s.readPool, shardName)
	if err != nil {
		return nil, fmt.Errorf("inspect CAS shard: %w", err)
	}
	defer shard.Close()
	if s.readOnlyTestHook != nil {
		if err := s.readOnlyTestHook(readOnlyStoreTestAfterShardOpen, hash); err != nil {
			return nil, err
		}
	}
	file, info, err := openMaterializeRegularAt(shard, hash)
	if err != nil {
		return nil, errors.Join(err, fmt.Errorf("%w: open CAS object %s", ErrUnsafePath, digest))
	}
	fail := func(err error) (*os.File, error) {
		return nil, errors.Join(err, file.Close())
	}
	if s.readOnlyTestHook != nil {
		if err := s.readOnlyTestHook(readOnlyStoreTestAfterObjectOpen, hash); err != nil {
			return fail(err)
		}
	}
	if err := s.verifyReadOnlyPoolBase(); err != nil {
		return fail(err)
	}
	currentShard, currentShardInfo, err := openStableReadOnlyDirectoryAt(s.readPool, shardName)
	if err != nil {
		return fail(fmt.Errorf("%w: CAS shard coordinate changed: %v", ErrUnsafePath, err))
	}
	defer currentShard.Close()
	if !os.SameFile(shardInfo, currentShardInfo) {
		return fail(fmt.Errorf("%w: CAS shard coordinate %q was replaced", ErrUnsafePath, shardName))
	}
	coordinate, coordinateInfo, err := openMaterializeRegularAt(currentShard, hash)
	if err != nil {
		return fail(fmt.Errorf("%w: CAS object coordinate %s changed: %v", ErrUnsafePath, hash, err))
	}
	closeErr := coordinate.Close()
	if closeErr != nil || !os.SameFile(info, coordinateInfo) {
		return fail(errors.Join(closeErr, fmt.Errorf("%w: CAS object coordinate %s was replaced", ErrUnsafePath, hash)))
	}
	return file, nil
}

// VerifyRootIdentity proves that expected names the same repository root bound
// by this Store. For OpenStore it compares against the retained root descriptor
// and brackets the comparison with public-coordinate continuity checks. A
// temporary A -> B -> A replacement remains safe and succeeds because the
// retained A descriptor is the authority; a persistent replacement fails.
func (s *Store) VerifyRootIdentity(expected os.FileInfo) error {
	if s == nil || expected == nil || !expected.IsDir() {
		return fmt.Errorf("%w: expected repository root identity is absent or not a directory", ErrUnsafePath)
	}
	if !s.readOnly {
		actual, err := stableRealDirectory(s.root)
		if err != nil || !os.SameFile(expected, actual) {
			return errors.Join(err, fmt.Errorf("%w: repository root differs from expected identity", ErrUnsafePath))
		}
		return nil
	}
	if err := s.verifyReadOnlyPoolBase(); err != nil {
		return err
	}
	if s.readRoot == nil {
		return fmt.Errorf("%w: retained repository root is closed", ErrUnsafePath)
	}
	actual, err := s.readRoot.Stat()
	if err != nil || !actual.IsDir() || !os.SameFile(expected, actual) {
		return errors.Join(err, fmt.Errorf("%w: retained repository root differs from expected identity", ErrUnsafePath))
	}
	return s.verifyReadOnlyPoolBase()
}

// Close releases the capabilities retained by OpenStore. It is idempotent;
// NewStore has no retained read-only descriptors and therefore closes as a
// no-op. Callers must not race Close with another Store operation.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		if !s.readOnly {
			return
		}
		s.closeErr = errors.Join(
			closeReadOnlyHandle(&s.readPool),
			closeReadOnlyHandle(&s.readPoolParent),
			closeReadOnlyHandle(&s.readRoot),
			closeReadOnlyHandle(&s.readRootParent),
		)
	})
	return s.closeErr
}

func closeReadOnlyHandle(handle **os.File) error {
	if handle == nil || *handle == nil {
		return nil
	}
	err := (*handle).Close()
	*handle = nil
	return err
}
