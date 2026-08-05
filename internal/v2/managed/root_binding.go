package managed

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pgsty/sow/internal/v2/config"
	"golang.org/x/sys/unix"
)

type activeWorkspaceRoot struct {
	path   string
	device uint64
	inode  uint64
	refs   int
}

type workspaceRootGuard struct {
	handle     *os.File
	binding    rootedDirectoryBinding
	registered bool
}

var activeWorkspaceRoots = struct {
	sync.Mutex
	byPath map[string]activeWorkspaceRoot
}{byPath: make(map[string]activeWorkspaceRoot)}

func bindDiscoveredWorkspaceRoot(workspace config.Workspace) (*workspaceRootGuard, error) {
	device, inode, ok := workspace.RootIdentity()
	if !ok {
		return nil, fmt.Errorf("%w: discovery returned no workspace root identity", ErrWorkspaceInput)
	}
	return bindWorkspaceRoot(workspace.Root, device, inode)
}

func bindCurrentWorkspaceRoot(root string) (*workspaceRootGuard, error) {
	var raw unix.Stat_t
	if err := unix.Lstat(filepath.Clean(normalizePlatformPhysicalPath(root)), &raw); err != nil || uint32(raw.Mode)&unix.S_IFMT != unix.S_IFDIR {
		return nil, fmt.Errorf("%w: bind workspace root: %v", ErrIntegrity, err)
	}
	return bindWorkspaceRoot(root, uint64(raw.Dev), uint64(raw.Ino))
}

func bindWorkspaceRoot(root string, expectedDevice, expectedInode uint64) (*workspaceRootGuard, error) {
	handle, binding, err := openBoundRootDirectory(root)
	if err != nil {
		return nil, fmt.Errorf("%w: bind workspace root: %v", ErrIntegrity, err)
	}
	if uint64(binding.stat.Dev) != expectedDevice || uint64(binding.stat.Ino) != expectedInode {
		_ = handle.Close()
		return nil, fmt.Errorf("%w: workspace root identity changed after discovery", ErrIntegrity)
	}
	guard := &workspaceRootGuard{handle: handle, binding: binding}
	if err := guard.register(); err != nil {
		_ = handle.Close()
		return nil, err
	}
	return guard, nil
}

func (guard *workspaceRootGuard) register() error {
	if guard == nil || guard.handle == nil || guard.binding.path == "" {
		return fmt.Errorf("%w: invalid workspace root guard", ErrIntegrity)
	}
	entry := activeWorkspaceRoot{
		path: guard.binding.path, device: uint64(guard.binding.stat.Dev), inode: uint64(guard.binding.stat.Ino), refs: 1,
	}
	activeWorkspaceRoots.Lock()
	defer activeWorkspaceRoots.Unlock()
	if current, ok := activeWorkspaceRoots.byPath[entry.path]; ok {
		if current.device != entry.device || current.inode != entry.inode {
			return fmt.Errorf("%w: workspace pathname is already bound to another active identity", ErrIntegrity)
		}
		current.refs++
		activeWorkspaceRoots.byPath[entry.path] = current
	} else {
		activeWorkspaceRoots.byPath[entry.path] = entry
	}
	guard.registered = true
	return nil
}

func (guard *workspaceRootGuard) Verify() error {
	if guard == nil || guard.handle == nil || !guard.registered {
		return fmt.Errorf("%w: workspace root guard is unavailable", ErrIntegrity)
	}
	if err := verifyBoundRootDirectory(guard.handle, guard.binding); err != nil {
		return fmt.Errorf("%w: workspace root identity changed during command: %v", ErrIntegrity, err)
	}
	return nil
}

func (guard *workspaceRootGuard) Close() error {
	if guard == nil {
		return nil
	}
	verifyErr := guard.Verify()
	if guard.registered {
		activeWorkspaceRoots.Lock()
		current, ok := activeWorkspaceRoots.byPath[guard.binding.path]
		if ok && current.device == uint64(guard.binding.stat.Dev) && current.inode == uint64(guard.binding.stat.Ino) {
			current.refs--
			if current.refs == 0 {
				delete(activeWorkspaceRoots.byPath, guard.binding.path)
			} else {
				activeWorkspaceRoots.byPath[guard.binding.path] = current
			}
		}
		activeWorkspaceRoots.Unlock()
		guard.registered = false
	}
	var closeErr error
	if guard.handle != nil {
		closeErr = guard.handle.Close()
		guard.handle = nil
	}
	return errors.Join(verifyErr, closeErr)
}

func activeWorkspaceRootForPath(path string) (activeWorkspaceRoot, bool) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return activeWorkspaceRoot{}, false
	}
	absolute = filepath.Clean(normalizePlatformPhysicalPath(absolute))
	activeWorkspaceRoots.Lock()
	defer activeWorkspaceRoots.Unlock()
	var selected activeWorkspaceRoot
	for candidate, binding := range activeWorkspaceRoots.byPath {
		if absolute != candidate && !strings.HasPrefix(absolute, candidate+string(filepath.Separator)) {
			continue
		}
		if len(candidate) > len(selected.path) {
			selected = binding
		}
	}
	return selected, selected.path != ""
}

func verifyActiveWorkspaceRoot(path string) error {
	binding, ok := activeWorkspaceRootForPath(path)
	if !ok {
		return nil
	}
	var raw unix.Stat_t
	if err := unix.Lstat(binding.path, &raw); err != nil || uint32(raw.Mode)&unix.S_IFMT != unix.S_IFDIR || uint64(raw.Dev) != binding.device || uint64(raw.Ino) != binding.inode {
		return fmt.Errorf("%w: workspace root identity changed during command", ErrIntegrity)
	}
	return nil
}

func verifyAllActiveWorkspaceRoots() error {
	activeWorkspaceRoots.Lock()
	paths := make([]string, 0, len(activeWorkspaceRoots.byPath))
	for path := range activeWorkspaceRoots.byPath {
		paths = append(paths, path)
	}
	activeWorkspaceRoots.Unlock()
	var result error
	for _, path := range paths {
		result = errors.Join(result, verifyActiveWorkspaceRoot(path))
	}
	return result
}
