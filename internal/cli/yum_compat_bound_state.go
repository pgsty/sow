package cli

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pgsty/sow/internal/state"
)

// yumCompatibilityCanonicalWorkspace keeps every path-oriented state/Git/SQL
// operation away from the live repository namespace. The authoritative .sow
// state is copied through the already-open state root, changed in a private
// 0700 workspace, and installed through a parent-FD atomic directory exchange.
// A repository-root rename therefore cannot redirect a canonical write into a
// replacement tree even though go-git itself is path based.
type yumCompatibilityCanonicalWorkspace struct {
	root     string
	stateDir string
	store    *state.Store
	baseline map[string]yumCompatibilityTreeIdentity
}

type yumCompatibilityTreeIdentity struct {
	Exists bool
	SHA256 string
}

var yumCompatibilityCanonicalDirectories = []string{"state", "journal", "transactions", "cache"}

func newYUMCompatibilityCanonicalWorkspace(workflow yumCompatibilityWorkflow) (*yumCompatibilityCanonicalWorkspace, error) {
	if workflow.root == nil || workflow.root.stateRoot == nil {
		return nil, errors.New("bound YUM compatibility state root is unavailable")
	}
	temporary, err := os.MkdirTemp("", "sow-yum-canonical-")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(temporary, 0o700); err != nil {
		_ = os.RemoveAll(temporary)
		return nil, err
	}
	workspace := &yumCompatibilityCanonicalWorkspace{
		root: temporary, stateDir: filepath.Join(temporary, ".sow"),
		baseline: make(map[string]yumCompatibilityTreeIdentity, len(yumCompatibilityCanonicalDirectories)),
	}
	if err := os.Mkdir(workspace.stateDir, 0o700); err != nil {
		_ = workspace.Close()
		return nil, err
	}
	for _, name := range yumCompatibilityCanonicalDirectories {
		identity, err := fingerprintYUMCompatibilityBoundTree(workflow.root.stateRoot, name)
		if err != nil {
			_ = workspace.Close()
			return nil, fmt.Errorf("snapshot canonical %s identity: %w", name, err)
		}
		workspace.baseline[name] = identity
		if !identity.Exists {
			continue
		}
		if err := copyYUMCompatibilityBoundTreeToLocal(workflow.root.stateRoot, name, filepath.Join(workspace.stateDir, name)); err != nil {
			_ = workspace.Close()
			return nil, fmt.Errorf("snapshot canonical %s tree: %w", name, err)
		}
		copied, err := fingerprintYUMCompatibilityLocalTree(filepath.Join(workspace.stateDir, name))
		if err != nil || copied != identity {
			_ = workspace.Close()
			return nil, errors.Join(err, fmt.Errorf("canonical %s tree changed while taking its bound snapshot", name))
		}
	}
	workspace.store = state.New(workspace.stateDir)
	return workspace, nil
}

func (workspace *yumCompatibilityCanonicalWorkspace) Close() error {
	if workspace == nil || workspace.root == "" {
		return nil
	}
	err := os.RemoveAll(workspace.root)
	workspace.root, workspace.stateDir, workspace.store = "", "", nil
	return err
}

func (workspace *yumCompatibilityCanonicalWorkspace) Store() *state.Store {
	if workspace == nil {
		return nil
	}
	return workspace.store
}

func (workspace *yumCompatibilityCanonicalWorkspace) NewTransactionDir(prefix string) (string, error) {
	if workspace == nil || workspace.stateDir == "" {
		return "", errors.New("canonical workspace is unavailable")
	}
	return newTransactionDir(workspace.stateDir, prefix)
}

func (workspace *yumCompatibilityCanonicalWorkspace) RemoveTransaction(transaction string) error {
	if workspace == nil || transaction == "" {
		return nil
	}
	parent := filepath.Join(workspace.stateDir, "transactions")
	relative, err := filepath.Rel(parent, filepath.Clean(transaction))
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return errors.Join(err, errors.New("refuse to remove a transaction outside the bound canonical workspace"))
	}
	return os.RemoveAll(transaction)
}

// Commit installs only directories whose byte/mode tree changed in the private
// workspace. "state" is exchanged first because it is the authority; journal,
// transaction-marker, and cache directories are recovery/disposable followers.
// If a follower install fails after the authority exchange, the old journal or
// marker remains a safe signal for the next --recover rather than rolling an
// already-durable Git commit backward.
func (workspace *yumCompatibilityCanonicalWorkspace) Commit(workflow yumCompatibilityWorkflow, phase string) (bool, error) {
	if workspace == nil || workspace.store == nil || workflow.root == nil || workflow.root.stateRoot == nil || workflow.root.stateFile == nil {
		return false, errors.New("bound canonical commit capability is unavailable")
	}
	type change struct {
		name    string
		desired yumCompatibilityTreeIdentity
	}
	changes := make([]change, 0, len(yumCompatibilityCanonicalDirectories))
	for _, name := range yumCompatibilityCanonicalDirectories {
		desired, err := fingerprintYUMCompatibilityLocalTree(filepath.Join(workspace.stateDir, name))
		if err != nil {
			return false, fmt.Errorf("fingerprint staged canonical %s: %w", name, err)
		}
		if desired != workspace.baseline[name] {
			changes = append(changes, change{name: name, desired: desired})
		}
	}
	if len(changes) == 0 {
		return false, nil
	}
	if err := requireYUMCompatibilityMutationBoundary(workflow, "admit "+phase+" bound canonical commit"); err != nil {
		return false, err
	}
	if workflow.mutationHook != nil {
		if err := workflow.mutationHook(phase); err != nil {
			return false, fmt.Errorf("YUM compatibility canonical mutation hook %s: %w", phase, err)
		}
	}
	for _, item := range changes {
		current, err := fingerprintYUMCompatibilityBoundTree(workflow.root.stateRoot, item.name)
		if err != nil {
			return false, fmt.Errorf("recheck bound canonical %s before install: %w", item.name, err)
		}
		if current != workspace.baseline[item.name] {
			return false, fmt.Errorf("bound canonical %s changed after its private snapshot", item.name)
		}
		if err := installYUMCompatibilityCanonicalDirectory(workflow.root, workspace.stateDir, item.name, workspace.baseline[item.name], item.desired); err != nil {
			return false, fmt.Errorf("install bound canonical %s: %w", item.name, err)
		}
		workspace.baseline[item.name] = item.desired
	}
	if err := requireYUMCompatibilityMutationBoundary(workflow, "finish "+phase+" bound canonical commit"); err != nil {
		return true, err
	}
	return true, nil
}

func installYUMCompatibilityCanonicalDirectory(binding *yumCompatibilityRepositoryBinding, localStateDir, name string, expected, desired yumCompatibilityTreeIdentity) (resultErr error) {
	if binding == nil || binding.stateRoot == nil || binding.stateFile == nil || !validYUMCompatibilityTreeSegment(name) {
		return errors.New("invalid bound canonical directory install")
	}
	nonce, err := randomYUMCompatibilityBoundNonce()
	if err != nil {
		return err
	}
	stage := ".yum-canonical-install-" + nonce
	if err := binding.stateRoot.Mkdir(stage, 0o700); err != nil {
		return err
	}
	stageInfo, err := binding.stateRoot.Lstat(stage)
	if err != nil || stageInfo.Mode()&os.ModeSymlink != 0 || !stageInfo.IsDir() {
		return errors.Join(err, errors.New("bound canonical stage is not a real directory"))
	}
	stageRoot, err := binding.stateRoot.OpenRoot(stage)
	if err != nil {
		return err
	}
	openedStage, err := stageRoot.Stat(".")
	if err != nil || !os.SameFile(stageInfo, openedStage) {
		_ = stageRoot.Close()
		return errors.Join(err, errors.New("bound canonical stage changed while opening"))
	}
	defer func() {
		resultErr = errors.Join(resultErr, removeExactYUMCompatibilityBoundDirectory(binding.stateRoot, stage, stageInfo), stageRoot.Close())
	}()
	staged := filepath.Join(stage, name)
	if desired.Exists {
		if err := copyYUMCompatibilityLocalTreeToBound(filepath.Join(localStateDir, name), stageRoot, name); err != nil {
			return err
		}
		observed, err := fingerprintYUMCompatibilityBoundTree(stageRoot, name)
		if err != nil || observed != desired {
			return errors.Join(err, errors.New("staged bound canonical tree differs before atomic install"))
		}
	}
	if err := verifyExactYUMCompatibilityBoundDirectory(binding.stateRoot, stage, stageRoot, stageInfo); err != nil {
		return err
	}
	current, err := binding.stateRoot.Lstat(name)
	currentExists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if currentExists && (current.Mode()&os.ModeSymlink != 0 || !current.IsDir()) {
		return errors.New("canonical directory destination is not a real directory")
	}
	switch {
	case desired.Exists && currentExists:
		if err := exchangeYUMCompatibilityDirectories(binding.stateFile.Fd(), staged, name); err != nil {
			return err
		}
		captured, captureErr := fingerprintYUMCompatibilityBoundTree(stageRoot, name)
		if captureErr != nil || captured != expected {
			rollbackErr := exchangeYUMCompatibilityDirectories(binding.stateFile.Fd(), staged, name)
			return errors.Join(captureErr, rollbackErr, errors.New("canonical directory changed before its parent-bound atomic exchange"))
		}
	case desired.Exists:
		if err := renameYUMCompatibilityCandidateNoReplace(binding.stateFile.Fd(), staged, name); err != nil {
			return err
		}
	case currentExists:
		if err := renameYUMCompatibilityCandidateNoReplace(binding.stateFile.Fd(), name, staged); err != nil {
			return err
		}
		captured, captureErr := fingerprintYUMCompatibilityBoundTree(stageRoot, name)
		if captureErr != nil || captured != expected {
			rollbackErr := renameYUMCompatibilityCandidateNoReplace(binding.stateFile.Fd(), staged, name)
			return errors.Join(captureErr, rollbackErr, errors.New("canonical directory changed before its parent-bound removal"))
		}
	default:
		// Both sides are absent; this can only arise from an idempotent replay.
	}
	if err := syncYUMCompatibilityRootDirectory(binding.stateRoot); err != nil {
		return err
	}
	installed, err := fingerprintYUMCompatibilityBoundTree(binding.stateRoot, name)
	if err != nil || installed != desired {
		return errors.Join(err, errors.New("bound canonical tree differs after atomic install"))
	}
	return nil
}

func verifyExactYUMCompatibilityBoundDirectory(parent *os.Root, name string, root *os.Root, expected os.FileInfo) error {
	if parent == nil || root == nil || expected == nil || !validYUMCompatibilityTreeSegment(name) {
		return errors.New("exact bound canonical directory capability is unavailable")
	}
	throughParent, parentErr := parent.Lstat(name)
	throughRoot, rootErr := root.Stat(".")
	if parentErr != nil || rootErr != nil || throughParent.Mode()&os.ModeSymlink != 0 || !throughParent.IsDir() ||
		!os.SameFile(expected, throughParent) || !os.SameFile(expected, throughRoot) {
		return errors.Join(parentErr, rootErr, fmt.Errorf("bound canonical directory %s was replaced", name))
	}
	return nil
}

func emptyYUMCompatibilityBoundDirectory(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		name := entry.Name()
		if !validYUMCompatibilityTreeSegment(name) {
			return errors.New("unsafe bound canonical cleanup entry")
		}
		info, err := root.Lstat(name)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.Join(err, fmt.Errorf("unsafe bound canonical cleanup entry %s", name))
		}
		if info.IsDir() {
			child, err := root.OpenRoot(name)
			if err != nil {
				return err
			}
			opened, err := child.Stat(".")
			if err != nil || !os.SameFile(info, opened) {
				_ = child.Close()
				return errors.Join(err, fmt.Errorf("bound canonical cleanup directory %s changed while opening", name))
			}
			if err := emptyYUMCompatibilityBoundDirectory(child); err != nil {
				_ = child.Close()
				return err
			}
			current, currentErr := root.Lstat(name)
			closeErr := child.Close()
			if currentErr != nil || closeErr != nil || !os.SameFile(info, current) {
				return errors.Join(currentErr, closeErr, fmt.Errorf("bound canonical cleanup directory %s was replaced", name))
			}
		} else {
			if !info.Mode().IsRegular() {
				return fmt.Errorf("special bound canonical cleanup entry %s is forbidden", name)
			}
			file, err := root.Open(name)
			if err != nil {
				return err
			}
			opened, statErr := file.Stat()
			closeErr := file.Close()
			current, currentErr := root.Lstat(name)
			if statErr != nil || closeErr != nil || currentErr != nil || !os.SameFile(info, opened) || !os.SameFile(info, current) {
				return errors.Join(statErr, closeErr, currentErr, fmt.Errorf("bound canonical cleanup file %s was replaced", name))
			}
		}
		if err := root.Remove(name); err != nil {
			return err
		}
	}
	return syncYUMCompatibilityRootDirectory(root)
}

func removeExactYUMCompatibilityBoundDirectory(parent *os.Root, name string, expected os.FileInfo) error {
	if parent == nil || expected == nil || !validYUMCompatibilityTreeSegment(name) {
		return errors.New("exact bound canonical cleanup capability is unavailable")
	}
	info, err := parent.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || !os.SameFile(expected, info) {
		return errors.Join(err, fmt.Errorf("bound canonical cleanup directory %s was replaced", name))
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := verifyExactYUMCompatibilityBoundDirectory(parent, name, root, expected); err != nil {
		return err
	}
	if err := emptyYUMCompatibilityBoundDirectory(root); err != nil {
		return err
	}
	if err := verifyExactYUMCompatibilityBoundDirectory(parent, name, root, expected); err != nil {
		return err
	}
	if err := parent.Remove(name); err != nil {
		return err
	}
	return syncYUMCompatibilityRootDirectory(parent)
}

func randomYUMCompatibilityBoundNonce() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func validYUMCompatibilityTreeSegment(value string) bool {
	return value != "" && value != "." && value != ".." && filepath.Base(value) == value && !strings.ContainsAny(value, "/\\\x00\t\r\n")
}

func fingerprintYUMCompatibilityLocalTree(root string) (yumCompatibilityTreeIdentity, error) {
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return yumCompatibilityTreeIdentity{}, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return yumCompatibilityTreeIdentity{}, errors.Join(err, errors.New("local canonical tree is not a real directory"))
	}
	hasher := sha256.New()
	err = filepath.WalkDir(root, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink %s is forbidden in canonical state", relative)
		}
		if info.IsDir() {
			_, _ = fmt.Fprintf(hasher, "D\x00%s\x00%04o\n", relative, info.Mode().Perm())
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("special file %s is forbidden in canonical state", relative)
		}
		file, err := os.Open(filename)
		if err != nil {
			return err
		}
		opened, statErr := file.Stat()
		if statErr != nil || !os.SameFile(info, opened) {
			return errors.Join(statErr, file.Close(), fmt.Errorf("canonical file %s changed while hashing", relative))
		}
		fileHash := sha256.New()
		size, copyErr := io.Copy(fileHash, file)
		after, restatErr := file.Stat()
		closeErr := file.Close()
		if copyErr != nil || restatErr != nil || closeErr != nil || !os.SameFile(opened, after) || size != info.Size() {
			return errors.Join(copyErr, restatErr, closeErr, fmt.Errorf("canonical file %s changed while hashing", relative))
		}
		_, _ = fmt.Fprintf(hasher, "F\x00%s\x00%04o\x00%d\x00%x\n", relative, info.Mode().Perm(), size, fileHash.Sum(nil))
		return nil
	})
	if err != nil {
		return yumCompatibilityTreeIdentity{}, err
	}
	return yumCompatibilityTreeIdentity{Exists: true, SHA256: hex.EncodeToString(hasher.Sum(nil))}, nil
}

func fingerprintYUMCompatibilityBoundTree(parent *os.Root, relative string) (yumCompatibilityTreeIdentity, error) {
	info, err := parent.Lstat(relative)
	if errors.Is(err, os.ErrNotExist) {
		return yumCompatibilityTreeIdentity{}, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return yumCompatibilityTreeIdentity{}, errors.Join(err, fmt.Errorf("bound canonical tree %s is not a real directory", relative))
	}
	root, err := parent.OpenRoot(relative)
	if err != nil {
		return yumCompatibilityTreeIdentity{}, err
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		return yumCompatibilityTreeIdentity{}, errors.Join(err, errors.New("bound canonical tree changed while opening"))
	}
	hasher := sha256.New()
	if err := hashYUMCompatibilityBoundDirectory(root, ".", hasher); err != nil {
		return yumCompatibilityTreeIdentity{}, err
	}
	return yumCompatibilityTreeIdentity{Exists: true, SHA256: hex.EncodeToString(hasher.Sum(nil))}, nil
}

func hashYUMCompatibilityBoundDirectory(root *os.Root, relative string, destination io.Writer) error {
	info, err := root.Lstat(relative)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.Join(err, fmt.Errorf("bound canonical directory %s changed", relative))
	}
	_, _ = fmt.Fprintf(destination, "D\x00%s\x00%04o\n", filepath.ToSlash(relative), info.Mode().Perm())
	directory, err := root.Open(relative)
	if err != nil {
		return err
	}
	opened, statErr := directory.Stat()
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if statErr != nil || readErr != nil || closeErr != nil || !os.SameFile(info, opened) {
		return errors.Join(statErr, readErr, closeErr, fmt.Errorf("bound canonical directory %s changed while reading", relative))
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		name := filepath.Join(relative, entry.Name())
		child, err := root.Lstat(name)
		if err != nil || child.Mode()&os.ModeSymlink != 0 {
			return errors.Join(err, fmt.Errorf("unsafe canonical entry %s", name))
		}
		if child.IsDir() {
			if err := hashYUMCompatibilityBoundDirectory(root, name, destination); err != nil {
				return err
			}
			continue
		}
		if !child.Mode().IsRegular() {
			return fmt.Errorf("special canonical entry %s is forbidden", name)
		}
		file, err := root.Open(name)
		if err != nil {
			return err
		}
		opened, statErr := file.Stat()
		if statErr != nil || !os.SameFile(child, opened) {
			return errors.Join(statErr, file.Close(), fmt.Errorf("canonical entry %s changed while opening", name))
		}
		fileHash := sha256.New()
		size, copyErr := io.Copy(fileHash, file)
		after, restatErr := file.Stat()
		closeErr := file.Close()
		if copyErr != nil || restatErr != nil || closeErr != nil || !os.SameFile(opened, after) || size != child.Size() {
			return errors.Join(copyErr, restatErr, closeErr, fmt.Errorf("canonical entry %s changed while hashing", name))
		}
		_, _ = fmt.Fprintf(destination, "F\x00%s\x00%04o\x00%d\x00%x\n", filepath.ToSlash(name), child.Mode().Perm(), size, fileHash.Sum(nil))
	}
	return nil
}

func copyYUMCompatibilityBoundTreeToLocal(parent *os.Root, relative, destination string) error {
	source, identity, err := openRealYUMCompatibilityDirectory(parent, relative, false)
	if err != nil {
		return err
	}
	defer source.Close()
	if err := os.Mkdir(destination, identity.Mode().Perm()); err != nil {
		return err
	}
	return copyYUMCompatibilityBoundDirectoryToLocal(source, ".", destination)
}

func copyYUMCompatibilityBoundDirectoryToLocal(root *os.Root, relative, destination string) error {
	directory, err := root.Open(relative)
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		name := filepath.Join(relative, entry.Name())
		info, err := root.Lstat(name)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.Join(err, fmt.Errorf("unsafe canonical snapshot entry %s", name))
		}
		local := filepath.Join(destination, entry.Name())
		if info.IsDir() {
			if err := os.Mkdir(local, info.Mode().Perm()); err != nil {
				return err
			}
			if err := copyYUMCompatibilityBoundDirectoryToLocal(root, name, local); err != nil {
				return err
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("special canonical snapshot entry %s is forbidden", name)
		}
		source, err := root.Open(name)
		if err != nil {
			return err
		}
		opened, statErr := source.Stat()
		if statErr != nil || !os.SameFile(info, opened) {
			return errors.Join(statErr, source.Close(), fmt.Errorf("canonical snapshot entry %s changed while opening", name))
		}
		destinationFile, err := os.OpenFile(local, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
		if err != nil {
			_ = source.Close()
			return err
		}
		_, copyErr := io.Copy(destinationFile, source)
		syncErr := destinationFile.Sync()
		closeDestinationErr := destinationFile.Close()
		after, restatErr := source.Stat()
		closeSourceErr := source.Close()
		if copyErr != nil || syncErr != nil || closeDestinationErr != nil || restatErr != nil || closeSourceErr != nil || !os.SameFile(opened, after) {
			return errors.Join(copyErr, syncErr, closeDestinationErr, restatErr, closeSourceErr, fmt.Errorf("canonical snapshot entry %s changed while copying", name))
		}
	}
	return syncLocalDirectory(destination)
}

func copyYUMCompatibilityLocalTreeToBound(source string, root *os.Root, destination string) error {
	info, err := os.Lstat(source)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.Join(err, errors.New("staged canonical source is not a real directory"))
	}
	if err := root.Mkdir(destination, info.Mode().Perm()); err != nil {
		return err
	}
	err = filepath.WalkDir(source, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, filename)
		if err != nil || relative == "." {
			return err
		}
		info, err := entry.Info()
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.Join(err, fmt.Errorf("unsafe staged canonical entry %s", relative))
		}
		target := filepath.Join(destination, relative)
		if info.IsDir() {
			return root.Mkdir(target, info.Mode().Perm())
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("special staged canonical entry %s is forbidden", relative)
		}
		sourceFile, err := os.Open(filename)
		if err != nil {
			return err
		}
		opened, statErr := sourceFile.Stat()
		if statErr != nil || !os.SameFile(info, opened) {
			return errors.Join(statErr, sourceFile.Close(), fmt.Errorf("staged canonical entry %s changed while opening", relative))
		}
		destinationFile, err := root.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
		if err != nil {
			_ = sourceFile.Close()
			return err
		}
		_, copyErr := io.Copy(destinationFile, sourceFile)
		syncErr := destinationFile.Sync()
		closeDestinationErr := destinationFile.Close()
		after, restatErr := sourceFile.Stat()
		closeSourceErr := sourceFile.Close()
		if copyErr != nil || syncErr != nil || closeDestinationErr != nil || restatErr != nil || closeSourceErr != nil || !os.SameFile(opened, after) {
			return errors.Join(copyErr, syncErr, closeDestinationErr, restatErr, closeSourceErr, fmt.Errorf("staged canonical entry %s changed while copying", relative))
		}
		return nil
	})
	if err != nil {
		return err
	}
	return syncYUMCompatibilityBoundTree(root, destination)
}

func syncYUMCompatibilityBoundTree(root *os.Root, relative string) error {
	directory, err := root.Open(relative)
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(-1)
	if readErr != nil {
		_ = directory.Close()
		return readErr
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		name := filepath.Join(relative, entry.Name())
		info, err := root.Lstat(name)
		if err != nil {
			_ = directory.Close()
			return err
		}
		if info.IsDir() {
			if err := syncYUMCompatibilityBoundTree(root, name); err != nil {
				_ = directory.Close()
				return err
			}
		}
	}
	return errors.Join(directory.Sync(), directory.Close())
}
