package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// derivedStateSecurityIdentity records the POSIX-DAC attributes that are not
// represented by os.FileInfo's portable identity. Directory link counts are
// intentionally not compared: adding or removing a child changes them.
type derivedStateSecurityIdentity struct {
	uid   uint32
	gid   uint32
	links uint64
}

var derivedStateControlDirectoryAdmission sync.Mutex

// derivedStateControlBeforeExchangeHook is a deterministic filesystem fault
// seam for tests. Production leaves it nil.
var derivedStateControlBeforeExchangeHook func(source, destination string) error

// derivedStateControlBeforeWriteHook is a deterministic filesystem fault seam
// for create-only YUM control writers. Production leaves it nil.
var derivedStateControlBeforeWriteHook func(kind, name string) error

type derivedStateControlExchangeResult struct {
	Exchanged bool
	Displaced os.FileInfo
}

func admitDerivedStateDirectory(info os.FileInfo, description string) (derivedStateSecurityIdentity, error) {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return derivedStateSecurityIdentity{}, fmt.Errorf("%s is not a real directory", description)
	}
	identity, ok := derivedStateSecurityIdentityFromInfo(info)
	if !ok {
		return derivedStateSecurityIdentity{}, fmt.Errorf("%s lacks a POSIX security identity", description)
	}
	if identity.uid != derivedStateEffectiveUID() {
		return derivedStateSecurityIdentity{}, fmt.Errorf(
			"%s owner uid %d does not match effective uid %d",
			description,
			identity.uid,
			derivedStateEffectiveUID(),
		)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return derivedStateSecurityIdentity{}, fmt.Errorf(
			"%s is group/other writable (mode %#o)",
			description,
			info.Mode().Perm(),
		)
	}
	return identity, nil
}

func admitDerivedStateControlFile(info os.FileInfo, description string) (derivedStateSecurityIdentity, error) {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return derivedStateSecurityIdentity{}, fmt.Errorf("%s is not a regular file", description)
	}
	identity, ok := derivedStateSecurityIdentityFromInfo(info)
	if !ok {
		return derivedStateSecurityIdentity{}, fmt.Errorf("%s lacks a POSIX security identity", description)
	}
	if identity.uid != derivedStateEffectiveUID() {
		return derivedStateSecurityIdentity{}, fmt.Errorf(
			"%s owner uid %d does not match effective uid %d",
			description,
			identity.uid,
			derivedStateEffectiveUID(),
		)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return derivedStateSecurityIdentity{}, fmt.Errorf(
			"%s is group/other writable (mode %#o)",
			description,
			info.Mode().Perm(),
		)
	}
	if identity.links != 1 {
		return derivedStateSecurityIdentity{}, fmt.Errorf(
			"%s has link count %d; expected exactly one",
			description,
			identity.links,
		)
	}
	return identity, nil
}

func sameDerivedStateDirectorySecurity(expected, current os.FileInfo) bool {
	if expected == nil || current == nil {
		return false
	}
	expectedSecurity, expectedOK := derivedStateSecurityIdentityFromInfo(expected)
	currentSecurity, currentOK := derivedStateSecurityIdentityFromInfo(current)
	return expectedOK && currentOK &&
		expectedSecurity.uid == currentSecurity.uid &&
		expectedSecurity.gid == currentSecurity.gid &&
		expected.Mode() == current.Mode()
}

func sameDerivedStateDirectoryAuthority(expected, current os.FileInfo) bool {
	if expected == nil || current == nil {
		return false
	}
	expectedSecurity, expectedOK := derivedStateSecurityIdentityFromInfo(expected)
	currentSecurity, currentOK := derivedStateSecurityIdentityFromInfo(current)
	return expectedOK && currentOK &&
		expectedSecurity.uid == currentSecurity.uid &&
		expectedSecurity.gid == currentSecurity.gid
}

func sameDerivedStateControlFileSecurity(expected, current os.FileInfo) bool {
	return sameDerivedStateControlFileAuthority(expected, current) &&
		expected.Mode() == current.Mode()
}

// sameDerivedStateControlFileAuthority permits an intentional descriptor-bound
// chmod while still proving that ownership and the single-link capability did
// not change. Callers must separately require the exact post-chmod mode.
func sameDerivedStateControlFileAuthority(expected, current os.FileInfo) bool {
	if expected == nil || current == nil {
		return false
	}
	expectedSecurity, expectedErr := admitDerivedStateControlFile(expected, "expected derived state control file")
	currentSecurity, currentErr := admitDerivedStateControlFile(current, "current derived state control file")
	return expectedErr == nil && currentErr == nil &&
		expectedSecurity == currentSecurity
}

func bindDerivedStateControlFile(root *os.Root, name, description string) (*os.File, os.FileInfo, error) {
	if root == nil || filepath.Base(name) != name || name == "" || name == "." {
		return nil, nil, errors.New("derived state control-file binding coordinate is invalid")
	}
	before, err := root.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if _, err := admitDerivedStateControlFile(before, description); err != nil {
		return nil, nil, err
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	opened, statErr := file.Stat()
	current, lstatErr := root.Lstat(name)
	var openedAdmissionErr, currentAdmissionErr error
	if opened != nil {
		_, openedAdmissionErr = admitDerivedStateControlFile(opened, "opened "+description)
	}
	if current != nil {
		_, currentAdmissionErr = admitDerivedStateControlFile(current, "current "+description)
	}
	if statErr != nil || lstatErr != nil || opened == nil || current == nil ||
		openedAdmissionErr != nil || currentAdmissionErr != nil ||
		!os.SameFile(before, opened) || !os.SameFile(before, current) ||
		!sameDerivedStateControlFileSecurity(before, opened) ||
		!sameDerivedStateControlFileSecurity(before, current) {
		closeErr := file.Close()
		return nil, nil, errors.Join(
			statErr,
			lstatErr,
			openedAdmissionErr,
			currentAdmissionErr,
			closeErr,
			fmt.Errorf("%s changed while binding", description),
		)
	}
	return file, opened, nil
}

func verifyBoundDerivedStateControlFile(root *os.Root, name string, file *os.File, identity os.FileInfo, description string) (os.FileInfo, error) {
	if root == nil || file == nil || identity == nil || filepath.Base(name) != name || name == "" || name == "." {
		return nil, errors.New("derived state control-file mutation binding is incomplete")
	}
	opened, statErr := file.Stat()
	current, lstatErr := root.Lstat(name)
	var openedAdmissionErr, currentAdmissionErr error
	if opened != nil {
		_, openedAdmissionErr = admitDerivedStateControlFile(opened, "opened "+description)
	}
	if current != nil {
		_, currentAdmissionErr = admitDerivedStateControlFile(current, "current "+description)
	}
	if statErr != nil || lstatErr != nil || opened == nil || current == nil ||
		openedAdmissionErr != nil || currentAdmissionErr != nil ||
		!os.SameFile(identity, opened) || !os.SameFile(identity, current) ||
		!sameDerivedStateControlFileSecurity(identity, opened) ||
		!sameDerivedStateControlFileSecurity(identity, current) {
		return nil, errors.Join(
			statErr,
			lstatErr,
			openedAdmissionErr,
			currentAdmissionErr,
			fmt.Errorf("%s changed before mutation", description),
		)
	}
	return opened, nil
}

func readBoundDerivedStateControlFile(root *os.Root, name string, file *os.File, identity os.FileInfo, maximum int64, description string) ([]byte, error) {
	if maximum < 0 {
		return nil, errors.New("derived state control-file read limit is invalid")
	}
	if _, err := verifyBoundDerivedStateControlFile(root, name, file, identity, description); err != nil {
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	body, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	after, verifyErr := verifyBoundDerivedStateControlFile(root, name, file, identity, description)
	if readErr != nil || verifyErr != nil || after == nil ||
		int64(len(body)) > maximum || int64(len(body)) != identity.Size() ||
		after.Size() != identity.Size() ||
		!after.ModTime().Equal(identity.ModTime()) {
		return nil, errors.Join(readErr, verifyErr, fmt.Errorf("%s changed while reading", description))
	}
	return body, nil
}

// exchangeBoundDerivedStateControlFiles atomically installs source while
// retaining destination at source. Both names and held descriptors are
// re-admitted immediately before the exchange; no raced-in destination is
// overwritten or deleted. A returned Exchanged result is durable recovery
// authority even when a later verification or directory fsync reports an
// error.
func exchangeBoundDerivedStateControlFiles(
	root *os.Root,
	directory *os.File,
	source string,
	sourceExpected os.FileInfo,
	destination string,
	destinationMaximum int64,
	validateDestination func([]byte) error,
) (result derivedStateControlExchangeResult, resultErr error) {
	if root == nil || directory == nil || sourceExpected == nil ||
		filepath.Base(source) != source || source == "" || source == "." ||
		filepath.Base(destination) != destination || destination == "" || destination == "." ||
		source == destination {
		return result, errors.New("derived state control-file exchange binding is invalid")
	}
	sourceFile, sourceIdentity, err := bindDerivedStateControlFile(root, source, "derived state exchange source")
	if err != nil {
		return result, err
	}
	defer sourceFile.Close()
	if !os.SameFile(sourceExpected, sourceIdentity) ||
		!sameDerivedStateControlFileSecurity(sourceExpected, sourceIdentity) {
		return result, errors.New("derived state exchange source differs from its prepared identity")
	}
	destinationFile, destinationIdentity, err := bindDerivedStateControlFile(root, destination, "derived state exchange destination")
	if err != nil {
		return result, err
	}
	defer destinationFile.Close()
	if validateDestination != nil {
		body, err := readBoundDerivedStateControlFile(
			root,
			destination,
			destinationFile,
			destinationIdentity,
			destinationMaximum,
			"derived state exchange destination",
		)
		if err != nil {
			return result, err
		}
		if err := validateDestination(body); err != nil {
			return result, err
		}
	}
	if derivedStateControlBeforeExchangeHook != nil {
		if err := derivedStateControlBeforeExchangeHook(source, destination); err != nil {
			return result, err
		}
	}
	if _, err := verifyBoundDerivedStateControlFile(root, source, sourceFile, sourceIdentity, "derived state exchange source"); err != nil {
		return result, err
	}
	if _, err := verifyBoundDerivedStateControlFile(root, destination, destinationFile, destinationIdentity, "derived state exchange destination"); err != nil {
		return result, err
	}
	if err := exchangeDerivedStateFiles(directory.Fd(), source, destination); err != nil {
		return result, err
	}
	result.Exchanged = true
	result.Displaced = destinationIdentity
	sourcePath, sourceErr := root.Lstat(source)
	destinationPath, destinationErr := root.Lstat(destination)
	sourceOpened, sourceStatErr := sourceFile.Stat()
	destinationOpened, destinationStatErr := destinationFile.Stat()
	if sourceErr != nil || destinationErr != nil || sourceStatErr != nil || destinationStatErr != nil ||
		sourcePath == nil || destinationPath == nil || sourceOpened == nil || destinationOpened == nil ||
		!os.SameFile(destinationIdentity, sourcePath) ||
		!os.SameFile(destinationIdentity, destinationOpened) ||
		!sameDerivedStateControlFileSecurity(destinationIdentity, sourcePath) ||
		!sameDerivedStateControlFileSecurity(destinationIdentity, destinationOpened) ||
		!os.SameFile(sourceIdentity, destinationPath) ||
		!os.SameFile(sourceIdentity, sourceOpened) ||
		!sameDerivedStateControlFileSecurity(sourceIdentity, destinationPath) ||
		!sameDerivedStateControlFileSecurity(sourceIdentity, sourceOpened) {
		return result, errors.Join(
			sourceErr,
			destinationErr,
			sourceStatErr,
			destinationStatErr,
			errors.New("derived state control-file exchange changed its bound identities"),
		)
	}
	if err := directory.Sync(); err != nil {
		return result, err
	}
	return result, nil
}

func verifyDerivedStateImmediateParent(stateRoot string) error {
	if stateRoot == "" || !filepath.IsAbs(stateRoot) {
		return errors.New("derived state immediate-parent coordinate is invalid")
	}
	parentPath := filepath.Dir(stateRoot)
	before, err := os.Lstat(parentPath)
	if err != nil {
		return err
	}
	if _, err := admitDerivedStateDirectory(before, "derived state immediate parent"); err != nil {
		return err
	}
	parent, err := os.OpenRoot(parentPath)
	if err != nil {
		return err
	}
	defer parent.Close()
	opened, statErr := parent.Stat(".")
	current, lstatErr := os.Lstat(parentPath)
	if statErr != nil || lstatErr != nil || opened == nil || current == nil ||
		!os.SameFile(before, opened) || !os.SameFile(before, current) ||
		!sameDerivedStateDirectorySecurity(before, opened) ||
		!sameDerivedStateDirectorySecurity(before, current) {
		return errors.Join(
			statErr,
			lstatErr,
			errors.New("derived state immediate parent changed while binding"),
		)
	}
	if _, err := admitDerivedStateDirectory(opened, "bound derived state immediate parent"); err != nil {
		return err
	}
	if _, err := admitDerivedStateDirectory(current, "current derived state immediate parent"); err != nil {
		return err
	}
	return nil
}

// bindAdmittedDerivedStateDirectory turns a path into a descriptor-bound
// mutation capability only after both the directory and its immediate parent
// have passed the hostile-writer admission policy. The returned identity is the
// frozen UID/GID/mode tuple callers must revalidate at every mutation boundary.
func bindAdmittedDerivedStateDirectory(path, description string) (string, *os.Root, os.FileInfo, error) {
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", nil, nil, err
	}
	if err := verifyDerivedStateImmediateParent(absolute); err != nil {
		return "", nil, nil, fmt.Errorf("admit %s immediate parent: %w", description, err)
	}
	before, err := os.Lstat(absolute)
	if err != nil {
		return "", nil, nil, err
	}
	if _, err := admitDerivedStateDirectory(before, description); err != nil {
		return "", nil, nil, err
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return "", nil, nil, err
	}
	if err := verifyBoundDerivedStateRoot(root, absolute, before); err != nil {
		root.Close()
		return "", nil, nil, err
	}
	opened, err := root.Stat(".")
	if err != nil || opened == nil || !os.SameFile(before, opened) ||
		!sameDerivedStateDirectorySecurity(before, opened) {
		root.Close()
		return "", nil, nil, errors.Join(err, fmt.Errorf("%s changed while binding", description))
	}
	return absolute, root, opened, nil
}

func ensureDerivedStateControlDirectory(stateRoot, relative, description string, create bool) (string, bool, error) {
	// One CLI command may materialize several independent leaves concurrently.
	// Serialize their create-and-secure window so a sibling worker cannot
	// observe a just-created directory before its descriptor-bound chmod and
	// parent fsync have completed. Cross-process writers are already serialized
	// by the repository state lock.
	derivedStateControlDirectoryAdmission.Lock()
	defer derivedStateControlDirectoryAdmission.Unlock()

	if filepath.Base(relative) != relative || relative == "" || relative == "." {
		return "", false, errors.New("derived state control-directory coordinate is invalid")
	}
	stateAbs, err := filepath.Abs(filepath.Clean(stateRoot))
	if err != nil {
		return "", false, err
	}
	destination := filepath.Join(stateAbs, relative)
	if _, err := os.Lstat(stateAbs); errors.Is(err, os.ErrNotExist) && !create {
		return destination, false, nil
	}
	stateAbs, root, rootIdentity, err := bindAdmittedDerivedStateDirectory(stateAbs, "derived state root")
	if err != nil {
		return "", false, err
	}
	defer root.Close()
	info, err := root.Lstat(relative)
	created := false
	if errors.Is(err, os.ErrNotExist) && !create {
		return destination, false, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		if err := root.Mkdir(relative, 0o700); err != nil {
			return "", false, err
		}
		created = true
		info, err = root.Lstat(relative)
	}
	if err != nil || info == nil {
		return "", false, errors.Join(err, fmt.Errorf("%s is unavailable", description))
	}
	security, admissionErr := admitDerivedStateDirectory(info, description)
	if admissionErr != nil {
		return "", false, admissionErr
	}
	child, err := root.OpenRoot(relative)
	if err != nil {
		return "", false, err
	}
	defer child.Close()
	if err := verifyBoundDerivedStateRoot(child, destination, info); err != nil {
		return "", false, err
	}
	if created {
		directory, err := child.Open(".")
		if err != nil {
			return "", false, err
		}
		opened, statErr := directory.Stat()
		current, lstatErr := root.Lstat(relative)
		if statErr != nil || lstatErr != nil || opened == nil || current == nil ||
			!os.SameFile(info, opened) || !os.SameFile(info, current) ||
			!sameDerivedStateDirectorySecurity(info, opened) ||
			!sameDerivedStateDirectorySecurity(info, current) {
			directory.Close()
			return "", false, errors.Join(statErr, lstatErr, fmt.Errorf("%s changed before securing", description))
		}
		chmodErr := directory.Chmod(0o700)
		syncErr := directory.Sync()
		after, afterErr := directory.Stat()
		current, currentErr := root.Lstat(relative)
		closeErr := directory.Close()
		afterSecurity, afterOK := derivedStateSecurityIdentityFromInfo(after)
		currentSecurity, currentOK := derivedStateSecurityIdentityFromInfo(current)
		if chmodErr != nil || syncErr != nil || afterErr != nil || currentErr != nil || closeErr != nil ||
			after == nil || current == nil || after.Mode().Perm() != 0o700 || current.Mode().Perm() != 0o700 ||
			!os.SameFile(info, after) || !os.SameFile(info, current) ||
			!afterOK || !currentOK ||
			afterSecurity.uid != security.uid || afterSecurity.gid != security.gid ||
			currentSecurity.uid != security.uid || currentSecurity.gid != security.gid {
			return "", false, errors.Join(chmodErr, syncErr, afterErr, currentErr, closeErr, fmt.Errorf("%s changed while securing", description))
		}
		info = after
		parent, openErr := root.Open(".")
		if openErr != nil {
			return "", false, openErr
		}
		parentSyncErr := parent.Sync()
		parentCloseErr := parent.Close()
		if parentSyncErr != nil || parentCloseErr != nil {
			return "", false, errors.Join(parentSyncErr, parentCloseErr)
		}
	}
	if err := verifyBoundDerivedStateRoot(root, stateAbs, rootIdentity); err != nil {
		return "", false, err
	}
	if err := verifyBoundDerivedStateRoot(child, destination, info); err != nil {
		return "", false, err
	}
	return destination, true, nil
}
