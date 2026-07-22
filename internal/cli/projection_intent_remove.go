package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/pgsty/sow/internal/state"
)

// projectionStateBeforeUnlinkHook is the last deterministic seam before an
// exact removal. Production never sets it.
var projectionStateBeforeUnlinkHook func(string) error

// projectionStateBeforeBindOpenHook deterministically replaces a pathname
// between Lstat and nonblocking open in tests. Production never sets it.
var projectionStateBeforeBindOpenHook func(string) error

// projectionStageIdentity is a process-local cleanup capability. The inode is
// captured while the writer still owns the retained descriptor; size and
// digest independently fence in-place mutation, while the bound state root
// prevents applying the capability to a replacement tree.
type projectionStageIdentity struct {
	stateRoot string
	root      os.FileInfo
	relative  string
	inode     os.FileInfo
	size      int64
	sha256    string
}

func (identity projectionStageIdentity) valid() bool {
	return identity.stateRoot != "" && filepath.IsAbs(identity.stateRoot) && identity.root != nil && identity.root.IsDir() &&
		identity.root.Mode()&os.ModeSymlink == 0 && filepath.Base(identity.relative) == identity.relative &&
		identity.relative != "" && identity.relative != "." && identity.inode != nil &&
		privateExactProjectionStage(identity.inode, identity.size) && validMaterializationTrustSHA256(identity.sha256)
}

func verifyProjectionStageRootIdentity(stateRoot string, expected os.FileInfo) error {
	if stateRoot == "" || expected == nil {
		return errors.New("prepared projection state-root binding is invalid")
	}
	absolute, err := filepath.Abs(stateRoot)
	if err != nil {
		return err
	}
	current, err := os.Lstat(absolute)
	if err != nil || current == nil || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() ||
		!os.SameFile(expected, current) || current.Mode() != expected.Mode() {
		return errors.Join(err, errors.New("prepared projection state-root coordinate changed"))
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return err
	}
	defer root.Close()
	return verifyBoundDerivedStateRoot(root, absolute, expected)
}

func verifyInstalledProjectionStage(identity projectionStageIdentity) error {
	if !identity.valid() {
		return errors.New("installed projection stage verification capability is invalid")
	}
	if err := verifyProjectionStageRootIdentity(identity.stateRoot, identity.root); err != nil {
		return err
	}
	root, err := os.OpenRoot(identity.stateRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	file, opened, err := bindExactProjectionStage(root, identity.relative, identity.size)
	if err != nil {
		return err
	}
	defer file.Close()
	if !os.SameFile(identity.inode, opened) {
		return errors.New("installed projection stage inode changed before verification")
	}
	if _, err := hashExactOpenProjectionStage(file, opened, identity.size, identity.sha256); err != nil {
		return err
	}
	current, err := root.Lstat(identity.relative)
	if err != nil || current == nil || !os.SameFile(identity.inode, current) {
		return errors.Join(err, errors.New("installed projection stage coordinate changed after verification"))
	}
	return verifyBoundDerivedStateRoot(root, identity.stateRoot, identity.root)
}

func verifyInstalledProjectionStages(stages []projectionStageIdentity) error {
	for _, identity := range stages {
		if err := verifyInstalledProjectionStage(identity); err != nil {
			return fmt.Errorf("verify prepared projection stage %s: %w", identity.relative, err)
		}
	}
	return nil
}

// removeInstalledProjectionStage consumes only the inode capability returned
// by the stage writer. A same-byte replacement is unrelated and survives.
func removeInstalledProjectionStage(identity projectionStageIdentity) (bool, error) {
	if !identity.valid() {
		return false, errors.New("installed projection stage cleanup capability is invalid")
	}
	rootBefore, err := os.Lstat(identity.stateRoot)
	if err != nil || rootBefore == nil || !os.SameFile(identity.root, rootBefore) || !rootBefore.IsDir() || rootBefore.Mode()&os.ModeSymlink != 0 {
		return false, errors.Join(err, errors.New("installed projection stage root coordinate changed"))
	}
	root, err := os.OpenRoot(identity.stateRoot)
	if err != nil {
		return false, err
	}
	defer root.Close()
	if err := verifyBoundDerivedStateRoot(root, identity.stateRoot, identity.root); err != nil {
		return false, err
	}
	current, err := root.Lstat(identity.relative)
	if errors.Is(err, os.ErrNotExist) {
		return false, errors.New("installed projection stage disappeared before cleanup")
	}
	if err != nil || current == nil || !os.SameFile(identity.inode, current) {
		return false, errors.Join(err, errors.New("installed projection stage was replaced; refuse cleanup"))
	}
	file, opened, err := bindExactProjectionStage(root, identity.relative, identity.size)
	if err != nil {
		return false, err
	}
	defer file.Close()
	if !os.SameFile(identity.inode, opened) {
		return false, errors.New("installed projection stage inode changed while binding cleanup")
	}
	firstDigest, err := hashExactOpenProjectionStage(file, opened, identity.size, identity.sha256)
	if err != nil {
		return false, err
	}
	current, err = root.Lstat(identity.relative)
	if err != nil || current == nil || !os.SameFile(identity.inode, current) {
		return false, errors.Join(err, errors.New("installed projection stage coordinate changed while hashing"))
	}
	if err := verifyBoundDerivedStateRoot(root, identity.stateRoot, identity.root); err != nil {
		return false, err
	}
	directory, err := root.Open(".")
	if err != nil {
		return false, err
	}
	defer directory.Close()
	if err := commitExactPrivateStateFileRemoval(root, directory, file, identity.inode, identity.relative, func() error {
		lastDigest, verifyErr := hashExactOpenProjectionStage(file, opened, identity.size, identity.sha256)
		if verifyErr != nil || firstDigest != lastDigest {
			return errors.Join(verifyErr, errors.New("installed projection stage bytes changed before rollback commit"))
		}
		return verifyBoundDerivedStateRoot(root, identity.stateRoot, identity.root)
	}); err != nil {
		return false, errors.Join(err, verifyBoundDerivedStateRoot(root, identity.stateRoot, identity.root))
	}
	if err := verifyBoundDerivedStateRoot(root, identity.stateRoot, identity.root); err != nil {
		return false, err
	}
	return true, nil
}

func rollbackInstalledProjectionStages(stages []projectionStageIdentity) error {
	var cleanupErr error
	for index := len(stages) - 1; index >= 0; index-- {
		if _, err := removeInstalledProjectionStage(stages[index]); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("clean %s: %w", stages[index].relative, err))
		}
	}
	if cleanupErr != nil {
		return fmt.Errorf("prepared projection stage cleanup failed; retry with --recover: %w", cleanupErr)
	}
	return nil
}

func isAssetProjectionStageFinalName(name string) bool {
	transaction, ok := strings.CutPrefix(name, assetProjectionStagePrefix)
	if !ok || len(transaction) < 32 || !exactLowerHex(transaction[:32], 32) {
		return false
	}
	return transaction[32:] == ".tsv" || transaction[32:] == "-config.yaml"
}

func isPackageProjectionStageFinalName(name string) bool {
	transaction, ok := strings.CutPrefix(name, packageProjectionStagePrefix)
	if !ok || len(transaction) < 32 || !exactLowerHex(transaction[:32], 32) {
		return false
	}
	suffix := transaction[32:]
	if suffix == "-config.yaml" {
		return true
	}
	if len(suffix) < len("-000.tsv") || suffix[0] != '-' || !strings.HasSuffix(suffix, ".tsv") {
		return false
	}
	digits := suffix[1 : len(suffix)-len(".tsv")]
	if len(digits) < 3 || len(digits) > 3 && digits[0] == '0' {
		return false
	}
	for _, current := range []byte(digits) {
		if current < '0' || current > '9' {
			return false
		}
	}
	return true
}

func isProjectionStageTemporaryName(name string, isFinal func(string) bool) bool {
	for _, marker := range []string{".tmp-install-", ".tmp-remove-", ".tmp-"} {
		index := strings.Index(name, marker)
		if index > 0 && isFinal(name[:index]) && isDerivedStateTemporaryName(name, name[:index]) {
			return true
		}
	}
	return false
}

func isProjectionStagePreservedName(name string, isFinal func(string) bool) bool {
	index := strings.LastIndex(name, ".preserved-")
	return index > 0 && isFinal(name[:index]) && exactLowerHex(name[index+len(".preserved-"):], 32)
}

// preserveExactProjectionResidue moves a private orphan out of the live stage
// namespace without deleting it. The retained descriptor proves which inode
// was moved; any race still leaves all bytes reachable for operator audit.
func preserveExactProjectionResidue(stateRoot, relative string) (string, bool, error) {
	if filepath.Base(relative) != relative || relative == "" || relative == "." {
		return "", false, errors.New("projection residue preservation capability is invalid")
	}
	stateRoot, err := filepath.Abs(stateRoot)
	if err != nil {
		return "", false, err
	}
	rootBefore, err := os.Lstat(stateRoot)
	if err != nil || rootBefore == nil || rootBefore.Mode()&os.ModeSymlink != 0 || !rootBefore.IsDir() {
		return "", false, errors.Join(err, errors.New("projection residue preservation root is not a real directory"))
	}
	root, err := os.OpenRoot(stateRoot)
	if err != nil {
		return "", false, err
	}
	defer root.Close()
	rootIdentity, err := root.Stat(".")
	if err != nil || rootIdentity == nil || !os.SameFile(rootBefore, rootIdentity) {
		return "", false, errors.Join(err, errors.New("projection residue preservation root changed while binding"))
	}
	if _, err := root.Lstat(relative); errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	} else if err != nil {
		return "", false, err
	}
	file, identity, err := bindExactProjectionResidue(root, relative, -1)
	if err != nil {
		return "", false, err
	}
	defer file.Close()
	if projectionResidueCleanupHook != nil {
		if err := projectionResidueCleanupHook(relative); err != nil {
			return "", false, err
		}
	}
	if err := verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity); err != nil {
		return "", false, err
	}
	current, err := root.Lstat(relative)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil || current == nil || !os.SameFile(identity, current) || !privateExactProjectionResidue(current, -1) {
		return "", false, errors.Join(err, errors.New("projection residue changed before preservation"))
	}
	directory, err := root.Open(".")
	if err != nil {
		return "", false, err
	}
	defer directory.Close()
	nonce, err := state.NewTransactionID()
	if err != nil {
		return "", false, err
	}
	preserved := relative + ".preserved-" + nonce
	if err := renameYUMCompatibilityCandidateNoReplace(directory.Fd(), relative, preserved); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity)
		}
		return "", false, err
	}
	if err := directory.Sync(); err != nil {
		return preserved, true, fmt.Errorf("sync preserved projection residue %s: %w", preserved, err)
	}
	moved, lstatErr := root.Lstat(preserved)
	opened, statErr := file.Stat()
	rootErr := verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity)
	if lstatErr != nil || statErr != nil || rootErr != nil || moved == nil || opened == nil ||
		!os.SameFile(identity, moved) || !os.SameFile(identity, opened) || !privateExactProjectionResidue(moved, -1) ||
		moved.Size() != identity.Size() || moved.Mode() != identity.Mode() || !moved.ModTime().Equal(identity.ModTime()) {
		return preserved, true, errors.Join(lstatErr, statErr, rootErr, fmt.Errorf("projection residue preservation identity changed; retained at %s", preserved))
	}
	return preserved, true, nil
}

// removeExactProjectionIntent commits removal through a no-replace quarantine.
// A pathname replacement is moved out of the live coordinate but is never
// deleted: its inode is compared with the exact file that supplied the
// validated bytes and restored without overwrite on any mismatch.
func removeExactProjectionIntent(stateRoot, relative string, maximum int64, validate func([]byte) error) error {
	if filepath.Base(relative) != relative || relative == "." || relative == "" || maximum <= 0 || validate == nil {
		return errors.New("projection intent removal capability is invalid")
	}
	root, err := os.OpenRoot(stateRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	file, identity, body, err := bindExactProjectionIntent(root, relative, maximum)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := validate(body); err != nil {
		return err
	}
	if projectionIntentRemovalHook != nil {
		if err := projectionIntentRemovalHook(relative); err != nil {
			return err
		}
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return commitExactPrivateStateFileRemoval(root, directory, file, identity, relative, func() error {
		lastBody, readErr := readExactOpenProjectionIntent(file, identity, maximum)
		if readErr != nil || !bytes.Equal(body, lastBody) {
			return errors.Join(readErr, errors.New("projection intent bytes changed before completion commit"))
		}
		return nil
	})
}

func removeExactProjectionStage(stateRoot, relative string, expectedSize int64, expectedSHA256 string) (bool, error) {
	if filepath.Base(relative) != relative || relative == "." || relative == "" ||
		expectedSize < 0 || expectedSize == math.MaxInt64 || !validMaterializationTrustSHA256(expectedSHA256) {
		return false, errors.New("projection stage cleanup capability is invalid")
	}
	root, err := os.OpenRoot(stateRoot)
	if err != nil {
		return false, err
	}
	defer root.Close()
	if _, err := root.Lstat(relative); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	file, identity, err := bindExactProjectionStage(root, relative, expectedSize)
	if err != nil {
		return false, err
	}
	defer file.Close()
	firstDigest, err := hashExactOpenProjectionStage(file, identity, expectedSize, expectedSHA256)
	if err != nil {
		return false, err
	}
	current, err := root.Lstat(relative)
	if err != nil || !os.SameFile(identity, current) {
		return false, errors.Join(err, errors.New("projection stage coordinate changed while hashing"))
	}
	if projectionStageCleanupHook != nil {
		if err := projectionStageCleanupHook(relative); err != nil {
			return false, err
		}
	}
	directory, err := root.Open(".")
	if err != nil {
		return false, err
	}
	defer directory.Close()
	err = commitExactPrivateStateFileRemoval(root, directory, file, identity, relative, func() error {
		lastDigest, verifyErr := hashExactOpenProjectionStage(file, identity, expectedSize, expectedSHA256)
		if verifyErr != nil || firstDigest != lastDigest {
			return errors.Join(verifyErr, errors.New("projection stage bytes changed before cleanup commit"))
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return true, nil
}

func removeExactProjectionResidue(stateRoot, relative string) (bool, error) {
	return removeExactProjectionResidueBounded(stateRoot, relative, -1)
}

func removeExactProjectionResidueBounded(stateRoot, relative string, maximum int64) (bool, error) {
	if filepath.Base(relative) != relative || relative == "." || relative == "" {
		return false, errors.New("projection residue cleanup capability is invalid")
	}
	stateRoot, err := filepath.Abs(stateRoot)
	if err != nil {
		return false, err
	}
	rootBefore, err := os.Lstat(stateRoot)
	if err != nil || rootBefore == nil || rootBefore.Mode()&os.ModeSymlink != 0 || !rootBefore.IsDir() {
		return false, errors.Join(err, errors.New("projection residue root is not a real directory"))
	}
	root, err := os.OpenRoot(stateRoot)
	if err != nil {
		return false, err
	}
	defer root.Close()
	rootIdentity, err := root.Stat(".")
	if err != nil || rootIdentity == nil || !os.SameFile(rootBefore, rootIdentity) {
		return false, errors.Join(err, errors.New("projection residue root changed while binding"))
	}
	if err := verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity); err != nil {
		return false, err
	}
	if _, err := root.Lstat(relative); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	file, identity, err := bindExactProjectionResidue(root, relative, maximum)
	if err != nil {
		return false, err
	}
	defer file.Close()
	if projectionResidueCleanupHook != nil {
		if err := projectionResidueCleanupHook(relative); err != nil {
			return false, err
		}
	}
	if err := verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity); err != nil {
		return false, err
	}
	directory, err := root.Open(".")
	if err != nil {
		return false, errors.Join(err, verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity))
	}
	if err := verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity); err != nil {
		return false, err
	}
	defer directory.Close()
	err = commitExactPrivateStateFileRemoval(root, directory, file, identity, relative, func() error {
		after, statErr := file.Stat()
		if statErr != nil || after == nil || !os.SameFile(identity, after) ||
			after.Size() != identity.Size() || !after.ModTime().Equal(identity.ModTime()) || after.Mode() != identity.Mode() {
			return errors.Join(statErr, errors.New("projection residue changed before cleanup commit"))
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			_, coordinateErr := root.Lstat(relative)
			rootErr := verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity)
			if errors.Is(coordinateErr, os.ErrNotExist) && rootErr == nil {
				return true, directory.Sync()
			}
			return false, errors.Join(err, coordinateErr, rootErr)
		}
		return false, errors.Join(err, verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity))
	}
	if err := verifyBoundDerivedStateRoot(root, stateRoot, rootIdentity); err != nil {
		return false, err
	}
	return true, nil
}

func commitExactPrivateStateFileRemoval(root *os.Root, directory, file *os.File, identity os.FileInfo, relative string, verify func() error) error {
	if root == nil || directory == nil || file == nil || identity == nil || verify == nil {
		return errors.New("projection state removal binding is incomplete")
	}
	nonce, err := state.NewTransactionID()
	if err != nil {
		return err
	}
	quarantine := relative + ".tmp-remove-" + nonce
	if err := renameYUMCompatibilityCandidateNoReplace(directory.Fd(), relative, quarantine); err != nil {
		return err
	}
	restore := func(cause error) error {
		restoreErr := renameYUMCompatibilityCandidateNoReplace(directory.Fd(), quarantine, relative)
		syncErr := directory.Sync()
		if restoreErr != nil {
			return errors.Join(cause, restoreErr, syncErr, fmt.Errorf("projection state replacement retained at %s", quarantine))
		}
		return errors.Join(cause, syncErr)
	}
	quarantined, lstatErr := root.Lstat(quarantine)
	opened, statErr := file.Stat()
	if lstatErr != nil || statErr != nil || quarantined == nil || opened == nil ||
		quarantined.Mode()&os.ModeSymlink != 0 || !quarantined.Mode().IsRegular() ||
		!os.SameFile(identity, quarantined) || !os.SameFile(identity, opened) {
		return restore(errors.Join(lstatErr, statErr, errors.New("projection state file changed before removal commit")))
	}
	if err := verify(); err != nil {
		return restore(err)
	}
	quarantined, lstatErr = root.Lstat(quarantine)
	opened, statErr = file.Stat()
	if lstatErr != nil || statErr != nil || quarantined == nil || opened == nil ||
		quarantined.Mode()&os.ModeSymlink != 0 || !quarantined.Mode().IsRegular() ||
		!os.SameFile(identity, quarantined) || !os.SameFile(identity, opened) {
		return restore(errors.Join(lstatErr, statErr, errors.New("projection state quarantine changed before removal")))
	}
	if err := directory.Sync(); err != nil {
		return restore(fmt.Errorf("sync projection state removal commit: %w", err))
	}
	if projectionStateBeforeUnlinkHook != nil {
		if err := projectionStateBeforeUnlinkHook(quarantine); err != nil {
			return restore(err)
		}
	}
	quarantined, lstatErr = root.Lstat(quarantine)
	opened, statErr = file.Stat()
	if lstatErr != nil || statErr != nil || quarantined == nil || opened == nil ||
		!os.SameFile(identity, quarantined) || !os.SameFile(identity, opened) {
		return restore(errors.Join(lstatErr, statErr, errors.New("projection state quarantine changed before unlink")))
	}
	if err := verify(); err != nil {
		return restore(err)
	}
	quarantined, lstatErr = root.Lstat(quarantine)
	opened, statErr = file.Stat()
	if lstatErr != nil || statErr != nil || quarantined == nil || opened == nil ||
		quarantined.Mode()&os.ModeSymlink != 0 || !quarantined.Mode().IsRegular() ||
		!os.SameFile(identity, quarantined) || !os.SameFile(identity, opened) {
		return restore(errors.Join(lstatErr, statErr, errors.New("projection state quarantine changed at unlink boundary")))
	}
	if err := root.Remove(quarantine); err != nil {
		return restore(fmt.Errorf("remove exact projection state quarantine: %w", err))
	}
	return directory.Sync()
}

func bindExactProjectionStage(root *os.Root, relative string, expectedSize int64) (*os.File, os.FileInfo, error) {
	before, err := root.Lstat(relative)
	if err != nil || !privateExactProjectionStage(before, expectedSize) {
		return nil, nil, errors.Join(err, errors.New("projection stage is not an exact private regular file"))
	}
	if projectionStateBeforeBindOpenHook != nil {
		if err := projectionStateBeforeBindOpenHook(relative); err != nil {
			return nil, nil, err
		}
	}
	file, err := root.OpenFile(relative, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	opened, statErr := file.Stat()
	current, lstatErr := root.Lstat(relative)
	if statErr != nil || lstatErr != nil || opened == nil || current == nil ||
		!os.SameFile(before, opened) || !os.SameFile(before, current) ||
		!privateExactProjectionStage(opened, expectedSize) || !privateExactProjectionStage(current, expectedSize) {
		file.Close()
		return nil, nil, errors.Join(statErr, lstatErr, errors.New("projection stage changed while binding its inode"))
	}
	return file, opened, nil
}

func bindExactProjectionResidue(root *os.Root, relative string, maximum int64) (*os.File, os.FileInfo, error) {
	before, err := root.Lstat(relative)
	if err != nil || !privateExactProjectionResidue(before, maximum) {
		return nil, nil, errors.Join(err, errors.New("projection residue is not a private regular file"))
	}
	if projectionStateBeforeBindOpenHook != nil {
		if err := projectionStateBeforeBindOpenHook(relative); err != nil {
			return nil, nil, err
		}
	}
	file, err := root.OpenFile(relative, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	opened, statErr := file.Stat()
	current, lstatErr := root.Lstat(relative)
	if statErr != nil || lstatErr != nil || opened == nil || current == nil ||
		!os.SameFile(before, opened) || !os.SameFile(before, current) ||
		!privateExactProjectionResidue(opened, maximum) || !privateExactProjectionResidue(current, maximum) {
		file.Close()
		return nil, nil, errors.Join(statErr, lstatErr, errors.New("projection residue changed while binding its inode"))
	}
	return file, opened, nil
}

func hashExactOpenProjectionStage(file *os.File, identity os.FileInfo, expectedSize int64, expectedSHA256 string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return result, err
	}
	hasher := sha256.New()
	written, readErr := io.CopyBuffer(hasher, io.LimitReader(file, expectedSize+1), make([]byte, 256*1024))
	after, statErr := file.Stat()
	copy(result[:], hasher.Sum(nil))
	if readErr != nil || statErr != nil || after == nil || written != expectedSize ||
		!os.SameFile(identity, after) || after.Size() != identity.Size() ||
		!after.ModTime().Equal(identity.ModTime()) || after.Mode() != identity.Mode() ||
		hex.EncodeToString(result[:]) != expectedSHA256 {
		return result, errors.Join(readErr, statErr, errors.New("projection stage differs from its frozen identity"))
	}
	return result, nil
}

func bindExactProjectionIntent(root *os.Root, relative string, maximum int64) (*os.File, os.FileInfo, []byte, error) {
	if root == nil {
		return nil, nil, nil, errors.New("projection intent root is unavailable")
	}
	before, err := root.Lstat(relative)
	if err != nil || !privateExactProjectionIntent(before, maximum) {
		return nil, nil, nil, errors.Join(err, errors.New("projection intent is not a private exact regular file"))
	}
	if projectionStateBeforeBindOpenHook != nil {
		if err := projectionStateBeforeBindOpenHook(relative); err != nil {
			return nil, nil, nil, err
		}
	}
	file, err := root.OpenFile(relative, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, nil, err
	}
	opened, statErr := file.Stat()
	current, lstatErr := root.Lstat(relative)
	if statErr != nil || lstatErr != nil || opened == nil || current == nil ||
		!os.SameFile(before, opened) || !os.SameFile(before, current) ||
		!privateExactProjectionIntent(opened, maximum) || !privateExactProjectionIntent(current, maximum) {
		file.Close()
		return nil, nil, nil, errors.Join(statErr, lstatErr, errors.New("projection intent changed while binding its inode"))
	}
	body, err := readExactOpenProjectionIntent(file, opened, maximum)
	if err != nil {
		file.Close()
		return nil, nil, nil, err
	}
	last, lstatErr := root.Lstat(relative)
	if lstatErr != nil || last == nil || !os.SameFile(opened, last) || !privateExactProjectionIntent(last, maximum) {
		file.Close()
		return nil, nil, nil, errors.Join(lstatErr, errors.New("projection intent coordinate changed while reading"))
	}
	return file, opened, body, nil
}

func readExactOpenProjectionIntent(file *os.File, identity os.FileInfo, maximum int64) ([]byte, error) {
	if file == nil || identity == nil {
		return nil, errors.New("projection intent file binding is incomplete")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	body, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	after, statErr := file.Stat()
	if readErr != nil || statErr != nil || after == nil || len(body) == 0 || int64(len(body)) > maximum ||
		int64(len(body)) != identity.Size() || !os.SameFile(identity, after) || after.Size() != identity.Size() ||
		!after.ModTime().Equal(identity.ModTime()) || after.Mode() != identity.Mode() {
		return nil, errors.Join(readErr, statErr, errors.New("projection intent changed while reading its exact bytes"))
	}
	return body, nil
}

func privateExactProjectionIntent(info os.FileInfo, maximum int64) bool {
	return info != nil && info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular() &&
		info.Mode().Perm()&0o077 == 0 && info.Size() > 0 && info.Size() <= maximum
}

func privateExactProjectionStage(info os.FileInfo, expectedSize int64) bool {
	return info != nil && info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular() &&
		info.Mode().Perm()&0o077 == 0 && info.Size() == expectedSize
}

func privateExactProjectionResidue(info os.FileInfo, maximum int64) bool {
	return info != nil && info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0 &&
		(maximum < 0 || info.Size() <= maximum)
}
