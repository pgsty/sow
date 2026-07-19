package serving

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const mirrorlistMaxBytes = 4 << 10

var errMirrorlistReadRace = errors.New("mirrorlist changed during atomic read")

func ReconcileMirrorlist(root string, channel Channel) (bool, error) {
	if err := channel.Validate(); err != nil {
		return false, err
	}
	desired, err := channel.MirrorlistBody()
	if err != nil {
		return false, err
	}
	current, exists, err := ReadMirrorlist(root, channel.MirrorlistPath)
	if err != nil {
		return false, err
	}
	if exists && bytes.Equal(current, desired) {
		changed, err := reconcileMirrorlistPermissions(root, channel.MirrorlistPath)
		if err != nil {
			return false, err
		}
		if err := syncMirrorlistParent(root, channel.MirrorlistPath); err != nil {
			return false, err
		}
		observed, stillExists, err := ReadMirrorlist(root, channel.MirrorlistPath)
		if err != nil || !stillExists || !bytes.Equal(observed, desired) {
			return false, errors.Join(err, errors.New("mirrorlist changed after canonical fast-path validation"))
		}
		return changed, nil
	}
	if !exists {
		if channel.ParentMirrorlistSHA256 != "" {
			return false, errors.New("mirrorlist disappeared after its parent state was recorded")
		}
	} else {
		if channel.ParentMirrorlistSHA256 == "" {
			return false, errors.New("unmanaged mirrorlist occupies first-install coordinate")
		}
		digest := sha256.Sum256(current)
		if hex.EncodeToString(digest[:]) != channel.ParentMirrorlistSHA256 {
			return false, errors.New("mirrorlist differs from both parent and desired canonical state")
		}
	}
	var expected []byte
	if exists {
		expected = current
	}
	if err := atomicServingFile(root, channel.MirrorlistPath, desired, expected); err != nil {
		return false, err
	}
	observed, exists, err := ReadMirrorlist(root, channel.MirrorlistPath)
	if err != nil || !exists || !bytes.Equal(observed, desired) {
		return false, errors.Join(err, errors.New("mirrorlist read-back differs after atomic replacement"))
	}
	if err := ValidateMirrorlistPermissions(root, channel.MirrorlistPath); err != nil {
		return false, err
	}
	return true, nil
}

// RestoreMirrorlist recreates an absent pointer from an already-committed
// canonical channel. Unlike ReconcileMirrorlist it does not accept the former
// parent body: recovery is legal only when the coordinate is absent or already
// equals the committed desired body. Foreign bytes always fail closed.
func RestoreMirrorlist(root string, channel Channel) (bool, error) {
	if err := channel.Validate(); err != nil {
		return false, err
	}
	desired, err := channel.MirrorlistBody()
	if err != nil {
		return false, err
	}
	current, exists, err := ReadMirrorlist(root, channel.MirrorlistPath)
	if err != nil {
		return false, err
	}
	if exists {
		if !bytes.Equal(current, desired) {
			return false, errors.New("mirrorlist differs from committed canonical state")
		}
		changed, err := reconcileMirrorlistPermissions(root, channel.MirrorlistPath)
		if err != nil {
			return false, err
		}
		if err := syncMirrorlistParent(root, channel.MirrorlistPath); err != nil {
			return false, err
		}
		observed, stillExists, err := ReadMirrorlist(root, channel.MirrorlistPath)
		if err != nil || !stillExists || !bytes.Equal(observed, desired) {
			return false, errors.Join(err, errors.New("mirrorlist changed after committed fast-path validation"))
		}
		return changed, nil
	}
	if err := atomicServingFile(root, channel.MirrorlistPath, desired, nil); err != nil {
		return false, err
	}
	observed, exists, err := ReadMirrorlist(root, channel.MirrorlistPath)
	if err != nil || !exists || !bytes.Equal(observed, desired) {
		return false, errors.Join(err, errors.New("restored mirrorlist read-back differs from canonical state"))
	}
	return true, ValidateMirrorlistPermissions(root, channel.MirrorlistPath)
}

// RemoveMirrorlist performs a parent-bound topology deletion. It removes only
// the exact body committed in channel; absence is an idempotent success and a
// foreign replacement fails closed.
func RemoveMirrorlist(root string, channel Channel) (bool, error) {
	if err := channel.Validate(); err != nil {
		return false, err
	}
	wanted, err := channel.MirrorlistBody()
	if err != nil {
		return false, err
	}
	current, exists, err := ReadMirrorlist(root, channel.MirrorlistPath)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, syncMirrorlistParent(root, channel.MirrorlistPath)
	}
	if !bytes.Equal(current, wanted) {
		return false, errors.New("mirrorlist differs from canonical deletion parent")
	}
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return false, err
	}
	defer rootHandle.Close()
	relative := filepath.FromSlash(channel.MirrorlistPath)
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return false, err
	}
	temporary := filepath.Join(filepath.Dir(relative), ".mirrorlist-"+hex.EncodeToString(nonce[:]))
	if err := rootHandle.Rename(relative, temporary); err != nil {
		return false, err
	}
	captured, exists, captureErr := readMirrorlistOnce(root, filepath.ToSlash(temporary))
	if captureErr != nil || !exists || !bytes.Equal(captured, wanted) {
		// Restore with no-replace semantics. If another writer occupied the
		// coordinate, preserve both bodies and fail rather than deleting either.
		restoreErr := rootHandle.Link(temporary, relative)
		if restoreErr == nil {
			restoreErr = rootHandle.Remove(temporary)
		}
		return false, errors.Join(captureErr, restoreErr, errors.New("mirrorlist changed before parent-bound deletion"))
	}
	if err := rootHandle.Remove(temporary); err != nil {
		return false, err
	}
	directoryHandle, err := rootHandle.Open(filepath.Dir(relative))
	if err != nil {
		return false, err
	}
	if err := errors.Join(directoryHandle.Sync(), directoryHandle.Close()); err != nil {
		return false, err
	}
	if _, exists, err := ReadMirrorlist(root, channel.MirrorlistPath); err != nil || exists {
		return false, errors.Join(err, errors.New("mirrorlist remains after canonical deletion"))
	}
	return true, nil
}

// RollbackMirrorlist restores the exact pointer state captured immediately
// before ReconcileMirrorlist/recovery. The current coordinate must still equal
// channel's desired body; a foreign replacement is never overwritten. A
// present prior body must match the parent digest sealed into channel.
func RollbackMirrorlist(root string, channel Channel, prior []byte, priorExists bool) error {
	if err := channel.Validate(); err != nil {
		return err
	}
	desired, err := channel.MirrorlistBody()
	if err != nil {
		return err
	}
	current, exists, err := ReadMirrorlist(root, channel.MirrorlistPath)
	if err != nil || !exists || !bytes.Equal(current, desired) {
		return errors.Join(err, errors.New("mirrorlist differs from the desired rollback child"))
	}
	if !priorExists {
		if channel.ParentMirrorlistSHA256 != "" {
			return errors.New("cannot roll a parent-bound mirrorlist back to absence")
		}
		_, err := RemoveMirrorlist(root, channel)
		return err
	}
	if channel.ParentMirrorlistSHA256 == "" {
		return errors.New("first-install mirrorlist has no rollback parent")
	}
	digest := sha256.Sum256(prior)
	if hex.EncodeToString(digest[:]) != channel.ParentMirrorlistSHA256 {
		return errors.New("captured mirrorlist rollback parent differs from the sealed parent identity")
	}
	if err := atomicServingFile(root, channel.MirrorlistPath, prior, desired); err != nil {
		return err
	}
	observed, exists, err := ReadMirrorlist(root, channel.MirrorlistPath)
	if err != nil || !exists || !bytes.Equal(observed, prior) {
		return errors.Join(err, errors.New("mirrorlist rollback read-back differs from captured parent"))
	}
	return ValidateMirrorlistPermissions(root, channel.MirrorlistPath)
}

func ReadMirrorlist(root, relative string) ([]byte, bool, error) {
	if err := validateServingRelativePath(relative); err != nil {
		return nil, false, err
	}
	for range 32 {
		body, exists, err := readMirrorlistOnce(root, relative)
		if errors.Is(err, errMirrorlistReadRace) {
			continue
		}
		return body, exists, err
	}
	return nil, false, errors.New("mirrorlist did not stabilize during atomic reads")
}

func readMirrorlistOnce(root, relative string) ([]byte, bool, error) {
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return nil, false, err
	}
	defer rootHandle.Close()
	relativePath := filepath.FromSlash(relative)
	info, err := rootHandle.Lstat(relativePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > mirrorlistMaxBytes {
		return nil, false, errors.Join(err, errors.New("mirrorlist coordinate is not a regular non-symlink file"))
	}
	file, err := rootHandle.Open(relativePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, errMirrorlistReadRace
	}
	if err != nil {
		return nil, false, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, false, errors.Join(errMirrorlistReadRace, statErr, file.Close())
	}
	body, readErr := io.ReadAll(io.LimitReader(file, mirrorlistMaxBytes+1))
	afterOpen, restatErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || restatErr != nil || closeErr != nil {
		return nil, false, errors.Join(readErr, restatErr, closeErr)
	}
	// The directory entry may legitimately be atomically replaced after open;
	// the opened inode remains a complete parent or desired body. Validate that
	// inode itself rather than turning normal concurrent readers into failures.
	if len(body) > mirrorlistMaxBytes || int64(len(body)) != info.Size() || !os.SameFile(info, afterOpen) || info.Size() != afterOpen.Size() || !info.ModTime().Equal(afterOpen.ModTime()) {
		return nil, false, errors.New("mirrorlist exceeded its limit or changed while reading")
	}
	return body, true, nil
}

// ValidateMirrorlistPermissions verifies the frozen cross-UID static-serving
// contract without changing an unrecognized pointer body.
func ValidateMirrorlistPermissions(root, relative string) error {
	if err := ValidateHostableFile(root, relative); err != nil {
		return fmt.Errorf("mirrorlist permissions: %w", err)
	}
	return nil
}

// ValidateMirrorlistPermissionsRoot is the retained-root counterpart to
// ValidateMirrorlistPermissions. Nginx admission uses it after reading the
// exact canonical pointer so a mode-0600 file or mode-0700 product-owned
// parent cannot be exposed as if it were usable by the server worker UID.
func ValidateMirrorlistPermissionsRoot(root *os.Root, relative string) error {
	if err := ValidateHostableFileRoot(root, relative); err != nil {
		return fmt.Errorf("mirrorlist permissions: %w", err)
	}
	return nil
}

func reconcileMirrorlistPermissions(root, relative string) (bool, error) {
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return false, err
	}
	defer rootHandle.Close()
	relativePath := filepath.FromSlash(relative)
	changed := false
	prefix := ""
	for _, component := range strings.Split(filepath.Dir(relativePath), string(filepath.Separator)) {
		prefix = filepath.Join(prefix, component)
		info, err := rootHandle.Lstat(prefix)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false, errors.Join(err, fmt.Errorf("mirrorlist parent %s is unsafe", prefix))
		}
		if info.Mode().Perm() != 0o755 {
			directory, err := rootHandle.Open(prefix)
			if err != nil {
				return false, err
			}
			opened, statErr := directory.Stat()
			if statErr != nil || !os.SameFile(info, opened) || !opened.IsDir() {
				return false, errors.Join(statErr, directory.Close(), errors.New("mirrorlist parent changed while opening for permission repair"))
			}
			if err := errors.Join(directory.Chmod(0o755), directory.Sync(), directory.Close()); err != nil {
				return false, err
			}
			after, err := rootHandle.Lstat(prefix)
			if err != nil || !os.SameFile(info, after) {
				return false, errors.Join(err, errors.New("mirrorlist parent changed during permission repair"))
			}
			changed = true
		}
	}
	info, err := rootHandle.Lstat(relativePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, errors.Join(err, errors.New("mirrorlist coordinate is unsafe"))
	}
	if info.Mode().Perm() != 0o444 {
		file, err := rootHandle.Open(relativePath)
		if err != nil {
			return false, err
		}
		opened, statErr := file.Stat()
		if statErr != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
			return false, errors.Join(statErr, file.Close(), errors.New("mirrorlist changed while opening for permission repair"))
		}
		if err := errors.Join(file.Chmod(0o444), file.Sync(), file.Close()); err != nil {
			return false, err
		}
		after, err := rootHandle.Lstat(relativePath)
		if err != nil || !os.SameFile(info, after) {
			return false, errors.Join(err, errors.New("mirrorlist changed during permission repair"))
		}
		changed = true
	}
	if changed {
		directory, err := rootHandle.Open(filepath.Dir(relativePath))
		if err != nil {
			return false, err
		}
		if err := errors.Join(directory.Sync(), directory.Close()); err != nil {
			return false, err
		}
	}
	return changed, ValidateMirrorlistPermissions(root, relative)
}

func atomicServingFile(root, relative string, body, expected []byte) error {
	if err := validateServingRelativePath(relative); err != nil {
		return err
	}
	if len(body) > mirrorlistMaxBytes {
		return fmt.Errorf("mirrorlist body exceeds %d-byte limit", mirrorlistMaxBytes)
	}
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer rootHandle.Close()
	relative = filepath.FromSlash(relative)
	directory := filepath.Dir(relative)
	if err := rootHandle.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	prefix := ""
	for _, component := range strings.Split(directory, string(filepath.Separator)) {
		prefix = filepath.Join(prefix, component)
		info, err := rootHandle.Lstat(prefix)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.Join(err, fmt.Errorf("mirrorlist parent %s is not a real directory", prefix))
		}
		if info.Mode().Perm() != 0o755 {
			if err := rootHandle.Chmod(prefix, 0o755); err != nil {
				return err
			}
		}
	}
	if info, err := rootHandle.Lstat(relative); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("mirrorlist destination is not a regular non-symlink file")
		}
		if expected == nil {
			return errors.New("mirrorlist destination appeared before first-install commit")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else if expected != nil {
		return errors.New("mirrorlist disappeared before parent-bound commit")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temporary := filepath.Join(directory, ".mirrorlist-"+hex.EncodeToString(nonce[:]))
	file, err := rootHandle.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	cleanupTemporary := true
	defer func() {
		if cleanupTemporary {
			_ = file.Close()
			_ = rootHandle.Remove(temporary)
		}
	}()
	if _, err := file.Write(body); err != nil {
		return err
	}
	if err := file.Chmod(0o444); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if expected == nil {
		// Link is an atomic no-replace commit: an out-of-band writer that wins
		// the coordinate is preserved and causes a conflict instead of being
		// overwritten by a first-install rename.
		if err := rootHandle.Link(temporary, relative); err != nil {
			return err
		}
		if err := rootHandle.Remove(temporary); err != nil {
			return err
		}
		cleanupTemporary = false
	} else {
		// Exchange atomically captures the exact body displaced at commit time.
		// Validate that captured inode before deleting it; a concurrent foreign
		// replacement is swapped back and never silently overwritten.
		if err := atomicSwapFiles(root, temporary, relative); err != nil {
			return err
		}
		captured, exists, err := readMirrorlistOnce(root, temporary)
		if err != nil || !exists || !bytes.Equal(captured, expected) {
			rollbackErr := atomicSwapFiles(root, temporary, relative)
			if rollbackErr == nil {
				cleanupTemporary = true
			} else {
				cleanupTemporary = false
			}
			return errors.Join(err, rollbackErr, errors.New("mirrorlist changed before parent-bound atomic exchange"))
		}
		if err := rootHandle.Remove(temporary); err != nil {
			cleanupTemporary = false
			return err
		}
		cleanupTemporary = false
	}
	directoryHandle, err := rootHandle.Open(directory)
	if err != nil {
		return err
	}
	return errors.Join(directoryHandle.Sync(), directoryHandle.Close())
}

func syncMirrorlistParent(root, relative string) error {
	if err := validateServingRelativePath(relative); err != nil {
		return err
	}
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer rootHandle.Close()
	directory := filepath.Dir(filepath.FromSlash(relative))
	info, err := rootHandle.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.Join(err, errors.New("mirrorlist parent is not a real directory"))
	}
	handle, err := rootHandle.Open(directory)
	if err != nil {
		return err
	}
	return errors.Join(handle.Sync(), handle.Close())
}

func validateServingRelativePath(value string) error {
	if value == "" || filepath.IsAbs(value) || filepath.ToSlash(filepath.Clean(filepath.FromSlash(value))) != value || strings.HasPrefix(value, "../") || strings.ContainsAny(value, "\\\x00\t\r\n") {
		return errors.New("unsafe serving-relative path")
	}
	return nil
}
