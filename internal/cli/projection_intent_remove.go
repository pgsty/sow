package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/pgsty/sow/internal/state"
)

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
			return errors.Join(cause, restoreErr, syncErr, fmt.Errorf("projection intent replacement retained at %s", quarantine))
		}
		return errors.Join(cause, syncErr)
	}
	quarantined, lstatErr := root.Lstat(quarantine)
	opened, statErr := file.Stat()
	if lstatErr != nil || statErr != nil || quarantined == nil || opened == nil ||
		quarantined.Mode()&os.ModeSymlink != 0 || !quarantined.Mode().IsRegular() ||
		!os.SameFile(identity, quarantined) || !os.SameFile(identity, opened) {
		return restore(errors.Join(lstatErr, statErr, errors.New("projection intent changed before completion commit")))
	}
	lastBody, readErr := readExactOpenProjectionIntent(file, identity, maximum)
	if readErr != nil || !bytes.Equal(body, lastBody) {
		return restore(errors.Join(readErr, errors.New("projection intent bytes changed before completion commit")))
	}
	if err := directory.Sync(); err != nil {
		return restore(fmt.Errorf("sync projection intent completion commit: %w", err))
	}
	// The preceding directory sync is the completion commit. A later failure
	// can only leave a private, recognizable residue for --recover; it must not
	// turn a completed transaction back into a reported transaction failure.
	if err := root.Remove(quarantine); err == nil {
		_ = directory.Sync()
	}
	return nil
}

func bindExactProjectionIntent(root *os.Root, relative string, maximum int64) (*os.File, os.FileInfo, []byte, error) {
	if root == nil {
		return nil, nil, nil, errors.New("projection intent root is unavailable")
	}
	before, err := root.Lstat(relative)
	if err != nil || !privateExactProjectionIntent(before, maximum) {
		return nil, nil, nil, errors.Join(err, errors.New("projection intent is not a private exact regular file"))
	}
	file, err := root.Open(relative)
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
