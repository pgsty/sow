package plain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func bindPriorDirectories(root string, journal *operationJournal) error {
	hasRPMInstall := false
	for _, action := range journal.Actions {
		if isRPMPointerAction(*journal, action) {
			hasRPMInstall = true
			break
		}
	}
	if !hasRPMInstall {
		return nil
	}
	path := filepath.Join(root, "repodata")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		journal.Dirs = []priorDirectoryState{{Path: "repodata"}}
		return nil
	}
	if err != nil {
		return &Error{Kind: KindRuntime, Op: "inspect prior live directory", Path: path, Err: err}
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return &Error{Kind: KindIntegrity, Op: "inspect prior live directory", Path: path, Err: errors.New("repodata is not a real directory")}
	}
	journal.Dirs = []priorDirectoryState{{Path: "repodata", Exists: true}}
	return nil
}

// bindPriorFiles snapshots every live path that an install action may replace.
// The snapshots are durable before the operation journal becomes visible, so a
// normal (non-process-termination) failure can always restore the old public
// pointers instead of returning with a mixed RPM/DEB generation.
func bindPriorFiles(ctx context.Context, root string, journal *operationJournal) error {
	rollbackDir := filepath.Join(journal.Trash, "rollback")
	rollbackCreated := false
	for index := range journal.Actions {
		action := &journal.Actions[index]
		if action.Kind != "install" {
			continue
		}
		target, err := safePath(root, action.Target)
		if err != nil {
			return err
		}
		info, err := os.Lstat(target)
		if errors.Is(err, os.ErrNotExist) {
			action.Prior = &priorFileState{}
			continue
		}
		if err != nil {
			return &Error{Kind: KindRuntime, Op: "inspect prior live file", Path: target, Err: err}
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return &Error{Kind: KindIntegrity, Op: "inspect prior live file", Path: target, Err: errors.New("install target is not a regular file")}
		}
		if !rollbackCreated {
			bound, err := os.OpenRoot(root)
			if err != nil {
				return &Error{Kind: KindRuntime, Op: "bind rollback root", Path: root, Err: err}
			}
			createErr := ensureRealDirectoryRoot(bound, rollbackDir, 0o700)
			closeErr := bound.Close()
			if err := errors.Join(createErr, closeErr); err != nil {
				return err
			}
			rollbackCreated = true
		}
		backup := filepath.Join(rollbackDir, fmt.Sprintf("%06d", index))
		backupPath, err := safePath(root, backup)
		if err != nil {
			return err
		}
		var digest string
		if isSignedPackageAction(*journal, *action) {
			digest, err = linkSnapshot(ctx, target, backupPath, info)
		} else {
			digest, err = copySnapshot(ctx, target, backupPath, info)
		}
		if err != nil {
			return err
		}
		owner, err := ownershipFromInfo(info)
		if err != nil {
			return &Error{Kind: KindRuntime, Op: "inspect prior live ownership", Path: target, Err: err}
		}
		action.Prior = &priorFileState{
			Exists: true,
			SHA256: digest,
			Backup: backup,
			Mode:   encodePreservedFileMode(info.Mode()),
			UID:    uint32(owner.uid),
			GID:    uint32(owner.gid),
		}
	}
	return nil
}

// linkSnapshot retains the original RPM inode without copying a potentially
// multi-gigabyte package. The later atomic rename unlinks only the live name;
// this recovery hardlink remains an exact pre-image until journal cleanup.
func linkSnapshot(ctx context.Context, source, target string, before os.FileInfo) (_ string, resultErr error) {
	if err := os.Link(source, target); err != nil {
		return "", &Error{Kind: KindRuntime, Op: "link prior rpm", Path: target, Err: err}
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(target)
		}
	}()
	linked, err := os.Lstat(target)
	if err != nil || !linked.Mode().IsRegular() || linked.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, linked) {
		return "", &Error{Kind: KindIntegrity, Op: "bind prior rpm link", Path: target, Err: errors.Join(err, errors.New("recovery link does not bind the live RPM inode"))}
	}
	digest, err := hashFile(ctx, target)
	if err != nil {
		return "", err
	}
	after, err := os.Lstat(source)
	if err != nil || !after.Mode().IsRegular() || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return "", &Error{Kind: KindIntegrity, Op: "bind prior rpm link", Path: source, Err: errors.Join(err, errors.New("live RPM changed while linking recovery pre-image"))}
	}
	if err := syncDir(filepath.Dir(target)); err != nil {
		return "", &Error{Kind: KindRuntime, Op: "sync prior rpm link", Path: filepath.Dir(target), Err: err}
	}
	ok = true
	return digest, nil
}

func copySnapshot(ctx context.Context, source, target string, before os.FileInfo) (_ string, resultErr error) {
	src, err := os.Open(source)
	if err != nil {
		return "", &Error{Kind: KindRuntime, Op: "open prior live file", Path: source, Err: err}
	}
	defer func() { resultErr = errors.Join(resultErr, src.Close()) }()
	opened, err := src.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return "", &Error{Kind: KindIntegrity, Op: "bind prior live file", Path: source, Err: errors.Join(err, errors.New("live file changed while opening"))}
	}
	// Recovery evidence is private state. Keep it owner-readable regardless of
	// the public pointer's original mode; that mode is recorded separately and
	// restored only when the pre-image is reinstalled.
	dst, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", &Error{Kind: KindRuntime, Op: "create rollback snapshot", Path: target, Err: err}
	}
	ok := false
	defer func() {
		_ = dst.Close()
		if !ok {
			_ = os.Remove(target)
		}
	}()
	h := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(dst, h), &contextReader{ctx: ctx, reader: src})
	syncErr := dst.Sync()
	closeErr := dst.Close()
	after, statErr := os.Lstat(source)
	if err := errors.Join(copyErr, syncErr, closeErr, statErr); err != nil {
		return "", &Error{Kind: KindRuntime, Op: "persist rollback snapshot", Path: target, Err: err}
	}
	if !after.Mode().IsRegular() || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return "", &Error{Kind: KindIntegrity, Op: "bind prior live file", Path: source, Err: errors.New("live file changed while snapshotting")}
	}
	if err := syncDir(filepath.Dir(target)); err != nil {
		return "", &Error{Kind: KindRuntime, Op: "sync rollback snapshot", Path: filepath.Dir(target), Err: err}
	}
	ok = true
	return hex.EncodeToString(h.Sum(nil)), nil
}

func validatePriorPlan(root string, journal operationJournal) error {
	invalid := func(detail string) error {
		return &Error{Kind: KindIntegrity, Op: "validate rollback plan", Path: root, Err: errors.New(detail)}
	}
	for index, action := range journal.Actions {
		if action.Kind == "move" {
			if action.Prior != nil {
				return invalid("move action unexpectedly carries an install pre-image")
			}
			continue
		}
		if action.Prior == nil {
			return invalid("install action has no pre-image state")
		}
		prior := action.Prior
		if !prior.Exists {
			if prior.SHA256 != "" || prior.Backup != "" || prior.Mode != 0 || prior.UID != 0 || prior.GID != 0 {
				return invalid("absent install pre-image carries file evidence")
			}
			continue
		}
		wantBackup := filepath.Join(journal.Trash, "rollback", fmt.Sprintf("%06d", index))
		if !validSHA256(prior.SHA256) || prior.Backup != wantBackup || prior.Mode > 0o7777 {
			return invalid("install pre-image evidence is malformed")
		}
		if _, err := safePath(root, prior.Backup); err != nil {
			return err
		}
	}
	return validatePriorDirectoryPlan(root, journal)
}

func validatePriorDirectoryPlan(root string, journal operationJournal) error {
	invalid := func(detail string) error {
		return &Error{Kind: KindIntegrity, Op: "validate rollback directory plan", Path: root, Err: errors.New(detail)}
	}
	hasRPMInstall := false
	for _, action := range journal.Actions {
		if isRPMPointerAction(journal, action) {
			hasRPMInstall = true
			break
		}
	}
	if !hasRPMInstall {
		if len(journal.Dirs) != 0 {
			return invalid("journal binds a public directory that no action can create")
		}
		return nil
	}
	if len(journal.Dirs) != 1 || journal.Dirs[0].Path != "repodata" {
		return invalid("RPM install has no exact repodata directory pre-image")
	}
	if _, err := safePath(root, journal.Dirs[0].Path); err != nil {
		return err
	}
	if !journal.Dirs[0].Exists {
		for _, action := range journal.Actions {
			if action.Kind == "install" && filepath.Dir(action.Target) == "repodata" && action.Prior.Exists {
				return invalid("absent repodata pre-image contains an existing file pre-image")
			}
		}
	}
	return nil
}

func validateRollbackEvidence(ctx context.Context, bound *os.Root, root string, journal operationJournal) error {
	for _, action := range journal.Actions {
		if action.Kind != "install" || action.Prior == nil || !action.Prior.Exists {
			continue
		}
		digest, exists, err := existingDigestRoot(ctx, bound, action.Prior.Backup)
		if err != nil {
			return err
		}
		if !exists || digest != action.Prior.SHA256 {
			return &Error{Kind: KindIntegrity, Op: "verify rollback snapshot", Path: filepath.Join(root, action.Prior.Backup), Err: errors.New("durable pre-image is missing or changed")}
		}
	}
	return nil
}

func confirmCommittedDurable(ctx context.Context, root string, journal *operationJournal) (bool, error) {
	bound, err := os.OpenRoot(root)
	if err != nil {
		return false, &Error{Kind: KindRuntime, Op: "bind committed state", Path: root, Err: err}
	}
	defer bound.Close()
	committed, err := committedJournalState(ctx, bound, journal)
	if err != nil || !committed {
		return committed, err
	}
	directories := map[string]struct{}{".": {}}
	for _, action := range journal.Actions {
		directories[filepath.Dir(action.Source)] = struct{}{}
		directories[filepath.Dir(action.Target)] = struct{}{}
	}
	for directory := range directories {
		if directory != "." {
			info, err := bound.Lstat(directory)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return false, &Error{Kind: KindIntegrity, Op: "sync committed state", Path: filepath.Join(root, directory), Err: errors.Join(err, errors.New("action parent is not a real directory"))}
			}
		}
		if err := syncRootDir(bound, directory); err != nil {
			return false, &Error{Kind: KindRuntime, Op: "sync committed state", Path: filepath.Join(root, directory), Err: err}
		}
	}
	return true, nil
}

func rollbackJournal(ctx context.Context, root string, journal operationJournal) error {
	bound, err := os.OpenRoot(root)
	if err != nil {
		return &Error{Kind: KindRuntime, Op: "bind rollback root", Path: root, Err: err}
	}
	defer bound.Close()
	if err := validateRollbackEvidence(ctx, bound, root, journal); err != nil {
		return err
	}
	for index := len(journal.Actions) - 1; index >= 0; index-- {
		if err := ctx.Err(); err != nil {
			return &Error{Kind: KindRuntime, Op: "rollback", Path: root, Err: err}
		}
		action := journal.Actions[index]
		if action.Kind == "install" {
			if err := rollbackInstall(ctx, bound, root, action); err != nil {
				return err
			}
			continue
		}
		if err := rollbackMove(ctx, bound, root, journal, action); err != nil {
			return err
		}
	}
	if err := removeCreatedDirectories(bound, root, journal); err != nil {
		return err
	}
	if err := verifyRolledBackState(ctx, bound, root, journal); err != nil {
		return err
	}
	if err := bound.Close(); err != nil {
		return &Error{Kind: KindRuntime, Op: "close rollback root", Path: root, Err: err}
	}
	return cleanupRolledBackJournal(root, journal)
}

func removeCreatedDirectories(bound *os.Root, root string, journal operationJournal) error {
	for index := len(journal.Dirs) - 1; index >= 0; index-- {
		prior := journal.Dirs[index]
		if prior.Exists {
			continue
		}
		info, err := bound.Lstat(prior.Path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return &Error{Kind: KindIntegrity, Op: "remove rolled-back directory", Path: filepath.Join(root, prior.Path), Err: errors.Join(err, errors.New("created path is not a real directory"))}
		}
		directory, err := bound.Open(prior.Path)
		if err != nil {
			return &Error{Kind: KindRuntime, Op: "inspect rolled-back directory", Path: filepath.Join(root, prior.Path), Err: err}
		}
		entries, readErr := directory.ReadDir(1)
		closeErr := directory.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return &Error{Kind: KindRuntime, Op: "inspect rolled-back directory", Path: filepath.Join(root, prior.Path), Err: errors.Join(readErr, closeErr)}
		}
		if closeErr != nil {
			return &Error{Kind: KindRuntime, Op: "close rolled-back directory", Path: filepath.Join(root, prior.Path), Err: closeErr}
		}
		if len(entries) != 0 {
			return &Error{Kind: KindIntegrity, Op: "remove rolled-back directory", Path: filepath.Join(root, prior.Path), Err: errors.New("created directory contains an unjournaled entry")}
		}
		if err := bound.Remove(prior.Path); err != nil {
			return &Error{Kind: KindRuntime, Op: "remove rolled-back directory", Path: filepath.Join(root, prior.Path), Err: err}
		}
		if err := syncRootDir(bound, filepath.Dir(prior.Path)); err != nil {
			return &Error{Kind: KindRuntime, Op: "sync rolled-back directory removal", Path: filepath.Dir(filepath.Join(root, prior.Path)), Err: err}
		}
	}
	return nil
}

func rollbackInstall(ctx context.Context, bound *os.Root, root string, action fileAction) error {
	prior := action.Prior
	if prior == nil {
		return &Error{Kind: KindIntegrity, Op: "rollback install", Path: action.Target, Err: errors.New("install action has no pre-image")}
	}
	currentDigest, currentExists, err := existingDigestRoot(ctx, bound, action.Target)
	if err != nil {
		return err
	}
	if !prior.Exists {
		if !currentExists {
			return nil
		}
		if currentDigest != action.SHA256 {
			return &Error{Kind: KindIntegrity, Op: "rollback new file", Path: action.Target, Err: errors.New("live file is neither the installed generation nor the absent pre-image")}
		}
		if err := bound.Remove(action.Target); err != nil {
			return &Error{Kind: KindRuntime, Op: "remove rolled-back file", Path: filepath.Join(root, action.Target), Err: err}
		}
		if err := syncRootDir(bound, filepath.Dir(action.Target)); err != nil {
			return &Error{Kind: KindRuntime, Op: "sync rolled-back removal", Path: filepath.Dir(filepath.Join(root, action.Target)), Err: err}
		}
		return nil
	}
	if currentExists && currentDigest != action.SHA256 && currentDigest != prior.SHA256 {
		return &Error{Kind: KindIntegrity, Op: "rollback replaced file", Path: action.Target, Err: errors.New("live file changed outside the journal")}
	}
	return restoreSnapshot(ctx, bound, root, *prior, action.Target)
}

func restoreSnapshot(ctx context.Context, bound *os.Root, root string, prior priorFileState, target string) (_ error) {
	digest, exists, err := existingDigestRoot(ctx, bound, prior.Backup)
	if err != nil {
		return err
	}
	if !exists || digest != prior.SHA256 {
		return &Error{Kind: KindIntegrity, Op: "restore rollback snapshot", Path: filepath.Join(root, prior.Backup), Err: errors.New("pre-image is missing or changed")}
	}
	if info, err := bound.Lstat(target); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return &Error{Kind: KindIntegrity, Op: "restore rollback snapshot", Path: filepath.Join(root, target), Err: errors.New("rollback target is not a regular file")}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return &Error{Kind: KindRuntime, Op: "inspect rollback target", Path: filepath.Join(root, target), Err: err}
	}
	parent := filepath.Dir(target)
	if err := validateRealDirectoryRoot(bound, parent); err != nil {
		return err
	}
	absParent, err := safeDirectoryPath(root, parent)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(absParent, ".sow-plain-rollback-")
	if err != nil {
		return &Error{Kind: KindRuntime, Op: "create rollback replacement", Path: absParent, Err: err}
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	snapshot, err := bound.Open(prior.Backup)
	if err != nil {
		return &Error{Kind: KindRuntime, Op: "open rollback snapshot", Path: filepath.Join(root, prior.Backup), Err: err}
	}
	h := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(tmp, h), &contextReader{ctx: ctx, reader: snapshot})
	closeSnapshotErr := snapshot.Close()
	chownErr := tmp.Chown(int(prior.UID), int(prior.GID))
	chmodErr := tmp.Chmod(decodePreservedFileMode(prior.Mode))
	syncErr := tmp.Sync()
	closeErr := tmp.Close()
	if err := errors.Join(copyErr, closeSnapshotErr, chownErr, chmodErr, syncErr, closeErr); err != nil {
		return &Error{Kind: KindRuntime, Op: "write rollback replacement", Path: tmpName, Err: err}
	}
	if hex.EncodeToString(h.Sum(nil)) != prior.SHA256 {
		return &Error{Kind: KindIntegrity, Op: "restore rollback snapshot", Path: filepath.Join(root, prior.Backup), Err: errors.New("pre-image changed while restoring")}
	}
	if err := os.Rename(tmpName, filepath.Join(root, target)); err != nil {
		return &Error{Kind: KindRuntime, Op: "install rollback snapshot", Path: filepath.Join(root, target), Err: err}
	}
	if err := syncRootDir(bound, parent); err != nil {
		return &Error{Kind: KindRuntime, Op: "sync rollback snapshot", Path: absParent, Err: err}
	}
	ok = true
	return nil
}

func rollbackMove(ctx context.Context, bound *os.Root, root string, journal operationJournal, action fileAction) error {
	sourceDigest, sourceExists, err := existingDigestRoot(ctx, bound, action.Source)
	if err != nil {
		return err
	}
	if sourceExists {
		if sourceDigest != action.SHA256 {
			return &Error{Kind: KindIntegrity, Op: "rollback move", Path: action.Source, Err: errors.New("restored source bytes changed")}
		}
		// Rename cannot leave both names behind. For ordinary moves the live
		// source alone proves that the action never committed; any unusable
		// recovery subtree is private residue and cleanup may remove it. The old
		// marker is the one exception because the final marker restore can
		// deliberately recreate its live source before this reverse action.
		if !isOldMarkerAction(journal, action) {
			return nil
		}
		targetDigest, targetExists, err := existingDigestRoot(ctx, bound, action.Target)
		if err != nil {
			return err
		}
		if !targetExists {
			return nil
		}
		if targetDigest != action.SHA256 {
			return &Error{Kind: KindIntegrity, Op: "rollback move", Path: action.Target, Err: errors.New("source and recovery target both exist")}
		}
		if err := bound.Remove(action.Target); err != nil {
			return &Error{Kind: KindRuntime, Op: "remove duplicate old marker", Path: filepath.Join(root, action.Target), Err: err}
		}
		return syncRootDir(bound, filepath.Dir(action.Target))
	}
	targetDigest, targetExists, err := existingDigestRoot(ctx, bound, action.Target)
	if err != nil {
		return err
	}
	if !targetExists || targetDigest != action.SHA256 {
		return &Error{Kind: KindIntegrity, Op: "rollback move", Path: action.Target, Err: errors.New("recovery source is missing or changed")}
	}
	if err := ensureRealDirectoryRoot(bound, filepath.Dir(action.Source), 0o755); err != nil {
		return err
	}
	if err := bound.Rename(action.Target, action.Source); err != nil {
		return &Error{Kind: KindRuntime, Op: "restore moved file", Path: filepath.Join(root, action.Source), Err: err}
	}
	if err := syncRootDir(bound, filepath.Dir(action.Source)); err != nil {
		return &Error{Kind: KindRuntime, Op: "sync restored file", Path: filepath.Dir(filepath.Join(root, action.Source)), Err: err}
	}
	if filepath.Dir(action.Source) != filepath.Dir(action.Target) {
		if err := syncRootDir(bound, filepath.Dir(action.Target)); err != nil {
			return &Error{Kind: KindRuntime, Op: "sync recovery move", Path: filepath.Dir(filepath.Join(root, action.Target)), Err: err}
		}
	}
	return nil
}

func verifyRolledBackState(ctx context.Context, bound *os.Root, root string, journal operationJournal) error {
	for _, action := range journal.Actions {
		if action.Kind == "install" {
			digest, exists, err := existingDigestRoot(ctx, bound, action.Target)
			if err != nil {
				return err
			}
			if action.Prior.Exists != exists || (exists && digest != action.Prior.SHA256) {
				return &Error{Kind: KindIntegrity, Op: "verify rolled-back install", Path: filepath.Join(root, action.Target), Err: errors.New("live state differs from the pre-image")}
			}
			continue
		}
		sourceDigest, sourceExists, err := existingDigestRoot(ctx, bound, action.Source)
		if err != nil {
			return err
		}
		if !sourceExists || sourceDigest != action.SHA256 {
			return &Error{Kind: KindIntegrity, Op: "verify rolled-back move", Path: filepath.Join(root, action.Source), Err: errors.New("moved live file was not restored exactly")}
		}
		if isOldMarkerAction(journal, action) {
			_, targetExists, err := existingDigestRoot(ctx, bound, action.Target)
			if err != nil {
				return err
			}
			if targetExists {
				return &Error{Kind: KindIntegrity, Op: "verify rolled-back move", Path: filepath.Join(root, action.Target), Err: errors.New("old marker recovery copy remains live")}
			}
		}
	}
	for _, prior := range journal.Dirs {
		info, err := bound.Lstat(prior.Path)
		if !prior.Exists {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return &Error{Kind: KindIntegrity, Op: "verify rolled-back directory", Path: filepath.Join(root, prior.Path), Err: errors.Join(err, errors.New("directory created by the failed operation remains"))}
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return &Error{Kind: KindIntegrity, Op: "verify rolled-back directory", Path: filepath.Join(root, prior.Path), Err: errors.Join(err, errors.New("pre-existing directory was not preserved"))}
		}
	}
	return syncDir(root)
}

func cleanupRolledBackJournal(root string, journal operationJournal) error {
	bound, err := os.OpenRoot(root)
	if err != nil {
		return &Error{Kind: KindRuntime, Op: "bind rollback cleanup root", Path: root, Err: err}
	}
	defer bound.Close()
	withdrawn := filepath.Join(journal.Trash, "rolled-back-journal")
	if err := bound.Rename(journalFilename, withdrawn); err != nil {
		return &Error{Kind: KindRuntime, Op: "withdraw rolled-back journal", Path: filepath.Join(root, journalFilename), Err: err}
	}
	if err := errors.Join(syncRootDir(bound, "."), syncRootDir(bound, journal.Trash)); err != nil {
		return &Error{Kind: KindRuntime, Op: "sync rolled-back journal withdrawal", Path: root, Err: err}
	}
	for _, relative := range []string{journal.Stage, journal.Trash} {
		info, err := bound.Lstat(relative)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return &Error{Kind: KindIntegrity, Op: "clean rolled-back operation", Path: filepath.Join(root, relative), Err: errors.Join(err, errors.New("operation path is not a real directory"))}
		}
		if err := bound.RemoveAll(relative); err != nil {
			return &Error{Kind: KindRuntime, Op: "clean rolled-back operation", Path: filepath.Join(root, relative), Err: err}
		}
	}
	if err := syncRootDir(bound, "."); err != nil {
		return &Error{Kind: KindRuntime, Op: "sync rolled-back cleanup", Path: root, Err: err}
	}
	return nil
}

func safeDirectoryPath(root, relative string) (string, error) {
	if relative == "." {
		return root, nil
	}
	return safePath(root, relative)
}
