package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/pgsty/sow/internal/manifest"
)

type archiveResult struct {
	Path    string
	Stage   string
	Entries int64
	Bytes   int64
	Size    int64
	SHA256  string
}

type archiveCommitLifecycle struct {
	Precommit func(archiveResult) error
	Complete  func(archiveResult) error
}

// archiveDestinationBeforeBindHook is a deterministic test seam for replacing
// a validated destination parent immediately before capability binding.
// Production never sets it.
var archiveDestinationBeforeBindHook func(string)

// archiveBeforeTaintPrecommitHook is a deterministic test seam after the
// complete archive has been fsynced inside the private state transaction but
// before its digest-level taint receipt is committed. Production never sets
// it. A failure here must leave no bytes at the operator-visible destination.
var archiveBeforeTaintPrecommitHook func(archiveResult) error

// archiveBeforeAtomicInstallHook is a deterministic test seam after the taint
// receipt is durable and immediately before the private inode is linked at its
// final operator-visible name. A process stop here must leave no staging name
// anywhere in the directly served tree.
var archiveBeforeAtomicInstallHook func(archiveResult) error

// archiveAfterAtomicInstallHook and archiveAfterDestinationSyncHook bracket
// the two durable-publication boundaries after the final no-clobber link. They
// are deterministic crash/error seams only; production leaves both nil.
var archiveAfterAtomicInstallHook func(archiveResult) error
var archiveAfterDestinationSyncHook func(archiveResult) error

// archiveDirectorySync is replaceable only by focused tests that assert each
// newly-created directory entry is made durable before traversal continues.
var archiveDirectorySync = syncBoundArchiveDirectory

// archiveFilesystemIdentity is a test seam around the platform device check.
// Linux and Darwin production implementations compare st_dev.
var archiveFilesystemIdentity = sameArchiveFilesystem

// writeDeterministicTGZWithPrecommit keeps the completed archive in the private
// state transaction until precommit has durably recorded its digest-level
// taint. The final cross-directory hard-link install is atomic and no-clobber;
// no complete or partial staging name is ever created in the directly served
// destination parent. Idempotent replay accepts an already-present
// byte-identical destination.
func writeDeterministicTGZWithPrecommit(ctx context.Context, materializedRoot, manifestPath, destination string, allowInsideRoot bool, privateStageDir, marker string, precommit func(archiveResult) error) (archiveResult, error) {
	return writeDeterministicTGZWithLifecycle(ctx, materializedRoot, manifestPath, destination, allowInsideRoot, privateStageDir, marker, archiveCommitLifecycle{Precommit: precommit})
}

// writeDeterministicTGZWithLifecycle extends the precommit boundary with a
// completion callback. Materialize uses it to retain a durable, exact archive
// operation intent until the final hard link, destination directory fsync, and
// private-stage cleanup have all converged. Simpler callers keep using the
// precommit wrapper above.
func writeDeterministicTGZWithLifecycle(ctx context.Context, materializedRoot, manifestPath, destination string, allowInsideRoot bool, privateStageDir, marker string, lifecycle archiveCommitLifecycle) (archiveResult, error) {
	var result archiveResult
	if destination == "" {
		return result, errors.New("archive destination is empty")
	}
	rootAbs, err := archiveAbsolutePath(materializedRoot)
	if err != nil {
		return result, err
	}
	destinationAbs, err := archiveAbsolutePath(destination)
	if err != nil {
		return result, err
	}
	inside, err := filepath.Rel(rootAbs, destinationAbs)
	if !allowInsideRoot && err == nil && inside != ".." && !strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
		return result, errors.New("archive destination must be outside the materialized tree")
	}
	privateStageAbs, err := archiveAbsolutePath(privateStageDir)
	if err != nil {
		return result, err
	}
	privateRoot, privateIdentity, err := bindPrivateArchiveStage(privateStageAbs)
	if err != nil {
		return result, err
	}
	defer privateRoot.Close()
	// Fail before compressing source bytes or committing a taint receipt when an
	// atomic hard-link install cannot possibly succeed. The nearest existing
	// destination ancestor is sufficient: no mount point can exist beneath a
	// path component that does not yet exist.
	if err := preflightArchiveAtomicFilesystem(privateIdentity, filepath.Dir(destinationAbs)); err != nil {
		return result, err
	}
	temporaryName, temporary, err := createBoundArchiveTemp(privateRoot)
	if err != nil {
		return result, err
	}
	temporaryOpen := true
	temporaryPresent := true
	defer func() {
		if temporaryOpen {
			temporary.Close()
		}
		if temporaryPresent {
			privateRoot.Remove(temporaryName)
		}
	}()
	archiveHash := sha256.New()
	gzipWriter, err := gzip.NewWriterLevel(io.MultiWriter(temporary, archiveHash), gzip.BestCompression)
	if err != nil {
		return result, err
	}
	gzipWriter.Header.ModTime = time.Unix(0, 0).UTC()
	gzipWriter.Header.OS = 255
	var payloadMarker []byte
	if marker != "" {
		parsed, markerErr := parseOfflineArchiveMarker(marker)
		if markerErr != nil || parsed == nil {
			return result, errors.Join(markerErr, errors.New("offline archive gzip marker is invalid"), gzipWriter.Close())
		}
		payloadMarker, markerErr = offlineArchivePayloadMarkerForComment(marker)
		if markerErr != nil {
			return result, errors.Join(markerErr, gzipWriter.Close())
		}
		gzipWriter.Header.Comment = marker
	}
	tarWriter := tar.NewWriter(gzipWriter)
	if len(payloadMarker) != 0 {
		header := &tar.Header{
			Name: offlineArchivePayloadMarkerPath, Mode: 0o444, Size: int64(len(payloadMarker)), Typeflag: tar.TypeReg,
			ModTime: time.Unix(0, 0).UTC(), AccessTime: time.Time{}, ChangeTime: time.Time{},
			Uid: 0, Gid: 0, Uname: "", Gname: "", Format: tar.FormatUSTAR,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return result, errors.Join(err, tarWriter.Close(), gzipWriter.Close())
		}
		if _, err := tarWriter.Write(payloadMarker); err != nil {
			return result, errors.Join(err, tarWriter.Close(), gzipWriter.Close())
		}
	}
	manifestFile, err := os.Open(manifestPath)
	if err != nil {
		return result, errors.Join(err, tarWriter.Close(), gzipWriter.Close())
	}
	reader := manifest.NewReader(manifestFile)
	for {
		if err := ctx.Err(); err != nil {
			return result, errors.Join(err, manifestFile.Close(), tarWriter.Close(), gzipWriter.Close())
		}
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return result, errors.Join(err, manifestFile.Close(), tarWriter.Close(), gzipWriter.Close())
		}
		if len(payloadMarker) != 0 && offlineArchivePayloadMarkerPathEquivalent(entry.Path) {
			return result, errors.Join(manifestFile.Close(), tarWriter.Close(), gzipWriter.Close(), errors.New("materialized manifest collides with the reserved offline archive payload marker"))
		}
		if allowInsideRoot && filepath.ToSlash(inside) == entry.Path {
			return result, errors.Join(manifestFile.Close(), tarWriter.Close(), gzipWriter.Close(), errors.New("archive destination is present in the exact materialized manifest"))
		}
		filename := filepath.Join(rootAbs, filepath.FromSlash(entry.Path))
		info, err := os.Lstat(filename)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() != entry.Size {
			return result, errors.Join(err, manifestFile.Close(), tarWriter.Close(), gzipWriter.Close(), fmt.Errorf("archive source %s is not the expected regular file", entry.Path))
		}
		file, err := os.Open(filename)
		if err != nil {
			return result, errors.Join(err, manifestFile.Close(), tarWriter.Close(), gzipWriter.Close())
		}
		opened, err := file.Stat()
		if err != nil || !os.SameFile(info, opened) {
			file.Close()
			return result, errors.Join(err, manifestFile.Close(), tarWriter.Close(), gzipWriter.Close(), fmt.Errorf("archive source %s changed while opening", entry.Path))
		}
		header := &tar.Header{
			Name: entry.Path, Mode: 0o444, Size: entry.Size, Typeflag: tar.TypeReg,
			ModTime: time.Unix(0, 0).UTC(), AccessTime: time.Time{}, ChangeTime: time.Time{},
			Uid: 0, Gid: 0, Uname: "", Gname: "", Format: tar.FormatPAX,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			file.Close()
			return result, errors.Join(err, manifestFile.Close(), tarWriter.Close(), gzipWriter.Close())
		}
		objectHash := sha256.New()
		written, copyErr := io.CopyBuffer(io.MultiWriter(tarWriter, objectHash), io.LimitReader(file, entry.Size+1), make([]byte, 256*1024))
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || written != entry.Size || !bytes.Equal(objectHash.Sum(nil), entry.SHA256[:]) {
			return result, errors.Join(copyErr, closeErr, manifestFile.Close(), tarWriter.Close(), gzipWriter.Close(), fmt.Errorf("archive source %s failed content verification", entry.Path))
		}
		result.Entries++
		result.Bytes += entry.Size
	}
	// The enclosing state transaction is mode 0700, so the completed private
	// inode can already carry its final 0444 mode without becoming reachable.
	// The atomic hard link below then publishes the final mode and bytes at once.
	if err := errors.Join(manifestFile.Close(), tarWriter.Close(), gzipWriter.Close(), temporary.Sync(), temporary.Chmod(0o444), temporary.Sync()); err != nil {
		return result, err
	}
	temporaryInfo, err := temporary.Stat()
	if err != nil || !temporaryInfo.Mode().IsRegular() {
		return result, errors.Join(err, errors.New("completed archive staging file is not regular"))
	}
	if err := temporary.Close(); err != nil {
		return result, err
	}
	temporaryOpen = false
	result.Path, result.Stage, result.Size, result.SHA256 = destinationAbs, filepath.Join(privateStageAbs, temporaryName), temporaryInfo.Size(), fmt.Sprintf("%x", archiveHash.Sum(nil))
	if archiveBeforeTaintPrecommitHook != nil {
		if err := archiveBeforeTaintPrecommitHook(result); err != nil {
			return result, fmt.Errorf("before offline archive taint precommit: %w", err)
		}
	}
	if lifecycle.Precommit != nil {
		if err := lifecycle.Precommit(result); err != nil {
			return result, fmt.Errorf("commit offline archive taint before visibility: %w", err)
		}
	}
	if archiveBeforeAtomicInstallHook != nil {
		if err := archiveBeforeAtomicInstallHook(result); err != nil {
			return result, fmt.Errorf("before atomic offline archive installation: %w", err)
		}
	}
	if err := requireBoundArchiveDirectory(privateStageAbs, privateRoot, privateIdentity); err != nil {
		return result, fmt.Errorf("private archive stage changed before installation: %w", err)
	}
	destinationParent := filepath.Dir(destinationAbs)
	destinationName := filepath.Base(destinationAbs)
	destinationRoot, destinationIdentity, err := bindArchiveDestinationParent(destinationParent)
	if err != nil {
		return result, err
	}
	defer destinationRoot.Close()
	if info, err := destinationRoot.Lstat(destinationName); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return result, errors.New("archive destination is not a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return result, err
	}
	if err := requireBoundArchiveDestinationParent(destinationParent, destinationRoot, destinationIdentity); err != nil {
		return result, err
	}
	if err := installBoundArchiveNoClobber(privateRoot, temporaryName, destinationRoot, destinationName, result); err != nil {
		return result, err
	}
	if archiveAfterAtomicInstallHook != nil {
		if err := archiveAfterAtomicInstallHook(result); err != nil {
			return result, fmt.Errorf("after atomic offline archive installation: %w", err)
		}
	}
	if err := archiveDirectorySync(destinationRoot); err != nil {
		return result, err
	}
	if archiveAfterDestinationSyncHook != nil {
		if err := archiveAfterDestinationSyncHook(result); err != nil {
			return result, fmt.Errorf("after offline archive destination sync: %w", err)
		}
	}
	if err := requireBoundArchiveDestinationParent(destinationParent, destinationRoot, destinationIdentity); err != nil {
		return result, err
	}
	if err := requireBoundArchiveFile(destinationRoot, destinationName, result); err != nil {
		return result, err
	}
	if err := privateRoot.Remove(temporaryName); err != nil {
		return result, err
	}
	if err := archiveDirectorySync(privateRoot); err != nil {
		return result, fmt.Errorf("sync private archive stage after cleanup: %w", err)
	}
	temporaryPresent = false
	if lifecycle.Complete != nil {
		if err := lifecycle.Complete(result); err != nil {
			return result, fmt.Errorf("complete offline archive durable intent: %w", err)
		}
	}
	return result, nil
}

func bindArchiveDestinationParent(parent string) (*os.Root, os.FileInfo, error) {
	if archiveDestinationBeforeBindHook != nil {
		archiveDestinationBeforeBindHook(parent)
	}
	return walkAbsoluteArchiveDirectory(parent, true)
}

func preflightArchiveAtomicFilesystem(private os.FileInfo, destinationParent string) error {
	ancestor, identity, err := bindNearestExistingArchiveDirectory(destinationParent)
	if err != nil {
		return fmt.Errorf("bind nearest existing archive destination ancestor: %w", err)
	}
	defer ancestor.Close()
	same, err := archiveFilesystemIdentity(private, identity)
	if err != nil {
		return fmt.Errorf("compare archive staging and destination filesystems: %w", err)
	}
	if !same {
		return errors.New("atomic offline archive publication requires the private state and destination to share a filesystem")
	}
	return nil
}

func bindNearestExistingArchiveDirectory(directory string) (*os.Root, os.FileInfo, error) {
	candidate := filepath.Clean(directory)
	for {
		root, identity, err := walkAbsoluteArchiveDirectory(candidate, false)
		if err == nil {
			return root, identity, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, nil, err
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			return nil, nil, err
		}
		candidate = parent
	}
}

func requireBoundArchiveDestinationParent(parent string, root *os.Root, expected os.FileInfo) error {
	return requireBoundArchiveDirectory(parent, root, expected)
}

func bindPrivateArchiveStage(directory string) (*os.Root, os.FileInfo, error) {
	root, identity, err := walkAbsoluteArchiveDirectory(directory, false)
	if err != nil {
		return nil, nil, err
	}
	if identity.Mode().Perm()&0o077 != 0 {
		root.Close()
		return nil, nil, errors.New("private archive stage directory is accessible by group or others")
	}
	return root, identity, nil
}

func requireBoundArchiveDirectory(directory string, root *os.Root, expected os.FileInfo) error {
	if root == nil || expected == nil {
		return errors.New("archive destination directory capability is unavailable")
	}
	opened, openErr := root.Stat(".")
	verified, current, pathErr := walkAbsoluteArchiveDirectory(directory, false)
	if verified != nil {
		defer verified.Close()
	}
	if openErr != nil || pathErr != nil || current == nil || !os.SameFile(expected, opened) || !os.SameFile(expected, current) {
		return errors.Join(openErr, pathErr, errors.New("archive directory path changed after validation"))
	}
	return nil
}

// walkAbsoluteArchiveDirectory starts from the already-open filesystem root
// and traverses one path segment at a time. Every create/open is fd-relative;
// symlinks and non-directories are rejected at each segment. The returned Root
// remains bound even if an ancestor is renamed later.
func walkAbsoluteArchiveDirectory(directory string, create bool) (*os.Root, os.FileInfo, error) {
	clean := filepath.Clean(directory)
	if !filepath.IsAbs(clean) {
		return nil, nil, errors.New("archive directory path is not absolute")
	}
	current, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, nil, err
	}
	segments := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	if clean == string(filepath.Separator) {
		segments = nil
	}
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			current.Close()
			return nil, nil, errors.New("archive directory contains an unsafe path segment")
		}
		before, statErr := current.Lstat(segment)
		if errors.Is(statErr, os.ErrNotExist) && create {
			if err := current.Mkdir(segment, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
				current.Close()
				return nil, nil, err
			}
			// fsync the directory that owns the new entry before descending. A
			// successful archive command must not depend on unsynced parent names.
			if err := archiveDirectorySync(current); err != nil {
				current.Close()
				return nil, nil, fmt.Errorf("sync archive directory after creating %s: %w", segment, err)
			}
			before, statErr = current.Lstat(segment)
		}
		if statErr != nil || before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
			current.Close()
			return nil, nil, errors.Join(statErr, fmt.Errorf("archive directory segment %s is not a real directory", segment))
		}
		next, openErr := current.OpenRoot(segment)
		after, afterErr := current.Lstat(segment)
		if openErr != nil || afterErr != nil {
			if next != nil {
				next.Close()
			}
			current.Close()
			return nil, nil, errors.Join(openErr, afterErr)
		}
		opened, openedErr := next.Stat(".")
		if openedErr != nil || after.Mode()&os.ModeSymlink != 0 || !after.IsDir() || !os.SameFile(before, after) || !os.SameFile(before, opened) {
			next.Close()
			current.Close()
			return nil, nil, errors.Join(openedErr, errors.New("archive directory segment changed while binding"))
		}
		current.Close()
		current = next
	}
	identity, err := current.Stat(".")
	if err != nil {
		current.Close()
		return nil, nil, err
	}
	return current, identity, nil
}

func createBoundArchiveTemp(root *os.Root) (string, *os.File, error) {
	for attempt := 0; attempt < 32; attempt++ {
		var random [12]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", nil, err
		}
		name := ".sow-archive-" + hex.EncodeToString(random[:]) + ".tgz"
		file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		return name, file, err
	}
	return "", nil, errors.New("cannot allocate unique bound archive staging file")
}

func archiveAbsolutePath(value string) (string, error) {
	absolute, err := filepath.Abs(value)
	if err != nil {
		return "", err
	}
	absolute = filepath.Clean(absolute)
	// Darwin exposes these root-owned compatibility symlinks on every normal
	// installation. Canonicalize only the fixed OS aliases; user-controlled
	// components remain subject to the segment-by-segment no-follow walk.
	if runtime.GOOS == "darwin" {
		for _, alias := range []string{"/var", "/tmp", "/etc"} {
			if absolute == alias || strings.HasPrefix(absolute, alias+string(filepath.Separator)) {
				absolute = "/private" + absolute
				break
			}
		}
	}
	return absolute, nil
}

func installBoundArchiveNoClobber(sourceRoot *os.Root, source string, destinationRoot *os.Root, destination string, expected archiveResult) error {
	if sourceRoot == nil || destinationRoot == nil {
		return errors.New("archive installation capabilities are unavailable")
	}
	if err := requireBoundArchiveFile(sourceRoot, source, expected); err != nil {
		return fmt.Errorf("private archive stage changed before atomic installation: %w", err)
	}
	sourceDirectory, err := sourceRoot.Open(".")
	if err != nil {
		return err
	}
	destinationDirectory, destinationErr := destinationRoot.Open(".")
	if destinationErr != nil {
		sourceDirectory.Close()
		return destinationErr
	}
	linkErr := linkArchiveAcrossRoots(sourceDirectory.Fd(), source, destinationDirectory.Fd(), destination)
	closeErr := errors.Join(sourceDirectory.Close(), destinationDirectory.Close())
	if linkErr == nil {
		if err := requireBoundArchiveFile(destinationRoot, destination, expected); err != nil {
			removeErr := destinationRoot.Remove(destination)
			return errors.Join(fmt.Errorf("atomically installed archive failed verification: %w", err), removeErr, syncBoundArchiveDirectory(destinationRoot), closeErr)
		}
		return closeErr
	}
	if closeErr != nil {
		return errors.Join(linkErr, closeErr)
	}
	if archiveLinkCrossDevice(linkErr) {
		return errors.New("atomic offline archive publication requires the private state and destination to share a filesystem")
	}
	if !errors.Is(linkErr, os.ErrExist) {
		return linkErr
	}
	if err := requireBoundArchiveFile(destinationRoot, destination, expected); err != nil {
		return fmt.Errorf("archive destination exists with different bytes: %w", err)
	}
	return nil
}

func requireBoundArchiveFile(root *os.Root, name string, expected archiveResult) error {
	info, err := root.Lstat(name)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o444 || info.Size() != expected.Size {
		return errors.Join(err, errors.New("bound archive destination is not the expected regular file"))
	}
	file, err := root.Open(name)
	if err != nil {
		return err
	}
	opened, statErr := file.Stat()
	hasher := sha256.New()
	written, copyErr := io.Copy(hasher, file)
	closeErr := file.Close()
	after, afterErr := root.Lstat(name)
	if statErr != nil || copyErr != nil || closeErr != nil || afterErr != nil || !os.SameFile(info, opened) || !os.SameFile(info, after) ||
		written != expected.Size || hex.EncodeToString(hasher.Sum(nil)) != expected.SHA256 {
		return errors.Join(statErr, copyErr, closeErr, afterErr, errors.New("bound archive destination content or identity changed"))
	}
	return nil
}

func syncBoundArchiveDirectory(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
