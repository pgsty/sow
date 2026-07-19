package cli

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/yumrepo"
)

// writeFrozenAPTMetadataManifest writes only metadata named by the completed
// APT builds and, for mutable canonical targets, immutable by-hash objects
// retained by the staged canonical ledgers. It deliberately never discovers
// desired state by walking the live archive tree: a pre-existing file cannot
// become canonical merely because it happens to be under dists/.
func writeFrozenAPTMetadataManifest(ctx context.Context, archiveRoot, prefix, destination string, builds []aptrepo.BuildResult, ledgerStages map[string]string) (resultErr error) {
	if ctx == nil {
		return errors.New("frozen APT metadata manifest requires a context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if prefix != "" && (prefix == "." || path.IsAbs(prefix) || path.Clean(prefix) != prefix || strings.ContainsAny(prefix, "\\\x00\t\r\n")) {
		return fmt.Errorf("unsafe frozen APT metadata prefix %q", prefix)
	}
	entries := make(map[string]manifest.Entry)
	for _, build := range builds {
		for _, artifact := range build.Artifacts {
			digest, err := repository.ParseDigest(artifact.SHA256)
			if err != nil {
				return fmt.Errorf("invalid generated APT artifact digest for %s: %w", artifact.Path, err)
			}
			entry := manifest.Entry{Path: artifact.Path, Size: artifact.Size, SHA256: [sha256.Size]byte(digest)}
			if err := addFrozenMetadataEntry(entries, prefix, entry); err != nil {
				return fmt.Errorf("record generated APT artifact %s: %w", artifact.Path, err)
			}
		}
	}

	root, err := os.OpenRoot(archiveRoot)
	if err != nil {
		return fmt.Errorf("open frozen APT archive root: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	stageKeys := make([]string, 0, len(ledgerStages))
	for canonicalPath := range ledgerStages {
		stageKeys = append(stageKeys, canonicalPath)
	}
	sort.Strings(stageKeys)
	for _, canonicalPath := range stageKeys {
		stagePath := ledgerStages[canonicalPath]
		file, err := os.Open(stagePath)
		if err != nil {
			return fmt.Errorf("open staged APT by-hash ledger %s: %w", canonicalPath, err)
		}
		ledger, decodeErr := aptrepo.DecodeByHashLedger(file)
		closeErr := file.Close()
		if decodeErr != nil || closeErr != nil {
			return fmt.Errorf("decode staged APT by-hash ledger %s: %w", canonicalPath, errors.Join(decodeErr, closeErr))
		}
		for _, generation := range ledger.Generations {
			for _, retainedPath := range generation.Paths {
				if _, current := entries[frozenMetadataPath(prefix, retainedPath)]; current {
					continue
				}
				entry, err := hashFrozenAPTByHashFile(ctx, root, retainedPath)
				if err != nil {
					return fmt.Errorf("record retained APT by-hash object %s: %w", retainedPath, err)
				}
				if err := addFrozenMetadataEntry(entries, prefix, entry); err != nil {
					return fmt.Errorf("record retained APT by-hash object %s: %w", retainedPath, err)
				}
			}
		}
	}

	paths := make([]string, 0, len(entries))
	for entryPath := range entries {
		paths = append(paths, entryPath)
	}
	sort.Strings(paths)
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	for _, entryPath := range paths {
		if err := manifest.WriteEntry(output, entries[entryPath]); err != nil {
			return errors.Join(err, output.Close())
		}
	}
	return errors.Join(output.Sync(), output.Close())
}

func addFrozenMetadataEntry(entries map[string]manifest.Entry, prefix string, entry manifest.Entry) error {
	if err := entry.Validate(); err != nil {
		return err
	}
	entry.Path = frozenMetadataPath(prefix, entry.Path)
	if err := entry.Validate(); err != nil {
		return err
	}
	if previous, exists := entries[entry.Path]; exists {
		if previous.Size != entry.Size || previous.SHA256 != entry.SHA256 {
			return fmt.Errorf("conflicting frozen metadata path %q", entry.Path)
		}
		return nil
	}
	entries[entry.Path] = entry
	return nil
}

func frozenMetadataPath(prefix, relative string) string {
	if prefix == "" {
		return relative
	}
	return path.Join(prefix, relative)
}

func hashFrozenAPTByHashFile(ctx context.Context, root *os.Root, relative string) (entry manifest.Entry, resultErr error) {
	if root == nil {
		return manifest.Entry{}, errors.New("frozen APT archive root is unavailable")
	}
	if err := (manifest.Entry{Path: relative}).Validate(); err != nil {
		return manifest.Entry{}, err
	}
	parts := strings.Split(relative, "/")
	if len(parts) != 7 || parts[0] != "dists" || parts[4] != "by-hash" || parts[5] != "SHA256" {
		return manifest.Entry{}, fmt.Errorf("unexpected retained APT by-hash path %q", relative)
	}
	expected, err := repository.ParseDigest(parts[6])
	if err != nil {
		return manifest.Entry{}, err
	}
	info, err := root.Lstat(filepath.FromSlash(relative))
	if err != nil {
		return manifest.Entry{}, err
	}
	if !info.Mode().IsRegular() {
		return manifest.Entry{}, fmt.Errorf("retained APT by-hash path is not a regular file")
	}
	file, err := root.Open(filepath.FromSlash(relative))
	if err != nil {
		return manifest.Entry{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	opened, err := file.Stat()
	if err != nil {
		return manifest.Entry{}, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return manifest.Entry{}, errors.New("retained APT by-hash path changed while opening")
	}
	hasher := sha256.New()
	buffer := make([]byte, 256*1024)
	var size int64
	for {
		if err := ctx.Err(); err != nil {
			return manifest.Entry{}, err
		}
		read, readErr := file.Read(buffer)
		if read > 0 {
			written, writeErr := hasher.Write(buffer[:read])
			if writeErr != nil || written != read {
				return manifest.Entry{}, errors.Join(writeErr, io.ErrShortWrite)
			}
			size += int64(read)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return manifest.Entry{}, readErr
		}
	}
	if size != opened.Size() {
		return manifest.Entry{}, errors.New("retained APT by-hash size changed while hashing")
	}
	var actual [sha256.Size]byte
	copy(actual[:], hasher.Sum(nil))
	if actual != [sha256.Size]byte(expected) {
		return manifest.Entry{}, errors.New("retained APT by-hash checksum does not match its path")
	}
	return manifest.Entry{Path: relative, Size: size, SHA256: actual}, nil
}

// writeFrozenYUMMetadataManifest records exactly the five files in the frozen
// YUM generation contract: primary, filelists, other, repomd.xml, and its
// detached signature. The caller supplies the strictly validated generation
// selected by activation; this function rejects extra directory entries rather
// than silently treating a same-UID injection as desired state.
func writeFrozenYUMMetadataManifest(ctx context.Context, generationDir, destination, prefix string, generation *yumrepo.Generation) (resultErr error) {
	if prefix == "" || prefix == "." || path.IsAbs(prefix) || path.Clean(prefix) != prefix || strings.ContainsAny(prefix, "\\\x00\t\r\n") {
		return fmt.Errorf("unsafe frozen YUM metadata prefix %q", prefix)
	}
	if ctx == nil || generation == nil {
		return errors.New("frozen YUM metadata generation is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	type expectedFile struct {
		size   int64
		digest *repository.Digest
	}
	expected := map[string]expectedFile{
		"repomd.xml.asc": {size: -1},
	}
	repomdDigest, err := repository.ParseDigest(generation.RepomdSHA256)
	if err != nil {
		return fmt.Errorf("invalid generated YUM repomd digest: %w", err)
	}
	expected["repomd.xml"] = expectedFile{size: -1, digest: &repomdDigest}
	wantedTypes := map[string]struct{}{"primary": {}, "filelists": {}, "other": {}}
	seenTypes := make(map[string]struct{}, len(wantedTypes))
	for _, artifact := range generation.Artifacts {
		if _, wanted := wantedTypes[artifact.Type]; !wanted {
			return fmt.Errorf("invalid generated YUM artifact type %q", artifact.Type)
		}
		if _, duplicate := seenTypes[artifact.Type]; duplicate {
			return fmt.Errorf("duplicate generated YUM artifact type %q", artifact.Type)
		}
		seenTypes[artifact.Type] = struct{}{}
		if path.Clean(artifact.Path) != artifact.Path || path.Dir(artifact.Path) != "repodata" || path.Base(artifact.Path) == artifact.Path || strings.ContainsAny(artifact.Path, "\\\x00\t\r\n") {
			return fmt.Errorf("invalid generated YUM artifact path %q", artifact.Path)
		}
		name := path.Base(artifact.Path)
		if _, duplicate := expected[name]; duplicate {
			return fmt.Errorf("duplicate generated YUM artifact %q", name)
		}
		digest, err := repository.ParseDigest(artifact.SHA256)
		if err != nil {
			return fmt.Errorf("invalid generated YUM artifact digest for %s: %w", artifact.Path, err)
		}
		if artifact.Size < 0 {
			return fmt.Errorf("invalid generated YUM artifact size for %s", artifact.Path)
		}
		expected[name] = expectedFile{size: artifact.Size, digest: &digest}
	}
	if len(expected) != 5 {
		return fmt.Errorf("generated YUM metadata names %d files, want exactly 5", len(expected))
	}

	root, err := os.OpenRoot(generationDir)
	if err != nil {
		return fmt.Errorf("open frozen YUM generation: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open frozen YUM generation directory: %w", err)
	}
	directoryEntries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return fmt.Errorf("enumerate frozen YUM generation: %w", errors.Join(readErr, closeErr))
	}
	if len(directoryEntries) != len(expected) {
		return fmt.Errorf("frozen YUM generation contains %d entries, want exactly %d", len(directoryEntries), len(expected))
	}
	for _, directoryEntry := range directoryEntries {
		if _, exists := expected[directoryEntry.Name()]; !exists {
			return fmt.Errorf("unexpected frozen YUM generation entry %q", directoryEntry.Name())
		}
	}

	names := make([]string, 0, len(expected))
	for name := range expected {
		names = append(names, name)
	}
	sort.Strings(names)
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	for _, name := range names {
		entry, err := hashFrozenRootRegularFile(ctx, root, name)
		if err != nil {
			return errors.Join(fmt.Errorf("hash frozen YUM generation entry %s: %w", name, err), output.Close())
		}
		want := expected[name]
		if want.size >= 0 && entry.Size != want.size {
			return errors.Join(fmt.Errorf("frozen YUM generation entry %s size mismatch", name), output.Close())
		}
		if want.digest != nil && entry.SHA256 != [sha256.Size]byte(*want.digest) {
			return errors.Join(fmt.Errorf("frozen YUM generation entry %s checksum mismatch", name), output.Close())
		}
		entry.Path = path.Join(prefix, name)
		if err := manifest.WriteEntry(output, entry); err != nil {
			return errors.Join(err, output.Close())
		}
	}
	return errors.Join(output.Sync(), output.Close())
}

func hashFrozenRootRegularFile(ctx context.Context, root *os.Root, relative string) (entry manifest.Entry, resultErr error) {
	if root == nil {
		return manifest.Entry{}, errors.New("frozen metadata root is unavailable")
	}
	if err := (manifest.Entry{Path: relative}).Validate(); err != nil || path.Base(relative) != relative {
		return manifest.Entry{}, errors.Join(err, fmt.Errorf("frozen metadata name is not a safe basename %q", relative))
	}
	info, err := root.Lstat(relative)
	if err != nil {
		return manifest.Entry{}, err
	}
	if !info.Mode().IsRegular() {
		return manifest.Entry{}, errors.New("frozen metadata entry is not a regular file")
	}
	file, err := root.Open(relative)
	if err != nil {
		return manifest.Entry{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	opened, err := file.Stat()
	if err != nil {
		return manifest.Entry{}, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return manifest.Entry{}, errors.New("frozen metadata entry changed while opening")
	}
	hasher := sha256.New()
	buffer := make([]byte, 256*1024)
	var size int64
	for {
		if err := ctx.Err(); err != nil {
			return manifest.Entry{}, err
		}
		read, readErr := file.Read(buffer)
		if read > 0 {
			written, writeErr := hasher.Write(buffer[:read])
			if writeErr != nil || written != read {
				return manifest.Entry{}, errors.Join(writeErr, io.ErrShortWrite)
			}
			size += int64(read)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return manifest.Entry{}, readErr
		}
	}
	if size != opened.Size() {
		return manifest.Entry{}, errors.New("frozen metadata entry size changed while hashing")
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return manifest.Entry{Path: relative, Size: size, SHA256: digest}, nil
}
