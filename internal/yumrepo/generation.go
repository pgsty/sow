package yumrepo

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/klauspost/compress/zstd"
)

const copyBufferSize = 256 * 1024

type bodyFiles struct {
	primaryFile, filelistsFile, otherFile *os.File
	bodies                                xmlBodies
}

// Generate builds a complete immutable repodata directory at dest. The input
// iterator is consumed once and only one RPM header/file list is retained at a
// time. Package fragments are spooled to disk because the XML root requires a
// final package count. dest is installed only after hashes, repomd, signature,
// and signature self-verification all succeed.
func Generate(ctx context.Context, dest string, opts Options, packages PackageIterator) (*Generation, error) {
	if ctx == nil {
		return nil, errors.New("yumrepo: nil context")
	}
	if packages == nil {
		return nil, errors.New("yumrepo: nil package iterator")
	}
	if opts.Signer == nil {
		return nil, errors.New("yumrepo: a detached signer/verifier is required")
	}
	if opts.Revision < 0 {
		return nil, errors.New("yumrepo: revision must be non-negative")
	}
	if err := preflightSigner(ctx, opts.Signer); err != nil {
		return nil, err
	}
	compression, err := CompressionForOptions(opts)
	if err != nil {
		return nil, err
	}
	dest = filepath.Clean(dest)
	if dest == "." || dest == string(filepath.Separator) {
		return nil, errors.New("yumrepo: unsafe generation destination")
	}
	parent := filepath.Dir(dest)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return nil, fmt.Errorf("yumrepo: create generation parent: %w", err)
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("yumrepo: generation parent %q is not a real directory", parent)
	}
	tmp, err := os.MkdirTemp(parent, "."+filepath.Base(dest)+".build-")
	if err != nil {
		return nil, fmt.Errorf("yumrepo: create generation staging directory: %w", err)
	}
	installed := false
	defer func() {
		if !installed {
			_ = os.RemoveAll(tmp)
		}
	}()

	bodies, err := openBodyFiles(tmp)
	if err != nil {
		return nil, err
	}
	var count int64
	var previous string
	for {
		if err := ctx.Err(); err != nil {
			bodies.closeDiscard()
			return nil, err
		}
		input, nextErr := packages.Next(ctx)
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			bodies.closeDiscard()
			return nil, fmt.Errorf("yumrepo: read package input: %w", nextErr)
		}
		metadata, readErr := readPackage(ctx, input)
		if readErr != nil {
			bodies.closeDiscard()
			return nil, readErr
		}
		if previous != "" && metadata.Location <= previous {
			bodies.closeDiscard()
			return nil, fmt.Errorf("%w: %q follows %q", ErrUnsortedInput, metadata.Location, previous)
		}
		if err := bodies.bodies.writePackage(metadata); err != nil {
			bodies.closeDiscard()
			return nil, fmt.Errorf("yumrepo: write XML package %q: %w", metadata.Location, err)
		}
		previous = metadata.Location
		count++
	}
	if err := bodies.finish(); err != nil {
		return nil, err
	}

	types := []struct {
		name, body string
	}{
		{"primary", bodies.primaryFile.Name()},
		{"filelists", bodies.filelistsFile.Name()},
		{"other", bodies.otherFile.Name()},
	}
	generation := &Generation{Dir: dest, Packages: count, Revision: uint64(opts.Revision)}
	for i, item := range types {
		rawPath := filepath.Join(tmp, item.name+".xml")
		if err := assembleXML(rawPath, item.name, item.body, count); err != nil {
			return nil, err
		}
		artifact, err := compressXML(ctx, tmp, item.name, rawPath, compression, count, opts.Revision)
		if err != nil {
			return nil, err
		}
		generation.Artifacts[i] = artifact
	}
	for _, item := range types {
		if err := os.Remove(item.body); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("yumrepo: remove XML spool: %w", err)
		}
	}
	if err := writeRepomd(filepath.Join(tmp, "repomd.xml"), generation); err != nil {
		return nil, err
	}
	generation.RepomdSHA256, err = hashFileContext(ctx, filepath.Join(tmp, "repomd.xml"))
	if err != nil {
		return nil, fmt.Errorf("yumrepo: hash repomd.xml: %w", err)
	}
	if err := signRepomd(ctx, tmp, opts.Signer); err != nil {
		return nil, err
	}
	validated, err := ValidateDirectory(ctx, tmp, compression, opts.Signer)
	if err != nil {
		return nil, fmt.Errorf("yumrepo: generated repodata failed self-validation: %w", err)
	}
	if validated.Packages != generation.Packages || validated.Revision != generation.Revision || validated.RepomdSHA256 != generation.RepomdSHA256 {
		return nil, fmt.Errorf("yumrepo: generated repodata self-validation changed generation identity")
	}
	if err := syncDirectory(tmp); err != nil {
		return nil, err
	}

	if destInfo, err := os.Lstat(dest); err == nil {
		if !destInfo.IsDir() || destInfo.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: destination is not an immutable directory: %s", ErrGenerationConflict, dest)
		}
		equivalent, compareErr := equivalentGeneration(ctx, dest, tmp, opts.Signer)
		if compareErr != nil {
			return nil, compareErr
		}
		if !equivalent {
			return nil, fmt.Errorf("%w: %s", ErrGenerationConflict, dest)
		}
		if err := os.RemoveAll(tmp); err != nil {
			return nil, fmt.Errorf("yumrepo: discard duplicate staging generation: %w", err)
		}
		installed = true
		generation.Reused = true
		return generation, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("yumrepo: inspect generation destination: %w", err)
	}

	// This create-only rename installs a previously absent immutable generation.
	// It is not the live repodata pair flip; live replacement is exclusively
	// performed by NativeDirectoryExchanger using RENAME_EXCHANGE/RENAME_SWAP.
	if err := installImmutable(tmp, dest); err != nil {
		if _, statErr := os.Lstat(dest); statErr == nil {
			equivalent, compareErr := equivalentGeneration(ctx, dest, tmp, opts.Signer)
			if compareErr == nil && equivalent {
				_ = os.RemoveAll(tmp)
				installed = true
				generation.Reused = true
				return generation, nil
			}
		}
		return nil, fmt.Errorf("yumrepo: install immutable generation: %w", err)
	}
	installed = true
	if err := syncDirectory(parent); err != nil {
		return nil, err
	}
	return generation, nil
}

type boundedWriter struct {
	w         io.Writer
	remaining int64
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, fmt.Errorf("signature exceeds %d-byte limit", maxSignatureBytes)
	}
	n, err := w.w.Write(p)
	w.remaining -= int64(n)
	return n, err
}

func preflightSigner(ctx context.Context, signer DetachedSigner) error {
	probe := []byte("sow yumrepo detached-signature preflight v1\n")
	var signature bytes.Buffer
	w := &boundedWriter{w: &signature, remaining: maxSignatureBytes}
	if err := signer.Sign(ctx, bytes.NewReader(probe), w); err != nil {
		return fmt.Errorf("yumrepo: detached signer preflight sign: %w", err)
	}
	if signature.Len() == 0 {
		return fmt.Errorf("yumrepo: detached signer preflight produced an empty signature")
	}
	if err := signer.Verify(ctx, bytes.NewReader(probe), bytes.NewReader(signature.Bytes())); err != nil {
		return fmt.Errorf("yumrepo: detached signer preflight verify: %w", err)
	}
	return nil
}

func openBodyFiles(dir string) (*bodyFiles, error) {
	b := &bodyFiles{}
	var err error
	if b.primaryFile, err = os.OpenFile(filepath.Join(dir, ".primary.body"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600); err != nil {
		return nil, fmt.Errorf("yumrepo: create primary spool: %w", err)
	}
	if b.filelistsFile, err = os.OpenFile(filepath.Join(dir, ".filelists.body"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600); err != nil {
		b.closeDiscard()
		return nil, fmt.Errorf("yumrepo: create filelists spool: %w", err)
	}
	if b.otherFile, err = os.OpenFile(filepath.Join(dir, ".other.body"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600); err != nil {
		b.closeDiscard()
		return nil, fmt.Errorf("yumrepo: create other spool: %w", err)
	}
	b.bodies = xmlBodies{
		primary:   bufio.NewWriterSize(b.primaryFile, copyBufferSize),
		filelists: bufio.NewWriterSize(b.filelistsFile, copyBufferSize),
		other:     bufio.NewWriterSize(b.otherFile, copyBufferSize),
	}
	return b, nil
}

func (b *bodyFiles) finish() error {
	for _, writer := range []*bufio.Writer{b.bodies.primary, b.bodies.filelists, b.bodies.other} {
		if err := writer.Flush(); err != nil {
			b.closeDiscard()
			return fmt.Errorf("yumrepo: flush XML spool: %w", err)
		}
	}
	for _, file := range []*os.File{b.primaryFile, b.filelistsFile, b.otherFile} {
		if err := file.Sync(); err != nil {
			b.closeDiscard()
			return fmt.Errorf("yumrepo: sync XML spool: %w", err)
		}
		if err := file.Close(); err != nil {
			b.closeDiscard()
			return fmt.Errorf("yumrepo: close XML spool: %w", err)
		}
	}
	return nil
}

func (b *bodyFiles) closeDiscard() {
	for _, file := range []*os.File{b.primaryFile, b.filelistsFile, b.otherFile} {
		if file != nil {
			_ = file.Close()
		}
	}
}

func assembleXML(dest, kind, body string, packages int64) error {
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("yumrepo: create %s XML: %w", kind, err)
	}
	if err := out.Chmod(0o644); err != nil {
		_ = out.Close()
		_ = os.Remove(dest)
		return fmt.Errorf("yumrepo: chmod %s XML: %w", kind, err)
	}
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(dest)
		}
	}()
	w := bufio.NewWriterSize(out, copyBufferSize)
	var header, footer string
	switch kind {
	case "primary":
		header = fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata xmlns=\"%s\" xmlns:rpm=\"%s\" packages=\"%d\">\n", commonNS, rpmNS, packages)
		footer = "</metadata>\n"
	case "filelists":
		header = fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<filelists xmlns=\"%s\" packages=\"%d\">\n", filelistsNS, packages)
		footer = "</filelists>\n"
	case "other":
		header = fmt.Sprintf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<otherdata xmlns=\"%s\" packages=\"%d\">\n", otherNS, packages)
		footer = "</otherdata>\n"
	default:
		return fmt.Errorf("yumrepo: unknown metadata type %q", kind)
	}
	if _, err := io.WriteString(w, header); err != nil {
		return err
	}
	in, err := os.Open(body)
	if err != nil {
		return fmt.Errorf("yumrepo: open %s XML spool: %w", kind, err)
	}
	_, copyErr := io.CopyBuffer(w, in, make([]byte, copyBufferSize))
	closeErr := in.Close()
	if copyErr != nil {
		return fmt.Errorf("yumrepo: assemble %s XML: %w", kind, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("yumrepo: close %s XML spool: %w", kind, closeErr)
	}
	if _, err := io.WriteString(w, footer); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return fmt.Errorf("yumrepo: sync %s XML: %w", kind, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("yumrepo: close %s XML: %w", kind, err)
	}
	ok = true
	return nil
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (w *countingWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	w.n += int64(n)
	return n, err
}

func compressXML(ctx context.Context, dir, kind, rawPath string, compression Compression, packages, timestamp int64) (Artifact, error) {
	in, err := os.Open(rawPath)
	if err != nil {
		return Artifact{}, fmt.Errorf("yumrepo: open %s XML: %w", kind, err)
	}
	defer in.Close()
	tmpPath := filepath.Join(dir, "."+kind+".compressed")
	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return Artifact{}, fmt.Errorf("yumrepo: create compressed %s: %w", kind, err)
	}
	if err := out.Chmod(0o644); err != nil {
		_ = out.Close()
		_ = os.Remove(tmpPath)
		return Artifact{}, fmt.Errorf("yumrepo: chmod compressed %s: %w", kind, err)
	}
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(tmpPath)
		}
	}()
	compressedHash, openHash := sha256.New(), sha256.New()
	compressedCount := &countingWriter{w: io.MultiWriter(out, compressedHash)}
	openCount := &countingWriter{w: openHash}
	reader := io.TeeReader(&contextReader{ctx: ctx, r: in}, openCount)
	var compressor io.WriteCloser
	var extension string
	switch compression {
	case CompressionGzip:
		gz, err := gzip.NewWriterLevel(compressedCount, gzip.DefaultCompression)
		if err != nil {
			return Artifact{}, fmt.Errorf("yumrepo: create gzip writer: %w", err)
		}
		gz.Header.ModTime = unixEpoch
		gz.Header.OS = 255
		compressor, extension = gz, ".gz"
	case CompressionZstd:
		zw, err := zstd.NewWriter(compressedCount,
			zstd.WithEncoderConcurrency(1),
			zstd.WithEncoderLevel(zstd.SpeedDefault),
			zstd.WithEncoderCRC(true),
			zstd.WithWindowSize(8<<20),
		)
		if err != nil {
			return Artifact{}, fmt.Errorf("yumrepo: create zstd writer: %w", err)
		}
		compressor, extension = zw, ".zst"
	default:
		return Artifact{}, fmt.Errorf("yumrepo: unsupported compression %q", compression)
	}
	if _, err := io.CopyBuffer(compressor, reader, make([]byte, copyBufferSize)); err != nil {
		_ = compressor.Close()
		return Artifact{}, fmt.Errorf("yumrepo: compress %s XML: %w", kind, err)
	}
	if err := compressor.Close(); err != nil {
		return Artifact{}, fmt.Errorf("yumrepo: finish compressed %s XML: %w", kind, err)
	}
	if err := out.Sync(); err != nil {
		return Artifact{}, fmt.Errorf("yumrepo: sync compressed %s XML: %w", kind, err)
	}
	if err := out.Close(); err != nil {
		return Artifact{}, fmt.Errorf("yumrepo: close compressed %s XML: %w", kind, err)
	}
	compressedSHA := hex.EncodeToString(compressedHash.Sum(nil))
	name := compressedSHA + "-" + kind + ".xml" + extension
	finalPath := filepath.Join(dir, name)
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return Artifact{}, fmt.Errorf("yumrepo: name compressed %s by hash: %w", kind, err)
	}
	if err := os.Remove(rawPath); err != nil {
		return Artifact{}, fmt.Errorf("yumrepo: remove raw %s XML: %w", kind, err)
	}
	ok = true
	return Artifact{
		Type: kind, Path: "repodata/" + name,
		SHA256: compressedSHA, OpenSHA256: hex.EncodeToString(openHash.Sum(nil)),
		Size: compressedCount.n, OpenSize: openCount.n, Timestamp: timestamp,
		Packages: packages, Compression: compression,
	}, nil
}

var unixEpoch = timeUnixEpoch()

func timeUnixEpoch() (t time.Time) { return time.Unix(0, 0).UTC() }

func writeRepomd(filename string, generation *Generation) error {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("yumrepo: create repomd.xml: %w", err)
	}
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		_ = os.Remove(filename)
		return fmt.Errorf("yumrepo: chmod repomd.xml: %w", err)
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(filename)
		}
	}()
	w := bufio.NewWriterSize(f, 64*1024)
	if _, err := fmt.Fprintf(w, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<repomd xmlns=\"%s\" xmlns:rpm=\"%s\">\n  <revision>%d</revision>\n", repoNS, rpmNS, generation.Revision); err != nil {
		return err
	}
	for _, a := range generation.Artifacts {
		if _, err := fmt.Fprintf(w, "  <data type=\"%s\">\n    <checksum type=\"sha256\">%s</checksum>\n    <open-checksum type=\"sha256\">%s</open-checksum>\n    <location href=\"%s\"/>\n    <timestamp>%d</timestamp>\n    <size>%d</size>\n    <open-size>%d</open-size>\n  </data>\n", a.Type, a.SHA256, a.OpenSHA256, a.Path, a.Timestamp, a.Size, a.OpenSize); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(w, "</repomd>\n"); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("yumrepo: sync repomd.xml: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("yumrepo: close repomd.xml: %w", err)
	}
	ok = true
	return nil
}

func signRepomd(ctx context.Context, dir string, signer DetachedSigner) error {
	repomdPath, signaturePath := filepath.Join(dir, "repomd.xml"), filepath.Join(dir, "repomd.xml.asc")
	message, err := os.Open(repomdPath)
	if err != nil {
		return fmt.Errorf("yumrepo: open repomd.xml for signing: %w", err)
	}
	signature, err := os.OpenFile(signaturePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		_ = message.Close()
		return fmt.Errorf("yumrepo: create repomd.xml.asc: %w", err)
	}
	if err := signature.Chmod(0o644); err != nil {
		_ = message.Close()
		_ = signature.Close()
		_ = os.Remove(signaturePath)
		return fmt.Errorf("yumrepo: chmod repomd.xml.asc: %w", err)
	}
	signErr := signer.Sign(ctx, message, signature)
	var signatureSyncErr error
	if signErr == nil {
		signatureSyncErr = signature.Sync()
	}
	messageCloseErr, signatureCloseErr := message.Close(), signature.Close()
	if signErr != nil {
		return fmt.Errorf("yumrepo: sign repomd.xml: %w", signErr)
	}
	if signatureSyncErr != nil {
		return fmt.Errorf("yumrepo: sync repomd.xml.asc: %w", signatureSyncErr)
	}
	if messageCloseErr != nil {
		return fmt.Errorf("yumrepo: close signed repomd.xml: %w", messageCloseErr)
	}
	if signatureCloseErr != nil {
		return fmt.Errorf("yumrepo: close repomd.xml.asc: %w", signatureCloseErr)
	}
	message, err = os.Open(repomdPath)
	if err != nil {
		return err
	}
	defer message.Close()
	signature, err = os.Open(signaturePath)
	if err != nil {
		return err
	}
	defer signature.Close()
	if err := signer.Verify(ctx, message, signature); err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureValidation, err)
	}
	return nil
}

func equivalentGeneration(ctx context.Context, existing, candidate string, verifier DetachedVerifier) (bool, error) {
	for _, dir := range []string{existing, candidate} {
		message, err := os.Open(filepath.Join(dir, "repomd.xml"))
		if err != nil {
			return false, fmt.Errorf("yumrepo: open existing repomd.xml: %w", err)
		}
		signature, err := os.Open(filepath.Join(dir, "repomd.xml.asc"))
		if err != nil {
			_ = message.Close()
			return false, fmt.Errorf("yumrepo: open existing repomd.xml.asc: %w", err)
		}
		verifyErr := verifier.Verify(ctx, message, signature)
		_ = message.Close()
		_ = signature.Close()
		if verifyErr != nil {
			return false, fmt.Errorf("%w: %v", ErrSignatureValidation, verifyErr)
		}
	}
	existingFiles, err := directoryFiles(existing)
	if err != nil {
		return false, err
	}
	candidateFiles, err := directoryFiles(candidate)
	if err != nil {
		return false, err
	}
	delete(existingFiles, "repomd.xml.asc")
	delete(candidateFiles, "repomd.xml.asc")
	if len(existingFiles) != len(candidateFiles) {
		return false, nil
	}
	for name, digest := range candidateFiles {
		if existingFiles[name] != digest {
			return false, nil
		}
	}
	return true, nil
}

func directoryFiles(dir string) (map[string]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("yumrepo: list generation %q: %w", dir, err)
	}
	files := make(map[string]string, len(entries))
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: non-regular generation entry %q", ErrInvalidRepodata, name)
		}
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		_, copyErr := io.CopyBuffer(h, f, make([]byte, copyBufferSize))
		closeErr := f.Close()
		if copyErr != nil {
			return nil, copyErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		files[name] = hex.EncodeToString(h.Sum(nil))
	}
	return files, nil
}

func syncDirectory(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("yumrepo: open directory %q for sync: %w", dir, err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("yumrepo: sync directory %q: %w", dir, err)
	}
	return nil
}
