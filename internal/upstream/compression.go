package upstream

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

type interruptibleReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *interruptibleReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

type expandedStream struct {
	reader   *boundedReader
	file     *os.File
	closer   io.Closer
	hash     hash.Hash
	filename string
	identity os.FileInfo
}

func (s *expandedStream) Read(p []byte) (int, error) {
	return s.reader.Read(p)
}

func (s *expandedStream) Close() error {
	var result error
	if s.closer != nil {
		if err := s.closer.Close(); err != nil {
			result = errors.Join(result, err)
		}
	}
	last, statErr := s.file.Stat()
	closeErr := s.file.Close()
	after, pathErr := os.Lstat(s.filename)
	result = errors.Join(result, statErr, closeErr, pathErr)
	if statErr != nil || pathErr != nil || s.identity == nil || after.Mode()&os.ModeSymlink != 0 ||
		!after.Mode().IsRegular() || !last.Mode().IsRegular() || !os.SameFile(s.identity, last) || !os.SameFile(s.identity, after) ||
		s.identity.Size() != last.Size() || s.identity.Size() != after.Size() ||
		!s.identity.ModTime().Equal(last.ModTime()) || !s.identity.ModTime().Equal(after.ModTime()) {
		result = errors.Join(result, fmt.Errorf("%w: index changed while streaming", ErrInvalidMetadata))
	}
	return result
}

func (s *expandedStream) digest() (string, int64) {
	return hex.EncodeToString(s.hash.Sum(nil)), s.reader.used
}

type boundedReader struct {
	underlying io.Reader
	max        int64
	used       int64
}

type phaseBudgetReader struct {
	underlying io.Reader
	remaining  int64
	unlimited  bool
}

func (r *phaseBudgetReader) Read(p []byte) (int, error) {
	if r.unlimited {
		return r.underlying.Read(p)
	}
	if r.remaining <= 0 {
		return 0, ErrMetadataTooLarge
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.underlying.Read(p)
	r.remaining -= int64(n)
	return n, err
}

func (r *boundedReader) Read(p []byte) (int, error) {
	if r.used >= r.max {
		var probe [1]byte
		n, err := r.underlying.Read(probe[:])
		if n > 0 {
			return 0, ErrMetadataTooLarge
		}
		return 0, err
	}
	remaining := r.max - r.used
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := r.underlying.Read(p)
	r.used += int64(n)
	return n, err
}

func openIndex(filename, sourceURL string, limits Limits, expected ...os.FileInfo) (*expandedStream, error) {
	before, err := os.Lstat(filename)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.Join(err, fmt.Errorf("%w: index is absent, symlinked, or non-regular", ErrInvalidMetadata))
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	afterOpen, pathErr := os.Lstat(filename)
	if statErr != nil || pathErr != nil || !opened.Mode().IsRegular() || afterOpen.Mode()&os.ModeSymlink != 0 ||
		!afterOpen.Mode().IsRegular() || !os.SameFile(before, opened) || !os.SameFile(before, afterOpen) {
		return nil, errors.Join(statErr, pathErr, file.Close(), fmt.Errorf("%w: index changed while opening", ErrInvalidMetadata))
	}
	for _, identity := range expected {
		if identity == nil || !os.SameFile(identity, before) || !os.SameFile(identity, opened) {
			return nil, errors.Join(file.Close(), fmt.Errorf("%w: index differs from its verified identity", ErrInvalidMetadata))
		}
	}
	var reader io.Reader = file
	var closer io.Closer
	switch {
	case strings.HasSuffix(sourceURL, ".gz"):
		headerGuard := &phaseBudgetReader{underlying: file, remaining: int64(limits.XMLTokenBytes)}
		gz, err := gzip.NewReader(headerGuard)
		if err != nil {
			_ = file.Close()
			if errors.Is(err, ErrMetadataTooLarge) || headerGuard.remaining <= 0 {
				return nil, ErrMetadataTooLarge
			}
			return nil, fmt.Errorf("%w: invalid gzip index: %v", ErrInvalidMetadata, err)
		}
		headerGuard.unlimited = true
		reader, closer = gz, gz
	case strings.HasSuffix(sourceURL, ".xz"):
		xr, err := (xz.ReaderConfig{DictCap: limits.XZDictionaryBytes}).NewReader(file)
		if err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("%w: invalid xz index: %v", ErrInvalidMetadata, err)
		}
		reader = xr
	case strings.HasSuffix(sourceURL, ".zst") || strings.HasSuffix(sourceURL, ".zstd"):
		zr, err := zstd.NewReader(file, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(limits.ZstdMemoryBytes))
		if err != nil {
			_ = file.Close()
			return nil, fmt.Errorf("%w: invalid zstd index: %v", ErrInvalidMetadata, err)
		}
		reader, closer = zr, zr.IOReadCloser()
	}
	h := sha256.New()
	bounded := &boundedReader{underlying: io.TeeReader(reader, h), max: limits.IndexUncompressedBytes}
	return &expandedStream{reader: bounded, file: file, closer: closer, hash: h, filename: filename, identity: opened}, nil
}
