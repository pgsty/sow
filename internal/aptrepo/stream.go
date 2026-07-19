package aptrepo

import (
	"bufio"
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"pault.ag/go/debian/control"
	"pault.ag/go/debian/version"
)

const (
	packageRunMagic      = "SOWAPT1\n"
	packageRunMaxRecord  = 16 << 20
	packageRunMergeFanIn = 64
)

// PackageIterator supplies already inspected Debian packages without retaining
// a repository-wide slice. Iterators are one-shot and must return io.EOF at
// end. GenerateStreaming validates both the package metadata and source bytes.
type PackageIterator interface {
	Next(context.Context) (Package, error)
}

// StreamingIndex binds one externally sorted package stream to a configured
// component/architecture Packages index. A nil iterator denotes an empty
// index, which remains publishable.
type StreamingIndex struct {
	Component    string
	Architecture string
	Packages     PackageIterator
}

// StreamingOptions bounds concurrent component/architecture index writers.
// Workers above 64 are deliberately capped to bound file descriptors and xz
// compressor memory.
type StreamingOptions struct {
	Workers int
	// StagedTransform may rewrite only InRelease and Release.gpg while they are
	// still in the private staging tree. GenerateStreaming re-seals them and
	// rejects any other artifact change before commit. This is used by
	// deterministic snapshot materialization without exposing a partially
	// rewritten live suite.
	StagedTransform func(stageRoot string, result BuildResult) error
	// CommitGuard is evaluated immediately before the first live mutation and
	// after the final checkpoint replacement. A failed post-commit guard rolls
	// the complete suite back to its pre-commit state.
	CommitGuard func(CommitPhase) error
}

// CommitPhase identifies the two trust/authorization boundaries surrounding
// a staged APT build's live commit.
type CommitPhase uint8

const (
	CommitBeforeMutation CommitPhase = iota + 1
	CommitAfterMutation
)

// PackageSpoolStats is evidence about the bounded external-sort footprint.
type PackageSpoolStats struct {
	Entries        int64
	Runs           int
	DiskBytes      int64
	PeakChunkItems int
}

type packageRunRecord struct {
	Name         string            `json:"name"`
	Source       string            `json:"source"`
	Version      string            `json:"version"`
	Architecture string            `json:"architecture"`
	Component    string            `json:"component"`
	SourcePath   string            `json:"source_path"`
	PoolPath     string            `json:"pool_path"`
	Size         int64             `json:"size"`
	SHA256       string            `json:"sha256"`
	Order        []string          `json:"order"`
	Values       map[string]string `json:"values"`
}

// SortedPackageSpool is a disk-backed external sorter. Memory is bounded by
// chunkEntries packages while ingesting and one decoded package per run while
// merging. Close removes every run and may be called repeatedly.
type SortedPackageSpool struct {
	tempDir      string
	chunkEntries int
	chunk        []Package
	runs         []string
	stats        PackageSpoolStats
	sealed       bool
	closed       bool
	iterator     *packageMergeIterator
}

func NewSortedPackageSpool(tempDir string, chunkEntries int) (*SortedPackageSpool, error) {
	if tempDir == "" {
		return nil, errors.New("aptrepo: package spool temp directory is required")
	}
	if chunkEntries < 1 {
		return nil, errors.New("aptrepo: package spool chunk entries must be positive")
	}
	if err := os.MkdirAll(tempDir, 0o700); err != nil {
		return nil, fmt.Errorf("aptrepo: create package spool directory: %w", err)
	}
	info, err := os.Lstat(tempDir)
	if err != nil {
		return nil, fmt.Errorf("aptrepo: inspect package spool directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("aptrepo: package spool directory must be a real directory")
	}
	return &SortedPackageSpool{
		tempDir: tempDir, chunkEntries: chunkEntries,
		// Do not reserve the full configured run for every empty component.
		// Capacity grows only for components that actually receive packages.
		chunk: make([]Package, 0, min(chunkEntries, 64)),
	}, nil
}

// Add validates one inspected package and adds it to the current bounded run.
// Source bytes are verified later by GenerateStreaming immediately before the
// package paragraph is emitted.
func (s *SortedPackageSpool) Add(ctx context.Context, pkg Package) error {
	if s == nil {
		return errors.New("aptrepo: nil package spool")
	}
	if ctx == nil {
		return errors.New("aptrepo: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.closed {
		return errors.New("aptrepo: package spool is closed")
	}
	if s.sealed {
		return errors.New("aptrepo: package spool is already sealed")
	}
	if err := validatePackageMetadata(pkg); err != nil {
		return err
	}
	// InspectPackage owns a fresh immutable control paragraph. Package exposes
	// no paragraph mutator, so transferring this value avoids a second map copy
	// for every in-flight package.
	s.chunk = append(s.chunk, pkg)
	s.stats.Entries++
	if len(s.chunk) > s.stats.PeakChunkItems {
		s.stats.PeakChunkItems = len(s.chunk)
	}
	if len(s.chunk) == s.chunkEntries {
		return s.flushChunk(ctx)
	}
	return nil
}

// Seal flushes the final run and performs bounded-fan-in compaction. The last
// merge remains lazy so Packages output is written directly from a k-way merge.
func (s *SortedPackageSpool) Seal(ctx context.Context) error {
	if s == nil {
		return errors.New("aptrepo: nil package spool")
	}
	if ctx == nil {
		return errors.New("aptrepo: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.closed {
		return errors.New("aptrepo: package spool is closed")
	}
	if s.sealed {
		return nil
	}
	if len(s.chunk) > 0 {
		if err := s.flushChunk(ctx); err != nil {
			return err
		}
	}
	for len(s.runs) > packageRunMergeFanIn {
		var next []string
		for offset := 0; offset < len(s.runs); offset += packageRunMergeFanIn {
			end := offset + packageRunMergeFanIn
			if end > len(s.runs) {
				end = len(s.runs)
			}
			group := append([]string(nil), s.runs[offset:end]...)
			if len(group) == 1 {
				next = append(next, group[0])
				continue
			}
			merged, err := mergePackageRunsToFile(ctx, s.tempDir, group)
			if err != nil {
				removePackageRuns(next)
				return err
			}
			removePackageRuns(group)
			next = append(next, merged)
		}
		s.runs = next
	}
	s.sealed = true
	return s.refreshStats()
}

func (s *SortedPackageSpool) Stats() PackageSpoolStats {
	if s == nil {
		return PackageSpoolStats{}
	}
	stats := s.stats
	stats.Runs = len(s.runs)
	return stats
}

// Next implements PackageIterator. It lazily opens at most 64 sorted runs and
// rejects duplicate package identities at the merge boundary.
func (s *SortedPackageSpool) Next(ctx context.Context) (Package, error) {
	if s == nil {
		return Package{}, errors.New("aptrepo: nil package spool")
	}
	if ctx == nil {
		return Package{}, errors.New("aptrepo: nil context")
	}
	if err := ctx.Err(); err != nil {
		return Package{}, err
	}
	if s.closed {
		return Package{}, errors.New("aptrepo: package spool is closed")
	}
	if !s.sealed {
		return Package{}, errors.New("aptrepo: package spool is not sealed")
	}
	if s.iterator == nil {
		iterator, err := newPackageMergeIterator(s.runs)
		if err != nil {
			return Package{}, err
		}
		s.iterator = iterator
	}
	pkg, err := s.iterator.Next(ctx)
	if err != nil && !errors.Is(err, io.EOF) {
		_ = s.iterator.Close()
	}
	return pkg, err
}

func (s *SortedPackageSpool) Close() error {
	if s == nil || s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.iterator != nil {
		err = s.iterator.Close()
	}
	removePackageRuns(s.runs)
	s.runs = nil
	s.chunk = nil
	return err
}

func (s *SortedPackageSpool) flushChunk(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	SortPackages(s.chunk)
	if err := rejectAdjacentDuplicateIdentities(s.chunk); err != nil {
		return err
	}
	file, err := createPackageRun(s.tempDir)
	if err != nil {
		return err
	}
	name := file.Name()
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	writer := bufio.NewWriterSize(file, 256*1024)
	for _, pkg := range s.chunk {
		if err := writePackageRunRecord(writer, pkg); err != nil {
			return err
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("aptrepo: flush package run: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("aptrepo: sync package run: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("aptrepo: close package run: %w", err)
	}
	ok = true
	s.runs = append(s.runs, name)
	s.chunk = make([]Package, 0, min(s.chunkEntries, 64))
	return nil
}

func (s *SortedPackageSpool) refreshStats() error {
	var bytes int64
	for _, name := range s.runs {
		info, err := os.Lstat(name)
		if err != nil {
			return fmt.Errorf("aptrepo: inspect package run: %w", err)
		}
		if !info.Mode().IsRegular() {
			return errors.New("aptrepo: package run is not a regular file")
		}
		bytes += info.Size()
	}
	s.stats.Runs = len(s.runs)
	s.stats.DiskBytes = bytes
	return nil
}

func createPackageRun(tempDir string) (*os.File, error) {
	file, err := os.CreateTemp(tempDir, "apt-packages-run-*.bin")
	if err != nil {
		return nil, fmt.Errorf("aptrepo: create package run: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return nil, fmt.Errorf("aptrepo: secure package run: %w", err)
	}
	if _, err := io.WriteString(file, packageRunMagic); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return nil, fmt.Errorf("aptrepo: write package run header: %w", err)
	}
	return file, nil
}

func writePackageRunRecord(w io.Writer, pkg Package) error {
	record := packageRunRecord{
		Name: pkg.Name, Source: pkg.Source, Version: pkg.Version,
		Architecture: pkg.Architecture, Component: pkg.Component,
		SourcePath: pkg.SourcePath, PoolPath: pkg.PoolPath,
		Size: pkg.Size, SHA256: pkg.SHA256,
		Order:  append([]string(nil), pkg.paragraph.Order...),
		Values: cloneStringMap(pkg.paragraph.Values),
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("aptrepo: encode package run record: %w", err)
	}
	if len(payload) == 0 || len(payload) > packageRunMaxRecord {
		return errors.New("aptrepo: package run record exceeds size limit")
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(payload)))
	digest := sha256.Sum256(payload)
	if _, err := w.Write(length[:]); err != nil {
		return fmt.Errorf("aptrepo: write package run record length: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("aptrepo: write package run record: %w", err)
	}
	if _, err := w.Write(digest[:]); err != nil {
		return fmt.Errorf("aptrepo: write package run checksum: %w", err)
	}
	return nil
}

type packageRunReader struct {
	file   *os.File
	reader *bufio.Reader
}

func openPackageRun(name string) (*packageRunReader, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("aptrepo: inspect package run: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("aptrepo: package run is not a regular file")
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("aptrepo: open package run: %w", err)
	}
	header := make([]byte, len(packageRunMagic))
	if _, err := io.ReadFull(file, header); err != nil || string(header) != packageRunMagic {
		_ = file.Close()
		return nil, errors.New("aptrepo: corrupt package run header")
	}
	return &packageRunReader{file: file, reader: bufio.NewReaderSize(file, 256*1024)}, nil
}

func (r *packageRunReader) Next() (Package, error) {
	var length [4]byte
	_, err := io.ReadFull(r.reader, length[:])
	if errors.Is(err, io.EOF) {
		return Package{}, io.EOF
	}
	if err != nil {
		return Package{}, errors.New("aptrepo: truncated package run record length")
	}
	size := binary.BigEndian.Uint32(length[:])
	if size == 0 || size > packageRunMaxRecord {
		return Package{}, errors.New("aptrepo: invalid package run record size")
	}
	payload := make([]byte, int(size))
	if _, err := io.ReadFull(r.reader, payload); err != nil {
		return Package{}, errors.New("aptrepo: truncated package run record")
	}
	var expected [sha256.Size]byte
	if _, err := io.ReadFull(r.reader, expected[:]); err != nil {
		return Package{}, errors.New("aptrepo: truncated package run checksum")
	}
	actual := sha256.Sum256(payload)
	if actual != expected {
		return Package{}, errors.New("aptrepo: corrupt package run checksum")
	}
	decoder := json.NewDecoder(bytesReader(payload))
	decoder.DisallowUnknownFields()
	var record packageRunRecord
	if err := decoder.Decode(&record); err != nil {
		return Package{}, fmt.Errorf("aptrepo: decode package run record: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Package{}, errors.New("aptrepo: trailing package run record data")
	}
	parsedVersion, err := version.Parse(record.Version)
	if err != nil {
		return Package{}, fmt.Errorf("aptrepo: invalid package run version: %w", err)
	}
	pkg := Package{
		Name: record.Name, Source: record.Source, Version: record.Version,
		Architecture: record.Architecture, Component: record.Component,
		SourcePath: record.SourcePath, PoolPath: record.PoolPath,
		Size: record.Size, SHA256: record.SHA256,
		debianVersion: parsedVersion,
		paragraph:     control.Paragraph{Order: append([]string(nil), record.Order...), Values: cloneStringMap(record.Values)},
	}
	if err := validatePackageMetadata(pkg); err != nil {
		return Package{}, fmt.Errorf("aptrepo: invalid package run record: %w", err)
	}
	return pkg, nil
}

func (r *packageRunReader) Close() error {
	if r == nil || r.file == nil {
		return nil
	}
	err := r.file.Close()
	r.file = nil
	return err
}

type packageRunCursor struct {
	pkg    Package
	reader *packageRunReader
	index  int
}

type packageRunHeap []*packageRunCursor

func (h packageRunHeap) Len() int { return len(h) }
func (h packageRunHeap) Less(i, j int) bool {
	comparison := comparePackages(h[i].pkg, h[j].pkg)
	if comparison != 0 {
		return comparison < 0
	}
	return h[i].index < h[j].index
}
func (h packageRunHeap) Swap(i, j int)   { h[i], h[j] = h[j], h[i] }
func (h *packageRunHeap) Push(value any) { *h = append(*h, value.(*packageRunCursor)) }
func (h *packageRunHeap) Pop() any {
	old := *h
	value := old[len(old)-1]
	*h = old[:len(old)-1]
	return value
}

type packageMergeIterator struct {
	cursors packageRunHeap
	last    *Package
	closed  bool
}

func newPackageMergeIterator(runs []string) (*packageMergeIterator, error) {
	iterator := &packageMergeIterator{}
	for index, name := range runs {
		reader, err := openPackageRun(name)
		if err != nil {
			_ = iterator.Close()
			return nil, err
		}
		pkg, err := reader.Next()
		if errors.Is(err, io.EOF) {
			_ = reader.Close()
			continue
		}
		if err != nil {
			_ = reader.Close()
			_ = iterator.Close()
			return nil, err
		}
		iterator.cursors = append(iterator.cursors, &packageRunCursor{pkg: pkg, reader: reader, index: index})
	}
	heap.Init(&iterator.cursors)
	return iterator, nil
}

func (m *packageMergeIterator) Next(ctx context.Context) (Package, error) {
	if err := ctx.Err(); err != nil {
		return Package{}, err
	}
	if m.closed || m.cursors.Len() == 0 {
		return Package{}, io.EOF
	}
	cursor := heap.Pop(&m.cursors).(*packageRunCursor)
	pkg := cursor.pkg
	if m.last != nil && samePackageIdentity(*m.last, pkg) {
		_ = cursor.reader.Close()
		_ = m.Close()
		return Package{}, ErrDuplicatePackageIdentity
	}
	next, err := cursor.reader.Next()
	if errors.Is(err, io.EOF) {
		_ = cursor.reader.Close()
	} else if err != nil {
		_ = cursor.reader.Close()
		_ = m.Close()
		return Package{}, err
	} else {
		cursor.pkg = next
		heap.Push(&m.cursors, cursor)
	}
	copyForOrder := pkg
	m.last = &copyForOrder
	return pkg, nil
}

func (m *packageMergeIterator) Close() error {
	if m == nil || m.closed {
		return nil
	}
	m.closed = true
	var err error
	for m.cursors.Len() > 0 {
		cursor := heap.Pop(&m.cursors).(*packageRunCursor)
		err = errors.Join(err, cursor.reader.Close())
	}
	return err
}

func mergePackageRunsToFile(ctx context.Context, tempDir string, runs []string) (string, error) {
	iterator, err := newPackageMergeIterator(runs)
	if err != nil {
		return "", err
	}
	defer iterator.Close()
	file, err := createPackageRun(tempDir)
	if err != nil {
		return "", err
	}
	name := file.Name()
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	writer := bufio.NewWriterSize(file, 256*1024)
	for {
		pkg, nextErr := iterator.Next(ctx)
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return "", nextErr
		}
		if err := writePackageRunRecord(writer, pkg); err != nil {
			return "", err
		}
	}
	if err := writer.Flush(); err != nil {
		return "", fmt.Errorf("aptrepo: flush merged package run: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("aptrepo: sync merged package run: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("aptrepo: close merged package run: %w", err)
	}
	ok = true
	return name, nil
}

func rejectAdjacentDuplicateIdentities(packages []Package) error {
	for i := 1; i < len(packages); i++ {
		if samePackageIdentity(packages[i-1], packages[i]) {
			return ErrDuplicatePackageIdentity
		}
	}
	return nil
}

func samePackageIdentity(a, b Package) bool {
	return a.Name == b.Name && version.Compare(a.debianVersion, b.debianVersion) == 0 && a.Architecture == b.Architecture
}

func cloneStringMap(values map[string]string) map[string]string {
	clone := make(map[string]string, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

func removePackageRuns(names []string) {
	for _, name := range names {
		_ = os.Remove(name)
	}
}

// bytesReader is kept narrow to avoid a bytes.Buffer allocation per record.
type byteSliceReader struct {
	data []byte
	off  int
}

func bytesReader(data []byte) *byteSliceReader { return &byteSliceReader{data: data} }

func (r *byteSliceReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

// compile-time guards for imports and intended ordering behavior.
var _ PackageIterator = (*SortedPackageSpool)(nil)
