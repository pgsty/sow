package aptrepo

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"pault.ag/go/debian/control"
	debversion "pault.ag/go/debian/version"
)

func TestSortedPackageSpoolExternalOrderUsesDebianVersions(t *testing.T) {
	payload := writeSpoolPayload(t)
	spool, err := NewSortedPackageSpool(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	input := []Package{
		syntheticParsedPackage(t, payload, "zeta", "1.0", "amd64", "main"),
		syntheticParsedPackage(t, payload, "alpha", "2.0", "amd64", "main"),
		syntheticParsedPackage(t, payload, "alpha", "1:0.1", "amd64", "main"),
		syntheticParsedPackage(t, payload, "alpha", "1.0", "amd64", "main"),
		syntheticParsedPackage(t, payload, "alpha", "1.0~rc1", "amd64", "main"),
	}
	for _, pkg := range input {
		if err := spool.Add(context.Background(), pkg); err != nil {
			t.Fatal(err)
		}
	}
	if err := spool.Seal(context.Background()); err != nil {
		t.Fatal(err)
	}
	var got []string
	for {
		pkg, err := spool.Next(context.Background())
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, pkg.Name+"="+pkg.Version)
	}
	want := []string{"alpha=1.0~rc1", "alpha=1.0", "alpha=2.0", "alpha=1:0.1", "zeta=1.0"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("external Debian order = %v, want %v", got, want)
	}
	if stats := spool.Stats(); stats.Entries != int64(len(input)) || stats.PeakChunkItems != 1 || stats.Runs != len(input) || stats.DiskBytes == 0 {
		t.Fatalf("unexpected spool stats: %+v", stats)
	}
}

func TestSortedPackageSpoolRejectsDuplicateAcrossRuns(t *testing.T) {
	pkg := syntheticParsedPackage(t, writeSpoolPayload(t), "duplicate", "1.0", "amd64", "main")
	spool, err := NewSortedPackageSpool(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	if err := spool.Add(context.Background(), pkg); err != nil {
		t.Fatal(err)
	}
	if err := spool.Add(context.Background(), pkg); err != nil {
		t.Fatal(err)
	}
	if err := spool.Seal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Next(context.Background()); !errors.Is(err, ErrDuplicatePackageIdentity) {
		t.Fatalf("duplicate merge error = %v, want %v", err, ErrDuplicatePackageIdentity)
	}
}

func TestSortedPackageSpoolCancellationAndCorruption(t *testing.T) {
	pkg := syntheticParsedPackage(t, writeSpoolPayload(t), "cancel", "1.0", "amd64", "main")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	spool, err := NewSortedPackageSpool(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Add(canceled, pkg); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Add error = %v", err)
	}
	if err := spool.Add(context.Background(), pkg); err != nil {
		t.Fatal(err)
	}
	if err := spool.Seal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Next(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Next error = %v", err)
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}

	corrupt, err := NewSortedPackageSpool(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer corrupt.Close()
	if err := corrupt.Add(context.Background(), pkg); err != nil {
		t.Fatal(err)
	}
	if err := corrupt.Seal(context.Background()); err != nil {
		t.Fatal(err)
	}
	run := corrupt.runs[0]
	file, err := os.OpenFile(run, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(int64(len(packageRunMagic)+4+8), io.SeekStart); err != nil {
		t.Fatal(err)
	}
	one := []byte{0}
	if _, err := file.Read(one); err != nil {
		t.Fatal(err)
	}
	one[0] ^= 0xff
	if _, err := file.Seek(-1, io.SeekCurrent); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(one); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := corrupt.Next(context.Background()); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("corrupt run error = %v", err)
	}
}

func TestSortedPackageSpoolHierarchicalMergeKeepsFanInBounded(t *testing.T) {
	payload := writeSpoolPayload(t)
	spool, err := NewSortedPackageSpool(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	for i := 129; i >= 0; i-- {
		pkg := syntheticParsedPackage(t, payload, fmt.Sprintf("pkg%04d", i), "1.0", "amd64", "main")
		if err := spool.Add(context.Background(), pkg); err != nil {
			t.Fatal(err)
		}
	}
	if err := spool.Seal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if stats := spool.Stats(); stats.Runs > packageRunMergeFanIn {
		t.Fatalf("final merge fan-in = %d, max %d", stats.Runs, packageRunMergeFanIn)
	}
	last := ""
	count := 0
	for {
		pkg, err := spool.Next(context.Background())
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if pkg.Name <= last {
			t.Fatalf("merged order regressed: %q after %q", pkg.Name, last)
		}
		last = pkg.Name
		count++
	}
	if count != 130 {
		t.Fatalf("merged entries = %d, want 130", count)
	}
}

func TestGenerateStreamingBoundsWorkersAndProducesParseableIndexes(t *testing.T) {
	created := time.Date(2026, 7, 12, 5, 0, 0, 0, time.UTC)
	signer, _, _ := testSigningMaterial(t, created.Add(-time.Hour))
	payload := writeSpoolPayload(t)
	gate := newIteratorGate(2)
	indexes := []StreamingIndex{
		{Component: "main", Architecture: "amd64", Packages: gate.iterator(syntheticParsedPackage(t, payload, "alpha", "1.0", "amd64", "main"))},
		{Component: "main", Architecture: "arm64", Packages: gate.iterator(syntheticParsedPackage(t, payload, "beta", "1.0", "arm64", "main"))},
	}
	root := t.TempDir()
	result, err := GenerateStreaming(context.Background(), root, RepositoryConfig{
		Origin: "Pigsty", Label: "Pigsty", Suite: "beta", Codename: "beta",
		Components: []string{"main"}, Architectures: []string{"amd64", "arm64"}, Date: created,
	}, indexes, signer, StreamingOptions{Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	if result.StreamedPackages != 2 || result.PeakIndexWorkers != 2 || gate.peak.Load() != 2 {
		t.Fatalf("streaming result packages=%d peak=%d iterator_peak=%d", result.StreamedPackages, result.PeakIndexWorkers, gate.peak.Load())
	}
	for _, arch := range []string{"amd64", "arm64"} {
		file, err := os.Open(filepath.Join(root, "dists", "beta", "main", "binary-"+arch, "Packages"))
		if err != nil {
			t.Fatal(err)
		}
		entries, parseErr := control.ParseBinaryIndex(bufio.NewReader(file))
		closeErr := file.Close()
		if parseErr != nil || closeErr != nil || len(entries) != 1 {
			t.Fatalf("parse %s Packages entries=%d err=%v", arch, len(entries), errors.Join(parseErr, closeErr))
		}
	}
}

// This is intentionally opt-in because it writes and compresses all 50,000
// package paragraphs. CI and release evidence run it with SOW_RUN_PERF=1.
func TestGenerateStreaming50000Performance(t *testing.T) {
	if os.Getenv("SOW_RUN_PERF") != "1" {
		t.Skip("set SOW_RUN_PERF=1 to run the 50,000-package evidence test")
	}
	const (
		packageCount = 50_000
		indexCount   = 8
		chunkEntries = 256
		workers      = 4
	)
	created := time.Date(2026, 7, 12, 6, 0, 0, 0, time.UTC)
	payload := writeSpoolPayload(t)
	tempDir := t.TempDir()
	spools := make([]*SortedPackageSpool, indexCount)
	indexes := make([]StreamingIndex, 0, indexCount)
	arches := []string{"amd64", "arm64", "ppc64el", "s390x"}
	components := []string{"main", "contrib"}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	started := time.Now()
	for index := range indexCount {
		spool, err := NewSortedPackageSpool(tempDir, chunkEntries)
		if err != nil {
			t.Fatal(err)
		}
		spools[index] = spool
		component := components[index/len(arches)]
		arch := arches[index%len(arches)]
		for item := index; item < packageCount; item += indexCount {
			pkg := syntheticParsedPackage(t, payload, fmt.Sprintf("pkg%05d", item), "1.0~rc1+pgsty1", arch, component)
			if err := spool.Add(context.Background(), pkg); err != nil {
				t.Fatal(err)
			}
		}
		if err := spool.Seal(context.Background()); err != nil {
			t.Fatal(err)
		}
		indexes = append(indexes, StreamingIndex{Component: component, Architecture: arch, Packages: spool})
	}
	defer func() {
		for _, spool := range spools {
			_ = spool.Close()
		}
	}()
	runtime.GC()
	var afterSpool runtime.MemStats
	runtime.ReadMemStats(&afterSpool)
	var diskBytes int64
	peakChunk := 0
	for _, spool := range spools {
		stats := spool.Stats()
		diskBytes += stats.DiskBytes
		if stats.PeakChunkItems > peakChunk {
			peakChunk = stats.PeakChunkItems
		}
	}
	signer, _, _ := testSigningMaterial(t, created.Add(-time.Hour))
	result, err := GenerateStreaming(context.Background(), t.TempDir(), RepositoryConfig{
		Origin: "Pigsty", Label: "Pigsty", Suite: "perf", Codename: "perf",
		Components: components, Architectures: arches, Date: created,
	}, indexes, signer, StreamingOptions{Workers: workers})
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	retained := int64(afterSpool.HeapAlloc) - int64(before.HeapAlloc)
	if retained < 0 {
		retained = 0
	}
	var usage unix.Rusage
	_ = unix.Getrusage(unix.RUSAGE_SELF, &usage)
	t.Logf("apt_stream_50k packages=%d elapsed=%s retained_heap=%d heap_after=%d maxrss_raw=%d spool_disk=%d chunk_peak=%d worker_peak=%d", packageCount, time.Since(started), retained, after.HeapAlloc, usage.Maxrss, diskBytes, peakChunk, result.PeakIndexWorkers)
	if result.StreamedPackages != packageCount {
		t.Fatalf("streamed packages = %d, want %d", result.StreamedPackages, packageCount)
	}
	if peakChunk > chunkEntries || result.PeakIndexWorkers < 2 || result.PeakIndexWorkers > workers {
		t.Fatalf("unbounded evidence chunk=%d workers=%d", peakChunk, result.PeakIndexWorkers)
	}
	if diskBytes == 0 {
		t.Fatal("external sort did not retain disk spool evidence")
	}
	if retained > 96<<20 {
		t.Fatalf("retained heap = %d, expected <= 96 MiB", retained)
	}
}

func syntheticParsedPackage(t *testing.T, payload, name, rawVersion, arch, component string) Package {
	t.Helper()
	parsed, err := debversion.Parse(rawVersion)
	if err != nil {
		t.Fatal(err)
	}
	filename := fmt.Sprintf("%s_%s_%s.deb", name, rawVersion, arch)
	poolPath, err := PoolPath(component, name, filename)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(payload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	values := map[string]string{
		"Package": name, "Source": name, "Version": rawVersion,
		"Architecture": arch, "Description": "synthetic parsed package",
	}
	return Package{
		Name: name, Source: name, Version: rawVersion, Architecture: arch,
		Component: component, SourcePath: payload, PoolPath: poolPath,
		Size: int64(len(data)), SHA256: hex.EncodeToString(digest[:]),
		debianVersion: parsed,
		paragraph: control.Paragraph{
			Order:  []string{"Package", "Source", "Version", "Architecture", "Description"},
			Values: values,
		},
	}
}

func writeSpoolPayload(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "source.bin")
	if err := os.WriteFile(path, []byte("sow-apt-stream-payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type iteratorGate struct {
	want    int64
	active  atomic.Int64
	peak    atomic.Int64
	release chan struct{}
	once    sync.Once
}

func newIteratorGate(want int64) *iteratorGate {
	return &iteratorGate{want: want, release: make(chan struct{})}
}

func (g *iteratorGate) iterator(pkg Package) PackageIterator {
	used := false
	return packageIteratorFunc(func(ctx context.Context) (Package, error) {
		if used {
			return Package{}, io.EOF
		}
		used = true
		current := g.active.Add(1)
		defer g.active.Add(-1)
		for previous := g.peak.Load(); current > previous && !g.peak.CompareAndSwap(previous, current); previous = g.peak.Load() {
		}
		if current >= g.want {
			g.once.Do(func() { close(g.release) })
		}
		select {
		case <-g.release:
			return pkg, nil
		case <-ctx.Done():
			return Package{}, ctx.Err()
		}
	})
}

type packageIteratorFunc func(context.Context) (Package, error)

func (f packageIteratorFunc) Next(ctx context.Context) (Package, error) { return f(ctx) }
