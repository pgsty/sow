//go:build perf

package perf_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/catalog"
	"github.com/pgsty/sow/internal/cli"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/provenance"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

// TestLegacyAssetAdoptionFiftyThousand drives the real CLI over 50,000
// distinct source files and contents. Unlike the materialize scale fixture,
// this exercises init scanning, the disk-backed adoption spool, concurrent CAS
// imports, canonical view/receipt installation, cache rebuild, and idempotent
// replay as one product path.
func TestLegacyAssetAdoptionFiftyThousand(t *testing.T) {
	const (
		entries                 = 50_000
		workers                 = 8
		chunkEntries            = 512
		peakHeapGrowthLimit     = uint64(384 << 20)
		retainedHeapGrowthLimit = uint64(96 << 20)
		peakRSSGrowthLimit      = uint64(768 << 20)
	)
	root := t.TempDir()
	assetRoot := filepath.Join(root, "pkg")
	if err := os.MkdirAll(assetRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	var expectedBytes int64
	fixtureStarted := time.Now()
	for index := 0; index < entries; index++ {
		directory := filepath.Join(assetRoot, fmt.Sprintf("%03d", index/1000))
		if index%1000 == 0 {
			if err := os.Mkdir(directory, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		body := []byte(fmt.Sprintf("sow-adoption-asset-%05d\n", index))
		if err := os.WriteFile(filepath.Join(directory, fmt.Sprintf("asset-%05d.bin", index)), body, 0o644); err != nil {
			t.Fatal(err)
		}
		expectedBytes += int64(len(body))
	}
	fixtureElapsed := time.Since(fixtureStarted)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(`schema: sow/v1
state: {}
gpg: {}
pools:
  public: {}
  gated: {}
repos:
  - id: assets
    type: asset
    path: pkg
    default_pool: public
    asset: {kind: release, mutable_paths: [mutable/latest]}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge: {token_verifier: provider://test}
`), 0o600); err != nil {
		t.Fatal(err)
	}

	manifestDir := t.TempDir()
	beforePath := filepath.Join(manifestDir, "before.tsv")
	beforeStats, err := manifest.Scan(context.Background(), root, manifest.Scope{Path: "pkg"}, beforePath, manifest.ScanOptions{
		Workers: workers, ChunkEntries: chunkEntries, TempDir: filepath.Join(manifestDir, "before-runs"),
	})
	if err != nil || beforeStats.Files != entries || beforeStats.Bytes != expectedBytes {
		t.Fatalf("before serving manifest stats=%+v err=%v expected_bytes=%d", beforeStats, err, expectedBytes)
	}

	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)
	baselineRSS := maxRSSBytes(t)
	peakHeap := atomic.Uint64{}
	peakHeap.Store(baseline.HeapAlloc)
	stopSampling := make(chan struct{})
	samplingDone := make(chan struct{})
	go sampleHeapAlloc(&peakHeap, stopSampling, samplingDone)
	samplingStopped := false
	defer func() {
		if !samplingStopped {
			close(stopSampling)
			<-samplingDone
		}
	}()

	var stdout, stderr bytes.Buffer
	started := time.Now()
	code := cli.Main([]string{
		"init", "--adopt-content", "--config", configPath, "--repo", "assets",
		"--view", "latest", "--workers", strconv.Itoa(workers), "--chunk-entries", strconv.Itoa(chunkEntries),
	}, &stdout, &stderr)
	adoptElapsed := time.Since(started)
	if code != cli.ExitOK {
		t.Fatalf("50k adoption code=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	firstRunRSS := maxRSSBytes(t)

	runtime.GC()
	var retained runtime.MemStats
	runtime.ReadMemStats(&retained)
	retainedGrowth := positiveDifference(retained.HeapAlloc, baseline.HeapAlloc)
	if retainedGrowth > retainedHeapGrowthLimit {
		t.Fatalf("50k adoption retained heap exceeded bound: baseline=%d retained=%d retained_growth=%d",
			baseline.HeapAlloc, retained.HeapAlloc, retainedGrowth)
	}

	first := parseAdoptionSummary(t, stdout.String())
	assertAdoptionSummary(t, first, entries, expectedBytes, workers, true)
	if scannedPeak := parseScannedPeak(t, stdout.String(), "assets"); scannedPeak != first.int64(t, "peak_import_workers") {
		t.Fatalf("scanned peak=%d summary peak=%d", scannedPeak, first.int64(t, "peak_import_workers"))
	}

	canonical := state.New(filepath.Join(root, ".sow"))
	head, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	baselineCount, baselineClosure := manifestClosure(t, beforePath, "public")
	viewCount, viewClosure := adoptedViewClosure(t, canonical, "latest", "assets", "all", "all")
	receiptCount, receiptClosure, receiptProvenanceClosure := legacyReceiptClosure(t, canonical, "assets")
	cacheStats, err := catalog.Statistics(context.Background(), filepath.Join(root, ".sow"))
	if err != nil {
		t.Fatal(err)
	}
	cacheCount, cacheClosure := catalogClosure(t, filepath.Join(root, ".sow"), "assets", "public")
	cacheProvenanceCount, cacheProvenanceClosure := catalogLegacyProvenanceClosure(t, filepath.Join(root, ".sow"), "assets")
	casCount := countRegularFiles(t, filepath.Join(root, ".pool", "sha256"))
	verifyCASClosure(t, root, beforePath)
	if baselineCount != entries || viewCount != entries || receiptCount != entries || cacheCount != entries || cacheProvenanceCount != entries || casCount != entries ||
		cacheStats.Files != entries || cacheStats.Packages != 0 || cacheStats.Memberships != 0 || cacheStats.Provenance != entries || cacheStats.Relations != 0 ||
		baselineClosure != viewClosure || baselineClosure != receiptClosure || baselineClosure != cacheClosure || receiptProvenanceClosure != cacheProvenanceClosure {
		t.Fatalf("adoption closure baseline=%d view=%d receipt=%d cache=%d cache_provenance=%d cas=%d stats=%+v tuple_hashes=%x/%x/%x/%x provenance_hashes=%x/%x want=%d",
			baselineCount, viewCount, receiptCount, cacheCount, cacheProvenanceCount, casCount, cacheStats,
			baselineClosure, viewClosure, receiptClosure, cacheClosure, receiptProvenanceClosure, cacheProvenanceClosure, entries)
	}

	afterPath := filepath.Join(manifestDir, "after.tsv")
	afterStats, err := manifest.Scan(context.Background(), root, manifest.Scope{Path: "pkg"}, afterPath, manifest.ScanOptions{
		Workers: workers, ChunkEntries: chunkEntries, TempDir: filepath.Join(manifestDir, "after-runs"),
	})
	if err != nil || afterStats != beforeStats || fileSHA256(t, afterPath) != fileSHA256(t, beforePath) {
		t.Fatalf("adoption rewrote serving tree: before=%+v after=%+v err=%v", beforeStats, afterStats, err)
	}

	var replayStdout, replayStderr bytes.Buffer
	replayStarted := time.Now()
	replayCode := cli.Main([]string{
		"init", "--adopt-content", "--config", configPath, "--repo", "assets",
		"--view", "latest", "--workers", strconv.Itoa(workers), "--chunk-entries", strconv.Itoa(chunkEntries),
	}, &replayStdout, &replayStderr)
	replayElapsed := time.Since(replayStarted)
	if replayCode != cli.ExitOK {
		t.Fatalf("50k replay code=%d stderr=%s stdout=%s", replayCode, replayStderr.String(), replayStdout.String())
	}
	close(stopSampling)
	<-samplingDone
	samplingStopped = true
	peakGrowth := positiveDifference(peakHeap.Load(), baseline.HeapAlloc)
	if peakGrowth > peakHeapGrowthLimit {
		t.Fatalf("50k adoption and replay sampled heap exceeded bound: baseline=%d peak=%d peak_growth=%d limit=%d",
			baseline.HeapAlloc, peakHeap.Load(), peakGrowth, peakHeapGrowthLimit)
	}
	replayRSS := maxRSSBytes(t)
	rssGrowth := positiveDifference(replayRSS, baselineRSS)
	if rssGrowth > peakRSSGrowthLimit {
		t.Fatalf("50k adoption process RSS exceeded bound: baseline=%d first=%d replay=%d growth=%d limit=%d", baselineRSS, firstRunRSS, replayRSS, rssGrowth, peakRSSGrowthLimit)
	}
	replay := parseAdoptionSummary(t, replayStdout.String())
	assertAdoptionSummary(t, replay, entries, expectedBytes, workers, false)
	afterReplayHead, err := canonical.HeadHash()
	if err != nil || afterReplayHead != head {
		t.Fatalf("idempotent replay advanced HEAD before=%s after=%s err=%v", head, afterReplayHead, err)
	}
	if got := countRegularFiles(t, filepath.Join(root, ".pool", "sha256")); got != entries {
		t.Fatalf("idempotent replay CAS objects=%d want=%d", got, entries)
	}

	afterReplayPath := filepath.Join(manifestDir, "after-replay.tsv")
	afterReplayStats, err := manifest.Scan(context.Background(), root, manifest.Scope{Path: "pkg"}, afterReplayPath, manifest.ScanOptions{
		Workers: workers, ChunkEntries: chunkEntries, TempDir: filepath.Join(manifestDir, "after-replay-runs"),
	})
	if err != nil || afterReplayStats != beforeStats || fileSHA256(t, afterReplayPath) != fileSHA256(t, beforePath) {
		t.Fatalf("idempotent replay rewrote serving tree: before=%+v after=%+v err=%v", beforeStats, afterReplayStats, err)
	}

	t.Logf("legacy-adoption50k entries=%d unique_payloads=%d bytes=%d workers=%d peak_import_workers=%d fixture=%s adopt=%s replay=%s view=%d receipts=%d cache=%d cache_provenance=%d cas=%d baseline_heap=%d sampled_peak_heap=%d sampled_peak_growth=%d retained_heap=%d retained_growth=%d baseline_rss=%d first_rss=%d replay_rss=%d rss_growth=%d tuple_closure_sha256=%x provenance_closure_sha256=%x serving_manifest_unchanged=true replay_changed=false",
		entries, first.int64(t, "payloads"), expectedBytes, workers, first.int64(t, "peak_import_workers"), fixtureElapsed,
		adoptElapsed, replayElapsed, viewCount, receiptCount, cacheCount, cacheProvenanceCount, casCount, baseline.HeapAlloc, peakHeap.Load(), peakGrowth,
		retained.HeapAlloc, retainedGrowth, baselineRSS, firstRunRSS, replayRSS, rssGrowth, baselineClosure, receiptProvenanceClosure)
}

type adoptionMetrics map[string]string

func parseAdoptionSummary(t *testing.T, output string) adoptionMetrics {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if !strings.HasPrefix(line, "adopt-content commit=") {
			continue
		}
		metrics := adoptionMetrics{}
		for _, field := range strings.Fields(strings.TrimPrefix(line, "adopt-content ")) {
			key, value, ok := strings.Cut(field, "=")
			if ok {
				metrics[key] = value
			}
		}
		return metrics
	}
	t.Fatalf("missing adoption summary in output:\n%s", output)
	return nil
}

func (m adoptionMetrics) int64(t *testing.T, key string) int64 {
	t.Helper()
	value, ok := m[key]
	if !ok {
		t.Fatalf("missing metric %s in %+v", key, m)
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		t.Fatalf("metric %s=%q: %v", key, value, err)
	}
	return parsed
}

func assertAdoptionSummary(t *testing.T, metrics adoptionMetrics, entries int64, expectedBytes int64, workers int64, changed bool) {
	t.Helper()
	if metrics["changed"] != strconv.FormatBool(changed) ||
		metrics.int64(t, "payloads") != entries || metrics.int64(t, "bytes") != expectedBytes ||
		metrics.int64(t, "leaves") != 1 || metrics.int64(t, "receipts") != entries ||
		metrics.int64(t, "pruned_missing_yum") != 0 || metrics.int64(t, "cache_entries") != entries ||
		metrics["serving_tree_rewritten"] != "false" {
		t.Fatalf("unexpected adoption summary: %+v", metrics)
	}
	peak := metrics.int64(t, "peak_import_workers")
	if peak < 2 || peak > workers {
		t.Fatalf("adoption did not demonstrate bounded parallel import: peak=%d workers=%d", peak, workers)
	}
}

func parseScannedPeak(t *testing.T, output, repo string) int64 {
	t.Helper()
	prefix := "adopt-content scanned repo=" + repo + " "
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		for _, field := range strings.Fields(line) {
			if strings.HasPrefix(field, "peak_import_workers=") {
				value, err := strconv.ParseInt(strings.TrimPrefix(field, "peak_import_workers="), 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				return value
			}
		}
	}
	t.Fatalf("missing scanned peak for %s in output:\n%s", repo, output)
	return 0
}

func manifestClosure(t *testing.T, filename, pool string) (int64, [sha256.Size]byte) {
	t.Helper()
	stream, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	reader := manifest.NewReader(stream)
	hash := sha256.New()
	var count int64
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return count, closureDigest(hash)
		}
		if err != nil {
			t.Fatal(err)
		}
		writeClosureTuple(t, hash, entry.Path, entry.Size, entry.HashString(), pool)
		count++
	}
}

func adoptedViewClosure(t *testing.T, canonical *state.Store, view, repo, osName, arch string) (int64, [sha256.Size]byte) {
	t.Helper()
	ref, err := state.ViewRef(view, repo, osName, arch)
	if err != nil {
		t.Fatal(err)
	}
	commit, exists, err := canonical.Ref(ref)
	if err != nil || !exists {
		t.Fatalf("view ref %s exists=%t err=%v", ref, exists, err)
	}
	viewPath, err := state.ViewPath(view, repo, osName, arch)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := canonical.OpenPathAt(commit, viewPath)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	reader := views.NewReader(stream)
	hash := sha256.New()
	var count int64
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return count, closureDigest(hash)
		}
		if err != nil {
			t.Fatal(err)
		}
		writeClosureTuple(t, hash, entry.Path, entry.Size, entry.SHA256, entry.Pool)
		count++
	}
}

func legacyReceiptClosure(t *testing.T, canonical *state.Store, repo string) (int64, [sha256.Size]byte, [sha256.Size]byte) {
	t.Helper()
	stream, err := canonical.OpenPath(filepath.ToSlash(filepath.Join("provenance", "legacy", repo+".jsonl")))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	reader := provenance.NewLegacyAdoptionReader(stream)
	tupleHash := sha256.New()
	provenanceHash := sha256.New()
	var count int64
	for {
		receipt, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return count, closureDigest(tupleHash), closureDigest(provenanceHash)
		}
		if err != nil {
			t.Fatal(err)
		}
		if receipt.Format != "asset" || receipt.CanonicalPath != receipt.SourcePath {
			t.Fatalf("unexpected 50k asset receipt format=%q source=%q canonical=%q", receipt.Format, receipt.SourcePath, receipt.CanonicalPath)
		}
		canonicalJSON, err := receipt.CanonicalJSON()
		if err != nil {
			t.Fatal(err)
		}
		receiptDigest := sha256.Sum256(canonicalJSON)
		writeClosureTuple(t, tupleHash, receipt.CanonicalPath, receipt.ArtifactSize, receipt.ArtifactSHA256, receipt.Pool)
		writeProvenanceClosureRecord(t, provenanceHash, catalog.ProvenanceRecord{
			ReceiptID: fmt.Sprintf("%x", receiptDigest[:]), ArtifactSHA256: receipt.ArtifactSHA256,
			Format: receipt.Format, Kind: "legacy", Repo: receipt.Repo, SourcePath: receipt.SourcePath,
			Pool: receipt.Pool, ObservedAt: receipt.AdoptedAt.Format("2006-01-02T15:04:05.999999999Z"),
		})
		count++
	}
}

func catalogLegacyProvenanceClosure(t *testing.T, stateDir, repo string) (int64, [sha256.Size]byte) {
	t.Helper()
	stream, err := catalog.OpenLegacyProvenanceProjection(context.Background(), stateDir, repo)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	hash := sha256.New()
	var count int64
	for {
		record, err := stream.Next()
		if errors.Is(err, io.EOF) {
			return count, closureDigest(hash)
		}
		if err != nil {
			t.Fatal(err)
		}
		writeProvenanceClosureRecord(t, hash, record)
		count++
	}
}

func catalogClosure(t *testing.T, stateDir, repo, pool string) (int64, [sha256.Size]byte) {
	t.Helper()
	stream, err := catalog.OpenManifestProjection(context.Background(), stateDir, repo)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	reader := manifest.NewReader(stream)
	hash := sha256.New()
	var count int64
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return count, closureDigest(hash)
		}
		if err != nil {
			t.Fatal(err)
		}
		writeClosureTuple(t, hash, entry.Path, entry.Size, entry.HashString(), pool)
		count++
	}
}

func verifyCASClosure(t *testing.T, root, manifestPath string) {
	t.Helper()
	pool, err := repository.OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := pool.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	stream, err := os.Open(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	reader := manifest.NewReader(stream)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		digest, err := repository.ParseDigest(entry.HashString())
		if err != nil {
			t.Fatal(err)
		}
		if err := pool.Verify(context.Background(), repository.Object{SHA256: digest, Size: entry.Size}); err != nil {
			t.Fatalf("verify CAS object for %q: %v", entry.Path, err)
		}
	}
}

func writeClosureTuple(t *testing.T, writer io.Writer, path string, size int64, digest, pool string) {
	t.Helper()
	if _, err := fmt.Fprintf(writer, "%s\t%d\t%s\t%s\n", path, size, digest, pool); err != nil {
		t.Fatal(err)
	}
}

func writeProvenanceClosureRecord(t *testing.T, writer io.Writer, record catalog.ProvenanceRecord) {
	t.Helper()
	if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
		record.ReceiptID, record.ArtifactSHA256, record.Format, record.Kind, record.Repo,
		record.SourcePath, record.Pool, record.UpstreamURL, record.ObservedAt); err != nil {
		t.Fatal(err)
	}
}

func closureDigest(hash interface{ Sum([]byte) []byte }) [sha256.Size]byte {
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func countRegularFiles(t *testing.T, root string) int64 {
	t.Helper()
	var count int64
	if err := filepath.WalkDir(root, func(_ string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			count++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return count
}

func fileSHA256(t *testing.T, filename string) [sha256.Size]byte {
	t.Helper()
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatalf("hash %s: copy=%v close=%v", filename, copyErr, closeErr)
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func sampleHeapAlloc(peak *atomic.Uint64, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			var stats runtime.MemStats
			runtime.ReadMemStats(&stats)
			for observed := peak.Load(); stats.HeapAlloc > observed; observed = peak.Load() {
				if peak.CompareAndSwap(observed, stats.HeapAlloc) {
					break
				}
			}
		case <-stop:
			return
		}
	}
}

func maxRSSBytes(t *testing.T) uint64 {
	t.Helper()
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		t.Fatalf("read process maximum RSS: %v", err)
	}
	if usage.Maxrss < 0 {
		t.Fatalf("process maximum RSS is negative: %d", usage.Maxrss)
	}
	value := uint64(usage.Maxrss)
	switch runtime.GOOS {
	case "darwin":
		return value
	case "linux":
		return value * 1024
	default:
		t.Fatalf("unsupported process maximum RSS unit on %s", runtime.GOOS)
		return 0
	}
}

func positiveDifference(after, before uint64) uint64 {
	if after > before {
		return after - before
	}
	return 0
}
