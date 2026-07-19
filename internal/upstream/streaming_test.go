package upstream

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/provenance"
	"github.com/pgsty/sow/internal/syncer"
)

type allPresentInventory struct{}

func (allPresentInventory) Has(string, int64) (bool, error) { return true, nil }

type countingResultSink struct {
	downloaded int
	present    int
}

func (s *countingResultSink) PutDownloaded(Downloaded) error {
	s.downloaded++
	return nil
}

func (s *countingResultSink) PutPresent(ReceiptCommit) error {
	s.present++
	return nil
}

func TestStreamingCandidateStoreFiftyThousandBoundedMemory(t *testing.T) {
	const candidateCount = 50_000
	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)

	discovery, err := newDiscovery("rpm", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer discovery.Close()
	indexDigest := fmt.Sprintf("%064x", candidateCount+1)
	for index := 0; index < candidateCount; index++ {
		digest := fmt.Sprintf("%064x", index+1)
		candidate := syncer.Candidate{
			Format: "rpm", Name: fmt.Sprintf("package-%05d", index), Version: "1.0-1", Arch: "x86_64",
			URL:  fmt.Sprintf("https://packages.example.invalid/Packages/package-%05d.rpm", index),
			Size: 4096, SHA256: digest,
		}
		proof := provenance.RPMProof{
			IndexURL: "https://packages.example.invalid/repodata/primary.xml.zst", IndexSHA256: indexDigest,
			IndexSize: 1, OriginalRPMSHA: digest, SignaturePolicy: "preserve-upstream",
		}
		if err := addDiscoveredCandidate(discovery, candidate, candidateProof{rpm: &proof}); err != nil {
			t.Fatalf("add candidate %d: %v", index, err)
		}
	}
	if err := finalizeDiscovery(discovery); err != nil {
		t.Fatal(err)
	}
	if discovery.CandidateCount() != candidateCount || discovery.Candidates != nil {
		t.Fatalf("streaming discovery count=%d materialized=%d", discovery.CandidateCount(), len(discovery.Candidates))
	}
	if info, err := os.Stat(discovery.store.path); err != nil || info.Size() < 1<<20 {
		t.Fatalf("candidate disk spool size=%v err=%v", func() int64 {
			if info == nil {
				return 0
			}
			return info.Size()
		}(), err)
	}

	seen := 0
	previous := ""
	plan, err := syncer.BuildPlanStream(discovery.ForEachCandidate, syncer.Filter{DebugInfo: "keep"}, allPresentInventory{}, func(candidate syncer.Candidate) error {
		if previous != "" && candidate.SHA256 <= previous {
			t.Fatalf("candidate iterator is not strictly ordered: %s then %s", previous, candidate.SHA256)
		}
		previous = candidate.SHA256
		seen++
		return nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if seen != candidateCount || plan.Present != candidateCount || plan.DownloadCount != 0 {
		t.Fatalf("seen=%d plan=%+v", seen, plan)
	}

	runtime.GC()
	var retained runtime.MemStats
	runtime.ReadMemStats(&retained)
	const maxRetainedGrowth = 24 << 20
	const maxRetainedHeap = 16 << 20
	growth := positiveHeapGrowth(baseline.HeapAlloc, retained.HeapAlloc)
	t.Logf("50k candidates: baseline_heap=%d retained_heap=%d growth=%d disk_spool=%d bytes", baseline.HeapAlloc, retained.HeapAlloc, growth, func() int64 {
		info, _ := os.Stat(discovery.store.path)
		if info == nil {
			return 0
		}
		return info.Size()
	}())
	if growth > maxRetainedGrowth {
		t.Fatalf("50k disk-backed iteration retained %d bytes; limit is %d", growth, maxRetainedGrowth)
	}
	if retained.HeapAlloc > maxRetainedHeap {
		t.Fatalf("50k disk-backed iteration heap=%d bytes; absolute limit is %d", retained.HeapAlloc, maxRetainedHeap)
	}
}

func positiveHeapGrowth(before, after uint64) uint64 {
	if after <= before {
		return 0
	}
	return after - before
}

func TestStreamingExecutorBoundsRealHTTPDownloadConcurrency(t *testing.T) {
	const (
		packageCount = 24
		workers      = 3
	)
	bodies := make(map[string][]byte, packageCount)
	var active atomic.Int32
	var maximum atomic.Int32
	overlapped := make(chan struct{})
	var releaseOverlap sync.Once
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, ok := bodies[request.URL.Path]
		if !ok {
			http.NotFound(response, request)
			return
		}
		current := active.Add(1)
		defer active.Add(-1)
		for {
			prior := maximum.Load()
			if current <= prior || maximum.CompareAndSwap(prior, current) {
				break
			}
		}
		if current >= 2 {
			releaseOverlap.Do(func() { close(overlapped) })
		}
		// Hold the first request open until another worker reaches the real
		// HTTP server. This proves overlap without depending on a 10 ms
		// scheduler window, which becomes flaky while the full repository's
		// disk-heavy integration tests are running concurrently.
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case <-overlapped:
		case <-timer.C:
			releaseOverlap.Do(func() { close(overlapped) })
		}
		_, _ = response.Write(body)
	}))
	defer server.Close()

	work := t.TempDir()
	discovery, err := newDiscovery("deb", filepath.Join(work, "metadata"))
	if err != nil {
		t.Fatal(err)
	}
	defer discovery.Close()
	releaseEvidence, err := preserveBytes(filepath.Join(work, "metadata"), "apt-inrelease", server.URL+"/dists/test/InRelease", []byte("signed-release"), true)
	if err != nil {
		t.Fatal(err)
	}
	packagesEvidence, err := preserveBytes(filepath.Join(work, "metadata"), "apt-packages", server.URL+"/dists/test/main/binary-amd64/Packages", []byte("packages-index"), true)
	if err != nil {
		t.Fatal(err)
	}
	discovery.Evidence = []Evidence{releaseEvidence, packagesEvidence}
	for index := 0; index < packageCount; index++ {
		path := fmt.Sprintf("/pool/main/p/package-%02d.deb", index)
		body := []byte(fmt.Sprintf("verified-package-body-%02d", index))
		bodies[path] = body
		digest := sha256.Sum256(body)
		candidate := syncer.Candidate{
			Format: "deb", Name: fmt.Sprintf("package-%02d", index), Version: "1", Arch: "amd64",
			URL: server.URL + path, Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:]),
		}
		proof := provenance.DEBProof{
			PackagesEntrySHA256: candidate.SHA256, PackagesEvidenceSHA256: packagesEvidence.SHA256,
			SignedReleaseSHA256: releaseEvidence.SHA256, SignedReleaseKind: "InRelease",
		}
		if err := addDiscoveredCandidate(discovery, candidate, candidateProof{deb: &proof}); err != nil {
			t.Fatal(err)
		}
	}
	if err := finalizeDiscovery(discovery); err != nil {
		t.Fatal(err)
	}
	if err := sealEvidence(discovery); err != nil {
		t.Fatal(err)
	}
	sink := &countingResultSink{}
	result, err := (Executor{
		Downloader:  syncer.Downloader{Client: server.Client(), Attempts: 1},
		DownloadDir: filepath.Join(work, "downloads"), Provenance: provenance.NewStore(filepath.Join(work, "state")),
		Workers: workers, Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}).RunStreaming(context.Background(), discovery, syncer.Filter{DebugInfo: "keep"}, emptyInventory{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	if result.Plan.DownloadCount != packageCount || sink.downloaded != packageCount || sink.present != 0 {
		t.Fatalf("result=%+v sink=%+v", result.Plan, sink)
	}
	if got := maximum.Load(); got < 2 || got > workers {
		t.Fatalf("real HTTP concurrency=%d, want 2..%d", got, workers)
	}
}
