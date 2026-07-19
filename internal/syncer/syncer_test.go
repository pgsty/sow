package syncer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
)

func TestFilterNameArchRegexAndDebugInfo(t *testing.T) {
	filter := Filter{Allow: []string{"postgresql-*", "re:^pig@(?:amd64|x86_64)$"}, Deny: []string{"*-docs"}, DebugInfo: "drop"}
	if err := filter.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		name, arch  string
		debug, want bool
	}{
		{"postgresql-18", "amd64", false, true},
		{"pig", "x86_64", false, true},
		{"pig", "aarch64", false, false},
		{"postgresql-docs", "amd64", false, false},
		{"postgresql-debuginfo", "amd64", true, false},
	} {
		if got := filter.Match(item.name, item.arch, item.debug); got != item.want {
			t.Errorf("Match(%s,%s,%v)=%v want=%v", item.name, item.arch, item.debug, got, item.want)
		}
	}
}

type inventory map[string]int64

func (i inventory) Has(hash string, size int64) (bool, error) {
	stored, ok := i[hash]
	return ok && stored == size, nil
}

func TestBuildPlanIsAdditiveFilteredDeterministic(t *testing.T) {
	a := candidateFor("z", "1", "amd64", []byte("present"), "https://example.com/z")
	b := candidateFor("a", "2", "amd64", []byte("download"), "https://example.com/a")
	c := candidateFor("debug", "1", "amd64", []byte("debug"), "https://example.com/debug")
	c.DebugInfo = true
	plan, err := BuildPlan([]Candidate{a, b, b, c}, Filter{DebugInfo: "drop"}, inventory{a.SHA256: a.Size})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Present != 1 || plan.Filtered != 1 || len(plan.Download) != 1 || plan.Download[0].Name != "a" {
		t.Fatalf("unexpected additive plan: %#v", plan)
	}
}

func TestBuildPlanStreamKeepsOnlySummaryAndRejectsUnorderedInput(t *testing.T) {
	presentCandidate := candidateFor("present", "1", "amd64", []byte("present"), "https://example.com/present")
	downloadCandidate := candidateFor("download", "1", "amd64", []byte("download"), "https://example.com/download")
	debugCandidate := candidateFor("debug", "1", "amd64", []byte("debug"), "https://example.com/debug")
	debugCandidate.DebugInfo = true
	candidates := []Candidate{presentCandidate, downloadCandidate, debugCandidate}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].SHA256 < candidates[j].SHA256 })
	stream := func(yield func(Candidate) error) error {
		for _, candidate := range candidates {
			if err := yield(candidate); err != nil {
				return err
			}
		}
		return nil
	}
	var present, download []string
	plan, err := BuildPlanStream(stream, Filter{DebugInfo: "drop"}, inventory{presentCandidate.SHA256: presentCandidate.Size},
		func(candidate Candidate) error {
			present = append(present, candidate.Name)
			return nil
		}, func(candidate Candidate) error {
			download = append(download, candidate.Name)
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Present != 1 || plan.DownloadCount != 1 || plan.Filtered != 1 || len(plan.Download) != 0 ||
		len(present) != 1 || present[0] != "present" || len(download) != 1 || download[0] != "download" {
		t.Fatalf("stream plan=%+v present=%v download=%v", plan, present, download)
	}

	unordered := func(yield func(Candidate) error) error {
		if err := yield(candidates[len(candidates)-1]); err != nil {
			return err
		}
		return yield(candidates[0])
	}
	if _, err := BuildPlanStream(unordered, Filter{}, inventory{}, nil, nil); err == nil || !strings.Contains(err.Error(), "not ordered") {
		t.Fatalf("unordered candidate stream accepted: %v", err)
	}
}

func TestDownloaderRetriesWithRealHTTPRange(t *testing.T) {
	body := bytes.Repeat([]byte("sow-range-data"), 8192)
	candidate := candidateFor("pkg", "1", "amd64", body, "")
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := requests.Add(1)
		if request == 1 {
			w.Header().Set("Content-Length", fmt.Sprint(len(body)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body[:len(body)/2])
			return
		}
		offset := len(body) / 2
		if got, want := r.Header.Get("Range"), fmt.Sprintf("bytes=%d-", offset); got != want {
			t.Errorf("Range=%q want=%q", got, want)
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", offset, len(body)-1, len(body)))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(body[offset:])
	}))
	defer server.Close()
	candidate.URL = server.URL + "/pkg"
	dir := t.TempDir()
	path, err := (Downloader{Client: server.Client(), Attempts: 3, BufferSize: 4096}).Download(context.Background(), candidate, dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("download mismatch err=%v bytes=%d", err, len(got))
	}
	if requests.Load() != 2 {
		t.Fatalf("requests=%d want=2", requests.Load())
	}
	second, err := (Downloader{Client: server.Client()}).Download(context.Background(), candidate, dir)
	if err != nil || second != path || requests.Load() != 2 {
		t.Fatalf("completed download not idempotent: path=%s err=%v requests=%d", second, err, requests.Load())
	}
}

func TestDownloaderRestartsWhenServerIgnoresRangeAndRejectsBadHash(t *testing.T) {
	body := []byte("complete-body")
	candidate := candidateFor("pkg", "1", "amd64", body, "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer server.Close()
	candidate.URL = server.URL + "/pkg"
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, candidate.SHA256+".part"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	path, err := (Downloader{Client: server.Client(), Attempts: 2}).Download(context.Background(), candidate, dir)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, body) {
		t.Fatalf("server Range fallback appended instead of truncating: %q", got)
	}

	bad := candidate
	bad.SHA256 = strings.Repeat("f", 64)
	if _, err := (Downloader{Client: server.Client(), Attempts: 2}).Download(context.Background(), bad, t.TempDir()); err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("bad checksum accepted: %v", err)
	}
}

func candidateFor(name, version, arch string, body []byte, rawURL string) Candidate {
	hash := sha256.Sum256(body)
	if rawURL == "" {
		rawURL = "http://example.invalid/pkg"
	}
	return Candidate{Format: "rpm", Name: name, Version: version, Arch: arch, URL: rawURL, Size: int64(len(body)), SHA256: hex.EncodeToString(hash[:])}
}

func TestVerifyFileStreams(t *testing.T) {
	body := []byte("stream")
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(body)
	if err := verifyFile(path, int64(len(body)), hex.EncodeToString(hash[:]), 2); err != nil {
		t.Fatal(err)
	}
}
