package managed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/v2/state"
)

func TestHTTPPublicationVerifierOrdinaryGETRemainsAuthoritative(t *testing.T) {
	oldBody, newBody := []byte("old"), []byte("new")
	digest := sha256.Sum256(newBody)
	expected := state.GenerationFile{Path: "pool/p/package.rpm", Phase: "payload", Size: int64(len(newBody)), SHA256: hex.EncodeToString(digest[:])}
	regular, revalidated, refreshed := 0, 0, false
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.RawQuery != "" {
			t.Errorf("canonical cache key acquired a query: %s", request.URL.String())
		}
		if request.Header.Get("Cache-Control") == "no-cache" {
			revalidated++
			refreshed = true
			_, _ = response.Write(newBody)
			return
		}
		regular++
		if refreshed {
			_, _ = response.Write(newBody)
		} else {
			_, _ = response.Write(oldBody)
		}
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL + "/repo/")
	verifier := httpPublicationVerifier{
		client: server.Client(), base: base, maxCacheTTL: time.Second,
		sleep: func(context.Context, time.Duration) error { return nil },
	}
	if err := verifier.Verify(context.Background(), expected); err != nil {
		t.Fatal(err)
	}
	if regular != 2 || revalidated != 1 {
		t.Fatalf("ordinary=%d revalidated=%d", regular, revalidated)
	}
}

func TestHTTPPublicationVerifierBoundsTransientOversizeAndSlowBodies(t *testing.T) {
	t.Run("transient window", func(t *testing.T) {
		calls := 0
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			calls++
			response.WriteHeader(http.StatusTooManyRequests)
		}))
		defer server.Close()
		base, _ := url.Parse(server.URL + "/")
		current := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
		started := current
		verifier := httpPublicationVerifier{
			client: server.Client(), base: base, maxCacheTTL: 24 * time.Hour, transientRetryWindow: 500 * time.Millisecond,
			now:   func() time.Time { return current },
			sleep: func(_ context.Context, duration time.Duration) error { current = current.Add(duration); return nil },
		}
		expected := state.GenerationFile{Path: "pool/p/package.rpm", Phase: "payload", Size: 1, SHA256: strings.Repeat("a", 64)}
		if err := verifier.Verify(context.Background(), expected); err == nil || calls < 2 || current.Sub(started) != 500*time.Millisecond {
			t.Fatalf("calls=%d elapsed=%s err=%v", calls, current.Sub(started), err)
		}
	})

	t.Run("size plus one guard", func(t *testing.T) {
		body := []byte("oversize")
		digest := sha256.Sum256(body[:len(body)-1])
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { _, _ = response.Write(body) }))
		defer server.Close()
		base, _ := url.Parse(server.URL + "/")
		verifier := httpPublicationVerifier{client: server.Client(), base: base}
		expected := state.GenerationFile{Path: "pool/p/package.rpm", Phase: "payload", Size: int64(len(body) - 1), SHA256: hex.EncodeToString(digest[:])}
		if err := verifier.Verify(context.Background(), expected); err == nil {
			t.Fatal("oversized response passed")
		}
	})

	t.Run("slow progressive body has no total request timeout", func(t *testing.T) {
		body := []byte("slow-progress")
		digest := sha256.Sum256(body)
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			flusher := response.(http.Flusher)
			for _, value := range body {
				_, _ = response.Write([]byte{value})
				flusher.Flush()
				time.Sleep(5 * time.Millisecond)
			}
		}))
		defer server.Close()
		base, _ := url.Parse(server.URL + "/")
		verifier := httpPublicationVerifier{client: newPublicVerificationClient(), base: base, readIdleTimeout: 20 * time.Millisecond}
		expected := state.GenerationFile{Path: "pool/p/package.rpm", Phase: "payload", Size: int64(len(body)), SHA256: hex.EncodeToString(digest[:])}
		if err := verifier.Verify(context.Background(), expected); err != nil {
			t.Fatal(err)
		}
		if verifier.client.Timeout != 0 {
			t.Fatalf("public client has total timeout %s", verifier.client.Timeout)
		}
	})
}

func TestHTTPPublicationVerifierAbsenceRetriesStale200UntilCanonical404(t *testing.T) {
	regular, revalidated, refreshed := 0, 0, false
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Cache-Control") == "no-cache" {
			revalidated++
			refreshed = true
			response.WriteHeader(http.StatusNotFound)
			return
		}
		regular++
		if refreshed {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = response.Write([]byte("stale"))
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL + "/repo/")
	verifier := httpPublicationVerifier{
		client: server.Client(), base: base, maxCacheTTL: time.Second,
		sleep: func(context.Context, time.Duration) error { return nil },
	}
	if err := verifier.VerifyAbsent(context.Background(), "pool/p/package.rpm"); err != nil {
		t.Fatal(err)
	}
	if regular != 2 || revalidated != 1 {
		t.Fatalf("absence ordinary=%d revalidated=%d", regular, revalidated)
	}
}

func TestHTTPPublicationVerifierAbsenceHonorsTTLAnd410(t *testing.T) {
	t.Run("TTL exhaustion", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { _, _ = response.Write([]byte("stale")) }))
		defer server.Close()
		base, _ := url.Parse(server.URL + "/")
		current := time.Now()
		verifier := httpPublicationVerifier{
			client: server.Client(), base: base, maxCacheTTL: 250 * time.Millisecond,
			now:   func() time.Time { return current },
			sleep: func(_ context.Context, duration time.Duration) error { current = current.Add(duration); return nil },
		}
		if err := verifier.VerifyAbsent(context.Background(), "pool/p/package.rpm"); err == nil {
			t.Fatal("stale 200 outlived TTL")
		}
	})

	t.Run("410 is absent", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusGone) }))
		defer server.Close()
		base, _ := url.Parse(server.URL + "/")
		verifier := httpPublicationVerifier{client: server.Client(), base: base}
		if err := verifier.VerifyAbsent(context.Background(), "pool/p/package.rpm"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestR2PublicAbsenceRemainsDisabled(t *testing.T) {
	backend := &r2PublicationBackend{}
	if err := backend.VerifyPublicAbsent(context.Background(), "pool/p/package.rpm"); !errors.Is(err, ErrRejected) {
		t.Fatalf("R2 absence error=%v", err)
	}
}
