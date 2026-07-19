package verify

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestHTTPCheckFetchesRealBytesWithoutLeakingTokenURL(t *testing.T) {
	body := []byte("immutable repository object")
	digest := sha256.Sum256(body)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/pro/v1/super-secret-token/object" {
			http.NotFound(w, request)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		_, _ = w.Write(body)
	}))
	defer server.Close()
	object := HTTPObject{Label: "published-object", URL: server.URL + "/pro/v1/super-secret-token/object", Size: int64(len(body)), SHA256: fmt.Sprintf("%x", digest), AllowHTTP: true, ExpectedResponseHeaders: map[string]string{"cache-control": "public, max-age=31536000, immutable"}}
	clean := Run(context.Background(), Request{Layers: []Layer{LayerL3}, Checks: []Check{HTTPCheck{CheckID: "cdn", Client: server.Client(), Objects: []HTTPObject{object}}}})
	if clean.Outcome != OutcomePassed {
		t.Fatalf("valid HTTP evidence rejected: %+v", clean)
	}
	object.SHA256 = strings.Repeat("0", 64)
	drift := Run(context.Background(), Request{Layers: []Layer{LayerL3}, Checks: []Check{HTTPCheck{CheckID: "cdn", Client: server.Client(), Objects: []HTTPObject{object}}}})
	if !hasCode(drift, "CDN_BYTES_DRIFT") {
		t.Fatalf("CDN byte drift not detected: %+v", drift)
	}
	for _, finding := range drift.Findings {
		if strings.Contains(finding.Subject, "super-secret") || strings.Contains(finding.Message, "super-secret") {
			t.Fatalf("token URL leaked in report: %+v", finding)
		}
	}
}

func TestHTTPCheckSeparatesRedirectDriftFromNetworkAndAuthFailure(t *testing.T) {
	body := []byte("object")
	digest := sha256.Sum256(body)
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	defer foreign.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		http.Redirect(w, request, foreign.URL+"/object", http.StatusFound)
	}))
	defer redirect.Close()
	object := HTTPObject{Label: "redirected-object", URL: redirect.URL + "/object", Size: int64(len(body)), SHA256: fmt.Sprintf("%x", digest), AllowHTTP: true}
	var marked atomic.Bool
	report := Run(context.Background(), Request{Layers: []Layer{LayerL3}, Checks: []Check{HTTPCheck{
		CheckID: "redirect", Client: redirect.Client(), Objects: []HTTPObject{object}, MarkNetworkFailure: func() { marked.Store(true) },
	}}})
	if report.Exit != ExitVerification || !hasCode(report, "CDN_REDIRECT_POLICY") || marked.Load() {
		t.Fatalf("redirect classification report=%+v network=%v", report, marked.Load())
	}

	unauthorized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	defer unauthorized.Close()
	object.URL = unauthorized.URL + "/object"
	marked.Store(false)
	report = Run(context.Background(), Request{Layers: []Layer{LayerL3}, Checks: []Check{HTTPCheck{
		CheckID: "auth", Client: unauthorized.Client(), Objects: []HTTPObject{object}, MarkNetworkFailure: func() { marked.Store(true) },
	}}})
	if report.Exit != ExitOperational || !hasCode(report, "CDN_NETWORK_STATUS") || !marked.Load() {
		t.Fatalf("auth classification report=%+v network=%v", report, marked.Load())
	}
}

func TestHTTPCheckRefusesSameOriginRedirectWithoutReplayingCredential(t *testing.T) {
	body := []byte("object")
	digest := sha256.Sum256(body)
	for _, fixture := range []struct {
		name    string
		path    string
		headers http.Header
	}{
		{name: "basic", path: "/pro/v1/basic/object", headers: protocolBasicHeaders()},
		{name: "token", path: "/pro/v1/abcdefghijklmnopqrstuvwxyz0123456789/object"},
	} {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			var replayed atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path == fixture.path {
					http.Redirect(writer, request, "/public/object", http.StatusFound)
					return
				}
				replayed.Store(true)
				_, _ = writer.Write(body)
			}))
			defer server.Close()
			object := HTTPObject{
				Label: fixture.name, URL: server.URL + fixture.path, Headers: fixture.headers,
				Size: int64(len(body)), SHA256: fmt.Sprintf("%x", digest), AllowHTTP: true,
			}
			report := Run(context.Background(), Request{Layers: []Layer{LayerL3}, Checks: []Check{HTTPCheck{CheckID: fixture.name, Client: server.Client(), Objects: []HTTPObject{object}}}})
			if report.Exit != ExitVerification || !hasCode(report, "CDN_REDIRECT_POLICY") {
				t.Fatalf("same-origin redirect report = %+v", report)
			}
			if replayed.Load() {
				t.Fatal("redirect Location received a replayed credential-bearing request")
			}
		})
	}
}

func TestHTTPCheckRejectsCredentialedOrNonCanonicalExpectationURL(t *testing.T) {
	for _, raw := range []string{"https://user:secret@example.invalid/object", "https://example.invalid/a/../object", "https://example.invalid/object?token=secret"} {
		object := HTTPObject{Label: "unsafe", URL: raw, Size: 0, SHA256: strings.Repeat("0", 64)}
		report := Run(context.Background(), Request{Layers: []Layer{LayerL3}, Checks: []Check{HTTPCheck{CheckID: "unsafe", Objects: []HTTPObject{object}}}})
		if !hasCode(report, "CDN_EXPECTATION_INVALID") {
			t.Fatalf("unsafe URL %q accepted: %+v", raw, report)
		}
	}
}

func TestHTTPAbsenceCheckAcceptsOnly404Or410(t *testing.T) {
	status := atomic.Int64{}
	status.Store(http.StatusNotFound)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write([]byte("stale"))
	}))
	defer server.Close()
	object := HTTPAbsentObject{Label: "expired-snapshot-route", URL: server.URL + "/route", AllowHTTP: true}
	run := func() Report {
		return Run(context.Background(), Request{Layers: []Layer{LayerL3}, Checks: []Check{HTTPAbsenceCheck{CheckID: "cdn/absent", Client: server.Client(), Objects: []HTTPAbsentObject{object}}}})
	}
	if report := run(); report.Outcome != OutcomePassed {
		t.Fatalf("404 absence rejected: %+v", report)
	}
	status.Store(http.StatusGone)
	if report := run(); report.Outcome != OutcomePassed {
		t.Fatalf("410 absence rejected: %+v", report)
	}
	status.Store(http.StatusOK)
	if report := run(); report.Exit != ExitVerification || !hasCode(report, "CDN_ABSENCE_DRIFT") {
		t.Fatalf("stale CDN 200 accepted: %+v", report)
	}

	for _, absolute := range []bool{false, true} {
		redirectBase := ""
		redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/route" {
				location := "/missing"
				if absolute {
					location = redirectBase + location
				}
				http.Redirect(w, request, location, http.StatusFound)
				return
			}
			http.NotFound(w, request)
		}))
		redirectBase = redirect.URL
		object.URL = redirect.URL + "/route"
		if report := run(); report.Exit != ExitVerification || !hasCode(report, "CDN_ABSENCE_DRIFT") {
			redirect.Close()
			t.Fatalf("same-origin redirect absolute=%t to 404 was accepted as absence: %+v", absolute, report)
		}
		redirect.Close()
	}
}

func TestClientCheckRejectsBooleanOnlyEvidence(t *testing.T) {
	report := Run(context.Background(), Request{Layers: []Layer{LayerL4}, Checks: []Check{ClientCheck{CheckID: "apt", Probe: staticClientProbe{}}}})
	if report.Outcome != OutcomeIncomplete || !hasCode(report, "CLIENT_EVIDENCE_INCOMPLETE") {
		t.Fatalf("empty client evidence accepted: %+v", report)
	}
}

func TestClientCheckAcceptsTranscriptBackedAdapterEvidence(t *testing.T) {
	report := Run(context.Background(), Request{Layers: []Layer{LayerL4}, Checks: []Check{ClientCheck{CheckID: "dnf", Probe: staticClientProbe{evidence: ClientEvidence{
		Client: "dnf", Protocol: "rpm-md-v1", Version: "5.2.0", TranscriptSHA256: strings.Repeat("a", 64),
		TranscriptSummary: "repomd->primary->RPM", MetadataObjects: 4, InstalledObjects: 1,
		PackageName: "postgresql", PackageVersion: "18.1-1", PackageSHA256: strings.Repeat("b", 64),
	}}}}})
	if report.Outcome != OutcomePassed || !hasCode(report, "CLIENT_EVIDENCE_ACCEPTED") {
		t.Fatalf("complete client adapter evidence rejected: %+v", report)
	}
}

type staticClientProbe struct {
	evidence ClientEvidence
}

func (p staticClientProbe) Run(context.Context) (ClientEvidence, error) {
	return p.evidence, nil
}
