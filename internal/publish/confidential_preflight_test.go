package publish

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type preflightRoundTripper func(*http.Request) (*http.Response, error)

func (f preflightRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type preflightReadCloser struct {
	io.Reader
	closeErr error
}

func (r *preflightReadCloser) Close() error { return r.closeErr }

func TestVendorPreflightAttestsConfidentialEdgeBeforePublication(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Method != http.MethodGet || request.URL.Path != "/"+confidentialEdgeCanaryKey || request.URL.RawQuery != "" {
			t.Errorf("unexpected canary request method=%s path=%q query=%q", request.Method, request.URL.Path, request.URL.RawQuery)
		}
		if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
			t.Error("confidentiality canary carried client credentials")
		}
		if request.Header.Get("Accept-Encoding") != "identity" ||
			request.Header.Get("Cache-Control") != "no-store, no-cache, max-age=0" ||
			request.Header.Get("Pragma") != "no-cache" {
			t.Errorf("unexpected canary request headers: %#v", request.Header)
		}
		writeValidConfidentialDenial(response)
	}))
	defer server.Close()

	base, _, err := parseCDNBaseURL(server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(base, []*http.Cookie{{Name: "preexisting-session", Value: "must-not-be-sent"}})
	client := server.Client()
	client.Jar = jar
	credentials := &BasicAuthCredentials{Username: "probe", Password: "not-sent"}
	plan := Plan{
		Objects: []PlannedObject{{RemoteKey: ".sow/gated/pkg/private.pkg", CDNPath: "pro/v1/basic/pkg/private.pkg"}},
		Verify:  []VerifyObject{{URL: server.URL + "/pro/v1/basic/pkg/private.pkg"}},
	}
	providers := []struct {
		name      string
		preflight func(context.Context, Plan) error
	}{
		{name: "cloudflare", preflight: (&R2CloudflareHTTP{client: client, cdnBase: base, basic: credentials}).CloudflarePreflight},
		{name: "edgeone", preflight: (&COSEdgeOneHTTP{client: client, cdnBase: base, basic: credentials}).EdgeOnePreflight},
	}
	for _, provider := range providers {
		t.Run(provider.name, func(t *testing.T) {
			if err := provider.preflight(context.Background(), plan); err != nil {
				t.Fatalf("confidential provider preflight failed: %v", err)
			}
		})
	}
	if got := requests.Load(); got != int32(len(providers)) {
		t.Fatalf("confidential preflight requests=%d want=%d", got, len(providers))
	}
}

func TestVendorPreflightDoesNotProbePublicOnlyPlan(t *testing.T) {
	base, _, err := parseCDNBaseURL("https://cdn.example/", false)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	client := &http.Client{Transport: preflightRoundTripper(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("public-only preflight unexpectedly used the network")
	})}
	plan := Plan{Verify: []VerifyObject{{URL: "https://cdn.example/public/file"}}}
	providers := []func(context.Context, Plan) error{
		(&R2CloudflareHTTP{client: client, cdnBase: base}).CloudflarePreflight,
		(&COSEdgeOneHTTP{client: client, cdnBase: base}).EdgeOnePreflight,
	}
	for _, preflight := range providers {
		if err := preflight(context.Background(), plan); err != nil {
			t.Fatal(err)
		}
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("public-only preflight made %d network requests", got)
	}
}

func TestConfidentialEdgePlanDetectionClosesEveryPersistedRouteSurface(t *testing.T) {
	basicURL := "https://cdn.example/pro/v1/basic/private"
	tests := []struct {
		name string
		plan Plan
		want bool
	}{
		{name: "public-only", plan: Plan{
			Objects: []PlannedObject{{RemoteKey: "public/file", CDNPath: "public/file"}},
			Verify:  []VerifyObject{{URL: "https://cdn.example/public/file"}},
		}},
		{name: "gated-object-key", want: true, plan: Plan{Objects: []PlannedObject{{RemoteKey: ".sow/gated/private"}}}},
		{name: "basic-object-route", want: true, plan: Plan{Objects: []PlannedObject{{RemoteKey: ".sow/snapshots/id.json", CDNPath: "pro/v1/basic/private"}}}},
		{name: "gated-delete-key", want: true, plan: Plan{Deletes: []PlannedDelete{{RemoteKey: ".sow/gated/private"}}}},
		{name: "basic-delete-route", want: true, plan: Plan{Deletes: []PlannedDelete{{RemoteKey: ".sow/snapshots/id.json", CDNPath: "pro/v1/basic/private"}}}},
		{name: "basic-purge", want: true, plan: Plan{PurgeURLs: []string{basicURL}}},
		{name: "basic-verify", want: true, plan: Plan{Verify: []VerifyObject{{URL: basicURL}}}},
		{name: "basic-probe", want: true, plan: Plan{Probes: []VerifyObject{{URL: basicURL}}}},
		{name: "basic-absence", want: true, plan: Plan{VerifyAbsent: []VerifyAbsentObject{{URL: basicURL}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := planRequiresConfidentialEdge(test.plan); got != test.want {
				t.Fatalf("planRequiresConfidentialEdge=%t want=%t", got, test.want)
			}
		})
	}
}

func TestConfidentialEdgeDenialAttestationFailsClosed(t *testing.T) {
	base, _, err := parseCDNBaseURL("https://cdn.example/", false)
	if err != nil {
		t.Fatal(err)
	}
	closeFailure := errors.New("injected response close failure")
	tests := []struct {
		name   string
		mutate func(*http.Response)
	}{
		{name: "raw-direct-404-without-runtime-marker", mutate: func(response *http.Response) {
			response.Header.Del("X-SOW-Edge-Contract")
		}},
		{name: "anonymous-object-body", mutate: func(response *http.Response) {
			response.StatusCode = http.StatusOK
			setPreflightResponseBody(response, "private bytes")
		}},
		{name: "redirect", mutate: func(response *http.Response) {
			response.StatusCode = http.StatusFound
			response.Header.Set("Location", "https://origin.example/private")
		}},
		{name: "obsolete-runtime", mutate: func(response *http.Response) {
			response.Header.Set("X-SOW-Edge-Contract", "sow-edge-runtime/v1")
		}},
		{name: "public-cache-policy", mutate: func(response *http.Response) {
			response.Header.Set("Cache-Control", "public, max-age=300")
		}},
		{name: "origin-transport-marker", mutate: func(response *http.Response) {
			response.Header.Set("X-SOW-Origin-Transport", "r2-service")
		}},
		{name: "origin-cache-marker", mutate: func(response *http.Response) {
			response.Header.Set("X-SOW-Origin-Cache-Status", "HIT")
		}},
		{name: "oversized-body", mutate: func(response *http.Response) {
			setPreflightResponseBody(response, strings.Repeat("x", maxConfidentialEdgeCanaryBody+1))
		}},
		{name: "response-close-failure", mutate: func(response *http.Response) {
			response.Body = &preflightReadCloser{Reader: strings.NewReader(confidentialEdgeCanaryBody), closeErr: closeFailure}
		}},
		{name: "content-encoding", mutate: func(response *http.Response) {
			response.Header.Set("Content-Encoding", "gzip")
		}},
		{name: "authentication-challenge", mutate: func(response *http.Response) {
			response.Header.Set("WWW-Authenticate", `Basic realm="raw"`)
		}},
		{name: "duplicate-runtime-marker", mutate: func(response *http.Response) {
			response.Header.Add("X-SOW-Edge-Contract", "sow-edge-runtime/v2")
		}},
		{name: "unexpected-trailer", mutate: func(response *http.Response) {
			response.Trailer = http.Header{"X-SOW-Origin-Cache-Status": {"HIT"}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: preflightRoundTripper(func(request *http.Request) (*http.Response, error) {
				response := validConfidentialDenialResponse(request)
				test.mutate(response)
				return response, nil
			})}
			err := attestConfidentialEdgeDenial(context.Background(), client, base)
			if err == nil || !errors.Is(err, ErrCapability) {
				t.Fatalf("unsafe denial response was accepted: %v", err)
			}
			if test.name == "response-close-failure" && !errors.Is(err, closeFailure) {
				t.Fatalf("response close failure was not propagated: %v", err)
			}
		})
	}
}

func TestConfidentialEdgeDenialAttestationHonorsCancellation(t *testing.T) {
	base, _, err := parseCDNBaseURL("https://cdn.example/", false)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &http.Client{Transport: preflightRoundTripper(func(request *http.Request) (*http.Response, error) {
		return nil, request.Context().Err()
	})}
	err = attestConfidentialEdgeDenial(ctx, client, base)
	if !errors.Is(err, ErrCapability) || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled preflight error=%v", err)
	}
}

func TestAuthorizedCloudflareRawDomainsFailConfidentialPreflight(t *testing.T) {
	if os.Getenv("SOW_RUN_AUTHORIZED_CF_RAW_PREFLIGHT_NEGATIVE") != "1" {
		t.Skip("set SOW_RUN_AUTHORIZED_CF_RAW_PREFLIGHT_NEGATIVE=1 for the owner-authorized read-only pro.pigsty.io negative probe")
	}
	plan := Plan{Objects: []PlannedObject{{
		RemoteKey: ".sow/gated/pkg/private.pkg",
		CDNPath:   "pro/v1/basic/pkg/private.pkg",
	}}}
	for _, rawBase := range []string{"https://pro.pigsty.io/", "https://beta.pro.pigsty.io/"} {
		t.Run(rawBase, func(t *testing.T) {
			base, canonical, err := parseCDNBaseURL(rawBase, false)
			if err != nil || canonical != rawBase {
				t.Fatalf("invalid frozen test base canonical=%q err=%v", canonical, err)
			}
			provider := &R2CloudflareHTTP{
				client:  &http.Client{Timeout: 20 * time.Second},
				cdnBase: base,
				basic:   &BasicAuthCredentials{Username: "probe", Password: "not-sent"},
			}
			err = provider.CloudflarePreflight(context.Background(), plan)
			if err == nil || !errors.Is(err, ErrCapability) {
				t.Fatalf("raw public custom domain passed the confidential edge preflight: %v", err)
			}
		})
	}
}

func TestProviderPreflightFailurePrecedesEveryRemoteAndJournalMutation(t *testing.T) {
	for _, target := range []TargetName{TargetCloudflare, TargetTencent} {
		t.Run(string(target), func(t *testing.T) {
			root, plan := sourcePlan(t)
			remote := newFakeRemote()
			injected := errors.New("injected confidential edge denial failure")
			remote.preflightErr = injected
			journalDir := filepath.Join(t.TempDir(), "journal")
			var publisher *Publisher
			if target == TargetCloudflare {
				publisher = NewR2CloudflarePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{})
			} else {
				publisher = NewCOSEdgeOnePublisher(remote, DirectorySource{Root: root}, journalDir, Hooks{})
			}
			if _, err := publisher.Run(context.Background(), requestFixture(target, plan, "preflight-zero-mutation-"+string(target))); !errors.Is(err, injected) {
				t.Fatalf("publisher preflight error=%v", err)
			}
			remote.mutex.Lock()
			preflightCalls := remote.preflightCalls
			putAttempts := len(remote.putAttempts)
			controlReads := len(remote.controlReads)
			copyAttempts := len(remote.copyAttempts)
			deleteAttempts := len(remote.deleteAttempts)
			purgeCalls := len(remote.purgeCalls)
			remote.mutex.Unlock()
			if preflightCalls != 1 || putAttempts != 0 || controlReads != 0 || copyAttempts != 0 || deleteAttempts != 0 || purgeCalls != 0 {
				t.Fatalf("preflight crossed mutation boundary calls=%d put=%d get=%d copy=%d delete=%d purge=%d", preflightCalls, putAttempts, controlReads, copyAttempts, deleteAttempts, purgeCalls)
			}
			if _, err := os.Stat(journalDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("preflight failure created a publication journal: %v", err)
			}
		})
	}
}

func validConfidentialDenialResponse(request *http.Request) *http.Response {
	header := make(http.Header)
	header.Set("Content-Type", "text/plain; charset=utf-8")
	header.Set("Cache-Control", "private, no-store, max-age=0")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-SOW-Edge-Contract", "sow-edge-runtime/v2")
	return &http.Response{
		StatusCode:    http.StatusNotFound,
		Header:        header,
		Body:          io.NopCloser(strings.NewReader(confidentialEdgeCanaryBody)),
		ContentLength: int64(len(confidentialEdgeCanaryBody)),
		Request:       request,
	}
}

func setPreflightResponseBody(response *http.Response, body string) {
	response.Body = io.NopCloser(strings.NewReader(body))
	response.ContentLength = int64(len(body))
}

func writeValidConfidentialDenial(response http.ResponseWriter) {
	response.Header().Set("Content-Type", "text/plain; charset=utf-8")
	response.Header().Set("Cache-Control", "private, no-store, max-age=0")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("X-SOW-Edge-Contract", "sow-edge-runtime/v2")
	response.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(response, confidentialEdgeCanaryBody)
}
