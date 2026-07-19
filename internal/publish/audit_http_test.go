package publish

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	cloudflareapi "github.com/cloudflare/cloudflare-go/v7"
	teo "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/teo/v20220901"
)

func TestHTTPProvidersRejectRedirectsAndCrossOriginCDNURLs(t *testing.T) {
	t.Parallel()
	var followed atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		followed.Add(1)
		_, _ = io.WriteString(writer, "wrong-origin")
	}))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL+"/object", http.StatusFound)
	}))
	defer origin.Close()
	base, _, err := parseCDNBaseURL(origin.URL+"/", true)
	if err != nil {
		t.Fatal(err)
	}
	body, err := openCDN(context.Background(), origin.Client(), base, origin.URL+"/object", nil)
	if body != nil {
		_ = body.Close()
	}
	var status *httpStatusError
	if !errors.As(err, &status) || status.Status != http.StatusFound {
		t.Fatalf("redirect was not rejected as an invalid verification response: %v", err)
	}
	if followed.Load() != 0 {
		t.Fatal("CDN verification followed a redirect to another origin")
	}
	if _, err := validateCDNTarget(base, destination.URL+"/object"); err == nil {
		t.Fatal("cross-origin CDN URL was accepted")
	}
}

func TestBasicVerificationCredentialsAreScopedToBasicRoute(t *testing.T) {
	t.Parallel()
	var basicCalls, publicCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Cookie") != "" {
			t.Error("ambient client cookie leaked onto a CDN verification request")
		}
		if isBasicVerificationPath(request.URL.Path) {
			basicCalls.Add(1)
			username, password, ok := request.BasicAuth()
			if !ok || username != "verifier" || password != "top-secret" {
				t.Error("Basic verification request did not carry the configured credential")
			}
		} else {
			publicCalls.Add(1)
			if request.Header.Get("Authorization") != "" {
				t.Error("Basic verification credential leaked onto a public request")
			}
		}
		_, _ = io.WriteString(writer, "ok")
	}))
	defer server.Close()
	base, _, err := parseCDNBaseURL(server.URL+"/", true)
	if err != nil {
		t.Fatal(err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(base, []*http.Cookie{{Name: "ambient-session", Value: "must-not-be-sent"}})
	client := server.Client()
	client.Jar = jar
	credentials := &BasicAuthCredentials{Username: "verifier", Password: "top-secret"}
	for _, rawURL := range []string{server.URL + "/pro/v1/basic/repo/file", server.URL + "/public/file"} {
		body, err := openCDN(context.Background(), client, base, rawURL, credentials)
		if err != nil {
			t.Fatal(err)
		}
		_ = body.Close()
	}
	if basicCalls.Load() != 1 || publicCalls.Load() != 1 {
		t.Fatalf("unexpected verification calls basic=%d public=%d", basicCalls.Load(), publicCalls.Load())
	}
	if _, err := openCDN(context.Background(), client, base, server.URL+"/pro/v1/basic/repo/file", nil); err == nil {
		t.Fatal("Basic verification route was called without credentials")
	}
	if basicCalls.Load() != 1 {
		t.Fatal("credential-less Basic request reached the network")
	}
}

func TestHTTPErrorRedactsBearerPathAndResponseBody(t *testing.T) {
	t.Parallel()
	const token = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	requestURL, err := url.Parse("https://cdn.test/pro/v1/" + token + "/repo/file")
	if err != nil {
		t.Fatal(err)
	}
	request := &http.Request{Method: http.MethodGet, URL: requestURL}
	response := &http.Response{
		StatusCode: http.StatusForbidden,
		Request:    request,
		Body:       io.NopCloser(strings.NewReader("echo-secret=" + token)),
	}
	message := httpResponseError(response).Error()
	if strings.Contains(message, token) || strings.Contains(message, "echo-secret") || !strings.Contains(message, "REDACTED") {
		t.Fatalf("HTTP error leaked a bearer secret: %s", message)
	}
}

func TestPlanBindsVerificationAndPurgeToCanonicalCDNBase(t *testing.T) {
	t.Parallel()
	plan := Plan{Schema: planSchema, Objects: []PlannedObject{{
		SourcePath: "pointer", RemoteKey: "pointer", Size: 1,
		SHA256: hashString("p"), Class: ObjectPointer,
	}}}
	plan, err := plan.WithCDN("https://cdn.test/base/")
	if err != nil {
		t.Fatal(err)
	}
	plan.Verify[0].URL = "https://attacker.test/base/pointer"
	if _, err := plan.Canonical(); err == nil {
		t.Fatal("verification URL outside the canonical CDN base was accepted")
	}
	if _, err := (Plan{Schema: planSchema}).WithCDN("https://cdn.test/pro/v1/abcdefghijklmnopqrstuvwxyz0123456789/repo/"); err == nil {
		t.Fatal("bearer credential was accepted in a persisted CDN base URL")
	}
	if _, err := (Plan{Schema: planSchema}).WithCDN("https://cdn.test//"); err == nil {
		t.Fatal("double-slash CDN base path was accepted")
	}
}

func TestCOSVersioningProbeIsNotCachedAcrossPublications(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || !request.URL.Query().Has("versioning") {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		if calls.Add(1) == 1 {
			_, _ = io.WriteString(writer, `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>`)
			return
		}
		_, _ = io.WriteString(writer, `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>`)
	}))
	defer server.Close()
	provider, err := NewCOSEdgeOneHTTP(COSEdgeOneHTTPConfig{
		ObjectBaseURL: server.URL + "/bucket", CDNBaseURL: "https://cdn.test/",
		ObjectCredentials:  S3Credentials{AccessKeyID: "id", SecretAccessKey: "secret", Region: "ap-shanghai"},
		TencentCredentials: TencentCredentials{SecretID: "tc-id", SecretKey: "tc-secret"},
		ZoneID:             "zone", EdgeOneAPIURL: server.URL, Client: server.Client(), AllowInsecure: true,
		UnversionedBucketConfirmed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.COSProbeUnversioned(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := provider.COSProbeUnversioned(context.Background()); !errors.Is(err, ErrCapability) {
		t.Fatalf("changed COS versioning state was hidden by a cached probe: %v", err)
	}
}

func TestCloudflarePurgeBatchesAtUniversalLimit(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || !strings.HasSuffix(request.URL.Path, "/purge_cache") {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		calls.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"success":true,"errors":[],"result":{"id":"x"}}`)
	}))
	defer server.Close()
	provider, err := NewR2CloudflareHTTP(R2CloudflareHTTPConfig{
		ObjectBaseURL: server.URL + "/bucket", CDNBaseURL: "https://cdn.test/",
		Credentials: S3Credentials{AccessKeyID: "id", SecretAccessKey: "secret", Region: "auto"},
		ZoneID:      "zone", APIToken: "token", CloudflareAPIURL: server.URL,
		Client: server.Client(), AllowInsecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	urls := make([]string, 205)
	for index := range urls {
		urls[index] = "https://cdn.test/pointer-" + string(rune('a'+index%26)) + "-" + strings.Repeat("x", index/26)
	}
	if err := provider.CloudflarePurge(context.Background(), urls); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatalf("purge calls=%d, want 3 bounded batches", calls.Load())
	}
}

func TestCloudflarePurgeRejectsHTTP200BusinessFailure(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		body string
	}{
		{
			name: "success-false-with-result",
			body: `{"success":false,"errors":[{"code":1000,"message":"purge rejected"}],"messages":[],"result":{"id":"zone"}}`,
		},
		{
			name: "success-true-with-errors",
			body: `{"success":true,"errors":[{"code":1000,"message":"partial rejection"}],"messages":[],"result":{"id":"zone"}}`,
		},
		{
			name: "success-true-null-result",
			body: `{"success":true,"errors":[],"messages":[],"result":null}`,
		},
		{
			name: "success-true-empty-id",
			body: `{"success":true,"errors":[],"messages":[],"result":{"id":""}}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodPost || !strings.HasSuffix(request.URL.Path, "/purge_cache") {
					writer.WriteHeader(http.StatusNotFound)
					return
				}
				writer.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(writer, test.body)
			}))
			defer server.Close()
			provider, err := NewR2CloudflareHTTP(R2CloudflareHTTPConfig{
				ObjectBaseURL: server.URL + "/bucket", CDNBaseURL: "https://cdn.test/",
				Credentials: S3Credentials{AccessKeyID: "id", SecretAccessKey: "secret", Region: "auto"},
				ZoneID:      "zone", APIToken: "token", CloudflareAPIURL: server.URL,
				Client: server.Client(), AllowInsecure: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := provider.CloudflarePurge(context.Background(), []string{"https://cdn.test/pointer"}); err == nil {
				t.Fatal("Cloudflare HTTP 200 business failure was accepted")
			}
		})
	}
}

func TestCOSRuntimeVersioningProbeRejectsEnabledAndSuspended(t *testing.T) {
	t.Parallel()
	for _, status := range []string{"Enabled", "Suspended"} {
		status := status
		t.Run(status, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Method == http.MethodGet && request.URL.Query().Has("versioning") {
					_, _ = io.WriteString(writer, `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>`+status+`</Status></VersioningConfiguration>`)
					return
				}
				writer.WriteHeader(http.StatusNotFound)
			}))
			defer server.Close()
			provider, err := NewCOSEdgeOneHTTP(COSEdgeOneHTTPConfig{
				ObjectBaseURL: server.URL + "/bucket", CDNBaseURL: "https://cdn.test/",
				ObjectCredentials:  S3Credentials{AccessKeyID: "id", SecretAccessKey: "secret", Region: "ap-shanghai"},
				TencentCredentials: TencentCredentials{SecretID: "tc-id", SecretKey: "tc-secret"},
				ZoneID:             "zone", EdgeOneAPIURL: server.URL, Client: server.Client(), AllowInsecure: true,
				UnversionedBucketConfirmed: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := provider.COSProbeUnversioned(context.Background()); !errors.Is(err, ErrCapability) {
				t.Fatalf("versioning state %s was not rejected: %v", status, err)
			}
		})
	}
}

func TestProviderConstructorsBindFrozenOfficialSDKs(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	r2, err := NewR2CloudflareHTTP(R2CloudflareHTTPConfig{
		Bucket: "bucket", ObjectBaseURL: server.URL + "/bucket", CDNBaseURL: "https://cdn.test/",
		Credentials: S3Credentials{AccessKeyID: "r2-id", SecretAccessKey: "r2-secret", Region: "auto"},
		ZoneID:      "cf-zone", APIToken: "cf-token", CloudflareAPIURL: server.URL,
		Client: server.Client(), AllowInsecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	cos, err := NewCOSEdgeOneHTTP(COSEdgeOneHTTPConfig{
		Bucket: "bucket", ObjectBaseURL: server.URL + "/bucket", CDNBaseURL: "https://cdn.test/",
		ObjectCredentials:  S3Credentials{AccessKeyID: "cos-id", SecretAccessKey: "cos-secret", Region: "ap-shanghai"},
		TencentCredentials: TencentCredentials{SecretID: "tc-id", SecretKey: "tc-secret"},
		ZoneID:             "eo-zone", EdgeOneAPIURL: server.URL, Client: server.Client(), AllowInsecure: true,
		UnversionedBucketConfirmed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertS3 := func(*s3.Client) {}
	assertCloudflare := func(*cloudflareapi.Client) {}
	assertTEO := func(*teo.Client) {}
	assertS3(r2.objects.sdk)
	assertS3(cos.objects.sdk)
	assertCloudflare(r2.cloudflare)
	assertTEO(cos.edgeOne)
	if r2.objects.sdk == nil || cos.objects.sdk == nil || r2.cloudflare == nil || cos.edgeOne == nil {
		t.Fatal("provider constructor omitted a frozen official SDK client")
	}
	if r2.objects.dialect != s3VendorR2 || cos.objects.dialect != s3VendorCOS {
		t.Fatal("shared S3 SDK wrapper lost its closed R2/COS dialect binding")
	}
}
