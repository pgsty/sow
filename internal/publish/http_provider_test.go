package publish

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestR2CloudflareHTTPUsesConditionalObjectProtocolAndExactPurge(t *testing.T) {
	t.Parallel()
	var mutex sync.Mutex
	var requests []*http.Request
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mutex.Lock()
		requests = append(requests, request.Clone(request.Context()))
		mutex.Unlock()
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/bucket/.sow/manifest.json":
			writer.WriteHeader(http.StatusNotFound)
		case request.Method == http.MethodPut && request.URL.Path == "/bucket/immutable/object":
			assertNoOptionalS3ChecksumHeaders(t, request)
			if request.Header.Get("If-None-Match") != "*" {
				t.Errorf("R2 immutable put missing If-None-Match: %q", request.Header.Get("If-None-Match"))
			}
			if request.Header.Get("X-Amz-Meta-Sow-Sha256") != hashString("body") {
				t.Error("R2 immutable put missing explicit SHA metadata")
			}
			if !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
				t.Error("R2 request was not SigV4 signed")
			}
			authorization := request.Header.Get("Authorization")
			if !strings.Contains(authorization, "if-none-match") || !strings.Contains(authorization, "x-amz-meta-sow-sha256") {
				t.Error("R2 create-only condition and integrity metadata were not signature-bound")
			}
			_, _ = io.Copy(io.Discard, request.Body)
			writer.Header().Set("ETag", `"r2"`)
			writer.WriteHeader(http.StatusOK)
		case request.Method == http.MethodPost && request.URL.Path == "/zones/zone/purge_cache":
			if request.Header.Get("Authorization") != "Bearer cf-token" {
				t.Error("Cloudflare purge missing bearer token")
			}
			var body struct {
				Files []string `json:"files"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			want := []string{"https://cdn.example/dists/jammy/InRelease", "https://cdn.example/.sow/gated/dists/jammy/InRelease"}
			if len(body.Files) != len(want) || body.Files[0] != want[0] || body.Files[1] != want[1] {
				t.Errorf("Cloudflare purge expanded beyond exact URL: %v", body.Files)
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"success":true,"errors":[],"result":{"id":"x"}}`)
		default:
			t.Errorf("unexpected/list-like request: %s %s", request.Method, request.URL.String())
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	provider, err := NewR2CloudflareHTTP(R2CloudflareHTTPConfig{
		ObjectBaseURL: server.URL + "/bucket",
		CDNBaseURL:    "https://cdn.example/",
		Credentials:   S3Credentials{AccessKeyID: "access", SecretAccessKey: "secret", Region: "auto"},
		ZoneID:        "zone", APIToken: "cf-token", CloudflareAPIURL: server.URL,
		Client: server.Client(), AllowInsecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := provider.R2GetControl(context.Background(), CheckpointKey)
	if err != nil || checkpoint.Exists {
		t.Fatalf("missing checkpoint result=%#v err=%v", checkpoint, err)
	}
	data := []byte("body")
	if _, err := provider.R2Put(context.Background(), "immutable/object", bytes.NewReader(data), int64(len(data)), hashString("body"), R2PutCondition{IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	if err := provider.CloudflarePurge(context.Background(), []string{"https://cdn.example/dists/jammy/InRelease", "https://cdn.example/.sow/gated/dists/jammy/InRelease"}); err != nil {
		t.Fatal(err)
	}
	mutex.Lock()
	defer mutex.Unlock()
	purgeRequests := 0
	for _, request := range requests {
		if request.Method == http.MethodPost && request.URL.Path == "/zones/zone/purge_cache" {
			purgeRequests++
		}
		if request.URL.Query().Get("list-type") != "" || request.Method == http.MethodGet && request.URL.Path == "/bucket/" {
			t.Fatalf("default path issued ListObjects: %s", request.URL.String())
		}
	}
	if purgeRequests != 1 {
		t.Fatalf("Cloudflare exact purge requests=%d, want 1", purgeRequests)
	}
}

func TestR2CloudflareControlHTTPNeedsNoCDNAuthority(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Method != http.MethodGet || request.URL.Path != "/bucket/.sow/bootstrap/leases/plan.json" {
			t.Errorf("R2-only control client reached a non-object endpoint: %s %s", request.Method, request.URL.String())
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Error("R2-only control request was not SigV4 signed")
		}
		writer.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	provider, err := NewR2CloudflareControlHTTP(R2CloudflareControlHTTPConfig{
		ObjectBaseURL: server.URL + "/bucket",
		Credentials:   S3Credentials{AccessKeyID: "control-access", SecretAccessKey: "control-secret", Region: "auto"},
		Client:        server.Client(), AllowInsecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	observed, err := provider.R2GetControl(context.Background(), ".sow/bootstrap/leases/plan.json")
	if err != nil || observed.Exists {
		t.Fatalf("R2-only control GET result=%+v err=%v", observed, err)
	}
	if requests.Load() != 1 {
		t.Fatalf("R2-only control request count=%d want=1", requests.Load())
	}
}

func TestCOSControlHTTPNeedsNoEdgeOneAuthority(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Method != http.MethodGet || request.URL.Path != "/bucket/.sow/bootstrap/leases/plan.json" {
			t.Errorf("COS-only control client reached a non-object endpoint: %s %s", request.Method, request.URL.String())
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Error("COS-only control request was not SigV4 signed")
		}
		writer.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	provider, err := NewCOSControlHTTP(COSControlHTTPConfig{
		ObjectBaseURL: server.URL + "/bucket",
		Credentials:   S3Credentials{AccessKeyID: "control-access", SecretAccessKey: "control-secret", Region: "ap-shanghai"},
		Client:        server.Client(), AllowInsecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	observed, err := provider.COSGetControl(context.Background(), ".sow/bootstrap/leases/plan.json")
	if err != nil || observed.Exists {
		t.Fatalf("COS-only control GET result=%+v err=%v", observed, err)
	}
	if requests.Load() != 1 {
		t.Fatalf("COS-only control request count=%d want=1", requests.Load())
	}
}

func TestR2CheckpointFencedDeleteIsExplicitlyUnconditionalAndSigned(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodDelete || request.URL.Path != "/bucket/pkg/retired.bin" {
			t.Errorf("unexpected checkpoint-fenced request: %s %s", request.Method, request.URL.String())
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if request.Header.Get("If-Match") != "" {
			t.Errorf("checkpoint-fenced delete falsely advertised If-Match: %#v", request.Header)
		}
		if !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Error("checkpoint-fenced delete was not SigV4 signed")
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	provider, err := NewR2CloudflareControlHTTP(R2CloudflareControlHTTPConfig{
		ObjectBaseURL: server.URL + "/bucket",
		Credentials:   S3Credentials{AccessKeyID: "control-access", SecretAccessKey: "control-secret", Region: "auto"},
		Client:        server.Client(), AllowInsecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.R2DeleteCheckpointFenced(context.Background(), "pkg/retired.bin"); err != nil {
		t.Fatal(err)
	}
}

func TestFullProvidersCheckpointFencedDeleteIsExactSignedAndFailClosed(t *testing.T) {
	t.Parallel()
	for _, dialect := range []string{"r2", "cos"} {
		dialect := dialect
		t.Run(dialect, func(t *testing.T) {
			statuses := []int{http.StatusNoContent, http.StatusNotFound, http.StatusPreconditionFailed, http.StatusNotImplemented}
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				index := int(requests.Add(1)) - 1
				if index >= len(statuses) {
					t.Errorf("%s checkpoint-fenced delete issued an unexpected request %d", dialect, index+1)
					writer.WriteHeader(http.StatusInternalServerError)
					return
				}
				if request.Method != http.MethodDelete || request.URL.Path != "/bucket/.sow/publication/retired.json" || request.URL.RawQuery != "x-id=DeleteObject" {
					t.Errorf("unexpected %s checkpoint-fenced request: %s %s", dialect, request.Method, request.URL.String())
					writer.WriteHeader(http.StatusBadRequest)
					return
				}
				if request.Header.Get("If-Match") != "" || request.Header.Get("If-None-Match") != "" {
					t.Errorf("%s checkpoint-fenced delete advertised a false object precondition: %#v", dialect, request.Header)
				}
				authorization := request.Header.Get("Authorization")
				if !strings.HasPrefix(authorization, "AWS4-HMAC-SHA256 ") || strings.Contains(strings.ToLower(authorization), "if-match") {
					t.Errorf("%s checkpoint-fenced delete has the wrong SigV4 contract: %q", dialect, authorization)
				}
				switch dialect {
				case "r2":
					if !strings.Contains(authorization, "Credential=r2-access/") || !strings.Contains(authorization, "/auto/s3/aws4_request") ||
						request.Header.Get("X-Amz-Security-Token") != "r2-session-token" || request.Header.Get("X-Cos-Security-Token") != "" ||
						!strings.Contains(authorization, "x-amz-security-token") {
						t.Errorf("R2 checkpoint-fenced delete lost its exact credential scope: headers=%#v", request.Header)
					}
				case "cos":
					if !strings.Contains(authorization, "Credential=cos-access/") || !strings.Contains(authorization, "/ap-shanghai/s3/aws4_request") ||
						request.Header.Get("X-Cos-Security-Token") != "cos-session-token" || request.Header.Get("X-Amz-Security-Token") != "" ||
						!strings.Contains(authorization, "x-cos-security-token") {
						t.Errorf("COS checkpoint-fenced delete lost its exact credential scope: headers=%#v", request.Header)
					}
				}
				writer.WriteHeader(statuses[index])
			}))
			defer server.Close()

			var remove func(context.Context, string) error
			if dialect == "r2" {
				provider, err := NewR2CloudflareHTTP(R2CloudflareHTTPConfig{
					Bucket: "bucket", ObjectBaseURL: server.URL + "/bucket", CDNBaseURL: "https://cdn.example/",
					Credentials: S3Credentials{AccessKeyID: "r2-access", SecretAccessKey: "r2-secret", SessionToken: "r2-session-token", Region: "auto"},
					ZoneID:      "zone", APIToken: "cf-token", CloudflareAPIURL: server.URL, Client: server.Client(),
				})
				if err != nil {
					t.Fatal(err)
				}
				remove = provider.R2DeleteCheckpointFenced
			} else {
				provider, err := NewCOSEdgeOneHTTP(COSEdgeOneHTTPConfig{
					Bucket: "bucket", ObjectBaseURL: server.URL + "/bucket", CDNBaseURL: "https://cdn.example/",
					ObjectCredentials:  S3Credentials{AccessKeyID: "cos-access", SecretAccessKey: "cos-secret", SessionToken: "cos-session-token", Region: "ap-shanghai"},
					TencentCredentials: TencentCredentials{SecretID: "tc-id", SecretKey: "tc-secret"},
					ZoneID:             "zone", EdgeOneAPIURL: server.URL, Client: server.Client(), UnversionedBucketConfirmed: true,
				})
				if err != nil {
					t.Fatal(err)
				}
				remove = provider.COSDeleteCheckpointFenced
			}

			key := ".sow/publication/retired.json"
			for index, want := range []error{nil, ErrNotFound, ErrConflict, ErrCapability} {
				err := remove(context.Background(), key)
				if want == nil && err != nil || want != nil && !errors.Is(err, want) {
					t.Fatalf("%s checkpoint-fenced response %d err=%v want=%v", dialect, statuses[index], err, want)
				}
			}
			if err := remove(context.Background(), "../escape"); err == nil || !strings.Contains(err.Error(), "invalid checkpoint-fenced") {
				t.Fatalf("%s checkpoint-fenced delete accepted an unsafe key: %v", dialect, err)
			}
			if requests.Load() != int32(len(statuses)) {
				t.Fatalf("%s checkpoint-fenced delete requests=%d want=%d", dialect, requests.Load(), len(statuses))
			}
		})
	}
}

func TestCloudflarePurgeResponseLossRequiresExplicitExactReplay(t *testing.T) {
	t.Parallel()
	wantURLs := []string{
		"https://cdn.example/dists/jammy/InRelease",
		"https://cdn.example/.sow/gated/dists/jammy/InRelease",
	}
	var calls atomic.Int32
	var mutex sync.Mutex
	var received [][]string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/zones/zone/purge_cache" {
			t.Errorf("unexpected Cloudflare request: %s %s", request.Method, request.URL.String())
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		if request.Header.Get("Authorization") != "Bearer cf-token" {
			t.Error("Cloudflare purge replay omitted the bearer token")
		}
		var body struct {
			Files []string `json:"files"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Errorf("decode complete Cloudflare purge body: %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		mutex.Lock()
		received = append(received, append([]string(nil), body.Files...))
		mutex.Unlock()

		if calls.Add(1) == 1 {
			writeTruncatedJSONResponse(t, writer, `{"success":true`)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"success":true,"errors":[],"result":{"id":"zone"}}`)
	}))
	defer server.Close()

	provider, err := NewR2CloudflareHTTP(R2CloudflareHTTPConfig{
		ObjectBaseURL: server.URL + "/bucket", CDNBaseURL: "https://cdn.example/",
		Credentials: S3Credentials{AccessKeyID: "access", SecretAccessKey: "secret", Region: "auto"},
		ZoneID:      "zone", APIToken: "cf-token", CloudflareAPIURL: server.URL,
		Client: server.Client(), AllowInsecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.CloudflarePurge(context.Background(), wantURLs); err == nil {
		t.Fatal("truncated Cloudflare success response was accepted")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("first Cloudflare invocation issued %d HTTP requests, want exactly one without a hidden SDK retry", got)
	}
	if err := provider.CloudflarePurge(context.Background(), wantURLs); err != nil {
		t.Fatalf("explicit Cloudflare purge replay failed: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("explicit Cloudflare replay issued total HTTP requests=%d, want 2", got)
	}
	mutex.Lock()
	gotBodies := append([][]string(nil), received...)
	mutex.Unlock()
	if len(gotBodies) != 2 || !reflect.DeepEqual(gotBodies[0], wantURLs) || !reflect.DeepEqual(gotBodies[1], wantURLs) {
		t.Fatalf("Cloudflare purge was not replayed with the same exact URLs: %#v", gotBodies)
	}
}

func TestCloudflarePurgeEvidenceUsesCFRayNotVendorResultID(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("CF-Ray", "8abc1234-SJC")
		_, _ = io.WriteString(writer, `{"success":true,"errors":[],"result":{"id":"zone-not-a-request-id"}}`)
	}))
	defer server.Close()
	provider, err := NewR2CloudflareHTTP(R2CloudflareHTTPConfig{
		ObjectBaseURL: server.URL + "/bucket", CDNBaseURL: "https://cdn.example/",
		Credentials: S3Credentials{AccessKeyID: "access", SecretAccessKey: "secret", Region: "auto"},
		ZoneID:      "zone", APIToken: "cf-token", CloudflareAPIURL: server.URL,
		Client: server.Client(), AllowInsecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	urls := []string{"https://cdn.example/pointer"}
	receipt, err := provider.CloudflarePurgeBatchEvidence(context.Background(), urls)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, _ := PurgeURLsDigest(urls)
	if receipt.Status != PurgeReceiptCompleted || receipt.Vendor != PurgeVendorCloudflare ||
		receipt.AcceptedRequestID != "8abc1234-SJC" || receipt.CompletedRequestID != "8abc1234-SJC" ||
		receipt.VendorResultID != "zone-not-a-request-id" || receipt.URLCount != 1 || receipt.URLsSHA256 != wantDigest {
		t.Fatalf("unexpected Cloudflare receipt: %#v", receipt)
	}
}

func TestCOSEdgeOneHTTPUsesCreateOnlyLockWithoutIfMatch(t *testing.T) {
	t.Parallel()
	if _, err := NewCOSEdgeOneHTTP(COSEdgeOneHTTPConfig{}); !errors.Is(err, ErrCapability) {
		t.Fatalf("unconfirmed COS bucket was not rejected: %v", err)
	}
	var sawCreate, sawPut, sawPurge bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, "/bucket") {
			authorization := request.Header.Get("Authorization")
			if request.Header.Get("X-Cos-Security-Token") != "cos-session-token" || request.Header.Get("X-Amz-Security-Token") != "" ||
				!strings.Contains(authorization, "x-cos-security-token") {
				t.Errorf("COS temporary credential token was not projected and signature-bound: headers=%#v", request.Header)
			}
		}
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/bucket" && request.URL.Query().Has("versioning"):
			_, _ = io.WriteString(writer, `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>`)
		case request.Method == http.MethodPut && strings.HasPrefix(request.URL.Path, "/bucket/.sow/locks/"):
			sawCreate = true
			assertNoOptionalS3ChecksumHeaders(t, request)
			if request.Header.Get("X-Cos-Forbid-Overwrite") != "true" {
				t.Error("COS lock is not create-only")
			}
			if request.Header.Get("If-Match") != "" || request.Header.Get("If-None-Match") != "" {
				t.Error("COS lock pretended to use S3 conditional overwrite")
			}
			authorization := request.Header.Get("Authorization")
			if !strings.Contains(authorization, "x-cos-forbid-overwrite") || !strings.Contains(authorization, "x-cos-meta-sow-sha256") {
				t.Error("COS create-only condition and integrity metadata were not signature-bound")
			}
			_, _ = io.Copy(io.Discard, request.Body)
			writer.Header().Set("ETag", `"lock"`)
			writer.WriteHeader(http.StatusOK)
		case request.Method == http.MethodPut && request.URL.Path == "/bucket/.sow/manifest.json":
			sawPut = true
			if request.Header.Get("X-Cos-Forbid-Overwrite") != "" || request.Header.Get("If-Match") != "" {
				t.Error("COS checkpoint overwrite used a false CAS header")
			}
			_, _ = io.Copy(io.Discard, request.Body)
			writer.Header().Set("ETag", `"checkpoint"`)
			writer.WriteHeader(http.StatusOK)
		case request.Method == http.MethodPost && request.URL.Path == "/" && request.Header.Get("X-TC-Action") == "CreatePurgeTask":
			sawPurge = true
			if request.Header.Get("X-TC-Action") != "CreatePurgeTask" || request.Header.Get("X-TC-Version") != "2022-09-01" {
				t.Error("EdgeOne purge used the wrong API contract")
			}
			if !strings.HasPrefix(request.Header.Get("Authorization"), "TC3-HMAC-SHA256 ") {
				t.Error("EdgeOne purge was not TC3 signed")
			}
			var body struct {
				Targets []string `json:"Targets"`
				Type    string   `json:"Type"`
				ZoneID  string   `json:"ZoneId"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body.Type != "purge_url" || body.ZoneID != "zone" || len(body.Targets) != 2 ||
				body.Targets[0] != "https://cdn.example/pointer" || body.Targets[1] != "https://cdn.example/.sow/gated/pointer" {
				t.Errorf("unexpected EdgeOne purge body: %#v", body)
			}
			_, _ = io.WriteString(writer, `{"Response":{"JobId":"job","FailedList":[],"RequestId":"req"}}`)
		case request.Method == http.MethodPost && request.URL.Path == "/" && request.Header.Get("X-TC-Action") == "DescribePurgeTasks":
			_, _ = io.WriteString(writer, `{"Response":{"Tasks":[{"JobId":"job","Status":"success"}],"TotalCount":1,"RequestId":"req"}}`)
		default:
			t.Errorf("unexpected COS/EdgeOne request: %s %s", request.Method, request.URL.String())
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	provider, err := NewCOSEdgeOneHTTP(COSEdgeOneHTTPConfig{
		ObjectBaseURL:      server.URL + "/bucket",
		CDNBaseURL:         "https://cdn.example/",
		ObjectCredentials:  S3Credentials{AccessKeyID: "cos-id", SecretAccessKey: "cos-key", SessionToken: "cos-session-token", Region: "ap-shanghai"},
		TencentCredentials: TencentCredentials{SecretID: "tc-id", SecretKey: "tc-key"},
		ZoneID:             "zone", EdgeOneAPIURL: server.URL, Client: server.Client(), AllowInsecure: true,
		UnversionedBucketConfirmed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.COSProbeUnversioned(context.Background()); err != nil {
		t.Fatal(err)
	}
	lock := []byte("lock")
	if _, err := provider.COSCreate(context.Background(), ".sow/locks/00000000000000000001.json", bytes.NewReader(lock), int64(len(lock)), hashString("lock")); err != nil {
		t.Fatal(err)
	}
	checkpoint := []byte("checkpoint")
	if _, err := provider.COSPut(context.Background(), CheckpointKey, bytes.NewReader(checkpoint), int64(len(checkpoint)), hashString("checkpoint")); err != nil {
		t.Fatal(err)
	}
	if err := provider.EdgeOnePurge(context.Background(), []string{"https://cdn.example/pointer", "https://cdn.example/.sow/gated/pointer"}); err != nil {
		t.Fatal(err)
	}
	if !sawCreate || !sawPut || !sawPurge {
		t.Fatalf("missing provider path create=%v put=%v purge=%v", sawCreate, sawPut, sawPurge)
	}
}

func TestEdgeOnePurgeDescribeResponseLossRequiresNewExactJobReplay(t *testing.T) {
	t.Parallel()
	wantURLs := []string{
		"https://cdn.example/pointer",
		"https://cdn.example/.sow/gated/pointer",
	}
	type createRequest struct {
		Targets []string `json:"Targets"`
		Type    string   `json:"Type"`
		ZoneID  string   `json:"ZoneId"`
	}
	var createCalls atomic.Int32
	var describeCalls atomic.Int32
	var mutex sync.Mutex
	var createBodies []createRequest
	var describeJobs []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/" {
			t.Errorf("unexpected EdgeOne request: %s %s", request.Method, request.URL.String())
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		switch request.Header.Get("X-TC-Action") {
		case "CreatePurgeTask":
			var body createRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode complete EdgeOne CreatePurgeTask body: %v", err)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			mutex.Lock()
			createBodies = append(createBodies, createRequest{ZoneID: body.ZoneID, Type: body.Type, Targets: append([]string(nil), body.Targets...)})
			mutex.Unlock()
			jobID := "job-1"
			if createCalls.Add(1) == 2 {
				jobID = "job-2"
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"Response":{"JobId":"`+jobID+`","FailedList":[],"RequestId":"create-request"}}`)
		case "DescribePurgeTasks":
			var body struct {
				ZoneID  string `json:"ZoneId"`
				Filters []struct {
					Name   string   `json:"Name"`
					Values []string `json:"Values"`
				} `json:"Filters"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode complete EdgeOne DescribePurgeTasks body: %v", err)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			jobID := ""
			for _, filter := range body.Filters {
				if filter.Name == "job-id" && len(filter.Values) == 1 {
					jobID = filter.Values[0]
				}
			}
			if body.ZoneID != "zone" || jobID == "" {
				t.Errorf("unexpected EdgeOne describe body: zone=%q job=%q", body.ZoneID, jobID)
			}
			mutex.Lock()
			describeJobs = append(describeJobs, jobID)
			mutex.Unlock()
			if describeCalls.Add(1) == 1 {
				writeTruncatedJSONResponse(t, writer, `{"Response":{"Tasks":[`)
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"Response":{"Tasks":[{"JobId":"job-2","Status":"success"}],"TotalCount":1,"RequestId":"describe-request"}}`)
		default:
			t.Errorf("unexpected Tencent action %q", request.Header.Get("X-TC-Action"))
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	provider, err := NewCOSEdgeOneHTTP(COSEdgeOneHTTPConfig{
		ObjectBaseURL:      server.URL + "/bucket",
		CDNBaseURL:         "https://cdn.example/",
		ObjectCredentials:  S3Credentials{AccessKeyID: "cos-id", SecretAccessKey: "cos-key", Region: "ap-shanghai"},
		TencentCredentials: TencentCredentials{SecretID: "tc-id", SecretKey: "tc-key"},
		ZoneID:             "zone", EdgeOneAPIURL: server.URL, Client: server.Client(), AllowInsecure: true,
		UnversionedBucketConfirmed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.EdgeOnePurge(context.Background(), wantURLs); err == nil {
		t.Fatal("truncated EdgeOne DescribePurgeTasks response was accepted")
	}
	if got := createCalls.Load(); got != 1 {
		t.Fatalf("first EdgeOne invocation created %d jobs, want exactly one without a hidden SDK retry", got)
	}
	if got := describeCalls.Load(); got != 1 {
		t.Fatalf("first EdgeOne invocation described the job %d times, want exactly one without a hidden SDK retry", got)
	}
	if err := provider.EdgeOnePurge(context.Background(), wantURLs); err != nil {
		t.Fatalf("explicit EdgeOne purge replay failed: %v", err)
	}
	if got := createCalls.Load(); got != 2 {
		t.Fatalf("explicit EdgeOne replay created total jobs=%d, want 2", got)
	}
	if got := describeCalls.Load(); got != 2 {
		t.Fatalf("explicit EdgeOne replay issued total describe calls=%d, want 2", got)
	}

	wantCreate := createRequest{ZoneID: "zone", Type: "purge_url", Targets: wantURLs}
	mutex.Lock()
	gotCreateBodies := append([]createRequest(nil), createBodies...)
	gotDescribeJobs := append([]string(nil), describeJobs...)
	mutex.Unlock()
	if len(gotCreateBodies) != 2 || !reflect.DeepEqual(gotCreateBodies[0], wantCreate) || !reflect.DeepEqual(gotCreateBodies[1], wantCreate) {
		t.Fatalf("EdgeOne replay changed Zone/Type/URLs: %#v", gotCreateBodies)
	}
	if !reflect.DeepEqual(gotDescribeJobs, []string{"job-1", "job-2"}) {
		t.Fatalf("EdgeOne replay did not track the newly created job: %v", gotDescribeJobs)
	}
}

func TestEdgeOnePurgeEvidenceResumesAcceptedJobWithoutRecreate(t *testing.T) {
	t.Parallel()
	var createCalls atomic.Int32
	var describeCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.Header.Get("X-TC-Action") {
		case "CreatePurgeTask":
			createCalls.Add(1)
			_, _ = io.WriteString(writer, `{"Response":{"JobId":"job-resume","FailedList":[],"RequestId":"create-request"}}`)
		case "DescribePurgeTasks":
			if describeCalls.Add(1) == 1 {
				writeTruncatedJSONResponse(t, writer, `{"Response":{"Tasks":[`)
				return
			}
			_, _ = io.WriteString(writer, `{"Response":{"Tasks":[{"JobId":"job-resume","Status":"success","CreateTime":"2026-07-14T00:00:00Z","UpdateTime":"2026-07-14T00:00:01Z"}],"RequestId":"describe-request"}}`)
		default:
			t.Errorf("unexpected Tencent action %q", request.Header.Get("X-TC-Action"))
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	provider, err := NewCOSEdgeOneHTTP(COSEdgeOneHTTPConfig{
		ObjectBaseURL: server.URL + "/bucket", CDNBaseURL: "https://cdn.example/",
		ObjectCredentials:  S3Credentials{AccessKeyID: "cos-id", SecretAccessKey: "cos-key", Region: "ap-shanghai"},
		TencentCredentials: TencentCredentials{SecretID: "tc-id", SecretKey: "tc-key"},
		ZoneID:             "zone", EdgeOneAPIURL: server.URL, Client: server.Client(), AllowInsecure: true,
		UnversionedBucketConfirmed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := provider.EdgeOneAcceptPurgeBatch(context.Background(), []string{"https://cdn.example/pointer"})
	if err != nil || accepted.Status != PurgeReceiptAccepted {
		t.Fatalf("accept receipt=%#v err=%v", accepted, err)
	}
	if _, err := provider.EdgeOneCompletePurgeBatch(context.Background(), accepted); err == nil {
		t.Fatal("truncated status response was accepted")
	}
	completed, err := provider.EdgeOneCompletePurgeBatch(context.Background(), accepted)
	if err != nil {
		t.Fatal(err)
	}
	if createCalls.Load() != 1 || describeCalls.Load() != 2 {
		t.Fatalf("resume calls create=%d describe=%d", createCalls.Load(), describeCalls.Load())
	}
	if completed.Status != PurgeReceiptCompleted || completed.JobID != accepted.JobID ||
		completed.AcceptedRequestID != "create-request" || completed.CompletedRequestID != "describe-request" ||
		completed.ProviderCreatedAt != "2026-07-14T00:00:00Z" || completed.ProviderUpdatedAt != "2026-07-14T00:00:01Z" {
		t.Fatalf("unexpected completed EdgeOne receipt: %#v", completed)
	}
}

func TestEdgeOnePurgeEvidenceMarksRepeatedMissingAcceptedJobIndeterminate(t *testing.T) {
	t.Parallel()
	var createCalls atomic.Int32
	var describeCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.Header.Get("X-TC-Action") {
		case "CreatePurgeTask":
			createCalls.Add(1)
			_, _ = io.WriteString(writer, `{"Response":{"JobId":"job-missing","FailedList":[],"RequestId":"create-missing"}}`)
		case "DescribePurgeTasks":
			call := describeCalls.Add(1)
			_, _ = fmt.Fprintf(writer, `{"Response":{"Tasks":[],"RequestId":"describe-missing-%d"}}`, call)
		default:
			t.Errorf("unexpected Tencent action %q", request.Header.Get("X-TC-Action"))
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	provider, err := NewCOSEdgeOneHTTP(COSEdgeOneHTTPConfig{
		ObjectBaseURL: server.URL + "/bucket", CDNBaseURL: "https://cdn.example/",
		ObjectCredentials:  S3Credentials{AccessKeyID: "cos-id", SecretAccessKey: "cos-key", Region: "ap-shanghai"},
		TencentCredentials: TencentCredentials{SecretID: "tc-id", SecretKey: "tc-key"},
		ZoneID:             "zone", EdgeOneAPIURL: server.URL, Client: server.Client(), AllowInsecure: true,
		UnversionedBucketConfirmed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	provider.purgePollInterval = time.Millisecond
	// Leave enough wall-clock budget for the signed SDK request and the race
	// detector; the contract under test is the cross-call persistence boundary,
	// not a scheduler-dependent six-millisecond deadline.
	provider.purgeWaitTimeout = 75 * time.Millisecond
	provider.purgeMissingGrace = 0
	accepted, err := provider.EdgeOneAcceptPurgeBatch(context.Background(), []string{"https://cdn.example/pointer"})
	if err != nil {
		t.Fatal(err)
	}
	first, err := provider.EdgeOneCompletePurgeBatch(context.Background(), accepted)
	if err == nil || first.Status != PurgeReceiptAccepted || first.NotFoundConfirmations != 1 ||
		first.JobID != accepted.JobID || first.FirstNotFoundRequestID == "" || first.FirstNotFoundRequestID != first.LastNotFoundRequestID {
		t.Fatalf("first missing query receipt=%#v err=%v", first, err)
	}
	second, err := provider.EdgeOneCompletePurgeBatch(context.Background(), first)
	if err == nil || second.Status != PurgeReceiptIndeterminate || second.NotFoundConfirmations != 2 ||
		second.JobID != accepted.JobID || second.IndeterminateRequestID != second.LastNotFoundRequestID ||
		second.IndeterminateObservedAt != second.LastNotFoundObservedAt {
		t.Fatalf("second missing query receipt=%#v err=%v", second, err)
	}
	if createCalls.Load() != 1 || describeCalls.Load() < 2 {
		t.Fatalf("missing-job polling recreated before persistence boundary create=%d describe=%d", createCalls.Load(), describeCalls.Load())
	}
}

func writeTruncatedJSONResponse(t *testing.T, writer http.ResponseWriter, prefix string) {
	t.Helper()
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		t.Error("test HTTP server does not support connection hijacking")
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	connection, buffer, err := hijacker.Hijack()
	if err != nil {
		t.Errorf("hijack test HTTP connection: %v", err)
		return
	}
	defer connection.Close()
	if _, err := buffer.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1024\r\nConnection: close\r\n\r\n" + prefix); err != nil {
		t.Errorf("write truncated test response: %v", err)
		return
	}
	if err := buffer.Flush(); err != nil {
		t.Errorf("flush truncated test response: %v", err)
	}
}

func assertNoOptionalS3ChecksumHeaders(t *testing.T, request *http.Request) {
	t.Helper()
	for _, name := range []string{"X-Amz-Sdk-Checksum-Algorithm", "X-Amz-Checksum-Crc32", "X-Amz-Checksum-Crc32c", "X-Amz-Checksum-Crc64nvme", "X-Amz-Trailer"} {
		if value := request.Header.Get(name); value != "" {
			t.Errorf("S3 SDK added unsupported optional checksum header %s=%q", name, value)
		}
	}
	if strings.EqualFold(request.Header.Get("Content-Encoding"), "aws-chunked") {
		t.Error("S3 SDK enabled aws-chunked framing for an S3-compatible target")
	}
}

func TestR2AndCOSUseVendorSpecificSignedServerSideCopy(t *testing.T) {
	t.Parallel()
	for _, dialect := range []string{"r2", "cos"} {
		t.Run(dialect, func(t *testing.T) {
			var sawCopy bool
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodPut || request.URL.Path != "/bucket/.sow/gated/snapshots/jammy-20260712/yum/repo/Packages/pkg.rpm" {
					t.Errorf("unexpected CopyObject request: %s %s", request.Method, request.URL.String())
					writer.WriteHeader(http.StatusNotFound)
					return
				}
				sawCopy = true
				if request.ContentLength != 0 {
					t.Errorf("CopyObject request body length=%d", request.ContentLength)
				}
				authorization := request.Header.Get("Authorization")
				if !strings.HasPrefix(authorization, "AWS4-HMAC-SHA256 ") {
					t.Error("CopyObject request is not SigV4 signed")
				}
				if dialect == "r2" {
					if request.Header.Get("X-Amz-Copy-Source") != "/bucket/yum/repo/Packages/pkg.rpm" || request.Header.Get("X-Amz-Copy-Source-If-Match") != `"source"` || request.Header.Get("X-Amz-Metadata-Directive") != "REPLACE" || request.Header.Get("Cf-Copy-Destination-If-None-Match") != "*" {
						t.Errorf("wrong R2 CopyObject headers: %#v", request.Header)
					}
					for _, signed := range []string{"cf-copy-destination-if-none-match", "x-amz-copy-source", "x-amz-copy-source-if-match", "x-amz-meta-sow-sha256"} {
						if !strings.Contains(authorization, signed) {
							t.Errorf("R2 copy header %s is not signature-bound", signed)
						}
					}
				} else {
					if request.Header.Get("X-Cos-Copy-Source") != request.Host+"/yum/repo/Packages/pkg.rpm" || request.Header.Get("X-Cos-Copy-Source-If-Match") != `"source"` || request.Header.Get("X-Cos-Metadata-Directive") != "Replaced" || request.Header.Get("X-Cos-Forbid-Overwrite") != "true" {
						t.Errorf("wrong COS CopyObject headers: %#v", request.Header)
					}
					for _, signed := range []string{"x-cos-copy-source", "x-cos-copy-source-if-match", "x-cos-forbid-overwrite", "x-cos-meta-sow-sha256"} {
						if !strings.Contains(authorization, signed) {
							t.Errorf("COS copy header %s is not signature-bound", signed)
						}
					}
				}
				writer.Header().Set("Content-Type", "application/xml")
				_, _ = io.WriteString(writer, `<CopyObjectResult><ETag>&quot;destination&quot;</ETag><LastModified>2026-07-12T00:00:00Z</LastModified></CopyObjectResult>`)
			}))
			defer server.Close()

			var etag string
			var err error
			if dialect == "r2" {
				provider, createErr := NewR2CloudflareHTTP(R2CloudflareHTTPConfig{
					Bucket: "bucket", ObjectBaseURL: server.URL + "/bucket", CDNBaseURL: "https://cdn.example/",
					Credentials: S3Credentials{AccessKeyID: "access", SecretAccessKey: "secret", Region: "auto"},
					ZoneID:      "zone", APIToken: "cf-token", CloudflareAPIURL: server.URL, Client: server.Client(), AllowInsecure: true,
				})
				if createErr != nil {
					t.Fatal(createErr)
				}
				etag, err = provider.R2Copy(context.Background(), ".sow/gated/snapshots/jammy-20260712/yum/repo/Packages/pkg.rpm", "yum/repo/Packages/pkg.rpm", 3, hashString("pkg"), `"source"`)
			} else {
				provider, createErr := NewCOSEdgeOneHTTP(COSEdgeOneHTTPConfig{
					ObjectBaseURL: server.URL + "/bucket", CDNBaseURL: "https://cdn.example/",
					ObjectCredentials:  S3Credentials{AccessKeyID: "cos-id", SecretAccessKey: "cos-key", Region: "ap-shanghai"},
					TencentCredentials: TencentCredentials{SecretID: "tc-id", SecretKey: "tc-key"}, ZoneID: "zone",
					EdgeOneAPIURL: server.URL, Client: server.Client(), AllowInsecure: true, UnversionedBucketConfirmed: true,
				})
				if createErr != nil {
					t.Fatal(createErr)
				}
				etag, err = provider.COSCopy(context.Background(), ".sow/gated/snapshots/jammy-20260712/yum/repo/Packages/pkg.rpm", "yum/repo/Packages/pkg.rpm", 3, hashString("pkg"), `"source"`)
			}
			if err != nil || etag != `"destination"` || !sawCopy {
				t.Fatalf("CopyObject etag=%q saw=%t err=%v", etag, sawCopy, err)
			}
		})
	}
}

func TestS3SDKCopyObjectEmbedded200ErrorFailsClosed(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Method != http.MethodPut {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(writer, `<Error><Code>InternalError</Code><Message>copy failed after acceptance</Message><RequestId>req</RequestId></Error>`)
	}))
	defer server.Close()
	provider, err := NewR2CloudflareHTTP(R2CloudflareHTTPConfig{
		Bucket: "bucket", ObjectBaseURL: server.URL + "/bucket", CDNBaseURL: "https://cdn.example/",
		Credentials: S3Credentials{AccessKeyID: "access", SecretAccessKey: "secret", Region: "auto"},
		ZoneID:      "zone", APIToken: "cf-token", CloudflareAPIURL: server.URL, Client: server.Client(), AllowInsecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if etag, err := provider.R2Copy(context.Background(), "snapshot/pkg.rpm", "live/pkg.rpm", 3, hashString("pkg"), `"source"`); err == nil || etag != "" {
		t.Fatalf("HTTP-200 embedded CopyObject error was accepted: etag=%q err=%v", etag, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("embedded CopyObject error calls=%d, want one fail-closed SDK attempt", calls.Load())
	}
}

func TestS3SDKCopyObjectOversized200DocumentFailsClosed(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		writer.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(writer, `<CopyObjectResult><ETag>"destination"</ETag><Padding>`+strings.Repeat("x", (1<<20)+1)+`</Padding></CopyObjectResult>`)
	}))
	defer server.Close()
	provider, err := NewR2CloudflareHTTP(R2CloudflareHTTPConfig{
		Bucket: "bucket", ObjectBaseURL: server.URL + "/bucket", CDNBaseURL: "https://cdn.example/",
		Credentials: S3Credentials{AccessKeyID: "access", SecretAccessKey: "secret", Region: "auto"},
		ZoneID:      "zone", APIToken: "cf-token", CloudflareAPIURL: server.URL, Client: server.Client(), AllowInsecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if etag, err := provider.R2Copy(context.Background(), "snapshot/pkg.rpm", "live/pkg.rpm", 3, hashString("pkg"), `"source"`); err == nil || etag != "" || !strings.Contains(err.Error(), "safety limit") {
		t.Fatalf("oversized HTTP-200 CopyObject document was accepted: etag=%q err=%v", etag, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("oversized CopyObject response calls=%d, want one bounded SDK attempt", calls.Load())
	}
}

func TestR2AndCOSSnapshotDeleteUsesSignedExactKey(t *testing.T) {
	t.Parallel()
	for _, dialect := range []string{"r2", "cos"} {
		t.Run(dialect, func(t *testing.T) {
			var deleteRequests int
			var mutex sync.Mutex
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodDelete || request.URL.Path != "/bucket/.sow/snapshots/jammy-20260131.json" {
					t.Errorf("unexpected deletion: %s %s", request.Method, request.URL.String())
					writer.WriteHeader(http.StatusBadRequest)
					return
				}
				if !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
					t.Error("snapshot deletion was not SigV4 signed")
				}
				if request.Header.Get("If-Match") != `"route-etag"` || !strings.Contains(request.Header.Get("Authorization"), "if-match") {
					t.Errorf("snapshot deletion was not condition-bound: If-Match=%q Authorization=%q", request.Header.Get("If-Match"), request.Header.Get("Authorization"))
				}
				mutex.Lock()
				deleteRequests++
				mutex.Unlock()
				writer.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			if dialect == "r2" {
				provider, err := NewR2CloudflareHTTP(R2CloudflareHTTPConfig{
					Bucket: "bucket", ObjectBaseURL: server.URL + "/bucket", CDNBaseURL: "https://cdn.example/",
					Credentials: S3Credentials{AccessKeyID: "access", SecretAccessKey: "secret", Region: "auto"},
					ZoneID:      "zone", APIToken: "cf-token", CloudflareAPIURL: server.URL, Client: server.Client(), AllowInsecure: true,
				})
				if err != nil || provider.R2Delete(context.Background(), ".sow/snapshots/jammy-20260131.json", `"route-etag"`) != nil {
					t.Fatalf("R2 delete err=%v", err)
				}
			} else {
				provider, err := NewCOSEdgeOneHTTP(COSEdgeOneHTTPConfig{
					ObjectBaseURL: server.URL + "/bucket", CDNBaseURL: "https://cdn.example/",
					ObjectCredentials:  S3Credentials{AccessKeyID: "cos-id", SecretAccessKey: "cos-key", Region: "ap-shanghai"},
					TencentCredentials: TencentCredentials{SecretID: "tc-id", SecretKey: "tc-key"}, ZoneID: "zone",
					EdgeOneAPIURL: server.URL, Client: server.Client(), AllowInsecure: true, UnversionedBucketConfirmed: true,
				})
				if err != nil || provider.COSDelete(context.Background(), ".sow/snapshots/jammy-20260131.json", `"route-etag"`) != nil {
					t.Fatalf("COS delete err=%v", err)
				}
			}
			mutex.Lock()
			deletes := deleteRequests
			mutex.Unlock()
			if deletes != 1 {
				t.Fatalf("%s exact DELETE requests=%d, want 1", dialect, deletes)
			}
		})
	}
}
