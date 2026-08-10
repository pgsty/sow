package r2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListObjectsV2PrefixIsSignedBoundedAndConfined(t *testing.T) {
	const prefix = "repos/prod/"
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls++
		if request.Method != http.MethodGet || request.URL.Path != "/bucket" ||
			request.URL.Query().Get("list-type") != "2" || request.URL.Query().Get("encoding-type") != "url" ||
			request.URL.Query().Get("max-keys") != "1000" || request.URL.Query().Get("prefix") != prefix {
			t.Errorf("unexpected list request: %s %s", request.Method, request.URL.String())
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Error("ListObjectsV2 request was not SigV4 signed")
		}
		writer.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(writer, `<ListBucketResult><EncodingType>url</EncodingType><IsTruncated>false</IsTruncated><Contents><Key>repos%2Fprod%2Fpackage.rpm</Key><Size>7</Size><ETag>&quot;etag&quot;</ETag></Contents></ListBucketResult>`)
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Bucket: "bucket", ObjectBaseURL: server.URL + "/bucket", Client: server.Client(), AllowInsecure: true,
		Credentials: S3Credentials{AccessKeyID: "access", SecretAccessKey: "secret", SessionToken: "session", Region: "auto"},
	})
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.ListObjectsV2Prefix(context.Background(), prefix, "")
	if err != nil || len(page.Objects) != 1 || page.Objects[0].Key != "repos/prod/package.rpm" || page.Objects[0].Size != 7 {
		t.Fatalf("page=%#v err=%v", page, err)
	}
	before := calls
	if _, err := client.ListObjectsV2Prefix(context.Background(), "../unsafe/", ""); err == nil || calls != before {
		t.Fatalf("unsafe prefix reached provider: calls=%d before=%d err=%v", calls, before, err)
	}
}

func TestListObjectsV2PrefixPreservesOpaquePagination(t *testing.T) {
	const prefix = "repos/prod/"
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls++
		if request.Method != http.MethodGet || request.URL.Path != "/bucket" || request.URL.Query().Get("prefix") != prefix ||
			request.URL.Query().Get("list-type") != "2" || request.URL.Query().Get("encoding-type") != "url" || request.URL.Query().Get("max-keys") != "1000" {
			t.Errorf("unexpected list request: %s %s", request.Method, request.URL.String())
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		authorization := request.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, "AWS4-HMAC-SHA256 ") || request.Header.Get("X-Amz-Security-Token") != "session" ||
			!strings.Contains(authorization, "x-amz-security-token") {
			t.Errorf("temporary credential was not signature-bound: %#v", request.Header)
		}
		writer.Header().Set("Content-Type", "application/xml")
		switch calls {
		case 1:
			if request.URL.Query().Get("continuation-token") != "" {
				t.Error("first list request carried a continuation token")
			}
			_, _ = io.WriteString(writer, `<ListBucketResult><EncodingType>url</EncodingType><IsTruncated>true</IsTruncated><Contents><Key>repos%2Fprod%2Fa%20file</Key><Size>1</Size><ETag>&quot;a&quot;</ETag></Contents><NextContinuationToken>next+/=</NextContinuationToken></ListBucketResult>`)
		case 2:
			if request.URL.Query().Get("continuation-token") != "next+/=" {
				t.Errorf("opaque continuation token changed: %q", request.URL.Query().Get("continuation-token"))
			}
			_, _ = io.WriteString(writer, `<ListBucketResult><EncodingType>url</EncodingType><IsTruncated>false</IsTruncated><Contents><Key>repos%2Fprod%2Fb%2Fobject</Key><Size>2</Size><ETag>&quot;b&quot;</ETag></Contents></ListBucketResult>`)
		default:
			t.Error("unexpected extra list page")
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Bucket: "bucket", ObjectBaseURL: server.URL + "/bucket", Client: server.Client(), AllowInsecure: true,
		Credentials: S3Credentials{AccessKeyID: "access", SecretAccessKey: "secret", SessionToken: "session", Region: "auto"},
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.ListObjectsV2Prefix(context.Background(), prefix, "")
	if err != nil || len(first.Objects) != 1 || first.Objects[0].Key != "repos/prod/a file" || first.NextContinuationToken != "next+/=" {
		t.Fatalf("first page=%#v err=%v", first, err)
	}
	second, err := client.ListObjectsV2Prefix(context.Background(), prefix, first.NextContinuationToken)
	if err != nil || len(second.Objects) != 1 || second.Objects[0].Key != "repos/prod/b/object" || second.NextContinuationToken != "" || calls != 2 {
		t.Fatalf("second page=%#v calls=%d err=%v", second, calls, err)
	}
}

func TestHeadOpenAndPutUseSignedConditionalWireContract(t *testing.T) {
	body := []byte("object-body")
	digest := sha256.Sum256(body)
	sha := hex.EncodeToString(digest[:])
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/bucket/repos/prod/package.rpm" || !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Errorf("unexpected or unsigned object request: %s %s", request.Method, request.URL.String())
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		switch request.Method {
		case http.MethodHead:
			writer.Header().Set("Content-Length", "11")
			writer.Header().Set("ETag", `"current"`)
			writer.Header().Set("X-Amz-Meta-Sow-Sha256", sha)
			writer.WriteHeader(http.StatusOK)
		case http.MethodGet:
			writer.Header().Set("Content-Length", "11")
			writer.Header().Set("ETag", `"current"`)
			writer.Header().Set("X-Amz-Meta-Sow-Sha256", sha)
			_, _ = writer.Write(body)
		case http.MethodPut:
			data, err := io.ReadAll(request.Body)
			if err != nil || !bytes.Equal(data, body) || request.Header.Get("X-Amz-Content-Sha256") != sha ||
				request.Header.Get("X-Amz-Meta-Sow-Sha256") != sha {
				t.Errorf("invalid put body or digest contract: body=%q headers=%#v err=%v", data, request.Header, err)
			}
			authorization := request.Header.Get("Authorization")
			if !strings.Contains(authorization, "x-amz-meta-sow-sha256") {
				t.Errorf("put metadata was not signature-bound: %q", authorization)
			}
			switch {
			case request.Header.Get("If-None-Match") == "*" && request.Header.Get("If-Match") == "":
				if !strings.Contains(authorization, "if-none-match") {
					t.Errorf("create-only condition was not signature-bound: %q", authorization)
				}
				writer.Header().Set("ETag", `"created"`)
				writer.WriteHeader(http.StatusOK)
			case request.Header.Get("If-Match") == `"wrong"` && request.Header.Get("If-None-Match") == "":
				if !strings.Contains(authorization, "if-match") {
					t.Errorf("compare-and-set condition was not signature-bound: %q", authorization)
				}
				writer.Header().Set("Content-Type", "application/xml")
				writer.WriteHeader(http.StatusPreconditionFailed)
				_, _ = io.WriteString(writer, `<Error><Code>PreconditionFailed</Code><Message>wrong ETag</Message></Error>`)
			default:
				t.Errorf("unexpected put conditions: %#v", request.Header)
				writer.WriteHeader(http.StatusBadRequest)
			}
		default:
			t.Errorf("unexpected object method: %s", request.Method)
			writer.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Bucket: "bucket", ObjectBaseURL: server.URL + "/bucket", Client: server.Client(), AllowInsecure: true,
		Credentials: S3Credentials{AccessKeyID: "access", SecretAccessKey: "secret", Region: "auto"},
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := client.Head(context.Background(), "repos/prod/package.rpm")
	if err != nil || !info.Exists || info.Size != int64(len(body)) || info.SHA256 != sha || info.ETag != `"current"` {
		t.Fatalf("head=%#v err=%v", info, err)
	}
	object, err := client.OpenObject(context.Background(), "repos/prod/package.rpm")
	if err != nil {
		t.Fatal(err)
	}
	opened, readErr := io.ReadAll(object.Body)
	closeErr := object.Body.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(opened, body) || object.Info.SHA256 != sha || object.Info.ETag != `"current"` {
		t.Fatalf("open info=%#v body=%q read=%v close=%v", object.Info, opened, readErr, closeErr)
	}
	created, err := client.Put(context.Background(), "repos/prod/package.rpm", bytes.NewReader(body), int64(len(body)), sha, PutCondition{IfNoneMatch: true})
	if err != nil || created != `"created"` {
		t.Fatalf("create-only put etag=%q err=%v", created, err)
	}
	if _, err := client.Put(context.Background(), "repos/prod/package.rpm", bytes.NewReader(body), int64(len(body)), sha, PutCondition{IfMatch: `"wrong"`}); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong If-Match did not map to ErrConflict: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

type repeatingByteReader struct{}

func (repeatingByteReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = 'x'
	}
	return len(buffer), nil
}

func TestS3SDKHTTPClientRejectsOversizedListResponse(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://example.test/bucket?list-type=2", nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(io.LimitReader(repeatingByteReader{}, maxListResponseSize+1)),
			Request:    request,
		}, nil
	})
	client := &s3SDKHTTPClient{client: &http.Client{Transport: transport}}
	if _, err := client.Do(request); err == nil || !strings.Contains(err.Error(), "exceeds safety limit") {
		t.Fatalf("oversized ListObjectsV2 response error=%v", err)
	}
}

func TestPutOversizedErrorPreservesConflictStatus(t *testing.T) {
	body := []byte("object-body")
	digest := sha256.Sum256(body)
	sha := hex.EncodeToString(digest[:])
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPut {
			t.Errorf("unexpected method: %s", request.Method)
		}
		writer.WriteHeader(http.StatusPreconditionFailed)
		_, _ = io.CopyN(writer, repeatingByteReader{}, maxErrorResponseSize+1)
	}))
	defer server.Close()
	client, err := NewClient(Config{
		Bucket: "bucket", ObjectBaseURL: server.URL + "/bucket", Client: server.Client(), AllowInsecure: true,
		Credentials: S3Credentials{AccessKeyID: "access", SecretAccessKey: "secret", Region: "auto"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Put(context.Background(), "repos/prod/package.rpm", bytes.NewReader(body), int64(len(body)), sha, PutCondition{IfMatch: `"wrong"`}); !errors.Is(err, ErrConflict) {
		t.Fatalf("oversized 412 response lost conflict status: %v", err)
	}
}

func TestListObjectsV2RejectsOutOfPrefixAndWrongDocument(t *testing.T) {
	for name, body := range map[string]string{
		"out-of-prefix": `<ListBucketResult><EncodingType>url</EncodingType><IsTruncated>false</IsTruncated><Contents><Key>other%2Fpackage.rpm</Key><Size>1</Size></Contents></ListBucketResult>`,
		"wrong-root":    `<WrongDocument><EncodingType>url</EncodingType><IsTruncated>false</IsTruncated></WrongDocument>`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(writer, body)
			}))
			defer server.Close()
			client, err := NewClient(Config{
				Bucket: "bucket", ObjectBaseURL: server.URL + "/bucket", Client: server.Client(), AllowInsecure: true,
				Credentials: S3Credentials{AccessKeyID: "access", SecretAccessKey: "secret", Region: "auto"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.ListObjectsV2Prefix(context.Background(), "repos/prod/", ""); err == nil {
				t.Fatal("unsafe provider document was accepted")
			}
		})
	}
}

func TestPutRejectsConflictingConditionsWithoutRequest(t *testing.T) {
	client, err := NewClient(Config{
		Bucket: "bucket", ObjectBaseURL: "https://example.invalid/bucket",
		Credentials: S3Credentials{AccessKeyID: "access", SecretAccessKey: "secret", Region: "auto"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Put(context.Background(), "package.rpm", strings.NewReader("x"), 1, strings.Repeat("a", 64), PutCondition{IfMatch: `"etag"`, IfNoneMatch: true}); err == nil {
		t.Fatal("conflicting conditions were accepted")
	}
}
