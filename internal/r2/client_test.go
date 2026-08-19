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
	"strconv"
	"strings"
	"testing"
	"time"
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

func TestDefaultTransportUsesPhaseTimeoutsWithoutWholeRequestDeadline(t *testing.T) {
	client := cloneNoRedirectClient(nil)
	if client.Timeout != 0 {
		t.Fatalf("default R2 client retained whole-request timeout %s", client.Timeout)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.ResponseHeaderTimeout != responseHeaderLimit || transport.TLSHandshakeTimeout == 0 {
		t.Fatalf("default R2 transport=%#v", client.Transport)
	}
}

func TestR2ReadAndWriteRetryTransientServiceErrors(t *testing.T) {
	t.Run("head", func(t *testing.T) {
		calls := 0
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			calls++
			if request.Method != http.MethodHead || request.URL.Path != "/bucket/object" {
				t.Errorf("unexpected HEAD request: %s %s", request.Method, request.URL.String())
			}
			if calls < 3 {
				writer.Header().Set("Content-Type", "application/xml")
				writer.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(writer, `<Error><Code>SlowDown</Code><Message>retry</Message></Error>`)
				return
			}
			writer.Header().Set("Content-Length", "7")
			writer.Header().Set("ETag", `"head-etag"`)
			writer.Header().Set("x-amz-meta-sow-sha256", strings.Repeat("a", 64))
		}))
		defer server.Close()
		client, err := NewClient(Config{
			Bucket: "bucket", ObjectBaseURL: server.URL + "/bucket", Client: server.Client(), AllowInsecure: true,
			Credentials: S3Credentials{AccessKeyID: "access", SecretAccessKey: "secret", Region: "auto"},
		})
		if err != nil {
			t.Fatal(err)
		}
		info, err := client.Head(context.Background(), "object")
		if err != nil || !info.Exists || info.Size != 7 || calls != 3 {
			t.Fatalf("retried HEAD info=%#v calls=%d err=%v", info, calls, err)
		}
	})

	t.Run("put", func(t *testing.T) {
		body := []byte("replayable conditional body")
		digest := sha256.Sum256(body)
		sha := hex.EncodeToString(digest[:])
		calls := 0
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			calls++
			if request.Header.Get("Cache-Control") != "public, max-age=60" {
				t.Errorf("PUT Cache-Control=%q", request.Header.Get("Cache-Control"))
			}
			got, err := io.ReadAll(request.Body)
			if err != nil || !bytes.Equal(got, body) {
				t.Errorf("PUT body=%q err=%v", got, err)
			}
			if calls == 1 {
				writer.Header().Set("Content-Type", "application/xml")
				writer.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(writer, `<Error><Code>SlowDown</Code><Message>retry</Message></Error>`)
				return
			}
			writer.Header().Set("ETag", `"put-etag"`)
		}))
		defer server.Close()
		client, err := NewClient(Config{
			Bucket: "bucket", ObjectBaseURL: server.URL + "/bucket", Client: server.Client(), AllowInsecure: true,
			Credentials: S3Credentials{AccessKeyID: "access", SecretAccessKey: "secret", Region: "auto"},
		})
		if err != nil {
			t.Fatal(err)
		}
		etag, err := client.Put(context.Background(), "object", bytes.NewReader(body), int64(len(body)), sha, PutCondition{IfNoneMatch: true, CacheControl: "public, max-age=60"})
		if err != nil || etag != `"put-etag"` || calls != 2 {
			t.Fatalf("retried PUT etag=%q calls=%d err=%v", etag, calls, err)
		}
	})
}

func TestMultipartPutUsesBoundedReplayablePartsAndConditionalComplete(t *testing.T) {
	body := []byte("abcdefghijkl")
	digest := sha256.Sum256(body)
	sha := hex.EncodeToString(digest[:])
	parts := map[int][]byte{}
	completed := false
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		query := request.URL.Query()
		switch {
		case request.Method == http.MethodPost && query.Has("uploads"):
			if request.Header.Get("x-amz-meta-sow-sha256") != sha {
				t.Errorf("multipart create metadata=%q", request.Header.Get("x-amz-meta-sow-sha256"))
			}
			if request.Header.Get("Cache-Control") != "no-cache, must-revalidate" {
				t.Errorf("multipart create Cache-Control=%q", request.Header.Get("Cache-Control"))
			}
			writer.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(writer, `<InitiateMultipartUploadResult><Bucket>bucket</Bucket><Key>object</Key><UploadId>upload-1</UploadId></InitiateMultipartUploadResult>`)
		case request.Method == http.MethodPut && query.Get("uploadId") == "upload-1":
			partNumber, err := strconv.Atoi(query.Get("partNumber"))
			if err != nil {
				t.Error(err)
			}
			parts[partNumber], _ = io.ReadAll(request.Body)
			writer.Header().Set("ETag", `"part-`+strconv.Itoa(partNumber)+`"`)
		case request.Method == http.MethodPost && query.Get("uploadId") == "upload-1":
			if request.Header.Get("If-None-Match") != "*" {
				t.Errorf("multipart complete If-None-Match=%q", request.Header.Get("If-None-Match"))
			}
			completed = true
			writer.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(writer, `<CompleteMultipartUploadResult><Bucket>bucket</Bucket><Key>object</Key><ETag>&quot;complete-etag&quot;</ETag></CompleteMultipartUploadResult>`)
		default:
			t.Errorf("unexpected multipart request: %s %s", request.Method, request.URL.String())
			writer.WriteHeader(http.StatusBadRequest)
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
	client.objects.multipartThreshold = 4
	client.objects.multipartMinPartSize = 5
	client.objects.noProgressTimeout = time.Second
	etag, err := client.Put(context.Background(), "object", bytes.NewReader(body), int64(len(body)), sha, PutCondition{IfNoneMatch: true, CacheControl: "no-cache, must-revalidate"})
	if err != nil || etag != `"complete-etag"` || !completed || !bytes.Equal(parts[1], body[:5]) || !bytes.Equal(parts[2], body[5:10]) || !bytes.Equal(parts[3], body[10:]) {
		t.Fatalf("multipart etag=%q completed=%t parts=%v err=%v", etag, completed, parts, err)
	}
	partSize, err := multipartPartSize(maximumMultipartSize, defaultPartSize)
	if err != nil || partSize > maximumPartSize || (maximumMultipartSize+partSize-1)/partSize > maximumParts {
		t.Fatalf("maximum multipart partSize=%d err=%v", partSize, err)
	}
}

func TestMultipartConditionalFailureAbortsUpload(t *testing.T) {
	body := []byte("multipart-conflict")
	digest := sha256.Sum256(body)
	sha := hex.EncodeToString(digest[:])
	aborted := false
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		query := request.URL.Query()
		switch {
		case request.Method == http.MethodPost && query.Has("uploads"):
			writer.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(writer, `<InitiateMultipartUploadResult><Bucket>bucket</Bucket><Key>object</Key><UploadId>upload-conflict</UploadId></InitiateMultipartUploadResult>`)
		case request.Method == http.MethodPut && query.Get("uploadId") == "upload-conflict":
			_, _ = io.Copy(io.Discard, request.Body)
			writer.Header().Set("ETag", `"part"`)
		case request.Method == http.MethodPost && query.Get("uploadId") == "upload-conflict":
			writer.Header().Set("Content-Type", "application/xml")
			writer.WriteHeader(http.StatusPreconditionFailed)
			_, _ = io.WriteString(writer, `<Error><Code>PreconditionFailed</Code><Message>exists</Message></Error>`)
		case request.Method == http.MethodDelete && query.Get("uploadId") == "upload-conflict":
			aborted = true
			writer.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected multipart conflict request: %s %s", request.Method, request.URL.String())
			writer.WriteHeader(http.StatusBadRequest)
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
	client.objects.multipartThreshold = 4
	client.objects.multipartMinPartSize = 5
	_, err = client.Put(context.Background(), "object", bytes.NewReader(body), int64(len(body)), sha, PutCondition{IfNoneMatch: true})
	if !errors.Is(err, ErrAlreadyExists) || !aborted {
		t.Fatalf("multipart conflict err=%v aborted=%t", err, aborted)
	}
}

func TestUploadProgressMonitorCancelsAnIdleBody(t *testing.T) {
	ctx, _, finish := monitorUploadProgress(context.Background(), bytes.NewReader([]byte("body")), 20*time.Millisecond)
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("idle upload monitor did not cancel")
	}
	if err := finish(); !errors.Is(err, errUploadNoProgress) {
		t.Fatalf("idle upload finish error=%v", err)
	}
}

func TestReadProgressMonitorBoundsOnlyIdleTime(t *testing.T) {
	t.Run("idle", func(t *testing.T) {
		reader, writer := io.Pipe()
		defer writer.Close()
		monitored := NewIdleReadCloser(context.Background(), reader, 20*time.Millisecond)
		_, readErr := monitored.Read(make([]byte, 1))
		closeErr := monitored.Close()
		if !errors.Is(readErr, ErrReadNoProgress) || !errors.Is(closeErr, ErrReadNoProgress) {
			t.Fatalf("idle read=%v close=%v", readErr, closeErr)
		}
	})

	t.Run("healthy slow stream", func(t *testing.T) {
		reader, writer := io.Pipe()
		go func() {
			defer writer.Close()
			for _, value := range []byte("healthy") {
				time.Sleep(5 * time.Millisecond)
				_, _ = writer.Write([]byte{value})
			}
		}()
		monitored := NewIdleReadCloser(context.Background(), reader, 20*time.Millisecond)
		body, readErr := io.ReadAll(monitored)
		closeErr := monitored.Close()
		if readErr != nil || closeErr != nil || string(body) != "healthy" {
			t.Fatalf("slow body=%q read=%v close=%v", body, readErr, closeErr)
		}
	})
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
