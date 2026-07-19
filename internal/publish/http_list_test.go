package publish

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestR2AndCOSListObjectsV2UseSignedOpaquePagination(t *testing.T) {
	for _, providerName := range []string{"r2", "cos"} {
		providerName := providerName
		t.Run(providerName, func(t *testing.T) {
			t.Parallel()
			var calls int
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				calls++
				if request.Method != http.MethodGet || request.URL.Path != "/bucket" || request.URL.Query().Get("list-type") != "2" || request.URL.Query().Get("encoding-type") != "url" || request.URL.Query().Get("max-keys") != "1000" {
					t.Errorf("unexpected list request: %s %s", request.Method, request.URL.String())
					writer.WriteHeader(http.StatusBadRequest)
					return
				}
				if !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
					t.Error("ListObjectsV2 request was not SigV4 signed")
				}
				if providerName == "cos" && (request.Header.Get("X-Cos-Security-Token") != "cos-session-token" ||
					request.Header.Get("X-Amz-Security-Token") != "" || !strings.Contains(request.Header.Get("Authorization"), "x-cos-security-token")) {
					t.Error("COS ListObjectsV2 temporary credential token was not projected and signature-bound")
				}
				if providerName == "r2" && (request.Header.Get("X-Amz-Security-Token") != "r2-session-token" ||
					request.Header.Get("X-Cos-Security-Token") != "" || !strings.Contains(request.Header.Get("Authorization"), "x-amz-security-token")) {
					t.Error("R2 ListObjectsV2 temporary credential token lost standard S3 signing")
				}
				writer.Header().Set("Content-Type", "application/xml")
				switch calls {
				case 1:
					if request.URL.Query().Get("continuation-token") != "" {
						t.Error("first list request carried a continuation token")
					}
					_, _ = io.WriteString(writer, `<ListBucketResult><EncodingType>url</EncodingType><IsTruncated>true</IsTruncated><Contents><Key>a%20file</Key><Size>1</Size><ETag>&quot;a&quot;</ETag></Contents><NextContinuationToken>next+/=</NextContinuationToken></ListBucketResult>`)
				case 2:
					if request.URL.Query().Get("continuation-token") != "next+/=" {
						t.Errorf("opaque continuation token changed: %q", request.URL.Query().Get("continuation-token"))
					}
					_, _ = io.WriteString(writer, `<ListBucketResult><EncodingType>url</EncodingType><IsTruncated>false</IsTruncated><Contents><Key>b%2Fobject</Key><Size>2</Size><ETag>&quot;b&quot;</ETag></Contents></ListBucketResult>`)
				default:
					t.Error("unexpected extra list page")
				}
			}))
			defer server.Close()

			var list func(context.Context, string) (ObjectListPage, error)
			if providerName == "r2" {
				provider, err := NewR2CloudflareHTTP(R2CloudflareHTTPConfig{
					ObjectBaseURL: server.URL + "/bucket", CDNBaseURL: "https://cdn.test/",
					Credentials: S3Credentials{AccessKeyID: "id", SecretAccessKey: "secret", SessionToken: "r2-session-token", Region: "auto"},
					ZoneID:      "zone", APIToken: "token", CloudflareAPIURL: server.URL,
					Client: server.Client(), AllowInsecure: true,
				})
				if err != nil {
					t.Fatal(err)
				}
				list = provider.R2ListObjectsV2
			} else {
				provider, err := NewCOSEdgeOneHTTP(COSEdgeOneHTTPConfig{
					ObjectBaseURL: server.URL + "/bucket", CDNBaseURL: "https://cdn.test/",
					ObjectCredentials:  S3Credentials{AccessKeyID: "id", SecretAccessKey: "secret", SessionToken: "cos-session-token", Region: "ap-shanghai"},
					TencentCredentials: TencentCredentials{SecretID: "tc-id", SecretKey: "tc-secret"},
					ZoneID:             "zone", EdgeOneAPIURL: server.URL, Client: server.Client(), AllowInsecure: true,
					UnversionedBucketConfirmed: true,
				})
				if err != nil {
					t.Fatal(err)
				}
				list = provider.COSListObjectsV2
			}

			first, err := list(context.Background(), "")
			if err != nil || len(first.Objects) != 1 || first.Objects[0].Key != "a file" || first.NextContinuationToken != "next+/=" {
				t.Fatalf("first page=%+v err=%v", first, err)
			}
			second, err := list(context.Background(), first.NextContinuationToken)
			if err != nil || len(second.Objects) != 1 || second.Objects[0].Key != "b/object" || second.NextContinuationToken != "" {
				t.Fatalf("second page=%+v err=%v", second, err)
			}
			if calls != 2 {
				t.Fatalf("list calls=%d", calls)
			}
		})
	}
}

func TestR2AndCOSListObjectsV2PrefixIsSignedAndProviderConfined(t *testing.T) {
	const prefix = "sow-provider-logs/cloudflare/real-edge-test-run-20260714/"
	for _, providerName := range []string{"r2", "cos"} {
		providerName := providerName
		t.Run(providerName, func(t *testing.T) {
			var calls int
			outOfPrefix := false
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				calls++
				if request.Method != http.MethodGet || request.URL.Path != "/bucket" || request.URL.Query().Get("prefix") != prefix ||
					request.URL.Query().Get("list-type") != "2" || request.URL.Query().Get("encoding-type") != "url" ||
					request.URL.Query().Get("max-keys") != "1000" || !strings.HasPrefix(request.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
					t.Errorf("prefix inventory request was not exact and signed: %s %s", request.Method, request.URL.String())
					writer.WriteHeader(http.StatusBadRequest)
					return
				}
				key := prefix + "part-0001.jsonl"
				if outOfPrefix {
					key = "sow-provider-logs/historical-run/part-0001.jsonl"
				}
				writer.Header().Set("Content-Type", "application/xml")
				_, _ = io.WriteString(writer, `<ListBucketResult><EncodingType>url</EncodingType><IsTruncated>false</IsTruncated><Contents><Key>`+
					url.PathEscape(key)+`</Key><Size>7</Size><ETag>&quot;etag&quot;</ETag></Contents></ListBucketResult>`)
			}))
			defer server.Close()

			var list func(context.Context, string, string) (ObjectListPage, error)
			if providerName == "r2" {
				provider, err := NewR2CloudflareHTTP(R2CloudflareHTTPConfig{
					ObjectBaseURL: server.URL + "/bucket", CDNBaseURL: "https://cdn.test/",
					Credentials: S3Credentials{AccessKeyID: "id", SecretAccessKey: "secret", Region: "auto"},
					ZoneID:      "zone", APIToken: "token", Client: server.Client(), AllowInsecure: true,
				})
				if err != nil {
					t.Fatal(err)
				}
				list = provider.R2ListObjectsV2Prefix
			} else {
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
				list = provider.COSListObjectsV2Prefix
			}

			page, err := list(context.Background(), prefix, "")
			if err != nil || len(page.Objects) != 1 || page.Objects[0].Key != prefix+"part-0001.jsonl" {
				t.Fatalf("exact prefix inventory page=%+v err=%v", page, err)
			}
			outOfPrefix = true
			if _, err := list(context.Background(), prefix, ""); err == nil || !strings.Contains(err.Error(), "unsafe object key") {
				t.Fatalf("provider object outside signed prefix was accepted: %v", err)
			}
			before := calls
			if _, err := list(context.Background(), "../unsafe/", ""); err == nil || calls != before {
				t.Fatalf("unsafe prefix reached provider: calls=%d before=%d err=%v", calls, before, err)
			}
		})
	}
}

func TestListObjectsV2RejectsUnsafeOrUnboundedProviderDocuments(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		`<ListBucketResult><EncodingType>url</EncodingType><IsTruncated>true</IsTruncated></ListBucketResult>`,
		`<ListBucketResult><EncodingType>url</EncodingType><IsTruncated>false</IsTruncated><Contents><Key>../escape</Key><Size>1</Size></Contents></ListBucketResult>`,
		`<WrongDocument><EncodingType>url</EncodingType><IsTruncated>false</IsTruncated></WrongDocument>`,
	} {
		body := body
		t.Run(fmt.Sprintf("case-%d", len(body)), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(writer, body) }))
			defer server.Close()
			provider, err := NewR2CloudflareHTTP(R2CloudflareHTTPConfig{
				ObjectBaseURL: server.URL + "/bucket", CDNBaseURL: "https://cdn.test/",
				Credentials: S3Credentials{AccessKeyID: "id", SecretAccessKey: "secret", Region: "auto"},
				ZoneID:      "zone", APIToken: "token", Client: server.Client(), AllowInsecure: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := provider.R2ListObjectsV2(context.Background(), ""); err == nil {
				t.Fatal("unsafe ListObjectsV2 document was accepted")
			} else if strings.Contains(err.Error(), "escape") {
				t.Fatalf("unsafe remote key leaked through provider error: %v", err)
			}
		})
	}
}
