package publish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// This digest is intentionally pinned: the integration test is evidence for a
// repeatable S3 protocol fixture, not a floating "latest" container.
const minioCompatibilityImage = "minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e"

func TestMinIOS3Compatibility(t *testing.T) {
	if os.Getenv("SOW_MINIO_TEST") != "1" {
		t.Skip("set SOW_MINIO_TEST=1 to run the pinned real S3-compatible service test")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatalf("SOW_MINIO_TEST=1 requires docker: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	dataRoot := filepath.Join(t.TempDir(), "minio-data")
	if err := os.MkdirAll(filepath.Join(dataRoot, "repo"), 0o755); err != nil {
		t.Fatal(err)
	}
	containerName := fmt.Sprintf("sow-minio-%d", time.Now().UnixNano())
	command := exec.CommandContext(ctx, docker,
		"run", "-d", "--rm", "--name", containerName,
		"-e", "MINIO_ROOT_USER=sowtest",
		"-e", "MINIO_ROOT_PASSWORD=sowtest-secret-key",
		"-e", "MINIO_DOMAIN=localhost",
		"-e", "MINIO_BROWSER=off",
		"-p", "127.0.0.1::9000",
		"--mount", "type=bind,src="+dataRoot+",dst=/data",
		minioCompatibilityImage, "server", "/data", "--address", ":9000", "--console-address", ":9001",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("start pinned MinIO fixture: %v: %s", err, strings.TrimSpace(string(output)))
	}
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer stopCancel()
		_ = exec.CommandContext(stopCtx, docker, "rm", "-f", containerName).Run()
	})

	portOutput, err := exec.CommandContext(ctx, docker, "port", containerName, "9000/tcp").CombinedOutput()
	if err != nil {
		t.Fatalf("discover MinIO port: %v: %s", err, strings.TrimSpace(string(portOutput)))
	}
	address := strings.TrimSpace(string(portOutput))
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("parse MinIO port %q: %v", address, err)
	}
	minioHealth := "http://127.0.0.1:" + port + "/minio/health/ready"
	waitForMinIO(t, ctx, minioHealth)

	var provider *R2CloudflareHTTP
	var purgeCalls atomic.Int64
	edge := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case strings.HasSuffix(request.URL.Path, "/purge_cache"):
			if request.Method != http.MethodPost || request.Header.Get("Authorization") != "Bearer test-token" {
				http.Error(writer, "bad purge request", http.StatusForbidden)
				return
			}
			var body struct {
				Files []string `json:"files"`
			}
			if err := json.NewDecoder(io.LimitReader(request.Body, 1<<20)).Decode(&body); err != nil || len(body.Files) != 1 {
				http.Error(writer, "bad purge closure", http.StatusBadRequest)
				return
			}
			purgeCalls.Add(1)
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"success":true,"errors":[],"messages":[],"result":{"id":"test-zone"}}`)
		case strings.HasPrefix(request.URL.Path, "/cdn/"):
			if provider == nil {
				http.Error(writer, "provider unavailable", http.StatusServiceUnavailable)
				return
			}
			key, err := url.PathUnescape(strings.TrimPrefix(request.URL.EscapedPath(), "/cdn/"))
			if err != nil {
				http.Error(writer, "bad key", http.StatusBadRequest)
				return
			}
			object, err := provider.R2OpenObject(request.Context(), key)
			if errors.Is(err, ErrNotFound) {
				http.NotFound(writer, request)
				return
			}
			if err != nil {
				http.Error(writer, "object read failed", http.StatusBadGateway)
				return
			}
			defer object.Body.Close()
			writer.Header().Set("Content-Length", fmt.Sprintf("%d", object.Info.Size))
			_, _ = io.Copy(writer, object.Body)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer edge.Close()

	transport := edge.Client().Transport.(*http.Transport).Clone()
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, service, splitErr := net.SplitHostPort(address)
		if splitErr == nil && host == "repo.localhost" {
			address = net.JoinHostPort("127.0.0.1", service)
		}
		return dialer.DialContext(ctx, network, address)
	}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Minute}
	t.Cleanup(transport.CloseIdleConnections)
	provider, err = NewR2CloudflareHTTP(R2CloudflareHTTPConfig{
		Bucket:        "repo",
		ObjectBaseURL: "http://repo.localhost:" + port,
		CDNBaseURL:    edge.URL + "/cdn/",
		Credentials: S3Credentials{
			AccessKeyID: "sowtest", SecretAccessKey: "sowtest-secret-key", Region: "us-east-1",
		},
		ZoneID: "test-zone", APIToken: "test-token", CloudflareAPIURL: edge.URL + "/client/v4",
		Client: client, AllowInsecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	root, plan := minioSourcePlan(t, edge.URL+"/cdn/")
	if len(plan.PurgeURLs) != 1 || len(plan.Verify) != len(plan.Objects) {
		t.Fatalf("fixture closure is incomplete: objects=%d purge=%v verify=%d", len(plan.Objects), plan.PurgeURLs, len(plan.Verify))
	}
	request := minioPublishRequest(plan)
	journalDir := filepath.Join(t.TempDir(), "journals")
	publisher := NewR2CloudflarePublisher(provider, DirectorySource{Root: root}, journalDir, Hooks{}).WithWorkers(3)
	first, err := publisher.Run(ctx, request)
	if err != nil || !first.RemoteRefReady || first.Phase != PhaseRemoteRefReady {
		t.Fatalf("real MinIO publication failed: result=%+v err=%v", first, err)
	}
	if purgeCalls.Load() != 1 {
		t.Fatalf("minimal purge calls=%d, want 1; result=%+v purge=%v", purgeCalls.Load(), first, plan.PurgeURLs)
	}
	second, err := publisher.Run(ctx, request)
	if err != nil || !second.RemoteRefReady || second.CheckpointSHA256 != first.CheckpointSHA256 {
		t.Fatalf("real MinIO replay failed: first=%+v second=%+v err=%v", first, second, err)
	}
	if purgeCalls.Load() != 2 {
		t.Fatalf("committed replay did not reissue the exact purge closure: calls=%d", purgeCalls.Load())
	}

	probeBody := []byte("conditional-v1")
	probeSHA := minioDigest(probeBody)
	probeETag, err := provider.R2Put(ctx, "probe/conditional", bytes.NewReader(probeBody), int64(len(probeBody)), probeSHA, R2PutCondition{IfNoneMatch: true})
	if err != nil || probeETag == "" {
		t.Fatalf("create-only PUT failed: etag=%q err=%v", probeETag, err)
	}
	if _, err := provider.R2Put(ctx, "probe/conditional", bytes.NewReader(probeBody), int64(len(probeBody)), probeSHA, R2PutCondition{IfNoneMatch: true}); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("create-only replay did not conflict: %v", err)
	}
	updatedBody := []byte("conditional-v2")
	updatedSHA := minioDigest(updatedBody)
	if _, err := provider.R2Put(ctx, "probe/conditional", bytes.NewReader(updatedBody), int64(len(updatedBody)), updatedSHA, R2PutCondition{IfMatch: `"wrong"`}); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong If-Match did not conflict: %v", err)
	}
	updatedETag, err := provider.R2Put(ctx, "probe/conditional", bytes.NewReader(updatedBody), int64(len(updatedBody)), updatedSHA, R2PutCondition{IfMatch: probeETag})
	if err != nil || updatedETag == "" || updatedETag == probeETag {
		t.Fatalf("conditional update failed: old=%q new=%q err=%v", probeETag, updatedETag, err)
	}

	info, err := provider.R2Head(ctx, "probe/conditional")
	if err != nil || !info.Exists || info.Size != int64(len(updatedBody)) || info.SHA256 != updatedSHA || info.ETag != updatedETag {
		t.Fatalf("HEAD metadata mismatch: info=%+v err=%v", info, err)
	}
	copyETag, err := provider.R2Copy(ctx, "probe/copied", "probe/conditional", int64(len(updatedBody)), updatedSHA, updatedETag)
	if err != nil || copyETag == "" {
		t.Fatalf("server-side CopyObject failed: etag=%q err=%v", copyETag, err)
	}
	copied, err := provider.R2Head(ctx, "probe/copied")
	if err != nil || !copied.Exists || copied.Size != int64(len(updatedBody)) || copied.SHA256 != updatedSHA {
		t.Fatalf("copied object metadata mismatch: info=%+v err=%v", copied, err)
	}
	opened, err := provider.R2OpenObject(ctx, "probe/copied")
	if err != nil {
		t.Fatal(err)
	}
	readBack, readErr := io.ReadAll(opened.Body)
	closeErr := opened.Body.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(readBack, updatedBody) {
		t.Fatalf("streamed GET mismatch: bytes=%q read=%v close=%v", readBack, readErr, closeErr)
	}

	page, err := provider.R2ListObjectsV2(ctx, "")
	if err != nil || len(page.Objects) < 7 || page.NextContinuationToken != "" {
		t.Fatalf("ListObjectsV2 mismatch: objects=%d next=%q err=%v", len(page.Objects), page.NextContinuationToken, err)
	}
	// The pinned MinIO build accepts If-Match on DELETE but ignores it. Keep
	// this real-service negative evidence: the product-level capability probe
	// must detect the behavior and fail before deleting a live serving object.
	if err := provider.R2Delete(ctx, "probe/copied", `"wrong-delete-etag"`); err != nil {
		t.Fatalf("pinned MinIO conditional-delete behavior changed: %v", err)
	}
	if afterDelete, err := provider.R2Head(ctx, "probe/copied"); err != nil || afterDelete.Exists {
		t.Fatalf("pinned MinIO no longer demonstrates ignored If-Match: info=%+v err=%v", afterDelete, err)
	}
	probePublisher := NewR2CloudflarePublisher(provider, DirectorySource{Root: t.TempDir()}, filepath.Join(t.TempDir(), "journal"), Hooks{})
	if err := probePublisher.probeConditionalDelete(ctx, "minio-conditional-delete-capability"); !errors.Is(err, ErrCapability) {
		t.Fatalf("product did not fail closed on ignored conditional DeleteObject: %v", err)
	}
}

func waitForMinIO(t *testing.T, ctx context.Context, healthURL string) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		response, err := client.Do(request)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for MinIO: %v", ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
	t.Fatal("MinIO readiness deadline exceeded")
}

func minioSourcePlan(t *testing.T, cdnBase string) (string, Plan) {
	t.Helper()
	root := t.TempDir()
	fixtures := []struct {
		path  string
		body  string
		class ObjectClass
	}{
		{path: "pool/a.pkg", body: "immutable", class: ObjectImmutable},
		{path: "metadata/index", body: "metadata", class: ObjectMetadata},
		{path: "dists/jammy/InRelease", body: "pointer", class: ObjectPointer},
	}
	plan := Plan{Schema: planSchema}
	for _, fixture := range fixtures {
		filename := filepath.Join(root, filepath.FromSlash(fixture.path))
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			t.Fatal(err)
		}
		body := []byte(fixture.body)
		if err := os.WriteFile(filename, body, 0o644); err != nil {
			t.Fatal(err)
		}
		plan.Objects = append(plan.Objects, PlannedObject{
			SourcePath: fixture.path, RemoteKey: fixture.path, Size: int64(len(body)),
			SHA256: minioDigest(body), Class: fixture.class,
		})
	}
	plan, err := plan.WithCDN(cdnBase)
	if err != nil {
		t.Fatal(err)
	}
	return root, plan
}

func minioPublishRequest(plan Plan) Request {
	return Request{
		TransactionID: "minio-real-s3",
		Plan:          plan,
		Generation: TargetGeneration{
			Schema: TargetGenerationSchema, Target: TargetCloudflare, Generation: 1,
			DesiredCommit: strings.Repeat("a", 40), IntentView: "latest",
			ConfigSHA256: strings.Repeat("b", 64),
			Refs: []RefState{{
				Name: "refs/sow/views/latest/assets/all/all", Commit: strings.Repeat("c", 40), ManifestSHA256: strings.Repeat("d", 64),
			}},
			ContentManifestSHA256: strings.Repeat("e", 64),
		},
		UpdatedAt: time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC),
	}
}

func minioDigest(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}
