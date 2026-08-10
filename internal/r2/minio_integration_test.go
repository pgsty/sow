package r2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This digest is pinned so the integration gate is a repeatable protocol
// fixture rather than an implicit dependency on a floating container tag.
const minioCompatibilityImage = "minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e"

func TestMinIOS3Compatibility(t *testing.T) {
	if os.Getenv("SOW_MINIO_TEST") != "1" {
		t.Skip("set SOW_MINIO_TEST=1 to run the pinned S3-compatible service test")
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
	container := fmt.Sprintf("sow-minio-%d", time.Now().UnixNano())
	command := exec.CommandContext(ctx, docker,
		"run", "-d", "--rm", "--name", container,
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"-e", "MINIO_ROOT_USER=sowtest",
		"-e", "MINIO_ROOT_PASSWORD=sowtest-secret-key",
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
		_ = exec.CommandContext(stopCtx, docker, "rm", "-f", container).Run()
	})
	portOutput, err := exec.CommandContext(ctx, docker, "port", container, "9000/tcp").CombinedOutput()
	if err != nil {
		t.Fatalf("discover MinIO port: %v: %s", err, strings.TrimSpace(string(portOutput)))
	}
	_, port, err := net.SplitHostPort(strings.TrimSpace(string(portOutput)))
	if err != nil {
		t.Fatal(err)
	}
	waitForMinIO(t, ctx, "http://127.0.0.1:"+port+"/minio/health/ready")
	client, err := NewClient(Config{
		Bucket: "repo", ObjectBaseURL: "http://127.0.0.1:" + port + "/repo", AllowInsecure: true,
		Credentials: S3Credentials{AccessKeyID: "sowtest", SecretAccessKey: "sowtest-secret-key", Region: "us-east-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	waitForR2(t, ctx, client)
	body := []byte("conditional-v1")
	sha := digestBytes(body)
	etag, err := client.Put(ctx, "repos/prod/package.rpm", bytes.NewReader(body), int64(len(body)), sha, PutCondition{IfNoneMatch: true})
	if err != nil || etag == "" {
		t.Fatalf("create-only put: etag=%q err=%v", etag, err)
	}
	if _, err := client.Put(ctx, "repos/prod/package.rpm", bytes.NewReader(body), int64(len(body)), sha, PutCondition{IfNoneMatch: true}); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("create-only replay did not conflict: %v", err)
	}
	updated := []byte("conditional-v2")
	updatedSHA := digestBytes(updated)
	if _, err := client.Put(ctx, "repos/prod/package.rpm", bytes.NewReader(updated), int64(len(updated)), updatedSHA, PutCondition{IfMatch: `"wrong"`}); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong If-Match did not conflict: %v", err)
	}
	updatedETag, err := client.Put(ctx, "repos/prod/package.rpm", bytes.NewReader(updated), int64(len(updated)), updatedSHA, PutCondition{IfMatch: etag})
	if err != nil || updatedETag == "" || updatedETag == etag {
		t.Fatalf("conditional update: old=%q new=%q err=%v", etag, updatedETag, err)
	}
	info, err := client.Head(ctx, "repos/prod/package.rpm")
	if err != nil || !info.Exists || info.Size != int64(len(updated)) || info.SHA256 != updatedSHA || info.ETag != updatedETag {
		t.Fatalf("head=%#v err=%v", info, err)
	}
	object, err := client.OpenObject(ctx, "repos/prod/package.rpm")
	if err != nil {
		t.Fatal(err)
	}
	readBack, readErr := io.ReadAll(object.Body)
	closeErr := object.Body.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(readBack, updated) {
		t.Fatalf("open mismatch: %q read=%v close=%v", readBack, readErr, closeErr)
	}
	page, err := client.ListObjectsV2Prefix(ctx, "repos/prod/", "")
	if err != nil || len(page.Objects) != 1 || page.Objects[0].Key != "repos/prod/package.rpm" {
		t.Fatalf("list=%#v err=%v", page, err)
	}
}

func digestBytes(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
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

func waitForR2(t *testing.T, ctx context.Context, client *Client) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := client.ListObjectsV2Prefix(ctx, "", ""); err == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for MinIO object API: %v", ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
	t.Fatal("MinIO object API readiness deadline exceeded")
}
