package r2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// TestCloudflareR2ReadOnlyCompatibility is an explicit, read-only hosted
// provider gate. It never writes or deletes an object: operators point it at a
// dedicated immutable fixture whose body and sow-sha256 metadata are known.
func TestCloudflareR2ReadOnlyCompatibility(t *testing.T) {
	if os.Getenv("SOW_REAL_R2_TEST") != "1" {
		t.Skip("set SOW_REAL_R2_TEST=1 and the SOW_REAL_R2_* fixture variables")
	}
	endpoint := requiredR2TestEnvironment(t, "SOW_REAL_R2_ENDPOINT")
	bucket := requiredR2TestEnvironment(t, "SOW_REAL_R2_BUCKET")
	prefix := requiredR2TestEnvironment(t, "SOW_REAL_R2_PREFIX")
	key := requiredR2TestEnvironment(t, "SOW_REAL_R2_OBJECT_KEY")
	wantSHA := requiredR2TestEnvironment(t, "SOW_REAL_R2_OBJECT_SHA256")
	accessKey := requiredR2TestEnvironment(t, "SOW_REAL_R2_ACCESS_KEY_ID")
	secretKey := requiredR2TestEnvironment(t, "SOW_REAL_R2_SECRET_ACCESS_KEY")
	if !strings.HasSuffix(prefix, "/") || !strings.HasPrefix(key, prefix) || !hexSHA256Pattern.MatchString(wantSHA) {
		t.Fatal("SOW_REAL_R2_PREFIX, object key, and expected SHA256 do not describe one canonical fixture")
	}
	region := os.Getenv("SOW_REAL_R2_REGION")
	if region == "" {
		region = "auto"
	}
	client, err := NewClient(Config{
		Bucket: bucket, ObjectBaseURL: strings.TrimSuffix(endpoint, "/") + "/" + bucket,
		Credentials: S3Credentials{
			AccessKeyID: accessKey, SecretAccessKey: secretKey,
			SessionToken: os.Getenv("SOW_REAL_R2_SESSION_TOKEN"), Region: region,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	found := false
	continuation := ""
	seenTokens := map[string]struct{}{}
	for pageNumber := 0; pageNumber < 100; pageNumber++ {
		page, err := client.ListObjectsV2Prefix(ctx, prefix, continuation)
		if err != nil {
			t.Fatal(err)
		}
		for _, object := range page.Objects {
			if object.Key == key {
				found = true
			}
		}
		if page.NextContinuationToken == "" {
			break
		}
		if _, duplicate := seenTokens[page.NextContinuationToken]; duplicate {
			t.Fatal("Cloudflare R2 repeated a continuation token")
		}
		seenTokens[page.NextContinuationToken] = struct{}{}
		continuation = page.NextContinuationToken
	}
	if !found {
		t.Fatalf("Cloudflare R2 fixture %q was not found within 100 bounded pages", key)
	}
	info, err := client.Head(ctx, key)
	if err != nil || !info.Exists || info.Size < 0 || info.SHA256 != wantSHA || info.ETag == "" {
		t.Fatalf("Cloudflare R2 HEAD evidence differs: exists=%t size=%d sha=%q etag-present=%t err=%v", info.Exists, info.Size, info.SHA256, info.ETag != "", err)
	}
	object, err := client.OpenObject(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	size, readErr := io.Copy(hash, io.LimitReader(object.Body, info.Size+1))
	closeErr := object.Body.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		t.Fatal(err)
	}
	if size != info.Size || hex.EncodeToString(hash.Sum(nil)) != wantSHA || object.Info.Size != info.Size || object.Info.SHA256 != wantSHA || object.Info.ETag != info.ETag {
		t.Fatalf("Cloudflare R2 GET evidence differs: size=%d want=%d sha=%q", size, info.Size, hex.EncodeToString(hash.Sum(nil)))
	}
}

func requiredR2TestEnvironment(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required when SOW_REAL_R2_TEST=1", name)
	}
	return value
}
