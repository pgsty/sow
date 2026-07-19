package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pub "github.com/pgsty/sow/internal/publish"
)

func TestRestoreAuditDecoderRequiresCanonicalContentBoundRecord(t *testing.T) {
	record := restoreAuditRecord{
		Schema: restoreAuditSchema, Target: "cf", Generation: 3, SourceGeneration: 1,
		SourceGenerationSHA256: strings.Repeat("a", 64), SourcePlanSHA256: strings.Repeat("b", 64),
		SourceStateCommit: strings.Repeat("c", 40), IntentView: "beta",
		TransactionID: "sow-restore-cf-00000000000000000003-from-00000000000000000001-head-" + strings.Repeat("d", 40) + "-0123456789abcdef",
		Refs: []pub.RefState{{
			Name: "refs/sow/views/beta/assets/all/all", Commit: strings.Repeat("e", 40), ManifestSHA256: strings.Repeat("f", 64),
		}},
	}
	body, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeRestoreAudit(body)
	if err != nil || decoded.TransactionID != record.TransactionID {
		t.Fatalf("canonical restore audit rejected: record=%+v err=%v", decoded, err)
	}
	tests := []struct {
		name string
		body []byte
		want string
	}{
		{"outer-whitespace", append(append([]byte(nil), body...), '\n'), "not canonical JSON"},
		{"unknown-field", append(append([]byte(nil), body[:len(body)-1]...), []byte(`,"extra":true}`)...), "unknown field"},
	}
	wrongTransaction := record
	wrongTransaction.TransactionID = strings.Replace(record.TransactionID, "from-00000000000000000001", "from-00000000000000000002", 1)
	wrongBody, err := json.Marshal(wrongTransaction)
	if err != nil {
		t.Fatal(err)
	}
	tests = append(tests, struct {
		name string
		body []byte
		want string
	}{"wrong-source-transaction", wrongBody, "does not bind"})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodeRestoreAudit(test.body); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("restore audit mutation accepted or wrong error: %v", err)
			}
		})
	}
}

func TestCleanupStaleRestoreMaterializationsPreservesServingTrees(t *testing.T) {
	root := nginxWorkerTempDir(t)
	stale := filepath.Join(root, ".sow", "materialized", "restores", "cf", "00000000000000000001", "beta", "pkg", "latest")
	serving := filepath.Join(root, ".sow", "materialized", "beta", "pkg", "latest")
	for filename, body := range map[string]string{stale: "historical", serving: "current"} {
		if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	removed, err := cleanupStaleRestoreMaterializations(root)
	if err != nil || !removed {
		t.Fatalf("cleanup removed=%t err=%v", removed, err)
	}
	if _, err := os.Lstat(filepath.Join(root, ".sow", "materialized", "restores")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale restore namespace still exists: %v", err)
	}
	if body, err := os.ReadFile(serving); err != nil || string(body) != "current" {
		t.Fatalf("cleanup changed serving tree body=%q err=%v", body, err)
	}
	removed, err = cleanupStaleRestoreMaterializations(root)
	if err != nil || removed {
		t.Fatalf("idempotent cleanup removed=%t err=%v", removed, err)
	}
}

func TestCleanupStaleRestoreMaterializationsRejectsSymlink(t *testing.T) {
	root := nginxWorkerTempDir(t)
	target := t.TempDir()
	marker := filepath.Join(target, "must-survive")
	if err := os.WriteFile(marker, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	materialized := filepath.Join(root, ".sow", "materialized")
	if err := os.MkdirAll(materialized, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(materialized, "restores")); err != nil {
		t.Fatal(err)
	}
	removed, err := cleanupStaleRestoreMaterializations(root)
	if err == nil || removed || !strings.Contains(err.Error(), "unsafe restore materialization namespace") {
		t.Fatalf("symlink cleanup removed=%t err=%v", removed, err)
	}
	if body, err := os.ReadFile(marker); err != nil || string(body) != "outside" {
		t.Fatalf("cleanup followed symlink body=%q err=%v", body, err)
	}
}

func TestPublishStartupCleansStaleRestoreMaterializations(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "release.txt")
	if err := os.WriteFile(input, []byte("release\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })

	var stdout, stderr bytes.Buffer
	if code := Main([]string{"add", input, "--config", configPath, "--repo", "assets", "--dest", "latest"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("add code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	stale := filepath.Join(root, ".sow", "materialized", "restores", "cf", "00000000000000000009", "beta", "pkg", "latest")
	if err := os.MkdirAll(filepath.Dir(stale), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("interrupted"), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	code := Main([]string{"publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"}, &stdout, &stderr)
	if code != ExitOK || !strings.Contains(stdout.String(), "recovery stale_restore_materializations=removed") {
		t.Fatalf("publish code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Lstat(filepath.Join(root, ".sow", "materialized", "restores")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("publish startup retained stale restore namespace: %v", err)
	}
}
