package cli

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFSCKRemoteAdoptionProjectsAssetPhysicalPathButKeepsSourceContent(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	configText := strings.Replace(publishAssetConfig,
		"    path: pkg\n    default_pool: public\n    asset:\n      kind: release",
		"    path: asset/bootstrap\n    default_pool: public\n    asset:\n      kind: bootstrap\n      public_path: pkg", 1)
	if configText == publishAssetConfig {
		t.Fatal("asset projection fixture replacement did not match")
	}
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"local-fake","secret_access_key":"local-fake"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"local-fake"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(arguments ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(arguments, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	input := filepath.Join(root, "release.bin")
	payload := []byte("projected legacy payload\n")
	if err := os.WriteFile(input, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range [][]string{
		{"add", input, "--config", configPath, "--repo", "assets", "--dest", "release.bin"},
		{"promote", "beta", "latest", "--config", configPath, "--repo", "assets"},
		{"materialize", "latest", "--config", configPath, "--repo", "assets", "--workers", "2"},
		{"init", "--config", configPath, "--repo", "assets", "--workers", "2"},
	} {
		if code, stdout, stderr := run(command...); code != ExitOK {
			t.Fatalf("command %v code=%d stdout=%s stderr=%s", command, code, stdout, stderr)
		}
	}
	transport.mutex.Lock()
	transport.objects["pkg/release.bin"] = protocolObject{body: payload, sha: publishDigest(payload), etag: `"local-projected"`}
	transport.mutex.Unlock()
	code, stdout, stderr := run("fsck", "--adopt-remote-inventory", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "inventory_coverage=complete") || !strings.Contains(stdout, "local_expected=1") {
		t.Fatalf("projected adoption code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	content, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "content.tsv"))
	if err != nil || !strings.Contains(string(content), "asset/bootstrap/release.bin\t") || strings.Contains(string(content), "\npkg/release.bin\t") {
		t.Fatalf("physical source content=%s err=%v", content, err)
	}
	inventory, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "inventory.tsv"))
	if err != nil || !strings.Contains(string(inventory), "pkg/release.bin\t") || strings.Contains(string(inventory), "asset/bootstrap/release.bin\t") {
		t.Fatalf("projected remote inventory=%s err=%v", inventory, err)
	}
}
