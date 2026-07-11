package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitAndFSCKEndToEnd(t *testing.T) {
	root := t.TempDir()
	asset := filepath.Join(root, "asset", "hello.txt")
	if err := os.MkdirAll(filepath.Dir(asset), 0o755); err != nil {
		t.Fatal(err)
	}
	original := []byte("hello")
	if err := os.WriteFile(asset, original, 0o644); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Main([]string{"init", "--config", configPath, "--workers", "2", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("init code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "baseline committed=") {
		t.Fatalf("missing commit evidence: %s", stdout.String())
	}
	after, err := os.ReadFile(asset)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, original) {
		t.Fatal("init modified a published file")
	}

	stdout.Reset()
	stderr.Reset()
	code = Main([]string{"init", "--config", configPath, "--workers", "2", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitOK || !strings.Contains(stdout.String(), "baseline unchanged=") {
		t.Fatalf("idempotent init code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = Main([]string{"fsck", "--config", configPath, "--workers", "2", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitOK || !strings.Contains(stdout.String(), "fsck clean") {
		t.Fatalf("clean fsck code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	if err := os.WriteFile(asset, []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = Main([]string{"fsck", "--config", configPath, "--workers", "2", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitVerification || !strings.Contains(stdout.String(), "kind=changed") || !strings.Contains(stderr.String(), "drift detected") {
		t.Fatalf("dirty fsck code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestHelpAndUsageCodes(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Main(nil, &stdout, &stderr); code != ExitOK || !strings.Contains(stdout.String(), "init       adopt") {
		t.Fatalf("help code/content mismatch: %d %s", code, stdout.String())
	}
	stdout.Reset()
	if code := Main([]string{"unknown"}, &stdout, &stderr); code != ExitUsage {
		t.Fatalf("unknown command code=%d", code)
	}
}

const testConfig = `schema: sow/v1
state: {}
gpg: {}
pools:
  public: {}
  gated: {}
repos:
  - id: asset
    type: asset
    path: asset
    default_pool: public
    asset: {kind: test}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge:
  token_verifier: provider://test
`
