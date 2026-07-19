package cli

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pgsty/sow/internal/config"
	verification "github.com/pgsty/sow/internal/verify"
)

func TestVerificationLeafScopeIntersectsTargetAndView(t *testing.T) {
	cfg := &config.Config{Views: map[string]config.View{
		"latest": {Repos: []string{"cf-only", "both"}},
	}}
	repos := []config.Repo{
		{ID: "cf-only", Type: "asset", Arches: []string{"all"}, PublishTargets: []string{"cf"}},
		{ID: "cos-only", Type: "asset", Arches: []string{"all"}, PublishTargets: []string{"cos"}},
		{ID: "both", Type: "asset", Arches: []string{"all"}, PublishTargets: []string{"cf", "cos"}},
	}
	leaves := selectedVerificationViewLeaves(cfg, repos, "cf", "latest", commonFlags{})
	if got := verificationLeafRepoIDs(leaves); got != "both,cf-only" {
		t.Fatalf("CF/latest verification leaves=%s", got)
	}
	leaves = selectedVerificationViewLeaves(cfg, repos, "cos", "latest", commonFlags{})
	if got := verificationLeafRepoIDs(leaves); got != "both" {
		t.Fatalf("COS/latest verification leaves=%s", got)
	}
	snapshot, err := selectedVerificationSnapshotLeaves(cfg, repos, "cos", "jammy-20260715", commonFlags{})
	if err != nil {
		t.Fatal(err)
	}
	if got := verificationLeafRepoIDs(snapshot); got != "both,cos-only" {
		t.Fatalf("COS snapshot verification leaves=%s", got)
	}
}

func TestBuildL2ChecksEmptyScopedTargetFailsCoverageWithoutProvider(t *testing.T) {
	for _, test := range []struct {
		name  string
		view  config.View
		repos []config.Repo
	}{
		{
			name: "target-affinity",
			view: config.View{},
			repos: []config.Repo{{
				ID: "cos-only", Type: "asset", Arches: []string{"all"}, PublishTargets: []string{"cos"},
			}},
		},
		{
			name: "view-scope",
			view: config.View{Repos: []string{"cos-only"}},
			repos: []config.Repo{{
				ID: "cf-only", Type: "asset", Arches: []string{"all"}, PublishTargets: []string{"cf"},
			}},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := &config.Config{
				Views:   map[string]config.View{"latest": test.view},
				Targets: map[string]config.Target{"cf": {}},
			}
			checks, err := buildL2Checks(cfg, nil, test.repos, []string{"latest"}, commonFlags{}, []string{"cf"}, &atomic.Bool{})
			if err != nil {
				t.Fatal(err)
			}
			report := verification.Run(t.Context(), verification.Request{
				Layers: []verification.Layer{verification.LayerL2}, Checks: checks, Workers: 1, MaxFindings: 10,
			})
			if len(report.Findings) != 1 || report.Findings[0].Code != "REMOTE_TARGET_COVERAGE_MISSING" {
				t.Fatalf("empty scoped target report=%+v", report)
			}
		})
	}
}

func TestVerifyExplicitAffinityMismatchPrecedesTokenStateAndProvider(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAffinityBuildConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })

	var stdout, stderr bytes.Buffer
	code := Main([]string{
		"verify", "--layer", "L3", "--view", "stable", "--target", "cf", "--repo", "cos-only",
		"--pro-token-file", filepath.Join(root, "missing-token"), "--config", configPath,
	}, &stdout, &stderr)
	if code != ExitConfig || !strings.Contains(stderr.String(), "cos-only publishes to none of the selected targets") || strings.Contains(stderr.String(), "token") {
		t.Fatalf("affinity mismatch code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	assertVerifyRejectedBeforeStateAndProvider(t, root, transport)
}

func TestVerifyExplicitTargetViewMismatchPrecedesStateAndProvider(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	configBody := strings.Replace(publishAffinityBuildConfig,
		"latest: {access: public, allowed_pools: [public], append_only: false}",
		"latest: {access: public, allowed_pools: [public], append_only: false, repos: [cos-only]}", 1)
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })

	var stdout, stderr bytes.Buffer
	code := Main([]string{
		"verify", "--layer", "L2", "--view", "latest", "--target", "cf", "--repo", "cf-only", "--config", configPath,
	}, &stdout, &stderr)
	if code != ExitConfig || !strings.Contains(stderr.String(), "view latest contains no selected repository assigned to target cf") {
		t.Fatalf("target/view mismatch code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	assertVerifyRejectedBeforeStateAndProvider(t, root, transport)
}

func assertVerifyRejectedBeforeStateAndProvider(t *testing.T, root string, transport *cloudProtocolTransport) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(root, ".sow")); !os.IsNotExist(err) {
		t.Fatalf("verify scope rejection created state: %v", err)
	}
	transport.mutex.Lock()
	remoteCalls := transport.puts + transport.copies + transport.deletes + transport.purges + transport.cdnGets + transport.listCalls + transport.objectGets + transport.headCalls
	transport.mutex.Unlock()
	if remoteCalls != 0 {
		t.Fatalf("verify scope rejection reached provider calls=%d", remoteCalls)
	}
}

func verificationLeafRepoIDs(leaves []viewLeaf) string {
	seen := make(map[string]struct{}, len(leaves))
	for _, leaf := range leaves {
		seen[leaf.repo.ID] = struct{}{}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return strings.Join(ids, ",")
}
