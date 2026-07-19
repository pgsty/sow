package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
)

func TestStageFrozenCompatibilityS0RollbackUsesExactCarrierBytes(t *testing.T) {
	fixture := newFlatYUMCompatibilityFixture(t)
	workspace := filepath.Clean(filepath.Join(fixture.root, "..", "..", ".."))
	configPath := filepath.Join(workspace, "sow.yaml")
	if err := os.MkdirAll(filepath.Join(workspace, "yum", "infra", "el9", "x86_64"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(workspace, "files"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(nginxCompatibilityConfigYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	privateKey := filepath.Join(workspace, "legacy-private.key")
	candidate := filepath.Join(t.TempDir(), "candidate")
	runOK := func(args ...string) string {
		t.Helper()
		var stdout, stderr bytes.Buffer
		if code := Main(args, &stdout, &stderr); code != ExitOK || stderr.Len() != 0 {
			t.Fatalf("command %v code=%d stdout=%s stderr=%s", args, code, stdout.String(), stderr.String())
		}
		return stdout.String()
	}

	runOK("init", "--config", configPath, "--workers", "1", "--chunk-entries", "2")
	runOK("compatibility", "yum-adopt", "--id", "infra-legacy-x86-64", "--config", configPath, "--workers", "1", "--chunk-entries", "2")
	candidateOutput := runOK("compatibility", "yum-candidate", "--id", "infra-legacy-x86-64", "--output", candidate, "--gpg-private-key-file", privateKey, "--config", configPath, "--workers", "1", "--chunk-entries", "2")
	freezeOutput := runOK("compatibility", "yum-freeze", "--id", "infra-legacy-x86-64", "--candidate", candidate, "--confirm", nginxTestOutputValue(t, candidateOutput, "freeze_confirm"), "--config", configPath, "--workers", "1", "--chunk-entries", "2")
	cutoverOutput := runOK("compatibility", "yum-cutover", "--id", "infra-legacy-x86-64", "--confirm", nginxTestOutputValue(t, freezeOutput, "cutover_confirm"), "--config", configPath, "--workers", "1", "--chunk-entries", "2")
	runOK("compatibility", "yum-rollback", "--id", "infra-legacy-x86-64", "--confirm", nginxTestOutputValue(t, cutoverOutput, "rollback_confirm"), "--config", configPath, "--workers", "1", "--chunk-entries", "2")

	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(cfg.StatePath())
	pool, err := repository.NewStore(cfg.Root)
	if err != nil {
		t.Fatal(err)
	}
	projection := cfg.CompatibilityProjections[0]
	owner, exists := cfg.RepoByName(projection.Source.Repo)
	if !exists {
		t.Fatal("compatibility owner is absent")
	}
	frozen, err := loadYUMCompatibilityFrozenStateAt(canonical, plumbing.ZeroHash, projection.ID)
	if err != nil {
		t.Fatal(err)
	}
	identity := pub.CompatibilityState{
		ID: projection.ID, Carrier: frozen.Receipt.Carrier, OwnerRepo: frozen.Receipt.OwnerRepo,
		SourceCommit: frozen.Receipt.SourceCommit, FreezeCommit: frozen.Commit.String(),
		PackageTrustSHA256: frozen.Receipt.PackageTrustSHA256,
		PackageTrustGit:    frozen.Receipt.PackageTrustGit,
		PackageTrustSize:   frozen.Receipt.PackageTrustSize,
	}
	type stageResult struct {
		target string
		stage  compatibilityS0RollbackStage
		err    error
	}
	results := make(chan stageResult, 2)
	start := make(chan struct{})
	ctx := t.Context()
	workspaces := map[string]string{"cf": t.TempDir(), "cos": t.TempDir()}
	for _, target := range []string{"cf", "cos"} {
		target := target
		go func() {
			<-start
			stage, err := stageFrozenYUMCompatibilityS0Rollback(ctx, cfg, canonical, pool, projection, owner, identity, target, workspaces[target], commonFlags{workers: 1, chunk: 2})
			results <- stageResult{target: target, stage: stage, err: err}
		}()
	}
	close(start)
	stages := make(map[string]compatibilityS0RollbackStage, 2)
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("stage target %s: %v", result.target, result.err)
		}
		stages[result.target] = result.stage
	}
	stage := stages["cf"]
	if stage.projection.localRoot == stages["cos"].projection.localRoot ||
		!strings.Contains(stage.projection.localRoot, "/s0/cf/") ||
		!strings.Contains(stages["cos"].projection.localRoot, "/s0/cos/") {
		t.Fatalf("concurrent target rollback stages share a local source: cf=%s cos=%s", stage.projection.localRoot, stages["cos"].projection.localRoot)
	}
	if !stage.projection.isYUMCompatibilityRollback() || stage.projection.localRoot == projection.Root {
		t.Fatalf("S0 rollback was not isolated: %+v", stage.projection)
	}

	liveManifest := filepath.Join(t.TempDir(), "live-s0.tsv")
	stagedManifest := filepath.Join(t.TempDir(), "staged-s0.tsv")
	if _, err := manifest.Scan(t.Context(), fixture.root, manifest.Scope{Path: "."}, liveManifest, manifest.ScanOptions{Workers: 1, ChunkEntries: 2, TempDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	stagedRoot := filepath.Join(cfg.Root, filepath.FromSlash(stage.projection.localRoot))
	if _, err := manifest.Scan(t.Context(), stagedRoot, manifest.Scope{Path: "."}, stagedManifest, manifest.ScanOptions{Workers: 1, ChunkEntries: 2, TempDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if err := compareManifestFiles(liveManifest, stagedManifest); err != nil {
		t.Fatalf("isolated rollback differs from byte-exact S0 carrier: %v", err)
	}
	for _, forbidden := range []string{"Packages", filepath.Join("repodata", "repomd.xml.asc")} {
		if _, err := os.Lstat(filepath.Join(stagedRoot, forbidden)); !os.IsNotExist(err) {
			t.Fatalf("S3-only path %s survived exact S0 stage: %v", forbidden, err)
		}
	}

	repomd := filepath.Join(fixture.root, "repodata", "repomd.xml")
	body, err := os.ReadFile(repomd)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(repomd, append(body, []byte("\n<!-- tampered -->\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = stageFrozenYUMCompatibilityS0Rollback(t.Context(), cfg, canonical, pool, projection, owner, identity, "cf", t.TempDir(), commonFlags{workers: 1, chunk: 2})
	if err == nil || !strings.Contains(err.Error(), "S0 baseline") {
		t.Fatalf("tampered local S0 carrier was accepted: %v", err)
	}
}
