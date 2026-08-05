package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/klauspost/compress/zstd"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/provenance"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
	"github.com/pgsty/sow/internal/yumrepo"
)

func TestInitAdoptContentAssetsIsZeroRewriteAtomicAndIdempotent(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	configText := legacyAssetConfig("public")
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		filepath.Join(root, "pkg", "pig", "latest"):        []byte("v4.0.0\n"),
		filepath.Join(root, "pkg", "pig", "v4.0.0.tar.gz"): []byte("archive-bytes"),
	}
	for name, body := range files {
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run := legacyCLIRunner()
	code, stdout, stderr := run("init", "--adopt-content", "--config", configPath, "--repo", "assets", "--workers", "3", "--chunk-entries", "1")
	if code != ExitOK || !strings.Contains(stdout, "serving_tree_rewritten=false") || !strings.Contains(stdout, "payloads=2") || !strings.Contains(stdout, "peak_import_workers=") {
		t.Fatalf("adopt assets code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for name, want := range files {
		got, err := os.ReadFile(name)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("serving bytes changed %s got=%q want=%q err=%v", name, got, want, err)
		}
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	head, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := state.ViewRef("latest", "assets", "all", "all")
	commit, exists, err := canonical.Ref(ref)
	if err != nil || !exists || commit != head {
		t.Fatalf("latest ref exists=%v commit=%s head=%s err=%v", exists, commit, head, err)
	}
	stableRef, _ := state.ViewRef("stable", "assets", "all", "all")
	if _, exists, err := canonical.Ref(stableRef); err != nil || exists {
		t.Fatalf("default adoption unexpectedly advanced stable exists=%v err=%v", exists, err)
	}
	viewPath, _ := state.ViewPath("latest", "assets", "all", "all")
	viewReader, err := canonical.OpenPathAt(commit, viewPath)
	if err != nil {
		t.Fatal(err)
	}
	reader := views.NewReader(viewReader)
	var entries int
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		digest, _ := repository.ParseDigest(entry.SHA256)
		if err := pool.Verify(context.Background(), repository.Object{SHA256: digest, Size: entry.Size}); err != nil {
			t.Fatal(err)
		}
		entries++
	}
	if err := viewReader.Close(); err != nil || entries != 2 {
		t.Fatalf("view entries=%d close=%v", entries, err)
	}
	ledger, err := canonical.OpenPath("provenance/legacy/assets.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	legacy := provenance.NewLegacyAdoptionReader(ledger)
	for count := 0; ; count++ {
		receipt, err := legacy.Next()
		if errors.Is(err, io.EOF) {
			if count != 2 {
				t.Fatalf("receipt count=%d", count)
			}
			break
		}
		if err != nil || receipt.Format != "asset" || receipt.ConfigCommit == "" {
			t.Fatalf("receipt=%+v err=%v", receipt, err)
		}
	}
	_ = ledger.Close()

	code, stdout, stderr = run("init", "--adopt-content", "--view", "latest", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "changed=false") {
		t.Fatalf("idempotent adopt code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	after, err := canonical.HeadHash()
	if err != nil || after != head {
		t.Fatalf("idempotent adoption changed head before=%s after=%s err=%v", head, after, err)
	}
	if _, exists, err := canonical.Ref(stableRef); err != nil || exists {
		t.Fatalf("explicit latest adoption unexpectedly advanced stable exists=%v err=%v", exists, err)
	}
}

func TestInitAdoptContentRejectsLateServingTreeMutationBeforeApply(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(legacyAssetConfig("public")), 0o600); err != nil {
		t.Fatal(err)
	}
	assetPath := filepath.Join(root, "pkg", "release.bin")
	if err := os.MkdirAll(filepath.Dir(assetPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(assetPath, []byte("before"), 0o644); err != nil {
		t.Fatal(err)
	}
	legacyAdoptionBeforeFinalTreeVerificationHook = func() error {
		return os.WriteFile(assetPath, []byte("after!"), 0o644)
	}
	t.Cleanup(func() { legacyAdoptionBeforeFinalTreeVerificationHook = nil })
	code, stdout, stderr := legacyCLIRunner()("init", "--adopt-content", "--config", configPath, "--repo", "assets", "--workers", "2")
	legacyAdoptionBeforeFinalTreeVerificationHook = nil
	if code != ExitVerification || !strings.Contains(stderr, "legacy serving tree changed during adoption") || !strings.Contains(stderr, "changed=1") {
		t.Fatalf("late serving mutation code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	ref, _ := state.ViewRef("latest", "assets", "all", "all")
	if _, exists, err := canonical.Ref(ref); err != nil || exists {
		t.Fatalf("late serving mutation advanced view exists=%v err=%v", exists, err)
	}
	if ledger, err := canonical.OpenPath("provenance/legacy/assets.jsonl"); err == nil {
		ledger.Close()
		t.Fatal("late serving mutation committed provenance")
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func TestInitAdoptContentPreservesCodedFailureExitClass(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(legacyAssetConfig("public")), 0o600); err != nil {
		t.Fatal(err)
	}
	assetPath := filepath.Join(root, "pkg", "release.bin")
	if err := os.MkdirAll(filepath.Dir(assetPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(assetPath, []byte("release"), 0o644); err != nil {
		t.Fatal(err)
	}
	legacyAdoptionBeforeFinalTreeVerificationHook = func() error {
		return withExitCode(ExitInternal, "injected adoption persistence failure")
	}
	t.Cleanup(func() { legacyAdoptionBeforeFinalTreeVerificationHook = nil })
	code, stdout, stderr := legacyCLIRunner()("init", "--adopt-content", "--config", configPath, "--repo", "assets")
	legacyAdoptionBeforeFinalTreeVerificationHook = nil
	if code != ExitInternal || !strings.Contains(stderr, "injected adoption persistence failure") {
		t.Fatalf("coded adoption failure code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

func TestLegacyAdoptionReceiptAnchorRejectsCommitTimestampAndRouteForgery(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(legacyAssetConfig("public")), 0o600); err != nil {
		t.Fatal(err)
	}
	assetPath := filepath.Join(root, "pkg", "release.bin")
	if err := os.MkdirAll(filepath.Dir(assetPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(assetPath, []byte("release"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := legacyCLIRunner()("init", "--adopt-content", "--config", configPath, "--repo", "assets"); code != ExitOK {
		t.Fatalf("prepare anchored receipt code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	repo, exists := cfg.RepoByName("assets")
	if !exists {
		t.Fatal("asset repo disappeared")
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	ref, _ := state.RepoRef(repo.ID)
	baselineCommit, exists, err := canonical.Ref(ref)
	if err != nil || !exists {
		t.Fatalf("baseline ref exists=%v err=%v", exists, err)
	}
	baseline, err := canonical.OpenPathAt(baselineCommit, "manifests/assets.tsv")
	if err != nil {
		t.Fatal(err)
	}
	spool, err := newLegacyAdoptionSpool(filepath.Join(t.TempDir(), "anchor.db"))
	if err != nil {
		baseline.Close()
		t.Fatal(err)
	}
	defer spool.Close()
	if err := spool.seedBaseline(repo.ID, baseline); err != nil {
		baseline.Close()
		t.Fatal(err)
	}
	if err := baseline.Close(); err != nil {
		t.Fatal(err)
	}
	ledger, err := canonical.OpenPath("provenance/legacy/assets.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := provenance.NewLegacyAdoptionReader(ledger).Next()
	closeErr := ledger.Close()
	if err != nil || closeErr != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
	if err := spool.validateLegacyReceiptAnchor(canonical, repo, baselineCommit, receipt); err != nil {
		t.Fatalf("valid receipt anchor rejected: %v", err)
	}
	for _, test := range []struct {
		name string
		edit func(*provenance.LegacyAdoptionReceipt)
		want string
	}{
		{name: "commit", edit: func(value *provenance.LegacyAdoptionReceipt) { value.ConfigCommit = strings.Repeat("0", 40) }, want: "lineage"},
		{name: "timestamp", edit: func(value *provenance.LegacyAdoptionReceipt) { value.AdoptedAt = value.AdoptedAt.Add(time.Second) }, want: "timestamp"},
		{name: "canonical route", edit: func(value *provenance.LegacyAdoptionReceipt) { value.CanonicalPath = "pkg/forged.bin" }, want: "canonical path"},
	} {
		t.Run(test.name, func(t *testing.T) {
			forged := receipt
			test.edit(&forged)
			if err := spool.validateLegacyReceiptAnchor(canonical, repo, baselineCommit, forged); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("forged receipt error=%v want=%q", err, test.want)
			}
		})
	}
}

func TestInitAdoptContentRejectsInvalidViewBeforeStateMutation(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(legacyAssetConfig("public")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pkg", "asset.bin"), []byte("asset\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := legacyCLIRunner()("init", "--adopt-content", "--view", "beta", "--config", configPath, "--repo", "assets")
	if code != ExitUsage || !strings.Contains(stderr, "supports only latest and stable") {
		t.Fatalf("invalid adoption view code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(root, ".sow")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid adoption view mutated state: %v", err)
	}
}

func TestInitAdoptContentRejectsNonRoutableAssetsBeforeCASImport(t *testing.T) {
	for _, relative := range []string{"bad name.bin", "tool@latest", "中文.tar.gz"} {
		t.Run(relative, func(t *testing.T) {
			root := t.TempDir()
			configPath := filepath.Join(root, "sow.yaml")
			if err := os.WriteFile(configPath, []byte(legacyAssetConfig("public")), 0o600); err != nil {
				t.Fatal(err)
			}
			body := []byte("must-not-enter-cas\n")
			assetPath := filepath.Join(root, "pkg", relative)
			if err := os.MkdirAll(filepath.Dir(assetPath), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(assetPath, body, 0o644); err != nil {
				t.Fatal(err)
			}

			code, stdout, stderr := legacyCLIRunner()("init", "--adopt-content", "--config", configPath, "--repo", "assets")
			if code != ExitVerification || !strings.Contains(stderr, "not edge-routable") {
				t.Fatalf("non-routable adoption code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			canonical := state.New(filepath.Join(root, ".sow"))
			latest, err := state.ViewRef("latest", "assets", "all", "all")
			if err != nil {
				t.Fatal(err)
			}
			if _, exists, err := canonical.Ref(latest); err != nil || exists {
				t.Fatalf("failed adoption advanced latest exists=%v err=%v", exists, err)
			}
			pool, err := repository.NewStore(root)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(body)
			if err := pool.Verify(context.Background(), repository.Object{SHA256: digest, Size: int64(len(body))}); err == nil {
				t.Fatal("non-routable asset was imported into CAS before rejection")
			}
		})
	}
	t.Run("valid-before-invalid", func(t *testing.T) {
		root := t.TempDir()
		configPath := filepath.Join(root, "sow.yaml")
		if err := os.WriteFile(configPath, []byte(legacyAssetConfig("public")), 0o600); err != nil {
			t.Fatal(err)
		}
		validBody := []byte("must-not-enter-cas-before-later-rejection\n")
		for relative, body := range map[string][]byte{"aaa-valid.bin": validBody, "zzz bad.bin": []byte("invalid\n")} {
			assetPath := filepath.Join(root, "pkg", relative)
			if err := os.MkdirAll(filepath.Dir(assetPath), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(assetPath, body, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		code, stdout, stderr := legacyCLIRunner()("init", "--adopt-content", "--config", configPath, "--repo", "assets", "--workers", "4")
		if code != ExitVerification || !strings.Contains(stderr, "not edge-routable") {
			t.Fatalf("mixed adoption code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		pool, err := repository.NewStore(root)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(validBody)
		if err := pool.Verify(context.Background(), repository.Object{SHA256: digest, Size: int64(len(validBody))}); err == nil {
			t.Fatal("valid asset was imported before a later non-routable baseline path was rejected")
		}
	})
	t.Run("valid-repo-before-invalid-repo", func(t *testing.T) {
		root := t.TempDir()
		configPath := filepath.Join(root, "sow.yaml")
		configText := `schema: sow/v1
state: {}
gpg: {}
pools: {public: {}, gated: {}}
repos:
  - {id: assets-a, type: asset, path: pkg-a, default_pool: public, asset: {kind: release}}
  - {id: assets-z, type: asset, path: pkg-z, default_pool: public, asset: {kind: release}}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge: {token_verifier: provider://test}
`
		if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
			t.Fatal(err)
		}
		validBody := []byte("earlier-repo-must-not-enter-cas\n")
		for relative, body := range map[string][]byte{"pkg-a/valid.bin": validBody, "pkg-z/bad name.bin": []byte("invalid\n")} {
			assetPath := filepath.Join(root, filepath.FromSlash(relative))
			if err := os.MkdirAll(filepath.Dir(assetPath), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(assetPath, body, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		code, stdout, stderr := legacyCLIRunner()("init", "--adopt-content", "--config", configPath, "--workers", "4")
		if code != ExitVerification || !strings.Contains(stderr, "not edge-routable") {
			t.Fatalf("cross-repo adoption code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		pool, err := repository.NewStore(root)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(validBody)
		if err := pool.Verify(context.Background(), repository.Object{SHA256: digest, Size: int64(len(validBody))}); err == nil {
			t.Fatal("valid earlier repository was imported before a later repository failed admission")
		}
	})
}

func TestInitAdoptContentRejectsGatedPublicAndAllowsStable(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	configText := legacyAssetConfig("gated")
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pkg", "secret.bin"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := legacyCLIRunner()
	code, stdout, stderr := run("init", "--adopt-content", "--config", configPath, "--repo", "assets")
	if code != ExitVerification || !strings.Contains(stderr, "confidentiality closure violation") {
		t.Fatalf("gated latest code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	latest, _ := state.ViewRef("latest", "assets", "all", "all")
	if _, exists, err := canonical.Ref(latest); err != nil || exists {
		t.Fatalf("failed public adoption advanced latest exists=%v err=%v", exists, err)
	}
	poolObjects, err := filepath.Glob(filepath.Join(root, ".pool", "sha256", "*", strings.Repeat("?", 64)))
	if err != nil {
		t.Fatal(err)
	}
	if len(poolObjects) != 0 {
		t.Fatalf("failed confidentiality admission wrote %d CAS object(s)", len(poolObjects))
	}
	code, stdout, stderr = run("init", "--adopt-content", "--view", "stable", "--config", configPath, "--repo", "assets")
	if code != ExitOK || !strings.Contains(stdout, "pool=gated") {
		t.Fatalf("gated stable code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	stable, _ := state.ViewRef("stable", "assets", "all", "all")
	if _, exists, err := canonical.Ref(stable); err != nil || !exists {
		t.Fatalf("stable ref exists=%v err=%v", exists, err)
	}
}

func TestInitAdoptContentMembershipFailureLeavesOnlyBaselineAndNoCASMutation(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(legacyPartialFailureConfig()), 0o600); err != nil {
		t.Fatal(err)
	}
	body := []byte("imported-before-later-repo-fails\n")
	assetPath := filepath.Join(root, "pkg", "orphan.bin")
	if err := os.MkdirAll(filepath.Dir(assetPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(assetPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "apt", "bad"), 0o755); err != nil {
		t.Fatal(err)
	}

	run := legacyCLIRunner()
	code, stdout, stderr := run("init", "--adopt-content", "--config", configPath, "--workers", "2")
	if code != ExitVerification || !strings.Contains(stderr, "lacks a usable Packages index") {
		t.Fatalf("partial adoption code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	baselineHead, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	for _, repoID := range []string{"assets", "z-apt-bad"} {
		ref, err := state.RepoRef(repoID)
		if err != nil {
			t.Fatal(err)
		}
		commit, exists, err := canonical.Ref(ref)
		if err != nil || !exists || commit != baselineHead {
			t.Fatalf("baseline ref %s exists=%v commit=%s head=%s err=%v", ref, exists, commit, baselineHead, err)
		}
	}
	latest, _ := state.ViewRef("latest", "assets", "all", "all")
	if _, exists, err := canonical.Ref(latest); err != nil || exists {
		t.Fatalf("failed adoption advanced latest exists=%v err=%v", exists, err)
	}
	if ledger, err := canonical.OpenPath("provenance/legacy/assets.jsonl"); err == nil {
		ledger.Close()
		t.Fatal("failed adoption committed receipt ledger")
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inspect failed adoption receipt ledger: %v", err)
	}
	digest := sha256.Sum256(body)
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Verify(context.Background(), repository.Object{SHA256: digest, Size: int64(len(body))}); err == nil {
		t.Fatal("transaction-wide membership failure imported an earlier asset into CAS")
	}
	poolObjects, err := filepath.Glob(filepath.Join(root, ".pool", "sha256", "*", strings.Repeat("?", 64)))
	if err != nil {
		t.Fatal(err)
	}
	if len(poolObjects) != 0 {
		t.Fatalf("transaction-wide membership failure wrote %d CAS object(s)", len(poolObjects))
	}
}

func TestInitAdoptContentUsesExactSparseAPTMatrix(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(legacySparseAPTConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	exactIndexes := []string{
		"apt/pgdg/dists/bookworm-pgdg/main/binary-arm64/Packages",
		"apt/pgdg/dists/bookworm-pgdg-testing/main/binary-arm64/Packages",
		"apt/pgdg/dists/bookworm-pgdg-testing/18/binary-arm64/Packages",
		"apt/pgdg/dists/bookworm-pgdg-testing/19/binary-arm64/Packages",
	}
	for _, relative := range exactIndexes {
		filename := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	code, stdout, stderr := legacyCLIRunner()("init", "--adopt-content", "--config", configPath, "--repo", "apt-pgdg", "--workers", "2", "--chunk-entries", "1")
	if code != ExitOK || !strings.Contains(stdout, "payloads=0") || !strings.Contains(stdout, "leaves=2") {
		t.Fatalf("sparse APT adoption code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, forbidden := range []string{
		"apt/pgdg/dists/bookworm-pgdg/18",
		"apt/pgdg/dists/bookworm-pgdg/19",
	} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(forbidden))); !os.IsNotExist(err) {
			t.Fatalf("adoption required or created phantom stable component %s: %v", forbidden, err)
		}
	}
}

func TestInitAdoptContentRejectsAPTIndexCandidateDriftBetweenPasses(t *testing.T) {
	root := t.TempDir()
	_, publicKey := writeLegacySigningKey(t, root)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(legacyPackageConfig(filepath.Base(publicKey))), 0o600); err != nil {
		t.Fatal(err)
	}
	debInput := decodeLegacyFixture(t, filepath.Join("..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"), filepath.Join(root, "input.deb"))
	pkg, err := aptrepo.InspectPackage(context.Background(), debInput, "main")
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(debInput)
	if err != nil {
		t.Fatal(err)
	}
	poolPath := filepath.Join(root, "apt", "test", filepath.FromSlash(pkg.PoolPath))
	if err := os.MkdirAll(filepath.Dir(poolPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(poolPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	packagesPath := filepath.Join(root, "apt", "test", "dists", "jammy", "main", "binary-arm64", "Packages")
	if err := os.MkdirAll(filepath.Dir(packagesPath), 0o755); err != nil {
		t.Fatal(err)
	}
	packages, err := os.OpenFile(packagesPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	writeErr := aptrepo.WritePackages(packages, []aptrepo.Package{pkg})
	closeErr := packages.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal(errors.Join(writeErr, closeErr))
	}
	run := legacyCLIRunner()
	legacyAdoptionAfterMembershipPreflightHook = func() error {
		body, err := os.ReadFile(packagesPath)
		if err != nil {
			return err
		}
		start := bytes.Index(body, []byte("Version: "))
		if start < 0 {
			return errors.New("APT drift fixture has no Version field")
		}
		end := bytes.IndexByte(body[start:], '\n')
		if end < 0 {
			return errors.New("APT drift fixture has unterminated Version field")
		}
		end += start
		mutated := append([]byte(nil), body[:end]...)
		mutated = append(mutated, []byte("+index-drift")...)
		mutated = append(mutated, body[end:]...)
		return os.WriteFile(packagesPath, mutated, 0o644)
	}
	t.Cleanup(func() { legacyAdoptionAfterMembershipPreflightHook = nil })
	code, stdout, stderr := run("init", "--adopt-content", "--config", configPath, "--repo", "apt-legacy", "--workers", "2")
	legacyAdoptionAfterMembershipPreflightHook = nil
	if code != ExitVerification || !strings.Contains(stderr, "legacy index candidate set changed") {
		t.Fatalf("APT candidate drift code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	ref, _ := state.ViewRef("latest", "apt-legacy", "jammy", "arm64")
	if _, exists, err := canonical.Ref(ref); err != nil || exists {
		t.Fatalf("APT candidate drift advanced view exists=%v err=%v", exists, err)
	}
	assertLegacyPoolRegularFiles(t, root, 0)
}

func TestInitAdoptContentRealAPTAndYUMThenMaterializeVerifyFSCK(t *testing.T) {
	root := nginxWorkerTempDir(t)
	privateKey, publicKey := writeLegacySigningKey(t, root)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(legacyPackageConfig(filepath.Base(publicKey))), 0o600); err != nil {
		t.Fatal(err)
	}
	debInput := decodeLegacyFixture(t, filepath.Join("..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"), filepath.Join(root, "input.deb"))
	rpmInput := decodeLegacyFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "input.rpm"))
	run := legacyCLIRunner()
	for _, arguments := range [][]string{
		{"add", debInput, "--config", configPath, "--repo", "apt-legacy", "--component", "main", "--gpg-private-key-file", privateKey, "--workers", "2"},
		{"add", rpmInput, "--config", configPath, "--repo", "yum-legacy", "--gpg-private-key-file", privateKey, "--workers", "2"},
		{"promote", "beta", "latest", "--config", configPath, "--repo", "apt-legacy", "--repo", "yum-legacy"},
		{"materialize", "latest", "--config", configPath, "--repo", "apt-legacy", "--repo", "yum-legacy", "--gpg-private-key-file", privateKey, "--workers", "2"},
	} {
		if code, stdout, stderr := run(arguments...); code != ExitOK {
			t.Fatalf("prepare legacy %v code=%d stdout=%s stderr=%s", arguments, code, stdout, stderr)
		}
	}
	configBody, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	configBody = bytes.Replace(configBody,
		[]byte("os: {family: el, major: 10, lifecycle: active}"),
		[]byte("os: {family: el, major: 10, lifecycle: frozen}"), 1)
	if err := os.WriteFile(configPath, configBody, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	before := snapshotLegacyRepos(t, cfg, []string{"apt-legacy", "yum-legacy"})
	if err := os.RemoveAll(filepath.Join(root, ".sow")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(root, ".pool")); err != nil {
		t.Fatal(err)
	}
	// This fixture models a pre-SOW raw legacy tree. The preparation command now
	// also emits the new strong-YUM `_sow` namespace, so remove that derived
	// namespace before adoption instead of presenting an unmanaged SOW pointer
	// with its canonical channel ledger deliberately deleted above.
	if err := os.RemoveAll(filepath.Join(root, "_sow")); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run("init", "--adopt-content", "--view", "latest,stable", "--config", configPath, "--repo", "apt-legacy", "--repo", "yum-legacy", "--workers", "3", "--chunk-entries", "2")
	if code != ExitOK || !strings.Contains(stdout, "payloads=2") || !strings.Contains(stdout, "leaves=4") ||
		!strings.Contains(stdout, "yum_metadata_signature=not-claimed yum_metadata_keyring_sha256=-") {
		t.Fatalf("package adoption code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	after := snapshotLegacyRepos(t, cfg, []string{"apt-legacy", "yum-legacy"})
	if !bytes.Equal(before, after) {
		t.Fatalf("init adoption rewrote serving tree\nbefore:\n%s\nafter:\n%s", before, after)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	for _, view := range []string{"latest", "stable"} {
		for _, leaf := range []struct{ repo, os, arch string }{{"apt-legacy", "jammy", "arm64"}, {"yum-legacy", "el10", "x86_64"}} {
			ref, _ := state.ViewRef(view, leaf.repo, leaf.os, leaf.arch)
			if _, exists, err := canonical.Ref(ref); err != nil || !exists {
				t.Fatalf("adopted ref %s exists=%v err=%v", ref, exists, err)
			}
		}
	}
	for _, arguments := range [][]string{
		{"materialize", "latest", "--config", configPath, "--repo", "apt-legacy", "--repo", "yum-legacy", "--gpg-private-key-file", privateKey, "--workers", "2"},
		{"verify", "--layer", "L1", "--config", configPath, "--repo", "apt-legacy", "--repo", "yum-legacy", "--gpg-public-key-file", publicKey, "--workers", "2"},
		{"fsck", "--config", configPath, "--repo", "apt-legacy", "--repo", "yum-legacy", "--workers", "2"},
	} {
		if code, stdout, stderr := run(arguments...); code != ExitOK {
			t.Fatalf("post-adoption %v code=%d stdout=%s stderr=%s", arguments, code, stdout, stderr)
		}
	}
	if code, stdout, stderr := run("add", rpmInput, "--config", configPath, "--repo", "yum-legacy", "--gpg-private-key-file", privateKey); code != ExitConflict || !strings.Contains(stderr, "frozen") {
		t.Fatalf("frozen add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

func TestInitAdoptContentYUMSeparateNoarchRouting(t *testing.T) {
	for _, test := range []struct {
		name          string
		x86Package    string
		noarchPackage string
		wantEntries   map[string]int
	}{
		{name: "matching independent leaves", x86Package: "x86_64", noarchPackage: "noarch", wantEntries: map[string]int{"x86_64": 1, "noarch": 1}},
		{name: "noarch replicas converge to noarch leaf", x86Package: "noarch", noarchPackage: "noarch", wantEntries: map[string]int{"x86_64": 0, "noarch": 2}},
		{name: "basearch package in noarch leaf", x86Package: "x86_64", noarchPackage: "x86_64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			metadataPrivate, publicKey := writeLegacySigningKey(t, root)
			configPath := filepath.Join(root, "sow.yaml")
			if err := os.WriteFile(configPath, []byte(legacySeparateYUMConfig(filepath.Base(publicKey))), 0o600); err != nil {
				t.Fatal(err)
			}
			noarchInput := decodeLegacyFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "input-noarch.rpm"))
			x86Input := filepath.Join("..", "..", "third_party", "cavaliergopher-rpm", "testdata", "centos-release-4-0.1.x86_64.rpm")
			inputs := map[string]string{"noarch": noarchInput, "x86_64": x86Input}
			writePigstyV1FlatYUM(t, filepath.Join(root, "yum", "percona", "el10.x86_64"), inputs[test.x86Package], metadataPrivate, "base-leaf.rpm")
			writePigstyV1FlatYUM(t, filepath.Join(root, "yum", "percona", "el10.noarch"), inputs[test.noarchPackage], metadataPrivate, "noarch-leaf.rpm")

			code, stdout, stderr := legacyCLIRunner()("init", "--adopt-content", "--config", configPath, "--repo", "yum-percona-el10", "--workers", "2", "--chunk-entries", "1")
			canonical := state.New(filepath.Join(root, ".sow"))
			if test.wantEntries == nil {
				if code != ExitVerification || !strings.Contains(stderr, "architecture") || !strings.Contains(stderr, "is indexed by") {
					t.Fatalf("mismatched separate adoption code=%d stdout=%s stderr=%s", code, stdout, stderr)
				}
				for _, leaf := range []string{"x86_64", "noarch"} {
					ref, _ := state.ViewRef("latest", "yum-percona-el10", "el10", leaf)
					if _, exists, err := canonical.Ref(ref); err != nil || exists {
						t.Fatalf("rejected separate adoption advanced %s exists=%v err=%v", ref, exists, err)
					}
				}
				return
			}

			if code != ExitOK || !strings.Contains(stdout, "payloads=2") || !strings.Contains(stdout, "leaves=2") {
				t.Fatalf("matching separate adoption code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			for _, leaf := range []string{"x86_64", "noarch"} {
				ref, _ := state.ViewRef("latest", "yum-percona-el10", "el10", leaf)
				commit, exists, err := canonical.Ref(ref)
				if err != nil || !exists {
					t.Fatalf("separate adoption ref %s exists=%v err=%v", ref, exists, err)
				}
				viewPath, _ := state.ViewPath("latest", "yum-percona-el10", "el10", leaf)
				reader, err := canonical.OpenPathAt(commit, viewPath)
				if err != nil {
					t.Fatal(err)
				}
				entries := views.NewReader(reader)
				count := 0
				for {
					entry, readErr := entries.Next()
					if errors.Is(readErr, io.EOF) {
						break
					}
					if readErr != nil || entry.Arch != leaf || !strings.HasPrefix(entry.Path, "yum/percona/el10."+leaf+"/") {
						reader.Close()
						t.Fatalf("separate leaf=%s entry=%+v read_err=%v", leaf, entry, readErr)
					}
					count++
				}
				if closeErr := reader.Close(); closeErr != nil {
					t.Fatal(closeErr)
				}
				if count != test.wantEntries[leaf] {
					t.Fatalf("separate leaf=%s entries=%d want=%d", leaf, count, test.wantEntries[leaf])
				}
			}
		})
	}
}

func TestInitAdoptContentSequentialArchSelectorsMergeViewsAndReceipts(t *testing.T) {
	root := t.TempDir()
	metadataPrivate, publicKey := writeLegacySigningKey(t, root)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(legacySeparateYUMConfig(filepath.Base(publicKey))), 0o600); err != nil {
		t.Fatal(err)
	}
	noarchInput := decodeLegacyFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "input-noarch.rpm"))
	x86Input := filepath.Join("..", "..", "third_party", "cavaliergopher-rpm", "testdata", "centos-release-4-0.1.x86_64.rpm")
	writePigstyV1FlatYUM(t, filepath.Join(root, "yum", "percona", "el10.x86_64"), x86Input, metadataPrivate, "base-leaf.rpm")
	writePigstyV1FlatYUM(t, filepath.Join(root, "yum", "percona", "el10.noarch"), noarchInput, metadataPrivate, "noarch-leaf.rpm")

	run := legacyCLIRunner()
	if code, stdout, stderr := run("init", "--config", configPath, "--repo", "yum-percona-el10"); code != ExitOK {
		t.Fatalf("full M0 baseline code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for index, arch := range []string{"x86_64", "noarch"} {
		code, stdout, stderr := run("init", "--adopt-content", "--config", configPath, "--repo", "yum-percona-el10", "--arch", arch, "--workers", "2", "--chunk-entries", "1")
		if code != ExitOK || !strings.Contains(stdout, "payloads=1") || !strings.Contains(stdout, fmt.Sprintf("receipts=%d", index+1)) {
			t.Fatalf("partial adoption arch=%s code=%d stdout=%s stderr=%s", arch, code, stdout, stderr)
		}
	}

	canonical := state.New(filepath.Join(root, ".sow"))
	for _, arch := range []string{"x86_64", "noarch"} {
		ref, _ := state.ViewRef("latest", "yum-percona-el10", "el10", arch)
		commit, exists, err := canonical.Ref(ref)
		if err != nil || !exists {
			t.Fatalf("partial view %s exists=%v err=%v", ref, exists, err)
		}
		viewPath, _ := state.ViewPath("latest", "yum-percona-el10", "el10", arch)
		stream, err := canonical.OpenPathAt(commit, viewPath)
		if err != nil {
			t.Fatal(err)
		}
		reader := views.NewReader(stream)
		if _, err := reader.Next(); err != nil {
			stream.Close()
			t.Fatalf("partial view %s has no package: %v", ref, err)
		}
		if _, err := reader.Next(); !errors.Is(err, io.EOF) {
			stream.Close()
			t.Fatalf("partial view %s contains unexpected second entry: %v", ref, err)
		}
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
	}
	ledger, err := canonical.OpenPath("provenance/legacy/yum-percona-el10.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	receipts := provenance.NewLegacyAdoptionReader(ledger)
	var receiptCount int
	for {
		_, err := receipts.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			ledger.Close()
			t.Fatal(err)
		}
		receiptCount++
	}
	if err := ledger.Close(); err != nil || receiptCount != 2 {
		t.Fatalf("merged receipt count=%d close=%v", receiptCount, err)
	}
	head, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run("init", "--adopt-content", "--config", configPath, "--repo", "yum-percona-el10", "--arch", "x86_64", "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "changed=false") || !strings.Contains(stdout, "receipts=2") {
		t.Fatalf("partial replay code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	after, err := canonical.HeadHash()
	if err != nil || after != head {
		t.Fatalf("partial replay changed HEAD before=%s after=%s err=%v", head, after, err)
	}
}

func TestInitAdoptContentSequentialAPTSelectorsCannotHideSharedPoolOrphan(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(legacySharedPoolAPTConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	debInput := decodeLegacyFixture(t, filepath.Join("..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"), filepath.Join(root, "input.deb"))
	pkg, err := aptrepo.InspectPackage(context.Background(), debInput, "main")
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(debInput)
	if err != nil {
		t.Fatal(err)
	}
	poolPath := filepath.Join(root, "apt", "test", filepath.FromSlash(pkg.PoolPath))
	if err := os.MkdirAll(filepath.Dir(poolPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(poolPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	orphanRelative := "apt/test/pool/main/o/orphan/orphan_1_arm64.deb"
	orphanPath := filepath.Join(root, filepath.FromSlash(orphanRelative))
	if err := os.MkdirAll(filepath.Dir(orphanPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(orphanPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, suite := range []string{"jammy", "noble"} {
		packagesPath := filepath.Join(root, "apt", "test", "dists", suite, "main", "binary-arm64", "Packages")
		if err := os.MkdirAll(filepath.Dir(packagesPath), 0o755); err != nil {
			t.Fatal(err)
		}
		packages, err := os.OpenFile(packagesPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		writeErr := aptrepo.WritePackages(packages, []aptrepo.Package{pkg})
		closeErr := packages.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatal(errors.Join(writeErr, closeErr))
		}
	}
	run := legacyCLIRunner()
	if code, stdout, stderr := run("init", "--config", configPath, "--repo", "apt-legacy"); code != ExitOK {
		t.Fatalf("full APT M0 code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, suite := range []string{"jammy", "noble"} {
		code, stdout, stderr := run("init", "--adopt-content", "--config", configPath, "--repo", "apt-legacy", "--os", suite, "--workers", "2")
		if code != ExitVerification || !strings.Contains(stderr, "body-without-index") || !strings.Contains(stderr, orphanRelative) {
			t.Fatalf("partial APT suite=%s hid shared-pool orphan code=%d stdout=%s stderr=%s", suite, code, stdout, stderr)
		}
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	for _, suite := range []string{"jammy", "noble"} {
		ref, _ := state.ViewRef("latest", "apt-legacy", suite, "arm64")
		if _, exists, err := canonical.Ref(ref); err != nil || exists {
			t.Fatalf("shared-pool orphan advanced %s exists=%t err=%v", ref, exists, err)
		}
	}
	assertLegacyPoolRegularFiles(t, root, 0)
}

func TestInitAdoptContentLegacyYUMMetadataTrustIsExplicit(t *testing.T) {
	type fixture struct {
		root, configPath                            string
		repositoryPrivate, repositoryPublic         string
		metadataPrivate, metadataPublic, repomdPath string
		rpmInput                                    string
	}
	setup := func(t *testing.T) fixture {
		t.Helper()
		value := fixture{root: t.TempDir()}
		value.repositoryPrivate, value.repositoryPublic = writeLegacySigningKey(t, value.root)
		value.metadataPrivate, value.metadataPublic = writeLegacyMetadataSigningKey(t, value.root)
		value.configPath = filepath.Join(value.root, "sow.yaml")
		if err := os.WriteFile(value.configPath, []byte(pigstyV1PackageConfig(filepath.Base(value.repositoryPublic))), 0o600); err != nil {
			t.Fatal(err)
		}
		value.rpmInput = decodeLegacyFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(value.root, "input.rpm"))
		yumRoot := filepath.Join(value.root, "yum", "pgsql", "el10.x86_64")
		writePigstyV1FlatYUM(t, yumRoot, value.rpmInput, value.metadataPrivate, "pgdg-redhat-nonfree-repo.rpm")
		value.repomdPath = filepath.Join(yumRoot, "repodata", "repomd.xml")
		return value
	}

	t.Run("unsigned default is validated but not claimed", func(t *testing.T) {
		value := setup(t)
		if err := os.Remove(value.repomdPath + ".asc"); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := legacyCLIRunner()("init", "--adopt-content", "--config", value.configPath, "--repo", "yum-pgsql-el10")
		line := legacyScannedRepoLine(t, stdout, "yum-pgsql-el10")
		if code != ExitOK || !strings.HasSuffix(line, " metadata_signature=not-claimed") ||
			!strings.Contains(stdout, "yum_metadata_signature=not-claimed yum_metadata_keyring_sha256=-") {
			t.Fatalf("unsigned default code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
	})

	t.Run("explicit public key verifies signature", func(t *testing.T) {
		value := setup(t)
		publicBody, err := os.ReadFile(value.metadataPublic)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(publicBody)
		wantDigest := hex.EncodeToString(digest[:])
		code, stdout, stderr := legacyCLIRunner()("init", "--adopt-content", "--config", value.configPath, "--repo", "yum-pgsql-el10", "--legacy-metadata-keyring", filepath.Base(value.metadataPublic))
		line := legacyScannedRepoLine(t, stdout, "yum-pgsql-el10")
		if code != ExitOK || !strings.HasSuffix(line, " metadata_signature=verified") ||
			!strings.Contains(stdout, "yum_metadata_signature=verified yum_metadata_keyring_sha256="+wantDigest) {
			t.Fatalf("explicit trust code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
	})

	t.Run("explicit keyring requires detached signature", func(t *testing.T) {
		value := setup(t)
		if err := os.Remove(value.repomdPath + ".asc"); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := legacyCLIRunner()("init", "--adopt-content", "--config", value.configPath, "--repo", "yum-pgsql-el10", "--legacy-metadata-keyring", value.metadataPublic)
		if code != ExitVerification || !strings.Contains(stderr, "repomd.xml.asc") {
			t.Fatalf("missing signature code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		canonical := state.New(filepath.Join(value.root, ".sow"))
		ref, _ := state.ViewRef("latest", "yum-pgsql-el10", "el10", "x86_64")
		if _, exists, err := canonical.Ref(ref); err != nil || exists {
			t.Fatalf("failed signature verification advanced view exists=%v err=%v", exists, err)
		}
	})

	t.Run("new repository key cannot verify historical metadata", func(t *testing.T) {
		value := setup(t)
		code, stdout, stderr := legacyCLIRunner()("init", "--adopt-content", "--config", value.configPath, "--repo", "yum-pgsql-el10", "--legacy-metadata-keyring", value.repositoryPublic)
		if code != ExitVerification || !strings.Contains(stderr, "repomd.xml.asc") {
			t.Fatalf("wrong metadata key code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		canonical := state.New(filepath.Join(value.root, ".sow"))
		ref, _ := state.ViewRef("latest", "yum-pgsql-el10", "el10", "x86_64")
		if _, exists, err := canonical.Ref(ref); err != nil || exists {
			t.Fatalf("wrong metadata key advanced view exists=%v err=%v", exists, err)
		}
	})

	t.Run("every selected yum leaf must verify", func(t *testing.T) {
		value := setup(t)
		configText := fmt.Sprintf(`schema: sow/v1
state: {}
gpg: {public_key: %q}
pools: {public: {}, gated: {}}
repos:
  - id: yum-one
    type: yum
    path: yum/one/x86_64
    os: {family: el, major: 10, lifecycle: active}
    arches: [x86_64]
    default_pool: public
    yum: {compression: zstd, package_keyring: package-trust.asc}
  - id: yum-two
    type: yum
    path: yum/two/x86_64
    os: {family: el, major: 10, lifecycle: active}
    arches: [x86_64]
    default_pool: public
    yum: {compression: zstd, package_keyring: package-trust.asc}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge: {token_verifier: provider://test}
`, filepath.Base(value.repositoryPublic))
		if err := os.WriteFile(value.configPath, []byte(configText), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, repoRoot := range []string{"yum/one/x86_64", "yum/two/x86_64"} {
			writePigstyV1FlatYUM(t, filepath.Join(value.root, filepath.FromSlash(repoRoot)), value.rpmInput, value.metadataPrivate, "pgdg-redhat-nonfree-repo.rpm")
		}
		if err := os.Remove(filepath.Join(value.root, "yum", "two", "x86_64", "repodata", "repomd.xml.asc")); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := legacyCLIRunner()("init", "--adopt-content", "--config", value.configPath, "--repo", "yum-one,yum-two", "--legacy-metadata-keyring", value.metadataPublic)
		if code != ExitVerification || !strings.Contains(stderr, "repomd.xml.asc") {
			t.Fatalf("partial signed selection code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		canonical := state.New(filepath.Join(value.root, ".sow"))
		for _, repoID := range []string{"yum-one", "yum-two"} {
			ref, _ := state.ViewRef("latest", repoID, "el10", "x86_64")
			if _, exists, err := canonical.Ref(ref); err != nil || exists {
				t.Fatalf("partial signed selection advanced %s exists=%v err=%v", repoID, exists, err)
			}
		}
	})

	t.Run("private key is rejected before state mutation", func(t *testing.T) {
		value := setup(t)
		code, stdout, stderr := legacyCLIRunner()("init", "--adopt-content", "--config", value.configPath, "--repo", "yum-pgsql-el10", "--legacy-metadata-keyring", value.metadataPrivate)
		if code != ExitConfig || !strings.Contains(stderr, "public keys only") {
			t.Fatalf("private key code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		if _, err := os.Stat(filepath.Join(value.root, ".sow")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("invalid keyring mutated state: %v", err)
		}
	})

	t.Run("flag requires adopt content", func(t *testing.T) {
		code, stdout, stderr := legacyCLIRunner()("init", "--legacy-metadata-keyring", "unused.asc")
		if code != ExitUsage || !strings.Contains(stderr, "valid only with --adopt-content") {
			t.Fatalf("flag without adoption code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
	})

	t.Run("flag requires selected yum repo", func(t *testing.T) {
		root := t.TempDir()
		configPath := filepath.Join(root, "sow.yaml")
		if err := os.WriteFile(configPath, []byte(legacyAssetConfig("public")), 0o600); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := legacyCLIRunner()("init", "--adopt-content", "--config", configPath, "--repo", "assets", "--legacy-metadata-keyring", "unused.asc")
		if code != ExitUsage || !strings.Contains(stderr, "requires at least one selected YUM repository") {
			t.Fatalf("asset-only keyring code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		if _, err := os.Stat(filepath.Join(root, ".sow")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("asset-only keyring mutated state: %v", err)
		}
	})
}

func TestInitAdoptContentPigstyV1SuiteNestedAPTAndFlatYUM(t *testing.T) {
	root := nginxWorkerTempDir(t)
	privateKey, publicKey := writeLegacySigningKey(t, root)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(pigstyV1PackageConfig(filepath.Base(publicKey))), 0o600); err != nil {
		t.Fatal(err)
	}
	debInput := decodeLegacyFixture(t, filepath.Join("..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"), filepath.Join(root, "input.deb"))
	rpmInput := decodeLegacyFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "input.rpm"))
	run := legacyCLIRunner()
	for _, arguments := range [][]string{
		{"add", debInput, "--config", configPath, "--repo", "apt-pgsql-jammy", "--component", "main", "--gpg-private-key-file", privateKey},
		{"promote", "beta", "latest", "--config", configPath, "--repo", "apt-pgsql-jammy"},
		{"materialize", "latest", "--config", configPath, "--repo", "apt-pgsql-jammy", "--gpg-private-key-file", privateKey},
	} {
		if code, stdout, stderr := run(arguments...); code != ExitOK {
			t.Fatalf("prepare suite-nested APT %v code=%d stdout=%s stderr=%s", arguments, code, stdout, stderr)
		}
	}
	flatSource, canonicalRelative := writePigstyV1FlatYUM(t, filepath.Join(root, "yum", "pgsql", "el10.x86_64"), rpmInput, privateKey, "pgdg-redhat-nonfree-repo.rpm")
	if err := os.RemoveAll(filepath.Join(root, ".sow")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(root, ".pool")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(root, "_sow")); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	before := snapshotLegacyRepos(t, cfg, []string{"apt-pgsql-jammy", "yum-pgsql-el10"})
	code, stdout, stderr := run("init", "--adopt-content", "--config", configPath, "--repo", "apt-pgsql-jammy,yum-pgsql-el10", "--workers", "3", "--chunk-entries", "2")
	if code != ExitOK || !strings.Contains(stdout, "payloads=2") || !strings.Contains(stdout, "serving_tree_rewritten=false") {
		t.Fatalf("Pigsty-v1 adoption code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	after := snapshotLegacyRepos(t, cfg, []string{"apt-pgsql-jammy", "yum-pgsql-el10"})
	if !bytes.Equal(before, after) {
		t.Fatalf("Pigsty-v1 adoption rewrote source tree\nbefore:\n%s\nafter:\n%s", before, after)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	viewRef, _ := state.ViewRef("latest", "yum-pgsql-el10", "el10", "x86_64")
	viewCommit, exists, err := canonical.Ref(viewRef)
	if err != nil || !exists {
		t.Fatalf("flat YUM view exists=%v err=%v", exists, err)
	}
	viewPath, _ := state.ViewPath("latest", "yum-pgsql-el10", "el10", "x86_64")
	viewBody, err := canonical.OpenPathAt(viewCommit, viewPath)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := views.NewReader(viewBody).Next()
	if closeErr := viewBody.Close(); err != nil || closeErr != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
	wantCanonical := filepath.ToSlash(filepath.Join("yum", "pgsql", "el10.x86_64", canonicalRelative))
	if entry.Path != wantCanonical {
		t.Fatalf("canonical view path=%q want=%q", entry.Path, wantCanonical)
	}
	ledger, err := canonical.OpenPath("provenance/legacy/yum-pgsql-el10.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := provenance.NewLegacyAdoptionReader(ledger).Next()
	if closeErr := ledger.Close(); err != nil || closeErr != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
	wantSource := filepath.ToSlash(filepath.Join("yum", "pgsql", "el10.x86_64", flatSource))
	if receipt.SourcePath != wantSource || receipt.CanonicalPath != wantCanonical {
		t.Fatalf("flat receipt source=%q canonical=%q", receipt.SourcePath, receipt.CanonicalPath)
	}
	if code, stdout, stderr := run("fsck", "--config", configPath, "--repo", "apt-pgsql-jammy,yum-pgsql-el10"); code != ExitOK {
		t.Fatalf("post-adoption fsck code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	candidate := "migration-candidate"
	for _, arguments := range [][]string{
		{"materialize", "latest", "--config", configPath, "--repo", "apt-pgsql-jammy,yum-pgsql-el10", "--target", candidate, "--serving-base-url", "https://migration.example.invalid", "--gpg-private-key-file", privateKey},
	} {
		if code, stdout, stderr := run(arguments...); code != ExitOK {
			t.Fatalf("post-adoption %v code=%d stdout=%s stderr=%s", arguments, code, stdout, stderr)
		}
	}
	if _, err := os.Stat(filepath.Join(root, candidate, filepath.FromSlash(wantCanonical))); err != nil {
		t.Fatalf("canonical candidate RPM missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, candidate, filepath.FromSlash(wantSource))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("flat RPM leaked into candidate: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, candidate, "apt", "pgsql", "jammy", "dists", "jammy", "InRelease")); err != nil {
		t.Fatalf("suite-nested candidate APT missing: %v", err)
	}
	publicBody, err := os.ReadFile(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(publicBody), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	generation, err := yumrepo.ValidateDirectory(context.Background(), filepath.Join(root, candidate, "yum", "pgsql", "el10.x86_64", "repodata"), yumrepo.CompressionZstd, verifier)
	if err != nil || generation.Packages != 1 {
		t.Fatalf("canonical candidate YUM packages=%v err=%v", generation, err)
	}

	// Exercise the local cutover/rollback shape with the real suite-nested APT
	// and flat-source YUM candidate. The failed candidate is moved outside the
	// legacy origin before the source-tree byte proof is repeated.
	switchDir := t.TempDir()
	serving := filepath.Join(switchDir, "serving")
	candidateRoot := filepath.Join(root, candidate)
	if err := os.Symlink(candidateRoot, serving); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(serving, filepath.FromSlash(wantCanonical))); err != nil {
		t.Fatalf("cutover does not serve canonical RPM: %v", err)
	}
	candidateRPM := filepath.Join(candidateRoot, filepath.FromSlash(wantCanonical))
	if err := os.Remove(candidateRPM); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(candidateRPM); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("injected candidate payload loss was not observed: %v", err)
	}
	if err := os.Remove(serving); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, serving); err != nil {
		t.Fatal(err)
	}
	failedCandidate := filepath.Join(switchDir, "failed-candidate")
	if err := os.Rename(candidateRoot, failedCandidate); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(candidateRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed candidate remains inside legacy origin: %v", err)
	}
	if rolledBack := snapshotLegacyRepos(t, cfg, []string{"apt-pgsql-jammy", "yum-pgsql-el10"}); !bytes.Equal(before, rolledBack) {
		t.Fatalf("package rollback changed legacy bytes\nbefore:\n%s\nafter:\n%s", before, rolledBack)
	}
	// Replaying the same rollback target is safe and retains the untouched flat
	// source layout rather than the canonical candidate layout.
	resolvedRoot, rootErr := filepath.EvalSymlinks(root)
	if resolved, err := filepath.EvalSymlinks(serving); err != nil || rootErr != nil || resolved != resolvedRoot {
		t.Fatalf("rollback serving root=%q want=%q err=%v root_err=%v", resolved, resolvedRoot, err, rootErr)
	}
	if _, err := os.Stat(filepath.Join(serving, filepath.FromSlash(wantSource))); err != nil {
		t.Fatalf("rollback no longer serves flat legacy RPM: %v", err)
	}
}

func TestInitAdoptContentPrunesMissingYUMOnlyWithExactAuditedSet(t *testing.T) {
	root := nginxWorkerTempDir(t)
	privateKey, publicKey := writeLegacySigningKey(t, root)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(pigstyV1PackageConfig(filepath.Base(publicKey))), 0o600); err != nil {
		t.Fatal(err)
	}
	rpmInput := decodeLegacyFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "input.rpm"))
	yumRoot := filepath.Join(root, "yum", "pgsql", "el10.x86_64")
	flatSource, _ := writePigstyV1FlatYUM(t, yumRoot, rpmInput, privateKey, "pgdg-redhat-nonfree-repo.rpm")
	missingPath := filepath.Join(yumRoot, filepath.FromSlash(flatSource))
	if err := os.Remove(missingPath); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	before := snapshotLegacyRepos(t, cfg, []string{"yum-pgsql-el10"})
	run := legacyCLIRunner()

	validButUnreviewed := strings.Repeat("0", 64)
	if code, stdout, stderr := run("init", "--adopt-prune-missing-yum-confirm", validButUnreviewed, "--config", configPath, "--repo", "yum-pgsql-el10"); code != ExitUsage || !strings.Contains(stderr, "valid only with --adopt-content") {
		t.Fatalf("standalone prune confirmation code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}

	code, stdout, stderr := run("init", "--adopt-content", "--config", configPath, "--repo", "yum-pgsql-el10", "--workers", "2", "--chunk-entries", "1")
	if code != ExitVerification || !strings.Contains(stderr, "legacy-adoption-blocker kind=indexed-body-missing") || !strings.Contains(stderr, "path=yum/pgsql/el10.x86_64/"+flatSource) {
		t.Fatalf("default missing-body rejection code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	const digestMarker = "confirmation sha256="
	digestOffset := strings.Index(stderr, digestMarker)
	if digestOffset < 0 || len(stderr) < digestOffset+len(digestMarker)+64 {
		t.Fatalf("missing confirmation digest in stderr: %s", stderr)
	}
	confirmation := stderr[digestOffset+len(digestMarker) : digestOffset+len(digestMarker)+64]
	if parsed, err := repository.ParseDigest(confirmation); err != nil || parsed.String() != confirmation {
		t.Fatalf("reported confirmation=%q err=%v", confirmation, err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	viewRef, _ := state.ViewRef("latest", "yum-pgsql-el10", "el10", "x86_64")
	if _, exists, err := canonical.Ref(viewRef); err != nil || exists {
		t.Fatalf("default rejection advanced view exists=%v err=%v", exists, err)
	}
	assertLegacyPoolRegularFiles(t, root, 0)

	wrong := "0" + confirmation[1:]
	if confirmation[0] == '0' {
		wrong = "1" + confirmation[1:]
	}
	code, stdout, stderr = run("init", "--adopt-content", "--adopt-prune-missing-yum-confirm", wrong, "--config", configPath, "--repo", "yum-pgsql-el10")
	if code != ExitVerification || !strings.Contains(stderr, "blocker set changed") || !strings.Contains(stderr, "sha256="+confirmation) {
		t.Fatalf("stale prune confirmation code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if _, exists, err := canonical.Ref(viewRef); err != nil || exists {
		t.Fatalf("stale confirmation advanced view exists=%v err=%v", exists, err)
	}
	assertLegacyPoolRegularFiles(t, root, 0)

	repodataSnapshot := make(map[string][]byte)
	for _, name := range []string{"primary.xml.zst", "repomd.xml", "repomd.xml.asc"} {
		filename := filepath.Join(yumRoot, "repodata", name)
		body, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		repodataSnapshot[filename] = body
	}
	legacyAdoptionAfterPrunePreflightHook = func() error {
		changedSource, _ := writePigstyV1FlatYUM(t, yumRoot, rpmInput, privateKey, "changed-after-preflight.rpm")
		return os.Remove(filepath.Join(yumRoot, filepath.FromSlash(changedSource)))
	}
	t.Cleanup(func() { legacyAdoptionAfterPrunePreflightHook = nil })
	code, stdout, stderr = run("init", "--adopt-content", "--adopt-prune-missing-yum-confirm", confirmation, "--config", configPath, "--repo", "yum-pgsql-el10")
	legacyAdoptionAfterPrunePreflightHook = nil
	if code != ExitVerification || !strings.Contains(stderr, "legacy index candidate set changed") || !strings.Contains(stderr, "changed-after-preflight.rpm") {
		t.Fatalf("post-preflight index drift code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for filename, body := range repodataSnapshot {
		if err := os.WriteFile(filename, body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, exists, err := canonical.Ref(viewRef); err != nil || exists {
		t.Fatalf("post-preflight drift advanced view exists=%v err=%v", exists, err)
	}
	assertLegacyPoolRegularFiles(t, root, 0)

	code, stdout, stderr = run("init", "--adopt-content", "--adopt-prune-missing-yum-confirm", confirmation, "--config", configPath, "--repo", "yum-pgsql-el10", "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "confirmed_sha256="+confirmation+" entries=1") || !strings.Contains(stdout, "pruned_missing_yum=1") || !strings.Contains(stdout, "serving_tree_rewritten=false") {
		t.Fatalf("confirmed prune code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	after := snapshotLegacyRepos(t, cfg, []string{"yum-pgsql-el10"})
	if !bytes.Equal(before, after) {
		t.Fatalf("confirmed adoption rewrote legacy serving tree\nbefore:\n%s\nafter:\n%s", before, after)
	}
	assertLegacyPoolRegularFiles(t, root, 0)
	viewCommit, exists, err := canonical.Ref(viewRef)
	if err != nil || !exists {
		t.Fatalf("confirmed prune view exists=%v err=%v", exists, err)
	}
	viewPath, _ := state.ViewPath("latest", "yum-pgsql-el10", "el10", "x86_64")
	viewBody, err := canonical.OpenPathAt(viewCommit, viewPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := views.NewReader(viewBody).Next(); !errors.Is(err, io.EOF) {
		_ = viewBody.Close()
		t.Fatalf("pruned missing body remained in canonical view: %v", err)
	}
	if err := viewBody.Close(); err != nil {
		t.Fatal(err)
	}
	ledger, err := canonical.OpenPath("provenance/legacy-pruned/yum-pgsql-el10.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	prunes := provenance.NewLegacyIndexPruneReader(ledger)
	receipt, err := prunes.Next()
	if err != nil {
		_ = ledger.Close()
		t.Fatal(err)
	}
	wantPath := filepath.ToSlash(filepath.Join("yum", "pgsql", "el10.x86_64", flatSource))
	if receipt.Repo != "yum-pgsql-el10" || receipt.Path != wantPath || receipt.ConfirmationSHA256 != confirmation || receipt.Reason != "indexed-body-missing" {
		_ = ledger.Close()
		t.Fatalf("prune receipt=%+v", receipt)
	}
	if _, err := prunes.Next(); !errors.Is(err, io.EOF) {
		_ = ledger.Close()
		t.Fatalf("unexpected second prune receipt: %v", err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	code, replayOut, replayErr := run("init", "--adopt-content", "--adopt-prune-missing-yum-confirm", confirmation, "--config", configPath, "--repo", "yum-pgsql-el10")
	if code != ExitOK || !strings.Contains(replayOut, "changed=false") || !strings.Contains(replayOut, "pruned_missing_yum=1") {
		t.Fatalf("confirmed prune replay code=%d stdout=%s stderr=%s", code, replayOut, replayErr)
	}

	candidate := "repaired-missing-yum"
	code, stdout, stderr = run("materialize", "latest", "--config", configPath, "--repo", "yum-pgsql-el10", "--target", candidate, "--serving-base-url", "https://migration.example.invalid", "--gpg-private-key-file", privateKey)
	if code != ExitOK {
		t.Fatalf("materialize repaired YUM code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	publicBody, err := os.ReadFile(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(publicBody), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	generation, err := yumrepo.ValidateDirectory(context.Background(), filepath.Join(root, candidate, "yum", "pgsql", "el10.x86_64", "repodata"), yumrepo.CompressionZstd, verifier)
	if err != nil || generation.Packages != 0 {
		t.Fatalf("repaired YUM packages=%v err=%v", generation, err)
	}
	if code, stdout, stderr := run("fsck", "--config", configPath, "--repo", "yum-pgsql-el10"); code != ExitOK || !strings.Contains(stdout, "fsck legacy_prune_ledgers=1 receipts=1 confirmation_sets=1 drift=0") {
		t.Fatalf("post-prune fsck code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}

	safeHead, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	ledgerPath := "provenance/legacy-pruned/yum-pgsql-el10.jsonl"
	commitAssetProjectionState(t, root, []plumbing.Hash{safeHead}, time.Now().UTC(), "test: delete legacy prune ledger", nil, ledgerPath)
	if _, err := auditCanonicalLegacyIndexPruneLedgers(canonical); err == nil || !strings.Contains(err.Error(), "was deleted from HEAD") {
		t.Fatalf("canonical prune audit accepted historical ledger deletion: %v", err)
	}
	resetAssetProjectionHead(t, root, safeHead)
	canonical = state.New(filepath.Join(root, ".sow"))
	if _, err := auditCanonicalLegacyIndexPruneLedgers(canonical); err != nil {
		t.Fatalf("canonical prune audit did not recover after test-only HEAD reset: %v", err)
	}

	ledger, err = canonical.OpenPath(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	ledgerBody, readErr := io.ReadAll(ledger)
	if closeErr := ledger.Close(); readErr != nil || closeErr != nil {
		t.Fatal(errors.Join(readErr, closeErr))
	}
	tamperedBody := bytes.Replace(ledgerBody, []byte(confirmation), []byte(wrong), 1)
	if bytes.Equal(tamperedBody, ledgerBody) {
		t.Fatal("test did not alter the prune confirmation")
	}
	tamperedPath := filepath.Join(t.TempDir(), "legacy-pruned.jsonl")
	if err := os.WriteFile(tamperedPath, tamperedBody, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := canonical.InstallPaths(map[string]string{ledgerPath: tamperedPath}, "test: corrupt legacy prune confirmation"); err != nil || !changed {
		t.Fatalf("install corrupt prune ledger changed=%t err=%v", changed, err)
	}
	if _, err := auditCanonicalLegacyIndexPruneLedgers(canonical); err == nil || !strings.Contains(err.Error(), "changed across canonical history") {
		t.Fatalf("canonical prune audit accepted historical ledger replacement: %v", err)
	}
}

func assertLegacyPoolRegularFiles(t *testing.T, root string, want int) {
	t.Helper()
	count := 0
	err := filepath.WalkDir(filepath.Join(root, ".pool", "sha256"), func(_ string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			count++
		}
		return nil
	})
	if err != nil || count != want {
		t.Fatalf("CAS regular files=%d want=%d err=%v", count, want, err)
	}
}

func TestCanonicalLegacyYUMLocationAcceptsIndexProvenNestedSource(t *testing.T) {
	for _, test := range []struct {
		location string
		want     string
		ok       bool
	}{
		{"pkg-1.0-1.x86_64.rpm", "Packages/p/pkg-1.0-1.x86_64.rpm", true},
		{"Packages/p/pkg-1.0-1.x86_64.rpm", "Packages/p/pkg-1.0-1.x86_64.rpm", true},
		{"nested/pkg-1.0-1.x86_64.rpm", "Packages/p/pkg-1.0-1.x86_64.rpm", true},
		{"Packages/z/pkg-1.0-1.x86_64.rpm", "", false},
		{"../pkg-1.0-1.x86_64.rpm", "", false},
	} {
		got, err := canonicalLegacyYUMLocation("pkg", test.location)
		if test.ok && (err != nil || got != test.want) {
			t.Fatalf("location=%q got=%q err=%v", test.location, got, err)
		}
		if !test.ok && err == nil {
			t.Fatalf("location=%q unexpectedly canonicalized to %q", test.location, got)
		}
	}
}

func TestInitAdoptContentPigstyV1FlatYUMRejectsUnsupportedAndUnlistedRPM(t *testing.T) {
	for _, test := range []struct {
		name        string
		location    string
		addUnlisted bool
		tamper      bool
		want        string
	}{
		{name: "unlisted rpm", location: "pgdg-redhat-nonfree-repo.rpm", addUnlisted: true, want: "no repository index proves"},
		{name: "tampered indexed rpm", location: "pgdg-redhat-nonfree-repo.rpm", tamper: true, want: "checksum"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			privateKey, publicKey := writeLegacySigningKey(t, root)
			configPath := filepath.Join(root, "sow.yaml")
			if err := os.WriteFile(configPath, []byte(pigstyV1PackageConfig(filepath.Base(publicKey))), 0o600); err != nil {
				t.Fatal(err)
			}
			rpmInput := decodeLegacyFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "input.rpm"))
			yumRoot := filepath.Join(root, "yum", "pgsql", "el10.x86_64")
			flatSource, _ := writePigstyV1FlatYUM(t, yumRoot, rpmInput, privateKey, test.location)
			if test.addUnlisted {
				body, err := os.ReadFile(rpmInput)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(yumRoot, "unlisted.rpm"), body, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if test.tamper {
				file, err := os.OpenFile(filepath.Join(yumRoot, filepath.FromSlash(flatSource)), os.O_WRONLY|os.O_APPEND, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.Write([]byte("tamper")); err != nil {
					file.Close()
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			code, stdout, stderr := legacyCLIRunner()("init", "--adopt-content", "--config", configPath, "--repo", "yum-pgsql-el10")
			if code != ExitVerification || !strings.Contains(stderr, test.want) {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			canonical := state.New(filepath.Join(root, ".sow"))
			ref, _ := state.ViewRef("latest", "yum-pgsql-el10", "el10", "x86_64")
			if _, exists, err := canonical.Ref(ref); err != nil || exists {
				t.Fatalf("rejected adoption advanced view exists=%v err=%v", exists, err)
			}
			if ledger, err := canonical.OpenPath("provenance/legacy/yum-pgsql-el10.jsonl"); err == nil {
				ledger.Close()
				t.Fatal("rejected adoption committed ledger")
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			poolObjects, err := filepath.Glob(filepath.Join(root, ".pool", "sha256", "*", strings.Repeat("?", 64)))
			if err != nil {
				t.Fatal(err)
			}
			if len(poolObjects) != 0 {
				t.Fatalf("rejected transaction wrote %d CAS object(s) before package admission closed", len(poolObjects))
			}
		})
	}
}

func TestLegacyAdoptionPreflightTreatsDDEBAsPackagePayload(t *testing.T) {
	spool, err := newLegacyAdoptionSpool(filepath.Join(t.TempDir(), "adoption.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	manifestBody := "apt/repo/pool/main/p/pkg/pkg_1_amd64.ddeb\t1\t" + strings.Repeat("a", 64) + "\n" +
		"apt/repo/pool/main/p/pkg/pkg_2_amd64.deb\t2\t" + strings.Repeat("b", 64) + "\n"
	if err := spool.seedBaseline("apt-repo", strings.NewReader(manifestBody)); err != nil {
		t.Fatal(err)
	}
	if err := spool.recordEveryUnindexedPackage("apt-repo", "apt", false); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(t.TempDir(), ".sow")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	report, err := spool.writeBlockerReport(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	err = report.asError("repo apt-repo contains 2 package(s) that no repository index proves; adoption refuses to guess membership")
	if err == nil || !strings.Contains(err.Error(), ".ddeb") || !strings.Contains(err.Error(), "pkg_2_amd64.deb") ||
		!strings.Contains(err.Error(), "size=2") || !strings.Contains(err.Error(), strings.Repeat("b", 64)) {
		t.Fatalf("unindexed ddeb escaped package admission: %v", err)
	}
}

func TestLegacyAdoptionBlockerReportIsSortedAndComplete(t *testing.T) {
	spool, err := newLegacyAdoptionSpool(filepath.Join(t.TempDir(), "adoption.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	blockers := []legacyAdoptionBlocker{
		{kind: "indexed-body-missing", repo: "z-repo", path: "z.rpm", size: 2, sha256: strings.Repeat("b", 64), name: "z", version: "2-1", arch: "x86_64"},
		{kind: "body-without-index", repo: "a-repo", path: "a.deb", size: 1, sha256: strings.Repeat("a", 64)},
	}
	for _, blocker := range blockers {
		if _, err := spool.db.Exec(`INSERT INTO blocker(kind,repo,path,name,version,arch,size,sha256) VALUES(?,?,?,?,?,?,?,?)`,
			blocker.kind, blocker.repo, blocker.path, blocker.name, blocker.version, blocker.arch, blocker.size, blocker.sha256); err != nil {
			t.Fatal(err)
		}
	}
	stateDir := filepath.Join(t.TempDir(), ".sow")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	report, err := spool.writeBlockerReport(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	text := report.asError("found 2 blockers").Error()
	if report.Count != 2 || !strings.Contains(text, "found 2 blockers") || !strings.Contains(text, "name=z version=2-1 arch=x86_64") {
		t.Fatalf("incomplete blocker report: %s", text)
	}
	if strings.Index(text, "repo=a-repo") > strings.Index(text, "repo=z-repo") {
		t.Fatalf("blocker report is not deterministic: %s", text)
	}
}

func TestLegacyAdoptionLargeNegativeInventoryIsDiskBackedAndBounded(t *testing.T) {
	spool, err := newLegacyAdoptionSpool(filepath.Join(t.TempDir(), "adoption.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	const count = 100
	blockers := make([]legacyAdoptionBlocker, count)
	repo := config.Repo{ID: "yum-pgdg"}
	if err := spool.admitIndexed(context.Background(), repo.ID, func(_ context.Context, emit func(legacyCandidate) error) error {
		for index := range blockers {
			blockers[index] = legacyAdoptionBlocker{
				kind: "indexed-body-missing", repo: repo.ID, path: fmt.Sprintf("yum/pgdg/missing-%03d.rpm", index),
				name: fmt.Sprintf("missing-%03d", index), version: "1-1", arch: "x86_64", size: int64(index + 1), sha256: fmt.Sprintf("%064x", index+1),
			}
			blocker := blockers[index]
			if err := emit(legacyCandidate{repo: repo, blocker: &blocker}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(t.TempDir(), ".sow")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	report, err := spool.writeBlockerReport(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Count != count || len(report.Preview) != legacyAdoptionBlockerPreviewLimit {
		t.Fatalf("report count=%d preview=%d", report.Count, len(report.Preview))
	}
	body, err := os.ReadFile(report.Path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	if hex.EncodeToString(digest[:]) != report.SHA256 || bytes.Count(body, []byte{'\n'}) != count {
		t.Fatalf("report digest=%x want=%s lines=%d", digest, report.SHA256, bytes.Count(body, []byte{'\n'}))
	}
	message := report.asError("blocked").Error()
	if len(message) > 12_000 || !strings.Contains(message, "omitted=80") || !strings.Contains(message, report.Path) {
		t.Fatalf("unbounded or incomplete blocker summary bytes=%d message=%s", len(message), message)
	}
	identities := make([]provenance.LegacyIndexPruneIdentity, 0, len(blockers))
	for _, blocker := range blockers {
		identities = append(identities, provenance.LegacyIndexPruneIdentity{
			Repo: blocker.repo, Path: blocker.path, Name: blocker.name, Version: blocker.version, Arch: blocker.arch,
			ArtifactSize: blocker.size, ArtifactSHA256: blocker.sha256,
		})
	}
	wantConfirmation, err := provenance.LegacyIndexPruneSetSHA256(identities)
	if err != nil {
		t.Fatal(err)
	}
	gotConfirmation, err := spool.legacyIndexPruneDigest()
	if err != nil || gotConfirmation != wantConfirmation {
		t.Fatalf("streamed confirmation=%s want=%s err=%v", gotConfirmation, wantConfirmation, err)
	}
}

func TestLegacyAdoptionComparesDebianVersionsSemantically(t *testing.T) {
	if !sameLegacyDebianVersion("0.3.16~3-0~debian-bookworm", "0:0.3.16~3-0~debian-bookworm") {
		t.Fatal("explicit Debian epoch zero was treated as a different package body")
	}
	if sameLegacyDebianVersion("1:0.3.16-1", "0:0.3.16-1") {
		t.Fatal("different Debian epochs were treated as equal")
	}
}

func TestLegacyAdoptionSpoolAllowsIdenticalAliasesAndRejectsByteCollision(t *testing.T) {
	spool, err := newLegacyAdoptionSpool(filepath.Join(t.TempDir(), "adoption.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	entry := views.Entry{Repo: "yum-pgsql-el10", OS: "el10", Arch: "x86_64", Name: "pkg", Version: "1-1", Path: "yum/pgsql/el10.x86_64/Packages/p/pkg.rpm", Size: 1, SHA256: strings.Repeat("a", 64), Pool: "public"}
	first := legacyImported{entry: entry, format: "rpm", sourcePath: "yum/pgsql/el10.x86_64/pkg.rpm", canonicalPath: entry.Path}
	if _, err := spool.addImported(first); err != nil {
		t.Fatal(err)
	}
	second := first
	second.sourcePath = "yum/pgsql/el10.x86_64/Packages/p/pkg.rpm"
	if _, err := spool.addImported(second); err != nil {
		t.Fatalf("byte-identical canonical alias rejected: %v", err)
	}
	third := second
	third.sourcePath = "yum/pgsql/el10.x86_64/nested/pkg.rpm"
	third.entry.SHA256 = strings.Repeat("b", 64)
	if _, err := spool.addImported(third); err == nil || !strings.Contains(err.Error(), "conflicting legacy canonical destination") {
		t.Fatalf("canonical collision err=%v", err)
	}
}

func TestLegacyAdoptionSpoolConcurrentCanonicalDestinationCollision(t *testing.T) {
	spool, err := newLegacyAdoptionSpool(filepath.Join(t.TempDir(), "adoption.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	entry := views.Entry{Repo: "yum-pgsql-el10", OS: "el10", Arch: "x86_64", Name: "pkg", Version: "1-1", Path: "yum/pgsql/el10.x86_64/Packages/p/pkg.rpm", Size: 1, SHA256: strings.Repeat("a", 64), Pool: "public"}
	imports := []legacyImported{
		{entry: entry, format: "rpm", sourcePath: "yum/pgsql/el10.x86_64/pkg.rpm", canonicalPath: entry.Path},
		{entry: entry, format: "rpm", sourcePath: "yum/pgsql/el10.x86_64/Packages/p/pkg.rpm", canonicalPath: entry.Path},
	}
	imports[1].entry.SHA256 = strings.Repeat("b", 64)
	start := make(chan struct{})
	results := make(chan error, len(imports))
	for _, imported := range imports {
		imported := imported
		go func() {
			<-start
			_, err := spool.addImported(imported)
			results <- err
		}()
	}
	close(start)
	succeeded, rejected := 0, 0
	for range imports {
		err := <-results
		switch {
		case err == nil:
			succeeded++
		case strings.Contains(err.Error(), "conflicting legacy canonical destination"), strings.Contains(err.Error(), "conflicting legacy package membership"):
			rejected++
		default:
			t.Fatalf("unexpected concurrent collision error: %v", err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("concurrent canonical collision succeeded=%d rejected=%d", succeeded, rejected)
	}
}

func TestLegacyAdoptionSpoolConfiguresEverySQLiteConnection(t *testing.T) {
	spool, err := newLegacyAdoptionSpool(filepath.Join(t.TempDir(), "adoption.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	connections := make([]*sql.Conn, 0, 8)
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()
	for range 8 {
		connection, err := spool.db.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, connection)
		var timeout int
		if err := connection.QueryRowContext(context.Background(), `PRAGMA busy_timeout`).Scan(&timeout); err != nil {
			t.Fatal(err)
		}
		if timeout != legacyAdoptionBusyTimeoutMS {
			t.Fatalf("connection %d busy_timeout=%d want=%d", len(connections), timeout, legacyAdoptionBusyTimeoutMS)
		}
	}
}

func TestLegacyAdoptionSpoolConcurrentPruneAndPayloadWriters(t *testing.T) {
	spool, err := newLegacyAdoptionSpool(filepath.Join(t.TempDir(), "adoption.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	const count = 64
	blockers := make([]legacyAdoptionBlocker, count)
	if err := spool.admitIndexed(context.Background(), "yum-pgdg", func(_ context.Context, emit func(legacyCandidate) error) error {
		for i := range blockers {
			blockers[i] = legacyAdoptionBlocker{
				kind: "indexed-body-missing", repo: "yum-pgdg", path: fmt.Sprintf("yum/pgdg/missing-%03d.rpm", i),
				name: fmt.Sprintf("missing-%03d", i), version: "1-1", arch: "x86_64", size: int64(i + 1), sha256: fmt.Sprintf("%064x", i+1),
			}
			blocker := blockers[i]
			if err := emit(legacyCandidate{repo: config.Repo{ID: "yum-pgdg"}, blocker: &blocker}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, count*2)
	for i := range count {
		i := i
		go func() {
			<-start
			results <- spool.markPrunedYUMBlockerReobserved(blockers[i])
		}()
		go func() {
			<-start
			sha := fmt.Sprintf("%064x", count+i+1)
			path := fmt.Sprintf("yum/pgdg/Packages/p/pkg-%03d.rpm", i)
			_, err := spool.addImported(legacyImported{
				entry:  views.Entry{Repo: "yum-pgdg", OS: "el10", Arch: "x86_64", Name: fmt.Sprintf("pkg-%03d", i), Version: "1-1", Path: path, Size: int64(i + 1), SHA256: sha, Pool: "public"},
				format: "rpm", sourcePath: path, canonicalPath: path,
			})
			results <- err
		}()
	}
	close(start)
	for range count * 2 {
		if err := <-results; err != nil {
			t.Fatalf("concurrent spool writer failed: %v", err)
		}
	}
	if err := spool.requireEveryPrunedYUMBlockerReobserved(); err != nil {
		t.Fatal(err)
	}
	var payloads int
	if err := spool.db.QueryRow(`SELECT COUNT(*) FROM payload`).Scan(&payloads); err != nil {
		t.Fatal(err)
	}
	if payloads != count {
		t.Fatalf("payloads=%d want=%d", payloads, count)
	}
}

func TestLegacyRPMSeparateNoarchRoutesReplicasToOneLeaf(t *testing.T) {
	repo := config.Repo{Type: "yum", Arches: []string{"aarch64", "noarch", "x86_64"}, YUM: &config.YUMConfig{NoarchMode: config.YUMNoarchSeparate}}
	for _, source := range []string{"aarch64", "noarch", "x86_64"} {
		if got, err := legacyRPMTargetArch(repo, source, "noarch"); err != nil || got != "noarch" {
			t.Fatalf("source=%s separate noarch target=%q err=%v", source, got, err)
		}
	}
	if got, err := legacyRPMTargetArch(repo, "aarch64", "aarch64"); err != nil || got != "aarch64" {
		t.Fatalf("native target=%q err=%v", got, err)
	}
	if got, err := legacyRPMTargetArch(repo, "aarch64", "src"); err != nil || got != "aarch64" {
		t.Fatalf("legacy source RPM target=%q err=%v", got, err)
	}
	if _, err := legacyRPMTargetArch(repo, "noarch", "aarch64"); err == nil {
		t.Fatal("architecture-specific RPM was accepted from the noarch source leaf")
	}
}

func legacyCLIRunner() func(...string) (int, string, string) {
	return func(arguments ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(arguments, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
}

func legacyScannedRepoLine(t *testing.T, stdout, repoID string) string {
	t.Helper()
	prefix := "adopt-content scanned repo=" + repoID + " "
	matched := ""
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		if matched != "" {
			t.Fatalf("duplicate adoption scan lines for %s in output:\n%s", repoID, stdout)
		}
		matched = line
	}
	if matched == "" {
		t.Fatalf("missing adoption scan line for %s in output:\n%s", repoID, stdout)
	}
	return matched
}

func legacyAssetConfig(pool string) string {
	return fmt.Sprintf(`schema: sow/v1
state: {}
gpg: {}
pools:
  public: {}
  gated: {}
repos:
  - id: assets
    type: asset
    path: pkg
    default_pool: %s
    asset: {kind: release, mutable_paths: [pig/latest]}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge: {token_verifier: provider://test}
`, pool)
}

func legacyPackageConfig(publicKey string) string {
	return fmt.Sprintf(`schema: sow/v1
state: {}
gpg: {public_key: %q}
pools:
  public: {}
  gated: {}
repos:
  - id: apt-legacy
    type: apt
    path: apt/test
    os: {suite: jammy, lifecycle: active}
    arches: [arm64]
    default_pool: public
    apt: {suites: [jammy], components: [main]}
  - id: yum-legacy
    type: yum
    path: yum/test/x86_64
    os: {family: el, major: 10, lifecycle: active}
    arches: [x86_64]
    default_pool: public
    yum: {compression: zstd, package_keyring: package-trust.asc}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
serving:
  latest: {base_url: "https://repo.example.invalid"}
  beta: {base_url: "https://beta.example.invalid"}
  stable: {base_url: "https://repo.example.invalid/pro/v1/basic"}
targets: {}
edge: {token_verifier: provider://test}
`, publicKey)
}

func legacySeparateYUMConfig(publicKey string) string {
	return fmt.Sprintf(`schema: sow/v1
state: {}
gpg: {public_key: %q}
pools: {public: {}, gated: {}}
repos:
  - id: yum-percona-el10
    type: yum
    path: yum/percona/el10.{arch}
    os: {family: el, major: 10, lifecycle: active}
    arches: [x86_64, noarch]
    default_pool: public
    yum: {compression: zstd, package_keyring: package-trust.asc, noarch_mode: separate}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge: {token_verifier: provider://test}
`, publicKey)
}

const legacySharedPoolAPTConfig = `schema: sow/v1
state: {}
gpg: {}
pools: {public: {}, gated: {}}
repos:
  - id: apt-legacy
    type: apt
    path: apt/test
    os: {family: ubuntu, lifecycle: active}
    arches: [arm64]
    default_pool: public
    apt:
      suites: [jammy, noble]
      components: [main]
      suite_lifecycle: {jammy: active, noble: active}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge: {token_verifier: provider://test}
`

const legacySparseAPTConfig = `schema: sow/v1
state: {}
gpg: {}
pools: {public: {}, gated: {}}
repos:
  - id: apt-pgdg
    type: apt
    path: apt/pgdg
    os: {family: debian, lifecycle: active}
    arches: [arm64]
    default_pool: public
    apt:
      suites: [bookworm-pgdg, bookworm-pgdg-testing]
      components: [main, "18", "19"]
      suite_components:
        bookworm-pgdg: [main]
        bookworm-pgdg-testing: [main, "18", "19"]
      suite_lifecycle:
        bookworm-pgdg: active
        bookworm-pgdg-testing: active
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge: {token_verifier: provider://test}
`

func pigstyV1PackageConfig(publicKey string) string {
	return fmt.Sprintf(`schema: sow/v1
state: {}
gpg: {public_key: %q}
pools: {public: {}, gated: {}}
repos:
  - id: apt-pgsql-jammy
    type: apt
    path: apt/pgsql/jammy
    os: {family: ubuntu, major: 22, suite: jammy, lifecycle: active}
    arches: [arm64]
    default_pool: public
    apt: {suites: [jammy], components: [main]}
  - id: yum-pgsql-el10
    type: yum
    path: yum/pgsql/el10.x86_64
    os: {family: el, major: 10, lifecycle: active}
    arches: [x86_64]
    default_pool: public
    yum: {compression: zstd, package_keyring: package-trust.asc}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
serving:
  latest: {base_url: "https://repo.example.invalid"}
  beta: {base_url: "https://beta.example.invalid"}
  stable: {base_url: "https://repo.example.invalid/pro/v1/basic"}
targets: {}
edge: {token_verifier: provider://test}
`, publicKey)
}

func writePigstyV1FlatYUM(t *testing.T, root, rpmInput, privateKey, location string) (string, string) {
	t.Helper()
	body, err := os.ReadFile(rpmInput)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "repodata"), 0o755); err != nil {
		t.Fatal(err)
	}
	packagePath := filepath.Join(root, filepath.FromSlash(location))
	if err := os.MkdirAll(filepath.Dir(packagePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(packagePath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := yumrepo.InspectPackage(context.Background(), yumrepo.PackageInput{Path: packagePath, Basename: pathBase(location)})
	if err != nil {
		t.Fatal(err)
	}
	primary := []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" packages="1"><package type="rpm"><name>%s</name><arch>%s</arch><version epoch="%d" ver="%s" rel="%s"/><checksum type="sha256" pkgid="YES">%s</checksum><size package="%d" installed="1" archive="1"/><location href="%s"/><format xmlns:rpm="http://linux.duke.edu/metadata/rpm"/></package></metadata>
`, info.Name, info.Arch, info.Epoch, info.Version, info.Release, info.SHA256, info.Size, location))
	var compressed bytes.Buffer
	encoder, err := zstd.NewWriter(&compressed, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := encoder.Write(primary); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	compressedSHA, openSHA := sha256.Sum256(compressed.Bytes()), sha256.Sum256(primary)
	primaryRelative := "repodata/primary.xml.zst"
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(primaryRelative)), compressed.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	repomd := []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo"><revision>1</revision><data type="primary"><checksum type="sha256">%s</checksum><open-checksum type="sha256">%s</open-checksum><location href="%s"/><timestamp>1</timestamp><size>%d</size><open-size>%d</open-size></data></repomd>
`, hex.EncodeToString(compressedSHA[:]), hex.EncodeToString(openSHA[:]), primaryRelative, compressed.Len(), len(primary)))
	repomdPath := filepath.Join(root, "repodata", "repomd.xml")
	if err := os.WriteFile(repomdPath, repomd, 0o644); err != nil {
		t.Fatal(err)
	}
	keyBody, err := os.ReadFile(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(keyBody), nil, time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	var signature bytes.Buffer
	if err := signer.Sign(context.Background(), bytes.NewReader(repomd), &signature); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(repomdPath+".asc", signature.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return location, info.Location
}

func pathBase(value string) string {
	parts := strings.Split(value, "/")
	return parts[len(parts)-1]
}

func legacyPartialFailureConfig() string {
	return `schema: sow/v1
state: {}
gpg: {}
pools:
  public: {}
  gated: {}
repos:
  - id: assets
    type: asset
    path: pkg
    default_pool: public
    asset: {kind: release}
  - id: z-apt-bad
    type: apt
    path: apt/bad
    os: {suite: jammy, lifecycle: active}
    arches: [arm64]
    default_pool: public
    apt: {suites: [jammy], components: [main]}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets: {}
edge: {token_verifier: provider://test}
`
}

func writeLegacySigningKey(t *testing.T, root string) (string, string) {
	t.Helper()
	writeRPMPackageTrustFixture(t, root)
	created := time.Unix(1_500_000_000, 0).UTC()
	entity, err := openpgp.NewEntity("SOW Legacy Adoption", "", "legacy@example.invalid", &packet.Config{Time: func() time.Time { return created }, RSABits: testOpenPGPRSABits})
	if err != nil {
		t.Fatal(err)
	}
	var private, public bytes.Buffer
	if err := entity.SerializePrivate(&private, &packet.Config{Time: func() time.Time { return created }}); err != nil {
		t.Fatal(err)
	}
	if err := entity.Serialize(&public); err != nil {
		t.Fatal(err)
	}
	privatePath, publicPath := filepath.Join(root, "legacy-private.key"), filepath.Join(root, "legacy-public.key")
	if err := os.WriteFile(privatePath, private.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, public.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return privatePath, publicPath
}

func writeLegacyMetadataSigningKey(t *testing.T, root string) (string, string) {
	t.Helper()
	created := time.Unix(1_500_000_100, 0).UTC()
	entity, err := openpgp.NewEntity("SOW Historical Metadata", "", "historical-metadata@example.invalid", &packet.Config{Time: func() time.Time { return created }, RSABits: testOpenPGPRSABits})
	if err != nil {
		t.Fatal(err)
	}
	var private, public bytes.Buffer
	if err := entity.SerializePrivate(&private, &packet.Config{Time: func() time.Time { return created }}); err != nil {
		t.Fatal(err)
	}
	if err := entity.Serialize(&public); err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(root, "historical-metadata-private.key")
	publicPath := filepath.Join(root, "historical-metadata-public.key")
	if err := os.WriteFile(privatePath, private.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, public.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return privatePath, publicPath
}

func snapshotLegacyRepos(t *testing.T, cfg *config.Config, repoIDs []string) []byte {
	t.Helper()
	var output bytes.Buffer
	for _, id := range repoIDs {
		repo, exists := cfg.RepoByName(id)
		if !exists {
			t.Fatal(id)
		}
		filename := filepath.Join(t.TempDir(), id+".tsv")
		if _, err := scanRepoManifest(context.Background(), cfg, repo, filename, manifest.ScanOptions{Workers: 2, ChunkEntries: 2, TempDir: filepath.Join(cfg.StatePath(), "tmp")}); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&output, "[%s]\n", id)
		output.Write(data)
	}
	return output.Bytes()
}

func decodeLegacyFixture(t *testing.T, source, destination string) string {
	t.Helper()
	encoded, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	body, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return destination
}
