package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

func TestGCDryRunConfirmationAndHistoryRoots(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	reachable, err := pool.Put(context.Background(), strings.NewReader("reachable"))
	if err != nil {
		t.Fatal(err)
	}
	orphan, err := pool.Put(context.Background(), strings.NewReader("orphan"))
	if err != nil {
		t.Fatal(err)
	}
	entry := views.Entry{Repo: "asset", OS: "all", Arch: "all", Name: "reachable", Version: "1", Path: "asset/reachable", Size: reachable.Size, SHA256: reachable.HashString(), Pool: "public"}
	var encoded bytes.Buffer
	if err := views.WriteEntry(&encoded, entry); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, ".sow", "seed.tsv")
	if err := os.MkdirAll(filepath.Dir(stage), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stage, encoded.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	viewPath, _ := state.ViewPath("beta", "asset", "all", "all")
	commit, _, err := canonical.InstallPaths(map[string]string{
		"config/sow.yaml": configPath,
		viewPath:          stage,
	}, "seed GC root")
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := state.ViewRef("beta", "asset", "all", "all")
	if err := canonical.AdvanceRef(ref, plumbing.ZeroHash, commit, false); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := Main([]string{"gc", "--config", configPath}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("gc dry run code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "orphans=1") || !strings.Contains(stdout.String(), orphan.HashString()) {
		t.Fatalf("dry run omitted orphan evidence: %s", stdout.String())
	}
	match := regexp.MustCompile(`orphan_set_sha256=([0-9a-f]{64})`).FindStringSubmatch(stdout.String())
	if len(match) != 2 {
		t.Fatalf("missing confirmation digest: %s", stdout.String())
	}
	if _, err := os.Stat(pool.ObjectPath(orphan.SHA256)); err != nil {
		t.Fatalf("dry run deleted orphan: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Main([]string{"gc", "--config", configPath, "--apply", "--confirm", strings.Repeat("0", 64)}, &stdout, &stderr); code != ExitConflict {
		t.Fatalf("stale confirmation code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Main([]string{"gc", "--config", configPath, "--apply", "--confirm", match[1]}, &stdout, &stderr); code != ExitOK || !strings.Contains(stdout.String(), "deleted=1") {
		t.Fatalf("gc apply code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(pool.ObjectPath(orphan.SHA256)); !os.IsNotExist(err) {
		t.Fatalf("confirmed orphan remains: %v", err)
	}
	if _, err := os.Stat(pool.ObjectPath(reachable.SHA256)); err != nil {
		t.Fatalf("history root was deleted: %v", err)
	}
}

func TestGCRemoteInventoryIsNotACASRoot(t *testing.T) {
	root := t.TempDir()
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	object, err := pool.Put(context.Background(), strings.NewReader("source-object"))
	if err != nil {
		t.Fatal(err)
	}
	remoteOnly := strings.Repeat("f", 64)
	contentPath := filepath.Join(root, "content.tsv")
	inventoryPath := filepath.Join(root, "inventory.tsv")
	var content, inventory bytes.Buffer
	var contentHash [32]byte
	copy(contentHash[:], object.SHA256[:])
	if err := manifest.WriteEntry(&content, manifest.Entry{Path: "asset/source", Size: object.Size, SHA256: contentHash}); err != nil {
		t.Fatal(err)
	}
	missingRemoteSource, err := repository.ParseDigest(strings.Repeat("e", 64))
	if err != nil {
		t.Fatal(err)
	}
	var missingSourceHash [32]byte
	copy(missingSourceHash[:], missingRemoteSource[:])
	if err := manifest.WriteEntry(&content, manifest.Entry{Path: "asset/zero-byte-adopted", Size: 99, SHA256: missingSourceHash}); err != nil {
		t.Fatal(err)
	}
	decoded, err := repository.ParseDigest(remoteOnly)
	if err != nil {
		t.Fatal(err)
	}
	var remoteHash [32]byte
	copy(remoteHash[:], decoded[:])
	if err := manifest.WriteEntry(&inventory, manifest.Entry{Path: ".sow/generations/00000000000000000001/generation.json", Size: 123, SHA256: remoteHash}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(contentPath, content.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inventoryPath, inventory.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	if _, _, err := canonical.InstallPaths(map[string]string{
		"remotes/cf/content.tsv":   contentPath,
		"remotes/cf/inventory.tsv": inventoryPath,
	}, "seed remote audit state"); err != nil {
		t.Fatal(err)
	}
	roots, _, err := collectCanonicalRoots(context.Background(), canonical, pool, config.DefaultCASHistory)
	if err != nil {
		t.Fatal(err)
	}
	report, err := pool.Audit(context.Background(), roots)
	if err != nil {
		t.Fatal(err)
	}
	if report.Stats.MissingObjects != 0 || roots.Len() != 1 {
		t.Fatalf("remote inventory leaked into CAS roots: roots=%d report=%+v", roots.Len(), report.Stats)
	}
}

func TestGCLocalServingGenerationManifestIsAStrictCASRoot(t *testing.T) {
	root := t.TempDir()
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	object, err := pool.Put(t.Context(), strings.NewReader("generation-only-metadata"))
	if err != nil {
		t.Fatal(err)
	}
	var digest [32]byte
	copy(digest[:], object.SHA256[:])
	var body bytes.Buffer
	if err := manifest.WriteEntry(&body, manifest.Entry{Path: "yum/test/x86_64/repodata/repomd.xml", Size: object.Size, SHA256: digest}); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, "generation.tsv")
	if err := os.WriteFile(stage, body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	canonicalPath := "serving/yum/generations/00000000000000000001/latest/rpm-test/el10/x86_64.tsv"
	if _, _, err := canonical.InstallPaths(map[string]string{canonicalPath: stage}, "seed local serving generation"); err != nil {
		t.Fatal(err)
	}
	roots, _, err := collectCanonicalRoots(t.Context(), canonical, pool, 1)
	if err != nil {
		t.Fatal(err)
	}
	report, err := pool.Audit(t.Context(), roots)
	if err != nil || report.Stats.ReachableObjects != 1 || report.Stats.OrphanObjects != 0 || roots.Count(object.SHA256) != 1 {
		t.Fatalf("local serving root count=%d report=%+v err=%v", roots.Count(object.SHA256), report.Stats, err)
	}

	missing := strings.Repeat("f", 64)
	missingDigest, _ := repository.ParseDigest(missing)
	copy(digest[:], missingDigest[:])
	body.Reset()
	if err := manifest.WriteEntry(&body, manifest.Entry{Path: "yum/test/x86_64/repodata/repomd.xml", Size: 99, SHA256: digest}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stage, body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := canonical.InstallPaths(map[string]string{"serving/yum/generations/00000000000000000002/latest/rpm-test/el10/x86_64.tsv": stage}, "seed missing generation object"); err != nil {
		t.Fatal(err)
	}
	roots, _, err = collectCanonicalRoots(t.Context(), canonical, pool, 1)
	if err != nil {
		t.Fatal(err)
	}
	report, err = pool.Audit(t.Context(), roots)
	if err != nil || report.Stats.MissingObjects != 1 {
		t.Fatalf("missing generation object was silently skipped report=%+v err=%v", report.Stats, err)
	}
}

func TestGCRemovedServingLedgerIsNotPinnedByGitHistory(t *testing.T) {
	root := t.TempDir()
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	retired, err := pool.Put(t.Context(), strings.NewReader("retired-serving-generation"))
	if err != nil {
		t.Fatal(err)
	}
	var digest [32]byte
	copy(digest[:], retired.SHA256[:])
	var body bytes.Buffer
	if err := manifest.WriteEntry(&body, manifest.Entry{Path: "yum/test/x86_64/repodata/repomd.xml", Size: retired.Size, SHA256: digest}); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, "retired-generation.tsv")
	if err := os.WriteFile(stage, body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	canonicalPath := "serving/yum/generations/00000000000000000001/latest/rpm-test/el10/x86_64.tsv"
	if _, _, err := canonical.InstallPaths(map[string]string{canonicalPath: stage}, "seed retained generation"); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := canonical.Apply(t.Context(), "test", "retire serving generation", nil, nil, state.ApplyOptions{DeletePaths: []string{canonicalPath}}); err != nil || !changed {
		t.Fatalf("delete canonical generation changed=%v err=%v", changed, err)
	}

	roots, _, err := collectCanonicalRoots(t.Context(), canonical, pool, config.DefaultCASHistory)
	if err != nil {
		t.Fatal(err)
	}
	report, err := pool.Audit(t.Context(), roots)
	if err != nil {
		t.Fatal(err)
	}
	if roots.Count(retired.SHA256) != 0 || report.Stats.OrphanObjects != 1 {
		t.Fatalf("deleted serving ledger remained history-rooted count=%d report=%+v", roots.Count(retired.SHA256), report.Stats)
	}
}

func TestGCHistoryRetentionIsBoundedAndExplicit(t *testing.T) {
	root := t.TempDir()
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	retired, err := pool.Put(context.Background(), strings.NewReader("retired"))
	if err != nil {
		t.Fatal(err)
	}
	entry := views.Entry{Repo: "asset", OS: "all", Arch: "all", Name: "retired", Version: "1", Path: "asset/retired", Size: retired.Size, SHA256: retired.HashString(), Pool: "public"}
	var oldView bytes.Buffer
	if err := views.WriteEntry(&oldView, entry); err != nil {
		t.Fatal(err)
	}
	oldPath := filepath.Join(root, "old.tsv")
	emptyPath := filepath.Join(root, "empty.tsv")
	if err := os.WriteFile(oldPath, oldView.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(emptyPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	viewPath, _ := state.ViewPath("beta", "asset", "all", "all")
	ref, _ := state.ViewRef("beta", "asset", "all", "all")
	first, _, err := canonical.InstallPaths(map[string]string{viewPath: oldPath}, "old membership")
	if err != nil {
		t.Fatal(err)
	}
	if err := canonical.AdvanceRef(ref, plumbing.ZeroHash, first, false); err != nil {
		t.Fatal(err)
	}
	second, _, err := canonical.InstallPaths(map[string]string{viewPath: emptyPath}, "remove membership")
	if err != nil {
		t.Fatal(err)
	}
	if err := canonical.AdvanceRef(ref, first, second, false); err != nil {
		t.Fatal(err)
	}

	currentOnly, _, err := collectCanonicalRoots(context.Background(), canonical, pool, 1)
	if err != nil {
		t.Fatal(err)
	}
	report, err := pool.Audit(context.Background(), currentOnly)
	if err != nil || report.Stats.OrphanObjects != 1 {
		t.Fatalf("current-only roots report=%+v err=%v", report.Stats, err)
	}
	rollbackWindow, _, err := collectCanonicalRoots(context.Background(), canonical, pool, 2)
	if err != nil {
		t.Fatal(err)
	}
	report, err = pool.Audit(context.Background(), rollbackWindow)
	if err != nil || report.Stats.OrphanObjects != 0 {
		t.Fatalf("two-commit rollback roots report=%+v err=%v", report.Stats, err)
	}
}

func TestYUMCompatibilitySourceAndCandidateRefsArePermanentCASRoots(t *testing.T) {
	payload := []byte("immutable-s1-rpm")
	digest := sha256.Sum256(payload)
	manifestPath := filepath.Join(t.TempDir(), "compatibility.tsv")
	var manifestBody bytes.Buffer
	if err := manifest.WriteEntry(&manifestBody, manifest.Entry{Path: "yum/infra/x86_64/pkg.rpm", Size: int64(len(payload)), SHA256: digest}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, manifestBody.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	fixture := newYUMCompatibilityContractFixture(t, manifestPath)
	pool, err := repository.NewStore(fixture.root)
	if err != nil {
		t.Fatal(err)
	}
	payloadObject, err := pool.Put(t.Context(), bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	var receipt yumCompatibilityCandidate
	if err := json.Unmarshal(fixture.candidateReceiptBody, &receipt); err != nil {
		t.Fatal(err)
	}
	packageTrustDigest, err := repository.ParseDigest(receipt.PackageTrustSHA256)
	if err != nil {
		t.Fatal(err)
	}
	repositoryTrustDigest, err := repository.ParseDigest(receipt.RepositoryTrustSHA256)
	if err != nil {
		t.Fatal(err)
	}
	orphan, err := pool.Put(t.Context(), strings.NewReader("unreferenced-control"))
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 4; index++ {
		marker := filepath.Join(fixture.root, fmt.Sprintf("compat-gc-marker-%d", index))
		if err := os.WriteFile(marker, []byte("m"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, changed, err := fixture.canonical.InstallPaths(map[string]string{fmt.Sprintf("tests/compat-gc-%d", index): marker}, "advance bounded HEAD history"); err != nil || !changed {
			t.Fatalf("advance history changed=%t err=%v", changed, err)
		}
	}
	roots, _, err := collectCanonicalRoots(t.Context(), fixture.canonical, pool, 1)
	if err != nil {
		t.Fatal(err)
	}
	if roots.Count(payloadObject.SHA256) == 0 || roots.Count(packageTrustDigest) == 0 || roots.Count(repositoryTrustDigest) == 0 {
		t.Fatalf("immutable compatibility refs were not permanent roots: payload=%d package_trust=%d repository_trust=%d",
			roots.Count(payloadObject.SHA256), roots.Count(packageTrustDigest), roots.Count(repositoryTrustDigest))
	}
	report, err := pool.Audit(t.Context(), roots)
	if err != nil {
		t.Fatal(err)
	}
	if report.Stats.MissingObjects != 0 || report.Stats.OrphanObjects != 1 || len(report.Orphans) != 1 || report.Orphans[0].SHA256 != orphan.SHA256 {
		t.Fatalf("compatibility permanent root partition=%+v", report)
	}
	packageObjectPath := pool.ObjectPath(packageTrustDigest)
	heldPackageTrust := filepath.Join(fixture.root, "held-package-trust-cas-object")
	if err := os.Rename(packageObjectPath, heldPackageTrust); err != nil {
		t.Fatal(err)
	}
	report, err = pool.Audit(t.Context(), roots)
	if err != nil || report.Stats.MissingObjects != 1 || len(report.Missing) != 1 || report.Missing[0].SHA256 != packageTrustDigest {
		t.Fatalf("missing frozen trust was not critical reachability evidence: report=%+v err=%v", report, err)
	}
	if err := os.Rename(heldPackageTrust, packageObjectPath); err != nil {
		t.Fatal(err)
	}
}

func TestYUMCompatibilityRefCASRootsRejectContentUnboundFrozenReceipt(t *testing.T) {
	fixture := newYUMCompatibilityContractFixture(t, "")
	var forged yumCompatibilityCandidate
	if err := json.Unmarshal(fixture.candidateReceiptBody, &forged); err != nil {
		t.Fatal(err)
	}
	forged.PackageTrustSHA256 = strings.Repeat("f", 64)
	var err error
	forged.FreezeConfirm, err = yumCompatibilityConfirmation("freeze", forged)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(fixture.root, "forged-candidate.json")
	if err := os.WriteFile(stage, append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	receiptPath, _ := state.YUMCompatibilityCandidateReceiptPath(forged.ID)
	forgedCommit, changed, err := fixture.canonical.InstallPaths(map[string]string{receiptPath: stage}, "test: forge content-unbound compatibility receipt")
	if err != nil || !changed {
		t.Fatalf("install forged receipt changed=%t err=%v", changed, err)
	}
	gitRepository, err := git.PlainOpen(filepath.Join(fixture.root, ".sow", "state"))
	if err != nil {
		t.Fatal(err)
	}
	freezeRef, _ := state.YUMCompatibilityRef(forged.ID)
	if err := gitRepository.Storer.SetReference(plumbing.NewHashReference(freezeRef, forgedCommit)); err != nil {
		t.Fatal(err)
	}
	if _, err := addYUMCompatibilityRefCASRoots(fixture.canonical, &repository.ReferenceSet{}); err == nil || !strings.Contains(err.Error(), "package trust bytes changed") {
		t.Fatalf("content-unbound frozen receipt was admitted as CAS roots: %v", err)
	}
}
