package cli

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
)

func TestAuditCanonicalMaterializedRouteLedgersChecksEveryTriple(t *testing.T) {
	root, configPath := newAssetMaterializeHardeningFixture(t)
	addAssetMaterializeFixture(t, configPath, "payload.bin", "canonical route fsck payload\n", false)
	target := filepath.Join(root, "route-fsck-export")
	runMaterializeSuccessForTest(t, []string{"beta", "--config", configPath, "--target", "route-fsck-export", "--workers", "1", "--chunk-entries", "1"})
	store := state.New(filepath.Join(root, ".sow"))
	stats, err := auditCanonicalMaterializedRouteLedgers(store, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Partitions != 1 || stats.Ledgers != 1 || stats.Files != 3 {
		t.Fatalf("unexpected materialized-route audit stats: %+v", stats)
	}

	ledgers := loadRouteLedgersForTest(t, store, target, "beta")
	if len(ledgers) != 1 {
		t.Fatalf("materialized route ledgers=%d want=1", len(ledgers))
	}
	corrupt := filepath.Join(t.TempDir(), "corrupt.tsv")
	if err := os.WriteFile(corrupt, []byte("forged\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := store.InstallPaths(map[string]string{ledgers[0].ExactCanonicalPath: corrupt}, "test: corrupt canonical route ledger"); err != nil || !changed {
		t.Fatalf("corrupt canonical route ledger changed=%t err=%v", changed, err)
	}
	if _, err := auditCanonicalMaterializedRouteLedgers(store, t.TempDir()); err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("corrupt exact manifest was accepted: %v", err)
	}
}

func TestAuditCanonicalMaterializedRouteLedgersRejectsUnknownDescendant(t *testing.T) {
	stage := filepath.Join(t.TempDir(), "unknown")
	if err := os.WriteFile(stage, []byte("unknown\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := state.New(filepath.Join(t.TempDir(), ".sow"))
	unknown := materializedRouteLedgerRootPrefix + "not-a-target/beta/routes/README"
	if _, changed, err := store.InstallPaths(map[string]string{unknown: stage}, "test: unknown route ledger descendant"); err != nil || !changed {
		t.Fatalf("install unknown materialized-route path changed=%t err=%v", changed, err)
	}
	if _, err := auditCanonicalMaterializedRouteLedgers(store, t.TempDir()); err == nil || !strings.Contains(err.Error(), "unknown canonical materialized-route ledger path") {
		t.Fatalf("unknown materialized-route descendant was accepted: %v", err)
	}
}

func TestAuditCanonicalMaterializedRouteLedgersRejectsNamespaceRootBlob(t *testing.T) {
	stage := filepath.Join(t.TempDir(), "root-blob")
	if err := os.WriteFile(stage, []byte("not a namespace directory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := state.New(filepath.Join(t.TempDir(), ".sow"))
	if _, changed, err := store.InstallPaths(map[string]string{strings.TrimSuffix(materializedRouteLedgerRootPrefix, "/"): stage}, "test: route namespace root blob"); err != nil || !changed {
		t.Fatalf("install namespace root blob changed=%t err=%v", changed, err)
	}
	if _, err := auditCanonicalMaterializedRouteLedgers(store, t.TempDir()); err == nil || !strings.Contains(err.Error(), "namespace root is a blob") {
		t.Fatalf("materialized-route namespace root blob was accepted: %v", err)
	}
}

func TestAuditCanonicalMaterializedRouteLedgersRejectsSelfConsistentForgedClosure(t *testing.T) {
	root, configPath := newAssetMaterializeHardeningFixture(t)
	addAssetMaterializeFixture(t, configPath, "payload.bin", "canonical route forged closure payload\n", false)
	target := filepath.Join(root, "route-forged-export")
	runMaterializeSuccessForTest(t, []string{"beta", "--config", configPath, "--target", "route-forged-export", "--workers", "1", "--chunk-entries", "1"})
	store := state.New(filepath.Join(root, ".sow"))
	base := loadRouteLedgersForTest(t, store, target, "beta")
	if len(base) != 1 {
		t.Fatalf("base route ledgers=%d want=1", len(base))
	}

	forgedPayload := filepath.Join(t.TempDir(), "forged-payload.tsv")
	body := []byte("forged payload\n")
	writeCLIRouteManifest(t, forgedPayload, []manifest.Entry{{Path: "asset/ghost.bin", Size: int64(len(body)), SHA256: sha256.Sum256(body)}})
	forged := deriveRouteReceiptForTest(t, base[0].Receipt, base[0].ExactManifest, forgedPayload)
	staged, err := stageMaterializedRouteLedger(t.TempDir(), forged, base[0].ExactManifest, forgedPayload)
	if err != nil {
		t.Fatal(err)
	}
	if _, changed, err := store.InstallPaths(staged, "test: self-consistent payload/exact forgery"); err != nil || !changed {
		t.Fatalf("install payload forgery changed=%t err=%v", changed, err)
	}
	if _, err := auditCanonicalMaterializedRouteLedgers(store, t.TempDir()); err == nil || !strings.Contains(err.Error(), "absent or differs") {
		t.Fatalf("self-consistent payload/exact forgery was accepted: %v", err)
	}

	forgedExact := filepath.Join(t.TempDir(), "forged-exact.tsv")
	emptyPayload := filepath.Join(t.TempDir(), "empty-payload.tsv")
	writeCLIRouteManifest(t, forgedExact, []manifest.Entry{{Path: "outside/ghost.bin", Size: int64(len(body)), SHA256: sha256.Sum256(body)}})
	writeCLIRouteManifest(t, emptyPayload, nil)
	forged = deriveRouteReceiptForTest(t, base[0].Receipt, forgedExact, emptyPayload)
	staged, err = stageMaterializedRouteLedger(t.TempDir(), forged, forgedExact, emptyPayload)
	if err != nil {
		t.Fatal(err)
	}
	if _, changed, err := store.InstallPaths(staged, "test: self-consistent claim forgery"); err != nil || !changed {
		t.Fatalf("install claim forgery changed=%t err=%v", changed, err)
	}
	if _, err := auditCanonicalMaterializedRouteLedgers(store, t.TempDir()); err == nil || !strings.Contains(err.Error(), "not covered by any claim") {
		t.Fatalf("self-consistent exact/claim forgery was accepted: %v", err)
	}

	inClaim := filepath.Join(t.TempDir(), "in-claim.tsv")
	writeCLIRouteManifest(t, inClaim, []manifest.Entry{{Path: "asset/ghost.bin", Size: int64(len(body)), SHA256: sha256.Sum256(body)}})
	forged = deriveRouteReceiptForTest(t, base[0].Receipt, inClaim, inClaim)
	staged, err = stageMaterializedRouteLedger(t.TempDir(), forged, inClaim, inClaim)
	if err != nil {
		t.Fatal(err)
	}
	if _, changed, err := store.InstallPaths(staged, "test: self-consistent in-claim ref forgery"); err != nil || !changed {
		t.Fatalf("install in-claim forgery changed=%t err=%v", changed, err)
	}
	if _, err := auditCanonicalMaterializedRouteLedgers(store, t.TempDir()); err == nil || !strings.Contains(err.Error(), "live payload differs from frozen refs") {
		t.Fatalf("self-consistent in-claim ref forgery was accepted: %v", err)
	}
}

func TestAuditCanonicalMaterializedRouteLedgersReplaysHistoricalYUMLifecycle(t *testing.T) {
	for _, test := range []struct {
		name  string
		edit  func(t *testing.T, base materializedRouteLedger, mirrorPath, generationID string) (serving.MaterializedRoute, string, string)
		want  string
		nginx bool
	}{
		{
			name: "generation payload",
			edit: func(t *testing.T, base materializedRouteLedger, _ string, generationID string) (serving.MaterializedRoute, string, string) {
				body := []byte("forged generation payload\n")
				ghost := manifest.Entry{Path: "_sow/v1/g/" + generationID + "/yum/test/x86_64/Packages/z/ghost.rpm", Size: int64(len(body)), SHA256: sha256.Sum256(body)}
				exactEntries := append(readCLIRouteManifestEntries(t, base.ExactManifest), ghost)
				payloadEntries := append(readCLIRouteManifestEntries(t, base.PayloadManifest), ghost)
				sort.Slice(exactEntries, func(i, j int) bool { return exactEntries[i].Path < exactEntries[j].Path })
				sort.Slice(payloadEntries, func(i, j int) bool { return payloadEntries[i].Path < payloadEntries[j].Path })
				exact := filepath.Join(t.TempDir(), "forged-generation-exact.tsv")
				payload := filepath.Join(t.TempDir(), "forged-generation-payload.tsv")
				writeCLIRouteManifest(t, exact, exactEntries)
				writeCLIRouteManifest(t, payload, payloadEntries)
				return deriveRouteReceiptForTest(t, base.Receipt, exact, payload), exact, payload
			},
			want: "historical lifecycle",
		},
		{
			name: "mirrorlist",
			edit: func(t *testing.T, base materializedRouteLedger, mirrorPath, _ string) (serving.MaterializedRoute, string, string) {
				entries := readCLIRouteManifestEntries(t, base.ExactManifest)
				found := false
				for index := range entries {
					if entries[index].Path == mirrorPath {
						body := []byte("https://forged.example.invalid/ghost\n")
						entries[index].Size = int64(len(body))
						entries[index].SHA256 = sha256.Sum256(body)
						found = true
					}
				}
				if !found {
					t.Fatalf("route exact manifest lacks mirrorlist %s", mirrorPath)
				}
				exact := filepath.Join(t.TempDir(), "forged-mirrorlist-exact.tsv")
				writeCLIRouteManifest(t, exact, entries)
				return deriveRouteReceiptForTest(t, base.Receipt, exact, base.PayloadManifest), exact, base.PayloadManifest
			},
			want: "historical lifecycle",
		},
		{
			name: "serving target",
			edit: func(t *testing.T, base materializedRouteLedger, _, _ string) (serving.MaterializedRoute, string, string) {
				altered := base.Receipt
				altered.ServingTargetID = strings.Repeat("f", 64)
				return deriveRouteReceiptForTest(t, altered, base.ExactManifest, base.PayloadManifest), base.ExactManifest, base.PayloadManifest
			},
			want:  "serving target",
			nginx: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, configPath, _, keyPath, _ := setupServingYUMView(t)
			arguments := []string{"materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "1", "--chunk-entries", "1"}
			if code, stdout, stderr := runServingCLI(t, arguments...); code != ExitOK {
				t.Fatalf("materialize YUM route code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			canonical := state.New(filepath.Join(root, ".sow"))
			if _, err := auditCanonicalMaterializedRouteLedgers(canonical, t.TempDir()); err != nil {
				t.Fatalf("valid historical YUM route failed fsck: %v", err)
			}
			ledgers := loadRouteLedgersForTest(t, canonical, root, "latest")
			if len(ledgers) != 1 || ledgers[0].Receipt.Kind != "yum" {
				t.Fatalf("YUM route ledgers=%+v", ledgers)
			}
			mirror := "_sow/v1/mirrorlist/latest/rpm-test/el10/x86_64.txt"
			generation := mirrorGenerationID(t, root, mirror)
			receipt, exact, payload := test.edit(t, ledgers[0], mirror, generation)
			staged, err := stageMaterializedRouteLedger(t.TempDir(), receipt, exact, payload)
			if err != nil {
				t.Fatal(err)
			}
			if _, changed, err := canonical.InstallPaths(staged, "test: forge historical YUM route input"); err != nil || !changed {
				t.Fatalf("install forged YUM route changed=%t err=%v", changed, err)
			}
			if _, err := auditCanonicalMaterializedRouteLedgers(canonical, t.TempDir()); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("forged historical YUM %s was accepted: %v", test.name, err)
			}
			if test.nginx {
				var stdout, stderr bytes.Buffer
				err := runMaterialize(t.Context(), []string{"latest", "--config", configPath, "--repo", "rpm-test", "--nginx-include", "-", "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
				if err == nil || !strings.Contains(err.Error(), "serving target") {
					t.Fatalf("Nginx admitted forged YUM serving target err=%v stdout=%s stderr=%s", err, stdout.String(), stderr.String())
				}
			}
		})
	}
}

func readCLIRouteManifestEntries(t *testing.T, filename string) []manifest.Entry {
	t.Helper()
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	reader := manifest.NewReader(file)
	var result []manifest.Entry
	for {
		entry, readErr := reader.Next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_ = file.Close()
			t.Fatal(readErr)
		}
		result = append(result, entry)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return result
}

func deriveRouteReceiptForTest(t *testing.T, base serving.MaterializedRoute, exactPath, payloadPath string) serving.MaterializedRoute {
	t.Helper()
	exact, err := os.Open(exactPath)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.Open(payloadPath)
	if err != nil {
		_ = exact.Close()
		t.Fatal(err)
	}
	receipt, deriveErr := serving.NewMaterializedRoute(serving.MaterializedRouteIdentity{
		Kind: base.Kind, View: base.View, Source: base.Source, TargetSHA256: base.TargetSHA256,
		Claims: base.Claims, ConfigSHA256: base.ConfigSHA256, ConfigCommit: base.ConfigCommit, ServingTargetID: base.ServingTargetID, Repo: base.Repo, OS: base.OS, Arch: base.Arch, Refs: base.Refs,
	}, exact, payload)
	closeErr := errors.Join(exact.Close(), payload.Close())
	if deriveErr != nil || closeErr != nil {
		t.Fatal(errors.Join(deriveErr, closeErr))
	}
	return receipt
}

func TestFSCKFailsBeforeRepositoryScanOnCanonicalRouteLedgerCorruption(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "asset"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "asset", "payload"), []byte("payload\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"init", "--config", configPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("init code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	unknownStage := filepath.Join(t.TempDir(), "unknown")
	if err := os.WriteFile(unknownStage, []byte("unknown\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := state.New(filepath.Join(root, ".sow"))
	unknown := materializedRouteLedgerRootPrefix + "not-a-target/beta/routes/README"
	if _, changed, err := store.InstallPaths(map[string]string{unknown: unknownStage}, "test: inject canonical route corruption"); err != nil || !changed {
		t.Fatalf("inject canonical route corruption changed=%t err=%v", changed, err)
	}

	stdout.Reset()
	stderr.Reset()
	code := Main([]string{"fsck", "--config", configPath, "--workers", "1", "--chunk-entries", "1"}, &stdout, &stderr)
	if code != ExitVerification || !strings.Contains(stderr.String(), "unknown canonical materialized-route ledger path") {
		t.Fatalf("fsck accepted route corruption code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "fsck repo=") || strings.Contains(stdout.String(), "fsck clean") {
		t.Fatalf("fsck scanned repositories after canonical route corruption: %s", stdout.String())
	}
}
