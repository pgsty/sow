package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/yumrepo"
)

func TestRetiredYUMGenerationReceiptIsTargetSpecificAndShrinksAfterConfirmedGC(t *testing.T) {
	root, configPath, rpmPath, keyPath, _ := setupServingYUMView(t)
	// Commit the retention change through the supported init path before the
	// first working-tree materialization. The configured zero-byte physical
	// owner must exist so init can scan it without fabricating package bytes.
	if err := os.MkdirAll(filepath.Join(root, "yum", "test", "x86_64"), 0o755); err != nil {
		t.Fatal(err)
	}
	rewriteServingReceiptRetentionConfig(t, configPath, 6)
	materializeArgs := []string{
		"materialize", "latest", "--config", configPath, "--repo", "rpm-test",
		"--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2",
	}
	if code, stdout, stderr := runServingCLI(t, materializeArgs...); code != ExitOK {
		t.Fatalf("first materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	mirror := "_sow/v1/mirrorlist/latest/rpm-test/el10/x86_64.txt"
	retiredID := mirrorGenerationID(t, root, mirror)
	info, err := yumrepo.InspectPackage(t.Context(), yumrepo.PackageInput{Path: rpmPath})
	if err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := runServingCLI(t,
		"rm", "--view", "latest", "--config", configPath, "--repo", "rpm-test",
		"--gpg-private-key-file", keyPath, info.Name,
	); code != ExitOK {
		t.Fatalf("remove package code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := runServingCLI(t, materializeArgs...); code != ExitOK {
		t.Fatalf("successor materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	rewriteServingReceiptRetentionConfig(t, configPath, 7)
	if code, stdout, stderr := runServingCLI(t, materializeArgs...); code != ExitOK {
		t.Fatalf("retirement materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	activeID := mirrorGenerationID(t, root, mirror)
	if activeID == retiredID {
		t.Fatalf("retirement materialize did not advance generation %s", retiredID)
	}
	// Restore the public package from beta, then materialize the default target
	// once more. This keeps the later export independently Nginx-admissible while
	// the already-retired first generation remains installed only at default.
	if code, stdout, stderr := runServingCLI(t, "promote", "beta", "latest", "--config", configPath, "--repo", "rpm-test"); code != ExitOK {
		t.Fatalf("restore latest package code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := runServingCLI(t, materializeArgs...); code != ExitOK {
		t.Fatalf("restore package materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}

	retiredRoot := filepath.Join(root, "_sow", "v1", "g", retiredID)
	if _, err := os.Stat(retiredRoot); err != nil {
		t.Fatalf("default target lost installed retired generation: %v", err)
	}
	exportRelative := "export-latest"
	exportRoot := filepath.Join(root, exportRelative)
	if err := os.MkdirAll(filepath.Join(exportRoot, "yum", "test", "x86_64"), 0o755); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := runServingCLI(t,
		"materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--target", exportRelative,
		"--serving-base-url", "https://export.example.invalid", "--gpg-private-key-file", keyPath,
		"--workers", "2", "--chunk-entries", "2",
	); code != ExitOK {
		t.Fatalf("export materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(exportRoot, "_sow", "v1", "g", retiredID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("later export inherited default-target retired generation: %v", err)
	}

	canonical := state.New(filepath.Join(root, ".sow"))
	lifecycle, err := loadCanonicalServingLifecycle(canonical)
	if err != nil {
		t.Fatal(err)
	}
	var retired canonicalServingRetiredGeneration
	retiredFound := false
	for _, record := range lifecycle.Retired {
		generation := record.Retired.Generation
		if generation.ID == retiredID && generation.View == "latest" && generation.Repo == "rpm-test" && generation.OS == "el10" && generation.Arch == "x86_64" {
			retired = record
			retiredFound = true
			break
		}
	}
	if !retiredFound {
		t.Fatalf("generation %s has no canonical retirement witness", retiredID)
	}
	defaultLedgers := loadRouteLedgersForTest(t, canonical, root, "latest")
	exportLedgers := loadRouteLedgersForTest(t, canonical, exportRoot, "latest")
	if len(defaultLedgers) != 1 || defaultLedgers[0].Receipt.Kind != "yum" || len(exportLedgers) != 1 || exportLedgers[0].Receipt.Kind != "yum" {
		t.Fatalf("target route ledgers default=%+v export=%+v", defaultLedgers, exportLedgers)
	}
	defaultBefore := defaultLedgers[0]
	exportBefore := exportLedgers[0]
	retiredPrefix := path.Join("_sow/v1/g", retiredID) + "/"
	defaultExact := routeManifestEntryMap(t, defaultBefore.ExactManifest)
	defaultPayload := routeManifestEntryMap(t, defaultBefore.PayloadManifest)
	exportExact := routeManifestEntryMap(t, exportBefore.ExactManifest)
	if countRouteManifestPrefix(defaultExact, retiredPrefix) == 0 {
		t.Fatalf("default target exact receipt omitted installed retired generation %s", retiredID)
	}
	if countRouteManifestPrefix(defaultPayload, retiredPrefix) != 0 {
		t.Fatalf("retired generation %s was reintroduced into the default target CAS payload", retiredID)
	}
	if countRouteManifestPrefix(exportExact, retiredPrefix) != 0 {
		t.Fatalf("export exact receipt widened to default-target retired generation %s", retiredID)
	}

	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _, err := loadAndSelect(commonFlags{configPath: configPath, workers: 2, chunk: 2})
	if err != nil {
		t.Fatal(err)
	}
	roots, _, err := collectCanonicalRoots(t.Context(), canonical, pool, cfg.State.CASHistoryCommits)
	if err != nil {
		t.Fatal(err)
	}
	retiredManifest, err := canonical.OpenPath(retired.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	reader := manifest.NewReader(retiredManifest)
	var exactOnly repository.Object
	var exactOnlyPath string
	for {
		entry, readErr := reader.Next()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_ = retiredManifest.Close()
			t.Fatal(readErr)
		}
		digest := repository.Digest(entry.SHA256)
		globalPath := path.Join("_sow/v1/g", retiredID, entry.Path)
		if roots.Count(digest) != 0 {
			continue
		}
		global, exact := defaultExact[globalPath]
		if !exact || global.Size != entry.Size || global.SHA256 != entry.SHA256 {
			continue
		}
		if _, payload := defaultPayload[globalPath]; payload {
			continue
		}
		exactOnly = repository.Object{SHA256: digest, Size: entry.Size}
		exactOnlyPath = globalPath
		break
	}
	if err := retiredManifest.Close(); err != nil {
		t.Fatal(err)
	}
	if exactOnlyPath == "" {
		t.Fatal("retired receipt had no exact-only CAS object proving that exact does not extend reachability")
	}
	if roots.Count(exactOnly.SHA256) != 0 {
		t.Fatalf("retired exact-only object %s unexpectedly has %d canonical roots", exactOnly.HashString(), roots.Count(exactOnly.SHA256))
	}
	report, err := pool.Audit(t.Context(), roots)
	if err != nil {
		t.Fatal(err)
	}
	if !repositoryObjectListed(report.Orphans, exactOnly) {
		t.Fatalf("retired exact-only object %s is not an orphan: %+v", exactOnly.HashString(), report.Stats)
	}
	poolInfo, err := os.Stat(pool.ObjectPath(exactOnly.SHA256))
	if err != nil {
		t.Fatal(err)
	}
	generationInfo, err := os.Stat(filepath.Join(root, filepath.FromSlash(exactOnlyPath)))
	if err != nil || !os.SameFile(poolInfo, generationInfo) {
		t.Fatalf("retired exact-only byte is not the installed CAS hardlink path=%s err=%v", exactOnlyPath, err)
	}

	for label, args := range map[string][]string{
		"default": {"materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--nginx-include", "-", "--workers", "2", "--chunk-entries", "2"},
		"export":  {"materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--target", exportRelative, "--nginx-include", "-", "--workers", "2", "--chunk-entries", "2"},
	} {
		code, stdout, stderr := runServingCLI(t, args...)
		if code != ExitOK {
			t.Fatalf("pre-GC %s Nginx admission code=%d stdout=%s stderr=%s", label, code, stdout, stderr)
		}
		assertRetiredReceiptYUMNginx(t, stdout)
	}
	if code, stdout, stderr := runServingCLI(t, "fsck", "--config", configPath, "--repo", "rpm-test", "--workers", "2", "--chunk-entries", "2"); code != ExitOK || !strings.Contains(stdout, "fsck clean") {
		t.Fatalf("pre-GC fsck code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}

	code, stdout, stderr := runGCTestCLI(t, "gc", "--config", configPath, "--limit", "100", "--workers", "2", "--chunk-entries", "2")
	if code != ExitOK || gcIntegerField(t, stdout, "serving_generation_orphans") != 2 || !strings.Contains(stdout, "gc orphan sha256="+exactOnly.HashString()) {
		t.Fatalf("generation GC dry run code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	confirm := gcDigest(t, stdout, "gc_set_sha256")
	code, stdout, stderr = runGCTestCLI(t, "gc", "--config", configPath, "--apply", "--confirm", confirm, "--limit", "100", "--workers", "2", "--chunk-entries", "2")
	if code != ExitOK || gcIntegerField(t, stdout, "deleted_serving_generations") != 2 || gcIntegerField(t, stdout, "deleted_serving_tombstones") != 2 {
		t.Fatalf("confirmed generation GC code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if _, err := os.Stat(retiredRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("confirmed GC retained retired generation directory: %v", err)
	}
	if _, err := os.Stat(pool.ObjectPath(exactOnly.SHA256)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("confirmed GC retained exact-only orphan %s: %v", exactOnly.HashString(), err)
	}

	// GC deliberately cannot rewrite a route receipt in the same destructive
	// transaction. Until the next legal materialize commit, the old exact
	// receipt remains canonical and Nginx must reject the missing directory.
	staleLedgers := loadRouteLedgersForTest(t, canonical, root, "latest")
	if len(staleLedgers) != 1 || staleLedgers[0].Receipt.ExactManifestSHA256 != defaultBefore.Receipt.ExactManifestSHA256 || countRouteManifestPrefix(routeManifestEntryMap(t, staleLedgers[0].ExactManifest), retiredPrefix) == 0 {
		t.Fatalf("GC silently rewrote the route receipt instead of leaving a detectable stale boundary: %+v", staleLedgers)
	}
	code, staleNginx, staleErr := runServingCLI(t,
		"materialize", "latest", "--config", configPath, "--repo", "rpm-test",
		"--nginx-include", "-", "--workers", "2", "--chunk-entries", "2",
	)
	if code == ExitOK || strings.Contains(staleNginx, "location ^~ /yum/test/x86_64/ {") || !strings.Contains(staleErr, "canonical lifecycle state") {
		t.Fatalf("stale retired-generation receipt was not fail-closed code=%d stdout=%s stderr=%s", code, staleNginx, staleErr)
	}
	if code, exportNginx, exportErr := runServingCLI(t,
		"materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--target", exportRelative,
		"--nginx-include", "-", "--workers", "2", "--chunk-entries", "2",
	); code != ExitOK {
		t.Fatalf("default-target stale receipt polluted export admission code=%d stdout=%s stderr=%s", code, exportNginx, exportErr)
	} else {
		assertRetiredReceiptYUMNginx(t, exportNginx)
	}
	if code, stdout, stderr := runServingCLI(t, materializeArgs...); code != ExitOK {
		t.Fatalf("post-GC receipt reconciliation code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	refreshed := loadRouteLedgersForTest(t, canonical, root, "latest")
	if len(refreshed) != 1 {
		t.Fatalf("post-GC route ledgers=%+v", refreshed)
	}
	if refreshed[0].Receipt.ExactManifestSHA256 == defaultBefore.Receipt.ExactManifestSHA256 {
		t.Fatal("post-GC materialize did not replace the stale exact receipt")
	}
	refreshedExact := routeManifestEntryMap(t, refreshed[0].ExactManifest)
	if countRouteManifestPrefix(refreshedExact, retiredPrefix) != 0 {
		t.Fatalf("post-GC exact receipt still names removed generation %s", retiredID)
	}
	if len(refreshedExact) >= len(defaultExact) {
		t.Fatalf("post-GC exact receipt did not shrink entries before=%d after=%d", len(defaultExact), len(refreshedExact))
	}
	assertRouteLedgerValidForTest(t, root, root, refreshed[0])
	assertRouteLedgerValidForTest(t, root, exportRoot, exportBefore)
	for label, args := range map[string][]string{
		"default": {"materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--nginx-include", "-", "--workers", "2", "--chunk-entries", "2"},
		"export":  {"materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--target", exportRelative, "--nginx-include", "-", "--workers", "2", "--chunk-entries", "2"},
	} {
		code, stdout, stderr := runServingCLI(t, args...)
		if code != ExitOK {
			t.Fatalf("post-GC %s Nginx admission code=%d stdout=%s stderr=%s", label, code, stdout, stderr)
		}
		assertRetiredReceiptYUMNginx(t, stdout)
	}
	if code, stdout, stderr := runServingCLI(t, "fsck", "--config", configPath, "--repo", "rpm-test", "--workers", "2", "--chunk-entries", "2"); code != ExitOK || !strings.Contains(stdout, "fsck clean") {
		t.Fatalf("post-GC fsck code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

func routeManifestEntryMap(t *testing.T, filename string) map[string]manifest.Entry {
	t.Helper()
	result := make(map[string]manifest.Entry)
	for _, entry := range readCLIRouteManifestEntries(t, filename) {
		result[entry.Path] = entry
	}
	return result
}

func countRouteManifestPrefix(entries map[string]manifest.Entry, prefix string) int {
	count := 0
	for name := range entries {
		if strings.HasPrefix(name, prefix) {
			count++
		}
	}
	return count
}

func repositoryObjectListed(objects []repository.Object, wanted repository.Object) bool {
	for _, object := range objects {
		if object == wanted {
			return true
		}
	}
	return false
}

func gcIntegerField(t *testing.T, output, name string) int {
	t.Helper()
	prefix := name + "="
	for _, field := range strings.Fields(output) {
		if !strings.HasPrefix(field, prefix) {
			continue
		}
		value, err := strconv.Atoi(strings.TrimPrefix(field, prefix))
		if err != nil {
			t.Fatalf("invalid GC integer field %s in %q: %v", name, field, err)
		}
		return value
	}
	t.Fatalf("missing GC integer field %s in output: %s", name, output)
	return 0
}

func assertRetiredReceiptYUMNginx(t *testing.T, document string) {
	t.Helper()
	for _, wanted := range []string{
		"location ^~ /yum/test/x86_64/ {",
		"location = /_sow/v1/mirrorlist/latest/rpm-test/el10/x86_64.txt {",
	} {
		if !strings.Contains(document, wanted) {
			t.Fatalf("Nginx include omitted target YUM route %q:\n%s", wanted, document)
		}
	}
}

func rewriteServingReceiptRetentionConfig(t *testing.T, configPath string, snapshotMonths int) {
	t.Helper()
	body, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(body), "\n")
	replaced := false
	for index, line := range lines {
		if strings.HasPrefix(line, "state:") {
			lines[index] = fmt.Sprintf("state: {snapshot_materialization_months: %d, yum_generation_retention: 1, cas_history_commits: 1}", snapshotMonths)
			replaced = true
			break
		}
	}
	if !replaced {
		t.Fatal("serving receipt fixture has no state mapping")
	}
	if err := os.WriteFile(configPath, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := runServingCLI(t, "init", "--config", configPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
		t.Fatalf("commit serving receipt retention config code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}
