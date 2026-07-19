package cli

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

func TestPublishCLIPartialAPTIsSuiteWideAndSnapshotSafe(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAPTSelectorConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	initializeRepoBaselineForTest(t, root, configPath, "apt/one", "apt/two")
	keyPath := writePublishTestPrivateKey(t, root)
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token","basic_username":"verifier","basic_password":"verify-secret"}`)
	transport := newCloudProtocolTransport()
	previousClient, previousVerificationClient := publishProviderHTTPClient, verificationHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	verificationHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() {
		publishProviderHTTPClient = previousClient
		verificationHTTPClient = previousVerificationClient
	})
	run := func(args ...string) (int, string, string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	add := func(repo, suite, name, version, arch string) {
		t.Helper()
		input := writeSelectorDEB(t, root, name, version, arch)
		code, stdout, stderr := run("add", input, "--config", configPath, "--repo", repo, "--os", suite, "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2")
		if code != ExitOK {
			t.Fatalf("add %s/%s/%s code=%d stdout=%s stderr=%s", repo, suite, arch, code, stdout, stderr)
		}
	}

	// Two suites in deb-one and a sibling APT repository make both classes of
	// selector-owned state visible. Architecture: all seeds both configured
	// leaf refs without requiring duplicate package bodies.
	add("deb-one", "jammy", "jammy-shared", "1.0-1", "all")
	add("deb-one", "bookworm", "bookworm-shared", "1.0-1", "all")
	add("deb-two", "jammy", "repo-two-shared", "1.0-1", "all")

	if code, stdout, stderr := run("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
		t.Fatalf("initial full APT publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	verifyPartial := func() (int, string, string) {
		t.Helper()
		return run("verify", "--layer", "L1", "--view", "beta", "--config", configPath, "--repo", "deb-one", "--os", "jammy", "--arch", "amd64", "--gpg-public-key-file", keyPath+".pub", "--workers", "2", "--chunk-entries", "2")
	}
	if code, stdout, stderr := verifyPartial(); code != ExitOK {
		t.Fatalf("healthy partial APT verify code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	aptRoot := filepath.Join(root, ".sow", "materialized", "beta", "apt", "one")
	bookwormDir := filepath.Join(aptRoot, "dists", "bookworm")
	hiddenBookworm := filepath.Join(aptRoot, "bookworm-unselected-hidden")
	if err := os.Rename(bookwormDir, hiddenBookworm); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := verifyPartial(); code != ExitOK {
		t.Fatalf("unselected suite polluted partial verify code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("verify", "--layer", "L1", "--view", "beta", "--config", configPath, "--repo", "deb-one", "--gpg-public-key-file", keyPath+".pub", "--workers", "2", "--chunk-entries", "2"); code == ExitOK {
		t.Fatalf("full verify accepted missing bookworm stdout=%s stderr=%s", stdout, stderr)
	}
	if err := os.Rename(hiddenBookworm, bookwormDir); err != nil {
		t.Fatal(err)
	}
	selectedSibling := filepath.Join(aptRoot, "dists", "jammy", "main", "binary-arm64", "Packages")
	selectedSiblingBody, err := os.ReadFile(selectedSibling)
	if err != nil {
		t.Fatal(err)
	}
	selectedSiblingInfo, err := os.Stat(selectedSibling)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(selectedSibling, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(selectedSibling, []byte("corrupted sibling architecture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := verifyPartial(); code == ExitOK {
		t.Fatalf("partial --arch verify accepted corrupt sibling architecture stdout=%s stderr=%s", stdout, stderr)
	}
	if err := os.WriteFile(selectedSibling, selectedSiblingBody, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(selectedSibling, selectedSiblingInfo.Mode().Perm()); err != nil {
		t.Fatal(err)
	}
	beforeGeneration := readSelectorTargetGeneration(t, root)
	beforeRefs := selectorRefMap(beforeGeneration)
	transport.mutex.Lock()
	partialPutStart := len(transport.putKeys)
	transport.mutex.Unlock()

	// Keep a real pending change in an unselected suite. The full local APT
	// materialization sees it, but the jammy transaction must not publish it.
	add("deb-one", "bookworm", "bookworm-pending", "2.0-1", "all")
	// Change the sibling architecture, then request only amd64. Publication
	// must nevertheless include that pending arm64 state because InRelease is a
	// suite-wide pointer. Bookworm remains outside the transaction closure.
	add("deb-one", "jammy", "jammy-arm64", "2.0-1", "arm64")
	code, stdout, stderr := run("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "deb-one", "--os", "jammy", "--arch", "amd64", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2")
	if code != ExitOK || !strings.Contains(stdout, "publish route-receipts view=beta receipts=1") {
		t.Fatalf("partial APT publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	// The touched APT owner is rebuilt repo-wide for local Nginx safety even
	// though the remote logical transaction remains limited to jammy below.
	localPending := filepath.Join(aptRoot, "pool", "main", "b", "bookworm-pending", "bookworm-pending_2.0-1_all.deb")
	if _, err := os.Stat(localPending); err != nil {
		t.Fatalf("partial publish omitted the unselected suite from its physical APT owner: %v", err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	routeLedgers := loadRouteLedgersForTest(t, canonical, filepath.Join(root, ".sow", "materialized", "beta"), "beta")
	if len(routeLedgers) != 2 {
		t.Fatalf("partial publish did not preserve the sibling APT route capability: %+v", routeLedgers)
	}
	var selectedRoute materializedRouteLedger
	for _, ledger := range routeLedgers {
		if ledger.Receipt.Repo == "deb-one" {
			selectedRoute = ledger
		}
	}
	if selectedRoute.Receipt.ID == "" || len(selectedRoute.Receipt.Refs) != 4 {
		t.Fatalf("partial publish committed an incomplete APT owner receipt: %+v", selectedRoute.Receipt)
	}
	assertRouteLedgerValidForTest(t, root, filepath.Join(root, ".sow", "materialized", "beta"), selectedRoute)
	content := readPublishManifest(t, filepath.Join(root, ".sow", "state", "remotes", "cf", "content.tsv"))
	assertSelectorManifestPath(t, content, ".sow/materialized/beta/apt/one/dists/bookworm/main/binary-amd64/Packages")
	assertSelectorManifestPath(t, content, ".sow/materialized/beta/apt/one/dists/bookworm/main/binary-arm64/Packages")
	assertSelectorManifestPath(t, content, ".sow/materialized/beta/apt/one/dists/jammy/main/binary-amd64/Packages")
	assertSelectorManifestPath(t, content, ".sow/materialized/beta/apt/one/dists/jammy/main/binary-arm64/Packages")
	assertSelectorManifestSuffix(t, content, "/bookworm-shared_1.0-1_all.deb")
	assertSelectorManifestSuffix(t, content, "/jammy-shared_1.0-1_all.deb")
	assertSelectorManifestSuffix(t, content, "/jammy-arm64_2.0-1_arm64.deb")
	assertSelectorManifestOmitsSuffix(t, content, "/bookworm-pending_2.0-1_all.deb")
	release, err := os.ReadFile(filepath.Join(root, ".sow", "materialized", "beta", "apt", "one", "dists", "jammy", "Release"))
	if err != nil || !bytes.Contains(release, []byte("main/binary-amd64/Packages")) || !bytes.Contains(release, []byte("main/binary-arm64/Packages")) {
		t.Fatalf("suite-wide Release closure err=%v body=%s", err, release)
	}
	planBody, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "intents", "views", "beta", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := pub.DecodePlan(planBody)
	if err != nil {
		t.Fatal(err)
	}
	for _, removed := range plan.Removed {
		if strings.Contains(removed, "/dists/bookworm/") || strings.Contains(removed, "/dists/jammy/main/binary-arm64/") || strings.HasSuffix(removed, "/bookworm-shared_1.0-1_all.deb") || strings.Contains(removed, "bookworm-pending") {
			t.Fatalf("partial plan removed sibling path %q", removed)
		}
	}
	for _, object := range plan.Objects {
		if strings.Contains(object.SourcePath, "bookworm-pending") || strings.Contains(object.SourcePath, "/dists/bookworm/") {
			t.Fatalf("partial plan included pending unselected suite object %#v", object)
		}
	}
	afterGeneration := readSelectorTargetGeneration(t, root)
	afterRefs := selectorRefMap(afterGeneration)
	for _, arch := range []string{"amd64", "arm64"} {
		name, _ := state.ViewRef("beta", "deb-one", "bookworm", arch)
		if beforeRefs[name.String()] != afterRefs[name.String()] {
			t.Fatalf("unselected suite ref changed %s: before=%#v after=%#v", name, beforeRefs[name.String()], afterRefs[name.String()])
		}
	}
	transport.mutex.Lock()
	partialPutKeys := append([]string(nil), transport.putKeys[partialPutStart:]...)
	transport.mutex.Unlock()
	for _, key := range partialPutKeys {
		if strings.Contains(key, "/dists/bookworm/") || strings.Contains(key, "bookworm-pending") {
			t.Fatalf("partial publication uploaded unselected suite key %q", key)
		}
	}
	if code, stdout, stderr := run("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "deb-one", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
		t.Fatalf("follow-up full APT publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	fullContent := readPublishManifest(t, filepath.Join(root, ".sow", "state", "remotes", "cf", "content.tsv"))
	assertSelectorManifestSuffix(t, fullContent, "/bookworm-pending_2.0-1_all.deb")
	fullRefs := selectorRefMap(readSelectorTargetGeneration(t, root))
	bookwormArm64, _ := state.ViewRef("beta", "deb-one", "bookworm", "arm64")
	if fullRefs[bookwormArm64.String()] == beforeRefs[bookwormArm64.String()] {
		t.Fatalf("full publication did not advance pending bookworm ref %s", bookwormArm64)
	}

	// Freeze the current stable union, publish the complete snapshot, then
	// replay the same immutable snapshot through a narrow repo/arch selector.
	// The fixed local snapshot root and cumulative remote manifest must retain
	// every sibling from the first publication.
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath); code != ExitOK {
		t.Fatalf("promote latest code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	snapshotID, err := views.SnapshotID("jammy", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("promote", "stable", snapshotID, "--config", configPath); code != ExitOK {
		t.Fatalf("create snapshot code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("publish", "--snapshot", snapshotID, "--target", "cf", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
		t.Fatalf("full snapshot publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("publish", "--snapshot", snapshotID, "--target", "cf", "--config", configPath, "--repo", "deb-one", "--arch", "amd64", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
		t.Fatalf("partial snapshot replay code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	snapshotRoot := filepath.Join(root, ".sow", "materialized", "snapshots", snapshotID)
	for _, relative := range []string{
		"apt/one/dists/" + snapshotID + "/main/binary-amd64/Packages",
		"apt/one/dists/" + snapshotID + "/main/binary-arm64/Packages",
		"apt/two/dists/" + snapshotID + "/main/binary-amd64/Packages",
		"apt/two/dists/" + snapshotID + "/main/binary-arm64/Packages",
	} {
		if _, err := os.Stat(filepath.Join(snapshotRoot, filepath.FromSlash(relative))); err != nil {
			t.Fatalf("partial snapshot pruned local sibling %s: %v", relative, err)
		}
	}
	snapshotContent := readPublishManifest(t, filepath.Join(root, ".sow", "state", "remotes", "cf", "content.tsv"))
	for _, relative := range []string{
		"apt/one/dists/" + snapshotID + "/main/binary-arm64/Packages",
		"apt/two/dists/" + snapshotID + "/main/binary-amd64/Packages",
		"apt/two/dists/" + snapshotID + "/main/binary-arm64/Packages",
	} {
		assertSelectorManifestPath(t, snapshotContent, ".sow/materialized/snapshots/"+snapshotID+"/"+relative)
	}
	finalGeneration := readSelectorTargetGeneration(t, root)
	finalRefs := selectorRefMap(finalGeneration)
	for _, repo := range []string{"deb-one", "deb-two"} {
		for _, arch := range []string{"amd64", "arm64"} {
			name, _ := state.SnapshotRef(snapshotID, repo, "jammy", arch)
			if _, exists := finalRefs[name.String()]; !exists {
				t.Fatalf("partial snapshot target ref vector lost %s", name)
			}
		}
	}
}

func writeSelectorDEB(t *testing.T, root, name, version, arch string) string {
	t.Helper()
	control := []byte("Package: " + name + "\n" +
		"Source: " + name + "\n" +
		"Version: " + version + "\n" +
		"Architecture: " + arch + "\n" +
		"Maintainer: SOW Test <sow@example.invalid>\n" +
		"Section: misc\nPriority: optional\n" +
		"Description: SOW selector publication fixture\n")
	controlTar := retentionTarGzip(t, map[string][]byte{"control": control})
	dataTar := retentionTarGzip(t, map[string][]byte{"usr/share/doc/" + name + "/version": []byte(version + "\n")})
	var archive bytes.Buffer
	archive.WriteString("!<arch>\n")
	writeRetentionArMember(t, &archive, "debian-binary", []byte("2.0\n"))
	writeRetentionArMember(t, &archive, "control.tar.gz", controlTar)
	writeRetentionArMember(t, &archive, "data.tar.gz", dataTar)
	filename := filepath.Join(root, fmt.Sprintf("%s_%s_%s.deb", name, version, arch))
	if err := os.WriteFile(filename, archive.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return filename
}

func readSelectorTargetGeneration(t *testing.T, root string) pub.TargetGeneration {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "generation.json"))
	if err != nil {
		t.Fatal(err)
	}
	generation, err := pub.DecodeTargetGeneration(body)
	if err != nil {
		t.Fatal(err)
	}
	return generation
}

func selectorRefMap(generation pub.TargetGeneration) map[string]pub.RefState {
	result := make(map[string]pub.RefState, len(generation.Refs))
	for _, ref := range generation.Refs {
		result[ref.Name] = ref
	}
	return result
}

func assertSelectorManifestPath(t *testing.T, entries []manifest.Entry, want string) {
	t.Helper()
	for _, entry := range entries {
		if entry.Path == want {
			return
		}
	}
	t.Fatalf("manifest omitted %s", want)
}

func assertSelectorManifestSuffix(t *testing.T, entries []manifest.Entry, suffix string) {
	t.Helper()
	for _, entry := range entries {
		if strings.HasSuffix(entry.Path, suffix) {
			return
		}
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if strings.Contains(entry.Path, "/pool/") {
			paths = append(paths, entry.Path)
		}
	}
	t.Fatalf("manifest omitted suffix %s; pool paths=%v", suffix, paths)
}

func assertSelectorManifestOmitsSuffix(t *testing.T, entries []manifest.Entry, suffix string) {
	t.Helper()
	for _, entry := range entries {
		if strings.HasSuffix(entry.Path, suffix) {
			t.Fatalf("manifest unexpectedly included suffix %s", suffix)
		}
	}
}

const publishAPTSelectorConfig = `schema: sow/v1
state: {snapshot_materialization_months: 6}
gpg: {public_key: signing.key.pub}
pools:
  public: {}
  gated: {}
repos:
  - id: deb-one
    type: apt
    path: apt/one
    default_pool: public
    arches: [amd64, arm64]
    os: {family: ubuntu, suite: jammy, lifecycle: active}
    apt: {suites: [jammy, bookworm], components: [main]}
  - id: deb-two
    type: apt
    path: apt/two
    default_pool: public
    arches: [amd64, arm64]
    os: {family: ubuntu, suite: jammy, lifecycle: active}
    apt: {suites: [jammy], components: [main]}
upstreams: []
views:
  beta: {access: public, allowed_pools: [public], append_only: false}
  latest: {access: public, allowed_pools: [public], append_only: false}
  stable: {access: pro, allowed_pools: [public, gated], append_only: true}
targets:
  cf:
    storage: {kind: r2, endpoint: "https://storage.test", bucket: repo-bucket, credential: env://SOW_TEST_R2}
    cdn: {kind: cloudflare, base_url: "https://repo.test", beta_base_url: "https://beta.test", zone_id: zone-test, credential: env://SOW_TEST_CF}
edge:
  token_verifier: provider://test
`
