package cli

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
	"github.com/pgsty/sow/internal/yumrepo"
)

func TestPublishPartialYUMAliasClosesFastPathAndRepairsRouteReceipt(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	configBody := strings.Replace(snapshotYUMConfig,
		"os: {family: el, major: 10, lifecycle: active}",
		"os: {family: el, suite: rocky, major: 10, lifecycle: active}", 1)
	configBody = strings.Replace(configBody, "targets: {}\n", `serving:
  latest: {base_url: "https://repo.test"}
  beta: {base_url: "https://beta.test"}
  stable: {base_url: "https://repo.test/pro/v1/basic"}
targets:
  cf:
    storage: {kind: r2, endpoint: "https://storage.test", bucket: repo-bucket, credential: env://SOW_TEST_R2}
    cdn: {kind: cloudflare, base_url: "https://repo.test", beta_base_url: "https://beta.test", zone_id: zone-test, credential: env://SOW_TEST_CF}
`, 1)
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	rpmPath := decodeMaterializeFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "package.rpm"))
	private, keyPath := writeMaterializeSigningKey(t, root)
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
	if code, stdout, stderr := run("add", rpmPath, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"); code != ExitOK {
		t.Fatalf("add aliases code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}

	// Give the two logical aliases distinct manifests. They still share one
	// repo+arch repodata root, so a partial rocky publish must materialize and
	// receipt their union exactly once.
	canonical := state.New(filepath.Join(root, ".sow"))
	rockyRPM := filepath.Join("..", "..", "third_party", "cavaliergopher-rpm", "testdata", "centos-release-5-0.0.el5.centos.2.x86_64.rpm")
	rockyInfo, err := yumrepo.InspectPackage(t.Context(), yumrepo.PackageInput{Path: rockyRPM})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	rockyObject, err := pool.Import(t.Context(), rockyRPM)
	if err != nil || rockyObject.HashString() != rockyInfo.SHA256 || rockyObject.Size != rockyInfo.Size {
		t.Fatalf("import rocky-only RPM object=%+v info=%+v err=%v", rockyObject, rockyInfo, err)
	}
	rockyVersion := rockyInfo.Version + "-" + rockyInfo.Release
	if rockyInfo.Epoch > 0 {
		rockyVersion = fmt.Sprintf("%d:%s", rockyInfo.Epoch, rockyVersion)
	}
	rockyEntry := views.Entry{
		Repo: "rpm-test", OS: "rocky", Arch: "x86_64", Name: rockyInfo.Name, Version: rockyVersion,
		Path: path.Join("yum/test/x86_64", rockyInfo.Location), Size: rockyInfo.Size, SHA256: rockyInfo.SHA256, Pool: "public",
	}
	var rockyBody bytes.Buffer
	if err := views.WriteEntry(&rockyBody, rockyEntry); err != nil {
		t.Fatal(err)
	}
	rockyStage := filepath.Join(root, ".sow", "publish-rocky-alias.tsv")
	if err := os.WriteFile(rockyStage, rockyBody.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	rockyPath, _ := state.ViewPath("beta", "rpm-test", "rocky", "x86_64")
	rockyRef, _ := state.ViewRef("beta", "rpm-test", "rocky", "x86_64")
	if _, changed, err := canonical.Apply(t.Context(), "test-yum-publish-alias", "test: seed rocky publication alias", map[string]string{rockyPath: rockyStage}, []state.RefUpdate{{Name: rockyRef}}, state.ApplyOptions{}); err != nil || !changed {
		t.Fatalf("seed rocky publication alias changed=%t err=%v", changed, err)
	}
	selection := commonFlags{
		configPath: configPath, repos: csvFlag{items: []string{"rpm-test"}}, oses: csvFlag{items: []string{"rocky"}},
		workers: 1, chunk: 2,
	}
	cfg, repos, err := loadAndSelect(selection)
	if err != nil {
		t.Fatal(err)
	}
	closedLeaves, err := selectedMutableRoutePhysicalLeaves(cfg, canonical, repos, "beta", selection)
	if err != nil || len(closedLeaves) != 2 {
		t.Fatalf("partial alias durable closure leaves=%+v err=%v", closedLeaves, err)
	}
	servingTarget, err := defaultMutableServingTarget(cfg, "beta")
	if err != nil {
		t.Fatal(err)
	}
	source := materializeCanonicalSource{ID: "beta", Public: true}
	units, err := planMaterializationSelectedUnits(cfg, canonical, []materializationSelectionRequest{
		{Source: source, Leaves: closedLeaves, TargetRoot: cfg.Root, IncludeMetadata: true},
		{Source: source, Leaves: closedLeaves, TargetRoot: servingTarget, IncludeServing: true},
	})
	if err != nil || len(units) != 4 {
		t.Fatalf("partial alias durable units=%+v err=%v", units, err)
	}
	recovery, err := decodePublicationMaterializationRecovery(cfg, materializationSelectionJournal{Units: units})
	if err != nil {
		t.Fatal(err)
	}
	if closureErr := requireClosedPublicationRecoveryViewLeaves(cfg, canonical, recovery); closureErr != nil {
		t.Fatalf("owner-closed durable recovery vector was rejected: recovery=%+v err=%v", recovery, closureErr)
	}
	var incompleteUnits []materializationSelectedUnit
	for _, unit := range units {
		if unit.OS == "rocky" {
			incompleteUnits = append(incompleteUnits, unit)
		}
	}
	incomplete, err := decodePublicationMaterializationRecovery(cfg, materializationSelectionJournal{Units: incompleteUnits})
	if err != nil {
		t.Fatal(err)
	}
	if err := requireClosedPublicationRecoveryViewLeaves(cfg, canonical, incomplete); err == nil || !strings.Contains(err.Error(), "incomplete physical route owner vector") {
		t.Fatalf("incomplete durable alias vector was accepted: %v", err)
	}

	publishArgs := []string{"publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "rpm-test", "--os", "rocky", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2"}
	code, stdout, stderr := run(publishArgs...)
	if code != ExitOK || !strings.Contains(stdout, "status=published") || !strings.Contains(stdout, "aliases=2") || !strings.Contains(stdout, "publish route-receipts view=beta receipts=1") {
		t.Fatalf("partial alias publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	targetGeneration := readSelectorTargetGeneration(t, root)
	if len(targetGeneration.Refs) != 2 || len(targetGeneration.Channels) != 2 {
		t.Fatalf("partial alias target closure refs=%+v channels=%+v", targetGeneration.Refs, targetGeneration.Channels)
	}
	channelOS := make(map[string]struct{}, len(targetGeneration.Channels))
	for _, channel := range targetGeneration.Channels {
		channelOS[channel.OS] = struct{}{}
	}
	for _, osName := range []string{"rocky", "el10"} {
		if _, exists := channelOS[osName]; !exists {
			t.Fatalf("partial alias target generation omitted %s: %+v", osName, targetGeneration.Channels)
		}
	}

	servingRoot := filepath.Join(root, ".sow", "materialized", "beta")
	rockyMirror := "_sow/v1/mirrorlist/beta/rpm-test/rocky/x86_64.txt"
	elMirror := "_sow/v1/mirrorlist/beta/rpm-test/el10/x86_64.txt"
	rockyGeneration := mirrorGenerationID(t, servingRoot, rockyMirror)
	elGeneration := mirrorGenerationID(t, servingRoot, elMirror)
	verifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(private), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	validated, err := yumrepo.ValidateDirectory(t.Context(), filepath.Join(servingRoot, "yum", "test", "x86_64", "repodata"), yumrepo.CompressionZstd, verifier)
	if err != nil || validated.Packages != 2 {
		t.Fatalf("partial alias physical repodata packages=%v err=%v", validated, err)
	}
	var generationRepomd []byte
	for _, generationID := range []string{rockyGeneration, elGeneration} {
		generationRoot := filepath.Join(servingRoot, "_sow", "v1", "g", generationID, "yum", "test", "x86_64", "repodata")
		generation, err := yumrepo.ValidateDirectory(t.Context(), generationRoot, yumrepo.CompressionZstd, verifier)
		if err != nil || generation.Packages != 2 {
			t.Fatalf("alias generation %s packages=%v err=%v", generationID, generation, err)
		}
		repomd, err := os.ReadFile(filepath.Join(generationRoot, "repomd.xml"))
		if err != nil {
			t.Fatal(err)
		}
		if generationRepomd != nil && !bytes.Equal(generationRepomd, repomd) {
			t.Fatalf("alias generations do not preserve the same physical repodata bytes rocky=%s el10=%s", rockyGeneration, elGeneration)
		}
		generationRepomd = repomd
	}
	ledgers := loadRouteLedgersForTest(t, canonical, servingRoot, "beta")
	if len(ledgers) != 1 || ledgers[0].Receipt.Kind != "yum" || len(ledgers[0].Receipt.Refs) != 2 {
		t.Fatalf("partial alias route capability is incomplete: %+v", ledgers)
	}
	assertRouteLedgerValidForTest(t, root, servingRoot, ledgers[0])

	putsBefore, purgesBefore, getsBefore := transport.counts()
	code, stdout, stderr = run(publishArgs...)
	putsAfter, purgesAfter, getsAfter := transport.counts()
	if code != ExitOK || !strings.Contains(stdout, "status=unchanged preflight=ref-vector") || strings.Contains(stdout, "materialized view=") ||
		putsAfter != putsBefore || purgesAfter != purgesBefore || getsAfter != getsBefore {
		t.Fatalf("partial alias fast path code=%d stdout=%s stderr=%s puts=%d/%d purges=%d/%d gets=%d/%d", code, stdout, stderr, putsBefore, putsAfter, purgesBefore, purgesAfter, getsBefore, getsAfter)
	}

	// Remove only the canonical read capability. Remote refs and local bytes
	// are still current, but publish must refuse the ref-vector-only fast path.
	lost := ledgers[0]
	deletePaths := []string{lost.ReceiptPath, lost.ExactCanonicalPath, lost.PayloadCanonicalPath}
	if _, changed, err := canonical.Apply(t.Context(), "test-yum-route-loss", "test: remove YUM route receipt", nil, nil, state.ApplyOptions{DeletePaths: deletePaths}); err != nil || !changed {
		t.Fatalf("remove YUM route receipt changed=%t err=%v", changed, err)
	}
	code, nginxOutput, nginxErr := run("materialize", "beta", "--config", configPath, "--repo", "rpm-test", "--os", "rocky", "--nginx-include", "-", "--workers", "1", "--chunk-entries", "2")
	if code == ExitOK || nginxOutput != "" || nginxErr == "" {
		t.Fatalf("Nginx admitted a route without its canonical receipt code=%d stdout=%s stderr=%s", code, nginxOutput, nginxErr)
	}

	putsBefore, purgesBefore, getsBefore = transport.counts()
	code, stdout, stderr = run(publishArgs...)
	putsAfter, purgesAfter, getsAfter = transport.counts()
	if code != ExitOK || !strings.Contains(stdout, "aliases=2") || !strings.Contains(stdout, "publish route-receipts view=beta receipts=1") ||
		!strings.Contains(stdout, "status=unchanged") || strings.Contains(stdout, "preflight=ref-vector") ||
		putsAfter != putsBefore || purgesAfter != purgesBefore || getsAfter != getsBefore {
		t.Fatalf("partial alias route repair code=%d stdout=%s stderr=%s puts=%d/%d purges=%d/%d gets=%d/%d", code, stdout, stderr, putsBefore, putsAfter, purgesBefore, purgesAfter, getsBefore, getsAfter)
	}
	repaired := loadRouteLedgersForTest(t, canonical, servingRoot, "beta")
	if len(repaired) != 1 || len(repaired[0].Receipt.Refs) != 2 {
		t.Fatalf("partial alias route repair remained incomplete: %+v", repaired)
	}
	assertRouteLedgerValidForTest(t, root, servingRoot, repaired[0])
	code, nginxOutput, nginxErr = run("materialize", "beta", "--config", configPath, "--repo", "rpm-test", "--os", "rocky", "--nginx-include", "-", "--workers", "1", "--chunk-entries", "2")
	if code != ExitOK || !strings.Contains(nginxOutput, "location ^~ /yum/test/x86_64/") || nginxErr != "" {
		t.Fatalf("repaired partial alias route is not Nginx-admissible code=%d stdout=%s stderr=%s", code, nginxOutput, nginxErr)
	}
}
