package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/config"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/repository"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
	"github.com/pgsty/sow/internal/yumrepo"
)

// TestPublishRestoreHistoricalYUMAliasesSharePhysicalOwnerAndPlanIsolatedAliasRemoval
// uses only the in-memory cloud protocol transport. The target name exercises
// the Cloudflare protocol implementation without making any provider or
// network request.
func TestPublishRestoreHistoricalYUMAliasesSharePhysicalOwnerAndPlanIsolatedAliasRemoval(t *testing.T) {
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
	baseRPM := decodeMaterializeFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "base.rpm"))
	privateKey, keyPath := writeMaterializeSigningKey(t, root)
	baseInfo, err := yumrepo.InspectPackage(t.Context(), yumrepo.PackageInput{Path: baseRPM})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
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
	runOK := func(args ...string) string {
		t.Helper()
		code, stdout, stderr := run(args...)
		if code != ExitOK {
			t.Fatalf("command=%v code=%d stdout=%s stderr=%s", args, code, stdout, stderr)
		}
		return stdout
	}

	runOK("add", baseRPM, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2")
	canonical := state.New(filepath.Join(root, ".sow"))
	rockyInfo := seedHistoricalRockyAlias(t, root, canonical)
	firstOutput := runOK("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2")
	if !strings.Contains(firstOutput, "aliases=2") {
		t.Fatalf("dual-alias source did not report one owner with two aliases: %s", firstOutput)
	}
	historicalDual, _, exists, err := readLocalTargetGeneration(canonical, "cf")
	if err != nil || !exists || historicalDual.Generation != 1 || len(historicalDual.Refs) != 2 || len(historicalDual.Channels) != 2 {
		t.Fatalf("dual-alias historical generation=%#v exists=%t err=%v", historicalDual, exists, err)
	}
	assertHistoricalYUMAliasVector(t, historicalDual, 1, "el10", "rocky")
	refDigests := make(map[string]struct{}, len(historicalDual.Refs))
	refCommits := make(map[string]struct{}, len(historicalDual.Refs))
	for _, ref := range historicalDual.Refs {
		refDigests[ref.ManifestSHA256] = struct{}{}
		refCommits[ref.Commit] = struct{}{}
	}
	if len(refDigests) != 2 || len(refCommits) != 2 {
		t.Fatalf("historical aliases are not disjoint ref states: refs=%#v", historicalDual.Refs)
	}
	objects := snapshotOfflineProtocolObjects(transport)
	firstStrong := ".sow/generations/00000000000000000001/yum/yum/test/x86_64/repodata/"
	assertRemoteYUMRepodataPackages(t, objects, firstStrong, privateKey, 2)
	assertRemoteYUMRawPairMatchesGeneration(t, objects, ".sow/beta/yum/test/x86_64/repodata/", firstStrong)

	changedRPM := writeRestoreRPMFixture(t, root, "1.0.0")
	changedInfo, err := yumrepo.InspectPackage(t.Context(), yumrepo.PackageInput{Path: changedRPM})
	if err != nil {
		t.Fatal(err)
	}
	runOK("add", changedRPM, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2")
	secondOutput := runOK("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2")
	if !strings.Contains(secondOutput, "aliases=2") {
		t.Fatalf("changed dual-alias publication lost physical closure: %s", secondOutput)
	}
	currentDual, _, exists, err := readLocalTargetGeneration(canonical, "cf")
	if err != nil || !exists || currentDual.Generation != 2 || len(currentDual.Refs) != 2 || len(currentDual.Channels) != 2 {
		t.Fatalf("changed dual-alias generation=%#v exists=%t err=%v", currentDual, exists, err)
	}
	objects = snapshotOfflineProtocolObjects(transport)
	secondStrong := ".sow/generations/00000000000000000002/yum/yum/test/x86_64/repodata/"
	assertRemoteYUMRepodataPackages(t, objects, secondStrong, privateKey, 3)
	assertRemoteYUMRawPairMatchesGeneration(t, objects, ".sow/beta/yum/test/x86_64/repodata/", secondStrong)

	purgesAtCrash := injectOfflineHistoricalYUMAliasRestoreCrash(t, root, configPath, privateKey, transport, 1, 2)
	restoreOutput := runOK("publish", "--restore-generation", "1", "--target", "cf", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2")
	if !strings.Contains(restoreOutput, "source_generation=1") || !strings.Contains(restoreOutput, "refs=2") || !strings.Contains(restoreOutput, "yum_repos=1") || !strings.Contains(restoreOutput, "status=complete") {
		t.Fatalf("dual-alias historical restore output=%s", restoreOutput)
	}
	restoredDual, _, exists, err := readLocalTargetGeneration(canonical, "cf")
	if err != nil || !exists || restoredDual.Generation != 3 || restoredDual.ParentGeneration != 2 || len(restoredDual.Refs) != 2 || len(restoredDual.Channels) != 2 {
		t.Fatalf("dual-alias restored generation=%#v exists=%t err=%v", restoredDual, exists, err)
	}
	transport.mutex.Lock()
	purgesAfterRecovery := transport.purges
	transport.mutex.Unlock()
	if purgesAfterRecovery <= purgesAtCrash {
		t.Fatalf("crashed dual-alias restore was not safely repurged during replay purges=%d/%d", purgesAtCrash, purgesAfterRecovery)
	}
	assertHistoricalYUMAliasVector(t, restoredDual, 3, "el10", "rocky")
	objects = snapshotOfflineProtocolObjects(transport)
	elMirror := "_sow/v1/mirrorlist/beta/rpm-test/el10/x86_64.txt"
	rockyMirror := "_sow/v1/mirrorlist/beta/rpm-test/rocky/x86_64.txt"
	strongPrefix := ".sow/generations/00000000000000000003/yum/yum/test/x86_64/repodata/"
	assertRemoteYUMRepodataPackages(t, objects, strongPrefix, privateKey, 2)
	assertRemoteYUMRawPairMatchesGeneration(t, objects, ".sow/beta/yum/test/x86_64/repodata/", strongPrefix)
	wantMirrorBody := "https://beta.test/_sow/v1/g/00000000000000000003/yum/test/x86_64/\n"
	for _, mirror := range []string{elMirror, rockyMirror} {
		object, exists := objects[mirror]
		if !exists || string(object.body) != wantMirrorBody {
			t.Fatalf("restored alias mirror %s body=%q exists=%t", mirror, object.body, exists)
		}
	}
	if count := remoteRepomdRoots(objects, ".sow/generations/00000000000000000003/yum/"); count != 1 {
		t.Fatalf("dual-alias restore generated %d physical YUM roots, want one", count)
	}
	for _, payload := range []string{
		path.Join("yum/test/x86_64", baseInfo.Location),
		path.Join("yum/test/x86_64", rockyInfo.Location),
		path.Join("yum/test/x86_64", changedInfo.Location),
	} {
		if _, exists := objects[payload]; !exists {
			t.Fatalf("historical restore deleted immutable physical payload %s", payload)
		}
	}

	// The package topology contract is immutable, so there is no valid CLI
	// fixture that can manufacture a historical one-alias generation after the
	// two-alias owner exists. Exercise the exact removal planner instead, using
	// the real sealed parent channel/plan evidence produced above. Removing the
	// rocky logical alias must yield one pointer deletion and retain the el10
	// channel plus their shared physical root.
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	repo, exists := cfg.RepoByName("rpm-test")
	if !exists {
		t.Fatal("rpm-test config disappeared")
	}
	elLeaf := viewLeaf{repo: repo, os: "el10", arch: "x86_64"}
	elProjection := publicationProjection{
		view: "beta", repo: repo, os: "el10", arch: "x86_64", sourceRoot: ".sow/beta/yum/test/x86_64",
		canonicalRoot: "yum/test/x86_64", remoteRoot: "yum/test/x86_64", legacyRoot: "yum/test/x86_64",
	}
	rockyChannelKey := ""
	for _, channel := range restoredDual.Channels {
		if channel.OS == "rocky" {
			rockyChannelKey = channel.RemoteKey
		}
	}
	if rockyChannelKey == "" {
		t.Fatal("sealed parent has no rocky channel evidence")
	}
	removalPrepared := preparedPublication{
		view: "beta", restoreSourceGeneration: historicalDual.Generation,
		projections:               []publicationProjection{elProjection},
		yumOwnerLeaves:            map[string][]viewLeaf{yumPublicationOwnerKey("rpm-test", "x86_64"): {elLeaf}},
		restoreRemovedChannelKeys: map[string]bool{rockyChannelKey: true},
	}
	changed := map[string]bool{channelRemoteKey("beta", elProjection): true}
	desiredChannels, err := desiredPublicationChannels(&restoredDual, removalPrepared, 4, changed, nil)
	if err != nil || len(desiredChannels) != 1 || desiredChannels[0].OS != "el10" {
		t.Fatalf("single-alias desired channels=%#v err=%v", desiredChannels, err)
	}
	var removalPlan pub.Plan
	if err := augmentRemovedYUMChannelDeletes(canonical, "cf", removalPrepared, &restoredDual, desiredChannels, &removalPlan); err != nil {
		t.Fatal(err)
	}
	if len(removalPlan.Deletes) != 1 || removalPlan.Deletes[0].RemoteKey != rockyMirror || strings.Contains(removalPlan.Deletes[0].RemoteKey, "yum/test/x86_64/Packages/") {
		t.Fatalf("single-alias removal escaped its pointer route: %#v", removalPlan.Deletes)
	}
	if _, exists := objects[elMirror]; !exists {
		t.Fatalf("removal planning mutated retained sibling %s", elMirror)
	}
	if _, exists := objects[".sow/beta/yum/test/x86_64/repodata/repomd.xml"]; !exists {
		t.Fatal("removal planning lost shared physical root")
	}

	transport.mutex.Lock()
	putsBefore, copiesBefore, deletesBefore, purgesBefore, getsBefore := transport.puts, transport.copies, transport.deletes, transport.purges, transport.cdnGets
	transport.mutex.Unlock()
	replayOutput := runOK("publish", "--restore-generation", "1", "--target", "cf", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2", "--chunk-entries", "2")
	transport.mutex.Lock()
	putsAfter, copiesAfter, deletesAfter, purgesAfter, getsAfter := transport.puts, transport.copies, transport.deletes, transport.purges, transport.cdnGets
	transport.mutex.Unlock()
	if !strings.Contains(replayOutput, "status=unchanged") || !strings.Contains(replayOutput, "status=complete") ||
		putsAfter != putsBefore || copiesAfter != copiesBefore || deletesAfter != deletesBefore || purgesAfter != purgesBefore || getsAfter != getsBefore {
		t.Fatalf("dual-alias restore replay repeated effects output=%s puts=%d/%d copies=%d/%d deletes=%d/%d purges=%d/%d gets=%d/%d",
			replayOutput, putsBefore, putsAfter, copiesBefore, copiesAfter, deletesBefore, deletesAfter, purgesBefore, purgesAfter, getsBefore, getsAfter)
	}
}

func seedHistoricalRockyAlias(t *testing.T, root string, canonical *state.Store) yumrepo.PackageInfo {
	t.Helper()
	rockyRPM := filepath.Join("..", "..", "third_party", "cavaliergopher-rpm", "testdata", "centos-release-5-0.0.el5.centos.2.x86_64.rpm")
	info, err := yumrepo.InspectPackage(t.Context(), yumrepo.PackageInput{Path: rockyRPM})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	object, err := pool.Import(t.Context(), rockyRPM)
	if err != nil || object.HashString() != info.SHA256 || object.Size != info.Size {
		t.Fatalf("import rocky historical object=%+v info=%+v err=%v", object, info, err)
	}
	version := info.Version + "-" + info.Release
	if info.Epoch > 0 {
		version = fmt.Sprintf("%d:%s", info.Epoch, version)
	}
	entry := views.Entry{
		Repo: "rpm-test", OS: "rocky", Arch: "x86_64", Name: info.Name, Version: version,
		Path: path.Join("yum/test/x86_64", info.Location), Size: info.Size, SHA256: info.SHA256, Pool: "public",
	}
	var body bytes.Buffer
	if err := views.WriteEntry(&body, entry); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, ".sow", "historical-rocky-alias.tsv")
	if err := os.WriteFile(stage, body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	canonicalPath, _ := state.ViewPath("beta", "rpm-test", "rocky", "x86_64")
	ref, _ := state.ViewRef("beta", "rpm-test", "rocky", "x86_64")
	if _, changed, err := canonical.Apply(t.Context(), "test-historical-yum-alias", "test: seed disjoint rocky historical alias", map[string]string{canonicalPath: stage}, []state.RefUpdate{{Name: ref}}, state.ApplyOptions{}); err != nil || !changed {
		t.Fatalf("seed rocky historical alias changed=%t err=%v", changed, err)
	}
	return info
}

func injectOfflineHistoricalYUMAliasRestoreCrash(t *testing.T, root, configPath string, privateKey []byte, transport *cloudProtocolTransport, sourceGeneration, parentGeneration uint64) int {
	t.Helper()
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(cfg.StatePath())
	historical, err := loadHistoricalTargetPublication(canonical, "cf", sourceGeneration)
	if err != nil {
		t.Fatal(err)
	}
	txDir, err := newTransactionDir(cfg.StatePath(), "historical-yum-alias-crash-")
	if err != nil {
		t.Fatal(err)
	}
	client, err := newPublishTargetClient(cfg, "cf", "beta", false)
	if err != nil {
		t.Fatal(err)
	}
	inspection := filepath.Join(txDir, "inspect")
	if err := os.Mkdir(inspection, 0o700); err != nil {
		t.Fatal(err)
	}
	observation, err := observeRemoteTarget(t.Context(), canonical, client, "cf", inspection)
	if err != nil {
		t.Fatal(err)
	}
	if observation.parent == nil || observation.parent.Generation != parentGeneration {
		t.Fatalf("restore crash parent=%#v want_generation=%d", observation.parent, parentGeneration)
	}
	pool, err := repository.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	values := commonFlags{configPath: configPath, workers: 2, chunk: 2}
	historicalLeaves, err := configuredHistoricalLeaves(cfg, historical.Generation)
	if err != nil {
		t.Fatal(err)
	}
	leaves := make([]viewLeaf, 0, len(historicalLeaves))
	for _, historicalLeaf := range historicalLeaves {
		leaves = append(leaves, historicalLeaf.leaf)
	}
	repositoryKeySHA, err := repositorySigningKeyIdentity(cfg, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	values.materializeTrust, err = captureMaterializationTrust(cfg, leaves, privateKey, repositoryKeySHA)
	if err != nil {
		t.Fatal(err)
	}
	values.materializeOperation = "publish"
	prepared, err := prepareHistoricalPublication(t.Context(), cfg, cfg, canonical, pool, cfg.Repos, "cf", historical, observation.parent, txDir, values, privateKey, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	prepared.repositoryKeySHA256 = repositoryKeySHA
	head, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	publication, err := buildTargetPublication(t.Context(), cfg, canonical, cfg.Repos, prepared, "cf", head, txDir, values)
	if err != nil {
		t.Fatal(err)
	}
	injected := false
	transport.mutex.Lock()
	purgesBeforeCrash := transport.purges
	transport.mutex.Unlock()
	publisher := pub.NewR2CloudflarePublisher(publication.client.r2, pub.DirectorySource{Root: root}, filepath.Join(cfg.StatePath(), "publish-journal"), pub.Hooks{AfterPhase: func(_ pub.TargetName, phase pub.Phase) error {
		if phase == pub.PhasePurged && !injected {
			injected = true
			return errors.New("injected historical YUM alias restore crash after purge")
		}
		return nil
	}}).WithWorkers(2)
	if _, err := publisher.Run(t.Context(), publication.request); err == nil || !strings.Contains(err.Error(), "injected historical YUM alias restore crash after purge") || !injected {
		t.Fatalf("historical YUM alias restore crash err=%v injected=%t", err, injected)
	}
	local, _, exists, err := readLocalTargetGeneration(canonical, "cf")
	if err != nil || !exists || local.Generation != parentGeneration {
		t.Fatalf("crashed restore advanced local target generation=%#v exists=%t err=%v", local, exists, err)
	}
	transport.mutex.Lock()
	purgesAfterCrash := transport.purges
	transport.mutex.Unlock()
	if purgesAfterCrash <= purgesBeforeCrash {
		t.Fatalf("injected restore never reached mandatory purge purges=%d/%d", purgesBeforeCrash, purgesAfterCrash)
	}
	if err := os.RemoveAll(txDir); err != nil {
		t.Fatal(err)
	}
	return purgesAfterCrash
}

func assertHistoricalYUMAliasVector(t *testing.T, generation pub.TargetGeneration, wantGeneration uint64, aliases ...string) {
	t.Helper()
	want := append([]string(nil), aliases...)
	sort.Strings(want)
	got := make([]string, 0, len(generation.Channels))
	for _, channel := range generation.Channels {
		if channel.Generation != wantGeneration || channel.Repo != "rpm-test" || channel.Arch != "x86_64" || channel.LegacyRoot != "yum/test/x86_64" {
			t.Fatalf("historical YUM channel escaped one physical owner: %#v", channel)
		}
		got = append(got, channel.OS)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("historical YUM aliases=%v want=%v", got, want)
	}
}

func snapshotOfflineProtocolObjects(transport *cloudProtocolTransport) map[string]protocolObject {
	transport.mutex.Lock()
	defer transport.mutex.Unlock()
	objects := make(map[string]protocolObject, len(transport.objects))
	for key, object := range transport.objects {
		copy := object
		copy.body = append([]byte(nil), object.body...)
		objects[key] = copy
	}
	return objects
}

func assertRemoteYUMRepodataPackages(t *testing.T, objects map[string]protocolObject, prefix string, privateKey []byte, packages int64) {
	t.Helper()
	repodata := t.TempDir()
	files := 0
	for key, object := range objects {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		name := strings.TrimPrefix(key, prefix)
		if name == "" || strings.Contains(name, "/") {
			t.Fatalf("unsafe remote repodata key %s", key)
		}
		if err := os.WriteFile(filepath.Join(repodata, name), object.body, 0o600); err != nil {
			t.Fatal(err)
		}
		files++
	}
	if files == 0 {
		t.Fatalf("remote repodata prefix %s is absent", prefix)
	}
	verifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(privateKey), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	generation, err := yumrepo.ValidateDirectory(t.Context(), repodata, yumrepo.CompressionZstd, verifier)
	if err != nil {
		t.Fatalf("remote repodata prefix %s is not consumable: %v", prefix, err)
	}
	if generation.Packages != packages {
		t.Fatalf("remote repodata prefix %s packages=%d want=%d", prefix, generation.Packages, packages)
	}
}

func assertRemoteYUMRawPairMatchesGeneration(t *testing.T, objects map[string]protocolObject, rawPrefix, generationPrefix string) {
	t.Helper()
	for _, name := range []string{"repomd.xml", "repomd.xml.asc"} {
		raw, rawExists := objects[rawPrefix+name]
		generation, generationExists := objects[generationPrefix+name]
		if !rawExists || !generationExists || !bytes.Equal(raw.body, generation.body) {
			t.Fatalf("raw YUM pointer pair %s differs from immutable generation raw_exists=%t generation_exists=%t", name, rawExists, generationExists)
		}
	}
}

func remoteRepomdRoots(objects map[string]protocolObject, prefix string) int {
	roots := make(map[string]struct{})
	for key := range objects {
		if strings.HasPrefix(key, prefix) && strings.HasSuffix(key, "/repodata/repomd.xml") {
			roots[strings.TrimSuffix(key, "/repodata/repomd.xml")] = struct{}{}
		}
	}
	return len(roots)
}
