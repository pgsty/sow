package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/verify"
)

type yumConsumerRoundTripFunc func(*http.Request) (*http.Response, error)

func (function yumConsumerRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type yumConsumerMutatingTransport struct {
	next        http.RoundTripper
	mutate      func() error
	when        func(*http.Request) bool
	once        sync.Once
	mutationErr error
}

func (transport *yumConsumerMutatingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.next.RoundTrip(request)
	if err == nil && (transport.when == nil || transport.when(request)) {
		transport.once.Do(func() { transport.mutationErr = transport.mutate() })
	}
	return response, err
}

type yumConsumerCloseErrorBody struct {
	reader *bytes.Reader
}

func (body *yumConsumerCloseErrorBody) Read(buffer []byte) (int, error) {
	return body.reader.Read(buffer)
}

func (*yumConsumerCloseErrorBody) Close() error {
	return errors.New("injected response close failure")
}

func TestYUMConsumerPreflightClosesPublishedProtocolAndReceiptWithoutNetworkReplay(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	configBody := strings.Replace(publishPackageConfig, "upstreams: []", `  - id: trust-assets
    type: asset
    path: pkg
    default_pool: public
    asset: {kind: release}
upstreams: []`, 1)
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := writePublishTestPrivateKey(t, root)
	publicPath := writeVerifyPublicKey(t, keyPath)
	packageTrustPath := filepath.Join(root, "package-trust.asc")
	publicBody, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	packageTrustBody, err := os.ReadFile(packageTrustPath)
	if err != nil {
		t.Fatal(err)
	}
	decoyPrivatePath := writePublishTestPrivateKey(t, t.TempDir())
	decoyPackageTrust, err := os.ReadFile(decoyPrivatePath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	aggregatePath := filepath.Join(root, "rpm-trust.asc")
	aggregateBody := append(append(append([]byte(nil), publicBody...), packageTrustBody...), decoyPackageTrust...)
	if err := os.WriteFile(aggregatePath, aggregateBody, 0o600); err != nil {
		t.Fatal(err)
	}
	rpmPath := decodeVerifyFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "pgdg-repo.rpm"))

	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	transport := newCloudProtocolTransport()
	previousPublishClient, previousPreflightClient := publishProviderHTTPClient, yumConsumerPreflightHTTPClient
	previousNow := yumConsumerPreflightNow
	publishProviderHTTPClient = &http.Client{Transport: transport}
	yumConsumerPreflightHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() {
		publishProviderHTTPClient = previousPublishClient
		yumConsumerPreflightHTTPClient = previousPreflightClient
		yumConsumerPreflightNow = previousNow
	})
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	for _, invocation := range [][]string{
		{"add", rpmPath, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2"},
		{"add", aggregatePath, "--config", configPath, "--repo", "trust-assets", "--dest", "keys/rpm-trust.asc", "--workers", "2"},
	} {
		if code, stdout, stderr := run(invocation...); code != ExitOK {
			t.Fatalf("add code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
	}
	if code, stdout, stderr := run("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2"); code != ExitOK || !strings.Contains(stdout, "status=published") {
		t.Fatalf("publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	fixedNow := time.Now().UTC().Truncate(time.Second)
	clockNow := fixedNow
	yumConsumerPreflightNow = func() time.Time { return clockNow }
	stage := t.TempDir()
	mapPath, inventoryPath, planDigest := writeYUMConsumerPreflightStage(t, stage)
	receiptPath := filepath.Join(stage, "preflight-receipt.json")
	baseArgs := []string{
		"--config", configPath, "--staged", stage, "--map", mapPath, "--inventory", inventoryPath,
		"--trust-bundle", aggregatePath, "--receipt", receiptPath, "--confirm", planDigest,
		"--workers", "2", "--chunk-entries", "1",
	}
	preflightArgs := append([]string{"compatibility", "yum-consumer-preflight"}, baseArgs...)
	preflightArgs = append(preflightArgs, "--valid-for", "5m")
	code, stdout, stderr := run(preflightArgs...)
	if code != ExitOK || !strings.Contains(stdout, "preflight=pass endpoints=1 consumer_definitions=1 consumer_bindings=1") || stderr != "" {
		inventory, _ := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "inventory.tsv"))
		t.Fatalf("preflight code=%d stdout=%s stderr=%s inventory=%s", code, stdout, stderr, inventory)
	}
	receiptBody, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := decodeYUMConsumerReceipt(receiptBody)
	if err != nil || len(receipt.Endpoints) != 1 || receipt.Endpoints[0].PackageName != "pgdg-redhat-nonfree-repo" || receipt.Endpoints[0].MetadataObjects != 6 || receipt.Endpoints[0].InstalledObjects != 1 {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	offsetReceipt := receipt
	offset := time.FixedZone("review-offset", 8*60*60)
	verifiedAt, _ := time.Parse(time.RFC3339, receipt.VerifiedAt)
	expiresAt, _ := time.Parse(time.RFC3339, receipt.ExpiresAt)
	offsetReceipt.VerifiedAt = verifiedAt.In(offset).Format(time.RFC3339)
	offsetReceipt.ExpiresAt = expiresAt.In(offset).Format(time.RFC3339)
	if _, err := canonicalYUMConsumerReceipt(offsetReceipt); err == nil || !strings.Contains(err.Error(), "canonical UTC") {
		t.Fatalf("non-UTC receipt time error=%v", err)
	}

	// receipt-check must be a local/canonical replay gate. Replacing its client
	// with a transport that fails every request proves it performs no network IO.
	yumConsumerPreflightHTTPClient = &http.Client{Transport: failingVerificationTransport{}}
	checkArgs := append([]string{"compatibility", "yum-consumer-receipt-check"}, baseArgs...)
	code, stdout, stderr = run(checkArgs...)
	if code != ExitOK || !strings.Contains(stdout, "receipt=valid endpoints=1") || stderr != "" {
		t.Fatalf("receipt check code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}

	// Presence in aggregate inventory is not enough. A different, still-valid
	// ordering of the same public certificates changes the managed object bytes
	// and must fail before any network proof can bless an out-of-band object.
	driftedAggregate := append(append(append([]byte(nil), packageTrustBody...), publicBody...), decoyPackageTrust...)
	if bytes.Equal(driftedAggregate, aggregateBody) {
		t.Fatal("aggregate drift fixture did not change bytes")
	}
	if err := os.WriteFile(aggregatePath, driftedAggregate, 0o600); err != nil {
		t.Fatal(err)
	}
	aggregateDriftReceipt := filepath.Join(stage, "aggregate-inventory-drift-receipt.json")
	aggregateDriftArgs := append([]string(nil), preflightArgs...)
	for index := range aggregateDriftArgs {
		if aggregateDriftArgs[index] == receiptPath {
			aggregateDriftArgs[index] = aggregateDriftReceipt
		}
	}
	if code, _, stderr := run(aggregateDriftArgs...); code != ExitConflict || !strings.Contains(stderr, "aggregate inventory identity") {
		t.Fatalf("aggregate inventory drift code=%d stderr=%s", code, stderr)
	}
	if _, err := os.Stat(aggregateDriftReceipt); !os.IsNotExist(err) {
		t.Fatalf("aggregate inventory drift installed receipt: %v", err)
	}
	if err := os.WriteFile(aggregatePath, aggregateBody, 0o600); err != nil {
		t.Fatal(err)
	}

	// Any reviewed-input drift invalidates the otherwise authentic receipt.
	mapBody, err := os.ReadFile(mapPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mapPath, append(mapBody, []byte("# reviewed-note-change\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := run(checkArgs...); code != ExitConflict || !strings.Contains(stderr, "not current authority") {
		t.Fatalf("map drift check code=%d stderr=%s", code, stderr)
	}
	if err := os.WriteFile(mapPath, mapBody, 0o600); err != nil {
		t.Fatal(err)
	}
	clockNow = fixedNow.Add(5 * time.Minute)
	if code, _, stderr := run(checkArgs...); code != ExitConflict || !strings.Contains(stderr, "expired") {
		t.Fatalf("expiry check code=%d stderr=%s", code, stderr)
	}

	// A public trust object that is target-owned but no longer byte-identical to
	// the reviewed bundle fails before a second receipt can be installed.
	clockNow = fixedNow
	yumConsumerPreflightHTTPClient = &http.Client{Transport: transport}
	badReceipt := filepath.Join(stage, "bad-trust-receipt.json")
	badArgs := append([]string(nil), preflightArgs...)
	for index := range badArgs {
		if badArgs[index] == receiptPath {
			badArgs[index] = badReceipt
		}
	}
	transport.mutex.Lock()
	transport.cdnOverrides["https://beta.test/pkg/keys/rpm-trust.asc"] = protocolObject{body: []byte("wrong-trust\n")}
	transport.mutex.Unlock()
	if code, _, stderr := run(badArgs...); code != ExitVerification || !strings.Contains(stderr, "aggregate bundle") {
		t.Fatalf("remote trust drift code=%d stderr=%s", code, stderr)
	}
	if _, err := os.Stat(badReceipt); !os.IsNotExist(err) {
		t.Fatalf("failed remote trust preflight installed receipt: %v", err)
	}

	// The endpoint proof can take minutes on a real network. A local stage
	// replacement during that window must invalidate the proof before receipt
	// installation, even though all remote protocol requests succeeded.
	transport.mutex.Lock()
	delete(transport.cdnOverrides, "https://beta.test/pkg/keys/rpm-trust.asc")
	transport.mutex.Unlock()
	remoteFlip := &yumConsumerMutatingTransport{
		next: transport,
		when: func(request *http.Request) bool {
			return strings.HasSuffix(request.URL.Path, ".rpm")
		},
		mutate: func() error {
			transport.mutex.Lock()
			defer transport.mutex.Unlock()
			transport.cdnOverrides["https://beta.test/_sow/v1/mirrorlist/beta/rpm-test/el10/x86_64.txt"] = protocolObject{body: []byte("https://beta.test/_sow/v1/g/99999999999999999999/yum/yum/test/x86_64/\n")}
			return nil
		},
	}
	yumConsumerPreflightHTTPClient = &http.Client{Transport: remoteFlip}
	remoteFlipReceipt := filepath.Join(stage, "post-probe-remote-flip-receipt.json")
	remoteFlipArgs := append([]string(nil), preflightArgs...)
	for index := range remoteFlipArgs {
		if remoteFlipArgs[index] == receiptPath {
			remoteFlipArgs[index] = remoteFlipReceipt
		}
	}
	if code, _, stderr := run(remoteFlipArgs...); code != ExitVerification || !strings.Contains(stderr, "changed after protocol proof") {
		t.Fatalf("post-probe remote flip code=%d stderr=%s mutation_err=%v", code, stderr, remoteFlip.mutationErr)
	}
	if remoteFlip.mutationErr != nil {
		t.Fatal(remoteFlip.mutationErr)
	}
	if _, err := os.Stat(remoteFlipReceipt); !os.IsNotExist(err) {
		t.Fatalf("post-probe remote flip installed receipt: %v", err)
	}
	transport.mutex.Lock()
	delete(transport.cdnOverrides, "https://beta.test/_sow/v1/mirrorlist/beta/rpm-test/el10/x86_64.txt")
	transport.mutex.Unlock()
	packageTrustMutation := &yumConsumerMutatingTransport{
		next: transport,
		mutate: func() error {
			return os.WriteFile(packageTrustPath, append(append([]byte(nil), packageTrustBody...), '\n'), 0o600)
		},
	}
	yumConsumerPreflightHTTPClient = &http.Client{Transport: packageTrustMutation}
	keyringDriftReceipt := filepath.Join(stage, "post-probe-keyring-drift-receipt.json")
	keyringDriftArgs := append([]string(nil), preflightArgs...)
	for index := range keyringDriftArgs {
		if keyringDriftArgs[index] == receiptPath {
			keyringDriftArgs[index] = keyringDriftReceipt
		}
	}
	if code, _, stderr := run(keyringDriftArgs...); code != ExitConflict || !strings.Contains(stderr, "local inputs changed") || !strings.Contains(stderr, "package trust digest differs") {
		t.Fatalf("post-probe keyring drift code=%d stderr=%s mutation_err=%v", code, stderr, packageTrustMutation.mutationErr)
	}
	if packageTrustMutation.mutationErr != nil {
		t.Fatal(packageTrustMutation.mutationErr)
	}
	if _, err := os.Stat(keyringDriftReceipt); !os.IsNotExist(err) {
		t.Fatalf("post-probe keyring drift installed receipt: %v", err)
	}
	if err := os.WriteFile(packageTrustPath, packageTrustBody, 0o600); err != nil {
		t.Fatal(err)
	}

	// One verification time governs metadata, RPMs, and receipt issuance. A
	// probe that completes after its requested validity window cannot mint a
	// fresh-looking receipt from the later wall clock.
	timeWindowMutation := &yumConsumerMutatingTransport{
		next: transport,
		mutate: func() error {
			clockNow = fixedNow.Add(1200 * time.Millisecond)
			return nil
		},
	}
	yumConsumerPreflightHTTPClient = &http.Client{Transport: timeWindowMutation}
	timeWindowReceipt := filepath.Join(stage, "expired-during-probe-receipt.json")
	timeWindowArgs := append([]string(nil), preflightArgs...)
	for index := range timeWindowArgs {
		if timeWindowArgs[index] == receiptPath {
			timeWindowArgs[index] = timeWindowReceipt
		}
		if timeWindowArgs[index] == "5m" {
			timeWindowArgs[index] = "1500ms"
		}
	}
	if code, _, stderr := run(timeWindowArgs...); code != ExitConflict || !strings.Contains(stderr, "outlived its receipt validity window") {
		t.Fatalf("probe validity window code=%d stderr=%s mutation_err=%v", code, stderr, timeWindowMutation.mutationErr)
	}
	if timeWindowMutation.mutationErr != nil {
		t.Fatal(timeWindowMutation.mutationErr)
	}
	if _, err := os.Stat(timeWindowReceipt); !os.IsNotExist(err) {
		t.Fatalf("expired endpoint proof installed receipt: %v", err)
	}
	clockNow = fixedNow

	// Byte-identical replacement at the same path is still a different review
	// directory and receipt parent. Path strings and hashes alone must not let
	// that swap inherit an in-flight endpoint proof.
	replacementStage := stage + ".replacement"
	displacedStage := stage + ".displaced"
	directoryMutation := &yumConsumerMutatingTransport{
		next: transport,
		mutate: func() error {
			if err := cloneFlatYUMConsumerDirectory(stage, replacementStage); err != nil {
				return err
			}
			if err := os.Rename(stage, displacedStage); err != nil {
				return err
			}
			if err := os.Rename(replacementStage, stage); err != nil {
				_ = os.Rename(displacedStage, stage)
				return err
			}
			return nil
		},
	}
	yumConsumerPreflightHTTPClient = &http.Client{Transport: directoryMutation}
	directoryDriftReceipt := filepath.Join(stage, "post-probe-directory-drift-receipt.json")
	directoryDriftArgs := append([]string(nil), preflightArgs...)
	for index := range directoryDriftArgs {
		if directoryDriftArgs[index] == receiptPath {
			directoryDriftArgs[index] = directoryDriftReceipt
		}
	}
	if code, _, stderr := run(directoryDriftArgs...); code != ExitConflict || !strings.Contains(stderr, "directory identity differs") {
		t.Fatalf("post-probe directory drift code=%d stderr=%s mutation_err=%v", code, stderr, directoryMutation.mutationErr)
	}
	if directoryMutation.mutationErr != nil {
		t.Fatal(directoryMutation.mutationErr)
	}
	if _, err := os.Stat(directoryDriftReceipt); !os.IsNotExist(err) {
		t.Fatalf("post-probe directory drift installed receipt: %v", err)
	}
	if err := os.Rename(stage, replacementStage); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(displacedStage, stage); err != nil {
		t.Fatal(err)
	}

	consumerPath := filepath.Join(stage, "consumer.yml")
	consumerBody, err := os.ReadFile(consumerPath)
	if err != nil {
		t.Fatal(err)
	}
	mutating := &yumConsumerMutatingTransport{
		next: transport,
		mutate: func() error {
			return os.WriteFile(consumerPath, append(append([]byte(nil), consumerBody...), []byte("# post-probe drift\n")...), 0o600)
		},
	}
	yumConsumerPreflightHTTPClient = &http.Client{Transport: mutating}
	driftReceipt := filepath.Join(stage, "post-probe-drift-receipt.json")
	driftArgs := append([]string(nil), preflightArgs...)
	for index := range driftArgs {
		if driftArgs[index] == receiptPath {
			driftArgs[index] = driftReceipt
		}
	}
	if code, _, stderr := run(driftArgs...); code != ExitConflict || !strings.Contains(stderr, "local inputs changed") {
		t.Fatalf("post-probe local drift code=%d stderr=%s mutation_err=%v", code, stderr, mutating.mutationErr)
	}
	if mutating.mutationErr != nil {
		t.Fatal(mutating.mutationErr)
	}
	if _, err := os.Stat(driftReceipt); !os.IsNotExist(err) {
		t.Fatalf("post-probe drift installed receipt: %v", err)
	}
}

func cloneFlatYUMConsumerDirectory(source, destination string) error {
	if err := os.Mkdir(destination, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return errors.New("consumer directory clone encountered a non-regular entry")
		}
		body, err := os.ReadFile(filepath.Join(source, entry.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(destination, entry.Name()), body, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func writeYUMConsumerPreflightStage(t *testing.T, stage string) (string, string, string) {
	t.Helper()
	consumer := []byte(`repo_upstream:
  - name: pigsty-pgsql
    description: Pigsty PGSQL
    module: pgsql
    releases: [10]
    arch: [x86_64]
    mirrorlist:
      default:
        x86_64: https://beta.test/_sow/v1/mirrorlist/beta/rpm-test/el10/x86_64.txt
        aarch64: https://beta.test/_sow/v1/mirrorlist/beta/rpm-test/el10/aarch64.txt
    gpgkey:
      default: https://beta.test/pkg/keys/rpm-trust.asc
    meta: {gpgcheck: 1, repo_gpgcheck: 1}
`)
	consumerPath := filepath.Join(stage, "consumer.yml")
	if err := os.WriteFile(consumerPath, consumer, 0o600); err != nil {
		t.Fatal(err)
	}
	renderer := []byte(`{% for repo in repo_upstream %}
{% if os_version|int in repo.releases and repo.module == module_name and os_arch in repo.arch %}
{% if os_package == 'rpm' %}
{% set target_version = '$releasever' %}
{% if (os_version|int >= 10) and (repo.name | lower | regex_search('^epel')) %}{% set target_version = os_version|string ~ 'z' %}{% endif %}
{% if (repo.name | lower | regex_search('^pgdg')) and ((os_version|int >= 10) or ((os_version|int == 9) and (os_version_full|string | regex_search('^9\.([6-9]|[1-9][0-9]+)(\..*)?$')))) %}{% set target_version = os_version_full|string | regex_replace('^(9\.([6-9]|[1-9][0-9]+)).*$', '\1') %}{% endif %}
{% if repo.minor is defined and repo.minor|bool %}{% set target_version = os_version_full|string %}{% endif %}
[{{ repo.name }}]
name = {{ repo.description }} $releasever - $basearch
# sow-yum-mirrorlist/v2
{% if repo.mirrorlist is defined and region in repo.mirrorlist and repo.mirrorlist[region] is mapping and os_arch in repo.mirrorlist[region] %}
mirrorlist = {{ repo.mirrorlist[region][os_arch] | replace("${admin_ip}", admin_ip) | replace("$releasever", target_version|string) }}
{% elif repo.mirrorlist is defined and region in repo.mirrorlist and repo.mirrorlist[region] is string and repo.mirrorlist[region] != "" %}
mirrorlist = {{ repo.mirrorlist[region] | replace("${admin_ip}", admin_ip) | replace("$releasever", target_version|string) }}
{% elif repo.baseurl is defined and region in repo.baseurl and repo.baseurl[region] != "" %}
baseurl = {{ repo.baseurl[region] | replace("${admin_ip}", admin_ip) | replace("$releasever", target_version|string) }}
{% elif repo.mirrorlist is defined and "default" in repo.mirrorlist and repo.mirrorlist.default is mapping and os_arch in repo.mirrorlist.default %}
mirrorlist = {{ repo.mirrorlist.default[os_arch] | replace("${admin_ip}", admin_ip) | replace("$releasever", target_version|string) }}
{% elif repo.mirrorlist is defined and "default" in repo.mirrorlist and repo.mirrorlist.default is string and repo.mirrorlist.default != "" %}
mirrorlist = {{ repo.mirrorlist.default | replace("${admin_ip}", admin_ip) | replace("$releasever", target_version|string) }}
{% else %}
baseurl = {{ repo.baseurl.default | replace("${admin_ip}", admin_ip) | replace("$releasever", target_version|string) }}
{% endif %}
{% set repo_opts = {'gpgcheck': 0, 'enabled': 1} %}
{% if os_version|int >= 8 %}{% set repo_opts = repo_opts | combine({'module_hotfixes': 1}) %}{% endif %}
{% if repo.meta is defined %}{% set repo_opts = repo_opts | combine(repo.meta) %}{% endif %}
{% if repo.gpgkey is defined %}
{% if region in repo.gpgkey and repo.gpgkey[region] != "" %}
{% set repo_opts = repo_opts | combine({"gpgkey": repo.gpgkey[region]}) %}
{% else %}
{% set repo_opts = repo_opts | combine({"gpgkey": repo.gpgkey.default}) %}
{% endif %}
{% endif %}
{% for key, value in repo_opts.items() %}
{{ key }} = {{ value }}
{% endfor %}
{% else %}
`)
	rendererPath := filepath.Join(stage, "renderer.yml")
	if err := os.WriteFile(rendererPath, renderer, 0o600); err != nil {
		t.Fatal(err)
	}
	afterDigest := sha256.Sum256(consumer)
	rendererDigest := sha256.Sum256(renderer)
	manifest := []byte("consumer.yml\t" + strings.Repeat("0", 64) + "\t" + hex.EncodeToString(afterDigest[:]) + "\n" +
		"renderer.yml\t" + strings.Repeat("0", 64) + "\t" + hex.EncodeToString(rendererDigest[:]) + "\n")
	manifestPath := filepath.Join(stage, "manifest.tsv")
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	planDigestBytes := sha256.Sum256(manifest)
	planDigest := hex.EncodeToString(planDigestBytes[:])
	if err := os.WriteFile(filepath.Join(stage, "plan.sha256"), []byte(planDigest+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mapPath := filepath.Join(stage, "map.tsv")
	mapBody := "# schema=sow-pigsty-yum-consumer-map/v2\n# name\tx86\tarm\tcount\npigsty-pgsql\trpm-test/el$releasever/x86_64\trpm-test/el$releasever/aarch64\t1\n"
	if err := os.WriteFile(mapPath, []byte(mapBody), 0o600); err != nil {
		t.Fatal(err)
	}
	inventoryPath := filepath.Join(stage, "files.tsv")
	inventoryBody := "# schema=sow-pigsty-yum-consumer-files/v1\n# path\tcount\tkind\nconsumer.yml\t1\tconsumer\nrenderer.yml\t0\trenderer\n"
	if err := os.WriteFile(inventoryPath, []byte(inventoryBody), 0o600); err != nil {
		t.Fatal(err)
	}
	return mapPath, inventoryPath, planDigest
}

func TestYUMConsumerReceiptInstallIsNoReplaceAndCanonical(t *testing.T) {
	directory := t.TempDir()
	identity, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "receipt.json")
	body := []byte("receipt\n")
	if err := installYUMConsumerReceipt(destination, body, identity); err != nil {
		t.Fatal(err)
	}
	if err := installYUMConsumerReceipt(destination, []byte("replacement\n"), identity); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("receipt replacement err=%v", err)
	}
	observed, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(observed, body) {
		t.Fatalf("installed receipt=%q err=%v", observed, err)
	}
	foreignIdentity, err := os.Lstat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := installYUMConsumerReceipt(filepath.Join(directory, "foreign.json"), body, foreignIdentity); err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("foreign receipt parent identity err=%v", err)
	}
}

func TestYUMConsumerReviewParsersRejectUnsafeSurfaces(t *testing.T) {
	if _, _, err := parseYUMConsumerMap([]byte("# schema=sow-pigsty-yum-consumer-map/v1\nrepo\trepo/el$releasever/x86_64\trepo/el$releasever/aarch64\t1\n")); err == nil || !strings.Contains(err.Error(), yumConsumerMapSchema) {
		t.Fatalf("legacy map schema error=%v", err)
	}
	if err := validateYUMConsumerRouteTemplate("repo/el$releasever/$basearch", "x86_64"); err == nil || !strings.Contains(err.Error(), "unsupported placeholder") {
		t.Fatalf("unsupported route placeholder error=%v", err)
	}
	if _, _, err := parseYUMConsumerMap([]byte("# schema=" + yumConsumerMapSchema + "\nordinary\trepo/el9/x86_64\trepo/el9/aarch64\t1\n")); err == nil || !strings.Contains(err.Error(), "release-aware") {
		t.Fatalf("release-independent ordinary route error=%v", err)
	}
	if _, _, err := parseYUMConsumerMap([]byte("# schema=" + yumConsumerMapSchema + "\npgdg-common\trepo/el$releasever/x86_64\trepo/el$releasever/aarch64\t1\n")); err == nil || !strings.Contains(err.Error(), "target_version semantics") {
		t.Fatalf("renderer-specific target version error=%v", err)
	}
	var oversizedMap strings.Builder
	oversizedMap.WriteString("# schema=" + yumConsumerMapSchema + "\n")
	for index := 0; index < 5; index++ {
		oversizedMap.WriteString("repo" + string(rune('a'+index)) + "\trepo/el$releasever/x86_64\trepo/el$releasever/aarch64\t1000\n")
	}
	if _, _, err := parseYUMConsumerMap([]byte(oversizedMap.String())); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized definition map error=%v", err)
	}

	entry := yumConsumerMapEntry{Name: "pigsty-pgsql", ExpectedModule: "pgsql", X8664Route: "rpm-test/el$releasever/x86_64", AArch64Route: "rpm-test/el$releasever/aarch64", ExpectedDefinitions: 1}
	entries := map[string]yumConsumerMapEntry{entry.Name: entry}
	tests := []struct {
		name      string
		body      string
		wantError string
	}{
		{
			name: "unmapped-sow-raw-url",
			body: `repo_upstream:
  - name: unreviewed
    baseurl: https://repo.pigsty.io/yum/unreviewed
`,
			wantError: "unmapped SOW-hosted YUM definition",
		},
		{
			name: "unnamed-sow-raw-url",
			body: `repo_upstream:
  - baseurl: https://repo.pigsty.io/yum/unreviewed
`,
			wantError: "unmapped SOW-hosted YUM URL",
		},
		{
			name: "non-string-name-sow-raw-url",
			body: `repo_upstream:
  - name: 42
    baseurl: https://repo.pigsty.cc/yum/unreviewed
`,
			wantError: "unmapped SOW-hosted YUM URL",
		},
		{
			name: "unmapped-alias-domain-raw-url",
			body: `repo_upstream:
  - name: unreviewed
    baseurl: https://repo.pigsty.com/yum/unreviewed
`,
			wantError: "unmapped SOW-hosted YUM definition",
		},
		{
			name: "percent-encoded-raw-url",
			body: `repo_upstream:
  - name: unreviewed
    baseurl: https://repo.pigsty.io/yum%2Funreviewed
`,
			wantError: "unmapped SOW-hosted YUM definition",
		},
		{
			name: "case-folded-host-raw-url",
			body: `repo_upstream:
  - name: unreviewed
    baseurl: HTTPS://REPO.PIGSTY.IO/yum
`,
			wantError: "unmapped SOW-hosted YUM definition",
		},
		{
			name: "duplicate-security-key",
			body: `repo_upstream:
  - name: pigsty-pgsql
    releases: [10]
    arch: [x86_64]
    mirrorlist: {default: {x86_64: https://beta.test/_sow/v1/mirrorlist/beta/rpm-test/el10/x86_64.txt}}
    gpgkey: {default: https://beta.test/pkg/keys/rpm-trust.asc}
    meta: {gpgcheck: 1, gpgcheck: 1, repo_gpgcheck: 1}
`,
			wantError: "meta repeats YAML key gpgcheck",
		},
		{
			name: "renderer-specific-minor-version",
			body: `repo_upstream:
  - name: pigsty-pgsql
    minor: true
    releases: [10]
    arch: [x86_64]
    mirrorlist: {default: {x86_64: https://beta.test/_sow/v1/mirrorlist/beta/rpm-test/el10/x86_64.txt}}
    gpgkey: {default: https://beta.test/pkg/keys/rpm-trust.asc}
    meta: {gpgcheck: 1, repo_gpgcheck: 1}
`,
			wantError: "minor target_version semantics",
		},
		{
			name: "meta-route-override",
			body: `repo_upstream:
  - name: pigsty-pgsql
    releases: [10]
    arch: [x86_64]
    mirrorlist: {default: {x86_64: https://beta.test/_sow/v1/mirrorlist/beta/rpm-test/el10/x86_64.txt}}
    gpgkey: {default: https://beta.test/pkg/keys/rpm-trust.asc}
    meta: {gpgcheck: 1, repo_gpgcheck: 1, baseurl: https://repo.pigsty.io/yum/override}
`,
			wantError: "cannot override the reviewed route or trust policy",
		},
		{
			name: "missing-renderer-module",
			body: `repo_upstream:
  - name: pigsty-pgsql
    description: Pigsty PGSQL
    releases: [10]
    arch: [x86_64]
    mirrorlist: {default: {x86_64: https://beta.test/_sow/v1/mirrorlist/beta/rpm-test/el10/x86_64.txt}}
    gpgkey: {default: https://beta.test/pkg/keys/rpm-trust.asc}
    meta: {gpgcheck: 1, repo_gpgcheck: 1}
`,
			wantError: "module must be one literal Pigsty module segment",
		},
		{
			name: "wrong-renderer-module",
			body: `repo_upstream:
  - name: pigsty-pgsql
    description: Pigsty PGSQL
    module: infra
    releases: [10]
    arch: [x86_64]
    mirrorlist: {default: {x86_64: https://beta.test/_sow/v1/mirrorlist/beta/rpm-test/el10/x86_64.txt}}
    gpgkey: {default: https://beta.test/pkg/keys/rpm-trust.asc}
    meta: {gpgcheck: 1, repo_gpgcheck: 1}
`,
			wantError: "differs from frozen pigsty-pgsql module pgsql",
		},
		{
			name: "renderer-description-injection",
			body: `repo_upstream:
  - name: pigsty-pgsql
    description: |-
      Pigsty PGSQL
      baseurl = https://repo.pigsty.io/yum/override
    module: pgsql
    releases: [10]
    arch: [x86_64]
    mirrorlist: {default: {x86_64: https://beta.test/_sow/v1/mirrorlist/beta/rpm-test/el10/x86_64.txt}}
    gpgkey: {default: https://beta.test/pkg/keys/rpm-trust.asc}
    meta: {gpgcheck: 1, repo_gpgcheck: 1}
`,
			wantError: "description contains a control character",
		},
		{
			name: "custom-tagged-definition",
			body: `repo_upstream:
  - !unsafe
    name: pigsty-pgsql
    description: Pigsty PGSQL
    module: pgsql
    releases: [10]
    arch: [x86_64]
    mirrorlist: {default: {x86_64: https://beta.test/_sow/v1/mirrorlist/beta/rpm-test/el10/x86_64.txt}}
    gpgkey: {default: https://beta.test/pkg/keys/rpm-trust.asc}
    meta: {gpgcheck: 1, repo_gpgcheck: 1}
`,
			wantError: "consumer definition is not a YAML mapping",
		},
		{
			name: "scalar-v1-mirrorlist",
			body: `repo_upstream:
  - name: pigsty-pgsql
    releases: [10]
    arch: [x86_64]
    mirrorlist: {default: https://beta.test/_sow/v1/mirrorlist/beta/rpm-test/el10/x86_64.txt}
    gpgkey: {default: https://beta.test/pkg/keys/rpm-trust.asc}
    meta: {gpgcheck: 1, repo_gpgcheck: 1}
`,
			wantError: "mirrorlist default must be a non-empty YAML mapping",
		},
		{
			name: "missing-architecture-route",
			body: `repo_upstream:
  - name: pigsty-pgsql
    description: Pigsty PGSQL
    module: pgsql
    releases: [10]
    arch: [x86_64, aarch64]
    mirrorlist: {default: {x86_64: https://beta.test/_sow/v1/mirrorlist/beta/rpm-test/el10/x86_64.txt}}
    gpgkey: {default: https://beta.test/pkg/keys/rpm-trust.asc}
    meta: {gpgcheck: 1, repo_gpgcheck: 1}
`,
			wantError: "lacks architecture aarch64",
		},
		{
			name: "missing-default-fallback-region",
			body: `repo_upstream:
  - name: pigsty-pgsql
    releases: [10]
    arch: [x86_64]
    mirrorlist: {china: {x86_64: https://beta.test/_sow/v1/mirrorlist/beta/rpm-test/el10/x86_64.txt}}
    gpgkey: {china: https://beta.test/pkg/keys/rpm-trust.asc}
    meta: {gpgcheck: 1, repo_gpgcheck: 1}
`,
			wantError: "default fallback region",
		},
		{
			name: "yaml-alias",
			body: `definition: &definition
  name: pigsty-pgsql
  releases: [10]
  arch: [x86_64]
  mirrorlist: {default: {x86_64: https://beta.test/_sow/v1/mirrorlist/beta/rpm-test/el10/x86_64.txt}}
  gpgkey: {default: https://beta.test/pkg/keys/rpm-trust.asc}
  meta: {gpgcheck: 1, repo_gpgcheck: 1}
copy: *definition
`,
			wantError: "uses a YAML alias",
		},
		{
			name: "alias-hidden-inside-mapped-definition",
			body: `shared: &shared harmless
repo_upstream:
  - name: pigsty-pgsql
    releases: [10]
    arch: [x86_64]
    mirrorlist: {default: {x86_64: https://beta.test/_sow/v1/mirrorlist/beta/rpm-test/el10/x86_64.txt}}
    gpgkey: {default: https://beta.test/pkg/keys/rpm-trust.asc}
    meta: {gpgcheck: 1, repo_gpgcheck: 1}
    hidden: *shared
`,
			wantError: "uses a YAML alias",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			counts := make(map[string]int)
			var bindings []yumConsumerBinding
			testEntries := entries
			if test.name == "unmapped-sow-raw-url" {
				testEntries = map[string]yumConsumerMapEntry{}
			}
			err := parseYUMConsumerYAML("consumer.yml", []byte(test.body), testEntries, counts, &bindings)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("parse error=%v, want %q", err, test.wantError)
			}
		})
	}
}

func TestYUMConsumerStageReadRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.yml")
	if err := os.WriteFile(target, []byte("payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "consumer.yml")); err != nil {
		t.Fatal(err)
	}
	if _, err := readYUMConsumerStageFile(root, "consumer.yml"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink stage read error=%v", err)
	}
}

func TestYUMConsumerRepositoryAndStageOverlapIsSymmetric(t *testing.T) {
	parent := t.TempDir()
	repository := filepath.Join(parent, "repository")
	stageInsideRepository := filepath.Join(repository, "review")
	for _, directory := range []string{repository, stageInsideRepository} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if !yumConsumerPathInside(repository, stageInsideRepository) {
		t.Fatal("stage nested in repository was not recognized")
	}
	if !yumConsumerPathInside(parent, repository) {
		t.Fatal("repository nested in stage ancestor was not recognized")
	}
}

func TestYUMConsumerCompatibilityTrustCacheIsPublicationScoped(t *testing.T) {
	repoID := "infra-legacy-x86-64"
	keys := map[string]struct{}{}
	for _, publication := range []string{"cf\x00latest", "cos\x00latest", "cf\x00beta"} {
		key := yumConsumerCompatibilityTrustCacheKey(publication, repoID)
		if _, duplicate := keys[key]; duplicate {
			t.Fatalf("compatibility trust cache collapsed publication %q", publication)
		}
		keys[key] = struct{}{}
	}
}

func TestYUMConsumerRendererRejectsCommentOnlyMarkers(t *testing.T) {
	body := []byte(`# sow-yum-mirrorlist/v2
# mirrorlist = {{ repo.mirrorlist[region][os_arch] }}
# {% set repo_opts = repo_opts | combine({"gpgkey": repo.gpgkey[region]}) %}
`)
	if err := validateYUMConsumerRenderer("renderer.yml", body); err == nil || !strings.Contains(err.Error(), "control flow") {
		t.Fatalf("comment-only renderer error=%v", err)
	}
	stage := t.TempDir()
	writeYUMConsumerPreflightStage(t, stage)
	valid, err := os.ReadFile(filepath.Join(stage, "renderer.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateYUMConsumerRenderer("renderer.yml", valid); err != nil {
		t.Fatalf("reviewed renderer rejected: %v", err)
	}
	lastElse := bytes.LastIndex(valid, []byte("\n{% else %}"))
	if lastElse < 0 {
		t.Fatal("reviewed renderer lacks final RPM/APT branch boundary")
	}
	override := append(append([]byte(nil), valid[:lastElse]...), append([]byte("\nbaseurl = https://repo.pigsty.io/yum/override"), valid[lastElse:]...)...)
	if err := validateYUMConsumerRenderer("renderer.yml", override); err == nil || !strings.Contains(err.Error(), "control flow") {
		t.Fatalf("RPM branch override renderer error=%v", err)
	}
	wrongSelector := bytes.Replace(valid,
		[]byte(`{% if os_version|int in repo.releases and repo.module == module_name and os_arch in repo.arch %}`),
		[]byte(`{% if os_version|int in repo.releases and os_arch in repo.arch %}`), 1)
	if err := validateYUMConsumerRenderer("renderer.yml", wrongSelector); err == nil || !strings.Contains(err.Error(), "control flow") {
		t.Fatalf("outer selector drift renderer error=%v", err)
	}
}

func TestYUMConsumerRemoteTrustTreatsCloseFailureAsNetworkFailure(t *testing.T) {
	wanted := []byte("public trust bytes\n")
	client := &http.Client{Transport: yumConsumerRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			ContentLength: int64(len(wanted)),
			Body:          &yumConsumerCloseErrorBody{reader: bytes.NewReader(wanted)},
			Header:        make(http.Header),
		}, nil
	})}
	err := readYUMConsumerRemoteTrust(t.Context(), client, "https://example.invalid/pkg/keys/rpm-trust.asc", wanted)
	if !errors.Is(err, verify.ErrClientNetwork) || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("remote trust close error=%v", err)
	}
}

func TestYUMConsumerPreparationFailureDiagnosesDurableLockReleaseFailure(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), ".sow")
	lock, err := state.AcquireLock(statePath, "consumer-preflight-release-test", false)
	if err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(statePath, "locks", "state.lock")
	displacedPath := lockPath + ".displaced"
	if err := os.Rename(lockPath, displacedPath); err != nil {
		t.Fatal(err)
	}
	primary := withExitCode(ExitVerification, "injected preparation failure")
	var stderr bytes.Buffer
	resultErr := releaseYUMConsumerPreparationLock(lock, primary, &stderr)
	if resultErr != primary || exitCode(resultErr) != ExitVerification {
		t.Fatalf("release failure replaced primary result: got=%v want=%v", resultErr, primary)
	}
	if diagnostic := stderr.String(); !strings.Contains(diagnostic, "warning: release state lock") ||
		!strings.Contains(diagnostic, "durable record is missing") {
		t.Fatalf("durable lock release failure was hidden: %q", diagnostic)
	}
	if _, err := os.Lstat(displacedPath); err != nil {
		t.Fatalf("foreign lock evidence was removed: %v", err)
	}
}

func TestYUMConsumerVerbHelpHasDedicatedGateSurface(t *testing.T) {
	for _, verb := range []string{"yum-consumer-preflight", "yum-consumer-receipt-check"} {
		t.Run(verb, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Main([]string{"compatibility", verb, "--help"}, &stdout, &stderr); code != ExitOK {
				t.Fatalf("help code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			body := stdout.String() + stderr.String()
			for _, flagName := range []string{"--config", "--root", "--workers", "--chunk-entries", "--recover", "--staged", "--map", "--inventory", "--trust-bundle", "--receipt", "--confirm"} {
				if !strings.Contains(body, "\n  -"+strings.TrimPrefix(flagName, "--")) {
					t.Errorf("help omitted %s: %s", flagName, body)
				}
			}
			if hasValidity := strings.Contains(body, "\n  -valid-for"); hasValidity != (verb == "yum-consumer-preflight") {
				t.Errorf("--valid-for presence=%v for %s", hasValidity, verb)
			}
			for _, forbidden := range []string{"--repo", "--os", "--arch"} {
				if strings.Contains(body, forbidden) {
					t.Errorf("help exposed ordinary selector %s: %s", forbidden, body)
				}
			}
		})
	}
}

var _ io.ReadCloser = (*yumConsumerCloseErrorBody)(nil)
