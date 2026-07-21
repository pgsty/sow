package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/aptrepo"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/verify"
	"github.com/pgsty/sow/internal/views"
	"github.com/pgsty/sow/internal/yumrepo"
)

const verifyTestProToken = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"

func TestNetworkCredentialCheckReportsActionableOperationalFinding(t *testing.T) {
	var networkFailure atomic.Bool
	report := verify.Run(t.Context(), verify.Request{
		Layers: []verify.Layer{verify.LayerL3}, Workers: 1,
		Checks: []verify.Check{networkCredentialCheck("cdn/cf/stable", verify.LayerL3, &networkFailure)},
	})
	if report.Outcome != verify.OutcomeIncomplete || report.Exit != verify.ExitOperational || !networkFailure.Load() {
		t.Fatalf("credential report=%+v network_failure=%t", report, networkFailure.Load())
	}
	if len(report.Findings) != 1 || report.Findings[0].Code != "CDN_VERIFICATION_CREDENTIAL_UNAVAILABLE" || report.Findings[0].Category != verify.CategoryOperational {
		t.Fatalf("credential finding is not actionable: %+v", report.Findings)
	}
	var output bytes.Buffer
	if err := emitVerifyReport(&output, false, report, networkFailure.Load()); exitCode(err) != ExitNetworkAuth {
		t.Fatalf("credential exit=%d err=%v report=%s", exitCode(err), err, output.String())
	}
	if !strings.Contains(output.String(), "CDN_VERIFICATION_CREDENTIAL_UNAVAILABLE") || strings.Contains(output.String(), "VERIFY_CHECK_OPERATIONAL") {
		t.Fatalf("credential report lost its safe reason: %s", output.String())
	}
}

func TestBuildCompatibilityL4ChecksBindsIndependentGenerationAndRawRoutes(t *testing.T) {
	root := nginxWorkerTempDir(t)
	privatePath, _ := writeLegacySigningKey(t, root)
	privateKey, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	verificationTime := time.Now().UTC()
	metadataVerifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(privateKey), verificationTime)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Path: filepath.Join(root, "sow.yaml"),
		Targets: map[string]config.Target{
			"local": {CDN: config.CDN{BaseURL: "https://repo.example.invalid"}},
		},
	}
	packageKeyring, _, err := loadRPMPackageKeyring(cfg.Path, "package-trust.asc")
	if err != nil {
		t.Fatal(err)
	}
	projection := config.YUMCompatibilityProjection{
		ID: "infra-legacy-x86-64", Root: "yum/infra^next/x86_64",
		Source: config.YUMCompatibilitySource{Arch: "x86_64"},
	}
	channel := pub.ChannelState{Generation: 42, LegacyRoot: projection.Root}
	var networkFailure atomic.Bool
	checks, err := buildCompatibilityL4Checks(cfg, "local", "client/local/latest/compatibility/"+projection.ID, projection, channel, http.Header{"X-Test": []string{"bound"}}, metadataVerifier, packageKeyring, verificationTime, t.TempDir(), 7, &networkFailure)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 2 {
		t.Fatalf("compatibility L4 checks=%d want=2", len(checks))
	}
	probes := make(map[string]verify.YUMProtocolProbe, 2)
	for _, check := range checks {
		clientCheck, ok := check.(verify.ClientCheck)
		if !ok {
			t.Fatalf("compatibility L4 check type=%T", check)
		}
		probe, ok := clientCheck.Probe.(verify.YUMProtocolProbe)
		if !ok {
			t.Fatalf("compatibility L4 probe type=%T", clientCheck.Probe)
		}
		probes[clientCheck.CheckID] = probe
	}
	generation := probes["client/local/latest/compatibility/"+projection.ID+"/generation"]
	if generation.MirrorlistPath != "_sow/v1/mirrorlist/latest/infra-legacy-x86-64/cross-el/x86_64.txt" || generation.RepositoryPath != "" || generation.ExpectedGenerationURL != "https://repo.example.invalid/_sow/v1/g/00000000000000000042/yum/infra%5Enext/x86_64/" {
		t.Fatalf("generation probe=%+v", generation)
	}
	raw := probes["client/local/latest/compatibility/"+projection.ID+"/raw"]
	if raw.RepositoryPath != projection.Root || raw.MirrorlistPath != "" || raw.ExpectedGenerationURL != "" {
		t.Fatalf("raw probe=%+v", raw)
	}
	for name, probe := range probes {
		if probe.Compression != yumrepo.CompressionGzip || probe.Architecture != "x86_64" || probe.Verifier == nil || probe.PackageKeyring == nil || probe.ChunkEntries != 7 || probe.Headers.Get("X-Test") != "bound" {
			t.Fatalf("probe %s lost frozen protocol contract: %+v", name, probe)
		}
	}
}

func TestCompatibilityL4ChecksConsumeBothLoopbackRoutesIndependently(t *testing.T) {
	fixture := newFlatYUMCompatibilityFixture(t)
	verificationTime := time.Now().UTC()
	canonicalPackage := filepath.Join(fixture.root, filepath.FromSlash(fixture.canonical))
	if err := copyAllSelectorFile(filepath.Join(fixture.root, fixture.flat), canonicalPackage, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(fixture.root, "repodata")); err != nil {
		t.Fatal(err)
	}
	metadataSigner, err := yumrepo.NewOpenPGPSigner(bytes.NewReader(fixture.privateKey), nil, verificationTime.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := yumrepo.Generate(t.Context(), filepath.Join(fixture.root, "repodata"), yumrepo.Options{
		ELMajor: 0, Frozen: true, Compatibility: true, Compression: yumrepo.CompressionGzip,
		Revision: verificationTime.Add(-time.Minute).Unix(), Signer: metadataSigner,
	}, &yumrepo.SliceIterator{Inputs: []yumrepo.PackageInput{{Path: canonicalPackage, Basename: filepath.Base(canonicalPackage), FileTime: verificationTime.Add(-time.Minute)}}}); err != nil {
		t.Fatal(err)
	}
	metadataVerifier, err := yumrepo.NewOpenPGPVerifier(bytes.NewReader(fixture.privateKey), verificationTime)
	if err != nil {
		t.Fatal(err)
	}
	const (
		mirrorPath      = "/_sow/v1/mirrorlist/latest/infra-legacy-x86-64/cross-el/x86_64.txt"
		generationPath  = "/_sow/v1/g/00000000000000000042/yum/infra/x86_64/"
		rawPath         = "/yum/infra/x86_64/"
		generationCheck = "client/local/latest/compatibility/infra-legacy-x86-64/generation"
		rawCheck        = "client/local/latest/compatibility/infra-legacy-x86-64/raw"
	)
	var generationEnabled, rawEnabled, tamperGeneration atomic.Bool
	generationEnabled.Store(true)
	rawEnabled.Store(true)
	files := http.FileServer(http.Dir(fixture.root))
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == mirrorPath:
			fmt.Fprintf(writer, "https://%s%s\n", request.Host, generationPath)
		case strings.HasPrefix(request.URL.Path, generationPath) && generationEnabled.Load():
			if tamperGeneration.Load() && request.URL.Path == generationPath+"repodata/repomd.xml" {
				body, err := os.ReadFile(filepath.Join(fixture.root, "repodata", "repomd.xml"))
				if err != nil {
					http.Error(writer, "fixture", http.StatusInternalServerError)
					return
				}
				body[len(body)-1] ^= 1
				_, _ = writer.Write(body)
				return
			}
			http.StripPrefix(generationPath, files).ServeHTTP(writer, request)
		case strings.HasPrefix(request.URL.Path, rawPath) && rawEnabled.Load():
			http.StripPrefix(rawPath, files).ServeHTTP(writer, request)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	previousClient := verificationHTTPClient
	verificationHTTPClient = server.Client()
	t.Cleanup(func() { verificationHTTPClient = previousClient })
	cfg := &config.Config{Targets: map[string]config.Target{"local": {CDN: config.CDN{BaseURL: server.URL}}}}
	projection := config.YUMCompatibilityProjection{ID: "infra-legacy-x86-64", Root: "yum/infra/x86_64", Source: config.YUMCompatibilitySource{Arch: "x86_64"}}
	channel := pub.ChannelState{Generation: 42, LegacyRoot: projection.Root}
	var networkFailure atomic.Bool
	checks, err := buildCompatibilityL4Checks(cfg, "local", "client/local/latest/compatibility/"+projection.ID, projection, channel, nil, metadataVerifier, fixture.packageKeyring, verificationTime, t.TempDir(), 2, &networkFailure)
	if err != nil {
		t.Fatal(err)
	}
	byID := make(map[string]verify.Check, len(checks))
	for _, check := range checks {
		byID[check.ID()] = check
	}
	run := func(check verify.Check) verify.Report {
		return verify.Run(t.Context(), verify.Request{Layers: []verify.Layer{verify.LayerL4}, Checks: []verify.Check{check}, Workers: 1})
	}
	for _, id := range []string{generationCheck, rawCheck} {
		if report := run(byID[id]); report.Outcome != verify.OutcomePassed {
			t.Fatalf("loopback compatibility route %s report=%#v", id, report)
		}
	}
	generationEnabled.Store(false)
	if report := run(byID[generationCheck]); report.Outcome == verify.OutcomePassed {
		t.Fatal("missing generation route passed its independent L4 check")
	}
	if report := run(byID[rawCheck]); report.Outcome != verify.OutcomePassed {
		t.Fatalf("raw route depended on missing generation route: %#v", report)
	}
	generationEnabled.Store(true)
	rawEnabled.Store(false)
	if report := run(byID[rawCheck]); report.Outcome == verify.OutcomePassed {
		t.Fatal("missing raw route passed its independent L4 check")
	}
	if report := run(byID[generationCheck]); report.Outcome != verify.OutcomePassed {
		t.Fatalf("generation route depended on missing raw route: %#v", report)
	}
	rawEnabled.Store(true)
	tamperGeneration.Store(true)
	if report := run(byID[generationCheck]); report.Outcome == verify.OutcomePassed {
		t.Fatal("tampered generation repomd passed signature/integrity verification")
	}
	if report := run(byID[rawCheck]); report.Outcome != verify.OutcomePassed {
		t.Fatalf("raw route was affected by generation-only tamper: %#v", report)
	}
}

func TestExactAPTRepositoryProbeBindsSparseSuiteComponentContract(t *testing.T) {
	for _, test := range []struct {
		name       string
		components []string
	}{
		{name: "stable", components: []string{"main"}},
		{name: "testing", components: []string{"main", "18", "19"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := append([]string(nil), test.components...)
			probe := exactAPTRepositoryProbe(verify.APTProtocolProbe{Suite: "bookworm-pgdg-" + test.name, Architecture: "arm64"}, input)
			if len(probe.Components) != len(input) {
				t.Fatalf("component probes=%d want=%d", len(probe.Components), len(input))
			}
			for index, component := range probe.Components {
				if component.Component != input[index] || strings.Join(component.ExpectedComponents, ",") != strings.Join(input, ",") {
					t.Fatalf("probe[%d]=%+v input=%v", index, component, input)
				}
			}
			probe.Components[0].ExpectedComponents[0] = "mutated"
			if input[0] != "main" || len(probe.Components) > 1 && probe.Components[1].ExpectedComponents[0] != "main" {
				t.Fatal("L4 exact component contracts alias caller or sibling probe slices")
			}
		})
	}
}

func TestBuildL4ChecksCarriesSparseSuiteComponentsThroughLocalProtocol(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(sparseAPTMaterializeTestConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	privatePath := writePublishTestPrivateKey(t, root)
	publicPath := writeVerifyPublicKey(t, privatePath)
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	cfg.GPG.PublicKey = filepath.Base(publicPath)

	privateKey, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := aptrepo.NewSigner(bytes.NewReader(privateKey), nil)
	if err != nil {
		t.Fatal(err)
	}
	debPath := decodeVerifyFixture(t, filepath.Join("..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"), filepath.Join(root, "fixture.deb"))
	mainPackage, err := aptrepo.InspectPackage(t.Context(), debPath, "main")
	if err != nil {
		t.Fatal(err)
	}
	testingPackage, err := aptrepo.InspectPackage(t.Context(), debPath, "18")
	if err != nil {
		t.Fatal(err)
	}
	archiveRoot := filepath.Join(root, "apt", "pgdg")
	debBody, err := os.ReadFile(debPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{mainPackage.PoolPath, testingPackage.PoolPath} {
		destination := filepath.Join(archiveRoot, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destination, debBody, 0o444); err != nil {
			t.Fatal(err)
		}
	}
	created := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	if _, err := aptrepo.Generate(t.Context(), archiveRoot, aptrepo.RepositoryConfig{
		Origin: "Pigsty", Label: "Pigsty", Suite: "bookworm-pgdg", Codename: "bookworm-pgdg",
		Components: []string{"main"}, Architectures: []string{"arm64"}, Date: created,
	}, []aptrepo.Index{{Component: "main", Architecture: "arm64", Packages: []aptrepo.Package{mainPackage}}}, signer); err != nil {
		t.Fatal(err)
	}
	if _, err := aptrepo.Generate(t.Context(), archiveRoot, aptrepo.RepositoryConfig{
		Origin: "Pigsty", Label: "Pigsty", Suite: "bookworm-pgdg-testing", Codename: "bookworm-pgdg-testing",
		Components: []string{"main", "18", "19"}, Architectures: []string{"arm64"}, Date: created,
	}, []aptrepo.Index{
		{Component: "main", Architecture: "arm64"},
		{Component: "18", Architecture: "arm64", Packages: []aptrepo.Package{testingPackage}},
		{Component: "19", Architecture: "arm64"},
	}, signer); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewTLSServer(http.FileServer(http.Dir(root)))
	defer server.Close()
	cfg.Targets = map[string]config.Target{"cf": {CDN: config.CDN{Kind: "cloudflare", BaseURL: server.URL, BetaBaseURL: server.URL}}}

	canonical := state.New(cfg.StatePath())
	stages := make(map[string]string)
	for _, suite := range []string{"bookworm-pgdg", "bookworm-pgdg-testing"} {
		canonicalPath, err := state.ViewPath("beta", "apt-pgdg", suite, "arm64")
		if err != nil {
			t.Fatal(err)
		}
		stage := filepath.Join(t.TempDir(), suite+".tsv")
		if err := os.WriteFile(stage, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		stages[canonicalPath] = stage
	}
	commit, _, err := canonical.InstallPaths(stages, "test: seed sparse L4 view refs")
	if err != nil {
		t.Fatal(err)
	}
	generationRefs := make([]pub.RefState, 0, 2)
	for _, suite := range []string{"bookworm-pgdg", "bookworm-pgdg-testing"} {
		ref, err := state.ViewRef("beta", "apt-pgdg", suite, "arm64")
		if err != nil {
			t.Fatal(err)
		}
		if err := canonical.AdvanceRef(ref, plumbing.ZeroHash, commit, false); err != nil {
			t.Fatal(err)
		}
		generationRefs = append(generationRefs, pub.RefState{Name: ref.String(), Commit: commit.String(), ManifestSHA256: digestBytesCLI(nil)})
	}
	configSHA, err := publicationConfigSHA256ForRefs(cfg, generationRefs)
	if err != nil {
		t.Fatal(err)
	}
	repositoryKeySHA, err := repositoryTrustAnchorSHA256ForRefs(cfg, generationRefs)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := (pub.Plan{}).WithCDN(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	generation := pub.TargetGeneration{
		Schema: pub.TargetGenerationSchema, Target: pub.TargetCloudflare,
		Generation: 1, DesiredCommit: commit.String(), IntentView: "beta",
		ConfigSHA256: configSHA, RepositoryKeySHA256: repositoryKeySHA, Refs: generationRefs,
		ContentManifestSHA256: digestBytesCLI(nil),
	}
	generationBody, err := generation.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	planSHA, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := pub.NewCheckpoint(generation, "sparse-l4-local", planSHA, pub.PhaseCheckpointCommitted, created)
	if err != nil {
		t.Fatal(err)
	}
	checkpointBody, err := checkpoint.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	planBody, err := plan.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	remoteStages := make(map[string]string, 3)
	for name, body := range map[string][]byte{"generation.json": generationBody, "checkpoint.json": checkpointBody, "plan.json": planBody} {
		canonicalPath, err := remoteIntentStatePath("cf", "beta", "", name)
		if err != nil {
			t.Fatal(err)
		}
		stage := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(stage, body, 0o600); err != nil {
			t.Fatal(err)
		}
		remoteStages[canonicalPath] = stage
	}
	if _, _, err := canonical.InstallPaths(remoteStages, "test: committed sparse L4 publication"); err != nil {
		t.Fatal(err)
	}

	previousClient := verificationHTTPClient
	verificationHTTPClient = server.Client()
	t.Cleanup(func() { verificationHTTPClient = previousClient })
	var networkFailure atomic.Bool
	checks, err := buildL4Checks(cfg, canonical, cfg.Repos, []string{"beta"}, commonFlags{workers: 2, chunk: 1}, []string{"cf"}, publicPath, nil, t.TempDir(), &networkFailure)
	if err != nil {
		t.Fatal(err)
	}
	wantComponents := map[string]string{"bookworm-pgdg": "main", "bookworm-pgdg-testing": "main,18,19"}
	if len(checks) != len(wantComponents) {
		t.Fatalf("L4 checks=%d want=%d", len(checks), len(wantComponents))
	}
	for _, check := range checks {
		clientCheck, ok := check.(verify.ClientCheck)
		if !ok {
			t.Fatalf("builder returned non-client L4 check %T", check)
		}
		probe, ok := clientCheck.Probe.(verify.APTRepositoryProbe)
		if !ok || len(probe.Components) == 0 {
			t.Fatalf("builder returned non-APT or empty probe %#v", clientCheck.Probe)
		}
		suite := probe.Components[0].Suite
		want, exists := wantComponents[suite]
		if !exists || len(probe.Components) != len(strings.Split(want, ",")) {
			t.Fatalf("suite=%s probes=%d want=%s", suite, len(probe.Components), want)
		}
		for _, component := range probe.Components {
			if strings.Join(component.ExpectedComponents, ",") != want {
				t.Fatalf("suite=%s expected components=%v want=%s", suite, component.ExpectedComponents, want)
			}
		}
	}
	report := verify.Run(t.Context(), verify.Request{Layers: []verify.Layer{verify.LayerL4}, Checks: checks, Workers: 2})
	if report.Outcome != verify.OutcomePassed || report.Exit != verify.ExitSuccess || networkFailure.Load() {
		t.Fatalf("local sparse L4 report=%#v network_failure=%t", report, networkFailure.Load())
	}
}

func TestVerifyCLIL3AndL4ClosePublishedAPTAndYUMProtocols(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	caretConfig := strings.Replace(publishPackageConfig, "path: yum/test/x86_64", "path: yum/test^next/x86_64", 1)
	if err := os.WriteFile(configPath, []byte(caretConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	debPath := decodeVerifyFixture(t, filepath.Join("..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"), filepath.Join(root, "libpqtypes.deb"))
	rpmPath := decodeVerifyFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "pgdg-repo.rpm"))
	keyPath := writePublishTestPrivateKey(t, root)
	publicKeyPath := writeVerifyPublicKey(t, keyPath)

	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	transport := newCloudProtocolTransport()
	previousPublishClient, previousVerificationClient := publishProviderHTTPClient, verificationHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	verificationHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() {
		publishProviderHTTPClient = previousPublishClient
		verificationHTTPClient = previousVerificationClient
	})

	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	for _, add := range [][]string{
		{"add", debPath, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--workers", "2"},
		{"add", rpmPath, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2"},
	} {
		if code, stdout, stderr := run(add...); code != ExitOK {
			t.Fatalf("add code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
	}
	if code, stdout, stderr := run("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2"); code != ExitOK || !strings.Contains(stdout, "status=published") {
		t.Fatalf("publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}

	if code, stdout, stderr := run("verify", "--layer", "L3", "--view", "beta", "--target", "cf", "--config", configPath, "--workers", "2"); code != ExitOK || !strings.Contains(stdout, "outcome=passed") {
		t.Fatalf("L3 code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	// An explicit leaf selector must narrow the committed change-set before any
	// CDN request is built. Otherwise a healthy sibling repository can hide a
	// selected repository whose plan has no usable probe or whose bytes drifted.
	transport.mutex.Lock()
	transport.cdnURLs = nil
	transport.mutex.Unlock()
	if code, stdout, stderr := run("verify", "--layer", "L3", "--view", "beta", "--target", "cf", "--repo", "deb-test", "--arch", "arm64", "--config", configPath, "--workers", "2"); code != ExitOK || !strings.Contains(stdout, "outcome=passed") {
		t.Fatalf("selected APT L3 code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	aptURLs := append([]string(nil), transport.cdnURLs...)
	transport.cdnURLs = nil
	transport.mutex.Unlock()
	if joined := strings.Join(aptURLs, "\n"); len(aptURLs) == 0 || !strings.Contains(joined, "/apt/test/") || strings.Contains(joined, "/yum/test%5Enext/") || strings.Contains(joined, "/_sow/v1/mirrorlist/") {
		t.Fatalf("selected APT L3 escaped its repository leaf: %v", aptURLs)
	}
	if code, stdout, stderr := run("verify", "--layer", "L3", "--view", "beta", "--target", "cf", "--repo", "rpm-test", "--os", "el10", "--arch", "x86_64", "--config", configPath, "--workers", "2"); code != ExitOK || !strings.Contains(stdout, "outcome=passed") {
		t.Fatalf("selected YUM L3 code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	yumURLs := append([]string(nil), transport.cdnURLs...)
	transport.cdnURLs = nil
	transport.mutex.Unlock()
	if joined := strings.Join(yumURLs, "\n"); len(yumURLs) == 0 || !strings.Contains(joined, "/yum/test%5Enext/") || strings.Contains(joined, "/yum/test^next/") || !strings.Contains(joined, "/_sow/v1/mirrorlist/beta/rpm-test/el10/x86_64.txt") || strings.Contains(joined, "/apt/test/") {
		t.Fatalf("selected YUM L3 escaped or omitted its exact logical channel: %v", yumURLs)
	}
	// Publishing another view advances the bucket-global checkpoint. The beta
	// plan must remain independently verifiable instead of being overwritten by
	// the latest intent.
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--workers", "2"); code != ExitOK {
		t.Fatalf("promote latest code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("publish", "--view", "latest", "--target", "cf", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2"); code != ExitOK {
		t.Fatalf("publish latest code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, viewName := range []string{"beta", "latest"} {
		if code, stdout, stderr := run("verify", "--layer", "L3", "--view", viewName, "--target", "cf", "--config", configPath, "--workers", "2"); code != ExitOK || !strings.Contains(stdout, "outcome=passed") {
			t.Fatalf("retained %s L3 code=%d stdout=%s stderr=%s", viewName, code, stdout, stderr)
		}
		intentPlan := filepath.Join(root, ".sow", "state", "remotes", "cf", "intents", "views", viewName, "plan.json")
		if _, err := os.Stat(intentPlan); err != nil {
			t.Fatalf("%s intent plan missing: %v", viewName, err)
		}
	}
	for _, repository := range []struct {
		id, client, pkg string
	}{{"deb-test", `client="apt"`, "libpqtypes0"}, {"rpm-test", `client="dnf"`, "pgdg-redhat-nonfree-repo"}} {
		code, stdout, stderr := run("verify", "--layer", "L4", "--view", "beta", "--target", "cf", "--repo", repository.id, "--config", configPath, "--gpg-public-key-file", publicKeyPath, "--workers", "2", "--chunk-entries", "1")
		if code != ExitOK || !strings.Contains(stdout, "outcome=passed") || !strings.Contains(stdout, "CLIENT_EVIDENCE_ACCEPTED") || !strings.Contains(stdout, repository.client) || !strings.Contains(stdout, repository.pkg) {
			t.Fatalf("L4 %s code=%d stdout=%s stderr=%s", repository.id, code, stdout, stderr)
		}
	}

	transport.mutex.Lock()
	key := ".sow/beta/apt/test/dists/jammy/InRelease"
	original := transport.objects[key]
	tampered := original
	tampered.body = append(append([]byte(nil), original.body...), '\n')
	transport.objects[key] = tampered
	transport.mutex.Unlock()
	code, stdout, stderr := run("verify", "--layer", "L3", "--view", "beta", "--target", "cf", "--config", configPath)
	if code != ExitVerification || !strings.Contains(stdout, "CDN_BYTES_DRIFT") {
		t.Fatalf("L3 drift code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	transport.objects[key] = original
	transport.mutex.Unlock()

	verificationHTTPClient = &http.Client{Transport: failingVerificationTransport{}}
	code, stdout, stderr = run("verify", "--layer", "L3", "--view", "beta", "--target", "cf", "--config", configPath)
	if code != ExitNetworkAuth || !strings.Contains(stdout, "CDN_REQUEST_FAILED") || !strings.Contains(stderr, "remote verification incomplete") {
		t.Fatalf("L3 network code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, output := range []string{stdout, stderr} {
		if strings.Contains(output, "cf-api-token") || strings.Contains(output, "r2-secret") || strings.Contains(output, "verify-secret") {
			t.Fatalf("verification output leaked a credential: %s", output)
		}
	}
}

func TestVerifyCLIStableUsesRuntimeTokenWithoutPersistingOrLoggingIt(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	caretConfig := strings.Replace(publishPackageConfig, "path: yum/test/x86_64", "path: yum/test^next/x86_64", 1)
	if err := os.WriteFile(configPath, []byte(caretConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	debPath := decodeVerifyFixture(t, filepath.Join("..", "aptrepo", "testdata", "libpqtypes0_1.5.1-9.pgdg22.04+1_arm64.deb.b64"), filepath.Join(root, "libpqtypes.deb"))
	rpmPath := decodeVerifyFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "pgdg-repo.rpm"))
	keyPath := writePublishTestPrivateKey(t, root)
	publicKeyPath := writeVerifyPublicKey(t, keyPath)
	tokenPath := filepath.Join(root, "pro-token")
	if err := os.WriteFile(tokenPath, []byte(verifyTestProToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	cdnSecret := `{"api_token":"cf-api-token","basic_username":"verifier","basic_password":"verify-secret"}`
	t.Setenv("SOW_TEST_CF", cdnSecret)
	transport := newCloudProtocolTransport()
	previousPublishClient, previousVerificationClient := publishProviderHTTPClient, verificationHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	verificationHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() {
		publishProviderHTTPClient = previousPublishClient
		verificationHTTPClient = previousVerificationClient
	})
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	for _, add := range [][]string{
		{"add", debPath, "--config", configPath, "--repo", "deb-test", "--gpg-private-key-file", keyPath, "--workers", "2"},
		{"add", rpmPath, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2"},
	} {
		if code, stdout, stderr := run(add...); code != ExitOK {
			t.Fatalf("stable add code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
	}
	if code, stdout, stderr := run("promote", "beta", "stable", "--config", configPath, "--workers", "2"); code != ExitOK {
		t.Fatalf("stable promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("publish", "--view", "stable", "--target", "cf", "--config", configPath, "--gpg-private-key-file", keyPath, "--workers", "2"); code != ExitOK || !strings.Contains(stdout, "status=published") {
		t.Fatalf("stable publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	planPath := filepath.Join(root, ".sow", "state", "remotes", "cf", "plan.json")
	planBefore, err := os.ReadFile(planPath)
	if err != nil || bytes.Contains(planBefore, []byte(verifyTestProToken)) || !bytes.Contains(planBefore, []byte("/pro/v1/basic/")) {
		t.Fatalf("canonical plan token contract err=%v body=%s", err, planBefore)
	}
	transport.mutex.Lock()
	basicBefore, tokenBefore := transport.basicGets, transport.tokenGets
	transport.mutex.Unlock()
	t.Setenv("SOW_TEST_CF", "")

	for _, invocation := range [][]string{
		{"verify", "--layer", "L3", "--view", "stable", "--target", "cf", "--config", configPath, "--pro-token-file", tokenPath, "--workers", "2"},
		{"verify", "--layer", "L4", "--view", "stable", "--target", "cf", "--repo", "deb-test", "--config", configPath, "--gpg-public-key-file", publicKeyPath, "--pro-token-file", tokenPath, "--workers", "2", "--chunk-entries", "1"},
		{"verify", "--layer", "L4", "--view", "stable", "--target", "cf", "--repo", "rpm-test", "--config", configPath, "--gpg-public-key-file", publicKeyPath, "--pro-token-file", tokenPath, "--workers", "2", "--chunk-entries", "1"},
	} {
		code, stdout, stderr := run(invocation...)
		if code != ExitOK || !strings.Contains(stdout, "outcome=passed") {
			t.Fatalf("stable token verify code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		if strings.Contains(stdout, verifyTestProToken) || strings.Contains(stderr, verifyTestProToken) {
			t.Fatalf("stable verification leaked runtime token stdout=%s stderr=%s", stdout, stderr)
		}
	}
	code, jsonReport, jsonError := run("verify", "--layer", "L3", "--view", "stable", "--target", "cf", "--config", configPath, "--pro-token-file", tokenPath, "--json")
	if code != ExitOK || !strings.Contains(jsonReport, `"outcome":"passed"`) || strings.Contains(jsonReport+jsonError, verifyTestProToken) {
		t.Fatalf("stable token JSON code=%d report=%s stderr=%s", code, jsonReport, jsonError)
	}
	transport.mutex.Lock()
	basicAfterToken, tokenAfter := transport.basicGets, transport.tokenGets
	transport.mutex.Unlock()
	if tokenAfter <= tokenBefore || basicAfterToken != basicBefore {
		t.Fatalf("runtime token route token=%d/%d basic=%d/%d", tokenBefore, tokenAfter, basicBefore, basicAfterToken)
	}
	planAfter, err := os.ReadFile(planPath)
	if err != nil || !bytes.Equal(planBefore, planAfter) {
		t.Fatal("runtime token verification mutated the canonical publication plan")
	}

	t.Setenv("SOW_TEST_CF", cdnSecret)
	code, stdout, stderr := run("verify", "--layer", "L3", "--view", "stable", "--target", "cf", "--config", configPath, "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "outcome=passed") || strings.Contains(stdout+stderr, "verify-secret") {
		t.Fatalf("stable Basic fallback code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	basicAfterFallback := transport.basicGets
	transport.mutex.Unlock()
	if basicAfterFallback <= basicAfterToken {
		t.Fatal("stable Basic fallback did not authenticate any verification requests")
	}

	t.Setenv("SOW_TEST_CF", "")
	for _, invocation := range [][]string{
		{"verify", "--layer", "L3", "--view", "stable", "--target", "cf", "--config", configPath, "--workers", "2"},
		{"verify", "--layer", "L4", "--view", "stable", "--target", "cf", "--repo", "rpm-test", "--config", configPath, "--gpg-public-key-file", publicKeyPath, "--workers", "2", "--chunk-entries", "1"},
	} {
		code, stdout, stderr := run(invocation...)
		if code != ExitNetworkAuth || !strings.Contains(stdout, "CDN_VERIFICATION_CREDENTIAL_UNAVAILABLE") || !strings.Contains(stderr, "remote verification incomplete") {
			t.Fatalf("missing stable credential code=%d stdout=%s stderr=%s", code, stdout, stderr)
		}
		if strings.Contains(stdout+stderr, verifyTestProToken) || strings.Contains(stdout+stderr, "verify-secret") || strings.Contains(stdout, "VERIFY_CHECK_OPERATIONAL") {
			t.Fatalf("missing stable credential report leaked or lost its reason: stdout=%s stderr=%s", stdout, stderr)
		}
	}
}

func TestVerificationHeadersResolveBasicOnlyForStable(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishPackageConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_CF", `{"api_token":"not-relevant","basic_username":"verifier","basic_password":"verify-secret"}`)
	stable, err := verificationHeaders(cfg, "cf", "stable", nil)
	if err != nil {
		t.Fatal(err)
	}
	username, password, ok := (&http.Request{Header: stable}).BasicAuth()
	if !ok || username != "verifier" || password != "verify-secret" {
		t.Fatal("stable verification did not load the configured Basic credential")
	}
	t.Setenv("SOW_TEST_CF", "")
	for _, viewName := range []string{"beta", "latest"} {
		headers, err := verificationHeaders(cfg, "cf", viewName, nil)
		if err != nil || len(headers) != 0 {
			t.Fatalf("%s unexpectedly resolved CDN credentials: headers=%v err=%v", viewName, headers, err)
		}
	}
}

func TestCommittedVerificationStateAcceptsZeroObjectPlans(t *testing.T) {
	empty, err := (pub.Plan{}).WithCDN("https://repo.test")
	if err != nil {
		t.Fatal(err)
	}
	deletionOnly, err := (pub.Plan{Deletes: []pub.PlannedDelete{{
		RemoteKey: ".sow/snapshots/all-20260701.json",
		CDNPath:   "pro/v1/basic/_sow/v1/snapshots/all-20260701/_route.json",
	}}}).WithCDN("https://repo.test")
	if err != nil {
		t.Fatal(err)
	}

	for name, plan := range map[string]pub.Plan{"empty": empty, "deletion-only": deletionOnly} {
		t.Run(name, func(t *testing.T) {
			root := nginxWorkerTempDir(t)
			configPath := filepath.Join(root, "sow.yaml")
			if err := os.WriteFile(configPath, []byte(publishAssetConfig), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(configPath, "")
			if err != nil {
				t.Fatal(err)
			}
			canonical, _, _, _ := installZeroObjectSnapshotPublication(t, cfg, plan)
			publication, err := loadCommittedVerificationState(canonical, "cf", "snapshot", "all-20260712")
			if err != nil {
				t.Fatalf("zero-object committed state rejected: %v", err)
			}
			if len(publication.plan.Objects) != 0 || len(publication.plan.Verify) != 0 || len(publication.plan.Deletes) != len(plan.Deletes) {
				t.Fatalf("decoded zero-object plan=%#v", publication.plan)
			}
		})
	}
}

func TestSnapshotAbsenceFiltersOnlyTheRestoredSnapshot(t *testing.T) {
	const restored = "all-20260701"
	const retired = "all-20260702"
	aggregate := aggregateVerificationState{
		generation: pub.TargetGeneration{Refs: []pub.RefState{{Name: "refs/sow/snapshots/" + restored + "/assets/all/all"}}},
		inventory: map[string]struct{}{
			".sow/snapshots/" + restored + ".json":                       {},
			".sow/gated/snapshots/" + restored + "/yum/repo/package.rpm": {},
		},
	}
	expectations := []pub.VerifyAbsentObject{
		{URL: "https://repo.test/pro/v1/basic/_sow/v1/snapshots/" + restored + "/_route.json"},
		{URL: "https://repo.test/pro/v1/basic/_sow/v1/snapshots/" + retired + "/_route.json"},
	}
	filtered := filterSupersededSnapshotAbsences(expectations, aggregate)
	if len(filtered) != 1 || !strings.Contains(filtered[0].URL, retired) {
		t.Fatalf("active snapshot absence filter=%#v", filtered)
	}
	deletions := []pub.PlannedDelete{
		{RemoteKey: ".sow/snapshots/" + restored + ".json", CDNPath: "pro/v1/basic/_sow/v1/snapshots/" + restored + "/_route.json"},
		{RemoteKey: ".sow/gated/snapshots/" + restored + "/yum/repo/package.rpm"},
		{RemoteKey: ".sow/snapshots/" + retired + ".json", CDNPath: "pro/v1/basic/_sow/v1/snapshots/" + retired + "/_route.json"},
		{RemoteKey: ".sow/gated/snapshots/" + retired + "/yum/repo/package.rpm"},
	}
	filteredDeletes := filterSupersededSnapshotDeletions(deletions, aggregate)
	if len(filteredDeletes) != 2 {
		t.Fatalf("active snapshot deletion filter=%#v", filteredDeletes)
	}
	for _, deletion := range filteredDeletes {
		if !strings.Contains(deletion.RemoteKey, retired) {
			t.Fatalf("restored snapshot deletion remained: %#v", filteredDeletes)
		}
	}
	delete(aggregate.inventory, ".sow/gated/snapshots/"+restored+"/yum/repo/package.rpm")
	filteredDeletes = filterSupersededSnapshotDeletions(deletions, aggregate)
	if len(filteredDeletes) != 3 {
		t.Fatalf("partial restore hid an unmaterialized historical deletion: %#v", filteredDeletes)
	}
}

func TestCurrentAggregateVerificationInventoryFailsClosed(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := (pub.Plan{}).WithCDN("https://repo.test")
	if err != nil {
		t.Fatal(err)
	}
	canonical, generationBody, checkpointBody, _ := installZeroObjectSnapshotPublication(t, cfg, plan)
	planBody, err := plan.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	staged := make(map[string]string)
	for name, body := range map[string][]byte{
		remoteStatePath("cf", "generation.json"): generationBody,
		remoteStatePath("cf", "checkpoint.json"): checkpointBody,
		remoteStatePath("cf", "plan.json"):       planBody,
	} {
		filename := filepath.Join(t.TempDir(), filepath.Base(name))
		if err := os.WriteFile(filename, body, 0o600); err != nil {
			t.Fatal(err)
		}
		staged[name] = filename
	}
	if _, _, err := canonical.InstallPaths(staged, "test: aggregate verification triplet"); err != nil {
		t.Fatal(err)
	}
	assertCode := func(want string) {
		t.Helper()
		_, err := loadCurrentAggregateVerificationState(canonical, "cf", map[string]struct{}{pub.CheckpointKey: {}})
		var stateErr *verificationStateError
		if !errors.As(err, &stateErr) || stateErr.code != want {
			t.Fatalf("aggregate inventory error=%v state=%#v want=%s", err, stateErr, want)
		}
	}
	assertCode("REMOTE_AGGREGATE_INVENTORY_MISSING")

	malformed := filepath.Join(t.TempDir(), "inventory.tsv")
	if err := os.WriteFile(malformed, []byte("not-a-manifest\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := canonical.InstallPaths(map[string]string{remoteStatePath("cf", "inventory.tsv"): malformed}, "test: malformed aggregate inventory"); err != nil {
		t.Fatal(err)
	}
	assertCode("REMOTE_AGGREGATE_INVENTORY_INVALID")

	unsorted := filepath.Join(t.TempDir(), "inventory.tsv")
	file, err := os.OpenFile(unsorted, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"z-last", "a-first"} {
		digest := sha256.Sum256([]byte(name))
		if err := manifest.WriteEntry(file, manifest.Entry{Path: name, Size: int64(len(name)), SHA256: digest}); err != nil {
			file.Close()
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := canonical.InstallPaths(map[string]string{remoteStatePath("cf", "inventory.tsv"): unsorted}, "test: unsorted aggregate inventory"); err != nil {
		t.Fatal(err)
	}
	assertCode("REMOTE_AGGREGATE_INVENTORY_INVALID")
}

func TestSnapshotL2AcceptsRefOnlyEmptyPlan(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := (pub.Plan{}).WithCDN("https://repo.test")
	if err != nil {
		t.Fatal(err)
	}
	canonical, generationBody, checkpointBody, generation := installZeroObjectSnapshotPublication(t, cfg, plan)

	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	transport := newCloudProtocolTransport()
	generationKey, err := pub.GenerationKey(generation.Generation)
	if err != nil {
		t.Fatal(err)
	}
	transport.objects[pub.CheckpointKey] = protocolObject{body: checkpointBody, sha: digestBytesCLI(checkpointBody), etag: `"checkpoint"`}
	transport.objects[generationKey] = protocolObject{body: generationBody, sha: digestBytesCLI(generationBody), etag: `"generation"`}
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })

	var networkFailure atomic.Bool
	checks, err := buildSnapshotL2Checks(cfg, canonical, cfg.Repos, "all-20260712", commonFlags{workers: 2, chunk: 2}, []string{"cf"}, &networkFailure)
	if err != nil {
		t.Fatal(err)
	}
	report := verify.Run(t.Context(), verify.Request{Layers: []verify.Layer{verify.LayerL2}, Checks: checks, Workers: 2})
	if report.Outcome != verify.OutcomePassed || report.Exit != verify.ExitSuccess || networkFailure.Load() {
		t.Fatalf("zero-object snapshot L2 report=%#v network_failure=%t", report, networkFailure.Load())
	}
}

func installZeroObjectSnapshotPublication(t *testing.T, cfg *config.Config, plan pub.Plan) (*state.Store, []byte, []byte, pub.TargetGeneration) {
	t.Helper()
	canonical := state.New(cfg.StatePath())
	snapshotID := "all-20260712"
	manifestPath, err := state.SnapshotPath(snapshotID, "assets", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	emptyManifest := filepath.Join(t.TempDir(), "manifest.tsv")
	if err := os.WriteFile(emptyManifest, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	commit, _, err := canonical.InstallPaths(map[string]string{manifestPath: emptyManifest}, "test: empty immutable snapshot")
	if err != nil {
		t.Fatal(err)
	}
	snapshotRef, err := state.SnapshotRef(snapshotID, "assets", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	if err := canonical.AdvanceRef(snapshotRef, plumbing.ZeroHash, commit, false); err != nil {
		t.Fatal(err)
	}
	generationRefs := []pub.RefState{{Name: snapshotRef.String(), Commit: commit.String(), ManifestSHA256: digestBytesCLI(nil)}}
	configSHA, err := publicationConfigSHA256ForRefs(cfg, generationRefs)
	if err != nil {
		t.Fatal(err)
	}
	generation := pub.TargetGeneration{
		Schema: pub.TargetGenerationSchema, Target: pub.TargetCloudflare,
		Generation: 1, ParentGeneration: 0, DesiredCommit: commit.String(),
		IntentView: "snapshot", IntentSnapshot: snapshotID, ConfigSHA256: configSHA,
		Refs:                  generationRefs,
		ContentManifestSHA256: digestBytesCLI(nil),
	}
	generationBody, err := generation.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	planSHA, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := pub.NewCheckpoint(generation, "sow-cf-empty-plan", planSHA, pub.PhaseCheckpointCommitted, time.Unix(1_700_000_000, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	checkpointBody, err := checkpoint.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	planBody, err := plan.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	generationPath, _ := remoteIntentStatePath("cf", "snapshot", snapshotID, "generation.json")
	checkpointPath, _ := remoteIntentStatePath("cf", "snapshot", snapshotID, "checkpoint.json")
	planPath, _ := remoteIntentStatePath("cf", "snapshot", snapshotID, "plan.json")
	stages := make(map[string]string, 3)
	for name, item := range map[string][]byte{generationPath: generationBody, checkpointPath: checkpointBody, planPath: planBody} {
		stage := filepath.Join(t.TempDir(), filepath.Base(name))
		if err := os.WriteFile(stage, item, 0o600); err != nil {
			t.Fatal(err)
		}
		stages[name] = stage
	}
	if _, _, err := canonical.InstallPaths(stages, "test: committed zero-object snapshot publication"); err != nil {
		t.Fatal(err)
	}
	remoteRef, err := state.RemoteRef("cf", snapshotID, "assets", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	if err := canonical.AdvanceRef(remoteRef, plumbing.ZeroHash, commit, false); err != nil {
		t.Fatal(err)
	}
	return canonical, generationBody, checkpointBody, generation
}

func TestVerifyCLIL3FailsClosedWithoutCommittedPlan(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishPackageConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Main([]string{"verify", "--layer", "L3", "--view", "beta", "--target", "cf", "--config", configPath}, &stdout, &stderr)
	if code == ExitOK || !strings.Contains(stdout.String(), "REMOTE_PLAN_COVERAGE_MISSING") {
		t.Fatalf("missing plan code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestVerifySnapshotArgumentsAndMissingCoverageFailClosed(t *testing.T) {
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, _, stderr := run("verify", "--view", "latest", "--snapshot", "el10-20260712"); code != ExitUsage || !strings.Contains(stderr, "mutually exclusive") {
		t.Fatalf("view/snapshot mix code=%d stderr=%s", code, stderr)
	}
	if code, _, stderr := run("verify", "--snapshot", "el10-20260712", "--snapshot", "el10-20260711"); code != ExitUsage || !strings.Contains(stderr, "exactly one") {
		t.Fatalf("multiple snapshots code=%d stderr=%s", code, stderr)
	}
	if code, _, stderr := run("verify", "--snapshot", "el10-20260230"); code != ExitConfig || !strings.Contains(stderr, "invalid UTC date") {
		t.Fatalf("invalid snapshot code=%d stderr=%s", code, stderr)
	}

	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishPackageConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	rpmPath := decodeVerifyFixture(t, filepath.Join("testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), filepath.Join(root, "pgdg-repo.rpm"))
	keyPath := writePublishTestPrivateKey(t, root)
	publicKeyPath := writeVerifyPublicKey(t, keyPath)
	if code, stdout, stderr := run("add", rpmPath, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath); code != ExitOK {
		t.Fatalf("seed package code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	snapshotID, err := views.SnapshotID("el10", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run("verify", "--layer", "L1", "--snapshot", snapshotID, "--config", configPath, "--repo", "rpm-test", "--gpg-public-key-file", publicKeyPath)
	if code == ExitOK || !strings.Contains(stdout, "SNAPSHOT_REF_MISSING") || !strings.Contains(stdout, "outcome=incomplete") {
		t.Fatalf("missing snapshot coverage code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

func TestVerifySnapshotL1ChecksAssetMaterialization(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	assetPath := filepath.Join(root, "release.bin")
	if err := os.WriteFile(assetPath, []byte("immutable snapshot asset\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("add", assetPath, "--config", configPath, "--repo", "asset"); code != ExitOK {
		t.Fatalf("asset add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", "asset"); code != ExitOK {
		t.Fatalf("asset promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	snapshotID, err := views.SnapshotID("all", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("promote", "stable", snapshotID, "--config", configPath, "--repo", "asset"); code != ExitOK {
		t.Fatalf("asset snapshot code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("materialize", snapshotID, "--config", configPath, "--repo", "asset"); code != ExitOK {
		t.Fatalf("asset materialize code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("verify", "--layer", "L1", "--snapshot", snapshotID, "--config", configPath, "--repo", "asset"); code != ExitOK || !strings.Contains(stdout, "outcome=passed") {
		t.Fatalf("asset snapshot L1 code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	materialized := filepath.Join(root, ".sow", "materialized", "snapshots", snapshotID, "asset", filepath.Base(assetPath))
	if err := os.Remove(materialized); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(materialized, []byte("tampered\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("verify", "--layer", "L1", "--snapshot", snapshotID, "--config", configPath, "--repo", "asset"); code != ExitVerification || !strings.Contains(stdout, "FS_CHANGED") {
		t.Fatalf("asset snapshot drift code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

func TestProVerificationTokenFileIsPrivateScopedAndStrict(t *testing.T) {
	root := nginxWorkerTempDir(t)
	path := filepath.Join(root, "token")
	if err := os.WriteFile(path, []byte(verifyTestProToken+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProVerificationToken(path, []string{"stable"}); err == nil || strings.Contains(err.Error(), verifyTestProToken) {
		t.Fatalf("world-readable token accepted or leaked: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProVerificationToken(path, []string{"beta"}); err == nil || strings.Contains(err.Error(), verifyTestProToken) {
		t.Fatalf("non-stable token accepted or leaked: %v", err)
	}
	if err := os.WriteFile(path, []byte("short-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProVerificationToken(path, []string{"stable"}); err == nil || strings.Contains(err.Error(), "short-secret") {
		t.Fatalf("unsafe token accepted or leaked: %v", err)
	}
	if err := os.WriteFile(path, []byte(verifyTestProToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token, err := loadProVerificationToken(path, []string{"stable"})
	if err != nil || string(token) != verifyTestProToken {
		t.Fatalf("valid private token rejected: %v", err)
	}
	clearSecret(token)
}

func decodeVerifyFixture(t *testing.T, source, destination string) string {
	t.Helper()
	encoded, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	body, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, body, 0o444); err != nil {
		t.Fatal(err)
	}
	return destination
}

func writeVerifyPublicKey(t *testing.T, privatePath string) string {
	t.Helper()
	body, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	entities, err := openpgp.ReadKeyRing(bytes.NewReader(body))
	if err != nil || len(entities) != 1 {
		t.Fatalf("read verification key: entities=%d err=%v", len(entities), err)
	}
	var public bytes.Buffer
	if err := entities[0].Serialize(&public); err != nil {
		t.Fatal(err)
	}
	publicPath := privatePath + ".pub"
	if err := os.WriteFile(publicPath, public.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return publicPath
}

type failingVerificationTransport struct{}

func (failingVerificationTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("fixture network outage")
}
