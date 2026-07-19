package compat_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/cli"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
	"golang.org/x/sys/unix"
)

const (
	realCloudSecretScratchSuffix  = ".secrets"
	realCloudSecretRegistryName   = ".sow-real-cloud-secret-registry.json"
	realCloudSecretRegistrySchema = "sow-real-cloud-secret-registry/v1"
)

var errRealCloudProviderAPIAttestationRequired = errors.New("real-cloud acceptance requires in-repo provider API raw-export attestation and deployed edge build identity; operator-supplied joined JSONL and fixed contract headers cannot close the ledger")

type realCloudSecretRegistry struct {
	Schema          string                        `json:"schema"`
	WorkspaceSHA256 string                        `json:"workspace_sha256"`
	Entry           *realCloudSecretRegistryEntry `json:"entry,omitempty"`
}

type realCloudSecretRegistryEntry struct {
	LogicalName string `json:"logical_name"`
	Path        string `json:"path"`
	Device      uint64 `json:"device"`
	Inode       uint64 `json:"inode"`
	Size        int    `json:"size"`
}

type realCloudAcceptanceProgram struct {
	t               *testing.T
	environment     realCloudEnvironment
	identity        realCloudRunIdentity
	secretFragments []string
	publicKey       []byte
	configBody      []byte
	root            string
	configPath      string
	ledger          *realCloudAcceptanceLedgerStore
	reservation     *realEdgePersistentRunReservation
	artifactPath    string
	providerLogPath string
	mode            string
	activeStepID    string
	cliCursor       int

	firstPackage      string
	secondPackage     string
	rpmPackage        string
	assetPackage      string
	gatedAssetPackage string
	gatedBodies       [3][]byte
}

type realCloudStepIntent struct {
	Template    string   `json:"template"`
	Operations  []string `json:"operations"`
	LogicalAuth string   `json:"logical_auth"`
}

func executeRealCloudAcceptanceProgram(
	t *testing.T,
	mode, root string,
	environment realCloudEnvironment,
	identity realCloudRunIdentity,
	secretFragments []string,
	publicKey, configBody []byte,
) {
	t.Helper()
	// Defense in depth: no local ledger/artifact setup and, critically, no
	// observer or provider request may occur unless every configured resource is
	// an exact allowlisted, visibly non-production test resource.
	if err := validateRealCloudDedicatedTestResources(environment, os.Getenv); err != nil {
		t.Fatalf("refuse production or non-allowlisted cloud resources before acceptance bootstrap: %v", err)
	}
	artifactPath, err := canonicalRealEdgeExternalPath(strings.TrimSpace(os.Getenv(realEdgeActiveArtifactEnv)), realEdgeActiveArtifactEnv)
	if err != nil {
		t.Fatalf("canonicalize real edge active artifact destination: %v", err)
	}
	providerLogPath, err := canonicalRealEdgeExternalPath(strings.TrimSpace(os.Getenv(realEdgeProviderLogEnv)), realEdgeProviderLogEnv)
	if err != nil {
		t.Fatalf("canonicalize real edge provider-log destination: %v", err)
	}
	topology := realCloudObserverTopologyBinding(t)
	binding, err := realCloudAcceptanceBindingFor(identity, artifactPath, providerLogPath, topology)
	if err != nil {
		t.Fatalf("bind real-cloud acceptance ledger: %v", err)
	}
	ledger, err := acquireRealCloudAcceptanceLedger(root, mode, binding)
	if err != nil {
		t.Fatalf("acquire real-cloud acceptance ledger: %v", err)
	}
	defer func() {
		if err := ledger.Close(); err != nil {
			t.Errorf("close real-cloud acceptance ledger: %v", err)
		}
	}()
	if err := recoverRealCloudSecretScratch(root); err != nil {
		t.Fatalf("recover stale real-cloud runtime secret scratch: %v", err)
	}

	if ledger.Snapshot().Status == "complete" {
		revalidateCompletedRealCloudAcceptance(t, root, artifactPath, providerLogPath, environment, identity, secretFragments, configBody, ledger.Snapshot())
		lockPath := artifactPath + realEdgeRunLockSuffix
		if _, statErr := os.Lstat(lockPath); statErr == nil {
			reservation, acquireErr := acquireRealEdgePersistentRunReservation(artifactPath, identity.RunID, "recover")
			if acquireErr != nil {
				t.Fatalf("recover completed run reservation cleanup: %v", acquireErr)
			}
			if completeErr := reservation.Complete(); completeErr != nil {
				t.Fatalf("complete recovered run reservation cleanup: %v", completeErr)
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("inspect completed run reservation: %v", statErr)
		}
		t.Logf("real-cloud acceptance run=%s read-only revalidation passed proof_sha256=%s", identity.RunID, ledger.Snapshot().FinalProofSHA256)
		return
	}
	if mode == "fresh" {
		if err := preflightRealCloudEdgeMultiPoPInputs(os.Getenv); err != nil {
			t.Fatalf("real edge multi-PoP fresh preflight: %v", err)
		}
	}
	reservation, err := acquireRealEdgePersistentRunReservation(artifactPath, identity.RunID, mode)
	if err != nil && mode == "recover" && len(ledger.Snapshot().Receipts) == 0 && ledger.Snapshot().Current == nil {
		// A crash may occur after the durable workspace/ledger exists but before
		// the external reservation is created. This is the only recovery state
		// allowed to create a missing reservation.
		if preflightErr := preflightRealCloudEdgeMultiPoPInputs(os.Getenv); preflightErr == nil {
			reservation, err = acquireRealEdgePersistentRunReservation(artifactPath, identity.RunID, "fresh")
		}
	}
	if err != nil {
		t.Fatalf("acquire persistent real edge run reservation: %v", err)
	}
	defer func() {
		if reservation != nil && reservation.file != nil {
			if err := reservation.CloseIncomplete(); err != nil {
				t.Errorf("retain incomplete real edge run reservation: %v", err)
			}
		}
	}()
	program := newRealCloudAcceptanceProgram(t, mode, environment, identity, secretFragments, publicKey, configBody, root, ledger, reservation, artifactPath, providerLogPath)
	program.run()
}

func revalidateCompletedRealCloudAcceptance(
	t *testing.T,
	root, artifactPath, providerLogPath string,
	environment realCloudEnvironment,
	identity realCloudRunIdentity,
	secretFragments []string,
	configBody []byte,
	ledger realCloudAcceptanceLedger,
) {
	t.Helper()
	if err := validateRealCloudAcceptanceLedger(ledger); err != nil {
		t.Fatalf("completed real-cloud acceptance ledger: %v", err)
	}
	installedConfig := readRequiredFile(t, filepath.Join(root, "sow.yaml"))
	if !bytes.Equal(installedConfig, configBody) || realCloudLowerSHA256(installedConfig) != identity.ConfigSHA256 {
		t.Fatal("completed real-cloud acceptance config no longer matches the bound run")
	}
	records, err := loadRealEdgeSealedActiveArtifact(artifactPath, secretFragments, identity.RunID)
	if err != nil || len(records) != 4 {
		t.Fatalf("completed active artifact closure records=%d err=%v", len(records), err)
	}
	program := &realCloudAcceptanceProgram{t: t, environment: environment, identity: identity, secretFragments: secretFragments, root: root, configPath: filepath.Join(root, "sow.yaml"), artifactPath: artifactPath, providerLogPath: providerLogPath}
	stage4, exists4 := program.loadActiveStage(4)
	stage5, exists5 := program.loadActiveStage(5)
	if !exists4 || !exists5 {
		t.Fatal("completed active artifact does not contain exact generation 4 and 5 stages")
	}
	assertRealCloudEdgeMultiPoPPurgeTransition(t, stage4, stage5)
	for _, target := range []struct {
		name     string
		provider publish.TargetName
	}{{name: "cf", provider: publish.TargetCloudflare}, {name: "cos", provider: publish.TargetTencent}} {
		local := readRealCloudPublication(t, root, target.name)
		asset := assertRealCloudGatedPublication(t, environment, target.name, local, target.provider, 10)
		wantedBody := []byte("sow real-cloud gated generation three run=" + identity.RunID + "\n")
		if asset.SHA256 != realCloudLowerSHA256(wantedBody) {
			t.Fatalf("completed target %s gated digest changed", target.name)
		}
		remote := readRealCloudCheckpoint(t, environment, secretFragments, target.name)
		remoteBody, canonicalErr := remote.Canonical()
		if canonicalErr != nil || !bytes.Equal(remoteBody, local.checkpointBody) {
			t.Fatalf("completed target %s remote checkpoint changed: %v", target.name, canonicalErr)
		}
	}
	closure, err := collectRealCloudProviderClosure(root, artifactPath, providerLogPath, secretFragments, identity.RunID)
	if err != nil {
		t.Fatalf("completed provider-log closure no longer validates: %v", err)
	}
	if ledger.Facts.ProviderClosure == nil || *ledger.Facts.ProviderClosure != closure ||
		closure.ProviderLogPathSHA256 != ledger.Binding.ProviderLogPathSHA256 {
		t.Fatal("completed provider-log closure differs from the ledger-bound exact file and seal")
	}
}

func collectRealCloudProviderClosure(root, artifactPath, providerLogPath string, secretFragments []string, runID string) (realCloudProviderClosureFact, error) {
	forbidden := append([]string(nil), secretFragments...)
	observers, err := loadRealEdgeObservers(os.Getenv)
	if err != nil {
		return realCloudProviderClosureFact{}, err
	}
	for _, observer := range observers {
		forbidden = append(forbidden, realEdgeObserverSecretFragments(observer)...)
	}
	records, err := loadRealEdgeSealedActiveArtifact(artifactPath, forbidden, runID)
	if err != nil {
		return realCloudProviderClosureFact{}, err
	}
	logs, err := loadRealEdgeProviderLogs(providerLogPath, forbidden)
	if err != nil {
		return realCloudProviderClosureFact{}, err
	}
	stages, err := pairRealEdgeArtifactStages(records, logs)
	if err != nil {
		return realCloudProviderClosureFact{}, err
	}
	if len(stages) != 2 {
		return realCloudProviderClosureFact{}, fmt.Errorf("provider closure stage count=%d, want 2", len(stages))
	}
	for index, generation := range []uint64{4, 5} {
		for _, vendor := range []string{"cloudflare", "edgeone"} {
			if stages[index].Vendors[vendor].Generation != generation {
				return realCloudProviderClosureFact{}, fmt.Errorf("provider closure stage %d %s generation is not %d", index, vendor, generation)
			}
		}
		if err := validateRealEdgeMultiPoPStage(stages[index], forbidden); err != nil {
			return realCloudProviderClosureFact{}, fmt.Errorf("provider closure stage %d: %w", index, err)
		}
	}
	if err := validateRealEdgeProviderLogClosure(stages, logs, runID); err != nil {
		return realCloudProviderClosureFact{}, err
	}
	if err := validateRealEdgeMultiPoPPurgeTransition(stages[0], stages[1]); err != nil {
		return realCloudProviderClosureFact{}, err
	}
	cfPurgeSHA, cosPurgeSHA, err := validateRealCloudGenerationFivePurgeReceipts(root, stages[1])
	if err != nil {
		return realCloudProviderClosureFact{}, err
	}
	activeBody, err := readRealEdgeSafeJSONL(artifactPath, realEdgeMaxProviderLogBytes, "active artifact")
	if err != nil {
		return realCloudProviderClosureFact{}, err
	}
	activeSeal, err := readRealEdgeSafeJSONL(artifactPath+".seal", 4<<10, "active artifact seal")
	if err != nil || verifyRealEdgeActiveArtifactSeal(artifactPath, activeBody, runID) != nil {
		return realCloudProviderClosureFact{}, errors.Join(err, errors.New("active artifact seal changed during provider closure"))
	}
	providerBody, err := readRealEdgeSafeJSONL(providerLogPath, realEdgeMaxProviderLogBytes, "provider log")
	if err != nil {
		return realCloudProviderClosureFact{}, err
	}
	providerSeal, err := readRealEdgeSafeJSONL(providerLogPath+".seal", 4<<10, "provider log seal")
	if err != nil {
		return realCloudProviderClosureFact{}, err
	}
	sealRun, sealErr := verifyRealEdgeProviderLogSeal(providerLogPath, providerBody)
	if sealErr != nil || sealRun != runID {
		return realCloudProviderClosureFact{}, errors.Join(sealErr, errors.New("provider log seal changed or belongs to another run"))
	}
	candidate := realCloudProviderClosureFact{
		ProviderLogPathSHA256: realCloudLowerSHA256([]byte(providerLogPath)),
		ProviderLogSHA256:     realCloudLowerSHA256(providerBody), ProviderSealSHA256: realCloudLowerSHA256(providerSeal),
		ActiveArtifactSHA256: realCloudLowerSHA256(activeBody), ActiveSealSHA256: realCloudLowerSHA256(activeSeal),
		CFPurgeEvidenceSHA256: cfPurgeSHA, COSPurgeEvidenceSHA256: cosPurgeSHA,
		ProviderRecords: len(logs),
	}
	attestation, err := validateRealCloudProviderAPIAttestedRawClosure(context.Background(), stages, logs, forbidden)
	if err != nil {
		return realCloudProviderClosureFact{}, err
	}
	candidate = applyRealCloudProviderRawAttestation(candidate, attestation)
	return candidate, nil
}

func validateRealCloudGenerationFivePurgeReceipts(root string, stage realEdgeMultiPoPStageEvidence) (string, string, error) {
	digests := make(map[string]string, 2)
	for _, input := range []struct {
		vendor string
		target publish.TargetName
	}{{vendor: "cloudflare", target: publish.TargetCloudflare}, {vendor: "edgeone", target: publish.TargetTencent}} {
		vendorStage, exists := stage.Vendors[input.vendor]
		if !exists || vendorStage.Generation != 5 || vendorStage.PrePurge == nil {
			return "", "", fmt.Errorf("generation-five purge receipt lacks %s active stage", input.vendor)
		}
		path := filepath.Join(root, config.StateDirectory, "state", "remotes", string(input.target), "purges",
			fmt.Sprintf("%020d-%s.json", vendorStage.Generation, vendorStage.TransactionID))
		evidence, body, err := publish.LoadPurgeEvidenceFile(path)
		if err != nil {
			return "", "", fmt.Errorf("load generation-five %s purge receipt: %w", input.vendor, err)
		}
		if evidence.Schema != publish.PurgeEvidenceSchema || evidence.Target != input.target || evidence.Generation != vendorStage.Generation ||
			evidence.TransactionID != vendorStage.TransactionID || evidence.GenerationSHA256 != vendorStage.GenerationSHA256 ||
			evidence.CheckpointSHA256 != vendorStage.CheckpointSHA256 {
			return "", "", fmt.Errorf("generation-five %s purge receipt is not bound to the active publication", input.vendor)
		}
		latestFull := -1
		for index := range evidence.Attempts {
			if evidence.Attempts[index].Purpose == publish.PurgeAttemptFull {
				latestFull = index
			}
		}
		if latestFull < 0 {
			return "", "", fmt.Errorf("generation-five %s purge receipt has no full attempt", input.vendor)
		}
		attempt := evidence.Attempts[latestFull]
		if attempt.URLCount != evidence.URLCount || attempt.URLsSHA256 != evidence.URLsSHA256 || len(attempt.Batches) == 0 {
			return "", "", fmt.Errorf("generation-five %s latest purge attempt is not the exact URL closure", input.vendor)
		}
		var completedURLs int
		var lastCompleted time.Time
		for _, receipt := range attempt.Batches {
			if receipt.Status != publish.PurgeReceiptCompleted || receipt.Vendor != input.vendor {
				return "", "", fmt.Errorf("generation-five %s purge batch is not provider-completed", input.vendor)
			}
			completedAt, parseErr := parseRealEdgeUTC(receipt.CompletedObservedAt)
			if parseErr != nil {
				return "", "", fmt.Errorf("generation-five %s purge completion time: %w", input.vendor, parseErr)
			}
			if completedAt.After(lastCompleted) {
				lastCompleted = completedAt
			}
			completedURLs += receipt.URLCount
		}
		if completedURLs != attempt.URLCount || lastCompleted.IsZero() || lastCompleted.After(vendorStage.CommittedObservedAt) {
			return "", "", fmt.Errorf("generation-five %s purge completion is outside the committed active window", input.vendor)
		}
		postByObserver := make(map[string]realEdgeMultiPoPObservation, len(vendorStage.Observations))
		for _, observation := range vendorStage.Observations {
			postByObserver[observation.ObserverID] = observation
		}
		for _, pre := range vendorStage.PrePurge.Observations {
			post, found := postByObserver[pre.ObserverID]
			remaining := time.Duration(pre.CacheMaxAge-pre.CacheAgeSeconds) * time.Second
			freshUntil := pre.ResponseObserved.Add(remaining - realEdgeCacheFreshnessMargin)
			if !found || !pre.ResponseObserved.Before(lastCompleted) || !lastCompleted.Before(freshUntil) ||
				!lastCompleted.Before(post.RequestStarted) || !post.ResponseObserved.Before(freshUntil) {
				return "", "", fmt.Errorf("generation-five %s purge receipt is not causally inside observer %s old-cache TTL", input.vendor, pre.ObserverID)
			}
		}
		digests[input.vendor] = realCloudLowerSHA256(body)
	}
	return digests["cloudflare"], digests["edgeone"], nil
}

func realCloudObserverTopologyBinding(t *testing.T) []byte {
	t.Helper()
	body, err := realCloudObserverTopologyBindingFrom(os.Getenv)
	if err != nil {
		t.Fatalf("load observer topology for persistent binding: %v", err)
	}
	return body
}

// realCloudObserverTopologyBindingFrom binds the durable run to the observer
// identities and their actual egress endpoints, while deliberately excluding
// proxy userinfo. Proxy credentials are runtime secrets and may rotate between
// recovery attempts without changing the physical observer topology.
func realCloudObserverTopologyBindingFrom(getenv func(string) string) ([]byte, error) {
	observers, err := loadRealEdgeObservers(getenv)
	if err != nil {
		return nil, err
	}
	type boundObserver struct {
		ID            string `json:"id"`
		ProxyEnv      string `json:"proxy_env"`
		ProxyEndpoint string `json:"proxy_endpoint"`
	}
	bound := make([]boundObserver, 0, len(observers))
	for _, observer := range observers {
		host := net.JoinHostPort(strings.ToLower(observer.proxyURL.Hostname()), observer.proxyURL.Port())
		endpoint := observer.proxyURL.Scheme + "://" + host
		if observer.proxyURL.Path == "/" {
			endpoint += "/"
		}
		bound = append(bound, boundObserver{ID: observer.ID, ProxyEnv: observer.ProxyEnv, ProxyEndpoint: endpoint})
	}
	body, err := json.Marshal(bound)
	if err != nil {
		return nil, errors.New("encode observer topology binding")
	}
	return body, nil
}

func newRealCloudAcceptanceProgram(
	t *testing.T,
	mode string,
	environment realCloudEnvironment,
	identity realCloudRunIdentity,
	secretFragments []string,
	publicKey, configBody []byte,
	root string,
	ledger *realCloudAcceptanceLedgerStore,
	reservation *realEdgePersistentRunReservation,
	artifactPath, providerLogPath string,
) *realCloudAcceptanceProgram {
	t.Helper()
	program := &realCloudAcceptanceProgram{
		t: t, environment: environment, identity: identity,
		secretFragments: append([]string(nil), secretFragments...),
		publicKey:       append([]byte(nil), publicKey...), configBody: append([]byte(nil), configBody...),
		root: root, configPath: filepath.Join(root, "sow.yaml"), ledger: ledger,
		reservation: reservation, artifactPath: artifactPath, providerLogPath: providerLogPath,
		mode: mode,
	}
	program.firstPackage = filepath.Join(root, "sow-compat-deb_"+realCloudFirstPackageVersion+"_amd64.deb")
	program.secondPackage = filepath.Join(root, "sow-compat-deb_"+realCloudSecondPackageVersion+"_amd64.deb")
	program.rpmPackage = filepath.Join(root, "pgdg-redhat-nonfree-repo-42.0-20PGDG.noarch.rpm")
	program.assetPackage = filepath.Join(root, "real-cloud-latest.txt")
	program.gatedAssetPackage = filepath.Join(root, "real-cloud-gated.txt")
	for index, label := range []string{"one", "two", "three"} {
		program.gatedBodies[index] = []byte("sow real-cloud gated generation " + label + " run=" + identity.RunID + "\n")
	}
	return program
}

func (program *realCloudAcceptanceProgram) run() {
	t := program.t
	if program.ledger.Snapshot().Status == "complete" {
		t.Logf("real-cloud acceptance run=%s already complete; no destructive step replayed", program.identity.RunID)
		return
	}
	if program.mode == "recover" && program.ledger.StepCompleted("edge-reservation-connectivity-preflight") {
		program.reconcileProviderRawSinks("")
	}

	program.step("edge-reservation-connectivity-preflight", []string{"anonymous-edge-connectivity", "provider-raw-sink-reconcile", "cf", "cos"}, "@provider", func() any {
		observers, err := loadRealEdgeObservers(os.Getenv)
		if err != nil {
			t.Fatalf("load real edge observers after persistent reservation: %v", err)
		}
		if err := preflightRealEdgeObserverConnectivity(t.Context(), observers, program.environment, program.secretFragments); err != nil {
			t.Fatalf("real edge observer connectivity preflight: %v", err)
		}
		program.reconcileProviderRawSinks("edge-reservation-connectivity-preflight")
		return map[string]any{"observers": len(observers), "vendors": 2, "status": "verified", "provider_raw_sinks": "run-bound"}
	})

	program.step("bootstrap-files-init", []string{"init", "--config", "@config", "--workers", "2", "--chunk-entries", "64"}, "@none", func() any {
		for _, directory := range []string{
			filepath.Join(program.root, "apt", "real-cloud"),
			filepath.Join(program.root, "yum", "real-cloud", "x86_64"),
			filepath.Join(program.root, "assets", "real-cloud"),
			filepath.Join(program.root, "assets", "real-cloud-gated"),
		} {
			if err := os.MkdirAll(directory, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		writeFile(t, filepath.Join(program.root, realCloudRepositoryPublicKey), program.publicKey, 0o644)
		writeFile(t, program.configPath, program.configBody, 0o600)
		if _, err := config.Load(program.configPath, ""); err != nil {
			t.Fatalf("generated real-cloud configuration is invalid: %v", err)
		}
		program.runCLI(cli.ExitOK, "init", "--config", program.configPath, "--workers", "2", "--chunk-entries", "64")
		return map[string]string{
			"config_sha256":     realCloudLowerSHA256(program.configBody),
			"public_key_sha256": realCloudLowerSHA256(program.publicKey),
		}
	})

	program.step("prove-both-buckets-empty", []string{"fsck-adopt-empty", "cf", "cos"}, "@none", func() any {
		result := make(map[string]string, 2)
		for _, target := range []string{"cf", "cos"} {
			output := program.runCLI(cli.ExitOK, "fsck", "--config", program.configPath, "--target", target,
				"--adopt-remote-inventory", "--limit", "0", "--workers", "2")
			if !strings.Contains(output, "fsck-adopt target="+target+" listed=0 local_expected=0 retained_extra=0 streamed_get=0 pages=2 ") ||
				!strings.Contains(output, "inventory_coverage=complete") {
				t.Fatalf("refuse destructive publication: target %s did not prove an empty dedicated bucket\n%s", target, output)
			}
			result[target] = realCloudLowerSHA256([]byte(output))
		}
		return result
	})

	program.step("seed-local-generation-1", []string{"fixtures-v1", "add-deb", "add-rpm", "add-public-asset", "add-gated-asset", "promote-beta-latest"}, "@none", func() any {
		program.firstPackage = writeInstallableDEB(t, program.root, realCloudFirstPackageVersion)
		moduleRoot := findModuleRoot(t)
		program.rpmPackage = decodeBase64Fixture(t,
			filepath.Join(moduleRoot, "internal", "cli", "testdata", "pgdg-redhat-nonfree-repo.rpm.b64"), program.rpmPackage)
		writeFile(t, program.assetPackage, []byte("sow real-cloud asset generation one\n"), 0o600)
		writeFile(t, program.gatedAssetPackage, program.gatedBodies[0], 0o600)
		program.runCLI(cli.ExitOK, "add", program.firstPackage, "--config", program.configPath, "--repo", realCloudRepositoryID, "--component", "main", "--workers", "2", "--chunk-entries", "64")
		program.runCLI(cli.ExitOK, "add", program.rpmPackage, "--config", program.configPath, "--repo", realCloudYUMRepositoryID, "--workers", "2", "--chunk-entries", "64")
		program.runCLI(cli.ExitOK, "add", program.assetPackage, "--config", program.configPath, "--repo", realCloudAssetRepositoryID, "--dest", "latest.txt", "--workers", "2", "--chunk-entries", "64")
		program.runCLI(cli.ExitOK, "add", program.gatedAssetPackage, "--config", program.configPath, "--repo", realCloudGatedAssetRepoID, "--dest", "secret.txt", "--workers", "2", "--chunk-entries", "64")
		program.runCLI(cli.ExitOK, "promote", "beta", "latest", "--config", program.configPath,
			"--repo", realCloudRepositoryID, "--repo", realCloudYUMRepositoryID, "--repo", realCloudAssetRepositoryID,
			"--workers", "2", "--chunk-entries", "64")
		return map[string]string{"apt": realCloudLowerSHA256(readRequiredFile(t, program.firstPackage)), "rpm": realCloudLowerSHA256(readRequiredFile(t, program.rpmPackage))}
	})

	program.step("publish-latest-cf-g1", []string{"publish", "latest", "cf", "generation=1"}, "@provider", func() any {
		program.runCLI(cli.ExitOK, "publish", "--view", "latest", "--target", "cf", "--config", program.configPath, "--workers", "2", "--chunk-entries", "64")
		publication := readRealCloudPublication(t, program.root, "cf")
		assertRealCloudPublication(t, program.environment, publication, publish.TargetCloudflare, 1)
		assertRealCloudFirstPublicationProtocols(t, program.environment, "cf", publication, publish.TargetCloudflare)
		assertRealCloudPublicationAbsent(t, program.root, "cos")
		return realCloudPublicationResult(publication)
	})

	program.step("publish-latest-cos-g1", []string{"publish", "latest", "cos", "generation=1"}, "@provider", func() any {
		program.runCLI(cli.ExitOK, "publish", "--view", "latest", "--target", "cos", "--config", program.configPath, "--workers", "2", "--chunk-entries", "64")
		publication := readRealCloudPublication(t, program.root, "cos")
		assertRealCloudPublication(t, program.environment, publication, publish.TargetTencent, 1)
		assertRealCloudFirstPublicationProtocols(t, program.environment, "cos", publication, publish.TargetTencent)
		return realCloudPublicationResult(publication)
	})

	program.step("seed-local-generation-2", []string{"fixture-deb-v2", "add-apt-v2", "promote-beta-latest-apt"}, "@none", func() any {
		program.secondPackage = writeInstallableDEB(t, program.root, realCloudSecondPackageVersion)
		program.runCLI(cli.ExitOK, "add", program.secondPackage, "--config", program.configPath, "--repo", realCloudRepositoryID, "--component", "main", "--workers", "2", "--chunk-entries", "64")
		program.runCLI(cli.ExitOK, "promote", "beta", "latest", "--config", program.configPath, "--repo", realCloudRepositoryID, "--workers", "2", "--chunk-entries", "64")
		return map[string]string{"deb_v2_sha256": realCloudLowerSHA256(readRequiredFile(t, program.secondPackage))}
	})

	program.step("publish-latest-cf-g2", []string{"publish", "latest", "cf", "repo=apt", "generation=2"}, "@provider", func() any {
		program.runCLI(cli.ExitOK, "publish", "--view", "latest", "--target", "cf", "--config", program.configPath, "--repo", realCloudRepositoryID, "--workers", "2", "--chunk-entries", "64")
		cf := readRealCloudPublication(t, program.root, "cf")
		cos := readRealCloudPublication(t, program.root, "cos")
		assertRealCloudPublication(t, program.environment, cf, publish.TargetCloudflare, 2)
		assertRealCloudPublication(t, program.environment, cos, publish.TargetTencent, 1)
		return realCloudPublicationResult(cf)
	})

	program.step("verify-cos-lag-g1", []string{"verify", "L2", "latest", "cos", "repo=apt", "expect=REF_POINTER_DRIFT"}, "@provider", func() any {
		output := program.runCLI(cli.ExitVerification, "verify", "--layer", "L2", "--view", "latest", "--target", "cos", "--config", program.configPath, "--repo", realCloudRepositoryID, "--workers", "2", "--chunk-entries", "64")
		if !strings.Contains(output, "code=REF_POINTER_DRIFT") {
			t.Fatalf("lagging cos target did not produce explicit L2 ref drift\n%s", output)
		}
		return map[string]string{"output_sha256": realCloudLowerSHA256([]byte(output))}
	})

	program.step("publish-latest-cos-g2", []string{"publish", "latest", "cos", "repo=apt", "generation=2"}, "@provider", func() any {
		program.runCLI(cli.ExitOK, "publish", "--view", "latest", "--target", "cos", "--config", program.configPath, "--repo", realCloudRepositoryID, "--workers", "2", "--chunk-entries", "64")
		publication := readRealCloudPublication(t, program.root, "cos")
		assertRealCloudPublication(t, program.environment, publication, publish.TargetTencent, 2)
		return realCloudPublicationResult(publication)
	})

	program.runLatestGenerationThree()
	program.runStableGenerations()
	program.runSnapshotsAndRestore()

	// The final receipt and provider-closure fact can survive a crash before
	// status=complete. Re-read every final local/remote/provider surface, then
	// collect the external files once more inside the finalization callback so
	// a recovery never completes solely from a stale persisted digest.
	revalidateCompletedRealCloudAcceptance(t, program.root, program.artifactPath, program.providerLogPath, program.environment, program.identity, program.secretFragments, program.configBody, program.ledger.Snapshot())
	if err := finalizeRealCloudAcceptanceLedger(program.ledger, func() error {
		actual, err := collectRealCloudProviderClosure(program.root, program.artifactPath, program.providerLogPath, program.secretFragments, program.identity.RunID)
		if err != nil {
			return err
		}
		snapshot := program.ledger.Snapshot()
		if snapshot.Facts.ProviderClosure == nil || *snapshot.Facts.ProviderClosure != actual || actual.ProviderLogPathSHA256 != snapshot.Binding.ProviderLogPathSHA256 {
			return errors.New("provider closure changed after final receipt")
		}
		return nil
	}, time.Now().UTC()); err != nil {
		t.Fatalf("complete real-cloud acceptance ledger: %v", err)
	}
	if err := program.reservation.Complete(); err != nil {
		t.Fatalf("complete real edge run reservation: %v", err)
	}
	program.reservation = nil
	final := program.ledger.Snapshot()
	t.Logf("real-cloud acceptance complete run=%s proof_sha256=%s receipts=%d", program.identity.RunID, final.FinalProofSHA256, len(final.Receipts))
}

func (program *realCloudAcceptanceProgram) reconcileProviderRawSinks(activeStep string) {
	program.t.Helper()
	held := program.reservation != nil && program.reservation.file != nil
	if err := validateRealCloudProviderSinkMutationAdmission(program.ledger.Snapshot(), held, program.mode, activeStep); err != nil {
		program.t.Fatalf("refuse provider raw-log sink mutation without durable admission: %v", err)
	}
	if err := prepareRealCloudProviderPerRunRawSinks(program.t.Context(), program.environment, program.identity.RunID, os.Getenv); err != nil {
		assertNoRealCloudSecret(program.t, "provider raw-log sink setup error", []byte(err.Error()), program.secretFragments)
		program.t.Fatalf("prepare exact ledger-bound per-run provider raw-log sinks: %v", err)
	}
}

func validateRealCloudProviderSinkMutationAdmission(ledger realCloudAcceptanceLedger, reservationHeld bool, mode, activeStep string) error {
	const sinkStep = "edge-reservation-connectivity-preflight"
	if ledger.Status != "running" || ledger.Binding.RunID == "" {
		return errors.New("acceptance ledger is not one running bound run")
	}
	if !reservationHeld {
		return errors.New("provider-scoped run reservation is not held")
	}
	if activeStep == sinkStep {
		if ledger.Current == nil || ledger.Current.Index != 0 || ledger.Current.ID != sinkStep || len(ledger.Receipts) != 0 {
			return errors.New("initial provider sink mutation is outside its durable in-flight step")
		}
		return nil
	}
	if activeStep != "" || mode != "recover" || len(ledger.Receipts) == 0 || ledger.Receipts[0].Index != 0 || ledger.Receipts[0].ID != sinkStep {
		return errors.New("provider sink recovery lacks the completed run-bound setup receipt")
	}
	descriptor, err := realCloudAcceptanceStepDescriptorAt(0)
	if err != nil || ledger.Receipts[0].DescriptorSHA256 != realCloudAcceptanceDescriptorSHA256(descriptor) {
		return errors.New("provider sink recovery receipt does not match the frozen setup descriptor")
	}
	return nil
}

func TestRealCloudProviderSinkMutationRequiresDurableLedgerAndReservation(t *testing.T) {
	const step = "edge-reservation-connectivity-preflight"
	descriptor, err := realCloudAcceptanceStepDescriptorAt(0)
	if err != nil {
		t.Fatal(err)
	}
	initial := realCloudAcceptanceLedger{
		Status: "running", Binding: realCloudAcceptanceBinding{RunID: "real-edge-test-run-20260717"},
		Current: &realCloudStepAttempt{Index: 0, ID: step},
	}
	recovery := realCloudAcceptanceLedger{
		Status: "running", Binding: realCloudAcceptanceBinding{RunID: "real-edge-test-run-20260717"},
		Receipts: []realCloudStepReceipt{{Index: 0, ID: step, DescriptorSHA256: realCloudAcceptanceDescriptorSHA256(descriptor)}},
	}
	tests := []struct {
		name       string
		ledger     realCloudAcceptanceLedger
		held       bool
		mode       string
		activeStep string
		wantOK     bool
	}{
		{name: "initial-durable-step", ledger: initial, held: true, mode: "fresh", activeStep: step, wantOK: true},
		{name: "recovery-from-receipt", ledger: recovery, held: true, mode: "recover", wantOK: true},
		{name: "reservation-missing", ledger: initial, held: false, mode: "fresh", activeStep: step},
		{name: "step-not-durable", ledger: realCloudAcceptanceLedger{Status: "running", Binding: initial.Binding}, held: true, mode: "fresh", activeStep: step},
		{name: "fresh-cannot-use-old-receipt", ledger: recovery, held: true, mode: "fresh"},
		{name: "completed-is-read-only", ledger: realCloudAcceptanceLedger{Status: "complete", Binding: initial.Binding, Receipts: recovery.Receipts}, held: true, mode: "recover"},
		{name: "wrong-recovery-receipt", ledger: func() realCloudAcceptanceLedger {
			value := recovery
			value.Receipts = append([]realCloudStepReceipt(nil), recovery.Receipts...)
			value.Receipts[0].DescriptorSHA256 = strings.Repeat("0", 64)
			return value
		}(), held: true, mode: "recover"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateRealCloudProviderSinkMutationAdmission(test.ledger, test.held, test.mode, test.activeStep)
			if (err == nil) != test.wantOK {
				t.Fatalf("admission err=%v want_ok=%t", err, test.wantOK)
			}
		})
	}
}

func (program *realCloudAcceptanceProgram) step(id string, operations []string, logicalAuth string, action func() any) {
	program.t.Helper()
	if program.ledger.StepCompleted(id) {
		return
	}
	index := len(program.ledger.Snapshot().Receipts)
	descriptor, err := realCloudAcceptanceStepDescriptorAt(index)
	if err != nil || descriptor.ID != id {
		program.t.Fatalf("real-cloud acceptance descriptor for %s: %v", id, err)
	}
	intent := realCloudStepIntent{Template: descriptor.IntentTemplate, Operations: append([]string(nil), operations...), LogicalAuth: logicalAuth}
	if _, err := program.ledger.BeginStep(id, intent, nil, time.Now().UTC()); err != nil {
		program.t.Fatalf("begin real-cloud acceptance step %s: %v", id, err)
	}
	program.activeStepID, program.cliCursor = id, 0
	defer func() { program.activeStepID, program.cliCursor = "", 0 }()
	result := action()
	if err := program.ledger.RequireCLISubstepsConsumed(id, program.cliCursor); err != nil {
		program.t.Fatalf("close real-cloud CLI substeps for %s: %v", id, err)
	}
	if err := program.ledger.CompleteStep(id, result, nil, time.Now().UTC()); err != nil {
		program.t.Fatalf("complete real-cloud acceptance step %s: %v", id, err)
	}
}

func (program *realCloudAcceptanceProgram) stepFacts(id string, operations []string, logicalAuth string, action func() (any, func(*realCloudResumeFacts) error)) {
	program.t.Helper()
	if program.ledger.StepCompleted(id) {
		return
	}
	index := len(program.ledger.Snapshot().Receipts)
	descriptor, err := realCloudAcceptanceStepDescriptorAt(index)
	if err != nil || descriptor.ID != id {
		program.t.Fatalf("real-cloud acceptance descriptor for %s: %v", id, err)
	}
	intent := realCloudStepIntent{Template: descriptor.IntentTemplate, Operations: append([]string(nil), operations...), LogicalAuth: logicalAuth}
	if _, err := program.ledger.BeginStep(id, intent, nil, time.Now().UTC()); err != nil {
		program.t.Fatalf("begin real-cloud acceptance step %s: %v", id, err)
	}
	program.activeStepID, program.cliCursor = id, 0
	defer func() { program.activeStepID, program.cliCursor = "", 0 }()
	result, updateFacts := action()
	if err := program.ledger.RequireCLISubstepsConsumed(id, program.cliCursor); err != nil {
		program.t.Fatalf("close real-cloud CLI substeps for %s: %v", id, err)
	}
	if err := program.ledger.CompleteStep(id, result, updateFacts, time.Now().UTC()); err != nil {
		program.t.Fatalf("complete real-cloud acceptance step %s: %v", id, err)
	}
}

func (program *realCloudAcceptanceProgram) runCLI(expected int, arguments ...string) string {
	program.t.Helper()
	if program.activeStepID == "" {
		program.t.Fatal("real-cloud CLI invocation escaped its persistent phase")
	}
	index := program.cliCursor
	program.cliCursor++
	normalizedArguments := normalizeRealCloudCLIArguments(arguments)
	completed, resumed, storedOutput, err := program.ledger.BeginCLISubstep(program.activeStepID, index, expected, normalizedArguments, time.Now().UTC())
	if err != nil {
		program.t.Fatalf("begin real-cloud CLI substep %s/%d: %v", program.activeStepID, index, err)
	}
	if completed {
		program.t.Logf("sow %s recovered from durable CLI receipt exit=%d", strings.Join(normalizedArguments, " "), expected)
		return storedOutput
	}
	executionArguments := append([]string(nil), arguments...)
	if resumed {
		executionArguments = injectRealCloudRecoverFlag(executionArguments)
	}
	result, err := executeCheckedRealCloudCLI(cli.Main, program.root, expected, program.secretFragments, executionArguments...)
	program.t.Logf("sow %s exit=%d elapsed=%s\n%s", strings.Join(normalizedArguments, " "), result.code, result.elapsed, result.output)
	if err != nil {
		program.t.Fatalf("sow %s failed acceptance guard: %v\n%s", strings.Join(normalizedArguments, " "), err, result.output)
	}
	if err := program.ledger.CompleteCLISubstep(program.activeStepID, index, result.code, string(result.output), time.Now().UTC()); err != nil {
		program.t.Fatalf("complete real-cloud CLI substep %s/%d: %v", program.activeStepID, index, err)
	}
	return string(result.output)
}

func (program *realCloudAcceptanceProgram) consumeRecoveredCLIFromPostcondition(expected int, output string, arguments ...string) string {
	program.t.Helper()
	if program.activeStepID == "" {
		program.t.Fatal("real-cloud recovered CLI postcondition escaped its persistent phase")
	}
	index := program.cliCursor
	program.cliCursor++
	normalized := normalizeRealCloudCLIArguments(arguments)
	completed, resumed, storedOutput, err := program.ledger.BeginCLISubstep(program.activeStepID, index, expected, normalized, time.Now().UTC())
	if err != nil {
		program.t.Fatalf("consume recovered real-cloud CLI substep %s/%d: %v", program.activeStepID, index, err)
	}
	if completed {
		return storedOutput
	}
	if !resumed {
		program.t.Fatal("real-cloud postcondition attempted to synthesize a CLI substep that was never started")
	}
	if err := program.ledger.CompleteCLISubstep(program.activeStepID, index, expected, output, time.Now().UTC()); err != nil {
		program.t.Fatalf("complete postcondition-recovered real-cloud CLI substep %s/%d: %v", program.activeStepID, index, err)
	}
	return output
}

func normalizeRealCloudCLIArguments(arguments []string) []string {
	normalized := append([]string(nil), arguments...)
	for index := 0; index+1 < len(normalized); index++ {
		if normalized[index] == "--pro-token-file" {
			normalized[index+1] = "@runtime-token"
			index++
		}
	}
	return normalized
}

func injectRealCloudRecoverFlag(arguments []string) []string {
	for _, argument := range arguments {
		if argument == "--recover" || strings.HasPrefix(argument, "--recover=") {
			return arguments
		}
	}
	if len(arguments) == 0 {
		return arguments
	}
	insertAt := len(arguments)
	switch arguments[0] {
	case "promote":
		if len(arguments) >= 3 {
			insertAt = 3
		}
	case "add":
		insertAt = 1
		for insertAt < len(arguments) && !strings.HasPrefix(arguments[insertAt], "-") {
			insertAt++
		}
	case "rm":
		insertAt = 1
	}
	result := make([]string, 0, len(arguments)+1)
	result = append(result, arguments[:insertAt]...)
	result = append(result, "--recover")
	result = append(result, arguments[insertAt:]...)
	return result
}

func (program *realCloudAcceptanceProgram) runLatestGenerationThree() {
	t := program.t
	program.step("seed-local-generation-3", []string{"rm-yum", "replace-public-asset-v2", "promote-beta-latest-asset"}, "@none", func() any {
		program.runCLI(cli.ExitOK, "rm", "--view", "latest", "--config", program.configPath, "--repo", realCloudYUMRepositoryID, "--workers", "2", "--chunk-entries", "64", "pgdg-redhat-nonfree-repo")
		writeFile(t, program.assetPackage, []byte("sow real-cloud asset generation two\n"), 0o600)
		program.runCLI(cli.ExitOK, "add", program.assetPackage, "--config", program.configPath, "--repo", realCloudAssetRepositoryID, "--dest", "latest.txt", "--replace", "--workers", "2", "--chunk-entries", "64")
		program.runCLI(cli.ExitOK, "promote", "beta", "latest", "--config", program.configPath, "--repo", realCloudAssetRepositoryID, "--workers", "2", "--chunk-entries", "64")
		return map[string]string{"asset_v2_sha256": realCloudLowerSHA256([]byte("sow real-cloud asset generation two\n"))}
	})

	firstAsset := realCloudPublication{plan: publish.Plan{Objects: []publish.PlannedObject{{
		RemoteKey: "assets/real-cloud/latest.txt", SHA256: realCloudLowerSHA256([]byte("sow real-cloud asset generation one\n")),
	}}}}
	program.step("publish-latest-cf-g3", []string{"publish", "latest", "cf", "generation=3"}, "@provider", func() any {
		program.runCLI(cli.ExitOK, "publish", "--view", "latest", "--target", "cf", "--config", program.configPath, "--workers", "2", "--chunk-entries", "64")
		publication := readRealCloudPublication(t, program.root, "cf")
		assertRealCloudLatestPublicationEnvelope(t, program.environment, publication, publish.TargetCloudflare, 3)
		assertRealCloudYUMAssetUpdate(t, program.environment, "cf", firstAsset, publication, publish.TargetCloudflare, 3)
		cos := readRealCloudPublication(t, program.root, "cos")
		assertRealCloudPublication(t, program.environment, cos, publish.TargetTencent, 2)
		return realCloudPublicationResult(publication)
	})

	program.step("verify-cos-lag-g2", []string{"verify", "L2", "latest", "cos", "expect=REF_POINTER_DRIFT"}, "@provider", func() any {
		output := program.runCLI(cli.ExitVerification, "verify", "--layer", "L2", "--view", "latest", "--target", "cos", "--config", program.configPath, "--workers", "2", "--chunk-entries", "64")
		if !strings.Contains(output, "code=REF_POINTER_DRIFT") {
			t.Fatalf("lagging cos target did not report YUM/asset ref drift\n%s", output)
		}
		return map[string]string{"output_sha256": realCloudLowerSHA256([]byte(output))}
	})

	program.step("publish-latest-cos-g3", []string{"publish", "latest", "cos", "generation=3"}, "@provider", func() any {
		program.runCLI(cli.ExitOK, "publish", "--view", "latest", "--target", "cos", "--config", program.configPath, "--workers", "2", "--chunk-entries", "64")
		publication := readRealCloudPublication(t, program.root, "cos")
		assertRealCloudLatestPublicationEnvelope(t, program.environment, publication, publish.TargetTencent, 3)
		assertRealCloudYUMAssetUpdate(t, program.environment, "cos", firstAsset, publication, publish.TargetTencent, 3)
		for _, target := range []string{"cf", "cos"} {
			assertRealCloudYUMGenerationInventory(t, program.root, target, 1, 3)
		}
		return realCloudPublicationResult(publication)
	})

	program.step("verify-latest-l2-l4", []string{"verify", "L2,L3,L4", "latest", "cf", "cos"}, "@provider", func() any {
		output := program.runCLI(cli.ExitOK, "verify", "--layer", "L2,L3,L4", "--view", "latest", "--target", "cf", "--target", "cos", "--config", program.configPath, "--workers", "2", "--chunk-entries", "64")
		if !strings.Contains(output, "verify outcome=passed") {
			t.Fatalf("real-cloud L2-L4 verification did not pass\n%s", output)
		}
		return map[string]string{"output_sha256": realCloudLowerSHA256([]byte(output))}
	})

	program.stepWithBaselines("latest-noop-replay-and-cas", []string{"publish", "latest", "cf", "cos", "expect=unchanged", "competing-cas"}, "@provider",
		program.publicationBaselines("cf", "cos"), func() any {
			beforeCF, beforeCOS := readRealCloudPublication(t, program.root, "cf"), readRealCloudPublication(t, program.root, "cos")
			output := program.runCLI(cli.ExitOK, "publish", "--view", "latest", "--target", "cf", "--target", "cos", "--config", program.configPath, "--workers", "2", "--chunk-entries", "64")
			for _, target := range []string{"cf", "cos"} {
				if !strings.Contains(output, "publish target="+target+" view=latest status=unchanged preflight=ref-vector") {
					t.Fatalf("target %s replay was not an explicit ref-vector no-op\n%s", target, output)
				}
			}
			afterCF, afterCOS := readRealCloudPublication(t, program.root, "cf"), readRealCloudPublication(t, program.root, "cos")
			assertRealCloudReplayUnchanged(t, "cf", beforeCF, afterCF)
			assertRealCloudReplayUnchanged(t, "cos", beforeCOS, afterCOS)
			assertRealCloudCompetingCAS(t, program.environment, program.secretFragments, afterCF, afterCOS)
			return map[string]string{"cf_checkpoint_sha256": realCloudLowerSHA256(afterCF.checkpointBody), "cos_checkpoint_sha256": realCloudLowerSHA256(afterCOS.checkpointBody)}
		})
}

func (program *realCloudAcceptanceProgram) stepWithBaselines(id string, operations []string, logicalAuth string, baselines []realCloudBaseline, action func() any) {
	program.t.Helper()
	if program.ledger.StepCompleted(id) {
		return
	}
	index := len(program.ledger.Snapshot().Receipts)
	descriptor, err := realCloudAcceptanceStepDescriptorAt(index)
	if err != nil || descriptor.ID != id {
		program.t.Fatalf("real-cloud acceptance descriptor for %s: %v", id, err)
	}
	intent := realCloudStepIntent{Template: descriptor.IntentTemplate, Operations: append([]string(nil), operations...), LogicalAuth: logicalAuth}
	if _, err := program.ledger.BeginStep(id, intent, baselines, time.Now().UTC()); err != nil {
		program.t.Fatalf("begin real-cloud acceptance step %s: %v", id, err)
	}
	program.activeStepID, program.cliCursor = id, 0
	defer func() { program.activeStepID, program.cliCursor = "", 0 }()
	result := action()
	if err := program.ledger.RequireCLISubstepsConsumed(id, program.cliCursor); err != nil {
		program.t.Fatalf("close real-cloud CLI substeps for %s: %v", id, err)
	}
	if err := program.ledger.CompleteStep(id, result, nil, time.Now().UTC()); err != nil {
		program.t.Fatalf("complete real-cloud acceptance step %s: %v", id, err)
	}
}

func (program *realCloudAcceptanceProgram) publicationBaselines(targets ...string) []realCloudBaseline {
	baselines := make([]realCloudBaseline, 0, len(targets)*3)
	for _, target := range targets {
		publication := readRealCloudPublication(program.t, program.root, target)
		baselines = append(baselines,
			realCloudBaseline{Name: target + "/checkpoint", SHA256: realCloudLowerSHA256(publication.checkpointBody)},
			realCloudBaseline{Name: target + "/generation", SHA256: realCloudLowerSHA256(publication.generationBody)},
			realCloudBaseline{Name: target + "/plan", SHA256: realCloudLowerSHA256(publication.planBody)},
		)
	}
	sort.Slice(baselines, func(i, j int) bool { return baselines[i].Name < baselines[j].Name })
	return baselines
}

func (program *realCloudAcceptanceProgram) runStableGenerations() {
	t := program.t
	program.step("promote-stable", []string{"promote", "beta", "stable", "apt", "yum", "public-asset"}, "@none", func() any {
		program.runCLI(cli.ExitOK, "promote", "beta", "stable", "--config", program.configPath,
			"--repo", realCloudRepositoryID, "--repo", realCloudYUMRepositoryID, "--repo", realCloudAssetRepositoryID,
			"--workers", "2", "--chunk-entries", "64")
		return map[string]string{"status": "stable-ref-verified"}
	})

	program.step("publish-stable-both-g4", []string{"publish", "stable", "cf", "cos", "generation=4"}, "@provider", func() any {
		program.runCLI(cli.ExitOK, "publish", "--view", "stable", "--target", "cf", "--target", "cos", "--config", program.configPath, "--workers", "2", "--chunk-entries", "64")
		cf := readRealCloudPublication(t, program.root, "cf")
		cos := readRealCloudPublication(t, program.root, "cos")
		cfAsset := assertRealCloudStablePublication(t, program.environment, "cf", cf, publish.TargetCloudflare, 4)
		cosAsset := assertRealCloudStablePublication(t, program.environment, "cos", cos, publish.TargetTencent, 4)
		wantedSHA := realCloudLowerSHA256(program.gatedBodies[0])
		if cfAsset.SHA256 != wantedSHA || cosAsset.SHA256 != wantedSHA {
			t.Fatalf("generation 4 gated asset digest cf=%s cos=%s want=%s", cfAsset.SHA256, cosAsset.SHA256, wantedSHA)
		}
		return map[string]any{"cf": realCloudPublicationResult(cf), "cos": realCloudPublicationResult(cos)}
	})

	program.step("edge-stage-g4", []string{"multi-pop", "generation=4", "cf", "edgeone"}, "@token-a,@token-b", func() any {
		stage, exists := program.loadActiveStage(4)
		if !exists {
			cf := readRealCloudPublication(t, program.root, "cf")
			cos := readRealCloudPublication(t, program.root, "cos")
			stage = assertRealCloudEdgeMultiPoPStage(t, program.environment, program.identity, program.secretFragments, program.gatedBodies[0], cf, cos, nil)
		}
		if err := validateRealEdgeActiveStagePair(stage); err != nil {
			t.Fatalf("generation 4 active stage reconstruction: %v", err)
		}
		return realCloudActiveStageResult(stage)
	})

	program.step("verify-stable-g4", []string{"cache-phase-v1", "dynamic-mirrorlist-g4", "verify-stable-token-a", "verify-stable-token-b"}, "@token-a,@token-b", func() any {
		assertRealCloudGatedCachePhase(t, program.environment, program.secretFragments, program.gatedBodies[0])
		assertRealCloudDynamicMirrorlists(t, program.environment, program.secretFragments, 4)
		var tokenAOutput, tokenBOutput string
		program.withRuntimeToken("a", program.environment.EdgeProTokenA, func(tokenPath string) {
			tokenAOutput = program.runCLI(cli.ExitOK, "verify", "--layer", "L2,L3,L4", "--view", "stable", "--target", "cf", "--target", "cos",
				"--config", program.configPath, "--repo", realCloudRepositoryID, "--repo", realCloudYUMRepositoryID,
				"--repo", realCloudAssetRepositoryID, "--repo", realCloudGatedAssetRepoID,
				"--pro-token-file", tokenPath, "--workers", "2", "--chunk-entries", "64")
		})
		if !strings.Contains(tokenAOutput, "verify outcome=passed") || !strings.Contains(tokenAOutput, `client="apt"`) || !strings.Contains(tokenAOutput, `client="dnf"`) {
			t.Fatalf("real-cloud stable token L2-L4 did not close APT and YUM\n%s", tokenAOutput)
		}
		program.withRuntimeToken("b", program.environment.EdgeProTokenB, func(tokenPath string) {
			tokenBOutput = program.runCLI(cli.ExitOK, "verify", "--layer", "L3", "--view", "stable", "--target", "cf", "--target", "cos",
				"--config", program.configPath, "--repo", realCloudRepositoryID, "--repo", realCloudYUMRepositoryID,
				"--repo", realCloudAssetRepositoryID, "--repo", realCloudGatedAssetRepoID,
				"--pro-token-file", tokenPath, "--workers", "2", "--chunk-entries", "64")
		})
		if !strings.Contains(tokenBOutput, "verify outcome=passed") {
			t.Fatalf("real-cloud second entitlement did not pass stable L3\n%s", tokenBOutput)
		}
		return map[string]string{"token_a_output_sha256": realCloudLowerSHA256([]byte(tokenAOutput)), "token_b_output_sha256": realCloudLowerSHA256([]byte(tokenBOutput))}
	})

	program.step("seed-gated-generation-2", []string{"write-gated-v2", "add-replace-gated"}, "@none", func() any {
		writeFile(t, program.gatedAssetPackage, program.gatedBodies[1], 0o600)
		program.runCLI(cli.ExitOK, "add", program.gatedAssetPackage, "--config", program.configPath, "--repo", realCloudGatedAssetRepoID, "--dest", "secret.txt", "--replace", "--workers", "2", "--chunk-entries", "64")
		return map[string]string{"gated_v2_sha256": realCloudLowerSHA256(program.gatedBodies[1])}
	})

	program.stepFacts("capture-pre-purge-g4", []string{"pre-purge", "generation=4", "cf", "edgeone"}, "@token-b", func() (any, func(*realCloudResumeFacts) error) {
		before, exists := program.loadActiveStage(4)
		if !exists {
			t.Fatal("generation 4 active stage is absent before pre-purge capture")
		}
		prePurge := captureRealCloudEdgePrePurge(t, program.environment, program.secretFragments, program.gatedBodies[0], before)
		resultSHA, err := realCloudCanonicalValueSHA256(prePurge)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]string{"pre_purge_sha256": resultSHA}, func(facts *realCloudResumeFacts) error {
			facts.PrePurge = cloneRealCloudPrePurgeFacts(prePurge)
			return validateRealCloudResumeFacts(*facts)
		}
	})

	program.runInterruptedPublication("interrupt-cf-g5", "cf", 5, 4)

	program.step("recover-cf-g5", []string{"require-independent-post-purge-watcher", "publish", "stable", "cf", "gated", "recover-generation=5"}, "@provider", func() any {
		program.armGenerationFivePurgeWatcher()
		fact := program.ledger.Snapshot().Facts.CFInterrupted
		if fact == nil {
			t.Fatal("Cloudflare recovery has no persisted interrupted transaction fact")
		}
		program.runCLI(cli.ExitOK, "publish", "--view", "stable", "--target", "cf", "--config", program.configPath,
			"--repo", realCloudGatedAssetRepoID, "--workers", "2", "--chunk-entries", "64")
		publication := readRealCloudPublication(t, program.root, "cf")
		asset := assertRealCloudGatedPublication(t, program.environment, "cf", publication, publish.TargetCloudflare, 5)
		if publication.checkpoint.TransactionID != fact.TransactionID || asset.SHA256 != realCloudLowerSHA256(program.gatedBodies[1]) {
			t.Fatalf("Cloudflare recovery identity changed transaction=%s wanted=%s asset=%s", publication.checkpoint.TransactionID, fact.TransactionID, asset.SHA256)
		}
		return realCloudPublicationResult(publication)
	})

	program.step("publish-cos-g5", []string{"require-independent-post-purge-watcher", "publish", "stable", "cos", "gated", "generation=5"}, "@provider", func() any {
		program.armGenerationFivePurgeWatcher()
		program.runCLI(cli.ExitOK, "publish", "--view", "stable", "--target", "cos", "--config", program.configPath,
			"--repo", realCloudGatedAssetRepoID, "--workers", "2", "--chunk-entries", "64")
		publication := readRealCloudPublication(t, program.root, "cos")
		asset := assertRealCloudGatedPublication(t, program.environment, "cos", publication, publish.TargetTencent, 5)
		if asset.SHA256 != realCloudLowerSHA256(program.gatedBodies[1]) {
			t.Fatal("COS generation 5 gated bytes do not match the frozen run body")
		}
		return realCloudPublicationResult(publication)
	})

	program.step("edge-stage-g5", []string{"multi-pop", "generation=5", "cf", "edgeone", "persisted-pre-purge"}, "@token-a,@token-b", func() any {
		before, exists := program.loadActiveStage(4)
		if !exists {
			t.Fatal("generation 4 active stage is absent")
		}
		after, exists := program.loadActiveStage(5)
		if !exists {
			prePurge := cloneRealCloudPrePurgeFacts(program.ledger.Snapshot().Facts.PrePurge)
			if len(prePurge) != 2 {
				t.Fatal("persisted pre-purge facts are absent")
			}
			after = program.consumeGenerationFivePurgeWatcher()
		} else if err := program.validatePersistedGenerationFivePurgeWatcherClosure(); err != nil {
			t.Fatalf("generation 5 active stage has no retained exact watcher closure: %v", err)
		}
		assertRealCloudEdgeMultiPoPPurgeTransition(t, before, after)
		return realCloudActiveStageResult(after)
	})

	program.step("seal-active-evidence", []string{"seal", "active-artifact", "generation=4,5"}, "@none", func() any {
		// Always invoke the idempotent sealer. A kill can happen after the seal
		// link is durable but before the active-artifact lock is released; merely
		// noticing the seal would strand that stale lock forever.
		if err := sealRealEdgeActiveArtifact(program.artifactPath, program.identity.RunID); err != nil {
			t.Fatalf("seal completed real edge active artifact: %v", err)
		}
		records, loadErr := loadRealEdgeSealedActiveArtifact(program.artifactPath, program.secretFragments, program.identity.RunID)
		if loadErr != nil || len(records) != 4 {
			t.Fatalf("existing active artifact seal is invalid records=%d err=%v", len(records), loadErr)
		}
		sealBody := readRequiredFile(t, program.artifactPath+".seal")
		return map[string]string{"seal_sha256": realCloudLowerSHA256(sealBody)}
	})

	program.step("verify-stable-g5", []string{"cache-phase-v2", "verify-stable-gated-L2,L3"}, "@provider", func() any {
		assertRealCloudGatedCachePhase(t, program.environment, program.secretFragments, program.gatedBodies[1])
		output := program.runCLI(cli.ExitOK, "verify", "--layer", "L2,L3", "--view", "stable", "--target", "cf", "--target", "cos", "--config", program.configPath, "--repo", realCloudGatedAssetRepoID, "--workers", "2", "--chunk-entries", "64")
		if !strings.Contains(output, "verify outcome=passed") {
			t.Fatalf("real-cloud gated L2-L3 verification did not pass\n%s", output)
		}
		return map[string]string{"output_sha256": realCloudLowerSHA256([]byte(output))}
	})

	program.step("seed-gated-generation-3", []string{"write-gated-v3", "add-replace-gated"}, "@none", func() any {
		writeFile(t, program.gatedAssetPackage, program.gatedBodies[2], 0o600)
		program.runCLI(cli.ExitOK, "add", program.gatedAssetPackage, "--config", program.configPath, "--repo", realCloudGatedAssetRepoID, "--dest", "secret.txt", "--replace", "--workers", "2", "--chunk-entries", "64")
		return map[string]string{"gated_v3_sha256": realCloudLowerSHA256(program.gatedBodies[2])}
	})

	program.runInterruptedPublication("interrupt-cos-g6", "cos", 6, 5)

	program.step("recover-cos-g6", []string{"publish", "stable", "cos", "gated", "recover-generation=6"}, "@provider", func() any {
		fact := program.ledger.Snapshot().Facts.COSInterrupted
		if fact == nil {
			t.Fatal("COS recovery has no persisted interrupted transaction fact")
		}
		program.runCLI(cli.ExitOK, "publish", "--view", "stable", "--target", "cos", "--config", program.configPath,
			"--repo", realCloudGatedAssetRepoID, "--workers", "2", "--chunk-entries", "64")
		publication := readRealCloudPublication(t, program.root, "cos")
		asset := assertRealCloudGatedPublication(t, program.environment, "cos", publication, publish.TargetTencent, 6)
		if publication.checkpoint.TransactionID != fact.TransactionID || asset.SHA256 != realCloudLowerSHA256(program.gatedBodies[2]) {
			t.Fatal("COS recovery changed its locked transaction or gated bytes")
		}
		return realCloudPublicationResult(publication)
	})

	program.step("publish-cf-g6", []string{"publish", "stable", "cf", "gated", "generation=6"}, "@provider", func() any {
		cos := readRealCloudPublication(t, program.root, "cos")
		program.runCLI(cli.ExitOK, "publish", "--view", "stable", "--target", "cf", "--config", program.configPath,
			"--repo", realCloudGatedAssetRepoID, "--workers", "2", "--chunk-entries", "64")
		publication := readRealCloudPublication(t, program.root, "cf")
		asset := assertRealCloudGatedPublication(t, program.environment, "cf", publication, publish.TargetCloudflare, 6)
		assertRealCloudGatedPublication(t, program.environment, "cos", cos, publish.TargetTencent, 6)
		if asset.SHA256 != realCloudLowerSHA256(program.gatedBodies[2]) {
			t.Fatal("Cloudflare generation 6 gated bytes do not match")
		}
		return realCloudPublicationResult(publication)
	})

	program.step("verify-stable-g6", []string{"cache-phase-v3", "independent-target-generation=6"}, "@provider", func() any {
		assertRealCloudGatedCachePhase(t, program.environment, program.secretFragments, program.gatedBodies[2])
		return map[string]string{"gated_v3_sha256": realCloudLowerSHA256(program.gatedBodies[2])}
	})
}

func (program *realCloudAcceptanceProgram) runInterruptedPublication(stepID, target string, generation, parent uint64) {
	operations := []string{"publish", "stable", target, "gated", fmt.Sprintf("interrupt-generation=%d", generation)}
	if target == "cf" && generation == 5 {
		operations = append(operations, "arm-independent-post-purge-watcher")
	}
	program.stepFacts(stepID, operations, "@intentional-invalid-provider", func() (any, func(*realCloudResumeFacts) error) {
		if target == "cf" && generation == 5 {
			// No provider/observer request for generation five is allowed until a
			// separately surviving process has durably taken ownership of the
			// pre-purge TTL window.
			program.armGenerationFivePurgeWatcher()
		}
		providerTarget := publish.TargetCloudflare
		if target == "cos" {
			providerTarget = publish.TargetTencent
		}
		locked := readRealCloudCheckpoint(program.t, program.environment, program.secretFragments, target)
		if err := validateRealCloudInterruptedPublicationEntry(locked, providerTarget, generation, parent); err != nil {
			program.t.Fatalf("interrupted %s entry checkpoint: %v", target, err)
		}
		// Always replay the intentionally invalid purge while this ledger step
		// is current. A SIGKILL can land after the generation lock, after the
		// pointer flip, or after the failed purge but before CompleteStep. The
		// product journal must converge all three windows to the same locked
		// transaction; merely observing the locked checkpoint is not proof that
		// the required pointer-flipped failure was exercised.
		program.runIntentionalPurgeFailure(target)
		locked = readRealCloudCheckpoint(program.t, program.environment, program.secretFragments, target)
		if locked.Generation != generation || locked.ParentGeneration != parent || locked.Phase != publish.PhaseLocked || locked.IntentView != "stable" || locked.Target != providerTarget {
			program.t.Fatalf("interrupted %s checkpoint=%#v, want locked generation=%d parent=%d", target, locked, generation, parent)
		}
		parentPublication := readRealCloudPublication(program.t, program.root, target)
		if parentPublication.checkpoint.Generation != parent {
			program.t.Fatalf("interrupted %s advanced local committed generation=%d want parent=%d", target, parentPublication.checkpoint.Generation, parent)
		}
		wantedBody := program.gatedBodies[generation-4]
		assertRealCloudInterruptedRemotePointer(program.t, program.environment, program.secretFragments, target, locked, wantedBody)
		assertRealCloudInterruptedJournal(program.t, program.root, target, locked, parentPublication)
		canonical, err := locked.Canonical()
		if err != nil {
			program.t.Fatal(err)
		}
		fact := &realCloudInterruptedFact{
			Target: target, Generation: generation, ParentGeneration: parent,
			TransactionID: locked.TransactionID, LockedCheckpointSHA256: realCloudLowerSHA256(canonical),
		}
		return map[string]any{"target": target, "generation": generation, "transaction": locked.TransactionID}, func(facts *realCloudResumeFacts) error {
			if target == "cf" {
				facts.CFInterrupted = fact
			} else {
				facts.COSInterrupted = fact
			}
			return validateRealCloudResumeFacts(*facts)
		}
	})
}

func validateRealCloudInterruptedPublicationEntry(checkpoint publish.Checkpoint, target publish.TargetName, generation, parent uint64) error {
	parentCommitted := checkpoint.Generation == parent && checkpoint.Phase == publish.PhaseCheckpointCommitted
	expectedLocked := checkpoint.Generation == generation && checkpoint.ParentGeneration == parent && checkpoint.Phase == publish.PhaseLocked &&
		checkpoint.IntentView == "stable" && checkpoint.Target == target
	if parentCommitted {
		if checkpoint.Target != target || checkpoint.IntentView != "stable" {
			return errors.New("parent checkpoint has the wrong target or view")
		}
		return nil
	}
	if expectedLocked {
		return nil
	}
	if checkpoint.Generation == generation && checkpoint.Phase == publish.PhaseCheckpointCommitted {
		return errors.New("expected interrupted generation is already committed; intentional failure proof was skipped")
	}
	return fmt.Errorf("checkpoint generation=%d parent=%d phase=%s target=%s view=%s is neither parent-committed nor expected-locked",
		checkpoint.Generation, checkpoint.ParentGeneration, checkpoint.Phase, checkpoint.Target, checkpoint.IntentView)
}

func (program *realCloudAcceptanceProgram) runIntentionalPurgeFailure(target string) {
	if target == "cf" {
		original := os.Getenv(realCloudCDNCredentialCF)
		invalid := realCloudInvalidCloudflareCDNCredential(program.t, original)
		program.t.Setenv(realCloudCDNCredentialCF, invalid)
		prior := program.secretFragments
		program.secretFragments = append(append([]string(nil), prior...), invalid, realCloudInvalidCFToken)
		sort.Strings(program.secretFragments)
		output := program.runCLI(cli.ExitNetworkAuth, "publish", "--view", "stable", "--target", "cf", "--config", program.configPath,
			"--repo", realCloudGatedAssetRepoID, "--workers", "2", "--chunk-entries", "64")
		program.secretFragments = prior
		program.t.Setenv(realCloudCDNCredentialCF, original)
		if !strings.Contains(output, "generation=5 phase=pointer-flipped status=failed") {
			program.t.Fatalf("Cloudflare credential failure did not stop at pointer-flipped\n%s", output)
		}
		return
	}
	original := os.Getenv(realCloudCDNCredentialCOS)
	invalid := realCloudInvalidTencentCDNCredential(program.t, original)
	program.t.Setenv(realCloudCDNCredentialCOS, invalid)
	prior := program.secretFragments
	program.secretFragments = append(append([]string(nil), prior...), invalid, realCloudInvalidTencentID, realCloudInvalidTencentKey)
	sort.Strings(program.secretFragments)
	output := program.runCLI(cli.ExitNetworkAuth, "publish", "--view", "stable", "--target", "cos", "--config", program.configPath,
		"--repo", realCloudGatedAssetRepoID, "--workers", "2", "--chunk-entries", "64")
	program.secretFragments = prior
	program.t.Setenv(realCloudCDNCredentialCOS, original)
	if !strings.Contains(output, "generation=6 phase=pointer-flipped status=failed") {
		program.t.Fatalf("EdgeOne credential failure did not stop at pointer-flipped\n%s", output)
	}
}

func (program *realCloudAcceptanceProgram) loadActiveStage(generation uint64) (realEdgeMultiPoPStageEvidence, bool) {
	program.t.Helper()
	if _, err := os.Lstat(program.artifactPath); errors.Is(err, os.ErrNotExist) {
		return realEdgeMultiPoPStageEvidence{}, false
	} else if err != nil {
		program.t.Fatalf("inspect active artifact before generation %d reconstruction: %v", generation, err)
	}
	records, err := loadRealEdgeActiveArtifact(program.artifactPath, program.secretFragments)
	if err != nil {
		program.t.Fatalf("load active artifact before generation %d reconstruction: %v", generation, err)
	}
	result := realEdgeMultiPoPStageEvidence{Vendors: make(map[string]realEdgeMultiPoPVendorStage, 2)}
	for _, record := range records {
		if record.Generation != generation {
			continue
		}
		if record.RunID != program.identity.RunID || record.ConfirmationSHA256 != program.identity.ConfirmationSHA256 || record.ConfigSHA256 != program.identity.ConfigSHA256 {
			program.t.Fatalf("generation %d active artifact record belongs to another run", generation)
		}
		stage, err := artifactRecordToRealEdgeStage(record)
		if err != nil {
			program.t.Fatalf("decode generation %d %s active stage: %v", generation, record.Vendor, err)
		}
		if _, duplicate := result.Vendors[record.Vendor]; duplicate {
			program.t.Fatalf("generation %d active artifact contains duplicate %s", generation, record.Vendor)
		}
		result.Vendors[record.Vendor] = stage
		if result.EntitlementSHA256 == nil {
			result.EntitlementSHA256 = append([]string(nil), record.EntitlementSHA256...)
		} else if !slices.Equal(result.EntitlementSHA256, record.EntitlementSHA256) {
			program.t.Fatalf("generation %d active vendors disagree on entitlement digest set", generation)
		}
	}
	if len(result.Vendors) == 0 {
		return realEdgeMultiPoPStageEvidence{}, false
	}
	if len(result.Vendors) != 2 {
		program.t.Fatalf("generation %d active artifact is partial", generation)
	}
	return result, true
}

func validateRealEdgeActiveStagePair(stage realEdgeMultiPoPStageEvidence) error {
	if len(stage.Vendors) != 2 {
		return errors.New("active stage pair must contain exactly two vendors")
	}
	cloudflare, cfOK := stage.Vendors["cloudflare"]
	edgeOne, edgeOK := stage.Vendors["edgeone"]
	if !cfOK || !edgeOK || !sameRealEdgeRunBinding(cloudflare, edgeOne) || cloudflare.Generation != edgeOne.Generation {
		return errors.New("active stage pair is not one run and generation")
	}
	if err := validateRealEdgeActiveStage(cloudflare); err != nil {
		return fmt.Errorf("cloudflare active stage: %w", err)
	}
	if err := validateRealEdgeActiveStage(edgeOne); err != nil {
		return fmt.Errorf("edgeone active stage: %w", err)
	}
	return validateRealEdgeEntitlementDigests(stage.EntitlementSHA256)
}

func realCloudActiveStageResult(stage realEdgeMultiPoPStageEvidence) map[string]any {
	result := make(map[string]any, 2)
	for _, vendor := range []string{"cloudflare", "edgeone"} {
		value := stage.Vendors[vendor]
		result[vendor] = map[string]any{
			"generation": value.Generation, "transaction": value.TransactionID,
			"body_sha256": value.BodySHA256, "observations": len(value.Observations),
		}
	}
	return result
}

func cloneRealCloudPrePurgeFacts(source map[string]realEdgePrePurgeVendorEvidence) map[string]realEdgePrePurgeVendorEvidence {
	if source == nil {
		return nil
	}
	result := make(map[string]realEdgePrePurgeVendorEvidence, len(source))
	for key, value := range source {
		value.Observations = append([]realEdgeMultiPoPObservation(nil), value.Observations...)
		result[key] = value
	}
	return result
}

func (program *realCloudAcceptanceProgram) withRuntimeToken(logicalName, value string, action func(string)) {
	program.t.Helper()
	err := withRegisteredRealCloudRuntimeToken(program.root, logicalName, value, func(path string) error {
		action(path)
		return nil
	}, func(err error) {
		program.t.Errorf("cleanup logical runtime token %s: %v", logicalName, err)
	})
	if err != nil {
		program.t.Fatalf("logical runtime token %s: %v", logicalName, err)
	}
}

func withRegisteredRealCloudRuntimeToken(root, logicalName, value string, action func(string) error, reportCleanup func(error)) (resultErr error) {
	if action == nil || reportCleanup == nil {
		return errors.New("runtime token action and cleanup reporter are required")
	}
	var cleanup func()
	name, err := prepareRealCloudRuntimeSecretFile(
		value,
		func() (realCloudRuntimeSecretFile, error) {
			return createRegisteredRealCloudRuntimeSecretFile(root, logicalName, len(value)+1)
		},
		func(callback func()) { cleanup = callback },
		func(identity realCloudRuntimeSecretIdentity) error {
			if err := cleanupRealCloudRuntimeSecretHandle(identity); err != nil {
				return err
			}
			return clearRealCloudSecretRegistry(root)
		},
		reportCleanup,
	)
	if err != nil {
		return err
	}
	if cleanup == nil {
		return errors.New("logical runtime token did not arm cleanup")
	}
	defer cleanup()
	return action(name)
}

func createRegisteredRealCloudRuntimeSecretFile(root, logicalName string, size int) (realCloudRuntimeSecretFile, error) {
	if logicalName != "a" && logicalName != "b" || size <= 1 || size > 4096 {
		return nil, errors.New("runtime secret registry logical identity or size is invalid")
	}
	scratch := root + realCloudSecretScratchSuffix
	if err := ensureRealCloudSecretScratchDirectory(scratch); err != nil {
		return nil, err
	}
	registryPath := filepath.Join(scratch, realCloudSecretRegistryName)
	if _, err := os.Lstat(registryPath); err == nil {
		return nil, errors.New("runtime secret registry already contains an uncleared entry")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("runtime secret registry cannot be safely inspected")
	}
	file, err := os.CreateTemp(scratch, ".sow-real-cloud-pro-token-"+logicalName+"-*")
	if err != nil {
		return nil, errors.New("create registered runtime secret file")
	}
	cleanupUnregistered := func() {
		_ = file.Close()
		_ = os.Remove(file.Name())
	}
	if err := file.Chmod(0o600); err != nil {
		cleanupUnregistered()
		return nil, errors.New("secure registered runtime secret file")
	}
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil || stat.Ino == 0 {
		cleanupUnregistered()
		return nil, errors.New("registered runtime secret file has no stable inode identity")
	}
	registry := realCloudSecretRegistry{
		Schema: realCloudSecretRegistrySchema, WorkspaceSHA256: realCloudLowerSHA256([]byte(root)),
		Entry: &realCloudSecretRegistryEntry{LogicalName: logicalName, Path: file.Name(), Device: uint64(stat.Dev), Inode: uint64(stat.Ino), Size: size},
	}
	if err := replaceRealCloudSecretRegistry(registryPath, registry); err != nil {
		cleanupUnregistered()
		return nil, err
	}
	return file, nil
}

func ensureRealCloudSecretScratchDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return errors.New("create real-cloud secret scratch directory")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("real-cloud secret scratch is not one private non-symlink directory")
	}
	return nil
}

func replaceRealCloudSecretRegistry(path string, registry realCloudSecretRegistry) error {
	if registry.Schema != realCloudSecretRegistrySchema || !validRealCloudLowerSHA256(registry.WorkspaceSHA256) || registry.Entry == nil {
		return errors.New("runtime secret registry is invalid")
	}
	body, err := json.Marshal(registry)
	if err != nil {
		return errors.New("encode runtime secret registry")
	}
	body = append(body, '\n')
	installed, err := installRealCloudPrivateFileExclusiveWithPattern(path, body, ".sow-real-cloud-secret-registry-*.tmp")
	if err != nil {
		return errors.New("atomically install runtime secret registry")
	}
	if !installed {
		return errors.New("runtime secret registry appeared concurrently and was preserved")
	}
	return nil
}

func readRealCloudSecretRegistry(path string) (realCloudSecretRegistry, error) {
	var registry realCloudSecretRegistry
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > 16<<10 {
		return registry, errors.New("runtime secret registry is absent or unsafe")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return registry, errors.New("read runtime secret registry")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registry); err != nil {
		return registry, errors.New("decode runtime secret registry")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return registry, errors.New("runtime secret registry contains trailing values")
	}
	canonical, err := json.Marshal(registry)
	if err != nil || !bytes.Equal(body, append(canonical, '\n')) {
		return registry, errors.New("runtime secret registry is not canonical")
	}
	if registry.Schema != realCloudSecretRegistrySchema || !validRealCloudLowerSHA256(registry.WorkspaceSHA256) || registry.Entry == nil {
		return registry, errors.New("runtime secret registry identity is invalid")
	}
	return registry, nil
}

func recoverRealCloudSecretScratch(root string) error {
	scratch := root + realCloudSecretScratchSuffix
	if _, err := os.Lstat(scratch); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return errors.New("inspect real-cloud secret scratch")
	}
	if err := ensureRealCloudSecretScratchDirectory(scratch); err != nil {
		return err
	}
	registryPath := filepath.Join(scratch, realCloudSecretRegistryName)
	if _, err := os.Lstat(registryPath); errors.Is(err, os.ErrNotExist) {
		return cleanupEmptyRealCloudSecretScratch(scratch)
	} else if err != nil {
		return errors.New("inspect runtime secret registry")
	}
	registry, err := readRealCloudSecretRegistry(registryPath)
	if err != nil {
		return err
	}
	if registry.WorkspaceSHA256 != realCloudLowerSHA256([]byte(root)) {
		return errors.New("runtime secret registry belongs to another workspace")
	}
	entry := registry.Entry
	if filepath.Dir(entry.Path) != scratch || filepath.Clean(entry.Path) != entry.Path ||
		!strings.HasPrefix(filepath.Base(entry.Path), ".sow-real-cloud-pro-token-"+entry.LogicalName+"-") ||
		entry.Size <= 0 || entry.Size > 4096 || entry.LogicalName != "a" && entry.LogicalName != "b" {
		return errors.New("runtime secret registry entry escaped its scratch directory")
	}
	info, err := os.Lstat(entry.Path)
	if errors.Is(err, os.ErrNotExist) {
		if err := removeRealCloudSecretRegistry(registryPath); err != nil {
			return err
		}
		return cleanupEmptyRealCloudSecretScratch(scratch)
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("registered runtime secret path is unsafe")
	}
	var stat unix.Stat_t
	if unix.Lstat(entry.Path, &stat) != nil || uint64(stat.Dev) != entry.Device || uint64(stat.Ino) != entry.Inode {
		return errors.New("registered runtime secret inode identity changed")
	}
	fd, err := unix.Open(entry.Path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("open registered runtime secret for recovery scrub")
	}
	file := os.NewFile(uintptr(fd), entry.Path)
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return errors.New("registered runtime secret changed during recovery open")
	}
	identity := realCloudRuntimeSecretIdentity{name: entry.Path, size: entry.Size, file: file, info: opened}
	if err := cleanupRealCloudRuntimeSecretHandle(identity); err != nil {
		return err
	}
	if err := removeRealCloudSecretRegistry(registryPath); err != nil {
		return err
	}
	return cleanupEmptyRealCloudSecretScratch(scratch)
}

func clearRealCloudSecretRegistry(root string) error {
	return removeRealCloudSecretRegistry(filepath.Join(root+realCloudSecretScratchSuffix, realCloudSecretRegistryName))
}

func removeRealCloudSecretRegistry(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("runtime secret registry cannot be safely removed")
	}
	if err := os.Remove(path); err != nil {
		return errors.New("remove runtime secret registry")
	}
	return syncRealCloudDirectoryError(filepath.Dir(path))
}

func cleanupEmptyRealCloudSecretScratch(scratch string) error {
	entries, err := os.ReadDir(scratch)
	if err != nil {
		return errors.New("list real-cloud secret scratch")
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return errors.New("secret scratch contains an unregistered foreign entry")
		}
		path := filepath.Join(scratch, entry.Name())
		info, err := os.Lstat(path)
		registryTemporary := strings.HasPrefix(entry.Name(), ".sow-real-cloud-secret-registry-") && strings.HasSuffix(entry.Name(), ".tmp")
		tokenTemporary := strings.HasPrefix(entry.Name(), ".sow-real-cloud-pro-token-")
		if !registryTemporary && !tokenTemporary {
			return errors.New("secret scratch contains an unregistered foreign entry")
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 ||
			tokenTemporary && info.Size() != 0 || registryTemporary && (info.Size() < 0 || info.Size() > 16<<10) {
			return errors.New("secret scratch contains unregistered non-empty or unsafe bytes")
		}
		if err := os.Remove(path); err != nil {
			return errors.New("remove empty unregistered runtime secret file")
		}
	}
	return syncRealCloudDirectoryError(scratch)
}

func (program *realCloudAcceptanceProgram) runSnapshotsAndRestore() {
	t := program.t
	program.stepFacts("allocate-snapshot-ids", []string{"snapshot-expiry-policy", "el10", "now-7-months"}, "@none", func() (any, func(*realCloudResumeFacts) error) {
		now := time.Now().UTC()
		expired, err := views.SnapshotID("el10", now.AddDate(0, -7, 0))
		if err != nil {
			t.Fatal(err)
		}
		return map[string]string{"expired": expired, "policy": "utc-now-minus-seven-calendar-months"}, func(facts *realCloudResumeFacts) error {
			facts.ExpiredSnapshotID = expired
			return validateRealCloudResumeFacts(*facts)
		}
	})
	snapshotFacts := program.ledger.Snapshot().Facts
	expiredSnapshot := snapshotFacts.ExpiredSnapshotID
	if expiredSnapshot == "" {
		t.Fatal("snapshot expiry policy ID was not durably allocated")
	}

	program.stepFacts("prepare-current-and-historical-snapshots", []string{"recover-canonical-state", "discover-or-promote-current-utc-snapshot", "yum", "seed-historical", expiredSnapshot}, "@none", func() (any, func(*realCloudResumeFacts) error) {
		// A killed promote can leave the state lock or canonical Apply journal
		// behind. Recover it before inspecting refs; this also closes the window
		// where the immutable ref committed but the CLI died before releasing its
		// lock. The current snapshot date is chosen only after this convergence.
		program.runCLI(cli.ExitOK, "fsck", "--config", program.configPath, "--repo", realCloudYUMRepositoryID, "--recover", "--limit", "0", "--workers", "2", "--chunk-entries", "64")
		storedPromote, promoteStarted, promoteInFlight := program.ledger.CLISubstepArguments("prepare-current-and-historical-snapshots", 1)
		if promoteStarted {
			if err := recoverRealCloudSnapshotCanonicalMutation(t.Context(), program.root); err != nil {
				t.Fatalf("recover interrupted snapshot canonical mutation: %v", err)
			}
		}
		recentSnapshot, exists, err := discoverRealCloudCurrentSnapshot(program.root, expiredSnapshot)
		if err != nil {
			t.Fatalf("discover current snapshot recovery ref: %v", err)
		}
		var promoteArguments []string
		if promoteStarted {
			if len(storedPromote) < 3 || storedPromote[0] != "promote" || storedPromote[1] != "stable" || views.ValidateSnapshotID(storedPromote[2]) != nil {
				t.Fatal("durable snapshot promote CLI substep is malformed")
			}
			promoteArguments = append([]string(nil), storedPromote...)
		}
		if exists {
			if !promoteStarted || recentSnapshot != storedPromote[2] {
				t.Fatalf("discovered current snapshot %q is not the durable promote substep", recentSnapshot)
			}
			program.consumeRecoveredCLIFromPostcondition(cli.ExitOK, "promote recovered from exact immutable snapshot ref\n", promoteArguments...)
		} else {
			recentSnapshot, err = views.SnapshotID("el10", time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			wantedArguments := []string{"promote", "stable", recentSnapshot, "--config", program.configPath, "--repo", realCloudYUMRepositoryID, "--workers", "2", "--chunk-entries", "64"}
			if promoteStarted {
				if !promoteInFlight {
					t.Fatal("completed durable snapshot promote receipt lost its immutable ref")
				}
				if !slices.Equal(promoteArguments, wantedArguments) {
					if err := program.ledger.ReplaceInFlightCLIArguments("prepare-current-and-historical-snapshots", 1, cli.ExitOK, promoteArguments, wantedArguments, time.Now().UTC()); err != nil {
						t.Fatalf("roll unmutated snapshot intent to current UTC date: %v", err)
					}
				}
			}
			program.runCLI(cli.ExitOK, wantedArguments...)
			discovered, found, discoverErr := discoverRealCloudCurrentSnapshot(program.root, expiredSnapshot)
			if discoverErr != nil || !found || discovered != recentSnapshot {
				t.Fatalf("promoted current snapshot ref did not converge discovered=%q wanted=%q exists=%v err=%v", discovered, recentSnapshot, found, discoverErr)
			}
		}
		ensureRealCloudHistoricalSnapshot(t, program.root, recentSnapshot, expiredSnapshot)
		return map[string]string{"recent": recentSnapshot, "expired": expiredSnapshot}, func(facts *realCloudResumeFacts) error {
			facts.RecentSnapshotID = recentSnapshot
			return validateRealCloudResumeFacts(*facts)
		}
	})
	snapshotFacts = program.ledger.Snapshot().Facts
	recentSnapshot := snapshotFacts.RecentSnapshotID
	if recentSnapshot == "" || snapshotFacts.ExpiredSnapshotID != expiredSnapshot {
		t.Fatal("snapshot current/historical IDs were not atomically closed by the prepare step")
	}

	program.step("publish-expired-cf-g7", []string{"publish", "snapshot", expiredSnapshot, "cf", "generation=7"}, "@provider", func() any {
		program.runCLI(cli.ExitOK, "publish", "--snapshot", expiredSnapshot, "--target", "cf", "--config", program.configPath,
			"--repo", realCloudYUMRepositoryID, "--workers", "2", "--chunk-entries", "64")
		publication := readRealCloudPublication(t, program.root, "cf")
		assertRealCloudSnapshotPublication(t, program.environment, publication, publish.TargetCloudflare, 7, expiredSnapshot, "")
		assertRealCloudSnapshotInventory(t, program.root, "cf", []string{expiredSnapshot}, nil)
		return realCloudPublicationResult(publication)
	})

	program.step("copy-probe-expired-cf", []string{"server-side-copy-probe", "cf", expiredSnapshot}, "@provider", func() any {
		publication := readRealCloudPublication(t, program.root, "cf")
		program.cleanupSnapshotCopyProbe("cf", publication)
		assertRealCloudSnapshotCopyProvider(t, program.environment, program.secretFragments, "cf", publication)
		return map[string]string{"target": "cf", "snapshot": expiredSnapshot, "status": "copy-and-conditional-delete-verified"}
	})

	program.step("publish-expired-cos-g7", []string{"publish", "snapshot", expiredSnapshot, "cos", "generation=7"}, "@provider", func() any {
		program.runCLI(cli.ExitOK, "publish", "--snapshot", expiredSnapshot, "--target", "cos", "--config", program.configPath,
			"--repo", realCloudYUMRepositoryID, "--workers", "2", "--chunk-entries", "64")
		publication := readRealCloudPublication(t, program.root, "cos")
		assertRealCloudSnapshotPublication(t, program.environment, publication, publish.TargetTencent, 7, expiredSnapshot, "")
		assertRealCloudSnapshotInventory(t, program.root, "cos", []string{expiredSnapshot}, nil)
		return realCloudPublicationResult(publication)
	})

	program.step("copy-probe-expired-cos", []string{"server-side-copy-probe", "cos", expiredSnapshot}, "@provider", func() any {
		publication := readRealCloudPublication(t, program.root, "cos")
		program.cleanupSnapshotCopyProbe("cos", publication)
		assertRealCloudSnapshotCopyProvider(t, program.environment, program.secretFragments, "cos", publication)
		return map[string]string{"target": "cos", "snapshot": expiredSnapshot, "status": "copy-and-conditional-delete-verified"}
	})

	program.step("publish-current-cf-g8", []string{"publish", "snapshot", recentSnapshot, "cf", "generation=8", "expire=" + expiredSnapshot}, "@provider", func() any {
		program.runCLI(cli.ExitOK, "publish", "--snapshot", recentSnapshot, "--target", "cf", "--config", program.configPath,
			"--repo", realCloudYUMRepositoryID, "--workers", "2", "--chunk-entries", "64")
		publication := readRealCloudPublication(t, program.root, "cf")
		assertRealCloudSnapshotPublication(t, program.environment, publication, publish.TargetCloudflare, 8, recentSnapshot, expiredSnapshot)
		assertRealCloudDeletedObjectsAbsent(t, program.environment, program.secretFragments, "cf", publication)
		assertRealCloudSnapshotInventory(t, program.root, "cf", []string{recentSnapshot}, []string{expiredSnapshot})
		assertRealCloudSnapshotInventory(t, program.root, "cos", []string{expiredSnapshot}, []string{recentSnapshot})
		return realCloudPublicationResult(publication)
	})

	program.step("publish-current-cos-g8", []string{"publish", "snapshot", recentSnapshot, "cos", "generation=8", "expire=" + expiredSnapshot}, "@provider", func() any {
		program.runCLI(cli.ExitOK, "publish", "--snapshot", recentSnapshot, "--target", "cos", "--config", program.configPath,
			"--repo", realCloudYUMRepositoryID, "--workers", "2", "--chunk-entries", "64")
		publication := readRealCloudPublication(t, program.root, "cos")
		assertRealCloudSnapshotPublication(t, program.environment, publication, publish.TargetTencent, 8, recentSnapshot, expiredSnapshot)
		assertRealCloudDeletedObjectsAbsent(t, program.environment, program.secretFragments, "cos", publication)
		assertRealCloudSnapshotInventory(t, program.root, "cos", []string{recentSnapshot}, []string{expiredSnapshot})
		return realCloudPublicationResult(publication)
	})

	program.step("verify-current-snapshot", []string{"verify", "snapshot", recentSnapshot, "cf", "cos", "L2,L3,L4", "yum"}, "@token-a", func() any {
		var output string
		program.withRuntimeToken("a", program.environment.EdgeProTokenA, func(tokenPath string) {
			output = program.runCLI(cli.ExitOK, "verify", "--layer", "L2,L3,L4", "--snapshot", recentSnapshot, "--target", "cf", "--target", "cos",
				"--config", program.configPath, "--repo", realCloudYUMRepositoryID, "--pro-token-file", tokenPath, "--workers", "2", "--chunk-entries", "64")
		})
		if !strings.Contains(output, "verify outcome=passed") || !strings.Contains(output, `client="dnf"`) {
			t.Fatalf("recent snapshot token L2-L4 did not close YUM\n%s", output)
		}
		return map[string]string{"output_sha256": realCloudLowerSHA256([]byte(output))}
	})

	program.stepWithBaselines("snapshot-noop-replay", []string{"publish", "snapshot", recentSnapshot, "cf", "cos", "expect=unchanged"}, "@provider",
		program.publicationBaselines("cf", "cos"), func() any {
			beforeCF, beforeCOS := readRealCloudPublication(t, program.root, "cf"), readRealCloudPublication(t, program.root, "cos")
			output := program.runCLI(cli.ExitOK, "publish", "--snapshot", recentSnapshot, "--target", "cf", "--target", "cos", "--config", program.configPath,
				"--repo", realCloudYUMRepositoryID, "--workers", "2", "--chunk-entries", "64")
			for _, target := range []string{"cf", "cos"} {
				if !strings.Contains(output, "publish target="+target+" view=snapshot snapshot="+recentSnapshot+" status=unchanged") {
					t.Fatalf("target %s snapshot replay was not an explicit no-op\n%s", target, output)
				}
			}
			afterCF, afterCOS := readRealCloudPublication(t, program.root, "cf"), readRealCloudPublication(t, program.root, "cos")
			assertRealCloudReplayUnchanged(t, "cf", beforeCF, afterCF)
			assertRealCloudReplayUnchanged(t, "cos", beforeCOS, afterCOS)
			return map[string]string{"cf_checkpoint_sha256": realCloudLowerSHA256(afterCF.checkpointBody), "cos_checkpoint_sha256": realCloudLowerSHA256(afterCOS.checkpointBody)}
		})

	program.step("restore-cf-g9", []string{"publish", "restore-generation=4", "cf", "generation=9"}, "@provider", func() any {
		program.runCLI(cli.ExitOK, "publish", "--restore-generation", "4", "--target", "cf", "--config", program.configPath, "--workers", "2", "--chunk-entries", "64")
		publication := readRealCloudPublication(t, program.root, "cf")
		asset := assertRealCloudGatedPublication(t, program.environment, "cf", publication, publish.TargetCloudflare, 9)
		if publication.generation.ParentGeneration != 8 || publication.generation.IntentView != "stable" || asset.SHA256 != realCloudLowerSHA256(program.gatedBodies[0]) {
			t.Fatalf("R2 restore publication=%#v asset=%s", publication.generation, asset.SHA256)
		}
		assertRealCloudGatedVendorBody(t, "cloudflare", program.environment.CFCDNBase, program.environment, program.secretFragments, program.gatedBodies[0])
		assertRealCloudGatedVendorBody(t, "edgeone", program.environment.COSCDNBase, program.environment, program.secretFragments, program.gatedBodies[2])
		return realCloudPublicationResult(publication)
	})

	program.step("restore-cos-g9", []string{"publish", "restore-generation=4", "cos", "generation=9"}, "@provider", func() any {
		program.runCLI(cli.ExitOK, "publish", "--restore-generation", "4", "--target", "cos", "--config", program.configPath, "--workers", "2", "--chunk-entries", "64")
		publication := readRealCloudPublication(t, program.root, "cos")
		asset := assertRealCloudGatedPublication(t, program.environment, "cos", publication, publish.TargetTencent, 9)
		if publication.generation.ParentGeneration != 8 || publication.generation.IntentView != "stable" || asset.SHA256 != realCloudLowerSHA256(program.gatedBodies[0]) {
			t.Fatalf("COS restore publication=%#v asset=%s", publication.generation, asset.SHA256)
		}
		assertRealCloudGatedVendorBody(t, "edgeone", program.environment.COSCDNBase, program.environment, program.secretFragments, program.gatedBodies[0])
		return realCloudPublicationResult(publication)
	})

	program.stepWithBaselines("restore-noop-replays", []string{"publish", "restore-generation=4", "cf", "cos", "expect=unchanged"}, "@provider",
		program.publicationBaselines("cf", "cos"), func() any {
			result := make(map[string]string, 2)
			for _, target := range []string{"cf", "cos"} {
				before := readRealCloudPublication(t, program.root, target)
				output := program.runCLI(cli.ExitOK, "publish", "--restore-generation", "4", "--target", target, "--config", program.configPath, "--workers", "2", "--chunk-entries", "64")
				if !strings.Contains(output, "status=unchanged") || !strings.Contains(output, "status=complete") {
					t.Fatalf("target %s historical restore replay was not an explicit no-op\n%s", target, output)
				}
				after := readRealCloudPublication(t, program.root, target)
				assertRealCloudReplayUnchanged(t, target, before, after)
				result[target] = realCloudLowerSHA256(after.checkpointBody)
			}
			return result
		})

	program.step("publish-current-stable-cf-g10", []string{"publish", "stable", "cf", "gated", "generation=10"}, "@provider", func() any {
		program.runCLI(cli.ExitOK, "publish", "--view", "stable", "--target", "cf", "--config", program.configPath,
			"--repo", realCloudGatedAssetRepoID, "--workers", "2", "--chunk-entries", "64")
		publication := readRealCloudPublication(t, program.root, "cf")
		asset := assertRealCloudGatedPublication(t, program.environment, "cf", publication, publish.TargetCloudflare, 10)
		if asset.SHA256 != realCloudLowerSHA256(program.gatedBodies[2]) {
			t.Fatal("R2 generation 10 did not restore current gated bytes")
		}
		return realCloudPublicationResult(publication)
	})

	program.step("publish-current-stable-cos-g10", []string{"publish", "stable", "cos", "gated", "generation=10"}, "@provider", func() any {
		program.runCLI(cli.ExitOK, "publish", "--view", "stable", "--target", "cos", "--config", program.configPath,
			"--repo", realCloudGatedAssetRepoID, "--workers", "2", "--chunk-entries", "64")
		publication := readRealCloudPublication(t, program.root, "cos")
		asset := assertRealCloudGatedPublication(t, program.environment, "cos", publication, publish.TargetTencent, 10)
		if asset.SHA256 != realCloudLowerSHA256(program.gatedBodies[2]) {
			t.Fatal("COS generation 10 did not restore current gated bytes")
		}
		return realCloudPublicationResult(publication)
	})

	program.step("verify-g10-cache", []string{"cache-phase-v3", "generation=10"}, "@provider", func() any {
		assertRealCloudGatedCachePhase(t, program.environment, program.secretFragments, program.gatedBodies[2])
		return map[string]string{"gated_v3_sha256": realCloudLowerSHA256(program.gatedBodies[2])}
	})

	program.stepFacts("final-fsck", []string{"fsck", "cf", "cos", "limit=20", "expect=repos=4,targets=2", "provider-log-v3-exact-request-closure", "provider-log-seal"}, "@provider", func() (any, func(*realCloudResumeFacts) error) {
		facts := program.ledger.Snapshot().Facts
		if err := rebuildAndValidateRealCloudSnapshotCatalog(t.Context(), program.root, facts.RecentSnapshotID, facts.ExpiredSnapshotID); err != nil {
			t.Fatalf("final canonical/SQLite snapshot closure: %v", err)
		}
		output := program.runCLI(cli.ExitOK, "fsck", "--config", program.configPath, "--target", "cf", "--target", "cos", "--limit", "20", "--workers", "2", "--chunk-entries", "64")
		if !strings.Contains(output, "fsck clean repos=4 targets=2") {
			t.Fatalf("real-cloud full inventory audit was not clean\n%s", output)
		}
		closure, err := collectRealCloudProviderClosure(program.root, program.artifactPath, program.providerLogPath, program.secretFragments, program.identity.RunID)
		if err != nil {
			t.Fatalf("provider logs are not yet one exact sealed active request-set closure: %v", err)
		}
		if closure.ProviderLogPathSHA256 != program.ledger.Snapshot().Binding.ProviderLogPathSHA256 {
			t.Fatal("provider-log closure path differs from the persistent run binding")
		}
		return map[string]any{"output_sha256": realCloudLowerSHA256([]byte(output)), "provider_closure": closure}, func(facts *realCloudResumeFacts) error {
			value := closure
			facts.ProviderClosure = &value
			return validateRealCloudResumeFacts(*facts)
		}
	})
}

func recoverRealCloudSnapshotCanonicalMutation(ctx context.Context, root string) error {
	statePath := filepath.Join(root, config.StateDirectory)
	lock, err := state.AcquireLock(statePath, "real-cloud-snapshot-reconcile", true)
	if err != nil {
		return err
	}
	_, recoverErr := state.New(statePath).Recover(ctx)
	if recoverErr == nil {
		_, recoverErr = rebuildAndValidateRealCloudCatalogHead(ctx, root)
	}
	return errors.Join(recoverErr, lock.Release())
}

// discoverRealCloudCurrentSnapshot recovers only the unique immutable current
// snapshot created in this private run workspace. The separately frozen expiry
// fixture is excluded. A matching ref must contain bytes identical to the
// current stable YUM leaf; ambiguity or a divergent candidate fails closed.
func discoverRealCloudCurrentSnapshot(root, expiredSnapshotID string) (string, bool, error) {
	canonical := state.New(filepath.Join(root, config.StateDirectory))
	stableRef, err := state.ViewRef("stable", realCloudYUMRepositoryID, "el10", "x86_64")
	if err != nil {
		return "", false, err
	}
	stableCommit, exists, err := canonical.Ref(stableRef)
	if err != nil || !exists {
		return "", false, errors.Join(err, errors.New("stable YUM ref is absent during snapshot recovery"))
	}
	stablePath, err := state.ViewPath("stable", realCloudYUMRepositoryID, "el10", "x86_64")
	if err != nil {
		return "", false, err
	}
	stableBody, err := readRealCloudCanonicalPathAt(canonical, stableCommit, stablePath)
	if err != nil {
		return "", false, err
	}
	refs, err := canonical.SOWRefs()
	if err != nil {
		return "", false, err
	}
	const prefix = "refs/sow/snapshots/"
	const suffix = "/" + realCloudYUMRepositoryID + "/el10/x86_64"
	var current string
	for _, record := range refs {
		name := record.Name.String()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
			continue
		}
		snapshotID := strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix)
		if snapshotID == expiredSnapshotID {
			continue
		}
		suite, suiteErr := views.SnapshotSuite(snapshotID)
		if suiteErr != nil || suite != "el10" {
			return "", false, fmt.Errorf("snapshot recovery candidate %q is invalid", snapshotID)
		}
		candidatePath, pathErr := state.SnapshotPath(snapshotID, realCloudYUMRepositoryID, "el10", "x86_64")
		if pathErr != nil {
			return "", false, pathErr
		}
		candidateBody, readErr := readRealCloudCanonicalPathAt(canonical, record.Hash, candidatePath)
		if readErr != nil || !bytes.Equal(candidateBody, stableBody) {
			return "", false, errors.Join(readErr, fmt.Errorf("snapshot recovery candidate %q differs from stable", snapshotID))
		}
		if current != "" && current != snapshotID {
			return "", false, fmt.Errorf("snapshot recovery is ambiguous between %q and %q", current, snapshotID)
		}
		current = snapshotID
	}
	return current, current != "", nil
}

func TestRealCloudObserverTopologyBindingExcludesRotatingCredentials(t *testing.T) {
	values := map[string]string{
		realEdgeObserversEnv:    `[{"id":"egress-a","proxy_env":"SOW_REAL_EDGE_PROXY_A"},{"id":"egress-b","proxy_env":"SOW_REAL_EDGE_PROXY_B"}]`,
		"SOW_REAL_EDGE_PROXY_A": "https://first-user:first-secret@Proxy-A.Example:8443",
		"SOW_REAL_EDGE_PROXY_B": "socks5://second-user:second-secret@[2001:db8::1]:1080",
	}
	lookup := func(source map[string]string) func(string) string {
		return func(name string) string { return source[name] }
	}
	first, err := realCloudObserverTopologyBindingFrom(lookup(values))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"first-user", "first-secret", "second-user", "second-secret"} {
		if bytes.Contains(first, []byte(secret)) {
			t.Fatalf("topology binding leaked proxy secret %q: %s", secret, first)
		}
	}
	rotated := mapsCloneString(values)
	rotated["SOW_REAL_EDGE_PROXY_A"] = "https://rotated-user:rotated-secret@proxy-a.example:8443"
	rotated["SOW_REAL_EDGE_PROXY_B"] = "socks5://new-user:new-secret@[2001:db8::1]:1080"
	second, err := realCloudObserverTopologyBindingFrom(lookup(rotated))
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("credential rotation changed physical topology first=%s second=%s err=%v", first, second, err)
	}
	for name, mutate := range map[string]func(map[string]string){
		"host":   func(v map[string]string) { v["SOW_REAL_EDGE_PROXY_A"] = "https://u:p@proxy-other.example:8443" },
		"port":   func(v map[string]string) { v["SOW_REAL_EDGE_PROXY_A"] = "https://u:p@proxy-a.example:9443" },
		"scheme": func(v map[string]string) { v["SOW_REAL_EDGE_PROXY_A"] = "socks5://u:p@proxy-a.example:8443" },
		"observer": func(v map[string]string) {
			v[realEdgeObserversEnv] = `[{"id":"egress-c","proxy_env":"SOW_REAL_EDGE_PROXY_A"},{"id":"egress-b","proxy_env":"SOW_REAL_EDGE_PROXY_B"}]`
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := mapsCloneString(values)
			mutate(changed)
			body, err := realCloudObserverTopologyBindingFrom(lookup(changed))
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(first, body) {
				t.Fatal("physical topology mutation did not change binding")
			}
		})
	}
	noPort := mapsCloneString(values)
	noPort["SOW_REAL_EDGE_PROXY_A"] = "https://u:p@proxy-a.example"
	if _, err := realCloudObserverTopologyBindingFrom(lookup(noPort)); err == nil {
		t.Fatal("proxy endpoint without an explicit port was accepted")
	}
	if !bytes.Contains(first, []byte(`socks5://[2001:db8::1]:1080`)) {
		t.Fatalf("IPv6 endpoint was not canonically bracketed: %s", first)
	}
}

func TestRealCloudInterruptedPublicationEntryStates(t *testing.T) {
	parent := publish.Checkpoint{Target: publish.TargetCloudflare, Generation: 4, ParentGeneration: 3, IntentView: "stable", Phase: publish.PhaseCheckpointCommitted}
	if err := validateRealCloudInterruptedPublicationEntry(parent, publish.TargetCloudflare, 5, 4); err != nil {
		t.Fatalf("parent-committed state rejected: %v", err)
	}
	locked := publish.Checkpoint{Target: publish.TargetCloudflare, Generation: 5, ParentGeneration: 4, IntentView: "stable", Phase: publish.PhaseLocked}
	if err := validateRealCloudInterruptedPublicationEntry(locked, publish.TargetCloudflare, 5, 4); err != nil {
		t.Fatalf("expected locked state rejected: %v", err)
	}
	committed := locked
	committed.Phase = publish.PhaseCheckpointCommitted
	if err := validateRealCloudInterruptedPublicationEntry(committed, publish.TargetCloudflare, 5, 4); err == nil || !strings.Contains(err.Error(), "proof was skipped") {
		t.Fatalf("already-committed interrupted generation err=%v", err)
	}
	wrongTarget := locked
	wrongTarget.Target = publish.TargetTencent
	if err := validateRealCloudInterruptedPublicationEntry(wrongTarget, publish.TargetCloudflare, 5, 4); err == nil {
		t.Fatal("locked state for another target was accepted")
	}
	wrongView := parent
	wrongView.IntentView = "latest"
	if err := validateRealCloudInterruptedPublicationEntry(wrongView, publish.TargetCloudflare, 5, 4); err == nil {
		t.Fatal("parent committed state for another view was accepted")
	}
}

func TestRealCloudProviderClosureRemainsBlockedWithoutAPIAttestation(t *testing.T) {
	_, err := validateRealCloudProviderAPIAttestedRawClosure(t.Context(), nil, nil, nil)
	if !errors.Is(err, errRealCloudProviderAPIAttestationRequired) {
		t.Fatalf("unattested operator evidence unexpectedly closes acceptance: %v", err)
	}
}

func mapsCloneString(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func TestRealCloudRuntimeSecretRegistryCrashWindows(t *testing.T) {
	t.Run("normal-and-action-error-cleanup", func(t *testing.T) {
		for _, actionErr := range []error{nil, errors.New("action failed")} {
			root := filepath.Join(t.TempDir(), "workspace")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			var tokenPath string
			var reports []error
			err := withRegisteredRealCloudRuntimeToken(root, "a", "secret-value", func(path string) error {
				tokenPath = path
				if filepath.Dir(path) != root+realCloudSecretScratchSuffix {
					t.Fatalf("runtime token path %q is not in sibling scratch", path)
				}
				relative, err := filepath.Rel(root, path)
				if err != nil || !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
					t.Fatalf("runtime token unexpectedly resides inside workspace relative=%q err=%v", relative, err)
				}
				body, err := os.ReadFile(path)
				if err != nil || string(body) != "secret-value\n" {
					t.Fatalf("runtime token body=%q err=%v", body, err)
				}
				return actionErr
			}, func(err error) { reports = append(reports, err) })
			if !errors.Is(err, actionErr) || len(reports) != 0 {
				t.Fatalf("action result err=%v want=%v cleanup_reports=%v", err, actionErr, reports)
			}
			for _, path := range []string{tokenPath, filepath.Join(root+realCloudSecretScratchSuffix, realCloudSecretRegistryName)} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("cleanup left %s: %v", path, err)
				}
			}
		}
	})

	for name, written := range map[string][]byte{"registry-before-bytes": nil, "partial-secret": []byte("secret"), "complete-secret": []byte("secret-value\n")} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "workspace")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			file, err := createRegisteredRealCloudRuntimeSecretFile(root, "a", len("secret-value\n"))
			if err != nil {
				t.Fatal(err)
			}
			path := file.Name()
			registryPath := filepath.Join(root+realCloudSecretScratchSuffix, realCloudSecretRegistryName)
			if _, err := os.Lstat(registryPath); err != nil {
				t.Fatalf("registry was not installed before secret bytes: %v", err)
			}
			if len(written) > 0 {
				if _, err := file.Write(written); err != nil {
					t.Fatal(err)
				}
				if err := file.Sync(); err != nil {
					t.Fatal(err)
				}
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			witness, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer witness.Close()
			if err := recoverRealCloudSecretScratch(root); err != nil {
				t.Fatal(err)
			}
			if _, err := witness.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			remaining, err := io.ReadAll(witness)
			if err != nil || len(remaining) != 0 {
				t.Fatalf("recovered secret inode was not scrubbed and truncated body=%q err=%v", remaining, err)
			}
			for _, removed := range []string{path, registryPath} {
				if _, err := os.Lstat(removed); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("recovery left %s: %v", removed, err)
				}
			}
		})
	}

	t.Run("orphan-registry-temp-and-zero-token", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "workspace")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		scratch := root + realCloudSecretScratchSuffix
		if err := ensureRealCloudSecretScratchDirectory(scratch); err != nil {
			t.Fatal(err)
		}
		paths := []string{
			filepath.Join(scratch, ".sow-real-cloud-secret-registry-killed.tmp"),
			filepath.Join(scratch, ".sow-real-cloud-pro-token-a-killed"),
		}
		if err := os.WriteFile(paths[0], []byte("partial registry metadata"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(paths[1], nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := recoverRealCloudSecretScratch(root); err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("orphan %s remains: %v", path, err)
			}
		}
	})

	t.Run("token-removed-before-registry", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "workspace")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		file, err := createRegisteredRealCloudRuntimeSecretFile(root, "b", 8)
		if err != nil {
			t.Fatal(err)
		}
		path := file.Name()
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := recoverRealCloudSecretScratch(root); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(filepath.Join(root+realCloudSecretScratchSuffix, realCloudSecretRegistryName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stale registry remains: %v", err)
		}
	})

	t.Run("foreign-nonempty-and-symlink-fail-closed", func(t *testing.T) {
		for name, install := range map[string]func(string) error{
			"nonempty": func(path string) error { return os.WriteFile(path, []byte("must-preserve"), 0o600) },
			"symlink":  func(path string) error { return os.Symlink(filepath.Join(filepath.Dir(path), "missing-target"), path) },
		} {
			t.Run(name, func(t *testing.T) {
				root := filepath.Join(t.TempDir(), "workspace")
				if err := os.Mkdir(root, 0o700); err != nil {
					t.Fatal(err)
				}
				scratch := root + realCloudSecretScratchSuffix
				if err := ensureRealCloudSecretScratchDirectory(scratch); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(scratch, ".sow-real-cloud-pro-token-a-foreign")
				if err := install(path); err != nil {
					t.Fatal(err)
				}
				if err := recoverRealCloudSecretScratch(root); err == nil {
					t.Fatal("unsafe unregistered entry was removed instead of failing closed")
				}
				if _, err := os.Lstat(path); err != nil {
					t.Fatalf("unsafe entry was not preserved: %v", err)
				}
			})
		}
	})

	t.Run("inode-replacement-preserved", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "workspace")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		file, err := createRegisteredRealCloudRuntimeSecretFile(root, "a", 8)
		if err != nil {
			t.Fatal(err)
		}
		path := file.Name()
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		replacement := []byte("foreign-replacement")
		if err := os.WriteFile(path, replacement, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := recoverRealCloudSecretScratch(root); err == nil || !strings.Contains(err.Error(), "inode identity changed") {
			t.Fatalf("replacement inode recovery err=%v", err)
		}
		body, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(body, replacement) {
			t.Fatalf("replacement inode changed body=%q err=%v", body, err)
		}
		if _, err := os.Lstat(filepath.Join(root+realCloudSecretScratchSuffix, realCloudSecretRegistryName)); err != nil {
			t.Fatalf("failed-closed registry was removed: %v", err)
		}
	})
}

func readRealCloudCanonicalPathAt(canonical *state.Store, commit plumbing.Hash, path string) ([]byte, error) {
	reader, err := canonical.OpenPathAt(commit, path)
	if err != nil {
		return nil, err
	}
	body, readErr := io.ReadAll(reader)
	return body, errors.Join(readErr, reader.Close())
}

func ensureRealCloudHistoricalSnapshot(t *testing.T, root, currentSnapshotID, historicalSnapshotID string) {
	t.Helper()
	canonical := state.New(filepath.Join(root, config.StateDirectory))
	historicalRef, err := state.SnapshotRef(historicalSnapshotID, realCloudYUMRepositoryID, "el10", "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	historicalCommit, exists, err := canonical.Ref(historicalRef)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		seedRealCloudHistoricalSnapshot(t, root, currentSnapshotID, historicalSnapshotID)
		return
	}
	currentRef, _ := state.SnapshotRef(currentSnapshotID, realCloudYUMRepositoryID, "el10", "x86_64")
	currentCommit, currentExists, err := canonical.Ref(currentRef)
	if err != nil || !currentExists {
		t.Fatalf("current snapshot ref missing during historical recovery: %v", err)
	}
	currentPath, _ := state.SnapshotPath(currentSnapshotID, realCloudYUMRepositoryID, "el10", "x86_64")
	historicalPath, _ := state.SnapshotPath(historicalSnapshotID, realCloudYUMRepositoryID, "el10", "x86_64")
	current, err := canonical.OpenPathAt(currentCommit, currentPath)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	historical, err := canonical.OpenPathAt(historicalCommit, historicalPath)
	if err != nil {
		t.Fatal(err)
	}
	defer historical.Close()
	currentBody, currentErr := io.ReadAll(current)
	historicalBody, historicalErr := io.ReadAll(historical)
	if currentErr != nil || historicalErr != nil || !bytes.Equal(currentBody, historicalBody) {
		t.Fatal("existing historical snapshot fixture differs from the current canonical YUM leaf")
	}
	if err := rebuildAndValidateRealCloudSnapshotCatalog(t.Context(), root, currentSnapshotID, historicalSnapshotID); err != nil {
		t.Fatalf("rebuild recovered historical snapshot catalog closure: %v", err)
	}
}

func (program *realCloudAcceptanceProgram) cleanupSnapshotCopyProbe(target string, evidence realCloudPublication) {
	program.t.Helper()
	var planned publish.PlannedObject
	for _, object := range evidence.plan.Objects {
		if object.Class == publish.ObjectCopyImmutable && object.CopySource != "" {
			planned = object
			break
		}
	}
	if planned.RemoteKey == "" {
		program.t.Fatalf("target %s snapshot plan has no copy probe candidate", target)
	}
	probeDigest := realCloudLowerSHA256([]byte(target + "\x00" + evidence.checkpoint.TransactionID + "\x00" + evidence.generation.IntentSnapshot + "\x00" + planned.RemoteKey))
	probeKey := ".sow/probes/server-side-copy/" + target + "/" + probeDigest
	r2, cos := newRealCloudProviders(program.t, program.environment)
	var err error
	if target == "cf" {
		err = cleanupRealCloudCopyProbe(program.t.Context(), probeKey, planned.Size, planned.SHA256, "", r2.R2Head, r2.R2OpenObject, r2.R2DeleteCheckpointFenced)
	} else {
		err = cleanupRealCloudCopyProbe(program.t.Context(), probeKey, planned.Size, planned.SHA256, "", cos.COSHead, cos.COSOpenObject, cos.COSDeleteCheckpointFenced)
	}
	assertRealCloudProviderErrorSafe(program.t, target+" stale copy probe cleanup", err, program.secretFragments)
	if err != nil {
		program.t.Fatalf("target %s stale copy probe could not be safely reconciled", target)
	}
}

func realCloudPublicationResult(publication realCloudPublication) map[string]any {
	return map[string]any{
		"target": publication.checkpoint.Target, "generation": publication.checkpoint.Generation,
		"transaction":       publication.checkpoint.TransactionID,
		"generation_sha256": realCloudLowerSHA256(publication.generationBody),
		"checkpoint_sha256": realCloudLowerSHA256(publication.checkpointBody),
		"plan_sha256":       realCloudLowerSHA256(publication.planBody),
	}
}

func readRequiredFile(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
