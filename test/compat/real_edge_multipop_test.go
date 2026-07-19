package compat_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/pgsty/sow/internal/publish"
	"golang.org/x/sys/unix"
)

const (
	realEdgeObserversEnv          = "SOW_REAL_EDGE_OBSERVERS_JSON"
	realEdgeActiveArtifactEnv     = "SOW_REAL_EDGE_ACTIVE_OBSERVATIONS_JSONL"
	realEdgeProviderLogEnv        = "SOW_REAL_EDGE_PROVIDER_LOG_JSONL"
	realEdgeEvidenceOptInEnv      = "SOW_RUN_REAL_EDGE_EVIDENCE"
	realEdgeEvidenceForbiddenEnv  = "SOW_REAL_EDGE_EVIDENCE_FORBIDDEN_JSON"
	realEdgeRunLockSuffix         = ".run-lock"
	realEdgeProxyEnvPrefix        = "SOW_REAL_EDGE_PROXY_"
	realEdgeMaxObservers          = 8
	realEdgeMaxObserverJSONBytes  = 16 << 10
	realEdgeMaxProxyURLBytes      = 4 << 10
	realEdgeMaxProviderLogBytes   = 2 << 20
	realEdgeMaxProviderLogLine    = 64 << 10
	realEdgeMaxProviderLogRecords = 4096
	realEdgeResponseLimit         = 1 << 20
	realEdgeProviderClockSkew     = 30 * time.Second
	realEdgeProviderExportLag     = 5 * time.Minute
	realEdgeCacheFreshnessMargin  = 1 * time.Second
)

var errRealEdgeProviderLogsIncomplete = errors.New("real edge provider logs are incomplete")

type realEdgeObserverSpec struct {
	ID       string `json:"id"`
	ProxyEnv string `json:"proxy_env"`
}

type realEdgeObserver struct {
	ID       string
	ProxyEnv string
	proxyURL *url.URL
	proxyRaw string
}

type realEdgeMultiPoPObservation struct {
	Vendor           string
	Role             string
	ObserverID       string
	RequestID        string
	CloudflareColo   string
	CacheStatus      string
	Transport        string
	CleanURLSHA256   string
	BodySHA256       string
	CacheAgeSeconds  int64
	CacheMaxAge      int64
	RequestStarted   time.Time
	ResponseObserved time.Time
}

type realEdgeProviderLog struct {
	// Schema identifies a collector-normalized join, not one raw provider
	// event. RequestID is the child/subrequest identity and ParentRequestID must
	// equal the visitor-facing ID captured from CF-Ray or EO-LOG-UUID. For
	// Cloudflare the collector joins main RayID/EdgeColo fields with Worker
	// subrequest RayID/ParentRayID/CacheCacheStatus. For EdgeOne it joins main
	// RequestID/EdgeServer fields with function-subrequest
	// RequestID/ParentRequestID/EdgeCacheStatus.
	Schema          string `json:"schema"`
	RunID           string `json:"run_id"`
	ProbePhase      string `json:"probe_phase"`
	Vendor          string `json:"vendor"`
	RequestID       string `json:"request_id"`
	ParentRequestID string `json:"parent_request_id"`
	NodeID          string `json:"node_id"`
	NodeIP          string `json:"node_ip"`
	Region          string `json:"region"`
	CacheStatus     string `json:"cache_status"`
	CleanURLSHA256  string `json:"clean_url_sha256"`
	BodySHA256      string `json:"body_sha256"`
	Generation      uint64 `json:"generation"`
	TransactionID   string `json:"transaction_id"`
	ObservedAt      string `json:"observed_at"`

	observedTime time.Time
}

type realEdgeMultiPoPVendorStage struct {
	RunID               string
	ConfirmationSHA256  string
	ConfigSHA256        string
	GenerationSHA256    string
	CheckpointSHA256    string
	Vendor              string
	Generation          uint64
	TransactionID       string
	CommittedObservedAt time.Time
	CleanURLSHA256      string
	BodySHA256          string
	Observations        []realEdgeMultiPoPObservation
	PrePurge            *realEdgePrePurgeVendorEvidence
}

type realEdgePrePurgeVendorEvidence struct {
	Generation     uint64
	TransactionID  string
	CleanURLSHA256 string
	BodySHA256     string
	Observations   []realEdgeMultiPoPObservation
}

type realEdgeMultiPoPStageEvidence struct {
	Vendors           map[string]realEdgeMultiPoPVendorStage
	ProviderLogs      []realEdgeProviderLog
	EntitlementSHA256 []string
}

type realEdgeActiveArtifactRecord struct {
	Schema              string                              `json:"schema"`
	RunID               string                              `json:"run_id"`
	ConfirmationSHA256  string                              `json:"confirmation_sha256"`
	ConfigSHA256        string                              `json:"config_sha256"`
	GenerationSHA256    string                              `json:"generation_sha256"`
	CheckpointSHA256    string                              `json:"checkpoint_sha256"`
	Vendor              string                              `json:"vendor"`
	Generation          uint64                              `json:"generation"`
	TransactionID       string                              `json:"transaction_id"`
	CommittedObservedAt string                              `json:"committed_observed_at"`
	CleanURLSHA256      string                              `json:"clean_url_sha256"`
	BodySHA256          string                              `json:"body_sha256"`
	EntitlementSHA256   []string                            `json:"entitlement_sha256"`
	Observations        []realEdgeActiveArtifactObservation `json:"observations"`
	PrePurge            *realEdgeActivePrePurgeRecord       `json:"pre_purge,omitempty"`
}

type realEdgeActivePrePurgeRecord struct {
	Generation     uint64                              `json:"generation"`
	TransactionID  string                              `json:"transaction_id"`
	CleanURLSHA256 string                              `json:"clean_url_sha256"`
	BodySHA256     string                              `json:"body_sha256"`
	Observations   []realEdgeActiveArtifactObservation `json:"observations"`
}

type realEdgeActiveArtifactObservation struct {
	Role             string `json:"role"`
	ObserverID       string `json:"observer_id"`
	RequestID        string `json:"request_id"`
	CloudflareColo   string `json:"cloudflare_colo,omitempty"`
	CacheStatus      string `json:"cache_status"`
	Transport        string `json:"transport"`
	CleanURLSHA256   string `json:"clean_url_sha256"`
	BodySHA256       string `json:"body_sha256"`
	CacheAgeSeconds  int64  `json:"cache_age_seconds"`
	CacheMaxAge      int64  `json:"cache_max_age_seconds"`
	RequestStarted   string `json:"request_started"`
	ResponseObserved string `json:"response_observed"`
}

type realEdgeProviderLogSeal struct {
	Schema string `json:"schema"`
	RunID  string `json:"run_id"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type realEdgeActiveArtifactSeal struct {
	Schema string `json:"schema"`
	RunID  string `json:"run_id"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// assertRealCloudEdgeMultiPoPPreflight must run before the destructive
// real-cloud acceptance performs any remote mutation. It validates every
// observer/proxy indirection and proves a new external artifact can be created
// safely, while refusing to overwrite prior evidence or a stale writer lock.
func assertRealCloudEdgeMultiPoPPreflight(t *testing.T, environment realCloudEnvironment, runIdentity realCloudRunIdentity, forbidden []string) {
	t.Helper()
	if err := preflightRealCloudEdgeMultiPoPInputs(os.Getenv); err != nil {
		t.Fatalf("real edge multi-PoP preflight: %v", err)
	}
	artifactPath := strings.TrimSpace(os.Getenv(realEdgeActiveArtifactEnv))
	release, err := acquireRealEdgeRunReservation(artifactPath, runIdentity.RunID)
	if err != nil {
		t.Fatalf("reserve real edge multi-PoP run: %v", err)
	}
	t.Cleanup(func() {
		if err := release(); err != nil {
			t.Errorf("release real edge multi-PoP run reservation: %v", err)
		}
	})
	observers, err := loadRealEdgeObservers(os.Getenv)
	if err != nil {
		t.Fatalf("reload real edge observer set after reservation: %v", err)
	}
	if err := preflightRealEdgeObserverConnectivity(t.Context(), observers, environment, forbidden); err != nil {
		t.Fatalf("real edge observer connectivity preflight: %v", err)
	}
}

// preflightRealEdgeObserverConnectivity is the last read-only gate before the
// destructive acceptance may touch either bucket. Every configured egress
// proves proxy authentication, CONNECT/SOCKS transport, end-to-end TLS, and
// the deployed constant anonymous denial contract against both vendors. The
// clean gated URL contains no entitlement and cannot mutate provider state.
func preflightRealEdgeObserverConnectivity(ctx context.Context, observers []realEdgeObserver, environment realCloudEnvironment, forbidden []string) error {
	vendors := []struct {
		name string
		base string
	}{
		{name: "cloudflare", base: environment.CFCDNBase},
		{name: "edgeone", base: environment.COSCDNBase},
	}
	for _, observer := range observers {
		observerForbidden := append(append([]string(nil), forbidden...), realEdgeObserverSecretFragments(observer)...)
		for _, vendor := range vendors {
			if err := requestRealEdgeAnonymousPreflight(ctx, observer, vendor.base, observerForbidden); err != nil {
				return fmt.Errorf("observer %s cannot prove %s anonymous denial: %w", observer.ID, vendor.name, err)
			}
		}
	}
	return nil
}

func requestRealEdgeAnonymousPreflight(ctx context.Context, observer realEdgeObserver, baseURL string, forbidden []string) error {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" {
		return errors.New("edge preflight base is not one clean HTTPS origin")
	}
	target := *parsed
	target.Path = "/.sow/gated/" + realCloudGatedAssetPath
	target.RawPath = ""

	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return errors.New("default HTTP transport is not safely cloneable")
	}
	transport := defaultTransport.Clone()
	transport.Proxy = http.ProxyURL(observer.proxyURL)
	transport.DisableKeepAlives = true
	transport.ForceAttemptHTTP2 = true
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer transport.CloseIdleConnections()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return errors.New("construct anonymous edge preflight request")
	}
	request.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(request)
	if err != nil {
		// Proxy implementations may echo credential-bearing proxy URLs in error
		// text, so the underlying error is intentionally not returned.
		return errors.New("proxy transport failed")
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, realEdgeResponseLimit+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(body) > realEdgeResponseLimit {
		return errors.New("anonymous edge preflight response was not safely readable")
	}
	if response.TLS == nil || response.Request == nil || response.Request.URL.Scheme != "https" || response.Request.URL.Host != target.Host {
		return errors.New("anonymous edge preflight did not retain end-to-end target TLS")
	}
	if realEdgeResponseContainsForbidden(response.Header, response.Trailer, body, forbidden) {
		return errors.New("anonymous edge preflight exposed secret material")
	}
	evidence := realCloudEdgeResponse{
		status:       response.StatusCode,
		edgeContract: response.Header.Get("X-SOW-Edge-Contract"),
		body:         append([]byte(nil), body...),
		headers:      response.Header.Clone(),
	}
	if err := validateRealCloudAnonymousGatedResponse(evidence, []byte("sow-real-edge-preflight-protected-sentinel")); err != nil {
		return err
	}
	return nil
}

func preflightRealCloudEdgeMultiPoPInputs(getenv func(string) string) error {
	if _, err := loadRealEdgeObservers(getenv); err != nil {
		return err
	}
	artifactPath := strings.TrimSpace(getenv(realEdgeActiveArtifactEnv))
	canonicalArtifactPath, err := canonicalRealEdgeExternalPath(artifactPath, realEdgeActiveArtifactEnv)
	if err != nil {
		return err
	}
	artifactPath = canonicalArtifactPath
	for _, candidate := range []string{artifactPath, artifactPath + ".seal", artifactPath + ".lock", artifactPath + realEdgeRunLockSuffix} {
		if _, err := os.Lstat(candidate); err == nil {
			return fmt.Errorf("%s must not already exist", filepath.Base(candidate))
		} else if !errors.Is(err, os.ErrNotExist) {
			return errors.New("active artifact destination cannot be safely inspected")
		}
	}
	directory := filepath.Dir(artifactPath)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("active artifact parent must be an existing non-symlink directory")
	}
	probe, err := os.CreateTemp(directory, ".sow-real-edge-preflight-*.tmp")
	if err != nil {
		return errors.New("active artifact parent is not writable")
	}
	probePath := probe.Name()
	cleanup := func() {
		if probePath != "" {
			_ = os.Remove(probePath)
		}
	}
	defer cleanup()
	if err := probe.Chmod(0o600); err != nil {
		probe.Close()
		return errors.New("active artifact parent cannot secure a temporary file")
	}
	if _, err := probe.WriteString("sow-real-edge-preflight/v1\n"); err != nil {
		probe.Close()
		return errors.New("active artifact parent cannot write a temporary file")
	}
	if err := probe.Sync(); err != nil {
		probe.Close()
		return errors.New("active artifact parent cannot sync a temporary file")
	}
	if err := probe.Close(); err != nil {
		return errors.New("active artifact parent cannot close a temporary file")
	}
	if err := os.Remove(probePath); err != nil {
		return errors.New("active artifact parent cannot remove a temporary file")
	}
	probePath = ""
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return errors.New("active artifact parent cannot be opened for sync")
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return errors.New("active artifact parent cannot be synced")
	}
	return nil
}

// TestRealCloudEdgeMultiPoPEvidenceAcceptance is deliberately separate from
// the destructive, empty-bucket real-cloud transaction. An external provider
// log exporter may finish after the transaction exits; this read-only test can
// then correlate those logs without rerunning or mutating either cloud.
func TestRealCloudEdgeMultiPoPEvidenceAcceptance(t *testing.T) {
	if os.Getenv(realEdgeEvidenceOptInEnv) != "1" {
		t.Skip("set SOW_RUN_REAL_EDGE_EVIDENCE=1 after provider logs have been exported")
	}
	runID := strings.TrimSpace(os.Getenv(realCloudRunIDEnv))
	if !validRealCloudRunID(runID) {
		t.Fatalf("%s must identify the exact destructive run whose logs are being accepted", realCloudRunIDEnv)
	}
	forbidden, err := loadRealEdgeEvidenceForbidden(os.Getenv)
	if err != nil {
		t.Fatalf("load evidence forbidden fragments: %v", err)
	}
	artifactPath := strings.TrimSpace(os.Getenv(realEdgeActiveArtifactEnv))
	records, err := loadRealEdgeSealedActiveArtifact(artifactPath, forbidden, runID)
	if err != nil {
		t.Fatalf("load active multi-PoP artifact: %v", err)
	}
	providerPath := strings.TrimSpace(os.Getenv(realEdgeProviderLogEnv))
	logs, err := loadRealEdgeProviderLogs(providerPath, forbidden)
	if err != nil {
		t.Fatalf("load provider multi-PoP logs: %v", err)
	}
	stages, err := pairRealEdgeArtifactStages(records, logs)
	if err != nil {
		t.Fatalf("pair active multi-PoP stages: %v", err)
	}
	if len(stages) != 2 {
		t.Fatalf("multi-PoP purge proof needs exactly the destructive harness stages 4 and 5, got %d", len(stages))
	}
	for index, generation := range []uint64{4, 5} {
		for _, vendor := range []string{"cloudflare", "edgeone"} {
			if stages[index].Vendors[vendor].Generation != generation {
				t.Fatalf("multi-PoP stage %d %s generation=%d, want %d", index+1, vendor, stages[index].Vendors[vendor].Generation, generation)
			}
		}
	}
	if err := validateRealEdgeProviderLogClosure(stages, logs, runID); err != nil {
		t.Fatalf("provider log export is not an exact closed evidence set: %v", err)
	}
	for index, stage := range stages {
		if err := validateRealEdgeMultiPoPStage(stage, forbidden); err != nil {
			t.Fatalf("validate active multi-PoP stage %d: %v", index+1, err)
		}
		for _, vendor := range []string{"cloudflare", "edgeone"} {
			if stage.Vendors[vendor].RunID != runID {
				t.Fatalf("stage %d %s belongs to run %q, want %q", index+1, vendor, stage.Vendors[vendor].RunID, runID)
			}
		}
	}
	if err := validateRealEdgeMultiPoPPurgeTransition(stages[len(stages)-2], stages[len(stages)-1]); err != nil {
		t.Fatalf("validate real edge purge transition: %v", err)
	}
	if _, err := validateRealCloudProviderAPIAttestedRawClosure(t.Context(), stages, logs, forbidden); err != nil {
		t.Fatalf("provider evidence remains an incomplete local correlation set: %v", err)
	}
	for _, vendor := range []string{"cloudflare", "edgeone"} {
		latest := stages[len(stages)-1].Vendors[vendor]
		t.Logf("%s multi-PoP evidence generation=%d transaction=%s body_sha256=%s observations=%d", vendor, latest.Generation, latest.TransactionID, latest.BodySHA256, len(latest.Observations))
	}
}

func validateRealEdgeProviderLogClosure(stages []realEdgeMultiPoPStageEvidence, logs []realEdgeProviderLog, runID string) error {
	if len(stages) != 2 || !validRealCloudRunID(runID) {
		return errors.New("provider log closure requires exactly two stages and one valid destructive run")
	}
	expected := make(map[string]struct{})
	addExpected := func(phase, vendor string, generation uint64, transaction string, observations []realEdgeMultiPoPObservation) error {
		for _, observation := range observations {
			key := realEdgeProviderClosureKey(phase, vendor, generation, transaction, observation.RequestID)
			if _, duplicate := expected[key]; duplicate {
				return errors.New("active evidence reused a provider parent request identity")
			}
			expected[key] = struct{}{}
		}
		return nil
	}
	for _, evidence := range stages {
		for _, vendor := range []string{"cloudflare", "edgeone"} {
			stage, exists := evidence.Vendors[vendor]
			if !exists {
				return fmt.Errorf("provider closure stage is missing %s", vendor)
			}
			if err := addExpected("stage", vendor, stage.Generation, stage.TransactionID, stage.Observations); err != nil {
				return err
			}
			if stage.PrePurge != nil {
				if err := addExpected("pre-purge", vendor, stage.PrePurge.Generation, stage.PrePurge.TransactionID, stage.PrePurge.Observations); err != nil {
					return err
				}
			}
		}
	}
	if len(logs) != len(expected) {
		return fmt.Errorf("provider log record count=%d, want exact active request set %d", len(logs), len(expected))
	}
	matched := make(map[string]struct{}, len(logs))
	children := make(map[string]struct{}, len(logs))
	parents := make(map[string]struct{}, len(logs))
	for _, record := range logs {
		if err := validateRealEdgeProviderLogShape(record); err != nil {
			return err
		}
		if record.RunID != runID {
			return errors.New("provider log record belongs to another destructive run")
		}
		key := realEdgeProviderClosureKey(record.ProbePhase, record.Vendor, record.Generation, record.TransactionID, record.ParentRequestID)
		if _, exists := expected[key]; !exists {
			return errors.New("provider log contains an extra or unknown phase/generation/transaction/parent record")
		}
		if _, duplicate := matched[key]; duplicate {
			return errors.New("provider log contains duplicate evidence for one active request")
		}
		matched[key] = struct{}{}
		if _, duplicate := children[record.RequestID]; duplicate {
			return errors.New("provider child request ID was reused across the sealed export")
		}
		children[record.RequestID] = struct{}{}
		if _, duplicate := parents[record.ParentRequestID]; duplicate {
			return errors.New("active parent request ID was reused across the sealed export")
		}
		parents[record.ParentRequestID] = struct{}{}
	}
	for requestID := range children {
		if _, collision := parents[requestID]; collision {
			return errors.New("provider child request ID collides with an active parent request ID")
		}
	}
	return nil
}

func realEdgeProviderClosureKey(phase, vendor string, generation uint64, transaction, parent string) string {
	return fmt.Sprintf("%s/%s/%020d/%s/%s", phase, vendor, generation, transaction, parent)
}

// captureRealCloudEdgeMultiPoPStage is the live POC-01 transaction entry
// point. It deliberately obtains all proxy material outside the repository.
// The first egress primes with token A; every other egress crosses the shared
// clean cache with token B and must observe HIT. It atomically appends a
// secret-free active artifact, but does not wait for asynchronous provider-log
// delivery and therefore does not claim multi-PoP proof by itself.
func captureRealCloudEdgeMultiPoPStage(
	t *testing.T,
	environment realCloudEnvironment,
	runIdentity realCloudRunIdentity,
	secretFragments []string,
	wanted []byte,
	cloudflarePublication realCloudPublication,
	edgeOnePublication realCloudPublication,
	prePurge map[string]realEdgePrePurgeVendorEvidence,
) realEdgeMultiPoPStageEvidence {
	t.Helper()
	observers, err := loadRealEdgeObservers(os.Getenv)
	if err != nil {
		t.Fatalf("load %s: %v", realEdgeObserversEnv, err)
	}
	if !validRealCloudEdgeToken(environment.EdgeProTokenA) || !validRealCloudEdgeToken(environment.EdgeProTokenB) || environment.EdgeProTokenA == environment.EdgeProTokenB {
		t.Fatalf("real edge multi-PoP probes require two distinct valid entitlement tokens")
	}

	allSecrets := append([]string(nil), secretFragments...)
	allSecrets = append(allSecrets, environment.EdgeProTokenA, environment.EdgeProTokenB)
	for _, observer := range observers {
		allSecrets = append(allSecrets, realEdgeObserverSecretFragments(observer)...)
	}

	evidence := realEdgeMultiPoPStageEvidence{
		Vendors: make(map[string]realEdgeMultiPoPVendorStage, 2),
		EntitlementSHA256: realEdgeEntitlementDigests(
			environment.EdgeProTokenA,
			environment.EdgeProTokenB,
		),
	}
	// This harness timestamp is captured only after both canonical checkpoints
	// have been read back as checkpoint-committed. Checkpoint.UpdatedAt is the
	// desired Git commit time and is intentionally not wall-clock publication
	// evidence.
	committedObservedAt := time.Now().UTC()
	inputs := []struct {
		vendor      string
		baseURL     string
		publication realCloudPublication
	}{
		{vendor: "cloudflare", baseURL: environment.CFCDNBase, publication: cloudflarePublication},
		{vendor: "edgeone", baseURL: environment.COSCDNBase, publication: edgeOnePublication},
	}
	for _, input := range inputs {
		stage, stageErr := realEdgeStageFromPublication(input.vendor, input.baseURL, wanted, input.publication, committedObservedAt, runIdentity)
		if stageErr != nil {
			t.Fatalf("%s multi-PoP stage identity: %v", input.vendor, stageErr)
		}
		if prior, exists := prePurge[input.vendor]; exists {
			copyPrior := prior
			copyPrior.Observations = append([]realEdgeMultiPoPObservation(nil), prior.Observations...)
			stage.PrePurge = &copyPrior
		}
		for index, observer := range observers {
			role, token := "cross-pop", environment.EdgeProTokenB
			if index == 0 {
				role, token = "prime", environment.EdgeProTokenA
			}
			observation, probeErr := requestRealEdgeMultiPoP(
				t.Context(), observer, input.vendor, input.baseURL, token, role, wanted, allSecrets,
			)
			if probeErr != nil {
				t.Fatalf("%s observer=%s role=%s multi-PoP probe failed: %v", input.vendor, observer.ID, role, probeErr)
			}
			stage.Observations = append(stage.Observations, observation)
		}
		evidence.Vendors[input.vendor] = stage
	}

	artifactPath := strings.TrimSpace(os.Getenv(realEdgeActiveArtifactEnv))
	if err := appendRealEdgeActiveArtifact(artifactPath, evidence, allSecrets); err != nil {
		t.Fatalf("write active multi-PoP artifact: %v", err)
	}
	return evidence
}

func captureRealCloudEdgePrePurge(
	t *testing.T,
	environment realCloudEnvironment,
	secretFragments []string,
	wanted []byte,
	before realEdgeMultiPoPStageEvidence,
) map[string]realEdgePrePurgeVendorEvidence {
	t.Helper()
	observers, err := loadRealEdgeObservers(os.Getenv)
	if err != nil {
		t.Fatalf("load %s for pre-purge proof: %v", realEdgeObserversEnv, err)
	}
	allSecrets := append([]string(nil), secretFragments...)
	allSecrets = append(allSecrets, environment.EdgeProTokenA, environment.EdgeProTokenB)
	for _, observer := range observers {
		allSecrets = append(allSecrets, realEdgeObserverSecretFragments(observer)...)
	}
	result := make(map[string]realEdgePrePurgeVendorEvidence, 2)
	for _, input := range []struct {
		vendor  string
		baseURL string
	}{{vendor: "cloudflare", baseURL: environment.CFCDNBase}, {vendor: "edgeone", baseURL: environment.COSCDNBase}} {
		prior, exists := before.Vendors[input.vendor]
		if !exists || len(prior.Observations) != len(observers) {
			t.Fatalf("%s pre-purge proof has no complete prior observer stage", input.vendor)
		}
		pre := realEdgePrePurgeVendorEvidence{
			Generation: prior.Generation, TransactionID: prior.TransactionID,
			CleanURLSHA256: prior.CleanURLSHA256, BodySHA256: prior.BodySHA256,
			Observations: make([]realEdgeMultiPoPObservation, 0, len(observers)),
		}
		for index, observer := range observers {
			observation, probeErr := requestRealEdgeMultiPoP(
				t.Context(), observer, input.vendor, input.baseURL, environment.EdgeProTokenB, "cross-pop", wanted, allSecrets,
			)
			if probeErr != nil {
				t.Fatalf("%s observer=%s pre-purge HIT failed: %v", input.vendor, observer.ID, probeErr)
			}
			observation.Role = prior.Observations[index].Role
			if observation.ObserverID != prior.Observations[index].ObserverID || observation.CacheAgeSeconds < 0 || observation.CacheMaxAge <= observation.CacheAgeSeconds {
				t.Fatalf("%s observer=%s pre-purge response lacks same-observer freshness evidence age=%d max_age=%d", input.vendor, observer.ID, observation.CacheAgeSeconds, observation.CacheMaxAge)
			}
			pre.Observations = append(pre.Observations, observation)
		}
		result[input.vendor] = pre
	}
	return result
}

// assertRealCloudEdgeMultiPoPStage retains the assertion-style name used by
// the real-cloud acceptance test. Completion here means the active probes and
// durable artifact succeeded; provider-log proof remains the responsibility of
// TestRealCloudEdgeMultiPoPEvidenceAcceptance.
func assertRealCloudEdgeMultiPoPStage(
	t *testing.T,
	environment realCloudEnvironment,
	runIdentity realCloudRunIdentity,
	secretFragments []string,
	wanted []byte,
	cloudflarePublication realCloudPublication,
	edgeOnePublication realCloudPublication,
	prePurge map[string]realEdgePrePurgeVendorEvidence,
) realEdgeMultiPoPStageEvidence {
	t.Helper()
	return captureRealCloudEdgeMultiPoPStage(t, environment, runIdentity, secretFragments, wanted, cloudflarePublication, edgeOnePublication, prePurge)
}

// assertRealCloudEdgeMultiPoPPurgeTransition is the active-only transaction
// guard. It proves new generation/transaction/body observations occurred after
// publish without claiming provider-confirmed PoP identity; the read-only
// evidence acceptance adds that stronger proof later.
func assertRealCloudEdgeMultiPoPPurgeTransition(t *testing.T, before, after realEdgeMultiPoPStageEvidence) {
	t.Helper()
	if err := validateRealEdgeActivePurgeTransition(before, after); err != nil {
		t.Fatalf("real edge multi-PoP purge transition: %v", err)
	}
}

func realEdgeStageFromPublication(vendor, baseURL string, wanted []byte, publication realCloudPublication, committedObservedAt time.Time, runIdentity realCloudRunIdentity) (realEdgeMultiPoPVendorStage, error) {
	if publication.checkpoint.Phase != publish.PhaseCheckpointCommitted {
		return realEdgeMultiPoPVendorStage{}, fmt.Errorf("checkpoint phase=%q, want %q", publication.checkpoint.Phase, publish.PhaseCheckpointCommitted)
	}
	if publication.checkpoint.Generation == 0 || publication.checkpoint.Generation != publication.generation.Generation {
		return realEdgeMultiPoPVendorStage{}, errors.New("checkpoint and generation identity do not match")
	}
	if !validRealEdgeTransactionID(publication.checkpoint.TransactionID) {
		return realEdgeMultiPoPVendorStage{}, errors.New("checkpoint transaction ID is invalid")
	}
	if committedObservedAt.IsZero() || committedObservedAt.Location() != time.UTC {
		return realEdgeMultiPoPVendorStage{}, errors.New("checkpoint committed observation time is invalid")
	}
	if runIdentity.Schema != "sow-real-cloud-run/v1" || !validRealCloudRunID(runIdentity.RunID) || !validRealCloudLowerSHA256(runIdentity.ConfirmationSHA256) || !validRealCloudLowerSHA256(runIdentity.ConfigSHA256) {
		return realEdgeMultiPoPVendorStage{}, errors.New("real-cloud run identity is invalid")
	}
	cleanDigest, err := realEdgeCleanURLDigest(baseURL)
	if err != nil {
		return realEdgeMultiPoPVendorStage{}, err
	}
	return realEdgeMultiPoPVendorStage{
		RunID: runIdentity.RunID, ConfirmationSHA256: runIdentity.ConfirmationSHA256, ConfigSHA256: runIdentity.ConfigSHA256,
		GenerationSHA256: fmt.Sprintf("%x", sha256.Sum256(publication.generationBody)), CheckpointSHA256: fmt.Sprintf("%x", sha256.Sum256(publication.checkpointBody)),
		Vendor: vendor, Generation: publication.checkpoint.Generation,
		TransactionID: publication.checkpoint.TransactionID, CommittedObservedAt: committedObservedAt,
		CleanURLSHA256: cleanDigest, BodySHA256: fmt.Sprintf("%x", sha256.Sum256(wanted)),
	}, nil
}

func loadRealEdgeObservers(getenv func(string) string) ([]realEdgeObserver, error) {
	raw := getenv(realEdgeObserversEnv)
	if raw == "" {
		return nil, fmt.Errorf("%s is empty", realEdgeObserversEnv)
	}
	if len(raw) > realEdgeMaxObserverJSONBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", realEdgeObserversEnv, realEdgeMaxObserverJSONBytes)
	}
	var specs []realEdgeObserverSpec
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&specs); err != nil {
		return nil, fmt.Errorf("decode observer array: %w", err)
	}
	if err := requireRealEdgeJSONEOF(decoder); err != nil {
		return nil, err
	}
	if len(specs) < 2 || len(specs) > realEdgeMaxObservers {
		return nil, fmt.Errorf("observer count=%d, want 2..%d", len(specs), realEdgeMaxObservers)
	}

	ids := make(map[string]struct{}, len(specs))
	proxyEnvs := make(map[string]struct{}, len(specs))
	proxyEndpoints := make(map[string]struct{}, len(specs))
	observers := make([]realEdgeObserver, 0, len(specs))
	for _, spec := range specs {
		if !validRealEdgeIdentifier(spec.ID, 64) {
			return nil, fmt.Errorf("observer ID %q is invalid", spec.ID)
		}
		if _, exists := ids[spec.ID]; exists {
			return nil, fmt.Errorf("duplicate observer ID %q", spec.ID)
		}
		ids[spec.ID] = struct{}{}
		if !validRealEdgeProxyEnv(spec.ProxyEnv) {
			return nil, fmt.Errorf("observer %s proxy_env is invalid", spec.ID)
		}
		if _, exists := proxyEnvs[spec.ProxyEnv]; exists {
			return nil, fmt.Errorf("duplicate observer proxy_env %q", spec.ProxyEnv)
		}
		proxyEnvs[spec.ProxyEnv] = struct{}{}
		proxyRaw := getenv(spec.ProxyEnv)
		proxyURL, endpoint, err := parseRealEdgeProxyURL(proxyRaw)
		if err != nil {
			return nil, fmt.Errorf("observer %s proxy from %s is invalid: %w", spec.ID, spec.ProxyEnv, err)
		}
		if _, exists := proxyEndpoints[endpoint]; exists {
			return nil, fmt.Errorf("observer %s reuses proxy egress endpoint", spec.ID)
		}
		proxyEndpoints[endpoint] = struct{}{}
		observers = append(observers, realEdgeObserver{ID: spec.ID, ProxyEnv: spec.ProxyEnv, proxyURL: proxyURL, proxyRaw: proxyRaw})
	}
	return observers, nil
}

func loadRealEdgeEvidenceForbidden(getenv func(string) string) ([]string, error) {
	raw := getenv(realEdgeEvidenceForbiddenEnv)
	if raw == "" || len(raw) > 64<<10 {
		return nil, fmt.Errorf("%s must contain a bounded JSON string array", realEdgeEvidenceForbiddenEnv)
	}
	var fragments []string
	decoder := json.NewDecoder(strings.NewReader(raw))
	if err := decoder.Decode(&fragments); err != nil {
		return nil, errors.New("decode evidence forbidden fragments")
	}
	if err := requireRealEdgeJSONEOF(decoder); err != nil {
		return nil, err
	}
	if len(fragments) < 2 || len(fragments) > 64 {
		return nil, fmt.Errorf("evidence forbidden fragment count=%d, want 2..64", len(fragments))
	}
	seen := make(map[string]struct{}, len(fragments))
	for _, fragment := range fragments {
		if len(fragment) < 4 || len(fragment) > realEdgeMaxProxyURLBytes || strings.ContainsAny(fragment, "\x00\r\n") {
			return nil, errors.New("evidence forbidden fragment has unsafe length or control characters")
		}
		if _, duplicate := seen[fragment]; duplicate {
			return nil, errors.New("evidence forbidden fragments contain a duplicate")
		}
		seen[fragment] = struct{}{}
	}
	return fragments, nil
}

func parseRealEdgeProxyURL(raw string) (*url.URL, string, error) {
	if raw == "" {
		return nil, "", errors.New("proxy environment variable is empty")
	}
	if len(raw) > realEdgeMaxProxyURLBytes || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\x00\r\n\t") {
		return nil, "", errors.New("proxy URL has unsafe whitespace or size")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, "", errors.New("proxy URL cannot be parsed")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "socks5" && parsed.Scheme != "socks5h" {
		return nil, "", errors.New("proxy scheme must be https, socks5, or socks5h")
	}
	if parsed.Opaque != "" || parsed.Host == "" || parsed.Hostname() == "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" || parsed.Path != "" && parsed.Path != "/" {
		return nil, "", errors.New("proxy URL must contain only authority and optional credentials")
	}
	port := parsed.Port()
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, "", errors.New("proxy URL requires an explicit valid port")
	}
	if parsed.User != nil {
		username := parsed.User.Username()
		password, hasPassword := parsed.User.Password()
		if username == "" || !hasPassword || password == "" {
			return nil, "", errors.New("proxy credentials must contain non-empty username and password")
		}
	}
	hostname := strings.ToLower(parsed.Hostname())
	if net.ParseIP(hostname) == nil && !validRealEdgeDNSName(hostname) {
		return nil, "", errors.New("proxy hostname is invalid")
	}
	endpoint := net.JoinHostPort(hostname, port)
	return parsed, endpoint, nil
}

func requestRealEdgeMultiPoP(
	ctx context.Context,
	observer realEdgeObserver,
	vendor, baseURL, token, role string,
	wanted []byte,
	secretFragments []string,
) (realEdgeMultiPoPObservation, error) {
	target := realCloudTokenURL(baseURL, token)
	parsedTarget, err := url.Parse(target)
	if err != nil || parsedTarget.Scheme != "https" || parsedTarget.Host == "" || parsedTarget.User != nil {
		return realEdgeMultiPoPObservation{}, errors.New("edge target is not a clean HTTPS URL")
	}
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return realEdgeMultiPoPObservation{}, errors.New("default HTTP transport is not safely cloneable")
	}
	transport := defaultTransport.Clone()
	transport.Proxy = http.ProxyURL(observer.proxyURL)
	transport.DisableKeepAlives = true
	transport.ForceAttemptHTTP2 = true
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer transport.CloseIdleConnections()

	started := time.Now().UTC()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return realEdgeMultiPoPObservation{}, errors.New("construct edge probe request")
	}
	request.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(request)
	if err != nil {
		// Deliberately omit the underlying error: proxy errors can echo a URL
		// containing credentials supplied by the named environment variable.
		return realEdgeMultiPoPObservation{}, errors.New("proxy transport failed")
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, realEdgeResponseLimit+1))
	closeErr := response.Body.Close()
	observed := time.Now().UTC()
	if readErr != nil || closeErr != nil || len(body) > realEdgeResponseLimit {
		return realEdgeMultiPoPObservation{}, errors.New("edge response was not safely readable")
	}
	if response.TLS == nil || response.Request == nil || response.Request.URL.Scheme != "https" {
		return realEdgeMultiPoPObservation{}, errors.New("edge probe did not retain end-to-end origin TLS")
	}
	if realEdgeResponseContainsForbidden(response.Header, response.Trailer, body, secretFragments) {
		return realEdgeMultiPoPObservation{}, errors.New("edge response exposed secret material")
	}
	if response.StatusCode != http.StatusOK || !bytes.Equal(body, wanted) {
		return realEdgeMultiPoPObservation{}, fmt.Errorf("edge response status=%d bytes=%d, want protected payload", response.StatusCode, len(body))
	}
	if response.Header.Get("X-SOW-Edge-Contract") != "sow-edge-runtime/v1" || response.Header.Get("X-SOW-Origin-Transport") != "https-bearer" {
		return realEdgeMultiPoPObservation{}, errors.New("edge response did not traverse the HTTPS bearer contract")
	}
	cacheControl := strings.ToLower(response.Header.Get("Cache-Control"))
	if !strings.Contains(cacheControl, "private") || !strings.Contains(cacheControl, "no-store") {
		return realEdgeMultiPoPObservation{}, errors.New("edge response omitted the private no-store client contract")
	}
	cacheStatus := response.Header.Get("X-SOW-Origin-Cache-Status")
	if !validRealCloudSharedCacheStatus(cacheStatus) || role == "cross-pop" && cacheStatus != "HIT" {
		return realEdgeMultiPoPObservation{}, fmt.Errorf("edge cache status=%q is invalid for role=%s", cacheStatus, role)
	}
	cacheAge, cacheMaxAge, err := parseRealEdgeCacheFreshness(response.Header)
	if err != nil {
		return realEdgeMultiPoPObservation{}, err
	}
	cleanDigest := response.Header.Get("X-SOW-Clean-URL-SHA256")
	wantedCleanDigest, err := realEdgeCleanURLDigest(baseURL)
	if err != nil || cleanDigest != wantedCleanDigest {
		return realEdgeMultiPoPObservation{}, errors.New("edge clean URL digest does not match the canonical gated URL")
	}

	requestID, cloudflareColo, err := realEdgeResponseRequestID(vendor, response.Header)
	if err != nil {
		return realEdgeMultiPoPObservation{}, err
	}
	return realEdgeMultiPoPObservation{
		Vendor: vendor, Role: role, ObserverID: observer.ID, RequestID: requestID,
		CloudflareColo: cloudflareColo, CacheStatus: cacheStatus,
		Transport: response.Header.Get("X-SOW-Origin-Transport"), CleanURLSHA256: cleanDigest,
		BodySHA256: fmt.Sprintf("%x", sha256.Sum256(body)), CacheAgeSeconds: cacheAge, CacheMaxAge: cacheMaxAge,
		RequestStarted: started, ResponseObserved: observed,
	}, nil
}

func parseRealEdgeCacheFreshness(header http.Header) (int64, int64, error) {
	rawAge := header.Get("X-SOW-Origin-Cache-Age")
	rawMaxAge := header.Get("X-SOW-Origin-Cache-Max-Age")
	if rawAge == "" && rawMaxAge == "" {
		return -1, -1, nil
	}
	if rawAge == "" || rawMaxAge == "" {
		return 0, 0, errors.New("edge cache freshness evidence is incomplete")
	}
	age, err := strconv.ParseInt(rawAge, 10, 64)
	if err != nil || age < 0 || age > 315360000 {
		return 0, 0, errors.New("edge cache age evidence is invalid")
	}
	maxAge, err := strconv.ParseInt(rawMaxAge, 10, 64)
	if err != nil || maxAge <= age || maxAge > 315360000 {
		return 0, 0, errors.New("edge cache max-age evidence is invalid or already expired")
	}
	return age, maxAge, nil
}

func realEdgeResponseRequestID(vendor string, header http.Header) (string, string, error) {
	switch vendor {
	case "cloudflare":
		values := header.Values("CF-Ray")
		if len(values) != 1 {
			return "", "", errors.New("Cloudflare response must contain exactly one CF-Ray value")
		}
		base, colo, err := parseRealEdgeCloudflareRay(values[0])
		return base, colo, err
	case "edgeone":
		values := header.Values("EO-LOG-UUID")
		if len(values) != 1 || !validRealEdgeRequestID(values[0]) {
			return "", "", errors.New("EdgeOne response must contain exactly one safe EO-LOG-UUID")
		}
		return values[0], "", nil
	default:
		return "", "", fmt.Errorf("unsupported edge vendor %q", vendor)
	}
}

func parseRealEdgeCloudflareRay(raw string) (string, string, error) {
	if strings.TrimSpace(raw) != raw || strings.Contains(raw, ",") {
		return "", "", errors.New("CF-Ray is not one canonical value")
	}
	separator := strings.LastIndexByte(raw, '-')
	if separator < 8 || separator == len(raw)-1 {
		return "", "", errors.New("CF-Ray does not contain a base ID and colo")
	}
	base, colo := raw[:separator], raw[separator+1:]
	if len(base) > 64 || !isRealEdgeLowerOrUpperHex(base) || len(colo) != 3 {
		return "", "", errors.New("CF-Ray base ID or colo is invalid")
	}
	for _, character := range colo {
		if character < 'A' || character > 'Z' {
			return "", "", errors.New("CF-Ray colo must be three uppercase letters")
		}
	}
	return strings.ToLower(base), colo, nil
}

func realEdgeCleanURLDigest(baseURL string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" {
		return "", errors.New("edge base URL is not a clean HTTPS origin")
	}
	clean := *parsed
	clean.Path = "/.sow/gated/" + realCloudGatedAssetPath
	clean.RawPath = ""
	return fmt.Sprintf("%x", sha256.Sum256([]byte(clean.String()))), nil
}

func appendRealEdgeActiveArtifact(path string, evidence realEdgeMultiPoPStageEvidence, forbidden []string) error {
	canonicalPath, err := canonicalRealEdgeExternalPath(path, realEdgeActiveArtifactEnv)
	if err != nil {
		return err
	}
	path = canonicalPath
	cloudflareStage, cloudflareExists := evidence.Vendors["cloudflare"]
	edgeOneStage, edgeOneExists := evidence.Vendors["edgeone"]
	if !cloudflareExists || !edgeOneExists || !sameRealEdgeRunBinding(cloudflareStage, edgeOneStage) {
		return errors.New("active artifact evidence is not bound to one destructive run")
	}
	if err := validateRealEdgeRunReservation(path, cloudflareStage.RunID); err != nil {
		return err
	}
	releaseLock, err := acquireRealEdgeActiveArtifactLock(path)
	if err != nil {
		return err
	}
	released := false
	defer func() {
		if !released {
			_ = releaseLock()
		}
	}()
	if _, err := os.Lstat(path + ".seal"); err == nil {
		return errors.New("active artifact is sealed and cannot accept another stage")
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("active artifact seal cannot be safely inspected")
	}
	records, err := loadRealEdgeActiveArtifactForAppend(path, forbidden)
	if err != nil {
		return err
	}
	newRecords, err := realEdgeArtifactRecords(evidence)
	if err != nil {
		return err
	}
	byKey := make(map[string]realEdgeActiveArtifactRecord, len(records)+len(newRecords))
	for _, record := range append(records, newRecords...) {
		key := realEdgeArtifactRecordKey(record)
		if prior, exists := byKey[key]; exists {
			priorBody, _ := json.Marshal(prior)
			recordBody, _ := json.Marshal(record)
			if !bytes.Equal(priorBody, recordBody) {
				return fmt.Errorf("active artifact identity %s has conflicting evidence", key)
			}
			continue
		}
		byKey[key] = record
	}
	records = records[:0]
	for _, record := range byKey {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Generation != records[j].Generation {
			return records[i].Generation < records[j].Generation
		}
		if records[i].Vendor != records[j].Vendor {
			return records[i].Vendor < records[j].Vendor
		}
		return records[i].TransactionID < records[j].TransactionID
	})
	var body bytes.Buffer
	for _, record := range records {
		line, err := json.Marshal(record)
		if err != nil {
			return errors.New("encode active artifact record")
		}
		body.Write(line)
		body.WriteByte('\n')
	}
	if body.Len() > realEdgeMaxProviderLogBytes || containsRealEdgeForbidden(body.Bytes(), forbidden) || containsRealEdgeURLLeak(body.Bytes()) {
		return errors.New("active artifact is oversized or contains secret/URL material")
	}

	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("active artifact parent must be an existing non-symlink directory")
	}
	temporary, err := os.CreateTemp(directory, ".sow-real-edge-active-*.tmp")
	if err != nil {
		return errors.New("create active artifact temporary file")
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return errors.New("secure active artifact temporary file")
	}
	if _, err := temporary.Write(body.Bytes()); err != nil {
		temporary.Close()
		return errors.New("write active artifact temporary file")
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return errors.New("sync active artifact temporary file")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close active artifact temporary file")
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return errors.New("atomically install active artifact")
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return errors.New("open active artifact parent for sync")
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return errors.New("sync active artifact parent")
	}
	if err := releaseLock(); err != nil {
		return err
	}
	released = true
	if err := directoryHandle.Sync(); err != nil {
		return errors.New("sync active artifact lock release")
	}
	return nil
}

type realEdgePersistentRunReservation struct {
	lockPath   string
	file       *os.File
	identity   fs.FileInfo
	wantedBody []byte
}

// acquireRealEdgePersistentRunReservation holds an advisory lock for the
// entire destructive process. The persistent file is deliberately retained
// when an incomplete process exits: recover may adopt it only after the old
// process has released the kernel lock and only when inode/body/run identity
// still match. complete is the sole path that removes the reservation.
func acquireRealEdgePersistentRunReservation(path, runID, mode string) (*realEdgePersistentRunReservation, error) {
	if !validRealCloudRunID(runID) {
		return nil, errors.New("real edge run reservation requires a valid run ID")
	}
	canonicalPath, err := canonicalRealEdgeExternalPath(path, realEdgeActiveArtifactEnv)
	if err != nil {
		return nil, err
	}
	lockPath := canonicalPath + realEdgeRunLockSuffix
	wantedBody := []byte("sow-real-edge-run-lock/v1 " + runID + "\n")
	switch mode {
	case "fresh":
		installed, err := installRealCloudPrivateFileExclusive(lockPath, wantedBody)
		if err != nil {
			return nil, errors.New("install real edge run reservation")
		}
		if !installed {
			return nil, errors.New("real edge run reservation already exists or is unsafe")
		}
	case "recover":
	default:
		return nil, errors.New("real edge run reservation mode must be fresh or recover")
	}
	fd, err := unix.Open(lockPath, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("recover real edge run reservation is absent or unsafe")
	}
	file := os.NewFile(uintptr(fd), lockPath)
	closeOnly := func() {
		_ = unix.Flock(fd, unix.LOCK_UN)
		_ = file.Close()
	}
	identity, err := file.Stat()
	if err != nil || !identity.Mode().IsRegular() || identity.Mode().Perm()&0o077 != 0 {
		closeOnly()
		return nil, errors.New("real edge run reservation inode is unsafe")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		closeOnly()
		return nil, errors.New("real edge run reservation is owned by a live process")
	}
	info, err := os.Lstat(lockPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !os.SameFile(identity, info) {
		closeOnly()
		return nil, errors.New("recover real edge run reservation changed during open")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		closeOnly()
		return nil, errors.New("seek recover real edge run reservation")
	}
	body, err := io.ReadAll(io.LimitReader(file, 1025))
	if err != nil || len(body) > 1024 || !bytes.Equal(body, wantedBody) {
		closeOnly()
		return nil, errors.New("recover real edge run reservation belongs to another run")
	}
	return &realEdgePersistentRunReservation{lockPath: lockPath, file: file, identity: identity, wantedBody: wantedBody}, nil
}

func (reservation *realEdgePersistentRunReservation) CloseIncomplete() error {
	if reservation == nil || reservation.file == nil {
		return nil
	}
	fd := int(reservation.file.Fd())
	err := errors.Join(unix.Flock(fd, unix.LOCK_UN), reservation.file.Close())
	reservation.file = nil
	return err
}

func (reservation *realEdgePersistentRunReservation) Complete() error {
	if reservation == nil || reservation.file == nil {
		return errors.New("real edge run reservation is not held")
	}
	info, err := os.Lstat(reservation.lockPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !os.SameFile(reservation.identity, info) {
		return errors.New("real edge run reservation changed before completion")
	}
	if _, err := reservation.file.Seek(0, io.SeekStart); err != nil {
		return errors.New("seek real edge run reservation before completion")
	}
	body, err := io.ReadAll(io.LimitReader(reservation.file, 1025))
	if err != nil || !bytes.Equal(body, reservation.wantedBody) {
		return errors.New("real edge run reservation identity changed before completion")
	}
	after, err := os.Lstat(reservation.lockPath)
	if err != nil || !os.SameFile(reservation.identity, after) {
		return errors.New("real edge run reservation path changed before completion")
	}
	if err := os.Remove(reservation.lockPath); err != nil {
		return errors.New("complete real edge run reservation")
	}
	if err := syncRealEdgeDirectory(filepath.Dir(reservation.lockPath)); err != nil {
		return err
	}
	return reservation.CloseIncomplete()
}

func syncRealEdgeDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return errors.New("open real edge reservation directory for sync")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return errors.New("sync real edge reservation directory")
	}
	return nil
}

func acquireRealEdgeRunReservation(path, runID string) (func() error, error) {
	reservation, err := acquireRealEdgePersistentRunReservation(path, runID, "fresh")
	if err != nil {
		return nil, err
	}
	return reservation.Complete, nil
}

func validateRealEdgeRunReservation(path, runID string) error {
	if !validRealCloudRunID(runID) {
		return errors.New("active artifact has an invalid destructive run ID")
	}
	lockPath := path + realEdgeRunLockSuffix
	info, err := os.Lstat(lockPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("active artifact has no safe run-level reservation")
	}
	file, err := os.Open(lockPath)
	if err != nil {
		return errors.New("open active artifact run-level reservation")
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		return errors.New("active artifact run-level reservation changed during open")
	}
	body, err := io.ReadAll(io.LimitReader(file, 1025))
	if err != nil || len(body) > 1024 || string(body) != "sow-real-edge-run-lock/v1 "+runID+"\n" {
		return errors.New("active artifact run-level reservation belongs to another run")
	}
	return nil
}

func acquireRealEdgeActiveArtifactLock(path string) (func() error, error) {
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("active artifact parent must be an existing non-symlink directory")
	}
	lockPath := path + ".lock"
	wantedBody := []byte("sow-real-edge-active-lock/v1\n")
	if _, err := installRealCloudPrivateFileExclusive(lockPath, wantedBody); err != nil {
		return nil, errors.New("install active artifact lock")
	}
	fd, err := unix.Open(lockPath, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("active artifact lock is unsafe")
	}
	lock := os.NewFile(uintptr(fd), lockPath)
	closeOnly := func() {
		_ = unix.Flock(fd, unix.LOCK_UN)
		_ = lock.Close()
	}
	identity, err := lock.Stat()
	if err != nil || !identity.Mode().IsRegular() || identity.Mode().Perm()&0o077 != 0 {
		closeOnly()
		return nil, errors.New("active artifact lock inode is unsafe")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		closeOnly()
		return nil, errors.New("active artifact has another live writer")
	}
	pathInfo, err := os.Lstat(lockPath)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || !os.SameFile(identity, pathInfo) {
		closeOnly()
		return nil, errors.New("active artifact lock changed during open")
	}
	if _, err := lock.Seek(0, io.SeekStart); err != nil {
		closeOnly()
		return nil, errors.New("seek stale active artifact lock")
	}
	body, err := io.ReadAll(io.LimitReader(lock, 1025))
	if err != nil || !bytes.Equal(body, wantedBody) {
		closeOnly()
		return nil, errors.New("active artifact stale lock identity is invalid")
	}
	return func() error {
		info, err := os.Lstat(lockPath)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !os.SameFile(identity, info) {
			return errors.New("active artifact lock changed before release")
		}
		if _, err := lock.Seek(0, io.SeekStart); err != nil {
			return errors.New("seek active artifact lock before release")
		}
		body, err := io.ReadAll(io.LimitReader(lock, 1025))
		if err != nil || !bytes.Equal(body, wantedBody) {
			return errors.New("active artifact lock identity changed before release")
		}
		after, err := os.Lstat(lockPath)
		if err != nil || !os.SameFile(identity, after) {
			return errors.New("active artifact lock path changed before release")
		}
		if err := os.Remove(lockPath); err != nil {
			return errors.New("release active artifact lock")
		}
		return errors.Join(syncRealEdgeDirectory(directory), unix.Flock(fd, unix.LOCK_UN), lock.Close())
	}, nil
}

func loadRealEdgeActiveArtifact(path string, forbidden []string) ([]realEdgeActiveArtifactRecord, error) {
	canonicalPath, err := canonicalRealEdgeExternalPath(path, realEdgeActiveArtifactEnv)
	if err != nil {
		return nil, err
	}
	return loadRealEdgeActiveArtifactExisting(canonicalPath, forbidden)
}

func loadRealEdgeActiveArtifactForAppend(path string, forbidden []string) ([]realEdgeActiveArtifactRecord, error) {
	canonicalPath, err := canonicalRealEdgeExternalPath(path, realEdgeActiveArtifactEnv)
	if err != nil {
		return nil, err
	}
	path = canonicalPath
	_, err = os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("active artifact cannot be inspected")
	}
	return loadRealEdgeActiveArtifactExisting(path, forbidden)
}

func loadRealEdgeActiveArtifactExisting(path string, forbidden []string) ([]realEdgeActiveArtifactRecord, error) {
	body, err := readRealEdgeSafeJSONL(path, realEdgeMaxProviderLogBytes, "active artifact")
	if err != nil {
		return nil, err
	}
	return decodeRealEdgeActiveArtifactBody(body, forbidden)
}

func decodeRealEdgeActiveArtifactBody(body []byte, forbidden []string) ([]realEdgeActiveArtifactRecord, error) {
	if containsRealEdgeForbidden(body, forbidden) || containsRealEdgeURLLeak(body) {
		return nil, errors.New("active artifact contains token, proxy secret, URL, or protected path")
	}
	records := make([]realEdgeActiveArtifactRecord, 0, 8)
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 4096), realEdgeMaxProviderLogLine)
	for scanner.Scan() {
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			return nil, errors.New("active artifact contains a blank record")
		}
		if len(records) >= 2*realEdgeMaxProviderLogRecords {
			return nil, errors.New("active artifact has too many records")
		}
		record, err := decodeRealEdgeActiveArtifactRecord(scanner.Bytes())
		if err != nil {
			return nil, fmt.Errorf("active artifact record %d: %w", len(records)+1, err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.New("active artifact line exceeds its safe limit")
	}
	if len(records) == 0 {
		return nil, errors.New("active artifact is empty")
	}
	return records, nil
}

func loadRealEdgeSealedActiveArtifact(path string, forbidden []string, runID string) ([]realEdgeActiveArtifactRecord, error) {
	canonicalPath, err := canonicalRealEdgeExternalPath(path, realEdgeActiveArtifactEnv)
	if err != nil {
		return nil, err
	}
	body, err := readRealEdgeSafeJSONL(canonicalPath, realEdgeMaxProviderLogBytes, "active artifact")
	if err != nil {
		return nil, err
	}
	if err := verifyRealEdgeActiveArtifactSeal(canonicalPath, body, runID); err != nil {
		return nil, err
	}
	return decodeRealEdgeActiveArtifactBody(body, forbidden)
}

func realEdgeArtifactRecords(evidence realEdgeMultiPoPStageEvidence) ([]realEdgeActiveArtifactRecord, error) {
	if len(evidence.Vendors) != 2 {
		return nil, errors.New("active artifact requires exactly two vendors")
	}
	if err := validateRealEdgeEntitlementDigests(evidence.EntitlementSHA256); err != nil {
		return nil, err
	}
	records := make([]realEdgeActiveArtifactRecord, 0, 2)
	for _, vendor := range []string{"cloudflare", "edgeone"} {
		stage, exists := evidence.Vendors[vendor]
		if !exists {
			return nil, fmt.Errorf("active artifact is missing %s", vendor)
		}
		record := realEdgeActiveArtifactRecord{
			Schema: "sow-real-edge-active/v5", RunID: stage.RunID,
			ConfirmationSHA256: stage.ConfirmationSHA256, ConfigSHA256: stage.ConfigSHA256,
			GenerationSHA256: stage.GenerationSHA256, CheckpointSHA256: stage.CheckpointSHA256,
			Vendor: vendor, Generation: stage.Generation,
			TransactionID: stage.TransactionID, CommittedObservedAt: stage.CommittedObservedAt.UTC().Format(time.RFC3339Nano),
			CleanURLSHA256: stage.CleanURLSHA256, BodySHA256: stage.BodySHA256,
			EntitlementSHA256: append([]string(nil), evidence.EntitlementSHA256...),
			Observations:      encodeRealEdgeArtifactObservations(stage.Observations),
		}
		if stage.PrePurge != nil {
			record.PrePurge = &realEdgeActivePrePurgeRecord{
				Generation: stage.PrePurge.Generation, TransactionID: stage.PrePurge.TransactionID,
				CleanURLSHA256: stage.PrePurge.CleanURLSHA256, BodySHA256: stage.PrePurge.BodySHA256,
				Observations: encodeRealEdgeArtifactObservations(stage.PrePurge.Observations),
			}
		}
		if _, err := artifactRecordToRealEdgeStage(record); err != nil {
			return nil, fmt.Errorf("%s active stage: %w", vendor, err)
		}
		records = append(records, record)
	}
	return records, nil
}

func encodeRealEdgeArtifactObservations(observations []realEdgeMultiPoPObservation) []realEdgeActiveArtifactObservation {
	encoded := make([]realEdgeActiveArtifactObservation, 0, len(observations))
	for _, observation := range observations {
		encoded = append(encoded, realEdgeActiveArtifactObservation{
			Role: observation.Role, ObserverID: observation.ObserverID, RequestID: observation.RequestID,
			CloudflareColo: observation.CloudflareColo, CacheStatus: observation.CacheStatus,
			Transport: observation.Transport, CleanURLSHA256: observation.CleanURLSHA256,
			BodySHA256: observation.BodySHA256, CacheAgeSeconds: observation.CacheAgeSeconds, CacheMaxAge: observation.CacheMaxAge,
			RequestStarted: observation.RequestStarted.UTC().Format(time.RFC3339Nano), ResponseObserved: observation.ResponseObserved.UTC().Format(time.RFC3339Nano),
		})
	}
	return encoded
}

func decodeRealEdgeActiveArtifactRecord(line []byte) (realEdgeActiveArtifactRecord, error) {
	var record realEdgeActiveArtifactRecord
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, errors.New("record values cannot be decoded")
	}
	if err := requireRealEdgeJSONEOF(decoder); err != nil {
		return record, err
	}
	if _, err := artifactRecordToRealEdgeStage(record); err != nil {
		return record, err
	}
	return record, nil
}

func artifactRecordToRealEdgeStage(record realEdgeActiveArtifactRecord) (realEdgeMultiPoPVendorStage, error) {
	if record.Schema != "sow-real-edge-active/v5" || !validRealCloudRunID(record.RunID) ||
		!validRealCloudLowerSHA256(record.ConfirmationSHA256) || !validRealCloudLowerSHA256(record.ConfigSHA256) ||
		!validRealCloudLowerSHA256(record.GenerationSHA256) || !validRealCloudLowerSHA256(record.CheckpointSHA256) ||
		record.Vendor != "cloudflare" && record.Vendor != "edgeone" || record.Generation == 0 || !validRealEdgeTransactionID(record.TransactionID) || !validRealCloudLowerSHA256(record.CleanURLSHA256) || !validRealCloudLowerSHA256(record.BodySHA256) {
		return realEdgeMultiPoPVendorStage{}, errors.New("record stage identity is invalid")
	}
	if err := validateRealEdgeEntitlementDigests(record.EntitlementSHA256); err != nil {
		return realEdgeMultiPoPVendorStage{}, err
	}
	committedObservedAt, err := parseRealEdgeUTC(record.CommittedObservedAt)
	if err != nil {
		return realEdgeMultiPoPVendorStage{}, fmt.Errorf("committed_observed_at: %w", err)
	}
	if len(record.Observations) < 2 || len(record.Observations) > realEdgeMaxObservers {
		return realEdgeMultiPoPVendorStage{}, fmt.Errorf("observation count=%d, want 2..%d", len(record.Observations), realEdgeMaxObservers)
	}
	stage := realEdgeMultiPoPVendorStage{
		RunID: record.RunID, ConfirmationSHA256: record.ConfirmationSHA256, ConfigSHA256: record.ConfigSHA256,
		GenerationSHA256: record.GenerationSHA256, CheckpointSHA256: record.CheckpointSHA256,
		Vendor: record.Vendor, Generation: record.Generation, TransactionID: record.TransactionID,
		CommittedObservedAt: committedObservedAt, CleanURLSHA256: record.CleanURLSHA256, BodySHA256: record.BodySHA256,
		Observations: make([]realEdgeMultiPoPObservation, 0, len(record.Observations)),
	}
	stage.Observations, err = decodeRealEdgeArtifactObservations(record.Vendor, record.Observations)
	if err != nil {
		return realEdgeMultiPoPVendorStage{}, err
	}
	if record.PrePurge != nil {
		preObservations, err := decodeRealEdgeArtifactObservations(record.Vendor, record.PrePurge.Observations)
		if err != nil {
			return realEdgeMultiPoPVendorStage{}, fmt.Errorf("pre_purge: %w", err)
		}
		stage.PrePurge = &realEdgePrePurgeVendorEvidence{
			Generation: record.PrePurge.Generation, TransactionID: record.PrePurge.TransactionID,
			CleanURLSHA256: record.PrePurge.CleanURLSHA256, BodySHA256: record.PrePurge.BodySHA256,
			Observations: preObservations,
		}
	}
	if err := validateRealEdgeActiveStage(stage); err != nil {
		return realEdgeMultiPoPVendorStage{}, err
	}
	return stage, nil
}

func decodeRealEdgeArtifactObservations(vendor string, observations []realEdgeActiveArtifactObservation) ([]realEdgeMultiPoPObservation, error) {
	result := make([]realEdgeMultiPoPObservation, 0, len(observations))
	for _, encoded := range observations {
		started, err := parseRealEdgeUTC(encoded.RequestStarted)
		if err != nil {
			return nil, fmt.Errorf("request_started: %w", err)
		}
		observed, err := parseRealEdgeUTC(encoded.ResponseObserved)
		if err != nil {
			return nil, fmt.Errorf("response_observed: %w", err)
		}
		result = append(result, realEdgeMultiPoPObservation{
			Vendor: vendor, Role: encoded.Role, ObserverID: encoded.ObserverID,
			RequestID: encoded.RequestID, CloudflareColo: encoded.CloudflareColo,
			CacheStatus: encoded.CacheStatus, Transport: encoded.Transport,
			CleanURLSHA256: encoded.CleanURLSHA256, BodySHA256: encoded.BodySHA256, CacheAgeSeconds: encoded.CacheAgeSeconds, CacheMaxAge: encoded.CacheMaxAge,
			RequestStarted: started, ResponseObserved: observed,
		})
	}
	return result, nil
}

func pairRealEdgeArtifactStages(records []realEdgeActiveArtifactRecord, logs []realEdgeProviderLog) ([]realEdgeMultiPoPStageEvidence, error) {
	type stagePair struct {
		vendors           map[string]realEdgeMultiPoPVendorStage
		entitlementSHA256 []string
		runBinding        realEdgeMultiPoPVendorStage
	}
	pairs := make(map[uint64]*stagePair)
	for _, record := range records {
		stage, err := artifactRecordToRealEdgeStage(record)
		if err != nil {
			return nil, err
		}
		pair := pairs[stage.Generation]
		if pair == nil {
			pair = &stagePair{
				vendors:           make(map[string]realEdgeMultiPoPVendorStage, 2),
				entitlementSHA256: append([]string(nil), record.EntitlementSHA256...),
				runBinding:        stage,
			}
			pairs[stage.Generation] = pair
		} else if !slices.Equal(pair.entitlementSHA256, record.EntitlementSHA256) {
			return nil, fmt.Errorf("generation %d vendors have different entitlement identities", stage.Generation)
		} else if !sameRealEdgeRunBinding(pair.runBinding, stage) {
			return nil, fmt.Errorf("generation %d vendors have different destructive run bindings", stage.Generation)
		}
		if _, duplicate := pair.vendors[stage.Vendor]; duplicate {
			return nil, fmt.Errorf("generation %d has duplicate %s active records", stage.Generation, stage.Vendor)
		}
		pair.vendors[stage.Vendor] = stage
	}
	generations := make([]uint64, 0, len(pairs))
	for generation := range pairs {
		generations = append(generations, generation)
	}
	sort.Slice(generations, func(i, j int) bool { return generations[i] < generations[j] })
	stages := make([]realEdgeMultiPoPStageEvidence, 0, len(generations))
	var runEntitlements []string
	var runBinding *realEdgeMultiPoPVendorStage
	for _, generation := range generations {
		pair := pairs[generation]
		if len(pair.vendors) != 2 {
			return nil, fmt.Errorf("generation %d does not contain both vendors", generation)
		}
		if pair.vendors["cloudflare"].BodySHA256 != pair.vendors["edgeone"].BodySHA256 {
			return nil, fmt.Errorf("generation %d vendors observed different protected bytes", generation)
		}
		if runEntitlements == nil {
			runEntitlements = append([]string(nil), pair.entitlementSHA256...)
		} else if !slices.Equal(runEntitlements, pair.entitlementSHA256) {
			return nil, fmt.Errorf("generation %d changed entitlement identities", generation)
		}
		if runBinding == nil {
			binding := pair.runBinding
			runBinding = &binding
		} else if !sameRealEdgeRunBinding(*runBinding, pair.runBinding) {
			return nil, fmt.Errorf("generation %d changed destructive run identity", generation)
		}
		stages = append(stages, realEdgeMultiPoPStageEvidence{
			Vendors: pair.vendors, ProviderLogs: logs,
			EntitlementSHA256: append([]string(nil), pair.entitlementSHA256...),
		})
	}
	return stages, nil
}

func sameRealEdgeRunBinding(left, right realEdgeMultiPoPVendorStage) bool {
	return left.RunID == right.RunID && left.ConfirmationSHA256 == right.ConfirmationSHA256 && left.ConfigSHA256 == right.ConfigSHA256
}

func realEdgeArtifactRecordKey(record realEdgeActiveArtifactRecord) string {
	return fmt.Sprintf("%020d/%s/%s", record.Generation, record.Vendor, record.TransactionID)
}

func validateRealEdgeExternalPath(path, environmentName string) error {
	_, err := canonicalRealEdgeExternalPath(path, environmentName)
	return err
}

func canonicalRealEdgeExternalPath(path, environmentName string) (string, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, '\x00') {
		return "", fmt.Errorf("%s must be an absolute clean path", environmentName)
	}
	repositoryRoot, err := realEdgeRepositoryRoot()
	if err != nil {
		return "", err
	}
	canonicalRepositoryRoot, err := filepath.EvalSymlinks(repositoryRoot)
	if err != nil {
		return "", errors.New("canonicalize repository root")
	}
	rawDirectoryInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil || !rawDirectoryInfo.IsDir() || rawDirectoryInfo.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s parent must be an existing non-symlink directory", environmentName)
	}
	canonicalDirectory, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", fmt.Errorf("%s parent must be an existing resolvable directory", environmentName)
	}
	directoryInfo, err := os.Stat(canonicalDirectory)
	if err != nil || !directoryInfo.IsDir() {
		return "", fmt.Errorf("%s parent must resolve to a directory", environmentName)
	}
	canonicalPath := filepath.Join(canonicalDirectory, filepath.Base(path))
	relative, err := filepath.Rel(canonicalRepositoryRoot, canonicalPath)
	if err != nil || relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%s must remain outside the repository after resolving symlinks", environmentName)
	}
	return canonicalPath, nil
}

func realEdgeRepositoryRoot() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", errors.New("resolve current directory")
	}
	for {
		info, statErr := os.Stat(filepath.Join(directory, "go.mod"))
		if statErr == nil && info.Mode().IsRegular() {
			return directory, nil
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return "", errors.New("cannot locate repository root")
		}
		directory = parent
	}
}

func readRealEdgeSafeJSONL(path string, maximum int64, label string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s does not exist", errRealEdgeProviderLogsIncomplete, label)
		}
		return nil, fmt.Errorf("%s cannot be inspected", label)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a non-symlink regular file", label)
	}
	if info.Size() > maximum {
		return nil, fmt.Errorf("%s exceeds %d bytes", label, maximum)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s cannot be opened", label)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, fmt.Errorf("%s changed during safe open", label)
	}
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(body)) > maximum {
		return nil, fmt.Errorf("%s cannot be read within its size limit", label)
	}
	afterInfo, err := file.Stat()
	if err != nil || !afterInfo.Mode().IsRegular() || !os.SameFile(openedInfo, afterInfo) ||
		afterInfo.Size() != openedInfo.Size() || !afterInfo.ModTime().Equal(openedInfo.ModTime()) || int64(len(body)) != afterInfo.Size() {
		return nil, fmt.Errorf("%s changed while it was being read", label)
	}
	if len(body) == 0 || body[len(body)-1] != '\n' {
		return nil, fmt.Errorf("%w: %s has no complete final record", errRealEdgeProviderLogsIncomplete, label)
	}
	return body, nil
}

func parseRealEdgeUTC(raw string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || parsed.IsZero() || !strings.HasSuffix(raw, "Z") {
		return time.Time{}, errors.New("must be a non-zero UTC RFC3339 timestamp")
	}
	return parsed.UTC(), nil
}

func loadRealEdgeProviderLogs(path string, forbidden []string) ([]realEdgeProviderLog, error) {
	canonicalPath, err := canonicalRealEdgeExternalPath(path, realEdgeProviderLogEnv)
	if err != nil {
		return nil, err
	}
	body, err := readRealEdgeSafeJSONL(canonicalPath, realEdgeMaxProviderLogBytes, "provider log")
	if err != nil {
		return nil, err
	}
	if containsRealEdgeForbidden(body, forbidden) || containsRealEdgeURLLeak(body) {
		return nil, errors.New("provider log contains a token, proxy secret, URL, or protected path")
	}
	sealRunID, err := verifyRealEdgeProviderLogSeal(canonicalPath, body)
	if err != nil {
		return nil, err
	}

	logs := make([]realEdgeProviderLog, 0, 16)
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 4096), realEdgeMaxProviderLogLine)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			return nil, errors.New("provider JSONL contains a blank record")
		}
		if len(logs) >= realEdgeMaxProviderLogRecords {
			return nil, fmt.Errorf("provider JSONL exceeds %d records", realEdgeMaxProviderLogRecords)
		}
		log, err := decodeRealEdgeProviderLog(line)
		if err != nil {
			return nil, fmt.Errorf("provider JSONL record %d: %w", len(logs)+1, err)
		}
		logs = append(logs, log)
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.New("provider JSONL line exceeds its safe limit")
	}
	for _, log := range logs {
		if log.RunID != sealRunID {
			return nil, errors.New("provider log record does not match its completed exporter seal")
		}
	}
	return logs, nil
}

func verifyRealEdgeProviderLogSeal(path string, body []byte) (string, error) {
	sealBody, err := readRealEdgeSafeJSONL(path+".seal", 4<<10, "provider log seal")
	if err != nil {
		return "", fmt.Errorf("provider exporter did not atomically complete and seal its JSONL: %w", err)
	}
	var seal realEdgeProviderLogSeal
	decoder := json.NewDecoder(bytes.NewReader(sealBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&seal); err != nil {
		return "", errors.New("provider log seal is not one strict JSON object")
	}
	if err := requireRealEdgeJSONEOF(decoder); err != nil {
		return "", err
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(body))
	if seal.Schema != "sow-real-edge-provider-log-seal/v1" || !validRealCloudRunID(seal.RunID) || seal.SHA256 != digest || seal.Size != int64(len(body)) {
		return "", errors.New("provider log seal does not bind the complete JSONL bytes and destructive run")
	}
	return seal.RunID, nil
}

func sealRealEdgeActiveArtifact(path, runID string) error {
	canonicalPath, err := canonicalRealEdgeExternalPath(path, realEdgeActiveArtifactEnv)
	if err != nil {
		return err
	}
	if err := validateRealEdgeRunReservation(canonicalPath, runID); err != nil {
		return err
	}
	release, err := acquireRealEdgeActiveArtifactLock(canonicalPath)
	if err != nil {
		return err
	}
	released := false
	defer func() {
		if !released {
			_ = release()
		}
	}()
	body, err := readRealEdgeSafeJSONL(canonicalPath, realEdgeMaxProviderLogBytes, "active artifact")
	if err != nil {
		return err
	}
	records, err := decodeRealEdgeActiveArtifactBody(body, nil)
	if err != nil {
		return err
	}
	if len(records) != 4 {
		return fmt.Errorf("active artifact seal requires exactly four generation 4/5 vendor records, got %d", len(records))
	}
	wanted := map[string]struct{}{"4/cloudflare": {}, "4/edgeone": {}, "5/cloudflare": {}, "5/edgeone": {}}
	for _, record := range records {
		if record.RunID != runID {
			return errors.New("active artifact seal found another destructive run")
		}
		key := fmt.Sprintf("%d/%s", record.Generation, record.Vendor)
		if _, exists := wanted[key]; !exists {
			return errors.New("active artifact seal found an unexpected or duplicate generation/vendor record")
		}
		delete(wanted, key)
	}
	sealPath := canonicalPath + ".seal"
	if _, err := os.Lstat(sealPath); err == nil {
		if err := verifyRealEdgeActiveArtifactSeal(canonicalPath, body, runID); err != nil {
			return err
		}
		if err := release(); err != nil {
			return err
		}
		released = true
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("active artifact seal cannot be safely inspected")
	}
	digest := sha256.Sum256(body)
	seal := realEdgeActiveArtifactSeal{
		Schema: "sow-real-edge-active-seal/v1", RunID: runID,
		SHA256: fmt.Sprintf("%x", digest), Size: int64(len(body)),
	}
	encoded, err := json.Marshal(seal)
	if err != nil {
		return errors.New("encode active artifact seal")
	}
	encoded = append(encoded, '\n')
	directory := filepath.Dir(canonicalPath)
	temporary, err := os.CreateTemp(directory, ".sow-real-edge-active-seal-*.tmp")
	if err != nil {
		return errors.New("create active artifact seal temporary file")
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return errors.New("secure active artifact seal temporary file")
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return errors.New("write active artifact seal temporary file")
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return errors.New("sync active artifact seal temporary file")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close active artifact seal temporary file")
	}
	if err := os.Link(temporaryPath, sealPath); err != nil {
		return errors.New("atomically install active artifact seal")
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return errors.New("open active artifact seal parent for sync")
	}
	if err := directoryHandle.Sync(); err != nil {
		_ = directoryHandle.Close()
		return errors.New("sync active artifact seal parent")
	}
	_ = directoryHandle.Close()
	if err := release(); err != nil {
		return err
	}
	released = true
	return nil
}

func verifyRealEdgeActiveArtifactSeal(path string, body []byte, runID string) error {
	sealBody, err := readRealEdgeSafeJSONL(path+".seal", 4<<10, "active artifact seal")
	if err != nil {
		return fmt.Errorf("active probe writer did not atomically complete and seal its JSONL: %w", err)
	}
	var seal realEdgeActiveArtifactSeal
	decoder := json.NewDecoder(bytes.NewReader(sealBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&seal); err != nil {
		return errors.New("active artifact seal is not one strict JSON object")
	}
	if err := requireRealEdgeJSONEOF(decoder); err != nil {
		return err
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(body))
	if seal.Schema != "sow-real-edge-active-seal/v1" || seal.RunID != runID || !validRealCloudRunID(seal.RunID) || seal.SHA256 != digest || seal.Size != int64(len(body)) {
		return errors.New("active artifact seal does not bind the complete JSONL bytes and destructive run")
	}
	return nil
}

func decodeRealEdgeProviderLog(line []byte) (realEdgeProviderLog, error) {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(line, &keys); err != nil {
		return realEdgeProviderLog{}, errors.New("record is not one JSON object")
	}
	required := []string{
		"schema", "run_id", "probe_phase", "vendor", "request_id", "parent_request_id", "node_id", "node_ip", "region", "cache_status",
		"clean_url_sha256", "body_sha256", "generation", "transaction_id", "observed_at",
	}
	if len(keys) != len(required) {
		return realEdgeProviderLog{}, errors.New("record has missing or unknown fields")
	}
	for _, key := range required {
		if _, exists := keys[key]; !exists {
			return realEdgeProviderLog{}, fmt.Errorf("record is missing %s", key)
		}
	}
	var record realEdgeProviderLog
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return realEdgeProviderLog{}, errors.New("record values cannot be decoded")
	}
	if err := requireRealEdgeJSONEOF(decoder); err != nil {
		return realEdgeProviderLog{}, err
	}
	parsedTime, err := time.Parse(time.RFC3339Nano, record.ObservedAt)
	if err != nil || parsedTime.IsZero() || parsedTime.Location() != time.UTC {
		return realEdgeProviderLog{}, errors.New("observed_at must be a non-zero UTC RFC3339 timestamp")
	}
	record.observedTime = parsedTime.UTC()
	if err := validateRealEdgeProviderLogShape(record); err != nil {
		return realEdgeProviderLog{}, err
	}
	return record, nil
}

func validateRealEdgeProviderLogShape(record realEdgeProviderLog) error {
	if record.Schema != "sow-real-edge-provider-joined/v3" || !validRealCloudRunID(record.RunID) || record.ProbePhase != "stage" && record.ProbePhase != "pre-purge" {
		return errors.New("provider log is not the collector-normalized joined schema")
	}
	if record.Vendor != "cloudflare" && record.Vendor != "edgeone" {
		return errors.New("provider log vendor is invalid")
	}
	if !validRealEdgeRequestID(record.RequestID) || !validRealEdgeRequestID(record.ParentRequestID) || record.RequestID == record.ParentRequestID {
		return errors.New("provider log request identity is invalid")
	}
	if !validRealEdgeSafeText(record.NodeID, 128) || !validRealEdgeSafeText(record.Region, 128) {
		return errors.New("provider log node or region is invalid")
	}
	if record.Vendor == "cloudflare" {
		if record.NodeIP != "" {
			return errors.New("Cloudflare normalized log must leave unavailable node_ip empty")
		}
	} else {
		if !validRealEdgePublicRoutableIP(record.NodeIP) {
			return errors.New("EdgeOne provider log node_ip is not a public unicast address")
		}
		if !validRealEdgeEdgeOneRegion(record.Region) {
			return errors.New("EdgeOne provider log region is not a canonical ISO 3166-1 alpha-2 country code")
		}
	}
	if !validRealCloudSharedCacheStatus(record.CacheStatus) || !validRealCloudLowerSHA256(record.CleanURLSHA256) || !validRealCloudLowerSHA256(record.BodySHA256) {
		return errors.New("provider log cache status or digest is invalid")
	}
	if record.Generation == 0 || !validRealEdgeTransactionID(record.TransactionID) {
		return errors.New("provider log generation or transaction ID is invalid")
	}
	return nil
}

func validateRealEdgeMultiPoPStage(evidence realEdgeMultiPoPStageEvidence, forbidden []string) error {
	if len(evidence.Vendors) != 2 {
		return fmt.Errorf("vendor stage count=%d, want 2", len(evidence.Vendors))
	}
	if err := validateRealEdgeEntitlementDigests(evidence.EntitlementSHA256); err != nil {
		return err
	}
	if forbidden != nil {
		if err := validateRealEdgeForbiddenEntitlementCoverage(evidence.EntitlementSHA256, forbidden); err != nil {
			return err
		}
	}
	var runBinding *realEdgeMultiPoPVendorStage
	for _, vendor := range []string{"cloudflare", "edgeone"} {
		stage, exists := evidence.Vendors[vendor]
		if !exists || stage.Vendor != vendor {
			return fmt.Errorf("missing canonical %s stage", vendor)
		}
		if err := validateRealEdgeActiveStage(stage); err != nil {
			return fmt.Errorf("%s active stage: %w", vendor, err)
		}
		if runBinding == nil {
			binding := stage
			runBinding = &binding
		} else if !sameRealEdgeRunBinding(*runBinding, stage) {
			return errors.New("vendor stages belong to different destructive runs")
		}

		selectedLogs := make([]realEdgeProviderLog, 0, len(stage.Observations))
		for _, record := range evidence.ProviderLogs {
			if err := validateRealEdgeProviderLogShape(record); err != nil {
				return fmt.Errorf("provider log shape: %w", err)
			}
			if record.RunID != stage.RunID {
				return errors.New("provider log belongs to a different destructive run")
			}
			if containsRealEdgeForbidden([]byte(strings.Join([]string{record.Vendor, record.RequestID, record.ParentRequestID, record.NodeID, record.NodeIP, record.Region, record.TransactionID}, "\x00")), forbidden) {
				return errors.New("provider log field contains forbidden secret material")
			}
			if record.ProbePhase == "stage" && record.Vendor == vendor && record.Generation == stage.Generation && record.TransactionID == stage.TransactionID {
				selectedLogs = append(selectedLogs, record)
			}
		}
		if len(selectedLogs) < len(stage.Observations) {
			return fmt.Errorf("%w: %s correlated logs=%d observations=%d", errRealEdgeProviderLogsIncomplete, vendor, len(selectedLogs), len(stage.Observations))
		}
		if len(selectedLogs) != len(stage.Observations) {
			return fmt.Errorf("%s has duplicate or uncorrelated provider logs", vendor)
		}

		observerIDs := make(map[string]struct{}, len(stage.Observations))
		requestIDs := make(map[string]struct{}, len(stage.Observations))
		nodeIDs := make(map[string]struct{}, len(stage.Observations))
		nodeIPs := make(map[string]struct{}, len(stage.Observations))
		regions := make(map[string]struct{}, len(stage.Observations))
		providerRequestIDs := make(map[string]struct{}, len(stage.Observations))
		matchedLogs := make(map[int]struct{}, len(stage.Observations))
		primeCount := 0
		for index, observation := range stage.Observations {
			if observation.Vendor != vendor || !validRealEdgeIdentifier(observation.ObserverID, 64) || !validRealEdgeRequestID(observation.RequestID) {
				return fmt.Errorf("%s observation identity is invalid", vendor)
			}
			if _, duplicate := observerIDs[observation.ObserverID]; duplicate {
				return fmt.Errorf("%s reused observer %s", vendor, observation.ObserverID)
			}
			observerIDs[observation.ObserverID] = struct{}{}
			if _, duplicate := requestIDs[observation.RequestID]; duplicate {
				return fmt.Errorf("%s reused edge request ID", vendor)
			}
			requestIDs[observation.RequestID] = struct{}{}
			if observation.Role == "prime" {
				primeCount++
				if index != 0 {
					return fmt.Errorf("%s prime observation must be first", vendor)
				}
			} else if observation.Role != "cross-pop" {
				return fmt.Errorf("%s observation role=%q is invalid", vendor, observation.Role)
			}
			if observation.Role == "cross-pop" && observation.CacheStatus != "HIT" {
				return fmt.Errorf("%s cross-PoP cache status=%s, want HIT", vendor, observation.CacheStatus)
			}
			if !validRealCloudSharedCacheStatus(observation.CacheStatus) || observation.Transport != "https-bearer" || observation.CleanURLSHA256 != stage.CleanURLSHA256 || observation.BodySHA256 != stage.BodySHA256 {
				return fmt.Errorf("%s observation cache, transport, or digest mismatch", vendor)
			}
			if observation.RequestStarted.IsZero() || observation.ResponseObserved.Before(observation.RequestStarted) || observation.ResponseObserved.Before(stage.CommittedObservedAt) {
				return fmt.Errorf("%s observation time is outside the published request window", vendor)
			}
			if vendor == "cloudflare" && (len(observation.CloudflareColo) != 3 || observation.CloudflareColo != strings.ToUpper(observation.CloudflareColo)) {
				return errors.New("Cloudflare observation has no valid CF-Ray colo")
			}
			if vendor == "edgeone" && observation.CloudflareColo != "" {
				return errors.New("EdgeOne observation claimed a response-derived PoP")
			}

			matches := make([]int, 0, 1)
			for logIndex, record := range selectedLogs {
				if record.ParentRequestID == observation.RequestID {
					matches = append(matches, logIndex)
				}
			}
			if len(matches) != 1 {
				return fmt.Errorf("%s observation %s provider-log matches=%d, want 1", vendor, observation.ObserverID, len(matches))
			}
			logIndex := matches[0]
			if _, duplicate := matchedLogs[logIndex]; duplicate {
				return fmt.Errorf("%s provider log matched multiple observations", vendor)
			}
			matchedLogs[logIndex] = struct{}{}
			record := selectedLogs[logIndex]
			if _, duplicate := providerRequestIDs[record.RequestID]; duplicate {
				return fmt.Errorf("%s reused a provider subrequest ID", vendor)
			}
			providerRequestIDs[record.RequestID] = struct{}{}
			if record.CacheStatus != observation.CacheStatus || record.CleanURLSHA256 != stage.CleanURLSHA256 || record.BodySHA256 != stage.BodySHA256 {
				return fmt.Errorf("%s provider log cache status or digest disagrees with active probe", vendor)
			}
			if record.observedTime.Before(stage.CommittedObservedAt) || record.observedTime.Before(observation.RequestStarted.Add(-realEdgeProviderClockSkew)) || record.observedTime.After(observation.ResponseObserved.Add(realEdgeProviderExportLag)) {
				return fmt.Errorf("%s provider log time is outside the publication/probe window", vendor)
			}
			if vendor == "cloudflare" && record.Region != observation.CloudflareColo {
				return fmt.Errorf("Cloudflare provider region=%s disagrees with CF-Ray colo=%s", record.Region, observation.CloudflareColo)
			}
			if _, duplicate := nodeIDs[record.NodeID]; duplicate {
				return fmt.Errorf("%s observations came from the same provider node", vendor)
			}
			nodeIDs[record.NodeID] = struct{}{}
			if vendor == "cloudflare" {
				if _, duplicate := regions[record.Region]; duplicate {
					return errors.New("Cloudflare observations came from the same EdgeColoCode")
				}
				regions[record.Region] = struct{}{}
			} else {
				if _, duplicate := nodeIPs[record.NodeIP]; duplicate {
					return errors.New("EdgeOne observations came from the same EdgeServerIP")
				}
				nodeIPs[record.NodeIP] = struct{}{}
				// Distinct server IDs/IPs prove distinct nodes, but not distinct
				// points of presence. Require a different provider-reported ISO
				// country or (where available) subdivision as a conservative,
				// sufficient multi-PoP gate.
				if _, duplicate := regions[record.Region]; duplicate {
					return errors.New("EdgeOne observations came from the same provider geography")
				}
				regions[record.Region] = struct{}{}
			}
		}
		if primeCount != 1 || len(matchedLogs) != len(stage.Observations) {
			return fmt.Errorf("%s did not prove one prime plus independently logged cross-PoP hits", vendor)
		}
	}
	return nil
}

func validateRealEdgeActiveStage(stage realEdgeMultiPoPVendorStage) error {
	if !validRealCloudRunID(stage.RunID) || !validRealCloudLowerSHA256(stage.ConfirmationSHA256) || !validRealCloudLowerSHA256(stage.ConfigSHA256) ||
		!validRealCloudLowerSHA256(stage.GenerationSHA256) || !validRealCloudLowerSHA256(stage.CheckpointSHA256) ||
		stage.Vendor != "cloudflare" && stage.Vendor != "edgeone" || stage.Generation == 0 || !validRealEdgeTransactionID(stage.TransactionID) || stage.CommittedObservedAt.IsZero() || !validRealCloudLowerSHA256(stage.CleanURLSHA256) || !validRealCloudLowerSHA256(stage.BodySHA256) {
		return errors.New("stage identity is invalid")
	}
	if len(stage.Observations) < 2 || len(stage.Observations) > realEdgeMaxObservers {
		return fmt.Errorf("observation count=%d, want 2..%d", len(stage.Observations), realEdgeMaxObservers)
	}
	observers := make(map[string]struct{}, len(stage.Observations))
	requests := make(map[string]struct{}, len(stage.Observations))
	primeCount := 0
	var primeObserved time.Time
	for index, observation := range stage.Observations {
		if observation.Vendor != stage.Vendor || !validRealEdgeIdentifier(observation.ObserverID, 64) || !validRealEdgeRequestID(observation.RequestID) {
			return errors.New("observation identity is invalid")
		}
		if _, duplicate := observers[observation.ObserverID]; duplicate {
			return errors.New("observer egress was reused")
		}
		observers[observation.ObserverID] = struct{}{}
		if _, duplicate := requests[observation.RequestID]; duplicate {
			return errors.New("edge request ID was reused")
		}
		requests[observation.RequestID] = struct{}{}
		switch observation.Role {
		case "prime":
			primeCount++
			if index != 0 {
				return errors.New("prime observation must be first")
			}
			primeObserved = observation.ResponseObserved
		case "cross-pop":
			if observation.CacheStatus != "HIT" {
				return fmt.Errorf("cross-PoP cache status=%s, want HIT", observation.CacheStatus)
			}
			if primeObserved.IsZero() || observation.RequestStarted.Before(primeObserved) {
				return errors.New("cross-PoP request did not start after the prime response completed")
			}
		default:
			return fmt.Errorf("observation role=%q is invalid", observation.Role)
		}
		if !validRealCloudSharedCacheStatus(observation.CacheStatus) || observation.Transport != "https-bearer" || observation.CleanURLSHA256 != stage.CleanURLSHA256 || observation.BodySHA256 != stage.BodySHA256 {
			return errors.New("observation cache, transport, or digest mismatch")
		}
		if observation.RequestStarted.IsZero() || observation.ResponseObserved.Before(observation.RequestStarted) || observation.RequestStarted.Before(stage.CommittedObservedAt) || observation.ResponseObserved.Before(stage.CommittedObservedAt) {
			return errors.New("observation time is outside the published request window")
		}
		if stage.Vendor == "cloudflare" {
			if len(observation.CloudflareColo) != 3 || observation.CloudflareColo != strings.ToUpper(observation.CloudflareColo) {
				return errors.New("Cloudflare observation has no valid CF-Ray colo")
			}
		} else if observation.CloudflareColo != "" {
			return errors.New("EdgeOne observation claimed a response-derived PoP")
		}
	}
	if primeCount != 1 {
		return errors.New("stage must contain exactly one prime observation")
	}
	return nil
}

func validateRealEdgeMultiPoPPurgeTransition(before, after realEdgeMultiPoPStageEvidence) error {
	if err := validateRealEdgeMultiPoPStage(before, nil); err != nil {
		return fmt.Errorf("before stage: %w", err)
	}
	if err := validateRealEdgeMultiPoPStage(after, nil); err != nil {
		return fmt.Errorf("after stage: %w", err)
	}
	for _, vendor := range []string{"cloudflare", "edgeone"} {
		beforeBindings, err := realEdgeTransitionObserverBindings(before, vendor)
		if err != nil {
			return fmt.Errorf("before %s transition bindings: %w", vendor, err)
		}
		afterBindings, err := realEdgeTransitionObserverBindings(after, vendor)
		if err != nil {
			return fmt.Errorf("after %s transition bindings: %w", vendor, err)
		}
		if !mapsEqualRealEdgeTransitionBindings(beforeBindings, afterBindings) {
			return fmt.Errorf("%s purge transition changed observer role, node, or geography bindings", vendor)
		}
		if err := validateRealEdgePrePurgeProviderBindings(before, after, vendor, beforeBindings); err != nil {
			return fmt.Errorf("%s pre-purge provider evidence: %w", vendor, err)
		}
	}
	return validateRealEdgeActivePurgeTransition(before, after)
}

func validateRealEdgePrePurgeProviderBindings(before, after realEdgeMultiPoPStageEvidence, vendor string, wantedBindings map[string]realEdgeTransitionBinding) error {
	oldStage := before.Vendors[vendor]
	newStage := after.Vendors[vendor]
	if newStage.PrePurge == nil {
		return errors.New("pre-purge active evidence is absent")
	}
	matched := make(map[int]struct{}, len(newStage.PrePurge.Observations))
	for _, observation := range newStage.PrePurge.Observations {
		matchIndex := -1
		for index, record := range after.ProviderLogs {
			if record.ProbePhase == "pre-purge" && record.Vendor == vendor && record.Generation == oldStage.Generation && record.TransactionID == oldStage.TransactionID && record.ParentRequestID == observation.RequestID {
				if matchIndex >= 0 {
					return errors.New("pre-purge observation has duplicate provider records")
				}
				matchIndex = index
			}
		}
		if matchIndex < 0 {
			return fmt.Errorf("observer %s has no pre-purge provider record", observation.ObserverID)
		}
		if _, duplicate := matched[matchIndex]; duplicate {
			return errors.New("pre-purge provider record matched multiple observations")
		}
		matched[matchIndex] = struct{}{}
		record := after.ProviderLogs[matchIndex]
		wanted := wantedBindings[observation.ObserverID]
		if record.RunID != newStage.RunID || record.CacheStatus != "HIT" || record.CleanURLSHA256 != oldStage.CleanURLSHA256 || record.BodySHA256 != oldStage.BodySHA256 ||
			record.NodeID != wanted.NodeID || record.NodeIP != wanted.NodeIP || record.Region != wanted.Region ||
			record.observedTime.Before(observation.RequestStarted.Add(-realEdgeProviderClockSkew)) || record.observedTime.After(observation.ResponseObserved.Add(realEdgeProviderExportLag)) {
			return fmt.Errorf("observer %s pre-purge provider record is not bound to the old cached bytes on the same node", observation.ObserverID)
		}
	}
	return nil
}

type realEdgeTransitionBinding struct {
	Role   string
	NodeID string
	NodeIP string
	Region string
}

func realEdgeTransitionObserverBindings(evidence realEdgeMultiPoPStageEvidence, vendor string) (map[string]realEdgeTransitionBinding, error) {
	stage, exists := evidence.Vendors[vendor]
	if !exists {
		return nil, errors.New("vendor stage is absent")
	}
	result := make(map[string]realEdgeTransitionBinding, len(stage.Observations))
	for _, observation := range stage.Observations {
		var match *realEdgeProviderLog
		for index := range evidence.ProviderLogs {
			record := &evidence.ProviderLogs[index]
			if record.Vendor == vendor && record.Generation == stage.Generation && record.TransactionID == stage.TransactionID && record.ParentRequestID == observation.RequestID {
				if match != nil {
					return nil, errors.New("observation has duplicate provider bindings")
				}
				match = record
			}
		}
		if match == nil {
			return nil, fmt.Errorf("observer %s has no provider binding", observation.ObserverID)
		}
		result[observation.ObserverID] = realEdgeTransitionBinding{Role: observation.Role, NodeID: match.NodeID, NodeIP: match.NodeIP, Region: match.Region}
	}
	return result, nil
}

func mapsEqualRealEdgeTransitionBindings(left, right map[string]realEdgeTransitionBinding) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func validateRealEdgeActivePurgeTransition(before, after realEdgeMultiPoPStageEvidence) error {
	if len(before.Vendors) != 2 || len(after.Vendors) != 2 {
		return errors.New("active purge transition requires both vendors")
	}
	if err := validateRealEdgeEntitlementDigests(before.EntitlementSHA256); err != nil {
		return fmt.Errorf("before entitlements: %w", err)
	}
	if err := validateRealEdgeEntitlementDigests(after.EntitlementSHA256); err != nil {
		return fmt.Errorf("after entitlements: %w", err)
	}
	if !slices.Equal(before.EntitlementSHA256, after.EntitlementSHA256) {
		return errors.New("purge transition changed entitlement identities")
	}
	for _, vendor := range []string{"cloudflare", "edgeone"} {
		oldStage, oldExists := before.Vendors[vendor]
		newStage, newExists := after.Vendors[vendor]
		if !oldExists || !newExists {
			return fmt.Errorf("active purge transition is missing %s", vendor)
		}
		if err := validateRealEdgeActiveStage(oldStage); err != nil {
			return fmt.Errorf("before %s active stage: %w", vendor, err)
		}
		if err := validateRealEdgeActiveStage(newStage); err != nil {
			return fmt.Errorf("after %s active stage: %w", vendor, err)
		}
		if !sameRealEdgeRunBinding(oldStage, newStage) {
			return fmt.Errorf("%s purge transition changed destructive run binding", vendor)
		}
		if err := validateRealEdgeActivePrePurgeTransition(oldStage, newStage); err != nil {
			return fmt.Errorf("%s pre-purge active evidence: %w", vendor, err)
		}
		if newStage.Generation != oldStage.Generation+1 {
			return fmt.Errorf("%s generation did not advance by exactly one", vendor)
		}
		if newStage.TransactionID == oldStage.TransactionID {
			return fmt.Errorf("%s purge transition reused a transaction ID", vendor)
		}
		if newStage.BodySHA256 == oldStage.BodySHA256 {
			return fmt.Errorf("%s purge transition did not change protected bytes", vendor)
		}
		if newStage.CleanURLSHA256 != oldStage.CleanURLSHA256 {
			return fmt.Errorf("%s purge transition changed clean cache identity", vendor)
		}
		if !newStage.CommittedObservedAt.After(oldStage.CommittedObservedAt) {
			return fmt.Errorf("%s later publication time did not advance", vendor)
		}
		oldObservers := make(map[string]string, len(oldStage.Observations))
		oldRequests := make(map[string]struct{}, len(oldStage.Observations))
		for _, observation := range oldStage.Observations {
			oldObservers[observation.ObserverID] = observation.Role
			oldRequests[observation.RequestID] = struct{}{}
		}
		for _, observation := range newStage.Observations {
			if role, exists := oldObservers[observation.ObserverID]; !exists || role != observation.Role {
				return fmt.Errorf("%s purge transition changed observer identity or role", vendor)
			}
			if _, reused := oldRequests[observation.RequestID]; reused {
				return fmt.Errorf("%s purge transition reused an active request ID", vendor)
			}
			if observation.RequestStarted.Before(newStage.CommittedObservedAt) || observation.ResponseObserved.Before(newStage.CommittedObservedAt) {
				return fmt.Errorf("%s new-generation probe predates publication", vendor)
			}
		}
		oldProviderRequests := make(map[string]struct{})
		for _, record := range before.ProviderLogs {
			if record.Vendor == vendor && record.Generation == oldStage.Generation && record.TransactionID == oldStage.TransactionID {
				oldProviderRequests[record.RequestID] = struct{}{}
			}
		}
		for _, record := range after.ProviderLogs {
			if record.Vendor == vendor && record.Generation == newStage.Generation && record.TransactionID == newStage.TransactionID && record.observedTime.Before(newStage.CommittedObservedAt) {
				return fmt.Errorf("%s new-generation provider record predates publication", vendor)
			}
			if record.Vendor == vendor && record.Generation == newStage.Generation && record.TransactionID == newStage.TransactionID {
				if _, reused := oldProviderRequests[record.RequestID]; reused {
					return fmt.Errorf("%s purge transition reused a provider subrequest ID", vendor)
				}
			}
		}
	}
	return nil
}

func validateRealEdgeActivePrePurgeTransition(oldStage, newStage realEdgeMultiPoPVendorStage) error {
	pre := newStage.PrePurge
	if pre == nil || pre.Generation != oldStage.Generation || pre.TransactionID != oldStage.TransactionID || pre.CleanURLSHA256 != oldStage.CleanURLSHA256 || pre.BodySHA256 != oldStage.BodySHA256 {
		return errors.New("pre-purge evidence is not bound to the exact old generation")
	}
	if len(pre.Observations) != len(oldStage.Observations) || len(newStage.Observations) != len(oldStage.Observations) {
		return errors.New("pre-purge observer set is incomplete")
	}
	oldByObserver := make(map[string]realEdgeMultiPoPObservation, len(oldStage.Observations))
	newByObserver := make(map[string]realEdgeMultiPoPObservation, len(newStage.Observations))
	requestIDs := make(map[string]struct{}, len(oldStage.Observations)+len(newStage.Observations)+len(pre.Observations))
	var oldCompleted time.Time
	for _, observation := range oldStage.Observations {
		oldByObserver[observation.ObserverID] = observation
		requestIDs[observation.RequestID] = struct{}{}
		if observation.ResponseObserved.After(oldCompleted) {
			oldCompleted = observation.ResponseObserved
		}
	}
	for _, observation := range newStage.Observations {
		newByObserver[observation.ObserverID] = observation
		if _, reused := requestIDs[observation.RequestID]; reused {
			return errors.New("post-purge observation reused an earlier request ID")
		}
		requestIDs[observation.RequestID] = struct{}{}
	}
	for _, observation := range pre.Observations {
		oldObservation, oldExists := oldByObserver[observation.ObserverID]
		postObservation, postExists := newByObserver[observation.ObserverID]
		if !oldExists || !postExists || observation.Role != oldObservation.Role || postObservation.Role != oldObservation.Role {
			return errors.New("pre-purge evidence changed observer identity or role")
		}
		if _, reused := requestIDs[observation.RequestID]; reused {
			return errors.New("pre-purge observation reused an earlier request ID")
		}
		requestIDs[observation.RequestID] = struct{}{}
		if observation.CacheStatus != "HIT" || observation.Transport != "https-bearer" || observation.CleanURLSHA256 != oldStage.CleanURLSHA256 || observation.BodySHA256 != oldStage.BodySHA256 ||
			observation.RequestStarted.Before(oldCompleted) || observation.ResponseObserved.Before(observation.RequestStarted) || !observation.ResponseObserved.Before(newStage.CommittedObservedAt) {
			return errors.New("pre-purge observation is not an immediate old-body cache HIT before the new commit")
		}
		if observation.CacheAgeSeconds < 0 || observation.CacheMaxAge <= observation.CacheAgeSeconds {
			return errors.New("pre-purge observation has no positive cache freshness remainder")
		}
		remaining := time.Duration(observation.CacheMaxAge-observation.CacheAgeSeconds) * time.Second
		if remaining <= realEdgeCacheFreshnessMargin {
			return errors.New("pre-purge observation has no conservative cache freshness remainder")
		}
		freshUntil := observation.ResponseObserved.Add(remaining - realEdgeCacheFreshnessMargin)
		if !postObservation.RequestStarted.Before(freshUntil) || !postObservation.ResponseObserved.Before(freshUntil) {
			return errors.New("post-purge new bytes were not observed before the old cache entry's natural expiry")
		}
	}
	return nil
}

func requireRealEdgeJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing values")
	}
	return nil
}

func validRealEdgeProxyEnv(value string) bool {
	if !strings.HasPrefix(value, realEdgeProxyEnvPrefix) || len(value) > 128 || len(value) == len(realEdgeProxyEnvPrefix) {
		return false
	}
	for _, character := range value {
		if character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func validRealEdgeIdentifier(value string, maximum int) bool {
	if len(value) < 1 || len(value) > maximum {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func validRealEdgeTransactionID(value string) bool {
	return validRealEdgeIdentifier(value, 128)
}

func realEdgeEntitlementDigests(values ...string) []string {
	digests := make([]string, 0, len(values))
	for _, value := range values {
		digests = append(digests, fmt.Sprintf("%x", sha256.Sum256([]byte(value))))
	}
	sort.Strings(digests)
	return digests
}

func validateRealEdgeEntitlementDigests(digests []string) error {
	if len(digests) != 2 || !sort.StringsAreSorted(digests) || digests[0] == digests[1] {
		return errors.New("active evidence must bind two distinct sorted entitlement digests")
	}
	for _, digest := range digests {
		if !validRealCloudLowerSHA256(digest) {
			return errors.New("active evidence contains an invalid entitlement digest")
		}
	}
	return nil
}

func validateRealEdgeForbiddenEntitlementCoverage(digests, forbidden []string) error {
	if err := validateRealEdgeEntitlementDigests(digests); err != nil {
		return err
	}
	covered := make(map[string]struct{}, len(forbidden))
	for _, fragment := range forbidden {
		covered[fmt.Sprintf("%x", sha256.Sum256([]byte(fragment)))] = struct{}{}
	}
	for _, digest := range digests {
		if _, exists := covered[digest]; !exists {
			return errors.New("forbidden fragments do not cover the destructive run entitlements")
		}
	}
	return nil
}

func validRealEdgeRequestID(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '.' || character == '_' || character == ':' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validRealEdgeSafeText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.Contains(value, "://") || strings.ContainsAny(value, "/\\") {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

const realEdgeISO3166Alpha2 = " AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW "

var realEdgeNonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"),
	netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func validRealEdgePublicRoutableIP(value string) bool {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range realEdgeNonPublicPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func validRealEdgeEdgeOneRegion(value string) bool {
	return len(value) == 2 && strings.Contains(realEdgeISO3166Alpha2, " "+value+" ")
}

func validRealEdgeDNSName(value string) bool {
	if value == "" || len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func isRealEdgeLowerOrUpperHex(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character >= '0' && character <= '9' || character >= 'a' && character <= 'f' || character >= 'A' && character <= 'F' {
			continue
		}
		return false
	}
	return true
}

func realEdgeObserverSecretFragments(observer realEdgeObserver) []string {
	fragments := []string{observer.proxyRaw}
	if observer.proxyURL.User != nil {
		username := observer.proxyURL.User.Username()
		fragments = append(fragments, username, observer.proxyURL.User.String())
		if password, ok := observer.proxyURL.User.Password(); ok {
			plainAuthority := username + ":" + password
			basicPayload := base64.StdEncoding.EncodeToString([]byte(plainAuthority))
			fragments = append(fragments,
				password,
				plainAuthority,
				basicPayload,
				"Basic "+basicPayload,
				url.UserPassword(username, password).String(),
				url.QueryEscape(username)+":"+url.QueryEscape(password),
			)
		}
	}
	return fragments
}

func realEdgeResponseContainsForbidden(header, trailer http.Header, body []byte, forbidden []string) bool {
	var evidence strings.Builder
	for _, source := range []http.Header{header, trailer} {
		for name, values := range source {
			evidence.WriteString(name)
			evidence.WriteByte(':')
			evidence.WriteString(strings.Join(values, ","))
			evidence.WriteByte('\n')
		}
	}
	return containsRealEdgeForbidden([]byte(evidence.String()), forbidden) || containsRealEdgeForbidden(body, forbidden)
}

func containsRealEdgeForbidden(body []byte, forbidden []string) bool {
	for _, fragment := range forbidden {
		if len(fragment) >= 4 && bytes.Contains(body, []byte(fragment)) {
			return true
		}
	}
	return false
}

func containsRealEdgeURLLeak(body []byte) bool {
	lower := bytes.ToLower(body)
	for _, marker := range [][]byte{[]byte("://"), []byte("/pro/v1/"), []byte("/.sow/"), []byte(realCloudGatedAssetPath)} {
		if bytes.Contains(lower, bytes.ToLower(marker)) {
			return true
		}
	}
	return false
}

func sortedRealEdgeLogKeys(logs []realEdgeProviderLog) []string {
	keys := make([]string, 0, len(logs))
	for _, log := range logs {
		keys = append(keys, strings.Join([]string{log.Vendor, fmt.Sprint(log.Generation), log.TransactionID, log.RequestID}, "/"))
	}
	sort.Strings(keys)
	return keys
}

func TestRealEdgeObserverProxyContract(t *testing.T) {
	values := map[string]string{
		realEdgeObserversEnv: `[{
			"id":"egress-a","proxy_env":"SOW_REAL_EDGE_PROXY_A"
		},{
			"id":"egress-b","proxy_env":"SOW_REAL_EDGE_PROXY_B"
		}]`,
		"SOW_REAL_EDGE_PROXY_A": "https://observer:proxy-secret-a@proxy-a.example:8443",
		"SOW_REAL_EDGE_PROXY_B": "socks5h://observer:proxy-secret-b@proxy-b.example:1080",
	}
	lookup := func(name string) string { return values[name] }
	observers, err := loadRealEdgeObservers(lookup)
	if err != nil {
		t.Fatalf("valid observers rejected: %v", err)
	}
	if len(observers) != 2 || observers[0].ID != "egress-a" || observers[1].proxyURL.Scheme != "socks5h" {
		t.Fatalf("unexpected observers: %#v", observers)
	}
	if strings.Contains(fmt.Sprint(observers[0].ID, observers[0].ProxyEnv), "proxy-secret") {
		t.Fatal("public observer identity exposed proxy secret")
	}

	tests := []struct {
		name   string
		mutate func(map[string]string)
	}{
		{name: "one-observer", mutate: func(values map[string]string) {
			values[realEdgeObserversEnv] = `[{"id":"egress-a","proxy_env":"SOW_REAL_EDGE_PROXY_A"}]`
		}},
		{name: "unknown-json-field", mutate: func(values map[string]string) {
			values[realEdgeObserversEnv] = `[{"id":"egress-a","proxy_env":"SOW_REAL_EDGE_PROXY_A","proxy_url":"https://leak.invalid:443"},{"id":"egress-b","proxy_env":"SOW_REAL_EDGE_PROXY_B"}]`
		}},
		{name: "duplicate-id", mutate: func(values map[string]string) {
			values[realEdgeObserversEnv] = `[{"id":"egress-a","proxy_env":"SOW_REAL_EDGE_PROXY_A"},{"id":"egress-a","proxy_env":"SOW_REAL_EDGE_PROXY_B"}]`
		}},
		{name: "duplicate-proxy-env", mutate: func(values map[string]string) {
			values[realEdgeObserversEnv] = `[{"id":"egress-a","proxy_env":"SOW_REAL_EDGE_PROXY_A"},{"id":"egress-b","proxy_env":"SOW_REAL_EDGE_PROXY_A"}]`
		}},
		{name: "same-egress-endpoint", mutate: func(values map[string]string) {
			values["SOW_REAL_EDGE_PROXY_B"] = "socks5://different:credentials@proxy-a.example:8443"
		}},
		{name: "http-proxy", mutate: func(values map[string]string) {
			values["SOW_REAL_EDGE_PROXY_B"] = "http://observer:secret@proxy-b.example:1080"
		}},
		{name: "implicit-port", mutate: func(values map[string]string) {
			values["SOW_REAL_EDGE_PROXY_B"] = "https://observer:secret@proxy-b.example"
		}},
		{name: "inline-whitespace", mutate: func(values map[string]string) {
			values["SOW_REAL_EDGE_PROXY_B"] = " socks5://observer:secret@proxy-b.example:1080"
		}},
		{name: "unnamed-proxy-env", mutate: func(values map[string]string) {
			values[realEdgeObserversEnv] = `[{"id":"egress-a","proxy_env":"HTTPS_PROXY"},{"id":"egress-b","proxy_env":"SOW_REAL_EDGE_PROXY_B"}]`
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			copyValues := make(map[string]string, len(values))
			for key, value := range values {
				copyValues[key] = value
			}
			test.mutate(copyValues)
			_, err := loadRealEdgeObservers(func(name string) string { return copyValues[name] })
			if err == nil {
				t.Fatal("unsafe observer/proxy contract was accepted")
			}
			if strings.Contains(err.Error(), "proxy-secret-a") || strings.Contains(err.Error(), "proxy-secret-b") {
				t.Fatal("observer error exposed proxy credentials")
			}
		})
	}

	t.Run("observer-upper-bound", func(t *testing.T) {
		specs := make([]realEdgeObserverSpec, 0, realEdgeMaxObservers+1)
		lookupValues := map[string]string{}
		for index := 0; index <= realEdgeMaxObservers; index++ {
			environment := fmt.Sprintf("SOW_REAL_EDGE_PROXY_%d", index)
			specs = append(specs, realEdgeObserverSpec{ID: fmt.Sprintf("egress-%d", index), ProxyEnv: environment})
			lookupValues[environment] = fmt.Sprintf("socks5://observer:secret@proxy-%d.example:1080", index)
		}
		encoded, err := json.Marshal(specs)
		if err != nil {
			t.Fatal(err)
		}
		lookupValues[realEdgeObserversEnv] = string(encoded)
		if _, err := loadRealEdgeObservers(func(name string) string { return lookupValues[name] }); err == nil {
			t.Fatal("observer upper bound was not enforced")
		}
	})
}

func TestRealEdgeObserverSecretFragmentContract(t *testing.T) {
	raw := "https://observer%40site:p%40ss%3Aword@proxy-a.example:8443"
	parsed, _, err := parseRealEdgeProxyURL(raw)
	if err != nil {
		t.Fatalf("valid encoded proxy rejected: %v", err)
	}
	observer := realEdgeObserver{ID: "egress-a", ProxyEnv: "SOW_REAL_EDGE_PROXY_A", proxyURL: parsed, proxyRaw: raw}
	fragments := realEdgeObserverSecretFragments(observer)
	wantedBasic := base64.StdEncoding.EncodeToString([]byte("observer@site:p@ss:word"))
	for _, wanted := range []string{raw, "observer@site", "p@ss:word", "observer@site:p@ss:word", wantedBasic, "Basic " + wantedBasic, "observer%40site:p%40ss%3Aword"} {
		if !slices.Contains(fragments, wanted) {
			t.Fatalf("proxy secret fragment %q was not covered: %#v", wanted, fragments)
		}
	}
	for _, test := range []struct {
		name    string
		header  http.Header
		trailer http.Header
		body    []byte
	}{
		{name: "authorization-header", header: http.Header{"Proxy-Authorization": {"Basic " + wantedBasic}}},
		{name: "encoded-header-payload", header: http.Header{"X-Debug-Proxy": {wantedBasic}}},
		{name: "url-escaped-body", body: []byte("upstream=" + observer.proxyURL.User.String())},
		{name: "trailer", trailer: http.Header{"X-Proxy-Debug": {"Basic " + wantedBasic}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if !realEdgeResponseContainsForbidden(test.header, test.trailer, test.body, fragments) {
				t.Fatal("encoded proxy credential leak was not detected")
			}
		})
	}
	if realEdgeResponseContainsForbidden(http.Header{"X-Clean": {"ok"}}, nil, []byte("protected payload"), fragments) {
		t.Fatal("clean response produced a proxy-secret false positive")
	}
}

func TestRealEdgeMultiPoPPreflightContract(t *testing.T) {
	directory := t.TempDir()
	artifactPath := filepath.Join(directory, "active.jsonl")
	validValues := func() map[string]string {
		return map[string]string{
			realEdgeObserversEnv:      `[{"id":"egress-a","proxy_env":"SOW_REAL_EDGE_PROXY_A"},{"id":"egress-b","proxy_env":"SOW_REAL_EDGE_PROXY_B"}]`,
			realEdgeActiveArtifactEnv: artifactPath,
			"SOW_REAL_EDGE_PROXY_A":   "https://observer:secret-a@proxy-a.example:8443",
			"SOW_REAL_EDGE_PROXY_B":   "socks5://observer:secret-b@proxy-b.example:1080",
		}
	}
	lookup := func(values map[string]string) func(string) string {
		return func(name string) string { return values[name] }
	}
	if err := preflightRealCloudEdgeMultiPoPInputs(lookup(validValues())); err != nil {
		t.Fatalf("valid preflight rejected: %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("preflight left files behind entries=%d err=%v", len(entries), err)
	}

	t.Run("existing-artifact", func(t *testing.T) {
		if err := os.WriteFile(artifactPath, []byte("prior evidence\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(artifactPath)
		if err := preflightRealCloudEdgeMultiPoPInputs(lookup(validValues())); err == nil {
			t.Fatal("preflight accepted an existing artifact")
		}
	})

	t.Run("existing-lock", func(t *testing.T) {
		lockPath := artifactPath + ".lock"
		if err := os.WriteFile(lockPath, []byte("stale lock\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(lockPath)
		if err := preflightRealCloudEdgeMultiPoPInputs(lookup(validValues())); err == nil {
			t.Fatal("preflight accepted an existing writer lock")
		}
	})

	t.Run("symlink-parent", func(t *testing.T) {
		realDirectory := filepath.Join(directory, "real-parent")
		if err := os.Mkdir(realDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		linkDirectory := filepath.Join(directory, "linked-parent")
		if err := os.Symlink(realDirectory, linkDirectory); err != nil {
			t.Fatal(err)
		}
		values := validValues()
		values[realEdgeActiveArtifactEnv] = filepath.Join(linkDirectory, "active.jsonl")
		if err := preflightRealCloudEdgeMultiPoPInputs(lookup(values)); err == nil {
			t.Fatal("preflight accepted a symlink artifact parent")
		}
	})

	t.Run("repository-path", func(t *testing.T) {
		root, err := realEdgeRepositoryRoot()
		if err != nil {
			t.Fatal(err)
		}
		values := validValues()
		values[realEdgeActiveArtifactEnv] = filepath.Join(root, ".real-edge-active.jsonl")
		if err := preflightRealCloudEdgeMultiPoPInputs(lookup(values)); err == nil {
			t.Fatal("preflight accepted a repository-local artifact")
		}
	})

	t.Run("symlink-ancestor-into-repository", func(t *testing.T) {
		root, err := realEdgeRepositoryRoot()
		if err != nil {
			t.Fatal(err)
		}
		linkRoot := filepath.Join(directory, "repository-alias")
		if err := os.Symlink(root, linkRoot); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(linkRoot)
		values := validValues()
		values[realEdgeActiveArtifactEnv] = filepath.Join(linkRoot, "test", "compat", "ancestor-evidence.jsonl")
		if err := preflightRealCloudEdgeMultiPoPInputs(lookup(values)); err == nil {
			t.Fatal("preflight accepted an artifact path whose symlink ancestor resolves into the repository")
		}
		if _, err := os.Lstat(filepath.Join(root, "test", "compat", "ancestor-evidence.jsonl")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("ancestor-symlink preflight touched the repository")
		}
	})

	t.Run("invalid-observer-before-artifact", func(t *testing.T) {
		values := validValues()
		values[realEdgeObserversEnv] = `[{"id":"only-one","proxy_env":"SOW_REAL_EDGE_PROXY_A"}]`
		if err := preflightRealCloudEdgeMultiPoPInputs(lookup(values)); err == nil {
			t.Fatal("preflight accepted an invalid observer set")
		}
		if _, err := os.Lstat(artifactPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("invalid observer preflight touched the active artifact")
		}
	})
}

func TestRealEdgeRunReservationIdentityContract(t *testing.T) {
	path := filepath.Join(t.TempDir(), "active.jsonl")
	runID := "real-edge-reservation-run-20260714"
	release, err := acquireRealEdgeRunReservation(path, runID)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateRealEdgeRunReservation(path, runID); err != nil {
		t.Fatalf("valid run reservation rejected: %v", err)
	}
	if err := validateRealEdgeRunReservation(path, "different-reservation-run-20260714"); err == nil {
		t.Fatal("run reservation accepted a different run ID")
	}
	lockPath := path + realEdgeRunLockSuffix
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, []byte("sow-real-edge-run-lock/v1 attacker-replacement-run-20260714\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := release(); err == nil {
		t.Fatal("run reservation release deleted a replacement inode")
	}
	body, err := os.ReadFile(lockPath)
	if err != nil || !bytes.Contains(body, []byte("attacker-replacement")) {
		t.Fatal("failed release did not preserve the replacement reservation")
	}
}

func TestRealEdgePersistentRunReservationRecoveryContract(t *testing.T) {
	path := filepath.Join(t.TempDir(), "active.jsonl")
	runID := "real-edge-persistent-recovery-20260714"
	fresh, err := acquireRealEdgePersistentRunReservation(path, runID, "fresh")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireRealEdgePersistentRunReservation(path, runID, "recover"); err == nil || !strings.Contains(err.Error(), "live process") {
		t.Fatalf("concurrent live recovery err=%v", err)
	}
	if err := fresh.CloseIncomplete(); err != nil {
		t.Fatal(err)
	}
	lockPath := path + realEdgeRunLockSuffix
	if _, err := os.Lstat(lockPath); err != nil {
		t.Fatalf("incomplete close removed persistent reservation: %v", err)
	}
	if _, err := acquireRealEdgePersistentRunReservation(path, "real-edge-foreign-recovery-20260714", "recover"); err == nil || !strings.Contains(err.Error(), "another run") {
		t.Fatalf("foreign recovery err=%v", err)
	}
	recovered, err := acquireRealEdgePersistentRunReservation(path, runID, "recover")
	if err != nil {
		t.Fatalf("dead-owner recovery: %v", err)
	}
	if err := recovered.Complete(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed reservation remains: %v", err)
	}
}

func TestRealEdgePersistentRunReservationPreservesReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "active.jsonl")
	runID := "real-edge-persistent-replacement-20260714"
	reservation, err := acquireRealEdgePersistentRunReservation(path, runID, "fresh")
	if err != nil {
		t.Fatal(err)
	}
	lockPath := path + realEdgeRunLockSuffix
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	replacement := []byte("sow-real-edge-run-lock/v1 real-edge-replacement-foreign-20260714\n")
	if err := os.WriteFile(lockPath, replacement, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reservation.Complete(); err == nil {
		t.Fatal("reservation completion deleted a replacement inode")
	}
	body, err := os.ReadFile(lockPath)
	if err != nil || !bytes.Equal(body, replacement) {
		t.Fatalf("replacement reservation changed body=%q err=%v", body, err)
	}
	_ = reservation.CloseIncomplete()
}

func TestRealEdgeActiveLockIdentityContract(t *testing.T) {
	path := filepath.Join(t.TempDir(), "active.jsonl")
	release, err := acquireRealEdgeActiveArtifactLock(path)
	if err != nil {
		t.Fatal(err)
	}
	lockPath := path + ".lock"
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	replacement := []byte("sow-real-edge-active-lock/v1 attacker replacement\n")
	if err := os.WriteFile(lockPath, replacement, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := release(); err == nil {
		t.Fatal("active artifact lock release deleted a replacement inode")
	}
	body, err := os.ReadFile(lockPath)
	if err != nil || !bytes.Equal(body, replacement) {
		t.Fatalf("failed release did not preserve replacement lock body=%q err=%v", body, err)
	}
}

func TestRealEdgeBootstrapLocksRejectPartialFinalsAndIgnoreOrphans(t *testing.T) {
	for _, body := range [][]byte{nil, []byte("partial")} {
		t.Run(fmt.Sprintf("run-reservation-%d", len(body)), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "active.jsonl")
			lockPath := path + realEdgeRunLockSuffix
			if err := os.WriteFile(lockPath, body, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := acquireRealEdgePersistentRunReservation(path, "real-edge-partial-final-20260714", "recover"); err == nil {
				t.Fatal("partial run reservation final was adopted")
			}
			after, err := os.ReadFile(lockPath)
			if err != nil || !bytes.Equal(after, body) {
				t.Fatalf("partial run reservation was not preserved body=%q err=%v", after, err)
			}
		})
		t.Run(fmt.Sprintf("active-lock-%d", len(body)), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "active.jsonl")
			lockPath := path + ".lock"
			if err := os.WriteFile(lockPath, body, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := acquireRealEdgeActiveArtifactLock(path); err == nil {
				t.Fatal("partial active-artifact lock final was adopted")
			}
			after, err := os.ReadFile(lockPath)
			if err != nil || !bytes.Equal(after, body) {
				t.Fatalf("partial active lock was not preserved body=%q err=%v", after, err)
			}
		})
	}

	t.Run("orphan-temporaries", func(t *testing.T) {
		directory := t.TempDir()
		for index, body := range [][]byte{nil, []byte("partial"), []byte("complete but unlinked")} {
			if err := os.WriteFile(filepath.Join(directory, fmt.Sprintf(".sow-private-bootstrap-orphan-%d", index)), body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		path := filepath.Join(directory, "active.jsonl")
		reservation, err := acquireRealEdgePersistentRunReservation(path, "real-edge-orphan-bootstrap-20260714", "fresh")
		if err != nil {
			t.Fatal(err)
		}
		if err := reservation.Complete(); err != nil {
			t.Fatal(err)
		}
		release, err := acquireRealEdgeActiveArtifactLock(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := release(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRealEdgeResponseRequestIdentityContract(t *testing.T) {
	base, colo, err := parseRealEdgeCloudflareRay("a1b2c3d4e5f60718-SJC")
	if err != nil || base != "a1b2c3d4e5f60718" || colo != "SJC" {
		t.Fatalf("valid CF-Ray rejected: base=%s colo=%s err=%v", base, colo, err)
	}
	for _, invalid := range []string{"", "short-SJC", "a1b2c3d4e5f60718-sjc", "a1b2c3d4e5f60718-SJC,other", "not-hex-value-SJC"} {
		if _, _, err := parseRealEdgeCloudflareRay(invalid); err == nil {
			t.Fatalf("invalid CF-Ray accepted: %q", invalid)
		}
	}
	cloudflare := make(http.Header)
	cloudflare.Set("CF-Ray", "A1B2C3D4E5F60718-LHR")
	requestID, colo, err := realEdgeResponseRequestID("cloudflare", cloudflare)
	if err != nil || requestID != "a1b2c3d4e5f60718" || colo != "LHR" {
		t.Fatalf("Cloudflare request identity mismatch: id=%s colo=%s err=%v", requestID, colo, err)
	}
	edgeOne := make(http.Header)
	edgeOne.Set("EO-LOG-UUID", "550e8400-e29b-41d4-a716-446655440000")
	requestID, colo, err = realEdgeResponseRequestID("edgeone", edgeOne)
	if err != nil || requestID != "550e8400-e29b-41d4-a716-446655440000" || colo != "" {
		t.Fatalf("EdgeOne request identity mismatch: id=%s colo=%s err=%v", requestID, colo, err)
	}
}

func TestRealEdgeEvidenceForbiddenContract(t *testing.T) {
	values := map[string]string{
		realEdgeEvidenceForbiddenEnv: `["historic-token-a","historic-token-b","https://user:password@proxy.example:8443"]`,
	}
	fragments, err := loadRealEdgeEvidenceForbidden(func(name string) string { return values[name] })
	if err != nil || len(fragments) != 3 {
		t.Fatalf("valid evidence forbidden fragments rejected: fragments=%d err=%v", len(fragments), err)
	}
	for _, invalid := range []string{
		`[]`,
		`["only-one"]`,
		`["duplicate","duplicate"]`,
		`["abc","long-enough"]`,
		`["line\nbreak","long-enough"]`,
		`["valid-one","valid-two"] {}`,
	} {
		values[realEdgeEvidenceForbiddenEnv] = invalid
		if _, err := loadRealEdgeEvidenceForbidden(func(name string) string { return values[name] }); err == nil {
			t.Fatalf("invalid evidence forbidden JSON accepted: %s", invalid)
		}
	}
}

func TestRealEdgeMultiPoPValidatorContract(t *testing.T) {
	base := time.Date(2026, time.July, 14, 4, 0, 0, 0, time.UTC)
	valid := realEdgeTestEvidence(7, "protected generation seven", base)
	if err := validateRealEdgeMultiPoPStage(valid, []string{"historic-token-a", "historic-token-b", "never-present-token"}); err != nil {
		t.Fatalf("valid multi-PoP evidence rejected: %v", err)
	}
	if err := validateRealEdgeMultiPoPStage(valid, []string{"historic-token-a", "unrelated-token"}); err == nil {
		t.Fatal("provider-log secret scan accepted forbidden values that omit one destructive entitlement")
	}
	if err := validateRealEdgeMultiPoPStage(valid, append([]string(nil), valid.EntitlementSHA256...)); err == nil {
		t.Fatal("provider-log secret scan accepted entitlement digests instead of the original secret values")
	}

	tests := []struct {
		name   string
		mutate func(*realEdgeMultiPoPStageEvidence)
	}{
		{name: "same-pop", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			edgeStage := evidence.Vendors["edgeone"]
			for index := range evidence.ProviderLogs {
				if evidence.ProviderLogs[index].Vendor == "edgeone" && evidence.ProviderLogs[index].ParentRequestID == edgeStage.Observations[1].RequestID {
					evidence.ProviderLogs[index].NodeID = evidence.ProviderLogs[index-1].NodeID
					evidence.ProviderLogs[index].NodeIP = evidence.ProviderLogs[index-1].NodeIP
					evidence.ProviderLogs[index].Region = evidence.ProviderLogs[index-1].Region
				}
			}
		}},
		{name: "same-edgeone-geography", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			edgeStage := evidence.Vendors["edgeone"]
			for index := range evidence.ProviderLogs {
				if evidence.ProviderLogs[index].Vendor == "edgeone" && evidence.ProviderLogs[index].ParentRequestID == edgeStage.Observations[1].RequestID {
					evidence.ProviderLogs[index].Region = evidence.ProviderLogs[index-1].Region
				}
			}
		}},
		{name: "edgeone-noncanonical-geography", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			for index := range evidence.ProviderLogs {
				if evidence.ProviderLogs[index].Vendor == "edgeone" {
					evidence.ProviderLogs[index].Region = "NRT"
					break
				}
			}
		}},
		{name: "edgeone-invented-country", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			for index := range evidence.ProviderLogs {
				if evidence.ProviderLogs[index].Vendor == "edgeone" {
					evidence.ProviderLogs[index].Region = "ZZ"
					break
				}
			}
		}},
		{name: "edgeone-invented-subdivision", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			for index := range evidence.ProviderLogs {
				if evidence.ProviderLogs[index].Vendor == "edgeone" {
					evidence.ProviderLogs[index].Region = "US-ZZZ"
					break
				}
			}
		}},
		{name: "edgeone-special-use-node-ip", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			for index := range evidence.ProviderLogs {
				if evidence.ProviderLogs[index].Vendor == "edgeone" {
					evidence.ProviderLogs[index].NodeIP = "198.51.100.42"
					break
				}
			}
		}},
		{name: "missing-provider-log", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			evidence.ProviderLogs = evidence.ProviderLogs[:len(evidence.ProviderLogs)-1]
		}},
		{name: "missing-parent-request", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			evidence.ProviderLogs[0].ParentRequestID = ""
		}},
		{name: "wrong-parent-request", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			evidence.ProviderLogs[0].ParentRequestID = "ffffffffffffffff"
		}},
		{name: "reused-provider-subrequest", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			evidence.ProviderLogs[1].RequestID = evidence.ProviderLogs[0].RequestID
		}},
		{name: "provider-token-leak", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			evidence.ProviderLogs[0].NodeID = "forbidden-token-value"
		}},
		{name: "raw-provider-schema", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			evidence.ProviderLogs[0].Schema = ""
		}},
		{name: "cloudflare-invented-node-ip", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			evidence.ProviderLogs[0].NodeIP = "203.0.113.99"
		}},
		{name: "wrong-body-digest", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			evidence.ProviderLogs[0].BodySHA256 = strings.Repeat("f", 64)
		}},
		{name: "wrong-cache-status", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			evidence.ProviderLogs[1].CacheStatus = "MISS"
		}},
		{name: "wrong-generation", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			evidence.ProviderLogs[0].Generation++
		}},
		{name: "provider-time-before-publish", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			evidence.ProviderLogs[0].observedTime = base.Add(-time.Second)
			evidence.ProviderLogs[0].ObservedAt = evidence.ProviderLogs[0].observedTime.Format(time.RFC3339Nano)
		}},
		{name: "provider-time-after-window", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			stage := evidence.Vendors["cloudflare"]
			evidence.ProviderLogs[0].observedTime = stage.Observations[0].ResponseObserved.Add(realEdgeProviderExportLag + time.Second)
			evidence.ProviderLogs[0].ObservedAt = evidence.ProviderLogs[0].observedTime.Format(time.RFC3339Nano)
		}},
		{name: "cloudflare-colo-mismatch", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			evidence.ProviderLogs[0].Region = "FRA"
		}},
		{name: "edgeone-response-pop-claim", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			stage := evidence.Vendors["edgeone"]
			stage.Observations[0].CloudflareColo = "NRT"
			evidence.Vendors["edgeone"] = stage
		}},
		{name: "cross-pop-before-prime-completed", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			stage := evidence.Vendors["cloudflare"]
			stage.Observations[1].RequestStarted = stage.Observations[0].ResponseObserved.Add(-time.Nanosecond)
			stage.Observations[1].ResponseObserved = stage.Observations[1].RequestStarted.Add(time.Second)
			evidence.Vendors["cloudflare"] = stage
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := cloneRealEdgeEvidence(valid)
			test.mutate(&evidence)
			forbidden := []string{"historic-token-a", "historic-token-b", "forbidden-token-value"}
			if err := validateRealEdgeMultiPoPStage(evidence, forbidden); err == nil {
				t.Fatal("invalid multi-PoP evidence was accepted")
			}
		})
	}
}

func TestRealEdgeMultiPoPPurgeTransitionContract(t *testing.T) {
	base := time.Date(2026, time.July, 14, 5, 0, 0, 0, time.UTC)
	before := realEdgeTestEvidence(7, "protected generation seven", base)
	after := realEdgeTestEvidence(8, "protected generation eight", base.Add(10*time.Minute))
	after = attachRealEdgeTestPrePurge(before, after)
	if err := validateRealEdgeMultiPoPPurgeTransition(before, after); err != nil {
		t.Fatalf("valid purge transition rejected: %v", err)
	}
	activeBefore := cloneRealEdgeEvidence(before)
	activeBefore.ProviderLogs = nil
	activeAfter := cloneRealEdgeEvidence(after)
	activeAfter.ProviderLogs = nil
	if err := validateRealEdgeActivePurgeTransition(activeBefore, activeAfter); err != nil {
		t.Fatalf("active-only purge transition incorrectly required provider logs: %v", err)
	}
	if err := validateRealEdgeMultiPoPPurgeTransition(activeBefore, activeAfter); !errors.Is(err, errRealEdgeProviderLogsIncomplete) {
		t.Fatalf("full purge proof accepted active-only evidence or returned wrong error: %v", err)
	}
	t.Run("post-after-old-natural-expiry", func(t *testing.T) {
		oldStage := before.Vendors["cloudflare"]
		newStage := cloneRealEdgeEvidence(after).Vendors["cloudflare"]
		pre := newStage.PrePurge.Observations[0]
		pre.CacheAgeSeconds = 10
		pre.CacheMaxAge = 310
		newStage.PrePurge.Observations[0] = pre
		post := newStage.Observations[0]
		post.RequestStarted = pre.ResponseObserved.Add(300 * time.Second)
		post.ResponseObserved = post.RequestStarted.Add(time.Second)
		newStage.Observations[0] = post
		err := validateRealEdgeActivePrePurgeTransition(oldStage, newStage)
		if err == nil || !strings.Contains(err.Error(), "natural expiry") {
			t.Fatalf("post-expiry new bytes were not rejected by the TTL causal gate: %v", err)
		}
	})
	tests := []struct {
		name   string
		mutate func(*realEdgeMultiPoPStageEvidence)
	}{
		{name: "same-generation", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			for vendor, stage := range evidence.Vendors {
				stage.Generation = before.Vendors[vendor].Generation
				evidence.Vendors[vendor] = stage
				for index := range evidence.ProviderLogs {
					if evidence.ProviderLogs[index].Vendor == vendor {
						evidence.ProviderLogs[index].Generation = stage.Generation
					}
				}
			}
		}},
		{name: "missing-pre-purge", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			stage := evidence.Vendors["cloudflare"]
			stage.PrePurge = nil
			evidence.Vendors["cloudflare"] = stage
		}},
		{name: "pre-purge-not-hit", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			stage := evidence.Vendors["edgeone"]
			stage.PrePurge.Observations[0].CacheStatus = "MISS"
			evidence.Vendors["edgeone"] = stage
		}},
		{name: "pre-purge-freshness-expired", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			stage := evidence.Vendors["cloudflare"]
			stage.PrePurge.Observations[0].CacheMaxAge = stage.PrePurge.Observations[0].CacheAgeSeconds + 1
			evidence.Vendors["cloudflare"] = stage
		}},
		{name: "pre-purge-reused-request", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			stage := evidence.Vendors["edgeone"]
			oldRequest := stage.PrePurge.Observations[0].RequestID
			stage.PrePurge.Observations[0].RequestID = before.Vendors["edgeone"].Observations[0].RequestID
			evidence.Vendors["edgeone"] = stage
			for index := range evidence.ProviderLogs {
				if evidence.ProviderLogs[index].ProbePhase == "pre-purge" && evidence.ProviderLogs[index].ParentRequestID == oldRequest {
					evidence.ProviderLogs[index].ParentRequestID = stage.PrePurge.Observations[0].RequestID
				}
			}
		}},
		{name: "pre-purge-provider-moved-node", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			for index := range evidence.ProviderLogs {
				if evidence.ProviderLogs[index].ProbePhase == "pre-purge" && evidence.ProviderLogs[index].Vendor == "cloudflare" {
					evidence.ProviderLogs[index].NodeID = "different-edge-node"
					break
				}
			}
		}},
		{name: "same-transaction", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			for vendor, stage := range evidence.Vendors {
				oldTransaction := before.Vendors[vendor].TransactionID
				stage.TransactionID = oldTransaction
				evidence.Vendors[vendor] = stage
				for index := range evidence.ProviderLogs {
					if evidence.ProviderLogs[index].Vendor == vendor {
						evidence.ProviderLogs[index].TransactionID = oldTransaction
					}
				}
			}
		}},
		{name: "same-body", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			for vendor, stage := range evidence.Vendors {
				oldDigest := before.Vendors[vendor].BodySHA256
				stage.BodySHA256 = oldDigest
				for index := range stage.Observations {
					stage.Observations[index].BodySHA256 = oldDigest
				}
				evidence.Vendors[vendor] = stage
				for index := range evidence.ProviderLogs {
					if evidence.ProviderLogs[index].Vendor == vendor {
						evidence.ProviderLogs[index].BodySHA256 = oldDigest
					}
				}
			}
		}},
		{name: "changed-entitlements", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			evidence.EntitlementSHA256 = realEdgeEntitlementDigests("historic-token-a", "replacement-token")
		}},
		{name: "publish-time-not-advanced", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			for vendor, stage := range evidence.Vendors {
				stage.CommittedObservedAt = before.Vendors[vendor].CommittedObservedAt
				evidence.Vendors[vendor] = stage
			}
		}},
		{name: "new-probe-before-publish", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			stage := evidence.Vendors["edgeone"]
			stage.Observations[0].RequestStarted = stage.CommittedObservedAt.Add(-time.Second)
			evidence.Vendors["edgeone"] = stage
		}},
		{name: "generation-jump", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			for vendor, stage := range evidence.Vendors {
				stage.Generation++
				evidence.Vendors[vendor] = stage
				for index := range evidence.ProviderLogs {
					if evidence.ProviderLogs[index].Vendor == vendor {
						evidence.ProviderLogs[index].Generation = stage.Generation
					}
				}
			}
		}},
		{name: "changed-observer-role", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			stage := evidence.Vendors["cloudflare"]
			stage.Observations[0].ObserverID = "replacement-egress"
			evidence.Vendors["cloudflare"] = stage
		}},
		{name: "reused-active-request-id", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			stage := evidence.Vendors["edgeone"]
			oldRequest := stage.Observations[0].RequestID
			stage.Observations[0].RequestID = before.Vendors["edgeone"].Observations[0].RequestID
			evidence.Vendors["edgeone"] = stage
			for index := range evidence.ProviderLogs {
				if evidence.ProviderLogs[index].Vendor == "edgeone" && evidence.ProviderLogs[index].ParentRequestID == oldRequest {
					evidence.ProviderLogs[index].ParentRequestID = stage.Observations[0].RequestID
				}
			}
		}},
		{name: "changed-provider-node", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			for index := range evidence.ProviderLogs {
				if evidence.ProviderLogs[index].Vendor == "cloudflare" && evidence.ProviderLogs[index].ParentRequestID == evidence.Vendors["cloudflare"].Observations[0].RequestID {
					evidence.ProviderLogs[index].NodeID = "303"
				}
			}
		}},
		{name: "reused-provider-subrequest", mutate: func(evidence *realEdgeMultiPoPStageEvidence) {
			for index := range evidence.ProviderLogs {
				if evidence.ProviderLogs[index].Vendor == "edgeone" && evidence.ProviderLogs[index].ParentRequestID == evidence.Vendors["edgeone"].Observations[0].RequestID {
					evidence.ProviderLogs[index].RequestID = before.ProviderLogs[2].RequestID
				}
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := cloneRealEdgeEvidence(after)
			test.mutate(&mutated)
			if err := validateRealEdgeMultiPoPPurgeTransition(before, mutated); err == nil {
				t.Fatal("invalid purge transition was accepted")
			}
		})
	}
}

func TestRealEdgeProviderLogClosureContract(t *testing.T) {
	base := time.Date(2026, time.July, 14, 5, 30, 0, 0, time.UTC)
	before := realEdgeTestEvidence(4, "protected generation four", base)
	after := realEdgeTestEvidence(5, "protected generation five", base.Add(10*time.Minute))
	after = attachRealEdgeTestPrePurge(before, after)
	logs := append(append([]realEdgeProviderLog(nil), before.ProviderLogs...), after.ProviderLogs...)
	stages := []realEdgeMultiPoPStageEvidence{before, after}
	runID := before.Vendors["cloudflare"].RunID
	if err := validateRealEdgeProviderLogClosure(stages, logs, runID); err != nil {
		t.Fatalf("valid exact provider export rejected: %v", err)
	}
	t.Run("extra-record", func(t *testing.T) {
		mutated := append([]realEdgeProviderLog(nil), logs...)
		extra := mutated[0]
		extra.RequestID = "extra-provider-child-request"
		extra.ParentRequestID = "extra-active-parent-request"
		mutated = append(mutated, extra)
		if err := validateRealEdgeProviderLogClosure(stages, mutated, runID); err == nil {
			t.Fatal("sealed provider export with an extra record was accepted")
		}
	})
	t.Run("unknown-parent", func(t *testing.T) {
		mutated := append([]realEdgeProviderLog(nil), logs...)
		mutated[0].ParentRequestID = "unknown-active-parent-request"
		if err := validateRealEdgeProviderLogClosure(stages, mutated, runID); err == nil {
			t.Fatal("sealed provider export with an unknown parent was accepted")
		}
	})
	t.Run("reused-child", func(t *testing.T) {
		mutated := append([]realEdgeProviderLog(nil), logs...)
		mutated[len(mutated)-1].RequestID = mutated[0].RequestID
		if err := validateRealEdgeProviderLogClosure(stages, mutated, runID); err == nil {
			t.Fatal("sealed provider export with a reused child request ID was accepted")
		}
	})
}

func TestRealEdgeProviderLogFileContract(t *testing.T) {
	base := time.Date(2026, time.July, 14, 6, 0, 0, 0, time.UTC)
	evidence := realEdgeTestEvidence(9, "provider file fixture", base)
	directory := t.TempDir()
	path := filepath.Join(directory, "provider.jsonl")
	writeRealEdgeProviderLogFixture(t, path, evidence.ProviderLogs)
	logs, err := loadRealEdgeProviderLogs(path, []string{"forbidden-token"})
	if err != nil || len(logs) != 4 {
		t.Fatalf("valid provider log rejected logs=%d err=%v", len(logs), err)
	}
	if got := sortedRealEdgeLogKeys(logs); len(got) != 4 || got[0] == got[3] {
		t.Fatalf("provider log identities were not retained: %v", got)
	}

	t.Run("token-leak", func(t *testing.T) {
		leaked := append([]realEdgeProviderLog(nil), evidence.ProviderLogs...)
		leaked[0].NodeID = "forbidden-token"
		leakPath := filepath.Join(directory, "leaked.jsonl")
		writeRealEdgeProviderLogFixture(t, leakPath, leaked)
		if _, err := loadRealEdgeProviderLogs(leakPath, []string{"forbidden-token"}); err == nil {
			t.Fatal("provider token leak was accepted")
		}
	})
	t.Run("url-leak", func(t *testing.T) {
		body, err := json.Marshal(evidence.ProviderLogs[0])
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.Replace(body, []byte(`"region":"SJC"`), []byte(`"region":"https://repo.example/pro/v1/token"`), 1)
		leakPath := filepath.Join(directory, "url-leaked.jsonl")
		if err := os.WriteFile(leakPath, append(body, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadRealEdgeProviderLogs(leakPath, nil); err == nil {
			t.Fatal("provider URL leak was accepted")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		linkPath := filepath.Join(directory, "provider-link.jsonl")
		if err := os.Symlink(path, linkPath); err != nil {
			t.Fatal(err)
		}
		if _, err := loadRealEdgeProviderLogs(linkPath, nil); err == nil {
			t.Fatal("symlink provider log was accepted")
		}
	})
	t.Run("oversized", func(t *testing.T) {
		largePath := filepath.Join(directory, "provider-large.jsonl")
		if err := os.WriteFile(largePath, bytes.Repeat([]byte{'x'}, realEdgeMaxProviderLogBytes+1), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadRealEdgeProviderLogs(largePath, nil); err == nil {
			t.Fatal("oversized provider log was accepted")
		}
	})
	t.Run("append-after-exporter-seal", func(t *testing.T) {
		tamperedPath := filepath.Join(directory, "provider-tampered.jsonl")
		writeRealEdgeProviderLogFixture(t, tamperedPath, evidence.ProviderLogs)
		file, err := os.OpenFile(tamperedPath, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(evidence.ProviderLogs[0])
		if err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if _, err := file.Write(append(encoded, '\n')); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := loadRealEdgeProviderLogs(tamperedPath, nil); err == nil {
			t.Fatal("provider JSONL changed after exporter seal was accepted")
		}
	})
	t.Run("seal-from-another-run", func(t *testing.T) {
		wrongRunPath := filepath.Join(directory, "provider-wrong-run.jsonl")
		writeRealEdgeProviderLogFixture(t, wrongRunPath, evidence.ProviderLogs)
		sealBody, err := os.ReadFile(wrongRunPath + ".seal")
		if err != nil {
			t.Fatal(err)
		}
		var seal realEdgeProviderLogSeal
		if err := json.Unmarshal(sealBody, &seal); err != nil {
			t.Fatal(err)
		}
		seal.RunID = "different-real-edge-run-20260714"
		encoded, err := json.Marshal(seal)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(wrongRunPath+".seal", append(encoded, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadRealEdgeProviderLogs(wrongRunPath, nil); err == nil {
			t.Fatal("provider seal from another destructive run was accepted")
		}
	})
}

func TestRealEdgeActiveArtifactAtomicContract(t *testing.T) {
	base := time.Date(2026, time.July, 14, 7, 0, 0, 0, time.UTC)
	first := realEdgeTestEvidence(10, "artifact generation one", base)
	second := realEdgeTestEvidence(11, "artifact generation two", base.Add(10*time.Minute))
	second = attachRealEdgeTestPrePurge(first, second)
	directory := t.TempDir()
	path := filepath.Join(directory, "active.jsonl")
	releaseRun, err := acquireRealEdgeRunReservation(path, first.Vendors["cloudflare"].RunID)
	if err != nil {
		t.Fatalf("reserve active artifact test run: %v", err)
	}
	defer func() {
		if err := releaseRun(); err != nil {
			t.Errorf("release active artifact test run: %v", err)
		}
	}()
	activeFirst := cloneRealEdgeEvidence(first)
	activeFirst.ProviderLogs = nil
	if err := appendRealEdgeActiveArtifact(path, activeFirst, []string{"never-present"}); err != nil {
		t.Fatalf("write first active artifact: %v", err)
	}
	if err := appendRealEdgeActiveArtifact(path, activeFirst, []string{"never-present"}); err != nil {
		t.Fatalf("idempotent active artifact replay: %v", err)
	}
	activeSecond := cloneRealEdgeEvidence(second)
	activeSecond.ProviderLogs = nil
	if err := appendRealEdgeActiveArtifact(path, activeSecond, []string{"never-present"}); err != nil {
		t.Fatalf("append second active artifact: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("active artifact mode=%v err=%v", info.Mode().Perm(), err)
	}
	records, err := loadRealEdgeActiveArtifact(path, nil)
	if err != nil || len(records) != 4 {
		t.Fatalf("load active artifact records=%d err=%v", len(records), err)
	}
	logs := append(append([]realEdgeProviderLog(nil), first.ProviderLogs...), second.ProviderLogs...)
	stages, err := pairRealEdgeArtifactStages(records, logs)
	if err != nil || len(stages) != 2 {
		t.Fatalf("pair active artifact stages=%d err=%v", len(stages), err)
	}
	if err := validateRealEdgeMultiPoPPurgeTransition(stages[0], stages[1]); err != nil {
		t.Fatalf("artifact/provider purge validation failed: %v", err)
	}

	t.Run("exclusive-writer-lock", func(t *testing.T) {
		lockPath := path + ".lock"
		if err := os.WriteFile(lockPath, []byte("held\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		beforeBody, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := appendRealEdgeActiveArtifact(path, activeSecond, nil); err == nil {
			t.Fatal("concurrent/stale active artifact lock was ignored")
		}
		afterBody, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(beforeBody, afterBody) {
			t.Fatal("failed locked append modified the active artifact")
		}
		if err := os.Remove(lockPath); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("symlink-target", func(t *testing.T) {
		target := filepath.Join(directory, "real-active.jsonl")
		if err := os.WriteFile(target, []byte("sentinel\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(directory, "active-link.jsonl")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if err := appendRealEdgeActiveArtifact(link, activeSecond, nil); err == nil {
			t.Fatal("symlink active artifact target was accepted")
		}
		body, err := os.ReadFile(target)
		if err != nil || string(body) != "sentinel\n" {
			t.Fatalf("symlink rejection modified target body=%q err=%v", body, err)
		}
	})
}

func TestRealEdgeActiveArtifactSealContract(t *testing.T) {
	base := time.Date(2026, time.July, 14, 7, 30, 0, 0, time.UTC)
	first := realEdgeTestEvidence(4, "sealed generation four", base)
	second := attachRealEdgeTestPrePurge(first, realEdgeTestEvidence(5, "sealed generation five", base.Add(10*time.Minute)))
	first.ProviderLogs = nil
	second.ProviderLogs = nil
	path := filepath.Join(t.TempDir(), "active.jsonl")
	runID := first.Vendors["cloudflare"].RunID
	releaseRun, err := acquireRealEdgeRunReservation(path, runID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := releaseRun(); err != nil {
			t.Errorf("release sealed active artifact run: %v", err)
		}
	}()
	if err := appendRealEdgeActiveArtifact(path, first, nil); err != nil {
		t.Fatal(err)
	}
	if err := appendRealEdgeActiveArtifact(path, second, nil); err != nil {
		t.Fatal(err)
	}
	if err := sealRealEdgeActiveArtifact(path, runID); err != nil {
		t.Fatalf("seal active artifact: %v", err)
	}
	if records, err := loadRealEdgeSealedActiveArtifact(path, nil, runID); err != nil || len(records) != 4 {
		t.Fatalf("load sealed active artifact records=%d err=%v", len(records), err)
	}
	// Simulate SIGKILL after the seal link became durable but before the
	// active-artifact lock release. The idempotent sealer must adopt and remove
	// the exact stale lock even though the seal already exists.
	if err := os.WriteFile(path+".lock", []byte("sow-real-edge-active-lock/v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := sealRealEdgeActiveArtifact(path, runID); err != nil {
		t.Fatalf("recover stale post-seal lock: %v", err)
	}
	if _, err := os.Lstat(path + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("post-seal stale lock remains: %v", err)
	}
	if err := appendRealEdgeActiveArtifact(path, second, nil); err == nil {
		t.Fatal("sealed active artifact accepted another append")
	}
	if _, err := loadRealEdgeSealedActiveArtifact(path, nil, "different-real-edge-run-20260714"); err == nil {
		t.Fatal("active artifact seal was accepted for another run")
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(" \n"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRealEdgeSealedActiveArtifact(path, nil, runID); err == nil {
		t.Fatal("active artifact changed after its completion seal was accepted")
	}
}

func realEdgeTestEvidence(generation uint64, body string, publishedAt time.Time) realEdgeMultiPoPStageEvidence {
	bodyDigest := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
	evidence := realEdgeMultiPoPStageEvidence{
		Vendors: make(map[string]realEdgeMultiPoPVendorStage, 2),
		EntitlementSHA256: realEdgeEntitlementDigests(
			"historic-token-a",
			"historic-token-b",
		),
	}
	type vendorFixture struct {
		vendor      string
		cleanByte   byte
		requests    [2]string
		subrequests [2]string
		regions     [2]string
		nodes       [2]string
		ips         [2]string
	}
	fixtures := []vendorFixture{
		{vendor: "cloudflare", cleanByte: 'a', requests: [2]string{"a1b2c3d4e5f60718", "b1c2d3e4f5061728"}, subrequests: [2]string{"c1d2e3f405162738", "d1e2f30415263748"}, regions: [2]string{"SJC", "LHR"}, nodes: [2]string{"101", "202"}, ips: [2]string{"", ""}},
		{vendor: "edgeone", cleanByte: 'b', requests: [2]string{"550e8400-e29b-41d4-a716-446655440000", "650e8400-e29b-41d4-a716-446655440001"}, subrequests: [2]string{"750e8400-e29b-41d4-a716-446655440002", "850e8400-e29b-41d4-a716-446655440003"}, regions: [2]string{"JP", "DE"}, nodes: [2]string{"eo-edge-jp-1", "eo-edge-de-2"}, ips: [2]string{"8.8.8.8", "1.1.1.1"}},
	}
	for _, fixture := range fixtures {
		transaction := fmt.Sprintf("%s-tx-%d", fixture.vendor, generation)
		stage := realEdgeMultiPoPVendorStage{
			RunID: "real-edge-test-run-20260714", ConfirmationSHA256: strings.Repeat("c", 64), ConfigSHA256: strings.Repeat("d", 64),
			GenerationSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s-generation-%d", fixture.vendor, generation)))),
			CheckpointSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s-checkpoint-%d", fixture.vendor, generation)))),
			Vendor:           fixture.vendor, Generation: generation, TransactionID: transaction,
			CommittedObservedAt: publishedAt.UTC(), CleanURLSHA256: strings.Repeat(string(fixture.cleanByte), 64), BodySHA256: bodyDigest,
		}
		for index := 0; index < 2; index++ {
			requestID := fmt.Sprintf("%s-g%d", fixture.requests[index], generation)
			subrequestID := fmt.Sprintf("%s-g%d", fixture.subrequests[index], generation)
			started := publishedAt.Add(time.Minute + time.Duration(index)*time.Second).UTC()
			observed := started.Add(time.Second)
			role, status := "cross-pop", "HIT"
			if index == 0 {
				role, status = "prime", "MISS"
			}
			colo := ""
			if fixture.vendor == "cloudflare" {
				colo = fixture.regions[index]
			}
			stage.Observations = append(stage.Observations, realEdgeMultiPoPObservation{
				Vendor: fixture.vendor, Role: role, ObserverID: fmt.Sprintf("egress-%d", index+1),
				RequestID: requestID, CloudflareColo: colo, CacheStatus: status,
				Transport: "https-bearer", CleanURLSHA256: stage.CleanURLSHA256, BodySHA256: bodyDigest,
				RequestStarted: started, ResponseObserved: observed,
			})
			providerTime := started.Add(500 * time.Millisecond)
			evidence.ProviderLogs = append(evidence.ProviderLogs, realEdgeProviderLog{
				Schema: "sow-real-edge-provider-joined/v3", RunID: stage.RunID, ProbePhase: "stage", Vendor: fixture.vendor,
				RequestID: subrequestID, ParentRequestID: requestID,
				NodeID: fixture.nodes[index], NodeIP: fixture.ips[index], Region: fixture.regions[index],
				CacheStatus: status, CleanURLSHA256: stage.CleanURLSHA256, BodySHA256: bodyDigest,
				Generation: generation, TransactionID: transaction,
				ObservedAt: providerTime.Format(time.RFC3339Nano), observedTime: providerTime,
			})
		}
		evidence.Vendors[fixture.vendor] = stage
	}
	return evidence
}

func attachRealEdgeTestPrePurge(before, after realEdgeMultiPoPStageEvidence) realEdgeMultiPoPStageEvidence {
	result := cloneRealEdgeEvidence(after)
	for _, vendor := range []string{"cloudflare", "edgeone"} {
		oldStage := before.Vendors[vendor]
		newStage := result.Vendors[vendor]
		pre := &realEdgePrePurgeVendorEvidence{
			Generation: oldStage.Generation, TransactionID: oldStage.TransactionID,
			CleanURLSHA256: oldStage.CleanURLSHA256, BodySHA256: oldStage.BodySHA256,
			Observations: make([]realEdgeMultiPoPObservation, 0, len(oldStage.Observations)),
		}
		for index, oldObservation := range oldStage.Observations {
			started := newStage.CommittedObservedAt.Add(-2*time.Minute + time.Duration(index)*time.Second)
			observed := started.Add(500 * time.Millisecond)
			requestID := fmt.Sprintf("pre-%s-g%d-%d", vendor, oldStage.Generation, index)
			preObservation := realEdgeMultiPoPObservation{
				Vendor: vendor, Role: oldObservation.Role, ObserverID: oldObservation.ObserverID, RequestID: requestID,
				CloudflareColo: oldObservation.CloudflareColo, CacheStatus: "HIT", Transport: "https-bearer",
				CleanURLSHA256: oldStage.CleanURLSHA256, BodySHA256: oldStage.BodySHA256,
				CacheAgeSeconds: 60, CacheMaxAge: 3600, RequestStarted: started, ResponseObserved: observed,
			}
			pre.Observations = append(pre.Observations, preObservation)
			var oldLog realEdgeProviderLog
			for _, record := range before.ProviderLogs {
				if record.ProbePhase == "stage" && record.Vendor == vendor && record.ParentRequestID == oldObservation.RequestID {
					oldLog = record
					break
				}
			}
			providerTime := started.Add(250 * time.Millisecond)
			result.ProviderLogs = append(result.ProviderLogs, realEdgeProviderLog{
				Schema: "sow-real-edge-provider-joined/v3", RunID: newStage.RunID, ProbePhase: "pre-purge", Vendor: vendor,
				RequestID: fmt.Sprintf("pre-sub-%s-g%d-%d", vendor, oldStage.Generation, index), ParentRequestID: requestID,
				NodeID: oldLog.NodeID, NodeIP: oldLog.NodeIP, Region: oldLog.Region,
				CacheStatus: "HIT", CleanURLSHA256: oldStage.CleanURLSHA256, BodySHA256: oldStage.BodySHA256,
				Generation: oldStage.Generation, TransactionID: oldStage.TransactionID,
				ObservedAt: providerTime.Format(time.RFC3339Nano), observedTime: providerTime,
			})
		}
		newStage.PrePurge = pre
		result.Vendors[vendor] = newStage
	}
	return result
}

func cloneRealEdgeEvidence(source realEdgeMultiPoPStageEvidence) realEdgeMultiPoPStageEvidence {
	clone := realEdgeMultiPoPStageEvidence{
		Vendors:           make(map[string]realEdgeMultiPoPVendorStage, len(source.Vendors)),
		ProviderLogs:      append([]realEdgeProviderLog(nil), source.ProviderLogs...),
		EntitlementSHA256: append([]string(nil), source.EntitlementSHA256...),
	}
	for vendor, stage := range source.Vendors {
		stage.Observations = append([]realEdgeMultiPoPObservation(nil), stage.Observations...)
		if stage.PrePurge != nil {
			pre := *stage.PrePurge
			pre.Observations = append([]realEdgeMultiPoPObservation(nil), stage.PrePurge.Observations...)
			stage.PrePurge = &pre
		}
		clone.Vendors[vendor] = stage
	}
	return clone
}

func writeRealEdgeProviderLogFixture(t *testing.T, path string, logs []realEdgeProviderLog) {
	t.Helper()
	if len(logs) == 0 || !validRealCloudRunID(logs[0].RunID) {
		t.Fatal("provider log fixture requires one valid destructive run ID")
	}
	var body bytes.Buffer
	for _, record := range logs {
		if record.RunID != logs[0].RunID {
			t.Fatal("provider log fixture mixed destructive runs")
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		body.Write(encoded)
		body.WriteByte('\n')
	}
	if err := os.WriteFile(path, body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body.Bytes())
	seal := realEdgeProviderLogSeal{
		Schema: "sow-real-edge-provider-log-seal/v1", RunID: logs[0].RunID,
		SHA256: fmt.Sprintf("%x", digest), Size: int64(body.Len()),
	}
	encodedSeal, err := json.Marshal(seal)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".seal", append(encodedSeal, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
