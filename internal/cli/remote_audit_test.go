package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/verify"
	"github.com/pgsty/sow/internal/views"
)

func TestVerifyL2IsBoundedAndFSCKListsPaginatesAndFindsRemoteDrift(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "version.txt")
	if err := os.WriteFile(input, []byte("remote-audit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(arguments ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(arguments, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", "latest"); code != ExitOK {
		t.Fatalf("add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", "assets"); code != ExitOK {
		t.Fatalf("promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK {
		t.Fatalf("publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	if transport.listCalls != 0 {
		t.Fatalf("publish used ListObjectsV2 calls=%d", transport.listCalls)
	}
	transport.mutex.Unlock()
	if code, initOut, initErr := run("init", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK {
		t.Fatalf("init before fsck code=%d stdout=%s stderr=%s", code, initOut, initErr)
	}
	transport.mutex.Lock()
	transport.objects["legacy/unknown.bin"] = protocolObject{body: []byte("unknown"), sha: publishDigest([]byte("unknown")), etag: `"unknown"`}
	transport.mutex.Unlock()
	code, stdout, stderr := run("fsck", "--target", "cf", "--config", configPath, "--workers", "2", "--limit", "20")
	if code != ExitVerification || !strings.Contains(stdout, "kind=unknown") || strings.Contains(stdout, "kind=orphan") || !strings.Contains(stdout, "inventory_coverage=partial") {
		t.Fatalf("partial inventory classification code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	delete(transport.objects, "legacy/unknown.bin")
	listCallsBeforeL2 := transport.listCalls
	transport.mutex.Unlock()

	// This protocol fixture started with an empty bucket, but publish correctly
	// persisted partial coverage because it is forbidden from proving emptiness
	// with ListObjects. Simulate the result of a separately reviewed full-list
	// baseline import so L2 can exercise its complete canonical vector.
	coveragePath := filepath.Join(root, "coverage-complete")
	if err := os.WriteFile(coveragePath, []byte(remoteInventoryComplete), 0o600); err != nil {
		t.Fatal(err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	if _, _, err := canonical.InstallPaths(map[string]string{"remotes/cf/inventory.coverage": coveragePath}, "test: attest empty-bucket inventory coverage"); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr = run("verify", "--layer", "L2", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "outcome=passed") {
		t.Fatalf("clean L2 code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	extraRef, err := state.RemoteRef("cf", "latest", "stale-repo", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		t.Fatalf("canonical HEAD=%s err=%v", head, err)
	}
	if err := canonical.AdvanceRef(extraRef, plumbing.ZeroHash, head, false); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = run("verify", "--layer", "L2", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code != ExitVerification || !strings.Contains(stdout, "LOCAL_REMOTE_REF_EXTRA") {
		t.Fatalf("extra local remote ref was not detected code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	listBeforeClosureFailure := transport.listCalls
	getBeforeClosureFailure := transport.objectGets
	headBeforeClosureFailure := transport.headCalls
	transport.mutex.Unlock()
	code, stdout, stderr = run("fsck", "--target", "cf", "--config", configPath, "--workers", "2", "--limit", "20")
	if code != ExitVerification || !strings.Contains(stdout, "LOCAL_REMOTE_REF_EXTRA") {
		t.Fatalf("full fsck ignored extra local remote ref code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	if transport.listCalls != listBeforeClosureFailure || transport.objectGets != getBeforeClosureFailure || transport.headCalls != headBeforeClosureFailure {
		t.Fatalf("full fsck performed remote IO after local closure failure: list=%d/%d get=%d/%d head=%d/%d",
			transport.listCalls, listBeforeClosureFailure, transport.objectGets, getBeforeClosureFailure, transport.headCalls, headBeforeClosureFailure)
	}
	transport.mutex.Unlock()
	if err := canonical.DeleteRef(extraRef, head); err != nil {
		t.Fatal(err)
	}
	staleChannel := filepath.Join(root, ".sow", "stale-channel.json")
	if err := os.WriteFile(staleChannel, []byte("{\"stale\":true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := canonical.Apply(t.Context(), "test", "inject stale canonical channel", map[string]string{
		"remotes/cf/channels/latest/stale/el10/x86_64.json": staleChannel,
	}, nil, state.ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = run("verify", "--layer", "L2", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code != ExitVerification || !strings.Contains(stdout, "LOCAL_CHANNEL_EXTRA") {
		t.Fatalf("extra local channel was not detected code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if _, _, err := canonical.Apply(t.Context(), "test", "remove stale canonical channel", nil, nil, state.ApplyOptions{
		DeletePaths: []string{"remotes/cf/channels/latest/stale/el10/x86_64.json"},
	}); err != nil {
		t.Fatal(err)
	}
	transport.mutex.Lock()
	if transport.listCalls != listCallsBeforeL2 {
		t.Fatalf("bounded L2 used ListObjectsV2 calls=%d before=%d", transport.listCalls, listCallsBeforeL2)
	}
	pointer := transport.objects["pkg/latest"]
	pointer.sha = strings.Repeat("0", 64)
	transport.objects["pkg/latest"] = pointer
	transport.mutex.Unlock()
	code, stdout, stderr = run("verify", "--layer", "L2", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code != ExitVerification || !strings.Contains(stdout, "REMOTE_OBJECT_CHANGED") {
		t.Fatalf("L2 metadata drift code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	pointer.sha = publishDigest(pointer.body)
	transport.objects["pkg/latest"] = pointer
	// A legacy tracked object without SOW metadata is still verifiable in the
	// explicit full audit by streaming GET+SHA256.
	for key, object := range transport.objects {
		if key != publish.CheckpointKey && !strings.HasSuffix(key, "/generation.json") {
			object.sha = ""
			transport.objects[key] = object
			break
		}
	}
	transport.mutex.Unlock()
	code, stdout, stderr = run("fsck", "--target", "cf", "--config", configPath, "--workers", "3", "--limit", "20")
	if code != ExitOK || !strings.Contains(stdout, "fsck target=cf") || !strings.Contains(stdout, "inventory_coverage=complete") {
		t.Fatalf("clean remote fsck code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	if transport.listCalls < 2 {
		t.Fatalf("remote fsck did not paginate: list calls=%d", transport.listCalls)
	}
	transport.objects["legacy/CHECKSUMS"] = protocolObject{body: nil, sha: publishDigest(nil), etag: `"legacy-zero"`}
	transport.mutex.Unlock()
	code, stdout, stderr = run("fsck", "--target", "cf", "--config", configPath, "--workers", "2", "--limit", "20")
	if code != ExitVerification || !strings.Contains(stdout, "kind=zero-byte-checksum") || !strings.Contains(stdout, "orphan=1") || !strings.Contains(stdout, "zero_byte_checksums=1") {
		t.Fatalf("orphan fsck code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

func TestRemoteAuditRequiresCanonicalPurgeEvidenceClosure(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	cosBlock := `  cos:
    storage: {kind: cos, endpoint: "https://cos.ap-shanghai.myqcloud.com", bucket: repo-1250000000, region: ap-shanghai, credential: env://SOW_TEST_COS_STORAGE, unversioned_bucket_confirmed: true}
    cdn: {kind: edgeone, base_url: "https://repo-cn.test", beta_base_url: "https://beta-cn.test", distribution: zone-cn, credential: env://SOW_TEST_COS_CDN}
`
	configuration := strings.Replace(publishAssetConfig, "edge:\n", cosBlock+"edge:\n", 1)
	if err := os.WriteFile(configPath, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "purge-evidence.txt")
	if err := os.WriteFile(input, []byte("purge-evidence-audit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	t.Setenv("SOW_TEST_COS_STORAGE", `{"access_key_id":"cos-access","secret_access_key":"cos-secret"}`)
	t.Setenv("SOW_TEST_COS_CDN", `{"secret_id":"tencent-id","secret_key":"tencent-secret"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(arguments ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(arguments, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", "latest"); code != ExitOK {
		t.Fatalf("add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", "assets"); code != ExitOK {
		t.Fatalf("promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, target := range []string{"cf", "cos"} {
		if code, stdout, stderr := run("publish", "--view", "latest", "--target", target, "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK {
			t.Fatalf("publish target=%s code=%d stdout=%s stderr=%s", target, code, stdout, stderr)
		}
	}
	if code, stdout, stderr := run("init", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK {
		t.Fatalf("init code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	coveragePath := filepath.Join(root, "coverage-complete")
	if err := os.WriteFile(coveragePath, []byte(remoteInventoryComplete), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := canonical.InstallPaths(map[string]string{
		remoteStatePath("cf", "inventory.coverage"):  coveragePath,
		remoteStatePath("cos", "inventory.coverage"): coveragePath,
	}, "attest complete remote inventories"); err != nil {
		t.Fatal(err)
	}

	type evidenceFixture struct {
		target         string
		statePath      string
		body           []byte
		planPath       string
		planBody       []byte
		checkpointPath string
		checkpointBody []byte
	}
	fixtures := make(map[string]evidenceFixture, 2)
	for _, target := range []string{"cf", "cos"} {
		generation, _, exists, err := readLocalTargetGeneration(canonical, target)
		if err != nil || !exists {
			t.Fatalf("target=%s generation exists=%t err=%v", target, exists, err)
		}
		checkpoint, _, exists, err := readLocalTargetCheckpoint(canonical, target)
		if err != nil || !exists {
			t.Fatalf("target=%s checkpoint exists=%t err=%v", target, exists, err)
		}
		statePath := remoteStatePath(target, filepath.ToSlash(filepath.Join("purges", fmt.Sprintf("%020d-%s.json", generation.Generation, checkpoint.TransactionID))))
		body, exists, err := readOptionalCanonical(canonical, statePath)
		if err != nil || !exists {
			t.Fatalf("target=%s purge evidence exists=%t err=%v", target, exists, err)
		}
		if _, err := publish.DecodePurgeEvidence(body); err != nil {
			t.Fatalf("target=%s decode purge evidence: %v", target, err)
		}
		planPath := remoteStatePath(target, "plan.json")
		planBody, exists, err := readOptionalCanonical(canonical, planPath)
		if err != nil || !exists {
			t.Fatalf("target=%s plan exists=%t err=%v", target, exists, err)
		}
		checkpointPath := remoteStatePath(target, "checkpoint.json")
		checkpointBody, exists, err := readOptionalCanonical(canonical, checkpointPath)
		if err != nil || !exists {
			t.Fatalf("target=%s canonical checkpoint exists=%t err=%v", target, exists, err)
		}
		fixtures[target] = evidenceFixture{
			target: target, statePath: statePath, body: body,
			planPath: planPath, planBody: planBody,
			checkpointPath: checkpointPath, checkpointBody: checkpointBody,
		}
		if code, stdout, stderr := run("verify", "--layer", "L2", "--view", "latest", "--target", target, "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK || !strings.Contains(stdout, "outcome=passed") {
			t.Fatalf("positive L2 target=%s code=%d stdout=%s stderr=%s", target, code, stdout, stderr)
		}
		if code, stdout, stderr := run("fsck", "--target", target, "--config", configPath, "--workers", "2", "--limit", "20"); code != ExitOK || !strings.Contains(stdout, "fsck target="+target) {
			t.Fatalf("positive fsck target=%s code=%d stdout=%s stderr=%s", target, code, stdout, stderr)
		}
		if target == "cos" {
			lockKey, _ := publish.GenerationLockKey(generation.Generation)
			transport.mutex.Lock()
			lockObject, lockExists := transport.cosObjects[lockKey]
			delete(transport.cosObjects, lockKey)
			transport.mutex.Unlock()
			if !lockExists {
				t.Fatalf("COS fixture has no generation lock %s", lockKey)
			}
			if code, stdout, stderr := run("verify", "--layer", "L2", "--view", "latest", "--target", "cos", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitVerification || !strings.Contains(stdout, "REMOTE_GENERATION_LOCK_MISSING") {
				t.Fatalf("missing COS lock L2 code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			transport.mutex.Lock()
			transport.cosObjects[lockKey] = lockObject
			transport.mutex.Unlock()
		}
	}

	fixtureDir := t.TempDir()
	installEvidence := func(t *testing.T, fixture evidenceFixture, body []byte) {
		t.Helper()
		source := filepath.Join(fixtureDir, fixture.target+"-purge-evidence.json")
		if err := os.WriteFile(source, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := canonical.InstallPaths(map[string]string{fixture.statePath: source}, "replace canonical purge evidence"); err != nil {
			t.Fatal(err)
		}
	}
	deleteEvidence := func(t *testing.T, fixture evidenceFixture) {
		t.Helper()
		if _, _, err := canonical.Apply(t.Context(), "test", "delete canonical purge evidence", nil, nil, state.ApplyOptions{DeletePaths: []string{fixture.statePath}}); err != nil {
			t.Fatal(err)
		}
	}
	mutateEvidence := func(t *testing.T, original []byte, mutate func(*publish.PurgeEvidence)) []byte {
		t.Helper()
		evidence, err := publish.DecodePurgeEvidence(original)
		if err != nil {
			t.Fatal(err)
		}
		mutate(&evidence)
		body, err := evidence.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	wrongZone := func(t *testing.T, original []byte, zoneID string) []byte {
		t.Helper()
		return mutateEvidence(t, original, func(evidence *publish.PurgeEvidence) {
			latestFull := -1
			for index := range evidence.Attempts {
				if evidence.Attempts[index].Purpose == publish.PurgeAttemptFull {
					latestFull = index
				}
			}
			if latestFull < 0 {
				t.Fatal("published purge evidence has no full attempt")
			}
			for index := range evidence.Attempts[latestFull].Batches {
				evidence.Attempts[latestFull].Batches[index].ZoneID = zoneID
			}
		})
	}
	tests := []struct {
		name       string
		target     string
		code       string
		verifyCode int
		delete     bool
		mutateBody func(*testing.T, []byte) []byte
	}{
		{name: "missing", target: "cf", code: "LOCAL_PURGE_EVIDENCE_MISSING", verifyCode: ExitInternal, delete: true},
		{name: "tamper", target: "cf", code: "LOCAL_PURGE_EVIDENCE_INVALID", verifyCode: ExitVerification, mutateBody: func(_ *testing.T, body []byte) []byte {
			return append(append([]byte(nil), body...), ' ')
		}},
		{name: "binding-tamper", target: "cf", code: "LOCAL_PURGE_EVIDENCE_INVALID", verifyCode: ExitVerification, mutateBody: func(t *testing.T, body []byte) []byte {
			return mutateEvidence(t, body, func(evidence *publish.PurgeEvidence) {
				evidence.PlanSHA256 = strings.Repeat("0", 64)
			})
		}},
		{name: "incomplete-latest-full", target: "cf", code: "LOCAL_PURGE_EVIDENCE_INCOMPLETE", verifyCode: ExitInternal, mutateBody: func(t *testing.T, body []byte) []byte {
			return mutateEvidence(t, body, func(evidence *publish.PurgeEvidence) {
				for attemptIndex := len(evidence.Attempts) - 1; attemptIndex >= 0; attemptIndex-- {
					if evidence.Attempts[attemptIndex].Purpose != publish.PurgeAttemptFull {
						continue
					}
					for batchIndex := range evidence.Attempts[attemptIndex].Batches {
						receipt := &evidence.Attempts[attemptIndex].Batches[batchIndex]
						receipt.Status = publish.PurgeReceiptAccepted
						receipt.CompletedRequestID = ""
						receipt.CompletedObservedAt = ""
					}
					break
				}
			})
		}},
		{name: "wrong-cloudflare-zone", target: "cf", code: "LOCAL_PURGE_EVIDENCE_PROVIDER_CHANGED", verifyCode: ExitVerification, mutateBody: func(t *testing.T, body []byte) []byte {
			return wrongZone(t, body, "wrong-zone")
		}},
		{name: "wrong-edgeone-distribution", target: "cos", code: "LOCAL_PURGE_EVIDENCE_PROVIDER_CHANGED", verifyCode: ExitVerification, mutateBody: func(t *testing.T, body []byte) []byte {
			return wrongZone(t, body, "wrong-distribution")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := fixtures[test.target]
			if test.delete {
				deleteEvidence(t, fixture)
			} else {
				installEvidence(t, fixture, test.mutateBody(t, fixture.body))
			}
			defer installEvidence(t, fixture, fixture.body)
			transport.mutex.Lock()
			listBefore, headBefore, getBefore := transport.listCalls, transport.headCalls, transport.objectGets
			transport.mutex.Unlock()
			code, stdout, stderr := run("verify", "--layer", "L2", "--view", "latest", "--target", test.target, "--config", configPath, "--repo", "assets", "--workers", "2")
			if code != test.verifyCode || !strings.Contains(stdout, "severity=critical") || !strings.Contains(stdout, "code="+test.code) {
				t.Fatalf("L2 target=%s code=%d stdout=%s stderr=%s", test.target, code, stdout, stderr)
			}
			code, stdout, stderr = run("fsck", "--target", test.target, "--config", configPath, "--workers", "2", "--limit", "20")
			if code != ExitVerification || !strings.Contains(stdout, "severity=critical") || !strings.Contains(stdout, "code="+test.code) {
				t.Fatalf("fsck target=%s code=%d stdout=%s stderr=%s", test.target, code, stdout, stderr)
			}
			transport.mutex.Lock()
			listAfter, headAfter, getAfter := transport.listCalls, transport.headCalls, transport.objectGets
			transport.mutex.Unlock()
			if listAfter != listBefore || headAfter != headBefore || getAfter != getBefore {
				t.Fatalf("invalid canonical closure reached remote target=%s list=%d/%d head=%d/%d get=%d/%d", test.target, listBefore, listAfter, headBefore, headAfter, getBefore, getAfter)
			}
		})
	}

	// Put Cloudflare one generation ahead, then damage only its canonical purge
	// receipt. The next dual-target invocation must quarantine that target while
	// allowing the independently lagging COS target to commit the same desired
	// ref vector.
	if err := os.WriteFile(input, []byte("purge-evidence-audit-v2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", "latest", "--replace"); code != ExitOK {
		t.Fatalf("replacement add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", "assets"); code != ExitOK {
		t.Fatalf("replacement promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK {
		t.Fatalf("advance cf code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	cfGeneration, _, exists, err := readLocalTargetGeneration(canonical, "cf")
	if err != nil || !exists {
		t.Fatalf("advanced cf generation exists=%t err=%v", exists, err)
	}
	cfCheckpoint, _, exists, err := readLocalTargetCheckpoint(canonical, "cf")
	if err != nil || !exists {
		t.Fatalf("advanced cf checkpoint exists=%t err=%v", exists, err)
	}
	brokenCFReceipt := remoteStatePath("cf", filepath.ToSlash(filepath.Join("purges", fmt.Sprintf("%020d-%s.json", cfGeneration.Generation, cfCheckpoint.TransactionID))))
	if _, _, err := canonical.Apply(t.Context(), "test", "delete ahead target purge evidence", nil, nil, state.ApplyOptions{DeletePaths: []string{brokenCFReceipt}}); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run("publish", "--view", "latest", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code != ExitPartialPublish || !strings.Contains(stdout, "target=cf view=latest status=failed-preflight-verification") ||
		!strings.Contains(stdout, "target=cos view=latest") || !strings.Contains(stdout, "target=cos view=latest generation=2") || !strings.Contains(stdout, "status=published") {
		t.Fatalf("dual-target isolated preflight code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	cosGeneration, _, exists, err := readLocalTargetGeneration(canonical, "cos")
	if err != nil || !exists || cosGeneration.Generation != cfGeneration.Generation {
		t.Fatalf("healthy cos generation=%d exists=%t err=%v want=%d", cosGeneration.Generation, exists, err, cfGeneration.Generation)
	}
}

func TestCanonicalPurgeEvidenceIsOptionalForPurgeFreePlan(t *testing.T) {
	finding, err := inspectCanonicalPurgeEvidence(nil, nil, "cf", publish.TargetGeneration{}, nil, publish.Checkpoint{}, nil, publish.Plan{})
	if err != nil || finding != nil {
		t.Fatalf("purge-free plan finding=%#v err=%v", finding, err)
	}
}

func TestCanonicalPurgeLedgerAuditsHistoricalReceiptsBeforeNetwork(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "ledger.txt")
	if err := os.WriteFile(input, []byte("ledger-v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(arguments ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(arguments, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	publishVersion := func(t *testing.T, body string, replace bool) {
		t.Helper()
		if err := os.WriteFile(input, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		arguments := []string{"add", input, "--config", configPath, "--repo", "assets", "--dest", "latest"}
		if replace {
			arguments = append(arguments, "--replace")
		}
		if code, stdout, stderr := run(arguments...); code != ExitOK {
			t.Fatalf("add %q code=%d stdout=%s stderr=%s", body, code, stdout, stderr)
		}
		if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", "assets"); code != ExitOK {
			t.Fatalf("promote %q code=%d stdout=%s stderr=%s", body, code, stdout, stderr)
		}
		if code, stdout, stderr := run("publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK {
			t.Fatalf("publish %q code=%d stdout=%s stderr=%s", body, code, stdout, stderr)
		}
	}
	publishVersion(t, "ledger-v1\n", false)
	publishVersion(t, "ledger-v2\n", true)
	canonical := state.New(filepath.Join(root, ".sow"))
	generation2, _, exists, err := readLocalTargetGeneration(canonical, "cf")
	if err != nil || !exists || generation2.Generation != 2 {
		t.Fatalf("generation2=%#v exists=%t err=%v", generation2, exists, err)
	}
	checkpoint2, _, exists, err := readLocalTargetCheckpoint(canonical, "cf")
	if err != nil || !exists {
		t.Fatalf("checkpoint2 exists=%t err=%v", exists, err)
	}
	receipt2Path := purgeLedgerReceiptPath("cf", generation2.Generation, checkpoint2.TransactionID)
	receipt2Body, exists, err := readOptionalCanonical(canonical, receipt2Path)
	if err != nil || !exists {
		t.Fatalf("generation2 receipt exists=%t err=%v", exists, err)
	}
	rotatedConfig := strings.Replace(publishAssetConfig, "zone_id: zone-test", "zone_id: zone-next", 1)
	if err := os.WriteFile(configPath, []byte(rotatedConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("init", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK {
		t.Fatalf("record provider-zone rotation code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	publishVersion(t, "ledger-v3\n", true)
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	coverage := filepath.Join(t.TempDir(), "coverage")
	if err := os.WriteFile(coverage, []byte(remoteInventoryComplete), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := canonical.InstallPaths(map[string]string{remoteStatePath("cf", "inventory.coverage"): coverage}, "test: attest complete inventory"); err != nil {
		t.Fatal(err)
	}
	if findings, err := inspectCanonicalPurgeLedger(canonical, cfg, "cf"); err != nil || len(findings) != 0 {
		t.Fatalf("valid purge ledger findings=%#v err=%v", findings, err)
	}
	install := func(t *testing.T, statePath string, body []byte, message string) {
		t.Helper()
		source := filepath.Join(t.TempDir(), filepath.Base(statePath))
		if err := os.WriteFile(source, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := canonical.InstallPaths(map[string]string{statePath: source}, message); err != nil {
			t.Fatal(err)
		}
	}
	hasCode := func(findings []verify.Finding, code string) bool {
		for _, finding := range findings {
			if finding.Code == code {
				return true
			}
		}
		return false
	}

	if _, _, err := canonical.Apply(t.Context(), "test", "delete historical purge receipt", nil, nil, state.ApplyOptions{DeletePaths: []string{receipt2Path}}); err != nil {
		t.Fatal(err)
	}
	findings, err := inspectCanonicalPurgeLedger(canonical, cfg, "cf")
	if err != nil || !hasCode(findings, "LOCAL_PURGE_EVIDENCE_MISSING") {
		t.Fatalf("missing historical receipt findings=%#v err=%v", findings, err)
	}
	transport.mutex.Lock()
	before := [3]int{transport.listCalls, transport.headCalls, transport.objectGets}
	transport.mutex.Unlock()
	if code, stdout, stderr := run("verify", "--layer", "L2", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitInternal || !strings.Contains(stdout, "LOCAL_PURGE_EVIDENCE_MISSING") {
		t.Fatalf("historical ledger L2 code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("fsck", "--target", "cf", "--config", configPath, "--workers", "2", "--limit", "20"); code != ExitVerification || !strings.Contains(stdout, "LOCAL_PURGE_EVIDENCE_MISSING") {
		t.Fatalf("historical ledger fsck code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("fsck", "--adopt-remote-inventory", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitVerification || !strings.Contains(stderr, "LOCAL_PURGE_EVIDENCE_MISSING") {
		t.Fatalf("historical ledger adoption preflight code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	after := [3]int{transport.listCalls, transport.headCalls, transport.objectGets}
	transport.mutex.Unlock()
	if after != before {
		t.Fatalf("historical ledger failure touched remote before=%v after=%v", before, after)
	}
	install(t, receipt2Path, receipt2Body, "test: restore historical purge receipt")

	install(t, receipt2Path, append(append([]byte(nil), receipt2Body...), '\n'), "test: mutate historical purge receipt")
	findings, err = inspectCanonicalPurgeLedger(canonical, cfg, "cf")
	if err != nil || !hasCode(findings, "LOCAL_PURGE_EVIDENCE_CHANGED") {
		t.Fatalf("changed historical receipt findings=%#v err=%v", findings, err)
	}
	install(t, receipt2Path, receipt2Body, "test: restore historical receipt bytes")

	orphanPath := purgeLedgerReceiptPath("cf", 99, checkpoint2.TransactionID)
	install(t, orphanPath, receipt2Body, "test: add wrong-path historical purge receipt")
	findings, err = inspectCanonicalPurgeLedger(canonical, cfg, "cf")
	if err != nil || !hasCode(findings, "LOCAL_PURGE_EVIDENCE_INVALID") {
		t.Fatalf("wrong-path historical receipt findings=%#v err=%v", findings, err)
	}
}

func TestPublishNoOpPathsRequireCanonicalPurgeEvidence(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "no-op-evidence.txt")
	if err := os.WriteFile(input, []byte("no-op-purge-evidence\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token","basic_username":"verifier","basic_password":"verify-secret"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(arguments ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(arguments, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", "latest"); code != ExitOK {
		t.Fatalf("add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", "assets"); code != ExitOK {
		t.Fatalf("initial promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	type receiptFixture struct {
		statePath string
		body      []byte
		planPath  string
		planBody  []byte
	}
	currentReceipt := func(t *testing.T) receiptFixture {
		t.Helper()
		generation, _, exists, err := readLocalTargetGeneration(canonical, "cf")
		if err != nil || !exists {
			t.Fatalf("current generation exists=%t err=%v", exists, err)
		}
		checkpoint, _, exists, err := readLocalTargetCheckpoint(canonical, "cf")
		if err != nil || !exists {
			t.Fatalf("current checkpoint exists=%t err=%v", exists, err)
		}
		planBody, exists, err := readOptionalCanonical(canonical, remoteStatePath("cf", "plan.json"))
		if err != nil || !exists {
			t.Fatalf("current plan exists=%t err=%v", exists, err)
		}
		plan, err := publish.DecodePlan(planBody)
		if err != nil || len(plan.PurgeURLs) == 0 {
			t.Fatalf("current plan purge_urls=%d err=%v", len(plan.PurgeURLs), err)
		}
		statePath := remoteStatePath("cf", filepath.ToSlash(filepath.Join("purges", fmt.Sprintf("%020d-%s.json", generation.Generation, checkpoint.TransactionID))))
		body, exists, err := readOptionalCanonical(canonical, statePath)
		if err != nil || !exists {
			t.Fatalf("current receipt exists=%t err=%v", exists, err)
		}
		return receiptFixture{statePath: statePath, body: body, planPath: remoteStatePath("cf", "plan.json"), planBody: planBody}
	}
	replaceReceipt := func(t *testing.T, fixture receiptFixture, body []byte) {
		t.Helper()
		source := filepath.Join(t.TempDir(), "purge-evidence.json")
		if err := os.WriteFile(source, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := canonical.InstallPaths(map[string]string{fixture.statePath: source}, "test: replace no-op purge evidence"); err != nil {
			t.Fatal(err)
		}
	}
	removeReceipt := func(t *testing.T, fixture receiptFixture) {
		t.Helper()
		if _, _, err := canonical.Apply(t.Context(), "test", "delete no-op purge evidence", nil, nil, state.ApplyOptions{DeletePaths: []string{fixture.statePath}}); err != nil {
			t.Fatal(err)
		}
	}
	replacePlan := func(t *testing.T, fixture receiptFixture, body []byte) {
		t.Helper()
		source := filepath.Join(t.TempDir(), "plan.json")
		if err := os.WriteFile(source, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := canonical.InstallPaths(map[string]string{fixture.planPath: source}, "test: replace canonical plan"); err != nil {
			t.Fatal(err)
		}
	}
	assertNoOpFailure := func(t *testing.T, expectedCode string, arguments ...string) {
		t.Helper()
		putsBefore, purgesBefore, cdnBefore := transport.counts()
		code, stdout, stderr := run(arguments...)
		putsAfter, purgesAfter, cdnAfter := transport.counts()
		if code != ExitVerification || !strings.Contains(stderr, expectedCode) || strings.Contains(stdout, "status=unchanged") ||
			putsAfter != putsBefore || purgesAfter != purgesBefore || cdnAfter != cdnBefore {
			t.Fatalf("no-op gate code=%d stdout=%s stderr=%s puts=%d/%d purges=%d/%d cdn=%d/%d", code, stdout, stderr, putsBefore, putsAfter, purgesBefore, purgesAfter, cdnBefore, cdnAfter)
		}
	}
	assertPlanSubstitutionFails := func(t *testing.T, fixture receiptFixture, arguments ...string) {
		t.Helper()
		purgeFreeBody, err := (publish.Plan{}).Canonical()
		if err != nil {
			t.Fatal(err)
		}
		replacePlan(t, fixture, purgeFreeBody)
		removeReceipt(t, fixture)
		defer replacePlan(t, fixture, fixture.planBody)
		defer replaceReceipt(t, fixture, fixture.body)
		assertNoOpFailure(t, "LOCAL_PLAN_BINDING_INVALID", arguments...)
	}
	mutateZone := func(t *testing.T, body []byte) []byte {
		t.Helper()
		evidence, err := publish.DecodePurgeEvidence(body)
		if err != nil {
			t.Fatal(err)
		}
		latestFull := -1
		for index := range evidence.Attempts {
			if evidence.Attempts[index].Purpose == publish.PurgeAttemptFull {
				latestFull = index
			}
		}
		if latestFull < 0 {
			t.Fatal("canonical receipt has no full attempt")
		}
		for index := range evidence.Attempts[latestFull].Batches {
			evidence.Attempts[latestFull].Batches[index].ZoneID = "wrong-nonempty-zone"
		}
		mutated, err := evidence.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		return mutated
	}

	// Generation 1 establishes the mutable latest pointer. Its first publication
	// needs no cache purge because no prior pointer can be stale.
	if code, stdout, stderr := run("publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK || !strings.Contains(stdout, "status=published") {
		t.Fatalf("initial latest publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if err := os.WriteFile(input, []byte("no-op-purge-evidence-v2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", "latest", "--replace"); code != ExitOK {
		t.Fatalf("replacement add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", "assets"); code != ExitOK {
		t.Fatalf("replacement promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	// Generation 2 overwrites that pointer and therefore must create a nonempty
	// purge plan plus the canonical evidence closure guarded below.
	if code, stdout, stderr := run("publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK || !strings.Contains(stdout, "status=published") {
		t.Fatalf("replacement latest publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK || !strings.Contains(stdout, "status=unchanged preflight=ref-vector") {
		t.Fatalf("positive preflight no-op code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	latestReceipt := currentReceipt(t)
	t.Run("preflight-missing", func(t *testing.T) {
		removeReceipt(t, latestReceipt)
		defer replaceReceipt(t, latestReceipt, latestReceipt.body)
		assertNoOpFailure(t, "LOCAL_PURGE_EVIDENCE_MISSING", "publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	})
	t.Run("preflight-tampered", func(t *testing.T) {
		replaceReceipt(t, latestReceipt, append(append([]byte(nil), latestReceipt.body...), ' '))
		defer replaceReceipt(t, latestReceipt, latestReceipt.body)
		assertNoOpFailure(t, "LOCAL_PURGE_EVIDENCE_INVALID", "publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	})
	if code, stdout, stderr := run("promote", "latest", "stable", "--config", configPath, "--repo", "assets"); code != ExitOK {
		t.Fatalf("stable promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	snapshotID, err := views.SnapshotID("all", timeNowUTC())
	if err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("promote", "stable", snapshotID, "--config", configPath, "--repo", "assets"); code != ExitOK {
		t.Fatalf("snapshot promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("publish", "--snapshot", snapshotID, "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK || !strings.Contains(stdout, "status=published") {
		t.Fatalf("initial snapshot publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("publish", "--snapshot", snapshotID, "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK || !strings.Contains(stdout, "status=unchanged") || strings.Contains(stdout, "preflight=ref-vector") {
		t.Fatalf("positive equality no-op code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	snapshotReceipt := currentReceipt(t)
	t.Run("equality-missing", func(t *testing.T) {
		removeReceipt(t, snapshotReceipt)
		defer replaceReceipt(t, snapshotReceipt, snapshotReceipt.body)
		assertNoOpFailure(t, "LOCAL_PURGE_EVIDENCE_MISSING", "publish", "--snapshot", snapshotID, "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	})
	t.Run("equality-wrong-zone", func(t *testing.T) {
		replaceReceipt(t, snapshotReceipt, mutateZone(t, snapshotReceipt.body))
		defer replaceReceipt(t, snapshotReceipt, snapshotReceipt.body)
		assertNoOpFailure(t, "LOCAL_PURGE_EVIDENCE_PROVIDER_CHANGED", "publish", "--snapshot", snapshotID, "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	})
	t.Run("equality-purge-free-plan-substitution", func(t *testing.T) {
		assertPlanSubstitutionFails(t, snapshotReceipt, "publish", "--snapshot", snapshotID, "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	})
}

func TestRemoteInventoryPersistsControlAndPlanObjectsButRemainsPartial(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "version.txt")
	if err := os.WriteFile(input, []byte("inventory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	var stdout, stderr bytes.Buffer
	if code := Main([]string{"add", input, "--config", configPath, "--repo", "assets", "--dest", "latest"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("add code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Main([]string{"promote", "beta", "latest", "--config", configPath, "--repo", "assets"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("promote code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Main([]string{"publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("publish code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	inventory, err := os.Open(filepath.Join(root, ".sow", "state", "remotes", "cf", "inventory.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	defer inventory.Close()
	reader := manifest.NewReader(inventory)
	seen := make(map[string]bool)
	for {
		entry, err := reader.Next()
		if errorsIsEOF(err) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		seen[entry.Path] = true
	}
	if !seen[publish.CheckpointKey] || !seen["pkg/latest"] {
		t.Fatalf("inventory omitted checkpoint or pointer: %v", seen)
	}
	generation, _, exists, err := readLocalTargetGeneration(state.New(filepath.Join(root, ".sow")), "cf")
	if err != nil || !exists {
		t.Fatalf("generation exists=%v err=%v", exists, err)
	}
	generationKey, _ := publish.GenerationKey(generation.Generation)
	if !seen[generationKey] {
		t.Fatalf("inventory omitted generation %s", generationKey)
	}
	coverage, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "inventory.coverage"))
	if err != nil || string(coverage) != remoteInventoryPartial {
		t.Fatalf("coverage=%q err=%v", coverage, err)
	}
}

func publishDigest(body []byte) string { return digestBytesCLI(body) }

func errorsIsEOF(err error) bool { return err == io.EOF }

func TestRemoteInventoryMergeRetainsImmutableHistoryAndUpsertsMutableKeys(t *testing.T) {
	oldGeneration, _ := remoteInventoryEntry(".sow/generations/00000000000000000001/generation.json", 3, publishDigest([]byte("one")))
	oldPointer, _ := remoteInventoryEntry("pkg/latest", 3, publishDigest([]byte("old")))
	newGeneration, _ := remoteInventoryEntry(".sow/generations/00000000000000000002/generation.json", 3, publishDigest([]byte("two")))
	newPointer, _ := remoteInventoryEntry("pkg/latest", 3, publishDigest([]byte("new")))
	var parent bytes.Buffer
	for _, entry := range []manifest.Entry{oldGeneration, oldPointer} {
		if err := manifest.WriteEntry(&parent, entry); err != nil {
			t.Fatal(err)
		}
	}
	destination := filepath.Join(t.TempDir(), "inventory.tsv")
	if err := writeMergedRemoteInventory(&parent, map[string]manifest.Entry{
		newGeneration.Path: newGeneration,
		newPointer.Path:    newPointer,
	}, destination); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader := manifest.NewReader(file)
	got := make(map[string]string)
	for {
		entry, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got[entry.Path] = entry.HashString()
	}
	if got[oldGeneration.Path] != oldGeneration.HashString() || got[newGeneration.Path] != newGeneration.HashString() || got[newPointer.Path] != newPointer.HashString() || len(got) != 3 {
		t.Fatalf("unexpected cumulative inventory: %v", got)
	}
	if got[oldPointer.Path] == oldPointer.HashString() {
		t.Fatal("mutable pointer retained its old digest")
	}
}

func TestRemoteAuditKeyRedactsBearerSegments(t *testing.T) {
	const secret = "abcdefghijklmnopqrstuvwxyz0123456789"
	redacted := redactRemoteAuditKey("pro/v1/" + secret + "/repo/file")
	if strings.Contains(redacted, secret) || redacted != "pro/v1/REDACTED/repo/file" {
		t.Fatalf("remote audit key leaked bearer segment: %s", redacted)
	}
}

func TestFSCKAdoptRemoteInventoryIsStableIdempotentAndAvoidsPayloadRetransfer(t *testing.T) {
	root, configPath, transport, run := prepareRemoteAdoptionAsset(t, "cf")
	payload, err := os.ReadFile(filepath.Join(root, "pkg", "release.bin"))
	if err != nil {
		t.Fatal(err)
	}
	transport.mutex.Lock()
	transport.objects["pkg/release.bin"] = protocolObject{body: payload, sha: publishDigest(payload), etag: `"adopt-payload"`}
	transport.objects["legacy/retained.txt"] = protocolObject{body: []byte("retained"), sha: "", etag: `"retained"`}
	transport.mutex.Unlock()
	if code, stdout, stderr := run("fsck", "--adopt-remote-inventory", "--config", configPath, "--repo", "assets"); code != ExitUsage {
		t.Fatalf("adopt without explicit target code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}

	// Seed an explicitly incomplete prior ledger to prove the command is the
	// only path that promotes partial coverage to complete.
	canonical := state.New(filepath.Join(root, ".sow"))
	seedDir := t.TempDir()
	emptyInventory := filepath.Join(seedDir, "inventory.tsv")
	partialCoverage := filepath.Join(seedDir, "coverage")
	if err := os.WriteFile(emptyInventory, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(partialCoverage, []byte(remoteInventoryPartial), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := canonical.InstallPaths(map[string]string{
		"remotes/cf/inventory.tsv":      emptyInventory,
		"remotes/cf/inventory.coverage": partialCoverage,
	}, "test: seed partial remote inventory"); err != nil {
		t.Fatal(err)
	}

	// Remote fsck must not parse or otherwise consume the CDN credential.
	t.Setenv("SOW_TEST_CF", `this-is-deliberately-not-json`)
	code, stdout, stderr := run("fsck", "--adopt-remote-inventory", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "3", "--limit", "20")
	if code != ExitOK || !strings.Contains(stdout, "inventory_coverage=complete") || !strings.Contains(stdout, "streamed_get=2") || !strings.Contains(stdout, "retained_extra=1") || !strings.Contains(stdout, "changed=true") {
		t.Fatalf("adopt code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	coverage, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "inventory.coverage"))
	if err != nil || string(coverage) != remoteInventoryComplete {
		t.Fatalf("coverage=%q err=%v", coverage, err)
	}
	inventory, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "inventory.tsv"))
	if err != nil || !strings.Contains(string(inventory), "pkg/release.bin\t") || !strings.Contains(string(inventory), "legacy/retained.txt\t") {
		t.Fatalf("adopted inventory=%s err=%v", inventory, err)
	}
	content, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "content.tsv"))
	if err != nil || !strings.Contains(string(content), "pkg/release.bin\t") || strings.Contains(string(content), "legacy/retained.txt\t") {
		t.Fatalf("source content baseline=%s err=%v", content, err)
	}

	code, stdout, stderr = run("fsck", "--adopt-remote-inventory", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "changed=false") {
		t.Fatalf("idempotent adopt code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}

	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	transport.mutex.Lock()
	putStart := len(transport.putKeys)
	listStart := transport.listCalls
	cdnStart := len(transport.cdnURLs)
	transport.mutex.Unlock()
	code, stdout, stderr = run("publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "status=published") {
		t.Fatalf("first publish after adoption code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	newPutKeys := append([]string(nil), transport.putKeys[putStart:]...)
	newCDNURLs := append([]string(nil), transport.cdnURLs[cdnStart:]...)
	listEnd := transport.listCalls
	transport.mutex.Unlock()
	if len(newPutKeys) == 0 {
		t.Fatal("first publish wrote no control objects")
	}
	for _, key := range newPutKeys {
		if key != publish.CheckpointKey && !(strings.HasPrefix(key, ".sow/generations/") && strings.HasSuffix(key, "/generation.json")) {
			t.Fatalf("first publish retransferred adopted payload key=%s all=%v", key, newPutKeys)
		}
	}
	if listEnd != listStart || len(newCDNURLs) != 1 || newCDNURLs[0] != "https://repo.test/pkg/release.bin" {
		t.Fatalf("first publish protocol list=%d/%d cdn=%v", listStart, listEnd, newCDNURLs)
	}
	planBody, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := publish.DecodePlan(planBody)
	if err != nil || len(plan.Objects) != 1 || plan.Objects[0].Class != publish.ObjectAdoptedImmutable || len(plan.Probes) != 0 ||
		len(plan.Verify) != 1 || plan.Verify[0].URL != "https://repo.test/pkg/release.bin" || plan.Verify[0].SHA256 != publishDigest(payload) {
		t.Fatalf("adopted first-generation plan=%#v err=%v", plan, err)
	}
	coverage, err = os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "inventory.coverage"))
	if err != nil || string(coverage) != remoteInventoryComplete {
		t.Fatalf("publish regressed adopted coverage=%q err=%v", coverage, err)
	}
	t.Setenv("SOW_TEST_CF", "")
	code, stdout, stderr = run("fsck", "--adopt-remote-inventory", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "changed=false") {
		t.Fatalf("post-generation adopt code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

func TestFSCKAdoptRemoteInventoryRejectsMissingPriorContentOutsideNarrowSelector(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	const oneRepo = `  - id: assets
    type: asset
    path: pkg
    default_pool: public
    asset:
      kind: release
      mutable_paths: [latest]
`
	const twoRepos = `  - id: assets-a
    type: asset
    path: pkg-a
    default_pool: public
    asset:
      kind: release
      mutable_paths: [latest]
  - id: assets-b
    type: asset
    path: pkg-b
    default_pool: public
    asset:
      kind: release
      mutable_paths: [latest]
`
	configText := strings.Replace(publishAssetConfig, oneRepo, twoRepos, 1)
	if configText == publishAssetConfig {
		t.Fatal("failed to construct two-repository adoption fixture")
	}
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(arguments ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(arguments, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	assetA := filepath.Join(root, "asset-a.txt")
	assetB := filepath.Join(root, "asset-b.txt")
	if err := os.WriteFile(assetA, []byte("asset-a-v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(assetB, []byte("asset-b-v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range [][]string{
		{"add", assetA, "--config", configPath, "--repo", "assets-a", "--dest", "latest"},
		{"add", assetB, "--config", configPath, "--repo", "assets-b", "--dest", "latest"},
		{"promote", "beta", "latest", "--config", configPath, "--repo", "assets-a", "--repo", "assets-b"},
		{"publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets-a", "--repo", "assets-b", "--workers", "2"},
	} {
		if code, stdout, stderr := run(command...); code != ExitOK {
			t.Fatalf("command=%v code=%d stdout=%s stderr=%s", command, code, stdout, stderr)
		}
	}
	assetASecond := filepath.Join(root, "asset-a-second.txt")
	if err := os.WriteFile(assetASecond, []byte("asset-a-second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range [][]string{
		{"add", assetASecond, "--config", configPath, "--repo", "assets-a", "--dest", "second"},
		{"promote", "beta", "latest", "--config", configPath, "--repo", "assets-a"},
		{"publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets-a", "--workers", "2"},
	} {
		if code, stdout, stderr := run(command...); code != ExitOK {
			t.Fatalf("command=%v code=%d stdout=%s stderr=%s", command, code, stdout, stderr)
		}
	}

	planBody, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := publish.DecodePlan(planBody)
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range plan.Objects {
		if object.RemoteKey == "pkg-b/latest" {
			t.Fatal("narrow publication plan unexpectedly covers retained repo B")
		}
	}
	contentBody, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "content.tsv"))
	if err != nil || !strings.Contains(string(contentBody), "pkg-b/latest\t") {
		t.Fatalf("retained repo B missing from prior content baseline: %s err=%v", contentBody, err)
	}
	transport.mutex.Lock()
	delete(transport.objects, "pkg-b/latest")
	transport.mutex.Unlock()

	canonical := state.New(filepath.Join(root, ".sow"))
	if _, _, err := canonical.Apply(t.Context(), "test", "remove canonical inventory before repair", nil, nil, state.ApplyOptions{
		DeletePaths: []string{remoteStatePath("cf", "inventory.tsv")},
	}); err != nil {
		t.Fatal(err)
	}
	headBefore, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	transport.mutex.Lock()
	requestsBefore := [3]int{transport.listCalls, transport.headCalls, transport.objectGets}
	transport.mutex.Unlock()
	code, stdout, stderr := run("fsck", "--adopt-remote-inventory", "--target", "cf", "--config", configPath, "--repo", "assets-a", "--workers", "2")
	if code != ExitVerification || !strings.Contains(stderr, "REMOTE_INVENTORY_MISSING") {
		t.Fatalf("missing retained content adoption code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	requestsAfter := [3]int{transport.listCalls, transport.headCalls, transport.objectGets}
	transport.mutex.Unlock()
	if requestsAfter != requestsBefore {
		t.Fatalf("local adoption preflight touched remote before=%v after=%v", requestsBefore, requestsAfter)
	}
	headAfter, err := canonical.HeadHash()
	if err != nil || headAfter != headBefore {
		t.Fatalf("failed narrow adoption changed canonical HEAD before=%s after=%s err=%v", headBefore, headAfter, err)
	}
	if _, err := os.Stat(filepath.Join(root, ".sow", "state", "remotes", "cf", "inventory.tsv")); !os.IsNotExist(err) {
		t.Fatalf("failed narrow adoption recreated canonical inventory: %v", err)
	}
}

func TestFSCKAdoptRemoteInventoryStreamsBodyDespiteMatchingMetadata(t *testing.T) {
	root, configPath, transport, run := prepareRemoteAdoptionAsset(t, "cf")
	payload, err := os.ReadFile(filepath.Join(root, "pkg", "release.bin"))
	if err != nil {
		t.Fatal(err)
	}
	wrong := bytes.Repeat([]byte("x"), len(payload))
	transport.mutex.Lock()
	transport.objects["pkg/release.bin"] = protocolObject{
		body: wrong,
		sha:  publishDigest(payload),
		etag: `"lying-metadata"`,
	}
	getStart := transport.objectGets
	transport.mutex.Unlock()

	code, stdout, stderr := run("fsck", "--adopt-remote-inventory", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2", "--limit", "20")
	if code != ExitVerification || !strings.Contains(stderr, "metadata differs from streamed body") {
		t.Fatalf("lying metadata adoption code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	getEnd := transport.objectGets
	transport.mutex.Unlock()
	if getEnd-getStart != 1 {
		t.Fatalf("lying metadata body GETs=%d, want 1", getEnd-getStart)
	}
	if _, err := os.Stat(filepath.Join(root, ".sow", "state", "remotes", "cf", "inventory.tsv")); !os.IsNotExist(err) {
		t.Fatalf("lying metadata adoption persisted inventory: %v", err)
	}
}

func TestFSCKAdoptRemoteInventoryRequiresStableHEADAndGETETag(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*cloudProtocolTransport, []byte)
		wrap      func(http.RoundTripper, *remoteAuditTrackingBody) http.RoundTripper
		wantCode  int
	}{
		{
			name: "empty-head-etag",
			configure: func(transport *cloudProtocolTransport, payload []byte) {
				transport.objects["pkg/release.bin"] = protocolObject{body: payload, etag: ""}
			},
			wantCode: ExitVerification,
		},
		{
			name: "empty-get-etag",
			configure: func(transport *cloudProtocolTransport, payload []byte) {
				transport.objects["pkg/release.bin"] = protocolObject{body: payload, etag: `"head"`}
			},
			wrap: func(base http.RoundTripper, _ *remoteAuditTrackingBody) http.RoundTripper {
				return remoteAuditRoundTripFunc(func(request *http.Request) (*http.Response, error) {
					response, err := base.RoundTrip(request)
					if err == nil && isRemoteAuditObjectGET(request) && response.StatusCode >= 200 && response.StatusCode < 300 {
						response.Header.Del("ETag")
					}
					return response, err
				})
			},
			wantCode: ExitVerification,
		},
		{
			name: "head-get-etag-drift",
			configure: func(transport *cloudProtocolTransport, payload []byte) {
				transport.objects["pkg/release.bin"] = protocolObject{body: payload, etag: `"head"`}
				transport.mutateETagOnGet["pkg/release.bin"] = `"get"`
			},
			wantCode: ExitVerification,
		},
		{
			name: "canceled-read-closes-body",
			configure: func(transport *cloudProtocolTransport, payload []byte) {
				transport.objects["pkg/release.bin"] = protocolObject{body: payload, etag: `"stable"`}
			},
			wrap: func(base http.RoundTripper, tracking *remoteAuditTrackingBody) http.RoundTripper {
				return remoteAuditRoundTripFunc(func(request *http.Request) (*http.Response, error) {
					response, err := base.RoundTrip(request)
					if err == nil && isRemoteAuditObjectGET(request) && response.StatusCode >= 200 && response.StatusCode < 300 {
						tracking.inner = response.Body
						tracking.readErr = context.Canceled
						response.Body = tracking
					}
					return response, err
				})
			},
			wantCode: ExitNetworkAuth,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, configPath, transport, run := prepareRemoteAdoptionAsset(t, "cf")
			payload, err := os.ReadFile(filepath.Join(root, "pkg", "release.bin"))
			if err != nil {
				t.Fatal(err)
			}
			tracking := &remoteAuditTrackingBody{}
			transport.mutex.Lock()
			test.configure(transport, payload)
			transport.mutex.Unlock()
			if test.wrap != nil {
				publishProviderHTTPClient = &http.Client{Transport: test.wrap(transport, tracking)}
			}

			code, stdout, stderr := run("fsck", "--adopt-remote-inventory", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "1")
			if code != test.wantCode {
				t.Fatalf("ETag/body failure code=%d want=%d stdout=%s stderr=%s", code, test.wantCode, stdout, stderr)
			}
			if test.name == "canceled-read-closes-body" && !tracking.closed {
				t.Fatal("canceled adoption did not close the streamed object body")
			}
			if _, err := os.Stat(filepath.Join(root, ".sow", "state", "remotes", "cf", "inventory.tsv")); !os.IsNotExist(err) {
				t.Fatalf("failed adoption persisted inventory: %v", err)
			}
		})
	}
}

type remoteAuditRoundTripFunc func(*http.Request) (*http.Response, error)

func (function remoteAuditRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type remoteAuditTrackingBody struct {
	inner   io.ReadCloser
	readErr error
	closed  bool
}

func (body *remoteAuditTrackingBody) Read(buffer []byte) (int, error) {
	if body.readErr != nil {
		err := body.readErr
		body.readErr = nil
		return 0, err
	}
	return body.inner.Read(buffer)
}

func (body *remoteAuditTrackingBody) Close() error {
	body.closed = true
	return body.inner.Close()
}

func isRemoteAuditObjectGET(request *http.Request) bool {
	return request.Method == http.MethodGet && request.URL.Query().Get("list-type") == "" &&
		(request.URL.Host == "repo-bucket.storage.test" || strings.Contains(request.URL.Host, ".cos."))
}

func TestMarkAdoptedImmutableObjectsRequiresCompleteExactEvidence(t *testing.T) {
	entry := publishManifestEntry("pkg/release.bin", "already-remote-payload\n")

	tests := []struct {
		name      string
		coverage  string
		inventory []manifest.Entry
		baseline  []manifest.Entry
		want      string
		class     publish.ObjectClass
	}{
		{name: "exact", coverage: remoteInventoryComplete, inventory: []manifest.Entry{entry}, baseline: []manifest.Entry{entry}, class: publish.ObjectAdoptedImmutable},
		{name: "missing-coverage", inventory: []manifest.Entry{entry}, baseline: []manifest.Entry{entry}, class: publish.ObjectImmutable},
		{name: "partial-coverage", coverage: remoteInventoryPartial, inventory: []manifest.Entry{entry}, baseline: []manifest.Entry{entry}, class: publish.ObjectImmutable},
		{name: "missing-adopted-object", coverage: remoteInventoryComplete, inventory: []manifest.Entry{publishManifestEntry("pkg/other.bin", "other")}, baseline: []manifest.Entry{entry}, want: "missing from complete remote inventory"},
		{name: "tampered-adopted-object", coverage: remoteInventoryComplete, inventory: []manifest.Entry{publishManifestEntry(entry.Path, "same-size-different-body")}, baseline: []manifest.Entry{entry}, want: "disagrees with complete remote inventory"},
		{name: "new-object-is-uploadable", coverage: remoteInventoryComplete, inventory: []manifest.Entry{publishManifestEntry("pkg/other.bin", "other")}, class: publish.ObjectImmutable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := nginxWorkerTempDir(t)
			baselinePath := filepath.Join(root, "baseline.tsv")
			writePublishManifest(t, baselinePath, test.baseline...)
			inventoryPath := filepath.Join(root, "inventory.tsv")
			writePublishManifest(t, inventoryPath, test.inventory...)
			staged := map[string]string{remoteStatePath("cf", "inventory.tsv"): inventoryPath}
			if test.coverage != "" {
				coveragePath := filepath.Join(root, "coverage")
				if err := os.WriteFile(coveragePath, []byte(test.coverage), 0o600); err != nil {
					t.Fatal(err)
				}
				staged[remoteStatePath("cf", "inventory.coverage")] = coveragePath
			}
			canonical := state.New(filepath.Join(root, ".sow"))
			if _, _, err := canonical.InstallPaths(staged, "test: adopted immutable evidence"); err != nil {
				t.Fatal(err)
			}
			plan := publish.Plan{Objects: []publish.PlannedObject{{SourcePath: entry.Path, RemoteKey: entry.Path, Size: entry.Size, SHA256: entry.HashString(), Class: publish.ObjectImmutable}}}
			err := markAdoptedImmutableObjects(canonical, "cf", baselinePath, &plan)
			if test.want != "" {
				if err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("plan=%#v err=%v want=%q", plan, err, test.want)
				}
				return
			}
			if err != nil || plan.Objects[0].Class != test.class {
				t.Fatalf("plan=%#v err=%v", plan, err)
			}
		})
	}
}

func TestRemoteAdoptionInventoryRejectsDeletedObjectResurrection(t *testing.T) {
	inventoryPath := filepath.Join(t.TempDir(), "inventory.tsv")
	retained := publishManifestEntry("pkg/retained.bin", "retained")
	resurrected := publishManifestEntry("pkg/deleted.bin", "deleted")
	writePublishManifest(t, inventoryPath, resurrected, retained)
	plan := publish.Plan{
		Objects: []publish.PlannedObject{{
			SourcePath: retained.Path, RemoteKey: retained.Path, Size: retained.Size,
			SHA256: retained.HashString(), Class: publish.ObjectImmutable,
		}},
		Deletes: []publish.PlannedDelete{{RemoteKey: resurrected.Path}},
	}
	if err := requirePlanObjectsInInventory(plan, inventoryPath); err == nil || !errors.Is(err, errRemoteAdoptionDrift) || !strings.Contains(err.Error(), "reappeared") {
		t.Fatalf("resurrected deletion err=%v", err)
	}
}

func TestUnpublishedRemoteAdoptionRejectsOrphanCheckpointBeforeNetwork(t *testing.T) {
	root, configPath, transport, run := prepareRemoteAdoptionAsset(t, "cf")
	stateDir := filepath.Join(root, ".sow")
	stageDir, err := os.MkdirTemp(stateDir, "orphan-checkpoint-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stageDir)
	etagPath := filepath.Join(stageDir, "checkpoint.etag")
	if err := os.WriteFile(etagPath, []byte(`"orphan-etag"`), 0o600); err != nil {
		t.Fatal(err)
	}
	canonical := state.New(stateDir)
	if _, changed, err := applyCanonicalState(t.Context(), canonical, "test-orphan-etag", "test: orphan checkpoint ETag", map[string]string{
		remoteStatePath("cf", "checkpoint.etag"): etagPath,
	}, nil, state.ApplyOptions{}); err != nil || !changed {
		t.Fatalf("orphan ETag changed=%t err=%v", changed, err)
	}
	transport.mutex.Lock()
	before := [3]int{transport.listCalls, transport.headCalls, transport.objectGets}
	transport.mutex.Unlock()
	code, stdout, stderr := run("fsck", "--adopt-remote-inventory", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code != ExitVerification || !strings.Contains(stderr, "exists without a generation") {
		t.Fatalf("orphan checkpoint adoption code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	after := [3]int{transport.listCalls, transport.headCalls, transport.objectGets}
	transport.mutex.Unlock()
	if after != before {
		t.Fatalf("orphan checkpoint preflight touched remote before=%v after=%v", before, after)
	}
}

func TestContainsUntrackedSOWControlRejectsBothReservedNamespaces(t *testing.T) {
	for _, test := range []struct {
		path string
		want bool
	}{
		{path: ".sow/foreign/control.json", want: true},
		{path: "_sow/v1/mirrorlist/latest/repo/os/arch.txt", want: true},
		{path: "pkg/release.bin", want: false},
	} {
		t.Run(strings.ReplaceAll(test.path, "/", "-"), func(t *testing.T) {
			inventoryPath := filepath.Join(t.TempDir(), "inventory.tsv")
			writePublishManifest(t, inventoryPath, publishManifestEntry(test.path, "body"))
			if got := containsUntrackedSOWControl(inventoryPath); got != test.want {
				t.Fatalf("containsUntrackedSOWControl(%q)=%t want=%t", test.path, got, test.want)
			}
		})
	}
}

func TestMarkAdoptedImmutableObjectsRejectsMissingOrTamperedLaterObject(t *testing.T) {
	first := publishManifestEntry("pkg/first.bin", "first")
	second := publishManifestEntry("pkg/second.bin", "second")
	for _, test := range []struct {
		name      string
		inventory []manifest.Entry
	}{
		{name: "missing", inventory: []manifest.Entry{first}},
		{name: "tampered", inventory: []manifest.Entry{first, publishManifestEntry(second.Path, "other!")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := nginxWorkerTempDir(t)
			baselinePath := filepath.Join(root, "baseline.tsv")
			inventoryPath := filepath.Join(root, "inventory.tsv")
			coveragePath := filepath.Join(root, "coverage")
			writePublishManifest(t, baselinePath, first, second)
			writePublishManifest(t, inventoryPath, test.inventory...)
			if err := os.WriteFile(coveragePath, []byte(remoteInventoryComplete), 0o600); err != nil {
				t.Fatal(err)
			}
			canonical := state.New(filepath.Join(root, ".sow"))
			if _, _, err := canonical.InstallPaths(map[string]string{
				remoteStatePath("cf", "inventory.tsv"):      inventoryPath,
				remoteStatePath("cf", "inventory.coverage"): coveragePath,
			}, "test: complete multi-object adoption"); err != nil {
				t.Fatal(err)
			}
			plan := publish.Plan{Objects: []publish.PlannedObject{
				{SourcePath: first.Path, RemoteKey: first.Path, Size: first.Size, SHA256: first.HashString(), Class: publish.ObjectImmutable},
				{SourcePath: second.Path, RemoteKey: second.Path, Size: second.Size, SHA256: second.HashString(), Class: publish.ObjectImmutable},
			}}
			if err := markAdoptedImmutableObjects(canonical, "cf", baselinePath, &plan); err == nil || !strings.Contains(err.Error(), second.Path) {
				t.Fatalf("plan=%#v err=%v", plan, err)
			}
		})
	}
}

func TestUnpublishedLatestProjectionScopesDoNotBorrowCoveredRepo(t *testing.T) {
	left := config.Repo{ID: "left", Type: "asset", Path: "left", Asset: &config.AssetConfig{Kind: "release"}}
	right := config.Repo{ID: "right", Type: "asset", Path: "right", Asset: &config.AssetConfig{Kind: "release"}}
	leftRef, err := state.ViewRef("latest", left.ID, "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	prepared := preparedPublication{view: "latest", projections: []publicationProjection{
		{view: "latest", repo: left, os: "all", arch: "all", sourceRoot: "left", legacyRoot: "left"},
		{view: "latest", repo: right, os: "all", arch: "all", sourceRoot: "right", legacyRoot: "right"},
	}}
	scopes, err := unpublishedLatestProjectionScopes(&publish.TargetGeneration{Refs: []publish.RefState{{Name: leftRef.String(), Commit: strings.Repeat("1", 40)}}}, prepared)
	if err != nil || len(scopes) != 1 || scopes[0] != "right" {
		t.Fatalf("unpublished scopes=%v err=%v", scopes, err)
	}
}

func TestUnpublishedCompatibilityScopeRequiresIndependentChannelNotSourceRef(t *testing.T) {
	repo := config.Repo{ID: "infra-el9", Type: "yum", Path: "yum/infra/el9/{arch}", YUM: &config.YUMConfig{}}
	projection := publicationProjection{
		view: "latest", repo: repo, os: "el9", arch: "x86_64", compatibilityID: "infra-legacy-x86-64",
		sourceRoot: "yum/infra/x86_64", canonicalRoot: "yum/infra/x86_64", remoteRoot: "yum/infra/x86_64", legacyRoot: "yum/infra/x86_64",
	}
	ref, err := state.ViewRef("latest", repo.ID, "el9", "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	prepared := preparedPublication{view: "latest", projections: []publicationProjection{projection}}
	parent := &publish.TargetGeneration{Refs: []publish.RefState{{Name: ref.String(), Commit: strings.Repeat("1", 40)}}}
	scopes, err := unpublishedLatestProjectionScopes(parent, prepared)
	if err != nil || len(scopes) != 1 || scopes[0] != projection.sourceRoot {
		t.Fatalf("source ref incorrectly proved old URL published: scopes=%v err=%v", scopes, err)
	}
	parent.Channels = []publish.ChannelState{{RemoteKey: channelRemoteKey("latest", projection)}}
	scopes, err = unpublishedLatestProjectionScopes(parent, prepared)
	if err != nil || len(scopes) != 0 {
		t.Fatalf("independent compatibility channel not recognized: scopes=%v err=%v", scopes, err)
	}
}

func TestAdoptedLatestAfterBetaUsesFullNewScopePlanWithoutPayloadRetransfer(t *testing.T) {
	root, configPath, transport, run := prepareRemoteAdoptionAsset(t, "cf")
	payload, err := os.ReadFile(filepath.Join(root, "pkg", "release.bin"))
	if err != nil {
		t.Fatal(err)
	}
	transport.mutex.Lock()
	transport.objects["pkg/release.bin"] = protocolObject{body: payload, etag: `"adopt-payload"`}
	transport.mutex.Unlock()
	if code, stdout, stderr := run("fsck", "--adopt-remote-inventory", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK {
		t.Fatalf("adopt code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK {
		t.Fatalf("beta code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	putStart, listStart, cdnStart := len(transport.putKeys), transport.listCalls, len(transport.cdnURLs)
	transport.mutex.Unlock()
	code, stdout, stderr := run("publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "status=published") {
		t.Fatalf("latest code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	puts := append([]string(nil), transport.putKeys[putStart:]...)
	cdn := append([]string(nil), transport.cdnURLs[cdnStart:]...)
	listEnd := transport.listCalls
	transport.mutex.Unlock()
	for _, key := range puts {
		if key == "pkg/release.bin" {
			t.Fatalf("latest retransferred adopted payload puts=%v", puts)
		}
	}
	if listEnd != listStart || len(cdn) != 1 || cdn[0] != "https://repo.test/pkg/release.bin" {
		t.Fatalf("latest protocol list=%d/%d cdn=%v puts=%v", listStart, listEnd, cdn, puts)
	}
}

func TestAdoptedLatestYUMAfterBetaBuildsGenerationRouteWithoutRPMRetransfer(t *testing.T) {
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishPackageConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile("testdata/pgdg-redhat-nonfree-repo.rpm.b64")
	if err != nil {
		t.Fatal(err)
	}
	rpmBody, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	rpmPath := filepath.Join(root, "package.rpm")
	if err := os.WriteFile(rpmPath, rpmBody, 0o444); err != nil {
		t.Fatal(err)
	}
	keyPath := writePublishTestPrivateKey(t, root)
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(arguments ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(arguments, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	commands := [][]string{
		{"add", rpmPath, "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2"},
		{"promote", "beta", "latest", "--config", configPath, "--repo", "rpm-test"},
		{"materialize", "latest", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2"},
		{"init", "--config", configPath, "--repo", "rpm-test", "--workers", "2"},
	}
	for _, arguments := range commands {
		if code, stdout, stderr := run(arguments...); code != ExitOK {
			t.Fatalf("command=%v code=%d stdout=%s stderr=%s", arguments, code, stdout, stderr)
		}
	}
	if err := filepath.WalkDir(filepath.Join(root, "yum", "test", "x86_64"), func(filename string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		body, readErr := os.ReadFile(filename)
		if readErr != nil {
			return readErr
		}
		key, relErr := filepath.Rel(root, filename)
		if relErr != nil {
			return relErr
		}
		key = filepath.ToSlash(key)
		transport.objects[key] = protocolObject{body: body, etag: `"legacy-` + publishDigest(body)[:16] + `"`}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("fsck", "--adopt-remote-inventory", "--target", "cf", "--config", configPath, "--repo", "rpm-test", "--workers", "2"); code != ExitOK {
		t.Fatalf("adopt code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2"); code != ExitOK {
		t.Fatalf("beta code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	putStart, listStart := len(transport.putKeys), transport.listCalls
	transport.mutex.Unlock()
	code, stdout, stderr := run("publish", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "rpm-test", "--gpg-private-key-file", keyPath, "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "status=published") {
		t.Fatalf("latest code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	puts := append([]string(nil), transport.putKeys[putStart:]...)
	listEnd := transport.listCalls
	transport.mutex.Unlock()
	generationRepomd := ".sow/generations/00000000000000000002/yum/yum/test/x86_64/repodata/repomd.xml"
	foundGeneration, foundAlias, foundMirror := false, false, false
	for _, key := range puts {
		if strings.Contains(key, "/Packages/") || strings.HasSuffix(key, ".rpm") {
			t.Fatalf("latest retransferred adopted RPM key=%s puts=%v", key, puts)
		}
		switch key {
		case generationRepomd:
			foundGeneration = true
		case "yum/test/x86_64/repodata/repomd.xml":
			foundAlias = true
		case "_sow/v1/mirrorlist/latest/rpm-test/el10/x86_64.txt":
			foundMirror = true
		}
	}
	if listEnd != listStart || !foundGeneration || !foundAlias || !foundMirror {
		t.Fatalf("latest YUM closure list=%d/%d generation=%v alias=%v mirror=%v puts=%v", listStart, listEnd, foundGeneration, foundAlias, foundMirror, puts)
	}
	planBody, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cf", "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := publish.DecodePlan(planBody)
	if err != nil || len(plan.Objects) == 0 {
		t.Fatalf("latest YUM plan=%#v err=%v", plan, err)
	}
	foundAdoptedRPM := false
	for _, object := range plan.Objects {
		if strings.Contains(object.RemoteKey, "/Packages/") || strings.HasSuffix(object.RemoteKey, ".rpm") {
			if object.Class != publish.ObjectAdoptedImmutable {
				t.Fatalf("latest YUM plan did not bind adopted RPM as must-exist: %#v", object)
			}
			foundAdoptedRPM = true
		}
	}
	if !foundAdoptedRPM {
		t.Fatal("latest YUM full closure omitted adopted RPM")
	}
	code, stdout, stderr = run("verify", "--layer", "L2", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "rpm-test", "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "outcome=passed") {
		t.Fatalf("latest adopted L2 code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr = run("fsck", "--adopt-remote-inventory", "--target", "cf", "--config", configPath, "--repo", "rpm-test", "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "changed=false") {
		t.Fatalf("post-latest YUM adoption code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	adoptedRPMKey := "yum/test/x86_64/Packages/p/package.rpm"
	transport.mutex.Lock()
	legacy := transport.objects[adoptedRPMKey]
	legacy.etag = ""
	transport.objects[adoptedRPMKey] = legacy
	transport.mutex.Unlock()
	code, stdout, stderr = run("verify", "--layer", "L2", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "rpm-test", "--workers", "2")
	if code != ExitVerification || !strings.Contains(stdout, "REMOTE_OBJECT_CHANGED") {
		t.Fatalf("empty adopted ETag L2 code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	legacy.etag = `"legacy-restored"`
	transport.objects[adoptedRPMKey] = legacy
	transport.mutateETagOnGet[adoptedRPMKey] = `"legacy-drifted"`
	transport.mutex.Unlock()
	code, stdout, stderr = run("verify", "--layer", "L2", "--view", "latest", "--target", "cf", "--config", configPath, "--repo", "rpm-test", "--workers", "2")
	if code != ExitVerification || !strings.Contains(stdout, "REMOTE_OBJECT_CHANGED") {
		t.Fatalf("adopted HEAD/GET ETag drift L2 code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

func TestFSCKAdoptRemoteInventoryDoubleListDriftDoesNotCommit(t *testing.T) {
	root, configPath, transport, run := prepareRemoteAdoptionAsset(t, "cf")
	payload, err := os.ReadFile(filepath.Join(root, "pkg", "release.bin"))
	if err != nil {
		t.Fatal(err)
	}
	transport.mutex.Lock()
	transport.objects["pkg/release.bin"] = protocolObject{body: payload, sha: publishDigest(payload), etag: `"stable-first"`}
	transport.mutateOnSecondList = true
	transport.mutex.Unlock()
	canonical := state.New(filepath.Join(root, ".sow"))
	headBefore, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run("fsck", "--adopt-remote-inventory", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code != ExitVerification || !strings.Contains(stderr, "evidence drifted") {
		t.Fatalf("drifting adopt code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	headAfter, err := canonical.HeadHash()
	if err != nil || headAfter != headBefore {
		t.Fatalf("failed adoption changed canonical head before=%s after=%s err=%v", headBefore, headAfter, err)
	}
	if _, err := os.Stat(filepath.Join(root, ".sow", "state", "remotes", "cf", "inventory.tsv")); !os.IsNotExist(err) {
		t.Fatalf("failed adoption persisted inventory: %v", err)
	}
}

func TestFSCKAdoptRemoteInventoryRejectsMissingAndChangedLocalObjects(t *testing.T) {
	for _, mode := range []string{"missing", "changed"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			root, configPath, transport, run := prepareRemoteAdoptionAsset(t, "cf")
			payload, err := os.ReadFile(filepath.Join(root, "pkg", "release.bin"))
			if err != nil {
				t.Fatal(err)
			}
			transport.mutex.Lock()
			if mode == "changed" {
				changed := bytes.Repeat([]byte("x"), len(payload))
				transport.objects["pkg/release.bin"] = protocolObject{body: changed, sha: "", etag: `"changed"`}
			}
			transport.mutex.Unlock()
			code, stdout, stderr := run("fsck", "--adopt-remote-inventory", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2", "--limit", "20")
			if code != ExitVerification || !strings.Contains(stdout, "kind=local-") {
				t.Fatalf("%s adopt code=%d stdout=%s stderr=%s", mode, code, stdout, stderr)
			}
			if _, err := os.Stat(filepath.Join(root, ".sow", "state", "remotes", "cf", "inventory.tsv")); !os.IsNotExist(err) {
				t.Fatalf("%s adoption persisted inventory: %v", mode, err)
			}
		})
	}
}

func TestFSCKAdoptRemoteInventoryUsesCOSProtocol(t *testing.T) {
	root, configPath, transport, run := prepareRemoteAdoptionAsset(t, "cos")
	payload, err := os.ReadFile(filepath.Join(root, "pkg", "release.bin"))
	if err != nil {
		t.Fatal(err)
	}
	transport.mutex.Lock()
	transport.cosObjects["pkg/release.bin"] = protocolObject{body: payload, sha: "", etag: `"cos-adopt"`}
	transport.mutex.Unlock()
	t.Setenv("SOW_TEST_COS_CDN", "")
	code, stdout, stderr := run("fsck", "--adopt-remote-inventory", "--target", "cos", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "target=cos") || !strings.Contains(stdout, "streamed_get=1") {
		t.Fatalf("COS adopt code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	coverage, err := os.ReadFile(filepath.Join(root, ".sow", "state", "remotes", "cos", "inventory.coverage"))
	if err != nil || string(coverage) != remoteInventoryComplete {
		t.Fatalf("COS coverage=%q err=%v", coverage, err)
	}
}

func prepareRemoteAdoptionAsset(t *testing.T, target string) (string, string, *cloudProtocolTransport, func(...string) (int, string, string)) {
	t.Helper()
	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	configText := publishAssetConfig
	if target == "cos" {
		cosBlock := `  cos:
    storage: {kind: cos, endpoint: "https://cos.ap-shanghai.myqcloud.com", bucket: repo-1250000000, region: ap-shanghai, credential: env://SOW_TEST_COS_STORAGE, unversioned_bucket_confirmed: true}
    cdn: {kind: edgeone, base_url: "https://repo-cn.test", beta_base_url: "https://beta-cn.test", distribution: zone-cn, credential: env://SOW_TEST_COS_CDN}
`
		configText = strings.Replace(configText, "edge:\n", cosBlock+"edge:\n", 1)
	}
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"r2-access","secret_access_key":"r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)
	t.Setenv("SOW_TEST_COS_STORAGE", `{"access_key_id":"cos-access","secret_access_key":"cos-secret"}`)
	t.Setenv("SOW_TEST_COS_CDN", `{"secret_id":"tencent-id","secret_key":"tencent-secret"}`)
	transport := newCloudProtocolTransport()
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: transport}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(arguments ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(arguments, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	input := filepath.Join(root, "release.bin")
	if err := os.WriteFile(input, []byte("already-remote-payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", "release.bin"); code != ExitOK {
		t.Fatalf("add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", "assets"); code != ExitOK {
		t.Fatalf("promote code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("materialize", "latest", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK {
		t.Fatalf("materialize latest code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("init", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK {
		t.Fatalf("init code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	return root, configPath, transport, run
}
