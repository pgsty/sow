package cli

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pgsty/sow/internal/catalog"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
)

func TestFSCKRepairPurgeLedgerRestoresAnchorReceiptAndAttestsV1WithoutNetwork(t *testing.T) {
	plan := purgeLedgerPointerPlan(t)
	canonical, cfg, envelope := newPurgeLedgerTestState(t, plan)
	envelope.generation.ContentManifestSHA256 = digestBytesCLI(nil)
	generationBody, err := envelope.generation.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	envelope.generationBody = generationBody
	planSHA, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	legacyCheckpoint, err := pub.NewCheckpoint(envelope.generation, "ledger-test", planSHA, pub.PhaseCheckpointCommitted, time.Unix(1_700_000_000, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	legacyCheckpoint.Schema = pub.CheckpointSchemaV1
	legacyCheckpoint.PlanSHA256 = ""
	legacyCheckpointBody, err := legacyCheckpoint.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	receiptBody := canonicalCompletedCloudflarePurgeEvidence(t, envelope.generationBody, legacyCheckpoint, legacyCheckpointBody, plan)
	receiptPath := purgeLedgerReceiptPath("cf", envelope.generation.Generation, legacyCheckpoint.TransactionID)
	anchorBodies := purgeLedgerTestTriplet(envelope)
	anchorBodies[remoteStatePath("cf", "checkpoint.json")] = legacyCheckpointBody
	anchorBodies[receiptPath] = receiptBody
	anchorBodies[remoteStatePath("cf", "content.tsv")] = nil
	anchorBodies[remoteStatePath("cf", "inventory.tsv")] = nil
	for filename, body := range map[string][]byte{
		"generation.json": envelope.generationBody,
		"checkpoint.json": legacyCheckpointBody,
		"plan.json":       envelope.planBody,
	} {
		intentPath, pathErr := remoteIntentStatePath("cf", "latest", "", filename)
		if pathErr != nil {
			t.Fatal(pathErr)
		}
		anchorBodies[intentPath] = body
	}
	installPurgeLedgerTestBodies(t, canonical, anchorBodies, "test: atomic legacy publication envelope and receipt")
	anchor, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := canonical.Apply(t.Context(), "test", "test: delete retained legacy purge receipt", nil, nil, state.ApplyOptions{DeletePaths: []string{receiptPath}}); err != nil {
		t.Fatal(err)
	}

	findings, err := inspectCanonicalPurgeLedger(canonical, cfg, "cf")
	if err != nil {
		t.Fatal(err)
	}
	if !purgeLedgerHasFinding(findings, "LOCAL_PURGE_EVIDENCE_MISSING") || !purgeLedgerHasFinding(findings, "LOCAL_PLAN_BINDING_MISSING") {
		t.Fatalf("pre-repair findings=%#v", findings)
	}

	t.Setenv("SOW_TEST_R2", "")
	t.Setenv("SOW_TEST_CF", "")
	var networkCalls atomic.Int64
	previousClient := publishProviderHTTPClient
	publishProviderHTTPClient = &http.Client{Transport: remoteAuditRoundTripFunc(func(*http.Request) (*http.Response, error) {
		networkCalls.Add(1)
		return nil, errors.New("purge ledger repair attempted a network request")
	})}
	t.Cleanup(func() { publishProviderHTTPClient = previousClient })
	run := func(arguments ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := Main(arguments, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	configPath := filepath.Join(cfg.Root, "sow.yaml")
	code, stdout, stderr := run("fsck", "--repair-purge-ledger", "--target", "cf", "--config", configPath)
	if code != ExitOK || !strings.Contains(stdout, "receipts_restored=1") || !strings.Contains(stdout, "legacy_attestations=1") || !strings.Contains(stdout, "network_requests=0") {
		t.Fatalf("repair code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if calls := networkCalls.Load(); calls != 0 {
		t.Fatalf("repair issued network calls=%d", calls)
	}
	restored, exists, err := readOptionalCanonical(canonical, receiptPath)
	if err != nil || !exists || !bytes.Equal(restored, receiptBody) {
		t.Fatalf("restored receipt exists=%t equal=%t err=%v", exists, bytes.Equal(restored, receiptBody), err)
	}
	attestationPath := legacyPurgePlanAttestationPath("cf", envelope.generation.Generation, legacyCheckpoint.TransactionID)
	attestationBody, exists, err := readOptionalCanonical(canonical, attestationPath)
	if err != nil || !exists {
		t.Fatalf("attestation exists=%t err=%v", exists, err)
	}
	attestation, err := pub.DecodeLegacyPurgePlanAttestation(attestationBody)
	if err != nil || attestation.AnchorCommit != anchor.String() || attestation.ReceiptSHA256 != digestBytesCLI(receiptBody) {
		t.Fatalf("attestation=%#v err=%v anchor=%s", attestation, err, anchor)
	}
	if err := validateCurrentCanonicalPurgeEvidenceClosure(canonical, cfg, "cf"); err != nil {
		t.Fatalf("repaired current closure: %v", err)
	}
	if _, err := loadCurrentAggregateVerificationState(canonical, "cf", map[string]struct{}{}); err != nil {
		t.Fatalf("repaired aggregate verification reader: %v", err)
	}
	if _, err := loadCommittedVerificationState(canonical, "cf", "latest", ""); err != nil {
		t.Fatalf("repaired intent verification reader: %v", err)
	}
	if _, exists, err := loadHistoricalPublicationClosureAt(canonical, "cf", anchor); err != nil || !exists {
		t.Fatalf("repaired historical restore reader exists=%t err=%v", exists, err)
	}
	findings, err = inspectCanonicalPurgeLedger(canonical, cfg, "cf")
	if err != nil || len(findings) != 0 {
		t.Fatalf("post-repair findings=%#v err=%v", findings, err)
	}
	head, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	cacheHead, err := catalog.CanonicalHead(t.Context(), cfg.StatePath())
	if err != nil || cacheHead != head {
		t.Fatalf("cache head=%s canonical=%s err=%v", cacheHead, head, err)
	}

	code, stdout, stderr = run("fsck", "--repair-purge-ledger", "--target", "cf", "--config", configPath)
	if code != ExitOK || !strings.Contains(stdout, "changed=false") || !strings.Contains(stdout, "receipts_restored=0") || !strings.Contains(stdout, "legacy_attestations=0") {
		t.Fatalf("idempotent repair code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if calls := networkCalls.Load(); calls != 0 {
		t.Fatalf("idempotent repair issued network calls=%d", calls)
	}

	// A self-consistent replacement receipt plus a matching replacement
	// attestation still cannot supersede the immutable anchor. Repair must copy
	// both exact derived documents back to their anchor-bound bytes.
	forgedEvidence, err := pub.DecodePurgeEvidence(receiptBody)
	if err != nil {
		t.Fatal(err)
	}
	forgedTime := time.Unix(1_700_000_200, 0).UTC().Format(time.RFC3339Nano)
	forgedEvidence.UpdatedAt = forgedTime
	forgedEvidence.Attempts[0].UpdatedAt = forgedTime
	forgedEvidence.Attempts[0].Batches[0].CompletedObservedAt = forgedTime
	forgedReceiptBody, err := forgedEvidence.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	forgedAttestation := attestation
	forgedAttestation.ReceiptSHA256 = digestBytesCLI(forgedReceiptBody)
	forgedAttestationBody, err := forgedAttestation.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	installPurgeLedgerTestBodies(t, canonical, map[string][]byte{
		receiptPath:     forgedReceiptBody,
		attestationPath: forgedAttestationBody,
	}, "test: forge self-consistent replacement receipt and attestation")
	if err := validateCurrentCanonicalPurgeEvidenceClosure(canonical, cfg, "cf"); err == nil || !strings.Contains(err.Error(), "LOCAL_PLAN_BINDING_INVALID") {
		t.Fatalf("forged anchor replacement err=%v", err)
	}
	code, stdout, stderr = run("fsck", "--repair-purge-ledger", "--target", "cf", "--config", configPath)
	if code != ExitOK || !strings.Contains(stdout, "receipts_restored=1") || !strings.Contains(stdout, "legacy_attestations=1") {
		t.Fatalf("forged replacement repair code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if calls := networkCalls.Load(); calls != 0 {
		t.Fatalf("forged replacement repair issued network calls=%d", calls)
	}
	restored, exists, err = readOptionalCanonical(canonical, receiptPath)
	if err != nil || !exists || !bytes.Equal(restored, receiptBody) {
		t.Fatalf("anchor receipt was not restored exists=%t err=%v", exists, err)
	}
	restoredAttestation, exists, err := readOptionalCanonical(canonical, attestationPath)
	if err != nil || !exists || !bytes.Equal(restoredAttestation, attestationBody) {
		t.Fatalf("anchor attestation was not restored exists=%t err=%v", exists, err)
	}

	// Repair must not bless a ledger after any content/intent member was
	// deleted, even when the target-global triplet and provider receipt remain
	// self-consistent. The failure is local and precedes every HTTP path.
	intentPlanPath, err := remoteIntentStatePath("cf", "latest", "", "plan.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, changed, err := canonical.Apply(t.Context(), "test", "test: delete retained intent-local plan", nil, nil, state.ApplyOptions{DeletePaths: []string{intentPlanPath}}); err != nil || !changed {
		t.Fatalf("delete intent-local plan changed=%t err=%v", changed, err)
	}
	brokenHead, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = run("fsck", "--repair-purge-ledger", "--target", "cf", "--config", configPath)
	if code != ExitVerification || !strings.Contains(stderr, "content or intent-local publication closure changed") {
		t.Fatalf("incomplete intent repair code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if calls := networkCalls.Load(); calls != 0 {
		t.Fatalf("incomplete intent repair issued network calls=%d", calls)
	}
	afterBrokenRepair, err := canonical.HeadHash()
	if err != nil || afterBrokenRepair != brokenHead {
		t.Fatalf("failed repair mutated canonical head before=%s after=%s err=%v", brokenHead, afterBrokenRepair, err)
	}
}

func TestFSCKRepairPurgeLedgerThenPublishV2AndAuditLocally(t *testing.T) {
	// This test is intentionally incapable of reaching a real provider. Real
	// opt-ins and ambient provider credentials are cleared, the configured
	// endpoints use reserved .test hosts, and every HTTP request terminates in
	// cloudProtocolTransport below.
	for name, value := range map[string]string{
		"SOW_RUN_REAL_CLOUD":         "0",
		"SOW_RUN_REAL_EDGE_EVIDENCE": "0",
		"SOW_RUN_REAL_UPSTREAM":      "0",
		"AWS_ACCESS_KEY_ID":          "",
		"AWS_SECRET_ACCESS_KEY":      "",
		"AWS_SESSION_TOKEN":          "",
		"CLOUDFLARE_API_TOKEN":       "",
		"TENCENT_SECRET_ID":          "",
		"TENCENT_SECRET_KEY":         "",
		"SOW_REAL_COS_STORAGE_JSON":  "",
		"SOW_REAL_COS_CDN_JSON":      "",
	} {
		t.Setenv(name, value)
	}
	t.Setenv("SOW_TEST_R2", `{"access_key_id":"local-r2-access","secret_access_key":"local-r2-secret"}`)
	t.Setenv("SOW_TEST_CF", `{"api_token":"cf-api-token"}`)

	root := nginxWorkerTempDir(t)
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "release.txt")
	if err := os.WriteFile(input, []byte("legacy-v1-payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}
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
		t.Fatalf("initial add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(cfg.StatePath())
	desiredCommit, err := canonical.HeadHash()
	if err != nil || desiredCommit.IsZero() {
		t.Fatalf("legacy desired commit=%s err=%v", desiredCommit, err)
	}
	betaRef, err := state.ViewRef("beta", "assets", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	betaCommit, exists, err := canonical.Ref(betaRef)
	if err != nil || !exists {
		t.Fatalf("beta ref exists=%t err=%v", exists, err)
	}
	betaPath, err := state.ViewPath("beta", "assets", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	betaManifest, err := canonical.OpenPathAt(betaCommit, betaPath)
	if err != nil {
		t.Fatal(err)
	}
	betaSHA, err := hashReader(betaManifest)
	if err != nil {
		t.Fatal(err)
	}
	refs := []pub.RefState{{Name: betaRef.String(), Commit: betaCommit.String(), ManifestSHA256: betaSHA}}
	configSHA, err := publicationConfigSHA256ForRefs(cfg, refs)
	if err != nil {
		t.Fatal(err)
	}

	pointerBody, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	pointerSHA := digestBytesCLI(pointerBody)
	legacyPlan, err := (pub.Plan{Objects: []pub.PlannedObject{{
		SourcePath: "pkg/latest", RemoteKey: "pkg/latest", Size: int64(len(pointerBody)),
		SHA256: pointerSHA, Class: pub.ObjectPointer,
	}}}).WithCDN("https://repo.test")
	if err != nil {
		t.Fatal(err)
	}
	legacyPlanBody, err := legacyPlan.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	legacyPlanSHA, err := legacyPlan.Digest()
	if err != nil {
		t.Fatal(err)
	}

	stageDir, err := newTransactionDir(cfg.StatePath(), "test-legacy-v1-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stageDir) })
	stage := func(name string, body []byte) string {
		t.Helper()
		filename := filepath.Join(stageDir, name)
		if err := os.WriteFile(filename, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return filename
	}
	contentPath := filepath.Join(stageDir, "content.tsv")
	pointerEntry, err := remoteInventoryEntry("pkg/latest", int64(len(pointerBody)), pointerSHA)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeMergedRemoteInventory(nil, map[string]manifest.Entry{"pkg/latest": pointerEntry}, contentPath); err != nil {
		t.Fatal(err)
	}
	contentSHA, err := hashRegularPath(contentPath)
	if err != nil {
		t.Fatal(err)
	}
	legacyGeneration := pub.TargetGeneration{
		Schema: pub.TargetGenerationSchema, Target: pub.TargetCloudflare,
		Generation: 1, ParentGeneration: 0, DesiredCommit: desiredCommit.String(),
		IntentView: "beta", ConfigSHA256: configSHA, Refs: refs,
		ContentManifestSHA256: contentSHA,
	}
	legacyGenerationBody, err := legacyGeneration.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	legacyCheckpoint, err := pub.NewCheckpoint(legacyGeneration, "legacy-v1", legacyPlanSHA, pub.PhaseCheckpointCommitted, time.Unix(1_700_000_000, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	legacyCheckpoint.Schema = pub.CheckpointSchemaV1
	legacyCheckpoint.PlanSHA256 = ""
	legacyCheckpointBody, err := legacyCheckpoint.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	legacyReceiptBody := canonicalCompletedCloudflarePurgeEvidence(t, legacyGenerationBody, legacyCheckpoint, legacyCheckpointBody, legacyPlan)
	legacyReceiptPath := purgeLedgerReceiptPath("cf", 1, legacyCheckpoint.TransactionID)
	legacyETag := `"legacy-checkpoint"`

	generationKey, err := pub.GenerationKey(1)
	if err != nil {
		t.Fatal(err)
	}
	generationEntry, err := remoteInventoryEntry(generationKey, int64(len(legacyGenerationBody)), digestBytesCLI(legacyGenerationBody))
	if err != nil {
		t.Fatal(err)
	}
	checkpointEntry, err := remoteInventoryEntry(pub.CheckpointKey, int64(len(legacyCheckpointBody)), digestBytesCLI(legacyCheckpointBody))
	if err != nil {
		t.Fatal(err)
	}
	inventoryPath := filepath.Join(stageDir, "inventory.tsv")
	if err := writeMergedRemoteInventory(nil, map[string]manifest.Entry{
		"pkg/latest":      pointerEntry,
		generationKey:     generationEntry,
		pub.CheckpointKey: checkpointEntry,
	}, inventoryPath); err != nil {
		t.Fatal(err)
	}
	intentGeneration, _ := remoteIntentStatePath("cf", "beta", "", "generation.json")
	intentCheckpoint, _ := remoteIntentStatePath("cf", "beta", "", "checkpoint.json")
	intentPlan, _ := remoteIntentStatePath("cf", "beta", "", "plan.json")
	staged := map[string]string{
		remoteStatePath("cf", "generation.json"):    stage("generation.json", legacyGenerationBody),
		remoteStatePath("cf", "checkpoint.json"):    stage("checkpoint.json", legacyCheckpointBody),
		remoteStatePath("cf", "checkpoint.etag"):    stage("checkpoint.etag", []byte(legacyETag)),
		remoteStatePath("cf", "plan.json"):          stage("plan.json", legacyPlanBody),
		remoteStatePath("cf", "content.tsv"):        contentPath,
		remoteStatePath("cf", "inventory.tsv"):      inventoryPath,
		remoteStatePath("cf", "inventory.coverage"): stage("inventory.coverage", []byte(remoteInventoryComplete)),
		legacyReceiptPath:                           stage("purge-receipt.json", legacyReceiptBody),
		intentGeneration:                            stage("intent-generation.json", legacyGenerationBody),
		intentCheckpoint:                            stage("intent-checkpoint.json", legacyCheckpointBody),
		intentPlan:                                  stage("intent-plan.json", legacyPlanBody),
	}
	remoteRef, err := state.RemoteRef("cf", "beta", "assets", "all", "all")
	if err != nil {
		t.Fatal(err)
	}
	anchor, changed, err := applyCanonicalState(t.Context(), canonical, "test-legacy-publication", "test: install complete legacy v1 publication", staged, []state.RefUpdate{{Name: remoteRef, Target: betaCommit}}, state.ApplyOptions{})
	if err != nil || !changed {
		t.Fatalf("legacy anchor=%s changed=%t err=%v", anchor, changed, err)
	}
	if _, changed, err := applyCanonicalState(t.Context(), canonical, "test-legacy-receipt-loss", "test: remove legacy receipt before repair", nil, nil, state.ApplyOptions{DeletePaths: []string{legacyReceiptPath}}); err != nil || !changed {
		t.Fatalf("remove legacy receipt changed=%t err=%v", changed, err)
	}
	transport.mutex.Lock()
	transport.objects["pkg/latest"] = protocolObject{body: append([]byte(nil), pointerBody...), sha: pointerSHA, etag: `"legacy-pointer"`}
	transport.objects[generationKey] = protocolObject{body: append([]byte(nil), legacyGenerationBody...), sha: digestBytesCLI(legacyGenerationBody), etag: `"legacy-generation"`}
	transport.objects[pub.CheckpointKey] = protocolObject{body: append([]byte(nil), legacyCheckpointBody...), sha: digestBytesCLI(legacyCheckpointBody), etag: legacyETag}
	beforeRepairIO := [6]int{transport.puts, transport.purges, transport.cdnGets, transport.listCalls, transport.objectGets, transport.headCalls}
	transport.mutex.Unlock()

	code, stdout, stderr := run("fsck", "--repair-purge-ledger", "--target", "cf", "--config", configPath)
	if code != ExitOK || !strings.Contains(stdout, "receipts_restored=1") || !strings.Contains(stdout, "legacy_attestations=1") || !strings.Contains(stdout, "network_requests=0") {
		t.Fatalf("repair code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	transport.mutex.Lock()
	afterRepairIO := [6]int{transport.puts, transport.purges, transport.cdnGets, transport.listCalls, transport.objectGets, transport.headCalls}
	transport.mutex.Unlock()
	if afterRepairIO != beforeRepairIO {
		t.Fatalf("local repair reached protocol transport before=%v after=%v", beforeRepairIO, afterRepairIO)
	}
	legacyAttestationPath := legacyPurgePlanAttestationPath("cf", 1, legacyCheckpoint.TransactionID)
	if body, exists, err := readOptionalCanonical(canonical, legacyAttestationPath); err != nil || !exists {
		t.Fatalf("legacy attestation exists=%t err=%v", exists, err)
	} else if _, err := pub.DecodeLegacyPurgePlanAttestation(body); err != nil {
		t.Fatalf("decode legacy attestation: %v", err)
	}
	legacyHistorical, err := loadHistoricalTargetPublication(canonical, "cf", 1)
	if err != nil || legacyHistorical.Generation.Generation != 1 {
		t.Fatalf("legacy historical publication=%#v err=%v", legacyHistorical, err)
	}
	legacyAnchor, _, err := targetGenerationPublicationState(canonical, "cf", 1)
	if err != nil || legacyAnchor != anchor {
		t.Fatalf("legacy publication anchor=%s want=%s err=%v", legacyAnchor, anchor, err)
	}
	if _, exists, err := loadHistoricalPublicationClosureAt(canonical, "cf", anchor); err != nil || !exists {
		t.Fatalf("repaired v1 anchor closure exists=%t err=%v", exists, err)
	}

	if err := os.WriteFile(input, []byte("strict-v2-payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("add", input, "--config", configPath, "--repo", "assets", "--dest", "latest", "--replace"); code != ExitOK {
		t.Fatalf("replacement add code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr = run("publish", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "generation=2") || !strings.Contains(stdout, "status=published") {
		t.Fatalf("v2 publish code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}

	currentGeneration, _, exists, err := readLocalTargetGeneration(canonical, "cf")
	if err != nil || !exists || currentGeneration.Generation != 2 || currentGeneration.ParentGeneration != 1 {
		t.Fatalf("current generation=%#v exists=%t err=%v", currentGeneration, exists, err)
	}
	currentCheckpoint, _, exists, err := readLocalTargetCheckpoint(canonical, "cf")
	if err != nil || !exists || currentCheckpoint.Schema != pub.CheckpointSchema || currentCheckpoint.Generation != 2 {
		t.Fatalf("current checkpoint=%#v exists=%t err=%v", currentCheckpoint, exists, err)
	}
	currentPlanBody, exists, err := readOptionalCanonical(canonical, remoteStatePath("cf", "plan.json"))
	if err != nil || !exists {
		t.Fatalf("current plan exists=%t err=%v", exists, err)
	}
	currentPlan, err := pub.DecodePlan(currentPlanBody)
	if err != nil {
		t.Fatal(err)
	}
	currentPlanSHA, err := currentPlan.Digest()
	if err != nil || currentCheckpoint.PlanSHA256 == "" || currentCheckpoint.PlanSHA256 != currentPlanSHA {
		t.Fatalf("strict v2 plan binding checkpoint=%s plan=%s err=%v", currentCheckpoint.PlanSHA256, currentPlanSHA, err)
	}
	if _, exists, err := readOptionalCanonical(canonical, legacyPurgePlanAttestationPath("cf", 2, currentCheckpoint.TransactionID)); err != nil || exists {
		t.Fatalf("v2 generation unexpectedly used legacy attestation exists=%t err=%v", exists, err)
	}
	nextHistorical, err := loadHistoricalTargetPublication(canonical, "cf", 2)
	if err != nil {
		t.Fatalf("load strict v2 historical publication: %v", err)
	}
	if ancestor, err := canonical.IsAncestor(anchor, nextHistorical.StateCommit); err != nil || !ancestor {
		t.Fatalf("v2 publication does not descend from repaired v1 anchor ancestor=%t err=%v", ancestor, err)
	}
	if findings, err := inspectCanonicalPurgeLedger(canonical, cfg, "cf"); err != nil || len(findings) != 0 {
		t.Fatalf("mixed v1/v2 purge history findings=%#v err=%v", findings, err)
	}

	code, stdout, stderr = run("verify", "--layer", "L2", "--view", "beta", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2")
	if code != ExitOK || !strings.Contains(stdout, "outcome=passed") {
		t.Fatalf("mixed history L2 code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("promote", "beta", "latest", "--config", configPath, "--repo", "assets"); code != ExitOK {
		t.Fatalf("promote for local fsck tree code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if code, stdout, stderr := run("materialize", "latest", "--config", configPath, "--repo", "assets", "--workers", "2"); code != ExitOK || !strings.Contains(stdout, "target=working-tree") {
		t.Fatalf("materialize local fsck tree code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	code, stdout, stderr = run("fsck", "--target", "cf", "--config", configPath, "--repo", "assets", "--workers", "2", "--limit", "20")
	if code != ExitOK || !strings.Contains(stdout, "fsck target=cf") || !strings.Contains(stdout, "inventory_coverage=complete") {
		t.Fatalf("mixed history fsck code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

func canonicalCompletedCloudflarePurgeEvidence(t *testing.T, generationBody []byte, checkpoint pub.Checkpoint, checkpointBody []byte, plan pub.Plan) []byte {
	t.Helper()
	if len(plan.PurgeURLs) == 0 || len(plan.PurgeURLs) > 100 {
		t.Fatalf("test plan purge URL count=%d", len(plan.PurgeURLs))
	}
	urlsSHA, err := pub.PurgeURLsDigest(plan.PurgeURLs)
	if err != nil {
		t.Fatal(err)
	}
	planSHA, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_100, 0).UTC().Format(time.RFC3339Nano)
	evidence := pub.PurgeEvidence{
		Schema: pub.PurgeEvidenceSchema, Target: checkpoint.Target,
		TransactionID: checkpoint.TransactionID, Generation: checkpoint.Generation,
		GenerationSHA256: digestBytesCLI(generationBody), PlanSHA256: planSHA,
		CheckpointSHA256: digestBytesCLI(checkpointBody), URLCount: len(plan.PurgeURLs), URLsSHA256: urlsSHA,
		Attempts: []pub.PurgeAttempt{{
			ID: 1, Purpose: pub.PurgeAttemptFull, URLCount: len(plan.PurgeURLs), URLsSHA256: urlsSHA,
			Batches: []pub.PurgeReceipt{{
				BatchIndex: 0, URLCount: len(plan.PurgeURLs), URLsSHA256: urlsSHA,
				Vendor: pub.PurgeVendorCloudflare, ZoneID: "zone-test", Status: pub.PurgeReceiptCompleted,
				AcceptedRequestID: "accepted-request", AcceptedObservedAt: now,
				CompletedRequestID: "completed-request", CompletedObservedAt: now,
				VendorResultID: "cloudflare-result",
			}},
			StartedAt: now, UpdatedAt: now,
		}},
		CreatedAt: now, UpdatedAt: now,
	}
	body, err := evidence.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestFSCKRepairPurgeLedgerFlagValidation(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{name: "target-required", args: []string{"fsck", "--repair-purge-ledger", "--config", configPath}, want: "requires exactly one explicit --target"},
		{name: "mutually-exclusive", args: []string{"fsck", "--repair-purge-ledger", "--adopt-remote-inventory", "--target", "cf", "--config", configPath}, want: "cannot be combined"},
		{name: "selector-rejected", args: []string{"fsck", "--repair-purge-ledger", "--target", "cf", "--repo", "assets", "--config", configPath}, want: "does not accept repository"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Main(test.args, &stdout, &stderr); code != ExitUsage || !strings.Contains(stderr.String(), test.want) {
				t.Fatalf("code=%d stdout=%s stderr=%s want=%q", code, stdout.String(), stderr.String(), test.want)
			}
		})
	}
}
