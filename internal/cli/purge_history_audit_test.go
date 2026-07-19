package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/pgsty/sow/internal/config"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/verify"
)

func TestCanonicalPurgeLedgerCheckpointV1CompatibilityIsExplicit(t *testing.T) {
	for _, test := range []struct {
		name      string
		plan      pub.Plan
		wantCodes []string
	}{
		{name: "purge-free"},
		{name: "nonempty-purge", plan: purgeLedgerPointerPlan(t), wantCodes: []string{"LOCAL_PLAN_BINDING_MISSING", "LOCAL_PURGE_EVIDENCE_MISSING"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			configPath := filepath.Join(root, "sow.yaml")
			if err := os.WriteFile(configPath, []byte(publishAssetConfig), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(configPath, "")
			if err != nil {
				t.Fatal(err)
			}
			canonical := state.New(filepath.Join(root, ".sow"))
			base, changed, err := canonical.InstallPaths(map[string]string{"config/sow.yaml": configPath}, "test: canonical config")
			if err != nil || !changed {
				t.Fatalf("base=%s changed=%t err=%v", base, changed, err)
			}
			generation := pub.TargetGeneration{
				Schema: pub.TargetGenerationSchema, Target: pub.TargetCloudflare,
				Generation: 1, ParentGeneration: 0, DesiredCommit: base.String(),
				IntentView: "latest", ConfigSHA256: strings.Repeat("a", 64),
				Refs: []pub.RefState{{
					Name: "refs/sow/views/latest/assets/all/all", Commit: base.String(), ManifestSHA256: strings.Repeat("b", 64),
				}},
				ContentManifestSHA256: digestBytesCLI(nil),
			}
			generationBody, err := generation.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			planBody, err := test.plan.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			planSHA, err := test.plan.Digest()
			if err != nil {
				t.Fatal(err)
			}
			checkpoint, err := pub.NewCheckpoint(generation, "legacy-v1", planSHA, pub.PhaseCheckpointCommitted, time.Unix(1_700_000_000, 0).UTC())
			if err != nil {
				t.Fatal(err)
			}
			checkpoint.Schema = pub.CheckpointSchemaV1
			checkpoint.PlanSHA256 = ""
			checkpointBody, err := checkpoint.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			stageDir := t.TempDir()
			stage := func(name string, body []byte) string {
				filename := filepath.Join(stageDir, name)
				if err := os.WriteFile(filename, body, 0o600); err != nil {
					t.Fatal(err)
				}
				return filename
			}
			if _, changed, err := canonical.InstallPaths(map[string]string{
				remoteStatePath("cf", "generation.json"):                      stage("generation.json", generationBody),
				remoteStatePath("cf", "checkpoint.json"):                      stage("checkpoint.json", checkpointBody),
				remoteStatePath("cf", "plan.json"):                            stage("plan.json", planBody),
				remoteStatePath("cf", "content.tsv"):                          stage("content.tsv", nil),
				remoteStatePath("cf", "intents/views/latest/generation.json"): stage("intent-generation.json", generationBody),
				remoteStatePath("cf", "intents/views/latest/checkpoint.json"): stage("intent-checkpoint.json", checkpointBody),
				remoteStatePath("cf", "intents/views/latest/plan.json"):       stage("intent-plan.json", planBody),
			}, "test: legacy publication envelope"); err != nil || !changed {
				t.Fatalf("legacy envelope changed=%t err=%v", changed, err)
			}
			findings, err := inspectCanonicalPurgeLedger(canonical, cfg, "cf")
			if err != nil {
				t.Fatal(err)
			}
			for _, code := range test.wantCodes {
				if !purgeLedgerHasFinding(findings, code) {
					t.Fatalf("findings=%#v missing=%s", findings, code)
				}
			}
			if len(test.wantCodes) == 0 && len(findings) != 0 {
				t.Fatalf("purge-free v1 findings=%#v", findings)
			}
		})
	}
}

func purgeLedgerPointerPlan(t *testing.T) pub.Plan {
	t.Helper()
	plan, err := (pub.Plan{Objects: []pub.PlannedObject{{
		SourcePath: "pkg/latest", RemoteKey: "pkg/latest", Size: 1,
		SHA256: strings.Repeat("d", 64), Class: pub.ObjectPointer,
	}}}).WithCDN("https://repo.test")
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func purgeLedgerHasFinding(findings []verify.Finding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

type purgeLedgerTestEnvelope struct {
	generation     pub.TargetGeneration
	generationBody []byte
	checkpoint     pub.Checkpoint
	checkpointBody []byte
	plan           pub.Plan
	planBody       []byte
}

func newPurgeLedgerTestState(t *testing.T, plan pub.Plan) (*state.Store, *config.Config, purgeLedgerTestEnvelope) {
	t.Helper()
	root := t.TempDir()
	configPath := filepath.Join(root, "sow.yaml")
	if err := os.WriteFile(configPath, []byte(publishAssetConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath, "")
	if err != nil {
		t.Fatal(err)
	}
	canonical := state.New(filepath.Join(root, ".sow"))
	base, changed, err := canonical.InstallPaths(map[string]string{"config/sow.yaml": configPath}, "test: canonical config")
	if err != nil || !changed {
		t.Fatalf("base=%s changed=%t err=%v", base, changed, err)
	}
	generation := pub.TargetGeneration{
		Schema: pub.TargetGenerationSchema, Target: pub.TargetCloudflare,
		Generation: 1, ParentGeneration: 0, DesiredCommit: base.String(),
		IntentView: "latest", ConfigSHA256: strings.Repeat("a", 64),
		Refs: []pub.RefState{{
			Name: "refs/sow/views/latest/assets/all/all", Commit: base.String(), ManifestSHA256: strings.Repeat("b", 64),
		}},
		ContentManifestSHA256: digestBytesCLI(nil),
	}
	generationBody, err := generation.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	planBody, err := plan.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	planSHA, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := pub.NewCheckpoint(generation, "ledger-test", planSHA, pub.PhaseCheckpointCommitted, time.Unix(1_700_000_000, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	checkpointBody, err := checkpoint.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return canonical, cfg, purgeLedgerTestEnvelope{
		generation: generation, generationBody: generationBody,
		checkpoint: checkpoint, checkpointBody: checkpointBody,
		plan: plan, planBody: planBody,
	}
}

func installPurgeLedgerTestBodies(t *testing.T, canonical *state.Store, bodies map[string][]byte, message string) {
	t.Helper()
	stageDir := t.TempDir()
	paths := make(map[string]string, len(bodies))
	for name, body := range bodies {
		filename := filepath.Join(stageDir, strings.ReplaceAll(name, "/", "-"))
		if err := os.WriteFile(filename, body, 0o600); err != nil {
			t.Fatal(err)
		}
		paths[name] = filename
	}
	if _, changed, err := canonical.InstallPaths(paths, message); err != nil || !changed {
		t.Fatalf("install %s changed=%t err=%v", message, changed, err)
	}
}

func purgeLedgerTestTriplet(envelope purgeLedgerTestEnvelope) map[string][]byte {
	return map[string][]byte{
		remoteStatePath("cf", "generation.json"):                      envelope.generationBody,
		remoteStatePath("cf", "checkpoint.json"):                      envelope.checkpointBody,
		remoteStatePath("cf", "plan.json"):                            envelope.planBody,
		remoteStatePath("cf", "content.tsv"):                          nil,
		remoteStatePath("cf", "intents/views/latest/generation.json"): envelope.generationBody,
		remoteStatePath("cf", "intents/views/latest/checkpoint.json"): envelope.checkpointBody,
		remoteStatePath("cf", "intents/views/latest/plan.json"):       envelope.planBody,
	}
}

func TestCanonicalPurgeLedgerRejectsHistoricalPartialTriplets(t *testing.T) {
	for _, present := range []int{1, 2} {
		t.Run(strings.Repeat("file-", present), func(t *testing.T) {
			canonical, cfg, envelope := newPurgeLedgerTestState(t, pub.Plan{})
			triplet := purgeLedgerTestTriplet(envelope)
			partial := map[string][]byte{remoteStatePath("cf", "generation.json"): envelope.generationBody}
			if present == 2 {
				partial[remoteStatePath("cf", "checkpoint.json")] = envelope.checkpointBody
			}
			installPurgeLedgerTestBodies(t, canonical, partial, "test: partial publication triplet")
			installPurgeLedgerTestBodies(t, canonical, triplet, "test: complete repaired publication triplet")

			findings, err := inspectCanonicalPurgeLedger(canonical, cfg, "cf")
			if err != nil || !purgeLedgerHasFinding(findings, "LOCAL_PURGE_LEDGER_ENVELOPE_INVALID") ||
				!strings.Contains(findings[0].Message, "partial") {
				t.Fatalf("present=%d findings=%#v err=%v", present, findings, err)
			}
		})
	}
}

func TestCanonicalPurgeLedgerRejectsHistoricalTripletDeletion(t *testing.T) {
	canonical, cfg, envelope := newPurgeLedgerTestState(t, pub.Plan{})
	triplet := purgeLedgerTestTriplet(envelope)
	installPurgeLedgerTestBodies(t, canonical, triplet, "test: original publication envelope")
	if _, changed, err := canonical.Apply(t.Context(), "test", "delete complete publication triplet", nil, nil, state.ApplyOptions{DeletePaths: []string{
		remoteStatePath("cf", "generation.json"),
		remoteStatePath("cf", "checkpoint.json"),
		remoteStatePath("cf", "plan.json"),
	}}); err != nil || !changed {
		t.Fatalf("delete triplet changed=%t err=%v", changed, err)
	}
	installPurgeLedgerTestBodies(t, canonical, triplet, "test: restore complete publication triplet")

	findings, err := inspectCanonicalPurgeLedger(canonical, cfg, "cf")
	if err != nil || !purgeLedgerHasFinding(findings, "LOCAL_PURGE_LEDGER_ENVELOPE_INVALID") ||
		!strings.Contains(findings[0].Message, "deleted") {
		t.Fatalf("findings=%#v err=%v", findings, err)
	}
}

func TestCanonicalPurgeLedgerRejectsIntentClosureDeletion(t *testing.T) {
	canonical, cfg, envelope := newPurgeLedgerTestState(t, pub.Plan{})
	installPurgeLedgerTestBodies(t, canonical, purgeLedgerTestTriplet(envelope), "test: complete publication closure")
	intentPlanPath, err := remoteIntentStatePath("cf", "latest", "", "plan.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, changed, err := canonical.Apply(t.Context(), "test", "delete intent-local plan", nil, nil, state.ApplyOptions{DeletePaths: []string{intentPlanPath}}); err != nil || !changed {
		t.Fatalf("delete intent plan changed=%t err=%v", changed, err)
	}
	findings, err := inspectCanonicalPurgeLedger(canonical, cfg, "cf")
	if err != nil || !purgeLedgerHasFinding(findings, "LOCAL_PURGE_LEDGER_ENVELOPE_CHANGED") {
		t.Fatalf("intent closure deletion findings=%#v err=%v", findings, err)
	}
}

func TestCanonicalPurgeLedgerRejectsSiblingPublicationAnchors(t *testing.T) {
	canonical, cfg, generationOne := newPurgeLedgerTestState(t, pub.Plan{})
	base, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	installPurgeLedgerTestBodies(t, canonical, purgeLedgerTestTriplet(generationOne), "test: generation one on branch A")
	anchorOne, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	repository, err := git.PlainOpen(filepath.Join(canonical.StateDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	head, err := repository.Head()
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Storer.SetReference(plumbing.NewHashReference(head.Name(), base)); err != nil {
		t.Fatal(err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := worktree.Reset(&git.ResetOptions{Commit: base, Mode: git.HardReset}); err != nil {
		t.Fatal(err)
	}

	generationTwo := generationOne
	generationTwo.generation.Generation = 2
	generationTwo.generation.ParentGeneration = 1
	generationTwo.generation.DesiredCommit = base.String()
	generationTwo.generationBody, err = generationTwo.generation.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	planSHA, err := generationTwo.plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	generationTwo.checkpoint, err = pub.NewCheckpoint(generationTwo.generation, "sibling-generation-2", planSHA, pub.PhaseCheckpointCommitted, time.Unix(1_700_000_100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	generationTwo.checkpointBody, err = generationTwo.checkpoint.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	installPurgeLedgerTestBodies(t, canonical, purgeLedgerTestTriplet(generationTwo), "test: generation two on sibling branch B")
	anchorTwo, err := canonical.HeadHash()
	if err != nil {
		t.Fatal(err)
	}
	anchorTwoCommit, err := repository.CommitObject(anchorTwo)
	if err != nil {
		t.Fatal(err)
	}
	merge := &object.Commit{
		Author:    object.Signature{Name: "sow-test", Email: "sow@localhost", When: time.Now().UTC().Add(time.Second)},
		Committer: object.Signature{Name: "sow-test", Email: "sow@localhost", When: time.Now().UTC().Add(time.Second)},
		Message:   "test: merge sibling publication histories",
		TreeHash:  anchorTwoCommit.TreeHash, ParentHashes: []plumbing.Hash{anchorTwo, anchorOne},
	}
	encoded := repository.Storer.NewEncodedObject()
	if err := merge.Encode(encoded); err != nil {
		t.Fatal(err)
	}
	mergeHash, err := repository.Storer.SetEncodedObject(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Storer.SetReference(plumbing.NewHashReference(head.Name(), mergeHash)); err != nil {
		t.Fatal(err)
	}

	findings, err := inspectCanonicalPurgeLedger(canonical, cfg, "cf")
	if err != nil || !purgeLedgerHasFinding(findings, "LOCAL_PURGE_LEDGER_ENVELOPE_INVALID") || !strings.Contains(findings[0].Message, "does not descend") {
		t.Fatalf("sibling publication findings=%#v err=%v", findings, err)
	}
	txDir, err := os.MkdirTemp(canonical.StateDir(), "sibling-repair-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(txDir)
	if _, err := repairCanonicalPurgeLedger(t.Context(), canonical, cfg, "cf", txDir); err == nil || !strings.Contains(err.Error(), "does not descend") {
		t.Fatalf("sibling publication repair err=%v", err)
	}
}

func TestCanonicalPurgeLedgerRejectsSameGenerationEnvelopeRewrite(t *testing.T) {
	t.Run("checkpoint-plan-blobs", func(t *testing.T) {
		canonical, cfg, envelope := newPurgeLedgerTestState(t, pub.Plan{})
		triplet := purgeLedgerTestTriplet(envelope)
		installPurgeLedgerTestBodies(t, canonical, triplet, "test: original publication envelope")

		alternatePlan := purgeLedgerPointerPlan(t)
		alternatePlanBody, err := alternatePlan.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		alternatePlanSHA, err := alternatePlan.Digest()
		if err != nil {
			t.Fatal(err)
		}
		alternateCheckpoint, err := pub.NewCheckpoint(envelope.generation, "ledger-test-rewrite", alternatePlanSHA, pub.PhaseCheckpointCommitted, time.Unix(1_700_000_001, 0).UTC())
		if err != nil {
			t.Fatal(err)
		}
		alternateCheckpointBody, err := alternateCheckpoint.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		installPurgeLedgerTestBodies(t, canonical, map[string][]byte{
			remoteStatePath("cf", "checkpoint.json"): alternateCheckpointBody,
			remoteStatePath("cf", "plan.json"):       alternatePlanBody,
		}, "test: rewrite same-generation checkpoint and plan")
		installPurgeLedgerTestBodies(t, canonical, map[string][]byte{
			remoteStatePath("cf", "checkpoint.json"): envelope.checkpointBody,
			remoteStatePath("cf", "plan.json"):       envelope.planBody,
		}, "test: restore same-generation checkpoint and plan")

		findings, err := inspectCanonicalPurgeLedger(canonical, cfg, "cf")
		if err != nil || !purgeLedgerHasFinding(findings, "LOCAL_PURGE_LEDGER_ENVELOPE_CHANGED") {
			t.Fatalf("findings=%#v err=%v", findings, err)
		}
	})

	t.Run("generation-blob-same-number", func(t *testing.T) {
		canonical, cfg, envelope := newPurgeLedgerTestState(t, pub.Plan{})
		triplet := purgeLedgerTestTriplet(envelope)
		installPurgeLedgerTestBodies(t, canonical, triplet, "test: original publication envelope")

		alternateGeneration := envelope.generation
		alternateGeneration.ConfigSHA256 = strings.Repeat("e", 64)
		alternateGenerationBody, err := alternateGeneration.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		planSHA, err := envelope.plan.Digest()
		if err != nil {
			t.Fatal(err)
		}
		alternateCheckpoint, err := pub.NewCheckpoint(alternateGeneration, "ledger-test-rewrite", planSHA, pub.PhaseCheckpointCommitted, time.Unix(1_700_000_001, 0).UTC())
		if err != nil {
			t.Fatal(err)
		}
		alternateCheckpointBody, err := alternateCheckpoint.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		installPurgeLedgerTestBodies(t, canonical, map[string][]byte{
			remoteStatePath("cf", "generation.json"): alternateGenerationBody,
			remoteStatePath("cf", "checkpoint.json"): alternateCheckpointBody,
		}, "test: rewrite same-number generation envelope")
		installPurgeLedgerTestBodies(t, canonical, map[string][]byte{
			remoteStatePath("cf", "generation.json"): envelope.generationBody,
			remoteStatePath("cf", "checkpoint.json"): envelope.checkpointBody,
		}, "test: restore same-number generation envelope")

		findings, err := inspectCanonicalPurgeLedger(canonical, cfg, "cf")
		if err != nil || !purgeLedgerHasFinding(findings, "LOCAL_PURGE_LEDGER_ENVELOPE_CHANGED") {
			t.Fatalf("findings=%#v err=%v", findings, err)
		}
	})
}

func TestCurrentCanonicalPurgeEvidenceClosureRejectsControlSubstitution(t *testing.T) {
	t.Run("plan-binding", func(t *testing.T) {
		canonical, cfg, envelope := newPurgeLedgerTestState(t, purgeLedgerPointerPlan(t))
		installPurgeLedgerTestBodies(t, canonical, purgeLedgerTestTriplet(envelope), "test: original nonempty publication envelope")
		purgeFreeBody, err := (pub.Plan{}).Canonical()
		if err != nil {
			t.Fatal(err)
		}
		installPurgeLedgerTestBodies(t, canonical, map[string][]byte{
			remoteStatePath("cf", "plan.json"): purgeFreeBody,
		}, "test: substitute purge-free plan")
		if err := validateCurrentCanonicalPurgeEvidenceClosure(canonical, cfg, "cf"); err == nil || !strings.Contains(err.Error(), "LOCAL_PLAN_BINDING_INVALID") {
			t.Fatalf("plan substitution err=%v", err)
		}
	})

	t.Run("purge-free-checkpoint-closure", func(t *testing.T) {
		canonical, cfg, envelope := newPurgeLedgerTestState(t, pub.Plan{})
		installPurgeLedgerTestBodies(t, canonical, purgeLedgerTestTriplet(envelope), "test: original purge-free publication envelope")
		checkpoint := envelope.checkpoint
		checkpoint.Generation++
		checkpoint.ParentGeneration++
		corruptBody, err := checkpoint.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		installPurgeLedgerTestBodies(t, canonical, map[string][]byte{
			remoteStatePath("cf", "checkpoint.json"): corruptBody,
		}, "test: corrupt purge-free checkpoint closure")
		if err := validateCurrentCanonicalPurgeEvidenceClosure(canonical, cfg, "cf"); err == nil {
			t.Fatal("purge-free checkpoint substitution passed current closure")
		}
	})
}

func TestRunPublishPurgeLedgerAuditCacheIsSuccessOnlyAndHeadScoped(t *testing.T) {
	if purgeLedgerAuditCacheFromContext(t.Context()) != nil {
		t.Fatal("ordinary contexts must not carry a purge ledger audit cache")
	}
	ctx := withRunPublishPurgeLedgerAuditCache(t.Context())
	cache := purgeLedgerAuditCacheFromContext(ctx)
	if cache == nil {
		t.Fatal("runPublish context has no purge ledger audit cache")
	}
	key := purgeLedgerAuditCacheKey{target: "cf", head: plumbing.NewHash(strings.Repeat("1", 40))}
	calls := 0
	if err := cache.run(ctx, key, func() error { calls++; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := cache.run(ctx, key, func() error { calls++; return errors.New("cached success reran") }); err != nil {
		t.Fatalf("cached success: %v", err)
	}
	if calls != 1 {
		t.Fatalf("same target+HEAD audit calls=%d want=1", calls)
	}

	failedKey := purgeLedgerAuditCacheKey{target: "cf", head: plumbing.NewHash(strings.Repeat("2", 40))}
	wantFailure := errors.New("injected audit failure")
	if err := cache.run(ctx, failedKey, func() error { calls++; return wantFailure }); !errors.Is(err, wantFailure) {
		t.Fatalf("failure=%v want=%v", err, wantFailure)
	}
	if err := cache.run(ctx, failedKey, func() error { calls++; return nil }); err != nil {
		t.Fatalf("failed audit was incorrectly cached: %v", err)
	}
	otherTarget := purgeLedgerAuditCacheKey{target: "cos", head: key.head}
	if err := cache.run(ctx, otherTarget, func() error { calls++; return nil }); err != nil {
		t.Fatal(err)
	}
	if calls != 4 {
		t.Fatalf("head/target scoped audit calls=%d want=4", calls)
	}
	if purgeLedgerAuditCacheFromContext(withRunPublishPurgeLedgerAuditCache(t.Context())) == cache {
		t.Fatal("separate runPublish contexts shared an audit cache")
	}
}

func TestCanonicalPurgeLedgerReceiptUsesSidecarReadLimit(t *testing.T) {
	canonical, cfg, envelope := newPurgeLedgerTestState(t, pub.Plan{})
	installPurgeLedgerTestBodies(t, canonical, purgeLedgerTestTriplet(envelope), "test: publication envelope")
	oversizedPath := purgeLedgerReceiptPath("cf", 1, "oversized")
	installPurgeLedgerTestBodies(t, canonical, map[string][]byte{
		oversizedPath: bytes.Repeat([]byte{'x'}, int(canonicalPurgeReceiptMaxBytes)+1),
	}, "test: oversized purge receipt")

	findings, err := inspectCanonicalPurgeLedger(canonical, cfg, "cf")
	if err == nil || !strings.Contains(err.Error(), "exceeds 4194304 bytes") || len(findings) != 0 {
		t.Fatalf("findings=%#v err=%v", findings, err)
	}
}

func TestPurgeLedgerAuditRetainedStateContainsNoReceiptOrEnvelopeBodies(t *testing.T) {
	byteSlice := reflect.TypeOf([]byte(nil))
	for _, value := range []any{purgeLedgerEnvelope{}, purgeLedgerReceipt{}} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			field := typeOf.Field(index)
			if field.Type == byteSlice {
				t.Fatalf("%s retains raw body field %s", typeOf.Name(), field.Name)
			}
		}
	}
}
