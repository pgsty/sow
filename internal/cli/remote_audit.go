package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	"github.com/pgsty/sow/internal/manifest"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/verify"
)

const remoteHeadBatchSize = 256

var (
	errCanonicalRemoteAuditState = errors.New("canonical remote audit state is invalid")
	errRemoteAdoptionDrift       = errors.New("remote inventory adoption evidence drifted")
	errRemoteObjectChanged       = errors.New("remote object changed during audit")
)

type canonicalRemoteAudit struct {
	generation     pub.TargetGeneration
	generationBody []byte
	generationLock []byte
	checkpoint     pub.Checkpoint
	checkpointBody []byte
	checkpointETag string
	plan           pub.Plan
	coverage       string
}

type remoteFindingSink interface {
	Add(verify.Finding)
}

type remoteFindingCollector struct {
	findings []verify.Finding
}

func (collector *remoteFindingCollector) Add(finding verify.Finding) {
	collector.findings = append(collector.findings, finding)
}

type remoteAuditStats struct {
	Listed            int64
	Expected          int64
	Missing           int64
	Changed           int64
	Orphan            int64
	Untracked         int64
	ZeroByteChecksums int64
	Pages             int64
	Coverage          string
}

type remoteAdoptionResult struct {
	Listed            int64
	LocalExpected     int64
	RetainedExtra     int64
	StreamedGET       int64
	ZeroByteChecksums int64
	Pages             int64
	Commit            string
	Changed           bool
}

// adoptRemoteInventory is filled out below as the explicit double-list
// baseline transaction. Keep the signature narrow so fsck remains the only
// caller holding the canonical state lock.
func adoptRemoteInventory(ctx context.Context, cfg *config.Config, canonical *state.Store, repos []config.Repo, target string, client *publishTargetClient, txDir string, workers, limit int, output io.Writer) (remoteAdoptionResult, error) {
	return adoptRemoteInventoryVerified(ctx, cfg, canonical, repos, target, client, txDir, workers, limit, output)
}

func adoptRemoteInventoryVerified(ctx context.Context, cfg *config.Config, canonical *state.Store, repos []config.Repo, target string, client *publishTargetClient, txDir string, workers, limit int, output io.Writer) (remoteAdoptionResult, error) {
	var result remoteAdoptionResult
	// This local-only gate deliberately precedes the staging directory and the
	// first ListObjects request. A missing historical purge receipt, legacy
	// attestation, or publication closure must fail before any provider access.
	if err := validateCanonicalRemoteAdoptionPreflight(canonical, cfg, target); err != nil {
		return result, err
	}
	targetRepos := reposPublishingToTarget(repos, target)
	if len(targetRepos) == 0 {
		return result, fmt.Errorf("none of the selected repositories publish to target %s", target)
	}
	allTargetRepos := reposPublishingToTarget(cfg.Repos, target)
	stageDir := filepath.Join(txDir, "adopt-"+target)
	if err := os.Mkdir(stageDir, 0o700); err != nil {
		return result, err
	}
	localManifest := filepath.Join(stageDir, "local-serving.tsv")
	if err := stageSelectedServingManifest(canonical, targetRepos, localManifest, stageDir); err != nil {
		return result, fmt.Errorf("%w: %v", errCanonicalRemoteAuditState, err)
	}
	localRemoteManifest := filepath.Join(stageDir, "local-serving-remote.tsv")
	if err := projectLatestSourceManifest(targetRepos, localManifest, localRemoteManifest, stageDir); err != nil {
		return result, fmt.Errorf("%w: project selected local serving baseline: %v", errCanonicalRemoteAuditState, err)
	}
	firstList := filepath.Join(stageDir, "list-first.tsv")
	firstStats, err := listRemoteObjects(ctx, client, firstList)
	if err != nil {
		return result, err
	}
	result.Listed, result.Pages = firstStats.Listed, firstStats.Pages
	resolvedInventory := filepath.Join(stageDir, "inventory.tsv")
	streamed, zeroChecksums, err := resolveListedRemoteInventory(ctx, client, firstList, resolvedInventory, workers)
	if err != nil {
		return result, err
	}
	result.StreamedGET, result.ZeroByteChecksums = streamed, zeroChecksums

	secondList := filepath.Join(stageDir, "list-second.tsv")
	secondStats, err := listRemoteObjects(ctx, client, secondList)
	if err != nil {
		return result, err
	}
	result.Pages += secondStats.Pages
	if firstStats.Listed != secondStats.Listed {
		return result, fmt.Errorf("%w: bucket object count changed between list snapshots", errRemoteAdoptionDrift)
	}
	if err := requireIdenticalManifestFiles(firstList, secondList); err != nil {
		return result, err
	}

	localCount, extras, zeroFromComparison, err := compareExpectedRemoteSubset(localRemoteManifest, resolvedInventory, target, limit, output, true)
	if err != nil {
		return result, err
	}
	result.LocalExpected, result.RetainedExtra = localCount, extras
	if zeroFromComparison > result.ZeroByteChecksums {
		result.ZeroByteChecksums = zeroFromComparison
	}
	if err := validateKnownRemoteStateForAdoption(ctx, cfg, canonical, target, client, resolvedInventory); err != nil {
		return result, err
	}
	_, _, knownGenerationExists, generationErr := readLocalTargetGeneration(canonical, target)
	if generationErr != nil {
		return result, fmt.Errorf("%w: %v", errCanonicalRemoteAuditState, generationErr)
	}
	if existing, exists, err := stageOptionalCanonicalFile(canonical, remoteStatePath(target, "inventory.tsv"), filepath.Join(stageDir, "prior-inventory.tsv")); err != nil {
		return result, fmt.Errorf("%w: %v", errCanonicalRemoteAuditState, err)
	} else if exists {
		if _, _, _, err := compareExpectedRemoteSubset(existing, resolvedInventory, target, 0, io.Discard, false); err != nil {
			return result, fmt.Errorf("%w: prior canonical inventory disagrees with the stable bucket: %v", errRemoteAdoptionDrift, err)
		}
	} else if knownGenerationExists {
		// content.tsv is a source-path baseline, not a remote-key inventory:
		// generation-pinned APT/YUM objects deliberately use different remote
		// names. Without the prior remote inventory there is no sound way to
		// prove that retained objects from older selector-scoped plans still
		// exist, so repair must fail closed instead of trusting the latest plan.
		return result, fmt.Errorf("%w: canonical remote inventory is missing for a known target generation", errCanonicalRemoteAuditState)
	}

	contentPath := filepath.Join(stageDir, "content.tsv")
	if priorContent, exists, err := stageOptionalCanonicalFile(canonical, remoteStatePath(target, "content.tsv"), filepath.Join(stageDir, "prior-content.tsv")); err != nil {
		return result, fmt.Errorf("%w: %v", errCanonicalRemoteAuditState, err)
	} else if exists {
		if knownGenerationExists {
			if _, _, _, err := compareExpectedRemoteSubset(localManifest, priorContent, target, 0, io.Discard, false); err != nil {
				return result, fmt.Errorf("%w: selected local baseline is outside the published generation content", errRemoteAdoptionDrift)
			}
			if err := copyRegularFileExclusive(priorContent, contentPath); err != nil {
				return result, err
			}
		} else if err := mergeManifestUnion(priorContent, localManifest, contentPath); err != nil {
			return result, fmt.Errorf("%w: merge adopted source baseline: %v", errRemoteAdoptionDrift, err)
		}
	} else if err := copyRegularFileExclusive(localManifest, contentPath); err != nil {
		return result, err
	}
	if !knownGenerationExists {
		projectedContent := filepath.Join(stageDir, "content-remote.tsv")
		if err := projectLatestSourceManifest(allTargetRepos, contentPath, projectedContent, stageDir); err != nil {
			return result, fmt.Errorf("%w: project adopted source baseline: %v", errCanonicalRemoteAuditState, err)
		}
		if _, _, _, err := compareExpectedRemoteSubset(projectedContent, resolvedInventory, target, 0, io.Discard, false); err != nil {
			return result, fmt.Errorf("%w: adopted source baseline is not fully verified remotely", errRemoteAdoptionDrift)
		}
	}
	coveragePath, err := stageInventoryCoverage(stageDir, remoteInventoryComplete)
	if err != nil {
		return result, err
	}
	commit, changed, err := applyCanonicalState(ctx, canonical, "fsck-adopt-remote-inventory", "sow fsck: adopt verified "+target+" remote inventory", map[string]string{
		remoteStatePath(target, "inventory.tsv"):      resolvedInventory,
		remoteStatePath(target, "inventory.coverage"): coveragePath,
		remoteStatePath(target, "content.tsv"):        contentPath,
	}, nil, state.ApplyOptions{})
	if err != nil {
		return result, fmt.Errorf("%w: commit adopted remote inventory: %v", errCanonicalRemoteAuditState, err)
	}
	result.Commit, result.Changed = commit.String(), changed
	return result, nil
}

func validateCanonicalRemoteAdoptionPreflight(canonical *state.Store, cfg *config.Config, target string) error {
	_, _, generationExists, err := readLocalTargetGeneration(canonical, target)
	if err != nil {
		return fmt.Errorf("%w: target %s read local generation: %v", errCanonicalRemoteAuditState, target, err)
	}
	if generationExists {
		collector := &remoteFindingCollector{}
		_, ready, err := inspectCanonicalRemoteState(canonical, cfg, target, true, collector)
		if err != nil {
			return fmt.Errorf("%w: target %s inspect canonical adoption state: %v", errCanonicalRemoteAuditState, target, err)
		}
		if !ready || len(collector.findings) != 0 {
			if len(collector.findings) != 0 {
				first := collector.findings[0]
				return fmt.Errorf("%w: target %s canonical adoption state %s: %s", errCanonicalRemoteAuditState, target, first.Code, first.Message)
			}
			return fmt.Errorf("%w: target %s canonical adoption state is incomplete", errCanonicalRemoteAuditState, target)
		}
		return nil
	}
	_, _, checkpointExists, err := readLocalTargetCheckpoint(canonical, target)
	if err != nil {
		return fmt.Errorf("%w: target %s read orphan checkpoint: %v", errCanonicalRemoteAuditState, target, err)
	}
	_, etagExists, err := readLocalTargetCheckpointETag(canonical, target)
	if err != nil {
		return fmt.Errorf("%w: target %s read orphan checkpoint ETag: %v", errCanonicalRemoteAuditState, target, err)
	}
	if checkpointExists || etagExists {
		return fmt.Errorf("%w: target %s canonical checkpoint or ETag exists without a generation", errCanonicalRemoteAuditState, target)
	}
	// A target whose aggregate generation was deleted can still have historical
	// publication evidence. Audit that history before treating it as a pristine
	// bucket-adoption boundary.
	if err := validateCurrentCanonicalPurgeEvidenceClosure(canonical, cfg, target); err != nil {
		return fmt.Errorf("%w: target %s current purge evidence closure: %v", errCanonicalRemoteAuditState, target, err)
	}
	findings, err := inspectCanonicalPurgeLedger(canonical, cfg, target)
	if err != nil {
		return fmt.Errorf("%w: target %s inspect historical purge ledger: %v", errCanonicalRemoteAuditState, target, err)
	}
	if len(findings) != 0 {
		first := findings[0]
		return fmt.Errorf("%w: target %s historical purge ledger %s: %s", errCanonicalRemoteAuditState, target, first.Code, first.Message)
	}
	return nil
}

func (client *publishTargetClient) headObject(ctx context.Context, key string) (pub.ObjectInfo, error) {
	if client == nil {
		return pub.ObjectInfo{}, errors.New("nil remote audit client")
	}
	if client.r2 != nil {
		return client.r2.R2Head(ctx, key)
	}
	if client.cos != nil {
		return client.cos.COSHead(ctx, key)
	}
	return pub.ObjectInfo{}, errors.New("remote audit client has no provider")
}

func (client *publishTargetClient) listObjectsV2(ctx context.Context, continuationToken string) (pub.ObjectListPage, error) {
	if client == nil {
		return pub.ObjectListPage{}, errors.New("nil remote audit client")
	}
	if client.r2 != nil {
		return client.r2.R2ListObjectsV2(ctx, continuationToken)
	}
	if client.cos != nil {
		return client.cos.COSListObjectsV2(ctx, continuationToken)
	}
	return pub.ObjectListPage{}, errors.New("remote audit client has no provider")
}

func (client *publishTargetClient) openObject(ctx context.Context, key string) (pub.ObjectContent, error) {
	if client == nil {
		return pub.ObjectContent{}, errors.New("nil remote audit client")
	}
	if client.r2 != nil {
		return client.r2.R2OpenObject(ctx, key)
	}
	if client.cos != nil {
		return client.cos.COSOpenObject(ctx, key)
	}
	return pub.ObjectContent{}, errors.New("remote audit client has no provider")
}

func buildRemoteL2Check(canonical *state.Store, cfg *config.Config, target string, client *publishTargetClient, networkFailure *atomic.Bool) verify.Check {
	return verify.CheckFunc{
		CheckID: "remote/" + target + "/closure", CheckLayer: verify.LayerL2,
		Run: func(ctx context.Context, recorder *verify.Recorder) error {
			local, ready, err := inspectCanonicalRemoteState(canonical, cfg, target, false, recorder)
			if err != nil || !ready {
				return err
			}
			if err := auditBoundedRemoteState(ctx, cfg, client, target, local, recorder); err != nil {
				networkFailure.Store(true)
				return err
			}
			return nil
		},
	}
}

func inspectCanonicalRemoteState(canonical *state.Store, cfg *config.Config, target string, allowPartialCoverage bool, recorder remoteFindingSink) (canonicalRemoteAudit, bool, error) {
	var audit canonicalRemoteAudit
	ready := true
	generation, generationBody, generationExists, err := readLocalTargetGeneration(canonical, target)
	if err != nil {
		return audit, false, err
	}
	checkpoint, checkpointBody, checkpointExists, err := readLocalTargetCheckpoint(canonical, target)
	if err != nil {
		return audit, false, err
	}
	etag, etagExists, err := readLocalTargetCheckpointETag(canonical, target)
	if err != nil {
		return audit, false, err
	}
	for _, item := range []struct {
		exists bool
		name   string
	}{{generationExists, "generation.json"}, {checkpointExists, "checkpoint.json"}, {etagExists, "checkpoint.etag"}} {
		if !item.exists {
			ready = false
			addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryDrift, "LOCAL_REMOTE_STATE_MISSING", target+"/"+item.name, "canonical published-state closure is incomplete")
		}
	}
	content, contentExists, err := openOptionalCanonical(canonical, remoteStatePath(target, "content.tsv"))
	if err != nil {
		return audit, false, err
	}
	if !contentExists {
		ready = false
		addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryDrift, "LOCAL_REMOTE_STATE_MISSING", target+"/content.tsv", "canonical source publication baseline is missing")
	} else {
		digest, hashErr := hashReader(content)
		if hashErr != nil {
			return audit, false, hashErr
		}
		if generationExists && digest != generation.ContentManifestSHA256 {
			ready = false
			addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryIntegrity, "LOCAL_CONTENT_DIGEST_CHANGED", target+"/content.tsv", "canonical source baseline does not match target generation")
		}
	}
	inventory, inventoryExists, err := openOptionalCanonical(canonical, remoteStatePath(target, "inventory.tsv"))
	if err != nil {
		return audit, false, err
	}
	if inventory != nil {
		_ = inventory.Close()
	}
	if !inventoryExists {
		ready = false
		addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryCoverage, "REMOTE_INVENTORY_MISSING", target, "canonical remote-key inventory is missing; import the existing bucket before claiming full audit coverage")
	}
	if generationExists {
		if err := validatePublicationChannelOwners(cfg, target, generation); err != nil {
			return audit, false, err
		}
		if err := validateGenerationCompatibility(cfg, canonical, target, generation); err != nil {
			return audit, false, err
		}
	}
	coverageBody, coverageExists, err := readOptionalCanonical(canonical, remoteStatePath(target, "inventory.coverage"))
	if err != nil {
		return audit, false, err
	}
	if !coverageExists || string(coverageBody) != remoteInventoryComplete && string(coverageBody) != remoteInventoryPartial {
		ready = false
		addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryCoverage, "REMOTE_INVENTORY_COVERAGE_MISSING", target, "remote inventory coverage marker is absent or invalid")
	} else {
		audit.coverage = string(coverageBody)
		if audit.coverage == remoteInventoryPartial && !allowPartialCoverage {
			addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryCoverage, "REMOTE_INVENTORY_PARTIAL", target, "remote inventory was not imported from the pre-existing bucket; unknown keys cannot be classified as safe orphans")
			ready = false
		}
	}
	planBody, planExists, err := readOptionalCanonical(canonical, remoteStatePath(target, "plan.json"))
	if err != nil {
		return audit, false, err
	}
	if !planExists {
		ready = false
		addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryDrift, "LOCAL_REMOTE_STATE_MISSING", target+"/plan.json", "canonical publication plan is missing")
	} else {
		audit.plan, err = pub.DecodePlan(planBody)
		if err != nil {
			ready = false
			addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryIntegrity, "LOCAL_PLAN_INVALID", target+"/plan.json", "canonical publication plan is invalid")
		}
	}
	if !ready {
		return audit, false, nil
	}
	if err := validateCommittedCompatibilityPublicationClosure(canonical, target, generation, audit.plan); err != nil {
		addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryIntegrity, "LOCAL_COMPATIBILITY_CLOSURE_CHANGED", target, err.Error())
		return audit, false, nil
	}
	audit.generation, audit.generationBody = generation, generationBody
	audit.checkpoint, audit.checkpointBody, audit.checkpointETag = checkpoint, checkpointBody, etag
	if checkpoint.Phase != pub.PhaseCheckpointCommitted || checkpoint.Generation != generation.Generation || !pub.SamePublicationIntent(checkpoint.IntentView, checkpoint.IntentSnapshot, generation.IntentView, generation.IntentSnapshot) || checkpoint.GenerationSHA256 != digestBytesCLI(generationBody) || checkpoint.ContentManifestSHA256 != generation.ContentManifestSHA256 || checkpoint.DesiredCommit != generation.DesiredCommit {
		addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryIntegrity, "LOCAL_CHECKPOINT_GENERATION_CHANGED", target, "canonical checkpoint and target generation disagree")
		return audit, false, nil
	}
	if finding, evidenceErr := inspectCanonicalPurgeEvidence(canonical, cfg, target, generation, generationBody, checkpoint, checkpointBody, audit.plan); evidenceErr != nil {
		return audit, false, evidenceErr
	} else if finding != nil {
		recorder.Add(*finding)
		return audit, false, nil
	}
	ledgerFindings, ledgerErr := inspectCanonicalPurgeLedger(canonical, cfg, target)
	if ledgerErr != nil {
		return audit, false, ledgerErr
	}
	for _, finding := range ledgerFindings {
		recorder.Add(finding)
	}
	if len(ledgerFindings) != 0 {
		return audit, false, nil
	}
	refsReady, err := inspectCanonicalRefVector(canonical, target, generation, recorder)
	if err != nil {
		return audit, false, err
	}
	if !refsReady {
		ready = false
	}
	expectedChannelPaths := make(map[string]struct{}, len(generation.Channels))
	for _, channel := range generation.Channels {
		expected, err := channel.CanonicalBody()
		if err != nil {
			return audit, false, err
		}
		path := remoteStatePath(target, filepath.ToSlash(filepath.Join("channels", channel.View, channel.Repo, channel.OS, channel.Arch+".json")))
		expectedChannelPaths[path] = struct{}{}
		actual, exists, err := readOptionalCanonical(canonical, path)
		if err != nil {
			return audit, false, err
		}
		if !exists || !bytes.Equal(actual, expected) || digestBytesCLI(actual) != channel.BodySHA256 {
			addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryIntegrity, "LOCAL_CHANNEL_CHANGED", channel.RemoteKey, "canonical channel bytes disagree with the target generation")
			ready = false
		}
	}
	head, err := canonical.HeadHash()
	if err != nil || head.IsZero() {
		return audit, false, errors.Join(err, errors.New("canonical channel audit requires an initialized HEAD"))
	}
	channelPrefix := remoteStatePath(target, "channels") + "/"
	actualChannelPaths, err := canonical.ListFilesAt(head, channelPrefix)
	if err != nil {
		return audit, false, err
	}
	for _, actual := range actualChannelPaths {
		if _, expected := expectedChannelPaths[actual]; expected {
			continue
		}
		addRemoteFinding(recorder, verify.SeverityError, verify.CategoryDrift, "LOCAL_CHANNEL_EXTRA", actual, "canonical channel is absent from the target generation")
		ready = false
	}
	if target == string(pub.TargetTencent) {
		audit.generationLock, err = expectedCOSGenerationLockBody(canonical, target, generation, generationBody, checkpoint)
		if err != nil {
			return audit, false, err
		}
	}
	return audit, ready, nil
}

func inspectCanonicalPurgeEvidence(canonical *state.Store, cfg *config.Config, target string, generation pub.TargetGeneration, generationBody []byte, checkpoint pub.Checkpoint, checkpointBody []byte, plan pub.Plan) (*verify.Finding, error) {
	planSHA, err := plan.Digest()
	if err != nil {
		return nil, err
	}
	legacyPlanBinding := false
	if checkpoint.PlanSHA256 == "" {
		// A v1 checkpoint can still prove a purge-free historical publication,
		// but a nonempty purge set requires an explicit local migration witness
		// bound to its immutable publication anchor. Never grandfather it merely
		// because a current receipt happens to be self-consistent.
		if len(plan.PurgeURLs) != 0 {
			legacyPlanBinding = true
		}
	} else if checkpoint.PlanSHA256 != planSHA {
		return canonicalPurgeEvidenceFinding(verify.CategoryIntegrity, "LOCAL_PLAN_BINDING_INVALID", remoteStatePath(target, "plan.json"), "canonical publish plan disagrees with the remote checkpoint"), nil
	}
	if len(plan.PurgeURLs) == 0 {
		return nil, nil
	}
	path := remoteStatePath(target, filepath.ToSlash(filepath.Join(
		"purges",
		fmt.Sprintf("%020d-%s.json", generation.Generation, checkpoint.TransactionID),
	)))
	body, exists, err := readOptionalCanonical(canonical, path)
	if err != nil {
		return nil, err
	}
	if !exists {
		return canonicalPurgeEvidenceFinding(verify.CategoryCoverage, "LOCAL_PURGE_EVIDENCE_MISSING", path, "canonical provider purge evidence is missing"), nil
	}
	evidence, err := pub.DecodePurgeEvidence(body)
	if err != nil {
		return canonicalPurgeEvidenceFinding(verify.CategoryIntegrity, "LOCAL_PURGE_EVIDENCE_INVALID", path, "canonical provider purge evidence is invalid or non-canonical"), nil
	}
	urlsSHA, err := pub.PurgeURLsDigest(plan.PurgeURLs)
	if err != nil {
		return nil, err
	}
	if evidence.Target != pub.TargetName(target) || evidence.TransactionID != checkpoint.TransactionID ||
		evidence.Generation != generation.Generation || evidence.GenerationSHA256 != digestBytesCLI(generationBody) ||
		evidence.PlanSHA256 != planSHA || evidence.CheckpointSHA256 != digestBytesCLI(checkpointBody) ||
		evidence.URLCount != len(plan.PurgeURLs) || evidence.URLsSHA256 != urlsSHA {
		return canonicalPurgeEvidenceFinding(verify.CategoryIntegrity, "LOCAL_PURGE_EVIDENCE_INVALID", path, "canonical provider purge evidence disagrees with the committed publication"), nil
	}
	latestFull := -1
	for index := range evidence.Attempts {
		if evidence.Attempts[index].Purpose == pub.PurgeAttemptFull {
			latestFull = index
		}
	}
	if latestFull < 0 || evidence.ValidateFullClosure(evidence.Attempts[latestFull].ID, plan.PurgeURLs) != nil {
		return canonicalPurgeEvidenceFinding(verify.CategoryCoverage, "LOCAL_PURGE_EVIDENCE_INCOMPLETE", path, "canonical provider purge evidence has no latest completed full closure"), nil
	}
	providerConfig := cfg
	if canonical != nil {
		providerConfig, err = canonicalProviderConfigurationForGeneration(canonical, cfg, target, generation.Generation)
		if err != nil {
			return canonicalPurgeEvidenceFinding(verify.CategoryCoverage, "LOCAL_PURGE_EVIDENCE_PROVIDER_UNBOUND", path, "publication-time canonical provider configuration is unavailable"), nil
		}
	}
	if providerConfig == nil {
		return nil, fmt.Errorf("canonical purge audit configuration is unavailable for target %s", target)
	}
	configured, exists := providerConfig.Targets[target]
	if !exists {
		return nil, fmt.Errorf("target %s is absent from canonical purge audit configuration", target)
	}
	var vendor, zoneID string
	switch pub.TargetName(target) {
	case pub.TargetCloudflare:
		vendor, zoneID = pub.PurgeVendorCloudflare, configured.CDN.ZoneID
	case pub.TargetTencent:
		vendor, zoneID = pub.PurgeVendorEdgeOne, configured.CDN.Distribution
	default:
		return nil, fmt.Errorf("unsupported canonical purge evidence target %q", target)
	}
	for _, receipt := range evidence.Attempts[latestFull].Batches {
		if receipt.Vendor != vendor || receipt.ZoneID != zoneID {
			return canonicalPurgeEvidenceFinding(verify.CategoryIntegrity, "LOCAL_PURGE_EVIDENCE_PROVIDER_CHANGED", path, "canonical purge receipt provider or zone differs from publication-time configuration"), nil
		}
	}
	if legacyPlanBinding {
		if canonical == nil {
			return canonicalPurgeEvidenceFinding(verify.CategoryCoverage, "LOCAL_PLAN_BINDING_MISSING", remoteStatePath(target, "checkpoint.json"), "legacy v1 checkpoint requires canonical publication history and an explicit purge plan attestation"), nil
		}
		envelope, err := legacyPurgeEnvelopeForClosure(canonical, target, generation, generationBody, checkpoint, checkpointBody, plan)
		if err != nil {
			return nil, err
		}
		return inspectLegacyPurgePlanAttestation(canonical, target, envelope, path, body)
	}
	return nil, nil
}

func canonicalPurgeEvidenceFinding(category verify.Category, code, subject, message string) *verify.Finding {
	return &verify.Finding{
		Layer: verify.LayerL2, Severity: verify.SeverityCritical, Category: category,
		Code: code, Subject: subject, Message: message,
	}
}

type canonicalPurgeEvidenceClosureError struct {
	finding verify.Finding
}

func (e *canonicalPurgeEvidenceClosureError) Error() string {
	return fmt.Sprintf("%s: %s", e.finding.Code, e.finding.Message)
}

func (e *canonicalPurgeEvidenceClosureError) Unwrap() error {
	return errCanonicalRemoteAuditState
}

// validateCurrentCanonicalPurgeEvidenceClosure verifies the durable provider
// receipt for the target's committed plan. Publish no-op paths call this before
// reporting unchanged so a missing or corrupted receipt cannot bypass repair.
func validateCurrentCanonicalPurgeEvidenceClosure(canonical *state.Store, cfg *config.Config, target string) error {
	generation, generationBody, generationExists, err := readLocalTargetGeneration(canonical, target)
	if err != nil {
		return fmt.Errorf("%w: %v", errCanonicalRemoteAuditState, err)
	}
	if !generationExists {
		return nil
	}
	checkpoint, checkpointBody, checkpointExists, err := readLocalTargetCheckpoint(canonical, target)
	if err != nil {
		return fmt.Errorf("%w: %v", errCanonicalRemoteAuditState, err)
	}
	planBody, planExists, err := readOptionalCanonical(canonical, remoteStatePath(target, "plan.json"))
	if err != nil {
		return fmt.Errorf("%w: %v", errCanonicalRemoteAuditState, err)
	}
	if !checkpointExists || !planExists {
		return fmt.Errorf("%w: canonical generation/checkpoint/plan closure is incomplete", errCanonicalRemoteAuditState)
	}
	plan, err := pub.DecodePlan(planBody)
	if err != nil {
		return fmt.Errorf("%w: canonical publish plan is invalid", errCanonicalRemoteAuditState)
	}
	if checkpoint.Phase != pub.PhaseCheckpointCommitted || checkpoint.Generation != generation.Generation ||
		!pub.SamePublicationIntent(checkpoint.IntentView, checkpoint.IntentSnapshot, generation.IntentView, generation.IntentSnapshot) ||
		checkpoint.GenerationSHA256 != digestBytesCLI(generationBody) || checkpoint.ContentManifestSHA256 != generation.ContentManifestSHA256 ||
		checkpoint.DesiredCommit != generation.DesiredCommit {
		return fmt.Errorf("%w: canonical checkpoint disagrees with target generation", errCanonicalRemoteAuditState)
	}
	finding, err := inspectCanonicalPurgeEvidence(canonical, cfg, target, generation, generationBody, checkpoint, checkpointBody, plan)
	if err != nil {
		return fmt.Errorf("%w: inspect canonical purge evidence: %v", errCanonicalRemoteAuditState, err)
	}
	return canonicalPurgeEvidenceError(finding)
}

func canonicalPurgeEvidenceError(finding *verify.Finding) error {
	if finding == nil {
		return nil
	}
	return &canonicalPurgeEvidenceClosureError{finding: *finding}
}

func printRemoteFSCKFinding(output io.Writer, target string, finding *verify.Finding) {
	if finding == nil {
		return
	}
	fmt.Fprintf(output, "remote-drift target=%s kind=canonical severity=%s code=%s subject=%q message=%q\n",
		target, finding.Severity, finding.Code, finding.Subject, finding.Message)
}

func inspectCanonicalRefVector(canonical *state.Store, target string, generation pub.TargetGeneration, recorder remoteFindingSink) (bool, error) {
	valid := true
	desired := make(map[plumbing.ReferenceName]struct{}, len(generation.Refs))
	for _, ref := range generation.Refs {
		remoteRef, err := desiredToRemoteRef(target, ref.Name)
		if err != nil {
			return false, err
		}
		desired[remoteRef] = struct{}{}
		actual, exists, err := canonical.Ref(remoteRef)
		if err != nil {
			return false, err
		}
		if !exists || actual.String() != ref.Commit {
			addRemoteFinding(recorder, verify.SeverityError, verify.CategoryDrift, "LOCAL_REMOTE_REF_CHANGED", remoteRef.String(), "canonical remote ref differs from the target generation")
			valid = false
		}
		manifestPath, err := targetRefManifestPath(ref.Name)
		if err != nil {
			return false, err
		}
		reader, err := canonical.OpenPathAt(plumbing.NewHash(ref.Commit), manifestPath)
		if err != nil {
			addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryIntegrity, "LOCAL_REF_MANIFEST_MISSING", ref.Name, "target generation ref cannot open its canonical manifest")
			valid = false
			continue
		}
		digest, err := hashReader(reader)
		if err != nil {
			return false, err
		}
		if digest != ref.ManifestSHA256 {
			addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryIntegrity, "LOCAL_REF_MANIFEST_CHANGED", ref.Name, "target generation ref manifest digest differs")
			valid = false
		}
	}
	allRefs, err := canonical.SOWRefs()
	if err != nil {
		return false, err
	}
	prefix := "refs/sow/remotes/" + target + "/"
	for _, current := range allRefs {
		if !strings.HasPrefix(current.Name.String(), prefix) {
			continue
		}
		if _, expected := desired[current.Name]; expected {
			continue
		}
		addRemoteFinding(recorder, verify.SeverityError, verify.CategoryDrift, "LOCAL_REMOTE_REF_EXTRA", current.Name.String(), "canonical remote ref is absent from the target generation")
		valid = false
	}
	return valid, nil
}

func targetRefManifestPath(refName string) (string, error) {
	parts := strings.Split(refName, "/")
	if len(parts) != 7 || parts[0] != "refs" || parts[1] != "sow" {
		return "", fmt.Errorf("unsupported target ref %q", refName)
	}
	switch parts[2] {
	case "views":
		return state.ViewPath(parts[3], parts[4], parts[5], parts[6])
	case "snapshots":
		return state.SnapshotPath(parts[3], parts[4], parts[5], parts[6])
	default:
		return "", fmt.Errorf("unsupported target ref %q", refName)
	}
}

func auditBoundedRemoteState(ctx context.Context, cfg *config.Config, client *publishTargetClient, target string, local canonicalRemoteAudit, recorder *verify.Recorder) error {
	checkpoint, err := client.getControl(ctx, pub.CheckpointKey)
	if err != nil {
		return err
	}
	if !checkpoint.Exists {
		addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryDrift, "REMOTE_CHECKPOINT_MISSING", target, "remote checkpoint is missing")
		return nil
	}
	if !bytes.Equal(checkpoint.Body, local.checkpointBody) {
		addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryDrift, "REMOTE_CHECKPOINT_CHANGED", target, "remote checkpoint bytes differ from canonical published state")
	}
	if checkpoint.ETag != local.checkpointETag {
		addRemoteFinding(recorder, verify.SeverityError, verify.CategoryDrift, "REMOTE_CHECKPOINT_ETAG_CHANGED", target, "remote checkpoint ETag differs from canonical published state")
	}
	generationKey, _ := pub.GenerationKey(local.generation.Generation)
	generation, err := client.getControl(ctx, generationKey)
	if err != nil {
		return err
	}
	if !generation.Exists {
		addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryDrift, "REMOTE_GENERATION_MISSING", generationKey, "immutable target generation is missing")
	} else if !bytes.Equal(generation.Body, local.generationBody) || digestBytesCLI(generation.Body) != local.checkpoint.GenerationSHA256 {
		addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryDrift, "REMOTE_GENERATION_CHANGED", generationKey, "immutable target generation bytes differ from canonical state")
	}
	if target == string(pub.TargetTencent) {
		lockKey, _ := pub.GenerationLockKey(local.generation.Generation)
		lock, err := client.getControl(ctx, lockKey)
		if err != nil {
			return err
		}
		switch {
		case !lock.Exists:
			addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryDrift, "REMOTE_GENERATION_LOCK_MISSING", lockKey, "COS create-only generation lock is missing")
		case !bytes.Equal(lock.Body, local.generationLock):
			addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryIntegrity, "REMOTE_GENERATION_LOCK_CHANGED", lockKey, "COS create-only generation lock differs from canonical publication facts")
		}
	}
	for _, channel := range local.generation.Channels {
		baseURL := cfg.Targets[target].CDN.BaseURL
		if channel.View == "beta" {
			baseURL = cfg.Targets[target].CDN.BetaBaseURL
		}
		remoteKey, expected, err := pub.YUMChannelPointer(baseURL, channel)
		if err != nil {
			return err
		}
		actual, err := client.getControl(ctx, remoteKey)
		if err != nil {
			return err
		}
		switch {
		case !actual.Exists:
			addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryDrift, "REMOTE_CHANNEL_MISSING", remoteKey, "remote channel entry point is missing")
		case !bytes.Equal(actual.Body, expected):
			addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryDrift, "REMOTE_CHANNEL_CHANGED", remoteKey, "remote channel entry point bytes differ from canonical state")
		}
	}
	if err := auditPlanObjectHeads(ctx, client, local.plan.Objects, recorder); err != nil {
		return err
	}
	return auditPlanDeletionHeads(ctx, client, local.plan.Deletes, recorder)
}

func expectedCOSGenerationLockBody(canonical *state.Store, target string, generation pub.TargetGeneration, generationBody []byte, checkpoint pub.Checkpoint) ([]byte, error) {
	if target != string(pub.TargetTencent) || generation.Target != pub.TargetTencent || checkpoint.Target != pub.TargetTencent {
		return nil, errors.New("COS generation lock expectation requires the Tencent target")
	}
	parentCheckpointSHA := ""
	if generation.ParentGeneration != 0 {
		parentCommit, parentGeneration, err := targetGenerationPublicationState(canonical, target, generation.ParentGeneration)
		if err != nil {
			return nil, fmt.Errorf("resolve COS parent generation lock binding: %w", err)
		}
		parentBody, exists, err := readCanonicalBytesAt(canonical, parentCommit, remoteStatePath(target, "checkpoint.json"), 16<<20)
		if err != nil || !exists {
			return nil, errors.Join(err, errors.New("COS parent checkpoint is missing from canonical publication history"))
		}
		parentCheckpoint, err := pub.DecodeCheckpoint(parentBody)
		if err != nil || parentCheckpoint.Generation != parentGeneration.Generation || parentCheckpoint.Phase != pub.PhaseCheckpointCommitted {
			return nil, errors.Join(err, errors.New("COS parent checkpoint history is invalid"))
		}
		parentCheckpointSHA = digestBytesCLI(parentBody)
	}
	lock := pub.GenerationLock{
		Schema: pub.GenerationLockSchema, Target: pub.TargetTencent,
		Generation: generation.Generation, ParentGeneration: generation.ParentGeneration,
		ParentCheckpointSHA256: parentCheckpointSHA,
		GenerationSHA256:       digestBytesCLI(generationBody),
		TransactionID:          checkpoint.TransactionID,
		IntentView:             generation.IntentView,
		IntentSnapshot:         generation.IntentSnapshot,
		UpdatedAt:              checkpoint.UpdatedAt,
	}
	return lock.Canonical()
}

func auditPlanObjectHeads(ctx context.Context, client *publishTargetClient, objects []pub.PlannedObject, recorder *verify.Recorder) error {
	for _, adopted := range []bool{false, true} {
		entries := make([]manifest.Entry, 0, len(objects))
		for _, object := range objects {
			if (object.Class == pub.ObjectAdoptedImmutable) != adopted {
				continue
			}
			entry, err := remoteInventoryEntry(object.RemoteKey, object.Size, object.SHA256)
			if err != nil {
				return err
			}
			entries = append(entries, entry)
		}
		for start := 0; start < len(entries); start += remoteHeadBatchSize {
			end := min(start+remoteHeadBatchSize, len(entries))
			batch := entries[start:end]
			results := runRemoteHeadBatch(ctx, client, batch, min(16, len(batch)), adopted, adopted)
			for index, result := range results {
				if result.err != nil {
					if adopted && errors.Is(result.err, errRemoteObjectChanged) {
						drifted := result.info
						drifted.SHA256 = ""
						recordRemoteHeadFinding(recorder, batch[index], drifted)
						continue
					}
					return result.err
				}
				recordRemoteHeadFinding(recorder, batch[index], result.info)
			}
		}
	}
	return nil
}

func auditPlanDeletionHeads(ctx context.Context, client *publishTargetClient, deletions []pub.PlannedDelete, recorder *verify.Recorder) error {
	for _, deletion := range deletions {
		info, err := client.headObject(ctx, deletion.RemoteKey)
		if err != nil {
			return err
		}
		if info.Exists {
			addRemoteFinding(recorder, verify.SeverityCritical, verify.CategoryDrift, "REMOTE_DELETED_OBJECT_PRESENT", deletion.RemoteKey, "snapshot-owned object remains present after its committed deletion")
		}
	}
	return nil
}

type remoteHeadResult struct {
	info pub.ObjectInfo
	err  error
}

func runRemoteHeadBatch(ctx context.Context, client *publishTargetClient, entries []manifest.Entry, workers int, allowGETFallback, strictETag bool) []remoteHeadResult {
	results := make([]remoteHeadResult, len(entries))
	if len(entries) == 0 {
		return results
	}
	if workers < 1 {
		workers = 1
	}
	if workers > 64 {
		workers = 64
	}
	if workers > len(entries) {
		workers = len(entries)
	}
	jobs := make(chan int)
	var group sync.WaitGroup
	group.Add(workers)
	for range workers {
		go func() {
			defer group.Done()
			for index := range jobs {
				results[index].info, results[index].err = inspectRemoteObject(ctx, client, entries[index], allowGETFallback, strictETag)
			}
		}()
	}
	for index := range entries {
		jobs <- index
	}
	close(jobs)
	group.Wait()
	return results
}

func inspectRemoteObject(ctx context.Context, client *publishTargetClient, expected manifest.Entry, allowGETFallback, strictETag bool) (pub.ObjectInfo, error) {
	info, err := client.headObject(ctx, expected.Path)
	if err != nil || !info.Exists || info.Size != expected.Size || !allowGETFallback {
		return info, err
	}
	if info.SHA256 != "" && info.SHA256 != expected.HashString() {
		return info, nil
	}
	digest, err := streamRemoteObjectDigest(ctx, client, expected, info, strictETag)
	if err != nil {
		return info, err
	}
	info.SHA256 = digest
	return info, nil
}

func streamRemoteObjectDigest(ctx context.Context, client *publishTargetClient, expected manifest.Entry, head pub.ObjectInfo, strictETag bool) (string, error) {
	content, err := client.openObject(ctx, expected.Path)
	if err != nil {
		return "", err
	}
	hasher := sha256.New()
	if expected.Size == math.MaxInt64 {
		content.Body.Close()
		return "", errors.New("remote object size exceeds streaming safety limit")
	}
	written, copyErr := io.Copy(hasher, io.LimitReader(content.Body, expected.Size+1))
	closeErr := content.Body.Close()
	if copyErr != nil || closeErr != nil {
		return "", errors.Join(copyErr, closeErr)
	}
	if written != expected.Size || content.Info.Size >= 0 && content.Info.Size != expected.Size ||
		strictETag && (head.ETag == "" || content.Info.ETag == "" || head.ETag != content.Info.ETag) ||
		!strictETag && head.ETag != "" && content.Info.ETag != "" && head.ETag != content.Info.ETag {
		return "", errRemoteObjectChanged
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

type resolvedRemoteObject struct {
	entry       manifest.Entry
	streamedGET bool
	err         error
}

func resolveListedRemoteInventory(ctx context.Context, client *publishTargetClient, listedPath, destination string, workers int) (streamedGET, zeroChecksums int64, resultErr error) {
	listed, err := os.Open(listedPath)
	if err != nil {
		return 0, 0, err
	}
	defer listed.Close()
	reader := manifest.NewReader(listed)
	resultErr = writeExclusiveManifest(destination, func(output io.Writer) error {
		batch := make([]manifest.Entry, 0, remoteHeadBatchSize)
		flush := func() error {
			if len(batch) == 0 {
				return nil
			}
			results := resolveListedRemoteBatch(ctx, client, batch, workers)
			for _, resolved := range results {
				if resolved.err != nil {
					return resolved.err
				}
				if err := manifest.WriteEntry(output, resolved.entry); err != nil {
					return err
				}
				if resolved.streamedGET {
					streamedGET++
				}
				if resolved.entry.Size == 0 && looksLikeChecksumKey(resolved.entry.Path) {
					zeroChecksums++
				}
			}
			batch = batch[:0]
			return nil
		}
		for {
			entry, err := reader.Next()
			if errors.Is(err, io.EOF) {
				return flush()
			}
			if err != nil {
				return err
			}
			batch = append(batch, entry)
			if len(batch) == remoteHeadBatchSize {
				if err := flush(); err != nil {
					return err
				}
			}
		}
	})
	return streamedGET, zeroChecksums, resultErr
}

func resolveListedRemoteBatch(ctx context.Context, client *publishTargetClient, entries []manifest.Entry, workers int) []resolvedRemoteObject {
	results := make([]resolvedRemoteObject, len(entries))
	if len(entries) == 0 {
		return results
	}
	if workers < 1 {
		workers = 1
	}
	if workers > 64 {
		workers = 64
	}
	if workers > len(entries) {
		workers = len(entries)
	}
	jobs := make(chan int)
	var group sync.WaitGroup
	group.Add(workers)
	for range workers {
		go func() {
			defer group.Done()
			for index := range jobs {
				results[index] = resolveListedRemoteObject(ctx, client, entries[index])
			}
		}()
	}
	for index := range entries {
		jobs <- index
	}
	close(jobs)
	group.Wait()
	return results
}

func resolveListedRemoteObject(ctx context.Context, client *publishTargetClient, listed manifest.Entry) resolvedRemoteObject {
	info, err := client.headObject(ctx, listed.Path)
	if err != nil {
		return resolvedRemoteObject{err: err}
	}
	if !info.Exists || info.Size != listed.Size || info.ETag == "" || digestBytesCLI([]byte("etag:"+info.ETag)) != listed.HashString() {
		return resolvedRemoteObject{err: fmt.Errorf("%w: listed object changed before HEAD", errRemoteAdoptionDrift)}
	}
	// Explicit adoption is the remote byte-baseline operation. Custom metadata
	// is useful corroborating evidence but never substitutes for reading the
	// object: every listed key is streamed, bounded by its listed size, and tied
	// to the preceding HEAD through a non-empty, equal ETag.
	sha, err := streamRemoteObjectDigest(ctx, client, listed, info, true)
	if err != nil {
		if errors.Is(err, pub.ErrNotFound) || errors.Is(err, errRemoteObjectChanged) {
			return resolvedRemoteObject{err: fmt.Errorf("%w: listed object changed during GET", errRemoteAdoptionDrift)}
		}
		return resolvedRemoteObject{err: err}
	}
	if info.SHA256 != "" && !canonicalRemoteSHA256(info.SHA256) {
		return resolvedRemoteObject{err: fmt.Errorf("%w: object has malformed sow-sha256 metadata", errRemoteAdoptionDrift)}
	}
	if info.SHA256 != "" && info.SHA256 != sha {
		return resolvedRemoteObject{err: fmt.Errorf("%w: object sow-sha256 metadata differs from streamed body", errRemoteAdoptionDrift)}
	}
	entry, err := remoteInventoryEntry(listed.Path, listed.Size, sha)
	if err != nil {
		return resolvedRemoteObject{err: fmt.Errorf("%w: resolved object is invalid", errRemoteAdoptionDrift)}
	}
	return resolvedRemoteObject{entry: entry, streamedGET: true}
}

func canonicalRemoteSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func requireIdenticalManifestFiles(firstPath, secondPath string) error {
	first, err := os.Open(firstPath)
	if err != nil {
		return err
	}
	second, err := os.Open(secondPath)
	if err != nil {
		first.Close()
		return err
	}
	stats, diffErr := manifest.Diff(first, second, nil)
	closeErr := errors.Join(first.Close(), second.Close())
	if diffErr != nil || closeErr != nil {
		return errors.Join(diffErr, closeErr)
	}
	if !stats.Clean() {
		return fmt.Errorf("%w: bucket changed between ListObjectsV2 snapshots", errRemoteAdoptionDrift)
	}
	return nil
}

func stageSelectedServingManifest(canonical *state.Store, repos []config.Repo, destination, stageDir string) error {
	if len(repos) == 0 {
		return errors.New("no selected repositories")
	}
	inputs := make([]string, 0, len(repos))
	for index, repo := range repos {
		reader, err := canonical.OpenManifest(repo.ID)
		if err != nil {
			return fmt.Errorf("open baseline manifest for %s: %w", repo.ID, err)
		}
		path := filepath.Join(stageDir, fmt.Sprintf("local-%06d.tsv", index))
		if err := writeReaderExclusive(reader, path); err != nil {
			return err
		}
		inputs = append(inputs, path)
	}
	return mergePublicationManifests(inputs, destination, stageDir)
}

func writeReaderExclusive(reader io.ReadCloser, destination string) error {
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		reader.Close()
		return err
	}
	_, copyErr := io.Copy(file, reader)
	return errors.Join(copyErr, reader.Close(), file.Sync(), file.Close())
}

func stageOptionalCanonicalFile(canonical *state.Store, canonicalPath, destination string) (string, bool, error) {
	reader, exists, err := openOptionalCanonical(canonical, canonicalPath)
	if err != nil || !exists {
		return "", exists, err
	}
	if err := writeReaderExclusive(reader, destination); err != nil {
		return "", false, err
	}
	return destination, true, nil
}

func copyRegularFileExclusive(sourcePath, destinationPath string) error {
	source, err := openRegularManifest(sourcePath)
	if err != nil {
		return err
	}
	return writeReaderExclusive(source, destinationPath)
}

func mergeManifestUnion(leftPath, rightPath, destinationPath string) error {
	left, err := openRegularManifest(leftPath)
	if err != nil {
		return err
	}
	defer left.Close()
	right, err := openRegularManifest(rightPath)
	if err != nil {
		return err
	}
	defer right.Close()
	leftReader, rightReader := manifest.NewReader(left), manifest.NewReader(right)
	leftEntry, leftErr := leftReader.Next()
	rightEntry, rightErr := rightReader.Next()
	return writeExclusiveManifest(destinationPath, func(output io.Writer) error {
		for !errors.Is(leftErr, io.EOF) || !errors.Is(rightErr, io.EOF) {
			if leftErr != nil && !errors.Is(leftErr, io.EOF) || rightErr != nil && !errors.Is(rightErr, io.EOF) {
				return errors.Join(leftErr, rightErr)
			}
			var entry manifest.Entry
			switch {
			case errors.Is(leftErr, io.EOF):
				entry = rightEntry
				rightEntry, rightErr = rightReader.Next()
			case errors.Is(rightErr, io.EOF):
				entry = leftEntry
				leftEntry, leftErr = leftReader.Next()
			case leftEntry.Path < rightEntry.Path:
				entry = leftEntry
				leftEntry, leftErr = leftReader.Next()
			case rightEntry.Path < leftEntry.Path:
				entry = rightEntry
				rightEntry, rightErr = rightReader.Next()
			default:
				if leftEntry.Size != rightEntry.Size || leftEntry.SHA256 != rightEntry.SHA256 {
					return fmt.Errorf("source baseline path %q has conflicting bytes", leftEntry.Path)
				}
				entry = leftEntry
				leftEntry, leftErr = leftReader.Next()
				rightEntry, rightErr = rightReader.Next()
			}
			if err := manifest.WriteEntry(output, entry); err != nil {
				return err
			}
		}
		return nil
	})
}

func compareExpectedRemoteSubset(expectedPath, actualPath, target string, limit int, output io.Writer, reportExtras bool) (expectedCount, extras, zeroChecksums int64, resultErr error) {
	expectedFile, err := openRegularManifest(expectedPath)
	if err != nil {
		return 0, 0, 0, err
	}
	defer expectedFile.Close()
	actualFile, err := openRegularManifest(actualPath)
	if err != nil {
		return 0, 0, 0, err
	}
	defer actualFile.Close()
	expected, actual := manifest.NewReader(expectedFile), manifest.NewReader(actualFile)
	expectedEntry, expectedErr := expected.Next()
	actualEntry, actualErr := actual.Next()
	printed := 0
	drifted := false
	for !errors.Is(expectedErr, io.EOF) || !errors.Is(actualErr, io.EOF) {
		if expectedErr != nil && !errors.Is(expectedErr, io.EOF) {
			return expectedCount, extras, zeroChecksums, fmt.Errorf("read expected serving manifest: %w", expectedErr)
		}
		if actualErr != nil && !errors.Is(actualErr, io.EOF) {
			return expectedCount, extras, zeroChecksums, fmt.Errorf("read resolved remote inventory: %w", actualErr)
		}
		switch {
		case errors.Is(actualErr, io.EOF) || !errors.Is(expectedErr, io.EOF) && expectedEntry.Path < actualEntry.Path:
			expectedCount++
			drifted = true
			if printed < limit {
				fmt.Fprintf(output, "remote-adopt target=%s kind=local-missing path=%s\n", target, redactRemoteAuditKey(expectedEntry.Path))
				printed++
			}
			expectedEntry, expectedErr = expected.Next()
		case errors.Is(expectedErr, io.EOF) || actualEntry.Path < expectedEntry.Path:
			extras++
			if actualEntry.Size == 0 && looksLikeChecksumKey(actualEntry.Path) {
				zeroChecksums++
			}
			if reportExtras && printed < limit {
				fmt.Fprintf(output, "remote-adopt target=%s kind=retained-remote-extra path=%s\n", target, redactRemoteAuditKey(actualEntry.Path))
				printed++
			}
			actualEntry, actualErr = actual.Next()
		default:
			expectedCount++
			if expectedEntry.Size != actualEntry.Size || expectedEntry.SHA256 != actualEntry.SHA256 {
				drifted = true
				if printed < limit {
					fmt.Fprintf(output, "remote-adopt target=%s kind=local-changed path=%s\n", target, redactRemoteAuditKey(expectedEntry.Path))
					printed++
				}
			}
			if actualEntry.Size == 0 && looksLikeChecksumKey(actualEntry.Path) {
				zeroChecksums++
			}
			expectedEntry, expectedErr = expected.Next()
			actualEntry, actualErr = actual.Next()
		}
	}
	if drifted {
		return expectedCount, extras, zeroChecksums, fmt.Errorf("%w: local serving tree is not an exact remote subset", errRemoteAdoptionDrift)
	}
	return expectedCount, extras, zeroChecksums, nil
}

func validateKnownRemoteStateForAdoption(ctx context.Context, cfg *config.Config, canonical *state.Store, target string, client *publishTargetClient, resolvedInventory string) error {
	generation, generationBody, generationExists, err := readLocalTargetGeneration(canonical, target)
	if err != nil {
		return fmt.Errorf("%w: %v", errCanonicalRemoteAuditState, err)
	}
	checkpoint, checkpointBody, checkpointExists, err := readLocalTargetCheckpoint(canonical, target)
	if err != nil {
		return fmt.Errorf("%w: %v", errCanonicalRemoteAuditState, err)
	}
	etag, etagExists, err := readLocalTargetCheckpointETag(canonical, target)
	if err != nil {
		return fmt.Errorf("%w: %v", errCanonicalRemoteAuditState, err)
	}
	if !generationExists {
		if checkpointExists || etagExists {
			return fmt.Errorf("%w: canonical checkpoint exists without a target generation", errCanonicalRemoteAuditState)
		}
		if containsUntrackedSOWControl(resolvedInventory) {
			return fmt.Errorf("%w: bucket contains SOW control objects without matching canonical state", errRemoteAdoptionDrift)
		}
		return nil
	}
	if !checkpointExists || !etagExists {
		return fmt.Errorf("%w: canonical generation/checkpoint/ETag closure is incomplete", errCanonicalRemoteAuditState)
	}
	if checkpoint.Phase != pub.PhaseCheckpointCommitted || checkpoint.Generation != generation.Generation || !pub.SamePublicationIntent(checkpoint.IntentView, checkpoint.IntentSnapshot, generation.IntentView, generation.IntentSnapshot) || checkpoint.GenerationSHA256 != digestBytesCLI(generationBody) || checkpoint.ContentManifestSHA256 != generation.ContentManifestSHA256 || checkpoint.DesiredCommit != generation.DesiredCommit {
		return fmt.Errorf("%w: canonical checkpoint disagrees with target generation", errCanonicalRemoteAuditState)
	}
	content, exists, err := openOptionalCanonical(canonical, remoteStatePath(target, "content.tsv"))
	if err != nil || !exists {
		return fmt.Errorf("%w: canonical content baseline is missing", errCanonicalRemoteAuditState)
	}
	contentSHA, err := hashReader(content)
	if err != nil || contentSHA != generation.ContentManifestSHA256 {
		return fmt.Errorf("%w: canonical content baseline digest differs", errCanonicalRemoteAuditState)
	}
	planBody, exists, err := readOptionalCanonical(canonical, remoteStatePath(target, "plan.json"))
	if err != nil || !exists {
		return fmt.Errorf("%w: canonical publish plan is missing", errCanonicalRemoteAuditState)
	}
	plan, err := pub.DecodePlan(planBody)
	if err != nil {
		return fmt.Errorf("%w: canonical publish plan is invalid", errCanonicalRemoteAuditState)
	}
	if finding, evidenceErr := inspectCanonicalPurgeEvidence(canonical, cfg, target, generation, generationBody, checkpoint, checkpointBody, plan); evidenceErr != nil {
		return fmt.Errorf("%w: inspect canonical purge evidence: %v", errCanonicalRemoteAuditState, evidenceErr)
	} else if finding != nil {
		return canonicalPurgeEvidenceError(finding)
	}
	if err := validateLocalRemoteRefs(canonical, target, generation); err != nil {
		return fmt.Errorf("%w: %v", errCanonicalRemoteAuditState, err)
	}
	if err := validateLocalChannelState(canonical, target, generation); err != nil {
		return fmt.Errorf("%w: %v", errCanonicalRemoteAuditState, err)
	}
	for _, ref := range generation.Refs {
		manifestPath, err := targetRefManifestPath(ref.Name)
		if err != nil {
			return fmt.Errorf("%w: %v", errCanonicalRemoteAuditState, err)
		}
		reader, err := canonical.OpenPathAt(plumbing.NewHash(ref.Commit), manifestPath)
		if err != nil {
			return fmt.Errorf("%w: target ref manifest is missing", errCanonicalRemoteAuditState)
		}
		digest, err := hashReader(reader)
		if err != nil || digest != ref.ManifestSHA256 {
			return fmt.Errorf("%w: target ref manifest digest differs", errCanonicalRemoteAuditState)
		}
	}
	remoteCheckpoint, err := client.getControl(ctx, pub.CheckpointKey)
	if err != nil {
		return err
	}
	if !remoteCheckpoint.Exists || !bytes.Equal(remoteCheckpoint.Body, checkpointBody) || remoteCheckpoint.ETag != etag {
		return fmt.Errorf("%w: remote checkpoint differs from canonical state", errRemoteAdoptionDrift)
	}
	generationKey, _ := pub.GenerationKey(generation.Generation)
	remoteGeneration, err := client.getControl(ctx, generationKey)
	if err != nil {
		return err
	}
	if !remoteGeneration.Exists || !bytes.Equal(remoteGeneration.Body, generationBody) {
		return fmt.Errorf("%w: remote target generation differs from canonical state", errRemoteAdoptionDrift)
	}
	for _, channel := range generation.Channels {
		baseURL := cfg.Targets[target].CDN.BaseURL
		if channel.View == "beta" {
			baseURL = cfg.Targets[target].CDN.BetaBaseURL
		}
		remoteKey, expected, err := pub.YUMChannelPointer(baseURL, channel)
		if err != nil {
			return fmt.Errorf("%w: %v", errCanonicalRemoteAuditState, err)
		}
		remote, err := client.getControl(ctx, remoteKey)
		if err != nil {
			return err
		}
		if !remote.Exists || !bytes.Equal(remote.Body, expected) {
			return fmt.Errorf("%w: remote channel differs from canonical state", errRemoteAdoptionDrift)
		}
	}
	if err := requirePlanObjectsInInventory(plan, resolvedInventory); err != nil {
		return err
	}
	if target == string(pub.TargetTencent) {
		lockKey, _ := pub.GenerationLockKey(generation.Generation)
		remoteLock, err := client.getControl(ctx, lockKey)
		if err != nil {
			return err
		}
		expectedLock, expectationErr := expectedCOSGenerationLockBody(canonical, target, generation, generationBody, checkpoint)
		if expectationErr != nil {
			return fmt.Errorf("%w: derive COS generation lock: %v", errCanonicalRemoteAuditState, expectationErr)
		}
		if !remoteLock.Exists || !bytes.Equal(remoteLock.Body, expectedLock) {
			return fmt.Errorf("%w: COS generation lock differs from canonical state", errRemoteAdoptionDrift)
		}
	}
	return nil
}

func containsUntrackedSOWControl(inventoryPath string) bool {
	file, err := os.Open(inventoryPath)
	if err != nil {
		return true
	}
	defer file.Close()
	reader := manifest.NewReader(file)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return false
		}
		if err != nil {
			return true
		}
		if entry.Path == pub.CheckpointKey || strings.HasPrefix(entry.Path, ".sow/") || entry.Path == "_sow/v1" || strings.HasPrefix(entry.Path, "_sow/v1/") {
			return true
		}
	}
}

func requirePlanObjectsInInventory(plan pub.Plan, inventoryPath string) error {
	expected := make(map[string]pub.PlannedObject, len(plan.Objects))
	for _, object := range plan.Objects {
		expected[object.RemoteKey] = object
	}
	deleted := make(map[string]struct{}, len(plan.Deletes))
	for _, object := range plan.Deletes {
		deleted[object.RemoteKey] = struct{}{}
	}
	file, err := os.Open(inventoryPath)
	if err != nil {
		return err
	}
	defer file.Close()
	reader := manifest.NewReader(file)
	for {
		entry, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if _, forbidden := deleted[entry.Path]; forbidden {
			return fmt.Errorf("%w: object committed deleted by the publication plan reappeared in resolved inventory: %s", errRemoteAdoptionDrift, redactRemoteAuditKey(entry.Path))
		}
		object, exists := expected[entry.Path]
		if !exists {
			continue
		}
		if entry.Size != object.Size || entry.HashString() != object.SHA256 {
			return fmt.Errorf("%w: planned object differs in resolved inventory", errRemoteAdoptionDrift)
		}
		delete(expected, entry.Path)
	}
	if len(expected) != 0 {
		return fmt.Errorf("%w: planned object is missing from resolved inventory", errRemoteAdoptionDrift)
	}
	return nil
}

func recordRemoteHeadFinding(recorder *verify.Recorder, expected manifest.Entry, actual pub.ObjectInfo) {
	switch {
	case !actual.Exists:
		addRemoteFinding(recorder, verify.SeverityError, verify.CategoryDrift, "REMOTE_OBJECT_MISSING", expected.Path, "planned remote object is missing")
	case actual.Size != expected.Size || actual.SHA256 != expected.HashString():
		addRemoteFinding(recorder, verify.SeverityError, verify.CategoryDrift, "REMOTE_OBJECT_CHANGED", expected.Path, "planned remote object size or sow-sha256 metadata differs")
	}
}

func addRemoteFinding(recorder remoteFindingSink, severity verify.Severity, category verify.Category, code, subject, message string) {
	recorder.Add(verify.Finding{Layer: verify.LayerL2, Severity: severity, Category: category, Code: code, Subject: subject, Message: message})
}

func listRemoteObjects(ctx context.Context, client *publishTargetClient, destination string) (remoteAuditStats, error) {
	var stats remoteAuditStats
	var previousKey, token string
	seenTokens := make(map[[sha256.Size]byte]struct{})
	err := writeExclusiveManifest(destination, func(output io.Writer) error {
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			page, err := client.listObjectsV2(ctx, token)
			if err != nil {
				return err
			}
			stats.Pages++
			if stats.Pages > 200_000 {
				return errors.New("ListObjectsV2 exceeded page safety limit")
			}
			for _, object := range page.Objects {
				if previousKey != "" && object.Key <= previousKey {
					return errors.New("ListObjectsV2 pages are not globally key-sorted")
				}
				previousKey = object.Key
				entry, err := remoteInventoryEntry(object.Key, object.Size, digestBytesCLI([]byte("etag:"+object.ETag)))
				if err != nil {
					return err
				}
				if err := manifest.WriteEntry(output, entry); err != nil {
					return err
				}
				stats.Listed++
				if stats.Listed > 100_000_000 {
					return errors.New("ListObjectsV2 exceeded object safety limit")
				}
			}
			if page.NextContinuationToken == "" {
				return nil
			}
			tokenDigest := sha256.Sum256([]byte(page.NextContinuationToken))
			if _, duplicate := seenTokens[tokenDigest]; duplicate {
				return errors.New("ListObjectsV2 repeated a continuation token")
			}
			seenTokens[tokenDigest] = struct{}{}
			token = page.NextContinuationToken
		}
	})
	return stats, err
}

func auditFullRemoteInventory(ctx context.Context, cfg *config.Config, canonical *state.Store, target string, client *publishTargetClient, listedPath string, workers, limit int, output io.Writer) (remoteAuditStats, error) {
	var stats remoteAuditStats
	collector := &remoteFindingCollector{}
	// Full inventory fsck is allowed to enumerate a partial baseline so unknown
	// keys can be reported explicitly. Every other local closure defect still
	// fails before the first provider request; bounded L2 remains fail-closed on
	// partial coverage because it cannot classify unlisted keys.
	_, ready, err := inspectCanonicalRemoteState(canonical, cfg, target, true, collector)
	if err != nil {
		return stats, fmt.Errorf("%w: inspect canonical remote state: %v", errCanonicalRemoteAuditState, err)
	}
	for index := range collector.findings {
		printRemoteFSCKFinding(output, target, &collector.findings[index])
	}
	if !ready || len(collector.findings) != 0 {
		return stats, fmt.Errorf("%w: canonical remote state has %d finding(s)", errCanonicalRemoteAuditState, len(collector.findings))
	}
	listedStats, err := listRemoteObjects(ctx, client, listedPath)
	if err != nil {
		return stats, err
	}
	stats = listedStats
	coverageBody, exists, err := readOptionalCanonical(canonical, remoteStatePath(target, "inventory.coverage"))
	if err != nil {
		return stats, fmt.Errorf("%w: read inventory coverage: %v", errCanonicalRemoteAuditState, err)
	}
	if !exists || string(coverageBody) != remoteInventoryComplete && string(coverageBody) != remoteInventoryPartial {
		stats.Coverage = "missing"
	} else {
		stats.Coverage = strings.TrimSpace(string(coverageBody))
	}
	expectedFile, err := canonical.OpenPath(remoteStatePath(target, "inventory.tsv"))
	if err != nil {
		return stats, fmt.Errorf("%w: open canonical remote inventory: %v", errCanonicalRemoteAuditState, err)
	}
	defer expectedFile.Close()
	actualFile, err := os.Open(listedPath)
	if err != nil {
		return stats, err
	}
	defer actualFile.Close()
	expected := manifest.NewReader(expectedFile)
	actual := manifest.NewReader(actualFile)
	expectedEntry, expectedErr := expected.Next()
	actualEntry, actualErr := actual.Next()
	printed := 0
	var headBatch []manifest.Entry
	flushHeads := func() error {
		if len(headBatch) == 0 {
			return nil
		}
		results := runRemoteHeadBatch(ctx, client, headBatch, workers, true, false)
		for index, result := range results {
			if result.err != nil {
				return result.err
			}
			entry := headBatch[index]
			if !result.info.Exists || result.info.Size != entry.Size || result.info.SHA256 != entry.HashString() {
				stats.Changed++
				if printed < limit {
					fmt.Fprintf(output, "remote-drift target=%s kind=changed path=%s\n", target, redactRemoteAuditKey(entry.Path))
					printed++
				}
			}
		}
		headBatch = headBatch[:0]
		return nil
	}
	for !errors.Is(expectedErr, io.EOF) || !errors.Is(actualErr, io.EOF) {
		if expectedErr != nil && !errors.Is(expectedErr, io.EOF) {
			return stats, fmt.Errorf("%w: read canonical remote inventory: %v", errCanonicalRemoteAuditState, expectedErr)
		}
		if actualErr != nil && !errors.Is(actualErr, io.EOF) {
			return stats, fmt.Errorf("read listed remote inventory: %w", actualErr)
		}
		switch {
		case errors.Is(actualErr, io.EOF) || !errors.Is(expectedErr, io.EOF) && expectedEntry.Path < actualEntry.Path:
			stats.Expected++
			stats.Missing++
			if printed < limit {
				fmt.Fprintf(output, "remote-drift target=%s kind=missing path=%s\n", target, redactRemoteAuditKey(expectedEntry.Path))
				printed++
			}
			expectedEntry, expectedErr = expected.Next()
		case errors.Is(expectedErr, io.EOF) || actualEntry.Path < expectedEntry.Path:
			kind := "orphan"
			if stats.Coverage != strings.TrimSpace(remoteInventoryComplete) {
				kind = "unknown"
				stats.Untracked++
			} else {
				stats.Orphan++
			}
			if actualEntry.Size == 0 && looksLikeChecksumKey(actualEntry.Path) {
				stats.ZeroByteChecksums++
				kind = "zero-byte-checksum"
			}
			if printed < limit {
				fmt.Fprintf(output, "remote-drift target=%s kind=%s path=%s\n", target, kind, redactRemoteAuditKey(actualEntry.Path))
				printed++
			}
			actualEntry, actualErr = actual.Next()
		default:
			stats.Expected++
			if actualEntry.Size == 0 && looksLikeChecksumKey(actualEntry.Path) {
				stats.ZeroByteChecksums++
				if printed < limit {
					fmt.Fprintf(output, "remote-drift target=%s kind=zero-byte-checksum path=%s\n", target, redactRemoteAuditKey(actualEntry.Path))
					printed++
				}
			}
			if expectedEntry.Size != actualEntry.Size {
				stats.Changed++
				if printed < limit {
					fmt.Fprintf(output, "remote-drift target=%s kind=changed path=%s\n", target, redactRemoteAuditKey(expectedEntry.Path))
					printed++
				}
			} else {
				headBatch = append(headBatch, expectedEntry)
				if len(headBatch) == remoteHeadBatchSize {
					if err := flushHeads(); err != nil {
						return stats, err
					}
				}
			}
			expectedEntry, expectedErr = expected.Next()
			actualEntry, actualErr = actual.Next()
		}
	}
	if err := flushHeads(); err != nil {
		return stats, err
	}
	if stats.Coverage != strings.TrimSpace(remoteInventoryComplete) {
		fmt.Fprintf(output, "remote-drift target=%s kind=coverage status=%s message=%q\n", target, stats.Coverage, "unknown keys are not safe deletion candidates until existing bucket inventory is imported")
	}
	return stats, nil
}

func looksLikeChecksumKey(key string) bool {
	base := strings.ToLower(filepath.Base(key))
	return strings.Contains(base, "checksum") || strings.Contains(base, "sha256sum") || strings.Contains(base, "sha512sum") || strings.Contains(base, "md5sum") || strings.HasSuffix(base, ".sha256") || strings.HasSuffix(base, ".sha512")
}

func redactRemoteAuditKey(key string) string {
	parts := strings.Split(key, "/")
	for index := 0; index+2 < len(parts); index++ {
		if parts[index] == "pro" && parts[index+1] == "v1" && parts[index+2] != "" && parts[index+2] != "basic" {
			parts[index+2] = "REDACTED"
		}
	}
	value := strings.Join(parts, "/")
	if len(value) > 1024 {
		value = value[:1024]
	}
	return value
}

func remoteAuditDirty(stats remoteAuditStats) bool {
	return stats.Missing != 0 || stats.Changed != 0 || stats.Orphan != 0 || stats.Untracked != 0 || stats.ZeroByteChecksums != 0 || stats.Coverage != strings.TrimSpace(remoteInventoryComplete)
}
