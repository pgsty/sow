package cli

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"sync"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/config"
	pub "github.com/pgsty/sow/internal/publish"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/verify"
)

type purgeLedgerEnvelopeIdentity struct {
	generation state.BlobIdentity
	checkpoint state.BlobIdentity
	plan       state.BlobIdentity
}

type purgeLedgerClosureIdentity struct {
	content          state.BlobIdentity
	intentGeneration state.BlobIdentity
	intentCheckpoint state.BlobIdentity
	intentPlan       state.BlobIdentity
}

type purgeLedgerEnvelope struct {
	anchor        plumbing.Hash
	generationSHA string
	generation    pub.TargetGeneration
	checkpointSHA string
	checkpoint    pub.Checkpoint
	plan          pub.Plan
}

type purgeLedgerReceipt struct {
	identity state.BlobIdentity
	consumed bool
}

const canonicalPurgeReceiptMaxBytes int64 = 4 << 20

type purgeLedgerAuditCacheContextKey struct{}

type purgeLedgerAuditCacheKey struct {
	target string
	head   plumbing.Hash
}

type purgeLedgerAuditRun struct {
	done chan struct{}
	err  error
}

// purgeLedgerAuditCache belongs to exactly one runPublish invocation. It is
// deliberately carried by context instead of package state: two CLI commands
// must never trust one another's audit result. Only successful audits persist;
// concurrent callers may share the same in-flight result, but a failure is
// retried by the next independent call.
type purgeLedgerAuditCache struct {
	mutex      sync.Mutex
	successful map[purgeLedgerAuditCacheKey]struct{}
	running    map[purgeLedgerAuditCacheKey]*purgeLedgerAuditRun
}

func withRunPublishPurgeLedgerAuditCache(ctx context.Context) context.Context {
	return context.WithValue(ctx, purgeLedgerAuditCacheContextKey{}, &purgeLedgerAuditCache{
		successful: make(map[purgeLedgerAuditCacheKey]struct{}),
		running:    make(map[purgeLedgerAuditCacheKey]*purgeLedgerAuditRun),
	})
}

func purgeLedgerAuditCacheFromContext(ctx context.Context) *purgeLedgerAuditCache {
	if ctx == nil {
		return nil
	}
	cache, _ := ctx.Value(purgeLedgerAuditCacheContextKey{}).(*purgeLedgerAuditCache)
	return cache
}

func (cache *purgeLedgerAuditCache) run(ctx context.Context, key purgeLedgerAuditCacheKey, audit func() error) error {
	if cache == nil {
		return audit()
	}
	cache.mutex.Lock()
	if _, exists := cache.successful[key]; exists {
		cache.mutex.Unlock()
		return nil
	}
	if running := cache.running[key]; running != nil {
		cache.mutex.Unlock()
		select {
		case <-running.done:
			return running.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	running := &purgeLedgerAuditRun{done: make(chan struct{})}
	cache.running[key] = running
	cache.mutex.Unlock()

	err := audit()
	cache.mutex.Lock()
	running.err = err
	delete(cache.running, key)
	if err == nil {
		cache.successful[key] = struct{}{}
	}
	close(running.done)
	cache.mutex.Unlock()
	return err
}

func purgeLedgerFinding(category verify.Category, code, subject, message string) verify.Finding {
	return verify.Finding{
		Layer: verify.LayerL2, Severity: verify.SeverityCritical, Category: category,
		Code: code, Subject: subject, Message: message,
	}
}

// validateCanonicalPurgeLedgerForPublish is the fail-closed local gate shared
// by optimized and full publication paths. A later generation must never hide
// or supersede missing evidence from an earlier remote mutation.
func validateCanonicalPurgeLedgerForPublish(ctx context.Context, canonical *state.Store, runtime *config.Config, target string) error {
	audit := func() error {
		if err := validateCurrentCanonicalPurgeEvidenceClosure(canonical, runtime, target); err != nil {
			return fmt.Errorf("%w: target %s canonical purge evidence closure: %v", pub.ErrVerification, target, err)
		}
		findings, err := inspectCanonicalPurgeLedger(canonical, runtime, target)
		if err != nil {
			return fmt.Errorf("%w: target %s inspect canonical purge ledger: %v", pub.ErrVerification, target, err)
		}
		if len(findings) != 0 {
			first := findings[0]
			return fmt.Errorf("%w: target %s canonical purge ledger %s: %s", pub.ErrVerification, target, first.Code, first.Message)
		}
		return nil
	}
	cache := purgeLedgerAuditCacheFromContext(ctx)
	if cache == nil {
		return audit()
	}
	head, err := canonical.HeadHash()
	if err != nil {
		return fmt.Errorf("%w: target %s resolve canonical purge ledger head: %v", pub.ErrVerification, target, err)
	}
	key := purgeLedgerAuditCacheKey{target: target, head: head}
	return cache.run(ctx, key, func() error {
		if err := audit(); err != nil {
			return err
		}
		verifiedHead, err := canonical.HeadHash()
		if err != nil {
			return fmt.Errorf("%w: target %s recheck canonical purge ledger head: %v", pub.ErrVerification, target, err)
		}
		if verifiedHead != head {
			return fmt.Errorf("%w: target %s canonical state changed during purge ledger audit", pub.ErrVerification, target)
		}
		return nil
	})
}

// inspectCanonicalPurgeLedger proves every publication generation from the
// canonical Git history, not merely the target-global current triplet. The
// first commit containing a generation is its immutable publication envelope:
// persistPublishedTarget installs generation, checkpoint, plan, and purge
// receipt in that one commit. HEAD must retain every receipt byte-for-byte.
// This function is entirely local and is deliberately called before any
// remote inventory or CDN request.
func inspectCanonicalPurgeLedger(canonical *state.Store, runtime *config.Config, target string) ([]verify.Finding, error) {
	if canonical == nil || runtime == nil {
		return nil, errors.New("canonical purge ledger requires state and configuration")
	}
	history, err := canonical.History()
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, nil
	}
	historyIndex := make(map[plumbing.Hash]int, len(history))
	for index, commit := range history {
		historyIndex[commit] = index
	}

	generationPath := remoteStatePath(target, "generation.json")
	checkpointPath := remoteStatePath(target, "checkpoint.json")
	planPath := remoteStatePath(target, "plan.json")
	var findings []verify.Finding
	var lastIdentity purgeLedgerEnvelopeIdentity
	var lastClosureIdentity purgeLedgerClosureIdentity
	var lastEnvelope purgeLedgerEnvelope
	var lastGeneration uint64
	publicationSeen := false

	// Retain only immutable blob identities for HEAD receipts. Receipt bodies
	// are bounded small sidecars and are inflated one at a time only when their
	// publication envelope is visited (or when an unconsumed orphan is checked).
	head := history[0]
	receiptPrefix := remoteStatePath(target, "purges") + "/"
	headReceipts := make(map[string]*purgeLedgerReceipt)
	expectedLegacyAttestations := make(map[string]struct{})
	if err := canonical.ForEachFileAt(head, receiptPrefix, func(name string) error {
		identity, exists, identityErr := canonical.BlobIdentityAt(head, name)
		if identityErr != nil {
			return identityErr
		}
		if !exists {
			return fmt.Errorf("canonical purge receipt %s disappeared during audit", name)
		}
		headReceipts[name] = &purgeLedgerReceipt{identity: identity}
		return nil
	}); err != nil {
		return findings, err
	}

	// History is newest-first. Walking it backwards makes the first occurrence
	// of a generation its atomic publication commit and allows an exact 1..N
	// parent-chain check in one pass. Each decoded envelope is fully validated
	// before the next one is loaded, bounding live plan memory to one generation.
	for index := len(history) - 1; index >= 0; index-- {
		commit := history[index]
		identity, present, identityErr := purgeLedgerEnvelopeIdentityAt(canonical, commit, generationPath, checkpointPath, planPath)
		if identityErr != nil {
			return findings, identityErr
		}
		switch present {
		case 0:
			if !publicationSeen {
				// Commits before this target's first publication legitimately have
				// no control envelope. Once published, the triplet is permanent:
				// deleting all three files must not evade the partial-triplet gate.
				continue
			}
			findings = append(findings, purgeLedgerFinding(
				verify.CategoryIntegrity,
				"LOCAL_PURGE_LEDGER_ENVELOPE_INVALID",
				commit.String(),
				fmt.Sprintf("historical generation %d publication control triplet was deleted", lastGeneration),
			))
			return findings, nil
		case 3:
		default:
			findings = append(findings, purgeLedgerFinding(
				verify.CategoryIntegrity,
				"LOCAL_PURGE_LEDGER_ENVELOPE_INVALID",
				commit.String(),
				fmt.Sprintf("historical publication control triplet is partial: found %d of generation, checkpoint, and plan", present),
			))
			return findings, nil
		}
		if publicationSeen && identity == lastIdentity {
			closureIdentity, closurePresent, closureIdentityErr := purgeLedgerClosureIdentityAt(canonical, commit, target, lastEnvelope.generation)
			if closureIdentityErr != nil {
				return findings, closureIdentityErr
			}
			if closurePresent != 4 || closureIdentity != lastClosureIdentity {
				findings = append(findings, purgeLedgerFinding(
					verify.CategoryIntegrity,
					"LOCAL_PURGE_LEDGER_ENVELOPE_CHANGED",
					commit.String(),
					fmt.Sprintf("generation %d content or intent-local publication closure changed without advancing the generation", lastGeneration),
				))
				return findings, nil
			}
			continue
		}
		if publicationSeen && identity.generation == lastIdentity.generation {
			findings = append(findings, purgeLedgerFinding(
				verify.CategoryIntegrity,
				"LOCAL_PURGE_LEDGER_ENVELOPE_CHANGED",
				commit.String(),
				fmt.Sprintf("generation %d checkpoint or plan changed without advancing the generation", lastGeneration),
			))
			return findings, nil
		}
		envelope, envelopeErr := loadPurgeLedgerEnvelopeAt(canonical, commit, target, generationPath, checkpointPath, planPath)
		if envelopeErr != nil {
			findings = append(findings, purgeLedgerFinding(verify.CategoryIntegrity, "LOCAL_PURGE_LEDGER_ENVELOPE_INVALID", commit.String(), envelopeErr.Error()))
			return findings, nil
		}
		if publicationSeen && envelope.generation.Generation == lastGeneration {
			findings = append(findings, purgeLedgerFinding(
				verify.CategoryIntegrity,
				"LOCAL_PURGE_LEDGER_ENVELOPE_CHANGED",
				commit.String(),
				fmt.Sprintf("generation %d control envelope changed without advancing the generation", lastGeneration),
			))
			return findings, nil
		}
		if _, closureExists, closureErr := loadHistoricalPublicationClosureAtForMigration(canonical, target, commit); closureErr != nil || !closureExists {
			if closureErr == nil {
				closureErr = errors.New("historical target publication closure is absent")
			}
			findings = append(findings, purgeLedgerFinding(verify.CategoryIntegrity, "LOCAL_PURGE_LEDGER_ENVELOPE_INVALID", commit.String(), closureErr.Error()))
			return findings, nil
		}
		closureIdentity, closurePresent, closureIdentityErr := purgeLedgerClosureIdentityAt(canonical, commit, target, envelope.generation)
		if closureIdentityErr != nil {
			return findings, closureIdentityErr
		}
		if closurePresent != 4 {
			findings = append(findings, purgeLedgerFinding(verify.CategoryIntegrity, "LOCAL_PURGE_LEDGER_ENVELOPE_INVALID", commit.String(), "historical content and intent-local publication closure is incomplete"))
			return findings, nil
		}
		wantGeneration := uint64(1)
		wantParent := uint64(0)
		if publicationSeen {
			wantGeneration = lastGeneration + 1
			wantParent = lastGeneration
		}
		if envelope.generation.Generation != wantGeneration || envelope.generation.ParentGeneration != wantParent {
			findings = append(findings, purgeLedgerFinding(verify.CategoryCoverage, "LOCAL_PURGE_LEDGER_GENERATION_GAP", fmt.Sprintf("%s/%020d", target, envelope.generation.Generation), fmt.Sprintf("generation chain got generation=%d parent=%d, want generation=%d parent=%d", envelope.generation.Generation, envelope.generation.ParentGeneration, wantGeneration, wantParent)))
			return findings, nil
		}
		if publicationSeen {
			ancestor, ancestryErr := canonical.IsAncestor(lastEnvelope.anchor, envelope.anchor)
			if ancestryErr != nil {
				return findings, ancestryErr
			}
			if !ancestor {
				findings = append(findings, purgeLedgerFinding(verify.CategoryIntegrity, "LOCAL_PURGE_LEDGER_ENVELOPE_INVALID", commit.String(), fmt.Sprintf("generation %d publication anchor does not descend from generation %d anchor", envelope.generation.Generation, lastGeneration)))
				return findings, nil
			}
		}
		if err := validateHistoricalDesiredCommit(canonical, envelope.generation, commit, index, historyIndex); err != nil {
			findings = append(findings, purgeLedgerFinding(verify.CategoryIntegrity, "LOCAL_PURGE_LEDGER_ENVELOPE_INVALID", commit.String(), err.Error()))
			return findings, nil
		}
		planSHA, digestErr := envelope.plan.Digest()
		if digestErr != nil {
			return findings, digestErr
		}
		switch {
		case envelope.checkpoint.PlanSHA256 == "" && len(envelope.plan.PurgeURLs) != 0:
			attestationPath := legacyPurgePlanAttestationPath(target, envelope.generation.Generation, envelope.checkpoint.TransactionID)
			expectedLegacyAttestations[attestationPath] = struct{}{}
			receiptPath := purgeLedgerReceiptPath(target, envelope.generation.Generation, envelope.checkpoint.TransactionID)
			anchorBody, exists, readErr := readCanonicalBytesAt(canonical, envelope.anchor, receiptPath, canonicalPurgeReceiptMaxBytes)
			if readErr != nil {
				return findings, readErr
			}
			if !exists {
				findings = append(findings, purgeLedgerFinding(verify.CategoryCoverage, "LOCAL_PLAN_BINDING_MISSING", attestationPath, "legacy purge plan cannot be attested because its atomic publication receipt is missing"))
			} else {
				finding, validationErr := inspectLegacyPurgePlanAttestation(canonical, target, envelope, receiptPath, anchorBody)
				if validationErr != nil {
					return findings, validationErr
				}
				if finding != nil {
					findings = append(findings, *finding)
				}
			}
		case envelope.checkpoint.PlanSHA256 != "" && envelope.checkpoint.PlanSHA256 != planSHA:
			findings = append(findings, purgeLedgerFinding(verify.CategoryIntegrity, "LOCAL_PLAN_BINDING_INVALID", fmt.Sprintf("%s/%020d", target, envelope.generation.Generation), "historical publish plan disagrees with its checkpoint"))
		}
		if len(envelope.plan.PurgeURLs) != 0 {
			receiptPath := purgeLedgerReceiptPath(target, envelope.generation.Generation, envelope.checkpoint.TransactionID)
			anchorIdentity, anchorExists, readErr := canonical.BlobIdentityAt(envelope.anchor, receiptPath)
			if readErr != nil {
				return findings, readErr
			}
			headReceipt, headExists := headReceipts[receiptPath]
			if !anchorExists || !headExists {
				findings = append(findings, purgeLedgerFinding(verify.CategoryCoverage, "LOCAL_PURGE_EVIDENCE_MISSING", receiptPath, "nonempty historical purge plan lacks an atomic publication receipt or retained HEAD receipt"))
				if headExists {
					headReceipt.consumed = true
				}
			} else {
				headReceipt.consumed = true
				if anchorIdentity != headReceipt.identity {
					findings = append(findings, purgeLedgerFinding(verify.CategoryIntegrity, "LOCAL_PURGE_EVIDENCE_CHANGED", receiptPath, "purge receipt differs from the blob committed with its publication envelope"))
				} else {
					anchorBody, exists, bodyErr := readCanonicalBytesAt(canonical, envelope.anchor, receiptPath, canonicalPurgeReceiptMaxBytes)
					if bodyErr != nil {
						return findings, bodyErr
					}
					if !exists {
						return findings, fmt.Errorf("canonical purge receipt %s disappeared during audit", receiptPath)
					}
					finding, validationErr := validateHistoricalPurgeReceipt(canonical, runtime, target, envelope, receiptPath, anchorBody)
					if validationErr != nil {
						return findings, validationErr
					}
					if finding != nil {
						findings = append(findings, *finding)
					}
				}
			}
		}
		lastGeneration = envelope.generation.Generation
		lastIdentity = identity
		lastClosureIdentity = closureIdentity
		lastEnvelope = envelope
		publicationSeen = true
	}
	for name, receipt := range headReceipts {
		if receipt.consumed {
			continue
		}
		body, exists, readErr := readCanonicalBytesAt(canonical, head, name, canonicalPurgeReceiptMaxBytes)
		if readErr != nil {
			return findings, readErr
		}
		if !exists {
			return findings, fmt.Errorf("canonical purge receipt %s disappeared during audit", name)
		}
		evidence, decodeErr := pub.DecodePurgeEvidence(body)
		if decodeErr != nil {
			findings = append(findings, purgeLedgerFinding(verify.CategoryIntegrity, "LOCAL_PURGE_EVIDENCE_INVALID", name, "historical purge receipt is invalid or non-canonical"))
			continue
		}
		expected := purgeLedgerReceiptPath(target, evidence.Generation, evidence.TransactionID)
		if name != expected || evidence.Target != pub.TargetName(target) {
			findings = append(findings, purgeLedgerFinding(verify.CategoryIntegrity, "LOCAL_PURGE_EVIDENCE_INVALID", name, "purge receipt path or target does not match its canonical identity"))
			continue
		}
		findings = append(findings, purgeLedgerFinding(verify.CategoryIntegrity, "LOCAL_PURGE_EVIDENCE_ORPHAN", name, "purge receipt has no nonempty publication plan in canonical generation history"))
	}
	attestationPrefix := remoteStatePath(target, "purge-migrations") + "/"
	attestationPaths, err := canonical.ListFilesAt(head, attestationPrefix)
	if err != nil {
		return findings, err
	}
	for _, name := range attestationPaths {
		if _, expected := expectedLegacyAttestations[name]; expected {
			continue
		}
		findings = append(findings, purgeLedgerFinding(verify.CategoryIntegrity, "LOCAL_PLAN_BINDING_ORPHAN", name, "legacy purge plan attestation has no matching v1 nonempty publication envelope"))
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Code != findings[j].Code {
			return findings[i].Code < findings[j].Code
		}
		return findings[i].Subject < findings[j].Subject
	})
	return findings, nil
}

func purgeLedgerClosureIdentityAt(canonical *state.Store, commit plumbing.Hash, target string, generation pub.TargetGeneration) (purgeLedgerClosureIdentity, int, error) {
	var result purgeLedgerClosureIdentity
	paths := []struct {
		name     string
		identity *state.BlobIdentity
	}{
		{name: remoteStatePath(target, "content.tsv"), identity: &result.content},
	}
	for _, item := range []struct {
		filename string
		identity *state.BlobIdentity
	}{
		{filename: "generation.json", identity: &result.intentGeneration},
		{filename: "checkpoint.json", identity: &result.intentCheckpoint},
		{filename: "plan.json", identity: &result.intentPlan},
	} {
		intentPath, err := remoteIntentStatePath(target, generation.IntentView, generation.IntentSnapshot, item.filename)
		if err != nil {
			return result, 0, err
		}
		paths = append(paths, struct {
			name     string
			identity *state.BlobIdentity
		}{name: intentPath, identity: item.identity})
	}
	present := 0
	for _, item := range paths {
		identity, exists, err := canonical.BlobIdentityAt(commit, item.name)
		if err != nil {
			return result, 0, err
		}
		if exists {
			*item.identity = identity
			present++
		}
	}
	return result, present, nil
}

func purgeLedgerEnvelopeIdentityAt(canonical *state.Store, commit plumbing.Hash, generationPath, checkpointPath, planPath string) (purgeLedgerEnvelopeIdentity, int, error) {
	var result purgeLedgerEnvelopeIdentity
	present := 0
	for _, item := range []struct {
		path     string
		identity *state.BlobIdentity
	}{
		{path: generationPath, identity: &result.generation},
		{path: checkpointPath, identity: &result.checkpoint},
		{path: planPath, identity: &result.plan},
	} {
		identity, exists, err := canonical.BlobIdentityAt(commit, item.path)
		if err != nil {
			return result, 0, err
		}
		if exists {
			*item.identity = identity
			present++
		}
	}
	return result, present, nil
}

func loadPurgeLedgerEnvelopeAt(canonical *state.Store, commit plumbing.Hash, target, generationPath, checkpointPath, planPath string) (purgeLedgerEnvelope, error) {
	var result purgeLedgerEnvelope
	result.anchor = commit
	generationBody, generationExists, err := readCanonicalBytesAt(canonical, commit, generationPath, 16<<20)
	if err != nil {
		return result, err
	}
	if !generationExists {
		return result, errors.New("historical generation disappeared during audit")
	}
	result.generationSHA = digestBytesCLI(generationBody)
	result.generation, err = pub.DecodeTargetGeneration(generationBody)
	if err != nil {
		return result, fmt.Errorf("decode target generation: %w", err)
	}
	generationBody = nil

	checkpointBody, checkpointExists, err := readCanonicalBytesAt(canonical, commit, checkpointPath, 16<<20)
	if err != nil {
		return result, err
	}
	if !checkpointExists {
		return result, errors.New("historical checkpoint disappeared during audit")
	}
	result.checkpointSHA = digestBytesCLI(checkpointBody)
	result.checkpoint, err = pub.DecodeCheckpoint(checkpointBody)
	if err != nil {
		return result, fmt.Errorf("decode target checkpoint: %w", err)
	}
	checkpointBody = nil

	planBody, planExists, err := readCanonicalBytesAt(canonical, commit, planPath, 64<<20)
	if err != nil {
		return result, err
	}
	if !planExists {
		return result, errors.New("historical plan disappeared during audit")
	}
	result.plan, err = pub.DecodePlan(planBody)
	if err != nil {
		return result, fmt.Errorf("decode publication plan: %w", err)
	}
	if result.generation.Target != pub.TargetName(target) || result.checkpoint.Target != pub.TargetName(target) ||
		result.checkpoint.Phase != pub.PhaseCheckpointCommitted ||
		result.checkpoint.Generation != result.generation.Generation || result.checkpoint.ParentGeneration != result.generation.ParentGeneration ||
		!pub.SamePublicationIntent(result.checkpoint.IntentView, result.checkpoint.IntentSnapshot, result.generation.IntentView, result.generation.IntentSnapshot) ||
		result.checkpoint.GenerationSHA256 != result.generationSHA || result.checkpoint.DesiredCommit != result.generation.DesiredCommit ||
		result.checkpoint.ContentManifestSHA256 != result.generation.ContentManifestSHA256 {
		return result, errors.New("historical generation/checkpoint closure is invalid")
	}
	return result, nil
}

func purgeLedgerReceiptPath(target string, generation uint64, transactionID string) string {
	return remoteStatePath(target, path.Join("purges", fmt.Sprintf("%020d-%s.json", generation, transactionID)))
}

// canonicalProviderConfigurationForGeneration resolves the configuration that
// was committed with the first occurrence of a target generation. Provider
// identities are publication facts: a later, intentionally recorded CDN zone
// rotation must not invalidate an earlier generation's otherwise sound purge
// receipt, and it must not weaken validation of that receipt against the zone
// that actually accepted it.
func canonicalProviderConfigurationForGeneration(canonical *state.Store, runtime *config.Config, target string, generation uint64) (*config.Config, error) {
	commit, _, err := targetGenerationPublicationState(canonical, target, generation)
	if err != nil {
		return nil, err
	}
	return canonicalConfigurationAt(canonical, commit, runtime)
}

func validateHistoricalPurgeReceipt(canonical *state.Store, runtime *config.Config, target string, envelope purgeLedgerEnvelope, receiptPath string, body []byte) (*verify.Finding, error) {
	evidence, err := pub.DecodePurgeEvidence(body)
	if err != nil {
		finding := purgeLedgerFinding(verify.CategoryIntegrity, "LOCAL_PURGE_EVIDENCE_INVALID", receiptPath, "historical provider purge evidence is invalid or non-canonical")
		return &finding, nil
	}
	planSHA, err := envelope.plan.Digest()
	if err != nil {
		return nil, err
	}
	urlsSHA, err := pub.PurgeURLsDigest(envelope.plan.PurgeURLs)
	if err != nil {
		return nil, err
	}
	if evidence.Target != pub.TargetName(target) || evidence.TransactionID != envelope.checkpoint.TransactionID ||
		evidence.Generation != envelope.generation.Generation || evidence.GenerationSHA256 != envelope.generationSHA ||
		evidence.PlanSHA256 != planSHA || evidence.CheckpointSHA256 != envelope.checkpointSHA ||
		evidence.URLCount != len(envelope.plan.PurgeURLs) || evidence.URLsSHA256 != urlsSHA {
		finding := purgeLedgerFinding(verify.CategoryIntegrity, "LOCAL_PURGE_EVIDENCE_INVALID", receiptPath, "historical purge receipt disagrees with its publication envelope")
		return &finding, nil
	}
	latestFull := -1
	for index := range evidence.Attempts {
		if evidence.Attempts[index].Purpose == pub.PurgeAttemptFull {
			latestFull = index
		}
	}
	if latestFull < 0 || evidence.ValidateFullClosure(evidence.Attempts[latestFull].ID, envelope.plan.PurgeURLs) != nil {
		finding := purgeLedgerFinding(verify.CategoryCoverage, "LOCAL_PURGE_EVIDENCE_INCOMPLETE", receiptPath, "historical purge receipt has no latest completed full closure")
		return &finding, nil
	}
	committedConfig, err := canonicalConfigurationAt(canonical, envelope.anchor, runtime)
	if err != nil {
		finding := purgeLedgerFinding(verify.CategoryCoverage, "LOCAL_PURGE_EVIDENCE_PROVIDER_UNBOUND", receiptPath, "publication-time canonical provider configuration is unavailable")
		return &finding, nil
	}
	targetConfig, exists := committedConfig.Targets[target]
	if !exists {
		finding := purgeLedgerFinding(verify.CategoryCoverage, "LOCAL_PURGE_EVIDENCE_PROVIDER_UNBOUND", receiptPath, "publication-time canonical configuration has no matching target")
		return &finding, nil
	}
	var vendor, zoneID string
	switch pub.TargetName(target) {
	case pub.TargetCloudflare:
		vendor, zoneID = pub.PurgeVendorCloudflare, targetConfig.CDN.ZoneID
	case pub.TargetTencent:
		vendor, zoneID = pub.PurgeVendorEdgeOne, targetConfig.CDN.Distribution
	default:
		return nil, fmt.Errorf("unsupported historical purge target %q", target)
	}
	for _, receipt := range evidence.Attempts[latestFull].Batches {
		if receipt.Vendor != vendor || receipt.ZoneID != zoneID {
			finding := purgeLedgerFinding(verify.CategoryIntegrity, "LOCAL_PURGE_EVIDENCE_PROVIDER_CHANGED", receiptPath, "historical purge receipt provider or zone differs from publication-time configuration")
			return &finding, nil
		}
	}
	return nil, nil
}
